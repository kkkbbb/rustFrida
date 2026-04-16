//! ldmonitor - eBPF-based library loading monitor
//!
//! This library provides functionality to monitor `android_dlopen_ext` calls
//! using eBPF uprobes.

use aya::{maps::perf::PerfEventArray, programs::UProbe, util::online_cpus, Ebpf};
use bytes::BytesMut;
use log::debug;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tokio::io::unix::AsyncFd;
use tokio::runtime::Runtime;

pub use ldmonitor_common::{DlopenEvent, MAX_PATH_LEN};

/// 从 /proc/<pid>/status 读取 NSpid 字段，返回各namespace层级的PID列表
///
/// NSpid 格式: NSpid: <root_ns_pid> <ns1_pid> <ns2_pid> ...
/// 从外层(root)到内层排列，最后一个是进程所在最内层namespace的PID
fn get_nspid(host_pid: u32) -> Option<Vec<u32>> {
    let status_path = format!("/proc/{}/status", host_pid);
    let content = fs::read_to_string(&status_path).ok()?;

    for line in content.lines() {
        if line.starts_with("NSpid:") {
            let pids: Vec<u32> = line
                .trim_start_matches("NSpid:")
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !pids.is_empty() {
                return Some(pids);
            }
        }
    }
    None
}

/// 获取当前进程的 PID namespace inode
fn get_current_pid_ns() -> Option<u64> {
    let link = fs::read_link("/proc/self/ns/pid").ok()?;
    // 格式: pid:[4026531836]
    let s = link.to_string_lossy();
    let start = s.find('[')? + 1;
    let end = s.find(']')?;
    s[start..end].parse().ok()
}

/// 获取指定进程的 PID namespace inode
fn get_pid_ns(pid: u32) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{}/ns/pid", pid)).ok()?;
    let s = link.to_string_lossy();
    let start = s.find('[')? + 1;
    let end = s.find(']')?;
    s[start..end].parse().ok()
}

/// 将 host PID 转换为当前 namespace 的 PID
///
/// 如果进程在同一namespace或嵌套namespace中，返回对应的namespace PID
/// 如果无法转换（不同namespace分支），返回 None
pub fn translate_pid_to_current_ns(host_pid: u32) -> Option<u32> {
    let nspids = get_nspid(host_pid)?;

    // 如果只有一个PID，说明进程在root namespace
    if nspids.len() == 1 {
        return Some(nspids[0]);
    }

    // 获取当前namespace和目标进程namespace
    let current_ns = get_current_pid_ns()?;
    let target_ns = get_pid_ns(host_pid)?;

    // 如果在同一namespace，返回最内层的PID
    if current_ns == target_ns {
        return nspids.last().copied();
    }

    // 尝试返回最内层namespace的PID（适用于嵌套容器场景）
    // 这是最常见的场景：监控程序和目标进程在同一个容器内
    nspids.last().copied()
}

/// 监听到的 dlopen 事件
#[derive(Debug, Clone)]
pub struct DlopenInfo {
    /// 宿主机 namespace 的 PID
    pub host_pid: u32,
    /// 当前 namespace 的 PID（如果能转换的话）
    pub ns_pid: Option<u32>,
    pub uid: u32,
    pub path: String,
}

impl DlopenInfo {
    /// 获取可用的 PID（优先返回 namespace PID）
    pub fn pid(&self) -> u32 {
        self.ns_pid.unwrap_or(self.host_pid)
    }
}

impl From<&DlopenEvent> for DlopenInfo {
    fn from(event: &DlopenEvent) -> Self {
        let host_pid = event.pid;
        let ns_pid = translate_pid_to_current_ns(host_pid);

        Self {
            host_pid,
            ns_pid,
            uid: event.uid,
            path: event.path_str().to_string(),
        }
    }
}

/// eBPF dlopen 监听器
pub struct DlopenMonitor {
    receiver: Receiver<DlopenInfo>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DlopenMonitor {
    /// 创建新的监听器
    ///
    /// # Arguments
    /// * `target_pid` - 可选的目标进程 PID，如果为 None 则监听所有进程
    pub fn new(target_pid: Option<u32>) -> anyhow::Result<Self> {
        // 设置 memlock 限制
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        let (sender, receiver) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let handle = thread::spawn(move || {
            let rt = Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async move {
                if let Err(e) = run_monitor(target_pid, sender, stop_flag_clone).await {
                    eprintln!("Monitor error: {}", e);
                }
            });
        });

        Ok(Self {
            receiver,
            stop_flag,
            handle: Some(handle),
        })
    }

    /// 停止监听并卸载 eBPF 程序
    pub fn stop(mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        // if let Some(handle) = self.handle.take() {
        //     let _ = handle.join();
        // }
        println!("eBPF 监听已停止");
    }

    /// 阻塞等待下一个 dlopen 事件
    pub fn recv(&self) -> Option<DlopenInfo> {
        self.receiver.recv().ok()
    }

    /// 非阻塞尝试接收 dlopen 事件
    pub fn try_recv(&self) -> Option<DlopenInfo> {
        self.receiver.try_recv().ok()
    }

    /// 等待匹配指定路径的 SO 加载
    ///
    /// # Arguments
    /// * `path_pattern` - 要匹配的路径模式（包含匹配）
    ///
    /// # Returns
    /// 匹配到的 DlopenInfo
    pub fn wait_for_path(&self, path_pattern: &str) -> Option<DlopenInfo> {
        while let Some(info) = self.recv() {
            if info.path.contains(path_pattern) {
                return Some(info);
            }
        }
        None
    }

    /// 等待匹配指定路径的 SO 加载（带超时）
    ///
    /// # Arguments
    /// * `path_pattern` - 要匹配的路径模式（包含匹配）
    /// * `timeout` - 超时时间
    ///
    /// # Returns
    /// 匹配到的 DlopenInfo，超时返回 None
    pub fn wait_for_path_timeout(&self, path_pattern: &str, timeout: std::time::Duration) -> Option<DlopenInfo> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if let Ok(info) = self.receiver.recv_timeout(timeout - start.elapsed()) {
                if info.path.contains(path_pattern) {
                    return Some(info);
                }
            } else {
                break;
            }
        }
        None
    }
}

async fn run_monitor(
    target_pid: Option<u32>,
    sender: Sender<DlopenInfo>,
    stop_flag: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ldmonitor")))?;

    let program: &mut UProbe = ebpf.program_mut("ldmonitor").unwrap().try_into()?;
    program.load()?;
    program.attach(
        Some("android_dlopen_ext"),
        0, // offset
        "/apex/com.android.runtime/lib64/bionic/libdl.so",
        target_pid.map(|p| p as i32),
    )?;

    let mut perf_array = PerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    let cpus = online_cpus().map_err(|(s, e)| anyhow::anyhow!("{}: {}", s, e))?;
    for cpu_id in cpus {
        let buf = perf_array.open(cpu_id, None)?;
        let sender_clone = sender.clone();
        let stop_flag_clone = stop_flag.clone();

        tokio::spawn(async move {
            let mut async_fd = AsyncFd::new(buf).unwrap();
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<DlopenEvent>()))
                .collect::<Vec<_>>();

            loop {
                if stop_flag_clone.load(Ordering::SeqCst) {
                    return;
                }

                let mut guard = async_fd.readable_mut().await.unwrap();
                let events = guard.get_inner_mut().read_events(&mut buffers).unwrap();
                for buf in buffers.iter().take(events.read) {
                    let event = unsafe { &*(buf.as_ptr() as *const DlopenEvent) };
                    let info = DlopenInfo::from(event);
                    if sender_clone.send(info).is_err() {
                        return; // receiver dropped
                    }
                }
                guard.clear_ready();
            }
        });
    }

    // 等待停止信号
    while !stop_flag.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // eBPF 程序在 ebpf 变量 drop 时自动卸载
    drop(ebpf);
    Ok(())
}
