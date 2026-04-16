//! 内存快照 dump 模块
#![cfg(feature = "frida-gum")]

use crate::communication::log_msg;
use crate::OUTPUT_PATH;
use prost::Message;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::thread;

// 内存区域信息
#[derive(Clone, PartialEq, Message)]
struct MemoryRegion {
    #[prost(uint64, tag = "1")]
    start_addr: u64,
    #[prost(uint64, tag = "2")]
    end_addr: u64,
    #[prost(string, tag = "3")]
    permissions: String,
    #[prost(uint64, tag = "4")]
    offset: u64,
    #[prost(string, tag = "5")]
    dev: String,
    #[prost(uint64, tag = "6")]
    inode: u64,
    #[prost(string, tag = "7")]
    pathname: String,
    #[prost(bytes, tag = "8")]
    data: Vec<u8>,
}

// 内存快照头部信息
#[derive(Clone, PartialEq, Message)]
struct SnapshotHeader {
    #[prost(uint64, tag = "1")]
    timestamp: u64,
    #[prost(uint32, tag = "2")]
    pid: u32,
    #[prost(uint32, tag = "3")]
    region_count: u32,
}

// 解析 /proc/self/maps 中的单行
fn parse_maps_line(line: &str) -> Option<(u64, u64, String, u64, String, u64, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let addr_range: Vec<&str> = parts[0].split('-').collect();
    if addr_range.len() != 2 {
        return None;
    }
    let start_addr = u64::from_str_radix(addr_range[0], 16).ok()?;
    let end_addr = u64::from_str_radix(addr_range[1], 16).ok()?;
    let permissions = parts[1].to_string();
    let offset = u64::from_str_radix(parts[2], 16).ok()?;
    let dev = parts[3].to_string();
    let inode = parts[4].parse::<u64>().ok()?;
    let pathname = if parts.len() > 5 {
        parts[5..].join(" ")
    } else {
        String::new()
    };

    Some((start_addr, end_addr, permissions, offset, dev, inode, pathname))
}

const MEMORY_CHUNK_SIZE: usize = 4 * 1024 * 1024;

fn write_memory_region_chunked<W: Write>(
    output: &mut W,
    start_addr: u64,
    end_addr: u64,
    permissions: &str,
    offset: u64,
    pathname: &str,
) -> std::io::Result<()> {
    let total_size = (end_addr - start_addr) as usize;
    let mut current_addr = start_addr;
    let mut current_offset = offset;
    let mut chunk_index = 0u32;

    while current_addr < end_addr {
        let remaining = (end_addr - current_addr) as usize;
        let chunk_size = remaining.min(MEMORY_CHUNK_SIZE);
        let chunk_end = current_addr + chunk_size as u64;

        let data = unsafe {
            let ptr = current_addr as *const u8;
            let slice = std::slice::from_raw_parts(ptr, chunk_size);
            slice.to_vec()
        };

        let region = MemoryRegion {
            start_addr: current_addr,
            end_addr: chunk_end,
            permissions: permissions.to_string(),
            offset: current_offset,
            dev: String::new(),
            inode: chunk_index as u64,
            pathname: if total_size > MEMORY_CHUNK_SIZE {
                format!("{}#chunk{}", pathname, chunk_index)
            } else {
                pathname.to_string()
            },
            data,
        };

        let mut region_buf = Vec::with_capacity(chunk_size + 256);
        region
            .encode_length_delimited(&mut region_buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Region 编码失败: {}", e)))?;
        output.write_all(&region_buf)?;

        current_addr = chunk_end;
        current_offset += chunk_size as u64;
        chunk_index += 1;
    }

    Ok(())
}

pub(crate) fn dump_memory_snapshot(output_path: &str) -> std::io::Result<()> {
    use std::io::BufRead;

    let maps_file = File::open("/proc/self/maps")?;
    let reader = std::io::BufReader::new(maps_file);

    let mut regions_to_dump: Vec<(u64, u64, String, u64, String, u64, String)> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Some((start_addr, end_addr, permissions, offset, dev, inode, pathname)) = parse_maps_line(&line) {
            if ((pathname.contains(".so") && pathname.contains("/data")) || pathname.contains("base.apk"))
                && permissions.contains('r')
            {
                regions_to_dump.push((start_addr, end_addr, permissions, offset, dev, inode, pathname));
            }
        }
    }

    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let pid = std::process::id();

    let header = SnapshotHeader {
        timestamp,
        pid,
        region_count: regions_to_dump.len() as u32,
    };
    let mut header_buf = Vec::new();
    header
        .encode_length_delimited(&mut header_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Header 编码失败: {}", e)))?;
    output_file.write_all(&header_buf)?;

    for (start_addr, end_addr, permissions, offset, _dev, _inode, pathname) in regions_to_dump {
        if let Err(e) =
            write_memory_region_chunked(&mut output_file, start_addr, end_addr, &permissions, offset, &pathname)
        {
            log_msg(format!("写入内存区域失败 0x{:x}-0x{:x}: {}", start_addr, end_addr, e));
            continue;
        }
    }

    output_file.flush()?;
    Ok(())
}

pub fn spawn_memory_dump_thread(output_path: String) -> thread::JoinHandle<()> {
    thread::spawn(move || match dump_memory_snapshot(&output_path) {
        Ok(_) => log_msg(format!("内存快照已保存到: {}\n", output_path)),
        Err(e) => log_msg(format!("内存快照保存失败: {}\n", e)),
    })
}

pub fn start_dump_mem() {
    let snapshot_path = match OUTPUT_PATH.get() {
        Some(base) => format!("{}/memory_snapshot.pb", base),
        None => {
            log_msg("错误: OUTPUT_PATH 未设置，无法保存内存快照\n".to_string());
            return;
        }
    };
    let _dump_handle = spawn_memory_dump_thread(snapshot_path);
}
