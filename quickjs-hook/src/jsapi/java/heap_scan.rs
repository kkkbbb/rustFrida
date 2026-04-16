//! Java.choose 的 ART 堆扫描后端。
//!
//! 背景：API 34+ 把 `VMDebug.getInstancesOfClasses` 从 Java 层删了，API 36 更进一步
//! 把 `art::gc::Heap::VisitObjects / GetInstances` 这些 Frida 依赖的内部符号从 libart.so
//! `.dynsym` 里删了。Android Studio API 31 emulator image 更是连 VMDebug 的 native
//! 侧实现都没打进 libart —— 三条公开路径全挂。本后端直接对 ART 堆暴力扫描绕开。
//!
//! **兼容矩阵**（实测）：
//!
//! | API | VMDebug native | Heap::VisitObjects | Heap::GetInstances | 本后端 |
//! |-----|----------------|--------------------|--------------------|--------|
//! | 31 (emu) | ✗ (剥离) | ✗ | ✗ | ✓ 唯一可用 |
//! | 36 (stock) | ✗ (Java API 删除) | ✗ (dynsym 剥离) | ✗ | ✓ 唯一可用 |
//!
//! **算法**：
//!   1. 用 `art::Thread::CurrentFromGdb` 拿当前 `art::Thread*`
//!   2. `art::Thread::DecodeGlobalJObject(jclass)`（modern）或 `DecodeJObject`（API ≤13）
//!      把 target class 的 global ref 还原成 `art::mirror::Class*`（needle）
//!   3. 用 `art::ScopedSuspendAll` RAII 挂起所有线程（ctor/dtor 都走全局 Runtime，
//!      不 deref 传入的 `this`，所以不需要 struct 存储）
//!   4. `art::gc::ScopedGCCriticalSection(self, kGcCauseDebugger, kCollectorTypeHeapTrim)`
//!      锁 GC 临界区（ctor 存 Thread*/cause_name_，struct 需要栈存储 ~48B）
//!   5. 从 `/proc/self/maps` 枚举 `[anon:dalvik-main space...]` / `[anon:dalvik-large object...]`
//!      / `[anon:dalvik-zygote...]` / `[anon:dalvik-region space...]` 这些真正放对象的 VMA
//!      （按前缀匹配兼容 CMC/CC GC 变体，如 `[anon:dalvik-main space (region space)]`）
//!   6. 按 `mirror::Class::object_size_alloc_fast_path_` 步进扫描（偏移从反汇编
//!      `Class::SetObjectSizeAllocFastPath` 动态探测；API 31=0x64, API 36=0x5c）；
//!      读首 4 字节 compressed class ref，与 needle 低 32 位比对；命中后再做一次
//!      二重校验：`*candidate_class` 应指向 `java.lang.Class`
//!   7. 命中对象列表逐个 `art::JavaVMExt::AddGlobalRef` 成 jobject 返回
//!
//! **Frida 兼容性吸收**：所有版本敏感符号都采用 Frida 式的 `optionals` 多变体 fallback
//! （如 DecodeGlobalJObject/DecodeJObject，AddGlobalRef 的 ObjPtr/原生 Object* 变体）。
//!
//! Note：ART 堆位于低 4GB 虚拟地址（`[anon:dalvik-main space]` 实测 `0x02000000-0x12000000` /
//! CMC GC 下 `0x12c00000-0x2ac00000`），所以 `HeapReference<T>` 的 u32 存储 == 完整 64 位
//! 指针（零扩展）。

use std::collections::HashSet;
use std::ffi::{c_char, c_void, CString};
use std::sync::OnceLock;

use crate::jsapi::console::output_verbose;
use crate::jsapi::util::read_proc_self_maps;

use super::jni_core::*;
use super::reflect::find_class_safe;

// ============================================================================
// ART ABI 常量
// ============================================================================

/// `art::gc::kGcCauseDebugger` — Frida 用的同款 cause
const K_GC_CAUSE_DEBUGGER: u32 = 5;
/// `art::gc::kCollectorTypeHeapTrim` — Frida 用的同款 collector type
const K_COLLECTOR_TYPE_HEAP_TRIM: u32 = 8;

/// `ScopedGCCriticalSection` 栈实例大小。实测 ctor 只写 offset 0/8/16，留足 48B 以防
/// 布局随版本扩展。
const SGCS_STORAGE_BYTES: usize = 48;

/// `mirror::Class::object_size_alloc_fast_path_` 字段偏移的经验常量表。
/// 反汇编探测失败时从此列表兜底，按"现代版本优先"顺序尝试。
/// - 0x5c: API 34~36 (Android 14+)
/// - 0x64: API 31~33 (Android 12~13)
/// - 0x60, 0x68: AOSP 开发分支里观察到的偏移
/// 后续新版本触发未命中时，扩充该列表。
const CLASS_OBJECT_SIZE_OFFSET_CANDIDATES: &[usize] = &[0x5c, 0x64, 0x60, 0x68];

/// ART `kObjectAlignment` = 8 字节（mirror::Object 的最小对齐）。
const OBJECT_ALIGNMENT: u64 = 8;

/// 合理对象大小上限 —— 超此值认为 class 字段损坏或指错，保守推进。
/// 实际框架对象极少超过 1MB（字符串/数组走 large object space 不在 main space walk 里）。
const MAX_REASONABLE_OBJECT_SIZE: u32 = 1 << 20;

/// `mirror::Class::super_class_` 候选搜索范围（从 mirror::Class 头开始）。
/// AOSP 不同版本里这个字段在 32~80 之间徘徊；探测一次缓存即可。
const SUPER_CLASS_PROBE_MIN: usize = 8;
const SUPER_CLASS_PROBE_MAX: usize = 96;

/// 为了避免 super_class 链上出现自环或异常长链导致死循环，限制最多 32 级。
/// Java 类继承层级 5~10 已是上限。
const MAX_SUPER_CLASS_DEPTH: usize = 32;

// ============================================================================
// ART 函数签名
// ============================================================================

/// `art::Thread* art::Thread::CurrentFromGdb()`
type ThreadCurrentFromGdbFn = unsafe extern "C" fn() -> *mut c_void;

/// `art::mirror::Object* art::Thread::DecodeGlobalJObject(_jobject*) const`
/// x0=this(Thread*), x1=jobject, 返回 mirror::Object* (64-bit 完整指针)
type DecodeGlobalJObjectFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> u64;

/// `art::ScopedSuspendAll::ScopedSuspendAll(char const*, bool)`
/// 反汇编证实 ctor 不 deref this，直接读全局 Runtime。传 null this 即可。
type ScopedSuspendAllCtorFn = unsafe extern "C" fn(*mut c_void, *const c_char, u8);

/// `art::ScopedSuspendAll::~ScopedSuspendAll()`
type ScopedSuspendAllDtorFn = unsafe extern "C" fn(*mut c_void);

/// `art::gc::ScopedGCCriticalSection::ScopedGCCriticalSection(Thread*, GcCause, CollectorType)`
type ScopedGCCriticalSectionCtorFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u32);

/// `art::gc::ScopedGCCriticalSection::~ScopedGCCriticalSection()`
type ScopedGCCriticalSectionDtorFn = unsafe extern "C" fn(*mut c_void);

/// `jobject art::JavaVMExt::AddGlobalRef(Thread*, ObjPtr<Object>)`
/// x0=this(JavaVMExt*), x1=Thread*, x2=mirror::Object*
type AddGlobalRefFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u64) -> *mut c_void;

// ============================================================================
// 符号表
// ============================================================================

struct ArtHeapApi {
    thread_current: ThreadCurrentFromGdbFn,
    decode_global_jobject: DecodeGlobalJObjectFn,
    ssa_ctor: ScopedSuspendAllCtorFn,
    ssa_dtor: ScopedSuspendAllDtorFn,
    sgcs_ctor: ScopedGCCriticalSectionCtorFn,
    sgcs_dtor: ScopedGCCriticalSectionDtorFn,
    add_global_ref: AddGlobalRefFn,
}

unsafe impl Send for ArtHeapApi {}
unsafe impl Sync for ArtHeapApi {}

static ART_HEAP_API: OnceLock<Option<ArtHeapApi>> = OnceLock::new();

/// 缓存 `mirror::Class::object_size_alloc_fast_path_` 偏移（按 libart 实际版本探测）。
static CLASS_OBJECT_SIZE_OFFSET: OnceLock<usize> = OnceLock::new();

/// 反汇编 `Class::SetObjectSizeAllocFastPath` 定位 `add xD, xN, #imm12` 指令，
/// imm12 即 object_size_alloc_fast_path_ 字段偏移。
///
/// 典型函数体只有 ~16 条指令，且必定含 `add xD, xN, #offset` 后紧跟 `ldar/stlr`。
/// 我们扫前 40 条指令，取第一个 imm12 ∈ [0x20, 0xC0] 的 64-bit ADD immediate。
/// 探测失败 fallback 到 `CLASS_OBJECT_SIZE_OFFSET_CANDIDATES[0]`（最现代版本的值）。
fn resolve_class_object_size_offset() -> usize {
    *CLASS_OBJECT_SIZE_OFFSET.get_or_init(|| unsafe {
        let fn_addr = crate::jsapi::module::libart_dlsym(
            "_ZN3art6mirror5Class26SetObjectSizeAllocFastPathEj",
        ) as u64;
        let fallback = CLASS_OBJECT_SIZE_OFFSET_CANDIDATES[0];
        if fn_addr == 0 {
            output_verbose(&format!(
                "[heap_scan] SetObjectSizeAllocFastPath 符号缺失, object_size_offset fallback {:#x}",
                fallback,
            ));
            return fallback;
        }
        // 遇 RET (0xd65f03c0) 停止扫描
        const RET: u32 = 0xd65f_03c0;
        for i in 0..40u64 {
            let insn = std::ptr::read_volatile((fn_addr + i * 4) as *const u32);
            if insn == RET {
                break;
            }
            // 64-bit ADD immediate, shift=0: 31:22 = 10010001 00
            if (insn & 0xFFC0_0000) == 0x9100_0000 {
                let imm12 = ((insn >> 10) & 0xFFF) as usize;
                let rd = (insn & 0x1F) as u8;
                let rn = ((insn >> 5) & 0x1F) as u8;
                if imm12 >= 0x20 && imm12 <= 0xC0 && rd != rn {
                    output_verbose(&format!(
                        "[heap_scan] object_size_offset = {:#x} (probed from SetObjectSizeAllocFastPath@{:#x})",
                        imm12, fn_addr,
                    ));
                    return imm12;
                }
            }
        }
        output_verbose(&format!(
            "[heap_scan] object_size_offset 反汇编探测失败, 经验 fallback {:#x} (候选 {:?})",
            fallback, CLASS_OBJECT_SIZE_OFFSET_CANDIDATES,
        ));
        fallback
    })
}

fn resolve_art_heap_api() -> Option<&'static ArtHeapApi> {
    ART_HEAP_API
        .get_or_init(|| unsafe {
            let mut missing: Vec<&str> = Vec::new();

            let resolve = |sym: &str, missing: &mut Vec<&'static str>, label: &'static str| -> u64 {
                let addr = crate::jsapi::module::libart_dlsym(sym) as u64;
                if addr == 0 {
                    missing.push(label);
                }
                addr
            };

            let thread_current =
                resolve("_ZN3art6Thread14CurrentFromGdbEv", &mut missing, "Thread::CurrentFromGdb");
            // Thread::DecodeGlobalJObject（API 36+）/ Thread::DecodeJObject（API ≤13）同签名：
            // x0=this, x1=jobject, 返回 mirror::Object* u64。按 Frida optionals 顺序尝试。
            let decode_global = crate::jsapi::module::dlsym_first_match(&[
                "_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject",
                "_ZNK3art6Thread13DecodeJObjectEP8_jobject",
            ]);
            if decode_global == 0 {
                missing.push("Thread::DecodeGlobalJObject/DecodeJObject");
            }
            let ssa_ctor = resolve(
                "_ZN3art16ScopedSuspendAllC1EPKcb",
                &mut missing,
                "ScopedSuspendAll::ctor",
            );
            let ssa_dtor = resolve(
                "_ZN3art16ScopedSuspendAllD1Ev",
                &mut missing,
                "ScopedSuspendAll::dtor",
            );
            let sgcs_ctor = resolve(
                "_ZN3art2gc23ScopedGCCriticalSectionC1EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE",
                &mut missing,
                "ScopedGCCriticalSection::ctor",
            );
            let sgcs_dtor = resolve(
                "_ZN3art2gc23ScopedGCCriticalSectionD1Ev",
                &mut missing,
                "ScopedGCCriticalSection::dtor",
            );
            // JavaVMExt::AddGlobalRef 的两条 ABI 变体（与 Frida android.js::optionals 对齐）：
            //   ObjPtr<mirror::Object> 变体（modern） vs 原生 Object* 变体（legacy pre-Android 9）
            // 同签名对 x0/x1/x2 = (JavaVMExt*, Thread*, Object*) 调用 ABI 等价。
            let add_global_ref = crate::jsapi::module::dlsym_first_match(&[
                "_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE",
                "_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE",
            ]);
            if add_global_ref == 0 {
                missing.push("JavaVMExt::AddGlobalRef");
            }

            if !missing.is_empty() {
                output_verbose(&format!(
                    "[heap_scan] libart symbols missing: {}",
                    missing.join(", ")
                ));
                return None;
            }

            Some(ArtHeapApi {
                thread_current: std::mem::transmute::<u64, ThreadCurrentFromGdbFn>(thread_current),
                decode_global_jobject: std::mem::transmute::<u64, DecodeGlobalJObjectFn>(decode_global),
                ssa_ctor: std::mem::transmute::<u64, ScopedSuspendAllCtorFn>(ssa_ctor),
                ssa_dtor: std::mem::transmute::<u64, ScopedSuspendAllDtorFn>(ssa_dtor),
                sgcs_ctor: std::mem::transmute::<u64, ScopedGCCriticalSectionCtorFn>(sgcs_ctor),
                sgcs_dtor: std::mem::transmute::<u64, ScopedGCCriticalSectionDtorFn>(sgcs_dtor),
                add_global_ref: std::mem::transmute::<u64, AddGlobalRefFn>(add_global_ref),
            })
        })
        .as_ref()
}

// ============================================================================
// 堆 VMA 枚举
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct HeapRegion {
    start: u64,
    end: u64,
}

/// 真正放用户 object 的 ART 堆 VMA。
///
/// **刻意不扫** `[anon:dalvik-non moving space]`：该空间存放 app 侧动态加载类的
/// `mirror::Class` 元数据，其字段（super_class_、component_type_ 等）含大量指向
/// framework class（Activity / Application / String ...）的引用。扫它会产生 100%
/// 的假阳性 —— 用户调 `Activity.getPackageName()` 时拿到的其实是 Class 对象，
/// JNI 调用走错 class 的 v-table 直接 abort。
///
/// Zygote space + main space 只放 instance，非常干净。
///
/// 名字匹配用 **前缀** 而不是相等：
/// API 31 CMC/CC GC 实际 VMA 是 `[anon:dalvik-main space (region space)]`
/// API 36 CMC GC 直接是 `[anon:dalvik-main space]` 或 `[anon:dalvik-region space]`
/// Android 8 RosAlloc 还会有 `[anon:dalvik-main space 1]`。
/// 统一按已知前缀匹配，防御不同 GC 后端的括号后缀。
fn is_app_heap_vma_name(name: &str) -> bool {
    const APP_HEAP_PREFIXES: &[&str] = &[
        "[anon:dalvik-main space",
        "[anon:dalvik-zygote space",
        "[anon:dalvik-large object space",
        "[anon:dalvik-free list large object space",
        "[anon:dalvik-large object free list space",
        "[anon:dalvik-region space",
    ];
    APP_HEAP_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// boot image VMA —— 形如 `[anon:dalvik-/system/framework/boot.art]`，无空格。
fn is_boot_image_vma_name(name: &str) -> bool {
    name.starts_with("[anon:dalvik-/") && name.ends_with(".art]")
}

/// 文件映射的 dalvik-cache `.art` —— 形如 `/data/dalvik-cache/arm64/...classes.art` 或
/// `/data/misc/apexdata/com.android.art/dalvik-cache/arm64/...classes.art`。
/// 这里存 app 级编译类的 mirror::Class 副本，App-level Activity 子类的 super_class_
/// 字段可能 fall 在这里。
fn is_dalvik_cache_art_file(name: &str) -> bool {
    (name.starts_with("/data/dalvik-cache/") || name.starts_with("/data/misc/apexdata/"))
        && name.ends_with(".art")
}

/// 自己解析 /proc/self/maps 的一行。标准 `util::proc_maps_entries` 走 `split_whitespace`，
/// 会把带空格的 VMA 名（如 `[anon:dalvik-main space]`）截成第一个词（`[anon:dalvik-main`）。
/// 本地版本保留完整路径。
fn parse_maps_line(line: &str) -> Option<(u64, u64, &str, &str)> {
    // format: START-END PERMS OFFSET DEV INODE [spaces] PATH (可含空格)
    let mut rest = line.trim_start();
    let sp1 = rest.find(' ')?;
    let range = &rest[..sp1];
    rest = rest[sp1..].trim_start();
    let sp2 = rest.find(' ')?;
    let perms = &rest[..sp2];
    rest = rest[sp2..].trim_start();
    let sp3 = rest.find(' ')?;
    // offset
    rest = rest[sp3..].trim_start();
    let sp4 = rest.find(' ')?;
    // dev
    rest = rest[sp4..].trim_start();
    let sp5 = rest.find(|c: char| c.is_whitespace())?;
    // inode
    rest = rest[sp5..].trim_start();
    // rest 现在就是 PATH（可空 或 "[anon:dalvik-main space]"），去掉尾部换行
    let path = rest.trim_end();

    let mut parts = range.splitn(2, '-');
    let start = u64::from_str_radix(parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(parts.next()?, 16).ok()?;
    Some((start, end, perms, path))
}

/// non-moving space 存 app 级 Class 元数据；单独列出来是因为它能容纳 mirror::Class*
/// 但不该参与 instance scan（避免 Class 元字段的假阳性）。
fn is_non_moving_space_name(name: &str) -> bool {
    name == "[anon:dalvik-non moving space]"
}

/// 返回 (scan_regions, class_range_regions)：
/// - `scan_regions`：真正扫 instance 的空间（main + zygote + large object）
/// - `class_range_regions`：valid `mirror::Class*` 可能存放的所有 VMA。
///
/// **app 级类的存储位置**：API 36 上观察到 app 编译后的 mirror::Class 对象有时落在
/// **匿名无名 `rw-p` 区域**（紧挨 jit-cache 的纯 mmap 块）—— 不带 `[anon:dalvik-*]`
/// 标签。为了让 `subtypes:true` 能看到这些类，我们把所有 `rw-p` 无路径区都纳入
/// `class_range_regions`。读出来非 Class 的位置会被 `class_of_class==java.lang.Class`
/// 校验过滤掉。
fn enumerate_heap_regions() -> (Vec<HeapRegion>, Vec<HeapRegion>) {
    let maps = match read_proc_self_maps() {
        Some(s) => s,
        None => return (Vec::new(), Vec::new()),
    };

    let mut scan_regions = Vec::new();
    let mut class_range_regions = Vec::new();
    for line in maps.lines() {
        let (start, end, perms, path) = match parse_maps_line(line) {
            Some(v) => v,
            None => continue,
        };
        if !perms.starts_with('r') {
            continue;
        }

        if path.is_empty() {
            // 无名匿名 rw-p：可能是 ART class linker 用 mmap 直接申请的 class 存储区
            // （API 36 CMC GC 下 app 级 mirror::Class 实际就在这里）。纳入
            // class_range_regions 让 subtypes 能命中。
            // 不纳入 scan_regions —— 这里没有 instance。
            // 跳过过大的区（>256MB）避免扫无关 mmap (libpath cache, jemalloc 大页等)。
            if perms.starts_with("rw") && (end - start) <= (256u64 << 20) {
                class_range_regions.push(HeapRegion { start, end });
            }
            continue;
        }

        if is_app_heap_vma_name(path) {
            let reg = HeapRegion { start, end };
            scan_regions.push(reg);
            class_range_regions.push(reg);
        } else if is_non_moving_space_name(path)
            || is_boot_image_vma_name(path)
            || is_dalvik_cache_art_file(path)
        {
            class_range_regions.push(HeapRegion { start, end });
        }
    }

    (scan_regions, class_range_regions)
}

// ============================================================================
// super_class_ 偏移探测（运行时一次性）
// ============================================================================

/// 缓存 mirror::Class::super_class_ 的偏移。`Some(0)` 表示探测失败永久关闭；
/// `Some(n)` 表示成功；`None` 表示尚未探测。
static SUPER_CLASS_OFFSET: OnceLock<Option<usize>> = OnceLock::new();

/// 通过两组已知 super 关系交叉验证 super_class_ 字段在 mirror::Class 内的偏移。
///
/// - 关系 1: `String.class.getSuperclass() == Object.class`
/// - 关系 2: `Integer.class.getSuperclass() == Number.class`
///
/// 思路：在 [8..96] 范围里逐 4B 扫描两组 child class，取 BOTH 同时命中对应 parent
/// 的偏移作为答案。两组关系都满足的偏移基本不可能是巧合。
fn probe_super_class_offset(env: JniEnv, api: &ArtHeapApi, self_thread: *mut c_void) -> Option<usize> {
    *SUPER_CLASS_OFFSET.get_or_init(|| unsafe {
        let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        let delete_global_ref: DeleteGlobalRefFn =
            jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);

        let probe_one = |class_name: &str| -> Option<u64> {
            let local = find_class_safe(env, class_name);
            if local.is_null() {
                return None;
            }
            let global = new_global_ref(env, local);
            delete_local_ref(env, local);
            if global.is_null() {
                return None;
            }
            let obj = (api.decode_global_jobject)(self_thread, global);
            delete_global_ref(env, global);
            if obj == 0 || (obj >> 32) != 0 {
                return None;
            }
            Some(obj)
        };

        let str_cls = probe_one("java.lang.String")?;
        let obj_cls = probe_one("java.lang.Object")?;
        let int_cls = probe_one("java.lang.Integer")?;
        let num_cls = probe_one("java.lang.Number")?;

        let obj_low32 = obj_cls as u32;
        let num_low32 = num_cls as u32;

        // 同时满足两组关系的偏移
        let mut hits: Vec<usize> = Vec::new();
        let mut off = SUPER_CLASS_PROBE_MIN;
        while off <= SUPER_CLASS_PROBE_MAX {
            let v_str = std::ptr::read_volatile((str_cls + off as u64) as *const u32);
            let v_int = std::ptr::read_volatile((int_cls + off as u64) as *const u32);
            if v_str == obj_low32 && v_int == num_low32 {
                hits.push(off);
            }
            off += 4;
        }

        match hits.len() {
            1 => {
                output_verbose(&format!(
                    "[heap_scan] super_class_ offset = {} (cross-validated String→Object & Integer→Number)",
                    hits[0]
                ));
                Some(hits[0])
            }
            0 => {
                output_verbose("[heap_scan] super_class_ probe: 0 cross-validated candidates — subtypes disabled");
                None
            }
            _ => {
                let pick = *hits.first().unwrap();
                output_verbose(&format!(
                    "[heap_scan] super_class_ probe: ambiguous after cross-val {:?}, picking {}",
                    hits, pick
                ));
                Some(pick)
            }
        }
    })
}

/// 枚举 class_range_regions 中所有 super_class 链能到达 `needle_low32` 的 mirror::Class*
/// （含 needle 自身）。要求 super_class_ 偏移已知。
///
/// 该函数在 SuspendAll + GC critical 下调用：raw memory reads only。
///
/// `stats` 统计被各种原因拒绝的 candidate 数量（仅用于诊断）。
unsafe fn collect_subclass_set(
    class_range_regions: &[HeapRegion],
    needle_low32: u32,
    java_lang_class_low32: u32,
    super_class_offset: usize,
    stats: &mut SuperWalkStats,
) -> HashSet<u32> {
    let mut accept: HashSet<u32> = HashSet::new();
    accept.insert(needle_low32);

    for region in class_range_regions {
        let mut addr = region.start;
        let limit = region.end;
        while addr + 8 <= limit {
            let class_of_class = std::ptr::read_volatile(addr as *const u32);
            if class_of_class != java_lang_class_low32 {
                addr += OBJECT_ALIGNMENT;
                continue;
            }

            let candidate = addr as u32;
            stats.total_candidates += 1;
            if accept.contains(&candidate) {
                accept.insert(candidate);
                addr += OBJECT_ALIGNMENT;
                continue;
            }
            if super_chain_reaches(
                candidate,
                needle_low32,
                java_lang_class_low32,
                super_class_offset,
                class_range_regions,
                &accept,
                stats,
            ) {
                accept.insert(candidate);
            }

            addr += OBJECT_ALIGNMENT;
        }
    }

    accept
}

#[derive(Default, Debug)]
struct SuperWalkStats {
    total_candidates: usize,
    aborted_super_oor: usize,    // super_addr 超出 class_range
    aborted_null_super: usize,   // super == 0（Object）
    aborted_self_loop: usize,
    aborted_next_oor: usize,     // super 指向的 class 不在 class_range
    aborted_not_class: usize,    // super 指向的位置 class_of_class 不对
    aborted_depth: usize,        // 超过最大深度
}

#[inline]
unsafe fn super_chain_reaches(
    start_class: u32,
    target: u32,
    java_lang_class_low32: u32,
    super_class_offset: usize,
    class_range_regions: &[HeapRegion],
    known_subclasses: &HashSet<u32>,
    stats: &mut SuperWalkStats,
) -> bool {
    let mut cur = start_class;
    for _ in 0..MAX_SUPER_CLASS_DEPTH {
        if cur == target {
            return true;
        }
        if known_subclasses.contains(&cur) {
            return true;
        }
        let super_addr = (cur as u64) + super_class_offset as u64;
        if !address_in_any_region(super_addr, class_range_regions) {
            stats.aborted_super_oor += 1;
            return false;
        }
        let next = std::ptr::read_volatile(super_addr as *const u32);
        if next == 0 {
            stats.aborted_null_super += 1;
            return false;
        }
        if next == cur {
            stats.aborted_self_loop += 1;
            return false;
        }
        let next_full = next as u64;
        if !address_in_any_region(next_full, class_range_regions) {
            stats.aborted_next_oor += 1;
            return false;
        }
        let next_class_of_class = std::ptr::read_volatile(next_full as *const u32);
        if next_class_of_class != java_lang_class_low32 {
            stats.aborted_not_class += 1;
            return false;
        }
        cur = next;
    }
    stats.aborted_depth += 1;
    false
}

// ============================================================================
// 核心接口
// ============================================================================

/// 枚举指定 class 的所有存活实例。返回一组 global ref jobject。
///
/// `class_jobject` 必须是 global ref（由 find_class_safe 返回并 cache 过）。
/// `include_subtypes=true` 时同时返回所有子类实例（依赖 super_class_ 字段偏移探测，
/// 探测失败会自动降级为 false）。
/// `max_count`：最多返回多少 hit。0 表示不限。**强烈建议 ≤ 16384** —— ART 默认 JNI
/// global ref table 上限约 51200，无限扫 String.class 之类的高频类会瞬间填满崩进程。
///
/// 失败返回 Err(msg)，常见原因：
///   - libart 符号缺失（非 Android 或异常 ART 版本）
///   - 找不到 ART 堆 VMA（/proc/self/maps 读失败）
pub(super) unsafe fn heap_scan_enumerate_instances(
    env: JniEnv,
    class_global_ref: *mut c_void,
    include_subtypes: bool,
    max_count: usize,
) -> Result<Vec<*mut c_void>, String> {
    let api = resolve_art_heap_api().ok_or_else(|| {
        "[heap_scan] libart symbols unavailable (ART internal layout changed?)".to_string()
    })?;

    // 当前线程对应的 art::Thread*
    let self_thread = (api.thread_current)();
    if self_thread.is_null() {
        return Err("[heap_scan] Thread::CurrentFromGdb returned null".to_string());
    }

    // Decode jclass → mirror::Class*（needle 完整 64 位地址）
    let needle_obj = (api.decode_global_jobject)(self_thread, class_global_ref);
    if needle_obj == 0 {
        return Err("[heap_scan] DecodeGlobalJObject(class) returned null".to_string());
    }

    // 拿 java.lang.Class 的 mirror::Class* —— 所有合法 mirror::Class 的 class_ 字段
    // （即首 4 字节）都指向它。用作"候选位置确实是一个 Class 对象"的强校验。
    //
    // DecodeGlobalJObject 按 tag (obj & 0x3) 分派，local ref tag=0 走 fallback 路径，
    // 这条路径在 API 36 上会 access some stale state 导致 SIGSEGV；所以必须传 global ref。
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let delete_global_ref: DeleteGlobalRefFn =
        jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);

    let java_lang_class_local = find_class_safe(env, "java.lang.Class");
    if java_lang_class_local.is_null() {
        return Err("[heap_scan] java.lang.Class not found".to_string());
    }
    let java_lang_class_global = new_global_ref(env, java_lang_class_local);
    delete_local_ref(env, java_lang_class_local);
    if java_lang_class_global.is_null() {
        return Err("[heap_scan] NewGlobalRef(java.lang.Class) failed".to_string());
    }
    let java_lang_class_obj = (api.decode_global_jobject)(self_thread, java_lang_class_global);
    delete_global_ref(env, java_lang_class_global);

    if java_lang_class_obj == 0 {
        return Err("[heap_scan] DecodeGlobalJObject(java.lang.Class) returned null".to_string());
    }
    if (java_lang_class_obj >> 32) != 0 {
        return Err(format!(
            "[heap_scan] java.lang.Class {:#x} above 4GB",
            java_lang_class_obj
        ));
    }
    let java_lang_class_low32 = java_lang_class_obj as u32;

    let (scan_regions, class_range_regions) = enumerate_heap_regions();
    if scan_regions.is_empty() {
        return Err("[heap_scan] no [anon:dalvik-*] heap VMAs in /proc/self/maps".to_string());
    }
    output_verbose(&format!(
        "[heap_scan] regions: scan={} class_range={} needle={:#x} java.lang.Class={:#x}",
        scan_regions.len(),
        class_range_regions.len(),
        needle_obj,
        java_lang_class_obj,
    ));

    // JavaVMExt* = JavaVM*（ART 子类）
    let vm_ptr = {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(state) => state.vm,
            None => return Err("[heap_scan] JNI state has no JavaVM*".to_string()),
        }
    };
    if vm_ptr.is_null() {
        return Err("[heap_scan] JavaVM* is null".to_string());
    }

    // 扫描窗口需要满足：needle_obj 的 low32 用作匹配 key（heap 在低 4GB 时等于完整指针）
    if (needle_obj >> 32) != 0 {
        // 若 needle_obj 超 4GB —— 说明这台设备 ART 没开启 heap-in-low-4GB，我们做法失效
        return Err(format!(
            "[heap_scan] needle {:#x} above 4GB; compressed-ref assumption broken",
            needle_obj
        ));
    }
    let needle_low32 = needle_obj as u32;

    // 探测 super_class_ 偏移（仅 subtypes=true 时需要；首次调用做缓存）
    let super_offset = if include_subtypes {
        probe_super_class_offset(env, api, self_thread)
    } else {
        None
    };
    if include_subtypes && super_offset.is_none() {
        output_verbose("[heap_scan] subtypes 请求但 super_class_ 偏移探测失败，退化为 exact match");
    }

    // object_size_alloc_fast_path_ 字段偏移（版本敏感，首次调用做缓存）
    let class_obj_size_off = resolve_class_object_size_offset();

    // RAII：ScopedSuspendAll + ScopedGCCriticalSection
    let cause_cstr = CString::new("rustFrida Java.choose").unwrap();
    let mut sgcs_storage = [0u64; SGCS_STORAGE_BYTES / 8];

    // 进入 stop-the-world
    (api.ssa_ctor)(std::ptr::null_mut(), cause_cstr.as_ptr() as *const c_char, 0);

    // 扫描本身不会再触发 GC，但 ScopedGCCriticalSection 作双保险：
    // 避免任何可能 trigger GC 的路径在我们扫描期间插队（例如 AddGlobalRef 的惰性扩表）。
    // ctor 会读 Thread 内部状态，必须在 SuspendAll 之后调用（self_thread 此时仍然合法，
    // 因为我们就是发起 SuspendAll 的那个线程，不会被自己挂起）。
    (api.sgcs_ctor)(
        sgcs_storage.as_mut_ptr() as *mut c_void,
        self_thread,
        K_GC_CAUSE_DEBUGGER,
        K_COLLECTOR_TYPE_HEAP_TRIM,
    );

    // 扫描（用 catch_unwind 兜底，防止任何 panic 导致 SuspendAll 没 resume 吊死进程）
    let scan_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut walk_stats = SuperWalkStats::default();
        let accept_set = if let Some(off) = super_offset {
            collect_subclass_set(
                &class_range_regions,
                needle_low32,
                java_lang_class_low32,
                off,
                &mut walk_stats,
            )
        } else {
            let mut s = HashSet::new();
            s.insert(needle_low32);
            s
        };
        let hits = scan_regions_for_class_set(
            &scan_regions,
            &class_range_regions,
            &accept_set,
            java_lang_class_low32,
            max_count,
            class_obj_size_off,
        );
        (hits, accept_set.len(), walk_stats)
    }));

    // RAII 对偶析构（倒序）
    (api.sgcs_dtor)(sgcs_storage.as_mut_ptr() as *mut c_void);
    (api.ssa_dtor)(std::ptr::null_mut());

    let (hits, accept_count, walk_stats) = match scan_result {
        Ok(v) => v,
        Err(_) => return Err("[heap_scan] scan panicked".to_string()),
    };

    output_verbose(&format!(
        "[heap_scan] raw hits = {} (accept_set size = {})",
        hits.len(),
        accept_count
    ));
    if include_subtypes {
        output_verbose(&format!(
            "[heap_scan] super-walk stats: candidates={} aborted=(super_oor={} null={} self={} next_oor={} not_class={} depth={})",
            walk_stats.total_candidates,
            walk_stats.aborted_super_oor,
            walk_stats.aborted_null_super,
            walk_stats.aborted_self_loop,
            walk_stats.aborted_next_oor,
            walk_stats.aborted_not_class,
            walk_stats.aborted_depth,
        ));
    }


    // 把 mirror::Object* 包成 JNI global ref
    let mut global_refs = Vec::with_capacity(hits.len());
    // 用 HashSet 去重 —— 扫描中理论上不会重复，但 large object space 某些对象 8B 对齐
    // 后可能命中多个位置；双重校验已经过滤大部分，这里再去一次。
    let mut seen: HashSet<u64> = HashSet::new();
    for obj in hits {
        if !seen.insert(obj) {
            continue;
        }
        let jobj = (api.add_global_ref)(vm_ptr, self_thread, obj);
        if jobj.is_null() {
            jni_check_exc(env);
            continue;
        }
        global_refs.push(jobj);
    }

    Ok(global_refs)
}

/// 扫描主函数 —— 在 SuspendAll + GC critical 保护下执行。
/// 不调用任何可能触发 GC / JNI 的函数。
///
/// 策略：**对象步进扫描**。按 `mirror::Class::object_size_alloc_fast_path_` 跳过整个
/// 对象占用的字节数，保证我们只检查真正的 object 起点。
///
/// 对 array class（`object_size_alloc_fast_path_ == 0`）和异常/未知 class，保守按 8B
/// 步进。
///
/// `accept_set`：本次要匹配的所有 mirror::Class*.low32 集合（exact 模式只含 needle，
/// subtypes 模式含 needle + 全部子类）。
#[inline(never)]
unsafe fn scan_regions_for_class_set(
    app_regions: &[HeapRegion],
    class_range_regions: &[HeapRegion],
    accept_set: &HashSet<u32>,
    java_lang_class_low32: u32,
    max_count: usize,
    class_obj_size_off: usize,
) -> Vec<u64> {
    let mut hits = Vec::new();
    let cap = if max_count == 0 { usize::MAX } else { max_count };

    'outer: for region in app_regions {
        let mut addr = region.start;
        let limit = region.end;

        while addr + 8 <= limit {
            let class_ptr_low32 = std::ptr::read_volatile(addr as *const u32);

            if class_ptr_low32 == 0 {
                // 空位：BumpPointerSpace 允许块末尾有 zero padding。
                addr += OBJECT_ALIGNMENT;
                continue;
            }

            let class_ptr = class_ptr_low32 as u64;

            // class 必须落在 heap 或 boot image
            if !address_in_any_region(class_ptr, class_range_regions) {
                addr += OBJECT_ALIGNMENT;
                continue;
            }

            // 强校验：class_ptr 指向的 mirror::Class 对象，其首 4 字节（它自己的 class_）
            // 必须等于 java.lang.Class 的低 32 位。
            let class_of_class = std::ptr::read_volatile(class_ptr as *const u32);
            if class_of_class != java_lang_class_low32 {
                addr += OBJECT_ALIGNMENT;
                continue;
            }

            // addr 是真正的 object 起点。检查 class 是否在 accept 集合内。
            if accept_set.contains(&class_ptr_low32) {
                hits.push(addr);
                if hits.len() >= cap {
                    break 'outer;
                }
            }

            // 跳过整个对象
            let step = object_step_bytes(class_ptr, class_obj_size_off);
            addr += step;
        }
    }

    hits
}

/// 给定一个 mirror::Class*，返回该类实例占用字节数（已向 8B 对齐）。
/// 失败或不可推断（array / primitive class）返回 8，退化为保守步进。
#[inline]
unsafe fn object_step_bytes(class_ptr: u64, class_obj_size_off: usize) -> u64 {
    let size_addr = class_ptr + class_obj_size_off as u64;
    let raw = std::ptr::read_volatile(size_addr as *const u32);

    if raw == 0 || raw > MAX_REASONABLE_OBJECT_SIZE {
        // array/primitive/corrupt — fallback 保守步进
        return OBJECT_ALIGNMENT;
    }
    // 向 8 字节对齐
    ((raw as u64) + OBJECT_ALIGNMENT - 1) & !(OBJECT_ALIGNMENT - 1)
}

#[inline]
fn address_in_any_region(addr: u64, regions: &[HeapRegion]) -> bool {
    regions.iter().any(|r| addr >= r.start && addr + 4 <= r.end)
}

