//! ArtThread 结构体字段偏移探测 — 对标 Frida _getArtThreadSpec
//!
//! 通过扫描 Thread 结构体中的 JNIEnv 指针位置，反推 exception_、
//! managed_stack_、self_、top_handle_scope_ 等字段偏移。
//! 兼容 Android 5.x (API 22) 到最新版本的布局变化。

#![allow(dead_code)]

use std::sync::OnceLock;

use super::jni_core::get_android_api_level;
use super::jni_core::JniEnv;
use super::safe_mem::{refresh_mem_regions, safe_read_u64};
use super::PAC_STRIP_MASK;
use crate::jsapi::console::output_verbose;

// ============================================================================
// ManagedStack 布局规格 — 按 API level 硬编码 (对标 Frida getManagedStackSpec)
// ============================================================================

/// ManagedStack 结构体字段偏移规格
///
/// ManagedStack 是 ART Thread 中管理 ShadowFrame 链表的结构体。
/// 字段偏移因 API level 不同而异。
pub(super) struct ManagedStackSpec {
    /// top_quick_frame_ 偏移
    pub top_quick_frame_offset: usize,
    /// link_ 偏移（指向上一个 ManagedStack）
    pub link_offset: usize,
}

static MANAGED_STACK_SPEC: OnceLock<ManagedStackSpec> = OnceLock::new();

/// 获取 ManagedStack 布局规格（按 API level 硬编码，对标 Frida getManagedStackSpec）
///
/// API >= 23 (Android 6+): top_quick_frame=0, link=8
/// API < 23 (Android 5.x): top_quick_frame=16, link=0
pub(super) fn get_managed_stack_spec() -> &'static ManagedStackSpec {
    MANAGED_STACK_SPEC.get_or_init(|| {
        let api_level = get_android_api_level();
        let spec = if api_level >= 23 {
            ManagedStackSpec {
                top_quick_frame_offset: 0,
                link_offset: 8,
            }
        } else {
            ManagedStackSpec {
                top_quick_frame_offset: 16,
                link_offset: 0,
            }
        };
        output_verbose(&format!(
            "[managed stack] API {}: top_quick_frame={}, link={}",
            api_level, spec.top_quick_frame_offset, spec.link_offset
        ));
        spec
    })
}

// ============================================================================
// ArtThread 布局规格 — 动态探测 (Frida-style)
// ============================================================================

/// ArtThread 结构体字段偏移规格
///
/// 通过扫描 Thread 内存中的 JNIEnv 指针位置，动态推算各关键字段偏移。
/// 字段含义:
/// - exception_: 当前线程的 pending exception (mirror::Throwable*)
/// - managed_stack_: 托管栈（ShadowFrame 链表头）
/// - self_: Thread 自引用指针
/// - top_handle_scope_: HandleScope 链表头（JNI local/global ref 管理）
/// - is_exception_reported_offset: API ≤ 22 特有，异常是否已报告给 instrumentation
/// - throw_location_offset: API ≤ 22 特有，异常抛出位置 (ThrowLocation)
pub(super) struct ArtThreadSpec {
    pub exception_offset: usize,
    pub managed_stack_offset: usize,
    pub self_offset: usize,
    pub top_handle_scope_offset: usize,
    /// API ≤ 22: is_exception_reported_to_instrumentation_ 偏移，None 表示不可用
    pub is_exception_reported_offset: Option<usize>,
    /// API ≤ 22: throw_location_ 偏移 (ThrowLocation, 3 指针大小)，None 表示不可用
    pub throw_location_offset: Option<usize>,
}

pub(super) static ART_THREAD_SPEC: OnceLock<Option<ArtThreadSpec>> = OnceLock::new();

/// 获取 ArtThread 偏移规格（首次调用时探测并缓存）
pub(super) fn get_art_thread_spec(env: JniEnv) -> Option<&'static ArtThreadSpec> {
    ART_THREAD_SPEC.get_or_init(|| probe_art_thread_spec(env)).as_ref()
}

/// 探测 ArtThread 布局偏移（对标 Frida _getArtThreadSpec）
///
/// 算法:
/// 1. 从 JNIEnvExt 读取 self_ (Thread*) 指针
/// 2. 在 Thread 结构体中扫描 JNIEnv 指针位置 (offset 144..384)
/// 3. 根据 JNIEnv 偏移和 API 级别反推其他字段偏移
fn probe_art_thread_spec(env: JniEnv) -> Option<ArtThreadSpec> {
    let env_ptr = env as u64;

    // Step 1: 从 JNIEnvExt 获取 Thread* 指针
    // JNIEnvExt 布局: { JNINativeInterface* functions, Thread* self_, ... }
    // 所以 *(env + 8) 是 Thread*
    let thread_ptr = unsafe { *((env_ptr as usize + 8) as *const u64) };
    let thread = thread_ptr & PAC_STRIP_MASK;

    if thread == 0 {
        output_verbose("[art thread] Thread 指针为空");
        return None;
    }

    output_verbose(&format!(
        "[art thread] JNIEnv={:#x}, Thread*={:#x} (raw={:#x})",
        env_ptr, thread, thread_ptr
    ));

    // 刷新内存映射缓存，保护后续扫描
    refresh_mem_regions();

    // Step 2: 在 Thread 结构体中扫描 JNIEnv 指针
    // JNIEnv 指针通常位于 Thread 的 tlsPtr_.jni_env 字段
    // 扫描范围 144..384 覆盖 Android 5.x 到最新版本的已知布局
    let env_stripped = env_ptr & PAC_STRIP_MASK;
    let mut jni_env_offset: Option<usize> = None;

    for offset in (144..384).step_by(8) {
        let val = unsafe { safe_read_u64(thread + offset as u64) };
        let val_stripped = val & PAC_STRIP_MASK;
        if val_stripped == env_stripped {
            jni_env_offset = Some(offset);
            output_verbose(&format!(
                "[art thread] 找到 jni_env 在 Thread+{} (value={:#x})",
                offset, val
            ));
            break;
        }
    }

    let n = match jni_env_offset {
        Some(off) => off,
        None => {
            output_verbose("[art thread] Thread 中未找到 JNIEnv 指针 (扫描范围 144..384)");
            return None;
        }
    };

    let api_level = get_android_api_level();
    const PTR: usize = 8; // ARM64 pointer size

    // Step 3: 根据 JNIEnv 偏移回推其他字段（对标 Frida _getArtThreadSpec）
    //
    // Thread 结构体中 jni_env 之前的字段布局因 API 级别不同而有差异:
    // - exception_: pending exception 指针
    // - managed_stack_: ManagedStack (包含 top_shadow_frame_ 和 link_)
    // API <= 22: exception 在 jni_env 前 7 个指针位
    // API >= 23: exception 在 jni_env 前 6 个指针位
    let mut exception_offset = n - 6 * PTR;
    let mut managed_stack_offset = n - 4 * PTR;
    let mut self_offset = n + 2 * PTR;

    // API ≤ 22 特有字段（对标 Frida _getArtThreadSpec）
    let mut is_exception_reported_offset: Option<usize> = None;
    let mut throw_location_offset: Option<usize> = None;

    if api_level <= 22 {
        // Android 5.x: exception 前多了 is_exception_reported_to_instrumentation_
        exception_offset -= PTR;
        managed_stack_offset -= PTR;
        self_offset -= PTR;

        // 对标 Frida: isExceptionReportedOffset = exceptionOffset - pointerSize - (9*8) - (3*4)
        is_exception_reported_offset = Some(exception_offset - PTR - 9 * 8 - 3 * 4);

        // 对标 Frida: throwLocationOffset = jni_env + 6 * pointerSize
        throw_location_offset = Some(n + 6 * PTR);
    }

    // top_handle_scope_ 在 jni_env 之后更远处
    let mut top_handle_scope_offset = n + 9 * PTR;
    if api_level <= 22 {
        // Android 5.x: 额外 2 个指针 + 1 个 4 字节字段 (对齐 Frida: (2 * pointerSize) + 4)
        top_handle_scope_offset += 2 * PTR + 4;
    }
    if api_level >= 23 {
        // Android 6+: 增加了 tmp_jni_env_ 字段 (8 字节)
        top_handle_scope_offset += PTR;
    }

    output_verbose(&format!(
        "[art thread] 探测成功 (API {}): exception={}, managed_stack={}, self={}, top_handle_scope={}, \
         is_exception_reported={:?}, throw_location={:?}",
        api_level,
        exception_offset,
        managed_stack_offset,
        self_offset,
        top_handle_scope_offset,
        is_exception_reported_offset,
        throw_location_offset
    ));

    Some(ArtThreadSpec {
        exception_offset,
        managed_stack_offset,
        self_offset,
        top_handle_scope_offset,
        is_exception_reported_offset,
        throw_location_offset,
    })
}
