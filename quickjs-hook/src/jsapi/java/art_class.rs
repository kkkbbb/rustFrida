//! ArtClass (mirror::Class) 字段偏移探测 — 对标 Frida getArtClassSpec
//!
//! 通过 JNI 反射获取已知类 (java/lang/Thread) 的字段/方法引用，
//! 然后扫描 mirror::Class 对象内存定位 ifields_、sfields_、methods_ 和
//! copied_methods_offset_ 偏移。

#![allow(dead_code)]

use std::sync::OnceLock;

use super::art_method::get_art_field_spec;
use super::jni_core::*;
use super::safe_mem::{refresh_mem_regions, safe_read_u16, safe_read_u32, safe_read_u64};
use super::PAC_STRIP_MASK;
use crate::jsapi::console::output_verbose;
use crate::jsapi::module::libart_dlsym;

// ============================================================================
// ArtClass 布局规格 — 动态探测 (Frida-style)
// ============================================================================

/// ArtClass 结构体（mirror::Class）字段偏移规格
///
/// 通过扫描 mirror::Class 对象中的 ArtField/ArtMethod 数组指针,
/// 动态发现各字段数组偏移。对标 Frida getArtClassSpec。
pub(super) struct ArtClassSpec {
    /// 实例字段数组偏移 (ifields_)
    pub ifields_offset: usize,
    /// 静态字段数组偏移 (sfields_)
    pub sfields_offset: usize,
    /// 方法数组偏移 (methods_)
    pub methods_offset: usize,
    /// 拷贝方法数量偏移 (copied_methods_offset_)
    pub copied_methods_offset: usize,
}

static ART_CLASS_SPEC: OnceLock<Option<ArtClassSpec>> = OnceLock::new();

/// 获取 ArtClass 偏移规格（首次调用时探测并缓存）
pub(super) fn get_art_class_spec(env: JniEnv) -> Option<&'static ArtClassSpec> {
    ART_CLASS_SPEC.get_or_init(|| probe_art_class_spec(env)).as_ref()
}

/// 探测 ArtClass 布局偏移（对标 Frida getArtClassSpec）
///
/// 算法:
/// 1. 获取已知类 java/lang/Thread 的 jclass，转为 global ref
/// 2. 获取该类的已知字段 (MAX_PRIORITY, name) 和方法 (getName) 的 ArtField*/ArtMethod* 地址
/// 3. 在 Runnable 状态下解码 global ref 为 mirror::Class* 并扫描
/// 4. 扫描 Class 对象内存，查找包含已知指针的 LengthPrefixedArray
/// 5. 对于 copiedMethodsOffset，从 methods_ 起搜索等于 methods array length 的 u16
fn probe_art_class_spec(env: JniEnv) -> Option<ArtClassSpec> {
    output_verbose("[art class] 开始 ArtClass 布局探测...");

    let field_spec = get_art_field_spec()?;
    let method_spec = ART_METHOD_SPEC.get()?;

    unsafe {
        // Step 1: 获取 java/lang/Thread 的 jclass，转为 global ref（GC 安全）
        let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
        let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
        let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
        let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
        let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
        let delete_global_ref: DeleteGlobalRefFn = jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        let c_thread = std::ffi::CString::new("java/lang/Thread").unwrap();
        let cls_local = find_class(env, c_thread.as_ptr());
        if cls_local.is_null() || jni_check_exc(env) {
            output_verbose("[art class] FindClass(java/lang/Thread) 失败");
            return None;
        }

        // 转为 global ref: DecodeJObject 对 global ref 更可靠，
        // 且避免 GC 移动对象导致扫描时读到脏数据
        let cls_global = new_global_ref(env, cls_local);
        delete_local_ref(env, cls_local);
        if cls_global.is_null() {
            output_verbose("[art class] NewGlobalRef 失败");
            return None;
        }

        // Step 2: 获取已知字段/方法 ID
        let c_max_pri = std::ffi::CString::new("MAX_PRIORITY").unwrap();
        let c_int_sig = std::ffi::CString::new("I").unwrap();
        let c_name = std::ffi::CString::new("name").unwrap();
        let c_string_sig = std::ffi::CString::new("Ljava/lang/String;").unwrap();
        let c_get_name = std::ffi::CString::new("getName").unwrap();
        let c_get_name_sig = std::ffi::CString::new("()Ljava/lang/String;").unwrap();

        jni_check_exc(env);
        let static_field_id = get_static_field_id(env, cls_global, c_max_pri.as_ptr(), c_int_sig.as_ptr());
        jni_check_exc(env);
        let instance_field_id = get_field_id(env, cls_global, c_name.as_ptr(), c_string_sig.as_ptr());
        jni_check_exc(env);
        let method_id = get_method_id(env, cls_global, c_get_name.as_ptr(), c_get_name_sig.as_ptr());
        jni_check_exc(env);

        if static_field_id.is_null() && instance_field_id.is_null() && method_id.is_null() {
            output_verbose("[art class] 所有引用获取失败");
            delete_global_ref(env, cls_global);
            return None;
        }

        output_verbose(&format!(
            "[art class] Thread: static_field={:#x}, instance_field={:#x}, method={:#x}",
            static_field_id as u64, instance_field_id as u64, method_id as u64
        ));

        // Step 3: 解码 ID → 真实指针
        // jfieldID 在 API 30+ 可能是 opaque index 而非 ArtField*，需解码
        // jmethodID 可能是 opaque (API 30+)，使用 decode_method_id
        let art_field_static = super::reflect::decode_field_id(env, cls_global, static_field_id as u64, true);
        let art_field_instance = super::reflect::decode_field_id(env, cls_global, instance_field_id as u64, false);
        let art_method_instance = super::reflect::decode_method_id(env, cls_global, method_id as u64, false);

        output_verbose(&format!(
            "[art class] 解码后: static_field={:#x}, instance_field={:#x}, method={:#x}",
            art_field_static, art_field_instance, art_method_instance
        ));

        // Step 4: 在 Runnable 状态下解码 global ref → mirror::Class* 并扫描
        // 对标 Frida withRunnableArtThread: CC GC 可能在 kNative 下移动堆对象，
        // 需要在 kRunnable 状态下访问 mirror::Object* 裸指针以阻止 GC 移动
        let f_entry_size = field_spec.size;
        let m_entry_size = method_spec.size;

        let scan_result = with_runnable_thread(env, || {
            scan_class_layout(
                env,
                cls_global,
                art_field_static,
                art_field_instance,
                art_method_instance,
                f_entry_size,
                m_entry_size,
            )
        });

        delete_global_ref(env, cls_global);

        let spec = scan_result?;

        output_verbose(&format!(
            "[art class] 探测成功: ifields={}, sfields={}, methods={}, copied_methods={}",
            spec.ifields_offset, spec.sfields_offset, spec.methods_offset, spec.copied_methods_offset
        ));

        Some(spec)
    }
}

/// 在 Runnable 状态下扫描 mirror::Class 内存布局
///
/// 从 with_runnable_thread 闭包中调用，确保 GC 不会移动目标对象。
unsafe fn scan_class_layout(
    env: JniEnv,
    cls_global: *mut std::ffi::c_void,
    art_field_static: u64,
    art_field_instance: u64,
    art_method_instance: u64,
    f_entry_size: usize,
    m_entry_size: usize,
) -> Option<ArtClassSpec> {
    // decode_jclass() may need safe_read_*() when DecodeJObject is unavailable.
    refresh_mem_regions();

    let class_obj = match decode_jclass(env, cls_global) {
        Some(addr) => addr,
        None => {
            output_verbose("[art class] jclass 解码失败，跳过 ArtClass 探测");
            return None;
        }
    };
    output_verbose(&format!("[art class] mirror::Class* = {:#x}", class_obj));

    // 扫描 Class 对象查找字段数组和方法数组
    // LengthPrefixedArray<ArtField>: { u32 length, ArtField[length] } (4-aligned entries)
    // LengthPrefixedArray<ArtMethod>: { u32 length, [pad to 8], ArtMethod[length] } (8-aligned entries)
    const MAX_OFFSET: usize = 0x100;

    let mut ifield_offset: Option<usize> = None;
    let mut sfield_offset: Option<usize> = None;
    let mut methods_offset: Option<usize> = None;

    for offset in (0..MAX_OFFSET).step_by(4) {
        let val = safe_read_u64(class_obj + offset as u64);
        let val_stripped = val & PAC_STRIP_MASK;

        if val_stripped == 0 || val_stripped < 0x1000 {
            continue;
        }

        // 检查 LengthPrefixedArray<ArtField> 是否包含已知 field 指针
        if sfield_offset.is_none() && art_field_static != 0 {
            if check_array_contains(val_stripped, f_entry_size, 4, art_field_static, 50) {
                sfield_offset = Some(offset);
                output_verbose(&format!(
                    "[art class] 找到 sfields_ 在 Class+{:#x} (array={:#x})",
                    offset, val_stripped
                ));
            }
        }

        if ifield_offset.is_none() && art_field_instance != 0 {
            if check_array_contains(val_stripped, f_entry_size, 4, art_field_instance, 50) {
                ifield_offset = Some(offset);
                output_verbose(&format!(
                    "[art class] 找到 ifields_ 在 Class+{:#x} (array={:#x})",
                    offset, val_stripped
                ));
            }
        }

        // 检查 LengthPrefixedArray<ArtMethod> 是否包含已知 method 指针
        if methods_offset.is_none() && art_method_instance != 0 {
            if check_array_contains(val_stripped, m_entry_size, 8, art_method_instance, 100) {
                methods_offset = Some(offset);
                output_verbose(&format!(
                    "[art class] 找到 methods_ 在 Class+{:#x} (array={:#x})",
                    offset, val_stripped
                ));
            }
        }

        if sfield_offset.is_some() && ifield_offset.is_some() && methods_offset.is_some() {
            break;
        }
    }

    // 如果 sfields 和 ifields 只找到一个，尝试推算另一个
    // Frida: ifields 和 sfields 在 Class 中是相邻的指针大小字段
    if sfield_offset.is_some() && ifield_offset.is_none() {
        let candidate = sfield_offset.unwrap().wrapping_sub(8);
        if candidate < MAX_OFFSET {
            ifield_offset = Some(candidate);
            output_verbose(&format!(
                "[art class] ifields_ 推算: sfields-8 = Class+{:#x}",
                candidate
            ));
        }
    } else if ifield_offset.is_some() && sfield_offset.is_none() {
        let candidate = ifield_offset.unwrap() + 8;
        if candidate < MAX_OFFSET {
            sfield_offset = Some(candidate);
            output_verbose(&format!(
                "[art class] sfields_ 推算: ifields+8 = Class+{:#x}",
                candidate
            ));
        }
    }

    let ifields = match ifield_offset {
        Some(o) => o,
        None => {
            output_verbose("[art class] ifields_ 偏移未找到");
            return None;
        }
    };
    let sfields = match sfield_offset {
        Some(o) if o != ifields => o,
        _ => {
            // sfields 未找到或与 ifields 相同，设为 0 表示不可用
            output_verbose("[art class] sfields_ 偏移未找到或与 ifields 重合，设为 0");
            0
        }
    };
    let methods = match methods_offset {
        Some(o) => o,
        None => {
            output_verbose("[art class] methods_ 偏移未找到");
            return None;
        }
    };

    // Step 6: 查找 copiedMethodsOffset（对标 Frida: 从 methods 偏移到 MAX_OFFSET 扫描）
    // 读取 methods array 的 length (u32)，然后搜索等于该 length 的 u16 值
    let methods_header = safe_read_u64(class_obj + methods as u64) & PAC_STRIP_MASK;
    let mut copied_methods = 0usize;

    if methods_header != 0 {
        let methods_array_len = safe_read_u32(methods_header);
        if methods_array_len > 0 && methods_array_len <= 65535 {
            // 对标 Frida: 从 methods 偏移开始，步长 4，扫描到 MAX_OFFSET
            // 跳过 methods 指针本身 (methods+0..methods+8)，从 methods+4 开始
            let mut candidate = methods + 4;
            while candidate + 2 <= MAX_OFFSET {
                let val = safe_read_u16(class_obj + candidate as u64);
                if val as u32 == methods_array_len {
                    copied_methods = candidate;
                    output_verbose(&format!(
                        "[art class] copied_methods_offset 发现: Class+{:#x} (value={}, methods_count={})",
                        candidate, val, methods_array_len
                    ));
                    break;
                }
                candidate += 4;
            }
        }
    }

    Some(ArtClassSpec {
        ifields_offset: ifields,
        sfields_offset: sfields,
        methods_offset: methods,
        copied_methods_offset: copied_methods,
    })
}

/// 检查 LengthPrefixedArray 是否包含指定指针
///
/// LengthPrefixedArray 结构:
///   { u32 length, [padding to alignment], element[0], element[1], ... }
///
/// 参数:
/// - array_addr: 数组起始地址
/// - element_size: 每个元素的大小
/// - alignment: 元素对齐要求 (ArtField=4, ArtMethod=8)
/// - target: 要查找的元素地址
unsafe fn check_array_contains(
    array_addr: u64,
    element_size: usize,
    alignment: usize,
    target: u64,
    max_entries: u32,
) -> bool {
    // 读取长度 (前4字节)
    let length = safe_read_u32(array_addr);
    if length == 0 || length > max_entries {
        return false;
    }

    // 计算第一个元素的对齐偏移
    // 长度字段占 4 字节，之后对齐到 alignment
    let header_size = 4usize;
    let first_element_offset = (header_size + alignment - 1) & !(alignment - 1);

    for i in 0..length as usize {
        let element_addr = array_addr as usize + first_element_offset + i * element_size;
        if element_addr as u64 == target {
            return true;
        }
    }

    false
}

// ============================================================================
// GC 安全: 线程状态切换 — 对标 Frida withRunnableArtThread
// ============================================================================

/// ART kRunnable 状态值 — 在所有 ART 版本中固定为 67
///
/// enum ThreadState { kTerminated = 66, kRunnable = 67, ... }
/// 66 来自 java.lang.Thread.State.TERMINATED (Java spec 定义)，
/// kRunnable 紧随其后，跨所有 ART 版本稳定。
const K_RUNNABLE: u16 = 67;

/// 从 JNIEnvExt 获取 Thread* 指针
///
/// JNIEnvExt 布局: { JNINativeInterface* functions, Thread* self_, ... }
#[inline]
unsafe fn get_thread_ptr(env: JniEnv) -> u64 {
    let raw = *((env as u64 as usize + 8) as *const u64);
    raw & PAC_STRIP_MASK
}

/// 探测 Thread 中 state_and_flags 字段的偏移
///
/// state_and_flags 是 Thread::tls32_ 的第一个字段。在 AOSP 标准布局中
/// tls32_ 是 Thread 的第一个数据成员（无 vtable），所以通常在 offset 0。
/// 但厂商构建可能在前面插入字段，因此动态探测。
///
/// 布局: union { struct { u16 flags, u16 state } as_struct; i32 as_int; }
/// 当前线程在 JNI 代码中应处于 kNative 状态 (值 77-90 取决于版本)，
/// flags 通常为 0 或很小。通过特征匹配定位。
///
/// 返回 (offset, current_state_value)
unsafe fn detect_state_and_flags(thread: u64) -> Option<(usize, u16)> {
    for offset in (0..64).step_by(4) {
        let val = std::ptr::read_volatile((thread as usize + offset) as *const u32);
        let state = ((val >> 16) & 0xFFFF) as u16;
        let flags = (val & 0xFFFF) as u16;

        // kNative 在所有 ART 版本中值 >= 67 (> kRunnable) 且 <= 100
        // flags 在正常运行中应 < 256
        if state > K_RUNNABLE && state <= 100 && flags < 256 {
            return Some((offset, state));
        }
    }
    None
}

/// 在 Runnable 状态下执行闭包（对标 Frida withRunnableArtThread）
///
/// ART CC GC 可能在 kNative 状态下移动堆对象 (concurrent copying)。
/// 访问 mirror::Object* 裸指针前需要切换到 kRunnable，阻止 GC
/// 在操作期间移动目标对象。
///
/// 策略:
/// 1. dlsym TransitionFromSuspendedToRunnable — 最安全，处理 checkpoint 和 suspend flag
/// 2. 直接写 state_and_flags — 轻量但跳过 checkpoint（操作时间 <1μs，风险极低）
/// 3. 无切换 fallback — 接受微小 GC 竞争风险
unsafe fn with_runnable_thread<F, R>(env: JniEnv, f: F) -> R
where
    F: FnOnce() -> R,
{
    let thread = get_thread_ptr(env);
    if thread == 0 {
        output_verbose("[runnable] Thread* 为空，跳过状态切换");
        return f();
    }

    // Strategy 1: dlsym TransitionFromSuspendedToRunnable
    let to_runnable_sym = libart_dlsym("_ZN3art6Thread33TransitionFromSuspendedToRunnableEv");

    if !to_runnable_sym.is_null() {
        // 尝试找反向转换函数
        let to_suspended_sym = libart_dlsym("_ZN3art6Thread40TransitionToSuspendedAndRunCheckpointsENS_11ThreadStateE");

        type ToRunnableFn = unsafe extern "C" fn(this: u64) -> u32;
        let transition: ToRunnableFn = std::mem::transmute(to_runnable_sym);
        let old_state = transition(thread);

        output_verbose(&format!(
            "[runnable] TransitionFromSuspendedToRunnable: old_state={}",
            old_state
        ));

        let result = f();

        // 恢复原始状态
        if !to_suspended_sym.is_null() {
            type ToSuspendedFn = unsafe extern "C" fn(this: u64, state: u32);
            let reverse: ToSuspendedFn = std::mem::transmute(to_suspended_sym);
            reverse(thread, old_state);
        } else {
            // Fallback: 直接写回状态字段
            if let Some((offset, _)) = detect_state_and_flags(thread) {
                let ptr = (thread as usize + offset) as *mut u32;
                let current = std::ptr::read_volatile(ptr);
                let restored = (current & 0xFFFF) | ((old_state & 0xFFFF) << 16);
                std::ptr::write_volatile(ptr, restored);
            }
        }

        return result;
    }

    // Strategy 2: 直接操作 state_and_flags 字段
    if let Some((offset, native_state)) = detect_state_and_flags(thread) {
        let ptr = (thread as usize + offset) as *mut u32;
        let original = std::ptr::read_volatile(ptr);

        // 设置 state 为 kRunnable (保留 flags 不变)
        let runnable_val = (original & 0xFFFF) | ((K_RUNNABLE as u32) << 16);
        std::ptr::write_volatile(ptr, runnable_val);

        output_verbose(&format!(
            "[runnable] 直接状态切换: Thread+{:#x}, kNative({})→kRunnable({})",
            offset, native_state, K_RUNNABLE
        ));

        let result = f();

        // 恢复原始状态
        std::ptr::write_volatile(ptr, original);

        return result;
    }

    // Strategy 3: 无法切换状态，直接执行（best effort）
    output_verbose("[runnable] 状态切换不可用，直接执行（best effort）");
    f()
}

// ============================================================================
// jclass 解码
// ============================================================================

unsafe fn decode_jobject(env: JniEnv, obj: *mut std::ffi::c_void) -> Option<u64> {
    const DECODE_JOBJECT_SYMBOLS: [&str; 2] = [
        "_ZNK3art6Thread13DecodeJObjectEP8_jobject",
        "_ZN3art6Thread13DecodeJObjectEP8_jobject",
    ];

    let thread = get_thread_ptr(env);
    if thread == 0 {
        return None;
    }

    type DecodeJObjectFn = unsafe extern "C" fn(thread: u64, obj: *mut std::ffi::c_void) -> u64;

    for sym_name in DECODE_JOBJECT_SYMBOLS {
        let decode_sym = libart_dlsym(sym_name);
        if decode_sym.is_null() {
            continue;
        }

        let decode: DecodeJObjectFn = std::mem::transmute(decode_sym);
        let result = decode(thread, obj);
        let stripped = result & PAC_STRIP_MASK;
        if stripped != 0 {
            return Some(stripped);
        }
    }

    None
}

/// 解码 jclass 引用为 mirror::Class* 地址
///
/// 策略 1: dlsym Thread::DecodeJObject — 最可靠，支持所有 ref 类型
/// 策略 2: 直接读取 global ref 指向的 GcRoot（fallback）
///
/// 注意: 调用方应在 kRunnable 状态下调用此函数（通过 with_runnable_thread 包裹），
/// 以确保 CC GC 不会在解码后移动对象。
unsafe fn decode_jclass(env: JniEnv, cls: *mut std::ffi::c_void) -> Option<u64> {
    if let Some(stripped) = decode_jobject(env, cls) {
        output_verbose(&format!(
            "[art class] DecodeJObject: ref={:#x} → mirror::Class*={:#x}",
            cls as u64, stripped
        ));
        return Some(stripped);
    }

    // 策略 2: 直接读取 global ref entry
    // Global ref 在 ART 中指向 IndirectReferenceTable 的 IrtEntry，
    // IrtEntry 中存储 GcRoot<mirror::Object>，对于非压缩指针就是 mirror::Object*
    // 尝试: 将 ref 当作指针读取其指向的值
    let cls_val = cls as u64;
    if cls_val != 0 && cls_val > 0x1000 {
        let deref = safe_read_u64(cls_val);
        let stripped = deref & PAC_STRIP_MASK;
        // mirror::Class 对象应在合理堆地址范围
        if stripped > 0x1000_0000 && stripped < 0x0000_FFFF_0000_0000 {
            output_verbose(&format!(
                "[art class] IndirectRef 解码: *ref={:#x} → {:#x}",
                cls_val, stripped
            ));
            return Some(stripped);
        }

        // 可能使用压缩指针 (32-bit)
        let deref32 = safe_read_u32(cls_val) as u64;
        if deref32 > 0x1000_0000 {
            output_verbose(&format!(
                "[art class] IndirectRef 压缩指针解码: *ref(u32)={:#x}",
                deref32
            ));
            return Some(deref32);
        }
    }

    output_verbose("[art class] jclass 解码失败: DecodeJObject 不可用且 fallback 无效");
    None
}

/// Best-effort JNI ref validation for hook callbacks.
///
/// This avoids passing obviously bad register values into JNI object APIs.
pub(super) unsafe fn is_valid_jni_ref(env: JniEnv, obj: *mut std::ffi::c_void) -> bool {
    if obj.is_null() {
        return false;
    }

    with_runnable_thread(env, || decode_jobject(env, obj).is_some())
}
