//! js_hook, js_unhook, js_call_native implementations

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    dup_callback_to_bytes, ensure_function_arg, extract_pointer_address, js_i64_to_js_number_or_bigint,
    js_value_to_u64_or_zero, throw_internal_error,
};
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

use super::callback::hook_callback_wrapper;
use super::registry::{hook_error_message, init_registry, HookData, StealthMode, HOOK_OK, HOOK_REGISTRY};
use crate::jsapi::callback_util::with_registry_mut;

/// hook(ptr, callback, mode?) - Install a hook at the given address
///
/// mode: Hook.NORMAL (0, default), Hook.WXSHADOW (1) / true, Hook.RECOMP (2)
pub(crate) unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"hook() requires at least 2 arguments\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    // 解析 stealth 模式：0=Normal, 1/true=WxShadow, 2=Recomp
    let mode = if argc >= 3 {
        let mode_arg = JSValue(*argv.add(2));
        match mode_arg.to_i64(ctx) {
            Some(v) => StealthMode::from_js_arg(v),
            // bool true → WxShadow（向后兼容）
            None if mode_arg.to_bool() == Some(true) => StealthMode::WxShadow,
            None => StealthMode::Normal,
        }
    } else {
        StealthMode::Normal
    };

    install_hook(ctx, ptr_arg, callback_arg, mode)
}

/// recompHook(ptr, callback) - 便捷函数，等价于 hook(ptr, callback, Hook.RECOMP)
pub(crate) unsafe extern "C" fn js_recomp_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"recompHook() requires 2 arguments\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    install_hook(ctx, ptr_arg, callback_arg, StealthMode::Recomp)
}

/// 统一 hook 安装逻辑
unsafe fn install_hook(
    ctx: *mut ffi::JSContext,
    ptr_arg: JSValue,
    callback_arg: JSValue,
    mode: StealthMode,
) -> ffi::JSValue {
    let addr = match extract_pointer_address(ctx, ptr_arg, "hook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    if let Err(err) = ensure_function_arg(ctx, callback_arg, b"hook() second argument must be a function\0") {
        return err;
    }

    init_registry();

    // 方案 (b): 同一 addr 重复 hook 自动替换老 hook。
    // 先拆掉旧 hook（恢复 recomp 页字节 + 回收 slot + 释放老 callback），
    // 等 in-flight native callback 退出，再装新 hook。避免 HashMap.insert
    // 覆盖 HookData 后 slot 泄漏 + orig_insn 被当成"B→老 slot"污染 callOriginal。
    if let Some(old_data) = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&addr))
        .flatten()
    {
        super::remove_single_hook(addr, &old_data);
        // 短 wait 给当前在 thunk 内的 callback 退出；超时就放弃 free（old callback
        // 泄漏一次，callback_wrapper 自带 "not a function" 校验不会崩）。
        if super::callback::wait_for_in_flight_native_hook_callbacks(
            std::time::Duration::from_millis(20),
        ) {
            super::free_hook_callback(&old_data);
        }
    }

    // Recomp 模式：先重编译页，再分配跳板 slot
    // alloc_trampoline_slot 在 recomp 代码页写 B→slot，返回 slot 地址。
    // hook engine 以 stealth=0 在 slot 上写 full jump→thunk，无需碰原始 SO。
    let (hook_addr, recomp_addr) = match mode {
        StealthMode::Recomp => {
            // 确保页已重编译
            if let Err(e) = crate::recomp::ensure_and_translate(addr as usize) {
                return throw_internal_error(ctx, &format!("hook(recomp): {}", e));
            }
            // 分配跳板 slot（recomp 跳板区，B range 内保证）
            match crate::recomp::alloc_trampoline_slot(addr as usize) {
                Ok(slot) => (slot as u64, slot as u64),
                Err(e) => return throw_internal_error(ctx, &format!("hook(recomp slot): {}", e)),
            }
        }
        _ => (addr, 0),
    };

    let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

    let stealth_flag = match mode {
        StealthMode::WxShadow => 1,
        StealthMode::Recomp => 2,
        _ => 0,
    };

    let trampoline = hook_ffi::hook_replace(
        hook_addr as *mut std::ffi::c_void,
        Some(hook_callback_wrapper),
        addr as *mut std::ffi::c_void, // user_data = 原始地址（registry key）
        stealth_flag,
    );

    if trampoline.is_null() {
        let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, callback);
        return throw_internal_error(ctx, "hook_replace failed: could not install hook");
    }

    // Recomp: fixup trampoline + commit B 指令
    if mode == StealthMode::Recomp {
        let _ = crate::recomp::fixup_slot_trampoline(trampoline as *mut u8, addr as usize);
        let _ = crate::recomp::commit_slot_patch(addr as usize);
    }

    with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.insert(
            addr,
            HookData {
                ctx: ctx as usize,
                callback_bytes,
                trampoline: trampoline as u64,
                mode,
                recomp_addr,
            },
        );
    });

    JSValue::bool(true).raw()
}

/// unhook(ptr) - Remove a hook at the given address
pub(crate) unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"unhook() requires 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    let addr = match extract_pointer_address(ctx, ptr_arg, "unhook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    let registry_data = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&addr))
        .flatten();

    if let Some(data) = registry_data {
        super::remove_single_hook(addr, &data);
        super::free_hook_callback(&data);
        return JSValue::bool(true).raw();
    }

    // registry 中不存在, 可能是:
    //  1) writest 留下的 slot (无 HookData) — try_revert_slot_patch 恢复 recomp 页字节
    //  2) writeBytes(bytes, 1) 留下的 wxshadow patch — wxshadow_release 清 shadow 页
    //  3) 普通 stealth=0 hook 未登记但 hook engine 已 attach — hook_remove 恢复
    // 三路都静默尝试; 全不命中才报错.
    let slot_cleared = crate::recomp::try_revert_slot_patch(addr as usize);
    let wxshadow_released =
        ffi::hook::wxshadow_release(addr as *mut std::ffi::c_void) == 0;
    if wxshadow_released {
        crate::jsapi::memory::untrack_wxshadow_addr(addr);
    }
    let hook_removed = hook_ffi::hook_remove(addr as *mut std::ffi::c_void) == HOOK_OK;

    if !slot_cleared && !wxshadow_released && !hook_removed {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"unhook: no hook/writest/wxshadow patch registered at address\0".as_ptr() as *const _,
        );
    }

    JSValue::bool(true).raw()
}

/// callNative(ptr, arg0?, arg1?, ..., arg5?) - Call a native function at addr with 0-6 args.
/// Arguments are passed in x0-x5 (ARM64 calling convention). Unspecified args default to 0.
/// Return value: Number when result fits exactly in f64 (≤ 2^53), BigUint64 otherwise.
pub(crate) unsafe extern "C" fn js_call_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"callNative() requires at least 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    let addr = match extract_pointer_address(ctx, ptr_arg, "callNative") {
        Ok(a) => a,
        Err(e) => return e,
    };

    if addr < 0x10000 {
        return ffi::JS_ThrowRangeError(ctx, b"callNative() address is not mapped\0".as_ptr() as *const _);
    }

    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"callNative() address is not mapped\0".as_ptr() as *const _);
    }

    {
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        if unsafe { libc::dladdr(addr as *const std::ffi::c_void, &mut info) } == 0 {
            return ffi::JS_ThrowRangeError(
                ctx,
                b"callNative() address is not in an executable segment\0".as_ptr() as *const _,
            );
        }
    }

    let mut args = [0u64; 6];
    for i in 0..6usize {
        if (i + 1) < argc as usize {
            let arg = JSValue(*argv.add(i + 1));
            args[i] = js_value_to_u64_or_zero(ctx, arg);
        }
    }

    let func: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64 = std::mem::transmute(addr as usize);
    let result = func(args[0], args[1], args[2], args[3], args[4], args[5]);

    js_i64_to_js_number_or_bigint(ctx, result)
}

// ─────────────────────────── NativeFunction API ──────────────────────────────
//
// Frida-compatible native 函数调用器。通过 ARM64 AAPCS64 register-passing
// 约定调用任意签名的 native 函数，支持最多 8 个整数参数 (x0-x7) + 8 个浮点
// 参数 (d0-d7)，以及 void/bool/int*/long/size_t/pointer/float/double 返回值。
//
// 使用方式（与 Frida 完全一致）:
//   var open = new NativeFunction(
//       Module.findExportByName('libc.so', 'open'),
//       'int',
//       ['pointer', 'int']
//   );
//   var fd = open(Memory.allocUtf8String('/tmp/foo'), 2);
//
// 实现：NativeFunction 在 JS 侧通过 boot script 定义（native_boot.js），
// 它创建一个闭包保存 addr/retType/argTypes，每次调用时把参数分拆到 GPR/FPR
// 数组，然后调 __nativeCall(addr, retTypeKind, gprBytes, fprBytes) native 函数。
// native 函数通过 native_call_shim (asm) 把寄存器装好并跳转到目标。

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeRetKind {
    Void = 0,
    Int = 1,      // 整数类型 (bool/char/int/long/size_t/pointer)，从 x0 读
    Double = 2,   // double / float64，从 d0 读
    Float32 = 3,  // float (32-bit)，从 s0 读（必须用独立的 extern -> f32 签名）
}

impl NativeRetKind {
    fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Void),
            1 => Some(Self::Int),
            2 => Some(Self::Double),
            3 => Some(Self::Float32),
            _ => None,
        }
    }
}

extern "C" {
    /// ARM64 AAPCS64 shim：
    ///   - gpr[0..8] 载入 x0-x7
    ///   - fpr[0..8] 载入 d0-d7
    ///   - stk[0..stk_count] 拷贝到栈上 (每槽 8 字节，caller 分配/释放)
    ///   - 跳转到 fn_ptr
    ///
    /// 三个 extern 签名指向同一个 asm symbol，用不同的 Rust 返回类型告诉
    /// 编译器从哪个物理寄存器读返回值:
    ///   -> u64 → x0 (integer/pointer)
    ///   -> f64 → d0 (double)
    ///   -> f32 → s0 (float 32-bit，低 32 bits of v0)
    fn native_call_shim(
        fn_ptr: *const std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> u64;
    #[link_name = "native_call_shim"]
    fn native_call_shim_f64(
        fn_ptr: *const std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> f64;
    #[link_name = "native_call_shim"]
    fn native_call_shim_f32(
        fn_ptr: *const std::ffi::c_void,
        gpr: *const u64,
        fpr: *const f64,
        stk: *const u64,
        stk_count: usize,
    ) -> f32;
}

/// __nativeCall(addr, retKind, gpr[], fpr[], fprFloatMask, stk[])
///
/// - addr: NativePointer / number
/// - retKind: 0=void, 1=int, 2=double, 3=float32
/// - gpr[]: length-8 JS Array (BigInt/Number/Pointer) — x0-x7 寄存器参数
/// - fpr[]: length-8 JS Array (Number)                — d0-d7 寄存器参数
/// - fprFloatMask: int32 bit mask，bit i=1 表示 fpr[i] 是 float32 而非 float64
/// - stk[]: 变长 JS Array (BigInt)，溢出参数的**原始 u64 位图**
///          按声明顺序排列，JS 侧已经把 int/float/double 转好 bit pattern
///          每槽 8 字节，float32 在低 32 bits、高 32 bits = 0
///
/// 无参上限。stk 为空时走无栈溢出快路径。
pub(crate) unsafe extern "C" fn js_native_call(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 6 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"__nativeCall() requires 6 arguments: addr, retKind, gpr[], fpr[], fprFloatMask, stk[]\0"
                .as_ptr() as *const _,
        );
    }
    let addr_arg = JSValue(*argv);
    let kind_arg = JSValue(*argv.add(1));
    let gpr_arg = JSValue(*argv.add(2));
    let fpr_arg = JSValue(*argv.add(3));
    let mask_arg = JSValue(*argv.add(4));
    let stk_arg = JSValue(*argv.add(5));

    let addr = match extract_pointer_address(ctx, addr_arg, "__nativeCall") {
        Ok(a) => a,
        Err(e) => return e,
    };
    if addr < 0x10000 || !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"__nativeCall() address is not mapped\0".as_ptr() as *const _,
        );
    }
    // 检查页是否可执行 (PROT_EXEC): 通过 /proc/self/maps 查 prot 位。
    // 不依赖 dladdr 因为 Memory.alloc 分配的 RWX 页不在任何 loaded SO 里。
    {
        use crate::jsapi::util::{proc_maps_entries, read_proc_self_maps};
        let maps = read_proc_self_maps();
        let mut is_exec = false;
        if let Some(ref m) = maps {
            for entry in proc_maps_entries(m) {
                if entry.contains(addr) {
                    is_exec = (entry.prot_flags() & libc::PROT_EXEC) != 0;
                    break;
                }
            }
        }
        if !is_exec {
            return ffi::JS_ThrowRangeError(
                ctx,
                b"__nativeCall() address is not in an executable page\0".as_ptr() as *const _,
            );
        }
    }

    let kind_num = kind_arg.to_i64(ctx).unwrap_or(-1);
    let kind = match NativeRetKind::from_i32(kind_num as i32) {
        Some(k) => k,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"__nativeCall() retKind must be 0..3\0".as_ptr() as *const _,
            );
        }
    };

    let fpr_float_mask = mask_arg.to_i64(ctx).unwrap_or(0) as u32;

    // 从 JS Array 读 8 个 u64 → gpr 寄存器组
    let mut gpr = [0u64; 8];
    for i in 0..8u32 {
        let elem = ffi::JS_GetPropertyUint32(ctx, gpr_arg.raw(), i);
        let v = JSValue(elem);
        gpr[i as usize] = js_value_to_u64_or_zero(ctx, v);
        ffi::qjs_free_value(ctx, elem);
    }

    // 从 JS Array 读 8 个 number → fpr 寄存器组
    // 对标记为 float32 的槽做 f32 截断：低 32 bits 存 f32 位图，高 32 bits 为 0
    let mut fpr = [0.0f64; 8];
    for i in 0..8u32 {
        let elem = ffi::JS_GetPropertyUint32(ctx, fpr_arg.raw(), i);
        let v = JSValue(elem);
        let val = v.to_float().unwrap_or(0.0);
        ffi::qjs_free_value(ctx, elem);
        fpr[i as usize] = if (fpr_float_mask >> i) & 1 == 1 {
            let f32_bits = (val as f32).to_bits() as u64;
            f64::from_bits(f32_bits)
        } else {
            val
        };
    }

    // 读取 stk[] 长度 + 每个槽的 u64 值（JS 侧已转成 BigInt）
    // 上限：256 个溢出参数（2KB 栈空间），足够任何合理调用
    const MAX_STK: usize = 256;
    let stk_len = {
        let len_val = stk_arg.get_property(ctx, "length");
        let n = len_val.to_i64(ctx).unwrap_or(0);
        len_val.free(ctx);
        n.max(0) as usize
    };
    if stk_len > MAX_STK {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"__nativeCall() too many stack args (> 256)\0".as_ptr() as *const _,
        );
    }
    let mut stk = [0u64; MAX_STK];
    for i in 0..stk_len {
        let elem = ffi::JS_GetPropertyUint32(ctx, stk_arg.raw(), i as u32);
        let v = JSValue(elem);
        stk[i] = js_value_to_u64_or_zero(ctx, v);
        ffi::qjs_free_value(ctx, elem);
    }

    let fn_ptr = addr as *const std::ffi::c_void;
    let stk_ptr = stk.as_ptr();

    match kind {
        NativeRetKind::Void => {
            native_call_shim(fn_ptr, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk_len);
            JSValue::undefined().raw()
        }
        NativeRetKind::Int => {
            let r = native_call_shim(fn_ptr, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk_len);
            js_i64_to_js_number_or_bigint(ctx, r as i64)
        }
        NativeRetKind::Double => {
            let r = native_call_shim_f64(fn_ptr, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk_len);
            ffi::qjs_new_float64(ctx, r)
        }
        NativeRetKind::Float32 => {
            let r = native_call_shim_f32(fn_ptr, gpr.as_ptr(), fpr.as_ptr(), stk_ptr, stk_len);
            ffi::qjs_new_float64(ctx, r as f64)
        }
    }
}

/// diagAllocNear(addr) - 诊断 hook_alloc_near 对指定地址的有效性
pub(crate) unsafe extern "C" fn js_diag_alloc_near(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"diagAllocNear() requires 1 argument (address)\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);
    let addr = match extract_pointer_address(ctx, ptr_arg, "diagAllocNear") {
        Ok(a) => a,
        Err(e) => return e,
    };

    hook_ffi::hook_diag_alloc_near(addr as *mut std::ffi::c_void);
    JSValue::undefined().raw()
}