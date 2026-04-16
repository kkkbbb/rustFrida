#![cfg(feature = "qbdi")]

use crate::ffi;
use crate::jsapi::callback_util::{extract_pointer_address, throw_internal_error};
use crate::jsapi::console::output_message;
use crate::jsapi::module::{memfd_dlopen, module_dlsym};
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;
use crate::{qbdi_helper_blob, qbdi_output_dir};
use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::OnceLock;

type LastErrorFn = unsafe extern "C" fn() -> *const c_char;
type ShutdownFn = unsafe extern "C" fn();
type GetHideResultFn = unsafe extern "C" fn() -> *const HideResult;
type VmNewFn = unsafe extern "C" fn() -> u64;
type VmUnaryFn = unsafe extern "C" fn(u64) -> c_int;
type VmRangeFn = unsafe extern "C" fn(u64, u64, u64) -> c_int;
type VmModuleFn = unsafe extern "C" fn(u64, *const c_char) -> c_int;
type VmAddrFn = unsafe extern "C" fn(u64, u64) -> c_int;
type VmRecordMemoryAccessFn = unsafe extern "C" fn(u64, u32) -> c_int;
type VmStackAllocFn = unsafe extern "C" fn(u64, u32) -> c_int;
type VmSimulateCallFn = unsafe extern "C" fn(u64, u64, *const u64, u32) -> c_int;
type VmRunFn = unsafe extern "C" fn(u64, u64, u64) -> c_int;
type VmCallFn = unsafe extern "C" fn(u64, u64, *const u64, u32, *mut u64) -> c_int;
type VmSwitchStackAndCallFn = unsafe extern "C" fn(u64, u64, u32, *const u64, u32, *mut u64) -> c_int;
type VmGetGprFn = unsafe extern "C" fn(u64, u32, *mut u64) -> c_int;
type VmSetGprFn = unsafe extern "C" fn(u64, u32, u64) -> c_int;
type VmGetFprFn = unsafe extern "C" fn(u64, u32, *mut u64, *mut u64) -> c_int;
type VmSetFprFn = unsafe extern "C" fn(u64, u32, u64, u64) -> c_int;
type VmGetErrnoFn = unsafe extern "C" fn(u64, *mut u32) -> c_int;
type VmSetErrnoFn = unsafe extern "C" fn(u64, u32) -> c_int;
type VmTraceRegisterFn = unsafe extern "C" fn(u64, u64, *const c_char) -> c_int;
type TraceBundleMetadataFn = unsafe extern "C" fn(*const c_char, u64) -> c_int;

#[repr(C)]
#[derive(Clone, Copy)]
struct HideResult {
    status: i32,
    next_offset: i32,
    entries_scanned: i32,
    sym_matched: i32,
    head_ptr: u64,
    target_ptr: u64,
    error: [u8; 128],
    target_path: [u8; 128],
    head_path: [u8; 128],
}

impl HideResult {
    fn cstr(buf: &[u8]) -> &str {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        std::str::from_utf8(&buf[..end]).unwrap_or("")
    }
}

struct HelperApi {
    last_error: LastErrorFn,
    shutdown: Option<ShutdownFn>,
    vm_new: VmNewFn,
    vm_destroy: VmUnaryFn,
    vm_add_instrumented_range: VmRangeFn,
    vm_add_instrumented_module: VmModuleFn,
    vm_add_instrumented_module_from_addr: VmAddrFn,
    vm_instrument_all_executable_maps: VmUnaryFn,
    vm_remove_instrumented_range: VmRangeFn,
    vm_remove_all_instrumented_ranges: VmUnaryFn,
    vm_delete_all_instrumentations: VmUnaryFn,
    vm_record_memory_access: VmRecordMemoryAccessFn,
    vm_allocate_virtual_stack: VmStackAllocFn,
    vm_clear_virtual_stacks: VmUnaryFn,
    vm_simulate_call: VmSimulateCallFn,
    vm_run: VmRunFn,
    vm_call: VmCallFn,
    vm_switch_stack_and_call: VmSwitchStackAndCallFn,
    vm_get_gpr: VmGetGprFn,
    vm_set_gpr: VmSetGprFn,
    vm_get_fpr: VmGetFprFn,
    vm_set_fpr: VmSetFprFn,
    vm_get_errno: VmGetErrnoFn,
    vm_set_errno: VmSetErrnoFn,
    trace_set_bundle_metadata: TraceBundleMetadataFn,
    vm_register_trace_callbacks: VmTraceRegisterFn,
    vm_unregister_trace_callbacks: VmUnaryFn,
}

static HELPER_API: OnceLock<HelperApi> = OnceLock::new();
static QBDI_HELPER_HANDLE: OnceLock<usize> = OnceLock::new();

unsafe fn resolve_symbol(handle: *mut c_void, name: &str) -> *mut c_void {
    let ptr = module_dlsym("qbdi_helper.so", name);
    if !ptr.is_null() {
        return ptr;
    }
    let sym = CString::new(name).unwrap();
    libc::dlsym(handle, sym.as_ptr())
}

fn verify_qbdi_helper_hide_result(handle: *mut c_void) {
    let fn_ptr = ["rust_get_hide_result", "get_hide_result"]
        .iter()
        .find_map(|name| {
            let sym = CString::new(*name).unwrap();
            let ptr = unsafe {
                let ptr = module_dlsym("qbdi_helper.so", sym.to_str().unwrap());
                if ptr.is_null() {
                    libc::dlsym(handle, sym.as_ptr())
                } else {
                    ptr
                }
            };
            (!ptr.is_null()).then_some(ptr)
        })
        .unwrap_or(std::ptr::null_mut());
    if fn_ptr.is_null() {
        output_message("[qbdi] qbdi-helper hide_soinfo verify skipped: get_hide_result not found");
        return;
    }

    let result_ptr = unsafe {
        let get_hide_result: GetHideResultFn = std::mem::transmute(fn_ptr);
        get_hide_result()
    };
    if result_ptr.is_null() {
        output_message("[qbdi] qbdi-helper hide_soinfo verify failed: result pointer is NULL");
        return;
    }

    let result = unsafe { *result_ptr };
    let target_path = HideResult::cstr(&result.target_path);
    let head_path = HideResult::cstr(&result.head_path);
    if result.status == 1 {
        output_message(&format!(
            "[qbdi] qbdi-helper hide_soinfo ok: target=\"{}\" next_offset=0x{:x} scanned={} syms={} target=0x{:x}",
            target_path, result.next_offset, result.entries_scanned, result.sym_matched, result.target_ptr
        ));
        if !head_path.is_empty() {
            output_message(&format!(
                "[qbdi] qbdi-helper hide_soinfo head: \"{}\" ({:#x})",
                head_path, result.head_ptr
            ));
        }
    } else {
        let error = HideResult::cstr(&result.error);
        output_message(&format!(
            "[qbdi] qbdi-helper hide_soinfo failed: status={} error=\"{}\" next_offset=0x{:x} scanned={} syms={} head=0x{:x} target=0x{:x}",
            result.status,
            error,
            result.next_offset,
            result.entries_scanned,
            result.sym_matched,
            result.head_ptr,
            result.target_ptr
        ));
        if !target_path.is_empty() || !head_path.is_empty() {
            output_message(&format!(
                "[qbdi] qbdi-helper hide_soinfo paths: target=\"{}\" head=\"{}\"",
                target_path, head_path
            ));
        }
    }
}

unsafe fn build_helper_api(handle: *mut c_void) -> Result<HelperApi, String> {
    let required = |name: &str| {
        let ptr = resolve_symbol(handle, name);
        if ptr.is_null() {
            Err(format!("qbdi helper missing symbol {}", name))
        } else {
            Ok(ptr)
        }
    };

    Ok(HelperApi {
        last_error: std::mem::transmute(required("qbdi_trace_last_error")?),
        shutdown: {
            let ptr = resolve_symbol(handle, "qbdi_trace_shutdown");
            (!ptr.is_null()).then(|| std::mem::transmute(ptr))
        },
        vm_new: std::mem::transmute(required("qbdi_vm_new")?),
        vm_destroy: std::mem::transmute(required("qbdi_vm_destroy")?),
        vm_add_instrumented_range: std::mem::transmute(required("qbdi_vm_add_instrumented_range")?),
        vm_add_instrumented_module: std::mem::transmute(required("qbdi_vm_add_instrumented_module")?),
        vm_add_instrumented_module_from_addr: std::mem::transmute(required(
            "qbdi_vm_add_instrumented_module_from_addr",
        )?),
        vm_instrument_all_executable_maps: std::mem::transmute(required("qbdi_vm_instrument_all_executable_maps")?),
        vm_remove_instrumented_range: std::mem::transmute(required("qbdi_vm_remove_instrumented_range")?),
        vm_remove_all_instrumented_ranges: std::mem::transmute(required("qbdi_vm_remove_all_instrumented_ranges")?),
        vm_delete_all_instrumentations: std::mem::transmute(required("qbdi_vm_delete_all_instrumentations")?),
        vm_record_memory_access: std::mem::transmute(required("qbdi_vm_record_memory_access")?),
        vm_allocate_virtual_stack: std::mem::transmute(required("qbdi_vm_allocate_virtual_stack")?),
        vm_clear_virtual_stacks: std::mem::transmute(required("qbdi_vm_clear_virtual_stacks")?),
        vm_simulate_call: std::mem::transmute(required("qbdi_vm_simulate_call")?),
        vm_run: std::mem::transmute(required("qbdi_vm_run")?),
        vm_call: std::mem::transmute(required("qbdi_vm_call")?),
        vm_switch_stack_and_call: std::mem::transmute(required("qbdi_vm_switch_stack_and_call")?),
        vm_get_gpr: std::mem::transmute(required("qbdi_vm_get_gpr")?),
        vm_set_gpr: std::mem::transmute(required("qbdi_vm_set_gpr")?),
        vm_get_fpr: std::mem::transmute(required("qbdi_vm_get_fpr")?),
        vm_set_fpr: std::mem::transmute(required("qbdi_vm_set_fpr")?),
        vm_get_errno: std::mem::transmute(required("qbdi_vm_get_errno")?),
        vm_set_errno: std::mem::transmute(required("qbdi_vm_set_errno")?),
        trace_set_bundle_metadata: std::mem::transmute(required("qbdi_trace_set_bundle_metadata")?),
        vm_register_trace_callbacks: std::mem::transmute(required("qbdi_vm_register_trace_callbacks")?),
        vm_unregister_trace_callbacks: std::mem::transmute(required("qbdi_vm_unregister_trace_callbacks")?),
    })
}

fn load_qbdi_helper() -> Result<&'static HelperApi, String> {
    if let Some(api) = HELPER_API.get() {
        return Ok(api);
    }

    let helper_blob = qbdi_helper_blob().ok_or_else(|| "qbdi helper blob not configured".to_string())?;
    let memfd_name = CString::new("wwb_so").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create as libc::c_long, memfd_name.as_ptr(), 0) as c_int };
    if fd < 0 {
        return Err(format!(
            "memfd_create(qbdi_helper) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    {
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&helper_blob)
            .map_err(|e| format!("write helper blob to memfd failed: {}", e))?;
        file.flush()
            .map_err(|e| format!("flush helper blob memfd failed: {}", e))?;
        let _ = file.into_raw_fd();
    }
    let handle = unsafe { memfd_dlopen("qbdi_helper.so", fd) };
    if handle.is_null() {
        let msg = unsafe {
            let err = libc::dlerror();
            if err.is_null() {
                "android_dlopen_ext(qbdi helper) failed".to_string()
            } else {
                CStr::from_ptr(err).to_string_lossy().into_owned()
            }
        };
        unsafe { libc::close(fd) };
        return Err(format!("failed to load qbdi helper from memfd: {}", msg));
    }
    unsafe { libc::close(fd) };

    verify_qbdi_helper_hide_result(handle);
    let _ = QBDI_HELPER_HANDLE.set(handle as usize);
    let api = unsafe { build_helper_api(handle)? };
    let _ = HELPER_API.set(api);
    Ok(HELPER_API.get().expect("helper api set"))
}

pub fn preload_qbdi_helper() -> Result<(), String> {
    let _ = load_qbdi_helper()?;
    Ok(())
}

pub fn shutdown_qbdi_helper() {
    if let Some(api) = HELPER_API.get() {
        if let Some(shutdown) = api.shutdown {
            unsafe { shutdown() };
        }
    }
}

unsafe fn helper_last_error(api: &HelperApi) -> Option<String> {
    let ptr = (api.last_error)();
    if ptr.is_null() {
        None
    } else {
        Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

unsafe fn extract_u64_arg(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    index: usize,
    func: &str,
) -> Result<u64, ffi::JSValue> {
    extract_pointer_address(ctx, JSValue(*argv.add(index)), func)
}

unsafe fn extract_u32_arg(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    index: usize,
    func: &str,
) -> Result<u32, ffi::JSValue> {
    let value = JSValue(*argv.add(index))
        .to_i64(ctx)
        .filter(|v| *v >= 0 && *v <= u32::MAX as i64)
        .map(|v| v as u32);
    value.ok_or_else(|| {
        ffi::JS_ThrowTypeError(
            ctx,
            CString::new(format!("{}() argument {} must be u32", func, index))
                .unwrap()
                .as_ptr(),
        )
    })
}

unsafe fn extract_string_arg_owned(
    ctx: *mut ffi::JSContext,
    argv: *mut ffi::JSValue,
    index: usize,
    func: &str,
) -> Result<String, ffi::JSValue> {
    JSValue(*argv.add(index)).to_string(ctx).ok_or_else(|| {
        ffi::JS_ThrowTypeError(
            ctx,
            CString::new(format!("{}() argument {} must be string", func, index))
                .unwrap()
                .as_ptr(),
        )
    })
}

unsafe fn collect_u64_args(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    start: usize,
    func: &str,
) -> Result<Vec<u64>, ffi::JSValue> {
    let argc = argc.max(0) as usize;
    let mut args = Vec::with_capacity(argc.saturating_sub(start));
    for i in start..argc {
        args.push(extract_pointer_address(ctx, JSValue(*argv.add(i)), func)?);
    }
    Ok(args)
}

unsafe fn bool_from_rc(rc: i32) -> ffi::JSValue {
    JSValue::bool(rc == 0).raw()
}

unsafe fn value_or_null(ctx: *mut ffi::JSContext, rc: i32, value: u64) -> ffi::JSValue {
    if rc == 0 {
        if value <= (1u64 << 53) {
            ffi::qjs_new_int64(ctx, value as i64)
        } else {
            ffi::JS_NewBigUint64(ctx, value)
        }
    } else {
        JSValue::null().raw()
    }
}

unsafe extern "C" fn js_qbdi_new_vm(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = (api.vm_new)();
    if handle == 0 {
        return JSValue::null().raw();
    }
    if handle <= (1u64 << 53) {
        ffi::qjs_new_int64(ctx, handle as i64)
    } else {
        ffi::JS_NewBigUint64(ctx, handle)
    }
}

macro_rules! js_bool_method {
    ($name:ident, $argc_min:expr, |$ctx:ident, $argc:ident, $argv:ident| $body:block) => {
        unsafe extern "C" fn $name(
            $ctx: *mut ffi::JSContext,
            _this: ffi::JSValue,
            $argc: i32,
            $argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            if $argc < $argc_min {
                return ffi::JS_ThrowTypeError(
                    $ctx,
                    concat!(stringify!($name), " invalid argc\0").as_ptr() as *const _,
                );
            }
            $body
        }
    };
}

js_bool_method!(js_qbdi_destroy_vm, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.destroyVM") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_destroy)(handle))
});

js_bool_method!(js_qbdi_add_instrumented_range, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.addInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let start = match extract_u64_arg(ctx, argv, 1, "qbdi.addInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let end = match extract_u64_arg(ctx, argv, 2, "qbdi.addInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_add_instrumented_range)(handle, start, end))
});

js_bool_method!(js_qbdi_add_instrumented_module, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.addInstrumentedModule") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match extract_string_arg_owned(ctx, argv, 1, "qbdi.addInstrumentedModule") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let c_name = CString::new(name).unwrap();
    bool_from_rc((api.vm_add_instrumented_module)(handle, c_name.as_ptr()))
});

js_bool_method!(js_qbdi_add_instrumented_module_from_addr, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.addInstrumentedModuleFromAddr") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let addr = match extract_u64_arg(ctx, argv, 1, "qbdi.addInstrumentedModuleFromAddr") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_add_instrumented_module_from_addr)(handle, addr))
});

js_bool_method!(js_qbdi_instrument_all_executable_maps, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.instrumentAllExecutableMaps") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_instrument_all_executable_maps)(handle))
});

js_bool_method!(js_qbdi_remove_instrumented_range, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.removeInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let start = match extract_u64_arg(ctx, argv, 1, "qbdi.removeInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let end = match extract_u64_arg(ctx, argv, 2, "qbdi.removeInstrumentedRange") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_remove_instrumented_range)(handle, start, end))
});

js_bool_method!(js_qbdi_remove_all_instrumented_ranges, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.removeAllInstrumentedRanges") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_remove_all_instrumented_ranges)(handle))
});

js_bool_method!(js_qbdi_delete_all_instrumentations, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.deleteAllInstrumentations") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_delete_all_instrumentations)(handle))
});

js_bool_method!(js_qbdi_record_memory_access, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.recordMemoryAccess") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let access_type = match extract_u32_arg(ctx, argv, 1, "qbdi.recordMemoryAccess") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_record_memory_access)(handle, access_type))
});

js_bool_method!(js_qbdi_allocate_virtual_stack, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.allocateVirtualStack") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let stack_size = match extract_u32_arg(ctx, argv, 1, "qbdi.allocateVirtualStack") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_allocate_virtual_stack)(handle, stack_size))
});

js_bool_method!(js_qbdi_clear_virtual_stacks, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.clearVirtualStacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_clear_virtual_stacks)(handle))
});

js_bool_method!(js_qbdi_simulate_call, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.simulateCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let return_addr = match extract_u64_arg(ctx, argv, 1, "qbdi.simulateCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args = match collect_u64_args(ctx, argc, argv, 2, "qbdi.simulateCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_simulate_call)(
        handle,
        return_addr,
        args.as_ptr(),
        args.len() as u32,
    ))
});

js_bool_method!(js_qbdi_run, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.run") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let start = match extract_u64_arg(ctx, argv, 1, "qbdi.run") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let stop = match extract_u64_arg(ctx, argv, 2, "qbdi.run") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_run)(handle, start, stop))
});

unsafe fn js_call_like(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    func_name: &str,
    invoker: impl FnOnce(&HelperApi, u64, u64, &[u64], *mut u64) -> i32,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            CString::new(format!("{}() requires vm and target", func_name))
                .unwrap()
                .as_ptr(),
        );
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, func_name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match extract_u64_arg(ctx, argv, 1, func_name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args = match collect_u64_args(ctx, argc, argv, 2, func_name) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut result = 0u64;
    value_or_null(ctx, invoker(api, handle, target, &args, &mut result), result)
}

unsafe extern "C" fn js_qbdi_call(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_call_like(ctx, argc, argv, "qbdi.call", |api, handle, target, args, result_out| {
        (api.vm_call)(handle, target, args.as_ptr(), args.len() as u32, result_out)
    })
}

unsafe extern "C" fn js_qbdi_switch_stack_and_call(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"qbdi.switchStackAndCall() requires vm, target, stackSize\0".as_ptr() as *const _,
        );
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match extract_u64_arg(ctx, argv, 1, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let stack_size = match extract_u32_arg(ctx, argv, 2, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let args = match collect_u64_args(ctx, argc, argv, 3, "qbdi.switchStackAndCall") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut result = 0u64;
    value_or_null(
        ctx,
        (api.vm_switch_stack_and_call)(
            handle,
            target,
            stack_size,
            args.as_ptr(),
            args.len() as u32,
            &mut result,
        ),
        result,
    )
}

unsafe extern "C" fn js_qbdi_get_gpr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"qbdi.getGPR() requires vm and reg\0".as_ptr() as *const _);
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.getGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.getGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut value = 0u64;
    value_or_null(ctx, (api.vm_get_gpr)(handle, reg, &mut value), value)
}

js_bool_method!(js_qbdi_set_gpr, 3, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.setGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.setGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match extract_u64_arg(ctx, argv, 2, "qbdi.setGPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_set_gpr)(handle, reg, value))
});

unsafe extern "C" fn js_qbdi_get_fpr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"qbdi.getFPR() requires vm and reg\0".as_ptr() as *const _);
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.getFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.getFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut lo = 0u64;
    let mut hi = 0u64;
    if (api.vm_get_fpr)(handle, reg, &mut lo, &mut hi) != 0 {
        return JSValue::null().raw();
    }
    let obj = JSValue(ffi::JS_NewObject(ctx));
    let _ = obj.set_property(ctx, "lo", JSValue(ffi::JS_NewBigUint64(ctx, lo)));
    let _ = obj.set_property(ctx, "hi", JSValue(ffi::JS_NewBigUint64(ctx, hi)));
    obj.raw()
}

js_bool_method!(js_qbdi_set_fpr, 4, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reg = match extract_u32_arg(ctx, argv, 1, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let lo = match extract_u64_arg(ctx, argv, 2, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let hi = match extract_u64_arg(ctx, argv, 3, "qbdi.setFPR") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_set_fpr)(handle, reg, lo, hi))
});

unsafe extern "C" fn js_qbdi_get_errno(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"qbdi.getErrno() requires vm\0".as_ptr() as *const _);
    }
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.getErrno") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut value = 0u32;
    if (api.vm_get_errno)(handle, &mut value) != 0 {
        return JSValue::null().raw();
    }
    JSValue::int(value as i32).raw()
}

js_bool_method!(js_qbdi_set_errno, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.setErrno") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match extract_u32_arg(ctx, argv, 1, "qbdi.setErrno") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_set_errno)(handle, value))
});

js_bool_method!(js_qbdi_set_trace_bundle_metadata, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let module_path = match extract_string_arg_owned(ctx, argv, 0, "qbdi.setTraceBundleMetadata") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let module_base = match extract_u64_arg(ctx, argv, 1, "qbdi.setTraceBundleMetadata") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let c_path = CString::new(module_path).unwrap();
    bool_from_rc((api.trace_set_bundle_metadata)(c_path.as_ptr(), module_base))
});

js_bool_method!(js_qbdi_register_trace_callbacks, 2, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.registerTraceCallbacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let target = match extract_u64_arg(ctx, argv, 1, "qbdi.registerTraceCallbacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let output_dir = if argc >= 3 {
        match extract_string_arg_owned(ctx, argv, 2, "qbdi.registerTraceCallbacks") {
            Ok(v) => v,
            Err(e) => return e,
        }
    } else {
        qbdi_output_dir().unwrap_or("").to_string()
    };
    if output_dir.is_empty() {
        return throw_internal_error(ctx, "qbdi output dir not configured");
    }
    let c_output = CString::new(output_dir).unwrap();
    bool_from_rc((api.vm_register_trace_callbacks)(handle, target, c_output.as_ptr()))
});

js_bool_method!(js_qbdi_unregister_trace_callbacks, 1, |ctx, argc, argv| {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(err) => return throw_internal_error(ctx, err),
    };
    let handle = match extract_u64_arg(ctx, argv, 0, "qbdi.unregisterTraceCallbacks") {
        Ok(v) => v,
        Err(e) => return e,
    };
    bool_from_rc((api.vm_unregister_trace_callbacks)(handle))
});

unsafe extern "C" fn js_qbdi_last_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let api = match load_qbdi_helper() {
        Ok(api) => api,
        Err(_) => return JSValue::null().raw(),
    };
    match helper_last_error(api) {
        Some(err) => JSValue::string(ctx, &err).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_qbdi_shutdown(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    shutdown_qbdi_helper();
    JSValue::bool(true).raw()
}

pub fn register_qbdi_api(ctx: *mut ffi::JSContext, qbdi_obj: ffi::JSValue) {
    unsafe {
        add_cfunction_to_object(ctx, qbdi_obj, "newVM", js_qbdi_new_vm, 0);
        add_cfunction_to_object(ctx, qbdi_obj, "destroyVM", js_qbdi_destroy_vm, 1);
        add_cfunction_to_object(ctx, qbdi_obj, "addInstrumentedRange", js_qbdi_add_instrumented_range, 3);
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "addInstrumentedModule",
            js_qbdi_add_instrumented_module,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "addInstrumentedModuleFromAddr",
            js_qbdi_add_instrumented_module_from_addr,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "instrumentAllExecutableMaps",
            js_qbdi_instrument_all_executable_maps,
            1,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "removeInstrumentedRange",
            js_qbdi_remove_instrumented_range,
            3,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "removeAllInstrumentedRanges",
            js_qbdi_remove_all_instrumented_ranges,
            1,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "deleteAllInstrumentations",
            js_qbdi_delete_all_instrumentations,
            1,
        );
        add_cfunction_to_object(ctx, qbdi_obj, "recordMemoryAccess", js_qbdi_record_memory_access, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "allocateVirtualStack", js_qbdi_allocate_virtual_stack, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "clearVirtualStacks", js_qbdi_clear_virtual_stacks, 1);
        add_cfunction_to_object(ctx, qbdi_obj, "simulateCall", js_qbdi_simulate_call, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "run", js_qbdi_run, 3);
        add_cfunction_to_object(ctx, qbdi_obj, "call", js_qbdi_call, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "switchStackAndCall", js_qbdi_switch_stack_and_call, 3);
        add_cfunction_to_object(ctx, qbdi_obj, "getGPR", js_qbdi_get_gpr, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "setGPR", js_qbdi_set_gpr, 3);
        add_cfunction_to_object(ctx, qbdi_obj, "getFPR", js_qbdi_get_fpr, 2);
        add_cfunction_to_object(ctx, qbdi_obj, "setFPR", js_qbdi_set_fpr, 4);
        add_cfunction_to_object(ctx, qbdi_obj, "getErrno", js_qbdi_get_errno, 1);
        add_cfunction_to_object(ctx, qbdi_obj, "setErrno", js_qbdi_set_errno, 2);
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "setTraceBundleMetadata",
            js_qbdi_set_trace_bundle_metadata,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "registerTraceCallbacks",
            js_qbdi_register_trace_callbacks,
            2,
        );
        add_cfunction_to_object(
            ctx,
            qbdi_obj,
            "unregisterTraceCallbacks",
            js_qbdi_unregister_trace_callbacks,
            1,
        );
        add_cfunction_to_object(ctx, qbdi_obj, "lastError", js_qbdi_last_error, 0);
        add_cfunction_to_object(ctx, qbdi_obj, "shutdown", js_qbdi_shutdown, 0);
    }

    let obj = JSValue(qbdi_obj);
    let _ = obj.set_property(ctx, "MEMORY_READ", JSValue::int(1));
    let _ = obj.set_property(ctx, "MEMORY_WRITE", JSValue::int(2));
    let _ = obj.set_property(ctx, "MEMORY_READ_WRITE", JSValue::int(3));
    let _ = obj.set_property(ctx, "REG_RETURN", JSValue::int(0));
    let _ = obj.set_property(ctx, "REG_BP", JSValue::int(29));
    let _ = obj.set_property(ctx, "REG_LR", JSValue::int(30));
    let _ = obj.set_property(ctx, "REG_SP", JSValue::int(31));
    let _ = obj.set_property(ctx, "REG_FLAG", JSValue::int(32));
    let _ = obj.set_property(ctx, "REG_PC", JSValue::int(33));
}
