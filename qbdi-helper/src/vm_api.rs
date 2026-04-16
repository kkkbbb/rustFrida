use crate::state::{
    clear_last_error, decode_args, decode_memory_access_type, set_last_error, with_vm, ManagedVm, NEXT_VM_HANDLE,
    VM_REGISTRY,
};
use crate::writer::flush_thread_local_chunk;
use qbdi::{simulate_call, GPRState, VirtualStack};
use std::ffi::{c_char, CStr};
use std::sync::atomic::Ordering;

#[no_mangle]
pub extern "C" fn qbdi_vm_new() -> u64 {
    clear_last_error();
    let handle = NEXT_VM_HANDLE.fetch_add(1, Ordering::Relaxed);
    let mut registry = VM_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    registry.insert(
        handle,
        ManagedVm {
            vm: qbdi::VM::new(),
            stacks: Vec::new(),
            trace_callback_ids: Vec::new(),
        },
    );
    handle
}

#[no_mangle]
pub extern "C" fn qbdi_vm_destroy(handle: u64) -> i32 {
    clear_last_error();
    let mut registry = VM_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if registry.remove(&handle).is_some() {
        0
    } else {
        set_last_error(format!("invalid qbdi vm handle {}", handle));
        -1
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_add_instrumented_range(handle: u64, start: u64, end: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        managed.vm.add_instrumented_range(start, end);
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_add_instrumented_module(handle: u64, name: *const c_char) -> i32 {
    clear_last_error();
    if name.is_null() {
        set_last_error("module name is null");
        return -1;
    }
    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(name) => name,
        Err(_) => {
            set_last_error("module name is not utf-8");
            return -1;
        }
    };
    match with_vm(handle, |managed| Ok(managed.vm.add_instrumented_module(name))) {
        Ok(true) => 0,
        Ok(false) => {
            set_last_error(format!("qbdi addInstrumentedModule({}) failed", name));
            -1
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_add_instrumented_module_from_addr(handle: u64, addr: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| Ok(managed.vm.add_instrumented_module_from_addr(addr))) {
        Ok(true) => 0,
        Ok(false) => {
            set_last_error(format!("qbdi addInstrumentedModuleFromAddr({:#x}) failed", addr));
            -1
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_instrument_all_executable_maps(handle: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| Ok(managed.vm.instrument_all_executable_maps())) {
        Ok(true) => 0,
        Ok(false) => {
            set_last_error("qbdi instrumentAllExecutableMaps() failed");
            -1
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_remove_instrumented_range(handle: u64, start: u64, end: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        managed.vm.remove_instrumented_range(start, end);
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_remove_all_instrumented_ranges(handle: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        managed.vm.remove_all_instrumented_ranges();
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_delete_all_instrumentations(handle: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        managed.vm.delete_all_instrumentations();
        managed.trace_callback_ids.clear();
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_record_memory_access(handle: u64, access_type: u32) -> i32 {
    clear_last_error();
    let access_type = match decode_memory_access_type(access_type) {
        Ok(kind) => kind,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    match with_vm(handle, |managed| Ok(managed.vm.record_memory_access(access_type))) {
        Ok(true) => 0,
        Ok(false) => {
            set_last_error("qbdi recordMemoryAccess() failed");
            -1
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_allocate_virtual_stack(handle: u64, stack_size: u32) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        let gpr = managed
            .vm
            .gpr_state()
            .ok_or_else(|| "QBDI GPRState is null".to_string())?;
        let stack = VirtualStack::new(gpr as *mut GPRState, stack_size)
            .ok_or_else(|| format!("QBDI allocateVirtualStack({:#x}) failed", stack_size))?;
        managed.stacks.push(stack);
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_clear_virtual_stacks(handle: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        managed.stacks.clear();
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_simulate_call(handle: u64, return_addr: u64, args_ptr: *const u64, args_len: u32) -> i32 {
    clear_last_error();
    let args = match decode_args(args_ptr, args_len) {
        Ok(args) => args,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    match with_vm(handle, |managed| {
        let gpr = managed
            .vm
            .gpr_state()
            .ok_or_else(|| "QBDI GPRState is null".to_string())?;
        simulate_call(gpr, return_addr, args);
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_run(handle: u64, start: u64, stop: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        let ok = managed.vm.run(start, stop);
        flush_thread_local_chunk();
        Ok(ok)
    }) {
        Ok(true) => 0,
        Ok(false) => {
            set_last_error(format!("qbdi run({:#x}, {:#x}) failed", start, stop));
            -1
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_call(
    handle: u64,
    function: u64,
    args_ptr: *const u64,
    args_len: u32,
    result_out: *mut u64,
) -> i32 {
    clear_last_error();
    if result_out.is_null() {
        set_last_error("result_out is null");
        return -1;
    }
    let args = match decode_args(args_ptr, args_len) {
        Ok(args) => args,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    match with_vm(handle, |managed| {
        managed
            .vm
            .call(function, args)
            .ok_or_else(|| format!("qbdi call({:#x}) failed", function))
    }) {
        Ok(value) => {
            unsafe {
                *result_out = value;
            }
            0
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_switch_stack_and_call(
    handle: u64,
    function: u64,
    stack_size: u32,
    args_ptr: *const u64,
    args_len: u32,
    result_out: *mut u64,
) -> i32 {
    clear_last_error();
    if result_out.is_null() {
        set_last_error("result_out is null");
        return -1;
    }
    let args = match decode_args(args_ptr, args_len) {
        Ok(args) => args,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    match with_vm(handle, |managed| {
        managed
            .vm
            .switch_stack_and_call(function, stack_size, args)
            .ok_or_else(|| format!("qbdi switchStackAndCall({:#x}) failed", function))
    }) {
        Ok(value) => {
            unsafe {
                *result_out = value;
            }
            0
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_get_gpr(handle: u64, reg: u32, value_out: *mut u64) -> i32 {
    clear_last_error();
    if value_out.is_null() {
        set_last_error("value_out is null");
        return -1;
    }
    match with_vm(handle, |managed| {
        let gpr = managed
            .vm
            .gpr_state()
            .ok_or_else(|| "QBDI GPRState is null".to_string())?;
        gpr.get(reg as usize)
            .ok_or_else(|| format!("invalid gpr index {}", reg))
    }) {
        Ok(value) => {
            unsafe {
                *value_out = value;
            }
            0
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_set_gpr(handle: u64, reg: u32, value: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        let gpr = managed
            .vm
            .gpr_state()
            .ok_or_else(|| "QBDI GPRState is null".to_string())?;
        if gpr.set(reg as usize, value) {
            Ok(())
        } else {
            Err(format!("invalid gpr index {}", reg))
        }
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_get_fpr(handle: u64, reg: u32, lo_out: *mut u64, hi_out: *mut u64) -> i32 {
    clear_last_error();
    if lo_out.is_null() || hi_out.is_null() {
        set_last_error("lo_out or hi_out is null");
        return -1;
    }
    match with_vm(handle, |managed| {
        managed
            .vm
            .fpr_state()
            .get(reg as usize)
            .ok_or_else(|| format!("invalid fpr index {}", reg))
    }) {
        Ok(value) => {
            unsafe {
                *lo_out = value as u64;
                *hi_out = (value >> 64) as u64;
            }
            0
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_set_fpr(handle: u64, reg: u32, lo: u64, hi: u64) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        let value = (lo as u128) | ((hi as u128) << 64);
        if managed.vm.fpr_state().set(reg as usize, value) {
            Ok(())
        } else {
            Err(format!("invalid fpr index {}", reg))
        }
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_get_errno(handle: u64, value_out: *mut u32) -> i32 {
    clear_last_error();
    if value_out.is_null() {
        set_last_error("value_out is null");
        return -1;
    }
    match with_vm(handle, |managed| Ok(managed.vm.get_errno())) {
        Ok(value) => {
            unsafe {
                *value_out = value;
            }
            0
        }
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_set_errno(handle: u64, value: u32) -> i32 {
    clear_last_error();
    match with_vm(handle, |managed| {
        managed.vm.set_errno(value);
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}
