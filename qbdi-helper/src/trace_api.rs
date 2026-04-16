use crate::data::{DynamicExecChunk, ExternalReturn, MemAccess, TraceBundleEvent, TraceBundleEventKind, TraceContext};
use crate::state::{
    clear_last_error, get_trace_bundle_metadata, helper_log, set_last_error, set_trace_output_dir, ExecMap,
    ADDED_DYNAMIC_RANGES, ADDED_MODULES, DUMPED_DYNAMIC_RANGES, DYNAMIC_EXEC_CHUNK_SIZE, TRACE_EXECUTED_INSTRUCTIONS,
    TRACE_PROGRESS_EVERY,
};
use crate::writer::{finalize_trace_session_async, shutdown_trace_writer, start_trace_writer, trace_send};
use qbdi::ffi::{
    qbdi_addInstrumentedRange, InstPosition_QBDI_PREINST, MemoryAccessType_QBDI_MEMORY_READ, VMAction_QBDI_BREAK_TO_VM,
    VMAction_QBDI_CONTINUE, VMEvent_QBDI_EXEC_TRANSFER_CALL, VMEvent_QBDI_EXEC_TRANSFER_RETURN, VMInstanceRef,
};
use qbdi::{FPRState, GPRState, VMAction, VMRef, VM};
use std::ffi::{c_char, c_void, CStr};
use std::ptr::null_mut;
use std::sync::atomic::Ordering;

extern "C" fn qbdicb(
    _vm: VMInstanceRef,
    gpr_state: *mut GPRState,
    _fpr_state: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if !gpr_state.is_null() {
            let count = TRACE_EXECUTED_INSTRUCTIONS.fetch_add(1, Ordering::Relaxed) + 1;
            trace_send(TraceBundleEvent {
                kind: Some(TraceBundleEventKind::InstructionAddr((*gpr_state).pc)),
            });
            if count % TRACE_PROGRESS_EVERY == 0 {
                helper_log(&format!(
                    "[qbdi-helper] trace progress: instructions={} pc={:#x}",
                    count,
                    (*gpr_state).pc
                ));
            }
        }
    }
    VMAction_QBDI_CONTINUE
}

extern "C" fn mem_acc_cb(vm: VMInstanceRef, _gpr: *mut GPRState, _fpr: *mut FPRState, _data: *mut c_void) -> VMAction {
    unsafe {
        let accesses = VMRef::from_raw(vm).get_inst_memory_access();
        for acc in accesses {
            if !acc.is_read() {
                continue;
            }
            trace_send(TraceBundleEvent {
                kind: Some(TraceBundleEventKind::MemAccess(MemAccess {
                    inst_addr: acc.inst_address(),
                    access_addr: acc.access_address(),
                    value: acc.value(),
                    size: acc.size() as u32,
                })),
            });
        }
    }
    VMAction_QBDI_CONTINUE
}

extern "C" fn exec_transfer_return_cb(
    _vm: VMInstanceRef,
    event: *const qbdi::ffi::VMState,
    gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if !event.is_null() && !gpr.is_null() {
            trace_send(TraceBundleEvent {
                kind: Some(TraceBundleEventKind::ExternalReturn(ExternalReturn {
                    return_addr: (*gpr).pc,
                    return_value: (*gpr).x0,
                })),
            });
        }
    }
    VMAction_QBDI_CONTINUE
}

fn read_proc_self_maps() -> Option<String> {
    let bytes = std::fs::read("/proc/self/maps").ok()?;
    Some(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

fn is_executable(perms: &str) -> bool {
    perms.as_bytes().get(2) == Some(&b'x')
}

fn read_all_maps() -> Result<Vec<ExecMap>, String> {
    let maps = read_proc_self_maps().ok_or_else(|| "failed to read /proc/self/maps".to_string())?;
    Ok(maps
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields.next()?;
            let perms = fields.next()?;
            let _offset = fields.next()?;
            let _dev = fields.next()?;
            let _inode = fields.next()?;
            let path = fields.next().unwrap_or("");
            let mut parts = range.splitn(2, '-');
            let start = u64::from_str_radix(parts.next()?, 16).ok()?;
            let end = u64::from_str_radix(parts.next()?, 16).ok()?;
            Some(ExecMap {
                start,
                end,
                perms: perms.to_string(),
                path: path.to_string(),
            })
        })
        .collect())
}

fn read_exec_maps() -> Result<Vec<ExecMap>, String> {
    Ok(read_all_maps()?
        .into_iter()
        .filter(|e| is_executable(&e.perms))
        .collect())
}

fn find_exec_map(target: u64) -> Option<ExecMap> {
    read_exec_maps()
        .ok()?
        .into_iter()
        .find(|entry| target >= entry.start && target < entry.end)
}

fn is_dynamic_exec_map(map: &ExecMap) -> bool {
    if !is_executable(&map.perms) {
        return false;
    }
    map.path.is_empty() || map.path.starts_with("[anon:")
}

fn is_anon_map(map: &ExecMap) -> bool {
    map.path.is_empty() || map.path.starts_with("[anon:")
}

/// 从 all maps 中收集 target 所在匿名段的完整范围（包括相邻的数据段）
/// 返回所有相邻的匿名 map 条目（代码段 + 数据段）
fn collect_anon_region(target: u64) -> Option<Vec<ExecMap>> {
    let all = read_all_maps().ok()?;
    let idx = all.iter().position(|e| target >= e.start && target < e.end)?;
    if !is_anon_map(&all[idx]) {
        return None;
    }

    let is_valid_anon = |e: &ExecMap| is_anon_map(e) && is_readable(&e.perms);

    // 向前扩展：相邻、匿名、可读
    let mut start_idx = idx;
    while start_idx > 0 && is_valid_anon(&all[start_idx - 1]) && all[start_idx - 1].end == all[start_idx].start {
        start_idx -= 1;
    }
    // 向后扩展
    let mut end_idx = idx;
    while end_idx + 1 < all.len() && is_valid_anon(&all[end_idx + 1]) && all[end_idx].end == all[end_idx + 1].start {
        end_idx += 1;
    }

    Some(all[start_idx..=end_idx].to_vec())
}

pub(crate) fn collect_exec_ranges(target: u64) -> Result<Vec<ExecMap>, String> {
    let entries = read_exec_maps()?;
    let containing = entries
        .iter()
        .find(|entry| target >= entry.start && target < entry.end)
        .ok_or_else(|| format!("target {:#x} not found in /proc/self/maps", target))?;

    let ranges: Vec<ExecMap> = if !containing.path.is_empty() && !is_dynamic_exec_map(containing) {
        entries
            .iter()
            .filter(|entry| entry.path == containing.path && is_executable(&entry.perms))
            .cloned()
            .collect()
    } else {
        vec![containing.clone()]
    };

    if ranges.is_empty() {
        Err(format!("no executable range found for target {:#x}", target))
    } else {
        Ok(ranges)
    }
}

fn perms_to_u32(perms: &str) -> u32 {
    let bytes = perms.as_bytes();
    let mut prot = 0u32;
    if bytes.first() == Some(&b'r') {
        prot |= 1;
    }
    if bytes.get(1) == Some(&b'w') {
        prot |= 2;
    }
    if bytes.get(2) == Some(&b'x') {
        prot |= 4;
    }
    prot
}

fn is_readable(perms: &str) -> bool {
    perms.as_bytes().first() == Some(&b'r')
}

/// dump 单个 map 条目的内存到 trace bundle
fn dump_map_region(map: &ExecMap) {
    if !is_readable(&map.perms) {
        return;
    }
    {
        let mut dumped = DUMPED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner());
        if !dumped.insert((map.start, map.end)) {
            return;
        }
    }
    let size = (map.end - map.start) as usize;
    let data = unsafe { std::slice::from_raw_parts(map.start as *const u8, size) }.to_vec();
    let perm = perms_to_u32(&map.perms);
    for (chunk_index, chunk) in data.chunks(DYNAMIC_EXEC_CHUNK_SIZE).enumerate() {
        trace_send(TraceBundleEvent {
            kind: Some(TraceBundleEventKind::DynamicExecChunk(DynamicExecChunk {
                start_addr: map.start,
                end_addr: map.end,
                perm,
                path: map.path.clone(),
                chunk_offset: (chunk_index * DYNAMIC_EXEC_CHUNK_SIZE) as u64,
                data: chunk.to_vec(),
            })),
        });
    }
}

/// dump 目标地址所在的完整匿名段（包括相邻的数据段）
fn dump_anon_region(target: u64) {
    if let Some(region) = collect_anon_region(target) {
        for map in &region {
            dump_map_region(map);
        }
    }
}

pub(crate) fn ensure_dynamic_exec_range_instrumented(vm: VMInstanceRef, map: &ExecMap) {
    if !is_dynamic_exec_map(map) {
        return;
    }
    let mut added = ADDED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner());
    if added.insert((map.start, map.end)) {
        unsafe {
            qbdi_addInstrumentedRange(vm, map.start, map.end);
        }
    }
}

/// 判断路径是否为 app 自身的 SO (在 /data/app/ 下)
fn is_app_so(path: &str) -> bool {
    path.starts_with("/data/app/") && path.ends_with(".so")
}

/// 将模块的所有可执行段加入 instrumented range，并 emit 元数据
fn instrument_module(vm: VMInstanceRef, module_path: &str) {
    let entries = match read_exec_maps() {
        Ok(e) => e,
        Err(_) => return,
    };
    let module_ranges: Vec<&ExecMap> = entries.iter().filter(|e| e.path == module_path).collect();
    if module_ranges.is_empty() {
        return;
    }
    let module_base = module_ranges.iter().map(|e| e.start).min().unwrap();
    for map in &module_ranges {
        unsafe {
            qbdi_addInstrumentedRange(vm, map.start, map.end);
        }
    }
    // emit TraceBundleMetadata 让 replay 端知道需要加载这个 SO
    trace_send(TraceBundleEvent {
        kind: Some(TraceBundleEventKind::TraceBundleMetadata(
            crate::data::TraceBundleMetadata {
                module_path: module_path.to_string(),
                module_base,
            },
        )),
    });
    helper_log(&format!(
        "[trace] 添加 app SO 到 trace: {} base={:#x} ranges={}",
        module_path,
        module_base,
        module_ranges.len()
    ));
}

/// 探测不在 /proc/self/maps 中的隐藏内存页
/// Android 内核可能隐藏 RWX 匿名映射
/// 对 maps 中找不到的地址，按页对齐构造一个匿名 ExecMap
fn fallback_page_map(addr: u64) -> Option<ExecMap> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    if page_size == 0 {
        return None;
    }
    let page_start = addr & !(page_size - 1);
    Some(ExecMap {
        start: page_start,
        end: page_start + page_size,
        perms: "rwxp".to_string(),
        path: String::new(),
    })
}

extern "C" fn exec_transfer_call_cb(
    vm: VMInstanceRef,
    _event: *const qbdi::ffi::VMState,
    gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if gpr.is_null() {
            return VMAction_QBDI_CONTINUE;
        }
        let dest = (*gpr).pc;
        if let Some(map) = find_exec_map(dest) {
            // 匿名/动态内存 → instrument 当前 exec 段, dump 完整匿名段(含数据)
            if is_dynamic_exec_map(&map) {
                ensure_dynamic_exec_range_instrumented(vm, &map);
                dump_anon_region(dest);
                return VMAction_QBDI_BREAK_TO_VM;
            }
            // app 内的其他 SO → 添加整个模块
            if is_app_so(&map.path) {
                let mut added = ADDED_MODULES.lock().unwrap_or_else(|e| e.into_inner());
                if added.insert(map.path.clone()) {
                    drop(added);
                    instrument_module(vm, &map.path);
                    return VMAction_QBDI_BREAK_TO_VM;
                }
            }
            return VMAction_QBDI_CONTINUE;
        }

        // maps 中找不到 → 按页对齐 instrument，dump 单页
        if let Some(map) = fallback_page_map(dest) {
            ensure_dynamic_exec_range_instrumented(vm, &map);
            dump_map_region(&map);
            return VMAction_QBDI_BREAK_TO_VM;
        }
    }
    VMAction_QBDI_CONTINUE
}

fn snapshot_trace_context(vm: &VM, target: u64) -> Result<TraceContext, String> {
    let gpr = vm.gpr_state().ok_or_else(|| "QBDI GPRState is null".to_string())?;
    let fpr = vm.fpr_state();
    let tpidr_el0 = read_tpidr_el0();

    let x = vec![
        gpr.x0, gpr.x1, gpr.x2, gpr.x3, gpr.x4, gpr.x5, gpr.x6, gpr.x7, gpr.x8, gpr.x9, gpr.x10, gpr.x11, gpr.x12,
        gpr.x13, gpr.x14, gpr.x15, gpr.x16, gpr.x17, gpr.x18, gpr.x19, gpr.x20, gpr.x21, gpr.x22, gpr.x23, gpr.x24,
        gpr.x25, gpr.x26, gpr.x27, gpr.x28, gpr.x29, gpr.lr,
    ];
    let q_regs = [
        fpr.v0, fpr.v1, fpr.v2, fpr.v3, fpr.v4, fpr.v5, fpr.v6, fpr.v7, fpr.v8, fpr.v9, fpr.v10, fpr.v11, fpr.v12,
        fpr.v13, fpr.v14, fpr.v15, fpr.v16, fpr.v17, fpr.v18, fpr.v19, fpr.v20, fpr.v21, fpr.v22, fpr.v23, fpr.v24,
        fpr.v25, fpr.v26, fpr.v27, fpr.v28, fpr.v29, fpr.v30, fpr.v31,
    ];
    let mut q = Vec::with_capacity(64);
    for value in q_regs {
        q.push(value as u64);
        q.push((value >> 64) as u64);
    }

    Ok(TraceContext {
        x,
        sp: gpr.sp,
        pc: target,
        nzcv: gpr.nzcv,
        tpidr_el0,
        q,
        fpcr: fpr.fpcr,
        fpsr: fpr.fpsr,
    })
}

fn infer_trace_bundle_metadata(target: u64) -> Option<crate::data::TraceBundleMetadata> {
    let containing = find_exec_map(target)?;
    if containing.path.is_empty() || is_dynamic_exec_map(&containing) {
        return None;
    }

    let module_base = read_exec_maps()
        .ok()?
        .into_iter()
        .filter(|entry| entry.path == containing.path && is_executable(&entry.perms))
        .map(|entry| entry.start)
        .min()
        .unwrap_or(containing.start);

    Some(crate::data::TraceBundleMetadata {
        module_path: containing.path,
        module_base,
    })
}

fn emit_trace_bundle_metadata(target: u64) {
    let metadata = get_trace_bundle_metadata().or_else(|| infer_trace_bundle_metadata(target));
    if let Some(metadata) = metadata {
        trace_send(TraceBundleEvent {
            kind: Some(TraceBundleEventKind::TraceBundleMetadata(metadata)),
        });
    }
}

#[cfg(target_arch = "aarch64")]
fn read_tpidr_el0() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {value}, tpidr_el0", value = out(reg) value);
    }
    value
}

#[cfg(not(target_arch = "aarch64"))]
fn read_tpidr_el0() -> u64 {
    0
}

#[no_mangle]
pub extern "C" fn qbdi_trace_shutdown() {
    shutdown_trace_writer();
}

#[no_mangle]
pub extern "C" fn qbdi_vm_register_trace_callbacks(handle: u64, target: u64, output_dir: *const c_char) -> i32 {
    clear_last_error();
    if output_dir.is_null() {
        set_last_error("output_dir is null");
        return -1;
    }
    let output_dir = match unsafe { CStr::from_ptr(output_dir) }.to_str() {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => {
            set_last_error("empty output_dir");
            return -1;
        }
        Err(_) => {
            set_last_error("invalid output_dir");
            return -1;
        }
    };
    set_trace_output_dir(output_dir);
    if let Err(err) = start_trace_writer() {
        set_last_error(err);
        return -1;
    }

    let result = crate::state::with_vm(handle, |managed| {
        managed.vm.delete_all_instrumentations();
        managed.trace_callback_ids.clear();
        ADDED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner()).clear();
        DUMPED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner()).clear();
        {
            let mut modules = ADDED_MODULES.lock().unwrap_or_else(|e| e.into_inner());
            modules.clear();
            // 主模块加入已添加集合，避免 exec_transfer_call_cb 重复添加
            if let Some(map) = find_exec_map(target) {
                if !map.path.is_empty() {
                    modules.insert(map.path.clone());
                }
            }
        }

        let ranges = collect_exec_ranges(target)?;
        for map in &ranges {
            managed.vm.add_instrumented_range(map.start, map.end);
        }

        emit_trace_bundle_metadata(target);
        trace_send(TraceBundleEvent {
            kind: Some(TraceBundleEventKind::TraceContext(snapshot_trace_context(
                &managed.vm,
                target,
            )?)),
        });

        let code_cb = managed
            .vm
            .add_code_cb(InstPosition_QBDI_PREINST, Some(qbdicb), null_mut(), 0);
        let _ = managed.vm.record_memory_access(MemoryAccessType_QBDI_MEMORY_READ);
        let mem_cb = managed
            .vm
            .add_mem_access_cb(MemoryAccessType_QBDI_MEMORY_READ, Some(mem_acc_cb), null_mut(), 0);
        let call_cb =
            managed
                .vm
                .add_vm_event_cb(VMEvent_QBDI_EXEC_TRANSFER_CALL, Some(exec_transfer_call_cb), null_mut());
        let ret_cb = managed.vm.add_vm_event_cb(
            VMEvent_QBDI_EXEC_TRANSFER_RETURN,
            Some(exec_transfer_return_cb),
            null_mut(),
        );
        managed.trace_callback_ids = vec![code_cb, mem_cb, call_cb, ret_cb];
        Ok(())
    });

    match result {
        Ok(()) => 0,
        Err(err) => {
            finalize_trace_session_async();
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_unregister_trace_callbacks(handle: u64) -> i32 {
    clear_last_error();
    match crate::state::with_vm(handle, |managed| {
        for id in managed.trace_callback_ids.drain(..) {
            let _ = managed.vm.delete_instrumentation(id);
        }
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}
