//! QBDI Virtual Machine wrapper

use crate::callback::{
    AnalysisType, CallbackId, InstAnalysis, InstPosition, MemoryAccess, MemoryAccessType, INVALID_EVENTID,
};
use crate::ffi::{self, VMInstanceRef};
use crate::state::{FPRState, GPRState, RWord};
use bitflags::bitflags;
use libc::c_void;
use std::ffi::CString;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::ptr;

bitflags! {
    /// VM Options flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VMOptions: u32 {
        /// No options
        const NO_OPT = 0;
        /// Disable all FPU operations
        const DISABLE_FPR = 1 << 0;
        /// Disable FPR context switch optimization
        const DISABLE_OPTIONAL_FPR = 1 << 1;
        /// Don't load memory access values
        const DISABLE_MEMORYACCESS_VALUE = 1 << 2;
        /// Don't save/restore errno
        const DISABLE_ERRNO_BACKUP = 1 << 3;
        /// Disable local monitor for exclusive load/store
        const DISABLE_LOCAL_MONITOR = 1 << 24;
        /// Disable pointer authentication
        const BYPASS_PAUTH = 1 << 25;
        /// Enable BTI on instrumented code
        const ENABLE_BTI = 1 << 26;
    }
}

impl Default for VMOptions {
    fn default() -> Self {
        VMOptions::NO_OPT
    }
}

/// QBDI Virtual Machine (owned)
///
/// This type owns the VM instance and will terminate it when dropped.
#[repr(transparent)]
pub struct VM {
    instance: VMInstanceRef,
}

impl VM {
    /// Create a new VM instance with default options
    pub fn new() -> Self {
        Self::with_options(VMOptions::NO_OPT, None, None)
    }

    /// Create a new VM instance with specified options
    pub fn with_options(options: VMOptions, cpu: Option<&str>, mattrs: Option<&[&str]>) -> Self {
        let mut instance: VMInstanceRef = ptr::null_mut();

        let cpu_cstr = cpu.map(|s| CString::new(s).unwrap());
        let cpu_ptr = cpu_cstr.as_ref().map_or(ptr::null(), |s| s.as_ptr());

        let mattrs_cstrs: Option<Vec<CString>> =
            mattrs.map(|attrs| attrs.iter().map(|s| CString::new(*s).unwrap()).collect());

        let mut mattrs_ptrs: Option<Vec<*const libc::c_char>> = mattrs_cstrs.as_ref().map(|v| {
            let mut ptrs: Vec<*const libc::c_char> = v.iter().map(|s| s.as_ptr()).collect();
            ptrs.push(ptr::null()); // NULL terminator
            ptrs
        });

        let mattrs_ptr = mattrs_ptrs.as_mut().map_or(ptr::null_mut(), |v| v.as_mut_ptr());

        unsafe {
            ffi::qbdi_initVM(&mut instance, cpu_ptr, mattrs_ptr, options.bits());
        }

        Self { instance }
    }

    /// Get the raw VM instance pointer (for advanced use)
    #[inline]
    pub fn as_ptr(&self) -> VMInstanceRef {
        self.instance
    }

    // ========================================================================
    // Instrumented ranges management
    // ========================================================================

    /// Add an address range to the instrumented set
    pub fn add_instrumented_range(&self, start: RWord, end: RWord) {
        unsafe {
            ffi::qbdi_addInstrumentedRange(self.instance, start, end);
        }
    }

    /// Add a module's executable ranges to the instrumented set
    pub fn add_instrumented_module(&self, name: &str) -> bool {
        let name_cstr = CString::new(name).unwrap();
        unsafe { ffi::qbdi_addInstrumentedModule(self.instance, name_cstr.as_ptr()) }
    }

    /// Add a module's executable ranges using an address within the module
    pub fn add_instrumented_module_from_addr(&self, addr: RWord) -> bool {
        unsafe { ffi::qbdi_addInstrumentedModuleFromAddr(self.instance, addr) }
    }

    /// Add all executable memory maps to the instrumented set
    pub fn instrument_all_executable_maps(&self) -> bool {
        unsafe { ffi::qbdi_instrumentAllExecutableMaps(self.instance) }
    }

    /// Remove an address range from the instrumented set
    pub fn remove_instrumented_range(&self, start: RWord, end: RWord) {
        unsafe {
            ffi::qbdi_removeInstrumentedRange(self.instance, start, end);
        }
    }

    /// Remove a module's ranges from the instrumented set
    pub fn remove_instrumented_module(&self, name: &str) -> bool {
        let name_cstr = CString::new(name).unwrap();
        unsafe { ffi::qbdi_removeInstrumentedModule(self.instance, name_cstr.as_ptr()) }
    }

    /// Remove a module's ranges using an address within the module
    pub fn remove_instrumented_module_from_addr(&self, addr: RWord) -> bool {
        unsafe { ffi::qbdi_removeInstrumentedModuleFromAddr(self.instance, addr) }
    }

    /// Remove all instrumented ranges
    pub fn remove_all_instrumented_ranges(&self) {
        unsafe {
            ffi::qbdi_removeAllInstrumentedRanges(self.instance);
        }
    }

    // ========================================================================
    // Execution
    // ========================================================================

    /// Run execution from start address until stop address is reached
    pub fn run(&self, start: RWord, stop: RWord) -> bool {
        unsafe { ffi::qbdi_run(self.instance, start, stop) }
    }

    /// Call a function with the given arguments
    pub fn call(&self, function: RWord, args: &[RWord]) -> Option<RWord> {
        let mut retval: RWord = 0;
        let success = unsafe {
            ffi::qbdi_callA(
                self.instance,
                &mut retval,
                function,
                args.len() as u32,
                if args.is_empty() { ptr::null() } else { args.as_ptr() },
            )
        };

        if success {
            Some(retval)
        } else {
            None
        }
    }

    /// Call a function with a new stack
    pub fn switch_stack_and_call(&self, function: RWord, stack_size: u32, args: &[RWord]) -> Option<RWord> {
        let mut retval: RWord = 0;
        let success = unsafe {
            ffi::qbdi_switchStackAndCallA(
                self.instance,
                &mut retval,
                function,
                stack_size,
                args.len() as u32,
                if args.is_empty() { ptr::null() } else { args.as_ptr() },
            )
        };

        if success {
            Some(retval)
        } else {
            None
        }
    }

    // ========================================================================
    // State management
    // ========================================================================

    /// Get mutable reference to GPR state
    pub fn gpr_state(&self) -> Option<&mut GPRState> {
        let ptr = unsafe { ffi::qbdi_getGPRState(self.instance) };
        if ptr.is_null() {
            None
        } else {
            unsafe { Some(&mut *ptr) }
        }
    }

    /// Get mutable reference to FPR state
    pub fn fpr_state(&self) -> &mut FPRState {
        unsafe { &mut *ffi::qbdi_getFPRState(self.instance) }
    }

    /// Get the backed up errno value
    pub fn get_errno(&self) -> u32 {
        unsafe { ffi::qbdi_getErrno(self.instance) }
    }

    /// Set the errno backup value
    pub fn set_errno(&self, errno: u32) {
        unsafe {
            ffi::qbdi_setErrno(self.instance, errno);
        }
    }

    /// Set GPR state from a copy
    pub fn set_gpr_state(&self, state: &GPRState) {
        unsafe {
            let gpr = ffi::qbdi_getGPRState(self.instance);
            *gpr = *state;
        }
    }

    /// Set FPR state from a copy
    pub fn set_fpr_state(&self, state: &FPRState) {
        unsafe {
            let fpr = ffi::qbdi_getFPRState(self.instance);
            *fpr = *state;
        }
    }

    // ========================================================================
    // Options
    // ========================================================================

    /// Get current VM options
    pub fn get_options(&self) -> VMOptions {
        VMOptions::from_bits_truncate(unsafe { ffi::qbdi_getOptions(self.instance) })
    }

    /// Set VM options
    pub fn set_options(&self, options: VMOptions) {
        unsafe {
            ffi::qbdi_setOptions(self.instance, options.bits());
        }
    }

    // ========================================================================
    // Callbacks - Code
    // ========================================================================

    /// Add a callback for all instructions
    pub fn add_code_cb(
        &self,
        position: InstPosition,
        callback: ffi::InstCallback,
        data: *mut c_void,
        priority: i32,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addCodeCB(self.instance, position, callback, data, priority) }
    }

    /// Add a callback for a specific address
    pub fn add_code_addr_cb(
        &self,
        address: RWord,
        position: InstPosition,
        callback: ffi::InstCallback,
        data: *mut c_void,
        priority: i32,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addCodeAddrCB(self.instance, address, position, callback, data, priority) }
    }

    /// Add a callback for an address range
    pub fn add_code_range_cb(
        &self,
        start: RWord,
        end: RWord,
        position: InstPosition,
        callback: ffi::InstCallback,
        data: *mut c_void,
        priority: i32,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addCodeRangeCB(self.instance, start, end, position, callback, data, priority) }
    }

    /// Add a callback for instructions matching a mnemonic
    pub fn add_mnemonic_cb(
        &self,
        mnemonic: &str,
        position: InstPosition,
        callback: ffi::InstCallback,
        data: *mut c_void,
        priority: i32,
    ) -> CallbackId {
        let mnemonic_cstr = CString::new(mnemonic).unwrap();
        unsafe {
            ffi::qbdi_addMnemonicCB(
                self.instance,
                mnemonic_cstr.as_ptr(),
                position,
                callback,
                data,
                priority,
            )
        }
    }

    // ========================================================================
    // Callbacks - Memory
    // ========================================================================

    /// Add a callback for memory accesses
    pub fn add_mem_access_cb(
        &self,
        access_type: MemoryAccessType,
        callback: ffi::InstCallback,
        data: *mut c_void,
        priority: i32,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addMemAccessCB(self.instance, access_type, callback, data, priority) }
    }

    /// Add a callback for memory access at a specific address
    pub fn add_mem_addr_cb(
        &self,
        address: RWord,
        access_type: MemoryAccessType,
        callback: ffi::InstCallback,
        data: *mut c_void,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addMemAddrCB(self.instance, address, access_type, callback, data) }
    }

    /// Add a callback for memory access in an address range
    pub fn add_mem_range_cb(
        &self,
        start: RWord,
        end: RWord,
        access_type: MemoryAccessType,
        callback: ffi::InstCallback,
        data: *mut c_void,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addMemRangeCB(self.instance, start, end, access_type, callback, data) }
    }

    // ========================================================================
    // Callbacks - VM Events
    // ========================================================================

    /// Add a callback for VM events
    pub fn add_vm_event_cb(&self, events: u32, callback: ffi::VMCallback, data: *mut c_void) -> CallbackId {
        unsafe { ffi::qbdi_addVMEventCB(self.instance, events, callback, data) }
    }

    // ========================================================================
    // Callbacks - Instrumentation Rules
    // ========================================================================

    /// Add a custom instrumentation rule
    pub fn add_instr_rule(
        &self,
        callback: ffi::InstrRuleCallbackC,
        analysis_type: AnalysisType,
        data: *mut c_void,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addInstrRule(self.instance, callback, analysis_type as u32, data) }
    }

    /// Add a custom instrumentation rule for an address range
    pub fn add_instr_rule_range(
        &self,
        start: RWord,
        end: RWord,
        callback: ffi::InstrRuleCallbackC,
        analysis_type: AnalysisType,
        data: *mut c_void,
    ) -> CallbackId {
        unsafe { ffi::qbdi_addInstrRuleRange(self.instance, start, end, callback, analysis_type as u32, data) }
    }

    // ========================================================================
    // Instrumentation management
    // ========================================================================

    /// Delete an instrumentation by ID
    pub fn delete_instrumentation(&self, id: CallbackId) -> bool {
        if id == INVALID_EVENTID {
            return false;
        }
        unsafe { ffi::qbdi_deleteInstrumentation(self.instance, id) }
    }

    /// Delete all instrumentations
    pub fn delete_all_instrumentations(&self) {
        unsafe {
            ffi::qbdi_deleteAllInstrumentations(self.instance);
        }
    }

    // ========================================================================
    // Analysis
    // ========================================================================

    /// Get analysis of the current instruction (only valid in callbacks)
    pub fn get_inst_analysis(&self, analysis_type: AnalysisType) -> Option<InstAnalysis<'_>> {
        let raw = unsafe { ffi::qbdi_getInstAnalysis(self.instance, analysis_type as u32) };
        if raw.is_null() {
            None
        } else {
            Some(InstAnalysis::from_raw(unsafe { &*raw }))
        }
    }

    /// Get analysis of a cached instruction
    pub fn get_cached_inst_analysis(&self, address: RWord, analysis_type: AnalysisType) -> Option<InstAnalysis<'_>> {
        let raw = unsafe { ffi::qbdi_getCachedInstAnalysis(self.instance, address, analysis_type as u32) };
        if raw.is_null() {
            None
        } else {
            Some(InstAnalysis::from_raw(unsafe { &*raw }))
        }
    }

    /// Get analysis of a JIT instruction
    pub fn get_jit_inst_analysis(&self, address: RWord, analysis_type: AnalysisType) -> Option<InstAnalysis<'_>> {
        let raw = unsafe { ffi::qbdi_getJITInstAnalysis(self.instance, address, analysis_type as u32) };
        if raw.is_null() {
            None
        } else {
            Some(InstAnalysis::from_raw(unsafe { &*raw }))
        }
    }

    // ========================================================================
    // Memory access recording
    // ========================================================================

    /// Enable memory access recording
    pub fn record_memory_access(&self, access_type: MemoryAccessType) -> bool {
        unsafe { ffi::qbdi_recordMemoryAccess(self.instance, access_type) }
    }

    /// Get memory accesses made by the last instruction (only valid in callbacks)
    pub fn get_inst_memory_access(&self) -> Vec<MemoryAccess> {
        let mut size: libc::size_t = 0;
        let accesses = unsafe { ffi::qbdi_getInstMemoryAccess(self.instance, &mut size) };

        if accesses.is_null() || size == 0 {
            return Vec::new();
        }

        (0..size).map(|i| unsafe { *accesses.add(i) }).collect()
    }

    /// Get memory accesses made by the last basic block (only valid in SEQUENCE_EXIT callback)
    pub fn get_bb_memory_access(&self) -> Vec<MemoryAccess> {
        let mut size: libc::size_t = 0;
        let accesses = unsafe { ffi::qbdi_getBBMemoryAccess(self.instance, &mut size) };

        if accesses.is_null() || size == 0 {
            return Vec::new();
        }

        (0..size).map(|i| unsafe { *accesses.add(i) }).collect()
    }

    // ========================================================================
    // Cache management
    // ========================================================================

    /// Pre-cache a basic block
    pub fn precache_basic_block(&self, pc: RWord) -> bool {
        unsafe { ffi::qbdi_precacheBasicBlock(self.instance, pc) }
    }

    /// Clear cache for an address range
    pub fn clear_cache(&self, start: RWord, end: RWord) {
        unsafe {
            ffi::qbdi_clearCache(self.instance, start, end);
        }
    }

    /// Clear the entire cache
    pub fn clear_all_cache(&self) {
        unsafe {
            ffi::qbdi_clearAllCache(self.instance);
        }
    }

    /// Get number of exec blocks in cache
    pub fn get_nb_exec_block(&self) -> u32 {
        unsafe { ffi::qbdi_getNbExecBlock(self.instance) }
    }

    /// Reduce cache to a specific number of exec blocks
    pub fn reduce_cache_to(&self, nb: u32) {
        unsafe {
            ffi::qbdi_reduceCacheTo(self.instance, nb);
        }
    }
}

impl Drop for VM {
    fn drop(&mut self) {
        if !self.instance.is_null() {
            unsafe {
                ffi::qbdi_terminateVM(self.instance);
            }
        }
    }
}

impl Default for VM {
    fn default() -> Self {
        Self::new()
    }
}

// VM is Send but not Sync (not thread-safe)
unsafe impl Send for VM {}

// ============================================================================
// VMRef - Borrowed reference to a VM instance (for use in callbacks)
// ============================================================================

/// A borrowed reference to a QBDI VM instance.
///
/// This type wraps a `VMInstanceRef` without taking ownership, making it safe
/// to use in callbacks where the VM instance is passed as a raw pointer.
/// Unlike `VM`, dropping a `VMRef` does not terminate the VM instance.
///
/// `VMRef` implements `Deref<Target = VM>`, so you can call all `VM` methods
/// directly on a `VMRef`.
///
/// # Example
///
/// ```ignore
/// extern "C" fn my_callback(
///     vm: VMInstanceRef,
///     gpr: *mut GPRState,
///     fpr: *mut FPRState,
///     data: *mut c_void,
/// ) -> VMAction {
///     let vm_ref = unsafe { VMRef::from_raw(vm) };
///     // Call VM methods directly via Deref
///     if let Some(analysis) = vm_ref.get_inst_analysis(AnalysisType::ANALYSIS_INSTRUCTION) {
///         println!("Instruction at: 0x{:x}", analysis.address());
///     }
///     VMAction_QBDI_CONTINUE
/// }
/// ```
pub struct VMRef<'a> {
    inner: ManuallyDrop<VM>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> VMRef<'a> {
    /// Create a VMRef from a raw VMInstanceRef pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `instance` is a valid, non-null VM instance pointer
    /// - The VM instance remains valid for the lifetime `'a`
    #[inline]
    pub unsafe fn from_raw(instance: VMInstanceRef) -> Self {
        debug_assert!(!instance.is_null(), "VMInstanceRef must not be null");
        Self {
            inner: ManuallyDrop::new(VM { instance }),
            _marker: PhantomData,
        }
    }

    /// Get the raw VM instance pointer
    #[inline]
    pub fn as_ptr(&self) -> VMInstanceRef {
        self.inner.instance
    }
}

impl Deref for VMRef<'_> {
    type Target = VM;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for VMRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMRef").field("instance", &self.as_ptr()).finish()
    }
}

// VMRef is Send but not Sync
unsafe impl Send for VMRef<'_> {}
