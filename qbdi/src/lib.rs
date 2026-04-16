//! # QBDI - QuarkslaB Dynamic binary Instrumentation
//!
//! Rust bindings for QBDI, a modular, cross-platform, and cross-architecture DBI framework.
//!
//! ## Example
//!
//! ```rust,ignore
//! use qbdi::{VM, VMRef, VMOptions, VMAction, InstPosition, AnalysisType};
//!
//! // Create a new VM
//! let vm = VM::new();
//!
//! // Add instrumented range
//! vm.add_instrumented_module_from_addr(target_function as usize as u64);
//!
//! // Setup callback - use VMRef to access VM methods
//! extern "C" fn my_callback(
//!     vm_ptr: qbdi::ffi::VMInstanceRef,
//!     gpr: *mut qbdi::GPRState,
//!     fpr: *mut qbdi::FPRState,
//!     data: *mut std::ffi::c_void,
//! ) -> VMAction {
//!     let vm = unsafe { VMRef::from_raw(vm_ptr) };
//!     // VMRef derefs to VM, so all VM methods are available
//!     if let Some(analysis) = vm.get_inst_analysis(AnalysisType::ANALYSIS_INSTRUCTION) {
//!         println!("0x{:x}: {}", analysis.address(), analysis.mnemonic().unwrap_or("?"));
//!     }
//!     VMAction::Continue
//! }
//!
//! vm.add_code_cb(InstPosition::PreInst, Some(my_callback), std::ptr::null_mut(), 0);
//!
//! // Allocate stack and run
//! let gpr = vm.gpr_state().expect("GPRState is null");
//! let mut stack = qbdi::memory::VirtualStack::new(gpr, 0x100000).unwrap();
//!
//! // Call the function
//! vm.call(target_function as usize as u64, &[arg1, arg2]);
//! ```

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod callback;
pub mod ffi;
pub mod memory;
pub mod state;
pub mod vm;

// Re-export commonly used types
pub use callback::{
    AnalysisType, CallbackId, ConditionType, InstAnalysis, InstPosition, MemoryAccess, MemoryAccessFlags,
    MemoryAccessType, OperandAnalysis, OperandFlag, OperandType, RegisterAccessType, VMAction, VMEvent, VMState,
    INVALID_EVENTID, PRIORITY_DEFAULT, PRIORITY_MEMACCESS_LIMIT,
};

pub use memory::{
    find_module, find_module_by_addr, get_current_process_maps, get_module_executable_ranges, get_module_names,
    get_remote_process_maps, simulate_call, AlignedAlloc, MemoryMap, Permission, VirtualStack,
};

pub use state::{
    FPRState, GPRState, LocalMonitor, RWord, SWord, AVAILABLE_GPR, GPR_NAMES, NUM_GPR, REG_BP, REG_FLAG, REG_LR,
    REG_PC, REG_RETURN, REG_SP,
};

pub use vm::{VMOptions, VMRef, VM};

// Version information
pub const QBDI_VERSION_MAJOR: u32 = 0;
pub const QBDI_VERSION_MINOR: u32 = 12;
pub const QBDI_VERSION_PATCH: u32 = 1;
pub const QBDI_VERSION_STRING: &str = "0.12.1";

/// Get QBDI version information
pub fn get_version() -> (u32, &'static str) {
    let mut version: u32 = 0;
    let version_str = unsafe {
        let ptr = ffi::qbdi_getVersion(&mut version);
        if ptr.is_null() {
            QBDI_VERSION_STRING
        } else {
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or(QBDI_VERSION_STRING)
        }
    };
    (version, version_str)
}

/// Logging utilities
pub mod log {
    use super::ffi;
    use std::ffi::CString;

    pub use ffi::LogPriority;

    /// Set log output to a file
    pub fn set_log_file(filename: &str, truncate: bool) {
        let filename_cstr = CString::new(filename).unwrap();
        unsafe {
            ffi::qbdi_setLogFile(filename_cstr.as_ptr(), truncate);
        }
    }

    /// Set log output to console (stderr)
    pub fn set_log_console() {
        unsafe {
            ffi::qbdi_setLogConsole();
        }
    }

    /// Set log output to default (stderr on Linux, android_logger on Android)
    pub fn set_log_default() {
        unsafe {
            ffi::qbdi_setLogDefault();
        }
    }

    /// Set minimum log priority
    pub fn set_log_priority(priority: LogPriority) {
        unsafe {
            ffi::qbdi_setLogPriority(priority);
        }
    }
}
