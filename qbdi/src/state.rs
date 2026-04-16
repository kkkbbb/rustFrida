//! CPU state wrappers for QBDI

use crate::ffi;

pub use ffi::{FPRState, GPRState, LocalMonitor, RWord, SWord};

/// GPR register names for ARM64
pub const GPR_NAMES: [&str; 34] = [
    "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15", "X16", "X17",
    "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28", "X29", "LR", "SP", "NZCV", "PC",
];

/// Register indices
pub const NUM_GPR: usize = 32;
pub const AVAILABLE_GPR: usize = 28;
pub const REG_RETURN: usize = 0;
pub const REG_BP: usize = 29;
pub const REG_LR: usize = 30;
pub const REG_SP: usize = 31;
pub const REG_PC: usize = 33;
pub const REG_FLAG: usize = 32;

impl GPRState {
    /// Create a new zeroed GPRState
    pub fn new() -> Self {
        Self {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
            x7: 0,
            x8: 0,
            x9: 0,
            x10: 0,
            x11: 0,
            x12: 0,
            x13: 0,
            x14: 0,
            x15: 0,
            x16: 0,
            x17: 0,
            x18: 0,
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            x29: 0,
            lr: 0,
            sp: 0,
            nzcv: 0,
            pc: 0,
            localMonitor: LocalMonitor { addr: 0, enable: 0 },
        }
    }

    /// Get a GPR by index (0-33)
    #[inline]
    pub fn get(&self, index: usize) -> Option<RWord> {
        match index {
            0 => Some(self.x0),
            1 => Some(self.x1),
            2 => Some(self.x2),
            3 => Some(self.x3),
            4 => Some(self.x4),
            5 => Some(self.x5),
            6 => Some(self.x6),
            7 => Some(self.x7),
            8 => Some(self.x8),
            9 => Some(self.x9),
            10 => Some(self.x10),
            11 => Some(self.x11),
            12 => Some(self.x12),
            13 => Some(self.x13),
            14 => Some(self.x14),
            15 => Some(self.x15),
            16 => Some(self.x16),
            17 => Some(self.x17),
            18 => Some(self.x18),
            19 => Some(self.x19),
            20 => Some(self.x20),
            21 => Some(self.x21),
            22 => Some(self.x22),
            23 => Some(self.x23),
            24 => Some(self.x24),
            25 => Some(self.x25),
            26 => Some(self.x26),
            27 => Some(self.x27),
            28 => Some(self.x28),
            29 => Some(self.x29),
            30 => Some(self.lr),
            31 => Some(self.sp),
            32 => Some(self.nzcv),
            33 => Some(self.pc),
            _ => None,
        }
    }

    /// Set a GPR by index (0-33)
    #[inline]
    pub fn set(&mut self, index: usize, value: RWord) -> bool {
        match index {
            0 => self.x0 = value,
            1 => self.x1 = value,
            2 => self.x2 = value,
            3 => self.x3 = value,
            4 => self.x4 = value,
            5 => self.x5 = value,
            6 => self.x6 = value,
            7 => self.x7 = value,
            8 => self.x8 = value,
            9 => self.x9 = value,
            10 => self.x10 = value,
            11 => self.x11 = value,
            12 => self.x12 = value,
            13 => self.x13 = value,
            14 => self.x14 = value,
            15 => self.x15 = value,
            16 => self.x16 = value,
            17 => self.x17 = value,
            18 => self.x18 = value,
            19 => self.x19 = value,
            20 => self.x20 = value,
            21 => self.x21 = value,
            22 => self.x22 = value,
            23 => self.x23 = value,
            24 => self.x24 = value,
            25 => self.x25 = value,
            26 => self.x26 = value,
            27 => self.x27 = value,
            28 => self.x28 = value,
            29 => self.x29 = value,
            30 => self.lr = value,
            31 => self.sp = value,
            32 => self.nzcv = value,
            33 => self.pc = value,
            _ => return false,
        }
        true
    }

    /// Get the frame pointer (x29)
    #[inline]
    pub fn fp(&self) -> RWord {
        self.x29
    }

    /// Set the frame pointer (x29)
    #[inline]
    pub fn set_fp(&mut self, value: RWord) {
        self.x29 = value;
    }

    /// Get the return value register (x0)
    #[inline]
    pub fn return_value(&self) -> RWord {
        self.x0
    }

    /// Set the return value register (x0)
    #[inline]
    pub fn set_return_value(&mut self, value: RWord) {
        self.x0 = value;
    }

    /// Get function argument by index (0-7 for ARM64 ABI)
    #[inline]
    pub fn arg(&self, index: usize) -> Option<RWord> {
        match index {
            0 => Some(self.x0),
            1 => Some(self.x1),
            2 => Some(self.x2),
            3 => Some(self.x3),
            4 => Some(self.x4),
            5 => Some(self.x5),
            6 => Some(self.x6),
            7 => Some(self.x7),
            _ => None,
        }
    }

    /// Set function argument by index (0-7 for ARM64 ABI)
    #[inline]
    pub fn set_arg(&mut self, index: usize, value: RWord) -> bool {
        match index {
            0 => self.x0 = value,
            1 => self.x1 = value,
            2 => self.x2 = value,
            3 => self.x3 = value,
            4 => self.x4 = value,
            5 => self.x5 = value,
            6 => self.x6 = value,
            7 => self.x7 = value,
            _ => return false,
        }
        true
    }
}

impl FPRState {
    /// Create a new zeroed FPRState
    pub fn new() -> Self {
        Self {
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            v4: 0,
            v5: 0,
            v6: 0,
            v7: 0,
            v8: 0,
            v9: 0,
            v10: 0,
            v11: 0,
            v12: 0,
            v13: 0,
            v14: 0,
            v15: 0,
            v16: 0,
            v17: 0,
            v18: 0,
            v19: 0,
            v20: 0,
            v21: 0,
            v22: 0,
            v23: 0,
            v24: 0,
            v25: 0,
            v26: 0,
            v27: 0,
            v28: 0,
            v29: 0,
            v30: 0,
            v31: 0,
            fpcr: 0,
            fpsr: 0,
        }
    }

    /// Get a vector register by index (0-31)
    #[inline]
    pub fn get(&self, index: usize) -> Option<u128> {
        match index {
            0 => Some(self.v0),
            1 => Some(self.v1),
            2 => Some(self.v2),
            3 => Some(self.v3),
            4 => Some(self.v4),
            5 => Some(self.v5),
            6 => Some(self.v6),
            7 => Some(self.v7),
            8 => Some(self.v8),
            9 => Some(self.v9),
            10 => Some(self.v10),
            11 => Some(self.v11),
            12 => Some(self.v12),
            13 => Some(self.v13),
            14 => Some(self.v14),
            15 => Some(self.v15),
            16 => Some(self.v16),
            17 => Some(self.v17),
            18 => Some(self.v18),
            19 => Some(self.v19),
            20 => Some(self.v20),
            21 => Some(self.v21),
            22 => Some(self.v22),
            23 => Some(self.v23),
            24 => Some(self.v24),
            25 => Some(self.v25),
            26 => Some(self.v26),
            27 => Some(self.v27),
            28 => Some(self.v28),
            29 => Some(self.v29),
            30 => Some(self.v30),
            31 => Some(self.v31),
            _ => None,
        }
    }

    /// Set a vector register by index (0-31)
    #[inline]
    pub fn set(&mut self, index: usize, value: u128) -> bool {
        match index {
            0 => self.v0 = value,
            1 => self.v1 = value,
            2 => self.v2 = value,
            3 => self.v3 = value,
            4 => self.v4 = value,
            5 => self.v5 = value,
            6 => self.v6 = value,
            7 => self.v7 = value,
            8 => self.v8 = value,
            9 => self.v9 = value,
            10 => self.v10 = value,
            11 => self.v11 = value,
            12 => self.v12 = value,
            13 => self.v13 = value,
            14 => self.v14 = value,
            15 => self.v15 = value,
            16 => self.v16 = value,
            17 => self.v17 = value,
            18 => self.v18 = value,
            19 => self.v19 = value,
            20 => self.v20 = value,
            21 => self.v21 = value,
            22 => self.v22 = value,
            23 => self.v23 = value,
            24 => self.v24 = value,
            25 => self.v25 = value,
            26 => self.v26 = value,
            27 => self.v27 = value,
            28 => self.v28 = value,
            29 => self.v29 = value,
            30 => self.v30 = value,
            31 => self.v31 = value,
            _ => return false,
        }
        true
    }
}
