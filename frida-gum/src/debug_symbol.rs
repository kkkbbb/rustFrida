use {
    crate::NativePointer,
    core::{fmt, mem::MaybeUninit, str::Utf8Error},
    cstr_core::{CStr, CString},
    frida_gum_sys as gum_sys,
    gum_sys::{gum_find_function, gum_symbol_details_from_address, GumDebugSymbolDetails},
};

pub struct Symbol {
    gum_debug_symbol_details: GumDebugSymbolDetails,
}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Symbol")
            .field("address", &self.address())
            .field("module_name", &self.module_name())
            .field("symbol_name", &self.symbol_name())
            .field("file_name", &self.file_name())
            .field("line_number", &self.line_number())
            .finish()
    }
}

impl Symbol {
    /// Address that this symbol is for.
    pub fn address(&self) -> usize {
        self.gum_debug_symbol_details.address.try_into().unwrap()
    }

    /// Name of the symbol
    pub fn module_name(&self) -> Result<&str, Utf8Error> {
        unsafe { CStr::from_ptr(self.gum_debug_symbol_details.module_name.as_ptr().cast()) }.to_str()
    }

    /// Module name owning this symbol
    pub fn symbol_name(&self) -> Result<&str, Utf8Error> {
        unsafe { CStr::from_ptr(self.gum_debug_symbol_details.symbol_name.as_ptr().cast()) }.to_str()
    }

    /// File name owning this symbol
    pub fn file_name(&self) -> Result<&str, Utf8Error> {
        unsafe { CStr::from_ptr(self.gum_debug_symbol_details.file_name.as_ptr().cast()) }.to_str()
    }

    /// Line number in file_name
    pub fn line_number(&self) -> u32 {
        self.gum_debug_symbol_details.line_number
    }
}

pub struct DebugSymbol {}

impl DebugSymbol {
    /// Get debug symbol details for address
    pub fn from_address<N: AsRef<NativePointer>>(address: N) -> Option<Symbol> {
        let mut gum_symbol_details: GumDebugSymbolDetails = unsafe { MaybeUninit::zeroed().assume_init() };
        match unsafe { gum_symbol_details_from_address(address.as_ref().into(), &mut gum_symbol_details as *mut _) } {
            1 => Some(Symbol {
                gum_debug_symbol_details: gum_symbol_details,
            }),
            0 => None,
            _ => unreachable!(),
        }
    }

    pub fn find_function<S: AsRef<str>>(name: S) -> Option<NativePointer> {
        match CString::new(name.as_ref()) {
            Ok(name) => {
                let address = unsafe { gum_find_function(name.into_raw().cast()) };
                if address.is_null() {
                    None
                } else {
                    Some(NativePointer(address))
                }
            }
            _ => None,
        }
    }

    pub fn from_name<S: AsRef<str>>(name: S) -> Option<Symbol> {
        match Self::find_function(name) {
            Some(address) => Self::from_address(address),
            None => None,
        }
    }
}
