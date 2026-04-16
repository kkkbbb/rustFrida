//! JSValue wrapper

use crate::ffi;
use std::ffi::{CStr, CString};

/// Wrapper around QuickJS JSValue
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct JSValue(pub ffi::JSValue);

impl JSValue {
    /// Create undefined value
    pub fn undefined() -> Self {
        JSValue(unsafe { ffi::qjs_undefined() })
    }

    /// Create null value
    pub fn null() -> Self {
        JSValue(unsafe { ffi::qjs_null() })
    }

    /// Create boolean value
    pub fn bool(val: bool) -> Self {
        JSValue(unsafe { ffi::qjs_mkval(ffi::JS_TAG_BOOL as i32, val as i32) })
    }

    /// Create integer value
    pub fn int(val: i32) -> Self {
        JSValue(unsafe { ffi::qjs_mkval(ffi::JS_TAG_INT as i32, val) })
    }

    /// Create float value
    pub fn float(val: f64) -> Self {
        JSValue(ffi::JSValue {
            u: ffi::JSValueUnion { float64: val },
            tag: ffi::JS_TAG_FLOAT64 as i64,
        })
    }

    /// Create a string value
    /// 直接传 Rust &str 的原始字节，JS_NewStringLen 不要求 null termination，
    /// 因此内嵌 \0 字节也能正确处理。
    pub fn string(ctx: *mut ffi::JSContext, s: &str) -> Self {
        let val = unsafe { ffi::JS_NewStringLen(ctx, s.as_ptr() as *const std::ffi::c_char, s.len()) };
        JSValue(val)
    }

    /// Check if this is an exception
    pub fn is_exception(&self) -> bool {
        unsafe { ffi::qjs_is_exception(self.0) != 0 }
    }

    /// Check if this is undefined
    pub fn is_undefined(&self) -> bool {
        unsafe { ffi::qjs_is_undefined(self.0) != 0 }
    }

    /// Check if this is null
    pub fn is_null(&self) -> bool {
        unsafe { ffi::qjs_is_null(self.0) != 0 }
    }

    /// Check if this is a boolean
    pub fn is_bool(&self) -> bool {
        unsafe { ffi::qjs_is_bool(self.0) != 0 }
    }

    /// Check if this is an integer
    pub fn is_int(&self) -> bool {
        unsafe { ffi::qjs_value_get_tag(self.0) == ffi::JS_TAG_INT as i32 }
    }

    /// Check if this is a float
    pub fn is_float(&self) -> bool {
        unsafe { ffi::qjs_value_get_tag(self.0) == ffi::JS_TAG_FLOAT64 as i32 }
    }

    /// Check if this is a string
    pub fn is_string(&self) -> bool {
        unsafe { ffi::qjs_is_string(self.0) != 0 }
    }

    /// Check if this is an object
    pub fn is_object(&self) -> bool {
        unsafe { ffi::qjs_is_object(self.0) != 0 }
    }

    /// Check if this is a function
    pub fn is_function(&self, ctx: *mut ffi::JSContext) -> bool {
        unsafe { ffi::JS_IsFunction(ctx, self.0) != 0 }
    }

    /// Get as boolean
    pub fn to_bool(&self) -> Option<bool> {
        if self.is_bool() {
            Some(unsafe { ffi::qjs_value_get_bool(self.0) != 0 })
        } else {
            None
        }
    }

    /// Get as integer
    pub fn to_int(&self) -> Option<i32> {
        if self.is_int() {
            Some(unsafe { ffi::qjs_value_get_int(self.0) })
        } else {
            None
        }
    }

    /// Get as float
    pub fn to_float(&self) -> Option<f64> {
        if self.is_float() {
            Some(unsafe { ffi::qjs_value_get_float64(self.0) })
        } else if self.is_int() {
            Some(unsafe { ffi::qjs_value_get_int(self.0) as f64 })
        } else {
            None
        }
    }

    /// Get as string (returns owned String)
    pub fn to_string(&self, ctx: *mut ffi::JSContext) -> Option<String> {
        unsafe {
            let cstr = ffi::qjs_to_cstring(ctx, self.0);
            if cstr.is_null() {
                return None;
            }
            let result = CStr::from_ptr(cstr).to_string_lossy().into_owned();
            ffi::qjs_free_cstring(ctx, cstr);
            Some(result)
        }
    }

    /// Convert to i64 (handles int, float, AND BigInt via JS_ToInt64Ext)
    pub fn to_i64(&self, ctx: *mut ffi::JSContext) -> Option<i64> {
        let mut val: i64 = 0;
        let ret = unsafe { ffi::qjs_to_int64_ext(ctx, &mut val, self.0) };
        if ret == 0 {
            Some(val)
        } else {
            None
        }
    }

    /// Convert to u64
    pub fn to_u64(&self, ctx: *mut ffi::JSContext) -> Option<u64> {
        self.to_i64(ctx).map(|v| v as u64)
    }

    /// Get raw value
    pub fn raw(&self) -> ffi::JSValue {
        self.0
    }

    /// Free the value (must be called for values that own memory)
    pub fn free(self, ctx: *mut ffi::JSContext) {
        unsafe {
            ffi::qjs_free_value(ctx, self.0);
        }
    }

    /// Duplicate the value (increment reference count)
    pub fn dup(&self, ctx: *mut ffi::JSContext) -> Self {
        JSValue(unsafe { ffi::qjs_dup_value(ctx, self.0) })
    }

    /// Get a property by name
    pub fn get_property(&self, ctx: *mut ffi::JSContext, name: &str) -> Self {
        let cname = CString::new(name).unwrap();
        let atom = unsafe { ffi::JS_NewAtom(ctx, cname.as_ptr()) };
        let val = unsafe { ffi::qjs_get_property(ctx, self.0, atom) };
        unsafe { ffi::JS_FreeAtom(ctx, atom) };
        JSValue(val)
    }

    /// Set a property by name
    pub fn set_property(&self, ctx: *mut ffi::JSContext, name: &str, value: JSValue) -> bool {
        let cname = CString::new(name).unwrap();
        let atom = unsafe { ffi::JS_NewAtom(ctx, cname.as_ptr()) };
        let ret = unsafe { ffi::qjs_set_property(ctx, self.0, atom, value.0) };
        unsafe { ffi::JS_FreeAtom(ctx, atom) };
        ret >= 0
    }
}

impl Default for JSValue {
    fn default() -> Self {
        Self::undefined()
    }
}
