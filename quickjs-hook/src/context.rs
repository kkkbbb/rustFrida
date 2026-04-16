//! JSContext wrapper

use crate::ffi;
use crate::runtime::JSRuntime;
use crate::value::JSValue;
use std::ffi::CString;
use std::ptr::NonNull;

/// Wrapper around QuickJS JSContext
pub struct JSContext {
    ptr: NonNull<ffi::JSContext>,
    runtime: *mut ffi::JSRuntime,
}

impl JSContext {
    /// Create a new JSContext in the given runtime
    pub fn new(runtime: &JSRuntime) -> Option<Self> {
        // JS_NewContext already adds all standard intrinsics (BaseObjects, Date, Eval,
        // StringNormalize, RegExp, JSON, Proxy, MapSet, TypedArrays, Promise, BigInt)
        let ptr = unsafe { ffi::JS_NewContext(runtime.as_ptr()) };
        NonNull::new(ptr).map(|ptr| JSContext {
            ptr,
            runtime: runtime.as_ptr(),
        })
    }

    /// Get the raw pointer
    pub fn as_ptr(&self) -> *mut ffi::JSContext {
        self.ptr.as_ptr()
    }

    /// Get the global object
    pub fn global_object(&self) -> JSValue {
        JSValue(unsafe { ffi::JS_GetGlobalObject(self.ptr.as_ptr()) })
    }

    /// Evaluate a script
    pub fn eval(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        let cscript = CString::new(script).map_err(|e| format!("Invalid script: {}", e))?;
        let cfilename = CString::new(filename).map_err(|e| format!("Invalid filename: {}", e))?;

        // Update stack top for cross-thread usage (prevents false stack overflow detection)
        unsafe { ffi::qjs_update_stack_top(self.ptr.as_ptr()) };

        let val = unsafe {
            ffi::JS_Eval(
                self.ptr.as_ptr(),
                cscript.as_ptr(),
                script.len(),
                cfilename.as_ptr(),
                ffi::JS_EVAL_TYPE_GLOBAL as i32,
            )
        };

        let result = JSValue(val);
        if result.is_exception() {
            let exception = self.get_exception();
            return Err(exception);
        }

        Ok(result)
    }

    /// Evaluate a script as a module
    pub fn eval_module(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        let cscript = CString::new(script).map_err(|e| format!("Invalid script: {}", e))?;
        let cfilename = CString::new(filename).map_err(|e| format!("Invalid filename: {}", e))?;

        // 更新栈顶指针，防止跨线程调用时误报栈溢出
        unsafe { ffi::qjs_update_stack_top(self.ptr.as_ptr()) };

        let val = unsafe {
            ffi::JS_Eval(
                self.ptr.as_ptr(),
                cscript.as_ptr(),
                script.len(),
                cfilename.as_ptr(),
                ffi::JS_EVAL_TYPE_MODULE as i32,
            )
        };

        let result = JSValue(val);
        if result.is_exception() {
            let exception = self.get_exception();
            return Err(exception);
        }

        Ok(result)
    }

    /// Get the current exception as a string
    pub fn get_exception(&self) -> String {
        unsafe {
            let exception = ffi::JS_GetException(self.ptr.as_ptr());
            let exc_val = JSValue(exception);

            // Get the error message
            let message = exc_val
                .to_string(self.ptr.as_ptr())
                .unwrap_or_else(|| "Unknown error".to_string());

            // Try to get stack trace
            let stack = exc_val.get_property(self.ptr.as_ptr(), "stack");
            let stack_str = if !stack.is_undefined() {
                stack.to_string(self.ptr.as_ptr()).unwrap_or_default()
            } else {
                String::new()
            };

            // Free values
            exc_val.free(self.ptr.as_ptr());
            stack.free(self.ptr.as_ptr());

            if stack_str.is_empty() {
                message
            } else {
                format!("{}\n{}", message, stack_str)
            }
        }
    }

    /// Create a new object
    pub fn new_object(&self) -> JSValue {
        JSValue(unsafe { ffi::JS_NewObject(self.ptr.as_ptr()) })
    }

    /// Create a new array
    pub fn new_array(&self) -> JSValue {
        JSValue(unsafe { ffi::JS_NewArray(self.ptr.as_ptr()) })
    }

    /// Create a string value
    pub fn new_string(&self, s: &str) -> JSValue {
        JSValue::string(self.ptr.as_ptr(), s)
    }

    /// Create an integer value
    pub fn new_int(&self, val: i32) -> JSValue {
        JSValue::int(val)
    }

    /// Create a float value
    pub fn new_float(&self, val: f64) -> JSValue {
        JSValue::float(val)
    }

    /// Create a BigInt from i64
    pub fn new_bigint(&self, val: i64) -> JSValue {
        JSValue(unsafe { ffi::JS_NewBigInt64(self.ptr.as_ptr(), val) })
    }

    /// Create a BigInt from u64
    pub fn new_biguint(&self, val: u64) -> JSValue {
        JSValue(unsafe { ffi::JS_NewBigUint64(self.ptr.as_ptr(), val) })
    }

    /// Register a C function on the global object
    pub fn register_function(&self, name: &str, func: ffi::JSCFunction, argc: i32) -> bool {
        let global = self.global_object();
        let cname = CString::new(name).unwrap();

        let func_val = unsafe { ffi::qjs_new_cfunction(self.ptr.as_ptr(), func, cname.as_ptr(), argc) };

        let result = global.set_property(self.ptr.as_ptr(), name, JSValue(func_val));
        global.free(self.ptr.as_ptr());
        result
    }

    /// Set a property on the global object
    pub fn set_global_property(&self, name: &str, value: JSValue) -> bool {
        let global = self.global_object();
        let result = global.set_property(self.ptr.as_ptr(), name, value);
        global.free(self.ptr.as_ptr());
        result
    }

    /// Get a property from the global object
    pub fn get_global_property(&self, name: &str) -> JSValue {
        let global = self.global_object();
        let prop = global.get_property(self.ptr.as_ptr(), name);
        global.free(self.ptr.as_ptr());
        prop
    }

    /// Call a function
    pub fn call_function(&self, func: JSValue, this: JSValue, args: &[JSValue]) -> Result<JSValue, String> {
        let argc = args.len() as i32;
        let argv: Vec<ffi::JSValue> = args.iter().map(|v| v.raw()).collect();

        let result = unsafe {
            ffi::JS_Call(
                self.ptr.as_ptr(),
                func.raw(),
                this.raw(),
                argc,
                if argv.is_empty() {
                    std::ptr::null_mut()
                } else {
                    argv.as_ptr() as *mut _
                },
            )
        };

        let val = JSValue(result);
        if val.is_exception() {
            return Err(self.get_exception());
        }
        Ok(val)
    }

    /// Execute pending jobs (for promises, etc.)
    pub fn execute_pending_job(&self) -> bool {
        let mut pctx: *mut ffi::JSContext = std::ptr::null_mut();
        let ret = unsafe { ffi::JS_ExecutePendingJob(self.runtime, &mut pctx) };
        ret > 0
    }

    /// Check if there are pending jobs
    pub fn is_job_pending(&self) -> bool {
        unsafe { ffi::JS_IsJobPending(self.runtime) != 0 }
    }
}

impl Drop for JSContext {
    fn drop(&mut self) {
        unsafe {
            ffi::JS_FreeContext(self.ptr.as_ptr());
        }
    }
}

// Safety: JSContext is protected by Mutex in the global JS_ENGINE, ensuring single-threaded access
unsafe impl Send for JSContext {}
unsafe impl Sync for JSContext {}
