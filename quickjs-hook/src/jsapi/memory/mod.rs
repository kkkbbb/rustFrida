//! Memory API implementation

mod alloc;
mod helpers;
mod read;
mod write;
mod writest;

use crate::context::JSContext;
use crate::jsapi::util::add_cfunction_to_object;

pub(crate) use alloc::cleanup_owned_allocs;
pub use write::cleanup_wxshadow_patches;
pub(crate) use write::untrack_wxshadow_addr;
use alloc::{memory_alloc, memory_alloc_utf8_string, memory_flush_code_cache, memory_protect};
use read::*;
use write::*;
use writest::memory_writest;

/// 把 Memory 读写方法注册到 NativePointer prototype，实现 Frida 兼容的
/// `ptr.readXxx()` / `ptr.writeXxx(val)` 调用风格。
pub fn register_ptr_methods(ctx_ptr: *mut crate::ffi::JSContext, proto: crate::ffi::JSValue) {
    unsafe {
        add_cfunction_to_object(ctx_ptr, proto, "readU8", memory_read_u8, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readU16", memory_read_u16, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readU32", memory_read_u32, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readU64", memory_read_u64, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readPointer", memory_read_pointer, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readCString", memory_read_cstring, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readUtf8String", memory_read_utf8_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "readByteArray", memory_read_byte_array, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU8", memory_write_u8, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU16", memory_write_u16, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU32", memory_write_u32, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeU64", memory_write_u64, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writePointer", memory_write_pointer, 1);
        add_cfunction_to_object(ctx_ptr, proto, "writeBytes", memory_write_bytes, 2);
        add_cfunction_to_object(ctx_ptr, proto, "writest", memory_writest, 1);
    }
}

/// Register Memory API
pub fn register_memory_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let memory = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let obj = memory.raw();
        add_cfunction_to_object(ctx_ptr, obj, "alloc", memory_alloc, 1);
        add_cfunction_to_object(ctx_ptr, obj, "allocUtf8String", memory_alloc_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "flushCodeCache", memory_flush_code_cache, 2);
        add_cfunction_to_object(ctx_ptr, obj, "readU8", memory_read_u8, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU16", memory_read_u16, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU32", memory_read_u32, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU64", memory_read_u64, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readPointer", memory_read_pointer, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readCString", memory_read_cstring, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readUtf8String", memory_read_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readByteArray", memory_read_byte_array, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU8", memory_write_u8, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU16", memory_write_u16, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU32", memory_write_u32, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU64", memory_write_u64, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writePointer", memory_write_pointer, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeBytes", memory_write_bytes, 3);
        add_cfunction_to_object(ctx_ptr, obj, "writest", memory_writest, 2);
        add_cfunction_to_object(ctx_ptr, obj, "protect", memory_protect, 3);
    }

    // Set Memory on global object
    global.set_property(ctx.as_ptr(), "Memory", memory);
    global.free(ctx.as_ptr());
}
