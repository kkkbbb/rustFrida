use jni::sys::JNIEnv;
// use sys::JavaVM;
use jni::JavaVM;
use libc::{c_char, dlopen, dlsym, malloc, memset, size_t, RTLD_NOW};
use std::alloc::{alloc, Layout};
use std::ffi::{c_void, CStr, CString};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::{mem, ptr};
use std::collections::HashMap;
use std::hash::Hash;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use jni::sys;
use crate::{GLOBAL_STREAM};

/// 宏：解析动态库中的函数并转换为可调用函数指针
/// 参数:
///   - $lib_handle: 动态库句柄
///   - $func_name: 函数名（字符串字面量）
///   - $ret_type: 返回类型
///   - $($arg_type:ty),*: 参数类型列表
/// 返回: 指定类型的函数指针，若解析失败则返回None
#[macro_export]
macro_rules! resolve_sym {
    ($lib_handle:expr, $func_name:expr, $ret_type:ty, $($arg_type:ty),*) => {{
        let sym_name = CString::new($func_name).unwrap();
        let func_ptr = unsafe { dlsym($lib_handle, sym_name.as_ptr()) };
        if func_ptr.is_null() {
            None
        } else {
            let func: unsafe extern "C" fn($($arg_type),*) -> $ret_type = 
                unsafe { std::mem::transmute(func_ptr) };
            Some(func)
        }
    }};
    
    // 无参数版本
    ($lib_handle:expr, $func_name:expr, $ret_type:ty) => {{
        let sym_name = CString::new($func_name).unwrap();
        let func_ptr = unsafe { dlsym($lib_handle, sym_name.as_ptr()) };
        if func_ptr.is_null() {
            None
        } else {
            let func: unsafe extern "C" fn() -> $ret_type = 
                unsafe { std::mem::transmute(func_ptr) };
            Some(func)
        }
    }};
}

/// 优化后的 ArtClassVisitor，使用更安全的写法并添加注释
// fn ArtClassVisitor<F>(callback: F) -> *const usize
// where
//     F: FnMut() -> (),
// {
//     use std::mem::size_of;
//     use std::ptr;
//
//     unsafe {
//         let buf = malloc(4 * size_of::<usize>()) as *mut usize;
//         if buf.is_null() {
//             return ptr::null_mut();
//         }
//         // 内存清零
//         memset(buf as *mut c_void, 0, 4 * size_of::<usize>());
//
//         // 设置第一个元素为 buf + 1 的地址
//         *buf = buf.add(1) as usize;
//
//         // 设置最后一个元素为 callback 的函数指针
//         *buf.add(3) = callback as usize;
//
//         buf
//     }
// }

static pointer_size:usize = size_of::<usize>();
static std_str_size: usize = 3*pointer_size;
static cachedArtClassLinkerSpec: OnceLock<HashMap<&str,usize>> = OnceLock::new();
static apilevel:OnceLock<i32> = OnceLock::new();
static codename:OnceLock<String> = OnceLock::new();

pub fn jhook() -> Result<String,String> {
    let mut stream = GLOBAL_STREAM.get().unwrap();
    let lib_art = unsafe { dlopen(CString::new("libart.so").unwrap().as_ptr(), RTLD_NOW) };
    if lib_art.is_null() {
        stream.write_all(format!("dlopen failed").as_bytes()).unwrap();
        return Err(String::from("dlopen failed"));
    }
    let lib_c = unsafe { dlopen(CString::new("libc.so").unwrap().as_ptr(), RTLD_NOW) };
    if lib_c.is_null() {
        stream.write_all(format!("dlopen failed").as_bytes()).unwrap();
        return Err(String::from("dlopen failed"));
    }

    let system_property_get = resolve_sym!(lib_c, "__system_property_get",i32,*const c_char ,*mut c_char).take().unwrap();
    let jni_get_created_java_vms = resolve_sym!(lib_art, "JNI_GetCreatedJavaVMs", i32,*mut sys::JavaVM, i32,*mut i32).take().unwrap();
    let VisitClasses = resolve_sym!(lib_art, "_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE", c_void,*mut c_void, *mut usize).take().unwrap();

    unsafe {
        let mut buf = vec![0u8; 92];
        let mut buf_ptr = buf.as_mut_ptr() as *mut c_char;
        system_property_get(CString::new("ro.build.version.sdk").unwrap().as_ptr(),buf_ptr);
        let lapilevel = *apilevel.get_or_init(|| {
            unsafe { CString::from_raw(buf_ptr).to_str().unwrap().to_owned().parse().unwrap() }
        });
        buf.fill(0);
        system_property_get(CString::new("ro.build.version.codename").unwrap().as_ptr(),buf_ptr);
        let lcodename = codename.get_or_init(|| {
            unsafe { CString::from_raw(buf_ptr).to_str().unwrap().to_owned().parse().unwrap() }
        });
    
    
        let mut jvm_ptr:sys::JavaVM = ptr::null_mut();
        let mut vm_count = 0;
        jni_get_created_java_vms(&mut jvm_ptr, 1, &mut vm_count);
    
    
        // let java_vm = JavaVM::from_raw(&mut jvm_ptr);
        let runtime_ptr =  (*jvm_ptr).reserved0 as *mut usize;
        let startOffset =if size_of::<usize>() == 4 { 200 } else { 384 };
        let endOffset = startOffset + (100 * size_of::<usize>());

        let mut spec:*const HashMap<&str,usize> = null_mut();
        for offset in (startOffset..=endOffset).step_by(size_of::<usize>()) {
            let value = runtime_ptr.offset(offset as isize);
            if value == jvm_ptr as *mut usize {
                let mut classlinker_offsets = Vec::new();
                if lapilevel >= 33 || lcodename == "Tiramisu" {
                    classlinker_offsets.push(offset - 4*pointer_size);
                } else if lapilevel >= 30 || lcodename == "R" {
                    classlinker_offsets.push(offset - 3*pointer_size);
                    classlinker_offsets.push(offset - 4*pointer_size);
                } else if lapilevel >= 29 {
                    classlinker_offsets.push(offset - 2*pointer_size);
                } else if lapilevel >= 27 {
                    classlinker_offsets.push(offset - std_str_size - 3*pointer_size);
                } else { 
                    classlinker_offsets.push(offset - std_str_size - 2*pointer_size);
                }
                
                for classlinker_offset in classlinker_offsets.iter() {
                    let intern_table_offset = classlinker_offset - pointer_size;
                    
                    let mut candidate = HashMap::new();
                    candidate.insert("classLinker",classlinker_offset.clone());
                    candidate.insert("internTable",intern_table_offset.clone());
                    
                    match tryGetArtClassLinkerSpec(runtime_ptr,&candidate) {
                        Ok(_) => {
                            spec = &candidate;
                            break;
                        }
                        Err(_) => {}
                    }
                }
                break;
            }
        }

        if spec == null(){
            stream.write_all(format!("find offset failed").as_bytes()).unwrap();
            return Err(String::from("find offset failed"));
        }
    }
    
    // let jni_env :JNIEnv;
    // match java_vm.attach_current_thread() {
    //     Ok(mut env) => {
    //         jni_env = env.find_class()
    //     },
    //     Err(e) => {
    //         stream.write(format!("attach current thread failed: {}", e).as_bytes()).unwrap();
    //         return;
    //     }
    // }
    Ok(String::from("ok"))
}

fn tryGetArtClassLinkerSpec(runtime: *mut usize, candidate: *const HashMap<&str, usize>) -> Result<String, String> {
    unsafe {
        let tmp = &*candidate;
        let class_linker = runtime.offset(*tmp.get("classLinker").unwrap() as isize);
        let intern_table = runtime.offset(*(tmp.get("internTable").unwrap()) as isize);

        let start_offset = if pointer_size == 4  { 100 } else { 200 };
        let end_offset = start_offset + (100 * pointer_size);
        let lapilevel = *(apilevel.get().unwrap()) as isize;
        let lcodename = codename.get().unwrap();

        let mut spec = HashMap::new();
        for offset in (start_offset..=end_offset).step_by(pointer_size) {
            let value = *(class_linker.offset(offset as isize));
            if value == intern_table as usize {
                let delta ;
                if lapilevel >= 30 || lcodename == "R" {
                    delta = 6;
                }else if lapilevel >= 29 {
                    delta = 4;
                }else if lapilevel >= 23 {
                    delta = 3;
                } else {
                    delta = 5;
                }

                let quickGenericJniTrampolineOffset = offset + delta*pointer_size;

                let quickResolutionTrampolineOffset;
                if lapilevel >= 23 {
                    quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - (2 * pointer_size);
                }else {
                    quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - 3 * pointer_size;
                }

                spec.insert("quickResolutionTrampoline",quickResolutionTrampolineOffset);
                spec.insert("quickImtConflictTrampoline",quickGenericJniTrampolineOffset - pointer_size);
                spec.insert("quickGenericJniTrampoline",quickGenericJniTrampolineOffset);
                spec.insert("quickToInterpreterBridgeTrampoline", quickGenericJniTrampolineOffset + pointer_size);

                break;
            }
        }

        if spec.len() > 0 {
            Ok(String::from("OK"))
        }else {
            Err(String::from("failed to get artClassLinker"))
        }

    }
    
}
