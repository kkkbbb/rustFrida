//! Module API — Frida-style linker integration + JS Module namespace
//!
//! Split into focused fragments:
//! - ELF/linker type definitions
//! - `/proc/self/maps` parsing
//! - ELF symbol lookup and unrestricted linker init
//! - symbol resolution helpers and JS Module API

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::console::output_message;
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::{add_cfunction_to_object, is_addr_accessible};
use crate::value::JSValue;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;

include!("types.rs");
include!("maps.rs");
include!("elf.rs");
include!("enumerate.rs");
include!("linker.rs");
include!("resolve.rs");
include!("api.rs");
