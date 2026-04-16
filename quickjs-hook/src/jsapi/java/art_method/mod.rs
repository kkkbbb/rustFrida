//! ArtMethod resolution, entry_point access, ART bridge function discovery, field cache
//!
//! Split into focused fragments:
//! - shared layout helpers
//! - bridge/trampoline discovery
//! - method and field resolution/cache
//! - instrumentation and runtime probing

use crate::jsapi::console::output_verbose;
use crate::jsapi::module::{dlsym_first_match, is_in_libart, libart_dlsym};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

use super::jni_core::*;
use super::reflect::*;
use super::safe_mem::{refresh_mem_regions, safe_read_u64};
use super::PAC_STRIP_MASK;

include!("shared.rs");
include!("bridge.rs");
include!("resolution.rs");
include!("fields.rs");
include!("instrumentation.rs");
include!("runtime.rs");
