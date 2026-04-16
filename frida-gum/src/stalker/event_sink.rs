/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#![cfg_attr(any(target_arch = "x86_64", target_arch = "x86"), allow(clippy::unnecessary_cast))]

use {crate::NativePointer, core::ffi::c_void, frida_gum_sys as gum_sys, gum_sys::_GumEvent as GumEvent};

#[derive(FromPrimitive)]
#[repr(u32)]
#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
pub enum EventMask {
    None = gum_sys::_GumEventType_GUM_NOTHING as u32,
    Call = gum_sys::_GumEventType_GUM_CALL as u32,
    Ret = gum_sys::_GumEventType_GUM_RET as u32,
    Exec = gum_sys::_GumEventType_GUM_EXEC as u32,
    Block = gum_sys::_GumEventType_GUM_BLOCK as u32,
    Compile = gum_sys::_GumEventType_GUM_COMPILE as u32,
}

#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Event {
    Call {
        location: NativePointer,
        target: NativePointer,
        depth: i32,
    },
    Ret {
        location: NativePointer,
        target: NativePointer,
        depth: i32,
    },
    Exec {
        location: NativePointer,
    },
    Block {
        start: NativePointer,
        end: NativePointer,
    },
    Compile {
        start: NativePointer,
        end: NativePointer,
    },
}

#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
impl From<GumEvent> for Event {
    fn from(event: GumEvent) -> Event {
        match num::FromPrimitive::from_u32(unsafe { event.type_ }).unwrap() {
            EventMask::None => unreachable!(),
            EventMask::Call => {
                let call = unsafe { event.call };
                Event::Call {
                    location: NativePointer(call.location),
                    target: NativePointer(call.target),
                    depth: call.depth,
                }
            }
            EventMask::Ret => {
                let ret = unsafe { event.ret };
                Event::Ret {
                    location: NativePointer(ret.location),
                    target: NativePointer(ret.target),
                    depth: ret.depth,
                }
            }
            EventMask::Exec => {
                let exec = unsafe { event.exec };
                Event::Exec {
                    location: NativePointer(exec.location),
                }
            }
            EventMask::Block => {
                let block = unsafe { event.block };
                Event::Block {
                    start: NativePointer(block.start),
                    end: NativePointer(block.end),
                }
            }
            EventMask::Compile => {
                let compile = unsafe { event.compile };
                Event::Compile {
                    start: NativePointer(compile.start),
                    end: NativePointer(compile.end),
                }
            }
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "event-sink")))]
pub trait EventSink {
    fn query_mask(&mut self) -> EventMask;
    fn start(&mut self);
    fn process(&mut self, event: &Event);
    fn flush(&mut self);
    fn stop(&mut self);
}

unsafe extern "C" fn call_start<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.start();
}

unsafe extern "C" fn call_process<S: EventSink>(user_data: *mut c_void, event: *const frida_gum_sys::GumEvent) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.process(&(*event).into());
}

unsafe extern "C" fn call_flush<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.flush();
}

unsafe extern "C" fn call_stop<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.stop();
}

unsafe extern "C" fn call_query_mask<S: EventSink>(user_data: *mut c_void) -> frida_gum_sys::GumEventType {
    let event_sink: &mut S = &mut *(user_data as *mut S);
    event_sink.query_mask() as u32
}

pub(crate) fn event_sink_transform<S: EventSink>(event_sink: &mut S) -> *mut frida_gum_sys::GumEventSink {
    let rust = frida_gum_sys::RustEventSinkVTable {
        user_data: event_sink as *mut _ as *mut c_void,
        query_mask: Some(call_query_mask::<S>),
        start: Some(call_start::<S>),
        process: Some(call_process::<S>),
        flush: Some(call_flush::<S>),
        stop: Some(call_stop::<S>),
    };

    unsafe { frida_gum_sys::gum_rust_event_sink_new(rust) }
}
