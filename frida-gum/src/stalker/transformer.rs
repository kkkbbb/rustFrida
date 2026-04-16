/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_gum_sys::Insn;
use {
    crate::{instruction_writer::TargetInstructionWriter, CpuContext, Gum},
    core::{ffi::c_void, marker::PhantomData},
};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[derive(Clone, Copy)]
pub struct StalkerIterator<'a> {
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerIterator>,
}

extern "C" fn put_callout_callback(cpu_context: *mut frida_gum_sys::GumCpuContext, user_data: *mut c_void) {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(CpuContext)>) };
    f(CpuContext::from_raw(cpu_context));
    // Leak the box again, we want to destruct it in the data_destroy callback.
    //
    Box::leak(f);
}

unsafe extern "C" fn put_callout_destroy(user_data: *mut c_void) {
    let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(CpuContext)>);
}

impl<'a> StalkerIterator<'a> {
    fn from_raw(iterator: *mut frida_gum_sys::GumStalkerIterator) -> StalkerIterator<'a> {
        StalkerIterator {
            iterator,
            phantom: PhantomData,
        }
    }

    pub fn keep_instr(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_keep(self.iterator) };
    }

    pub fn put_callout(&self, callout: impl FnMut(CpuContext)) {
        unsafe {
            let user_data =
                Box::leak(Box::new(Box::new(callout) as Box<dyn FnMut(CpuContext)>)) as *mut _ as *mut c_void;

            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.iterator,
                Some(put_callout_callback),
                user_data,
                Some(put_callout_destroy),
            )
        };
    }

    pub fn put_chaining_return(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_put_chaining_return(self.iterator) };
    }
}

use frida_gum_sys::cs_insn;

pub struct Instruction<'a> {
    parent: *mut frida_gum_sys::GumStalkerIterator,
    instr: Insn,
    phantom: PhantomData<&'a *const cs_insn>,
}

impl<'a> Instruction<'a> {
    fn from_raw(parent: *mut frida_gum_sys::GumStalkerIterator, instr: *const cs_insn) -> Instruction<'a> {
        Instruction {
            parent,
            instr: unsafe { Insn::from_raw(instr) },
            phantom: PhantomData,
        }
    }

    pub fn keep(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_keep(self.parent) };
    }

    pub fn put_callout(&self, callout: impl FnMut(CpuContext)) {
        unsafe {
            let user_data =
                Box::leak(Box::new(Box::new(callout) as Box<dyn FnMut(CpuContext)>)) as *mut _ as *mut c_void;

            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.parent,
                Some(put_callout_callback),
                user_data,
                Some(put_callout_destroy),
            )
        };
    }

    pub fn put_chaining_return(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_put_chaining_return(self.parent) };
    }

    pub fn instr(&self) -> &Insn {
        &self.instr
    }
}

impl<'a> Iterator for StalkerIterator<'a> {
    type Item = Instruction<'a>;

    fn next(&mut self) -> Option<Instruction<'a>> {
        let mut instr: *const cs_insn = core::ptr::null();
        if unsafe { frida_gum_sys::gum_stalker_iterator_next(self.iterator, &mut instr as *mut _) } != 0 {
            Some(Instruction::from_raw(self.iterator, instr))
        } else {
            None
        }
    }
}

pub struct StalkerOutput<'a> {
    pub output: *mut frida_gum_sys::GumStalkerOutput,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerOutput>,
}

impl<'a> StalkerOutput<'a> {
    fn from_raw(output: *mut frida_gum_sys::GumStalkerOutput) -> StalkerOutput<'a> {
        StalkerOutput {
            output,
            phantom: PhantomData,
        }
    }

    /// Obtain an [`crate::instruction_writer::InstructionWriter`] for inserting into the stream.
    pub fn writer(&self) -> TargetInstructionWriter {
        unsafe {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let writer = TargetInstructionWriter::from_raw((*self.output).writer.x86);
            #[cfg(target_arch = "aarch64")]
            let writer = TargetInstructionWriter::from_raw((*self.output).writer.arm64);
            #[cfg(target_arch = "arm")]
            let writer = TargetInstructionWriter::from_raw((*self.output).writer.arm);

            writer
        }
    }
}

extern "C" fn transformer_callback(
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    output: *mut frida_gum_sys::GumStalkerOutput,
    user_data: *mut c_void,
) {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(StalkerIterator, StalkerOutput)>) };
    f(StalkerIterator::from_raw(iterator), StalkerOutput::from_raw(output));
    // Leak the box again, we want to destruct it in the data_destroy callback.
    //
    Box::leak(f);
}

unsafe extern "C" fn transformer_destroy(user_data: *mut c_void) {
    let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(StalkerIterator, StalkerOutput)>);
}

pub struct Transformer<'a> {
    pub(crate) transformer: *mut frida_gum_sys::GumStalkerTransformer,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerTransformer>,
}

impl<'a> Transformer<'a> {
    pub fn from_callback<'b>(
        _gum: &'b Gum,
        callback: impl FnMut(StalkerIterator, StalkerOutput) + 'a,
    ) -> Transformer<'a>
    where
        'b: 'a,
    {
        let user_data = Box::leak(Box::new(
            Box::new(callback) as Box<dyn FnMut(StalkerIterator, StalkerOutput)>
        )) as *mut _ as *mut c_void;

        Transformer {
            transformer: unsafe {
                frida_gum_sys::gum_stalker_transformer_make_from_callback(
                    Some(transformer_callback),
                    user_data,
                    Some(transformer_destroy),
                )
            },
            phantom: PhantomData,
        }
    }
}

impl Drop for Transformer<'_> {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.transformer as *mut c_void) }
    }
}
