use std::collections::BTreeSet;

use super::super::jni_core::JniEnv;
use super::super::reflect::{enumerate_methods, enumerate_methods_declared_only};

pub(super) const ACC_PUBLIC: u32 = 0x0001;
pub(super) const ACC_PRIVATE: u32 = 0x0002;
pub(super) const ACC_PROTECTED: u32 = 0x0004;
pub(super) const ACC_STATIC: u32 = 0x0008;
pub(super) const ACC_FINAL: u32 = 0x0010;
pub(super) const ACC_BRIDGE: u32 = 0x0040;
pub(super) const ACC_VOLATILE: u32 = 0x0040;
pub(super) const ACC_NATIVE: u32 = 0x0100;
pub(super) const ACC_SYNTHETIC: u32 = 0x1000;
pub(super) const ACC_CONSTRUCTOR: u32 = 0x0001_0000;
pub(super) const ACC_DECLARED_SYNCHRONIZED: u32 = 0x0002_0000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProtoSpec {
    pub return_type: String,
    pub params: Vec<String>,
}

impl ProtoSpec {
    pub(super) fn new(return_type: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            return_type: return_type.into(),
            params,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FieldRef {
    pub class_type: String,
    pub type_name: String,
    pub name: String,
}

impl FieldRef {
    pub(super) fn new(class_type: impl Into<String>, type_name: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            type_name: type_name.into(),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MethodRef {
    pub class_type: String,
    pub proto: ProtoSpec,
    pub name: String,
}

impl MethodRef {
    pub(super) fn new(
        class_type: impl Into<String>,
        name: impl Into<String>,
        return_type: impl Into<String>,
        params: Vec<String>,
    ) -> Self {
        Self {
            class_type: class_type.into(),
            proto: ProtoSpec::new(return_type, params),
            name: name.into(),
        }
    }
}

mod dex_ir;
use dex_ir::{
    value_kind_from_descriptor, DexCode, DexIntBinOp, DexIntLit16Op, DexIntLit8Op, DexIrBuilder, IfCmpOp,
    IrCatchHandler, ValueKind,
};

mod dex_writer;
use dex_writer::{DexBuilder, DexClass};

pub(super) struct GeneratedManagedDex {
    pub dex: Vec<u8>,
    pub class_name: String,
    pub method_name: String,
    pub method_sig: String,
    pub orig_backup_name: Option<String>,
    pub orig_backup_sig: Option<String>,
    pub fast_tail_orig: bool,
    pub orig_only_passthrough: bool,
    pub fast_tail_orig_counter_fields: Vec<String>,
    pub uses_orig: bool,
    pub string_literals: Vec<GeneratedStringLiteral>,
    pub counters: Vec<GeneratedCounter>,
    pub message_channels: Vec<GeneratedMessageChannel>,
    pub message_capacity: i32,
    pub uses_direct_buffer_helpers: bool,
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedStringLiteral {
    pub field_name: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedCounter {
    pub name: String,
    pub field_name: String,
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedMessageChannel {
    pub name: String,
    pub code: i32,
}

pub(super) const MANAGED_MESSAGE_CAPACITY: i32 = 4096;
pub(super) const MANAGED_MESSAGE_MAX_CAPACITY: i32 = 1 << 20;
pub(super) const MANAGED_MESSAGE_HEAD_FIELD: &str = "__rf_msg_head";
pub(super) const MANAGED_MESSAGE_TAIL_FIELD: &str = "__rf_msg_tail";
pub(super) const MANAGED_MESSAGE_DROPPED_FIELD: &str = "__rf_msg_dropped";
pub(super) const MANAGED_MESSAGE_CODES_FIELD: &str = "__rf_msg_codes";
pub(super) const MANAGED_MESSAGE_VALUES_FIELD: &str = "__rf_msg_values";
pub(super) const MANAGED_MESSAGE_TEXTS_FIELD: &str = "__rf_msg_texts";

pub(super) struct GeneratedJavaWorkerDex {
    pub dex: Vec<u8>,
    pub class_name: String,
}

pub(super) fn build_java_worker_dex(class_id: u64) -> Result<GeneratedJavaWorkerDex, String> {
    let descriptor = format!("Lrustfrida/JavaWorker{};", class_id);
    let class_name = descriptor
        .trim_start_matches('L')
        .trim_end_matches(';')
        .replace('/', ".");
    let mut class = DexClass::new(descriptor.clone())
        .super_type("Ljava/lang/Thread;")
        .source_file("RustFridaJavaWorker.java");

    let thread_ctor = MethodRef::new(
        "Ljava/lang/Thread;",
        "<init>",
        "V",
        vec!["Ljava/lang/String;".to_string()],
    );
    let mut ctor = DexIrBuilder::new(2, 1, 2);
    ctor.const_string(0, "wwb-javawoker");
    ctor.invoke_direct(vec![1, 0], thread_ctor.clone());
    ctor.return_void();
    class.direct_method("<init>", "V", Vec::new(), ACC_PUBLIC | ACC_CONSTRUCTOR, ctor.finish()?);

    let native_loop = MethodRef::new(descriptor.clone(), "nativeLoop", "Z", Vec::new());
    class.native_direct_method("nativeLoop", "Z", Vec::new(), ACC_PRIVATE | ACC_STATIC | ACC_NATIVE);

    let mut run = DexIrBuilder::new(1, 1, 0);
    let loop_label = run.new_label();
    run.bind(loop_label)?;
    run.invoke_static(Vec::new(), native_loop.clone());
    run.move_result(0);
    run.if_nez(0, loop_label);
    run.return_void();
    class.virtual_method("run", "V", Vec::new(), ACC_PUBLIC, run.finish()?);

    let mut dex = DexBuilder::new();
    dex.add_method_ref(thread_ctor);
    dex.add_method_ref(native_loop);
    dex.add_class(class);
    Ok(GeneratedJavaWorkerDex {
        dex: dex.build()?,
        class_name,
    })
}

mod descriptor;
use descriptor::{
    array_component_descriptor, build_method_sig, build_params_sig, common_value_descriptor_with_env,
    descriptor_is_interface, descriptor_list_word_count, descriptor_to_java_class_name, descriptor_word_count,
    java_class_to_descriptor, java_class_to_descriptor_or_primitive, object_assignability_score, parse_call_params,
    parse_method_params_signature, parse_method_signature, resolve_field_with_env, return_is_object,
};

fn build_orig_backup_stub(return_type: &str, ins_size: u16) -> Result<DexCode, String> {
    let min_ret_regs = match return_type {
        "V" => 0,
        "J" | "D" => 2,
        "Z" | "B" | "C" | "S" | "I" | "F" => 1,
        ret if return_is_object(ret) => 1,
        other => return Err(format!("unsupported return type '{}' for orig backup", other)),
    };
    let mut code = DexCode::new(ins_size.max(min_ret_regs), ins_size, 0);
    // Keep __rf_orig as a normal managed method so helper try/catch metadata can
    // cover the call, but make the stub too large for ART's inliner. After the
    // helper is compiled, installation rewrites this method's quick entrypoint
    // to the original-method trampoline, so these nops are not on the hot path.
    for _ in 0..128 {
        code.raw(0x0000);
    }
    match return_type {
        "V" => code.raw(0x000e),
        "J" | "D" => {
            code.raw(0x0016);
            code.raw(0);
            code.raw(0x0010);
        }
        ret if return_is_object(ret) => {
            code.raw(0x0012);
            code.raw(0x0011);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            code.raw(0x0012);
            code.raw(0x000f);
        }
        _ => unreachable!(),
    }
    Ok(code)
}

fn generated_int_field(generated_type: &str, name: &str) -> FieldRef {
    FieldRef::new(generated_type.to_string(), "I".to_string(), name.to_string())
}

fn generated_int_array_field(generated_type: &str, name: &str) -> FieldRef {
    FieldRef::new(generated_type.to_string(), "[I".to_string(), name.to_string())
}

fn generated_string_array_field(generated_type: &str, name: &str) -> FieldRef {
    FieldRef::new(
        generated_type.to_string(),
        "[Ljava/lang/String;".to_string(),
        name.to_string(),
    )
}

fn validate_message_capacity(capacity: i32) -> Result<(), String> {
    if capacity <= 0 {
        return Err("managed message capacity must be positive".to_string());
    }
    if capacity > MANAGED_MESSAGE_MAX_CAPACITY {
        return Err(format!(
            "managed message capacity too large: {} > {}",
            capacity, MANAGED_MESSAGE_MAX_CAPACITY
        ));
    }
    if (capacity & (capacity - 1)) != 0 {
        return Err(format!(
            "managed message capacity must be a power of two for the hot-path ring buffer: {}",
            capacity
        ));
    }
    Ok(())
}

fn build_message_send_code(generated_type: &str, capacity: i32) -> Result<DexCode, String> {
    validate_message_capacity(capacity)?;
    let mask = capacity - 1;
    let head_field = generated_int_field(generated_type, MANAGED_MESSAGE_HEAD_FIELD);
    let tail_field = generated_int_field(generated_type, MANAGED_MESSAGE_TAIL_FIELD);
    let dropped_field = generated_int_field(generated_type, MANAGED_MESSAGE_DROPPED_FIELD);
    let codes_field = generated_int_array_field(generated_type, MANAGED_MESSAGE_CODES_FIELD);
    let values_field = generated_int_array_field(generated_type, MANAGED_MESSAGE_VALUES_FIELD);
    let texts_field = generated_string_array_field(generated_type, MANAGED_MESSAGE_TEXTS_FIELD);

    // v6/v7 are incoming static method args: channel code and int payload.
    let mut ir = DexIrBuilder::new(8, 2, 0);
    let ok = ir.new_label();
    ir.sget(1, head_field.clone(), ValueKind::Narrow);
    ir.sget(2, tail_field, ValueKind::Narrow);
    ir.int_binop(DexIntBinOp::Sub, 3, 1, 2);
    ir.const32(4, capacity);
    ir.if_cmp(IfCmpOp::Lt, 3, 4, ok);

    ir.sget(5, dropped_field.clone(), ValueKind::Narrow);
    ir.int_binop_lit8(DexIntLit8Op::Add, 5, 5, 1);
    ir.sput(5, dropped_field, ValueKind::Narrow);
    ir.return_void();

    ir.bind(ok)?;
    ir.const32(5, mask);
    ir.int_binop(DexIntBinOp::And, 4, 1, 5);
    ir.sget(0, codes_field, ValueKind::Object);
    ir.aput(6, 0, 4, ValueKind::Narrow);
    ir.sget(0, values_field, ValueKind::Object);
    ir.aput(7, 0, 4, ValueKind::Narrow);
    ir.sget(0, texts_field, ValueKind::Object);
    ir.const4(5, 0);
    ir.aput(5, 0, 4, ValueKind::Object);
    ir.int_binop_lit8(DexIntLit8Op::Add, 1, 1, 1);
    ir.sput(1, head_field, ValueKind::Narrow);
    ir.return_void();
    ir.finish()
}

fn build_message_send_string_code(generated_type: &str, capacity: i32) -> Result<DexCode, String> {
    validate_message_capacity(capacity)?;
    let mask = capacity - 1;
    let head_field = generated_int_field(generated_type, MANAGED_MESSAGE_HEAD_FIELD);
    let tail_field = generated_int_field(generated_type, MANAGED_MESSAGE_TAIL_FIELD);
    let dropped_field = generated_int_field(generated_type, MANAGED_MESSAGE_DROPPED_FIELD);
    let codes_field = generated_int_array_field(generated_type, MANAGED_MESSAGE_CODES_FIELD);
    let values_field = generated_int_array_field(generated_type, MANAGED_MESSAGE_VALUES_FIELD);
    let texts_field = generated_string_array_field(generated_type, MANAGED_MESSAGE_TEXTS_FIELD);

    // v6/v7 are incoming static method args: channel code and String payload.
    let mut ir = DexIrBuilder::new(8, 2, 0);
    let ok = ir.new_label();
    ir.sget(1, head_field.clone(), ValueKind::Narrow);
    ir.sget(2, tail_field, ValueKind::Narrow);
    ir.int_binop(DexIntBinOp::Sub, 3, 1, 2);
    ir.const32(4, capacity);
    ir.if_cmp(IfCmpOp::Lt, 3, 4, ok);

    ir.sget(5, dropped_field.clone(), ValueKind::Narrow);
    ir.int_binop_lit8(DexIntLit8Op::Add, 5, 5, 1);
    ir.sput(5, dropped_field, ValueKind::Narrow);
    ir.return_void();

    ir.bind(ok)?;
    ir.const32(5, mask);
    ir.int_binop(DexIntBinOp::And, 4, 1, 5);
    ir.sget(0, codes_field, ValueKind::Object);
    ir.aput(6, 0, 4, ValueKind::Narrow);
    ir.sget(0, values_field, ValueKind::Object);
    ir.const4(5, 0);
    ir.aput(5, 0, 4, ValueKind::Narrow);
    ir.sget(0, texts_field, ValueKind::Object);
    ir.aput(7, 0, 4, ValueKind::Object);
    ir.int_binop_lit8(DexIntLit8Op::Add, 1, 1, 1);
    ir.sput(1, head_field, ValueKind::Narrow);
    ir.return_void();
    ir.finish()
}

mod semantic;
use semantic::validate_semantics;

fn resolve_call_proto_with_arg_types(
    env: JniEnv,
    stmt: &DslCallStmt,
    class_type: &str,
    arg_types: Option<&[Option<String>]>,
) -> Result<(Vec<String>, String, String), String> {
    if let Ok((params, return_type)) = parse_method_signature(&stmt.sig) {
        return Ok((params, return_type, stmt.sig.clone()));
    }

    let class_name = descriptor_to_java_class_name(class_type)?;
    let is_static = matches!(stmt.kind, DslCallKind::Static);
    if stmt.sig.is_empty() {
        let arg_types = arg_types.ok_or_else(|| {
            format!(
                "direct call {}.{}(...) requires argument type inference; use overload(\"...\") to disambiguate",
                class_name, stmt.method_name
            )
        })?;
        return resolve_direct_call_proto(env, stmt, &class_name, is_static, arg_types);
    }

    let params = parse_method_params_signature(&stmt.sig)?;
    let params_sig = build_params_sig(&params);
    let collect_matches = |declared_only: bool, include_synthetic: bool| -> Result<BTreeSet<String>, String> {
        let methods = unsafe {
            if declared_only {
                enumerate_methods_declared_only(env, &class_name)
            } else {
                enumerate_methods(env, &class_name)
            }
        }?;
        let mut matches = BTreeSet::new();
        for method in methods {
            if method.name != stmt.method_name || method.is_static != is_static {
                continue;
            }
            if !include_synthetic && (method.modifiers & (ACC_BRIDGE as i32 | ACC_SYNTHETIC as i32)) != 0 {
                continue;
            }
            let Ok((method_params, _)) = parse_method_signature(&method.sig) else {
                continue;
            };
            if build_params_sig(&method_params) == params_sig {
                matches.insert(method.sig);
            }
        }
        Ok(matches)
    };

    let declared_matches = collect_matches(true, false)?;
    let matches = if declared_matches.is_empty() {
        let inherited_matches = collect_matches(false, false)?;
        if inherited_matches.is_empty() {
            collect_matches(false, true)?
        } else {
            inherited_matches
        }
    } else {
        declared_matches
    };

    match matches.len() {
        1 => {
            let full_sig = matches.into_iter().next().unwrap();
            let (params, return_type) = parse_method_signature(&full_sig)?;
            Ok((params, return_type, full_sig))
        }
        0 => Err(format!(
            "method not found for {}.{}{}; use a full JNI signature if reflection cannot resolve it",
            class_name, stmt.method_name, params_sig
        )),
        _ => Err(format!(
            "ambiguous method return for {}.{}{}; use overload(\"full JNI signature\")",
            class_name, stmt.method_name, params_sig
        )),
    }
}

fn resolve_constructor_proto_with_arg_types(
    env: JniEnv,
    class_name: &str,
    ctor_sig: Option<&str>,
    arg_types: &[Option<String>],
) -> Result<(Vec<String>, String), String> {
    if let Some(sig) = ctor_sig {
        let (params, return_type) = parse_method_signature(sig)?;
        if return_type != "V" {
            return Err(format!("constructor signature must return void, got '{}'", return_type));
        }
        return Ok((params, sig.to_string()));
    }

    let stmt = DslCallStmt {
        kind: DslCallKind::Virtual,
        target: None,
        receiver: None,
        null_safe: false,
        class_name: Some(class_name.to_string()),
        method_name: "<init>".to_string(),
        sig: String::new(),
        args: Vec::new(),
    };
    let (params, return_type, full_sig) = resolve_direct_call_proto(env, &stmt, class_name, false, arg_types)?;
    if return_type != "V" {
        return Err(format!("constructor signature must return void, got '{}'", return_type));
    }
    Ok((params, full_sig))
}

fn resolve_direct_call_proto(
    env: JniEnv,
    stmt: &DslCallStmt,
    class_name: &str,
    is_static: bool,
    arg_types: &[Option<String>],
) -> Result<(Vec<String>, String, String), String> {
    let collect_matches = |declared_only: bool, include_synthetic: bool| -> Result<BTreeSet<(u16, String)>, String> {
        let methods = unsafe {
            if declared_only {
                enumerate_methods_declared_only(env, class_name)
            } else {
                enumerate_methods(env, class_name)
            }
        }?;
        let mut matches = BTreeSet::new();
        for method in methods {
            if method.name != stmt.method_name || method.is_static != is_static {
                continue;
            }
            if !include_synthetic && (method.modifiers & (ACC_BRIDGE as i32 | ACC_SYNTHETIC as i32)) != 0 {
                continue;
            }
            let Ok((method_params, _)) = parse_method_signature(&method.sig) else {
                continue;
            };
            let Some(score) = direct_call_match_score(env, arg_types, &method_params) else {
                continue;
            };
            matches.insert((score, method.sig));
        }
        Ok(matches)
    };

    let declared_matches = collect_matches(true, false)?;
    let matches = if declared_matches.is_empty() {
        let inherited_matches = collect_matches(false, false)?;
        if inherited_matches.is_empty() {
            collect_matches(false, true)?
        } else {
            inherited_matches
        }
    } else {
        declared_matches
    };

    pick_unique_direct_call_sig(env, class_name, &stmt.method_name, arg_types, matches).and_then(|full_sig| {
        let (params, return_type) = parse_method_signature(&full_sig)?;
        Ok((params, return_type, full_sig))
    })
}

fn pick_unique_direct_call_sig(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    arg_types: &[Option<String>],
    matches: BTreeSet<(u16, String)>,
) -> Result<String, String> {
    let Some(best_score) = matches.iter().map(|(score, _)| *score).min() else {
        return Err(format!(
            "method not found for {}.{}({} inferred arg(s)); use overload(\"...\") to specify parameter types",
            class_name,
            method_name,
            arg_types.len()
        ));
    };
    let best = matches
        .into_iter()
        .filter(|(score, _)| *score == best_score)
        .map(|(_, sig)| sig)
        .collect::<BTreeSet<_>>();
    if best.len() == 1 {
        return Ok(best.into_iter().next().unwrap());
    }
    if let Some(full_sig) = pick_most_specific_direct_call_sig(env, &best) {
        return Ok(full_sig);
    }
    Err(format!(
        "ambiguous overload for {}.{} with inferred argument types {}; use overload(\"...\")",
        class_name,
        method_name,
        format_inferred_arg_types(arg_types)
    ))
}

fn pick_most_specific_direct_call_sig(env: JniEnv, sigs: &BTreeSet<String>) -> Option<String> {
    let candidates = sigs
        .iter()
        .filter_map(|sig| parse_method_signature(sig).ok().map(|(params, _)| (sig, params)))
        .collect::<Vec<_>>();
    let mut best = None;
    for (sig, params) in &candidates {
        let more_specific_than_all = candidates
            .iter()
            .filter(|(other_sig, _)| *other_sig != *sig)
            .all(|(_, other_params)| params_more_specific(env, params, other_params));
        if more_specific_than_all {
            if best.is_some() {
                return None;
            }
            best = Some((*sig).clone());
        }
    }
    best
}

fn params_more_specific(env: JniEnv, params: &[String], other_params: &[String]) -> bool {
    params.len() == other_params.len()
        && params
            .iter()
            .zip(other_params)
            .all(|(param, other)| descriptor_more_specific_or_equal(env, param, other))
}

fn descriptor_more_specific_or_equal(env: JniEnv, desc: &str, other: &str) -> bool {
    desc == other || object_assignability_score(env, desc, other).is_some()
}

fn direct_call_match_score(env: JniEnv, arg_types: &[Option<String>], params: &[String]) -> Option<u16> {
    if arg_types.len() != params.len() {
        return None;
    }
    let mut score = 0u16;
    for (arg_type, param) in arg_types.iter().zip(params) {
        match arg_type {
            Some(arg) if arg == param => {}
            Some(arg) if return_is_object(arg) && return_is_object(param) => {
                score = score.saturating_add(object_assignability_score(env, arg, param)?);
            }
            None if return_is_object(param) => score = score.saturating_add(4096),
            _ => return None,
        }
    }
    Some(score)
}

fn format_inferred_arg_types(arg_types: &[Option<String>]) -> String {
    let parts = arg_types
        .iter()
        .map(|arg| arg.as_deref().unwrap_or("null"))
        .collect::<Vec<_>>();
    format!("({})", parts.join(", "))
}

mod emitter;
use emitter::{
    collect_local_slots, emit_managed_guard_enter, emit_managed_guard_leave, emit_statements, helper_param_layout,
    precollect_string_literals, program_array_literal_scratch_count, program_fast_tail_orig,
    program_fast_tail_orig_count_names, program_int_expr_scratch_count, program_max_invoke_depth,
    program_max_invoke_words, program_orig_only_passthrough, program_uses_orig, DslBuildContext, EmitContext,
    BASE_LOCAL_REG_COUNT,
};

pub(super) unsafe fn build_managed_dsl_dex(
    env: JniEnv,
    class_id: u64,
    target_class_name: &str,
    target_method_name: &str,
    target_sig: &str,
    is_static: bool,
    dsl: &str,
    message_capacity: i32,
) -> Result<GeneratedManagedDex, String> {
    validate_message_capacity(message_capacity)?;
    let program = parse_managed_dsl(dsl)?;
    let uses_orig = program_uses_orig(&program);
    let target_type = java_class_to_descriptor(target_class_name)?;
    let object_type = "Ljava/lang/Object;".to_string();
    let (target_params, return_type) = parse_method_signature(target_sig)?;
    let fast_tail_orig = program_fast_tail_orig(&program, target_params.len());
    let orig_only_passthrough = program_orig_only_passthrough(&program, target_params.len());
    let fast_tail_orig_count_names = program_fast_tail_orig_count_names(&program, target_params.len());
    let local_descriptors = validate_semantics(
        env,
        &program,
        is_static,
        target_type.clone(),
        target_params.clone(),
        return_type.clone(),
    )?;
    let mut helper_params = Vec::new();
    if !is_static {
        helper_params.push(target_type.clone());
    }
    helper_params.extend(target_params.clone());

    let ins_size = descriptor_list_word_count(&helper_params)?;
    if ins_size > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", ins_size));
    }
    let max_invoke_words = program_max_invoke_words(&program, &target_params, is_static)?;
    if max_invoke_words > u8::MAX as u16 {
        return Err(format!("too many DSL invoke argument words: {}", max_invoke_words));
    }
    let max_invoke_depth = program_max_invoke_depth(&program).max(1);
    let int_expr_scratch_count = program_int_expr_scratch_count(&program);
    let array_literal_scratch_base = BASE_LOCAL_REG_COUNT
        .checked_add(int_expr_scratch_count)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let array_literal_scratch_count = program_array_literal_scratch_count(&program);
    let invoke_scratch_base = array_literal_scratch_base
        .checked_add(array_literal_scratch_count)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let invoke_frame_words = max_invoke_words.max(1);
    let invoke_frame_span = invoke_frame_words
        .checked_mul(2)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let invoke_scratch_words = invoke_frame_span
        .checked_mul(max_invoke_depth)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let locals_start = invoke_scratch_base
        .checked_add(invoke_scratch_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let (local_slots, local_words) = collect_local_slots(&local_descriptors, locals_start)?;
    let local_count = locals_start
        .checked_add(local_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let registers_size = local_count
        .checked_add(ins_size)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let outs_size = std::cmp::max(1u16, std::cmp::max(ins_size, max_invoke_words));
    if registers_size > u8::MAX as u16 {
        return Err(format!(
            "too many dex registers for generated helper: {}",
            registers_size
        ));
    }

    let generated_type = format!("Lrustfrida/DynManagedHook{};", class_id);
    let generated_class_name = format!("rustfrida.DynManagedHook{}", class_id);
    let sink = FieldRef::new(generated_type.clone(), object_type.clone(), "sink");
    let mut dsl_ctx = DslBuildContext::new(
        env,
        generated_type.clone(),
        BASE_LOCAL_REG_COUNT,
        int_expr_scratch_count,
        array_literal_scratch_base,
        array_literal_scratch_count,
        invoke_scratch_base,
        invoke_frame_words,
        max_invoke_depth,
    );
    precollect_string_literals(&program, &mut dsl_ctx);
    if fast_tail_orig {
        dsl_ctx.set_managed_guard_enabled(false);
    }
    let target = MethodRef::new(
        target_type.clone(),
        target_method_name.to_string(),
        return_type.clone(),
        target_params.clone(),
    );
    let target_is_interface = !is_static && descriptor_is_interface(env, &target_type);
    let orig_backup_name = "__rf_orig".to_string();
    let orig_backup_sig = build_method_sig(&helper_params, &return_type);
    let orig_backup = MethodRef::new(
        generated_type.clone(),
        orig_backup_name.clone(),
        return_type.clone(),
        helper_params.clone(),
    );
    if uses_orig {
        dsl_ctx.set_orig_emit_context(
            is_static,
            local_count,
            ins_size,
            orig_backup.clone(),
            return_type.clone(),
        );
    }
    let mut ir = DexIrBuilder::new(registers_size, ins_size, outs_size);
    let layout = helper_param_layout(is_static, &target_type, &target_params, local_count, local_slots)?;
    emit_managed_guard_enter(&mut ir, &dsl_ctx);
    let guard_try_start = ir.new_label();
    let guard_try_end = ir.new_label();
    let guard_catch_all = ir.new_label();
    ir.bind(guard_try_start)?;
    let saw_return = {
        let mut emit_ctx = EmitContext {
            layout: &layout,
            dsl_ctx: &mut dsl_ctx,
            is_static,
            local_count,
            ins_size,
            target: &target,
            orig_backup: &orig_backup,
            target_is_interface,
            return_type: &return_type,
            sink: &sink,
            loop_stack: Vec::new(),
        };
        emit_statements(&mut ir, &program.stmts, &mut emit_ctx)?
    };
    ir.bind(guard_try_end)?;
    if !saw_return {
        return Err("managed DSL must end with return statement".to_string());
    }
    ir.bind(guard_catch_all)?;
    ir.move_exception(1);
    emit_managed_guard_leave(&mut ir, &dsl_ctx);
    ir.throw_value(1);
    ir.add_try_handlers(guard_try_start, guard_try_end, Vec::new(), Some(guard_catch_all));
    let code = ir.finish()?;

    let mut class = DexClass::new(generated_type.clone()).source_file("RustFridaDynamicManagedHook.java");
    class.static_field("sink", &object_type, ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
    for lit in &dsl_ctx.string_literals {
        class.static_field(
            &lit.field_name,
            "Ljava/lang/String;",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
    }
    for counter in &dsl_ctx.counters {
        class.static_field(&counter.field_name, "I", ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
    }
    if !dsl_ctx.message_channels.is_empty() {
        class.static_field(MANAGED_MESSAGE_HEAD_FIELD, "I", ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
        class.static_field(MANAGED_MESSAGE_TAIL_FIELD, "I", ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
        class.static_field(
            MANAGED_MESSAGE_DROPPED_FIELD,
            "I",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
        class.static_field(
            MANAGED_MESSAGE_CODES_FIELD,
            "[I",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
        class.static_field(
            MANAGED_MESSAGE_VALUES_FIELD,
            "[I",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
        class.static_field(
            MANAGED_MESSAGE_TEXTS_FIELD,
            "[Ljava/lang/String;",
            ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE,
        );
        class.direct_method(
            "__rf_send",
            "V",
            vec!["I".to_string(), "I".to_string()],
            ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC,
            build_message_send_code(&generated_type, message_capacity)?,
        );
        class.direct_method(
            "__rf_send_str",
            "V",
            vec!["I".to_string(), "Ljava/lang/String;".to_string()],
            ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC,
            build_message_send_string_code(&generated_type, message_capacity)?,
        );
    }
    if dsl_ctx.uses_direct_buffer_helpers {
        class.native_direct_method(
            "__rf_dbb_fill",
            "I",
            vec![
                "Ljava/nio/ByteBuffer;".to_string(),
                "I".to_string(),
                "I".to_string(),
                "I".to_string(),
            ],
            ACC_PUBLIC | ACC_STATIC | ACC_NATIVE | ACC_SYNTHETIC,
        );
        class.native_direct_method(
            "__rf_dbb_copy_from_byte_array",
            "I",
            vec![
                "Ljava/nio/ByteBuffer;".to_string(),
                "I".to_string(),
                "[B".to_string(),
                "I".to_string(),
                "I".to_string(),
            ],
            ACC_PUBLIC | ACC_STATIC | ACC_NATIVE | ACC_SYNTHETIC,
        );
        class.native_direct_method(
            "__rf_dbb_copy_to_byte_array",
            "I",
            vec![
                "Ljava/nio/ByteBuffer;".to_string(),
                "I".to_string(),
                "[B".to_string(),
                "I".to_string(),
                "I".to_string(),
            ],
            ACC_PUBLIC | ACC_STATIC | ACC_NATIVE | ACC_SYNTHETIC,
        );
        class.native_direct_method(
            "__rf_dbb_capacity",
            "I",
            vec!["Ljava/nio/ByteBuffer;".to_string()],
            ACC_PUBLIC | ACC_STATIC | ACC_NATIVE | ACC_SYNTHETIC,
        );
        class.native_direct_method(
            "__rf_dbb_get_u8",
            "I",
            vec!["Ljava/nio/ByteBuffer;".to_string(), "I".to_string()],
            ACC_PUBLIC | ACC_STATIC | ACC_NATIVE | ACC_SYNTHETIC,
        );
    }
    class.native_direct_method(
        "__rf_guard_enter",
        "V",
        Vec::new(),
        ACC_PUBLIC | ACC_STATIC | ACC_NATIVE | ACC_SYNTHETIC,
    );
    class.native_direct_method(
        "__rf_guard_leave",
        "V",
        Vec::new(),
        ACC_PUBLIC | ACC_STATIC | ACC_NATIVE | ACC_SYNTHETIC,
    );
    class.direct_method(
        "hook",
        &return_type,
        helper_params.clone(),
        ACC_PUBLIC | ACC_STATIC,
        code,
    );
    if uses_orig {
        class.direct_method(
            &orig_backup_name,
            &return_type,
            helper_params.clone(),
            ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC,
            build_orig_backup_stub(&return_type, ins_size)?,
        );
    }

    let mut builder = DexBuilder::new();
    builder.add_class(class);
    builder.add_method_ref(target);
    if uses_orig {
        builder.add_method_ref(orig_backup);
    }
    let dex = builder.build()?;
    let fast_tail_orig_counter_fields = fast_tail_orig_count_names
        .unwrap_or_default()
        .into_iter()
        .map(|name| {
            dsl_ctx
                .counters
                .iter()
                .find(|counter| counter.name == name)
                .map(|counter| counter.field_name.clone())
                .ok_or_else(|| format!("fast-tail counter not generated: {}", name))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(GeneratedManagedDex {
        dex,
        class_name: generated_class_name,
        method_name: "hook".to_string(),
        method_sig: build_method_sig(&helper_params, &return_type),
        orig_backup_name: uses_orig.then_some(orig_backup_name),
        orig_backup_sig: uses_orig.then_some(orig_backup_sig),
        fast_tail_orig,
        orig_only_passthrough,
        fast_tail_orig_counter_fields,
        uses_orig,
        string_literals: dsl_ctx.string_literals,
        counters: dsl_ctx.counters,
        message_channels: dsl_ctx.message_channels,
        message_capacity,
        uses_direct_buffer_helpers: dsl_ctx.uses_direct_buffer_helpers,
    })
}

mod dsl;
use dsl::{parse_managed_dsl, DslCallKind, DslCallStmt};
