/*
 * quickjs_wrapper.c - C wrappers for QuickJS inline functions
 *
 * QuickJS defines many functions as static inline, which bindgen cannot
 * generate bindings for. This file provides C wrapper functions.
 */

#include "quickjs.h"
#include <stdlib.h>
#include <string.h>

/* JS_FreeValue wrapper */
void qjs_free_value(JSContext *ctx, JSValue v) {
    JS_FreeValue(ctx, v);
}

/* JS_FreeValueRT wrapper */
void qjs_free_value_rt(JSRuntime *rt, JSValue v) {
    JS_FreeValueRT(rt, v);
}

/* JS_DupValue wrapper */
JSValue qjs_dup_value(JSContext *ctx, JSValue v) {
    return JS_DupValue(ctx, v);
}

/* JS_DupValueRT wrapper */
JSValue qjs_dup_value_rt(JSRuntime *rt, JSValue v) {
    return JS_DupValueRT(rt, v);
}

/* JS_ToCString wrapper */
const char *qjs_to_cstring(JSContext *ctx, JSValue val) {
    return JS_ToCString(ctx, val);
}

/* JS_FreeCString wrapper */
void qjs_free_cstring(JSContext *ctx, const char *str) {
    JS_FreeCString(ctx, str);
}

/* JS_GetProperty wrapper */
JSValue qjs_get_property(JSContext *ctx, JSValue this_obj, JSAtom prop) {
    return JS_GetProperty(ctx, this_obj, prop);
}

/* JS_SetProperty wrapper */
int qjs_set_property(JSContext *ctx, JSValue this_obj, JSAtom prop, JSValue val) {
    return JS_SetProperty(ctx, this_obj, prop, val);
}

/* JS_NewCFunction wrapper */
JSValue qjs_new_cfunction(JSContext *ctx, JSCFunction *func, const char *name, int length) {
    return JS_NewCFunction(ctx, func, name, length);
}

/* JS_NewCFunctionMagic wrapper */
JSValue qjs_new_cfunction_magic(JSContext *ctx, JSCFunctionMagic *func,
                                  const char *name, int length, JSCFunctionEnum cproto, int magic) {
    return JS_NewCFunctionMagic(ctx, func, name, length, cproto, magic);
}

/* JS_IsNumber wrapper */
int qjs_is_number(JSValue v) {
    return JS_IsNumber(v);
}

/* JS_IsBigInt wrapper */
int qjs_is_big_int(JSContext *ctx, JSValue v) {
    return JS_IsBigInt(ctx, v);
}

/* JS_IsBool wrapper */
int qjs_is_bool(JSValue v) {
    return JS_IsBool(v);
}

/* JS_IsNull wrapper */
int qjs_is_null(JSValue v) {
    return JS_IsNull(v);
}

/* JS_IsUndefined wrapper */
int qjs_is_undefined(JSValue v) {
    return JS_IsUndefined(v);
}

/* JS_IsException wrapper */
int qjs_is_exception(JSValue v) {
    return JS_IsException(v);
}

/* JS_IsUninitialized wrapper */
int qjs_is_uninitialized(JSValue v) {
    return JS_IsUninitialized(v);
}

/* JS_IsString wrapper */
int qjs_is_string(JSValue v) {
    return JS_IsString(v);
}

/* JS_IsSymbol wrapper */
int qjs_is_symbol(JSValue v) {
    return JS_IsSymbol(v);
}

/* JS_IsObject wrapper */
int qjs_is_object(JSValue v) {
    return JS_IsObject(v);
}

/* JS_VALUE_GET_TAG wrapper */
int32_t qjs_value_get_tag(JSValue v) {
    return JS_VALUE_GET_TAG(v);
}

/* JS_VALUE_GET_INT wrapper */
int32_t qjs_value_get_int(JSValue v) {
    return JS_VALUE_GET_INT(v);
}

/* JS_VALUE_GET_BOOL wrapper */
int qjs_value_get_bool(JSValue v) {
    return JS_VALUE_GET_BOOL(v);
}

/* JS_VALUE_GET_FLOAT64 wrapper */
double qjs_value_get_float64(JSValue v) {
    return JS_VALUE_GET_FLOAT64(v);
}

/* JS_VALUE_GET_PTR wrapper */
void *qjs_value_get_ptr(JSValue v) {
    return JS_VALUE_GET_PTR(v);
}

/* JS_MKVAL wrapper */
JSValue qjs_mkval(int32_t tag, int32_t val) {
    return JS_MKVAL(tag, val);
}

/* JS_MKPTR wrapper */
JSValue qjs_mkptr(int32_t tag, void *ptr) {
    return JS_MKPTR(tag, ptr);
}

/* JS_NewBool wrapper */
JSValue qjs_new_bool(JSContext *ctx, int val) {
    return JS_NewBool(ctx, val);
}

/* JS_NewInt32 wrapper */
JSValue qjs_new_int32(JSContext *ctx, int32_t val) {
    return JS_NewInt32(ctx, val);
}

/* JS_NewInt64 wrapper */
JSValue qjs_new_int64(JSContext *ctx, int64_t val) {
    return JS_NewInt64(ctx, val);
}

/* JS_NewUint32 wrapper */
JSValue qjs_new_uint32(JSContext *ctx, uint32_t val) {
    return JS_NewUint32(ctx, val);
}

/* JS_NewFloat64 wrapper */
JSValue qjs_new_float64(JSContext *ctx, double val) {
    return JS_NewFloat64(ctx, val);
}

/* JS_ToUint32 wrapper */
int qjs_to_uint32(JSContext *ctx, uint32_t *pres, JSValue val) {
    return JS_ToUint32(ctx, pres, val);
}

/* JS_ToInt64 wrapper */
int qjs_to_int64(JSContext *ctx, int64_t *pres, JSValue val) {
    return JS_ToInt64(ctx, pres, val);
}

/* JS_ToIndex wrapper */
int qjs_to_index(JSContext *ctx, uint64_t *pres, JSValue val) {
    return JS_ToIndex(ctx, pres, val);
}

/* JS_ToFloat64 wrapper */
int qjs_to_float64(JSContext *ctx, double *pres, JSValue val) {
    return JS_ToFloat64(ctx, pres, val);
}

/* JS_ToBigInt64 wrapper */
int qjs_to_big_int64(JSContext *ctx, int64_t *pres, JSValue val) {
    return JS_ToBigInt64(ctx, pres, val);
}

/* JS_ToInt64Ext wrapper — handles both Number AND BigInt */
int qjs_to_int64_ext(JSContext *ctx, int64_t *pres, JSValue val) {
    return JS_ToInt64Ext(ctx, pres, val);
}

/* Convert any numeric value (int, float, BigInt) to uint64_t.
 * For BigInt: convert to string then parse (avoids internal API dependency).
 * Returns 0 on success, -1 on failure. */
int qjs_value_to_u64(JSContext *ctx, uint64_t *pres, JSValue val) {
    if (JS_IsBigInt(ctx, val)) {
        /* BigInt → string → strtoull */
        JSValue str = JS_ToString(ctx, val);
        if (JS_IsException(str)) {
            *pres = 0;
            return -1;
        }
        const char *cstr = JS_ToCString(ctx, str);
        JS_FreeValue(ctx, str);
        if (!cstr) {
            *pres = 0;
            return -1;
        }
        char *end;
        *pres = strtoull(cstr, &end, 10);
        JS_FreeCString(ctx, cstr);
        return 0;
    }
    return JS_ToInt64(ctx, (int64_t *)pres, val);
}

/* JS_NULL constant */
JSValue qjs_null(void) {
    return JS_NULL;
}

/* JS_UNDEFINED constant */
JSValue qjs_undefined(void) {
    return JS_UNDEFINED;
}

/* JS_FALSE constant */
JSValue qjs_false(void) {
    return JS_FALSE;
}

/* JS_TRUE constant */
JSValue qjs_true(void) {
    return JS_TRUE;
}

/* JS_EXCEPTION constant */
JSValue qjs_exception(void) {
    return JS_EXCEPTION;
}

/* JS_UNINITIALIZED constant */
JSValue qjs_uninitialized(void) {
    return JS_UNINITIALIZED;
}

/* Update stack top for cross-thread usage */
void qjs_update_stack_top(JSContext *ctx) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JS_UpdateStackTop(rt);
}

/*
 * qjs_throw_error_with_message - 抛一个完整消息的 Error（绕开 256 字节截断）
 *
 * QuickJS 的 JS_ThrowInternalError / JS_ThrowTypeError 内部走 JS_ThrowError2，
 * 用的是硬编码的 char buf[256] + vsnprintf —— 长消息会被截成 255 字节。
 * 另外它把 fmt 当 printf 格式字符串，消息里含 % 会被误解析。
 *
 * 这里通过 `new ErrorClass(msg)` 的 JS 层路径构造 Error：
 *   1. 从 globalThis 拿 Error 构造器 (InternalError / TypeError / Error 等)
 *   2. 用 JS_NewStringLen 创建完整 message 值（无长度限制）
 *   3. JS_CallConstructor 调用 `new ErrorClass(message)`
 *   4. JS_Throw 抛出
 *
 * error_class_name 传 NULL 或未知类名时 fallback 到 Error。
 */
JSValue qjs_throw_error_with_message(JSContext *ctx,
                                     const char *error_class_name,
                                     const char *message,
                                     size_t message_len) {
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsException(global)) {
        return JS_EXCEPTION;
    }

    const char *cls_name = (error_class_name && *error_class_name)
                               ? error_class_name
                               : "Error";
    JSValue ctor = JS_GetPropertyStr(ctx, global, cls_name);
    if (JS_IsException(ctor) || !JS_IsFunction(ctx, ctor)) {
        JS_FreeValue(ctx, ctor);
        /* fallback 到 Error */
        ctor = JS_GetPropertyStr(ctx, global, "Error");
    }
    JS_FreeValue(ctx, global);

    if (JS_IsException(ctor) || !JS_IsFunction(ctx, ctor)) {
        JS_FreeValue(ctx, ctor);
        /* 最坏情况: 走短版本避免 crash */
        return JS_ThrowInternalError(ctx, "%s", message);
    }

    JSValue msg_val = JS_NewStringLen(ctx, message, message_len);
    if (JS_IsException(msg_val)) {
        JS_FreeValue(ctx, ctor);
        return JS_EXCEPTION;
    }

    JSValue err = JS_CallConstructor(ctx, ctor, 1, &msg_val);
    JS_FreeValue(ctx, msg_val);
    JS_FreeValue(ctx, ctor);

    if (JS_IsException(err)) {
        return JS_EXCEPTION;
    }
    return JS_Throw(ctx, err);
}
