/*
 * quickjs_wrapper.h - C wrappers for QuickJS inline functions
 */

#ifndef QUICKJS_WRAPPER_H
#define QUICKJS_WRAPPER_H

#include "quickjs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Value management */
void qjs_free_value(JSContext *ctx, JSValue v);
void qjs_free_value_rt(JSRuntime *rt, JSValue v);
JSValue qjs_dup_value(JSContext *ctx, JSValue v);
JSValue qjs_dup_value_rt(JSRuntime *rt, JSValue v);

/* String conversion */
const char *qjs_to_cstring(JSContext *ctx, JSValue val);
void qjs_free_cstring(JSContext *ctx, const char *str);

/* Property access */
JSValue qjs_get_property(JSContext *ctx, JSValue this_obj, JSAtom prop);
int qjs_set_property(JSContext *ctx, JSValue this_obj, JSAtom prop, JSValue val);

/* Function creation */
JSValue qjs_new_cfunction(JSContext *ctx, JSCFunction *func, const char *name, int length);
JSValue qjs_new_cfunction_magic(JSContext *ctx, JSCFunctionMagic *func,
                                  const char *name, int length, JSCFunctionEnum cproto, int magic);

/* Type checking */
int qjs_is_number(JSValue v);
int qjs_is_big_int(JSContext *ctx, JSValue v);
int qjs_is_bool(JSValue v);
int qjs_is_null(JSValue v);
int qjs_is_undefined(JSValue v);
int qjs_is_exception(JSValue v);
int qjs_is_uninitialized(JSValue v);
int qjs_is_string(JSValue v);
int qjs_is_symbol(JSValue v);
int qjs_is_object(JSValue v);

/* Value accessors */
int32_t qjs_value_get_tag(JSValue v);
int32_t qjs_value_get_int(JSValue v);
int qjs_value_get_bool(JSValue v);
double qjs_value_get_float64(JSValue v);
void *qjs_value_get_ptr(JSValue v);

/* Value creation */
JSValue qjs_mkval(int32_t tag, int32_t val);
JSValue qjs_mkptr(int32_t tag, void *ptr);
JSValue qjs_new_bool(JSContext *ctx, int val);
JSValue qjs_new_int32(JSContext *ctx, int32_t val);
JSValue qjs_new_int64(JSContext *ctx, int64_t val);
JSValue qjs_new_uint32(JSContext *ctx, uint32_t val);
JSValue qjs_new_float64(JSContext *ctx, double val);

/* Value conversion */
int qjs_to_uint32(JSContext *ctx, uint32_t *pres, JSValue val);
int qjs_to_int64(JSContext *ctx, int64_t *pres, JSValue val);
int qjs_to_index(JSContext *ctx, uint64_t *pres, JSValue val);
int qjs_to_float64(JSContext *ctx, double *pres, JSValue val);
int qjs_to_big_int64(JSContext *ctx, int64_t *pres, JSValue val);
int qjs_to_int64_ext(JSContext *ctx, int64_t *pres, JSValue val);
int qjs_value_to_u64(JSContext *ctx, uint64_t *pres, JSValue val);

/* Stack top update for cross-thread usage */
void qjs_update_stack_top(JSContext *ctx);

/* Throw an Error-class exception with a full-length message (bypasses
 * QuickJS's 256-byte vsnprintf truncation in JS_ThrowInternalError et al).
 * error_class_name: "InternalError" / "TypeError" / "Error" / NULL (→ Error) */
JSValue qjs_throw_error_with_message(JSContext *ctx,
                                     const char *error_class_name,
                                     const char *message,
                                     size_t message_len);

/* Constants */
JSValue qjs_null(void);
JSValue qjs_undefined(void);
JSValue qjs_false(void);
JSValue qjs_true(void);
JSValue qjs_exception(void);
JSValue qjs_uninitialized(void);

#ifdef __cplusplus
}
#endif

#endif /* QUICKJS_WRAPPER_H */
