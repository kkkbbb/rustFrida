//! RPC API: `rpc.exports` registry + `__rpc_dispatch` helper.
//!
//! Frida-style 用法：
//! ```js
//! rpc.exports = {
//!   add: function(a, b) { return a + b; },
//!   ping: function() { return "pong"; }
//! };
//!
//! // 或者单独注册
//! rpc.export('greet', function(name) { return 'hello ' + name; });
//! ```
//!
//! Host 端通过 `__rpc_dispatch(method, argsJson)` 派发调用，
//! 返回值经 JSON.stringify 后以字符串形式返回。

use crate::context::JSContext;

const RPC_BOOTSTRAP: &str = r#"
(function() {
    if (typeof globalThis.rpc === 'undefined' || globalThis.rpc === null) {
        globalThis.rpc = {};
    }
    if (typeof globalThis.rpc.exports === 'undefined' || globalThis.rpc.exports === null) {
        globalThis.rpc.exports = {};
    }
    if (typeof globalThis.rpc.export !== 'function') {
        Object.defineProperty(globalThis.rpc, 'export', {
            value: function(name, fn) {
                if (typeof name !== 'string') {
                    throw new TypeError('rpc.export: name must be a string');
                }
                if (typeof fn !== 'function') {
                    throw new TypeError('rpc.export: fn must be a function');
                }
                globalThis.rpc.exports[name] = fn;
            },
            writable: true,
            configurable: true,
            enumerable: false
        });
    }
    globalThis.__rpc_dispatch = function(method, argsJson) {
        var exp = globalThis.rpc && globalThis.rpc.exports;
        if (!exp || typeof exp[method] !== 'function') {
            throw new Error('RPC method not found: ' + method);
        }
        var args;
        if (argsJson === undefined || argsJson === null || argsJson === '') {
            args = [];
        } else {
            args = JSON.parse(argsJson);
            if (!Array.isArray(args)) {
                throw new TypeError('RPC args must be a JSON array');
            }
        }
        var result = exp[method].apply(null, args);
        if (result === undefined) {
            return 'null';
        }
        return JSON.stringify(result);
    };
})();
"#;

/// Register the `rpc` global object and `__rpc_dispatch` helper.
pub fn register_rpc(ctx: &JSContext) {
    // 在全局作用域中求值初始化脚本；忽略返回值但报告异常。
    match ctx.eval(RPC_BOOTSTRAP, "<rpc-bootstrap>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => {
            crate::jsapi::console::output_message(&format!("[rpc] bootstrap failed: {}", e));
        }
    }
}
