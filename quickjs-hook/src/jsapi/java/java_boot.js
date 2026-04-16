// Java.use() API — Frida-compatible syntax for Java method hooking
// Evaluated at engine init after C-level Java.hook/unhook/_methods/_fieldMeta/_readField/_writeField are registered.
(function() {
    "use strict";
    var _hook = Java.hook;
    var _unhook = Java.unhook;
    var _methods = Java._methods;
    var _invokeStaticMethod = Java._invokeStaticMethod;
    var _newObject = Java._newObject;
    var _fieldMeta = Java._fieldMeta;
    var _readField = Java._readField;
    var _writeField = Java._writeField;
    var _classLoaders = Java._classLoaders;
    var _findClassWithLoader = Java._findClassWithLoader;
    var _findClassObject = Java._findClassObject;
    var _setClassLoader = Java._setClassLoader;
    var _enumerateInstances = Java._enumerateInstances;
    var _releaseInstanceRefs = Java._releaseInstanceRefs;
    delete Java.hook;
    delete Java.unhook;
    delete Java._methods;
    delete Java._invokeStaticMethod;
    delete Java._newObject;
    delete Java._fieldMeta;
    delete Java._readField;
    delete Java._writeField;
    delete Java._classLoaders;
    delete Java._findClassWithLoader;
    delete Java._findClassObject;
    delete Java._setClassLoader;
    delete Java._enumerateInstances;
    delete Java._releaseInstanceRefs;

    function _argsFrom(argsLike, start) {
        var args = [];
        for (var i = start || 0; i < argsLike.length; i++) {
            args.push(argsLike[i]);
        }
        return args;
    }

    function _isWrappedJavaObject(value) {
        return value !== null && typeof value === "object"
            && value.__jptr !== undefined;
    }

    function _wrapJavaReturn(value) {
        if (_isWrappedJavaObject(value)) {
            return _wrapJavaObj(value.__jptr, value.__jclass);
        }
        return value;
    }

    function _invokeJavaMethod(jptr, jcls, name, sig, args) {
        return _wrapJavaReturn(
            Java._invokeMethod.apply(Java, [jptr, jcls, name, sig].concat(args))
        );
    }

    function _invokeJavaStaticMethod(jcls, name, sig, args) {
        return _wrapJavaReturn(
            _invokeStaticMethod.apply(Java, [jcls, name, sig].concat(args))
        );
    }

    // 简单的 JNI 签名解析，将 "(IILjava/lang/String;)V" → ["I","I","Ljava/lang/String;"]
    function _parseJniParams(jniSig) {
        var res = [];
        var start = jniSig.indexOf('(') + 1;
        var i = start;
        while (i < jniSig.length && jniSig[i] !== ')') {
            var end = i + 1;
            if (jniSig[i] === 'L') {
                while (end < jniSig.length && jniSig[end] !== ';') end++;
                end++;
            } else if (jniSig[i] === '[') {
                while (end < jniSig.length && jniSig[end] === '[') end++;
                if (end < jniSig.length && jniSig[end] === 'L') {
                    end++;
                    while (end < jniSig.length && jniSig[end] !== ';') end++;
                    end++;
                } else {
                    end++;
                }
            }
            res.push(jniSig.slice(i, end));
            i = end;
        }
        return res;
    }

    // Score a single JS value against a JNI parameter type.
    //   * 返回 >= 0: 兼容，分数越高越精确（用于多 overload 消歧）
    //   * 返回 -1:  不兼容，该 overload 应整体排除
    //
    // 评分原则: 精确匹配 10 > 父类/接口 6~8 > Object 5 > 通用 object 3
    // 数值类型按 JS 值是整数还是浮点分级:
    //   整数 JS number → int(10) > long(9) > short(8) > byte(7) > double(5) > float(4)
    //   浮点 JS number → double(10) > float(9)；整数类型不匹配以避免截断
    // JS 基础类型的对象参数可匹配 Java 装箱类 + 其祖先（Number/Object/Comparable 等）。
    function _scoreJsParam(jsVal, jniType) {
        var t0 = jniType.charAt(0);

        // null / undefined 只能填 L / [ 类型
        if (jsVal === null || jsVal === undefined) {
            return (t0 === 'L' || t0 === '[') ? 5 : -1;
        }

        var jsType = typeof jsVal;

        // --- 基础类型 ---
        if (t0 === 'Z') {
            if (jsType === "boolean") return 10;
            if (jsType === "number") return 6;
            return -1;
        }
        if (t0 === 'C') {
            // char: JS 单字符 string > JS 整数（code point）
            if (jsType === "string" && jsVal.length === 1) return 10;
            if (jsType === "number" && Number.isInteger(jsVal)
                && jsVal >= 0 && jsVal <= 65535) return 7;
            return -1;
        }
        // 整数类型 I/J/S/B
        if (t0 === 'I' || t0 === 'J' || t0 === 'S' || t0 === 'B') {
            if (jsType === "bigint") {
                // BigInt 只允许匹配 long
                return t0 === 'J' ? 10 : -1;
            }
            if (jsType !== "number") return -1;
            // 非整数不允许匹配整数类型（避免截断）
            if (!Number.isInteger(jsVal)) return -1;
            // 范围检查
            if (t0 === 'I') {
                if (jsVal < -2147483648 || jsVal > 2147483647) return -1;
                return 10;  // int 是整数 JS 值的首选
            }
            if (t0 === 'J') return 9;  // long 总能装
            if (t0 === 'S') {
                if (jsVal < -32768 || jsVal > 32767) return -1;
                return 8;
            }
            if (t0 === 'B') {
                if (jsVal < -128 || jsVal > 127) return -1;
                return 7;
            }
        }
        // 浮点类型 F/D
        if (t0 === 'F' || t0 === 'D') {
            if (jsType !== "number") return -1;
            if (Number.isInteger(jsVal)) {
                // 整数 JS 值也能匹配浮点，但分数低于整数类型
                return t0 === 'D' ? 5 : 4;
            }
            return t0 === 'D' ? 10 : 9;
        }

        // --- 数组类型 ---
        if (t0 === '[') {
            if (Array.isArray(jsVal)) return 8;
            if (jsType === "object") return 4;
            return -1;
        }

        // --- L 类型（对象引用）---
        if (t0 === 'L') {
            // JS string → String / CharSequence / Serializable / Object
            // 底层 marshal_js_to_jvalue 对任意 L 参数都能 NewStringUTF，所以放宽到 Object。
            if (jsType === "string") {
                if (jniType === "Ljava/lang/String;") return 10;
                if (jniType === "Ljava/lang/CharSequence;") return 7;
                if (jniType === "Ljava/lang/Comparable;") return 6;
                if (jniType === "Ljava/io/Serializable;") return 6;
                if (jniType === "Ljava/lang/Object;") return 5;
                return -1;
            }

            // JS number → 精确装箱类型 > Number > Object
            // autobox_primitive_to_jobject 根据 sig 精确选 Integer/Long/Float/Double/Short/Byte。
            if (jsType === "number") {
                if (jniType === "Ljava/lang/Integer;") return 10;
                if (jniType === "Ljava/lang/Long;") return 9;
                if (jniType === "Ljava/lang/Double;") return 9;
                if (jniType === "Ljava/lang/Float;") return 8;
                if (jniType === "Ljava/lang/Short;") return 8;
                if (jniType === "Ljava/lang/Byte;") return 7;
                if (jniType === "Ljava/lang/Number;") return 7;
                if (jniType === "Ljava/lang/Comparable;") return 6;
                if (jniType === "Ljava/io/Serializable;") return 6;
                if (jniType === "Ljava/lang/Object;") return 5;
                return -1;
            }

            // JS bigint → Long / Object
            if (jsType === "bigint") {
                if (jniType === "Ljava/lang/Long;") return 10;
                if (jniType === "Ljava/lang/Number;") return 7;
                if (jniType === "Ljava/lang/Object;") return 5;
                return -1;
            }

            // JS boolean → Boolean / Object
            if (jsType === "boolean") {
                if (jniType === "Ljava/lang/Boolean;") return 10;
                if (jniType === "Ljava/lang/Comparable;") return 6;
                if (jniType === "Ljava/io/Serializable;") return 6;
                if (jniType === "Ljava/lang/Object;") return 5;
                return -1;
            }

            // JS object: 可能是 Java wrapper {__jptr,__jclass}，或普通 object
            if (jsType === "object") {
                // 如果是 Java wrapper 且 __jclass 精确匹配 L 类型的内部名
                if (jsVal.__jptr !== undefined && typeof jsVal.__jclass === "string") {
                    var innerName = "L" + jsVal.__jclass.replace(/\./g, "/") + ";";
                    if (innerName === jniType) return 10;
                    // 无法静态判断 isAssignableFrom；对 Object 给通用分
                    if (jniType === "Ljava/lang/Object;") return 5;
                    // 其它类: 先给中间分，运行时 marshal 会按 __jptr 传过去
                    return 4;
                }
                return 3;
            }

            return -1;
        }

        return -1;
    }

    // 兼容性检查（保留旧名字供其它地方调用；内部走评分函数）
    function _isJsValueCompatible(jsVal, jniType) {
        return _scoreJsParam(jsVal, jniType) >= 0;
    }

    function _scoreOverload(methodInfo, jsArgs) {
        var paramTypes = _parseJniParams(methodInfo.sig);
        if (paramTypes.length !== jsArgs.length) {
            return -1;
        }

        var score = 0;
        for (var i = 0; i < paramTypes.length; i++) {
            var s = _scoreJsParam(jsArgs[i], paramTypes[i]);
            if (s < 0) return -1;
            score += s;
        }
        return score;
    }

    function _resolveInstanceMethodSig(jcls, name, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== name || methodInfo.static) {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No instance method found: " + jcls + "." + name);
        }
        if (bestScore < 0) {
            throw new Error("No matching overload for " + jcls + "." + name
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _resolveStaticMethodSig(jcls, name, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== name || !methodInfo.static) {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No static method found: " + jcls + "." + name);
        }
        if (bestScore < 0) {
            throw new Error("No matching static overload for " + jcls + "." + name
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _resolveConstructorSig(jcls, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== "<init>") {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No constructor found: " + jcls);
        }
        if (bestScore < 0) {
            throw new Error("No matching constructor for " + jcls
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    // Instance method invoker.
    //
    // 调用形式（优先级从高到低）:
    //   1. lockedSig 非空（来自 .overload(...)）→ 直接用锁定签名
    //   2. 首参是 "(...)..." → 当场 inline 签名，args.shift() 后当参数用
    //   3. 否则走 _resolveInstanceMethodSig 自动根据参数类型匹配 overload
    //
    // 返回的是**普通 JS function**，因此 Function.prototype.call/apply/bind 原生可用:
    //   svc.method.overload('java.lang.String').call(svc, 'hi')
    //   svc.method.overload('int').apply(svc, [42])
    // 注意: .call 的 thisArg 会被 JS 引擎赋给 `this`，但 invoker 内部闭包已经持有
    // target (__jptr + __jclass)，不读 `this`，所以 thisArg 是形式上的（保持 Frida 语法兼容）。
    function _makeInstanceMethodInvoker(target, name, lockedSig) {
        var invoker = function() {
            var args = _argsFrom(arguments);
            var sig;
            if (lockedSig) {
                sig = lockedSig;
            } else if (typeof args[0] === "string" && args[0].charAt(0) === '(') {
                sig = args.shift();
            } else {
                sig = _resolveInstanceMethodSig(target.__jclass, name, args);
            }
            return _invokeJavaMethod(
                target.__jptr,
                target.__jclass,
                name,
                sig,
                args
            );
        };

        // Frida-兼容 .overload(...) — 返回锁定到指定签名的新 invoker（target 不变）
        invoker.overload = function() {
            var sig = _resolveSingleOverload(target.__jclass, name, arguments, null);
            return _makeInstanceMethodInvoker(target, name, sig);
        };

        return invoker;
    }

    // ========================================================================
    // Frida-style FieldWrapper: obj.field 返回 FieldWrapper，通过 .value 读写
    //   obj.field.value        — 读（每次 JNI GetField，无 FIELD_CACHE 锁）
    //   obj.field.value = x    — 写（每次 JNI SetField，无 FIELD_CACHE 锁）
    // ========================================================================

    // 每个类的字段元数据缓存: cls → { prop → meta{id,sig,st,cls} | null }
    // null 表示已探测过但不是字段（即方法），避免重复 C 调用
    var _classFieldMeta = {};

    function _resolveFieldMeta(cls, prop, objPtr) {
        var cache = _classFieldMeta[cls];
        if (!cache) {
            cache = {};
            _classFieldMeta[cls] = cache;
        }
        if (prop in cache) return cache[prop];
        // 一次性 C 调用：解析 field_id/sig/isStatic，带 runtime class fallback
        var meta = _fieldMeta(cls, prop, objPtr);
        cache[prop] = (meta !== undefined) ? meta : null;
        return cache[prop];
    }

    function FieldWrapper(target, meta) {
        this._t = target;  // Proxy 的 backing {__jptr, __jclass}
        this._m = meta;     // {id: BigUint64, sig: string, st: boolean, cls: string}
    }

    Object.defineProperty(FieldWrapper.prototype, "value", {
        get: function() {
            var m = this._m;
            return _wrapJavaReturn(
                _readField(this._t.__jptr, m.id, m.sig, m.st, m.cls)
            );
        },
        set: function(v) {
            var m = this._m;
            _writeField(this._t.__jptr, m.id, m.sig, m.st, m.cls, v);
        },
        enumerable: true,
        configurable: true
    });

    FieldWrapper.prototype.toString = function() {
        try {
            var v = this.value;
            return String(v);
        } catch(e) {
            return "[FieldWrapper]";
        }
    };

    // ========================================================================
    // 方法名缓存 + hybrid wrapper（处理字段/方法同名冲突）
    // Java 允许同名字段和方法共存，JS 只有一个属性槽。
    // 同名时返回 hybrid：可调用（方法） + .value（字段）
    // ========================================================================

    var _classMethodNames = {};
    function _hasMethod(cls, name) {
        var set = _classMethodNames[cls];
        if (!set) {
            set = {};
            var ms = _methods(cls);
            for (var i = 0; i < ms.length; i++) set[ms[i].name] = true;
            _classMethodNames[cls] = set;
        }
        return !!set[name];
    }

    // 给函数对象挂 .value getter/setter（字段读写）
    function _decorateWithFieldValue(fn, target, meta) {
        Object.defineProperty(fn, "value", {
            get: function() {
                return _wrapJavaReturn(
                    _readField(target.__jptr, meta.id, meta.sig, meta.st, meta.cls)
                );
            },
            set: function(v) {
                _writeField(target.__jptr, meta.id, meta.sig, meta.st, meta.cls, v);
            },
            enumerable: true,
            configurable: true
        });
        return fn;
    }

    // Wrap a raw Java object pointer as a Proxy (Frida-compatible)
    // - 字段访问:   obj.fieldName          → FieldWrapper
    //              obj.fieldName.value     → 读取真实 JVM 值
    //              obj.fieldName.value = x → 写入 JVM 字段
    // - 同名冲突:   obj.name(args)         → 调用方法
    //              obj.name.value          → 读写字段
    // - 方法调用:
    //     1) 显式签名: obj.method("(Ljava/lang/String;)V", "arg")
    //     2) 自动匹配: obj.method("arg")
    // - 快捷调用:   obj.$call("methodName", "(sig)", ...args)
    // 内部：用已存在的 target 创建 Proxy（共享 mutable target 用于"释放"语义）
    function _wrapJavaObjOnTarget(target) {
        var fieldWrappers = {};  // per-instance FieldWrapper 缓存

        var handler = {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                // Rust 内部属性穿透（__origJobject 用于 hook 返回值 round-trip）
                if (prop === "__origJobject") return target.__origJobject;
                if (prop === Symbol.toPrimitive) return function(hint) {
                    if (hint === "string" || hint === "default") {
                        try {
                            return String(_invokeJavaMethod(target.__jptr, target.__jclass, "toString", "()Ljava/lang/String;", []));
                        } catch(e) {}
                    }
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (typeof prop !== "string") return undefined;
                if (prop === "toString") return function() {
                    try {
                        return _invokeJavaMethod(target.__jptr, target.__jclass, "toString", "()Ljava/lang/String;", []);
                    } catch(e) {
                        return "[JavaObject:" + target.__jclass + "]";
                    }
                };
                if (prop === "valueOf") return function() {
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (prop === "$className") return target.__jclass;
                if (prop === "$call") {
                    return function(name, sig) {
                        if (typeof name !== "string" || typeof sig !== "string") {
                            throw new Error("obj.$call(name, sig, ...args) requires (string, string, ...)");
                        }
                        return _invokeJavaMethod(
                            target.__jptr,
                            target.__jclass,
                            name,
                            sig,
                            _argsFrom(arguments, 2)
                        );
                    };
                }

                // 已缓存 — 直接返回（FieldWrapper 或 hybrid 函数）
                if (fieldWrappers[prop]) return fieldWrappers[prop];

                // 解析字段元数据（per-class 缓存，首次走 C，后续纯 JS 查找）
                var meta = _resolveFieldMeta(target.__jclass, prop, target.__jptr);
                if (meta) {
                    var fw;
                    if (_hasMethod(target.__jclass, prop)) {
                        // 同名冲突：hybrid（可调用 + .value）
                        fw = _decorateWithFieldValue(
                            _makeInstanceMethodInvoker(target, prop), target, meta
                        );
                    } else {
                        fw = new FieldWrapper(target, meta);
                    }
                    fieldWrappers[prop] = fw;
                    return fw;
                }

                // 不是字段 → 方法
                return _makeInstanceMethodInvoker(target, prop);
            }
        };
        return new Proxy(target, handler);
    }

    // 公共：从 ptr+cls 直接创建 wrapper（多数路径用这个）
    function _wrapJavaObj(ptr, cls) {
        return _wrapJavaObjOnTarget({__jptr: ptr, __jclass: cls});
    }

    function MethodWrapper(cls, method, sig, cache) {
        this._c = cls;
        this._m = method;
        this._s = sig || null;
        this._cache = cache || null;
    }

    // Convert Java type name to JNI type descriptor (mirrors Rust java_type_to_jni)
    function _jniType(t) {
        switch(t) {
            case "void": case "V": return "V";
            case "boolean": case "Z": return "Z";
            case "byte": case "B": return "B";
            case "char": case "C": return "C";
            case "short": case "S": return "S";
            case "int": case "I": return "I";
            case "long": case "J": return "J";
            case "float": case "F": return "F";
            case "double": case "D": return "D";
            default:
                if (t.charAt(0) === '[') return t.replace(/\./g, "/");
                return "L" + t.replace(/\./g, "/") + ";";
        }
    }

    // 获取方法列表（带缓存）
    function _getMethods(wrapper) {
        if (wrapper._cache && wrapper._cache.methods) return wrapper._cache.methods;
        var ms = _methods(wrapper._c);
        if (wrapper._cache) wrapper._cache.methods = ms;
        return ms;
    }

    // 根据参数签名前缀查找匹配的方法
    function _findOverload(ms, name, paramSig) {
        for (var i = 0; i < ms.length; i++) {
            if (ms[i].name === name && ms[i].sig.indexOf(paramSig) === 0) {
                return ms[i].sig;
            }
        }
        return null;
    }

    // 把 .overload(...) 的参数列表解析为单个 JNI 签名字符串。
    // 两种合法输入:
    //   (a) 单个 "(....)..." raw JNI 签名 → 直接返回
    //   (b) Java 类型名列表 "java.lang.String", "int" → 拼成 "(Ljava/lang/String;I)" 去 _methods 里找唯一匹配
    // 不处理数组批量语法（那是 hook 专用，保留在 MethodWrapper.prototype.overload 里）。
    //
    // methodsCache: 可选的 {methods?: [...]} 对象，命中则复用，否则调 _methods(cls) 并回填。
    function _resolveSingleOverload(cls, name, overloadArgs, methodsCache) {
        // (a) raw JNI signature
        if (overloadArgs.length === 1
            && typeof overloadArgs[0] === "string"
            && overloadArgs[0].charAt(0) === '(') {
            return overloadArgs[0];
        }
        // (b) Java type name list
        var paramSig = "(";
        for (var i = 0; i < overloadArgs.length; i++) {
            paramSig += _jniType(overloadArgs[i]);
        }
        paramSig += ")";
        var ms;
        if (methodsCache && methodsCache.methods) {
            ms = methodsCache.methods;
        } else {
            ms = _methods(cls);
            if (methodsCache) methodsCache.methods = ms;
        }
        var m = name === "$init" ? "<init>" : name;
        var sig = _findOverload(ms, m, paramSig);
        if (!sig) {
            throw new Error("No matching overload: " + cls + "." + name + paramSig);
        }
        return sig;
    }

    // Frida-compatible overload: accepts Java type names as arguments
    // e.g. .overload("java.lang.String", "int") → matches JNI sig "(Ljava/lang/String;I)..."
    // Also accepts raw JNI signature: .overload("(Ljava/lang/String;)I")
    // Also accepts arrays for multiple overloads: .overload(["int","int"], ["java.lang.String"])
    MethodWrapper.prototype.overload = function() {
        // Case 1: 数组语法，选择多个overload（hook 专用）
        if (arguments.length >= 1 && Array.isArray(arguments[0])) {
            var ms = _getMethods(this);
            var name = this._m === "$init" ? "<init>" : this._m;
            var sigs = [];
            for (var a = 0; a < arguments.length; a++) {
                var params = arguments[a];
                var paramSig = "(";
                for (var i = 0; i < params.length; i++) {
                    paramSig += _jniType(params[i]);
                }
                paramSig += ")";
                var sig = _findOverload(ms, name, paramSig);
                if (!sig) {
                    throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
                }
                sigs.push(sig);
            }
            return new MethodWrapper(this._c, this._m, sigs, this._cache);
        }
        // Case 2/3: 单一 overload（raw JNI 签名或 Java 类型名）— 走共享 helper
        var resolved = _resolveSingleOverload(this._c, this._m, arguments, this._cache);
        return new MethodWrapper(this._c, this._m, resolved, this._cache);
    };

    Object.defineProperty(MethodWrapper.prototype, "impl", {
        get: function() { return this._fn || null; },
        set: function(fn) {
            var name = this._m === "$init" ? "<init>" : this._m;
            var cls = this._c;

            // 确定要hook的签名列表
            var sigs;
            if (this._s === null) {
                // 未指定overload：hook所有overload
                var ms = _getMethods(this);
                var match = [];
                for (var i = 0; i < ms.length; i++) {
                    if (ms[i].name === name) match.push(ms[i]);
                }
                if (match.length === 0)
                    throw new Error("Method not found: " + cls + "." + this._m);
                sigs = match.map(function(m) { return m.sig; });
            } else if (Array.isArray(this._s)) {
                // 通过数组语法指定的多个overload
                sigs = this._s;
            } else {
                // 单个overload
                sigs = [this._s];
            }

            if (fn === null || fn === undefined) {
                for (var i = 0; i < sigs.length; i++) {
                    _unhook(cls, name, sigs[i]);
                }
                this._fn = null;
            } else {
                var userFn = fn;
                var wrapCallback = function(ctx) {
                    if (ctx.thisObj !== undefined) {
                        ctx.thisObj = _wrapJavaObj(ctx.thisObj, cls);
                    }
                    if (ctx.args) {
                        for (var i = 0; i < ctx.args.length; i++) {
                            var a = ctx.args[i];
                            if (a !== null && typeof a === "object"
                                && a.__jptr !== undefined) {
                                ctx.args[i] = _wrapJavaObj(a.__jptr, a.__jclass);
                            }
                        }
                    }
                    // Wrap orig so returned objects auto-convert to JS Proxy
                    var origCallOriginal = ctx.orig;
                    ctx.orig = function() {
                        var ret = origCallOriginal.apply(ctx, arguments);
                        if (ret !== null && typeof ret === "object"
                            && ret.__jptr !== undefined) {
                            return _wrapJavaObj(ret.__jptr, ret.__jclass);
                        }
                        return ret;
                    };
                    return userFn(ctx);
                };
                for (var i = 0; i < sigs.length; i++) {
                    _hook(cls, name, sigs[i], wrapCallback);
                }
                this._fn = fn;
            }
        }
    });

    function _invokeStaticWrapper(wrapper, argsLike) {
        var args = _argsFrom(argsLike);
        var sig;

        if (wrapper._s === null) {
            sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveStaticMethodSig(wrapper._c, wrapper._m, args);
        } else if (Array.isArray(wrapper._s)) {
            throw new Error("Cannot invoke multiple overloads at once: "
                + wrapper._c + "." + wrapper._m);
        } else {
            sig = wrapper._s;
        }

        return _invokeJavaStaticMethod(
            wrapper._c,
            wrapper._m === "$init" ? "<init>" : wrapper._m,
            sig,
            args
        );
    }

    function _invokeConstructorWrapper(wrapper, argsLike) {
        var args = _argsFrom(argsLike);
        var sig;

        if (wrapper._s === null) {
            sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveConstructorSig(wrapper._c, args);
        } else if (Array.isArray(wrapper._s)) {
            throw new Error("Cannot invoke multiple constructor overloads at once: "
                + wrapper._c + "." + wrapper._m);
        } else {
            sig = wrapper._s;
        }

        return _wrapJavaReturn(
            _newObject.apply(Java, [wrapper._c, sig].concat(args))
        );
    }

    function _bindMethodWrapper(wrapper) {
        var callable = function() {
            if (wrapper._m === "$init") {
                return _invokeConstructorWrapper(wrapper, arguments);
            }
            return _invokeStaticWrapper(wrapper, arguments);
        };

        callable.overload = function() {
            return _bindMethodWrapper(MethodWrapper.prototype.overload.apply(wrapper, arguments));
        };

        Object.defineProperty(callable, "impl", {
            get: function() {
                return wrapper.impl;
            },
            set: function(fn) {
                wrapper.impl = fn;
            },
            enumerable: true,
            configurable: true
        });

        return callable;
    }

    Java.use = function(cls) {
        var cache = {};
        var wrappers = {};
        var staticFieldWrappers = {};
        // 静态字段用虚拟 target（_readField/isStatic=true 时 objPtr 被忽略）
        var staticTarget = {__jptr: 0, __jclass: cls};
        return new Proxy({}, {
            get: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                // $className: 返回类名字符串（与 instance proxy 对称）
                // 不走字段/方法查找，避免被当作同名 Java 成员
                if (prop === "$className") return cls;
                // class: Frida 兼容语法糖，返回 java.lang.Class 实例包装器
                //
                // 使用 Java._findClassObject（内部 find_class_safe）而非 Class.forName，原因：
                //   - forName(String) 用 caller 的 ClassLoader；agent 线程 caller 是 native，
                //     解析出来的是 system loader，看不到 app 私有类（alipay bundle 更甚）
                //   - find_class_safe 会优先走 rustFrida 缓存的 app ClassLoader.loadClass，
                //     与 Java.use 的类查找路径完全一致，保证"能 Java.use 就能 .class"
                if (prop === "class") {
                    if (!cache._class) {
                        try {
                            cache._class = _wrapJavaReturn(_findClassObject(cls));
                        } catch (e) {
                            throw new Error(
                                "Java.use('" + cls + "').class: _findClassObject failed: "
                                + (e && e.message ? e.message : e)
                            );
                        }
                    }
                    return cache._class;
                }
                if (prop === "$new") {
                    if (!cache._new) {
                        cache._new = function() {
                            var args = _argsFrom(arguments);
                            var sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                                ? args.shift()
                                : _resolveConstructorSig(cls, args);
                            return _wrapJavaReturn(
                                _newObject.apply(Java, [cls, sig].concat(args))
                            );
                        };
                    }
                    return cache._new;
                }
                // 静态字段检查（per-class 缓存，仅首次走 C 调用）
                if (staticFieldWrappers[prop]) return staticFieldWrappers[prop];
                var meta = _resolveFieldMeta(cls, prop, 0);
                if (meta && meta.st) {
                    var fw;
                    if (_hasMethod(cls, prop)) {
                        // 同名冲突：方法可调用 + .value 读写静态字段
                        if (!wrappers[prop]) {
                            wrappers[prop] = _bindMethodWrapper(new MethodWrapper(cls, prop, null, cache));
                        }
                        fw = _decorateWithFieldValue(wrappers[prop], staticTarget, meta);
                    } else {
                        fw = new FieldWrapper(staticTarget, meta);
                    }
                    staticFieldWrappers[prop] = fw;
                    return fw;
                }
                // 方法
                if (!wrappers[prop]) {
                    wrappers[prop] = _bindMethodWrapper(new MethodWrapper(cls, prop, null, cache));
                }
                return wrappers[prop];
            },
            ownKeys: function(_) {
                if (cache._ownKeys) return cache._ownKeys;
                var ms = _methods(cls);
                var seen = {};
                var keys = [];
                keys.push("$new");
                for (var i = 0; i < ms.length; i++) {
                    var n = ms[i].name === "<init>" ? "$init" : ms[i].name;
                    if (!seen[n]) { seen[n] = true; keys.push(n); }
                }
                cache._ownKeys = keys;
                return keys;
            },
            getOwnPropertyDescriptor: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                return {enumerable: true, configurable: true};
            }
        });
    };

    // ========================================================================
    // Java.ready(fn) — 延迟到 app dex 加载后执行
    //
    // spawn 模式下脚本在 setArgV0 阶段加载，此时 app ClassLoader 还未创建，
    // FindClass 只能找到 framework 类。Java.ready() 通过 hook 框架类
    // Instrumentation.newApplication (ClassLoader 作为第一个参数传入) 来检测
    // dex 加载完成，在 Application.attachBaseContext 之前触发用户回调。
    //
    // 非 spawn 模式（attach 已运行的进程）时 ClassLoader 已就绪，立即执行。
    // ========================================================================
    var _readyCallbacks = [];
    var _readyFired = false;
    var _readyGateSig = "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)Landroid/app/Application;";

    Java.ready = function(fn) {
        if (typeof fn !== "function") {
            throw new Error("Java.ready() requires a function argument");
        }

        // ClassLoader 已就绪（非 spawn / 已触发过），立即执行
        if (_readyFired || Java._isClassLoaderReady()) {
            _readyFired = true;
            fn();
            return;
        }

        // 首个注册：安装 gate hook
        if (_readyCallbacks.length === 0) {
            _hook("android/app/Instrumentation", "newApplication", _readyGateSig, function(ctx) {
                // 先执行原始 newApplication。stealth2/recomp 下如果在编译方法入口
                // offset 0 就触发 FindClass/WalkStack，ART 可能在 GetDexPc/StackMap
                // 路径上看到当前 quick frame native_pc=0 并 abort。
                // 将 ClassLoader 更新和 ready 回调后置，避开“当前被 hook 编译帧”
                // 仍停在入口 PC 的窗口。
                var app = ctx.orig();

                // 从第一个参数获取 ClassLoader 并更新缓存
                if (ctx.args && ctx.args[0] !== null && ctx.args[0] !== undefined) {
                    var clPtr = ctx.args[0];
                    if (typeof clPtr === "object" && clPtr.__jptr !== undefined) {
                        clPtr = clPtr.__jptr;
                    }
                    Java._updateClassLoader(clPtr);
                }

                // 执行所有排队的回调 — 用户可在此安装 hook
                // 注意：用户可能重新 hook newApplication，所以先保存 orig 引用
                _readyFired = true;
                var cbs = _readyCallbacks;
                _readyCallbacks = [];
                for (var i = 0; i < cbs.length; i++) {
                    try {
                        cbs[i]();
                    } catch(e) {
                        console.log("[Java.ready] callback #" + i + " error: " + e);
                    }
                }

                return app;
            });
        }

        _readyCallbacks.push(fn);
    };

    Java.classLoaders = function() {
        return _classLoaders();
    };

    function _normalizeLoaderArg(loader) {
        if (loader !== null && typeof loader === "object") {
            if (loader.ptr !== undefined) {
                return loader.ptr;
            }
            if (loader.__jptr !== undefined) {
                return loader.__jptr;
            }
        }
        return loader;
    }

    Java.findClassWithLoader = function(loader, className) {
        if (typeof className !== "string") {
            throw new Error("Java.findClassWithLoader(loader, className) requires a string className");
        }
        return _findClassWithLoader(_normalizeLoaderArg(loader), className);
    };

    Java.setClassLoader = function(loader) {
        return _setClassLoader(_normalizeLoaderArg(loader));
    };

    // ========================================================================
    // Java.choose(className, {onMatch, onComplete}) — Frida 兼容
    //
    // 枚举 ART heap 上指定类（默认精确匹配，subtypes:true 含子类）的所有存活实例，
    // 每个实例自动包装为 Proxy（可直接 .method()/.field.value）。
    //
    // callbacks:
    //   onMatch(instance): 对每个 instance 触发；返回 "stop" 提前结束。
    //   onComplete(): 枚举结束（或被 stop）后触发，可选。
    //   subtypes: bool — 是否包含子类（rustFrida 扩展，Frida 无此参数）
    //   maxCount: int — 最多枚举多少实例。默认 16384，防止 String 这类高频类
    //                  瞬间填满 JNI global ref table。0 表示不限。
    //
    // **生命周期**：传给 onMatch 的 wrapper 仅在 onMatch 执行期间有效。函数返回
    // 后我们会立即 DeleteGlobalRef，wrapper.__jptr 被置 0。如果你想把实例存到
    // 全局变量，**必须**在 onMatch 内自己 NewGlobalRef（或调 obj.toString() 提前
    // 拷贝你需要的字段值）。这与 Frida 行为一致。
    // ========================================================================
    var DEFAULT_MAX_COUNT = 16384;
    Java.choose = function(className, callbacks, includeSubtypes) {
        if (typeof className !== "string" || className.length === 0) {
            throw new Error("Java.choose(className, callbacks) requires a non-empty string className");
        }
        if (!callbacks || typeof callbacks !== "object") {
            throw new Error("Java.choose(className, callbacks) requires a callbacks object");
        }
        var onMatch = callbacks.onMatch;
        var onComplete = callbacks.onComplete;
        if (typeof onMatch !== "function") {
            throw new Error("Java.choose: callbacks.onMatch must be a function");
        }

        // 接受第三参（位置）或 callbacks.subtypes
        var sub = includeSubtypes === true || callbacks.subtypes === true;

        // maxCount 语义（防 "0=无限扫全部" foot-gun）：
        //   未传 / 非数字 / 等于 0 → DEFAULT_MAX_COUNT (16384) 安全默认
        //   正整数 N → 最多 N 个实例
        //   Infinity 或负数 → native 0 = **显式** 不限（escape hatch，自负其责）
        //
        // 设计动机：launcher 等常驻进程里 String 实例 50K+，"0=无限" 会瞬间
        // 填满 JNI IndirectReferenceTable (默认上限 51200) → 目标进程 abort。
        // 无限扫描得由用户显式 opt-in (Infinity / 负数)。
        var mc = callbacks.maxCount;
        var maxCount;
        if (typeof mc !== "number" || mc === 0) {
            maxCount = DEFAULT_MAX_COUNT;
        } else if (mc === Infinity || mc < 0) {
            maxCount = 0; // native 侧 0 = 不限
        } else {
            maxCount = mc;
        }

        var raw = _enumerateInstances(className, !!sub, maxCount);
        // 我们给每个 wrapped 用单独 target 对象，并保留引用 —— release 时把 __jptr
        // 置 0 让 wrapper 即使被 onMatch 保存到外部也立即变成"空指针"，访问其方法
        // 会拿到 jptr=0，而不是 dangling 的 stale handle。
        var liveTargets = [];
        try {
            for (var i = 0; i < raw.length; i++) {
                var entry = raw[i];
                if (!entry || entry.__jptr === undefined || entry.__jptr === 0n
                        || entry.__jptr === 0) continue;
                var target = {__jptr: entry.__jptr, __jclass: entry.__jclass || className};
                liveTargets.push(target);
                var wrapped = _wrapJavaObjOnTarget(target);
                var ret;
                try {
                    ret = onMatch(wrapped);
                } catch (e) {
                    console.log("[Java.choose] onMatch(" + i + ") error: " + e);
                    continue;
                }
                if (ret === "stop") break;
            }
        } finally {
            // 1) 释放 native global refs
            try { _releaseInstanceRefs(raw); }
            catch (e) { console.log("[Java.choose] release error: " + e); }
            // 2) 把所有用户可能保存的 wrapper 的 __jptr 都置 0，断绝 dangling 访问
            for (var k = 0; k < liveTargets.length; k++) {
                liveTargets[k].__jptr = 0;
            }
        }

        if (typeof onComplete === "function") {
            try { onComplete(); }
            catch (e) { console.log("[Java.choose] onComplete error: " + e); }
        }
    };
})();
