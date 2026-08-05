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
    var _methodListCache = Object.create(null);
    var _classLoaderListCache = null;
    var _directHookImpls = Object.create(null);
    var _directHookBypass = Object.create(null);
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
        if (value === null || value === undefined) return value;
        if (_isWrappedJavaObject(value)) {
            return _wrapJavaObj(
                value.__jptr,
                value.__jclass,
                value.__jraw === true,
                value.__jglobal === true
            );
        }
        // Rust marshal 把 Java 对象数组自动转 JS Array, 元素为裸 {__jptr, __jclass}。
        // 这里递归把每个元素包成 Proxy, 让 `arr[i].method()` 和嵌套数组访问都生效。
        if (Array.isArray(value)) {
            for (var i = 0; i < value.length; i++) {
                value[i] = _wrapJavaReturn(value[i]);
            }
        }
        return value;
    }

    function _invokeJavaMethod(jtarget, jcls, name, sig, args) {
        return _wrapJavaReturn(
            Java._invokeMethod.apply(Java, [jtarget, jcls, name, sig].concat(args))
        );
    }

    function _invokeJavaStaticMethod(jcls, name, sig, args) {
        return _wrapJavaReturn(
            _invokeStaticMethod.apply(Java, [jcls, name, sig].concat(args))
        );
    }

    function _methodKey(cls, name, sig) {
        return cls + "." + name + sig;
    }

    function _withDirectHookBypass(key, fn) {
        _directHookBypass[key] = (_directHookBypass[key] || 0) + 1;
        try {
            return fn();
        } finally {
            var n = (_directHookBypass[key] || 1) - 1;
            if (n > 0) _directHookBypass[key] = n;
            else delete _directHookBypass[key];
        }
    }

    function _withDirectHookBypassMany(keys, fn) {
        for (var i = 0; i < keys.length; i++) {
            _directHookBypass[keys[i]] = (_directHookBypass[keys[i]] || 0) + 1;
        }
        try {
            return fn();
        } finally {
            for (var j = 0; j < keys.length; j++) {
                var key = keys[j];
                var n = (_directHookBypass[key] || 1) - 1;
                if (n > 0) _directHookBypass[key] = n;
                else delete _directHookBypass[key];
            }
        }
    }

    function _throwWithMessageStack(e) {
        if (e && e.stack && e.message) {
            var message = String(e);
            var stack = String(e.stack);
            if (stack.indexOf(message) < 0) {
                try {
                    e.stack = message + "\n" + stack;
                } catch (_) {}
            }
        }
        throw e;
    }

    function _maybeInvokeDirectInstanceHook(target, cls, name, sig, args, fallback) {
        var key = _methodKey(cls, name, sig);
        var fn = _directHookImpls[key];
        if (!fn || _directHookBypass[key]) return fallback();

        var orig = function() {
            var origArgs = arguments.length ? _argsFrom(arguments) : args;
            return _withDirectHookBypass(key, function() {
                return _invokeJavaMethod(target, cls, name, sig, origArgs);
            });
        };
        var thisObj = _wrapJavaObjOnTarget({
            __jptr: target.__jptr,
            __jclass: target.__jclass,
            __jraw: target.__jraw === true,
            __jglobal: target.__jglobal === true,
            __$orig: orig
        });
        var ret = _withDirectHookBypass(key, function() {
            return fn.apply(thisObj, args);
        });
        return _wrapJavaReturn(ret);
    }

    function _maybeInvokeDirectStaticHook(cls, name, sig, args, fallback) {
        var key = _methodKey(cls, name, sig);
        var fn = _directHookImpls[key];
        if (!fn || _directHookBypass[key]) return fallback();

        var orig = function() {
            var origArgs = arguments.length ? _argsFrom(arguments) : args;
            return _withDirectHookBypass(key, function() {
                return _invokeJavaStaticMethod(cls, name, sig, origArgs);
            });
        };
        var fnThis = {
            $orig: orig,
            $className: cls,
            $static: true
        };
        var ret = _withDirectHookBypass(key, function() {
            return fn.apply(fnThis, args);
        });
        return _wrapJavaReturn(ret);
    }

    function _getMethodList(jcls) {
        var cached = _methodListCache[jcls];
        if (cached) return cached;
        cached = _methods(jcls);
        _methodListCache[jcls] = cached;
        return cached;
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
            if (Array.isArray(jsVal)) {
                var elem = jniType.charAt(1);
                // 嵌套数组: 每个 JS 元素递归按内层 sig 评分, 取最小
                if (elem === '[') {
                    if (jsVal.length === 0) return 6;
                    var innerSig = jniType.slice(1);
                    var minScore = 10;
                    for (var k = 0; k < jsVal.length; k++) {
                        var s = _scoreJsParam(jsVal[k], innerSig);
                        if (s < 0) return -1;
                        if (s < minScore) minScore = s;
                    }
                    return minScore;
                }
                // 引用类型数组 [Ljava/xxx;
                if (elem === 'L') {
                    var innerSig = jniType.slice(1);
                    // String[]: JS array of strings 完美匹配
                    if (innerSig === "Ljava/lang/String;") {
                        if (jsVal.length === 0) return 8;
                        var allStr = true;
                        for (var k = 0; k < jsVal.length; k++) {
                            if (typeof jsVal[k] !== "string") { allStr = false; break; }
                        }
                        if (allStr) return 10;
                    }
                    // 通用 [Lxxx;: 每个元素递归按内层 L 评分
                    if (jsVal.length === 0) return 6;
                    var minScore = 10;
                    for (var k = 0; k < jsVal.length; k++) {
                        var s = _scoreJsParam(jsVal[k], innerSig);
                        if (s < 0) return -1;
                        if (s < minScore) minScore = s;
                    }
                    // 对象数组总体比原始数组分数略低 (让 primitive 数组优先命中)
                    return Math.max(minScore - 1, 4);
                }
                // 原始类型数组: 按元素实际范围选最精确的类型
                return _scoreArrayElements(jsVal, elem);
            }
            if (jsType === "object" && jsVal.__jptr !== undefined) {
                // Java 数组对象 {__jptr, __jclass="[B"/...} 透传
                if (typeof jsVal.__jclass === "string" && jsVal.__jclass === jniType) return 10;
                return 5;
            }
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

    // 按数组元素实际范围给 JS array vs Java 原始数组打分。
    // 分数高低指示该 overload 对给定 JS 数据的精确度:
    //   [1,2,3] 完美装 byte[] (10) 也能装 int[] (8), 选 byte[];
    //   [1,200,3] 只能装 int[] (8), 选 int[];
    //   [1n,2n] 装 long[] (10);
    //   [true,false] 装 boolean[] (10).
    // 返回 -1 表示该数组元素与目标类型不兼容 (例: bigint 不能进 int[])。
    function _scoreArrayElements(arr, elem) {
        if (arr.length === 0) {
            // 空数组: 无法区分元素类型, 按 Java 类型常用度优先
            return elem === 'I' ? 10 : elem === 'J' ? 9
                 : elem === 'S' ? 8 : elem === 'B' ? 7
                 : elem === 'D' ? 7 : elem === 'F' ? 6
                 : elem === 'Z' ? 8 : elem === 'C' ? 8 : 4;
        }
        // 逐元素分类:
        //   allIntNumber: 全是 JS number 且都是整数
        //   allBigInt:    全是 bigint
        //   allLongLike:  允许 JS int + bigint 混合 (都能进 long)
        //   allBool:      全是 boolean
        //   allChar1:     全是单字符 string
        //   allFloatLike: 全是 JS number 且含非整数
        // 以及整数值的范围 byte/short/int (只在 allIntNumber 时有意义)
        var allIntNumber = true, allBigInt = true, allLongLike = true;
        var allBool = true, allChar1 = true, allFloatLike = true;
        var hasFloat = false, hasInt = false, hasBigInt = false;
        var allInByte = true, allInShort = true, allInInt = true;
        for (var i = 0; i < arr.length; i++) {
            var v = arr[i];
            var t = typeof v;
            if (t === "boolean") {
                allIntNumber = allBigInt = allLongLike = allChar1 = allFloatLike = false;
                continue;
            }
            if (t === "bigint") {
                allIntNumber = allBool = allChar1 = allFloatLike = false;
                hasBigInt = true;
                continue;
            }
            if (t === "string") {
                allIntNumber = allBigInt = allLongLike = allBool = allFloatLike = false;
                if (v.length !== 1) allChar1 = false;
                continue;
            }
            if (t !== "number") return -1;
            allBool = allBigInt = allChar1 = false;
            if (!Number.isInteger(v)) {
                allIntNumber = allLongLike = false;
                hasFloat = true;
                continue;
            }
            hasInt = true;
            allFloatLike = false;
            if (v < -128 || v > 127) allInByte = false;
            if (v < -32768 || v > 32767) allInShort = false;
            if (v < -2147483648 || v > 2147483647) allInInt = false;
        }
        if (elem === 'Z') return allBool ? 10 : -1;
        if (elem === 'C') return allChar1 ? 10 : (allIntNumber && allInShort ? 7 : -1);
        if (elem === 'B') return allIntNumber && allInByte ? 10 : -1;
        if (elem === 'S') return allIntNumber && allInShort ? 9 : -1;
        if (elem === 'I') return allIntNumber && allInInt ? 8 : -1;
        if (elem === 'J') {
            // long[]: 纯 bigint 最佳 10; bigint+int 混合 9; 纯 int 降级 7
            if (allBigInt) return 10;
            if (allLongLike && hasBigInt) return 9;
            if (allIntNumber) return 7;
            return -1;
        }
        if (elem === 'F') {
            if (hasFloat && !hasBigInt) return 6;
            if (allIntNumber) return 4;
            return -1;
        }
        if (elem === 'D') {
            if (hasFloat && !hasBigInt) return 7;
            if (allIntNumber) return 5;
            return -1;
        }
        return 4;
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
        var methods = _getMethodList(jcls);
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
        var methods = _getMethodList(jcls);
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
        var methods = _getMethodList(jcls);
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
            return _maybeInvokeDirectInstanceHook(
                target,
                target.__jclass,
                name,
                sig,
                args,
                function() {
                    return _invokeJavaMethod(
                        target,
                        target.__jclass,
                        name,
                        sig,
                        args
                    );
                }
            );
        };

        // Frida-兼容 .overload(...) — 返回锁定到指定签名的新 invoker（target 不变）
        invoker.overload = function() {
            var sig = _resolveSingleOverload(target.__jclass, name, arguments, null);
            return _makeInstanceMethodInvoker(target, name, sig);
        };

        return invoker;
    }

    function _makeHookOriginalInvoker(target, name) {
        var invoker = function() {
            return target.__$orig.apply(target, arguments);
        };
        invoker.overload = function() {
            var sig = _resolveSingleOverload(target.__$hookClass || target.__jclass, name, arguments, null);
            if (target.__$hookSig && sig !== target.__$hookSig) {
                return _makeInstanceMethodInvoker(target, name, sig);
            }
            return _makeHookOriginalInvoker(target, name);
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
    // 用 Object.create(null) 避免 "toString"/"valueOf" 等名字命中 Object.prototype
    var _classFieldMeta = Object.create(null);

    function _resolveFieldMeta(cls, prop, objPtr) {
        var cache = _classFieldMeta[cls];
        if (!cache) {
            cache = Object.create(null);
            _classFieldMeta[cls] = cache;
        }
        if (prop in cache) return cache[prop];
        // 一次性 C 调用：解析 field_id/sig/isStatic，带 runtime class fallback
        var meta = _fieldMeta(cls, prop, objPtr);
        cache[prop] = (meta !== undefined) ? meta : null;
        return cache[prop];
    }

    function _cachedFieldMeta(cls, prop) {
        var cache = _classFieldMeta[cls];
        if (!cache || !(prop in cache)) return undefined;
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
                _readField(this._t.__jptr, m.id, m.sig, m.st, m.cls, this._t.__jglobal === true)
            );
        },
        set: function(v) {
            var m = this._m;
            _writeField(this._t.__jptr, m.id, m.sig, m.st, m.cls, v, this._t.__jglobal === true);
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

    var _classMethodNames = Object.create(null);
    function _hasMethod(cls, name) {
        var set = _classMethodNames[cls];
        if (!set) {
            set = Object.create(null);
            var ms = _getMethodList(cls);
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
                    _readField(target.__jptr, meta.id, meta.sig, meta.st, meta.cls, target.__jglobal === true)
                );
            },
            set: function(v) {
                _writeField(target.__jptr, meta.id, meta.sig, meta.st, meta.cls, v, target.__jglobal === true);
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
        var fieldWrappers = Object.create(null);  // per-instance FieldWrapper 缓存 (无原型, 避 toString 等名冲突)
        var isArray = typeof target.__jclass === "string" && target.__jclass[0] === "[";

        var handler = {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                if (prop === "__jraw") return target.__jraw === true;
                if (prop === "__jglobal") return target.__jglobal === true;
                // Rust 内部属性穿透（__origJobject 用于 hook 返回值 round-trip）
                if (prop === "__origJobject") return target.__origJobject;
                // Frida-compat hook invocation accessor（仅当 target 由 wrapCallback 注入时存在）
                if (prop === "$orig") return target.__$orig;
                if (prop === Symbol.toPrimitive) return function(hint) {
                    if (hint === "string" || hint === "default") {
                        if (isArray) {
                            try {
                                var n = Java._arrayLength(target.__jptr, target.__jglobal === true);
                                return "[" + target.__jclass + " length=" + n + "]";
                            } catch(e) {}
                        }
                        try {
                            return String(_invokeJavaMethod(target, target.__jclass, "toString", "()Ljava/lang/String;", []));
                        } catch(e) {}
                    }
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (typeof prop === "symbol") return undefined;

                // Java 数组特殊路径：`.length` + 数字索引 → JNI array op
                if (isArray) {
                    if (prop === "length") {
                        return Java._arrayLength(target.__jptr, target.__jglobal === true);
                    }
                    // 数字索引 (prop 可能是字符串 "0" 或实际数字转来的 string)
                    if (typeof prop === "string" && /^\d+$/.test(prop)) {
                        return Java._arrayGet(target.__jptr, +prop, target.__jclass, target.__jglobal === true);
                    }
                    // toString 特殊: 让 JS side 显示一个简略摘要
                    if (prop === "toString") return function() {
                        var n = Java._arrayLength(target.__jptr, target.__jglobal === true);
                        return "[" + target.__jclass + " length=" + n + "]";
                    };
                    // 其他 prop 走通用路径（可能是 Object 方法比如 hashCode）
                }
                if (typeof prop !== "string") return undefined;
                if (prop === "toString") return function() {
                    try {
                        return _maybeInvokeDirectInstanceHook(
                            target,
                            target.__jclass,
                            "toString",
                            "()Ljava/lang/String;",
                            [],
                            function() {
                                return _invokeJavaMethod(
                                    target,
                                    target.__jclass,
                                    "toString",
                                    "()Ljava/lang/String;",
                                    []
                                );
                            }
                        );
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
                            target,
                            target.__jclass,
                            name,
                            sig,
                            _argsFrom(arguments, 2)
                        );
                    };
                }
                if (target.__$orig && prop === target.__$hookName) {
                    return _makeHookOriginalInvoker(target, prop);
                }

                // 已缓存 — 直接返回（FieldWrapper 或 hybrid 函数）
                if (fieldWrappers[prop]) return fieldWrappers[prop];

                var cachedMeta = _cachedFieldMeta(target.__jclass, prop);
                if (cachedMeta !== undefined) {
                    if (cachedMeta === null) {
                        return _makeInstanceMethodInvoker(target, prop);
                    }
                    var cachedFw;
                    if (_hasMethod(target.__jclass, prop)) {
                        cachedFw = _decorateWithFieldValue(
                            _makeInstanceMethodInvoker(target, prop), target, cachedMeta
                        );
                    } else {
                        cachedFw = new FieldWrapper(target, cachedMeta);
                    }
                    fieldWrappers[prop] = cachedFw;
                    return cachedFw;
                }

                // 解析字段元数据（per-class 缓存，首次走 C，后续纯 JS 查找）。
                // raw clone worker 上字段访问不能先枚举方法；方法枚举可能需要按类名
                // 扫 Class mirror，字段路径可用当前对象直接定位 klass_。
                var meta = _resolveFieldMeta(target.__jclass, prop, target.__jptr);
                if (meta) {
                    var fw;
                    if (_hasMethod(target.__jclass, prop)) {
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
    function _wrapJavaObj(ptr, cls, raw, globalRef) {
        return _wrapJavaObjOnTarget({
            __jptr: ptr,
            __jclass: cls,
            __jraw: raw === true,
            __jglobal: globalRef === true
        });
    }

    function MethodWrapper(cls, method, sig, cache) {
        this._c = cls;
        this._m = method;
        this._s = sig || null;
        this._cache = cache || null;
        this._dslBuff = undefined;
    }

    // Convert Java type name to JNI type descriptor (mirrors Rust java_type_to_jni)
    function _jniType(t) {
        t = String(t).replace(/^\s+|\s+$/g, "");
        var dims = 0;
        while (t.slice(-2) === "[]") {
            dims++;
            t = t.slice(0, -2).replace(/^\s+|\s+$/g, "");
        }
        var base;
        switch(t) {
            case "void": case "V": base = "V"; break;
            case "boolean": case "Z": base = "Z"; break;
            case "byte": case "B": base = "B"; break;
            case "char": case "C": base = "C"; break;
            case "short": case "S": base = "S"; break;
            case "int": case "I": base = "I"; break;
            case "long": case "J": base = "J"; break;
            case "float": case "F": base = "F"; break;
            case "double": case "D": base = "D"; break;
            default:
                if (t.charAt(0) === '[') base = t.replace(/\./g, "/");
                else if (t.charAt(0) === "L" && t.charAt(t.length - 1) === ";") base = t.replace(/\./g, "/");
                else base = "L" + t.replace(/\./g, "/") + ";";
                break;
        }
        if (dims === 0) return base;
        if (base === "V") throw new Error("void[] is not a valid Java type");
        var prefix = "";
        for (var i = 0; i < dims; i++) prefix += "[";
        return prefix + base;
    }

    // 获取方法列表（带缓存）
    function _getMethods(wrapper) {
        if (wrapper._cache && wrapper._cache.methods) return wrapper._cache.methods;
        var ms = _getMethodList(wrapper._c);
        if (wrapper._cache) wrapper._cache.methods = ms;
        return ms;
    }

    function _getMethodListCached(cls, cache) {
        if (cache && cache.methods) return cache.methods;
        var ms = _getMethodList(cls);
        if (cache) cache.methods = ms;
        return ms;
    }

    function _isStaticMethodSig(cls, name, sig, cache) {
        var ms = _getMethodListCached(cls, cache);
        for (var i = 0; i < ms.length; i++) {
            if (ms[i].name === name && ms[i].sig === sig) {
                return ms[i].static === true;
            }
        }
        return false;
    }

    function _compileSigForMethod(cls, name, sig, cache) {
        return (_isStaticMethodSig(cls, name, sig, cache) ? "static:" : "") + sig;
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
            ms = _getMethodList(cls);
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
                    delete _directHookImpls[_methodKey(cls, name, sigs[i])];
                }
                this._fn = null;
            } else {
                var userFn = fn;
                var bypassKeys = sigs.map(function(sig) {
                    return _methodKey(cls, name, sig);
                });
                // wrapCallback 的 ctx 是 Rust 侧注入的内部 hook-ctx 对象，
                // 保留用于 origCallOriginal.apply(ctx, ...) 让 js_call_original 读到
                // __hookCtxPtr / __hookArtMethod，用户层不再可见。
                var makeWrapCallback = function(hookSig) {
                    return function(ctx) {
                    // Wrap args → JS Proxy for Java objects, 其它原样
                    var rawArgs = ctx.args || [];
                    var wrappedArgs = new Array(rawArgs.length);
                    for (var i = 0; i < rawArgs.length; i++) {
                        var a = rawArgs[i];
                        wrappedArgs[i] = (a !== null && typeof a === "object"
                            && a.__jptr !== undefined)
                            ? _wrapJavaObj(a.__jptr, a.__jclass, a.__jraw === true, a.__jglobal === true)
                            : a;
                    }
                    // Wrap orig 使返回的 Java 对象自动转 Proxy
                    var origCallOriginal = ctx.orig;
                    var origWrapped = function() {
                        var ret = origCallOriginal.apply(ctx, arguments);
                        if (ret !== null && typeof ret === "object"
                            && ret.__jptr !== undefined) {
                            return _wrapJavaObj(ret.__jptr, ret.__jclass, ret.__jraw === true, ret.__jglobal === true);
                        }
                        return ret;
                    };

                    // Frida-style: this = thisObj (instance) 或 class wrapper (static)
                    // arguments = Java 方法参数
                    var thisObjRaw = ctx.thisObj;
                    var fnThis;
                    if (thisObjRaw !== undefined) {
                        // 实例方法: 新建 Proxy target 携带 $orig
                        fnThis = _wrapJavaObjOnTarget({
                            __jptr: thisObjRaw,
                            __jclass: cls,
                            __$orig: origWrapped,
                            __$hookClass: cls,
                            __$hookName: name,
                            __$hookSig: hookSig
                        });
                    } else {
                        // 静态方法: 简单对象 + Frida-style 入口
                        fnThis = {
                            $orig: origWrapped,
                            $className: cls,
                            $static: true
                        };
                    }
                    return _withDirectHookBypassMany(bypassKeys, function() {
                        return userFn.apply(fnThis, wrappedArgs);
                    });
                    };
                };
                for (var i = 0; i < sigs.length; i++) {
                    _hook(cls, name, sigs[i], makeWrapCallback(sigs[i]));
                    _directHookImpls[_methodKey(cls, name, sigs[i])] = userFn;
                }
                this._fn = fn;
            }
        }
    });
    Object.defineProperty(MethodWrapper.prototype, "implementation", {
        get: function() { return this.impl; },
        set: function(fn) { this.impl = fn; }
    });

    Object.defineProperty(MethodWrapper.prototype, "dslImpl", {
        get: function() { return this._dslCode || null; },
        set: function(code) {
            var name = this._m === "$init" ? "<init>" : this._m;
            var cls = this._c;
            var dslCode = code;
            var inlineBuff = undefined;
            if (code !== null && code !== undefined && typeof code === "object") {
                inlineBuff = code.buff;
                if (code.code !== undefined) {
                    dslCode = code.code;
                } else if (code.dsl !== undefined) {
                    dslCode = code.dsl;
                } else if (code.script !== undefined) {
                    dslCode = code.script;
                } else {
                    throw new Error("dslImpl object requires code/dsl/script");
                }
            }
            var buff = inlineBuff !== undefined ? inlineBuff : this._dslBuff;

            var sigs;
            if (this._s === null) {
                var ms = _getMethods(this);
                var match = [];
                for (var i = 0; i < ms.length; i++) {
                    if (ms[i].name === name) match.push(ms[i]);
                }
                if (match.length === 0)
                    throw new Error("Method not found: " + cls + "." + this._m);
                sigs = match.map(function(m) { return m.sig; });
            } else if (Array.isArray(this._s)) {
                sigs = this._s;
            } else {
                sigs = [this._s];
            }

            if (code === null || code === undefined) {
                for (var i = 0; i < sigs.length; i++) {
                    _unhook(cls, name, sigs[i]);
                }
                this._dslCode = null;
                this._dslInfo = null;
            } else {
                if (this._dslInfo !== null && this._dslInfo !== undefined) {
                    for (var i = 0; i < sigs.length; i++) {
                        _unhook(cls, name, sigs[i]);
                    }
                    this._dslCode = null;
                    this._dslInfo = null;
                }
                var results = [];
                var installed = [];
                try {
                    for (var i = 0; i < sigs.length; i++) {
                        var opts = {
                            className: cls,
                            methodName: name,
                            signature: sigs[i],
                            dsl: String(dslCode)
                        };
                        if (buff !== undefined) opts.buff = buff;
                        results.push(Java.managedHookDsl(opts));
                        installed.push(sigs[i]);
                    }
                } catch (e) {
                    for (var j = 0; j < installed.length; j++) {
                        try { _unhook(cls, name, installed[j]); } catch (_) {}
                    }
                    _throwWithMessageStack(e);
                }
                this._dslCode = String(dslCode);
                this._dslInfo = results.length === 1 ? results[0] : results;
            }
        }
    });

    Object.defineProperty(MethodWrapper.prototype, "buff", {
        get: function() {
            return this._dslBuff;
        },
        set: function(value) {
            this._dslBuff = value;
        }
    });

    MethodWrapper.prototype.dsl = function(options) {
        if (options === null || options === undefined) {
            return this;
        }
        if (typeof options !== "object") {
            throw new Error("dsl options must be an object");
        }
        if (options.buff !== undefined) {
            this._dslBuff = options.buff;
        }
        return this;
    };

    MethodWrapper.prototype.opt = function(kind) {
        var name = this._m === "$init" ? "<init>" : this._m;
        var cls = this._c;
        var compileKind = "auto";
        if (kind !== null && kind !== undefined) {
            if (typeof kind === "object") {
                compileKind = kind.kind || kind.mode || "auto";
            } else {
                compileKind = kind;
            }
        }

        var sigs;
        if (this._s === null) {
            var ms = _getMethods(this);
            var match = [];
            for (var i = 0; i < ms.length; i++) {
                if (ms[i].name === name) match.push(ms[i]);
            }
            if (match.length === 0)
                throw new Error("Method not found: " + cls + "." + this._m);
            sigs = match.map(function(m) { return m.sig; });
        } else if (Array.isArray(this._s)) {
            sigs = this._s;
        } else {
            sigs = [this._s];
        }

        var results = [];
        for (var j = 0; j < sigs.length; j++) {
            results.push(Java.compileMethod(
                cls,
                name,
                _compileSigForMethod(cls, name, sigs[j], this._cache),
                String(compileKind)
            ));
        }
        return results.length === 1 ? results[0] : results;
    };

    MethodWrapper.prototype.compile = MethodWrapper.prototype.opt;

    Object.defineProperty(MethodWrapper.prototype, "dslInfo", {
        get: function() { return this._dslInfo || null; }
    });

    MethodWrapper.prototype.dslDrain = function(max) {
        if (!this._dslInfo) {
            return [];
        }
        return max === undefined
            ? Java.managedDrainMessages(this._dslInfo)
            : Java.managedDrainMessages(this._dslInfo, max);
    };

    function _dslInfoList(info) {
        if (!info) return [];
        return Array.isArray(info) ? info : [info];
    }

    function _invertDslMessages(messages) {
        var byCode = Object.create(null);
        if (!messages) return byCode;
        for (var name in messages) {
            if (Object.prototype.hasOwnProperty.call(messages, name)) {
                byCode[String(messages[name])] = name;
            }
        }
        return byCode;
    }

    MethodWrapper.prototype.dslRead = function(nameOrMax, max) {
        if (!this._dslInfo) {
            return [];
        }
        var filterName = typeof nameOrMax === "string" ? nameOrMax : null;
        var limit = filterName ? max : nameOrMax;
        var infos = _dslInfoList(this._dslInfo);
        var out = [];
        for (var i = 0; i < infos.length; i++) {
            var info = infos[i];
            var byCode = _invertDslMessages(info.messages);
            var items = limit === undefined
                ? Java.managedDrainMessages(info)
                : Java.managedDrainMessages(info, limit);
            for (var j = 0; j < items.length; j++) {
                var item = items[j];
                var channel = byCode[String(item.code)] || String(item.code);
                if (filterName && channel !== filterName) {
                    continue;
                }
                if (filterName) {
                    out.push(item.value);
                } else {
                    item.name = channel;
                    out.push(item);
                }
            }
        }
        return out;
    };

    MethodWrapper.prototype.dslTake = function(name, max) {
        if (typeof name !== "string") {
            throw new Error("dslTake(name[, max]) requires a channel name");
        }
        return this.dslRead(name, max);
    };

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

        var name = wrapper._m === "$init" ? "<init>" : wrapper._m;
        return _maybeInvokeDirectStaticHook(
            wrapper._c,
            name,
            sig,
            args,
            function() {
                return _invokeJavaStaticMethod(
                    wrapper._c,
                    name,
                    sig,
                    args
                );
            }
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
        Object.defineProperty(callable, "implementation", {
            get: function() {
                return wrapper.impl;
            },
            set: function(fn) {
                wrapper.impl = fn;
            },
            enumerable: true,
            configurable: true
        });

        Object.defineProperty(callable, "dslImpl", {
            get: function() {
                return wrapper.dslImpl;
            },
            set: function(code) {
                wrapper.dslImpl = code;
            },
            enumerable: true,
            configurable: true
        });

        Object.defineProperty(callable, "dslInfo", {
            get: function() {
                return wrapper.dslInfo;
            },
            enumerable: true,
            configurable: true
        });

        Object.defineProperty(callable, "buff", {
            get: function() {
                return wrapper.buff;
            },
            set: function(value) {
                wrapper.buff = value;
            },
            enumerable: true,
            configurable: true
        });

        callable.dsl = function(options) {
            wrapper.dsl(options);
            return callable;
        };

        callable.opt = function(kind) {
            return wrapper.opt(kind);
        };

        callable.compile = function(kind) {
            return wrapper.opt(kind);
        };

        callable.dslDrain = function(max) {
            return wrapper.dslDrain(max);
        };

        callable.dslRead = function(nameOrMax, max) {
            return wrapper.dslRead(nameOrMax, max);
        };

        callable.dslTake = function(name, max) {
            return wrapper.dslTake(name, max);
        };

        return callable;
    }

    Java.use = function(cls) {
        // Object.create(null) 避免 "toString" / "valueOf" / "hasOwnProperty" 等
        // Object.prototype 方法名被当作"已缓存"命中, 错返 Object.prototype.toString
        var cache = Object.create(null);
        var wrappers = Object.create(null);
        var staticFieldWrappers = Object.create(null);
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
                        var callable = function() {
                            var args = _argsFrom(arguments);
                            var sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                                ? args.shift()
                                : _resolveConstructorSig(cls, args);
                            return _wrapJavaReturn(
                                _newObject.apply(Java, [cls, sig].concat(args))
                            );
                        };
                        // Frida 兼容 .overload(typeName, ...) — 锁定构造函数签名
                        callable.overload = function() {
                            var sig;
                            if (arguments.length === 1
                                && typeof arguments[0] === "string"
                                && arguments[0].charAt(0) === '(') {
                                sig = arguments[0];
                            } else {
                                var paramSig = "(";
                                for (var i = 0; i < arguments.length; i++) {
                                    paramSig += _jniType(arguments[i]);
                                }
                                paramSig += ")";
                                var ms = _getMethodList(cls);
                                var found = _findOverload(ms, "<init>", paramSig);
                                if (!found) {
                                    throw new Error("No matching constructor: "
                                        + cls + paramSig);
                                }
                                sig = found;
                            }
                            return function() {
                                var args = _argsFrom(arguments);
                                return _wrapJavaReturn(
                                    _newObject.apply(Java, [cls, sig].concat(args))
                                );
                            };
                        };
                        cache._new = callable;
                    }
                    return cache._new;
                }
                // 静态字段检查（per-class 缓存，仅首次走 C 调用）。raw clone
                // pre-resume 阶段不能为了字段消歧等待 Java executor，否则
                // Java.ready 的 framework gate 可能在装好前就被 resume 越过。
                if (!_isRawCloneJsThread()) {
                    if (staticFieldWrappers[prop]) return staticFieldWrappers[prop];
                    var meta = _resolveFieldMeta(cls, prop, 0);
                    if (meta && meta.st) {
                        var fw;
                        if (_hasMethod(cls, prop)) {
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
                }
                // 方法
                if (!wrappers[prop]) {
                    wrappers[prop] = _bindMethodWrapper(new MethodWrapper(cls, prop, null, cache));
                }
                return wrappers[prop];
            },
            ownKeys: function(_) {
                if (cache._ownKeys) return cache._ownKeys;
                var ms = _getMethodList(cls);
                var seen = Object.create(null);
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
    var _readyCallAppSig = "(Landroid/app/Application;)V";
    var _gateInstalled = false;

    function _isRawCloneJsThread() {
        try {
            return Java._isRawCloneJsThread && Java._isRawCloneJsThread();
        } catch (_) {
            return false;
        }
    }

    function _callReadyCallback(fn, index) {
        try {
            fn();
        } catch(e) {
            console.log("[Java.ready] callback #" + index + " error: " + e);
        }
    }

    function _fireReadyCallbacks() {
        if (_readyFired) return;
        _readyFired = true;
        var cbs = _readyCallbacks;
        _readyCallbacks = [];
        for (var i = 0; i < cbs.length; i++) {
            _callReadyCallback(cbs[i], i);
        }
    }

    Java._installGateHook = function() {
        if (_gateInstalled) return;
        try {
            var Inst = Java.use("android.app.Instrumentation");
            Inst.newApplication.overload(_readyGateSig).impl = function(classLoader, className, context) {
                var app = this.$orig(classLoader, className, context);

                if (classLoader !== null && classLoader !== undefined) {
                    var clPtr = classLoader;
                    if (typeof clPtr === "object" && clPtr.__jptr !== undefined) {
                        clPtr = clPtr.__jptr;
                    }
                    Java._updateClassLoader(clPtr);
                }

                _fireReadyCallbacks();

                return app;
            };
            Inst.callApplicationOnCreate.overload(_readyCallAppSig).impl = function(app) {
                if (app !== null && app !== undefined) {
                    try {
                        var cl = app.getClass().getClassLoader();
                        var clPtr = cl;
                        if (typeof clPtr === "object" && clPtr.__jptr !== undefined) {
                            clPtr = clPtr.__jptr;
                        }
                        Java._updateClassLoader(clPtr);
                    } catch (_) {}
                }
                _fireReadyCallbacks();
                return this.$orig(app);
            };
            _gateInstalled = true;
        } catch(e) {
            console.log("[Java.ready] gate hook install failed: " + e);
            if (_isRawCloneJsThread()) {
                try {
                    if (Java._cutRawCloneExecutorHook) {
                        Java._cutRawCloneExecutorHook();
                    }
                } catch (_) {}
                throw e;
            }
        }
    };

    Java._flushReadyCallbacks = function() {
        if (_isRawCloneJsThread()) {
            return;
        }
        if (!_readyFired && !Java._isClassLoaderReady()) {
            try {
                if (Java._reprobeClassLoaderOnce && Java._reprobeClassLoaderOnce()) {
                    _readyFired = true;
                }
            } catch (_) {}
            if (!_readyFired && !Java._isClassLoaderReady()) {
                return;
            }
        }

        _readyFired = true;
        var cbs = _readyCallbacks;
        _readyCallbacks = [];
        for (var i = 0; i < cbs.length; i++) {
            _callReadyCallback(cbs[i], i);
        }
    };

    Java.ready = function(fn) {
        if (typeof fn !== "function") {
            throw new Error("Java.ready() requires a function argument");
        }

        if (_readyFired || Java._isClassLoaderReady()) {
            _readyFired = true;
            _readyCallbacks.push(fn);
            return;
        }

        if (_isRawCloneJsThread()) {
            var installRawGate = _readyCallbacks.length === 0;
            _readyCallbacks.push(fn);
            if (installRawGate) {
                Java._installGateHook();
            }
            return;
        }

        try {
            if (Java._reprobeClassLoaderOnce && Java._reprobeClassLoaderOnce()) {
                _readyFired = true;
                _readyCallbacks.push(fn);
                return;
            }
        } catch (_) {}

        var installGate = _readyCallbacks.length === 0;
        _readyCallbacks.push(fn);
        if (installGate) {
            Java._installGateHook();
        }
    };

    function _getClassLoaders() {
        if (_classLoaderListCache === null) {
            _classLoaderListCache = _classLoaders();
        }
        return _classLoaderListCache;
    }

    Java.classLoaders = function() {
        return _getClassLoaders();
    };

    Java.enumerateClassLoadersSync = function() {
        return _getClassLoaders();
    };

    Java.enumerateClassLoaders = function(callbacks) {
        if (!callbacks || typeof callbacks !== "object") {
            throw new Error("Java.enumerateClassLoaders(callbacks) requires a callbacks object");
        }
        if (callbacks.onMatch !== undefined && typeof callbacks.onMatch !== "function") {
            throw new Error("Java.enumerateClassLoaders: callbacks.onMatch must be a function");
        }
        if (callbacks.onComplete !== undefined && typeof callbacks.onComplete !== "function") {
            throw new Error("Java.enumerateClassLoaders: callbacks.onComplete must be a function");
        }

        var loaders = _getClassLoaders();
        for (var i = 0; i < loaders.length; i++) {
            if (callbacks.onMatch && callbacks.onMatch(loaders[i]) === "stop") {
                break;
            }
        }
        if (callbacks.onComplete) {
            callbacks.onComplete();
        }
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

    var _executorHookInstalled = false;
    Java.installExecutorHook = function() {
        if (_executorHookInstalled) return true;
        try {
            if (Java._installExecutorHook && Java._installExecutorHook()) {
                _executorHookInstalled = true;
                return true;
            }
        } catch (_) {}
        try {
            if (Java._initArtController && Java._initArtController()) {
                _executorHookInstalled = true;
                return true;
            }
        } catch (e) {
            return false;
        }
        return false;
    };

    try { Java.installExecutorHook(); } catch (_) {}

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
                var target = {
                    __jptr: entry.__jptr,
                    __jclass: entry.__jclass || className,
                    __jraw: entry.__jraw === true,
                    __jglobal: entry.__jglobal === true
                };
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
