# rustFrida

ARM64 Android 动态插桩框架。

## 环境要求

- Android NDK 25+（默认路径 `~/Android/Sdk/ndk/`）
- Rust toolchain + `aarch64-linux-android` target
- Python 3（构建 loader shellcode）
- `.cargo/config.toml` 已配置交叉编译（仓库自带）

## 构建

最终产物 `rustfrida` 通过 `include_bytes!` 内嵌了 loader shellcode 和 agent SO，有严格的**构建顺序**：

```
loader shellcode  ──┐
                    ├──→  rustfrida (主程序)
agent (libagent.so) ┘
```

### 1. 构建 loader shellcode（bootstrapper + rustfrida-loader）

```bash
python3 build_helpers.py
# 输出:
#   loader/build/bootstrapper.bin
#   loader/build/rustfrida-loader.bin
```

loader 是 bare-metal ARM64 shellcode，被 `rustfrida` 通过 `include_bytes!` 嵌入。**修改 loader C 代码后需重新运行此步。**

### 2. 构建 agent（libagent.so）

```bash
cargo build -p agent --release
# 输出: target/aarch64-linux-android/release/libagent.so
```

agent 是注入到目标进程的动态库，包含 hook 引擎、QuickJS、Java hook 等。**必须先于 rustfrida 构建**，因为 rustfrida 通过 `include_bytes!` 嵌入 agent SO。

### 3. 构建 rustfrida（主程序）

```bash
cargo build -p rust_frida --release
# 输出: target/aarch64-linux-android/release/rustfrida
```

rustfrida 内嵌了 `bootstrapper.bin` + `rustfrida-loader.bin` + `libagent.so`，是一个自包含的单文件。

### 可选组件（单独构建）

这些不在 default-members 里，按需构建：

**QBDI Trace 支持：** 需要先构建 qbdi-helper SO，再用 `--features qbdi` 编译 agent 和 rustfrida：

```bash
cargo build -p qbdi-helper --release           # → libqbdi_helper.so
cargo build -p agent --release --features qbdi  # agent 启用 qbdi feature
cargo build -p rust_frida --release --features qbdi  # rustfrida 嵌入 qbdi-helper SO
```

**eBPF SO 加载监控（`--watch-so`）：** ldmonitor 是 rustfrida 的编译依赖，默认构建已包含，`--watch-so` 无需额外步骤。如需独立使用 ldmonitor 命令行工具：

```bash
cargo build -p ldmonitor --release    # → ldmonitor 独立二进制
```

## 部署 & 运行

```bash
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/

# PID 注入
./rustfrida --pid <pid>
./rustfrida --pid <pid> -l script.js

# Spawn 模式（启动时注入）
./rustfrida --spawn com.example.app
./rustfrida --spawn com.example.app -l script.js

# 等待 SO 加载后注入（eBPF）
./rustfrida --watch-so libnative.so

# 详细日志
./rustfrida --pid <pid> --verbose
```

### REPL 命令

```
jsinit              # 初始化 JS 引擎
jseval <expr>       # 求值表达式
loadjs <script>     # 执行脚本
jsrepl              # 交互式 REPL（Tab 补全）
exit                # 退出
```

---

## HTTP RPC 远程调用

脚本里用 Frida 风格的 `rpc.exports` 注册方法，host 端通过 HTTP POST 调用，返回值会 `JSON.stringify` 后透传回来。适合把 agent 当成一个常驻服务用——UI、自动化脚本、测试框架都可以直接 `curl` 触发。

### 启动

在 legacy 单会话或 `--server` 多会话模式下，加上 `--rpc-port` 即可启动 HTTP 服务器。参数可以是纯端口号（默认绑 `0.0.0.0`），也可以是完整地址：

```bash
# legacy 模式：attach + 加载脚本 + 开 RPC 端口
./rustfrida --pid 1234 -l rpc_test.js --rpc-port 9191

# server 模式：多 session 共享同一个 RPC 端口，按 session id 路由
./rustfrida --server --rpc-port 127.0.0.1:9191

# 本机访问通过 adb forward 最简单
adb forward tcp:9191 tcp:9191
```

### JS 侧注册

```js
// 整体替换
rpc.exports = {
    ping: function() { return "pong"; },
    add: function(a, b) { return a + b; },
    echo: function(obj) { return { received: obj, ts: Date.now() }; },

    // 读取当前 App 的 package name + label
    getAppName: function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        var ctx = app.getApplicationContext();
        var pm = ctx.getPackageManager();
        return {
            packageName: String(ctx.getPackageName()),
            label: String(pm.getApplicationLabel(ctx.getApplicationInfo())),
        };
    }
};

// 或者单独追加
rpc.export('version', function() { return "1.0.0"; });
```

`rpc.exports` 就是个普通 JS 对象，**现场 lookup，不需要向 host 注册方法列表**——你可以任意时刻增删改，下一次 HTTP 请求立刻生效。

### HTTP 路由

| 方法 | 路径 | Body | 说明 |
| --- | --- | --- | --- |
| `GET` | `/` / `/health` | — | 健康检查 |
| `GET` | `/sessions` | — | 列出所有 session（id/pid/label/status）|
| `POST` | `/rpc/<session>/<method>` | JSON 数组 | 调用 `rpc.exports[method].apply(null, args)`；空 body 等价 `[]` |

`<session>` 在 legacy 模式下固定为 `0`，在 `--server` 模式下对应 `list` 命令显示的 id。

### 调用示例

```bash
# 简单调用
curl -X POST http://127.0.0.1:9191/rpc/0/ping
# → {"ok":true,"result":"pong"}

# 位置参数（JSON 数组）
curl -X POST http://127.0.0.1:9191/rpc/0/add -d '[3,4]'
# → {"ok":true,"result":7}

# 对象参数
curl -X POST http://127.0.0.1:9191/rpc/0/echo -d '[{"foo":1,"bar":"hi"}]'
# → {"ok":true,"result":{"received":{"foo":1,"bar":"hi"},"ts":1775806588866}}

# Java 集成
curl -X POST http://127.0.0.1:9191/rpc/0/getAppName
# → {"ok":true,"result":{"packageName":"com.android.settings","label":"设置"}}

# 列出 session
curl http://127.0.0.1:9191/sessions
# → [{"id":0,"pid":1234,"label":"PID:1234","status":"connected"}]
```

成功响应统一是 `{"ok":true,"result":<value>}`；失败是 `{"ok":false,"error":"<msg>"}`，HTTP 状态码 400（参数错）/404（session/method 不存在）/503（session 未连接）/500（JS 异常或超时）。

### 行为约束

- **返回值必须 JSON-safe**：`JSON.stringify` 在 JS 侧执行，函数/循环引用/`undefined` 会被跳过。直接 `return` 一个 Java wrapper 只会得到指针字面量——请手动 `String(obj.method())` 或构造 plain object。
- **并发串行化**：同一 session 内 HTTP 请求排队执行；跨 session 完全并行。
- **超时 30 秒**：超时返回 `{"ok":false,"error":"rpc call timed out"}`。长耗时任务请改用轮询接口。
- **仅同步**：不支持 `async` / Promise——Promise 会被 `JSON.stringify` 成 `{}`。

---

## JS API 参考

### 全局对象一览

`console`, `ptr()`, `Memory`, `Module`, `hook()`, `unhook()`, `callNative()`, `qbdi`, `Java`, `Jni`

### 常用类型别名

| 类型名 | 实际含义 |
| --- | --- |
| `AddressLike` | `NativePointer \| number \| bigint \| "0x..."` |
| `NativePointer` | `ptr()` 创建的指针对象 |
| `JavaObjectProxy` | `Java.use()` / Java hook 中返回的 Java 对象代理 |

### 结构体 / 上下文对象

```ts
type ModuleInfo = {
  name: string; base: NativePointer; size: number; path: string
}

type NativeHookContext = {
  x0 ~ x30: number | bigint    // ARM64 通用寄存器
  sp: number | bigint
  pc: number | bigint
  trampoline: number | bigint
  orig(): number | bigint       // 调用原函数，返回值写入 x0
}

type JavaHookContext = {
  thisObj?: JavaObjectProxy     // 实例方法的 this（静态方法无）
                                // 字段: thisObj.field.value 读/写
                                // 方法: thisObj.method(args) 调用
  args: any[]                   // 参数数组（Object 参数自动包装为 Proxy）
  env: number | bigint          // JNIEnv*
  orig(...args: any[]): any     // 调原方法，不传参用原始参数
}

type JniEntry = { name: string; index: number; address: NativePointer }

type JNINativeMethodInfo = {
  address: NativePointer; namePtr: NativePointer; sigPtr: NativePointer
  fnPtr: NativePointer; name: string | null; sig: string | null
}
```

---

## Native Hook

```js
// 基本 hook — 透传
hook(Module.findExportByName("libc.so", "open"), function(ctx) {
    console.log("open:", Memory.readCString(ptr(ctx.x0)));
    return ctx.orig();
});

// 修改返回值
hook(Module.findExportByName("libc.so", "getpid"), function(ctx) {
    ctx.orig();
    return 12345;              // 调用方拿到 12345
});

// 修改参数 — 通过 ctx 属性
hook(target, function(ctx) {
    ctx.x0 = ptr("0x1234");   // 改第一个参数
    ctx.x1 = 100;             // 改第二个参数
    return ctx.orig();         // 用修改后的参数调原函数
});

// 修改参数 — 通过 orig() 传参（按顺序覆盖 x0-xN）
hook(target, function(ctx) {
    return ctx.orig(ptr("0x1234"), 100);
});

// 不 return 也行 — ctx.x0 赋值会同步回 C 层
hook(Module.findExportByName("libc.so", "getuid"), function(ctx) {
    ctx.orig();
    ctx.x0 = 77777;           // 调用方拿到 77777
});

// 移除 hook
unhook(Module.findExportByName("libc.so", "open"));

// 直接调用 native 函数（最多 6 个参数，走 x0-x5）
var pid = callNative(Module.findExportByName("libc.so", "getpid"));
```

### NativeFunction（任意签名调用）

Frida 兼容 API，任意参数数量（寄存器用完自动栈溢出，上限 256 个栈参数）。

```js
var open = new NativeFunction(
    Module.findExportByName("libc.so", "open"),
    "int",                            // 返回类型
    ["pointer", "int"]                // 参数类型
);
var fd = open(Memory.allocUtf8String("/tmp/foo"), 0);

var atan2 = new NativeFunction(
    Module.findExportByName("libm.so", "atan2"),
    "double",
    ["double", "double"]
);
atan2(1.0, 2.0);
```

**支持的类型**：`void`, `bool`, `char`/`uchar`, `int8`/`uint8`, `short`/`ushort`, `int16`/`uint16`, `int`/`uint`, `int32`/`uint32`, `long`/`ulong` (64-bit), `int64`/`uint64`, `size_t`/`ssize_t`, `pointer`, `float`, `double`。

AAPCS64 调用约定：整数/指针先填 x0-x7，浮点先填 d0-d7（两队列独立），超出部分自动压栈。不支持 struct-by-value。

### Memory 堆分配

```js
var buf = Memory.alloc(128);                 // 分配 128 字节 RWX 内存 → NativePointer
var str = Memory.allocUtf8String("hello");   // 分配并写入 UTF-8 字符串 → NativePointer
```

### Stealth 模式

```js
hook(target, callback, Hook.NORMAL)     // 0: mprotect 直写（默认）
hook(target, callback, Hook.WXSHADOW)   // 1: 内核 shadow 页，/proc/mem 不可见
hook(target, callback, Hook.RECOMP)     // 2: 代码页重编译，仅 4B patch
hook(target, callback, 1)               // 数字也行
hook(target, callback, true)            // true = WXSHADOW
```

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `hook(target, callback, stealth?)` | `AddressLike, Function, number?` | `boolean` |
| `unhook(target)` | `AddressLike` | `boolean` |
| `callNative(func, ...args)` | `AddressLike, ...AddressLike` (最多6个) | `number \| bigint` |
| `new NativeFunction(addr, retType, argTypes)` | `AddressLike, string, string[]` | `Function` (可调用，任意签名) |
| `Memory.alloc(size)` | `number` | `NativePointer` (RWX 堆内存) |
| `Memory.allocUtf8String(s)` | `string` | `NativePointer` |
| `diagAllocNear(addr)` | `AddressLike` | `undefined` |

---

## Java Hook

```js
Java.ready(function() {
    var Activity = Java.use("android.app.Activity");

    // hook 实例方法（return 值就是方法返回值）
    Activity.onResume.impl = function(ctx) {
        console.log("onResume:", ctx.thisObj.$className);
        return ctx.orig();
    };

    // hook 构造函数
    var MyClass = Java.use("com.example.MyClass");
    MyClass.$init.impl = function(ctx) {
        console.log("new MyClass, arg0 =", ctx.args[0]);
        return ctx.orig();
    };

    // 修改参数
    MyClass.test.impl = function(ctx) {
        return ctx.orig("patched_arg");
    };

    // 指定 overload（Java 类型名或 JNI 签名都行）
    MyClass.foo.overload("int", "java.lang.String").impl = function(ctx) {
        return ctx.orig();
    };

    // 移除 hook
    Activity.onResume.impl = null;
});
```

### Java.use 对象操作

```js
var JString = Java.use("java.lang.String");
var s = JString.$new("hello");     // 创建对象
console.log(s.length());           // 调实例方法
console.log(s.$className);         // 类名

var Process = Java.use("android.os.Process");
console.log(Process.myPid());      // 调静态方法
```

### 字段访问（Frida 兼容 .value 模式）

字段通过 `.value` 读写，每次直接走 JNI，无缓存锁：

```js
// 静态字段
var Build = Java.use("android.os.Build");
console.log(Build.MODEL.value);          // 读: "Pixel 6"
Build.MODEL.value = "FakeModel";         // 写

// 实例字段（hook 回调中 / $new 创建的对象）
var Point = Java.use("android.graphics.Point");
var p = Point.$new(10, 20);
console.log(p.x.value, p.y.value);      // 读: 10, 20
p.x.value = 100;                         // 写: JVM 同步更新
console.log(p.toString());               // "Point(100, 20)"

// hook 中访问 this 字段
Activity.onResume.impl = function(ctx) {
    var name = ctx.thisObj.mComponent.value;  // 读实例字段
    console.log("resuming:", name);
    return ctx.orig();
};
```

**字段/方法同名**：Java 允许同名字段和方法共存。此时返回 hybrid——既可调用（方法）又有 `.value`（字段）：

```js
var map = HashMap.$new();
map.size();        // 调用 size() 方法
map.size.value;    // 读取 size 字段
```

### Java.ready

Spawn 模式下 app ClassLoader 未就绪，用 `Java.ready` 延迟执行。PID 注入模式下立即执行。

### Java.choose 枚举存活实例（Frida 兼容）

扫描 ART 堆，把目标类的所有存活实例交给 `onMatch`：

```js
Java.choose("android.app.Activity", {
    onMatch: function(instance) {
        console.log(instance.$className, "=>", instance.toString());
        // return "stop";   // 提前终止
    },
    onComplete: function() { console.log("done"); },
    subtypes: true,         // 包含子类（rustFrida 扩展）
    maxCount: 1000          // 最多枚举数量，默认 16384；0 = 不限
});

// 第三参等价 subtypes（位置参数形式）
Java.choose("java.util.List", { onMatch: fn }, true);
```

**生命周期**：传给 `onMatch` 的 wrapper **仅在 onMatch 执行期间有效**。函数返回后 `__jptr` 被置 0。若要跨回调保留实例，请在 `onMatch` 内调 `String(obj.method())` 拷字段，或自行 `NewGlobalRef`。

**后端**：Android ≤13 走 `VMDebug.getInstancesOfClasses`；API 36 自动降级为堆暴力扫描。

### ClassLoader 控制

```js
var loaders = Java.classLoaders();             // → 数组: app + boot + system
Java.setClassLoader(loaders[0]);               // 切换 Java.use() 查找上下文
var MyCls = Java.findClassWithLoader(loaders[0], "com.example.MyClass");
```

`loader` 参数接受 loader 对象、`{__jptr}` wrapper 或 `NativePointer`。Spawn 模式下 app loader 就绪前 `Java.classLoaders()` 可能只返回 boot loader，应在 `Java.ready()` 里调。

### Stealth 模式（Java hook）

```js
Java.setStealth(0);  // Normal: mprotect 直写
Java.setStealth(1);  // WxShadow: shadow 页，CRC 校验不可见
Java.setStealth(2);  // Recomp: 代码页重编译
Java.getStealth();   // 查询当前模式 (0/1/2)
```

须在 `Java.use().impl` 之前设置。

### Deopt API

```js
Java.deopt();                  // 清空 JIT 缓存（InvalidateAllMethods）
Java.deoptimizeBootImage();    // boot image AOT 降级为 interpreter (API >= 26)
Java.deoptimizeEverything();   // 全局强制解释执行
Java.deoptimizeMethod("com.example.Test", "foo", "(I)V");  // 单方法降级
```

手动调用的工具函数，hook 流程不自动使用。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Java.use(className)` | `string` | `JavaClassWrapper` |
| `Class.$new(...args)` | 任意 | `JavaObjectProxy` |
| `Class.method.impl = fn` | `(ctx: JavaHookContext) => any` | setter |
| `Class.method.impl = null` | — | setter |
| `Class.method.overload(...types)` | `string...` | `MethodWrapper` |
| `Java.ready(fn)` | `() => void` | `void` |
| `Java.choose(cls, callbacks, subtypes?)` | `string, {onMatch,onComplete?,subtypes?,maxCount?}, bool?` | `void` |
| `Java.classLoaders()` | — | `LoaderInfo[]` |
| `Java.findClassWithLoader(loader, cls)` | `Loader, string` | `JavaClassWrapper` |
| `Java.setClassLoader(loader)` | `Loader` | — |
| `Java.deopt()` | — | `boolean` |
| `Java.deoptimizeBootImage()` | — | `boolean` |
| `Java.deoptimizeEverything()` | — | `boolean` |
| `Java.deoptimizeMethod(cls, method, sig)` | `string, string, string` | `boolean` |
| `Java.setStealth(mode)` | `number (0/1/2)` | — |
| `Java.getStealth()` | — | `number` |
| `obj.field.value` | — | `any` (读字段) |
| `obj.field.value = x` | — | — (写字段) |
| `Java.getField(objPtr, cls, field, sig)` | `AddressLike, string, string, string` | `any` (低层 API) |

---

## JNI API

```js
Jni.addr("RegisterNatives")       // → NativePointer
Jni.FindClass                     // 属性直接取地址
Jni.find("FindClass")             // → { name, index, address }
Jni.table                         // 整张 JNI 函数表
Jni.addr(envPtr, "FindClass")     // 指定 JNIEnv
```

### Jni.helper

```js
Jni.helper.env.ptr                         // 当前线程 JNIEnv*
Jni.helper.env.getClassName(jclass)        // → "android.app.Activity"
Jni.helper.env.getObjectClassName(jobject)  // → 对象的类名
Jni.helper.env.readJString(jstring)        // → JS string
Jni.helper.env.getObjectClass(obj)         // → jclass
Jni.helper.env.getSuperclass(clazz)        // → jclass
Jni.helper.env.isSameObject(a, b)          // → boolean
Jni.helper.env.isInstanceOf(obj, clazz)    // → boolean
Jni.helper.env.exceptionCheck()            // → boolean
Jni.helper.env.exceptionClear()

Jni.helper.structs.JNINativeMethod.readArray(addr, count)  // → JNINativeMethodInfo[]
Jni.helper.structs.jvalue.readArray(addr, typesOrSig)      // → any[]
```

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Jni.addr(name)` | `string` | `NativePointer` |
| `Jni.addr(env, name)` | `AddressLike, string` | `NativePointer` |
| `Jni.find(name)` | `string` | `JniEntry` |
| `Jni.entries()` | — | `JniEntry[]` |
| `Jni.table` | — | `Record<string, JniEntry>` |
| `Jni.helper.env.getClassName(clazz)` | `AddressLike` | `string \| null` |
| `Jni.helper.env.readJString(jstr)` | `AddressLike` | `string \| null` |
| `Jni.helper.structs.JNINativeMethod.readArray(addr, count)` | `AddressLike, number` | `JNINativeMethodInfo[]` |

### 实战：监控 RegisterNatives

```js
hook(Jni.addr("RegisterNatives"), function(ctx) {
    var cls = Jni.helper.env.getClassName(ctx.x1);
    var count = Number(ctx.x3);
    console.log(cls + " (" + count + " methods)");

    var methods = Jni.helper.structs.JNINativeMethod.readArray(ptr(ctx.x2), count);
    for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var mod = Module.findByAddress(m.fnPtr);
        console.log("  " + m.name + " " + m.sig + " → " + mod.name + "+" + m.fnPtr.sub(mod.base));
    }
    return ctx.orig();
}, 1);
```

---

## Memory

**双风格 Frida 兼容**：`Memory.readXxx(addr)` ≡ `addr.readXxx()`，所有 read/write 方法同时挂在 `Memory` 和 `NativePointer.prototype` 上。

```js
// Memory.* 风格
var pid = Memory.readU32(ptr("0x7f1234"));
Memory.writeU64(dst, 0xdeadbeefn);
var cls = Memory.readCString(ptr(ctx.x1));

// ptr.* 风格（推荐，支持链式）
var p = ptr("0x7f1234");
p.readU32();
p.writeU64(0xdeadbeefn);
p.add(8).readPointer().readCString();     // 解指针再读字符串
p.add(0x10).readByteArray(32);            // → ArrayBuffer

// 写入代码后刷 I-cache
var code = Memory.alloc(16);
code.writeU32(0xd65f03c0);                // ret
Memory.flushCodeCache(code, 16);
```

| API | 参数 | 返回 |
| --- | --- | --- |
| **读** | | |
| `Memory.readU8/U16(addr)` / `p.readU8/U16()` | `AddressLike` | `number` |
| `Memory.readU32/U64(addr)` / `p.readU32/U64()` | `AddressLike` | `bigint` |
| `Memory.readPointer(addr)` / `p.readPointer()` | `AddressLike` | `NativePointer` |
| `Memory.readCString(addr)` / `p.readCString()` | `AddressLike` | `string` (最多 4096B) |
| `Memory.readUtf8String(addr)` / `p.readUtf8String()` | `AddressLike` | `string` |
| `Memory.readByteArray(addr, len)` / `p.readByteArray(len)` | `AddressLike, number` | `ArrayBuffer` (≤1GB) |
| **写** | | |
| `Memory.writeU8/U16/U32(addr, v)` / `p.writeU8/U16/U32(v)` | `AddressLike, number` | `undefined` |
| `Memory.writeU64(addr, v)` / `p.writeU64(v)` | `AddressLike, bigint` | `undefined` |
| `Memory.writePointer(addr, v)` / `p.writePointer(v)` | `AddressLike, AddressLike` | `undefined` |
| `Memory.writeBytes(addr, bytes, stealth?)` / `p.writeBytes(bytes, stealth?)` | `AddressLike, ArrayBuffer\|TypedArray\|number[], 0\|1` | `undefined` |
| `Memory.writest(addr, bytes)` / `p.writest(bytes)` | `AddressLike, 4B 倍数指令字节` | `undefined` |
| **分配 / 维护** | | |
| `Memory.alloc(size)` | `number` (≤ 256MB) | `NativePointer` (RWX, 零初始化) |
| `Memory.allocUtf8String(s)` | `string` | `NativePointer` (RWX，末尾 `\0`) |
| `Memory.flushCodeCache(addr, size)` | `AddressLike, number` | `undefined` |

**约束**：
- 无效地址抛 `RangeError`；`readCString` 超过 4096B 抛
- `Memory.alloc` 是 RWX 堆内存，GC 时自动释放；勿 `munmap`
- 写入代码后必须 `Memory.flushCodeCache` 刷 I-cache
- `writeXxx` 不会自动 mprotect；只读段写入抛错，需先 `Memory.protect`

### Memory.protect / writeBytes / writest

| API | 适用段 | read 可见 | 用途 |
| --- | --- | --- | --- |
| `Memory.protect(addr, size, "rwx")` | 任意 | — | 改页权限（页级 mprotect） |
| `p.writeBytes(bytes, 0)` 默认 | 可写段 | 可见 | 覆盖 N 字节（数据/结构体） |
| `p.writeBytes(bytes, 1)` | r-x | 不可见 | wxshadow 覆盖 N 字节（短 patch，单页内） |
| `p.writest(bytes)` | r-x | 不可见 | 1 条指令 → N 条指令替换（PC-rel 自动 relocate） |

`unhook(addr)` 统一清理 hook / writest / writeBytes(1) 留下的 patch。

```js
var addr = Module.findExportByName("libc.so", "getpid");

// 隐身短 patch: getpid() → 42, readByteArray 仍看原字节
addr.writeBytes(new Uint8Array([0x40,0x05,0x80,0xd2, 0xc0,0x03,0x5f,0xd6]), 1);

// 指令级替换: 原第一条指令被这 3 条顶替, 原第二条及以后保留
addr.writest(new Uint8Array([
    0x80,0x46,0x82,0x52,  // MOVZ W0, #0x1234
    0xa0,0x79,0xb5,0x72,  // MOVK W0, #0xABCD, LSL #16
    0xc0,0x03,0x5f,0xd6,  // RET
]));

// 写数据段: 先开写权限
Memory.protect(dataAddr, 8, "rwx");
dataAddr.writeU64(0xdeadbeefn);
Memory.protect(dataAddr, 8, "r--");
```

**writest 细节**：patch 不带 RET/B 时末尾自动 fall-through 到 `addr+4`；`ADR/ADRP/BL/LDR literal/CBZ/TBZ/B.cond` 自动 relocate；patch 内部分支 ≤64 条指令有效；同地址重装需先 `unhook`。

## Module

| API | 参数 | 返回 |
| --- | --- | --- |
| `Module.findExportByName(module, symbol)` | `string, string` | `NativePointer \| null` |
| `Module.findBaseAddress(module)` | `string` | `NativePointer \| null` |
| `Module.findByAddress(addr)` | `AddressLike` | `ModuleInfo \| null` |
| `Module.enumerateModules()` | — | `ModuleInfo[]` |
| `Module.enumerateExports(name)` | `string` | `{type, name, address}[]` |
| `Module.enumerateImports(name)` | `string` | `{type, name, slot, address}[]` |
| `Module.enumerateSymbols(name)` | `string` | `{type, name, address, isGlobal, isDefined}[]` |
| `Module.enumerateRanges(name, prot?)` | `string, "rwx" 风格` | `{base, size, protection, file:{path}}[]` |

```js
// 导出：defined + global/weak 符号
Module.enumerateExports("libc.so").slice(0, 3);
// [{type:"function", name:"__cxa_finalize", address:"0x7200f0e0a0"}, ...]

// 按内存权限过滤 (prot 里 '-' 是通配, "r-x" 会匹配 r-x 和 rwx)
Module.enumerateRanges("libc.so", "r-x");

// 外部引用符号 + PLT/GOT slot 地址
Module.enumerateImports("libart.so").filter(i => i.type === "function");
```

枚举的来源是模块的磁盘 ELF；memfd 或无文件支撑的合成模块返回空数组。

## ptr / NativePointer

```js
var p = ptr("0x7f12345678");   // hex string / number / BigInt / NativePointer
p.add(0x100).sub(0x10);        // 算术，返回新 NativePointer
p.toString();                  // → "0x7f12345678"
p.toInt();                     // → bigint (等价 toNumber)

// Frida 兼容读写（完整 API 见上面 Memory 章节）
p.readU32();                   // 等价 Memory.readU32(p)
p.writeU64(0xdeadbeefn);       // 自动 mprotect
p.readPointer().readCString(); // 链式解引用
```

| API | 参数 | 返回 |
| --- | --- | --- |
| `ptr(value)` | `number \| bigint \| string \| NativePointer` | `NativePointer` |
| `p.add(offset)` / `p.sub(offset)` | `AddressLike` | `NativePointer` |
| `p.toString()` / `p.toJSON()` | — | `string` (`"0x..."`) |
| `p.toNumber()` / `p.toInt()` | — | `bigint` |
| `p.readU8/U16/U32/U64/Pointer()` | — | `number \| bigint \| NativePointer` |
| `p.readCString()` / `p.readUtf8String()` | — | `string` |
| `p.readByteArray(len)` | `number` | `ArrayBuffer` |
| `p.writeU8/U16/U32/U64/Pointer(val)` | 值 | `undefined` |
| `p.writeBytes(bytes, stealth?)` | `ArrayBuffer\|TypedArray\|number[], 0\|1` | `undefined` |
| `p.writest(bytes)` | `ArrayBuffer\|TypedArray\|number[]` (4B 倍数) | `undefined` |

所有读写方法的语义、错误处理、i-cache 约束与 `Memory.*` 完全一致；`writeBytes` / `writest` 的行为见 Memory 章节的表格。

## console

`console.log(...)` / `console.info(...)` / `console.warn(...)` / `console.error(...)` / `console.debug(...)`

## QBDI Trace

| API | 参数 | 返回 |
| --- | --- | --- |
| `qbdi.newVM()` | — | `number` |
| `qbdi.destroyVM(vm)` | `number` | `boolean` |
| `qbdi.addInstrumentedModuleFromAddr(vm, addr)` | `number, AddressLike` | `boolean` |
| `qbdi.addInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeAllInstrumentedRanges(vm)` | `number` | `boolean` |
| `qbdi.allocateVirtualStack(vm, size)` | `number, number` | `boolean` |
| `qbdi.simulateCall(vm, retAddr, ...args)` | `number, AddressLike, ...AddressLike` | `boolean` |
| `qbdi.call(vm, target, ...args)` | `number, AddressLike, ...AddressLike` | `NativePointer \| null` |
| `qbdi.run(vm, start, stop)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.getGPR(vm, reg)` | `number, number` | `NativePointer` |
| `qbdi.setGPR(vm, reg, value)` | `number, number, AddressLike` | `boolean` |
| `qbdi.registerTraceCallbacks(vm, target, outDir?)` | `number, AddressLike, string?` | `boolean` |
| `qbdi.unregisterTraceCallbacks(vm)` | `number` | `boolean` |
| `qbdi.lastError()` | — | `string` |

常用寄存器常量：`qbdi.REG_RETURN`, `qbdi.REG_SP`, `qbdi.REG_LR`, `qbdi.REG_PC`

```js
var vm = qbdi.newVM();
qbdi.addInstrumentedModuleFromAddr(vm, target);
qbdi.allocateVirtualStack(vm, 0x100000);
qbdi.simulateCall(vm, 0, arg0, arg1);
qbdi.registerTraceCallbacks(vm, target);
qbdi.run(vm, target, 0);
var ret = qbdi.getGPR(vm, qbdi.REG_RETURN);
qbdi.unregisterTraceCallbacks(vm);
qbdi.destroyVM(vm);
```

Trace 文件默认输出到 `/data/data/<package>/trace_bundle.pb`，配合 qbdi-replay + IDA 插件回放。

---

## 注意事项

- **两种 hook 都建议 `return ctx.orig()`** 透传返回值
- **Native hook 改参数/返回值：** `ctx.x0 = value` 或 `ctx.orig(newArg0, newArg1)`，`return value` 覆盖返回值
- **Java hook 改参数/返回值：** `return ctx.orig(newArgs)` 改参数，`return value` 改返回值
- **Java 字段访问必须用 `.value`：** `obj.field` 返回 FieldWrapper，`obj.field.value` 才是真实值
- **`Java.choose` 的 wrapper 仅在 `onMatch` 内有效**，跨回调保留需要自己提取字段值
- Spawn 模式下 Java hook 必须放在 `Java.ready(fn)` 里（`Java.classLoaders()` / `Java.choose` 同理）
- `Java.setStealth()` 必须在 `Java.use().impl` 之前调用
- `callNative()` 仅支持整数/指针参数（最多 6 个），需要浮点/任意签名用 `NativeFunction`
- 自修改代码后需 `Memory.flushCodeCache(addr, size)` 清 I-cache

---

## 免责声明

本项目仅供安全研究、逆向工程学习和授权测试用途。使用者应确保在合法授权范围内使用本工具，遵守所在地区的法律法规。作者不对任何滥用、非法使用或由此造成的损失承担责任。使用本项目即表示您同意自行承担所有风险。
