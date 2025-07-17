# Shellcode Loader

这个目录包含了用于远程注入和加载SO库的shellcode源码和编译工具。

## 文件说明

- `loader.c`: C语言编写的shellcode源代码，不依赖任何共享库
- `loader.py`: Python脚本，用于使用Android NDK交叉编译生成ARM64架构的纯二进制shellcode

## 工作原理

该shellcode被远程注入到目标进程中执行，它会：

1. 连接到指定的抽象Socket套接字
2. 通过该套接字接收SO库的文件描述符
3. 使用dlopen加载接收到的SO库
4. 返回加载结果

## 编译需求

- Python 3.6+
- Android NDK (r20以上版本推荐)

## 使用方法

### 1. 安装Android NDK

如果尚未安装Android NDK，可以通过Android Studio或命令行方式安装。

### 2. 编译shellcode

使用Python脚本编译shellcode：

```bash
# 自动查找NDK路径
python loader.py

# 手动指定NDK路径
python loader.py --ndk=/path/to/android-ndk
```

### 其他选项

```bash
# 显示帮助
python loader.py --help

# 指定输出目录
python loader.py --output=my_build

# 指定目标架构(目前仅支持arm64-v8a)
python loader.py --arch=arm64-v8a
```

### 3. 输出文件

编译成功后，会在以下位置生成文件：

- `build/loader.o`: 目标文件
- `build/loader.s`: 汇编代码
- `build/loader.bin`: 纯二进制shellcode
- `../loader.bin`: 复制到主项目目录的shellcode (可直接被Rust代码使用)

## 注意事项

- shellcode必须是位置无关代码(PIC)，因此使用了 `-fPIC` 编译选项
- 不使用标准库和栈保护，使用了 `-nostdlib` 和 `-fno-stack-protector` 编译选项
- 代码优化使用了 `-O2` 级别，平衡了代码大小和性能
- 为减小大小，使用了 `-fomit-frame-pointer` 省略栈帧指针 