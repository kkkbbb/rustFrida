#!/usr/bin/env python3
"""
build_helpers.py — Compile Frida-style bootstrapper + loader into binary shellcode.

Produces:
  build/bootstrapper.bin  — Process probing + libc API resolution shellcode
  build/rustfrida-loader.bin — Agent loading + IPC handshake shellcode

Both are position-independent ARM64 binary blobs extracted from the .payload
section using the helper.lds linker script.
"""

import os
import sys
import subprocess
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HELPERS_DIR = os.path.join(SCRIPT_DIR, "helpers")
BUILD_DIR = os.path.join(SCRIPT_DIR, "build")

# Android NDK setup
NDK_BASE = os.path.expanduser("~/Android/Sdk/ndk")

def find_ndk():
    """Find the latest Android NDK."""
    if not os.path.isdir(NDK_BASE):
        print(f"错误: NDK 目录不存在: {NDK_BASE}")
        sys.exit(1)
    versions = sorted(os.listdir(NDK_BASE), reverse=True)
    if not versions:
        print("错误: 未找到 NDK 版本")
        sys.exit(1)
    return os.path.join(NDK_BASE, versions[0])

def find_tool(ndk_path, tool):
    """Find an NDK tool in the toolchain."""
    toolchain = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
    # Try llvm- prefixed first
    llvm_tool = os.path.join(toolchain, f"llvm-{tool}")
    if os.path.isfile(llvm_tool):
        return llvm_tool
    # Try aarch64- prefixed
    aarch64_tool = os.path.join(toolchain, f"aarch64-linux-android-{tool}")
    if os.path.isfile(aarch64_tool):
        return aarch64_tool
    return None

def find_clang(ndk_path, api=33):
    """Find the NDK clang for aarch64."""
    toolchain = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
    clang = os.path.join(toolchain, f"aarch64-linux-android{api}-clang")
    if os.path.isfile(clang):
        return clang
    # Fallback without API version
    clang = os.path.join(toolchain, "aarch64-linux-android-clang")
    if os.path.isfile(clang):
        return clang
    # Try plain clang
    clang = os.path.join(toolchain, "clang")
    if os.path.isfile(clang):
        return clang
    return None

def run_cmd(cmd, desc=""):
    """Run a command and check for errors."""
    if desc:
        print(f"  {desc}")
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  错误: 命令失败 (exit {result.returncode})")
        if result.stderr:
            print(f"  stderr: {result.stderr}")
        if result.stdout:
            print(f"  stdout: {result.stdout}")
        sys.exit(1)
    return result

def build_shellcode(cc, ld, objcopy, sources, output_name, extra_cflags=None):
    """Compile C sources into a binary shellcode blob."""
    if extra_cflags is None:
        extra_cflags = []

    lds = os.path.join(HELPERS_DIR, "helper.lds")
    obj_files = []

    # Common flags
    cflags = [
        "-target", "aarch64-linux-android33",
        "-fPIC",
        "-fno-stack-protector",
        "-fvisibility=hidden",
        "-fno-function-sections",
        "-fno-data-sections",
        "-fno-asynchronous-unwind-tables",
        # "-fno-optimize-strlen",  # GCC only, clang doesn't need it
        "-fomit-frame-pointer",
        "-O2",
        "-Wall",
        f"-I{HELPERS_DIR}",
    ] + extra_cflags

    ldflags = [
        "-target", "aarch64-linux-android33",
        "-nostdlib",
        "-shared",
        f"-Wl,-T,{lds}",
        "-Wl,--no-undefined",
    ]

    # Compile each source
    for src in sources:
        src_path = os.path.join(HELPERS_DIR, src)
        obj_path = os.path.join(BUILD_DIR, os.path.splitext(src)[0] + ".o")
        obj_files.append(obj_path)
        run_cmd(
            [cc] + cflags + ["-c", src_path, "-o", obj_path],
            f"编译 {src}"
        )

    # Link into shared module
    so_path = os.path.join(BUILD_DIR, output_name + ".so")
    run_cmd(
        [ld] + ldflags + obj_files + ["-o", so_path],
        f"链接 {output_name}.so"
    )

    # Extract .payload section as binary
    bin_path = os.path.join(BUILD_DIR, output_name + ".bin")
    run_cmd(
        [objcopy, "-O", "binary", "--only-section=.payload", so_path, bin_path],
        f"提取 {output_name}.bin"
    )

    # Report size
    size = os.path.getsize(bin_path)
    print(f"  ✓ {output_name}.bin: {size} 字节")
    return bin_path

def main():
    print("=== 构建 Frida-style helpers ===\n")

    # Find NDK
    ndk = find_ndk()
    print(f"NDK: {ndk}")

    cc = find_clang(ndk)
    if not cc:
        print("错误: 未找到 clang")
        sys.exit(1)

    # Use clang as linker too
    ld = cc

    objcopy = find_tool(ndk, "objcopy")
    if not objcopy:
        print("错误: 未找到 objcopy")
        sys.exit(1)

    print(f"CC: {cc}")
    print(f"OBJCOPY: {objcopy}")
    print()

    # Ensure build directory exists
    os.makedirs(BUILD_DIR, exist_ok=True)

    # Build bootstrapper (NOLIBC mode — no libc, raw syscalls only)
    print("[1/2] 构建 bootstrapper...")
    build_shellcode(
        cc, ld, objcopy,
        sources=["bootstrapper.c", "elf-parser.c"],
        output_name="bootstrapper",
        extra_cflags=[
            "-DNOLIBC",
            "-DNOLIBC_DISABLE_START",
            "-DNOLIBC_IGNORE_ERRNO",
            "-ffreestanding",
        ],
    )
    print()

    # Build loader (uses function pointers from bootstrapper, no direct libc calls)
    print("[2/2] 构建 rustfrida-loader...")
    build_shellcode(
        cc, ld, objcopy,
        sources=["rustfrida-loader.c", "syscall.c"],
        output_name="rustfrida-loader",
        extra_cflags=[
            "-ffreestanding",
        ],
    )
    print()

    print("=== 构建完成 ===")
    print(f"  bootstrapper.bin:      {BUILD_DIR}/bootstrapper.bin")
    print(f"  rustfrida-loader.bin:  {BUILD_DIR}/rustfrida-loader.bin")

if __name__ == "__main__":
    main()
