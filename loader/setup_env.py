#!/usr/bin/env python3
"""
setup_env.py — 自动检测本机 NDK，生成 .cargo/config.toml

Cargo 的 config.toml 不支持在 linker/rustflags 中展开环境变量，
因此用此脚本动态生成配置文件（已加入 .gitignore）。

用法:
    python3 loader/setup_env.py

可选环境变量:
    NDK_HOME  — 指定 NDK 路径（不设置则自动检测最新版本）
"""

import os
import sys
import platform


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
CARGO_DIR = os.path.join(PROJECT_ROOT, ".cargo")


def _host_tag():
    """返回 NDK prebuilt 目录的主机标签。"""
    system = platform.system().lower()
    tags = {"darwin": "darwin-x86_64", "linux": "linux-x86_64", "windows": "windows-x86_64"}
    return tags.get(system, "linux-x86_64")


def _version_key(name):
    """将版本字符串转为可比较的元组。"""
    try:
        return tuple(int(x) for x in name.split("."))
    except ValueError:
        return (0,)


def find_ndk():
    """自动检测 NDK 路径，优先使用 $NDK_HOME。"""
    env_ndk = os.environ.get("NDK_HOME")
    if env_ndk and os.path.isdir(env_ndk):
        return env_ndk

    system = platform.system().lower()
    if system == "darwin":
        ndk_base = os.path.expanduser("~/Library/Android/sdk/ndk")
    elif system == "linux":
        ndk_base = os.path.expanduser("~/Android/Sdk/ndk")
    elif system == "windows":
        local = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        ndk_base = os.path.join(local, "Android", "Sdk", "ndk")
    else:
        ndk_base = os.path.expanduser("~/Android/Sdk/ndk")

    if not os.path.isdir(ndk_base):
        print(f"错误: 未找到 NDK 目录: {ndk_base}")
        print("请设置环境变量 NDK_HOME 指向 NDK 安装路径")
        sys.exit(1)

    versions = [v for v in os.listdir(ndk_base)
                if os.path.isdir(os.path.join(ndk_base, v))]
    if not versions:
        print(f"错误: NDK 目录为空: {ndk_base}")
        sys.exit(1)

    versions.sort(key=_version_key, reverse=True)
    suitable = [v for v in versions if _version_key(v)[0] >= 25]
    chosen = suitable[0] if suitable else versions[0]
    return os.path.join(ndk_base, chosen)


def find_clang_version(prebuilt_dir):
    """从 prebuilt 目录推断 Clang 主版本号。

    注意：aarch64-linux-androidXX-clang 中的 XX 是 API 级别，不是 Clang 版本。
    Clang 版本需要从 lib/clang/XX 目录获取（例如 NDK 27.2 用 Clang 18）。
    """
    for lib_dir_name in ("lib", "lib64"):
        clang_base = os.path.join(prebuilt_dir, lib_dir_name, "clang")
        if os.path.isdir(clang_base):
            candidates = [d for d in os.listdir(clang_base)
                         if d.isdigit() and os.path.isdir(os.path.join(clang_base, d))]
            if candidates:
                return sorted(candidates, key=int)[-1]
    return None


def generate_config(ndk_path, host_tag):
    """生成 .cargo/config.toml。"""
    prebuilt = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", host_tag)
    bin_dir = os.path.join(prebuilt, "bin")

    linker = os.path.join(bin_dir, "aarch64-linux-android33-clang")
    ar = os.path.join(bin_dir, "llvm-ar")
    sysroot = os.path.join(prebuilt, "sysroot")

    if not os.path.isfile(linker):
        print(f"错误: 未找到 linker: {linker}")
        sys.exit(1)
    if not os.path.isfile(ar):
        print(f"错误: 未找到 ar: {ar}")
        sys.exit(1)
    if not os.path.isdir(sysroot):
        print(f"错误: 未找到 sysroot: {sysroot}")
        sys.exit(1)

    clang_ver = find_clang_version(prebuilt)
    if not clang_ver:
        print("错误: 无法检测 Clang 版本号")
        sys.exit(1)

    builtins_lib = os.path.join(prebuilt, "lib", "clang", clang_ver, "lib", "baremetal")
    if not os.path.isdir(builtins_lib):
        builtins_lib = os.path.join(prebuilt, "lib64", "clang", clang_ver, "lib", "baremetal")
    if not os.path.isdir(builtins_lib):
        print("警告: 未找到 builtins 库目录，rustflags 中的 -L 路径可能无效")

    # 写入 config.toml（覆盖，因为这个文件不应该被提交）
    os.makedirs(CARGO_DIR, exist_ok=True)
    config_path = os.path.join(CARGO_DIR, "config.toml")

    lines = [
        "# 由 loader/setup_env.py 自动生成 — 请勿手动编辑",
        f"# NDK: {ndk_path}",
        f"# Host: {host_tag}  Clang: {clang_ver}",
        "",
        "[target.aarch64-linux-android]",
        f'linker = "{linker}"',
        f'ar = "{ar}"',
        'rustflags = [',
        '    "-C", "relocation-model=pic",',
        '    "-l", "clang_rt.builtins-aarch64",',
        f'    "-L", "{builtins_lib}"',
        "]",
        "",
        "[env]",
        f'CC_aarch64-linux-android = "{linker}"',
        f'AR_aarch64-linux-android = "{ar}"',
        f'BINDGEN_EXTRA_CLANG_ARGS = "--sysroot={sysroot}"',
        f'CFLAGS_aarch64-linux-android = "-fPIC -fno-builtin -fno-stack-protector"',
        "",
    ]

    with open(config_path, "w") as f:
        f.write("\n".join(lines))

    return config_path, builtins_lib


def main():
    print("=== rustFrida 构建环境配置 ===\n")

    host_tag = _host_tag()
    print(f"主机平台: {host_tag}")

    ndk_path = find_ndk()
    print(f"NDK 路径: {ndk_path}")

    config_path, builtins_lib = generate_config(ndk_path, host_tag)
    clang = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", host_tag, "bin", "aarch64-linux-android33-clang")
    print(f"Clang:    {clang}")
    print(f"Builtins: {builtins_lib}")
    print(f"\n已生成: {config_path}")
    print("\n下一步:")
    print("  1. 安装 Rust:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
    print("  2. 加载环境:  source ~/.cargo/env")
    print("  3. 添加目标:  rustup target add aarch64-linux-android")
    print("  4. 同步子模块: git submodule update --init --recursive")
    print("  5. 构建 agent: cargo build -p agent --release")


if __name__ == "__main__":
    main()
