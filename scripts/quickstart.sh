#!/bin/bash
# quickstart.sh — rustFrida 快速开始脚本
# 自动检查环境、配置依赖、构建项目
#
# 用法:
#   chmod +x scripts/quickstart.sh
#   ./scripts/quickstart.sh

set -e  # 遇到错误立即退出

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; }

# 获取项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  rustFrida 快速开始${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# ==========================================
# 1. 检查基础工具
# ==========================================
info "检查基础工具..."

# 检查 git
if ! command -v git &> /dev/null; then
    error "git 未安装"
    echo "  macOS: brew install git"
    echo "  Linux: sudo apt install git"
    exit 1
fi
success "git $(git --version | cut -d' ' -f3)"

# 检查 python3
if ! command -v python3 &> /dev/null; then
    error "python3 未安装"
    echo "  macOS: brew install python3"
    echo "  Linux: sudo apt install python3"
    exit 1
fi
success "python3 $(python3 --version | cut -d' ' -f2)"

# 检查 rustc
if ! command -v rustc &> /dev/null; then
    warn "Rust 未安装，正在安装..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi
success "rustc $(rustc --version | cut -d' ' -f2)"

# 检查 cargo
if ! command -v cargo &> /dev/null; then
    error "cargo 未找到，请重新安装 Rust"
    exit 1
fi
success "cargo $(cargo --version | cut -d' ' -f2)"

echo ""

# ==========================================
# 2. 检查 Android 目标
# ==========================================
info "检查 Android ARM64 目标..."

if rustup target list | grep -q "aarch64-linux-android (installed)"; then
    success "aarch64-linux-android 已安装"
else
    warn "aarch64-linux-android 未安装，正在添加..."
    rustup target add aarch64-linux-android
    success "aarch64-linux-android 已添加"
fi

echo ""

# ==========================================
# 3. 检测 NDK
# ==========================================
info "检测 Android NDK..."

NDK_FOUND=false
NDK_PATH=""

# macOS 默认路径
if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
    NDK_BASE="$HOME/Library/Android/sdk/ndk"
    LATEST_NDK=$(ls -1 "$NDK_BASE" | sort -V | tail -n1)
    if [ -n "$LATEST_NDK" ]; then
        NDK_PATH="$NDK_BASE/$LATEST_NDK"
        NDK_FOUND=true
    fi
fi

# Linux 默认路径
if [ "$NDK_FOUND" = false ] && [ -d "$HOME/Android/Sdk/ndk" ]; then
    NDK_BASE="$HOME/Android/Sdk/ndk"
    LATEST_NDK=$(ls -1 "$NDK_BASE" | sort -V | tail -n1)
    if [ -n "$LATEST_NDK" ]; then
        NDK_PATH="$NDK_BASE/$LATEST_NDK"
        NDK_FOUND=true
    fi
fi

# 检查 NDK_HOME 环境变量
if [ "$NDK_FOUND" = false ] && [ -n "$NDK_HOME" ] && [ -d "$NDK_HOME" ]; then
    NDK_PATH="$NDK_HOME"
    NDK_FOUND=true
fi

if [ "$NDK_FOUND" = true ]; then
    success "NDK 已找到: $NDK_PATH"
    
    # 提取版本号
    NDK_VERSION=$(basename "$NDK_PATH")
    NDK_MAJOR=$(echo "$NDK_VERSION" | cut -d'.' -f1)
    
    if [ "$NDK_MAJOR" -lt 25 ]; then
        warn "NDK 版本 $NDK_VERSION < 25，可能不兼容"
        warn "建议安装 NDK 25+ 版本"
    else
        success "NDK 版本 $NDK_VERSION 符合要求 (>= 25)"
    fi
    
    # 添加 NDK 工具链到 PATH（cc-rs 需要）
    NDK_BIN="$NDK_PATH/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin"
    if [ -d "$NDK_BIN" ]; then
        export PATH="$NDK_BIN:$PATH"
        success "已添加 NDK 工具链到 PATH"
        
        # 创建符号链接（如果不存在）
        if [ ! -e "$NDK_BIN/aarch64-linux-android-clang" ]; then
            ln -sf aarch64-linux-android33-clang "$NDK_BIN/aarch64-linux-android-clang"
            ln -sf aarch64-linux-android33-clang++ "$NDK_BIN/aarch64-linux-android-clang++"
            success "已创建编译器符号链接"
        fi
    fi
else
    error "未找到 Android NDK"
    echo ""
    echo "请安装 NDK 25+ 版本："
    echo "  macOS:"
    echo "    1. 安装 Android Studio"
    echo "    2. SDK Manager → SDK Tools → Android NDK"
    echo "    3. 默认路径: ~/Library/Android/sdk/ndk/"
    echo ""
    echo "  Linux:"
    echo "    sdkmanager \"ndk;27.2.12479018\""
    echo "    或手动下载到 ~/Android/Sdk/ndk/"
    echo ""
    exit 1
fi

echo ""

# ==========================================
# 4. 生成 Cargo 配置
# ==========================================
info "生成 Cargo 配置..."

if [ -f "loader/setup_env.py" ]; then
    python3 loader/setup_env.py
    
    if [ -f ".cargo/config.toml" ]; then
        success "已生成 .cargo/config.toml"
    else
        error "配置生成失败"
        exit 1
    fi
else
    error "loader/setup_env.py 不存在"
    exit 1
fi

echo ""

# ==========================================
# 5. 初始化子仓库
# ==========================================
info "检查子仓库..."

if [ -d ".git" ]; then
    if [ -f ".gitmodules" ]; then
        # 检查子仓库是否已初始化
        SUBMODULE_UNINITIALIZED=$(git submodule status | grep "^-" || true)
        
        if [ -n "$SUBMODULE_UNINITIALIZED" ]; then
            warn "子仓库未初始化，正在拉取..."
            git submodule update --init --recursive
            success "子仓库已初始化"
        else
            success "子仓库已就绪"
        fi
    else
        warn "未找到 .gitmodules，跳过子仓库检查"
    fi
else
    warn "非 Git 仓库，跳过子仓库检查"
fi

echo ""

# ==========================================
# 6. 构建 loader shellcode
# ==========================================
info "构建 loader shellcode..."

if [ -f "loader/build_helpers.py" ]; then
    python3 loader/build_helpers.py
    
    if [ -f "loader/build/bootstrapper.bin" ] && [ -f "loader/build/rustfrida-loader.bin" ]; then
        success "loader shellcode 构建成功"
        BOOT_SIZE=$(wc -c < loader/build/bootstrapper.bin)
        LOADER_SIZE=$(wc -c < loader/build/rustfrida-loader.bin)
        echo "  bootstrapper.bin:      $BOOT_SIZE bytes"
        echo "  rustfrida-loader.bin:  $LOADER_SIZE bytes"
    else
        error "loader shellcode 构建失败"
        exit 1
    fi
else
    error "loader/build_helpers.py 不存在"
    exit 1
fi

echo ""

# ==========================================
# 7. 构建 agent (libagent.so)
# ==========================================
info "构建 agent (libagent.so)..."

if cargo build -p agent --release --target aarch64-linux-android; then
    if [ -f "target/aarch64-linux-android/release/libagent.so" ]; then
        success "agent 构建成功"
        AGENT_SIZE=$(wc -c < target/aarch64-linux-android/release/libagent.so)
        echo "  libagent.so: $AGENT_SIZE bytes"
    else
        error "agent 构建失败：未找到 libagent.so"
        exit 1
    fi
else
    error "agent 构建失败"
    exit 1
fi

echo ""

# ==========================================
# 8. 构建 rustfrida 主程序
# ==========================================
info "构建 rustfrida 主程序..."

if cargo build -p rust_frida --release --target aarch64-linux-android; then
    if [ -f "target/aarch64-linux-android/release/rustfrida" ]; then
        success "rustfrida 构建成功"
        MAIN_SIZE=$(wc -c < target/aarch64-linux-android/release/rustfrida)
        echo "  rustfrida: $MAIN_SIZE bytes"
    else
        error "rustfrida 构建失败：未找到 rustfrida 二进制"
        exit 1
    fi
else
    error "rustfrida 构建失败"
    exit 1
fi

echo ""

# ==========================================
# 完成
# ==========================================
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  ✓ 构建完成！${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "产物位置:"
echo "  loader/build/bootstrapper.bin"
echo "  loader/build/rustfrida-loader.bin"
echo "  target/aarch64-linux-android/release/libagent.so"
echo "  target/aarch64-linux-android/release/rustfrida"
echo ""
echo "部署到设备:"
echo "  adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/"
echo ""
echo "运行示例:"
echo "  ./rustfrida --pid <pid> -l script.js"
echo "  ./rustfrida --spawn com.example.app -l script.js"
echo ""
