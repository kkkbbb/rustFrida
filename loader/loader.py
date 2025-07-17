#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
交叉编译loader.c生成纯二进制shellcode
支持使用Android NDK编译为ARM64架构的shellcode
特别优化了Windows环境下的兼容性
"""

import os
import sys
import subprocess
import argparse
import platform
import shutil
import tempfile
from pathlib import Path

# 尝试导入ELF处理库
try:
    import lief
    HAS_LIEF = True
    print("已找到LIEF库，将使用它进行ELF处理")
except ImportError:
    HAS_LIEF = False
    try:
        import elftools
        from elftools.elf.elffile import ELFFile
        HAS_ELFTOOLS = True
        print("已找到pyelftools库，将使用它进行ELF处理")
    except ImportError:
        HAS_ELFTOOLS = False
        print("未找到ELF处理库，将使用备用方法")

def find_ndk():
    """尝试自动查找NDK路径"""
    # 常见NDK安装位置
    common_paths = []
    
    # Windows特定路径
    if platform.system() == "Windows":
        # 用户目录
        user_home = os.path.expanduser("~")
        common_paths.extend([
            os.path.join(user_home, "AppData", "Local", "Android", "Sdk", "ndk"),
            os.path.join(user_home, "AppData", "Local", "Android", "sdk", "ndk"),
            "C:/Android/sdk/ndk",
            "C:/Android/ndk",
            "D:/Android/sdk/ndk",
            "D:/Android/ndk",
            "C:/Program Files/Android/ndk",
            "C:/Program Files (x86)/Android/ndk",
        ])
        # 查找最新版本
        for base in [os.path.join(user_home, "AppData", "Local", "Android", "Sdk", "ndk"),
                   "C:/Android/sdk/ndk", "D:/Android/sdk/ndk"]:
            if os.path.exists(base):
                try:
                    # 找到最新版本的NDK
                    versions = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
                    if versions:
                        # 按版本号排序
                        versions.sort(reverse=True)
                        for v in versions:
                            ndk_path = os.path.join(base, v)
                            if os.path.exists(os.path.join(ndk_path, "source.properties")):
                                return ndk_path
                except Exception:
                    pass
    # Linux路径
    elif platform.system() == "Linux":
        common_paths.extend([
            "/opt/android-sdk-linux/ndk-bundle",
            "/opt/android-sdk/ndk-bundle",
            "/opt/android-ndk",
            "/opt/android-sdk/ndk",
            os.path.expanduser("~/Android/Sdk/ndk"),
        ])
    # macOS路径
    elif platform.system() == "Darwin":
        common_paths.extend([
            os.path.expanduser("~/Library/Android/sdk/ndk-bundle"),
            os.path.expanduser("~/Library/Android/sdk/ndk"),
        ])
    
    # 检查环境变量
    if "ANDROID_NDK_HOME" in os.environ:
        path = os.environ["ANDROID_NDK_HOME"]
        if os.path.exists(path):
            return path
    if "ANDROID_NDK_ROOT" in os.environ:
        path = os.environ["ANDROID_NDK_ROOT"]
        if os.path.exists(path):
            return path
    
    # 查找常见路径
    for path in common_paths:
        if os.path.exists(path):
            # 检查是否是NDK目录
            ndk_props = os.path.join(path, "source.properties")
            if os.path.exists(ndk_props):
                return path
            
            # 对于较新的SDK，NDK可能在子目录中
            try:
                for item in os.listdir(path):
                    subdir = os.path.join(path, item)
                    if os.path.isdir(subdir):
                        ndk_props = os.path.join(subdir, "source.properties")
                        if os.path.exists(ndk_props):
                            return subdir
            except Exception:
                pass
    
    return None

def setup_compilers(ndk_path, arch="arm64-v8a", api_level=None):
    """设置编译器和工具链"""
    if not ndk_path:
        raise ValueError("请指定有效的NDK路径")
    
    # 检查NDK路径是否有效
    if not os.path.exists(os.path.join(ndk_path, "source.properties")):
        raise ValueError(f"无效的NDK路径: {ndk_path} (缺少source.properties)")
    
    # 在Windows上处理路径
    if platform.system() == "Windows":
        ndk_path = ndk_path.replace('\\', '/')
    
    # 查找工具链目录
    toolchain_path = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt")
    if not os.path.exists(toolchain_path):
        raise ValueError(f"未找到工具链目录: {toolchain_path}")
    
    # 查找主机平台特定子目录
    host_tag = None
    if platform.system() == "Linux":
        host_tag = "linux-x86_64"
    elif platform.system() == "Darwin":
        host_tag = "darwin-x86_64"
    elif platform.system() == "Windows":
        host_tag = "windows-x86_64"
        # Windows下可能还有其他可能的标签
        if not os.path.exists(os.path.join(toolchain_path, host_tag)):
            if os.path.exists(os.path.join(toolchain_path, "windows")):
                host_tag = "windows"
            elif os.path.exists(os.path.join(toolchain_path, "windows-x86")):
                host_tag = "windows-x86"
    else:
        raise ValueError(f"不支持的操作系统: {platform.system()}")
    
    # 查找bin目录
    host_dir = os.path.join(toolchain_path, host_tag)
    if not os.path.exists(host_dir):
        # 尝试查找任何可用的主机目录
        host_dirs = [d for d in os.listdir(toolchain_path) if os.path.isdir(os.path.join(toolchain_path, d))]
        if not host_dirs:
            raise ValueError(f"未找到任何主机工具链目录在: {toolchain_path}")
        
        # 优先选择Windows相关目录
        windows_dirs = [d for d in host_dirs if "windows" in d.lower()]
        if windows_dirs and platform.system() == "Windows":
            host_dir = os.path.join(toolchain_path, windows_dirs[0])
        else:
            host_dir = os.path.join(toolchain_path, host_dirs[0])
    
    bin_dir = os.path.join(host_dir, "bin")
    if not os.path.exists(bin_dir):
        raise ValueError(f"未找到bin目录: {bin_dir}")
    
    # 设置编译器和工具
    tools = {}
    
    # Windows下可能的可执行文件扩展名
    exe_extensions = []
    if platform.system() == "Windows":
        exe_extensions = [".cmd", ".exe", ".bat", ""]  # 按优先级排序
    else:
        exe_extensions = [""]  # Unix系统无扩展名
    
    # 根据目标架构设置编译器前缀
    if arch == "arm64-v8a":
        # 查找合适的API级别
        base_prefix = os.path.join(bin_dir, "aarch64-linux-android")
        
        # 如果指定了API级别，优先使用指定的
        if api_level:
            cc_path = None
            api_value = int(api_level)
            
            # 尝试使用指定的API级别
            for ext in exe_extensions:
                candidate = f"{base_prefix}{api_value}-clang{ext}"
                if os.path.exists(candidate):
                    cc_path = candidate
                    print(f"使用指定的API级别 {api_value}，找到编译器: {os.path.basename(cc_path)}")
                    break
            
            # 没找到指定API级别的编译器
            if not cc_path:
                print(f"警告: 没有找到API级别 {api_value} 的编译器，将尝试找其他API级别")
        else:
            cc_path = None
        
        # 如果没有指定API级别或没找到指定的编译器，则查找可用的
        if not cc_path:
            # 查找可用的API级别和扩展名
            api_levels = []
            # 首先查找匹配的编译器文件
            for f in os.listdir(bin_dir):
                # 检查是否是编译器文件
                for ext in exe_extensions:
                    if f.startswith("aarch64-linux-android") and f.endswith(f"clang{ext}"):
                        try:
                            # 提取API级别
                            api_part = f.replace("aarch64-linux-android", "").replace(f"clang{ext}", "")
                            # 处理可能的前缀中划线
                            if api_part.startswith("-"):
                                api_part = api_part[1:]
                            # 提取数字部分
                            digit_part = ''.join(c for c in api_part if c.isdigit())
                            if digit_part:
                                api_levels.append((int(digit_part), ext))
                        except Exception as e:
                            print(f"解析API级别时出错: {e} 对于文件 {f}")
            
            # 如果找到API级别，使用最高的
            if api_levels:
                # 按API级别排序，优先级最高的在前
                api_levels.sort(reverse=True)
                api, ext = api_levels[0]
                cc_path = f"{base_prefix}{api}-clang{ext}"
                print(f"选择编译器: API={api}, 扩展名={ext}")
            else:
                # 逐个尝试可能的编译器名称
                api_candidates = [30, 29, 28, 27, 26, 25, 24, 23, 22, 21]
                for api in api_candidates:
                    for ext in exe_extensions:
                        candidate = f"{base_prefix}{api}-clang{ext}"
                        if os.path.exists(candidate):
                            cc_path = candidate
                            print(f"找到编译器: {os.path.basename(cc_path)}")
                            break
                    if cc_path:
                        break
                
                # 如果还没找到，尝试更通用的模式
                if not cc_path:
                    print("没有找到特定API级别的编译器，尝试通用模式...")
                    # 尝试不带API级别的clang
                    for ext in exe_extensions:
                        candidate = f"{base_prefix}-clang{ext}"
                        if os.path.exists(candidate):
                            cc_path = candidate
                            print(f"找到通用编译器: {os.path.basename(cc_path)}")
                            break
            
            # 如果仍然没有找到编译器，尝试直接查找任何clang文件
            if not cc_path:
                print("查找任何可用的clang编译器...")
                for f in os.listdir(bin_dir):
                    for ext in exe_extensions:
                        if f.endswith(f"clang{ext}") and os.path.isfile(os.path.join(bin_dir, f)):
                            cc_path = os.path.join(bin_dir, f)
                            print(f"找到替代编译器: {os.path.basename(cc_path)}")
                            break
                    if cc_path:
                        break
        
        # 最后检查
        if not cc_path or not os.path.exists(cc_path):
            print("\n警告: 列出bin目录中的所有文件:")
            for f in os.listdir(bin_dir):
                file_path = os.path.join(bin_dir, f)
                file_type = "目录" if os.path.isdir(file_path) else "文件"
                print(f"  - {f} [{file_type}]")
            
            raise ValueError(f"无法找到任何可用的编译器在: {bin_dir}")
        
        tools["CC"] = cc_path
        tools["LD"] = tools["CC"]  # 使用相同的编译器作为链接器
    else:
        raise ValueError(f"不支持的架构: {arch}")
    
    # 设置其他工具
    for tool in ["objcopy", "objdump", "readelf"]:
        tool_found = False
        
        # 尝试使用不同的扩展名
        for ext in exe_extensions:
            # 先尝试带llvm-前缀的工具
            tool_path = os.path.join(bin_dir, f"llvm-{tool}{ext}")
            if os.path.exists(tool_path) and os.path.isfile(tool_path):
                tools[tool.upper()] = tool_path
                tool_found = True
                break
                
            # 再尝试不带llvm-前缀的工具
            tool_path = os.path.join(bin_dir, f"{tool}{ext}")
            if os.path.exists(tool_path) and os.path.isfile(tool_path):
                tools[tool.upper()] = tool_path
                tool_found = True
                break
        
        if not tool_found:
            # 如果找不到工具，使用默认路径，后续会处理
            print(f"警告: 未找到工具 {tool}，将尝试使用替代方法")
            tools[tool.upper()] = os.path.join(bin_dir, f"llvm-{tool}")
    
    # 打印工具路径确认
    print("\n编译工具设置:")
    for tool_name, tool_path in tools.items():
        exists = "✓" if os.path.exists(tool_path) else "✗"
        print(f"  {tool_name}: {tool_path} {exists}")
    
    return tools

def extract_text_section_lief(obj_file, bin_file):
    """使用LIEF库提取.text段"""
    try:
        binary = lief.parse(obj_file)
        text_section = binary.get_section(".text")
        
        if text_section:
            print(f"找到.text段: 偏移=0x{text_section.offset:x}, 大小=0x{text_section.size:x}")
            with open(bin_file, 'wb') as f:
                f.write(bytes(text_section.content))
            return True
        else:
            print("未找到.text段")
            return False
    except Exception as e:
        print(f"使用LIEF提取失败: {e}")
        return False

def extract_text_section_elftools(obj_file, bin_file):
    """使用pyelftools提取.text段"""
    try:
        with open(obj_file, 'rb') as f:
            elf = ELFFile(f)
            text_section = elf.get_section_by_name('.text')
            
            if text_section:
                data = text_section.data()
                offset = text_section.header['sh_offset']
                size = text_section.header['sh_size']
                print(f"找到.text段: 偏移=0x{offset:x}, 大小=0x{size:x}")
                
                with open(bin_file, 'wb') as bf:
                    bf.write(data)
                return True
            else:
                print("未找到.text段")
                return False
    except Exception as e:
        print(f"使用pyelftools提取失败: {e}")
        return False

def extract_text_section_readelf(obj_file, bin_file, readelf_tool):
    """使用readelf工具提取.text段"""
    try:
        if os.path.exists(readelf_tool):
            print("使用readelf读取节信息...")
            cmd = [readelf_tool, "-S", obj_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # 解析输出找到.text段
                output = result.stdout
                text_offset = None
                text_size = None
                
                for line in output.splitlines():
                    if ".text" in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == ".text":
                                # 尝试解析偏移量和大小
                                for j, field in enumerate(parts[i:]):
                                    if "OFFSET" in field or "ADDR" in field:
                                        try:
                                            text_offset = int(parts[i+j+1], 16)
                                        except Exception:
                                            pass
                                    if "SIZE" in field:
                                        try:
                                            text_size = int(parts[i+j+1], 16)
                                        except Exception:
                                            pass
                                break
            
                if text_offset is not None and text_size is not None:
                    print(f"找到.text段: 偏移=0x{text_offset:x}, 大小=0x{text_size:x}")
                    # 读取目标文件并提取.text段
                    with open(obj_file, 'rb') as f:
                        data = f.read()
                        text_data = data[text_offset:text_offset+text_size]
                        with open(bin_file, 'wb') as bf:
                            bf.write(text_data)
                        return True
                else:
                    print("无法在readelf输出中找到.text段信息")
            else:
                print(f"readelf执行失败: {result.stderr}")
        else:
            print("未找到readelf工具")
        return False
    except Exception as e:
        print(f"使用readelf提取失败: {e}")
        return False

def extract_text_section_fallback(obj_file, bin_file):
    """使用简单的启发式方法提取.text段（作为最后的备用方案）"""
    try:
        # 简单的ELF解析以提取.text段
        # 注意：这只是一个非常基本的实现，可能不适用于所有情况
        with open(obj_file, 'rb') as f:
            elf_data = f.read()
        
        # 简单查找.text段的特征
        text_section = b".text\0"
        idx = elf_data.find(text_section)
        if idx >= 0:
            # 使用二进制特征模式寻找.text段
            # 这是一个非常简化的实现，仅用于紧急情况
            
            # ELF节头通常在文本名称后面有类型、标志、地址等信息
            # 我们尝试查找这些结构来定位实际内容
            
            # 尝试几种常见的内容定位策略
            strategies = [
                (idx + len(text_section) + 24, len(elf_data) - 100),  # 策略1：粗略估计
                (idx + 64, len(elf_data) - 64),                      # 策略2：大范围
            ]
            
            for start, end in strategies:
                try:
                    if start < end and start > 0 and end < len(elf_data):
                        # 需要至少有一些数据才有意义
                        data_slice = elf_data[start:end]
                        if len(data_slice) > 32:  # 确保有足够的数据
                            # 查找常见的结束模式
                            # 通常.text段后面会有其他段，如.data或.bss
                            end_markers = [b".data", b".bss", b".rodata", b".eh_frame"]
                            for marker in end_markers:
                                marker_idx = data_slice.find(marker)
                                if marker_idx > 32:  # 需要至少有一些有效内容
                                    data_slice = data_slice[:marker_idx]
                                    break
                            
                            with open(bin_file, 'wb') as bf:
                                bf.write(data_slice)
                            print(f"已提取估计的.text段到: {bin_file} (警告：这是一个不精确的提取)")
                            print(f"提取范围: 0x{start:x} - 0x{start+len(data_slice):x}")
                            return True
                except Exception:
                    continue
            
            # 如果上面的策略都失败，使用最简单的估计
            text_start = idx + len(text_section) + 24
            text_end = min(text_start + 4096, len(elf_data) - 1)  # 使用合理的大小限制
            
            with open(bin_file, 'wb') as bf:
                bf.write(elf_data[text_start:text_end])
            print(f"已提取估计的.text段到: {bin_file} (警告：这是一个极不精确的提取)")
            return True
        else:
            print("错误：无法找到.text段标记")
            return False
    except Exception as e:
        print(f"备用提取方法失败: {e}")
        return False

def compile_shellcode(src_file, tools, output_dir):
    """编译源文件并提取shellcode"""
    # 创建输出目录
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"确保输出目录存在: {output_dir}")
        
        # 验证目录权限
        test_file = os.path.join(output_dir, "test_write.tmp")
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        print("已验证输出目录具有写入权限")
    except Exception as e:
        print(f"无法创建或写入输出目录 {output_dir}: {e}")
        sys.exit(1)
    
    # 获取文件基名（不包括扩展名）
    base_name = os.path.splitext(os.path.basename(src_file))[0]
    
    # 输出文件路径，确保使用正确的路径分隔符
    obj_file = os.path.normpath(os.path.join(output_dir, f"{base_name}.o"))
    asm_file = os.path.normpath(os.path.join(output_dir, f"{base_name}.s"))
    bin_file = os.path.normpath(os.path.join(output_dir, f"{base_name}.bin"))
    
    print(f"编译 {src_file} 为目标文件...")
    print(f"目标文件路径: {obj_file}")
    print(f"汇编文件路径: {asm_file}")
    
    # 编译为目标文件
    cmd_args = [
        tools["CC"],
        "-fPIC",
        "-fno-stack-protector",
        "-nostdlib",
        "-O1",  # 禁用优化
        "-Wall",
        "-Werror",
        "-fbuiltin",
        "-fomit-frame-pointer",  # 省略栈帧指针
        "-c",
        src_file,
        "-o", obj_file
    ]
    
    # 首先编译目标文件
    cmd_str = " ".join(cmd_args)
    print(f"执行命令: {cmd_str}")
    
    # 在Windows上使用os.system而不是subprocess，因为后者在处理路径时可能有问题
    if platform.system() == "Windows":
        return_code = os.system(cmd_str)
        if return_code != 0:
            print(f"编译失败，返回代码: {return_code}")
            sys.exit(1)
    else:
        try:
            result = subprocess.run(cmd_args, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"编译失败:\n{result.stderr}")
                sys.exit(1)
        except Exception as e:
            print(f"执行编译命令时出错: {e}")
            sys.exit(1)
    
    # 然后生成汇编文件
    asm_cmd_args = [
        tools["CC"],
        "-fPIC",
        "-fno-stack-protector",
        "-nostdlib",
        "-O1",
        "-Wall",
        "-Werror",
        "-fomit-frame-pointer",
        "-fbuiltin",
        "-S",
        src_file,
        "-o", asm_file
    ]
    
    asm_cmd_str = " ".join(asm_cmd_args)
    print(f"执行命令生成汇编: {asm_cmd_str}")
    
    if platform.system() == "Windows":
        return_code = os.system(asm_cmd_str)
        if return_code != 0:
            print(f"生成汇编失败，返回代码: {return_code}")
            # 不退出，因为已经有了目标文件
    else:
        try:
            result = subprocess.run(asm_cmd_args, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"生成汇编失败:\n{result.stderr}")
                # 不退出，因为已经有了目标文件
        except Exception as e:
            print(f"执行生成汇编命令时出错: {e}")
            # 不退出，因为已经有了目标文件
    
    # 验证编译结果
    if not os.path.exists(obj_file) or os.path.getsize(obj_file) == 0:
        print(f"错误: 编译后目标文件未生成或为空: {obj_file}")
        print("可能的原因:")
        print("1. 编译器未正确执行")
        print("2. 输出路径有问题")
        print("3. 权限不足")
        
        # 最后尝试，使用更简单的命令
        print("\n尝试备用编译方法:")
        direct_obj = os.path.join(output_dir, "direct.o")
        # 使用正斜杠，这在Windows和Unix都工作
        direct_obj = direct_obj.replace("\\", "/")
        src_file_slash = src_file.replace("\\", "/")
        
        direct_cmd = f"{tools['CC']} -fPIC -fno-stack-protector -nostdlib -c {src_file_slash} -o {direct_obj}"
        print(direct_cmd)
        
        return_code = os.system(direct_cmd)
        if return_code == 0 and os.path.exists(direct_obj) and os.path.getsize(direct_obj) > 0:
            print("备用命令成功生成了目标文件！")
            # 使用备用生成的文件
            shutil.copy(direct_obj, obj_file)
            print(f"已复制 {direct_obj} 到 {obj_file}")
        else:
            print("所有编译尝试都失败了")
            sys.exit(1)
    
    if not os.path.exists(asm_file):
        print(f"警告: 汇编文件未生成: {asm_file}，但目标文件已存在，继续处理")
    
    print(f"已生成目标文件: {obj_file} (大小: {os.path.getsize(obj_file)} 字节)")
    if os.path.exists(asm_file):
        print(f"已生成汇编文件: {asm_file} (大小: {os.path.getsize(asm_file)} 字节)")
    
    # 尝试提取.text段
    print("\n开始提取.text段...")
    
    # 检查 objcopy 是否存在并可用
    objcopy_exists = os.path.exists(tools["OBJCOPY"])
    extract_success = False
    
    # 方法1: 使用objcopy工具（如果可用）
    if objcopy_exists:
        print("尝试方法1: 使用objcopy提取二进制shellcode...")
        objcopy_cmd = f"{tools['OBJCOPY']} -O binary --only-section=.text {obj_file} {bin_file}"
        print(f"执行命令: {objcopy_cmd}")
        
        if platform.system() == "Windows":
            return_code = os.system(objcopy_cmd)
            if return_code == 0:
                print("成功使用objcopy提取.text段")
                extract_success = True
            else:
                print(f"objcopy提取失败，返回代码: {return_code}")
        else:
            try:
                result = subprocess.run([tools["OBJCOPY"], "-O", "binary", "--only-section=.text", obj_file, bin_file], 
                                        capture_output=True, text=True)
                if result.returncode == 0:
                    print("成功使用objcopy提取.text段")
                    extract_success = True
                else:
                    print(f"objcopy提取失败: {result.stderr}")
            except Exception as e:
                print(f"执行objcopy命令时出错: {e}")
    
    # 方法2: 使用LIEF库
    if not extract_success and HAS_LIEF:
        print("\n尝试方法2: 使用LIEF库提取...")
        extract_success = extract_text_section_lief(obj_file, bin_file)
    
    # 方法3: 使用pyelftools库
    if not extract_success and HAS_ELFTOOLS:
        print("\n尝试方法3: 使用pyelftools库提取...")
        extract_success = extract_text_section_elftools(obj_file, bin_file)
    
    # 方法4: 使用readelf工具
    if not extract_success:
        print("\n尝试方法4: 使用readelf工具提取...")
        extract_success = extract_text_section_readelf(obj_file, bin_file, tools["READELF"])
    
    # 方法5: 备用方法 - 使用简单的启发式方法
    if not extract_success:
        print("\n尝试最后方法: 使用备用提取方法...")
        extract_success = extract_text_section_fallback(obj_file, bin_file)
    
    if not extract_success:
        print("\n错误: 所有提取方法都失败了")
        sys.exit(1)
    
    # 显示shellcode大小
    bin_size = os.path.getsize(bin_file)
    print(f"\nShellcode大小: {bin_size} 字节")
    
    # 显示shellcode内容预览
    try:
        with open(bin_file, "rb") as f:
            data = f.read()
            
        print("\nShellcode预览 (十六进制):")
        for i in range(0, min(64, len(data)), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            print(f"{i:04x}: {hex_str}")
        
        # 转换为C数组格式
        c_array_file = os.path.join(output_dir, f"{base_name}_array.h")
        with open(c_array_file, 'w') as f:
            f.write(f"// 自动生成的 {base_name} shellcode 数组\n")
            f.write(f"// 大小: {bin_size} 字节\n\n")
            f.write(f"unsigned char {base_name}_shellcode[] = {{\n    ")
            
            for i, b in enumerate(data):
                f.write(f"0x{b:02x}")
                if i < len(data) - 1:
                    f.write(", ")
                if (i + 1) % 12 == 0 and i < len(data) - 1:
                    f.write("\n    ")
            
            f.write("\n};\n")
            f.write(f"\nconst unsigned int {base_name}_shellcode_size = {bin_size};\n")
        
        print(f"已生成C数组头文件: {c_array_file}")
        
    except Exception as e:
        print(f"处理shellcode失败: {e}")
    
    return {
        "object": obj_file,
        "binary": bin_file,
        "assembly": asm_file,
        "c_array": c_array_file,
        "size": bin_size
    }

def main():
    parser = argparse.ArgumentParser(description="编译ARM64 shellcode")
    parser.add_argument("--ndk", help="Android NDK路径", default=None)
    parser.add_argument("--arch", help="目标架构", default="arm64-v8a", 
                        choices=["arm64-v8a"])
    parser.add_argument("--api", help="目标Android API级别", type=int, default=None)
    parser.add_argument("--output", "-o", help="输出目录", default="build")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")
    parser.add_argument("--install-deps", action="store_true", help="安装缺少的依赖库")
    
    args = parser.parse_args()
    
    # 检查是否需要安装依赖
    if args.install_deps:
        print("尝试安装ELF处理库...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "lief"])
            print("成功安装LIEF库")
        except Exception as e:
            print(f"安装LIEF失败: {e}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pyelftools"])
                print("成功安装pyelftools库")
            except Exception as e:
                print(f"安装pyelftools失败: {e}")
        sys.exit(0)
    
    # 显示操作系统信息
    print(f"操作系统: {platform.system()} {platform.version()}")
    print(f"Python版本: {platform.python_version()}")
    
    # 提示用户安装依赖库
    if not HAS_LIEF and not HAS_ELFTOOLS:
        print("\n提示: 未找到任何ELF处理库，提取过程可能不可靠")
        print("     建议安装LIEF或pyelftools库以提高提取精度")
        print("     可以通过运行此脚本加上 --install-deps 参数安装依赖")
        print("     例如: python loader.py --install-deps\n")
    
    # 查找NDK路径
    ndk_path = args.ndk or find_ndk()
    if not ndk_path:
        print("错误: 未指定NDK路径，且无法自动查找。")
        print("请使用 --ndk 参数指定NDK路径。")
        sys.exit(1)
    
    # 确保NDK路径存在
    if not os.path.exists(ndk_path):
        print(f"错误: NDK路径不存在: {ndk_path}")
        sys.exit(1)
    
    print(f"使用NDK: {ndk_path}")
    
    # 如果指定了API级别，显示信息
    if args.api:
        print(f"目标API级别: {args.api}")
    
    # 设置编译器
    try:
        tools = setup_compilers(ndk_path, args.arch, args.api)
        if args.verbose:
            print(f"编译器设置: {tools}")
        else:
            print(f"编译器: {os.path.basename(tools['CC'])}")
    except ValueError as e:
        print(f"错误: {e}")
        sys.exit(1)
    
    # 查找源文件
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_file = os.path.join(script_dir, "loader.c")
    
    if not os.path.exists(src_file):
        print(f"错误: 源文件不存在: {src_file}")
        sys.exit(1)
    
    # 设置输出目录
    output_dir = os.path.join(script_dir, args.output)
    
    # 编译
    try:
        result = compile_shellcode(src_file, tools, output_dir)
        print("\n编译完成!")
        print(f"目标文件: {result['object']}")
        print(f"汇编文件: {result['assembly']}")
        print(f"Shellcode: {result['binary']} ({result['size']} 字节)")
        if 'c_array' in result:
            print(f"C数组头文件: {result['c_array']}")
    except Exception as e:
        print(f"编译失败: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 