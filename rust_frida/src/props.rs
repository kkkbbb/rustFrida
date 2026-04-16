#![cfg(all(target_os = "android", target_arch = "aarch64"))]

//! 属性覆盖伪装模块：dump 本机属性 → 定制修改 → zymbiote 自动 mount+remap
//!
//! 工作流程:
//! 1. `--dump-props <profile>`: 复制 /dev/__properties__/ 到 profile 目录 + getprop 输出
//! 2. 用户编辑 profile 目录下的 override.prop (key=value 格式)
//! 3. `--spawn <pkg> --profile <profile>`: 预处理(patch 文件) → zymbiote 在 fork 后自动 mount+remap

use std::collections::HashMap;
use std::ffi::c_void;

use crate::{log_info, log_step, log_success, log_verbose, log_warn};

/// 属性 profile 存储目录（放在 /dev/__properties__/ 下，app 可读）
pub(crate) const PROP_PROFILES_DIR: &str = "/dev/__properties__/.profiles";
/// 系统属性区域目录
const PROP_SRC_DIR: &str = "/dev/__properties__";
/// prop_area magic: "PROP" in LE
const PROP_AREA_MAGIC: u32 = 0x504f5250;
/// prop_area header 大小
const PROP_AREA_HEADER_SIZE: usize = 128;
/// prop_info value 字段大小 (PROP_VALUE_MAX)
const PROP_VALUE_MAX: usize = 92;

/// 设置文件的 SELinux context（通过 lsetxattr）
fn set_selinux_context(path: &str, context: &str) {
    let path_cstr = format!("{}\0", path);
    let ctx_cstr = format!("{}\0", context);
    let ret = unsafe {
        libc::lsetxattr(
            path_cstr.as_ptr() as *const libc::c_char,
            b"security.selinux\0".as_ptr() as *const libc::c_char,
            ctx_cstr.as_ptr() as *const c_void,
            ctx_cstr.len(),
            0,
        )
    };
    if ret != 0 {
        log_verbose!("lsetxattr({}, {}) 失败: {}", path, context, std::io::Error::last_os_error());
    }
}

/// 从文件名推断 SELinux context
///
/// prop area 文件名即为其 context (u:object_r:xxx:s0)，
/// 特殊文件 (properties_serial, property_info) 各有固定 context。
fn selinux_context_from_filename(filename: &str) -> Option<&str> {
    if filename.starts_with("u:") {
        Some(filename)
    } else {
        match filename {
            "properties_serial" => Some("u:object_r:properties_serial:s0"),
            "property_info" => Some("u:object_r:property_info:s0"),
            _ => None,
        }
    }
}

// ─── 公开 API ────────────────────────────────────────────────────────────────

/// Dump 本机属性到 profile
pub(crate) fn dump_props(profile_name: &str) -> Result<(), String> {
    let profile_dir = format!("{}/{}", PROP_PROFILES_DIR, profile_name);

    log_step!("Dump 属性到 profile: {}", profile_name);

    std::fs::create_dir_all(&profile_dir)
        .map_err(|e| format!("创建目录 {} 失败: {}", profile_dir, e))?;

    // 复制 /dev/__properties__/ 下所有文件
    let entries = std::fs::read_dir(PROP_SRC_DIR)
        .map_err(|e| format!("读取 {} 失败: {}", PROP_SRC_DIR, e))?;

    let mut count = 0u32;
    for entry in entries {
        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let src = entry.path();
        if !src.is_file() {
            continue;
        }
        let filename = entry.file_name().to_string_lossy().to_string();
        let dst = format!("{}/{}", profile_dir, filename);
        std::fs::copy(&src, &dst)
            .map_err(|e| format!("复制 {:?} → {} 失败: {}", src, dst, e))?;
        // 恢复 SELinux context（文件名即 context，如 u:object_r:build_prop:s0）
        if let Some(ctx) = selinux_context_from_filename(&filename) {
            set_selinux_context(&dst, ctx);
        }
        count += 1;
    }
    log_info!("已复制 {} 个属性区域文件", count);

    // Dump getprop 输出（参考）
    let output = std::process::Command::new("getprop")
        .output()
        .map_err(|e| format!("执行 getprop 失败: {}", e))?;
    std::fs::write(format!("{}/props.txt", profile_dir), &output.stdout)
        .map_err(|e| format!("写入 props.txt 失败: {}", e))?;

    log_success!("Profile '{}' 已保存到 {}", profile_name, profile_dir);
    log_info!("  用 --set-prop {} <key=value> 修改属性", profile_name);
    log_info!("  用 --spawn <pkg> --profile {} 应用", profile_name);

    Ok(())
}

/// 修改 profile 中的属性值（类似 resetprop）
pub(crate) fn set_prop(profile_name: &str, key_value: &str) -> Result<(), String> {
    let profile_dir = format!("{}/{}", PROP_PROFILES_DIR, profile_name);

    if !std::path::Path::new(&profile_dir).exists() {
        return Err(format!(
            "Profile '{}' 不存在，先运行: rustfrida --dump-props {}",
            profile_name, profile_name
        ));
    }

    let (key, value) = key_value.split_once('=').ok_or_else(|| {
        format!("格式错误，应为 key=value: {}", key_value)
    })?;
    let key = key.trim();
    let value = value.trim();

    if key.is_empty() {
        return Err("属性名不能为空".to_string());
    }
    let mut overrides = HashMap::new();
    overrides.insert(key.to_string(), value.to_string());

    let (count, _modified_files) = patch_prop_files(&profile_dir, &overrides)?;
    if count == 0 {
        // 属性不存在，添加新属性到最匹配的 prop_area 文件
        log_info!("属性 {} 不存在，添加新属性...", key);
        add_prop_to_profile(&profile_dir, key, value)?;
    }
    // 注意: 不再调用 erase_dead_props_in_dir
    // short→short 修改不产生空洞，无需重建 trie。
    // long→short 产生空洞但不影响 bionic 读取（空洞只浪费空间）。
    // 如需清理空洞，用 --repack-props 显式执行。

    log_success!("{} = {}", key, value);
    Ok(())
}

/// 删除 profile 中的属性（彻底抹除：清零 prop_info + 断开 trie 指针）
pub(crate) fn del_prop(profile_name: &str, key: &str) -> Result<(), String> {
    let profile_dir = format!("{}/{}", PROP_PROFILES_DIR, profile_name);

    if !std::path::Path::new(&profile_dir).exists() {
        return Err(format!(
            "Profile '{}' 不存在，先运行: rustfrida --dump-props {}",
            profile_name, profile_name
        ));
    }

    let key = key.trim();
    if key.is_empty() {
        return Err("属性名不能为空".to_string());
    }

    // Step 1: 清零 value + serial（通过 patch_prop_files）
    let mut overrides = HashMap::new();
    overrides.insert(key.to_string(), String::new());

    let (count, modified_files) = patch_prop_files(&profile_dir, &overrides)?;
    if count == 0 {
        return Err(format!("未在属性文件中找到: {}", key));
    }

    // Step 2: 重建被修改的文件，抹除已删除属性的所有痕迹
    erase_dead_props_in_dir(&profile_dir, Some(&modified_files))?;

    log_success!("已删除: {}", key);
    Ok(())
}

/// 清理 profile：抹除已删除属性的所有痕迹（原地操作，不改变 trie 布局）
pub(crate) fn repack_props(profile_name: &str) -> Result<(), String> {
    let profile_dir = format!("{}/{}", PROP_PROFILES_DIR, profile_name);

    if !std::path::Path::new(&profile_dir).exists() {
        return Err(format!("Profile '{}' 不存在", profile_name));
    }

    let total = erase_dead_props_in_dir(&profile_dir, None)?;
    if total == 0 {
        log_info!("无需清理（没有已删除属性）");
    } else {
        log_success!("已抹除 {} 条已删除属性的痕迹", total);
    }
    Ok(())
}

/// 扫描 profile 目录，重建含已删除属性的 prop_area 文件，返回抹除数量
///
/// 重建策略: trie 从零构建（消除空洞和孤立节点），但每个存活 prop_info
/// 保留原始文件偏移（remap 后 zygote 缓存的 prop_info* 指针依然有效）。
/// `only_files`: 仅重建指定文件名（None = 所有文件）
fn erase_dead_props_in_dir(profile_dir: &str, only_files: Option<&[String]>) -> Result<u32, String> {
    let entries = std::fs::read_dir(profile_dir)
        .map_err(|e| format!("读取 {} 失败: {}", profile_dir, e))?;

    let mut total_erased = 0u32;

    for entry in entries {
        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let filename = entry.file_name().to_string_lossy().to_string();
        if matches!(filename.as_str(), "props.txt" | "properties_serial" | "property_info" | ".active") {
            continue;
        }
        // 仅处理指定文件
        if let Some(files) = only_files {
            if !files.iter().any(|f| f == &filename) {
                continue;
            }
        }

        let data = std::fs::read(&path)
            .map_err(|e| format!("读取 {:?} 失败: {}", path, e))?;

        if data.len() < PROP_AREA_HEADER_SIZE {
            continue;
        }
        let magic = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if magic != PROP_AREA_MAGIC {
            continue;
        }

        let all = parse_prop_area_with_offsets(&data);
        let alive: Vec<_> = all.iter().filter(|(_, v, _)| !v.is_empty()).cloned().collect();

        let new_data = rebuild_prop_area_preserving_offsets(&data, &alive);
        if new_data != data {
            std::fs::write(&path, &new_data)
                .map_err(|e| format!("写回 {:?} 失败: {}", path, e))?;
            total_erased += 1;
        }
    }

    Ok(total_erased)
}

/// 解析 prop_area，返回 (key, value, prop_info 在 data_section 中的偏移)
fn parse_prop_area_with_offsets(data: &[u8]) -> Vec<(String, String, usize)> {
    let mut result = Vec::new();
    if data.len() < PROP_AREA_HEADER_SIZE {
        return result;
    }
    let ds = &data[PROP_AREA_HEADER_SIZE..];
    if !ds.is_empty() {
        walk_trie_with_offsets(ds, 0, &mut result);
    }
    result
}

fn walk_trie_with_offsets(data: &[u8], offset: usize, result: &mut Vec<(String, String, usize)>) {
    if offset + 20 > data.len() {
        return;
    }
    let namelen = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    let prop_off = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
    let left = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()) as usize;
    let right = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap()) as usize;
    let children = u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap()) as usize;

    if left != 0 { walk_trie_with_offsets(data, left, result); }
    let name_start = offset + 20;
    if name_start + namelen <= data.len() {
        if prop_off != 0 {
            if let Some((key, value)) = read_prop_info(data, prop_off) {
                result.push((key, value, prop_off));
            }
        }
        if children != 0 { walk_trie_with_offsets(data, children, result); }
    }
    if right != 0 { walk_trie_with_offsets(data, right, result); }
}

/// 重建 prop_area: trie 从零构建（无空洞），prop_info 保留原始偏移
fn rebuild_prop_area_preserving_offsets(
    original: &[u8],
    alive: &[(String, String, usize)],
) -> Vec<u8> {
    let area_size = original.len();
    let mut data = vec![0u8; area_size];
    let data_start = PROP_AREA_HEADER_SIZE;
    let data_cap = area_size - data_start;

    // 复制 header
    data[..PROP_AREA_HEADER_SIZE].copy_from_slice(&original[..PROP_AREA_HEADER_SIZE]);

    // 计算保留区域: prop_info + long value（如果是 long property）
    let mut reserved: Vec<(usize, usize)> = Vec::new();
    for (name, _, pi_off) in alive {
        let pi_base = (4 + PROP_VALUE_MAX + name.len() + 1 + 3) & !3;
        reserved.push((*pi_off, pi_base));

        // 检测 long property: serial kLongFlag (bit 16)
        let serial_abs = data_start + pi_off;
        if serial_abs + 4 + 60 <= original.len() {
            let serial = u32::from_le_bytes(
                original[serial_abs..serial_abs + 4].try_into().unwrap(),
            );
            if serial & (1u32 << 16) != 0 {
                // long value offset 在 value[56..60]
                let offset = u32::from_le_bytes(
                    original[serial_abs + 4 + 56..serial_abs + 4 + 60].try_into().unwrap(),
                ) as usize;
                let long_abs = serial_abs + offset;
                if long_abs < original.len() {
                    let long_len = original[long_abs..].iter()
                        .position(|&b| b == 0).unwrap_or(0);
                    let long_ds_off = long_abs - data_start;
                    reserved.push((long_ds_off, (long_len + 1 + 3) & !3));
                }
            }
        }
    }
    reserved.sort_by_key(|&(off, _)| off);

    // 复制保留区域（prop_info + long value）到新文件的相同偏移
    for &(off, size) in &reserved {
        let s = data_start + off;
        let e = (s + size).min(area_size);
        data[s..e].copy_from_slice(&original[s..e]);
    }

    // Bump allocator: 跳过保留区域
    let mut alloc_pos = 0usize;
    let mut bump = |size: usize| -> Option<usize> {
        loop {
            let aligned = (alloc_pos + 3) & !3;
            let end = aligned + size;
            if end > data_cap { return None; }
            let conflict = reserved.iter().any(|&(rs, rsz)| aligned < rs + rsz && end > rs);
            if !conflict {
                alloc_pos = end;
                return Some(aligned);
            }
            let skip_to = reserved.iter()
                .filter(|&&(rs, rsz)| aligned < rs + rsz && end > rs)
                .map(|&(rs, rsz)| rs + rsz)
                .max().unwrap();
            alloc_pos = skip_to;
        }
    };

    // 根哨兵
    let _root = bump(20).unwrap();

    // prop_info 查找表
    let pi_map: HashMap<&str, usize> = alive.iter().map(|(k, _, off)| (k.as_str(), *off)).collect();

    // 辅助宏: 读写 data section 中的 u32
    macro_rules! ds_read_u32 {
        ($off:expr) => {
            u32::from_le_bytes(data[data_start + $off..data_start + $off + 4].try_into().unwrap())
        };
    }
    macro_rules! ds_write_u32 {
        ($off:expr, $val:expr) => {
            data[data_start + $off..data_start + $off + 4].copy_from_slice(&($val as u32).to_le_bytes());
        };
    }

    for (name, _, _) in alive {
        let parts: Vec<&str> = name.split('.').collect();
        let mut parent_children_ptr = 16usize;

        for (depth, part) in parts.iter().enumerate() {
            let is_leaf = depth == parts.len() - 1;
            let mut cur_ptr = parent_children_ptr;

            loop {
                let cur = ds_read_u32!(cur_ptr);
                if cur == 0 {
                    let nl = part.len();
                    let node = match bump(20 + nl) { Some(o) => o, None => break };
                    ds_write_u32!(node, nl);
                    data[data_start + node + 20..data_start + node + 20 + nl]
                        .copy_from_slice(part.as_bytes());
                    ds_write_u32!(cur_ptr, node);
                    if is_leaf {
                        if let Some(&pi) = pi_map.get(name.as_str()) {
                            ds_write_u32!(node + 4, pi);
                        }
                    }
                    parent_children_ptr = node + 16;
                    break;
                } else {
                    let co = cur as usize;
                    let nl = ds_read_u32!(co) as usize;
                    let cmp = {
                        let cn = &data[data_start + co + 20..data_start + co + 20 + nl];
                        // AOSP cmp_prop_name: 先比长度，同长度再比内容
                        if part.len() < nl { std::cmp::Ordering::Less }
                        else if part.len() > nl { std::cmp::Ordering::Greater }
                        else { part.as_bytes().cmp(cn) }
                    };
                    match cmp {
                        std::cmp::Ordering::Less => cur_ptr = co + 8,
                        std::cmp::Ordering::Greater => cur_ptr = co + 12,
                        std::cmp::Ordering::Equal => {
                            if is_leaf {
                                if let Some(&pi) = pi_map.get(name.as_str()) {
                                    ds_write_u32!(co + 4, pi);
                                }
                            }
                            parent_children_ptr = co + 16;
                            break;
                        }
                    }
                }
            }
        }
    }

    let max_pi = reserved.iter().map(|&(o, s)| o + s).max().unwrap_or(0);
    data[0..4].copy_from_slice(&(alloc_pos.max(max_pi) as u32).to_le_bytes());
    data
}

/// 激活属性 profile：写 .active 文件，返回 profile 目录路径
///
/// 在 spawn_and_inject 之前调用。zymbiote 在 fork 的子进程中
/// 读取 .active 自动 mount bind + remap。
pub(crate) fn prep_prop_profile(profile_name: &str) -> Result<String, String> {
    let profile_dir = format!("{}/{}", PROP_PROFILES_DIR, profile_name);

    if !std::path::Path::new(&profile_dir).exists() {
        return Err(format!(
            "Profile '{}' 不存在，先运行: rustfrida --dump-props {}",
            profile_name, profile_name
        ));
    }

    // 写 .active 文件：zymbiote 读取此文件获取 profile 目录路径
    let active_path = format!("{}/.active", PROP_PROFILES_DIR);
    std::fs::write(&active_path, format!("{}\n", profile_dir))
        .map_err(|e| format!("写入 {} 失败: {}", active_path, e))?;

    log_info!("属性 profile '{}' 已激活", profile_name);
    Ok(profile_dir)
}

// ─── 内部实现 ────────────────────────────────────────────────────────────────

/// 解析 property_info 二进制 trie，查找属性名对应的 context (area file name)。
/// property_info 格式: header(32B) + ... + contexts_table + trie_nodes
fn lookup_property_context(profile_dir: &str, key: &str) -> Option<String> {
    let pi_path = format!("{}/property_info", profile_dir);
    let data = std::fs::read(&pi_path).ok()?;
    if data.len() < 32 { return None; }

    let contexts_off = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
    let root_off = u32::from_le_bytes(data[28..32].try_into().ok()?) as usize;

    // 读取 contexts 字符串表（null-separated list）
    let contexts_data = &data[contexts_off..];

    // 遍历 property_info trie 查找最佳匹配的 context
    // property_info_area_node 布局:
    //   uint32_t name_offset     +0  (相对于 context_area 起始)
    //   uint32_t name_length     +4
    //   uint32_t context_index   +8
    //   uint32_t type_index      +12
    //   uint32_t left            +16
    //   uint32_t right           +20
    //   uint32_t children        +24
    //   uint32_t name_length_2   +28 (? 有些版本不同)
    // 但实际格式可能更简单。用 prefix match 方式遍历。

    // 简单方案: 从 /dev/__properties__/ 上的 property_contexts 或 plat_property_contexts 读取
    // 这些是文本文件，格式: prefix context_name
    let ctx_files = [
        "/system/etc/selinux/plat_property_contexts",
        "/vendor/etc/selinux/vendor_property_contexts",
        "/system_ext/etc/selinux/system_ext_property_contexts",
    ];

    let mut best_prefix = String::new();
    let mut best_context = String::new();

    for ctx_file in &ctx_files {
        if let Ok(content) = std::fs::read_to_string(ctx_file) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 { continue; }
                let prefix = parts[0];
                let context = parts[1];
                // 精确匹配或前缀匹配
                let matches = if prefix.ends_with('*') {
                    let p = &prefix[..prefix.len()-1];
                    key.starts_with(p) && p.len() > best_prefix.len()
                } else {
                    key == prefix && prefix.len() > best_prefix.len()
                };
                if matches {
                    best_prefix = prefix.to_string();
                    best_context = context.to_string();
                }
            }
        }
    }

    if best_context.is_empty() {
        return None;
    }

    // context 格式: "u:object_r:bootloader_prop:s0" → 返回 area file name
    Some(best_context)
}

/// 前缀启发式选择最匹配的 area file（fallback）
fn find_best_match_area(profile_dir: &str, key: &str) -> Result<String, String> {
    let entries = std::fs::read_dir(profile_dir)
        .map_err(|e| format!("读取 {} 失败: {}", profile_dir, e))?;

    let key_parts: Vec<&str> = key.split('.').collect();
    let mut best_path: Option<String> = None;
    let mut best_count: usize = 0;
    let mut best_score: usize = 0;

    for entry in entries {
        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let path = entry.path();
        if !path.is_file() { continue; }
        let filename = entry.file_name().to_string_lossy().to_string();
        if matches!(filename.as_str(),
            "props.txt" | "override.prop" | "properties_serial" | "property_info" | ".active"
        ) { continue; }

        let data = std::fs::read(&path).map_err(|e| format!("读取 {:?} 失败: {}", path, e))?;
        if data.len() < PROP_AREA_HEADER_SIZE { continue; }
        let magic = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if magic != PROP_AREA_MAGIC { continue; }

        let props = parse_prop_area(&data);
        if props.is_empty() { continue; }

        let mut file_score = 0usize;
        for (existing_key, _) in &props {
            let existing_parts: Vec<&str> = existing_key.split('.').collect();
            let common = key_parts.iter().zip(existing_parts.iter())
                .take_while(|(a, b)| a == b).count();
            if common > file_score { file_score = common; }
        }

        let better = match &best_path {
            None => true,
            Some(_) => file_score > best_score
                || (file_score == best_score && props.len() > best_count),
        };
        if better {
            best_path = Some(path.to_string_lossy().to_string());
            best_count = props.len();
            best_score = file_score;
        }
    }

    best_path.ok_or_else(|| "Profile 中没有可用的属性区域文件".to_string())
}

/// 向 profile 中添加新属性（当属性不存在时）
fn add_prop_to_profile(
    profile_dir: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    // 策略 1: 解析 property_info 获取精确的 context name
    let target_path = if let Some(ctx) = lookup_property_context(profile_dir, key) {
        let path = format!("{}/{}", profile_dir, ctx);
        if std::path::Path::new(&path).exists() {
            path
        } else {
            find_best_match_area(profile_dir, key)?
        }
    } else {
        // 策略 2: property_info 没找到映射，用前缀启发式
        find_best_match_area(profile_dir, key)?
    };

    // 在原始文件上原地插入新属性（保留 trie 布局）
    let mut data = std::fs::read(&target_path)
        .map_err(|e| format!("读取 {} 失败: {}", target_path, e))?;

    insert_prop_inplace(&mut data, key, value)?;

    std::fs::write(&target_path, &data)
        .map_err(|e| format!("写回 {} 失败: {}", target_path, e))?;

    let filename = std::path::Path::new(&target_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    if let Some(ctx) = selinux_context_from_filename(&filename) {
        set_selinux_context(&target_path, ctx);
    }
    log_info!(
        "添加新属性 [{}] 到 {}",
        key,
        filename,
    );

    Ok(())
}

/// 在 prop_area 原始二进制数据上原地插入新属性
///
/// 从 header.bytes_used 处接着分配 trie 节点和 prop_info，
/// 沿着已有 trie 路径找到插入点，不改变任何已有节点的偏移。
/// 分配 prop_info (short 或 long)，返回 data section 内偏移
fn alloc_prop_info(
    data: &mut Vec<u8>,
    data_start: usize,
    alloc_pos: &mut usize,
    data_cap: usize,
    key: &str,
    value: &str,
) -> Result<usize, String> {
    let vb = value.as_bytes();
    let full_name = key.as_bytes();
    let need_long = vb.len() >= PROP_VALUE_MAX;

    // 分配 prop_info 基本结构: serial(4) + value(92) + name\0
    let pi_base_size = 4 + PROP_VALUE_MAX + full_name.len() + 1;
    let aligned_base = (*alloc_pos + 3) & !3;
    let mut end = aligned_base + pi_base_size;
    if end > data_cap {
        return Err("prop_area 空间不足".to_string());
    }

    let pi_off = aligned_base;

    if need_long {
        // long: 分配 name\0 后紧跟 long value
        let long_val_off = (end + 3) & !3;
        end = long_val_off + vb.len() + 1;
        if end > data_cap {
            return Err("prop_area 空间不足（long value）".to_string());
        }

        // serial: kLongFlag
        let serial = 2u32 | (1u32 << 16);
        data[data_start + pi_off..data_start + pi_off + 4]
            .copy_from_slice(&serial.to_le_bytes());

        // value 区域: 占位符 + offset
        let placeholder = b"Must use __system_property_read_callback() to read";
        let plen = placeholder.len().min(56);
        data[data_start + pi_off + 4..data_start + pi_off + 4 + plen]
            .copy_from_slice(&placeholder[..plen]);
        // offset = long_value 绝对位置 - serial 绝对位置
        let offset = ((data_start + long_val_off) - (data_start + pi_off)) as u32;
        data[data_start + pi_off + 4 + 56..data_start + pi_off + 4 + 60]
            .copy_from_slice(&offset.to_le_bytes());

        // name
        let noff = pi_off + 4 + PROP_VALUE_MAX;
        data[data_start + noff..data_start + noff + full_name.len()]
            .copy_from_slice(full_name);

        // long value
        data[data_start + long_val_off..data_start + long_val_off + vb.len()]
            .copy_from_slice(vb);

        *alloc_pos = end;
    } else {
        // short: serial 高 8 位 = 值长度 (SERIAL_VALUE_LEN)
        let vlen = vb.len().min(PROP_VALUE_MAX - 1);
        let serial = ((vlen as u32) << 24) | 2u32;
        data[data_start + pi_off..data_start + pi_off + 4]
            .copy_from_slice(&serial.to_le_bytes());
        data[data_start + pi_off + 4..data_start + pi_off + 4 + vlen]
            .copy_from_slice(&vb[..vlen]);
        let noff = pi_off + 4 + PROP_VALUE_MAX;
        data[data_start + noff..data_start + noff + full_name.len()]
            .copy_from_slice(full_name);

        *alloc_pos = end;
    }

    Ok(pi_off)
}

fn insert_prop_inplace(data: &mut Vec<u8>, key: &str, value: &str) -> Result<(), String> {
    let data_start = PROP_AREA_HEADER_SIZE;
    let data_cap = data.len() - data_start;

    let mut alloc_pos =
        u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;

    // inline bump helper (不用 closure 避免借用冲突)
    macro_rules! bump {
        ($size:expr) => {{
            let aligned = (alloc_pos + 3) & !3;
            if aligned + $size > data_cap {
                return Err("prop_area 空间不足".to_string());
            }
            alloc_pos = aligned + $size;
            aligned
        }};
    }

    let read_u32 =
        |data: &[u8], off: usize| u32::from_le_bytes(data[data_start + off..data_start + off + 4].try_into().unwrap());

    let write_u32 = |data: &mut [u8], off: usize, val: u32| {
        data[data_start + off..data_start + off + 4].copy_from_slice(&val.to_le_bytes());
    };

    let parts: Vec<&str> = key.split('.').collect();
    // 从根节点的 children 指针开始
    let mut cur_ptr_off: usize = 16; // root.children 在 offset 16

    for (depth, part) in parts.iter().enumerate() {
        let is_leaf = depth == parts.len() - 1;

        loop {
            let cur = read_u32(data, cur_ptr_off);
            if cur == 0 {
                // 空位 → 创建新 trie 节点
                let namelen = part.len();
                let node_off = bump!(20 + namelen);
                write_u32(data, node_off, namelen as u32); // namelen
                data[data_start + node_off + 20..data_start + node_off + 20 + namelen]
                    .copy_from_slice(part.as_bytes());
                // 写入指针
                write_u32(data, cur_ptr_off, node_off as u32);

                if is_leaf {
                    let pi_off = alloc_prop_info(data, data_start, &mut alloc_pos, data_cap, key, value)?;
                    write_u32(data, node_off + 4, pi_off as u32);
                }
                cur_ptr_off = node_off + 16; // children
                break;
            } else {
                // 节点已存在 → 比较
                let cur_off = cur as usize;
                let nl = read_u32(data, cur_off) as usize;
                let cur_name = &data[data_start + cur_off + 20..data_start + cur_off + 20 + nl];

                // AOSP cmp_prop_name: 先比长度，同长度再比内容
                let cmp = if part.len() < nl {
                    std::cmp::Ordering::Less
                } else if part.len() > nl {
                    std::cmp::Ordering::Greater
                } else {
                    part.as_bytes().cmp(cur_name)
                };
                match cmp {
                    std::cmp::Ordering::Less => cur_ptr_off = cur_off + 8,    // left
                    std::cmp::Ordering::Greater => cur_ptr_off = cur_off + 12, // right
                    std::cmp::Ordering::Equal => {
                        if is_leaf {
                            let pi_off = alloc_prop_info(data, data_start, &mut alloc_pos, data_cap, key, value)?;
                            write_u32(data, cur_off + 4, pi_off as u32);
                        }
                        cur_ptr_off = cur_off + 16; // children
                        break;
                    }
                }
            }
        }
    }

    // 更新 bytes_used
    data[0..4].copy_from_slice(&(alloc_pos as u32).to_le_bytes());
    Ok(())
}

/// 修补 profile 中的属性区域文件
///
/// 在每个 prop_area 文件中搜索目标属性名，找到后覆写 value 字段。
/// prop_info 内存布局: serial(4) + value(PROP_VALUE_MAX=92) + name(null-terminated)
/// 返回成功修补的属性数量。
fn patch_prop_files(
    profile_dir: &str,
    overrides: &HashMap<String, String>,
) -> Result<(usize, Vec<String>), String> {
    if overrides.is_empty() {
        return Ok((0, Vec::new()));
    }

    let mut patch_count = 0usize;
    let mut modified_files: Vec<String> = Vec::new();
    let mut remaining: HashMap<&str, &str> = overrides
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let entries = std::fs::read_dir(profile_dir)
        .map_err(|e| format!("读取 {} 失败: {}", profile_dir, e))?;

    for entry in entries {
        if remaining.is_empty() {
            break;
        }

        let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let filename = entry.file_name().to_string_lossy().to_string();
        // 跳过非属性区域文件
        if matches!(
            filename.as_str(),
            "props.txt" | "override.prop" | "properties_serial" | "property_info"
        ) {
            continue;
        }

        let mut data =
            std::fs::read(&path).map_err(|e| format!("读取 {:?} 失败: {}", path, e))?;

        // 验证 prop_area magic
        if data.len() < PROP_AREA_HEADER_SIZE {
            continue;
        }
        let magic = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if magic != PROP_AREA_MAGIC {
            continue;
        }

        let mut modified = false;

        // 在当前文件中搜索每个待覆盖的属性
        let keys: Vec<String> = remaining.keys().map(|k| k.to_string()).collect();
        for key in &keys {
            let new_value = remaining[key.as_str()];

            // 构造 null-terminated 搜索模式（全名匹配，不会误命中 trie 节点的片段）
            let mut search = key.as_bytes().to_vec();
            search.push(0);

            if let Some(rel_offset) = find_bytes(&data[PROP_AREA_HEADER_SIZE..], &search) {
                let name_offset = PROP_AREA_HEADER_SIZE + rel_offset;

                // prop_info: serial(4) + value(92) + name
                if name_offset < PROP_VALUE_MAX + 4 {
                    log_warn!("属性 {} 偏移异常 (offset={}), 跳过", key, name_offset);
                    continue;
                }

                let value_offset = name_offset - PROP_VALUE_MAX;
                let serial_offset = value_offset - 4;

                // 读取原始 serial
                let original_serial = u32::from_le_bytes(
                    data[serial_offset..serial_offset + 4].try_into().unwrap(),
                );
                // long property 标记: value 区域包含 "Must use __system_property_read_callback"
                let is_long = data[value_offset..value_offset + 10]
                    .starts_with(b"Must use _");

                // 读取旧值
                let old_value = if is_long {
                    // long property: offset 在 value[56..60]，相对于 serial
                    let long_off = u32::from_le_bytes(
                        data[value_offset + 56..value_offset + 60].try_into().unwrap(),
                    ) as usize;
                    let long_start = serial_offset + long_off;
                    if long_start < data.len() {
                        let end = data[long_start..].iter()
                            .position(|&b| b == 0)
                            .unwrap_or(0);
                        String::from_utf8_lossy(&data[long_start..long_start + end]).to_string()
                    } else {
                        String::new()
                    }
                } else {
                    let old_end = data[value_offset..name_offset]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(PROP_VALUE_MAX);
                    String::from_utf8_lossy(&data[value_offset..value_offset + old_end])
                        .to_string()
                };

                let new_bytes = new_value.as_bytes();
                let need_long = new_bytes.len() >= PROP_VALUE_MAX;

                // 清零旧 long value 残留（如果有）
                if is_long {
                    let long_off = u32::from_le_bytes(
                        data[value_offset + 56..value_offset + 60].try_into().unwrap(),
                    ) as usize;
                    let long_start = serial_offset + long_off;
                    if long_start < data.len() {
                        let long_end = data[long_start..].iter()
                            .position(|&b| b == 0)
                            .map(|p| long_start + p + 1)
                            .unwrap_or(long_start);
                        for b in data[long_start..long_end].iter_mut() {
                            *b = 0;
                        }
                    }
                }

                // 清零 value 区域
                for byte in data[value_offset..value_offset + PROP_VALUE_MAX].iter_mut() {
                    *byte = 0;
                }

                if need_long {
                    // 写 long property: 在 bytes_used 处分配空间
                    let mut bytes_used = u32::from_le_bytes(
                        data[0..4].try_into().unwrap(),
                    ) as usize;
                    let alloc_pos = (bytes_used + 3) & !3;
                    let long_abs = PROP_AREA_HEADER_SIZE + alloc_pos;
                    let long_end = long_abs + new_bytes.len() + 1;
                    if long_end <= data.len() {
                        // 写入 long value
                        data[long_abs..long_abs + new_bytes.len()].copy_from_slice(new_bytes);
                        data[long_abs + new_bytes.len()] = 0;
                        bytes_used = alloc_pos + new_bytes.len() + 1;
                        data[0..4].copy_from_slice(&(bytes_used as u32).to_le_bytes());

                        // value 区域: 占位符 + offset
                        let placeholder = b"Must use __system_property_read_callback() to read";
                        let plen = placeholder.len().min(56);
                        data[value_offset..value_offset + plen].copy_from_slice(&placeholder[..plen]);
                        // offset = long_value 绝对地址 - prop_info serial 绝对地址
                        let offset = (long_abs - serial_offset) as u32;
                        data[value_offset + 56..value_offset + 60]
                            .copy_from_slice(&offset.to_le_bytes());
                        // serial: 设置 kLongFlag
                        let new_serial = original_serial | (1u32 << 16);
                        data[serial_offset..serial_offset + 4]
                            .copy_from_slice(&new_serial.to_le_bytes());
                    } else {
                        log_warn!("属性 {} 的 long value 分配空间不足", key);
                        continue;
                    }
                } else {
                    // 写 short property
                    data[value_offset..value_offset + new_bytes.len()]
                        .copy_from_slice(new_bytes);
                    // serial: 更新高 8 位值长度 + 清除 kLongFlag
                    // bionic 用 SERIAL_VALUE_LEN(serial) = serial >> 24 获取值长度
                    let base_serial = if is_long {
                        original_serial & !(1u32 << 16)
                    } else {
                        original_serial
                    };
                    let new_serial = (base_serial & 0x00FF_FFFF)
                        | ((new_bytes.len() as u32) << 24);
                    data[serial_offset..serial_offset + 4]
                        .copy_from_slice(&new_serial.to_le_bytes());
                }

                log_verbose!(
                    "修补属性 [{}] 在 {} (offset=0x{:x}): '{}' → '{}'",
                    key,
                    filename,
                    value_offset,
                    old_value,
                    new_value
                );

                patch_count += 1;
                modified = true;
                remaining.remove(key.as_str());
            }
        }

        if modified {
            std::fs::write(&path, &data)
                .map_err(|e| format!("写回 {:?} 失败: {}", path, e))?;
            modified_files.push(filename);
        }
    }

    // 报告未找到的属性
    for key in remaining.keys() {
        log_warn!("未在属性文件中找到: {} (可能是运行时动态设置的属性)", key);
    }

    Ok((patch_count, modified_files))
}

/// 在 haystack 中搜索 needle，返回首次匹配的起始偏移
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ─── prop_area 解析与重建 ────────────────────────────────────────────────────

/// 从 prop_area 二进制数据中提取所有 (key, value) 对
/// 遍历 trie 结构，收集所有 prop_info 条目
fn parse_prop_area(data: &[u8]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    if data.len() < PROP_AREA_HEADER_SIZE {
        return result;
    }

    let data_section = &data[PROP_AREA_HEADER_SIZE..];

    // 遍历 trie: prop_bt 从 offset 0 开始
    if !data_section.is_empty() {
        walk_trie(data_section, 0, &mut String::new(), &mut result);
    }
    result
}

/// 递归遍历 prop_bt trie 节点
/// prop_bt: namelen(4) + prop(4) + left(4) + right(4) + children(4) + name(namelen)
fn walk_trie(data: &[u8], offset: usize, prefix: &mut String, result: &mut Vec<(String, String)>) {
    if offset + 20 > data.len() {
        return;
    }

    let namelen = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    let prop_off = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
    let left = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()) as usize;
    let right = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap()) as usize;
    let children = u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap()) as usize;

    // 左子树
    if left != 0 {
        walk_trie(data, left, prefix, result);
    }

    // 当前节点
    let name_start = offset + 20;
    if name_start + namelen <= data.len() {
        let saved_len = prefix.len();

        if namelen > 0 {
            let name_frag = String::from_utf8_lossy(&data[name_start..name_start + namelen]).to_string();
            if !prefix.is_empty() {
                prefix.push('.');
            }
            prefix.push_str(&name_frag);
        }

        // 如果有 prop_info
        if prop_off != 0 {
            if let Some((key, value)) = read_prop_info(data, prop_off) {
                result.push((key, value));
            }
        }

        // children 子树（root 节点 namelen=0 也要递归 children）
        if children != 0 {
            walk_trie(data, children, prefix, result);
        }

        prefix.truncate(saved_len);
    }

    // 右子树
    if right != 0 {
        walk_trie(data, right, prefix, result);
    }
}

/// 从 prop_info 读取 (name, value)
/// prop_info: serial(4) + value(92) + name(null-terminated)
fn read_prop_info(data: &[u8], offset: usize) -> Option<(String, String)> {
    if offset + 4 + PROP_VALUE_MAX > data.len() {
        return None;
    }

    let value_start = offset + 4;
    let name_start = value_start + PROP_VALUE_MAX;

    // 读 name
    let name_end = data[name_start..].iter().position(|&b| b == 0)?;
    let name = String::from_utf8_lossy(&data[name_start..name_start + name_end]).to_string();

    // 检测 long property
    let is_long = data[value_start..value_start + 10]
        .starts_with(b"Must use _");

    let value = if is_long {
        // long property: offset 在 value[56..60]，相对于 prop_info 起始 (serial)
        if value_start + 60 <= data.len() {
            let long_off = u32::from_le_bytes(
                data[value_start + 56..value_start + 60].try_into().unwrap(),
            ) as usize;
            let long_start = offset + long_off; // offset = prop_info serial 在 data section 的偏移
            if long_start < data.len() {
                let end = data[long_start..].iter().position(|&b| b == 0).unwrap_or(0);
                String::from_utf8_lossy(&data[long_start..long_start + end]).to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    } else {
        let end = data[value_start..value_start + PROP_VALUE_MAX]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(PROP_VALUE_MAX);
        String::from_utf8_lossy(&data[value_start..value_start + end]).to_string()
    };

    if name.is_empty() {
        return None;
    }
    Some((name, value))
}

/// 检测文件是否有 long property 空洞
fn has_long_prop_holes(data: &[u8]) -> bool {
    // 如果文件中包含 "Must use __system_property" 占位符，说明有 long prop（可能已被改短）
    find_bytes(data, b"Must use _").is_some()
}

/// 从 (key, value) 列表构建 prop_area 二进制数据
fn build_prop_area(props: &[(String, String)]) -> Vec<u8> {
    let area_size = 128 * 1024;
    let mut data = vec![0u8; area_size];
    let data_start = PROP_AREA_HEADER_SIZE;

    // Header
    data[8..12].copy_from_slice(&PROP_AREA_MAGIC.to_le_bytes());
    data[12..16].copy_from_slice(&0xfc6ed0abu32.to_le_bytes());

    // Bump allocator
    let mut alloc_pos = 0usize;
    let data_cap = area_size - data_start;

    let mut bump = |size: usize| -> Option<usize> {
        let aligned = (alloc_pos + 3) & !3;
        if aligned + size > data_cap { return None; }
        alloc_pos = aligned + size;
        Some(aligned)
    };

    // 根哨兵节点 (namelen=0, 只有 children 指针有意义)
    let root_off = bump(20).unwrap(); // offset 0, 20 bytes (namelen=0, no name data)
    // root node: all zeros = namelen=0, prop=0, left=0, right=0, children=0

    // 辅助: 在 data section 中读/写 u32
    let read_u32 = |data: &[u8], off: usize| -> u32 {
        u32::from_le_bytes(data[data_start + off..data_start + off + 4].try_into().unwrap())
    };

    // 插入每个属性到 trie
    for (name, value) in props {
        let parts: Vec<&str> = name.split('.').collect();
        // 从根节点开始，逐级找/建 trie 节点
        let mut parent_children_ptr_off = root_off + 16; // root.children 在 root_off+16

        for (depth, part) in parts.iter().enumerate() {
            let is_leaf = depth == parts.len() - 1;

            // 在当前层的 BST 中查找或插入
            let mut cur_ptr_off = parent_children_ptr_off;
            loop {
                let cur = read_u32(&data, cur_ptr_off);
                if cur == 0 {
                    // 空位，创建新节点
                    let namelen = part.len();
                    let node_off = match bump(20 + namelen) {
                        Some(o) => o,
                        None => break,
                    };
                    data[data_start + node_off..data_start + node_off + 4]
                        .copy_from_slice(&(namelen as u32).to_le_bytes());
                    data[data_start + node_off + 20..data_start + node_off + 20 + namelen]
                        .copy_from_slice(part.as_bytes());
                    // 写指针
                    data[data_start + cur_ptr_off..data_start + cur_ptr_off + 4]
                        .copy_from_slice(&(node_off as u32).to_le_bytes());

                    if is_leaf {
                        // 分配 prop_info
                        let nbytes = name.as_bytes();
                        if let Some(pi_off) = bump(4 + PROP_VALUE_MAX + nbytes.len() + 1) {
                            data[data_start + pi_off..data_start + pi_off + 4]
                                .copy_from_slice(&2u32.to_le_bytes()); // serial=2
                            let vb = value.as_bytes();
                            let vlen = vb.len().min(PROP_VALUE_MAX - 1);
                            data[data_start + pi_off + 4..data_start + pi_off + 4 + vlen]
                                .copy_from_slice(&vb[..vlen]);
                            let noff = pi_off + 4 + PROP_VALUE_MAX;
                            data[data_start + noff..data_start + noff + nbytes.len()]
                                .copy_from_slice(nbytes);
                            // prop 指针
                            data[data_start + node_off + 4..data_start + node_off + 8]
                                .copy_from_slice(&(pi_off as u32).to_le_bytes());
                        }
                    }
                    parent_children_ptr_off = node_off + 16; // children
                    break;
                } else {
                    // 节点存在，比较
                    let cur_off = cur as usize;
                    let nl = read_u32(&data, cur_off) as usize;
                    let cur_name = &data[data_start + cur_off + 20..data_start + cur_off + 20 + nl];

                    // AOSP cmp_prop_name: 先比长度，同长度再比内容
                    let cmp = if part.len() < nl { std::cmp::Ordering::Less }
                              else if part.len() > nl { std::cmp::Ordering::Greater }
                              else { part.as_bytes().cmp(cur_name) };
                    match cmp {
                        std::cmp::Ordering::Less => cur_ptr_off = cur_off + 8,   // left
                        std::cmp::Ordering::Greater => cur_ptr_off = cur_off + 12, // right
                        std::cmp::Ordering::Equal => {
                            if is_leaf {
                                // 更新已有节点的 prop_info
                                let nbytes = name.as_bytes();
                                if let Some(pi_off) = bump(4 + PROP_VALUE_MAX + nbytes.len() + 1) {
                                    data[data_start + pi_off..data_start + pi_off + 4]
                                        .copy_from_slice(&2u32.to_le_bytes());
                                    let vb = value.as_bytes();
                                    let vlen = vb.len().min(PROP_VALUE_MAX - 1);
                                    data[data_start + pi_off + 4..data_start + pi_off + 4 + vlen]
                                        .copy_from_slice(&vb[..vlen]);
                                    let noff = pi_off + 4 + PROP_VALUE_MAX;
                                    data[data_start + noff..data_start + noff + nbytes.len()]
                                        .copy_from_slice(nbytes);
                                    data[data_start + cur_off + 4..data_start + cur_off + 8]
                                        .copy_from_slice(&(pi_off as u32).to_le_bytes());
                                }
                            }
                            parent_children_ptr_off = cur_off + 16; // children
                            break;
                        }
                    }
                }
            }
        }
    }

    // bytes_used
    data[0..4].copy_from_slice(&(alloc_pos as u32).to_le_bytes());

    // 保持标准 PA_SIZE (128KB)，不截断，避免文件大小异常被检测
    data
}
