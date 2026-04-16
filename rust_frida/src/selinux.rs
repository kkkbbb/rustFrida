/// SELinux 二进制策略修补模块
///
/// 参考 Frida frida-core/lib/selinux/patch.c 实现纯 Rust 二进制策略修补：
/// 读取 /sys/fs/selinux/policy，解析 policydb 二进制格式，
/// 添加 allow 规则到 avtab，写回 /sys/fs/selinux/load。
/// 不依赖 libsepol、magiskpolicy 等任何外部库。
///
/// 二进制格式参考 Linux kernel: security/selinux/ss/policydb.c
/// 关键点：所有整数使用小端序，字符串格式为 [len 在 u32 batch 中, key bytes 在 batch 之后]
use crate::{log_error, log_info, log_success, log_verbose, log_warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

// ─── 常量 ───

const POLICYDB_MAGIC: u32 = 0xF97CFF8C;

const AVTAB_ALLOWED: u16 = 0x0001;
const AVTAB_XPERMS: u16 = 0x0100;

/// Constraint expression type
const CEXPR_NAMES: u32 = 5;

/// policydb versions for conditional fields
const POLICYDB_VERSION_BOUNDARY: u32 = 24;
const POLICYDB_VERSION_DEFAULT_TYPE: u32 = 28;
const POLICYDB_VERSION_DEFAULT_RANGE: u32 = 29;
const POLICYDB_VERSION_CONSTRAINT_NAMES: u32 = 29;

/// SELinux 规则定义（完整参考 Frida patch.c frida_selinux_rules）
/// `?` 前缀表示可选：类型/权限不存在时静默跳过（兼容不同 Android 版本）
/// 注意：frida_file/frida_memfd 相关规则需要创建自定义类型，纯二进制修补无法实现，已省略
const RULES: &[(&str, &str, &str, &[&str])] = &[
    ("domain", "domain", "process", &["execmem"]),
    ("domain", "shell_data_file", "dir", &["search"]),
    // 放行 shell_data_file / tmpfs / frida_memfd 的文件操作
    // frida_memfd: Frida 创建的自定义类型（如策略中存在），用于 memfd SCM_RIGHTS 传递
    // tmpfs: memfd 的默认 label，需要 TE 规则 + MLS categories 匹配
    (
        "domain",
        "shell_data_file",
        "file",
        &["read", "open", "getattr", "execute", "?map"],
    ),
    (
        "domain",
        "?tmpfs",
        "file",
        &["read", "write", "open", "getattr", "execute", "?map"],
    ),
    (
        "domain",
        "?frida_memfd",
        "file",
        &["read", "write", "open", "getattr", "execute", "?map"],
    ),
    ("domain", "zygote_exec", "file", &["execute"]),
    ("domain", "$self", "process", &["sigchld"]),
    ("domain", "$self", "fd", &["use"]),
    (
        "domain",
        "$self",
        "unix_stream_socket",
        &["connectto", "read", "write", "getattr", "getopt"],
    ),
    ("domain", "$self", "tcp_socket", &["read", "write", "getattr", "getopt"]),
    ("zygote", "zygote", "capability", &["sys_ptrace"]),
    ("?app_zygote", "zygote_exec", "file", &["read"]),
    ("system_server", "?apex_art_data_file", "file", &["execute"]),
    // 属性伪装: 允许 domain 在子进程 mount namespace 中执行 bind mount
    // /dev/__properties__/ 类型是 properties_device，不是 tmpfs
    (
        "domain",
        "tmpfs",
        "filesystem",
        &["?mount", "?unmount", "?remount"],
    ),
    (
        "domain",
        "?properties_device",
        "dir",
        &["mounton", "read", "open", "getattr", "search"],
    ),
    (
        "domain",
        "?properties_device",
        "file",
        &["read", "open", "getattr", "?map"],
    ),
    (
        "domain",
        "tmpfs",
        "dir",
        &["?mounton", "read", "open", "getattr", "search"],
    ),
    // mount 需要 sys_admin capability
    (
        "domain",
        "domain",
        "capability",
        &["?sys_admin"],
    ),
];

// ─── 全局状态 ───

static SELINUX_SOFTENED: AtomicBool = AtomicBool::new(false);
static SELINUX_PATCHED: AtomicBool = AtomicBool::new(false);

// ─── 游标式二进制读取器 ───

struct R<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> R<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, pos: 0 }
    }

    fn u16(&mut self) -> Result<u16, String> {
        if self.pos + 2 > self.d.len() {
            return Err(format!("u16 越界 @ 0x{:X}", self.pos));
        }
        let v = u16::from_le_bytes([self.d[self.pos], self.d[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.d.len() {
            return Err(format!("u32 越界 @ 0x{:X}", self.pos));
        }
        let v = u32::from_le_bytes([
            self.d[self.pos],
            self.d[self.pos + 1],
            self.d[self.pos + 2],
            self.d[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn u64(&mut self) -> Result<u64, String> {
        if self.pos + 8 > self.d.len() {
            return Err(format!("u64 越界 @ 0x{:X}", self.pos));
        }
        let v = u64::from_le_bytes([
            self.d[self.pos],
            self.d[self.pos + 1],
            self.d[self.pos + 2],
            self.d[self.pos + 3],
            self.d[self.pos + 4],
            self.d[self.pos + 5],
            self.d[self.pos + 6],
            self.d[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    /// 读取 n 个原始字节
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.d.len() {
            return Err(format!("{} bytes 越界 @ 0x{:X}", n, self.pos));
        }
        let s = &self.d[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// 读取 policydb 字符串：先在外部读 len(u32)，再调用此方法读取 len 字节 → String
    fn str_of(&mut self, len: u32) -> Result<String, String> {
        let raw = self.bytes(len as usize)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8(raw[..end].to_vec()).map_err(|e| format!("UTF-8 错误 @ 0x{:X}: {}", self.pos, e))
    }

    fn skip(&mut self, n: usize) -> Result<(), String> {
        if self.pos + n > self.d.len() {
            return Err(format!("skip {} 越界 @ 0x{:X}", n, self.pos));
        }
        self.pos += n;
        Ok(())
    }
}

// ─── 数据结构 ───

struct ClassInfo {
    value: u32,
    perms: HashMap<String, u32>,
}

#[derive(Clone)]
struct AvtabEntry {
    source_type: u16,
    target_type: u16,
    target_class: u16,
    specified: u16,
    data: AvtabData,
}

#[derive(Clone)]
enum AvtabData {
    Normal(u32),
    Xperms(Vec<u8>), // 34 bytes: specified(u8)+driver(u8)+perms([u32;8])
}

struct PolicyInfo {
    types: HashMap<String, u32>,
    classes: HashMap<String, ClassInfo>,
    avtab_entries: Vec<AvtabEntry>,
    avtab_offset: usize,
    avtab_end_offset: usize,
    /// permissive_map ebitmap: 用于 emulator fallback 设置 permissive 类型
    permissive_map: Ebitmap,
    permissive_offset: usize,
    permissive_end_offset: usize,
}

// ─── ebitmap ───

/// SELinux ebitmap: mapsize(u32) highbit(u32) count(u32) + count*(startbit(u32)+map(u64))
struct Ebitmap {
    mapsize: u32,
    highbit: u32,
    nodes: Vec<(u32, u64)>, // (startbit, map)
}

impl Ebitmap {
    fn parse(r: &mut R) -> Result<Self, String> {
        let mapsize = r.u32()?;
        let highbit = r.u32()?;
        let count = r.u32()?;
        let mut nodes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let startbit = r.u32()?;
            let map = r.u64()?;
            nodes.push((startbit, map));
        }
        Ok(Ebitmap {
            mapsize,
            highbit,
            nodes,
        })
    }

    /// 在 ebitmap 中设置指定 bit
    fn set_bit(&mut self, bit: u32) {
        let startbit = (bit / 64) * 64;
        let bit_offset = bit % 64;

        if let Some(node) = self.nodes.iter_mut().find(|(sb, _)| *sb == startbit) {
            node.1 |= 1u64 << bit_offset;
        } else {
            self.nodes.push((startbit, 1u64 << bit_offset));
            self.nodes.sort_by_key(|(sb, _)| *sb);
        }

        if bit + 1 > self.highbit {
            self.highbit = bit + 1;
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.mapsize.to_le_bytes());
        buf.extend_from_slice(&self.highbit.to_le_bytes());
        buf.extend_from_slice(&(self.nodes.len() as u32).to_le_bytes());
        for &(startbit, map) in &self.nodes {
            buf.extend_from_slice(&startbit.to_le_bytes());
            buf.extend_from_slice(&map.to_le_bytes());
        }
        buf
    }
}

fn skip_ebitmap(r: &mut R) -> Result<(), String> {
    let _mapsize = r.u32()?;
    let _highbit = r.u32()?;
    let count = r.u32()?;
    r.skip(count as usize * 12) // 每个 node: startbit(u32) + map(u64)
}

fn skip_mls_level(r: &mut R) -> Result<(), String> {
    let _sens = r.u32()?;
    skip_ebitmap(r)
}

fn skip_mls_range(r: &mut R) -> Result<(), String> {
    let items = r.u32()?;
    skip_mls_level(r)?; // level[0]
    if items > 1 {
        skip_mls_level(r)?; // level[1]
    }
    Ok(())
}

/// type_set: 2 ebitmaps + flags(u32)
fn skip_type_set(r: &mut R) -> Result<(), String> {
    skip_ebitmap(r)?;
    skip_ebitmap(r)?;
    let _flags = r.u32()?;
    Ok(())
}

// ─── Symbol table entry 解析 ───

/// 解析 perm entry: len(u32) value(u32) key(len bytes)
fn read_perm(r: &mut R) -> Result<(String, u32), String> {
    let len = r.u32()?;
    let value = r.u32()?;
    let key = r.str_of(len)?;
    Ok((key, value))
}

/// 解析 SYM_COMMONS (kernel: common_read)
/// 格式: len(u32) value(u32) nprim(u32) nel(u32) key(len) + nel perm entries
fn parse_commons(r: &mut R, nel: u32) -> Result<HashMap<String, HashMap<String, u32>>, String> {
    let mut commons = HashMap::new();
    for _ in 0..nel {
        let len = r.u32()?;
        let _value = r.u32()?;
        let _nprim = r.u32()?;
        let perm_nel = r.u32()?;
        let key = r.str_of(len)?;

        let mut perms = HashMap::new();
        for _ in 0..perm_nel {
            let (pname, pval) = read_perm(r)?;
            perms.insert(pname, pval);
        }
        commons.insert(key, perms);
    }
    Ok(commons)
}

/// 跳过 constraint/validatetrans (libsepol: cond_write_list → put_entry)
/// 注意：libsepol 对 ALL CEXPR_NAMES 表达式写入 type_set（当 version >= 29），
/// 不仅仅是 validatetrans。内核读取代码有 allowxtarget 判断，但写入侧没有。
fn skip_constraints(r: &mut R, ncons: u32, version: u32) -> Result<(), String> {
    for _ in 0..ncons {
        let _perms = r.u32()?;
        let nexpr = r.u32()?;
        for _ in 0..nexpr {
            let expr_type = r.u32()?;
            let _attr = r.u32()?;
            let _op = r.u32()?;

            if expr_type == CEXPR_NAMES {
                skip_ebitmap(r)?; // names
                                  // version >= 29: type_set (libsepol always writes it)
                if version >= POLICYDB_VERSION_CONSTRAINT_NAMES {
                    skip_type_set(r)?;
                }
            }
        }
    }
    Ok(())
}

/// 解析 SYM_CLASSES (kernel: class_read)
/// 格式: len(u32) len2(u32) value(u32) ?(u32) nel(u32) ncons(u32) key(len) [common_key(len2)]
///       + nel perms + constraints + ncons2(u32) validatetrans + defaults
fn parse_classes(
    r: &mut R,
    nel: u32,
    version: u32,
    commons: &HashMap<String, HashMap<String, u32>>,
) -> Result<HashMap<String, ClassInfo>, String> {
    let mut classes = HashMap::new();
    for _ in 0..nel {
        // 6 u32s batch
        let len = r.u32()?; // class key len
        let len2 = r.u32()?; // common key len
        let value = r.u32()?; // class value (ID)
        let _buf3 = r.u32()?; // (primary perms count of class, unused)
        let perm_nel = r.u32()?; // number of class-specific permissions
        let ncons = r.u32()?; // number of constraints

        let key = r.str_of(len)?;

        // common key (inherited permissions)
        let mut perms = HashMap::new();
        if len2 > 0 {
            let common_key = r.str_of(len2)?;
            if let Some(common_perms) = commons.get(&common_key) {
                perms = common_perms.clone();
            }
        }

        // class-specific permissions
        for _ in 0..perm_nel {
            let (pname, pval) = read_perm(r)?;
            perms.insert(pname, pval);
        }

        // constraints
        skip_constraints(r, ncons, version)?;

        // validatetrans: ncons2(u32) + entries
        let ncons2 = r.u32()?;
        skip_constraints(r, ncons2, version)?;

        // defaults (version >= 28)
        if version >= POLICYDB_VERSION_DEFAULT_TYPE {
            let _default_user = r.u32()?;
            let _default_role = r.u32()?;
            let _default_type = r.u32()?;
        }
        if version >= POLICYDB_VERSION_DEFAULT_RANGE {
            let _default_range = r.u32()?;
        }

        classes.insert(key, ClassInfo { value, perms });
    }
    Ok(classes)
}

/// 解析 SYM_TYPES (libsepol: type_write)
/// v>=24 格式: len(u32) value(u32) properties(u32) bounds(u32) key(len bytes)
/// v<24 格式: len(u32) value(u32) primary(u32) key(len bytes)
fn parse_types(r: &mut R, nel: u32, version: u32) -> Result<HashMap<String, u32>, String> {
    let mut types = HashMap::new();
    for _ in 0..nel {
        let len = r.u32()?;
        let value = r.u32()?;
        let _primary = r.u32()?; // v>=24: properties, v<24: primary
        if version >= POLICYDB_VERSION_BOUNDARY {
            let _bounds = r.u32()?; // bounds 在 key 之前
        }
        let key = r.str_of(len)?;
        types.insert(key, value);
    }
    Ok(types)
}

/// 跳过 SYM_ROLES (kernel: role_read)
/// 格式: len(u32) value(u32) bounds(u32) key(len) ebitmap ebitmap
fn skip_role(r: &mut R) -> Result<(), String> {
    let len = r.u32()?;
    let _value = r.u32()?;
    let _bounds = r.u32()?; // 3rd u32: bounds (always present in batch)
    let _key = r.str_of(len)?;
    skip_ebitmap(r)?; // dominates
    skip_ebitmap(r)?; // types
    Ok(())
}

/// 跳过 SYM_USERS (libsepol: user_write)
/// v>=24 格式: len(u32) value(u32) bounds(u32) key(len) ebitmap [MLS range+level]
/// v<24 格式: len(u32) value(u32) key(len) ebitmap [MLS range+level]
fn skip_user(r: &mut R, version: u32, mls: bool) -> Result<(), String> {
    let len = r.u32()?;
    let _value = r.u32()?;
    if version >= POLICYDB_VERSION_BOUNDARY {
        let _bounds = r.u32()?; // bounds 在 key 之前
    }
    let _key = r.str_of(len)?;
    skip_ebitmap(r)?; // roles
    if mls {
        skip_mls_range(r)?;
        skip_mls_level(r)?;
    }
    Ok(())
}

/// 跳过 SYM_BOOLS (kernel: bool_read)
/// 格式: len(u32) value(u32) state(u32) key(len)
fn skip_bool(r: &mut R) -> Result<(), String> {
    let len = r.u32()?;
    let _value = r.u32()?;
    let _state = r.u32()?;
    let _key = r.str_of(len)?;
    Ok(())
}

/// 跳过 SYM_LEVELS (kernel: sens_read)
/// 格式: len(u32) isalias(u32) key(len) mls_level
fn skip_level(r: &mut R) -> Result<(), String> {
    let len = r.u32()?;
    let _isalias = r.u32()?;
    let _key = r.str_of(len)?;
    skip_mls_level(r)
}

/// 跳过 SYM_CATS (kernel: cat_read)
/// 格式: len(u32) value(u32) isalias(u32) key(len)
fn skip_cat(r: &mut R) -> Result<(), String> {
    let len = r.u32()?;
    let _value = r.u32()?;
    let _isalias = r.u32()?;
    let _key = r.str_of(len)?;
    Ok(())
}

// ─── avtab 解析 ───

fn parse_avtab(r: &mut R, nel: u32) -> Result<Vec<AvtabEntry>, String> {
    let mut entries = Vec::with_capacity(nel as usize);
    for _ in 0..nel {
        let source_type = r.u16()?;
        let target_type = r.u16()?;
        let target_class = r.u16()?;
        let specified = r.u16()?;

        let data = if (specified & AVTAB_XPERMS) != 0 {
            AvtabData::Xperms(r.bytes(34)?.to_vec())
        } else {
            AvtabData::Normal(r.u32()?)
        };

        entries.push(AvtabEntry {
            source_type,
            target_type,
            target_class,
            specified,
            data,
        });
    }
    Ok(entries)
}

// ─── 策略解析主函数 ───

fn parse_policy(data: &[u8]) -> Result<PolicyInfo, String> {
    let mut r = R::new(data);

    // Header
    let magic = r.u32()?;
    if magic != POLICYDB_MAGIC {
        return Err(format!(
            "无效 policydb magic: 0x{:08X}（期望 0x{:08X}）",
            magic, POLICYDB_MAGIC
        ));
    }

    // policydb string: len(u32) + bytes
    let str_len = r.u32()?;
    let _pdb_str = r.str_of(str_len)?;

    // version + config
    let version = r.u32()?;
    let config = r.u32()?;
    let mls = (config & 1) != 0;

    log_verbose!("SELinux 策略版本: {}, MLS: {}", version, mls);

    // sym_num + ocon_num
    let sym_num = r.u32()?;
    let _ocon_num = r.u32()?;

    // policycaps ebitmap (跳过)
    skip_ebitmap(&mut r)?;

    // permissive_map ebitmap (解析，用于 emulator fallback)
    let permissive_offset = r.pos;
    let permissive_map = Ebitmap::parse(&mut r)?;
    let permissive_end_offset = r.pos;

    // Symbol tables
    let mut commons = HashMap::new();
    let mut classes = HashMap::new();
    let mut types = HashMap::new();

    for sym_idx in 0..sym_num as usize {
        let _nprim = r.u32()?;
        let nel = r.u32()?;

        match sym_idx {
            0 => {
                // SYM_COMMONS
                commons = parse_commons(&mut r, nel)?;
                log_verbose!("解析 {} 个 commons", commons.len());
            }
            1 => {
                // SYM_CLASSES
                classes = parse_classes(&mut r, nel, version, &commons)?;
                log_verbose!("解析 {} 个 classes", classes.len());
            }
            2 => {
                // SYM_ROLES
                for _ in 0..nel {
                    skip_role(&mut r)?;
                }
            }
            3 => {
                // SYM_TYPES
                types = parse_types(&mut r, nel, version)?;
                log_verbose!("解析 {} 个 types", types.len());
            }
            4 => {
                // SYM_USERS
                for _ in 0..nel {
                    skip_user(&mut r, version, mls)?;
                }
            }
            5 => {
                // SYM_BOOLS
                for _ in 0..nel {
                    skip_bool(&mut r)?;
                }
            }
            6 => {
                // SYM_LEVELS (MLS only)
                if mls {
                    for _ in 0..nel {
                        skip_level(&mut r)?;
                    }
                }
            }
            7 => {
                // SYM_CATS (MLS only)
                if mls {
                    for _ in 0..nel {
                        skip_cat(&mut r)?;
                    }
                }
            }
            _ => return Err(format!("不支持的符号表索引: {}", sym_idx)),
        }
    }

    // avtab
    let avtab_offset = r.pos;
    let avtab_nel = r.u32()?;
    log_verbose!("avtab: {} 条目, offset 0x{:X}", avtab_nel, avtab_offset);

    let avtab_entries = parse_avtab(&mut r, avtab_nel)?;
    let avtab_end_offset = r.pos;

    log_verbose!(
        "avtab 范围: 0x{:X}..0x{:X} ({} bytes)",
        avtab_offset,
        avtab_end_offset,
        avtab_end_offset - avtab_offset
    );

    Ok(PolicyInfo {
        types,
        classes,
        avtab_entries,
        avtab_offset,
        avtab_end_offset,
        permissive_map,
        permissive_offset,
        permissive_end_offset,
    })
}

// ─── 规则添加 ───

fn add_rules(info: &mut PolicyInfo, self_type: &str) -> Result<usize, String> {
    let mut added = 0usize;
    let mut modified = 0usize;

    for &(source, target, class, permissions) in RULES {
        // `?` 前缀: 类型可选，不存在时静默跳过
        let (source_optional, source_name) = strip_optional(source);
        let (target_optional, target_raw) = strip_optional(target);
        let target_name = if target_raw == "$self" { self_type } else { target_raw };

        let source_id = match info.types.get(source_name) {
            Some(&id) => id as u16,
            None => {
                if !source_optional {
                    log_verbose!("跳过: source '{}' 不存在", source_name);
                }
                continue;
            }
        };
        let target_id = match info.types.get(target_name) {
            Some(&id) => id as u16,
            None => {
                if !target_optional {
                    log_verbose!("跳过: target '{}' 不存在", target_name);
                }
                continue;
            }
        };
        let class_info = match info.classes.get(class) {
            Some(ci) => ci,
            None => {
                log_verbose!("跳过: class '{}' 不存在", class);
                continue;
            }
        };
        let class_id = class_info.value as u16;

        let mut perm_mask: u32 = 0;
        for &perm in permissions {
            let (perm_optional, perm_name) = strip_optional(perm);
            if let Some(&pval) = class_info.perms.get(perm_name) {
                perm_mask |= 1u32 << (pval - 1);
            } else if !perm_optional {
                log_verbose!("跳过权限: {}.{} 不存在", class, perm_name);
            }
        }
        if perm_mask == 0 {
            continue;
        }

        let existing = info.avtab_entries.iter_mut().find(|e| {
            e.source_type == source_id
                && e.target_type == target_id
                && e.target_class == class_id
                && e.specified == AVTAB_ALLOWED
        });

        match existing {
            Some(entry) => {
                if let AvtabData::Normal(ref mut data) = entry.data {
                    let old = *data;
                    *data |= perm_mask;
                    if *data != old {
                        modified += 1;
                        log_verbose!(
                            "修改: {} → {} [{}] 0x{:X} → 0x{:X}",
                            source_name,
                            target_name,
                            class,
                            old,
                            *data
                        );
                    }
                }
            }
            None => {
                info.avtab_entries.push(AvtabEntry {
                    source_type: source_id,
                    target_type: target_id,
                    target_class: class_id,
                    specified: AVTAB_ALLOWED,
                    data: AvtabData::Normal(perm_mask),
                });
                added += 1;
                log_verbose!(
                    "新增: {} → {} [{}] perms=0x{:X}",
                    source_name,
                    target_name,
                    class,
                    perm_mask
                );
            }
        }
    }

    log_verbose!("规则变更: 新增 {}, 修改 {}", added, modified);
    Ok(added + modified)
}

/// 解析 `?` 前缀: `"?name"` → `(true, "name")`，`"name"` → `(false, "name")`
fn strip_optional(s: &str) -> (bool, &str) {
    if let Some(rest) = s.strip_prefix('?') {
        (true, rest)
    } else {
        (false, s)
    }
}

// ─── 二进制重建 ───

/// 重建修补后的策略二进制
/// 布局: [prefix | permissive_map | middle | avtab | suffix]
/// permissive_map 和 avtab 可能大小变化，需要分段拼接
fn build_modified_policy(original: &[u8], info: &PolicyInfo) -> Vec<u8> {
    // 5 段: prefix + permissive + middle + avtab + suffix
    let prefix = &original[..info.permissive_offset];
    let new_permissive = info.permissive_map.serialize();
    let middle = &original[info.permissive_end_offset..info.avtab_offset];
    let suffix = &original[info.avtab_end_offset..];

    let nel = info.avtab_entries.len() as u32;
    let mut avtab = Vec::new();
    avtab.extend_from_slice(&nel.to_le_bytes());

    for e in &info.avtab_entries {
        avtab.extend_from_slice(&e.source_type.to_le_bytes());
        avtab.extend_from_slice(&e.target_type.to_le_bytes());
        avtab.extend_from_slice(&e.target_class.to_le_bytes());
        avtab.extend_from_slice(&e.specified.to_le_bytes());
        match &e.data {
            AvtabData::Normal(d) => avtab.extend_from_slice(&d.to_le_bytes()),
            AvtabData::Xperms(xp) => avtab.extend_from_slice(xp),
        }
    }

    let total = prefix.len() + new_permissive.len() + middle.len() + avtab.len() + suffix.len();
    let mut result = Vec::with_capacity(total);
    result.extend_from_slice(prefix);
    result.extend_from_slice(&new_permissive);
    result.extend_from_slice(middle);
    result.extend_from_slice(&avtab);
    result.extend_from_slice(suffix);
    result
}

// ─── 辅助函数 ───

fn get_self_type() -> Result<String, String> {
    let content = std::fs::read_to_string("/proc/self/attr/current")
        .map_err(|e| format!("读取 /proc/self/attr/current 失败: {}", e))?;
    let content = content.trim().trim_end_matches('\0');
    let parts: Vec<&str> = content.split(':').collect();
    if parts.len() >= 3 {
        Ok(parts[2].to_string())
    } else {
        Err(format!("无法解析 SELinux context: '{}'", content))
    }
}

fn is_enforcing() -> bool {
    std::fs::read_to_string("/sys/fs/selinux/enforce")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn setenforce(enforce: bool) -> Result<(), String> {
    let val = if enforce { "1" } else { "0" };
    std::fs::write("/sys/fs/selinux/enforce", val).map_err(|e| format!("setenforce {} 失败: {}", val, e))
}

/// 参考 Frida frida_set_file_contents: 使用 libc::open(O_RDWR) + libc::write 循环
/// /sys/fs/selinux/load 要求整个策略在一次 write() 中写入（内核 sel_write_load），
/// Rust File::write 可能拆分大缓冲区，直接使用 libc::write 确保语义一致。
fn write_policy_file(path: &str, data: &[u8]) -> Result<(), String> {
    use std::ffi::CString;
    let c_path = CString::new(path).map_err(|_| format!("路径包含 null 字节: {}", path))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(format!("open({}) 失败: {}", path, std::io::Error::last_os_error()));
    }
    let mut offset = 0usize;
    while offset < data.len() {
        let ret = unsafe { libc::write(fd, data[offset..].as_ptr() as *const libc::c_void, data.len() - offset) };
        if ret >= 0 {
            offset += ret as usize;
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(format!("write({}) 失败 @ offset {}: {}", path, offset, err));
        }
    }
    unsafe { libc::close(fd) };
    Ok(())
}

// ─── 公共 API ───

/// 修补 SELinux 策略，允许目标进程访问 memfd/socket/ptrace 等注入所需资源。
/// 所有注入模式（spawn/server/--pid/--name）均调用。
pub fn patch_selinux() -> Result<(), String> {
    if SELINUX_PATCHED.load(Ordering::Relaxed) {
        log_verbose!("SELinux 策略已修补，跳过");
        return Ok(());
    }

    if !std::path::Path::new("/sys/fs/selinux/policy").exists() {
        log_verbose!("SELinux 未启用，跳过");
        return Ok(());
    }

    if !is_enforcing() {
        log_verbose!("SELinux permissive，跳过策略修补");
        return Ok(());
    }

    log_info!("正在修补 SELinux 策略...");

    let self_type = get_self_type()?;
    log_verbose!("当前 SELinux domain: {}", self_type);

    let policy_data = std::fs::read("/sys/fs/selinux/policy").map_err(|e| format!("读取策略失败: {}", e))?;
    log_verbose!("策略大小: {} bytes", policy_data.len());

    let mut info = parse_policy(&policy_data)?;

    let changes = add_rules(&mut info, &self_type)?;
    if changes == 0 {
        log_verbose!("所有规则已存在，无需修补");
        SELINUX_PATCHED.store(true, Ordering::Relaxed);
        return Ok(());
    }

    let new_policy = build_modified_policy(&policy_data, &info);
    log_verbose!("修补后大小: {} bytes (原 {})", new_policy.len(), policy_data.len());

    match write_policy_file("/sys/fs/selinux/load", &new_policy) {
        Ok(()) => {
            log_success!("SELinux 策略修补成功 ({} 条规则变更)", changes);
            SELINUX_PATCHED.store(true, Ordering::Relaxed);
            Ok(())
        }
        Err(e) => {
            log_warn!("写入 /sys/fs/selinux/load 失败: {}", e);
            fallback_with_setenforce(&policy_data, &mut info, changes, &self_type)
        }
    }
}

/// Emulator 回退方案（参考 Frida patch.c）:
/// 1. 临时关闭 enforcing
/// 2. 将 self_type 设为 permissive（避免 enforcing 恢复后仍被阻断）
/// 3. 重建策略并写入
/// 4. 恢复 enforcing
fn fallback_with_setenforce(
    original: &[u8],
    info: &mut PolicyInfo,
    changes: usize,
    self_type: &str,
) -> Result<(), String> {
    log_info!("尝试回退: 临时关闭 enforcing（可能在模拟器环境）...");

    if let Err(e) = setenforce(false) {
        log_error!("setenforce 0 失败: {}", e);
        return Err(format!("策略修补失败且无法关闭 enforcing: {}", e));
    }

    // 参考 Frida: 将当前 domain 设为 permissive（通过 permissive_map ebitmap）
    if let Some(&type_value) = info.types.get(self_type) {
        info.permissive_map.set_bit(type_value);
        log_verbose!("设置 '{}' (value={}) 为 permissive", self_type, type_value);
    }

    let new_policy = build_modified_policy(original, info);

    match write_policy_file("/sys/fs/selinux/load", &new_policy) {
        Ok(()) => {
            log_success!("SELinux 策略修补成功（回退模式, {} 条变更）", changes);
            if let Err(e) = setenforce(true) {
                log_warn!("重新启用 enforcing 失败: {}，保持 permissive", e);
                SELINUX_SOFTENED.store(true, Ordering::Relaxed);
            }
            SELINUX_PATCHED.store(true, Ordering::Relaxed);
            Ok(())
        }
        Err(e2) => {
            log_warn!("回退写入仍失败: {}，保持 permissive 继续", e2);
            SELINUX_SOFTENED.store(true, Ordering::Relaxed);
            Ok(())
        }
    }
}

pub fn restore_selinux() {
    if SELINUX_SOFTENED.swap(false, Ordering::Relaxed) {
        log_info!("正在还原 SELinux enforcing...");
        match setenforce(true) {
            Ok(()) => log_success!("SELinux enforcing 已还原"),
            Err(e) => log_warn!("还原 enforcing 失败: {}", e),
        }
    }
}
