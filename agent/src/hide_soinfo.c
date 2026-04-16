/**
 * hide_soinfo.c — .init_array constructor, dlopen 时自动从 linker soinfo 链表中摘除自身。
 *
 * 绕过 V-OS 等安全 SDK 的 dl_iterate_phdr 枚举检测。
 *
 * 版本无关方案：
 *   1. 解析 solist_add_soinfo 的机器码，自动推导 soinfo::next 偏移
 *   2. 调用 linker 自身的 solist_remove_soinfo 执行摘除（正确处理 sonext 尾指针）
 *   不依赖任何硬编码偏移，兼容 Android 7-15。
 *
 * 关键约束：.init_array 在 linker 持有 g_dl_mutex 期间执行，
 * 因此不能调用 dl_iterate_phdr 或再次 lock g_dl_mutex。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h>

/* ========== 调试结果（可通过 dlsym 从 host 读取） ========== */

struct hide_result {
    int status;             /* offset 0:  0=未执行, 1=成功, 负数=错误码 */
    int next_offset;        /* offset 4:  推导出的 soinfo::next 偏移, -1=失败 */
    int entries_scanned;    /* offset 8:  遍历的 soinfo 条目数 */
    int sym_matched;        /* offset 12: 匹配的 linker 符号数 */
    uint64_t head_ptr;      /* offset 16: solist head 地址 */
    uint64_t target_ptr;    /* offset 24: 被隐藏的 soinfo 地址 */
    char error[128];        /* offset 32: 错误描述 */
    char target_path[128];  /* offset 160: 被隐藏目标的路径 */
    char head_path[128];    /* offset 288: head 的路径 */
};

static struct hide_result g_hide_result = {0};

__attribute__((visibility("default")))
struct hide_result* get_hide_result(void) {
    return &g_hide_result;
}

/* ========== 错误处理宏 ========== */

#define FAIL(code, msg) do { \
    g_hide_result.status = (code); \
    strncpy(g_hide_result.error, (msg), sizeof(g_hide_result.error) - 1); \
    return; \
} while(0)

/* ========== ELF symbol resolution ========== */

typedef struct {
    uint64_t solist_get_head;       /* __dl__Z15solist_get_headv */
    uint64_t solist;                /* __dl__ZL6solist (fallback) */
    uint64_t solist_add_soinfo;     /* __dl__Z17solist_add_soinfoP6soinfo */
    uint64_t solist_remove_soinfo;  /* __dl__Z20solist_remove_soinfoP6soinfo */
    uint64_t soinfo_get_path;       /* __dl__ZNK6soinfo12get_realpathEv */
    uint64_t r_debug;               /* __dl__r_debug (struct r_debug) */
    uint64_t r_debug_tail;          /* __dl__ZL12r_debug_tail (link_map*) */
} linker_syms_t;

static int find_linker64(uint64_t *base, char *path, size_t path_size) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "linker64") || strstr(line, ".so"))
            continue;
        if (!strstr(line, "r--p"))
            continue;

        uint64_t start;
        if (sscanf(line, "%lx-", &start) != 1)
            continue;

        char *p = strrchr(line, '/');
        if (!p || !strstr(p, "linker64"))
            continue;

        char *path_start = strchr(line, '/');
        if (path_start) {
            char *nl = strchr(path_start, '\n');
            if (nl) *nl = 0;
            strncpy(path, path_start, path_size - 1);
            path[path_size - 1] = 0;
        }

        *base = start;
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

static uint64_t compute_load_bias(uint64_t base) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
    if (memcmp(ehdr->e_ident, "\x7f""ELF", 4) != 0 || ehdr->e_ident[4] != 2)
        return base;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD)
            return base - phdr[i].p_vaddr;
    }
    return base;
}

static int resolve_linker_syms(const char *path, uint64_t base, linker_syms_t *out) {
    memset(out, 0, sizeof(*out));
    uint64_t bias = compute_load_bias(base);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) { fclose(f); return -1; }
    if (memcmp(ehdr.e_ident, "\x7f""ELF", 4) != 0) { fclose(f); return -1; }

    Elf64_Shdr *shdrs = malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { fclose(f); return -1; }
    fseek(f, ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, sizeof(Elf64_Shdr), ehdr.e_shnum, f) != ehdr.e_shnum) {
        free(shdrs); fclose(f); return -1;
    }

    Elf64_Shdr *symtab_sh = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_sh = &shdrs[i];
            break;
        }
    }
    if (!symtab_sh) { free(shdrs); fclose(f); return -1; }

    Elf64_Shdr *strtab_sh = &shdrs[symtab_sh->sh_link];
    char *strtab = malloc(strtab_sh->sh_size);
    if (!strtab) { free(shdrs); fclose(f); return -1; }
    fseek(f, strtab_sh->sh_offset, SEEK_SET);
    fread(strtab, 1, strtab_sh->sh_size, f);

    int nsyms = symtab_sh->sh_size / sizeof(Elf64_Sym);
    Elf64_Sym *syms = malloc(symtab_sh->sh_size);
    if (!syms) { free(strtab); free(shdrs); fclose(f); return -1; }
    fseek(f, symtab_sh->sh_offset, SEEK_SET);
    fread(syms, sizeof(Elf64_Sym), nsyms, f);
    fclose(f);

    struct { const char *name; uint64_t *slot; } wanted[] = {
        { "__dl__Z15solist_get_headv",              &out->solist_get_head },
        { "__dl__ZL6solist",                        &out->solist },
        { "__dl__Z17solist_add_soinfoP6soinfo",     &out->solist_add_soinfo },
        { "__dl__Z20solist_remove_soinfoP6soinfo",  &out->solist_remove_soinfo },
        { "__dl__ZNK6soinfo12get_realpathEv",       &out->soinfo_get_path },
        { "__dl__ZNK6soinfo7get_pathEv",            &out->soinfo_get_path },
        { "__dl__r_debug",                          &out->r_debug },
        { "__dl__ZL12r_debug_tail",                 &out->r_debug_tail },
    };
    int nwanted = sizeof(wanted) / sizeof(wanted[0]);
    int matched = 0;

    for (int i = 0; i < nsyms; i++) {
        if (syms[i].st_name == 0 || syms[i].st_value == 0) continue;
        if (syms[i].st_name >= strtab_sh->sh_size) continue;
        const char *name = strtab + syms[i].st_name;
        for (int j = 0; j < nwanted; j++) {
            if (*(wanted[j].slot) != 0) continue;
            if (strcmp(name, wanted[j].name) == 0) {
                *(wanted[j].slot) = bias + syms[i].st_value;
                matched++;
                break;
            }
        }
    }

    free(syms);
    free(strtab);
    free(shdrs);

    g_hide_result.sym_matched = matched;
    return 0;
}

/* ========== soinfo::next 偏移推导 ========== */

/**
 * 从 solist_add_soinfo 的机器码推导 soinfo::next 偏移。
 *
 * Android 14+ 的 solist_add_soinfo 有两条代码路径（CBNZ 分支）：
 *   Path1 (空链表): ADRP→STR 全局变量→RET
 *   Path2 (追加):   STR X0, [tail, #next_off]→STR 全局变量→RET
 *
 * 关键特征：写入 soinfo::next 的 STR 偏移最小（结构体字段 < 256），
 * 而写入全局变量的 STR 使用页相对偏移（通常 > 256）。
 *
 * 策略：扫描所有指令（不在 RET 处停止），在所有 STR X0, [Rn, #off]
 * 中取最小非零偏移。
 */
static int derive_next_offset(uint64_t fn_addr) {
    uint32_t *insns = (uint32_t *)fn_addr;
    int best_offset = -1;
    int ret_count = 0;

    for (int i = 0; i < 16; i++) {
        uint32_t insn = insns[i];

        /* 遇到第二个 RET 时停止（覆盖两条路径） */
        if (insn == 0xd65f03c0) {
            if (++ret_count >= 2)
                break;
            continue;
        }

        /* STR (64-bit, unsigned offset): 11 111 0 01 00 imm12 Rn Rt
         * 固定位: 0xFFC00000 == 0xF9000000 */
        if ((insn & 0xFFC00000) == 0xF9000000) {
            int rt = insn & 0x1F;
            if (rt == 0) {
                int imm12 = (insn >> 10) & 0xFFF;
                int off = imm12 * 8;
                if (off > 0 && (best_offset < 0 || off < best_offset)) {
                    best_offset = off;
                }
            }
        }
    }

    return best_offset;
}

/* ========== .init_array constructor ========== */

typedef const char *(*get_path_fn)(void *);
typedef void *(*get_head_fn)(void);
typedef void (*remove_soinfo_fn)(void *);

__attribute__((constructor))
static void hide_from_solist(void) {
    g_hide_result.next_offset = -1;

    /* 1. 定位 linker64 */
    uint64_t linker_base = 0;
    char linker_path[256] = {0};
    if (find_linker64(&linker_base, linker_path, sizeof(linker_path)) != 0)
        FAIL(-1, "find_linker64 failed");

    /* 2. 解析 linker 符号 */
    linker_syms_t syms;
    if (resolve_linker_syms(linker_path, linker_base, &syms) != 0)
        FAIL(-2, "resolve_linker_syms failed");

    /* 必须有 get_path */
    if (!syms.soinfo_get_path)
        FAIL(-3, "soinfo_get_path not found");
    /* 必须有 solist_add_soinfo（用于推导 next 偏移） */
    if (!syms.solist_add_soinfo)
        FAIL(-4, "solist_add_soinfo not found");
    /* 必须有 solist_remove_soinfo（用于安全摘除） */
    if (!syms.solist_remove_soinfo)
        FAIL(-5, "solist_remove_soinfo not found");
    /* 必须有获取链表头的方法 */
    if (!syms.solist_get_head && !syms.solist)
        FAIL(-6, "neither solist_get_head nor solist found");

    /* 3. 从 solist_add_soinfo 机器码推导 soinfo::next 偏移 */
    int next_off = derive_next_offset(syms.solist_add_soinfo);
    g_hide_result.next_offset = next_off;
    if (next_off < 0 || next_off > 0x400)
        FAIL(-7, "derive_next_offset failed");

    /* 4. 获取链表头 */
    get_path_fn get_path = (get_path_fn)syms.soinfo_get_path;
    void *head = NULL;
    if (syms.solist_get_head) {
        head = ((get_head_fn)syms.solist_get_head)();
    } else {
        head = *(void **)syms.solist;
    }
    if (!head)
        FAIL(-8, "solist head is NULL");
    g_hide_result.head_ptr = (uint64_t)head;

    /* 记录 head 路径（调试用） */
    const char *hp = get_path(head);
    if (hp) strncpy(g_hide_result.head_path, hp, sizeof(g_hide_result.head_path) - 1);

    /* 5. 遍历链表，查找 memfd 加载的目标 */
    remove_soinfo_fn do_remove = (remove_soinfo_fn)syms.solist_remove_soinfo;
    void *cur = head;
    int count = 0;

    while (cur && count < 4096) {
        count++;
        const char *path = get_path(cur);

        if (path && strstr(path, "wwb_so")) {
            g_hide_result.target_ptr = (uint64_t)cur;
            strncpy(g_hide_result.target_path, path, sizeof(g_hide_result.target_path) - 1);

            /* 1. 从 soinfo 链表摘除（dl_iterate_phdr 使用此链表） */
            do_remove(cur);

            /* 2. 从 _r_debug.r_map link_map 双向链表摘除
             * link_map 结构体（标准 ELF ABI，布局固定）：
             *   +0x00: l_addr
             *   +0x08: l_name (char*)
             *   +0x10: l_ld
             *   +0x18: l_next (link_map*)
             *   +0x20: l_prev (link_map*)
             *
             * _r_debug 结构体：
             *   +0x00: r_version
             *   +0x08: r_map (link_map* head)
             */
            if (syms.r_debug) {
                uint64_t *r_map_ptr = (uint64_t *)(syms.r_debug + 0x08);
                struct link_map_entry {
                    uint64_t l_addr;
                    char *l_name;
                    uint64_t l_ld;
                    struct link_map_entry *l_next;
                    struct link_map_entry *l_prev;
                };
                struct link_map_entry *lm = (struct link_map_entry *)(*r_map_ptr);
                while (lm) {
                    if (lm->l_name && strstr(lm->l_name, "wwb_so")) {
                        /* 从双向链表摘除 */
                        if (lm->l_prev)
                            lm->l_prev->l_next = lm->l_next;
                        else
                            *r_map_ptr = (uint64_t)lm->l_next; /* head removal */
                        if (lm->l_next)
                            lm->l_next->l_prev = lm->l_prev;
                        /* 更新 r_debug_tail */
                        if (syms.r_debug_tail) {
                            uint64_t *tail_ptr = (uint64_t *)syms.r_debug_tail;
                            if (*tail_ptr == (uint64_t)lm)
                                *tail_ptr = (uint64_t)lm->l_prev;
                        }
                        break;
                    }
                    lm = lm->l_next;
                }
            }

            g_hide_result.entries_scanned = count;
            g_hide_result.status = 1;
            return;
        }

        cur = *(void **)((char *)cur + next_off);
    }

    g_hide_result.entries_scanned = count;
    FAIL(-9, "target not found in solist");
}
