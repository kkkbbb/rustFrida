/*
 * rustfrida-loader.c — Frida-style loader adapted for rustFrida's agent ABI
 *
 * Based on Frida's loader.c (frida-core/src/linux/helpers/loader.c).
 * Runs as position-independent code in the target process after bootstrap.
 * Entry point creates a worker thread via raw clone; the worker
 * receives agent SO fd + ctrl fd over the control socket, links the
 * agent with rustFrida's minimal ELF linker, and calls hello_entry(&AgentArgs) which blocks in the agent's
 * command loop.
 */

#include "inject-context.h"
#include "syscall.h"

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/un.h>

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif
#ifndef __NR_read
# define __NR_read 63
#endif
#ifndef __NR_openat
# define __NR_openat 56
#endif
#ifndef __NR_close
# define __NR_close 57
#endif
#ifndef __NR_lseek
# define __NR_lseek 62
#endif
#ifndef __NR_fcntl
# define __NR_fcntl 25
#endif
#ifndef __NR_mmap
# define __NR_mmap 222
#endif
#ifndef __NR_munmap
# define __NR_munmap 215
#endif
#ifndef __NR_mprotect
# define __NR_mprotect 226
#endif
#ifndef __NR_prctl
# define __NR_prctl 167
#endif
#ifndef __NR_socket
# define __NR_socket 198
#endif
#ifndef __NR_connect
# define __NR_connect 203
#endif
#ifndef __NR_recvmsg
# define __NR_recvmsg 212
#endif
#ifndef __NR_sendto
# define __NR_sendto 206
#endif
#ifndef __NR_readlinkat
# define __NR_readlinkat 78
#endif
#ifndef AT_FDCWD
# define AT_FDCWD -100
#endif
#ifndef O_RDONLY
# define O_RDONLY 0
#endif
#ifndef SEEK_END
# define SEEK_END 2
#endif
#ifndef R_AARCH64_ABS64
# define R_AARCH64_ABS64 257
#endif
#ifndef R_AARCH64_GLOB_DAT
# define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
# define R_AARCH64_JUMP_SLOT 1026
#endif
#ifndef R_AARCH64_RELATIVE
# define R_AARCH64_RELATIVE 1027
#endif
#ifndef R_AARCH64_TLSDESC
# define R_AARCH64_TLSDESC 1031
#endif
#ifndef STT_GNU_IFUNC
# define STT_GNU_IFUNC 10
#endif
#ifndef PR_SET_VMA
# define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
# define PR_SET_VMA_ANON_NAME 0
#endif
#ifndef PR_SET_NAME
# define PR_SET_NAME 15
#endif
#ifndef CLONE_VM
# define CLONE_VM 0x00000100
#endif
#ifndef CLONE_FS
# define CLONE_FS 0x00000200
#endif
#ifndef CLONE_FILES
# define CLONE_FILES 0x00000400
#endif
#ifndef CLONE_SIGHAND
# define CLONE_SIGHAND 0x00000800
#endif
#ifndef CLONE_THREAD
# define CLONE_THREAD 0x00010000
#endif
#ifndef CLONE_SYSVSEM
# define CLONE_SYSVSEM 0x00040000
#endif

/* ========== rustFrida types ========== */

typedef int FridaUnloadPolicy;
typedef union _FridaControlMessage FridaControlMessage;

enum _FridaUnloadPolicy
{
  FRIDA_UNLOAD_POLICY_IMMEDIATE,
  FRIDA_UNLOAD_POLICY_RESIDENT,
  FRIDA_UNLOAD_POLICY_DEFERRED,
};

union _FridaControlMessage
{
  struct cmsghdr header;
  uint8_t storage[CMSG_SPACE (sizeof (int))];
};

/*
 * RustFridaLoaderContext — extends FridaLoaderContext with rustFrida fields.
 *
 * The first 5 fields must match FridaLoaderContext layout exactly so that
 * the bootstrap code (which populates them) works unchanged.
 */
typedef struct {
  /* Standard Frida fields (must match FridaLoaderContext layout) */
  int ctrlfds[2];
  const char * agent_entrypoint;
  const char * agent_data;
  const char * fallback_address;
  FridaLibcApi * libc;

  /* rustFrida extensions */
  uint64_t string_table_addr;  /* Remote StringTable address for agent */
  const char * agent_current_thread_eval;
  void * libc_base;
  void * linker_base;

  /* Runtime state (filled by loader) */
  uintptr_t worker;
  void * agent_handle;
  void * agent_entrypoint_impl;
  void * agent_current_thread_eval_impl;
  void * loader_stack;
  size_t loader_stack_size;
} RustFridaLoaderContext;

/*
 * AgentArgs — passed to hello_entry().
 * Must match agent/src/lib.rs AgentArgs layout exactly.
 */
typedef struct {
  uint64_t table;       /* *const StringTable */
  int32_t  ctrl_fd;     /* REPL socketpair fd */
  int32_t  agent_memfd; /* -1 (unused in this path) */
} AgentArgs;

typedef void * (* hello_entry_fn) (void *);

#define RUSTFRIDA_MAX_MODULES 384

typedef struct {
  ElfW(Addr) base;
  const ElfW(Sym) * symtab;
  const char * strtab;
  size_t strsz;
  const uint32_t * gnu_hash;
  const uint32_t * sysv_hash;
  size_t nsyms;
} RustFridaExportModule;

typedef struct {
  RustFridaExportModule modules[RUSTFRIDA_MAX_MODULES];
  size_t count;
} RustFridaSymbolResolver;

typedef struct {
  ElfW(Addr) base;
  ElfW(Addr) load_start;
  ElfW(Addr) load_end;
  ElfW(Dyn) * dynamic;
  const ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_count;
  const ElfW(Sym) * symtab;
  const char * strtab;
  size_t strsz;
  const uint32_t * gnu_hash;
  size_t nsyms;
  RustFridaSymbolResolver resolver;
  bool initialized;
  bool finalized;
  char error[160];
} RustFridaLinkedModule;

/* ========== Forward declarations ========== */

static void * frida_main (void * user_data);

static int frida_connect (const char * address, const FridaLibcApi * libc);
static bool frida_send_hello (int sockfd, pid_t thread_id, const FridaLibcApi * libc);
static bool frida_send_ready (int sockfd, const FridaLibcApi * libc);
static bool frida_receive_ack (int sockfd, const FridaLibcApi * libc);
static bool frida_send_bye (int sockfd, FridaUnloadPolicy unload_policy, const FridaLibcApi * libc);
static bool frida_send_error (int sockfd, FridaMessageType type, const char * message, const FridaLibcApi * libc);
static bool frida_send_log (int sockfd, const char * message, const FridaLibcApi * libc);

static bool frida_receive_chunk (int sockfd, void * buffer, size_t length, const FridaLibcApi * api);
static int frida_receive_fd (int sockfd, const FridaLibcApi * libc);
static int frida_receive_fd_diag (int sockfd, const FridaLibcApi * libc, char * diag_buf);
static bool frida_send_chunk (int sockfd, const void * buffer, size_t length, const FridaLibcApi * libc);
static void frida_enable_close_on_exec (int fd, const FridaLibcApi * libc);

static bool rustfrida_link_agent (int fd, const FridaLibcApi * libc, RustFridaLinkedModule * module, int diagfd,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base);
static void * rustfrida_find_export (RustFridaLinkedModule * module, const char * symbol);
static void rustfrida_close_module (RustFridaLinkedModule * module, const FridaLibcApi * libc);
static void rustfrida_unmap_module (RustFridaLinkedModule * module, const FridaLibcApi * libc);
static bool rustfrida_build_symbol_resolver (RustFridaLinkedModule * module, const FridaLibcApi * libc,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base);
static void rustfrida_set_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * message);
static void rustfrida_set_symbol_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * prefix, const char * name);
static void rustfrida_get_fd_vma_name (int fd, char * name, size_t name_size, const FridaLibcApi * libc);
static void rustfrida_set_vma_name (ElfW(Addr) address, size_t size, const char * name);
static bool rustfrida_address_is_executable (ElfW(Addr) address);

static void frida_main_raw (void * user_data);
static void * frida_raw_mmap (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
static int frida_raw_munmap (void * addr, size_t length);
static int frida_raw_close (int fd);
static int frida_raw_socket (int domain, int type, int protocol);
static int frida_raw_connect (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
static ssize_t frida_raw_recvmsg (int sockfd, struct msghdr * msg, int flags);
static ssize_t frida_raw_send (int sockfd, const void * buf, size_t len, int flags);
static int frida_raw_fcntl (int fd, int cmd, size_t arg);

static size_t frida_strlen (const char * str);
static int frida_strcmp (const char * a, const char * b);
static bool frida_streq (const char * a, const char * b);
static bool frida_str_has_suffix (const char * str, const char * suffix);
static void * frida_memcpy (void * dst, const void * src, size_t n);
static void * frida_memmove (void * dst, const void * src, size_t n);
static void * frida_memset (void * dst, int c, size_t n);
static int frida_memcmp (const void * a, const void * b, size_t n);
static void * frida_memchr (const void * s, int c, size_t n);
static char * frida_strchr (const char * s, int c);
static bool rustfrida_resolve_builtin_symbol (const char * name, ElfW(Addr) * value);

static pid_t frida_gettid (void);

/* ========== Entry point ========== */

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
void
frida_load (RustFridaLoaderContext * ctx)
{
  const size_t stack_size = 1024 * 1024;
  const size_t flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
  void * stack;
  void * stack_top;
  ssize_t tid;

  stack = frida_raw_mmap (NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    return;

  ctx->loader_stack = stack;
  ctx->loader_stack_size = stack_size;
  stack_top = (void *) (((uintptr_t) stack + stack_size) & ~(uintptr_t) 15);
  tid = frida_clone_thread (flags, stack_top, frida_main_raw, ctx);
  if (tid > 0)
    ctx->worker = (uintptr_t) tid;
}

static void
frida_main_raw (void * user_data)
{
  (void) frida_main (user_data);
}

static void *
frida_raw_mmap (void * addr, size_t length, int prot, int flags, int fd, off_t offset)
{
  return (void *) frida_syscall_6 (__NR_mmap, (size_t) addr, length, prot, flags, fd, offset);
}

static int
frida_raw_munmap (void * addr, size_t length)
{
  return frida_syscall_2 (__NR_munmap, (size_t) addr, length);
}

static int
frida_raw_close (int fd)
{
  return frida_syscall_1 (__NR_close, fd);
}

static int
frida_raw_socket (int domain, int type, int protocol)
{
  return frida_syscall_3 (__NR_socket, domain, type, protocol);
}

static int
frida_raw_connect (int sockfd, const struct sockaddr * addr, socklen_t addrlen)
{
  return frida_syscall_3 (__NR_connect, sockfd, (size_t) addr, addrlen);
}

static ssize_t
frida_raw_recvmsg (int sockfd, struct msghdr * msg, int flags)
{
  return frida_syscall_3 (__NR_recvmsg, sockfd, (size_t) msg, flags);
}

static ssize_t
frida_raw_send (int sockfd, const void * buf, size_t len, int flags)
{
  return frida_syscall_6 (__NR_sendto, sockfd, (size_t) buf, len, flags, 0, 0);
}

static int
frida_raw_fcntl (int fd, int cmd, size_t arg)
{
  return frida_syscall_3 (__NR_fcntl, fd, cmd, arg);
}

/* ========== Minimal in-process ELF linker for agent.so ========== */

static ElfW(Addr)
rustfrida_align_down (ElfW(Addr) value, ElfW(Addr) alignment)
{
  return value & ~(alignment - 1);
}

static ElfW(Addr)
rustfrida_align_up (ElfW(Addr) value, ElfW(Addr) alignment)
{
  return (value + alignment - 1) & ~(alignment - 1);
}

static int
rustfrida_phdr_prot (const ElfW(Phdr) * phdr)
{
  int prot = 0;

  if ((phdr->p_flags & PF_R) != 0)
    prot |= PROT_READ;
  if ((phdr->p_flags & PF_W) != 0)
    prot |= PROT_WRITE;
  if ((phdr->p_flags & PF_X) != 0)
    prot |= PROT_EXEC;

  return prot;
}

static bool
rustfrida_is_valid_elf (const ElfW(Ehdr) * ehdr)
{
  return ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
      ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
      ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
      ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
      ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
      ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
      ehdr->e_machine == EM_AARCH64 &&
      ehdr->e_type == ET_DYN;
}

static bool
rustfrida_is_mapped_elf (const ElfW(Ehdr) * ehdr)
{
  return ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
      ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
      ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
      ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
      ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
      ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
      ehdr->e_phoff >= sizeof (ElfW(Ehdr)) &&
      ehdr->e_phentsize == sizeof (ElfW(Phdr)) &&
      ehdr->e_phnum != 0 &&
      ehdr->e_phnum < 128;
}

static size_t
rustfrida_gnu_hash_nsyms (const uint32_t * gnu_hash)
{
  uint32_t nbuckets, symoffset, bloom_size;
  const uint32_t * buckets;
  const uint32_t * chains;
  uint32_t max_sym = 0;
  uint32_t i;

  if (gnu_hash == NULL)
    return 0;

  nbuckets = gnu_hash[0];
  symoffset = gnu_hash[1];
  bloom_size = gnu_hash[2];
  buckets = gnu_hash + 4 + (bloom_size * (sizeof (ElfW(Addr)) / sizeof (uint32_t)));
  chains = buckets + nbuckets;

  for (i = 0; i != nbuckets; i++)
  {
    if (buckets[i] > max_sym)
      max_sym = buckets[i];
  }

  if (max_sym < symoffset)
    return symoffset;

  i = max_sym - symoffset;
  while ((chains[i] & 1) == 0)
    i++;

  return symoffset + i + 1;
}

static size_t
rustfrida_sysv_hash_nsyms (const uint32_t * sysv_hash)
{
  if (sysv_hash == NULL)
    return 0;

  return sysv_hash[1];
}

static int
rustfrida_hex_value (char ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static const char *
rustfrida_parse_hex (const char * cursor, ElfW(Addr) * value)
{
  ElfW(Addr) result = 0;
  int digit;

  digit = rustfrida_hex_value (*cursor);
  if (digit == -1)
    return NULL;

  do
  {
    result = (result << 4) | (ElfW(Addr)) digit;
    cursor++;
    digit = rustfrida_hex_value (*cursor);
  }
  while (digit != -1);

  *value = result;
  return cursor;
}

static const char *
rustfrida_skip_spaces (const char * cursor)
{
  while (*cursor == ' ' || *cursor == '\t')
    cursor++;
  return cursor;
}

static const char *
rustfrida_next_field (const char * cursor)
{
  while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' && *cursor != '\n')
    cursor++;
  return rustfrida_skip_spaces (cursor);
}

static bool
rustfrida_export_module_init (ElfW(Addr) candidate_base, RustFridaExportModule * module)
{
  ElfW(Ehdr) * ehdr = (ElfW(Ehdr) *) candidate_base;
  ElfW(Phdr) * phdrs;
  ElfW(Half) i;
  ElfW(Addr) load_bias = candidate_base;
  ElfW(Dyn) * dynamic = NULL;
  ElfW(Dyn) * dyn;

  if (!rustfrida_is_mapped_elf (ehdr))
    return false;

  phdrs = (ElfW(Phdr) *) (candidate_base + ehdr->e_phoff);
  for (i = 0; i != ehdr->e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_LOAD)
    {
      load_bias = candidate_base - phdr->p_vaddr;
      break;
    }
  }

  for (i = 0; i != ehdr->e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_DYNAMIC)
    {
      dynamic = (ElfW(Dyn) *) (load_bias + phdr->p_vaddr);
    }
  }

  if (dynamic == NULL)
    return false;

  frida_memset (module, 0, sizeof (*module));
  module->base = load_bias;

  for (dyn = dynamic; dyn->d_tag != DT_NULL; dyn++)
  {
    ElfW(Addr) ptr = dyn->d_un.d_ptr;

    switch (dyn->d_tag)
    {
      case DT_SYMTAB:
        module->symtab = (const ElfW(Sym) *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      case DT_STRTAB:
        module->strtab = (const char *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      case DT_STRSZ:
        module->strsz = dyn->d_un.d_val;
        break;
      case DT_GNU_HASH:
        module->gnu_hash = (const uint32_t *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      case DT_HASH:
        module->sysv_hash = (const uint32_t *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      default:
        break;
    }
  }

  if (module->symtab == NULL || module->strtab == NULL || module->strsz == 0)
    return false;

  module->nsyms = rustfrida_gnu_hash_nsyms (module->gnu_hash);
  if (module->nsyms == 0)
    module->nsyms = rustfrida_sysv_hash_nsyms (module->sysv_hash);
  if ((ElfW(Addr)) module->strtab > (ElfW(Addr)) module->symtab)
  {
    size_t by_layout = ((ElfW(Addr)) module->strtab - (ElfW(Addr)) module->symtab) / sizeof (ElfW(Sym));

    if (by_layout > module->nsyms && by_layout < 65536)
      module->nsyms = by_layout;
  }

  return module->nsyms != 0;
}

static bool
rustfrida_address_is_executable (ElfW(Addr) address)
{
  static const char maps_path[] = "/proc/self/maps";
  char buffer[8192];
  char line[512];
  size_t line_len = 0;
  int fd;
  ssize_t n;
  bool result = false;

  fd = frida_syscall_4 (__NR_openat, AT_FDCWD, (size_t) maps_path, O_RDONLY, 0);
  if (fd < 0)
    return false;

  while (!result && (n = frida_syscall_3 (__NR_read, fd, (size_t) buffer, sizeof (buffer))) > 0)
  {
    ssize_t i;

    for (i = 0; i != n; i++)
    {
      char ch = buffer[i];

      if (ch == '\n' || line_len == sizeof (line) - 1)
      {
        ElfW(Addr) start;
        ElfW(Addr) end;
        const char * cursor;

        line[line_len] = '\0';
        line_len = 0;

        cursor = rustfrida_parse_hex (line, &start);
        if (cursor == NULL || *cursor != '-')
          continue;
        cursor++;
        cursor = rustfrida_parse_hex (cursor, &end);
        if (cursor == NULL || address < start || address >= end)
          continue;

        cursor = rustfrida_skip_spaces (cursor);
        result = cursor[2] == 'x';
        break;
      }
      else
      {
        line[line_len++] = ch;
      }
    }
  }

  if (!result && line_len != 0)
  {
    ElfW(Addr) start;
    ElfW(Addr) end;
    const char * cursor;

    line[line_len] = '\0';
    cursor = rustfrida_parse_hex (line, &start);
    if (cursor != NULL && *cursor == '-')
    {
      cursor++;
      cursor = rustfrida_parse_hex (cursor, &end);
      if (cursor != NULL && address >= start && address < end)
      {
        cursor = rustfrida_skip_spaces (cursor);
        result = cursor[2] == 'x';
      }
    }
  }

  frida_syscall_1 (__NR_close, fd);
  return result;
}

static bool
rustfrida_resolver_add_module (RustFridaSymbolResolver * resolver, ElfW(Addr) base)
{
  RustFridaExportModule module;
  size_t i;

  if (resolver->count == RUSTFRIDA_MAX_MODULES)
    return false;

  for (i = 0; i != resolver->count; i++)
  {
    if (resolver->modules[i].base == base)
      return true;
  }

  if (!rustfrida_export_module_init (base, &module))
    return false;

  resolver->modules[resolver->count++] = module;
  return true;
}

static bool
rustfrida_maps_line_add_module (RustFridaSymbolResolver * resolver, const char * line)
{
  ElfW(Addr) start;
  ElfW(Addr) ignored;
  ElfW(Addr) offset;
  const char * cursor = line;
  const char * path;

  cursor = rustfrida_parse_hex (cursor, &start);
  if (cursor == NULL || *cursor != '-')
    return false;
  cursor++;
  cursor = rustfrida_parse_hex (cursor, &ignored);
  if (cursor == NULL)
    return false;

  cursor = rustfrida_skip_spaces (cursor);
  if (cursor[0] != 'r')
    return false;
  cursor = rustfrida_next_field (cursor);

  cursor = rustfrida_parse_hex (cursor, &offset);
  if (cursor == NULL)
    return false;
  cursor = rustfrida_next_field (cursor);
  cursor = rustfrida_next_field (cursor);
  cursor = rustfrida_next_field (cursor);

  path = cursor;
  if (*path != '/')
    return false;
  /*
   * Only index the platform modules needed by the agent's imports. Scanning
   * every app .so is both noisy and unsafe in hardened apps with unusual
   * mappings or intentionally hostile ELF layouts.
   */
  if (!frida_str_has_suffix (path, "/libc.so") &&
      !frida_str_has_suffix (path, "/libdl.so") &&
      !frida_str_has_suffix (path, "/libm.so") &&
      !frida_str_has_suffix (path, "/linker64"))
  {
    return false;
  }

  if (offset > start)
    return false;

  return rustfrida_resolver_add_module (resolver, start - offset);
}

static bool
rustfrida_build_symbol_resolver (RustFridaLinkedModule * module, const FridaLibcApi * libc,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base)
{
  static const char maps_path[] = "/proc/self/maps";
  char buffer[16384];
  char line[512];
  size_t line_len = 0;
  int fd;
  ssize_t n;

  frida_memset (&module->resolver, 0, sizeof (module->resolver));

  if (libc_base != 0)
    rustfrida_resolver_add_module (&module->resolver, libc_base);
  if (linker_base != 0)
    rustfrida_resolver_add_module (&module->resolver, linker_base);

  fd = frida_syscall_4 (__NR_openat, AT_FDCWD, (size_t) maps_path, O_RDONLY, 0);
  if (fd < 0)
  {
    rustfrida_set_error (module, libc, "open /proc/self/maps failed");
    return false;
  }

  while ((n = frida_syscall_3 (__NR_read, fd, (size_t) buffer, sizeof (buffer))) > 0)
  {
    ssize_t i;

    for (i = 0; i != n; i++)
    {
      char ch = buffer[i];

      if (ch == '\n' || line_len == sizeof (line) - 1)
      {
        line[line_len] = '\0';
        rustfrida_maps_line_add_module (&module->resolver, line);
        line_len = 0;
      }
      else
      {
        line[line_len++] = ch;
      }
    }
  }

  if (line_len != 0)
  {
    line[line_len] = '\0';
    rustfrida_maps_line_add_module (&module->resolver, line);
  }

  frida_syscall_1 (__NR_close, fd);

  if (module->resolver.count == 0)
  {
    rustfrida_set_error (module, libc, "no export modules found");
    return false;
  }

  return true;
}

static bool
rustfrida_resolver_lookup (const RustFridaSymbolResolver * resolver, const char * name, ElfW(Addr) * value)
{
  size_t module_index;

  for (module_index = 0; module_index != resolver->count; module_index++)
  {
    const RustFridaExportModule * module = &resolver->modules[module_index];
    size_t i;

    for (i = 0; i != module->nsyms; i++)
    {
      const ElfW(Sym) * sym = &module->symtab[i];
      unsigned char bind;
      unsigned char type;

      if (sym->st_name >= module->strsz || sym->st_shndx == SHN_UNDEF || sym->st_value == 0)
        continue;

      bind = ELF64_ST_BIND (sym->st_info);
      if (bind != STB_GLOBAL && bind != STB_WEAK)
        continue;

      type = ELF64_ST_TYPE (sym->st_info);
      if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE && type != STT_GNU_IFUNC)
        continue;

      if (frida_streq (module->strtab + sym->st_name, name))
      {
        ElfW(Addr) resolved = (sym->st_shndx == SHN_ABS) ? sym->st_value : module->base + sym->st_value;

        if (type == STT_GNU_IFUNC)
        {
          if (!rustfrida_address_is_executable (resolved))
            continue;
          resolved = ((ElfW(Addr) (*) (void)) resolved) ();
          if (resolved == 0 || !rustfrida_address_is_executable (resolved))
            continue;
        }
        *value = resolved;
        return true;
      }
    }
  }

  *value = 0;
  return false;
}

static void
rustfrida_set_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * message)
{
  if (libc->sprintf != NULL)
    libc->sprintf (module->error, "%s", message);
}

static void
rustfrida_set_symbol_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * prefix, const char * name)
{
  if (libc->sprintf != NULL)
  {
    libc->sprintf (module->error, "%s%s (modules=%zu nsyms=%zu,%zu,%zu)",
        prefix,
        name,
        module->resolver.count,
        module->resolver.count > 0 ? module->resolver.modules[0].nsyms : 0,
        module->resolver.count > 1 ? module->resolver.modules[1].nsyms : 0,
        module->resolver.count > 2 ? module->resolver.modules[2].nsyms : 0);
  }
}

static bool
rustfrida_parse_dynamic (RustFridaLinkedModule * module)
{
  ElfW(Dyn) * dyn;
  ElfW(Rela) * rela = NULL;
  size_t relasz = 0;
  ElfW(Rela) * jmprel = NULL;
  size_t pltrelsz = 0;
  size_t max_reloc_sym = 0;

  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_SYMTAB:
        module->symtab = (const ElfW(Sym) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_STRTAB:
        module->strtab = (const char *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_STRSZ:
        module->strsz = dyn->d_un.d_val;
        break;
      case DT_GNU_HASH:
        module->gnu_hash = (const uint32_t *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_RELA:
        rela = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_RELASZ:
        relasz = dyn->d_un.d_val;
        break;
      case DT_JMPREL:
        jmprel = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (module->symtab == NULL || module->strtab == NULL || module->strsz == 0)
    return false;

  module->nsyms = rustfrida_gnu_hash_nsyms (module->gnu_hash);

  if (rela != NULL)
  {
    size_t n = relasz / sizeof (ElfW(Rela));
    size_t i;
    for (i = 0; i != n; i++)
    {
      size_t sym = ELF64_R_SYM (rela[i].r_info);
      if (sym > max_reloc_sym)
        max_reloc_sym = sym;
    }
  }
  if (jmprel != NULL)
  {
    size_t n = pltrelsz / sizeof (ElfW(Rela));
    size_t i;
    for (i = 0; i != n; i++)
    {
      size_t sym = ELF64_R_SYM (jmprel[i].r_info);
      if (sym > max_reloc_sym)
        max_reloc_sym = sym;
    }
  }

  if (module->nsyms <= max_reloc_sym)
    module->nsyms = max_reloc_sym + 1;

  return module->nsyms != 0;
}

static bool
rustfrida_resolve_symbol (RustFridaLinkedModule * module, size_t sym_index, const FridaLibcApi * libc, ElfW(Addr) * value)
{
  const ElfW(Sym) * sym;
  const char * name;
  unsigned char bind;

  if (sym_index == 0)
  {
    *value = 0;
    return true;
  }

  if (sym_index >= module->nsyms)
  {
    rustfrida_set_error (module, libc, "symbol index out of range");
    return false;
  }

  sym = &module->symtab[sym_index];
  if (sym->st_shndx != SHN_UNDEF)
  {
    *value = (sym->st_shndx == SHN_ABS) ? sym->st_value : module->base + sym->st_value;
    return true;
  }

  if (sym->st_name >= module->strsz)
  {
    rustfrida_set_error (module, libc, "symbol name out of range");
    return false;
  }

  name = module->strtab + sym->st_name;
  bind = ELF64_ST_BIND (sym->st_info);
  if (rustfrida_resolve_builtin_symbol (name, value))
    return true;
  if (rustfrida_resolver_lookup (&module->resolver, name, value))
    return true;

  if (bind == STB_WEAK)
  {
    *value = 0;
    return true;
  }

  rustfrida_set_symbol_error (module, libc, "missing symbol: ", name);
  return false;
}

static bool
rustfrida_apply_relocations (RustFridaLinkedModule * module, ElfW(Rela) * rela, size_t relasz, const FridaLibcApi * libc)
{
  size_t count = relasz / sizeof (ElfW(Rela));
  size_t i;

  for (i = 0; i != count; i++)
  {
    ElfW(Rela) * r = &rela[i];
    ElfW(Addr) * target = (ElfW(Addr) *) (module->base + r->r_offset);
    size_t type = ELF64_R_TYPE (r->r_info);
    size_t sym_index = ELF64_R_SYM (r->r_info);
    ElfW(Addr) symbol_value;

    switch (type)
    {
      case R_AARCH64_RELATIVE:
        *target = module->base + r->r_addend;
        break;
      case R_AARCH64_ABS64:
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT:
        if (!rustfrida_resolve_symbol (module, sym_index, libc, &symbol_value))
          return false;
        *target = symbol_value + r->r_addend;
        break;
      case R_AARCH64_TLSDESC:
        /* TLSDESC: set to 0 (we don't use TLS, skip resolution) */
        *target = 0;
        break;
      default:
        if (libc->sprintf != NULL)
          libc->sprintf (module->error, "unsupported relocation type: %zu", type);
        return false;
    }
  }

  return true;
}

static bool
rustfrida_protect_relro (RustFridaLinkedModule * module, const FridaLibcApi * libc)
{
  ElfW(Half) i;

  for (i = 0; i != module->phdr_count; i++)
  {
    const ElfW(Phdr) * phdr = &module->phdrs[i];
    ElfW(Addr) start, end;

    if (phdr->p_type != PT_GNU_RELRO || phdr->p_memsz == 0)
      continue;

    start = rustfrida_align_down (module->base + phdr->p_vaddr, 4096);
    end = rustfrida_align_up (module->base + phdr->p_vaddr + phdr->p_memsz, 4096);
    if (frida_syscall_3 (__NR_mprotect, start, end - start, PROT_READ) != 0)
    {
      rustfrida_set_error (module, libc, "mprotect RELRO failed");
      return false;
    }
  }

  return true;
}

static void
rustfrida_call_init_functions (RustFridaLinkedModule * module)
{
  ElfW(Dyn) * dyn;
  void (* init_func) (void) = NULL;
  void (** init_array) (void) = NULL;
  size_t init_array_size = 0;
  size_t i;

  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_INIT:
        init_func = (void (*) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_INIT_ARRAY:
        init_array = (void (**) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_INIT_ARRAYSZ:
        init_array_size = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (init_func != NULL)
    init_func ();

  if (init_array != NULL && init_array_size != 0)
  {
    for (i = 0; i != init_array_size / sizeof (init_array[0]); i++)
    {
      if (init_array[i] != NULL)
        init_array[i] ();
    }
  }

  module->initialized = true;
}

static void
rustfrida_call_fini_functions (RustFridaLinkedModule * module)
{
  ElfW(Dyn) * dyn;
  void (* fini_func) (void) = NULL;
  void (** fini_array) (void) = NULL;
  size_t fini_array_size = 0;
  size_t count;

  if (!module->initialized || module->finalized)
    return;
  module->finalized = true;

  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_FINI:
        fini_func = (void (*) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_FINI_ARRAY:
        fini_array = (void (**) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_FINI_ARRAYSZ:
        fini_array_size = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (fini_array != NULL && fini_array_size != 0)
  {
    count = fini_array_size / sizeof (fini_array[0]);
    while (count != 0)
    {
      void (* fini) (void) = fini_array[--count];
      if (fini != NULL)
        fini ();
    }
  }

  if (fini_func != NULL)
    fini_func ();
}

static void
rustfrida_get_fd_vma_name (int fd, char * name, size_t name_size, const FridaLibcApi * libc)
{
  char path[32];
  char target[128];
  ssize_t n;
  const char * start = target;
  const char * cursor;
  size_t copied = 0;

  if (name_size == 0)
    return;

  name[0] = '\0';

  if (libc->sprintf == NULL)
    return;

  libc->sprintf (path, "/proc/self/fd/%d", fd);
  n = frida_syscall_4 (__NR_readlinkat, AT_FDCWD, (size_t) path, (size_t) target, sizeof (target) - 1);
  if (n <= 0)
    return;

  target[n] = '\0';

  for (cursor = target; *cursor != '\0'; cursor++)
  {
    if (cursor[0] == 'm' && cursor[1] == 'e' && cursor[2] == 'm' &&
        cursor[3] == 'f' && cursor[4] == 'd' && cursor[5] == ':')
    {
      start = cursor + 6;
      break;
    }
  }

  for (cursor = start; *cursor != '\0' && *cursor != ' ' && copied + 1 < name_size; cursor++)
    name[copied++] = *cursor;

  name[copied] = '\0';
}

static void
rustfrida_set_vma_name (ElfW(Addr) address, size_t size, const char * name)
{
  if (address == 0 || size == 0 || name == NULL || name[0] == '\0')
    return;

  frida_syscall_5 (__NR_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME, address, size, (size_t) name);
}

static bool
rustfrida_link_agent (int fd, const FridaLibcApi * libc, RustFridaLinkedModule * module, int diagfd,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base)
{
  size_t page_size = 4096;
  ssize_t file_size;
  void * file_map = MAP_FAILED;
  void * reservation = MAP_FAILED;
  const ElfW(Ehdr) * file_ehdr;
  const ElfW(Phdr) * file_phdrs;
  ElfW(Addr) min_vaddr = (ElfW(Addr)) -1;
  ElfW(Addr) max_vaddr = 0;
  ElfW(Addr) load_start;
  ElfW(Addr) load_end;
  ElfW(Addr) load_size;
  ElfW(Addr) load_bias;
  ElfW(Half) i;
  ElfW(Rela) * rela = NULL;
  size_t relasz = 0;
  ElfW(Rela) * jmprel = NULL;
  size_t pltrelsz = 0;
  ElfW(Dyn) * dyn;
  char agent_vma_name[80];

  frida_memset (module, 0, sizeof (*module));
  rustfrida_get_fd_vma_name (fd, agent_vma_name, sizeof (agent_vma_name), libc);
  frida_send_log (diagfd, "link: start", libc);

  file_size = frida_syscall_3 (__NR_lseek, fd, 0, SEEK_END);
  if (file_size <= 0)
  {
    rustfrida_set_error (module, libc, "lseek agent fd failed");
    return false;
  }

  file_map = frida_raw_mmap (NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (file_map == MAP_FAILED)
  {
    rustfrida_set_error (module, libc, "mmap agent fd failed");
    return false;
  }

  file_ehdr = (const ElfW(Ehdr) *) file_map;
  if (!rustfrida_is_valid_elf (file_ehdr))
  {
    rustfrida_set_error (module, libc, "invalid agent ELF");
    goto fail;
  }
  frida_send_log (diagfd, "link: elf mapped", libc);

  if (file_ehdr->e_phoff + (file_ehdr->e_phnum * sizeof (ElfW(Phdr))) > (size_t) file_size)
  {
    rustfrida_set_error (module, libc, "agent phdr out of range");
    goto fail;
  }

  file_phdrs = (const ElfW(Phdr) *) ((const uint8_t *) file_map + file_ehdr->e_phoff);
  for (i = 0; i != file_ehdr->e_phnum; i++)
  {
    const ElfW(Phdr) * phdr = &file_phdrs[i];

    if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
      continue;

    if (phdr->p_vaddr < min_vaddr)
      min_vaddr = phdr->p_vaddr;
    if (phdr->p_vaddr + phdr->p_memsz > max_vaddr)
      max_vaddr = phdr->p_vaddr + phdr->p_memsz;
  }

  if (min_vaddr == (ElfW(Addr)) -1 || max_vaddr <= min_vaddr)
  {
    rustfrida_set_error (module, libc, "agent has no loadable segments");
    goto fail;
  }

  load_start = rustfrida_align_down (min_vaddr, page_size);
  load_end = rustfrida_align_up (max_vaddr, page_size);
  load_size = load_end - load_start;

  reservation = frida_raw_mmap (NULL, load_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED)
  {
    rustfrida_set_error (module, libc, "reserve agent address space failed");
    goto fail;
  }

  load_bias = (ElfW(Addr)) reservation - load_start;
  rustfrida_set_vma_name ((ElfW(Addr)) reservation, load_size, agent_vma_name);

  for (i = 0; i != file_ehdr->e_phnum; i++)
  {
    const ElfW(Phdr) * phdr = &file_phdrs[i];
    ElfW(Addr) seg_start;
    ElfW(Addr) seg_end;
    ElfW(Addr) map_size;
    ElfW(Addr) target;
    ElfW(Off) file_page_start;
    int prot;

    if (phdr->p_type == PT_DYNAMIC)
      module->dynamic = (ElfW(Dyn) *) (load_bias + phdr->p_vaddr);

    if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
      continue;

    if (phdr->p_offset + phdr->p_filesz > (ElfW(Off)) file_size)
    {
      rustfrida_set_error (module, libc, "agent segment out of range");
      goto fail;
    }

    seg_start = rustfrida_align_down (phdr->p_vaddr, page_size);
    seg_end = rustfrida_align_up (phdr->p_vaddr + phdr->p_memsz, page_size);
    map_size = seg_end - seg_start;
    target = load_bias + seg_start;
    file_page_start = rustfrida_align_down (phdr->p_offset, page_size);
    prot = rustfrida_phdr_prot (phdr);

    if ((uint64_t) file_page_start + map_size > (uint64_t) file_size)
    {
      rustfrida_set_error (module, libc, "agent padded segment out of range");
      goto fail;
    }

    {
      void * mapped = frida_raw_mmap ((void *) target, map_size, prot,
          MAP_PRIVATE | MAP_FIXED, fd, file_page_start);
      if (mapped == MAP_FAILED)
      {
        rustfrida_set_error (module, libc, "map agent segment failed");
        goto fail;
      }
    }

    if (phdr->p_memsz > phdr->p_filesz)
    {
      ElfW(Addr) bss_start = load_bias + phdr->p_vaddr + phdr->p_filesz;
      ElfW(Addr) bss_end = load_bias + rustfrida_align_up (phdr->p_vaddr + phdr->p_filesz, page_size);
      ElfW(Addr) limit = load_bias + seg_end;

      if (bss_end > limit)
        bss_end = limit;
      if (bss_end > bss_start)
        frida_memset ((void *) bss_start, 0, bss_end - bss_start);
    }
  }

  frida_send_log (diagfd, "link: load segments mapped", libc);

  module->base = load_bias;
  module->load_start = (ElfW(Addr)) reservation;
  module->load_end = (ElfW(Addr)) reservation + load_size;
  module->phdrs = (const ElfW(Phdr) *) (load_bias + file_ehdr->e_phoff);
  module->phdr_count = file_ehdr->e_phnum;

  frida_raw_munmap (file_map, file_size);
  file_map = MAP_FAILED;

  if (module->dynamic == NULL)
  {
    rustfrida_set_error (module, libc, "agent has no dynamic section");
    goto fail;
  }

  if (!rustfrida_parse_dynamic (module))
  {
    rustfrida_set_error (module, libc, "agent dynamic section incomplete");
    goto fail;
  }
  frida_send_log (diagfd, "link: dynamic parsed", libc);

  if (!rustfrida_build_symbol_resolver (module, libc, libc_base, linker_base))
    goto fail;
  frida_send_log (diagfd, "link: resolver built", libc);

  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_RELA:
        rela = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_RELASZ:
        relasz = dyn->d_un.d_val;
        break;
      case DT_JMPREL:
        jmprel = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn->d_un.d_val;
        break;
      case DT_PLTREL:
        if (dyn->d_un.d_val != DT_RELA)
        {
          rustfrida_set_error (module, libc, "unsupported PLT relocation format");
          goto fail;
        }
        break;
      default:
        break;
    }
  }

  if (rela != NULL && !rustfrida_apply_relocations (module, rela, relasz, libc))
    goto fail;
  frida_send_log (diagfd, "link: rela applied", libc);
  if (jmprel != NULL && !rustfrida_apply_relocations (module, jmprel, pltrelsz, libc))
    goto fail;
  frida_send_log (diagfd, "link: plt rela applied", libc);

  if (!rustfrida_protect_relro (module, libc))
    goto fail;
  frida_send_log (diagfd, "link: relro protected", libc);

  rustfrida_call_init_functions (module);
  frida_send_log (diagfd, "link: init done", libc);
  return true;

fail:
  if (file_map != MAP_FAILED)
    frida_raw_munmap (file_map, file_size);
  if (reservation != MAP_FAILED)
  {
    module->load_start = (ElfW(Addr)) reservation;
    module->load_end = (ElfW(Addr)) reservation + load_size;
  }
  rustfrida_unmap_module (module, libc);
  return false;
}

static void *
rustfrida_find_export (RustFridaLinkedModule * module, const char * symbol)
{
  size_t i;

  if (module->symtab == NULL || module->strtab == NULL)
    return NULL;

  for (i = 0; i != module->nsyms; i++)
  {
    const ElfW(Sym) * sym = &module->symtab[i];
    unsigned char bind;

    if (sym->st_name >= module->strsz || sym->st_shndx == SHN_UNDEF)
      continue;

    bind = ELF64_ST_BIND (sym->st_info);
    if (bind != STB_GLOBAL && bind != STB_WEAK)
      continue;

    if (frida_streq (module->strtab + sym->st_name, symbol))
      return (void *) (module->base + sym->st_value);
  }

  return NULL;
}

static void
rustfrida_close_module (RustFridaLinkedModule * module, const FridaLibcApi * libc)
{
  rustfrida_call_fini_functions (module);
  rustfrida_unmap_module (module, libc);
}

static void
rustfrida_unmap_module (RustFridaLinkedModule * module, const FridaLibcApi * libc)
{
  if (module->load_start != 0 && module->load_end > module->load_start)
  {
    frida_raw_munmap ((void *) module->load_start, module->load_end - module->load_start);
    module->load_start = 0;
    module->load_end = 0;
    module->base = 0;
    module->dynamic = NULL;
    module->phdrs = NULL;
    module->phdr_count = 0;
  }
}

/* ========== Worker thread ========== */

static void *
frida_main (void * user_data)
{
  RustFridaLoaderContext * ctx = user_data;
  const FridaLibcApi * libc = ctx->libc;
  RustFridaLinkedModule agent_module;
  pid_t thread_id;
  FridaUnloadPolicy unload_policy;
  int ctrlfd_for_peer, ctrlfd, agent_codefd, agent_ctrlfd;

  frida_syscall_5 (__NR_prctl, PR_SET_NAME, (size_t) "wwb-loader", 0, 0, 0);

  frida_memset (&agent_module, 0, sizeof (agent_module));
  thread_id = frida_gettid ();
  unload_policy = FRIDA_UNLOAD_POLICY_IMMEDIATE;
  ctrlfd = -1;
  agent_codefd = -1;
  agent_ctrlfd = -1;

  /* Close the peer end of the control socketpair */
  ctrlfd_for_peer = ctx->ctrlfds[0];
  if (ctrlfd_for_peer != -1)
    frida_raw_close (ctrlfd_for_peer);

  /* Try the pre-created socketpair fd first */
  ctrlfd = ctx->ctrlfds[1];
  if (ctrlfd != -1)
  {
    if (!frida_send_hello (ctrlfd, thread_id, libc))
    {
      frida_raw_close (ctrlfd);
      ctrlfd = -1;
    }
  }
  /* Fall back to abstract Unix socket */
  if (ctrlfd == -1)
  {
    ctrlfd = frida_connect (ctx->fallback_address, libc);
    if (ctrlfd == -1)
      goto beach;

    if (!frida_send_hello (ctrlfd, thread_id, libc))
      goto beach;
  }

  /* Link the agent SO from a memfd received over the socket. */
  if (ctx->agent_handle == NULL)
  {
    char recv_diag[32];

    agent_codefd = frida_receive_fd_diag (ctrlfd, libc, recv_diag);
    if (agent_codefd == -1)
    {
      frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN,
          recv_diag /* contains diag msg */, libc);
      goto beach;
    }

    if (!rustfrida_link_agent (agent_codefd, libc, &agent_module, ctrlfd,
            (ElfW(Addr)) ctx->libc_base, (ElfW(Addr)) ctx->linker_base))
      goto dlopen_failed;
    frida_send_log (ctrlfd, "worker: agent linked", libc);

    frida_raw_close (agent_codefd);
    agent_codefd = -1;

    ctx->agent_entrypoint_impl = rustfrida_find_export (&agent_module, ctx->agent_entrypoint);
    if (ctx->agent_entrypoint_impl == NULL)
      goto dlsym_failed;
    ctx->agent_current_thread_eval_impl = rustfrida_find_export (&agent_module, ctx->agent_current_thread_eval);
    frida_send_log (ctrlfd, "worker: exports resolved", libc);

    ctx->agent_handle = (void *) agent_module.base;
  }

  /* Receive the REPL socketpair fd for the agent */
  agent_ctrlfd = frida_receive_fd (ctrlfd, libc);
  frida_send_log (ctrlfd, "worker: repl fd received", libc);
  if (agent_ctrlfd != -1)
    frida_enable_close_on_exec (agent_ctrlfd, libc);

  /* Signal READY and wait for ACK before entering agent */
  if (!frida_send_ready (ctrlfd, libc))
  {
    frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN,
        "frida_send_ready failed", libc);
    goto beach;
  }
  if (!frida_receive_ack (ctrlfd, libc))
  {
    frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN,
        "frida_receive_ack failed", libc);
    goto beach;
  }

  /* Construct AgentArgs on stack and call hello_entry */
  {
    AgentArgs args;
    hello_entry_fn entry = (hello_entry_fn) ctx->agent_entrypoint_impl;

    args.table      = ctx->string_table_addr;
    args.ctrl_fd    = agent_ctrlfd;
    args.agent_memfd = -1;

    /* hello_entry blocks in the agent command loop */
    entry (&args);

    /* Agent returned — close the REPL fd so the host observes EOF before dlclose. */
    if (agent_ctrlfd != -1)
      frida_raw_close (agent_ctrlfd);
    agent_ctrlfd = -1;
  }

  goto beach;

dlopen_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLOPEN,
        agent_module.error[0] != '\0' ? agent_module.error : "Unable to link library",
        libc);
    goto beach;
  }
dlsym_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLSYM,
        "Unable to find entrypoint",
        libc);
    goto beach;
  }
beach:
  {
    if (agent_module.load_start != 0)
    {
      void * module_handle = (void *) agent_module.base;
      rustfrida_close_module (&agent_module, libc);
      if (ctx->agent_handle == module_handle)
      {
        ctx->agent_handle = NULL;
        ctx->agent_entrypoint_impl = NULL;
        ctx->agent_current_thread_eval_impl = NULL;
      }
    }

    if (agent_ctrlfd != -1)
      frida_raw_close (agent_ctrlfd);

    if (agent_codefd != -1)
      frida_raw_close (agent_codefd);

    if (ctrlfd != -1)
    {
      frida_send_bye (ctrlfd, unload_policy, libc);
      frida_raw_close (ctrlfd);
    }

    return NULL;
  }
}

/* ========== Socket helpers (from Frida's loader.c, verbatim) ========== */

/* TODO: Handle EINTR. */

static int
frida_connect (const char * address, const FridaLibcApi * libc)
{
  bool success = false;
  int sockfd;
  struct sockaddr_un addr;
  size_t len;
  const char * c;
  char ch;

  sockfd = frida_raw_socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1)
    goto beach;

  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  for (c = address, len = 0; (ch = *c) != '\0'; c++, len++)
    addr.sun_path[1 + len] = ch;

  if (frida_raw_connect (sockfd, (struct sockaddr *) &addr, offsetof (struct sockaddr_un, sun_path) + 1 + len) == -1)
    goto beach;

  success = true;

beach:
  if (!success && sockfd != -1)
  {
    frida_raw_close (sockfd);
    sockfd = -1;
  }

  return sockfd;
}

static bool
frida_send_hello (int sockfd, pid_t thread_id, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_HELLO;
  FridaHelloMessage hello = {
    .thread_id = thread_id,
  };

  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return frida_send_chunk (sockfd, &hello, sizeof (hello), libc);
}

static bool
frida_send_ready (int sockfd, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_READY;

  return frida_send_chunk (sockfd, &type, sizeof (type), libc);
}

static bool
frida_receive_ack (int sockfd, const FridaLibcApi * libc)
{
  FridaMessageType type;

  if (!frida_receive_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return type == FRIDA_MESSAGE_ACK;
}

static bool
frida_send_bye (int sockfd, FridaUnloadPolicy unload_policy, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_BYE;
  FridaByeMessage bye = {
    .unload_policy = unload_policy,
  };

  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return frida_send_chunk (sockfd, &bye, sizeof (bye), libc);
}

static bool
frida_send_error (int sockfd, FridaMessageType type, const char * message, const FridaLibcApi * libc)
{
  uint16_t length;

  length = frida_strlen (message);

  #define FRIDA_SEND_VALUE(v) \
      if (!frida_send_chunk (sockfd, &(v), sizeof (v), libc)) \
        return false
  #define FRIDA_SEND_BYTES(data, size) \
      if (!frida_send_chunk (sockfd, data, size, libc)) \
        return false

  FRIDA_SEND_VALUE (type);
  FRIDA_SEND_VALUE (length);
  FRIDA_SEND_BYTES (message, length);

  return true;
}

static bool
frida_send_log (int sockfd, const char * message, const FridaLibcApi * libc)
{
  return frida_send_error (sockfd, FRIDA_MESSAGE_LOG, message, libc);
}

static bool
frida_receive_chunk (int sockfd, void * buffer, size_t length, const FridaLibcApi * libc)
{
  void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    struct iovec io = {
      .iov_base = cursor,
      .iov_len = remaining
    };
    struct msghdr msg;
    ssize_t n;

    /*
     * Avoid inline initialization to prevent the compiler attempting to insert
     * a call to memset.
     */
    msg.msg_name = NULL,
    msg.msg_namelen = 0,
    msg.msg_iov = &io,
    msg.msg_iovlen = 1,
    msg.msg_control = NULL,
    msg.msg_controllen = 0,

    n = frida_raw_recvmsg (sockfd, &msg, 0);
    if (n <= 0)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static int
frida_receive_fd_diag (int sockfd, const FridaLibcApi * libc, char * diag_buf)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  FridaControlMessage control;
  struct msghdr msg;

  msg.msg_name = NULL,
  msg.msg_namelen = 0,
  msg.msg_iov = &io,
  msg.msg_iovlen = 1,
  msg.msg_control = &control,
  msg.msg_controllen = sizeof (control),

  res = frida_raw_recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0 || msg.msg_controllen == 0)
  {
    libc->sprintf (diag_buf, "recvfd:res=%d,ctl=%d,fd=%d",
        res, (int) msg.msg_controllen, sockfd);
    return -1;
  }

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static int
frida_receive_fd (int sockfd, const FridaLibcApi * libc)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  FridaControlMessage control;
  struct msghdr msg;

  /*
   * Avoid inline initialization to prevent the compiler attempting to insert
   * a call to memset.
   */
  msg.msg_name = NULL,
  msg.msg_namelen = 0,
  msg.msg_iov = &io,
  msg.msg_iovlen = 1,
  msg.msg_control = &control,
  msg.msg_controllen = sizeof (control),

  res = frida_raw_recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0 || msg.msg_controllen == 0)
    return -1;

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static bool
frida_send_chunk (int sockfd, const void * buffer, size_t length, const FridaLibcApi * libc)
{
  const void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    ssize_t n;

    n = frida_raw_send (sockfd, cursor, remaining, MSG_NOSIGNAL);
    if (n == -1)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static void
frida_enable_close_on_exec (int fd, const FridaLibcApi * libc)
{
  frida_raw_fcntl (fd, F_SETFD, frida_raw_fcntl (fd, F_GETFD, 0) | FD_CLOEXEC);
}

static size_t
frida_strlen (const char * str)
{
  size_t n = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    asm ("");
    n++;
  }

  return n;
}

static int
frida_strcmp (const char * a, const char * b)
{
  while (*a != '\0' && *a == *b)
  {
    a++;
    b++;
  }

  return ((unsigned char) *a) - ((unsigned char) *b);
}

static bool
frida_streq (const char * a, const char * b)
{
  while (*a != '\0' && *a == *b)
  {
    a++;
    b++;
  }

  return *a == *b;
}

static bool
frida_str_has_suffix (const char * str, const char * suffix)
{
  size_t str_len = 0;
  size_t suffix_len = frida_strlen (suffix);
  size_t i;

  while (str[str_len] != '\0' && str[str_len] != '\n')
    str_len++;

  if (str_len < suffix_len)
    return false;

  for (i = 0; i != suffix_len; i++)
  {
    if (str[str_len - suffix_len + i] != suffix[i])
      return false;
  }

  return true;
}

static void *
frida_memcpy (void * dst, const void * src, size_t n)
{
  uint8_t * d = dst;
  const uint8_t * s = src;

  while (n != 0)
  {
    *d++ = *s++;
    n--;
  }

  return dst;
}

static void *
frida_memmove (void * dst, const void * src, size_t n)
{
  uint8_t * d = dst;
  const uint8_t * s = src;

  if (d == s || n == 0)
    return dst;

  if (d < s)
  {
    while (n != 0)
    {
      *d++ = *s++;
      n--;
    }
  }
  else
  {
    d += n;
    s += n;
    while (n != 0)
    {
      *--d = *--s;
      n--;
    }
  }

  return dst;
}

static void *
frida_memset (void * dst, int c, size_t n)
{
  uint8_t * d = dst;

  while (n != 0)
  {
    *d++ = (uint8_t) c;
    n--;
  }

  return dst;
}

static int
frida_memcmp (const void * a, const void * b, size_t n)
{
  const uint8_t * ap = a;
  const uint8_t * bp = b;

  while (n != 0)
  {
    if (*ap != *bp)
      return ((int) *ap) - ((int) *bp);
    ap++;
    bp++;
    n--;
  }

  return 0;
}

static void *
frida_memchr (const void * s, int c, size_t n)
{
  const uint8_t * cursor = s;
  uint8_t needle = (uint8_t) c;

  while (n != 0)
  {
    if (*cursor == needle)
      return (void *) cursor;
    cursor++;
    n--;
  }

  return NULL;
}

static char *
frida_strchr (const char * s, int c)
{
  char needle = (char) c;

  for (;;)
  {
    if (*s == needle)
      return (char *) s;
    if (*s == '\0')
      return NULL;
    s++;
  }
}

static bool
rustfrida_resolve_builtin_symbol (const char * name, ElfW(Addr) * value)
{
  if (frida_streq (name, "memcpy"))
    *value = (ElfW(Addr)) (uintptr_t) frida_memcpy;
  else if (frida_streq (name, "memmove"))
    *value = (ElfW(Addr)) (uintptr_t) frida_memmove;
  else if (frida_streq (name, "memset"))
    *value = (ElfW(Addr)) (uintptr_t) frida_memset;
  else if (frida_streq (name, "memcmp"))
    *value = (ElfW(Addr)) (uintptr_t) frida_memcmp;
  else if (frida_streq (name, "memchr"))
    *value = (ElfW(Addr)) (uintptr_t) frida_memchr;
  else if (frida_streq (name, "strlen"))
    *value = (ElfW(Addr)) (uintptr_t) frida_strlen;
  else if (frida_streq (name, "strcmp"))
    *value = (ElfW(Addr)) (uintptr_t) frida_strcmp;
  else if (frida_streq (name, "strchr"))
    *value = (ElfW(Addr)) (uintptr_t) frida_strchr;
  else if (frida_streq (name, "gettid"))
    *value = (ElfW(Addr)) (uintptr_t) frida_gettid;
  else
    return false;

  return true;
}

static pid_t
frida_gettid (void)
{
  return frida_syscall_0 (SYS_gettid);
}
