/*
 * bootstrapper.c — Adapted from Frida (https://github.com/frida/frida-core)
 *
 * Original: frida-core/src/linux/helpers/bootstrapper.c
 * Stripped down for Android ARM64 only:
 *   - Removed glibc/musl/uclibc-specific codepaths
 *   - Removed frida_try_load_libc_and_raise / frida_libc_main / frida_map_elf
 *   - Removed BUILDING_TEST_PROGRAM section
 *   - In NOLIBC mode, uses our nolibc-compat.h (ARM64 raw syscall wrappers)
 *
 * Copyright (C) Frida contributors — Licensed under wxWidgets Library Licence
 */

/* nolibc-compat.h must come first — defines ssize_t, pid_t, off_t
 * and all POSIX-like functions as raw syscall wrappers */
#ifdef NOLIBC
# include "nolibc-compat.h"
#else
# include <errno.h>
# include <fcntl.h>
# include <signal.h>
# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <sys/prctl.h>
# include <sys/socket.h>
# include <sys/mman.h>
#endif

#include "elf-parser.h"
#include "inject-context.h"

#include <stdalign.h>

#ifndef AF_UNIX
# define AF_UNIX 1
#endif
#ifndef SOCK_STREAM
# define SOCK_STREAM 1
#endif
#ifndef PR_GET_DUMPABLE
# define PR_GET_DUMPABLE 3
#endif
#ifndef PR_SET_DUMPABLE
# define PR_SET_DUMPABLE 4
#endif
#ifndef RTLD_LAZY
# define RTLD_LAZY 1
#endif
#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif
#ifndef O_RDONLY
# define O_RDONLY 0
#endif

#define FRIDA_STRINGIFY(identifier) _FRIDA_STRINGIFY (identifier)
#define _FRIDA_STRINGIFY(identifier) #identifier

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef DF_1_PIE
# define DF_1_PIE 0x08000000
#endif

#ifndef AT_RANDOM
# define AT_RANDOM 25
#endif

#ifndef AT_EXECFN
# define AT_EXECFN  31
#endif

typedef struct _FridaCollectLibcApiContext FridaCollectLibcApiContext;
typedef struct _FridaProcessLayout FridaProcessLayout;
typedef struct _FridaRDebug FridaRDebug;
typedef int FridaRState;
typedef struct _FridaLinkMap FridaLinkMap;
typedef struct _FridaOpenFileForMappedRangeContext FridaOpenFileForMappedRangeContext;
typedef struct _FridaDetectRtldFlavorContext FridaDetectRtldFlavorContext;
typedef ssize_t (* FridaParseFunc) (void * data, size_t size, void * user_data);

struct _FridaCollectLibcApiContext
{
  int total_missing;
  FridaRtldFlavor rtld_flavor;
  FridaLibcApi * api;
};

struct _FridaProcessLayout
{
  ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_size;
  ElfW(Half) phdr_count;
  ElfW(Ehdr) * interpreter;
  FridaRtldFlavor rtld_flavor;
  FridaRDebug * r_debug;
  void * r_brk;
  void * libc;
};

struct _FridaRDebug
{
  int r_version;
  FridaLinkMap * r_map;
  ElfW(Addr) r_brk;
  FridaRState r_state;
  ElfW(Addr) r_ldbase;
};

enum _FridaRState
{
  RT_CONSISTENT,
  RT_ADD,
  RT_DELETE
};

struct _FridaLinkMap
{
  ElfW(Addr) l_addr;
  char * l_name;
  ElfW(Dyn) * l_ld;
  FridaLinkMap * l_next;
  FridaLinkMap * l_prev;
};

struct _FridaOpenFileForMappedRangeContext
{
  void * base;
  int fd;
};

struct _FridaDetectRtldFlavorContext
{
  ElfW(Ehdr) * interpreter;
  FridaRtldFlavor flavor;
};

static bool frida_resolve_libc_apis (const FridaProcessLayout * layout, FridaLibcApi * libc);
static bool frida_collect_libc_symbol (const FridaElfExportDetails * details, void * user_data);
static bool frida_collect_android_linker_symbol (const FridaElfExportDetails * details, void * user_data);

static bool frida_probe_process (size_t page_size, FridaProcessLayout * layout);
static void frida_enumerate_module_symbols_on_disk (void * loaded_base, FridaFoundElfSymbolFunc func, void * user_data);
static int frida_open_file_for_mapped_range_with_base (void * base);
static ssize_t frida_open_file_for_matching_maps_line (void * data, size_t size, void * user_data);
static FridaRtldFlavor frida_detect_rtld_flavor (ElfW(Ehdr) * interpreter);
static FridaRtldFlavor frida_infer_rtld_flavor_from_filename (const char * name);
static ssize_t frida_try_infer_rtld_flavor_from_maps_line (void * data, size_t size, void * user_data);
static bool frida_path_is_libc (const char * path, FridaRtldFlavor rtld_flavor);
static ssize_t frida_parse_auxv_entry (void * data, size_t size, void * user_data);
static bool frida_collect_interpreter_symbol (const FridaElfExportDetails * details, void * user_data);
static ssize_t frida_try_find_libc_from_maps_line (void * data, size_t size, void * user_data);

static void frida_parse_file (const char * path, FridaParseFunc parse, void * user_data);
static size_t frida_parse_size (const char * str);
static bool frida_str_has_prefix (const char * str, const char * prefix);
static bool frida_str_has_suffix (const char * str, const char * suffix);

static int frida_socketpair (int domain, int type, int protocol, int sv[2]);
static int frida_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
FridaBootstrapStatus
frida_bootstrap (FridaBootstrapContext * ctx)
{
  FridaLibcApi * libc = ctx->libc;
  FridaProcessLayout process;

  if (ctx->allocation_base == NULL)
  {
    ctx->allocation_base = mmap (NULL, ctx->allocation_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx->allocation_base != MAP_FAILED)
      frida_prctl (0x53564d41 /* PR_SET_VMA */, 0 /* PR_SET_VMA_ANON_NAME */,
                   (unsigned long) ctx->allocation_base, ctx->allocation_size,
                   (unsigned long) "wwb_loader");
    return (ctx->allocation_base == MAP_FAILED)
        ? FRIDA_BOOTSTRAP_ALLOCATION_ERROR
        : FRIDA_BOOTSTRAP_ALLOCATION_SUCCESS;
  }

  if (!frida_probe_process (ctx->page_size, &process))
    return FRIDA_BOOTSTRAP_AUXV_NOT_FOUND;

  ctx->rtld_flavor = process.rtld_flavor;
  ctx->rtld_base = process.interpreter;
  ctx->r_brk = process.r_brk;

  if (process.interpreter != NULL && process.libc == NULL)
    return FRIDA_BOOTSTRAP_TOO_EARLY;

  if (process.interpreter == NULL && process.libc == NULL)
  {
    return FRIDA_BOOTSTRAP_LIBC_LOAD_ERROR;
  }

  if (!frida_resolve_libc_apis (&process, libc))
    return FRIDA_BOOTSTRAP_LIBC_UNSUPPORTED;

  ctx->ctrlfds[0] = -1;
  ctx->ctrlfds[1] = -1;
  if (ctx->enable_ctrlfds)
    frida_socketpair (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctx->ctrlfds);

  return FRIDA_BOOTSTRAP_SUCCESS;
}

static bool
frida_resolve_libc_apis (const FridaProcessLayout * layout, FridaLibcApi * libc)
{
  FridaCollectLibcApiContext ctx;

  memset (libc, 0, sizeof (FridaLibcApi));
  libc->dlopen_flags = RTLD_LAZY;

  ctx.total_missing = 13;
  ctx.rtld_flavor = layout->rtld_flavor;
  ctx.api = libc;
  frida_elf_enumerate_exports (layout->libc, frida_collect_libc_symbol, &ctx);

  if (ctx.total_missing != 0)
    return false;

  if (layout->rtld_flavor == FRIDA_RTLD_ANDROID)
  {
    bool found_all_or_none;

    ctx.total_missing = 4;
    frida_elf_enumerate_exports (layout->interpreter, frida_collect_android_linker_symbol, &ctx);

    if (ctx.total_missing == 4)
      frida_enumerate_module_symbols_on_disk (layout->interpreter, frida_collect_android_linker_symbol, &ctx);

    found_all_or_none = ctx.total_missing == 0 || ctx.total_missing == 4;
    if (!found_all_or_none)
      return false;
  }

  return true;
}

static bool
frida_collect_libc_symbol (const FridaElfExportDetails * details, void * user_data)
{
  FridaCollectLibcApiContext * ctx = user_data;
  FridaLibcApi * api = ctx->api;

  if (details->type != STT_FUNC)
    return true;

#define FRIDA_TRY_COLLECT(e) \
    FRIDA_TRY_COLLECT_NAMED (e, FRIDA_STRINGIFY (e))
#define FRIDA_TRY_COLLECT_NAMED(e, n) \
    if (api->e == NULL && strcmp (details->name, n) == 0) \
    { \
      api->e = details->address; \
      ctx->total_missing--; \
      goto beach; \
    }

  FRIDA_TRY_COLLECT (printf)
  FRIDA_TRY_COLLECT (sprintf)

  FRIDA_TRY_COLLECT (mmap)
  FRIDA_TRY_COLLECT (munmap)
  FRIDA_TRY_COLLECT (socket)
  FRIDA_TRY_COLLECT (socketpair)
  FRIDA_TRY_COLLECT (connect)
  FRIDA_TRY_COLLECT (recvmsg)
  FRIDA_TRY_COLLECT (send)
  FRIDA_TRY_COLLECT (fcntl)
  FRIDA_TRY_COLLECT (close)

  FRIDA_TRY_COLLECT (pthread_create)
  FRIDA_TRY_COLLECT (pthread_detach)

#undef FRIDA_TRY_COLLECT_NAMED
#undef FRIDA_TRY_COLLECT

beach:
  return ctx->total_missing > 0;
}

static bool
frida_collect_android_linker_symbol (const FridaElfExportDetails * details, void * user_data)
{
  FridaCollectLibcApiContext * ctx = user_data;
  FridaLibcApi * api = ctx->api;

  if (details->type != STT_FUNC)
    return true;

#define FRIDA_TRY_COLLECT(e, n) \
    if (api->e == NULL && strcmp (details->name, n) == 0) \
    { \
      api->e = details->address; \
      ctx->total_missing--; \
      goto beach; \
    }

  FRIDA_TRY_COLLECT (dlopen, "__loader_dlopen");
  FRIDA_TRY_COLLECT (dlclose, "__loader_dlclose");
  FRIDA_TRY_COLLECT (dlsym, "__loader_dlsym");
  FRIDA_TRY_COLLECT (dlerror, "__loader_dlerror");

  FRIDA_TRY_COLLECT (dlopen, "__dl__Z8__dlopenPKciPKv");
  FRIDA_TRY_COLLECT (dlclose, "__dl__Z9__dlclosePv");
  FRIDA_TRY_COLLECT (dlsym, "__dl__Z7__dlsymPvPKcPKv");
  FRIDA_TRY_COLLECT (dlerror, "__dl__Z9__dlerrorv");

#undef FRIDA_TRY_COLLECT

beach:
  return ctx->total_missing > 0;
}

static bool
frida_probe_process (size_t page_size, FridaProcessLayout * layout)
{
  int previous_dumpable;
  bool use_proc_fallback;

  layout->phdrs = NULL;
  layout->phdr_size = 0;
  layout->phdr_count = 0;
  layout->interpreter = NULL;
  layout->rtld_flavor = FRIDA_RTLD_UNKNOWN;
  layout->r_debug = NULL;
  layout->r_brk = NULL;
  layout->libc = NULL;

  previous_dumpable = frida_prctl (PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (previous_dumpable != -1 && previous_dumpable != 1)
    frida_prctl (PR_SET_DUMPABLE, 1, 0, 0, 0);

  frida_parse_file ("/proc/self/auxv", frida_parse_auxv_entry, layout);

  if (previous_dumpable != -1 && previous_dumpable != 1)
    frida_prctl (PR_SET_DUMPABLE, previous_dumpable, 0, 0, 0);

  if (layout->phdrs == NULL)
    return false;

  layout->rtld_flavor = frida_detect_rtld_flavor (layout->interpreter);

  if (layout->interpreter != NULL)
  {
    frida_elf_enumerate_exports (layout->interpreter, frida_collect_interpreter_symbol, layout);

    if (layout->r_debug == NULL || layout->r_brk == NULL)
      frida_enumerate_module_symbols_on_disk (layout->interpreter, frida_collect_interpreter_symbol, layout);

    if (layout->r_debug != NULL)
    {
      FridaRDebug * r = layout->r_debug;
      FridaLinkMap * map, * program;

      for (map = r->r_map; map != NULL; map = map->l_next)
      {
        if (frida_path_is_libc (map->l_name, layout->rtld_flavor))
        {
          layout->libc = (void *) map->l_addr;
          break;
        }
      }

      /*
       * Injecting right after libc has been loaded is risky, e.g. it may not yet be fully linked.
       * So instead of waiting for r_brk to be executed again, we use the program's earliest initializer / entrypoint.
       *
       * This still leaves the issue where we might be attaching to a process in the brief moment right after libc has become
       * visible, but before it's been fully linked in. So we definitely want to move to a better strategy.
       */
      program = r->r_map;
      if (layout->libc == NULL && program != NULL)
      {
        const ElfW(Ehdr) * program_elf;
        ElfW(Addr) addr_delta;
        const ElfW(Dyn) * entries, * entry;

        program_elf = (const ElfW(Ehdr) *)
            frida_elf_compute_base_from_phdrs (layout->phdrs, layout->phdr_size, layout->phdr_count, page_size);

        addr_delta = (program_elf->e_type == ET_EXEC)
            ? 0
            : (ElfW(Addr)) program_elf;

        entries = (program->l_ld != NULL)
            ? program->l_ld
            : frida_elf_find_dynamic_section (program_elf);

        layout->r_brk = NULL;

        for (entry = entries; entry->d_tag != DT_NULL; entry++)
        {
          switch (entry->d_tag)
          {
            case DT_INIT:
              layout->r_brk = (void *) (entry->d_un.d_ptr + addr_delta);
              break;
            case DT_PREINIT_ARRAY:
            case DT_INIT_ARRAY:
              if (layout->r_brk == NULL)
              {
                void * val = *((void **) (entry->d_un.d_ptr + addr_delta));
                if (val != NULL && val != (void *) -1)
                  layout->r_brk = val;
              }
              break;
          }
        }

        if (layout->r_brk == NULL)
          layout->r_brk = (void *) (program_elf->e_entry + addr_delta);
      }

      use_proc_fallback = false;
    }
    else
    {
      use_proc_fallback = true;
    }
  }
  else
  {
    use_proc_fallback = true;
  }

  if (use_proc_fallback)
    frida_parse_file ("/proc/self/maps", frida_try_find_libc_from_maps_line, layout);

  return true;
}

static void
frida_enumerate_module_symbols_on_disk (void * loaded_base, FridaFoundElfSymbolFunc func, void * user_data)
{
  int fd;
  off_t size;
  void * elf;

  fd = frida_open_file_for_mapped_range_with_base (loaded_base);
  if (fd == -1)
    return;
  size = lseek (fd, 0, SEEK_END);
  elf = mmap (NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

  frida_elf_enumerate_symbols (elf, loaded_base, func, user_data);

  munmap (elf, size);
  close (fd);
}

static int
frida_open_file_for_mapped_range_with_base (void * base)
{
  FridaOpenFileForMappedRangeContext ctx;

  ctx.base = base;
  ctx.fd = -1;
  frida_parse_file ("/proc/self/maps", frida_open_file_for_matching_maps_line, &ctx);

  return ctx.fd;
}

static ssize_t
frida_open_file_for_matching_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  FridaOpenFileForMappedRangeContext * ctx = user_data;
  char * next_newline;
  void * base;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  base = (void *) frida_parse_size (line);
  if (base == ctx->base)
  {
    const char * path = strchr (line, '/');
    if (path != NULL)
    {
      ctx->fd = open (path, O_RDONLY);
      return -1;
    }
  }

  return (next_newline + 1) - (char *) data;
}

static FridaRtldFlavor
frida_detect_rtld_flavor (ElfW(Ehdr) * interpreter)
{
  const char * soname;
  FridaDetectRtldFlavorContext ctx;

  if (interpreter == NULL)
    return FRIDA_RTLD_NONE;

  soname = frida_elf_query_soname (interpreter);
  if (soname != NULL)
    return frida_infer_rtld_flavor_from_filename (soname);

  ctx.interpreter = interpreter;
  ctx.flavor = FRIDA_RTLD_UNKNOWN;
  frida_parse_file ("/proc/self/maps", frida_try_infer_rtld_flavor_from_maps_line, &ctx);

  return ctx.flavor;
}

static FridaRtldFlavor
frida_infer_rtld_flavor_from_filename (const char * name)
{
  if (frida_str_has_prefix (name, "ld-linux-"))
    return FRIDA_RTLD_GLIBC;

  if (frida_str_has_prefix (name, "ld-uClibc"))
    return FRIDA_RTLD_UCLIBC;

  if (strcmp (name, "libc.so") == 0 ||
      frida_str_has_prefix (name, "libc.musl") ||
      frida_str_has_prefix (name, "ld-musl"))
    return FRIDA_RTLD_MUSL;

  if (strcmp (name, "ld-android.so") == 0)
    return FRIDA_RTLD_ANDROID;
  if (strcmp (name, "linker") == 0)
    return FRIDA_RTLD_ANDROID;
  if (strcmp (name, "linker64") == 0)
    return FRIDA_RTLD_ANDROID;

  return FRIDA_RTLD_UNKNOWN;
}

static ssize_t
frida_try_infer_rtld_flavor_from_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  FridaDetectRtldFlavorContext * ctx = user_data;
  char * next_newline;
  void * base;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  base = (void *) frida_parse_size (line);

  if (base == ctx->interpreter)
  {
    const char * filename = strrchr (line, '/') + 1;
    ctx->flavor = frida_infer_rtld_flavor_from_filename (filename);
    return -1;
  }

  return (next_newline + 1) - (char *) data;
}

static bool
frida_path_is_libc (const char * path, FridaRtldFlavor rtld_flavor)
{
  const char * last_slash, * name;

  if (rtld_flavor == FRIDA_RTLD_ANDROID)
  {
    return frida_str_has_suffix (path, "/lib/libc.so") ||
        frida_str_has_suffix (path, "/lib64/libc.so") ||
        frida_str_has_suffix (path, "/bionic/libc.so");
  }

  last_slash = strrchr (path, '/');
  if (last_slash != NULL)
    name = last_slash + 1;
  else
    name = path;

  return frida_str_has_prefix (name, "libc.so") ||
      frida_str_has_prefix (name, "libc.musl") ||
      frida_str_has_prefix (name, "ld-musl");
}

static ssize_t
frida_parse_auxv_entry (void * data, size_t size, void * user_data)
{
  ElfW(auxv_t) * entry = data;
  FridaProcessLayout * layout = user_data;

  if (size < sizeof (ElfW(auxv_t)))
    return 0;

  switch (entry->a_type)
  {
    case AT_PHDR:
      layout->phdrs = (ElfW(Phdr) *) entry->a_un.a_val;
      break;
    case AT_PHENT:
      layout->phdr_size = entry->a_un.a_val;
      break;
    case AT_PHNUM:
      layout->phdr_count = entry->a_un.a_val;
      break;
    case AT_BASE:
      layout->interpreter = (ElfW(Ehdr) *) entry->a_un.a_val;
      break;
  }

  return sizeof (ElfW(auxv_t));
}

static bool
frida_collect_interpreter_symbol (const FridaElfExportDetails * details, void * user_data)
{
  FridaProcessLayout * layout = user_data;
  bool found_both;

  if (layout->r_debug == NULL &&
        details->type == STT_OBJECT && (
        strcmp (details->name, "_r_debug") == 0 ||
        strcmp (details->name, "__dl__r_debug") == 0))
    layout->r_debug = details->address;

  if (layout->r_brk == NULL &&
        details->type == STT_FUNC && (
        strcmp (details->name, "_dl_debug_state") == 0 ||
        strcmp (details->name, "__dl_rtld_db_dlactivity") == 0 ||
        strcmp (details->name, "rtld_db_dlactivity") == 0))
    layout->r_brk = details->address;

  found_both = layout->r_debug != NULL && layout->r_brk != NULL;
  return !found_both;
}

static ssize_t
frida_try_find_libc_from_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  FridaProcessLayout * layout = user_data;
  char * next_newline, * path;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  path = strchr (line, '/');
  if (path != NULL && frida_path_is_libc (path, layout->rtld_flavor))
  {
    layout->libc = (void *) frida_parse_size (line);
    return -1;
  }

  return (next_newline + 1) - (char *) data;
}

static void
frida_parse_file (const char * path, FridaParseFunc parse, void * user_data)
{
  int fd;
  char * cursor;
  size_t fill_amount;
  char buffer[2048];

  fd = open (path, O_RDONLY);
  if (fd == -1)
    goto beach;

  fill_amount = 0;
  while (true)
  {
    ssize_t n;

    n = read (fd, buffer + fill_amount, sizeof (buffer) - fill_amount - 1);
    if (n > 0)
    {
      fill_amount += n;
      buffer[fill_amount] = '\0';
    }
    if (fill_amount == 0)
      break;

    cursor = buffer;
    while (true)
    {
      ssize_t n = parse (cursor, buffer + fill_amount - cursor, user_data);
      if (n == -1)
        goto beach;
      if (n == 0)
      {
        size_t consumed = cursor - buffer;
        if (consumed != 0)
        {
          memmove (buffer, buffer + consumed, fill_amount - consumed + 1);
          fill_amount -= consumed;
        }
        else
        {
          fill_amount = 0;
        }
        break;
      }

      cursor += n;
    }
  }

beach:
  if (fd != -1)
    close (fd);
}

static size_t
frida_parse_size (const char * str)
{
  size_t result = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    char ch = *cursor;

    if (ch >= '0' && ch <= '9')
      result = (result * 16) + (ch - '0');
    else if (ch >= 'a' && ch <= 'f')
      result = (result * 16) + (10 + (ch - 'a'));
    else
      break;
  }

  return result;
}

static bool
frida_str_has_prefix (const char * str, const char * prefix)
{
  return strncmp (str, prefix, strlen (prefix)) == 0;
}

static bool
frida_str_has_suffix (const char * str, const char * suffix)
{
  size_t str_length, suffix_length;

  str_length = strlen (str);
  suffix_length = strlen (suffix);
  if (str_length < suffix_length)
    return false;

  return strcmp (str + str_length - suffix_length, suffix) == 0;
}

static int
frida_socketpair (int domain, int type, int protocol, int sv[2])
{
#ifdef NOLIBC
  return socketpair (domain, type, protocol, sv);
#else
  return socketpair (domain, type, protocol, sv);
#endif
}

static int
frida_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
#ifdef NOLIBC
  return prctl (option, arg2, arg3, arg4, arg5);
#else
  return prctl (option, arg2, arg3, arg4, arg5);
#endif
}
