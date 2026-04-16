/*
 * nolibc-compat.h — Minimal freestanding runtime for ARM64 Android
 *
 * Replaces Linux nolibc.h with raw ARM64 syscall wrappers + string functions.
 * Used by bootstrapper.c which runs as position-independent shellcode
 * in the target process without access to libc.
 */

#ifndef NOLIBC_COMPAT_H
#define NOLIBC_COMPAT_H

#include <stdint.h>
#include <stddef.h>

/* POSIX types not in freestanding headers */
typedef long ssize_t;
typedef int pid_t;
typedef long off_t;

/* ========== ARM64 syscall numbers ========== */

#define __NR_read           63
#define __NR_write          64
#define __NR_openat         56
#define __NR_close          57
#define __NR_lseek          62
#define __NR_mmap           222
#define __NR_munmap         215
#define __NR_prctl          167
#define __NR_socketpair     199
#define __NR_getpid         172

/* openat flags */
#define AT_FDCWD            -100
#ifndef O_RDONLY
#define O_RDONLY            0
#endif

/* mmap flags */
#ifndef PROT_READ
#define PROT_READ           0x1
#define PROT_WRITE          0x2
#define PROT_EXEC           0x4
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE         0x02
#define MAP_ANONYMOUS       0x20
#define MAP_FAILED          ((void *)-1)
#endif

/* lseek whence */
#ifndef SEEK_SET
#define SEEK_SET            0
#define SEEK_CUR            1
#define SEEK_END            2
#endif

/* prctl */
#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE     3
#define PR_SET_DUMPABLE     4
#endif

/* socket */
#ifndef AF_UNIX
#define AF_UNIX             1
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM         1
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC        0x80000
#endif

/* dlopen */
#ifndef RTLD_LAZY
#define RTLD_LAZY           1
#endif

/* ========== Raw syscall primitives ========== */

static inline long __syscall0(long nr) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline long __syscall1(long nr, long a0) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline long __syscall2(long nr, long a0, long a1) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}

static inline long __syscall3(long nr, long a0, long a1, long a2) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

static inline long __syscall4(long nr, long a0, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}

static inline long __syscall5(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
    return x0;
}

static inline long __syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory");
    return x0;
}

/* ========== POSIX-like wrappers ========== */

static inline int open(const char *path, int flags) {
    return (int)__syscall4(__NR_openat, AT_FDCWD, (long)path, flags, 0);
}

static inline ssize_t read(int fd, void *buf, size_t len) {
    return (ssize_t)__syscall3(__NR_read, fd, (long)buf, (long)len);
}

static inline ssize_t write(int fd, const void *buf, size_t len) {
    return (ssize_t)__syscall3(__NR_write, fd, (long)buf, (long)len);
}

static inline int close(int fd) {
    return (int)__syscall1(__NR_close, fd);
}

static inline off_t lseek(int fd, off_t offset, int whence) {
    return (off_t)__syscall3(__NR_lseek, fd, offset, whence);
}

static inline void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    return (void *)__syscall6(__NR_mmap, (long)addr, (long)len, prot, flags, fd, off);
}

static inline int munmap(void *addr, size_t len) {
    return (int)__syscall2(__NR_munmap, (long)addr, (long)len);
}

static inline int prctl(int option, unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5) {
    return (int)__syscall5(__NR_prctl, option, arg2, arg3, arg4, arg5);
}

static inline int socketpair(int domain, int type, int protocol, int sv[2]) {
    return (int)__syscall4(__NR_socketpair, domain, type, protocol, (long)sv);
}

static inline int getpid(void) {
    return (int)__syscall0(__NR_getpid);
}

/* ========== String functions ========== */

static inline size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static inline int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    return n ? (unsigned char)*a - (unsigned char)*b : 0;
}

static inline char *strchr(const char *s, int c) {
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return (c == 0) ? (char *)s : NULL;
}

static inline char *strrchr(const char *s, int c) {
    const char *last = NULL;
    while (*s) {
        if (*s == (char)c) last = s;
        s++;
    }
    if (c == 0) return (char *)s;
    return (char *)last;
}

static inline char *strstr(const char *haystack, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0) return (char *)haystack;
    while (*haystack) {
        if (strncmp(haystack, needle, nlen) == 0) return (char *)haystack;
        haystack++;
    }
    return NULL;
}

static inline int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *pa = a, *pb = b;
    while (n--) {
        if (*pa != *pb) return *pa - *pb;
        pa++; pb++;
    }
    return 0;
}

static inline void *memset(void *s, int c, size_t n) {
    unsigned char *p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

static inline void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

/* ========== stdio stubs (bootstrapper uses FILE * for /proc parsing) ========== */

/* The bootstrapper's frida_parse_file() reads /proc/self/auxv and /proc/self/maps
 * using open/read/close directly. We need to provide fopen/fgets/fclose-like
 * functionality or adapt the bootstrapper to use raw fd I/O.
 *
 * Frida's bootstrapper with NOLIBC already uses raw fd I/O via nolibc's wrappers.
 * Our nolibc-compat.h provides the same raw syscall functions.
 */

/* errno stub — bootstrapper checks return values directly, not errno */
static int __nolibc_errno;
#define errno __nolibc_errno

/* alloca is a compiler builtin */
#ifndef alloca
#define alloca __builtin_alloca
#endif

/* NULL */
#ifndef NULL
#define NULL ((void *)0)
#endif

/* bool */
#ifndef __cplusplus
#ifndef bool
#define bool    _Bool
#define true    1
#define false   0
#endif
#endif

/* ssize_t, pid_t, off_t defined at top of this file */

#endif /* NOLIBC_COMPAT_H */
