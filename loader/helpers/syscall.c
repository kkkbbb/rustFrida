#include "syscall.h"

ssize_t
frida_syscall_4 (size_t n, size_t a, size_t b, size_t c, size_t d)
{
  ssize_t result;

  register ssize_t x8 asm ("x8") = n;
  register  size_t x0 asm ("x0") = a;
  register  size_t x1 asm ("x1") = b;
  register  size_t x2 asm ("x2") = c;
  register  size_t x3 asm ("x3") = d;

  asm volatile (
      "svc 0x0\n\t"
      : "+r" (x0)
      : "r" (x1),
        "r" (x2),
        "r" (x3),
        "r" (x8)
      : "memory"
  );

  result = x0;

  return result;
}
