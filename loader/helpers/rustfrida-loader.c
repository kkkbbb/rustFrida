/*
 * rustfrida-loader.c — Frida-style loader adapted for rustFrida's agent ABI
 *
 * Based on Frida's loader.c (frida-core/src/linux/helpers/loader.c).
 * Runs as position-independent code in the target process after bootstrap.
 * Entry point creates a worker thread via pthread_create; the worker
 * receives agent SO fd + ctrl fd over the control socket, dlopen's the
 * agent, and calls hello_entry(&AgentArgs) which blocks in the agent's
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
#include <sys/un.h>

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
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

  /* Runtime state (filled by loader) */
  void * worker;               /* pthread_t */
  void * agent_handle;
  void * agent_entrypoint_impl;
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

/* ========== Forward declarations ========== */

static void * frida_main (void * user_data);

static int frida_connect (const char * address, const FridaLibcApi * libc);
static bool frida_send_hello (int sockfd, pid_t thread_id, const FridaLibcApi * libc);
static bool frida_send_ready (int sockfd, const FridaLibcApi * libc);
static bool frida_receive_ack (int sockfd, const FridaLibcApi * libc);
static bool frida_send_bye (int sockfd, FridaUnloadPolicy unload_policy, const FridaLibcApi * libc);
static bool frida_send_error (int sockfd, FridaMessageType type, const char * message, const FridaLibcApi * libc);

static bool frida_receive_chunk (int sockfd, void * buffer, size_t length, const FridaLibcApi * api);
static int frida_receive_fd (int sockfd, const FridaLibcApi * libc);
static int frida_receive_fd_diag (int sockfd, const FridaLibcApi * libc, char * diag_buf);
static bool frida_send_chunk (int sockfd, const void * buffer, size_t length, const FridaLibcApi * libc);
static void frida_enable_close_on_exec (int fd, const FridaLibcApi * libc);

static size_t frida_strlen (const char * str);

static pid_t frida_gettid (void);

/* ========== Entry point ========== */

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
void
frida_load (RustFridaLoaderContext * ctx)
{
  ctx->libc->pthread_create (&ctx->worker, NULL, frida_main, ctx);
}

/* ========== Worker thread ========== */

static void *
frida_main (void * user_data)
{
  RustFridaLoaderContext * ctx = user_data;
  const FridaLibcApi * libc = ctx->libc;
  pid_t thread_id;
  FridaUnloadPolicy unload_policy;
  int ctrlfd_for_peer, ctrlfd, agent_codefd, agent_ctrlfd;

  thread_id = frida_gettid ();
  /* RESIDENT: 不 dlclose agent.so，避免 exec pool 中的 trampoline/thunk
   * 指向已卸载代码导致 SIGSEGV（对标 Frida 默认行为）。
   * agent 内存成本 ~3MB，但消除了 dlclose 后的 use-after-unload 崩溃。 */
  unload_policy = FRIDA_UNLOAD_POLICY_RESIDENT;
  ctrlfd = -1;
  agent_codefd = -1;
  agent_ctrlfd = -1;

  /* Close the peer end of the control socketpair */
  ctrlfd_for_peer = ctx->ctrlfds[0];
  if (ctrlfd_for_peer != -1)
    libc->close (ctrlfd_for_peer);

  /* Try the pre-created socketpair fd first */
  ctrlfd = ctx->ctrlfds[1];
  if (ctrlfd != -1)
  {
    if (!frida_send_hello (ctrlfd, thread_id, libc))
    {
      libc->close (ctrlfd);
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

  /* dlopen the agent SO from a memfd received over the socket */
  if (ctx->agent_handle == NULL)
  {
    char agent_path[32];
    const void * pretend_caller_addr = libc->close;

    agent_codefd = frida_receive_fd_diag (ctrlfd, libc, agent_path /* reuse as diag buf */);
    if (agent_codefd == -1)
    {
      frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN,
          agent_path /* contains diag msg */, libc);
      goto beach;
    }

    libc->sprintf (agent_path, "/proc/self/fd/%d", agent_codefd);

    ctx->agent_handle = libc->dlopen (agent_path, libc->dlopen_flags, pretend_caller_addr);
    if (ctx->agent_handle == NULL)
      goto dlopen_failed;

    libc->close (agent_codefd);
    agent_codefd = -1;

    ctx->agent_entrypoint_impl = libc->dlsym (ctx->agent_handle, ctx->agent_entrypoint, pretend_caller_addr);
    if (ctx->agent_entrypoint_impl == NULL)
      goto dlsym_failed;
  }

  /* Receive the REPL socketpair fd for the agent */
  agent_ctrlfd = frida_receive_fd (ctrlfd, libc);
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

    /* Agent returned — close the REPL fd (agent may have already closed it) */
    agent_ctrlfd = -1;
  }

  goto beach;

dlopen_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLOPEN,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to load library",
        libc);
    goto beach;
  }
dlsym_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLSYM,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to find entrypoint",
        libc);
    goto beach;
  }
beach:
  {
    if (unload_policy == FRIDA_UNLOAD_POLICY_IMMEDIATE && ctx->agent_handle != NULL)
      libc->dlclose (ctx->agent_handle);

    if (unload_policy != FRIDA_UNLOAD_POLICY_DEFERRED)
      libc->pthread_detach (ctx->worker);

    if (agent_ctrlfd != -1)
      libc->close (agent_ctrlfd);

    if (agent_codefd != -1)
      libc->close (agent_codefd);

    if (ctrlfd != -1)
    {
      frida_send_bye (ctrlfd, unload_policy, libc);
      libc->close (ctrlfd);
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

  sockfd = libc->socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1)
    goto beach;

  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  for (c = address, len = 0; (ch = *c) != '\0'; c++, len++)
    addr.sun_path[1 + len] = ch;

  if (libc->connect (sockfd, (struct sockaddr *) &addr, offsetof (struct sockaddr_un, sun_path) + 1 + len) == -1)
    goto beach;

  success = true;

beach:
  if (!success && sockfd != -1)
  {
    libc->close (sockfd);
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

    n = libc->recvmsg (sockfd, &msg, 0);
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

  res = libc->recvmsg (sockfd, &msg, 0);
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

  res = libc->recvmsg (sockfd, &msg, 0);
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

    n = libc->send (sockfd, cursor, remaining, MSG_NOSIGNAL);
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
  libc->fcntl (fd, F_SETFD, libc->fcntl (fd, F_GETFD) | FD_CLOEXEC);
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

static pid_t
frida_gettid (void)
{
  return frida_syscall_0 (SYS_gettid);
}
