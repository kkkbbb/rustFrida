#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>

// 定义字符串表结构体，与main.rs中的完全一致
typedef struct {
    uint64_t socket_name;
    uint32_t socket_name_len;

    uint64_t hello_msg;
    uint32_t hello_msg_len;

    uint64_t sym_name;
    uint32_t sym_name_len;

    uint64_t pthread_err;
    uint32_t pthread_err_len;

    uint64_t dlsym_err;
    uint32_t dlsym_err_len;

    uint64_t proc_path;
    uint32_t proc_path_len;
} StringTable;

// 定义与main.rs中相同的结构体
typedef struct {
    uintptr_t malloc;    // 用于分配内存
    uintptr_t free;      // 用于释放内存
    uintptr_t socket;    // 用于创建套接字
    uintptr_t connect;   // 用于连接套接字
    uintptr_t write;     // 用于发送数据
    uintptr_t close;     // 用于关闭套接字
    uintptr_t mprotect;  // 用于设置内存保护
    uintptr_t mmap;      // 用于内存映射
    uintptr_t munmap;
    uintptr_t recvmsg;   // 用于接收文件描述符
    uintptr_t pthread_create; // 用于创建线程
    uintptr_t pthread_detach; // 用于分离线程
    uintptr_t snprintf;  // 用于格式化字符串
    uintptr_t memcpy;
} LibcOffsets;

typedef struct {
    uintptr_t dlopen;   // 动态加载
    uintptr_t dlsym;    // 动态符号查找
} DlOffsets;

// 定义函数指针类型
typedef void* (*malloc_t)(size_t);
typedef void (*free_t)(void*);
typedef int (*socket_t)(int, int, int);
typedef int (*connect_t)(int, const void*, socklen_t);
typedef ssize_t (*write_t)(int, const void*, size_t);
typedef int (*close_t)(int);
typedef char* (*strcpy_t)(char*, const char*);
typedef void* (*dlopen_t)(const char*, int);
typedef ssize_t (*recvmsg_t)(int, struct msghdr*, int);
typedef int (*pthread_create_t)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
typedef int (*pthread_detach_t)(pthread_t);
typedef void* (*dlopen_t)(const char*, int);
typedef void* (*dlsym_t)(void*, const char*);
typedef int (*snprintf_t)(char*, size_t, const char*, ...);
typedef void* (*memcpy_t)(void*, const void*, size_t);

static int recv_fd(int sock, ssize_t (*recvmsg_fn)(int, struct msghdr*, int));

int shellcode_entry(LibcOffsets* offsets, DlOffsets* dl, StringTable* table) {
    // 定义函数指针
//    malloc_t malloc = (malloc_t)offsets->malloc;
    free_t free = (free_t)offsets->free;
    socket_t socket = (socket_t)offsets->socket;
    connect_t connect = (connect_t)offsets->connect;
    write_t write = (write_t)offsets->write;
    close_t close = (close_t)offsets->close;
    dlopen_t dlopen = (dlopen_t)dl->dlopen;
    recvmsg_t recvmsg = (recvmsg_t)offsets->recvmsg;
    dlsym_t dlsym = (dlsym_t)dl->dlsym;
    pthread_create_t pthread_create = (pthread_create_t)offsets->pthread_create;
    snprintf_t snprintf_fn = (snprintf_t)offsets->snprintf;
    pthread_detach_t pthread_detach = (pthread_detach_t)offsets->pthread_detach;
    memcpy_t memcpy = (memcpy_t)offsets->memcpy;

    // 获取字符串引用 (现在所有字符串都已经有 NULL 结尾)
    const char* socket_name = (const char*)table->socket_name;
    size_t socket_name_len = table->socket_name_len - 1; // 减去 NULL 结尾
    
    const char* hello_msg = (const char*)table->hello_msg;
    size_t hello_msg_len = table->hello_msg_len - 1; // 减去 NULL 结尾
    
    const char* sym_name = (const char*)table->sym_name;
    // 符号名可以直接作为 C 字符串使用，因为已有 NULL 结尾
    
    const char* pthread_err = (const char*)table->pthread_err;
    size_t pthread_err_len = table->pthread_err_len - 1; // 减去 NULL 结尾
    
    const char* dlsym_err = (const char*)table->dlsym_err;
    size_t dlsym_err_len = table->dlsym_err_len - 1; // 减去 NULL 结尾
    
    const char* proc_path = (const char*)table->proc_path;
    // proc_path 可以直接作为 C 字符串使用，因为已有 NULL 结尾
    
    
    // 创建socket
    int sock = socket(1, 1, 0);  // AF_UNIX, SOCK_STREAM, 0
    if (sock < 0) {
        free(offsets);
        free(dl);
        free(table);
        return -1;
    }
    
    // 准备地址结构
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = 1;  // AF_UNIX

    // 使用字符串表中的socket_name
    memcpy(addr.sun_path + 1, socket_name, socket_name_len);
    size_t addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + socket_name_len;
    
    // 连接
    if (connect(sock, (struct sockaddr*)&addr, addrlen) < 0) {
        close(sock);
        free(offsets);
        free(dl);
        free(table);
        return -2;
    }
    
    // 发送hello消息
    write(sock, hello_msg, hello_msg_len);
    
    // 接收文件描述符
    int memfd = recv_fd(sock, recvmsg);
    if (memfd < 0) {
        close(sock);
        free(offsets);
        free(dl);
        free(table);
        return -3;
    }
    
    // 构造 "/proc/self/fd/<memfd>" 路径
    // 现在使用函数指针调用 snprintf
    char path[64];
    char format[5];
    format[0] = '%';
    format[1] = 's';
    format[2] = '%';
    format[3] = 'd';
    format[4] = '\0';
    int idx = snprintf_fn(path, sizeof(path), format, proc_path, memfd);
    if (idx < 0 || idx >= sizeof(path)) {
        close(memfd);
        close(sock);
        free(offsets);
        free(dl);
        free(table);
        return -4;
    }
    
    // 加载共享库
    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        close(memfd);
        close(sock);
        free(offsets);
        free(dl);
        free(table);
        return -5;
    }
    
    // 查找符号 (sym_name 已有 NULL 结尾，可直接使用)
    void* sym = dlsym(handle, sym_name);

    if (sym) {
        
        pthread_t tid;
        // 传递 socket_name 作为参数给 hello_entry 函数
        if (pthread_create(&tid, NULL, sym, NULL) == 0) {
            pthread_detach(tid);
        } else {
            // 发送线程创建失败消息
            write(sock, pthread_err, pthread_err_len);
        }
    } else {
        // 发送符号查找失败消息
        write(sock, dlsym_err, dlsym_err_len);
    }
    
   
    close(memfd);
    close(sock);
    free(offsets);
    free(dl);
    free(table);
    return 1;
}

static int recv_fd(int sock, ssize_t (*recvmsg_fn)(int, struct msghdr*, int)) {
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))];
    char databuf[1];
    struct iovec io = {
        .iov_base = databuf,
        .iov_len = sizeof(databuf)
    };

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    if (recvmsg_fn(sock, &msg, 0) < 0) {
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) return -1;

    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        return -1;
    }

    return *((int*) CMSG_DATA(cmsg));
}