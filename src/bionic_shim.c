/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bionic_shim.c — Bionic-on-Darwin C library, pthread, errno, signal, and
 * Linux AArch64 syscall compatibility layer for Husk-JITLess.
 */
#include "bionic_shim.h"
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const struct {
    int darwin_err;
    int bionic_err;
} k_errno_map[] = {
    { EPERM, 1 },   { ENOENT, 2 },  { ESRCH, 3 },   { EINTR, 4 },   { EIO, 5 },
    { ENXIO, 6 },   { E2BIG, 7 },   { ENOEXEC, 8 }, { EBADF, 9 },   { ECHILD, 10 },
    { EAGAIN, 11 }, { ENOMEM, 12 }, { EACCES, 13 }, { EFAULT, 14 }, { EBUSY, 16 },
    { EEXIST, 17 }, { EXDEV, 18 },  { ENODEV, 19 }, { ENOTDIR, 20 },{ EISDIR, 21 },
    { EINVAL, 22 }, { ENFILE, 23 }, { EMFILE, 24 }, { ENOTTY, 25 }, { EFBIG, 27 },
    { ENOSPC, 28 }, { ESPIPE, 29 }, { EROFS, 30 },  { EMLINK, 31 }, { EPIPE, 32 },
    { EDOM, 33 },   { ERANGE, 34 }, { EDEADLK, 35 },{ ENAMETOOLONG, 36 },
    { ENOLCK, 37 }, { ENOSYS, 38 }, { ENOTEMPTY, 39 }, { ELOOP, 40 },
    { ETIMEDOUT, 110 }, { ECONNREFUSED, 111 }, { EINPROGRESS, 115 }
};

int husk_errno_to_bionic(int darwin_errno)
{
    for (size_t i = 0; i < sizeof(k_errno_map) / sizeof(k_errno_map[0]); i++) {
        if (k_errno_map[i].darwin_err == darwin_errno) return k_errno_map[i].bionic_err;
    }
    return darwin_errno;
}

int husk_errno_from_bionic(int bionic_errno)
{
    for (size_t i = 0; i < sizeof(k_errno_map) / sizeof(k_errno_map[0]); i++) {
        if (k_errno_map[i].bionic_err == bionic_errno) return k_errno_map[i].darwin_err;
    }
    return bionic_errno;
}

static __thread int g_bionic_errno = 0;

int *husk_bionic_errno_ptr(void)
{
    return &g_bionic_errno;
}

void husk_set_bionic_errno(int bionic_errno)
{
    g_bionic_errno = bionic_errno;
}

int husk_signal_to_darwin(int linux_sig)
{
    switch (linux_sig) {
    case 0:  return 0;
    case 1:  return SIGHUP;
    case 2:  return SIGINT;
    case 3:  return SIGQUIT;
    case 4:  return SIGILL;
    case 5:  return SIGTRAP;
    case 6:  return SIGABRT;
    case 7:  return SIGBUS;
    case 8:  return SIGFPE;
    case 9:  return SIGKILL;
    case 10: return SIGUSR1;
    case 11: return SIGSEGV;
    case 12: return SIGUSR2;
    case 13: return SIGPIPE;
    case 14: return SIGALRM;
    case 15: return SIGTERM;
    case 17: return SIGCHLD;
    default: return -1;
    }
}

int husk_signal_from_darwin(int darwin_sig)
{
    for (int s = 1; s <= 17; s++) {
        if (husk_signal_to_darwin(s) == darwin_sig) return s;
    }
    return darwin_sig;
}

#define BIONIC_MUTEX_MAGIC 0x484D5458u

static pthread_mutex_t *ensure_host_mutex(husk_bionic_mutex *m)
{
    if (!m) return NULL;
    if (m->state == BIONIC_MUTEX_MAGIC && m->handle != 0) {
        return (pthread_mutex_t *)(uintptr_t)m->handle;
    }
    pthread_mutex_t *hm = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    if (!hm) return NULL;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    if (((m->state >> 14) & 3u) == 1u) {
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    }
    pthread_mutex_init(hm, &attr);
    pthread_mutexattr_destroy(&attr);
    m->state = BIONIC_MUTEX_MAGIC;
    m->handle = (uint64_t)(uintptr_t)hm;
    return hm;
}

int husk_bionic_mutex_init(husk_bionic_mutex *m, const void *attr)
{
    (void)attr;
    if (!m) return 22;
    memset(m, 0, sizeof(*m));
    return ensure_host_mutex(m) ? 0 : 12;
}

int husk_bionic_mutex_lock(husk_bionic_mutex *m)
{
    pthread_mutex_t *hm = ensure_host_mutex(m);
    if (!hm) return 22;
    return husk_errno_to_bionic(pthread_mutex_lock(hm));
}

int husk_bionic_mutex_trylock(husk_bionic_mutex *m)
{
    pthread_mutex_t *hm = ensure_host_mutex(m);
    if (!hm) return 22;
    return husk_errno_to_bionic(pthread_mutex_trylock(hm));
}

int husk_bionic_mutex_unlock(husk_bionic_mutex *m)
{
    pthread_mutex_t *hm = ensure_host_mutex(m);
    if (!hm) return 22;
    return husk_errno_to_bionic(pthread_mutex_unlock(hm));
}

int husk_bionic_mutex_destroy(husk_bionic_mutex *m)
{
    if (!m) return 22;
    if (m->state == BIONIC_MUTEX_MAGIC && m->handle != 0) {
        pthread_mutex_t *hm = (pthread_mutex_t *)(uintptr_t)m->handle;
        pthread_mutex_destroy(hm);
        free(hm);
    }
    memset(m, 0, sizeof(*m));
    return 0;
}

static const struct {
    const char *key;
    const char *val;
} k_android_props[] = {
    { "ro.build.version.sdk", "34" },
    { "ro.build.version.release", "14" },
    { "ro.product.cpu.abi", "arm64-v8a" },
    { "ro.product.manufacturer", "Apple" },
    { "ro.product.model", "iPhone (Husk-JITLess)" },
    { "ro.hardware", "apple_arm64" },
};

int husk_bionic_system_property_get(const char *name, char *value)
{
    if (!name || !value) return 0;
    for (size_t i = 0; i < sizeof(k_android_props) / sizeof(k_android_props[0]); i++) {
        if (strcmp(name, k_android_props[i].key) == 0) {
            size_t len = strlen(k_android_props[i].val);
            memcpy(value, k_android_props[i].val, len + 1);
            return (int)len;
        }
    }
    value[0] = '\0';
    return 0;
}

static int bionic_android_log_print(int prio, const char *tag, const char *fmt, ...)
{
    (void)prio; (void)tag; (void)fmt;
    return 0;
}

static int bionic_cxa_atexit(void (*func)(void *), void *arg, void *dso)
{
    (void)func; (void)arg; (void)dso;
    return 0;
}

#define LINUX_NR_GETCWD        17
#define LINUX_NR_WRITE         64
#define LINUX_NR_CLOCK_GETTIME 113
#define LINUX_NR_GETPID        172
#define LINUX_NR_GETTID        178
#define LINUX_NR_GETTIMEOFDAY  169
#define LINUX_NR_GETRANDOM     278

long husk_linux_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long nr)
{
    (void)a3; (void)a4; (void)a5;
    switch (nr) {
    case LINUX_NR_GETPID:
    case LINUX_NR_GETTID:
        return (long)getpid();
    case LINUX_NR_GETCWD:
        return getcwd((char *)a0, (size_t)a1) ? a0 : -husk_errno_to_bionic(errno);
    case LINUX_NR_WRITE: {
        ssize_t w = write((int)a0, (const void *)a1, (size_t)a2);
        return (w < 0) ? -husk_errno_to_bionic(errno) : (long)w;
    }
    case LINUX_NR_CLOCK_GETTIME: {
        struct timespec *ts = (struct timespec *)a1;
        if (!ts) return -14;
        if (clock_gettime(CLOCK_REALTIME, ts) != 0) return -husk_errno_to_bionic(errno);
        return 0;
    }
    case LINUX_NR_GETTIMEOFDAY: {
        struct timeval *tv = (struct timeval *)a0;
        if (gettimeofday(tv, NULL) != 0) return -husk_errno_to_bionic(errno);
        return 0;
    }
    case LINUX_NR_GETRANDOM: {
        uint8_t *buf = (uint8_t *)a0;
        size_t len = (size_t)a1;
        if (!buf) return -14;
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)((i * 73 + 0x5Au) & 0xFFu);
        return (long)len;
    }
    default:
        return -38;
    }
}

void husk_svc_common_entry(void)
{
}

static const husk_bionic_symbol k_bionic_table[] = {
    { "__errno",                 (void *)husk_bionic_errno_ptr },
    { "__system_property_get",   (void *)husk_bionic_system_property_get },
    { "__android_log_print",     (void *)bionic_android_log_print },
    { "__cxa_atexit",            (void *)bionic_cxa_atexit },
    { "pthread_mutex_init",      (void *)husk_bionic_mutex_init },
    { "pthread_mutex_lock",      (void *)husk_bionic_mutex_lock },
    { "pthread_mutex_trylock",   (void *)husk_bionic_mutex_trylock },
    { "pthread_mutex_unlock",    (void *)husk_bionic_mutex_unlock },
    { "pthread_mutex_destroy",   (void *)husk_bionic_mutex_destroy },
    { "malloc",                  (void *)malloc },
    { "calloc",                  (void *)calloc },
    { "realloc",                 (void *)realloc },
    { "free",                    (void *)free },
    { "memcpy",                  (void *)memcpy },
    { "memmove",                 (void *)memmove },
    { "memset",                  (void *)memset },
    { "memcmp",                  (void *)memcmp },
    { "strlen",                  (void *)strlen },
    { "strcmp",                  (void *)strcmp },
    { "strncmp",                 (void *)strncmp },
    { "snprintf",                (void *)snprintf },
    { NULL,                      NULL }
};

void *husk_bionic_resolve(const char *symbol_name)
{
    if (!symbol_name) return NULL;
    for (size_t i = 0; k_bionic_table[i].name != NULL; i++) {
        if (strcmp(symbol_name, k_bionic_table[i].name) == 0) {
            return k_bionic_table[i].addr;
        }
    }
    return NULL;
}

bool husk_bionic_is_system_lib(const char *soname)
{
    if (!soname) return false;
    static const char *const k_sys_libs[] = {
        "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
        "libandroid.so", "libEGL.so", "libGLESv2.so", "libGLESv3.so",
        "libvulkan.so", "libOpenSLES.so", "libaaudio.so"
    };
    for (size_t i = 0; i < sizeof(k_sys_libs) / sizeof(k_sys_libs[0]); i++) {
        if (strcmp(soname, k_sys_libs[i]) == 0) return true;
    }
    return false;
}
