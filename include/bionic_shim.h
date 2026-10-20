/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bionic_shim.h — Bionic-on-Darwin C library, pthread, errno, signal, and
 * Linux ARM64 syscall compatibility layer for Husk-JITLess.
 */
#ifndef HUSK_JITLESS_BIONIC_SHIM_H
#define HUSK_JITLESS_BIONIC_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct husk_bionic_symbol {
    const char *name;
    void       *addr;
} husk_bionic_symbol;

void *husk_bionic_resolve(const char *symbol_name);
bool  husk_bionic_is_system_lib(const char *soname);

int  husk_errno_to_bionic(int darwin_errno);
int  husk_errno_from_bionic(int bionic_errno);
int *husk_bionic_errno_ptr(void);
void husk_set_bionic_errno(int bionic_errno);

int husk_signal_to_darwin(int linux_sig);
int husk_signal_from_darwin(int darwin_sig);

typedef struct husk_bionic_mutex {
    uint32_t state;
    uint32_t pad;
    uint64_t handle;
    uint8_t  reserved[24];
} husk_bionic_mutex;

int husk_bionic_mutex_init(husk_bionic_mutex *m, const void *attr);
int husk_bionic_mutex_lock(husk_bionic_mutex *m);
int husk_bionic_mutex_trylock(husk_bionic_mutex *m);
int husk_bionic_mutex_unlock(husk_bionic_mutex *m);
int husk_bionic_mutex_destroy(husk_bionic_mutex *m);

int  husk_bionic_system_property_get(const char *name, char *value);
long husk_linux_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long nr);
void husk_svc_common_entry(void);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_JITLESS_BIONIC_SHIM_H */
