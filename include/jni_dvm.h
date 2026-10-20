/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jni_dvm.h — 64-bit High-Level Emulated (HLE) JNI environment (JavaVM, JNIEnv)
 * and JIT-less Dalvik (DEX) bytecode interpreter for Husk-JITLess.
 */
#ifndef HUSK_JITLESS_JNI_DVM_H
#define HUSK_JITLESS_JNI_DVM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union husk_jvalue {
    uint8_t  z;
    int8_t   b;
    uint16_t c;
    int16_t  s;
    int32_t  i;
    int64_t  j;
    float    f;
    double   d;
    void    *l;
} husk_jvalue;

typedef struct husk_jobj husk_jobj;
typedef struct husk_jclass husk_jclass;

typedef struct husk_jcall {
    husk_jobj         *self;
    husk_jclass       *cls;
    const husk_jvalue *args;
    int                nargs;
    husk_jvalue        ret;
} husk_jcall;

typedef void (*husk_jhle_fn)(husk_jcall *call);

typedef struct husk_JNIEnv {
    const void *functions;
    void       *vm;
} husk_JNIEnv;

typedef struct husk_JavaVM {
    const void  *functions;
    husk_JNIEnv *env;
} husk_JavaVM;

void         husk_jni_init(void);
husk_JavaVM *husk_jni_get_vm(void);
husk_JNIEnv *husk_jni_get_env(void);

husk_jclass *husk_jni_register_class(const char *slash_name, const char *super_name);
bool         husk_jni_register_method(const char *cls_name,
                                      const char *method_name,
                                      const char *sig,
                                      husk_jhle_fn fn,
                                      bool is_static);

husk_jobj   *husk_jni_new_string_utf(const char *utf8);
const char  *husk_jni_get_string_utf_chars(husk_jobj *str_obj);
void         husk_jni_free_object(husk_jobj *obj);

typedef struct husk_dex_vm husk_dex_vm;

husk_dex_vm *husk_dex_vm_create(void);
void         husk_dex_vm_destroy(husk_dex_vm *vm);
bool         husk_dex_vm_load_dex(husk_dex_vm *vm, const uint8_t *dex_bytes, size_t dex_len, char *err, size_t errlen);
bool         husk_dex_exec_bytecode(husk_dex_vm *vm,
                                    const uint16_t *insns,
                                    uint32_t insns_count,
                                    uint16_t regs_size,
                                    const husk_jvalue *args,
                                    int nargs,
                                    husk_jvalue *out_ret);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_JITLESS_JNI_DVM_H */
