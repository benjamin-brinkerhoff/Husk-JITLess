/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jni_dvm.c — 64-bit High-Level Emulated (HLE) JNI environment (JavaVM, JNIEnv)
 * and JIT-less Dalvik (DEX) bytecode interpreter for Husk-JITLess.
 */
#include "jni_dvm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct husk_jclass {
    char name[128];
    char super_name[128];
    bool initialized;
};

struct husk_jobj {
    husk_jclass *cls;
    char        *utf8;
};

typedef struct {
    char         cls_name[128];
    char         name[64];
    char         sig[128];
    husk_jhle_fn fn;
    bool         is_static;
} hle_method_entry_t;

static husk_jclass g_classes[128];
static int g_num_classes = 0;

static hle_method_entry_t g_methods[256];
static int g_num_methods = 0;

static const void *g_jni_native_interface[232];
static const void *g_jni_invoke_interface[10];
static husk_JNIEnv g_env;
static husk_JavaVM g_vm;
static bool g_jni_ready = false;

static int jni_GetVersion(husk_JNIEnv *env)
{
    (void)env;
    return 0x00010006;
}

static void *jni_FindClass(husk_JNIEnv *env, const char *name)
{
    (void)env;
    if (!name) return NULL;
    for (int i = 0; i < g_num_classes; i++) {
        if (strcmp(g_classes[i].name, name) == 0) return &g_classes[i];
    }
    return husk_jni_register_class(name, "java/lang/Object");
}

static void *jni_GetMethodID(husk_JNIEnv *env, void *clazz, const char *name, const char *sig)
{
    (void)env;
    husk_jclass *c = (husk_jclass *)clazz;
    if (!c || !name || !sig) return NULL;
    for (int i = 0; i < g_num_methods; i++) {
        if (!g_methods[i].is_static &&
            strcmp(g_methods[i].cls_name, c->name) == 0 &&
            strcmp(g_methods[i].name, name) == 0 &&
            strcmp(g_methods[i].sig, sig) == 0) {
            return &g_methods[i];
        }
    }
    return NULL;
}

static void *jni_GetStaticMethodID(husk_JNIEnv *env, void *clazz, const char *name, const char *sig)
{
    (void)env;
    husk_jclass *c = (husk_jclass *)clazz;
    if (!c || !name || !sig) return NULL;
    for (int i = 0; i < g_num_methods; i++) {
        if (g_methods[i].is_static &&
            strcmp(g_methods[i].cls_name, c->name) == 0 &&
            strcmp(g_methods[i].name, name) == 0 &&
            strcmp(g_methods[i].sig, sig) == 0) {
            return &g_methods[i];
        }
    }
    return NULL;
}

static husk_jobj *jni_NewStringUTF(husk_JNIEnv *env, const char *bytes)
{
    (void)env;
    return husk_jni_new_string_utf(bytes);
}

static const char *jni_GetStringUTFChars(husk_JNIEnv *env, husk_jobj *string, uint8_t *isCopy)
{
    (void)env;
    if (isCopy) *isCopy = 0;
    return husk_jni_get_string_utf_chars(string);
}

static int jni_GetEnv(husk_JavaVM *vm, void **env, int version)
{
    (void)version;
    if (!vm || !env) return -1;
    *env = &g_env;
    return 0;
}

void husk_jni_init(void)
{
    if (g_jni_ready) return;
    memset(g_jni_native_interface, 0, sizeof(g_jni_native_interface));
    memset(g_jni_invoke_interface, 0, sizeof(g_jni_invoke_interface));

    g_jni_native_interface[4]   = (const void *)jni_GetVersion;
    g_jni_native_interface[6]   = (const void *)jni_FindClass;
    g_jni_native_interface[33]  = (const void *)jni_GetMethodID;
    g_jni_native_interface[113] = (const void *)jni_GetStaticMethodID;
    g_jni_native_interface[167] = (const void *)jni_NewStringUTF;
    g_jni_native_interface[169] = (const void *)jni_GetStringUTFChars;
    g_jni_invoke_interface[6]   = (const void *)jni_GetEnv;

    g_env.functions = g_jni_native_interface;
    g_env.vm = &g_vm;
    g_vm.functions = g_jni_invoke_interface;
    g_vm.env = &g_env;
    g_jni_ready = true;

    husk_jni_register_class("java/lang/Object", "");
    husk_jni_register_class("java/lang/String", "java/lang/Object");
    husk_jni_register_class("android/app/Activity", "android/content/Context");
    husk_jni_register_class("android/app/NativeActivity", "android/app/Activity");
}

husk_JavaVM *husk_jni_get_vm(void)
{
    husk_jni_init();
    return &g_vm;
}

husk_JNIEnv *husk_jni_get_env(void)
{
    husk_jni_init();
    return &g_env;
}

husk_jclass *husk_jni_register_class(const char *slash_name, const char *super_name)
{
    if (!slash_name) return NULL;
    for (int i = 0; i < g_num_classes; i++) {
        if (strcmp(g_classes[i].name, slash_name) == 0) return &g_classes[i];
    }
    if (g_num_classes >= 128) return NULL;
    husk_jclass *c = &g_classes[g_num_classes++];
    snprintf(c->name, sizeof(c->name), "%s", slash_name);
    snprintf(c->super_name, sizeof(c->super_name), "%s", super_name ? super_name : "java/lang/Object");
    c->initialized = false;
    return c;
}

bool husk_jni_register_method(const char *cls_name,
                              const char *method_name,
                              const char *sig,
                              husk_jhle_fn fn,
                              bool is_static)
{
    if (!cls_name || !method_name || !sig || g_num_methods >= 256) return false;
    husk_jni_register_class(cls_name, "java/lang/Object");
    hle_method_entry_t *m = &g_methods[g_num_methods++];
    snprintf(m->cls_name, sizeof(m->cls_name), "%s", cls_name);
    snprintf(m->name, sizeof(m->name), "%s", method_name);
    snprintf(m->sig, sizeof(m->sig), "%s", sig);
    m->fn = fn;
    m->is_static = is_static;
    return true;
}

husk_jobj *husk_jni_new_string_utf(const char *utf8)
{
    husk_jni_init();
    husk_jobj *o = (husk_jobj *)calloc(1, sizeof(husk_jobj));
    if (!o) return NULL;
    o->cls = husk_jni_register_class("java/lang/String", "java/lang/Object");
    o->utf8 = strdup(utf8 ? utf8 : "");
    return o;
}

const char *husk_jni_get_string_utf_chars(husk_jobj *str_obj)
{
    return (str_obj && str_obj->utf8) ? str_obj->utf8 : "";
}

void husk_jni_free_object(husk_jobj *obj)
{
    if (!obj) return;
    free(obj->utf8);
    free(obj);
}

struct husk_dex_vm {
    const uint8_t *dex_data;
    size_t         dex_len;
    int32_t        static_fields[64];
    bool           clinit_ran[64];
};

husk_dex_vm *husk_dex_vm_create(void)
{
    return (husk_dex_vm *)calloc(1, sizeof(husk_dex_vm));
}

void husk_dex_vm_destroy(husk_dex_vm *vm)
{
    free(vm);
}

bool husk_dex_vm_load_dex(husk_dex_vm *vm, const uint8_t *dex_bytes, size_t dex_len, char *err, size_t errlen)
{
    if (!vm || !dex_bytes || dex_len < 112) {
        if (err) snprintf(err, errlen, "Invalid DEX buffer");
        return false;
    }
    if (memcmp(dex_bytes, "dex\n", 4) != 0) {
        if (err) snprintf(err, errlen, "Missing 'dex\\n' magic");
        return false;
    }
    vm->dex_data = dex_bytes;
    vm->dex_len = dex_len;
    return true;
}

bool husk_dex_exec_bytecode(husk_dex_vm *vm,
                            const uint16_t *insns,
                            uint32_t insns_count,
                            uint16_t regs_size,
                            const husk_jvalue *args,
                            int nargs,
                            husk_jvalue *out_ret)
{
    if (!insns || regs_size == 0 || regs_size > 256) return false;
    int32_t v[256];
    memset(v, 0, sizeof(v));

    if (args && nargs > 0 && nargs <= regs_size) {
        for (int i = 0; i < nargs; i++) {
            v[regs_size - nargs + i] = args[i].i;
        }
    }

    uint32_t pc = 0;
    while (pc < insns_count) {
        uint16_t inst = insns[pc];
        uint8_t op = (uint8_t)(inst & 0xFFu);

        switch (op) {
        case 0x00:
            pc += 1;
            break;
        case 0x01: {
            uint8_t va = (inst >> 8) & 0x0Fu;
            uint8_t vb = (inst >> 12) & 0x0Fu;
            v[va] = v[vb];
            pc += 1;
            break;
        }
        case 0x0e:
            if (out_ret) out_ret->j = 0;
            return true;
        case 0x0f: {
            uint8_t vaa = (inst >> 8) & 0xFFu;
            if (out_ret) out_ret->i = v[vaa];
            return true;
        }
        case 0x12: {
            uint8_t va = (inst >> 8) & 0x0Fu;
            int8_t imm4 = (int8_t)((int8_t)(inst >> 8) >> 4);
            v[va] = imm4;
            pc += 1;
            break;
        }
        case 0x13: {
            uint8_t vaa = (inst >> 8) & 0xFFu;
            int16_t imm16 = (int16_t)insns[pc + 1];
            v[vaa] = imm16;
            pc += 2;
            break;
        }
        case 0x28: {
            int8_t off = (int8_t)(inst >> 8);
            pc = (uint32_t)((int32_t)pc + off);
            break;
        }
        case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37: {
            uint8_t va = (inst >> 8) & 0x0Fu;
            uint8_t vb = (inst >> 12) & 0x0Fu;
            int16_t off = (int16_t)insns[pc + 1];
            bool take = false;
            if (op == 0x32) take = (v[va] == v[vb]);
            else if (op == 0x33) take = (v[va] != v[vb]);
            else if (op == 0x34) take = (v[va] <  v[vb]);
            else if (op == 0x35) take = (v[va] >= v[vb]);
            else if (op == 0x36) take = (v[va] >  v[vb]);
            else if (op == 0x37) take = (v[va] <= v[vb]);
            pc = take ? (uint32_t)((int32_t)pc + off) : (pc + 2);
            break;
        }
        case 0x60: {
            uint8_t vaa = (inst >> 8) & 0xFFu;
            uint16_t fid = insns[pc + 1] & 63u;
            if (vm && !vm->clinit_ran[fid]) vm->clinit_ran[fid] = true;
            v[vaa] = vm ? vm->static_fields[fid] : 0;
            pc += 2;
            break;
        }
        case 0x67: {
            uint8_t vaa = (inst >> 8) & 0xFFu;
            uint16_t fid = insns[pc + 1] & 63u;
            if (vm) {
                vm->clinit_ran[fid] = true;
                vm->static_fields[fid] = v[vaa];
            }
            pc += 2;
            break;
        }
        case 0x90: case 0x91: case 0x92: {
            uint8_t vaa = (inst >> 8) & 0xFFu;
            uint8_t vbb = insns[pc + 1] & 0xFFu;
            uint8_t vcc = (insns[pc + 1] >> 8) & 0xFFu;
            if (op == 0x90) v[vaa] = v[vbb] + v[vcc];
            else if (op == 0x91) v[vaa] = v[vbb] - v[vcc];
            else v[vaa] = v[vbb] * v[vcc];
            pc += 2;
            break;
        }
        case 0xd8: {
            uint8_t vaa = (inst >> 8) & 0xFFu;
            uint8_t vbb = insns[pc + 1] & 0xFFu;
            int8_t  imm = (int8_t)(insns[pc + 1] >> 8);
            v[vaa] = v[vbb] + imm;
            pc += 2;
            break;
        }
        default:
            return false;
        }
    }
    return false;
}
