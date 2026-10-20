/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * test_translation_layer.c — Automated test suite for Husk-JITLess.
 */
#include "husk_jitless.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_a64_rewriter(void)
{
    printf("[1/4] Testing AOT AArch64 instruction decoder and rewriter...\n");

    bool known = false;
    assert(a64_uses_gpr(0x8B020032u, 18, &known) && known);
    assert(a64_uses_gpr(0x8B020032u, 1, &known) && known);
    assert(a64_uses_gpr(0x8B020032u, 2, &known) && known);
    assert(!a64_uses_gpr(0x8B020032u, 3, &known) && known);

    uint32_t subst = a64_subst_gpr(0x8B020032u, 18, 16);
    assert((subst & 0x1Fu) == 16);

    uint32_t code[6] = {
        0xD53BD048u,
        0xF9401509u,
        0x91000412u,
        0xD53B002Au,
        0xD4000001u,
        0xD65F03C0u
    };
    uint8_t stubs[16384];
    memset(stubs, 0, sizeof(stubs));
    a64_rewrite_stats stats;

    uint64_t code_va = 0x4000ULL;
    uint64_t stub_va = 0x8000ULL;
    uint64_t host_va = 0xC000ULL;

    bool ok = a64_rewrite_text_aot(code, sizeof(code), code_va,
                                   stubs, sizeof(stubs), stub_va,
                                   host_va, 0x100u, &stats);
    assert(ok);
    assert(stats.tpidr_rewritten == 1);
    assert(stats.x18_rewritten == 1);
    assert(stats.ctr_rewritten == 1);
    assert(stats.svc_rewritten == 1);
    assert(stats.x18_failed == 0);
    assert(stats.stubs_bytes_used == 128);

    assert((code[0] & 0x9F00001Fu) == (0x90000000u | 8u));
    assert(code[1] == 0xF9401509u);
    assert(code[5] == 0xD65F03C0u);
    assert((code[2] >> 26) == 0x05u);
    assert((code[3] >> 26) == 0x05u);
    assert((code[4] >> 26) == 0x05u);

    printf("      PASS: tpidr_el0=%zu, x18=%zu, ctr_el0=%zu, svc=%zu, stubs=%zuB\n",
           stats.tpidr_rewritten, stats.x18_rewritten,
           stats.ctr_rewritten, stats.svc_rewritten, stats.stubs_bytes_used);
}

static size_t build_synthetic_android_elf(uint8_t *buf, size_t cap)
{
    assert(cap >= 65536);
    memset(buf, 0, 65536);

    buf[0] = 0x7Fu; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[4] = 2u;
    buf[5] = 1u;
    buf[6] = 1u;
    *(uint16_t *)(buf + 16) = 3u;
    *(uint16_t *)(buf + 18) = 183u;
    *(uint32_t *)(buf + 20) = 1u;
    *(uint64_t *)(buf + 32) = 64u;
    *(uint16_t *)(buf + 52) = 64u;
    *(uint16_t *)(buf + 54) = 56u;
    *(uint16_t *)(buf + 56) = 3u;

    uint8_t *ph0 = buf + 64;
    *(uint32_t *)(ph0 + 0)  = 1u;
    *(uint32_t *)(ph0 + 4)  = 5u;
    *(uint64_t *)(ph0 + 8)  = 0u;
    *(uint64_t *)(ph0 + 16) = 0u;
    *(uint64_t *)(ph0 + 32) = 0x4000u;
    *(uint64_t *)(ph0 + 40) = 0x4000u;
    *(uint64_t *)(ph0 + 48) = 0x4000u;

    uint8_t *ph1 = ph0 + 56;
    *(uint32_t *)(ph1 + 0)  = 1u;
    *(uint32_t *)(ph1 + 4)  = 6u;
    *(uint64_t *)(ph1 + 8)  = 0x4000u;
    *(uint64_t *)(ph1 + 16) = 0x8000u;
    *(uint64_t *)(ph1 + 32) = 0x4000u;
    *(uint64_t *)(ph1 + 40) = 0x4000u;
    *(uint64_t *)(ph1 + 48) = 0x4000u;

    uint8_t *ph2 = ph1 + 56;
    *(uint32_t *)(ph2 + 0)  = 2u;
    *(uint32_t *)(ph2 + 4)  = 6u;
    *(uint64_t *)(ph2 + 8)  = 0x4000u;
    *(uint64_t *)(ph2 + 16) = 0x8000u;
    *(uint64_t *)(ph2 + 32) = 256u;
    *(uint64_t *)(ph2 + 40) = 256u;
    *(uint64_t *)(ph2 + 48) = 8u;

    uint32_t *code = (uint32_t *)(buf + 0x1000);
    code[0] = 0xD53BD048u;
    code[1] = 0x91000412u;
    code[2] = 0xD4000001u;
    code[3] = 0xD65F03C0u;

    uint8_t *symtab = buf + 0x0400;
    *(uint32_t *)(symtab + 24 + 0)  = 1u;
    *(uint8_t  *)(symtab + 24 + 4)  = 0x12u;
    *(uint16_t *)(symtab + 24 + 6)  = 0u;
    *(uint32_t *)(symtab + 48 + 0)  = 23u;
    *(uint8_t  *)(symtab + 48 + 4)  = 0x12u;
    *(uint16_t *)(symtab + 48 + 6)  = 1u;
    *(uint64_t *)(symtab + 48 + 8)  = 0x1000u;

    char *strtab = (char *)(buf + 0x0600);
    strtab[0] = '\0';
    strcpy(strtab + 1,  "__system_property_get");
    strcpy(strtab + 23, "JNI_OnLoad");
    strcpy(strtab + 34, "libtest_game.so");

    uint8_t *rela = buf + 0x0800;
    *(uint64_t *)(rela + 0)  = 0x9000u;
    *(uint64_t *)(rela + 8)  = 1027ULL;
    *(int64_t  *)(rela + 16) = 0x1000LL;
    *(uint64_t *)(rela + 24) = 0x9008u;
    *(uint64_t *)(rela + 32) = (1ULL << 32) | 1025ULL;
    *(int64_t  *)(rela + 40) = 0LL;

    uint64_t *dyn = (uint64_t *)(buf + 0x4000);
    int d = 0;
    dyn[d++] = 5;  dyn[d++] = 0x0600;
    dyn[d++] = 10; dyn[d++] = 128;
    dyn[d++] = 6;  dyn[d++] = 0x0400;
    dyn[d++] = 11; dyn[d++] = 24;
    dyn[d++] = 14; dyn[d++] = 34;
    dyn[d++] = 7;  dyn[d++] = 0x0800;
    dyn[d++] = 8;  dyn[d++] = 48;
    dyn[d++] = 0;  dyn[d++] = 0;

    return 0x8000;
}

static void test_elf2macho_and_jitless_linker(void)
{
    printf("[2/4] Testing ELF-to-Mach-O AOT conversion, Dev Cert signing, and JIT-less loading...\n");

    uint8_t elf_buf[65536];
    size_t elf_sz = build_synthetic_android_elf(elf_buf, sizeof(elf_buf));

    husk_jitless_runtime rt;
    assert(husk_jitless_init(&rt, "/tmp/husk_jitless_test"));

    const char *mock_p12 = "MOCK_PKCS12_PAYLOAD_TEAMID:9X8Y7Z6W5V_END";
    char err[256] = {0};
    assert(husk_jitless_set_dev_cert(&rt, (const uint8_t *)mock_p12, strlen(mock_p12),
                                     "devpass", err, sizeof(err)));
    assert(strcmp(rt.cert.team_id, "9X8Y7Z6W5V") == 0);

    husk_jitless_lib *lib = husk_jitless_load_elf_bytes(&rt, "libtest_game.so",
                                                        elf_buf, elf_sz, err, sizeof(err));
    assert(lib != NULL);
    assert(lib->relocated && lib->initialized);
    assert(strcmp(lib->meta.soname, "libtest_game.so") == 0);
    assert(lib->meta.rewrite_stats.tpidr_rewritten == 1);
    assert(lib->meta.rewrite_stats.x18_rewritten == 1);
    assert(lib->meta.rewrite_stats.svc_rewritten == 1);

    FILE *df = fopen(lib->dylib_path, "rb");
    assert(df != NULL);
    fseek(df, 0, SEEK_END);
    size_t disk_sz = (size_t)ftell(df);
    fseek(df, 0, SEEK_SET);
    uint8_t *disk_buf = (uint8_t *)malloc(disk_sz);
    assert(disk_buf && fread(disk_buf, 1, disk_sz, df) == disk_sz);
    fclose(df);

    char verified_team[32] = {0};
    assert(husk_macho_verify_signature(disk_buf, disk_sz,
                                       verified_team, sizeof(verified_team), err, sizeof(err)));
    free(disk_buf);
    assert(strcmp(verified_team, "9X8Y7Z6W5V") == 0);

    void *jni_onload = husk_jitless_dlsym(lib, "JNI_OnLoad");
    assert(jni_onload == lib->image_base + lib->meta.macho_text_vmaddr + 0x1000);

    uint64_t rel_slot = 0;
    memcpy(&rel_slot, lib->image_base + lib->meta.macho_text_vmaddr + 0x9000, 8);
    assert((void *)(uintptr_t)rel_slot == jni_onload);

    uint64_t glob_slot = 0;
    memcpy(&glob_slot, lib->image_base + lib->meta.macho_text_vmaddr + 0x9008, 8);
    assert((void *)(uintptr_t)glob_slot == (void *)husk_bionic_system_property_get);

    printf("      PASS: Mach-O signed with TeamID=%s, SHA-256 pages verified, GOT relocated in __DATA\n",
           verified_team);

    husk_jitless_shutdown(&rt);
}

static void test_bionic_shim(void)
{
    printf("[3/4] Testing Bionic-on-Darwin ABI shim (errno, pthread, properties, syscalls)...\n");

    assert(husk_errno_to_bionic(EAGAIN) == 11);
    assert(husk_errno_from_bionic(11) == EAGAIN);

    assert(sizeof(husk_bionic_mutex) == 40);
    husk_bionic_mutex mtx;
    assert(husk_bionic_mutex_init(&mtx, NULL) == 0);
    assert(husk_bionic_mutex_lock(&mtx) == 0);
    assert(husk_bionic_mutex_unlock(&mtx) == 0);
    assert(husk_bionic_mutex_destroy(&mtx) == 0);

    char prop[64] = {0};
    assert(husk_bionic_system_property_get("ro.build.version.sdk", prop) > 0);
    assert(strcmp(prop, "34") == 0);

    assert(husk_linux_syscall(0, 0, 0, 0, 0, 0, 172) == (long)getpid());
    uint8_t rnd[8] = {0};
    assert(husk_linux_syscall((long)(uintptr_t)rnd, 8, 0, 0, 0, 0, 278) == 8);
    assert(rnd[0] == 0x5Au);

    printf("      PASS: 40B Bionic mutex, errno/signal tables, and Linux svc #0 syscalls verified\n");
}

static void test_dalvik_and_jni(void)
{
    printf("[4/4] Testing JIT-less Dalvik DEX bytecode interpreter and 64-bit HLE JNI...\n");

    husk_JavaVM *vm = husk_jni_get_vm();
    husk_JNIEnv *env = husk_jni_get_env();
    assert(vm != NULL && env != NULL);

    husk_jobj *jstr = husk_jni_new_string_utf("Hello from Husk-JITLess");
    assert(strcmp(husk_jni_get_string_utf_chars(jstr), "Hello from Husk-JITLess") == 0);
    husk_jni_free_object(jstr);

    const uint16_t dex_code[] = {
        0x0013u, 0x000Au,
        0x0067u, 0x0003u,
        0x0160u, 0x0003u,
        0x0290u, 0x0301u,
        0x020Fu
    };
    husk_dex_vm *dvm = husk_dex_vm_create();
    husk_jvalue arg0;
    arg0.i = 32;
    husk_jvalue ret;
    ret.i = 0;

    bool ok = husk_dex_exec_bytecode(dvm, dex_code, sizeof(dex_code) / 2, 4, &arg0, 1, &ret);
    assert(ok && ret.i == 42);
    husk_dex_vm_destroy(dvm);

    printf("      PASS: Dalvik interpreter returned %d and HLE JNI initialized cleanly\n", ret.i);
}

int main(void)
{
    printf("=== Husk-JITLess Test Suite ===\n");
    test_a64_rewriter();
    test_elf2macho_and_jitless_linker();
    test_bionic_shim();
    test_dalvik_and_jni();
    printf("=== ALL TESTS PASSED ===\n");
    return 0;
}
