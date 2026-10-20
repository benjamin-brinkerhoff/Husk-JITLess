/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * a64_rewriter.h — AArch64 instruction decoder and Ahead-Of-Time (AOT) binary
 * translator for running Android arm64-v8a code on iOS without JIT.
 */
#ifndef HUSK_JITLESS_A64_REWRITER_H
#define HUSK_JITLESS_A64_REWRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool     a64_gpr_fields(uint32_t insn, uint8_t shifts[5], int *n);
bool     a64_uses_gpr(uint32_t insn, unsigned reg, bool *known);
uint32_t a64_subst_gpr(uint32_t insn, unsigned from, unsigned to);
uint32_t a64_gpr_mask(uint32_t insn);
uint32_t a64_encode_adrp(unsigned rd, uint64_t pc_vaddr, uint64_t target_vaddr);
uint32_t a64_encode_b(uint64_t from_vaddr, uint64_t to_vaddr, bool link);
bool     a64_in_branch_range(uint64_t from_vaddr, uint64_t to_vaddr);

#define HUSK_HOST_PAGE_SIZE       16384u
#define HUSK_HOST_OFF_SVC_COMMON  0x00u
#define HUSK_HOST_OFF_UNRESOLVED  0x08u
#define HUSK_HOST_OFF_TLSDESC     0x10u
#define HUSK_HOST_OFF_VX18_TSD    0x18u
#define HUSK_HOST_OFF_BIONIC_FIND 0x20u
#define HUSK_HOST_OFF_STACK_GUARD 0x28u
#define HUSK_HOST_OFF_VX18_FALLBK 0x30u

typedef struct a64_rewrite_stats {
    size_t x18_rewritten;
    size_t x18_failed;
    size_t tpidr_rewritten;
    size_t ctr_rewritten;
    size_t svc_rewritten;
    size_t svc_enosys_fallback;
    size_t stubs_bytes_used;
} a64_rewrite_stats;

bool a64_rewrite_text_aot(uint32_t *code_buf,
                          size_t code_len,
                          uint64_t code_vaddr,
                          uint8_t *stub_buf,
                          size_t stub_cap,
                          uint64_t stub_vaddr,
                          uint64_t host_page_vaddr,
                          uint32_t vx18_tsd_off,
                          a64_rewrite_stats *stats);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_JITLESS_A64_REWRITER_H */
