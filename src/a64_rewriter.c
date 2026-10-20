/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * a64_rewriter.c — AArch64 instruction decoder and Ahead-Of-Time (AOT) binary
 * translator for Husk-JITLess.
 */
#include "a64_rewriter.h"
#include <string.h>

bool a64_gpr_fields(uint32_t w, uint8_t s[5], int *n)
{
    int k = 0;
#define F(shift) (s[k++] = (uint8_t)(shift))
    *n = 0;

    if ((w & 0x1C000000u) == 0x10000000u) {
        switch ((w >> 23) & 7u) {
        case 0: case 1: F(0); break;
        case 2: F(0); F(5); break;
        case 4: F(0); F(5); break;
        case 5: F(0); break;
        case 6: F(0); F(5); break;
        case 7: F(0); F(5); F(16); break;
        default: return false;
        }
    } else if ((w & 0x0E000000u) == 0x0A000000u) {
        if      ((w & 0x1F000000u) == 0x0A000000u) { F(0); F(5); F(16); }
        else if ((w & 0x1F000000u) == 0x0B000000u) { F(0); F(5); F(16); }
        else if ((w & 0x1FE00000u) == 0x1A000000u) { F(0); F(5); F(16); }
        else if ((w & 0x1FE00000u) == 0x1A400000u) { F(5); if (!(w & 0x800u)) F(16); }
        else if ((w & 0x1FE00000u) == 0x1A800000u) { F(0); F(5); F(16); }
        else if ((w & 0x1F000000u) == 0x1B000000u) { F(0); F(5); F(10); F(16); }
        else if ((w & 0x5FE00000u) == 0x1AC00000u) { F(0); F(5); F(16); }
        else if ((w & 0x5FE00000u) == 0x5AC00000u) { F(0); F(5); }
        else return false;
    } else if ((w & 0x3A000000u) == 0x28000000u) {
        if (!((w >> 26) & 1u)) { F(0); F(10); }
        F(5);
    } else if ((w & 0x3B000000u) == 0x18000000u) {
        if (!((w >> 26) & 1u) && ((w >> 30) & 3u) != 3u) F(0);
    } else if ((w & 0x3B000000u) == 0x38000000u || (w & 0x3B000000u) == 0x39000000u) {
        unsigned v = (w >> 26) & 1u, size = (w >> 30) & 3u, opc = (w >> 22) & 3u;
        bool prfm = !v && size == 3 && opc == 2;
        if (!v && !prfm) F(0);
        F(5);
        if (!((w >> 24) & 1u) && ((w >> 21) & 1u)) {
            unsigned b = (w >> 10) & 3u;
            if (b == 2 || b == 0) F(16);
            else return false;
        }
    } else if ((w & 0x3F000000u) == 0x08000000u) {
        F(0); F(5); F(10); F(16);
    } else if ((w & 0xBE000000u) == 0x0C000000u) {
        F(5);
        if ((w >> 23) & 1u) F(16);
    } else if ((w & 0x0E000000u) == 0x0E000000u) {
        if ((w & 0x7F20FC00u) == 0x1E200000u) {
            switch ((w >> 16) & 7u) {
            case 0: case 1: case 4: case 5: case 6: F(0); break;
            default: F(5); break;
            }
        } else if ((w & 0xFFFFFC00u) == 0x1E7E0000u) {
            F(0);
        } else if ((w & 0x7F200000u) == 0x1E000000u) {
            switch ((w >> 16) & 7u) {
            case 2: case 3: F(5); break;
            default: F(0); break;
            }
        } else if ((w & 0x9FE08400u) == 0x0E000400u) {
            switch ((w >> 11) & 0xFu) {
            case 1: case 3: F(5); break;
            case 5: case 7: F(0); break;
            default: break;
            }
        }
    } else if ((w & 0xFFC00000u) == 0xD5000000u) {
        F(0);
    } else if ((w & 0x7E000000u) == 0x34000000u || (w & 0x7E000000u) == 0x36000000u) {
        F(0);
    } else if ((w & 0xFE000000u) == 0xD6000000u) {
        F(5);
    } else if ((w & 0x7C000000u) == 0x14000000u || (w & 0xFF000010u) == 0x54000000u || (w & 0xFFE0001Fu) == 0xD4000001u) {
        /* branch / syscall: no GPR fields */
    } else {
        return false;
    }
    *n = k;
    return true;
#undef F
}

uint32_t a64_gpr_mask(uint32_t insn)
{
    uint8_t s[5];
    int n = 0;
    uint32_t m = 0;
    if (!a64_gpr_fields(insn, s, &n)) return 0xFFFFFFFFu;
    for (int i = 0; i < n; i++) {
        unsigned r = (insn >> s[i]) & 31u;
        if (r < 31) m |= (1u << r);
    }
    return m;
}

bool a64_uses_gpr(uint32_t insn, unsigned reg, bool *known)
{
    uint8_t s[5];
    int n = 0;
    if (!a64_gpr_fields(insn, s, &n)) {
        *known = false;
        return ((insn & 31u) == reg) || (((insn >> 5) & 31u) == reg) ||
               (((insn >> 10) & 31u) == reg) || (((insn >> 16) & 31u) == reg);
    }
    *known = true;
    for (int i = 0; i < n; i++) {
        if (((insn >> s[i]) & 31u) == reg) return true;
    }
    return false;
}

uint32_t a64_subst_gpr(uint32_t insn, unsigned from, unsigned to)
{
    uint8_t s[5];
    int n = 0;
    if (!a64_gpr_fields(insn, s, &n)) return insn;
    for (int i = 0; i < n; i++) {
        if (((insn >> s[i]) & 31u) == from) {
            insn = (insn & ~(31u << s[i])) | ((to & 31u) << s[i]);
        }
    }
    return insn;
}

uint32_t a64_encode_adrp(unsigned rd, uint64_t pc_vaddr, uint64_t target_vaddr)
{
    int64_t delta = ((int64_t)(target_vaddr & ~(uint64_t)0xFFF) -
                     (int64_t)(pc_vaddr & ~(uint64_t)0xFFF)) >> 12;
    uint32_t imm = (uint32_t)delta & 0x1FFFFFu;
    return 0x90000000u | ((imm & 3u) << 29) | ((imm >> 2) << 5) | (rd & 0x1Fu);
}

bool a64_in_branch_range(uint64_t from_vaddr, uint64_t to_vaddr)
{
    int64_t off = ((int64_t)to_vaddr - (int64_t)from_vaddr) / 4;
    return off > -(1 << 25) && off < (1 << 25);
}

uint32_t a64_encode_b(uint64_t from_vaddr, uint64_t to_vaddr, bool link)
{
    int64_t off = ((int64_t)to_vaddr - (int64_t)from_vaddr) / 4;
    uint32_t op = link ? 0x94000000u : 0x14000000u;
    return op | ((uint32_t)off & 0x3FFFFFFu);
}

static inline uint32_t e_stur(unsigned rt, int imm) {
    return 0xF8000000u | (((uint32_t)imm & 0x1FFu) << 12) | (31u << 5) | rt;
}
static inline uint32_t e_ldur(unsigned rt, int imm) {
    return 0xF8400000u | (((uint32_t)imm & 0x1FFu) << 12) | (31u << 5) | rt;
}
static inline uint32_t e_mrs_tsd(unsigned rt) {
    return 0xD53BD060u | rt;
}
static inline uint32_t e_and_tsd(unsigned r) {
    return 0x927DF000u | (r << 5) | r;
}
static inline uint32_t e_ldr_uimm64(unsigned rt, unsigned rn, uint32_t byte_off) {
    return 0xF9400000u | (((byte_off / 8) & 0xFFFu) << 10) | (rn << 5) | rt;
}
static inline uint32_t e_str_uimm64(unsigned rt, unsigned rn, uint32_t byte_off) {
    return 0xF9000000u | (((byte_off / 8) & 0xFFFu) << 10) | (rn << 5) | rt;
}

static unsigned pick_scratch(uint32_t used, unsigned avoid)
{
    static const unsigned order[] = { 16, 17, 15, 14, 13, 12, 11, 10, 9 };
    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        if (!(used & (1u << order[i])) && order[i] != avoid) return order[i];
    }
    return 0;
}

static int emit_mov64(uint32_t *out, unsigned rd, uint64_t v)
{
    int n = 0;
    out[n++] = 0xD2800000u | (uint32_t)((v & 0xFFFFu) << 5) | rd;
    for (int sh = 1; sh < 4; sh++) {
        uint64_t part = (v >> (16 * sh)) & 0xFFFFu;
        if (part) {
            out[n++] = 0xF2800000u | ((uint32_t)sh << 21) | ((uint32_t)part << 5) | rd;
        }
    }
    return n;
}

bool a64_rewrite_text_aot(uint32_t *code_buf,
                          size_t code_len,
                          uint64_t code_vaddr,
                          uint8_t *stub_buf,
                          size_t stub_cap,
                          uint64_t stub_vaddr,
                          uint64_t host_page_vaddr,
                          uint32_t vx18_tsd_off,
                          a64_rewrite_stats *stats)
{
    if (stats) memset(stats, 0, sizeof(*stats));
    if (!code_buf || (code_len % 4) != 0) return false;

    size_t nwords = code_len / 4;
    size_t stub_used = 0;
    uint32_t tsd_off = vx18_tsd_off ? vx18_tsd_off : 0x100u;

    for (size_t i = 0; i < nwords; i++) {
        uint32_t insn = code_buf[i];
        uint64_t pc = code_vaddr + (uint64_t)i * 4;

        if ((insn & 0xFFFFFFE0u) == 0xD53BD040u) {
            unsigned rt = insn & 0x1Fu;
            code_buf[i] = a64_encode_adrp(rt, pc, host_page_vaddr);
            if (stats) stats->tpidr_rewritten++;
            continue;
        }

        if ((insn & 0xFFFFFFE0u) == 0xD53B0020u) {
            unsigned rt = insn & 0x1Fu;
            uint64_t cur_stub_va = stub_vaddr + stub_used;
            if (stub_used + 32 <= stub_cap && a64_in_branch_range(pc, cur_stub_va)) {
                uint32_t *s = (uint32_t *)(stub_buf + stub_used);
                int k = emit_mov64(s, rt, 0x8444c004ULL);
                s[k] = a64_encode_b(cur_stub_va + (uint64_t)k * 4, pc + 4, false);
                for (int pad = k + 1; pad < 8; pad++) s[pad] = 0xD503201Fu;
                code_buf[i] = a64_encode_b(pc, cur_stub_va, false);
                stub_used += 32;
                if (stats) stats->ctr_rewritten++;
            }
            continue;
        }

        if (insn == 0xD4000001u) {
            uint64_t cur_stub_va = stub_vaddr + stub_used;
            if (stub_used + 32 <= stub_cap && a64_in_branch_range(pc, cur_stub_va)) {
                uint32_t *s = (uint32_t *)(stub_buf + stub_used);
                s[0] = 0xA9BF7BFDu;
                s[1] = 0xA9BF47F0u;
                s[2] = a64_encode_adrp(16, cur_stub_va + 8, host_page_vaddr);
                s[3] = e_ldr_uimm64(16, 16, HUSK_HOST_OFF_SVC_COMMON);
                s[4] = 0xD63F0200u;
                s[5] = 0xA8C147F0u;
                s[6] = 0xA8C17BFDu;
                s[7] = a64_encode_b(cur_stub_va + 28, pc + 4, false);
                code_buf[i] = a64_encode_b(pc, cur_stub_va, false);
                stub_used += 32;
                if (stats) stats->svc_rewritten++;
            } else {
                code_buf[i] = 0x92800000u | (37u << 5);
                if (stats) stats->svc_enosys_fallback++;
            }
            continue;
        }

        if ((insn & 31u) != 18 && ((insn >> 5) & 31u) != 18 &&
            ((insn >> 10) & 31u) != 18 && ((insn >> 16) & 31u) != 18) {
            continue;
        }
        bool known = false;
        if (!a64_uses_gpr(insn, 18, &known)) continue;
        if (!known || stub_used + 64 > stub_cap) {
            if (stats) stats->x18_failed++;
            continue;
        }

        uint64_t cur_stub_va = stub_vaddr + stub_used;
        if (!a64_in_branch_range(pc, cur_stub_va)) {
            if (stats) stats->x18_failed++;
            continue;
        }

        uint32_t *s = (uint32_t *)(stub_buf + stub_used);
        int n = 0;
        uint32_t used = a64_gpr_mask(insn);

        if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) {
            s[n++] = e_mrs_tsd(17);
            s[n++] = e_and_tsd(17);
            s[n++] = e_ldr_uimm64(17, 17, tsd_off);
            s[n++] = 0xD61F0000u | (17u << 5);
        } else {
            unsigned S = pick_scratch(used, 0);
            unsigned T = pick_scratch(used, S);
            if (!S || !T) {
                if (stats) stats->x18_failed++;
                continue;
            }
            s[n++] = e_stur(S, -16);
            s[n++] = e_stur(T, -8);
            s[n++] = e_mrs_tsd(S);
            s[n++] = e_and_tsd(S);
            s[n++] = e_ldr_uimm64(S, S, tsd_off);
            s[n++] = a64_subst_gpr(insn, 18, S);
            s[n++] = e_mrs_tsd(T);
            s[n++] = e_and_tsd(T);
            s[n++] = e_str_uimm64(S, T, tsd_off);
            s[n++] = e_ldur(T, -8);
            s[n++] = e_ldur(S, -16);
            s[n]   = a64_encode_b(cur_stub_va + (uint64_t)n * 4, pc + 4, false);
            n++;
        }

        for (int pad = n; pad < 16; pad++) s[pad] = 0xD503201Fu;
        code_buf[i] = a64_encode_b(pc, cur_stub_va, false);
        stub_used += 64;
        if (stats) stats->x18_rewritten++;
    }

    if (stats) stats->stubs_bytes_used = stub_used;
    return true;
}
