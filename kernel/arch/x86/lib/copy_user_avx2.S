/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2011 Siarhei Siamashka <siarhei.siamashka@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <linux/linkage.h>
#include <asm/current.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/cpufeatures.h>
#include <asm/alternative.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/export.h>
#include <asm/trapnr.h>

#define PREFETCH_DISTANCE 64

#define PREFETCH(addr)	prefetchnta addr

.macro ALIGN_DESTINATION_32
    /* check for bad alignment of destination, there is 32Bytes, for we will use vmovntdq */
    /* if <32Bytes, jb 302f */
    cmpl $32, %edx
    jb 302f

    movl %edi, %ecx
    andl $31, %ecx
    jz 302f                         /* already aligned */

    subl $32, %ecx
    negl %ecx
    subl %ecx, %edx

300:
    movb (%rsi), %al
301:
    movb %al, (%rdi)
    incq %rsi
    incq %rdi
    decl %ecx
    jnz 300b
302:

.section .fixup,"ax"
303:
    addl %ecx,%edx/* ecx is zerorest also */
    jmp .Lavx2_copy_user_handle_tail
    .previous

    _ASM_EXTABLE_CPY(300b, 303b)
    _ASM_EXTABLE_CPY(301b, 303b)
.endm

/*
 * large block copy, use avx2 nt & prefetchnta
 */
SYM_FUNC_START(copy_user_avx2_pf64_nt_string)
    ASM_STAC
    ALIGN_DESTINATION_32

    /* len >= 256 .  */
    cmpl $256, %edx
    jb	.Lless_than_256_bytes_cpy

    movl %esi, %ecx /* check if src is aligned */
    andl $31, %ecx
    jnz large_block_nt_unaligned_cpy

large_block_nt_aligned_cpy:
    PREFETCH(PREFETCH_DISTANCE(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 64)(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 128)(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 192)(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 256)(%rsi))

32:
    vmovdqa 0(%rsi), %ymm0
33:
    vmovdqa 32(%rsi), %ymm1
34:
    vmovdqa 64(%rsi), %ymm2
35:
    vmovdqa 96(%rsi), %ymm3
36:
    vmovdqa 128(%rsi), %ymm4
37:
    vmovdqa 160(%rsi), %ymm5
38:
    vmovdqa 192(%rsi), %ymm6
39:
    vmovdqa 224(%rsi), %ymm7

40:
    vmovntdq %ymm0, 0(%rdi)
41:
    vmovntdq %ymm1, 32(%rdi)
42:
    vmovntdq %ymm2, 64(%rdi)
43:
    vmovntdq %ymm3, 96(%rdi)
44:
    vmovntdq %ymm4, 128(%rdi)
45:
    vmovntdq %ymm5, 160(%rdi)
46:
    vmovntdq %ymm6, 192(%rdi)
47:
    vmovntdq %ymm7, 224(%rdi)

    add $256, %rsi
    add $256, %rdi
    subl $256, %edx
    cmpl $256, %edx
    jg large_block_nt_aligned_cpy

    vzeroupper
    sfence
    jmp .Lless_than_256_bytes_cpy

large_block_nt_unaligned_cpy:
    PREFETCH(PREFETCH_DISTANCE(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 64)(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 128)(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 192)(%rsi))
    PREFETCH((PREFETCH_DISTANCE + 256)(%rsi))

48:
    vmovdqu 0(%rsi), %ymm0
49:
    vmovdqu 32(%rsi), %ymm1
50:
    vmovdqu 64(%rsi), %ymm2
51:
    vmovdqu 96(%rsi), %ymm3
52:
    vmovdqu 128(%rsi), %ymm4
53:
    vmovdqu 160(%rsi), %ymm5
54:
    vmovdqu 192(%rsi), %ymm6
55:
    vmovdqu 224(%rsi), %ymm7

56:
    vmovntdq %ymm0, 0(%rdi)
57:
    vmovntdq %ymm1, 32(%rdi)
58:
    vmovntdq %ymm2, 64(%rdi)
59:
    vmovntdq %ymm3, 96(%rdi)
60:
    vmovntdq %ymm4, 128(%rdi)
61:
    vmovntdq %ymm5, 160(%rdi)
62:
    vmovntdq %ymm6, 192(%rdi)
63:
    vmovntdq %ymm7, 224(%rdi)

    add $256, %rsi
    add $256, %rdi
    subl $256, %edx
    cmpl $256, %edx
    jg large_block_nt_unaligned_cpy

    vzeroupper
    sfence
    jmp .Lless_than_256_bytes_cpy

    .section .fixup,"ax"

88:
    vzeroupper
    jmp .Lavx2_copy_user_handle_tail
    .previous

    _ASM_EXTABLE_CPY(32b, 88b)
    _ASM_EXTABLE_CPY(33b, 88b)
    _ASM_EXTABLE_CPY(34b, 88b)
    _ASM_EXTABLE_CPY(35b, 88b)
    _ASM_EXTABLE_CPY(36b, 88b)
    _ASM_EXTABLE_CPY(37b, 88b)
    _ASM_EXTABLE_CPY(38b, 88b)
    _ASM_EXTABLE_CPY(39b, 88b)

    _ASM_EXTABLE_CPY(40b, 88b)
    _ASM_EXTABLE_CPY(41b, 88b)
    _ASM_EXTABLE_CPY(42b, 88b)
    _ASM_EXTABLE_CPY(43b, 88b)
    _ASM_EXTABLE_CPY(44b, 88b)
    _ASM_EXTABLE_CPY(45b, 88b)
    _ASM_EXTABLE_CPY(46b, 88b)
    _ASM_EXTABLE_CPY(47b, 88b)
    _ASM_EXTABLE_CPY(48b, 88b)
    _ASM_EXTABLE_CPY(49b, 88b)

    _ASM_EXTABLE_CPY(50b, 88b)
    _ASM_EXTABLE_CPY(51b, 88b)
    _ASM_EXTABLE_CPY(52b, 88b)
    _ASM_EXTABLE_CPY(53b, 88b)
    _ASM_EXTABLE_CPY(54b, 88b)
    _ASM_EXTABLE_CPY(55b, 88b)
    _ASM_EXTABLE_CPY(56b, 88b)
    _ASM_EXTABLE_CPY(57b, 88b)
    _ASM_EXTABLE_CPY(58b, 88b)
    _ASM_EXTABLE_CPY(59b, 88b)

    _ASM_EXTABLE_CPY(60b, 88b)
    _ASM_EXTABLE_CPY(61b, 88b)
    _ASM_EXTABLE_CPY(62b, 88b)
    _ASM_EXTABLE_CPY(63b, 88b)
SYM_FUNC_END(copy_user_avx2_pf64_nt_string)
EXPORT_SYMBOL(copy_user_avx2_pf64_nt_string)

/*
 * If len < 256 bytes, then we use rep mov directly.
 */
SYM_CODE_START_LOCAL(.Lless_than_256_bytes_cpy)
    movl %edx, %ecx
90:
    rep movsb

    xorl %eax,%eax
    ASM_CLAC
    RET

    .section .fixup,"ax"
99:
    mov %ecx,%eax

    ASM_CLAC
    RET
    .previous

    _ASM_EXTABLE_CPY(90b, 99b)
SYM_CODE_END(.Lless_than_256_bytes_cpy)

/*
 * Try to copy last bytes and clear the rest if needed.
 * Since protection fault in copy_from/to_user is not a normal situation,
 * it is not necessary to optimize tail handling.
 * Don't try to copy the tail if machine check happened
 *
 * Input:
 * rdi destination
 * rsi source
 * rdx count
 *
 * Output:
 * eax uncopied bytes or 0 if successful.
 */

SYM_CODE_START_LOCAL(.Lavx2_copy_user_handle_tail)
    movl %edx,%ecx
    cmp $X86_TRAP_MC,%eax       /* check if X86_TRAP_MC */
    je 3f

1:  rep movsb
2:  mov %ecx,%eax

    ASM_CLAC
    RET

3:  xorl %eax,%eax
    ASM_CLAC
    RET

    _ASM_EXTABLE_CPY(1b, 2b)
SYM_CODE_END(.Lavx2_copy_user_handle_tail)

/*
 * Called when task schedule. we call fpu_save_%ymm0_7 to save old
 * task's fpu states and we call fpu_restore_%ymm0_7 to restore new
 * task's fpu states.
 */
SYM_FUNC_START(fpu_restore_ymm0_7)
   vmovdqu 0(%rsi), %ymm0
   vmovdqu 32(%rsi), %ymm1
   vmovdqu 64(%rsi), %ymm2
   vmovdqu 96(%rsi), %ymm3
   vmovdqu 128(%rsi), %ymm4
   vmovdqu 160(%rsi), %ymm5
   vmovdqu 192(%rsi), %ymm6
   vmovdqu 224(%rsi), %ymm7

   xorl %eax,%eax
   RET//ret
SYM_FUNC_END(fpu_restore_ymm0_7)
EXPORT_SYMBOL(fpu_restore_ymm0_7)

SYM_FUNC_START(fpu_save_ymm0_7)
   vmovdqu %ymm0, 0(%rdi)
   vmovdqu %ymm1, 32(%rdi)
   vmovdqu %ymm2, 64(%rdi)
   vmovdqu %ymm3, 96(%rdi)
   vmovdqu %ymm4, 128(%rdi)
   vmovdqu %ymm5, 160(%rdi)
   vmovdqu %ymm6, 192(%rdi)
   vmovdqu %ymm7, 224(%rdi)

   xorl %eax,%eax
   RET
SYM_FUNC_END(fpu_save_ymm0_7)
EXPORT_SYMBOL(fpu_save_ymm0_7)