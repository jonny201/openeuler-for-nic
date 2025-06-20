/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <linux/threads.h>
#include <asm/asm-offsets.h>
#include <asm/assembler.h>
#include <asm/glue-cache.h>
#include <asm/glue-proc.h>
	.text

/*
 * Implementation of MPIDR hash algorithm through shifting
 * and OR'ing.
 *
 * @dst: register containing hash result
 * @rs0: register containing affinity level 0 bit shift
 * @rs1: register containing affinity level 1 bit shift
 * @rs2: register containing affinity level 2 bit shift
 * @mpidr: register containing MPIDR value
 * @mask: register containing MPIDR mask
 *
 * Pseudo C-code:
 *
 *u32 dst;
 *
 *compute_mpidr_hash(u32 rs0, u32 rs1, u32 rs2, u32 mpidr, u32 mask) {
 *	u32 aff0, aff1, aff2;
 *	u32 mpidr_masked = mpidr & mask;
 *	aff0 = mpidr_masked & 0xff;
 *	aff1 = mpidr_masked & 0xff00;
 *	aff2 = mpidr_masked & 0xff0000;
 *	dst = (aff0 >> rs0 | aff1 >> rs1 | aff2 >> rs2);
 *}
 * Input registers: rs0, rs1, rs2, mpidr, mask
 * Output register: dst
 * Note: input and output registers must be disjoint register sets
         (eg: a macro instance with mpidr = r1 and dst = r1 is invalid)
 */
	.macro compute_mpidr_hash dst, rs0, rs1, rs2, mpidr, mask
	and	\mpidr, \mpidr, \mask			@ mask out MPIDR bits
	and	\dst, \mpidr, #0xff			@ mask=aff0
 ARM(	mov	\dst, \dst, lsr \rs0		)	@ dst=aff0>>rs0
 THUMB(	lsr	\dst, \dst, \rs0		)
	and	\mask, \mpidr, #0xff00			@ mask = aff1
 ARM(	orr	\dst, \dst, \mask, lsr \rs1	)	@ dst|=(aff1>>rs1)
 THUMB(	lsr	\mask, \mask, \rs1		)
 THUMB(	orr	\dst, \dst, \mask		)
	and	\mask, \mpidr, #0xff0000		@ mask = aff2
 ARM(	orr	\dst, \dst, \mask, lsr \rs2	)	@ dst|=(aff2>>rs2)
 THUMB(	lsr	\mask, \mask, \rs2		)
 THUMB(	orr	\dst, \dst, \mask		)
	.endm

/*
 * Save CPU state for a suspend.  This saves the CPU general purpose
 * registers, and allocates space on the kernel stack to save the CPU
 * specific registers and some other data for resume.
 *  r0 = suspend function arg0
 *  r1 = suspend function
 *  r2 = MPIDR value the resuming CPU will use
 */
ENTRY(__cpu_suspend)
	stmfd	sp!, {r4 - r11, lr}
#ifdef MULTI_CPU
	ldr_l	r4, processor + CPU_SLEEP_SIZE	@ size of CPU sleep state
#else
	adr_l	r4, cpu_suspend_size
#endif
	mov	r5, sp			@ current virtual SP
	add	r4, r4, #12		@ Space for pgd, virt sp, phys resume fn
	sub	sp, sp, r4		@ allocate CPU state on stack
	adr_l	r3, sleep_save_sp
	stmfd	sp!, {r0, r1}		@ save suspend func arg and pointer
	ldr	r3, [r3, #SLEEP_SAVE_SP_VIRT]
	ALT_SMP(W(nop))			@ don't use adr_l inside ALT_SMP()
	ALT_UP_B(1f)
	adr_l	r0, mpidr_hash
	/* This ldmia relies on the memory layout of the mpidr_hash struct */
	ldmia	r0, {r1, r6-r8}	@ r1 = mpidr mask (r6,r7,r8) = l[0,1,2] shifts
	compute_mpidr_hash	r0, r6, r7, r8, r2, r1
	add	r3, r3, r0, lsl #2
1:	mov	r2, r5			@ virtual SP
	mov	r1, r4			@ size of save block
	add	r0, sp, #8		@ pointer to save block
	bl	__cpu_suspend_save
	badr	lr, cpu_suspend_abort
	ldmfd	sp!, {r0, pc}		@ call suspend fn
ENDPROC(__cpu_suspend)
	.ltorg

cpu_suspend_abort:
	ldmia	sp!, {r1 - r3}		@ pop phys pgd, virt SP, phys resume fn
	teq	r0, #0
	moveq	r0, #1			@ force non-zero value
	mov	sp, r2
	ldmfd	sp!, {r4 - r11, pc}
ENDPROC(cpu_suspend_abort)

/*
 * r0 = control register value
 */
	.align	5
	.pushsection	.idmap.text,"ax"
ENTRY(cpu_resume_mmu)
	ldr	r3, =cpu_resume_after_mmu
	instr_sync
	mcr	p15, 0, r0, c1, c0, 0	@ turn on MMU, I-cache, etc
	mrc	p15, 0, r0, c0, c0, 0	@ read id reg
	instr_sync
	mov	r0, r0
	mov	r0, r0
	ret	r3			@ jump to virtual address
ENDPROC(cpu_resume_mmu)
	.popsection
cpu_resume_after_mmu:
	bl	cpu_init		@ restore the und/abt/irq banked regs
#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
	mov	r0, sp
	bl	kasan_unpoison_task_stack_below
#endif
	mov	r0, #0			@ return zero on success
	ldmfd	sp!, {r4 - r11, pc}
ENDPROC(cpu_resume_after_mmu)

	.text
	.align

#ifdef CONFIG_MCPM
	.arm
THUMB(	.thumb			)
ENTRY(cpu_resume_no_hyp)
ARM_BE8(setend be)			@ ensure we are in BE mode
	b	no_hyp
#endif

#ifdef CONFIG_MMU
	.arm
ENTRY(cpu_resume_arm)
 THUMB(	badr	r9, 1f		)	@ Kernel is entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)
#endif

ENTRY(cpu_resume)
ARM_BE8(setend be)			@ ensure we are in BE mode
#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install_secondary
#endif
	safe_svcmode_maskall r1
no_hyp:
	mov	r1, #0
	ALT_SMP(mrc p15, 0, r0, c0, c0, 5)
	ALT_UP_B(1f)
	adr_l	r2, mpidr_hash		@ r2 = struct mpidr_hash phys address

	/*
	 * This ldmia relies on the memory layout of the mpidr_hash
	 * struct mpidr_hash.
	 */
	ldmia	r2, { r3-r6 }	@ r3 = mpidr mask (r4,r5,r6) = l[0,1,2] shifts
	compute_mpidr_hash	r1, r4, r5, r6, r0, r3
1:
	ldr_l	r0, sleep_save_sp + SLEEP_SAVE_SP_PHYS
	ldr	r0, [r0, r1, lsl #2]

	@ load phys pgd, stack, resume fn
  ARM(	ldmia	r0!, {r1, sp, pc}	)
THUMB(	ldmia	r0!, {r1, r2, r3}	)
THUMB(	mov	sp, r2			)
THUMB(	bx	r3			)
ENDPROC(cpu_resume)

#ifdef CONFIG_MMU
ENDPROC(cpu_resume_arm)
#endif
#ifdef CONFIG_MCPM
ENDPROC(cpu_resume_no_hyp)
#endif

	.data
	.align	2
	.type	sleep_save_sp, #object
ENTRY(sleep_save_sp)
	.space	SLEEP_SAVE_SP_SZ		@ struct sleep_save_sp
