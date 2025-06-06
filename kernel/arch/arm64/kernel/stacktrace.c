// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack tracing support
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>

#include <asm/irq.h>
#include <asm/pointer_auth.h>
#include <asm/stack_pointer.h>
#include <asm/stacktrace.h>

/*
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 * 	sub	sp, sp, #0x10
 *   	stp	x29, x30, [sp]
 *	mov	x29, sp
 *
 * A simple function epilogue looks like this:
 *	mov	sp, x29
 *	ldp	x29, x30, [sp]
 *	add	sp, sp, #0x10
 */

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
int notrace unwind_frame(struct task_struct *tsk, struct stackframe *frame)
{
	unsigned long fp = frame->fp;
	struct stack_info info;

	if (fp & 0xf)
		return -EINVAL;

	if (!tsk)
		tsk = current;

	if (!on_accessible_stack(tsk, fp, &info))
		return -EINVAL;

	if (test_bit(info.type, frame->stacks_done))
		return -EINVAL;

	/*
	 * As stacks grow downward, any valid record on the same stack must be
	 * at a strictly higher address than the prior record.
	 *
	 * Stacks can nest in several valid orders, e.g.
	 *
	 * TASK -> IRQ -> OVERFLOW -> SDEI_NORMAL
	 * TASK -> SDEI_NORMAL -> SDEI_CRITICAL -> OVERFLOW
	 *
	 * ... but the nesting itself is strict. Once we transition from one
	 * stack to another, it's never valid to unwind back to that first
	 * stack.
	 */
	if (info.type == frame->prev_type) {
		if (fp <= frame->prev_fp)
			return -EINVAL;
	} else {
		set_bit(frame->prev_type, frame->stacks_done);
	}

	/*
	 * Record this frame record's values and location. The prev_fp and
	 * prev_type are only meaningful to the next unwind_frame() invocation.
	 */
	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
	frame->prev_fp = fp;
	frame->prev_type = info.type;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (tsk->ret_stack &&
		(ptrauth_strip_insn_pac(frame->pc) == (unsigned long)return_to_handler)) {
		struct ftrace_ret_stack *ret_stack;
		/*
		 * This is a case where function graph tracer has
		 * modified a return address (LR) in a stack frame
		 * to hook a function return.
		 * So replace it to an original value.
		 */
		ret_stack = ftrace_graph_get_ret_stack(tsk, frame->graph++);
		if (WARN_ON_ONCE(!ret_stack))
			return -EINVAL;
		frame->pc = ret_stack->ret;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */
#ifdef CONFIG_KRETPROBES
	if (is_kretprobe_trampoline(frame->pc))
		frame->pc = kretprobe_find_ret_addr(tsk, (void *)frame->fp);
#endif

	frame->pc = ptrauth_strip_insn_pac(frame->pc);

	/*
	 * Frames created upon entry from EL0 have NULL FP and PC values, so
	 * don't bother reporting these. Frames created by __noreturn functions
	 * might have a valid FP even if PC is bogus, so only terminate where
	 * both are NULL.
	 */
	if (!frame->fp && !frame->pc)
		return -EINVAL;

	return 0;
}
NOKPROBE_SYMBOL(unwind_frame);

void notrace walk_stackframe(struct task_struct *tsk, struct stackframe *frame,
			     bool (*fn)(void *, unsigned long), void *data)
{
	while (1) {
		int ret;

		if (!fn(data, frame->pc))
			break;
#ifdef CONFIG_PREEMPTION
		/*
		 * Suppose existing call chain: P() -> A() -> B(), B() don't construct stack
		 * frame in which fp and lr are saved for call stack unwinding, then if task1
		 * is interrupted as running at address 'B2' and then preempted by task2,
		 * and task2 unwind the call stack of task1, it expect to see P->A->B, but
		 * actually P->B, A disappeared!
		 *
		 *   A():
		 *   A1:  stp fp, lr, ...  <-- suppose fp_P and lr_P saved
		 *   A2:  mov fp, sp       <-- suppose fp_A saved in 'fp' register
		 *   A3:  bl  B            <-- call to B()
		 *   A4:  mov ...          <-- 'A4' saved in 'lr' register
		 *
		 *   B():
		 *   B1:  mov ...
		 *   B2:  mov ...   <--  interrupt comes, then run into el1_irq()
		 *   B3:  mov ...   <--  'B3' is saved in 'elr_el1' register
		 *
		 *   el1_irq():
		 *   ...          <-- save registers then construct stack frame
		 *   Cm:  bl  arm64_preempt_schedule_irq    <-- Can be preempted here
		 *   Cn:  ...
		 *
		 * In this case, at the time interrupt comes, the address 'A4' will be saved
		 * In 'lr' register, then in interrupt entry, 'lr' register will be saved in
		 * Stack memory as struct pt_regs.
		 *
		 * See following stack memory layout, as call stack unwinding, if address
		 * 'Cn' is found , we know that fp_C is point to pt_regs.stackframe[0],
		 * then we can found the 'A4' in pt_regs.regs[30], then we can know that
		 * B() is currently called by A().
		 *
		 * Stack memory (High address downto Low address):
		 *
		 *   <High address>
		 *         |-----------------|
		 *         |      lr_P       |
		 *         |-----------------|
		 *         |      fp_P       |
		 *      -> |-----------------|
		 *     |   |      ...        |
		 *     |   |-----------------|
		 *     |   |       B3        |
		 *     |   |-----------------|
		 *      -- |       fp_A      |
		 *      -> |-----------------|  <-- pt_regs.stackframe[0]
		 *     |   |                 |
		 *     |   | X0... fp lr(A4) |  <-- pt_regs.regs[]
		 *     |   |-----------------|
		 *     |   |       ...       |
		 *     |   |-----------------|
		 *     |   |        Cn       |  <-- 'Cn' is return address of
		 *     |   |-----------------|      arm64_preempt_schedule_irq()
		 *      -- |       fp_C      |
		 *         |-----------------|
		 *   <Low address>
		 */
		if (frame->pc == (unsigned long)preempt_schedule_irq_ret_addr) {
			struct pt_regs *reg = container_of((u64 *)frame->fp,
							   struct pt_regs, stackframe[0]);

			if (!fn(data, reg->regs[30]))
				break;
		}
#endif
		ret = unwind_frame(tsk, frame);
		if (ret < 0)
			break;
	}
}
NOKPROBE_SYMBOL(walk_stackframe);

static void dump_backtrace_entry(unsigned long where, const char *loglvl)
{
	printk("%s %pS\n", loglvl, (void *)where);
}

void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
		    const char *loglvl)
{
	struct stackframe frame;
	int skip = 0;

	pr_debug("%s(regs = %p tsk = %p)\n", __func__, regs, tsk);

	if (regs) {
		if (user_mode(regs))
			return;
		skip = 1;
	}

	if (!tsk)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	if (tsk == current) {
		start_backtrace(&frame,
				(unsigned long)__builtin_frame_address(0),
				(unsigned long)dump_backtrace);
	} else {
		/*
		 * task blocked in __switch_to
		 */
		start_backtrace(&frame,
				thread_saved_fp(tsk),
				thread_saved_pc(tsk));
	}

	printk("%sCall trace:\n", loglvl);
	do {
		/* skip until specified stack frame */
		if (!skip) {
			dump_backtrace_entry(frame.pc, loglvl);
		} else if (frame.fp == regs->regs[29]) {
			skip = 0;
			/*
			 * Mostly, this is the case where this function is
			 * called in panic/abort. As exception handler's
			 * stack frame does not contain the corresponding pc
			 * at which an exception has taken place, use regs->pc
			 * instead.
			 */
			dump_backtrace_entry(regs->pc, loglvl);
		}
	} while (!unwind_frame(tsk, &frame));

	put_task_stack(tsk);
}

void show_stack(struct task_struct *tsk, unsigned long *sp, const char *loglvl)
{
	dump_backtrace(NULL, tsk, loglvl);
	barrier();
}

#ifdef CONFIG_STACKTRACE

noinline notrace void arch_stack_walk(stack_trace_consume_fn consume_entry,
			      void *cookie, struct task_struct *task,
			      struct pt_regs *regs)
{
	struct stackframe frame;

	if (regs)
		start_backtrace(&frame, regs->regs[29], regs->pc);
	else if (task == current)
		start_backtrace(&frame,
				(unsigned long)__builtin_frame_address(1),
				(unsigned long)__builtin_return_address(0));
	else
		start_backtrace(&frame, thread_saved_fp(task),
				thread_saved_pc(task));

	walk_stackframe(task, &frame, consume_entry, cookie);
}

#endif
