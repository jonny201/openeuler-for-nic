// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/fault.c
 *
 * Copyright (C) 1995  Linus Torvalds
 * Copyright (C) 1995-2004 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/extable.h>
#include <linux/kfence.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/page-flags.h>
#include <linux/sched/signal.h>
#include <linux/sched/debug.h>
#include <linux/highmem.h>
#include <linux/perf_event.h>
#include <linux/preempt.h>
#include <linux/hugetlb.h>

#include <asm/acpi.h>
#include <asm/bug.h>
#include <asm/cmpxchg.h>
#include <asm/cpufeature.h>
#include <asm/exception.h>
#include <asm/daifflags.h>
#include <asm/debug-monitors.h>
#include <asm/esr.h>
#include <asm/kprobes.h>
#include <asm/processor.h>
#include <asm/sysreg.h>
#include <asm/system_misc.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>

int sysctl_machine_check_safe = 1;

struct fault_info {
	int	(*fn)(unsigned long addr, unsigned int esr,
		      struct pt_regs *regs);
	int	sig;
	int	code;
	const char *name;
};

static const struct fault_info fault_info[];
static struct fault_info debug_fault_info[];

static inline const struct fault_info *esr_to_fault_info(unsigned int esr)
{
	return fault_info + (esr & ESR_ELx_FSC);
}

static inline const struct fault_info *esr_to_debug_fault_info(unsigned int esr)
{
	return debug_fault_info + DBG_ESR_EVT(esr);
}

static void data_abort_decode(unsigned int esr)
{
	pr_alert("Data abort info:\n");

	if (esr & ESR_ELx_ISV) {
		pr_alert("  Access size = %u byte(s)\n",
			 1U << ((esr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT));
		pr_alert("  SSE = %lu, SRT = %lu\n",
			 (esr & ESR_ELx_SSE) >> ESR_ELx_SSE_SHIFT,
			 (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT);
		pr_alert("  SF = %lu, AR = %lu\n",
			 (esr & ESR_ELx_SF) >> ESR_ELx_SF_SHIFT,
			 (esr & ESR_ELx_AR) >> ESR_ELx_AR_SHIFT);
	} else {
		pr_alert("  ISV = 0, ISS = 0x%08lx\n", esr & ESR_ELx_ISS_MASK);
	}

	pr_alert("  CM = %lu, WnR = %lu\n",
		 (esr & ESR_ELx_CM) >> ESR_ELx_CM_SHIFT,
		 (esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT);
}

static void mem_abort_decode(unsigned int esr)
{
	pr_alert("Mem abort info:\n");

	pr_alert("  ESR = 0x%08x\n", esr);
	pr_alert("  EC = 0x%02lx: %s, IL = %u bits\n",
		 ESR_ELx_EC(esr), esr_get_class_string(esr),
		 (esr & ESR_ELx_IL) ? 32 : 16);
	pr_alert("  SET = %lu, FnV = %lu\n",
		 (esr & ESR_ELx_SET_MASK) >> ESR_ELx_SET_SHIFT,
		 (esr & ESR_ELx_FnV) >> ESR_ELx_FnV_SHIFT);
	pr_alert("  EA = %lu, S1PTW = %lu\n",
		 (esr & ESR_ELx_EA) >> ESR_ELx_EA_SHIFT,
		 (esr & ESR_ELx_S1PTW) >> ESR_ELx_S1PTW_SHIFT);

	if (esr_is_data_abort(esr))
		data_abort_decode(esr);
}

static inline unsigned long mm_to_pgd_phys(struct mm_struct *mm)
{
	/* Either init_pg_dir or swapper_pg_dir */
	if (mm == &init_mm)
		return __pa_symbol(mm->pgd);

	return (unsigned long)virt_to_phys(mm->pgd);
}

/*
 * Dump out the page tables associated with 'addr' in the currently active mm.
 */
static void show_pte(unsigned long addr)
{
	struct mm_struct *mm;
	pgd_t *pgdp;
	pgd_t pgd;

	if (is_ttbr0_addr(addr)) {
		/* TTBR0 */
		mm = current->active_mm;
		if (mm == &init_mm) {
			pr_alert("[%016lx] user address but active_mm is swapper\n",
				 addr);
			return;
		}
	} else if (is_ttbr1_addr(addr)) {
		/* TTBR1 */
		mm = &init_mm;
	} else {
		pr_alert("[%016lx] address between user and kernel address ranges\n",
			 addr);
		return;
	}

	pr_alert("%s pgtable: %luk pages, %llu-bit VAs, pgdp=%016lx\n",
		 mm == &init_mm ? "swapper" : "user", PAGE_SIZE / SZ_1K,
		 vabits_actual, mm_to_pgd_phys(mm));
	pgdp = pgd_offset(mm, addr);
	pgd = READ_ONCE(*pgdp);
	pr_alert("[%016lx] pgd=%016llx", addr, pgd_val(pgd));

	do {
		p4d_t *p4dp, p4d;
		pud_t *pudp, pud;
		pmd_t *pmdp, pmd;
		pte_t *ptep, pte;

		if (pgd_none(pgd) || pgd_bad(pgd))
			break;

		p4dp = p4d_offset(pgdp, addr);
		p4d = READ_ONCE(*p4dp);
		pr_cont(", p4d=%016llx", p4d_val(p4d));
		if (p4d_none(p4d) || p4d_bad(p4d))
			break;

		pudp = pud_offset(p4dp, addr);
		pud = READ_ONCE(*pudp);
		pr_cont(", pud=%016llx", pud_val(pud));
		if (pud_none(pud) || pud_bad(pud))
			break;

		pmdp = pmd_offset(pudp, addr);
		pmd = READ_ONCE(*pmdp);
		pr_cont(", pmd=%016llx", pmd_val(pmd));
		if (pmd_none(pmd) || pmd_bad(pmd))
			break;

		ptep = pte_offset_map(pmdp, addr);
		pte = READ_ONCE(*ptep);
		pr_cont(", pte=%016llx", pte_val(pte));
		pte_unmap(ptep);
	} while(0);

	pr_cont("\n");
}

/*
 * This function sets the access flags (dirty, accessed), as well as write
 * permission, and only to a more permissive setting.
 *
 * It needs to cope with hardware update of the accessed/dirty state by other
 * agents in the system and can safely skip the __sync_icache_dcache() call as,
 * like set_pte_at(), the PTE is never changed from no-exec to exec here.
 *
 * Returns whether or not the PTE actually changed.
 */
int ptep_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pte_t *ptep,
			  pte_t entry, int dirty)
{
	pteval_t old_pteval, pteval;
	pte_t pte = READ_ONCE(*ptep);

	if (pte_same(pte, entry))
		return 0;

	/* only preserve the access flags and write permission */
	pte_val(entry) &= PTE_RDONLY | PTE_AF | PTE_WRITE | PTE_DIRTY;

	/*
	 * Setting the flags must be done atomically to avoid racing with the
	 * hardware update of the access/dirty state. The PTE_RDONLY bit must
	 * be set to the most permissive (lowest value) of *ptep and entry
	 * (calculated as: a & b == ~(~a | ~b)).
	 */
	pte_val(entry) ^= PTE_RDONLY;
	pteval = pte_val(pte);
	do {
		old_pteval = pteval;
		pteval ^= PTE_RDONLY;
		pteval |= pte_val(entry);
		pteval ^= PTE_RDONLY;
		pteval = cmpxchg_relaxed(&pte_val(*ptep), old_pteval, pteval);
	} while (pteval != old_pteval);

	/* Invalidate a stale read-only entry */
	if (dirty)
		flush_tlb_page(vma, address);
	return 1;
}

static bool is_el1_instruction_abort(unsigned int esr)
{
	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_CUR;
}

static inline bool is_el1_permission_fault(unsigned long addr, unsigned int esr,
					   struct pt_regs *regs)
{
	unsigned int ec       = ESR_ELx_EC(esr);
	unsigned int fsc_type = esr & ESR_ELx_FSC_TYPE;

	if (ec != ESR_ELx_EC_DABT_CUR && ec != ESR_ELx_EC_IABT_CUR)
		return false;

	if (fsc_type == ESR_ELx_FSC_PERM)
		return true;

	if (is_ttbr0_addr(addr) && system_uses_ttbr0_pan())
		return fsc_type == ESR_ELx_FSC_FAULT &&
			(regs->pstate & PSR_PAN_BIT);

	return false;
}

static bool __kprobes is_spurious_el1_translation_fault(unsigned long addr,
							unsigned int esr,
							struct pt_regs *regs)
{
	unsigned long flags;
	u64 par, dfsc;

	if (ESR_ELx_EC(esr) != ESR_ELx_EC_DABT_CUR ||
	    (esr & ESR_ELx_FSC_TYPE) != ESR_ELx_FSC_FAULT)
		return false;

	local_irq_save(flags);
	asm volatile("at s1e1r, %0" :: "r" (addr));
	isb();
	par = read_sysreg_par();
	local_irq_restore(flags);

	/*
	 * If we now have a valid translation, treat the translation fault as
	 * spurious.
	 */
	if (!(par & SYS_PAR_EL1_F))
		return true;

	/*
	 * If we got a different type of fault from the AT instruction,
	 * treat the translation fault as spurious.
	 */
	dfsc = FIELD_GET(SYS_PAR_EL1_FST, par);
	return (dfsc & ESR_ELx_FSC_TYPE) != ESR_ELx_FSC_FAULT;
}

static void die_kernel_fault(const char *msg, unsigned long addr,
			     unsigned int esr, struct pt_regs *regs)
{
	bust_spinlocks(1);

	pr_alert("Unable to handle kernel %s at virtual address %016lx\n", msg,
		 addr);

	mem_abort_decode(esr);

	show_pte(addr);
	die("Oops", regs, esr);
	bust_spinlocks(0);
	do_exit(SIGKILL);
}

#ifdef CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP
static inline bool vmemmap_fault_may_fixup(unsigned long addr,
					   unsigned long esr)
{
	if (!hugetlb_optimize_vmemmap_enabled())
		return false;

	if (addr < VMEMMAP_START || addr >= VMEMMAP_END)
		return false;

	/*
	 * Only try to handle translation fault level 2 or level 3,
	 * because hugetlb vmemmap optimize only clear pmd or pte.
	 */
	switch (esr & ESR_ELx_FSC) {
	case ESR_ELx_FSC_FAULT_L2:
	case ESR_ELx_FSC_FAULT_L3:
		return true;
	default:
		return false;
	}
}

/*
 * PMD mapped vmemmap should has been split as PTE mapped
 * by HVO now, here we only check this case, other cases
 * should fail.
 * Also should check the addr is healthy enough that will not cause
 * a level2 or level3 translation fault again after page fault
 * handled with success, so we need check both bits[1:0] of PMD and
 * PTE as ARM Spec mentioned below:
 * A Translation fault is generated if bits[1:0] of a translation
 * table descriptor identify the descriptor as either a Fault
 * encoding or a reserved encoding.
 */
static inline bool vmemmap_addr_healthy(unsigned long addr)
{
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;

	pmdp = pmd_off_k(addr);
	pmd = READ_ONCE(*pmdp);
	if (!pmd_table(pmd))
		return false;

	ptep = pte_offset_kernel(pmdp, addr);
	pte = ptep_get(ptep);
	return (pte_val(pte) & PTE_TYPE_MASK) == PTE_TYPE_PAGE;
}

static bool vmemmap_handle_page_fault(unsigned long addr,
				      unsigned long esr)
{
	bool ret;
	unsigned long flags;

	if (likely(!vmemmap_fault_may_fixup(addr, esr)))
		return false;

	spin_lock_irqsave(&init_mm.page_table_lock, flags);
	ret = vmemmap_addr_healthy(addr);
	spin_unlock_irqrestore(&init_mm.page_table_lock, flags);

	return ret;
}
#else
static inline bool vmemmap_fault_may_fixup(unsigned long addr,
					   unsigned long esr)
{
	return false;
}

static inline bool vmemmap_handle_page_fault(unsigned long addr,
					     unsigned long esr)
{
	return false;
}
#endif /* CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP */

static bool is_translation_fault(unsigned long esr)
{
	return (esr & ESR_ELx_FSC_TYPE) == ESR_ELx_FSC_FAULT;
}

static void __do_kernel_fault(unsigned long addr, unsigned int esr,
			      struct pt_regs *regs)
{
	const char *msg;

	/*
	 * Are we prepared to handle this kernel fault?
	 * We are almost certainly not prepared to handle instruction faults.
	 */
	if (!is_el1_instruction_abort(esr) && fixup_exception(regs))
		return;

	if (is_spurious_el1_translation_fault(addr, esr, regs)) {
		WARN_RATELIMIT(!vmemmap_fault_may_fixup(addr, esr),
		"Ignoring spurious kernel translation fault at virtual address %016lx\n", addr);
		return;
	}

	if (is_el1_permission_fault(addr, esr, regs)) {
		if (esr & ESR_ELx_WNR)
			msg = "write to read-only memory";
		else if (is_el1_instruction_abort(esr))
			msg = "execute from non-executable memory";
		else
			msg = "read from unreadable memory";
	} else if (addr < PAGE_SIZE) {
		msg = "NULL pointer dereference";
	} else {
		if (is_translation_fault(esr)) {
			if (kfence_handle_page_fault(addr, esr & ESR_ELx_WNR, regs))
				return;
			if (vmemmap_handle_page_fault(addr, esr))
				return;
		}

		msg = "paging request";
	}

	die_kernel_fault(msg, addr, esr, regs);
}

static void set_thread_esr(unsigned long address, unsigned int esr)
{
	current->thread.fault_address = address;

	/*
	 * If the faulting address is in the kernel, we must sanitize the ESR.
	 * From userspace's point of view, kernel-only mappings don't exist
	 * at all, so we report them as level 0 translation faults.
	 * (This is not quite the way that "no mapping there at all" behaves:
	 * an alignment fault not caused by the memory type would take
	 * precedence over translation fault for a real access to empty
	 * space. Unfortunately we can't easily distinguish "alignment fault
	 * not caused by memory type" from "alignment fault caused by memory
	 * type", so we ignore this wrinkle and just return the translation
	 * fault.)
	 */
	if (!is_ttbr0_addr(current->thread.fault_address)) {
		switch (ESR_ELx_EC(esr)) {
		case ESR_ELx_EC_DABT_LOW:
			/*
			 * These bits provide only information about the
			 * faulting instruction, which userspace knows already.
			 * We explicitly clear bits which are architecturally
			 * RES0 in case they are given meanings in future.
			 * We always report the ESR as if the fault was taken
			 * to EL1 and so ISV and the bits in ISS[23:14] are
			 * clear. (In fact it always will be a fault to EL1.)
			 */
			esr &= ESR_ELx_EC_MASK | ESR_ELx_IL |
				ESR_ELx_CM | ESR_ELx_WNR;
			esr |= ESR_ELx_FSC_FAULT;
			break;
		case ESR_ELx_EC_IABT_LOW:
			/*
			 * Claim a level 0 translation fault.
			 * All other bits are architecturally RES0 for faults
			 * reported with that DFSC value, so we clear them.
			 */
			esr &= ESR_ELx_EC_MASK | ESR_ELx_IL;
			esr |= ESR_ELx_FSC_FAULT;
			break;
		default:
			/*
			 * This should never happen (entry.S only brings us
			 * into this code for insn and data aborts from a lower
			 * exception level). Fail safe by not providing an ESR
			 * context record at all.
			 */
			WARN(1, "ESR 0x%x is not DABT or IABT from EL0\n", esr);
			esr = 0;
			break;
		}
	}

	current->thread.fault_code = esr;
}

static void do_bad_area(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	/*
	 * If we are in kernel mode at this point, we have no context to
	 * handle this fault with.
	 */
	if (user_mode(regs)) {
		const struct fault_info *inf = esr_to_fault_info(esr);

		set_thread_esr(addr, esr);
		arm64_force_sig_fault(inf->sig, inf->code, (void __user *)addr,
				      inf->name);
	} else {
		__do_kernel_fault(addr, esr, regs);
	}
}

#define VM_FAULT_BADMAP		((__force vm_fault_t)0x010000)
#define VM_FAULT_BADACCESS	((__force vm_fault_t)0x020000)

static vm_fault_t __do_page_fault(struct mm_struct *mm, unsigned long addr,
				  unsigned int mm_flags, unsigned long vm_flags,
				  struct pt_regs *regs)
{
	struct vm_area_struct *vma = find_vma(mm, addr);

	if (unlikely(!vma))
		return VM_FAULT_BADMAP;

	/*
	 * Ok, we have a good vm_area for this memory access, so we can handle
	 * it.
	 */
	if (unlikely(vma->vm_start > addr)) {
		if (!(vma->vm_flags & VM_GROWSDOWN))
			return VM_FAULT_BADMAP;
		if (expand_stack(vma, addr))
			return VM_FAULT_BADMAP;
	}

	/*
	 * Check that the permissions on the VMA allow for the fault which
	 * occurred.
	 */
	if (!(vma->vm_flags & vm_flags))
		return VM_FAULT_BADACCESS;
	return handle_mm_fault(vma, addr & PAGE_MASK, mm_flags, regs);
}

static bool is_el0_instruction_abort(unsigned int esr)
{
	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

/*
 * Note: not valid for EL1 DC IVAC, but we never use that such that it
 * should fault. EL0 cannot issue DC IVAC (undef).
 */
static bool is_write_abort(unsigned int esr)
{
	return (esr & ESR_ELx_WNR) && !(esr & ESR_ELx_CM);
}

static int __kprobes do_page_fault(unsigned long addr, unsigned int esr,
				   struct pt_regs *regs)
{
	const struct fault_info *inf;
	struct mm_struct *mm = current->mm;
	vm_fault_t fault;
	unsigned long vm_flags;
	unsigned int mm_flags = FAULT_FLAG_DEFAULT;

	if (kprobe_page_fault(regs, esr))
		return 0;

	/*
	 * If we're in an interrupt or have no user context, we must not take
	 * the fault.
	 */
	if (faulthandler_disabled() || !mm)
		goto no_context;

	if (user_mode(regs))
		mm_flags |= FAULT_FLAG_USER;

	/*
	 * vm_flags tells us what bits we must have in vma->vm_flags
	 * for the fault to be benign, __do_page_fault() would check
	 * vma->vm_flags & vm_flags and returns an error if the
	 * intersection is empty
	 */
	if (is_el0_instruction_abort(esr)) {
		/* It was exec fault */
		vm_flags = VM_EXEC;
		mm_flags |= FAULT_FLAG_INSTRUCTION;
	} else if (is_write_abort(esr)) {
		/* It was write fault */
		vm_flags = VM_WRITE;
		mm_flags |= FAULT_FLAG_WRITE;
	} else {
		/* It was read fault */
		vm_flags = VM_READ;
		/* Write implies read */
		vm_flags |= VM_WRITE;
		/* If EPAN is absent then exec implies read */
		if (!cpus_have_const_cap(ARM64_HAS_EPAN))
			vm_flags |= VM_EXEC;
	}

	if (is_ttbr0_addr(addr) && is_el1_permission_fault(addr, esr, regs)) {
		if (is_el1_instruction_abort(esr))
			die_kernel_fault("execution of user memory",
					 addr, esr, regs);

		if (!search_exception_tables(regs->pc))
			die_kernel_fault("access to user memory outside uaccess routines",
					 addr, esr, regs);
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);

	/*
	 * As per x86, we may deadlock here. However, since the kernel only
	 * validly references user space from well defined areas of the code,
	 * we can bug out early if this is from code which shouldn't.
	 */
	if (!mmap_read_trylock(mm)) {
		if (!user_mode(regs) && !search_exception_tables(regs->pc))
			goto no_context;
retry:
		mmap_read_lock(mm);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in which
		 * case, we'll have missed the might_sleep() from down_read().
		 */
		might_sleep();
#ifdef CONFIG_DEBUG_VM
		if (!user_mode(regs) && !search_exception_tables(regs->pc)) {
			mmap_read_unlock(mm);
			goto no_context;
		}
#endif
	}

	fault = __do_page_fault(mm, addr, mm_flags, vm_flags, regs);

	/* Quick path to respond to signals */
	if (fault_signal_pending(fault, regs)) {
		if (!user_mode(regs))
			goto no_context;
		return 0;
	}

	if (fault & VM_FAULT_RETRY) {
		if (mm_flags & FAULT_FLAG_ALLOW_RETRY) {
			mm_flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}
	mmap_read_unlock(mm);

	/*
	 * Handle the "normal" (no error) case first.
	 */
	if (likely(!(fault & (VM_FAULT_ERROR | VM_FAULT_BADMAP |
			      VM_FAULT_BADACCESS))))
		return 0;

	/*
	 * If we are in kernel mode at this point, we have no context to
	 * handle this fault with.
	 */
	if (!user_mode(regs))
		goto no_context;

	if (fault & VM_FAULT_OOM) {
		/*
		 * We ran out of memory, call the OOM killer, and return to
		 * userspace (which will retry the fault, or kill us if we got
		 * oom-killed).
		 */
		pagefault_out_of_memory();
		return 0;
	}

	inf = esr_to_fault_info(esr);
	set_thread_esr(addr, esr);
	if (fault & VM_FAULT_SIGBUS) {
		/*
		 * We had some memory, but were unable to successfully fix up
		 * this page fault.
		 */
		arm64_force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)addr,
				      inf->name);
	} else if (fault & (VM_FAULT_HWPOISON_LARGE | VM_FAULT_HWPOISON)) {
		unsigned int lsb;

		lsb = PAGE_SHIFT;
		if (fault & VM_FAULT_HWPOISON_LARGE)
			lsb = hstate_index_to_shift(VM_FAULT_GET_HINDEX(fault));

		arm64_force_sig_mceerr(BUS_MCEERR_AR, (void __user *)addr, lsb,
				       inf->name);
	} else {
		/*
		 * Something tried to access memory that isn't in our memory
		 * map.
		 */
		arm64_force_sig_fault(SIGSEGV,
				      fault == VM_FAULT_BADACCESS ? SEGV_ACCERR : SEGV_MAPERR,
				      (void __user *)addr,
				      inf->name);
	}

	return 0;

no_context:
	__do_kernel_fault(addr, esr, regs);
	return 0;
}

static int __kprobes do_translation_fault(unsigned long addr,
					  unsigned int esr,
					  struct pt_regs *regs)
{
	if (is_ttbr0_addr(addr))
		return do_page_fault(addr, esr, regs);

	do_bad_area(addr, esr, regs);
	return 0;
}

static int do_alignment_fault(unsigned long addr, unsigned int esr,
			      struct pt_regs *regs)
{
	do_bad_area(addr, esr, regs);
	return 0;
}

static int do_bad(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	return 1; /* "fault" */
}

static bool arm64_do_kernel_sea(void __user *addr, unsigned int esr,
				struct pt_regs *regs, int sig, int code)
{
	u64 orig_pc = regs->pc;
	int err;

	if (!IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC))
		return false;

	if (!sysctl_machine_check_safe)
		return false;

	if (user_mode(regs))
		return false;

	if (!fixup_exception_mc(regs))
		return false;

	err = apei_claim_sea(regs);
	if (err)
		pr_emerg(
			"comm: %s pid: %d apei claim sea failed. addr: %#lx, esr: %#x\n",
			current->comm, current->pid, (unsigned long)addr, esr);

	if (!current->mm) {
		if (err) {
			regs->pc = orig_pc;
			return false;
		}

		return true;
	}

	set_thread_esr(0, esr);
	arm64_force_sig_fault(sig, code, addr,
		"Uncorrected memory error on access to user memory\n");

	return true;
}

static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	const struct fault_info *inf;
	void __user *siaddr;

	inf = esr_to_fault_info(esr);

	if (user_mode(regs) && apei_claim_sea(regs) == 0) {
		/*
		 * APEI claimed this as a firmware-first notification.
		 * Some processing deferred to task_work before ret_to_user().
		 */
		return 0;
	}

	if (esr & ESR_ELx_FnV)
		siaddr = NULL;
	else
		siaddr  = (void __user *)addr;

	if (!arm64_do_kernel_sea(siaddr, esr, regs, inf->sig, inf->code))
		arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, esr);

	return 0;
}

static int do_tag_check_fault(unsigned long addr, unsigned int esr,
			      struct pt_regs *regs)
{
	do_bad_area(addr, esr, regs);
	return 0;
}

static const struct fault_info fault_info[] = {
	{ do_bad,		SIGKILL, SI_KERNEL,	"ttbr address size fault"	},
	{ do_bad,		SIGKILL, SI_KERNEL,	"level 1 address size fault"	},
	{ do_bad,		SIGKILL, SI_KERNEL,	"level 2 address size fault"	},
	{ do_bad,		SIGKILL, SI_KERNEL,	"level 3 address size fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 0 translation fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 1 translation fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 2 translation fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 3 translation fault"	},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 8"			},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 1 access flag fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 2 access flag fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 3 access flag fault"	},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 12"			},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 1 permission fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 2 permission fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 3 permission fault"	},
	{ do_sea,		SIGBUS,  BUS_OBJERR,	"synchronous external abort"	},
	{ do_tag_check_fault,	SIGSEGV, SEGV_MTESERR,	"synchronous tag check fault"	},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 18"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 19"			},
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 0 (translation table walk)"	},
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 1 (translation table walk)"	},
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 2 (translation table walk)"	},
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 3 (translation table walk)"	},
	{ do_sea,		SIGBUS,  BUS_OBJERR,	"synchronous parity or ECC error" },	// Reserved when RAS is implemented
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 25"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 26"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 27"			},
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 0 synchronous parity error (translation table walk)"	},	// Reserved when RAS is implemented
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 1 synchronous parity error (translation table walk)"	},	// Reserved when RAS is implemented
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 2 synchronous parity error (translation table walk)"	},	// Reserved when RAS is implemented
	{ do_sea,		SIGKILL, SI_KERNEL,	"level 3 synchronous parity error (translation table walk)"	},	// Reserved when RAS is implemented
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 32"			},
	{ do_alignment_fault,	SIGBUS,  BUS_ADRALN,	"alignment fault"		},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 34"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 35"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 36"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 37"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 38"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 39"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 40"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 41"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 42"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 43"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 44"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 45"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 46"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 47"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"TLB conflict abort"		},
	{ do_bad,		SIGKILL, SI_KERNEL,	"Unsupported atomic hardware update fault"	},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 50"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 51"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"implementation fault (lockdown abort)" },
	{ do_bad,		SIGBUS,  BUS_OBJERR,	"implementation fault (unsupported exclusive)" },
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 54"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 55"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 56"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 57"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 58" 			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 59"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 60"			},
	{ do_bad,		SIGKILL, SI_KERNEL,	"section domain fault"		},
	{ do_bad,		SIGKILL, SI_KERNEL,	"page domain fault"		},
	{ do_bad,		SIGKILL, SI_KERNEL,	"unknown 63"			},
};

void do_mem_abort(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	const struct fault_info *inf = esr_to_fault_info(esr);

	if (!inf->fn(addr, esr, regs))
		return;

	if (!user_mode(regs)) {
		pr_alert("Unhandled fault at 0x%016lx\n", addr);
		mem_abort_decode(esr);
		show_pte(addr);
	}

	arm64_notify_die(inf->name, regs,
			 inf->sig, inf->code, (void __user *)addr, esr);
}
NOKPROBE_SYMBOL(do_mem_abort);

void do_el0_irq_bp_hardening(void)
{
	/* PC has already been checked in entry.S */
	arm64_apply_bp_hardening();
}
NOKPROBE_SYMBOL(do_el0_irq_bp_hardening);

void do_sp_pc_abort(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	arm64_notify_die("SP/PC alignment exception", regs,
			 SIGBUS, BUS_ADRALN, (void __user *)addr, esr);
}
NOKPROBE_SYMBOL(do_sp_pc_abort);

int __init early_brk64(unsigned long addr, unsigned int esr,
		       struct pt_regs *regs);

/*
 * __refdata because early_brk64 is __init, but the reference to it is
 * clobbered at arch_initcall time.
 * See traps.c and debug-monitors.c:debug_traps_init().
 */
static struct fault_info __refdata debug_fault_info[] = {
	{ do_bad,	SIGTRAP,	TRAP_HWBKPT,	"hardware breakpoint"	},
	{ do_bad,	SIGTRAP,	TRAP_HWBKPT,	"hardware single-step"	},
	{ do_bad,	SIGTRAP,	TRAP_HWBKPT,	"hardware watchpoint"	},
	{ do_bad,	SIGKILL,	SI_KERNEL,	"unknown 3"		},
	{ do_bad,	SIGTRAP,	TRAP_BRKPT,	"aarch32 BKPT"		},
	{ do_bad,	SIGKILL,	SI_KERNEL,	"aarch32 vector catch"	},
	{ early_brk64,	SIGTRAP,	TRAP_BRKPT,	"aarch64 BRK"		},
	{ do_bad,	SIGKILL,	SI_KERNEL,	"unknown 7"		},
};

void __init hook_debug_fault_code(int nr,
				  int (*fn)(unsigned long, unsigned int, struct pt_regs *),
				  int sig, int code, const char *name)
{
	BUG_ON(nr < 0 || nr >= ARRAY_SIZE(debug_fault_info));

	debug_fault_info[nr].fn		= fn;
	debug_fault_info[nr].sig	= sig;
	debug_fault_info[nr].code	= code;
	debug_fault_info[nr].name	= name;
}

/*
 * In debug exception context, we explicitly disable preemption despite
 * having interrupts disabled.
 * This serves two purposes: it makes it much less likely that we would
 * accidentally schedule in exception context and it will force a warning
 * if we somehow manage to schedule by accident.
 */
static void debug_exception_enter(struct pt_regs *regs)
{
	preempt_disable();

	/* This code is a bit fragile.  Test it. */
	RCU_LOCKDEP_WARN(!rcu_is_watching(), "exception_enter didn't work");
}
NOKPROBE_SYMBOL(debug_exception_enter);

static void debug_exception_exit(struct pt_regs *regs)
{
	preempt_enable_no_resched();
}
NOKPROBE_SYMBOL(debug_exception_exit);

#ifdef CONFIG_ARM64_ERRATUM_1463225
DECLARE_PER_CPU(int, __in_cortex_a76_erratum_1463225_wa);

static int cortex_a76_erratum_1463225_debug_handler(struct pt_regs *regs)
{
	if (user_mode(regs))
		return 0;

	if (!__this_cpu_read(__in_cortex_a76_erratum_1463225_wa))
		return 0;

	/*
	 * We've taken a dummy step exception from the kernel to ensure
	 * that interrupts are re-enabled on the syscall path. Return back
	 * to cortex_a76_erratum_1463225_svc_handler() with debug exceptions
	 * masked so that we can safely restore the mdscr and get on with
	 * handling the syscall.
	 */
	regs->pstate |= PSR_D_BIT;
	return 1;
}
#else
static int cortex_a76_erratum_1463225_debug_handler(struct pt_regs *regs)
{
	return 0;
}
#endif /* CONFIG_ARM64_ERRATUM_1463225 */
NOKPROBE_SYMBOL(cortex_a76_erratum_1463225_debug_handler);

void do_debug_exception(unsigned long addr_if_watchpoint, unsigned int esr,
			struct pt_regs *regs)
{
	const struct fault_info *inf = esr_to_debug_fault_info(esr);
	unsigned long pc = instruction_pointer(regs);

	if (cortex_a76_erratum_1463225_debug_handler(regs))
		return;

	debug_exception_enter(regs);

	if (user_mode(regs) && !is_ttbr0_addr(pc))
		arm64_apply_bp_hardening();

	if (inf->fn(addr_if_watchpoint, esr, regs)) {
		arm64_notify_die(inf->name, regs,
				 inf->sig, inf->code, (void __user *)pc, esr);
	}

	debug_exception_exit(regs);
}
NOKPROBE_SYMBOL(do_debug_exception);
