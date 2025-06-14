/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Derived from arch/arm/include/asm/kvm_host.h:
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 */

#ifndef __ARM64_KVM_HOST_H__
#define __ARM64_KVM_HOST_H__

#include <linux/arm-smccc.h>
#include <linux/bitmap.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <linux/kvm_types.h>
#include <linux/percpu.h>
#include <asm/arch_gicv3.h>
#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/cputype.h>
#include <asm/daifflags.h>
#include <asm/fpsimd.h>
#include <asm/kvm.h>
#include <asm/kvm_asm.h>
#include <asm/thread_info.h>
#ifdef CONFIG_CVM_HOST
#include <asm/kvm_tmm.h>
#endif

#define __KVM_HAVE_ARCH_INTC_INITIALIZED

#define KVM_HALT_POLL_NS_DEFAULT 500000

#include <kvm/arm_vgic.h>
#include <kvm/arm_arch_timer.h>
#include <kvm/arm_pmu.h>

#define KVM_MAX_VCPUS VGIC_V3_MAX_CPUS

#define KVM_VCPU_MAX_FEATURES 7

#define KVM_REQ_SLEEP \
	KVM_ARCH_REQ_FLAGS(0, KVM_REQUEST_WAIT | KVM_REQUEST_NO_WAKEUP)
#define KVM_REQ_IRQ_PENDING	KVM_ARCH_REQ(1)
#define KVM_REQ_VCPU_RESET	KVM_ARCH_REQ(2)
#define KVM_REQ_RECORD_STEAL	KVM_ARCH_REQ(3)
#define KVM_REQ_RELOAD_GICv4	KVM_ARCH_REQ(4)
#define KVM_REQ_RELOAD_PMU	KVM_ARCH_REQ(5)
#define KVM_REQ_RELOAD_DVMBM	KVM_ARCH_REQ(6)
#define KVM_REQ_RELOAD_WFI_TRAPS	KVM_ARCH_REQ(7)

#define KVM_DIRTY_LOG_MANUAL_CAPS   (KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE | \
				     KVM_DIRTY_LOG_INITIALLY_SET)

DECLARE_STATIC_KEY_FALSE(userspace_irqchip_in_use);

extern unsigned int kvm_sve_max_vl;
int kvm_arm_init_sve(void);

int __attribute_const__ kvm_target_cpu(void);
int kvm_reset_vcpu(struct kvm_vcpu *vcpu);
void kvm_arm_vcpu_destroy(struct kvm_vcpu *vcpu);
int kvm_arch_vm_ioctl_check_extension(struct kvm *kvm, long ext);
void __extended_idmap_trampoline(phys_addr_t boot_pgd, phys_addr_t idmap_start);

struct kvm_vmid {
	/* The VMID generation used for the virt. memory system */
	u64    vmid_gen;
	u32    vmid;
};

struct kvm_s2_mmu {
	struct kvm_vmid vmid;

	/*
	 * stage2 entry level table
	 *
	 * Two kvm_s2_mmu structures in the same VM can point to the same
	 * pgd here.  This happens when running a guest using a
	 * translation regime that isn't affected by its own stage-2
	 * translation, such as a non-VHE hypervisor running at vEL2, or
	 * for vEL1/EL0 with vHCR_EL2.VM == 0.  In that case, we use the
	 * canonical stage-2 page tables.
	 */
	phys_addr_t	pgd_phys;
	struct kvm_pgtable *pgt;

	/* The last vcpu id that ran on each physical CPU */
	int __percpu *last_vcpu_ran;

	struct kvm *kvm;
};

struct kvm_arch {
	struct kvm_s2_mmu mmu;

	/* VTCR_EL2 value for this VM */
	u64    vtcr;

	/* The maximum number of vCPUs depends on the used GIC model */
	int max_vcpus;

	/* Interrupt controller */
	struct vgic_dist	vgic;

	/* Mandated version of PSCI */
	u32 psci_version;

	/*
	 * If we encounter a data abort without valid instruction syndrome
	 * information, report this to user space.  User space can (and
	 * should) opt in to this feature if KVM_CAP_ARM_NISV_TO_USER is
	 * supported.
	 */
	bool return_nisv_io_abort_to_user;

	/*
	 * VM-wide PMU filter, implemented as a bitmap and big enough for
	 * up to 2^10 events (ARMv8.0) or 2^16 events (ARMv8.1+).
	 */
	unsigned long *pmu_filter;
	unsigned int pmuver;

	u8 pfr0_csv2;

#ifdef CONFIG_KVM_HISI_VIRT
	spinlock_t dvm_lock;
#endif

#if defined(CONFIG_KVM_HISI_VIRT) || defined(CONFIG_CVM_HOST)
#ifndef __GENKSYMS__
	union {
		cpumask_t *dvm_cpumask; /* Union of all vcpu's cpus_ptr */
		void *cvm;
	};
#else
	cpumask_t *dvm_cpumask; /* Union of all vcpu's cpus_ptr */
#endif
#endif

#ifdef CONFIG_KVM_HISI_VIRT
	u64 lsudvmbm_el2;
#endif
};

struct kvm_vcpu_fault_info {
	u32 esr_el2;		/* Hyp Syndrom Register */
	u64 far_el2;		/* Hyp Fault Address Register */
	u64 hpfar_el2;		/* Hyp IPA Fault Address Register */
	u64 disr_el1;		/* Deferred [SError] Status Register */
};

enum vcpu_sysreg {
	__INVALID_SYSREG__,   /* 0 is reserved as an invalid value */
	MPIDR_EL1,	/* MultiProcessor Affinity Register */
	CSSELR_EL1,	/* Cache Size Selection Register */
	SCTLR_EL1,	/* System Control Register */
	ACTLR_EL1,	/* Auxiliary Control Register */
	CPACR_EL1,	/* Coprocessor Access Control */
	ZCR_EL1,	/* SVE Control */
	TTBR0_EL1,	/* Translation Table Base Register 0 */
	TTBR1_EL1,	/* Translation Table Base Register 1 */
	TCR_EL1,	/* Translation Control Register */
	ESR_EL1,	/* Exception Syndrome Register */
	AFSR0_EL1,	/* Auxiliary Fault Status Register 0 */
	AFSR1_EL1,	/* Auxiliary Fault Status Register 1 */
	FAR_EL1,	/* Fault Address Register */
	MAIR_EL1,	/* Memory Attribute Indirection Register */
	VBAR_EL1,	/* Vector Base Address Register */
	CONTEXTIDR_EL1,	/* Context ID Register */
	TPIDR_EL0,	/* Thread ID, User R/W */
	TPIDRRO_EL0,	/* Thread ID, User R/O */
	TPIDR_EL1,	/* Thread ID, Privileged */
	AMAIR_EL1,	/* Aux Memory Attribute Indirection Register */
	CNTKCTL_EL1,	/* Timer Control Register (EL1) */
	PAR_EL1,	/* Physical Address Register */
	MDSCR_EL1,	/* Monitor Debug System Control Register */
	MDCCINT_EL1,	/* Monitor Debug Comms Channel Interrupt Enable Reg */
	DISR_EL1,	/* Deferred Interrupt Status Register */

	/* Performance Monitors Registers */
	PMCR_EL0,	/* Control Register */
	PMSELR_EL0,	/* Event Counter Selection Register */
	PMEVCNTR0_EL0,	/* Event Counter Register (0-30) */
	PMEVCNTR30_EL0 = PMEVCNTR0_EL0 + 30,
	PMCCNTR_EL0,	/* Cycle Counter Register */
	PMEVTYPER0_EL0,	/* Event Type Register (0-30) */
	PMEVTYPER30_EL0 = PMEVTYPER0_EL0 + 30,
	PMCCFILTR_EL0,	/* Cycle Count Filter Register */
	PMCNTENSET_EL0,	/* Count Enable Set Register */
	PMINTENSET_EL1,	/* Interrupt Enable Set Register */
	PMOVSSET_EL0,	/* Overflow Flag Status Set Register */
	PMSWINC_EL0,	/* Software Increment Register */
	PMUSERENR_EL0,	/* User Enable Register */

	/* Pointer Authentication Registers in a strict increasing order. */
	APIAKEYLO_EL1,
	APIAKEYHI_EL1,
	APIBKEYLO_EL1,
	APIBKEYHI_EL1,
	APDAKEYLO_EL1,
	APDAKEYHI_EL1,
	APDBKEYLO_EL1,
	APDBKEYHI_EL1,
	APGAKEYLO_EL1,
	APGAKEYHI_EL1,

	ELR_EL1,
	SP_EL1,
	SPSR_EL1,

	CNTVOFF_EL2,
	CNTV_CVAL_EL0,
	CNTV_CTL_EL0,
	CNTP_CVAL_EL0,
	CNTP_CTL_EL0,

	/* 32bit specific registers. Keep them at the end of the range */
	DACR32_EL2,	/* Domain Access Control Register */
	IFSR32_EL2,	/* Instruction Fault Status Register */
	FPEXC32_EL2,	/* Floating-Point Exception Control Register */
	DBGVCR32_EL2,	/* Debug Vector Catch Register */

	NR_SYS_REGS	/* Nothing after this line! */
};

/* 32bit mapping */
#define c0_MPIDR	(MPIDR_EL1 * 2)	/* MultiProcessor ID Register */
#define c0_CSSELR	(CSSELR_EL1 * 2)/* Cache Size Selection Register */
#define c1_SCTLR	(SCTLR_EL1 * 2)	/* System Control Register */
#define c1_ACTLR	(ACTLR_EL1 * 2)	/* Auxiliary Control Register */
#define c1_CPACR	(CPACR_EL1 * 2)	/* Coprocessor Access Control */
#define c2_TTBR0	(TTBR0_EL1 * 2)	/* Translation Table Base Register 0 */
#define c2_TTBR0_high	(c2_TTBR0 + 1)	/* TTBR0 top 32 bits */
#define c2_TTBR1	(TTBR1_EL1 * 2)	/* Translation Table Base Register 1 */
#define c2_TTBR1_high	(c2_TTBR1 + 1)	/* TTBR1 top 32 bits */
#define c2_TTBCR	(TCR_EL1 * 2)	/* Translation Table Base Control R. */
#define c2_TTBCR2	(c2_TTBCR + 1)	/* Translation Table Base Control R. 2 */
#define c3_DACR		(DACR32_EL2 * 2)/* Domain Access Control Register */
#define c5_DFSR		(ESR_EL1 * 2)	/* Data Fault Status Register */
#define c5_IFSR		(IFSR32_EL2 * 2)/* Instruction Fault Status Register */
#define c5_ADFSR	(AFSR0_EL1 * 2)	/* Auxiliary Data Fault Status R */
#define c5_AIFSR	(AFSR1_EL1 * 2)	/* Auxiliary Instr Fault Status R */
#define c6_DFAR		(FAR_EL1 * 2)	/* Data Fault Address Register */
#define c6_IFAR		(c6_DFAR + 1)	/* Instruction Fault Address Register */
#define c7_PAR		(PAR_EL1 * 2)	/* Physical Address Register */
#define c7_PAR_high	(c7_PAR + 1)	/* PAR top 32 bits */
#define c10_PRRR	(MAIR_EL1 * 2)	/* Primary Region Remap Register */
#define c10_NMRR	(c10_PRRR + 1)	/* Normal Memory Remap Register */
#define c12_VBAR	(VBAR_EL1 * 2)	/* Vector Base Address Register */
#define c13_CID		(CONTEXTIDR_EL1 * 2)	/* Context ID Register */
#define c13_TID_URW	(TPIDR_EL0 * 2)	/* Thread ID, User R/W */
#define c13_TID_URO	(TPIDRRO_EL0 * 2)/* Thread ID, User R/O */
#define c13_TID_PRIV	(TPIDR_EL1 * 2)	/* Thread ID, Privileged */
#define c10_AMAIR0	(AMAIR_EL1 * 2)	/* Aux Memory Attr Indirection Reg */
#define c10_AMAIR1	(c10_AMAIR0 + 1)/* Aux Memory Attr Indirection Reg */
#define c14_CNTKCTL	(CNTKCTL_EL1 * 2) /* Timer Control Register (PL1) */

#define cp14_DBGDSCRext	(MDSCR_EL1 * 2)
#define cp14_DBGBCR0	(DBGBCR0_EL1 * 2)
#define cp14_DBGBVR0	(DBGBVR0_EL1 * 2)
#define cp14_DBGBXVR0	(cp14_DBGBVR0 + 1)
#define cp14_DBGWCR0	(DBGWCR0_EL1 * 2)
#define cp14_DBGWVR0	(DBGWVR0_EL1 * 2)
#define cp14_DBGDCCINT	(MDCCINT_EL1 * 2)
#define cp14_DBGVCR	(DBGVCR32_EL2 * 2)

#define NR_COPRO_REGS	(NR_SYS_REGS * 2)

struct kvm_cpu_context {
	struct user_pt_regs regs;	/* sp = sp_el0 */

	u64	spsr_abt;
	u64	spsr_und;
	u64	spsr_irq;
	u64	spsr_fiq;

	struct user_fpsimd_state fp_regs;

	union {
		u64 sys_regs[NR_SYS_REGS];
		u32 copro[NR_COPRO_REGS];
	};

	struct kvm_vcpu *__hyp_running_vcpu;
};

struct kvm_pmu_events {
	u32 events_host;
	u32 events_guest;
};

struct kvm_host_data {
	struct kvm_cpu_context host_ctxt;
	struct kvm_pmu_events pmu_events;
};

struct vcpu_reset_state {
	unsigned long	pc;
	unsigned long	r0;
	bool		be;
	bool		reset;
};

struct kvm_vcpu_arch {
	struct kvm_cpu_context ctxt;

	/* Guest floating point state */
	void *sve_state;
	unsigned int sve_max_vl;
	u64 svcr;

	/* Stage 2 paging state used by the hardware on next switch */
	struct kvm_s2_mmu *hw_mmu;

	/* HYP configuration */
	u64 hcr_el2;
	u32 mdcr_el2;

	/* Exception Information */
	struct kvm_vcpu_fault_info fault;

	/* State of various workarounds, see kvm_asm.h for bit assignment */
	u64 workaround_flags;

	/* Miscellaneous vcpu state flags */
	u64 flags;

	/*
	 * We maintain more than a single set of debug registers to support
	 * debugging the guest from the host and to maintain separate host and
	 * guest state during world switches. vcpu_debug_state are the debug
	 * registers of the vcpu as the guest sees them.  host_debug_state are
	 * the host registers which are saved and restored during
	 * world switches. external_debug_state contains the debug
	 * values we want to debug the guest. This is set via the
	 * KVM_SET_GUEST_DEBUG ioctl.
	 *
	 * debug_ptr points to the set of debug registers that should be loaded
	 * onto the hardware when running the guest.
	 */
	struct kvm_guest_debug_arch *debug_ptr;
	struct kvm_guest_debug_arch vcpu_debug_state;
	struct kvm_guest_debug_arch external_debug_state;

	struct thread_info *host_thread_info;	/* hyp VA */
	struct user_fpsimd_state *host_fpsimd_state;	/* hyp VA */

	struct {
		/* {Break,watch}point registers */
		struct kvm_guest_debug_arch regs;
		/* Statistical profiling extension */
		u64 pmscr_el1;
	} host_debug_state;

	/* VGIC state */
	struct vgic_cpu vgic_cpu;
	struct arch_timer_cpu timer_cpu;
	struct kvm_pmu pmu;

	/*
	 * Anything that is not used directly from assembly code goes
	 * here.
	 */

	/*
	 * Guest registers we preserve during guest debugging.
	 *
	 * These shadow registers are updated by the kvm_handle_sys_reg
	 * trap handler if the guest accesses or updates them while we
	 * are using guest debug.
	 */
	struct {
		u32	mdscr_el1;
	} guest_debug_preserved;

	/* vcpu power-off state */
	bool power_off;

	/* Don't run the guest (internal implementation need) */
	bool pause;

	/* Cache some mmu pages needed inside spinlock regions */
	struct kvm_mmu_memory_cache mmu_page_cache;

	/* Target CPU and feature flags */
	int target;
	DECLARE_BITMAP(features, KVM_VCPU_MAX_FEATURES);

	/* Detect first run of a vcpu */
	bool has_run_once;

	/* Virtual SError ESR to restore when HCR_EL2.VSE is set */
	u64 vsesr_el2;

	/* Additional reset state */
	struct vcpu_reset_state	reset_state;

	/* True when deferrable sysregs are loaded on the physical CPU,
	 * see kvm_vcpu_load_sysregs_vhe and kvm_vcpu_put_sysregs_vhe. */
	bool sysregs_loaded_on_cpu;

	/* Guest PV state */
	struct {
		u64 last_steal;
		gpa_t base;
	} steal;

	/* Guest PV sched state */
	struct {
		bool pv_unhalted;
		bool preempted;
		gpa_t base;
	} pvsched;

	struct id_registers idregs;

#ifdef CONFIG_KVM_HISI_VIRT
	/* Copy of current->cpus_ptr */
	cpumask_t *cpus_ptr;
#endif

#if defined(CONFIG_KVM_HISI_VIRT) || defined(CONFIG_CVM_HOST)
#ifndef __GENKSYMS__
	union {
		cpumask_t *pre_cpus_ptr;
		void *tec;
	};
#else
	cpumask_t *pre_cpus_ptr;
#endif
#endif
};

/* Pointer to the vcpu's SVE FFR for sve_{save,load}_state() */
#define vcpu_sve_pffr(vcpu) (kern_hyp_va((vcpu)->arch.sve_state) +	\
			     sve_ffr_offset((vcpu)->arch.sve_max_vl))

#define vcpu_sve_max_vq(vcpu)	sve_vq_from_vl((vcpu)->arch.sve_max_vl)

#define vcpu_sve_state_size(vcpu) ({					\
	size_t __size_ret;						\
	unsigned int __vcpu_vq;						\
									\
	if (WARN_ON(!sve_vl_valid((vcpu)->arch.sve_max_vl))) {		\
		__size_ret = 0;						\
	} else {							\
		__vcpu_vq = vcpu_sve_max_vq(vcpu);			\
		__size_ret = SVE_SIG_REGS_SIZE(__vcpu_vq);		\
	}								\
									\
	__size_ret;							\
})

/* vcpu_arch flags field values: */
#define KVM_ARM64_DEBUG_DIRTY		(1 << 0)
#define KVM_ARM64_FP_ENABLED		(1 << 1) /* guest FP regs loaded */
#define KVM_ARM64_FP_HOST		(1 << 2) /* host FP regs loaded */
#define KVM_ARM64_HOST_SVE_IN_USE	(1 << 3) /* backup for host TIF_SVE */
#define KVM_ARM64_HOST_SVE_ENABLED	(1 << 4) /* SVE enabled for EL0 */
#define KVM_ARM64_GUEST_HAS_SVE		(1 << 5) /* SVE exposed to guest */
#define KVM_ARM64_VCPU_SVE_FINALIZED	(1 << 6) /* SVE config completed */
#define KVM_ARM64_GUEST_HAS_PTRAUTH	(1 << 7) /* PTRAUTH exposed to guest */
#define KVM_ARM64_HOST_SME_ENABLED	(1 << 16) /* SME enabled for EL0 */
#define KVM_ARM64_WFIT			(1 << 17) /* WFIT instruction trapped */

#define vcpu_has_sve(vcpu) (system_supports_sve() && \
			    ((vcpu)->arch.flags & KVM_ARM64_GUEST_HAS_SVE))

#ifdef CONFIG_ARM64_PTR_AUTH
#define vcpu_has_ptrauth(vcpu)						\
	((cpus_have_final_cap(ARM64_HAS_ADDRESS_AUTH) ||		\
	  cpus_have_final_cap(ARM64_HAS_GENERIC_AUTH)) &&		\
	 (vcpu)->arch.flags & KVM_ARM64_GUEST_HAS_PTRAUTH)
#else
#define vcpu_has_ptrauth(vcpu)		false
#endif

#define vcpu_gp_regs(v)		(&(v)->arch.ctxt.regs)

/*
 * Only use __vcpu_sys_reg/ctxt_sys_reg if you know you want the
 * memory backed version of a register, and not the one most recently
 * accessed by a running VCPU.  For example, for userspace access or
 * for system registers that are never context switched, but only
 * emulated.
 */
#define __ctxt_sys_reg(c,r)	(&(c)->sys_regs[(r)])

#define ctxt_sys_reg(c,r)	(*__ctxt_sys_reg(c,r))

#define __vcpu_sys_reg(v,r)	(ctxt_sys_reg(&(v)->arch.ctxt, (r)))

u64 vcpu_read_sys_reg(const struct kvm_vcpu *vcpu, int reg);
void vcpu_write_sys_reg(struct kvm_vcpu *vcpu, u64 val, int reg);

/*
 * CP14 and CP15 live in the same array, as they are backed by the
 * same system registers.
 */
#define CPx_BIAS		IS_ENABLED(CONFIG_CPU_BIG_ENDIAN)

#define vcpu_cp14(v,r)		((v)->arch.ctxt.copro[(r) ^ CPx_BIAS])
#define vcpu_cp15(v,r)		((v)->arch.ctxt.copro[(r) ^ CPx_BIAS])

struct kvm_vm_stat {
	ulong remote_tlb_flush;
};

struct kvm_vcpu_stat {
	u64 pid;
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
	u64 hvc_exit_stat;
	u64 wfe_exit_stat;
	u64 wfi_exit_stat;
	u64 mmio_exit_user;
	u64 mmio_exit_kernel;
	u64 signal_exits;
	u64 exits;
	u64 fp_asimd_exit_stat;
	u64 irq_exit_stat;
	u64 sys64_exit_stat;
	u64 mabt_exit_stat;
	u64 fail_entry_exit_stat;
	u64 internal_error_exit_stat;
	u64 unknown_ec_exit_stat;
	u64 cp15_32_exit_stat;
	u64 cp15_64_exit_stat;
	u64 cp14_mr_exit_stat;
	u64 cp14_ls_exit_stat;
	u64 cp14_64_exit_stat;
	u64 smc_exit_stat;
	u64 sve_exit_stat;
	u64 debug_exit_stat;
	u64 steal;
	u64 st_max;
	u64 utime;
	u64 stime;
	u64 gtime;
};

int kvm_vcpu_preferred_target(struct kvm_vcpu_init *init);
unsigned long kvm_arm_num_regs(struct kvm_vcpu *vcpu);
int kvm_arm_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *indices);
int kvm_arm_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);
int kvm_arm_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg);
int __kvm_arm_vcpu_get_events(struct kvm_vcpu *vcpu,
			      struct kvm_vcpu_events *events);

int __kvm_arm_vcpu_set_events(struct kvm_vcpu *vcpu,
			      struct kvm_vcpu_events *events);

#define KVM_ARCH_WANT_MMU_NOTIFIER
#define KVM_ARCH_WANT_NEW_MMU_NOTIFIER_APIS

void kvm_arm_halt_guest(struct kvm *kvm);
void kvm_arm_resume_guest(struct kvm *kvm);

#define kvm_call_hyp_nvhe(f, ...)						\
	({								\
		struct arm_smccc_res res;				\
									\
		arm_smccc_1_1_hvc(KVM_HOST_SMCCC_FUNC(f),		\
				  ##__VA_ARGS__, &res);			\
		WARN_ON(res.a0 != SMCCC_RET_SUCCESS);			\
									\
		res.a1;							\
	})

/*
 * The couple of isb() below are there to guarantee the same behaviour
 * on VHE as on !VHE, where the eret to EL1 acts as a context
 * synchronization event.
 */
#define kvm_call_hyp(f, ...)						\
	do {								\
		if (has_vhe()) {					\
			f(__VA_ARGS__);					\
			isb();						\
		} else {						\
			kvm_call_hyp_nvhe(f, ##__VA_ARGS__);		\
		}							\
	} while(0)

#define kvm_call_hyp_ret(f, ...)					\
	({								\
		typeof(f(__VA_ARGS__)) ret;				\
									\
		if (has_vhe()) {					\
			ret = f(__VA_ARGS__);				\
			isb();						\
		} else {						\
			ret = kvm_call_hyp_nvhe(f, ##__VA_ARGS__);	\
		}							\
									\
		ret;							\
	})

void force_vm_exit(const cpumask_t *mask);
void kvm_mmu_wp_memory_region(struct kvm *kvm, int slot);

int handle_exit(struct kvm_vcpu *vcpu, int exception_index);
void handle_exit_early(struct kvm_vcpu *vcpu, int exception_index);

/* MMIO helpers */
void kvm_mmio_write_buf(void *buf, unsigned int len, unsigned long data);
unsigned long kvm_mmio_read_buf(const void *buf, unsigned int len);

int kvm_handle_mmio_return(struct kvm_vcpu *vcpu);
int io_mem_abort(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa);

int kvm_perf_init(void);
int kvm_perf_teardown(void);

long kvm_hypercall_pv_features(struct kvm_vcpu *vcpu);
gpa_t kvm_init_stolen_time(struct kvm_vcpu *vcpu);
void kvm_update_stolen_time(struct kvm_vcpu *vcpu);

bool kvm_arm_pvtime_supported(void);
int kvm_arm_pvtime_set_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);
int kvm_arm_pvtime_get_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);
int kvm_arm_pvtime_has_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);

static inline void kvm_arm_pvtime_vcpu_init(struct kvm_vcpu_arch *vcpu_arch)
{
	vcpu_arch->steal.base = GPA_INVALID;
}

static inline bool kvm_arm_is_pvtime_enabled(struct kvm_vcpu_arch *vcpu_arch)
{
	return (vcpu_arch->steal.base != GPA_INVALID);
}

long kvm_hypercall_pvsched_features(struct kvm_vcpu *vcpu);
void kvm_update_pvsched_preempted(struct kvm_vcpu *vcpu, u32 preempted);
long kvm_pvsched_kick_vcpu(struct kvm_vcpu *vcpu);

extern bool pv_preempted_enable;
static inline void kvm_arm_pvsched_vcpu_init(struct kvm_vcpu_arch *vcpu_arch)
{
	vcpu_arch->pvsched.base = GPA_INVALID;
	vcpu_arch->pvsched.preempted = false;
}

static inline bool kvm_arm_is_pvsched_valid(struct kvm_vcpu_arch *vcpu_arch)
{
	return (vcpu_arch->pvsched.base != GPA_INVALID);
}

void kvm_set_sei_esr(struct kvm_vcpu *vcpu, u64 syndrome);

struct kvm_vcpu *kvm_mpidr_to_vcpu(struct kvm *kvm, unsigned long mpidr);

DECLARE_KVM_HYP_PER_CPU(struct kvm_host_data, kvm_host_data);

static inline void kvm_init_host_cpu_context(struct kvm_cpu_context *cpu_ctxt)
{
	/* The host's MPIDR is immutable, so let's set it up at boot time */
	ctxt_sys_reg(cpu_ctxt, MPIDR_EL1) = read_cpuid_mpidr();
}

static inline bool kvm_arch_requires_vhe(void)
{
	/*
	 * The Arm architecture specifies that implementation of SVE
	 * requires VHE also to be implemented.  The KVM code for arm64
	 * relies on this when SVE is present:
	 */
	if (system_supports_sve())
		return true;

	return false;
}

void kvm_arm_vcpu_ptrauth_trap(struct kvm_vcpu *vcpu);

static inline void kvm_arch_hardware_unsetup(void) {}
static inline void kvm_arch_sync_events(struct kvm *kvm) {}
static inline void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu) {}
static inline void kvm_arch_vcpu_block_finish(struct kvm_vcpu *vcpu) {}

void kvm_arm_init_debug(void);
void kvm_arm_vcpu_init_debug(struct kvm_vcpu *vcpu);
void kvm_arm_setup_debug(struct kvm_vcpu *vcpu);
void kvm_arm_clear_debug(struct kvm_vcpu *vcpu);
void kvm_arm_reset_debug_ptr(struct kvm_vcpu *vcpu);
int kvm_arm_vcpu_arch_set_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr);
int kvm_arm_vcpu_arch_get_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr);
int kvm_arm_vcpu_arch_has_attr(struct kvm_vcpu *vcpu,
			       struct kvm_device_attr *attr);

/* Guest/host FPSIMD coordination helpers */
int kvm_arch_vcpu_run_map_fp(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_load_fp(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_ctxsync_fp(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_put_fp(struct kvm_vcpu *vcpu);

static inline bool kvm_pmu_counter_deferred(struct perf_event_attr *attr)
{
	return (!has_vhe() && attr->exclude_host);
}

#ifdef CONFIG_KVM /* Avoid conflicts with core headers if CONFIG_KVM=n */
static inline int kvm_arch_vcpu_run_pid_change(struct kvm_vcpu *vcpu)
{
	return kvm_arch_vcpu_run_map_fp(vcpu);
}

void kvm_set_pmu_events(u32 set, struct perf_event_attr *attr);
void kvm_clr_pmu_events(u32 clr);

void kvm_vcpu_pmu_restore_guest(struct kvm_vcpu *vcpu);
void kvm_vcpu_pmu_restore_host(struct kvm_vcpu *vcpu);
#else
static inline void kvm_set_pmu_events(u32 set, struct perf_event_attr *attr) {}
static inline void kvm_clr_pmu_events(u32 clr) {}
#endif

void kvm_vcpu_load_sysregs_vhe(struct kvm_vcpu *vcpu);
void kvm_vcpu_put_sysregs_vhe(struct kvm_vcpu *vcpu);

int kvm_set_ipa_limit(void);

#define __KVM_HAVE_ARCH_VM_ALLOC
struct kvm *kvm_arch_alloc_vm(void);
void kvm_arch_free_vm(struct kvm *kvm);

int kvm_arm_setup_stage2(struct kvm *kvm, unsigned long type);

int kvm_arm_vcpu_finalize(struct kvm_vcpu *vcpu, int feature);
bool kvm_arm_vcpu_is_finalized(struct kvm_vcpu *vcpu);

#define kvm_arm_vcpu_sve_finalized(vcpu) \
	((vcpu)->arch.flags & KVM_ARM64_VCPU_SVE_FINALIZED)

#define kvm_vcpu_has_pmu(vcpu) \
	(test_bit(KVM_ARM_VCPU_PMU_V3, (vcpu)->arch.features))

int kvm_trng_call(struct kvm_vcpu *vcpu);

#ifdef CONFIG_ARM64_TWED
#define use_twed() (has_twed() && twed_enable)
extern bool twed_enable;
extern unsigned int twedel;
#else
#define use_twed() (false)
#endif

extern bool force_wfi_trap;
extern bool kvm_ncsnp_support;
extern bool kvm_dvmbm_support;

#endif /* __ARM64_KVM_HOST_H__ */
