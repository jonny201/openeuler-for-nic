// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 */

#include <linux/bug.h>
#include <linux/cpu_pm.h>
#include <linux/entry-kvm.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/kvm.h>
#include <linux/kvm_irqfd.h>
#include <linux/irqbypass.h>
#include <linux/sched/stat.h>
#include <trace/events/kvm.h>

#define CREATE_TRACE_POINTS
#include "trace_arm.h"

#include <linux/uaccess.h>
#include <asm/ptrace.h>
#include <asm/mman.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/virt.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_coproc.h>
#include <asm/sections.h>
#ifdef CONFIG_CVM_HOST
#include <asm/kvm_tmi.h>
#include <linux/perf/arm_pmu.h>
#endif

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_pmu.h>
#include <kvm/arm_psci.h>

#ifdef REQUIRES_VIRT
__asm__(".arch_extension	virt");
#endif

#ifdef CONFIG_KVM_HISI_VIRT
#include "hisilicon/hisi_virt.h"
#endif

DECLARE_KVM_HYP_PER_CPU(unsigned long, kvm_hyp_vector);

static DEFINE_PER_CPU(unsigned long, kvm_arm_hyp_stack_page);
unsigned long kvm_arm_hyp_percpu_base[NR_CPUS];

/* The VMID used in the VTTBR */
static atomic64_t kvm_vmid_gen = ATOMIC64_INIT(1);
static u32 kvm_next_vmid;
static DEFINE_SPINLOCK(kvm_vmid_lock);

static bool vgic_present;

/* Capability of non-cacheable snooping */
bool kvm_ncsnp_support;

/* Capability of DVMBM */
bool kvm_dvmbm_support;

static DEFINE_PER_CPU(unsigned char, kvm_arm_hardware_enabled);
DEFINE_STATIC_KEY_FALSE(userspace_irqchip_in_use);

#ifdef CONFIG_ARM64_TWED
bool twed_enable = false;
module_param(twed_enable, bool, S_IRUGO | S_IWUSR);

unsigned int twedel = 0;
module_param(twedel, uint, S_IRUGO | S_IWUSR);
#endif

static const struct kernel_param_ops pv_preempted_enable_ops = {
	.set = param_set_bool,
	.get = param_get_bool,
};

bool pv_preempted_enable = true;
MODULE_PARM_DESC(pv_preempted_enable, "bool");
module_param_cb(pv_preempted_enable, &pv_preempted_enable_ops, &pv_preempted_enable, 0644);

static int vcpu_req_reload_wfi_traps(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops force_wfi_trap_ops = {
	.set = vcpu_req_reload_wfi_traps,
	.get = param_get_bool,
};

bool force_wfi_trap;
module_param_cb(force_wfi_trap, &force_wfi_trap_ops, &force_wfi_trap, 0644);

static int vcpu_req_reload_wfi_traps(const char *val, const struct kernel_param *kp)
{
	struct kvm *kvm;
	bool oldvalue;
	int err;

	oldvalue = force_wfi_trap;
	err = param_set_bool(val, kp);
	if (err)
		return err;

	if (oldvalue == force_wfi_trap)
		return err;

	/*
	 * If set the force_wfi_trap from 1 to 0, no need to kick vcpus here.
	 * The HCR_TWI flag will be cleared in kvm_arch_vcpu_load().
	 */
	if (force_wfi_trap == 0)
		return 0;

	/*
	 * We need to kick vcpus out of guest mode here to reload
	 * wfx trapping config when re-enter guest mode.
	 */
	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		kvm_make_all_cpus_request(kvm, KVM_REQ_RELOAD_WFI_TRAPS);
	mutex_unlock(&kvm_lock);
	return err;
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}

int kvm_arch_hardware_setup(void *opaque)
{
	return 0;
}

int kvm_arch_check_processor_compat(void *opaque)
{
	return 0;
}

int kvm_vm_ioctl_enable_cap(struct kvm *kvm,
			    struct kvm_enable_cap *cap)
{
	int r;

	if (cap->flags)
		return -EINVAL;

	switch (cap->cap) {
	case KVM_CAP_ARM_NISV_TO_USER:
		r = 0;
		kvm->arch.return_nisv_io_abort_to_user = true;
		break;
#ifdef CONFIG_CVM_HOST
	case KVM_CAP_ARM_TMM:
		if (static_branch_unlikely(&kvm_cvm_is_available))
			r = kvm_cvm_enable_cap(kvm, cap);
		break;
#endif
	default:
		r = -EINVAL;
		break;
	}

	return r;
}

static int kvm_arm_default_max_vcpus(void)
{
	return vgic_present ? kvm_vgic_get_max_vcpus() : KVM_MAX_VCPUS;
}

static void set_default_csv2(struct kvm *kvm)
{
	/*
	 * The default is to expose CSV2 == 1 if the HW isn't affected.
	 * Although this is a per-CPU feature, we make it global because
	 * asymmetric systems are just a nuisance.
	 *
	 * Userspace can override this as long as it doesn't promise
	 * the impossible.
	 */
	if (arm64_get_spectre_v2_state() == SPECTRE_UNAFFECTED)
		kvm->arch.pfr0_csv2 = 1;
}

/**
 * kvm_arch_init_vm - initializes a VM data structure
 * @kvm:	pointer to the KVM struct
 */
int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	int ret;

#ifdef CONFIG_KVM_HISI_VIRT
	ret = kvm_hisi_init_dvmbm(kvm);
	if (ret)
		return ret;
#endif

#ifdef CONFIG_CVM_HOST
	if (kvm_arm_cvm_type(type)) {
		ret = kvm_create_cvm_vm(kvm);
		if (ret)
			return ret;
	}
#endif

	ret = kvm_arm_setup_stage2(kvm, type);
	if (ret)
#ifdef CONFIG_CVM_HOST
		goto out_free_cvm;
#else
		return ret;
#endif

	ret = kvm_init_stage2_mmu(kvm, &kvm->arch.mmu);
	if (ret)
#ifdef CONFIG_CVM_HOST
		goto out_free_cvm;
#else
		return ret;
#endif
	ret = create_hyp_mappings(kvm, kvm + 1, PAGE_HYP);
	if (ret)
		goto out_free_stage2_pgd;

	kvm_vgic_early_init(kvm);

	/* The maximum number of VCPUs is limited by the host's GIC model */
	kvm->arch.max_vcpus = kvm_arm_default_max_vcpus();

	set_default_csv2(kvm);

#ifdef CONFIG_CVM_HOST
	if (kvm_arm_cvm_type(type)) {
		ret = kvm_init_cvm_vm(kvm);
		if (ret)
			goto out_free_stage2_pgd;
	}
#endif

	return ret;
out_free_stage2_pgd:
	kvm_free_stage2_pgd(&kvm->arch.mmu);

#ifdef CONFIG_CVM_HOST
out_free_cvm:
	kfree(kvm->arch.cvm);
	kvm->arch.cvm = NULL;
#endif
	return ret;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}


/**
 * kvm_arch_destroy_vm - destroy the VM data structure
 * @kvm:	pointer to the KVM struct
 */
void kvm_arch_destroy_vm(struct kvm *kvm)
{
	int i;

#ifdef CONFIG_KVM_HISI_VIRT
	kvm_hisi_destroy_dvmbm(kvm);
#endif

	bitmap_free(kvm->arch.pmu_filter);

	kvm_vgic_destroy(kvm);

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (kvm->vcpus[i]) {
			kvm_vcpu_destroy(kvm->vcpus[i]);
			kvm->vcpus[i] = NULL;
		}
	}
	atomic_set(&kvm->online_vcpus, 0);
#ifdef CONFIG_CVM_HOST
	if (kvm_is_cvm(kvm))
		kvm_destroy_cvm(kvm);
#endif
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;
	switch (ext) {
	case KVM_CAP_IRQCHIP:
		r = vgic_present;
		break;
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_DEVICE_CTRL:
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_ARM_PSCI:
	case KVM_CAP_ARM_PSCI_0_2:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_IMMEDIATE_EXIT:
	case KVM_CAP_VCPU_EVENTS:
	case KVM_CAP_ARM_IRQ_LINE_LAYOUT_2:
	case KVM_CAP_ARM_NISV_TO_USER:
	case KVM_CAP_ARM_INJECT_EXT_DABT:
	case KVM_CAP_ARM_CPU_FEATURE:
	case KVM_CAP_PTP_KVM:
		r = 1;
		break;
	case KVM_CAP_ARM_SET_DEVICE_ADDR:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		r = num_online_cpus();
		break;
	case KVM_CAP_MAX_VCPUS:
	case KVM_CAP_MAX_VCPU_ID:
		if (kvm)
			r = kvm->arch.max_vcpus;
		else
			r = kvm_arm_default_max_vcpus();
		break;
	case KVM_CAP_MSI_DEVID:
		if (!kvm)
			r = -EINVAL;
		else
			r = kvm->arch.vgic.msis_require_devid;
		break;
	case KVM_CAP_ARM_USER_IRQ:
		/*
		 * 1: EL1_VTIMER, EL1_PTIMER, and PMU.
		 * (bump this number if adding more devices)
		 */
		r = 1;
		break;
	case KVM_CAP_STEAL_TIME:
#ifdef CONFIG_CVM_HOST
		if (kvm && kvm_is_cvm(kvm))
			r = 0;
		else
#endif
			r = kvm_arm_pvtime_supported();
		break;
	case KVM_CAP_ARM_VIRT_MSI_BYPASS:
		r = sdev_enable;
		break;
#ifdef CONFIG_CVM_HOST
	case KVM_CAP_ARM_TMM:
		if (!is_armv8_4_sel2_present()) {
			r = -ENXIO;
			break;
		}
		r = static_key_enabled(&kvm_cvm_is_available);
		break;
#endif
	default:
		r = kvm_arch_vm_ioctl_check_extension(kvm, ext);
		break;
	}
	return r;
}

long kvm_arch_dev_ioctl(struct file *filp,
			unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

struct kvm *kvm_arch_alloc_vm(void)
{
	if (!has_vhe())
		return kzalloc(sizeof(struct kvm), GFP_KERNEL);

	return vzalloc(sizeof(struct kvm));
}

void kvm_arch_free_vm(struct kvm *kvm)
{
	if (!has_vhe())
		kfree(kvm);
	else
		vfree(kvm);
}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	if (irqchip_in_kernel(kvm) && vgic_initialized(kvm))
		return -EBUSY;

	if (id >= kvm->arch.max_vcpus)
		return -EINVAL;

	return 0;
}

static int get_cpu_ftr(u32 id, u64 val, void *argp)
{
	struct id_registers *idregs = argp;

	/*
	 * (Op0, Op1, CRn, CRm, Op2) of ID registers is (3, 0, 0, crm, op2),
	 * where 1<=crm<8, 0<=op2<8.
	 */
	if (sys_reg_Op0(id) == 3 && sys_reg_Op1(id) == 0 &&
	    sys_reg_CRn(id) == 0 && sys_reg_CRm(id) > 0) {
		idregs->regs[idregs->num].sys_id = id;
		idregs->regs[idregs->num].sys_val = val;
		idregs->num++;
	}

	return 0;
}

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	int err;

	/* Force users to call KVM_ARM_VCPU_INIT */
	vcpu->arch.target = -1;
	bitmap_zero(vcpu->arch.features, KVM_VCPU_MAX_FEATURES);

	vcpu->arch.mmu_page_cache.gfp_zero = __GFP_ZERO;

	/* Set up the timer */
	kvm_timer_vcpu_init(vcpu);

	kvm_pmu_vcpu_init(vcpu);

	kvm_arm_reset_debug_ptr(vcpu);

	kvm_arm_pvtime_vcpu_init(&vcpu->arch);

	kvm_arm_pvsched_vcpu_init(&vcpu->arch);

	vcpu->arch.hw_mmu = &vcpu->kvm->arch.mmu;

	err = kvm_vgic_vcpu_init(vcpu);
	if (err)
		return err;

	err = arm64_cpu_ftr_regs_traverse(get_cpu_ftr, &vcpu->arch.idregs);
	if (err)
		return err;

#ifdef CONFIG_KVM_HISI_VIRT
	err = kvm_hisi_dvmbm_vcpu_init(vcpu);
	if (err)
		return err;
#endif
	return create_hyp_mappings(vcpu, vcpu + 1, PAGE_HYP);
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.has_run_once && unlikely(!irqchip_in_kernel(vcpu->kvm)))
		static_branch_dec(&userspace_irqchip_in_use);

	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_page_cache);
	kvm_timer_vcpu_terminate(vcpu);
	kvm_pmu_vcpu_destroy(vcpu);

	kvm_arm_vcpu_destroy(vcpu);

#ifdef CONFIG_KVM_HISI_VIRT
	kvm_hisi_dvmbm_vcpu_destroy(vcpu);
#endif
}

void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu)
{
	/*
	 * If we're about to block (most likely because we've just hit a
	 * WFI), we need to sync back the state of the GIC CPU interface
	 * so that we have the latest PMR and group enables. This ensures
	 * that kvm_arch_vcpu_runnable has up-to-date data to decide
	 * whether we have pending interrupts.
	 *
	 * For the same reason, we want to tell GICv4 that we need
	 * doorbells to be signalled, should an interrupt become pending.
	 */
	preempt_disable();
	kvm_vgic_vmcr_sync(vcpu);
	vgic_v4_put(vcpu, true);
	preempt_enable();
}

void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu)
{
	preempt_disable();
	vgic_v4_load(vcpu);
	preempt_enable();
}

void kvm_arch_vcpu_stat_reset(struct kvm_vcpu_stat *vcpu_stat)
{
	vcpu_stat->st_max = 0;
}

static void update_steal_time(struct kvm_vcpu *vcpu)
{
	u64 delta;

	delta = current->sched_info.run_delay - vcpu->stat.steal;
	vcpu->stat.steal = current->sched_info.run_delay;
	vcpu->stat.st_max = max(vcpu->stat.st_max, delta);
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct kvm_s2_mmu *mmu;
	int *last_ran;

	mmu = vcpu->arch.hw_mmu;
	last_ran = this_cpu_ptr(mmu->last_vcpu_ran);

	/*
	 * We guarantee that both TLBs and I-cache are private to each
	 * vcpu. If detecting that a vcpu from the same VM has
	 * previously run on the same physical CPU, call into the
	 * hypervisor code to nuke the relevant contexts.
	 *
	 * We might get preempted before the vCPU actually runs, but
	 * over-invalidation doesn't affect correctness.
	 */
	if (*last_ran != vcpu->vcpu_id) {
		kvm_call_hyp(__kvm_flush_cpu_context, mmu);
		*last_ran = vcpu->vcpu_id;
	}

	vcpu->cpu = cpu;

#ifdef CONFIG_CVM_HOST
	if (vcpu_is_tec(vcpu)) {
		if (single_task_running())
			vcpu_clear_wfx_traps(vcpu);
		else
			vcpu_set_wfx_traps(vcpu);
	}
#endif
	kvm_vgic_load(vcpu);
	kvm_timer_vcpu_load(vcpu);
#ifdef CONFIG_CVM_HOST
	if (vcpu_is_tec(vcpu)) {
		if (kvm_arm_is_pvtime_enabled(&vcpu->arch))
			kvm_make_request(KVM_REQ_RECORD_STEAL, vcpu);
		return;
	}
#endif
	if (has_vhe())
		kvm_vcpu_load_sysregs_vhe(vcpu);
	kvm_arch_vcpu_load_fp(vcpu);
	kvm_vcpu_pmu_restore_guest(vcpu);
	if (kvm_arm_is_pvtime_enabled(&vcpu->arch))
		kvm_make_request(KVM_REQ_RECORD_STEAL, vcpu);

	if (single_task_running())
		vcpu_clear_wfx_traps(vcpu);
	else
		vcpu_set_wfx_traps(vcpu);

	update_steal_time(vcpu);
	if (vcpu_has_ptrauth(vcpu))
		vcpu_ptrauth_disable(vcpu);

	/*
	 * When pv_preempted is changed from enabled to disabled, preempted
	 * state will not be updated in kvm_arch_vcpu_put/load. So we must
	 * update the preempted state to 0 for every vCPU in case some vCPUs'
	 * preempted state will always be 1.
	 */
	if (kvm_arm_is_pvsched_valid(&vcpu->arch)) {
		if (pv_preempted_enable)
			kvm_update_pvsched_preempted(vcpu, 0);
		else {
			if (vcpu->arch.pvsched.preempted)
				kvm_update_pvsched_preempted(vcpu, 0);
		}
	}

#ifdef CONFIG_KVM_HISI_VIRT
	kvm_hisi_dvmbm_load(vcpu);
#endif
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_CVM_HOST
	if (vcpu_is_tec(vcpu)) {
		kvm_cvm_vcpu_put(vcpu);
		return;
	}
#endif
	kvm_arch_vcpu_put_fp(vcpu);
	if (has_vhe())
		kvm_vcpu_put_sysregs_vhe(vcpu);
	kvm_timer_vcpu_put(vcpu);
	kvm_vgic_put(vcpu);
	kvm_vcpu_pmu_restore_host(vcpu);

	vcpu->cpu = -1;

	if (kvm_arm_is_pvsched_valid(&vcpu->arch) && pv_preempted_enable)
		kvm_update_pvsched_preempted(vcpu, 1);

#ifdef CONFIG_KVM_HISI_VIRT
	kvm_hisi_dvmbm_put(vcpu);
#endif
}

static void vcpu_power_off(struct kvm_vcpu *vcpu)
{
	vcpu->arch.power_off = true;
	kvm_make_request(KVM_REQ_SLEEP, vcpu);
	kvm_vcpu_kick(vcpu);
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	if (vcpu->arch.power_off)
		mp_state->mp_state = KVM_MP_STATE_STOPPED;
	else
		mp_state->mp_state = KVM_MP_STATE_RUNNABLE;

	return 0;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	int ret = 0;

	switch (mp_state->mp_state) {
	case KVM_MP_STATE_RUNNABLE:
		vcpu->arch.power_off = false;
		break;
	case KVM_MP_STATE_STOPPED:
		vcpu_power_off(vcpu);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

/**
 * kvm_arch_vcpu_runnable - determine if the vcpu can be scheduled
 * @v:		The VCPU pointer
 *
 * If the guest CPU is not waiting for interrupts or an interrupt line is
 * asserted, the CPU is by definition runnable.
 */
int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	bool irq_lines = *vcpu_hcr(v) & (HCR_VI | HCR_VF);
	bool pv_unhalted = v->arch.pvsched.pv_unhalted;

	return ((irq_lines || kvm_vgic_vcpu_pending_irq(v) || pv_unhalted)
		&& !v->arch.power_off && !v->arch.pause);
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return vcpu_mode_priv(vcpu);
}

/* Just ensure a guest exit from a particular CPU */
static void exit_vm_noop(void *info)
{
}

void force_vm_exit(const cpumask_t *mask)
{
	preempt_disable();
	smp_call_function_many(mask, exit_vm_noop, NULL, true);
	preempt_enable();
}

/**
 * need_new_vmid_gen - check that the VMID is still valid
 * @vmid: The VMID to check
 *
 * return true if there is a new generation of VMIDs being used
 *
 * The hardware supports a limited set of values with the value zero reserved
 * for the host, so we check if an assigned value belongs to a previous
 * generation, which requires us to assign a new value. If we're the first to
 * use a VMID for the new generation, we must flush necessary caches and TLBs
 * on all CPUs.
 */
static bool need_new_vmid_gen(struct kvm_vmid *vmid)
{
	u64 current_vmid_gen = atomic64_read(&kvm_vmid_gen);
	smp_rmb(); /* Orders read of kvm_vmid_gen and kvm->arch.vmid */
	return unlikely(READ_ONCE(vmid->vmid_gen) != current_vmid_gen);
}

/**
 * update_vmid - Update the vmid with a valid VMID for the current generation
 * @vmid: The stage-2 VMID information struct
 */
static void update_vmid(struct kvm_vmid *vmid)
{
	if (!need_new_vmid_gen(vmid))
		return;

	spin_lock(&kvm_vmid_lock);

	/*
	 * We need to re-check the vmid_gen here to ensure that if another vcpu
	 * already allocated a valid vmid for this vm, then this vcpu should
	 * use the same vmid.
	 */
	if (!need_new_vmid_gen(vmid)) {
		spin_unlock(&kvm_vmid_lock);
		return;
	}

	/* First user of a new VMID generation? */
	if (unlikely(kvm_next_vmid == 0)) {
		atomic64_inc(&kvm_vmid_gen);
		kvm_next_vmid = 1;

		/*
		 * On SMP we know no other CPUs can use this CPU's or each
		 * other's VMID after force_vm_exit returns since the
		 * kvm_vmid_lock blocks them from reentry to the guest.
		 */
		force_vm_exit(cpu_all_mask);
		/*
		 * Now broadcast TLB + ICACHE invalidation over the inner
		 * shareable domain to make sure all data structures are
		 * clean.
		 */
		kvm_call_hyp(__kvm_flush_vm_context);
	}

	vmid->vmid = kvm_next_vmid;
	kvm_next_vmid++;
	kvm_next_vmid &= (1 << kvm_get_vmid_bits()) - 1;

	smp_wmb();
	WRITE_ONCE(vmid->vmid_gen, atomic64_read(&kvm_vmid_gen));

	spin_unlock(&kvm_vmid_lock);
}

static int kvm_vcpu_first_run_init(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	int ret = 0;

	if (likely(vcpu->arch.has_run_once))
		return 0;

	if (!kvm_arm_vcpu_is_finalized(vcpu))
		return -EPERM;

	vcpu->arch.has_run_once = true;

	kvm_arm_vcpu_init_debug(vcpu);

	ret = kvm_vtimer_config(kvm);
	if (ret)
		return ret;

	if (likely(irqchip_in_kernel(kvm))) {
		/*
		 * Map the VGIC hardware resources before running a vcpu the
		 * first time on this VM.
		 */
		if (unlikely(!vgic_ready(kvm))) {
			ret = kvm_vgic_map_resources(kvm);
			if (ret)
				return ret;
		}
	} else {
		/*
		 * Tell the rest of the code that there are userspace irqchip
		 * VMs in the wild.
		 */
#ifdef CONFIG_CVM_HOST
	if (!kvm_is_cvm(kvm))
#endif
		static_branch_inc(&userspace_irqchip_in_use);
	}

	ret = kvm_timer_enable(vcpu);
	if (ret)
		return ret;

	ret = kvm_arm_pmu_v3_enable(vcpu);

	return ret;
}

bool kvm_arch_intc_initialized(struct kvm *kvm)
{
	return vgic_initialized(kvm);
}

void kvm_arm_halt_guest(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		vcpu->arch.pause = true;
	kvm_make_all_cpus_request(kvm, KVM_REQ_SLEEP);
}

void kvm_arm_resume_guest(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		vcpu->arch.pause = false;
		rcuwait_wake_up(kvm_arch_vcpu_get_wait(vcpu));
	}
}

static void vcpu_req_sleep(struct kvm_vcpu *vcpu)
{
	struct rcuwait *wait = kvm_arch_vcpu_get_wait(vcpu);

	rcuwait_wait_event(wait,
			   (!vcpu->arch.power_off) &&(!vcpu->arch.pause),
			   TASK_INTERRUPTIBLE);

	if (vcpu->arch.power_off || vcpu->arch.pause) {
		/* Awaken to handle a signal, request we sleep again later. */
		kvm_make_request(KVM_REQ_SLEEP, vcpu);
	}

	/*
	 * Make sure we will observe a potential reset request if we've
	 * observed a change to the power state. Pairs with the smp_wmb() in
	 * kvm_psci_vcpu_on().
	 */
	smp_rmb();
}

static int kvm_vcpu_initialized(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.target >= 0;
}

static void check_vcpu_requests(struct kvm_vcpu *vcpu)
{
	if (kvm_request_pending(vcpu)) {
		if (kvm_check_request(KVM_REQ_SLEEP, vcpu))
			vcpu_req_sleep(vcpu);

		if (kvm_check_request(KVM_REQ_VCPU_RESET, vcpu))
			kvm_reset_vcpu(vcpu);

		/*
		 * Clear IRQ_PENDING requests that were made to guarantee
		 * that a VCPU sees new virtual interrupts.
		 */
		kvm_check_request(KVM_REQ_IRQ_PENDING, vcpu);

		if (kvm_check_request(KVM_REQ_RECORD_STEAL, vcpu))
			kvm_update_stolen_time(vcpu);

		if (kvm_check_request(KVM_REQ_RELOAD_GICv4, vcpu)) {
			/* The distributor enable bits were changed */
			preempt_disable();
			vgic_v4_put(vcpu, false);
			vgic_v4_load(vcpu);
			preempt_enable();
		}

		if (kvm_check_request(KVM_REQ_RELOAD_PMU, vcpu))
			kvm_pmu_handle_pmcr(vcpu,
					    __vcpu_sys_reg(vcpu, PMCR_EL0));

#ifdef CONFIG_KVM_HISI_VIRT
		if (kvm_check_request(KVM_REQ_RELOAD_DVMBM, vcpu))
			kvm_hisi_reload_lsudvmbm(vcpu->kvm);
#endif

		if (kvm_check_request(KVM_REQ_RELOAD_WFI_TRAPS, vcpu)) {
			if (single_task_running())
				vcpu_clear_wfx_traps(vcpu);
			else
				vcpu_set_wfx_traps(vcpu);
		}
	}
}

static void update_vcpu_stat_time(struct kvm_vcpu_stat *vcpu_stat)
{
	vcpu_stat->utime = current->utime;
	vcpu_stat->stime = current->stime;
	vcpu_stat->gtime = current->gtime;
}

/**
 * kvm_vcpu_exit_request - returns true if the VCPU should *not* enter the guest
 * @vcpu:	The VCPU pointer
 * @ret:	Pointer to write optional return code
 *
 * Returns: true if the VCPU needs to return to a preemptible + interruptible
 *	    and skip guest entry.
 *
 * This function disambiguates between two different types of exits: exits to a
 * preemptible + interruptible kernel context and exits to userspace. For an
 * exit to userspace, this function will write the return code to ret and return
 * true. For an exit to preemptible + interruptible kernel context (i.e. check
 * for pending work and re-enter), return true without writing to ret.
 */
static bool kvm_vcpu_exit_request(struct kvm_vcpu *vcpu, int *ret)
{
	struct kvm_run *run = vcpu->run;

	/*
	 * If we're using a userspace irqchip, then check if we need
	 * to tell a userspace irqchip about timer or PMU level
	 * changes and if so, exit to userspace (the actual level
	 * state gets updated in kvm_timer_update_run and
	 * kvm_pmu_update_run below).
	 */
	if (static_branch_unlikely(&userspace_irqchip_in_use)) {
		if (kvm_timer_should_notify_user(vcpu) ||
		    kvm_pmu_should_notify_user(vcpu)) {
			*ret = -EINTR;
			run->exit_reason = KVM_EXIT_INTR;
			return true;
		}
	}

	return kvm_request_pending(vcpu) ||
			need_new_vmid_gen(&vcpu->arch.hw_mmu->vmid) ||
			xfer_to_guest_mode_work_pending();
}

#ifdef CONFIG_CVM_HOST
static inline void update_pmu_phys_irq(struct kvm_vcpu *vcpu, bool *pmu_stopped)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;

	if (pmu->irq_level) {
		*pmu_stopped = true;
		arm_pmu_set_phys_irq(false);
	}
}
#endif

/**
 * kvm_arch_vcpu_ioctl_run - the main VCPU run function to execute guest code
 * @vcpu:	The VCPU pointer
 *
 * This function is called through the VCPU_RUN ioctl called from user space. It
 * will execute VM code in a loop until the time slice for the process is used
 * or some emulation is needed from user space in which case the function will
 * return with return value 0 and with the kvm_run structure filled in with the
 * required data for the requested emulation.
 */
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	int ret;

	if (unlikely(!kvm_vcpu_initialized(vcpu)))
		return -ENOEXEC;

	ret = kvm_vcpu_first_run_init(vcpu);
	if (ret)
		return ret;
	if (run->exit_reason == KVM_EXIT_MMIO) {
		ret = kvm_handle_mmio_return(vcpu);
		if (ret)
			return ret;
	}

	if (run->immediate_exit)
		return -EINTR;

	vcpu_load(vcpu);

	kvm_sigset_activate(vcpu);

	ret = 1;
	run->exit_reason = KVM_EXIT_UNKNOWN;
	while (ret > 0) {
#ifdef CONFIG_CVM_HOST
		bool pmu_stopped = false;
#endif
		/*
		 * Check conditions before entering the guest
		 */
		ret = xfer_to_guest_mode_handle_work(vcpu);
		if (!ret)
			ret = 1;

		update_vmid(&vcpu->arch.hw_mmu->vmid);

		check_vcpu_requests(vcpu);

		/*
		 * Preparing the interrupts to be injected also
		 * involves poking the GIC, which must be done in a
		 * non-preemptible context.
		 */
		preempt_disable();

		kvm_pmu_flush_hwstate(vcpu);
#ifdef CONFIG_CVM_HOST
		if (vcpu_is_tec(vcpu))
			update_pmu_phys_irq(vcpu, &pmu_stopped);
#endif

		local_irq_disable();

		kvm_vgic_flush_hwstate(vcpu);

		/*
		 * Ensure we set mode to IN_GUEST_MODE after we disable
		 * interrupts and before the final VCPU requests check.
		 * See the comment in kvm_vcpu_exiting_guest_mode() and
		 * Documentation/virt/kvm/vcpu-requests.rst
		 */
		smp_store_mb(vcpu->mode, IN_GUEST_MODE);

		if (ret <= 0 || kvm_vcpu_exit_request(vcpu, &ret)) {
			vcpu->mode = OUTSIDE_GUEST_MODE;
			isb(); /* Ensure work in x_flush_hwstate is committed */
			kvm_pmu_sync_hwstate(vcpu);
			if (static_branch_unlikely(&userspace_irqchip_in_use))
				kvm_timer_sync_user(vcpu);
			kvm_vgic_sync_hwstate(vcpu);
			local_irq_enable();
			preempt_enable();
			continue;
		}

		kvm_arm_setup_debug(vcpu);

		if (use_twed()) {
			vcpu_twed_enable(vcpu);
			vcpu_set_twed(vcpu);
		} else {
			vcpu_twed_disable(vcpu);
		}

		/**************************************************************
		 * Enter the guest
		 */
		trace_kvm_entry(vcpu->vcpu_id, *vcpu_pc(vcpu));
		guest_enter_irqoff();
#ifdef CONFIG_CVM_HOST
		if (vcpu_is_tec(vcpu))
			ret = kvm_tec_enter(vcpu);
		else
#endif
			ret = kvm_call_hyp_ret(__kvm_vcpu_run, vcpu);

		vcpu->mode = OUTSIDE_GUEST_MODE;
		vcpu->stat.exits++;
		/*
		 * Back from guest
		 *************************************************************/

		kvm_arm_clear_debug(vcpu);

		/*
		 * We must sync the PMU state before the vgic state so
		 * that the vgic can properly sample the updated state of the
		 * interrupt line.
		 */
		kvm_pmu_sync_hwstate(vcpu);

		/*
		 * Sync the vgic state before syncing the timer state because
		 * the timer code needs to know if the virtual timer
		 * interrupts are active.
		 */
		kvm_vgic_sync_hwstate(vcpu);

		/*
		 * Sync the timer hardware state before enabling interrupts as
		 * we don't want vtimer interrupts to race with syncing the
		 * timer virtual interrupt state.
		 */
		if (static_branch_unlikely(&userspace_irqchip_in_use))
			kvm_timer_sync_user(vcpu);

		kvm_arch_vcpu_ctxsync_fp(vcpu);

		/*
		 * We may have taken a host interrupt in HYP mode (ie
		 * while executing the guest). This interrupt is still
		 * pending, as we haven't serviced it yet!
		 *
		 * We're now back in SVC mode, with interrupts
		 * disabled.  Enabling the interrupts now will have
		 * the effect of taking the interrupt again, in SVC
		 * mode this time.
		 */
		local_irq_enable();

		/*
		 * We do local_irq_enable() before calling guest_exit() so
		 * that if a timer interrupt hits while running the guest we
		 * account that tick as being spent in the guest.  We enable
		 * preemption after calling guest_exit() so that if we get
		 * preempted we make sure ticks after that is not counted as
		 * guest time.
		 */
		guest_exit();
#ifdef CONFIG_CVM_HOST
		if (!vcpu_is_tec(vcpu)) {
#endif
			trace_kvm_exit(vcpu->vcpu_id, ret, *vcpu_pc(vcpu));

			/* Exit types that need handling before we can be preempted */
			handle_exit_early(vcpu, ret);
#ifdef CONFIG_CVM_HOST
		}
#endif
		preempt_enable();
#ifdef CONFIG_CVM_HOST
		if (pmu_stopped)
			arm_pmu_set_phys_irq(true);
#endif

		/*
		 * The ARMv8 architecture doesn't give the hypervisor
		 * a mechanism to prevent a guest from dropping to AArch32 EL0
		 * if implemented by the CPU. If we spot the guest in such
		 * state and that we decided it wasn't supposed to do so (like
		 * with the asymmetric AArch32 case), return to userspace with
		 * a fatal error.
		 */
		if (!system_supports_32bit_el0() && vcpu_mode_is_32bit(vcpu)) {
			/*
			 * As we have caught the guest red-handed, decide that
			 * it isn't fit for purpose anymore by making the vcpu
			 * invalid. The VMM can try and fix it by issuing  a
			 * KVM_ARM_VCPU_INIT if it really wants to.
			 */
			vcpu->arch.target = -1;
			ret = ARM_EXCEPTION_IL;
		}
#ifdef CONFIG_CVM_HOST
		if (vcpu_is_tec(vcpu))
			ret = handle_cvm_exit(vcpu, ret);
		else
#endif
			ret = handle_exit(vcpu, ret);
		update_vcpu_stat_time(&vcpu->stat);
	}

	/* Tell userspace about in-kernel device output levels */
	if (unlikely(!irqchip_in_kernel(vcpu->kvm))) {
		kvm_timer_update_run(vcpu);
		kvm_pmu_update_run(vcpu);
	}

	kvm_sigset_deactivate(vcpu);

	vcpu_put(vcpu);
	return ret;
}

static int vcpu_interrupt_line(struct kvm_vcpu *vcpu, int number, bool level)
{
	int bit_index;
	bool set;
	unsigned long *hcr;

	if (number == KVM_ARM_IRQ_CPU_IRQ)
		bit_index = __ffs(HCR_VI);
	else /* KVM_ARM_IRQ_CPU_FIQ */
		bit_index = __ffs(HCR_VF);

	hcr = vcpu_hcr(vcpu);
	if (level)
		set = test_and_set_bit(bit_index, hcr);
	else
		set = test_and_clear_bit(bit_index, hcr);

	/*
	 * If we didn't change anything, no need to wake up or kick other CPUs
	 */
	if (set == level)
		return 0;

	/*
	 * The vcpu irq_lines field was updated, wake up sleeping VCPUs and
	 * trigger a world-switch round on the running physical CPU to set the
	 * virtual IRQ/FIQ fields in the HCR appropriately.
	 */
	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
	kvm_vcpu_kick(vcpu);

	return 0;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level,
			  bool line_status)
{
	u32 irq = irq_level->irq;
	unsigned int irq_type, vcpu_idx, irq_num;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	struct kvm_vcpu *vcpu = NULL;
	bool level = irq_level->level;

	irq_type = (irq >> KVM_ARM_IRQ_TYPE_SHIFT) & KVM_ARM_IRQ_TYPE_MASK;
	vcpu_idx = (irq >> KVM_ARM_IRQ_VCPU_SHIFT) & KVM_ARM_IRQ_VCPU_MASK;
	vcpu_idx += ((irq >> KVM_ARM_IRQ_VCPU2_SHIFT) & KVM_ARM_IRQ_VCPU2_MASK) * (KVM_ARM_IRQ_VCPU_MASK + 1);
	irq_num = (irq >> KVM_ARM_IRQ_NUM_SHIFT) & KVM_ARM_IRQ_NUM_MASK;

	trace_kvm_irq_line(irq_type, vcpu_idx, irq_num, irq_level->level);

	switch (irq_type) {
	case KVM_ARM_IRQ_TYPE_CPU:
		if (irqchip_in_kernel(kvm))
			return -ENXIO;

		if (vcpu_idx >= nrcpus)
			return -EINVAL;

		vcpu = kvm_get_vcpu(kvm, vcpu_idx);
		if (!vcpu)
			return -EINVAL;

		if (irq_num > KVM_ARM_IRQ_CPU_FIQ)
			return -EINVAL;

		return vcpu_interrupt_line(vcpu, irq_num, level);
	case KVM_ARM_IRQ_TYPE_PPI:
		if (!irqchip_in_kernel(kvm))
			return -ENXIO;

		if (vcpu_idx >= nrcpus)
			return -EINVAL;

		vcpu = kvm_get_vcpu(kvm, vcpu_idx);
		if (!vcpu)
			return -EINVAL;

		if (irq_num < VGIC_NR_SGIS || irq_num >= VGIC_NR_PRIVATE_IRQS)
			return -EINVAL;

		return kvm_vgic_inject_irq(kvm, vcpu->vcpu_id, irq_num, level, NULL);
	case KVM_ARM_IRQ_TYPE_SPI:
		if (!irqchip_in_kernel(kvm))
			return -ENXIO;

		if (irq_num < VGIC_NR_PRIVATE_IRQS)
			return -EINVAL;

		return kvm_vgic_inject_irq(kvm, 0, irq_num, level, NULL);
	}

	return -EINVAL;
}

static int kvm_vcpu_set_target(struct kvm_vcpu *vcpu,
			       const struct kvm_vcpu_init *init)
{
	unsigned int i, ret;
	int phys_target = kvm_target_cpu();

	if (init->target != phys_target)
		return -EINVAL;

	/*
	 * Secondary and subsequent calls to KVM_ARM_VCPU_INIT must
	 * use the same target.
	 */
	if (vcpu->arch.target != -1 && vcpu->arch.target != init->target)
		return -EINVAL;

	/* -ENOENT for unknown features, -EINVAL for invalid combinations. */
	for (i = 0; i < sizeof(init->features) * 8; i++) {
		bool set = (init->features[i / 32] & (1 << (i % 32)));

		if (set && i >= KVM_VCPU_MAX_FEATURES)
			return -ENOENT;

		/*
		 * Secondary and subsequent calls to KVM_ARM_VCPU_INIT must
		 * use the same feature set.
		 */
		if (vcpu->arch.target != -1 && i < KVM_VCPU_MAX_FEATURES &&
		    test_bit(i, vcpu->arch.features) != set)
			return -EINVAL;

		if (set)
			set_bit(i, vcpu->arch.features);
	}

	vcpu->arch.target = phys_target;

	/* Now we know what it is, we can reset it. */
	ret = kvm_reset_vcpu(vcpu);
	if (ret) {
		vcpu->arch.target = -1;
		bitmap_zero(vcpu->arch.features, KVM_VCPU_MAX_FEATURES);
	}

	return ret;
}

static int kvm_arch_vcpu_ioctl_vcpu_init(struct kvm_vcpu *vcpu,
					 struct kvm_vcpu_init *init)
{
	int ret;

	ret = kvm_vcpu_set_target(vcpu, init);
	if (ret)
		return ret;

	/*
	 * Ensure a rebooted VM will fault in RAM pages and detect if the
	 * guest MMU is turned off and flush the caches as needed.
	 *
	 * S2FWB enforces all memory accesses to RAM being cacheable,
	 * ensuring that the data side is always coherent. We still
	 * need to invalidate the I-cache though, as FWB does *not*
	 * imply CTR_EL0.DIC.
	 */
	if (vcpu->arch.has_run_once) {
		if (!cpus_have_final_cap(ARM64_HAS_STAGE2_FWB))
			stage2_unmap_vm(vcpu->kvm);
		else
			__flush_icache_all();
	}

	vcpu_reset_hcr(vcpu);

	/*
	 * Handle the "start in power-off" case.
	 */
	if (test_bit(KVM_ARM_VCPU_POWER_OFF, vcpu->arch.features))
		vcpu_power_off(vcpu);
	else
		vcpu->arch.power_off = false;

	kvm_arm_pvsched_vcpu_init(&vcpu->arch);

	return 0;
}

static int kvm_arm_vcpu_set_attr(struct kvm_vcpu *vcpu,
				 struct kvm_device_attr *attr)
{
	int ret = -ENXIO;

	switch (attr->group) {
	default:
		ret = kvm_arm_vcpu_arch_set_attr(vcpu, attr);
		break;
	}

	return ret;
}

static int kvm_arm_vcpu_get_attr(struct kvm_vcpu *vcpu,
				 struct kvm_device_attr *attr)
{
	int ret = -ENXIO;

	switch (attr->group) {
	default:
		ret = kvm_arm_vcpu_arch_get_attr(vcpu, attr);
		break;
	}

	return ret;
}

static int kvm_arm_vcpu_has_attr(struct kvm_vcpu *vcpu,
				 struct kvm_device_attr *attr)
{
	int ret = -ENXIO;

	switch (attr->group) {
	default:
		ret = kvm_arm_vcpu_arch_has_attr(vcpu, attr);
		break;
	}

	return ret;
}

static int kvm_arm_vcpu_get_events(struct kvm_vcpu *vcpu,
				   struct kvm_vcpu_events *events)
{
	memset(events, 0, sizeof(*events));

	return __kvm_arm_vcpu_get_events(vcpu, events);
}

static int kvm_arm_vcpu_set_events(struct kvm_vcpu *vcpu,
				   struct kvm_vcpu_events *events)
{
	int i;

	/* check whether the reserved field is zero */
	for (i = 0; i < ARRAY_SIZE(events->reserved); i++)
		if (events->reserved[i])
			return -EINVAL;

	/* check whether the pad field is zero */
	for (i = 0; i < ARRAY_SIZE(events->exception.pad); i++)
		if (events->exception.pad[i])
			return -EINVAL;

	return __kvm_arm_vcpu_set_events(vcpu, events);
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	struct kvm_device_attr attr;
	long r;

	switch (ioctl) {
	case KVM_ARM_VCPU_INIT: {
		struct kvm_vcpu_init init;

		r = -EFAULT;
		if (copy_from_user(&init, argp, sizeof(init)))
			break;

		r = kvm_arch_vcpu_ioctl_vcpu_init(vcpu, &init);
		break;
	}
	case KVM_SET_ONE_REG:
	case KVM_GET_ONE_REG: {
		struct kvm_one_reg reg;

		r = -ENOEXEC;
		if (unlikely(!kvm_vcpu_initialized(vcpu)))
			break;

		r = -EFAULT;
		if (copy_from_user(&reg, argp, sizeof(reg)))
			break;

		/*
		 * We could owe a reset due to PSCI. Handle the pending reset
		 * here to ensure userspace register accesses are ordered after
		 * the reset.
		 */
		if (kvm_check_request(KVM_REQ_VCPU_RESET, vcpu))
			kvm_reset_vcpu(vcpu);

		if (ioctl == KVM_SET_ONE_REG)
			r = kvm_arm_set_reg(vcpu, &reg);
		else
			r = kvm_arm_get_reg(vcpu, &reg);
		break;
	}
	case KVM_GET_REG_LIST: {
		struct kvm_reg_list __user *user_list = argp;
		struct kvm_reg_list reg_list;
		unsigned n;

		r = -ENOEXEC;
		if (unlikely(!kvm_vcpu_initialized(vcpu)))
			break;

		r = -EPERM;
		if (!kvm_arm_vcpu_is_finalized(vcpu))
			break;

		r = -EFAULT;
		if (copy_from_user(&reg_list, user_list, sizeof(reg_list)))
			break;
		n = reg_list.n;
		reg_list.n = kvm_arm_num_regs(vcpu);
		if (copy_to_user(user_list, &reg_list, sizeof(reg_list)))
			break;
		r = -E2BIG;
		if (n < reg_list.n)
			break;
		r = kvm_arm_copy_reg_indices(vcpu, user_list->reg);
		break;
	}
	case KVM_SET_DEVICE_ATTR: {
		r = -EFAULT;
		if (copy_from_user(&attr, argp, sizeof(attr)))
			break;
		r = kvm_arm_vcpu_set_attr(vcpu, &attr);
		break;
	}
	case KVM_GET_DEVICE_ATTR: {
		r = -EFAULT;
		if (copy_from_user(&attr, argp, sizeof(attr)))
			break;
		r = kvm_arm_vcpu_get_attr(vcpu, &attr);
		break;
	}
	case KVM_HAS_DEVICE_ATTR: {
		r = -EFAULT;
		if (copy_from_user(&attr, argp, sizeof(attr)))
			break;
		r = kvm_arm_vcpu_has_attr(vcpu, &attr);
		break;
	}
	case KVM_GET_VCPU_EVENTS: {
		struct kvm_vcpu_events events;

		if (kvm_arm_vcpu_get_events(vcpu, &events))
			return -EINVAL;

		if (copy_to_user(argp, &events, sizeof(events)))
			return -EFAULT;

		return 0;
	}
	case KVM_SET_VCPU_EVENTS: {
		struct kvm_vcpu_events events;

		if (copy_from_user(&events, argp, sizeof(events)))
			return -EFAULT;

		return kvm_arm_vcpu_set_events(vcpu, &events);
	}
	case KVM_ARM_VCPU_FINALIZE: {
		int what;

		if (!kvm_vcpu_initialized(vcpu))
			return -ENOEXEC;

		if (get_user(what, (const int __user *)argp))
			return -EFAULT;

		return kvm_arm_vcpu_finalize(vcpu, what);
	}
	default:
		r = -EINVAL;
	}

	return r;
}

void kvm_arch_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{

}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					struct kvm_memory_slot *memslot)
{
	kvm_flush_remote_tlbs(kvm);
}

static int kvm_vm_ioctl_set_device_addr(struct kvm *kvm,
					struct kvm_arm_device_addr *dev_addr)
{
	unsigned long dev_id, type;

	dev_id = (dev_addr->id & KVM_ARM_DEVICE_ID_MASK) >>
		KVM_ARM_DEVICE_ID_SHIFT;
	type = (dev_addr->id & KVM_ARM_DEVICE_TYPE_MASK) >>
		KVM_ARM_DEVICE_TYPE_SHIFT;

	switch (dev_id) {
	case KVM_ARM_DEVICE_VGIC_V2:
		if (!vgic_present)
			return -ENXIO;
		return kvm_vgic_addr(kvm, type, &dev_addr->addr, true);
	default:
		return -ENODEV;
	}
}

long kvm_arch_vm_ioctl(struct file *filp,
		       unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;

	switch (ioctl) {
#ifdef CONFIG_CVM_HOST
	case KVM_LOAD_USER_DATA: {
		return kvm_load_user_data(kvm, arg);
	}
#endif
	case KVM_CREATE_IRQCHIP: {
		int ret;
		if (!vgic_present)
			return -ENXIO;
		mutex_lock(&kvm->lock);
		ret = kvm_vgic_create(kvm, KVM_DEV_TYPE_ARM_VGIC_V2);
		mutex_unlock(&kvm->lock);
		return ret;
	}
	case KVM_ARM_SET_DEVICE_ADDR: {
		struct kvm_arm_device_addr dev_addr;

		if (copy_from_user(&dev_addr, argp, sizeof(dev_addr)))
			return -EFAULT;
		return kvm_vm_ioctl_set_device_addr(kvm, &dev_addr);
	}
	case KVM_ARM_PREFERRED_TARGET: {
		int err;
		struct kvm_vcpu_init init;

		err = kvm_vcpu_preferred_target(&init);
		if (err)
			return err;

		if (copy_to_user(argp, &init, sizeof(init)))
			return -EFAULT;

		return 0;
	}
	case KVM_CREATE_SHADOW_DEV: {
		struct kvm_master_dev_info *mdi;
		u32 nvectors;
		int ret;

		if (get_user(nvectors, (const u32 __user *)argp))
			return -EFAULT;
		if (!nvectors)
			return -EINVAL;

		mdi = memdup_user(argp, sizeof(*mdi) + nvectors * sizeof(mdi->msi[0]));
		if (IS_ERR(mdi))
			return PTR_ERR(mdi);

		ret = kvm_shadow_dev_create(kvm, mdi);
		kfree(mdi);

		return ret;
	}
	case KVM_DEL_SHADOW_DEV: {
		u32 devid;

		if (get_user(devid, (const u32 __user *)argp))
			return -EFAULT;

		kvm_shadow_dev_delete(kvm, devid);
		return 0;
	}
	default:
		return -EINVAL;
	}
}

static unsigned long nvhe_percpu_size(void)
{
	return (unsigned long)CHOOSE_NVHE_SYM(__per_cpu_end) -
		(unsigned long)CHOOSE_NVHE_SYM(__per_cpu_start);
}

static unsigned long nvhe_percpu_order(void)
{
	unsigned long size = nvhe_percpu_size();

	return size ? get_order(size) : 0;
}

static int kvm_map_vectors(void)
{
	/*
	 * SV2  = ARM64_SPECTRE_V2
	 * HEL2 = ARM64_HARDEN_EL2_VECTORS
	 *
	 * !SV2 + !HEL2 -> use direct vectors
	 *  SV2 + !HEL2 -> use hardened vectors in place
	 * !SV2 +  HEL2 -> allocate one vector slot and use exec mapping
	 *  SV2 +  HEL2 -> use hardened vectors and use exec mapping
	 */
	if (cpus_have_const_cap(ARM64_SPECTRE_V2) ||
	    cpus_have_const_cap(ARM64_SPECTRE_BHB)) {
		__kvm_bp_vect_base = kvm_ksym_ref(__bp_harden_hyp_vecs);
		__kvm_bp_vect_base = kern_hyp_va(__kvm_bp_vect_base);
	}

	if (cpus_have_const_cap(ARM64_HARDEN_EL2_VECTORS)) {
		phys_addr_t vect_pa = __pa_symbol(__bp_harden_hyp_vecs);
		unsigned long size = __BP_HARDEN_HYP_VECS_SZ;

		/*
		 * Always allocate a spare vector slot, as we don't
		 * know yet which CPUs have a BP hardening slot that
		 * we can reuse.
		 */
		__kvm_harden_el2_vector_slot = atomic_inc_return(&arm64_el2_vector_last_slot);
		BUG_ON(__kvm_harden_el2_vector_slot >= BP_HARDEN_EL2_SLOTS);
		return create_hyp_exec_mappings(vect_pa, size,
						&__kvm_bp_vect_base);
	}

	return 0;
}

static void cpu_init_hyp_mode(void)
{
	phys_addr_t pgd_ptr;
	unsigned long hyp_stack_ptr;
	unsigned long vector_ptr;
	unsigned long tpidr_el2;
	struct arm_smccc_res res;

	/* Switch from the HYP stub to our own HYP init vector */
	__hyp_set_vectors(kvm_get_idmap_vector());

	/*
	 * Calculate the raw per-cpu offset without a translation from the
	 * kernel's mapping to the linear mapping, and store it in tpidr_el2
	 * so that we can use adr_l to access per-cpu variables in EL2.
	 */
	tpidr_el2 = (unsigned long)this_cpu_ptr_nvhe_sym(__per_cpu_start) -
		    (unsigned long)kvm_ksym_ref(CHOOSE_NVHE_SYM(__per_cpu_start));

	pgd_ptr = kvm_mmu_get_httbr();
	hyp_stack_ptr = __this_cpu_read(kvm_arm_hyp_stack_page) + PAGE_SIZE;
	hyp_stack_ptr = kern_hyp_va(hyp_stack_ptr);
	vector_ptr = (unsigned long)kern_hyp_va(kvm_ksym_ref(__kvm_hyp_host_vector));

	/*
	 * Call initialization code, and switch to the full blown HYP code.
	 * If the cpucaps haven't been finalized yet, something has gone very
	 * wrong, and hyp will crash and burn when it uses any
	 * cpus_have_const_cap() wrapper.
	 */
	BUG_ON(!system_capabilities_finalized());
	arm_smccc_1_1_hvc(KVM_HOST_SMCCC_FUNC(__kvm_hyp_init),
			  pgd_ptr, tpidr_el2, hyp_stack_ptr, vector_ptr, &res);
	WARN_ON(res.a0 != SMCCC_RET_SUCCESS);

	/*
	 * Disabling SSBD on a non-VHE system requires us to enable SSBS
	 * at EL2.
	 */
	if (this_cpu_has_cap(ARM64_SSBS) &&
	    arm64_get_spectre_v4_state() == SPECTRE_VULNERABLE) {
		kvm_call_hyp_nvhe(__kvm_enable_ssbs);
	}
}

static void cpu_hyp_reset(void)
{
	if (!is_kernel_in_hyp_mode())
		__hyp_reset_vectors();
}

static void cpu_hyp_reinit(void)
{
	kvm_init_host_cpu_context(&this_cpu_ptr_hyp_sym(kvm_host_data)->host_ctxt);

	cpu_hyp_reset();

	*this_cpu_ptr_hyp_sym(kvm_hyp_vector) = (unsigned long)kvm_get_hyp_vector();

	if (is_kernel_in_hyp_mode())
		kvm_timer_init_vhe();
	else
		cpu_init_hyp_mode();

	kvm_arm_init_debug();

	if (vgic_present)
		kvm_vgic_init_cpu_hardware();
}

static void _kvm_arch_hardware_enable(void *discard)
{
	if (!__this_cpu_read(kvm_arm_hardware_enabled)) {
		cpu_hyp_reinit();
		__this_cpu_write(kvm_arm_hardware_enabled, 1);
	}
}

int kvm_arch_hardware_enable(void)
{
	_kvm_arch_hardware_enable(NULL);
	return 0;
}

static void _kvm_arch_hardware_disable(void *discard)
{
	if (__this_cpu_read(kvm_arm_hardware_enabled)) {
		cpu_hyp_reset();
		__this_cpu_write(kvm_arm_hardware_enabled, 0);
	}
}

void kvm_arch_hardware_disable(void)
{
	_kvm_arch_hardware_disable(NULL);
}

#ifdef CONFIG_CPU_PM
static int hyp_init_cpu_pm_notifier(struct notifier_block *self,
				    unsigned long cmd,
				    void *v)
{
	/*
	 * kvm_arm_hardware_enabled is left with its old value over
	 * PM_ENTER->PM_EXIT. It is used to indicate PM_EXIT should
	 * re-enable hyp.
	 */
	switch (cmd) {
	case CPU_PM_ENTER:
		if (__this_cpu_read(kvm_arm_hardware_enabled))
			/*
			 * don't update kvm_arm_hardware_enabled here
			 * so that the hardware will be re-enabled
			 * when we resume. See below.
			 */
			cpu_hyp_reset();

		return NOTIFY_OK;
	case CPU_PM_ENTER_FAILED:
	case CPU_PM_EXIT:
		if (__this_cpu_read(kvm_arm_hardware_enabled))
			/* The hardware was enabled before suspend. */
			cpu_hyp_reinit();

		return NOTIFY_OK;

	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block hyp_init_cpu_pm_nb = {
	.notifier_call = hyp_init_cpu_pm_notifier,
};

static void __init hyp_cpu_pm_init(void)
{
	cpu_pm_register_notifier(&hyp_init_cpu_pm_nb);
}
static void __init hyp_cpu_pm_exit(void)
{
	cpu_pm_unregister_notifier(&hyp_init_cpu_pm_nb);
}
#else
static inline void hyp_cpu_pm_init(void)
{
}
static inline void hyp_cpu_pm_exit(void)
{
}
#endif

static int init_common_resources(void)
{
	return kvm_set_ipa_limit();
}

static int init_subsystems(void)
{
	int err = 0;

	/*
	 * Enable hardware so that subsystem initialisation can access EL2.
	 */
	on_each_cpu(_kvm_arch_hardware_enable, NULL, 1);

	/*
	 * Register CPU lower-power notifier
	 */
	hyp_cpu_pm_init();

	/*
	 * Init HYP view of VGIC
	 */
	err = kvm_vgic_hyp_init();
	switch (err) {
	case 0:
		vgic_present = true;
		break;
	case -ENODEV:
	case -ENXIO:
		vgic_present = false;
		err = 0;
		break;
	default:
		goto out;
	}

	/*
	 * Init HYP architected timer support
	 */
	err = kvm_timer_hyp_init(vgic_present);
	if (err)
		goto out;

	kvm_perf_init();
	kvm_coproc_table_init();

out:
	on_each_cpu(_kvm_arch_hardware_disable, NULL, 1);

	return err;
}

static void teardown_hyp_mode(void)
{
	int cpu;

	free_hyp_pgds();
	for_each_possible_cpu(cpu) {
		free_page(per_cpu(kvm_arm_hyp_stack_page, cpu));
		free_pages(kvm_arm_hyp_percpu_base[cpu], nvhe_percpu_order());
	}
}

/**
 * Inits Hyp-mode on all online CPUs
 */
static int init_hyp_mode(void)
{
	int cpu;
	int err = 0;

	/*
	 * Allocate Hyp PGD and setup Hyp identity mapping
	 */
	err = kvm_mmu_init();
	if (err)
		goto out_err;

	/*
	 * Allocate stack pages for Hypervisor-mode
	 */
	for_each_possible_cpu(cpu) {
		unsigned long stack_page;

		stack_page = __get_free_page(GFP_KERNEL);
		if (!stack_page) {
			err = -ENOMEM;
			goto out_err;
		}

		per_cpu(kvm_arm_hyp_stack_page, cpu) = stack_page;
	}

	/*
	 * Allocate and initialize pages for Hypervisor-mode percpu regions.
	 */
	for_each_possible_cpu(cpu) {
		struct page *page;
		void *page_addr;

		page = alloc_pages(GFP_KERNEL, nvhe_percpu_order());
		if (!page) {
			err = -ENOMEM;
			goto out_err;
		}

		page_addr = page_address(page);
		memcpy(page_addr, CHOOSE_NVHE_SYM(__per_cpu_start), nvhe_percpu_size());
		kvm_arm_hyp_percpu_base[cpu] = (unsigned long)page_addr;
	}

	/*
	 * Map the Hyp-code called directly from the host
	 */
	err = create_hyp_mappings(kvm_ksym_ref(__hyp_text_start),
				  kvm_ksym_ref(__hyp_text_end), PAGE_HYP_EXEC);
	if (err) {
		kvm_err("Cannot map world-switch code\n");
		goto out_err;
	}

	err = create_hyp_mappings(kvm_ksym_ref(__start_rodata),
				  kvm_ksym_ref(__end_rodata), PAGE_HYP_RO);
	if (err) {
		kvm_err("Cannot map rodata section\n");
		goto out_err;
	}

	err = create_hyp_mappings(kvm_ksym_ref(__bss_start),
				  kvm_ksym_ref(__bss_stop), PAGE_HYP_RO);
	if (err) {
		kvm_err("Cannot map bss section\n");
		goto out_err;
	}

	err = kvm_map_vectors();
	if (err) {
		kvm_err("Cannot map vectors\n");
		goto out_err;
	}

	/*
	 * Map the Hyp stack pages
	 */
	for_each_possible_cpu(cpu) {
		char *stack_page = (char *)per_cpu(kvm_arm_hyp_stack_page, cpu);
		err = create_hyp_mappings(stack_page, stack_page + PAGE_SIZE,
					  PAGE_HYP);

		if (err) {
			kvm_err("Cannot map hyp stack\n");
			goto out_err;
		}
	}

	/*
	 * Map Hyp percpu pages
	 */
	for_each_possible_cpu(cpu) {
		char *percpu_begin = (char *)kvm_arm_hyp_percpu_base[cpu];
		char *percpu_end = percpu_begin + nvhe_percpu_size();

		err = create_hyp_mappings(percpu_begin, percpu_end, PAGE_HYP);

		if (err) {
			kvm_err("Cannot map hyp percpu region\n");
			goto out_err;
		}
	}

	return 0;

out_err:
	teardown_hyp_mode();
	kvm_err("error initializing Hyp mode: %d\n", err);
	return err;
}

static void check_kvm_target_cpu(void *ret)
{
	*(int *)ret = kvm_target_cpu();
}

struct kvm_vcpu *kvm_mpidr_to_vcpu(struct kvm *kvm, unsigned long mpidr)
{
	struct kvm_vcpu *vcpu;
	int i;

	mpidr &= MPIDR_HWID_BITMASK;
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (mpidr == kvm_vcpu_get_mpidr_aff(vcpu))
			return vcpu;
	}
	return NULL;
}

bool kvm_arch_has_irq_bypass(void)
{
	return true;
}

int kvm_arch_irq_bypass_add_producer(struct irq_bypass_consumer *cons,
				      struct irq_bypass_producer *prod)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);

	return kvm_vgic_v4_set_forwarding(irqfd->kvm, prod->irq,
					  &irqfd->irq_entry);
}
void kvm_arch_irq_bypass_del_producer(struct irq_bypass_consumer *cons,
				      struct irq_bypass_producer *prod)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);

	kvm_vgic_v4_unset_forwarding(irqfd->kvm, prod->irq,
				     &irqfd->irq_entry);
}

void kvm_arch_irq_bypass_stop(struct irq_bypass_consumer *cons)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);

	kvm_arm_halt_guest(irqfd->kvm);
}

void kvm_arch_irq_bypass_start(struct irq_bypass_consumer *cons)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);

	kvm_arm_resume_guest(irqfd->kvm);
}

void kvm_arch_pre_destroy_vm(struct kvm *kvm)
{
	kvm_shadow_dev_delete_all(kvm);
}

/**
 * Initialize Hyp-mode and memory mappings on all CPUs.
 */
int kvm_arch_init(void *opaque)
{
	int err;
	int ret, cpu;
	bool in_hyp_mode;

	if (!is_hyp_mode_available()) {
		kvm_info("HYP mode not available\n");
		return -ENODEV;
	}

#ifdef CONFIG_KVM_HISI_VIRT
	probe_hisi_cpu_type();
	kvm_ncsnp_support = hisi_ncsnp_supported();
	kvm_dvmbm_support = hisi_dvmbm_supported();
	if (kvm_dvmbm_support)
		kvm_get_pg_cfg();
#endif
	kvm_info("KVM ncsnp %s\n", kvm_ncsnp_support ? "enabled" : "disabled");
	kvm_info("KVM dvmbm %s\n", kvm_dvmbm_support ? "enabled" : "disabled");

	in_hyp_mode = is_kernel_in_hyp_mode();

	if (!in_hyp_mode && kvm_arch_requires_vhe()) {
		kvm_pr_unimpl("CPU unsupported in non-VHE mode, not initializing\n");
		return -ENODEV;
	}
#ifdef CONFIG_CVM_HOST
	if (static_branch_unlikely(&kvm_cvm_is_enable) && in_hyp_mode) {
		err = kvm_init_tmm();
		if (err)
			return err;
	}
#endif
	if (cpus_have_final_cap(ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE) ||
	    cpus_have_final_cap(ARM64_WORKAROUND_1508412))
		kvm_info("Guests without required CPU erratum workarounds can deadlock system!\n" \
			 "Only trusted guests should be used on this system.\n");

	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, check_kvm_target_cpu, &ret, 1);
		if (ret < 0) {
			kvm_err("Error, CPU %d not supported!\n", cpu);
			return -ENODEV;
		}
	}

	err = init_common_resources();
	if (err)
		return err;

	err = kvm_arm_init_sve();
	if (err)
		return err;

	if (!in_hyp_mode) {
		err = init_hyp_mode();
		if (err)
			goto out_err;
	}

	err = init_subsystems();
	if (err)
		goto out_hyp;

	if (in_hyp_mode)
		kvm_info("VHE mode initialized successfully\n");
	else
		kvm_info("Hyp mode initialized successfully\n");

	kvm_shadow_dev_init();

	return 0;

out_hyp:
	hyp_cpu_pm_exit();
	if (!in_hyp_mode)
		teardown_hyp_mode();
out_err:
	return err;
}

/* NOP: Compiling as a module not supported */
void kvm_arch_exit(void)
{
	kvm_perf_teardown();
}

static int arm_init(void)
{
	int rc = kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);
	return rc;
}

module_init(arm_init);
