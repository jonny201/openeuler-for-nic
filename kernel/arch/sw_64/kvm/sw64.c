// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/mman.h>
#include <linux/sched/signal.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/msi.h>
#include <asm/kvm_timer.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/barrier.h>
#include <asm/core.h>
#include <asm/pci_impl.h>
#include <asm/cpu.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

bool set_msi_flag;
bool feature_vint;
extern struct smp_rcb_struct *smp_rcb;

#define DFX_STAT(n, x, ...) \
	{ n, offsetof(struct kvm_vcpu_stat, x), DFX_STAT_U64, ## __VA_ARGS__ }

static unsigned long get_new_vpn_context(struct kvm_vcpu *vcpu, long cpu)
{
	unsigned long vpn = last_vpn(cpu);
	unsigned long next = vpn + 1;

	if ((vpn & VPN_MASK) >= VPN_MASK) {
		kvm_flush_tlb_all();
		next = (vpn & ~VPN_MASK) + VPN_FIRST_VERSION + 1; /* bypass 0 */
	}
	last_vpn(cpu) = next;
	return next;
}

int kvm_arch_set_irq_inatomic(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	switch (e->type) {
	case KVM_IRQ_ROUTING_MSI:
		if (!kvm_set_msi(e, kvm, irq_source_id, level, line_status))
			return 0;
		break;
	default:
		break;
	}
	return -EWOULDBLOCK;
}

int kvm_arch_check_processor_compat(void *opaque)
{
	return 0;
}

int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e, struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	unsigned int dest_id;
	struct kvm_vcpu *vcpu = NULL;
	int vector = e->msi.data & 0xff;

	dest_id = (e->msi.address_lo & VT_MSIX_ADDR_DEST_ID_MASK) >> VT_MSIX_ADDR_DEST_ID_SHIFT;
	vcpu = kvm_get_vcpu(kvm, dest_id);

	if (!vcpu)
		return -EINVAL;

	return vcpu_interrupt_line(vcpu, vector);
}

void sw64_kvm_switch_vpn(struct kvm_vcpu *vcpu)
{
	unsigned long vpn;
	unsigned long vpnc;
	long cpu = smp_processor_id();

	vpn = last_vpn(cpu);
	vpnc = vcpu->arch.vpnc[cpu];

	if ((vpnc ^ vpn) & ~VPN_MASK) {
		/* vpnc and cpu vpn not in the same version, get new vpnc and vpn */
		vpnc = get_new_vpn_context(vcpu, cpu);
		vcpu->arch.vpnc[cpu] = vpnc;
	}

	vpn = vpnc & VPN_MASK;

	/* Always update vpn */
	/* Just setup vcb, hardware CSR will be changed later in HMcode */
	kvm_sw64_update_vpn(vcpu, vpn);

	/*
	 * If vcpu migrate to a new physical cpu, the new physical cpu may keep
	 * old tlb entries for this vcpu's vpn, upn in the old tlb entries and
	 * current vcpu's upn may not in the same version.
	 * For now, we don't know the vcpu's upn version and the current version.
	 * If we keep track of the vcpu's upn version, the TLB-flush could be less.
	 * To be safe and correct, flush all tlb entries of current vpn for now.
	 */

	if (vcpu->arch.pcpu_id != cpu) {
		tbivpn(0, 0, vpn);
		vcpu->arch.pcpu_id = cpu;
		vcpu->cpu = cpu;
	}
}

void check_vcpu_requests(struct kvm_vcpu *vcpu)
{
	unsigned long vpn;
	long cpu = smp_processor_id();

	if (kvm_request_pending(vcpu)) {
		if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu)) {
			vpn = vcpu->arch.vpnc[cpu] & VPN_MASK;
			tbivpn(0, 0, vpn);
		}
	}
}

struct kvm_stats_debugfs_item debugfs_entries[] = {
	VCPU_STAT("exits", exits),
	VCPU_STAT("io_exits", io_exits),
	VCPU_STAT("mmio_exits", mmio_exits),
	VCPU_STAT("migration_set_dirty", migration_set_dirty),
	VCPU_STAT("shutdown_exits", shutdown_exits),
	VCPU_STAT("restart_exits", restart_exits),
	VCPU_STAT("ipi_exits", ipi_exits),
	VCPU_STAT("timer_exits", timer_exits),
	VCPU_STAT("debug_exits", debug_exits),
	VCPU_STAT("fatal_error_exits", fatal_error_exits),
	VCPU_STAT("halt_exits", halt_exits),
	VCPU_STAT("halt_successful_poll", halt_successful_poll),
	VCPU_STAT("halt_attempted_poll", halt_attempted_poll),
	VCPU_STAT("halt_wakeup", halt_wakeup),
	VCPU_STAT("halt_poll_invalid", halt_poll_invalid),
	VCPU_STAT("signal_exits", signal_exits),
	{ "vcpu_stat", 0, KVM_STAT_DFX },
	{ NULL }
};

struct dfx_kvm_stats_debugfs_item dfx_debugfs_entries[] = {
	DFX_STAT("pid", pid),
	DFX_STAT("exits", exits),
	DFX_STAT("io_exits", io_exits),
	DFX_STAT("mmio_exits", mmio_exits),
	DFX_STAT("migration_set_dirty", migration_set_dirty),
	DFX_STAT("shutdown_exits", shutdown_exits),
	DFX_STAT("restart_exits", restart_exits),
	DFX_STAT("ipi_exits", ipi_exits),
	DFX_STAT("timer_exits", timer_exits),
	DFX_STAT("debug_exits", debug_exits),
	DFX_STAT("fatal_error_exits", fatal_error_exits),
	DFX_STAT("halt_exits", halt_exits),
	DFX_STAT("halt_successful_poll", halt_successful_poll),
	DFX_STAT("halt_attempted_poll", halt_attempted_poll),
	DFX_STAT("halt_wakeup", halt_wakeup),
	DFX_STAT("halt_poll_invalid", halt_poll_invalid),
	DFX_STAT("signal_exits", signal_exits),
	DFX_STAT("steal", steal),
	DFX_STAT("st_max", st_max),
	DFX_STAT("utime", utime),
	DFX_STAT("stime", stime),
	DFX_STAT("gtime", gtime),
	{ NULL }
};

int kvm_arch_hardware_enable(void)
{
	return 0;
}

void kvm_arch_hardware_unsetup(void)
{
}

bool kvm_arch_vcpu_in_kernel(struct kvm_vcpu *vcpu)
{
	return false;
}

bool kvm_arch_has_vcpu_debugfs(void)
{
	return false;
}

int kvm_arch_create_vcpu_debugfs(struct kvm_vcpu *vcpu)
{
	return 0;
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return kvm_vcpu_exiting_guest_mode(vcpu) == IN_GUEST_MODE;
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r = 0;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_SET_GUEST_DEBUG:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	default:
		r = 0;
	}

	return r;
}

void kvm_arch_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{
}

int kvm_arch_hardware_setup(void *opaque)
{
	return 0;
}

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	if (type)
		return -EINVAL;

	feature_vint = (cpuid(GET_FEATURES, 0) & CPU_FEAT_VINT);
	smp_rcb->feat_vint = 1;
	return kvm_sw64_init_vm(kvm);
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	return kvm_sw64_destroy_vm(kvm);
}

long kvm_arch_dev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

int kvm_arch_create_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
		unsigned long npages)
{
	return 0;
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	kvm_mmu_free_memory_cache(&vcpu->arch.mmu_page_cache);
	hrtimer_cancel(&vcpu->arch.hrt);
	kfree(vcpu);
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_free(vcpu);
}

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	/* Set up the timer for Guest */
	pr_info("vcpu: [%d], regs addr = %#lx, vcpucb = %#lx\n", vcpu->vcpu_id,
			(unsigned long)&vcpu->arch.regs, (unsigned long)&vcpu->arch.vcb);
	vcpu->arch.mmu_page_cache.gfp_zero = __GFP_ZERO;
	vcpu->arch.vtimer_freq = cpuid(GET_CPU_FREQ, 0) * 1000UL * 1000UL;
	hrtimer_init(&vcpu->arch.hrt, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	vcpu->arch.hrt.function = clockdev_fn;
	vcpu->arch.tsk = current;
	vcpu->arch.pcpu_id = -1; /* force flush tlb for the first time */

	return 0;
}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	return 0;
}

int kvm_set_routing_entry(struct kvm *kvm,
		struct kvm_kernel_irq_routing_entry *e,
		const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;

	switch (ue->type) {
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		e->msi.flags = ue->flags;
		e->msi.devid = ue->u.msi.devid;
		set_msi_flag = true;
		break;
	default:
		goto out;
	}
	r = 0;
out:
	return r;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
		struct kvm_translation *tr)
{
	return -EINVAL; /* not implemented yet */
}

int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	return 0;
}

void kvm_arch_vcpu_stat_reset(struct kvm_vcpu_stat *vcpu_stat)
{
	vcpu_stat->st_max = 0;
}

static void update_steal_time(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_SCHED_INFO
	u64 delta;

	delta = current->sched_info.run_delay - vcpu->stat.steal;
	vcpu->stat.steal = current->sched_info.run_delay;
	vcpu->stat.st_max = max(vcpu->stat.st_max, delta);
#endif
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	vcpu->cpu = cpu;
	update_steal_time(vcpu);
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	/*
	 * The arch-generic KVM code expects the cpu field of a vcpu to be -1
	 * if the vcpu is no longer assigned to a cpu.  This is used for the
	 * optimized make_all_cpus_request path.
	 */
	vcpu->cpu = -1;
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
		struct kvm_mp_state *mp_state)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
		struct kvm_mp_state *mp_state)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	memcpy(&(vcpu->arch.regs), regs, sizeof(struct kvm_regs));
	return 0;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	memcpy(regs, &(vcpu->arch.regs), sizeof(struct kvm_regs));
	return 0;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
						struct kvm_guest_debug *dbg)
{
	trace_kvm_set_guest_debug(vcpu, dbg->control);
	return 0;
}

void update_vcpu_stat_time(struct kvm_vcpu_stat *vcpu_stat)
{
	vcpu_stat->utime = current->utime;
	vcpu_stat->stime = current->stime;
	vcpu_stat->gtime = current->gtime;
}

/*
 * Return > 0 to return to guest, < 0 on error, 0 (and set exit_reason) on
 * proper exit to userspace.
 */
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	struct vcpucb *vcb = &(vcpu->arch.vcb);
	struct hcall_args hargs;
	int ret;
	sigset_t sigsaved;

	/* Set guest vcb */
	/* vpn will update later when vcpu is running */
	vcpu_set_numa_affinity(vcpu);
#ifdef CONFIG_PERF_EVENTS
	vcpu_load(vcpu);
#endif
	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	if (run->exit_reason == KVM_EXIT_MMIO)
		kvm_handle_mmio_return(vcpu, run);

	run->exit_reason = KVM_EXIT_UNKNOWN;
	ret = 1;
	while (ret > 0) {
		/* Check conditions before entering the guest */
		cond_resched();

		preempt_disable();
		local_irq_disable();

		if (signal_pending(current)) {
			ret = -EINTR;
			run->exit_reason = KVM_EXIT_INTR;
			vcpu->stat.signal_exits++;
		}

		if (ret <= 0) {
			local_irq_enable();
			preempt_enable();
			continue;
		}

		memset(&hargs, 0, sizeof(hargs));

		if (vcpu->arch.restart == 1) {
			/* handle reset vCPU */
			vcpu->arch.regs.pc = GUEST_RESET_PC;
			vcpu->arch.restart = 0;
		}

		sw64_kvm_try_deliver_interrupt(vcpu);

		vcpu->arch.halted = 0;

		sw64_kvm_switch_vpn(vcpu);
		check_vcpu_requests(vcpu);
		guest_enter_irqoff();

		/* update aptp before the guest runs */
		update_aptp((unsigned long)vcpu->kvm->arch.pgd);

		/* Enter the guest */
		trace_kvm_sw64_entry(vcpu->vcpu_id, vcpu->arch.regs.pc);
		vcpu->mode = IN_GUEST_MODE;

		ret = __sw64_vcpu_run(__pa(vcb), &(vcpu->arch.regs), &hargs);

		/* Back from guest */
		vcpu->mode = OUTSIDE_GUEST_MODE;

		vcpu->stat.exits++;
		local_irq_enable();
		guest_exit_irqoff();

		trace_kvm_sw64_exit(ret, vcpu->arch.regs.pc);

		preempt_enable();

		/* ret = 0 indicate interrupt in guest mode, ret > 0 indicate hcall */
		ret = handle_exit(vcpu, run, ret, &hargs);
		update_vcpu_stat_time(&vcpu->stat);
	}

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

#ifdef CONFIG_PERF_EVENTS
	vcpu_put(vcpu);
#endif

	return ret;
}

long kvm_arch_vcpu_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	int r;

	switch (ioctl) {
	case KVM_SW64_VCPU_INIT:
		r = kvm_sw64_vcpu_reset(vcpu);
		break;
	case KVM_SW64_GET_VCB:
		r = kvm_sw64_get_vcb(filp, arg);
		break;
	case KVM_SW64_SET_VCB:
		r = kvm_sw64_set_vcb(filp, arg);
		break;
	default:
		r =  -EINVAL;
	}

	return r;
}

long kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm __maybe_unused = filp->private_data;
	long r;

	switch (ioctl) {
	case KVM_CREATE_IRQCHIP: {
		struct kvm_irq_routing_entry routing;

		r = -EINVAL;
		memset(&routing, 0, sizeof(routing));
		r = kvm_set_irq_routing(kvm, &routing, 0, 0);
		break;
	}
	default:
		r = -ENOIOCTLCMD;
	}
	return r;
}

int kvm_arch_init(void *opaque)
{
	kvm_sw64_perf_init();
	return 0;
}

void kvm_arch_exit(void)
{
	kvm_sw64_perf_teardown();
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
		struct kvm_sregs *sregs)
{
	return -ENOIOCTLCMD;
}

void kvm_arch_vcpu_postcreate(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOIOCTLCMD;
}

vm_fault_t kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					struct kvm_memory_slot *memslot)
{
	kvm_flush_remote_tlbs(kvm);
}

int kvm_dev_ioctl_check_extension(long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_IOEVENTFD:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	default:
		r = 0;
	}

	return r;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level,
		bool line_status)
{
	u32 irq = irq_level->irq;
	unsigned int irq_num;
	struct kvm_vcpu *vcpu = NULL;

	irq_num = irq;
	trace_kvm_irq_line(0, irq_num, irq_level->level);

	/* target core for Intx is core0 */
	vcpu = kvm_get_vcpu(kvm, 0);
	if (!vcpu)
		return -EINVAL;

	return vcpu_interrupt_line(vcpu, irq_num);
}

