// SPDX-License-Identifier: GPL-2.0
/*
 * IOMMU API for ARM architected SMMUv3 implementations.
 *
 * Copyright (C) 2015 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 *
 * This driver is powered by bad coffee and bombay mix.
 */

#include <linux/acpi.h>
#include <linux/acpi_iort.h>
#include <linux/arm-smmu.h>
#include <linux/bitops.h>
#include <linux/crash_dump.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io-pgtable.h>
#include <linux/ioasid.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/pci-ats.h>
#include <linux/platform_device.h>

#include <linux/amba/bus.h>

#include "arm-smmu-v3.h"
#include "../../iommu-sva-lib.h"

static bool disable_bypass = true;
module_param(disable_bypass, bool, 0444);
MODULE_PARM_DESC(disable_bypass,
	"Disable bypass streams such that incoming transactions from devices that are not attached to an iommu domain will report an abort back to the device and will not be allowed to pass through the SMMU.");

static bool disable_msipolling;
module_param(disable_msipolling, bool, 0444);
MODULE_PARM_DESC(disable_msipolling,
	"Disable MSI-based polling for CMD_SYNC completion.");

static bool disable_ecmdq;
module_param(disable_ecmdq, bool, 0444);
MODULE_PARM_DESC(disable_ecmdq,	"Disable the use of ECMDQs");

#ifdef CONFIG_SMMU_BYPASS_DEV
struct smmu_bypass_device {
	unsigned short vendor;
	unsigned short device;
};
#define MAX_CMDLINE_SMMU_BYPASS_DEV 16

static struct smmu_bypass_device smmu_bypass_devices[MAX_CMDLINE_SMMU_BYPASS_DEV];
static int smmu_bypass_devices_num;

static int __init arm_smmu_bypass_dev_setup(char *str)
{
	unsigned short vendor;
	unsigned short device;
	int ret;

	if (!str)
		return -EINVAL;

	ret = sscanf(str, "%hx:%hx", &vendor, &device);
	if (ret != 2)
		return -EINVAL;

	if (smmu_bypass_devices_num >= MAX_CMDLINE_SMMU_BYPASS_DEV)
		return -ERANGE;

	smmu_bypass_devices[smmu_bypass_devices_num].vendor = vendor;
	smmu_bypass_devices[smmu_bypass_devices_num].device = device;
	smmu_bypass_devices_num++;

	return 0;
}

__setup("smmu.bypassdev=", arm_smmu_bypass_dev_setup);
#endif

enum arm_smmu_msi_index {
	EVTQ_MSI_INDEX,
	GERROR_MSI_INDEX,
	PRIQ_MSI_INDEX,
	ARM_SMMU_MAX_MSIS,
};

static phys_addr_t arm_smmu_msi_cfg[ARM_SMMU_MAX_MSIS][3] = {
	[EVTQ_MSI_INDEX] = {
		ARM_SMMU_EVTQ_IRQ_CFG0,
		ARM_SMMU_EVTQ_IRQ_CFG1,
		ARM_SMMU_EVTQ_IRQ_CFG2,
	},
	[GERROR_MSI_INDEX] = {
		ARM_SMMU_GERROR_IRQ_CFG0,
		ARM_SMMU_GERROR_IRQ_CFG1,
		ARM_SMMU_GERROR_IRQ_CFG2,
	},
	[PRIQ_MSI_INDEX] = {
		ARM_SMMU_PRIQ_IRQ_CFG0,
		ARM_SMMU_PRIQ_IRQ_CFG1,
		ARM_SMMU_PRIQ_IRQ_CFG2,
	},
};

struct arm_smmu_option_prop {
	u32 opt;
	const char *prop;
};

DEFINE_XARRAY_ALLOC1(arm_smmu_asid_xa);
DEFINE_MUTEX(arm_smmu_asid_lock);
static DECLARE_IOASID_SET(private_ioasid);

/*
 * Special value used by SVA when a process dies, to quiesce a CD without
 * disabling it.
 */
struct arm_smmu_ctx_desc quiet_cd = { 0 };

static struct arm_smmu_option_prop arm_smmu_options[] = {
	{ ARM_SMMU_OPT_SKIP_PREFETCH, "hisilicon,broken-prefetch-cmd" },
	{ ARM_SMMU_OPT_PAGE0_REGS_ONLY, "cavium,cn9900-broken-page1-regspace"},
	{ ARM_SMMU_OPT_SYNC_MAP, "hisilicon,broken-prefetch-pgtbl"},
	{ 0, NULL},
};

static void parse_driver_options(struct arm_smmu_device *smmu)
{
	int i = 0;

	do {
		if (of_property_read_bool(smmu->dev->of_node,
						arm_smmu_options[i].prop)) {
			smmu->options |= arm_smmu_options[i].opt;
			dev_notice(smmu->dev, "option %s\n",
				arm_smmu_options[i].prop);
		}
	} while (arm_smmu_options[++i].opt);
}

/* Low-level queue manipulation functions */
static bool queue_has_space(struct arm_smmu_ll_queue *q, u32 n)
{
	u32 space, prod, cons;

	prod = Q_IDX(q, q->prod);
	cons = Q_IDX(q, q->cons);

	if (Q_WRP(q, q->prod) == Q_WRP(q, q->cons))
		space = (1 << q->max_n_shift) - (prod - cons);
	else
		space = cons - prod;

	return space >= n;
}

static bool queue_full(struct arm_smmu_ll_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) != Q_WRP(q, q->cons);
}

static bool queue_empty(struct arm_smmu_ll_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) == Q_WRP(q, q->cons);
}

static bool queue_consumed(struct arm_smmu_ll_queue *q, u32 prod)
{
	return ((Q_WRP(q, q->cons) == Q_WRP(q, prod)) &&
		(Q_IDX(q, q->cons) > Q_IDX(q, prod))) ||
	       ((Q_WRP(q, q->cons) != Q_WRP(q, prod)) &&
		(Q_IDX(q, q->cons) <= Q_IDX(q, prod)));
}

static void queue_sync_cons_out(struct arm_smmu_queue *q)
{
	/*
	 * Ensure that all CPU accesses (reads and writes) to the queue
	 * are complete before we update the cons pointer.
	 */
	__iomb();
	writel_relaxed(q->llq.cons, q->cons_reg);
}

static void queue_inc_cons(struct arm_smmu_ll_queue *q)
{
	u32 cons = (Q_WRP(q, q->cons) | Q_IDX(q, q->cons)) + 1;
	q->cons = Q_OVF(q->cons) | Q_WRP(q, cons) | Q_IDX(q, cons);
}

static void queue_sync_cons_ovf(struct arm_smmu_queue *q)
{
	struct arm_smmu_ll_queue *llq = &q->llq;

	if (likely(Q_OVF(llq->prod) == Q_OVF(llq->cons)))
		return;

	llq->cons = Q_OVF(llq->prod) | Q_WRP(llq, llq->cons) |
		      Q_IDX(llq, llq->cons);
	queue_sync_cons_out(q);
}

static int queue_sync_prod_in(struct arm_smmu_queue *q)
{
	u32 prod;
	int ret = 0;

	/*
	 * We can't use the _relaxed() variant here, as we must prevent
	 * speculative reads of the queue before we have determined that
	 * prod has indeed moved.
	 */
	prod = readl(q->prod_reg);

	if (Q_OVF(prod) != Q_OVF(q->llq.prod))
		ret = -EOVERFLOW;

	q->llq.prod = prod;
	return ret;
}

static u32 queue_inc_prod_n(struct arm_smmu_ll_queue *q, int n)
{
	u32 prod = (Q_WRP(q, q->prod) | Q_IDX(q, q->prod)) + n;
	return Q_OVF(q->prod) | Q_WRP(q, prod) | Q_IDX(q, prod);
}

static void queue_poll_init(struct arm_smmu_device *smmu,
			    struct arm_smmu_queue_poll *qp)
{
	qp->delay = 1;
	qp->spin_cnt = 0;
	qp->wfe = !!(smmu->features & ARM_SMMU_FEAT_SEV);
	qp->timeout = ktime_add_us(ktime_get(), ARM_SMMU_POLL_TIMEOUT_US);
}

static int queue_poll(struct arm_smmu_queue_poll *qp)
{
	if (ktime_compare(ktime_get(), qp->timeout) > 0)
		return -ETIMEDOUT;

	if (qp->wfe) {
		wfe();
	} else if (++qp->spin_cnt < ARM_SMMU_POLL_SPIN_COUNT) {
		cpu_relax();
	} else {
		udelay(qp->delay);
		qp->delay *= 2;
		qp->spin_cnt = 0;
	}

	return 0;
}

static void queue_write(__le64 *dst, u64 *src, size_t n_dwords)
{
	int i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = cpu_to_le64(*src++);
}

static void queue_read(u64 *dst, __le64 *src, size_t n_dwords)
{
	int i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = le64_to_cpu(*src++);
}

static int queue_remove_raw(struct arm_smmu_queue *q, u64 *ent)
{
	if (queue_empty(&q->llq))
		return -EAGAIN;

	queue_read(ent, Q_ENT(q, q->llq.cons), q->ent_dwords);
	queue_inc_cons(&q->llq);
	queue_sync_cons_out(q);
	return 0;
}

static void arm_smmu_preempt_disable(struct arm_smmu_device *smmu)
{
	if (smmu->ecmdq_enabled)
		preempt_disable();
}

static void arm_smmu_preempt_enable(struct arm_smmu_device *smmu)
{
	if (smmu->ecmdq_enabled)
		preempt_enable();
}

/* High-level queue accessors */
static int arm_smmu_cmdq_build_cmd(u64 *cmd, struct arm_smmu_cmdq_ent *ent)
{
	memset(cmd, 0, 1 << CMDQ_ENT_SZ_SHIFT);
	cmd[0] |= FIELD_PREP(CMDQ_0_OP, ent->opcode);

	switch (ent->opcode) {
	case CMDQ_OP_TLBI_EL2_ALL:
	case CMDQ_OP_TLBI_NSNH_ALL:
		break;
	case CMDQ_OP_PREFETCH_CFG:
		cmd[0] |= FIELD_PREP(CMDQ_PREFETCH_0_SID, ent->prefetch.sid);
		cmd[1] |= FIELD_PREP(CMDQ_PREFETCH_1_SIZE, ent->prefetch.size);
		cmd[1] |= ent->prefetch.addr & CMDQ_PREFETCH_1_ADDR_MASK;
		break;
	case CMDQ_OP_CFGI_CD:
		cmd[0] |= FIELD_PREP(CMDQ_CFGI_0_SSID, ent->cfgi.ssid);
		fallthrough;
	case CMDQ_OP_CFGI_STE:
		cmd[0] |= FIELD_PREP(CMDQ_CFGI_0_SID, ent->cfgi.sid);
		cmd[1] |= FIELD_PREP(CMDQ_CFGI_1_LEAF, ent->cfgi.leaf);
		break;
	case CMDQ_OP_CFGI_CD_ALL:
		cmd[0] |= FIELD_PREP(CMDQ_CFGI_0_SID, ent->cfgi.sid);
		break;
	case CMDQ_OP_CFGI_ALL:
		/* Cover the entire SID range */
		cmd[1] |= FIELD_PREP(CMDQ_CFGI_1_RANGE, 31);
		break;
	case CMDQ_OP_TLBI_NH_VA:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_VMID, ent->tlbi.vmid);
		fallthrough;
	case CMDQ_OP_TLBI_EL2_VA:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_ASID, ent->tlbi.asid);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_LEAF, ent->tlbi.leaf);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_TTL, ent->tlbi.ttl);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_TG, ent->tlbi.tg);
		cmd[1] |= ent->tlbi.addr & CMDQ_TLBI_1_VA_MASK;
		break;
	case CMDQ_OP_TLBI_S2_IPA:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_VMID, ent->tlbi.vmid);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_LEAF, ent->tlbi.leaf);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_TTL, ent->tlbi.ttl);
		cmd[1] |= FIELD_PREP(CMDQ_TLBI_1_TG, ent->tlbi.tg);
		cmd[1] |= ent->tlbi.addr & CMDQ_TLBI_1_IPA_MASK;
		break;
	case CMDQ_OP_TLBI_NH_ASID:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_ASID, ent->tlbi.asid);
		fallthrough;
	case CMDQ_OP_TLBI_S12_VMALL:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_VMID, ent->tlbi.vmid);
		break;
	case CMDQ_OP_TLBI_EL2_ASID:
		cmd[0] |= FIELD_PREP(CMDQ_TLBI_0_ASID, ent->tlbi.asid);
		break;
	case CMDQ_OP_ATC_INV:
		cmd[0] |= FIELD_PREP(CMDQ_0_SSV, ent->substream_valid);
		cmd[0] |= FIELD_PREP(CMDQ_ATC_0_GLOBAL, ent->atc.global);
		cmd[0] |= FIELD_PREP(CMDQ_ATC_0_SSID, ent->atc.ssid);
		cmd[0] |= FIELD_PREP(CMDQ_ATC_0_SID, ent->atc.sid);
		cmd[1] |= FIELD_PREP(CMDQ_ATC_1_SIZE, ent->atc.size);
		cmd[1] |= ent->atc.addr & CMDQ_ATC_1_ADDR_MASK;
		break;
	case CMDQ_OP_PRI_RESP:
		cmd[0] |= FIELD_PREP(CMDQ_0_SSV, ent->substream_valid);
		cmd[0] |= FIELD_PREP(CMDQ_PRI_0_SSID, ent->pri.ssid);
		cmd[0] |= FIELD_PREP(CMDQ_PRI_0_SID, ent->pri.sid);
		cmd[1] |= FIELD_PREP(CMDQ_PRI_1_GRPID, ent->pri.grpid);
		cmd[1] |= FIELD_PREP(CMDQ_PRI_1_RESP, ent->pri.resp);
		break;
	case CMDQ_OP_RESUME:
		cmd[0] |= FIELD_PREP(CMDQ_RESUME_0_SID, ent->resume.sid);
		cmd[0] |= FIELD_PREP(CMDQ_RESUME_0_RESP, ent->resume.resp);
		cmd[1] |= FIELD_PREP(CMDQ_RESUME_1_STAG, ent->resume.stag);
		break;
	case CMDQ_OP_CMD_SYNC:
		if (ent->sync.msiaddr) {
			cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_CS, CMDQ_SYNC_0_CS_IRQ);
			cmd[1] |= ent->sync.msiaddr & CMDQ_SYNC_1_MSIADDR_MASK;
		} else {
			cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_CS, CMDQ_SYNC_0_CS_SEV);
		}
		cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_MSH, ARM_SMMU_SH_ISH);
		cmd[0] |= FIELD_PREP(CMDQ_SYNC_0_MSIATTR, ARM_SMMU_MEMATTR_OIWB);
		break;
	default:
		return -ENOENT;
	}

	return 0;
}

static struct arm_smmu_cmdq *arm_smmu_get_cmdq(struct arm_smmu_device *smmu)
{
	if (smmu->ecmdq_enabled) {
		struct arm_smmu_ecmdq *ecmdq;

		ecmdq = *this_cpu_ptr(smmu->ecmdqs);

		return &ecmdq->cmdq;
	}

	return &smmu->cmdq;
}

static void arm_smmu_cmdq_build_sync_cmd(u64 *cmd, struct arm_smmu_device *smmu,
					 struct arm_smmu_queue *q, u32 prod)
{
	struct arm_smmu_cmdq_ent ent = {
		.opcode = CMDQ_OP_CMD_SYNC,
	};

	/*
	 * Beware that Hi16xx adds an extra 32 bits of goodness to its MSI
	 * payload, so the write will zero the entire command on that platform.
	 */
	if (smmu->options & ARM_SMMU_OPT_MSIPOLL) {
		ent.sync.msiaddr = q->base_dma + Q_IDX(&q->llq, prod) *
				   q->ent_dwords * 8;
	}

	arm_smmu_cmdq_build_cmd(cmd, &ent);
}

static void __arm_smmu_cmdq_skip_err(struct arm_smmu_device *smmu,
				     struct arm_smmu_queue *q)
{
	static const char *cerror_str[] = {
		[CMDQ_ERR_CERROR_NONE_IDX]	= "No error",
		[CMDQ_ERR_CERROR_ILL_IDX]	= "Illegal command",
		[CMDQ_ERR_CERROR_ABT_IDX]	= "Abort on command fetch",
		[CMDQ_ERR_CERROR_ATC_INV_IDX]	= "ATC invalidate timeout",
	};

	int i;
	u64 cmd[CMDQ_ENT_DWORDS];
	u32 cons = readl_relaxed(q->cons_reg);
	u32 idx = FIELD_GET(CMDQ_CONS_ERR, cons);
	struct arm_smmu_cmdq_ent cmd_sync = {
		.opcode = CMDQ_OP_CMD_SYNC,
	};

	dev_err(smmu->dev, "CMDQ error (cons 0x%08x): %s\n", cons,
		idx < ARRAY_SIZE(cerror_str) ?  cerror_str[idx] : "Unknown");

	switch (idx) {
	case CMDQ_ERR_CERROR_ABT_IDX:
		dev_err(smmu->dev, "retrying command fetch\n");
	case CMDQ_ERR_CERROR_NONE_IDX:
		return;
	case CMDQ_ERR_CERROR_ATC_INV_IDX:
		/*
		 * ATC Invalidation Completion timeout. CONS is still pointing
		 * at the CMD_SYNC. Attempt to complete other pending commands
		 * by repeating the CMD_SYNC, though we might well end up back
		 * here since the ATC invalidation may still be pending.
		 */
		return;
	case CMDQ_ERR_CERROR_ILL_IDX:
	default:
		break;
	}

	/*
	 * We may have concurrent producers, so we need to be careful
	 * not to touch any of the shadow cmdq state.
	 */
	queue_read(cmd, Q_ENT(q, cons), q->ent_dwords);
	dev_err(smmu->dev, "skipping command in error state:\n");
	for (i = 0; i < ARRAY_SIZE(cmd); ++i)
		dev_err(smmu->dev, "\t0x%016llx\n", (unsigned long long)cmd[i]);

	/* Convert the erroneous command into a CMD_SYNC */
	if (arm_smmu_cmdq_build_cmd(cmd, &cmd_sync)) {
		dev_err(smmu->dev, "failed to convert to CMD_SYNC\n");
		return;
	}

	queue_write(Q_ENT(q, cons), cmd, q->ent_dwords);
}

static void arm_smmu_cmdq_skip_err(struct arm_smmu_device *smmu)
{
	__arm_smmu_cmdq_skip_err(smmu, &smmu->cmdq.q);
}

static void arm_smmu_ecmdq_skip_err(struct arm_smmu_device *smmu)
{
	int i;
	u32 prod, cons;
	struct arm_smmu_queue *q;
	struct arm_smmu_ecmdq *ecmdq;

	for (i = 0; i < smmu->nr_ecmdq; i++) {
		unsigned long flags;

		ecmdq = *per_cpu_ptr(smmu->ecmdqs, i);
		q = &ecmdq->cmdq.q;

		prod = readl_relaxed(q->prod_reg);
		cons = readl_relaxed(q->cons_reg);
		if (((prod ^ cons) & ECMDQ_CONS_ERR) == 0)
			continue;

		__arm_smmu_cmdq_skip_err(smmu, q);

		write_lock_irqsave(&q->ecmdq_lock, flags);
		q->ecmdq_prod &= ~ECMDQ_PROD_ERRACK;
		q->ecmdq_prod |= cons & ECMDQ_CONS_ERR;

		prod = readl_relaxed(q->prod_reg);
		prod &= ~ECMDQ_PROD_ERRACK;
		prod |= cons & ECMDQ_CONS_ERR;
		writel(prod, q->prod_reg);
		write_unlock_irqrestore(&q->ecmdq_lock, flags);
	}
}

/*
 * Command queue locking.
 * This is a form of bastardised rwlock with the following major changes:
 *
 * - The only LOCK routines are exclusive_trylock() and shared_lock().
 *   Neither have barrier semantics, and instead provide only a control
 *   dependency.
 *
 * - The UNLOCK routines are supplemented with shared_tryunlock(), which
 *   fails if the caller appears to be the last lock holder (yes, this is
 *   racy). All successful UNLOCK routines have RELEASE semantics.
 */
static void arm_smmu_cmdq_shared_lock(struct arm_smmu_cmdq *cmdq)
{
	int val;

	/*
	 * We can try to avoid the cmpxchg() loop by simply incrementing the
	 * lock counter. When held in exclusive state, the lock counter is set
	 * to INT_MIN so these increments won't hurt as the value will remain
	 * negative.
	 */
	if (atomic_fetch_inc_relaxed(&cmdq->lock) >= 0)
		return;

	do {
		val = atomic_cond_read_relaxed(&cmdq->lock, VAL >= 0);
	} while (atomic_cmpxchg_relaxed(&cmdq->lock, val, val + 1) != val);
}

static void arm_smmu_cmdq_shared_unlock(struct arm_smmu_cmdq *cmdq)
{
	(void)atomic_dec_return_release(&cmdq->lock);
}

static bool arm_smmu_cmdq_shared_tryunlock(struct arm_smmu_cmdq *cmdq)
{
	if (atomic_read(&cmdq->lock) == 1)
		return false;

	arm_smmu_cmdq_shared_unlock(cmdq);
	return true;
}

#define arm_smmu_cmdq_exclusive_trylock_irqsave(cmdq, flags)		\
({									\
	bool __ret;							\
	local_irq_save(flags);						\
	__ret = !atomic_cmpxchg_relaxed(&cmdq->lock, 0, INT_MIN);	\
	if (!__ret)							\
		local_irq_restore(flags);				\
	__ret;								\
})

#define arm_smmu_cmdq_exclusive_unlock_irqrestore(cmdq, flags)		\
({									\
	atomic_set_release(&cmdq->lock, 0);				\
	local_irq_restore(flags);					\
})


/*
 * Command queue insertion.
 * This is made fiddly by our attempts to achieve some sort of scalability
 * since there is one queue shared amongst all of the CPUs in the system.  If
 * you like mixed-size concurrency, dependency ordering and relaxed atomics,
 * then you'll *love* this monstrosity.
 *
 * The basic idea is to split the queue up into ranges of commands that are
 * owned by a given CPU; the owner may not have written all of the commands
 * itself, but is responsible for advancing the hardware prod pointer when
 * the time comes. The algorithm is roughly:
 *
 * 	1. Allocate some space in the queue. At this point we also discover
 *	   whether the head of the queue is currently owned by another CPU,
 *	   or whether we are the owner.
 *
 *	2. Write our commands into our allocated slots in the queue.
 *
 *	3. Mark our slots as valid in arm_smmu_cmdq.valid_map.
 *
 *	4. If we are an owner:
 *		a. Wait for the previous owner to finish.
 *		b. Mark the queue head as unowned, which tells us the range
 *		   that we are responsible for publishing.
 *		c. Wait for all commands in our owned range to become valid.
 *		d. Advance the hardware prod pointer.
 *		e. Tell the next owner we've finished.
 *
 *	5. If we are inserting a CMD_SYNC (we may or may not have been an
 *	   owner), then we need to stick around until it has completed:
 *		a. If we have MSIs, the SMMU can write back into the CMD_SYNC
 *		   to clear the first 4 bytes.
 *		b. Otherwise, we spin waiting for the hardware cons pointer to
 *		   advance past our command.
 *
 * The devil is in the details, particularly the use of locking for handling
 * SYNC completion and freeing up space in the queue before we think that it is
 * full.
 */
static void __arm_smmu_cmdq_poll_set_valid_map(struct arm_smmu_cmdq *cmdq,
					       u32 sprod, u32 eprod, bool set)
{
	u32 swidx, sbidx, ewidx, ebidx;
	struct arm_smmu_ll_queue llq = {
		.max_n_shift	= cmdq->q.llq.max_n_shift,
		.prod		= sprod,
	};

	ewidx = BIT_WORD(Q_IDX(&llq, eprod));
	ebidx = Q_IDX(&llq, eprod) % BITS_PER_LONG;

	while (llq.prod != eprod) {
		unsigned long mask;
		atomic_long_t *ptr;
		u32 limit = BITS_PER_LONG;

		swidx = BIT_WORD(Q_IDX(&llq, llq.prod));
		sbidx = Q_IDX(&llq, llq.prod) % BITS_PER_LONG;

		ptr = &cmdq->valid_map[swidx];

		if ((swidx == ewidx) && (sbidx < ebidx))
			limit = ebidx;

		mask = GENMASK(limit - 1, sbidx);

		/*
		 * The valid bit is the inverse of the wrap bit. This means
		 * that a zero-initialised queue is invalid and, after marking
		 * all entries as valid, they become invalid again when we
		 * wrap.
		 */
		if (set) {
			atomic_long_xor(mask, ptr);
		} else { /* Poll */
			unsigned long valid;

			valid = (ULONG_MAX + !!Q_WRP(&llq, llq.prod)) & mask;
			atomic_long_cond_read_relaxed(ptr, (VAL & mask) == valid);
		}

		llq.prod = queue_inc_prod_n(&llq, limit - sbidx);
	}
}

/* Mark all entries in the range [sprod, eprod) as valid */
static void arm_smmu_cmdq_set_valid_map(struct arm_smmu_cmdq *cmdq,
					u32 sprod, u32 eprod)
{
	__arm_smmu_cmdq_poll_set_valid_map(cmdq, sprod, eprod, true);
}

/* Wait for all entries in the range [sprod, eprod) to become valid */
static void arm_smmu_cmdq_poll_valid_map(struct arm_smmu_cmdq *cmdq,
					 u32 sprod, u32 eprod)
{
	__arm_smmu_cmdq_poll_set_valid_map(cmdq, sprod, eprod, false);
}

/* Wait for the command queue to become non-full */
static int arm_smmu_cmdq_poll_until_not_full(struct arm_smmu_device *smmu,
					     struct arm_smmu_ll_queue *llq)
{
	unsigned long flags;
	struct arm_smmu_queue_poll qp;
	struct arm_smmu_cmdq *cmdq = arm_smmu_get_cmdq(smmu);
	int ret = 0;

	/*
	 * Try to update our copy of cons by grabbing exclusive cmdq access. If
	 * that fails, spin until somebody else updates it for us.
	 */
	if (arm_smmu_cmdq_exclusive_trylock_irqsave(cmdq, flags)) {
		WRITE_ONCE(cmdq->q.llq.cons, readl_relaxed(cmdq->q.cons_reg));
		arm_smmu_cmdq_exclusive_unlock_irqrestore(cmdq, flags);
		llq->val = READ_ONCE(cmdq->q.llq.val);
		return 0;
	}

	queue_poll_init(smmu, &qp);
	do {
		llq->val = READ_ONCE(cmdq->q.llq.val);
		if (!queue_full(llq))
			break;

		ret = queue_poll(&qp);
	} while (!ret);

	return ret;
}

/*
 * Wait until the SMMU signals a CMD_SYNC completion MSI.
 * Must be called with the cmdq lock held in some capacity.
 */
static int __arm_smmu_cmdq_poll_until_msi(struct arm_smmu_device *smmu,
					  struct arm_smmu_ll_queue *llq)
{
	int ret = 0;
	struct arm_smmu_queue_poll qp;
	struct arm_smmu_cmdq *cmdq = arm_smmu_get_cmdq(smmu);
	u32 *cmd = (u32 *)(Q_ENT(&cmdq->q, llq->prod));

	queue_poll_init(smmu, &qp);

	/*
	 * The MSI won't generate an event, since it's being written back
	 * into the command queue.
	 */
	qp.wfe = false;
	smp_cond_load_relaxed(cmd, !VAL || (ret = queue_poll(&qp)));
	llq->cons = ret ? llq->prod : queue_inc_prod_n(llq, 1);
	return ret;
}

/*
 * Wait until the SMMU cons index passes llq->prod.
 * Must be called with the cmdq lock held in some capacity.
 */
static int __arm_smmu_cmdq_poll_until_consumed(struct arm_smmu_device *smmu,
					       struct arm_smmu_ll_queue *llq)
{
	struct arm_smmu_queue_poll qp;
	struct arm_smmu_cmdq *cmdq = arm_smmu_get_cmdq(smmu);
	u32 prod = llq->prod;
	int ret = 0;

	queue_poll_init(smmu, &qp);
	llq->val = READ_ONCE(cmdq->q.llq.val);
	do {
		if (queue_consumed(llq, prod))
			break;

		ret = queue_poll(&qp);

		/*
		 * This needs to be a readl() so that our subsequent call
		 * to arm_smmu_cmdq_shared_tryunlock() can fail accurately.
		 *
		 * Specifically, we need to ensure that we observe all
		 * shared_lock()s by other CMD_SYNCs that share our owner,
		 * so that a failing call to tryunlock() means that we're
		 * the last one out and therefore we can safely advance
		 * cmdq->q.llq.cons. Roughly speaking:
		 *
		 * CPU 0		CPU1			CPU2 (us)
		 *
		 * if (sync)
		 * 	shared_lock();
		 *
		 * dma_wmb();
		 * set_valid_map();
		 *
		 * 			if (owner) {
		 *				poll_valid_map();
		 *				<control dependency>
		 *				writel(prod_reg);
		 *
		 *						readl(cons_reg);
		 *						tryunlock();
		 *
		 * Requires us to see CPU 0's shared_lock() acquisition.
		 */
		llq->cons = readl(cmdq->q.cons_reg);
	} while (!ret);

	return ret;
}

static int arm_smmu_cmdq_poll_until_sync(struct arm_smmu_device *smmu,
					 struct arm_smmu_ll_queue *llq)
{
	if (smmu->options & ARM_SMMU_OPT_MSIPOLL)
		return __arm_smmu_cmdq_poll_until_msi(smmu, llq);

	return __arm_smmu_cmdq_poll_until_consumed(smmu, llq);
}

static void arm_smmu_cmdq_write_entries(struct arm_smmu_cmdq *cmdq, u64 *cmds,
					u32 prod, int n)
{
	int i;
	struct arm_smmu_ll_queue llq = {
		.max_n_shift	= cmdq->q.llq.max_n_shift,
		.prod		= prod,
	};

	for (i = 0; i < n; ++i) {
		u64 *cmd = &cmds[i * CMDQ_ENT_DWORDS];

		prod = queue_inc_prod_n(&llq, i);
		queue_write(Q_ENT(&cmdq->q, prod), cmd, CMDQ_ENT_DWORDS);
	}
}

/*
 * The function is used when the current core exclusively occupies an ECMDQ.
 * This is a reduced version of arm_smmu_cmdq_issue_cmdlist(), which eliminates
 * a lot of unnecessary inter-core competition considerations.
 */
static int arm_smmu_ecmdq_issue_cmdlist(struct arm_smmu_device *smmu,
					struct arm_smmu_cmdq *cmdq,
					u64 *cmds, int n, bool sync)
{
	u32 prod;
	unsigned long flags;
	struct arm_smmu_ll_queue llq = {
		.max_n_shift = cmdq->q.llq.max_n_shift,
	}, head;
	int ret = 0;

	/* 1. Allocate some space in the queue */
	local_irq_save(flags);
	llq.val = READ_ONCE(cmdq->q.llq.val);
	do {
		u64 old;

		while (!queue_has_space(&llq, n + sync)) {
			local_irq_restore(flags);
			if (arm_smmu_cmdq_poll_until_not_full(smmu, &llq))
				dev_err_ratelimited(smmu->dev, "ECMDQ timeout\n");
			local_irq_save(flags);
		}

		head.cons = llq.cons;
		head.prod = queue_inc_prod_n(&llq, n + sync);

		old = cmpxchg_relaxed(&cmdq->q.llq.val, llq.val, head.val);
		if (old == llq.val)
			break;

		llq.val = old;
	} while (1);

	/* 2. Write our commands into the queue */
	arm_smmu_cmdq_write_entries(cmdq, cmds, llq.prod, n);
	if (sync) {
		u64 cmd_sync[CMDQ_ENT_DWORDS];

		prod = queue_inc_prod_n(&llq, n);
		arm_smmu_cmdq_build_sync_cmd(cmd_sync, smmu, &cmdq->q, prod);
		queue_write(Q_ENT(&cmdq->q, prod), cmd_sync, CMDQ_ENT_DWORDS);
	}

	/* 3. Ensuring commands are visible first */
	dma_wmb();

	/* 4. Advance the hardware prod pointer */
	read_lock(&cmdq->q.ecmdq_lock);
	writel_relaxed(head.prod | cmdq->q.ecmdq_prod, cmdq->q.prod_reg);
	read_unlock(&cmdq->q.ecmdq_lock);

	/* 5. If we are inserting a CMD_SYNC, we must wait for it to complete */
	if (sync) {
		llq.prod = queue_inc_prod_n(&llq, n);
		ret = arm_smmu_cmdq_poll_until_sync(smmu, &llq);
		if (ret) {
			dev_err_ratelimited(smmu->dev,
					    "CMD_SYNC timeout at 0x%08x [hwprod 0x%08x, hwcons 0x%08x]\n",
					    llq.prod,
					    readl_relaxed(cmdq->q.prod_reg),
					    readl_relaxed(cmdq->q.cons_reg));
		}

		/*
		 * Update cmdq->q.llq.cons, to improve the success rate of
		 * queue_has_space() when some new commands are inserted next
		 * time.
		 */
		WRITE_ONCE(cmdq->q.llq.cons, llq.cons);
	}

	local_irq_restore(flags);
	return ret;
}

/*
 * This is the actual insertion function, and provides the following
 * ordering guarantees to callers:
 *
 * - There is a dma_wmb() before publishing any commands to the queue.
 *   This can be relied upon to order prior writes to data structures
 *   in memory (such as a CD or an STE) before the command.
 *
 * - On completion of a CMD_SYNC, there is a control dependency.
 *   This can be relied upon to order subsequent writes to memory (e.g.
 *   freeing an IOVA) after completion of the CMD_SYNC.
 *
 * - Command insertion is totally ordered, so if two CPUs each race to
 *   insert their own list of commands then all of the commands from one
 *   CPU will appear before any of the commands from the other CPU.
 */
static int arm_smmu_cmdq_issue_cmdlist(struct arm_smmu_device *smmu,
				       u64 *cmds, int n, bool sync)
{
	u64 cmd_sync[CMDQ_ENT_DWORDS];
	u32 prod;
	unsigned long flags;
	bool owner;
	struct arm_smmu_cmdq *cmdq = arm_smmu_get_cmdq(smmu);
	struct arm_smmu_ll_queue llq = {
		.max_n_shift = cmdq->q.llq.max_n_shift,
	}, head = llq;
	int ret = 0;

	if (!cmdq->shared)
		return arm_smmu_ecmdq_issue_cmdlist(smmu, cmdq, cmds, n, sync);

	/* 1. Allocate some space in the queue */
	local_irq_save(flags);
	llq.val = READ_ONCE(cmdq->q.llq.val);
	do {
		u64 old;

		while (!queue_has_space(&llq, n + sync)) {
			local_irq_restore(flags);
			if (arm_smmu_cmdq_poll_until_not_full(smmu, &llq))
				dev_err_ratelimited(smmu->dev, "CMDQ timeout\n");
			local_irq_save(flags);
		}

		head.cons = llq.cons;
		head.prod = queue_inc_prod_n(&llq, n + sync) |
					     CMDQ_PROD_OWNED_FLAG;

		old = cmpxchg_relaxed(&cmdq->q.llq.val, llq.val, head.val);
		if (old == llq.val)
			break;

		llq.val = old;
	} while (1);
	owner = !(llq.prod & CMDQ_PROD_OWNED_FLAG);
	head.prod &= ~CMDQ_PROD_OWNED_FLAG;
	llq.prod &= ~CMDQ_PROD_OWNED_FLAG;

	/*
	 * 2. Write our commands into the queue
	 * Dependency ordering from the cmpxchg() loop above.
	 */
	arm_smmu_cmdq_write_entries(cmdq, cmds, llq.prod, n);
	if (sync) {
		prod = queue_inc_prod_n(&llq, n);
		arm_smmu_cmdq_build_sync_cmd(cmd_sync, smmu, &cmdq->q, prod);
		queue_write(Q_ENT(&cmdq->q, prod), cmd_sync, CMDQ_ENT_DWORDS);

		/*
		 * In order to determine completion of our CMD_SYNC, we must
		 * ensure that the queue can't wrap twice without us noticing.
		 * We achieve that by taking the cmdq lock as shared before
		 * marking our slot as valid.
		 */
		arm_smmu_cmdq_shared_lock(cmdq);
	}

	/* 3. Mark our slots as valid, ensuring commands are visible first */
	dma_wmb();
	arm_smmu_cmdq_set_valid_map(cmdq, llq.prod, head.prod);

	/* 4. If we are the owner, take control of the SMMU hardware */
	if (owner) {
		/* a. Wait for previous owner to finish */
		atomic_cond_read_relaxed(&cmdq->owner_prod, VAL == llq.prod);

		/* b. Stop gathering work by clearing the owned flag */
		prod = atomic_fetch_andnot_relaxed(CMDQ_PROD_OWNED_FLAG,
						   &cmdq->q.llq.atomic.prod);
		prod &= ~CMDQ_PROD_OWNED_FLAG;

		/*
		 * c. Wait for any gathered work to be written to the queue.
		 * Note that we read our own entries so that we have the control
		 * dependency required by (d).
		 */
		arm_smmu_cmdq_poll_valid_map(cmdq, llq.prod, prod);

		/*
		 * d. Advance the hardware prod pointer
		 * Control dependency ordering from the entries becoming valid.
		 */
		if (smmu->ecmdq_enabled) {
			read_lock(&cmdq->q.ecmdq_lock);
			writel_relaxed(prod | cmdq->q.ecmdq_prod, cmdq->q.prod_reg);
			read_unlock(&cmdq->q.ecmdq_lock);
		} else {
			writel_relaxed(prod, cmdq->q.prod_reg);
		}

		/*
		 * e. Tell the next owner we're done
		 * Make sure we've updated the hardware first, so that we don't
		 * race to update prod and potentially move it backwards.
		 */
		atomic_set_release(&cmdq->owner_prod, prod);
	}

	/* 5. If we are inserting a CMD_SYNC, we must wait for it to complete */
	if (sync) {
		llq.prod = queue_inc_prod_n(&llq, n);
		ret = arm_smmu_cmdq_poll_until_sync(smmu, &llq);
		if (ret) {
			dev_err_ratelimited(smmu->dev,
					    "CMD_SYNC timeout at 0x%08x [hwprod 0x%08x, hwcons 0x%08x]\n",
					    llq.prod,
					    readl_relaxed(cmdq->q.prod_reg),
					    readl_relaxed(cmdq->q.cons_reg));
		}

		/*
		 * Try to unlock the cmdq lock. This will fail if we're the last
		 * reader, in which case we can safely update cmdq->q.llq.cons
		 */
		if (!arm_smmu_cmdq_shared_tryunlock(cmdq)) {
			WRITE_ONCE(cmdq->q.llq.cons, llq.cons);
			arm_smmu_cmdq_shared_unlock(cmdq);
		}
	}

	local_irq_restore(flags);
	return ret;
}

static int __arm_smmu_cmdq_issue_cmd(struct arm_smmu_device *smmu,
				     struct arm_smmu_cmdq_ent *ent,
				     bool sync)
{
	u64 cmd[CMDQ_ENT_DWORDS];

	if (arm_smmu_cmdq_build_cmd(cmd, ent)) {
		dev_warn(smmu->dev, "ignoring unknown CMDQ opcode 0x%x\n",
			 ent->opcode);
		return -EINVAL;
	}

	return arm_smmu_cmdq_issue_cmdlist(smmu, cmd, 1, sync);
}

static int arm_smmu_cmdq_issue_cmd(struct arm_smmu_device *smmu,
				   struct arm_smmu_cmdq_ent *ent)
{
	return __arm_smmu_cmdq_issue_cmd(smmu, ent, false);
}

static int arm_smmu_cmdq_issue_cmd_with_sync(struct arm_smmu_device *smmu,
					     struct arm_smmu_cmdq_ent *ent)
{
	return __arm_smmu_cmdq_issue_cmd(smmu, ent, true);
}

static void arm_smmu_cmdq_batch_add(struct arm_smmu_device *smmu,
				    struct arm_smmu_cmdq_batch *cmds,
				    struct arm_smmu_cmdq_ent *cmd)
{
	if (cmds->num == CMDQ_BATCH_ENTRIES) {
		arm_smmu_cmdq_issue_cmdlist(smmu, cmds->cmds, cmds->num, false);
		cmds->num = 0;
	}
	arm_smmu_cmdq_build_cmd(&cmds->cmds[cmds->num * CMDQ_ENT_DWORDS], cmd);
	cmds->num++;
}

static int arm_smmu_cmdq_batch_submit(struct arm_smmu_device *smmu,
				      struct arm_smmu_cmdq_batch *cmds)
{
	return arm_smmu_cmdq_issue_cmdlist(smmu, cmds->cmds, cmds->num, true);
}

static int arm_smmu_page_response(struct device *dev,
				  struct iommu_fault_event *evt,
				  struct iommu_page_response *resp)
{
	struct arm_smmu_cmdq_ent cmd = {0};
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	bool pasid_valid = resp->flags & IOMMU_PAGE_RESP_PASID_VALID;
	int sid = master->streams[0].id;

	if (master->stall_enabled) {
		cmd.opcode		= CMDQ_OP_RESUME;
		cmd.resume.sid		= sid;
		cmd.resume.stag		= resp->grpid;
		switch (resp->code) {
		case IOMMU_PAGE_RESP_INVALID:
		case IOMMU_PAGE_RESP_FAILURE:
			cmd.resume.resp = CMDQ_RESUME_0_RESP_ABORT;
			break;
		case IOMMU_PAGE_RESP_SUCCESS:
			cmd.resume.resp = CMDQ_RESUME_0_RESP_RETRY;
			break;
		default:
			return -EINVAL;
		}
	} else if (master->pri_supported) {
		bool needs_pasid = (evt->fault.prm.flags &
				    IOMMU_FAULT_PAGE_RESPONSE_NEEDS_PASID);

		cmd.opcode		= CMDQ_OP_PRI_RESP;
		cmd.substream_valid	= needs_pasid && pasid_valid;
		cmd.pri.sid		= sid;
		cmd.pri.ssid		= resp->pasid;
		cmd.pri.grpid		= resp->grpid;
		switch (resp->code) {
		case IOMMU_PAGE_RESP_FAILURE:
			cmd.pri.resp = CMDQ_PRI_1_RESP_FAILURE;
			break;
		case IOMMU_PAGE_RESP_INVALID:
			cmd.pri.resp = CMDQ_PRI_1_RESP_INVALID;
			break;
		case IOMMU_PAGE_RESP_SUCCESS:
			cmd.pri.resp = CMDQ_PRI_1_RESP_SUCCESS;
			break;
		default:
			return -EINVAL;
		}
	} else {
		return -ENODEV;
	}

	arm_smmu_cmdq_issue_cmd(master->smmu, &cmd);
	/*
	 * Don't send a SYNC, it doesn't do anything for RESUME or PRI_RESP.
	 * RESUME consumption guarantees that the stalled transaction will be
	 * terminated... at some point in the future. PRI_RESP is fire and
	 * forget.
	 */

	return 0;
}

/* Context descriptor manipulation functions */
void arm_smmu_tlb_inv_asid(struct arm_smmu_device *smmu, u16 asid)
{
	struct arm_smmu_cmdq_ent cmd = {
		.opcode	= smmu->features & ARM_SMMU_FEAT_E2H ?
			CMDQ_OP_TLBI_EL2_ASID : CMDQ_OP_TLBI_NH_ASID,
		.tlbi.asid = asid,
	};

	arm_smmu_cmdq_issue_cmd_with_sync(smmu, &cmd);
}

static void arm_smmu_sync_cd(struct arm_smmu_domain *smmu_domain,
			     int ssid, bool leaf)
{
	size_t i;
	unsigned long flags;
	struct arm_smmu_master *master;
	struct arm_smmu_cmdq_batch cmds = {};
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cmdq_ent cmd = {
		.opcode	= CMDQ_OP_CFGI_CD,
		.cfgi	= {
			.ssid	= ssid,
			.leaf	= leaf,
		},
	};

	arm_smmu_preempt_disable(smmu);
	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_for_each_entry(master, &smmu_domain->devices, domain_head) {
		for (i = 0; i < master->num_streams; i++) {
			cmd.cfgi.sid = master->streams[i].id;
			arm_smmu_cmdq_batch_add(smmu, &cmds, &cmd);
		}
	}
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	arm_smmu_cmdq_batch_submit(smmu, &cmds);
	arm_smmu_preempt_enable(smmu);
}

static int arm_smmu_alloc_cd_leaf_table(struct arm_smmu_device *smmu,
					struct arm_smmu_l1_ctx_desc *l1_desc)
{
	size_t size = CTXDESC_L2_ENTRIES * (CTXDESC_CD_DWORDS << 3);

	l1_desc->l2ptr = dmam_alloc_coherent(smmu->dev, size,
					     &l1_desc->l2ptr_dma, GFP_KERNEL);
	if (!l1_desc->l2ptr) {
		dev_warn(smmu->dev,
			 "failed to allocate context descriptor table\n");
		return -ENOMEM;
	}
	return 0;
}

static void arm_smmu_write_cd_l1_desc(__le64 *dst,
				      struct arm_smmu_l1_ctx_desc *l1_desc)
{
	u64 val = (l1_desc->l2ptr_dma & CTXDESC_L1_DESC_L2PTR_MASK) |
		  CTXDESC_L1_DESC_V;

	/* See comment in arm_smmu_write_ctx_desc() */
	WRITE_ONCE(*dst, cpu_to_le64(val));
}

static __le64 *arm_smmu_get_cd_ptr(struct arm_smmu_domain *smmu_domain,
				   u32 ssid)
{
	__le64 *l1ptr;
	unsigned int idx;
	struct arm_smmu_l1_ctx_desc *l1_desc;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_ctx_desc_cfg *cdcfg = &smmu_domain->s1_cfg.cdcfg;

	if (smmu_domain->s1_cfg.s1fmt == STRTAB_STE_0_S1FMT_LINEAR)
		return cdcfg->cdtab + ssid * CTXDESC_CD_DWORDS;

	idx = ssid >> CTXDESC_SPLIT;
	l1_desc = &cdcfg->l1_desc[idx];
	if (!l1_desc->l2ptr) {
		if (arm_smmu_alloc_cd_leaf_table(smmu, l1_desc))
			return NULL;

		l1ptr = cdcfg->cdtab + idx * CTXDESC_L1_DESC_DWORDS;
		arm_smmu_write_cd_l1_desc(l1ptr, l1_desc);
		/* An invalid L1CD can be cached */
		arm_smmu_sync_cd(smmu_domain, ssid, false);
	}
	idx = ssid & (CTXDESC_L2_ENTRIES - 1);
	return l1_desc->l2ptr + idx * CTXDESC_CD_DWORDS;
}

int arm_smmu_write_ctx_desc(struct arm_smmu_domain *smmu_domain, int ssid,
			    struct arm_smmu_ctx_desc *cd)
{
	/*
	 * This function handles the following cases:
	 *
	 * (1) Install primary CD, for normal DMA traffic (SSID = 0).
	 * (2) Install a secondary CD, for SID+SSID traffic.
	 * (3) Update ASID of a CD. Atomically write the first 64 bits of the
	 *     CD, then invalidate the old entry and mappings.
	 * (4) Quiesce the context without clearing the valid bit. Disable
	 *     translation, and ignore any translation fault.
	 * (5) Remove a secondary CD.
	 */
	u64 val;
	bool cd_live;
	__le64 *cdptr;
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (WARN_ON(ssid >= (1 << smmu_domain->s1_cfg.s1cdmax)))
		return -E2BIG;

	cdptr = arm_smmu_get_cd_ptr(smmu_domain, ssid);
	if (!cdptr)
		return -ENOMEM;

	val = le64_to_cpu(cdptr[0]);
	cd_live = !!(val & CTXDESC_CD_0_V);

	if (!cd) { /* (5) */
		val = 0;
	} else if (cd == &quiet_cd) { /* (4) */
		if (!(smmu->features & ARM_SMMU_FEAT_STALL_FORCE))
			val &= ~(CTXDESC_CD_0_S | CTXDESC_CD_0_R);
		val |= CTXDESC_CD_0_TCR_EPD0;
	} else if (cd_live) { /* (3) */
		val &= ~CTXDESC_CD_0_ASID;
		val |= FIELD_PREP(CTXDESC_CD_0_ASID, cd->asid);
		/*
		 * Until CD+TLB invalidation, both ASIDs may be used for tagging
		 * this substream's traffic
		 */
	} else { /* (1) and (2) */
		u64 tcr = cd->tcr;

		cdptr[1] = cpu_to_le64(cd->ttbr & CTXDESC_CD_1_TTB0_MASK);
		cdptr[2] = 0;
		cdptr[3] = cpu_to_le64(cd->mair);

		if (!(smmu->features & ARM_SMMU_FEAT_HD))
			tcr &= ~CTXDESC_CD_0_TCR_HD;
		if (!(smmu->features & ARM_SMMU_FEAT_HA))
			tcr &= ~CTXDESC_CD_0_TCR_HA;

		/*
		 * STE is live, and the SMMU might read dwords of this CD in any
		 * order. Ensure that it observes valid values before reading
		 * V=1.
		 */
		arm_smmu_sync_cd(smmu_domain, ssid, true);

		val = tcr |
#ifdef __BIG_ENDIAN
			CTXDESC_CD_0_ENDI |
#endif
			CTXDESC_CD_0_R | CTXDESC_CD_0_A |
			(cd->mm ? 0 : CTXDESC_CD_0_ASET) |
			CTXDESC_CD_0_AA64 |
			FIELD_PREP(CTXDESC_CD_0_ASID, cd->asid) |
			CTXDESC_CD_0_V;

		if (smmu_domain->stall_enabled)
			val |= CTXDESC_CD_0_S;
	}

	/*
	 * The SMMU accesses 64-bit values atomically. See IHI0070Ca 3.21.3
	 * "Configuration structures and configuration invalidation completion"
	 *
	 *   The size of single-copy atomic reads made by the SMMU is
	 *   IMPLEMENTATION DEFINED but must be at least 64 bits. Any single
	 *   field within an aligned 64-bit span of a structure can be altered
	 *   without first making the structure invalid.
	 */
	WRITE_ONCE(cdptr[0], cpu_to_le64(val));
	arm_smmu_sync_cd(smmu_domain, ssid, true);
	return 0;
}

static int arm_smmu_alloc_cd_tables(struct arm_smmu_domain *smmu_domain)
{
	int ret;
	size_t l1size;
	size_t max_contexts;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_s1_cfg *cfg = &smmu_domain->s1_cfg;
	struct arm_smmu_ctx_desc_cfg *cdcfg = &cfg->cdcfg;

	max_contexts = 1 << cfg->s1cdmax;

	if (!(smmu->features & ARM_SMMU_FEAT_2_LVL_CDTAB) ||
	    max_contexts <= CTXDESC_L2_ENTRIES) {
		cfg->s1fmt = STRTAB_STE_0_S1FMT_LINEAR;
		cdcfg->num_l1_ents = max_contexts;

		l1size = max_contexts * (CTXDESC_CD_DWORDS << 3);
	} else {
		cfg->s1fmt = STRTAB_STE_0_S1FMT_64K_L2;
		cdcfg->num_l1_ents = DIV_ROUND_UP(max_contexts,
						  CTXDESC_L2_ENTRIES);

		cdcfg->l1_desc = devm_kcalloc(smmu->dev, cdcfg->num_l1_ents,
					      sizeof(*cdcfg->l1_desc),
					      GFP_KERNEL);
		if (!cdcfg->l1_desc)
			return -ENOMEM;

		l1size = cdcfg->num_l1_ents * (CTXDESC_L1_DESC_DWORDS << 3);
	}

	cdcfg->cdtab = dmam_alloc_coherent(smmu->dev, l1size, &cdcfg->cdtab_dma,
					   GFP_KERNEL);
	if (!cdcfg->cdtab) {
		dev_warn(smmu->dev, "failed to allocate context descriptor\n");
		ret = -ENOMEM;
		goto err_free_l1;
	}

	return 0;

err_free_l1:
	if (cdcfg->l1_desc) {
		devm_kfree(smmu->dev, cdcfg->l1_desc);
		cdcfg->l1_desc = NULL;
	}
	return ret;
}

static void arm_smmu_free_cd_tables(struct arm_smmu_domain *smmu_domain)
{
	int i;
	size_t size, l1size;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_ctx_desc_cfg *cdcfg = &smmu_domain->s1_cfg.cdcfg;

	if (!cdcfg->cdtab)
		return;

	if (cdcfg->l1_desc) {
		size = CTXDESC_L2_ENTRIES * (CTXDESC_CD_DWORDS << 3);

		for (i = 0; i < cdcfg->num_l1_ents; i++) {
			if (!cdcfg->l1_desc[i].l2ptr)
				continue;

			dmam_free_coherent(smmu->dev, size,
					   cdcfg->l1_desc[i].l2ptr,
					   cdcfg->l1_desc[i].l2ptr_dma);
		}
		devm_kfree(smmu->dev, cdcfg->l1_desc);
		cdcfg->l1_desc = NULL;

		l1size = cdcfg->num_l1_ents * (CTXDESC_L1_DESC_DWORDS << 3);
	} else {
		l1size = cdcfg->num_l1_ents * (CTXDESC_CD_DWORDS << 3);
	}

	dmam_free_coherent(smmu->dev, l1size, cdcfg->cdtab, cdcfg->cdtab_dma);
	cdcfg->cdtab_dma = 0;
	cdcfg->cdtab = NULL;
}

bool arm_smmu_free_asid(struct arm_smmu_ctx_desc *cd)
{
	bool free;
	struct arm_smmu_ctx_desc *old_cd;

	if (!cd->asid)
		return false;

	free = refcount_dec_and_test(&cd->refs);
	if (free) {
		old_cd = xa_erase(&arm_smmu_asid_xa, cd->asid);
		WARN_ON(old_cd != cd);
	}
	return free;
}

/* Stream table manipulation functions */
static void
arm_smmu_write_strtab_l1_desc(__le64 *dst, struct arm_smmu_strtab_l1_desc *desc)
{
	u64 val = 0;

	val |= FIELD_PREP(STRTAB_L1_DESC_SPAN, desc->span);
	val |= desc->l2ptr_dma & STRTAB_L1_DESC_L2PTR_MASK;

	/* See comment in arm_smmu_write_ctx_desc() */
	WRITE_ONCE(*dst, cpu_to_le64(val));
}

static void arm_smmu_sync_ste_for_sid(struct arm_smmu_device *smmu, u32 sid)
{
	struct arm_smmu_cmdq_ent cmd = {
		.opcode	= CMDQ_OP_CFGI_STE,
		.cfgi	= {
			.sid	= sid,
			.leaf	= true,
		},
	};

	arm_smmu_cmdq_issue_cmd_with_sync(smmu, &cmd);
}

static void arm_smmu_write_strtab_ent(struct arm_smmu_master *master, u32 sid,
				      __le64 *dst)
{
	/*
	 * This is hideously complicated, but we only really care about
	 * three cases at the moment:
	 *
	 * 1. Invalid (all zero) -> bypass/fault (init)
	 * 2. Bypass/fault -> translation/bypass (attach)
	 * 3. Translation/bypass -> bypass/fault (detach)
	 *
	 * Given that we can't update the STE atomically and the SMMU
	 * doesn't read the thing in a defined order, that leaves us
	 * with the following maintenance requirements:
	 *
	 * 1. Update Config, return (init time STEs aren't live)
	 * 2. Write everything apart from dword 0, sync, write dword 0, sync
	 * 3. Update Config, sync
	 */
	u64 val = le64_to_cpu(dst[0]);
	bool ste_live = false;
	struct arm_smmu_device *smmu = NULL;
	struct arm_smmu_s1_cfg *s1_cfg = NULL;
	struct arm_smmu_s2_cfg *s2_cfg = NULL;
	struct arm_smmu_domain *smmu_domain = NULL;
	struct arm_smmu_cmdq_ent prefetch_cmd = {
		.opcode		= CMDQ_OP_PREFETCH_CFG,
		.prefetch	= {
			.sid	= sid,
		},
	};

	if (master) {
		smmu_domain = master->domain;
		smmu = master->smmu;
	}

	if (smmu_domain) {
		switch (smmu_domain->stage) {
		case ARM_SMMU_DOMAIN_S1:
			s1_cfg = &smmu_domain->s1_cfg;
			break;
		case ARM_SMMU_DOMAIN_S2:
		case ARM_SMMU_DOMAIN_NESTED:
			s2_cfg = &smmu_domain->s2_cfg;
			break;
		default:
			break;
		}
	}

	if (val & STRTAB_STE_0_V) {
		switch (FIELD_GET(STRTAB_STE_0_CFG, val)) {
		case STRTAB_STE_0_CFG_BYPASS:
			break;
		case STRTAB_STE_0_CFG_S1_TRANS:
		case STRTAB_STE_0_CFG_S2_TRANS:
			ste_live = true;
			break;
		case STRTAB_STE_0_CFG_ABORT:
			BUG_ON(!disable_bypass);
			break;
		default:
			BUG(); /* STE corruption */
		}
	}

	/* Nuke the existing STE_0 value, as we're going to rewrite it */
	val = STRTAB_STE_0_V;

	/* Bypass/fault */
	if (!smmu_domain || !(s1_cfg || s2_cfg)) {
		if (!smmu_domain && disable_bypass)
			val |= FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_ABORT);
		else
			val |= FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_BYPASS);

		dst[0] = cpu_to_le64(val);
		dst[1] = cpu_to_le64(FIELD_PREP(STRTAB_STE_1_SHCFG,
						STRTAB_STE_1_SHCFG_INCOMING));
		dst[2] = 0; /* Nuke the VMID */
		/*
		 * The SMMU can perform negative caching, so we must sync
		 * the STE regardless of whether the old value was live.
		 */
		if (smmu)
			arm_smmu_sync_ste_for_sid(smmu, sid);
		return;
	}

	if (s1_cfg) {
		u64 strw = smmu->features & ARM_SMMU_FEAT_E2H ?
			STRTAB_STE_1_STRW_EL2 : STRTAB_STE_1_STRW_NSEL1;

		BUG_ON(ste_live);
		dst[1] = cpu_to_le64(
			 FIELD_PREP(STRTAB_STE_1_S1DSS, STRTAB_STE_1_S1DSS_SSID0) |
			 FIELD_PREP(STRTAB_STE_1_S1CIR, STRTAB_STE_1_S1C_CACHE_WBRA) |
			 FIELD_PREP(STRTAB_STE_1_S1COR, STRTAB_STE_1_S1C_CACHE_WBRA) |
			 FIELD_PREP(STRTAB_STE_1_S1CSH, ARM_SMMU_SH_ISH) |
			 FIELD_PREP(STRTAB_STE_1_STRW, strw));

		if (master->prg_resp_needs_ssid)
			dst[1] |= cpu_to_le64(STRTAB_STE_1_PPAR);

		if (smmu->features & ARM_SMMU_FEAT_STALLS &&
		    !master->stall_enabled)
			dst[1] |= cpu_to_le64(STRTAB_STE_1_S1STALLD);

		val |= (s1_cfg->cdcfg.cdtab_dma & STRTAB_STE_0_S1CTXPTR_MASK) |
			FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_S1_TRANS) |
			FIELD_PREP(STRTAB_STE_0_S1CDMAX, s1_cfg->s1cdmax) |
			FIELD_PREP(STRTAB_STE_0_S1FMT, s1_cfg->s1fmt);
	}

	if (s2_cfg) {
		BUG_ON(ste_live);
		dst[2] = cpu_to_le64(
			 FIELD_PREP(STRTAB_STE_2_S2VMID, s2_cfg->vmid) |
			 FIELD_PREP(STRTAB_STE_2_VTCR, s2_cfg->vtcr) |
#ifdef __BIG_ENDIAN
			 STRTAB_STE_2_S2ENDI |
#endif
			 STRTAB_STE_2_S2PTW | STRTAB_STE_2_S2AA64 |
			 STRTAB_STE_2_S2R);

		dst[3] = cpu_to_le64(s2_cfg->vttbr & STRTAB_STE_3_S2TTB_MASK);

		val |= FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_S2_TRANS);
	}

	if (master->ats_enabled)
		dst[1] |= cpu_to_le64(FIELD_PREP(STRTAB_STE_1_EATS,
						 STRTAB_STE_1_EATS_TRANS));

	arm_smmu_sync_ste_for_sid(smmu, sid);
	/* See comment in arm_smmu_write_ctx_desc() */
	WRITE_ONCE(dst[0], cpu_to_le64(val));
	arm_smmu_sync_ste_for_sid(smmu, sid);

	/* It's likely that we'll want to use the new STE soon */
	if (!(smmu->options & ARM_SMMU_OPT_SKIP_PREFETCH))
		arm_smmu_cmdq_issue_cmd(smmu, &prefetch_cmd);
}

static void arm_smmu_init_bypass_stes(__le64 *strtab, unsigned int nent)
{
	unsigned int i;

	for (i = 0; i < nent; ++i) {
		arm_smmu_write_strtab_ent(NULL, -1, strtab);
		strtab += STRTAB_STE_DWORDS;
	}
}

static int arm_smmu_init_l2_strtab(struct arm_smmu_device *smmu, u32 sid)
{
	size_t size;
	void *strtab;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	struct arm_smmu_strtab_l1_desc *desc = &cfg->l1_desc[sid >> STRTAB_SPLIT];

	if (desc->l2ptr)
		return 0;

	size = 1 << (STRTAB_SPLIT + ilog2(STRTAB_STE_DWORDS) + 3);
	strtab = &cfg->strtab[(sid >> STRTAB_SPLIT) * STRTAB_L1_DESC_DWORDS];

	desc->span = STRTAB_SPLIT + 1;
	desc->l2ptr = dmam_alloc_coherent(smmu->dev, size, &desc->l2ptr_dma,
					  GFP_KERNEL);
	if (!desc->l2ptr) {
		dev_err(smmu->dev,
			"failed to allocate l2 stream table for SID %u\n",
			sid);
		return -ENOMEM;
	}

	arm_smmu_init_bypass_stes(desc->l2ptr, 1 << STRTAB_SPLIT);
	arm_smmu_write_strtab_l1_desc(strtab, desc);
	return 0;
}

static struct arm_smmu_master *
arm_smmu_find_master(struct arm_smmu_device *smmu, u32 sid)
{
	struct rb_node *node;
	struct arm_smmu_stream *stream;

	lockdep_assert_held(&smmu->streams_mutex);

	node = smmu->streams.rb_node;
	while (node) {
		stream = rb_entry(node, struct arm_smmu_stream, node);
		if (stream->id < sid)
			node = node->rb_right;
		else if (stream->id > sid)
			node = node->rb_left;
		else
			return stream->master;
	}

	return NULL;
}

/* IRQ and event handlers */
static int arm_smmu_handle_evt(struct arm_smmu_device *smmu, u64 *evt)
{
	int ret;
	u32 reason;
	u32 perm = 0;
	struct arm_smmu_master *master;
	bool ssid_valid = evt[0] & EVTQ_0_SSV;
	u32 sid = FIELD_GET(EVTQ_0_SID, evt[0]);
	struct iommu_fault_event fault_evt = { };
	struct iommu_fault *flt = &fault_evt.fault;

	switch (FIELD_GET(EVTQ_0_ID, evt[0])) {
	case EVT_ID_TRANSLATION_FAULT:
		reason = IOMMU_FAULT_REASON_PTE_FETCH;
		break;
	case EVT_ID_ADDR_SIZE_FAULT:
		reason = IOMMU_FAULT_REASON_OOR_ADDRESS;
		break;
	case EVT_ID_ACCESS_FAULT:
		reason = IOMMU_FAULT_REASON_ACCESS;
		break;
	case EVT_ID_PERMISSION_FAULT:
		reason = IOMMU_FAULT_REASON_PERMISSION;
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* Stage-2 is always pinned at the moment */
	if (evt[1] & EVTQ_1_S2)
		return -EFAULT;

	if (evt[1] & EVTQ_1_RnW)
		perm |= IOMMU_FAULT_PERM_READ;
	else
		perm |= IOMMU_FAULT_PERM_WRITE;

	if (evt[1] & EVTQ_1_InD)
		perm |= IOMMU_FAULT_PERM_EXEC;

	if (evt[1] & EVTQ_1_PnU)
		perm |= IOMMU_FAULT_PERM_PRIV;

	if (evt[1] & EVTQ_1_STALL) {
		flt->type = IOMMU_FAULT_PAGE_REQ;
		flt->prm = (struct iommu_fault_page_request) {
			.flags = IOMMU_FAULT_PAGE_REQUEST_LAST_PAGE,
			.grpid = FIELD_GET(EVTQ_1_STAG, evt[1]),
			.perm = perm,
			.addr = FIELD_GET(EVTQ_2_ADDR, evt[2]),
		};

		if (ssid_valid) {
			flt->prm.flags |= IOMMU_FAULT_PAGE_REQUEST_PASID_VALID;
			flt->prm.pasid = FIELD_GET(EVTQ_0_SSID, evt[0]);
		}
	} else {
		flt->type = IOMMU_FAULT_DMA_UNRECOV;
		flt->event = (struct iommu_fault_unrecoverable) {
			.reason = reason,
			.flags = IOMMU_FAULT_UNRECOV_ADDR_VALID,
			.perm = perm,
			.addr = FIELD_GET(EVTQ_2_ADDR, evt[2]),
		};

		if (ssid_valid) {
			flt->event.flags |= IOMMU_FAULT_UNRECOV_PASID_VALID;
			flt->event.pasid = FIELD_GET(EVTQ_0_SSID, evt[0]);
		}
	}

	mutex_lock(&smmu->streams_mutex);
	master = arm_smmu_find_master(smmu, sid);
	if (!master) {
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = iommu_report_device_fault(master->dev, &fault_evt);
	if (ret && flt->type == IOMMU_FAULT_PAGE_REQ) {
		/* Nobody cared, abort the access */
		struct iommu_page_response resp = {
			.pasid		= flt->prm.pasid,
			.grpid		= flt->prm.grpid,
			.code		= IOMMU_PAGE_RESP_FAILURE,
		};
		arm_smmu_page_response(master->dev, &fault_evt, &resp);
	}

out_unlock:
	mutex_unlock(&smmu->streams_mutex);
	return ret;
}

static irqreturn_t arm_smmu_evtq_thread(int irq, void *dev)
{
	int i, ret;
	struct arm_smmu_device *smmu = dev;
	struct arm_smmu_queue *q = &smmu->evtq.q;
	struct arm_smmu_ll_queue *llq = &q->llq;
	static DEFINE_RATELIMIT_STATE(rs, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	u64 evt[EVTQ_ENT_DWORDS];

	do {
		while (!queue_remove_raw(q, evt)) {
			u8 id = FIELD_GET(EVTQ_0_ID, evt[0]);

			ret = arm_smmu_handle_evt(smmu, evt);
			if (!ret || !__ratelimit(&rs))
				continue;

			dev_info(smmu->dev, "event 0x%02x received:\n", id);
			for (i = 0; i < ARRAY_SIZE(evt); ++i)
				dev_info(smmu->dev, "\t0x%016llx\n",
					 (unsigned long long)evt[i]);

			cond_resched();
		}

		/*
		 * Not much we can do on overflow, so scream and pretend we're
		 * trying harder.
		 */
		if (queue_sync_prod_in(q) == -EOVERFLOW)
			dev_err(smmu->dev, "EVTQ overflow detected -- events lost\n");
	} while (!queue_empty(llq));

	/* Sync our overflow flag, as we believe we're up to speed */
	queue_sync_cons_ovf(q);
	return IRQ_HANDLED;
}

static void arm_smmu_handle_ppr(struct arm_smmu_device *smmu, u64 *evt)
{
	bool pasid_valid, last;
	struct arm_smmu_master *master;
	u32 sid = FIELD_PREP(PRIQ_0_SID, evt[0]);
	struct iommu_fault_event fault_evt = {
		.fault.type = IOMMU_FAULT_PAGE_REQ,
		.fault.prm = {
			.grpid		= FIELD_GET(PRIQ_1_PRG_IDX, evt[1]),
			.addr		= evt[1] & PRIQ_1_ADDR_MASK,
		},
	};
	struct iommu_fault_page_request *pr = &fault_evt.fault.prm;

	pasid_valid = evt[0] & PRIQ_0_SSID_V;
	last = evt[0] & PRIQ_0_PRG_LAST;

	/* Discard Stop PASID marker, it isn't used */
	if (!(evt[0] & (PRIQ_0_PERM_READ | PRIQ_0_PERM_WRITE)) && last)
		return;

	if (last)
		pr->flags |= IOMMU_FAULT_PAGE_REQUEST_LAST_PAGE;
	if (pasid_valid) {
		pr->flags |= IOMMU_FAULT_PAGE_REQUEST_PASID_VALID;
		pr->pasid = FIELD_GET(PRIQ_0_SSID, evt[0]);
	}
	if (evt[0] & PRIQ_0_PERM_READ)
		pr->perm |= IOMMU_FAULT_PERM_READ;
	if (evt[0] & PRIQ_0_PERM_WRITE)
		pr->perm |= IOMMU_FAULT_PERM_WRITE;
	if (evt[0] & PRIQ_0_PERM_EXEC)
		pr->perm |= IOMMU_FAULT_PERM_EXEC;
	if (evt[0] & PRIQ_0_PERM_PRIV)
		pr->perm |= IOMMU_FAULT_PERM_PRIV;

	mutex_lock(&smmu->streams_mutex);
	master = arm_smmu_find_master(smmu, sid);
	if (!master) {
		dev_warn(smmu->dev, "Unexpected PPR from unknown SID 0x%x\n", sid);
		mutex_unlock(&smmu->streams_mutex);
		return;
	}

	if (pasid_valid && master->prg_resp_needs_ssid)
		pr->flags |= IOMMU_FAULT_PAGE_RESPONSE_NEEDS_PASID;

	if (iommu_report_device_fault(master->dev, &fault_evt)) {
		/*
		 * No handler registered, so subsequent faults won't produce
		 * better results. Try to disable PRI.
		 */
		struct iommu_page_response resp = {
			.flags		= pasid_valid ?
					  IOMMU_PAGE_RESP_PASID_VALID : 0,
			.pasid		= pr->pasid,
			.grpid		= pr->grpid,
			.code		= IOMMU_PAGE_RESP_FAILURE,
		};

		dev_warn(master->dev,
			 "PPR 0x%x:0x%llx 0x%x: nobody cared, disabling PRI\n",
			 pasid_valid ? pr->pasid : 0, pr->addr, pr->perm);
		if (last)
			arm_smmu_page_response(master->dev, &fault_evt, &resp);
	}
	mutex_unlock(&smmu->streams_mutex);
}

static irqreturn_t arm_smmu_priq_thread(int irq, void *dev)
{
	int num_handled = 0;
	bool overflow = false;
	struct arm_smmu_device *smmu = dev;
	struct arm_smmu_priq *priq = &smmu->priq;
	struct arm_smmu_queue *q = &priq->q;
	struct arm_smmu_ll_queue *llq = &q->llq;
	size_t queue_size = 1 << llq->max_n_shift;
	u64 evt[PRIQ_ENT_DWORDS];

	spin_lock(&priq->wq.lock);
	do {
		while (!queue_remove_raw(q, evt)) {
			spin_unlock(&priq->wq.lock);
			arm_smmu_handle_ppr(smmu, evt);
			spin_lock(&priq->wq.lock);
			if (++num_handled == queue_size) {
				priq->batch++;
				wake_up_all_locked(&priq->wq);
				num_handled = 0;
			}
		}

		if (queue_sync_prod_in(q) == -EOVERFLOW) {
			dev_err(smmu->dev, "PRIQ overflow detected -- requests lost\n");
			overflow = true;
		}
	} while (!queue_empty(llq));

	/* Sync our overflow flag, as we believe we're up to speed */
	queue_sync_cons_ovf(q);

	wake_up_all_locked(&priq->wq);
	spin_unlock(&priq->wq.lock);

	/*
	 * On overflow, the SMMU might have discarded the last PPR in a group.
	 * There is no way to know more about it, so we have to discard all
	 * partial faults already queued.
	 */
	if (overflow)
		iopf_queue_discard_partial(priq->iopf);

	return IRQ_HANDLED;
}

/*
 * arm_smmu_flush_priq - wait until all events currently in the queue have been
 *                       consumed.
 *
 * When unbinding a PASID, ensure there aren't any pending page requests for
 * that PASID in the queue.
 *
 * Wait either that the queue becomes empty or, if new events are continually
 * added the queue, that the event queue thread has handled a full batch (where
 * one batch corresponds to the queue size). For that we take the batch number
 * when entering flush() and wait for the event queue thread to increment it
 * twice. Note that we don't handle overflows on q->batch. If it occurs, just
 * wait for the queue to become empty.
 */
int arm_smmu_flush_priq(struct arm_smmu_device *smmu)
{
	int ret;
	u64 batch;
	bool overflow = false;
	struct arm_smmu_priq *priq = &smmu->priq;
	struct arm_smmu_queue *q = &priq->q;

	spin_lock(&priq->wq.lock);
	if (queue_sync_prod_in(q) == -EOVERFLOW) {
		dev_err(smmu->dev, "priq overflow detected -- requests lost\n");
		overflow = true;
	}

	batch = priq->batch;
	ret = wait_event_interruptible_locked(priq->wq, queue_empty(&q->llq) ||
					      priq->batch >= batch + 2);
	spin_unlock(&priq->wq.lock);

	if (overflow)
		iopf_queue_discard_partial(priq->iopf);
	return ret;
}

static int arm_smmu_device_disable(struct arm_smmu_device *smmu);

static irqreturn_t arm_smmu_gerror_handler(int irq, void *dev)
{
	u32 gerror, gerrorn, active;
	struct arm_smmu_device *smmu = dev;

	gerror = readl_relaxed(smmu->base + ARM_SMMU_GERROR);
	gerrorn = readl_relaxed(smmu->base + ARM_SMMU_GERRORN);

	active = gerror ^ gerrorn;
	if (!(active & GERROR_ERR_MASK))
		return IRQ_NONE; /* No errors pending */

	dev_warn(smmu->dev,
		 "unexpected global error reported (0x%08x), this could be serious\n",
		 active);

	if (active & GERROR_SFM_ERR) {
		dev_err(smmu->dev, "device has entered Service Failure Mode!\n");
		arm_smmu_device_disable(smmu);
	}

	if (active & GERROR_MSI_GERROR_ABT_ERR)
		dev_warn(smmu->dev, "GERROR MSI write aborted\n");

	if (active & GERROR_MSI_PRIQ_ABT_ERR)
		dev_warn(smmu->dev, "PRIQ MSI write aborted\n");

	if (active & GERROR_MSI_EVTQ_ABT_ERR)
		dev_warn(smmu->dev, "EVTQ MSI write aborted\n");

	if (active & GERROR_MSI_CMDQ_ABT_ERR)
		dev_warn(smmu->dev, "CMDQ MSI write aborted\n");

	if (active & GERROR_PRIQ_ABT_ERR)
		dev_err(smmu->dev, "PRIQ write aborted -- events may have been lost\n");

	if (active & GERROR_EVTQ_ABT_ERR)
		dev_err(smmu->dev, "EVTQ write aborted -- events may have been lost\n");

	if (active & GERROR_CMDQ_ERR)
		arm_smmu_cmdq_skip_err(smmu);

	if (active & GERROR_CMDQP_ERR)
		arm_smmu_ecmdq_skip_err(smmu);

	writel(gerror, smmu->base + ARM_SMMU_GERRORN);
	return IRQ_HANDLED;
}

static irqreturn_t arm_smmu_combined_irq_thread(int irq, void *dev)
{
	struct arm_smmu_device *smmu = dev;

	arm_smmu_evtq_thread(irq, dev);
	if (smmu->features & ARM_SMMU_FEAT_PRI)
		arm_smmu_priq_thread(irq, dev);

	return IRQ_HANDLED;
}

static irqreturn_t arm_smmu_combined_irq_handler(int irq, void *dev)
{
	arm_smmu_gerror_handler(irq, dev);
	return IRQ_WAKE_THREAD;
}

static void
arm_smmu_atc_inv_to_cmd(int ssid, unsigned long iova, size_t size,
			struct arm_smmu_cmdq_ent *cmd)
{
	size_t log2_span;
	size_t span_mask;
	/* ATC invalidates are always on 4096-bytes pages */
	size_t inval_grain_shift = 12;
	unsigned long page_start, page_end;

	/*
	 * ATS and PASID:
	 *
	 * If substream_valid is clear, the PCIe TLP is sent without a PASID
	 * prefix. In that case all ATC entries within the address range are
	 * invalidated, including those that were requested with a PASID! There
	 * is no way to invalidate only entries without PASID.
	 *
	 * When using STRTAB_STE_1_S1DSS_SSID0 (reserving CD 0 for non-PASID
	 * traffic), translation requests without PASID create ATC entries
	 * without PASID, which must be invalidated with substream_valid clear.
	 * This has the unpleasant side-effect of invalidating all PASID-tagged
	 * ATC entries within the address range.
	 */
	*cmd = (struct arm_smmu_cmdq_ent) {
		.opcode			= CMDQ_OP_ATC_INV,
		.substream_valid	= !!ssid,
		.atc.ssid		= ssid,
	};

	if (!size) {
		cmd->atc.size = ATC_INV_SIZE_ALL;
		return;
	}

	page_start	= iova >> inval_grain_shift;
	page_end	= (iova + size - 1) >> inval_grain_shift;

	/*
	 * In an ATS Invalidate Request, the address must be aligned on the
	 * range size, which must be a power of two number of page sizes. We
	 * thus have to choose between grossly over-invalidating the region, or
	 * splitting the invalidation into multiple commands. For simplicity
	 * we'll go with the first solution, but should refine it in the future
	 * if multiple commands are shown to be more efficient.
	 *
	 * Find the smallest power of two that covers the range. The most
	 * significant differing bit between the start and end addresses,
	 * fls(start ^ end), indicates the required span. For example:
	 *
	 * We want to invalidate pages [8; 11]. This is already the ideal range:
	 *		x = 0b1000 ^ 0b1011 = 0b11
	 *		span = 1 << fls(x) = 4
	 *
	 * To invalidate pages [7; 10], we need to invalidate [0; 15]:
	 *		x = 0b0111 ^ 0b1010 = 0b1101
	 *		span = 1 << fls(x) = 16
	 */
	log2_span	= fls_long(page_start ^ page_end);
	span_mask	= (1ULL << log2_span) - 1;

	page_start	&= ~span_mask;

	cmd->atc.addr	= page_start << inval_grain_shift;
	cmd->atc.size	= log2_span;
}

static int arm_smmu_atc_inv_master(struct arm_smmu_master *master, unsigned int ssid)
{
	int i, ret;
	struct arm_smmu_cmdq_ent cmd;
	struct arm_smmu_cmdq_batch cmds = {};
	struct arm_smmu_device *smmu = master->smmu;

	arm_smmu_atc_inv_to_cmd(ssid, 0, 0, &cmd);

	arm_smmu_preempt_disable(smmu);
	for (i = 0; i < master->num_streams; i++) {
		cmd.atc.sid = master->streams[i].id;
		arm_smmu_cmdq_batch_add(smmu, &cmds, &cmd);
	}

	ret = arm_smmu_cmdq_batch_submit(smmu, &cmds);
	arm_smmu_preempt_enable(smmu);

	return ret;
}

int arm_smmu_atc_inv_domain(struct arm_smmu_domain *smmu_domain, int ssid,
			    unsigned long iova, size_t size)
{
	int i, ret;
	unsigned long flags;
	struct arm_smmu_cmdq_ent cmd;
	struct arm_smmu_master *master;
	struct arm_smmu_cmdq_batch cmds = {};
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (!(smmu->features & ARM_SMMU_FEAT_ATS))
		return 0;

	/*
	 * Ensure that we've completed prior invalidation of the main TLBs
	 * before we read 'nr_ats_masters' in case of a concurrent call to
	 * arm_smmu_enable_ats():
	 *
	 *	// unmap()			// arm_smmu_enable_ats()
	 *	TLBI+SYNC			atomic_inc(&nr_ats_masters);
	 *	smp_mb();			[...]
	 *	atomic_read(&nr_ats_masters);	pci_enable_ats() // writel()
	 *
	 * Ensures that we always see the incremented 'nr_ats_masters' count if
	 * ATS was enabled at the PCI device before completion of the TLBI.
	 */
	smp_mb();
	if (!atomic_read(&smmu_domain->nr_ats_masters))
		return 0;

	arm_smmu_atc_inv_to_cmd(ssid, iova, size, &cmd);

	arm_smmu_preempt_disable(smmu);
	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_for_each_entry(master, &smmu_domain->devices, domain_head) {
		if (!master->ats_enabled)
			continue;

		for (i = 0; i < master->num_streams; i++) {
			cmd.atc.sid = master->streams[i].id;
			arm_smmu_cmdq_batch_add(smmu, &cmds, &cmd);
		}
	}
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	ret = arm_smmu_cmdq_batch_submit(smmu, &cmds);
	arm_smmu_preempt_enable(smmu);

	return ret;
}

/* IO_PGTABLE API */
static void arm_smmu_tlb_inv_context(void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cmdq_ent cmd;

	/*
	 * NOTE: when io-pgtable is in non-strict mode, we may get here with
	 * PTEs previously cleared by unmaps on the current CPU not yet visible
	 * to the SMMU. We are relying on the dma_wmb() implicit during cmd
	 * insertion to guarantee those are observed before the TLBI. Do be
	 * careful, 007.
	 */
	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		arm_smmu_tlb_inv_asid(smmu, smmu_domain->s1_cfg.cd.asid);
	} else {
		cmd.opcode	= CMDQ_OP_TLBI_S12_VMALL;
		cmd.tlbi.vmid	= smmu_domain->s2_cfg.vmid;
		arm_smmu_cmdq_issue_cmd_with_sync(smmu, &cmd);
	}
	if (smmu_domain->parent)
		arm_smmu_atc_inv_domain(smmu_domain->parent, smmu_domain->ssid,
					0, 0);
	else
		arm_smmu_atc_inv_domain(smmu_domain, 0, 0, 0);

}

static void __arm_smmu_tlb_inv_range(struct arm_smmu_cmdq_ent *cmd,
				     unsigned long iova, size_t size,
				     size_t granule,
				     struct arm_smmu_domain *smmu_domain)
{
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	unsigned long end = iova + size, num_pages = 0, tg = 0;
	size_t inv_range = granule;
	struct arm_smmu_cmdq_batch cmds = {};

	if (!size)
		return;

	if (smmu->features & ARM_SMMU_FEAT_RANGE_INV) {
		/* Get the leaf page size */
		tg = __ffs(smmu_domain->domain.pgsize_bitmap);

		/* Convert page size of 12,14,16 (log2) to 1,2,3 */
		cmd->tlbi.tg = (tg - 10) / 2;

		/* Determine what level the granule is at */
		cmd->tlbi.ttl = 4 - ((ilog2(granule) - 3) / (tg - 3));

		num_pages = size >> tg;
	}

	arm_smmu_preempt_disable(smmu);
	while (iova < end) {
		if (smmu->features & ARM_SMMU_FEAT_RANGE_INV) {
			/*
			 * On each iteration of the loop, the range is 5 bits
			 * worth of the aligned size remaining.
			 * The range in pages is:
			 *
			 * range = (num_pages & (0x1f << __ffs(num_pages)))
			 */
			unsigned long scale, num;

			/* Determine the power of 2 multiple number of pages */
			scale = __ffs(num_pages);
			cmd->tlbi.scale = scale;

			/* Determine how many chunks of 2^scale size we have */
			num = (num_pages >> scale) & CMDQ_TLBI_RANGE_NUM_MAX;
			cmd->tlbi.num = num - 1;

			/* range is num * 2^scale * pgsize */
			inv_range = num << (scale + tg);

			/* Clear out the lower order bits for the next iteration */
			num_pages -= num << scale;
		}

		cmd->tlbi.addr = iova;
		arm_smmu_cmdq_batch_add(smmu, &cmds, cmd);
		iova += inv_range;
	}
	arm_smmu_cmdq_batch_submit(smmu, &cmds);
	arm_smmu_preempt_enable(smmu);
}

static void arm_smmu_tlb_inv_range_domain(unsigned long iova, size_t size,
					  size_t granule, bool leaf,
					  struct arm_smmu_domain *smmu_domain)
{
	struct arm_smmu_cmdq_ent cmd = {
		.tlbi = {
			.leaf	= leaf,
		},
	};

	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		cmd.opcode	= smmu_domain->smmu->features & ARM_SMMU_FEAT_E2H ?
				  CMDQ_OP_TLBI_EL2_VA : CMDQ_OP_TLBI_NH_VA;
		cmd.tlbi.asid	= smmu_domain->s1_cfg.cd.asid;
	} else {
		cmd.opcode	= CMDQ_OP_TLBI_S2_IPA;
		cmd.tlbi.vmid	= smmu_domain->s2_cfg.vmid;
	}
	__arm_smmu_tlb_inv_range(&cmd, iova, size, granule, smmu_domain);

	/*
	 * Unfortunately, this can't be leaf-only since we may have
	 * zapped an entire table.
	 */
	if (smmu_domain->parent)
		arm_smmu_atc_inv_domain(smmu_domain->parent, smmu_domain->ssid,
					iova, size);
	else
		arm_smmu_atc_inv_domain(smmu_domain, 0, iova, size);
}

void arm_smmu_tlb_inv_range_asid(unsigned long iova, size_t size, int asid,
				 size_t granule, bool leaf,
				 struct arm_smmu_domain *smmu_domain)
{
	struct arm_smmu_cmdq_ent cmd = {
		.opcode	= smmu_domain->smmu->features & ARM_SMMU_FEAT_E2H ?
			  CMDQ_OP_TLBI_EL2_VA : CMDQ_OP_TLBI_NH_VA,
		.tlbi = {
			.asid	= asid,
			.leaf	= leaf,
		},
	};

	__arm_smmu_tlb_inv_range(&cmd, iova, size, granule, smmu_domain);
}

static void arm_smmu_tlb_inv_page_nosync(struct iommu_iotlb_gather *gather,
					 unsigned long iova, size_t granule,
					 void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct iommu_domain *domain = &smmu_domain->domain;

	iommu_iotlb_gather_add_page(domain, gather, iova, granule);
}

static void arm_smmu_tlb_inv_walk(unsigned long iova, size_t size,
				  size_t granule, void *cookie)
{
#ifdef CONFIG_HISILICON_ERRATUM_162100602
	if (!size) {
		arm_smmu_tlb_inv_range_domain(iova, granule, granule, true, cookie);
		return;
	}
#endif
	arm_smmu_tlb_inv_range_domain(iova, size, granule, false, cookie);
}

static const struct iommu_flush_ops arm_smmu_flush_ops = {
	.tlb_flush_all	= arm_smmu_tlb_inv_context,
	.tlb_flush_walk = arm_smmu_tlb_inv_walk,
	.tlb_add_page	= arm_smmu_tlb_inv_page_nosync,
};

/* IOMMU API */
static bool arm_smmu_capable(enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return true;
	case IOMMU_CAP_NOEXEC:
		return true;
	default:
		return false;
	}
}

static struct iommu_domain *arm_smmu_domain_alloc(unsigned type)
{
	struct arm_smmu_domain *smmu_domain;

	if (type != IOMMU_DOMAIN_UNMANAGED &&
	    type != IOMMU_DOMAIN_DMA &&
	    type != IOMMU_DOMAIN_IDENTITY)
		return NULL;

	/*
	 * Allocate the domain and initialise some of its data structures.
	 * We can't really do anything meaningful until we've added a
	 * master.
	 */
	smmu_domain = kzalloc(sizeof(*smmu_domain), GFP_KERNEL);
	if (!smmu_domain)
		return NULL;

	if (type == IOMMU_DOMAIN_DMA &&
	    iommu_get_dma_cookie(&smmu_domain->domain)) {
		kfree(smmu_domain);
		return NULL;
	}

	mutex_init(&smmu_domain->init_mutex);
	INIT_LIST_HEAD(&smmu_domain->devices);
	spin_lock_init(&smmu_domain->devices_lock);
	INIT_LIST_HEAD(&smmu_domain->mmu_notifiers);

	return &smmu_domain->domain;
}

static int arm_smmu_bitmap_alloc(unsigned long *map, int span)
{
	int idx, size = 1 << span;

	do {
		idx = find_first_zero_bit(map, size);
		if (idx == size)
			return -ENOSPC;
	} while (test_and_set_bit(idx, map));

	return idx;
}

static void arm_smmu_bitmap_free(unsigned long *map, int idx)
{
	clear_bit(idx, map);
}

static void arm_smmu_domain_free(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	iommu_put_dma_cookie(domain);
	free_io_pgtable_ops(smmu_domain->pgtbl_ops);

	/* Free the CD and ASID, if we allocated them */
	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1) {
		struct arm_smmu_s1_cfg *cfg = &smmu_domain->s1_cfg;

		/* Prevent SVA from touching the CD while we're freeing it */
		mutex_lock(&arm_smmu_asid_lock);
		if (cfg->cdcfg.cdtab)
			arm_smmu_free_cd_tables(smmu_domain);
		arm_smmu_free_asid(&cfg->cd);
		mutex_unlock(&arm_smmu_asid_lock);
		if (smmu_domain->ssid)
			ioasid_free(smmu_domain->ssid);
	} else {
		struct arm_smmu_s2_cfg *cfg = &smmu_domain->s2_cfg;
		if (cfg->vmid)
			arm_smmu_bitmap_free(smmu->vmid_map, cfg->vmid);
	}

	kfree(smmu_domain);
}

static int arm_smmu_domain_finalise_cd(struct arm_smmu_domain *smmu_domain,
				       struct arm_smmu_master *master,
				       struct io_pgtable_cfg *pgtbl_cfg)
{
	int ret;
	u32 asid;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_s1_cfg *cfg = &smmu_domain->s1_cfg;
	typeof(&pgtbl_cfg->arm_lpae_s1_cfg.tcr) tcr = &pgtbl_cfg->arm_lpae_s1_cfg.tcr;

	refcount_set(&cfg->cd.refs, 1);

	ret = xa_alloc(&arm_smmu_asid_xa, &asid, &cfg->cd,
		       XA_LIMIT(1, (1 << smmu->asid_bits) - 1), GFP_KERNEL);
	if (ret)
		return ret;

	cfg->cd.asid	= (u16)asid;
	cfg->cd.ttbr	= pgtbl_cfg->arm_lpae_s1_cfg.ttbr;
	cfg->cd.tcr	= FIELD_PREP(CTXDESC_CD_0_TCR_T0SZ, tcr->tsz) |
			  FIELD_PREP(CTXDESC_CD_0_TCR_TG0, tcr->tg) |
			  FIELD_PREP(CTXDESC_CD_0_TCR_IRGN0, tcr->irgn) |
			  FIELD_PREP(CTXDESC_CD_0_TCR_ORGN0, tcr->orgn) |
			  FIELD_PREP(CTXDESC_CD_0_TCR_SH0, tcr->sh) |
			  FIELD_PREP(CTXDESC_CD_0_TCR_IPS, tcr->ips) |
			  CTXDESC_CD_0_TCR_HA | CTXDESC_CD_0_TCR_HD |
			  CTXDESC_CD_0_TCR_EPD1 | CTXDESC_CD_0_AA64;
	cfg->cd.mair	= pgtbl_cfg->arm_lpae_s1_cfg.mair;
	return 0;
}

static int arm_smmu_domain_finalise_s1(struct arm_smmu_domain *smmu_domain,
				       struct arm_smmu_master *master,
				       struct io_pgtable_cfg *pgtbl_cfg)
{
	int ret;
	struct arm_smmu_s1_cfg *cfg = &smmu_domain->s1_cfg;

	/* Prevent SVA from modifying the ASID until it is written to the CD */
	mutex_lock(&arm_smmu_asid_lock);
	ret = arm_smmu_domain_finalise_cd(smmu_domain, master, pgtbl_cfg);
	if (ret)
		goto out_unlock;

	cfg->s1cdmax = master->ssid_bits;

	smmu_domain->stall_enabled = master->stall_enabled;

	ret = arm_smmu_alloc_cd_tables(smmu_domain);
	if (ret)
		goto out_free_asid;

	/*
	 * Note that this will end up calling arm_smmu_sync_cd() before
	 * the master has been added to the devices list for this domain.
	 * This isn't an issue because the STE hasn't been installed yet.
	 */
	ret = arm_smmu_write_ctx_desc(smmu_domain, 0, &cfg->cd);
	if (ret)
		goto out_free_cd_tables;

	mutex_unlock(&arm_smmu_asid_lock);
	return 0;

out_free_cd_tables:
	arm_smmu_free_cd_tables(smmu_domain);
out_free_asid:
	arm_smmu_free_asid(&cfg->cd);
out_unlock:
	mutex_unlock(&arm_smmu_asid_lock);
	return ret;
}

static int arm_smmu_domain_finalise_s2(struct arm_smmu_domain *smmu_domain,
				       struct arm_smmu_master *master,
				       struct io_pgtable_cfg *pgtbl_cfg)
{
	int vmid;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_s2_cfg *cfg = &smmu_domain->s2_cfg;
	typeof(&pgtbl_cfg->arm_lpae_s2_cfg.vtcr) vtcr;

	vmid = arm_smmu_bitmap_alloc(smmu->vmid_map, smmu->vmid_bits);
	if (vmid < 0)
		return vmid;

	vtcr = &pgtbl_cfg->arm_lpae_s2_cfg.vtcr;
	cfg->vmid	= (u16)vmid;
	cfg->vttbr	= pgtbl_cfg->arm_lpae_s2_cfg.vttbr;
	cfg->vtcr	= FIELD_PREP(STRTAB_STE_2_VTCR_S2T0SZ, vtcr->tsz) |
			  FIELD_PREP(STRTAB_STE_2_VTCR_S2SL0, vtcr->sl) |
			  FIELD_PREP(STRTAB_STE_2_VTCR_S2IR0, vtcr->irgn) |
			  FIELD_PREP(STRTAB_STE_2_VTCR_S2OR0, vtcr->orgn) |
			  FIELD_PREP(STRTAB_STE_2_VTCR_S2SH0, vtcr->sh) |
			  FIELD_PREP(STRTAB_STE_2_VTCR_S2TG, vtcr->tg) |
			  FIELD_PREP(STRTAB_STE_2_VTCR_S2PS, vtcr->ps);
	return 0;
}

static int arm_smmu_domain_finalise(struct iommu_domain *domain,
				    struct arm_smmu_master *master)
{
	int ret;
	unsigned long ias, oas;
	enum io_pgtable_fmt fmt;
	struct io_pgtable_cfg pgtbl_cfg;
	struct io_pgtable_ops *pgtbl_ops;
	int (*finalise_stage_fn)(struct arm_smmu_domain *,
				 struct arm_smmu_master *,
				 struct io_pgtable_cfg *);
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (domain->type == IOMMU_DOMAIN_IDENTITY) {
		smmu_domain->stage = ARM_SMMU_DOMAIN_BYPASS;
		return 0;
	}

	/* Restrict the stage to what we can actually support */
	if (!(smmu->features & ARM_SMMU_FEAT_TRANS_S1))
		smmu_domain->stage = ARM_SMMU_DOMAIN_S2;
	if (!(smmu->features & ARM_SMMU_FEAT_TRANS_S2))
		smmu_domain->stage = ARM_SMMU_DOMAIN_S1;

	switch (smmu_domain->stage) {
	case ARM_SMMU_DOMAIN_S1:
		ias = (smmu->features & ARM_SMMU_FEAT_VAX) ? 52 : 48;
		ias = min_t(unsigned long, ias, VA_BITS);
		oas = smmu->ias;
		fmt = ARM_64_LPAE_S1;
		if (smmu_domain->parent)
			finalise_stage_fn = arm_smmu_domain_finalise_cd;
		else
			finalise_stage_fn = arm_smmu_domain_finalise_s1;
		break;
	case ARM_SMMU_DOMAIN_NESTED:
	case ARM_SMMU_DOMAIN_S2:
		ias = smmu->ias;
		oas = smmu->oas;
		fmt = ARM_64_LPAE_S2;
		finalise_stage_fn = arm_smmu_domain_finalise_s2;
		break;
	default:
		return -EINVAL;
	}

	pgtbl_cfg = (struct io_pgtable_cfg) {
		.pgsize_bitmap	= smmu->pgsize_bitmap,
		.ias		= ias,
		.oas		= oas,
		.coherent_walk	= smmu->features & ARM_SMMU_FEAT_COHERENCY,
		.tlb		= &arm_smmu_flush_ops,
		.iommu_dev	= smmu->dev,
	};

	if (smmu_domain->non_strict)
		pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_NON_STRICT;
	if (smmu->features & ARM_SMMU_FEAT_HD)
		pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_ARM_HD;

	if (smmu->features & ARM_SMMU_FEAT_BBML1)
		pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_ARM_BBML1;
	else if (smmu->features & ARM_SMMU_FEAT_BBML2)
		pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_ARM_BBML2;

	if (smmu->options & ARM_SMMU_OPT_SYNC_BATCH)
		pgtbl_cfg.quirks |= IO_PGTABLE_QUIRK_HISI_ERRATA;

	pgtbl_ops = alloc_io_pgtable_ops(fmt, &pgtbl_cfg, smmu_domain);
	if (!pgtbl_ops)
		return -ENOMEM;

	domain->pgsize_bitmap = pgtbl_cfg.pgsize_bitmap;
	domain->geometry.aperture_end = (1UL << pgtbl_cfg.ias) - 1;
	domain->geometry.force_aperture = true;

	ret = finalise_stage_fn(smmu_domain, master, &pgtbl_cfg);
	if (ret < 0) {
		free_io_pgtable_ops(pgtbl_ops);
		return ret;
	}

	smmu_domain->pgtbl_ops = pgtbl_ops;
	return 0;
}

static __le64 *arm_smmu_get_step_for_sid(struct arm_smmu_device *smmu, u32 sid)
{
	__le64 *step;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
		struct arm_smmu_strtab_l1_desc *l1_desc;
		int idx;

		/* Two-level walk */
		idx = (sid >> STRTAB_SPLIT) * STRTAB_L1_DESC_DWORDS;
		l1_desc = &cfg->l1_desc[idx];
		idx = (sid & ((1 << STRTAB_SPLIT) - 1)) * STRTAB_STE_DWORDS;
		step = &l1_desc->l2ptr[idx];
	} else {
		/* Simple linear lookup */
		step = &cfg->strtab[sid * STRTAB_STE_DWORDS];
	}

	return step;
}

static void arm_smmu_install_ste_for_dev(struct arm_smmu_master *master)
{
	int i, j;
	struct arm_smmu_device *smmu = master->smmu;

	for (i = 0; i < master->num_streams; ++i) {
		u32 sid = master->streams[i].id;
		__le64 *step = arm_smmu_get_step_for_sid(smmu, sid);

		/* Bridged PCI devices may end up with duplicated IDs */
		for (j = 0; j < i; j++)
			if (master->streams[j].id == sid)
				break;
		if (j < i)
			continue;

		arm_smmu_write_strtab_ent(master, sid, step);
	}
}

static bool arm_smmu_ats_supported(struct arm_smmu_master *master)
{
	struct device *dev = master->dev;
	struct arm_smmu_device *smmu = master->smmu;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

	if (!(smmu->features & ARM_SMMU_FEAT_ATS))
		return false;

	if (!(fwspec->flags & IOMMU_FWSPEC_PCI_RC_ATS))
		return false;

	return dev_is_pci(dev) && pci_ats_supported(to_pci_dev(dev));
}

static void arm_smmu_enable_ats(struct arm_smmu_master *master)
{
	size_t stu;
	struct pci_dev *pdev;
	struct arm_smmu_device *smmu = master->smmu;
	struct arm_smmu_domain *smmu_domain = master->domain;

	/* Don't enable ATS at the endpoint if it's not enabled in the STE */
	if (!master->ats_enabled)
		return;

	/* Smallest Translation Unit: log2 of the smallest supported granule */
	stu = __ffs(smmu->pgsize_bitmap);
	pdev = to_pci_dev(master->dev);

	atomic_inc(&smmu_domain->nr_ats_masters);
	arm_smmu_atc_inv_domain(smmu_domain, 0, 0, 0);
	if (pci_enable_ats(pdev, stu))
		dev_err(master->dev, "Failed to enable ATS (STU %zu)\n", stu);
}

static void arm_smmu_disable_ats(struct arm_smmu_master *master)
{
	struct arm_smmu_domain *smmu_domain = master->domain;

	if (!master->ats_enabled)
		return;

	pci_disable_ats(to_pci_dev(master->dev));
	/*
	 * Ensure ATS is disabled at the endpoint before we issue the
	 * ATC invalidation via the SMMU.
	 */
	wmb();
	arm_smmu_atc_inv_master(master, 0);
	atomic_dec(&smmu_domain->nr_ats_masters);
}

static int arm_smmu_enable_pasid(struct arm_smmu_master *master)
{
	int ret;
	int features;
	int num_pasids;
	struct pci_dev *pdev;

	if (!dev_is_pci(master->dev))
		return -ENODEV;

	pdev = to_pci_dev(master->dev);

	features = pci_pasid_features(pdev);
	if (features < 0)
		return features;

	num_pasids = pci_max_pasids(pdev);
	if (num_pasids <= 0)
		return num_pasids;

	ret = pci_enable_pasid(pdev, features);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable PASID\n");
		return ret;
	}

	master->ssid_bits = min_t(u8, ilog2(num_pasids),
				  master->smmu->ssid_bits);
	return 0;
}

static void arm_smmu_disable_pasid(struct arm_smmu_master *master)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(master->dev))
		return;

	pdev = to_pci_dev(master->dev);

	if (!pdev->pasid_enabled)
		return;

	master->ssid_bits = 0;
	pci_disable_pasid(pdev);
}

static int arm_smmu_init_pri(struct arm_smmu_master *master)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(master->dev))
		return -EINVAL;

	if (!(master->smmu->features & ARM_SMMU_FEAT_PRI))
		return 0;

	pdev = to_pci_dev(master->dev);
	if (!pci_pri_supported(pdev))
		return 0;

	/* If the device supports PASID and PRI, set STE.PPAR */
	if (master->ssid_bits)
		master->prg_resp_needs_ssid = pci_prg_resp_pasid_required(pdev);

	master->pri_supported = true;
	return 0;
}

int arm_smmu_enable_pri(struct arm_smmu_master *master)
{
	int ret;
	struct pci_dev *pdev;
	/*
	 * TODO: find a good inflight PPR number. According to the SMMU spec we
	 * should divide the PRI queue by the number of PRI-capable devices, but
	 * it's impossible to know about future (probed late or hotplugged)
	 * devices. So we might miss some PPRs due to queue overflow.
	 */
	size_t max_inflight_pprs = 16;

	if (!master->pri_supported || !master->ats_enabled)
		return -ENODEV;

	pdev = to_pci_dev(master->dev);

	ret = pci_reset_pri(pdev);
	if (ret)
		return ret;

	ret = pci_enable_pri(pdev, max_inflight_pprs);
	if (ret) {
		dev_err(master->dev, "cannot enable PRI: %d\n", ret);
		return ret;
	}

	return 0;
}

void arm_smmu_disable_pri(struct arm_smmu_master *master)
{
	struct pci_dev *pdev;

	if (!dev_is_pci(master->dev))
		return;

	pdev = to_pci_dev(master->dev);

	if (!pdev->pri_enabled)
		return;

	pci_disable_pri(pdev);
}

static void arm_smmu_detach_dev(struct arm_smmu_master *master)
{
	unsigned long flags;
	struct arm_smmu_domain *smmu_domain = master->domain;

	if (!smmu_domain)
		return;

	arm_smmu_disable_ats(master);

	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_del(&master->domain_head);
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	master->domain = NULL;
	master->ats_enabled = false;
	arm_smmu_install_ste_for_dev(master);
}

static int arm_smmu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	int ret = 0;
	unsigned long flags;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct arm_smmu_device *smmu;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_master *master;

	if (!fwspec)
		return -ENOENT;

	master = dev_iommu_priv_get(dev);
	smmu = master->smmu;

	/*
	 * Checking that SVA is disabled ensures that this device isn't bound to
	 * any mm, and can be safely detached from its old domain. Bonds cannot
	 * be removed concurrently since we're holding the group mutex.
	 */
	if (arm_smmu_master_sva_enabled(master)) {
		dev_err(dev, "cannot attach - SVA enabled\n");
		return -EBUSY;
	}

	arm_smmu_detach_dev(master);

	mutex_lock(&smmu_domain->init_mutex);

	if (!smmu_domain->smmu) {
		smmu_domain->smmu = smmu;
		ret = arm_smmu_domain_finalise(domain, master);
		if (ret) {
			smmu_domain->smmu = NULL;
			goto out_unlock;
		}
	} else if (smmu_domain->smmu != smmu) {
		dev_err(dev,
			"cannot attach to SMMU %s (upstream of %s)\n",
			dev_name(smmu_domain->smmu->dev),
			dev_name(smmu->dev));
		ret = -ENXIO;
		goto out_unlock;
	} else if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1 &&
		   master->ssid_bits != smmu_domain->s1_cfg.s1cdmax) {
		dev_err(dev,
			"cannot attach to incompatible domain (%u SSID bits != %u)\n",
			smmu_domain->s1_cfg.s1cdmax, master->ssid_bits);
		ret = -EINVAL;
		goto out_unlock;
	} else if (smmu_domain->stage == ARM_SMMU_DOMAIN_S1 &&
		   smmu_domain->stall_enabled != master->stall_enabled) {
		dev_err(dev, "cannot attach to stall-%s domain\n",
			smmu_domain->stall_enabled ? "enabled" : "disabled");
		ret = -EINVAL;
		goto out_unlock;
	} else if (smmu_domain->parent) {
		dev_err(dev, "cannot attach auxiliary domain\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	master->domain = smmu_domain;

	if (smmu_domain->stage != ARM_SMMU_DOMAIN_BYPASS)
		master->ats_enabled = arm_smmu_ats_supported(master);

	arm_smmu_install_ste_for_dev(master);

	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_add(&master->domain_head, &smmu_domain->devices);
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	arm_smmu_enable_ats(master);

out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
	return ret;
}

static int arm_smmu_map(struct iommu_domain *domain, unsigned long iova,
			phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
	struct io_pgtable_ops *ops = to_smmu_domain(domain)->pgtbl_ops;

	if (!ops)
		return -ENODEV;

	return ops->map(ops, iova, paddr, size, prot, gfp);
}

static size_t arm_smmu_unmap(struct iommu_domain *domain, unsigned long iova,
			     size_t size, struct iommu_iotlb_gather *gather)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;

	if (!ops)
		return 0;

	return ops->unmap(ops, iova, size, gather);
}

static void arm_smmu_flush_iotlb_all(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (smmu_domain->smmu)
		arm_smmu_tlb_inv_context(smmu_domain);
}

static void arm_smmu_iotlb_sync(struct iommu_domain *domain,
				struct iommu_iotlb_gather *gather)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	arm_smmu_tlb_inv_range_domain(gather->start, gather->end - gather->start + 1,
			       gather->pgsize, true, smmu_domain);
}

#ifdef CONFIG_HISILICON_ERRATUM_162100602
static void arm_smmu_iotlb_sync_map(struct iommu_domain *domain,
				unsigned long iova, size_t size)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	size_t granule_size;

	if (!(smmu_domain->smmu->options & ARM_SMMU_OPT_SYNC_MAP))
		return;

	if (smmu_domain->smmu->options & ARM_SMMU_OPT_SYNC_BATCH)
		return;

	granule_size = 1 <<  __ffs(smmu_domain->domain.pgsize_bitmap);

	/* Add a SYNC command to sync io-pgtale to avoid errors in pgtable prefetch*/
	arm_smmu_tlb_inv_range_domain(iova, granule_size, granule_size, true, smmu_domain);
}
#endif

static phys_addr_t
arm_smmu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
	struct io_pgtable_ops *ops = to_smmu_domain(domain)->pgtbl_ops;

	if (domain->type == IOMMU_DOMAIN_IDENTITY)
		return iova;

	if (!ops)
		return 0;

	return ops->iova_to_phys(ops, iova);
}

static struct platform_driver arm_smmu_driver;

static
struct arm_smmu_device *arm_smmu_get_by_fwnode(struct fwnode_handle *fwnode)
{
	struct device *dev = driver_find_device_by_fwnode(&arm_smmu_driver.driver,
							  fwnode);
	put_device(dev);
	return dev ? dev_get_drvdata(dev) : NULL;
}

static bool arm_smmu_sid_in_range(struct arm_smmu_device *smmu, u32 sid)
{
	unsigned long limit = smmu->strtab_cfg.num_l1_ents;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		limit *= 1UL << STRTAB_SPLIT;

	return sid < limit;
}

static int arm_smmu_insert_master(struct arm_smmu_device *smmu,
				  struct arm_smmu_master *master)
{
	int i;
	int ret = 0;
	struct arm_smmu_stream *new_stream, *cur_stream;
	struct rb_node **new_node, *parent_node = NULL;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(master->dev);

	master->streams = kcalloc(fwspec->num_ids, sizeof(*master->streams),
				  GFP_KERNEL);
	if (!master->streams)
		return -ENOMEM;
	master->num_streams = fwspec->num_ids;

	mutex_lock(&smmu->streams_mutex);
	for (i = 0; i < fwspec->num_ids; i++) {
		u32 sid = fwspec->ids[i];

		new_stream = &master->streams[i];
		new_stream->id = sid;
		new_stream->master = master;

		/*
		 * Check the SIDs are in range of the SMMU and our stream table
		 */
		if (!arm_smmu_sid_in_range(smmu, sid)) {
			ret = -ERANGE;
			break;
		}

		/* Ensure l2 strtab is initialised */
		if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
			ret = arm_smmu_init_l2_strtab(smmu, sid);
			if (ret)
				break;
		}

		/* Insert into SID tree */
		new_node = &(smmu->streams.rb_node);
		while (*new_node) {
			cur_stream = rb_entry(*new_node, struct arm_smmu_stream,
					      node);
			parent_node = *new_node;
			if (cur_stream->id > new_stream->id) {
				new_node = &((*new_node)->rb_left);
			} else if (cur_stream->id < new_stream->id) {
				new_node = &((*new_node)->rb_right);
			} else {
				dev_warn(master->dev,
					 "stream %u already in tree\n",
					 cur_stream->id);
				ret = -EINVAL;
				break;
			}
		}
		if (ret)
			break;

		rb_link_node(&new_stream->node, parent_node, new_node);
		rb_insert_color(&new_stream->node, &smmu->streams);
	}

	if (ret) {
		for (i--; i >= 0; i--)
			rb_erase(&master->streams[i].node, &smmu->streams);
		kfree(master->streams);
	}
	mutex_unlock(&smmu->streams_mutex);

	return ret;
}

static void arm_smmu_remove_master(struct arm_smmu_master *master)
{
	int i;
	struct arm_smmu_device *smmu = master->smmu;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(master->dev);

	if (!smmu || !master->streams)
		return;

	mutex_lock(&smmu->streams_mutex);
	for (i = 0; i < fwspec->num_ids; i++)
		rb_erase(&master->streams[i].node, &smmu->streams);
	mutex_unlock(&smmu->streams_mutex);

	kfree(master->streams);
}

static struct iommu_ops arm_smmu_ops;

static struct iommu_device *arm_smmu_probe_device(struct device *dev)
{
	int ret;
	struct arm_smmu_device *smmu;
	struct arm_smmu_master *master;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
#ifdef CONFIG_ASCEND_FEATURES
	u32 sid;
	const union acpi_object *obj = NULL;
#endif

	if (!fwspec || fwspec->ops != &arm_smmu_ops)
		return ERR_PTR(-ENODEV);

	if (WARN_ON_ONCE(dev_iommu_priv_get(dev)))
		return ERR_PTR(-EBUSY);

	smmu = arm_smmu_get_by_fwnode(fwspec->iommu_fwnode);
	if (!smmu)
		return ERR_PTR(-ENODEV);

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	master->dev = dev;
	master->smmu = smmu;
	INIT_LIST_HEAD(&master->bonds);
	dev_iommu_priv_set(dev, master);

	ret = arm_smmu_insert_master(smmu, master);
	if (ret)
		goto err_free_master;

	device_property_read_u32(dev, "pasid-num-bits", &master->ssid_bits);
	master->ssid_bits = min(smmu->ssid_bits, master->ssid_bits);

	/*
	 * Note that PASID must be enabled before, and disabled after ATS:
	 * PCI Express Base 4.0r1.0 - 10.5.1.3 ATS Control Register
	 *
	 *   Behavior is undefined if this bit is Set and the value of the PASID
	 *   Enable, Execute Requested Enable, or Privileged Mode Requested bits
	 *   are changed.
	 */
	arm_smmu_enable_pasid(master);

	if (!(smmu->features & ARM_SMMU_FEAT_2_LVL_CDTAB))
		master->ssid_bits = min_t(u8, master->ssid_bits,
					  CTXDESC_LINEAR_CDMAX);

	if ((smmu->features & ARM_SMMU_FEAT_STALLS &&
	     device_property_read_bool(dev, "dma-can-stall")) ||
	    smmu->features & ARM_SMMU_FEAT_STALL_FORCE)
		master->stall_enabled = true;

#ifdef CONFIG_ASCEND_FEATURES
	if (!acpi_dev_get_property(ACPI_COMPANION(dev),
			"streamid", ACPI_TYPE_INTEGER, &obj) && obj) {
		sid = obj->integer.value;
		if (iommu_fwspec_add_ids(dev, &sid, 1))
			dev_info(dev, "failed to add ids\n");
		master->stall_enabled = true;
		master->ssid_bits = 0x10;
	}
#endif
	arm_smmu_init_pri(master);

	return &smmu->iommu;

err_free_master:
	kfree(master);
	dev_iommu_priv_set(dev, NULL);
	return ERR_PTR(ret);
}

static void arm_smmu_release_device(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct arm_smmu_master *master;

	if (!fwspec || fwspec->ops != &arm_smmu_ops)
		return;

	master = dev_iommu_priv_get(dev);
	if (WARN_ON(arm_smmu_master_sva_enabled(master))) {
		iopf_queue_remove_device(master->smmu->evtq.iopf, dev);
		iopf_queue_remove_device(master->smmu->priq.iopf, dev);
	}
	arm_smmu_detach_dev(master);
	arm_smmu_disable_pasid(master);
	arm_smmu_remove_master(master);
	kfree(master);
	iommu_fwspec_free(dev);
}

static struct iommu_group *arm_smmu_device_group(struct device *dev)
{
	struct iommu_group *group;

	/*
	 * We don't support devices sharing stream IDs other than PCI RID
	 * aliases, since the necessary ID-to-device lookup becomes rather
	 * impractical given a potential sparse 32-bit stream ID space.
	 */
	if (dev_is_pci(dev))
		group = pci_device_group(dev);
	else
		group = generic_device_group(dev);

	return group;
}

static int arm_smmu_domain_get_attr(struct iommu_domain *domain,
				    enum iommu_attr attr, void *data)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	switch (domain->type) {
	case IOMMU_DOMAIN_UNMANAGED:
		switch (attr) {
		case DOMAIN_ATTR_NESTING:
			*(int *)data = (smmu_domain->stage == ARM_SMMU_DOMAIN_NESTED);
			return 0;
		default:
			return -ENODEV;
		}
		break;
	case IOMMU_DOMAIN_DMA:
		switch (attr) {
		case DOMAIN_ATTR_DMA_USE_FLUSH_QUEUE:
			*(int *)data = smmu_domain->non_strict;
			return 0;
		default:
			return -ENODEV;
		}
		break;
	default:
		return -EINVAL;
	}
}

static int arm_smmu_domain_set_attr(struct iommu_domain *domain,
				    enum iommu_attr attr, void *data)
{
	int ret = 0;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	mutex_lock(&smmu_domain->init_mutex);

	switch (domain->type) {
	case IOMMU_DOMAIN_UNMANAGED:
		switch (attr) {
		case DOMAIN_ATTR_NESTING:
			if (smmu_domain->smmu) {
				ret = -EPERM;
				goto out_unlock;
			}

			if (*(int *)data)
				smmu_domain->stage = ARM_SMMU_DOMAIN_NESTED;
			else
				smmu_domain->stage = ARM_SMMU_DOMAIN_S1;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	case IOMMU_DOMAIN_DMA:
		switch(attr) {
		case DOMAIN_ATTR_DMA_USE_FLUSH_QUEUE:
			smmu_domain->non_strict = *(int *)data;
			break;
		default:
			ret = -ENODEV;
		}
		break;
	default:
		ret = -EINVAL;
	}

out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
	return ret;
}

static int arm_smmu_split_block(struct iommu_domain *domain,
				unsigned long iova, size_t size)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;
	size_t handled_size;

	if (!(smmu->features & (ARM_SMMU_FEAT_BBML1 | ARM_SMMU_FEAT_BBML2))) {
		dev_err(smmu->dev, "don't support BBML1/2, can't split block\n");
		return -ENODEV;
	}
	if (!ops || !ops->split_block) {
		pr_err("io-pgtable don't realize split block\n");
		return -ENODEV;
	}

	handled_size = ops->split_block(ops, iova, size);
	if (handled_size != size) {
		pr_err("split block failed\n");
		return -EFAULT;
	}

	return 0;
}

static int __arm_smmu_merge_page(struct iommu_domain *domain,
				 unsigned long iova, phys_addr_t paddr,
				 size_t size, int prot)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;
	size_t handled_size;

	if (!ops || !ops->merge_page) {
		pr_err("io-pgtable don't realize merge page\n");
		return -ENODEV;
	}

	while (size) {
		size_t pgsize = iommu_pgsize(domain, iova | paddr, size);

		handled_size = ops->merge_page(ops, iova, paddr, pgsize, prot);
		if (handled_size != pgsize) {
			pr_err("merge page failed\n");
			return -EFAULT;
		}

		pr_debug("merge handled: iova 0x%lx pa %pa size 0x%zx\n",
			 iova, &paddr, pgsize);

		iova += pgsize;
		paddr += pgsize;
		size -= pgsize;
	}

	return 0;
}

static int arm_smmu_merge_page(struct iommu_domain *domain, unsigned long iova,
			       size_t size, int prot)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;
	phys_addr_t phys;
	dma_addr_t p, i;
	size_t cont_size;
	int ret = 0;

	if (!(smmu->features & (ARM_SMMU_FEAT_BBML1 | ARM_SMMU_FEAT_BBML2))) {
		dev_err(smmu->dev, "don't support BBML1/2, can't merge page\n");
		return -ENODEV;
	}

	if (!ops || !ops->iova_to_phys)
		return -ENODEV;

	while (size) {
		phys = ops->iova_to_phys(ops, iova);
		cont_size = PAGE_SIZE;
		p = phys + cont_size;
		i = iova + cont_size;

		while (cont_size < size && p == ops->iova_to_phys(ops, i)) {
			p += PAGE_SIZE;
			i += PAGE_SIZE;
			cont_size += PAGE_SIZE;
		}

		if (cont_size != PAGE_SIZE) {
			ret = __arm_smmu_merge_page(domain, iova, phys,
						    cont_size, prot);
			if (ret)
				break;
		}

		iova += cont_size;
		size -= cont_size;
	}

	return ret;
}

static bool arm_smmu_support_dirty_log(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	return !!(smmu_domain->smmu->features & ARM_SMMU_FEAT_HD);
}

static int arm_smmu_switch_dirty_log(struct iommu_domain *domain, bool enable,
				     unsigned long iova, size_t size, int prot)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (!(smmu->features & ARM_SMMU_FEAT_HD))
		return -ENODEV;
	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1)
		return -EINVAL;

	if (enable) {
		/*
		 * For SMMU, the hardware dirty management is always enabled if
		 * hardware supports HTTU HD. The action to start dirty log is
		 * spliting block mapping.
		 *
		 * We don't return error even if the split operation fail, as we
		 * can still track dirty at block granule, which is still a much
		 * better choice compared to full dirty policy.
		 */
		arm_smmu_split_block(domain, iova, size);
	} else {
		/*
		 * For SMMU, the hardware dirty management is always enabled if
		 * hardware supports HTTU HD. The action to stop dirty log is
		 * merging page mapping.
		 *
		 * We don't return error even if the merge operation fail, as it
		 * just effects performace of DMA transaction.
		 */
		arm_smmu_merge_page(domain, iova, size, prot);
	}

	return 0;
}

static int arm_smmu_sync_dirty_log(struct iommu_domain *domain,
				   unsigned long iova, size_t size,
				   unsigned long *bitmap,
				   unsigned long base_iova,
				   unsigned long bitmap_pgshift)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (!(smmu->features & ARM_SMMU_FEAT_HD))
		return -ENODEV;
	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1)
		return -EINVAL;

	if (!ops || !ops->sync_dirty_log) {
		pr_err("io-pgtable don't realize sync dirty log\n");
		return -ENODEV;
	}

	/*
	 * Flush iotlb to ensure all inflight transactions are completed.
	 * See doc IHI0070Da 3.13.4 "HTTU behavior summary".
	 */
	arm_smmu_flush_iotlb_all(domain);
	return ops->sync_dirty_log(ops, iova, size, bitmap, base_iova,
				   bitmap_pgshift);
}

static int arm_smmu_clear_dirty_log(struct iommu_domain *domain,
				    unsigned long iova, size_t size,
				    unsigned long *bitmap,
				    unsigned long base_iova,
				    unsigned long bitmap_pgshift)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;
	struct arm_smmu_device *smmu = smmu_domain->smmu;

	if (!(smmu->features & ARM_SMMU_FEAT_HD))
		return -ENODEV;
	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1)
		return -EINVAL;

	if (!ops || !ops->clear_dirty_log) {
		pr_err("io-pgtable don't realize clear dirty log\n");
		return -ENODEV;
	}

	return ops->clear_dirty_log(ops, iova, size, bitmap, base_iova,
				    bitmap_pgshift);
}

static int arm_smmu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

static void arm_smmu_get_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *region;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	region = iommu_alloc_resv_region(MSI_IOVA_BASE, MSI_IOVA_LENGTH,
					 prot, IOMMU_RESV_SW_MSI);
	if (!region)
		return;

	list_add_tail(&region->list, head);

	iommu_dma_get_resv_regions(dev, head);
}

static bool arm_smmu_dev_has_feature(struct device *dev,
				     enum iommu_dev_features feat)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);

	if (!master)
		return false;

	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return arm_smmu_master_iopf_supported(master);
	case IOMMU_DEV_FEAT_SVA:
		return arm_smmu_master_sva_supported(master);
	case IOMMU_DEV_FEAT_AUX:
		return master->ssid_bits != 0;
	default:
		return false;
	}
}

static bool arm_smmu_dev_feature_enabled(struct device *dev,
					 enum iommu_dev_features feat)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);

	if (!master)
		return false;

	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return master->iopf_enabled;
	case IOMMU_DEV_FEAT_SVA:
		return arm_smmu_master_sva_enabled(master);
	case IOMMU_DEV_FEAT_AUX:
		return master->auxd_enabled;
	default:
		return false;
	}
}

static int arm_smmu_dev_enable_feature(struct device *dev,
				       enum iommu_dev_features feat)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);

	if (!arm_smmu_dev_has_feature(dev, feat))
		return -ENODEV;

	if (arm_smmu_dev_feature_enabled(dev, feat))
		return -EBUSY;

	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return arm_smmu_master_enable_iopf(master);
	case IOMMU_DEV_FEAT_SVA:
		return arm_smmu_master_enable_sva(master);
	case IOMMU_DEV_FEAT_AUX:
		master->auxd_enabled = true;
		return 0;
	default:
		return -EINVAL;
	}
}

static int arm_smmu_dev_disable_feature(struct device *dev,
					enum iommu_dev_features feat)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);

	if (!arm_smmu_dev_feature_enabled(dev, feat))
		return -EINVAL;

	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return arm_smmu_master_disable_iopf(master);
	case IOMMU_DEV_FEAT_SVA:
		return arm_smmu_master_disable_sva(master);
	case IOMMU_DEV_FEAT_AUX:
		/* TODO: check if aux domains are still attached? */
		master->auxd_enabled = false;
		return 0;
	default:
		return -EINVAL;
	}
}

static int arm_smmu_aux_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	int ret;
	struct iommu_domain *parent_domain;
	struct arm_smmu_domain *parent_smmu_domain;
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (!arm_smmu_dev_feature_enabled(dev, IOMMU_DEV_FEAT_AUX))
		return -EINVAL;

	parent_domain = iommu_get_domain_for_dev(dev);
	if (!parent_domain)
		return -EINVAL;
	parent_smmu_domain = to_smmu_domain(parent_domain);

	mutex_lock(&smmu_domain->init_mutex);
	if (smmu_domain->stage != ARM_SMMU_DOMAIN_S1 ||
	    parent_smmu_domain->stage != ARM_SMMU_DOMAIN_S1) {
		ret = -EINVAL;
		goto out_unlock;
	} else if (smmu_domain->s1_cfg.cdcfg.cdtab) {
		/* Already attached as a normal domain */
		dev_err(dev, "cannot attach domain in auxiliary mode\n");
		ret = -EINVAL;
		goto out_unlock;
	} else if (!smmu_domain->smmu) {
		ioasid_t ssid = ioasid_alloc(&private_ioasid, 1,
					     (1UL << master->ssid_bits) - 1,
					     NULL);
		if (ssid == INVALID_IOASID) {
			ret = -EINVAL;
			goto out_unlock;
		}
		smmu_domain->smmu = master->smmu;
		smmu_domain->parent = parent_smmu_domain;
		smmu_domain->ssid = ssid;

		ret = arm_smmu_domain_finalise(domain, master);
		if (ret) {
			smmu_domain->smmu = NULL;
			smmu_domain->ssid = 0;
			smmu_domain->parent = NULL;
			ioasid_free(ssid);
			goto out_unlock;
		}
	} else if (smmu_domain->parent != parent_smmu_domain) {
		/* Additional restriction: an aux domain has a single parent */
		dev_err(dev, "cannot attach aux domain with different parent\n");
		ret = -EINVAL;
		goto out_unlock;
	} else {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* FIXME: serialize against arm_smmu_share_asid() */
	if (!smmu_domain->aux_nr_devs++)
		arm_smmu_write_ctx_desc(parent_smmu_domain, smmu_domain->ssid,
					&smmu_domain->s1_cfg.cd);
	/*
	 * Note that all other devices attached to the parent domain can now
	 * access this context as well.
	 */

out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
	return ret;
}

static void arm_smmu_aux_detach_dev(struct iommu_domain *domain, struct device *dev)
{
	struct iommu_domain *parent_domain;
	struct arm_smmu_domain *parent_smmu_domain;
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (!arm_smmu_dev_feature_enabled(dev, IOMMU_DEV_FEAT_AUX))
		return;

	parent_domain = iommu_get_domain_for_dev(dev);
	if (!parent_domain)
		return;
	parent_smmu_domain = to_smmu_domain(parent_domain);

	mutex_lock(&smmu_domain->init_mutex);
	if (!smmu_domain->aux_nr_devs)
		goto out_unlock;

	if (!--smmu_domain->aux_nr_devs) {
		arm_smmu_write_ctx_desc(parent_smmu_domain, smmu_domain->ssid,
					NULL);
		/*
		 * TLB doesn't need invalidation since accesses from the device
		 * can't use this domain's ASID once the CD is clear.
		 *
		 * Sadly that doesn't apply to ATCs, which are PASID tagged.
		 * Invalidate all other devices as well, because even though
		 * they weren't 'officially' attached to the auxiliary domain,
		 * they could have formed ATC entries.
		 */
		arm_smmu_atc_inv_domain(parent_smmu_domain, smmu_domain->ssid,
					0, 0);
	} else {
		/* Invalidate only this device's ATC */
		arm_smmu_atc_inv_master(master, smmu_domain->ssid);
	}
out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
}

static int arm_smmu_aux_get_pasid(struct iommu_domain *domain, struct device *dev)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	return smmu_domain->ssid ?: -EINVAL;
}

static int arm_smmu_set_mpam(struct arm_smmu_device *smmu,
		int sid, int ssid, int partid, int pmg, int s1mpam)
{
	struct arm_smmu_master *master = arm_smmu_find_master(smmu, sid);
	struct arm_smmu_domain *domain = master ? master->domain : NULL;
	u64 val;
	__le64 *ste, *cd;

	struct arm_smmu_cmdq_ent prefetch_cmd = {
		.opcode		= CMDQ_OP_PREFETCH_CFG,
		.prefetch	= {
			.sid	= sid,
		},
	};

	if (WARN_ON(!domain))
		return -EINVAL;
	if (WARN_ON(domain->stage != ARM_SMMU_DOMAIN_S1))
		return -EINVAL;
	if (WARN_ON(ssid >= (1 << domain->s1_cfg.s1cdmax)))
		return -E2BIG;

	if (!(smmu->features & ARM_SMMU_FEAT_MPAM))
		return -ENODEV;

	if (partid > smmu->mpam_partid_max || pmg > smmu->mpam_pmg_max) {
		dev_err(smmu->dev,
			"mpam rmid out of range: partid[0, %d] pmg[0, %d]\n",
			smmu->mpam_partid_max, smmu->mpam_pmg_max);
		return -ERANGE;
	}

	/* get ste ptr */
	ste = arm_smmu_get_step_for_sid(smmu, sid);

	/* write s1mpam to ste */
	val = le64_to_cpu(ste[1]);
	val &= ~STRTAB_STE_1_S1MPAM;
	val |= FIELD_PREP(STRTAB_STE_1_S1MPAM, s1mpam);
	WRITE_ONCE(ste[1], cpu_to_le64(val));

	val = le64_to_cpu(ste[4]);
	val &= ~STRTAB_STE_4_PARTID_MASK;
	val |= FIELD_PREP(STRTAB_STE_4_PARTID_MASK, partid);
	WRITE_ONCE(ste[4], cpu_to_le64(val));

	val = le64_to_cpu(ste[5]);
	val &= ~STRTAB_STE_5_PMG_MASK;
	val |= FIELD_PREP(STRTAB_STE_5_PMG_MASK, pmg);
	WRITE_ONCE(ste[5], cpu_to_le64(val));
	arm_smmu_sync_ste_for_sid(smmu, sid);

	/* do not modify cd table which owned by guest */
	if (domain->stage == ARM_SMMU_DOMAIN_NESTED) {
		dev_err(smmu->dev,
			"mpam: smmu cd is owned by guest, not modified\n");
		return 0;
	}

	/* get cd ptr */
	cd = arm_smmu_get_cd_ptr(domain, ssid);
	if (s1mpam && WARN_ON(!cd))
		return -ENOMEM;

	val = le64_to_cpu(cd[5]);
	val &= ~CTXDESC_CD_5_PARTID_MASK;
	val &= ~CTXDESC_CD_5_PMG_MASK;
	val |= FIELD_PREP(CTXDESC_CD_5_PARTID_MASK, partid);
	val |= FIELD_PREP(CTXDESC_CD_5_PMG_MASK, pmg);
	WRITE_ONCE(cd[5], cpu_to_le64(val));
	arm_smmu_sync_cd(domain, ssid, true);

	/* It's likely that we'll want to use the new STE soon */
	if (!(smmu->options & ARM_SMMU_OPT_SKIP_PREFETCH))
		arm_smmu_cmdq_issue_cmd(smmu, &prefetch_cmd);

	dev_info(smmu->dev, "partid %d, pmg %d\n", partid, pmg);

	return 0;
}

static int arm_smmu_set_dev_user_mpam_en(struct device *dev, int user_mpam_en)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct arm_smmu_device *smmu;
	u32 reg, __iomem *cfg;

	if (WARN_ON(!master))
		return -EINVAL;

	smmu = master->domain->smmu;
	cfg = smmu->base + ARM_SMMU_USER_CFG0;

	reg = readl_relaxed(cfg);
	reg &= ~ARM_SMMU_USER_MPAM_EN;
	reg |= FIELD_PREP(ARM_SMMU_USER_MPAM_EN, user_mpam_en);
	writel(reg, cfg);
	return 0;
}

static int arm_smmu_device_set_mpam(struct device *dev,
				    struct arm_smmu_mpam *mpam)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	int ret;

	if (WARN_ON(!master) || WARN_ON(!mpam))
		return -EINVAL;

	if (mpam->flags & ARM_SMMU_DEV_SET_MPAM) {
		ret = arm_smmu_set_mpam(master->domain->smmu,
					master->streams->id,
					mpam->pasid,
					mpam->partid,
					mpam->pmg,
					mpam->s1mpam);
		if (ret < 0)
			return ret;
	}

	if (mpam->flags & ARM_SMMU_DEV_SET_USER_MPAM_EN) {
		ret = arm_smmu_set_dev_user_mpam_en(dev, mpam->user_mpam_en);
		if (ret < 0)
			return ret;
	}

	return 0;

}

static int arm_smmu_get_mpam(struct arm_smmu_device *smmu,
		int sid, int ssid, int *partid, int *pmg, int *s1mpam)
{
	struct arm_smmu_master *master = arm_smmu_find_master(smmu, sid);
	struct arm_smmu_domain *domain = master ? master->domain : NULL;
	u64 val;
	__le64 *ste, *cd;

	if (WARN_ON(!domain))
		return -EINVAL;
	if (WARN_ON(domain->stage != ARM_SMMU_DOMAIN_S1))
		return -EINVAL;
	if (WARN_ON(ssid >= (1 << domain->s1_cfg.s1cdmax)))
		return -E2BIG;

	if (!(smmu->features & ARM_SMMU_FEAT_MPAM))
		return -ENODEV;

	/* get ste ptr */
	ste = arm_smmu_get_step_for_sid(smmu, sid);

	val = le64_to_cpu(ste[4]);
	*partid = FIELD_GET(STRTAB_STE_4_PARTID_MASK, val);

	val = le64_to_cpu(ste[5]);
	*pmg = FIELD_GET(STRTAB_STE_5_PMG_MASK, val);

	val = le64_to_cpu(ste[1]);
	*s1mpam = FIELD_GET(STRTAB_STE_1_S1MPAM, val);
	/* return STE mpam configuration when s1mpam == 0 */
	if (!(*s1mpam))
		return 0;

	/* get cd ptr */
	cd = arm_smmu_get_cd_ptr(domain, ssid);
	if (WARN_ON(!cd))
		return -ENOMEM;

	val = le64_to_cpu(cd[5]);
	*partid = FIELD_GET(CTXDESC_CD_5_PARTID_MASK, val);
	*pmg = FIELD_GET(CTXDESC_CD_5_PMG_MASK, val);

	return 0;
}

static int arm_smmu_get_dev_user_mpam_en(struct device *dev, int *user_mpam_en)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct arm_smmu_device *smmu;
	u32 reg;

	if (WARN_ON(!master))
		return -EINVAL;

	smmu = master->domain->smmu;

	reg = readl_relaxed(smmu->base + ARM_SMMU_USER_CFG0);
	*user_mpam_en = FIELD_GET(ARM_SMMU_USER_MPAM_EN, reg);
	return 0;
}

static int arm_smmu_device_get_mpam(struct device *dev,
				    struct arm_smmu_mpam *mpam)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	int ret;

	if (WARN_ON(!master) || WARN_ON(!mpam))
		return -EINVAL;

	if (mpam->flags & ARM_SMMU_DEV_GET_MPAM) {
		ret = arm_smmu_get_mpam(master->domain->smmu,
					master->streams->id,
					mpam->pasid,
					&mpam->partid,
					&mpam->pmg,
					&mpam->s1mpam);
		if (ret < 0)
			return ret;
	}

	if (mpam->flags & ARM_SMMU_DEV_GET_USER_MPAM_EN) {
		ret = arm_smmu_get_dev_user_mpam_en(dev, &mpam->user_mpam_en);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int arm_smmu_device_get_config(struct device *dev, int type, void *data)
{
	switch (type) {
	case ARM_SMMU_MPAM:
		return arm_smmu_device_get_mpam(dev, data);
	default:
		return -EINVAL;
	}
}

static int arm_smmu_device_set_config(struct device *dev, int type, void *data)
{
	switch (type) {
	case ARM_SMMU_MPAM:
		return arm_smmu_device_set_mpam(dev, data);
	default:
		return -EINVAL;
	}
}

/*
 * HiSilicon PCIe tune and trace device can be used to trace TLP headers on the
 * PCIe link and save the data to memory by DMA. The hardware is restricted to
 * use identity mapping only.
 */
#define IS_HISI_PTT_DEVICE(pdev)	((pdev)->vendor == PCI_VENDOR_ID_HUAWEI && \
					 (pdev)->device == 0xa12e)

#ifdef CONFIG_SMMU_BYPASS_DEV
static int arm_smmu_bypass_dev_domain_type(struct device *dev)
{
	int i;
	struct pci_dev *pdev = to_pci_dev(dev);

	for (i = 0; i < smmu_bypass_devices_num; i++) {
		if ((smmu_bypass_devices[i].vendor == pdev->vendor) &&
		    (smmu_bypass_devices[i].device == pdev->device)) {
			dev_info(dev, "device 0x%hx:0x%hx uses identity mapping.",
				pdev->vendor, pdev->device);
			return IOMMU_DOMAIN_IDENTITY;
		}
	}

	return 0;
}
#endif

static int arm_smmu_def_domain_type(struct device *dev)
{
	int ret = 0;

	if (dev_is_pci(dev)) {
		struct pci_dev *pdev = to_pci_dev(dev);

		if (IS_HISI_PTT_DEVICE(pdev))
			return IOMMU_DOMAIN_IDENTITY;
		#ifdef CONFIG_SMMU_BYPASS_DEV
			ret = arm_smmu_bypass_dev_domain_type(dev);
		#endif
	}

	return ret;
}

static struct iommu_ops arm_smmu_ops = {
	.capable		= arm_smmu_capable,
	.domain_alloc		= arm_smmu_domain_alloc,
	.domain_free		= arm_smmu_domain_free,
	.attach_dev		= arm_smmu_attach_dev,
	.map			= arm_smmu_map,
	.unmap			= arm_smmu_unmap,
	.flush_iotlb_all	= arm_smmu_flush_iotlb_all,
	.iotlb_sync		= arm_smmu_iotlb_sync,
#ifdef CONFIG_HISILICON_ERRATUM_162100602
	.iotlb_sync_map		= arm_smmu_iotlb_sync_map,
#endif
	.iova_to_phys		= arm_smmu_iova_to_phys,
	.probe_device		= arm_smmu_probe_device,
	.release_device		= arm_smmu_release_device,
	.device_group		= arm_smmu_device_group,
	.domain_get_attr	= arm_smmu_domain_get_attr,
	.domain_set_attr	= arm_smmu_domain_set_attr,
	.support_dirty_log	= arm_smmu_support_dirty_log,
	.switch_dirty_log	= arm_smmu_switch_dirty_log,
	.sync_dirty_log		= arm_smmu_sync_dirty_log,
	.clear_dirty_log	= arm_smmu_clear_dirty_log,
	.of_xlate		= arm_smmu_of_xlate,
	.get_resv_regions	= arm_smmu_get_resv_regions,
	.put_resv_regions	= generic_iommu_put_resv_regions,
	.dev_has_feat		= arm_smmu_dev_has_feature,
	.dev_feat_enabled	= arm_smmu_dev_feature_enabled,
	.dev_enable_feat	= arm_smmu_dev_enable_feature,
	.dev_disable_feat	= arm_smmu_dev_disable_feature,
	.sva_bind		= arm_smmu_sva_bind,
	.sva_unbind		= arm_smmu_sva_unbind,
	.sva_get_pasid		= arm_smmu_sva_get_pasid,
	.page_response		= arm_smmu_page_response,
	.def_domain_type        = arm_smmu_def_domain_type,
	.aux_attach_dev		= arm_smmu_aux_attach_dev,
	.aux_detach_dev		= arm_smmu_aux_detach_dev,
	.aux_get_pasid		= arm_smmu_aux_get_pasid,
	.dev_get_config		= arm_smmu_device_get_config,
	.dev_set_config		= arm_smmu_device_set_config,
	.pgsize_bitmap		= -1UL, /* Restricted during device attach */
};

/* Probing and initialisation functions */
static int arm_smmu_init_one_queue(struct arm_smmu_device *smmu,
				   struct arm_smmu_queue *q,
				   void __iomem *page,
				   unsigned long prod_off,
				   unsigned long cons_off,
				   size_t dwords, const char *name)
{
	size_t qsz;

	do {
		qsz = ((1 << q->llq.max_n_shift) * dwords) << 3;
		q->base = dmam_alloc_coherent(smmu->dev, qsz, &q->base_dma,
					      GFP_KERNEL);
		if (q->base || qsz < PAGE_SIZE)
			break;

		q->llq.max_n_shift--;
	} while (1);

	if (!q->base) {
		dev_err(smmu->dev,
			"failed to allocate queue (0x%zx bytes) for %s\n",
			qsz, name);
		return -ENOMEM;
	}

	if (!WARN_ON(q->base_dma & (qsz - 1))) {
		dev_info(smmu->dev, "allocated %u entries for %s\n",
			 1 << q->llq.max_n_shift, name);
	}

	q->prod_reg	= page + prod_off;
	q->cons_reg	= page + cons_off;
	q->ent_dwords	= dwords;

	q->q_base  = Q_BASE_RWA;
	q->q_base |= q->base_dma & Q_BASE_ADDR_MASK;
	q->q_base |= FIELD_PREP(Q_BASE_LOG2SIZE, q->llq.max_n_shift);

	q->llq.prod = q->llq.cons = 0;
	return 0;
}

static void arm_smmu_cmdq_free_bitmap(void *data)
{
	unsigned long *bitmap = data;
	bitmap_free(bitmap);
}

static int arm_smmu_cmdq_init(struct arm_smmu_device *smmu)
{
	int ret = 0;
	struct arm_smmu_cmdq *cmdq = &smmu->cmdq;
	unsigned int nents = 1 << cmdq->q.llq.max_n_shift;
	atomic_long_t *bitmap;

	cmdq->shared = 1;
	atomic_set(&cmdq->owner_prod, 0);
	atomic_set(&cmdq->lock, 0);

	bitmap = (atomic_long_t *)bitmap_zalloc(nents, GFP_KERNEL);
	if (!bitmap) {
		dev_err(smmu->dev, "failed to allocate cmdq bitmap\n");
		ret = -ENOMEM;
	} else {
		cmdq->valid_map = bitmap;
		devm_add_action(smmu->dev, arm_smmu_cmdq_free_bitmap, bitmap);
	}

	return ret;
}

static int arm_smmu_ecmdq_init(struct arm_smmu_cmdq *cmdq)
{
	unsigned int nents = 1 << cmdq->q.llq.max_n_shift;

	atomic_set(&cmdq->owner_prod, 0);
	atomic_set(&cmdq->lock, 0);

	cmdq->valid_map = (atomic_long_t *)bitmap_zalloc(nents, GFP_KERNEL);
	if (!cmdq->valid_map)
		return -ENOMEM;

	return 0;
}

static int arm_smmu_init_queues(struct arm_smmu_device *smmu)
{
	int ret;

	/* cmdq */
	ret = arm_smmu_init_one_queue(smmu, &smmu->cmdq.q, smmu->base,
				      ARM_SMMU_CMDQ_PROD, ARM_SMMU_CMDQ_CONS,
				      CMDQ_ENT_DWORDS, "cmdq");
	if (ret)
		return ret;

	ret = arm_smmu_cmdq_init(smmu);
	if (ret)
		return ret;

	/* evtq */
	ret = arm_smmu_init_one_queue(smmu, &smmu->evtq.q, smmu->page1,
				      ARM_SMMU_EVTQ_PROD, ARM_SMMU_EVTQ_CONS,
				      EVTQ_ENT_DWORDS, "evtq");
	if (ret)
		return ret;

	if ((smmu->features & ARM_SMMU_FEAT_SVA) &&
	    (smmu->features & ARM_SMMU_FEAT_STALLS)) {
		smmu->evtq.iopf = iopf_queue_alloc(dev_name(smmu->dev));
		if (!smmu->evtq.iopf)
			return -ENOMEM;
	}

	/* priq */
	if (!(smmu->features & ARM_SMMU_FEAT_PRI))
		return 0;

	if (smmu->features & ARM_SMMU_FEAT_SVA) {
		smmu->priq.iopf = iopf_queue_alloc(dev_name(smmu->dev));
		if (!smmu->priq.iopf)
			return -ENOMEM;
	}

	init_waitqueue_head(&smmu->priq.wq);
	smmu->priq.batch = 0;

	return arm_smmu_init_one_queue(smmu, &smmu->priq.q, smmu->page1,
				       ARM_SMMU_PRIQ_PROD, ARM_SMMU_PRIQ_CONS,
				       PRIQ_ENT_DWORDS, "priq");
}

static int arm_smmu_init_l1_strtab(struct arm_smmu_device *smmu)
{
	unsigned int i;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	size_t size = sizeof(*cfg->l1_desc) * cfg->num_l1_ents;
	void *strtab = smmu->strtab_cfg.strtab;

	cfg->l1_desc = devm_kzalloc(smmu->dev, size, GFP_KERNEL);
	if (!cfg->l1_desc) {
		dev_err(smmu->dev, "failed to allocate l1 stream table desc\n");
		return -ENOMEM;
	}

	for (i = 0; i < cfg->num_l1_ents; ++i) {
		arm_smmu_write_strtab_l1_desc(strtab, &cfg->l1_desc[i]);
		strtab += STRTAB_L1_DESC_DWORDS << 3;
	}

	return 0;
}

#ifdef CONFIG_SMMU_BYPASS_DEV
static void arm_smmu_install_bypass_ste_for_dev(struct arm_smmu_device *smmu,
				    u32 sid)
{
	u64 val;
	__le64 *step = arm_smmu_get_step_for_sid(smmu, sid);

	if (!step)
		return;

	val = STRTAB_STE_0_V;
	val |= FIELD_PREP(STRTAB_STE_0_CFG, STRTAB_STE_0_CFG_BYPASS);
	step[0] = cpu_to_le64(val);
	step[1] = cpu_to_le64(FIELD_PREP(STRTAB_STE_1_SHCFG,
	STRTAB_STE_1_SHCFG_INCOMING));
	step[2] = 0;
}

static int arm_smmu_prepare_init_l2_strtab(struct device *dev, void *data)
{
	u32 sid;
	int ret;
	struct pci_dev *pdev;
	struct arm_smmu_device *smmu = (struct arm_smmu_device *)data;

	if (!arm_smmu_def_domain_type(dev))
		return 0;

	pdev = to_pci_dev(dev);
	sid = PCI_DEVID(pdev->bus->number, pdev->devfn);
	if (!arm_smmu_sid_in_range(smmu, sid))
		return -ERANGE;

	ret = arm_smmu_init_l2_strtab(smmu, sid);
	if (ret)
		return ret;

	arm_smmu_install_bypass_ste_for_dev(smmu, sid);

	return 0;
}
#endif

static int arm_smmu_init_strtab_2lvl(struct arm_smmu_device *smmu)
{
	void *strtab;
	u64 reg;
	u32 size, l1size;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
#ifdef CONFIG_SMMU_BYPASS_DEV
	int ret;
#endif

	/* Calculate the L1 size, capped to the SIDSIZE. */
	size = STRTAB_L1_SZ_SHIFT - (ilog2(STRTAB_L1_DESC_DWORDS) + 3);
	size = min(size, smmu->sid_bits - STRTAB_SPLIT);
	cfg->num_l1_ents = 1 << size;

	size += STRTAB_SPLIT;
	if (size < smmu->sid_bits)
		dev_warn(smmu->dev,
			 "2-level strtab only covers %u/%u bits of SID\n",
			 size, smmu->sid_bits);

	l1size = cfg->num_l1_ents * (STRTAB_L1_DESC_DWORDS << 3);
	strtab = dmam_alloc_coherent(smmu->dev, l1size, &cfg->strtab_dma,
				     GFP_KERNEL);
	if (!strtab) {
		dev_err(smmu->dev,
			"failed to allocate l1 stream table (%u bytes)\n",
			l1size);
		return -ENOMEM;
	}
	cfg->strtab = strtab;

	/* Configure strtab_base_cfg for 2 levels */
	reg  = FIELD_PREP(STRTAB_BASE_CFG_FMT, STRTAB_BASE_CFG_FMT_2LVL);
	reg |= FIELD_PREP(STRTAB_BASE_CFG_LOG2SIZE, size);
	reg |= FIELD_PREP(STRTAB_BASE_CFG_SPLIT, STRTAB_SPLIT);
	cfg->strtab_base_cfg = reg;
#ifdef CONFIG_SMMU_BYPASS_DEV
	ret = arm_smmu_init_l1_strtab(smmu);
	if (ret)
		return ret;

	if (smmu_bypass_devices_num) {
		ret = bus_for_each_dev(&pci_bus_type, NULL, (void *)smmu,
								arm_smmu_prepare_init_l2_strtab);
	}

	return ret;
#else
	return arm_smmu_init_l1_strtab(smmu);
#endif
}

static int arm_smmu_init_strtab_linear(struct arm_smmu_device *smmu)
{
	void *strtab;
	u64 reg;
	u32 size;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	size = (1 << smmu->sid_bits) * (STRTAB_STE_DWORDS << 3);
	strtab = dmam_alloc_coherent(smmu->dev, size, &cfg->strtab_dma,
				     GFP_KERNEL);
	if (!strtab) {
		dev_err(smmu->dev,
			"failed to allocate linear stream table (%u bytes)\n",
			size);
		return -ENOMEM;
	}
	cfg->strtab = strtab;
	cfg->num_l1_ents = 1 << smmu->sid_bits;

	/* Configure strtab_base_cfg for a linear table covering all SIDs */
	reg  = FIELD_PREP(STRTAB_BASE_CFG_FMT, STRTAB_BASE_CFG_FMT_LINEAR);
	reg |= FIELD_PREP(STRTAB_BASE_CFG_LOG2SIZE, smmu->sid_bits);
	cfg->strtab_base_cfg = reg;

	arm_smmu_init_bypass_stes(strtab, cfg->num_l1_ents);
	return 0;
}

static int arm_smmu_init_strtab(struct arm_smmu_device *smmu)
{
	u64 reg;
	int ret;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		ret = arm_smmu_init_strtab_2lvl(smmu);
	else
		ret = arm_smmu_init_strtab_linear(smmu);

	if (ret)
		return ret;

	/* Set the strtab base address */
	reg  = smmu->strtab_cfg.strtab_dma & STRTAB_BASE_ADDR_MASK;
	reg |= STRTAB_BASE_RA;
	smmu->strtab_cfg.strtab_base = reg;

	/* Allocate the first VMID for stage-2 bypass STEs */
	set_bit(0, smmu->vmid_map);
	return 0;
}

static int arm_smmu_init_structures(struct arm_smmu_device *smmu)
{
	int ret;

	mutex_init(&smmu->streams_mutex);
	smmu->streams = RB_ROOT;

	ret = arm_smmu_init_queues(smmu);
	if (ret)
		return ret;

	return arm_smmu_init_strtab(smmu);
}

static int arm_smmu_write_reg_sync(struct arm_smmu_device *smmu, u32 val,
				   unsigned int reg_off, unsigned int ack_off)
{
	u32 reg;

	writel_relaxed(val, smmu->base + reg_off);
	return readl_relaxed_poll_timeout(smmu->base + ack_off, reg, reg == val,
					  1, ARM_SMMU_POLL_TIMEOUT_US);
}

/* GBPA is "special" */
static int arm_smmu_update_gbpa(struct arm_smmu_device *smmu, u32 set, u32 clr)
{
	int ret;
	u32 reg, __iomem *gbpa = smmu->base + ARM_SMMU_GBPA;

	ret = readl_relaxed_poll_timeout(gbpa, reg, !(reg & GBPA_UPDATE),
					 1, ARM_SMMU_POLL_TIMEOUT_US);
	if (ret)
		return ret;

	reg &= ~clr;
	reg |= set;
	writel_relaxed(reg | GBPA_UPDATE, gbpa);
	ret = readl_relaxed_poll_timeout(gbpa, reg, !(reg & GBPA_UPDATE),
					 1, ARM_SMMU_POLL_TIMEOUT_US);

	if (ret)
		dev_err(smmu->dev, "GBPA not responding to update\n");
	return ret;
}

static void arm_smmu_free_msis(void *data)
{
	struct device *dev = data;
	platform_msi_domain_free_irqs(dev);
}

static void arm_smmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	phys_addr_t doorbell;
	struct device *dev = msi_desc_to_dev(desc);
	struct arm_smmu_device *smmu = dev_get_drvdata(dev);
	phys_addr_t *cfg = arm_smmu_msi_cfg[desc->platform.msi_index];

	doorbell = (((u64)msg->address_hi) << 32) | msg->address_lo;
	doorbell &= MSI_CFG0_ADDR_MASK;

#ifdef CONFIG_ARM_SMMU_V3_PM
	/* Saves the msg (base addr of msi irq) and restores it during resume */
	desc->msg.address_lo = msg->address_lo;
	desc->msg.address_hi = msg->address_hi;
	desc->msg.data = msg->data;
#endif

	writeq_relaxed(doorbell, smmu->base + cfg[0]);
	writel_relaxed(msg->data, smmu->base + cfg[1]);
	writel_relaxed(ARM_SMMU_MEMATTR_DEVICE_nGnRE, smmu->base + cfg[2]);
}

static void arm_smmu_setup_msis(struct arm_smmu_device *smmu)
{
	struct msi_desc *desc;
	int ret, nvec = ARM_SMMU_MAX_MSIS;
	struct device *dev = smmu->dev;

	/* Clear the MSI address regs */
	writeq_relaxed(0, smmu->base + ARM_SMMU_GERROR_IRQ_CFG0);
	writeq_relaxed(0, smmu->base + ARM_SMMU_EVTQ_IRQ_CFG0);

	if (smmu->features & ARM_SMMU_FEAT_PRI)
		writeq_relaxed(0, smmu->base + ARM_SMMU_PRIQ_IRQ_CFG0);
	else
		nvec--;

	if (!(smmu->features & ARM_SMMU_FEAT_MSI))
		return;

	if (!dev->msi_domain) {
		dev_info(smmu->dev, "msi_domain absent - falling back to wired irqs\n");
		return;
	}

	/* Allocate MSIs for evtq, gerror and priq. Ignore cmdq */
	ret = platform_msi_domain_alloc_irqs(dev, nvec, arm_smmu_write_msi_msg);
	if (ret) {
		dev_warn(dev, "failed to allocate MSIs - falling back to wired irqs\n");
		return;
	}

	for_each_msi_entry(desc, dev) {
		switch (desc->platform.msi_index) {
		case EVTQ_MSI_INDEX:
			smmu->evtq.q.irq = desc->irq;
			break;
		case GERROR_MSI_INDEX:
			smmu->gerr_irq = desc->irq;
			break;
		case PRIQ_MSI_INDEX:
			smmu->priq.q.irq = desc->irq;
			break;
		default:	/* Unknown */
			continue;
		}
	}

	/* Add callback to free MSIs on teardown */
	devm_add_action(dev, arm_smmu_free_msis, dev);
}

#ifdef CONFIG_ARM_SMMU_V3_PM
static void arm_smmu_resume_msis(struct arm_smmu_device *smmu)
{
	struct msi_desc *desc;
	struct device *dev = smmu->dev;

	for_each_msi_entry(desc, dev) {
		switch (desc->platform.msi_index) {
		case EVTQ_MSI_INDEX:
		case GERROR_MSI_INDEX:
		case PRIQ_MSI_INDEX: {
			phys_addr_t *cfg = arm_smmu_msi_cfg[desc->platform.msi_index];
			struct msi_msg *msg = &desc->msg;
			phys_addr_t doorbell = (((u64)msg->address_hi) << 32) | msg->address_lo;

			doorbell &= MSI_CFG0_ADDR_MASK;
			writeq_relaxed(doorbell, smmu->base + cfg[0]);
			writel_relaxed(msg->data, smmu->base + cfg[1]);
			writel_relaxed(ARM_SMMU_MEMATTR_DEVICE_nGnRE,
					smmu->base + cfg[2]);
			break;
		}
		default:
			continue;

		}
	}
}
#else
static void arm_smmu_resume_msis(struct arm_smmu_device *smmu)
{
}
#endif

static void arm_smmu_setup_unique_irqs(struct arm_smmu_device *smmu, bool resume)
{
	int irq, ret;

	if (!resume)
		arm_smmu_setup_msis(smmu);
	else {
		/* The irq doesn't need to be re-requested during resume */
		arm_smmu_resume_msis(smmu);
		return;
	}

	/* Request interrupt lines */
	irq = smmu->evtq.q.irq;
	if (irq) {
		ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
						arm_smmu_evtq_thread,
						IRQF_ONESHOT,
						"arm-smmu-v3-evtq", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable evtq irq\n");
	} else {
		dev_warn(smmu->dev, "no evtq irq - events will not be reported!\n");
	}

	irq = smmu->gerr_irq;
	if (irq) {
		ret = devm_request_irq(smmu->dev, irq, arm_smmu_gerror_handler,
				       0, "arm-smmu-v3-gerror", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable gerror irq\n");
	} else {
		dev_warn(smmu->dev, "no gerr irq - errors will not be reported!\n");
	}

	if (smmu->features & ARM_SMMU_FEAT_PRI) {
		irq = smmu->priq.q.irq;
		if (irq) {
			ret = devm_request_threaded_irq(smmu->dev, irq, NULL,
							arm_smmu_priq_thread,
							IRQF_ONESHOT,
							"arm-smmu-v3-priq",
							smmu);
			if (ret < 0)
				dev_warn(smmu->dev,
					 "failed to enable priq irq\n");
		} else {
			dev_warn(smmu->dev, "no priq irq - PRI will be broken\n");
		}
	}
}

static int arm_smmu_setup_irqs(struct arm_smmu_device *smmu, bool resume)
{
	int ret, irq;
	u32 irqen_flags = IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN;

	/* Disable IRQs first */
	ret = arm_smmu_write_reg_sync(smmu, 0, ARM_SMMU_IRQ_CTRL,
				      ARM_SMMU_IRQ_CTRLACK);
	if (ret) {
		dev_err(smmu->dev, "failed to disable irqs\n");
		return ret;
	}

	irq = smmu->combined_irq;
	if (irq) {
		/*
		 * Cavium ThunderX2 implementation doesn't support unique irq
		 * lines. Use a single irq line for all the SMMUv3 interrupts.
		 */
		ret = devm_request_threaded_irq(smmu->dev, irq,
					arm_smmu_combined_irq_handler,
					arm_smmu_combined_irq_thread,
					IRQF_ONESHOT,
					"arm-smmu-v3-combined-irq", smmu);
		if (ret < 0)
			dev_warn(smmu->dev, "failed to enable combined irq\n");
	} else
		arm_smmu_setup_unique_irqs(smmu, resume);

	if (smmu->features & ARM_SMMU_FEAT_PRI)
		irqen_flags |= IRQ_CTRL_PRIQ_IRQEN;

	/* Enable interrupt generation on the SMMU */
	ret = arm_smmu_write_reg_sync(smmu, irqen_flags,
				      ARM_SMMU_IRQ_CTRL, ARM_SMMU_IRQ_CTRLACK);
	if (ret)
		dev_warn(smmu->dev, "failed to enable irqs\n");

	return 0;
}

static int arm_smmu_device_disable(struct arm_smmu_device *smmu)
{
	int ret;

	ret = arm_smmu_write_reg_sync(smmu, 0, ARM_SMMU_CR0, ARM_SMMU_CR0ACK);
	if (ret)
		dev_err(smmu->dev, "failed to clear cr0\n");

	return ret;
}

static int arm_smmu_ecmdq_reset(struct arm_smmu_device *smmu)
{
	int i, cpu, ret = 0;
	u32 reg;

	if (!smmu->nr_ecmdq)
		return 0;

	i = 0;
	for_each_possible_cpu(cpu) {
		struct arm_smmu_ecmdq *ecmdq;
		struct arm_smmu_queue *q;

		ecmdq = *per_cpu_ptr(smmu->ecmdqs, cpu);
		if (ecmdq != per_cpu_ptr(smmu->ecmdq, cpu))
			continue;

		q = &ecmdq->cmdq.q;
		i++;

		if (WARN_ON(q->llq.prod != q->llq.cons)) {
			q->llq.prod = 0;
			q->llq.cons = 0;
		}

		reg = readl(q->prod_reg);
		if (reg & ECMDQ_PROD_EN) {
			/* disable ecmdq */
			writel(reg & ~ECMDQ_PROD_EN, q->prod_reg);
			ret = readl_relaxed_poll_timeout(q->cons_reg, reg,
				!(reg & ECMDQ_CONS_ENACK), 1, ARM_SMMU_POLL_TIMEOUT_US);
			if (ret) {
				dev_warn(smmu->dev, "ecmdq[%d] disable failed\n", i);
				smmu->ecmdq_enabled = 0;
				return ret;
			}
		}

		writeq_relaxed(q->q_base, ecmdq->base + ARM_SMMU_ECMDQ_BASE);
		writel_relaxed(q->llq.prod, ecmdq->base + ARM_SMMU_ECMDQ_PROD);
		writel_relaxed(q->llq.cons, ecmdq->base + ARM_SMMU_ECMDQ_CONS);

		/* enable ecmdq */
		writel(ECMDQ_PROD_EN | q->llq.prod, q->prod_reg);
		ret = readl_relaxed_poll_timeout(q->cons_reg, reg, reg & ECMDQ_CONS_ENACK,
					  1, ARM_SMMU_POLL_TIMEOUT_US);
		if (ret) {
			dev_err(smmu->dev, "ecmdq[%d] enable failed\n", i);
			smmu->ecmdq_enabled = 0;
			break;
		}
	}

	return ret;
}

static int arm_smmu_device_reset(struct arm_smmu_device *smmu, bool resume)
{
	int ret;
	u32 reg, enables;
	struct arm_smmu_cmdq_ent cmd;

	/* Clear CR0 and sync (disables SMMU and queue processing) */
	reg = readl_relaxed(smmu->base + ARM_SMMU_CR0);
	if (reg & CR0_SMMUEN) {
		dev_warn(smmu->dev, "SMMU currently enabled! Resetting...\n");
		WARN_ON(is_kdump_kernel() && !disable_bypass);
		arm_smmu_update_gbpa(smmu, GBPA_ABORT, 0);
	}

	ret = arm_smmu_device_disable(smmu);
	if (ret)
		return ret;

	/* CR1 (table and queue memory attributes) */
	reg = FIELD_PREP(CR1_TABLE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_TABLE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_TABLE_IC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_SH, ARM_SMMU_SH_ISH) |
	      FIELD_PREP(CR1_QUEUE_OC, CR1_CACHE_WB) |
	      FIELD_PREP(CR1_QUEUE_IC, CR1_CACHE_WB);
	writel_relaxed(reg, smmu->base + ARM_SMMU_CR1);

	/* CR2 (random crap) */
	reg = CR2_RECINVSID;

	if (smmu->features & ARM_SMMU_FEAT_E2H)
		reg |= CR2_E2H;

	if (!(smmu->features & ARM_SMMU_FEAT_BTM))
		reg |= CR2_PTM;

	writel_relaxed(reg, smmu->base + ARM_SMMU_CR2);

	/* Stream table */
	writeq_relaxed(smmu->strtab_cfg.strtab_base,
		       smmu->base + ARM_SMMU_STRTAB_BASE);
	writel_relaxed(smmu->strtab_cfg.strtab_base_cfg,
		       smmu->base + ARM_SMMU_STRTAB_BASE_CFG);

	/* Command queue */
	writeq_relaxed(smmu->cmdq.q.q_base, smmu->base + ARM_SMMU_CMDQ_BASE);
	writel_relaxed(smmu->cmdq.q.llq.prod, smmu->base + ARM_SMMU_CMDQ_PROD);
	writel_relaxed(smmu->cmdq.q.llq.cons, smmu->base + ARM_SMMU_CMDQ_CONS);

	arm_smmu_ecmdq_reset(smmu);

	enables = CR0_CMDQEN;
	ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
				      ARM_SMMU_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable command queue\n");
		return ret;
	}

	/* Invalidate any cached configuration */
	cmd.opcode = CMDQ_OP_CFGI_ALL;
	arm_smmu_cmdq_issue_cmd_with_sync(smmu, &cmd);

	/* Invalidate any stale TLB entries */
	if (smmu->features & ARM_SMMU_FEAT_HYP) {
		cmd.opcode = CMDQ_OP_TLBI_EL2_ALL;
		arm_smmu_cmdq_issue_cmd_with_sync(smmu, &cmd);
	}

	cmd.opcode = CMDQ_OP_TLBI_NSNH_ALL;
	arm_smmu_cmdq_issue_cmd_with_sync(smmu, &cmd);

	/* Event queue */
	writeq_relaxed(smmu->evtq.q.q_base, smmu->base + ARM_SMMU_EVTQ_BASE);
	writel_relaxed(smmu->evtq.q.llq.prod, smmu->page1 + ARM_SMMU_EVTQ_PROD);
	writel_relaxed(smmu->evtq.q.llq.cons, smmu->page1 + ARM_SMMU_EVTQ_CONS);

	enables |= CR0_EVTQEN;
	ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
				      ARM_SMMU_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable event queue\n");
		return ret;
	}

	/* PRI queue */
	if (smmu->features & ARM_SMMU_FEAT_PRI) {
		writeq_relaxed(smmu->priq.q.q_base,
			       smmu->base + ARM_SMMU_PRIQ_BASE);
		writel_relaxed(smmu->priq.q.llq.prod,
			       smmu->page1 + ARM_SMMU_PRIQ_PROD);
		writel_relaxed(smmu->priq.q.llq.cons,
			       smmu->page1 + ARM_SMMU_PRIQ_CONS);

		enables |= CR0_PRIQEN;
		ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
					      ARM_SMMU_CR0ACK);
		if (ret) {
			dev_err(smmu->dev, "failed to enable PRI queue\n");
			return ret;
		}
	}

	if (smmu->features & ARM_SMMU_FEAT_ATS) {
		enables |= CR0_ATSCHK;
		ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
					      ARM_SMMU_CR0ACK);
		if (ret) {
			dev_err(smmu->dev, "failed to enable ATS check\n");
			return ret;
		}
	}

	ret = arm_smmu_setup_irqs(smmu, resume);
	if (ret) {
		dev_err(smmu->dev, "failed to setup irqs\n");
		return ret;
	}

	if (is_kdump_kernel())
		enables &= ~(CR0_EVTQEN | CR0_PRIQEN);

	/* Enable the SMMU interface, or ensure bypass */
	if (!smmu->bypass || disable_bypass) {
		enables |= CR0_SMMUEN;
	} else {
		ret = arm_smmu_update_gbpa(smmu, 0, GBPA_ABORT);
		if (ret)
			return ret;
	}
	ret = arm_smmu_write_reg_sync(smmu, enables, ARM_SMMU_CR0,
				      ARM_SMMU_CR0ACK);
	if (ret) {
		dev_err(smmu->dev, "failed to enable SMMU interface\n");
		return ret;
	}

	return 0;
}

static int arm_smmu_ecmdq_layout(struct arm_smmu_device *smmu)
{
	int cpu, host_cpu;
	struct arm_smmu_ecmdq *ecmdq;

	ecmdq = devm_alloc_percpu(smmu->dev, *ecmdq);
	if (!ecmdq)
		return -ENOMEM;
	smmu->ecmdq = ecmdq;

	/* A core requires at most one ECMDQ */
	if (num_possible_cpus() < smmu->nr_ecmdq)
		smmu->nr_ecmdq = num_possible_cpus();

	for_each_possible_cpu(cpu) {
		if (cpu < smmu->nr_ecmdq) {
			*per_cpu_ptr(smmu->ecmdqs, cpu) = per_cpu_ptr(smmu->ecmdq, cpu);
		} else {
			host_cpu = cpu % smmu->nr_ecmdq;
			ecmdq = per_cpu_ptr(smmu->ecmdq, host_cpu);
			ecmdq->cmdq.shared = 1;
			*per_cpu_ptr(smmu->ecmdqs, cpu) = ecmdq;
		}
	}

	return 0;
}

static int arm_smmu_ecmdq_probe(struct arm_smmu_device *smmu)
{
	int ret, cpu;
	u32 i, nump, numq, gap;
	u32 reg, shift_increment;
	u64 addr, smmu_dma_base, val, pre_addr;
	void __iomem *cp_regs, *cp_base;

	/* IDR6 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR6);
	nump = 1 << FIELD_GET(IDR6_LOG2NUMP, reg);
	numq = 1 << FIELD_GET(IDR6_LOG2NUMQ, reg);
	smmu->nr_ecmdq = nump * numq;
	gap = ECMDQ_CP_RRESET_SIZE >> FIELD_GET(IDR6_LOG2NUMQ, reg);
	if (!smmu->nr_ecmdq)
		return -EOPNOTSUPP;

	smmu_dma_base = (vmalloc_to_pfn(smmu->base) << PAGE_SHIFT);
	cp_regs = ioremap(smmu_dma_base + ARM_SMMU_ECMDQ_CP_BASE, PAGE_SIZE);
	if (!cp_regs)
		return -ENOMEM;

	for (i = 0; i < nump; i++) {
		val = readq_relaxed(cp_regs + 32 * i);
		if (!(val & ECMDQ_CP_PRESET)) {
			iounmap(cp_regs);
			dev_err(smmu->dev, "ecmdq control page %u is memory mode\n", i);
			return -EFAULT;
		}

		if (i && ((val & ECMDQ_CP_ADDR) != (pre_addr + ECMDQ_CP_RRESET_SIZE))) {
			iounmap(cp_regs);
			dev_err(smmu->dev, "ecmdq_cp memory region is not contiguous\n");
			return -EFAULT;
		}

		pre_addr = val & ECMDQ_CP_ADDR;
	}

	addr = readl_relaxed(cp_regs) & ECMDQ_CP_ADDR;
	iounmap(cp_regs);

	cp_base = devm_ioremap(smmu->dev, smmu_dma_base + addr, ECMDQ_CP_RRESET_SIZE * nump);
	if (!cp_base)
		return -ENOMEM;

	smmu->ecmdqs = devm_alloc_percpu(smmu->dev, struct arm_smmu_ecmdq *);
	if (!smmu->ecmdqs)
		return -ENOMEM;

	ret = arm_smmu_ecmdq_layout(smmu);
	if (ret)
		return ret;

	shift_increment = order_base_2(num_possible_cpus() / smmu->nr_ecmdq);

	addr = 0;
	for_each_possible_cpu(cpu) {
		struct arm_smmu_ecmdq *ecmdq;
		struct arm_smmu_queue *q;

		ecmdq = *per_cpu_ptr(smmu->ecmdqs, cpu);

		/*
		 * The boot option "maxcpus=" can limit the number of online
		 * CPUs. The CPUs that are not selected are not showed in
		 * cpumask_of_node(node), their 'ecmdq' may be NULL.
		 *
		 * (ecmdq != per_cpu_ptr(smmu->ecmdq, cpu)) indicates that the
		 * ECMDQ is shared by multiple cores and should be initialized
		 * only by the first owner.
		 */
		if (!ecmdq || (ecmdq != per_cpu_ptr(smmu->ecmdq, cpu)))
			continue;

		q = &ecmdq->cmdq.q;
		ecmdq->base = cp_base + addr;

		q->llq.max_n_shift = ECMDQ_MAX_SZ_SHIFT + shift_increment;
		ret = arm_smmu_init_one_queue(smmu, q, ecmdq->base, ARM_SMMU_ECMDQ_PROD,
				ARM_SMMU_ECMDQ_CONS, CMDQ_ENT_DWORDS, "ecmdq");
		if (ret)
			return ret;

		q->ecmdq_prod = ECMDQ_PROD_EN;
		rwlock_init(&q->ecmdq_lock);

		ret = arm_smmu_ecmdq_init(&ecmdq->cmdq);
		if (ret) {
			dev_err(smmu->dev, "ecmdq[%d] init failed\n", i);
			return ret;
		}

		addr += gap;
	}

	return 0;
}

static void arm_smmu_get_httu(struct arm_smmu_device *smmu, u32 reg)
{
	u32 fw_features = smmu->features & (ARM_SMMU_FEAT_HA | ARM_SMMU_FEAT_HD);
	u32 features = 0;

	switch (FIELD_GET(IDR0_HTTU, reg)) {
	case IDR0_HTTU_ACCESS_DIRTY:
		features |= ARM_SMMU_FEAT_HD;
		fallthrough;
	case IDR0_HTTU_ACCESS:
		features |= ARM_SMMU_FEAT_HA;
	}

	if (smmu->dev->of_node)
		smmu->features |= features;
	else if (features != fw_features)
		/* ACPI IORT sets the HTTU bits */
		dev_warn(smmu->dev,
			 "IDR0.HTTU overridden by FW configuration (0x%x)\n",
			 fw_features);
}

#ifdef CONFIG_HISILICON_ERRATUM_162100602
static void hisi_smmu_check_errata(struct arm_smmu_device *smmu)
{
	u32 reg, i;

	if (!(smmu->options & ARM_SMMU_OPT_SYNC_MAP))
		return;

	reg = readl_relaxed(smmu->base + ARM_SMMU_USER_CFG1);
	reg = reg & GENMASK(15, 0);
	for (i = 0; i < 8; i++) {
		unsigned long val;

		val = (reg >> 2 * i) & GENMASK(1, 0);
		switch (PAGE_SIZE) {
		case SZ_4K:
			if (!val)
				return;
			break;
		case SZ_16K:
			if (!val || val == 0x1)
				return;
			break;
		case SZ_64K:
			if (!val || val == 0x1 || val == 0x3)
				return;
			break;
		default:
			return;
		}
	}
	smmu->options |= ARM_SMMU_OPT_SYNC_BATCH;
}
#else
static void hisi_smmu_check_errata(struct arm_smmu_device *smmu) {}
#endif

static int arm_smmu_device_hw_probe(struct arm_smmu_device *smmu)
{
	u32 reg;
	bool coherent = smmu->features & ARM_SMMU_FEAT_COHERENCY;
	bool vhe = cpus_have_cap(ARM64_HAS_VIRT_HOST_EXTN);

	/* IDR0 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR0);

	/* 2-level structures */
	if (FIELD_GET(IDR0_ST_LVL, reg) == IDR0_ST_LVL_2LVL)
		smmu->features |= ARM_SMMU_FEAT_2_LVL_STRTAB;

	if (reg & IDR0_CD2L)
		smmu->features |= ARM_SMMU_FEAT_2_LVL_CDTAB;

	/*
	 * Translation table endianness.
	 * We currently require the same endianness as the CPU, but this
	 * could be changed later by adding a new IO_PGTABLE_QUIRK.
	 */
	switch (FIELD_GET(IDR0_TTENDIAN, reg)) {
	case IDR0_TTENDIAN_MIXED:
		smmu->features |= ARM_SMMU_FEAT_TT_LE | ARM_SMMU_FEAT_TT_BE;
		break;
#ifdef __BIG_ENDIAN
	case IDR0_TTENDIAN_BE:
		smmu->features |= ARM_SMMU_FEAT_TT_BE;
		break;
#else
	case IDR0_TTENDIAN_LE:
		smmu->features |= ARM_SMMU_FEAT_TT_LE;
		break;
#endif
	default:
		dev_err(smmu->dev, "unknown/unsupported TT endianness!\n");
		return -ENXIO;
	}

	/* Boolean feature flags */
	if (IS_ENABLED(CONFIG_PCI_PRI) && reg & IDR0_PRI)
		smmu->features |= ARM_SMMU_FEAT_PRI;

	if (IS_ENABLED(CONFIG_PCI_ATS) && reg & IDR0_ATS)
		smmu->features |= ARM_SMMU_FEAT_ATS;

	if (reg & IDR0_SEV)
		smmu->features |= ARM_SMMU_FEAT_SEV;

	if (reg & IDR0_MSI) {
		smmu->features |= ARM_SMMU_FEAT_MSI;
		if (coherent && !disable_msipolling)
			smmu->options |= ARM_SMMU_OPT_MSIPOLL;
	}

	if (reg & IDR0_HYP) {
		smmu->features |= ARM_SMMU_FEAT_HYP;
		if (vhe)
			smmu->features |= ARM_SMMU_FEAT_E2H;
	}

	arm_smmu_get_httu(smmu, reg);

	/*
	 * If the CPU is using VHE, but the SMMU doesn't support it, the SMMU
	 * will create TLB entries for NH-EL1 world and will miss the
	 * broadcasted TLB invalidations that target EL2-E2H world. Don't enable
	 * BTM in that case.
	 */
	if (reg & IDR0_BTM && (!vhe || reg & IDR0_HYP))
		smmu->features |= ARM_SMMU_FEAT_BTM;

	/*
	 * The coherency feature as set by FW is used in preference to the ID
	 * register, but warn on mismatch.
	 */
	if (!!(reg & IDR0_COHACC) != coherent)
		dev_warn(smmu->dev, "IDR0.COHACC overridden by FW configuration (%s)\n",
			 coherent ? "true" : "false");

	switch (FIELD_GET(IDR0_STALL_MODEL, reg)) {
	case IDR0_STALL_MODEL_FORCE:
		smmu->features |= ARM_SMMU_FEAT_STALL_FORCE;
		fallthrough;
	case IDR0_STALL_MODEL_STALL:
		smmu->features |= ARM_SMMU_FEAT_STALLS;
	}

	if (reg & IDR0_S1P)
		smmu->features |= ARM_SMMU_FEAT_TRANS_S1;

	if (reg & IDR0_S2P)
		smmu->features |= ARM_SMMU_FEAT_TRANS_S2;

	if (!(reg & (IDR0_S1P | IDR0_S2P))) {
		dev_err(smmu->dev, "no translation support!\n");
		return -ENXIO;
	}

	/* We only support the AArch64 table format at present */
	switch (FIELD_GET(IDR0_TTF, reg)) {
	case IDR0_TTF_AARCH32_64:
		smmu->ias = 40;
		fallthrough;
	case IDR0_TTF_AARCH64:
		break;
	default:
		dev_err(smmu->dev, "AArch64 table format not supported!\n");
		return -ENXIO;
	}

	/* ASID/VMID sizes */
	smmu->asid_bits = reg & IDR0_ASID16 ? 16 : 8;
	smmu->vmid_bits = reg & IDR0_VMID16 ? 16 : 8;

	/* IDR1 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR1);
	if (reg & (IDR1_TABLES_PRESET | IDR1_QUEUES_PRESET | IDR1_REL)) {
		dev_err(smmu->dev, "embedded implementation not supported\n");
		return -ENXIO;
	}

	if (reg & IDR1_ECMDQ)
		smmu->features |= ARM_SMMU_FEAT_ECMDQ;

	/* Queue sizes, capped to ensure natural alignment */
	smmu->cmdq.q.llq.max_n_shift = min_t(u32, CMDQ_MAX_SZ_SHIFT,
					     FIELD_GET(IDR1_CMDQS, reg));
	if (smmu->cmdq.q.llq.max_n_shift <= ilog2(CMDQ_BATCH_ENTRIES)) {
		/*
		 * We don't support splitting up batches, so one batch of
		 * commands plus an extra sync needs to fit inside the command
		 * queue. There's also no way we can handle the weird alignment
		 * restrictions on the base pointer for a unit-length queue.
		 */
		dev_err(smmu->dev, "command queue size <= %d entries not supported\n",
			CMDQ_BATCH_ENTRIES);
		return -ENXIO;
	}

	smmu->evtq.q.llq.max_n_shift = min_t(u32, EVTQ_MAX_SZ_SHIFT,
					     FIELD_GET(IDR1_EVTQS, reg));
	smmu->priq.q.llq.max_n_shift = min_t(u32, PRIQ_MAX_SZ_SHIFT,
					     FIELD_GET(IDR1_PRIQS, reg));

	/* SID/SSID sizes */
	smmu->ssid_bits = FIELD_GET(IDR1_SSIDSIZE, reg);
	smmu->sid_bits = FIELD_GET(IDR1_SIDSIZE, reg);

	/*
	 * If the SMMU supports fewer bits than would fill a single L2 stream
	 * table, use a linear table instead.
	 */
	if (smmu->sid_bits <= STRTAB_SPLIT)
		smmu->features &= ~ARM_SMMU_FEAT_2_LVL_STRTAB;

	/* IDR3 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR3);
	switch (FIELD_GET(IDR3_BBML, reg)) {
	case IDR3_BBML0:
		break;
	case IDR3_BBML1:
		smmu->features |= ARM_SMMU_FEAT_BBML1;
		break;
	case IDR3_BBML2:
		smmu->features |= ARM_SMMU_FEAT_BBML2;
		break;
	default:
		dev_err(smmu->dev, "unknown/unsupported BBM behavior level\n");
		return -ENXIO;
	}

	if (FIELD_GET(IDR3_RIL, reg))
		smmu->features |= ARM_SMMU_FEAT_RANGE_INV;

	if (reg & IDR3_MPAM) {
		reg = readl_relaxed(smmu->base + ARM_SMMU_MPAMIDR);
		smmu->mpam_partid_max = FIELD_GET(MPAMIDR_PARTID_MAX, reg);
		smmu->mpam_pmg_max = FIELD_GET(MPAMIDR_PMG_MAX, reg);
		if (smmu->mpam_partid_max || smmu->mpam_pmg_max)
			smmu->features |= ARM_SMMU_FEAT_MPAM;
	}

	/* IDR5 */
	reg = readl_relaxed(smmu->base + ARM_SMMU_IDR5);

	/* Maximum number of outstanding stalls */
	smmu->evtq.max_stalls = FIELD_GET(IDR5_STALL_MAX, reg);

	/* Page sizes */
	if (reg & IDR5_GRAN64K)
		smmu->pgsize_bitmap |= SZ_64K | SZ_512M;
	if (reg & IDR5_GRAN16K)
		smmu->pgsize_bitmap |= SZ_16K | SZ_32M;
	if (reg & IDR5_GRAN4K)
		smmu->pgsize_bitmap |= SZ_4K | SZ_2M | SZ_1G;

	/* Input address size */
	if (FIELD_GET(IDR5_VAX, reg) == IDR5_VAX_52_BIT)
		smmu->features |= ARM_SMMU_FEAT_VAX;

	/* Output address size */
	switch (FIELD_GET(IDR5_OAS, reg)) {
	case IDR5_OAS_32_BIT:
		smmu->oas = 32;
		break;
	case IDR5_OAS_36_BIT:
		smmu->oas = 36;
		break;
	case IDR5_OAS_40_BIT:
		smmu->oas = 40;
		break;
	case IDR5_OAS_42_BIT:
		smmu->oas = 42;
		break;
	case IDR5_OAS_44_BIT:
		smmu->oas = 44;
		break;
	case IDR5_OAS_52_BIT:
		smmu->oas = 52;
		smmu->pgsize_bitmap |= 1ULL << 42; /* 4TB */
		break;
	default:
		dev_info(smmu->dev,
			"unknown output address size. Truncating to 48-bit\n");
		fallthrough;
	case IDR5_OAS_48_BIT:
		smmu->oas = 48;
	}

	hisi_smmu_check_errata(smmu);

	if (arm_smmu_ops.pgsize_bitmap == -1UL)
		arm_smmu_ops.pgsize_bitmap = smmu->pgsize_bitmap;
	else
		arm_smmu_ops.pgsize_bitmap |= smmu->pgsize_bitmap;

	/* Set the DMA mask for our table walker */
	if (dma_set_mask_and_coherent(smmu->dev, DMA_BIT_MASK(smmu->oas)))
		dev_warn(smmu->dev,
			 "failed to set DMA mask for table walker\n");

	smmu->ias = max(smmu->ias, smmu->oas);

	if (arm_smmu_sva_supported(smmu))
		smmu->features |= ARM_SMMU_FEAT_SVA;

	dev_info(smmu->dev, "ias %lu-bit, oas %lu-bit (features 0x%08x)\n",
		 smmu->ias, smmu->oas, smmu->features);

	if (smmu->features & ARM_SMMU_FEAT_ECMDQ && !disable_ecmdq) {
		int err;

		err = arm_smmu_ecmdq_probe(smmu);
		if (err) {
			dev_err(smmu->dev, "suppress ecmdq feature, errno=%d\n", err);
			smmu->ecmdq_enabled = 0;
		}
	}
	return 0;
}

#ifdef CONFIG_ACPI
static struct acpi_platform_list arm_smmu_v3_plat_info[] = {
	/* HiSilicon Hip09 Platform */
	{"HISI  ", "HIP09   ", 0, ACPI_SIG_IORT, greater_than_or_equal,
	 "Erratum #162100602", 0},
	{"HISI  ", "HIP10   ", 0, ACPI_SIG_IORT, greater_than_or_equal,
	 "Erratum #162100602", 0},
	{"HISI  ", "HIP11   ", 0, ACPI_SIG_IORT, greater_than_or_equal,
	 "Erratum #162100602", 0},
	{ }
};

static void acpi_get_hisi_options(struct arm_smmu_device *smmu)
{
	if (acpi_match_platform_list(arm_smmu_v3_plat_info) < 0)
		return;

	smmu->options |= ARM_SMMU_OPT_SYNC_MAP;
}

static void acpi_smmu_get_options(u32 model, struct arm_smmu_device *smmu)
{
	switch (model) {
	case ACPI_IORT_SMMU_V3_CAVIUM_CN99XX:
		smmu->options |= ARM_SMMU_OPT_PAGE0_REGS_ONLY;
		break;
	case ACPI_IORT_SMMU_V3_HISILICON_HI161X:
		smmu->options |= ARM_SMMU_OPT_SKIP_PREFETCH;
		break;
	}

	acpi_get_hisi_options(smmu);

	dev_notice(smmu->dev, "option mask 0x%x\n", smmu->options);
}

static int arm_smmu_device_acpi_probe(struct platform_device *pdev,
				      struct arm_smmu_device *smmu)
{
	struct acpi_iort_smmu_v3 *iort_smmu;
	struct device *dev = smmu->dev;
	struct acpi_iort_node *node;

	node = *(struct acpi_iort_node **)dev_get_platdata(dev);

	/* Retrieve SMMUv3 specific data */
	iort_smmu = (struct acpi_iort_smmu_v3 *)node->node_data;

	acpi_smmu_get_options(iort_smmu->model, smmu);

	if (iort_smmu->flags & ACPI_IORT_SMMU_V3_COHACC_OVERRIDE)
		smmu->features |= ARM_SMMU_FEAT_COHERENCY;

	switch (FIELD_GET(ACPI_IORT_SMMU_V3_HTTU_OVERRIDE, iort_smmu->flags)) {
	case IDR0_HTTU_ACCESS_DIRTY:
		smmu->features |= ARM_SMMU_FEAT_HD;
		fallthrough;
	case IDR0_HTTU_ACCESS:
		smmu->features |= ARM_SMMU_FEAT_HA;
	}

	return 0;
}
#else
static inline int arm_smmu_device_acpi_probe(struct platform_device *pdev,
					     struct arm_smmu_device *smmu)
{
	return -ENODEV;
}
#endif

static int arm_smmu_device_dt_probe(struct platform_device *pdev,
				    struct arm_smmu_device *smmu)
{
	struct device *dev = &pdev->dev;
	u32 cells;
	int ret = -EINVAL;

	if (of_property_read_u32(dev->of_node, "#iommu-cells", &cells))
		dev_err(dev, "missing #iommu-cells property\n");
	else if (cells != 1)
		dev_err(dev, "invalid #iommu-cells value (%d)\n", cells);
	else
		ret = 0;

	parse_driver_options(smmu);

	if (of_dma_is_coherent(dev->of_node))
		smmu->features |= ARM_SMMU_FEAT_COHERENCY;

	return ret;
}

static unsigned long arm_smmu_resource_size(struct arm_smmu_device *smmu)
{
	if (smmu->options & ARM_SMMU_OPT_PAGE0_REGS_ONLY)
		return SZ_64K;
	else
		return SZ_128K;
}

static int arm_smmu_set_bus_ops(struct iommu_ops *ops)
{
	int err;

#ifdef CONFIG_PCI
	if (pci_bus_type.iommu_ops != ops) {
		err = bus_set_iommu(&pci_bus_type, ops);
		if (err)
			return err;
	}
#endif
#ifdef CONFIG_ARM_AMBA
	if (amba_bustype.iommu_ops != ops) {
		err = bus_set_iommu(&amba_bustype, ops);
		if (err)
			goto err_reset_pci_ops;
	}
#endif
	if (platform_bus_type.iommu_ops != ops) {
		err = bus_set_iommu(&platform_bus_type, ops);
		if (err)
			goto err_reset_amba_ops;
	}

	return 0;

err_reset_amba_ops:
#ifdef CONFIG_ARM_AMBA
	bus_set_iommu(&amba_bustype, NULL);
#endif
err_reset_pci_ops: __maybe_unused;
#ifdef CONFIG_PCI
	bus_set_iommu(&pci_bus_type, NULL);
#endif
	return err;
}

static void __iomem *arm_smmu_ioremap(struct device *dev, resource_size_t start,
				      resource_size_t size)
{
	struct resource res = DEFINE_RES_MEM(start, size);

	return devm_ioremap_resource(dev, &res);
}

#ifdef CONFIG_ARM_SMMU_V3_PM
static int arm_smmu_ecmdq_disable(struct device *dev)
{
	int i, j;
	int ret, nr_fail = 0, n = 100;
	u32 reg, prod, cons;
	struct arm_smmu_ecmdq *ecmdq;
	struct arm_smmu_queue *q;
	struct arm_smmu_device *smmu = dev_get_drvdata(dev);

	for (i = 0; i < smmu->nr_ecmdq; i++) {
		ecmdq = *per_cpu_ptr(smmu->ecmdqs, i);
		q = &ecmdq->cmdq.q;

		prod = readl_relaxed(q->prod_reg);
		cons = readl_relaxed(q->cons_reg);
		if ((prod & ECMDQ_PROD_EN) == 0)
			continue;

		for (j = 0; j < n; j++) {
			if (Q_IDX(&q->llq, prod) == Q_IDX(&q->llq, cons) &&
			    Q_WRP(&q->llq, prod) == Q_WRP(&q->llq, cons))
				break;

			/* Wait a moment, so ECMDQ has a chance to finish */
			udelay(1);
			cons = readl_relaxed(q->cons_reg);
		}
		WARN_ON(prod != readl_relaxed(q->prod_reg));
		if (j >= n)
			dev_warn(smmu->dev,
				 "Forcibly disabling ecmdq[%d]: prod=%08x, cons=%08x\n",
				 i, prod, cons);

		/* disable ecmdq */
		prod &= ~ECMDQ_PROD_EN;
		writel(prod, q->prod_reg);
		ret = readl_relaxed_poll_timeout(q->cons_reg, reg, !(reg & ECMDQ_CONS_ENACK),
					  1, ARM_SMMU_POLL_TIMEOUT_US);
		if (ret) {
			nr_fail++;
			dev_err(smmu->dev, "ecmdq[%d] disable failed\n", i);
		}
	}

	if (nr_fail) {
		smmu->ecmdq_enabled = 0;
		pr_warn("Suppress ecmdq feature, switch to normal cmdq\n");
		return -EIO;
	}

	return 0;
}

static int arm_smmu_suspend(struct device *dev)
{
	arm_smmu_ecmdq_disable(dev);

	/*
	 * The smmu is powered off and related registers are automatically
	 * cleared when suspend. No need to do anything.
	 */
	return 0;
}

static int arm_smmu_resume(struct device *dev)
{
	struct arm_smmu_device *smmu = dev_get_drvdata(dev);

	arm_smmu_device_reset(smmu, true);

	return 0;
}
#endif

static int arm_smmu_device_probe(struct platform_device *pdev)
{
	int irq, ret;
	struct resource *res;
	resource_size_t ioaddr;
	struct arm_smmu_device *smmu;
	struct device *dev = &pdev->dev;

	smmu = devm_kzalloc(dev, sizeof(*smmu), GFP_KERNEL);
	if (!smmu) {
		dev_err(dev, "failed to allocate arm_smmu_device\n");
		return -ENOMEM;
	}
	smmu->dev = dev;

	if (dev->of_node) {
		ret = arm_smmu_device_dt_probe(pdev, smmu);
	} else {
		ret = arm_smmu_device_acpi_probe(pdev, smmu);
		if (ret == -ENODEV)
			return ret;
	}

	/* Set bypass mode according to firmware probing result */
	smmu->bypass = !!ret;

	/* Base address */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -EINVAL;
	if (resource_size(res) < arm_smmu_resource_size(smmu)) {
		dev_err(dev, "MMIO region too small (%pr)\n", res);
		return -EINVAL;
	}
	ioaddr = res->start;

	/*
	 * Don't map the IMPLEMENTATION DEFINED regions, since they may contain
	 * the PMCG registers which are reserved by the PMU driver.
	 */
	smmu->base = arm_smmu_ioremap(dev, ioaddr, ARM_SMMU_REG_SZ);
	if (IS_ERR(smmu->base))
		return PTR_ERR(smmu->base);

	if (arm_smmu_resource_size(smmu) > SZ_64K) {
		smmu->page1 = arm_smmu_ioremap(dev, ioaddr + SZ_64K,
					       ARM_SMMU_REG_SZ);
		if (IS_ERR(smmu->page1))
			return PTR_ERR(smmu->page1);
	} else {
		smmu->page1 = smmu->base;
	}

	/* Interrupt lines */

	irq = platform_get_irq_byname_optional(pdev, "combined");
	if (irq > 0)
		smmu->combined_irq = irq;
	else {
		irq = platform_get_irq_byname_optional(pdev, "eventq");
		if (irq > 0)
			smmu->evtq.q.irq = irq;

		irq = platform_get_irq_byname_optional(pdev, "priq");
		if (irq > 0)
			smmu->priq.q.irq = irq;

		irq = platform_get_irq_byname_optional(pdev, "gerror");
		if (irq > 0)
			smmu->gerr_irq = irq;
	}
	/* Probe the h/w */
	ret = arm_smmu_device_hw_probe(smmu);
	if (ret)
		return ret;

	/* Initialise in-memory data structures */
	ret = arm_smmu_init_structures(smmu);
	if (ret)
		return ret;

	/* Record our private device structure */
	platform_set_drvdata(pdev, smmu);

	/* Reset the device */
	ret = arm_smmu_device_reset(smmu, false);
	if (ret)
		return ret;

	/* And we're up. Go go go! */
	ret = iommu_device_sysfs_add(&smmu->iommu, dev, NULL,
				     "smmu3.%pa", &ioaddr);
	if (ret)
		return ret;

	iommu_device_set_ops(&smmu->iommu, &arm_smmu_ops);
	iommu_device_set_fwnode(&smmu->iommu, dev->fwnode);

	ret = iommu_device_register(&smmu->iommu);
	if (ret) {
		dev_err(dev, "Failed to register iommu\n");
		return ret;
	}

	return arm_smmu_set_bus_ops(&arm_smmu_ops);
}

static int arm_smmu_device_remove(struct platform_device *pdev)
{
	struct arm_smmu_device *smmu = platform_get_drvdata(pdev);

	arm_smmu_set_bus_ops(NULL);
	iommu_device_unregister(&smmu->iommu);
	iommu_device_sysfs_remove(&smmu->iommu);
	arm_smmu_device_disable(smmu);
	iopf_queue_free(smmu->evtq.iopf);
	iopf_queue_free(smmu->priq.iopf);

	return 0;
}

static void arm_smmu_device_shutdown(struct platform_device *pdev)
{
	arm_smmu_device_remove(pdev);
}

static const struct of_device_id arm_smmu_of_match[] = {
	{ .compatible = "arm,smmu-v3", },
	{ },
};
MODULE_DEVICE_TABLE(of, arm_smmu_of_match);

#ifdef CONFIG_ARM_SMMU_V3_PM
static const struct dev_pm_ops arm_smmu_pm_ops = {
	.suspend = arm_smmu_suspend,
	.resume = arm_smmu_resume,
};
#define ARM_SMMU_PM_OPS		(&arm_smmu_pm_ops)
#else
#define ARM_SMMU_PM_OPS		NULL
#endif

static void arm_smmu_driver_unregister(struct platform_driver *drv)
{
	arm_smmu_sva_notifier_synchronize();
	platform_driver_unregister(drv);
}

static struct platform_driver arm_smmu_driver = {
	.driver	= {
		.name			= "arm-smmu-v3",
		.of_match_table		= arm_smmu_of_match,
		.suppress_bind_attrs	= true,
		.pm			= ARM_SMMU_PM_OPS,
	},
	.probe	= arm_smmu_device_probe,
	.remove	= arm_smmu_device_remove,
	.shutdown = arm_smmu_device_shutdown,
};
module_driver(arm_smmu_driver, platform_driver_register,
	      arm_smmu_driver_unregister);

MODULE_DESCRIPTION("IOMMU API for ARM architected SMMUv3 implementations");
MODULE_AUTHOR("Will Deacon <will@kernel.org>");
MODULE_ALIAS("platform:arm-smmu-v3");
MODULE_LICENSE("GPL v2");
