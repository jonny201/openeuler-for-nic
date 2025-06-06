// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <asm/kvm_tmi.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/stage2_pgtable.h>
#include <linux/arm-smccc.h>
#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

/* Protects access to cvm_vmid_bitmap */
static DEFINE_SPINLOCK(cvm_vmid_lock);
static unsigned long *cvm_vmid_bitmap;
DEFINE_STATIC_KEY_FALSE(kvm_cvm_is_available);
DEFINE_STATIC_KEY_FALSE(kvm_cvm_is_enable);
#define SIMD_PAGE_SIZE 0x3000

static int __init setup_cvm_host(char *str)
{
	int ret;
	unsigned int val;

	if (!str)
		return 0;

	ret = kstrtouint(str, 10, &val);
	if (ret) {
		pr_warn("Unable to parse cvm_guest.\n");
	} else {
		if (val)
			static_branch_enable(&kvm_cvm_is_enable);
	}
	return ret;
}
early_param("cvm_host", setup_cvm_host);

static int cvm_vmid_init(void)
{
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	cvm_vmid_bitmap = bitmap_zalloc(vmid_count, GFP_KERNEL);
	if (!cvm_vmid_bitmap) {
		kvm_err("%s: Couldn't allocate cvm vmid bitmap\n", __func__);
		return -ENOMEM;
	}
	return 0;
}

static unsigned long tmm_feat_reg0;

static bool tmm_supports(unsigned long feature)
{
	return !!u64_get_bits(tmm_feat_reg0, feature);
}

bool kvm_cvm_supports_sve(void)
{
	return tmm_supports(TMI_FEATURE_REGISTER_0_SVE_EN);
}

bool kvm_cvm_supports_pmu(void)
{
	return tmm_supports(TMI_FEATURE_REGISTER_0_PMU_EN);
}

u32 kvm_cvm_ipa_limit(void)
{
	return u64_get_bits(tmm_feat_reg0, TMI_FEATURE_REGISTER_0_S2SZ);
}

u32 kvm_cvm_get_num_brps(void)
{
	return u64_get_bits(tmm_feat_reg0, TMI_FEATURE_REGISTER_0_NUM_BPS);
}

u32 kvm_cvm_get_num_wrps(void)
{
	return u64_get_bits(tmm_feat_reg0, TMI_FEATURE_REGISTER_0_NUM_WPS);
}

static int cvm_vmid_reserve(void)
{
	int ret;
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	spin_lock(&cvm_vmid_lock);
	ret = bitmap_find_free_region(cvm_vmid_bitmap, vmid_count, 0);
	spin_unlock(&cvm_vmid_lock);

	return ret;
}

static void cvm_vmid_release(unsigned int vmid)
{
	spin_lock(&cvm_vmid_lock);
	bitmap_release_region(cvm_vmid_bitmap, vmid, 0);
	spin_unlock(&cvm_vmid_lock);
}

static u32 __kvm_pgd_page_idx(struct kvm_pgtable *pgt, u64 addr)
{
	u64 shift = ARM64_HW_PGTABLE_LEVEL_SHIFT(pgt->start_level - 1);
	u64 mask = BIT(pgt->ia_bits) - 1;

	return (addr & mask) >> shift;
}

static u32 kvm_pgd_pages(u32 ia_bits, u32 start_level)
{
	struct kvm_pgtable pgt = {
		.ia_bits		= ia_bits,
		.start_level	= start_level,
	};
	return __kvm_pgd_page_idx(&pgt, -1ULL) + 1;
}

/*
 * the configurable physical numa range in QEMU is 0-127,
 * but in real scenarios, 0-63 is sufficient.
 */
static u64 kvm_get_host_numa_set_by_vcpu(u64 vcpu, struct kvm *kvm)
{
	int64_t i;
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct kvm_numa_info *numa_info = &cvm->numa_info;

	for (i = 0; i < numa_info->numa_cnt && i < MAX_NUMA_NODE; i++) {
		if (test_bit(vcpu, (unsigned long *)numa_info->numa_nodes[i].cpu_id))
			return numa_info->numa_nodes[i].host_numa_nodes[0];
	}
	return NO_NUMA;
}

static u64 kvm_get_first_binded_numa_set(struct kvm *kvm)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct kvm_numa_info *numa_info = &cvm->numa_info;

	if (numa_info->numa_cnt > 0)
		return numa_info->numa_nodes[0].host_numa_nodes[0];
	return NO_NUMA;
}

int kvm_arm_create_cvm(struct kvm *kvm)
{
	int ret;
	struct kvm_pgtable *pgt = kvm->arch.mmu.pgt;
	unsigned int pgd_sz;
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	/* get affine host numa set by default vcpu 0 */
	u64 numa_set = kvm_get_host_numa_set_by_vcpu(0, kvm);

	if (!kvm_is_cvm(kvm) || kvm_cvm_state(kvm) != CVM_STATE_NONE)
		return 0;

	if (!cvm->params) {
		ret = -EFAULT;
		goto out;
	}

	ret = cvm_vmid_reserve();
	if (ret < 0)
		goto out;

	cvm->cvm_vmid = ret;

	pgd_sz = kvm_pgd_pages(pgt->ia_bits, pgt->start_level);

	cvm->params->ttt_level_start = kvm->arch.mmu.pgt->start_level;
	cvm->params->ttt_num_start = pgd_sz;
	cvm->params->s2sz = VTCR_EL2_IPA(kvm->arch.vtcr);
	cvm->params->vmid = cvm->cvm_vmid;
	cvm->params->ns_vtcr = kvm->arch.vtcr;
	cvm->params->vttbr_el2 = kvm->arch.mmu.pgd_phys;
	memcpy(cvm->params->rpv, &cvm->cvm_vmid, sizeof(cvm->cvm_vmid));
	cvm->rd = tmi_cvm_create(__pa(cvm->params), numa_set);
	if (!cvm->rd) {
		kvm_err("KVM creates cVM failed: %d\n", cvm->cvm_vmid);
		ret = -ENOMEM;
		goto out;
	}

	WRITE_ONCE(cvm->state, CVM_STATE_NEW);
	ret = 0;
out:
	kfree(cvm->params);
	cvm->params = NULL;
	if (ret < 0) {
		kfree(cvm);
		kvm->arch.cvm = NULL;
	}
	return ret;
}

void kvm_destroy_cvm(struct kvm *kvm)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	uint32_t cvm_vmid;

	if (!cvm)
		return;

	cvm_vmid = cvm->cvm_vmid;
	kfree(cvm->params);
	cvm->params = NULL;

	if (kvm_cvm_state(kvm) == CVM_STATE_NONE)
		return;

	cvm_vmid_release(cvm_vmid);

	WRITE_ONCE(cvm->state, CVM_STATE_DYING);

	if (!tmi_cvm_destroy(cvm->rd))
		kvm_info("KVM has destroyed cVM: %d\n", cvm->cvm_vmid);

	kfree(kvm->arch.cvm);
	kvm->arch.cvm = NULL;
}

static int kvm_cvm_ttt_create(struct cvm *cvm,
			unsigned long addr,
			int level,
			u64 numa_set)
{
	addr = ALIGN_DOWN(addr, cvm_ttt_level_mapsize(level - 1));
	return tmi_ttt_create(numa_set, cvm->rd, addr, level);
}

int kvm_cvm_create_ttt_levels(struct kvm *kvm, struct cvm *cvm,
			unsigned long ipa,
			int level,
			int max_level,
			struct kvm_mmu_memory_cache *mc)
{
	int ret = 0;
	if (WARN_ON(level == max_level))
		return 0;

	while (level++ < max_level) {
		u64 numa_set = kvm_get_first_binded_numa_set(kvm);

		ret = kvm_cvm_ttt_create(cvm, ipa, level, numa_set);
		if (ret)
			return -ENXIO;
	}

	return 0;
}

static int kvm_cvm_create_protected_data_page(struct kvm *kvm, struct cvm *cvm,
			unsigned long ipa, int level, struct page *src_page, u64 numa_set)
{
	phys_addr_t src_phys = 0;
	int ret;

	if (src_page)
		src_phys = page_to_phys(src_page);
	ret = tmi_data_create(numa_set, cvm->rd, ipa, src_phys, level);

	if (TMI_RETURN_STATUS(ret) == TMI_ERROR_TTT_WALK) {
		/* Create missing RTTs and retry */
		int level_fault = TMI_RETURN_INDEX(ret);

		ret = kvm_cvm_create_ttt_levels(kvm, cvm, ipa, level_fault,
			level, NULL);
		if (ret)
			goto err;
		ret = tmi_data_create(numa_set, cvm->rd, ipa, src_phys, level);
	}
	if (ret)
		goto err;

	return 0;

err:
	kvm_err("Cvm create protected data page fail:%d\n", ret);
	return ret;
}

static u64 cvm_granule_size(u32 level)
{
	return BIT(ARM64_HW_PGTABLE_LEVEL_SHIFT(level));
}

static bool is_data_create_region(phys_addr_t ipa_base,
			struct kvm_cap_arm_tmm_populate_region_args *args)
{
	if ((ipa_base >= args->populate_ipa_base1 &&
		ipa_base < args->populate_ipa_base1 + args->populate_ipa_size1) ||
		(ipa_base >= args->populate_ipa_base2 &&
		ipa_base < args->populate_ipa_base2 + args->populate_ipa_size2))
		return true;
	return false;
}

int kvm_cvm_populate_par_region(struct kvm *kvm, u64 numa_set,
			phys_addr_t ipa_base, phys_addr_t ipa_end,
			struct kvm_cap_arm_tmm_populate_region_args *args)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct kvm_memory_slot *memslot;
	gfn_t base_gfn, end_gfn;
	int idx;
	phys_addr_t ipa;
	int ret = 0;
	int level = TMM_TTT_LEVEL_3;
	unsigned long map_size = cvm_granule_size(level);

	base_gfn = gpa_to_gfn(ipa_base);
	end_gfn = gpa_to_gfn(ipa_end);

	idx = srcu_read_lock(&kvm->srcu);
	memslot = gfn_to_memslot(kvm, base_gfn);
	if (!memslot) {
		ret = -EFAULT;
		goto out;
	}

	/* We require the region to be contained within a single memslot */
	if (memslot->base_gfn + memslot->npages < end_gfn) {
		ret = -EINVAL;
		goto out;
	}

	mmap_read_lock(current->mm);

	ipa = ipa_base;
	while (ipa < ipa_end) {
		struct page *page = NULL;
		kvm_pfn_t pfn = 0;

		/*
		 * FIXME: This causes over mapping, but there's no good
		 * solution here with the ABI as it stands
		 */
		ipa = ALIGN_DOWN(ipa, map_size);

		if (is_data_create_region(ipa, args)) {
			pfn = gfn_to_pfn_memslot(memslot, gpa_to_gfn(ipa));
			if (is_error_pfn(pfn)) {
				ret = -EFAULT;
				break;
			}

			page = pfn_to_page(pfn);
		}

		ret = kvm_cvm_create_protected_data_page(kvm, cvm, ipa, level, page, numa_set);
		if (ret)
			goto err_release_pfn;

		ipa += map_size;
		if (pfn)
			kvm_release_pfn_dirty(pfn);
err_release_pfn:
		if (ret) {
			if (pfn)
				kvm_release_pfn_clean(pfn);
			break;
		}
	}

	mmap_read_unlock(current->mm);
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static int kvm_create_tec(struct kvm_vcpu *vcpu)
{
	int ret = 0;
	int i;
	u64 numa_set;
	struct tmi_tec_params *params_ptr = NULL;
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	u64 mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	struct cvm *cvm = (struct cvm *)vcpu->kvm->arch.cvm;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	tec->tec_run = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!tec->tec_run) {
		ret = -ENOMEM;
		goto tec_free;
	}
	params_ptr = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!params_ptr) {
		ret = -ENOMEM;
		goto tec_free;
	}

	for (i = 0; i < TEC_CREATE_NR_GPRS; ++i)
		params_ptr->gprs[i] = vcpu_regs->regs[i];

	params_ptr->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params_ptr->flags = TMI_RUNNABLE;
	else
		params_ptr->flags = TMI_NOT_RUNNABLE;
	params_ptr->ram_size = cvm->ram_size;
	numa_set = kvm_get_host_numa_set_by_vcpu(vcpu->vcpu_id, vcpu->kvm);
	tec->tec = tmi_tec_create(numa_set, cvm->rd, mpidr, __pa(params_ptr));

	tec->tec_created = true;
	kfree(params_ptr);
	return ret;

tec_free:
	kfree(tec->tec_run);
	kfree(tec);
	kfree(params_ptr);
	vcpu->arch.tec = NULL;
	return ret;
}

int kvm_finalize_vcpu_tec(struct kvm_vcpu *vcpu)
{
	int ret = 0;

	mutex_lock(&vcpu->kvm->lock);
	if (!vcpu->arch.tec) {
		vcpu->arch.tec = kzalloc(sizeof(struct cvm_tec), GFP_KERNEL_ACCOUNT);
		if (!vcpu->arch.tec) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = kvm_create_tec(vcpu);

out:
	mutex_unlock(&vcpu->kvm->lock);
	return ret;
}

static int config_cvm_hash_algo(struct tmi_cvm_params *params,
			struct kvm_cap_arm_tmm_config_item *cfg)
{
	switch (cfg->hash_algo) {
	case KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256:
		if (!tmm_supports(TMI_FEATURE_REGISTER_0_HASH_SHA_256))
			return -EINVAL;
		break;
	case KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512:
		if (!tmm_supports(TMI_FEATURE_REGISTER_0_HASH_SHA_512))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	params->measurement_algo = cfg->hash_algo;
	return 0;
}

static int config_cvm_sve(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct tmi_cvm_params *params;
	int max_sve_vq;

	params = cvm->params;
	max_sve_vq = u64_get_bits(tmm_feat_reg0,
		TMI_FEATURE_REGISTER_0_SVE_VL);

	if (!kvm_cvm_supports_sve())
		return -EINVAL;

	if (cfg->sve_vq > max_sve_vq)
		return -EINVAL;

	params->sve_vl = cfg->sve_vq;
	params->flags |= TMI_CVM_PARAM_FLAG_SVE;

	return 0;
}

static int config_cvm_pmu(struct kvm *kvm, struct kvm_cap_arm_tmm_config_item *cfg)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct tmi_cvm_params *params;
	int max_pmu_num_ctrs;

	params = cvm->params;
	max_pmu_num_ctrs = u64_get_bits(tmm_feat_reg0,
			  TMI_FEATURE_REGISTER_0_PMU_NUM_CTRS);

	if (!kvm_cvm_supports_pmu())
		return -EINVAL;

	if (cfg->num_pmu_cntrs > max_pmu_num_ctrs)
		return -EINVAL;

	params->pmu_num_cnts = cfg->num_pmu_cntrs;
	params->flags |= TMI_CVM_PARAM_FLAG_PMU;

	return 0;
}

static int kvm_tmm_config_cvm(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct kvm_cap_arm_tmm_config_item cfg;
	int r = 0;

	if (kvm_cvm_state(kvm) != CVM_STATE_NONE)
		return -EBUSY;

	if (copy_from_user(&cfg, (void __user *)cap->args[1], sizeof(cfg)))
		return -EFAULT;

	switch (cfg.cfg) {
	case KVM_CAP_ARM_TMM_CFG_SVE:
		r = config_cvm_sve(kvm, &cfg);
		break;
	case KVM_CAP_ARM_TMM_CFG_PMU:
		r = config_cvm_pmu(kvm, &cfg);
		break;
	case KVM_CAP_ARM_TMM_CFG_HASH_ALGO:
		r = config_cvm_hash_algo(cvm->params, &cfg);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static int kvm_cvm_map_range(struct kvm *kvm)
{
	int ret;
	u64 curr_numa_set;
	int idx;
	u64 l2_granule = cvm_granule_size(TMM_TTT_LEVEL_2);
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct kvm_numa_info *numa_info = &cvm->numa_info;
	gpa_t gpa;

	curr_numa_set = kvm_get_first_binded_numa_set(kvm);
	gpa = round_up(cvm->dtb_end, l2_granule);
	for (idx = 0; idx < numa_info->numa_cnt; idx++) {
		struct kvm_numa_node *numa_node = &numa_info->numa_nodes[idx];

		if (idx)
			gpa = numa_node->ipa_start;
		if (gpa >= numa_node->ipa_start &&
			gpa < numa_node->ipa_start + numa_node->ipa_size) {
			ret = tmi_ttt_map_range(cvm->rd, gpa,
						numa_node->ipa_size - gpa + numa_node->ipa_start,
						curr_numa_set, numa_node->host_numa_nodes[0]);
			if (ret) {
				kvm_err("tmi_ttt_map_range failed: %d.\n", ret);
				return ret;
			}
		}
	}

	return ret;
}

static int kvm_activate_cvm(struct kvm *kvm)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;

	if (kvm_cvm_state(kvm) != CVM_STATE_NEW)
		return -EINVAL;

	if (kvm_cvm_map_range(kvm))
		return -EFAULT;

	if (tmi_cvm_activate(cvm->rd)) {
		kvm_err("tmi_cvm_activate failed!\n");
		return -ENXIO;
	}

	WRITE_ONCE(cvm->state, CVM_STATE_ACTIVE);
	kvm_info("cVM%d is activated!\n", cvm->cvm_vmid);
	return 0;
}

static int kvm_populate_ram_region(struct kvm *kvm, u64 map_size,
			phys_addr_t ipa_base, phys_addr_t ipa_end,
			struct kvm_cap_arm_tmm_populate_region_args *args)
{
	phys_addr_t gpa;
	u64 numa_set = kvm_get_first_binded_numa_set(kvm);

	for (gpa = ipa_base; gpa < ipa_end; gpa += map_size) {
		if (kvm_cvm_populate_par_region(kvm, numa_set, gpa, gpa + map_size, args)) {
			kvm_err("kvm_cvm_populate_par_region failed: %d\n", -EFAULT);
			return -EFAULT;
		}
	}
	return 0;
}

static int kvm_populate_ipa_cvm_range(struct kvm *kvm,
				struct kvm_cap_arm_tmm_populate_region_args *args)
{
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	u64 l2_granule = cvm_granule_size(TMM_TTT_LEVEL_2);
	phys_addr_t ipa_base1, ipa_end2;

	if (kvm_cvm_state(kvm) != CVM_STATE_NEW)
		return -EINVAL;
	if (!IS_ALIGNED(args->populate_ipa_base1, PAGE_SIZE) ||
		!IS_ALIGNED(args->populate_ipa_size1, PAGE_SIZE) ||
		!IS_ALIGNED(args->populate_ipa_base2, PAGE_SIZE) ||
		!IS_ALIGNED(args->populate_ipa_size2, PAGE_SIZE))
		return -EINVAL;

	if (args->populate_ipa_base1 < cvm->loader_start ||
		args->populate_ipa_base2 < args->populate_ipa_base1 + args->populate_ipa_size1 ||
		cvm->dtb_end < args->populate_ipa_base2 + args->populate_ipa_size2)
		return -EINVAL;

	if (args->flags & ~TMI_MEASURE_CONTENT)
		return -EINVAL;
	ipa_base1 = round_down(args->populate_ipa_base1, l2_granule);
	ipa_end2 = round_up(args->populate_ipa_base2 + args->populate_ipa_size2, l2_granule);

	return kvm_populate_ram_region(kvm, l2_granule, ipa_base1, ipa_end2, args);
}

int kvm_cvm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r = 0;

	mutex_lock(&kvm->lock);
	switch (cap->args[0]) {
	case KVM_CAP_ARM_TMM_CONFIG_CVM_HOST:
		r = kvm_tmm_config_cvm(kvm, cap);
		break;
	case KVM_CAP_ARM_TMM_CREATE_RD:
		r = kvm_arm_create_cvm(kvm);
		break;
	case KVM_CAP_ARM_TMM_POPULATE_CVM: {
		struct kvm_cap_arm_tmm_populate_region_args args;
		void __user *argp = u64_to_user_ptr(cap->args[1]);

		if (copy_from_user(&args, argp, sizeof(args))) {
			r = -EFAULT;
			break;
		}
		r = kvm_populate_ipa_cvm_range(kvm, &args);
		break;
	}
	case KVM_CAP_ARM_TMM_ACTIVATE_CVM:
		r = kvm_activate_cvm(kvm);
		break;
	default:
		r = -EINVAL;
		break;
	}
	mutex_unlock(&kvm->lock);

	return r;
}

void kvm_destroy_tec(struct kvm_vcpu *vcpu)
{
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	if (!vcpu_is_tec(vcpu))
		return;

	if (tmi_tec_destroy(tec->tec) != 0)
		kvm_err("%s vcpu id : %d failed!\n", __func__, vcpu->vcpu_id);

	tec->tec = 0;
	kfree(tec->tec_run);
	kfree(tec);
	vcpu->arch.tec = NULL;
}

static int tmi_check_version(void)
{
	u64 res;
	int version_major;
	int version_minor;

	res = tmi_version();
	if (res == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = TMI_ABI_VERSION_GET_MAJOR(res);
	version_minor = TMI_ABI_VERSION_GET_MINOR(res);

	if (version_major != TMI_ABI_VERSION_MAJOR) {
		kvm_err("Unsupported TMI_ABI (version %d %d)\n", version_major,
			 version_minor);
		return -ENXIO;
	}

	kvm_info("TMI ABI version %d,%d\n", version_major, version_minor);
	return 0;
}

int kvm_tec_enter(struct kvm_vcpu *vcpu)
{
	struct tmi_tec_run *run;
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;
	struct cvm *cvm = (struct cvm *)vcpu->kvm->arch.cvm;

	if (READ_ONCE(cvm->state) != CVM_STATE_ACTIVE)
		return -EINVAL;

	run = tec->tec_run;
	/* set/clear TWI TWE flags */
	if (vcpu->arch.hcr_el2 & HCR_TWI)
		run->tec_entry.flags |= TEC_ENTRY_FLAG_TRAP_WFI;
	else
		run->tec_entry.flags &= ~TEC_ENTRY_FLAG_TRAP_WFI;

	if (vcpu->arch.hcr_el2 & HCR_TWE)
		run->tec_entry.flags |= TEC_ENTRY_FLAG_TRAP_WFE;
	else
		run->tec_entry.flags &= ~TEC_ENTRY_FLAG_TRAP_WFE;

	return tmi_tec_enter(tec->tec, __pa(run));
}

int cvm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target)
{
	int ret;
	struct cvm_tec *calling_tec = (struct cvm_tec *)calling->arch.tec;
	struct cvm_tec *target_tec = (struct cvm_tec *)target->arch.tec;

	ret = tmi_psci_complete(calling_tec->tec, target_tec->tec);
	if (ret)
		return -EINVAL;
	return 0;
}

int kvm_init_tmm(void)
{
	int ret;

	if (PAGE_SIZE != SZ_4K)
		return 0;

	if (tmi_check_version())
		return 0;

	ret = cvm_vmid_init();
	if (ret)
		return ret;

	tmm_feat_reg0 = tmi_features(0);
	kvm_info("TMM feature0: 0x%lx\n", tmm_feat_reg0);

	static_branch_enable(&kvm_cvm_is_available);

	return 0;
}

static bool is_numa_ipa_range_valid(struct kvm_numa_info *numa_info)
{
	unsigned long i;
	struct kvm_numa_node *numa_node, *prev_numa_node;

	prev_numa_node = NULL;
	for (i = 0; i < numa_info->numa_cnt; i++) {
		numa_node = &numa_info->numa_nodes[i];
		if (numa_node->ipa_start + numa_node->ipa_size < numa_node->ipa_start)
			return false;
		if (prev_numa_node &&
			numa_node->ipa_start < prev_numa_node->ipa_start + prev_numa_node->ipa_size)
			return false;
		prev_numa_node = numa_node;
	}
	if (numa_node->ipa_start + numa_node->ipa_size > CVM_IPA_MAX_VAL)
		return false;
	return true;
}

int kvm_load_user_data(struct kvm *kvm, unsigned long arg)
{
	struct kvm_user_data user_data;
	void __user *argp = (void __user *)arg;
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;
	struct kvm_numa_info *numa_info;

	if (!kvm_is_cvm(kvm))
		return -EFAULT;

	if (copy_from_user(&user_data, argp, sizeof(user_data)))
		return -EINVAL;

	numa_info = &user_data.numa_info;
	if (numa_info->numa_cnt > MAX_NUMA_NODE)
		return -EINVAL;

	if (numa_info->numa_cnt > 0) {
		unsigned long i, total_size = 0;
		struct kvm_numa_node *numa_node = &numa_info->numa_nodes[0];
		unsigned long ipa_end = numa_node->ipa_start + numa_node->ipa_size;

		if (!is_numa_ipa_range_valid(numa_info))
			return -EINVAL;
		if (user_data.loader_start < numa_node->ipa_start ||
			user_data.dtb_end > ipa_end)
			return -EINVAL;
		for (i = 0; i < numa_info->numa_cnt; i++)
			total_size += numa_info->numa_nodes[i].ipa_size;
		if (total_size != user_data.ram_size)
			return -EINVAL;
	}

	if (user_data.image_end <= user_data.loader_start ||
		user_data.initrd_start < user_data.image_end ||
		user_data.dtb_end < user_data.initrd_start ||
		user_data.ram_size < user_data.dtb_end - user_data.loader_start)
		return -EINVAL;

	cvm->loader_start = user_data.loader_start;
	cvm->image_end = user_data.image_end;
	cvm->initrd_start = user_data.initrd_start;
	cvm->dtb_end = user_data.dtb_end;
	cvm->ram_size = user_data.ram_size;
	memcpy(&cvm->numa_info, numa_info, sizeof(struct kvm_numa_info));

	return 0;
}

void kvm_cvm_vcpu_put(struct kvm_vcpu *vcpu)
{
	kvm_timer_vcpu_put(vcpu);
	kvm_vgic_put(vcpu);
	vcpu->cpu = -1;
}

unsigned long cvm_psci_vcpu_affinity_info(struct kvm_vcpu *vcpu,
	unsigned long target_affinity, unsigned long lowest_affinity_level)
{
	struct kvm_vcpu *target_vcpu;

	if (lowest_affinity_level != 0)
		return PSCI_RET_INVALID_PARAMS;

	target_vcpu = kvm_mpidr_to_vcpu(vcpu->kvm, target_affinity);
	if (!target_vcpu)
		return PSCI_RET_INVALID_PARAMS;

	cvm_psci_complete(vcpu, target_vcpu);
	return PSCI_RET_SUCCESS;
}

int kvm_cvm_vcpu_set_events(struct kvm_vcpu *vcpu,
	bool serror_pending, bool ext_dabt_pending)
{
	struct cvm_tec *tec = (struct cvm_tec *)vcpu->arch.tec;

	if (serror_pending)
		return -EINVAL;

	if (ext_dabt_pending) {
		if (!(((struct tmi_tec_run *)tec->tec_run)->tec_entry.flags &
			TEC_ENTRY_FLAG_EMUL_MMIO))
			return -EINVAL;

		((struct tmi_tec_run *)tec->tec_run)->tec_entry.flags
						&= ~TEC_ENTRY_FLAG_EMUL_MMIO;
		((struct tmi_tec_run *)tec->tec_run)->tec_entry.flags
						|= TEC_ENTRY_FLAG_INJECT_SEA;
	}
	return 0;
}

int kvm_create_cvm_vm(struct kvm *kvm)
{
	struct cvm *cvm;

	if (!static_key_enabled(&kvm_cvm_is_available))
		return -EFAULT;

	if (kvm->arch.cvm) {
		kvm_info("cvm already create.\n");
		return 0;
	}

	kvm->arch.cvm = kzalloc(sizeof(struct cvm), GFP_KERNEL_ACCOUNT);
	if (!kvm->arch.cvm)
		return -ENOMEM;

	cvm = (struct cvm *)kvm->arch.cvm;
	cvm->is_cvm = true;
	return 0;
}

int kvm_init_cvm_vm(struct kvm *kvm)
{
	struct tmi_cvm_params *params;
	struct cvm *cvm = (struct cvm *)kvm->arch.cvm;

	params = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	cvm->params = params;
	WRITE_ONCE(cvm->state, CVM_STATE_NONE);

	return 0;
}
