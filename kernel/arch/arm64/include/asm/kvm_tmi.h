/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#ifndef __TMM_TMI_H
#define __TMM_TMI_H
#ifdef CONFIG_CVM_HOST
#include <linux/kvm_host.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_pgtable.h>
#include <linux/virtio_ring.h>
#include <asm/sysreg.h>

#define GRANULE_SIZE		4096

#define NO_NUMA			0 /* numa bitmap */

#define TMM_TTT_LEVEL_2 2
#define TMM_TTT_LEVEL_3 3

/* TMI error codes. */
#define TMI_SUCCESS				0
#define TMI_ERROR_INPUT			1
#define TMI_ERROR_MEMORY		2
#define TMI_ERROR_ALIAS			3
#define TMI_ERROR_IN_USE		4
#define TMI_ERROR_CVM_STATE		5
#define TMI_ERROR_OWNER			6
#define TMI_ERROR_TEC			7
#define TMI_ERROR_TTT_WALK		8
#define TMI_ERROR_TTT_ENTRY		9
#define TMI_ERROR_NOT_SUPPORTED	10
#define TMI_ERROR_INTERNAL		11
#define TMI_ERROR_CVM_POWEROFF		12
#define TMI_ERROR_TTT_CREATED		13

#define TMI_RETURN_STATUS(ret)		((ret) & 0xFF)
#define TMI_RETURN_INDEX(ret)		(((ret) >> 8) & 0xFF)

#define TMI_FEATURE_REGISTER_0_S2SZ			GENMASK(7, 0)
#define TMI_FEATURE_REGISTER_0_LPA2			BIT(8)
#define TMI_FEATURE_REGISTER_0_SVE_EN			BIT(9)
#define TMI_FEATURE_REGISTER_0_SVE_VL			GENMASK(13, 10)
#define TMI_FEATURE_REGISTER_0_NUM_BPS			GENMASK(17, 14)
#define TMI_FEATURE_REGISTER_0_NUM_WPS			GENMASK(21, 18)
#define TMI_FEATURE_REGISTER_0_PMU_EN			BIT(22)
#define TMI_FEATURE_REGISTER_0_PMU_NUM_CTRS	GENMASK(27, 23)
#define TMI_FEATURE_REGISTER_0_HASH_SHA_256	BIT(28)
#define TMI_FEATURE_REGISTER_0_HASH_SHA_512	BIT(29)

#define TMI_CVM_PARAM_FLAG_LPA2	BIT(0)
#define TMI_CVM_PARAM_FLAG_SVE		BIT(1)
#define TMI_CVM_PARAM_FLAG_PMU		BIT(2)

/*
 * Many of these fields are smaller than u64 but all fields have u64
 * alignment, so use u64 to ensure correct alignment.
 */
struct tmi_cvm_params {
	u64	flags;
	u64	s2sz;
	u64	sve_vl;
	u64	num_bps;
	u64	num_wps;
	u64	pmu_num_cnts;
	u64	measurement_algo;
	u64	vmid;
	u64	ns_vtcr;
	u64	vttbr_el2;
	u64	ttt_base;
	s64	ttt_level_start;
	u64	ttt_num_start;
	u8	rpv[64]; /* Bits 512 */
};

#define TMI_NOT_RUNNABLE	0
#define TMI_RUNNABLE		1

/*
 *	The number of GPRs (starting from X0) that are
 *	configured by the host when a TEC is created.
 */
#define TEC_CREATE_NR_GPRS		(8U)

struct tmi_tec_params {
	uint64_t gprs[TEC_CREATE_NR_GPRS];
	uint64_t pc;
	uint64_t flags;
	uint64_t ram_size;
};

#define TEC_ENTRY_FLAG_EMUL_MMIO		(1UL << 0U)
#define TEC_ENTRY_FLAG_INJECT_SEA		(1UL << 1U)
#define TEC_ENTRY_FLAG_TRAP_WFI		(1UL << 2U)
#define TEC_ENTRY_FLAG_TRAP_WFE		(1UL << 3U)

#define TMI_EXIT_SYNC		0
#define TMI_EXIT_IRQ		1
#define TMI_EXIT_FIQ		2
#define TMI_EXIT_PSCI		3
#define TMI_EXIT_HOST_CALL	5
#define TMI_EXIT_SERROR	6

/*
 * The number of GPRs (starting from X0) per voluntary exit context.
 * Per SMCCC.
 */
 #define TEC_EXIT_NR_GPRS		(31U)

/* Maximum number of Interrupt Controller List Registers. */
#define TEC_GIC_NUM_LRS		(16U)

struct tmi_tec_entry {
	uint64_t flags;
	uint64_t gprs[TEC_EXIT_NR_GPRS];
	uint64_t gicv3_lrs[TEC_GIC_NUM_LRS];
	uint64_t gicv3_hcr;
};

struct tmi_tec_exit {
	uint64_t exit_reason;
	uint64_t esr;
	uint64_t far;
	uint64_t hpfar;
	uint64_t gprs[TEC_EXIT_NR_GPRS];
	uint64_t gicv3_hcr;
	uint64_t gicv3_lrs[TEC_GIC_NUM_LRS];
	uint64_t gicv3_misr;
	uint64_t gicv3_vmcr;
	uint64_t cntv_ctl;
	uint64_t cntv_cval;
	uint64_t cntp_ctl;
	uint64_t cntp_cval;
	uint64_t imm;
	uint64_t pmu_ovf_status;
};

struct tmi_tec_run {
	struct tmi_tec_entry tec_entry;
	struct tmi_tec_exit tec_exit;
};

#define TMI_FNUM_MIN_VALUE	U(0x150)
#define TMI_FNUM_MAX_VALUE	U(0x18F)

/******************************************************************************
 * Bit definitions inside the function id as per the SMC calling convention
 ******************************************************************************/
#define FUNCID_TYPE_SHIFT		31
#define FUNCID_CC_SHIFT		30
#define FUNCID_OEN_SHIFT		24
#define FUNCID_NUM_SHIFT		0

#define FUNCID_TYPE_MASK		0x1
#define FUNCID_CC_MASK			0x1
#define FUNCID_OEN_MASK		0x3f
#define FUNCID_NUM_MASK		0xffff

#define FUNCID_TYPE_WIDTH		1
#define FUNCID_CC_WIDTH		1
#define FUNCID_OEN_WIDTH		6
#define FUNCID_NUM_WIDTH		16

#define SMC_64				1
#define SMC_32				0
#define SMC_TYPE_FAST			1
#define SMC_TYPE_STD			0

/*****************************************************************************
 * Owning entity number definitions inside the function id as per the SMC
 * calling convention
 *****************************************************************************/
#define OEN_ARM_START			0
#define OEN_ARM_END			0
#define OEN_CPU_START			1
#define OEN_CPU_END			1
#define OEN_SIP_START			2
#define OEN_SIP_END			2
#define OEN_OEM_START			3
#define OEN_OEM_END			3
#define OEN_STD_START			4	/* Standard Calls */
#define OEN_STD_END			4
#define OEN_TAP_START			48	/* Trusted Applications */
#define OEN_TAP_END			49
#define OEN_TOS_START			50	/* Trusted OS */
#define OEN_TOS_END			63
#define OEN_LIMIT				64

/* Get TMI fastcall std FID from function number */
#define TMI_FID(smc_cc, func_num)	\
	((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT)	|	\
	((smc_cc) << FUNCID_CC_SHIFT)			|	\
	(OEN_STD_START << FUNCID_OEN_SHIFT)		|	\
	((func_num) << FUNCID_NUM_SHIFT))

#define U(_x) (_x##U)

#define TMI_NO_MEASURE_CONTENT	U(0)
#define TMI_MEASURE_CONTENT	U(1)

#define CVM_IPA_MAX_VAL  (1UL << 48)

/*
 * SMC_TMM_INIT_COMPLETE is the only function in the TMI that originates from
 * the CVM world and is handled by the SPMD. The remaining functions are
 * always invoked by the Normal world, forward by SPMD and handled by the
 * TMM.
 */
#define TMI_FNUM_VERSION_REQ			U(0x260)
#define TMI_FNUM_MEM_INFO_SHOW			U(0x261)
#define TMI_FNUM_DATA_CREATE			U(0x262)
#define TMI_FNUM_DATA_DESTROY			U(0x263)
#define TMI_FNUM_CVM_ACTIVATE			U(0x264)
#define TMI_FNUM_CVM_CREATE			U(0x265)
#define TMI_FNUM_CVM_DESTROY			U(0x266)
#define TMI_FNUM_TEC_CREATE			U(0x267)
#define TMI_FNUM_TEC_DESTROY			U(0x268)
#define TMI_FNUM_TEC_ENTER			U(0x269)
#define TMI_FNUM_TTT_CREATE			U(0x26A)
#define TMI_FNUM_PSCI_COMPLETE			U(0x26B)
#define TMI_FNUM_FEATURES			U(0x26C)
#define TMI_FNUM_TTT_MAP_RANGE			U(0x26D)
#define TMI_FNUM_TTT_UNMAP_RANGE		U(0x26E)

/* TMI SMC64 PIDs handled by the SPMD */
#define TMI_TMM_VERSION_REQ			TMI_FID(SMC_64, TMI_FNUM_VERSION_REQ)
#define TMI_TMM_DATA_CREATE			TMI_FID(SMC_64, TMI_FNUM_DATA_CREATE)
#define TMI_TMM_DATA_DESTROY			TMI_FID(SMC_64, TMI_FNUM_DATA_DESTROY)
#define TMI_TMM_CVM_ACTIVATE			TMI_FID(SMC_64, TMI_FNUM_CVM_ACTIVATE)
#define TMI_TMM_CVM_CREATE			TMI_FID(SMC_64, TMI_FNUM_CVM_CREATE)
#define TMI_TMM_CVM_DESTROY			TMI_FID(SMC_64, TMI_FNUM_CVM_DESTROY)
#define TMI_TMM_TEC_CREATE			TMI_FID(SMC_64, TMI_FNUM_TEC_CREATE)
#define TMI_TMM_TEC_DESTROY			TMI_FID(SMC_64, TMI_FNUM_TEC_DESTROY)
#define TMI_TMM_TEC_ENTER			TMI_FID(SMC_64, TMI_FNUM_TEC_ENTER)
#define TMI_TMM_TTT_CREATE			TMI_FID(SMC_64, TMI_FNUM_TTT_CREATE)
#define TMI_TMM_PSCI_COMPLETE			TMI_FID(SMC_64, TMI_FNUM_PSCI_COMPLETE)
#define TMI_TMM_FEATURES			TMI_FID(SMC_64, TMI_FNUM_FEATURES)
#define TMI_TMM_MEM_INFO_SHOW			TMI_FID(SMC_64, TMI_FNUM_MEM_INFO_SHOW)
#define TMI_TMM_TTT_MAP_RANGE			TMI_FID(SMC_64, TMI_FNUM_TTT_MAP_RANGE)
#define TMI_TMM_TTT_UNMAP_RANGE			TMI_FID(SMC_64, TMI_FNUM_TTT_UNMAP_RANGE)

#define TMI_ABI_VERSION_GET_MAJOR(_version) ((_version) >> 16)
#define TMI_ABI_VERSION_GET_MINOR(_version) ((_version) & 0xFFFF)

#define TMI_ABI_VERSION_MAJOR			U(0x1)

/* KVM_CAP_ARM_TMM on VM fd */
#define KVM_CAP_ARM_TMM_CONFIG_CVM_HOST		0
#define KVM_CAP_ARM_TMM_CREATE_RD		1
#define KVM_CAP_ARM_TMM_POPULATE_CVM		2
#define KVM_CAP_ARM_TMM_ACTIVATE_CVM		3

#define KVM_CAP_ARM_TMM_MEASUREMENT_ALGO_SHA256		0
#define KVM_CAP_ARM_TMM_MEASUREMENT_ALGO_SHA512		1

#define KVM_CAP_ARM_TMM_RPV_SIZE 64

/* List of configuration items accepted for KVM_CAP_ARM_TMM_CONFIG_CVM_HOST */
#define KVM_CAP_ARM_TMM_CFG_RPV					0
#define KVM_CAP_ARM_TMM_CFG_HASH_ALGO				1
#define KVM_CAP_ARM_TMM_CFG_SVE					2
#define KVM_CAP_ARM_TMM_CFG_DBG					3
#define KVM_CAP_ARM_TMM_CFG_PMU					4

DECLARE_STATIC_KEY_FALSE(kvm_cvm_is_available);
DECLARE_STATIC_KEY_FALSE(kvm_cvm_is_enable);

struct kvm_cap_arm_tmm_config_item {
	__u32 cfg;
	union {
		/* cfg == KVM_CAP_ARM_TMM_CFG_RPV */
		struct {
			__u8	rpv[KVM_CAP_ARM_TMM_RPV_SIZE];
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_HASH_ALGO */
		struct {
			__u32	hash_algo;
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_SVE */
		struct {
			__u32	sve_vq;
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_DBG */
		struct {
			__u32	num_brps;
			__u32	num_wrps;
		};

		/* cfg == KVM_CAP_ARM_TMM_CFG_PMU */
		struct {
			__u32	num_pmu_cntrs;
		};
		/* Fix the size of the union */
		__u8	reserved[256];
	};
};

#define KVM_ARM_TMM_POPULATE_FLAGS_MEASURE	(1U << 0)
struct kvm_cap_arm_tmm_populate_region_args {
	__u64 populate_ipa_base1;
	__u64 populate_ipa_size1;
	__u64 populate_ipa_base2;
	__u64 populate_ipa_size2;
	__u32 flags;
	__u32 reserved[3];
};

static inline bool tmm_is_addr_ttt_level_aligned(uint64_t addr, int level)
{
	uint64_t mask = (1 << (12 + 9 * (3 - level))) - 1;

	return (addr & mask) == 0;
}

#define ID_AA64PFR0_SEL2_MASK      ULL(0xf)

static inline bool is_armv8_4_sel2_present(void)
{
	return ((read_sysreg(id_aa64pfr0_el1) >> ID_AA64PFR0_SEL2_SHIFT) &
			ID_AA64PFR0_SEL2_MASK) == 1UL;
}

u64 tmi_version(void);
u64 tmi_data_create(u64 data, u64 rd, u64 map_addr, u64 src, u64 level);
u64 tmi_data_destroy(u64 rd, u64 map_addr, u64 level);
u64 tmi_cvm_activate(u64 rd);
u64 tmi_cvm_create(u64 params_ptr, u64 numa_set);
u64 tmi_cvm_destroy(u64 rd);
u64 tmi_tec_create(u64 numa_set, u64 rd, u64 mpidr, u64 params_ptr);
u64 tmi_tec_destroy(u64 tec);
u64 tmi_tec_enter(u64 tec, u64 run_ptr);
u64 tmi_ttt_create(u64 numa_set, u64 rd, u64 map_addr, u64 level);
u64 tmi_psci_complete(u64 calling_tec, u64 target_tec);
u64 tmi_features(u64 index);
u64 tmi_ttt_map_range(u64 rd, u64 map_addr, u64 size, u64 cur_node, u64 target_node);
u64 tmi_ttt_unmap_range(u64 rd, u64 map_addr, u64 size, u64 node_id);
u64 tmi_mem_info_show(u64 mem_info_addr);

void kvm_cvm_vcpu_put(struct kvm_vcpu *vcpu);
int kvm_load_user_data(struct kvm *kvm, unsigned long arg);
unsigned long cvm_psci_vcpu_affinity_info(struct kvm_vcpu *vcpu,
	unsigned long target_affinity, unsigned long lowest_affinity_level);
int kvm_cvm_vcpu_set_events(struct kvm_vcpu *vcpu,
	bool serror_pending, bool ext_dabt_pending);
int kvm_create_cvm_vm(struct kvm *kvm);
int kvm_init_cvm_vm(struct kvm *kvm);

#endif
#endif
