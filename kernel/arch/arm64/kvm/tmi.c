// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, The Linux Foundation. All rights reserved.
 */
#include <linux/arm-smccc.h>
#include <asm/kvm_tmi.h>
#include <asm/memory.h>

u64 tmi_version(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_VERSION_REQ, &res);
	return res.a1;
}

u64 tmi_data_create(u64 numa_set, u64 rd, u64 map_addr, u64 src, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DATA_CREATE, numa_set, rd, map_addr, src, level, &res);
	return res.a1;
}

u64 tmi_data_destroy(u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_DATA_DESTROY, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_cvm_activate(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_ACTIVATE, rd, &res);
	return res.a1;
}

u64 tmi_cvm_create(u64 params_ptr, u64 numa_set)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_CREATE, params_ptr, numa_set, &res);
	return res.a1;
}

u64 tmi_cvm_destroy(u64 rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_CVM_DESTROY, rd, &res);
	return res.a1;
}

u64 tmi_tec_create(u64 numa_set, u64 rd, u64 mpidr, u64 params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_CREATE, numa_set, rd, mpidr, params_ptr, &res);
	return res.a1;
}

u64 tmi_tec_destroy(u64 tec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_DESTROY, tec, &res);
	return res.a1;
}

u64 tmi_tec_enter(u64 tec, u64 run_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TEC_ENTER, tec, run_ptr, &res);
	return res.a1;
}

u64 tmi_ttt_create(u64 numa_set, u64 rd, u64 map_addr, u64 level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_CREATE, numa_set, rd, map_addr, level, &res);
	return res.a1;
}

u64 tmi_psci_complete(u64 calling_tec, u64 target_tec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_PSCI_COMPLETE, calling_tec, target_tec, &res);
	return res.a1;
}

u64 tmi_features(u64 index)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_FEATURES, index, &res);
	return res.a1;
}

u64 tmi_mem_info_show(u64 mem_info_addr)
{
	struct arm_smccc_res res;
	u64 pa_addr = __pa(mem_info_addr);

	arm_smccc_1_1_smc(TMI_TMM_MEM_INFO_SHOW, pa_addr, &res);
	return res.a1;
}
EXPORT_SYMBOL_GPL(tmi_mem_info_show);

u64 tmi_ttt_map_range(u64 rd, u64 map_addr, u64 size, u64 cur_node, u64 target_node)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_MAP_RANGE, rd, map_addr, size, cur_node, target_node, &res);
	return res.a1;
}

u64 tmi_ttt_unmap_range(u64 rd, u64 map_addr, u64 size, u64 node_id)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(TMI_TMM_TTT_UNMAP_RANGE, rd, map_addr, size, node_id, &res);
	return res.a1;
}
