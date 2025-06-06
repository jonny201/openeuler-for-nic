// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include "util/evsel.h"
#include "util/env.h"
#include "util/pmu.h"
#include "linux/string.h"
#include "util/debug.h"

#define IBS_FETCH_L3MISSONLY   (1ULL << 59)
#define IBS_OP_L3MISSONLY      (1ULL << 16)

void arch_evsel__set_sample_weight(struct evsel *evsel)
{
	evsel__set_sample_bit(evsel, WEIGHT_STRUCT);
}

static void ibs_l3miss_warn(void)
{
	pr_warning(
"WARNING: Hw internally resets sampling period when L3 Miss Filtering is enabled\n"
"and tagged operation does not cause L3 Miss. This causes sampling period skew.\n");
}

void arch__post_evsel_config(struct evsel *evsel, struct perf_event_attr *attr)
{
	struct perf_pmu *evsel_pmu, *ibs_fetch_pmu, *ibs_op_pmu;
	static int warned_once;
	/* 0: Uninitialized, 1: Yes, -1: No */
	static int is_amd;

	if (warned_once || is_amd == -1)
		return;

	if (!is_amd) {
		struct perf_env *env = evsel__env(evsel);

		if (!perf_env__cpuid(env) || !env->cpuid ||
		    !strstarts(env->cpuid, "AuthenticAMD")) {
			is_amd = -1;
			return;
		}
		is_amd = 1;
	}

	evsel_pmu = evsel__find_pmu(evsel);
	if (!evsel_pmu)
		return;

	ibs_fetch_pmu = perf_pmu__find("ibs_fetch");
	ibs_op_pmu = perf_pmu__find("ibs_op");

	if (ibs_fetch_pmu && ibs_fetch_pmu->type == evsel_pmu->type) {
		if (attr->config & IBS_FETCH_L3MISSONLY) {
			ibs_l3miss_warn();
			warned_once = 1;
		}
	} else if (ibs_op_pmu && ibs_op_pmu->type == evsel_pmu->type) {
		if (attr->config & IBS_OP_L3MISSONLY) {
			ibs_l3miss_warn();
			warned_once = 1;
		}
	}
}
