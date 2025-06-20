/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/arch_topology.h - arch specific cpu topology information
 */
#ifndef _LINUX_ARCH_TOPOLOGY_H_
#define _LINUX_ARCH_TOPOLOGY_H_

#include <linux/types.h>
#include <linux/percpu.h>

void topology_normalize_cpu_scale(void);
int topology_update_cpu_topology(void);

#ifdef CONFIG_ACPI_CPPC_LIB
void topology_init_cpu_capacity_cppc(void);
#endif

struct device_node;
bool topology_parse_cpu_capacity(struct device_node *cpu_node, int cpu);

DECLARE_PER_CPU(unsigned long, cpu_scale);

static inline unsigned long topology_get_cpu_scale(int cpu)
{
	return per_cpu(cpu_scale, cpu);
}

void topology_set_cpu_scale(unsigned int cpu, unsigned long capacity);

DECLARE_PER_CPU(unsigned long, freq_scale);

static inline unsigned long topology_get_freq_scale(int cpu)
{
	return per_cpu(freq_scale, cpu);
}

void topology_set_freq_scale(const struct cpumask *cpus, unsigned long cur_freq,
			     unsigned long max_freq);
bool topology_scale_freq_invariant(void);

bool arch_freq_counters_available(const struct cpumask *cpus);

DECLARE_PER_CPU(unsigned long, thermal_pressure);

static inline unsigned long topology_get_thermal_pressure(int cpu)
{
	return per_cpu(thermal_pressure, cpu);
}

void topology_set_thermal_pressure(const struct cpumask *cpus,
				   unsigned long th_pressure);

struct cpu_topology {
	int thread_id;
	int core_id;
	int cluster_id;
	int package_id;
	int llc_id;
	cpumask_t thread_sibling;
	cpumask_t core_sibling;
	cpumask_t cluster_sibling;
	cpumask_t llc_sibling;
};

#ifdef CONFIG_GENERIC_ARCH_TOPOLOGY
extern struct cpu_topology cpu_topology[NR_CPUS];

#define topology_physical_package_id(cpu)	(cpu_topology[cpu].package_id)
#define topology_cluster_id(cpu)	(cpu_topology[cpu].cluster_id)
#define topology_core_id(cpu)		(cpu_topology[cpu].core_id)
#define topology_core_cpumask(cpu)	(&cpu_topology[cpu].core_sibling)
#define topology_sibling_cpumask(cpu)	(&cpu_topology[cpu].thread_sibling)
#define topology_cluster_cpumask(cpu)	(&cpu_topology[cpu].cluster_sibling)
#define topology_llc_cpumask(cpu)	(&cpu_topology[cpu].llc_sibling)
void init_cpu_topology(void);
void store_cpu_topology(unsigned int cpuid);
const struct cpumask *cpu_coregroup_mask(int cpu);
const struct cpumask *cpu_clustergroup_mask(int cpu);
void update_siblings_masks(unsigned int cpu);
void remove_cpu_topology(unsigned int cpuid);
void reset_cpu_topology(void);
int parse_acpi_topology(void);

#ifdef CONFIG_HOTPLUG_SMT
bool topology_is_primary_thread(unsigned int cpu);
void topology_smt_set_num_threads(unsigned int num_threads);
unsigned int topology_smt_get_num_threads(void);
#else
static inline bool topology_is_primary_thread(unsigned int cpu) { return false; }
static inline void topology_smt_set_num_threads(unsigned int num_threads) { }
static inline unsigned int topology_smt_get_num_threads(void)
{
	return 1;
}
#endif

#endif

#endif /* _LINUX_ARCH_TOPOLOGY_H_ */
