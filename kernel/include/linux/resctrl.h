/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RESCTRL_H
#define _RESCTRL_H

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/pid.h>

#ifdef CONFIG_PROC_CPU_RESCTRL

int proc_resctrl_show(struct seq_file *m,
		      struct pid_namespace *ns,
		      struct pid *pid,
		      struct task_struct *tsk);

#endif

/**
 * struct rdt_domain - group of CPUs sharing a resctrl resource
 * @list:		all instances of this resource
 * @id:			unique id for this instance
 * @cpu_mask:		which CPUs share this resource
 * @new_ctrl:		new ctrl value to be loaded
 * @have_new_ctrl:	did user provide new_ctrl for this domain
 * @rmid_busy_llc:	bitmap of which limbo RMIDs are above threshold
 * @mbm_total:		saved state for MBM total bandwidth
 * @mbm_local:		saved state for MBM local bandwidth
 * @mbm_over:		worker to periodically read MBM h/w counters
 * @cqm_limbo:		worker to periodically read CQM h/w counters
 * @mbm_work_cpu:	worker CPU for MBM h/w counters
 * @cqm_work_cpu:	worker CPU for CQM h/w counters
 * @plr:		pseudo-locked region (if any) associated with domain
 */
struct rdt_domain {
	struct list_head		list;
	int				id;
	struct cpumask			cpu_mask;
	u32				new_ctrl;
	bool				have_new_ctrl;
	unsigned long			*rmid_busy_llc;
	struct mbm_state		*mbm_total;
	struct mbm_state		*mbm_local;
	struct delayed_work		mbm_over;
	struct delayed_work		cqm_limbo;
	int				mbm_work_cpu;
	int				cqm_work_cpu;
	struct pseudo_lock_region	*plr;
};

/**
 * struct resctrl_cache - Cache allocation related data
 * @cbm_len:		Length of the cache bit mask
 * @min_cbm_bits:	Minimum number of consecutive bits to be set
 * @cbm_idx_mult:	Multiplier of CBM index
 * @cbm_idx_offset:	Offset of CBM index. CBM index is computed by:
 *			closid * cbm_idx_multi + cbm_idx_offset
 *			in a cache bit mask
 * @shareable_bits:	Bitmask of shareable resource with other
 *			executing entities
 * @arch_has_sparse_bitmaps:	True if a bitmap like f00f is valid.
 * @arch_has_empty_bitmaps:	True if the '0' bitmap is valid.
 * @arch_has_per_cpu_cfg:	True if QOS_CFG register for this cache
 *				level has CPU scope.
 */
struct resctrl_cache {
	unsigned int	cbm_len;
	unsigned int	min_cbm_bits;
	unsigned int	cbm_idx_mult;	// TODO remove this
	unsigned int	cbm_idx_offset; // TODO remove this
	unsigned int	shareable_bits;
	bool		arch_has_sparse_bitmaps;
	bool		arch_has_empty_bitmaps;
	bool		arch_has_per_cpu_cfg;
};

/**
 * enum membw_throttle_mode - System's memory bandwidth throttling mode
 * @THREAD_THROTTLE_UNDEFINED:	Not relevant to the system
 * @THREAD_THROTTLE_MAX:	Memory bandwidth is throttled at the core
 *				always using smallest bandwidth percentage
 *				assigned to threads, aka "max throttling"
 * @THREAD_THROTTLE_PER_THREAD:	Memory bandwidth is throttled at the thread
 */
enum membw_throttle_mode {
	THREAD_THROTTLE_UNDEFINED = 0,
	THREAD_THROTTLE_MAX,
	THREAD_THROTTLE_PER_THREAD,
};

/**
 * struct resctrl_membw - Memory bandwidth allocation related data
 * @min_bw:		Minimum memory bandwidth percentage user can request
 * @bw_gran:		Granularity at which the memory bandwidth is allocated
 * @delay_linear:	True if memory B/W delay is in linear scale
 * @arch_needs_linear:	True if we can't configure non-linear resources
 * @throttle_mode:	Bandwidth throttling mode when threads request
 *			different memory bandwidths
 * @mba_sc:		True if MBA software controller(mba_sc) is enabled
 * @mb_map:		Mapping of memory B/W percentage to memory B/W delay
 */
struct resctrl_membw {
	u32				min_bw;
	u32				bw_gran;
	u32				delay_linear;
	bool				arch_needs_linear;
	enum membw_throttle_mode	throttle_mode;
	bool				mba_sc;
	u32				*mb_map;
};

struct rdt_parse_data;

/**
 * struct rdt_resource - attributes of a resctrl resource
 * @rid:		The index of the resource
 * @alloc_enabled:	Is allocation enabled on this machine
 * @alloc_capable:	Is allocation available on this machine
 * @mon_capable:	Is monitor feature available on this machine
 * @num_rmid:		Number of RMIDs available
 * @cache_level:	Which cache level defines scope of this resource
 * @cache:		Cache allocation related data
 * @membw:		If the component has bandwidth controls, their properties.
 * @domains:		All domains for this resource
 * @name:		Name to use in "schemata" file.
 * @data_width:		Character width of data when displaying
 * @default_ctrl:	Specifies default cache cbm or memory B/W percent.
 * @format_str:		Per resource format string to show domain value
 * @parse_ctrlval:	Per resource function pointer to parse control values
 * @evt_list:		List of monitoring events
 * @fflags:		flags to choose base and info files
 */
struct rdt_resource {
	int			rid;
	bool			alloc_enabled;
	bool			alloc_capable;
	bool			mon_capable;
	int			num_rmid;
	int			cache_level;
	struct resctrl_cache	cache;
	struct resctrl_membw	membw;
	struct list_head	domains;
	char			*name;
	int			data_width;
	u32			default_ctrl;
	const char		*format_str;
	int			(*parse_ctrlval)(struct rdt_parse_data *data,
						 struct rdt_resource *r,
						 struct rdt_domain *d);
	struct list_head	evt_list;
	unsigned long		fflags;

};

/**
 * resctrl_arch_reset_rmid_all() - Reset all private state associated with
 *				   all rmids and eventids.
 * @r:		The resctrl resource.
 * @d:		The domain for which all architectural counter state will
 *		be cleared.
 *
 * This can be called from any CPU.
 */
void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_domain *d);
int resctrl_online_domain(struct rdt_resource *r, struct rdt_domain *d);

#endif /* _RESCTRL_H */
