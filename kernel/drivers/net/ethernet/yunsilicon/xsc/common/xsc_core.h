/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_CORE_H
#define XSC_CORE_H

#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/spinlock_types.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/radix-tree.h>
#include <linux/workqueue.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/if_vlan.h>
#include <linux/reboot.h>
#include <linux/rwlock.h>

#include "common/xsc_cmd.h"
#include "common/xsc_ioctl.h"
#include "common/driver.h"
#include "common/xsc_reg.h"
#include "common/xsc_eswitch.h"
#include "common/version.h"

#if (HOTFIX_NUM == 0)
#define DRIVER_VERSION __stringify(BRANCH_VERSION) "." __stringify(MAJOR_VERSION) "." \
		__stringify(MINOR_VERSION) "." __stringify(BUILD_VERSION)
#else
#define DRIVER_VERSION __stringify(BRANCH_VERSION) "." __stringify(MAJOR_VERSION) "." \
		__stringify(MINOR_VERSION) "." __stringify(BUILD_VERSION) ".H" \
		__stringify(HOTFIX_NUM)
#endif

extern uint xsc_debug_mask;
extern unsigned int xsc_log_level;

#ifndef mmiowb
#define mmiowb()
#endif


#define XSC_PCI_VENDOR_ID		0x1f67

#define XSC_MC_PF_DEV_ID		0x1011
#define XSC_MC_VF_DEV_ID		0x1012
#define XSC_MC_PF_DEV_ID_DIAMOND	0x1021
#define XSC_MC_PF_DEV_ID_DIAMOND_NEXT	0x1023

#define XSC_MF_HOST_PF_DEV_ID		0x1051
#define XSC_MF_HOST_VF_DEV_ID		0x1052
#define XSC_MF_SOC_PF_DEV_ID		0x1053

#define XSC_MS_PF_DEV_ID		0x1111
#define XSC_MS_VF_DEV_ID		0x1112

#define XSC_MV_HOST_PF_DEV_ID		0x1151
#define XSC_MV_HOST_VF_DEV_ID		0x1152
#define XSC_MV_SOC_PF_DEV_ID		0x1153

#define XSC_SUB_DEV_ID_MC_50		0xC050
#define XSC_SUB_DEV_ID_MC_100		0xC100
#define XSC_SUB_DEV_ID_MC_200		0xC200
#define XSC_SUB_DEV_ID_MC_400S		0xC400
#define XSC_SUB_DEV_ID_MF_50		0xF050
#define XSC_SUB_DEV_ID_MF_200		0xF200
#define XSC_SUB_DEV_ID_MS_50		0xA050
#define XSC_SUB_DEV_ID_MS_100Q		0xA104
#define XSC_SUB_DEV_ID_MS_200		0xA200
#define XSC_SUB_DEV_ID_MS_200S		0xA201
#define XSC_SUB_DEV_ID_MS_400M		0xA202
#define XSC_SUB_DEV_ID_MS_200_OCP	0xA203
#define XSC_SUB_DEV_ID_MS_100S_OCP	0xA204
#define XSC_SUB_DEV_ID_MV_100		0xD100
#define XSC_SUB_DEV_ID_MV_200		0xD200

#define XSC_MAX_PRODUCT_NAME_LEN	32

enum {
	XSC_LOG_LEVEL_DBG	= 0,
	XSC_LOG_LEVEL_INFO	= 1,
	XSC_LOG_LEVEL_WARN	= 2,
	XSC_LOG_LEVEL_ERR	= 3,
};

enum {
	XSC_CHIP_MC,
	XSC_CHIP_MF,
	XSC_CHIP_MS,
	XSC_CHIP_MV,
	XSC_CHIP_UNKNOWN,
};

#ifndef dev_fmt
#define dev_fmt(fmt) fmt
#endif

#define xsc_dev_log(condition, level, dev, fmt, ...)			\
do {									\
	if (condition)							\
		dev_printk(level, dev, dev_fmt(fmt), ##__VA_ARGS__);	\
} while (0)

#define xsc_core_dbg(__dev, format, ...)				\
	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_DBG, KERN_DEBUG,	\
		&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,		\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define xsc_core_dbg_once(__dev, format, ...)				\
	dev_dbg_once(&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,	\
		     __func__, __LINE__, current->pid,			\
		     ##__VA_ARGS__)

#define xsc_core_dbg_mask(__dev, mask, format, ...)			\
do {									\
	if ((mask) & xsc_debug_mask)					\
		xsc_core_dbg(__dev, format, ##__VA_ARGS__);		\
} while (0)

#define xsc_core_err(__dev, format, ...)				\
	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_ERR, KERN_ERR,	\
		&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,		\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define xsc_core_err_rl(__dev, format, ...)				\
	dev_err_ratelimited(&(__dev)->pdev->dev,			\
			   "%s:%d:(pid %d): " format,			\
			   __func__, __LINE__, current->pid,		\
			   ##__VA_ARGS__)

#define xsc_core_warn(__dev, format, ...)				\
	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_WARN, KERN_WARNING,	\
		&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,		\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define xsc_core_info(__dev, format, ...)				\
	xsc_dev_log(xsc_log_level <= XSC_LOG_LEVEL_INFO, KERN_INFO,	\
		&(__dev)->pdev->dev, "%s:%d:(pid %d): " format,		\
		__func__, __LINE__, current->pid, ##__VA_ARGS__)

#define xsc_pr_debug(format, ...)					\
do {									\
	if (xsc_log_level <= XSC_LOG_LEVEL_DBG)				\
		pr_debug(format, ##__VA_ARGS__);		\
} while (0)

#define assert(__dev, expr)						\
do {									\
	if (!(expr)) {							\
		dev_err(&(__dev)->pdev->dev,				\
		"Assertion failed! %s, %s, %s, line %d\n",		\
		#expr, __FILE__, __func__, __LINE__);			\
	}								\
} while (0)

#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)

#define XSC_PCIE_NO_HOST	0x0
#define XSC_PCIE_NO_SOC		0x1
#define XSC_PCIE_NO_UNSET	0xFF

enum xsc_dev_event {
	XSC_DEV_EVENT_SYS_ERROR,
	XSC_DEV_EVENT_PORT_UP,
	XSC_DEV_EVENT_PORT_DOWN,
	XSC_DEV_EVENT_PORT_INITIALIZED,
	XSC_DEV_EVENT_LID_CHANGE,
	XSC_DEV_EVENT_PKEY_CHANGE,
	XSC_DEV_EVENT_GUID_CHANGE,
	XSC_DEV_EVENT_CLIENT_REREG,
};

enum {
	/* one minute for the sake of bringup. Generally, commands must always
	 * complete and we may need to increase this timeout value
	 */
	XSC_CMD_TIMEOUT_MSEC	= 10 * 1000,
	XSC_CMD_WQ_MAX_NAME	= 32,
};

enum {
	XSC_MAX_NAME_LEN = 32,
};

enum {
	XSC_MAX_PORTS	= 2,
};

enum {
	MAX_MR_CACHE_ENTRIES    = 16,
};

enum {
	XSC_CMD_DATA, /* print command payload only */
	XSC_CMD_TIME, /* print command execution time */
};

enum xsc_rdma_driver_id {
	RDMA_DRIVER_XSC_UNKNOWN,
	RDMA_DRIVER_XSC5,
	RDMA_DRIVER_XSC4,
};

/* mutex for interface device list */
extern struct mutex xsc_intf_mutex;

#define GROUP_REFER_CNT_SIZE	1024

struct qp_group_refer {
	spinlock_t lock;	/* protect refer_cnt[] */
	u16 refer_cnt[GROUP_REFER_CNT_SIZE];
};

enum xsc_pci_status {
	XSC_PCI_STATUS_DISABLED,
	XSC_PCI_STATUS_ENABLED,
};

enum xsc_device_state {
	XSC_DEVICE_STATE_UNINITIALIZED,
	XSC_DEVICE_STATE_UP,
	XSC_DEVICE_STATE_INTERNAL_ERROR,
};

enum xsc_interface_state {
	XSC_INTERFACE_STATE_UP = BIT(0),
	XSC_INTERFACE_STATE_TEARDOWN = BIT(1),
};

enum {
	XSC_INTERFACE_PROTOCOL_IB  = 0,
	XSC_INTERFACE_PROTOCOL_ETH = 1,
};

enum {
	XSC_INTERFACE_ADDED,
	XSC_INTERFACE_ATTACHED,
};


enum xsc_coredev_type {
	XSC_COREDEV_PF,
	XSC_COREDEV_VF,
	XSC_COREDEV_SF
};

enum {
	XSC_PCI_DEV_IS_VF	= 1 << 0,
};

enum port_state_policy {
	XSC_POLICY_DOWN	= 0,
	XSC_POLICY_UP		= 1,
	XSC_POLICY_FOLLOW	= 2,
	XSC_POLICY_INVALID	= 0xffffffff
};

enum {
	XSC_CAP_PORT_TYPE_IB	= 0x0,
	XSC_CAP_PORT_TYPE_ETH	= 0x1,
};

enum xsc_inline_modes {
	XSC_INLINE_MODE_NONE,
	XSC_INLINE_MODE_L2,
	XSC_INLINE_MODE_IP,
	XSC_INLINE_MODE_TCP_UDP,
};

struct xsc_core_device;

struct xsc_vf_context {
	int	enabled;
	u64	port_guid;
	u64	node_guid;
	enum port_state_policy	policy;
};

struct xsc_sriov_vf {
	struct xsc_core_device  *dev;
	struct kobject		kobj;
	int			vf;
};

struct xsc_pci_sriov {
	/* standard SRIOV capability fields, mostly for debug */
	int	pos;		/* capability position */
	int	nres;		/* number of resources */
	u32	cap;		/* SR-IOV Capabilities */
	u16	ctrl;		/* SR-IOV Control */
	u16	total_vfs;	/* total VFs of PF */
	u16	initial_vfs;	/* initial VFs of PF */
	u16	num_vfs;	/* number of VFs available */
	u16	offset;		/* first VF Routing ID offset */
	u16	stride;		/* following VF stride */
	u16	vf_device;	/* VF device ID */
	u32	pgsz;		/* page size for BAR alignment */
	u8	link;		/* Function Dependency Link */
};

struct xsc_core_sriov {
	int	num_vfs;
	u16	max_vfs;
	u16	vf_bdf_base;
	u8	probe_vf;
	struct xsc_vf_context	*vfs_ctx;
	struct kobject		*config;
	struct kobject		*groups_config;
	struct kobject		node_guid_kobj;
	struct xsc_sriov_vf	*vfs;
	struct xsc_pci_sriov	pci_sriov;
};

struct xsc_vgroup {
	struct xsc_core_device *dev;
	u32		     group_id;
	u32		     num_vports;
	u32		     tsar_ix;
	u32		     max_rate;
	u32		     min_rate;
	u32		     bw_share;
	struct		     kobject kobj;
	struct		     list_head list;
};

struct xsc_vport_info {
	u8                      mac[ETH_ALEN];
	u16                     vlan;
	u8                      qos;
	__be16			        vlan_proto;
	u64                     node_guid;
	int                     link_state;
	u32                     min_rate;
	u32                     max_rate;
	u8                      spoofchk;
	u8                      trusted;
	u8                      roce;
	/* the admin approved vlan list */
	DECLARE_BITMAP(vlan_trunk_8021q_bitmap, VLAN_N_VID);
	u32			group;
};

#define XSC_L2_ADDR_HASH_SIZE	BIT(BITS_PER_BYTE)

enum xsc_eswitch_vport_event {
	XSC_VPORT_UC_ADDR_CHANGE = BIT(0),
	XSC_VPORT_MC_ADDR_CHANGE = BIT(1),
	XSC_VPORT_PROMISC_CHANGE = BIT(2),
	XSC_VPORT_VLAN_CHANGE = BIT(3),
};

struct xsc_vport {
	struct xsc_core_device  *dev;
	u16                     vport;
	struct hlist_head       uc_list[XSC_L2_ADDR_HASH_SIZE];
	struct hlist_head       mc_list[XSC_L2_ADDR_HASH_SIZE];
	/* The requested vlan list from the vport side */
	DECLARE_BITMAP(req_vlan_bitmap, VLAN_N_VID);
	/* Actual accepted vlans on the acl tables */
	DECLARE_BITMAP(acl_vlan_8021q_bitmap, VLAN_N_VID);
	struct work_struct      vport_change_handler;

	struct xsc_vport_info   info;

	struct {
		u8    enabled;
		u32     esw_tsar_ix;
		u32     bw_share;
	u32     min_rate;
	u32     max_rate;
	} qos;

	u8 enabled;
	enum xsc_eswitch_vport_event enabled_events;
	u16 match_id;
	u32 bond_metadata;
	u16 vlan_id;
	u8 vlan_qos;
	__be16 vlan_proto;
};

struct xsc_eswitch {
	struct xsc_core_device	*dev;
	u32	flags;
	int	total_vports;
	int	enabled_vports;
	int     num_vfs;
	struct xsc_vport        *vports;
	struct workqueue_struct *work_queue;

	/* Synchronize between vport change events
	 * and async SRIOV admin state changes
	 */
	struct mutex	state_lock;

	/* Protects eswitch mode changes occurring via sriov
	 * state change, devlink commands.
	 */
	struct mutex	mode_lock;
	int	mode;
	int	nvports;
	u16	manager_vport;
	u16	first_host_vport;
};

struct xsc_core_health {
	u8	sick;
};

struct xsc_priv {
	char			name[XSC_MAX_NAME_LEN];
	struct list_head	dev_list;
	struct list_head	ctx_list;
	spinlock_t		ctx_lock;	/* protect ctx_list */
	int			numa_node;
	struct xsc_core_sriov	sriov;
	struct xsc_eswitch	*eswitch;
	struct xsc_core_health	health;
};

struct xsc_port_ctrl {
	struct list_head node;
	dev_t devid;
	struct cdev cdev;
	struct device *device;
	struct list_head file_list;
	spinlock_t file_lock;	/* protect file_list */
};

typedef	int (*restore_func_t)(struct xsc_core_device *dev);

struct xsc_bdf_file {
	unsigned long key;
	struct radix_tree_root obj_tree;	/* protect obj_tree */
	spinlock_t obj_lock;
	struct xsc_core_device *xdev;
	restore_func_t restore_nic_fn;
};

struct xsc_port_ctrl_file {
	struct list_head file_node;
	struct radix_tree_root bdf_tree;
	spinlock_t bdf_lock;	/* protect bdf_tree */
	struct xsc_bdf_file *root_bdf;
	struct xsc_port_ctrl *ctrl;
};

struct xsc_port_caps {
	int		gid_table_len;
	int		pkey_table_len;
};

struct xsc_caps {
	u8		log_max_eq;
	u8		log_max_mkey;
	u8		log_max_srq;
	u8		log_max_msix;
	u32		max_cq;
	u32		max_qp;
	u32		max_pd;
	u32		max_cqes;
	u32		max_wqes;
	u32		max_sq_desc_sz;
	u32		max_rq_desc_sz;
	u64		flags;
	u16		stat_rate_support;
	u32		log_max_msg;
	u32		num_ports;
	u32		max_ra_res_qp;
	u32		max_ra_req_qp;
	u32		max_srq_wqes;
	u32		bf_reg_size;
	u32		bf_regs_per_page;
	struct xsc_port_caps	port[XSC_MAX_PORTS];
	u8		ext_port_cap[XSC_MAX_PORTS];
	u32		reserved_lkey;
	u8		local_ca_ack_delay;
	u8		log_max_mcg;
	u16		max_qp_mcg;
	u32		min_page_sz;
	u32		send_ds_num;
	u32		send_wqe_shift;
	u32		recv_ds_num;
	u32		recv_wqe_shift;
	u32		rx_pkt_len_max;

	u32		msix_enable:1;
	u32		port_type:1;
	u32		embedded_cpu:1;
	u32		eswitch_manager:1;
	u32		ecpf_vport_exists:1;
	u32		vport_group_manager:1;
	u32		sf:1;
	u32		wqe_inline_mode:3;
	u32		raweth_qp_id_base:15;
	u32		rsvd0:7;

	u16		max_vfs;
	u8		log_max_qp_depth;
	u8		log_max_current_uc_list;
	u8		log_max_current_mc_list;
	u16		log_max_vlan_list;
	u8		fdb_multi_path_to_table;
	u8		log_esw_max_sched_depth;

	u8		max_num_sf_partitions;
	u8		log_max_esw_sf;
	u16		sf_base_id;

	u32		max_tc:8;
	u32		ets:1;
	u32		dcbx:1;
	u32		dscp:1;
	u32		sbcam_reg:1;
	u32		qos:1;
	u32		port_buf:1;
	u32		rsvd1:2;
	u32		raw_tpe_qp_num:16;
	u32		max_num_eqs:8;
	u32		mac_port:8;
	u32		raweth_rss_qp_id_base:16;
	u16		msix_base;
	u16		msix_num;
	u32		max_mtt;
	u8		log_max_tso;
	u32		hca_core_clock;
	u32		max_rwq_indirection_tables;/*rss_caps*/
	u32		max_rwq_indirection_table_size;/*rss_caps*/
	u16		raweth_qp_id_end;
	u32		qp_rate_limit_min;
	u32		qp_rate_limit_max;
	u32		hw_feature_flag;
	u16		pf0_vf_funcid_base;
	u16		pf0_vf_funcid_top;
	u16		pf1_vf_funcid_base;
	u16		pf1_vf_funcid_top;
	u16		pcie0_pf_funcid_base;
	u16		pcie0_pf_funcid_top;
	u16		pcie1_pf_funcid_base;
	u16		pcie1_pf_funcid_top;
	u8		nif_port_num;
	u8		pcie_host;
	u8		mac_bit;
	u16		funcid_to_logic_port;
	u16		max_cmd_in_len;
	u16		max_cmd_out_len;
	u64		max_mr_size;
	u8		lag_logic_port_ofst;
	u32		mpt_tbl_addr;
	u32		mpt_tbl_depth;
	u32		mpt_tbl_width;
	u32		mtt_inst_base_addr;
	u32		mtt_inst_stride;
	u32		mtt_inst_num_log;
	u32		mtt_inst_depth;
};

struct cache_ent {
	/* protect block chain allocations
	 */
	spinlock_t		lock;
	struct list_head	head;
};

struct cmd_msg_cache {
	struct cache_ent	large;
	struct cache_ent	med;

};

#define CMD_FIRST_SIZE 8
struct xsc_cmd_first {
	__be32		data[CMD_FIRST_SIZE];
};

struct xsc_cmd_mailbox {
	void			*buf;
	dma_addr_t		dma;
	struct xsc_cmd_mailbox *next;
};

struct xsc_cmd_msg {
	struct list_head	list;
	struct cache_ent	*cache;
	u32			len;
	struct xsc_cmd_first	first;
	struct xsc_cmd_mailbox	*next;
};

#define RSP_FIRST_SIZE 14
struct xsc_rsp_first {
	__be32		data[RSP_FIRST_SIZE]; //can be larger, xsc_rsp_layout
};

struct xsc_rsp_msg {
	struct list_head		list;
	struct cache_ent	       *cache;
	u32				len;
	struct xsc_rsp_first		first;
	struct xsc_cmd_mailbox	    *next;
};

typedef void (*xsc_cmd_cbk_t)(int status, void *context);

//hw will use this for some records(e.g. vf_id)
struct cmdq_rsv {
	u16 vf_id;
	u8 rsv[2];
};

//related with hw, won't change
#define CMDQ_ENTRY_SIZE 64

struct xsc_cmd_layout {
	struct cmdq_rsv rsv0;
	__be32		inlen;
	__be64		in_ptr;
	__be32		in[CMD_FIRST_SIZE];
	__be64		out_ptr;
	__be32		outlen;
	u8		token;
	u8		sig;
	u8		idx;
	u8		type: 7;
	u8      owner_bit: 1; //rsv for hw, arm will check this bit to make sure mem written
};

struct xsc_rsp_layout {
	struct cmdq_rsv rsv0;
	__be32		out[RSP_FIRST_SIZE];
	u8		token;
	u8		sig;
	u8		idx;
	u8		type: 7;
	u8      owner_bit: 1; //rsv for hw, driver will check this bit to make sure mem written
};

struct xsc_cmd_work_ent {
	struct xsc_cmd_msg    *in;
	struct xsc_rsp_msg    *out;
	int idx;
	struct completion	done;
	struct xsc_cmd        *cmd;
	struct work_struct	work;
	struct xsc_cmd_layout *lay;
	struct xsc_rsp_layout *rsp_lay;
	int			ret;
	u8			status;
	u8			token;
	struct timespec64       ts1;
	struct timespec64       ts2;
};

struct xsc_cmd_debug {
	struct dentry	       *dbg_root;
	struct dentry	       *dbg_in;
	struct dentry	       *dbg_out;
	struct dentry	       *dbg_outlen;
	struct dentry	       *dbg_status;
	struct dentry	       *dbg_run;
	void		       *in_msg;
	void		       *out_msg;
	u8			status;
	u16			inlen;
	u16			outlen;
};

struct xsc_cmd_stats {
	u64		sum;
	u64		n;
	struct dentry  *root;
	struct dentry  *avg;
	struct dentry  *count;
	/* protect command average calculations */
	spinlock_t	lock;
};

enum xsc_cmd_status {
	XSC_CMD_STATUS_NORMAL,
	XSC_CMD_STATUS_TIMEDOUT,
};

#define	XSC_CMD_MAX_RETRY_CNT	3

struct xsc_cmd {
	void	       *cmd_buf;
	void	       *cq_buf;
	dma_addr_t	dma;
	dma_addr_t	cq_dma;
	u16     cmd_pid;
	u16     cq_cid;
	u8      owner_bit;
	u8		cmdif_rev;
	u8		log_sz;
	u8		log_stride;
	int		max_reg_cmds;
	int		events;
	u32 __iomem    *vector;

	spinlock_t	alloc_lock;	/* protect command queue allocations */
	spinlock_t	token_lock;	/* protect token allocations */
	spinlock_t	doorbell_lock;	/* protect cmdq req pid doorbell */
	u8		token;
	unsigned long	bitmask;
	char		wq_name[XSC_CMD_WQ_MAX_NAME];
	struct workqueue_struct *wq;
	struct task_struct *cq_task;
	struct semaphore sem;
	int	mode;
	struct xsc_cmd_work_ent *ent_arr[XSC_MAX_COMMANDS];
	struct pci_pool *pool;
	struct xsc_cmd_debug dbg;
	struct cmd_msg_cache cache;
	int checksum_disabled;
	struct xsc_cmd_stats stats[XSC_CMD_OP_MAX];
	unsigned int	irqn;
	u8	ownerbit_learned;
	u8	cmd_status;
	u8	retry_cnt;
};

struct xsc_reg_addr {
	u64	tx_db;
	u64	rx_db;
	u64	complete_db;
	u64	complete_reg;
	u64	event_db;
	u64	cpm_get_lock;
	u64	cpm_put_lock;
	u64	cpm_lock_avail;
	u64	cpm_data_mem;
	u64	cpm_cmd;
	u64	cpm_addr;
	u64	cpm_busy;
};

struct xsc_board_info {
	u32			ref_cnt;
	u32			board_id;
	char			board_sn[XSC_BOARD_SN_LEN];
	__be64			guid;
	u32			resource_access_mode;
	rwlock_t		mr_sync_lock;	/* protect mr sync */
	struct list_head	func_list;
	u32			rep_func_id;
};

/* our core device */
struct xsc_core_device {
	struct pci_dev	*pdev;
	struct device	*device;
	struct xsc_priv	priv;
	struct xsc_dev_resource *dev_res;
	void			*xsc_ib_dev;
	void			*netdev;
	void			*eth_priv;
	void			*ovs_priv;
	void __iomem		*bar;
	int			bar_num;

	u8			mac_port;	/* mac port */
	u8			pcie_no;	/* pcie number */
	u8			pf_id;
	u8			pcie_host_num;
	u8			pf_num_per_pcie;
	u16			vf_id;
	u16			glb_func_id;	/* function id */

	u16			gsi_qpn;	/* logic qpn for gsi*/
	u16			msix_vec_base;

	struct mutex		pci_status_mutex;	/* protect pci_status */
	enum xsc_pci_status	pci_status;
	struct mutex		intf_state_mutex;	/* protect intf_state */
	unsigned long		intf_state;
	enum xsc_coredev_type	coredev_type;
	struct xsc_caps		caps;
	atomic_t		num_qps;
	struct xsc_cmd		cmd;
	spinlock_t		reg_access_lock;	/* reg access lock */

	void			*counters_priv;
	struct xsc_board_info	*board_info;
	void (*event)(struct xsc_core_device *dev,
		      enum xsc_dev_event event, unsigned long param);

	void (*link_event_handler)(void *adapter);
	struct work_struct	event_work;

	u32			chip_ver_h;
	u32			chip_ver_m;
	u32			chip_ver_l;
	u32			hotfix_num;
	u32			feature_flag;
	u16			cmdq_ver;
	u8			fw_version_major;
	u8			fw_version_minor;
	u16			fw_version_patch;
	u32			fw_version_tweak;
	u8			fw_version_extra_flag;
	cpumask_var_t		xps_cpumask;

	u8	reg_mr_via_cmdq;
	u8	user_mode;
	u8	read_flush;

	struct xsc_port_ctrl port_ctrl;
	struct xsc_port_ctrl prgrmmbl_cc_ctrl;

	void	*rtt_priv;
	void	*ap_priv;
	void	*pcie_lat;

	void	*hal;
	u8	bond_id;
	struct list_head slave_node;
	struct	completion	recv_tunnel_resp_event;
	void	(*get_ifname)(void *xdev, u8 *ifname, int len);
	void	(*get_ibdev_name)(void *xdev, u8 *ibdev_name, int len);
	void	(*get_ip_addr)(void *xdev, u32 *ip_addr);
	int	(*get_rdma_ctrl_info)(struct xsc_core_device *xdev,
				      u16 opcode, void *out, int out_size);
	void	(*handle_netlink_cmd)(struct xsc_core_device *xdev, void *in, void *out);
	void	*sock;
	struct list_head func_node;
};

struct xsc_feature_flag {
	u8	fpga_type:2;
	u8	hps_ddr:2;
	u8	onchip_ft:1;
	u8	rdma_icrc:1;
	u8	ma_xbar:1;
	u8	anlt_fec:1;
	u8	pp_tbl_dma:1;
	u8	pct_exp:1;
};

struct xsc_interface {
	struct list_head list;
	int protocol;

	void *(*add)(struct xsc_core_device *dev);
	void (*remove)(struct xsc_core_device *dev, void *context);
	int (*attach)(struct xsc_core_device *dev, void *context);
	void (*detach)(struct xsc_core_device *dev, void *context);
	void (*event)(struct xsc_core_device *dev, void *context,
		      enum xsc_dev_event event, unsigned long param);
	void *(*get_dev)(void *context);
};

struct xsc_device_context {
	struct list_head list;
	struct xsc_interface *intf;
	void *context;
	unsigned long state;
};

struct xsc_mem_entry {
	struct list_head list;
	char task_name[TASK_COMM_LEN];
	struct xsc_ioctl_mem_info mem_info;
};

struct xsc_device_product_info {
	u16 vendor;
	u16 device;
	u16 subdevice;
	char product_name[XSC_MAX_PRODUCT_NAME_LEN];
};

#define XSC_DEVICE_PRODUCT_INFO(vend, dev, subdev, name) \
	.vendor = (vend), .device = (dev), \
	.subdevice = (subdev), .product_name = (name)

#define kcalloc_node(n, size, flags, node) kmalloc_node((n) * (size), (flags) | __GFP_ZERO, (node))

static inline bool xsc_fw_is_available(struct xsc_core_device *dev)
{
	return dev->cmd.cmd_status == XSC_CMD_STATUS_NORMAL;
}

int xsc_debugfs_init(struct xsc_core_device *dev);
void xsc_debugfs_fini(struct xsc_core_device *dev);
void xsc_register_debugfs(void);
void xsc_unregister_debugfs(void);

bool xsc_device_registered(struct xsc_core_device *dev);
int xsc_register_device(struct xsc_core_device *dev);
void xsc_unregister_device(struct xsc_core_device *dev);
void xsc_attach_device(struct xsc_core_device *dev);
void xsc_detach_device(struct xsc_core_device *dev);
int xsc_register_interface(struct xsc_interface *intf);
void xsc_unregister_interface(struct xsc_interface *intf);
void xsc_reload_interface(struct xsc_core_device *dev, int protocol);
void xsc_reload_interfaces(struct xsc_core_device *dev,
			   int protocol1, int protocol2,
			   bool valid1, bool valid2);

void xsc_remove_dev_by_protocol(struct xsc_core_device *dev, int protocol);
void xsc_add_dev_by_protocol(struct xsc_core_device *dev, int protocol);
void xsc_dev_list_lock(void);
void xsc_dev_list_unlock(void);
int xsc_dev_list_trylock(void);
void xsc_get_devinfo(u8 *data, u32 len);

int xsc_cmd_write_reg_directly(struct xsc_core_device *dev, void *in, int in_size, void *out,
			       int out_size, int func_id);
int xsc_cmd_exec(struct xsc_core_device *dev, void *in, int in_size,
		 void *out, int out_size);
int xsc_create_mkey(struct xsc_core_device *xdev, void *in, void *out);
int xsc_destroy_mkey(struct xsc_core_device *xdev, void *in, void *out);
int xsc_reg_mr(struct xsc_core_device *dev, void *in, void *out);
int xsc_dereg_mr(struct xsc_core_device *dev, void *in, void *out);
int xsc_eth_reset(struct xsc_core_device *dev);
int xsc_tbm_init(struct xsc_core_device *dev);
int xsc_qos_init(struct xsc_core_device *xdev);

bool xsc_chk_chip_ver(struct xsc_core_device *dev);

int xsc_alloc_iae_idx(struct xsc_core_device *dev, int *iae_idx);
void xsc_release_iae_idx(struct xsc_core_device *dev, int *iae_idx);
int xsc_get_iae_idx(struct xsc_core_device *dev);

int xsc_create_res(struct xsc_core_device *dev);
void xsc_destroy_res(struct xsc_core_device *dev);

int xsc_counters_init(struct ib_device *ib_dev,
		      struct xsc_core_device *dev);
void xsc_counters_fini(struct ib_device *ib_dev,
		       struct xsc_core_device *dev);

int xsc_eth_sysfs_create(struct net_device *netdev, struct xsc_core_device *dev);
void xsc_eth_sysfs_remove(struct net_device *netdev, struct xsc_core_device *dev);
int xsc_rtt_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev);
void xsc_rtt_sysfs_fini(struct xsc_core_device *xdev);

void xsc_ib_sysfs_init(struct ib_device *ib_dev, struct xsc_core_device *xdev);
void xsc_ib_sysfs_fini(struct ib_device *ib_dev, struct xsc_core_device *xdev);

int xsc_cmd_query_hca_cap(struct xsc_core_device *dev,
			  struct xsc_caps *caps);
int xsc_cmd_enable_hca(struct xsc_core_device *dev, u16 vf_num, u16 max_msix);
int xsc_cmd_disable_hca(struct xsc_core_device *dev, u16 vf_num);
int xsc_cmd_modify_hca(struct xsc_core_device *dev);
void xsc_free_board_info(void);

int xsc_irq_eq_create(struct xsc_core_device *dev);
int xsc_irq_eq_destroy(struct xsc_core_device *dev);

int xsc_sriov_init(struct xsc_core_device *dev);
void xsc_sriov_cleanup(struct xsc_core_device *dev);
int xsc_sriov_attach(struct xsc_core_device *dev);
void xsc_sriov_detach(struct xsc_core_device *dev);
int xsc_core_sriov_configure(struct pci_dev *dev, int num_vfs);
int xsc_sriov_sysfs_init(struct xsc_core_device *dev);
void xsc_sriov_sysfs_cleanup(struct xsc_core_device *dev);
int xsc_create_vfs_sysfs(struct xsc_core_device *dev, int num_vfs);
void xsc_destroy_vfs_sysfs(struct xsc_core_device *dev, int num_vfs);
int xsc_create_vf_group_sysfs(struct xsc_core_device *dev,
			      u32 group_id, struct kobject *group_kobj);
void xsc_destroy_vf_group_sysfs(struct xsc_core_device *dev,
				struct kobject *group_kobj);
u32 xsc_eth_pcie_read32_by_mac_port(struct xsc_core_device *xdev, u32 mac_port,
				    u32 eth_ip_inter_addr);
void xsc_eth_pcie_write32_by_mac_port(struct xsc_core_device *xdev, u32 mac_port,
				      u32 eth_ip_inter_addr, u32 val);
struct cpumask *xsc_comp_irq_get_affinity_mask(struct xsc_core_device *dev, int vector);
void mask_cpu_by_node(int node, struct cpumask *dstp);
int xsc_get_link_speed(struct xsc_core_device *dev);
int xsc_chip_type(struct xsc_core_device *dev);

#define XSC_ESWITCH_MANAGER(dev) ((dev)->caps.eswitch_manager)

static inline bool xsc_sriov_is_enabled(struct xsc_core_device *dev)
{
	return pci_num_vf(dev->pdev) ? true : false;
}

static inline u16 xsc_core_max_vfs(const struct xsc_core_device *dev)
{
	return dev->priv.sriov.max_vfs;
}

static inline int xsc_core_vfs_num(const struct xsc_core_device *dev)
{
	return dev->priv.sriov.num_vfs;
}

static inline bool xsc_core_is_pf(const struct xsc_core_device *dev)
{
	return dev->coredev_type == XSC_COREDEV_PF;
}

static inline bool xsc_core_is_sf(const struct xsc_core_device *dev)
{
	return dev->coredev_type == XSC_COREDEV_SF;
}

static inline bool xsc_core_is_ecpf(struct xsc_core_device *dev)
{
	return dev->caps.embedded_cpu;
}

#define XSC_ESWITCH_MANAGER(dev) ((dev)->caps.eswitch_manager)
#define ESW_ALLOWED(esw) ((esw) && XSC_ESWITCH_MANAGER((esw)->dev))

static inline bool
xsc_core_is_ecpf_esw_manager(const struct xsc_core_device *dev)
{
	return dev->caps.embedded_cpu && dev->caps.eswitch_manager;
}

static inline bool
xsc_ecpf_vport_exists(const struct xsc_core_device *dev)
{
	return xsc_core_is_pf(dev) && dev->caps.ecpf_vport_exists;
}

static inline bool
xsc_core_is_vport_manager(const struct xsc_core_device *dev)
{
	return dev->caps.vport_group_manager && xsc_core_is_pf(dev);
}

static inline bool xsc_rl_is_supported(struct xsc_core_device *dev)
{
	return false;
}

static inline unsigned long bdf_to_key(unsigned int domain, unsigned int bus, unsigned int devfn)
{
	return ((unsigned long)domain << 32) | ((bus & 0xff) << 16) | (devfn & 0xff);
}

static inline void
funcid_to_pf_vf_index(struct xsc_caps *caps, u16 func_id, u8 *pf_no, u8 *pf_id, u16 *vf_id)
{
	if (func_id >= caps->pf0_vf_funcid_base && func_id <= caps->pf0_vf_funcid_top) {
		*pf_id = 0;
		*pf_no = caps->pcie_host;
		*vf_id = func_id - caps->pf0_vf_funcid_base;
	} else if (func_id >= caps->pf1_vf_funcid_base && func_id <= caps->pf1_vf_funcid_top) {
		*pf_id = 1;
		*pf_no = caps->pcie_host;
		*vf_id = func_id - caps->pf1_vf_funcid_base;
	} else if (func_id >= caps->pcie0_pf_funcid_base && func_id <= caps->pcie0_pf_funcid_top) {
		*pf_id = func_id - caps->pcie0_pf_funcid_base;
		*pf_no = 0;
		*vf_id = -1;
	} else {
		*pf_id = func_id - caps->pcie1_pf_funcid_base;
		*pf_no = 1;
		*vf_id = -1;
	}
}

static inline bool
is_support_rdma(struct xsc_core_device *dev)
{
	if (!dev)
		return false;

	if (dev->caps.hw_feature_flag & XSC_HW_RDMA_SUPPORT)
		return true;

	return false;
}

static inline bool is_support_rdma_cm(struct xsc_core_device *dev)
{
	return dev->caps.hw_feature_flag & XSC_HW_RDMA_CM_SUPPORT;
}

static inline bool
is_support_pfc_prio_statistic(struct xsc_core_device *dev)
{
	if (!dev)
		return false;

	if (dev->caps.hw_feature_flag & XSC_HW_PFC_PRIO_STATISTIC_SUPPORT)
		return true;

	return false;
}

static inline bool is_dpu_soc_pf(u32 device_id)
{
	return device_id == XSC_MV_SOC_PF_DEV_ID;
}

static inline bool is_dpu_host_pf(u32 device_id)
{
	return device_id == XSC_MV_HOST_PF_DEV_ID;
}

static inline bool is_host_pf(struct xsc_core_device *xdev)
{
	return xsc_core_is_pf(xdev) && !is_dpu_soc_pf(xdev->pdev->device);
}

static inline bool
is_support_pfc_stall_stats(struct xsc_core_device *dev)
{
	if (!dev)
		return false;

	if (dev->caps.hw_feature_flag & XSC_HW_PFC_STALL_STATS_SUPPORT)
		return true;

	return false;
}

static inline bool is_support_hw_pf_stats(struct xsc_core_device *dev)
{
	return xsc_core_is_pf(dev);
}

static inline bool
is_support_pf_uc_statistic(struct xsc_core_device *dev)
{
	if (!dev)
		return false;

	if (dev->caps.hw_feature_flag & XSC_HW_PF_UC_STATISTIC_SUPPORT)
		return true;

	return false;
}

static inline void xsc_set_user_mode(struct xsc_core_device *dev, u8 mode)
{
	dev->user_mode = mode;
}

static inline bool xsc_support_hw_feature(struct xsc_core_device *dev, u32 feature)
{
	return dev->caps.hw_feature_flag & feature;
}

static inline u8 xsc_get_user_mode(struct xsc_core_device *dev)
{
	return dev->user_mode;
}

#define XSC_ORIGIN_PF_BAR_SIZE	(256 * 1024 * 1024)
static inline bool is_pf_bar_compressed(struct xsc_core_device *dev)
{
	return pci_resource_len(dev->pdev, 0) != XSC_ORIGIN_PF_BAR_SIZE;
}

void xsc_pci_exit(void);

void xsc_remove_eth_driver(void);
void xsc_remove_rdma_driver(void);

void xsc_init_hal(struct xsc_core_device *xdev, u32 device_id);
void xsc_set_pf_db_addr(struct xsc_core_device *xdev,
			u64 tx_db, u64 rx_db, u64 cq_db, u64 cq_reg, u64 eq_db);
void xsc_get_db_addr(struct xsc_core_device *xdev,
		     u64 *tx_db, u64 *rx_db, u64 *cq_db, u64 *cq_reg, u64 *eq_db);
void xsc_read_reg(struct xsc_core_device *xdev, u32 addr, void *data, int len);
void xsc_write_reg(struct xsc_core_device *xdev, u32 addr, void *data);
void xsc_ia_read(struct xsc_core_device *xdev, u32 addr, void *data, int nr);
void xsc_ia_write(struct xsc_core_device *xdev, u32 addr, void *data, int nr);
void xsc_update_tx_db(struct xsc_core_device *xdev, u32 sqn, u32 next_pid);
void xsc_update_rx_db(struct xsc_core_device *xdev, u32 rqn, u32 next_pid);

void xsc_arm_cq(struct xsc_core_device *xdev, u32 cqn, u32 next_cid, u8 solicited);
void xsc_update_cq_ci(struct xsc_core_device *xdev, u32 cqn, u32 next_cid);
void xsc_update_eq_ci(struct xsc_core_device *xdev, u32 eqn, u32 next_cid, u8 arm);

void xsc_update_cmdq_req_pid(struct xsc_core_device *xdev, u32 req_pid);
void xsc_update_cmdq_req_cid(struct xsc_core_device *xdev, u32 req_cid);
void xsc_update_cmdq_rsp_pid(struct xsc_core_device *xdev, u32 rsp_pid);
void xsc_update_cmdq_rsp_cid(struct xsc_core_device *xdev, u32 rsp_cid);
u32 xsc_get_cmdq_req_pid(struct xsc_core_device *xdev);
u32 xsc_get_cmdq_req_cid(struct xsc_core_device *xdev);
u32 xsc_get_cmdq_rsp_pid(struct xsc_core_device *xdev);
u32 xsc_get_cmdq_rsp_cid(struct xsc_core_device *xdev);
u32 xsc_get_cmdq_log_stride(struct xsc_core_device *xdev);
void xsc_set_cmdq_depth(struct xsc_core_device *xdev, u32 depth);
void xsc_set_cmdq_req_buf_addr(struct xsc_core_device *xdev, u32 haddr, u32 laddr);
void xsc_set_cmdq_rsp_buf_addr(struct xsc_core_device *xdev, u32 haddr, u32 laddr);
void xsc_set_cmdq_msix_vector(struct xsc_core_device *xdev, u32 vector);
void xsc_check_cmdq_status(struct xsc_core_device *xdev);
int xsc_handle_cmdq_interrupt(struct xsc_core_device *xdev);
u8 xsc_get_mr_page_mode(struct xsc_core_device *xdev, u8 page_shift);
u32 xsc_mkey_to_idx(struct xsc_core_device *xdev, u32 mkey);
u32 xsc_idx_to_mkey(struct xsc_core_device *xdev, u32 mkey_idx);
void xsc_set_mpt(struct xsc_core_device *xdev, int iae_idx, u32 mtt_base, void *mr_request);
void xsc_clear_mpt(struct xsc_core_device *xdev, int iae_idx, u32 mtt_base, void *mr_request);
void xsc_set_mtt(struct xsc_core_device *xdev, int iae_idx, u32 mtt_base, void *mr_request);
void xsc_set_read_done_msix_vector(struct xsc_core_device *xdev, u32 vector);
int xsc_dma_write_tbl_once(struct xsc_core_device *xdev, u32 data_len, u64 dma_wr_addr,
			   u32 host_id, u32 func_id, u64 success[2], u32 size);
void xsc_dma_read_tbl(struct xsc_core_device *xdev, u32 host_id, u32 func_id, u64 data_addr,
		      u32 tbl_id, u32 burst_num, u32 tbl_start_addr);
bool xsc_skb_need_linearize(struct xsc_core_device *xdev, int ds_num);
bool xsc_is_err_cqe(struct xsc_core_device *xdev, void *cqe);
u8 xsc_get_cqe_error_code(struct xsc_core_device *xdev, void *cqe);
u8 xsc_get_cqe_opcode(struct xsc_core_device *xdev, void *cqe);
u16 xsc_get_eth_channel_num(struct xsc_core_device *xdev);
u32 xsc_get_max_mtt_num(struct xsc_core_device *xdev);
u32 xsc_get_max_mpt_num(struct xsc_core_device *xdev);
u32 xsc_get_rdma_stat_mask(struct xsc_core_device *xdev);
u32 xsc_get_eth_stat_mask(struct xsc_core_device *xdev);
void xsc_set_data_seg(struct xsc_core_device *xdev, void *data_seg, u64 addr, u32 key, u32 length);
u8 xsc_get_mad_msg_opcode(struct xsc_core_device *xdev);
u32 xsc_get_max_qp_depth(struct xsc_core_device *xdev);
bool xsc_check_max_qp_depth(struct xsc_core_device *xdev, u32 *wqe_cnt, u32 max_qp_depth);
void xsc_set_mtt_info(struct xsc_core_device *xdev);

void xsc_set_exit_flag(void);
bool xsc_get_exit_flag(void);
bool exist_incomplete_qp_flush(void);
int xsc_cmd_query_read_flush(struct xsc_core_device *dev);

int xsc_register_devinfo(struct xsc_core_device *xdev, char *ifname, char *ibdev_name);
void xsc_register_get_mdev_info_func(int (*get_mdev_info)(void *data));

typedef void (*get_ibdev_name_func_t)(struct net_device *netdev, char *ibdev_name, int len);
void xsc_register_get_mdev_ibdev_name_func(get_ibdev_name_func_t fn);

#endif /* XSC_CORE_H */

