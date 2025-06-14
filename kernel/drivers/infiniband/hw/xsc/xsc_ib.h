/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_IB_H
#define XSC_IB_H

#include <linux/kernel.h>
#include <linux/sched.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_mad.h>
#include "common/xsc_core.h"
#include "common/driver.h"
#include "common/cq.h"
#include "common/qp.h"
#include <linux/types.h>
#include <linux/iommu.h>
#include <linux/dma-direct.h>
#include <linux/dma-mapping.h>
#include <crypto/hash.h>
#include <rdma/uverbs_ioctl.h>

#include "xsc_ib_compat.h"

#define xsc_ib_dbg(dev, format, arg...)						\
do {										\
	if (xsc_log_level <= XSC_LOG_LEVEL_DBG)					\
		pr_debug("%s:%s:%d:(pid %d): " format, (dev)->ib_dev.name,	\
			__func__, __LINE__, current->pid, ##arg);		\
} while (0)

#define xsc_ib_err(dev, format, arg...)						\
do {										\
	if (xsc_log_level <= XSC_LOG_LEVEL_ERR)					\
		pr_err("%s:%s:%d:(pid %d): " format, (dev)->ib_dev.name,	\
			__func__, __LINE__, current->pid, ##arg);		\
} while (0)

#define xsc_ib_warn(dev, format, arg...)					\
do {										\
	if (xsc_log_level <= XSC_LOG_LEVEL_WARN)				\
		pr_warn("%s:%s:%d:(pid %d): " format, (dev)->ib_dev.name,	\
			__func__, __LINE__, current->pid, ##arg);		\
} while (0)

#define xsc_ib_info(dev, format, arg...)					\
do {										\
	if (xsc_log_level <= XSC_LOG_LEVEL_INFO)				\
		pr_warn("%s:%s:%d:(pid %d): " format, (dev)->ib_dev.name,	\
			__func__, __LINE__, current->pid, ##arg);		\
} while (0)

struct xsc_ib_ucontext {
	struct ib_ucontext	ibucontext;
	struct list_head	db_page_list;

	/* protect doorbell record alloc/free
	 */
	struct mutex		db_page_mutex;
};

#define field_avail(type, fld, sz) (offsetof(type, fld) +		\
		sizeof(((type *)0)->fld) <= (sz))

#define	XSC_PAGE_SHIFT_4K	12
#define	XSC_PAGE_SHIFT_64K	16
#define	XSC_PAGE_SHIFT_2M	21
#define	XSC_PAGE_SHIFT_1G	30
#define XSC_PAGE_SZ_4K		BIT(XSC_PAGE_SHIFT_4K)
#define XSC_PAGE_SZ_64K		BIT(XSC_PAGE_SHIFT_64K)
#define XSC_PAGE_SZ_2M		BIT(XSC_PAGE_SHIFT_2M)
#define XSC_PAGE_SZ_1G		BIT(XSC_PAGE_SHIFT_1G)
#define XSC_MR_PAGE_CAP_MASK	(XSC_PAGE_SZ_4K |	\
				XSC_PAGE_SZ_64K |	\
				XSC_PAGE_SZ_2M |	\
				XSC_PAGE_SZ_1G)

static inline struct xsc_ib_ucontext *to_xucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct xsc_ib_ucontext, ibucontext);
}

struct xsc_ib_pd {
	struct ib_pd		ibpd;
	u32			pdn;
	u32			pa_lkey;
};

/* Use macros here so that don't have to duplicate
 * enum ib_send_flags and enum ib_qp_type for low-level driver
 */

#define XSC_IB_QPT_REG_UMR	IB_QPT_RESERVED1

struct wr_list {
	u16	opcode;
	u16	next;
};

struct xsc_ib_wq {
	u64		       *wrid;
	u32		       *wr_data;
	struct wr_list	       *w_list;
	unsigned long	       *wqe_head;
	u16		       unsig_count;

	/* serialize post to the work queue
	 */
	spinlock_t		lock;
	int			wqe_cnt;
	int			ds_cnt;
	int			max_post;
	int			max_gs;
	int			offset;
	int			wqe_shift;
	unsigned int		head;
	unsigned int		tail;
	u16			cur_post;
	u16			last_poll;
	void		       *qend;
	void		*hdr_buf;
	u32			hdr_size;
	dma_addr_t	hdr_dma;
	int			mad_queue_depth;
	int			mad_index;
	u32			*wr_opcode;
	u32			*need_flush;
	atomic_t	flush_wqe_cnt;
};

enum {
	XSC_QP_USER,
	XSC_QP_KERNEL,
	XSC_QP_EMPTY
};

struct xsc_ib_qp {
	struct ib_qp		ibqp;
	struct xsc_core_qp	xqp;
	struct xsc_buf		buf;

	struct xsc_db		db;
	struct xsc_ib_wq	rq;

	u32			doorbell_qpn;
	u8			sq_signal_bits;
	u8			fm_cache;
	int			sq_max_wqes_per_wr;
	int			sq_spare_wqes;
	struct xsc_ib_wq	sq;

	struct ib_umem	       *umem;
	int			buf_size;

	/* serialize qp state modifications
	 */
	struct mutex		mutex;
	u16			xrcdn;
	u32			flags;
	u8			port;
	u8			alt_port;
	u8			atomic_rd_en;
	u8			resp_depth;
	u8			state;
	int			xsc_type;
	int			wq_sig;
	int			scat_cqe;
	int			max_inline_data;
	int			has_rq;

	int			create_type;
	u32			pa_lkey;
	/* For QP1 */
	struct ib_ud_header	qp1_hdr;
	u32			send_psn;
	struct xsc_qp_context	ctx;
	struct ib_cq		*send_cq;
	struct ib_cq		*recv_cq;
	/* For qp resources */
	spinlock_t		lock;
};

struct xsc_ib_cq_buf {
	struct xsc_buf		buf;
	struct ib_umem		*umem;
	int			cqe_size;
};

enum xsc_ib_qp_flags {
	XSC_IB_QP_BLOCK_MULTICAST_LOOPBACK     = 1 << 0,
	XSC_IB_QP_SIGNATURE_HANDLING           = 1 << 1,
};

struct xsc_shared_mr_info {
	int mr_id;
	struct ib_umem		*umem;
};

struct xsc_ib_cq {
	struct ib_cq		ibcq;
	struct xsc_core_cq	xcq;
	struct xsc_ib_cq_buf	buf;
	struct xsc_db		db;

	/* serialize access to the CQ
	 */
	spinlock_t		lock;

	/* protect resize cq
	 */
	struct mutex		resize_mutex;
	struct xsc_ib_cq_resize *resize_buf;
	struct ib_umem	       *resize_umem;
	int			cqe_size;
	struct list_head	err_state_qp_list;
};

struct xsc_ib_xrcd {
	struct ib_xrcd		ibxrcd;
	u32			xrcdn;
};

struct xsc_ib_peer_id;

struct xsc_ib_mr {
	struct ib_mr		ibmr;
	struct xsc_core_mr	mmr;
	struct ib_umem	       *umem;
	struct xsc_shared_mr_info	*smr_info;
	struct list_head	list;
	int			order;
	__be64			*pas;
	dma_addr_t		dma;
	int			npages;
	struct completion	done;
	enum ib_wc_status	status;
	struct xsc_ib_peer_id	*peer_id;
	atomic_t		invalidated;
	struct completion	invalidation_comp;
};

struct xsc_ib_peer_id {
	struct completion comp;
	struct xsc_ib_mr *mr;
};

struct xsc_cache_ent {
	struct list_head	head;
	/* sync access to the cahce entry
	 */
	spinlock_t		lock;

	struct dentry	       *dir;
	char                    name[4];
	u32                     order;
	u32			size;
	u32                     cur;
	u32                     miss;
	u32			limit;

	struct dentry          *fsize;
	struct dentry          *fcur;
	struct dentry          *fmiss;
	struct dentry          *flimit;

	struct xsc_ib_dev     *dev;
	struct work_struct	work;
	struct delayed_work	dwork;
};

struct xsc_mr_cache {
	struct workqueue_struct *wq;
	struct xsc_cache_ent	ent[MAX_MR_CACHE_ENTRIES];
	int			stopped;
	struct dentry		*root;
	unsigned long		last_add;
};

struct xsc_gid {
	u8 data[16];
};

struct xsc_sgid_tbl {
	struct xsc_gid *tbl;
	u32 max;
	u32 count;
};

struct xsc_ib_res {
	struct xsc_sgid_tbl sgid_tbl;
};

struct xsc_ib_resources {
	struct ib_cq	*c0;
	struct ib_xrcd	*x0;
	struct ib_xrcd	*x1;
	struct ib_pd	*p0;
	struct ib_srq	*s0;
};

struct xsc_ib_dev {
	struct ib_device		ib_dev;
	struct uverbs_object_tree_def *driver_trees[6];
	struct net_device	*netdev;
	struct xsc_core_device *xdev;
	struct list_head		eqs_list;
	int				num_ports;
	int				num_comp_vectors;
	/* serialize update of capability mask
	 */
	struct mutex			cap_mask_mutex;
	u8				ib_active;
	/* sync used page count stats
	 */
	spinlock_t			mr_lock;
	struct xsc_ib_res		ib_res;
	struct xsc_ib_resources	devr;
	struct xsc_mr_cache		cache;
	u32				crc_32_table[256];
	int cm_pcp;
	int cm_dscp;
	int force_pcp;
	int force_dscp;
	int iommu_state;
	struct notifier_block nb;
};

union xsc_ib_fw_ver {
	u64 data;
	struct {
		u8	ver_major;
		u8	ver_minor;
		u16	ver_patch;
		u32	ver_tweak;
	} s;
};

struct xsc_pa_chunk {
	struct list_head list;
	u64 va;
	dma_addr_t pa;
	size_t length;
};

struct xsc_err_state_qp_node {
	struct list_head	entry;
	u32					qp_id;
	bool				is_sq;
};

static inline struct xsc_ib_cq *to_xibcq(struct xsc_core_cq *xcq)
{
	return container_of(xcq, struct xsc_ib_cq, xcq);
}

static inline struct xsc_ib_xrcd *to_mxrcd(struct ib_xrcd *ibxrcd)
{
	return container_of(ibxrcd, struct xsc_ib_xrcd, ibxrcd);
}

static inline struct xsc_ib_dev *to_mdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct xsc_ib_dev, ib_dev);
}

static inline struct xsc_ib_cq *to_xcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct xsc_ib_cq, ibcq);
}

static inline struct xsc_ib_qp *to_xibqp(struct xsc_core_qp *xqp)
{
	return container_of(xqp, struct xsc_ib_qp, xqp);
}

static inline struct xsc_ib_pd *to_mpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct xsc_ib_pd, ibpd);
}

static inline struct xsc_ib_qp *to_xqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct xsc_ib_qp, ibqp);
}

static inline struct xsc_ib_mr *to_mmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct xsc_ib_mr, ibmr);
}

struct xsc_ib_ah {
	struct ib_ah		ibah;
	struct xsc_av		av;
};

static inline struct xsc_ib_ah *to_mah(struct ib_ah *ibah)
{
	return container_of(ibah, struct xsc_ib_ah, ibah);
}

static inline struct xsc_ib_dev *xdev2ibdev(struct xsc_core_device *xdev)
{
	return container_of((void *)xdev, struct xsc_ib_dev, xdev);
}

int xsc_ib_query_port(struct ib_device *ibdev, u8 port,
		      struct ib_port_attr *props);

struct ib_qp *xsc_ib_create_qp(struct ib_pd *pd,
			       struct ib_qp_init_attr *init_attr,
			       struct ib_udata *udata);

void __xsc_ib_cq_clean(struct xsc_ib_cq *cq, u32 qpn);
void xsc_ib_cq_clean(struct xsc_ib_cq *cq, u32 qpn);

int xsc_ib_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr);
int xsc_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		     int attr_mask, struct ib_udata *udata);
int xsc_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		    struct ib_qp_init_attr *qp_init_attr);

int xsc_ib_post_send(struct ib_qp *ibqp, const struct ib_send_wr *wr,
		     const struct ib_send_wr **bad_wr);
int xsc_ib_post_recv(struct ib_qp *ibqp, const struct ib_recv_wr *wr,
		     const struct ib_recv_wr **bad_wr);

void *xsc_get_send_wqe(struct xsc_ib_qp *qp, int n);
int xsc_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
int xsc_ib_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
struct ib_mr *xsc_ib_get_dma_mr(struct ib_pd *pd, int acc);
struct ib_mr *xsc_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				 u64 virt_addr, int access_flags,
				 struct ib_udata *udata);
int xsc_ib_get_buf_offset(u64 addr, int page_shift, u32 *offset);
void xsc_ib_cont_pages(struct ib_umem *umem, u64 addr, int *count, int *shift,
		       int *ncont, int *order);
void xsc_ib_populate_pas(struct xsc_ib_dev *dev, struct ib_umem *umem,
			 int page_shift, __be64 *pas, int npages, bool need_to_devide);
const struct uverbs_object_tree_def *xsc_ib_get_devx_tree(void);

int xsc_ib_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
		     int sg_nents, unsigned int *sg_offset);
int xsc_wr_reg_mr(struct xsc_ib_dev *dev, const struct ib_send_wr *wr);
int xsc_wr_invalidate_mr(struct xsc_ib_dev *dev, const struct ib_send_wr *wr);
int xsc_find_best_pgsz(struct ib_umem *umem, unsigned long pgsz_bitmap,
		       unsigned long addr, int *npage, int *shift, u64 **pas);

void xsc_ib_drain_rq(struct ib_qp *qp);
void xsc_ib_drain_sq(struct ib_qp *qp);

static inline void init_query_mad(struct ib_smp *mad)
{
	mad->base_version  = 1;
	mad->mgmt_class    = IB_MGMT_CLASS_SUBN_LID_ROUTED;
	mad->class_version = 1;
	mad->method	   = IB_MGMT_METHOD_GET;
}

static inline u8 convert_access(int acc)
{
	return (acc & IB_ACCESS_REMOTE_ATOMIC ? XSC_PERM_ATOMIC       : 0) |
	       (acc & IB_ACCESS_REMOTE_WRITE  ? XSC_PERM_REMOTE_WRITE : 0) |
	       (acc & IB_ACCESS_REMOTE_READ   ? XSC_PERM_REMOTE_READ  : 0) |
	       (acc & IB_ACCESS_LOCAL_WRITE   ? XSC_PERM_LOCAL_WRITE  : 0) |
	       XSC_PERM_LOCAL_READ;
}

static inline enum ib_mtu xsc_net_to_ib_mtu(unsigned int mtu)
{
	mtu = mtu - (IB_GRH_BYTES + IB_UDP_BYTES + IB_BTH_BYTES +
		     IB_EXT_XRC_BYTES + IB_EXT_ATOMICETH_BYTES +
		     IB_ICRC_BYTES);

	if (mtu >= ib_mtu_enum_to_int(IB_MTU_4096))
		return IB_MTU_4096;
	else if (mtu >= ib_mtu_enum_to_int(IB_MTU_1024))
		return IB_MTU_1024;
	else
		return 0;
}

/**
 * UDP source port selection must adhere IANA port allocation ranges. Thus
 * we will be using IANA recommendation for Ephemeral port range of:
 * 49152-65535, or in hex: 0xC000-0xFFFF.
 */
#define IB_ROCE_UDP_ENCAP_VALID_PORT_MIN (0xC000)
#define IB_ROCE_UDP_ENCAP_VALID_PORT_MAX (0xFFFF)
#define IB_GRH_FLOWLABEL_MASK (0x000FFFFF)

/**
 * rdma_flow_label_to_udp_sport - generate a RoCE v2 UDP src port value based
 *                               on the flow_label
 *
 * This function will convert the 20 bit flow_label input to a valid RoCE v2
 * UDP src port 14 bit value. All RoCE V2 drivers should use this same
 * convention.
 */
static inline u16 xsc_flow_label_to_udp_sport(u32 fl)
{
	u32 fl_low = fl & 0x03fff, fl_high = fl & 0xFC000;

	fl_low ^= fl_high >> 14;
	return (u16)(fl_low | IB_ROCE_UDP_ENCAP_VALID_PORT_MIN);
}

#define XSC_IB_IOMMU_MAP_DISABLE 0
#define XSC_IB_IOMMU_MAP_UNKNOWN_DOMAIN 1
#define XSC_IB_IOMMU_MAP_NORMAL 2

static inline int xsc_ib_iommu_dma_map(struct ib_device *ibdev)
{
	return to_mdev(ibdev)->iommu_state;
}

static inline void *xsc_ib_iova_to_virt(struct ib_device *ibdev, dma_addr_t iova)
{
	phys_addr_t phyaddr;
	struct iommu_domain *domain;

	domain = iommu_get_domain_for_dev(ibdev->dma_device);
	if (likely(domain)) {
		phyaddr = iommu_iova_to_phys(domain, iova);
		phyaddr |= iova & (PAGE_SIZE - 1);
	} else {
		phyaddr = dma_to_phys(ibdev->dma_device, iova);
	}

	return phys_to_virt(phyaddr);
}

struct ib_mad_list_head {
	struct list_head list;
	struct ib_cqe cqe;
	struct ib_mad_queue *mad_queue;
};

#define IB_MAD_SEND_REQ_MAX_SG 2
struct ib_mad_send_wr_private {
	struct ib_mad_list_head mad_list;
	struct list_head agent_list;
	struct ib_mad_agent_private *mad_agent_priv;
	struct ib_mad_send_buf send_buf;
	u64 header_mapping;
	u64 payload_mapping;
	struct ib_ud_wr send_wr;
	struct ib_sge sg_list[IB_MAD_SEND_REQ_MAX_SG];
	__be64 tid;
	unsigned long timeout;
	int max_retries;
	int retries_left;
	int retry;
	int refcount;
	enum ib_wc_status status;

	/* RMPP control */
	struct list_head rmpp_list;
	struct ib_rmpp_segment *last_ack_seg;
	struct ib_rmpp_segment *cur_seg;
	int last_ack;
	int seg_num;
	int newwin;
	int pad;
};

struct ib_mad_private_header {
	struct ib_mad_list_head mad_list;
	struct ib_mad_recv_wc recv_wc;
	struct ib_wc wc;
	u64 mapping;
} __packed;

struct ib_mad_private {
	struct ib_mad_private_header header;
	size_t mad_size;
	struct ib_grh grh;
	u8 mad[0];
} __packed;

static inline void *xsc_ib_send_mad_sg_virt_addr(struct ib_device *ibdev,
						 const struct ib_send_wr *wr,
						 int sg)
{
	struct ib_mad_send_wr_private *mad_send_wr;
	struct ib_mad_list_head *mad_list;
	int iommu_state = xsc_ib_iommu_dma_map(ibdev);

	/* direct dma mapping */
	if (!iommu_state)
		return phys_to_virt(dma_to_phys(ibdev->dma_device, wr->sg_list[sg].addr));

	if (iommu_state == XSC_IB_IOMMU_MAP_NORMAL)
		return xsc_ib_iova_to_virt(ibdev, wr->sg_list[sg].addr);

	mad_list = container_of(wr->wr_cqe, struct ib_mad_list_head, cqe);
	mad_send_wr = container_of(mad_list, struct ib_mad_send_wr_private,
				   mad_list);

	/* sg_list[0] */
	if (sg == 0)
		return mad_send_wr->send_buf.mad;

	/* sg_list[1] */
	if (mad_send_wr->send_buf.seg_count)
		return ib_get_rmpp_segment(&mad_send_wr->send_buf,
					   mad_send_wr->seg_num);
	return mad_send_wr->send_buf.mad + mad_send_wr->send_buf.hdr_len;
}

static inline void *xsc_ib_recv_mad_sg_virt_addr(struct ib_device *ibdev,
						 struct ib_wc *wc,
						 u64 sg_addr)
{
	struct ib_mad_private_header *mad_priv_hdr;
	struct ib_mad_private *recv;
	struct ib_mad_list_head *mad_list;
	int iommu_state = xsc_ib_iommu_dma_map(ibdev);

	/* direct dma mapping */
	if (!iommu_state)
		return phys_to_virt(dma_to_phys(ibdev->dma_device, sg_addr));

	if (iommu_state == XSC_IB_IOMMU_MAP_NORMAL)
		return xsc_ib_iova_to_virt(ibdev, sg_addr);

	mad_list = container_of(wc->wr_cqe, struct ib_mad_list_head, cqe);
	mad_priv_hdr = container_of(mad_list, struct ib_mad_private_header, mad_list);
	recv = container_of(mad_priv_hdr, struct ib_mad_private, header);
	return &recv->grh;
}

int xsc_get_rdma_ctrl_info(struct xsc_core_device *xdev, u16 opcode, void *out, int out_size);

#endif /* XSC_IB_H */
