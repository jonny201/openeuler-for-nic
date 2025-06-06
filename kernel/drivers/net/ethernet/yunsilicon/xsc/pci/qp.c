// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/gfp.h>
#include <linux/time.h>
#include <linux/export.h>
#include "common/qp.h"
#include "common/driver.h"
#include <linux/kthread.h>
#include "common/xsc_core.h"

#define GROUP_DESTROY_FLAG_SHFIT 15
#define GROUP_DESTROY_FLAG_MASK (1 << (GROUP_DESTROY_FLAG_SHFIT))

#define	GROUP_OTHER_HASH_SIZE	16
#define	GROUP_CC_HASH_SIZE	(1024 - GROUP_OTHER_HASH_SIZE)

enum {
	GROUP_MODE_PER_QP = 0,
	GROUP_MODE_PER_DEST_IP,
};

struct {
	struct list_head	head;
	spinlock_t		lock;	/* protect delayed_release_list */
	struct task_struct	*poll_task;
	wait_queue_head_t	wq;
	int			wait_flag;
} delayed_release_list;

enum {
	SLEEP,
	WAKEUP,
	EXIT,
};

static bool exit_flag;

void xsc_set_exit_flag(void)
{
	exit_flag = true;
}
EXPORT_SYMBOL_GPL(xsc_set_exit_flag);

bool xsc_get_exit_flag(void)
{
	return exit_flag;
}
EXPORT_SYMBOL_GPL(xsc_get_exit_flag);

bool exist_incomplete_qp_flush(void)
{
	return !list_empty(&delayed_release_list.head);
}
EXPORT_SYMBOL_GPL(exist_incomplete_qp_flush);

static bool xsc_qp_flush_finished(struct xsc_core_device *xdev, u32 qpn)
{
	struct xsc_query_qp_flush_status_mbox_in in;
	struct xsc_query_qp_flush_status_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_QP_FLUSH_STATUS);
	in.qpn = cpu_to_be32(qpn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if ((!err && !out.hdr.status) || err == -ETIMEDOUT)
		return true;

	xsc_core_dbg(xdev, "qp[%d] flush incomplete.\n", qpn);
	return false;
}

static int xsc_qp_flush_check(void *arg)
{
	struct xsc_qp_rsc *entry;

	while (!kthread_should_stop()) {
		if (need_resched())
			schedule();

		spin_lock(&delayed_release_list.lock);
		entry = list_first_entry_or_null(&delayed_release_list.head,
						 struct xsc_qp_rsc, node);
		if (!entry) {
			spin_unlock(&delayed_release_list.lock);
			wait_event_interruptible(delayed_release_list.wq,
						 delayed_release_list.wait_flag != SLEEP);
			if (delayed_release_list.wait_flag == EXIT)
				break;
			delayed_release_list.wait_flag = SLEEP;
			continue;
		}
		list_del(&entry->node);
		spin_unlock(&delayed_release_list.lock);

		if (!exit_flag && !xsc_qp_flush_finished(entry->xdev, entry->qpn)) {
			spin_lock(&delayed_release_list.lock);
			list_add_tail(&entry->node, &delayed_release_list.head);
			spin_unlock(&delayed_release_list.lock);
		} else {
			complete(&entry->delayed_release);
		}
	}

	return 0;
}

void xsc_init_delayed_release(void)
{
	INIT_LIST_HEAD(&delayed_release_list.head);
	spin_lock_init(&delayed_release_list.lock);
	init_waitqueue_head(&delayed_release_list.wq);
	delayed_release_list.wait_flag = SLEEP;
	delayed_release_list.poll_task = kthread_create(xsc_qp_flush_check, NULL, "qp flush check");
	if (delayed_release_list.poll_task)
		wake_up_process(delayed_release_list.poll_task);
}

void xsc_stop_delayed_release(void)
{
	delayed_release_list.wait_flag = EXIT;
	wake_up(&delayed_release_list.wq);
	if (delayed_release_list.poll_task)
		kthread_stop(delayed_release_list.poll_task);
}

static void xsc_wait_qp_flush_complete(struct xsc_core_device *xdev, u32 qpn)
{
	struct xsc_qp_rsc qp_rsc;
	int err = 0;

	if (exit_flag)
		return;

	init_completion(&qp_rsc.delayed_release);
	qp_rsc.qpn = qpn;
	qp_rsc.xdev = xdev;
	spin_lock(&delayed_release_list.lock);
	list_add_tail(&qp_rsc.node, &delayed_release_list.head);
	spin_unlock(&delayed_release_list.lock);
	delayed_release_list.wait_flag = WAKEUP;
	wake_up(&delayed_release_list.wq);

	while ((err = wait_for_completion_interruptible(&qp_rsc.delayed_release))
		== -ERESTARTSYS) {
		xsc_core_dbg(xdev, "qp %d wait for completion is interrupted, err = %d\n",
			     qpn, err);
		if (need_resched()) {
			schedule();
		}
	}
}

int create_resource_common(struct xsc_core_device *xdev,
			   struct xsc_core_qp *qp)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;
	int err;

	spin_lock_irq(&table->lock);
	err = radix_tree_insert(&table->tree, qp->qpn, qp);
	spin_unlock_irq(&table->lock);
	if (err)
		return err;

	atomic_set(&qp->refcount, 1);
	init_completion(&qp->free);
	qp->pid = current->pid;

	return 0;
}
EXPORT_SYMBOL_GPL(create_resource_common);

void destroy_resource_common(struct xsc_core_device *xdev,
			     struct xsc_core_qp *qp)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;
	unsigned long flags;

	spin_lock_irqsave(&table->lock, flags);
	radix_tree_delete(&table->tree, qp->qpn);
	spin_unlock_irqrestore(&table->lock, flags);

	if (atomic_dec_and_test(&qp->refcount))
		complete(&qp->free);
	wait_for_completion(&qp->free);
}
EXPORT_SYMBOL_GPL(destroy_resource_common);

void xsc_qp_event(struct xsc_core_device *xdev, u32 qpn, int event_type)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;
	struct xsc_core_qp *qp;

	spin_lock(&table->lock);

	qp = radix_tree_lookup(&table->tree, qpn);
	if (qp)
		atomic_inc(&qp->refcount);

	spin_unlock(&table->lock);

	if (!qp) {
		xsc_core_warn(xdev, "Async event for bogus QP 0x%x\n", qpn);
		return;
	}

	qp->err_occurred = 1;
	qp->event(qp, event_type);

	if (atomic_dec_and_test(&qp->refcount))
		complete(&qp->free);
}

int xsc_alloc_qpn(struct xsc_core_device *xdev, u16 *qpn_base, u16 qp_cnt, u8 qp_type)
{
	struct xsc_alloc_qpn_mbox_in in;
	struct xsc_alloc_qpn_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ALLOC_QPN);
	in.qp_cnt = cpu_to_be16(qp_cnt);
	in.qp_type = qp_type;

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);
	*qpn_base = be16_to_cpu(out.qpn_base);
	return 0;
}
EXPORT_SYMBOL(xsc_alloc_qpn);

int xsc_dealloc_qpn(struct xsc_core_device *xdev, u16 qpn_base, u16 qp_cnt, u8 qp_type)
{
	struct xsc_dealloc_qpn_mbox_in in;
	struct xsc_dealloc_qpn_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DEALLOC_QPN);
	in.qp_cnt = cpu_to_be16(qp_cnt);
	in.qpn_base = cpu_to_be16(qpn_base);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);
	return 0;
}
EXPORT_SYMBOL(xsc_dealloc_qpn);

int xsc_unset_qp_info(struct xsc_core_device *xdev, u16 qpn)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_QP_UNSET_QP_INFO);
	in.qpn = cpu_to_be16(qpn);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);
	return 0;
}
EXPORT_SYMBOL(xsc_unset_qp_info);

int xsc_set_qp_info(struct xsc_core_device *xdev, struct xsc_create_qp_request *qp_info,
		    size_t pas_buf_size)
{
	struct xsc_set_qp_info_in *in;
	struct xsc_set_qp_info_out out;
	size_t in_size;
	int err;

	in_size = sizeof(*in) + pas_buf_size;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_QP_INFO);
	memcpy(&in->qp_info, qp_info, sizeof(*qp_info) + pas_buf_size);

	err = xsc_cmd_exec(xdev, in, in_size, &out, sizeof(out));
	if (err)
		goto out;

	if (out.hdr.status) {
		err = xsc_cmd_status_to_err(&out.hdr);
		goto out;
	}
	kfree(in);
	return 0;
out:
	kfree(in);
	return err;
}
EXPORT_SYMBOL(xsc_set_qp_info);

int xsc_core_create_qp(struct xsc_core_device *xdev,
		       struct xsc_core_qp *qp,
		       struct xsc_create_qp_mbox_in *in,
		       int inlen)
{
	struct xsc_create_qp_mbox_out out;
	struct xsc_destroy_qp_mbox_in din;
	struct xsc_destroy_qp_mbox_out dout;
	int err;
	struct timespec64 ts;

	ktime_get_boottime_ts64(&ts);

	memset(&dout, 0, sizeof(dout));
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_CREATE_QP);

	err = xsc_cmd_exec(xdev, in, inlen, &out, sizeof(out));
	if (err) {
		xsc_core_err(xdev, "ret %d", err);
		return err;
	}

	if (out.hdr.status) {
		xsc_core_err(xdev, "current num of QPs %u\n", atomic_read(&xdev->num_qps));
		return xsc_cmd_status_to_err(&out.hdr);
	}
	qp->qpn = be32_to_cpu(out.qpn) & 0xffffff;
	xsc_core_info(xdev, "qpn = %u\n", qp->qpn);

	qp->trace_info = kzalloc(sizeof(*qp->trace_info), GFP_KERNEL);
	if (!qp->trace_info) {
		err = -ENOMEM;
		goto err_cmd;
	}
	qp->trace_info->pid = current->pid;
	qp->trace_info->timestamp = (u64)(u32)ts.tv_sec * MSEC_PER_SEC +
			ts.tv_nsec / NSEC_PER_MSEC;

	err = create_resource_common(xdev, qp);
	if (err) {
		xsc_core_err(xdev, "err %d", err);
		goto err_trace;
	}

	err = xsc_debug_qp_add(xdev, qp);
	if (err)
		xsc_core_err(xdev, "failed adding QP %u to debug file system\n",
			     qp->qpn);

	atomic_inc(&xdev->num_qps);
	return 0;
err_trace:
	kfree(qp->trace_info);
err_cmd:
	memset(&din, 0, sizeof(din));
	memset(&dout, 0, sizeof(dout));
	din.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	din.qpn = cpu_to_be32(qp->qpn);
	xsc_cmd_exec(xdev, &din, sizeof(din), &out, sizeof(dout));

	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_create_qp);

int xsc_core_destroy_qp(struct xsc_core_device *xdev,
			struct xsc_core_qp *qp)
{
	struct xsc_destroy_qp_mbox_in in;
	struct xsc_destroy_qp_mbox_out out;
	int err;

	xsc_debug_qp_remove(xdev, qp);
	xsc_remove_qptrace(xdev, qp);
	kfree(qp->trace_info);

	destroy_resource_common(xdev, qp);

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(qp->qpn);

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);
	atomic_dec(&xdev->num_qps);
	return 0;
}
EXPORT_SYMBOL_GPL(xsc_core_destroy_qp);

int xsc_modify_qp(struct xsc_core_device *xdev,
		  struct xsc_modify_qp_mbox_in *in,
		  struct xsc_modify_qp_mbox_out *out,
		  u32 qpn, u16 status)
{
	int ret = 0;

	in->hdr.opcode = cpu_to_be16(status);
	in->qpn = cpu_to_be32(qpn);
	in->ctx.no_need_wait = 1;

	ret = xsc_cmd_exec(xdev, in, sizeof(*in), out, sizeof(*out));
	if ((status == XSC_CMD_OP_2RST_QP || status == XSC_CMD_OP_2ERR_QP) &&
	    out->hdr.status) {
		xsc_wait_qp_flush_complete(xdev, qpn);
		out->hdr.status = 0;
	}
	if (ret || out->hdr.status != 0) {
		xsc_core_err(xdev, "failed to modify qp %u status=%u, err=%d out.status %u\n",
			     qpn, status, ret, out->hdr.status);
		ret = -ENOEXEC;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(xsc_modify_qp);

int xsc_core_qp_modify(struct xsc_core_device *xdev, enum xsc_qp_state cur_state,
		       enum xsc_qp_state new_state,
		       struct xsc_modify_qp_mbox_in *in, int sqd_event,
		       struct xsc_core_qp *qp)
{
	static const u16 optab[XSC_QP_NUM_STATE][XSC_QP_NUM_STATE] = {
		[XSC_QP_STATE_RST] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_INIT]	= XSC_CMD_OP_RST2INIT_QP,
		},
		[XSC_QP_STATE_INIT]  = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_INIT]	= XSC_CMD_OP_INIT2INIT_QP,
			[XSC_QP_STATE_RTR]	= XSC_CMD_OP_INIT2RTR_QP,
		},
		[XSC_QP_STATE_RTR]   = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_RTR2RTS_QP,
		},
		[XSC_QP_STATE_RTS]   = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_RTS2RTS_QP,
			[XSC_QP_STATE_SQD]	= XSC_CMD_OP_RTS2SQD_QP,
		},
		[XSC_QP_STATE_SQD] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_SQD2RTS_QP,
			[XSC_QP_STATE_SQD]	= XSC_CMD_OP_SQD2SQD_QP,
		},
		[XSC_QP_STATE_SQER] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
			[XSC_QP_STATE_RTS]	= XSC_CMD_OP_SQERR2RTS_QP,
		},
		[XSC_QP_STATE_ERR] = {
			[XSC_QP_STATE_RST]	= XSC_CMD_OP_2RST_QP,
			[XSC_QP_STATE_ERR]	= XSC_CMD_OP_2ERR_QP,
		}
	};

	struct xsc_modify_qp_mbox_out out;
	int err = 0;
	u16 op;

	if (cur_state >= XSC_QP_NUM_STATE || new_state >= XSC_QP_NUM_STATE ||
	    !optab[cur_state][new_state])
		return -EINVAL;

	memset(&out, 0, sizeof(out));
	op = optab[cur_state][new_state];

	if (new_state == XSC_QP_STATE_RTR) {
		if (qp->qp_type_internal == XSC_QUEUE_TYPE_RDMA_RC &&
		    ((in->ctx.ip_type == 0 && in->ctx.dip[0] == in->ctx.sip[0]) ||
		    (in->ctx.ip_type != 0 &&
		    memcmp(in->ctx.dip, in->ctx.sip, sizeof(in->ctx.sip)) == 0)))
			in->ctx.qp_out_port = xdev->caps.nif_port_num + xdev->pcie_no;
		else if (in->ctx.lag_sel_en == 0)
			in->ctx.qp_out_port = xdev->pf_id;
		else
			in->ctx.qp_out_port = in->ctx.lag_sel;

		in->ctx.pcie_no = xdev->pcie_no;
		in->ctx.func_id = cpu_to_be16(xdev->glb_func_id);
	}

	err = xsc_modify_qp(xdev, in, &out, qp->qpn, op);
	if (err)
		return err;

	if (new_state == XSC_QP_STATE_RTR) {
		qp->trace_info->main_ver = YS_QPTRACE_VER_MAJOR;
		qp->trace_info->sub_ver = YS_QPTRACE_VER_MINOR;
		qp->trace_info->qp_type = qp->qp_type;
		qp->trace_info->s_port = in->ctx.src_udp_port;
		qp->trace_info->d_port = cpu_to_be16(4791);
		qp->trace_info->lqpn = qp->qpn;
		qp->trace_info->rqpn = be32_to_cpu(in->ctx.remote_qpn);
		qp->trace_info->affinity_idx = (in->ctx.lag_sel_en == 0 ? 0 : in->ctx.lag_sel);
		qp->trace_info->af_type = (in->ctx.ip_type == 0 ? AF_INET : AF_INET6);

		if (in->ctx.ip_type == 0) {
			qp->trace_info->s_addr.s_addr4 = in->ctx.sip[0];
			qp->trace_info->d_addr.d_addr4 = in->ctx.dip[0];
		} else {
			memcpy(qp->trace_info->s_addr.s_addr6, in->ctx.sip,
			       sizeof(qp->trace_info->s_addr.s_addr6));
			memcpy(qp->trace_info->d_addr.d_addr6, in->ctx.dip,
			       sizeof(qp->trace_info->d_addr.d_addr6));
		}

		err = xsc_create_qptrace(xdev, qp);
		if (err)
			return err;
	}

	return xsc_cmd_status_to_err(&out.hdr);
}
EXPORT_SYMBOL_GPL(xsc_core_qp_modify);

int xsc_core_qp_query(struct xsc_core_device *xdev, struct xsc_core_qp *qp,
		      struct xsc_query_qp_mbox_out *out, int outlen)
{
	struct xsc_query_qp_mbox_in in;
	int err;

	memset(&in, 0, sizeof(in));
	memset(out, 0, outlen);
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_QP);
	in.qpn = cpu_to_be32(qp->qpn);
	err = xsc_cmd_exec(xdev, &in, sizeof(in), out, outlen);
	if (err)
		return err;

	if (out->hdr.status)
		return xsc_cmd_status_to_err(&out->hdr);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_core_qp_query);

void xsc_init_qp_table(struct xsc_core_device *xdev)
{
	struct xsc_qp_table *table = &xdev->dev_res->qp_table;

	spin_lock_init(&table->lock);
	INIT_RADIX_TREE(&table->tree, GFP_ATOMIC);

	xsc_qp_debugfs_init(xdev);
	xsc_qptrace_debugfs_init(xdev);
}

void xsc_cleanup_qp_table(struct xsc_core_device *xdev)
{
	xsc_qp_debugfs_cleanup(xdev);
	xsc_qptrace_debugfs_cleanup(xdev);
}
