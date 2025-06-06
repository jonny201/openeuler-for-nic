// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/device.h>
#include "common/xsc_core.h"
#include "common/xsc_ioctl.h"
#include "common/xsc_hsi.h"
#include "common/xsc_port_ctrl.h"
#include "common/tunnel_cmd.h"
#include "xsc_ib.h"
#include "xsc_rdma_ctrl.h"

#define XSC_RDMA_CTRL_NAME	"rdma_ctrl"

static void encode_cc_cmd_enable_rp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_enable_rp *cc_cmd = (struct xsc_cc_cmd_enable_rp *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->enable = __cpu_to_be32(cc_cmd->enable);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_enable_np(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_enable_np *cc_cmd = (struct xsc_cc_cmd_enable_np *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->enable = __cpu_to_be32(cc_cmd->enable);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_init_alpha(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_init_alpha *cc_cmd = (struct xsc_cc_cmd_init_alpha *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->alpha = __cpu_to_be32(cc_cmd->alpha);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_g(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_g *cc_cmd = (struct xsc_cc_cmd_g *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->g = __cpu_to_be32(cc_cmd->g);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_ai(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_ai *cc_cmd = (struct xsc_cc_cmd_ai *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->ai = __cpu_to_be32(cc_cmd->ai);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_hai(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_hai *cc_cmd = (struct xsc_cc_cmd_hai *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->hai = __cpu_to_be32(cc_cmd->hai);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_th(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_th *cc_cmd = (struct xsc_cc_cmd_th *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->threshold = __cpu_to_be32(cc_cmd->threshold);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_bc(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_bc *cc_cmd = (struct xsc_cc_cmd_bc *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bytecount = __cpu_to_be32(cc_cmd->bytecount);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_cnp_opcode(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_opcode *cc_cmd = (struct xsc_cc_cmd_cnp_opcode *)data;

	cc_cmd->opcode = __cpu_to_be32(cc_cmd->opcode);
}

static void encode_cc_cmd_cnp_bth_b(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_bth_b *cc_cmd = (struct xsc_cc_cmd_cnp_bth_b *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bth_b = __cpu_to_be32(cc_cmd->bth_b);
}

static void encode_cc_cmd_cnp_bth_f(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_bth_f *cc_cmd = (struct xsc_cc_cmd_cnp_bth_f *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->bth_f = __cpu_to_be32(cc_cmd->bth_f);
}

static void encode_cc_cmd_cnp_ecn(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_ecn *cc_cmd = (struct xsc_cc_cmd_cnp_ecn *)data;

	cc_cmd->ecn = __cpu_to_be32(cc_cmd->ecn);
}

static void encode_cc_cmd_data_ecn(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_data_ecn *cc_cmd = (struct xsc_cc_cmd_data_ecn *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->ecn = __cpu_to_be32(cc_cmd->ecn);
}

static void encode_cc_cmd_cnp_tx_interval(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_tx_interval *cc_cmd = (struct xsc_cc_cmd_cnp_tx_interval *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->interval = __cpu_to_be32(cc_cmd->interval);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_evt_rsttime(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_evt_rsttime *cc_cmd =
			(struct xsc_cc_cmd_evt_rsttime *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->period = __cpu_to_be32(cc_cmd->period);
}

static void encode_cc_cmd_cnp_dscp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_dscp *cc_cmd = (struct xsc_cc_cmd_cnp_dscp *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->dscp = __cpu_to_be32(cc_cmd->dscp);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_cnp_pcp(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_cnp_pcp *cc_cmd = (struct xsc_cc_cmd_cnp_pcp *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->pcp = __cpu_to_be32(cc_cmd->pcp);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_evt_period_alpha(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_evt_period_alpha *cc_cmd = (struct xsc_cc_cmd_evt_period_alpha *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->period = __cpu_to_be32(cc_cmd->period);
}

static void encode_cc_cmd_clamp_tgt_rate(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_clamp_tgt_rate *cc_cmd = (struct xsc_cc_cmd_clamp_tgt_rate *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->clamp_tgt_rate = __cpu_to_be32(cc_cmd->clamp_tgt_rate);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_max_hai_factor(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_max_hai_factor *cc_cmd = (struct xsc_cc_cmd_max_hai_factor *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->max_hai_factor = __cpu_to_be32(cc_cmd->max_hai_factor);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_cmd_scale(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_scale *cc_cmd = (struct xsc_cc_cmd_scale *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->scale = __cpu_to_be32(cc_cmd->scale);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void encode_cc_get_cfg(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_get_cfg *cc_cmd = (struct xsc_cc_cmd_get_cfg *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void decode_cc_get_cfg(void *data)
{
	struct xsc_cc_cmd_get_cfg *cc_cmd = (struct xsc_cc_cmd_get_cfg *)data;

	cc_cmd->cmd = __be16_to_cpu(cc_cmd->cmd);
	cc_cmd->len = __be16_to_cpu(cc_cmd->len);
	cc_cmd->enable_rp = __be32_to_cpu(cc_cmd->enable_rp);
	cc_cmd->enable_np = __be32_to_cpu(cc_cmd->enable_np);
	cc_cmd->init_alpha = __be32_to_cpu(cc_cmd->init_alpha);
	cc_cmd->g = __be32_to_cpu(cc_cmd->g);
	cc_cmd->ai = __be32_to_cpu(cc_cmd->ai);
	cc_cmd->hai = __be32_to_cpu(cc_cmd->hai);
	cc_cmd->threshold = __be32_to_cpu(cc_cmd->threshold);
	cc_cmd->bytecount = __be32_to_cpu(cc_cmd->bytecount);
	cc_cmd->opcode = __be32_to_cpu(cc_cmd->opcode);
	cc_cmd->bth_b = __be32_to_cpu(cc_cmd->bth_b);
	cc_cmd->bth_f = __be32_to_cpu(cc_cmd->bth_f);
	cc_cmd->cnp_ecn = __be32_to_cpu(cc_cmd->cnp_ecn);
	cc_cmd->data_ecn = __be32_to_cpu(cc_cmd->data_ecn);
	cc_cmd->cnp_tx_interval = __be32_to_cpu(cc_cmd->cnp_tx_interval);
	cc_cmd->evt_period_rsttime = __be32_to_cpu(cc_cmd->evt_period_rsttime);
	cc_cmd->cnp_dscp = __be32_to_cpu(cc_cmd->cnp_dscp);
	cc_cmd->cnp_pcp = __be32_to_cpu(cc_cmd->cnp_pcp);
	cc_cmd->evt_period_alpha = __be32_to_cpu(cc_cmd->evt_period_alpha);
	cc_cmd->clamp_tgt_rate = __be32_to_cpu(cc_cmd->clamp_tgt_rate);
	cc_cmd->max_hai_factor = __be32_to_cpu(cc_cmd->max_hai_factor);
	cc_cmd->scale = __be32_to_cpu(cc_cmd->scale);
	cc_cmd->section = __be32_to_cpu(cc_cmd->section);
}

static void encode_cc_get_stat(void *data, u32 mac_port)
{
	struct xsc_cc_cmd_get_stat *cc_cmd = (struct xsc_cc_cmd_get_stat *)data;

	cc_cmd->cmd = __cpu_to_be16(cc_cmd->cmd);
	cc_cmd->len = __cpu_to_be16(cc_cmd->len);
	cc_cmd->section = __cpu_to_be32(mac_port);
}

static void decode_cc_get_stat(void *data)
{
	struct xsc_cc_cmd_stat *cc_cmd = (struct xsc_cc_cmd_stat *)data;

	cc_cmd->cnp_handled = __be32_to_cpu(cc_cmd->cnp_handled);
	cc_cmd->alpha_recovery = __be32_to_cpu(cc_cmd->alpha_recovery);
	cc_cmd->reset_timeout = __be32_to_cpu(cc_cmd->reset_timeout);
	cc_cmd->reset_bytecount = __be32_to_cpu(cc_cmd->reset_bytecount);
}

static int xsc_priv_dev_ioctl_get_force_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_force_pcp *resp = (struct xsc_ioctl_force_pcp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	resp->pcp = ib_dev->force_pcp;
	return 0;
}

static int xsc_priv_dev_ioctl_get_force_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_force_dscp *resp = (struct xsc_ioctl_force_dscp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	resp->dscp = ib_dev->force_dscp;
	return 0;
}

static int xsc_priv_dev_ioctl_set_force_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_force_pcp *req = (struct xsc_ioctl_force_pcp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	if (req->pcp < 0 || (req->pcp > QOS_PCP_MAX && req->pcp != DSCP_PCP_UNSET))
		return -EINVAL;

	ib_dev->force_pcp = req->pcp;
	return 0;
}

static int xsc_priv_dev_ioctl_set_force_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_force_dscp *req = (struct xsc_ioctl_force_dscp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	if (req->dscp < 0 || (req->dscp > QOS_DSCP_MAX && req->dscp != DSCP_PCP_UNSET))
		return -EINVAL;

	ib_dev->force_dscp = req->dscp;
	return 0;
}

static int xsc_priv_dev_ioctl_get_cma_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_pcp *resp = (struct xsc_ioctl_cma_pcp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	resp->pcp = ib_dev->cm_pcp;
	return 0;
}

static int xsc_priv_dev_ioctl_get_cma_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_dscp *resp = (struct xsc_ioctl_cma_dscp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	resp->dscp = ib_dev->cm_dscp;
	return 0;
}

static int xsc_priv_dev_ioctl_set_cma_pcp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_pcp *req = (struct xsc_ioctl_cma_pcp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	if (req->pcp < 0 || (req->pcp > QOS_PCP_MAX && req->pcp != DSCP_PCP_UNSET))
		return -EINVAL;

	ib_dev->cm_pcp = req->pcp;
	return 0;
}

static int xsc_priv_dev_ioctl_set_cma_dscp(struct xsc_core_device *xdev, void *in, void *out)
{
	struct xsc_ib_dev *ib_dev = xdev->xsc_ib_dev;
	struct xsc_ioctl_cma_dscp *req = (struct xsc_ioctl_cma_dscp *)out;

	if (!xsc_core_is_pf(xdev))
		return XSC_CMD_STATUS_NOT_SUPPORTED;

	if (req->dscp < 0 || (req->dscp > QOS_DSCP_MAX && req->dscp != DSCP_PCP_UNSET))
		return -EINVAL;

	ib_dev->cm_dscp = req->dscp;
	return 0;
}

static int _rdma_ctrl_ioctl_cc(struct xsc_core_device *xdev,
			       struct xsc_ioctl_hdr __user *user_hdr, struct xsc_ioctl_hdr *hdr,
			       u16 expect_req_size, u16 expect_resp_size,
			       void (*encode)(void *, u32), void (*decode)(void *))
{
	struct xsc_cc_mbox_in *in;
	struct xsc_cc_mbox_out *out;
	u16 user_size;
	int err;
	struct xsc_ioctl_tunnel_hdr tunnel_hdr = {0};

	if (hdr->attr.tunnel_cmd)
		hdr->attr.length -= sizeof(tunnel_hdr);

	user_size = expect_req_size > expect_resp_size ? expect_req_size : expect_resp_size;
	if (hdr->attr.length != user_size)
		return -EINVAL;

	in = kvzalloc(sizeof(struct xsc_cc_mbox_in) + expect_req_size, GFP_KERNEL);
	if (!in)
		goto err_in;
	out = kvzalloc(sizeof(struct xsc_cc_mbox_out) + expect_resp_size, GFP_KERNEL);
	if (!out)
		goto err_out;

	if (hdr->attr.tunnel_cmd) {
		err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
		if (err)
			goto err;
		err = copy_from_user(&in->data, user_hdr->attr.data + sizeof(tunnel_hdr),
				     expect_req_size);
		if (err)
			goto err;
	} else {
		err = copy_from_user(&in->data, user_hdr->attr.data, expect_req_size);
		if (err)
			goto err;
	}

	in->hdr.opcode = __cpu_to_be16(hdr->attr.opcode);
	in->hdr.ver = cpu_to_be16(hdr->attr.ver);
	if (encode)
		encode((void *)in->data, xdev->mac_port);

	if (hdr->attr.tunnel_cmd)
		err = xsc_tunnel_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
					  sizeof(*out) + expect_resp_size, &tunnel_hdr);
	else
		err = xsc_cmd_exec(xdev, in, sizeof(*in) + expect_req_size, out,
				   sizeof(*out) + expect_resp_size);

	hdr->attr.error = out->hdr.status;
	if (decode)
		decode((void *)out->data);

	if (copy_to_user((void *)user_hdr, hdr, sizeof(*hdr)))
		goto err;
	if (copy_to_user((void *)user_hdr->attr.data, &out->data, expect_resp_size))
		goto err;

	kvfree(in);
	kvfree(out);
	return 0;

err:
	kvfree(out);
err_out:
	kvfree(in);
err_in:
	return -EFAULT;
}

static int _rdma_ctrl_exec_tunnel_ioctl(struct xsc_core_device *xdev,
					void *in, int in_size,
					void *out, int out_size,
					struct xsc_ioctl_tunnel_hdr *tunnel_hdr)
{
	struct xsc_cmd_get_ioctl_info_mbox_in *_in;
	struct xsc_cmd_get_ioctl_info_mbox_out *_out;
	int inlen;
	int outlen;
	int err;
	struct xsc_ioctl_attr *hdr = (struct xsc_ioctl_attr *)in;

	inlen = sizeof(*_in) + out_size;
	_in = kvzalloc(inlen, GFP_KERNEL);
	if (!_in) {
		err = -ENOMEM;
		goto err_in;
	}

	outlen = sizeof(*_out) + out_size;
	_out = kvzalloc(outlen, GFP_KERNEL);
	if (!_out) {
		err = -ENOMEM;
		goto err_out;
	}

	memset(_in, 0, sizeof(*_in));
	_in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_GET_IOCTL_INFO);
	_in->ioctl_opcode = cpu_to_be16(hdr->opcode);
	_in->length = cpu_to_be16(out_size);
	memcpy(_in->data, out, out_size);
	err = xsc_tunnel_cmd_exec(xdev, _in, inlen, _out, outlen, tunnel_hdr);
	if (err)
		goto out;
	memcpy(out, _out->data, out_size);

	return 0;
out:
	kvfree(_out);
err_out:
	kvfree(_in);
err_in:
	return err;
}

static int _rdma_ctrl_exec_ioctl(struct xsc_core_device *xdev,
				 void *in, int in_size,
				 void *out, int out_size)
{
	int opcode, ret = 0;
	struct xsc_ioctl_attr *hdr;

	hdr = (struct xsc_ioctl_attr *)in;
	opcode = hdr->opcode;
	switch (opcode) {
	case XSC_IOCTL_GET_FORCE_PCP:
		ret = xsc_priv_dev_ioctl_get_force_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_FORCE_DSCP:
		ret = xsc_priv_dev_ioctl_get_force_dscp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_CMA_PCP:
		ret = xsc_priv_dev_ioctl_get_cma_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_GET_CMA_DSCP:
		ret = xsc_priv_dev_ioctl_get_cma_dscp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_FORCE_PCP:
		xsc_core_dbg(xdev, "setting global pcp\n");
		ret = xsc_priv_dev_ioctl_set_force_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_FORCE_DSCP:
		xsc_core_dbg(xdev, "setting global dscp\n");
		ret = xsc_priv_dev_ioctl_set_force_dscp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_CMA_PCP:
		ret = xsc_priv_dev_ioctl_set_cma_pcp(xdev, in, out);
		break;
	case XSC_IOCTL_SET_CMA_DSCP:
		ret = xsc_priv_dev_ioctl_set_cma_dscp(xdev, in, out);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

int xsc_get_rdma_ctrl_info(struct xsc_core_device *xdev, u16 opcode, void *out, int out_size)
{
	struct xsc_ioctl_attr attr;

	attr.opcode = opcode;
	return _rdma_ctrl_exec_ioctl(xdev, &attr, sizeof(attr), out, out_size);
}

static long _rdma_ctrl_ioctl_getinfo(struct xsc_core_device *xdev,
				     struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	struct xsc_ioctl_hdr *in;
	int in_size;
	int err;
	struct xsc_ioctl_tunnel_hdr tunnel_hdr;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;
	switch (hdr.attr.opcode) {
	case XSC_IOCTL_GET_FORCE_PCP:
	case XSC_IOCTL_GET_FORCE_DSCP:
	case XSC_IOCTL_SET_FORCE_PCP:
	case XSC_IOCTL_SET_FORCE_DSCP:
	case XSC_IOCTL_GET_CMA_PCP:
	case XSC_IOCTL_GET_CMA_DSCP:
	case XSC_IOCTL_SET_CMA_PCP:
	case XSC_IOCTL_SET_CMA_DSCP:
		break;
	default:
		return -EINVAL;
	}
	if (hdr.attr.tunnel_cmd)
		hdr.attr.length -= sizeof(tunnel_hdr);
	in_size = sizeof(struct xsc_ioctl_hdr) + hdr.attr.length;
	in = kvzalloc(in_size, GFP_KERNEL);
	if (!in)
		return -EFAULT;
	in->attr.opcode = hdr.attr.opcode;
	in->attr.length = hdr.attr.length;

	if (hdr.attr.tunnel_cmd) {
		err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
		if (err) {
			err = -EFAULT;
			goto out;
		}
		err = copy_from_user(in->attr.data, user_hdr->attr.data + sizeof(tunnel_hdr),
				     hdr.attr.length);
		if (err) {
			err = -EFAULT;
			goto out;
		}
		err = _rdma_ctrl_exec_tunnel_ioctl(xdev, &in->attr, (in_size - sizeof(u32)),
						   in->attr.data, hdr.attr.length, &tunnel_hdr);
	} else {
		err = copy_from_user(in->attr.data, user_hdr->attr.data, hdr.attr.length);
		if (err) {
			err = -EFAULT;
			goto out;
		}
		err = _rdma_ctrl_exec_ioctl(xdev, &in->attr, (in_size - sizeof(u32)), in->attr.data,
					    hdr.attr.length);
	}
	in->attr.error = err;
	if (copy_to_user(user_hdr, in, in_size))
		err = -EFAULT;
out:
	kvfree(in);
	return err;
}

static long _rdma_ctrl_ioctl_get_rdma_counters(struct xsc_core_device *xdev,
					       struct xsc_ioctl_hdr __user *user_hdr,
					       struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_tunnel_hdr tunnel_hdr;
	int err;
	struct xsc_hw_stats_mbox_in in;
	struct xsc_hw_stats_rdma_mbox_out out;

	err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
	if (err)
		return err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HW_STATS_RDMA);
	err = xsc_tunnel_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out), &tunnel_hdr);
	if (err)
		return err;

	if (out.hdr.status)
		return -EINVAL;

	err = copy_to_user(user_hdr->attr.data, &out.hw_stats, sizeof(out.hw_stats));
	if (err)
		return err;
	return 0;
}

static long _rdma_ctrl_ioctl_get_prio_counters(struct xsc_core_device *xdev,
					       struct xsc_ioctl_hdr __user *user_hdr,
					       struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_tunnel_hdr tunnel_hdr;
	int err;
	struct xsc_prio_stats_mbox_in in;
	struct xsc_prio_stats_mbox_out out;

	err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
	if (err)
		return err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_PRIO_STATS);
	err = xsc_tunnel_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out), &tunnel_hdr);
	if (err)
		return err;

	if (out.hdr.status)
		return -EINVAL;

	err = copy_to_user(user_hdr->attr.data, &out.prio_stats, sizeof(out.prio_stats));
	if (err)
		return err;
	return 0;
}

static long _rdma_ctrl_ioctl_get_pfc_counters(struct xsc_core_device *xdev,
					      struct xsc_ioctl_hdr __user *user_hdr,
					      struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_tunnel_hdr tunnel_hdr;
	int err;
	struct xsc_pfc_prio_stats_mbox_in in;
	struct xsc_pfc_prio_stats_mbox_out out;

	err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
	if (err)
		return err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_PFC_PRIO_STATS);
	err = xsc_tunnel_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out), &tunnel_hdr);
	if (err)
		return err;

	if (out.hdr.status)
		return -EINVAL;

	err = copy_to_user(user_hdr->attr.data, &out.prio_stats, sizeof(out.prio_stats));
	if (err)
		return err;
	return 0;
}

static long _rdma_ctrl_ioctl_get_hw_counters(struct xsc_core_device *xdev,
					     struct xsc_ioctl_hdr __user *user_hdr,
					     struct xsc_ioctl_hdr *hdr)
{
	struct xsc_ioctl_tunnel_hdr tunnel_hdr;
	int err;
	struct xsc_cmd_ioctl_get_hw_counters_mbox_in *in;
	struct xsc_cmd_ioctl_get_hw_counters_mbox_out *out;
	int inlen;
	int outlen;

	err = copy_from_user(&tunnel_hdr, user_hdr->attr.data, sizeof(tunnel_hdr));
	if (err)
		return err;

	hdr->attr.length -= sizeof(tunnel_hdr);
	inlen = sizeof(*in) + hdr->attr.length;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	outlen = sizeof(*out) + hdr->attr.length;
	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto out;
	}
	memset(in, 0, inlen);
	memset(out, 0, outlen);
	err = copy_from_user(in->data, user_hdr->attr.data + sizeof(tunnel_hdr), hdr->attr.length);
	if (err)
		goto out;
	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_IOCTL_GET_HW_COUNTERS);
	in->length = cpu_to_be32(hdr->attr.length);
	err = xsc_tunnel_cmd_exec(xdev, in, inlen, out, outlen, &tunnel_hdr);
	if (err)
		goto out;

	if (out->hdr.status) {
		err = -EINVAL;
		goto out;
	}

	err = copy_to_user(user_hdr->attr.data, out->data, hdr->attr.length);
	if (err)
		goto out;
out:
	kvfree(in);
	kvfree(out);
	return err;
}

static long _rdma_ctrl_ioctl_cmdq(struct xsc_core_device *xdev,
				  struct xsc_ioctl_hdr __user *user_hdr)
{
	struct xsc_ioctl_hdr hdr;
	int err;
	void *in;
	void *out;

	err = copy_from_user(&hdr, user_hdr, sizeof(hdr));
	if (err)
		return -EFAULT;

	/* check valid */
	if (hdr.check_filed != XSC_IOCTL_CHECK_FILED)
		return -EINVAL;

	/* check ioctl cmd */
	switch (hdr.attr.opcode) {
	case XSC_CMD_OP_IOCTL_SET_ENABLE_RP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_enable_rp),
					   0, encode_cc_cmd_enable_rp, NULL);
	case XSC_CMD_OP_IOCTL_SET_ENABLE_NP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_enable_np),
					   0, encode_cc_cmd_enable_np, NULL);
	case XSC_CMD_OP_IOCTL_SET_INIT_ALPHA:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_init_alpha),
					   0, encode_cc_cmd_init_alpha, NULL);
	case XSC_CMD_OP_IOCTL_SET_G:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_g),
					   0, encode_cc_cmd_g, NULL);
	case XSC_CMD_OP_IOCTL_SET_AI:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_ai),
					   0, encode_cc_cmd_ai, NULL);
	case XSC_CMD_OP_IOCTL_SET_HAI:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_hai),
					   0, encode_cc_cmd_hai, NULL);
	case XSC_CMD_OP_IOCTL_SET_TH:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_th),
					   0, encode_cc_cmd_th, NULL);
	case XSC_CMD_OP_IOCTL_SET_BC_TH:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_bc),
					   0, encode_cc_cmd_bc, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_OPCODE:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_opcode),
					   0, encode_cc_cmd_cnp_opcode, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_B:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_bth_b),
					   0, encode_cc_cmd_cnp_bth_b, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_F:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_bth_f),
					   0, encode_cc_cmd_cnp_bth_f, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_ECN:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_cnp_ecn),
			0, encode_cc_cmd_cnp_ecn, NULL);
	case XSC_CMD_OP_IOCTL_SET_DATA_ECN:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_data_ecn),
					   0, encode_cc_cmd_data_ecn, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_TX_INTERVAL:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_tx_interval),
					   0, encode_cc_cmd_cnp_tx_interval, NULL);
	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_RSTTIME:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_evt_rsttime),
					   0, encode_cc_cmd_evt_rsttime, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_DSCP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_dscp),
					   0, encode_cc_cmd_cnp_dscp, NULL);
	case XSC_CMD_OP_IOCTL_SET_CNP_PCP:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_cnp_pcp),
					   0, encode_cc_cmd_cnp_pcp, NULL);
	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_ALPHA:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_evt_period_alpha),
					   0, encode_cc_cmd_evt_period_alpha, NULL);
	case XSC_CMD_OP_IOCTL_SET_CLAMP_TGT_RATE:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_clamp_tgt_rate),
					   0, encode_cc_cmd_clamp_tgt_rate, NULL);
	case XSC_CMD_OP_IOCTL_SET_MAX_HAI_FACTOR:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_max_hai_factor),
					   0, encode_cc_cmd_max_hai_factor, NULL);
	case XSC_CMD_OP_IOCTL_SET_SCALE:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr,
					   sizeof(struct xsc_cc_cmd_scale),
					   0, encode_cc_cmd_scale, NULL);
	case XSC_CMD_OP_IOCTL_GET_CC_CFG:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_get_cfg),
					   sizeof(struct xsc_cc_cmd_get_cfg),
					   encode_cc_get_cfg, decode_cc_get_cfg);
	case XSC_CMD_OP_IOCTL_GET_CC_STAT:
		return _rdma_ctrl_ioctl_cc(xdev, user_hdr, &hdr, sizeof(struct xsc_cc_cmd_get_stat),
					   sizeof(struct xsc_cc_cmd_stat),
					   encode_cc_get_stat, decode_cc_get_stat);
	case XSC_CMD_OP_QUERY_HW_STATS_RDMA:
		return _rdma_ctrl_ioctl_get_rdma_counters(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_QUERY_PRIO_STATS:
		return _rdma_ctrl_ioctl_get_prio_counters(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_QUERY_PFC_PRIO_STATS:
		return _rdma_ctrl_ioctl_get_pfc_counters(xdev, user_hdr, &hdr);
	case XSC_CMD_OP_IOCTL_GET_HW_COUNTERS:
		return _rdma_ctrl_ioctl_get_hw_counters(xdev, user_hdr, &hdr);
	default:
		return -EINVAL;
	}

	in = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!in)
		return -ENOMEM;
	out = kvzalloc(hdr.attr.length, GFP_KERNEL);
	if (!out) {
		kfree(in);
		return -ENOMEM;
	}

	err = copy_from_user(in, user_hdr->attr.data, hdr.attr.length);
	if (err) {
		err = -EFAULT;
		goto err_exit;
	}

	xsc_cmd_exec(xdev, in, hdr.attr.length, out, hdr.attr.length);

	if (copy_to_user((void *)user_hdr, &hdr, sizeof(hdr)))
		err = -EFAULT;
	if (copy_to_user((void *)user_hdr->attr.data, out, hdr.attr.length))
		err = -EFAULT;
err_exit:
	kfree(in);
	kfree(out);
	return err;
}

static int _rdma_ctrl_reg_cb(struct xsc_bdf_file *file, unsigned int cmd,
			     struct xsc_ioctl_hdr __user *user_hdr, void *data)
{
	struct xsc_core_device *xdev = file->xdev;
	int err;

	switch (cmd) {
	case XSC_IOCTL_CMDQ:
		err = _rdma_ctrl_ioctl_cmdq(xdev, user_hdr);
		break;
	case XSC_IOCTL_DRV_GET:
	case XSC_IOCTL_DRV_SET:
		// TODO refactor to split driver get and set
		err = _rdma_ctrl_ioctl_getinfo(xdev, user_hdr);
		break;
	default:
		err = -EFAULT;
		break;
	}

	return err;
}

static void _rdma_ctrl_reg_fini(void)
{
	xsc_port_ctrl_cb_dereg(XSC_RDMA_CTRL_NAME);
}

static int _rdma_ctrl_reg_init(void)
{
	int ret;

	ret = xsc_port_ctrl_cb_reg(XSC_RDMA_CTRL_NAME, _rdma_ctrl_reg_cb, NULL);
	if (ret != 0)
		pr_err("failed to register port control node for %s\n", XSC_RDMA_CTRL_NAME);

	return ret;
}

void xsc_rdma_ctrl_fini(void)
{
	_rdma_ctrl_reg_fini();
}

int xsc_rdma_ctrl_init(void)
{
	return _rdma_ctrl_reg_init();
}

