// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/export.h>
#include <linux/etherdevice.h>
#include "common/xsc_core.h"
#include "common/xsc_cmd.h"
#include "eswitch.h"
#include "common/xsc_fs.h"
#include "net/xsc_eth.h"
#include "common/xsc_lag.h"

static int _xsc_query_vport_state(struct xsc_core_device *dev, u16 opmod,
				  u16 vport, void *out, int outlen)
{
	struct xsc_query_vport_state_in in;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_VPORT_STATE);
	in.vport_number = cpu_to_be16(vport);
	if (vport)
		in.other_vport = 1;

	return xsc_cmd_exec(dev, &in, sizeof(in), out, outlen);
}

u8 xsc_query_vport_state(struct xsc_core_device *dev, u16 opmod, u16 vport)
{
	struct xsc_query_vport_state_out out;

	memset(&out, 0, sizeof(out));
	_xsc_query_vport_state(dev, opmod, vport, &out, sizeof(out));

	return out.state;
}
EXPORT_SYMBOL(xsc_query_vport_state);

int xsc_modify_vport_admin_state(struct xsc_core_device *dev, u16 opmod,
				 u16 vport, u8 other_vport, u8 state)
{
	struct xsc_modify_vport_state_in in;
	struct xsc_modify_vport_state_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_VPORT_STATE);
	in.vport_number = cpu_to_be16(vport);
	in.other_vport = other_vport;
	in.admin_state = state;

	return xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
}

int __xsc_query_nic_vport_context(struct xsc_core_device *dev,
				  u16 vport, void *out, int outlen,
					 int force_other)
{
	struct xsc_query_nic_vport_context_in in;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_NIC_VPORT_CONTEXT);
	in.vport_number = cpu_to_be16(vport);
	if (vport || force_other)
		in.other_vport = 1;

	return xsc_cmd_exec(dev, &in, sizeof(in), out, outlen);
}

static int xsc_query_nic_vport_context(struct xsc_core_device *dev, u16 vport,
				       void *out, int outlen)
{
	return __xsc_query_nic_vport_context(dev, vport, out, outlen, 0);
}

static void xsc_nic_isolate_and_drop_modify(struct xsc_core_device *dev,
					    struct xsc_modify_nic_vport_context_in *in)
{
	u16 caps = 0;
	u16 caps_mask = 0;

	if (xsc_get_pf_isolate_config(dev, true)) {
		caps = BIT(XSC_TBM_CAP_PF_ISOLATE_CONFIG);
		caps_mask = BIT(XSC_TBM_CAP_PF_ISOLATE_CONFIG);
	}

	if (xsc_get_mac_drop_config(dev, true)) {
		caps |= BIT(XSC_TBM_CAP_MAC_DROP_CONFIG);
		caps_mask |= BIT(XSC_TBM_CAP_MAC_DROP_CONFIG);
	}

	in->caps |= cpu_to_be16(caps);
	in->caps_mask |= cpu_to_be16(caps_mask);
}

int xsc_modify_nic_vport_context(struct xsc_core_device *dev, void *in,
				 int inlen)
{
	struct xsc_modify_nic_vport_context_out out;
	struct xsc_modify_nic_vport_context_in *tmp;
	int err;

	memset(&out, 0, sizeof(out));
	tmp = (struct xsc_modify_nic_vport_context_in *)in;
	tmp->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	err = xsc_cmd_exec(dev, in, inlen, &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(dev, "fail to modify nic vport err=%d status=%d\n",
			     err, out.hdr.status);
	}
	return err;
}

int xsc_modify_nic_vport_min_inline(struct xsc_core_device *dev,
				    u16 vport, u8 min_inline)
{
	struct xsc_modify_nic_vport_context_in in;

	memset(&in, 0, sizeof(in));
	in.field_select.min_inline = 1;
	in.vport_number = vport;
	in.other_vport = 1;
	in.nic_vport_ctx.min_wqe_inline_mode = min_inline;

	return xsc_modify_nic_vport_context(dev, &in, sizeof(in));
}

static int __xsc_query_nic_vport_mac_address(struct xsc_core_device *dev,
					     u16 vport, u8 *addr,
					     int force_other)
{
	struct xsc_query_nic_vport_context_out out;
	u8 *out_addr;
	int err;

	memset(&out, 0, sizeof(out));
	out_addr = out.nic_vport_ctx.permanent_address;

	err = __xsc_query_nic_vport_context(dev, vport, &out, sizeof(out),
					    force_other);
	if (!err)
		ether_addr_copy(addr, out_addr);

	return err;
}

int xsc_query_other_nic_vport_mac_address(struct xsc_core_device *dev,
					  u16 vport, u8 *addr)
{
	return __xsc_query_nic_vport_mac_address(dev, vport, addr, 1);
}
EXPORT_SYMBOL_GPL(xsc_query_other_nic_vport_mac_address);

int xsc_query_nic_vport_mac_address(struct xsc_core_device *dev,
				    u16 vport, u8 *addr)
{
	return __xsc_query_nic_vport_mac_address(dev, vport, addr, 0);
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_mac_address);

static int __xsc_modify_nic_vport_mac_address(struct xsc_core_device *dev,
					      u16 vport, u8 *addr, int force_other, bool perm_mac)
{
	struct xsc_modify_nic_vport_context_in *in;
	struct xsc_modify_nic_vport_context_out out;
	struct xsc_adapter *adapter = netdev_priv(dev->netdev);
	struct xsc_vport *evport = NULL;
	int err, in_sz;
	int i = 0;
	u8 *mac_addr;
	u16 caps = 0;
	u16 caps_mask = 0;
	u16 lag_id = xsc_get_lag_id(dev);

	memset(&out, 0, sizeof(out));

	in_sz = sizeof(struct xsc_modify_nic_vport_context_in) + 2;

	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->lag_id = cpu_to_be16(lag_id);

	if (perm_mac) {
		in->field_select.permanent_address = 1;
		mac_addr = in->nic_vport_ctx.permanent_address;
	} else {
		in->field_select.current_address = 1;
		mac_addr = in->nic_vport_ctx.current_address;
	}

	if (force_other) {
		in->other_vport = 1;
		in->vport_number = cpu_to_be16(vport);
		evport = xsc_eswitch_get_vport(adapter->xdev->priv.eswitch, i + 1);
	}

	if (xsc_get_pp_bypass_res(dev, false))
		caps |= BIT(XSC_TBM_CAP_PP_BYPASS);
	caps_mask |= BIT(XSC_TBM_CAP_PP_BYPASS);
	in->caps = cpu_to_be16(caps);
	in->caps_mask = cpu_to_be16(caps_mask);

	xsc_nic_isolate_and_drop_modify(dev, in);

	ether_addr_copy(mac_addr, addr);

	in->field_select.addresses_list = 1;
	if (evport)
		in->nic_vport_ctx.vlan = cpu_to_be16(evport->vlan_id);

	in->nic_vport_ctx.vlan_allowed = 1;

	err = xsc_modify_nic_vport_context(dev, in, in_sz);
	if (be16_to_cpu(out.outer_vlan_id))
		goto ret;

	for (i = 0; i < VLAN_N_VID; i++) {
		if (test_bit(i, adapter->vlan_params.active_cvlans)) {
			in->nic_vport_ctx.vlan = cpu_to_be16(i);
			in->nic_vport_ctx.vlan_allowed = 1;
			err |= xsc_modify_nic_vport_context(dev, in, in_sz);
		}
		if (test_bit(i, adapter->vlan_params.active_svlans)) {
			in->nic_vport_ctx.vlan = cpu_to_be16(i);
			in->nic_vport_ctx.vlan_allowed = 1;
			err |= xsc_modify_nic_vport_context(dev, in, in_sz);
		}
	}

ret:
	kfree(in);
	return err;
}

static int __xsc_modify_vport_max_rate(struct xsc_core_device *dev,
				       u16 vport, u32 rate)
{
	struct xsc_vport_rate_limit_mobox_in  in;
	struct xsc_vport_rate_limit_mobox_out out;
	int err = 0;

	memset(&in, 0, sizeof(struct xsc_vport_rate_limit_mobox_in));
	memset(&out, 0, sizeof(struct xsc_vport_rate_limit_mobox_out));

	in.vport_number = cpu_to_be16(vport);
	if (vport)
		in.other_vport = 1;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_SET_VPORT_RATE_LIMIT);
	in.rate = cpu_to_be32(rate);

	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(dev, "modify_vport_max_rate failed!err=%d, status=%u\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return 0;
}

int xsc_modify_other_nic_vport_mac_address(struct xsc_core_device *dev,
					   u16 vport, u8 *addr, bool perm_mac)
{
	return __xsc_modify_nic_vport_mac_address(dev, vport, addr, 1, perm_mac);
}
EXPORT_SYMBOL(xsc_modify_other_nic_vport_mac_address);

int xsc_modify_vport_max_rate(struct xsc_core_device *dev,
			      u16 vport, u32 rate)
{
	return __xsc_modify_vport_max_rate(dev, vport, rate);
}
EXPORT_SYMBOL(xsc_modify_vport_max_rate);

int xsc_modify_nic_vport_mac_address(struct xsc_core_device *dev,
				     u16 vport, u8 *addr, bool perm_mac)
{
	return __xsc_modify_nic_vport_mac_address(dev, vport, addr, 0, perm_mac);
}
EXPORT_SYMBOL(xsc_modify_nic_vport_mac_address);

int xsc_query_nic_vport_mtu(struct xsc_core_device *dev, u16 *mtu)
{
	struct xsc_query_nic_vport_context_out out;
	int err;

	memset(&out, 0, sizeof(out));
	err = xsc_query_nic_vport_context(dev, 0, &out, sizeof(out));
	if (!err)
		*mtu = out.nic_vport_ctx.mtu;

	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_mtu);

int xsc_modify_nic_vport_mtu(struct xsc_core_device *dev, u16 mtu)
{
	struct xsc_modify_nic_vport_context_in in;
	int err;

	memset(&in, 0, sizeof(in));
	in.field_select.mtu = 1;
	in.nic_vport_ctx.mtu = mtu;

	err = xsc_modify_nic_vport_context(dev, &in, sizeof(in));

	return err;
}
EXPORT_SYMBOL_GPL(xsc_modify_nic_vport_mtu);

int xsc_query_nic_vport_mac_list(struct xsc_core_device *dev,
				 u16 vport,
				 enum xsc_list_type list_type,
				 u8 addr_list[][ETH_ALEN],
				 int *list_size)
{
	struct xsc_query_nic_vport_context_in in;
	struct xsc_query_nic_vport_context_out *out;
	int max_list_size;
	int req_list_size;
	int out_sz;
	int err;
	int i;

	req_list_size = *list_size;

	max_list_size = list_type == XSC_NVPRT_LIST_TYPE_UC ?
		1 << dev->caps.log_max_current_uc_list :
		1 << dev->caps.log_max_current_mc_list;

	if (req_list_size > max_list_size) {
		xsc_core_warn(dev, "Requested list size (%d) > (%d) max_list_size\n",
			      req_list_size, max_list_size);
		req_list_size = max_list_size;
	}

	out_sz = sizeof(struct xsc_query_nic_vport_context_out) +
			req_list_size * 8;

	memset(&in, 0, sizeof(in));
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	in.hdr.opcode = XSC_CMD_OP_QUERY_NIC_VPORT_CONTEXT;
	in.allowed_list_type = list_type;
	in.vport_number = vport;
	in.other_vport = 1;

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, out_sz);
	if (err)
		goto out;

	req_list_size = out->nic_vport_ctx.allowed_list_size;
	*list_size = req_list_size;
	for (i = 0; i < req_list_size; i++) {
		u8 *mac_addr = (u8 *)out->nic_vport_ctx.current_uc_mac_address[i];

		ether_addr_copy(addr_list[i], mac_addr);
	}
out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_mac_list);

int xsc_modify_nic_vport_mac_list(struct xsc_core_device *dev,
				  enum xsc_list_type list_type,
				  u8 addr_list[][ETH_ALEN],
				  int list_size)
{
	struct xsc_modify_nic_vport_context_out out;
	struct xsc_modify_nic_vport_context_in *in;
	int max_list_size;
	int in_sz;
	int err;
	int i;

	max_list_size = list_type == XSC_NVPRT_LIST_TYPE_UC ?
		 1 << dev->caps.log_max_current_uc_list :
		 1 << dev->caps.log_max_current_mc_list;

	if (list_size > max_list_size)
		return -ENOSPC;

	in_sz = sizeof(struct xsc_modify_nic_vport_context_in) +
		list_size * 8;
	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->hdr.opcode = XSC_CMD_OP_MODIFY_NIC_VPORT_CONTEXT;
	in->field_select.addresses_list = 1;
	in->nic_vport_ctx.allowed_list_type = list_type;
	in->nic_vport_ctx.allowed_list_size = list_size;

	for (i = 0; i < list_size; i++) {
		u8 *curr_mac =
			(u8 *)(in->nic_vport_ctx.current_uc_mac_address[i]);
		ether_addr_copy(curr_mac, addr_list[i]);
	}

	memset(&out, 0, sizeof(out));
	err = xsc_cmd_exec(dev, in, in_sz, &out, sizeof(out));
	kfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_modify_nic_vport_mac_list);

int xsc_nic_vport_add_uc_mac(struct xsc_core_device *xdev,
			     u8 *mac_addr, u16 *pct_prio)
{
	struct xsc_modify_nic_vport_uc_mac_in in;
	struct xsc_modify_nic_vport_uc_mac_out out;
	int err;

	memset(&in, 0, sizeof(in));

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_VPORT_UC_MAC);
	in.add_mac = true;
	ether_addr_copy(in.mac_addr, mac_addr);

	memset(&out, 0, sizeof(out));
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));

	if (err || (out.hdr.status && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)) {
		xsc_core_err(xdev, "Failed to add uc mac err=%d out.status=%u",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	*pct_prio = be16_to_cpu(out.out_pct_prio);

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_nic_vport_add_uc_mac);

int xsc_nic_vport_del_uc_mac(struct xsc_core_device *xdev, u16 pct_prio)
{
	struct xsc_modify_nic_vport_uc_mac_in in;
	struct xsc_modify_nic_vport_uc_mac_out out;
	int err;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_VPORT_UC_MAC);
	in.add_mac = false;
	in.in_pct_prio = cpu_to_be16(pct_prio);

	memset(&out, 0, sizeof(out));
	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));

	if (err || (out.hdr.status && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)) {
		xsc_core_err(xdev, "Failed to del uc mac err=%d out.status=%u",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_nic_vport_del_uc_mac);

int xsc_nic_vport_modify_mc_mac(struct xsc_core_device *xdev, u8 *mac, u8 action)
{
	struct xsc_modify_nic_vport_mc_mac_in in;
	struct xsc_modify_nic_vport_mc_mac_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_VPORT_MC_MAC);
	ether_addr_copy(in.mac, mac);
	in.action = action;

	err = xsc_cmd_exec(xdev, &in, sizeof(in), &out, sizeof(out));

	if (err || (out.hdr.status && out.hdr.status != XSC_CMD_STATUS_NOT_SUPPORTED)) {
		xsc_core_err(xdev, "Failed to mod mc mac err=%d out.status=%u",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_nic_vport_modify_mc_mac);

int xsc_query_nic_vport_vlans(struct xsc_core_device *dev, u32 vport,
			      unsigned long *vlans)
{
	struct xsc_query_nic_vport_context_in in;
	struct xsc_query_nic_vport_context_out *out;
	int req_list_size;
	int out_sz;
	int err;
	int i;

	req_list_size = 1 << dev->caps.log_max_vlan_list;
	out_sz = sizeof(*out) + req_list_size * 8;

	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = XSC_CMD_OP_QUERY_NIC_VPORT_CONTEXT;
	in.allowed_list_type = XSC_NVPRT_LIST_TYPE_VLAN;
	in.vport_number = vport;

	if (vport)
		in.other_vport = 1;

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, out_sz);
	if (err)
		goto out;

	req_list_size = out->nic_vport_ctx.allowed_list_size;

	for (i = 0; i < req_list_size; i++) {
		u16 *vlan_addr = (u16 *)&out->nic_vport_ctx.current_uc_mac_address[i];

		bitmap_set(vlans, (*vlan_addr & 0xfff),  1);
	}
out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_vlans);

int xsc_modify_nic_vport_vlans(struct xsc_core_device *dev,
			       u16 vid, bool add)
{
	struct xsc_modify_nic_vport_context_out out;
	struct xsc_modify_nic_vport_context_in *in;
	int in_sz;
	int err;

	in_sz = sizeof(struct xsc_modify_nic_vport_context_in) + 2;

	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);
	in->field_select.addresses_list = 1;

	in->nic_vport_ctx.vlan_allowed = add;
	in->nic_vport_ctx.allowed_list_type = XSC_NVPRT_LIST_TYPE_VLAN;
	in->nic_vport_ctx.vlan = cpu_to_be16(vid);

	xsc_nic_isolate_and_drop_modify(dev, in);

	memset(&out, 0, sizeof(out));
	err = xsc_cmd_exec(dev, in, in_sz, &out, sizeof(out));
	kfree(in);

	if (err || out.hdr.status) {
		xsc_core_err(dev, "Failed to modify vlan err=%d out.status=%u",
			     err, out.hdr.status);
		return -ENOEXEC;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_modify_nic_vport_vlans);

int xsc_query_nic_vport_system_image_guid(struct xsc_core_device *dev,
					  u64 *system_image_guid)
{
	struct xsc_query_nic_vport_context_out out;

	memset(&out, 0, sizeof(out));
	xsc_query_nic_vport_context(dev, 0, &out, sizeof(out));

	*system_image_guid = out.nic_vport_ctx.system_image_guid;

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_system_image_guid);

int xsc_query_nic_vport_node_guid(struct xsc_core_device *dev, u32 vport,
				  u64 *node_guid)
{
	struct xsc_query_nic_vport_context_out out;

	memset(&out, 0, sizeof(out));
	xsc_query_nic_vport_context(dev, vport, &out, sizeof(out));

	*node_guid = out.nic_vport_ctx.node_guid;

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_node_guid);

static int __xsc_modify_nic_vport_node_guid(struct xsc_core_device *dev,
					    u16 vport, u64 node_guid,
					    int force_other)
{
	struct xsc_modify_nic_vport_context_in in;
	int err;

	/* vport = 0 only if ECPF modifying Host PF */
	if (!vport && !force_other)
		return -EINVAL;
	if (!dev->caps.vport_group_manager)
		return -EACCES;

	memset(&in, 0, sizeof(in));
	in.field_select.node_guid = 1;
	in.vport_number = vport;
	if (vport || force_other)
		in.other_vport = 1;

	in.nic_vport_ctx.node_guid = node_guid;

	err = xsc_modify_nic_vport_context(dev, &in, sizeof(in));

	return err;
}

int xsc_modify_nic_vport_node_guid(struct xsc_core_device *dev,
				   u16 vport, u64 node_guid)
{
	return __xsc_modify_nic_vport_node_guid(dev, vport, node_guid, 0);
}

int xsc_modify_other_nic_vport_node_guid(struct xsc_core_device *dev,
					 u16 vport, u64 node_guid)
{
	return __xsc_modify_nic_vport_node_guid(dev, vport, node_guid, 1);
}

int xsc_query_nic_vport_qkey_viol_cntr(struct xsc_core_device *dev,
				       u16 *qkey_viol_cntr)
{
	struct xsc_query_nic_vport_context_out out;

	memset(&out, 0, sizeof(out));
	xsc_query_nic_vport_context(dev, 0, &out, sizeof(out));

	*qkey_viol_cntr = out.nic_vport_ctx.qkey_violation_counter;

	return 0;
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_qkey_viol_cntr);

int xsc_query_hca_vport_gid(struct xsc_core_device *dev, u8 other_vport,
			    u8 port_num, u16 vf_num, u16 gid_index,
			    union ib_gid *gid)
{
	int in_sz = sizeof(struct xsc_query_hca_vport_gid_in);
	int out_sz = sizeof(struct xsc_query_hca_vport_gid_out);
	struct xsc_query_hca_vport_gid_in *in;
	struct xsc_query_hca_vport_gid_out *out;
	int is_group_manager;
	union ib_gid *tmp;
	int tbsz;
	int nout;
	int err;

	is_group_manager = dev->caps.vport_group_manager;
	tbsz = dev->caps.port[port_num].gid_table_len;
	xsc_core_dbg(dev, "vf_num %d, index %d, gid_table_size %d\n",
		     vf_num, gid_index, tbsz);

	if (gid_index > tbsz && gid_index != 0xffff)
		return -EINVAL;

	if (gid_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * sizeof(*gid);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	in->hdr.opcode = XSC_CMD_OP_QUERY_HCA_VPORT_GID;
	if (other_vport) {
		if (is_group_manager) {
			in->vport_number = vf_num;
			in->other_vport = 1;
		} else {
			err = -EPERM;
			goto out;
		}
	}

	in->gid_index = gid_index;
	in->port_num = port_num;

	err = xsc_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	tmp = (union ib_gid *)((void *)out +
			sizeof(struct xsc_query_hca_vport_gid_out));
	gid->global.subnet_prefix = tmp->global.subnet_prefix;
	gid->global.interface_id = tmp->global.interface_id;

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_hca_vport_gid);

int xsc_query_hca_vport_pkey(struct xsc_core_device *dev, u8 other_vport,
			     u8 port_num, u16 vf_num, u16 pkey_index,
			     u16 *pkey)
{
	int in_sz = sizeof(struct xsc_query_hca_vport_pkey_in);
	int out_sz = sizeof(struct xsc_query_hca_vport_pkey_out);
	struct xsc_query_hca_vport_pkey_in *in;
	struct xsc_query_hca_vport_pkey_out *out;
	int is_group_manager;
	void *pkarr;
	int nout;
	int tbsz;
	int err;
	int i;

	is_group_manager = dev->caps.vport_group_manager;

	tbsz = dev->caps.port[port_num].pkey_table_len;
	if (pkey_index > tbsz && pkey_index != 0xffff)
		return -EINVAL;

	if (pkey_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * sizeof(*pkey);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	in->hdr.opcode = XSC_CMD_OP_QUERY_HCA_VPORT_PKEY;
	if (other_vport) {
		if (is_group_manager) {
			in->vport_number = vf_num;
			in->other_vport = 1;
		} else {
			err = -EPERM;
			goto out;
		}
	}
	in->pkey_index = pkey_index;

	if (dev->caps.num_ports == 2)
		in->port_num = port_num;

	err = xsc_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	pkarr = out->pkey;
	for (i = 0; i < nout; i++, pkey++, pkarr += sizeof(*pkey))
		*pkey = *(u16 *)pkarr;

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_hca_vport_pkey);

int xsc_query_hca_vport_context(struct xsc_core_device *dev,
				u8 other_vport, u8 port_num,
				u16 vf_num,
				struct xsc_hca_vport_context *rep)
{
	struct xsc_query_hca_vport_context_out *out = NULL;
	struct xsc_query_hca_vport_context_in in;
	int is_group_manager;
	void *ctx;
	int err;

	is_group_manager = dev->caps.vport_group_manager;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = XSC_CMD_OP_QUERY_HCA_VPORT_CONTEXT;

	if (other_vport) {
		if (is_group_manager) {
			in.other_vport = 1;
			in.vport_number = vf_num;
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	if (dev->caps.num_ports == 2)
		in.port_num = port_num;

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out));
	if (err)
		goto ex;

	ctx = &out->hca_vport_ctx;
	memcpy(rep, ctx, sizeof(struct xsc_hca_vport_context));

ex:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_hca_vport_context);

int xsc_query_hca_vport_node_guid(struct xsc_core_device *dev,
				  u64 *node_guid)
{
	struct xsc_hca_vport_context *rep;
	int err;

	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = xsc_query_hca_vport_context(dev, 0, 1, 0, rep);
	if (!err)
		*node_guid = rep->node_guid;

	kfree(rep);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_hca_vport_node_guid);

int xsc_query_nic_vport_promisc(struct xsc_core_device *dev,
				u16 vport,
				int *promisc,
				int *allmcast)
{
	struct xsc_query_nic_vport_context_out *out;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = xsc_query_nic_vport_context(dev, vport, out, sizeof(*out));
	if (err)
		goto out;

	*promisc = out->nic_vport_ctx.promisc;
	*allmcast = out->nic_vport_ctx.allmcast;

out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_nic_vport_promisc);

int xsc_modify_nic_vport_promisc(struct xsc_core_device *dev,
				 bool allmulti_flag, bool promisc_flag,
				 int allmulti, int promisc)
{
	struct xsc_modify_nic_vport_context_in *in;
	int err;

	in = kvzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select.allmcast = allmulti_flag;
	in->nic_vport_ctx.allmcast = allmulti;

	in->field_select.promisc = promisc_flag;
	in->nic_vport_ctx.promisc = promisc;

	err = xsc_modify_nic_vport_context(dev, in, sizeof(*in));

	kvfree(in);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_modify_nic_vport_promisc);

int xsc_modify_nic_vport_spoofchk(struct xsc_core_device *dev,
				  u16 vport, int spoofchk)
{
	struct xsc_modify_nic_vport_context_in *in;
	int err;

	in = kvzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->other_vport = 1;
	in->vport_number = cpu_to_be16(vport);
	in->field_select.spoofchk = 1;
	in->nic_vport_ctx.spoofchk = spoofchk;

	err = xsc_modify_nic_vport_context(dev, in, sizeof(*in));

	kvfree(in);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_modify_nic_vport_spoofchk);

int xsc_modify_nic_vport_trust(struct xsc_core_device *dev,
			       u16 vport, bool trust)
{
	struct xsc_modify_nic_vport_context_in *in;
	int err;

	in = kvzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->other_vport = 1;
	in->vport_number = cpu_to_be16(vport);
	in->field_select.trust = 1;
	in->nic_vport_ctx.trust = (trust ? 1 : 0);

	err = xsc_modify_nic_vport_context(dev, in, sizeof(*in));

	kvfree(in);

	return err;
}
EXPORT_SYMBOL_GPL(xsc_modify_nic_vport_trust);

int xsc_query_vport_counter(struct xsc_core_device *dev, u8 other_vport,
			    int vf, u8 port_num, void *out,
			    size_t out_sz)
{
	struct xsc_query_vport_counter_in *in;
	int	is_group_manager;
	int	err;

	is_group_manager = dev->caps.vport_group_manager;
	in = kvzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		return err;
	}

	in->hdr.opcode = XSC_CMD_OP_QUERY_VPORT_COUNTER;
	if (other_vport) {
		if (is_group_manager) {
			in->other_vport = 1;
			in->vport_number = (vf + 1);
		} else {
			err = -EPERM;
			goto free;
		}
	}

	if (dev->caps.num_ports == 2)
		in->port_num = port_num;

	err = xsc_cmd_exec(dev, in, sizeof(*in), out, out_sz);
free:
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(xsc_query_vport_counter);

int xsc_modify_hca_vport_context(struct xsc_core_device *dev,
				 u8 other_vport, u8 port_num,
				 int vf,
				 struct xsc_hca_vport_context *req)
{
	struct xsc_modify_hca_vport_context_in in;
	struct xsc_modify_hca_vport_context_out out;
	int is_group_manager;
	int err;

	xsc_core_dbg(dev, "vf %d\n", vf);
	is_group_manager = dev->caps.vport_group_manager;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = XSC_CMD_OP_MODIFY_HCA_VPORT_CONTEXT;
	if (other_vport) {
		if (is_group_manager) {
			in.other_vport = 1;
			in.vport_number = vf;
		} else {
			err = -EPERM;
			goto err;
		}
	}

	if (dev->caps.num_ports > 1)
		in.port_num = port_num;
	memcpy(&in.hca_vport_ctx, req, sizeof(*req));
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
err:
	return err;
}
EXPORT_SYMBOL_GPL(xsc_modify_hca_vport_context);

/**
 * xsc_eswitch_get_total_vports - Get total vports of the eswitch
 *
 * @dev:	Pointer to core device
 *
 * xsc_eswitch_get_total_vports returns total number of vports for
 * the eswitch.
 */
u16 xsc_eswitch_get_total_vports(const struct xsc_core_device *dev)
{
	return XSC_SPECIAL_VPORTS(dev) + xsc_core_max_vfs(dev);
}
EXPORT_SYMBOL(xsc_eswitch_get_total_vports);
