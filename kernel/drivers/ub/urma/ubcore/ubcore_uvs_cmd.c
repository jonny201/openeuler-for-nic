// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore uvs cmd implement
 * Author: Ji Lei
 * Create: 2023-07-03
 * Note:
 * History: 2023-07-03: create file
 */

#include <net/net_namespace.h>
#include <linux/slab.h>
#include <urma/ubcore_api.h>
#include "ubcore_device.h"
#include "ubcore_priv.h"
#include "ubcore_tpg.h"
#include "ubcore_utp.h"
#include "ubcore_ctp.h"
#include "ubcore_netdev.h"
#include "ubcore_tp.h"
#include <urma/ubcore_uapi.h>
#include "ubcore_device.h"
#include "urma/ubcore_jetty.h"
#include "ubcore_main.h"
#include "ubcore_uvs_cmd.h"

static int ubcore_uvs_cmd_channel_init(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_channel_init arg = {0};
	int ret;

	ret = ubcore_copy_from_user(&arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_channel_init));
	if (ret != 0)
		return -EPERM;

	arg.in.userspace_in[UBCORE_CMD_CHANNEL_INIT_SIZE - 1] = '\0';
	if (strlen(arg.in.userspace_in) == 0 || strcmp(arg.in.userspace_in, "Hello ubcore!") != 0)
		return -EPERM;

	ubcore_log_info("ubcore recv uvs user space call, ctx is %s.\n", arg.in.userspace_in);

	(void)strncpy(arg.out.kernel_out, "Hello uvs!", strlen("Hello uvs!"));

	ret = ubcore_copy_to_user(
		(void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_channel_init)
	);
	if (ret != 0)
		return -EPERM;

	return 0;
}

static void ubcore_set_tp_cfg_with_cmd(struct ubcore_tp_cfg *cfg, struct ubcore_cmd_tp_cfg *cmd)
{
	cfg->flag = cmd->flag;
	if (cmd->trans_mode == UBCORE_TP_RM) {
		cfg->local_eid = cmd->local_eid;
		cfg->peer_eid = cmd->peer_eid;
	} else {
		cfg->local_jetty = cmd->local_jetty;
		cfg->peer_jetty = cmd->peer_jetty;
	}

	cfg->trans_mode = cmd->trans_mode;
	cfg->retry_num = cmd->retry_num;
	cfg->retry_factor = cmd->retry_factor;
	cfg->ack_timeout = cmd->ack_timeout;
	cfg->dscp = cmd->dscp;
	cfg->oor_cnt = cmd->oor_cnt;
	cfg->fe_idx = cmd->fe_idx;
}

static struct ubcore_tp_cfg *ubcore_get_multi_tp_cfg(uint32_t tp_cnt,
	struct ubcore_cmd_tp_cfg *arg, struct ubcore_tpg *tpg)
{
	struct ubcore_tp_cfg *tp_cfgs;
	uint32_t i;

	tp_cfgs = kcalloc(1, tp_cnt * sizeof(struct ubcore_tp_cfg), GFP_KERNEL);
	if (tp_cfgs == NULL)
		return NULL;

	for (i = 0; i < tp_cnt; i++) {
		ubcore_set_tp_cfg_with_cmd(&tp_cfgs[i], &arg[i]);
		tp_cfgs[i].tpg = tpg;
	}
	return tp_cfgs;
}

#define RC_TP_CNT 2

/* create tpg and multiple tp in the tpg at initiator or target */
static struct ubcore_tpg *ubcore_create_tpg_and_multi_tp(struct ubcore_device *dev,
	struct ubcore_tpg_cfg *tpg_cfg, struct ubcore_cmd_tp_cfg *tp_cfg_arg)
{
	struct ubcore_tp_cfg *tp_cfgs;
	struct ubcore_tpg *tpg;
	int ret = 0;

	if (tpg_cfg->tp_cnt > UBCORE_MAX_TP_CNT_IN_GRP || tpg_cfg->tp_cnt == 0 ||
		(tpg_cfg->trans_mode == UBCORE_TP_RC && tpg_cfg->tp_cnt != RC_TP_CNT))
		return ERR_PTR(-EINVAL);

	tpg = ubcore_create_tpg(dev, tpg_cfg);
	if (IS_ERR_OR_NULL(tpg))
		return tpg;

	/* create tp in the tpg */
	tp_cfgs = ubcore_get_multi_tp_cfg(tpg_cfg->tp_cnt, tp_cfg_arg, tpg);
	if (tp_cfgs == NULL) {
		ret = -ENOMEM;
		goto destroy_tpg;
	}
	ret = ubcore_create_multi_tp(dev, tpg, tp_cfgs);
	if (ret)
		goto free_tp_cfg;

	kfree(tp_cfgs);
	return tpg;

free_tp_cfg:
	kfree(tp_cfgs);
destroy_tpg:
	ubcore_tpg_kref_put(tpg);
	return ERR_PTR(ret);
}

static int ubcore_parse_ta_get_jetty(struct ubcore_device *dev, struct ubcore_tp_advice *advice,
	struct ubcore_ta_data *ta_data)
{
	struct ubcore_tp_meta *meta;
	struct ubcore_jetty *jetty;
	struct ubcore_jfs *jfs;

	advice->ta.type = ta_data->ta_type;
	meta = &advice->meta;

	switch (ta_data->ta_type) {
	case UBCORE_TA_JFS_TJFR:
		jfs = ubcore_find_get_jfs(dev, ta_data->jetty_id.id);
		if (jfs == NULL) {
			ubcore_log_err("Failed to find jfs by jetty id %u", ta_data->jetty_id.id);
			return -1;
		}
		meta->ht = ubcore_get_tptable(jfs->tptable);
		advice->ta.jfs = jfs;
		advice->ta.tjetty_id = ta_data->tjetty_id;
		break;
	case UBCORE_TA_JETTY_TJETTY:
		jetty = ubcore_find_get_jetty(dev, ta_data->jetty_id.id);
		if (jetty == NULL) {
			ubcore_log_err("Failed to find jetty by jetty id %u", ta_data->jetty_id.id);
			return -1;
		}
		meta->ht = ubcore_get_tptable(jetty->tptable);
		advice->ta.jetty = jetty;
		advice->ta.tjetty_id = ta_data->tjetty_id;
		break;
	case UBCORE_TA_NONE:
	case UBCORE_TA_VIRT:
	default:
		return -1;
	}
	ubcore_init_tp_key_jetty_id(&meta->key, &ta_data->tjetty_id);
	advice->meta.hash = ubcore_get_jetty_hash(&ta_data->tjetty_id);
	return 0;
}

static int ubcore_get_active_mtu(struct ubcore_device *dev, uint8_t port_num,
	enum ubcore_mtu *mtu)
{
	struct ubcore_device_status st = { 0 };

	if (dev == NULL || dev->ops == NULL ||
		dev->ops->query_device_status == NULL ||
		port_num >= UBCORE_MAX_PORT_CNT) {
		ubcore_log_err("Invalid parameter");
		return -1;
	}
	if (dev->ops->query_device_status(dev, &st) != 0) {
		ubcore_log_err("Failed to query query_device_status for port %d", port_num);
		return -1;
	}
	if (st.port_status[port_num].state != UBCORE_PORT_ACTIVE) {
		ubcore_log_err("Port %d is not active", port_num);
		return -1;
	}
	*mtu = st.port_status[port_num].active_mtu;
	return 0;
}

static int ubcore_copy_tpg_udrv_data(struct ubcore_cmd_hdr *hdr, struct ubcore_cmd_create_tpg *arg,
	struct ubcore_tp_node *tp_node)
{
	int ret = 0;

	if (ubcore_get_active_mtu(tp_node->tp->ub_dev, 0, &arg->local_mtu) != 0)
		return -1;
	arg->out.tpn[0] = tp_node->tp->tpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_tpg));
	if (ret)
		return -1;

	return ret;
}

static inline void ubcore_set_udata(struct ubcore_udata *udata, struct ubcore_tp_advice *advice,
	struct ubcore_udrv_priv *udrv_data)
{
	udata->uctx = (advice->ta.type == UBCORE_TA_JFS_TJFR ?
		advice->ta.jfs->uctx : advice->ta.jetty->uctx);
	udata->udrv_data = udrv_data;
}

static struct ubcore_tp_node *ubcore_get_tp_node(struct ubcore_device *dev,
	struct ubcore_tp_advice *advice, struct ubcore_tp_cfg *tp_cfg, struct ubcore_udata *udata)
{
	struct ubcore_tp_node *tp_node = NULL;
	struct ubcore_tp *new_tp = NULL;

	tp_node = ubcore_lookup_tpnode(advice->meta.ht, advice->meta.hash, &advice->meta.key);
	if (tp_node == NULL) {
		new_tp = ubcore_create_tp(dev, tp_cfg, udata);
		if (IS_ERR_OR_NULL(new_tp)) {
			ubcore_log_err("Failed to create tp");
			return (void *)new_tp;
		}
		tp_node = ubcore_add_tp_node(advice->meta.ht, advice->meta.hash, &advice->meta.key,
			new_tp, &advice->ta);
		if (tp_node == NULL) {
			(void)ubcore_destroy_tp(new_tp);
			ubcore_log_err("Failed to find and add tp\n");
			return NULL;
		} else if (tp_node != NULL && tp_node->tp != new_tp) {
			(void)ubcore_destroy_tp(new_tp);
			new_tp = NULL;
		}
	}
	return tp_node;
}

static int ubcore_cmd_create_tp(struct ubcore_cmd_hdr *hdr, struct ubcore_cmd_create_tpg *arg)
{
	struct ubcore_tp_advice advice = { 0 };
	struct ubcore_tp_node *tp_node = NULL;
	struct ubcore_device *dev = NULL;
	int ret = 0;

	dev = ubcore_find_device(&arg->ta_data.jetty_id.eid, arg->ta_data.trans_type);
	if (dev == NULL)
		return -ENODEV;

	if (ubcore_parse_ta_get_jetty(dev, &advice, &arg->ta_data) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", advice.ta.type);
		goto put_device;
	} else if (advice.meta.ht == NULL) {
		ubcore_log_info("tp table is already released");
		goto put_jetty;
	}

	tp_node = ubcore_lookup_tpnode(advice.meta.ht, advice.meta.hash, &advice.meta.key);
	if (!tp_node)
		goto put_tptable;

	ret = ubcore_copy_tpg_udrv_data(hdr, arg, tp_node);
	ubcore_tpnode_kref_put(tp_node);
	if (ret)
		goto put_tptable;

	ubcore_put_tptable(advice.meta.ht);
	ubcore_put_ta_jetty(&advice.ta);
	ubcore_put_device(dev);
	return ret;

put_tptable:
	ubcore_put_tptable(advice.meta.ht);
put_jetty:
	ubcore_put_ta_jetty(&advice.ta);
put_device:
	ubcore_put_device(dev);
	return -1;
}

static int ubcore_cmd_create_tpg(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_create_tpg *arg;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret = 0;
	uint32_t i;

	arg = kzalloc(sizeof(struct ubcore_cmd_create_tpg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_create_tpg));
	if (ret != 0)
		goto free_arg;

	if (arg->ta_data.trans_type == UBCORE_TRANSPORT_HNS_UB ||
		arg->ta_data.trans_type == UBCORE_TRANSPORT_IB) {
		ret = ubcore_cmd_create_tp(hdr, arg);
		goto free_arg;
	}

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	if (ubcore_get_active_mtu(dev, 0, &arg->local_mtu) != 0)
		goto put_device;

	if (ubcore_get_max_mtu(dev, &arg->out.max_mtu) != 0)
		goto put_device;

	tpg = ubcore_create_tpg_and_multi_tp(dev, &arg->in.tpg_cfg, arg->in.tp_cfg);
	if (IS_ERR_OR_NULL(tpg)) {
		ret = PTR_ERR(tpg);
		goto put_device;
	}

	ret = ubcore_find_add_tpg(dev, tpg);
	if (ret != 0) {
		ubcore_log_err("Failed to add tpg to the tpg table");
		goto destroy_tpg;
	}

	/* fill output */
	arg->out.tpgn = tpg->tpgn;
	for (i = 0; i < tpg->tpg_cfg.tp_cnt; i++)
		arg->out.tpn[i] = tpg->tp_list[i]->tpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_tpg));
	if (ret != 0)
		goto remove_tpg;
	else
		goto put_tpg;

remove_tpg:
	ubcore_find_remove_tpg(dev, tpg->tpgn);
destroy_tpg:
	(void)ubcore_destroy_multi_tp(dev, tpg);
put_tpg:
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_get_tp_state_attr_and_mask(enum ubcore_tp_state s, uint32_t tp_cnt,
	struct ubcore_tp_attr **attr, union ubcore_tp_attr_mask **mask)
{
	union ubcore_tp_attr_mask *_mask;
	struct ubcore_tp_attr *_attr;
	uint32_t i;

	_attr = kcalloc(1, tp_cnt * sizeof(struct ubcore_tp_attr), GFP_KERNEL);
	if (_attr == NULL)
		return -ENOMEM;

	_mask = kcalloc(1, tp_cnt * sizeof(union ubcore_tp_attr_mask), GFP_KERNEL);
	if (_mask == NULL) {
		kfree(_attr);
		return -ENOMEM;
	}

	for (i = 0; i < tp_cnt; i++) {
		_attr[i].state = s;
		_mask[i].value = 0;
		_mask[i].bs.state = 1;
	}
	*attr = _attr;
	*mask = _mask;
	return 0;
}

static void ubcore_set_vtp_common_cfg(struct ubcore_vtp_cfg *cfg, struct ubcore_cmd_vtp_cfg *cmd)
{
	cfg->fe_idx = cmd->fe_idx;
	cfg->vtpn = cmd->vtpn;
	cfg->local_jetty = cmd->local_jetty;
	cfg->local_eid = cmd->local_eid;
	cfg->peer_eid = cmd->peer_eid;
	cfg->peer_jetty = cmd->peer_jetty;
	cfg->flag = cmd->flag;
	cfg->trans_mode = cmd->trans_mode;
}

static void ubcore_set_vtp2tpg_cfg(struct ubcore_vtp_cfg *cfg,
	struct ubcore_cmd_vtp_cfg *cmd, struct ubcore_tpg *tpg)
{
	ubcore_set_vtp_common_cfg(cfg, cmd);
	cfg->tpg = tpg;
}

static void ubcore_set_vtp2utp_cfg(struct ubcore_vtp_cfg *cfg,
	struct ubcore_cmd_vtp_cfg *cmd, struct ubcore_utp *utp)
{
	ubcore_set_vtp_common_cfg(cfg, cmd);
	cfg->utp = utp;
}

static void ubcore_set_vtp2ctp_cfg(struct ubcore_vtp_cfg *cfg,
	struct ubcore_cmd_vtp_cfg *cmd, struct ubcore_ctp *ctp)
{
	ubcore_set_vtp_common_cfg(cfg, cmd);
	cfg->ctp = ctp;
}

static int ubcore_cmd_create_vtp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_tp *failed_tp[UBCORE_MAX_TP_CNT_IN_GRP];
	union ubcore_tp_attr_mask *rts_mask = NULL;
	struct ubcore_tp_attr *rts_attr = NULL;
	struct ubcore_cmd_create_vtp *arg;
	struct ubcore_vtp_cfg vtp_cfg;
	struct ubcore_vtp *vtp = NULL;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret;

	arg = kzalloc(sizeof(struct ubcore_cmd_create_vtp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_create_vtp));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	/* deal with RM first */
	tpg = ubcore_find_get_tpg(dev, arg->in.tpgn);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg");
		goto put_device;
	}

	/* modify to RTR */
	arg->out.rtr_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, arg->in.rtr_attr,
		arg->in.rtr_mask, failed_tp);
	if (arg->out.rtr_tp_cnt != tpg->tpg_cfg.tp_cnt) {
		/* todonext: modify tp to reset ? */
		ret = -EPERM;
		goto to_user;
	}

	/* modify to RTS */
	ret = ubcore_get_tp_state_attr_and_mask(UBCORE_TP_STATE_RTS, tpg->tpg_cfg.tp_cnt,
		&rts_attr, &rts_mask);
	if (ret != 0)
		goto to_user;

	arg->out.rts_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, rts_attr, rts_mask, failed_tp);
	if (arg->out.rts_tp_cnt != tpg->tpg_cfg.tp_cnt) {
		/* todonext: modify tp to reset ? */
		ret = -EPERM;
		goto to_user;
	}

	ubcore_set_vtp2tpg_cfg(&vtp_cfg, &arg->in.vtp, tpg);
	vtp = ubcore_create_and_map_vtp(dev, &vtp_cfg);
	if (IS_ERR_OR_NULL(vtp)) {
		ret = PTR_ERR(vtp);
		goto to_user;
	}
	vtp->eid_idx = arg->in.eid_idx;
	vtp->upi = arg->in.upi;
	vtp->share_mode = arg->in.share_mode;

	arg->out.vtpn = vtp->cfg.vtpn;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_vtp));
	if (ret != 0)
		(void)ubcore_unmap_vtp(vtp);

	/* Pair with kref_init, then vtp ownership is
	 * transferred to vtp hash table
	 */
	ubcore_vtp_kref_put(vtp);
	goto free_attr;

to_user:
	(void)ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_vtp));
free_attr:
	if (rts_attr != NULL)
		kfree(rts_attr);
	if (rts_mask != NULL)
		kfree(rts_mask);
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_modify_tp_node(struct ubcore_tp_node *tp_node, struct ubcore_tp_attr *tp_attr,
	struct ubcore_udata *udata)
{
	/* Modify REST TO RTR */
	if (tp_node->tp->state == UBCORE_TP_STATE_RESET &&
		ubcore_modify_tp(tp_node->tp->ub_dev, tp_node, tp_attr, *udata) != 0) {
		ubcore_log_err("Failed to modify tp");
		return -1;
	}
	/* modify RTR TO RTS */
	if (tp_node->tp->state == UBCORE_TP_STATE_RTR &&
		ubcore_modify_tp(tp_node->tp->ub_dev, tp_node, tp_attr, *udata) != 0) {
		ubcore_log_err("Failed to modify tp");
		return -1;
	}
	return 0;
}

static int ubcore_cmd_modify_tp(struct ubcore_cmd_hdr *hdr, struct ubcore_cmd_modify_tpg *arg)
{
	struct ubcore_device *dev = NULL;
	struct ubcore_udata udata = { 0 };
	struct ubcore_tp_node *tp_node;
	struct ubcore_tp_advice advice = {0};
	int ret = 0;

	dev = ubcore_find_device(&arg->ta_data.jetty_id.eid, arg->ta_data.trans_type);
	if (dev == NULL)
		return -ENODEV;

	if (ubcore_parse_ta_get_jetty(dev, &advice, &arg->ta_data) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", advice.ta.type);
		goto put_device;
	} else if (advice.meta.ht == NULL) {
		ubcore_log_info("tp table is already released");
		goto put_jetty;
	}

	tp_node = ubcore_lookup_tpnode(advice.meta.ht, advice.meta.hash, &advice.meta.key);
	if (tp_node == NULL) {
		ubcore_log_err("tp node is already released");
		goto put_tptable;
	}

	ubcore_set_udata(&udata, &advice, (struct ubcore_udrv_priv *)&arg->udrv_ext);
	ret = ubcore_modify_tp_node(tp_node, &arg->in.rtr_attr[0], &udata);
	ubcore_tpnode_kref_put(tp_node);
	if (ret)
		goto put_tptable;

	ubcore_put_tptable(advice.meta.ht);
	ubcore_put_ta_jetty(&advice.ta);
	ubcore_put_device(dev);
	return ret;

put_tptable:
	ubcore_put_tptable(advice.meta.ht);
put_jetty:
	ubcore_put_ta_jetty(&advice.ta);
put_device:
	ubcore_put_device(dev);
	return -1;
}

static int ubcore_cmd_modify_tpg(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_tp *failed_tp[UBCORE_MAX_TP_CNT_IN_GRP];
	union ubcore_tp_attr_mask *rts_mask = NULL;
	struct ubcore_tp_attr *rts_attr = NULL;
	struct ubcore_cmd_modify_tpg *arg;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret;

	arg = kzalloc(sizeof(struct ubcore_cmd_modify_tpg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_modify_tpg));
	if (ret != 0)
		goto free_arg;

	if (arg->in.peer_tp_cnt > UBCORE_MAX_TP_CNT_IN_GRP) {
		ret = -EINVAL;
		ubcore_log_err("arg->in.peer_tp_cnt %d too big", arg->in.peer_tp_cnt);
		goto free_arg;
	}

	if (arg->ta_data.trans_type == UBCORE_TRANSPORT_HNS_UB ||
		arg->ta_data.trans_type == UBCORE_TRANSPORT_IB) {
		ret = ubcore_cmd_modify_tp(hdr, arg);
		goto free_arg;
	}

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	/* deal with RM first */
	tpg = ubcore_find_get_tpg(dev, arg->in.tpgn);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg");
		goto put_device;
	}

	if (tpg->tpg_cfg.tp_cnt > arg->in.peer_tp_cnt) {
		ret = ubcore_destroy_multi_tp_from_index(dev, tpg, arg->in.peer_tp_cnt);
		if (ret == (tpg->tpg_cfg.tp_cnt - arg->in.peer_tp_cnt)) {
			tpg->tpg_cfg.tp_cnt = arg->in.peer_tp_cnt;
		} else {
			ubcore_log_err("ubcore_destroy_multi_tp_from_index failed %d", ret);
			ret = -EPERM;
			goto to_user;
		}
	}

	/* modify to RTR */
	arg->out.rtr_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, arg->in.rtr_attr,
		arg->in.rtr_mask, failed_tp);
	if (arg->out.rtr_tp_cnt != tpg->tpg_cfg.tp_cnt) {
		/* todonext: modify tp to reset ? */
		ret = -EPERM;
		goto to_user;
	}

	/* modify to RTS */
	ret = ubcore_get_tp_state_attr_and_mask(UBCORE_TP_STATE_RTS, tpg->tpg_cfg.tp_cnt,
		&rts_attr, &rts_mask);
	if (ret != 0)
		goto to_user;

	arg->out.rts_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, rts_attr, rts_mask, failed_tp);
	if (arg->out.rts_tp_cnt != tpg->tpg_cfg.tp_cnt) {
		/* todonext: modify tp to reset ? */
		ret = -EPERM;
		goto to_user;
	}

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_modify_tpg));

to_user:
	if (ret)
		ubcore_log_warn("ubcore cmd modify tpg to user failed");
	if (rts_attr != NULL)
		kfree(rts_attr);
	if (rts_mask != NULL)
		kfree(rts_mask);
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_modify_tpg_map_vtp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_tp *failed_tp[UBCORE_MAX_TP_CNT_IN_GRP];
	union ubcore_tp_attr_mask *rts_mask = NULL;
	struct ubcore_cmd_modify_tpg_map_vtp *arg;
	struct ubcore_tp_attr *rts_attr = NULL;
	struct ubcore_vtp_cfg vtp_cfg;
	struct ubcore_vtp *vtp = NULL;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret;

	arg = kzalloc(sizeof(struct ubcore_cmd_modify_tpg_map_vtp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr,
			sizeof(struct ubcore_cmd_modify_tpg_map_vtp));
	if (ret != 0)
		goto free_arg;

	if (arg->in.peer_tp_cnt > UBCORE_MAX_TP_CNT_IN_GRP) {
		ret = -EINVAL;
		ubcore_log_err("arg->in.peer_tp_cnt %d too big", arg->in.peer_tp_cnt);
		goto free_arg;
	}

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	/* deal with RM first */
	tpg = ubcore_find_get_tpg(dev, arg->in.tpgn);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg");
		goto put_device;
	}

	if (tpg->tpg_cfg.tp_cnt > arg->in.peer_tp_cnt) {
		ret = ubcore_destroy_multi_tp_from_index(dev, tpg, arg->in.peer_tp_cnt);
		if (ret == (tpg->tpg_cfg.tp_cnt - arg->in.peer_tp_cnt)) {
			tpg->tpg_cfg.tp_cnt = arg->in.peer_tp_cnt;
		} else {
			ubcore_log_err("ubcore_destroy_multi_tp_from_index failed %d", ret);
			ret = -EPERM;
			goto to_user;
		}
	}

	/* modify to RTR */
	arg->out.rtr_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, arg->in.rtr_attr,
		arg->in.rtr_mask, failed_tp);
	if (arg->out.rtr_tp_cnt != tpg->tpg_cfg.tp_cnt) {
		ret = -EPERM;
		goto to_user;
	}

	/* modify to RTS */
	ret = ubcore_get_tp_state_attr_and_mask(UBCORE_TP_STATE_RTS, tpg->tpg_cfg.tp_cnt,
		&rts_attr, &rts_mask);
	if (ret != 0)
		goto to_user;

	arg->out.rts_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, rts_attr, rts_mask, failed_tp);
	if (arg->out.rts_tp_cnt != tpg->tpg_cfg.tp_cnt) {
		ret = -EPERM;
		goto to_user;
	}

	ubcore_set_vtp2tpg_cfg(&vtp_cfg, &arg->in.vtp, tpg);
	vtp = ubcore_check_and_map_vtp(dev, &vtp_cfg, arg->in.role);
	if (vtp == NULL) {
		ret = -EPERM;
		goto to_user;
	}

	vtp->eid_idx = arg->in.eid_idx;
	vtp->upi = arg->in.upi;
	vtp->share_mode = arg->in.share_mode;

	arg->out.vtpn = vtp->cfg.vtpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_modify_tpg_map_vtp));
	if (ret != 0)
		(void)ubcore_check_and_unmap_vtp(vtp, arg->in.role);

	ubcore_vtp_kref_put(vtp);

to_user:
	if (ret)
		ubcore_log_warn("ubcore cmd modify tpg map vtp to user failed");
	if (rts_attr != NULL)
		kfree(rts_attr);
	if (rts_mask != NULL)
		kfree(rts_mask);
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_mark_bind_tjetty(struct ubcore_jetty *jetty, struct ubcore_tp_meta *meta,
	struct ubcore_jetty_id *default_tjetty_id, struct ubcore_ta_data *ta_data)
{
	spin_lock(&meta->ht->lock);
	if (jetty->jetty_cfg.trans_mode == UBCORE_TP_RC &&
		memcmp(&meta->ht->rc_tjetty_id, default_tjetty_id,
			sizeof(struct ubcore_jetty_id)) == 0) {
		meta->ht->rc_tjetty_id = ta_data->jetty_id;
	} else if (jetty->jetty_cfg.trans_mode == UBCORE_TP_RC &&
		memcmp(&meta->ht->rc_tjetty_id,
			&ta_data->jetty_id, sizeof(struct ubcore_jetty_id)) != 0) {
		spin_unlock(&meta->ht->lock);
		ubcore_log_err("the same jetty_id: %u is binded with another remote jetty_id: %pI6c-%u.\n",
			jetty->jetty_id.id, &meta->ht->rc_tjetty_id.eid, meta->ht->rc_tjetty_id.id);
		return -1;
	}
	spin_unlock(&meta->ht->lock);
	return 0;
}

static int ubcore_para_target_ta_get_jetty(struct ubcore_device *dev,
	struct ubcore_tp_advice *advice, struct ubcore_ta_data *ta_data)
{
	struct ubcore_jetty_id default_tjetty_id;
	struct ubcore_tp_meta *meta;
	struct ubcore_jetty *jetty;
	struct ubcore_jfr *jfr;
	int ret = 0;

	advice->ta.type = ta_data->ta_type;
	meta = &advice->meta;

	(void)memset(&default_tjetty_id, 0,
		sizeof(struct ubcore_jetty_id));

	switch (ta_data->ta_type) {
	case UBCORE_TA_JFS_TJFR:
		jfr = ubcore_find_get_jfr(dev, ta_data->tjetty_id.id);
		if (jfr != NULL) {
			meta->ht = ubcore_get_tptable(jfr->tptable);
			advice->ta.jfr = jfr;
			advice->ta.tjetty_id = ta_data->jetty_id;
		}
		break;
	case UBCORE_TA_JETTY_TJETTY:
		jetty = ubcore_find_get_jetty(dev, ta_data->tjetty_id.id);
		if (jetty != NULL) {
			meta->ht = ubcore_get_tptable(jetty->tptable);
			advice->ta.jetty = jetty;
			advice->ta.tjetty_id = ta_data->jetty_id;
			ret = ubcore_mark_bind_tjetty(jetty, meta, &default_tjetty_id, ta_data);
			if (ret != 0) {
				ubcore_put_jetty(jetty);
				advice->ta.jetty = NULL;
			}
		}
		break;
	case UBCORE_TA_NONE:
	case UBCORE_TA_VIRT:
	default:
		return -1;
	}
	ubcore_init_tp_key_jetty_id(&meta->key, &ta_data->jetty_id);
	advice->meta.hash = ubcore_get_jetty_hash(&ta_data->jetty_id);
	return ret;
}

static int ubcore_copy_target_tpg_udrv_data(struct ubcore_cmd_hdr *hdr,
	struct ubcore_cmd_create_target_tpg *arg, struct ubcore_tp_node *tp_node)
{
	int ret;

	if (arg->udrv_ext.out_len < tp_node->tp->tp_ext.len) {
		ubcore_log_err("tp_ext memory is not long enough\n");
		return -1;
	}
	arg->udrv_ext.out_len = tp_node->tp->tp_ext.len;
	arg->out.tpn[0] = tp_node->tp->tpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_target_tpg));
	if (ret)
		return -1;

	ret = (int)copy_to_user((void __user *)(uintptr_t)arg->udrv_ext.out_addr,
		(char *)tp_node->tp->tp_ext.addr,
		tp_node->tp->tp_ext.len);

	return ret;
}

static int ubcore_modify_target_tp_node(struct ubcore_tp_node *tp_node,
	struct ubcore_tp_attr *tp_attr, struct ubcore_udata *udata,
	struct ubcore_cmd_create_target_tpg *arg)
{
	/* The receiving side rm mode cannot switch the rts state */
	if (tp_node->tp->trans_mode == UBCORE_TP_RM &&
		tp_node->tp->state == UBCORE_TP_STATE_RTR)
		return 0;

	if (ubcore_get_active_mtu(tp_node->tp->ub_dev, 0, &arg->local_mtu) != 0 &&
		(arg->local_mtu == 0 || arg->peer_mtu == 0))
		return -1;
	tp_attr->mtu = min(arg->local_mtu, arg->peer_mtu);

	udata->udrv_data->in_addr = arg->udrv_ext.in_addr;
	udata->udrv_data->in_len = arg->udrv_ext.in_len;
	if (ubcore_modify_tp(tp_node->tp->ub_dev, tp_node, tp_attr, *udata) != 0) {
		ubcore_log_err("Failed to modify tp");
		return -1;
	}
	return 0;
}

static int ubcore_cmd_create_target_tp(struct ubcore_cmd_hdr *hdr,
	struct ubcore_cmd_create_target_tpg *arg)
{
	struct ubcore_udata udata = { 0 };
	struct ubcore_device *dev = NULL;
	struct ubcore_tp_node *tp_node = NULL;
	struct ubcore_tp_advice advice = { 0 };
	struct ubcore_tp_cfg tp_cfg = { 0 };
	struct ubcore_tp_attr *tp_attr = NULL;

	int ret = 0;

	tp_attr = &arg->in.rtr_attr[0];
	dev = ubcore_find_device(&arg->ta_data.tjetty_id.eid, arg->ta_data.trans_type);
	if (dev == NULL)
		return -ENODEV;

	if (ubcore_para_target_ta_get_jetty(dev, &advice, &arg->ta_data) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", advice.ta.type);
		goto put_device;
	} else if (advice.meta.ht == NULL) {
		ubcore_log_info("tp table is already released");
		goto put_jetty;
	}

	ubcore_set_udata(&udata, &advice, (struct ubcore_udrv_priv *)&arg->udata);
	ubcore_set_tp_cfg_with_cmd(&tp_cfg, &arg->in.tp_cfg[0]);
	tp_node = ubcore_get_tp_node(dev, &advice, &tp_cfg, &udata);
	if (IS_ERR_OR_NULL(tp_node))
		goto put_tptable;

	ret = ubcore_modify_target_tp_node(tp_node, tp_attr, &udata, arg);
	if (ret)
		goto remove_tp_node;

	ret = ubcore_copy_target_tpg_udrv_data(hdr, arg, tp_node);
	if (ret)
		goto remove_tp_node;

	/* The receiving side rm mode cannot switch the rts state */
	if (tp_node->tp->trans_mode == UBCORE_TP_RM && tp_node->tp->state == UBCORE_TP_STATE_RTR) {
		ubcore_tpnode_kref_put(tp_node);
		ubcore_put_tptable(advice.meta.ht);
		ubcore_put_target_ta_jetty(&advice.ta);
		ubcore_put_device(dev);
		return 0;
	}
	if (tp_node->tp->state == UBCORE_TP_STATE_RTR &&
		ubcore_modify_tp(dev, tp_node, tp_attr, udata) != 0) {
		ubcore_log_err("Failed to modify tp");
		ubcore_tpnode_kref_put(tp_node);
		goto put_tptable;
	}

	ubcore_tpnode_kref_put(tp_node);
	ubcore_put_tptable(advice.meta.ht);
	ubcore_put_target_ta_jetty(&advice.ta);
	ubcore_put_device(dev);
	return ret;

remove_tp_node:
	ubcore_tpnode_kref_put(tp_node);
	ubcore_find_remove_tp(advice.meta.ht, advice.meta.hash, &advice.meta.key);
put_tptable:
	ubcore_put_tptable(advice.meta.ht);
put_jetty:
	ubcore_put_target_ta_jetty(&advice.ta);
put_device:
	ubcore_put_device(dev);
	if (IS_ERR(tp_node))
		return PTR_ERR(tp_node);
	return -1;
}

static int ubcore_cmd_modify_tpg_tp_cnt(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_modify_tpg_tp_cnt *arg;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret = 0;

	arg = kzalloc(sizeof(struct ubcore_cmd_modify_tpg_tp_cnt), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_modify_tpg_tp_cnt));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	ubcore_log_info("tpgn_for_modify %d", arg->in.tpgn_for_modify);

	tpg = ubcore_find_get_tpg(dev, arg->in.tpgn_for_modify);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg");
		goto put_device;
	}
	arg->out.tpgn = tpg->tpgn;
	ret = 0;
	if (tpg->tpg_cfg.tp_cnt > arg->in.tp_cnt &&
		arg->in.tp_cnt < UBCORE_MAX_TP_CNT_IN_GRP) {
		if (ubcore_destroy_multi_tp_from_index(dev, tpg, arg->in.tp_cnt) ==
			(tpg->tpg_cfg.tp_cnt - arg->in.tp_cnt)) {
			tpg->tpg_cfg.tp_cnt = arg->in.tp_cnt;
			goto copy_to_user;
		} else {
			ret = -1;
			goto put_tpg;
		}
	}

copy_to_user:
	/* fill output */
	arg->out.tpgn = tpg->tpgn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_modify_tpg_tp_cnt));
put_tpg:
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_create_target_tpg(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_tp *failed_tp[UBCORE_MAX_TP_CNT_IN_GRP];
	union ubcore_tp_attr_mask *rts_mask = NULL;
	struct ubcore_cmd_create_target_tpg *arg;
	struct ubcore_tp_attr *rts_attr = NULL;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret = 0;
	uint32_t i;

	arg = kzalloc(sizeof(struct ubcore_cmd_create_target_tpg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_create_target_tpg));
	if (ret != 0)
		goto free_arg;

	if (arg->ta_data.trans_type == UBCORE_TRANSPORT_HNS_UB ||
		arg->ta_data.trans_type == UBCORE_TRANSPORT_IB) {
		ret = ubcore_cmd_create_target_tp(hdr, arg);
		goto free_arg;
	}

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	tpg = ubcore_create_tpg_and_multi_tp(dev, &arg->in.tpg_cfg, arg->in.tp_cfg);
	if (IS_ERR_OR_NULL(tpg)) {
		ret = PTR_ERR(tpg);
		goto put_device;
	}

	ubcore_log_info("create target tpg and mtu is %u", (uint32_t)arg->in.rtr_attr[0].mtu);

	ret = ubcore_find_add_tpg(dev, tpg);
	if (ret != 0) {
		ubcore_log_err("Failed to add tpg to the tpg table");
		goto destroy_tpg;
	}

	/* modify to RTR */
	if (ubcore_modify_tp_in_tpg(dev, tpg, arg->in.rtr_attr, arg->in.rtr_mask, failed_tp) !=
		tpg->tpg_cfg.tp_cnt) {
		/* todonext: modify tp to reset ? */
		ret = -EPERM;
		goto remove_tpg;
	}

	/* modify to RTS */
	ret = ubcore_get_tp_state_attr_and_mask(UBCORE_TP_STATE_RTS, tpg->tpg_cfg.tp_cnt,
		&rts_attr, &rts_mask);
	if (ret != 0)
		goto remove_tpg;

	arg->out.rts_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, rts_attr, rts_mask, failed_tp);
	if (arg->out.rts_tp_cnt != tpg->tpg_cfg.tp_cnt) {
		/* todonext: modify tp to reset ? */
		ret = -EPERM;
		kfree(rts_attr);
		kfree(rts_mask);
		goto remove_tpg;
	}

	kfree(rts_attr);
	kfree(rts_mask);

	/* fill output */
	arg->out.tpgn = tpg->tpgn;
	for (i = 0; i < tpg->tpg_cfg.tp_cnt; i++)
		arg->out.tpn[i] = tpg->tp_list[i]->tpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_target_tpg));
	if (ret)
		goto remove_tpg;
	else
		goto put_tpg;

remove_tpg:
	ubcore_find_remove_tpg(dev, tpg->tpgn);
destroy_tpg:
	(void)ubcore_destroy_multi_tp(dev, tpg);
put_tpg:
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_modify_target_tpg(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_tp *failed_tp[UBCORE_MAX_TP_CNT_IN_GRP];
	union ubcore_tp_attr_mask *rts_mask = NULL;
	struct ubcore_cmd_modify_target_tpg *arg;
	struct ubcore_tp_attr *rts_attr = NULL;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret;

	arg = kzalloc(sizeof(struct ubcore_cmd_modify_target_tpg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_modify_target_tpg));
	if (ret != 0)
		goto free_arg;

	if (arg->in.peer_tp_cnt > UBCORE_MAX_TP_CNT_IN_GRP) {
		ret = -EINVAL;
		ubcore_log_err("arg->in.peer_tp_cnt %d too big", arg->in.peer_tp_cnt);
		goto free_arg;
	}

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	tpg = ubcore_find_get_tpg(dev, arg->in.tpgn);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg");
		goto put_device;
	}

	if (tpg->tpg_cfg.tp_cnt > arg->in.peer_tp_cnt) {
		ret = ubcore_destroy_multi_tp_from_index(dev, tpg, arg->in.peer_tp_cnt);
		if (ret == (tpg->tpg_cfg.tp_cnt - arg->in.peer_tp_cnt)) {
			tpg->tpg_cfg.tp_cnt = arg->in.peer_tp_cnt;
		} else {
			ubcore_log_err("ubcore_destroy_multi_tp_from_index failed %d", ret);
			ret = -EPERM;
			goto put_tpg;
		}
	}

	/* modify to RTR */
	if (ubcore_modify_tp_in_tpg(dev, tpg, arg->in.rtr_attr, arg->in.rtr_mask, failed_tp) !=
		tpg->tpg_cfg.tp_cnt) {
		/* todonext: modify tp to reset ? */
		ret = -EPERM;
		goto put_tpg;
	}

	/* modify to RTS */
	ret = ubcore_get_tp_state_attr_and_mask(UBCORE_TP_STATE_RTS, tpg->tpg_cfg.tp_cnt,
		&rts_attr, &rts_mask);
	if (ret != 0)
		goto put_tpg;

	arg->out.rts_tp_cnt = ubcore_modify_tp_in_tpg(dev, tpg, rts_attr, rts_mask, failed_tp);
	if (arg->out.rts_tp_cnt != tpg->tpg_cfg.tp_cnt)
		/* todonext: modify tp to reset ? */
		ret = -EPERM;

	/* do not modify ret if copy success */
	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_modify_target_tpg)) != 0)
		ret = -EPERM;

	kfree(rts_attr);
	kfree(rts_mask);
put_tpg:
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_destroy_vtp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_destroy_vtp arg;
	struct ubcore_device *dev;
	struct ubcore_vtp *vtp;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_destroy_vtp));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, arg.in.tpf.trans_type);
	if (dev == NULL)
		return -ENODEV;

	vtp = ubcore_find_get_vtp(dev, arg.in.mode, &arg.in.local_eid, &arg.in.peer_eid);
	if (vtp == NULL) {
		ret = -EINVAL;
		goto put_device;
	}

	ret = ubcore_check_and_unmap_vtp(vtp, arg.in.role);
	ubcore_vtp_kref_put(vtp);
put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_check_dev_name(char *dev_name)
{
	struct ubcore_device *pf_dev = NULL;

	pf_dev = ubcore_find_device_with_name(dev_name);
	if (pf_dev == NULL) {
		ubcore_log_err("cannot find dev_name: %s", dev_name);
		return -EINVAL;
	}

	ubcore_put_device(pf_dev);
	return 0;
}

static int ubcore_cmd_opt_sip(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_opt_sip arg;
	uint32_t sip_idx = UINT_MAX;
	int ret;
	int op_res;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_opt_sip));
	if (ret != 0)
		return ret;

	arg.in.info.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	arg.in.info.netdev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	ret = ubcore_check_dev_name(arg.in.info.dev_name);
	if (ret != 0)
		return ret;

	if (hdr->command == UBCORE_CMD_ADD_SIP) {
		op_res = ubcore_add_sip(&arg.in.info, &sip_idx);
		arg.out.sip_idx = sip_idx;
	} else {
		op_res = ubcore_delete_sip(&arg.in.info);
	}

	 /*
	  * add opt may return exist, need send sip_idx to userspace,
	  * otherwise return failed immediately.
	  */
	if (op_res != 0 && op_res != -EEXIST)
		return op_res;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_opt_sip));
	if (ret != 0) {
		/* op_res is EEXIST means no need to rollback */
		if (hdr->command == UBCORE_CMD_ADD_SIP && op_res == 0)
			(void)ubcore_delete_sip(&arg.in.info);
		else if (hdr->command == UBCORE_CMD_DEL_SIP)
			(void)ubcore_add_sip(&arg.in.info, &sip_idx);
		return ret;
	}

	/* we need return -EEXIST back to userspace */
	return (op_res == -EEXIST) ? op_res : ret;
}

static int ubcore_eidtbl_add_entry(struct ubcore_device *dev, union ubcore_eid *eid,
	uint32_t *eid_idx, struct net *net)
{
	uint32_t i;

	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (memcmp(dev->eid_table.eid_entries[i].eid.raw, eid->raw, UBCORE_EID_SIZE) == 0) {
			ubcore_log_warn("eid already exists\n");
			return 0;
		}
	}
	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (dev->eid_table.eid_entries[i].valid == false) {
			dev->eid_table.eid_entries[i].eid = *eid;
			dev->eid_table.eid_entries[i].valid = true;
			dev->eid_table.eid_entries[i].eid_index = i;
			dev->eid_table.eid_entries[i].net = (net == NULL) ? &init_net : net;
			*eid_idx = i;
			ubcore_log_info("dev:%s, add eid: %pI6c, idx: %u, net:0x%p\n",
				dev->dev_name, eid, i, net);
			break;
		}
	}
	if (i == dev->attr.dev_cap.max_eid_cnt) {
		ubcore_log_err("eid table is full\n");
		return -1;
	}
	return 0;
}

static int ubcore_eidtbl_del_entry(struct ubcore_device *dev, union ubcore_eid *eid,
	uint32_t *eid_idx)
{
	uint32_t i;

	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		if (memcmp(dev->eid_table.eid_entries[i].eid.raw, eid->raw, UBCORE_EID_SIZE) == 0) {
			(void)memset(&dev->eid_table.eid_entries[i],
				0, sizeof(struct ubcore_eid_entry));
			*eid_idx = i;
			ubcore_log_info("dev:%s, del eid: %pI6c, idx: %u\n", dev->dev_name, eid, i);
			break;
		}
	}
	if (i == dev->attr.dev_cap.max_eid_cnt) {
		ubcore_log_err("eid table is empty");
		return -1;
	}
	return 0;
}

static inline void ubcore_dispatch_eid_change(struct ubcore_device *dev, uint32_t eid_idx)
{
	struct ubcore_event event;

	event.ub_dev = dev;
	event.event_type = UBCORE_EVENT_EID_CHANGE;
	event.element.eid_idx = eid_idx;

	ubcore_dispatch_async_event(&event);
}

static int ubcore_eidtbl_update_entry(struct ubcore_device *dev, union ubcore_eid *eid,
	uint32_t eid_idx, bool is_add, struct net *net)
{
	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	if (eid_idx >= dev->attr.dev_cap.max_eid_cnt) {
		ubcore_log_err("eid table is full\n");
		return -1;
	}
	if (is_add) {
		dev->eid_table.eid_entries[eid_idx].eid = *eid;
	} else {
		(void)memset(&dev->eid_table.eid_entries[eid_idx].eid, 0, sizeof(union ubcore_eid));
		ubcore_dispatch_eid_change(dev, eid_idx);
	}

	dev->eid_table.eid_entries[eid_idx].valid = is_add;
	dev->eid_table.eid_entries[eid_idx].eid_index = eid_idx;
	dev->eid_table.eid_entries[eid_idx].net = net;
	ubcore_log_info("%s eid: %pI6c, idx: %u\n", is_add == true ? "add" : "del", eid, eid_idx);
	return 0;
}

int ubcore_update_eidtbl_by_eid(struct ubcore_device *dev, union ubcore_eid *eid,
	uint32_t *eid_idx, bool is_alloc_eid, struct net *net)
{
	int ret;

	spin_lock(&dev->eid_table.lock);
	if (is_alloc_eid)
		ret = ubcore_eidtbl_add_entry(dev, eid, eid_idx, net);
	else
		ret = ubcore_eidtbl_del_entry(dev, eid, eid_idx);

	spin_unlock(&dev->eid_table.lock);
	return ret;
}

int ubcore_update_eidtbl_by_idx(struct ubcore_device *dev, union ubcore_eid *eid,
	uint32_t eid_idx, bool is_alloc_eid, struct net *net)
{
	int ret;

	spin_lock(&dev->eid_table.lock);
	ret = ubcore_eidtbl_update_entry(dev, eid, eid_idx, is_alloc_eid, net);
	spin_unlock(&dev->eid_table.lock);
	return ret;
}

static int ubcore_cmd_set_upi(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_set_upi arg;
	struct ubcore_device *dev;
	uint32_t pattern3_upi;
	union ubcore_eid *eid;
	uint32_t i;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_set_upi));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_upi_with_dev_name(arg.in.dev_name, &pattern3_upi);
	if (dev == NULL) {
		ubcore_log_err("device not found by name: %s\n", arg.in.dev_name);
		return -1;
	}
	if (!(dev->dynamic_eid && dev->attr.pattern == (uint8_t)UBCORE_PATTERN_3)) {
		ubcore_log_err("This mode does not support setting upi\n");
		return -1;
	}
	if (dev->eid_table.eid_entries == NULL)
		return -EINVAL;

	for (i = 0; i < dev->attr.dev_cap.max_eid_cnt; i++) {
		eid = &dev->eid_table.eid_entries[i].eid;
		if (dev->eid_table.eid_entries[i].valid == false)
			continue;

		if (pattern3_upi != UCBORE_INVALID_UPI)
			(void)ubcore_send_eid_update_req(
				dev, UBCORE_DEL_NET_ADDR, eid, i, &pattern3_upi);

		(void)ubcore_send_eid_update_req(
			dev, UBCORE_ADD_NET_ADDR, eid, i, &arg.in.upi);
	}
	(void)ubcore_add_upi_list(dev, arg.in.upi);
	return 0;
}

static int ubcore_cmd_show_upi(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_show_upi arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_show_upi));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_upi_with_dev_name(arg.in.dev_name, &arg.out.upi);
	if (dev == NULL) {
		ubcore_log_err("device not found by name: %s\n", arg.in.dev_name);
		return -1;
	}

	if (dev->transport_type == UBCORE_TRANSPORT_UB && dev->dynamic_eid == 0) {
		ubcore_log_err("Failed to use show_upi to query upi in pattern3 static mode");
		return -1;
	}

	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_show_upi)) != 0)
		ret = -EPERM;

	return ret;
}

static int ubcore_cmd_set_global_cfg(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_set_global_cfg arg;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_set_global_cfg));
	if (ret != 0)
		return ret;

	ret = ubcore_tpf_device_set_global_cfg(&arg.in.global_cfg);
	return ret;
}

static int ubcore_set_vport_cfg(struct ubcore_device *dev,
	struct ubcore_set_vport_cfg *vport_cfg)
{
	struct ubcore_device_cfg dev_cfg = {0};
	int ret;

	dev_cfg.fe_idx = vport_cfg->fe_idx;
	if (vport_cfg->mask.bs.pattern == 1) {
		dev_cfg.mask.bs.pattern = 1;
		dev_cfg.pattern = (uint8_t)vport_cfg->pattern;
		dev->cfg.pattern = (uint8_t)vport_cfg->pattern;
	}
	if (vport_cfg->mask.bs.virtualization == 1) {
		dev_cfg.mask.bs.virtualization = 1;
		dev_cfg.virtualization = (bool)vport_cfg->virtualization;
		dev->cfg.virtualization = (bool)vport_cfg->virtualization;
	}
	if (vport_cfg->mask.bs.min_jetty_cnt == 1) {
		dev_cfg.mask.bs.min_jetty_cnt = 1;
		dev_cfg.min_jetty_cnt = vport_cfg->min_jetty_cnt;
		dev->cfg.min_jetty_cnt = vport_cfg->min_jetty_cnt;
	}
	if (vport_cfg->mask.bs.max_jetty_cnt == 1) {
		dev_cfg.mask.bs.max_jetty_cnt = 1;
		dev_cfg.max_jetty_cnt = vport_cfg->max_jetty_cnt;
		dev->cfg.max_jetty_cnt = vport_cfg->max_jetty_cnt;
	}
	if (vport_cfg->mask.bs.min_jfr_cnt == 1) {
		dev_cfg.mask.bs.min_jfr_cnt = 1;
		dev_cfg.min_jfr_cnt = vport_cfg->min_jfr_cnt;
		dev->cfg.min_jfr_cnt = vport_cfg->min_jfr_cnt;
	}
	if (vport_cfg->mask.bs.max_jfr_cnt == 1) {
		dev_cfg.mask.bs.max_jfr_cnt = 1;
		dev_cfg.max_jfr_cnt = vport_cfg->max_jfr_cnt;
		dev->cfg.max_jfr_cnt = vport_cfg->max_jfr_cnt;
	}
	if (vport_cfg->mask.bs.slice == 1) {
		dev_cfg.mask.bs.slice = 1;
		dev_cfg.slice = vport_cfg->slice;
		dev->cfg.slice = vport_cfg->slice;
	}
	dev->cfg.mask.value |= dev_cfg.mask.value;

	ret = ubcore_config_device(dev, &dev_cfg);
	if (ret != 0)
		ubcore_log_err("dev: %s set vport cfg failed, ret: %d", dev->dev_name, ret);
	return ret;
}

static int ubcore_cmd_set_vport_cfg(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_set_vport_cfg arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_set_vport_cfg));
	if (ret != 0)
		return ret;

	arg.in.vport_cfg.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.vport_cfg.dev_name);
	if (dev == NULL) {
		ubcore_log_err("find dev failed, arg_in: %s.\n", arg.in.vport_cfg.dev_name);
		return -EINVAL;
	}

	if (dev->transport_type == UBCORE_TRANSPORT_HNS_UB ||
		dev->transport_type == UBCORE_TRANSPORT_IB) {
		ubcore_log_info("ib devices don't need to call ops->config_device");
		ubcore_put_device(dev);
		return 0;
	}

	if (!dev->attr.tp_maintainer) {
		ubcore_log_err("vport should config in tpf, dev_name:%s ", dev->dev_name);
		ubcore_put_device(dev);
		return -ENXIO;
	}

	/* check whethre the tp in tpg configed is exceeded the device cap */
	if (arg.in.vport_cfg.tp_cnt > dev->attr.dev_cap.max_tp_in_tpg) {
		ubcore_log_err("configed tp_cnt:%u is exceeded the devce cap:%u",
			arg.in.vport_cfg.tp_cnt, dev->attr.dev_cap.max_tp_in_tpg);
		ubcore_put_device(dev);
		return -EINVAL;
	}

	ret = ubcore_set_vport_cfg(dev, &arg.in.vport_cfg);
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_get_dev_info(struct ubcore_cmd_hdr *hdr)
{
	enum ubcore_mtu max_mtu = UBCORE_MTU_1024;
	struct ubcore_cmd_get_dev_info arg = {0};
	struct ubcore_device *tpf_dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_get_dev_info));
	if (ret != 0)
		return ret;

	arg.in.target_tpf_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	tpf_dev = ubcore_find_device_with_name(arg.in.target_tpf_name);
	if (tpf_dev == NULL) {
		ubcore_log_err("failed to find tpf_dev device with %s", arg.in.target_tpf_name);
		return -1;
	}

	ret = ubcore_get_max_mtu(tpf_dev, &max_mtu);
	if (ret != 0) {
		ubcore_log_err("failed to get max mtu");
		ubcore_put_device(tpf_dev);
		return ret;
	}
	arg.out.max_mtu = max_mtu;

	ubcore_put_device(tpf_dev);

	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_get_dev_info)) != 0)
		ret = -EPERM;

	return ret;
}

/* Caller ensures that meta->ht is not NULL */
static int ubcore_unmark_bind_tjetty(struct ubcore_tp_advice *advice,
	struct ubcore_ta_data *ta_data)
{
	struct ubcore_tp_meta *meta;
	struct ubcore_jetty *jetty;

	meta = &advice->meta;
	jetty = advice->ta.jetty;
	spin_lock(&meta->ht->lock);
	if (jetty != NULL && jetty->jetty_cfg.trans_mode == UBCORE_TP_RC) {
		if (memcmp(&meta->ht->rc_tjetty_id, &ta_data->jetty_id,
			sizeof(struct ubcore_jetty_id)) == 0) {
			(void)memset(&meta->ht->rc_tjetty_id, 0, sizeof(struct ubcore_jetty_id));
		} else {
			spin_unlock(&meta->ht->lock);
			ubcore_log_err("The jetty_id: %u is not bound tjetty_id: %u\n",
				jetty->jetty_id.id, ta_data->jetty_id.id);
			return -1;
		}
	}
	spin_unlock(&meta->ht->lock);
	return 0;
}

static int ubcore_cmd_destroy_tp(struct ubcore_cmd_hdr *hdr, struct ubcore_cmd_destroy_tpg *arg)
{
	struct ubcore_tp_advice advice = {0};
	struct ubcore_device *dev = NULL;
	int ret = 0;

	if (!arg->ta_data.is_target)
		return 0;

	dev = ubcore_find_device(&arg->ta_data.tjetty_id.eid, arg->ta_data.trans_type);
	if (dev == NULL)
		return -ENODEV;

	if (ubcore_para_target_ta_get_jetty(dev, &advice, &arg->ta_data) != 0) {
		ubcore_log_err("Failed to parse ta with type %u", (uint32_t)advice.ta.type);
		ret = -1;
		goto put_device;
	} else if (advice.meta.ht == NULL) {
		ubcore_log_info("tp table is already released");
		goto put_jetty;
	}

	ret = ubcore_unmark_bind_tjetty(&advice, &arg->ta_data);
	if (ret != 0)
		goto put_tptable;

	ubcore_find_remove_tp(advice.meta.ht, advice.meta.hash, &advice.meta.key);

put_tptable:
	ubcore_put_tptable(advice.meta.ht);
put_jetty:
	ubcore_put_target_ta_jetty(&advice.ta);
put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_destroy_tpg(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_destroy_tpg arg = {0};
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_destroy_tpg));
	if (ret != 0)
		return ret;

	if (arg.ta_data.trans_type == UBCORE_TRANSPORT_HNS_UB ||
		arg.ta_data.trans_type == UBCORE_TRANSPORT_IB)
		return ubcore_cmd_destroy_tp(hdr, &arg);

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, arg.in.tpf.trans_type);
	if (dev == NULL)
		return -ENODEV;

	/* deal with RM first */
	tpg = ubcore_find_get_tpg(dev, arg.in.tpgn);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg");
		goto put_device;
	}
	ret = ubcore_find_remove_tpg(dev, arg.in.tpgn);
	if (ret == 0)
		arg.out.destroyed_tp_cnt = ubcore_destroy_multi_tp(dev, tpg);

	if (arg.out.destroyed_tp_cnt != tpg->tpg_cfg.tp_cnt)
		ret = -EPERM;

	/* do not modify ret if copy success */
	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_destroy_tpg)) != 0)
		ret = -EPERM;
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
	return ret;
}

static void ubcore_put_tpg_utp_ctp_in_vtp(struct ubcore_cmd_vtp_cfg *cmd,
	struct ubcore_tpg *tpg, struct ubcore_utp *utp, struct ubcore_ctp *ctp)
{
	if (cmd->flag.bs.clan_tp == 0) {
		if (cmd->trans_mode != UBCORE_TP_UM && tpg != NULL)
			ubcore_tpg_kref_put(tpg);
		else if (cmd->trans_mode == UBCORE_TP_UM && utp != NULL)
			ubcore_utp_kref_put(utp);
	} else {
		ubcore_ctp_kref_put(ctp);
	}
}

static int ubcore_cmd_map_vtp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_map_vtp *arg;
	struct ubcore_vtp_cfg vtp_cfg;
	struct ubcore_vtp *vtp = NULL;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg = NULL;
	struct ubcore_utp *utp = NULL;
	struct ubcore_ctp *ctp = NULL;
	int ret;

	arg = kzalloc(sizeof(struct ubcore_cmd_map_vtp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_map_vtp));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	if (arg->in.vtp.flag.bs.clan_tp == 0) {
		/* deal with trans domain -G */
		if (arg->in.vtp.trans_mode != UBCORE_TP_UM) {
			/* deal with RM first */
			tpg = ubcore_find_get_tpg(dev, arg->in.vtp.tpgn);
			if (tpg == NULL) {
				ret = -EINVAL;
				ubcore_log_err("Failed to find tpg");
				goto put_device;
			}
			ubcore_set_vtp2tpg_cfg(&vtp_cfg, &arg->in.vtp, tpg);
		} else {
			/* deal with UM */
			utp = ubcore_find_get_utp(dev, arg->in.vtp.utpn);
			if (utp == NULL) {
				ret = -EINVAL;
				ubcore_log_err("Failed to find utp");
				goto put_device;
			}
			ubcore_set_vtp2utp_cfg(&vtp_cfg, &arg->in.vtp, utp);
		}
	} else {
		/* deal with trans domain -C */
		ctp = ubcore_find_get_ctp(dev, arg->in.vtp.ctpn);
		if (ctp == NULL) {
			ret = -EINVAL;
			ubcore_log_err("Failed to find ctp");
			goto put_device;
		}
		ubcore_set_vtp2ctp_cfg(&vtp_cfg, &arg->in.vtp, ctp);
	}

	vtp = ubcore_check_and_map_vtp(dev, &vtp_cfg, arg->in.role);
	if (vtp == NULL) {
		ret = -EPERM;
		goto put_tpg_utp;
	}

	vtp->eid_idx = arg->in.eid_idx;
	vtp->upi = arg->in.upi;
	vtp->share_mode = arg->in.share_mode;

	arg->out.vtpn = vtp->cfg.vtpn;
	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_map_vtp));
	if (ret != 0)
		(void)ubcore_check_and_unmap_vtp(vtp, arg->in.role);

	ubcore_vtp_kref_put(vtp);

	goto put_tpg_utp;

put_tpg_utp:
	ubcore_put_tpg_utp_ctp_in_vtp(&arg->in.vtp, tpg, utp, ctp);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static void ubcore_get_utp_mtu(struct ubcore_device *dev, struct ubcore_utp_cfg *cfg)
{
	enum ubcore_mtu mtu;
	int ret;

	ret = ubcore_get_max_mtu(dev, &mtu);
	if (ret < 0) {
		mtu = UBCORE_MTU_1024;
		ubcore_log_warn("dev:%s, port_id:%u Failed to get max mtu",
			dev->dev_name, cfg->port_id);
	}
	cfg->mtu = min(cfg->mtu, mtu);
}

static int ubcore_cmd_create_utp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_create_utp *arg;
	struct ubcore_device *dev;
	struct ubcore_utp *utp = NULL;
	struct ubcore_vtp_cfg vtp_cfg;
	struct ubcore_vtp *vtp = NULL;
	int ret = 0;

	arg = kzalloc(sizeof(struct ubcore_cmd_create_utp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_create_utp));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	ubcore_get_utp_mtu(dev, &arg->in.utp_cfg);

	utp = ubcore_create_utp(dev, &arg->in.utp_cfg);
	if (utp == NULL) {
		ret = -EPERM;
		goto put_device;
	}

	ubcore_set_vtp2utp_cfg(&vtp_cfg, &arg->in.vtp, utp);
	vtp = ubcore_create_and_map_vtp(dev, &vtp_cfg);
	if (IS_ERR_OR_NULL(vtp)) {
		ret = PTR_ERR(vtp);
		goto destroy_utp;
	}
	vtp->eid_idx = arg->in.eid_idx;
	vtp->upi = arg->in.upi;
	vtp->share_mode = arg->in.share_mode;

	/* fill output */
	arg->out.idx = utp->utpn;
	arg->out.vtpn = vtp->cfg.vtpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_utp));
	if (ret) {
		goto unmap_vtp;
	} else {
		ubcore_vtp_kref_put(vtp);
		goto put_utp;
	}
unmap_vtp:
	(void)ubcore_unmap_vtp(vtp);
	ubcore_vtp_kref_put(vtp);
destroy_utp:
	ubcore_find_remove_utp(dev, utp->utpn);
put_utp:
	ubcore_utp_kref_put(utp);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_only_create_utp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_create_utp *arg;
	struct ubcore_device *dev;
	struct ubcore_utp *utp = NULL;
	int ret;

	arg = kzalloc(sizeof(struct ubcore_cmd_create_utp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_create_utp));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	ubcore_get_utp_mtu(dev, &arg->in.utp_cfg);

	utp = ubcore_create_utp(dev, &arg->in.utp_cfg);
	if (utp == NULL) {
		ret = -EPERM;
		goto put_device;
	}

	/* fill output */
	arg->out.idx = utp->utpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_utp));
	if (ret)
		goto destroy_utp;
	else
		goto put_utp;

destroy_utp:
	ubcore_find_remove_utp(dev, utp->utpn);
put_utp:
	ubcore_utp_kref_put(utp);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_destroy_utp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_destroy_utp arg = {0};
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_destroy_utp));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, arg.in.tpf.trans_type);
	if (dev == NULL)
		return -ENODEV;

	ubcore_find_remove_utp(dev, arg.in.utp_idx);

	ubcore_put_device(dev);
	return 0;
}

static int ubcore_cmd_create_ctp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_create_ctp *arg = NULL;
	struct ubcore_device *dev = NULL;
	struct ubcore_ctp *ctp = NULL;
	struct ubcore_vtp_cfg vtp_cfg;
	struct ubcore_vtp *vtp = NULL;
	int ret = 0;

	arg = kzalloc(sizeof(struct ubcore_cmd_create_ctp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg,
		(void __user *)(uintptr_t)hdr->args_addr, sizeof(struct ubcore_cmd_create_ctp));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	ctp = ubcore_create_ctp(dev, &arg->in.ctp_cfg);
	if (ctp == NULL)
		goto put_device;

	ubcore_set_vtp2ctp_cfg(&vtp_cfg, &arg->in.vtp, ctp);
	vtp = ubcore_create_and_map_vtp(dev, &vtp_cfg);
	if (IS_ERR_OR_NULL(vtp)) {
		ret = PTR_ERR(vtp);
		goto destroy_ctp;
	}

	/* fill output */
	arg->out.idx = ctp->ctpn;
	arg->out.vtpn = vtp->cfg.vtpn;

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg,
		sizeof(struct ubcore_cmd_create_ctp));
	if (ret) {
		goto unmap_vtp;
	} else {
		ubcore_vtp_kref_put(vtp);
		goto put_device;
	}

unmap_vtp:
	(void)ubcore_unmap_vtp(vtp);
	ubcore_vtp_kref_put(vtp);
destroy_ctp:
	(void)dev->ops->destroy_ctp(ctp);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_destroy_ctp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_destroy_ctp arg = {0};
	struct ubcore_device *dev = NULL;
	struct ubcore_ctp *ctp = NULL;
	int ret = 0;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_destroy_ctp));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, arg.in.tpf.trans_type);
	if (dev == NULL) {
		ubcore_log_err("Failed to find tpf by addr: %pI6c", &arg.in.tpf.netaddr);
		return -ENODEV;
	}

	ctp = ubcore_find_remove_ctp(dev, arg.in.ctp_idx);
	if (ctp == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find ctp");
		goto put_device;
	}

	ret = ubcore_destroy_ctp(ctp);
	if (ret)
		ubcore_log_err("Failed to destroy ctp");

put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_restore_tp_error_op(struct ubcore_cmd_hdr *hdr,
	bool set_to_rtr, bool set_to_rts)
{
	struct ubcore_cmd_restore_tp_error arg = {0};
	struct ubcore_device *dev;
	struct ubcore_tp *tp;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_restore_tp_error));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, UBCORE_TRANSPORT_UB);
	if (dev == NULL) {
		ubcore_log_err("Failed to find tpf by addr: %pI6c", &arg.in.tpf.netaddr);
		return -ENODEV;
	}

	if (dev->ops == NULL || dev->ops->modify_tp == NULL) {
		ret = -ENODEV;
		goto put_device;
	}

	tp = ubcore_find_get_tp(dev, arg.in.tpn);
	if (tp == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tp");
		goto put_device;
	}

	if (set_to_rtr && ubcore_restore_tp_error_to_rtr(dev, tp, arg.in.rx_psn, arg.in.tx_psn,
		arg.in.data_udp_start, arg.in.ack_udp_start) != 0) {
		ret = -1;
		ubcore_log_err("Failed to restore error tp %u to rtr, cmd:%u",
			arg.in.tpn, hdr->command);
		goto put_tp;
	}

	if (set_to_rts && ubcore_restore_tp_error_to_rts(dev, tp) != 0) {
		ret = -1;
		ubcore_log_err("Failed to restore error tp %u to rts, cmd:%u",
			arg.in.tpn, hdr->command);
		goto put_tp;
	}

	ubcore_log_info("Success to restore tp %u error, cmd:%u",  arg.in.tpn, hdr->command);

put_tp:
	ubcore_tp_kref_put(tp);

put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_restore_tp_error_rsp(struct ubcore_cmd_hdr *hdr)
{
	return ubcore_cmd_restore_tp_error_op(hdr, true, true);
}

static int ubcore_cmd_restore_target_tp_error_req(struct ubcore_cmd_hdr *hdr)
{
	return ubcore_cmd_restore_tp_error_op(hdr, true, false);
}

static int ubcore_cmd_restore_target_tp_error_ack(struct ubcore_cmd_hdr *hdr)
{
	return ubcore_cmd_restore_tp_error_op(hdr, false, true);
}

static void ubcore_fill_attr_restore_tp_suspend(struct ubcore_cmd_restore_tp_suspend *arg,
	union ubcore_tp_attr_mask *mask, struct ubcore_tp_attr *attr)
{
	mask->value = 0;
	mask->bs.state = 1;
	mask->bs.data_udp_start = 1;
	mask->bs.ack_udp_start = 1;
	attr->state = UBCORE_TP_STATE_RTS;
	attr->data_udp_start = arg->in.data_udp_start;
	attr->ack_udp_start = arg->in.ack_udp_start;
	ubcore_log_info("restore tp suspend(mask): state: %u, data_udp_start: %u, ack_udp_start: %u",
		mask->bs.state, mask->bs.data_udp_start, mask->bs.ack_udp_start);
	ubcore_log_info("restore tp suspend(attr): state: %u, data_udp_start: %hu, ack_udp_start: %hu",
		(uint32_t)attr->state, attr->data_udp_start, attr->ack_udp_start);
}

static int ubcore_cmd_restore_tp_suspend(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_restore_tp_suspend arg = {0};
	union ubcore_tp_attr_mask mask;
	struct ubcore_tp_attr attr;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	struct ubcore_tp *tp;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_restore_tp_suspend));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, UBCORE_TRANSPORT_UB);
	if (dev == NULL) {
		ubcore_log_err("Failed to find tpf by addr: %pI6c", &arg.in.tpf.netaddr);
		return -ENODEV;
	}

	if (dev->ops == NULL || dev->ops->modify_tp == NULL) {
		ret = -ENODEV;
		goto put_device;
	}
	/* deal with RM first */
	tpg = ubcore_find_get_tpg(dev, arg.in.tpgn);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg");
		goto put_device;
	}

	tp = ubcore_find_get_tp_in_tpg(tpg, arg.in.tpn);
	if (tp == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tp");
		goto put_tpg;
	}

	if (ubcore_modify_tp_state_check(tp, UBCORE_TP_STATE_RTS) != 0) {
		ubcore_log_err("Failed to modify tp to RTR from state %u and tpn = %u",
			(uint32_t)tp->state, tp->tpn);
		ret = -1;
		goto put_tp;
	}

	ubcore_fill_attr_restore_tp_suspend(&arg, &mask, &attr);
	if (dev->ops->modify_tp(tp, &attr, mask) != 0) {
		ret = -1;
		ubcore_log_err("Failed to modify tp to RTR from state %u and tpn = %u",
			(uint32_t)tp->state, tp->tpn);
		goto put_tp;
	}
	tp->state = UBCORE_TP_STATE_RTS;
	tp->data_udp_start = arg.in.data_udp_start;
	tp->ack_udp_start = arg.in.ack_udp_start;

	ubcore_log_info("Success to restore tp suspend");

put_tp:
	ubcore_tp_kref_put(tp);
put_tpg:
	ubcore_tpg_kref_put(tpg);
put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_get_dev_feature(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_get_dev_feature arg = {0};
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_get_dev_feature));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("no available devices found by dev_name: %s\n", arg.in.dev_name);
		ret = -1;
		return ret;
	}

	arg.out.feature.value = dev->attr.dev_cap.feature.value;
	arg.out.max_ueid_cnt = dev->attr.dev_cap.max_eid_cnt;
	ubcore_put_device(dev);

	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_get_dev_feature)) != 0)
		ret = -EPERM;

	return ret;
}

static int ubcore_cmd_change_tp_to_error(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_change_tp_to_error arg = {0};
	struct ubcore_device *dev;
	struct ubcore_tp *tp;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_change_tp_to_error));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, UBCORE_TRANSPORT_UB);
	if (dev == NULL) {
		ubcore_log_err("Failed to find tpf by addr: %pI6c", &arg.in.tpf.netaddr);
		return -ENODEV;
	}

	if (dev->ops == NULL || dev->ops->modify_tp == NULL) {
		ret = -ENODEV;
		goto put_device;
	}

	tp = ubcore_find_get_tp(dev, arg.in.tpn);
	if (tp == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tp");
		goto put_device;
	}

	/* check tp's state, it cannot be change to ERR state when it's in RESET state */
	if (tp->state == UBCORE_TP_STATE_RESET) {
		ubcore_log_warn("Found tp in RESET state, no need to change tp to error with tpn = %u",
			tp->tpn);
		goto put_tp;
	}

	if (ubcore_change_tp_to_err(dev, tp) != 0) {
		ret = -EINVAL;
		ubcore_log_err("Failed to change tp to error");
		goto put_tp;
	}

	ubcore_log_info("Success to change tp to error");

put_tp:
	ubcore_tp_kref_put(tp);
put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_change_tpg_to_error(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_change_tpg_to_error arg = {0};
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg;
	struct ubcore_tp *tp;
	int ret;
	uint32_t i;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_change_tpg_to_error));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, UBCORE_TRANSPORT_UB);
	if (dev == NULL) {
		ubcore_log_err("Failed to find tpf by addr: %pI6c", &arg.in.tpf.netaddr);
		return -ENODEV;
	}

	if (dev->ops == NULL || dev->ops->modify_tp == NULL) {
		ret = -ENODEV;
		goto put_device;
	}
	tpg = ubcore_find_get_tpg(dev, arg.in.tpgn);
	if (tpg == NULL) {
		ret = -EINVAL;
		ubcore_log_err("Failed to find tpg %u", arg.in.tpgn);
		goto put_device;
	}

	mutex_lock(&tpg->mutex);
	for (i = 0; i < tpg->tpg_cfg.tp_cnt; i++) {
		tp = tpg->tp_list[i];
		if (tp == NULL) {
			ubcore_log_warn("tp in tpg %u is NULL", arg.in.tpgn);
			continue;
		}
		ubcore_tp_get(tp);

		if (tp->state == UBCORE_TP_STATE_RESET || tp->state == UBCORE_TP_STATE_ERR) {
			ubcore_log_info("TP:%u already in %u", tp->tpn, (uint32_t)tp->state);
			ubcore_tp_kref_put(tp);
			continue;
		}

		if (ubcore_change_tp_to_err(dev, tp) != 0) {
			ubcore_log_warn("Failed to change tp:%u, to error in tpg %u",
				tp->tpn, arg.in.tpgn);
			ubcore_tp_kref_put(tp);
			continue;
		}
		arg.out.tp_error_cnt++;
		ubcore_tp_kref_put(tp);
	}
	mutex_unlock(&tpg->mutex);
	ubcore_tpg_kref_put(tpg);

	ubcore_log_info("Success to finish change tpg to error, tp err cnt:%u, tpgn %u",
		arg.out.tp_error_cnt, arg.in.tpgn);

	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_change_tpg_to_error)) != 0)
		ret = -EPERM;

put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_config_function_migrate_state(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_config_function_migrate_state arg = {0};
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_config_function_migrate_state));
	if (ret != 0)
		return ret;

	dev = ubcore_find_tpf_device(&arg.in.tpf.netaddr, arg.in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		ubcore_log_err("fail to find tpf device");
		return ret;
	}

	if (dev->ops == NULL || dev->ops->config_function_migrate_state == NULL) {
		ret = -EINVAL;
		goto put_dev;
	}

	arg.out.cnt = (uint32_t)ubcore_config_function_migrate_state(dev, arg.in.fe_idx,
		arg.in.config_cnt, &arg.in.config[0], arg.in.state);

	if (arg.out.cnt != arg.in.config_cnt)
		ret = -EPERM;

	/* do not modify ret if copy success */
	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_config_function_migrate_state)) != 0)
		ret = -EPERM;

put_dev:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_init_modify_vtp(struct ubcore_device *dev, struct ubcore_cmd_vtp_cfg *vtp,
	struct ubcore_vtp_param *vtp_param, struct ubcore_vtp_attr *vattr,
	union ubcore_vtp_attr_mask *vattr_mask)
{
	vtp_param->trans_mode = vtp->trans_mode;
	vtp_param->local_eid = vtp->local_eid;
	vtp_param->peer_eid = vtp->peer_eid;
	vtp_param->local_jetty = vtp->local_jetty;
	vtp_param->peer_jetty = vtp->peer_jetty;

	if (vtp_param->trans_mode != UBCORE_TP_UM) {
		vattr->tp.tpg = ubcore_find_get_tpg(dev, vtp->tpgn);
		if (vattr->tp.tpg == NULL) {
			ubcore_log_err("fail to find tpg");
			return -EPERM;
		}
	} else {
		vattr->tp.utp = ubcore_find_get_utp(dev, vtp->utpn);
		if (vattr->tp.utp == NULL) {
			ubcore_log_err("fail to find utp");
			return -EPERM;
		}
	}
	vattr_mask->bs.tp = 1;

	return 0;
}

static void ubcore_uninit_modify_vtp(struct ubcore_vtp_attr *vattr,
								struct ubcore_vtp_param *vtp_param)
{
	if (vtp_param->trans_mode != UBCORE_TP_UM)
		ubcore_tpg_kref_put(vattr->tp.tpg);
	else
		ubcore_utp_kref_put(vattr->tp.utp);
}

static int ubcore_cmd_modify_vtp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_modify_vtp *arg;
	struct ubcore_device *dev;
	struct ubcore_vtp_param vtp_param = {0};
	struct ubcore_vtp_attr vattr = {0};
	union ubcore_vtp_attr_mask vattr_mask = {0};
	int ret;
	uint32_t i;

	arg = kzalloc(sizeof(struct ubcore_cmd_modify_vtp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_modify_vtp));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ubcore_log_err("Failed to find tpf by addr: %pI6c", &arg->in.tpf.netaddr);
		ret = -ENODEV;
		goto free_arg;
	}

	if (dev->ops == NULL || dev->ops->modify_vtp == NULL) {
		ret = -ENODEV;
		ubcore_log_err("fail to find tpf device");
		goto put_device;
	}
	if (arg->in.cfg_cnt > UBCORE_MAX_VTP_CFG_CNT) {
		ret = -ENODEV;
		ubcore_log_err("arg cfg_cnt %u is err, range in [0, %d].\n",
			arg->in.cfg_cnt, UBCORE_MAX_VTP_CFG_CNT);
		goto put_device;
	}

	for (i = 0; i < arg->in.cfg_cnt; i++) {
		ret = ubcore_init_modify_vtp(dev, &arg->in.vtp[i], &vtp_param,
			&vattr, &vattr_mask);
		if (ret < 0) {
			ubcore_log_err("fail to init modify vtp");
			goto put_device;
		}

		ret = ubcore_modify_vtp(dev, &vtp_param, &vattr, &vattr_mask);
		if (ret < 0) {
			ubcore_uninit_modify_vtp(&vattr, &vtp_param);
			ubcore_log_err("fail to modify vtp");
			goto put_device;
		}
	}

put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_cmd_opt_config_dscp_vl(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_opt_config_dscp_vl arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_opt_config_dscp_vl));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_warn("fail to find dev:%s\n", arg.in.dev_name);
		return -ENODEV;
	}

	if (dev->ops->config_dscp_vl == NULL) {
		ret = -ENODEV;
		goto put_device;
	}
	if (arg.in.num > UBCORE_MAX_DSCP_VL_NUM) {
		ret = -EINVAL;
		goto put_device;
	}
	ret = dev->ops->config_dscp_vl(dev, arg.in.dscp, arg.in.vl, arg.in.num);
	if (ret != 0) {
		ubcore_log_err("fail to config dscp vl, dev:%s\n", arg.in.dev_name);
		goto put_device;
	}

put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_opt_query_dscp_vl(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_opt_query_dscp_vl arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_opt_query_dscp_vl));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_warn("fail to find dev:%s\n", arg.in.dev_name);
		return -ENODEV;
	}

	if (dev->ops->query_dscp_vl == NULL) {
		ret = -ENODEV;
		goto put_device;
	}

	if (arg.in.num > UBCORE_MAX_DSCP_VL_NUM) {
		ret = -EINVAL;
		goto put_device;
	}

	ret = dev->ops->query_dscp_vl(dev, arg.in.dscp, arg.in.num, arg.out.vl);
	if (ret != 0) {
		ubcore_log_err("fail to query dscp vl, dev:%s\n", arg.in.dev_name);
		goto put_device;
	}

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_opt_query_dscp_vl));

put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_opt_update_eid(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_opt_eid arg;
	struct ubcore_ueid_cfg cfg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_opt_eid));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_tpf_device_by_name(arg.in.dev_name);
	if (dev == NULL)
		return -EINVAL;

	cfg.eid = arg.in.eid;
	cfg.eid_index = arg.in.eid_index;
	cfg.upi = arg.in.upi;
	cfg.uuid = arg.in.uuid;

	if (hdr->command == UBCORE_CMD_ALLOC_EID)
		ret = ubcore_add_ueid(dev, arg.in.fe_idx, &cfg);
	else
		ret = ubcore_delete_ueid(dev, arg.in.fe_idx, &cfg);

	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_opt_query_fe_idx(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_opt_query_fe_idx arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_opt_query_fe_idx));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_err("fail to query dev, dev:%s\n", arg.in.dev_name);
		return -ENODEV;
	}

	if (dev->ops->query_fe_idx == NULL) {
		ret = -ENODEV;
		goto put_device;
	}

	ret = dev->ops->query_fe_idx(dev, &arg.in.devid, &arg.out.fe_idx);
	if (ret != 0) {
		ubcore_log_err("fail to query fe_idx, dev:%s\n", arg.in.dev_name);
		goto put_device;
	}

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_opt_query_fe_idx));

put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_cmd_get_vtp_table_cnt(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_get_vtp_table_cnt arg;
	struct ubcore_device **dev_list = NULL;
	uint32_t dev_cnt, i = 0;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_get_vtp_table_cnt));
	if (ret != 0)
		return ret;

	arg.out.vtp_cnt = 0;
	dev_list = ubcore_get_all_tpf_device(UBCORE_TRANSPORT_UB, &dev_cnt);

	if (dev_cnt != 0) {
		if (dev_list == NULL) {
			ubcore_log_err("get all tpf device failed.\n");
			return -1;
		}

		for (i = 0; i < dev_cnt; ++i) {
			arg.out.vtp_cnt +=
				ubcore_get_all_vtp_cnt(&dev_list[i]->ht[UBCORE_HT_RM_VTP]);
			arg.out.vtp_cnt +=
				ubcore_get_all_vtp_cnt(&dev_list[i]->ht[UBCORE_HT_UM_VTP]);
		}
	}

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_get_vtp_table_cnt));

	if (dev_list != NULL) {
		for (i = 0; i < dev_cnt; ++i)
			if (dev_list[i] != NULL)
				ubcore_put_device(dev_list[i]);

		kfree(dev_list);
	}
	return ret;
}

static int ubcore_assign_single_out_vtp_table(struct ubcore_device *dev, struct ubcore_vtp *vtp,
	struct ubcore_restored_vtp_entry *out_entry, const char *dev_name)
{
	struct ubcore_sip_info *sip_entry = NULL;
	uint32_t dev_tpn_idx = 0;

	if (vtp == NULL)
		return -1;

	out_entry->fe_idx = vtp->cfg.fe_idx;
	out_entry->vtpn = vtp->cfg.vtpn;
	out_entry->local_jetty = vtp->cfg.local_jetty;
	out_entry->local_eid = vtp->cfg.local_eid;
	out_entry->peer_eid = vtp->cfg.peer_eid;
	out_entry->peer_jetty = vtp->cfg.peer_jetty;
	out_entry->trans_mode = vtp->cfg.trans_mode;
	out_entry->role = vtp->role;
	out_entry->eid_idx = vtp->eid_idx;
	out_entry->upi = vtp->upi;
	out_entry->share_mode = vtp->share_mode;
	out_entry->restore_succeed = false;

	if (vtp->cfg.trans_mode == UBCORE_TP_RM || vtp->cfg.trans_mode == UBCORE_TP_RC) {
		if (vtp->cfg.tpg == NULL) {
			ubcore_log_err("tpg is null");
			return -1;
		}

		if (vtp->cfg.tpg->tp_list[0] == NULL) {
			ubcore_log_err("tpg->tp_list[0] is null");
			return -1;
		}
		out_entry->local_net_addr_idx = vtp->cfg.tpg->tp_list[0]->local_net_addr_idx;
		out_entry->dip = vtp->cfg.tpg->tp_list[0]->peer_net_addr;
		out_entry->tpgn = vtp->cfg.tpg->tpgn;
		out_entry->tp_cnt = vtp->cfg.tpg->tpg_cfg.tp_cnt;
		for (dev_tpn_idx = 0; dev_tpn_idx < out_entry->tp_cnt; dev_tpn_idx++)
			out_entry->tpn[dev_tpn_idx] = (vtp->cfg.tpg->tp_list[dev_tpn_idx] == NULL ?
				0 : vtp->cfg.tpg->tp_list[dev_tpn_idx]->tpn);
	} else {
		if (vtp->cfg.utp == NULL) {
			ubcore_log_err("utp is null");
			return -1;
		}
		out_entry->local_net_addr_idx = vtp->cfg.utp->utp_cfg.local_net_addr_idx;
		out_entry->utp_idx = vtp->cfg.utp->utpn;
		out_entry->dip = vtp->cfg.utp->utp_cfg.peer_net_addr;
	}

	sip_entry = ubcore_lookup_sip_info_without_lock(
		&dev->sip_table, out_entry->local_net_addr_idx);
	if (sip_entry == NULL) {
		ubcore_log_err("sip does not exist\n");
		return -1;
	}
	out_entry->sip = sip_entry->addr;
	(void)memcpy(out_entry->dev_name, dev_name, UBCORE_MAX_DEV_NAME);
	return 0;
}

static void ubcore_get_dev_vtp_table(struct ubcore_device *dev, enum ubcore_hash_table_type type,
	uint32_t *out_entry_idx, struct ubcore_cmd_restored_vtp_entry *arg)
{
	uint32_t dev_vtp_idx, dev_vtp_cnt = 0;
	struct ubcore_vtp **e = NULL;

	e = ubcore_get_all_vtp(&dev->ht[type], &dev_vtp_cnt);
	if (dev_vtp_cnt == 0 || e == NULL)
		return;

	for (dev_vtp_idx = 0; dev_vtp_idx < dev_vtp_cnt; dev_vtp_idx++) {
		if (ubcore_assign_single_out_vtp_table(dev, e[dev_vtp_idx],
			&arg->out.entry[*out_entry_idx], dev->dev_name) != 0) {
			continue;
		} else {
			(*out_entry_idx)++;
		}
	}

	kfree(e);
}

static int ubcore_cmd_restore_vtp_table(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_restored_vtp_entry *arg;
	struct ubcore_device **dev_list = NULL;
	uint32_t dev_cnt, i = 0, out_idx = 0;
	int ret;

	dev_list = ubcore_get_all_tpf_device(UBCORE_TRANSPORT_UB, &dev_cnt);
	if (dev_cnt == 0) {
		ubcore_log_info("dev count is 0\n");
		return 0;
	}

	if (dev_list == NULL) {
		ubcore_log_info("dev list is NULL\n");
		return -1;
	}

	if (hdr->args_len > sizeof(struct ubcore_cmd_restored_vtp_entry) +
		dev_cnt * UBCORE_MAX_VTP_CNT_PER_TPF * sizeof(struct ubcore_restored_vtp_entry)) {
		ubcore_log_info("hdr->args_len too long to alloc\n");
		ret = -1;
		goto free_dev;
	}

	arg = kcalloc(1, hdr->args_len, GFP_KERNEL);
	if (arg == NULL) {
		ret = -ENOMEM;
		goto free_dev;
	}

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr, hdr->args_len);
	if (ret != 0)
		goto free_arg;

	arg->out.vtp_cnt = 0;
	for (i = 0; i < dev_cnt; ++i) {
		arg->out.vtp_cnt += ubcore_get_all_vtp_cnt(&dev_list[i]->ht[UBCORE_HT_RM_VTP]);
		arg->out.vtp_cnt += ubcore_get_all_vtp_cnt(&dev_list[i]->ht[UBCORE_HT_UM_VTP]);
	}
	if (arg->out.vtp_cnt != arg->in.vtp_cnt) {
		ubcore_log_warn("input vtp_cnt: %u does not match current vtp_cnt: %u\n",
			arg->in.vtp_cnt, arg->out.vtp_cnt);
		ret = -1;
		goto free_arg;
	}

	for (i = 0; i < dev_cnt; ++i) {
		ubcore_get_dev_vtp_table(dev_list[i], UBCORE_HT_RM_VTP, &out_idx, arg);
		ubcore_get_dev_vtp_table(dev_list[i], UBCORE_HT_UM_VTP, &out_idx, arg);
	}

	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, arg, hdr->args_len) != 0)
		ret = -EPERM;

free_arg:
	kfree(arg);

free_dev:
	ubcore_put_devices(dev_list, dev_cnt);
	return ret;
}

// target vtp is pseudo.
static int ubcore_cmd_map_target_vtp(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_map_target_vtp *arg;
	struct ubcore_vtp_cfg vtp_cfg;
	struct ubcore_vtp *vtp = NULL;
	struct ubcore_device *dev;
	struct ubcore_tpg *tpg = NULL;
	struct ubcore_utp *utp = NULL;
	struct ubcore_ctp *ctp = NULL;
	int ret;

	arg = kzalloc(sizeof(struct ubcore_cmd_map_target_vtp), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_map_target_vtp));
	if (ret != 0)
		goto free_arg;

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		goto free_arg;
	}

	if (arg->in.vtp.flag.bs.clan_tp == 0) {
		/* deal with trans domain -G */
		if (arg->in.vtp.trans_mode != UBCORE_TP_UM) {
			/* deal with RM first */
			tpg = ubcore_find_get_tpg(dev, arg->in.vtp.tpgn);
			if (tpg == NULL) {
				ret = -EINVAL;
				ubcore_log_err("Failed to find tpg, tpgn: %u.\n", arg->in.vtp.tpgn);
				goto put_device;
			}
			ubcore_set_vtp2tpg_cfg(&vtp_cfg, &arg->in.vtp, tpg);
		} else {
			/* deal with UM */
			utp = ubcore_find_get_utp(dev, arg->in.vtp.utpn);
			if (utp == NULL) {
				ret = -EINVAL;
				ubcore_log_err("Failed to find utp, utpn: %u.\n", arg->in.vtp.utpn);
				goto put_device;
			}
			ubcore_set_vtp2utp_cfg(&vtp_cfg, &arg->in.vtp, utp);
		}
	} else {
		/* deal with trans domain -C */
		ctp = ubcore_find_get_ctp(dev, arg->in.vtp.ctpn);
		if (ctp == NULL) {
			ret = -EINVAL;
			ubcore_log_err("Failed to find ctp, ctpn: %u.\n", arg->in.vtp.ctpn);
			goto put_device;
		}
		ubcore_set_vtp2ctp_cfg(&vtp_cfg, &arg->in.vtp, ctp);
	}

	vtp = ubcore_check_and_map_target_vtp(dev, &vtp_cfg, arg->in.role);
	if (vtp == NULL) {
		ret = -EPERM;
		goto put_tpg_and_utp;
	}
	vtp->role = (vtp->role != arg->in.role ? UBCORE_VTP_DUPLEX : vtp->role);
	vtp->eid_idx = arg->in.eid_idx;
	vtp->upi = arg->in.upi;
	vtp->share_mode = arg->in.share_mode;
	ubcore_vtp_kref_put(vtp);

put_tpg_and_utp:
	ubcore_put_tpg_utp_ctp_in_vtp(&arg->in.vtp, tpg, utp, ctp);
put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static int ubcore_query_fe_stats(struct ubcore_device *dev,
	struct ubcore_list_migrate_entry_param *param, uint32_t cnt)
{
	int ret;
	uint32_t i;
	struct ubcore_fe_stats *stats = NULL;
	uint16_t *fe_idx = NULL;

	if (dev->ops == NULL || dev->ops->query_fe_stats == NULL) {
		ubcore_log_err("Device without query_fe_stats, dev_name: %s", dev->dev_name);
		return -ENODEV;
	}

	if (cnt > UBCORE_MAX_MIG_ENTRY_CNT) {
		ubcore_log_warn("count too long to alloc, cnt = %u\n", cnt);
		return -ENOMEM;
	}

	fe_idx = kcalloc(1, cnt * sizeof(uint16_t), GFP_KERNEL);
	if (fe_idx == NULL)
		return -ENOMEM;

	stats = kcalloc(1, cnt * sizeof(struct ubcore_fe_stats), GFP_KERNEL);
	if (fe_idx == NULL) {
		ret = -ENOMEM;
		goto free_idx;
	}

	for (i = 0; i < cnt; i++)
		fe_idx[i] = param[i].fe_idx;

	ret = dev->ops->query_fe_stats(dev, cnt, fe_idx, stats);
	if (ret != 0) {
		ubcore_log_err("Fail to query_fe_stats, ret: %d, dev_name: %s", ret, dev->dev_name);
		goto free_stats;
	}

	for (i = 0; i < cnt; i++)
		param[i].stats = stats[i];

free_stats:
	kfree(stats);
free_idx:
	kfree(fe_idx);
	return ret;
}

static int ubcore_cmd_list_migrate_entry(struct ubcore_cmd_hdr *hdr)
{
	int ret = 0;
	struct ubcore_cmd_list_migrate_entry *arg = NULL;
	struct ubcore_device *dev = NULL;
	uint32_t cnt = 0;

	if (hdr->args_len > sizeof(struct ubcore_cmd_list_migrate_entry) +
		UBCORE_MAX_MIG_ENTRY_CNT * sizeof(struct ubcore_list_migrate_entry_param)) {
		ubcore_log_warn("hdr->args_len too long to alloc, len = %u\n", hdr->args_len);
		return -ENOMEM;
	}

	arg = kcalloc(1, hdr->args_len, GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	ret = ubcore_copy_from_user(arg, (void __user *)(uintptr_t)hdr->args_addr, hdr->args_len);
	if (ret != 0)
		goto free_arg;

	cnt = arg->in.cnt;
	if (cnt * sizeof(struct ubcore_list_migrate_entry_param) +
		sizeof(ubcore_cmd_list_migrate_entry) != hdr->args_len) {
		ret = -EINVAL;
		ubcore_log_err("Invalid argument, args_len = %u, cnt = %u", hdr->args_len, cnt);
		goto free_arg;
	}

	dev = ubcore_find_tpf_device(&arg->in.tpf.netaddr, arg->in.tpf.trans_type);
	if (dev == NULL) {
		ret = -ENODEV;
		ubcore_log_err("fail to find tpf device");
		goto free_arg;
	}

	ret = ubcore_query_fe_stats(dev, arg->param, cnt);
	if (ret != 0)
		goto put_device;

	if (ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr,
		arg, hdr->args_len) != 0) {
		ret = -EPERM;
		goto put_device;
	}

put_device:
	ubcore_put_device(dev);
free_arg:
	kfree(arg);
	return ret;
}

static void ubcore_fill_stats_val(struct ubcore_stats_com_val com_val,
	struct ubcore_cmd_opt_dfx_query_stats *arg)
{
	arg->out.tx_pkt = com_val.tx_pkt;
	arg->out.rx_pkt = com_val.rx_pkt;
	arg->out.tx_bytes = com_val.tx_bytes;
	arg->out.rx_bytes = com_val.rx_bytes;
	arg->out.tx_pkt_err = com_val.tx_pkt_err;
	arg->out.rx_pkt_err = com_val.rx_pkt_err;
}

static void ubcore_fill_fe_stats_val(struct ubcore_fe_stats stats,
	struct ubcore_cmd_opt_dfx_query_stats *arg)
{
	arg->out.tx_pkt = stats.tx_pkt;
	arg->out.rx_pkt = stats.rx_pkt;
	arg->out.tx_bytes = stats.tx_bytes;
	arg->out.rx_bytes = stats.rx_bytes;
	arg->out.tx_pkt_err = stats.tx_pkt_err;
	arg->out.rx_pkt_err = stats.rx_pkt_err;

	arg->out.tx_timeout_cnt = stats.tx_timeout_cnt;
	arg->out.rx_ce_pkt = stats.rx_ce_pkt;
}

static int ubcore_dfx_query_stats(struct ubcore_device *dev,
	struct ubcore_cmd_opt_dfx_query_stats *arg)
{
	struct ubcore_stats_com_val com_val;
	struct ubcore_stats_key key;
	struct ubcore_stats_val val;
	int ret;

	if (dev->ops == NULL || dev->ops->query_stats == NULL) {
		ubcore_log_warn("dev ops does not contain query_stats");
		return 0;
	}
	key.type = arg->in.type;
	key.key = arg->in.id;
	val.addr = (uint64_t)&com_val;
	val.len = (uint32_t)sizeof(struct ubcore_stats_com_val);

	ret = ubcore_query_stats(dev, &key, &val);
	if (ret != 0) {
		ubcore_log_err("fail to query stats");
		return ret;
	}

	ubcore_fill_stats_val(com_val, arg);
	return ret;
}

static int ubcore_dfx_query_fe_stats(struct ubcore_device *dev,
	struct ubcore_cmd_opt_dfx_query_stats *arg)
{
	struct ubcore_fe_stats stats;
	int ret;

	uint16_t fe_idx = (uint16_t)arg->in.id;

	if (dev == NULL || dev->ops == NULL || dev->ops->query_fe_stats == NULL) {
		ubcore_log_err("Invalid dev.\n");
		return -1;
	}

	ret = dev->ops->query_fe_stats(dev, 1, &fe_idx, &stats);
	if (ret != 0) {
		ubcore_log_err("Fail to query_fe_stats, ret: %d, dev_name: %s", ret, dev->dev_name);
		return -1;
	}

	ubcore_fill_fe_stats_val(stats, arg);
	return ret;
}

static int ubcore_cmd_opt_dfx_query_stats(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_opt_dfx_query_stats arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_opt_dfx_query_stats));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_warn("fail to find dev:%s\n", arg.in.dev_name);
		return -ENODEV;
	}

	switch (arg.in.type) {
	case UBCORE_STATS_KEY_VTP:
	case UBCORE_STATS_KEY_TP:
	case UBCORE_STATS_KEY_TPG:
		ret = ubcore_dfx_query_stats(dev, &arg);
		break;
	case UBCORE_STATS_KEY_URMA_DEV:
		ret = ubcore_dfx_query_fe_stats(dev, &arg);
		break;
	default:
		ret = -1;
		break;
	}

	if (ret != 0) {
		ubcore_log_err("fail to query stats, dev: %s, type: %u\n",
			arg.in.dev_name, arg.in.type);
		goto put_device;
	}

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_opt_dfx_query_stats));

put_device:
	ubcore_put_device(dev);
	return ret;
}

static int ubcore_fill_tpg_info(struct ubcore_device *dev, struct ubcore_res_tpg_val tpg,
	struct ubcore_cmd_opt_dfx_query_res *arg)
{
	enum ubcore_tp_state tp_state[UBCORE_MAX_TP_CNT_IN_GRP] = {0};
	struct ubcore_tp *tp_infos = NULL;
	int i = 0;

	for (i = 0; i < tpg.tp_cnt; i++) {
		tp_infos = ubcore_find_get_tp(dev, tpg.tp_list[i]);
		if (tp_infos == NULL) {
			ubcore_log_err("Unknown tpn: %d", tpg.tp_list[i]);
			return -1;
		}
		tp_state[i] = tp_infos->state;
		ubcore_tp_kref_put(tp_infos);
	}
	(void)memcpy(arg->out.tpg.tp_state,
		tp_state, sizeof(arg->out.tpg.tp_state));
	(void)memcpy(arg->out.tpg.tpn, tpg.tp_list,
		tpg.tp_cnt * sizeof(*(tpg.tp_list)));
	arg->out.tpg.dscp = tpg.dscp;
	arg->out.tpg.tp_cnt = tpg.tp_cnt;
	return 0;
}

static int ubcore_cmd_opt_dfx_query_res_with_type(struct ubcore_device *dev,
	struct ubcore_cmd_opt_dfx_query_res *arg)
{
	struct ubcore_res_tpg_val tpg = {0};
	struct ubcore_res_key key = {0};
	struct ubcore_res_val val = {0};
	int ret = -1;

	key.type = (uint8_t)arg->in.type;
	key.key = arg->in.key;
	key.key_ext = arg->in.key_ext;
	key.key_cnt = arg->in.key_cnt;

	switch (arg->in.type) {
	case UBCORE_RES_KEY_VTP:
		val.addr = (uint64_t)&arg->out.vtp;
		val.len = (uint32_t)sizeof(struct ubcore_res_vtp_val);
		break;
	case UBCORE_RES_KEY_TP:
		val.addr = (uint64_t)&arg->out.tp;
		val.len = (uint32_t)sizeof(struct ubcore_res_tp_val);
		break;
	case UBCORE_RES_KEY_TPG:
		val.addr = (uint64_t)&tpg;
		val.len = (uint32_t)sizeof(struct ubcore_res_tpg_val);
		break;
	case UBCORE_RES_KEY_UTP:
		val.addr = (uint64_t)&arg->out.utp;
		val.len = (uint32_t)sizeof(struct ubcore_res_utp_val);
		break;
	case UBCORE_RES_KEY_DEV_TP:
		val.addr = (uint64_t)&arg->out.tpf;
		val.len = (uint32_t)sizeof(struct ubcore_res_dev_tp_val);
		break;
	default:
		ubcore_log_err("Unsupported type: %d", arg->in.type);
		return -1;
	}

	ret = ubcore_query_resource(dev, &key, &val);
	if (ret == 0 && arg->in.type == UBCORE_RES_KEY_TPG) {
		ret = ubcore_fill_tpg_info(dev, tpg, arg);
		vfree(tpg.tp_list);
	}
	return ret;
}

static int ubcore_cmd_opt_dfx_query_res(struct ubcore_cmd_hdr *hdr)
{
	struct ubcore_cmd_opt_dfx_query_res arg;
	struct ubcore_device *dev;
	int ret;

	ret = ubcore_copy_from_user(&arg, (void __user *)(uintptr_t)hdr->args_addr,
		sizeof(struct ubcore_cmd_opt_dfx_query_res));
	if (ret != 0)
		return ret;

	arg.in.dev_name[UBCORE_MAX_DEV_NAME - 1] = '\0';
	dev = ubcore_find_device_with_name(arg.in.dev_name);
	if (dev == NULL) {
		ubcore_log_warn("fail to find dev:%s\n", arg.in.dev_name);
		return -ENODEV;
	}

	ret = ubcore_cmd_opt_dfx_query_res_with_type(dev, &arg);
	if (ret != 0) {
		ubcore_log_err("fail to query res, dev: %s, type: %u\n",
			arg.in.dev_name, arg.in.type);
		goto put_device;
	}

	ret = ubcore_copy_to_user((void __user *)(uintptr_t)hdr->args_addr, &arg,
		sizeof(struct ubcore_cmd_opt_dfx_query_res));

put_device:
	ubcore_put_device(dev);
	return ret;
}

typedef int (*ubcore_uvs_cmd_handler)(struct ubcore_cmd_hdr *hdr);
struct ubcore_uvs_cmd_func {
	ubcore_uvs_cmd_handler func;
	bool need_cap_verify;
};

static struct ubcore_uvs_cmd_func g_ubcore_uvs_cmd_funcs[] = {
	[0] = {NULL, false},
	[UBCORE_CMD_CHANNEL_INIT] = {ubcore_uvs_cmd_channel_init, false},
	[UBCORE_CMD_CREATE_TPG] = {ubcore_cmd_create_tpg, false},
	[UBCORE_CMD_CREATE_VTP] = {ubcore_cmd_create_vtp, false},
	[UBCORE_CMD_MODIFY_TPG] = {ubcore_cmd_modify_tpg, false},
	[UBCORE_CMD_MODIFY_TPG_MAP_VTP] = {ubcore_cmd_modify_tpg_map_vtp, false},
	[UBCORE_CMD_MODIFY_TPG_TP_CNT] = {ubcore_cmd_modify_tpg_tp_cnt, false},
	[UBCORE_CMD_CREATE_TARGET_TPG] = {ubcore_cmd_create_target_tpg, false},
	[UBCORE_CMD_MODIFY_TARGET_TPG] = {ubcore_cmd_modify_target_tpg, false},
	[UBCORE_CMD_DESTROY_VTP] = {ubcore_cmd_destroy_vtp, false},
	[UBCORE_CMD_DESTROY_TPG] = {ubcore_cmd_destroy_tpg, false},
	[UBCORE_CMD_ADD_SIP] = {ubcore_cmd_opt_sip, true},
	[UBCORE_CMD_DEL_SIP] = {ubcore_cmd_opt_sip, true},
	[UBCORE_CMD_MAP_VTP] = {ubcore_cmd_map_vtp, false},
	[UBCORE_CMD_CREATE_UTP] = {ubcore_cmd_create_utp, false},
	[UBCORE_CMD_ONLY_CREATE_UTP] = {ubcore_cmd_only_create_utp, false},
	[UBCORE_CMD_DESTROY_UTP] = {ubcore_cmd_destroy_utp, false},
	[UBCORE_CMD_RESTORE_TP_ERROR_RSP] = {ubcore_cmd_restore_tp_error_rsp, false},
	[UBCORE_CMD_RESTORE_TARGET_TP_ERROR_REQ] = {
		ubcore_cmd_restore_target_tp_error_req, false},
	[UBCORE_CMD_RESTORE_TARGET_TP_ERROR_ACK] = {
		ubcore_cmd_restore_target_tp_error_ack, false},
	[UBCORE_CMD_RESTORE_TP_SUSPEND] = {ubcore_cmd_restore_tp_suspend, false},
	[UBCORE_CMD_GET_DEV_FEATURE] = {ubcore_cmd_get_dev_feature, false},
	[UBCORE_CMD_CHANGE_TP_TO_ERROR] = {ubcore_cmd_change_tp_to_error, false},
	[UBCORE_CMD_SET_UPI] =  {ubcore_cmd_set_upi, true},
	[UBCORE_CMD_SHOW_UPI] =  {ubcore_cmd_show_upi, false},
	[UBCORE_CMD_SET_GLOBAL_CFG] =  {ubcore_cmd_set_global_cfg, true},
	[UBCORE_CMD_CONFIG_FUNCTION_MIGRATE_STATE] = {
		ubcore_cmd_config_function_migrate_state, false},
	[UBCORE_CMD_SET_VPORT_CFG] =  {ubcore_cmd_set_vport_cfg, true},
	[UBCORE_CMD_MODIFY_VTP] = {ubcore_cmd_modify_vtp, false},
	[UBCORE_CMD_GET_DEV_INFO] = {ubcore_cmd_get_dev_info, false},
	[UBCORE_CMD_CREATE_CTP] = {ubcore_cmd_create_ctp, false},
	[UBCORE_CMD_DESTROY_CTP] = {ubcore_cmd_destroy_ctp, false},
	[UBCORE_CMD_CHANGE_TPG_TO_ERROR] = {ubcore_cmd_change_tpg_to_error, false},
	[UBCORE_CMD_ALLOC_EID] = {ubcore_cmd_opt_update_eid, true},
	[UBCORE_CMD_DEALLOC_EID] = {ubcore_cmd_opt_update_eid, true},
	[UBCORE_CMD_QUERY_FE_IDX] = {ubcore_cmd_opt_query_fe_idx, false},
	[UBCORE_CMD_CONFIG_DSCP_VL] = {ubcore_cmd_opt_config_dscp_vl, true},
	[UBCORE_CMD_GET_VTP_TABLE_CNT] = {ubcore_cmd_get_vtp_table_cnt, false},
	[UBCORE_CMD_RESTORE_TABLE] = {ubcore_cmd_restore_vtp_table, false},
	[UBCORE_CMD_MAP_TARGET_VTP] = {ubcore_cmd_map_target_vtp, false},
	[UBCORE_CMD_LIST_MIGRATE_ENTRY] = {ubcore_cmd_list_migrate_entry, false},
	[UBCORE_CMD_QUERY_DSCP_VL] = {ubcore_cmd_opt_query_dscp_vl, false},
	[UBCORE_CMD_DFX_QUERY_STATS] = {ubcore_cmd_opt_dfx_query_stats, false},
	[UBCORE_CMD_DFX_QUERY_RES] = {ubcore_cmd_opt_dfx_query_res, false},
};

int ubcore_uvs_cmd_parse(struct ubcore_cmd_hdr *hdr)
{
	if (hdr->command < UBCORE_CMD_CHANNEL_INIT || hdr->command >= UBCORE_CMD_LAST ||
		g_ubcore_uvs_cmd_funcs[hdr->command].func == NULL) {
		ubcore_log_err("bad ubcore command: %d.\n", (int)hdr->command);
		return -EINVAL;
	}

	if (g_ubcore_uvs_cmd_funcs[hdr->command].need_cap_verify && !capable(CAP_NET_ADMIN)) {
		ubcore_log_err("failed cap verify, ubcore command: %d.\n", (int)hdr->command);
		return -EPERM;
	}
	return g_ubcore_uvs_cmd_funcs[hdr->command].func(hdr);
}
