// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Description: ubcore kernel module
 * Author: Qian Guoxin
 * Create: 2021-08-03
 * Note:
 * History: 2021-08-03: create file
 */

#include <net/addrconf.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/inetdevice.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/types.h>

#include "ubcore_cmd.h"
#include "ubcore_uvs_cmd.h"
#include "ubcore_log.h"
#include "ubcore_netlink.h"
#include <urma/ubcore_types.h>
#include <urma/ubcore_api.h>
#include <urma/ubcore_uapi.h>
#include "ubcore_priv.h"
#include "ubcore_netdev.h"
#include "ubcore_msg.h"
#include "ubcore_genl.h"
#include "ubcore_workqueue.h"
#include "ubcore_device.h"

#include "ubcore_main.h"

#define UBCORE_LOG_FILE_PERMISSION (0644)

module_param(g_ubcore_log_level, uint, UBCORE_LOG_FILE_PERMISSION);
MODULE_PARM_DESC(g_ubcore_log_level, " 3: ERR, 4: WARNING, 6: INFO, 7: DEBUG");

/* ubcore create independent cdev and ioctl channels
 * to handle public work.
 */
#define UBCORE_IPV4_MAP_IPV6_PREFIX 0x0000ffff
#define UBCORE_LOCAL_SHUNET (0xfe80000000000000ULL)
#define SIP_MTU_BITS_BASE_SHIFT 7

struct ubcore_net_addr_node {
	struct list_head node;
	struct ubcore_net_addr addr;
};

enum ubcore_bond_op_type {
	UBCORE_BOND_ADD = 0,
	UBCORE_BOND_REMOVE,
	UBCORE_BOND_SLAVE_UPDATE
};

struct ubcore_bond_event_work {
	struct work_struct work;
	struct netdev_lag_upper_info info_upper;
	struct netdev_lag_lower_state_info info_lower;
	enum ubcore_bond_op_type bond_op_type;
	struct net_device *slave;
	struct net_device *bond;
	int (*bond_add)(struct net_device *bond, struct net_device *slave,
		struct netdev_lag_upper_info *upper_info);
	int (*bond_remove)(struct net_device *bond, struct net_device *slave);
	int (*slave_update)(struct net_device *bond, struct net_device *slave,
		struct netdev_lag_lower_state_info *lower_info);
};

enum ubcore_sip_op_type {
	UBCORE_SIP_DEL = 0,
	UBCORE_SIP_ADD,
	UBCORE_SIP_UPDATE
};

struct ubcore_notify_uvs_sip_event_work {
	struct work_struct work;
	struct ubcore_device *tpf_dev;
	struct ubcore_sip_info new_sip;
	struct ubcore_sip_info old_sip;
	enum ubcore_sip_op_type sip_op;
	uint32_t index;
};

struct ubcore_version {
	uint32_t version; /* UBCORE_INVALID_VERSION: not negotiated yet. */
	uint32_t cap; /* Currently, not used. */
};

static struct ubcore_version g_ubcore_version = {UBCORE_INVALID_VERSION, 0};
/* Versions should be in decending order. */
static uint32_t g_ubcore_support_versions[UBCORE_SUPPORT_VERION_NUM] = {UBCORE_VERSION0};

bool ubcore_negotiated(void)
{
	return g_ubcore_version.version != UBCORE_INVALID_VERSION;
}

uint32_t ubcore_get_version(void)
{
	return g_ubcore_version.version;
}

void ubcore_set_version(uint32_t version)
{
	g_ubcore_version.version = version;
}

uint32_t ubcore_get_cap(void)
{
	return g_ubcore_version.cap;
}

void ubcore_set_cap(uint32_t cap)
{
	g_ubcore_version.cap = cap;
}

uint32_t *ubcore_get_support_versions(void)
{
	return g_ubcore_support_versions;
}

/* Caller should ensure parameters are not NULL. */
int ubcore_negotiate_version(struct ubcore_msg_nego_ver_req *req, uint32_t *ver, uint32_t *cap)
{
	uint32_t ver_ = UBCORE_INVALID_VERSION;
	uint32_t cap_ = UBCORE_CAP & req->cap;
	uint32_t i, j;

	for (i = 0; i < req->version_num; i++) {
		for (j = 0; j < UBCORE_SUPPORT_VERION_NUM; j++) {
			if (req->versions[i] == g_ubcore_support_versions[j]) {
				ver_ = req->versions[i];
				break;
			}
		}
	}

	if (ver_ == UBCORE_INVALID_VERSION)
		return -1;

	*ver = ver_;
	*cap = cap_;
	return 0;
}

int ubcore_open(struct inode *i_node, struct file *filp)
{
	return 0;
}

static void ubcore_ipv4_to_netaddr(struct ubcore_net_addr *netaddr, __be32 ipv4)
{
	netaddr->net_addr.in4.reserved1 = 0;
	netaddr->net_addr.in4.reserved2 = htonl(UBCORE_IPV4_MAP_IPV6_PREFIX);
	netaddr->net_addr.in4.addr = ipv4;
}

static inline uint32_t sip_mtu_enum_to_int(enum ubcore_mtu mtu)
{
	return (uint32_t)(1 << ((uint32_t)mtu + SIP_MTU_BITS_BASE_SHIFT));
}

static enum ubcore_mtu sip_get_mtu(uint32_t mtu)
{
	if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_8192))
		return UBCORE_MTU_8192;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_4096))
		return UBCORE_MTU_4096;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_2048))
		return UBCORE_MTU_2048;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_1024))
		return UBCORE_MTU_1024;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_512))
		return UBCORE_MTU_512;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_256))
		return UBCORE_MTU_256;
	else
		return (enum ubcore_mtu)0;
}

static enum ubcore_mtu sip_get_mtu_with_ub(uint32_t mtu)
{
	if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_8192))
		return UBCORE_MTU_8192;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_4096))
		return UBCORE_MTU_4096;
	else if (mtu >= sip_mtu_enum_to_int(UBCORE_MTU_1024))
		return UBCORE_MTU_1024;
	else
		return (enum ubcore_mtu)0;
}

static void ubcore_sip_init(struct ubcore_sip_info *sip, struct ubcore_device *dev,
	const struct ubcore_net_addr *netaddr, struct net_device *netdev)
{
	(void)memcpy(sip->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
	(void)memcpy(&sip->addr, netaddr, sizeof(struct ubcore_net_addr));

	ubcore_fill_port_netdev(dev, netdev, sip->port_id, &sip->port_cnt);
	sip->mtu = dev->transport_type == UBCORE_TRANSPORT_UB ?
		(uint32_t)sip_get_mtu_with_ub(netdev->mtu) : (uint32_t)sip_get_mtu(netdev->mtu);
	(void)memcpy(sip->netdev_name, netdev_name(netdev),
		UBCORE_MAX_DEV_NAME);
}

static void ubcore_notify_uvs_update_sip(
	struct ubcore_device *tpf_dev, struct ubcore_sip_info *new_sip,
	struct ubcore_sip_info *old_sip, uint32_t index)
{
	(void)ubcore_notify_uvs_del_sip(tpf_dev, old_sip, index);
	(void)ubcore_notify_uvs_add_sip(tpf_dev, new_sip, index);
}

static bool ubcore_notify_uvs_update_sip_sync(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *new_sip, struct ubcore_sip_info *old_sip,
	enum ubcore_sip_op_type sip_op, uint32_t index)
{
	if (ubcore_get_netlink_valid() != true)
		return true;

	switch (sip_op) {
	case UBCORE_SIP_DEL:
		(void)ubcore_notify_uvs_del_sip(tpf_dev, old_sip, index);
		return true;
	case UBCORE_SIP_ADD:
		(void)ubcore_notify_uvs_add_sip(tpf_dev, new_sip, index);
		return true;
	case UBCORE_SIP_UPDATE:
		ubcore_notify_uvs_update_sip(tpf_dev, new_sip, old_sip, index);
		return true;
	default:
		ubcore_log_err("sip_op_type out of range");
		return false;
	}
}

static void ubcore_notify_uvs_update_sip_task(struct work_struct *work)
{
	struct ubcore_notify_uvs_sip_event_work *l_work = container_of(
		work, struct ubcore_notify_uvs_sip_event_work, work);

	(void)ubcore_notify_uvs_update_sip_sync(
		l_work->tpf_dev, &l_work->new_sip, &l_work->old_sip, l_work->sip_op, l_work->index);
	kfree(l_work);
}

static int ubcore_notify_uvs_update_sip_async(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *new_sip, struct ubcore_sip_info *old_sip,
	enum ubcore_sip_op_type sip_op, uint32_t index)
{
	struct ubcore_notify_uvs_sip_event_work *work;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return -ENOMEM;

	INIT_WORK(&work->work, ubcore_notify_uvs_update_sip_task);
	work->tpf_dev = tpf_dev;
	if (new_sip != NULL)
		work->new_sip = *(new_sip);
	if (old_sip != NULL)
		work->old_sip = *(old_sip);
	work->index = index;
	work->sip_op = sip_op;
	if (ubcore_queue_work((int)UBCORE_SIP_NOTIFY_WQ, &work->work) != 0) {
		kfree(work);
		ubcore_log_err("Queue work failed");
		return -1;
	}
	return 0;
}

static int ubcore_notify_uvs_update_sip_manage(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *new_sip, struct ubcore_sip_info *old_sip,
	enum ubcore_sip_op_type sip_op, uint32_t index, bool async)
{
	int ret = 0;

	if (!async) {
		(void)ubcore_notify_uvs_update_sip_sync(tpf_dev, new_sip, old_sip, sip_op, index);
		return 0;
	}

	ret = ubcore_notify_uvs_update_sip_async(tpf_dev, new_sip, old_sip, sip_op, index);
	if (ret != 0)
		ubcore_log_err("kzalloc failed or queue type err");
	return ret;
}


static int ubcore_get_upi(char *dev_name, uint32_t pattern, uint32_t *upi)
{
	if (pattern == UBCORE_PATTERN_1) {
		*upi = 0;
		return 0;
	}

	if (pattern == UBCORE_PATTERN_3) {
		if (ubcore_find_upi_with_dev_name(dev_name, upi) == NULL) {
			ubcore_log_err("can not find dev:%s\n", dev_name);
			return -EINVAL;
		}

		if (*upi == (uint32_t)UCBORE_INVALID_UPI) {
			ubcore_log_err("dev:%s not cfg upi in pattern3 mode\n", dev_name);
			return -EINVAL;
		}
		return 0;
	}

	ubcore_log_err("Invalid pattern\n");
	return -EINVAL;
}

static int ubcore_handle_update_eid(struct ubcore_device *tpf_dev, uint32_t fe_idx,
	enum ubcore_net_addr_op op, struct ubcore_eid_update_info *eid_info)
{
	struct ubcore_ueid_cfg cfg = {0};

	cfg.eid = eid_info->eid;
	cfg.eid_index = eid_info->eid_idx;

	if (eid_info->upi_present) {
		cfg.upi = eid_info->upi;
	} else {
		if (ubcore_get_upi(eid_info->dev_name, eid_info->pattern, &cfg.upi) != 0) {
			ubcore_log_err("Failed to upi, dev:%s, idx:%u",
				eid_info->dev_name, eid_info->eid_idx);
			return -ENXIO;
		}
	}

	if (op == UBCORE_ADD_NET_ADDR)
		return ubcore_add_ueid(tpf_dev, fe_idx, &cfg);

	if (op == UBCORE_DEL_NET_ADDR)
		return ubcore_delete_ueid(tpf_dev, fe_idx, &cfg);

	return -EINVAL;
}

int ubcore_recv_eid_update_req(struct ubcore_device *tpf_dev, struct ubcore_req_host *req)
{
	struct ubcore_update_eid_req *msg_data = (struct ubcore_update_eid_req *)req->req.data;

	ubcore_handle_update_eid(tpf_dev, req->src_fe_idx, msg_data->op, &msg_data->eid_info);
	return 0;
}

int ubcore_send_eid_update_req(struct ubcore_device *dev, enum ubcore_net_addr_op op,
	union ubcore_eid *eid, uint32_t eid_idx, uint32_t *upi)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_update_eid_req);
	struct ubcore_update_eid_req *msg_data;
	struct ubcore_req *req;
	int ret;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return -ENOMEM;
	req->opcode = UBCORE_MSP_UPDATE_EID;
	req->len = data_len;

	msg_data = (struct ubcore_update_eid_req *)req->data;

	msg_data->op = op;
	msg_data->eid_info.eid = *eid;
	msg_data->eid_info.pattern = dev->attr.pattern;
	if (upi) {
		msg_data->eid_info.upi_present = true;
		msg_data->eid_info.upi = *upi;
	}

	if (dev->attr.tp_maintainer)
		ret = ubcore_handle_update_eid(dev, dev->attr.fe_idx,
			msg_data->op, &msg_data->eid_info);
	else
		/* handle by backend ubcore: ubcore_recv_eid_update_req */
		ret = ubcore_send_req(dev, req);
	kfree(req);
	return ret;
}

static void ubcore_handle_add_sip(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *sip, bool async)
{
	uint32_t index;
	int ret;

	ret = ubcore_lookup_sip_idx(&tpf_dev->sip_table, sip, &index);
	if (ret == 0) {
		ubcore_log_err("sip already exists\n");
		return;
	}

	index = (uint32_t)ubcore_sip_idx_alloc(&tpf_dev->sip_table);

	if (tpf_dev->ops != NULL && tpf_dev->ops->add_net_addr != NULL &&
		tpf_dev->ops->add_net_addr(tpf_dev, &sip->addr, index) != 0)
		ubcore_log_err("Failed to set net addr");

	/* add net_addr entry, record idx -> netaddr mapping */
	(void)ubcore_add_sip_entry(&tpf_dev->sip_table, sip, index);

	/* nodify uvs add sip info */
	if (ubcore_notify_uvs_update_sip_manage(tpf_dev, sip, NULL,
		UBCORE_SIP_ADD, index, async) != 0)
		ubcore_log_err("notify uvs sip failed");
}

static void ubcore_handle_delete_sip(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *sip, bool async)
{
	uint32_t index;

	if (ubcore_lookup_sip_idx(&tpf_dev->sip_table, sip, &index) != 0)
		return;

	if (tpf_dev->ops != NULL && tpf_dev->ops->delete_net_addr != NULL &&
		tpf_dev->ops->delete_net_addr(tpf_dev, index) != 0)
		ubcore_log_err("Failed to delete net addr");

	(void)ubcore_del_sip_entry(&tpf_dev->sip_table, index);
	(void)ubcore_sip_idx_free(&tpf_dev->sip_table, index);
	/* nodify uvs delete sip info */
	if (ubcore_notify_uvs_update_sip_manage(
		tpf_dev, NULL, sip, UBCORE_SIP_DEL, index, async) != 0)
		ubcore_log_err("notify uvs sip failed");
}

static void ubcore_handle_update_sip(struct ubcore_device *tpf_dev,
	struct ubcore_sip_info *sip, bool async)
{
	struct ubcore_sip_info old_sip = {0};
	uint32_t sip_idx;
	int ret = 0;

	ret = ubcore_update_sip_entry(&tpf_dev->sip_table, sip, &sip_idx, &old_sip);
	if (ret != 0) {
		ubcore_log_err("Failed to update sip");
		return;
	}

	if (ubcore_notify_uvs_update_sip_manage(tpf_dev, sip, &old_sip, UBCORE_SIP_UPDATE,
		sip_idx, async) != 0)
		ubcore_log_err("notify uvs sip failed");
}

static int ubcore_handle_update_net_addr(struct ubcore_device *tpf_dev, uint32_t fe_idx,
	struct ubcore_update_net_addr_req *req, bool async)
{
	if (ubcore_is_ub_device(tpf_dev) && req->sip_present) {
		if (req->op == UBCORE_ADD_NET_ADDR)
			ubcore_handle_add_sip(tpf_dev, &req->sip_info, async);
		else if (req->op == UBCORE_DEL_NET_ADDR)
			ubcore_handle_delete_sip(tpf_dev, &req->sip_info, async);
		else if (req->op == UBCORE_UPDATE_NET_ADDR)
			ubcore_handle_update_sip(tpf_dev, &req->sip_info, async);
	}

	if (req->eid_present)
		return ubcore_handle_update_eid(tpf_dev, fe_idx, req->op, &req->eid_info);

	return 0;
}

int ubcore_recv_net_addr_update(struct ubcore_device *tpf_dev, struct ubcore_req_host *req)
{
	struct ubcore_update_net_addr_req *msg_data =
		(struct ubcore_update_net_addr_req *)req->req.data;

	memcpy(msg_data->sip_info.dev_name, tpf_dev->dev_name, UBCORE_MAX_DEV_NAME);

	return ubcore_handle_update_net_addr(tpf_dev, req->src_fe_idx, msg_data, false);
}

static int ubcore_send_net_addr_update_req(struct ubcore_device *dev,
	struct ubcore_update_net_addr_req *add_req)
{
	uint32_t data_len = (uint32_t)sizeof(struct ubcore_update_net_addr_req);
	struct ubcore_update_net_addr_req *msg_data;
	struct ubcore_req *req;
	int ret;

	req = kzalloc(sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req == NULL)
		return -ENOMEM;

	req->opcode = UBCORE_MSG_UPDATE_NET_ADDR;
	req->len = data_len;

	msg_data = (struct ubcore_update_net_addr_req *)req->data;
	*msg_data = *add_req;

	ret = ubcore_send_req(dev, req); // handle by backend ubcore: ubcore_recv_net_addr_update
	kfree(req);
	return ret;
}

static int ubcore_update_eid_tbl(struct ubcore_device *dev,
	struct ubcore_net_addr *netaddr, bool is_add, struct net *net, uint32_t *eid_idx)
{
	union ubcore_eid *eid;

	if (dev->transport_type <= UBCORE_TRANSPORT_INVALID ||
		dev->transport_type >= UBCORE_TRANSPORT_MAX)
		return -EINVAL;

	if (!dev->dynamic_eid) {
		ubcore_log_err("static mode does not allow modify of eid\n");
		return -EINVAL;
	}
	eid = (union ubcore_eid *)(void *)&netaddr->net_addr;
	return ubcore_update_eidtbl_by_eid(dev, eid, eid_idx, is_add, net);
}

static int ubcore_handle_inetaddr_event(struct net_device *netdev, unsigned long event,
	struct ubcore_net_addr *netaddr)
{
	struct ubcore_device **devices;
	uint32_t num_devices = 0;
	struct ubcore_device *dev;

	uint32_t i;

	if (netdev == NULL || netdev->reg_state >= NETREG_UNREGISTERING)
		return NOTIFY_DONE;

	devices = ubcore_get_devices_from_netdev(netdev, &num_devices);
	if (devices == NULL)
		return NOTIFY_DONE;

	for (i = 0; i < num_devices; i++) {
		dev = devices[i];
		if (dev->attr.virtualization)
			continue;

		switch (event) {
		case NETDEV_UP:
			ubcore_update_net_addr(dev, netdev, netaddr, UBCORE_ADD_NET_ADDR, true);
			break;
		case NETDEV_DOWN:
			ubcore_update_net_addr(dev, netdev, netaddr, UBCORE_DEL_NET_ADDR, true);
			break;
		default:
			break;
		}
	}
	ubcore_put_devices(devices, num_devices);

	return NOTIFY_OK;
}

static int ubcore_ipv6_notifier_call(struct notifier_block *nb,
	unsigned long event, void *arg)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->idev == NULL || ifa->idev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->idev->dev;
	ubcore_log_info("Get a ipv6 event %s from netdev %s%s ip %pI6c prefixlen %u\n",
		netdev_cmd_to_name(event), netdev_name(netdev), netdev_reg_state(netdev),
		&ifa->addr, ifa->prefix_len);

	memset(&netaddr, 0, sizeof(struct ubcore_net_addr));
	(void)memcpy(&netaddr.net_addr, &ifa->addr, sizeof(struct in6_addr));
	(void)ubcore_fill_netaddr_macvlan(&netaddr, netdev, UBCORE_NET_ADDR_TYPE_IPV6);
	netaddr.prefix_len = ifa->prefix_len;

	if (netaddr.net_addr.in6.subnet_prefix == cpu_to_be64(UBCORE_LOCAL_SHUNET))
		/* When mtu changes, intercept the ipv6 address up/down that triggers fe80 */
		return NOTIFY_DONE;
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr);
}

static int ubcore_ipv4_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)arg;
	struct ubcore_net_addr netaddr;
	struct net_device *netdev;

	if (ifa == NULL || ifa->ifa_dev == NULL || ifa->ifa_dev->dev == NULL)
		return NOTIFY_DONE;

	netdev = ifa->ifa_dev->dev;
	ubcore_log_info("Get a ipv4 event %s netdev %s%s ip %pI4 prefixlen %hhu",
		netdev_cmd_to_name(event), netdev_name(netdev), netdev_reg_state(netdev),
		&ifa->ifa_address, ifa->ifa_prefixlen);

	memset(&netaddr, 0, sizeof(struct ubcore_net_addr));
	ubcore_ipv4_to_netaddr(&netaddr, ifa->ifa_address);
	(void)ubcore_fill_netaddr_macvlan(&netaddr, netdev, UBCORE_NET_ADDR_TYPE_IPV4);
	netaddr.prefix_len = ifa->ifa_prefixlen;
	return ubcore_handle_inetaddr_event(netdev, event, &netaddr);
}

static void ubcore_add_ipv4_entry(struct list_head *list, __be32 ipv4, uint32_t prefix_len,
	struct net_device *netdev)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);
	if (na_entry == NULL)
		return;

	ubcore_ipv4_to_netaddr(&na_entry->addr, ipv4);
	(void)ubcore_fill_netaddr_macvlan(&na_entry->addr, netdev, UBCORE_NET_ADDR_TYPE_IPV4);
	na_entry->addr.prefix_len = prefix_len;
	list_add_tail(&na_entry->node, list);
}

static void ubcore_add_ipv6_entry(struct list_head *list, struct in6_addr *ipv6,
	uint32_t prefix_len, struct net_device *netdev)
{
	struct ubcore_net_addr_node *na_entry;

	na_entry = kzalloc(sizeof(struct ubcore_net_addr_node), GFP_ATOMIC);
	if (na_entry == NULL)
		return;

	(void)memcpy(&na_entry->addr.net_addr, ipv6, sizeof(struct in6_addr));
	(void)ubcore_fill_netaddr_macvlan(&na_entry->addr, netdev, UBCORE_NET_ADDR_TYPE_IPV6);
	na_entry->addr.prefix_len = prefix_len;
	list_add_tail(&na_entry->node, list);
}

static void ubcore_netdev_get_ipv4(struct net_device *netdev, struct list_head *list)
{
	struct in_ifaddr *ifa;
	struct in_device *in_dev;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(netdev);
	if (in_dev == NULL) {
		rcu_read_unlock();
		return;
	}

	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		ubcore_add_ipv4_entry(list, ifa->ifa_address, ifa->ifa_prefixlen, netdev);
	}
	rcu_read_unlock();
}

static void ubcore_netdev_get_ipv6(struct net_device *netdev, struct list_head *list)
{
	struct inet6_ifaddr *ifa;
	struct inet6_dev *in_dev;

	in_dev = in6_dev_get(netdev);
	if (in_dev == NULL)
		return;

	read_lock_bh(&in_dev->lock);
	list_for_each_entry(ifa, &in_dev->addr_list, if_list) {
		ubcore_add_ipv6_entry(list, (struct in6_addr *)&ifa->addr, ifa->prefix_len, netdev);
	}
	read_unlock_bh(&in_dev->lock);
	in6_dev_put(in_dev);
}

int ubcore_update_net_addr(struct ubcore_device *dev, struct net_device *netdev,
	struct ubcore_net_addr *netaddr, enum ubcore_net_addr_op op, bool async)
{
	struct ubcore_update_net_addr_req req = {0};
	uint32_t eid_idx = 0;
	int ret = 0;

	req.op = op;
	if (ubcore_is_ub_device(dev) && dev->dynamic_eid) {
		ubcore_sip_init(&req.sip_info, dev, netaddr, netdev);
		req.sip_present = true;
	}

	// Add eid table entry
	if ((op == UBCORE_ADD_NET_ADDR || op == UBCORE_DEL_NET_ADDR)) {
		ret = ubcore_update_eid_tbl(dev, netaddr, op == UBCORE_ADD_NET_ADDR,
			dev_net(netdev), &eid_idx);
		if (ret == 0 && dev->dynamic_eid) {
			req.eid_present = true;
			req.eid_info.eid_idx = eid_idx;
			req.eid_info.pattern = dev->attr.pattern;

			memcpy(req.eid_info.eid.raw, netaddr->net_addr.raw, UBCORE_NET_ADDR_BYTES);
			memcpy(req.eid_info.dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);
		}
	}

	// If dev is not TPF, send msg to TPF
	if (dev->attr.tp_maintainer)
		ret = ubcore_handle_update_net_addr(dev, dev->attr.fe_idx, &req, async);
	else
		/* handle by: ubcore_recv_net_addr_update */
		ret = ubcore_send_net_addr_update_req(dev, &req);

	// Delete eid entry if failed
	if (ret != 0 && op == UBCORE_ADD_NET_ADDR && req.eid_present)
		(void)ubcore_update_eid_tbl(dev, netaddr, false, dev_net(netdev), &eid_idx);

	return ret;
}

void ubcore_update_netdev_addr(struct ubcore_device *dev, struct net_device *netdev,
	enum ubcore_net_addr_op op, bool async)
{
	struct ubcore_net_addr_node *na_entry;
	struct ubcore_net_addr_node *next;
	LIST_HEAD(na_list);

	if (netdev == NULL)
		return;

	/* In virtualization situation sip and eid are not from net_dev */
	if (dev->attr.virtualization)
		return;

	ubcore_netdev_get_ipv4(netdev, &na_list);
	ubcore_netdev_get_ipv6(netdev, &na_list);
	list_for_each_entry_safe(na_entry, next, &na_list, node) {
		if (na_entry->addr.net_addr.in6.subnet_prefix == cpu_to_be64(UBCORE_LOCAL_SHUNET))
			continue;
		ubcore_update_net_addr(dev, netdev, &na_entry->addr, op, async);
		list_del(&na_entry->node);
		kfree(na_entry);
	}
}

static void ubcore_change_mtu(struct ubcore_device *dev, struct net_device *netdev)
{
	ubcore_update_netdev_addr(dev, netdev, UBCORE_UPDATE_NET_ADDR, true);
}

static void ubcore_do_bond(struct ubcore_bond_event_work *l_bond_event)
{
	int ret = -1;

	switch (l_bond_event->bond_op_type) {
	case UBCORE_BOND_ADD:
		ret = l_bond_event->bond_add(l_bond_event->bond,
			l_bond_event->slave, &l_bond_event->info_upper);
		if (ret != 0)
			ubcore_log_err("Failed to bond_add and ret value is %d", ret);
		break;
	case UBCORE_BOND_REMOVE:
		ret = l_bond_event->bond_remove(l_bond_event->bond, l_bond_event->slave);
		if (ret != 0)
			ubcore_log_err("Failed to bond_remove and ret value is %d", ret);
		break;
	case UBCORE_BOND_SLAVE_UPDATE:
		ret = l_bond_event->slave_update(
			l_bond_event->bond, l_bond_event->slave, &l_bond_event->info_lower);
		if (ret != 0)
			ubcore_log_err("Failed to slave_update and ret value is %d", ret);
		break;
	default:
		break;
	}
	if (l_bond_event->bond)
		dev_put(l_bond_event->bond);
	dev_put(l_bond_event->slave);
	if (ret == 0)
		ubcore_log_info("Success running bond_event with type %d",
			(int)l_bond_event->bond_op_type);
	kfree(l_bond_event);
}

static void ubcore_do_bond_work(struct work_struct *work)
{
	struct ubcore_bond_event_work *l_bond_event =
		container_of(work, struct ubcore_bond_event_work, work);

	ubcore_do_bond(l_bond_event);
}

static void ubcore_queue_bond_work(struct ubcore_bond_event_work *l_bond_event)
{
	if (ubcore_queue_work((int)UBCORE_BOND_EVENT_WQ, &l_bond_event->work) != 0) {
		dev_put(l_bond_event->slave);
		if (l_bond_event->bond)
			dev_put(l_bond_event->bond);
		ubcore_log_err("Queue work type %d, op type %d failed",
			(int)UBCORE_BOND_EVENT_WQ,
			(int)l_bond_event->bond_op_type);
		kfree(l_bond_event);
	}
}

static int ubcore_netdev_event_change_upper(struct ubcore_device *dev,
	struct net_device *slave,
	struct netdev_notifier_changeupper_info *info)
{
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	struct ubcore_bond_event_work *l_bond_event;
	struct net_device *bond = info->upper_dev;

	if (dev == NULL || dev->ops == NULL || dev->ops->bond_add == NULL ||
		dev->ops->bond_remove == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		ubcore_put_device(dev);
		return -EINVAL;
	}

	ubcore_log_info("Event with master netdev %s and slave netdev %s",
		netdev_name(bond), netdev_name(slave));

	l_bond_event = kzalloc(sizeof(*l_bond_event), GFP_KERNEL);
	if (!l_bond_event) {
		ubcore_put_device(dev);
		return -ENOMEM;
	}

	dev_hold(bond);
	l_bond_event->bond = bond;
	dev_hold(slave);
	l_bond_event->slave = slave;
	if (info->linking) {
		lag_upper_info = info->upper_info;
		l_bond_event->info_upper = *lag_upper_info;
		l_bond_event->bond_add = dev->ops->bond_add;
		l_bond_event->bond_op_type = UBCORE_BOND_ADD;
	} else {
		l_bond_event->bond_op_type = UBCORE_BOND_REMOVE;
		l_bond_event->bond_remove = dev->ops->bond_remove;
	}

	/* dev may be unregistered so it has to be put_device here */
	ubcore_put_device(dev);

	INIT_WORK(&l_bond_event->work, ubcore_do_bond_work);
	ubcore_queue_bond_work(l_bond_event);
	ubcore_log_info("Success to deal with event NETDEV_CHANGEUPPER");
	return 0;
}

static int ubcore_netdev_event_change_lower_state(struct ubcore_device *dev,
	struct net_device *slave,
	struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info = NULL;
	struct net_device *bond = NULL;
	struct ubcore_bond_event_work *l_bond_event;

	if (dev == NULL || dev->ops == NULL || dev->ops->slave_update == NULL) {
		ubcore_log_err("Invalid parameter!\n");
		return -EINVAL;
	}
	l_bond_event = kzalloc(sizeof(*l_bond_event), GFP_KERNEL);
	if (!l_bond_event)
		return false;
	bond = netdev_master_upper_dev_get_rcu(slave);
	if (bond) {
		dev_hold(bond);
		l_bond_event->bond = bond;
		ubcore_log_info("Event with master netdev %s and slave netdev %s",
			netdev_name(bond), netdev_name(slave));
	} else {
		l_bond_event->bond = NULL;
		ubcore_log_info("Event with master netdev NULL and slave netdev %s",
			netdev_name(slave));
	}
	lag_lower_info = info->lower_state_info;
	l_bond_event->info_lower = *lag_lower_info;
	dev_hold(slave);
	l_bond_event->slave = slave;
	l_bond_event->slave_update = dev->ops->slave_update;
	l_bond_event->bond_op_type = UBCORE_BOND_SLAVE_UPDATE;
	INIT_WORK(&l_bond_event->work, ubcore_do_bond_work);
	ubcore_queue_bond_work(l_bond_event);
	ubcore_log_info("Success to deal with event NETDEV_CHANGELOWERSTATE");
	return 0;
}

static struct net_device *ubcore_find_master_netdev(unsigned long event,
	struct netdev_notifier_changeupper_info *info,
	struct net_device *slave)
{
	/* When we need to remove slaves from the bond device,
	 * we cannot find the ubcore dev by the netdev provided by unlink NETDEV_CHANGEUPPER.
	 * It has been unregistered. We need to find ubcore dev by the master netdev
	 */
	struct net_device *bond = NULL;

	if (event == NETDEV_CHANGEUPPER && !info->linking)
		bond = info->upper_dev;
	else if (event == NETDEV_CHANGELOWERSTATE)
		bond = netdev_master_upper_dev_get_rcu(slave);

	return bond;
}

static void ubcore_do_netdev_notify(unsigned long event, struct ubcore_device *dev,
	struct net_device *netdev, void *arg)
{
	switch (event) {
	case NETDEV_REGISTER:
	case NETDEV_UP:
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_DOWN:
		break;
	case NETDEV_CHANGEADDR:
		break;
	case NETDEV_CHANGEMTU:
		if (dev->transport_type == UBCORE_TRANSPORT_UB)
			ubcore_change_mtu(dev, netdev);
		break;
	case NETDEV_CHANGEUPPER:
		/* NETDEV_CHANGEUPPER event need to put_device ahead due to unregister dev */
		if (dev->transport_type == UBCORE_TRANSPORT_UB)
			(void)ubcore_netdev_event_change_upper(dev, netdev, arg);
		else
			ubcore_put_device(dev);

		break;
	case NETDEV_CHANGELOWERSTATE:
		if (dev->transport_type == UBCORE_TRANSPORT_UB)
			(void)ubcore_netdev_event_change_lower_state(dev, netdev, arg);
		break;
	default:
		break;
	}
}

static int ubcore_net_notifier_call(struct notifier_block *nb, unsigned long event, void *arg)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);
	struct ubcore_device **devices;
	struct net_device *master_netdev;
	uint32_t num_devices = 0;
	uint32_t i;

	if (netdev == NULL)
		return NOTIFY_DONE;

	ubcore_log_info("Get a net event %s from ubcore_dev %s%s", netdev_cmd_to_name(event),
			netdev_name(netdev), netdev_reg_state(netdev));

	devices = ubcore_get_devices_from_netdev(netdev, &num_devices);
	if (devices == NULL) {
		if (event != NETDEV_CHANGEUPPER && event != NETDEV_CHANGELOWERSTATE)
			return NOTIFY_DONE;

		master_netdev = ubcore_find_master_netdev(event, arg, netdev);
		if (master_netdev == NULL) {
			ubcore_log_warn("Can not find master netdev by slave netdev %s",
				netdev_name(netdev));
			return NOTIFY_DONE;
		}
		ubcore_log_info("Success to find master netdev %s",
			netdev_name(master_netdev));
		devices = ubcore_get_devices_from_netdev(master_netdev, &num_devices);
		if (devices == NULL) {
			ubcore_log_warn("Can not find devices from master netdev %s",
				netdev_name(master_netdev));
			return NOTIFY_DONE;
		}
	}

	for (i = 0; i < num_devices; i++)
		ubcore_do_netdev_notify(event, devices[i], netdev, arg);

	if (event != NETDEV_CHANGEUPPER)
		ubcore_put_devices(devices, num_devices);
	else
		kfree(devices);

	return NOTIFY_OK;
}

static struct notifier_block ubcore_ipv6_notifier = {
	.notifier_call = ubcore_ipv6_notifier_call,
};

static struct notifier_block ubcore_ipv4_notifier = {
	.notifier_call = ubcore_ipv4_notifier_call,
};

static struct notifier_block ubcore_net_notifier = {
	.notifier_call = ubcore_net_notifier_call,
};

static int ubcore_register_notifiers(void)
{
	int ret;

	ret = register_netdevice_notifier(&ubcore_net_notifier);
	if (ret != 0) {
		pr_err("Failed to register netdev notifier, ret = %d\n", ret);
		return ret;
	}
	ret = register_inetaddr_notifier(&ubcore_ipv4_notifier);
	if (ret != 0) {
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		pr_err("Failed to register inetaddr notifier, ret = %d\n", ret);
		return -1;
	}
	ret = register_inet6addr_notifier(&ubcore_ipv6_notifier);
	if (ret != 0) {
		(void)unregister_inetaddr_notifier(&ubcore_ipv4_notifier);
		(void)unregister_netdevice_notifier(&ubcore_net_notifier);
		pr_err("Failed to register inet6addr notifier, ret = %d\n", ret);
		return -1;
	}
	return 0;
}

static void ubcore_unregister_notifiers(void)
{
	(void)unregister_inet6addr_notifier(&ubcore_ipv6_notifier);
	(void)unregister_inetaddr_notifier(&ubcore_ipv4_notifier);
	(void)unregister_netdevice_notifier(&ubcore_net_notifier);
}

static int __init ubcore_init(void)
{
	int ret;

	ret = ubcore_class_register();
	if (ret != 0)
		return ret;

	ret = ubcore_genl_init();
	if (ret != 0) {
		(void)pr_err("Failed to ubcore genl init\n");
		ubcore_class_unregister();
		return -1;
	}

	ret = ubcore_register_notifiers();
	if (ret != 0) {
		pr_err("Failed to register notifiers\n");
		ubcore_genl_exit();
		ubcore_class_unregister();
		return -1;
	}

	ret = ubcore_register_pnet_ops();
	if (ret != 0) {
		ubcore_unregister_notifiers();
		ubcore_genl_exit();
		ubcore_class_unregister();
	}

	ret = ubcore_create_workqueues();
	if (ret != 0) {
		pr_err("Failed to create all the workqueues, ret = %d\n", ret);
		ubcore_unregister_pnet_ops();
		ubcore_unregister_notifiers();
		ubcore_genl_exit();
		ubcore_class_unregister();
		return ret;
	}
	ubcore_log_info("ubcore module init success.\n");
	return 0;
}

static void __exit ubcore_exit(void)
{
	ubcore_destroy_workqueues();
	ubcore_unregister_pnet_ops();
	ubcore_unregister_notifiers();
	ubcore_genl_exit();
	ubcore_unregister_sysfs();
	ubcore_class_unregister();
	ubcore_log_info("ubcore module exits.\n");
}

module_init(ubcore_init);
module_exit(ubcore_exit);

MODULE_DESCRIPTION("Kernel module for ubus");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL v2");
