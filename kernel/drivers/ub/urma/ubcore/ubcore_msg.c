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
 * Description: ubcore message table implementation
 * Author: Yang Yijian
 * Create: 2023-07-05
 * Note:
 * History: 2023-07-05: Create file
 */

#include <linux/slab.h>
#include <urma/ubcore_types.h>
#include <linux/timekeeping.h>
#include "ubcore_log.h"
#include "urma/ubcore_api.h"
#include "ubcore_netlink.h"
#include "ubcore_vtp.h"
#include "urma/ubcore_uapi.h"
#include "ubcore_priv.h"
#include "ubcore_workqueue.h"
#include "ubcore_main.h"
#include "ubcore_msg.h"

#define MS_PER_SEC                  1000
static LIST_HEAD(g_msg_session_list);
static DEFINE_SPINLOCK(g_msg_session_lock);
static atomic_t g_msg_seq = ATOMIC_INIT(0);

static uint32_t ubcore_get_msg_seq(void)
{
	return (uint32_t)atomic_inc_return(&g_msg_seq);
}

static void ubcore_free_msg_session(struct kref *kref)
{
	struct ubcore_msg_session *s = container_of(kref, struct ubcore_msg_session, kref);
	unsigned long flags;

	spin_lock_irqsave(&g_msg_session_lock, flags);
	list_del(&s->node);
	spin_unlock_irqrestore(&g_msg_session_lock, flags);
	kfree(s);
}

static struct ubcore_msg_session *ubcore_find_msg_session(uint32_t seq)
{
	struct ubcore_msg_session *tmp, *target = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_msg_session_lock, flags);
	list_for_each_entry(tmp, &g_msg_session_list, node) {
		if (tmp->req->msg_id == seq) {
			target = tmp;
			kref_get(&target->kref);
			break;
		}
	}
	spin_unlock_irqrestore(&g_msg_session_lock, flags);
	return target;
}

void ubcore_destroy_msg_session(struct ubcore_msg_session *s)
{
	(void)kref_put(&s->kref, ubcore_free_msg_session);
}

static struct ubcore_msg_session *ubcore_create_msg_session(struct ubcore_req *req)
{
	struct ubcore_msg_session *s;
	unsigned long flags;

	s = kzalloc(sizeof(struct ubcore_msg_session), GFP_KERNEL);
	if (s == NULL)
		return NULL;

	s->req = req;
	spin_lock_irqsave(&g_msg_session_lock, flags);
	list_add_tail(&s->node, &g_msg_session_list);
	spin_unlock_irqrestore(&g_msg_session_lock, flags);
	kref_init(&s->kref);
	init_completion(&s->comp);
	return s;
}

static struct ubcore_nlmsg *ubcore_get_fe2uvs_nlmsg(struct ubcore_device *dev,
	struct ubcore_req_host *req_host)
{
	uint32_t payload_len = (uint32_t)sizeof(*req_host) + req_host->req.len;
	struct ubcore_nlmsg *nlmsg;

	nlmsg = ubcore_alloc_nlmsg(payload_len, NULL, NULL);
	if (nlmsg == NULL)
		return NULL;

	nlmsg->transport_type = dev->transport_type;
	nlmsg->msg_type = UBCORE_CMD_FE2TPF_REQ;
	(void)memcpy(nlmsg->payload, req_host, payload_len);
	return nlmsg;
}

/* called when recv nl response from uvs */
static int ubcore_forward_uvs2fe_msg(struct ubcore_nlmsg *msg, void *user_arg)
{
	struct ubcore_device *dev = (struct ubcore_device *)user_arg;
	int ret;

	ret = ubcore_send_resp(dev, (struct ubcore_resp_host *)msg->payload);
	return ret;
}

static int ubcore_forward_fe2uvs_msg(struct ubcore_device *dev, struct ubcore_req_host *req_host)
{
	struct ubcore_nl_resp_cb cb;
	struct ubcore_nlmsg *nlmsg;
	int ret;

	nlmsg = ubcore_get_fe2uvs_nlmsg(dev, req_host);
	if (nlmsg == NULL)
		return -ENOMEM;

	cb.callback = ubcore_forward_uvs2fe_msg;
	cb.user_arg = NULL; /* If bind or advise tp timeout expires, dev may drive unregister */
	ret = ubcore_nl_send_nowait(dev, nlmsg, &cb);
	if (ret) {
		kfree(nlmsg);
		return -EIO;
	}

	return 0;
}

/* msg is a copy of received msg from driver */
static int ubcore_fe2tpf_msg(struct ubcore_device *dev, struct ubcore_req_host *req_host)
{
	int ret;

	ret = ubcore_forward_fe2uvs_msg(dev, req_host);
	kfree(req_host);
	return ret;
}

/* msg is a copy of received msg from driver */
static int ubcore_tpf2fe_msg(struct ubcore_device *dev, struct ubcore_resp *resp)
{
	struct ubcore_msg_session *s;

	s = ubcore_find_msg_session(resp->msg_id);
	if (s == NULL) {
		ubcore_log_err("Failed to find resp session with seq %u", resp->msg_id);
		kfree(resp);
		return -ENXIO;
	}
	s->resp = resp;
	kref_put(&s->kref, ubcore_free_msg_session);
	complete(&s->comp);

	return 0;
}

static void ubcore_fill_tpf_dev_name(struct ubcore_device *tpf_dev,
	struct ubcore_req_host *req_host)
{
	char *p = NULL;

	/* dev should report as tpf */
	if (!tpf_dev->attr.tp_maintainer) {
		ubcore_log_err("dev:%s, Not tpf!", tpf_dev->dev_name);
		return;
	}

	switch (req_host->req.opcode) {
	case UBCORE_MSG_CREATE_VTP:
	case UBCORE_MSG_DESTROY_VTP:
		if (req_host->req.len >= sizeof(struct ubcore_create_vtp_req))
			p = ((struct ubcore_create_vtp_req *)req_host->req.data)->tpfdev_name;
		break;
	case UBCORE_MSG_ALLOC_EID:
	case UBCORE_MSG_DEALLOC_EID:
		if (req_host->req.len >= sizeof(struct ubcore_msg_discover_eid_req))
			p = ((struct ubcore_msg_discover_eid_req *)
				req_host->req.data)->tpfdev_name;
		break;
	case UBCORE_MSG_CONFIG_DEVICE:
		if (req_host->req.len >= sizeof(struct ubcore_msg_config_device_req))
			p = ((struct ubcore_msg_config_device_req *)
				req_host->req.data)->tpfdev_name;
		break;
	case UBCORE_MSG_STOP_PROC_VTP_MSG:
	case UBCORE_MSG_QUERY_VTP_MIG_STATUS:
	case UBCORE_MSG_FLOW_STOPPED:
	case UBCORE_MSG_MIG_ROLLBACK:
	case UBCORE_MSG_MIG_VM_START:
	case UBCORE_MSG_NEGO_VER:
		ubcore_log_err("Wrong type when try to fill tpf dev name\n");
		break;
	default:
		ubcore_log_err("Unrecognized type of opcode %d\n", (int)req_host->req.opcode);
	}

	if (p != NULL)
		memcpy(p, tpf_dev->dev_name, UBCORE_MAX_DEV_NAME);
}

static struct ubcore_req_host *ubcore_copy_req_host(struct ubcore_req_host *req_host)
{
	uint32_t len = (uint32_t)sizeof(struct ubcore_req_host) + req_host->req.len;
	struct ubcore_req_host *resp;

	resp = kzalloc(len, GFP_ATOMIC);
	if (resp == NULL)
		return NULL;

	(void)memcpy(resp, req_host, len);
	return resp;
}

static struct ubcore_resp *ubcore_copy_resp(struct ubcore_resp *resp)
{
	uint32_t len = (uint32_t)sizeof(struct ubcore_resp) + resp->len;
	struct ubcore_resp *resp_copy;

	resp_copy = kzalloc(len, GFP_KERNEL);
	if (resp_copy == NULL)
		return NULL;

	(void)memcpy(resp_copy, resp, len);
	return resp_copy;
}

static struct ubcore_req_host *ubcore_migrate_req(struct ubcore_device *dev,
	struct ubcore_req_host *req_host)
{
	uint32_t len;
	struct ubcore_nl_function_mig_req *mig_resp;
	struct ubcore_function_mig_req *mig_msg;
	struct ubcore_req_host *req_copy;

	len = (uint32_t)sizeof(struct ubcore_req_host) +
		(uint32_t)sizeof(struct ubcore_nl_function_mig_req);
	mig_msg = (struct ubcore_function_mig_req *)req_host->req.data;
	req_copy = kzalloc(len, GFP_KERNEL);
	if (req_copy == NULL) {
		ubcore_log_err("Failed to kzalloc req_host req_copy!\n");
		return NULL;
	}

	req_copy->src_fe_idx = req_host->src_fe_idx;
	req_copy->req.opcode = req_host->req.opcode;
	req_copy->req.msg_id = req_host->req.msg_id;
	req_copy->req.len = sizeof(struct ubcore_nl_function_mig_req);

	mig_resp = (struct ubcore_nl_function_mig_req *)req_copy->req.data;
	mig_resp->mig_fe_idx = mig_msg->mig_fe_idx;
	(void)strncpy(mig_resp->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME - 1);

	return req_copy;
}

static void ubcore_handle_nego_ver(struct ubcore_device *dev, struct ubcore_req_host *req)
{
	struct ubcore_msg_nego_ver_resp *data;
	struct ubcore_resp_host *rsp;
	int rc;

	rsp = kzalloc(sizeof(struct ubcore_resp_host) + sizeof(struct ubcore_msg_nego_ver_resp),
		GFP_KERNEL);
	if (rsp == NULL)
		return;

	rsp->dst_fe_idx = req->src_fe_idx;
	rsp->resp.msg_id = req->req.msg_id;
	rsp->resp.opcode = UBCORE_MSG_NEGO_VER;
	rsp->resp.len = sizeof(struct ubcore_msg_nego_ver_resp);

	data = (struct ubcore_msg_nego_ver_resp *)rsp->resp.data;
	rc = ubcore_negotiate_version((struct ubcore_msg_nego_ver_req *)req->req.data,
		&data->version, &data->cap);
	data->ret = rc == 0 ? UBCORE_MSG_RESP_SUCCESS : UBCORE_MSG_RESP_FAIL;

	(void)ubcore_send_resp(dev, rsp);

	/* Backend response is freed after "ubcore_send_resp" returns. */
	kfree(rsp);
}

static void ubcore_handle_frontend_message(struct work_struct *work)
{
	struct ubcore_front_back_work *fb_work =
		container_of(work, struct ubcore_front_back_work, work);

	switch (fb_work->req->req.opcode) {
	case UBCORE_MSG_NEGO_VER:
		ubcore_handle_nego_ver(fb_work->dev, fb_work->req);
		break;
	case UBCORE_MSG_UPDATE_NET_ADDR:
		ubcore_recv_net_addr_update(fb_work->dev, fb_work->req);
		break;
	case UBCORE_MSP_UPDATE_EID:
		ubcore_recv_eid_update_req(fb_work->dev, fb_work->req);
		break;
	default:
		ubcore_log_err("Unsupported opcode: %d\n", (int)fb_work->req->req.opcode);
	}

	/* Backend request is freed after it is handled. */
	kfree(fb_work->req);
	kfree(fb_work);
}

static int ubcore_queue_frontend_message(struct ubcore_device *dev, struct ubcore_req_host *req)
{
	struct ubcore_front_back_work *work;
	struct ubcore_req_host *inner_req;

	inner_req = ubcore_copy_req_host(req);
	if (inner_req == NULL) {
		ubcore_log_err("Fail to copy frontend ubcore message.\n");
		return -ENOMEM;
	}

	work = kzalloc(sizeof(struct ubcore_front_back_work), GFP_ATOMIC);
	if (work == NULL) {
		kfree(inner_req);
		return -ENOMEM;
	}

	work->dev = dev;
	work->req = inner_req;
	INIT_WORK(&work->work, ubcore_handle_frontend_message);
	if (ubcore_queue_work((int)UBCORE_FRONT_BACK_WQ, &work->work) != 0) {
		ubcore_log_err("Fail to queue work for frontend ubcore message.\n");
		kfree(inner_req);
		kfree(work);
		return -1;
	}

	return 0;
}

int ubcore_recv_req(struct ubcore_device *dev, struct ubcore_req_host *req)
{
	struct ubcore_req_host *handle_req;
	int ret;

	if (dev == NULL || req == NULL || req->req.len > UBCORE_MAX_MSG) {
		ubcore_log_err("Invalid parameter.\n!");
		return -EINVAL;
	}

	if (strnlen(dev->dev_name, UBCORE_MAX_DEV_NAME) == UBCORE_MAX_DEV_NAME) {
		ubcore_log_err("Invalid dev_name.\n!");
		return -EINVAL;
	}

	if (req->req.opcode >= UBCORE_MSG_NEGO_VER) {
		return ubcore_queue_frontend_message(dev, req);
	} else if (req->req.opcode >= UBCORE_MSG_STOP_PROC_VTP_MSG) {
		handle_req = ubcore_migrate_req(dev, req);
		if (handle_req == NULL) {
			ubcore_log_err("null msg when handle migrate\n!");
			return -EINVAL;
		}
	} else {
		handle_req = ubcore_copy_req_host(req);
		if (handle_req == NULL) {
			ubcore_log_err("Failed to create handle msg req!\n");
			return -ENOMEM;
		}

		ubcore_fill_tpf_dev_name(dev, handle_req);
	}

	ret = ubcore_fe2tpf_msg(dev, handle_req);

	return ret;
}
EXPORT_SYMBOL(ubcore_recv_req);

int ubcore_recv_resp(struct ubcore_device *dev, struct ubcore_resp *resp)
{
	struct ubcore_resp *handle_resp;
	int ret;

	if (dev == NULL || resp == NULL || resp->len > UBCORE_MAX_MSG) {
		ubcore_log_err("Invalid parameter.\n!");
		return -EINVAL;
	}

	handle_resp = ubcore_copy_resp(resp);
	if (handle_resp == NULL) {
		ubcore_log_err("Failed to create handle resp req!\n");
		return -ENOMEM;
	}

	ret = ubcore_tpf2fe_msg(dev, handle_resp);

	/* do not free copy here */
	return ret;
}
EXPORT_SYMBOL(ubcore_recv_resp);

int ubcore_send_req(struct ubcore_device *dev, struct ubcore_req *req)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->send_req == NULL ||
		req->len > UBCORE_MAX_MSG) {
		ubcore_log_err("Invalid parameter!\n");
		return -EINVAL;
	}

	ret = dev->ops->send_req(dev, req);
	if (ret != 0) {
		ubcore_log_err("Failed to send message! msg_id = %u!\n", req->msg_id);
		return -EIO;
	}
	return 0;
}

int ubcore_send_resp(struct ubcore_device *dev, struct ubcore_resp_host *resp_host)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->send_resp == NULL ||
		resp_host == NULL || resp_host->resp.len > UBCORE_MAX_MSG) {
		ubcore_log_err("Invalid parameter!\n");
		return -EINVAL;
	}

	ret = dev->ops->send_resp(dev, resp_host);
	if (ret != 0) {
		ubcore_log_err("Failed to send message! msg_id = %u!\n",
			resp_host->resp.msg_id);
		return -EIO;
	}
	return 0;
}

int ubcore_send_fe2tpf_msg(struct ubcore_device *dev, struct ubcore_req *req,
	struct ubcore_resp_cb *cb)
{
	unsigned long leavetime;
	struct ubcore_msg_session *s;
	int ret;

	req->msg_id = ubcore_get_msg_seq();
	s = ubcore_create_msg_session(req);
	if (s == NULL) {
		ubcore_log_err("Failed to create req session!\n");
		return -ENOMEM;
	}

	ret = ubcore_send_req(dev, req);
	if (ret != 0) {
		ubcore_log_err("Failed to send req, msg_id = %u, opcode = %hu.\n",
			req->msg_id, (uint16_t)req->opcode);
		ubcore_destroy_msg_session(s);
		return ret;
	}

	leavetime = wait_for_completion_timeout(&s->comp, msecs_to_jiffies(UBCORE_TIMEOUT));
	if (leavetime == 0) {
		ubcore_log_err("Failed to wait req reply, msg_id = %u, opcode = %hu, leavetime =  %lu.\n",
			req->msg_id, (uint16_t)req->opcode, leavetime);
		ubcore_destroy_msg_session(s);
		return -EIO;
	}

	ubcore_log_info("Success to wait req reply, msg_id = %u, opcode = %hu, leavetime =  %lu.\n",
			req->msg_id, (uint16_t)req->opcode, leavetime);

	ret = cb->callback(dev, s->resp, cb->user_arg);
	kfree(s->resp);
	ubcore_destroy_msg_session(s);
	return ret;
}

static int ubcore_msg_discover_eid_cb(struct ubcore_device *dev,
	struct ubcore_resp *resp, void *msg_ctx)
{
	struct ubcore_msg_discover_eid_resp *data;
	struct net *net = (struct net *)msg_ctx;
	bool is_alloc_eid;

	if (dev == NULL || resp == NULL ||
		resp->len < sizeof(struct ubcore_msg_discover_eid_resp)) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	data = (struct ubcore_msg_discover_eid_resp *)(void *)resp->data;
	if (data == NULL || data->ret != 0 ||
		(resp->opcode != UBCORE_MSG_ALLOC_EID &&
			resp->opcode != UBCORE_MSG_DEALLOC_EID)) {
		ubcore_log_err("Failed to query data from the UVS. Use the default value.\n");
		return -EINVAL;
	}

	is_alloc_eid = (resp->opcode == UBCORE_MSG_ALLOC_EID);
	if (ubcore_update_eidtbl_by_idx(dev, &data->eid, data->eid_index, is_alloc_eid, net) != 0)
		return -1;

	return 0;
}

/**
 *	If you do not need to wait for the response of a message, use ubcore_asyn_send_fe2tpf_msg.
 *	If you need to wait for a response to a message, use ubcore_send_fe2tpf_msg
 */
struct ubcore_msg_session *ubcore_asyn_send_fe2tpf_msg(struct ubcore_device *dev,
	struct ubcore_req *req)
{
	struct ubcore_msg_session *s;
	int ret;

	req->msg_id = ubcore_get_msg_seq();
	s = ubcore_create_msg_session(req);
	if (s == NULL) {
		ubcore_log_err("Failed to create req session!\n");
		return NULL;
	}

	ret = ubcore_send_req(dev, req);
	if (ret != 0) {
		ubcore_log_err("Failed to send req, msg_id = %u, opcode = %hu.\n",
			req->msg_id, (uint16_t)req->opcode);
		ubcore_destroy_msg_session(s);
		return NULL;
	}
	return s;
}

int ubcore_msg_discover_eid(struct ubcore_device *dev, uint32_t eid_index,
	enum ubcore_msg_opcode op, struct net *net, struct ubcore_update_eid_ctx *ctx)
{
	struct ubcore_msg_discover_eid_req *data;
	struct ubcore_msg_session *s;
	struct ubcore_req *req_msg;
	uint32_t data_len;

	ctx->cb.callback = ubcore_msg_discover_eid_cb;
	ctx->cb.user_arg = net;
	data_len = sizeof(struct ubcore_msg_discover_eid_req);
	req_msg = kcalloc(1, sizeof(struct ubcore_req) + data_len, GFP_KERNEL);
	if (req_msg == NULL)
		return -ENOMEM;

	req_msg->len = data_len;
	req_msg->opcode = op;
	data = (struct ubcore_msg_discover_eid_req *)req_msg->data;
	data->eid_index = eid_index;
	data->eid_type = dev->attr.pattern;
	data->virtualization = dev->attr.virtualization;
	(void)memcpy(data->dev_name, dev->dev_name, UBCORE_MAX_DEV_NAME);

	s = ubcore_asyn_send_fe2tpf_msg(dev, req_msg);
	if (s == NULL) {
		ubcore_log_err("send fe2tpf failed.\n");
		kfree(req_msg);
		return -1;
	}
	ctx->req_msg = req_msg;
	ctx->s = s;
	return 0;
}

/**
 *	if the operation times out or is successful, 0 is returned and reply done  to urma_admin.
 *	if the operation is waiting for the result, 1 is returned  and reply dump to urma_admin.
 */
int ubcore_update_uvs_eid_ret(struct ubcore_update_eid_ctx *ctx)
{
	long start_ts = ctx->start_ts;
	long leave_time = 0;
	struct timespec64 tv;
	bool is_done;

	is_done = try_wait_for_completion(&ctx->s->comp);
	if (is_done == false) {
		ktime_get_ts64(&tv);
		leave_time = tv.tv_sec - start_ts;
		if (leave_time * MS_PER_SEC < UBCORE_TIMEOUT)
			return 1;

		ubcore_log_err("waiting req reply timeout, msg_id = %u, opcode = %hu, leavetime =  %ld.\n",
			ctx->req_msg->msg_id, (uint16_t)ctx->req_msg->opcode, leave_time);
		return -EAGAIN;
	}

	ubcore_log_info("waiting req reply success, msg_id = %u, opcode = %hu\n",
			ctx->req_msg->msg_id, (uint16_t)ctx->req_msg->opcode);

	if (ctx->cb.callback(ctx->dev, ctx->s->resp, ctx->cb.user_arg) != 0)
		return -EINVAL;

	return 0;
}
