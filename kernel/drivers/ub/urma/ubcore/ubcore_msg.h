/* SPDX-License-Identifier: GPL-2.0 */
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
 * Description: ubcore msg table header
 * Author: Yang Yijian
 * Create: 2023-07-05
 * Note:
 * History: 2023-07-05: Create file
 */

#ifndef UBCORE_MSG_H
#define UBCORE_MSG_H

#include <urma/ubcore_types.h>

// Must be the same as TPSA_NL_RESP_XXX
#define UBCORE_MSG_RESP_LIMIT_RATE (-EBUSY)
#define UBCORE_MSG_RESP_RC_JETTY_ALREADY_BIND (-EEXIST)
#define UBCORE_MSG_RESP_IN_PROGRESS (-EINPROGRESS)
#define UBCORE_MSG_RESP_FAIL (-EPERM)
#define UBCORE_MSG_RESP_SUCCESS 0

typedef int (*ubcore_req_handler)(struct ubcore_device *dev, struct ubcore_req_host *req);
typedef int (*ubcore_resp_handler)(struct ubcore_device *dev,
	struct ubcore_resp *msg, void *msg_ctx);

struct ubcore_resp_cb {
	void *user_arg;
	ubcore_resp_handler callback;
};

struct ubcore_msg_session {
	struct ubcore_req *req;
	struct ubcore_resp *resp;
	struct list_head node;
	struct kref kref;
	struct completion comp; /* Synchronization event of timeout sleep and thread wakeup */
	struct ubcore_resp_cb cb;
};

struct ubcore_msg_config_device_req {
	char dev_name[UBCORE_MAX_DEV_NAME];
	uint32_t max_rc_cnt;
	uint32_t max_rc_depth;
	uint32_t min_slice;                 /* TA slice size byte */
	uint32_t max_slice;                 /* TA slice size byte */
	bool is_tpf_dev;
	bool virtualization;
	char tpfdev_name[UBCORE_MAX_DEV_NAME];
};

struct ubcore_msg_config_device_resp {
	int ret;
	uint32_t rc_cnt;
	uint32_t rc_depth;
	uint32_t slice;                 /* TA slice size byte */
	uint32_t set_slice;
	bool is_tpf_dev;
	uint32_t suspend_period;
	uint32_t suspend_cnt;
};

struct ubcore_msg_discover_eid_req {
	uint32_t eid_index;
	char dev_name[UBCORE_MAX_DEV_NAME];
	enum ubcore_pattern eid_type;
	bool virtualization;
	char tpfdev_name[UBCORE_MAX_DEV_NAME];
};

struct ubcore_msg_discover_eid_resp {
	uint32_t ret;
	union ubcore_eid eid;
	uint32_t eid_index;
	uint32_t upi;
	uint16_t fe_idx;
};

struct ubcore_msg_nego_ver_req {
	uint32_t cap;
	uint32_t version_num;
	uint32_t versions[0];
};

struct ubcore_msg_nego_ver_resp {
	int ret;
	uint32_t cap;
	uint32_t version;
};

struct ubcore_function_mig_req {
	uint16_t mig_fe_idx;
};

struct ubcore_function_mig_resp {
	uint16_t mig_fe_idx;
	enum ubcore_mig_resp_status status;
};

struct ubcore_eid_update_info {
	uint32_t pattern;
	uint32_t eid_idx;
	union ubcore_eid eid;
	char dev_name[UBCORE_MAX_DEV_NAME];
	bool upi_present;
	uint32_t upi;
};

struct ubcore_update_net_addr_req {
	enum ubcore_net_addr_op op;
	bool sip_present;
	struct ubcore_sip_info sip_info;
	bool eid_present;
	struct ubcore_eid_update_info eid_info;
};

struct ubcore_update_eid_req {
	enum ubcore_net_addr_op op;
	struct ubcore_eid_update_info eid_info;
};

struct ubcore_update_eid_ctx {
	struct ubcore_device *dev;
	struct ubcore_req *req_msg;
	struct ubcore_msg_session *s;
	struct net *net;
	struct ubcore_resp_cb cb;
	long start_ts;
};

int ubcore_send_req(struct ubcore_device *dev, struct ubcore_req *req);
int ubcore_send_resp(struct ubcore_device *dev, struct ubcore_resp_host *resp_host);
/* caller should free memory of req after return */
int ubcore_send_fe2tpf_msg(struct ubcore_device *dev, struct ubcore_req *req,
	struct ubcore_resp_cb *cb);
int ubcore_msg_discover_eid(struct ubcore_device *dev, uint32_t eid_index,
	enum ubcore_msg_opcode op, struct net *net, struct ubcore_update_eid_ctx *ctx);
void ubcore_destroy_msg_session(struct ubcore_msg_session *s);
int ubcore_update_uvs_eid_ret(struct ubcore_update_eid_ctx *ctx);
#endif
