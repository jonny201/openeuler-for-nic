// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
 * Description: Ubcore workqueue
 * Author:Zhangjiayu
 * Create: 2024-1-27
 * Note:
 * History: 2024-1-27: Create file
 */

#include "ubcore_log.h"
#include "ubcore_workqueue.h"

static struct workqueue_struct *g_ubcore_workqueues[(int)UBCORE_QUEUE_TYPE_NUM];
const char UBCORE_QUEUE_NAMES[(int)UBCORE_QUEUE_TYPE_NUM][UBCORE_QUEUE_NAME_LEN] = {
	{"ubcore-device-wq"}, {"ubcore-sip-wq"}, {"ubcore-bond-wq"}, {"ubcore-fb-wq"}};

static bool check_queue_type_valid(int queue_type)
{
	return (queue_type >= (int)UBCORE_DISPATCH_EVENT_WQ) &&
		(queue_type < (int)UBCORE_QUEUE_TYPE_NUM);
}

void ubcore_flush_workqueue(int queue_type)
{
	if (!check_queue_type_valid(queue_type) || g_ubcore_workqueues[queue_type] == NULL) {
		ubcore_log_err("queue_type %d out of range or workqueue is NULL\n", queue_type);
		return;
	}

	flush_workqueue(g_ubcore_workqueues[queue_type]);
}

int ubcore_queue_work(int queue_type, struct work_struct *work)
{
	if (!check_queue_type_valid(queue_type) || g_ubcore_workqueues[queue_type] == NULL) {
		ubcore_log_err("queue_type %d out of range or workqueue is NULL\n", queue_type);
		return -EINVAL;
	}
	return queue_work(g_ubcore_workqueues[queue_type], work) ? 0 : -1;
}

int ubcore_create_workqueues(void)
{
	uint32_t i, j;

	for (i = 0; i < UBCORE_QUEUE_TYPE_NUM; i++) {
		g_ubcore_workqueues[i] = alloc_workqueue("%s", 0, 0, UBCORE_QUEUE_NAMES[i]);
		if (g_ubcore_workqueues[i] == NULL) {
			ubcore_log_err("Fail to alloc workqueue, queue type %u.\n", i);
			break;
		}
	}

	if (i == UBCORE_QUEUE_TYPE_NUM)
		return 0;

	for (j = 0; j < i; j++)
		destroy_workqueue(g_ubcore_workqueues[j]);

	return -1;
}

void ubcore_destroy_workqueues(void)
{
	uint32_t i;

	for (i = 0; i < UBCORE_QUEUE_TYPE_NUM; i++) {
		flush_workqueue(g_ubcore_workqueues[i]);
		destroy_workqueue(g_ubcore_workqueues[i]);
	}
}
