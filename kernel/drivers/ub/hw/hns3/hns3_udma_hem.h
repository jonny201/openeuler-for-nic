/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 */

#ifndef _HNS3_UDMA_HEM_H
#define _HNS3_UDMA_HEM_H

#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include "hns3_udma_device.h"

#define HEM_HOP_STEP_DIRECT 0xff
#define HEM_INDEX_BUF BIT(0)
#define HEM_INDEX_L0 BIT(1)
#define HEM_INDEX_L1 BIT(2)

struct hns3_udma_hem_index {
	uint64_t buf;
	uint64_t l0;
	uint64_t l1;
	uint32_t inited; /* indicate which index is available */
};

enum {
	/* HNS3_UDMA MAP HEM(Hardware Entry Memory) */
	HEM_TYPE_QPC = 0,
	HEM_TYPE_MTPT,
	HEM_TYPE_CQC,
	HEM_TYPE_SRQC,
	/* SCC CONTEXT */
	HEM_TYPE_SCCC,
	HEM_TYPE_QPC_TIMER,
	HEM_TYPE_CQC_TIMER,
	/* GID MAC VLAN */
	HEM_TYPE_GMV,

	/* HNS3_UDMA UNMAP HEM */
	HEM_TYPE_MTT,
	HEM_TYPE_CQE,
	HEM_TYPE_SRQWQE,
	HEM_TYPE_INDEX,
};

#define HNS3_UDMA_HEM_CHUNK_LEN                              \
	((256 - sizeof(struct list_head) - 2 * sizeof(int)) / \
	 (sizeof(struct scatterlist) + sizeof(void *)))

#define check_whether_bt_num_3(type, hop_num) \
	(type < HEM_TYPE_MTT && (hop_num) == 2)

#define check_whether_bt_num_2(type, hop_num) \
	((type < HEM_TYPE_MTT && (hop_num) == 1) || \
	 (type >= HEM_TYPE_MTT && (hop_num) == 2))

#define check_whether_bt_num_1(type, hop_num)                \
	(((hop_num) == HNS3_UDMA_HOP_NUM_0) || \
	 (type >= HEM_TYPE_MTT && (hop_num) == 1))

#define check_whether_last_step(hop_num, step_idx) \
	(((step_idx) == 0 && (hop_num) == HNS3_UDMA_HOP_NUM_0) || \
	((step_idx) == 1 && (hop_num) == 1) || \
	((step_idx) == 2 && (hop_num) == 2))

struct hns3_udma_hem_chunk {
	struct list_head	list;
	int			npages;
	int			nsg;
	struct scatterlist	mem[HNS3_UDMA_HEM_CHUNK_LEN];
	void			*buf[HNS3_UDMA_HEM_CHUNK_LEN];
};

struct hns3_udma_hem {
	struct list_head	chunk_list;
	refcount_t		refcount;
};

struct hns3_udma_hem_iter {
	struct hns3_udma_hem		*hem;
	struct hns3_udma_hem_chunk	*chunk;
	int page_idx;
};

struct hns3_udma_hem_mhop {
	uint32_t hop_num;
	uint32_t buf_chunk_size;
	uint32_t bt_chunk_size;
	uint32_t ba_l0_num;
	uint32_t l0_idx; /* level 0 base address table index */
	uint32_t l1_idx; /* level 1 base address table index */
	uint32_t l2_idx; /* level 2 base address table index */
};

struct hns3_udma_hem_item {
	struct list_head	list; /* link all hems in the same bt level */
	struct list_head	sibling; /* link all hems in last hop for mtt */
	void			*addr;
	dma_addr_t		dma_addr;
	size_t			count; /* max ba numbers */
	int			start; /* start buf offset in this hem */
	int			end; /* end buf offset in this hem */
};

/* All HEM itmes are linked in a tree structure */
struct hns3_udma_hem_head {
	struct list_head branch[HNS3_UDMA_MAX_BT_REGION];
	struct list_head root;
	struct list_head leaf;
};

struct hns3_udma_buf *hns3_udma_buf_alloc(struct hns3_udma_dev *udma_dev, uint32_t size,
				uint32_t page_shift, uint32_t flags);
void hns3_udma_buf_free(struct hns3_udma_dev *udma_dev, struct hns3_udma_buf *buf);
int hns3_udma_table_get(struct hns3_udma_dev *udma_dev,
			struct hns3_udma_hem_table *table, uint64_t obj);
void hns3_udma_table_put(struct hns3_udma_dev *udma_dev,
			 struct hns3_udma_hem_table *table, uint64_t obj);
int hns3_udma_init_hem_table(struct hns3_udma_dev *udma_dev,
			     struct hns3_udma_hem_table *table, uint32_t type,
			     uint64_t obj_size, uint64_t nobj);
void hns3_udma_cleanup_hem_table(struct hns3_udma_dev *udma_dev,
				 struct hns3_udma_hem_table *table);
int hns3_udma_calc_hem_mhop(struct hns3_udma_dev *udma_dev,
			    struct hns3_udma_hem_table *table, uint64_t *obj,
			    struct hns3_udma_hem_mhop *mhop);
bool hns3_udma_check_whether_mhop(struct hns3_udma_dev *udma_dev, uint32_t type);

int hns3_udma_mtr_find(struct hns3_udma_dev *udma_device, struct hns3_udma_mtr *mtr,
		       int offset, uint64_t *mtt_buf, int mtt_max,
		       uint64_t *base_addr);

void hns3_udma_mtr_move(struct hns3_udma_mtr *from_mtr, struct hns3_udma_mtr *to_mtr);

int hns3_udma_mtr_map(struct hns3_udma_dev *dev, struct hns3_udma_mtr *mtr,
		      dma_addr_t *pages, uint32_t page_cnt);

static inline void hns3_udma_hem_first(struct hns3_udma_hem *hem,
				       struct hns3_udma_hem_iter *iter)
{
	iter->hem = hem;
	iter->chunk = list_empty(&hem->chunk_list) ? NULL :
		      list_entry(hem->chunk_list.next, struct hns3_udma_hem_chunk,
				 list);
	iter->page_idx = 0;
}

static inline int hns3_udma_hem_last(struct hns3_udma_hem_iter *iter)
{
	return !iter->chunk;
}

static inline void hns3_udma_hem_next(struct hns3_udma_hem_iter *iter)
{
	if (++iter->page_idx >= iter->chunk->nsg) {
		if (iter->chunk->list.next == &iter->hem->chunk_list) {
			iter->chunk = NULL;
			return;
		}

		iter->chunk = list_entry(iter->chunk->list.next,
					 struct hns3_udma_hem_chunk, list);
		iter->page_idx = 0;
	}
}

static inline dma_addr_t hns3_udma_hem_addr(struct hns3_udma_hem_iter *iter)
{
	return sg_dma_address(&iter->chunk->mem[iter->page_idx]);
}

#endif /* _HNS3_UDMA_HEM_H */
