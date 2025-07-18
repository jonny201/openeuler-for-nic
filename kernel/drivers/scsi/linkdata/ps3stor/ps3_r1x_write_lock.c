// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) LD. */
#ifndef _WINDOWS
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/hash.h>
#include <linux/cache.h>

#endif
#include "ps3_err_def.h"
#include "ps3_driver_log.h"
#include "ps3_rb_tree.h"
#include "ps3_inner_data.h"
#include "ps3_htp_meta.h"
#include "ps3_cmd_channel.h"
#include "ps3_scsih_cmd_parse.h"
#include "ps3_r1x_write_lock.h"
#include "ps3_instance_manager.h"
#include "ps3_platform_utils.h"
#include "ps3_driver_log.h"
#include "ps3_cmd_statistics.h"
#include "ps3_scsih.h"
#include "ps3_scsi_cmd_err.h"
#include "ps3_module_para.h"

enum {
	PS3_CONFLICT_QUEUE_EMPTY = 0,
	PS3_CONFLICT_QUEUE_CONFLICT = 1,
	PS3_CONFLICT_QUEUE_NO_CONFLICT = 2,
};

#define PS3_R1X_RESEND_COUNT (32)

#define LOCK_BLOCK_SIZE_SHIFT 3
#define HASH_TABLE_SIZE_SHIFT 12
#define HASH_TABLE_SIZE (1 << HASH_TABLE_SIZE_SHIFT)
#define HASH_TABLE_SIZE_MASK (HASH_TABLE_SIZE - 1)
#define SZBLOCK_SIZE_SHIFT 10
#define SZBLOCK_SIZE ((unsigned int)(1 << SZBLOCK_SIZE_SHIFT))
#define SZBLOCK_SIZE_MASK (SZBLOCK_SIZE - 1)
#define VD_QUE_DEPTH 512
#define CMD_SIZE_MAX 4096

#define PS3_R1X_BIT_CNT                                                        \
	((SZBLOCK_SIZE >> LOCK_BLOCK_SIZE_SHIFT) * HASH_TABLE_SIZE)
#define PS3_R1X_BIT_MAP_SIZE (PS3_R1X_BIT_CNT >> 3)

#define SECTOR_SIZE_4K 4096
#define SECTOR_512_4K_SHIFT 3
#define SZ_BLOCK_SPLIT_MAX ((4096 >> SZBLOCK_SIZE_SHIFT) + 2)

#define RW_R1X_HASHIDX(lba)                                                    \
	(((lba) >> SZBLOCK_SIZE_SHIFT) & HASH_TABLE_SIZE_MASK)
#define RW_R1X_HASHIDX_HASH(mgr, lba)                                          \
	ps3_private_r1x_hash((mgr), ((lba) >> SZBLOCK_SIZE_SHIFT))

#define PS3_LBA(lba_hi, lba_lo)                                                \
	((((unsigned long long)(lba_hi)) << PS3_SHIFT_DWORD) | (lba_lo))

#define PS3_SZ_BLOCK_CNT (2560)

enum {
	PS3_R1X_IO_CONFLICT = 1,
	PS3_R1X_HASH_CONFILICT = 2,
	PS3_R1X_BIT_NOT_ENOUGH = 3,
};

#define PS3_R1X_LOCK_TRACE(fmt, ...) LOG_DEBUG(fmt "\n", ##__VA_ARGS__)
#define PS3_R1X_LOCK_INFO(fmt, ...) LOG_INFO(fmt "\n", ##__VA_ARGS__)
#define PS3_R1X_LOCK_WARN(fmt, ...) LOG_WARN(fmt "\n", ##__VA_ARGS__)
#define PS3_R1X_LOCK_ERROR(fmt, ...) LOG_ERROR(fmt "\n", ##__VA_ARGS__)

#define PS3_R1X_TIMEOUT(cmd, tmo)                                              \
	(time_after(jiffies, (cmd)->scmd->jiffies_at_alloc + (tmo)))

unsigned int g_ps3_r1x_lock_flag = PS3_R1X_HASHRANGE_LOCK;
unsigned int g_ps3_r1x_lock_enable = 1;

static int ps3_r1x_hash_bit_lock_of_conflict_queue(struct ps3_r1x_lock_mgr *mgr,
						   struct ps3_cmd *cmd);

#if PS3_DESC("-----------------------hash bit互斥方案------------------------")
#define LOCK_BLOCK_SIZE (1 << LOCK_BLOCK_SIZE_SHIFT)
#define LOCK_BLOCK_SIZE_MASK (LOCK_BLOCK_SIZE - 1)
#define RW_BIT_TO_BYTE(bit) ((bit) >> 3)
#define RW_BYTE_TO_BIT(byte) ((bit) << 3)
#define RW_BIT_BYTE_MASK 7
#define RW_R1X_SZBLOCKIDX(lba) (lba >> SZBLOCK_SIZE_SHIFT)
#define RW_SZBLOCK_IDX_INVALID 0xFFFFFFFFFFFF
#define RW_BITMAP_IDX_INVALID 0xFFFF
#define RW_R1X_GET_BITMAP(bit_buff, idx) (bit_buff[idx])
#define RW_BIT_64_MASK 63
#define RW_BYTE_TO_U64(n) (n >> 3)

struct ps3_r1x_hash_bit_item {
	unsigned long long sz_block_idx : 48;
	unsigned long long bitmap_idx : 16;
};

struct ps3_r1x_bit_block_mgr {
	unsigned char *bit_buff;
	unsigned char bit_block_size;
	unsigned char resv[7];
};

struct ps3_r1x_hash_bit_mgr {
	struct ps3_r1x_hash_bit_item hash_item[HASH_TABLE_SIZE];
	struct ps3_r1x_bit_block_mgr bitmap_mgr;
};

static unsigned short ps3_private_r1x_hash(struct ps3_r1x_lock_mgr *mgr,
					   unsigned long hashval)
{
	unsigned long tmp;

	tmp = (hashval * (unsigned long)mgr) ^
	      (GOLDEN_RATIO_PRIME + hashval) / L1_CACHE_BYTES;
	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> HASH_TABLE_SIZE_SHIFT);
	return tmp & HASH_TABLE_SIZE_MASK;
}

static inline void ps3_r1x_conflict_queue_del(struct ps3_r1x_lock_mgr *mgr,
					      struct ps3_cmd *cmd)
{
	unsigned long flag = 0;

	if (cmd->is_inserted_c_q == 1) {
		ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);
		list_del(&cmd->cmd_list);
		cmd->is_inserted_c_q = 0;
		mgr->cmd_count_in_q--;
		ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);
	}
}

void ps3_r1x_conflict_queue_clean(struct ps3_scsi_priv_data *pri_data,
				  int ret_code)
{
	unsigned long flag = 0;

	if (unlikely(pri_data == NULL) || pri_data->lock_mgr.hash_mgr == NULL)
		return;

	ps3_spin_lock_irqsave(&pri_data->lock_mgr.mgr_lock, &flag);
	if (pri_data->lock_mgr.force_ret_code == SCSI_STATUS_GOOD) {
		pri_data->lock_mgr.force_ret_code = ret_code;
		complete(&pri_data->lock_mgr.thread_sync);
	}
	ps3_spin_unlock_irqrestore(&pri_data->lock_mgr.mgr_lock, flag);

	LOG_FILE_INFO("dev[%u:%u], wait r1x conflict queue clean begin\n",
		      PS3_CHANNEL(&pri_data->disk_pos),
		      PS3_TARGET(&pri_data->disk_pos));
	wmb(); /* in order to force CPU ordering */
	while (pri_data->lock_mgr.force_ret_code != SCSI_STATUS_GOOD) {
		ps3_msleep(100);
		rmb(); /* in order to force CPU ordering */
	}
	LOG_FILE_INFO("dev[%u:%u], wait r1x conflict queue clean end\n",
		      PS3_CHANNEL(&pri_data->disk_pos),
		      PS3_TARGET(&pri_data->disk_pos));
}

void ps3_r1x_conflict_queue_target_reset(struct ps3_instance *instance,
					 unsigned short target_id)
{
	struct PS3ChannelInfo *channel_info = &instance->ctrl_info.channelInfo;
	unsigned char i = 0;
	struct ps3_scsi_priv_data *pri_data = NULL;

	for (i = 0; i < channel_info->channelNum; i++) {
		if (channel_info->channels[i].channelType != PS3_DISK_TYPE_VD ||
		    channel_info->channels[i].maxDevNum <= target_id) {
			continue;
		}
		ps3_mutex_lock(&instance->dev_context.dev_priv_lock);

		pri_data =
			ps3_dev_mgr_lookup_vd_pri_data(instance, i, target_id);
		ps3_r1x_conflict_queue_clean(pri_data,
					     SCSI_STATUS_TASK_ABORTED);

		ps3_mutex_unlock(&instance->dev_context.dev_priv_lock);
	}
}

void ps3_r1x_conflict_queue_clean_all(struct ps3_instance *instance,
				      int ret_code, unsigned char is_remove)
{
	struct PS3ChannelInfo *channel_info = &instance->ctrl_info.channelInfo;
	unsigned short maxDevNum = 0;
	unsigned char i = 0;
	unsigned short j = 0;
	struct ps3_scsi_priv_data *pri_data = NULL;

	for (i = 0; i < channel_info->channelNum; i++) {
		if (channel_info->channels[i].channelType != PS3_DISK_TYPE_VD)
			continue;
		maxDevNum = channel_info->channels[i].maxDevNum;

		for (j = 0; j < maxDevNum; j++) {
			ps3_mutex_lock(&instance->dev_context.dev_priv_lock);

			pri_data =
				ps3_dev_mgr_lookup_vd_pri_data(instance, i, j);
			if (unlikely(pri_data == NULL) ||
			    pri_data->lock_mgr.hash_mgr == NULL) {
				ps3_mutex_unlock(
					&instance->dev_context.dev_priv_lock);
				continue;
			}
			pri_data->lock_mgr.dev_deling = is_remove;
			ps3_r1x_conflict_queue_clean(pri_data, ret_code);

			ps3_mutex_unlock(&instance->dev_context.dev_priv_lock);
		}
	}
}

unsigned char ps3_r1x_conflict_queue_abort(struct ps3_cmd *cmd,
					   struct scsi_cmnd *scmd)
{
	unsigned char ret = PS3_TRUE;
	struct ps3_scsi_priv_data *data = NULL;

	if (cmd->is_inserted_c_q == 0) {
		ret = PS3_FALSE;
		goto l_out;
	}

	LOG_INFO("task abort cmd:%d is in conflict queue !\n", cmd->index);

	data = (struct ps3_scsi_priv_data *)scmd->device->hostdata;
	if (unlikely(data == NULL)) {
		ret = PS3_FALSE;
		goto l_out;
	}

	cmd->is_r1x_aborting = 1;
	complete(&data->lock_mgr.thread_sync);

	while (cmd->is_inserted_c_q == 1) {
		ps3_msleep(100);
		rmb(); /* in order to force CPU ordering */
	}

	if (cmd->is_r1x_aborting == 0) {
		ret = PS3_TRUE;
		while (cmd->cmd_state.state != PS3_CMD_STATE_INIT) {
			ps3_msleep(10);
			rmb(); /* in order to force CPU ordering */
		}
	} else {
		ret = PS3_FALSE;
	}
	LOG_INFO("task abort cmd:%d in conflict queue aborting ret:%d\n",
		 cmd->index, ret);

l_out:
	return ret;
}

static void ps3_conflict_queue_clean_bitmap(struct ps3_r1x_hash_bit_mgr *mgr)
{
	unsigned int i = 0;

	LOG_FILE_INFO("ready clean conflict queue bitmap\n");

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		mgr->hash_item[i].sz_block_idx = RW_SZBLOCK_IDX_INVALID;

	memset(mgr->bitmap_mgr.bit_buff, 0, PS3_R1X_BIT_MAP_SIZE);
}

static void ps3_conflict_queue_return_all(struct ps3_r1x_lock_mgr *mgr)
{
	unsigned long flag = 0;
	struct list_head conflict_cmd_list_tmp;
	struct ps3_cmd *cmd = NULL;
	struct ps3_cmd *cmd_next = NULL;
	struct scsi_cmnd *s_cmd = NULL;
	int ret_result = SCSI_STATUS_GOOD;

	INIT_LIST_HEAD(&conflict_cmd_list_tmp);
	ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);

	ret_result = mgr->force_ret_code;

	if (!list_empty(&mgr->conflict_cmd_list)) {
		list_for_each_entry_safe(cmd, cmd_next,
					  &mgr->conflict_cmd_list, cmd_list) {
			list_move_tail(&cmd->cmd_list, &conflict_cmd_list_tmp);
		}
	}

	ps3_conflict_queue_clean_bitmap(
		(struct ps3_r1x_hash_bit_mgr *)mgr->hash_mgr_conflict);

	mgr->cmd_count_in_q = 0;

	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

	list_for_each_entry_safe(cmd, cmd_next, &conflict_cmd_list_tmp,
				  cmd_list) {
		LOG_DEBUG("conflict queue cmd:%d t_id:0x%llx return:0x%x\n",
			  cmd->index, cmd->trace_id, ret_result);

		ps3_scsi_dma_unmap(cmd);
		s_cmd = cmd->scmd;
		PS3_IO_OUTSTAND_DEC(cmd->instance, s_cmd);
		PS3_IO_BACK_ERR_INC(cmd->instance, s_cmd);
		PS3_DEV_BUSY_DEC(s_cmd);
		ps3_scsi_cmd_free(cmd);
		s_cmd->result = ret_result;
		SCMD_IO_DONE(s_cmd);
	}

	if (ret_result != SCSI_STATUS_GOOD)
		mgr->force_ret_code = SCSI_STATUS_GOOD;
}

static int ps3_conflict_queue_resend(struct ps3_instance *instance,
				     struct ps3_r1x_lock_mgr *mgr,
				     struct ps3_cmd *cmd)
{
	int ret = PS3_SUCCESS;
	struct ps3_scsi_priv_data *pri_data = NULL;
	struct scsi_cmnd *s_cmd = cmd->scmd;
	static unsigned long j;

	ret = instance->ioc_adpter->io_cmd_build(cmd);
	if (ret == -PS3_IO_CONFLICT_IN_Q) {
		LOG_DEBUG("t_id:0x%llx hno:%u tag:%d cmd build err ret:%d\n",
			  cmd->trace_id, PS3_HOST(instance), cmd->index, ret);
		goto l_out;
	}

	ps3_r1x_conflict_queue_del(mgr, cmd);

	if (ret == -PS3_IN_QOS_Q) {
		ret = PS3_SUCCESS;
		LOG_DEBUG("insert qos waitq. hno:%u t_id:0x%llx tag:%u\n",
			  PS3_HOST(instance), cmd->trace_id, cmd->index);
		goto l_out;
	}

	if (ret != PS3_SUCCESS) {
		s_cmd->result = PS3_SCSI_RESULT_HOST_STATUS(DID_NO_CONNECT);
		LOG_ERROR_TIME_LIM(
			&j, PS3_LOG_LIMIT_INTERVAL_MSEC,
			"t_id:0x%llx hno:%u tag:%d cmd build NOK ret:%d\n",
			cmd->trace_id, PS3_HOST(instance), cmd->index, ret);
		goto l_cmd_release;
	}

	ret = ps3_scsi_cmd_send(instance, cmd, PS3_TRUE);
	if (unlikely(ret != PS3_SUCCESS)) {
		if (ret == -PS3_RECOVERED || ret == -PS3_RETRY) {
			ps3_errcode_to_scsi_status(instance, s_cmd,
						   SCSI_STATUS_BUSY, NULL, 0,
						   cmd);
		} else {
			s_cmd->result =
				PS3_SCSI_RESULT_HOST_STATUS(DID_NO_CONNECT);
		}
		LOG_ERROR_TIME_LIM(
			&j, PS3_LOG_LIMIT_INTERVAL_MSEC,
			"t_id:0x%llx hno:%u tag:%d cmd send NOK ret:%d\n",
			cmd->trace_id, PS3_HOST(instance), cmd->index, ret);
		PS3_DEV_IO_START_ERR_INC(instance, cmd);
		goto l_cmd_release;
	}

	goto l_out;

l_cmd_release:
	if (cmd->is_got_r1x == 1) {
		pri_data = (struct ps3_scsi_priv_data *)s_cmd->device->hostdata;
		ps3_r1x_write_unlock(&pri_data->lock_mgr, cmd);
	}
l_out:
	return ret;
}

static int ps3_conflict_queue_send_wk(void *data)
{
	struct scsi_device *sdev = (struct scsi_device *)data;
	struct ps3_r1x_lock_mgr *mgr = &PS3_SDEV_PRI_DATA(sdev)->lock_mgr;
	struct ps3_instance *instance =
		(struct ps3_instance *)sdev->host->hostdata;
	struct ps3_cmd *cmd = NULL;
	struct ps3_cmd *cmd_next = NULL;
	struct scsi_cmnd *s_cmd = NULL;
	unsigned long flag = 0;
	int ret = PS3_SUCCESS;
	unsigned int cur_total_count = 0;
	unsigned int cmd_count = 0;
	unsigned char try_count = 0;

	LOG_INFO("hno:%u vd[%u:%u] conflict queue thread enter\n",
		 PS3_HOST(instance), PS3_SDEV_CHANNEL(sdev),
		 PS3_SDEV_TARGET(sdev));

	while (true) {
		wait_for_completion_interruptible(&mgr->thread_sync);
		if (mgr->thread_stop || kthread_should_stop()) {
			LOG_INFO("hno:%u r1x conflict thread, ready stop\n",
				 PS3_HOST(instance));
			goto l_out;
		}

		if (mgr->force_ret_code != SCSI_STATUS_GOOD) {
			LOG_INFO(
				"hno:%u r1x conflict thread, return all cmd with:0x%x\n",
				PS3_HOST(instance), mgr->force_ret_code);
			ps3_conflict_queue_return_all(mgr);
			LOG_INFO(
				"hno:%u r1x conflict thread, return all cmd with:0x%x end\n",
				PS3_HOST(instance), mgr->force_ret_code);
			continue;
		}

		ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);
		cur_total_count = mgr->cmd_count_in_q;
		ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);
		cmd_count = 0;
		try_count = 0;

		list_for_each_entry_safe(cmd, cmd_next,
					  &mgr->conflict_cmd_list, cmd_list) {
			if (cmd->is_r1x_aborting == 1) {
				ps3_scsi_dma_unmap(cmd);
				s_cmd = cmd->scmd;
				cmd->is_r1x_aborting = 0;
				wmb(); /* in order to force CPU ordering */
				ps3_r1x_conflict_queue_del(mgr, cmd);
				PS3_IO_OUTSTAND_DEC(instance, s_cmd);
				PS3_IO_BACK_ERR_INC(instance, s_cmd);
				PS3_DEV_BUSY_DEC(s_cmd);
				s_cmd->result = SCSI_STATUS_TASK_ABORTED;
				SCMD_IO_DONE(s_cmd);
				ps3_scsi_cmd_free(cmd);
				LOG_INFO(
					"hno:%u cmd:%d out r1x conflict queue by abort\n",
					PS3_HOST(instance), cmd->index);
				continue;
			}

			LOG_DEBUG("hno:%u cmd:%d t_id:0x%llx ready resend\n",
				  PS3_HOST(instance), cmd->index,
				  cmd->trace_id);
			ret = ps3_conflict_queue_resend(instance, mgr, cmd);
			if (ret == PS3_SUCCESS) {
				LOG_DEBUG(
					"hno:%u cmd:%d t_id[%llx] out r1x conflict queue by send success\n",
					PS3_HOST(instance), cmd->index,
					cmd->trace_id);
			} else if (ret == -PS3_IO_CONFLICT_IN_Q) {
			} else {
				LOG_INFO(
					"hno:%u cmd:%d tid:0x%llx out r1x conflict queue by send failed\n",
					PS3_HOST(instance), cmd->index,
					cmd->trace_id);
				ps3_scsi_dma_unmap(cmd);
				s_cmd = cmd->scmd;
				PS3_IO_OUTSTAND_DEC(cmd->instance, s_cmd);
				PS3_IO_BACK_ERR_INC(cmd->instance, s_cmd);
				PS3_DEV_BUSY_DEC(s_cmd);
				ps3_scsi_cmd_free(cmd);
				SCMD_IO_DONE(s_cmd);
			}
			LOG_DEBUG("hno:%u cmd:%d t_id:0x%llx resend ret:%d\n",
				  PS3_HOST(instance), cmd->index, cmd->trace_id,
				  ret);
			if (++cmd_count == cur_total_count)
				break;

			if (++try_count == PS3_R1X_RESEND_COUNT) {
				cond_resched();
				try_count = 0;
			}
		}

		ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);
		if (list_empty(&mgr->conflict_cmd_list)) {
			if (mgr->cmd_count_in_q != 0) {
				LOG_INFO_LIM("cmd count in q not zero\n");
				PS3_BUG();
			}
			ps3_conflict_queue_clean_bitmap(
				(struct ps3_r1x_hash_bit_mgr *)
					mgr->hash_mgr_conflict);
		}
		ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);
	}

l_out:
	LOG_FILE_INFO("hno:%u vd[%u:%u] conflict queue thread exit\n",
		      PS3_HOST(instance), PS3_SDEV_CHANNEL(sdev),
		      PS3_SDEV_TARGET(sdev));

	return 0;
}

static inline void ps3_r1x_bitmap_set(struct ps3_r1x_hash_bit_mgr *pHashbitMgr,
				      unsigned short bitmap_idx,
				      unsigned int bit_start,
				      unsigned int bit_cnt)
{
	unsigned int i = 0;
	unsigned long *addr = (unsigned long *)(void *)&RW_R1X_GET_BITMAP(
		pHashbitMgr->bitmap_mgr.bit_buff, bitmap_idx);
	for (; i < bit_cnt; ++i)
		setBitNonAtomic(bit_start + i, addr);
}

static inline void
ps3_r1x_bitmap_clean(struct ps3_r1x_hash_bit_mgr *pHashbitMgr,
		     unsigned short bitmap_idx, unsigned int bit_start,
		     unsigned int bit_cnt)
{
	unsigned int i = 0;
	unsigned long *addr = (unsigned long *)(void *)&RW_R1X_GET_BITMAP(
		pHashbitMgr->bitmap_mgr.bit_buff, bitmap_idx);
	for (; i < bit_cnt; ++i)
		clearBitNonAtomic(bit_start + i, addr);
}

static inline int ps3_r1x_bitmap_check(struct ps3_r1x_hash_bit_mgr *pHashbitMgr,
				       unsigned short bitmap_idx,
				       unsigned int bit_start,
				       unsigned int bit_cnt)
{
	unsigned int i = 0;
	unsigned long *addr = (unsigned long *)(void *)&RW_R1X_GET_BITMAP(
		pHashbitMgr->bitmap_mgr.bit_buff, bitmap_idx);
	for (; i < bit_cnt; ++i) {
		if (unlikely(testBitNonAtomic(bit_start + i, addr)))
			return -PS3_R1X_IO_CONFLICT;
	}
	return PS3_SUCCESS;
}

static inline unsigned int calc_block_num(unsigned long long lba,
					  unsigned int len,
					  unsigned int block_shift,
					  unsigned int block_mask)
{
	unsigned long long start_align = lba;
	unsigned int block_num = 0;
	unsigned int remain_len = 0;

	if (lba & block_mask) {
		block_num += 1;
		start_align = ((lba >> block_shift) + 1) << block_shift;
	}

	if (start_align < lba + len) {
		remain_len = len - ((unsigned int)(start_align - lba));
		block_num += remain_len >> block_shift;
		if (remain_len & block_mask)
			block_num += 1;
	}

	return block_num;
}

struct ps3_write_r1x_hash_tmp {
	struct ps3_r1x_hash_bit_item *hash_item;
	unsigned int bit_start;
	unsigned int bit_cnt;
	unsigned char is_new;
	unsigned char resv[7];
};

int ps3_r1x_hash_bit_check(struct ps3_r1x_hash_bit_mgr *hash_mgr,
			   unsigned long long lba, unsigned int len,
			   struct ps3_write_r1x_hash_tmp *hash_tmp,
			   unsigned short hash_idx)
{
	unsigned long long sz_block_idx = 0;
	unsigned int offset = 0;
	struct ps3_r1x_hash_bit_item *hash_item = NULL;
	int ret = PS3_SUCCESS;
	unsigned int bit_start = 0;
	unsigned int bit_cnt = 0;

	hash_item = &hash_mgr->hash_item[hash_idx];
	sz_block_idx = RW_R1X_SZBLOCKIDX(lba);
	offset = (unsigned int)(lba & SZBLOCK_SIZE_MASK);
	bit_start = offset >> LOCK_BLOCK_SIZE_SHIFT;
	bit_cnt = calc_block_num(lba, len, LOCK_BLOCK_SIZE_SHIFT,
				 LOCK_BLOCK_SIZE_MASK);
	hash_tmp->hash_item = hash_item;
	hash_tmp->is_new = PS3_FALSE;
	hash_tmp->bit_start = bit_start;
	hash_tmp->bit_cnt = bit_cnt;

	PS3_R1X_LOCK_TRACE(
		"lba=%llu, len=%u, hash_idx=%u, hash item=%p, bit check.", lba,
		len, hash_idx, hash_item);
	if (hash_item->sz_block_idx == RW_SZBLOCK_IDX_INVALID) {
		hash_item->sz_block_idx = sz_block_idx;
		hash_tmp->is_new = PS3_TRUE;
		PS3_R1X_LOCK_TRACE(
			"lba=%llu, len=%u, hash_idx=%u, bit_idx=%u, hash item=%p, new hash item.",
			lba, len, hash_idx,
			(unsigned short)hash_item->bitmap_idx, hash_item);
	} else {
		if (hash_item->sz_block_idx == sz_block_idx) {
			ret = ps3_r1x_bitmap_check(
				hash_mgr, (unsigned short)hash_item->bitmap_idx,
				bit_start, bit_cnt);
		} else {
			PS3_R1X_LOCK_TRACE(
				"hash item=%p, oldSzBlock=%llu, newSzBlock=%llu, hash conflict.",
				hash_item,
				(unsigned long long)hash_item->sz_block_idx,
				sz_block_idx);
			ret = -PS3_R1X_HASH_CONFILICT;
		}
	}

	return ret;
}

static unsigned char
ps3_r1x_hash_bit_check_conflict_queue(struct ps3_r1x_lock_mgr *mgr,
				      unsigned long long lba, unsigned int len,
				      unsigned int left)
{
	unsigned char is_conflict = PS3_TRUE;
	int ret = PS3_SUCCESS;
	unsigned int i = 0;
	unsigned char item_cnt = 0;

	struct ps3_write_r1x_hash_tmp *hash_tmp = NULL;
	struct ps3_write_r1x_hash_tmp tmp_array[SZ_BLOCK_SPLIT_MAX];
	struct ps3_r1x_hash_bit_mgr *hash_mgr =
		(struct ps3_r1x_hash_bit_mgr *)mgr->hash_mgr_conflict;

	LOG_DEBUG("lba=%llu, len=%u, left=%u,\n"
		  "\tcheck if conflict with conflict queue.\n",
		  lba, len, left);

	do {
		len = PS3_MIN(len, left);
		ret = ps3_r1x_hash_bit_check(hash_mgr, lba, len,
					     &tmp_array[item_cnt],
					     RW_R1X_HASHIDX(lba));
		item_cnt += 1;
		if (ret != PS3_SUCCESS) {
			is_conflict = PS3_TRUE;
			goto exit_fail;
		}
		left -= len;
		lba += len;
		len = SZBLOCK_SIZE;
	} while (left > 0);

	is_conflict = PS3_FALSE;

exit_fail:

	for (i = 0; i < item_cnt; ++i) {
		hash_tmp = &tmp_array[i];
		if (hash_tmp->is_new) {
			hash_tmp->hash_item->sz_block_idx =
				RW_SZBLOCK_IDX_INVALID;
		}
	}

	return is_conflict;
}

void ps3_r1x_conflict_queue_hash_bit_lock(struct ps3_r1x_lock_mgr *mgr,
					  struct ps3_cmd *cmd)
{
	unsigned int i = 0;
	unsigned char item_cnt = 0;
	unsigned int shift = 0;
	unsigned long long lba = 0;
	unsigned int len = 0;
	unsigned int left = 0;

	struct ps3_r1x_hash_bit_mgr *hash_mgr_conflict =
		(struct ps3_r1x_hash_bit_mgr *)mgr->hash_mgr_conflict;
	struct ps3_write_r1x_hash_tmp *hash_tmp = NULL;
	struct ps3_write_r1x_hash_tmp tmp_array[SZ_BLOCK_SPLIT_MAX];

	shift = cmd->io_attr.vd_entry->sectorSize != SECTOR_SIZE_4K ?
			0 :
			SECTOR_512_4K_SHIFT;
	lba = PS3_LBA(cmd->io_attr.lba_hi, cmd->io_attr.lba_lo) << shift;
	left = cmd->io_attr.num_blocks << shift;
	len = SZBLOCK_SIZE - (lba & SZBLOCK_SIZE_MASK);

	do {
		len = PS3_MIN(len, left);

		hash_tmp = &tmp_array[item_cnt];
		hash_tmp->hash_item =
			&hash_mgr_conflict->hash_item[RW_R1X_HASHIDX(lba)];
		hash_tmp->hash_item->sz_block_idx = RW_R1X_SZBLOCKIDX(lba);
		hash_tmp->is_new = PS3_TRUE;
		hash_tmp->bit_start =
			((unsigned int)(lba & SZBLOCK_SIZE_MASK)) >>
			LOCK_BLOCK_SIZE_SHIFT;
		hash_tmp->bit_cnt = calc_block_num(
			lba, len, LOCK_BLOCK_SIZE_SHIFT, LOCK_BLOCK_SIZE_MASK);

		item_cnt += 1;
		left -= len;
		lba += len;
		len = SZBLOCK_SIZE;
	} while (left > 0);

	for (i = 0; i < item_cnt; ++i) {
		hash_tmp = &tmp_array[i];
		ps3_r1x_bitmap_set(
			hash_mgr_conflict,
			(unsigned short)hash_tmp->hash_item->bitmap_idx,
			hash_tmp->bit_start, hash_tmp->bit_cnt);
	}

}

int ps3_r1x_hash_bit_lock(struct ps3_r1x_lock_mgr *mgr, struct ps3_cmd *cmd)
{
	int ret = PS3_SUCCESS;
	unsigned int i = 0;
	unsigned char item_cnt = 0;
	unsigned char item_cnt_conflict = 0;
	unsigned int shift = 0;
	unsigned long long lba = 0;
	unsigned int len = 0;
	unsigned int left = 0;
	struct ps3_r1x_hash_bit_mgr *hash_mgr =
		(struct ps3_r1x_hash_bit_mgr *)mgr->hash_mgr;
	struct ps3_r1x_hash_bit_mgr *hash_mgr_conflict =
		(struct ps3_r1x_hash_bit_mgr *)mgr->hash_mgr_conflict;
	struct ps3_write_r1x_hash_tmp *hash_tmp = NULL;
	struct ps3_write_r1x_hash_tmp tmp_array[SZ_BLOCK_SPLIT_MAX];
	struct ps3_write_r1x_hash_tmp tmp_array_conflict[SZ_BLOCK_SPLIT_MAX];
	unsigned long flag = 0;
	unsigned char is_conflict_q_empty = PS3_FALSE;

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, cmd=%p, try lock.\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks, cmd);

	shift = cmd->io_attr.vd_entry->sectorSize != SECTOR_SIZE_4K ?
			0 :
			SECTOR_512_4K_SHIFT;
	lba = PS3_LBA(cmd->io_attr.lba_hi, cmd->io_attr.lba_lo) << shift;
	len = cmd->io_attr.num_blocks << shift;
	left = len;

	ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);

	if (mgr->dev_deling) {
		ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);
		ret = PS3_IO_CONFLICT;
		goto l_out;
	}

	is_conflict_q_empty = list_empty(&mgr->conflict_cmd_list);


	len = SZBLOCK_SIZE - (lba & SZBLOCK_SIZE_MASK);
	if (is_conflict_q_empty) {
		do {
			PS3_BUG_ON(item_cnt >= SZ_BLOCK_SPLIT_MAX);
			len = PS3_MIN(len, left);
			ret = ps3_r1x_hash_bit_check(hash_mgr, lba, len,
						     &tmp_array[item_cnt],
						     RW_R1X_HASHIDX(lba));
			item_cnt += 1;
			if (ret != PS3_SUCCESS)
				goto exit_fail;
			left -= len;
			lba += len;
			len = SZBLOCK_SIZE;
		} while (left > 0);
	} else {
		do {
			PS3_BUG_ON(item_cnt >= SZ_BLOCK_SPLIT_MAX);
			len = PS3_MIN(len, left);
			ret = ps3_r1x_hash_bit_check(hash_mgr, lba, len,
						     &tmp_array[item_cnt],
						     RW_R1X_HASHIDX(lba));
			item_cnt += 1;
			if (ret != PS3_SUCCESS)
				goto exit_fail;
			ret = ps3_r1x_hash_bit_check(
				hash_mgr_conflict, lba, len,
				&tmp_array_conflict[item_cnt_conflict],
				RW_R1X_HASHIDX(lba));
			item_cnt_conflict += 1;
			if (ret != PS3_SUCCESS)
				goto exit_fail;
			left -= len;
			lba += len;
			len = SZBLOCK_SIZE;
		} while (left > 0);

		for (i = 0; i < item_cnt_conflict; ++i) {
			hash_tmp = &tmp_array_conflict[i];
			if (hash_tmp->is_new == PS3_TRUE) {
				hash_tmp->hash_item->sz_block_idx =
					RW_SZBLOCK_IDX_INVALID;
			}
		}
	}

	for (i = 0; i < item_cnt; ++i) {
		hash_tmp = &tmp_array[i];
		ps3_r1x_bitmap_set(
			hash_mgr,
			(unsigned short)hash_tmp->hash_item->bitmap_idx,
			hash_tmp->bit_start, hash_tmp->bit_cnt);
	}

	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

	cmd->szblock_cnt = item_cnt;
	cmd->is_got_r1x = 1;

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, lock success.\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks);

	ret = PS3_SUCCESS;
	goto l_out;
exit_fail:

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, lock failed, ret=%d\n"
		"\t(%d: io conflict, %d: hash conflict, %d: bitmap not enough).\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks, ret, -PS3_R1X_IO_CONFLICT,
		-PS3_R1X_HASH_CONFILICT, -PS3_R1X_BIT_NOT_ENOUGH);

	cmd->szblock_cnt = 0;
	for (i = 0; i < item_cnt; ++i) {
		hash_tmp = &tmp_array[i];
		if (hash_tmp->is_new == PS3_TRUE) {
			hash_tmp->hash_item->sz_block_idx =
				RW_SZBLOCK_IDX_INVALID;
		}
	}

	for (i = 0; i < item_cnt_conflict; ++i) {
		hash_tmp = &tmp_array_conflict[i];
		if (hash_tmp->is_new == PS3_TRUE) {
			hash_tmp->hash_item->sz_block_idx =
				RW_SZBLOCK_IDX_INVALID;
		}
	}

	if (ps3_r1x_conflict_queue_support_query()) {
		if (PS3_R1X_TIMEOUT(cmd, ps3_r1x_tmo_query())) {
			list_add_tail(&cmd->cmd_list, &mgr->conflict_cmd_list);

			ps3_r1x_conflict_queue_hash_bit_lock(mgr, cmd);
			cmd->is_inserted_c_q = 1;
			mgr->cmd_count_in_q++;

			ret = -PS3_IO_CONFLICT_IN_Q;
		} else {
			if (is_conflict_q_empty)
				ret = -PS3_IO_REQUEUE;
			else
				ret = -PS3_IO_CONFLICT;
		}
	} else {
		ret = -PS3_IO_CONFLICT;
	}

	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, lock failed, fanal ret=%d\n"
		"\t(%d: conflict requeue, %d: conflict in queue, %d: conflict busy).\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks, ret, -PS3_IO_REQUEUE,
		-PS3_IO_CONFLICT_IN_Q, -PS3_IO_CONFLICT);
l_out:

	return ret;
}

static int ps3_r1x_hash_bit_lock_of_conflict_queue(struct ps3_r1x_lock_mgr *mgr,
						   struct ps3_cmd *cmd)
{
	int ret = PS3_SUCCESS;
	unsigned int i = 0;
	unsigned char item_cnt = 0;
	unsigned int shift = 0;
	unsigned long long lba = 0;
	unsigned int len = 0;
	unsigned int left = 0;
	struct ps3_r1x_hash_bit_mgr *hash_mgr =
		(struct ps3_r1x_hash_bit_mgr *)mgr->hash_mgr;
	struct ps3_write_r1x_hash_tmp *hash_tmp = NULL;
	struct ps3_write_r1x_hash_tmp tmp_array[SZ_BLOCK_SPLIT_MAX];
	unsigned long flag = 0;

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, cmd=%p, try lock.\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks, cmd);

	shift = cmd->io_attr.vd_entry->sectorSize != SECTOR_SIZE_4K ?
			0 :
			SECTOR_512_4K_SHIFT;
	;
	lba = PS3_LBA(cmd->io_attr.lba_hi, cmd->io_attr.lba_lo) << shift;
	;
	len = cmd->io_attr.num_blocks << shift;
	left = len;

	ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);

	len = SZBLOCK_SIZE - (lba & SZBLOCK_SIZE_MASK);
	do {
		PS3_BUG_ON(item_cnt >= SZ_BLOCK_SPLIT_MAX);
		len = PS3_MIN(len, left);
		ret = ps3_r1x_hash_bit_check(hash_mgr, lba, len,
					     &tmp_array[item_cnt],
					     RW_R1X_HASHIDX(lba));
		item_cnt += 1;
		if (ret != PS3_SUCCESS)
			goto exit_fail;
		left -= len;
		lba += len;
		len = SZBLOCK_SIZE;
	} while (left > 0);

	for (i = 0; i < item_cnt; ++i) {
		hash_tmp = &tmp_array[i];
		ps3_r1x_bitmap_set(
			hash_mgr,
			(unsigned short)hash_tmp->hash_item->bitmap_idx,
			hash_tmp->bit_start, hash_tmp->bit_cnt);
	}

	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

	cmd->szblock_cnt = item_cnt;
	cmd->is_got_r1x = 1;

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, lock success.\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks);

	return PS3_SUCCESS;

exit_fail:

	for (i = 0; i < item_cnt; ++i) {
		hash_tmp = &tmp_array[i];
		if (hash_tmp->is_new == PS3_TRUE) {
			hash_tmp->hash_item->sz_block_idx =
				RW_SZBLOCK_IDX_INVALID;
		}
	}

	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

	cmd->szblock_cnt = 0;
	ret = -PS3_IO_CONFLICT_IN_Q;

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, relock failed, ret=%d\n"
		"\t(%d: io conflict, %d: hash conflict, %d: bitmap not enough).\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks, ret, -PS3_R1X_IO_CONFLICT,
		-PS3_R1X_HASH_CONFILICT, -PS3_R1X_BIT_NOT_ENOUGH);
	return ret;
}

void ps3_r1x_hash_bit_unlock(struct ps3_r1x_lock_mgr *mgr, struct ps3_cmd *cmd)
{
	struct ps3_r1x_hash_bit_item *hash_item = NULL;
	unsigned int bit_start = 0;
	unsigned int bit_cnt = 0;
	unsigned long long *bit_map = NULL;
	unsigned int i = 0;
	int is_clean = PS3_TRUE;
	unsigned int shift = 0;
	unsigned long long lba = 0;
	unsigned int len = 0;
	unsigned int left = 0;
	unsigned long long conflict_check_lba = 0;
	unsigned int conflict_check_len = 0;
	unsigned int conflict_check_left = 0;
	struct ps3_r1x_hash_bit_mgr *hash_mgr =
		(struct ps3_r1x_hash_bit_mgr *)mgr->hash_mgr;
	struct ps3_r1x_bit_block_mgr *bit_map_mgr = &hash_mgr->bitmap_mgr;
	unsigned long flag = 0;
	unsigned char ret_check = PS3_CONFLICT_QUEUE_EMPTY;

	PS3_R1X_LOCK_TRACE(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, cmd=%p, unlock.",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks, cmd);

	shift = cmd->io_attr.vd_entry->sectorSize != SECTOR_SIZE_4K ?
			0 :
			SECTOR_512_4K_SHIFT;
	lba = PS3_LBA(cmd->io_attr.lba_hi, cmd->io_attr.lba_lo) << shift;
	left = cmd->io_attr.num_blocks << shift;
	len = SZBLOCK_SIZE - (lba & SZBLOCK_SIZE_MASK);

	conflict_check_lba = lba;
	conflict_check_len = len;
	conflict_check_left = left;

	ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);
	do {
		hash_item = &hash_mgr->hash_item[RW_R1X_HASHIDX(lba)];
		len = PS3_MIN(len, left);
		bit_start = (lba & SZBLOCK_SIZE_MASK) >> LOCK_BLOCK_SIZE_SHIFT;
		bit_cnt = calc_block_num(lba, len, LOCK_BLOCK_SIZE_SHIFT,
					 LOCK_BLOCK_SIZE_MASK);
		ps3_r1x_bitmap_clean(hash_mgr,
				     (unsigned short)hash_item->bitmap_idx,
				     bit_start, bit_cnt);

		is_clean = PS3_TRUE;
		bit_map = (unsigned long long *)(void *)&RW_R1X_GET_BITMAP(
			bit_map_mgr->bit_buff, hash_item->bitmap_idx);
		for (i = 0; i < bit_map_mgr->bit_block_size; ++i) {
			if (bit_map[i] != 0)
				is_clean = PS3_FALSE;
		}

		if (is_clean == PS3_TRUE) {
			PS3_R1X_LOCK_TRACE(
				"t_id:0x%llx lba=%llu, len=%u, szBlockIdx=%llu, bitIdx=%lu,\n"
				"\tszblock_cnt=%u, cmd=%p, release hash item.",
				cmd->trace_id, lba, len,
				(unsigned long long)hash_item->sz_block_idx,
				(unsigned long)hash_item->bitmap_idx,
				cmd->szblock_cnt, cmd);
			hash_item->sz_block_idx = RW_SZBLOCK_IDX_INVALID;
		}

		left -= len;
		lba += len;
		len = SZBLOCK_SIZE;
	} while (left > 0);

	if (!list_empty(&mgr->conflict_cmd_list)) {
		if (ps3_r1x_hash_bit_check_conflict_queue(
			    mgr, conflict_check_lba, conflict_check_len,
			    conflict_check_left)) {
			ret_check = PS3_CONFLICT_QUEUE_CONFLICT;
		} else {
			ret_check = PS3_CONFLICT_QUEUE_NO_CONFLICT;
		}
	}

	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

	if (ret_check != PS3_CONFLICT_QUEUE_EMPTY) {
		LOG_FILE_INFO("t_id:0x%llx lba_high=%u, lba_low=%u, len=%u,\n"
			      "\tconflict queue check ret:%d.\n",
			      cmd->trace_id, cmd->io_attr.lba_hi,
			      cmd->io_attr.lba_lo, cmd->io_attr.num_blocks,
			      ret_check);

		if (ret_check == PS3_CONFLICT_QUEUE_CONFLICT)
			complete(&mgr->thread_sync);
	}

}

static void *ps3_r1x_lock_hash_bit_init(struct ps3_instance *instance)
{
	unsigned int bit_map_size = 0;
	unsigned short sz_block_bit_cnt = 0;
	unsigned short bitmap_block_size = 0;
	unsigned short bitmap_block_cnt = 0;
	unsigned int total_size = 0;
	struct ps3_r1x_hash_bit_mgr *mgr = NULL;
	unsigned char *buff = NULL;
	unsigned int i = 0;
	(void)instance;
	(void)bitmap_block_cnt;

	if (SZBLOCK_SIZE & LOCK_BLOCK_SIZE_MASK) {
		LOG_FILE_ERROR("hno: %u, SZBLOCK_SIZE check NOK\n",
			       PS3_HOST(instance));
		goto exit;
	}
	bit_map_size = PS3_R1X_BIT_MAP_SIZE;
	sz_block_bit_cnt = SZBLOCK_SIZE >> LOCK_BLOCK_SIZE_SHIFT;
	if (sz_block_bit_cnt & RW_BIT_64_MASK) {
		LOG_FILE_ERROR("hno: %u, sz_block_bit_cnt check NOK\n",
			       PS3_HOST(instance));
		goto exit;
	}
	total_size = sizeof(struct ps3_r1x_hash_bit_mgr) + bit_map_size;
	buff = (unsigned char *)(void *)ps3_vzalloc(instance, total_size);
	if (buff == NULL) {
		PS3_R1X_LOCK_ERROR(
			"r1x vd alloc write lock mgr failed. totoalSize=%u",
			total_size);
		goto exit;
	}

	bitmap_block_size = RW_BIT_TO_BYTE(sz_block_bit_cnt);
	mgr = (struct ps3_r1x_hash_bit_mgr *)(void *)buff;
	for (i = 0; i < HASH_TABLE_SIZE; ++i) {
		mgr->hash_item[i].sz_block_idx = RW_SZBLOCK_IDX_INVALID;
		if (RW_BITMAP_IDX_INVALID < (i * bitmap_block_size)) {
			LOG_ERROR("hno: %u, bitmap_block_size check NOK\n",
				  PS3_HOST(instance));
			PS3_BUG();
			ps3_vfree(instance, buff);
			mgr = NULL;
			goto exit;
		}
		mgr->hash_item[i].bitmap_idx = i * bitmap_block_size;
	}
	mgr->bitmap_mgr.bit_block_size =
		(unsigned char)RW_BYTE_TO_U64(bitmap_block_size);
	buff += sizeof(struct ps3_r1x_hash_bit_mgr);
	mgr->bitmap_mgr.bit_buff = (unsigned char *)(void *)buff;
	buff += bit_map_size;

	LOG_FILE_INFO(
		"r1x vd init write lock mgr success,totoalSize=%u, hashTableSize=%u,\n"
		"\tbitmapSize=%u(bytes), bitmap_block_cnt=%u, bitmap_block_size=%u.\n",
		total_size, HASH_TABLE_SIZE, bit_map_size, bitmap_block_cnt,
		bitmap_block_size);

exit:
	return mgr;
}
#endif

#if PS3_DESC("-----------------------hash range互斥方案------------------------")
struct ps3_renge_extent {
	unsigned long long start;
	unsigned long long end;
};

struct ps3_range_tree_node {
	struct Ps3RbNode rbNode;
	struct ps3_renge_extent extent;
};

struct ps3_range_tree_root {
	struct Ps3RbRoot rbRoot;
};

struct ps3_r1x_hash_range_mgr {
	struct ps3_range_tree_root hash_item[HASH_TABLE_SIZE];
};

#define RANGETEE_EXTENT(rbNodePtr)                                             \
	((ps3_container_of(rbNodePtr, struct ps3_range_tree_node, rbNode))     \
		 ->extent)

int ps3_range_check_and_insert(struct ps3_range_tree_root *range_root,
			       struct ps3_range_tree_node *range_node)
{
	int ret = PS3_SUCCESS;
	struct Ps3RbNode *node = &range_node->rbNode;
	struct Ps3RbNode *parent = NULL;
	struct Ps3RbNode **pp_linker = NULL;
	struct ps3_renge_extent *ext = &range_node->extent;

	PS3_R1X_LOCK_TRACE("root=%p, rbNode=%p, lba=%llu, endLba=%llu, check.",
			   range_root->rbRoot.pRoot, node, ext->start,
			   ext->end);

	pp_linker = &range_root->rbRoot.pRoot;
	while (*pp_linker != NULL) {
		parent = *pp_linker;
		if (ext->start > RANGETEE_EXTENT(parent).end) {
			pp_linker = &parent->pRight;
		} else if (ext->end < RANGETEE_EXTENT(parent).start) {
			pp_linker = &parent->pLeft;
		} else {
			ret = -PS3_R1X_IO_CONFLICT;
			PS3_R1X_LOCK_TRACE(
				"root=%p, rbNode=%p, lba=%llu, endLba=%llu, confilct.",
				range_root->rbRoot.pRoot, node, ext->start,
				ext->end);
			goto exit;
		}
	}

	node->pParentColor = ((uintptr_t)(void *)parent);
	node->pLeft = NULL;
	node->pRight = NULL;
	(*pp_linker) = node;
	ps3RbtColorAfterAdd(&range_root->rbRoot, node);
	PS3_R1X_LOCK_TRACE("root=%p, rbNode=%p, lba=%llu, endLba=%llu, add.",
			   range_root->rbRoot.pRoot, node, ext->start,
			   ext->end);

exit:
	return ret;
}

static inline void ps3_range_del_node(struct ps3_range_tree_root *range_root,
				      struct ps3_range_tree_node *del_node)
{
	PS3_R1X_LOCK_TRACE("root=%p, rbNode=%p, lba=%llu, endLba=%llu, del.",
			   range_root->rbRoot.pRoot, &del_node->rbNode,
			   del_node->extent.start, del_node->extent.end);
	if (unlikely(PS3_SUCCESS !=
		     ps3RbtDelNode(&range_root->rbRoot, &del_node->rbNode))) {
		LOG_FILE_ERROR(
			"startLba=%llu, endLba=%llu, del range node failed.\n",
			del_node->extent.start, del_node->extent.end);
		PS3_BUG();
	}
}

int ps3_r1x_hash_range_lock(struct ps3_r1x_lock_mgr *mgr, struct ps3_cmd *cmd)
{
	int ret = PS3_SUCCESS;
	unsigned long long hash_idx = 0;
	unsigned char node_num = 0;
	unsigned int shift = 0;
	unsigned long long lba = 0;
	unsigned int len = 0;
	unsigned int left = 0;
	struct ps3_r1x_hash_range_mgr *hash_range_mgr =
		(struct ps3_r1x_hash_range_mgr *)mgr->hash_mgr;
	struct ps3_range_tree_node *range_node =
		(struct ps3_range_tree_node *)cmd->node_buff;
	struct ps3_range_tree_node *del_node = NULL;
	unsigned long flag = 0;

	PS3_R1X_LOCK_TRACE(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, try lock.",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks);

	shift = cmd->io_attr.vd_entry->sectorSize != SECTOR_SIZE_4K ?
			0 :
			SECTOR_512_4K_SHIFT;
	;
	lba = PS3_LBA(cmd->io_attr.lba_hi, cmd->io_attr.lba_lo) << shift;
	;
	len = cmd->io_attr.num_blocks << shift;
	left = len;

	ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);

	len = SZBLOCK_SIZE - (lba & SZBLOCK_SIZE_MASK);
	do {
		range_node = &(
			(struct ps3_range_tree_node *)cmd->node_buff)[node_num];
		len = PS3_MIN(len, left);
		range_node->extent.start = lba;
		range_node->extent.end = lba + len - 1;
		ps3RbNodeInit(&range_node->rbNode);
		hash_idx = RW_R1X_HASHIDX_HASH(mgr, lba);

		ret = ps3_range_check_and_insert(
			&hash_range_mgr->hash_item[hash_idx], range_node);
		if (unlikely(ret != PS3_SUCCESS))
			goto exit_fail;

		left -= len;
		lba += len;
		len = SZBLOCK_SIZE;
		node_num++;
	} while (left > 0);

	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);
	cmd->szblock_cnt = node_num;
	cmd->is_got_r1x = 1;

	PS3_R1X_LOCK_TRACE(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, lock success.",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks);
	return ret;

exit_fail:
	cmd->szblock_cnt = 0;
	del_node = (struct ps3_range_tree_node *)cmd->node_buff;
	for (; del_node != range_node; del_node++) {
		hash_idx = RW_R1X_HASHIDX_HASH(mgr, del_node->extent.start);
		ps3_range_del_node(&hash_range_mgr->hash_item[hash_idx],
				   del_node);
	}
	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

	LOG_DEBUG(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, io conflict, lock failed.\n",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks);
	ret = -PS3_IO_REQUEUE;
	return ret;
}

void ps3_r1x_hash_range_unlock(struct ps3_r1x_lock_mgr *mgr,
			       struct ps3_cmd *cmd)
{
	unsigned int i = 0;
	unsigned long long hash_idx = 0;
	struct ps3_range_tree_node *range_node = NULL;
	struct ps3_r1x_hash_range_mgr *hash_range_mgr =
		(struct ps3_r1x_hash_range_mgr *)mgr->hash_mgr;
	unsigned long flag = 0;

	PS3_R1X_LOCK_TRACE(
		"t_id:0x%llx lba_high=%u, lba_low=%u, len=%u, unlock.",
		cmd->trace_id, cmd->io_attr.lba_hi, cmd->io_attr.lba_lo,
		cmd->io_attr.num_blocks);

	ps3_spin_lock_irqsave(&mgr->mgr_lock, &flag);

	for (i = 0; i < cmd->szblock_cnt; ++i) {
		range_node = &((struct ps3_range_tree_node *)cmd->node_buff)[i];
		hash_idx = RW_R1X_HASHIDX_HASH(mgr, range_node->extent.start);
		ps3_range_del_node(&hash_range_mgr->hash_item[hash_idx],
				   range_node);
	}
	ps3_spin_unlock_irqrestore(&mgr->mgr_lock, flag);

}

static void *ps3_r1x_hash_range_init(struct ps3_instance *instance)
{
	unsigned int total_size = 0;
	unsigned int i = 0;
	struct ps3_r1x_hash_range_mgr *mgr = NULL;

	total_size = sizeof(struct ps3_r1x_hash_range_mgr);
	mgr = (struct ps3_r1x_hash_range_mgr *)(void *)ps3_vzalloc(instance,
								   total_size);
	if (mgr == NULL) {
		PS3_R1X_LOCK_ERROR(
			"r1x vd write lock alloc hash range mgr failed. totoalSize=%u",
			total_size);
		goto exit;
	}

	for (i = 0; i < HASH_TABLE_SIZE; ++i)
		mgr->hash_item[i].rbRoot.pRoot = NULL;

	LOG_FILE_INFO("r1x vd write lock init hash range mgr success.\n"
		      "\ttotoalSize=%u, hashTableSize=%u\n",
		      total_size, HASH_TABLE_SIZE);
exit:
	return mgr;
}

#endif

#if PS3_DESC("-----------------------对外接口------------------------")

unsigned int ps3_r1x_get_node_Buff_size(void)
{
	return sizeof(struct ps3_range_tree_node) * SZ_BLOCK_SPLIT_MAX;
}

int ps3_r1x_lock_prepare_for_vd(struct ps3_instance *instance,
				struct scsi_device *sdev,
				unsigned char raid_level)
{
	int ret = PS3_SUCCESS;
	struct ps3_r1x_lock_mgr *mgr = &PS3_SDEV_PRI_DATA(sdev)->lock_mgr;

	mgr->hash_mgr = NULL;
	mgr->try_lock = NULL;
	mgr->unlock = NULL;

	if (raid_level != RAID1 && raid_level != RAID1E &&
	    raid_level != RAID10) {
		goto exit;
	}

	ps3_spin_lock_init(&mgr->mgr_lock);

	if (g_ps3_r1x_lock_flag == PS3_R1X_HASHBIT_LOCK) {
		mgr->hash_mgr = ps3_r1x_lock_hash_bit_init(instance);
		mgr->try_lock = (int (*)(struct ps3_r1x_lock_mgr *, void *))(
			void *)ps3_r1x_hash_bit_lock;
		mgr->resend_try_lock =
			(int (*)(struct ps3_r1x_lock_mgr *, void *))(
				void *)ps3_r1x_hash_bit_lock_of_conflict_queue;
		mgr->unlock = (void (*)(struct ps3_r1x_lock_mgr *, void *))(
			void *)ps3_r1x_hash_bit_unlock;
	} else if (g_ps3_r1x_lock_flag == PS3_R1X_HASHRANGE_LOCK) {
		LOG_DEBUG("hno:%u vd[%u:%u] use rb tree r1x\n",
			  PS3_HOST(instance), PS3_SDEV_CHANNEL(sdev),
			  PS3_SDEV_TARGET(sdev));
		mgr->hash_mgr = ps3_r1x_hash_range_init(instance);
		mgr->try_lock = (int (*)(struct ps3_r1x_lock_mgr *, void *))(
			void *)ps3_r1x_hash_range_lock;
		mgr->resend_try_lock =
			(int (*)(struct ps3_r1x_lock_mgr *, void *))(
				void *)ps3_r1x_hash_range_lock;
		mgr->unlock = (void (*)(struct ps3_r1x_lock_mgr *, void *))(
			void *)ps3_r1x_hash_range_unlock;
	}
	if (unlikely(mgr->hash_mgr == NULL)) {
		LOG_ERROR("hno:%u vd[%u:%u] r1x hash mgr init failed\n",
			  PS3_HOST(instance), PS3_SDEV_CHANNEL(sdev),
			  PS3_SDEV_TARGET(sdev));
		goto l_err;
	}

	mgr->hash_mgr_conflict = ps3_r1x_lock_hash_bit_init(instance);
	if (unlikely(mgr->hash_mgr_conflict == NULL)) {
		LOG_ERROR(
			"hno:%u vd[%u:%u] r1x hash mgr conflict init failed\n",
			PS3_HOST(instance), PS3_SDEV_CHANNEL(sdev),
			PS3_SDEV_TARGET(sdev));
		goto l_err;
	}

	mgr->thread_stop = PS3_FALSE;
	mgr->dev_deling = PS3_FALSE;
	mgr->force_ret_code = SCSI_STATUS_GOOD;

	INIT_LIST_HEAD(&mgr->conflict_cmd_list);
	mgr->cmd_count_in_q = 0;
	init_completion(&mgr->thread_sync);

	mgr->conflict_send_th =
		kthread_run(ps3_conflict_queue_send_wk, sdev, "r1x_send");
	if (IS_ERR(mgr->conflict_send_th)) {
		LOG_ERROR(
			"hno:%u vd[%u:%u] r1x conflict send thread creat failed\n",
			PS3_HOST(instance), PS3_SDEV_CHANNEL(sdev),
			PS3_SDEV_TARGET(sdev));
		goto l_err;
	}

	goto exit;
l_err:
	ps3_r1x_lock_destroy_for_vd(instance, mgr);
	ret = -PS3_FAILED;
exit:
	return ret;
}

static int ps3_kthread_stop(struct ps3_instance *instance,
			    struct ps3_r1x_lock_mgr *mgr)
{
	int ret = PS3_SUCCESS;

	(void)instance;
	mgr->thread_stop = PS3_TRUE;
	complete(&mgr->thread_sync);

	LOG_FILE_INFO("hno:%u r1x conflict destroy, begin stop\n",
		      PS3_HOST(instance));
	ret = kthread_stop(mgr->conflict_send_th);
	LOG_FILE_INFO("hno:%u r1x conflict destroy, stopped\n",
		      PS3_HOST(instance));

	return ret;
}

void ps3_r1x_lock_destroy_for_vd(struct ps3_instance *instance,
				 struct ps3_r1x_lock_mgr *mgr)
{
	if (mgr->conflict_send_th != NULL)
		ps3_kthread_stop(instance, mgr);

	if (mgr->hash_mgr_conflict != NULL)
		ps3_vfree(instance, mgr->hash_mgr_conflict);

	if (mgr->hash_mgr != NULL)
		ps3_vfree(instance, mgr->hash_mgr);
	mgr->hash_mgr = NULL;
	mgr->try_lock = NULL;
	mgr->unlock = NULL;
	LOG_FILE_INFO("r1x vd deinit write lock mgr success.");

}

#endif
