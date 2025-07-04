// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) LD. */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/rtc.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#ifdef PS3_UT
#include <linux/uaccess.h>
#endif

#include "ps3_dump.h"
#include "ps3_mgr_cmd.h"
#include "ps3_cmd_channel.h"
#include "ps3_mgr_channel.h"
#include "ps3_cmd_statistics.h"
#include "ps3_ioc_manager.h"
#include "ps3_util.h"
#include "ps3_cli.h"
#include "ps3_module_para.h"
#include "ps3_kernel_version.h"

static inline void ps3_dump_status_set(struct ps3_instance *instance,
				       unsigned long long value);

int ps3_dump_local_time(struct rtc_time *tm)
{
#if defined(PS3_DUMP_TIME_32)
	struct timeval time;
	unsigned long long local_time;

	do_gettimeofday(&time);
	local_time = (unsigned long long)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, tm);
#else
	struct timespec64 time;
	unsigned long long local_time;

	ktime_get_real_ts64(&time);
	local_time = (unsigned long long)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time64_to_tm(local_time, tm);
#endif
	tm->tm_mon += 1;
	tm->tm_year += 1900;
	return 0;
}

int ps3_dump_filename_build(struct ps3_instance *instance, char *filename,
			    unsigned int len, unsigned char *prefix)
{
	struct ps3_dump_context *ctxt = &instance->dump_context;
	struct rtc_time tm;
	char *p_str = filename;

	if (filename == NULL || prefix == NULL)
		return -1;

	ps3_dump_local_time(&tm);
	p_str +=
		snprintf(p_str, len - (p_str - filename), "%s", ctxt->dump_dir);
	p_str +=
		snprintf(p_str, len - (p_str - filename), (const char *)prefix);
	p_str += snprintf(p_str, len - (p_str - filename), "host%d-",
			  instance->host->host_no);
	p_str += snprintf(p_str, len - (p_str - filename),
			  "%04d%02d%02d-%02d%02d%02d-", tm.tm_year, tm.tm_mon,
			  tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	p_str += snprintf(p_str, len - (p_str - filename), "%llu",
			  instance->ioc_fw_version);

	return 0;
}

int ps3_dump_file_open(struct ps3_dump_context *ctxt, unsigned int dump_type)
{
	struct ps3_dump_file_info *file_info = &ctxt->dump_out_file;
	unsigned char filename[PS3_DUMP_FILE_NAME_LEN] = { 0 };
	unsigned char *p_prefix = NULL;
	int ret = PS3_SUCCESS;
	struct file *fp = NULL;
#if defined(PS3_SUPPORT_FS)
	mm_segment_t old_fs;
#endif

	if (file_info->fp || file_info->file_status == PS3_DUMP_FILE_OPEN) {
		LOG_INFO("dump file open: file already open\n");
		ret = -PS3_FAILED;
		goto l_out;
	}

	memset(file_info, 0, sizeof(struct ps3_dump_file_info));

	switch (dump_type) {
	case PS3_DUMP_TYPE_FW_LOG:
		p_prefix = (unsigned char *)PS3_DUMP_FILE_FWLOG_PREFIX;
		break;
	case PS3_DUMP_TYPE_BAR_DATA:
		p_prefix = (unsigned char *)PS3_DUMP_FILE_BAR_PREFIX;
		break;
	case PS3_DUMP_TYPE_CRASH:
		p_prefix = (unsigned char *)PS3_DUMP_FILE_CORE_PREFIX;
		break;
	default:
		LOG_INFO("dump file create: unknown dump type %d\n", dump_type);
		ret = -PS3_FAILED;
		goto l_out;
	}

	if (ps3_dump_filename_build(ctxt->instance, (char *)filename,
				    PS3_DUMP_FILE_NAME_LEN, p_prefix) != 0) {
		LOG_INFO("dump file create: filename build NOK\n");
		ret = -PS3_FAILED;
		goto l_out;
	}

	fp = (struct file *)filp_open(
		(char *)filename, O_CREAT | O_RDWR | O_TRUNC | O_LARGEFILE, 0);
	if (IS_ERR(fp)) {
		LOG_INFO(
			"dump file create: filp_open error filename %s errno %d\n",
			filename, (int)PTR_ERR(fp));
		ret = -PS3_FAILED;
		goto l_out;
	}
	if (!ps3_fs_requires_dev(fp)) {
#if defined(PS3_KERNEL_WRITE_GET_DS)
		old_fs = get_fs();
		set_fs(get_ds());
#elif defined(PS3_KERNEL_WRITE)
		old_fs = get_fs();
		set_fs(KERNEL_DS);
#elif defined(PS3_VFS_WRITE)
#else
		old_fs = force_uaccess_begin();
#endif
		filp_close(fp, NULL);
#if defined(PS3_SET_FS)
		set_fs(old_fs);
#elif defined(PS3_FORCE_UACCESS)
#else
		force_uaccess_end(old_fs);
#endif

		ret = -PS3_FAILED;
		goto l_out;
	}

	memcpy(file_info->filename, filename, PS3_DUMP_FILE_NAME_LEN);
	file_info->type = dump_type;
	file_info->file_status = PS3_DUMP_FILE_OPEN;
	file_info->fp = fp;

l_out:
	return ret;
}

int ps3_dump_file_write(struct ps3_dump_file_info *file_info, unsigned char *buf, unsigned int len)
{
	struct file *fp = NULL;
#if defined(PS3_SUPPORT_FS)
	mm_segment_t old_fs;
#endif
	int ret = 0;

	if (file_info && file_info->fp) {
		fp = file_info->fp;
#if defined(PS3_KERNEL_WRITE_GET_DS)
		old_fs = get_fs();
		set_fs(get_ds());
#elif defined(PS3_KERNEL_WRITE)
		old_fs = get_fs();
		set_fs(KERNEL_DS);
#elif defined(PS3_VFS_WRITE)
#else
		old_fs = force_uaccess_begin();
#endif

#if defined(PS3_KERNEL_WRITE_FILE)
		ret = kernel_write(fp, (char *)buf, len, &fp->f_pos);
#else
		ret = vfs_write(fp, (char *)buf, len, &fp->f_pos);
#endif
#if defined(PS3_SET_FS)
		set_fs(old_fs);
#elif defined(PS3_FORCE_UACCESS)
#else
		force_uaccess_end(old_fs);
#endif

		if (ret > 0)
			file_info->file_size += len;
		file_info->file_w_cnt++;
	}

	return ret;
}

int ps3_dump_file_close(struct ps3_dump_file_info *file_info)
{
#if defined(PS3_SUPPORT_FS)
	mm_segment_t old_fs;
#endif
	if (file_info && file_info->fp) {
		PS3_BUG_ON(IS_ERR(file_info->fp));
#if defined(PS3_KERNEL_WRITE_GET_DS)
		old_fs = get_fs();
		set_fs(get_ds());
#elif defined(PS3_KERNEL_WRITE)
		old_fs = get_fs();
		set_fs(KERNEL_DS);
#elif defined(PS3_VFS_WRITE)
#else
		old_fs = force_uaccess_begin();
#endif
		filp_close(file_info->fp, NULL);
#if defined(PS3_SET_FS)
		set_fs(old_fs);
#elif defined(PS3_FORCE_UACCESS)
#else
		force_uaccess_end(old_fs);
#endif

		file_info->fp = NULL;
		file_info->file_status = PS3_DUMP_FILE_CLOSE;
	}
	return 0;
}

struct ps3_dump_context *dev_to_dump_context(struct device *cdev)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct ps3_instance *instance = (struct ps3_instance *)shost->hostdata;

	return &instance->dump_context;
}

static inline unsigned char ps3_dump_ctrl_get(struct ps3_instance *instance,
				     unsigned long long *dump_ctrl)
{
	unsigned char ret = PS3_TRUE;

	PS3_IOC_REG_READ_WITH_CHECK(instance, reg_f.Excl_reg, ps3DumpCtrl,
				    *dump_ctrl);
	if (*dump_ctrl == U64_MAX) {
		LOG_INFO("hno:%u  read reg ps3DumpCtrl NOK!\n",
			 PS3_HOST(instance));
		ret = PS3_FALSE;
		goto l_out;
	}
	*dump_ctrl &= 0xff;

l_out:
	return ret;
}

static inline void ps3_dump_ctrl_set(struct ps3_instance *instance, unsigned long long value)
{
	PS3_IOC_REG_WRITE(instance, reg_f.Excl_reg, ps3DumpCtrl, value);
}

static inline void ps3_dump_abort(struct ps3_instance *instance)
{
	struct ps3_dump_context *ctxt = &instance->dump_context;
	unsigned long long dump_ctrl;
	unsigned char ret = PS3_TRUE;

	if (ctxt->dump_state == PS3_DUMP_STATE_ABORTED ||
	    ctxt->dump_state == PS3_DUMP_STATE_INVALID) {
		goto l_ret;
	}

	ret = ps3_dump_ctrl_get(instance, &dump_ctrl);
	if (ret) {
		if (dump_ctrl) {
			LOG_WARN("dump ctrl is not cleared 0x%llx\n",
				 dump_ctrl);
		}
		ps3_dump_ctrl_set(instance, PS3_DUMP_CTRL_DUMP_ABORT);
	} else {
		LOG_INFO("hno:%u read ps3DumpCtrl NOK!\n", PS3_HOST(instance));
	}
	ctxt->dump_state = PS3_DUMP_STATE_ABORTED;
l_ret:
	return;
}

static inline void ps3_dump_end(struct ps3_instance *instance)
{
	unsigned long long dump_ctrl;
	unsigned char ret = PS3_TRUE;

	ret = ps3_dump_ctrl_get(instance, &dump_ctrl);
	if (ret) {
		if (dump_ctrl) {
			LOG_WARN("dump ctrl is not cleared 0x%llx\n",
				 dump_ctrl);
		}
		ps3_dump_ctrl_set(instance, PS3_DUMP_CTRL_DUMP_END);
	} else {
		LOG_INFO("hno:%u read ps3DumpCtrl NOK!\n", PS3_HOST(instance));
	}
}

static inline int ps3_dump_trigger(struct ps3_instance *instance, int dump_type)
{
	unsigned long long dump_ctrl;
	unsigned long long ctrl_val = 0;
	int ret = PS3_SUCCESS;
	unsigned char reg_ret = PS3_TRUE;

	switch (dump_type) {
	case PS3_DUMP_TYPE_CRASH:
		ctrl_val = PS3_DUMP_CTRL_DUMP_CORE_FILE;
		break;
	case PS3_DUMP_TYPE_FW_LOG:
		ctrl_val = PS3_DUMP_CTRL_DUMP_FW_LOG;
		break;
	case PS3_DUMP_TYPE_BAR_DATA:
		ctrl_val = PS3_DUMP_CTRL_DUMP_BAR_DATA;
		break;
	default:
		ret = -PS3_FAILED;
		goto l_ret;
	}

	reg_ret = ps3_dump_ctrl_get(instance, &dump_ctrl);
	if (reg_ret) {
		if (dump_ctrl) {
			LOG_WARN("dump ctrl is not cleared 0x%llx\n",
				 dump_ctrl);
			ret = -PS3_FAILED;
		} else {
			ps3_dump_ctrl_set(instance, ctrl_val);
		}
	} else {
		LOG_INFO("hno:%u read ps3DumpCtrl NOK!\n", PS3_HOST(instance));
		ret = -PS3_FAILED;
	}
l_ret:
	return ret;
}

static inline unsigned char ps3_dump_status_get(struct ps3_instance *instance,
				       unsigned long long *dump_status)
{
	unsigned char ret = PS3_TRUE;

	PS3_IOC_REG_READ_WITH_CHECK(instance, reg_f.Excl_reg, ps3DumpStatus,
				    *dump_status);
	if (*dump_status == U64_MAX) {
		LOG_INFO("hno:%u  read reg ps3DumpStatus NOK!\n",
			 PS3_HOST(instance));
		*dump_status = 0;
		ret = PS3_FALSE;
		goto l_out;
	}

	*dump_status &= 0xff;

l_out:
	return ret;
}

static inline void ps3_dump_status_set(struct ps3_instance *instance, unsigned long long value)
{
	PS3_IOC_REG_WRITE(instance, reg_f.Excl_reg, ps3DumpStatus, value);
}

static inline unsigned char ps3_dump_data_size_get_clear(struct ps3_instance *instance,
						unsigned long long *data_size)
{
	unsigned char ret = PS3_TRUE;

	PS3_IOC_REG_READ_WITH_CHECK(instance, reg_f.Excl_reg, ps3DumpDataSize,
				    *data_size);
	if (*data_size == U64_MAX) {
		LOG_INFO("hno:%u  read reg ps3DumpDataSize NOK!\n",
			 PS3_HOST(instance));
		*data_size = 0;
		ret = PS3_FALSE;
	}

	PS3_IOC_REG_WRITE_WITH_CHECK(instance, reg_f.Excl_reg, ps3DumpDataSize,
				     0);
	return ret;
}

static unsigned char ps3_dump_status_check(unsigned long long status, unsigned char dump_type)
{
	unsigned char ret = PS3_TRUE;

	switch (dump_type) {
	case PS3_DUMP_TYPE_FW_LOG:
		ret = PS3_REG_TEST(status, PS3_DUMP_STATUS_REG_FW_DUMP_MASK);
		break;
	case PS3_DUMP_TYPE_BAR_DATA:
		ret = PS3_REG_TEST(status, PS3_DUMP_STATUS_REG_BAR_DUMP_MASK);
		break;
	case PS3_DUMP_TYPE_CRASH:
		ret = PS3_REG_TEST(status, PS3_DUMP_STATUS_REG_CRASH_DUMP_MASK);
		break;
	default:
		LOG_INFO("invalid type %d\n", dump_type);
		ret = PS3_FALSE;
		goto l_out;
	}

	if (ret == PS3_TRUE)
		ret = PS3_REG_TEST(status, PS3_DUMP_STATUS_REG_DMA_FINISH_MASK);

l_out:
	return ret;
}

static int ps3_dump_dma_data_copy(struct ps3_dump_context *ctxt, unsigned long long status)
{
	unsigned long long dma_size = 0;
	unsigned long long dump_ctrl;
	int ret = PS3_SUCCESS;
	unsigned char reg_ret = PS3_TRUE;

	if (!ps3_dump_data_size_get_clear(ctxt->instance, &dma_size)) {
		ret = -PS3_FAILED;
		goto l_out;
	}

	if (dma_size == 0 || dma_size > PS3_DUMP_DMA_BUF_SIZE) {
		LOG_ERROR("error: invalid data size %llu\n", dma_size);
		ret = -PS3_FAILED;
		goto l_out;
	}
	ctxt->dump_data_size += dma_size;

	ret = ps3_dump_file_write(&ctxt->dump_out_file, ctxt->dump_dma_buf,
				  dma_size);
	if (ret < 0 || ret != (int)dma_size) {
		LOG_WARN("error: write data failure ret %d, dma_size %llu\n",
			 ret, dma_size);
		ret = -PS3_FAILED;
		goto l_out;
	}
	ctxt->copyed_data_size += ret;

	PS3_REG_CLR(status, PS3_DUMP_STATUS_REG_DMA_FINISH_MASK);
	ps3_dump_status_set(ctxt->instance, status);

	reg_ret = ps3_dump_ctrl_get(ctxt->instance, &dump_ctrl);
	if (reg_ret) {
		if (dump_ctrl) {
			LOG_WARN("dump ctrl is not cleared 0x%llx\n",
				 dump_ctrl);
		}
		ps3_dump_ctrl_set(ctxt->instance, PS3_DUMP_CTRL_COPY_FINISH);
		ret = PS3_SUCCESS;
	} else {
		LOG_INFO("hno:%u read ps3DumpCtrl NOK!\n",
			 PS3_HOST(ctxt->instance));
		ret = -PS3_FAILED;
	}

l_out:
	return ret;
}

static inline void ps3_dump_work_done(struct ps3_dump_context *ctxt,
				      int cur_state)
{
	ctxt->dump_work_status = PS3_DUMP_WORK_STOP;
	ps3_dump_file_close(&ctxt->dump_out_file);
	cur_state = ctxt->dump_state;
	ctxt->dump_state = PS3_DUMP_STATE_INVALID;
	if (cur_state == PS3_DUMP_STATE_COPY_DONE) {
		LOG_INFO("end dump in COPY_DONE STATE\n");
		ps3_dump_end(ctxt->instance);
	}
}

static void ps3_dump_work(struct work_struct *work)
{
	unsigned int work_wait_times = 0;
	struct ps3_dump_context *ctxt =
		ps3_container_of(work, struct ps3_dump_context, dump_work.work);
	unsigned long long status = 0, delay_ms = 0;
	int cur_state = 0;
	unsigned char ret = PS3_TRUE;

	ctxt->dump_work_status = PS3_DUMP_WORK_RUNNING;
	ret = ps3_dump_status_get(ctxt->instance, &status);
	if (!ret) {
		delay_ms = PS3_REG_READ_INTERVAL_MS;
		LOG_INFO("ps3_dump_status_get error, delay %llums try again\n",
			 delay_ms);
		queue_delayed_work(ctxt->dump_work_queue, &ctxt->dump_work,
				   msecs_to_jiffies(delay_ms));
		goto l_out;
	}


	while (delay_ms == 0) {
		if (ctxt->is_hard_recovered) {
			LOG_WARN("dump in hard recovery, ready to abort\n");
			ctxt->dump_state = PS3_DUMP_STATE_PRE_ABORT;
		}

		switch (ctxt->dump_state) {
		case PS3_DUMP_STATE_START:
			if ((status & PS3_DUMP_STATUS_REG_INVALID_BITS_MASK) ==
				    0 ||
			    (status & PS3_DUMP_STATUS_REG_ABORT_MASK) != 0) {
				LOG_INFO(
					"abort dump in START STATE, status: 0x%llx\n",
					status);
				ctxt->dump_state = PS3_DUMP_STATE_PRE_ABORT;
				continue;
			}

			if ((status & PS3_DUMP_STATUS_REG_MASK) == 0 ||
			    ps3_dump_status_check(status, ctxt->dump_type) ==
				    PS3_FALSE) {
				delay_ms = WAIT_DUMP_COLLECT;
				work_wait_times++;
				break;
			}

			if (ctxt->dump_out_file.file_status !=
			    PS3_DUMP_FILE_OPEN) {
				if (ps3_dump_file_open(ctxt,
						       (unsigned int)ctxt->dump_type) !=
				    PS3_SUCCESS) {
					delay_ms = WAIT_DUMP_COLLECT;
					work_wait_times++;
					break;
				}
			}
			work_wait_times = 0;
			ctxt->dump_state = PS3_DUMP_STATE_COPYING;
			break;
		case PS3_DUMP_STATE_COPYING:
			if (status & PS3_DUMP_STATUS_REG_ABORT_MASK) {
				LOG_INFO("abort dump in COPYING STATE\n");
				ctxt->dump_state = PS3_DUMP_STATE_PRE_ABORT;
				continue;
			}

			if ((status & PS3_DUMP_STATUS_REG_MASK) == 0) {
				ctxt->dump_state = PS3_DUMP_STATE_COPY_DONE;
				ctxt->dump_work_status = PS3_DUMP_WORK_DONE;
				break;
			}
			if (ps3_dump_status_check(status, ctxt->dump_type) ==
			    PS3_FALSE) {
				delay_ms = WAIT_DUMP_COLLECT;
				work_wait_times++;
				break;
			}
			if (ps3_dump_dma_data_copy(ctxt, status) !=
			    PS3_SUCCESS) {
				LOG_INFO("abort dump in COPYING STATE\n");
				ctxt->dump_state = PS3_DUMP_STATE_PRE_ABORT;
				continue;
			}

			delay_ms = WAIT_DUMP_DMA_DONE;
			work_wait_times = 0;
			break;
		case PS3_DUMP_STATE_PRE_ABORT:
			ps3_dump_abort(ctxt->instance);
#if defined(PS3_FALLTHROUGH)
			ps3_dump_work_done(ctxt, cur_state);
			work_wait_times = 0;
			goto l_out;
#endif
		case PS3_DUMP_STATE_ABORTED:
		case PS3_DUMP_STATE_COPY_DONE:
			ps3_dump_work_done(ctxt, cur_state);
			work_wait_times = 0;
			goto l_out;
		default:
			LOG_INFO("warn: dump work state %d\n",
				 ctxt->dump_state);
			ctxt->dump_state = PS3_DUMP_STATE_PRE_ABORT;
			continue;
		}
		if (delay_ms) {
			if (work_wait_times >=
			    max_t(unsigned int, WAIT_DUMP_TIMES_MIN, ctxt->dump_dma_wait_times)) {
				LOG_INFO(
					"error: wait too many times %d for dump %s, abort it\n",
					work_wait_times,
					ps3_dump_type_to_name(ctxt->dump_type));
				ctxt->dump_state = PS3_DUMP_STATE_PRE_ABORT;
				work_wait_times = 0;
				delay_ms = 0;
				continue;
			}

			queue_delayed_work(ctxt->dump_work_queue,
					   &ctxt->dump_work,
					   msecs_to_jiffies(delay_ms));
			break;
		}
	}

l_out:
	return;
}

int ps3_dump_dma_buf_alloc(struct ps3_instance *instance)
{
	int ret = PS3_SUCCESS;
	struct ps3_dump_context *ctxt = &instance->dump_context;

	ctxt->dump_dma_buf = (unsigned char *)ps3_dma_alloc_coherent(
		instance, PS3_DUMP_DMA_BUF_SIZE, (unsigned long long *)&ctxt->dump_dma_addr);
	if (ctxt->dump_dma_buf == NULL) {
		LOG_ERROR("host_no[%d], dump dma alloc NOK!\n",
			  PS3_HOST(instance));
		ret = -PS3_FAILED;
	}

	return ret;
}

void ps3_dump_dma_buf_free(struct ps3_instance *instance)
{
	struct ps3_dump_context *ctxt = &instance->dump_context;

	if (ctxt->dump_dma_buf != NULL) {
		ps3_dma_free_coherent(instance, PS3_DUMP_DMA_BUF_SIZE,
				      ctxt->dump_dma_buf, ctxt->dump_dma_addr);
		ctxt->dump_dma_buf = NULL;
	}
}

static void ps3_dump_reset(struct ps3_dump_context *ctxt)
{
	ctxt->dump_data_size = 0;
	ctxt->copyed_data_size = 0;
	ctxt->dump_type = PS3_DUMP_TYPE_UNKNOWN;
	ctxt->dump_state = PS3_DUMP_STATE_INVALID;
	memset(&ctxt->dump_out_file, 0, sizeof(ctxt->dump_out_file));
}

int ps3_dump_type_set(struct ps3_dump_context *ctxt, int type, unsigned int env)
{
	int ret = PS3_SUCCESS;
	int cur_state = PS3_INSTANCE_STATE_INIT;

	LOG_INFO("dump type set: type %d\n", type);

	if ((type < PS3_DUMP_TYPE_CRASH) || (type > PS3_DUMP_TYPE_BAR_DATA)) {
		ret = -PS3_FAILED;
		goto l_ret;
	}

	if (ctxt->dump_work_queue == NULL) {
		LOG_WARN("dump type set: no work to do, type %d\n", type);
		ret = -PS3_FAILED;
		goto l_ret;
	}

	ps3_mutex_lock(&ctxt->dump_lock);
	if (ctxt->dump_state != PS3_DUMP_STATE_INVALID) {
		LOG_FILE_ERROR(
			"dump type set: work is busy, current state: %d, type %d\n",
			ctxt->dump_state, type);
		ret = -PS3_FAILED;
		goto l_unlock;
	}

	ps3_dump_reset(ctxt);


	ctxt->is_hard_recovered = PS3_FALSE;


	cur_state = ps3_atomic_read(&ctxt->instance->state_machine.state);
	if (!ps3_state_is_normal(cur_state)) {
		LOG_WARN("h_no[%u], instance state is unnormal[%s]\n",
			 PS3_HOST(ctxt->instance),
			 namePS3InstanceState(cur_state));
		ret = -PS3_FAILED;
		goto l_unlock;
	}

	ctxt->dump_state = PS3_DUMP_STATE_START;
	ctxt->dump_type = type;
	ctxt->dump_env = env;
	ctxt->dump_type_times++;


	ret = ps3_dump_trigger(ctxt->instance, type);
	if (ret != PS3_SUCCESS) {
		ps3_dump_reset(ctxt);
		goto l_unlock;
	}

	queue_delayed_work(ctxt->dump_work_queue, &ctxt->dump_work, 0);
l_unlock:
	ps3_mutex_unlock(&ctxt->dump_lock);
l_ret:
	return ret;
}

int ps3_dump_state_set(struct ps3_dump_context *ctxt, int state)
{
	int ret = PS3_SUCCESS;
	int cur_state;

	LOG_INFO("dump state set: state %d\n", state);

	if (state != PS3_DUMP_STATE_INVALID) {
		ret = -PS3_FAILED;
		goto l_ret;
	}

	ps3_mutex_lock(&ctxt->dump_lock);
	cur_state = ctxt->dump_state;
	if (cur_state == PS3_DUMP_STATE_INVALID)
		goto l_unlock;

	cancel_delayed_work_sync(&ctxt->dump_work);
	ctxt->dump_work_status = PS3_DUMP_WORK_CANCEL;
	ctxt->dump_state_times++;

	if (cur_state == PS3_DUMP_STATE_PRE_ABORT ||
	    cur_state == PS3_DUMP_STATE_START ||
	    cur_state == PS3_DUMP_STATE_COPYING) {
		ps3_dump_abort(ctxt->instance);
	}

	ps3_dump_file_close(&ctxt->dump_out_file);

	ps3_dump_reset(ctxt);
	if (cur_state == PS3_DUMP_STATE_COPY_DONE)
		ps3_dump_end(ctxt->instance);
l_unlock:
	ps3_mutex_unlock(&ctxt->dump_lock);
l_ret:
	return ret;
}

void ps3_dump_detect(struct ps3_instance *instance)
{
	struct ps3_dump_context *p_dump_ctx = &instance->dump_context;
	int ret = PS3_SUCCESS;
	int dump_type = 0;
	unsigned long long status = 0;
	union HilReg0Ps3RegisterFPs3DumpStatus dump_status = { 0 };
	unsigned char is_trigger_log;

	if (!ps3_dump_status_get(instance, &status))
		goto l_out;
	dump_status.val = status;

	dump_type = dump_status.reg.hasAutoDump;
	if (dump_type == 0)
		goto l_out;

	ps3_ioc_dump_support_get(instance);

	if (!PS3_IOC_DUMP_SUPPORT(instance))
		goto l_out;

	LOG_DEBUG("hno:%u  detect dump log file type[%d], status[%llx]\n",
		  PS3_HOST(instance), dump_type, status);

	is_trigger_log = ps3_dump_is_trigger_log(instance);
	if (!is_trigger_log) {
		LOG_DEBUG("cannot dump type set!\n");
		goto l_out;
	}

	ret = ps3_dump_type_set(p_dump_ctx, dump_type, PS3_DUMP_ENV_NOTIFY);
	LOG_DEBUG("hno:%u  type[%d] autodump set trigger ret %d\n",
		  PS3_HOST(instance), dump_type, ret);
	if (ret == PS3_SUCCESS)
		goto l_out;

l_out:
	return;
}

static void ps3_dump_irq_handler_work(struct work_struct *work)
{
	struct ps3_dump_context *ctxt = ps3_container_of(
		work, struct ps3_dump_context, dump_irq_handler_work);

	ctxt->dump_irq_handler_work_status = PS3_DUMP_IRQ_HANDLER_WORK_RUNNING;
	ps3_dump_detect(ctxt->instance);
	ctxt->dump_irq_handler_work_status = PS3_DUMP_IRQ_HANDLER_WORK_DONE;
}

irqreturn_t ps3_dump_irq_handler(int virq, void *dev_id)
{
	struct ps3_instance *pInstance = (struct ps3_instance *)dev_id;
	struct ps3_dump_context *p_dump_ctx = &pInstance->dump_context;
	unsigned long flags = 0;

	spin_lock_irqsave(&p_dump_ctx->dump_irq_handler_lock, flags);
	if (p_dump_ctx->dump_enabled) {

		LOG_DEBUG(
			"hno:%u  dump irq received, virq: %d, dev_id: 0x%llx\n",
			PS3_HOST(pInstance), virq, (unsigned long long)(uintptr_t)dev_id);

		if (!work_busy(&p_dump_ctx->dump_irq_handler_work)) {
			queue_work(p_dump_ctx->dump_irq_handler_work_queue,
				   &p_dump_ctx->dump_irq_handler_work);
		}
	}

	spin_unlock_irqrestore(&p_dump_ctx->dump_irq_handler_lock, flags);

	return IRQ_HANDLED;
}

static void ps3_dump_dir_init(char *dump_dir)
{
	char *log_path_p;
	unsigned int log_path_len = 0;

	log_path_p = ps3_log_path_query();
	if (log_path_p != NULL)
		log_path_len = strlen(log_path_p);

	if (log_path_p != NULL && log_path_p[0] == '/') {
		if (log_path_p[log_path_len - 1] == '/') {
			snprintf(dump_dir, PS3_DUMP_FILE_DIR_LEN, "%s",
				 log_path_p);
		} else {
			snprintf(dump_dir, PS3_DUMP_FILE_DIR_LEN, "%s/",
				 log_path_p);
		}
	} else {
		LOG_INFO("provided log dump dir not valid, using default\n");
		snprintf(dump_dir, PS3_DUMP_FILE_DIR_LEN, "%s/",
			 PS3_DUMP_FILE_DIR);
	}
}

int ps3_dump_init(struct ps3_instance *instance)
{
	int ret = PS3_SUCCESS;
	struct ps3_dump_context *ctxt = &instance->dump_context;

	if (reset_devices) {
		LOG_INFO(
			"resetting device in progress, Do not initialize dump\n");
		goto l_ret;
	}

	if (ctxt->dump_dma_buf != NULL) {
		LOG_INFO("hno:%u init already\n", PS3_HOST(instance));
		goto l_ret;
	}
	memset((void *)ctxt, 0, sizeof(struct ps3_dump_context));

	if (!ps3_ioc_dump_support_get(instance))
		goto l_ret;

	ps3_dump_dir_init((char *)ctxt->dump_dir);

	ctxt->instance = instance;
	ctxt->dump_type = PS3_DUMP_TYPE_UNKNOWN;
	ctxt->dump_state = PS3_DUMP_STATE_INVALID;
	ctxt->dump_dma_wait_times = WAIT_DUMP_TIMES_DEFAULT;
	if (ps3_dump_dma_buf_alloc(instance) != PS3_SUCCESS) {
		ret = -PS3_FAILED;
		goto l_failed;
	}

	INIT_DELAYED_WORK(&ctxt->dump_work, ps3_dump_work);
	ctxt->dump_work_queue =
		create_singlethread_workqueue((char *)"ps3_dump_work_queue");
	if (ctxt->dump_work_queue == NULL) {
		LOG_ERROR("dump work queue create NOK\n");
		ret = -PS3_FAILED;
		goto l_failed;
	}

	INIT_WORK(&ctxt->dump_irq_handler_work, ps3_dump_irq_handler_work);
	ctxt->dump_irq_handler_work_queue = create_singlethread_workqueue(
		(char *)"ps3_dump_irq_handler_work_queue");
	if (ctxt->dump_irq_handler_work_queue == NULL) {
		LOG_ERROR("dump irq handler work queue create NOK\n");
		ret = -PS3_FAILED;
		goto l_failed;
	}
	ps3_mutex_init(&ctxt->dump_lock);

	spin_lock_init(&ctxt->dump_irq_handler_lock);
	ctxt->dump_enabled = 1;
	goto l_ret;
l_failed:
	ps3_dump_exit(instance);
l_ret:
	return ret;
}

void ps3_dump_exit(struct ps3_instance *instance)
{
	struct ps3_dump_context *ctxt = &instance->dump_context;
	unsigned long flags = 0;

	if (ctxt->dump_dma_buf == NULL)
		return;

	spin_lock_irqsave(&ctxt->dump_irq_handler_lock, flags);
	ctxt->dump_enabled = 0;
	spin_unlock_irqrestore(&ctxt->dump_irq_handler_lock, flags);

	if (ctxt->dump_irq_handler_work_queue != NULL) {
		if (!cancel_work_sync(&ctxt->dump_irq_handler_work)) {
			flush_workqueue(ctxt->dump_irq_handler_work_queue);
		} else {
			ctxt->dump_irq_handler_work_status =
				PS3_DUMP_IRQ_HANDLER_WORK_CANCEL;
		}
		destroy_workqueue(ctxt->dump_irq_handler_work_queue);
		ctxt->dump_irq_handler_work_queue = NULL;
	}

	if (ctxt->dump_work_queue != NULL) {
		if (!cancel_delayed_work_sync(&ctxt->dump_work))
			flush_workqueue(ctxt->dump_work_queue);
		else
			ctxt->dump_work_status = PS3_DUMP_WORK_CANCEL;
		destroy_workqueue(ctxt->dump_work_queue);
		ctxt->dump_work_queue = NULL;
	}

	ctxt->dump_state = PS3_DUMP_STATE_INVALID;
	ps3_dump_file_close(&ctxt->dump_out_file);

	ps3_mutex_destroy(&ctxt->dump_lock);
	LOG_INFO("hno:%u  dump destroy work and stop service\n",
		 PS3_HOST(instance));
}

void ps3_dump_work_stop(struct ps3_instance *instance)
{
	struct ps3_dump_context *ctxt = &instance->dump_context;
	unsigned long flags = 0;

	spin_lock_irqsave(&ctxt->dump_irq_handler_lock, flags);
	if (ctxt->dump_enabled == 0) {
		spin_unlock_irqrestore(&ctxt->dump_irq_handler_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&ctxt->dump_irq_handler_lock, flags);

	if (ctxt->dump_irq_handler_work_queue != NULL) {
		if (!cancel_work_sync(&ctxt->dump_irq_handler_work)) {
			flush_workqueue(ctxt->dump_irq_handler_work_queue);
		} else {
			ctxt->dump_irq_handler_work_status =
				PS3_DUMP_IRQ_HANDLER_WORK_CANCEL;
		}
	}

	if (ctxt->dump_work_queue != NULL) {
		ps3_dump_state_set(ctxt, PS3_DUMP_STATE_INVALID);
		if (!cancel_delayed_work_sync(&ctxt->dump_work))
			flush_workqueue(ctxt->dump_work_queue);
		else
			ctxt->dump_work_status = PS3_DUMP_WORK_CANCEL;
	}
}
void ps3_dump_ctrl_set_int_ready(struct ps3_instance *instance)
{
	if (reset_devices) {
		LOG_INFO(
			"resetting device in progress, unable to confiure ps3DumpCtrl\n");
		return;
	}
	PS3_IOC_REG_WRITE(instance, reg_f.Excl_reg, ps3DumpCtrl,
			  PS3_DUMP_CTRL_DUMP_INT_READY);
}

unsigned char ps3_dump_is_trigger_log(struct ps3_instance *instance)
{
	unsigned char is_support_halt = PS3_IOC_STATE_HALT_SUPPORT(instance);
	unsigned long long dump_ctrl;
	unsigned char is_trigger_log = PS3_FALSE;
	int cur_state = ps3_atomic_read(&instance->state_machine.state);
	unsigned char is_halt =
		(is_support_halt && (cur_state == PS3_INSTANCE_STATE_DEAD));
	unsigned char ret = PS3_TRUE;

	if (likely(is_halt || (cur_state == PS3_INSTANCE_STATE_OPERATIONAL &&
			       !ps3_pci_err_recovery_get(instance)))) {
		is_trigger_log = PS3_TRUE;
	}

	if (instance->is_support_dump_ctrl) {
		ret = ps3_dump_ctrl_get(instance, &dump_ctrl);
		if (ret) {
			if (dump_ctrl != 0)
				is_trigger_log = PS3_FALSE;
		} else {
			LOG_INFO("hno:%u read ps3DumpCtrl NOK!\n",
				 PS3_HOST(instance));
			is_trigger_log = PS3_FALSE;
		}
	}

	return is_trigger_log;
}
