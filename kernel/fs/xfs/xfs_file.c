// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_inode_item.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_ioctl.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_icache.h"
#include "xfs_pnfs.h"
#include "xfs_iomap.h"
#include "xfs_reflink.h"

#include <linux/falloc.h>
#include <linux/backing-dev.h>
#include <linux/mman.h>
#include <linux/fadvise.h>
#include <trace/events/fs.h>

static const struct vm_operations_struct xfs_file_vm_ops;

/*
 * Decide if the given file range is aligned to the size of the fundamental
 * allocation unit for the file.
 */
static bool
xfs_is_falloc_aligned(
	struct xfs_inode	*ip,
	loff_t			pos,
	long long int		len)
{
	struct xfs_mount	*mp = ip->i_mount;
	uint64_t		mask;

	if (XFS_IS_REALTIME_INODE(ip)) {
		if (!is_power_of_2(mp->m_sb.sb_rextsize)) {
			u64	rextbytes;
			u32	mod;

			rextbytes = XFS_FSB_TO_B(mp, mp->m_sb.sb_rextsize);
			div_u64_rem(pos, rextbytes, &mod);
			if (mod)
				return false;
			div_u64_rem(len, rextbytes, &mod);
			return mod == 0;
		}
		mask = XFS_FSB_TO_B(mp, mp->m_sb.sb_rextsize) - 1;
	} else {
		if (xfs_inode_forcealign(ip) && ip->i_d.di_extsize > 1)
			mask = (mp->m_sb.sb_blocksize * ip->i_d.di_extsize) - 1;
		else
			mask = mp->m_sb.sb_blocksize - 1;
	}

	return !((pos | len) & mask);
}

int
xfs_update_prealloc_flags(
	struct xfs_inode	*ip,
	enum xfs_prealloc_flags	flags)
{
	struct xfs_trans	*tp;
	int			error;

	error = xfs_trans_alloc(ip->i_mount, &M_RES(ip->i_mount)->tr_writeid,
			0, 0, 0, &tp);
	if (error)
		return error;

	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	if (!(flags & XFS_PREALLOC_INVISIBLE)) {
		VFS_I(ip)->i_mode &= ~S_ISUID;
		if (VFS_I(ip)->i_mode & S_IXGRP)
			VFS_I(ip)->i_mode &= ~S_ISGID;
		xfs_trans_ichgtime(tp, ip, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	}

	if (flags & XFS_PREALLOC_SET)
		ip->i_d.di_flags |= XFS_DIFLAG_PREALLOC;
	if (flags & XFS_PREALLOC_CLEAR)
		ip->i_d.di_flags &= ~XFS_DIFLAG_PREALLOC;

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	return xfs_trans_commit(tp);
}

/*
 * Fsync operations on directories are much simpler than on regular files,
 * as there is no file data to flush, and thus also no need for explicit
 * cache flush operations, and there are no non-transaction metadata updates
 * on directories either.
 */
STATIC int
xfs_dir_fsync(
	struct file		*file,
	loff_t			start,
	loff_t			end,
	int			datasync)
{
	struct xfs_inode	*ip = XFS_I(file->f_mapping->host);

	trace_xfs_dir_fsync(ip);
	return xfs_log_force_inode(ip);
}

static xfs_csn_t
xfs_fsync_seq(
	struct xfs_inode	*ip,
	bool			datasync)
{
	if (!xfs_ipincount(ip))
		return 0;
	if (datasync && !(ip->i_itemp->ili_fsync_fields & ~XFS_ILOG_TIMESTAMP))
		return 0;
	return ip->i_itemp->ili_commit_seq;
}

/*
 * All metadata updates are logged, which means that we just have to flush the
 * log up to the latest LSN that touched the inode.
 *
 * If we have concurrent fsync/fdatasync() calls, we need them to all block on
 * the log force before we clear the ili_fsync_fields field. This ensures that
 * we don't get a racing sync operation that does not wait for the metadata to
 * hit the journal before returning.  If we race with clearing ili_fsync_fields,
 * then all that will happen is the log force will do nothing as the lsn will
 * already be on disk.  We can't race with setting ili_fsync_fields because that
 * is done under XFS_ILOCK_EXCL, and that can't happen because we hold the lock
 * shared until after the ili_fsync_fields is cleared.
 */
static  int
xfs_fsync_flush_log(
	struct xfs_inode	*ip,
	bool			datasync,
	int			*log_flushed)
{
	int			error = 0;
	xfs_csn_t		seq;

	xfs_ilock(ip, XFS_ILOCK_SHARED);
	seq = xfs_fsync_seq(ip, datasync);
	if (seq) {
		error = xfs_log_force_seq(ip->i_mount, seq, XFS_LOG_SYNC,
					  log_flushed);

		spin_lock(&ip->i_itemp->ili_lock);
		ip->i_itemp->ili_fsync_fields = 0;
		spin_unlock(&ip->i_itemp->ili_lock);
	}
	xfs_iunlock(ip, XFS_ILOCK_SHARED);
	return error;
}

STATIC int
xfs_file_fsync(
	struct file		*file,
	loff_t			start,
	loff_t			end,
	int			datasync)
{
	struct xfs_inode	*ip = XFS_I(file->f_mapping->host);
	struct xfs_mount	*mp = ip->i_mount;
	int			error, err2;
	int			log_flushed = 0;

	trace_xfs_file_fsync(ip);

	error = file_write_and_wait_range(file, start, end);
	if (error)
		return error;

	if (xfs_is_shutdown(mp))
		return -EIO;

	xfs_iflags_clear(ip, XFS_ITRUNCATED);

	/*
	 * If we have an RT and/or log subvolume we need to make sure to flush
	 * the write cache the device used for file data first.  This is to
	 * ensure newly written file data make it to disk before logging the new
	 * inode size in case of an extending write.
	 */
	if (XFS_IS_REALTIME_INODE(ip))
		error = blkdev_issue_flush(mp->m_rtdev_targp->bt_bdev, GFP_NOFS);
	else if (mp->m_logdev_targp != mp->m_ddev_targp)
		error = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev, GFP_NOFS);

	/*
	 * Any inode that has dirty modifications in the log is pinned.  The
	 * racy check here for a pinned inode will not catch modifications
	 * that happen concurrently to the fsync call, but fsync semantics
	 * only require to sync previously completed I/O.
	 */
	if (xfs_ipincount(ip)) {
		err2 = xfs_fsync_flush_log(ip, datasync, &log_flushed);
		if (err2 && !error)
			error = err2;
	}

	/*
	 * If we only have a single device, and the log force about was
	 * a no-op we might have to flush the data device cache here.
	 * This can only happen for fdatasync/O_DSYNC if we were overwriting
	 * an already allocated file and thus do not have any metadata to
	 * commit.
	 */
	if (!log_flushed && !XFS_IS_REALTIME_INODE(ip) &&
	    mp->m_logdev_targp == mp->m_ddev_targp) {
		err2 = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev, GFP_NOFS);
		if (err2 && !error)
			error = err2;
	}
	return error;
}

static int
xfs_ilock_iocb(
	struct kiocb		*iocb,
	unsigned int		lock_mode)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!xfs_ilock_nowait(ip, lock_mode))
			return -EAGAIN;
	} else {
		xfs_ilock(ip, lock_mode);
	}

	return 0;
}

STATIC ssize_t
xfs_file_dio_aio_read(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));
	size_t			count = iov_iter_count(to);
	ssize_t			ret;

	trace_xfs_file_direct_read(ip, count, iocb->ki_pos);

	if (!count)
		return 0; /* skip atime */

	file_accessed(iocb->ki_filp);

	ret = xfs_ilock_iocb(iocb, XFS_IOLOCK_SHARED);
	if (ret)
		return ret;
	ret = iomap_dio_rw(iocb, to, &xfs_read_iomap_ops, NULL, 0);
	xfs_iunlock(ip, XFS_IOLOCK_SHARED);

	return ret;
}

static noinline ssize_t
xfs_file_dax_read(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct xfs_inode	*ip = XFS_I(iocb->ki_filp->f_mapping->host);
	size_t			count = iov_iter_count(to);
	ssize_t			ret = 0;

	trace_xfs_file_dax_read(ip, count, iocb->ki_pos);

	if (!count)
		return 0; /* skip atime */

	ret = xfs_ilock_iocb(iocb, XFS_IOLOCK_SHARED);
	if (ret)
		return ret;
	ret = dax_iomap_rw(iocb, to, &xfs_read_iomap_ops);
	xfs_iunlock(ip, XFS_IOLOCK_SHARED);

	file_accessed(iocb->ki_filp);
	return ret;
}

STATIC ssize_t
xfs_file_buffered_aio_read(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));
	ssize_t			ret;

	trace_xfs_file_buffered_read(ip, iov_iter_count(to), iocb->ki_pos);
	fs_file_read_do_trace(iocb);

	ret = xfs_ilock_iocb(iocb, XFS_IOLOCK_SHARED);
	if (ret)
		return ret;
	ret = generic_file_read_iter(iocb, to);
	xfs_iunlock(ip, XFS_IOLOCK_SHARED);

	return ret;
}

STATIC ssize_t
xfs_file_read_iter(
	struct kiocb		*iocb,
	struct iov_iter		*to)
{
	struct inode		*inode = file_inode(iocb->ki_filp);
	struct xfs_mount	*mp = XFS_I(inode)->i_mount;
	ssize_t			ret = 0;

	XFS_STATS_INC(mp, xs_read_calls);

	if (xfs_is_shutdown(mp))
		return -EIO;

	if (IS_DAX(inode))
		ret = xfs_file_dax_read(iocb, to);
	else if (iocb->ki_flags & IOCB_DIRECT)
		ret = xfs_file_dio_aio_read(iocb, to);
	else
		ret = xfs_file_buffered_aio_read(iocb, to);

	if (ret > 0)
		XFS_STATS_ADD(mp, xs_read_bytes, ret);
	return ret;
}

/*
 * Common pre-write limit and setup checks.
 *
 * Called with the iolocked held either shared and exclusive according to
 * @iolock, and returns with it held.  Might upgrade the iolock to exclusive
 * if called for a direct write beyond i_size.
 */
STATIC ssize_t
xfs_file_aio_write_checks(
	struct kiocb		*iocb,
	struct iov_iter		*from,
	int			*iolock)
{
	struct file		*file = iocb->ki_filp;
	struct inode		*inode = file->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			error = 0;
	size_t			count = iov_iter_count(from);
	bool			drained_dio = false;
	loff_t			isize;

restart:
	error = generic_write_checks(iocb, from);
	if (error <= 0)
		return error;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		error = break_layout(inode, false);
		if (error == -EWOULDBLOCK)
			error = -EAGAIN;
	} else {
		error = xfs_break_layouts(inode, iolock, BREAK_WRITE);
	}

	if (error)
		return error;

	/*
	 * For changing security info in file_remove_privs() we need i_rwsem
	 * exclusively.
	 */
	if (*iolock == XFS_IOLOCK_SHARED && !IS_NOSEC(inode)) {
		xfs_iunlock(ip, *iolock);
		*iolock = XFS_IOLOCK_EXCL;
		error = xfs_ilock_iocb(iocb, *iolock);
		if (error) {
			*iolock = 0;
			return error;
		}
		goto restart;
	}

	/*
	 * If the offset is beyond the size of the file, we need to zero any
	 * blocks that fall between the existing EOF and the start of this
	 * write.  If zeroing is needed and we are currently holding the iolock
	 * shared, we need to update it to exclusive which implies having to
	 * redo all checks before.
	 *
	 * We need to serialise against EOF updates that occur in IO completions
	 * here. We want to make sure that nobody is changing the size while we
	 * do this check until we have placed an IO barrier (i.e.  hold the
	 * XFS_IOLOCK_EXCL) that prevents new IO from being dispatched.  The
	 * spinlock effectively forms a memory barrier once we have the
	 * XFS_IOLOCK_EXCL so we are guaranteed to see the latest EOF value and
	 * hence be able to correctly determine if we need to run zeroing.
	 *
	 * We can do an unlocked check here safely as IO completion can only
	 * extend EOF. Truncate is locked out at this point, so the EOF can
	 * not move backwards, only forwards. Hence we only need to take the
	 * slow path and spin locks when we are at or beyond the current EOF.
	 */
	if (iocb->ki_pos <= i_size_read(inode))
		goto out;

	spin_lock(&ip->i_flags_lock);
	isize = i_size_read(inode);
	if (iocb->ki_pos > isize) {
		spin_unlock(&ip->i_flags_lock);

		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;

		if (!drained_dio) {
			if (*iolock == XFS_IOLOCK_SHARED) {
				xfs_iunlock(ip, *iolock);
				*iolock = XFS_IOLOCK_EXCL;
				xfs_ilock(ip, *iolock);
				iov_iter_reexpand(from, count);
			}
			/*
			 * We now have an IO submission barrier in place, but
			 * AIO can do EOF updates during IO completion and hence
			 * we now need to wait for all of them to drain. Non-AIO
			 * DIO will have drained before we are given the
			 * XFS_IOLOCK_EXCL, and so for most cases this wait is a
			 * no-op.
			 */
			inode_dio_wait(inode);
			drained_dio = true;
			goto restart;
		}

		trace_xfs_zero_eof(ip, isize, iocb->ki_pos - isize);
		error = iomap_zero_range(inode, isize, iocb->ki_pos - isize,
				NULL, &xfs_buffered_write_iomap_ops);
		if (error)
			return error;
	} else
		spin_unlock(&ip->i_flags_lock);

out:
	return file_modified(file);
}

static int
xfs_dio_write_end_io(
	struct kiocb		*iocb,
	ssize_t			size,
	int			error,
	unsigned		flags)
{
	struct inode		*inode = file_inode(iocb->ki_filp);
	struct xfs_inode	*ip = XFS_I(inode);
	loff_t			offset = iocb->ki_pos;
	unsigned int		nofs_flag;

	trace_xfs_end_io_direct_write(ip, offset, size);

	if (xfs_is_shutdown(ip->i_mount))
		return -EIO;

	if (error)
		return error;
	if (!size)
		return 0;

	/*
	 * Capture amount written on completion as we can't reliably account
	 * for it on submission.
	 */
	XFS_STATS_ADD(ip->i_mount, xs_write_bytes, size);

	/*
	 * We can allocate memory here while doing writeback on behalf of
	 * memory reclaim.  To avoid memory allocation deadlocks set the
	 * task-wide nofs context for the following operations.
	 */
	nofs_flag = memalloc_nofs_save();

	if (flags & IOMAP_DIO_COW) {
		error = xfs_reflink_end_cow(ip, offset, size);
		if (error)
			goto out;
	}

	/*
	 * Unwritten conversion updates the in-core isize after extent
	 * conversion but before updating the on-disk size. Updating isize any
	 * earlier allows a racing dio read to find unwritten extents before
	 * they are converted.
	 */
	if (flags & IOMAP_DIO_UNWRITTEN) {
		error = xfs_iomap_write_unwritten(ip, offset, size, true);
		goto out;
	}

	/*
	 * We need to update the in-core inode size here so that we don't end up
	 * with the on-disk inode size being outside the in-core inode size. We
	 * have no other method of updating EOF for AIO, so always do it here
	 * if necessary.
	 *
	 * We need to lock the test/set EOF update as we can be racing with
	 * other IO completions here to update the EOF. Failing to serialise
	 * here can result in EOF moving backwards and Bad Things Happen when
	 * that occurs.
	 *
	 * As IO completion only ever extends EOF, we can do an unlocked check
	 * here to avoid taking the spinlock. If we land within the current EOF,
	 * then we do not need to do an extending update at all, and we don't
	 * need to take the lock to check this. If we race with an update moving
	 * EOF, then we'll either still be beyond EOF and need to take the lock,
	 * or we'll be within EOF and we don't need to take it at all.
	 */
	if (offset + size <= i_size_read(inode))
		goto out;

	spin_lock(&ip->i_flags_lock);
	if (offset + size > i_size_read(inode)) {
		i_size_write(inode, offset + size);
		spin_unlock(&ip->i_flags_lock);
		error = xfs_setfilesize(ip, offset, size);
	} else {
		spin_unlock(&ip->i_flags_lock);
	}

out:
	memalloc_nofs_restore(nofs_flag);
	return error;
}

static const struct iomap_dio_ops xfs_dio_write_ops = {
	.end_io		= xfs_dio_write_end_io,
};

/*
 * xfs_file_dio_aio_write - handle direct IO writes
 *
 * Lock the inode appropriately to prepare for and issue a direct IO write.
 * By separating it from the buffered write path we remove all the tricky to
 * follow locking changes and looping.
 *
 * If there are cached pages or we're extending the file, we need IOLOCK_EXCL
 * until we're sure the bytes at the new EOF have been zeroed and/or the cached
 * pages are flushed out.
 *
 * In most cases the direct IO writes will be done holding IOLOCK_SHARED
 * allowing them to be done in parallel with reads and other direct IO writes.
 * However, if the IO is not aligned to filesystem blocks, the direct IO layer
 * needs to do sub-block zeroing and that requires serialisation against other
 * direct IOs to the same block. In this case we need to serialise the
 * submission of the unaligned IOs so that we don't get racing block zeroing in
 * the dio layer.  To avoid the problem with aio, we also need to wait for
 * outstanding IOs to complete so that unwritten extent conversion is completed
 * before we try to map the overlapping block. This is currently implemented by
 * hitting it with a big hammer (i.e. inode_dio_wait()).
 *
 * Returns with locks held indicated by @iolock and errors indicated by
 * negative return values.
 */
STATIC ssize_t
xfs_file_dio_aio_write(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	struct file		*file = iocb->ki_filp;
	struct address_space	*mapping = file->f_mapping;
	struct inode		*inode = mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	ssize_t			ret = 0;
	int			unaligned_io = 0;
	int			iolock;
	size_t			count = iov_iter_count(from);
	struct xfs_buftarg      *target = xfs_inode_buftarg(ip);

	if (iocb->ki_flags & IOCB_ATOMIC) {
		if (!generic_atomic_write_valid(iocb->ki_pos, count,
			i_blocksize(inode),
			XFS_FSB_TO_B(mp, xfs_get_extsz(ip)))) {
			return -EINVAL;
		}
	}

	/* DIO must be aligned to device logical sector size */
	if ((iocb->ki_pos | count) & target->bt_logical_sectormask)
		return -EINVAL;

	/*
	 * Don't take the exclusive iolock here unless the I/O is unaligned to
	 * the file system block size.  We don't need to consider the EOF
	 * extension case here because xfs_file_aio_write_checks() will relock
	 * the inode as necessary for EOF zeroing cases and fill out the new
	 * inode size as appropriate.
	 */
	if ((iocb->ki_pos & (XFS_FSB_TO_B(mp, xfs_get_extsz(ip)) - 1)) ||
	    ((iocb->ki_pos + count) & (XFS_FSB_TO_B(mp, xfs_get_extsz(ip)) - 1))) {
		unaligned_io = 1;

		/*
		 * We can't properly handle unaligned direct I/O to reflink
		 * files yet, as we can't unshare a partial block.
		 */
		if (xfs_is_cow_inode(ip)) {
			trace_xfs_reflink_bounce_dio_write(ip, iocb->ki_pos, count);
			return -ENOTBLK;
		}
		iolock = XFS_IOLOCK_EXCL;
	} else {
		iolock = XFS_IOLOCK_SHARED;
	}

	if (iocb->ki_flags & IOCB_NOWAIT) {
		/* unaligned dio always waits, bail */
		if (unaligned_io)
			return -EAGAIN;
		if (!xfs_ilock_nowait(ip, iolock))
			return -EAGAIN;
	} else {
		xfs_ilock(ip, iolock);
	}

	ret = xfs_file_aio_write_checks(iocb, from, &iolock);
	if (ret)
		goto out;
	count = iov_iter_count(from);

	/*
	 * If we are doing unaligned IO, we can't allow any other overlapping IO
	 * in-flight at the same time or we risk data corruption. Wait for all
	 * other IO to drain before we submit. If the IO is aligned, demote the
	 * iolock if we had to take the exclusive lock in
	 * xfs_file_aio_write_checks() for other reasons.
	 */
	if (unaligned_io) {
		inode_dio_wait(inode);
	} else if (iolock == XFS_IOLOCK_EXCL) {
		xfs_ilock_demote(ip, XFS_IOLOCK_EXCL);
		iolock = XFS_IOLOCK_SHARED;
	}

	trace_xfs_file_direct_write(ip, count, iocb->ki_pos);
	/*
	 * If unaligned, this is the only IO in-flight. Wait on it before we
	 * release the iolock to prevent subsequent overlapping IO.
	 */
	ret = iomap_dio_rw(iocb, from, &xfs_direct_write_iomap_ops,
			   &xfs_dio_write_ops,
			   unaligned_io ? IOMAP_DIO_FORCE_WAIT : 0);
out:
	if (iolock)
		xfs_iunlock(ip, iolock);

	/*
	 * No fallback to buffered IO after short writes for XFS, direct I/O
	 * will either complete fully or return an error.
	 */
	ASSERT(ret < 0 || ret == count);
	return ret;
}

static noinline ssize_t
xfs_file_dax_write(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	struct inode		*inode = iocb->ki_filp->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	int			iolock = XFS_IOLOCK_EXCL;
	ssize_t			ret, error = 0;
	size_t			count;
	loff_t			pos;

	ret = xfs_ilock_iocb(iocb, iolock);
	if (ret)
		return ret;
	ret = xfs_file_aio_write_checks(iocb, from, &iolock);
	if (ret)
		goto out;

	pos = iocb->ki_pos;
	count = iov_iter_count(from);

	trace_xfs_file_dax_write(ip, count, pos);
	ret = dax_iomap_rw(iocb, from, &xfs_direct_write_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		error = xfs_setfilesize(ip, pos, ret);
	}
out:
	if (iolock)
		xfs_iunlock(ip, iolock);
	if (error)
		return error;

	if (ret > 0) {
		XFS_STATS_ADD(ip->i_mount, xs_write_bytes, ret);

		/* Handle various SYNC-type writes */
		ret = generic_write_sync(iocb, ret);
	}
	return ret;
}

STATIC ssize_t
xfs_file_buffered_aio_write(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	struct file		*file = iocb->ki_filp;
	struct address_space	*mapping = file->f_mapping;
	struct inode		*inode = mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;
	bool			cleared_space = false;
	int			iolock;

	if (iocb->ki_flags & IOCB_NOWAIT)
		return -EOPNOTSUPP;

write_retry:
	iolock = XFS_IOLOCK_EXCL;
	xfs_ilock(ip, iolock);

	ret = xfs_file_aio_write_checks(iocb, from, &iolock);
	if (ret)
		goto out;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);

	trace_xfs_file_buffered_write(ip, iov_iter_count(from), iocb->ki_pos);
	ret = iomap_file_buffered_write(iocb, from,
			&xfs_buffered_write_iomap_ops);
	if (likely(ret >= 0))
		iocb->ki_pos += ret;

	/*
	 * If we hit a space limit, try to free up some lingering preallocated
	 * space before returning an error. In the case of ENOSPC, first try to
	 * write back all dirty inodes to free up some of the excess reserved
	 * metadata space. This reduces the chances that the eofblocks scan
	 * waits on dirty mappings. Since xfs_flush_inodes() is serialized, this
	 * also behaves as a filter to prevent too many eofblocks scans from
	 * running at the same time.  Use a synchronous scan to increase the
	 * effectiveness of the scan.
	 */
	if (ret == -EDQUOT && !cleared_space) {
		xfs_iunlock(ip, iolock);
		xfs_blockgc_free_quota(ip, XFS_ICWALK_FLAG_SYNC);
		cleared_space = true;
		goto write_retry;
	} else if (ret == -ENOSPC && !cleared_space) {
		struct xfs_icwalk	icw = {0};

		cleared_space = true;
		xfs_flush_inodes(ip->i_mount);

		xfs_iunlock(ip, iolock);
		icw.icw_flags = XFS_ICWALK_FLAG_SYNC;
		xfs_blockgc_free_space(ip->i_mount, &icw);
		goto write_retry;
	}

	current->backing_dev_info = NULL;
out:
	if (iolock)
		xfs_iunlock(ip, iolock);

	if (ret > 0) {
		XFS_STATS_ADD(ip->i_mount, xs_write_bytes, ret);
		/* Handle various SYNC-type writes */
		ret = generic_write_sync(iocb, ret);
	}
	return ret;
}

STATIC ssize_t
xfs_file_write_iter(
	struct kiocb		*iocb,
	struct iov_iter		*from)
{
	struct file		*file = iocb->ki_filp;
	struct address_space	*mapping = file->f_mapping;
	struct inode		*inode = mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;
	size_t			ocount = iov_iter_count(from);

	XFS_STATS_INC(ip->i_mount, xs_write_calls);

	if (ocount == 0)
		return 0;

	if (xfs_is_shutdown(ip->i_mount))
		return -EIO;

	if (IS_DAX(inode))
		return xfs_file_dax_write(iocb, from);

	if (iocb->ki_flags & IOCB_DIRECT) {

		if (xfs_inode_atomicwrites(ip) &&
		    xfs_has_atomicalways(ip->i_mount) &&
		    !(iocb->ki_flags & IOCB_ATOMIC))
			iocb->ki_flags |= IOCB_ATOMIC;
		/*
		 * Allow a directio write to fall back to a buffered
		 * write *only* in the case that we're doing a reflink
		 * CoW.  In all other directio scenarios we do not
		 * allow an operation to fall back to buffered mode.
		 */
		ret = xfs_file_dio_aio_write(iocb, from);
		if (ret != -ENOTBLK)
			return ret;
	}

	return xfs_file_buffered_aio_write(iocb, from);
}

static void
xfs_wait_dax_page(
	struct inode		*inode)
{
	struct xfs_inode        *ip = XFS_I(inode);

	xfs_iunlock(ip, XFS_MMAPLOCK_EXCL);
	schedule();
	xfs_ilock(ip, XFS_MMAPLOCK_EXCL);
}

static int
xfs_break_dax_layouts(
	struct inode		*inode,
	bool			*retry)
{
	struct page		*page;

	ASSERT(xfs_isilocked(XFS_I(inode), XFS_MMAPLOCK_EXCL));

	page = dax_layout_busy_page(inode->i_mapping);
	if (!page)
		return 0;

	*retry = true;
	return ___wait_var_event(&page->_refcount,
			atomic_read(&page->_refcount) == 1, TASK_INTERRUPTIBLE,
			0, 0, xfs_wait_dax_page(inode));
}

int
xfs_break_layouts(
	struct inode		*inode,
	uint			*iolock,
	enum layout_break_reason reason)
{
	bool			retry;
	int			error;

	ASSERT(xfs_isilocked(XFS_I(inode), XFS_IOLOCK_SHARED|XFS_IOLOCK_EXCL));

	do {
		retry = false;
		switch (reason) {
		case BREAK_UNMAP:
			error = xfs_break_dax_layouts(inode, &retry);
			if (error || retry)
				break;
			fallthrough;
		case BREAK_WRITE:
			error = xfs_break_leased_layouts(inode, iolock, &retry);
			break;
		default:
			WARN_ON_ONCE(1);
			error = -EINVAL;
		}
	} while (error == 0 && retry);

	return error;
}

#define	XFS_FALLOC_FL_SUPPORTED						\
		(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |		\
		 FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |	\
		 FALLOC_FL_INSERT_RANGE | FALLOC_FL_UNSHARE_RANGE)

STATIC long
xfs_file_fallocate(
	struct file		*file,
	int			mode,
	loff_t			offset,
	loff_t			len)
{
	struct inode		*inode = file_inode(file);
	struct xfs_inode	*ip = XFS_I(inode);
	long			error;
	uint			iolock = XFS_IOLOCK_EXCL | XFS_MMAPLOCK_EXCL;
	loff_t			new_size = 0;
	bool			do_file_insert = false;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;
	if (mode & ~XFS_FALLOC_FL_SUPPORTED)
		return -EOPNOTSUPP;

	xfs_ilock(ip, iolock);
	error = xfs_break_layouts(inode, &iolock, BREAK_UNMAP);
	if (error)
		goto out_unlock;

	/*
	 * Must wait for all AIO to complete before we continue as AIO can
	 * change the file size on completion without holding any locks we
	 * currently hold. We must do this first because AIO can update both
	 * the on disk and in memory inode sizes, and the operations that follow
	 * require the in-memory size to be fully up-to-date.
	 */
	inode_dio_wait(inode);

	/*
	 * Now AIO and DIO has drained we flush and (if necessary) invalidate
	 * the cached range over the first operation we are about to run.
	 *
	 * We care about zero and collapse here because they both run a hole
	 * punch over the range first. Because that can zero data, and the range
	 * of invalidation for the shift operations is much larger, we still do
	 * the required flush for collapse in xfs_prepare_shift().
	 *
	 * Insert has the same range requirements as collapse, and we extend the
	 * file first which can zero data. Hence insert has the same
	 * flush/invalidate requirements as collapse and so they are both
	 * handled at the right time by xfs_prepare_shift().
	 */
	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE |
		    FALLOC_FL_COLLAPSE_RANGE)) {
		error = xfs_flush_unmap_range(ip, offset, len);
		if (error)
			goto out_unlock;
	}

	error = file_modified(file);
	if (error)
		goto out_unlock;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		error = xfs_free_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		if (!xfs_is_falloc_aligned(ip, offset, len)) {
			error = -EINVAL;
			goto out_unlock;
		}

		/*
		 * There is no need to overlap collapse range with EOF,
		 * in which case it is effectively a truncate operation
		 */
		if (offset + len >= i_size_read(inode)) {
			error = -EINVAL;
			goto out_unlock;
		}

		new_size = i_size_read(inode) - len;

		error = xfs_collapse_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	} else if (mode & FALLOC_FL_INSERT_RANGE) {
		loff_t		isize = i_size_read(inode);

		if (!xfs_is_falloc_aligned(ip, offset, len)) {
			error = -EINVAL;
			goto out_unlock;
		}

		/*
		 * New inode size must not exceed ->s_maxbytes, accounting for
		 * possible signed overflow.
		 */
		if (inode->i_sb->s_maxbytes - isize < len) {
			error = -EFBIG;
			goto out_unlock;
		}
		new_size = isize + len;

		/* Offset should be less than i_size */
		if (offset >= isize) {
			error = -EINVAL;
			goto out_unlock;
		}
		do_file_insert = true;
	} else {
		if (!(mode & FALLOC_FL_KEEP_SIZE) &&
		    offset + len > i_size_read(inode)) {
			new_size = offset + len;
			error = inode_newsize_ok(inode, new_size);
			if (error)
				goto out_unlock;
		}

		if (mode & FALLOC_FL_ZERO_RANGE) {
			/*
			 * Punch a hole and prealloc the range.  We use a hole
			 * punch rather than unwritten extent conversion for two
			 * reasons:
			 *
			 *   1.) Hole punch handles partial block zeroing for us.
			 *   2.) If prealloc returns ENOSPC, the file range is
			 *       still zero-valued by virtue of the hole punch.
			 */
			unsigned int blksize = i_blocksize(inode);

			trace_xfs_zero_file_space(ip);

			error = xfs_free_file_space(ip, offset, len);
			if (error)
				goto out_unlock;

			len = round_up(offset + len, blksize) -
			      round_down(offset, blksize);
			offset = round_down(offset, blksize);
		} else if (mode & FALLOC_FL_UNSHARE_RANGE) {
			error = xfs_reflink_unshare(ip, offset, len);
			if (error)
				goto out_unlock;
		} else {
			/*
			 * If always_cow mode we can't use preallocations and
			 * thus should not create them.
			 */
			if (xfs_is_always_cow_inode(ip)) {
				error = -EOPNOTSUPP;
				goto out_unlock;
			}
		}

		if (!xfs_is_always_cow_inode(ip)) {
			error = xfs_alloc_file_space(ip, offset, len,
						     XFS_BMAPI_PREALLOC);
			if (error)
				goto out_unlock;
		}
	}

	/* Change file size if needed */
	if (new_size) {
		struct iattr iattr;

		iattr.ia_valid = ATTR_SIZE;
		iattr.ia_size = new_size;
		error = xfs_vn_setattr_size(file_dentry(file), &iattr);
		if (error)
			goto out_unlock;
	}

	/*
	 * Perform hole insertion now that the file size has been
	 * updated so that if we crash during the operation we don't
	 * leave shifted extents past EOF and hence losing access to
	 * the data that is contained within them.
	 */
	if (do_file_insert) {
		error = xfs_insert_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	}

	if (file->f_flags & O_DSYNC)
		error = xfs_log_force_inode(ip);

out_unlock:
	xfs_iunlock(ip, iolock);
	return error;
}

STATIC int
xfs_file_fadvise(
	struct file	*file,
	loff_t		start,
	loff_t		end,
	int		advice)
{
	struct xfs_inode *ip = XFS_I(file_inode(file));
	int ret;
	int lockflags = 0;

	/*
	 * Operations creating pages in page cache need protection from hole
	 * punching and similar ops
	 */
	if (advice == POSIX_FADV_WILLNEED) {
		lockflags = XFS_IOLOCK_SHARED;
		xfs_ilock(ip, lockflags);
	}
	ret = generic_fadvise(file, start, end, advice);
	if (lockflags)
		xfs_iunlock(ip, lockflags);
	return ret;
}

/* Does this file, inode, or mount want synchronous writes? */
static inline bool xfs_file_sync_writes(struct file *filp)
{
	struct xfs_inode	*ip = XFS_I(file_inode(filp));

	if (xfs_has_wsync(ip->i_mount))
		return true;
	if (filp->f_flags & (__O_SYNC | O_DSYNC))
		return true;
	if (IS_SYNC(file_inode(filp)))
		return true;

	return false;
}

STATIC loff_t
xfs_file_remap_range(
	struct file		*file_in,
	loff_t			pos_in,
	struct file		*file_out,
	loff_t			pos_out,
	loff_t			len,
	unsigned int		remap_flags)
{
	struct inode		*inode_in = file_inode(file_in);
	struct xfs_inode	*src = XFS_I(inode_in);
	struct inode		*inode_out = file_inode(file_out);
	struct xfs_inode	*dest = XFS_I(inode_out);
	struct xfs_mount	*mp = src->i_mount;
	loff_t			remapped = 0;
	xfs_extlen_t		cowextsize;
	int			ret;

	if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
		return -EINVAL;

	if (!xfs_has_reflink(mp))
		return -EOPNOTSUPP;

	if (xfs_is_shutdown(mp))
		return -EIO;

	/* Prepare and then clone file data. */
	ret = xfs_reflink_remap_prep(file_in, pos_in, file_out, pos_out,
			&len, remap_flags);
	if (ret || len == 0)
		return ret;

	trace_xfs_reflink_remap_range(src, pos_in, len, dest, pos_out);

	ret = xfs_reflink_remap_blocks(src, pos_in, dest, pos_out, len,
			&remapped);
	if (ret)
		goto out_unlock;

	/*
	 * Carry the cowextsize hint from src to dest if we're sharing the
	 * entire source file to the entire destination file, the source file
	 * has a cowextsize hint, and the destination file does not.
	 */
	cowextsize = 0;
	if (pos_in == 0 && len == i_size_read(inode_in) &&
	    (src->i_d.di_flags2 & XFS_DIFLAG2_COWEXTSIZE) &&
	    pos_out == 0 && len >= i_size_read(inode_out) &&
	    !(dest->i_d.di_flags2 & XFS_DIFLAG2_COWEXTSIZE))
		cowextsize = src->i_d.di_cowextsize;

	ret = xfs_reflink_update_dest(dest, pos_out + len, cowextsize,
			remap_flags);
	if (ret)
		goto out_unlock;

	if (xfs_file_sync_writes(file_in) || xfs_file_sync_writes(file_out))
		xfs_log_force_inode(dest);
out_unlock:
	xfs_iunlock2_io_mmap(src, dest);
	if (ret)
		trace_xfs_reflink_remap_range_error(dest, ret, _RET_IP_);
	return remapped > 0 ? remapped : ret;
}

static bool xfs_file_open_can_atomicwrite(
	struct inode		*inode,
	struct file		*file)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_buftarg	*target = xfs_inode_buftarg(ip);

	if (!(file->f_flags & O_DIRECT))
		return false;

	if (!xfs_inode_atomicwrites(ip))
		return false;

	if (!bdev_can_atomic_write(target->bt_bdev))
		return false;

	return true;
}

STATIC int
xfs_file_open(
	struct inode	*inode,
	struct file	*file)
{
	if (!(file->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
		return -EFBIG;
	if (xfs_is_shutdown(XFS_M(inode->i_sb)))
		return -EIO;
	file->f_mode |= FMODE_NOWAIT | FMODE_BUF_RASYNC;
	if (xfs_file_open_can_atomicwrite(inode, file))
		file->f_mode |= FMODE_CAN_ATOMIC_WRITE;
	return 0;
}

STATIC int
xfs_dir_open(
	struct inode	*inode,
	struct file	*file)
{
	struct xfs_inode *ip = XFS_I(inode);
	int		mode;
	int		error;

	error = xfs_file_open(inode, file);
	if (error)
		return error;

	/*
	 * If there are any blocks, read-ahead block 0 as we're almost
	 * certain to have the next operation be a read there.
	 */
	mode = xfs_ilock_data_map_shared(ip);
	if (ip->i_df.if_nextents > 0)
		error = xfs_dir3_data_readahead(ip, 0, 0);
	xfs_iunlock(ip, mode);
	return error;
}

STATIC int
xfs_file_release(
	struct inode	*inode,
	struct file	*filp)
{
	trace_fs_file_release(inode, filp);
	return xfs_release(XFS_I(inode));
}

STATIC int
xfs_file_readdir(
	struct file	*file,
	struct dir_context *ctx)
{
	struct inode	*inode = file_inode(file);
	xfs_inode_t	*ip = XFS_I(inode);
	size_t		bufsize;

	/*
	 * The Linux API doesn't pass down the total size of the buffer
	 * we read into down to the filesystem.  With the filldir concept
	 * it's not needed for correct information, but the XFS dir2 leaf
	 * code wants an estimate of the buffer size to calculate it's
	 * readahead window and size the buffers used for mapping to
	 * physical blocks.
	 *
	 * Try to give it an estimate that's good enough, maybe at some
	 * point we can change the ->readdir prototype to include the
	 * buffer size.  For now we use the current glibc buffer size.
	 */
	bufsize = (size_t)min_t(loff_t, XFS_READDIR_BUFSIZE, ip->i_d.di_size);

	return xfs_readdir(NULL, ip, ctx, bufsize);
}

STATIC loff_t
xfs_file_llseek(
	struct file	*file,
	loff_t		offset,
	int		whence)
{
	struct inode		*inode = file->f_mapping->host;

	if (xfs_is_shutdown(XFS_I(inode)->i_mount))
		return -EIO;

	switch (whence) {
	default:
		return generic_file_llseek(file, offset, whence);
	case SEEK_HOLE:
		offset = iomap_seek_hole(inode, offset, &xfs_seek_iomap_ops);
		break;
	case SEEK_DATA:
		offset = iomap_seek_data(inode, offset, &xfs_seek_iomap_ops);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, inode->i_sb->s_maxbytes);
}

/*
 * Locking for serialisation of IO during page faults. This results in a lock
 * ordering of:
 *
 * mmap_lock (MM)
 *   sb_start_pagefault(vfs, freeze)
 *     i_mmaplock (XFS - truncate serialisation)
 *       page_lock (MM)
 *         i_lock (XFS - extent map serialisation)
 */
static vm_fault_t
__xfs_filemap_fault(
	struct vm_fault		*vmf,
	enum page_entry_size	pe_size,
	bool			write_fault)
{
	struct inode		*inode = file_inode(vmf->vma->vm_file);
	struct xfs_inode	*ip = XFS_I(inode);
	vm_fault_t		ret;

	trace_xfs_filemap_fault(ip, pe_size, write_fault);

	if (write_fault) {
		sb_start_pagefault(inode->i_sb);
		file_update_time(vmf->vma->vm_file);
	}

	xfs_ilock(XFS_I(inode), XFS_MMAPLOCK_SHARED);
	if (IS_DAX(inode)) {
		pfn_t pfn;

		ret = dax_iomap_fault(vmf, pe_size, &pfn, NULL,
				(write_fault && !vmf->cow_page) ?
				 &xfs_direct_write_iomap_ops :
				 &xfs_read_iomap_ops);
		if (ret & VM_FAULT_NEEDDSYNC)
			ret = dax_finish_sync_fault(vmf, pe_size, pfn);
	} else {
		if (write_fault)
			ret = iomap_page_mkwrite(vmf,
					&xfs_page_mkwrite_iomap_ops);
		else
			ret = filemap_fault(vmf);
	}
	xfs_iunlock(XFS_I(inode), XFS_MMAPLOCK_SHARED);

	if (write_fault)
		sb_end_pagefault(inode->i_sb);
	return ret;
}

static inline bool
xfs_is_write_fault(
	struct vm_fault		*vmf)
{
	return (vmf->flags & FAULT_FLAG_WRITE) &&
	       (vmf->vma->vm_flags & VM_SHARED);
}

static vm_fault_t
xfs_filemap_fault(
	struct vm_fault		*vmf)
{
	/* DAX can shortcut the normal fault path on write faults! */
	return __xfs_filemap_fault(vmf, PE_SIZE_PTE,
			IS_DAX(file_inode(vmf->vma->vm_file)) &&
			xfs_is_write_fault(vmf));
}

static vm_fault_t
xfs_filemap_huge_fault(
	struct vm_fault		*vmf,
	enum page_entry_size	pe_size)
{
	if (!IS_DAX(file_inode(vmf->vma->vm_file)))
		return VM_FAULT_FALLBACK;

	/* DAX can shortcut the normal fault path on write faults! */
	return __xfs_filemap_fault(vmf, pe_size,
			xfs_is_write_fault(vmf));
}

static vm_fault_t
xfs_filemap_page_mkwrite(
	struct vm_fault		*vmf)
{
	return __xfs_filemap_fault(vmf, PE_SIZE_PTE, true);
}

/*
 * pfn_mkwrite was originally intended to ensure we capture time stamp updates
 * on write faults. In reality, it needs to serialise against truncate and
 * prepare memory for writing so handle is as standard write fault.
 */
static vm_fault_t
xfs_filemap_pfn_mkwrite(
	struct vm_fault		*vmf)
{

	return __xfs_filemap_fault(vmf, PE_SIZE_PTE, true);
}

static void
xfs_filemap_map_pages(
	struct vm_fault		*vmf,
	pgoff_t			start_pgoff,
	pgoff_t			end_pgoff)
{
	struct inode		*inode = file_inode(vmf->vma->vm_file);

	xfs_ilock(XFS_I(inode), XFS_MMAPLOCK_SHARED);
	filemap_map_pages(vmf, start_pgoff, end_pgoff);
	xfs_iunlock(XFS_I(inode), XFS_MMAPLOCK_SHARED);
}

static const struct vm_operations_struct xfs_file_vm_ops = {
	.fault		= xfs_filemap_fault,
	.huge_fault	= xfs_filemap_huge_fault,
	.map_pages	= xfs_filemap_map_pages,
	.page_mkwrite	= xfs_filemap_page_mkwrite,
	.pfn_mkwrite	= xfs_filemap_pfn_mkwrite,
};

STATIC int
xfs_file_mmap(
	struct file		*file,
	struct vm_area_struct	*vma)
{
	struct inode		*inode = file_inode(file);
	struct xfs_buftarg	*target = xfs_inode_buftarg(XFS_I(inode));

	/*
	 * We don't support synchronous mappings for non-DAX files and
	 * for DAX files if underneath dax_device is not synchronous.
	 */
	if (!daxdev_mapping_supported(vma, target->bt_daxdev))
		return -EOPNOTSUPP;

	file_accessed(file);
	vma->vm_ops = &xfs_file_vm_ops;
	if (IS_DAX(inode))
		vma->vm_flags |= VM_HUGEPAGE;
	return 0;
}

const struct file_operations xfs_file_operations = {
	.llseek		= xfs_file_llseek,
	.read_iter	= xfs_file_read_iter,
	.write_iter	= xfs_file_write_iter,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.iopoll		= iomap_dio_iopoll,
	.unlocked_ioctl	= xfs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= xfs_file_compat_ioctl,
#endif
	.mmap		= xfs_file_mmap,
	.mmap_supported_flags = MAP_SYNC,
	.open		= xfs_file_open,
	.release	= xfs_file_release,
	.fsync		= xfs_file_fsync,
	.get_unmapped_area = thp_get_unmapped_area,
	.fallocate	= xfs_file_fallocate,
	.fadvise	= xfs_file_fadvise,
	.remap_file_range = xfs_file_remap_range,
};

const struct file_operations xfs_dir_file_operations = {
	.open		= xfs_dir_open,
	.read		= generic_read_dir,
	.iterate_shared	= xfs_file_readdir,
	.llseek		= generic_file_llseek,
	.unlocked_ioctl	= xfs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= xfs_file_compat_ioctl,
#endif
	.fsync		= xfs_dir_fsync,
};
