// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * Copyright (c) 2016-2018 Christoph Hellwig.
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
#include "xfs_btree.h"
#include "xfs_bmap_btree.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_trans.h"
#include "xfs_trans_space.h"
#include "xfs_inode_item.h"
#include "xfs_iomap.h"
#include "xfs_trace.h"
#include "xfs_quota.h"
#include "xfs_dquot_item.h"
#include "xfs_dquot.h"
#include "xfs_reflink.h"


#define XFS_ALLOC_ALIGN(mp, off) \
	(((off) >> mp->m_allocsize_log) << mp->m_allocsize_log)

static int
xfs_alert_fsblock_zero(
	xfs_inode_t	*ip,
	xfs_bmbt_irec_t	*imap)
{
	xfs_alert_tag(ip->i_mount, XFS_PTAG_FSBLOCK_ZERO,
			"Access to block zero in inode %llu "
			"start_block: %llx start_off: %llx "
			"blkcnt: %llx extent-state: %x",
		(unsigned long long)ip->i_ino,
		(unsigned long long)imap->br_startblock,
		(unsigned long long)imap->br_startoff,
		(unsigned long long)imap->br_blockcount,
		imap->br_state);
	return -EFSCORRUPTED;
}

u64
xfs_iomap_inode_sequence(
	struct xfs_inode	*ip,
	u16			iomap_flags)
{
	u64			cookie = 0;

	if (iomap_flags & IOMAP_F_XATTR)
		return READ_ONCE(ip->i_af.if_seq);
	if ((iomap_flags & IOMAP_F_SHARED) && ip->i_cowfp)
		cookie = (u64)READ_ONCE(ip->i_cowfp->if_seq) << 32;
	return cookie | READ_ONCE(ip->i_df.if_seq);
}

/*
 * Check that the iomap passed to us is still valid for the given offset and
 * length.
 */
static bool
xfs_iomap_valid(
	struct inode		*inode,
	const struct iomap	*iomap)
{
	return iomap->validity_cookie ==
			xfs_iomap_inode_sequence(XFS_I(inode), iomap->flags);
}

const struct iomap_page_ops xfs_iomap_page_ops = {
	.iomap_valid		= xfs_iomap_valid,
};

int
xfs_bmbt_to_iomap(
	struct xfs_inode	*ip,
	struct iomap		*iomap,
	struct xfs_bmbt_irec	*imap,
	u16			flags,
	u64			sequence_cookie)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_buftarg	*target = xfs_inode_buftarg(ip);
	xfs_extlen_t		extsz = xfs_get_extsz(ip);

	if (unlikely(!xfs_valid_startblock(ip, imap->br_startblock)))
		return xfs_alert_fsblock_zero(ip, imap);

	if (imap->br_startblock == HOLESTARTBLOCK) {
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->type = IOMAP_HOLE;
	} else if (imap->br_startblock == DELAYSTARTBLOCK ||
		   isnullstartblock(imap->br_startblock)) {
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->type = IOMAP_DELALLOC;
	} else {
		iomap->addr = BBTOB(xfs_fsb_to_db(ip, imap->br_startblock));
		if (imap->br_state == XFS_EXT_UNWRITTEN)
			iomap->type = IOMAP_UNWRITTEN;
		else
			iomap->type = IOMAP_MAPPED;
	}
	iomap->offset = XFS_FSB_TO_B(mp, imap->br_startoff);
	iomap->length = XFS_FSB_TO_B(mp, imap->br_blockcount);
	iomap->bdev = target->bt_bdev;
	iomap->dax_dev = target->bt_daxdev;
	iomap->flags = flags;

	if (xfs_ipincount(ip) &&
	    (ip->i_itemp->ili_fsync_fields & ~XFS_ILOG_TIMESTAMP))
		iomap->flags |= IOMAP_F_DIRTY;

	iomap->validity_cookie = sequence_cookie;
	iomap->page_ops = &xfs_iomap_page_ops;
	if (extsz > 1)
		iomap->extent_shift = ffs(extsz) - 1;
	return 0;
}

static void
xfs_hole_to_iomap(
	struct xfs_inode	*ip,
	struct iomap		*iomap,
	xfs_fileoff_t		offset_fsb,
	xfs_fileoff_t		end_fsb)
{
	struct xfs_buftarg	*target = xfs_inode_buftarg(ip);

	iomap->addr = IOMAP_NULL_ADDR;
	iomap->type = IOMAP_HOLE;
	iomap->offset = XFS_FSB_TO_B(ip->i_mount, offset_fsb);
	iomap->length = XFS_FSB_TO_B(ip->i_mount, end_fsb - offset_fsb);
	iomap->bdev = target->bt_bdev;
	iomap->dax_dev = target->bt_daxdev;
}

static inline xfs_fileoff_t
xfs_iomap_end_fsb(
	struct xfs_mount	*mp,
	loff_t			offset,
	loff_t			count)
{
	ASSERT(offset <= mp->m_super->s_maxbytes);
	return min(XFS_B_TO_FSB(mp, offset + count),
		   XFS_B_TO_FSB(mp, mp->m_super->s_maxbytes));
}

static xfs_extlen_t
xfs_eof_alignment(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_extlen_t		align = 0;

	if (!XFS_IS_REALTIME_INODE(ip)) {
		/*
		 * Round up the allocation request to a stripe unit
		 * (m_dalign) boundary if the file size is >= stripe unit
		 * size, and we are allocating past the allocation eof.
		 *
		 * If mounted with the "-o swalloc" option the alignment is
		 * increased from the strip unit size to the stripe width.
		 */
		if (xfs_inode_forcealign(ip))
			align = xfs_get_extsz_hint(ip);
		else if (mp->m_swidth && xfs_has_swalloc(mp))
			align = mp->m_swidth;
		else if (mp->m_dalign)
			align = mp->m_dalign;

		if (align && XFS_ISIZE(ip) < XFS_FSB_TO_B(mp, align))
			align = 0;
	}

	return align;
}

/*
 * Check if last_fsb is outside the last extent, and if so grow it to the next
 * stripe unit boundary.
 */
xfs_fileoff_t
xfs_iomap_eof_align_last_fsb(
	struct xfs_inode	*ip,
	xfs_fileoff_t		end_fsb)
{
	struct xfs_ifork	*ifp = xfs_ifork_ptr(ip, XFS_DATA_FORK);
	xfs_extlen_t		extsz = xfs_get_extsz_hint(ip);
	xfs_extlen_t		align = xfs_eof_alignment(ip);
	struct xfs_bmbt_irec	irec;
	struct xfs_iext_cursor	icur;

	ASSERT(ifp->if_flags & XFS_IFEXTENTS);

	/*
	 * Always round up the allocation request to the extent hint boundary.
	 */
	if (extsz) {
		if (align)
			align = roundup_64(align, extsz);
		else
			align = extsz;
	}

	if (align) {
		xfs_fileoff_t	aligned_end_fsb = roundup_64(end_fsb, align);

		xfs_iext_last(ifp, &icur);
		if (!xfs_iext_get_extent(ifp, &icur, &irec) ||
		    aligned_end_fsb >= irec.br_startoff + irec.br_blockcount)
			return aligned_end_fsb;
	}

	return end_fsb;
}

int
xfs_iomap_write_direct(
	struct xfs_inode	*ip,
	xfs_fileoff_t		offset_fsb,
	xfs_fileoff_t		count_fsb,
	struct xfs_bmbt_irec	*imap,
	u64			*seq)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	xfs_filblks_t		resaligned;
	int			nimaps;
	unsigned int		dblocks, rblocks;
	bool			force = false;
	int			error;
	int			bmapi_flags = XFS_BMAPI_PREALLOC;
	int			nr_exts = XFS_IEXT_ADD_NOSPLIT_CNT;

	ASSERT(count_fsb > 0);

	resaligned = xfs_aligned_fsb_count(offset_fsb, count_fsb,
					   xfs_get_extsz_hint(ip));
	if (unlikely(XFS_IS_REALTIME_INODE(ip))) {
		dblocks = XFS_DIOSTRAT_SPACE_RES(mp, 0);
		rblocks = resaligned;
	} else {
		dblocks = XFS_DIOSTRAT_SPACE_RES(mp, resaligned);
		rblocks = 0;
	}

	error = xfs_qm_dqattach(ip);
	if (error)
		return error;

	/*
	 * For DAX, we do not allocate unwritten extents, but instead we zero
	 * the block before we commit the transaction.  Ideally we'd like to do
	 * this outside the transaction context, but if we commit and then crash
	 * we may not have zeroed the blocks and this will be exposed on
	 * recovery of the allocation. Hence we must zero before commit.
	 *
	 * Further, if we are mapping unwritten extents here, we need to zero
	 * and convert them to written so that we don't need an unwritten extent
	 * callback for DAX. This also means that we need to be able to dip into
	 * the reserve block pool for bmbt block allocation if there is no space
	 * left but we need to do unwritten extent conversion.
	 */
	if (IS_DAX(VFS_I(ip))) {
		bmapi_flags = XFS_BMAPI_CONVERT | XFS_BMAPI_ZERO;
		if (imap->br_state == XFS_EXT_UNWRITTEN) {
			force = true;
			nr_exts = XFS_IEXT_WRITE_UNWRITTEN_CNT;
			dblocks = XFS_DIOSTRAT_SPACE_RES(mp, 0) << 1;
		}
	}

	error = xfs_trans_alloc_inode(ip, &M_RES(mp)->tr_write, dblocks,
			rblocks, force, &tp);
	if (error)
		return error;

	error = xfs_iext_count_may_overflow(ip, XFS_DATA_FORK, nr_exts);
	if (error)
		goto out_trans_cancel;

	/*
	 * From this point onwards we overwrite the imap pointer that the
	 * caller gave to us.
	 */
	nimaps = 1;
	error = xfs_bmapi_write(tp, ip, offset_fsb, count_fsb, bmapi_flags, 0,
				imap, &nimaps);
	if (error)
		goto out_trans_cancel;

	/*
	 * Complete the transaction
	 */
	error = xfs_trans_commit(tp);
	if (error)
		goto out_unlock;

	/*
	 * Copy any maps to caller's array and return any error.
	 */
	if (nimaps == 0) {
		error = -ENOSPC;
		goto out_unlock;
	}

	if (unlikely(!xfs_valid_startblock(ip, imap->br_startblock)))
		error = xfs_alert_fsblock_zero(ip, imap);

out_unlock:
	*seq = xfs_iomap_inode_sequence(ip, 0);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return error;

out_trans_cancel:
	xfs_trans_cancel(tp);
	goto out_unlock;
}

STATIC bool
xfs_quota_need_throttle(
	struct xfs_inode	*ip,
	xfs_dqtype_t		type,
	xfs_fsblock_t		alloc_blocks)
{
	struct xfs_dquot	*dq = xfs_inode_dquot(ip, type);

	if (!dq || !xfs_this_quota_on(ip->i_mount, type))
		return false;

	/* no hi watermark, no throttle */
	if (!dq->q_prealloc_hi_wmark)
		return false;

	/* under the lo watermark, no throttle */
	if (dq->q_blk.reserved + alloc_blocks < dq->q_prealloc_lo_wmark)
		return false;

	return true;
}

STATIC void
xfs_quota_calc_throttle(
	struct xfs_inode	*ip,
	xfs_dqtype_t		type,
	xfs_fsblock_t		*qblocks,
	int			*qshift,
	int64_t			*qfreesp)
{
	struct xfs_dquot	*dq = xfs_inode_dquot(ip, type);
	int64_t			freesp;
	int			shift = 0;

	/* no dq, or over hi wmark, squash the prealloc completely */
	if (!dq || dq->q_blk.reserved >= dq->q_prealloc_hi_wmark) {
		*qblocks = 0;
		*qfreesp = 0;
		return;
	}

	freesp = dq->q_prealloc_hi_wmark - dq->q_blk.reserved;
	if (freesp < dq->q_low_space[XFS_QLOWSP_5_PCNT]) {
		shift = 2;
		if (freesp < dq->q_low_space[XFS_QLOWSP_3_PCNT])
			shift += 2;
		if (freesp < dq->q_low_space[XFS_QLOWSP_1_PCNT])
			shift += 2;
	}

	if (freesp < *qfreesp)
		*qfreesp = freesp;

	/* only overwrite the throttle values if we are more aggressive */
	if ((freesp >> shift) < (*qblocks >> *qshift)) {
		*qblocks = freesp;
		*qshift = shift;
	}
}

/*
 * If we don't have a user specified preallocation size, dynamically increase
 * the preallocation size as the size of the file grows.  Cap the maximum size
 * at a single extent or less if the filesystem is near full. The closer the
 * filesystem is to being full, the smaller the maximum preallocation.
 */
STATIC xfs_fsblock_t
xfs_iomap_prealloc_size(
	struct xfs_inode	*ip,
	int			whichfork,
	loff_t			offset,
	loff_t			count,
	struct xfs_iext_cursor	*icur)
{
	struct xfs_iext_cursor	ncur = *icur;
	struct xfs_bmbt_irec	prev, got;
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_ifork	*ifp = xfs_ifork_ptr(ip, whichfork);
	xfs_fileoff_t		offset_fsb = XFS_B_TO_FSBT(mp, offset);
	int64_t			freesp;
	xfs_fsblock_t		qblocks;
	xfs_fsblock_t		alloc_blocks = 0;
	xfs_extlen_t		plen;
	int			shift = 0;
	int			qshift = 0;

	/*
	 * As an exception we don't do any preallocation at all if the file is
	 * smaller than the minimum preallocation and we are using the default
	 * dynamic preallocation scheme, as it is likely this is the only write
	 * to the file that is going to be done.
	 */
	if (XFS_ISIZE(ip) < XFS_FSB_TO_B(mp, mp->m_allocsize_blocks))
		return 0;

	/*
	 * Use the minimum preallocation size for small files or if we are
	 * writing right after a hole.
	 */
	if (XFS_ISIZE(ip) < XFS_FSB_TO_B(mp, mp->m_dalign) ||
	    !xfs_iext_prev_extent(ifp, &ncur, &prev) ||
	    prev.br_startoff + prev.br_blockcount < offset_fsb)
		return mp->m_allocsize_blocks;

	/*
	 * Take the size of the preceding data extents as the basis for the
	 * preallocation size. Note that we don't care if the previous extents
	 * are written or not.
	 */
	plen = prev.br_blockcount;
	while (xfs_iext_prev_extent(ifp, &ncur, &got)) {
		if (plen > MAXEXTLEN / 2 ||
		    isnullstartblock(got.br_startblock) ||
		    got.br_startoff + got.br_blockcount != prev.br_startoff ||
		    got.br_startblock + got.br_blockcount != prev.br_startblock)
			break;
		plen += got.br_blockcount;
		prev = got;
	}

	/*
	 * If the size of the extents is greater than half the maximum extent
	 * length, then use the current offset as the basis.  This ensures that
	 * for large files the preallocation size always extends to MAXEXTLEN
	 * rather than falling short due to things like stripe unit/width
	 * alignment of real extents.
	 */
	alloc_blocks = plen * 2;
	if (alloc_blocks > MAXEXTLEN)
		alloc_blocks = XFS_B_TO_FSB(mp, offset);
	qblocks = alloc_blocks;

	/*
	 * MAXEXTLEN is not a power of two value but we round the prealloc down
	 * to the nearest power of two value after throttling. To prevent the
	 * round down from unconditionally reducing the maximum supported
	 * prealloc size, we round up first, apply appropriate throttling,
	 * round down and cap the value to MAXEXTLEN.
	 */
	alloc_blocks = XFS_FILEOFF_MIN(roundup_pow_of_two(MAXEXTLEN),
				       alloc_blocks);

	freesp = percpu_counter_read_positive(&mp->m_fdblocks);
	if (freesp < mp->m_low_space[XFS_LOWSP_5_PCNT]) {
		shift = 2;
		if (freesp < mp->m_low_space[XFS_LOWSP_4_PCNT])
			shift++;
		if (freesp < mp->m_low_space[XFS_LOWSP_3_PCNT])
			shift++;
		if (freesp < mp->m_low_space[XFS_LOWSP_2_PCNT])
			shift++;
		if (freesp < mp->m_low_space[XFS_LOWSP_1_PCNT])
			shift++;
	}

	/*
	 * Check each quota to cap the prealloc size, provide a shift value to
	 * throttle with and adjust amount of available space.
	 */
	if (xfs_quota_need_throttle(ip, XFS_DQTYPE_USER, alloc_blocks))
		xfs_quota_calc_throttle(ip, XFS_DQTYPE_USER, &qblocks, &qshift,
					&freesp);
	if (xfs_quota_need_throttle(ip, XFS_DQTYPE_GROUP, alloc_blocks))
		xfs_quota_calc_throttle(ip, XFS_DQTYPE_GROUP, &qblocks, &qshift,
					&freesp);
	if (xfs_quota_need_throttle(ip, XFS_DQTYPE_PROJ, alloc_blocks))
		xfs_quota_calc_throttle(ip, XFS_DQTYPE_PROJ, &qblocks, &qshift,
					&freesp);

	/*
	 * The final prealloc size is set to the minimum of free space available
	 * in each of the quotas and the overall filesystem.
	 *
	 * The shift throttle value is set to the maximum value as determined by
	 * the global low free space values and per-quota low free space values.
	 */
	alloc_blocks = min(alloc_blocks, qblocks);
	shift = max(shift, qshift);

	if (shift)
		alloc_blocks >>= shift;
	/*
	 * rounddown_pow_of_two() returns an undefined result if we pass in
	 * alloc_blocks = 0.
	 */
	if (alloc_blocks)
		alloc_blocks = rounddown_pow_of_two(alloc_blocks);
	if (alloc_blocks > MAXEXTLEN)
		alloc_blocks = MAXEXTLEN;

	/*
	 * If we are still trying to allocate more space than is
	 * available, squash the prealloc hard. This can happen if we
	 * have a large file on a small filesystem and the above
	 * lowspace thresholds are smaller than MAXEXTLEN.
	 */
	while (alloc_blocks && alloc_blocks >= freesp)
		alloc_blocks >>= 4;
	if (alloc_blocks < mp->m_allocsize_blocks)
		alloc_blocks = mp->m_allocsize_blocks;
	trace_xfs_iomap_prealloc_size(ip, alloc_blocks, shift,
				      mp->m_allocsize_blocks);
	return alloc_blocks;
}

int
xfs_iomap_write_unwritten(
	xfs_inode_t	*ip,
	xfs_off_t	offset,
	xfs_off_t	count,
	bool		update_isize)
{
	xfs_mount_t	*mp = ip->i_mount;
	xfs_fileoff_t	offset_fsb;
	xfs_filblks_t	count_fsb;
	xfs_filblks_t	numblks_fsb;
	int		nimaps;
	xfs_trans_t	*tp;
	xfs_bmbt_irec_t imap;
	struct inode	*inode = VFS_I(ip);
	xfs_fsize_t	i_size;
	uint		resblks;
	int		error;
	xfs_extlen_t	extsz = xfs_get_extsz(ip);

	trace_xfs_unwritten_convert(ip, offset, count);

	if (extsz > 1) {
		xfs_extlen_t extsize_bytes = XFS_FSB_TO_B(mp, extsz);

		offset_fsb = XFS_B_TO_FSBT(mp, round_down(offset, extsize_bytes));
		count_fsb = XFS_B_TO_FSB(mp, round_up(offset + count, extsize_bytes));
	} else {
		offset_fsb = XFS_B_TO_FSBT(mp, offset);
		count_fsb = XFS_B_TO_FSB(mp, (xfs_ufsize_t)offset + count);
	}
	count_fsb = (xfs_filblks_t)(count_fsb - offset_fsb);

	/*
	 * Reserve enough blocks in this transaction for two complete extent
	 * btree splits.  We may be converting the middle part of an unwritten
	 * extent and in this case we will insert two new extents in the btree
	 * each of which could cause a full split.
	 *
	 * This reservation amount will be used in the first call to
	 * xfs_bmbt_split() to select an AG with enough space to satisfy the
	 * rest of the operation.
	 */
	resblks = XFS_DIOSTRAT_SPACE_RES(mp, 0) << 1;

	/* Attach dquots so that bmbt splits are accounted correctly. */
	error = xfs_qm_dqattach(ip);
	if (error)
		return error;

	do {
		/*
		 * Set up a transaction to convert the range of extents
		 * from unwritten to real. Do allocations in a loop until
		 * we have covered the range passed in.
		 *
		 * Note that we can't risk to recursing back into the filesystem
		 * here as we might be asked to write out the same inode that we
		 * complete here and might deadlock on the iolock.
		 */
		error = xfs_trans_alloc_inode(ip, &M_RES(mp)->tr_write, resblks,
				0, true, &tp);
		if (error)
			return error;

		error = xfs_iext_count_may_overflow(ip, XFS_DATA_FORK,
				XFS_IEXT_WRITE_UNWRITTEN_CNT);
		if (error)
			goto error_on_bmapi_transaction;

		/*
		 * Modify the unwritten extent state of the buffer.
		 */
		nimaps = 1;
		error = xfs_bmapi_write(tp, ip, offset_fsb, count_fsb,
					XFS_BMAPI_CONVERT, resblks, &imap,
					&nimaps);
		if (error)
			goto error_on_bmapi_transaction;

		/*
		 * Log the updated inode size as we go.  We have to be careful
		 * to only log it up to the actual write offset if it is
		 * halfway into a block.
		 */
		i_size = XFS_FSB_TO_B(mp, offset_fsb + count_fsb);
		if (i_size > offset + count)
			i_size = offset + count;
		if (update_isize && i_size > i_size_read(inode))
			i_size_write(inode, i_size);
		i_size = xfs_new_eof(ip, i_size);
		if (i_size) {
			ip->i_d.di_size = i_size;
			xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
		}

		error = xfs_trans_commit(tp);
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
		if (error)
			return error;

		if (unlikely(!xfs_valid_startblock(ip, imap.br_startblock)))
			return xfs_alert_fsblock_zero(ip, &imap);

		if ((numblks_fsb = imap.br_blockcount) == 0) {
			/*
			 * The numblks_fsb value should always get
			 * smaller, otherwise the loop is stuck.
			 */
			ASSERT(imap.br_blockcount);
			break;
		}
		offset_fsb += numblks_fsb;
		count_fsb -= numblks_fsb;
	} while (count_fsb > 0);

	return 0;

error_on_bmapi_transaction:
	xfs_trans_cancel(tp);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return error;
}

static inline bool
imap_needs_alloc(
	struct inode		*inode,
	unsigned		flags,
	struct xfs_bmbt_irec	*imap,
	int			nimaps)
{
	/* don't allocate blocks when just zeroing */
	if (flags & IOMAP_ZERO)
		return false;
	if (!nimaps ||
	    imap->br_startblock == HOLESTARTBLOCK ||
	    imap->br_startblock == DELAYSTARTBLOCK)
		return true;
	/* we convert unwritten extents before copying the data for DAX */
	if (IS_DAX(inode) && imap->br_state == XFS_EXT_UNWRITTEN)
		return true;
	return false;
}

static inline bool
imap_needs_cow(
	struct xfs_inode	*ip,
	unsigned int		flags,
	struct xfs_bmbt_irec	*imap,
	int			nimaps)
{
	if (!xfs_is_cow_inode(ip))
		return false;

	/* when zeroing we don't have to COW holes or unwritten extents */
	if (flags & IOMAP_ZERO) {
		if (!nimaps ||
		    imap->br_startblock == HOLESTARTBLOCK ||
		    imap->br_state == XFS_EXT_UNWRITTEN)
			return false;
	}

	return true;
}

static int
xfs_ilock_for_iomap(
	struct xfs_inode	*ip,
	unsigned		flags,
	unsigned		*lockmode)
{
	unsigned		mode = XFS_ILOCK_SHARED;
	bool			is_write = flags & (IOMAP_WRITE | IOMAP_ZERO);

	/*
	 * COW writes may allocate delalloc space or convert unwritten COW
	 * extents, so we need to make sure to take the lock exclusively here.
	 */
	if (xfs_is_cow_inode(ip) && is_write)
		mode = XFS_ILOCK_EXCL;

	/*
	 * Extents not yet cached requires exclusive access, don't block.  This
	 * is an opencoded xfs_ilock_data_map_shared() call but with
	 * non-blocking behaviour.
	 */
	if (!(ip->i_df.if_flags & XFS_IFEXTENTS)) {
		if (flags & IOMAP_NOWAIT)
			return -EAGAIN;
		mode = XFS_ILOCK_EXCL;
	}

relock:
	if (flags & IOMAP_NOWAIT) {
		if (!xfs_ilock_nowait(ip, mode))
			return -EAGAIN;
	} else {
		xfs_ilock(ip, mode);
	}

	/*
	 * The reflink iflag could have changed since the earlier unlocked
	 * check, so if we got ILOCK_SHARED for a write and but we're now a
	 * reflink inode we have to switch to ILOCK_EXCL and relock.
	 */
	if (mode == XFS_ILOCK_SHARED && is_write && xfs_is_cow_inode(ip)) {
		xfs_iunlock(ip, mode);
		mode = XFS_ILOCK_EXCL;
		goto relock;
	}

	*lockmode = mode;
	return 0;
}

/*
 * Check that the imap we are going to return to the caller spans the entire
 * range that the caller requested for the IO.
 */
static bool
imap_spans_range(
	struct xfs_bmbt_irec	*imap,
	xfs_fileoff_t		offset_fsb,
	xfs_fileoff_t		end_fsb)
{
	if (imap->br_startoff > offset_fsb)
		return false;
	if (imap->br_startoff + imap->br_blockcount < end_fsb)
		return false;
	return true;
}

static int
xfs_direct_write_iomap_begin(
	struct inode		*inode,
	loff_t			offset,
	loff_t			length,
	unsigned		flags,
	struct iomap		*iomap,
	struct iomap		*srcmap)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_bmbt_irec	imap, cmap;
	xfs_fileoff_t		offset_fsb = XFS_B_TO_FSBT(mp, offset);
	xfs_fileoff_t		end_fsb = xfs_iomap_end_fsb(mp, offset, length);
	int			nimaps = 1, error = 0;
	bool			shared = false;
	u16			iomap_flags = 0;
	unsigned		lockmode;
	u64			seq;

	ASSERT(flags & (IOMAP_WRITE | IOMAP_ZERO));

	if (xfs_is_shutdown(mp))
		return -EIO;

	/*
	 * Writes that span EOF might trigger an IO size update on completion,
	 * so consider them to be dirty for the purposes of O_DSYNC even if
	 * there is no other metadata changes pending or have been made here.
	 */
	if (offset + length > i_size_read(inode))
		iomap_flags |= IOMAP_F_DIRTY;

	error = xfs_ilock_for_iomap(ip, flags, &lockmode);
	if (error)
		return error;

	error = xfs_bmapi_read(ip, offset_fsb, end_fsb - offset_fsb, &imap,
			       &nimaps, 0);
	if (error)
		goto out_unlock;

	if (imap_needs_cow(ip, flags, &imap, nimaps)) {
		error = -EAGAIN;
		if (flags & IOMAP_NOWAIT)
			goto out_unlock;

		/* may drop and re-acquire the ilock */
		error = xfs_reflink_allocate_cow(ip, &imap, &cmap, &shared,
				&lockmode, flags & IOMAP_DIRECT);
		if (error)
			goto out_unlock;
		if (shared)
			goto out_found_cow;
		end_fsb = imap.br_startoff + imap.br_blockcount;
		length = XFS_FSB_TO_B(mp, end_fsb) - offset;
	}

	if (imap_needs_alloc(inode, flags, &imap, nimaps))
		goto allocate_blocks;

	/*
	 * NOWAIT IO needs to span the entire requested IO with a single map so
	 * that we avoid partial IO failures due to the rest of the IO range not
	 * covered by this map triggering an EAGAIN condition when it is
	 * subsequently mapped and aborting the IO.
	 */
	if ((flags & IOMAP_NOWAIT) &&
	    !imap_spans_range(&imap, offset_fsb, end_fsb)) {
		error = -EAGAIN;
		goto out_unlock;
	}

	seq = xfs_iomap_inode_sequence(ip, iomap_flags);
	xfs_iunlock(ip, lockmode);
	trace_xfs_iomap_found(ip, offset, length, XFS_DATA_FORK, &imap);
	return xfs_bmbt_to_iomap(ip, iomap, &imap, iomap_flags, seq);

allocate_blocks:
	error = -EAGAIN;
	if (flags & IOMAP_NOWAIT)
		goto out_unlock;

	/*
	 * We cap the maximum length we map to a sane size  to keep the chunks
	 * of work done where somewhat symmetric with the work writeback does.
	 * This is a completely arbitrary number pulled out of thin air as a
	 * best guess for initial testing.
	 *
	 * Note that the values needs to be less than 32-bits wide until the
	 * lower level functions are updated.
	 */
	length = min_t(loff_t, length, 1024 * PAGE_SIZE);
	end_fsb = xfs_iomap_end_fsb(mp, offset, length);

	if (offset + length > XFS_ISIZE(ip))
		end_fsb = xfs_iomap_eof_align_last_fsb(ip, end_fsb);
	else if (nimaps && imap.br_startblock == HOLESTARTBLOCK)
		end_fsb = min(end_fsb, imap.br_startoff + imap.br_blockcount);
	xfs_iunlock(ip, lockmode);

	error = xfs_iomap_write_direct(ip, offset_fsb, end_fsb - offset_fsb,
			&imap, &seq);
	if (error)
		return error;

	trace_xfs_iomap_alloc(ip, offset, length, XFS_DATA_FORK, &imap);
	return xfs_bmbt_to_iomap(ip, iomap, &imap, iomap_flags | IOMAP_F_NEW, seq);

out_found_cow:
	length = XFS_FSB_TO_B(mp, cmap.br_startoff + cmap.br_blockcount);
	trace_xfs_iomap_found(ip, offset, length - offset, XFS_COW_FORK, &cmap);
	if (imap.br_startblock != HOLESTARTBLOCK) {
		seq = xfs_iomap_inode_sequence(ip, 0);
		error = xfs_bmbt_to_iomap(ip, srcmap, &imap, 0, seq);
		if (error)
			goto out_unlock;
	}
	seq = xfs_iomap_inode_sequence(ip, IOMAP_F_SHARED);
	xfs_iunlock(ip, lockmode);
	return xfs_bmbt_to_iomap(ip, iomap, &cmap, IOMAP_F_SHARED, seq);

out_unlock:
	if (lockmode)
		xfs_iunlock(ip, lockmode);
	return error;
}

const struct iomap_ops xfs_direct_write_iomap_ops = {
	.iomap_begin		= xfs_direct_write_iomap_begin,
};

static int
xfs_buffered_write_iomap_begin(
	struct inode		*inode,
	loff_t			offset,
	loff_t			count,
	unsigned		flags,
	struct iomap		*iomap,
	struct iomap		*srcmap)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	xfs_fileoff_t		offset_fsb = XFS_B_TO_FSBT(mp, offset);
	xfs_fileoff_t		end_fsb = xfs_iomap_end_fsb(mp, offset, count);
	struct xfs_bmbt_irec	imap, cmap;
	struct xfs_iext_cursor	icur, ccur;
	xfs_fsblock_t		prealloc_blocks = 0;
	bool			eof = false, cow_eof = false, shared = false;
	int			allocfork = XFS_DATA_FORK;
	int			error = 0;
	u64			seq;

	if (xfs_is_shutdown(mp))
		return -EIO;

	/* we can't use delayed allocations when using extent size hints */
	if (xfs_get_extsz_hint(ip))
		return xfs_direct_write_iomap_begin(inode, offset, count,
				flags, iomap, srcmap);

	ASSERT(!XFS_IS_REALTIME_INODE(ip));

	error = xfs_qm_dqattach(ip);
	if (error)
		return error;

	xfs_ilock(ip, XFS_ILOCK_EXCL);

	if (XFS_IS_CORRUPT(mp, !xfs_ifork_has_extents(&ip->i_df)) ||
	    XFS_TEST_ERROR(false, mp, XFS_ERRTAG_BMAPIFORMAT)) {
		error = -EFSCORRUPTED;
		goto out_unlock;
	}

	XFS_STATS_INC(mp, xs_blk_mapw);

	if (!(ip->i_df.if_flags & XFS_IFEXTENTS)) {
		error = xfs_iread_extents(NULL, ip, XFS_DATA_FORK);
		if (error)
			goto out_unlock;
	}

	/*
	 * Search the data fork first to look up our source mapping.  We
	 * always need the data fork map, as we have to return it to the
	 * iomap code so that the higher level write code can read data in to
	 * perform read-modify-write cycles for unaligned writes.
	 */
	eof = !xfs_iext_lookup_extent(ip, &ip->i_df, offset_fsb, &icur, &imap);
	if (eof)
		imap.br_startoff = end_fsb; /* fake hole until the end */

	/* We never need to allocate blocks for zeroing a hole. */
	if ((flags & IOMAP_ZERO) && imap.br_startoff > offset_fsb) {
		xfs_hole_to_iomap(ip, iomap, offset_fsb, imap.br_startoff);
		goto out_unlock;
	}

	/*
	 * Search the COW fork extent list even if we did not find a data fork
	 * extent.  This serves two purposes: first this implements the
	 * speculative preallocation using cowextsize, so that we also unshare
	 * block adjacent to shared blocks instead of just the shared blocks
	 * themselves.  Second the lookup in the extent list is generally faster
	 * than going out to the shared extent tree.
	 */
	if (xfs_is_cow_inode(ip)) {
		if (!ip->i_cowfp) {
			ASSERT(!xfs_is_reflink_inode(ip));
			xfs_ifork_init_cow(ip);
		}
		cow_eof = !xfs_iext_lookup_extent(ip, ip->i_cowfp, offset_fsb,
				&ccur, &cmap);
		if (!cow_eof && cmap.br_startoff <= offset_fsb) {
			trace_xfs_reflink_cow_found(ip, &cmap);
			goto found_cow;
		}
	}

	if (imap.br_startoff <= offset_fsb) {
		/*
		 * For reflink files we may need a delalloc reservation when
		 * overwriting shared extents.   This includes zeroing of
		 * existing extents that contain data.
		 */
		if (!xfs_is_cow_inode(ip) ||
		    ((flags & IOMAP_ZERO) && imap.br_state != XFS_EXT_NORM)) {
			trace_xfs_iomap_found(ip, offset, count, XFS_DATA_FORK,
					&imap);
			goto found_imap;
		}

		xfs_trim_extent(&imap, offset_fsb, end_fsb - offset_fsb);

		/* Trim the mapping to the nearest shared extent boundary. */
		error = xfs_bmap_trim_cow(ip, &imap, &shared);
		if (error)
			goto out_unlock;

		/* Not shared?  Just report the (potentially capped) extent. */
		if (!shared) {
			trace_xfs_iomap_found(ip, offset, count, XFS_DATA_FORK,
					&imap);
			goto found_imap;
		}

		/*
		 * Fork all the shared blocks from our write offset until the
		 * end of the extent.
		 */
		allocfork = XFS_COW_FORK;
		end_fsb = imap.br_startoff + imap.br_blockcount;
	} else {
		/*
		 * We cap the maximum length we map here to MAX_WRITEBACK_PAGES
		 * pages to keep the chunks of work done where somewhat
		 * symmetric with the work writeback does.  This is a completely
		 * arbitrary number pulled out of thin air.
		 *
		 * Note that the values needs to be less than 32-bits wide until
		 * the lower level functions are updated.
		 */
		count = min_t(loff_t, count, 1024 * PAGE_SIZE);
		end_fsb = xfs_iomap_end_fsb(mp, offset, count);

		if (xfs_is_always_cow_inode(ip))
			allocfork = XFS_COW_FORK;
	}

	if (eof && offset + count > XFS_ISIZE(ip)) {
		/*
		 * Determine the initial size of the preallocation.
		 * We clean up any extra preallocation when the file is closed.
		 */
		if (xfs_has_allocsize(mp))
			prealloc_blocks = mp->m_allocsize_blocks;
		else
			prealloc_blocks = xfs_iomap_prealloc_size(ip, allocfork,
						offset, count, &icur);
		if (prealloc_blocks) {
			xfs_extlen_t	align;
			xfs_off_t	end_offset;
			xfs_fileoff_t	p_end_fsb;

			end_offset = XFS_ALLOC_ALIGN(mp, offset + count - 1);
			p_end_fsb = XFS_B_TO_FSBT(mp, end_offset) +
					prealloc_blocks;

			align = xfs_eof_alignment(ip);
			if (align)
				p_end_fsb = roundup_64(p_end_fsb, align);

			p_end_fsb = min(p_end_fsb,
				XFS_B_TO_FSB(mp, mp->m_super->s_maxbytes));
			ASSERT(p_end_fsb > offset_fsb);
			prealloc_blocks = p_end_fsb - end_fsb;
		}
	}

retry:
	error = xfs_bmapi_reserve_delalloc(ip, allocfork, offset_fsb,
			end_fsb - offset_fsb, prealloc_blocks,
			allocfork == XFS_DATA_FORK ? &imap : &cmap,
			allocfork == XFS_DATA_FORK ? &icur : &ccur,
			allocfork == XFS_DATA_FORK ? eof : cow_eof);
	switch (error) {
	case 0:
		break;
	case -ENOSPC:
	case -EDQUOT:
		/* retry without any preallocation */
		trace_xfs_delalloc_enospc(ip, offset, count);
		if (prealloc_blocks) {
			prealloc_blocks = 0;
			goto retry;
		}
		fallthrough;
	default:
		goto out_unlock;
	}

	if (allocfork == XFS_COW_FORK) {
		trace_xfs_iomap_alloc(ip, offset, count, allocfork, &cmap);
		goto found_cow;
	}

	/*
	 * Flag newly allocated delalloc blocks with IOMAP_F_NEW so we punch
	 * them out if the write happens to fail.
	 */
	seq = xfs_iomap_inode_sequence(ip, IOMAP_F_NEW);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	trace_xfs_iomap_alloc(ip, offset, count, allocfork, &imap);
	return xfs_bmbt_to_iomap(ip, iomap, &imap, IOMAP_F_NEW, seq);

found_imap:
	seq = xfs_iomap_inode_sequence(ip, 0);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return xfs_bmbt_to_iomap(ip, iomap, &imap, 0, seq);

found_cow:
	seq = xfs_iomap_inode_sequence(ip, 0);
	if (imap.br_startoff <= offset_fsb) {
		error = xfs_bmbt_to_iomap(ip, srcmap, &imap, 0, seq);
		if (error)
			goto out_unlock;
		seq = xfs_iomap_inode_sequence(ip, IOMAP_F_SHARED);
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
		return xfs_bmbt_to_iomap(ip, iomap, &cmap, IOMAP_F_SHARED, seq);
	}

	xfs_trim_extent(&cmap, offset_fsb, imap.br_startoff - offset_fsb);
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return xfs_bmbt_to_iomap(ip, iomap, &cmap, 0, seq);

out_unlock:
	xfs_iunlock(ip, XFS_ILOCK_EXCL);
	return error;
}

static int
xfs_buffered_write_delalloc_punch(
	struct inode		*inode,
	loff_t			offset,
	loff_t			length)
{
	return xfs_bmap_punch_delalloc_range(XFS_I(inode), offset,
			offset + length);
}

/*
 * Scan the data range passed to us for dirty page cache folios. If we find a
 * dirty folio, punch out the preceeding range and update the offset from which
 * the next punch will start from.
 *
 * We can punch out storage reservations under clean pages because they either
 * contain data that has been written back - in which case the delalloc punch
 * over that range is a no-op - or they have been read faults in which case they
 * contain zeroes and we can remove the delalloc backing range and any new
 * writes to those pages will do the normal hole filling operation...
 *
 * This makes the logic simple: we only need to keep the delalloc extents only
 * over the dirty ranges of the page cache.
 *
 * This function uses [start_byte, end_byte) intervals (i.e. open ended) to
 * simplify range iterations.
 */
static int
xfs_iomap_write_delalloc_scan(
	struct inode	*inode,
	loff_t		*punch_start_byte,
	loff_t		start_byte,
	loff_t		end_byte,
	int (*punch)(struct inode *inode, loff_t offset, loff_t length))
{
	while (start_byte < end_byte) {
		struct page	*page;

		/* grab locked page */
		page = find_lock_page(inode->i_mapping,
				start_byte >> PAGE_SHIFT);

		if (!page) {
			start_byte = ALIGN_DOWN(start_byte, PAGE_SIZE) +
					PAGE_SIZE;
			continue;
		}

		/* if dirty, punch up to offset */
		if (PageDirty(page)) {
			if (start_byte > *punch_start_byte) {
				int	error;

				error = punch(inode, *punch_start_byte,
						start_byte - *punch_start_byte);
				if (error) {
					unlock_page(page);
					put_page(page);
					return error;
				}
			}

			/*
			 * Make sure the next punch start is correctly bound to
			 * the end of this data range, not the end of the folio.
			 */
			*punch_start_byte = min_t(loff_t, end_byte,
				page_offset(page) + PAGE_SIZE);
		}

		/* move offset to start of next folio in range */
		start_byte = page_offset(page) + PAGE_SIZE;
		unlock_page(page);
		put_page(page);
	}
	return 0;
}

/*
 * Punch out all the delalloc blocks in the range given except for those that
 * have dirty data still pending in the page cache - those are going to be
 * written and so must still retain the delalloc backing for writeback.
 *
 * As we are scanning the page cache for data, we don't need to reimplement the
 * wheel - mapping_seek_hole_data() does exactly what we need to identify the
 * start and end of data ranges correctly even for sub-folio block sizes. This
 * byte range based iteration is especially convenient because it means we
 * don't have to care about variable size folios, nor where the start or end of
 * the data range lies within a folio, if they lie within the same folio or even
 * if there are multiple discontiguous data ranges within the folio.
 *
 * It should be noted that mapping_seek_hole_data() is not aware of EOF, and so
 * can return data ranges that exist in the cache beyond EOF. e.g. a page fault
 * spanning EOF will initialise the post-EOF data to zeroes and mark it up to
 * date. A write page fault can then mark it dirty. If we then fail a write()
 * beyond EOF into that up to date cached range, we allocate a delalloc block
 * beyond EOF and then have to punch it out. Because the range is up to date,
 * mapping_seek_hole_data() will return it, and we will skip the punch because
 * the folio is dirty. THis is incorrect - we always need to punch out delalloc
 * beyond EOF in this case as writeback will never write back and covert that
 * delalloc block beyond EOF. Hence we limit the cached data scan range to EOF,
 * resulting in always punching out the range from the EOF to the end of the
 * range the iomap spans.
 *
 * Intervals are of the form [start_byte, end_byte) (i.e. open ended) because it
 * matches the intervals returned by mapping_seek_hole_data(). i.e. SEEK_DATA
 * returns the start of a data range (start_byte), and SEEK_HOLE(start_byte)
 * returns the end of the data range (data_end). Using closed intervals would
 * require sprinkling this code with magic "+ 1" and "- 1" arithmetic and expose
 * the code to subtle off-by-one bugs....
 */
static int
xfs_iomap_write_delalloc_release(
	struct inode	*inode,
	loff_t		start_byte,
	loff_t		end_byte,
	int (*punch)(struct inode *inode, loff_t pos, loff_t length))
{
	struct xfs_inode *ip = XFS_I(inode);
	loff_t punch_start_byte = start_byte;
	loff_t scan_end_byte = min(i_size_read(inode), end_byte);
	int error = 0;

	/*
	 * Lock the mapping to avoid races with page faults re-instantiating
	 * folios and dirtying them via ->page_mkwrite whilst we walk the
	 * cache and perform delalloc extent removal. Failing to do this can
	 * leave dirty pages with no space reservation in the cache.
	 */
	xfs_ilock(ip, XFS_MMAPLOCK_EXCL);
	while (start_byte < scan_end_byte) {
		loff_t		data_end;

		start_byte = mapping_seek_hole_data(inode->i_mapping,
				start_byte, scan_end_byte, SEEK_DATA);
		/*
		 * If there is no more data to scan, all that is left is to
		 * punch out the remaining range.
		 */
		if (start_byte == -ENXIO || start_byte == scan_end_byte)
			break;
		if (start_byte < 0) {
			error = start_byte;
			goto out_unlock;
		}
		WARN_ON_ONCE(start_byte < punch_start_byte);
		WARN_ON_ONCE(start_byte > scan_end_byte);

		/*
		 * We find the end of this contiguous cached data range by
		 * seeking from start_byte to the beginning of the next hole.
		 */
		data_end = mapping_seek_hole_data(inode->i_mapping, start_byte,
				scan_end_byte, SEEK_HOLE);
		if (data_end < 0) {
			error = data_end;
			goto out_unlock;
		}
		WARN_ON_ONCE(data_end < start_byte);
		WARN_ON_ONCE(data_end > scan_end_byte);

		error = xfs_iomap_write_delalloc_scan(inode, &punch_start_byte,
				start_byte, data_end, punch);
		if (error)
			goto out_unlock;

		/* The next data search starts at the end of this one. */
		start_byte = data_end;
	}

	if (punch_start_byte < end_byte)
		error = punch(inode, punch_start_byte,
				end_byte - punch_start_byte);
out_unlock:
	xfs_iunlock(ip, XFS_MMAPLOCK_EXCL);
	return error;
}

/*
 * When a short write occurs, the filesystem may need to remove reserved space
 * that was allocated in ->iomap_begin from it's ->iomap_end method. For
 * filesystems that use delayed allocation, we need to punch out delalloc
 * extents from the range that are not dirty in the page cache. As the write can
 * race with page faults, there can be dirty pages over the delalloc extent
 * outside the range of a short write but still within the delalloc extent
 * allocated for this iomap.
 *
 * This function uses [start_byte, end_byte) intervals (i.e. open ended) to
 * simplify range iterations.
 *
 * The punch() callback *must* only punch delalloc extents in the range passed
 * to it. It must skip over all other types of extents in the range and leave
 * them completely unchanged. It must do this punch atomically with respect to
 * other extent modifications.
 *
 * The punch() callback may be called with a folio locked to prevent writeback
 * extent allocation racing at the edge of the range we are currently punching.
 * The locked folio may or may not cover the range being punched, so it is not
 * safe for the punch() callback to lock folios itself.
 *
 * Lock order is:
 *
 * inode->i_rwsem (shared or exclusive)
 *   inode->i_mapping->invalidate_lock (exclusive)
 *     folio_lock()
 *       ->punch
 *         internal filesystem allocation lock
 */
static int
xfs_iomap_file_buffered_write_punch_delalloc(
		struct inode		*inode,
		struct iomap		*iomap,
		loff_t			pos,
		loff_t			length,
		ssize_t			written,
		int (*punch)(struct inode *inode, loff_t pos, loff_t length))
{
	loff_t			start_byte;
	loff_t			end_byte;
	int			blocksize = i_blocksize(inode);

	if (iomap->type != IOMAP_DELALLOC)
		return 0;

	/* If we didn't reserve the blocks, we're not allowed to punch them. */
	if (!(iomap->flags & IOMAP_F_NEW))
		return 0;

	/*
	 * start_byte refers to the first unused block after a short write. If
	 * nothing was written, round offset down to point at the first block in
	 * the range.
	 */
	if (unlikely(!written))
		start_byte = round_down(pos, blocksize);
	else
		start_byte = round_up(pos + written, blocksize);
	end_byte = round_up(pos + length, blocksize);

	/* Nothing to do if we've written the entire delalloc extent */
	if (start_byte >= end_byte)
		return 0;

	return xfs_iomap_write_delalloc_release(inode, start_byte, end_byte,
					punch);
}

static int
xfs_buffered_write_iomap_end(
	struct inode		*inode,
	loff_t			offset,
	loff_t			length,
	ssize_t			written,
	unsigned		flags,
	struct iomap		*iomap)
{
	struct xfs_mount	*mp = XFS_M(inode->i_sb);
	int			error;

	/*
	 * Behave as if the write failed if drop writes is enabled. Set the NEW
	 * flag to force delalloc cleanup.
	 */
	if (XFS_TEST_ERROR(false, mp, XFS_ERRTAG_DROP_WRITES)) {
		iomap->flags |= IOMAP_F_NEW;
		written = 0;
	}

	error = xfs_iomap_file_buffered_write_punch_delalloc(inode, iomap, offset,
			length, written, &xfs_buffered_write_delalloc_punch);
	if (error && !xfs_is_shutdown(mp)) {
		xfs_alert(mp, "%s: unable to clean up ino 0x%llx",
			__func__, XFS_I(inode)->i_ino);
		return error;
	}
	return 0;
}

const struct iomap_ops xfs_buffered_write_iomap_ops = {
	.iomap_begin		= xfs_buffered_write_iomap_begin,
	.iomap_end		= xfs_buffered_write_iomap_end,
};

/*
 * iomap_page_mkwrite() will never fail in a way that requires delalloc extents
 * that it allocated to be revoked. Hence we do not need an .iomap_end method
 * for this operation.
 */
const struct iomap_ops xfs_page_mkwrite_iomap_ops = {
	.iomap_begin		= xfs_buffered_write_iomap_begin,
};

static int
xfs_read_iomap_begin(
	struct inode		*inode,
	loff_t			offset,
	loff_t			length,
	unsigned		flags,
	struct iomap		*iomap,
	struct iomap		*srcmap)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_bmbt_irec	imap;
	xfs_fileoff_t		offset_fsb = XFS_B_TO_FSBT(mp, offset);
	xfs_fileoff_t		end_fsb = xfs_iomap_end_fsb(mp, offset, length);
	int			nimaps = 1, error = 0;
	bool			shared = false;
	unsigned		lockmode;
	u64			seq;

	ASSERT(!(flags & (IOMAP_WRITE | IOMAP_ZERO)));

	if (xfs_is_shutdown(mp))
		return -EIO;

	error = xfs_ilock_for_iomap(ip, flags, &lockmode);
	if (error)
		return error;
	error = xfs_bmapi_read(ip, offset_fsb, end_fsb - offset_fsb, &imap,
			       &nimaps, 0);
	if (!error && (flags & IOMAP_REPORT))
		error = xfs_reflink_trim_around_shared(ip, &imap, &shared);
	seq = xfs_iomap_inode_sequence(ip, shared ? IOMAP_F_SHARED : 0);
	xfs_iunlock(ip, lockmode);

	if (error)
		return error;
	trace_xfs_iomap_found(ip, offset, length, XFS_DATA_FORK, &imap);
	return xfs_bmbt_to_iomap(ip, iomap, &imap,
				 shared ? IOMAP_F_SHARED : 0, seq);
}

const struct iomap_ops xfs_read_iomap_ops = {
	.iomap_begin		= xfs_read_iomap_begin,
};

static int
xfs_seek_iomap_begin(
	struct inode		*inode,
	loff_t			offset,
	loff_t			length,
	unsigned		flags,
	struct iomap		*iomap,
	struct iomap		*srcmap)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	xfs_fileoff_t		offset_fsb = XFS_B_TO_FSBT(mp, offset);
	xfs_fileoff_t		end_fsb = XFS_B_TO_FSB(mp, offset + length);
	xfs_fileoff_t		cow_fsb = NULLFILEOFF, data_fsb = NULLFILEOFF;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	imap, cmap;
	int			error = 0;
	unsigned		lockmode;
	u64			seq;

	if (xfs_is_shutdown(mp))
		return -EIO;

	lockmode = xfs_ilock_data_map_shared(ip);
	if (!(ip->i_df.if_flags & XFS_IFEXTENTS)) {
		error = xfs_iread_extents(NULL, ip, XFS_DATA_FORK);
		if (error)
			goto out_unlock;
	}

	if (xfs_iext_lookup_extent(ip, &ip->i_df, offset_fsb, &icur, &imap)) {
		/*
		 * If we found a data extent we are done.
		 */
		if (imap.br_startoff <= offset_fsb)
			goto done;
		data_fsb = imap.br_startoff;
	} else {
		/*
		 * Fake a hole until the end of the file.
		 */
		data_fsb = xfs_iomap_end_fsb(mp, offset, length);
	}

	/*
	 * If a COW fork extent covers the hole, report it - capped to the next
	 * data fork extent:
	 */
	if (xfs_inode_has_cow_data(ip) &&
	    xfs_iext_lookup_extent(ip, ip->i_cowfp, offset_fsb, &icur, &cmap))
		cow_fsb = cmap.br_startoff;
	if (cow_fsb != NULLFILEOFF && cow_fsb <= offset_fsb) {
		if (data_fsb < cow_fsb + cmap.br_blockcount)
			end_fsb = min(end_fsb, data_fsb);
		xfs_trim_extent(&cmap, offset_fsb, end_fsb);
		seq = xfs_iomap_inode_sequence(ip, IOMAP_F_SHARED);
		error = xfs_bmbt_to_iomap(ip, iomap, &cmap, IOMAP_F_SHARED, seq);
		/*
		 * This is a COW extent, so we must probe the page cache
		 * because there could be dirty page cache being backed
		 * by this extent.
		 */
		iomap->type = IOMAP_UNWRITTEN;
		goto out_unlock;
	}

	/*
	 * Else report a hole, capped to the next found data or COW extent.
	 */
	if (cow_fsb != NULLFILEOFF && cow_fsb < data_fsb)
		imap.br_blockcount = cow_fsb - offset_fsb;
	else
		imap.br_blockcount = data_fsb - offset_fsb;
	imap.br_startoff = offset_fsb;
	imap.br_startblock = HOLESTARTBLOCK;
	imap.br_state = XFS_EXT_NORM;
done:
	seq = xfs_iomap_inode_sequence(ip, 0);
	xfs_trim_extent(&imap, offset_fsb, end_fsb);
	error = xfs_bmbt_to_iomap(ip, iomap, &imap, 0, seq);
out_unlock:
	xfs_iunlock(ip, lockmode);
	return error;
}

const struct iomap_ops xfs_seek_iomap_ops = {
	.iomap_begin		= xfs_seek_iomap_begin,
};

static int
xfs_xattr_iomap_begin(
	struct inode		*inode,
	loff_t			offset,
	loff_t			length,
	unsigned		flags,
	struct iomap		*iomap,
	struct iomap		*srcmap)
{
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	xfs_fileoff_t		offset_fsb = XFS_B_TO_FSBT(mp, offset);
	xfs_fileoff_t		end_fsb = XFS_B_TO_FSB(mp, offset + length);
	struct xfs_bmbt_irec	imap;
	int			nimaps = 1, error = 0;
	unsigned		lockmode;
	int			seq;

	if (xfs_is_shutdown(mp))
		return -EIO;

	lockmode = xfs_ilock_attr_map_shared(ip);

	/* if there are no attribute fork or extents, return ENOENT */
	if (!xfs_inode_has_attr_fork(ip) || !ip->i_af.if_nextents) {
		error = -ENOENT;
		goto out_unlock;
	}

	ASSERT(ip->i_af.if_format != XFS_DINODE_FMT_LOCAL);
	error = xfs_bmapi_read(ip, offset_fsb, end_fsb - offset_fsb, &imap,
			       &nimaps, XFS_BMAPI_ATTRFORK);
out_unlock:

	seq = xfs_iomap_inode_sequence(ip, IOMAP_F_XATTR);
	xfs_iunlock(ip, lockmode);

	if (error)
		return error;
	ASSERT(nimaps);
	return xfs_bmbt_to_iomap(ip, iomap, &imap, 0, seq);
}

const struct iomap_ops xfs_xattr_iomap_ops = {
	.iomap_begin		= xfs_xattr_iomap_begin,
};
