/* SPDX-License-Identifier: GPL-2.0 */
/* XDP user-space ring structure
 * Copyright(c) 2018 Intel Corporation.
 */

#ifndef _LINUX_XSK_QUEUE_H
#define _LINUX_XSK_QUEUE_H

#include <linux/types.h>
#include <linux/if_xdp.h>
#include <net/xdp_sock.h>
#include <net/xsk_buff_pool.h>

#include "xsk.h"

struct xdp_ring {
	u32 producer ____cacheline_aligned_in_smp;
	/* Hinder the adjacent cache prefetcher to prefetch the consumer
	 * pointer if the producer pointer is touched and vice versa.
	 */
	u32 pad ____cacheline_aligned_in_smp;
	u32 consumer ____cacheline_aligned_in_smp;
	u32 flags;
};

/* Used for the RX and TX queues for packets */
struct xdp_rxtx_ring {
	struct xdp_ring ptrs;
	struct xdp_desc desc[] ____cacheline_aligned_in_smp;
};

/* Used for the fill and completion queues for buffers */
struct xdp_umem_ring {
	struct xdp_ring ptrs;
	u64 desc[] ____cacheline_aligned_in_smp;
};

struct xsk_queue {
	u32 ring_mask;
	u32 nentries;
	u32 cached_prod;
	u32 cached_cons;
	struct xdp_ring *ring;
	u64 invalid_descs;
	u64 queue_empty_descs;
};

/* The structure of the shared state of the rings are the same as the
 * ring buffer in kernel/events/ring_buffer.c. For the Rx and completion
 * ring, the kernel is the producer and user space is the consumer. For
 * the Tx and fill rings, the kernel is the consumer and user space is
 * the producer.
 *
 * producer                         consumer
 *
 * if (LOAD ->consumer) {           LOAD ->producer
 *                    (A)           smp_rmb()       (C)
 *    STORE $data                   LOAD $data
 *    smp_wmb()       (B)           smp_mb()        (D)
 *    STORE ->producer              STORE ->consumer
 * }
 *
 * (A) pairs with (D), and (B) pairs with (C).
 *
 * Starting with (B), it protects the data from being written after
 * the producer pointer. If this barrier was missing, the consumer
 * could observe the producer pointer being set and thus load the data
 * before the producer has written the new data. The consumer would in
 * this case load the old data.
 *
 * (C) protects the consumer from speculatively loading the data before
 * the producer pointer actually has been read. If we do not have this
 * barrier, some architectures could load old data as speculative loads
 * are not discarded as the CPU does not know there is a dependency
 * between ->producer and data.
 *
 * (A) is a control dependency that separates the load of ->consumer
 * from the stores of $data. In case ->consumer indicates there is no
 * room in the buffer to store $data we do not. So no barrier is needed.
 *
 * (D) protects the load of the data to be observed to happen after the
 * store of the consumer pointer. If we did not have this memory
 * barrier, the producer could observe the consumer pointer being set
 * and overwrite the data with a new value before the consumer got the
 * chance to read the old value. The consumer would thus miss reading
 * the old entry and very likely read the new entry twice, once right
 * now and again after circling through the ring.
 */

/* The operations on the rings are the following:
 *
 * producer                           consumer
 *
 * RESERVE entries                    PEEK in the ring for entries
 * WRITE data into the ring           READ data from the ring
 * SUBMIT entries                     RELEASE entries
 *
 * The producer reserves one or more entries in the ring. It can then
 * fill in these entries and finally submit them so that they can be
 * seen and read by the consumer.
 *
 * The consumer peeks into the ring to see if the producer has written
 * any new entries. If so, the consumer can then read these entries
 * and when it is done reading them release them back to the producer
 * so that the producer can use these slots to fill in new entries.
 *
 * The function names below reflect these operations.
 */

/* Functions that read and validate content from consumer rings. */

static inline bool xskq_cons_read_addr_unchecked(struct xsk_queue *q, u64 *addr)
{
	struct xdp_umem_ring *ring = (struct xdp_umem_ring *)q->ring;

	if (q->cached_cons != q->cached_prod) {
		u32 idx = q->cached_cons & q->ring_mask;

		*addr = ring->desc[idx];
		return true;
	}

	return false;
}

#ifdef CONFIG_XSK_MULTI_BUF
static inline bool xp_unused_options_set(u32 options)
{
	return options & ~XDP_PKT_CONTD;
}
#endif

static inline bool xp_aligned_validate_desc(struct xsk_buff_pool *pool,
					    struct xdp_desc *desc)
{
	u64 chunk, chunk_end;

	chunk = xp_aligned_extract_addr(pool, desc->addr);
	if (likely(desc->len)) {
		chunk_end = xp_aligned_extract_addr(pool, desc->addr + desc->len - 1);
		if (chunk != chunk_end)
			return false;
	}

	if (chunk >= pool->addrs_cnt)
		return false;

#ifdef CONFIG_XSK_MULTI_BUF
	if (xp_unused_options_set(desc->options))
#else
	if (desc->options)
#endif
		return false;
	return true;
}

static inline bool xp_unaligned_validate_desc(struct xsk_buff_pool *pool,
					      struct xdp_desc *desc)
{
	u64 addr, base_addr;

	base_addr = xp_unaligned_extract_addr(desc->addr);
	addr = xp_unaligned_add_offset_to_addr(desc->addr);

	if (desc->len > pool->chunk_size)
		return false;

	if (base_addr >= pool->addrs_cnt || addr >= pool->addrs_cnt ||
	    addr + desc->len > pool->addrs_cnt ||
	    xp_desc_crosses_non_contig_pg(pool, addr, desc->len))
		return false;

#ifdef CONFIG_XSK_MULTI_BUF
	if (xp_unused_options_set(desc->options))
#else
	if (desc->options)
#endif
		return false;
	return true;
}

static inline bool xp_validate_desc(struct xsk_buff_pool *pool,
				    struct xdp_desc *desc)
{
	return pool->unaligned ? xp_unaligned_validate_desc(pool, desc) :
		xp_aligned_validate_desc(pool, desc);
}

#ifdef CONFIG_XSK_MULTI_BUF
static inline bool xskq_has_descs(struct xsk_queue *q)
{
	return q->cached_cons != q->cached_prod;
}
#endif

static inline bool xskq_cons_is_valid_desc(struct xsk_queue *q,
					   struct xdp_desc *d,
					   struct xsk_buff_pool *pool)
{
	if (!xp_validate_desc(pool, d)) {
		q->invalid_descs++;
		return false;
	}
	return true;
}

static inline bool xskq_cons_read_desc(struct xsk_queue *q,
				       struct xdp_desc *desc,
				       struct xsk_buff_pool *pool)
{
	while (q->cached_cons != q->cached_prod) {
		struct xdp_rxtx_ring *ring = (struct xdp_rxtx_ring *)q->ring;
		u32 idx = q->cached_cons & q->ring_mask;

		*desc = ring->desc[idx];
		if (xskq_cons_is_valid_desc(q, desc, pool))
			return true;

		q->cached_cons++;
	}

	return false;
}

/* Functions for consumers */

static inline void __xskq_cons_release(struct xsk_queue *q)
{
	smp_mb(); /* D, matches A */
	WRITE_ONCE(q->ring->consumer, q->cached_cons);
}

static inline void __xskq_cons_peek(struct xsk_queue *q)
{
	/* Refresh the local pointer */
	q->cached_prod = READ_ONCE(q->ring->producer);
	smp_rmb(); /* C, matches B */
}

static inline void xskq_cons_get_entries(struct xsk_queue *q)
{
	__xskq_cons_release(q);
	__xskq_cons_peek(q);
}

static inline bool xskq_cons_has_entries(struct xsk_queue *q, u32 cnt)
{
	u32 entries = q->cached_prod - q->cached_cons;

	if (entries >= cnt)
		return true;

	__xskq_cons_peek(q);
	entries = q->cached_prod - q->cached_cons;

	return entries >= cnt;
}

static inline bool xskq_cons_peek_addr_unchecked(struct xsk_queue *q, u64 *addr)
{
	if (q->cached_prod == q->cached_cons)
		xskq_cons_get_entries(q);
	return xskq_cons_read_addr_unchecked(q, addr);
}

static inline bool xskq_cons_peek_desc(struct xsk_queue *q,
				       struct xdp_desc *desc,
				       struct xsk_buff_pool *pool)
{
	if (q->cached_prod == q->cached_cons)
		xskq_cons_get_entries(q);
	return xskq_cons_read_desc(q, desc, pool);
}

static inline void xskq_cons_release(struct xsk_queue *q)
{
	/* To improve performance, only update local state here.
	 * Reflect this to global state when we get new entries
	 * from the ring in xskq_cons_get_entries() and whenever
	 * Rx or Tx processing are completed in the NAPI loop.
	 */
	q->cached_cons++;
}

static inline bool xskq_cons_is_full(struct xsk_queue *q)
{
	/* No barriers needed since data is not accessed */
	return READ_ONCE(q->ring->producer) - READ_ONCE(q->ring->consumer) ==
		q->nentries;
}

#ifdef CONFIG_XSK_MULTI_BUF
static inline void xskq_cons_cancel_n(struct xsk_queue *q, u32 cnt)
{
	q->cached_cons -= cnt;
}
#endif

static inline u32 xskq_cons_present_entries(struct xsk_queue *q)
{
	/* No barriers needed since data is not accessed */
	return READ_ONCE(q->ring->producer) - READ_ONCE(q->ring->consumer);
}

/* Functions for producers */

#ifdef CONFIG_XSK_MULTI_BUF
static inline u32 xskq_prod_nb_free(struct xsk_queue *q, u32 max)
{
	u32 free_entries = q->nentries - (q->cached_prod - q->cached_cons);

	if (free_entries >= max)
		return max;

	/* Refresh the local tail pointer */
	q->cached_cons = READ_ONCE(q->ring->consumer);
	free_entries = q->nentries - (q->cached_prod - q->cached_cons);

	return free_entries >= max ? max : free_entries;
}

static inline bool xskq_prod_is_full(struct xsk_queue *q)
{
	return xskq_prod_nb_free(q, 1) ? false : true;
}

static inline void xskq_prod_cancel_n(struct xsk_queue *q, u32 cnt)
{
	q->cached_prod -= cnt;
}

#else
static inline bool xskq_prod_is_full(struct xsk_queue *q)
{
	u32 free_entries = q->nentries - (q->cached_prod - q->cached_cons);

	if (free_entries)
		return false;

	/* Refresh the local tail pointer */
	q->cached_cons = READ_ONCE(q->ring->consumer);
	free_entries = q->nentries - (q->cached_prod - q->cached_cons);

	return !free_entries;
}
#endif

static inline void xskq_prod_cancel(struct xsk_queue *q)
{
	q->cached_prod--;
}

static inline int xskq_prod_reserve(struct xsk_queue *q)
{
	if (xskq_prod_is_full(q))
		return -ENOSPC;

	/* A, matches D */
	q->cached_prod++;
	return 0;
}

static inline int xskq_prod_reserve_addr(struct xsk_queue *q, u64 addr)
{
	struct xdp_umem_ring *ring = (struct xdp_umem_ring *)q->ring;

	if (xskq_prod_is_full(q))
		return -ENOSPC;

	/* A, matches D */
	ring->desc[q->cached_prod++ & q->ring_mask] = addr;
	return 0;
}

#ifdef CONFIG_XSK_MULTI_BUF
static inline int xskq_prod_reserve_desc_op(struct xsk_queue *q,
					    u64 addr, u32 len, u32 flags)
{
	struct xdp_rxtx_ring *ring = (struct xdp_rxtx_ring *)q->ring;
	u32 idx;

	if (xskq_prod_is_full(q))
		return -ENOSPC;

	/* A, matches D */
	idx = q->cached_prod++ & q->ring_mask;
	ring->desc[idx].addr = addr;
	ring->desc[idx].len = len;
	ring->desc[idx].options = flags;

	return 0;
}
#endif

static inline int xskq_prod_reserve_desc(struct xsk_queue *q,
					 u64 addr, u32 len)
{
	struct xdp_rxtx_ring *ring = (struct xdp_rxtx_ring *)q->ring;
	u32 idx;

	if (xskq_prod_is_full(q))
		return -ENOSPC;

	/* A, matches D */
	idx = q->cached_prod++ & q->ring_mask;
	ring->desc[idx].addr = addr;
	ring->desc[idx].len = len;

	return 0;
}

static inline void __xskq_prod_submit(struct xsk_queue *q, u32 idx)
{
	smp_wmb(); /* B, matches C */

	WRITE_ONCE(q->ring->producer, idx);
}

static inline void xskq_prod_submit(struct xsk_queue *q)
{
	__xskq_prod_submit(q, q->cached_prod);
}

static inline void xskq_prod_submit_addr(struct xsk_queue *q, u64 addr)
{
	struct xdp_umem_ring *ring = (struct xdp_umem_ring *)q->ring;
	u32 idx = q->ring->producer;

	ring->desc[idx++ & q->ring_mask] = addr;

	__xskq_prod_submit(q, idx);
}

static inline void xskq_prod_submit_n(struct xsk_queue *q, u32 nb_entries)
{
	__xskq_prod_submit(q, q->ring->producer + nb_entries);
}

static inline bool xskq_prod_is_empty(struct xsk_queue *q)
{
	/* No barriers needed since data is not accessed */
	return READ_ONCE(q->ring->consumer) == READ_ONCE(q->ring->producer);
}

/* For both producers and consumers */

static inline u64 xskq_nb_invalid_descs(struct xsk_queue *q)
{
	return q ? q->invalid_descs : 0;
}

static inline u64 xskq_nb_queue_empty_descs(struct xsk_queue *q)
{
	return q ? q->queue_empty_descs : 0;
}

struct xsk_queue *xskq_create(u32 nentries, bool umem_queue);
void xskq_destroy(struct xsk_queue *q_ops);

#endif /* _LINUX_XSK_QUEUE_H */
