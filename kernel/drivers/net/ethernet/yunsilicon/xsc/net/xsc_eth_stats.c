// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/types.h>
#include "common/xsc_cmd.h"
#include "common/xsc_core.h"

#include "xsc_eth_stats.h"
#include "xsc_eth.h"

static const struct counter_desc sw_stats_desc[] = {
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_inner_packets) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_tso_inner_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_unnecessary) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_none) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_csum_succ) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_csum_partial) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_csum_partial_inner) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_queue_stopped) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_queue_dropped) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_xmit_more) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_cqes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_queue_wake) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_cqe_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_oversize_pkts_sw_drop) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_dim_us) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, tx_dim_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, txdone_skb_null) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, txdone_skb_refcnt_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cqes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cqe_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_wqes) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_wqe_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_dim_us) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_dim_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_oversize_pkts_sw_drop) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_oversize_pkts_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_buff_alloc_err) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_reuse) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_full) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_empty) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_busy) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_alloc) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_waive) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_ext) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, rx_cache_rdc) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_events) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_0) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_1_63) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_64_511) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_512_1023) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_1024) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_poll_tx) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_arm) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_noarm) },
	{ XSC_DECLARE_STAT(struct xsc_sw_stats, ch_aff_change) },
};

#define NUM_SW_COUNTERS			ARRAY_SIZE(sw_stats_desc)

static int xsc_grp_sw_get_num_stats(struct xsc_adapter *adapter)
{
	return NUM_SW_COUNTERS;
}

static int xsc_grp_sw_fill_strings(struct xsc_adapter *adapter, u8 *data, int idx)
{
	int i;

	for (i = 0; i < NUM_SW_COUNTERS; i++)
		strscpy(data + (idx++) * ETH_GSTRING_LEN,
			sw_stats_desc[i].format,
			ETH_GSTRING_LEN);
	return idx;
}

static int xsc_grp_sw_fill_stats(struct xsc_adapter *adapter, u64 *data, int idx)
{
	int i;

	for (i = 0; i < NUM_SW_COUNTERS; i++)
		data[idx++] = XSC_READ_CTR64_CPU(&adapter->stats->sw, sw_stats_desc, i);
	return idx;
}

static void xsc_grp_sw_update_stats(struct xsc_adapter *adapter)
{
	struct xsc_sw_stats *s = &adapter->stats->sw;
	int max_tc = xsc_get_netdev_max_tc(adapter);
	int i;

	memset(s, 0, sizeof(*s));

	for (i = 0; i < xsc_get_netdev_max_channels(adapter); i++) {
		struct xsc_channel_stats *channel_stats =
			&adapter->stats->channel_stats[i];

		struct xsc_rq_stats *rq_stats = &channel_stats->rq;
		struct xsc_ch_stats *ch_stats = &channel_stats->ch;
		int j;

		s->rx_packets	+= rq_stats->packets;
		s->rx_bytes	+= rq_stats->bytes;
		s->rx_csum_unnecessary += rq_stats->csum_unnecessary;
		s->rx_csum_none	+= rq_stats->csum_none;
		s->rx_csum_err += rq_stats->csum_err;
		s->rx_csum_succ += rq_stats->csum_succ;
		s->rx_cqes	+= rq_stats->cqes;
		s->rx_cqe_err   += rq_stats->cqe_err;
		s->rx_wqes	+= rq_stats->wqes;
		s->rx_wqe_err   += rq_stats->wqe_err;
		s->rx_oversize_pkts_sw_drop += rq_stats->oversize_pkts_sw_drop;
		s->rx_oversize_pkts_err += rq_stats->oversize_pkts_err;
		s->rx_buff_alloc_err += rq_stats->buff_alloc_err;
		s->rx_cache_reuse += rq_stats->cache_reuse;
		s->rx_cache_full += rq_stats->cache_full;
		s->rx_cache_empty += rq_stats->cache_empty;
		s->rx_cache_busy += rq_stats->cache_busy;
		s->rx_cache_alloc += rq_stats->cache_alloc;
		s->rx_cache_waive += rq_stats->cache_waive;
		s->rx_cache_ext += rq_stats->cache_ext;
		s->rx_cache_rdc += rq_stats->cache_rdc;
		s->rx_dim_us += rq_stats->dim_us;
		s->rx_dim_pkts += rq_stats->dim_pkts;

		s->ch_events		+= ch_stats->events;
		s->ch_poll		+= ch_stats->poll;
		s->ch_poll_0		+= ch_stats->poll_0;
		s->ch_poll_1_63		+= ch_stats->poll_1_63;
		s->ch_poll_64_511	+= ch_stats->poll_64_511;
		s->ch_poll_512_1023	+= ch_stats->poll_512_1023;
		s->ch_poll_1024		+= ch_stats->poll_1024;
		s->ch_poll_tx		+= ch_stats->poll_tx;
		s->ch_arm		+= ch_stats->arm;
		s->ch_noarm		+= ch_stats->noarm;
		s->ch_aff_change	+= ch_stats->aff_change;

		for (j = 0; j < max_tc; j++) {
			struct xsc_sq_stats *sq_stats = &channel_stats->sq[j];

			s->tx_packets		+= sq_stats->packets;
			s->tx_bytes		+= sq_stats->bytes;
			s->tx_tso_packets	+= sq_stats->tso_packets;
			s->tx_tso_bytes		+= sq_stats->tso_bytes;
			s->tx_tso_inner_packets	+= sq_stats->tso_inner_packets;
			s->tx_tso_inner_bytes	+= sq_stats->tso_inner_bytes;
			s->tx_csum_partial	+= sq_stats->csum_partial;
			s->tx_csum_partial_inner += sq_stats->csum_partial_inner;
			s->tx_csum_none		+= sq_stats->csum_none;
			s->tx_queue_stopped	+= sq_stats->stopped;
			s->tx_queue_dropped	+= sq_stats->dropped;
			s->tx_xmit_more		+= sq_stats->xmit_more;
			s->tx_cqes		+= sq_stats->cqes;
			s->tx_queue_wake	+= sq_stats->wake;
			s->tx_cqe_err		+= sq_stats->cqe_err;
			s->tx_oversize_pkts_sw_drop += sq_stats->oversize_pkts_sw_drop;
			s->txdone_skb_null += sq_stats->txdone_skb_null;
			s->txdone_skb_refcnt_err += sq_stats->txdone_skb_refcnt_err;
			s->skb_linear += sq_stats->skb_linear;
			s->tx_dim_us += sq_stats->dim_us;
			s->tx_dim_pkts += sq_stats->dim_pkts;
		}
	}
}

static const struct counter_desc rq_stats_desc[] = {
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, packets) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, bytes) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_unnecessary) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_none) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, csum_succ) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cqes) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, dim_us) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, dim_pkts) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, wqe_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, oversize_pkts_sw_drop) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, oversize_pkts_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, buff_alloc_err) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_reuse) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_full) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_empty) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_busy) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_alloc) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_waive) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_ext) },
	{ XSC_DECLARE_RX_STAT(struct xsc_rq_stats, cache_rdc) },
};

static const struct counter_desc sq_stats_desc[] = {
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, packets) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, bytes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_packets) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_bytes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_inner_packets) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, tso_inner_bytes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, csum_partial) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, csum_partial_inner) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, csum_none) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, stopped) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, dropped) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, xmit_more) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, cqes) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, wake) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, dim_us) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, dim_pkts) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, cqe_err) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, oversize_pkts_sw_drop) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, txdone_skb_null) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, txdone_skb_refcnt_err) },
	{ XSC_DECLARE_TX_STAT(struct xsc_sq_stats, skb_linear) },
};

static const struct counter_desc ch_stats_desc[] = {
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, events) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_0) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_1_63) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_64_511) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_512_1023) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_1024) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, poll_tx) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, arm) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, noarm) },
	{ XSC_DECLARE_CH_STAT(struct xsc_ch_stats, aff_change) },
};

#define NUM_RQ_STATS			ARRAY_SIZE(rq_stats_desc)
#define NUM_SQ_STATS			ARRAY_SIZE(sq_stats_desc)
#define NUM_CH_STATS			ARRAY_SIZE(ch_stats_desc)

static int xsc_grp_channels_get_num_stats(struct xsc_adapter *adapter)
{
	int max_nch = xsc_get_netdev_max_channels(adapter);
	int max_tc = xsc_get_netdev_max_tc(adapter);

	return (NUM_RQ_STATS * max_nch) +
	       (NUM_CH_STATS * max_nch) +
	       (NUM_SQ_STATS * max_nch * max_tc);
}

static int xsc_grp_channels_fill_strings(struct xsc_adapter *adapter, u8 *data,
					 int idx)
{
	int max_nch = xsc_get_netdev_max_channels(adapter);
	int max_tc = xsc_get_netdev_max_tc(adapter);
	int i, j, tc;

	for (i = 0; i < max_nch; i++)
		for (j = 0; j < NUM_CH_STATS; j++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN,
				ch_stats_desc[j].format, i);

	for (i = 0; i < max_nch; i++) {
		for (j = 0; j < NUM_RQ_STATS; j++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN,
				rq_stats_desc[j].format, i);
	}

	for (tc = 0; tc < max_tc; tc++)
		for (i = 0; i < max_nch; i++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				sprintf(data + (idx++) * ETH_GSTRING_LEN,
					sq_stats_desc[j].format,
					i + tc * max_nch);

	return idx;
}

static int xsc_grp_channels_fill_stats(struct xsc_adapter *adapter, u64 *data,
				       int idx)
{
	int max_nch = xsc_get_netdev_max_channels(adapter);
	int max_tc = xsc_get_netdev_max_tc(adapter);
	int i, j, tc;
	struct xsc_stats *stats = adapter->stats;

	for (i = 0; i < max_nch; i++)
		for (j = 0; j < NUM_CH_STATS; j++)
			data[idx++] =
				XSC_READ_CTR64_CPU(&stats->channel_stats[i].ch,
						   ch_stats_desc, j);

	for (i = 0; i < max_nch; i++) {
		for (j = 0; j < NUM_RQ_STATS; j++)
			data[idx++] =
				XSC_READ_CTR64_CPU(&stats->channel_stats[i].rq,
						   rq_stats_desc, j);
	}

	for (tc = 0; tc < max_tc; tc++)
		for (i = 0; i < max_nch; i++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				data[idx++] =
					XSC_READ_CTR64_CPU(&stats->channel_stats[i].sq[tc],
							   sq_stats_desc, j);

	return idx;
}

static const struct counter_desc hw_prio_stats_desc[] = {
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  0),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  1),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  2),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  3),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  4),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  5),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  6),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_bytes, 7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_bytes, 7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, tx_pkts,  7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_prio_stats, rx_pkts,  7),

};

static const struct counter_desc hw_pfc_prio_stats_desc[] = {
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  0),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  0),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  1),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  1),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  2),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  2),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  3),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  3),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  4),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  4),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  5),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  5),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  6),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  6),

	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause, 7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, tx_pause_duration, 7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause,  7),
	XSC_DECLARE_HW_PRIO_STAT(struct xsc_pfc_prio_stats, rx_pause_duration,  7),
};

static const struct counter_desc hw_eth_stats_pf_desc[] = {
	/*by mac port*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rdma_tx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rdma_tx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rdma_rx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rdma_rx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  tx_pause) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rx_pause) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rx_fcs_errors) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rx_discards) },

	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  tx_multicast_phy) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  tx_broadcast_phy) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rx_multicast_phy) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rx_broadcast_phy) },

	/*by global*/
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rdma_loopback_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_pf,  rdma_loopback_bytes) },
};

static const struct counter_desc hw_eth_stats_vf_desc[] = {
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_vf,  rdma_tx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_vf,  rdma_tx_bytes) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_vf,  rdma_rx_pkts) },
	{ XSC_DECLARE_STAT(struct xsc_hw_stats_eth_vf,  rdma_rx_bytes) },
};

static const struct counter_desc pfc_stall_stats_desc[] = {
	/*by mac port*/
	{ XSC_DECLARE_STAT(struct xsc_pfc_stall_stats, tx_pause_storm_triggered) },
};

static const struct counter_desc hw_eth_uc_stats_pf_desc[] = {
	/*for uc statistcs*/
	{ XSC_DECLARE_STAT(struct xsc_hw_uc_stats_eth,  tx_unicast_phy) },
	{ XSC_DECLARE_STAT(struct xsc_hw_uc_stats_eth,  rx_unicast_phy) },
};

static int get_hw_stats_eth(struct xsc_core_device *dev, struct xsc_hw_stats_eth *stats_eth)
{
	int ret;
	struct xsc_hw_stats_mbox_in in;
	struct xsc_hw_stats_eth_mbox_out out;

	memset(stats_eth, 0, sizeof(*stats_eth));

	if (!dev)
		return -1;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HW_STATS_ETH);
	in.mac_port = dev->mac_port;

	ret = xsc_cmd_exec(dev, (void *)&in, sizeof(in), (void *)&out, sizeof(out));
	if (ret || out.hdr.status)
		return -1;

	memcpy(stats_eth, &out.hw_stats, sizeof(*stats_eth));
	return 0;
}

static u32 mask2size(u32 mask)
{
	u32 size = 0;

	while (mask) {
		size += mask & 0x1;
		mask >>= 1;
	}

	return size;
}

static int xsc_hw_get_num_stats(struct xsc_adapter *adapter)
{
	int ret = 0;
	u32 mask = xsc_get_eth_stat_mask(adapter->xdev);
	u32 eth_stats_size = mask2size(mask);

	if (is_support_hw_pf_stats(adapter->xdev)) {
		ret = ARRAY_SIZE(hw_prio_stats_desc) + eth_stats_size +
		      (is_support_pfc_prio_statistic(adapter->xdev) ?
		      ARRAY_SIZE(hw_pfc_prio_stats_desc) : 0) +
			  (is_support_pf_uc_statistic(adapter->xdev) ?
			  ARRAY_SIZE(hw_eth_uc_stats_pf_desc) : 0) +
		      (is_support_pfc_stall_stats(adapter->xdev) ?
		      ARRAY_SIZE(pfc_stall_stats_desc) : 0);
	} else {
		ret = eth_stats_size;
	}

	return ret;
}

static int xsc_hw_fill_strings(struct xsc_adapter *adapter, u8 *data, int idx)
{
	int i;
	struct xsc_core_device *xdev;
	u32 mask = 0;

	xdev = adapter->xdev;
	mask = xsc_get_eth_stat_mask(xdev);

	if (is_support_hw_pf_stats(xdev)) {
		for (i = 0; i < ARRAY_SIZE(hw_prio_stats_desc); i++)
			strscpy(data + (idx++) * ETH_GSTRING_LEN,
				hw_prio_stats_desc[i].format,
				ETH_GSTRING_LEN);

		if (is_support_pfc_prio_statistic(xdev))
			for (i = 0; i < ARRAY_SIZE(hw_pfc_prio_stats_desc); i++)
				strscpy(data + (idx++) * ETH_GSTRING_LEN,
					hw_pfc_prio_stats_desc[i].format,
					ETH_GSTRING_LEN);

		for (i = 0 ; i < ARRAY_SIZE(hw_eth_stats_pf_desc); i++) {
			if (!((1 << i) & mask))
				continue;
			strscpy(data + (idx++) * ETH_GSTRING_LEN,
				hw_eth_stats_pf_desc[i].format,
				ETH_GSTRING_LEN);
		}

		if (is_support_pf_uc_statistic(xdev))
			for (i = 0; i < ARRAY_SIZE(hw_eth_uc_stats_pf_desc); i++)
				strscpy(data + (idx++) * ETH_GSTRING_LEN,
					hw_eth_uc_stats_pf_desc[i].format,
					ETH_GSTRING_LEN);

		if (is_support_pfc_stall_stats(xdev))
			for (i = 0; i < ARRAY_SIZE(pfc_stall_stats_desc); i++)
				strscpy(data + (idx++) * ETH_GSTRING_LEN,
					pfc_stall_stats_desc[i].format,
					ETH_GSTRING_LEN);
	} else {
		for (i = 0 ; i < ARRAY_SIZE(hw_eth_stats_vf_desc); i++) {
			if (!((1 << i) & mask))
				continue;
			strscpy(data + (idx++) * ETH_GSTRING_LEN,
				hw_eth_stats_vf_desc[i].format,
				ETH_GSTRING_LEN);
		}
	}

	return idx;
}

static int xsc_hw_fill_stats(struct xsc_adapter *adapter, u64 *data, int idx)
{
	struct xsc_prio_stats_mbox_in in;
	struct xsc_prio_stats_mbox_out out;
	struct xsc_pfc_prio_stats_mbox_in pfc_prio_in;
	struct xsc_pfc_prio_stats_mbox_out pfc_prio_out;
	struct xsc_pfc_stall_stats_mbox_in pfc_stall_in;
	struct xsc_pfc_stall_stats_mbox_out pfc_stall_out;
	struct xsc_hw_uc_stats_mbox_in hw_ucstats_in;
	struct xsc_hw_uc_stats_mbox_out hw_ucstats_out;
	struct xsc_core_device *xdev;
	int ret;
	u32 i;
	u64 val;
	u8 *stats;
	struct xsc_hw_stats_eth stats_eth;
	int ret_s;
	u32 mask = 0;

	xdev = adapter->xdev;
	ret_s = get_hw_stats_eth(xdev, &stats_eth);
	mask = xsc_get_eth_stat_mask(xdev);

	if (is_support_hw_pf_stats(xdev)) {
		memset(&in, 0, sizeof(in));
		memset(&out, 0, sizeof(out));

		in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_QUERY_PRIO_STATS);
		in.pport = xdev->mac_port;

		ret = xsc_cmd_exec(adapter->xdev, (void *)&in,
				   sizeof(struct xsc_prio_stats_mbox_in),
				   (void *)&out, sizeof(struct xsc_prio_stats_mbox_out));
		if (ret == 0 && out.hdr.status == 0) {
			for (i = 0; i < ARRAY_SIZE(hw_prio_stats_desc); i++) {
				val = XSC_READ_CTR64_CPU(&out.prio_stats,
							 hw_prio_stats_desc, i);
				data[idx++] = __be64_to_cpu(val);
			}
		}

		if (is_support_pfc_prio_statistic(xdev)) {
			memset(&pfc_prio_in, 0, sizeof(pfc_prio_in));
			memset(&pfc_prio_out, 0, sizeof(pfc_prio_out));
			pfc_prio_in.hdr.opcode =
				__cpu_to_be16(XSC_CMD_OP_QUERY_PFC_PRIO_STATS);
			pfc_prio_in.pport = xdev->mac_port;

			ret = xsc_cmd_exec(adapter->xdev, (void *)&pfc_prio_in,
					   sizeof(struct xsc_pfc_prio_stats_mbox_in),
					   (void *)&pfc_prio_out,
					   sizeof(struct xsc_pfc_prio_stats_mbox_out));
			if (ret == 0 && pfc_prio_out.hdr.status == 0) {
				for (i = 0; i < ARRAY_SIZE(hw_pfc_prio_stats_desc); i++) {
					val = XSC_READ_CTR64_CPU(&pfc_prio_out.prio_stats,
								 hw_pfc_prio_stats_desc,
								 i);
					data[idx++] = __be64_to_cpu(val);
				}
			}
		}

		if (!ret_s && stats_eth.is_pf) {
			stats = (u8 *)&stats_eth.stats.pf_stats;
			for (i = 0 ; i < ARRAY_SIZE(hw_eth_stats_pf_desc); i++) {
				if (!((1 << i) & mask))
					continue;
				val = XSC_READ_CTR64_CPU(stats, hw_eth_stats_pf_desc, i);
				data[idx++] = __be64_to_cpu(val);
			}
		}

		if (is_support_pf_uc_statistic(xdev)) {
			memset(&hw_ucstats_in, 0, sizeof(hw_ucstats_in));
			memset(&hw_ucstats_out, 0, sizeof(hw_ucstats_out));
			hw_ucstats_in.hdr.opcode =
				__cpu_to_be16(XSC_CMD_OP_QUERY_HW_PF_UC_STATS);
			hw_ucstats_in.mac_port = xdev->mac_port;

			ret = xsc_cmd_exec(adapter->xdev,
					   (void *)&hw_ucstats_in,
					   sizeof(struct xsc_hw_uc_stats_mbox_in),
					   (void *)&hw_ucstats_out,
					   sizeof(struct xsc_hw_uc_stats_mbox_out));
			if (ret == 0 && hw_ucstats_out.hdr.status == 0 &&
			    hw_ucstats_out.hw_uc_stats.is_pf) {
				stats = (u8 *)&hw_ucstats_out.hw_uc_stats.eth_uc_stats;
				for (i = 0; i < ARRAY_SIZE(hw_eth_uc_stats_pf_desc); i++) {
					val = XSC_READ_CTR64_CPU(stats,
								 hw_eth_uc_stats_pf_desc,
								 i);
					data[idx++] = __be64_to_cpu(val);
				}
			}
		}

		if (is_support_pfc_stall_stats(xdev)) {
			memset(&pfc_stall_in, 0, sizeof(pfc_stall_in));
			memset(&pfc_stall_out, 0, sizeof(pfc_stall_out));
			pfc_stall_in.hdr.opcode =
				__cpu_to_be16(XSC_CMD_OP_IOCTL_QUERY_PFC_STALL_STATS);
			pfc_stall_in.mac_port = xdev->mac_port;

			ret = xsc_cmd_exec(adapter->xdev,
					   (void *)&pfc_stall_in,
					   sizeof(struct xsc_pfc_stall_stats_mbox_in),
					   (void *)&pfc_stall_out,
					   sizeof(struct xsc_pfc_stall_stats_mbox_out));
			if (ret == 0 && pfc_stall_out.hdr.status == 0) {
				for (i = 0; i < ARRAY_SIZE(pfc_stall_stats_desc); i++) {
					val = XSC_READ_CTR64_CPU(&pfc_stall_out.pfc_stall_stats,
								 pfc_stall_stats_desc, i);
					data[idx++] = __be64_to_cpu(val);
				}
			}
		}
	} else {
		if (!ret_s && !stats_eth.is_pf) {
			stats = (u8 *)&stats_eth.stats.vf_stats;
			for (i = 0 ; i < ARRAY_SIZE(hw_eth_stats_vf_desc); i++) {
				if (!((1 << i) & mask))
					continue;
				val = XSC_READ_CTR64_CPU(stats, hw_eth_stats_vf_desc, i);
				data[idx++] = __be64_to_cpu(val);
			}
		}
	}

	return idx;
}

/* The stats groups order is opposite to the update_stats() order calls */
const struct xsc_stats_grp xsc_stats_grps[] = {
	{
		.get_num_stats = xsc_grp_sw_get_num_stats,
		.fill_strings = xsc_grp_sw_fill_strings,
		.fill_stats = xsc_grp_sw_fill_stats,
		.update_stats = xsc_grp_sw_update_stats,
	},

	{
		.get_num_stats = xsc_grp_channels_get_num_stats,
		.fill_strings = xsc_grp_channels_fill_strings,
		.fill_stats = xsc_grp_channels_fill_stats,
	},

	{
		.get_num_stats = xsc_hw_get_num_stats,
		.fill_strings = xsc_hw_fill_strings,
		.fill_stats = xsc_hw_fill_stats,
	},
};

const int xsc_num_stats_grps = ARRAY_SIZE(xsc_stats_grps);

void xsc_fold_sw_stats64(struct xsc_adapter *adapter, struct rtnl_link_stats64 *s)
{
	int i, j;

	for (i = 0; i < xsc_get_netdev_max_channels(adapter); i++) {
		struct xsc_channel_stats *channel_stats = &adapter->stats->channel_stats[i];
		struct xsc_rq_stats *rq_stats = &channel_stats->rq;

		s->rx_packets   += rq_stats->packets;
		s->rx_bytes     += rq_stats->bytes;

		for (j = 0; j < xsc_get_netdev_max_tc(adapter); j++) {
			struct xsc_sq_stats *sq_stats = &channel_stats->sq[j];

			s->tx_packets    += sq_stats->packets;
			s->tx_bytes      += sq_stats->bytes;
			s->tx_dropped    += sq_stats->dropped;
		}
	}
}

static const struct counter_desc xsc_prs_chk_err_stats_desc[] = {
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_sip_dip_eq) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_sip_invalid) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_smac_invalid) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_ip_ver) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_smac_dmac_eq) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_dmac_zero) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_sip_dip_eq) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_sip_invalid) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_smac_invalid) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_ip_ver) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_smac_dmac_eq) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_dmac_zero) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_udp_len) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_tp_checksum) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_ipv4_checksum) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_ip_ttl) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_ip_len) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, inner_ipv4_ihl) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_udp_len) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_tp_checksum) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_ipv4_checksum) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_ip_ttl) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_ip_len) },
	{ XSC_DECLARE_STAT(struct xsc_prs_chk_err_stats, outer_ipv4_ihl) },
};

#define XSC_PHY_STATS_CNT	ARRAY_SIZE(xsc_prs_chk_err_stats_desc)

int xsc_get_prs_chk_err_stats_count(struct xsc_adapter *adapter)
{
	return XSC_PHY_STATS_CNT;
}

void xsc_get_prs_chk_err_stats_strings(struct xsc_adapter *adapter, u8 *data)
{
	int i;

	for (i = 0; i < XSC_PHY_STATS_CNT; i++)
		strscpy(data + i * ETH_GSTRING_LEN,
			xsc_prs_chk_err_stats_desc[i].format,
			ETH_GSTRING_LEN);
}

int xsc_fill_prs_chk_err_stats(struct xsc_adapter *adapter, u64 *data)
{
	struct xsc_query_hw_prs_chk_err_stats_mbox_out out;
	struct xsc_query_hw_prs_chk_err_stats_mbox_in in;
	__be64 val;
	int err;
	int i;

	memset(&out, 0, sizeof(out));
	memset(&in, 0, sizeof(in));
	in.hdr.opcode = __cpu_to_be16(XSC_CMD_OP_QUERY_HW_PRS_CHK_ERR_STATS);

	err = xsc_cmd_exec(adapter->xdev, (void *)&in, sizeof(in),
			   (void *)&out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);

	for (i = 0; i < XSC_PHY_STATS_CNT; i++) {
		val = XSC_READ_CTR64_CPU(&out.stats,
					 xsc_prs_chk_err_stats_desc, i);
		data[i] = __be64_to_cpu(val);
	}
	return 0;
}
