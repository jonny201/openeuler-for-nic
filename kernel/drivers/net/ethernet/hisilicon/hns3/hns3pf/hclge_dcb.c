// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "hclge_main.h"
#include "hclge_dcb.h"
#include "hclge_tm.h"
#include "hclge_mbx.h"
#include "hnae3.h"

#define BW_PERCENT	100

static int hclge_ieee_ets_to_tm_info(struct hclge_dev *hdev,
				     struct ieee_ets *ets)
{
	u8 i;

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_STRICT:
			hdev->tm_info.tc_info[i].tc_sch_mode =
				HCLGE_SCH_MODE_SP;
			hdev->tm_info.pg_info[0].tc_dwrr[i] = 0;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			hdev->tm_info.tc_info[i].tc_sch_mode =
				HCLGE_SCH_MODE_DWRR;
			hdev->tm_info.pg_info[0].tc_dwrr[i] =
				ets->tc_tx_bw[i];
			break;
		default:
			/* Hardware only supports SP (strict priority)
			 * or ETS (enhanced transmission selection)
			 * algorithms, if we receive some other value
			 * from dcbnl, then throw an error.
			 */
			return -EINVAL;
		}
	}

	hclge_tm_prio_tc_info_update(hdev, ets->prio_tc);

	return 0;
}

static void hclge_tm_info_to_ieee_ets(struct hclge_dev *hdev,
				      struct ieee_ets *ets)
{
	u32 i;

	memset(ets, 0, sizeof(*ets));
	ets->willing = 1;
	ets->ets_cap = hdev->tc_max;

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		ets->prio_tc[i] = hdev->tm_info.prio_tc[i];
		if (i < hdev->tm_info.num_tc)
			ets->tc_tx_bw[i] = hdev->tm_info.pg_info[0].tc_dwrr[i];
		else
			ets->tc_tx_bw[i] = 0;

		if (hdev->tm_info.tc_info[i].tc_sch_mode ==
		    HCLGE_SCH_MODE_SP)
			ets->tc_tsa[i] = IEEE_8021QAZ_TSA_STRICT;
		else
			ets->tc_tsa[i] = IEEE_8021QAZ_TSA_ETS;
	}
}

/* IEEE std */
static int hclge_ieee_getets(struct hnae3_handle *h, struct ieee_ets *ets)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct hclge_dev *hdev = vport->back;

	hclge_tm_info_to_ieee_ets(hdev, ets);

	return 0;
}

static int hclge_dcb_common_validate(struct hclge_dev *hdev, u8 num_tc,
				     u8 *prio_tc)
{
	int i;

	/* Based on hardware limitation, VFs share the configuration of PF. */
	if (hnae3_ae_dev_vf_multi_tcs_supported(hdev) &&
	    !bitmap_empty(hdev->vf_multi_tcs_en, HCLGE_VPORT_NUM)) {
		dev_err(&hdev->pdev->dev,
			"the tc resource is still being used by VF\n");
		return -EOPNOTSUPP;
	}

	if (num_tc > hdev->tc_max) {
		dev_err(&hdev->pdev->dev,
			"tc num checking failed, %u > tc_max(%u)\n",
			num_tc, hdev->tc_max);
		return -EINVAL;
	}

	for (i = 0; i < HNAE3_MAX_USER_PRIO; i++) {
		if (prio_tc[i] >= num_tc) {
			dev_err(&hdev->pdev->dev,
				"prio_tc[%d] checking failed, %u >= num_tc(%u)\n",
				i, prio_tc[i], num_tc);
			return -EINVAL;
		}
	}

	if (num_tc > hdev->vport[0].alloc_tqps) {
		dev_err(&hdev->pdev->dev,
			"allocated tqp checking failed, %u > tqp(%u)\n",
			num_tc, hdev->vport[0].alloc_tqps);
		return -EINVAL;
	}

	return 0;
}

static u8 hclge_ets_tc_changed(struct hclge_dev *hdev, struct ieee_ets *ets,
			       bool *changed)
{
	u8 max_tc_id = 0;
	u8 i;

	for (i = 0; i < HNAE3_MAX_USER_PRIO; i++) {
		if (ets->prio_tc[i] != hdev->tm_info.prio_tc[i])
			*changed = true;

		if (ets->prio_tc[i] > max_tc_id)
			max_tc_id = ets->prio_tc[i];
	}

	/* return max tc number, max tc id need to plus 1 */
	return max_tc_id + 1;
}

static int hclge_ets_sch_mode_validate(struct hclge_dev *hdev,
				       struct ieee_ets *ets, bool *changed,
				       u8 tc_num)
{
	bool has_ets_tc = false;
	u32 total_ets_bw = 0;
	u8 i;

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_STRICT:
			if (hdev->tm_info.tc_info[i].tc_sch_mode !=
				HCLGE_SCH_MODE_SP)
				*changed = true;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			if (i >= tc_num) {
				dev_err(&hdev->pdev->dev,
					"tc%u is disabled, cannot set ets bw\n",
					i);
				return -EINVAL;
			}

			/* The hardware will switch to sp mode if bandwidth is
			 * 0, so limit ets bandwidth must be greater than 0.
			 */
			if (!ets->tc_tx_bw[i]) {
				dev_err(&hdev->pdev->dev,
					"tc%u ets bw cannot be 0\n", i);
				return -EINVAL;
			}

			if (hdev->tm_info.tc_info[i].tc_sch_mode !=
				HCLGE_SCH_MODE_DWRR)
				*changed = true;

			total_ets_bw += ets->tc_tx_bw[i];
			has_ets_tc = true;
			break;
		default:
			return -EINVAL;
		}
	}

	if (has_ets_tc && total_ets_bw != BW_PERCENT)
		return -EINVAL;

	return 0;
}

static int hclge_ets_validate(struct hclge_dev *hdev, struct ieee_ets *ets,
			      u8 *tc, bool *changed)
{
	u8 tc_num;
	int ret;

	tc_num = hclge_ets_tc_changed(hdev, ets, changed);

	ret = hclge_dcb_common_validate(hdev, tc_num, ets->prio_tc);
	if (ret)
		return ret;

	ret = hclge_ets_sch_mode_validate(hdev, ets, changed, tc_num);
	if (ret)
		return ret;

	*tc = tc_num;
	if (*tc != hdev->tm_info.num_tc)
		*changed = true;

	return 0;
}

static bool hclge_ets_not_need_config(struct hclge_dev *hdev,
				      struct ieee_ets *ets)
{
	u8 max_tc_id = 0;
	u32 i;

	if (ets->ets_cap != hdev->tc_max)
		return false;

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		if (ets->tc_tx_bw[i] != hdev->tm_info.pg_info[0].tc_dwrr[i])
			return false;

		if (ets->prio_tc[i] != hdev->tm_info.prio_tc[i])
			return false;

		if (hdev->tm_info.tc_info[i].tc_sch_mode ==
		    HCLGE_SCH_MODE_SP) {
			if (ets->tc_tsa[i] != IEEE_8021QAZ_TSA_STRICT)
				return false;
		} else {
			if (ets->tc_tsa[i] != IEEE_8021QAZ_TSA_ETS)
				return false;
		}

		if (ets->prio_tc[i] > max_tc_id)
			max_tc_id = ets->prio_tc[i];
	}

	if (max_tc_id + 1 != hdev->tm_info.num_tc)
		return false;

	return true;
}

static int hclge_map_update(struct hclge_dev *hdev)
{
	int ret;

	ret = hclge_tm_schd_setup_hw(hdev);
	if (ret)
		return ret;

	ret = hclge_pause_setup_hw(hdev, false);
	if (ret)
		return ret;

	ret = hclge_buffer_alloc(hdev);
	if (ret)
		return ret;

	hclge_comm_rss_indir_init_cfg(hdev->ae_dev, &hdev->rss_cfg);

	return hclge_rss_init_hw(hdev);
}

static int hclge_notify_down_uinit(struct hclge_dev *hdev)
{
	int ret;

	ret = hclge_notify_client(hdev, HNAE3_DOWN_CLIENT);
	if (ret)
		return ret;

	ret = hclge_tm_flush_cfg(hdev, true);
	if (ret)
		return ret;

	return hclge_notify_client(hdev, HNAE3_UNINIT_CLIENT);
}

static int hclge_notify_init_up(struct hclge_dev *hdev)
{
	int ret;

	ret = hclge_notify_client(hdev, HNAE3_INIT_CLIENT);
	if (ret)
		return ret;

	ret = hclge_tm_flush_cfg(hdev, false);
	if (ret)
		return ret;

	return hclge_notify_client(hdev, HNAE3_UP_CLIENT);
}

static int hclge_ieee_setets(struct hnae3_handle *h, struct ieee_ets *ets)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct net_device *netdev = h->kinfo.netdev;
	struct hclge_dev *hdev = vport->back;
	bool map_changed = false;
	u8 num_tc = 0;
	int ret;

	if (!(hdev->dcbx_cap & DCB_CAP_DCBX_VER_IEEE) ||
	    h->kinfo.tc_info.mqprio_active)
		return -EINVAL;

	if (hclge_ets_not_need_config(hdev, ets))
		return 0;

	ret = hclge_ets_validate(hdev, ets, &num_tc, &map_changed);
	if (ret)
		return ret;

	if (map_changed) {
		netif_dbg(h, drv, netdev, "set ets\n");

		ret = hclge_notify_down_uinit(hdev);
		if (ret)
			return ret;
	}

	mutex_lock(&hdev->vport_lock);
	hclge_tm_schd_info_update(hdev, num_tc);
	h->kinfo.tc_info.dcb_ets_active = num_tc > 1;

	ret = hclge_ieee_ets_to_tm_info(hdev, ets);
	if (ret)
		goto err_out;

	if (map_changed) {
		ret = hclge_map_update(hdev);
		if (ret)
			goto err_out;

		mutex_unlock(&hdev->vport_lock);
		return hclge_notify_init_up(hdev);
	}

	mutex_unlock(&hdev->vport_lock);
	return hclge_tm_dwrr_cfg(hdev);

err_out:
	mutex_unlock(&hdev->vport_lock);
	if (!map_changed)
		return ret;

	hclge_notify_init_up(hdev);

	return ret;
}

static int hclge_ieee_getpfc(struct hnae3_handle *h, struct ieee_pfc *pfc)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct hclge_dev *hdev = vport->back;
	int ret;

	memset(pfc, 0, sizeof(*pfc));
	pfc->pfc_cap = hdev->pfc_max;
	pfc->pfc_en = hdev->tm_info.pfc_en;

	ret = hclge_mac_update_stats(hdev);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to update MAC stats, ret = %d.\n", ret);
		return ret;
	}

	hclge_pfc_tx_stats_get(hdev, pfc->requests);
	hclge_pfc_rx_stats_get(hdev, pfc->indications);

	return 0;
}

static int hclge_ieee_setpfc(struct hnae3_handle *h, struct ieee_pfc *pfc)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct net_device *netdev = h->kinfo.netdev;
	struct hclge_dev *hdev = vport->back;
	u8 i, j, pfc_map, *prio_tc;
	int last_bad_ret = 0;
	int ret;

	if (!(hdev->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	if (pfc->pfc_en == hdev->tm_info.pfc_en)
		return 0;

	prio_tc = hdev->tm_info.prio_tc;
	pfc_map = 0;

	for (i = 0; i < hdev->tm_info.num_tc; i++) {
		for (j = 0; j < HNAE3_MAX_USER_PRIO; j++) {
			if ((prio_tc[j] == i) && (pfc->pfc_en & BIT(j))) {
				pfc_map |= BIT(i);
				break;
			}
		}
	}

	hdev->tm_info.hw_pfc_map = pfc_map;
	hdev->tm_info.pfc_en = pfc->pfc_en;

	netif_dbg(h, drv, netdev,
		  "set pfc: pfc_en=%x, pfc_map=%x, num_tc=%u\n",
		  pfc->pfc_en, pfc_map, hdev->tm_info.num_tc);

	hclge_tm_pfc_info_update(hdev);

	ret = hclge_pause_setup_hw(hdev, false);
	if (ret)
		return ret;

	ret = hclge_notify_client(hdev, HNAE3_DOWN_CLIENT);
	if (ret)
		return ret;

	ret = hclge_tm_flush_cfg(hdev, true);
	if (ret)
		return ret;

	/* No matter whether the following operations are performed
	 * successfully or not, disabling the tm flush and notify
	 * the network status to up are necessary.
	 * Do not return immediately.
	 */
	ret = hclge_buffer_alloc(hdev);
	if (ret)
		last_bad_ret = ret;

	ret = hclge_tm_flush_cfg(hdev, false);
	if (ret)
		last_bad_ret = ret;

	ret = hclge_notify_client(hdev, HNAE3_UP_CLIENT);
	if (ret)
		last_bad_ret = ret;

	return last_bad_ret;
}

static void hclge_notify_dscp_change(struct hclge_dev *hdev)
{
	struct hclge_vport *vport;
	int ret;
	int i;

	if (!hnae3_ae_dev_vf_multi_tcs_supported(hdev))
		return;

	for (i = 0; i < pci_num_vf(hdev->pdev); i++) {
		vport = &hdev->vport[i + HCLGE_VF_VPORT_START_NUM];

		if (!test_bit(HCLGE_VPORT_STATE_ALIVE, &vport->state))
			continue;

		ret = hclge_mbx_event_notify(vport, BIT(HCLGE_MBX_DSCP_CHANGE));
		if (ret)
			break;
	}
}

static int hclge_ieee_setapp(struct hnae3_handle *h, struct dcb_app *app)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct net_device *netdev = h->kinfo.netdev;
	struct hclge_dev *hdev = vport->back;
	struct dcb_app old_app;
	int ret1;
	int ret;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP ||
	    app->protocol >= HNAE3_MAX_DSCP ||
	    app->priority >= HNAE3_MAX_USER_PRIO)
		return -EINVAL;

	dev_info(&hdev->pdev->dev, "setapp dscp=%u priority=%u\n",
		 app->protocol, app->priority);

	if (app->priority == h->kinfo.dscp_prio[app->protocol])
		return 0;

	ret = dcb_ieee_setapp(netdev, app);
	if (ret)
		return ret;

	old_app.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	old_app.protocol = app->protocol;
	old_app.priority = h->kinfo.dscp_prio[app->protocol];

	h->kinfo.dscp_prio[app->protocol] = app->priority;
	ret = hclge_dscp_to_tc_map(hdev);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to set dscp to tc map, ret = %d\n", ret);
		h->kinfo.dscp_prio[app->protocol] = old_app.priority;
		(void)dcb_ieee_delapp(netdev, app);
		return ret;
	}

	vport->nic.kinfo.tc_map_mode = HNAE3_TC_MAP_MODE_DSCP;
	if (old_app.priority == HNAE3_PRIO_ID_INVALID)
		h->kinfo.dscp_app_cnt++;
	else
		ret = dcb_ieee_delapp(netdev, &old_app);

	ret1 = hclge_dscp_to_pri_map(hdev);
	if (ret1)
		return ret1;
	hclge_notify_dscp_change(hdev);

	return ret;
}

static int hclge_ieee_delapp(struct hnae3_handle *h, struct dcb_app *app)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct net_device *netdev = h->kinfo.netdev;
	struct hclge_dev *hdev = vport->back;
	int ret;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP ||
	    app->protocol >= HNAE3_MAX_DSCP ||
	    app->priority >= HNAE3_MAX_USER_PRIO ||
	    app->priority != h->kinfo.dscp_prio[app->protocol])
		return -EINVAL;

	dev_info(&hdev->pdev->dev, "delapp dscp=%u priority=%u\n",
		 app->protocol, app->priority);

	ret = dcb_ieee_delapp(netdev, app);
	if (ret)
		return ret;

	h->kinfo.dscp_prio[app->protocol] = HNAE3_PRIO_ID_INVALID;
	ret = hclge_dscp_to_tc_map(hdev);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to del dscp to tc map, ret = %d\n", ret);
		h->kinfo.dscp_prio[app->protocol] = app->priority;
		(void)dcb_ieee_setapp(netdev, app);
		return ret;
	}

	if (h->kinfo.dscp_app_cnt)
		h->kinfo.dscp_app_cnt--;

	if (!h->kinfo.dscp_app_cnt) {
		vport->nic.kinfo.tc_map_mode = HNAE3_TC_MAP_MODE_PRIO;
		ret = hclge_up_to_tc_map(hdev);
	}

	ret = hclge_dscp_to_pri_map(hdev);
	if (ret)
		return ret;
	hclge_notify_dscp_change(hdev);

	return ret;
}

/* DCBX configuration */
static u8 hclge_getdcbx(struct hnae3_handle *h)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct hclge_dev *hdev = vport->back;

	if (h->kinfo.tc_info.mqprio_active)
		return 0;

	return hdev->dcbx_cap;
}

static u8 hclge_setdcbx(struct hnae3_handle *h, u8 mode)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct net_device *netdev = h->kinfo.netdev;
	struct hclge_dev *hdev = vport->back;

	netif_dbg(h, drv, netdev, "set dcbx: mode=%u\n", mode);

	/* No support for LLD_MANAGED modes or CEE */
	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    (mode & DCB_CAP_DCBX_VER_CEE) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return 1;

	hdev->dcbx_cap = mode;

	return 0;
}

static int hclge_ieee_getmaxrate(struct hnae3_handle *h,
				 struct ieee_maxrate *maxrate)
{
	struct hnae3_tc_info *tc_info = &h->kinfo.tc_info;
	struct hclge_vport *vport = hclge_get_vport(h);
	struct hclge_dev *hdev = vport->back;

	if (!hnae3_dev_roh_supported(hdev) &&
	    !hnae3_dev_ubl_supported(hdev->ae_dev))
		return -EOPNOTSUPP;

	memcpy(maxrate, tc_info->max_rate, sizeof(struct ieee_maxrate));
	return 0;
}

static int hclge_check_maxrate(struct hclge_dev *hdev,
			       struct ieee_maxrate *maxrate)
{
	u64 max_speed = (u64)hdev->hw.mac.max_speed * TM_RATE_PORT_RATE_SCALE;
	u8 i;

	for (i = 0; i < HNAE3_MAX_TC; i++) {
		/* no limit */
		if (!maxrate->tc_maxrate[i])
			continue;
		if (maxrate->tc_maxrate[i] < TM_RATE_PORT_RATE_SCALE ||
		    maxrate->tc_maxrate[i] > max_speed) {
			dev_err(&hdev->pdev->dev,
				"invalid max_rate[%llubps]: the range is [1Mbps, %uMbps]\n",
				maxrate->tc_maxrate[i] * HCLGE_BYTE_BITS,
				hdev->hw.mac.max_speed);
			return -EINVAL;
		}
	}
	return 0;
}

static int hclge_ieee_setmaxrate(struct hnae3_handle *h,
				 struct ieee_maxrate *maxrate)
{
	struct hnae3_tc_info *tc_info = &h->kinfo.tc_info;
	struct hclge_vport *vport = hclge_get_vport(h);
	struct hclge_dev *hdev = vport->back;
	struct hnae3_tc_info old_tc_info;
	int ret;

	if (!hnae3_dev_roh_supported(hdev) &&
	    !hnae3_dev_ubl_supported(hdev->ae_dev))
		return -EOPNOTSUPP;

	if (!(hdev->dcbx_cap & DCB_CAP_DCBX_VER_IEEE) || tc_info->mqprio_active)
		return -EINVAL;

	ret = hclge_check_maxrate(hdev, maxrate);
	if (ret)
		return ret;

	memcpy(&old_tc_info, tc_info, sizeof(struct hnae3_tc_info));
	memcpy(tc_info->max_rate, maxrate, sizeof(struct ieee_maxrate));
	ret = hclge_tm_set_tc_rate_limit(hdev, tc_info);
	if (ret)
		memcpy(tc_info, &old_tc_info, sizeof(struct hnae3_tc_info));

	return ret;
}

static int hclge_buffer_validate(struct hclge_dev *hdev,
				 struct dcbnl_buffer *buffer)
{
	u8 prio2buffer;
	int ret;
	u8 i;

	ret = hclge_tm_tc_buffer_check(hdev, buffer->buffer_size, HNAE3_MAX_TC);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"invalid buffer size, ret = %d\n", ret);
		return ret;
	}

	for (i = 0; i < HNAE3_MAX_USER_PRIO; i++) {
		prio2buffer = (i < hdev->tc_max) ? i : 0;
		if (buffer->prio2buffer[i] != prio2buffer) {
			dev_err(&hdev->pdev->dev,
				"not support prio[%u] buffer %u map\n",
				i, buffer->prio2buffer[i]);
			return -EINVAL;
		}
	}

	return 0;
}

static int hclge_setbuffer(struct hnae3_handle *h, struct dcbnl_buffer *buffer)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct net_device *netdev = h->kinfo.netdev;
	u32 *buffer_size = h->kinfo.buffer_size;
	struct hclge_dev *hdev = vport->back;
	int result;
	int ret;

	if (!hnae3_ae_dev_tc_buffer_supported(hdev))
		return -EOPNOTSUPP;

	ret = hclge_buffer_validate(hdev, buffer);
	if (ret)
		return ret;

	if (netif_msg_ifdown(h))
		netdev_info(netdev, "set buffer\n");

	ret = hclge_notify_down_uinit(hdev);
	if (ret)
		return ret;

	result = hclge_tm_tc_buffer_update(hdev, buffer->buffer_size,
					   HNAE3_MAX_TC);
	if (!result)
		memcpy(buffer_size, buffer->buffer_size,
		       sizeof(h->kinfo.buffer_size));
	else
		netdev_err(netdev, "failed to update tc buffer, ret = %d\n",
			   result);

	ret = hclge_notify_init_up(hdev);
	if (ret)
		return ret;

	return result;
}

static int hclge_getbuffer(struct hnae3_handle *h, struct dcbnl_buffer *buffer)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	u32 *buffer_size = h->kinfo.buffer_size;
	struct hclge_dev *hdev = vport->back;
	u8 i;

	if (!hnae3_ae_dev_tc_buffer_supported(hdev))
		return -EOPNOTSUPP;

	memcpy(buffer->buffer_size, buffer_size,
	       sizeof(buffer->buffer_size));

	for (i = 0; i < HNAE3_MAX_USER_PRIO; i++)
		buffer->prio2buffer[i] = (i < hdev->tc_max) ? i : 0;

	buffer->total_size = hdev->ae_dev->dev_specs.total_rx_buffer_size;
	return 0;
}

static int hclge_mqprio_qopt_check_rate(struct hclge_dev *hdev, u64 min_rate,
					u64 max_rate)
{
	u32 max_speed = hclge_tm_rate_2_port_rate(max_rate);

	if (min_rate) {
		dev_err(&hdev->pdev->dev, "unsupported min_rate, min_rate = %lluB/s\n",
			min_rate);
		return -EOPNOTSUPP;
	}

	if (!max_rate)
		return 0;

	if (hnae3_dev_roh_supported(hdev) ||
	    hnae3_dev_ubl_supported(hdev->ae_dev)) {
		if (max_rate < TM_RATE_PORT_RATE_SCALE ||
		    max_speed > hdev->hw.mac.max_speed) {
			dev_err(&hdev->pdev->dev,
				"invalid max_rate[%lluB/s]: the range is [1Mbps, %uMbps]\n",
				max_rate, hdev->hw.mac.max_speed);
			return -EINVAL;
		}
		return 0;
	}

	dev_err(&hdev->pdev->dev, "unsupported max_rate, max_rate = %lluB/s\n",
		max_rate);
	return -EOPNOTSUPP;
}

static int hclge_mqprio_qopt_check(struct hclge_dev *hdev,
				   struct tc_mqprio_qopt_offload *mqprio_qopt)
{
	u16 queue_sum = 0;
	int ret;
	int i;

	if (!mqprio_qopt->qopt.num_tc) {
		mqprio_qopt->qopt.num_tc = 1;
		return 0;
	}

	ret = hclge_dcb_common_validate(hdev, mqprio_qopt->qopt.num_tc,
					mqprio_qopt->qopt.prio_tc_map);
	if (ret)
		return ret;

	for (i = 0; i < mqprio_qopt->qopt.num_tc; i++) {
		if (!is_power_of_2(mqprio_qopt->qopt.count[i])) {
			dev_err(&hdev->pdev->dev,
				"qopt queue count must be power of 2\n");
			return -EINVAL;
		}

		if (mqprio_qopt->qopt.count[i] > hdev->pf_rss_size_max) {
			dev_err(&hdev->pdev->dev,
				"qopt queue count should be no more than %u\n",
				hdev->pf_rss_size_max);
			return -EINVAL;
		}

		if (mqprio_qopt->qopt.offset[i] != queue_sum) {
			dev_err(&hdev->pdev->dev,
				"qopt queue offset must start from 0, and being continuous\n");
			return -EINVAL;
		}

		ret = hclge_mqprio_qopt_check_rate(hdev,
						   mqprio_qopt->min_rate[i],
						   mqprio_qopt->max_rate[i]);
		if (ret)
			return ret;

		queue_sum = mqprio_qopt->qopt.offset[i];
		queue_sum += mqprio_qopt->qopt.count[i];
	}
	if (hdev->vport[0].alloc_tqps < queue_sum) {
		dev_err(&hdev->pdev->dev,
			"qopt queue count sum should be less than %u\n",
			hdev->vport[0].alloc_tqps);
		return -EINVAL;
	}

	return 0;
}

static void hclge_sync_mqprio_qopt(struct hnae3_tc_info *tc_info,
				   struct tc_mqprio_qopt_offload *mqprio_qopt)
{
	memset(tc_info, 0, sizeof(*tc_info));
	tc_info->num_tc = mqprio_qopt->qopt.num_tc;
	memcpy(tc_info->prio_tc, mqprio_qopt->qopt.prio_tc_map,
	       sizeof_field(struct hnae3_tc_info, prio_tc));
	memcpy(tc_info->tqp_count, mqprio_qopt->qopt.count,
	       sizeof_field(struct hnae3_tc_info, tqp_count));
	memcpy(tc_info->tqp_offset, mqprio_qopt->qopt.offset,
	       sizeof_field(struct hnae3_tc_info, tqp_offset));
	memcpy(tc_info->max_rate, mqprio_qopt->max_rate,
	       sizeof_field(struct hnae3_tc_info, max_rate));
}

static int hclge_config_tc(struct hclge_dev *hdev,
			   struct hnae3_tc_info *tc_info)
{
	int ret;
	int i;

	hclge_tm_schd_info_update(hdev, tc_info->num_tc);
	for (i = 0; i < HNAE3_MAX_USER_PRIO; i++)
		hdev->tm_info.prio_tc[i] = tc_info->prio_tc[i];

	ret = hclge_map_update(hdev);
	if (ret)
		return ret;

	if (hnae3_dev_roh_supported(hdev) || hnae3_dev_ubl_supported(hdev->ae_dev))
		return hclge_tm_set_tc_rate_limit(hdev, tc_info);

	return 0;
}

/* Set up TC for hardware offloaded mqprio in channel mode */
static int hclge_setup_tc(struct hnae3_handle *h,
			  struct tc_mqprio_qopt_offload *mqprio_qopt)
{
	struct hclge_vport *vport = hclge_get_vport(h);
	struct hnae3_knic_private_info *kinfo;
	struct hclge_dev *hdev = vport->back;
	struct hnae3_tc_info old_tc_info;
	u8 tc = mqprio_qopt->qopt.num_tc;
	int ret;

	/* if client unregistered, it's not allowed to change
	 * mqprio configuration, which may cause uninit ring
	 * fail.
	 */
	if (!test_bit(HCLGE_STATE_NIC_REGISTERED, &hdev->state))
		return -EBUSY;

	kinfo = &vport->nic.kinfo;
	if (kinfo->tc_info.dcb_ets_active)
		return -EINVAL;

	ret = hclge_mqprio_qopt_check(hdev, mqprio_qopt);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to check mqprio qopt params, ret = %d\n", ret);
		return ret;
	}

	kinfo->tc_info.mqprio_destroy = !tc;

	ret = hclge_notify_down_uinit(hdev);
	if (ret)
		return ret;

	memcpy(&old_tc_info, &kinfo->tc_info, sizeof(old_tc_info));
	hclge_sync_mqprio_qopt(&kinfo->tc_info, mqprio_qopt);
	kinfo->tc_info.mqprio_active = tc > 0;

	ret = hclge_config_tc(hdev, &kinfo->tc_info);
	if (ret)
		goto err_out;

	return hclge_notify_init_up(hdev);

err_out:
	if (!tc) {
		dev_warn(&hdev->pdev->dev,
			 "failed to destroy mqprio, will active after reset, ret = %d\n",
			 ret);
	} else {
		/* roll-back */
		memcpy(&kinfo->tc_info, &old_tc_info, sizeof(old_tc_info));
		if (hclge_config_tc(hdev, &kinfo->tc_info))
			dev_err(&hdev->pdev->dev,
				"failed to roll back tc configuration\n");
	}
	hclge_notify_init_up(hdev);

	return ret;
}

static const struct hnae3_dcb_ops hns3_dcb_ops = {
	.ieee_getets	= hclge_ieee_getets,
	.ieee_setets	= hclge_ieee_setets,
	.ieee_getpfc	= hclge_ieee_getpfc,
	.ieee_setpfc	= hclge_ieee_setpfc,
	.ieee_setapp    = hclge_ieee_setapp,
	.ieee_delapp    = hclge_ieee_delapp,
	.getdcbx	= hclge_getdcbx,
	.setdcbx	= hclge_setdcbx,
	.setup_tc	= hclge_setup_tc,
	.ieee_setmaxrate = hclge_ieee_setmaxrate,
	.ieee_getmaxrate = hclge_ieee_getmaxrate,
	.setbuffer	= hclge_setbuffer,
	.getbuffer	= hclge_getbuffer,
};

void hclge_dcb_ops_set(struct hclge_dev *hdev)
{
	struct hclge_vport *vport = hdev->vport;
	struct hnae3_knic_private_info *kinfo;

	/* Hdev does not support DCB or vport is
	 * not a pf, then dcb_ops is not set.
	 */
	if (!hnae3_dev_dcb_supported(hdev) ||
	    vport->vport_id != 0)
		return;

	kinfo = &vport->nic.kinfo;
	kinfo->dcb_ops = &hns3_dcb_ops;
	hdev->dcbx_cap = DCB_CAP_DCBX_VER_IEEE | DCB_CAP_DCBX_HOST;
}
