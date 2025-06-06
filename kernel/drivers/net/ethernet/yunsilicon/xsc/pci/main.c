// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "common/driver.h"
#include "common/cq.h"
#include "common/qp.h"
#include "common/xsc_lag.h"
#include "common/xsc_port_ctrl.h"
#include "devlink.h"
#include "eswitch.h"
#include "xsc_pci_ctrl.h"

unsigned int xsc_debug_mask;
module_param_named(debug_mask, xsc_debug_mask, uint, 0644);
MODULE_PARM_DESC(debug_mask,
		 "debug mask: 1=dump cmd data, 2=dump cmd exec time, 3=both. Default=0");

unsigned int xsc_log_level = XSC_LOG_LEVEL_WARN;
module_param_named(log_level, xsc_log_level, uint, 0644);
MODULE_PARM_DESC(log_level,
		 "lowest log level to print: 0=debug, 1=info, 2=warning, 3=error. Default=2");
EXPORT_SYMBOL(xsc_log_level);

static bool probe_vf = 1;
module_param_named(probe_vf, probe_vf, bool, 0644);
MODULE_PARM_DESC(probe_vf, "probe VFs or not, 0 = not probe, 1 = probe. Default = 1");

static bool xsc_hw_reset;

#define DRIVER_NAME			"xsc_pci"
#define ETH_DRIVER_NAME			"xsc_eth"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Yunsilicon network adapters pci driver");
MODULE_VERSION(DRIVER_VERSION);

static const struct pci_device_id xsc_pci_id_table[] = {
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MC_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID_DIAMOND) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID_DIAMOND_NEXT) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_HOST_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_HOST_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_SOC_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MS_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_HOST_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_HOST_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_SOC_PF_DEV_ID) },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, xsc_pci_id_table);

static const struct xsc_device_product_info xsc_product_list[] = {
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MC_50, "metaConnect-50")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MC_100, "metaConnect-100")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MC_200, "metaConnect-200")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID_DIAMOND,
				 XSC_SUB_DEV_ID_MC_400S, "metaConnect-400S")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID_DIAMOND_NEXT,
				 XSC_SUB_DEV_ID_MC_400S, "metaConnect-400S")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MF_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MF_50, "metaFusion-50")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MF_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MF_200, "metaFusion-200")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_50, "metaScale-50")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_100Q, "metaScale-100Q")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_200, "metaScale-200")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_200S, "metaScale-200S")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_400M, "metaScale-400M")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_200_OCP, "metaScale-200-OCP")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_100S_OCP, "metaScale-100S-OCP")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MV_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MV_100, "metaVisor-100")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MV_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MV_200, "metaVisor-200")},
	{0}
};

#define	IS_VIRT_FUNCTION(id) ((id)->driver_data == XSC_PCI_DEV_IS_VF)

static bool need_write_reg_directly(void *in)
{
	struct xsc_inbox_hdr *hdr;
	struct xsc_ioctl_mbox_in *req;
	struct xsc_ioctl_data_tl *tl;
	char *data;

	hdr = (struct xsc_inbox_hdr *)in;
	if (unlikely(be16_to_cpu(hdr->opcode) == XSC_CMD_OP_IOCTL_FLOW)) {
		req = (struct xsc_ioctl_mbox_in *)in;
		data = (char *)req->data;
		tl = (struct xsc_ioctl_data_tl *)data;
		if (tl->opmod == XSC_IOCTL_OP_ADD) {
			if (unlikely(tl->table == XSC_FLOW_DMA_WR || tl->table == XSC_FLOW_DMA_RD))
				return true;
		}
	}
	return false;
}

int xsc_cmd_exec(struct xsc_core_device *dev, void *in, int in_size, void *out,
		 int out_size)
{
	if (need_write_reg_directly(in))
		return xsc_cmd_write_reg_directly(dev, in, in_size, out,
						  out_size, dev->glb_func_id);
	return _xsc_cmd_exec(dev, in, in_size, out, out_size);
}
EXPORT_SYMBOL(xsc_cmd_exec);

static int set_dma_caps(struct pci_dev *pdev)
{
	int err = 0;

	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err)
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	else
		err = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));

	if (!err)
		dma_set_max_seg_size(&pdev->dev, 2u * 1024 * 1024 * 1024);

	return err;
}

static int xsc_pci_enable_device(struct xsc_core_device *dev)
{
	struct pci_dev *pdev = dev->pdev;
	int err = 0;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == XSC_PCI_STATUS_DISABLED) {
		err = pci_enable_device(pdev);
		if (!err)
			dev->pci_status = XSC_PCI_STATUS_ENABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);

	return err;
}

static void xsc_pci_disable_device(struct xsc_core_device *dev)
{
	struct pci_dev *pdev = dev->pdev;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == XSC_PCI_STATUS_ENABLED) {
		pci_disable_device(pdev);
		dev->pci_status = XSC_PCI_STATUS_DISABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);
}

static int xsc_priv_init(struct xsc_core_device *dev)
{
	struct xsc_priv *priv = &dev->priv;

	strscpy(priv->name, dev_name(&dev->pdev->dev), XSC_MAX_NAME_LEN);
	priv->name[XSC_MAX_NAME_LEN - 1] = 0;

	INIT_LIST_HEAD(&priv->ctx_list);
	spin_lock_init(&priv->ctx_lock);
	mutex_init(&dev->intf_state_mutex);

	return 0;
}

static int xsc_dev_res_init(struct xsc_core_device *dev)
{
	struct xsc_dev_resource *dev_res = NULL;

	dev_res = kvzalloc(sizeof(*dev_res), GFP_KERNEL);
	if (!dev_res)
		return -ENOMEM;

	dev->dev_res = dev_res;
	/* init access lock */
	spin_lock_init(&dev->reg_access_lock);
	mutex_init(&dev_res->alloc_mutex);
	mutex_init(&dev_res->pgdir_mutex);
	INIT_LIST_HEAD(&dev_res->pgdir_list);
	spin_lock_init(&dev_res->mkey_lock);

	return 0;
}

static void xsc_dev_res_cleanup(struct xsc_core_device *dev)
{
	kfree(dev->dev_res);
	dev->dev_res = NULL;
}

int xsc_dev_init(struct xsc_core_device *dev)
{
	int err = 0;

	xsc_priv_init(dev);

	err = xsc_dev_res_init(dev);
	if (err) {
		xsc_core_err(dev, "xsc dev res init failed %d\n", err);
		goto err_res_init;
	}

	/* create debugfs */
	err = xsc_debugfs_init(dev);
	if (err) {
		xsc_core_err(dev, "xsc_debugfs_init failed %d\n", err);
		goto err_debugfs_init;
	}

	return 0;

err_debugfs_init:
	xsc_dev_res_cleanup(dev);
err_res_init:
	return err;
}

void xsc_dev_cleanup(struct xsc_core_device *dev)
{
//	iounmap(dev->iseg);
	xsc_debugfs_fini(dev);
	xsc_dev_res_cleanup(dev);
}

static void xsc_product_info(struct pci_dev *pdev)
{
	const struct xsc_device_product_info *p_info = xsc_product_list;

	while (p_info->vendor) {
		if (pdev->device == p_info->device && pdev->subsystem_device == p_info->subdevice) {
			pr_info("Product: %s, Vendor: Yunsilicon\n", p_info->product_name);
			break;
		}
		p_info++;
	}
}

static int xsc_pci_init(struct xsc_core_device *dev, const struct pci_device_id *id)
{
	struct pci_dev *pdev = dev->pdev;
	int err = 0;
	int bar_num = 0;
	void __iomem *bar_base = NULL;

	mutex_init(&dev->pci_status_mutex);
	dev->priv.numa_node = dev_to_node(&pdev->dev);
	if (dev->priv.numa_node == -1)
		dev->priv.numa_node = 0;

	/* enable the device */
	err = xsc_pci_enable_device(dev);
	if (err) {
		xsc_core_err(dev, "failed to enable PCI device: err=%d\n", err);
		goto err_ret;
	}

	err = pci_request_region(pdev, bar_num, KBUILD_MODNAME);
	if (err) {
		xsc_core_err(dev, "failed to request %s pci_region=%d: err=%d\n",
			     KBUILD_MODNAME, bar_num, err);
		goto err_disable;
	}

	pci_set_master(pdev);

	err = set_dma_caps(pdev);
	if (err) {
		xsc_core_err(dev, "failed to set DMA capabilities mask: err=%d\n", err);
		goto err_clr_master;
	}

	bar_base = pci_ioremap_bar(pdev, bar_num);
	if (!bar_base) {
		xsc_core_err(dev, "failed to ioremap %s bar%d\n", KBUILD_MODNAME, bar_num);
		goto err_clr_master;
	}

	err = pci_save_state(pdev);
	if (err) {
		xsc_core_err(dev, "pci_save_state failed: err=%d\n", err);
		goto err_io_unmap;
	}

	dev->bar_num = bar_num;
	dev->bar = bar_base;

	xsc_init_hal(dev, id->device);

	return 0;

err_io_unmap:
	pci_iounmap(pdev, bar_base);
err_clr_master:
	pci_clear_master(pdev);
	pci_release_region(pdev, bar_num);
err_disable:
	xsc_pci_disable_device(dev);
err_ret:
	return err;
}

static void xsc_pci_fini(struct xsc_core_device *dev)
{
	struct pci_dev *pdev = dev->pdev;

	if (dev->bar)
		pci_iounmap(pdev, dev->bar);
	pci_clear_master(pdev);
	pci_release_region(pdev, dev->bar_num);
	xsc_pci_disable_device(dev);
}

static int xsc_check_cmdq_version(struct xsc_core_device *dev)
{
	struct xsc_cmd_query_cmdq_ver_mbox_out *out;
	struct xsc_cmd_query_cmdq_ver_mbox_in in;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto no_mem_out;
	}

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_CMDQ_VERSION);

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out));
	if (err)
		goto out_out;

	if (out->hdr.status) {
		err = xsc_cmd_status_to_err(&out->hdr);
		goto out_out;
	}

	if (be16_to_cpu(out->cmdq_ver) != CMDQ_VERSION) {
		xsc_core_err(dev, "cmdq version check failed, expecting version %d, actual version %d\n",
			     CMDQ_VERSION, be16_to_cpu(out->cmdq_ver));
		err = -EINVAL;
		goto out_out;
	}
	dev->cmdq_ver = CMDQ_VERSION;

out_out:
	kfree(out);
no_mem_out:
	return err;
}

static int xsc_reset_function_resource(struct xsc_core_device *dev)
{
	struct xsc_function_reset_mbox_in in;
	struct xsc_function_reset_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_FUNCTION_RESET);
	in.glb_func_id = cpu_to_be16(dev->glb_func_id);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status)
		return -EINVAL;

	return 0;
}

int xsc_chip_type(struct xsc_core_device *dev)
{
	switch (dev->pdev->device) {
	case XSC_MC_PF_DEV_ID:
	case XSC_MC_VF_DEV_ID:
		return XSC_CHIP_MC;
	case XSC_MF_HOST_PF_DEV_ID:
	case XSC_MF_HOST_VF_DEV_ID:
	case XSC_MF_SOC_PF_DEV_ID:
		return XSC_CHIP_MF;
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		return XSC_CHIP_MS;
	case XSC_MV_HOST_PF_DEV_ID:
	case XSC_MV_HOST_VF_DEV_ID:
	case XSC_MV_SOC_PF_DEV_ID:
		return XSC_CHIP_MV;
	default:
		return XSC_CHIP_UNKNOWN;
	}
}
EXPORT_SYMBOL(xsc_chip_type);

#if defined(__sw_64__)
static void xsc_enable_relaxed_order(struct xsc_core_device *dev)
{
	struct xsc_cmd_enable_relaxed_order_in in;
	struct xsc_cmd_enable_relaxed_order_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_RELAXED_ORDER);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		goto err_out;

	if (out.hdr.status) {
		err = xsc_cmd_status_to_err(&out.hdr);
		goto err_out;
	}

	return;
err_out:
	xsc_core_warn(dev, "Failed to enable relaxed order %d\n", err);
}
#endif

static int xsc_cmd_activate_hw_config(struct xsc_core_device *dev)
{
	struct xsc_cmd_activate_hw_config_mbox_in in;
	struct xsc_cmd_activate_hw_config_mbox_out out;
	int err = 0;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ACTIVATE_HW_CONFIG);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;
	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);
	return 0;
}

static int xsc_cmd_query_guid(struct xsc_core_device *dev)
{
	struct xsc_cmd_query_guid_mbox_in in;
	struct xsc_cmd_query_guid_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_GUID);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);
	dev->board_info->guid = out.guid;
	return 0;
}

static int xsc_cmd_announce_driver_instance(struct xsc_core_device *dev, u8 status)
{
	struct xsc_cmd_announce_driver_instance_mbox_in in;
	struct xsc_cmd_announce_driver_instance_mbox_out out;
	struct xsc_core_device *rep_dev;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ANNOUNCE_DRIVER_INSTANCE);
	in.status = status;
	if (status == DRIVER_INSTANCE_UPDATE_REP_FUNC) {
		rep_dev = list_first_entry_or_null(&dev->board_info->func_list,
						   struct xsc_core_device, func_node);
		in.rep_func_id = cpu_to_be16(rep_dev->glb_func_id);
	}
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status) {
		if (out.hdr.status == XSC_CMD_STATUS_NOT_SUPPORTED) {
			dev->board_info->resource_access_mode = dev->reg_mr_via_cmdq;
			return 0;
		}
		return xsc_cmd_status_to_err(&out.hdr);
	}

	if (status == DRIVER_INSTANCE_LAUNCH)
		dev->board_info->resource_access_mode = out.resource_access_mode;
	return 0;
}

static int xsc_board_level_init(struct xsc_core_device *dev)
{
	int err = 0;

	if (dev->board_info->ref_cnt) {
		dev->board_info->ref_cnt++;
		list_add_tail(&dev->func_node, &dev->board_info->func_list);
		return 0;
	}

	err = xsc_cmd_announce_driver_instance(dev, DRIVER_INSTANCE_LAUNCH);
	if (err) {
		xsc_core_err(dev, "failed to announce driver instance launch\n");
		goto out;
	}
	err = xsc_cmd_query_guid(dev);
	if (err) {
		xsc_core_err(dev, "failed to query guid, err=%d\n", err);
		goto out;
	}

	err = xsc_cmd_activate_hw_config(dev);
	if (err) {
		xsc_core_err(dev, "failed to activate hw config, err=%d\n", err);
		goto out;
	}

#if defined(__sw_64__)
	xsc_enable_relaxed_order(dev);
#endif
	if (dev->board_info->resource_access_mode == EXCLUSIVE_MODE) {
		err = xsc_create_res(dev);
		if (err) {
			xsc_core_err(dev, "Failed to create resource, err=%d\n", err);
			goto out;
		}
	}
	dev->board_info->rep_func_id = dev->glb_func_id;
	dev->board_info->ref_cnt++;
	list_add_tail(&dev->func_node, &dev->board_info->func_list);

out:
	return err;
}

static void xsc_board_level_uninit(struct xsc_core_device *dev)
{
	dev->board_info->ref_cnt--;
	list_del(&dev->func_node);
	if (dev->board_info->ref_cnt) {
		if (dev->glb_func_id == dev->board_info->rep_func_id)
			xsc_cmd_announce_driver_instance(dev, DRIVER_INSTANCE_UPDATE_REP_FUNC);
		return;
	}

	xsc_cmd_announce_driver_instance(dev, DRIVER_INSTANCE_PHASE_OUT);

	if (dev->board_info->resource_access_mode == EXCLUSIVE_MODE)
		xsc_destroy_res(dev);
}

static int xsc_init_once(struct xsc_core_device *dev)
{
	int err;

	err = xsc_cmd_init(dev);
	if (err) {
		xsc_core_err(dev, "Failed initializing command interface, aborting\n");
		goto err_cmd_init;
	}

	err = xsc_check_cmdq_version(dev);
	if (err) {
		xsc_core_err(dev, "Failed to check cmdq version\n");
		goto err_cmdq_ver_chk;
	}

	err = xsc_cmd_query_hca_cap(dev, &dev->caps);
	if (err) {
		xsc_core_err(dev, "Failed to query hca, err=%d\n", err);
		goto err_cmdq_ver_chk;
	}

	err = xsc_reset_function_resource(dev);
	if (err) {
		xsc_core_err(dev, "Failed to reset function resource\n");
		goto err_cmdq_ver_chk;
	}

	xsc_init_cq_table(dev);
	xsc_init_qp_table(dev);
	xsc_eq_init(dev);

	err = xsc_sriov_init(dev);
	if (err) {
		xsc_core_err(dev, "Failed to init sriov %d\n", err);
		goto err_sriov_init;
	}
	err = xsc_eswitch_init(dev);
	if (err) {
		xsc_core_err(dev, "Failed to init eswitch %d\n", err);
		goto err_eswitch_init;
	}
	err = xsc_board_level_init(dev);
	if (err)
		goto err_board_init;

	return 0;

err_board_init:
	xsc_eswitch_cleanup(dev);
err_eswitch_init:
	xsc_sriov_cleanup(dev);
err_sriov_init:
	xsc_eq_cleanup(dev);
	xsc_cleanup_qp_table(dev);
	xsc_cleanup_cq_table(dev);
err_cmdq_ver_chk:
	xsc_cmd_cleanup(dev);
err_cmd_init:
	return err;
}

static int xsc_cleanup_once(struct xsc_core_device *dev)
{
	xsc_eswitch_cleanup(dev);
	xsc_sriov_cleanup(dev);
	xsc_eq_cleanup(dev);
	xsc_cleanup_qp_table(dev);
	xsc_cleanup_cq_table(dev);
	xsc_cmd_cleanup(dev);
	return 0;
}

static int xsc_load(struct xsc_core_device *dev)
{
	int err;

	err = xsc_irq_eq_create(dev);
	if (err) {
		xsc_core_err(dev, "xsc_irq_eq_create failed %d\n", err);
		goto err_irq_eq_create;
	}

	err = xsc_sriov_attach(dev);
	if (err) {
		xsc_core_err(dev, "sriov init failed %d\n", err);
		goto err_sriov;
	}
	return 0;

err_sriov:
	xsc_irq_eq_destroy(dev);
err_irq_eq_create:
	return err;
}

static int xsc_unload(struct xsc_core_device *dev)
{
	xsc_sriov_detach(dev);
	if (xsc_fw_is_available(dev))
		xsc_irq_eq_destroy(dev);

	return 0;
}

static int xsc_load_one(struct xsc_core_device *dev, bool boot)
{
	int err = 0;

	mutex_lock(&dev->intf_state_mutex);
	if (test_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state)) {
		xsc_core_warn(dev, "interface is up, NOP\n");
		goto out;
	}

	if (test_bit(XSC_INTERFACE_STATE_TEARDOWN, &dev->intf_state)) {
		xsc_core_warn(dev, "device is being removed, stop load\n");
		err = -ENODEV;
		goto out;
	}

	if (boot) {
		err = xsc_init_once(dev);
		if (err) {
			xsc_core_err(dev, "xsc_init_once failed %d\n", err);
			goto err_dev_init;
		}
	}

	err = xsc_load(dev);
	if (err) {
		xsc_core_err(dev, "xsc_load failed %d\n", err);
		goto err_load;
	}

	if (boot) {
		err = xsc_devlink_register(priv_to_devlink(dev), dev->device);
		if (err)
			goto err_devlink_reg;
	}

	if (xsc_core_is_pf(dev))
		xsc_lag_add_xdev(dev);

	if (xsc_device_registered(dev)) {
		xsc_attach_device(dev);
	} else {
		err = xsc_register_device(dev);
		if (err) {
			xsc_core_err(dev, "register device failed %d\n", err);
			goto err_reg_dev;
		}
	}

	err = xsc_port_ctrl_probe(dev);
	if (err) {
		xsc_core_err(dev, "failed to probe port control node\n");
		goto err_port_ctrl;
	}

	set_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state);
	mutex_unlock(&dev->intf_state_mutex);

	return err;

err_port_ctrl:
	xsc_unregister_device(dev);
err_reg_dev:
	if (xsc_core_is_pf(dev))
		xsc_lag_remove_xdev(dev);
	if (boot)
		xsc_devlink_unregister(priv_to_devlink(dev));
err_devlink_reg:
	xsc_unload(dev);

err_load:
	if (boot)
		xsc_cleanup_once(dev);
err_dev_init:
out:
	mutex_unlock(&dev->intf_state_mutex);
	return err;
}

static int xsc_unload_one(struct xsc_core_device *dev, bool cleanup)
{
	xsc_port_ctrl_remove(dev);
	xsc_devlink_unregister(priv_to_devlink(dev));
	if (cleanup)
		xsc_unregister_device(dev);
	mutex_lock(&dev->intf_state_mutex);
	if (!test_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state)) {
		xsc_core_warn(dev, "%s: interface is down, NOP\n",
			      __func__);
		if (cleanup)
			xsc_cleanup_once(dev);
		goto out;
	}

	clear_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state);
	if (xsc_device_registered(dev))
		xsc_detach_device(dev);

	if (xsc_core_is_pf(dev))
		xsc_lag_remove_xdev(dev);

	xsc_board_level_uninit(dev);
	xsc_unload(dev);

	if (cleanup)
		xsc_cleanup_once(dev);

out:
	mutex_unlock(&dev->intf_state_mutex);

	return 0;
}

static int xsc_pci_probe(struct pci_dev *pci_dev,
			 const struct pci_device_id *id)
{
	struct xsc_core_device *xdev;
	struct xsc_priv *priv;
	int err;
	struct devlink *devlink;
	devlink = xsc_devlink_alloc();
	if (!devlink) {
		dev_err(&pci_dev->dev, "devlink alloc failed\n");
		return -ENOMEM;
	}
	xdev = devlink_priv(devlink);

	xsc_product_info(pci_dev);
	xdev->pdev = pci_dev;
	xdev->device = &pci_dev->dev;
	priv = &xdev->priv;
	xdev->coredev_type = (IS_VIRT_FUNCTION(id)) ?
				XSC_COREDEV_VF : XSC_COREDEV_PF;
	xsc_core_info(xdev, "dev_type=%d is_vf=%d\n",
		      xdev->coredev_type, pci_dev->is_virtfn);

	priv->sriov.probe_vf = probe_vf;
	if ((IS_VIRT_FUNCTION(id)) && !probe_vf) {
		xsc_core_err(xdev, "VFs are not binded to xsc driver\n");
		return 0;
	}

	/* init pcie device */
	pci_set_drvdata(pci_dev, xdev);
	err = xsc_pci_init(xdev, id);
	if (err) {
		xsc_core_err(xdev, "xsc_pci_init failed %d\n", err);
		goto err_pci_init;
	}

	err = xsc_dev_init(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_dev_init failed %d\n", err);
		goto err_dev_init;
	}

	err = xsc_load_one(xdev, true);
	if (err) {
		xsc_core_err(xdev, "xsc_load_one failed %d\n", err);
		goto err_load;
	}

	request_module_nowait(ETH_DRIVER_NAME);

	return 0;

err_load:
	xsc_dev_cleanup(xdev);
err_dev_init:
	xsc_pci_fini(xdev);
err_pci_init:
	pci_set_drvdata(pci_dev, NULL);
	xsc_devlink_free(devlink);
	return err;
}

static void xsc_pci_remove(struct pci_dev *pci_dev)
{
	struct xsc_core_device *xdev = pci_get_drvdata(pci_dev);

	set_bit(XSC_INTERFACE_STATE_TEARDOWN, &xdev->intf_state);
	xsc_unload_one(xdev, true);
	xsc_dev_cleanup(xdev);

	xsc_pci_fini(xdev);
	pci_set_drvdata(pci_dev, NULL);
	xsc_devlink_free(priv_to_devlink(xdev));
}

static struct pci_driver xsc_pci_driver = {
	.name		= "xsc-pci",
	.id_table	= xsc_pci_id_table,
	.probe		= xsc_pci_probe,
	.remove		= xsc_pci_remove,

	.sriov_configure   = xsc_core_sriov_configure,
};

static int xsc_pci_reboot_event_handler(struct notifier_block *nb, unsigned long action, void *data)
{
	pr_info("xsc pci driver recv %lu event\n", action);
	if (xsc_get_exit_flag())
		return NOTIFY_OK;
	xsc_pci_exit();

	return NOTIFY_OK;
}

struct notifier_block xsc_pci_nb = {
	.notifier_call = xsc_pci_reboot_event_handler,
	.next = NULL,
	.priority = 0,
};

void xsc_pci_exit(void)
{
	xsc_stop_delayed_release();
	pci_unregister_driver(&xsc_pci_driver);
	xsc_pci_ctrl_fini();
	xsc_port_ctrl_fini();
	xsc_unregister_debugfs();
	qpts_fini();
	xsc_free_board_info();
}

static int __init xsc_init(void)
{
	int err;

	xsc_register_debugfs();

	qpts_init();

	err = xsc_port_ctrl_init();
	if (err) {
		pr_err("failed to initialize port control\n");
		goto err_port_ctrl;
	}

	err = xsc_pci_ctrl_init();
	if (err) {
		pr_err("failed to initialize dpdk ctrl\n");
		goto err_pci_ctrl;
	}

	xsc_hw_reset = false;
	err = pci_register_driver(&xsc_pci_driver);
	if (err) {
		pr_err("failed to register pci driver\n");
		goto err_register;
	}

	xsc_init_delayed_release();
	register_reboot_notifier(&xsc_pci_nb);

	return 0;

err_register:
	xsc_pci_ctrl_fini();
err_pci_ctrl:
	xsc_port_ctrl_fini();
err_port_ctrl:
	xsc_unregister_debugfs();
	qpts_fini();
	return err;
}

static void __exit xsc_fini(void)
{
	unregister_reboot_notifier(&xsc_pci_nb);
	xsc_pci_exit();
}

module_init(xsc_init);
module_exit(xsc_fini);

