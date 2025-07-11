# SPDX-License-Identifier: GPL-2.0+
#
# Makefile for the HISILICON network device drivers.
#

ccflags-y += -I$(srctree)/$(src)
ccflags-y += -I$(srctree)/drivers/net/ub/dev
ccflags-y += -I$(srctree)/drivers/net/ethernet/hisilicon/hns3/hns3pf
ccflags-y += -I$(srctree)/drivers/net/ethernet/hisilicon/hns3/hns3vf
ccflags-y += -I$(srctree)/drivers/net/ethernet/hisilicon/hns3/hns3_common

obj-$(CONFIG_HNS3) += hnae3.o

obj-$(CONFIG_HNS3_ENET) += hns3.o
hns3-objs = hns3_enet.o hns3_ethtool.o hns3_debugfs.o
hns3-objs += hns3_ext.o hns3_roh.o

hns3-$(CONFIG_HNS3_DCB) += hns3_dcbnl.o
hns3-$(CONFIG_HNS3_UBL) += hns3_unic.o hns3_unic_debugfs.o

obj-$(CONFIG_HNS3_HCLGEVF) += hclgevf.o

hclgevf-objs = hns3vf/hclgevf_main.o hns3vf/hclgevf_mbx.o  hns3vf/hclgevf_devlink.o hns3vf/hclgevf_regs.o \
		hns3_common/hclge_comm_cmd.o hns3_common/hclge_comm_rss.o hns3_common/hclge_comm_tqp_stats.o
hclgevf-$(CONFIG_HNS3_UBL) += hns3_common/hclge_comm_unic_addr.o hns3vf/hclgevf_unic_ip.o hns3vf/hclgevf_unic_guid.o \
				hns3vf/hclgevf_unic_addr.o
hclgevf-$(CONFIG_UB_UDMA_HNS3) += hns3vf/hclgevf_udma.o
hclgevf-$(CONFIG_HNS3_DCB) += hns3vf/hclgevf_dcb.o

obj-$(CONFIG_HNS3_HCLGE) += hclge.o
hclge-objs = hns3pf/hclge_main.o hns3pf/hclge_mdio.o hns3pf/hclge_tm.o hns3pf/hclge_sysfs.o hns3pf/hclge_regs.o \
		hns3pf/hclge_mbx.o hns3pf/hclge_err.o  hns3pf/hclge_debugfs.o hns3pf/hclge_ptp.o hns3pf/hclge_devlink.o \
		hns3_common/hclge_comm_cmd.o hns3_common/hclge_comm_rss.o hns3_common/hclge_comm_tqp_stats.o
hclge-objs += hns3pf/hclge_ext.o

hclge-$(CONFIG_HNS3_UBL) += hns3_common/hclge_comm_unic_addr.o hns3pf/hclge_unic_ip.o hns3pf/hclge_unic_guid.o \
			hns3pf/hclge_unic_addr.o hns3pf/hclge_unic_debugfs.o
hclge-$(CONFIG_UB_UDMA_HNS3) += hns3pf/hclge_udma.o
hclge-$(CONFIG_HNS3_DCB) += hns3pf/hclge_dcb.o
