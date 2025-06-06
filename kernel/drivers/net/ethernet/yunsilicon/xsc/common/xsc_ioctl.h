/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_IOCTL_H
#define XSC_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* Documentation/ioctl/ioctl-number.txt */
#define XSC_IOCTL_MAGIC	(0x1b)	/* TBD */
#define XSC_IOCTL_CMDQ \
	_IOWR(XSC_IOCTL_MAGIC, 1, struct xsc_ioctl_hdr)
#define XSC_IOCTL_DRV_GET \
	_IOR(XSC_IOCTL_MAGIC, 2, struct xsc_ioctl_hdr)
#define XSC_IOCTL_DRV_SET \
	_IOWR(XSC_IOCTL_MAGIC, 3, struct xsc_ioctl_hdr)
#define XSC_IOCTL_MEM \
	_IOWR(XSC_IOCTL_MAGIC, 4, struct xsc_ioctl_hdr)
#define XSC_IOCTL_CMDQ_RAW \
	_IOWR(XSC_IOCTL_MAGIC, 5, struct xsc_ioctl_hdr)
#define XSC_IOCTL_USER_MODE \
	_IOWR(XSC_IOCTL_MAGIC, 8, struct xsc_ioctl_hdr)


#define XSC_IOCTL_CHECK_FILED		0x01234567
enum {
	XSC_IOCTL_OP_GET_LOCAL,
	XSC_IOCTL_OP_GET_VF_INFO,
	XSC_IOCTL_OP_GET_CONTEXT,
	XSC_IOCTL_OP_GET_INFO_BY_BDF,
	XSC_IOCTL_OP_GET_MAX
};

enum {
	XSC_IOCTL_GET_PHY_INFO		= 0x100,
	XSC_IOCTL_GET_FORCE_PCP	= 0x101,
	XSC_IOCTL_GET_FORCE_DSCP	= 0x102,
	XSC_IOCTL_GET_CMA_PCP		= 0x103,
	XSC_IOCTL_GET_CMA_DSCP		= 0x104,
	XSC_IOCTL_GET_CONTEXT		= 0x105,
	XSC_IOCTL_GET_DEVINFO	= 0x106,
	XSC_IOCTL_GAT_MAX
};

enum {
	XSC_IOCTL_SET_QP_STATUS     = 0x200,
	XSC_IOCTL_SET_FORCE_PCP    = 0x201,
	XSC_IOCTL_SET_FORCE_DSCP   = 0x202,
	XSC_IOCTL_SET_CMA_PCP		= 0x203,
	XSC_IOCTL_SET_CMA_DSCP		= 0x204,
	XSC_IOCTL_SET_MAX
};

enum {
	XSC_IOCTL_MEM_ALLOC		= 0x300,
	XSC_IOCTL_MEM_FREE,
	XSC_IOCTL_MEM_MAX
};

enum {
	XSC_IOCTL_GET_VECTOR_MATRIX	= 0x400,
	XSC_IOCTL_SET_LOG_LEVEL		= 0x401,
	XSC_IOCTL_SET_CMD_VERBOSE	= 0x402,
	XSC_IOCTL_DRIVER_MAX
};

enum {
	XSC_IOCTL_OPCODE_VF_USER_MODE = 0x600,
	XSC_IOCTL_OPCODE_PF_USER_MODE = 0x601,
	XSC_IOCTL_OPCODE_BOND_USER_MODE = 0x602,
};

enum {
	XSC_USER_MODE_FWD_BCAST_PKT_BIT = 0,
	XSC_USER_MODE_FWD_LLDP_PKT_BIT,
	XSC_USER_MODE_FWD_PKT_NUM,
};

enum  xsc_flow_tbl_id {
	XSC_FLOW_TBL_IPAT,	//IN_PORT_ATTR
	XSC_FLOW_TBL_IPVLANMT,	//IN_PORT_VLAN_MEMBER
	XSC_FLOW_TBL_IN_VLAN_M,	//IN_VLAN_MAPPING
	XSC_FLOW_TBL_HOST_VLAN_M,	//HOST_VLAN_MAPPING
	XSC_FLOW_TBL_PCT_V4,	//PACKET_CLASSIFIER_V4
	XSC_FLOW_TBL_PCT_V6,	//PACKET_CLASSIFIER_V6
	XSC_FLOW_TBL_WCT_KP,	//WCT_KEY_PROFILE
	XSC_FLOW_TBL_WCT,	//WILDCARD_TBL
	XSC_FLOW_TBL_FKP,	//FLOW_KEY_PROFILE
	XSC_FLOW_TBL_EM,	//EXACT_MATCH
	XSC_FLOW_TBL_FAT,	//FLOW_ACTION
	XSC_FLOW_TBL_TNL_ECP,	//TUNNEL_ENCAP
	XSC_FLOW_TBL_ERP_HDR,	//ERSPAN_HDR_INFO
	XSC_FLOW_TBL_MIR_IDX,	//MIRROR_INDEX
	XSC_FLOW_TBL_MIR,	//MIRROR_TBL
	XSC_FLOW_TBL_MIR_HDR,	//ENCAP_MIRROR_HDR
	XSC_FLOW_TBL_VER,	//VERSION_TBL
	XSC_FLOW_TBL_LCMT,	//LCMT_TBL
	XSC_FLOW_TBL_CT,	//CONN_TRACK
	XSC_FLOW_TBL_EPAT,	//EG_PORT_ATTR
	XSC_FLOW_TBL_OPVLANMT,	//OUT_PORT_VLAN_MEMBER
	XSC_FLOW_TBL_RSS_HASH,	//RSS_HASH
	XSC_FLOW_TBL_MDF_MAC,	//MODIFY_MAC
	XSC_FLOW_TBL_MDF_IP,		//MODIFY_IP
	XSC_FLOW_TBL_MDF_TPID,	//MODIFY_TPID
	XSC_FLOW_TBL_ECP_HDR,	//ENCAP_HDR
	XSC_FLOW_TBL_ECP_MAC,	//ENCAP_MAC
	XSC_FLOW_TBL_ECP_IP,	//ENCAP_IP
	XSC_FLOW_TBL_ECP_TPID,	//ENCAP_TPID
	XSC_FLOW_TBL_ECP_TP_TNL,	//ENCAP_TP_TUNNEL
	XSC_FLOW_TBL_ECP_DPORT,	//ENCAP_DPORT
	XSC_FLOW_TBL_VFSO,	//VF_START_OFST
	XSC_FLOW_TBL_IACL,	//INGRESS_ACL
	XSC_FLOW_TBL_IACL_CNT,	//INGRESS_ACL_COUNTER
	XSC_FLOW_TBL_EACL,	//EGRESS_ACL
	XSC_FLOW_TBL_EACL_CNT,	//EGRESS_ACL_COUNTER
	XSC_FLOW_TBL_EM_EXT,	//EXACT_MATCH_EXT
	XSC_FLOW_TBL_EM_EXT_2M_HASH_ADR,	//EM_EXT_2M_HASH_ADDR
	XSC_FLOW_TBL_EM_EXT_1G_HASH_ADR,	//EM_EXT_1G_HASH_ADDR
	XSC_FLOW_TBL_EM_EXT_2M_KEY_ADR,	//EM_EXT_2M_KEY_ADDR
	XSC_FLOW_TBL_EM_EXT_1G_KEY_ADR,	//EM_EXT_1G_KEY_ADDR
	XSC_FLOW_TBL_PG_QP_SET_ID,	//PG_QP_SET_ID
	XSC_FLOW_DIR_REGISTER,	//DIR_REGISTER
	XSC_FLOW_INDIR_REGISTER,	//INDIR_REGISTER
	XSC_FLOW_TBL_BM_PCT_V4,	//BIM MATCH PACKET_CLASSIFIER_V4
	XSC_FLOW_TBL_BM_PCT_V6,	//BIM MATCH PACKET_CLASSIFIER_V6
	XSC_FLOW_TBL_BM_WCT,	//BIM MATCH WILDCARD_TBL
	XSC_FLOW_TBL_BM_IACL,	//BIM MATCH INGRESS_ACL
	XSC_FLOW_TBL_BMT, //BROADCAST MEMBER
	XSC_FLOW_TBL_BOMT, //BROADCAST OUTPUT
	XSC_FLOW_TBL_PST, //pst
	XSC_FLOW_DMA_WR,	//DMA WRITE
	XSC_FLOW_DMA_RD,	//DMA READ
	XSC_FLOW_PARSER_TBL,	//PARSER_TBL
	XSC_FLOW_UDF_AWARE_TBL,	//UDF_AWARE_TBL
	XSC_FLOW_UDF_UNAWARE_TBL,	//UDF_UNAWARE_TBL
	XSC_FLOW_MTR_CTRL_TBL,	//MTR_CTRL_TBL
	XSC_FLOW_MTR_FLOW_PD,	//MTR_FLOW_PD
	XSC_FLOW_MTR_VPORT_PD,	//MTR_VPORT_PD
	XSC_FLOW_MTR_VPG_PD,	//MTR_VPG_PD
	XSC_FLOW_MTR_FLOW_SCAN,	//MTR_FLOW_SCAN
	XSC_FLOW_MTR_VPORT_SCAN,	//MTR_VPORT_SCAN
	XSC_FLOW_MTR_VPG_SCAN,	//MTR_VPG_SCAN
	XSC_FLOW_MTR_MAPPING,	//MTR_MAPPING
	XSC_FLOW_PRG_ACT_IDX,	//PRG_ACT_INDEX
	XSC_FLOW_PRG_ACT0,	//PRG_ACT0
	XSC_FLOW_PRG_ACT1,	//PRG_ACT1
	XSC_FLOW_PRG_ACT2,	//PRG_ACT2
	XSC_FLOW_NIF_PRI_CNT,	//NIF_PRI_CNT
	XSC_FLOW_PRS2CLSF_SRC_PORT_CNT,	//PRS2CLSF_SRC_PORT_CNT
	XSC_FLOW_QUEUE_RX_CNT,	//QUEUE_TX_CNT
	XSC_FLOW_QUEUE_TX_CNT,	//QUEUE_TX_CNT
	XSC_FLOW_MAC_LAG_PORT_SEL,	//MAC_LAG_PORT_SEL
	XSC_FLOW_EXT_CT_CLR,	//EXT_CT_CLR
	XSC_FLOW_IP_TBL_CFG,	//IP_TBL_CFG
	XSC_FLOW_RSS_HASH_INIT_KEY_CFG,	//SS_HASH_INIT_KEY_CFG
	XSC_FLOW_QP_ID_BASE_CFG,	//QP_ID_BASE_CFG
	XSC_FLOW_PSS_INFO,	//CLSF_CTRL_PSS_INFO
	XSC_FLOW_SNAPSHOT,	//SNAPSHOT
	XSC_FLOW_PSS_MATCH_KEY,	//PSS_MATCH_KEY
	XSC_FLOW_PSS_CLR,	//PSS_CLEAR
	XSC_FLOW_PSS_START,	//PSS_START
	XSC_FLOW_PSS_DONE,	//PSS_DONE
	XSC_FLOW_MAC_PORT_MTU,	//MAC_PORT_MTU
	XSC_FLOW_ECP_PKT_LEN_INC,	//ECP_PKT_LEN_INC
	XSC_FLOW_TCP_FLAGS_CFG,	//TCP_FLAGS_CFG
	XSC_FLOW_DBG_CNT,	//DBG_CNT
	XSC_FLOW_PRS_REC_PORT_UDF_SEL,
	XSC_FLOW_TBL_MAX
};

enum  xsc_other_tbl_id {
	XSC_OTHER_TBL_MAX
};

enum xsc_ioctl_op {
	XSC_IOCTL_OP_ADD,
	XSC_IOCTL_OP_DEL,
	XSC_IOCTL_OP_GET,
	XSC_IOCTL_OP_CLR,
	XSC_IOCTL_OP_MOD,
	XSC_IOCTL_OP_MAX
};

struct xsc_ioctl_mem_info {
	u32 mem_num;
	u32 size;
	u64 vir_addr;
	u64 phy_addr;
};

#define	MAX_IFNAME_LEN	31
struct xsc_devinfo {
	u32	domain;
	u32	bus;
	u32	devfn;
	u8	ifname[MAX_IFNAME_LEN + 1];
	u8	ibdev_name[MAX_IFNAME_LEN + 1];
	u32	ip_addr;
	u32	vendor_id;
};

struct xsc_ioctl_get_devinfo {
	u32	dev_num;
	struct xsc_devinfo data[];
};

/* get phy info */
struct xsc_ioctl_get_phy_info_attr {
	u16 bdf;
	u16 rsvd;
};

struct xsc_ioctl_qp_range {
	u16 opcode;
	int num;
	u32 qpn;
};

struct xsc_ioctl_get_phy_info_res {
	u32 domain;
	u32 bus;
	u32 devfn;
	u32 pcie_no; //pcie number
	u32 func_id; //pf glb func id
	u32 pcie_host; //host pcie number
	u32 mac_phy_port; //mac port
	u32 funcid_to_logic_port_off;
	u16 lag_id;
	u16 raw_qp_id_base;
	u16 raw_rss_qp_id_base;
	u16 pf0_vf_funcid_base;
	u16 pf0_vf_funcid_top;
	u16 pf1_vf_funcid_base;
	u16 pf1_vf_funcid_top;
	u16 pcie0_pf_funcid_base;
	u16 pcie0_pf_funcid_top;
	u16 pcie1_pf_funcid_base;
	u16 pcie1_pf_funcid_top;
	u16 lag_port_start;
	u16 raw_tpe_qp_num;
	int send_seg_num;
	int recv_seg_num;
	u8 on_chip_tbl_vld;
	u8 dma_rw_tbl_vld;
	u8 pct_compress_vld;
	u32 chip_version;
	u32 hca_core_clock;
	u8 mac_bit;
	u8 esw_mode;
	u32 board_id;
};

struct xsc_ioctl_get_vf_info_res {
	u16	vf_id;		//start from 1, 0 is reserved for pf
	u16	phy_port;	//pcie0=0, pcie1=1
	u16	pf_id;		//pf0=0, pf1=1
	u32	func_id;
	u32	logic_port;
};

struct xsc_alloc_ucontext_req {
	u32 domain;
	u32 bus;
	u32 devfn;
};

struct xsc_ioctl_force_pcp {
	int pcp;
};

struct xsc_ioctl_force_dscp {
	int dscp;
};

struct xsc_alloc_ucontext_resp {
	int                 max_cq;
	int                 max_qp;
	u32	        max_rwq_indirection_table_size;
	u64			qpm_tx_db;
	u64			qpm_rx_db;
	u64			cqm_next_cid_reg;
	u64			cqm_armdb;
	u32			send_ds_num;
	u32			recv_ds_num;
	u32			send_ds_shift;
	u32			recv_ds_shift;
	u32			glb_func_id;
	u32            max_wqes;
};

struct xsc_ioctl_cma_pcp {
	int pcp;
};

struct xsc_ioctl_cma_dscp {
	int dscp;
};

struct xsc_ioctl_set_debug_info {
	unsigned int	log_level;
	unsigned int	cmd_verbose;
};

struct xsc_ioctl_user_mode_attr {
	u8  enable;
	u8  mac_bitmap;
	u16 pkt_bitmap;
	u16 dst_info;
	u32 resv0;
};

/* type-value */
struct xsc_ioctl_data_tl {
	u16 table;		/* table id */
	u16 opmod;		/* add/del/mod */
	u16 length;
	u16 rsvd;
};

/* public header */
struct xsc_ioctl_attr {
	u16 opcode;		/* ioctl cmd */
	u16 length;		/* data length */
	u32 error;		/* ioctl error info */
	u16 ver;
	u8 tunnel_cmd;
	u8 rsvd;
	u8 data[];		/* specific table info */
};

struct xsc_ioctl_tunnel_hdr {
	u32	domain;
	u32	bus;
	u32	devfn;
};

struct xsc_ioctl_emu_hdr {
	u16	in_length;	/* cmd req length */
	u16	out_length;	/* cmd rsp length */
	u8	data[];	/* emu cmd content start from here */
};

struct xsc_ioctl_hdr {
	u32 check_filed;		/* Validity verification fileds */
	u32 domain;
	u32 bus;
	u32 devfn;
	struct xsc_ioctl_attr attr;
};

#endif
