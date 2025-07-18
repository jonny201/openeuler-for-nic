/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */
/* generated time:
 * Tue Jan 21 16:02:05 CST 2025
 */

#ifndef XSC_HW_H
#define XSC_HW_H

//hif_irq_csr_defines.h

//hif_cpm_csr_defines.h
#define HIF_CPM_LOCK_GET_REG_ADDR   0xa0000208
#define HIF_CPM_LOCK_PUT_REG_ADDR   0xa0000210
#define HIF_CPM_LOCK_AVAIL_REG_ADDR   0xa0000218
#define HIF_CPM_IDA_DATA_MEM_ADDR   0xa0000800
#define HIF_CPM_IDA_CMD_REG_ADDR   0xa0000080
#define HIF_CPM_IDA_ADDR_REG_ADDR   0xa0000100
#define HIF_CPM_IDA_BUSY_REG_ADDR   0xa0000200
#define HIF_CPM_IDA_CMD_REG_IDA_IDX_WIDTH 5
#define HIF_CPM_IDA_CMD_REG_IDA_LEN_WIDTH 4
#define HIF_CPM_IDA_CMD_REG_IDA_R0W1_WIDTH 1
#define HIF_CPM_LOCK_GET_REG_LOCK_VLD_SHIFT 5
#define HIF_CPM_LOCK_GET_REG_LOCK_IDX_MASK  0x1f
#define HIF_CPM_IDA_ADDR_REG_STRIDE 0x8
#define HIF_CPM_CHIP_VERSION_H_REG_ADDR   0xa0000000

//mmc_csr_defines.h
#define MMC_MPT_TBL_MEM_DEPTH  32768
#define MMC_MTT_TBL_MEM_DEPTH  76800
#define MMC_MPT_TBL_MEM_WIDTH  256
#define MMC_MTT_TBL_MEM_WIDTH  64
#define MMC_MPT_TBL_MEM_ADDR   0xa2100000
#define MMC_MTT_TBL_MEM_ADDR   0xa2800000
#define MMC_MTT_TBL_MEM_SIZE   8
#define MMC_MTT_TBL_MEM_STRIDE 0x100000

//clsf_dma_csr_defines.h

//hif_tbl_csr_defines.h

//hif_cmdqm_csr_defines.h
#define HIF_CMDQM_HOST_REQ_PID_MEM_ADDR   0xa1101100
#define HIF_CMDQM_HOST_REQ_CID_MEM_ADDR   0xa1101180
#define HIF_CMDQM_HOST_RSP_PID_MEM_ADDR   0xa1101300
#define HIF_CMDQM_HOST_RSP_CID_MEM_ADDR   0xa1101380
#define HIF_CMDQM_HOST_REQ_BUF_BASE_H_ADDR_MEM_ADDR   0xa1101000
#define HIF_CMDQM_HOST_REQ_BUF_BASE_L_ADDR_MEM_ADDR   0xa1101080
#define HIF_CMDQM_HOST_RSP_BUF_BASE_H_ADDR_MEM_ADDR   0xa1101200
#define HIF_CMDQM_HOST_RSP_BUF_BASE_L_ADDR_MEM_ADDR   0xa1101280
#define HIF_CMDQM_VECTOR_ID_MEM_ADDR   0xa1101480
#define HIF_CMDQM_Q_ELEMENT_SZ_REG_ADDR   0xa1100100
#define HIF_CMDQM_HOST_Q_DEPTH_REG_ADDR   0xa1100110
#define HIF_CMDQM_HOST_VF_ERR_STS_MEM_ADDR   0xa1101400

//PSV use
//hif_irq_csr_defines.h
#define HIF_IRQ_CONTROL_TBL_MEM_ADDR   0xa1004000
#define HIF_IRQ_INT_DB_REG_ADDR   0xa1000148
#define HIF_IRQ_CFG_VECTOR_TABLE_BUSY_REG_ADDR   0xa1000208
#define HIF_IRQ_CFG_VECTOR_TABLE_ADDR_REG_ADDR   0xa10001c0
#define HIF_IRQ_CFG_VECTOR_TABLE_CMD_REG_ADDR   0xa10001b8
#define HIF_IRQ_CFG_VECTOR_TABLE_MSG_LADDR_REG_ADDR   0xa10001c8
#define HIF_IRQ_CFG_VECTOR_TABLE_MSG_UADDR_REG_ADDR   0xa10001d0
#define HIF_IRQ_CFG_VECTOR_TABLE_MSG_DATA_REG_ADDR   0xa10001d8
#define HIF_IRQ_CFG_VECTOR_TABLE_CTRL_REG_ADDR   0xa10001e0
#define HIF_IRQ_CFG_VECTOR_TABLE_START_REG_ADDR   0xa10001b0

#endif /* XSC_HW_H  */
