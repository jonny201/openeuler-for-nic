# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
# All rights reserved.

ccflags-y := -I$(srctree)/drivers/net/ethernet/yunsilicon/xsc
ccflags-y += -Wno-implicit-fallthrough
ifeq ($(USE_INTERNAL_IB_CORE), 1)
	ccflags-y += -include /usr/src/ofa_kernel/include/rdma/ib_umem.h
endif

ifeq ($(HAVE_TO_USE_M_IB_CORE), 1)
	ccflags-y += ${xsc-ccflags}
	export KBUILD_EXTRA_SYMBOLS += $(PWD)/net/ethernet/yunsilicon/Module.symvers
endif

obj-$(CONFIG_INFINIBAND_XSC) += xsc_ib.o

xsc_ib-y := main.o xsc_rdma_ctrl.o xsc_rdma_prgrmmbl_cc_ctrl.o cq.o qp.o mem.o mr.o ah.o \
		counters.o devx.o ib_umem_ex.o\
		rtt.o xsc_ib_sysfs.o

xsc_ib-$(CONFIG_XSC_PEER_SUPPORT) += peer_mem.o

