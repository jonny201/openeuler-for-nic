# SPDX-License-Identifier: GPL-2.0-or-later
MODULE_NAME := sdma_dae
ccflags-y += -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits

$(MODULE_NAME)-objs := sdma_main.o sdma_cdev.o sdma_umem.o sdma_irq.o sdma_auth.o sdma_dbg.o

obj-$(CONFIG_SDMA_DAE) += sdma_dae.o