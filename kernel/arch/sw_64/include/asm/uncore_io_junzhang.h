/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_UNCORE_IO_JUNZHANG_H
#define _ASM_SW64_UNCORE_IO_JUNZHANG_H

#include <asm/platform.h>

#define IO_BASE			(0x1UL << 47)
#define PCI_BASE		(0x1UL << 43)
#define PCI_IOR0_BASE		(0x2UL << 32)
#define PCI_IOR1_BASE		(0x3UL << 32)

#define PCI_RC_CFG		(0x5UL << 32)

#define PCI_EP_CFG		(0x3UL << 33)
#define PCI_LEGACY_IO		(0x1UL << 32)
#define PCI_LEGACY_IO_SIZE	(0x100000000UL)
#define PCI_MEM_UNPRE		0x0UL
#define PCI_32BIT_VT_MEMIO	(0xc0000000UL)
#define PCI_32BIT_MEMIO		(0xe0000000UL)
#define PCI_32BIT_MEMIO_SIZE	(0x20000000UL)
#define PCI_64BIT_MEMIO		(0x1UL << 39)
#define PCI_64BIT_MEMIO_SIZE	(0x8000000000UL)

#define IO_RC_SHIFT		40
#define IO_NODE_SHIFT		44
#define IO_MARK_BIT		47

#define VT_MAX_CPUS_SHIFT	0
#define VT_MAX_CPUS_MASK	0x3ff
#define VT_CORES_SHIFT		10
#define VT_CORES_MASK		0x3ff
#define VT_THREADS_SHIFT	20
#define VT_THREADS_MASK		0xfff

#define QEMU_PRINTF_BUFF_BASE  (IO_BASE | SPBU_BASE | 0x40000UL)
#define QEMU_RESTART_SHUTDOWN_BASE  (IO_BASE | SPBU_BASE | 0x50000UL)
/* MSIConfig */
#define MSICONFIG_VALID		(0x1UL << 63)
#define MSICONFIG_EN		(0x1UL << 62)
#define MSICONFIG_VECTOR_SHIFT	10

#define MSIX_MSG_ADDR		(0xfff00000UL)

#define SW64_PCI_IO_BASE(m, n)	\
	(IO_BASE | ((m) << IO_NODE_SHIFT) | PCI_BASE | ((n) << IO_RC_SHIFT))
#define SW64_IO_BASE(x)		(IO_BASE | ((x) << IO_NODE_SHIFT))

#define SW64_PCI0_BUS		0
#define PCI0_BUS		SW64_PCI0_BUS

#define SPBU_BASE		(0x3UL << 36)
#define INTPU_BASE		(0x3aUL << 32)
#define IIC0_BASE		(0x31UL << 32)
#define SPI_BASE		(0x32UL << 32)
#define UART_BASE		(0x33UL << 32)
#define IIC1_BASE		(0x34UL << 32)
#define IIC2_BASE		(0x35UL << 32)
#define GPIO_BASE		(0x36UL << 32)
#define LPC_BASE		(0x37UL << 32)
#define LPC_LEGACY_IO		(0x1UL << 28 | IO_BASE | LPC_BASE)
#define LPC_MEM_IO		(0x2UL << 28 | IO_BASE | LPC_BASE)
#define LPC_FIRMWARE_IO		(0x3UL << 28 | IO_BASE | LPC_BASE)
#define PCI_VT_LEGACY_IO	(IO_BASE | PCI_BASE | PCI_LEGACY_IO)

#define CORE0_CID		(rcid_to_domain_id(cpu_to_rcid(0)) << 7 | \
				rcid_to_thread_id(cpu_to_rcid(0)) << 6 | \
				rcid_to_core_id(cpu_to_rcid(0)))
#define PME_ENABLE_INTD_CORE0	(0x1UL << 62 | 0x8UL << 10 | CORE0_CID)
#define AER_ENABLE_INTD_CORE0	(0x1UL << 62 | 0x8UL << 10 | CORE0_CID)
#define HP_ENABLE_INTD_CORE0	(0x1UL << 62 | 0x8UL << 10 | CORE0_CID)

#define PIUCONFIG0_INIT_VAL	0x38016

#endif /* _ASM_SW64_UNCORE_IO_JUNZHANG_H */
