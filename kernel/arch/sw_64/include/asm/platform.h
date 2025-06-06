/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SW64_PLATFORM_H
#define _ASM_SW64_PLATFORM_H

#include <linux/types.h>
#if defined(CONFIG_UNCORE_XUELANG)
#include <asm/uncore_io_xuelang.h>
#elif defined(CONFIG_UNCORE_JUNZHANG)
#include <asm/uncore_io_junzhang.h>
#endif

#ifdef CONFIG_EFI
#define BIOS_VERSION_GUID       EFI_GUID(0xc47a23c3, 0xcebb, 0x4cc9, 0xa5, 0xe2, 0xde, 0xd0, 0x8f, 0xe4, 0x20, 0xb5)

#define BIOS_SUPPORT_RESET_CLALLBACK(bios_version) ((bios_version) != NULL)

extern unsigned long bios_version;

#endif

extern struct boot_params *sunway_boot_params;
extern unsigned long sunway_boot_magic;
extern unsigned long sunway_dtb_address;

extern void sw64_halt(void);
extern void sw64_poweroff(void);
extern void sw64_restart(void);
extern void (*pm_restart)(void);
extern void (*pm_halt)(void);
extern int i2c_set_adapter(void);
extern void cpld_write(uint8_t slave_addr, uint8_t reg, uint8_t data);
extern void early_parse_fdt_property(const void *fdt, const char *path,
		const char *prop_name, u64 *property, int size);

extern void __iomem *misc_platform_get_spbu_base(unsigned long node);
extern void __iomem *misc_platform_get_intpu_base(unsigned long node);
extern void __iomem *misc_platform_get_gpio_base(unsigned long node);

#ifdef CONFIG_SUBARCH_C3B
extern void __iomem *misc_platform_get_cab0_base(unsigned long node);
#endif

extern bool sunway_machine_is_compatible(const char *compat);

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/numa.h>

static inline void __init
sunway_of_get_numa_node(struct device_node *np, u32 *node, u32 fallback)
{
	int nid;

	nid = of_node_to_nid(np);
	if (nid != NUMA_NO_NODE) {
		*node = nid;
		return;
	}

	/* Fallback to legacy property */
	if (of_property_read_u32(np, "sw64,node", node)) {
		*node = fallback;
		pr_warn("node fallback to %u\n", fallback);
	}
}

static inline void __init
sunway_of_get_irq_num(struct device_node *np, u32 *irq_num, u32 fallback)
{
	if (!of_property_read_u32(np, "sunway,irq-num", irq_num))
		return;

	/* Fallback to legacy property */
	if (of_property_read_u32(np, "sw64,irq-num", irq_num)) {
		*irq_num = fallback;
		pr_warn("irq-num fallback to %u\n", fallback);
	}
}

static inline void __init
sunway_of_get_version(struct device_node *np, u32 *version, u32 fallback)
{
	if (!of_property_read_u32(np, "sunway,version", version))
		return;

	/* Fallback to legacy property */
	if (of_property_read_u32(np, "sw64,ver", version)) {
		*version = fallback;
		pr_warn("version fallback to %u\n", fallback);
	}
}
#endif

#endif /* _ASM_SW64_PLATFORM_H */
