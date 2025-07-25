// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/init.c
 *
 * Copyright (C) 1995-2005 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/cache.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/initrd.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/sort.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/efi.h>
#include <linux/swiotlb.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/crash_dump.h>
#include <linux/hugetlb.h>
#include <linux/acpi_iort.h>
#include <linux/pin_mem.h>
#include <linux/suspend.h>
#include <linux/nmi.h>

#include <asm/boot.h>
#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/kernel-pgtable.h>
#include <asm/kexec.h>
#include <asm/memory.h>
#include <asm/numa.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/sizes.h>
#include <asm/tlb.h>
#include <asm/alternative.h>
#include <asm/cpu_park.h>
#include <asm/set_memory.h>

#include "internal.h"

/*
 * We need to be able to catch inadvertent references to memstart_addr
 * that occur (potentially in generic code) before arm64_memblock_init()
 * executes, which assigns it its actual value. So use a default value
 * that cannot be mistaken for a real physical address.
 */
s64 memstart_addr __ro_after_init = -1;
EXPORT_SYMBOL(memstart_addr);

/*
 * If the corresponding config options are enabled, we create both ZONE_DMA
 * and ZONE_DMA32. By default ZONE_DMA covers the 32-bit addressable memory
 * unless restricted on specific platforms (e.g. 30-bit on Raspberry Pi 4).
 * In such case, ZONE_DMA32 covers the rest of the 32-bit addressable memory,
 * otherwise it is empty.
 *
 * Memory reservation for crash kernel either done early or deferred
 * depending on DMA memory zones configs (ZONE_DMA) --
 *
 * In absence of ZONE_DMA configs arm64_dma_phys_limit initialized
 * here instead of max_zone_phys().  This lets early reservation of
 * crash kernel memory which has a dependency on arm64_dma_phys_limit.
 * Reserving memory early for crash kernel allows linear creation of block
 * mappings (greater than page-granularity) for all the memory bank rangs.
 * In this scheme a comparatively quicker boot is observed.
 *
 * If ZONE_DMA configs are defined, crash kernel memory reservation
 * is delayed until DMA zone memory range size initilazation performed in
 * zone_sizes_init().  The defer is necessary to steer clear of DMA zone
 * memory range to avoid overlap allocation.  So crash kernel memory boundaries
 * are not known when mapping all bank memory ranges, which otherwise means
 * not possible to exclude crash kernel range from creating block mappings
 * so page-granularity mappings are created for the entire memory range.
 * Hence a slightly slower boot is observed.
 *
 * Note: Page-granularity mapppings are necessary for crash kernel memory
 * range for shrinking its size via /sys/kernel/kexec_crash_size interface.
 */
#if IS_ENABLED(CONFIG_ZONE_DMA) || IS_ENABLED(CONFIG_ZONE_DMA32)
phys_addr_t __ro_after_init arm64_dma_phys_limit;
#else
phys_addr_t __ro_after_init arm64_dma_phys_limit = PHYS_MASK + 1;
#endif

#ifndef CONFIG_KEXEC_CORE
static void __init reserve_crashkernel(void)
{
}

static void __init reserve_crashkernel_high(void)
{
}
#endif

/*
 * The main usage of linux,usable-memory-range is for crash dump kernel.
 * Originally, the number of usable-memory regions is one. Now there may
 * be two regions, low region and high region.
 * To make compatibility with existing user-space and older kdump, the low
 * region is always the last range of linux,usable-memory-range if exist.
 */
#define MAX_USABLE_RANGES	2

#ifdef CONFIG_CRASH_DUMP
static int __init early_init_dt_scan_elfcorehdr(unsigned long node,
		const char *uname, int depth, void *data)
{
	const __be32 *reg;
	int len;

	if (depth != 1 || strcmp(uname, "chosen") != 0)
		return 0;

	reg = of_get_flat_dt_prop(node, "linux,elfcorehdr", &len);
	if (!reg || (len < (dt_root_addr_cells + dt_root_size_cells)))
		return 1;

	elfcorehdr_addr = dt_mem_next_cell(dt_root_addr_cells, &reg);
	elfcorehdr_size = dt_mem_next_cell(dt_root_size_cells, &reg);

	return 1;
}

/*
 * reserve_elfcorehdr() - reserves memory for elf core header
 *
 * This function reserves the memory occupied by an elf core header
 * described in the device tree. This region contains all the
 * information about primary kernel's core image and is used by a dump
 * capture kernel to access the system memory on primary kernel.
 */
static void __init reserve_elfcorehdr(void)
{
	of_scan_flat_dt(early_init_dt_scan_elfcorehdr, NULL);

	if (!elfcorehdr_size)
		return;

	if (memblock_is_region_reserved(elfcorehdr_addr, elfcorehdr_size)) {
		pr_warn("elfcorehdr is overlapped\n");
		return;
	}

	memblock_reserve(elfcorehdr_addr, elfcorehdr_size);

	pr_info("Reserving %lldKB of memory at 0x%llx for elfcorehdr\n",
		elfcorehdr_size >> 10, elfcorehdr_addr);
}
#else
static void __init reserve_elfcorehdr(void)
{
}
#endif /* CONFIG_CRASH_DUMP */

/*
 * Return the maximum physical address for a zone accessible by the given bits
 * limit. If DRAM starts above 32-bit, expand the zone to the maximum
 * available memory, otherwise cap it at 32-bit.
 */
static phys_addr_t __init max_zone_phys(unsigned int zone_bits)
{
	phys_addr_t zone_mask = DMA_BIT_MASK(zone_bits);
	phys_addr_t phys_start = memblock_start_of_DRAM();

	if (phys_start > U32_MAX)
		zone_mask = PHYS_ADDR_MAX;
	else if (phys_start > zone_mask)
		zone_mask = U32_MAX;

	return min(zone_mask, memblock_end_of_DRAM() - 1) + 1;
}

static void __init zone_sizes_init(unsigned long min, unsigned long max)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES]  = {0};
	unsigned int __maybe_unused acpi_zone_dma_bits;
	unsigned int __maybe_unused dt_zone_dma_bits;
	phys_addr_t __maybe_unused dma32_phys_limit = max_zone_phys(32);

#ifdef CONFIG_ZONE_DMA
	acpi_zone_dma_bits = fls64(acpi_iort_dma_get_max_cpu_address());
	dt_zone_dma_bits = fls64(of_dma_get_max_cpu_address(NULL));
	zone_dma_bits = min3(32U, dt_zone_dma_bits, acpi_zone_dma_bits);
	arm64_dma_phys_limit = max_zone_phys(zone_dma_bits);
	max_zone_pfns[ZONE_DMA] = PFN_DOWN(arm64_dma_phys_limit);
#endif
#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32] = PFN_DOWN(dma32_phys_limit);
	if (!arm64_dma_phys_limit)
		arm64_dma_phys_limit = dma32_phys_limit;
#endif
	max_zone_pfns[ZONE_NORMAL] = max;

	free_area_init(max_zone_pfns);
}

int pfn_valid(unsigned long pfn)
{
	phys_addr_t addr = pfn << PAGE_SHIFT;

	if ((addr >> PAGE_SHIFT) != pfn)
		return 0;

#ifdef CONFIG_SPARSEMEM
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;

	if (!valid_section(__pfn_to_section(pfn)))
		return 0;

	/*
	 * ZONE_DEVICE memory does not have the memblock entries.
	 * memblock_is_map_memory() check for ZONE_DEVICE based
	 * addresses will always fail. Even the normal hotplugged
	 * memory will never have MEMBLOCK_NOMAP flag set in their
	 * memblock entries. Skip memblock search for all non early
	 * memory sections covering all of hotplug memory including
	 * both normal and ZONE_DEVICE based.
	 */
	if (!early_section(__pfn_to_section(pfn)))
		return pfn_section_valid(__pfn_to_section(pfn), pfn);
#endif
	return memblock_is_map_memory(addr);
}
EXPORT_SYMBOL(pfn_valid);

static phys_addr_t memory_limit = PHYS_ADDR_MAX;

/*
 * Limit the memory size that was specified via FDT.
 */
static int __init early_mem(char *p)
{
	if (!p)
		return 1;

	memory_limit = memparse(p, &p) & PAGE_MASK;
	pr_notice("Memory limited to %lldMB\n", memory_limit >> 20);

	return 0;
}
early_param("mem", early_mem);

static int __init early_init_dt_scan_usablemem(unsigned long node,
		const char *uname, int depth, void *data)
{
	struct memblock_region *usable_rgns = data;
	const __be32 *reg, *endp;
	int len, nr = 0;

	if (depth != 1 || strcmp(uname, "chosen") != 0)
		return 0;

	reg = of_get_flat_dt_prop(node, "linux,usable-memory-range", &len);
	if (!reg || (len < (dt_root_addr_cells + dt_root_size_cells)))
		return 1;

	endp = reg + (len / sizeof(__be32));
	while ((endp - reg) >= (dt_root_addr_cells + dt_root_size_cells)) {
		usable_rgns[nr].base = dt_mem_next_cell(dt_root_addr_cells, &reg);
		usable_rgns[nr].size = dt_mem_next_cell(dt_root_size_cells, &reg);

		if (++nr >= MAX_USABLE_RANGES)
			break;
	}

	return 1;
}

static void __init fdt_enforce_memory_region(void)
{
	struct memblock_region usable_rgns[MAX_USABLE_RANGES] = {
		{ .size = 0 },
		{ .size = 0 }
	};

	of_scan_flat_dt(early_init_dt_scan_usablemem, &usable_rgns);

	/*
	 * The first range of usable-memory regions is for crash dump
	 * kernel with only one region or for high region with two regions,
	 * the second range is dedicated for low region if exist.
	 */
	if (usable_rgns[0].size)
		memblock_cap_memory_range(usable_rgns[0].base, usable_rgns[0].size);
	if (usable_rgns[1].size)
		memblock_add(usable_rgns[1].base, usable_rgns[1].size);
}

struct memblock_region mbk_memmap_regions[MAX_RES_REGIONS] __initdata_memblock;
int mbk_memmap_cnt __initdata;

static void __init setup_mbk_memmap_regions(phys_addr_t base, phys_addr_t size)
{
	if (mbk_memmap_cnt >= MAX_RES_REGIONS) {
		pr_err("Too many memmap specified, exceed %d\n", MAX_RES_REGIONS);
		return;
	}

	mbk_memmap_regions[mbk_memmap_cnt].base = base;
	mbk_memmap_regions[mbk_memmap_cnt].size = size;
	mbk_memmap_cnt++;
}

static void __init reserve_memmap_regions(void)
{
	phys_addr_t base, size;
	const char *str;
	int i;

	for (i = 0; i < mbk_memmap_cnt; i++) {
		base = mbk_memmap_regions[i].base;
		size = mbk_memmap_regions[i].size;

		if (!memblock_is_region_memory(base, size)) {
			str = "is not a memory region - ignore";
			goto err;
		}

		if (memblock_is_region_reserved(base, size)) {
			str = "overlaps in-use memory region - ignore";
			goto err;
		}

		if (memblock_reserve(base, size)) {
			str = "failed";
			goto err;
		}

		pr_info("memmap reserved: 0x%08llx - 0x%08llx (%lld MB)",
			base, base + size - 1, size >> 20);
		continue;
err:
		mbk_memmap_regions[i].size = 0;
		pr_warn("memmap reserve: 0x%08llx - 0x%08llx %s\n",
			base, base + size - 1, str);
	}
}

static int need_remove_real_memblock __initdata;

static int __init parse_memmap_one(char *p)
{
	char *oldp;
	u64 start_at, mem_size;

	if (!p)
		return -EINVAL;

	if (!strncmp(p, "exactmap", 8)) {
		need_remove_real_memblock = 1;
		return -EINVAL;
	}

	oldp = p;
	mem_size = memparse(p, &p);
	if (p == oldp)
		return -EINVAL;

	if (!mem_size)
		return -EINVAL;

	if (*p == '@') {
		start_at = memparse(p + 1, &p);
		/*
		 * use the exactmap defined by nn[KMG]@ss[KMG], remove
		 * memblock populated by DT etc.
		 */
		if (need_remove_real_memblock) {
			need_remove_real_memblock = 0;
			memblock_remove(0, ULLONG_MAX);
		}
		memblock_add(start_at, mem_size);
	} else if (*p == '$') {
		start_at = memparse(p + 1, &p);
		setup_mbk_memmap_regions(start_at, mem_size);
	} else if (*p == '!') {
		start_at = memparse(p + 1, &p);
		setup_reserve_pmem(start_at, mem_size);
	} else
		pr_info("Unrecognized memmap option, please check the parameter.\n");

	return *p == '\0' ? 0 : -EINVAL;
}

static int __init parse_memmap_opt(char *str)
{
	while (str) {
		char *k = strchr(str, ',');

		if (k)
			*k++ = 0;

		parse_memmap_one(str);
		str = k;
	}

	return 0;
}
early_param("memmap", parse_memmap_opt);

#ifdef CONFIG_ARCH_PHYTIUM
#define SOCID_PS23064 0x8
#define RMV_PS23064 0x510783f00000
static inline void phytium_ps23064_quirk(void)
{
	if (read_sysreg_s(SYS_AIDR_EL1) == SOCID_PS23064 &&
		read_cpuid_id() == MIDR_PHYTIUM_FTC862) {
		pr_warn("Enable Phytium S5000C-128 Core quirk\n");
		memblock_remove(RMV_PS23064, (1ULL << PHYS_MASK_SHIFT) - RMV_PS23064);
	}
}
#endif

void __init arm64_memblock_init(void)
{
	const s64 linear_region_size = BIT(vabits_actual - 1);

	/* Handle linux,usable-memory-range property */
	fdt_enforce_memory_region();

	/* Remove memory above our supported physical address size */
	memblock_remove(1ULL << PHYS_MASK_SHIFT, ULLONG_MAX);
#ifdef CONFIG_ARCH_PHYTIUM
	if (IS_ENABLED(CONFIG_KASAN))
		phytium_ps23064_quirk();
#endif
	/*
	 * Select a suitable value for the base of physical memory.
	 */
	memstart_addr = round_down(memblock_start_of_DRAM(),
				   ARM64_MEMSTART_ALIGN);

	/*
	 * Remove the memory that we will not be able to cover with the
	 * linear mapping. Take care not to clip the kernel which may be
	 * high in memory.
	 */
	memblock_remove(max_t(u64, memstart_addr + linear_region_size,
			__pa_symbol(_end)), ULLONG_MAX);
	if (memstart_addr + linear_region_size < memblock_end_of_DRAM()) {
		/* ensure that memstart_addr remains sufficiently aligned */
		memstart_addr = round_up(memblock_end_of_DRAM() - linear_region_size,
					 ARM64_MEMSTART_ALIGN);
		memblock_remove(0, memstart_addr);
	}

	/*
	 * If we are running with a 52-bit kernel VA config on a system that
	 * does not support it, we have to place the available physical
	 * memory in the 48-bit addressable part of the linear region, i.e.,
	 * we have to move it upward. Since memstart_addr represents the
	 * physical address of PAGE_OFFSET, we have to *subtract* from it.
	 */
	if (IS_ENABLED(CONFIG_ARM64_VA_BITS_52) && (vabits_actual != 52))
		memstart_addr -= _PAGE_OFFSET(48) - _PAGE_OFFSET(52);

	/*
	 * Apply the memory limit if it was set. Since the kernel may be loaded
	 * high up in memory, add back the kernel region that must be accessible
	 * via the linear mapping.
	 */
	if (memory_limit != PHYS_ADDR_MAX) {
		memblock_mem_limit_remove_map(memory_limit);
		memblock_add(__pa_symbol(_text), (u64)(_end - _text));
	}

	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/*
		 * Add back the memory we just removed if it results in the
		 * initrd to become inaccessible via the linear mapping.
		 * Otherwise, this is a no-op
		 */
		u64 base = phys_initrd_start & PAGE_MASK;
		u64 size = PAGE_ALIGN(phys_initrd_start + phys_initrd_size) - base;

		/*
		 * We can only add back the initrd memory if we don't end up
		 * with more memory than we can address via the linear mapping.
		 * It is up to the bootloader to position the kernel and the
		 * initrd reasonably close to each other (i.e., within 32 GB of
		 * each other) so that all granule/#levels combinations can
		 * always access both.
		 */
		if (WARN(base < memblock_start_of_DRAM() ||
			 base + size > memblock_start_of_DRAM() +
				       linear_region_size,
			"initrd not fully accessible via the linear mapping -- please check your bootloader ...\n")) {
			phys_initrd_size = 0;
		} else {
			memblock_remove(base, size); /* clear MEMBLOCK_ flags */
			memblock_add(base, size);
			memblock_reserve(base, size);
		}
	}

	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		extern u16 memstart_offset_seed;
		u64 range = linear_region_size -
			    (memblock_end_of_DRAM() - memblock_start_of_DRAM());

		/*
		 * If the size of the linear region exceeds, by a sufficient
		 * margin, the size of the region that the available physical
		 * memory spans, randomize the linear region as well.
		 */
		if (memstart_offset_seed > 0 && range >= ARM64_MEMSTART_ALIGN) {
			range /= ARM64_MEMSTART_ALIGN;
			memstart_addr -= ARM64_MEMSTART_ALIGN *
					 ((range * memstart_offset_seed) >> 16);
		}
	}

	/*
	 * Register the kernel text, kernel data, initrd, and initial
	 * pagetables with memblock.
	 */
	memblock_reserve(__pa_symbol(_text), _end - _text);
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/* the generic initrd code expects virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}

	early_init_fdt_scan_reserved_mem();

	reserve_crashkernel_high();

	reserve_elfcorehdr();

	if (!IS_ENABLED(CONFIG_ZONE_DMA) && !IS_ENABLED(CONFIG_ZONE_DMA32))
		reserve_crashkernel();

	high_memory = __va(memblock_end_of_DRAM() - 1) + 1;
}

void __init bootmem_init(void)
{
	unsigned long min, max;

	min = PFN_UP(memblock_start_of_DRAM());
	max = PFN_DOWN(memblock_end_of_DRAM());

	early_memtest(min << PAGE_SHIFT, max << PAGE_SHIFT);

	max_pfn = max_low_pfn = max;
	min_low_pfn = min;

	arm64_numa_init();

	/*
	 * must be done after arm64_numa_init() which calls numa_init() to
	 * initialize node_online_map that gets used in hugetlb_cma_reserve()
	 * while allocating required CMA size across online nodes.
	 */
#if defined(CONFIG_HUGETLB_PAGE) && defined(CONFIG_CMA)
	arm64_hugetlb_cma_reserve();
#endif

	dma_pernuma_cma_reserve();

	/*
	 * sparse_init() tries to allocate memory from memblock, so must be
	 * done after the fixed reservations
	 */
	sparse_init();
	zone_sizes_init(min, max);

	/*
	 * Reserve the CMA area after arm64_dma_phys_limit was initialised.
	 */
	dma_contiguous_reserve(arm64_dma_phys_limit);

	/*
	 * Reserve park memory before crashkernel and quick kexec.
	 * Because park memory must be specified by address, but
	 * crashkernel and quickkexec may be specified by memory length,
	 * then find one sutiable memory region to reserve.
	 *
	 * So reserve park memory firstly is better, but it may cause
	 * crashkernel or quickkexec reserving failed.
	 */
	reserve_park_mem();

	/*
	 * request_standard_resources() depends on crashkernel's memory being
	 * reserved, so do it here.
	 */
	if (IS_ENABLED(CONFIG_ZONE_DMA) || IS_ENABLED(CONFIG_ZONE_DMA32))
		reserve_crashkernel();

	reserve_quick_kexec();

	reserve_memmap_regions();

	reserve_pmem();

	reserve_pin_memory_res();

	memblock_dump_all();
}

#ifndef CONFIG_SPARSEMEM_VMEMMAP
static inline void free_memmap(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *start_pg, *end_pg;
	unsigned long pg, pgend;

	/*
	 * Convert start_pfn/end_pfn to a struct page pointer.
	 */
	start_pg = pfn_to_page(start_pfn - 1) + 1;
	end_pg = pfn_to_page(end_pfn - 1) + 1;

	/*
	 * Convert to physical addresses, and round start upwards and end
	 * downwards.
	 */
	pg = (unsigned long)PAGE_ALIGN(__pa(start_pg));
	pgend = (unsigned long)__pa(end_pg) & PAGE_MASK;

	/*
	 * If there are free pages between these, free the section of the
	 * memmap array.
	 */
	if (pg < pgend)
		memblock_free(pg, pgend - pg);
}

/*
 * The mem_map array can get very big. Free the unused area of the memory map.
 */
static void __init free_unused_memmap(void)
{
	unsigned long start, end, prev_end = 0;
	int i;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start, &end, NULL) {
#ifdef CONFIG_SPARSEMEM
		/*
		 * Take care not to free memmap entries that don't exist due
		 * to SPARSEMEM sections which aren't present.
		 */
		start = min(start, ALIGN(prev_end, PAGES_PER_SECTION));
#endif
		/*
		 * If we had a previous bank, and there is a space between the
		 * current bank and the previous, free it.
		 */
		if (prev_end && prev_end < start)
			free_memmap(prev_end, start);

		/*
		 * Align up here since the VM subsystem insists that the
		 * memmap entries are valid from the bank end aligned to
		 * MAX_ORDER_NR_PAGES.
		 */
		prev_end = ALIGN(end, MAX_ORDER_NR_PAGES);
	}

#ifdef CONFIG_SPARSEMEM
	if (!IS_ALIGNED(prev_end, PAGES_PER_SECTION))
		free_memmap(prev_end, ALIGN(prev_end, PAGES_PER_SECTION));
#endif
}
#endif	/* !CONFIG_SPARSEMEM_VMEMMAP */

/*
 * mem_init() marks the free areas in the mem_map and tells us how much memory
 * is free.  This is done after various parts of the system have claimed their
 * memory after the kernel image.
 */
void __init mem_init(void)
{
	if (swiotlb_force == SWIOTLB_FORCE ||
	    max_pfn > PFN_DOWN(arm64_dma_phys_limit))
		swiotlb_init(1);
	else
		swiotlb_force = SWIOTLB_NO_FORCE;

	swiotlb_cvm_update_mem_attributes();

	set_max_mapnr(max_pfn - PHYS_PFN_OFFSET);

#ifndef CONFIG_SPARSEMEM_VMEMMAP
	free_unused_memmap();
#endif
	/* this will put all unused low memory onto the freelists */
	memblock_free_all();

	/* pre alloc the pages for pin memory */
	init_reserve_page_map();

	mem_init_print_info(NULL);

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can be
	 * detected at build time already.
	 */
#ifdef CONFIG_COMPAT
	BUILD_BUG_ON(TASK_SIZE_32 > DEFAULT_MAP_WINDOW_64);
#endif

	if (PAGE_SIZE >= 16384 && get_num_physpages() <= 128) {
		extern int sysctl_overcommit_memory;
		/*
		 * On a machine this small we won't get anywhere without
		 * overcommit, so turn it on by default.
		 */
		sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;
	}
}

void free_initmem(void)
{
	free_reserved_area(lm_alias(__init_begin),
			   lm_alias(__init_end),
			   POISON_FREE_INITMEM, "unused kernel");
	/*
	 * Unmap the __init region but leave the VM area in place. This
	 * prevents the region from being reused for kernel modules, which
	 * is not supported by kallsyms.
	 */
	unmap_kernel_range((u64)__init_begin, (u64)(__init_end - __init_begin));
}

void dump_mem_limit(void)
{
	if (memory_limit != PHYS_ADDR_MAX) {
		pr_emerg("Memory Limit: %llu MB\n", memory_limit >> 20);
	} else {
		pr_emerg("Memory Limit: none\n");
	}
}

#ifdef CONFIG_ASCEND_CHARGE_MIGRATE_HUGEPAGES
extern int enable_charge_mighp;
#endif

#ifdef CONFIG_ARM64_PSEUDO_NMI
extern bool enable_pseudo_nmi;
#endif

void ascend_enable_all_features(void)
{
	if (IS_ENABLED(CONFIG_ASCEND_DVPP_MMAP))
		enable_mmap_dvpp = 1;

#ifdef CONFIG_ASCEND_CHARGE_MIGRATE_HUGEPAGES
	enable_charge_mighp = 1;
#endif

#ifdef CONFIG_SUSPEND
	mem_sleep_current = PM_SUSPEND_ON;
#endif

#ifdef CONFIG_ARM64_PSEUDO_NMI
	enable_pseudo_nmi = true;
#endif

#ifdef CONFIG_CORELOCKUP_DETECTOR
	enable_corelockup_detector = true;
#endif
}

static int __init ascend_enable_setup(char *__unused)
{
	ascend_enable_all_features();

	return 0;
}
early_param("ascend_enable_all", ascend_enable_setup);
