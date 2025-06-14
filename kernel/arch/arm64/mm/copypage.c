// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/copypage.c
 *
 * Copyright (C) 2002 Deep Blue Solutions Ltd, All Rights Reserved.
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/bitops.h>
#include <linux/mm.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/mte.h>

static void do_mte(struct page *to, struct page *from, void *kto, void *kfrom, bool mc)
{
	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
		set_bit(PG_mte_tagged, &to->flags);
		if (mc)
			mte_copy_page_tags_mc(kto, kfrom);
		else
			mte_copy_page_tags(kto, kfrom);
	}
}

void copy_highpage(struct page *to, struct page *from)
{
	void *kto = page_address(to);
	void *kfrom = page_address(from);

	copy_page(kto, kfrom);
	do_mte(to, from, kto, kfrom, false);
}
EXPORT_SYMBOL(copy_highpage);

void copy_user_highpage(struct page *to, struct page *from,
			unsigned long vaddr, struct vm_area_struct *vma)
{
	copy_highpage(to, from);
	flush_dcache_page(to);
}
EXPORT_SYMBOL_GPL(copy_user_highpage);

#ifdef CONFIG_ARCH_HAS_COPY_MC
int copy_highpage_mc(struct page *to, struct page *from)
{
	void *kto = page_address(to);
	void *kfrom = page_address(from);
	int ret;

	ret = copy_page_mc(kto, kfrom);
	if (!ret)
		do_mte(to, from, kto, kfrom, true);

	return ret;
}
EXPORT_SYMBOL(copy_highpage_mc);

int copy_user_highpage_mc(struct page *to, struct page *from,
			unsigned long vaddr, struct vm_area_struct *vma)
{
	int ret;

	ret = copy_highpage_mc(to, from);
	if (!ret)
		flush_dcache_page(to);

	return ret;
}
EXPORT_SYMBOL_GPL(copy_user_highpage_mc);

int copy_mc_highpage(struct page *to, struct page *from)
{
	void *kto = page_address(to);
	void *kfrom = page_address(from);
	int ret;

	ret = copy_mc_to_kernel(kto, kfrom, PAGE_SIZE);
	if (!ret)
		do_mte(to, from, kto, kfrom, true);

	return ret;
}
#endif
