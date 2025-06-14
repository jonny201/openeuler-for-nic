/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/lib/strchr.S
 *
 * Copyright (C) 1995-2000 Russell King
 * Copyright (C) 2013 ARM Ltd.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

/*
 * Find the first occurrence of a character in a string.
 *
 * Parameters:
 *	x0 - str
 *	x1 - c
 * Returns:
 *	x0 - address of first occurrence of 'c' or 0
 */
#if defined(CONFIG_UEFI_KASLR_SKIP_MEMMAP) || defined(CONFIG_NOKASLR_MEM_RANGE)
SYM_FUNC_START_WEAK_PI(strchr)
#else
SYM_FUNC_START_WEAK(strchr)
#endif
	and	w1, w1, #0xff
1:	ldrb	w2, [x0], #1
	cmp	w2, w1
	ccmp	w2, wzr, #4, ne
	b.ne	1b
	sub	x0, x0, #1
	cmp	w2, w1
	csel	x0, x0, xzr, eq
	ret
#if defined(CONFIG_UEFI_KASLR_SKIP_MEMMAP) || defined(CONFIG_NOKASLR_MEM_RANGE)
SYM_FUNC_END_PI(strchr)
#else
SYM_FUNC_END(strchr)
#endif
EXPORT_SYMBOL_NOKASAN(strchr)
