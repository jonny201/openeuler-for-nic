/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#define LOAD_OFFSET PAGE_OFFSET
#include <asm/vmlinux.lds.h>
#include <asm/page.h>
#include <asm/cache.h>
#include <asm/thread_info.h>
#include <asm/set_memory.h>
#include "image-vars.h"

#include <linux/sizes.h>
OUTPUT_ARCH(riscv)
ENTRY(_start)

jiffies = jiffies_64;

PECOFF_SECTION_ALIGNMENT = 0x1000;
PECOFF_FILE_ALIGNMENT = 0x200;

SECTIONS
{
	/* Beginning of code and text segment */
	. = LOAD_OFFSET;
	_start = .;
	HEAD_TEXT_SECTION
	. = ALIGN(PAGE_SIZE);

	__init_begin = .;
	INIT_TEXT_SECTION(PAGE_SIZE)
	. = ALIGN(8);
	__soc_early_init_table : {
		__soc_early_init_table_start = .;
		KEEP(*(__soc_early_init_table))
		__soc_early_init_table_end = .;
	}
	__soc_builtin_dtb_table : {
		__soc_builtin_dtb_table_start = .;
		KEEP(*(__soc_builtin_dtb_table))
		__soc_builtin_dtb_table_end = .;
	}
	/* we have to discard exit text and such at runtime, not link time */
	__exittext_begin = .;
	.exit.text :
	{
		EXIT_TEXT
	}
	__exittext_end = .;

	.exit.data :
	{
		EXIT_DATA
	}
	PERCPU_SECTION(L1_CACHE_BYTES)
	__init_end = .;

	. = ALIGN(SECTION_ALIGN);
	.text : {
		_text = .;
		_stext = .;
		TEXT_TEXT
		SCHED_TEXT
		CPUIDLE_TEXT
		LOCK_TEXT
		KPROBES_TEXT
		ENTRY_TEXT
		IRQENTRY_TEXT
		SOFTIRQENTRY_TEXT
		*(.fixup)
		_etext = .;
	}

#ifdef CONFIG_EFI
	. = ALIGN(PECOFF_SECTION_ALIGNMENT);
	__pecoff_text_end = .;
#endif

	INIT_DATA_SECTION(16)

	/* Start of data section */
	_sdata = .;
	RO_DATA(SECTION_ALIGN)
	.srodata : {
		*(.srodata*)
	}

	EXCEPTION_TABLE(0x10)

	. = ALIGN(SECTION_ALIGN);
	_data = .;

	RW_DATA(L1_CACHE_BYTES, PAGE_SIZE, THREAD_SIZE)
	.sdata : {
		__global_pointer$ = . + 0x800;
		*(.sdata*)
	}

#ifdef CONFIG_EFI
	.pecoff_edata_padding : { BYTE(0); . = ALIGN(PECOFF_FILE_ALIGNMENT); }
	__pecoff_data_raw_size = ABSOLUTE(. - __pecoff_text_end);
#endif

	/* End of data section */
	_edata = .;

	BSS_SECTION(PAGE_SIZE, PAGE_SIZE, 0)

	.rel.dyn : {
		*(.rel.dyn*)
	}

#ifdef CONFIG_EFI
	. = ALIGN(PECOFF_SECTION_ALIGNMENT);
	__pecoff_data_virt_size = ABSOLUTE(. - __pecoff_text_end);
#endif
	_end = .;

	STABS_DEBUG
	DWARF_DEBUG
	ELF_DETAILS

	DISCARDS
}
