/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INTEL_VSEC_H
#define _INTEL_VSEC_H

#include <linux/auxiliary_bus.h>
#include <linux/bits.h>

#define VSEC_CAP_TELEMETRY	BIT(0)
#define VSEC_CAP_WATCHER	BIT(1)
#define VSEC_CAP_CRASHLOG	BIT(2)
#define VSEC_CAP_TPMI		BIT(4)

/* Intel DVSEC offsets */
#define INTEL_DVSEC_ENTRIES            0xA
#define INTEL_DVSEC_SIZE               0xB
#define INTEL_DVSEC_TABLE              0xC
#define INTEL_DVSEC_TABLE_BAR(x)       ((x) & GENMASK(2, 0))
#define INTEL_DVSEC_TABLE_OFFSET(x)    ((x) & GENMASK(31, 3))
#define TABLE_OFFSET_SHIFT             3

struct pci_dev;
struct resource;

enum intel_vsec_id {
       VSEC_ID_TELEMETRY       = 2,
       VSEC_ID_WATCHER         = 3,
       VSEC_ID_CRASHLOG        = 4,
       VSEC_ID_TPMI            = 66,
};

/**
 * struct intel_vsec_header - Common fields of Intel VSEC and DVSEC registers.
 * @rev:         Revision ID of the VSEC/DVSEC register space
 * @length:      Length of the VSEC/DVSEC register space
 * @id:          ID of the feature
 * @num_entries: Number of instances of the feature
 * @entry_size:  Size of the discovery table for each feature
 * @tbir:        BAR containing the discovery tables
 * @offset:      BAR offset of start of the first discovery table
 */
struct intel_vsec_header {
       u8      rev;
       u16     length;
       u16     id;
       u8      num_entries;
       u8      entry_size;
       u8      tbir;
       u32     offset;
};

enum intel_vsec_quirks {
	/* Watcher feature not supported */
	VSEC_QUIRK_NO_WATCHER	= BIT(0),

	/* Crashlog feature not supported */
	VSEC_QUIRK_NO_CRASHLOG	= BIT(1),

	/* Use shift instead of mask to read discovery table offset */
	VSEC_QUIRK_TABLE_SHIFT	= BIT(2),

	/* DVSEC not present (provided in driver data) */
	VSEC_QUIRK_NO_DVSEC	= BIT(3),

	/* Platforms requiring quirk in the auxiliary driver */
	VSEC_QUIRK_EARLY_HW     = BIT(4),
};

/* Platform specific data */
struct intel_vsec_platform_info {
	struct device *parent;
	struct intel_vsec_header **headers;
	unsigned long caps;
	unsigned long quirks;
	u64 base_addr;
};

struct intel_vsec_device {
	struct auxiliary_device auxdev;
	struct pci_dev *pcidev;
	struct resource *resource;
	struct ida *ida;
	int num_resources;
	int id; /* xa */
	void *priv_data;
	size_t priv_data_size;
	unsigned long quirks;
	u64 base_addr;
};

int intel_vsec_add_aux(struct pci_dev *pdev, struct device *parent,
		       struct intel_vsec_device *intel_vsec_dev,
		       const char *name);

static inline struct intel_vsec_device *dev_to_ivdev(struct device *dev)
{
	return container_of(dev, struct intel_vsec_device, auxdev.dev);
}

static inline struct intel_vsec_device *auxdev_to_ivdev(struct auxiliary_device *auxdev)
{
	return container_of(auxdev, struct intel_vsec_device, auxdev);
}

void intel_vsec_register(struct pci_dev *pdev,
			 struct intel_vsec_platform_info *info);
#endif
