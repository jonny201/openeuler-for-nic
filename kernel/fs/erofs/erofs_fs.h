/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
/*
 * EROFS (Enhanced ROM File System) on-disk format definition
 *
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */
#ifndef __EROFS_FS_H
#define __EROFS_FS_H

#define EROFS_SUPER_OFFSET      1024

#define EROFS_FEATURE_COMPAT_SB_CHKSUM          0x00000001

/*
 * Any bits that aren't in EROFS_ALL_FEATURE_INCOMPAT should
 * be incompatible with this kernel version.
 */
#define EROFS_FEATURE_INCOMPAT_LZ4_0PADDING	0x00000001
#define EROFS_FEATURE_INCOMPAT_CHUNKED_FILE	0x00000004
#define EROFS_FEATURE_INCOMPAT_DEVICE_TABLE	0x00000008
#define EROFS_ALL_FEATURE_INCOMPAT		\
	(EROFS_FEATURE_INCOMPAT_LZ4_0PADDING | \
	 EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | \
	 EROFS_FEATURE_INCOMPAT_DEVICE_TABLE)

#define EROFS_SB_EXTSLOT_SIZE	16

struct erofs_deviceslot {
	u8 tag[64];		/* digest(sha256), etc. */
	__le32 blocks;		/* total fs blocks of this device */
	__le32 mapped_blkaddr;	/* map starting at mapped_blkaddr */
	u8 reserved[56];
};
#define EROFS_DEVT_SLOT_SIZE	sizeof(struct erofs_deviceslot)

/* 128-byte erofs on-disk super block */
struct erofs_super_block {
	__le32 magic;           /* file system magic number */
	__le32 checksum;        /* crc32c(super_block) */
	__le32 feature_compat;
	__u8 blkszbits;         /* support block_size == PAGE_SIZE only */
	__u8 reserved;

	__le16 root_nid;	/* nid of root directory */
	__le64 inos;            /* total valid ino # (== f_files - f_favail) */

	__le64 build_time;      /* inode v1 time derivation */
	__le32 build_time_nsec;	/* inode v1 time derivation in nano scale */
	__le32 blocks;          /* used for statfs */
	__le32 meta_blkaddr;	/* start block address of metadata area */
	__le32 xattr_blkaddr;	/* start block address of shared xattr area */
	__u8 uuid[16];          /* 128-bit uuid for volume */
	__u8 volume_name[16];   /* volume name */
	__le32 feature_incompat;
	__le16 reserved2;
	__le16 extra_devices;	/* # of devices besides the primary device */
	__le16 devt_slotoff;	/* startoff = devt_slotoff * devt_slotsize */
	__u8 reserved3[38];
};

/*
 * erofs inode datalayout (i_format in on-disk inode):
 * 0 - inode plain without inline data A:
 * inode, [xattrs], ... | ... | no-holed data
 * 1 - inode VLE compression B (legacy):
 * inode, [xattrs], extents ... | ...
 * 2 - inode plain with inline data C:
 * inode, [xattrs], last_inline_data, ... | ... | no-holed data
 * 3 - inode compression D:
 * inode, [xattrs], map_header, extents ... | ...
 * 4 - inode chunk-based E:
 * inode, [xattrs], chunk indexes ... | ...
 * 5~7 - reserved
 */
enum {
	EROFS_INODE_FLAT_PLAIN			= 0,
	EROFS_INODE_FLAT_COMPRESSION_LEGACY	= 1,
	EROFS_INODE_FLAT_INLINE			= 2,
	EROFS_INODE_FLAT_COMPRESSION		= 3,
	EROFS_INODE_CHUNK_BASED			= 4,
	EROFS_INODE_DATALAYOUT_MAX
};

static inline bool erofs_inode_is_data_compressed(unsigned int datamode)
{
	return datamode == EROFS_INODE_FLAT_COMPRESSION ||
		datamode == EROFS_INODE_FLAT_COMPRESSION_LEGACY;
}

/* bit definitions of inode i_advise */
#define EROFS_I_VERSION_BITS            1
#define EROFS_I_DATALAYOUT_BITS         3

#define EROFS_I_VERSION_BIT             0
#define EROFS_I_DATALAYOUT_BIT          1

#define EROFS_I_ALL	\
	((1 << (EROFS_I_DATALAYOUT_BIT + EROFS_I_DATALAYOUT_BITS)) - 1)

/* indicate chunk blkbits, thus 'chunksize = blocksize << chunk blkbits' */
#define EROFS_CHUNK_FORMAT_BLKBITS_MASK		0x001F
/* with chunk indexes or just a 4-byte blkaddr array */
#define EROFS_CHUNK_FORMAT_INDEXES		0x0020

#define EROFS_CHUNK_FORMAT_ALL	\
	(EROFS_CHUNK_FORMAT_BLKBITS_MASK | EROFS_CHUNK_FORMAT_INDEXES)

struct erofs_inode_chunk_info {
	__le16 format;		/* chunk blkbits, etc. */
	__le16 reserved;
};

/* 32-byte reduced form of an ondisk inode */
struct erofs_inode_compact {
	__le16 i_format;	/* inode format hints */

/* 1 header + n-1 * 4 bytes inline xattr to keep continuity */
	__le16 i_xattr_icount;
	__le16 i_mode;
	__le16 i_nlink;
	__le32 i_size;
	__le32 i_reserved;
	union {
		/* file total compressed blocks for data mapping 1 */
		__le32 compressed_blocks;
		__le32 raw_blkaddr;

		/* for device files, used to indicate old/new device # */
		__le32 rdev;

		/* for chunk-based files, it contains the summary info */
		struct erofs_inode_chunk_info c;
	} i_u;
	__le32 i_ino;           /* only used for 32-bit stat compatibility */
	__le16 i_uid;
	__le16 i_gid;
	__le32 i_reserved2;
};

/* 32 bytes on-disk inode */
#define EROFS_INODE_LAYOUT_COMPACT	0
/* 64 bytes on-disk inode */
#define EROFS_INODE_LAYOUT_EXTENDED	1

/* 64-byte complete form of an ondisk inode */
struct erofs_inode_extended {
	__le16 i_format;	/* inode format hints */

/* 1 header + n-1 * 4 bytes inline xattr to keep continuity */
	__le16 i_xattr_icount;
	__le16 i_mode;
	__le16 i_reserved;
	__le64 i_size;
	union {
		/* file total compressed blocks for data mapping 1 */
		__le32 compressed_blocks;
		__le32 raw_blkaddr;

		/* for device files, used to indicate old/new device # */
		__le32 rdev;

		/* for chunk-based files, it contains the summary info */
		struct erofs_inode_chunk_info c;
	} i_u;

	/* only used for 32-bit stat compatibility */
	__le32 i_ino;

	__le32 i_uid;
	__le32 i_gid;
	__le64 i_ctime;
	__le32 i_ctime_nsec;
	__le32 i_nlink;
	__u8   i_reserved2[16];
};

#define EROFS_MAX_SHARED_XATTRS         (128)
/* h_shared_count between 129 ... 255 are special # */
#define EROFS_SHARED_XATTR_EXTENT       (255)

/*
 * inline xattrs (n == i_xattr_icount):
 * erofs_xattr_ibody_header(1) + (n - 1) * 4 bytes
 *          12 bytes           /                   \
 *                            /                     \
 *                           /-----------------------\
 *                           |  erofs_xattr_entries+ |
 *                           +-----------------------+
 * inline xattrs must starts in erofs_xattr_ibody_header,
 * for read-only fs, no need to introduce h_refcount
 */
struct erofs_xattr_ibody_header {
	__le32 h_reserved;
	__u8   h_shared_count;
	__u8   h_reserved2[7];
	__le32 h_shared_xattrs[0];      /* shared xattr id array */
};

/* Name indexes */
#define EROFS_XATTR_INDEX_USER              1
#define EROFS_XATTR_INDEX_POSIX_ACL_ACCESS  2
#define EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT 3
#define EROFS_XATTR_INDEX_TRUSTED           4
#define EROFS_XATTR_INDEX_LUSTRE            5
#define EROFS_XATTR_INDEX_SECURITY          6

/* xattr entry (for both inline & shared xattrs) */
struct erofs_xattr_entry {
	__u8   e_name_len;      /* length of name */
	__u8   e_name_index;    /* attribute name index */
	__le16 e_value_size;    /* size of attribute value */
	/* followed by e_name and e_value */
	char   e_name[0];       /* attribute name */
};

static inline unsigned int erofs_xattr_ibody_size(__le16 i_xattr_icount)
{
	if (!i_xattr_icount)
		return 0;

	return sizeof(struct erofs_xattr_ibody_header) +
		sizeof(__u32) * (le16_to_cpu(i_xattr_icount) - 1);
}

#define EROFS_XATTR_ALIGN(size) round_up(size, sizeof(struct erofs_xattr_entry))

static inline unsigned int erofs_xattr_entry_size(struct erofs_xattr_entry *e)
{
	return EROFS_XATTR_ALIGN(sizeof(struct erofs_xattr_entry) +
				 e->e_name_len + le16_to_cpu(e->e_value_size));
}

/* represent a zeroed chunk (hole) */
#define EROFS_NULL_ADDR			-1

/* 4-byte block address array */
#define EROFS_BLOCK_MAP_ENTRY_SIZE	sizeof(__le32)

/* 8-byte inode chunk indexes */
struct erofs_inode_chunk_index {
	__le16 advise;		/* always 0, don't care for now */
	__le16 device_id;	/* back-end storage id (with bits masked) */
	__le32 blkaddr;		/* start block address of this inode chunk */
};

/* available compression algorithm types (for h_algorithmtype) */
enum {
	Z_EROFS_COMPRESSION_LZ4	= 0,
	Z_EROFS_COMPRESSION_MAX
};

/*
 * bit 0 : COMPACTED_2B indexes (0 - off; 1 - on)
 *  e.g. for 4k logical cluster size,      4B        if compacted 2B is off;
 *                                  (4B) + 2B + (4B) if compacted 2B is on.
 */
#define Z_EROFS_ADVISE_COMPACTED_2B_BIT         0

#define Z_EROFS_ADVISE_COMPACTED_2B     (1 << Z_EROFS_ADVISE_COMPACTED_2B_BIT)

struct z_erofs_map_header {
	__le32	h_reserved1;
	__le16	h_advise;
	/*
	 * bit 0-3 : algorithm type of head 1 (logical cluster type 01);
	 * bit 4-7 : algorithm type of head 2 (logical cluster type 11).
	 */
	__u8	h_algorithmtype;
	/*
	 * bit 0-2 : logical cluster bits - 12, e.g. 0 for 4096;
	 * bit 3-4 : (physical - logical) cluster bits of head 1:
	 *       For example, if logical clustersize = 4096, 1 for 8192.
	 * bit 5-7 : (physical - logical) cluster bits of head 2.
	 */
	__u8	h_clusterbits;
};

#define Z_EROFS_VLE_LEGACY_HEADER_PADDING       8

/*
 * Fixed-sized output compression ondisk Logical Extent cluster type:
 *    0 - literal (uncompressed) cluster
 *    1 - compressed cluster (for the head logical cluster)
 *    2 - compressed cluster (for the other logical clusters)
 *
 * In detail,
 *    0 - literal (uncompressed) cluster,
 *        di_advise = 0
 *        di_clusterofs = the literal data offset of the cluster
 *        di_blkaddr = the blkaddr of the literal cluster
 *
 *    1 - compressed cluster (for the head logical cluster)
 *        di_advise = 1
 *        di_clusterofs = the decompressed data offset of the cluster
 *        di_blkaddr = the blkaddr of the compressed cluster
 *
 *    2 - compressed cluster (for the other logical clusters)
 *        di_advise = 2
 *        di_clusterofs =
 *           the decompressed data offset in its own head cluster
 *        di_u.delta[0] = distance to its corresponding head cluster
 *        di_u.delta[1] = distance to its corresponding tail cluster
 *                (di_advise could be 0, 1 or 2)
 */
enum {
	Z_EROFS_VLE_CLUSTER_TYPE_PLAIN		= 0,
	Z_EROFS_VLE_CLUSTER_TYPE_HEAD		= 1,
	Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD	= 2,
	Z_EROFS_VLE_CLUSTER_TYPE_RESERVED	= 3,
	Z_EROFS_VLE_CLUSTER_TYPE_MAX
};

#define Z_EROFS_VLE_DI_CLUSTER_TYPE_BITS        2
#define Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT         0

struct z_erofs_vle_decompressed_index {
	__le16 di_advise;
	/* where to decompress in the head cluster */
	__le16 di_clusterofs;

	union {
		/* for the head cluster */
		__le32 blkaddr;
		/*
		 * for the rest clusters
		 * eg. for 4k page-sized cluster, maximum 4K*64k = 256M)
		 * [0] - pointing to the head cluster
		 * [1] - pointing to the tail cluster
		 */
		__le16 delta[2];
	} di_u;
};

#define Z_EROFS_VLE_LEGACY_INDEX_ALIGN(size) \
	(round_up(size, sizeof(struct z_erofs_vle_decompressed_index)) + \
	 sizeof(struct z_erofs_map_header) + Z_EROFS_VLE_LEGACY_HEADER_PADDING)

/* dirent sorts in alphabet order, thus we can do binary search */
struct erofs_dirent {
	__le64 nid;     /* node number */
	__le16 nameoff; /* start offset of file name */
	__u8 file_type; /* file type */
	__u8 reserved;  /* reserved */
} __packed;

/*
 * EROFS file types should match generic FT_* types and
 * it seems no need to add BUILD_BUG_ONs since potential
 * unmatchness will break other fses as well...
 */

#define EROFS_NAME_LEN      255

/* check the EROFS on-disk layout strictly at compile time */
static inline void erofs_check_ondisk_layout_definitions(void)
{
	BUILD_BUG_ON(sizeof(struct erofs_super_block) != 128);
	BUILD_BUG_ON(sizeof(struct erofs_inode_compact) != 32);
	BUILD_BUG_ON(sizeof(struct erofs_inode_extended) != 64);
	BUILD_BUG_ON(sizeof(struct erofs_xattr_ibody_header) != 12);
	BUILD_BUG_ON(sizeof(struct erofs_xattr_entry) != 4);
	BUILD_BUG_ON(sizeof(struct erofs_inode_chunk_info) != 4);
	BUILD_BUG_ON(sizeof(struct erofs_inode_chunk_index) != 8);
	BUILD_BUG_ON(sizeof(struct z_erofs_map_header) != 8);
	BUILD_BUG_ON(sizeof(struct z_erofs_vle_decompressed_index) != 8);
	BUILD_BUG_ON(sizeof(struct erofs_dirent) != 12);
	/* keep in sync between 2 index structures for better extendibility */
	BUILD_BUG_ON(sizeof(struct erofs_inode_chunk_index) !=
		     sizeof(struct z_erofs_vle_decompressed_index));
	BUILD_BUG_ON(sizeof(struct erofs_deviceslot) != 128);

	BUILD_BUG_ON(BIT(Z_EROFS_VLE_DI_CLUSTER_TYPE_BITS) <
		     Z_EROFS_VLE_CLUSTER_TYPE_MAX - 1);
}

#endif
