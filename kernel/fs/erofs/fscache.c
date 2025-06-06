/*
 * Copyright (C) 2022, Alibaba Cloud
 * Copyright (C) 2022, Bytedance Inc. All rights reserved.
 */
#include <linux/pseudo_fs.h>
#include <linux/fscache.h>
#include <linux/fscache-cache.h>
#include <linux/mount.h>
#include "internal.h"

static DEFINE_MUTEX(erofs_domain_list_lock);
static DEFINE_MUTEX(erofs_domain_cookies_lock);
static LIST_HEAD(erofs_domain_list);
static LIST_HEAD(erofs_domain_cookies_list);
static struct vfsmount *erofs_pseudo_mnt;

static int erofs_anon_init_fs_context(struct fs_context *fc)
{
	return init_pseudo(fc, EROFS_SUPER_MAGIC) ? 0 : -ENOMEM;
}

static struct file_system_type erofs_anon_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "pseudo_erofs",
	.init_fs_context = erofs_anon_init_fs_context,
	.kill_sb	= kill_anon_super,
};

const struct fscache_cookie_def erofs_fscache_super_index_def = {
	.name = "EROFS.super",
	.type = FSCACHE_COOKIE_TYPE_INDEX,
	.check_aux = NULL,
	.new_version = true,
};

const struct fscache_cookie_def erofs_fscache_inode_object_def = {
	.name           = "EROFS.uniqueid",
	.type           = FSCACHE_COOKIE_TYPE_DATAFILE,
};

static void erofs_readpage_from_fscache_complete(struct page *page, void *ctx,
						 int error)
{
	if (!error)
		SetPageUptodate(page);
	unlock_page(page);
}

static void erofs_readahead_from_fscache_complete(struct page *page, void *ctx,
						 int error)
{
	erofs_readpage_from_fscache_complete(page, ctx, error);
	put_page(page);
}

static int erofs_fscache_meta_readpage(struct file *data, struct page *page)
{
	int ret;
	struct super_block *sb = page->mapping->host->i_sb;
	struct erofs_fscache *ctx = page->mapping->host->i_private;

	ret = fscache_read_or_alloc_page(ctx->cookie, page,
					 erofs_readpage_from_fscache_complete,
					 NULL,
					 GFP_KERNEL);
	switch (ret) {
	case 0: /* page found in fscache, read submitted */
		erofs_dbg("%s: submitted", __func__);
		return ret;
	case -ENOBUFS:	/* page won't be cached */
	case -ENODATA:	/* page not in cache */
		erofs_err(sb, "%s: %d", __func__, ret);
		ret = -EIO;
		goto out;
	default:
		erofs_err(sb, "unknown error ret = %d", ret);
	}

out:
	unlock_page(page);
	return ret;
}

static int erofs_fscache_release_page(struct page *page, gfp_t gfp)
{
	if (WARN_ON(PagePrivate(page)))
		return 0;

	ClearPageFsCache(page);
	return 1;
}

static void erofs_fscache_invalidate_page(struct page *page, unsigned int offset,
					  unsigned int length)
{
	if (offset == 0 && length == PAGE_SIZE)
		ClearPageFsCache(page);
}

static int erofs_fscache_readpage_inline(struct page *page,
					 struct erofs_map_blocks *map)
{
	struct super_block *sb = page->mapping->host->i_sb;
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	erofs_blk_t blknr;
	size_t offset, len;
	void *src, *dst;

	/* For tail packing layout, the offset may be non-zero. */
	offset = erofs_blkoff(map->m_pa);
	blknr = erofs_blknr(map->m_pa);
	len = map->m_llen;

	src = erofs_read_metabuf(&buf, sb, blknr, EROFS_KMAP_ATOMIC);
	if (IS_ERR(src))
		return PTR_ERR(src);

	dst = kmap_atomic(page);
	memcpy(dst, src + offset, len);
	memset(dst + len, 0, PAGE_SIZE - len);
	kunmap_atomic(dst);

	erofs_put_metabuf(&buf);
	SetPageUptodate(page);
	return 0;
}

static int erofs_fscache_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct erofs_map_blocks map;
	struct erofs_map_dev mdev;
	erofs_off_t pos = page_offset(page);
	loff_t pstart;
	int ret;

	map.m_la = pos;
	ret = erofs_map_blocks(inode, &map);
	if (ret)
		goto out_unlock;

	if (!(map.m_flags & EROFS_MAP_MAPPED)) {
		zero_user_segment(page, 0, PAGE_SIZE);
		SetPageUptodate(page);
		goto out_unlock;
	}

	if (map.m_flags & EROFS_MAP_META) {
		ret = erofs_fscache_readpage_inline(page, &map);
		goto out_unlock;
	}

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};

	ret = erofs_map_dev(sb, &mdev);
	if (ret)
		goto out_unlock;

	pstart = mdev.m_pa + (pos - map.m_la);
	ret = fscache_read_or_alloc_page2(mdev.m_fscache->cookie, page,
					 erofs_readpage_from_fscache_complete,
					 NULL,
					 GFP_KERNEL, pstart);
	switch (ret) {
	case 0: /* page found in fscache, read submitted */
		erofs_dbg("%s: submitted", __func__);
		return ret;
	case -ENOBUFS:	/* page won't be cached */
	case -ENODATA:	/* page not in cache */
		erofs_err(sb, "%s: %d", __func__, ret);
		ret = -EIO;
		goto out_unlock;
	default:
		erofs_err(sb, "unknown error ret = %d", ret);
	}

out_unlock:
	unlock_page(page);
	return ret;
}

static void erofs_fscache_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct page *page;
	size_t len, count, done = 0;
	erofs_off_t pos;
	loff_t start, start_pos;
	int ret;

	if (!readahead_count(rac))
		return;

	start = readahead_pos(rac);
	len = readahead_length(rac);

	do {
		struct erofs_map_blocks map;
		struct erofs_map_dev mdev;

		pos = start + done;

		map.m_la = pos;
		ret = erofs_map_blocks(inode, &map);
		if (ret)
			return;

		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			page = readahead_page(rac);
			zero_user_segment(page, 0, PAGE_SIZE);
			SetPageUptodate(page);
			unlock_page(page);
			put_page(page);
			done += PAGE_SIZE;
			continue;
		}

		if (map.m_flags & EROFS_MAP_META) {
			page = readahead_page(rac);
			ret = erofs_fscache_readpage_inline(page, &map);
			unlock_page(page);
			put_page(page);
			done += PAGE_SIZE;
			continue;
		}

		mdev = (struct erofs_map_dev) {
			.m_deviceid = map.m_deviceid,
			.m_pa = map.m_pa,
		};

		ret = erofs_map_dev(sb, &mdev);
		if (ret)
			return;

		start_pos = mdev.m_pa + (pos - map.m_la);
		count = min_t(size_t, map.m_llen - (pos - map.m_la), len - done);
		ret = fscache_prepare_read(mdev.m_fscache->cookie, rac->mapping,
				pos / PAGE_SIZE, count / PAGE_SIZE, start_pos,
				erofs_readahead_from_fscache_complete, NULL);
		if (ret) {
			erofs_err(sb, "%s: prepare_read %d", __func__, ret);
			return;
		}

		done += count;
		count /= PAGE_SIZE;
		rac->_nr_pages -= count;
		rac->_index += count;
	} while (done < len);
}

static const struct address_space_operations erofs_fscache_meta_aops = {
	.readpage = erofs_fscache_meta_readpage,
	.releasepage = erofs_fscache_release_page,
	.invalidatepage = erofs_fscache_invalidate_page,
};

const struct address_space_operations erofs_fscache_access_aops = {
	.readpage = erofs_fscache_readpage,
	.readahead = erofs_fscache_readahead,
	.releasepage = erofs_fscache_release_page,
	.invalidatepage = erofs_fscache_invalidate_page,
};

static void erofs_fscache_domain_put(struct erofs_domain *domain)
{
	mutex_lock(&erofs_domain_list_lock);
	if (refcount_dec_and_test(&domain->ref)) {
		list_del(&domain->list);
		if (list_empty(&erofs_domain_list)) {
			kern_unmount(erofs_pseudo_mnt);
			erofs_pseudo_mnt = NULL;
		}
		fscache_relinquish_cookie(domain->volume, NULL, false);
		mutex_unlock(&erofs_domain_list_lock);
		kfree(domain->domain_id);
		kfree(domain);
		return;
	}
	mutex_unlock(&erofs_domain_list_lock);
}

static int erofs_fscache_register_volume(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	char *domain_id = sbi->domain_id;
	struct fscache_cookie *volume;
	char *name;
	int ret = 0;

	name = kasprintf(GFP_KERNEL, "erofs,%s",
			 domain_id ? domain_id : sbi->fsid);
	if (!name)
		return -ENOMEM;

	volume = fscache_acquire_cookie(&fscache_fsdef_index,
			&erofs_fscache_super_index_def, name, strlen(name),
			NULL, 0, NULL, 0, true);
	if (IS_ERR_OR_NULL(volume)) {
		erofs_err(sb, "failed to register volume for %s", name);
		ret = volume ? PTR_ERR(volume) : -EOPNOTSUPP;
		volume = NULL;
	}

	sbi->volume = volume;
	kfree(name);
	return ret;
}

static int erofs_fscache_init_domain(struct super_block *sb)
{
	int err;
	struct erofs_domain *domain;
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	domain = kzalloc(sizeof(struct erofs_domain), GFP_KERNEL);
	if (!domain)
		return -ENOMEM;

	domain->domain_id = kstrdup(sbi->domain_id, GFP_KERNEL);
	if (!domain->domain_id) {
		kfree(domain);
		return -ENOMEM;
	}

	err = erofs_fscache_register_volume(sb);
	if (err)
		goto out;

	if (!erofs_pseudo_mnt) {
		struct vfsmount *mnt = kern_mount(&erofs_anon_fs_type);

		if (IS_ERR(mnt)) {
			err = PTR_ERR(mnt);
			goto out;
		}
		erofs_pseudo_mnt = mnt;
	}

	domain->volume = sbi->volume;
	refcount_set(&domain->ref, 1);
	list_add(&domain->list, &erofs_domain_list);
	sbi->domain = domain;
	return 0;
out:
	kfree(domain->domain_id);
	kfree(domain);
	return err;
}

static int erofs_fscache_register_domain(struct super_block *sb)
{
	int err;
	struct erofs_domain *domain;
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	mutex_lock(&erofs_domain_list_lock);
	list_for_each_entry(domain, &erofs_domain_list, list) {
		if (!strcmp(domain->domain_id, sbi->domain_id)) {
			sbi->domain = domain;
			sbi->volume = domain->volume;
			refcount_inc(&domain->ref);
			mutex_unlock(&erofs_domain_list_lock);
			return 0;
		}
	}
	err = erofs_fscache_init_domain(sb);
	mutex_unlock(&erofs_domain_list_lock);
	return err;
}

static struct erofs_fscache *erofs_fscache_acquire_cookie(struct super_block *sb,
						char *name, unsigned int flags)
{
	struct erofs_fscache *ctx;
	struct fscache_cookie *cookie;
	struct super_block *isb;
	struct inode *inode;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&ctx->node);
	refcount_set(&ctx->ref, 1);

	cookie = fscache_acquire_cookie(EROFS_SB(sb)->volume,
					&erofs_fscache_inode_object_def,
					name, strlen(name),
					NULL, 0, NULL, 0, true);
	if (!cookie) {
		erofs_err(sb, "failed to get cookie for %s", name);
		ret = -EINVAL;
		goto err;
	}

	//fscache_use_cookie(cookie, false);

	/*
	 * Allocate anonymous inode in global pseudo mount for shareable blobs,
	 * so that they are accessible among erofs fs instances.
	 */
	isb = flags & EROFS_REG_COOKIE_SHARE ? erofs_pseudo_mnt->mnt_sb : sb;
	inode = new_inode(isb);
	if (!inode) {
		erofs_err(sb, "failed to get anon inode for %s", name);
		ret = -ENOMEM;
		goto err_cookie;
	}

	inode->i_size = OFFSET_MAX;
	inode->i_mapping->a_ops = &erofs_fscache_meta_aops;
	mapping_set_gfp_mask(inode->i_mapping, GFP_NOFS);
	inode->i_private = ctx;

	ctx->cookie = cookie;
	ctx->inode = inode;
	return ctx;

err_cookie:
//	fscache_unuse_cookie(cookie, NULL, NULL);
	fscache_relinquish_cookie(cookie, NULL, false);
err:
	kfree(ctx);
	return ERR_PTR(ret);
}

static void erofs_fscache_relinquish_cookie(struct erofs_fscache *ctx)
{
	//fscache_unuse_cookie(ctx->cookie, NULL, NULL);
	fscache_relinquish_cookie(ctx->cookie, NULL, false);
	iput(ctx->inode);
	kfree(ctx->name);
	kfree(ctx);
}

static struct erofs_fscache *erofs_domain_init_cookie(struct super_block *sb,
						char *name, unsigned int flags)
{
	struct erofs_fscache *ctx;
	struct erofs_domain *domain = EROFS_SB(sb)->domain;

	ctx = erofs_fscache_acquire_cookie(sb, name, flags);
	if (IS_ERR(ctx))
		return ctx;

	ctx->name = kstrdup(name, GFP_KERNEL);
	if (!ctx->name) {
		erofs_fscache_relinquish_cookie(ctx);
		return ERR_PTR(-ENOMEM);
	}

	refcount_inc(&domain->ref);
	ctx->domain = domain;
	list_add(&ctx->node, &erofs_domain_cookies_list);
	return ctx;
}

static struct erofs_fscache *erofs_domain_register_cookie(struct super_block *sb,
						char *name, unsigned int flags)
{
	struct erofs_fscache *ctx;
	struct erofs_domain *domain = EROFS_SB(sb)->domain;

	flags |= EROFS_REG_COOKIE_SHARE;
	mutex_lock(&erofs_domain_cookies_lock);
	list_for_each_entry(ctx, &erofs_domain_cookies_list, node) {
		if (ctx->domain != domain || strcmp(ctx->name, name))
			continue;
		if (!(flags & EROFS_REG_COOKIE_NEED_NOEXIST)) {
			refcount_inc(&ctx->ref);
		} else {
			erofs_err(sb, "%s already exists in domain %s", name,
				  domain->domain_id);
			ctx = ERR_PTR(-EEXIST);
		}
		mutex_unlock(&erofs_domain_cookies_lock);
		return ctx;
	}
	ctx = erofs_domain_init_cookie(sb, name, flags);
	mutex_unlock(&erofs_domain_cookies_lock);
	return ctx;
}

struct erofs_fscache *erofs_fscache_register_cookie(struct super_block *sb,
						    char *name,
						    unsigned int flags)
{
	if (EROFS_SB(sb)->domain_id)
		return erofs_domain_register_cookie(sb, name, flags);
	return erofs_fscache_acquire_cookie(sb, name, flags);
}

void erofs_fscache_unregister_cookie(struct erofs_fscache *ctx)
{
	struct erofs_domain *domain = NULL;

	if (!ctx)
		return;
	if (!ctx->domain)
		return erofs_fscache_relinquish_cookie(ctx);

	mutex_lock(&erofs_domain_cookies_lock);
	if (refcount_dec_and_test(&ctx->ref)) {
		domain = ctx->domain;
		list_del(&ctx->node);
		erofs_fscache_relinquish_cookie(ctx);
	}
	mutex_unlock(&erofs_domain_cookies_lock);
	if (domain)
		erofs_fscache_domain_put(domain);
}

int erofs_fscache_register_fs(struct super_block *sb)
{
	int ret;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_fscache *fscache;
	unsigned int flags = 0;

	if (sbi->domain_id)
		ret = erofs_fscache_register_domain(sb);
	else
		ret = erofs_fscache_register_volume(sb);
	if (ret)
		return ret;

	/*
	 * When shared domain is enabled, using NEED_NOEXIST to guarantee
	 * the primary data blob (aka fsid) is unique in the shared domain.
	 *
	 * For non-shared-domain case, fscache_acquire_volume() invoked by
	 * erofs_fscache_register_volume() has already guaranteed
	 * the uniqueness of primary data blob.
	 *
	 * Acquired domain/volume will be relinquished in kill_sb() on error.
	 */
	if (sbi->domain_id)
		flags |= EROFS_REG_COOKIE_NEED_NOEXIST;
	fscache = erofs_fscache_register_cookie(sb, sbi->fsid, flags);
	if (IS_ERR(fscache))
		return PTR_ERR(fscache);

	sbi->s_fscache = fscache;
	return 0;
}

void erofs_fscache_unregister_fs(struct super_block *sb)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	erofs_fscache_unregister_cookie(sbi->s_fscache);

	if (sbi->domain)
		erofs_fscache_domain_put(sbi->domain);
	else
		fscache_relinquish_cookie(sbi->volume, NULL, false);

	sbi->s_fscache = NULL;
	sbi->volume = NULL;
	sbi->domain = NULL;
}
