// SPDX-License-Identifier: GPL-2.0-or-later
/* Daemon interface
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/fs_struct.h>
#include "internal.h"

static int cachefiles_daemon_open(struct inode *, struct file *);
static int cachefiles_daemon_release(struct inode *, struct file *);
static ssize_t cachefiles_daemon_read(struct file *, char __user *, size_t,
				      loff_t *);
static ssize_t cachefiles_daemon_write(struct file *, const char __user *,
				       size_t, loff_t *);
static __poll_t cachefiles_daemon_poll(struct file *,
					   struct poll_table_struct *);
static int cachefiles_daemon_frun(struct cachefiles_cache *, char *);
static int cachefiles_daemon_fcull(struct cachefiles_cache *, char *);
static int cachefiles_daemon_fstop(struct cachefiles_cache *, char *);
static int cachefiles_daemon_brun(struct cachefiles_cache *, char *);
static int cachefiles_daemon_bcull(struct cachefiles_cache *, char *);
static int cachefiles_daemon_bstop(struct cachefiles_cache *, char *);
static int cachefiles_daemon_cull(struct cachefiles_cache *, char *);
static int cachefiles_daemon_debug(struct cachefiles_cache *, char *);
static int cachefiles_daemon_dir(struct cachefiles_cache *, char *);
static int cachefiles_daemon_inuse(struct cachefiles_cache *, char *);
static int cachefiles_daemon_secctx(struct cachefiles_cache *, char *);
static int cachefiles_daemon_tag(struct cachefiles_cache *, char *);

static unsigned long cachefiles_open;

const struct file_operations cachefiles_daemon_fops = {
	.owner		= THIS_MODULE,
	.open		= cachefiles_daemon_open,
	.release	= cachefiles_daemon_release,
	.read		= cachefiles_daemon_read,
	.write		= cachefiles_daemon_write,
	.poll		= cachefiles_daemon_poll,
	.llseek		= noop_llseek,
};

struct cachefiles_daemon_cmd {
	char name[8];
	int (*handler)(struct cachefiles_cache *cache, char *args);
};

static const struct cachefiles_daemon_cmd cachefiles_daemon_cmds[] = {
	{ "bind",	cachefiles_daemon_bind		},
	{ "brun",	cachefiles_daemon_brun		},
	{ "bcull",	cachefiles_daemon_bcull		},
	{ "bstop",	cachefiles_daemon_bstop		},
	{ "cull",	cachefiles_daemon_cull		},
	{ "debug",	cachefiles_daemon_debug		},
	{ "dir",	cachefiles_daemon_dir		},
	{ "frun",	cachefiles_daemon_frun		},
	{ "fcull",	cachefiles_daemon_fcull		},
	{ "fstop",	cachefiles_daemon_fstop		},
	{ "inuse",	cachefiles_daemon_inuse		},
	{ "secctx",	cachefiles_daemon_secctx	},
	{ "tag",	cachefiles_daemon_tag		},
#ifdef CONFIG_CACHEFILES_ONDEMAND
	{ "copen",	cachefiles_ondemand_copen	},
	{ "restore",	cachefiles_ondemand_restore	},
#endif
	{ "",		NULL				}
};


/*
 * do various checks
 */
static int cachefiles_daemon_open(struct inode *inode, struct file *file)
{
	struct cachefiles_cache *cache;

	_enter("");

	/* only the superuser may do this */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* the cachefiles device may only be open once at a time */
	if (xchg(&cachefiles_open, 1) == 1)
		return -EBUSY;

	/* allocate a cache record */
	cache = kzalloc(sizeof(struct cachefiles_cache), GFP_KERNEL);
	if (!cache) {
		cachefiles_open = 0;
		return -ENOMEM;
	}

	mutex_init(&cache->daemon_mutex);
	cache->active_nodes = RB_ROOT;
	rwlock_init(&cache->active_lock);
	init_waitqueue_head(&cache->daemon_pollwq);
	refcount_set(&cache->unbind_pincount, 1);

	INIT_RADIX_TREE(&cache->reqs, GFP_ATOMIC);
	idr_init(&cache->ondemand_ids);

	/* set default caching limits
	 * - limit at 1% free space and/or free files
	 * - cull below 5% free space and/or free files
	 * - cease culling above 7% free space and/or free files
	 */
	cache->frun_percent = 7;
	cache->fcull_percent = 5;
	cache->fstop_percent = 1;
	cache->brun_percent = 7;
	cache->bcull_percent = 5;
	cache->bstop_percent = 1;

	file->private_data = cache;
	cache->cachefilesd = file;
	return 0;
}

void cachefiles_flush_reqs(struct cachefiles_cache *cache)
{
	void **slot;
	struct radix_tree_iter iter;
	struct cachefiles_req *req;

	/*
	 * Make sure the following two operations won't be reordered.
	 *   1) set CACHEFILES_DEAD bit
	 *   2) flush requests in the xarray
	 * Otherwise the request may be enqueued after xarray has been
	 * flushed, leaving the orphan request never being completed.
	 *
	 * CPU 1			CPU 2
	 * =====			=====
	 * flush requests in the xarray
	 *				test CACHEFILES_DEAD bit
	 *				enqueue the request
	 * set CACHEFILES_DEAD bit
	 */
	smp_mb();

	xa_lock(&cache->reqs);
	radix_tree_for_each_slot(slot, &cache->reqs, &iter, 0) {
		req = radix_tree_deref_slot_protected(slot,
						      &cache->reqs.xa_lock);
		if (WARN_ON(!req))
			continue;
		radix_tree_delete(&cache->reqs, iter.index);
		req->error = -EIO;
		complete(&req->done);
	}
	xa_unlock(&cache->reqs);

	xa_lock(&cache->ondemand_ids.idr_rt);
	idr_destroy(&cache->ondemand_ids);
	xa_unlock(&cache->ondemand_ids.idr_rt);
}

void cachefiles_put_unbind_pincount(struct cachefiles_cache *cache)
{
	if (refcount_dec_and_test(&cache->unbind_pincount)) {
		cachefiles_daemon_unbind(cache);
		ASSERT(!cache->active_nodes.rb_node);
		cachefiles_open = 0;
		kfree(cache);
	}
}

void cachefiles_get_unbind_pincount(struct cachefiles_cache *cache)
{
	refcount_inc(&cache->unbind_pincount);
}

/*
 * release a cache
 */
static int cachefiles_daemon_release(struct inode *inode, struct file *file)
{
	struct cachefiles_cache *cache = file->private_data;

	_enter("");

	ASSERT(cache);

	set_bit(CACHEFILES_DEAD, &cache->flags);

	if (cachefiles_in_ondemand_mode(cache))
		cachefiles_flush_reqs(cache);

	/* clean up the control file interface */
	cache->cachefilesd = NULL;
	file->private_data = NULL;

	cachefiles_put_unbind_pincount(cache);
	_leave("");
	return 0;
}

static ssize_t cachefiles_do_daemon_read(struct cachefiles_cache *cache,
		char __user *_buffer, size_t buflen, loff_t *pos)
{
	unsigned long long b_released;
	unsigned f_released;
	char buffer[256];
	int n;

	/* check how much space the cache has */
	cachefiles_has_space(cache, 0, 0);

	/* summarise */
	f_released = atomic_xchg(&cache->f_released, 0);
	b_released = atomic_long_xchg(&cache->b_released, 0);
	clear_bit(CACHEFILES_STATE_CHANGED, &cache->flags);

	n = snprintf(buffer, sizeof(buffer),
		     "cull=%c"
		     " frun=%llx"
		     " fcull=%llx"
		     " fstop=%llx"
		     " brun=%llx"
		     " bcull=%llx"
		     " bstop=%llx"
		     " freleased=%x"
		     " breleased=%llx",
		     test_bit(CACHEFILES_CULLING, &cache->flags) ? '1' : '0',
		     (unsigned long long) cache->frun,
		     (unsigned long long) cache->fcull,
		     (unsigned long long) cache->fstop,
		     (unsigned long long) cache->brun,
		     (unsigned long long) cache->bcull,
		     (unsigned long long) cache->bstop,
		     f_released,
		     b_released);

	if (n > buflen)
		return -EMSGSIZE;

	if (copy_to_user(_buffer, buffer, n) != 0)
		return -EFAULT;

	return n;
}

/*
 * read the cache state
 */
static ssize_t cachefiles_daemon_read(struct file *file,
		char __user *_buffer, size_t buflen, loff_t *pos)
{
	struct cachefiles_cache *cache = file->private_data;

	//_enter(",,%zu,", buflen);

	if (!test_bit(CACHEFILES_READY, &cache->flags))
		return 0;

	if (cachefiles_in_ondemand_mode(cache))
		return cachefiles_ondemand_daemon_read(cache, _buffer, buflen, pos);
	else
		return cachefiles_do_daemon_read(cache, _buffer, buflen, pos);
}

/*
 * command the cache
 */
static ssize_t cachefiles_daemon_write(struct file *file,
				       const char __user *_data,
				       size_t datalen,
				       loff_t *pos)
{
	const struct cachefiles_daemon_cmd *cmd;
	struct cachefiles_cache *cache = file->private_data;
	ssize_t ret;
	char *data, *args, *cp;

	//_enter(",,%zu,", datalen);

	ASSERT(cache);

	if (test_bit(CACHEFILES_DEAD, &cache->flags))
		return -EIO;

	if (datalen < 0 || datalen > PAGE_SIZE - 1)
		return -EOPNOTSUPP;

	/* drag the command string into the kernel so we can parse it */
	data = memdup_user_nul(_data, datalen);
	if (IS_ERR(data))
		return PTR_ERR(data);

	ret = -EINVAL;
	if (memchr(data, '\0', datalen))
		goto error;

	/* strip any newline */
	cp = memchr(data, '\n', datalen);
	if (cp) {
		if (cp == data)
			goto error;

		*cp = '\0';
	}

	/* parse the command */
	ret = -EOPNOTSUPP;

	for (args = data; *args; args++)
		if (isspace(*args))
			break;
	if (*args) {
		if (args == data)
			goto error;
		*args = '\0';
		args = skip_spaces(++args);
	}

	/* run the appropriate command handler */
	for (cmd = cachefiles_daemon_cmds; cmd->name[0]; cmd++)
		if (strcmp(cmd->name, data) == 0)
			goto found_command;

error:
	kfree(data);
	//_leave(" = %zd", ret);
	return ret;

found_command:
	mutex_lock(&cache->daemon_mutex);

	ret = -EIO;
	if (!test_bit(CACHEFILES_DEAD, &cache->flags))
		ret = cmd->handler(cache, args);

	mutex_unlock(&cache->daemon_mutex);

	if (ret == 0)
		ret = datalen;
	goto error;
}

/*
 * poll for culling state
 * - use EPOLLOUT to indicate culling state
 */
static __poll_t cachefiles_daemon_poll(struct file *file,
					   struct poll_table_struct *poll)
{
	struct cachefiles_cache *cache = file->private_data;
	struct cachefiles_req *req;
	struct radix_tree_iter iter;
	__poll_t mask;
	void **slot;

	poll_wait(file, &cache->daemon_pollwq, poll);
	mask = 0;

	if (cachefiles_in_ondemand_mode(cache)) {
		if (!radix_tree_empty(&cache->reqs)) {
			xa_lock(&cache->reqs);
			radix_tree_for_each_tagged(slot, &cache->reqs, &iter, 0,
					CACHEFILES_REQ_NEW) {
				req = radix_tree_deref_slot_protected(slot,
						&cache->reqs.xa_lock);
				if (!cachefiles_ondemand_is_reopening_read(req)) {
					mask |= EPOLLIN;
					break;
				}
			}
			xa_unlock(&cache->reqs);
		}
	} else {
		if (test_bit(CACHEFILES_STATE_CHANGED, &cache->flags))
			mask |= EPOLLIN;
	}

	if (test_bit(CACHEFILES_CULLING, &cache->flags))
		mask |= EPOLLOUT;

	return mask;
}

/*
 * give a range error for cache space constraints
 * - can be tail-called
 */
static int cachefiles_daemon_range_error(struct cachefiles_cache *cache,
					 char *args)
{
	pr_err("Free space limits must be in range 0%%<=stop<cull<run<100%%\n");

	return -EINVAL;
}

/*
 * set the percentage of files at which to stop culling
 * - command: "frun <N>%"
 */
static int cachefiles_daemon_frun(struct cachefiles_cache *cache, char *args)
{
	unsigned long frun;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	frun = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (frun <= cache->fcull_percent || frun >= 100)
		return cachefiles_daemon_range_error(cache, args);

	cache->frun_percent = frun;
	return 0;
}

/*
 * set the percentage of files at which to start culling
 * - command: "fcull <N>%"
 */
static int cachefiles_daemon_fcull(struct cachefiles_cache *cache, char *args)
{
	unsigned long fcull;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	fcull = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (fcull <= cache->fstop_percent || fcull >= cache->frun_percent)
		return cachefiles_daemon_range_error(cache, args);

	cache->fcull_percent = fcull;
	return 0;
}

/*
 * set the percentage of files at which to stop allocating
 * - command: "fstop <N>%"
 */
static int cachefiles_daemon_fstop(struct cachefiles_cache *cache, char *args)
{
	unsigned long fstop;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	fstop = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (fstop < 0 || fstop >= cache->fcull_percent)
		return cachefiles_daemon_range_error(cache, args);

	cache->fstop_percent = fstop;
	return 0;
}

/*
 * set the percentage of blocks at which to stop culling
 * - command: "brun <N>%"
 */
static int cachefiles_daemon_brun(struct cachefiles_cache *cache, char *args)
{
	unsigned long brun;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	brun = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (brun <= cache->bcull_percent || brun >= 100)
		return cachefiles_daemon_range_error(cache, args);

	cache->brun_percent = brun;
	return 0;
}

/*
 * set the percentage of blocks at which to start culling
 * - command: "bcull <N>%"
 */
static int cachefiles_daemon_bcull(struct cachefiles_cache *cache, char *args)
{
	unsigned long bcull;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	bcull = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (bcull <= cache->bstop_percent || bcull >= cache->brun_percent)
		return cachefiles_daemon_range_error(cache, args);

	cache->bcull_percent = bcull;
	return 0;
}

/*
 * set the percentage of blocks at which to stop allocating
 * - command: "bstop <N>%"
 */
static int cachefiles_daemon_bstop(struct cachefiles_cache *cache, char *args)
{
	unsigned long bstop;

	_enter(",%s", args);

	if (!*args)
		return -EINVAL;

	bstop = simple_strtoul(args, &args, 10);
	if (args[0] != '%' || args[1] != '\0')
		return -EINVAL;

	if (bstop < 0 || bstop >= cache->bcull_percent)
		return cachefiles_daemon_range_error(cache, args);

	cache->bstop_percent = bstop;
	return 0;
}

/*
 * set the cache directory
 * - command: "dir <name>"
 */
static int cachefiles_daemon_dir(struct cachefiles_cache *cache, char *args)
{
	char *dir;

	_enter(",%s", args);

	if (!*args) {
		pr_err("Empty directory specified\n");
		return -EINVAL;
	}

	if (cache->rootdirname) {
		pr_err("Second cache directory specified\n");
		return -EEXIST;
	}

	dir = kstrdup(args, GFP_KERNEL);
	if (!dir)
		return -ENOMEM;

	cache->rootdirname = dir;
	return 0;
}

/*
 * set the cache security context
 * - command: "secctx <ctx>"
 */
static int cachefiles_daemon_secctx(struct cachefiles_cache *cache, char *args)
{
	char *secctx;

	_enter(",%s", args);

	if (!*args) {
		pr_err("Empty security context specified\n");
		return -EINVAL;
	}

	if (cache->secctx) {
		pr_err("Second security context specified\n");
		return -EEXIST;
	}

	secctx = kstrdup(args, GFP_KERNEL);
	if (!secctx)
		return -ENOMEM;

	cache->secctx = secctx;
	return 0;
}

/*
 * set the cache tag
 * - command: "tag <name>"
 */
static int cachefiles_daemon_tag(struct cachefiles_cache *cache, char *args)
{
	char *tag;

	_enter(",%s", args);

	if (!*args) {
		pr_err("Empty tag specified\n");
		return -EINVAL;
	}

	if (cache->tag)
		return -EEXIST;

	tag = kstrdup(args, GFP_KERNEL);
	if (!tag)
		return -ENOMEM;

	cache->tag = tag;
	return 0;
}

/*
 * request a node in the cache be culled from the current working directory
 * - command: "cull <name>"
 */
static int cachefiles_daemon_cull(struct cachefiles_cache *cache, char *args)
{
	struct path path;
	const struct cred *saved_cred;
	int ret;

	_enter(",%s", args);

	if (strchr(args, '/'))
		goto inval;

	if (!test_bit(CACHEFILES_READY, &cache->flags)) {
		pr_err("cull applied to unready cache\n");
		return -EIO;
	}

	if (test_bit(CACHEFILES_DEAD, &cache->flags)) {
		pr_err("cull applied to dead cache\n");
		return -EIO;
	}

	/* extract the directory dentry from the cwd */
	get_fs_pwd(current->fs, &path);

	if (!d_can_lookup(path.dentry))
		goto notdir;

	/* limit the scope of cull */
	if (cache->mnt != path.mnt) {
		path_put(&path);
		return -EOPNOTSUPP;
	}

	cachefiles_begin_secure(cache, &saved_cred);
	ret = cachefiles_cull(cache, path.dentry, args);
	cachefiles_end_secure(cache, saved_cred);

	path_put(&path);
	_leave(" = %d", ret);
	return ret;

notdir:
	path_put(&path);
	pr_err("cull command requires dirfd to be a directory\n");
	return -ENOTDIR;

inval:
	pr_err("cull command requires dirfd and filename\n");
	return -EINVAL;
}

/*
 * set debugging mode
 * - command: "debug <mask>"
 */
static int cachefiles_daemon_debug(struct cachefiles_cache *cache, char *args)
{
	unsigned long mask;

	_enter(",%s", args);

	mask = simple_strtoul(args, &args, 0);
	if (args[0] != '\0')
		goto inval;

	cachefiles_debug = mask;
	_leave(" = 0");
	return 0;

inval:
	pr_err("debug command requires mask\n");
	return -EINVAL;
}

/*
 * find out whether an object in the current working directory is in use or not
 * - command: "inuse <name>"
 */
static int cachefiles_daemon_inuse(struct cachefiles_cache *cache, char *args)
{
	struct path path;
	const struct cred *saved_cred;
	int ret;

	//_enter(",%s", args);

	if (strchr(args, '/'))
		goto inval;

	if (!test_bit(CACHEFILES_READY, &cache->flags)) {
		pr_err("inuse applied to unready cache\n");
		return -EIO;
	}

	if (test_bit(CACHEFILES_DEAD, &cache->flags)) {
		pr_err("inuse applied to dead cache\n");
		return -EIO;
	}

	/* extract the directory dentry from the cwd */
	get_fs_pwd(current->fs, &path);

	if (!d_can_lookup(path.dentry))
		goto notdir;

	cachefiles_begin_secure(cache, &saved_cred);
	ret = cachefiles_check_in_use(cache, path.dentry, args);
	cachefiles_end_secure(cache, saved_cred);

	path_put(&path);
	//_leave(" = %d", ret);
	return ret;

notdir:
	path_put(&path);
	pr_err("inuse command requires dirfd to be a directory\n");
	return -ENOTDIR;

inval:
	pr_err("inuse command requires dirfd and filename\n");
	return -EINVAL;
}

/*
 * see if we have space for a number of pages and/or a number of files in the
 * cache
 */
int cachefiles_has_space(struct cachefiles_cache *cache,
			 unsigned fnr, unsigned bnr)
{
	struct kstatfs stats;
	struct path path = {
		.mnt	= cache->mnt,
		.dentry	= cache->mnt->mnt_root,
	};
	int ret;

	//_enter("{%llu,%llu,%llu,%llu,%llu,%llu},%u,%u",
	//       (unsigned long long) cache->frun,
	//       (unsigned long long) cache->fcull,
	//       (unsigned long long) cache->fstop,
	//       (unsigned long long) cache->brun,
	//       (unsigned long long) cache->bcull,
	//       (unsigned long long) cache->bstop,
	//       fnr, bnr);

	/* find out how many pages of blockdev are available */
	memset(&stats, 0, sizeof(stats));

	ret = vfs_statfs(&path, &stats);
	if (ret < 0) {
		if (ret == -EIO)
			cachefiles_io_error(cache, "statfs failed");
		_leave(" = %d", ret);
		return ret;
	}

	stats.f_bavail >>= cache->bshift;

	//_debug("avail %llu,%llu",
	//       (unsigned long long) stats.f_ffree,
	//       (unsigned long long) stats.f_bavail);

	/* see if there is sufficient space */
	if (stats.f_ffree > fnr)
		stats.f_ffree -= fnr;
	else
		stats.f_ffree = 0;

	if (stats.f_bavail > bnr)
		stats.f_bavail -= bnr;
	else
		stats.f_bavail = 0;

	ret = -ENOBUFS;
	if (stats.f_ffree < cache->fstop ||
	    stats.f_bavail < cache->bstop)
		goto begin_cull;

	ret = 0;
	if (stats.f_ffree < cache->fcull ||
	    stats.f_bavail < cache->bcull)
		goto begin_cull;

	if (test_bit(CACHEFILES_CULLING, &cache->flags) &&
	    stats.f_ffree >= cache->frun &&
	    stats.f_bavail >= cache->brun &&
	    test_and_clear_bit(CACHEFILES_CULLING, &cache->flags)
	    ) {
		_debug("cease culling");
		cachefiles_state_changed(cache);
	}

	//_leave(" = 0");
	return 0;

begin_cull:
	if (!test_and_set_bit(CACHEFILES_CULLING, &cache->flags)) {
		_debug("### CULL CACHE ###");
		cachefiles_state_changed(cache);
	}

	_leave(" = %d", ret);
	return ret;
}
