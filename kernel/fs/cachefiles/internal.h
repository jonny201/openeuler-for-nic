/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General netfs cache on cache files internal defs
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "CacheFiles: " fmt


#include <linux/fscache-cache.h>
#include <linux/timer.h>
#include <linux/wait_bit.h>
#include <linux/cred.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/cachefiles.h>
#include <linux/idr.h>

struct cachefiles_cache;
struct cachefiles_object;

extern unsigned cachefiles_debug;
#define CACHEFILES_DEBUG_KENTER	1
#define CACHEFILES_DEBUG_KLEAVE	2
#define CACHEFILES_DEBUG_KDEBUG	4

#define cachefiles_gfp (__GFP_RECLAIM | __GFP_NORETRY | __GFP_NOMEMALLOC)

enum cachefiles_object_state {
	CACHEFILES_ONDEMAND_OBJSTATE_close, /* Anonymous fd closed by daemon or initial state */
	CACHEFILES_ONDEMAND_OBJSTATE_open, /* Anonymous fd associated with object is available */
	CACHEFILES_ONDEMAND_OBJSTATE_reopening, /* Object that was closed and is being reopened. */
	CACHEFILES_ONDEMAND_OBJSTATE_dropping, /* Object is being dropped. */
};

struct cachefiles_ondemand_info {
	struct work_struct		work;
	int				ondemand_id;
	enum cachefiles_object_state	state;
	struct cachefiles_object	*object;
	spinlock_t			lock;
};

/*
 * node records
 */
struct cachefiles_object {
	struct fscache_object		fscache;	/* fscache handle */
	struct cachefiles_lookup_data	*lookup_data;	/* cached lookup data */
	struct dentry			*dentry;	/* the file/dir representing this object */
	struct dentry			*backer;	/* backing file */
	struct file __rcu		*file;		/* backing file in on-demand mode */
	loff_t				i_size;		/* object size */
	unsigned long			flags;
#define CACHEFILES_OBJECT_ACTIVE	0		/* T if marked active */
	atomic_t			usage;		/* object usage count */
	uint8_t				type;		/* object type */
	uint8_t				new;		/* T if object new */
	spinlock_t			work_lock;
	struct rb_node			active_node;	/* link in active tree (dentry is key) */
	struct cachefiles_ondemand_info	*private;
};

extern struct kmem_cache *cachefiles_object_jar;

#define CACHEFILES_ONDEMAND_ID_CLOSED	-1

/*
 * Cache files cache definition
 */
struct cachefiles_cache {
	struct fscache_cache		cache;		/* FS-Cache record */
	struct vfsmount			*mnt;		/* mountpoint holding the cache */
	struct dentry			*graveyard;	/* directory into which dead objects go */
	struct file			*cachefilesd;	/* manager daemon handle */
	const struct cred		*cache_cred;	/* security override for accessing cache */
	struct mutex			daemon_mutex;	/* command serialisation mutex */
	wait_queue_head_t		daemon_pollwq;	/* poll waitqueue for daemon */
	struct rb_root			active_nodes;	/* active nodes (can't be culled) */
	rwlock_t			active_lock;	/* lock for active_nodes */
	atomic_t			gravecounter;	/* graveyard uniquifier */
	atomic_t			f_released;	/* number of objects released lately */
	atomic_long_t			b_released;	/* number of blocks released lately */
	unsigned			frun_percent;	/* when to stop culling (% files) */
	unsigned			fcull_percent;	/* when to start culling (% files) */
	unsigned			fstop_percent;	/* when to stop allocating (% files) */
	unsigned			brun_percent;	/* when to stop culling (% blocks) */
	unsigned			bcull_percent;	/* when to start culling (% blocks) */
	unsigned			bstop_percent;	/* when to stop allocating (% blocks) */
	unsigned			bsize;		/* cache's block size */
	unsigned			bshift;		/* min(ilog2(PAGE_SIZE / bsize), 0) */
	uint64_t			frun;		/* when to stop culling */
	uint64_t			fcull;		/* when to start culling */
	uint64_t			fstop;		/* when to stop allocating */
	sector_t			brun;		/* when to stop culling */
	sector_t			bcull;		/* when to start culling */
	sector_t			bstop;		/* when to stop allocating */
	unsigned long			flags;
#define CACHEFILES_READY		0	/* T if cache prepared */
#define CACHEFILES_DEAD			1	/* T if cache dead */
#define CACHEFILES_CULLING		2	/* T if cull engaged */
#define CACHEFILES_STATE_CHANGED	3	/* T if state changed (poll trigger) */
#define CACHEFILES_ONDEMAND_MODE	4	/* T if in on-demand read mode */
	char				*rootdirname;	/* name of cache root directory */
	char				*secctx;	/* LSM security context */
	char				*tag;		/* cache binding tag */
	refcount_t			unbind_pincount;/* refcount to do daemon unbind */
	struct radix_tree_root		reqs;		/* xarray of pending on-demand requests */
	unsigned long			req_id_next;
	struct idr			ondemand_ids;	/* xarray for ondemand_id allocation */
	u32				ondemand_id_next;
};

static inline bool cachefiles_in_ondemand_mode(struct cachefiles_cache *cache)
{
	return IS_ENABLED(CONFIG_CACHEFILES_ONDEMAND) &&
		test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags);
}

struct cachefiles_req {
	struct cachefiles_object *object;
	struct completion done;
	refcount_t ref;
	int error;
	struct cachefiles_msg msg;
};

#define CACHEFILES_REQ_NEW	0

/*
 * backing file read tracking
 */
struct cachefiles_one_read {
	wait_queue_entry_t			monitor;	/* link into monitored waitqueue */
	struct page			*back_page;	/* backing file page we're waiting for */
	struct page			*netfs_page;	/* netfs page we're going to fill */
	struct fscache_retrieval	*op;		/* retrieval op covering this */
	struct list_head		op_link;	/* link in op's todo list */
	unsigned long			flags;
#define CACHEFILES_MONITOR_ENTER_READ	0       /* restrict calls to read_page */
};

/*
 * backing file write tracking
 */
struct cachefiles_one_write {
	struct page			*netfs_page;	/* netfs page to copy */
	struct cachefiles_object	*object;
	struct list_head		obj_link;	/* link in object's lists */
	fscache_rw_complete_t		end_io_func;
	void				*context;
};

/*
 * auxiliary data xattr buffer
 */
struct cachefiles_xattr {
	uint16_t			len;
	uint8_t				type;
	uint8_t				data[];
};

#include <trace/events/cachefiles.h>

/*
 * note change of state for daemon
 */
static inline void cachefiles_state_changed(struct cachefiles_cache *cache)
{
	set_bit(CACHEFILES_STATE_CHANGED, &cache->flags);
	wake_up_all(&cache->daemon_pollwq);
}

/*
 * bind.c
 */
extern int cachefiles_daemon_bind(struct cachefiles_cache *cache, char *args);
extern void cachefiles_daemon_unbind(struct cachefiles_cache *cache);

/*
 * daemon.c
 */
extern const struct file_operations cachefiles_daemon_fops;
extern void cachefiles_flush_reqs(struct cachefiles_cache *cache);
extern void cachefiles_get_unbind_pincount(struct cachefiles_cache *cache);
extern void cachefiles_put_unbind_pincount(struct cachefiles_cache *cache);

extern int cachefiles_has_space(struct cachefiles_cache *cache,
				unsigned fnr, unsigned bnr);

/*
 * interface.c
 */
extern const struct fscache_cache_ops cachefiles_cache_ops;

/*
 * key.c
 */
extern char *cachefiles_cook_key(struct cachefiles_object *object,
				 const u8 *raw, int keylen);

/*
 * namei.c
 */
extern void cachefiles_mark_object_inactive(struct cachefiles_cache *cache,
					    struct cachefiles_object *object,
					    blkcnt_t i_blocks);
extern int cachefiles_mark_object_active(struct cachefiles_cache *cache,
					 struct cachefiles_object *object);
extern int cachefiles_delete_object(struct cachefiles_cache *cache,
				    struct cachefiles_object *object);
extern int cachefiles_walk_to_object(struct cachefiles_object *parent,
				     struct cachefiles_object *object,
				     const char *key,
				     struct cachefiles_xattr *auxdata);
extern struct dentry *cachefiles_get_directory(struct cachefiles_cache *cache,
					       struct dentry *dir,
					       const char *name);

extern int cachefiles_cull(struct cachefiles_cache *cache, struct dentry *dir,
			   char *filename);

extern int cachefiles_check_in_use(struct cachefiles_cache *cache,
				   struct dentry *dir, char *filename);

/*
 * proc.c
 */
#ifdef CONFIG_CACHEFILES_HISTOGRAM
extern atomic_t cachefiles_lookup_histogram[HZ];
extern atomic_t cachefiles_mkdir_histogram[HZ];
extern atomic_t cachefiles_create_histogram[HZ];

extern int __init cachefiles_proc_init(void);
extern void cachefiles_proc_cleanup(void);
static inline
void cachefiles_hist(atomic_t histogram[], unsigned long start_jif)
{
	unsigned long jif = jiffies - start_jif;
	if (jif >= HZ)
		jif = HZ - 1;
	atomic_inc(&histogram[jif]);
}

#else
#define cachefiles_proc_init()		(0)
#define cachefiles_proc_cleanup()	do {} while (0)
#define cachefiles_hist(hist, start_jif) do {} while (0)
#endif

/*
 * rdwr.c
 */
extern int cachefiles_read_or_alloc_page(struct fscache_retrieval *,
					 struct page *, gfp_t);
extern int cachefiles_read_or_alloc_pages(struct fscache_retrieval *,
					  struct list_head *, unsigned *,
					  gfp_t);
extern int cachefiles_prepare_read(struct fscache_retrieval *op, pgoff_t index);
extern int cachefiles_allocate_page(struct fscache_retrieval *, struct page *,
				    gfp_t);
extern int cachefiles_allocate_pages(struct fscache_retrieval *,
				     struct list_head *, unsigned *, gfp_t);
extern int cachefiles_write_page(struct fscache_storage *, struct page *);
extern void cachefiles_uncache_page(struct fscache_object *, struct page *);

/*
 * ondemand.c
 */
#ifdef CONFIG_CACHEFILES_ONDEMAND
extern ssize_t cachefiles_ondemand_daemon_read(struct cachefiles_cache *cache,
				char __user *_buffer, size_t buflen, loff_t *pos);

extern int cachefiles_ondemand_copen(struct cachefiles_cache *cache,
				     char *args);

extern int cachefiles_ondemand_restore(struct cachefiles_cache *cache,
					char *args);

extern int cachefiles_ondemand_init_object(struct cachefiles_object *object);
extern void cachefiles_ondemand_clean_object(struct cachefiles_object *object);
extern int cachefiles_ondemand_read(struct cachefiles_object *object,
			     loff_t pos, size_t len);

extern int cachefiles_ondemand_init_obj_info(struct cachefiles_object *object);

#define CACHEFILES_OBJECT_STATE_FUNCS(_state)	\
static inline bool								\
cachefiles_ondemand_object_is_##_state(const struct cachefiles_object *object) \
{												\
	return object->private->state == CACHEFILES_ONDEMAND_OBJSTATE_##_state; \
}												\
												\
static inline void								\
cachefiles_ondemand_set_object_##_state(struct cachefiles_object *object) \
{												\
	object->private->state = CACHEFILES_ONDEMAND_OBJSTATE_##_state; \
}

CACHEFILES_OBJECT_STATE_FUNCS(open);
CACHEFILES_OBJECT_STATE_FUNCS(close);
CACHEFILES_OBJECT_STATE_FUNCS(reopening);
CACHEFILES_OBJECT_STATE_FUNCS(dropping);

static inline bool cachefiles_ondemand_is_reopening_read(struct cachefiles_req *req)
{
	return cachefiles_ondemand_object_is_reopening(req->object) &&
			req->msg.opcode == CACHEFILES_OP_READ;
}

#else
static inline ssize_t cachefiles_ondemand_daemon_read(struct cachefiles_cache *cache,
				char __user *_buffer, size_t buflen, loff_t *pos)
{
	return -EOPNOTSUPP;
}

static inline int cachefiles_ondemand_init_object(struct cachefiles_object *object)
{
	return 0;
}

static inline void cachefiles_ondemand_clean_object(struct cachefiles_object *object)
{
}
static inline int cachefiles_ondemand_read(struct cachefiles_object *object,
					   loff_t pos, size_t len)
{
	return -EOPNOTSUPP;
}

static inline int cachefiles_ondemand_init_obj_info(struct cachefiles_object *object)
{
	return 0;
}

static inline bool cachefiles_ondemand_is_reopening_read(struct cachefiles_req *req)
{
	return false;
}
#endif

/*
 * security.c
 */
extern int cachefiles_get_security_ID(struct cachefiles_cache *cache);
extern int cachefiles_determine_cache_security(struct cachefiles_cache *cache,
					       struct dentry *root,
					       const struct cred **_saved_cred);

static inline void cachefiles_begin_secure(struct cachefiles_cache *cache,
					   const struct cred **_saved_cred)
{
	*_saved_cred = override_creds(cache->cache_cred);
}

static inline void cachefiles_end_secure(struct cachefiles_cache *cache,
					 const struct cred *saved_cred)
{
	revert_creds(saved_cred);
}

/*
 * xattr.c
 */
extern int cachefiles_check_object_type(struct cachefiles_object *object,
					struct cachefiles_cache *cache);
extern int cachefiles_set_object_xattr(struct cachefiles_object *object,
				       struct cachefiles_xattr *auxdata);
extern int cachefiles_update_object_xattr(struct cachefiles_object *object,
					  struct cachefiles_xattr *auxdata);
extern int cachefiles_check_auxdata(struct cachefiles_object *object);
extern int cachefiles_check_object_xattr(struct cachefiles_object *object,
					 struct cachefiles_xattr *auxdata);
extern int cachefiles_remove_object_xattr(struct cachefiles_cache *cache,
					  struct dentry *dentry);


/*
 * error handling
 */

#define cachefiles_io_error(___cache, FMT, ...)		\
do {							\
	pr_err("I/O Error: " FMT"\n", ##__VA_ARGS__);	\
	fscache_io_error(&(___cache)->cache);		\
	set_bit(CACHEFILES_DEAD, &(___cache)->flags);	\
	if (cachefiles_in_ondemand_mode(___cache))	\
		cachefiles_flush_reqs(___cache);	\
} while (0)

#define cachefiles_io_error_obj(object, FMT, ...)			\
do {									\
	struct cachefiles_cache *___cache;				\
									\
	___cache = container_of((object)->fscache.cache,		\
				struct cachefiles_cache, cache);	\
	cachefiles_io_error(___cache, FMT, ##__VA_ARGS__);		\
} while (0)


/*
 * debug tracing
 */
#define dbgprintk(FMT, ...) \
	printk(KERN_DEBUG "[%-6.6s] "FMT"\n", current->comm, ##__VA_ARGS__)

#define kenter(FMT, ...) dbgprintk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) dbgprintk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define kdebug(FMT, ...) dbgprintk(FMT, ##__VA_ARGS__)


#if defined(__KDEBUG)
#define _enter(FMT, ...) kenter(FMT, ##__VA_ARGS__)
#define _leave(FMT, ...) kleave(FMT, ##__VA_ARGS__)
#define _debug(FMT, ...) kdebug(FMT, ##__VA_ARGS__)

#elif defined(CONFIG_CACHEFILES_DEBUG)
#define _enter(FMT, ...)				\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KENTER)	\
		kenter(FMT, ##__VA_ARGS__);		\
} while (0)

#define _leave(FMT, ...)				\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KLEAVE)	\
		kleave(FMT, ##__VA_ARGS__);		\
} while (0)

#define _debug(FMT, ...)				\
do {							\
	if (cachefiles_debug & CACHEFILES_DEBUG_KDEBUG)	\
		kdebug(FMT, ##__VA_ARGS__);		\
} while (0)

#else
#define _enter(FMT, ...) no_printk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define _leave(FMT, ...) no_printk("<== %s()"FMT"", __func__, ##__VA_ARGS__)
#define _debug(FMT, ...) no_printk(FMT, ##__VA_ARGS__)
#endif

#if 1 /* defined(__KDEBUGALL) */

#define ASSERT(X)							\
do {									\
	if (unlikely(!(X))) {						\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		BUG();							\
	}								\
} while (0)

#define ASSERTCMP(X, OP, Y)						\
do {									\
	if (unlikely(!((X) OP (Y)))) {					\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		pr_err("%lx " #OP " %lx is false\n",			\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while (0)

#define ASSERTIF(C, X)							\
do {									\
	if (unlikely((C) && !(X))) {					\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		BUG();							\
	}								\
} while (0)

#define ASSERTIFCMP(C, X, OP, Y)					\
do {									\
	if (unlikely((C) && !((X) OP (Y)))) {				\
		pr_err("\n");						\
		pr_err("Assertion failed\n");		\
		pr_err("%lx " #OP " %lx is false\n",			\
		       (unsigned long)(X), (unsigned long)(Y));		\
		BUG();							\
	}								\
} while (0)

#else

#define ASSERT(X)			do {} while (0)
#define ASSERTCMP(X, OP, Y)		do {} while (0)
#define ASSERTIF(C, X)			do {} while (0)
#define ASSERTIFCMP(C, X, OP, Y)	do {} while (0)

#endif
