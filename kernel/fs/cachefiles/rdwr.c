// SPDX-License-Identifier: GPL-2.0-or-later
/* Storage object read/write
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/swap.h>
#include <linux/backing-dev.h>
#include <linux/uio.h>
#include "internal.h"

/*
 * detect wake up events generated by the unlocking of pages in which we're
 * interested
 * - we use this to detect read completion of backing pages
 * - the caller holds the waitqueue lock
 */
static int cachefiles_read_waiter(wait_queue_entry_t *wait, unsigned mode,
				  int sync, void *_key)
{
	struct cachefiles_one_read *monitor =
		container_of(wait, struct cachefiles_one_read, monitor);
	struct cachefiles_object *object;
	struct fscache_retrieval *op = monitor->op;
	struct wait_page_key *key = _key;
	struct page *page = wait->private;

	ASSERT(key);

	_enter("{%lu},%u,%d,{%p,%u}",
	       monitor->netfs_page->index, mode, sync,
	       key->page, key->bit_nr);

	if (key->page != page || key->bit_nr != PG_locked)
		return 0;

	_debug("--- monitor %p %lx ---", page, page->flags);

	if (!PageUptodate(page) && !PageError(page)) {
		/* unlocked, not uptodate and not erronous? */
		_debug("page probably truncated");
	}

	/* remove from the waitqueue */
	list_del(&wait->entry);

	/* move onto the action list and queue for FS-Cache thread pool */
	ASSERT(op);

	/* We need to temporarily bump the usage count as we don't own a ref
	 * here otherwise cachefiles_read_copier() may free the op between the
	 * monitor being enqueued on the op->to_do list and the op getting
	 * enqueued on the work queue.
	 */
	fscache_get_retrieval(op);

	object = container_of(op->op.object, struct cachefiles_object, fscache);
	spin_lock(&object->work_lock);
	list_add_tail(&monitor->op_link, &op->to_do);
	fscache_enqueue_retrieval(op);
	spin_unlock(&object->work_lock);

	fscache_put_retrieval(op);
	return 0;
}

/*
 * handle a probably truncated page
 * - check to see if the page is still relevant and reissue the read if
 *   possible
 * - return -EIO on error, -ENODATA if the page is gone, -EINPROGRESS if we
 *   must wait again and 0 if successful
 */
static int cachefiles_read_reissue(struct cachefiles_object *object,
				   struct cachefiles_one_read *monitor)
{
	struct address_space *bmapping = d_backing_inode(object->backer)->i_mapping;
	struct page *backpage = monitor->back_page, *backpage2;
	int ret;

	_enter("{ino=%lx},{%lx,%lx}",
	       d_backing_inode(object->backer)->i_ino,
	       backpage->index, backpage->flags);

	/* skip if the page was truncated away completely */
	if (backpage->mapping != bmapping) {
		_leave(" = -ENODATA [mapping]");
		return -ENODATA;
	}

	backpage2 = find_get_page(bmapping, backpage->index);
	if (!backpage2) {
		_leave(" = -ENODATA [gone]");
		return -ENODATA;
	}

	if (backpage != backpage2) {
		put_page(backpage2);
		_leave(" = -ENODATA [different]");
		return -ENODATA;
	}

	/* the page is still there and we already have a ref on it, so we don't
	 * need a second */
	put_page(backpage2);

	/*
	 * end the process if the page was not truncated
	 * and we have already read it before
	 */
	if (test_bit(CACHEFILES_MONITOR_ENTER_READ, &monitor->flags))
		return -EIO;

	INIT_LIST_HEAD(&monitor->op_link);
	add_page_wait_queue(backpage, &monitor->monitor);

	if (trylock_page(backpage)) {
		ret = -EIO;
		if (PageError(backpage))
			goto unlock_discard;
		ret = 0;
		if (PageUptodate(backpage))
			goto unlock_discard;

		_debug("reissue read");
		if (data_new_version(object->fscache.cookie))
			set_bit(CACHEFILES_MONITOR_ENTER_READ, &monitor->flags);
		ret = bmapping->a_ops->readpage(NULL, backpage);
		if (ret < 0)
			goto discard;
	}

	/* but the page may have been read before the monitor was installed, so
	 * the monitor may miss the event - so we have to ensure that we do get
	 * one in such a case */
	if (trylock_page(backpage)) {
		_debug("jumpstart %p {%lx}", backpage, backpage->flags);
		unlock_page(backpage);
	}

	/* it'll reappear on the todo list */
	_leave(" = -EINPROGRESS");
	return -EINPROGRESS;

unlock_discard:
	unlock_page(backpage);
discard:
	spin_lock_irq(&object->work_lock);
	list_del(&monitor->op_link);
	spin_unlock_irq(&object->work_lock);
	_leave(" = %d", ret);
	return ret;
}

/*
 * copy data from backing pages to netfs pages to complete a read operation
 * - driven by FS-Cache's thread pool
 */
static void cachefiles_read_copier(struct fscache_operation *_op)
{
	struct cachefiles_one_read *monitor;
	struct cachefiles_object *object;
	struct fscache_retrieval *op;
	int error, max;

	op = container_of(_op, struct fscache_retrieval, op);
	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);

	_enter("{ino=%lu}", d_backing_inode(object->backer)->i_ino);

	max = 8;
	spin_lock_irq(&object->work_lock);

	while (!list_empty(&op->to_do)) {
		monitor = list_entry(op->to_do.next,
				     struct cachefiles_one_read, op_link);
		list_del(&monitor->op_link);

		spin_unlock_irq(&object->work_lock);

		_debug("- copy {%lu}", monitor->back_page->index);

	recheck:
		if (test_bit(FSCACHE_COOKIE_INVALIDATING,
			     &object->fscache.cookie->flags)) {
			error = -ESTALE;
		} else if (PageUptodate(monitor->back_page)) {
			copy_highpage(monitor->netfs_page, monitor->back_page);
			fscache_mark_page_cached(monitor->op,
						 monitor->netfs_page);
			error = 0;
		} else if (!PageError(monitor->back_page)) {
			/* the page has probably been truncated */
			error = cachefiles_read_reissue(object, monitor);
			if (error == -EINPROGRESS)
				goto next;
			if (!data_new_version(object->fscache.cookie) || !error)
				goto recheck;
			pr_warn("%s, read error: %d, at page %lu, flags: %lx\n",
				__func__, error, monitor->back_page->index,
				(unsigned long) monitor->back_page->flags);
		} else {
			cachefiles_io_error_obj(
				object,
				"Readpage failed on backing file %lx",
				(unsigned long) monitor->back_page->flags);
			error = -EIO;
		}

		put_page(monitor->back_page);

		fscache_end_io(op, monitor->netfs_page, error);
		put_page(monitor->netfs_page);
		fscache_retrieval_complete(op, 1);
		fscache_put_retrieval(op);
		kfree(monitor);

	next:
		/* let the thread pool have some air occasionally */
		max--;
		if (max < 0 || need_resched()) {
			if (!list_empty(&op->to_do))
				fscache_enqueue_retrieval(op);
			_leave(" [maxed out]");
			return;
		}

		spin_lock_irq(&object->work_lock);
	}

	spin_unlock_irq(&object->work_lock);
	_leave("");
}

/*
 * read the corresponding page to the given set from the backing file
 * - an uncertain page is simply discarded, to be tried again another time
 */
static int cachefiles_read_backing_file_one(struct cachefiles_object *object,
					    struct fscache_retrieval *op,
					    struct page *netpage)
{
	struct cachefiles_one_read *monitor;
	struct address_space *bmapping;
	struct page *newpage, *backpage;
	pgoff_t index = op->offset >> PAGE_SHIFT;
	int ret;

	_enter("");

	_debug("read back %p{%lu,%d}",
	       netpage, index, page_count(netpage));

	monitor = kzalloc(sizeof(*monitor), cachefiles_gfp);
	if (!monitor)
		goto nomem;

	monitor->netfs_page = netpage;
	monitor->op = fscache_get_retrieval(op);

	init_waitqueue_func_entry(&monitor->monitor, cachefiles_read_waiter);

	/* attempt to get hold of the backing page */
	bmapping = d_backing_inode(object->backer)->i_mapping;
	newpage = NULL;

	for (;;) {
		backpage = find_get_page(bmapping, index);
		if (backpage)
			goto backing_page_already_present;

		if (!newpage) {
			newpage = __page_cache_alloc(cachefiles_gfp);
			if (!newpage)
				goto nomem_monitor;
		}

		ret = add_to_page_cache_lru(newpage, bmapping,
					    index, cachefiles_gfp);
		if (ret == 0)
			goto installed_new_backing_page;
		if (ret != -EEXIST)
			goto nomem_page;
	}

	/* we've installed a new backing page, so now we need to start
	 * it reading */
installed_new_backing_page:
	_debug("- new %p", newpage);

	backpage = newpage;
	newpage = NULL;

read_backing_page:
	if (data_new_version(object->fscache.cookie))
		set_bit(CACHEFILES_MONITOR_ENTER_READ, &monitor->flags);
	ret = bmapping->a_ops->readpage(NULL, backpage);
	if (ret < 0)
		goto read_error;

	/* set the monitor to transfer the data across */
monitor_backing_page:
	_debug("- monitor add");

	/* install the monitor */
	get_page(monitor->netfs_page);
	get_page(backpage);
	monitor->back_page = backpage;
	monitor->monitor.private = backpage;
	add_page_wait_queue(backpage, &monitor->monitor);
	monitor = NULL;

	/* but the page may have been read before the monitor was installed, so
	 * the monitor may miss the event - so we have to ensure that we do get
	 * one in such a case */
	if (trylock_page(backpage)) {
		_debug("jumpstart %p {%lx}", backpage, backpage->flags);
		unlock_page(backpage);
	}
	goto success;

	/* if the backing page is already present, it can be in one of
	 * three states: read in progress, read failed or read okay */
backing_page_already_present:
	_debug("- present");

	if (newpage) {
		put_page(newpage);
		newpage = NULL;
	}

	if (PageError(backpage))
		goto io_error;

	if (PageUptodate(backpage))
		goto backing_page_already_uptodate;

	if (!trylock_page(backpage))
		goto monitor_backing_page;
	_debug("read %p {%lx}", backpage, backpage->flags);
	goto read_backing_page;

	/* the backing page is already up to date, attach the netfs
	 * page to the pagecache and LRU and copy the data across */
backing_page_already_uptodate:
	_debug("- uptodate");

	fscache_mark_page_cached(op, netpage);

	copy_highpage(netpage, backpage);
	fscache_end_io(op, netpage, 0);
	fscache_retrieval_complete(op, 1);

success:
	_debug("success");
	ret = 0;

out:
	if (backpage)
		put_page(backpage);
	if (monitor) {
		fscache_put_retrieval(monitor->op);
		kfree(monitor);
	}
	_leave(" = %d", ret);
	return ret;

read_error:
	_debug("read error %d", ret);
	if (ret == -ENOMEM) {
		fscache_retrieval_complete(op, 1);
		goto out;
	}
io_error:
	cachefiles_io_error_obj(object, "Page read error on backing file");
	fscache_retrieval_complete(op, 1);
	ret = -ENOBUFS;
	goto out;

nomem_page:
	put_page(newpage);
nomem_monitor:
	fscache_put_retrieval(monitor->op);
	kfree(monitor);
nomem:
	fscache_retrieval_complete(op, 1);
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

/*
 * read a page from the cache or allocate a block in which to store it
 * - cache withdrawal is prevented by the caller
 * - returns -EINTR if interrupted
 * - returns -ENOMEM if ran out of memory
 * - returns -ENOBUFS if no buffers can be made available
 * - returns -ENOBUFS if page is beyond EOF
 * - if the page is backed by a block in the cache:
 *   - a read will be started which will call the callback on completion
 *   - 0 will be returned
 * - else if the page is unbacked:
 *   - the metadata will be retained
 *   - -ENODATA will be returned
 */
int cachefiles_read_or_alloc_page(struct fscache_retrieval *op,
				  struct page *page,
				  gfp_t gfp)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct inode *inode;
	sector_t block;
	unsigned shift;
	int ret, ret2;
	bool again = true;
	loff_t pos = op->offset;

	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	_enter("{%p},{%lx},,,", object, page->index);

	if (!object->backer)
		goto enobufs;

	inode = d_backing_inode(object->backer);
	ASSERT(S_ISREG(inode->i_mode));

	/* calculate the shift required to use bmap */
	shift = PAGE_SHIFT - inode->i_sb->s_blocksize_bits;

	op->op.flags &= FSCACHE_OP_KEEP_FLAGS;
	op->op.flags |= FSCACHE_OP_ASYNC;
	op->op.processor = cachefiles_read_copier;

	/* we assume the absence or presence of the first block is a good
	 * enough indication for the page as a whole
	 * - TODO: don't use bmap() for this as it is _not_ actually good
	 *   enough for this as it doesn't indicate errors, but it's all we've
	 *   got for the moment
	 */
retry:
	block = pos >> PAGE_SHIFT;
	block <<= shift;

	ret2 = bmap(inode, &block);
	ASSERT(ret2 == 0);

	_debug("%llx -> %llx",
	       (unsigned long long) (pos >> PAGE_SHIFT << shift),
	       (unsigned long long) block);

	if (block) {
		/* submit the apparently valid page to the backing fs to be
		 * read from disk */
		ret = cachefiles_read_backing_file_one(object, op, page);
	} else if (cachefiles_has_space(cache, 0, 1) == 0) {
		if (cachefiles_in_ondemand_mode(cache) && again) {
			ret = cachefiles_ondemand_read(object, pos, PAGE_SIZE);
			if (!ret) {
				again = false;
				goto retry;
			}
		}
		/* there's space in the cache we can use */
		fscache_mark_page_cached(op, page);
		fscache_retrieval_complete(op, 1);
		ret = -ENODATA;
	} else {
		goto enobufs;
	}

	_leave(" = %d", ret);
	return ret;

enobufs:
	fscache_retrieval_complete(op, 1);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}

/*
 * read the corresponding pages to the given set from the backing file
 * - any uncertain pages are simply discarded, to be tried again another time
 */
static int cachefiles_read_backing_file(struct cachefiles_object *object,
					struct fscache_retrieval *op,
					struct list_head *list)
{
	struct cachefiles_one_read *monitor = NULL;
	struct address_space *bmapping = d_backing_inode(object->backer)->i_mapping;
	struct page *newpage = NULL, *netpage, *_n, *backpage = NULL;
	int ret = 0;

	_enter("");

	list_for_each_entry_safe(netpage, _n, list, lru) {
		list_del(&netpage->lru);

		_debug("read back %p{%lu,%d}",
		       netpage, netpage->index, page_count(netpage));

		if (!monitor) {
			monitor = kzalloc(sizeof(*monitor), cachefiles_gfp);
			if (!monitor)
				goto nomem;

			monitor->op = fscache_get_retrieval(op);
			init_waitqueue_func_entry(&monitor->monitor,
						  cachefiles_read_waiter);
		}

		for (;;) {
			backpage = find_get_page(bmapping, netpage->index);
			if (backpage)
				goto backing_page_already_present;

			if (!newpage) {
				newpage = __page_cache_alloc(cachefiles_gfp);
				if (!newpage)
					goto nomem;
			}

			ret = add_to_page_cache_lru(newpage, bmapping,
						    netpage->index,
						    cachefiles_gfp);
			if (ret == 0)
				goto installed_new_backing_page;
			if (ret != -EEXIST)
				goto nomem;
		}

		/* we've installed a new backing page, so now we need
		 * to start it reading */
	installed_new_backing_page:
		_debug("- new %p", newpage);

		backpage = newpage;
		newpage = NULL;

	reread_backing_page:
		ret = bmapping->a_ops->readpage(NULL, backpage);
		if (ret < 0)
			goto read_error;

		/* add the netfs page to the pagecache and LRU, and set the
		 * monitor to transfer the data across */
	monitor_backing_page:
		_debug("- monitor add");

		ret = add_to_page_cache_lru(netpage, op->mapping,
					    netpage->index, cachefiles_gfp);
		if (ret < 0) {
			if (ret == -EEXIST) {
				put_page(backpage);
				backpage = NULL;
				put_page(netpage);
				netpage = NULL;
				fscache_retrieval_complete(op, 1);
				continue;
			}
			goto nomem;
		}

		/* install a monitor */
		get_page(netpage);
		monitor->netfs_page = netpage;

		get_page(backpage);
		monitor->back_page = backpage;
		monitor->monitor.private = backpage;
		add_page_wait_queue(backpage, &monitor->monitor);
		monitor = NULL;

		/* but the page may have been read before the monitor was
		 * installed, so the monitor may miss the event - so we have to
		 * ensure that we do get one in such a case */
		if (trylock_page(backpage)) {
			_debug("2unlock %p {%lx}", backpage, backpage->flags);
			unlock_page(backpage);
		}

		put_page(backpage);
		backpage = NULL;

		put_page(netpage);
		netpage = NULL;
		continue;

		/* if the backing page is already present, it can be in one of
		 * three states: read in progress, read failed or read okay */
	backing_page_already_present:
		_debug("- present %p", backpage);

		if (PageError(backpage))
			goto io_error;

		if (PageUptodate(backpage))
			goto backing_page_already_uptodate;

		_debug("- not ready %p{%lx}", backpage, backpage->flags);

		if (!trylock_page(backpage))
			goto monitor_backing_page;

		if (PageError(backpage)) {
			_debug("error %lx", backpage->flags);
			unlock_page(backpage);
			goto io_error;
		}

		if (PageUptodate(backpage))
			goto backing_page_already_uptodate_unlock;

		/* we've locked a page that's neither up to date nor erroneous,
		 * so we need to attempt to read it again */
		goto reread_backing_page;

		/* the backing page is already up to date, attach the netfs
		 * page to the pagecache and LRU and copy the data across */
	backing_page_already_uptodate_unlock:
		_debug("uptodate %lx", backpage->flags);
		unlock_page(backpage);
	backing_page_already_uptodate:
		_debug("- uptodate");

		ret = add_to_page_cache_lru(netpage, op->mapping,
					    netpage->index, cachefiles_gfp);
		if (ret < 0) {
			if (ret == -EEXIST) {
				put_page(backpage);
				backpage = NULL;
				put_page(netpage);
				netpage = NULL;
				fscache_retrieval_complete(op, 1);
				continue;
			}
			goto nomem;
		}

		copy_highpage(netpage, backpage);

		put_page(backpage);
		backpage = NULL;

		fscache_mark_page_cached(op, netpage);

		/* the netpage is unlocked and marked up to date here */
		fscache_end_io(op, netpage, 0);
		put_page(netpage);
		netpage = NULL;
		fscache_retrieval_complete(op, 1);
		continue;
	}

	netpage = NULL;

	_debug("out");

out:
	/* tidy up */
	if (newpage)
		put_page(newpage);
	if (netpage)
		put_page(netpage);
	if (backpage)
		put_page(backpage);
	if (monitor) {
		fscache_put_retrieval(op);
		kfree(monitor);
	}

	list_for_each_entry_safe(netpage, _n, list, lru) {
		list_del(&netpage->lru);
		put_page(netpage);
		fscache_retrieval_complete(op, 1);
	}

	_leave(" = %d", ret);
	return ret;

nomem:
	_debug("nomem");
	ret = -ENOMEM;
	goto record_page_complete;

read_error:
	_debug("read error %d", ret);
	if (ret == -ENOMEM)
		goto record_page_complete;
io_error:
	cachefiles_io_error_obj(object, "Page read error on backing file");
	ret = -ENOBUFS;
record_page_complete:
	fscache_retrieval_complete(op, 1);
	goto out;
}

/*
 * read a list of pages from the cache or allocate blocks in which to store
 * them
 */
int cachefiles_read_or_alloc_pages(struct fscache_retrieval *op,
				   struct list_head *pages,
				   unsigned *nr_pages,
				   gfp_t gfp)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct list_head backpages;
	struct pagevec pagevec;
	struct inode *inode;
	struct page *page, *_n;
	unsigned shift, nrbackpages;
	int ret, ret2, space;

	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	_enter("{OBJ%x,%d},,%d,,",
	       object->fscache.debug_id, atomic_read(&op->op.usage),
	       *nr_pages);

	if (!object->backer)
		goto all_enobufs;

	space = 1;
	if (cachefiles_has_space(cache, 0, *nr_pages) < 0)
		space = 0;

	inode = d_backing_inode(object->backer);
	ASSERT(S_ISREG(inode->i_mode));

	/* calculate the shift required to use bmap */
	shift = PAGE_SHIFT - inode->i_sb->s_blocksize_bits;

	pagevec_init(&pagevec);

	op->op.flags &= FSCACHE_OP_KEEP_FLAGS;
	op->op.flags |= FSCACHE_OP_ASYNC;
	op->op.processor = cachefiles_read_copier;

	INIT_LIST_HEAD(&backpages);
	nrbackpages = 0;

	ret = space ? -ENODATA : -ENOBUFS;
	list_for_each_entry_safe(page, _n, pages, lru) {
		sector_t block;

		/* we assume the absence or presence of the first block is a
		 * good enough indication for the page as a whole
		 * - TODO: don't use bmap() for this as it is _not_ actually
		 *   good enough for this as it doesn't indicate errors, but
		 *   it's all we've got for the moment
		 */
		block = page->index;
		block <<= shift;

		ret2 = bmap(inode, &block);
		ASSERT(ret2 == 0);

		_debug("%llx -> %llx",
		       (unsigned long long) (page->index << shift),
		       (unsigned long long) block);

		if (block) {
			/* we have data - add it to the list to give to the
			 * backing fs */
			list_move(&page->lru, &backpages);
			(*nr_pages)--;
			nrbackpages++;
		} else if (space && pagevec_add(&pagevec, page) == 0) {
			fscache_mark_pages_cached(op, &pagevec);
			fscache_retrieval_complete(op, 1);
			ret = -ENODATA;
		} else {
			fscache_retrieval_complete(op, 1);
		}
	}

	if (pagevec_count(&pagevec) > 0)
		fscache_mark_pages_cached(op, &pagevec);

	if (list_empty(pages))
		ret = 0;

	/* submit the apparently valid pages to the backing fs to be read from
	 * disk */
	if (nrbackpages > 0) {
		ret2 = cachefiles_read_backing_file(object, op, &backpages);
		if (ret2 == -ENOMEM || ret2 == -EINTR)
			ret = ret2;
	}

	_leave(" = %d [nr=%u%s]",
	       ret, *nr_pages, list_empty(pages) ? " empty" : "");
	return ret;

all_enobufs:
	fscache_retrieval_complete(op, *nr_pages);
	return -ENOBUFS;
}

static int cachefiles_ondemand_check(struct cachefiles_object *object,
		loff_t start_pos, size_t len)
{
	struct file *file = rcu_dereference_raw(object->file);
	size_t remained;
	loff_t pos;
	int ret;

	/* make sure there's no hole in the requested range */
	pos = start_pos;
	remained = len;

	while (remained) {
		bool again = true;
		size_t count = remained;
		loff_t off, off2, new_pos;
retry:
		off = vfs_llseek(file, pos, SEEK_DATA);
		if (off < 0) {
			if (off == (loff_t)-ENXIO)
				goto ondemand_read;
			return -ENODATA;
		}

		if (off >= pos + remained)
			goto ondemand_read;

		if (off > pos) {
			count = off - pos;
			goto ondemand_read;
		}

		off2 = vfs_llseek(file, pos, SEEK_HOLE);
		if (off2 < 0)
			return -ENODATA;

		new_pos = min_t(loff_t, off2, pos + remained);
		remained -= new_pos - pos;
		pos = new_pos;
		continue;
ondemand_read:
		if (again) {
			ret = cachefiles_ondemand_read(object, pos, count);
			if (!ret) {
				/* recheck if the hole has been filled or not */
				again = false;
				goto retry;
			}
		}
		return -ENODATA;
	}
	return 0;
}

struct cachefiles_kiocb {
	struct kiocb iocb;
	struct fscache_retrieval *op;
	struct iov_iter iter;
	struct work_struct work;
	struct bio_vec bvs[];
};

void cachefiles_readpages_work_func(struct work_struct *work)
{
	struct cachefiles_kiocb *ki = container_of(work, struct cachefiles_kiocb, work);
	int ret;

	ret = vfs_iocb_iter_read(ki->iocb.ki_filp, &ki->iocb, &ki->iter);
	/* complete the request if there's any progress or error occurred */
	if (ret != -EIOCBQUEUED) {
		struct fscache_retrieval *op = ki->op;
		unsigned int nr_pages = atomic_read(&op->n_pages);
		unsigned int done_pages = 0;
		int i, error;

		if (ret > 0)
			done_pages = ret / PAGE_SIZE;

		for (i = 0; i < nr_pages; i++) {
			error = i < done_pages ? 0 : -EIO;
			fscache_end_io(op, ki->bvs[i].bv_page, error);
		}

		fscache_retrieval_complete(op, nr_pages);
		fscache_put_retrieval(op);
		kfree(ki);
	}
}

int cachefiles_prepare_read(struct fscache_retrieval *op, pgoff_t index)
{
	struct cachefiles_object *object;
	struct cachefiles_kiocb *ki;
	loff_t start_pos = op->offset;
	unsigned int n, nr_pages = atomic_read(&op->n_pages);
	size_t len = nr_pages << PAGE_SHIFT;
	struct page **pages;
	struct file *file;
	size_t size;
	int i, ret;

	object = container_of(op->op.object, struct cachefiles_object, fscache);
	if (!object->backer)
		goto all_enobufs;
	file = rcu_dereference_raw(object->file);

	/*
	 * 1. Check if there's hole in the requested range, and trigger an
	 * on-demand read request if there's any.
	 */
	ASSERT(start_pos % PAGE_SIZE == 0);
	ret = cachefiles_ondemand_check(object, start_pos, len);
	if (ret)
		goto all_enobufs;

	/*
	 * 2. Trigger readahead on the backing file in advance. Since
	 * FMODE_RANDOM, the following page_cache_sync_readahead() will fallback
	 * to force_page_cache_readahead().
	 */
	page_cache_sync_readahead(d_inode(object->backer)->i_mapping,
			&file->f_ra, file, start_pos / PAGE_SIZE, nr_pages);

	size = sizeof(struct cachefiles_kiocb) + nr_pages * sizeof(struct bio_vec);
	ki = kzalloc(size, GFP_KERNEL);
	if (!ki)
		goto all_enobufs;

	/* reuse the tailing part of ki as pages[] */
	pages = (void *)ki + size - nr_pages * sizeof(struct page *);
	n = find_get_pages_contig(op->mapping, index, nr_pages, pages);
	if (WARN_ON(n != nr_pages)) {
		for (i = 0; i < n; i++)
			put_page(pages[i]);
		kfree(ki);
		goto all_enobufs;
	}

	for (i = 0; i < n; i++) {
		put_page(pages[i]);
		ki->bvs[i].bv_page = pages[i];
		ki->bvs[i].bv_offset = 0;
		ki->bvs[i].bv_len = PAGE_SIZE;
	}
	iov_iter_bvec(&ki->iter, READ, ki->bvs, n, n * PAGE_SIZE);

	ki->iocb.ki_filp	= file;
	ki->iocb.ki_pos		= start_pos;
	ki->iocb.ki_ioprio	= get_current_ioprio();
	ki->op			= fscache_get_retrieval(op);

	/* 3. Start a buffer read in worker context */
	INIT_WORK(&ki->work, cachefiles_readpages_work_func);
	queue_work(system_unbound_wq, &ki->work);
	return 0;

all_enobufs:
	fscache_retrieval_complete(op, nr_pages);
	return -ENOBUFS;
}

/*
 * allocate a block in the cache in which to store a page
 * - cache withdrawal is prevented by the caller
 * - returns -EINTR if interrupted
 * - returns -ENOMEM if ran out of memory
 * - returns -ENOBUFS if no buffers can be made available
 * - returns -ENOBUFS if page is beyond EOF
 * - otherwise:
 *   - the metadata will be retained
 *   - 0 will be returned
 */
int cachefiles_allocate_page(struct fscache_retrieval *op,
			     struct page *page,
			     gfp_t gfp)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	int ret;

	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	_enter("%p,{%lx},", object, page->index);

	ret = cachefiles_has_space(cache, 0, 1);
	if (ret == 0)
		fscache_mark_page_cached(op, page);
	else
		ret = -ENOBUFS;

	fscache_retrieval_complete(op, 1);
	_leave(" = %d", ret);
	return ret;
}

/*
 * allocate blocks in the cache in which to store a set of pages
 * - cache withdrawal is prevented by the caller
 * - returns -EINTR if interrupted
 * - returns -ENOMEM if ran out of memory
 * - returns -ENOBUFS if some buffers couldn't be made available
 * - returns -ENOBUFS if some pages are beyond EOF
 * - otherwise:
 *   - -ENODATA will be returned
 * - metadata will be retained for any page marked
 */
int cachefiles_allocate_pages(struct fscache_retrieval *op,
			      struct list_head *pages,
			      unsigned *nr_pages,
			      gfp_t gfp)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct pagevec pagevec;
	struct page *page;
	int ret;

	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	_enter("%p,,,%d,", object, *nr_pages);

	ret = cachefiles_has_space(cache, 0, *nr_pages);
	if (ret == 0) {
		pagevec_init(&pagevec);

		list_for_each_entry(page, pages, lru) {
			if (pagevec_add(&pagevec, page) == 0)
				fscache_mark_pages_cached(op, &pagevec);
		}

		if (pagevec_count(&pagevec) > 0)
			fscache_mark_pages_cached(op, &pagevec);
		ret = -ENODATA;
	} else {
		ret = -ENOBUFS;
	}

	fscache_retrieval_complete(op, *nr_pages);
	_leave(" = %d", ret);
	return ret;
}

/*
 * request a page be stored in the cache
 * - cache withdrawal is prevented by the caller
 * - this request may be ignored if there's no cache block available, in which
 *   case -ENOBUFS will be returned
 * - if the op is in progress, 0 will be returned
 */
int cachefiles_write_page(struct fscache_storage *op, struct page *page)
{
	struct cachefiles_object *object;
	struct cachefiles_cache *cache;
	struct file *file;
	struct path path;
	loff_t pos, eof;
	size_t len;
	void *data;
	int ret = -ENOBUFS;

	ASSERT(op != NULL);
	ASSERT(page != NULL);

	object = container_of(op->op.object,
			      struct cachefiles_object, fscache);

	_enter("%p,%p{%lx},,,", object, page, page->index);

	if (!object->backer) {
		_leave(" = -ENOBUFS");
		return -ENOBUFS;
	}

	ASSERT(d_is_reg(object->backer));

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	pos = (loff_t)page->index << PAGE_SHIFT;

	/* We mustn't write more data than we have, so we have to beware of a
	 * partial page at EOF.
	 */
	eof = object->fscache.store_limit_l;
	if (pos >= eof)
		goto error;

	/* write the page to the backing filesystem and let it store it in its
	 * own time */
	path.mnt = cache->mnt;
	path.dentry = object->backer;
	file = dentry_open(&path, O_RDWR | O_LARGEFILE, cache->cache_cred);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto error_2;
	}

	len = PAGE_SIZE;
	if (eof & ~PAGE_MASK) {
		if (eof - pos < PAGE_SIZE) {
			_debug("cut short %llx to %llx",
			       pos, eof);
			len = eof - pos;
			ASSERTCMP(pos + len, ==, eof);
		}
	}

	data = kmap(page);
	ret = kernel_write(file, data, len, &pos);
	kunmap(page);
	fput(file);
	if (ret != len)
		goto error_eio;

	_leave(" = 0");
	return 0;

error_eio:
	ret = -EIO;
error_2:
	if (ret == -EIO)
		cachefiles_io_error_obj(object,
					"Write page to backing file failed");
error:
	_leave(" = -ENOBUFS [%d]", ret);
	return -ENOBUFS;
}

/*
 * detach a backing block from a page
 * - cache withdrawal is prevented by the caller
 */
void cachefiles_uncache_page(struct fscache_object *_object, struct page *page)
	__releases(&object->fscache.cookie->lock)
{
	struct cachefiles_object *object;

	object = container_of(_object, struct cachefiles_object, fscache);

	_enter("%p,{%lu}", object, page->index);

	spin_unlock(&object->fscache.cookie->lock);
}
