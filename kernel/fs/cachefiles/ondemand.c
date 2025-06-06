// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/uio.h>
#include <linux/module.h>
#include "internal.h"

struct anon_file {
	struct file *file;
	int fd;
};

static bool cachefiles_buffered_ondemand = true;
module_param_named(buffered_ondemand, cachefiles_buffered_ondemand, bool, 0644);

static inline void cachefiles_req_put(struct cachefiles_req *req)
{
	if (refcount_dec_and_test(&req->ref))
		kfree(req);
}

static int cachefiles_ondemand_fd_release(struct inode *inode,
					  struct file *file)
{
	struct cachefiles_object *object = file->private_data;
	struct cachefiles_cache *cache;
	void **slot;
	struct radix_tree_iter iter;
	struct cachefiles_ondemand_info *info;
	int object_id;
	struct cachefiles_req *req;

	if (!object)
		return 0;

	info = object->private;
	object_id = info->ondemand_id;
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	xa_lock(&cache->reqs);
	spin_lock(&info->lock);
	info->ondemand_id = CACHEFILES_ONDEMAND_ID_CLOSED;
	cachefiles_ondemand_set_object_close(object);
	spin_unlock(&info->lock);

	/* Only flush CACHEFILES_REQ_NEW marked req to avoid race with daemon_read */
	radix_tree_for_each_tagged(slot, &cache->reqs, &iter, 0, CACHEFILES_REQ_NEW) {
		req = radix_tree_deref_slot_protected(slot,
						      &cache->reqs.xa_lock);
		if (WARN_ON(!req))
			continue;
		if (req->msg.object_id == object_id &&
		    req->msg.opcode == CACHEFILES_OP_CLOSE) {
			complete(&req->done);
			radix_tree_iter_delete(&cache->reqs, &iter, slot);
		}
	}
	xa_unlock(&cache->reqs);

	xa_lock(&cache->ondemand_ids.idr_rt);
	idr_remove(&cache->ondemand_ids, object_id);
	xa_unlock(&cache->ondemand_ids.idr_rt);
	object->fscache.cache->ops->put_object(&object->fscache,
			cachefiles_obj_put_ondemand_fd);
	cachefiles_put_unbind_pincount(cache);
	return 0;
}

static ssize_t cachefiles_ondemand_fd_write_iter(struct kiocb *kiocb,
						 struct iov_iter *iter)
{
	struct cachefiles_object *object = kiocb->ki_filp->private_data;
	struct kiocb iocb;
	struct file *file;
	ssize_t ret = 0;
	ssize_t written = 0;
	size_t bytes;

	rcu_read_lock();
	file = rcu_dereference(object->file);
	if (!file || !get_file_rcu(file))
		file = NULL;
	rcu_read_unlock();

	if (!file)
		return -ENOBUFS;

	iocb = (struct kiocb) {
		.ki_filp   = file,
		.ki_pos    = kiocb->ki_pos,
		.ki_flags  = IOCB_WRITE,
		.ki_ioprio = get_current_ioprio(),
	};

	if (!cachefiles_buffered_ondemand)
		iocb.ki_flags |= IOCB_DIRECT;
retry:
	bytes = iov_iter_count(iter);
	if (unlikely(!bytes))
		goto out;

	ret = iov_iter_fault_in_readable(iter, bytes);
	if (unlikely(ret))
		goto out;

	pagefault_disable();
	ret = vfs_iocb_iter_write(file, &iocb, iter);
	pagefault_enable();
	if (ret > 0) {
		written += ret;
		goto retry;
	} else if (ret == -EFAULT) {
		goto retry;
	}
out:
	fput(file);
	if (!ret && iov_iter_count(iter))
		return -EIO;
	return ret < 0 ? ret : written;
}

static long cachefiles_ondemand_fd_ioctl(struct file *filp, unsigned int ioctl,
					 unsigned long arg)
{
	struct cachefiles_object *object = filp->private_data;
	struct cachefiles_cache *cache;
	struct cachefiles_req *req;
	unsigned long id;

	if (ioctl != CACHEFILES_IOC_READ_COMPLETE)
		return -EINVAL;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	if (!test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags))
		return -EOPNOTSUPP;

	id = arg;
	xa_lock(&cache->reqs);
	req = radix_tree_lookup(&cache->reqs, id);
	if (!req || req->msg.opcode != CACHEFILES_OP_READ ||
	    req->object != object) {
		xa_unlock(&cache->reqs);
		return -EINVAL;
	}
	radix_tree_delete(&cache->reqs, id);
	xa_unlock(&cache->reqs);

	complete(&req->done);
	return 0;
}

static const struct file_operations cachefiles_ondemand_fd_fops = {
	.owner		= THIS_MODULE,
	.release	= cachefiles_ondemand_fd_release,
	.write_iter	= cachefiles_ondemand_fd_write_iter,
	.unlocked_ioctl	= cachefiles_ondemand_fd_ioctl,
};

/*
 * OPEN request Completion (copen)
 * - command: "copen <id>,<cache_size>"
 *   <cache_size> indicates the object size if >=0, error code if negative
 */
int cachefiles_ondemand_copen(struct cachefiles_cache *cache, char *args)
{
	struct cachefiles_req *req;
	struct fscache_cookie *cookie;
	struct cachefiles_ondemand_info *info;
	char *pid, *psize;
	unsigned long id;
	long size;
	int ret;

	if (!test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags))
		return -EOPNOTSUPP;

	if (!*args) {
		pr_err("Empty id specified\n");
		return -EINVAL;
	}

	pid = args;
	psize = strchr(args, ',');
	if (!psize) {
		pr_err("Cache size is not specified\n");
		return -EINVAL;
	}

	*psize = 0;
	psize++;

	ret = kstrtoul(pid, 0, &id);
	if (ret)
		return ret;

	xa_lock(&cache->reqs);
	req = radix_tree_lookup(&cache->reqs, id);
	if (!req || req->msg.opcode != CACHEFILES_OP_OPEN ||
	    !req->object->private->ondemand_id) {
		xa_unlock(&cache->reqs);
		return -EINVAL;
	}
	radix_tree_delete(&cache->reqs, id);
	xa_unlock(&cache->reqs);

	info = req->object->private;
	/* fail OPEN request if copen format is invalid */
	ret = kstrtol(psize, 0, &size);
	if (ret) {
		req->error = ret;
		goto out;
	}

	/* fail OPEN request if daemon reports an error */
	if (size < 0) {
		if (!IS_ERR_VALUE(size)) {
			req->error = -EINVAL;
			ret = -EINVAL;
		} else {
			req->error = size;
			ret = 0;
		}
		goto out;
	}

	spin_lock(&info->lock);
	/* The anonymous fd was closed before copen. */
	if (info->ondemand_id == CACHEFILES_ONDEMAND_ID_CLOSED) {
		spin_unlock(&info->lock);
		req->error = -EBADFD;
		goto out;
	}
	cookie = req->object->fscache.cookie;
	fscache_set_store_limit(&req->object->fscache, size);
	if (size)
		clear_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);
	else
		set_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);

	cachefiles_ondemand_set_object_open(req->object);
	spin_unlock(&info->lock);
	wake_up_all(&cache->daemon_pollwq);

out:
	spin_lock(&info->lock);
	/* Need to set object close to avoid reopen status continuing */
	if (info->ondemand_id == CACHEFILES_ONDEMAND_ID_CLOSED)
		cachefiles_ondemand_set_object_close(req->object);
	spin_unlock(&info->lock);
	complete(&req->done);
	return ret;
}

int cachefiles_ondemand_restore(struct cachefiles_cache *cache, char *args)
{
	struct cachefiles_req *req;

	XA_STATE(xas, &cache->reqs, 0);

	if (!test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags))
		return -EOPNOTSUPP;

	/*
	 * Reset the requests to CACHEFILES_REQ_NEW state, so that the
	 * requests have been processed halfway before the crash of the
	 * user daemon could be reprocessed after the recovery.
	 */
	xas_lock(&xas);
	xas_for_each(&xas, req, ULONG_MAX)
		xas_set_mark(&xas, CACHEFILES_REQ_NEW);
	xas_unlock(&xas);

	wake_up_all(&cache->daemon_pollwq);
	return 0;
}

static int cachefiles_ondemand_get_fd(struct cachefiles_req *req,
				      struct anon_file *anon_file)
{
	struct cachefiles_object *object = req->object;
	struct cachefiles_cache *cache;
	struct cachefiles_open *load;
	u32 object_id;
	int ret;

	object->fscache.cache->ops->grab_object(&object->fscache,
			cachefiles_obj_get_ondemand_fd);

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);
	idr_preload(GFP_KERNEL);
	xa_lock(&cache->ondemand_ids.idr_rt);
	ret = idr_alloc_cyclic(&cache->ondemand_ids, NULL,
			       1, INT_MAX, GFP_ATOMIC);
	xa_unlock(&cache->ondemand_ids.idr_rt);
	idr_preload_end();
	if (ret < 0)
		goto err;
	object_id = ret;

	anon_file->fd = get_unused_fd_flags(O_WRONLY);
	if (anon_file->fd < 0) {
		ret = anon_file->fd;
		goto err_free_id;
	}

	anon_file->file = anon_inode_getfile("[cachefiles]",
				&cachefiles_ondemand_fd_fops, object, O_WRONLY);
	if (IS_ERR(anon_file->file)) {
		ret = PTR_ERR(anon_file->file);
		goto err_put_fd;
	}

	spin_lock(&object->private->lock);
	if (object->private->ondemand_id > 0) {
		spin_unlock(&object->private->lock);
		ret = -EEXIST;
		anon_file->file->private_data = NULL;
		goto err_put_file;
	}

	anon_file->file->f_mode |= FMODE_PWRITE | FMODE_LSEEK;

	load = (void *)req->msg.data;
	load->fd = anon_file->fd;
	object->private->ondemand_id = object_id;
	spin_unlock(&object->private->lock);

	cachefiles_get_unbind_pincount(cache);
	return 0;

err_put_file:
	fput(anon_file->file);
	anon_file->file = NULL;
err_put_fd:
	put_unused_fd(anon_file->fd);
	anon_file->fd = ret;
err_free_id:
	xa_lock(&cache->ondemand_ids.idr_rt);
	idr_remove(&cache->ondemand_ids, object_id);
	xa_unlock(&cache->ondemand_ids.idr_rt);
err:
	spin_lock(&req->object->private->lock);
	/* Avoid marking an opened object as closed. */
	if (object->private->ondemand_id <= 0)
		cachefiles_ondemand_set_object_close(req->object);
	spin_unlock(&req->object->private->lock);

	object->fscache.cache->ops->put_object(&object->fscache,
			cachefiles_obj_put_ondemand_fd);
	return ret;
}

static void ondemand_object_worker(struct work_struct *work)
{
	struct cachefiles_object *object;

	object = ((struct cachefiles_ondemand_info *)work)->object;
	cachefiles_ondemand_init_object(object);
}

/*
 * Find a request to be handled in the range of [start, end].  If there are any
 * inflight or subsequent READ requests on the closed object, reopen it.  Skip
 * read requests whose related object is reopening.
 */
static struct cachefiles_req *cachefiles_ondemand_select_req(struct cachefiles_cache *cache,
							     struct radix_tree_iter *iter,
							     unsigned long start,
							     unsigned long end)
{
	void **slot;
	struct cachefiles_req *req;
	struct cachefiles_ondemand_info *info;

	radix_tree_for_each_tagged(slot, &cache->reqs, iter, start, CACHEFILES_REQ_NEW) {
		req = radix_tree_deref_slot_protected(slot, &cache->reqs.xa_lock);
		if (WARN_ON(!req))
			return NULL;
		if (iter->index > end)
			return NULL;
		if (req->msg.opcode != CACHEFILES_OP_READ)
			return req;
		info = req->object->private;
		if (cachefiles_ondemand_object_is_close(req->object)) {
			cachefiles_ondemand_set_object_reopening(req->object);
			queue_work(fscache_object_wq, &info->work);
			continue;
		} else if (cachefiles_ondemand_object_is_reopening(req->object)) {
			continue;
		}
		return req;
	}
	return NULL;
}

ssize_t cachefiles_ondemand_daemon_read(struct cachefiles_cache *cache,
					char __user *_buffer, size_t buflen, loff_t *pos)
{
	struct cachefiles_req *req;
	struct cachefiles_msg *msg;
	unsigned long id = 0;
	size_t n;
	int ret = 0;
	struct radix_tree_iter iter;
	struct anon_file anon_file;

	/*
	 * Cyclically search for a request that has not ever been processed,
	 * to prevent requests from being processed repeatedly, and make
	 * request distribution fair.
	 */
	xa_lock(&cache->reqs);
	req = cachefiles_ondemand_select_req(cache, &iter, cache->req_id_next, ULONG_MAX);
	if (!req && cache->req_id_next > 0)
		req = cachefiles_ondemand_select_req(cache, &iter, 0, cache->req_id_next - 1);
	if (!req) {
		xa_unlock(&cache->reqs);
		return 0;
	}

	msg = &req->msg;
	n = msg->len;

	if (n > buflen) {
		xa_unlock(&cache->reqs);
		return -EMSGSIZE;
	}

	radix_tree_iter_tag_clear(&cache->reqs, &iter, CACHEFILES_REQ_NEW);
	cache->req_id_next = iter.index + 1;
	refcount_inc(&req->ref);
	req->object->fscache.cache->ops->grab_object(&req->object->fscache,
			cachefiles_obj_get_read_req);
	xa_unlock(&cache->reqs);

	id = iter.index;

	if (msg->opcode == CACHEFILES_OP_OPEN) {
		ret = cachefiles_ondemand_get_fd(req, &anon_file);
		if (ret)
			goto out;
	}

	msg->msg_id = id;
	msg->object_id = req->object->private->ondemand_id;

	if (copy_to_user(_buffer, msg, n) != 0)
		ret = -EFAULT;

	if (msg->opcode == CACHEFILES_OP_OPEN) {
		if (ret < 0) {
			fput(anon_file.file);
			put_unused_fd(anon_file.fd);
			goto out;
		}
		fd_install(anon_file.fd, anon_file.file);
	}

out:
	req->object->fscache.cache->ops->put_object(&req->object->fscache,
			cachefiles_obj_put_read_req);
	/* Remove error request and CLOSE request has no reply */
	if (ret || msg->opcode == CACHEFILES_OP_CLOSE) {
		xa_lock(&cache->reqs);
		if (radix_tree_lookup(&cache->reqs, id) == req) {
			req->error = ret;
			complete(&req->done);
			radix_tree_delete(&cache->reqs, id);
		}
		xa_unlock(&cache->reqs);
	}
	cachefiles_req_put(req);
	return ret ? ret : n;
}

typedef int (*init_req_fn)(struct cachefiles_req *req, void *private);

static int cachefiles_ondemand_send_req(struct cachefiles_object *object,
					enum cachefiles_opcode opcode,
					size_t data_len,
					init_req_fn init_req,
					void *private)
{
	static atomic64_t global_index = ATOMIC64_INIT(0);
	struct cachefiles_cache *cache;
	struct cachefiles_req *req = NULL;
	long id;
	int ret;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	if (!test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags))
		return 0;

	if (test_bit(CACHEFILES_DEAD, &cache->flags)) {
		ret = -EIO;
		goto out;
	}

	req = kzalloc(sizeof(*req) + data_len, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out;
	}

	refcount_set(&req->ref, 1);
	req->object = object;
	init_completion(&req->done);
	req->msg.opcode = opcode;
	req->msg.len = sizeof(struct cachefiles_msg) + data_len;

	ret = init_req(req, private);
	if (ret)
		goto out;

	/*
	 * Stop enqueuing the request when daemon is dying. The
	 * following two operations need to be atomic as a whole.
	 *   1) check cache state, and
	 *   2) enqueue request if cache is alive.
	 * Otherwise the request may be enqueued after xarray has been
	 * flushed, leaving the orphan request never being completed.
	 *
	 * CPU 1			CPU 2
	 * =====			=====
	 *				test CACHEFILES_DEAD bit
	 * set CACHEFILES_DEAD bit
	 * flush requests in the xarray
	 *				enqueue the request
	 */
	xa_lock(&cache->reqs);

	if (test_bit(CACHEFILES_DEAD, &cache->flags) ||
	    cachefiles_ondemand_object_is_dropping(object)) {
		xa_unlock(&cache->reqs);
		ret = -EIO;
		goto out;
	}

	/* coupled with the barrier in cachefiles_flush_reqs() */
	smp_mb();
	if (opcode == CACHEFILES_OP_CLOSE &&
		!cachefiles_ondemand_object_is_open(object)) {
		WARN_ON_ONCE(object->private->ondemand_id == 0);
		xa_unlock(&cache->reqs);
		ret = -EIO;
		goto out;
	}

	do {
		id = atomic64_inc_return(&global_index);
		if (unlikely(id == UINT_MAX))
			atomic64_set(&global_index, 0);
	} while (radix_tree_insert(&cache->reqs, id, req));

	radix_tree_tag_set(&cache->reqs, id, CACHEFILES_REQ_NEW);
	xa_unlock(&cache->reqs);

	wake_up_all(&cache->daemon_pollwq);
wait:
	ret = wait_for_completion_killable(&req->done);
	if (!ret) {
		ret = req->error;
	} else {
		xa_lock(&cache->reqs);
		if (radix_tree_lookup(&cache->reqs, id) == req) {
			radix_tree_delete(&cache->reqs, id);
			ret = -EINTR;
		}
		xa_unlock(&cache->reqs);

		/* Someone will complete it soon. */
		if (ret != -EINTR) {
			cpu_relax();
			goto wait;
		}
	}
	cachefiles_req_put(req);
	return ret;
out:
	/* Reset the object to close state in error handling path.
	 * If error occurs after creating the anonymous fd,
	 * cachefiles_ondemand_fd_release() will set object to close.
	 */
	if (opcode == CACHEFILES_OP_OPEN &&
	    !cachefiles_ondemand_object_is_dropping(object))
		cachefiles_ondemand_set_object_close(object);
	kfree(req);
	return ret;
}

static int cachefiles_ondemand_init_open_req(struct cachefiles_req *req,
					     void *private)
{
	struct cachefiles_object *object = req->object;
	struct fscache_cookie *cookie = object->fscache.cookie;
	struct fscache_cookie *volume = object->fscache.parent->cookie;
	struct cachefiles_open *load = (void *)req->msg.data;
	size_t volume_key_size, cookie_key_size;
	char *cookie_key, *volume_key;

	/*
	 * cookie_key is a string without trailing '\0', while cachefiles_open
	 * expects cookie key a string without trailing '\0'.
	 */
	cookie_key_size = cookie->key_len;
	if (cookie->key_len <= sizeof(cookie->inline_key))
		cookie_key = cookie->inline_key;
	else
		cookie_key = cookie->key;

	/*
	 * volume_key is a string without trailing '\0', while cachefiles_open
	 * expects volume key a string with trailing '\0'.
	 */
	volume_key_size = volume->key_len + 1;
	if (volume->key_len <= sizeof(volume->inline_key))
		volume_key = volume->inline_key;
	else
		volume_key = volume->key;

	load->volume_key_size = volume_key_size;
	load->cookie_key_size = cookie_key_size;
	memcpy(load->data, volume_key, volume->key_len);
	load->data[volume_key_size - 1] = '\0';
	memcpy(load->data + volume_key_size, cookie_key, cookie_key_size);
	return 0;
}

static int cachefiles_ondemand_init_close_req(struct cachefiles_req *req,
					      void *private)
{
	struct cachefiles_object *object = req->object;

	if (!cachefiles_ondemand_object_is_open(object))
		return -ENOENT;
	return 0;
}

struct cachefiles_read_ctx {
	loff_t off;
	size_t len;
};

static int cachefiles_ondemand_init_read_req(struct cachefiles_req *req,
					     void *private)
{
	struct cachefiles_read *load = (void *)req->msg.data;
	struct cachefiles_read_ctx *read_ctx = private;

	load->off = read_ctx->off;
	load->len = read_ctx->len;
	return 0;
}

int cachefiles_ondemand_init_object(struct cachefiles_object *object)
{
	struct fscache_cookie *cookie = object->fscache.cookie;
	size_t volume_key_size, cookie_key_size, data_len;

	if (!object->private)
		return 0;

	/*
	 * CacheFiles will firstly check the cache file under the root cache
	 * directory. If the coherency check failed, it will fallback to
	 * creating a new tmpfile as the cache file. Reuse the previously
	 * allocated object ID if any.
	 */
	if (cachefiles_ondemand_object_is_open(object) ||
		object->type == FSCACHE_COOKIE_TYPE_INDEX)
		return 0;

	volume_key_size = object->fscache.parent->cookie->key_len + 1;
	cookie_key_size = cookie->key_len;
	data_len = sizeof(struct cachefiles_open) + volume_key_size + cookie_key_size;

	return cachefiles_ondemand_send_req(object, CACHEFILES_OP_OPEN,
			data_len, cachefiles_ondemand_init_open_req, NULL);
}

void cachefiles_ondemand_clean_object(struct cachefiles_object *object)
{
	void **slot;
	struct cachefiles_req *req;
	struct radix_tree_iter iter;
	struct cachefiles_cache *cache;

	if (!object->private)
		return;

	cachefiles_ondemand_send_req(object, CACHEFILES_OP_CLOSE, 0,
			cachefiles_ondemand_init_close_req, NULL);

	if (!object->private->ondemand_id)
		return;

	/* Flush all requests for the object that is being dropped. */
	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);
	xa_lock(&cache->reqs);
	cachefiles_ondemand_set_object_dropping(object);
	radix_tree_for_each_slot(slot, &cache->reqs, &iter, 0) {
		req = radix_tree_deref_slot_protected(slot,
						      &cache->reqs.xa_lock);
		if (WARN_ON(!req))
			continue;
		if (req->object == object) {
			req->error = -EIO;
			complete(&req->done);
			radix_tree_delete(&cache->reqs, iter.index);
		}
	}
	xa_unlock(&cache->reqs);

	/* Wait for ondemand_object_worker() to finish. */
	cancel_work_sync(&object->private->work);
}

int cachefiles_ondemand_read(struct cachefiles_object *object,
			     loff_t pos, size_t len)
{
	struct cachefiles_read_ctx read_ctx = {pos, len};

	return cachefiles_ondemand_send_req(object, CACHEFILES_OP_READ,
			sizeof(struct cachefiles_read),
			cachefiles_ondemand_init_read_req, &read_ctx);
}

int cachefiles_ondemand_init_obj_info(struct cachefiles_object *object)
{
	struct cachefiles_cache *cache;

	cache = container_of(object->fscache.cache, struct cachefiles_cache, cache);
	if (!cachefiles_in_ondemand_mode(cache))
		return 0;

	object->private = kzalloc(sizeof(struct cachefiles_ondemand_info), GFP_KERNEL);
	if (!object->private)
		return -ENOMEM;

	object->private->object = object;
	spin_lock_init(&object->private->lock);
	INIT_WORK(&object->private->work, ondemand_object_worker);
	return 0;
}
