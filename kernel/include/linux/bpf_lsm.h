/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2020 Google LLC.
 */

#ifndef _LINUX_BPF_LSM_H
#define _LINUX_BPF_LSM_H

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/lsm_hooks.h>

#ifdef CONFIG_BPF_LSM

#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	RET bpf_lsm_##NAME(__VA_ARGS__);
#include <linux/lsm_hook_defs.h>
#undef LSM_HOOK

struct bpf_storage_blob {
	struct bpf_local_storage __rcu *storage;
};

extern struct lsm_blob_sizes bpf_lsm_blob_sizes;

int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
			const struct bpf_prog *prog);

static inline struct bpf_storage_blob *bpf_inode(
	const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;

	return inode->i_security + bpf_lsm_blob_sizes.lbs_inode;
}

extern const struct bpf_func_proto bpf_inode_storage_get_proto;
extern const struct bpf_func_proto bpf_inode_storage_delete_proto;
void bpf_inode_storage_free(struct inode *inode);

int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
			     struct bpf_retval_range *range);
#else /* !CONFIG_BPF_LSM */

static inline int bpf_lsm_verify_prog(struct bpf_verifier_log *vlog,
				      const struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}

static inline struct bpf_storage_blob *bpf_inode(
	const struct inode *inode)
{
	return NULL;
}

static inline void bpf_inode_storage_free(struct inode *inode)
{
}

static inline int bpf_lsm_get_retval_range(const struct bpf_prog *prog,
					   struct bpf_retval_range *range)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_BPF_LSM */

#endif /* _LINUX_BPF_LSM_H */
