/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_CGROUP_H
#define _BPF_CGROUP_H

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/percpu-refcount.h>
#include <linux/rbtree.h>
#include <uapi/linux/bpf.h>
#include <linux/kabi.h>

struct sock;
struct sockaddr;
struct cgroup;
struct sk_buff;
struct bpf_map;
struct bpf_prog;
struct bpf_sock_ops_kern;
struct bpf_cgroup_storage;
struct ctl_table;
struct ctl_table_header;
struct task_struct;

#ifdef CONFIG_CGROUP_BPF
enum cgroup_bpf_attach_type {
	CGROUP_BPF_ATTACH_TYPE_INVALID = -1,
	CGROUP_INET_INGRESS = 0,
	CGROUP_INET_EGRESS,
	CGROUP_INET_SOCK_CREATE,
	CGROUP_SOCK_OPS,
	CGROUP_DEVICE,
	CGROUP_INET4_BIND,
	CGROUP_INET6_BIND,
	CGROUP_INET4_CONNECT,
	CGROUP_INET6_CONNECT,
	CGROUP_INET4_POST_BIND,
	CGROUP_INET6_POST_BIND,
	CGROUP_UDP4_SENDMSG,
	CGROUP_UDP6_SENDMSG,
	CGROUP_SYSCTL,
	CGROUP_UDP4_RECVMSG,
	CGROUP_UDP6_RECVMSG,
	CGROUP_GETSOCKOPT,
	CGROUP_SETSOCKOPT,
	CGROUP_INET4_GETPEERNAME,
	CGROUP_INET6_GETPEERNAME,
	CGROUP_INET4_GETSOCKNAME,
	CGROUP_INET6_GETSOCKNAME,
	CGROUP_INET_SOCK_RELEASE,
#ifdef CONFIG_KABI_RESERVE
	CGROUP_ATTACH_TYPE_KABI_RESERVE_1,
	CGROUP_ATTACH_TYPE_KABI_RESERVE_2,
	CGROUP_ATTACH_TYPE_KABI_RESERVE_3,
	CGROUP_ATTACH_TYPE_KABI_RESERVE_4,
	CGROUP_ATTACH_TYPE_KABI_RESERVE_5,
	CGROUP_ATTACH_TYPE_KABI_RESERVE_6,
	CGROUP_ATTACH_TYPE_KABI_RESERVE_7,
	CGROUP_ATTACH_TYPE_KABI_RESERVE_8,
#endif
	MAX_CGROUP_BPF_ATTACH_TYPE
};

#define CGROUP_ATYPE(type) \
	case BPF_##type: return type

static inline enum cgroup_bpf_attach_type
to_cgroup_bpf_attach_type(enum bpf_attach_type attach_type)
{
	switch (attach_type) {
	CGROUP_ATYPE(CGROUP_INET_INGRESS);
	CGROUP_ATYPE(CGROUP_INET_EGRESS);
	CGROUP_ATYPE(CGROUP_INET_SOCK_CREATE);
	CGROUP_ATYPE(CGROUP_SOCK_OPS);
	CGROUP_ATYPE(CGROUP_DEVICE);
	CGROUP_ATYPE(CGROUP_INET4_BIND);
	CGROUP_ATYPE(CGROUP_INET6_BIND);
	CGROUP_ATYPE(CGROUP_INET4_CONNECT);
	CGROUP_ATYPE(CGROUP_INET6_CONNECT);
	CGROUP_ATYPE(CGROUP_INET4_POST_BIND);
	CGROUP_ATYPE(CGROUP_INET6_POST_BIND);
	CGROUP_ATYPE(CGROUP_UDP4_SENDMSG);
	CGROUP_ATYPE(CGROUP_UDP6_SENDMSG);
	CGROUP_ATYPE(CGROUP_SYSCTL);
	CGROUP_ATYPE(CGROUP_UDP4_RECVMSG);
	CGROUP_ATYPE(CGROUP_UDP6_RECVMSG);
	CGROUP_ATYPE(CGROUP_GETSOCKOPT);
	CGROUP_ATYPE(CGROUP_SETSOCKOPT);
	CGROUP_ATYPE(CGROUP_INET4_GETPEERNAME);
	CGROUP_ATYPE(CGROUP_INET6_GETPEERNAME);
	CGROUP_ATYPE(CGROUP_INET4_GETSOCKNAME);
	CGROUP_ATYPE(CGROUP_INET6_GETSOCKNAME);
	CGROUP_ATYPE(CGROUP_INET_SOCK_RELEASE);
	default:
		return CGROUP_BPF_ATTACH_TYPE_INVALID;
	}
}

#undef CGROUP_ATYPE

extern struct static_key_false cgroup_bpf_enabled_key[MAX_CGROUP_BPF_ATTACH_TYPE];
#define cgroup_bpf_enabled(atype) static_branch_unlikely(&cgroup_bpf_enabled_key[atype])

#define for_each_cgroup_storage_type(stype) \
	for (stype = 0; stype < MAX_BPF_CGROUP_STORAGE_TYPE; stype++)

struct bpf_cgroup_storage_map;

struct bpf_storage_buffer {
	struct rcu_head rcu;
	char data[];
};

struct bpf_cgroup_storage {
	union {
		struct bpf_storage_buffer *buf;
		void __percpu *percpu_buf;
	};
	struct bpf_cgroup_storage_map *map;
	struct bpf_cgroup_storage_key key;
	struct list_head list_map;
	struct list_head list_cg;
	struct rb_node node;
	struct rcu_head rcu;
};

struct bpf_cgroup_link {
	struct bpf_link link;
	struct cgroup *cgroup;
	enum bpf_attach_type type;
};

struct bpf_prog_list {
	struct list_head node;
	struct bpf_prog *prog;
	struct bpf_cgroup_link *link;
	struct bpf_cgroup_storage *storage[MAX_BPF_CGROUP_STORAGE_TYPE];
};

struct bpf_prog_array;

struct cgroup_bpf {
	/* array of effective progs in this cgroup */
	struct bpf_prog_array __rcu *effective[MAX_CGROUP_BPF_ATTACH_TYPE];

	/* attached progs to this cgroup and attach flags
	 * when flags == 0 or BPF_F_ALLOW_OVERRIDE the progs list will
	 * have either zero or one element
	 * when BPF_F_ALLOW_MULTI the list can have up to BPF_CGROUP_MAX_PROGS
	 */
	struct list_head progs[MAX_CGROUP_BPF_ATTACH_TYPE];
	u32 flags[MAX_CGROUP_BPF_ATTACH_TYPE];

	/* list of cgroup shared storages */
	struct list_head storages;

	/* temp storage for effective prog array used by prog_attach/detach */
	struct bpf_prog_array *inactive;

	/* reference counter used to detach bpf programs after cgroup removal */
	struct percpu_ref refcnt;

	/* cgroup_bpf is released using a work queue */
	struct work_struct release_work;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
	KABI_RESERVE(6)
	KABI_RESERVE(7)
	KABI_RESERVE(8)
	KABI_RESERVE(9)
	KABI_RESERVE(10)
	KABI_RESERVE(11)
	KABI_RESERVE(12)
	KABI_RESERVE(13)
	KABI_RESERVE(14)
	KABI_RESERVE(15)
	KABI_RESERVE(16)
};

int cgroup_bpf_inherit(struct cgroup *cgrp);
void cgroup_bpf_offline(struct cgroup *cgrp);

int __cgroup_bpf_attach(struct cgroup *cgrp,
			struct bpf_prog *prog, struct bpf_prog *replace_prog,
			struct bpf_cgroup_link *link,
			enum bpf_attach_type type, u32 flags);
int __cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
			struct bpf_cgroup_link *link,
			enum bpf_attach_type type);
int __cgroup_bpf_query(struct cgroup *cgrp, const union bpf_attr *attr,
		       union bpf_attr __user *uattr);

/* Wrapper for __cgroup_bpf_*() protected by cgroup_mutex */
int cgroup_bpf_attach(struct cgroup *cgrp,
		      struct bpf_prog *prog, struct bpf_prog *replace_prog,
		      struct bpf_cgroup_link *link, enum bpf_attach_type type,
		      u32 flags);
int cgroup_bpf_detach(struct cgroup *cgrp, struct bpf_prog *prog,
		      enum bpf_attach_type type);
int cgroup_bpf_query(struct cgroup *cgrp, const union bpf_attr *attr,
		     union bpf_attr __user *uattr);

int __cgroup_bpf_run_filter_skb(struct sock *sk,
				struct sk_buff *skb,
				enum cgroup_bpf_attach_type atype);

int __cgroup_bpf_run_filter_sk(struct sock *sk,
			       enum cgroup_bpf_attach_type atype);

int __cgroup_bpf_run_filter_sock_addr(struct sock *sk,
				      struct sockaddr *uaddr,
				      enum cgroup_bpf_attach_type atype,
				      void *t_ctx);

int __cgroup_bpf_run_filter_sock_ops(struct sock *sk,
				     struct bpf_sock_ops_kern *sock_ops,
				     enum cgroup_bpf_attach_type atype);

int __cgroup_bpf_check_dev_permission(short dev_type, u32 major, u32 minor,
				      short access, enum cgroup_bpf_attach_type atype);

int __cgroup_bpf_run_filter_sysctl(struct ctl_table_header *head,
				   struct ctl_table *table, int write,
				   char **buf, size_t *pcount, loff_t *ppos,
				   enum cgroup_bpf_attach_type atype);

int __cgroup_bpf_run_filter_setsockopt(struct sock *sock, int *level,
				       int *optname, char __user *optval,
				       int *optlen, char **kernel_optval);
int __cgroup_bpf_run_filter_getsockopt(struct sock *sk, int level,
				       int optname, char __user *optval,
				       int __user *optlen, int max_optlen,
				       int retval);

static inline enum bpf_cgroup_storage_type cgroup_storage_type(
	struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		return BPF_CGROUP_STORAGE_PERCPU;

	return BPF_CGROUP_STORAGE_SHARED;
}

struct bpf_cgroup_storage *
cgroup_storage_lookup(struct bpf_cgroup_storage_map *map,
		      void *key, bool locked);
struct bpf_cgroup_storage *bpf_cgroup_storage_alloc(struct bpf_prog *prog,
					enum bpf_cgroup_storage_type stype);
void bpf_cgroup_storage_free(struct bpf_cgroup_storage *storage);
void bpf_cgroup_storage_link(struct bpf_cgroup_storage *storage,
			     struct cgroup *cgroup,
			     enum bpf_attach_type type);
void bpf_cgroup_storage_unlink(struct bpf_cgroup_storage *storage);
int bpf_cgroup_storage_assign(struct bpf_prog_aux *aux, struct bpf_map *map);

int bpf_percpu_cgroup_storage_copy(struct bpf_map *map, void *key, void *value);
int bpf_percpu_cgroup_storage_update(struct bpf_map *map, void *key,
				     void *value, u64 flags);

/* Wrappers for __cgroup_bpf_run_filter_skb() guarded by cgroup_bpf_enabled. */
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)			      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled(CGROUP_INET_INGRESS))		      \
		__ret = __cgroup_bpf_run_filter_skb(sk, skb,		      \
						    CGROUP_INET_INGRESS); \
									      \
	__ret;								      \
})

#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_INET_EGRESS) && sk && sk == skb->sk) { \
		typeof(sk) __sk = sk_to_full_sk(sk);			       \
		if (sk_fullsock(__sk))					       \
			__ret = __cgroup_bpf_run_filter_skb(__sk, skb,	       \
						      CGROUP_INET_EGRESS); \
	}								       \
	__ret;								       \
})

#define BPF_CGROUP_RUN_SK_PROG(sk, atype)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(atype)) {					       \
		__ret = __cgroup_bpf_run_filter_sk(sk, atype);		       \
	}								       \
	__ret;								       \
})

#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET_SOCK_CREATE)

#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk)			       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET_SOCK_RELEASE)

#define BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET4_POST_BIND)

#define BPF_CGROUP_RUN_PROG_INET6_POST_BIND(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET6_POST_BIND)

#define BPF_CGROUP_RUN_SA_PROG(sk, uaddr, atype)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(atype))					       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,     \
							  NULL);	       \
	__ret;								       \
})

#define BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, atype, t_ctx)		       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(atype))	{				       \
		lock_sock(sk);						       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,     \
							  t_ctx);	       \
		release_sock(sk);					       \
	}								       \
	__ret;								       \
})

#define BPF_CGROUP_RUN_PROG_INET4_BIND_LOCK(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET4_BIND, NULL)

#define BPF_CGROUP_RUN_PROG_INET6_BIND_LOCK(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET6_BIND, NULL)

#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk)				       \
	((cgroup_bpf_enabled(CGROUP_INET4_CONNECT) ||		       \
	  cgroup_bpf_enabled(CGROUP_INET6_CONNECT)) &&		       \
	 (sk)->sk_prot->pre_connect)

#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, CGROUP_INET4_CONNECT)

#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, CGROUP_INET6_CONNECT)

#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET4_CONNECT, NULL)

#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET6_CONNECT, NULL)

#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP4_SENDMSG, t_ctx)

#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP6_SENDMSG, t_ctx)

#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP4_RECVMSG, NULL)

#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP6_RECVMSG, NULL)

/* The SOCK_OPS"_SK" macro should be used when sock_ops->sk is not a
 * fullsock and its parent fullsock cannot be traced by
 * sk_to_full_sk().
 *
 * e.g. sock_ops->sk is a request_sock and it is under syncookie mode.
 * Its listener-sk is not attached to the rsk_listener.
 * In this case, the caller holds the listener-sk (unlocked),
 * set its sock_ops->sk to req_sk, and call this SOCK_OPS"_SK" with
 * the listener-sk such that the cgroup-bpf-progs of the
 * listener-sk will be run.
 *
 * Regardless of syncookie mode or not,
 * calling bpf_setsockopt on listener-sk will not make sense anyway,
 * so passing 'sock_ops->sk == req_sk' to the bpf prog is appropriate here.
 */
#define BPF_CGROUP_RUN_PROG_SOCK_OPS_SK(sock_ops, sk)			\
({									\
	int __ret = 0;							\
	if (cgroup_bpf_enabled(CGROUP_SOCK_OPS))			\
		__ret = __cgroup_bpf_run_filter_sock_ops(sk,		\
							 sock_ops,	\
							 CGROUP_SOCK_OPS); \
	__ret;								\
})

#define BPF_CGROUP_RUN_PROG_SOCK_OPS(sock_ops)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_SOCK_OPS) && (sock_ops)->sk) {       \
		typeof(sk) __sk = sk_to_full_sk((sock_ops)->sk);	       \
		if (__sk && sk_fullsock(__sk))				       \
			__ret = __cgroup_bpf_run_filter_sock_ops(__sk,	       \
								 sock_ops,     \
							 CGROUP_SOCK_OPS); \
	}								       \
	__ret;								       \
})

#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(atype, major, minor, access)	      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled(CGROUP_DEVICE))			      \
		__ret = __cgroup_bpf_check_dev_permission(atype, major, minor, \
							  access,	      \
							  CGROUP_DEVICE); \
									      \
	__ret;								      \
})


#define BPF_CGROUP_RUN_PROG_SYSCTL(head, table, write, buf, count, pos)  \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_SYSCTL))			       \
		__ret = __cgroup_bpf_run_filter_sysctl(head, table, write,     \
						       buf, count, pos,        \
						       CGROUP_SYSCTL);     \
	__ret;								       \
})

#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock, level, optname, optval, optlen,   \
				       kernel_optval)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_SETSOCKOPT))			       \
		__ret = __cgroup_bpf_run_filter_setsockopt(sock, level,	       \
							   optname, optval,    \
							   optlen,	       \
							   kernel_optval);     \
	__ret;								       \
})

#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock, level, optname, optval, optlen,   \
				       max_optlen, retval)		       \
({									       \
	int __ret = retval;						       \
	if (cgroup_bpf_enabled(CGROUP_GETSOCKOPT))			       \
		__ret = __cgroup_bpf_run_filter_getsockopt(sock, level,	       \
							   optname, optval,    \
							   optlen, max_optlen, \
							   retval);	       \
	__ret;								       \
})

int cgroup_bpf_prog_attach(const union bpf_attr *attr,
			   enum bpf_prog_type ptype, struct bpf_prog *prog);
int cgroup_bpf_prog_detach(const union bpf_attr *attr,
			   enum bpf_prog_type ptype);
int cgroup_bpf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int cgroup_bpf_prog_query(const union bpf_attr *attr,
			  union bpf_attr __user *uattr);
#else

struct bpf_prog;
struct cgroup_bpf {};
static inline int cgroup_bpf_inherit(struct cgroup *cgrp) { return 0; }
static inline void cgroup_bpf_offline(struct cgroup *cgrp) {}

static inline int cgroup_bpf_prog_attach(const union bpf_attr *attr,
					 enum bpf_prog_type ptype,
					 struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int cgroup_bpf_prog_detach(const union bpf_attr *attr,
					 enum bpf_prog_type ptype)
{
	return -EINVAL;
}

static inline int cgroup_bpf_link_attach(const union bpf_attr *attr,
					 struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int cgroup_bpf_prog_query(const union bpf_attr *attr,
					union bpf_attr __user *uattr)
{
	return -EINVAL;
}

static inline int bpf_cgroup_storage_assign(struct bpf_prog_aux *aux,
					    struct bpf_map *map) { return 0; }
static inline struct bpf_cgroup_storage *bpf_cgroup_storage_alloc(
	struct bpf_prog *prog, enum bpf_cgroup_storage_type stype) { return NULL; }
static inline void bpf_cgroup_storage_free(
	struct bpf_cgroup_storage *storage) {}
static inline int bpf_percpu_cgroup_storage_copy(struct bpf_map *map, void *key,
						 void *value) {
	return 0;
}
static inline int bpf_percpu_cgroup_storage_update(struct bpf_map *map,
					void *key, void *value, u64 flags) {
	return 0;
}

#define cgroup_bpf_enabled(atype) (0)
#define BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, atype, t_ctx) ({ 0; })
#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk) (0)
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk,skb) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk,skb) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_BIND_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_BIND_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_POST_BIND(sk) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr) ({ 0; })
#define BPF_CGROUP_RUN_PROG_SOCK_OPS(sock_ops) ({ 0; })
#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(atype, major, minor, access) ({ 0; })
#define BPF_CGROUP_RUN_PROG_SYSCTL(head,table,write,buf,count,pos) ({ 0; })
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock, level, optname, optval, \
				       optlen, max_optlen, retval) ({ retval; })
#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock, level, optname, optval, optlen, \
				       kernel_optval) ({ 0; })

#define for_each_cgroup_storage_type(stype) for (; false; )

#endif /* CONFIG_CGROUP_BPF */

#endif /* _BPF_CGROUP_H */
