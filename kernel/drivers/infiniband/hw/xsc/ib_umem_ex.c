// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/sched/mm.h>
#include <rdma/ib_verbs.h>

#include "ib_umem_ex.h"
#ifndef CONFIG_INFINIBAND_PEER_MEMORY
#include "ib_peer_mem.h"
#endif

struct ib_umem_ex *ib_umem_ex(struct ib_umem *umem)
{
	struct ib_umem_ex *ret_umem;

	if (!umem)
		return ERR_PTR(-EINVAL);

#ifdef CONFIG_INFINIBAND_PEER_MEMORY
	ret_umem = (struct ib_umem_ex *)umem;
#else
	ret_umem =  kzalloc(sizeof(*ret_umem), GFP_KERNEL);
	if (!ret_umem)
		return ERR_PTR(-ENOMEM);

	ret_umem->umem = *umem;
	kfree(umem);
#endif

	return ret_umem;
}

struct ib_umem_ex *ib_client_umem_get(struct ib_ucontext *context,
				      unsigned long addr,
				      size_t size, int access,
				      int dmasync, u8 *peer_exists)
{
	return NULL;
}

void ib_umem_ex_release(struct ib_umem_ex *umem_ex)
{
	struct ib_umem *umem = (struct ib_umem *)umem_ex;
	ib_umem_release(umem);
}

int ib_client_umem_activate_invalidation_notifier(struct ib_umem_ex *umem_ex,
						  umem_invalidate_func_t func,
						  void *cookie)
{
	return 0;
}

