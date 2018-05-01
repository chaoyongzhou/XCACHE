/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include "cmpic.inc"

#include "type.h"
#include "cmisc.h"

#include "mm.h"
#include "log.h"
#include "debug.h"

#include "clist.h"
#include "cvector.h"

#include "mod.h"
#include "rank.h"

#include "tcnode.h"

#include "task.h"

#include "super.h"

/*global variables*/

/*supported MOD_MGR_LDB table*/
static MOD_MGR_LDB g_mod_mgr_ldb[ ]  =
{
    {
        LOAD_BALANCING_LOOP,
        mod_mgr_ldb_loop_get,
    },
    {
        LOAD_BALANCING_MOD,
        mod_mgr_ldb_mod_get,
    },
    {
        LOAD_BALANCING_QUE,
        mod_mgr_ldb_que_get,
    },
    {
        LOAD_BALANCING_OBJ,
        mod_mgr_ldb_obj_get,
    },
    {
        LOAD_BALANCING_CPU,
        mod_mgr_ldb_cpu_get,
    },
    {
        LOAD_BALANCING_MEM,
        mod_mgr_ldb_mem_get,
    },
    {
        LOAD_BALANCING_DSK,
        mod_mgr_ldb_dsk_get,
    },
    {
        LOAD_BALANCING_NET,
        mod_mgr_ldb_net_get,
    },
};

/*---------------------------------------- interface of MOD_NODE ----------------------------------------------*/
EC_BOOL mod_node_alloc(MOD_NODE **mod_node)
{
    alloc_static_mem(MM_MOD_NODE, mod_node, LOC_MOD_0001);
    return (EC_TRUE);
}

MOD_NODE *mod_node_new()
{
    MOD_NODE *mod_node;

    alloc_static_mem(MM_MOD_NODE, &mod_node, LOC_MOD_0002);
    mod_node_init(mod_node);
    return (mod_node);
}

STATIC_CAST static MOD_NODE *mod_node_alloc_0()
{
    MOD_NODE *mod_node;

    alloc_static_mem(MM_MOD_NODE, &mod_node, LOC_MOD_0003);
    return (mod_node);
}

EC_BOOL mod_node_clean(MOD_NODE *mod_node)
{
    if(NULL_PTR != mod_node)
    {
        MOD_NODE_TCID(mod_node) = CMPI_ANY_TCID;
        MOD_NODE_COMM(mod_node) = CMPI_COMM_NULL;
        MOD_NODE_RANK(mod_node) = CMPI_ANY_RANK;
        MOD_NODE_MODI(mod_node) = CMPI_ERROR_MODI;
        MOD_NODE_HOPS(mod_node) = 0;
        MOD_NODE_LOAD(mod_node) = 0;
        MOD_NODE_STAT(mod_node) = 0;
        cload_stat_init(MOD_NODE_CLOAD_STAT(mod_node));
    }

    return (EC_TRUE);
}

EC_BOOL mod_node_free(MOD_NODE *mod_node)
{
    mod_node_clean(mod_node);
    free_static_mem(MM_MOD_NODE, mod_node, LOC_MOD_0004);
    return (EC_TRUE);
}

EC_BOOL mod_node_init(MOD_NODE *mod_node)
{
    if(NULL_PTR != mod_node)
    {
        MOD_NODE_TCID(mod_node) = CMPI_ANY_TCID;
        MOD_NODE_COMM(mod_node) = CMPI_COMM_NULL;
        MOD_NODE_RANK(mod_node) = CMPI_ANY_RANK;
        MOD_NODE_MODI(mod_node) = CMPI_ERROR_MODI;
        MOD_NODE_HOPS(mod_node) = 0;
        MOD_NODE_LOAD(mod_node) = 0;
        MOD_NODE_STAT(mod_node) = 0;
        cload_stat_init(MOD_NODE_CLOAD_STAT(mod_node));
    }

    return (EC_TRUE);
}

EC_BOOL mod_node_clone(const MOD_NODE *src_mod_node, MOD_NODE *des_mod_node)
{
    if(NULL_PTR != des_mod_node && NULL_PTR != src_mod_node)
    {
        MOD_NODE_TCID(des_mod_node) = MOD_NODE_TCID(src_mod_node);
        MOD_NODE_COMM(des_mod_node) = MOD_NODE_COMM(src_mod_node);
        MOD_NODE_RANK(des_mod_node) = MOD_NODE_RANK(src_mod_node);
        MOD_NODE_MODI(des_mod_node) = MOD_NODE_MODI(src_mod_node);
        MOD_NODE_HOPS(des_mod_node) = MOD_NODE_HOPS(src_mod_node);
        MOD_NODE_LOAD(des_mod_node) = MOD_NODE_LOAD(src_mod_node);
        MOD_NODE_STAT(des_mod_node) = MOD_NODE_STAT(src_mod_node);

        cload_stat_clone(MOD_NODE_CLOAD_STAT(src_mod_node), MOD_NODE_CLOAD_STAT(des_mod_node));
    }
    return (EC_TRUE);
}

EC_BOOL mod_node_is_local(const MOD_NODE *mod_node)
{
    if(
       CMPI_LOCAL_TCID == MOD_NODE_TCID(mod_node)
    && CMPI_LOCAL_COMM == MOD_NODE_COMM(mod_node)
    && CMPI_LOCAL_RANK == MOD_NODE_RANK(mod_node)
    )
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_update_local_stat(MOD_NODE *mod_node)
{
    if(EC_TRUE == mod_node_is_local(mod_node))
    {
        TASK_BRD *task_brd;
        task_brd = task_brd_default_get();
        cload_stat_clone(TASK_BRD_CLOAD_STAT(task_brd), MOD_NODE_CLOAD_STAT(mod_node));
    }
    return (EC_TRUE);
}

EC_BOOL mod_node_cmp(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    if(
        (CMPI_ANY_TCID == MOD_NODE_TCID(src_mod_node_1) || CMPI_ANY_TCID == MOD_NODE_TCID(src_mod_node_2) || MOD_NODE_TCID(src_mod_node_1) == MOD_NODE_TCID(src_mod_node_2))
     && (CMPI_ANY_COMM == MOD_NODE_COMM(src_mod_node_1) || CMPI_ANY_COMM == MOD_NODE_COMM(src_mod_node_2) || MOD_NODE_COMM(src_mod_node_1) == MOD_NODE_COMM(src_mod_node_2))
     && (CMPI_ANY_RANK == MOD_NODE_RANK(src_mod_node_1) || CMPI_ANY_RANK == MOD_NODE_RANK(src_mod_node_2) || MOD_NODE_RANK(src_mod_node_1) == MOD_NODE_RANK(src_mod_node_2))
     && (CMPI_ANY_MODI == MOD_NODE_MODI(src_mod_node_1) || CMPI_ANY_MODI == MOD_NODE_MODI(src_mod_node_2) || MOD_NODE_MODI(src_mod_node_1) == MOD_NODE_MODI(src_mod_node_2))
     )
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_gt_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    if(MOD_NODE_HOPS(src_mod_node_1) > MOD_NODE_HOPS(src_mod_node_2))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_ge_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    if(MOD_NODE_HOPS(src_mod_node_1) >= MOD_NODE_HOPS(src_mod_node_2))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_lt_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    if(MOD_NODE_HOPS(src_mod_node_1) < MOD_NODE_HOPS(src_mod_node_2))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_le_hops(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    if(MOD_NODE_HOPS(src_mod_node_1) <= MOD_NODE_HOPS(src_mod_node_2))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_gt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_ge_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL mod_node_vote_lt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_le_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_gt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_ge_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL mod_node_vote_lt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_le_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_gt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_ge_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL mod_node_vote_lt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_le_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_gt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_ge_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL mod_node_vote_lt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_le_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_gt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_ge_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL mod_node_vote_lt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_le_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL mod_node_vote_gt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_ge_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL mod_node_vote_lt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_vote_le_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}



void mod_node_print(LOG *log, const MOD_NODE *mod_node)
{
    const CLOAD_STAT *cload_stat;

    cload_stat = MOD_NODE_CLOAD_STAT(mod_node);
    sys_print(log, "tcid %s, comm %ld, rank %ld, modi %ld, hops %ld, stat %ld, load (que %d, obj %d, cpu %d, mem %d, dsk %d, net %d)\n",
                    MOD_NODE_TCID_STR(mod_node),
                    MOD_NODE_COMM(mod_node),
                    MOD_NODE_RANK(mod_node),
                    MOD_NODE_MODI(mod_node),
                    MOD_NODE_HOPS(mod_node),
                    MOD_NODE_STAT(mod_node),
                    CLOAD_STAT_QUE_LOAD(cload_stat),
                    CLOAD_STAT_OBJ_LOAD(cload_stat),
                    CLOAD_STAT_CPU_LOAD(cload_stat),
                    CLOAD_STAT_MEM_LOAD(cload_stat),
                    CLOAD_STAT_DSK_LOAD(cload_stat),
                    CLOAD_STAT_NET_LOAD(cload_stat)
                    );
    return;
}

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_que(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_que(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_obj(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_obj(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_cpu(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_cpu(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_mem(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_mem(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_dsk(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_dsk(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 < src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_lt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st < load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 <= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_le_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st <= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 > src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_gt_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st > load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*as the algo described below, when src_mod_node_1 >= src_mod_node_2, return EC_TRUE, otherwise return EC_FALSE*/
EC_BOOL mod_node_ge_net(const MOD_NODE *src_mod_node_1, const MOD_NODE *src_mod_node_2)
{
    UINT32 load_1st;
    UINT32 load_2nd;

    load_1st = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_1), MOD_NODE_RANK(src_mod_node_1));
    load_2nd = task_brd_rank_load_tbl_get_net(task_brd_default_get(), MOD_NODE_TCID(src_mod_node_2), MOD_NODE_RANK(src_mod_node_2));

    if(load_1st >= load_2nd)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_tcid_filter(const MOD_NODE *mod_node, const UINT32 tcid)
{
    if(tcid == MOD_NODE_TCID(mod_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_rank_filter(const MOD_NODE *mod_node, const UINT32 rank)
{
    if(rank == MOD_NODE_RANK(mod_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_modi_filter(const MOD_NODE *mod_node, const UINT32 modi)
{
    if(modi == MOD_NODE_MODI(mod_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_tcid_excl_filter(const MOD_NODE *mod_node, const UINT32 tcid)
{
    if(tcid != MOD_NODE_TCID(mod_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_rank_excl_filter(const MOD_NODE *mod_node, const UINT32 rank)
{
    if(rank != MOD_NODE_RANK(mod_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_node_modi_excl_filter(const MOD_NODE *mod_node, const UINT32 modi)
{
    if(modi != MOD_NODE_MODI(mod_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*---------------------------------------- interface of MOD_MGR ----------------------------------------------*/
EC_BOOL mod_mgr_init(MOD_MGR * mod_mgr)
{
    MOD_MGR_LDB_CHOICE(mod_mgr) = LOAD_BALANCING_END;

    mod_node_init(MOD_MGR_LOCAL_MOD(mod_mgr));

    cvector_init(MOD_MGR_REMOTE_LIST(mod_mgr), 0, MM_MOD_NODE, CVECTOR_LOCK_ENABLE, LOC_MOD_0005);
    MOD_MGR_REMOTE_POS(mod_mgr) = 0;

    MOD_MGR_LOCAL_MOD_POS(mod_mgr) = CVECTOR_ERR_POS;

    return (EC_TRUE);
}

MOD_MGR * mod_mgr_new(const UINT32 local_md_id, const UINT32 load_balancing_choice)
{
    TASK_BRD *task_brd;
    MOD_MGR *mod_mgr;

    alloc_static_mem(MM_MOD_MGR, &mod_mgr, LOC_MOD_0006);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    task_brd = task_brd_default_get();
    mod_mgr_init(mod_mgr);

    mod_mgr_set_local_mod(mod_mgr, local_md_id);
    mod_mgr_set_load_balancing(mod_mgr, load_balancing_choice);

    task_brd_mod_mgr_add(task_brd, mod_mgr);

    return (mod_mgr);
}

/*trick! used by creg*/
EC_BOOL mod_mgr_free(MOD_MGR *mod_mgr)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    if(EC_TRUE == task_brd_mod_mgr_rmv(task_brd, mod_mgr))
    {
        mod_mgr_clean(mod_mgr);
        free_static_mem(MM_MOD_MGR, mod_mgr, LOC_MOD_0007);
    }
    return (EC_TRUE);
}

EC_BOOL mod_mgr_clean(MOD_MGR * mod_mgr)
{
    CVECTOR *remote_mod_node_list;

    remote_mod_node_list = MOD_MGR_REMOTE_LIST(mod_mgr);
    cvector_clean(remote_mod_node_list, (CLIST_DATA_DATA_CLEANER)mod_node_free, LOC_MOD_0008);
    MOD_MGR_REMOTE_POS(mod_mgr) = 0;
    MOD_MGR_LOCAL_MOD_POS(mod_mgr) = CVECTOR_ERR_POS;

    return (EC_TRUE);
}

EC_BOOL mod_mgr_set_local_mod(MOD_MGR * mod_mgr, const UINT32 local_md_id)
{
    if(NULL_PTR != mod_mgr)
    {
        MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(mod_mgr)) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(mod_mgr)) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(mod_mgr)) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(mod_mgr)) = local_md_id;
        MOD_NODE_LOAD(MOD_MGR_LOCAL_MOD(mod_mgr)) = 0;
        MOD_NODE_STAT(MOD_MGR_LOCAL_MOD(mod_mgr)) = 0;
        cload_stat_init(MOD_NODE_CLOAD_STAT(MOD_MGR_LOCAL_MOD(mod_mgr)));

        MOD_MGR_LOCAL_MOD_POS(mod_mgr) = CVECTOR_ERR_POS;
    }

    return (EC_TRUE);
}

EC_BOOL mod_mgr_set_load_balancing(MOD_MGR * mod_mgr, const UINT32 load_balancing_choice)
{
    if(NULL_PTR != mod_mgr)
    {
        MOD_MGR_LDB *mod_mgr_ldb;

        MOD_MGR_LDB_CHOICE(mod_mgr) = load_balancing_choice;
        mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(mod_mgr)); /*initialize the function pointer*/
        if(NULL_PTR == mod_mgr_ldb)
        {
            dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_set_load_balancing: "
                                                 "invalid load balancing strategy %ld\n",
                                                 MOD_MGR_LDB_CHOICE(mod_mgr));
            return (EC_FALSE);
        }
        MOD_MGR_LDB_FUNCPTR(mod_mgr) = mod_mgr_ldb->get;
    }

    return (EC_TRUE);
}

/*clone limited part, but not the whole, of mod_mgr*/
EC_BOOL mod_mgr_limited_clone(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, MOD_MGR *des_mod_mgr)
{
    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;

    MOD_MGR_LDB *mod_mgr_ldb;
    //MOD_NODE *mod_node;

    this_tcid = CMPI_LOCAL_TCID;
    this_comm = CMPI_LOCAL_COMM;
    this_rank = CMPI_LOCAL_RANK;

    /*clone MOD_MGR_LDB*/
    MOD_MGR_LDB_CHOICE(des_mod_mgr) = MOD_MGR_LDB_CHOICE(src_mod_mgr);
    mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(des_mod_mgr)); /*initialize the function pointer*/
    if(NULL_PTR == mod_mgr_ldb)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_limited_clone: invalid load balancing strategy %ld\n", MOD_MGR_LDB_CHOICE(des_mod_mgr));
        return (EC_FALSE);
    }
    MOD_MGR_LDB_FUNCPTR(des_mod_mgr) = mod_mgr_ldb->get;

    /*clone local mod node*/
    MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_tcid;
    MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_comm;
    MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_rank;
    MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = mod_id;

    /*clone remote mod node list*/
    cvector_clone(MOD_MGR_REMOTE_LIST(src_mod_mgr), MOD_MGR_REMOTE_LIST(des_mod_mgr), (CVECTOR_DATA_MALLOC)mod_node_alloc_0, (CVECTOR_DATA_CLONE)mod_node_clone);
    MOD_MGR_REMOTE_POS(des_mod_mgr) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(des_mod_mgr) = cvector_search_front(MOD_MGR_REMOTE_LIST(des_mod_mgr), MOD_MGR_LOCAL_MOD(des_mod_mgr), (CVECTOR_DATA_CMP)mod_node_cmp);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_limited_clone_with_tcid_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;

    MOD_MGR_LDB *mod_mgr_ldb;

    this_tcid = CMPI_LOCAL_TCID;
    this_comm = CMPI_LOCAL_COMM;
    this_rank = CMPI_LOCAL_RANK;/*here rank should get in current process!!!*/

    /*clone MOD_MGR_LDB*/
    MOD_MGR_LDB_CHOICE(des_mod_mgr) = MOD_MGR_LDB_CHOICE(src_mod_mgr);
    mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(des_mod_mgr)); /*initialize the function pointer*/
    if(NULL_PTR == mod_mgr_ldb)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_limited_clone_with_tcid_filter: invalid load balancing strategy %ld\n", MOD_MGR_LDB_CHOICE(des_mod_mgr));
        return (EC_FALSE);
    }
    MOD_MGR_LDB_FUNCPTR(des_mod_mgr) = mod_mgr_ldb->get;

    /*clone local mod node*/
    MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_tcid;
    MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_comm;
    MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_rank;
    MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = mod_id;

    /*clone remote mod node list with tcid filter*/
    mod_mgr_remote_mod_node_clone_with_tcid_filter(src_mod_mgr, tcid_vec, des_mod_mgr);
    MOD_MGR_REMOTE_POS(des_mod_mgr) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(des_mod_mgr) = cvector_search_front(MOD_MGR_REMOTE_LIST(des_mod_mgr), MOD_MGR_LOCAL_MOD(des_mod_mgr), (CVECTOR_DATA_CMP)mod_node_cmp);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_limited_clone_with_rank_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;

    MOD_MGR_LDB *mod_mgr_ldb;

    this_tcid = CMPI_LOCAL_TCID;
    this_comm = CMPI_LOCAL_COMM;
    this_rank = CMPI_LOCAL_RANK;

    /*clone MOD_MGR_LDB*/
    MOD_MGR_LDB_CHOICE(des_mod_mgr) = MOD_MGR_LDB_CHOICE(src_mod_mgr);
    mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(des_mod_mgr)); /*initialize the function pointer*/
    if(NULL_PTR == mod_mgr_ldb)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_limited_clone_with_rank_filter: invalid load balancing strategy %ld\n", MOD_MGR_LDB_CHOICE(des_mod_mgr));
        return (EC_FALSE);
    }
    MOD_MGR_LDB_FUNCPTR(des_mod_mgr) = mod_mgr_ldb->get;

    /*clone local mod node*/
    MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_tcid;
    MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_comm;
    MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_rank;
    MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = mod_id;

    /*clone remote mod node list with rank filter*/
    mod_mgr_remote_mod_node_clone_with_rank_filter(src_mod_mgr, rank_vec, des_mod_mgr);
    MOD_MGR_REMOTE_POS(des_mod_mgr) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(des_mod_mgr) = cvector_search_front(MOD_MGR_REMOTE_LIST(des_mod_mgr), MOD_MGR_LOCAL_MOD(des_mod_mgr), (CVECTOR_DATA_CMP)mod_node_cmp);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_limited_clone_with_modi_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;

    MOD_MGR_LDB *mod_mgr_ldb;

    this_tcid = CMPI_LOCAL_TCID;
    this_comm = CMPI_LOCAL_COMM;
    this_rank = CMPI_LOCAL_RANK;

    /*clone MOD_MGR_LDB*/
    MOD_MGR_LDB_CHOICE(des_mod_mgr) = MOD_MGR_LDB_CHOICE(src_mod_mgr);
    mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(des_mod_mgr)); /*initialize the function pointer*/
    if(NULL_PTR == mod_mgr_ldb)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_limited_clone_with_modi_filter: invalid load balancing strategy %ld\n", MOD_MGR_LDB_CHOICE(des_mod_mgr));
        return (EC_FALSE);
    }
    MOD_MGR_LDB_FUNCPTR(des_mod_mgr) = mod_mgr_ldb->get;

    /*clone local mod node*/
    MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_tcid;
    MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_comm;
    MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_rank;
    MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = mod_id;

    /*clone remote mod node list with modi filter*/
    mod_mgr_remote_mod_node_clone_with_modi_filter(src_mod_mgr, modi_vec, des_mod_mgr);
    MOD_MGR_REMOTE_POS(des_mod_mgr) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(des_mod_mgr) = cvector_search_front(MOD_MGR_REMOTE_LIST(des_mod_mgr), MOD_MGR_LOCAL_MOD(des_mod_mgr), (CVECTOR_DATA_CMP)mod_node_cmp);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_limited_clone_with_tcid_excl_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;

    MOD_MGR_LDB *mod_mgr_ldb;

    this_tcid = CMPI_LOCAL_TCID;
    this_comm = CMPI_LOCAL_COMM;
    this_rank = CMPI_LOCAL_RANK;/*here rank should get in current process!!!*/

    /*clone MOD_MGR_LDB*/
    MOD_MGR_LDB_CHOICE(des_mod_mgr) = MOD_MGR_LDB_CHOICE(src_mod_mgr);
    mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(des_mod_mgr)); /*initialize the function pointer*/
    if(NULL_PTR == mod_mgr_ldb)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_limited_clone_with_tcid_excl_filter: invalid load balancing strategy %ld\n", MOD_MGR_LDB_CHOICE(des_mod_mgr));
        return (EC_FALSE);
    }
    MOD_MGR_LDB_FUNCPTR(des_mod_mgr) = mod_mgr_ldb->get;

    /*clone local mod node*/
    MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_tcid;
    MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_comm;
    MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_rank;
    MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = mod_id;

    /*clone remote mod node list with tcid excl filter*/
    mod_mgr_remote_mod_node_clone_with_tcid_excl_filter(src_mod_mgr, tcid_vec, des_mod_mgr);
    MOD_MGR_REMOTE_POS(des_mod_mgr) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(des_mod_mgr) = cvector_search_front(MOD_MGR_REMOTE_LIST(des_mod_mgr), MOD_MGR_LOCAL_MOD(des_mod_mgr), (CVECTOR_DATA_CMP)mod_node_cmp);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_limited_clone_with_rank_excl_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;

    MOD_MGR_LDB *mod_mgr_ldb;

    this_tcid = CMPI_LOCAL_TCID;
    this_comm = CMPI_LOCAL_COMM;
    this_rank = CMPI_LOCAL_RANK;

    /*clone MOD_MGR_LDB*/
    MOD_MGR_LDB_CHOICE(des_mod_mgr) = MOD_MGR_LDB_CHOICE(src_mod_mgr);
    mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(des_mod_mgr)); /*initialize the function pointer*/
    if(NULL_PTR == mod_mgr_ldb)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_limited_clone_with_rank_excl_filter: invalid load balancing strategy %ld\n", MOD_MGR_LDB_CHOICE(des_mod_mgr));
        return (EC_FALSE);
    }
    MOD_MGR_LDB_FUNCPTR(des_mod_mgr) = mod_mgr_ldb->get;

    /*clone local mod node*/
    MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_tcid;
    MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_comm;
    MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_rank;
    MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = mod_id;

    /*clone remote mod node list with rank excl filter*/
    mod_mgr_remote_mod_node_clone_with_rank_excl_filter(src_mod_mgr, rank_vec, des_mod_mgr);
    MOD_MGR_REMOTE_POS(des_mod_mgr) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(des_mod_mgr) = cvector_search_front(MOD_MGR_REMOTE_LIST(des_mod_mgr), MOD_MGR_LOCAL_MOD(des_mod_mgr), (CVECTOR_DATA_CMP)mod_node_cmp);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_limited_clone_with_modi_excl_filter(const UINT32 mod_id, const MOD_MGR * src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 this_tcid;
    UINT32 this_comm;
    UINT32 this_rank;

    MOD_MGR_LDB *mod_mgr_ldb;

    this_tcid = CMPI_LOCAL_TCID;
    this_comm = CMPI_LOCAL_COMM;
    this_rank = CMPI_LOCAL_RANK;

    /*clone MOD_MGR_LDB*/
    MOD_MGR_LDB_CHOICE(des_mod_mgr) = MOD_MGR_LDB_CHOICE(src_mod_mgr);
    mod_mgr_ldb = mod_mgr_ldb_strategy(MOD_MGR_LDB_CHOICE(des_mod_mgr)); /*initialize the function pointer*/
    if(NULL_PTR == mod_mgr_ldb)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_limited_clone_with_modi_filter: invalid load balancing strategy %ld\n", MOD_MGR_LDB_CHOICE(des_mod_mgr));
        return (EC_FALSE);
    }
    MOD_MGR_LDB_FUNCPTR(des_mod_mgr) = mod_mgr_ldb->get;

    /*clone local mod node*/
    MOD_NODE_TCID(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_tcid;
    MOD_NODE_COMM(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_comm;
    MOD_NODE_RANK(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = this_rank;
    MOD_NODE_MODI(MOD_MGR_LOCAL_MOD(des_mod_mgr)) = mod_id;

    /*clone remote mod node list with modi excl filter*/
    mod_mgr_remote_mod_node_clone_with_modi_excl_filter(src_mod_mgr, modi_vec, des_mod_mgr);
    MOD_MGR_REMOTE_POS(des_mod_mgr) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(des_mod_mgr) = cvector_search_front(MOD_MGR_REMOTE_LIST(des_mod_mgr), MOD_MGR_LOCAL_MOD(des_mod_mgr), (CVECTOR_DATA_CMP)mod_node_cmp);

    return (EC_TRUE);
}


EC_BOOL mod_mgr_set(const UINT32 that_tcid, const UINT32 that_comm, const UINT32 that_modi, const CSET *rank_set, MOD_MGR *mod_mgr_def)
{
    MOD_NODE *remote_mod_node;
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(rank_set, clist_data)
    {
        UINT32 that_rank;

        that_rank = (UINT32)CLIST_DATA_DATA(clist_data);

        mod_node_alloc(&remote_mod_node);

        MOD_NODE_TCID(remote_mod_node) = that_tcid;
        MOD_NODE_COMM(remote_mod_node) = that_comm;
        MOD_NODE_RANK(remote_mod_node) = that_rank;
        MOD_NODE_MODI(remote_mod_node) = that_modi;

        cvector_push(MOD_MGR_REMOTE_LIST(mod_mgr_def), remote_mod_node);
    }
    return (EC_TRUE);
}

/*generate mod_mgr from taskc_mgr*/
EC_BOOL mod_mgr_gen_by_taskc_mgr(const TASKC_MGR *taskc_mgr, const UINT32 tcid, const UINT32 rank, const UINT32 spec_modi, MOD_MGR *mod_mgr)
{
    CLIST      *taskc_node_list;
    CLIST_DATA *clist_data;

    CSET *remote_rank_set;

    rank_set_new(&remote_rank_set);

    taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(taskc_mgr);

    CLIST_LOOP_NEXT(taskc_node_list, clist_data)
    {
        TASKC_NODE *taskc_node;

        taskc_node = (TASKC_NODE *)CLIST_DATA_DATA(clist_data);
        dbg_log(SEC_0108_MOD, 9)(LOGSTDNULL, "[DEBUG] mod_mgr_gen_by_taskc_mgr: taskc_node: tcid %s, comm %ld, size %ld .v.s. tcid %s, rank %ld\n",
                            TASKC_NODE_TCID_STR(taskc_node), TASKC_NODE_COMM(taskc_node), TASKC_NODE_SIZE(taskc_node),
                            c_word_to_ipv4(tcid), rank);

        if(
           (CMPI_ANY_TCID == tcid)
        || (CMPI_ANY_DBG_TCID == tcid && CMPI_DBG_TCID_BEG <= TASKC_NODE_TCID(taskc_node) && TASKC_NODE_TCID(taskc_node) <= CMPI_DBG_TCID_END)
        || (CMPI_ANY_MON_TCID == tcid && CMPI_MON_TCID_BEG <= TASKC_NODE_TCID(taskc_node) && TASKC_NODE_TCID(taskc_node) <= CMPI_MON_TCID_END)
        || tcid == TASKC_NODE_TCID(taskc_node)
        )
        {
            if(CMPI_ANY_RANK == rank)
            {
                rank_set_init(remote_rank_set, taskc_node->taskc_size);
            }
            else if(rank < taskc_node->taskc_size)
            {
                rank_set_incl(remote_rank_set, rank);
            }
            else
            {
                /*do nothing*/
            }

            mod_mgr_set(TASKC_NODE_TCID(taskc_node), TASKC_NODE_COMM(taskc_node), spec_modi, remote_rank_set, mod_mgr);

            rank_set_clean(remote_rank_set);
        }
    }

    rank_set_free(remote_rank_set);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_set_by_cload_node(const CLOAD_NODE *cload_node, const UINT32 that_modi, MOD_MGR *mod_mgr_def)
{
    UINT32 rank;
    UINT32 num;

    num = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node));
    //dbg_log(SEC_0108_MOD, 9)(LOGSTDNULL, "[DEBUG] mod_mgr_set_by_cload_node: vec size = %ld\n", num);

    for(rank = 0; rank < num; rank ++)
    {
        CLOAD_STAT *cload_stat;
        MOD_NODE   *remote_mod_node;

        cload_stat = CLOAD_NODE_RANK_LOAD_STAT(cload_node, rank);

        mod_node_alloc(&remote_mod_node);

        MOD_NODE_TCID(remote_mod_node) = CLOAD_NODE_TCID(cload_node);
        MOD_NODE_COMM(remote_mod_node) = CLOAD_NODE_COMM(cload_node);
        MOD_NODE_RANK(remote_mod_node) = rank;
        MOD_NODE_MODI(remote_mod_node) = that_modi;

        cload_stat_clone(cload_stat, MOD_NODE_CLOAD_STAT(remote_mod_node));

        cvector_push(MOD_MGR_REMOTE_LIST(mod_mgr_def), remote_mod_node);
    }
    return (EC_TRUE);
}

EC_BOOL mod_mgr_gen_from_cload_mgr(const CLOAD_MGR *cload_mgr, const UINT32 tcid, const UINT32 rank, const UINT32 spec_modi, MOD_MGR *mod_mgr)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(cload_mgr, clist_data)
    {
        CLOAD_NODE *cload_node;

        cload_node = (CLOAD_NODE *)CLIST_DATA_DATA(clist_data);

        dbg_log(SEC_0108_MOD, 9)(LOGSTDNULL, "[DEBUG] mod_mgr_gen_from_cload_mgr: expect (tcid %s, rank %ld) <---> cload node (tcid %s, rank vec)\n",
                            c_word_to_ipv4(tcid), rank,
                            CLOAD_NODE_TCID_STR(cload_node)
                            );

        if(
           (CMPI_ANY_TCID == tcid)
        || (CMPI_ANY_DBG_TCID == tcid && CMPI_DBG_TCID_BEG <= CLOAD_NODE_TCID(cload_node) && CLOAD_NODE_TCID(cload_node) <= CMPI_DBG_TCID_END)
        || (CMPI_ANY_MON_TCID == tcid && CMPI_MON_TCID_BEG <= CLOAD_NODE_TCID(cload_node) && CLOAD_NODE_TCID(cload_node) <= CMPI_MON_TCID_END)
        || tcid == CLOAD_NODE_TCID(cload_node)
        )
        {
            //dbg_log(SEC_0108_MOD, 9)(LOGSTDNULL, "[DEBUG] mod_mgr_gen_from_cload_mgr: tcid matched\n");
            if(CMPI_ANY_RANK == rank)
            {
                mod_mgr_set_by_cload_node(cload_node, spec_modi, mod_mgr);
                continue;
            }
            else
            {
                CLOAD_STAT *cload_stat;
                MOD_NODE   *remote_mod_node;

                cload_stat = CLOAD_NODE_RANK_LOAD_STAT(cload_node, rank);
                if(NULL_PTR == cload_stat)
                {
                    continue;
                }

                mod_node_alloc(&remote_mod_node);

                MOD_NODE_TCID(remote_mod_node) = CLOAD_NODE_TCID(cload_node);
                MOD_NODE_COMM(remote_mod_node) = CLOAD_NODE_COMM(cload_node);
                MOD_NODE_RANK(remote_mod_node) = rank;
                MOD_NODE_MODI(remote_mod_node) = spec_modi;

                cload_stat_clone(cload_stat, MOD_NODE_CLOAD_STAT(remote_mod_node));

                cvector_push(MOD_MGR_REMOTE_LIST(mod_mgr), remote_mod_node);
            }
        }
    }

    return (EC_TRUE);
}


/*initialize mod_mgr_def*/
/*note 1: only rank info is important, modi can be ignored because mod_mgr_def should only be used by task_act*/
/*note 2: generally, one mod_mgr belong to some kind of MODULE (see task_act), but mod_mgr_def does not belong to any MODULE*/
EC_BOOL mod_mgr_default_init(MOD_MGR *mod_mgr_def, const UINT32 tcid, const UINT32 rank)
{
    TASK_BRD *task_brd;
    TASKC_MGR *taskc_mgr;

    task_brd = task_brd_default_get();

    taskc_mgr = taskc_mgr_new();
    task_brd_sync_taskc_mgr(task_brd, taskc_mgr);

    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT,"======================================================================\n");
    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT,"               mod_mgr_default_init: taskc_mgr synced result          \n");
    taskc_mgr_print(LOGSTDOUT, taskc_mgr);/*debug only*/
    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT,"======================================================================\n");

    mod_mgr_gen_by_taskc_mgr(taskc_mgr, /*CMPI_ANY_TCID*/tcid, /*CMPI_ANY_RANK*/rank, CMPI_ERROR_MODI, mod_mgr_def);

    taskc_mgr_free(taskc_mgr);

#if 0
    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "------------------------------------ mod_mgr_init beg ----------------------------------\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr_def);
    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "------------------------------------ mod_mgr_init end ----------------------------------\n");
#endif

    return (EC_TRUE);
}

EC_BOOL mod_mgr_default_sync(const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, MOD_MGR *mod_mgr_def)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    task_brd_sync_mod_nodes(task_brd, max_hops, max_remotes, time_to_live, MOD_MGR_REMOTE_LIST(mod_mgr_def));

    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT,"======================================================================\n");
    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT,"               mod_mgr_default_sync: mod_node_vec synced result          \n");
    cvector_print(LOGSTDOUT, MOD_MGR_REMOTE_LIST(mod_mgr_def), (CVECTOR_DATA_PRINT)mod_node_print);/*debug only*/
    dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT,"======================================================================\n");

    return (EC_TRUE);
}

UINT32 mod_mgr_remote_mod_node_clone_with_tcid_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 mod_node_pos;

    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(src_mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *src_mod_node;
        MOD_NODE *des_mod_node;
        UINT32    src_mod_node_tcid;

        src_mod_node      = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(src_mod_mgr), mod_node_pos);
        src_mod_node_tcid = MOD_NODE_TCID(src_mod_node);

        if(CVECTOR_ERR_POS == cvector_search_front(tcid_vec, (void *)src_mod_node_tcid, NULL_PTR))
        {
            /*skip this src_mod_node when tcid of src_mod_node not belong to tcid_vec*/
            continue;
        }

        mod_node_alloc(&des_mod_node);
        mod_node_clone(src_mod_node, des_mod_node);

        cvector_push(MOD_MGR_REMOTE_LIST(des_mod_mgr), (void *)des_mod_node);
    }

    return (0);
}

UINT32 mod_mgr_remote_mod_node_clone_with_rank_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 mod_node_pos;

    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(src_mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *src_mod_node;
        MOD_NODE *des_mod_node;
        UINT32    src_mod_node_rank;

        src_mod_node      = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(src_mod_mgr), mod_node_pos);
        src_mod_node_rank = MOD_NODE_RANK(src_mod_node);

        if(CVECTOR_ERR_POS == cvector_search_front(rank_vec, (void *)src_mod_node_rank, NULL_PTR))
        {
            /*skip this src_mod_node when rank of src_mod_node not belong to rannk_vec*/
            continue;
        }

        mod_node_alloc(&des_mod_node);
        mod_node_clone(src_mod_node, des_mod_node);

        cvector_push(MOD_MGR_REMOTE_LIST(des_mod_mgr), (void *)des_mod_node);
    }

    return (0);
}

UINT32 mod_mgr_remote_mod_node_clone_with_modi_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 mod_node_pos;

    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(src_mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *src_mod_node;
        MOD_NODE *des_mod_node;
        UINT32    src_mod_node_modi;

        src_mod_node      = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(src_mod_mgr), mod_node_pos);
        src_mod_node_modi = MOD_NODE_RANK(src_mod_node);

        if(CVECTOR_ERR_POS == cvector_search_front(modi_vec, (void *)src_mod_node_modi, NULL_PTR))
        {
            /*skip this src_mod_node when modi of src_mod_node not belong to rannk_vec*/
            continue;
        }

        mod_node_alloc(&des_mod_node);
        mod_node_clone(src_mod_node, des_mod_node);

        cvector_push(MOD_MGR_REMOTE_LIST(des_mod_mgr), (void *)des_mod_node);
    }

    return (0);
}

UINT32 mod_mgr_remote_mod_node_clone_with_tcid_excl_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *tcid_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 mod_node_pos;

    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(src_mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *src_mod_node;
        MOD_NODE *des_mod_node;
        UINT32    src_mod_node_tcid;

        src_mod_node      = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(src_mod_mgr), mod_node_pos);
        src_mod_node_tcid = MOD_NODE_TCID(src_mod_node);

        if(CVECTOR_ERR_POS == cvector_search_front(tcid_vec, (void *)src_mod_node_tcid, NULL_PTR))
        {
            mod_node_alloc(&des_mod_node);
            mod_node_clone(src_mod_node, des_mod_node);

            cvector_push(MOD_MGR_REMOTE_LIST(des_mod_mgr), (void *)des_mod_node);
        }
    }

    return (0);
}

UINT32 mod_mgr_remote_mod_node_clone_with_rank_excl_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *rank_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 mod_node_pos;

    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(src_mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *src_mod_node;
        MOD_NODE *des_mod_node;
        UINT32    src_mod_node_rank;

        src_mod_node      = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(src_mod_mgr), mod_node_pos);
        src_mod_node_rank = MOD_NODE_RANK(src_mod_node);

        if(CVECTOR_ERR_POS == cvector_search_front(rank_vec, (void *)src_mod_node_rank, NULL_PTR))
        {
            mod_node_alloc(&des_mod_node);
            mod_node_clone(src_mod_node, des_mod_node);

            cvector_push(MOD_MGR_REMOTE_LIST(des_mod_mgr), (void *)des_mod_node);
        }
    }

    return (0);
}

UINT32 mod_mgr_remote_mod_node_clone_with_modi_excl_filter(const MOD_MGR *src_mod_mgr, const CVECTOR *modi_vec, MOD_MGR *des_mod_mgr)
{
    UINT32 mod_node_pos;

    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(src_mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *src_mod_node;
        MOD_NODE *des_mod_node;
        UINT32    src_mod_node_modi;

        src_mod_node      = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(src_mod_mgr), mod_node_pos);
        src_mod_node_modi = MOD_NODE_RANK(src_mod_node);

        if(CVECTOR_ERR_POS == cvector_search_front(modi_vec, (void *)src_mod_node_modi, NULL_PTR))
        {
            mod_node_alloc(&des_mod_node);
            mod_node_clone(src_mod_node, des_mod_node);

            cvector_push(MOD_MGR_REMOTE_LIST(des_mod_mgr), (void *)des_mod_node);
        }
    }

    return (0);
}

UINT32 mod_mgr_remote_mod_node_num(const MOD_MGR *mod_mgr)
{
    return MOD_MGR_REMOTE_NUM(mod_mgr);
}

EC_BOOL mod_mgr_remote_mod_node_is_local(const MOD_MGR *mod_mgr, const UINT32 remote_mod_node_pos)
{
    MOD_NODE *remote_mod_node;
    MOD_NODE *local_mod_node;

    if(remote_mod_node_pos >= MOD_MGR_REMOTE_NUM(mod_mgr))
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDERR, "error:mod_mgr_remote_mod_node_is_local: remote_mode_node_pos %ld overflow where remote mode node num is %ld\n",
                        remote_mod_node_pos, MOD_MGR_REMOTE_NUM(mod_mgr));
        return (EC_FALSE);
    }

    /*when local mod_node not in remote_mod_node list*/
    if(CVECTOR_ERR_POS == MOD_MGR_LOCAL_MOD_POS(mod_mgr))
    {
        return (EC_FALSE);
    }

    if(remote_mod_node_pos == MOD_MGR_LOCAL_MOD_POS(mod_mgr))
    {
        return (EC_TRUE);
    }

    remote_mod_node = (MOD_NODE *)MOD_MGR_REMOTE_MOD(mod_mgr, remote_mod_node_pos);
    local_mod_node  = (MOD_NODE *)MOD_MGR_LOCAL_MOD(mod_mgr);
    if(EC_TRUE == mod_node_cmp(remote_mod_node, local_mod_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL mod_mgr_first_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;
    UINT32 cur_remote_mod_node_pos;
    UINT32 local_mod_node_pos;

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    local_mod_node_pos = MOD_MGR_LOCAL_MOD_POS(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_first_remote_mod_node_pos: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }

    for(cur_remote_mod_node_pos = 0; cur_remote_mod_node_pos < remote_mod_node_num; cur_remote_mod_node_pos ++)
    {
        if(cur_remote_mod_node_pos != local_mod_node_pos)
        {
            break;
        }
    }

    if(cur_remote_mod_node_pos < remote_mod_node_num)
    {
        (*remote_mod_node_pos) = cur_remote_mod_node_pos;
        return (EC_TRUE);
    }

    (*remote_mod_node_pos) = CVECTOR_ERR_POS;
    return (EC_FALSE);
}

EC_BOOL mod_mgr_last_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;
    UINT32 cur_remote_mod_node_pos;
    UINT32 local_mod_node_pos;

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    local_mod_node_pos = MOD_MGR_LOCAL_MOD_POS(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_last_remote_mod_node_pos: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }

    for(cur_remote_mod_node_pos = remote_mod_node_num; cur_remote_mod_node_pos -- > 0; )
    {
        if(cur_remote_mod_node_pos != local_mod_node_pos)
        {
            break;
        }
    }

    if(((UINT32)-1) != cur_remote_mod_node_pos)
    {
        (*remote_mod_node_pos) = cur_remote_mod_node_pos;
        return (EC_TRUE);
    }

    (*remote_mod_node_pos) = CVECTOR_ERR_POS;
    return (EC_FALSE);
}

EC_BOOL mod_mgr_next_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;
    UINT32 cur_remote_mod_node_pos;
    UINT32 local_mod_node_pos;

    UINT32 lower;/*low boundary*/
    UINT32 upper;/*up boundary*/

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    local_mod_node_pos = MOD_MGR_LOCAL_MOD_POS(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_next_remote_mod_node_pos: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }

    lower = (*remote_mod_node_pos) + 1;
    upper = remote_mod_node_num;

    for(cur_remote_mod_node_pos = lower; cur_remote_mod_node_pos < upper; cur_remote_mod_node_pos ++)
    {
        if(cur_remote_mod_node_pos != local_mod_node_pos)
        {
            break;
        }
    }

    if(cur_remote_mod_node_pos < upper)
    {
        (*remote_mod_node_pos) = cur_remote_mod_node_pos;
        return (EC_TRUE);
    }

    lower = 0;
    upper = (*remote_mod_node_pos);

    for(cur_remote_mod_node_pos = lower; cur_remote_mod_node_pos < upper; cur_remote_mod_node_pos ++)
    {
        if(cur_remote_mod_node_pos != local_mod_node_pos)
        {
            break;
        }
    }

    if(cur_remote_mod_node_pos < upper)
    {
        (*remote_mod_node_pos) = cur_remote_mod_node_pos;
        return (EC_TRUE);
    }

    (*remote_mod_node_pos) = CVECTOR_ERR_POS;
    return (EC_FALSE);
}

EC_BOOL mod_mgr_prev_remote_mod_node_pos(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;
    UINT32 cur_remote_mod_node_pos;
    UINT32 local_mod_node_pos;

    UINT32 lower;/*low boundary*/
    UINT32 upper;/*up boundary*/

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    local_mod_node_pos = MOD_MGR_LOCAL_MOD_POS(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_prev_remote_mod_node_pos: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }

    lower = 0;
    upper = (*remote_mod_node_pos);

    for(cur_remote_mod_node_pos = upper; cur_remote_mod_node_pos -- > lower; )
    {
        if(cur_remote_mod_node_pos != local_mod_node_pos)
        {
            break;
        }
    }

    if(((UINT32)-1) != cur_remote_mod_node_pos)
    {
        (*remote_mod_node_pos) = cur_remote_mod_node_pos;
        return (EC_TRUE);
    }

    lower = (*remote_mod_node_pos) + 1; /*lower >= 1*/
    upper = remote_mod_node_num;

    for(cur_remote_mod_node_pos = upper; cur_remote_mod_node_pos -- > lower; )
    {
        if(cur_remote_mod_node_pos != local_mod_node_pos)
        {
            break;
        }
    }

    if((lower - 1) != cur_remote_mod_node_pos)
    {
        (*remote_mod_node_pos) = cur_remote_mod_node_pos;
        return (EC_TRUE);
    }

    (*remote_mod_node_pos) = CVECTOR_ERR_POS;
    return (EC_FALSE);
}

EC_BOOL mod_mgr_remote_num(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_num)
{
    (*remote_mod_node_num) = MOD_MGR_REMOTE_NUM(mod_mgr);
    return (EC_TRUE);
}

/*simple interface for remote mod_node position, do not consider the local mod_node issue*/
EC_BOOL mod_mgr_first_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_first_remote: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }
    (*remote_mod_node_pos) = 0;
    return (EC_TRUE);
}

/*simple interface for remote mod_node position, do not consider the local mod_node issue*/
EC_BOOL mod_mgr_last_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_last_remote: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }
    (*remote_mod_node_pos) = (remote_mod_node_num - 1);
    return (EC_TRUE);
}

EC_BOOL mod_mgr_next_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_next_remote: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }

    if((*remote_mod_node_pos) >= remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_next_remote: remote_mod_node_pos %ld overflow where remote mod_node num is %ld\n",
                        (*remote_mod_node_pos), remote_mod_node_num);
        return (EC_FALSE);
    }

    (*remote_mod_node_pos) = ((*remote_mod_node_pos) + 1) % (remote_mod_node_num);

    return (EC_TRUE);
}

EC_BOOL mod_mgr_prev_remote(const MOD_MGR *mod_mgr, UINT32 *remote_mod_node_pos)
{
    UINT32 remote_mod_node_num;

    remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);

    /*validity checking*/
    if(0 == remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_prev_remote: mod_mgr %p has no remote mod node\n", mod_mgr);
        return (EC_FALSE);
    }

    if((*remote_mod_node_pos) >= remote_mod_node_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_prev_remote: remote_mod_node_pos %ld overflow where remote mod_node num is %ld\n",
                        (*remote_mod_node_pos), remote_mod_node_num);
        return (EC_FALSE);
    }

    (*remote_mod_node_pos) = ((*remote_mod_node_pos) + remote_mod_node_num - 1) % (remote_mod_node_num);

    return (EC_TRUE);
}


void mod_mgr_remote_mod_load_print(LOG *log, TASK_BRD *task_brd, MOD_NODE *mod_node)
{
    sys_log(log, "taskc %s, comm %ld, rank %ld, modi %ld: mod load %ld, rank load %ld\n",
                MOD_NODE_TCID_STR(mod_node),
                MOD_NODE_COMM(mod_node),
                MOD_NODE_RANK(mod_node),
                MOD_NODE_MODI(mod_node),
                MOD_NODE_LOAD(mod_node),
                task_brd_rank_load_tbl_get_que(task_brd, MOD_NODE_TCID(mod_node), MOD_NODE_RANK(mod_node)));
}

void mod_mgr_remote_mod_list_load_print(LOG *log, TASK_BRD *task_brd, MOD_MGR *mod_mgr)
{
    MOD_NODE *mod_node;

    UINT32 pos;

    for(pos = 0; pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)); pos ++)
    {
        mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);

        sys_log(log, "No. %ld: tcid %s, comm %ld, rank %ld, modi %ld: mod load %ld, rank load %ld\n",
                    pos ++,
                    MOD_NODE_TCID_STR(mod_node),
                    MOD_NODE_COMM(mod_node),
                    MOD_NODE_RANK(mod_node),
                    MOD_NODE_MODI(mod_node),
                    MOD_NODE_LOAD(mod_node),
                    task_brd_rank_load_tbl_get_que(task_brd, MOD_NODE_TCID(mod_node), MOD_NODE_RANK(mod_node)));
    }
    return;
}

MOD_NODE * mod_mgr_loop_get(const MOD_MGR *mod_mgr, UINT32 *pos)
{
    MOD_NODE   *remote_mod_node;

    UINT32 remote_mod_num;
    UINT32 remote_mod_pos;
    UINT32 local_mod_pos;
    UINT32 count;

    remote_mod_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    if(0 == remote_mod_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDERR, "error:mod_mgr_loop_get: mod_mgr %p has no remote mods\n", mod_mgr);
        return (NULL_PTR);
    }

    if(remote_mod_num <= (*pos))
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDERR, "error:mod_mgr_loop_get: position %ld out of mod_mgr %p range with has %ld remote mods\n",
                           (*pos), mod_mgr, remote_mod_num);
        return (NULL_PTR);
    }

    remote_mod_pos = (*pos);
    local_mod_pos  = MOD_MGR_LOCAL_MOD_POS(mod_mgr);

    for(count = 0; count < remote_mod_num; count ++)
    {
        if(remote_mod_pos == local_mod_pos)
        {
            remote_mod_pos = (remote_mod_pos + 1) % (remote_mod_num);
            continue;
        }

        remote_mod_node = (MOD_NODE   *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), remote_mod_pos);
        remote_mod_pos = (remote_mod_pos + 1) % (remote_mod_num);

        (*pos) = remote_mod_pos;
        return (remote_mod_node);
    }

    return (NULL_PTR);
}

MOD_NODE * mod_mgr_loop_find(const MOD_MGR *mod_mgr, const UINT32 tcid, UINT32 *pos)
{
    MOD_NODE   *remote_mod_node;

    UINT32 remote_mod_num;
    UINT32 remote_mod_pos;
    UINT32 local_mod_pos;
    UINT32 count;

    remote_mod_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    if(0 == remote_mod_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDERR, "error:mod_mgr_loop_find: mod_mgr %p has no remote mods\n", mod_mgr);
        return (NULL_PTR);
    }

    if(remote_mod_num <= (*pos))
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDERR, "error:mod_mgr_loop_find: position %ld out of mod_mgr %p range with has %ld remote mods\n",
                           (*pos), mod_mgr, remote_mod_num);
        return (NULL_PTR);
    }

    remote_mod_pos = (*pos);
    local_mod_pos  = MOD_MGR_LOCAL_MOD_POS(mod_mgr);

    for(count = 0; count < remote_mod_num; count ++)
    {
        if(remote_mod_pos == local_mod_pos)
        {
            remote_mod_pos = (remote_mod_pos + 1) % (remote_mod_num);
            continue;
        }

        remote_mod_node = (MOD_NODE   *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), remote_mod_pos);
        remote_mod_pos = (remote_mod_pos + 1) % (remote_mod_num);/*move to next position*/

        if(MOD_NODE_TCID(remote_mod_node) == tcid)
        {
            (*pos) = remote_mod_pos;
            return (remote_mod_node);
        }
    }

    return (NULL_PTR);
}



MOD_NODE *mod_mgr_find_min_load_with_tcid_filter(const MOD_MGR *mod_mgr, const UINT32 tcid)
{
    MOD_NODE   *remote_mod_node;

    remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)tcid,
                                                           (CVECTOR_DATA_POST_FILTER)mod_node_tcid_filter,
                                                           (CVECTOR_DATA_VOTER)mod_node_lt_que);
    return (remote_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_rank_filter(const MOD_MGR *mod_mgr, const UINT32 rank)
{
    MOD_NODE   *remote_mod_node;

    remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)rank,
                                                           (CVECTOR_DATA_POST_FILTER)mod_node_rank_filter,
                                                           (CVECTOR_DATA_VOTER)mod_node_lt_que);
    return (remote_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_modi_filter(const MOD_MGR *mod_mgr, const UINT32 modi)
{
    MOD_NODE   *remote_mod_node;

    remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)modi,
                                                           (CVECTOR_DATA_POST_FILTER)mod_node_modi_filter,
                                                           (CVECTOR_DATA_VOTER)mod_node_lt_que);
    return (remote_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_tcid_vec_filter(const MOD_MGR *mod_mgr, const CVECTOR *tcid_vec)
{
    UINT32     tcid_num;
    UINT32     tcid_pos;

    MOD_NODE  *best_mod_node;
    TASK_BRD  *task_brd;

    task_brd = task_brd_default_get();
    best_mod_node = NULL_PTR;

    tcid_num = cvector_size(tcid_vec);
    for(tcid_pos = 0; tcid_pos < tcid_num; tcid_pos ++)
    {
        UINT32 tcid;

        MOD_NODE   *remote_mod_node;

        tcid = (UINT32)cvector_get(tcid_vec, tcid_pos);

        remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)tcid,
                                                               (CVECTOR_DATA_POST_FILTER)mod_node_tcid_filter,
                                                               (CVECTOR_DATA_VOTER)mod_node_lt_que);
        if(NULL_PTR == remote_mod_node)
        {
            continue;
        }

        if(NULL_PTR == best_mod_node || MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) < MOD_NODE_LOAD_GET_QUE(task_brd, best_mod_node))
        {
            best_mod_node = remote_mod_node;
        }
    }

    return (best_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_rank_vec_filter(const MOD_MGR *mod_mgr, const CVECTOR *rank_vec)
{
    UINT32     rank_num;
    UINT32     rank_pos;

    MOD_NODE  *best_mod_node;
    TASK_BRD  *task_brd;

    task_brd = task_brd_default_get();
    best_mod_node = NULL_PTR;

    rank_num = cvector_size(rank_vec);
    for(rank_pos = 0; rank_pos < rank_num; rank_pos ++)
    {
        UINT32 rank;

        MOD_NODE   *remote_mod_node;

        rank = (UINT32)cvector_get(rank_vec, rank_pos);

        remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)rank,
                                                               (CVECTOR_DATA_POST_FILTER)mod_node_rank_filter,
                                                               (CVECTOR_DATA_VOTER)mod_node_lt_que);

        if(NULL_PTR == remote_mod_node)
        {
            continue;
        }

        if(NULL_PTR == best_mod_node || MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) < MOD_NODE_LOAD_GET_QUE(task_brd, best_mod_node))
        {
            best_mod_node = remote_mod_node;
        }
    }

    return (best_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_modi_vec_filter(const MOD_MGR *mod_mgr, const CVECTOR *modi_vec)
{
    UINT32     modi_num;
    UINT32     modi_pos;

    MOD_NODE  *best_mod_node;
    TASK_BRD  *task_brd;

    task_brd = task_brd_default_get();
    best_mod_node = NULL_PTR;

    modi_num = cvector_size(modi_vec);
    for(modi_pos = 0; modi_pos < modi_num; modi_pos ++)
    {
        UINT32 modi;

        MOD_NODE   *remote_mod_node;

        modi = (UINT32)cvector_get(modi_vec, modi_pos);

        remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)modi,
                                                               (CVECTOR_DATA_POST_FILTER)mod_node_modi_filter,
                                                               (CVECTOR_DATA_VOTER)mod_node_lt_que);

        if(NULL_PTR == remote_mod_node)
        {
            continue;
        }

        if(NULL_PTR == best_mod_node || MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) < MOD_NODE_LOAD_GET_QUE(task_brd, best_mod_node))
        {
            best_mod_node = remote_mod_node;
        }
    }

    return (best_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_tcid_excl_filter(const MOD_MGR *mod_mgr, const UINT32 tcid)
{
    MOD_NODE   *remote_mod_node;

    remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)tcid,
                                                           (CVECTOR_DATA_POST_FILTER)mod_node_tcid_excl_filter,
                                                           (CVECTOR_DATA_VOTER)mod_node_lt_que);
    return (remote_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_rank_excl_filter(const MOD_MGR *mod_mgr, const UINT32 rank)
{
    MOD_NODE   *remote_mod_node;

    remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)rank,
                                                           (CVECTOR_DATA_POST_FILTER)mod_node_rank_excl_filter,
                                                           (CVECTOR_DATA_VOTER)mod_node_lt_que);
    return (remote_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_modi_excl_filter(const MOD_MGR *mod_mgr, const UINT32 modi)
{
    MOD_NODE   *remote_mod_node;

    remote_mod_node = (MOD_NODE *)cvector_vote_with_post_filter(MOD_MGR_REMOTE_LIST(mod_mgr), (void *)modi,
                                                           (CVECTOR_DATA_POST_FILTER)mod_node_modi_excl_filter,
                                                           (CVECTOR_DATA_VOTER)mod_node_lt_que);
    return (remote_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_tcid_vec_excl_filter(const MOD_MGR *mod_mgr, const CVECTOR *tcid_vec)
{
    UINT32     mod_node_pos;

    MOD_NODE  *best_mod_node;
    TASK_BRD  *task_brd;

    task_brd = task_brd_default_get();
    best_mod_node = NULL_PTR;

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0009);
    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE   *remote_mod_node;

        remote_mod_node = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node_pos);
        if(NULL_PTR == remote_mod_node)
        {
            continue;
        }

        if(CVECTOR_ERR_POS != cvector_search_front(tcid_vec, (void *)MOD_NODE_TCID(remote_mod_node), NULL_PTR))
        {
            continue;
        }

        if(NULL_PTR == best_mod_node || MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) < MOD_NODE_LOAD_GET_QUE(task_brd, best_mod_node))
        {
            best_mod_node = remote_mod_node;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0010);

    return (best_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_rank_vec_excl_filter(const MOD_MGR *mod_mgr, const CVECTOR *rank_vec)
{
    UINT32     mod_node_pos;

    MOD_NODE  *best_mod_node;
    TASK_BRD  *task_brd;

    task_brd = task_brd_default_get();
    best_mod_node = NULL_PTR;

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0011);
    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE   *remote_mod_node;

        remote_mod_node = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node_pos);
        if(NULL_PTR == remote_mod_node)
        {
            continue;
        }

        if(CVECTOR_ERR_POS != cvector_search_front(rank_vec, (void *)MOD_NODE_RANK(remote_mod_node), NULL_PTR))
        {
            continue;
        }

        if(NULL_PTR == best_mod_node || MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) < MOD_NODE_LOAD_GET_QUE(task_brd, best_mod_node))
        {
            best_mod_node = remote_mod_node;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0012);

    return (best_mod_node);
}

MOD_NODE *mod_mgr_find_min_load_with_modi_vec_excl_filter(const MOD_MGR *mod_mgr, const CVECTOR *modi_vec)
{
    UINT32     mod_node_pos;

    MOD_NODE  *best_mod_node;
    TASK_BRD  *task_brd;

    task_brd = task_brd_default_get();
    best_mod_node = NULL_PTR;

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0013);
    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE   *remote_mod_node;

        remote_mod_node = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node_pos);
        if(NULL_PTR == remote_mod_node)
        {
            continue;
        }

        if(CVECTOR_ERR_POS != cvector_search_front(modi_vec, (void *)MOD_NODE_MODI(remote_mod_node), NULL_PTR))
        {
            continue;
        }

        if(NULL_PTR == best_mod_node || MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) < MOD_NODE_LOAD_GET_QUE(task_brd, best_mod_node))
        {
            best_mod_node = remote_mod_node;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0014);

    return (best_mod_node);
}

/*------------------ load balancing strategy of mod_mgr ------------------ */

/*get load balancing strategy*/
MOD_MGR_LDB * mod_mgr_ldb_strategy(const UINT32 load_balancing_strategy)
{
    UINT32 idx;
    UINT32 size;

    size = sizeof(g_mod_mgr_ldb)/sizeof(g_mod_mgr_ldb[ 0 ]);

    if(load_balancing_strategy < size
    && load_balancing_strategy == g_mod_mgr_ldb[ load_balancing_strategy ].load_balancing_strategy)
    {
        return (&(g_mod_mgr_ldb[ load_balancing_strategy ]));
    }

    for(idx = 0; idx < size; idx ++)
    {
        if(load_balancing_strategy == g_mod_mgr_ldb[ idx ].load_balancing_strategy)
        {
            return (&(g_mod_mgr_ldb[ idx ]));
        }
    }
    return (NULL_PTR);
}

/*get remote mod node by loop load balancing strategy*/
MOD_NODE * mod_mgr_ldb_loop_get(MOD_MGR *mod_mgr)
{
    MOD_NODE   *remote_mod_node;

    UINT32 remote_mod_num;
    UINT32 remote_mod_pos;
    UINT32 local_mod_pos;

    remote_mod_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    if(0 == remote_mod_num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDERR, "error:mod_mgr_ldb_loop_get: mod_mgr %p has no remote mods\n", mod_mgr);
        return (NULL_PTR);
    }

    remote_mod_pos = MOD_MGR_REMOTE_POS(mod_mgr);
    local_mod_pos  = MOD_MGR_LOCAL_MOD_POS(mod_mgr);

    remote_mod_pos = (remote_mod_pos + 1) % (remote_mod_num);
    if(remote_mod_pos == local_mod_pos)
    {
        remote_mod_pos = (remote_mod_pos + 1) % (remote_mod_num);
    }

    remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), remote_mod_pos);

    MOD_MGR_REMOTE_POS(mod_mgr) = remote_mod_pos;

    //dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "mod_mgr_ldb_loop_get: mod_mgr %p: remote_mod_node %p: ", mod_mgr, remote_mod_node);
    //mod_node_print(LOGSTDOUT, remote_mod_node);

    return (remote_mod_node);
}

/*get remote mod node by queue load balancing strategy*/
MOD_NODE * mod_mgr_ldb_mod_get(MOD_MGR *mod_mgr)
{
    MOD_NODE *remote_mod_node;
    remote_mod_node = (MOD_NODE *)cvector_vote(MOD_MGR_REMOTE_LIST(mod_mgr), (CVECTOR_DATA_VOTER)mod_node_lt_que);

    return (remote_mod_node);
}


/*get remote mod node by rank load balancing strategy*/
MOD_NODE * mod_mgr_ldb_que_get(MOD_MGR *mod_mgr)
{
    TASK_BRD *task_brd;
    MOD_NODE *mod_node_min;
    UINT32 load_min;

    UINT32 num;
    UINT32 pos;

    task_brd = task_brd_default_get();

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0015);
    num = cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr));

    if(0 == num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_ldb_que_get: mod mgr has no remote mode node\n");
        CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0016);
        return (NULL_PTR);
    }

    mod_node_min = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), 0);
    load_min     = task_brd_rank_load_tbl_get_que(task_brd, MOD_NODE_TCID(mod_node_min), MOD_NODE_RANK(mod_node_min));

    for(pos = 1; pos < num; pos ++)
    {
        MOD_NODE *mod_node_cur;
        UINT32 load_cur;

        mod_node_cur = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(NULL_PTR == mod_node_cur)
        {
            continue;
        }

        load_cur = task_brd_rank_load_tbl_get_que(task_brd, MOD_NODE_TCID(mod_node_cur), MOD_NODE_RANK(mod_node_cur));
        if(CLOAD_ERR_LOAD != load_cur && load_min > load_cur)
        {
            mod_node_min = mod_node_cur;
            load_min     = load_cur;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0017);
#if 0
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: mod_mgr:\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: chose mod node: ");
    mod_node_print(LOGSTDOUT, mod_node_min);
#endif
    return (mod_node_min);
}

MOD_NODE * mod_mgr_ldb_obj_get(MOD_MGR *mod_mgr)
{
    TASK_BRD *task_brd;
    MOD_NODE *mod_node_min;
    UINT32 load_min;

    UINT32 remote_mod_pos;
    UINT32 num;
    UINT32 pos;

    task_brd = task_brd_default_get();

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0018);
    num = cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr));

    if(0 == num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_ldb_obj_get: mod mgr has no remote mode node\n");
        CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0019);
        return (NULL_PTR);
    }

    remote_mod_pos = (MOD_MGR_REMOTE_POS(mod_mgr) % num);

    mod_node_min = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), remote_mod_pos);
    load_min     = task_brd_rank_load_tbl_get_obj(task_brd, MOD_NODE_TCID(mod_node_min), MOD_NODE_RANK(mod_node_min));

    for(pos = ((remote_mod_pos + 1) % num); pos != remote_mod_pos; pos = ((pos + 1) % num))
    {
        MOD_NODE *mod_node_cur;
        UINT32 load_cur;

        mod_node_cur = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(NULL_PTR == mod_node_cur)
        {
            continue;
        }

        load_cur = task_brd_rank_load_tbl_get_obj(task_brd, MOD_NODE_TCID(mod_node_cur), MOD_NODE_RANK(mod_node_cur));
        if(CLOAD_ERR_LOAD != load_cur && load_min > load_cur)
        {
            mod_node_min = mod_node_cur;
            load_min     = load_cur;
        }
    }
    MOD_MGR_REMOTE_POS(mod_mgr) = pos;
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0020);
#if 0
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: mod_mgr:\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: chose mod node: ");
    mod_node_print(LOGSTDOUT, mod_node_min);
#endif
    return (mod_node_min);
}

MOD_NODE * mod_mgr_ldb_cpu_get(MOD_MGR *mod_mgr)
{
    TASK_BRD *task_brd;
    MOD_NODE *mod_node_min;
    UINT32 load_min;

    UINT32 num;
    UINT32 pos;

    task_brd = task_brd_default_get();

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0021);
    num = cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr));

    if(0 == num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_ldb_cpu_get: mod mgr has no remote mode node\n");
        CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0022);
        return (NULL_PTR);
    }

    mod_node_min = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), 0);
    load_min     = task_brd_rank_load_tbl_get_cpu(task_brd, MOD_NODE_TCID(mod_node_min), MOD_NODE_RANK(mod_node_min));

    for(pos = 1; pos < num; pos ++)
    {
        MOD_NODE *mod_node_cur;
        UINT32 load_cur;

        mod_node_cur = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(NULL_PTR == mod_node_cur)
        {
            continue;
        }

        load_cur = task_brd_rank_load_tbl_get_cpu(task_brd, MOD_NODE_TCID(mod_node_cur), MOD_NODE_RANK(mod_node_cur));
        if(CLOAD_ERR_LOAD != load_cur && load_min > load_cur)
        {
            mod_node_min = mod_node_cur;
            load_min     = load_cur;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0023);
#if 0
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: mod_mgr:\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: chose mod node: ");
    mod_node_print(LOGSTDOUT, mod_node_min);
#endif
    return (mod_node_min);
}

MOD_NODE * mod_mgr_ldb_mem_get(MOD_MGR *mod_mgr)
{
    TASK_BRD *task_brd;
    MOD_NODE *mod_node_min;
    UINT32 load_min;

    UINT32 num;
    UINT32 pos;

    task_brd = task_brd_default_get();

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0024);
    num = cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr));

    if(0 == num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_ldb_mem_get: mod mgr has no remote mode node\n");
        CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0025);
        return (NULL_PTR);
    }

    mod_node_min = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), 0);
    load_min     = task_brd_rank_load_tbl_get_mem(task_brd, MOD_NODE_TCID(mod_node_min), MOD_NODE_RANK(mod_node_min));

    for(pos = 1; pos < num; pos ++)
    {
        MOD_NODE *mod_node_cur;
        UINT32 load_cur;

        mod_node_cur = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(NULL_PTR == mod_node_cur)
        {
            continue;
        }

        load_cur = task_brd_rank_load_tbl_get_mem(task_brd, MOD_NODE_TCID(mod_node_cur), MOD_NODE_RANK(mod_node_cur));
        if(CLOAD_ERR_LOAD != load_cur && load_min > load_cur)
        {
            mod_node_min = mod_node_cur;
            load_min     = load_cur;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0026);
#if 0
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: mod_mgr:\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: chose mod node: ");
    mod_node_print(LOGSTDOUT, mod_node_min);
#endif
    return (mod_node_min);
}

MOD_NODE * mod_mgr_ldb_dsk_get(MOD_MGR *mod_mgr)
{
    TASK_BRD *task_brd;
    MOD_NODE *mod_node_min;
    UINT32 load_min;

    UINT32 num;
    UINT32 pos;

    task_brd = task_brd_default_get();

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0027);
    num = cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr));

    if(0 == num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_ldb_dsk_get: mod mgr has no remote mode node\n");
        CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0028);
        return (NULL_PTR);
    }

    mod_node_min = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), 0);
    load_min     = task_brd_rank_load_tbl_get_dsk(task_brd, MOD_NODE_TCID(mod_node_min), MOD_NODE_RANK(mod_node_min));

    for(pos = 1; pos < num; pos ++)
    {
        MOD_NODE *mod_node_cur;
        UINT32 load_cur;

        mod_node_cur = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(NULL_PTR == mod_node_cur)
        {
            continue;
        }

        load_cur = task_brd_rank_load_tbl_get_dsk(task_brd, MOD_NODE_TCID(mod_node_cur), MOD_NODE_RANK(mod_node_cur));
        if(CLOAD_ERR_LOAD != load_cur && load_min > load_cur)
        {
            mod_node_min = mod_node_cur;
            load_min     = load_cur;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0029);
#if 0
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: mod_mgr:\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: chose mod node: ");
    mod_node_print(LOGSTDOUT, mod_node_min);
#endif
    return (mod_node_min);
}

MOD_NODE * mod_mgr_ldb_net_get(MOD_MGR *mod_mgr)
{
    TASK_BRD *task_brd;
    MOD_NODE *mod_node_min;
    UINT32 load_min;

    UINT32 num;
    UINT32 pos;

    task_brd = task_brd_default_get();

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0030);
    num = cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr));

    if(0 == num)
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_ldb_net_get: mod mgr has no remote mode node\n");
        CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0031);
        return (NULL_PTR);
    }

    mod_node_min = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), 0);
    load_min     = task_brd_rank_load_tbl_get_net(task_brd, MOD_NODE_TCID(mod_node_min), MOD_NODE_RANK(mod_node_min));

    for(pos = 1; pos < num; pos ++)
    {
        MOD_NODE *mod_node_cur;
        UINT32 load_cur;

        mod_node_cur = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(NULL_PTR == mod_node_cur)
        {
            continue;
        }

        load_cur = task_brd_rank_load_tbl_get_net(task_brd, MOD_NODE_TCID(mod_node_cur), MOD_NODE_RANK(mod_node_cur));
        if(CLOAD_ERR_LOAD != load_cur && load_min > load_cur)
        {
            mod_node_min = mod_node_cur;
            load_min     = load_cur;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_MOD_0032);
#if 0
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: mod_mgr:\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr);
    dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_ldb_que_get: chose mod node: ");
    mod_node_print(LOGSTDOUT, mod_node_min);
#endif
    return (mod_node_min);
}


EC_BOOL mod_mgr_print(LOG *log, const MOD_MGR * mod_mgr)
{
    const MOD_NODE *local_mod_node;

    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0108_MOD, 1)(LOGSTDOUT, "warn:mod_mgr_print: mod_mgr is null\n");
        return (EC_TRUE);
    }

    sys_log(log, "mod_mgr %p is:\n", mod_mgr);
    sys_log(log, "ldb choice    : %ld\n", MOD_MGR_LDB_CHOICE(mod_mgr));
    sys_log(log, "local mod pos : %ld\n", MOD_MGR_LOCAL_MOD_POS(mod_mgr));

    local_mod_node = MOD_MGR_LOCAL_MOD(mod_mgr);
    sys_log(log, "local mod     : tcid %s, comm %ld, rank %ld, modi %ld\n",
                    MOD_NODE_TCID_STR(local_mod_node),
                    MOD_NODE_COMM(local_mod_node),
                    MOD_NODE_RANK(local_mod_node),
                    MOD_NODE_MODI(local_mod_node));

    sys_log(log, "remote mod num: %ld\n", MOD_MGR_REMOTE_NUM(mod_mgr));
    cvector_print(log, MOD_MGR_REMOTE_LIST(mod_mgr), (CVECTOR_DATA_PRINT)mod_node_print);

    if(LOAD_BALANCING_END != MOD_MGR_LDB_CHOICE(mod_mgr))
    {
        sys_log(log, "current rank load table info:\n");
        cload_mgr_print(log, TASK_BRD_CLOAD_MGR(task_brd_default_get()));
    }
    return (EC_TRUE);
}

UINT32 mod_mgr_incl(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, MOD_MGR *mod_mgr)
{
    MOD_NODE *mod_node;
    UINT32  pos;

    mod_node_alloc(&mod_node);

    MOD_NODE_TCID(mod_node) = tcid;
    MOD_NODE_COMM(mod_node) = comm;
    MOD_NODE_RANK(mod_node) = rank;
    MOD_NODE_MODI(mod_node) = modi;

    pos = cvector_search_front(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node, (CVECTOR_DATA_CMP)mod_node_cmp);
    /*found*/
    if(CVECTOR_ERR_POS != pos)
    {
        mod_node_free(mod_node);
        return (pos);
    }
    /*not found*/
    return cvector_push(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node);
}

UINT32 mod_mgr_excl_pos(MOD_MGR *mod_mgr, const UINT32 pos)
{
    MOD_NODE *remote_mod_node;

    remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);

    /*adjust local_mod_pos and remote_mod_pos if necessary*/
    if(pos == MOD_MGR_LOCAL_MOD_POS(mod_mgr))
    {
        MOD_MGR_LOCAL_MOD_POS(mod_mgr) = CVECTOR_ERR_POS;
    }
    else if(pos < MOD_MGR_LOCAL_MOD_POS(mod_mgr))
    {
        MOD_MGR_LOCAL_MOD_POS(mod_mgr) --;
    }

    if(pos <= MOD_MGR_REMOTE_POS(mod_mgr))
    {
        MOD_MGR_REMOTE_POS(mod_mgr) = (MOD_MGR_REMOTE_POS(mod_mgr) + MOD_MGR_REMOTE_NUM(mod_mgr) - 1) % MOD_MGR_REMOTE_NUM(mod_mgr);
    }

    remote_mod_node = (MOD_NODE *)cvector_erase(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
    mod_node_free(remote_mod_node);

    return (0);
}

UINT32 mod_mgr_excl(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, MOD_MGR *mod_mgr)
{
    MOD_NODE *remote_mod_node;
    UINT32  pos;

    pos = 0;
    while(pos < MOD_MGR_REMOTE_NUM(mod_mgr))
    {
        remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);

        /*exclude remote_mod_node only when it satifies all (tcid, comm, rank,modi) matches the input condition*/
        if(MOD_NODE_MATCH(remote_mod_node, tcid, comm, rank, modi))
        {
            /*found*/
            mod_mgr_excl_pos(mod_mgr, pos);
            continue;
        }
        pos ++;
    }
    return (0);
}

MOD_NODE *mod_mgr_search(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, const MOD_MGR *mod_mgr)
{
    UINT32  pos;

    for(pos = 0; pos < MOD_MGR_REMOTE_NUM(mod_mgr); pos ++)
    {
        MOD_NODE *remote_mod_node;

        remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(
           tcid == MOD_NODE_TCID(remote_mod_node)
        && comm == MOD_NODE_COMM(remote_mod_node)
        && rank == MOD_NODE_RANK(remote_mod_node)
        && modi == MOD_NODE_MODI(remote_mod_node)
        )
        {
            return (remote_mod_node);
        }
    }

    return (NULL_PTR);
}

EC_BOOL mod_mgr_has(const UINT32 tcid, const UINT32 comm, const UINT32 rank, const UINT32 modi, const MOD_MGR *mod_mgr)
{
    UINT32  pos;

    for(pos = 0; pos < MOD_MGR_REMOTE_NUM(mod_mgr); pos ++)
    {
        MOD_NODE *remote_mod_node;

        remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
        if(
           tcid == MOD_NODE_TCID(remote_mod_node)
        && comm == MOD_NODE_COMM(remote_mod_node)
        && rank == MOD_NODE_RANK(remote_mod_node)
        && modi == MOD_NODE_MODI(remote_mod_node)
        )
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}


EC_BOOL mod_mgr_local_mod_load_set(const UINT32 load, const MOD_NODE *check_local_mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr)
{
    MOD_NODE *local_mod_node;
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

#if 1
    /*only for debug purpose: consistency checking*/
    if(EC_FALSE == mod_node_cmp(check_local_mod_node, MOD_MGR_LOCAL_MOD(mod_mgr)))
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_set: inconsistent local_mod_node: mod_mgr %p: (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        mod_mgr,
                        MOD_NODE_TCID_STR(check_local_mod_node),MOD_NODE_COMM(check_local_mod_node),
                        MOD_NODE_RANK(check_local_mod_node),MOD_NODE_MODI(check_local_mod_node));

        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_set: inputed local_mod_node: \n");
        mod_node_print(LOGSTDOUT, check_local_mod_node);

        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_set: mod_mgr %p local_mod_node: \n", mod_mgr);
        mod_node_print(LOGSTDOUT, MOD_MGR_LOCAL_MOD(mod_mgr));

        return (EC_FALSE);
    }
#endif

    local_mod_node = MOD_MGR_LOCAL_MOD(mod_mgr);
    if(0 == except_mod_node || EC_FALSE == mod_node_cmp(local_mod_node, except_mod_node))
    {
#if 0
        dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "local  mod load update: mod_mgr %p: (comm %ld, rank %ld, modi %ld): load %ld -> %ld\n",
                        mod_mgr,
                        MOD_NODE_COMM(local_mod_node),MOD_NODE_RANK(local_mod_node),MOD_NODE_MODI(local_mod_node),
                        MOD_NODE_LOAD(local_mod_node),load);
#endif
        MOD_NODE_LOAD_SET_QUE(task_brd, local_mod_node, load);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL mod_mgr_local_mod_load_inc(const UINT32 increasement, const MOD_NODE *check_local_mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr)
{
    MOD_NODE *local_mod_node;
    TASK_BRD *task_brd;

    UINT32 load;

    task_brd = task_brd_default_get();
#if 1
    /*only for debug purpose: consistency checking*/
    if(EC_FALSE == mod_node_cmp(check_local_mod_node, MOD_MGR_LOCAL_MOD(mod_mgr)))
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_inc: inconsistent local_mod_node: mod_mgr %p: (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        mod_mgr,
                        MOD_NODE_TCID_STR(check_local_mod_node),MOD_NODE_COMM(check_local_mod_node),
                        MOD_NODE_RANK(check_local_mod_node),MOD_NODE_MODI(check_local_mod_node));

        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_inc: inputed local_mod_node: \n");
        mod_node_print(LOGSTDOUT, check_local_mod_node);

        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_inc: mod_mgr %p local_mod_node: \n", mod_mgr);
        mod_node_print(LOGSTDOUT, MOD_MGR_LOCAL_MOD(mod_mgr));

        return (EC_FALSE);
    }
#endif

    local_mod_node = MOD_MGR_LOCAL_MOD(mod_mgr);
    if(0 == except_mod_node || EC_FALSE == mod_node_cmp(local_mod_node, except_mod_node))
    {
        load = MOD_NODE_LOAD_GET_QUE(task_brd, local_mod_node) + increasement;
#if 0
        dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "local  mod load increase: mod_mgr %p: (comm %ld, rank %ld, modi %ld): load %ld -> %ld\n",
                        mod_mgr,
                        MOD_NODE_COMM(local_mod_node),MOD_NODE_RANK(local_mod_node),MOD_NODE_MODI(local_mod_node),
                        MOD_NODE_LOAD(local_mod_node),load);
#endif
        MOD_NODE_LOAD_SET_QUE(task_brd, local_mod_node, load);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL mod_mgr_local_mod_load_dec(const UINT32 decreasement, const MOD_NODE *check_local_mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr)
{
    MOD_NODE *local_mod_node;
    TASK_BRD *task_brd;

    UINT32 load;

    task_brd = task_brd_default_get();

#if 1
    /*only for debug purpose: consistency checking*/
    if(EC_FALSE == mod_node_cmp(check_local_mod_node, MOD_MGR_LOCAL_MOD(mod_mgr)))
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_dec: inconsistent local_mod_node: mod_mgr %p: (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        mod_mgr,
                        MOD_NODE_TCID_STR(check_local_mod_node),MOD_NODE_COMM(check_local_mod_node),
                        MOD_NODE_RANK(check_local_mod_node),MOD_NODE_MODI(check_local_mod_node));

        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_dec: inputed local_mod_node: \n");
        mod_node_print(LOGSTDOUT, check_local_mod_node);

        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_local_mod_load_dec: mod_mgr %p local_mod_node: \n", mod_mgr);
        mod_node_print(LOGSTDOUT, MOD_MGR_LOCAL_MOD(mod_mgr));

        return (EC_FALSE);
    }
#endif

    local_mod_node = MOD_MGR_LOCAL_MOD(mod_mgr);
    if(0 == except_mod_node || EC_FALSE == mod_node_cmp(local_mod_node, except_mod_node))
    {
        load = MOD_NODE_LOAD_GET_QUE(task_brd, local_mod_node) - decreasement;
#if 0
        dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "local  mod load decrease: mod_mgr %p: (comm %ld, rank %ld, modi %ld): load %ld -> %ld\n",
                        mod_mgr,
                        MOD_NODE_COMM(local_mod_node),MOD_NODE_RANK(local_mod_node),MOD_NODE_MODI(local_mod_node),
                        MOD_NODE_LOAD(local_mod_node),load);
#endif
        MOD_NODE_LOAD_SET_QUE(task_brd, local_mod_node, load);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL mod_mgr_remote_mod_load_set(const UINT32 load, const MOD_NODE *mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr)
{
    MOD_NODE *remote_mod_node;
    TASK_BRD *task_brd;
    UINT32 pos;

    task_brd = task_brd_default_get();

    pos = cvector_search_front(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node, (CVECTOR_DATA_CMP)mod_node_cmp);
    if(CVECTOR_ERR_POS == pos)/*not found*/
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_remote_mod_load_set: failed to match mod_node %p: (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        mod_node,
                        MOD_NODE_TCID_STR(mod_node),MOD_NODE_COMM(mod_node),
                        MOD_NODE_RANK(mod_node),MOD_NODE_MODI(mod_node));
        return (EC_FALSE);
    }

    if(0 == except_mod_node || EC_FALSE == mod_node_cmp(mod_node, except_mod_node))
    {
        remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);
#if 0
        dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "remote mod load update: mod_mgr %p: (comm %ld, rank %ld, modi %ld): load %ld -> %ld\n",
                        mod_mgr,
                        MOD_NODE_COMM(mod_node),MOD_NODE_RANK(mod_node),MOD_NODE_MODI(mod_node),
                        MOD_NODE_LOAD(remote_mod_node),load);
#endif
        MOD_NODE_LOAD_SET_QUE(task_brd, remote_mod_node, load);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL mod_mgr_remote_mod_load_inc(const UINT32 increasement, const MOD_NODE *mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr)
{
    MOD_NODE *remote_mod_node;
    TASK_BRD *task_brd;
    UINT32 pos;

    UINT32 load;

    task_brd = task_brd_default_get();

    pos = cvector_search_front(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node, (CVECTOR_DATA_CMP)mod_node_cmp);
    if(CVECTOR_ERR_POS == pos)/*not found*/
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_remote_mod_load_inc: failed to match mod_node %p: (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        mod_node,
                        MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node),
                        MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));

        dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "mod_mgr_remote_mod_load_inc: mod_mgr %p\n", mod_mgr);
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        return (EC_FALSE);
    }

    if(0 == except_mod_node || EC_FALSE == mod_node_cmp(mod_node, except_mod_node))
    {
        remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);

        load = MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) + increasement;
#if 0
        dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "remote mod load increase: mod_mgr %p: (comm %ld, rank %ld, modi %ld): load %ld -> %ld\n",
                        mod_mgr,
                        MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        MOD_NODE_LOAD(remote_mod_node),load);
#endif
        MOD_NODE_LOAD_SET_QUE(task_brd, remote_mod_node, load);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL mod_mgr_remote_mod_load_dec(const UINT32 decreasement, const MOD_NODE *mod_node, const MOD_NODE *except_mod_node, MOD_MGR *mod_mgr)
{
    MOD_NODE *remote_mod_node;
    TASK_BRD *task_brd;
    UINT32 pos;

    UINT32 load;

    task_brd = task_brd_default_get();

    pos = cvector_search_front(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node, (CVECTOR_DATA_CMP)mod_node_cmp);
    if(CVECTOR_ERR_POS == pos)/*not found*/
    {
        dbg_log(SEC_0108_MOD, 0)(LOGSTDOUT, "error:mod_mgr_remote_mod_load_dec: failed to match mod_node %p: (tcid %s, comm %ld, rank %ld, modi %ld)\n",
                        mod_node,
                        MOD_NODE_TCID_STR(mod_node), MOD_NODE_COMM(mod_node),
                        MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node));
        //dbg_log(SEC_0108_MOD, 9)(LOGSTDOUT, "[DEBUG] mod_mgr_remote_mod_load_dec: remote mod node list:\n");
        //cvector_print(LOGSTDOUT, MOD_MGR_REMOTE_LIST(mod_mgr), (CVECTOR_DATA_PRINT)mod_node_print);
        return (EC_FALSE);
    }

    if(0 == except_mod_node || EC_FALSE == mod_node_cmp(mod_node, except_mod_node))
    {
        remote_mod_node = (MOD_NODE *)cvector_get(MOD_MGR_REMOTE_LIST(mod_mgr), pos);

        load = MOD_NODE_LOAD_GET_QUE(task_brd, remote_mod_node) - decreasement;
#if 0
        dbg_log(SEC_0108_MOD, 5)(LOGSTDOUT, "remote mod load decrease: mod_mgr %p: (comm %ld, rank %ld, modi %ld): load %ld -> %ld\n",
                        mod_mgr,
                        MOD_NODE_COMM(mod_node), MOD_NODE_RANK(mod_node), MOD_NODE_MODI(mod_node),
                        MOD_NODE_LOAD(remote_mod_node),load);
#endif
        MOD_NODE_LOAD_SET_QUE(task_brd, remote_mod_node, load);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
