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

#include "mm.h"
#include "log.h"
#include "debug.h"

#include "cset.h"

#include "task.h"

static EC_BOOL rank_cmp(const void * src_rank, const void * des_rank)
{
    if(((UINT32)src_rank) == ((UINT32)des_rank))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

static void rank_print(LOG *log, void * rank)
{
    dbg_log(SEC_0095_RANK, 5)(LOGSTDOUT, "rank: %ld\n", (UINT32)rank);
}

EC_BOOL rank_set_new(CSET **rank_set)
{
    *rank_set = cset_new(MM_IGNORE, LOC_RANK_0001);
    return (EC_TRUE);
}

EC_BOOL rank_set_clean(CSET *rank_set)
{
    cset_clean(rank_set, NULL_PTR);
    return (EC_TRUE);
}

EC_BOOL rank_set_free(CSET *rank_set)
{
    cset_clean(rank_set, NULL_PTR);
    cset_free(rank_set, LOC_RANK_0002);

    return (EC_TRUE);
}

UINT32 rank_set_incl(CSET *rank_set, const UINT32 rank)
{
    if(!cset_search(rank_set, (const void *)rank, rank_cmp))
    {
        cset_add(rank_set, (void *)rank, NULL_PTR);
    }

    return (0);
}

UINT32 rank_set_excl(CSET *rank_set, const UINT32 rank)
{
    cset_erase(rank_set, (void *)rank, rank_cmp);
    return (0);
}

UINT32 rank_set_print(LOG *log, const CSET *rank_set)
{
    cset_print(log, rank_set, (CSET_DATA_PRINT)rank_print);
    return (0);
}

UINT32 rank_set_init(CSET *rank_set, const UINT32 comm_size)
{
    UINT32 rank;
    for(rank = 0; rank < comm_size; rank ++)
    {
        rank_set_incl(rank_set, rank);
    }
    return (0);
}

UINT32 rank_set_default_init(CSET *rank_set)
{
    UINT32 this_comm;
    UINT32 comm_size;

    this_comm = CMPI_LOCAL_COMM;
    comm_size = CMPI_LOCAL_SIZE;

    return rank_set_init(rank_set, comm_size);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
