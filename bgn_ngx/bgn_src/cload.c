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

#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "type.h"
#include "mm.h"
#include "clist.h"
#include "cvector.h"
#include "cload.h"
#include "cmisc.h"
#include "cmpic.inc"
#include "task.h"
#include "log.h"

#define CLOAD_TCID_ASSERT_RETURN_LOAD(info, tcid) do{\
    if(0 == (tcid) || ((tcid) & 0xFFFFFFFF) == 0xFFFFFFFF) {\
        dbg_log(SEC_0086_CLOAD, 9)(LOGSTDOUT, "[DEBUG]%s error: tcid = %s\n", (info), c_word_to_ipv4(tcid));\
        return ((UINT32)-1);\
    }\
    return ((UINT32)0);\
}while(0)


CLOAD_STAT *cload_stat_new()
{
    CLOAD_STAT *cload_stat;

    alloc_static_mem(MM_CLOAD_STAT, &cload_stat, LOC_CLOAD_0001);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_stat_new: new cload stat failed\n");
        return (NULL_PTR);
    }
    cload_stat_init(cload_stat);
    return (cload_stat);
}

EC_BOOL cload_stat_init(CLOAD_STAT *cload_stat)
{
    CLOAD_STAT_QUE_LOAD(cload_stat) = 0;
    CLOAD_STAT_OBJ_LOAD(cload_stat) = 0;
    CLOAD_STAT_CPU_LOAD(cload_stat) = 0;
    CLOAD_STAT_MEM_LOAD(cload_stat) = 0;
    CLOAD_STAT_DSK_LOAD(cload_stat) = 0;
    CLOAD_STAT_NET_LOAD(cload_stat) = 0;
    CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat));
    return (EC_TRUE);
}

EC_BOOL cload_stat_clean(CLOAD_STAT *cload_stat)
{
    CLOAD_STAT_QUE_LOAD(cload_stat) = 0;
    CLOAD_STAT_OBJ_LOAD(cload_stat) = 0;
    CLOAD_STAT_CPU_LOAD(cload_stat) = 0;
    CLOAD_STAT_MEM_LOAD(cload_stat) = 0;
    CLOAD_STAT_DSK_LOAD(cload_stat) = 0;
    CLOAD_STAT_NET_LOAD(cload_stat) = 0;
    //CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat));
    return (EC_TRUE);
}

EC_BOOL cload_stat_free(CLOAD_STAT *cload_stat)
{
    if(NULL_PTR != cload_stat)
    {
        cload_stat_clean(cload_stat);
        free_static_mem(MM_CLOAD_STAT, cload_stat, LOC_CLOAD_0002);
    }
    return (EC_TRUE);
}

EC_BOOL cload_stat_clone(const CLOAD_STAT *cload_stat_src, CLOAD_STAT *cload_stat_des)
{
    CLOAD_STAT_QUE_LOAD(cload_stat_des) = CLOAD_STAT_QUE_LOAD(cload_stat_src);
    CLOAD_STAT_OBJ_LOAD(cload_stat_des) = CLOAD_STAT_OBJ_LOAD(cload_stat_src);
    CLOAD_STAT_CPU_LOAD(cload_stat_des) = CLOAD_STAT_CPU_LOAD(cload_stat_src);
    CLOAD_STAT_MEM_LOAD(cload_stat_des) = CLOAD_STAT_MEM_LOAD(cload_stat_src);
    CLOAD_STAT_DSK_LOAD(cload_stat_des) = CLOAD_STAT_DSK_LOAD(cload_stat_src);
    CLOAD_STAT_NET_LOAD(cload_stat_des) = CLOAD_STAT_NET_LOAD(cload_stat_src);
    CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat_des));
    return (EC_TRUE);
}

EC_BOOL cload_stat_update(const CLOAD_STAT *cload_stat_src, CLOAD_STAT *cload_stat_des)
{
    CLOAD_STAT_QUE_LOAD(cload_stat_des) = CLOAD_STAT_QUE_LOAD(cload_stat_src);
    CLOAD_STAT_OBJ_LOAD(cload_stat_des) = CLOAD_STAT_OBJ_LOAD(cload_stat_src);
    CLOAD_STAT_CPU_LOAD(cload_stat_des) = CLOAD_STAT_CPU_LOAD(cload_stat_src);
    CLOAD_STAT_MEM_LOAD(cload_stat_des) = CLOAD_STAT_MEM_LOAD(cload_stat_src);
    CLOAD_STAT_DSK_LOAD(cload_stat_des) = CLOAD_STAT_DSK_LOAD(cload_stat_src);
    CLOAD_STAT_NET_LOAD(cload_stat_des) = CLOAD_STAT_NET_LOAD(cload_stat_src);
    CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat_des));
    return (EC_TRUE);
}

EC_BOOL cload_stat_set_que(CLOAD_STAT *cload_stat, const UINT32 que_load)
{
    CLOAD_STAT_QUE_LOAD(cload_stat) = (UINT16)que_load;
    CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat));
    return (EC_TRUE);
}

EC_BOOL cload_stat_inc_que(CLOAD_STAT *cload_stat)
{
    CLOAD_STAT_QUE_LOAD(cload_stat) ++;
    CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat));
    return (EC_TRUE);
}

EC_BOOL cload_stat_dec_que(CLOAD_STAT *cload_stat)
{
    if(0 < CLOAD_STAT_QUE_LOAD(cload_stat))
    {
        CLOAD_STAT_QUE_LOAD(cload_stat) --;
    }
    CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat));
    return (EC_TRUE);
}

CLOAD_NODE *cload_node_new(const UINT32 tcid, const UINT32 comm, const UINT32 size)
{
    CLOAD_NODE *cload_node;

    if(0 == tcid || 0xffffffff == (tcid & 0xffffffff) || 0x10000 < size)/*shit! debug here!*/
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_new: invalid tcid %s or size %ld\n", c_word_to_ipv4(tcid), size);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CLOAD_NODE, &cload_node, LOC_CLOAD_0003);
    if(NULL_PTR == cload_node)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_new: new cload node failed\n");
        return (NULL_PTR);
    }
    cload_node_init(cload_node, tcid, comm, size);
    return (cload_node);
}

EC_BOOL cload_node_init(CLOAD_NODE *cload_node, const UINT32 tcid, const UINT32 comm, const UINT32 size)
{
    UINT32 rank;
    CLOAD_NODE_TCID(cload_node) = tcid;
    CLOAD_NODE_COMM(cload_node) = comm;


    cvector_init(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), size, MM_CLOAD_STAT, CVECTOR_LOCK_ENABLE, LOC_CLOAD_0004);
    for(rank = 0; rank < size; rank ++)
    {
        CLOAD_STAT *cload_stat;

        cload_stat = cload_stat_new();
        cvector_push_no_lock(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), (void *)cload_stat);
    }

    return (EC_TRUE);
}

EC_BOOL cload_node_clean(CLOAD_NODE *cload_node)
{
    CLOAD_NODE_TCID(cload_node) = CMPI_ERROR_TCID;
    cvector_clean(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), (CVECTOR_DATA_CLEANER)cload_stat_free, LOC_CLOAD_0005);
    return (EC_TRUE);
}

EC_BOOL cload_node_free(CLOAD_NODE *cload_node)
{
    if(NULL_PTR != cload_node)
    {
        cload_node_clean(cload_node);
        free_static_mem(MM_CLOAD_NODE, cload_node, LOC_CLOAD_0006);
    }
    return (EC_TRUE);
}

EC_BOOL cload_node_clone(const CLOAD_NODE *cload_node_src, CLOAD_NODE *cload_node_des)
{
    cload_node_clean(cload_node_des);
    CLOAD_NODE_TCID(cload_node_des) = CLOAD_NODE_TCID(cload_node_src);
    cvector_clone(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_src), CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_des),
                  (CVECTOR_DATA_MALLOC)cload_stat_new, (CVECTOR_DATA_CLONE)cload_stat_clone);
    return (EC_TRUE);
}

EC_BOOL cload_node_update(const CLOAD_NODE *cload_node_src, CLOAD_NODE *cload_node_des)
{
    UINT32 src_size;
    UINT32 des_size;

    UINT32 pos;
    UINT32 local_tcid;
    UINT32 local_rank;

    if(CLOAD_NODE_TCID(cload_node_des) != CLOAD_NODE_TCID(cload_node_src))
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_update: tcid not matched: src tcid %s, des tcid %s\n",
                            CLOAD_NODE_TCID_STR(cload_node_src), CLOAD_NODE_TCID_STR(cload_node_des));
        return (EC_FALSE);
    }

    src_size = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_src));
    des_size = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_des));

    local_tcid = CMPI_LOCAL_TCID;
    local_rank = CMPI_LOCAL_RANK;

    if(src_size <= des_size)
    {
        for(pos = 0; pos < src_size; pos ++)
        {
            if(local_tcid != CLOAD_NODE_TCID(cload_node_des) || local_rank != pos)/*not update local rank load*/
            {
                CLOAD_STAT *cload_stat_src;
                CLOAD_STAT *cload_stat_des;

                cload_stat_src = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_src), pos);
                cload_stat_des = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_des), pos);

                cload_stat_update(cload_stat_src, cload_stat_des);
                //dbg_log(SEC_0086_CLOAD, 9)(LOGSTDOUT, "[DEBUG] cload_node_update[1]: load_src %ld, load_des %ld => %ld\n", load_src, load_des, CLOAD_MAKE(load_des, load_src));
            }
        }
    }
    else
    {
        for(pos = 0; pos < des_size; pos ++)
        {
            if(local_tcid != CLOAD_NODE_TCID(cload_node_des) || local_rank != pos)/*not update local rank load*/
            {
                CLOAD_STAT *cload_stat_src;
                CLOAD_STAT *cload_stat_des;

                cload_stat_src = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_src), pos);
                cload_stat_des = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_des), pos);

                cload_stat_update(cload_stat_src, cload_stat_des);
                //dbg_log(SEC_0086_CLOAD, 9)(LOGSTDOUT, "[DEBUG] cload_node_update[1]: load_src %ld, load_des %ld => %ld\n", load_src, load_des, CLOAD_MAKE(load_des, load_src));
            }
        }
        for(;pos < src_size; pos ++)
        {
            CLOAD_STAT *cload_stat_src;
            CLOAD_STAT *cload_stat_des;

            cload_stat_src = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_src), pos);
            cload_stat_des = cload_stat_new();
            cload_stat_clone(cload_stat_src, cload_stat_des);

            cvector_push(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node_des), (void *)cload_stat_des);
        }
    }

    return (EC_TRUE);
}

void cload_node_print(LOG *log, const CLOAD_NODE *cload_node)
{
    UINT32 rank;
    UINT32 size;

    size = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node));
    sys_log(log, "tcid %s, rank load vec size = %ld \n", CLOAD_NODE_TCID_STR(cload_node), size);
    for(rank = 0; rank < size; rank ++)
    {
        CLOAD_STAT *cload_stat;
        cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
        if(NULL_PTR != cload_stat)
        {
            sys_log(log, "\t\trank %ld load (que %d, obj %d, cpu %d, mem %d, dsk %d, net %d), \n",
                            rank,
                            CLOAD_STAT_QUE_LOAD(cload_stat),
                            CLOAD_STAT_OBJ_LOAD(cload_stat),
                            CLOAD_STAT_CPU_LOAD(cload_stat),
                            CLOAD_STAT_MEM_LOAD(cload_stat),
                            CLOAD_STAT_DSK_LOAD(cload_stat),
                            CLOAD_STAT_NET_LOAD(cload_stat)
                            );
        }
    }
    sys_print(log, "\n");
}

EC_BOOL cload_node_init_0(CLOAD_NODE *cload_node)
{
    return cload_node_init(cload_node, CMPI_ERROR_TCID, CMPI_ERROR_COMM, 0);
}

CLOAD_STAT * cload_node_get(CLOAD_NODE *cload_node, const UINT32 rank)
{
    CLOAD_STAT *cload_stat;

    cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_get: rank overflow where tcid %s, rank %ld but size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        return (NULL_PTR);
    }

    return cload_stat;
}

EC_BOOL cload_node_set(CLOAD_NODE *cload_node, const UINT32 rank, const CLOAD_STAT *cload_stat_src)
{
    UINT32 pos;

    //dbg_log(SEC_0086_CLOAD, 9)(LOGSTDOUT, "[DEBUG] cload_node_set_que: try to set tcid %s rank %ld load %ld\n", CLOAD_NODE_TCID_STR(cload_node), rank, load);

    for(pos = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)); pos <= rank; pos ++)
    {
        CLOAD_STAT *cload_stat_des;
        cload_stat_des = cload_stat_new();

        cvector_push(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), (void *)cload_stat_des);
    }

    if(rank < cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)))
    {
        CLOAD_STAT *cload_stat_des;
        cload_stat_des = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
        cload_stat_clone(cload_stat_src, cload_stat_des);
        return (EC_TRUE);
    }
    dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_set_que: unknown issue where tcid %s, rank %ld but rank load vec size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
    return (EC_FALSE);
}

EC_BOOL cload_node_set_que(CLOAD_NODE *cload_node, const UINT32 rank, const UINT32 que_load)
{
    UINT32 pos;

    //dbg_log(SEC_0086_CLOAD, 9)(LOGSTDOUT, "[DEBUG] cload_node_set_que: try to set tcid %s rank %ld load %ld\n", CLOAD_NODE_TCID_STR(cload_node), rank, load);

    for(pos = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)); pos <= rank; pos ++)
    {
        CLOAD_STAT *cload_stat;
        cload_stat = cload_stat_new();

        cvector_push(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), (void *)cload_stat);
    }

    if(rank < cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)))
    {
        CLOAD_STAT *cload_stat;
        cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
        cload_stat_set_que(cload_stat, que_load);
        return (EC_TRUE);
    }
    dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_set_que: unknown issue where tcid %s, rank %ld, que load %ld but rank load vec size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, que_load, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
    return (EC_FALSE);
}

UINT32 cload_node_get_que(CLOAD_NODE *cload_node, const UINT32 rank)
{
    CLOAD_STAT *cload_stat;

    cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_get_que: rank overflow where tcid %s, rank %ld but size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        return ((UINT32)0);
    }

    return CLOAD_STAT_QUE_LOAD(cload_stat);
}

EC_BOOL cload_node_inc_que(CLOAD_NODE *cload_node, const UINT32 rank)
{
    UINT32 pos;

    for(pos = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)); pos <= rank; pos ++)
    {
        CLOAD_STAT *cload_stat;
        cload_stat = cload_stat_new();
        cvector_push(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), (void *)cload_stat);
    }

    if(rank < cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)))
    {
        CLOAD_STAT *cload_stat;

        cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
        cload_stat_inc_que(cload_stat);
        return (EC_TRUE);
    }
    dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_inc_que: unknown issue where tcid %s, rank %ld, but rank load vec size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
    return (EC_FALSE);
}

EC_BOOL cload_node_dec_que(CLOAD_NODE *cload_node, const UINT32 rank)
{
    UINT32 pos;

    for(pos = cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)); pos <= rank; pos ++)
    {
        CLOAD_STAT *cload_stat;
        cload_stat = cload_stat_new();
        cvector_push(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), (void *)cload_stat);
    }

    if(rank < cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)))
    {
        CLOAD_STAT *cload_stat;

        cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
        cload_stat_dec_que(cload_stat);
        return (EC_TRUE);
    }
    dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_dec_que: unknown issue where tcid %s, rank %ld, but rank load vec size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
    return (EC_FALSE);
}

EC_BOOL cload_node_fast_dec_que(CLOAD_NODE *cload_node, const UINT32 interval_nsec)
{
    CTIMET cur;
    UINT32 rank;

    CTIMET_GET(cur);
    for(rank = 0; rank < cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)); rank ++)
    {
        CLOAD_STAT *cload_stat;
        UINT32 elapsed_time_from_last_update;

        cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
        elapsed_time_from_last_update = lrint(CTIMET_DIFF(CLOAD_STAT_LAST_UPDATE(cload_stat), cur));
        if(elapsed_time_from_last_update > interval_nsec)
        {
            CLOAD_STAT_QUE_LOAD(cload_stat) >>= 1; /*decrease half*/
            CTIMET_GET(CLOAD_STAT_LAST_UPDATE(cload_stat));
        }
    }
    return (EC_TRUE);
}

EC_BOOL cload_node_cmp_tcid(const CLOAD_NODE *cload_node_1st, const CLOAD_NODE *cload_node_2nd)
{
    if(CLOAD_NODE_TCID(cload_node_1st) == CLOAD_NODE_TCID(cload_node_2nd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

UINT32 cload_node_get_obj(CLOAD_NODE *cload_node, const UINT32 rank)
{
    CLOAD_STAT *cload_stat;

    cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_get_obj: rank overflow where tcid %s, rank %ld but size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        return ((UINT32)0);
    }

    return CLOAD_STAT_OBJ_LOAD(cload_stat);
}

UINT32 cload_node_get_cpu(CLOAD_NODE *cload_node, const UINT32 rank)
{
    CLOAD_STAT *cload_stat;

    cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_get_cpu: rank overflow where tcid %s, rank %ld but size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        return ((UINT32)0);
    }

    return CLOAD_STAT_CPU_LOAD(cload_stat);
}

UINT32 cload_node_get_mem(CLOAD_NODE *cload_node, const UINT32 rank)
{
    CLOAD_STAT *cload_stat;

    cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_get_mem: rank overflow where tcid %s, rank %ld but size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        return ((UINT32)0);
    }

    return CLOAD_STAT_MEM_LOAD(cload_stat);
}

UINT32 cload_node_get_dsk(CLOAD_NODE *cload_node, const UINT32 rank)
{
    CLOAD_STAT *cload_stat;

    cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_get_dsk: rank overflow where tcid %s, rank %ld but size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        return ((UINT32)0);
    }

    return CLOAD_STAT_DSK_LOAD(cload_stat);
}

UINT32 cload_node_get_net(CLOAD_NODE *cload_node, const UINT32 rank)
{
    CLOAD_STAT *cload_stat;

    cload_stat = (CLOAD_STAT *)cvector_get(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node), rank);
    if(NULL_PTR == cload_stat)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_node_get_net: rank overflow where tcid %s, rank %ld but size %ld\n",
                    CLOAD_NODE_TCID_STR(cload_node), rank, cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        return ((UINT32)0);
    }

    return CLOAD_STAT_NET_LOAD(cload_stat);
}

CLIST *cload_mgr_new()
{
    CLIST *cload_mgr;

    alloc_static_mem(MM_CLIST, &cload_mgr, LOC_CLOAD_0007);
    if(NULL_PTR != cload_mgr)
    {
        cload_mgr_init(cload_mgr);
    }
    return (cload_mgr);
}

EC_BOOL cload_mgr_init(CLIST *cload_mgr)
{
    clist_init(cload_mgr, MM_IGNORE, LOC_CLOAD_0008);
    return (EC_TRUE);
}

EC_BOOL cload_mgr_clean(CLIST *cload_mgr)
{
    clist_clean(cload_mgr, (CLIST_DATA_DATA_CLEANER)cload_node_free);
    return (EC_TRUE);
}

EC_BOOL cload_mgr_free(CLIST *cload_mgr)
{
    cload_mgr_clean(cload_mgr);
    free_static_mem(MM_CLIST, cload_mgr, LOC_CLOAD_0009);
    return (EC_TRUE);
}

EC_BOOL cload_mgr_add(CLIST *cload_mgr, const CLOAD_NODE *cload_node)
{
    if(NULL_PTR != clist_search_front(cload_mgr, (void *)cload_node, (CLIST_DATA_DATA_CMP)cload_node_cmp_tcid))
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_mgr_add: cload node of tcid %s already exist\n", CLOAD_NODE_TCID_STR(cload_node));
        return (EC_FALSE);
    }
    clist_push_back(cload_mgr, (void *)cload_node);
    return (EC_TRUE);
}

EC_BOOL cload_mgr_rmv(CLIST *cload_mgr, const CLOAD_NODE *cload_node)
{
    CLIST_DATA *clist_data;

    clist_data = clist_search_front(cload_mgr, (void *)cload_node, (CLIST_DATA_DATA_CMP)cload_node_cmp_tcid);
    if(NULL_PTR == clist_data)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_mgr_rmv: cload node of tcid %s not exist\n", CLOAD_NODE_TCID_STR(cload_node));
        return (EC_FALSE);
    }
    clist_rmv(cload_mgr, clist_data);

    return (EC_TRUE);
}

EC_BOOL cload_mgr_update(CLIST *cload_mgr, const CLOAD_NODE *cload_node)
{
    CLIST_DATA *clist_data;
    CLOAD_NODE *cload_node_des;

    clist_data = clist_search_front(cload_mgr, (void *)cload_node, (CLIST_DATA_DATA_CMP)cload_node_cmp_tcid);
    if(NULL_PTR == clist_data)
    {
        cload_node_des = cload_node_new(CLOAD_NODE_TCID(cload_node), CLOAD_NODE_COMM(cload_node), cvector_size(CLOAD_NODE_RANK_LOAD_STAT_VEC(cload_node)));
        cload_node_clone(cload_node, cload_node_des);
        clist_push_back(cload_mgr, (void *)cload_node_des);
        return (EC_TRUE);
    }

    cload_node_des = (CLOAD_NODE *)CLIST_DATA_DATA(clist_data);
    return cload_node_update(cload_node, cload_node_des);
}

CLOAD_NODE * cload_mgr_search(const CLIST *cload_mgr, const UINT32 tcid)
{
    CLOAD_NODE cload_node;
    CLIST_DATA *clist_data;

    CLOAD_NODE_TCID(&cload_node) = tcid;
    clist_data = clist_search_front(cload_mgr, (void *)&cload_node, (CLIST_DATA_DATA_CMP)cload_node_cmp_tcid);
    if(NULL_PTR == clist_data)
    {
        //dbg_log(SEC_0086_CLOAD, 1)(LOGSTDOUT, "warn:cload_mgr_search: cload node of tcid %s not exist\n", c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    return (CLOAD_NODE *)CLIST_DATA_DATA(clist_data);
}

CLOAD_STAT * cload_mgr_get(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_get(cload_node, rank);
    }

    dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_mgr_get: no cload node for tcid %s rank %ld\n", c_word_to_ipv4(tcid), rank);
    return (NULL_PTR);
}

EC_BOOL cload_mgr_set(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank, const CLOAD_STAT *cload_stat)
{
    CLOAD_NODE *cload_node;

    //dbg_log(SEC_0086_CLOAD, 9)(LOGSTDOUT, "[DEBUG] cload_mgr_set: try to set tcid %s rank %ld load %ld\n", c_word_to_ipv4(tcid), rank, load);

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_set(cload_node, rank, cload_stat);
    }

    cload_node = cload_node_new(tcid, CMPI_ANY_COMM, rank + 1);
    if(NULL_PTR == cload_node)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_mgr_set_que: new cload node for tcid %s, size %ld failed\n",
                            c_word_to_ipv4(tcid), rank + 1);
        return (EC_FALSE);
    }
    clist_push_back(cload_mgr, (void *)cload_node);

    return cload_node_set(cload_node, rank, cload_stat);
}

EC_BOOL cload_mgr_set_que(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank, const UINT32 que_load)
{
    CLOAD_NODE *cload_node;

    //dbg_log(SEC_0086_CLOAD, 9)(LOGSTDOUT, "[DEBUG] cload_mgr_set: try to set tcid %s rank %ld load %ld\n", c_word_to_ipv4(tcid), rank, que_load);

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_set_que(cload_node, rank, que_load);
    }

    cload_node = cload_node_new(tcid, CMPI_ANY_COMM, rank + 1);
    if(NULL_PTR == cload_node)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_mgr_set_que: new cload node for tcid %s, size %ld failed\n",
                            c_word_to_ipv4(tcid), rank + 1);
        return (EC_FALSE);
    }
    clist_push_back(cload_mgr, (void *)cload_node);

    return cload_node_set_que(cload_node, rank, que_load);
}

UINT32 cload_mgr_get_que(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_get_que(cload_node, rank);
    }
    CLOAD_TCID_ASSERT_RETURN_LOAD("cload_mgr_get_que", tcid);
    //return ((UINT32)0);
}

UINT32 cload_mgr_get_obj(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_get_obj(cload_node, rank);
    }
    CLOAD_TCID_ASSERT_RETURN_LOAD("cload_mgr_get_obj", tcid);
    //return ((UINT32)0);
}

UINT32 cload_mgr_get_cpu(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_get_cpu(cload_node, rank);
    }
    CLOAD_TCID_ASSERT_RETURN_LOAD("cload_mgr_get_cpu", tcid);
    //return ((UINT32)0);
}

UINT32 cload_mgr_get_mem(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_get_mem(cload_node, rank);
    }
    CLOAD_TCID_ASSERT_RETURN_LOAD("cload_mgr_get_mem", tcid);
    //return ((UINT32)0);
}

UINT32 cload_mgr_get_dsk(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_get_dsk(cload_node, rank);
    }
    CLOAD_TCID_ASSERT_RETURN_LOAD("cload_mgr_get_dsk", tcid);
    //return ((UINT32)0);
}

UINT32 cload_mgr_get_net(const CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_get_net(cload_node, rank);
    }
    CLOAD_TCID_ASSERT_RETURN_LOAD("cload_mgr_get_net", tcid);
    //return ((UINT32)0);
}

EC_BOOL cload_mgr_del(CLIST *cload_mgr, const UINT32 tcid)
{
    CLOAD_NODE  cload_node_t;
    CLOAD_NODE *cload_node;
    CLIST_DATA *clist_data;

    CLOAD_NODE_TCID(&cload_node_t) = tcid;
    clist_data = clist_search_front(cload_mgr, (void *)&cload_node_t, (CLIST_DATA_DATA_CMP)cload_node_cmp_tcid);
    if(NULL_PTR == clist_data)
    {
        //dbg_log(SEC_0086_CLOAD, 7)(LOGSTDOUT, "error:cload_mgr_del: cload node of tcid %s not exist\n", c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    cload_node = (CLOAD_NODE *)clist_rmv(cload_mgr, clist_data);
    cload_node_free(cload_node);
    return (EC_TRUE);
}

EC_BOOL cload_mgr_inc_que(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_inc_que(cload_node, rank);
    }

    cload_node = cload_node_new(tcid, CMPI_ANY_COMM, rank + 1);
    if(NULL_PTR == cload_node)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_mgr_inc_que: new cload node for tcid %s, size %ld failed\n",
                            c_word_to_ipv4(tcid), rank + 1);
        return (EC_FALSE);
    }
    clist_push_back(cload_mgr, (void *)cload_node);

    return cload_node_inc_que(cload_node, rank);
}

EC_BOOL cload_mgr_dec_que(CLIST *cload_mgr, const UINT32 tcid, const UINT32 rank)
{
    CLOAD_NODE *cload_node;

    cload_node = cload_mgr_search(cload_mgr, tcid);
    if(NULL_PTR != cload_node)
    {
        return cload_node_dec_que(cload_node, rank);
    }

    cload_node = cload_node_new(tcid, CMPI_ANY_COMM, rank + 1);
    if(NULL_PTR == cload_node)
    {
        dbg_log(SEC_0086_CLOAD, 0)(LOGSTDOUT, "error:cload_mgr_dec_que: new cload node for tcid %s, size %ld failed\n",
                            c_word_to_ipv4(tcid), rank + 1);
        return (EC_FALSE);
    }
    clist_push_back(cload_mgr, (void *)cload_node);

    return (EC_TRUE);
}

EC_BOOL cload_mgr_fast_decrease(CLIST *cload_mgr, const UINT32 interval_nsec)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(cload_mgr, LOC_CLOAD_0010);
    CLIST_LOOP_NEXT(cload_mgr, clist_data)
    {
        CLOAD_NODE *cload_node;
        cload_node = (CLOAD_NODE *)CLIST_DATA_DATA(clist_data);
        cload_node_fast_dec_que(cload_node, interval_nsec);
    }
    CLIST_UNLOCK(cload_mgr, LOC_CLOAD_0011);
    return (EC_TRUE);
}

void cload_mgr_print(LOG *log, const CLIST *cload_mgr)
{
    clist_print(log, cload_mgr, (CLIST_DATA_DATA_PRINT)cload_node_print);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

