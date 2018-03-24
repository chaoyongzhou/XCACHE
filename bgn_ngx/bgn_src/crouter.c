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
#include <unistd.h>

#include "type.h"
#include "cmisc.h"
#include "mm.h"

#include "log.h"

#include "clist.h"
#include "cvector.h"

#include "csocket.h"

#include "cmpic.inc"

#include "taskcfg.inc"
#include "taskcfg.h"
#include "tasks.h"

#include "crouter.h"

#include "cmutex.h"

STATIC_CAST static void crouter_cfg_ident_print_xml(LOG *log, const UINT32 level)
{
    UINT32 idx;

    for(idx = 0; idx < level; idx ++)
    {
        sys_print(log, "    ");
    }
    return;
}

CROUTER_NODE *crouter_node_new(const UINT32 des_tcid)
{
    CROUTER_NODE *crouter_node;

    alloc_static_mem(MM_CROUTER_NODE, &crouter_node, LOC_CROUTER_0001);
    crouter_node_init(crouter_node, des_tcid);
    return (crouter_node);
}

EC_BOOL crouter_node_init(CROUTER_NODE *crouter_node, const UINT32 des_tcid)
{
    CROUTER_NODE_DES_TCID(crouter_node) = des_tcid;
    cvector_init(CROUTER_NODE_NEXT_HOPS(crouter_node), 0, MM_TASKS_NODE, CVECTOR_LOCK_ENABLE, LOC_CROUTER_0002);
    return (EC_TRUE);
}

EC_BOOL crouter_node_clean(CROUTER_NODE *crouter_node)
{
    CROUTER_NODE_DES_TCID(crouter_node) = CMPI_ERROR_TCID;
    /*note: here tasks node just save its reference, so do not alloc or free its memory*/
    cvector_clean(CROUTER_NODE_NEXT_HOPS(crouter_node), NULL_PTR, LOC_CROUTER_0003);
    return (EC_TRUE);
}

EC_BOOL crouter_node_free(CROUTER_NODE *crouter_node)
{
    crouter_node_clean(crouter_node);
    free_static_mem(MM_CROUTER_NODE, crouter_node, LOC_CROUTER_0004);
    return (EC_TRUE);
}

CROUTER_NODE *crouter_node_create(const UINT32 des_tcid, const TASKS_NODE *next_hop_tasks_node)
{
    CROUTER_NODE *crouter_node;

    crouter_node = crouter_node_new(des_tcid);
    if(NULL_PTR == crouter_node)
    {
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_create: failed to alloc crouter node for des tcid %s\n", c_word_to_ipv4(des_tcid));
        return (NULL_PTR);
    }

    if(CVECTOR_ERR_POS == cvector_push(CROUTER_NODE_NEXT_HOPS(crouter_node), (void *)next_hop_tasks_node))
    {
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_create: failed to add route (des tcid %s, next hop tcid %s)\n",
                            c_word_to_ipv4(des_tcid), TASKS_NODE_TCID_STR(next_hop_tasks_node));
        crouter_node_free(crouter_node);
        return (NULL_PTR);
    }

    return (crouter_node);
}

EC_BOOL crouter_node_is_empty(const CROUTER_NODE *crouter_node)
{
    return cvector_is_empty(CROUTER_NODE_NEXT_HOPS(crouter_node));
}

void crouter_node_print(LOG *log, const CROUTER_NODE *crouter_node)
{
    sys_log(log, "crouter_node %lx: des_tcid %s, next hops %lx:\n",
                 crouter_node, CROUTER_NODE_DES_TCID_STR(crouter_node), CROUTER_NODE_NEXT_HOPS(crouter_node));
    cvector_print(log, CROUTER_NODE_NEXT_HOPS(crouter_node), (CVECTOR_DATA_PRINT)tasks_node_print);
    return;
}

void crouter_node_sprint_in_plain(CSTRING *cstring, const CROUTER_NODE *crouter_node, UINT32 *index)
{
    UINT32 pos;

    CVECTOR_LOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0005);
    for(pos = 0; pos < cvector_size(CROUTER_NODE_NEXT_HOPS(crouter_node)); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(CROUTER_NODE_NEXT_HOPS(crouter_node), pos);
        if(NULL_PTR == tasks_node)
        {
            cstring_format(cstring, "Route No. %ld: des tcid %s, next hop [%ld]: (null)\n",
                                    (*index) ++, CROUTER_NODE_DES_TCID_STR(crouter_node), pos);
            continue;
        }

        cstring_format(cstring, "Route No. %ld: des tcid %s, next hop [%ld]: ",
                                (*index) ++, CROUTER_NODE_DES_TCID_STR(crouter_node), pos);
        tasks_node_sprint(cstring, tasks_node);
    }
    CVECTOR_UNLOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0006);
    return;
}

void crouter_node_print_in_plain(LOG *log, const CROUTER_NODE *crouter_node, UINT32 *index)
{
    UINT32 pos;

    CVECTOR_LOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0007);
    for(pos = 0; pos < cvector_size(CROUTER_NODE_NEXT_HOPS(crouter_node)); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(CROUTER_NODE_NEXT_HOPS(crouter_node), pos);
        if(NULL_PTR == tasks_node)
        {
            sys_log(log, "Route No. %ld: des tcid %s, next hop [%ld]: (null)\n",
                        (*index) ++, CROUTER_NODE_DES_TCID_STR(crouter_node), pos);
            continue;
        }

        sys_log(log, "Route No. %ld: des tcid %s, next hop [%ld]: ",
                     (*index) ++, CROUTER_NODE_DES_TCID_STR(crouter_node), pos);
        tasks_node_print_in_plain(log, tasks_node);
    }
    CVECTOR_UNLOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0008);
    return;
}

UINT32 crouter_node_add_next_hop(CROUTER_NODE *crouter_node, const TASKS_NODE *tasks_node)
{
    UINT32 pos;
    pos = cvector_search_front(CROUTER_NODE_NEXT_HOPS(crouter_node), (void *)tasks_node, (CVECTOR_DATA_CMP)tasks_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        return cvector_push(CROUTER_NODE_NEXT_HOPS(crouter_node), (void *)tasks_node);
    }
    return (pos);
}

TASKS_NODE * crouter_node_rmv_next_hop(CROUTER_NODE *crouter_node, const TASKS_NODE *tasks_node)
{
    UINT32 pos;
    pos = cvector_search_front(CROUTER_NODE_NEXT_HOPS(crouter_node), (void *)tasks_node, (CVECTOR_DATA_CMP)tasks_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        return (NULL_PTR);
    }
    return (TASKS_NODE *)cvector_erase(CROUTER_NODE_NEXT_HOPS(crouter_node), pos);
}

TASKS_NODE * crouter_node_rmv_next_hop_by_tcid(CROUTER_NODE *crouter_node, const UINT32 next_hop_tcid)
{
    UINT32 pos;
    pos = crouter_node_search_next_hop_by_tcid(crouter_node, next_hop_tcid);
    if(CVECTOR_ERR_POS == pos)
    {
        return (NULL_PTR);
    }
    return (TASKS_NODE *)cvector_erase(CROUTER_NODE_NEXT_HOPS(crouter_node), pos);
}

TASKS_NODE * crouter_node_rmv_next_hop_by_pos(CROUTER_NODE *crouter_node, const UINT32 next_hop_pos)
{
    return (TASKS_NODE *)cvector_erase(CROUTER_NODE_NEXT_HOPS(crouter_node), next_hop_pos);
}

UINT32 crouter_node_count_next_hop(const CROUTER_NODE *crouter_node)
{
    return cvector_size(CROUTER_NODE_NEXT_HOPS(crouter_node));
}

UINT32 crouter_node_search_next_hop_by_tcid(CROUTER_NODE *crouter_node, const UINT32 next_hop_tcid)
{
    UINT32 pos;

    CVECTOR_LOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0009);
    for(pos = 0; pos < cvector_size(CROUTER_NODE_NEXT_HOPS(crouter_node)); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(CROUTER_NODE_NEXT_HOPS(crouter_node), pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(next_hop_tcid == TASKS_NODE_TCID(tasks_node))
        {
            CVECTOR_UNLOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0010);
            return (pos);
        }
    }
    CVECTOR_UNLOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0011);
    return (CVECTOR_ERR_POS);
}

TASKS_NODE *crouter_node_find_next_hop_by_tcid(CROUTER_NODE *crouter_node, const UINT32 next_hop_tcid)
{
    UINT32 pos;

    CVECTOR_LOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0012);
    for(pos = 0; pos < cvector_size(CROUTER_NODE_NEXT_HOPS(crouter_node)); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(CROUTER_NODE_NEXT_HOPS(crouter_node), pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(next_hop_tcid == TASKS_NODE_TCID(tasks_node))
        {
            CVECTOR_UNLOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0013);
            return (tasks_node);
        }
    }
    CVECTOR_UNLOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0014);
    return (NULL_PTR);
}

TASKS_NODE * crouter_node_min_load_next_hop(const CROUTER_NODE *crouter_node)
{
    UINT32      pos;
    UINT32      min_load;
    TASKS_NODE *min_tasks_node;

    min_load = ((UINT32)-1);
    min_tasks_node = NULL_PTR;

    CVECTOR_LOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0015);
    for(pos = 0; pos < cvector_size(CROUTER_NODE_NEXT_HOPS(crouter_node)); pos ++)
    {
        TASKS_NODE *tasks_node;
        UINT32 cur_load;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(CROUTER_NODE_NEXT_HOPS(crouter_node), pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        cur_load = TASKS_NODE_LOAD(tasks_node);/*replace it when TASKS_NOE implement load*/
        if(min_load > cur_load)
        {
            min_load = cur_load;
            min_tasks_node = tasks_node;
        }
    }
    CVECTOR_UNLOCK(CROUTER_NODE_NEXT_HOPS(crouter_node), LOC_CROUTER_0016);

    return (min_tasks_node);
}

CROUTER_NODE_VEC *crouter_node_vec_new()
{
    CROUTER_NODE_VEC *crouter_node_vec;

    alloc_static_mem(MM_CROUTER_NODE_VEC, &crouter_node_vec, LOC_CROUTER_0017);
    crouter_node_vec_init(crouter_node_vec);
    return (crouter_node_vec);
}

EC_BOOL crouter_node_vec_init(CROUTER_NODE_VEC *crouter_node_vec)
{
    cvector_init(CROUTER_NODE_VEC_NODES(crouter_node_vec), 0, MM_CROUTER_NODE, CVECTOR_LOCK_ENABLE, LOC_CROUTER_0018);
    return (EC_TRUE);
}

EC_BOOL crouter_node_vec_clean(CROUTER_NODE_VEC *crouter_node_vec)
{
    cvector_clean(CROUTER_NODE_VEC_NODES(crouter_node_vec), (CVECTOR_DATA_CLEANER)crouter_node_free, LOC_CROUTER_0019);
    return (EC_TRUE);
}

EC_BOOL crouter_node_vec_free(CROUTER_NODE_VEC *crouter_node_vec)
{
    crouter_node_vec_clean(crouter_node_vec);
    free_static_mem(MM_CROUTER_NODE_VEC, crouter_node_vec, LOC_CROUTER_0020);
    return (EC_TRUE);
}

CROUTER_NODE *crouter_node_vec_get(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos)
{
    return (CROUTER_NODE *)cvector_get(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
}

CROUTER_NODE *crouter_node_vec_get_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos)
{
    return (CROUTER_NODE *)cvector_get_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
}

CROUTER_NODE *crouter_node_vec_add(CROUTER_NODE_VEC *crouter_node_vec, const TASKS_WORKER *tasks_worker, const UINT32 des_tcid, const UINT32 next_hop_tcid)
{
    TASKS_NODE   *next_hop_tasks_node;
    CROUTER_NODE *crouter_node;

    next_hop_tasks_node = tasks_worker_search_tasks_node_by_tcid(tasks_worker, next_hop_tcid);
    if(NULL_PTR == next_hop_tasks_node)
    {
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_add: next hop tcid %s does not exist\n", c_word_to_ipv4(next_hop_tcid));
        return (NULL_PTR);
    }

    CVECTOR_LOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0021);
    crouter_node = crouter_node_vec_find_no_lock(crouter_node_vec, des_tcid);
    if(NULL_PTR == crouter_node)
    {
        crouter_node = crouter_node_create(des_tcid, next_hop_tasks_node);
        if(NULL_PTR == crouter_node)
        {
            CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0022);
            dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_add: failed to create route (des tcid %s, next hop tcid %s)\n",
                                c_word_to_ipv4(des_tcid), TASKS_NODE_TCID_STR(next_hop_tasks_node));
            return (NULL_PTR);
        }

        cvector_push_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), (void *)crouter_node);
        CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0023);
        return (crouter_node);
    }

    if(CVECTOR_ERR_POS == crouter_node_add_next_hop(crouter_node, next_hop_tasks_node))
    {
        CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0024);
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_add: failed to add route (des tcid %s, next hop tcid %s)\n",
                            c_word_to_ipv4(des_tcid), c_word_to_ipv4(next_hop_tcid));
        return (NULL_PTR);
    }

    CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0025);
    return (crouter_node);
}

CROUTER_NODE *crouter_node_vec_add_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const TASKS_WORKER *tasks_worker, const UINT32 des_tcid, const UINT32 next_hop_tcid)
{
    TASKS_NODE   *next_hop_tasks_node;
    CROUTER_NODE *crouter_node;

    next_hop_tasks_node = tasks_worker_search_tasks_node_by_tcid(tasks_worker, next_hop_tcid);
    if(NULL_PTR == next_hop_tasks_node)
    {
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_add_no_lock: next hop tcid %s does not exist\n", c_word_to_ipv4(next_hop_tcid));
        return (NULL_PTR);
    }

    crouter_node = crouter_node_vec_find_no_lock(crouter_node_vec, des_tcid);
    if(NULL_PTR == crouter_node)
    {
        crouter_node = crouter_node_create(des_tcid, next_hop_tasks_node);
        if(NULL_PTR == crouter_node)
        {
            dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_add: failed to create route (des tcid %s, next hop tcid %s)\n",
                                c_word_to_ipv4(des_tcid), TASKS_NODE_TCID_STR(next_hop_tasks_node));
            return (NULL_PTR);
        }

        cvector_push_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), (void *)crouter_node);
        return (crouter_node);
    }

    if(CVECTOR_ERR_POS == crouter_node_add_next_hop(crouter_node, next_hop_tasks_node))
    {
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_add_no_lock: failed to add route (des tcid %s, next hop tcid %s)\n",
                            c_word_to_ipv4(des_tcid), c_word_to_ipv4(next_hop_tcid));
        return (NULL_PTR);
    }
    return (crouter_node);
}

CROUTER_NODE *crouter_node_vec_erase(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos)
{
    return (CROUTER_NODE *)cvector_erase(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
}

CROUTER_NODE *crouter_node_vec_erase_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos)
{
    return (CROUTER_NODE *)cvector_erase_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
}

EC_BOOL crouter_node_vec_rmv(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid, const UINT32 next_hop_tcid)
{
    UINT32 crouter_node_pos;
    CROUTER_NODE *crouter_node;

    CVECTOR_LOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0026);
    crouter_node_pos = crouter_node_vec_search_no_lock(crouter_node_vec, des_tcid);
    if(CVECTOR_ERR_POS == crouter_node_pos)
    {
        CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0027);
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_rmv: no route to des tcid %s\n", c_word_to_ipv4(des_tcid));
        return (EC_FALSE);
    }

    crouter_node = crouter_node_vec_get_no_lock(crouter_node_vec, crouter_node_pos);
    crouter_node_rmv_next_hop_by_tcid(crouter_node, next_hop_tcid);

    /*update crouter_node_vec if necessary*/
    if(EC_TRUE == crouter_node_is_empty(crouter_node))
    {
        crouter_node_vec_erase_no_lock(crouter_node_vec, crouter_node_pos);
        crouter_node_free(crouter_node);
        CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0028);
        dbg_log(SEC_0005_CROUTER, 5)(LOGSTDOUT, "crouter_node_vec_rmv: no more route to des tcid %s, free whole croute node\n", c_word_to_ipv4(des_tcid));
        return (EC_TRUE);
    }

    CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0029);
    return (EC_TRUE);
}

EC_BOOL crouter_node_vec_rmv_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid, const UINT32 next_hop_tcid)
{
    UINT32 crouter_node_pos;
    CROUTER_NODE *crouter_node;

    crouter_node_pos = crouter_node_vec_search_no_lock(crouter_node_vec, des_tcid);
    if(CVECTOR_ERR_POS == crouter_node_pos)
    {
        dbg_log(SEC_0005_CROUTER, 0)(LOGSTDOUT, "error:crouter_node_vec_rmv_no_lock: no route to des tcid %s\n", c_word_to_ipv4(des_tcid));
        return (EC_FALSE);
    }

    crouter_node = crouter_node_vec_get_no_lock(crouter_node_vec, crouter_node_pos);
    crouter_node_rmv_next_hop_by_tcid(crouter_node, next_hop_tcid);

    /*update crouter_node_vec if necessary*/
    if(EC_TRUE == crouter_node_is_empty(crouter_node))
    {
        crouter_node_vec_erase_no_lock(crouter_node_vec, crouter_node_pos);
        crouter_node_free(crouter_node);
        dbg_log(SEC_0005_CROUTER, 5)(LOGSTDOUT, "crouter_node_vec_rmv_no_lock: no more route to des tcid %s, free whole croute node\n", c_word_to_ipv4(des_tcid));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

UINT32 crouter_node_vec_search(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid)
{
    UINT32 pos;

    CVECTOR_LOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0030);
    for(pos = 0; pos < cvector_size(CROUTER_NODE_VEC_NODES(crouter_node_vec)); pos ++)
    {
        CROUTER_NODE *crouter_node;

        crouter_node = (CROUTER_NODE *)cvector_get_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
        if(NULL_PTR == crouter_node)
        {
            continue;
        }

        if(des_tcid == CROUTER_NODE_DES_TCID(crouter_node))
        {
            CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0031);
            return (pos);
        }
    }
    CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0032);

    return (CVECTOR_ERR_POS);
}

UINT32 crouter_node_vec_search_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid)
{
    UINT32 pos;

    for(pos = 0; pos < cvector_size(CROUTER_NODE_VEC_NODES(crouter_node_vec)); pos ++)
    {
        CROUTER_NODE *crouter_node;

        crouter_node = (CROUTER_NODE *)cvector_get_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
        if(NULL_PTR == crouter_node)
        {
            continue;
        }

        if(des_tcid == CROUTER_NODE_DES_TCID(crouter_node))
        {
            return (pos);
        }
    }

    return (CVECTOR_ERR_POS);
}

CROUTER_NODE *crouter_node_vec_find(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid)
{
    UINT32 pos;

    CVECTOR_LOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0033);
    for(pos = 0; pos < cvector_size(CROUTER_NODE_VEC_NODES(crouter_node_vec)); pos ++)
    {
        CROUTER_NODE *crouter_node;

        crouter_node = (CROUTER_NODE *)cvector_get_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
        if(NULL_PTR == crouter_node)
        {
            continue;
        }

        if(des_tcid == CROUTER_NODE_DES_TCID(crouter_node))
        {
            CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0034);
            return (crouter_node);
        }
    }
    CVECTOR_UNLOCK(CROUTER_NODE_VEC_NODES(crouter_node_vec), LOC_CROUTER_0035);

    return (NULL_PTR);
}

CROUTER_NODE *crouter_node_vec_find_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid)
{
    UINT32 pos;

    for(pos = 0; pos < cvector_size(CROUTER_NODE_VEC_NODES(crouter_node_vec)); pos ++)
    {
        CROUTER_NODE *crouter_node;

        crouter_node = (CROUTER_NODE *)cvector_get_no_lock(CROUTER_NODE_VEC_NODES(crouter_node_vec), pos);
        if(NULL_PTR == crouter_node)
        {
            continue;
        }

        if(des_tcid == CROUTER_NODE_DES_TCID(crouter_node))
        {
            return (crouter_node);
        }
    }

    return (NULL_PTR);
}

CROUTER_CFG *crouter_cfg_new(const UINT32 src_tcid, const UINT32 des_tcid, const UINT32 next_hop, const UINT32 max_hops)
{
    CROUTER_CFG *crouter_cfg;

    alloc_static_mem(MM_CROUTER_CFG, &crouter_cfg, LOC_CROUTER_0036);
    crouter_cfg_init(crouter_cfg, src_tcid, des_tcid, next_hop, max_hops);
    return (crouter_cfg);
}

CROUTER_CFG *crouter_cfg_new_0()
{
    CROUTER_CFG *crouter_cfg;

    alloc_static_mem(MM_CROUTER_CFG, &crouter_cfg, LOC_CROUTER_0037);
    crouter_cfg_init(crouter_cfg, CMPI_ERROR_TCID, CMPI_ERROR_TCID, CMPI_ERROR_TCID, CROUTE_MAX_HOPS);
    return (crouter_cfg);
}


EC_BOOL crouter_cfg_init(CROUTER_CFG *crouter_cfg, const UINT32 src_tcid, const UINT32 des_tcid, const UINT32 next_hop, const UINT32 max_hops)
{
    CROUTER_CFG_SRC_TCID(crouter_cfg) = src_tcid;
    CROUTER_CFG_DES_TCID(crouter_cfg) = des_tcid;
    CROUTER_CFG_NEXT_HOP(crouter_cfg) = next_hop;
    CROUTER_CFG_MAX_HOPS(crouter_cfg) = max_hops;
    return (EC_TRUE);
}

EC_BOOL crouter_cfg_clean(CROUTER_CFG *crouter_cfg)
{
    CROUTER_CFG_SRC_TCID(crouter_cfg) = CMPI_ERROR_TCID;
    CROUTER_CFG_DES_TCID(crouter_cfg) = CMPI_ERROR_TCID;
    CROUTER_CFG_NEXT_HOP(crouter_cfg) = CMPI_ERROR_TCID;
    CROUTER_CFG_MAX_HOPS(crouter_cfg) = CROUTE_MAX_HOPS;
    return (EC_TRUE);
}

EC_BOOL crouter_cfg_free(CROUTER_CFG *crouter_cfg)
{
    crouter_cfg_clean(crouter_cfg);
    free_static_mem(MM_CROUTER_CFG, crouter_cfg, LOC_CROUTER_0038);
    return (EC_TRUE);
}

EC_BOOL crouter_cfg_clone(const CROUTER_CFG *src_crouter_cfg, CROUTER_CFG *des_crouter_cfg)
{
    CROUTER_CFG_SRC_TCID(des_crouter_cfg) = CROUTER_CFG_SRC_TCID(src_crouter_cfg);
    CROUTER_CFG_DES_TCID(des_crouter_cfg) = CROUTER_CFG_DES_TCID(src_crouter_cfg);
    CROUTER_CFG_NEXT_HOP(des_crouter_cfg) = CROUTER_CFG_NEXT_HOP(src_crouter_cfg);
    CROUTER_CFG_MAX_HOPS(des_crouter_cfg) = CROUTER_CFG_MAX_HOPS(src_crouter_cfg);
    return (EC_TRUE);
}

void crouter_cfg_print(LOG *log, CROUTER_CFG *crouter_cfg)
{
    sys_log(log, "crouter_cfg %lx: src tcid %s, des tcid %s, next hop %s, max hops %ld\n", crouter_cfg,
                CROUTER_CFG_SRC_TCID_STR(crouter_cfg),
                CROUTER_CFG_DES_TCID_STR(crouter_cfg),
                CROUTER_CFG_NEXT_HOP_STR(crouter_cfg),
                CROUTER_CFG_MAX_HOPS(crouter_cfg));
    return;
}

void crouter_cfg_print_xml(LOG *log, const CROUTER_CFG *crouter_cfg, const UINT32 level)
{
    crouter_cfg_ident_print_xml(log, level);

#if 1
    sys_print(log, "<route  src_tcid=\"%s\" des_tcid=\"%s\" next_hop=\"%s\" max_hops=\"%ld\"/>\n",
                    CROUTER_CFG_SRC_TCID_STR(crouter_cfg),
                    CROUTER_CFG_DES_TCID_STR(crouter_cfg),
                    CROUTER_CFG_NEXT_HOP_STR(crouter_cfg),
                    CROUTER_CFG_MAX_HOPS(crouter_cfg)
            );
#endif
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

