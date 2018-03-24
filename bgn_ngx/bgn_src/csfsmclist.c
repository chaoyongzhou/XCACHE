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
#include <string.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "db_internal.h"

#include "csfsmclist.h"
#include "csfsmc.h"


void csfsmclist_node_del(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    CSFSMCLIST_NODE *node;

    node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
    ASSERT(CSFSMCLIST_NODE_USED == CSFSMCLIST_NODE_USED_FLAG(node));

    if(CSFSMCLIST_HEAD(csfsmclist) == node_pos)
    {
        CSFSMCLIST_HEAD(csfsmclist) = CSFSMCLIST_NODE_RIGHT_POS(node);
    }
    else
    {
        CSFSMCLIST_NODE *left_node;

        left_node = CSFSMCLIST_FETCH_NODE(csfsmclist, CSFSMCLIST_NODE_LEFT_POS(node));
        CSFSMCLIST_NODE_RIGHT_POS(left_node) = CSFSMCLIST_NODE_RIGHT_POS(node);
    }

    if(CSFSMCLIST_TAIL(csfsmclist) == node_pos)
    {
        CSFSMCLIST_TAIL(csfsmclist) = CSFSMCLIST_NODE_LEFT_POS(node);
    }
    else
    {
        CSFSMCLIST_NODE *right_node;

        right_node = CSFSMCLIST_FETCH_NODE(csfsmclist, CSFSMCLIST_NODE_RIGHT_POS(node));
        CSFSMCLIST_NODE_LEFT_POS(right_node) = CSFSMCLIST_NODE_LEFT_POS(node);
    }

    CSFSMCLIST_NODE_LEFT_POS(node)  = CSFSMCLIST_ERR_POS;
    CSFSMCLIST_NODE_RIGHT_POS(node) = CSFSMCLIST_ERR_POS;

    CSFSMCLIST_NODE_USED_FLAG(node) = CSFSMCLIST_NODE_NOT_USED;

    CSFSMCLIST_NODE_USED_NUM(csfsmclist) --;
    return;
}

void csfsmclist_node_add_head(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    CSFSMCLIST_NODE *new_node;

    new_node  = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos );
    ASSERT(CSFSMCLIST_NODE_NOT_USED == CSFSMCLIST_NODE_USED_FLAG(new_node));

    if(CSFSMCLIST_ERR_POS == CSFSMCLIST_HEAD(csfsmclist))
    {
        CSFSMCLIST_NODE_LEFT_POS(new_node)  = CSFSMCLIST_ERR_POS;
        CSFSMCLIST_NODE_RIGHT_POS(new_node) = CSFSMCLIST_ERR_POS;
        CSFSMCLIST_HEAD(csfsmclist)         = node_pos;
    }
    else
    {
        CSFSMCLIST_NODE *left_node;

        left_node = CSFSMCLIST_FETCH_NODE(csfsmclist, CSFSMCLIST_HEAD(csfsmclist));

        CSFSMCLIST_NODE_LEFT_POS(new_node)  = CSFSMCLIST_ERR_POS;
        CSFSMCLIST_NODE_RIGHT_POS(new_node) = CSFSMCLIST_HEAD(csfsmclist);
        CSFSMCLIST_NODE_LEFT_POS(left_node) = node_pos;
        CSFSMCLIST_HEAD(csfsmclist)         = node_pos;
    }

    if(CSFSMCLIST_ERR_POS == CSFSMCLIST_TAIL(csfsmclist))
    {
        CSFSMCLIST_TAIL(csfsmclist) = node_pos;
    }

    CSFSMCLIST_NODE_USED_FLAG(new_node) = CSFSMCLIST_NODE_USED;

    CSFSMCLIST_NODE_USED_NUM(csfsmclist) ++;
    return;
}

void csfsmclist_node_add_tail(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    CSFSMCLIST_NODE *new_node;

    new_node  = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos );
    ASSERT(CSFSMCLIST_NODE_NOT_USED == CSFSMCLIST_NODE_USED_FLAG(new_node));

    if(CSFSMCLIST_ERR_POS == CSFSMCLIST_TAIL(csfsmclist))
    {
        CSFSMCLIST_NODE_LEFT_POS(new_node)  = CSFSMCLIST_ERR_POS;
        CSFSMCLIST_NODE_RIGHT_POS(new_node) = CSFSMCLIST_ERR_POS;
        CSFSMCLIST_TAIL(csfsmclist)     = node_pos;
    }
    else
    {
        CSFSMCLIST_NODE *right_node;

        right_node = CSFSMCLIST_FETCH_NODE(csfsmclist, CSFSMCLIST_TAIL(csfsmclist));

        CSFSMCLIST_NODE_LEFT_POS(new_node)    = CSFSMCLIST_TAIL(csfsmclist);
        CSFSMCLIST_NODE_RIGHT_POS(new_node)   = CSFSMCLIST_ERR_POS;
        CSFSMCLIST_NODE_RIGHT_POS(right_node) = node_pos;
        CSFSMCLIST_TAIL(csfsmclist)       = node_pos;
    }

    if(CSFSMCLIST_ERR_POS == CSFSMCLIST_HEAD(csfsmclist))
    {
        CSFSMCLIST_HEAD(csfsmclist) = node_pos;
    }

    CSFSMCLIST_NODE_USED_FLAG(new_node) = CSFSMCLIST_NODE_USED;

    CSFSMCLIST_NODE_USED_NUM(csfsmclist) ++;
    return;
}

EC_BOOL csfsmclist_node_new(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    CSFSMCLIST_NODE *node;

    node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmclist_node_new: csfsmclist %p, max %u, used %u, head %u, tail %u, node %u overflow\n",
                           csfsmclist,
                           CSFSMCLIST_NODE_MAX_NUM(csfsmclist),
                           CSFSMCLIST_NODE_USED_NUM(csfsmclist),
                           CSFSMCLIST_HEAD(csfsmclist),
                           CSFSMCLIST_TAIL(csfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    if(CSFSMCLIST_NODE_USED == CSFSMCLIST_NODE_USED_FLAG(node))
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmclist_node_new: csfsmclist %p, max %u, used %u, head %u, tail %u, node %u is already used\n",
                           csfsmclist,
                           CSFSMCLIST_NODE_MAX_NUM(csfsmclist),
                           CSFSMCLIST_NODE_USED_NUM(csfsmclist),
                           CSFSMCLIST_HEAD(csfsmclist),
                           CSFSMCLIST_TAIL(csfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    csfsmclist_node_add_head(csfsmclist, node_pos);
    return (EC_TRUE);
}

EC_BOOL csfsmclist_node_free(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    CSFSMCLIST_NODE *node;

    node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmclist_node_free: csfsmclist %p, max %u, used %u, head %u, tail %u, node %u overflow\n",
                           csfsmclist,
                           CSFSMCLIST_NODE_MAX_NUM(csfsmclist),
                           CSFSMCLIST_NODE_USED_NUM(csfsmclist),
                           CSFSMCLIST_HEAD(csfsmclist),
                           CSFSMCLIST_TAIL(csfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    if(CSFSMCLIST_NODE_NOT_USED == CSFSMCLIST_NODE_USED_FLAG(node))
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmclist_node_free: csfsmclist %p, max %u, used %u, head %u, tail %u, node %u is not used\n",
                           csfsmclist,
                           CSFSMCLIST_NODE_MAX_NUM(csfsmclist),
                           CSFSMCLIST_NODE_USED_NUM(csfsmclist),
                           CSFSMCLIST_HEAD(csfsmclist),
                           CSFSMCLIST_TAIL(csfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    csfsmclist_node_del(csfsmclist, node_pos);
    return (EC_TRUE);
}

void csfsmclist_node_init(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    CSFSMCLIST_NODE *node;

    node  = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    CSFSMCLIST_NODE_RIGHT_POS(node)  = CSFSMCLIST_ERR_POS;
    CSFSMCLIST_NODE_LEFT_POS(node)   = CSFSMCLIST_ERR_POS;
    CSFSMCLIST_NODE_USED_FLAG(node)  = CSFSMCLIST_NODE_NOT_USED;

    return;
}

void csfsmclist_node_clean(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    CSFSMCLIST_NODE *node;

    ASSERT(node_pos < CSFSMCLIST_NODE_MAX_NUM(csfsmclist));

    node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    CSFSMCLIST_NODE_RIGHT_POS(node)  = CSFSMCLIST_ERR_POS;
    CSFSMCLIST_NODE_LEFT_POS(node)   = CSFSMCLIST_ERR_POS;
    CSFSMCLIST_NODE_USED_FLAG(node)  = CSFSMCLIST_NODE_NOT_USED;

    return;
}

EC_BOOL csfsmclist_node_is_used(const CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    const CSFSMCLIST_NODE *node;
    node  = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    if(CSFSMCLIST_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void csfsmclist_node_print(LOG *log, const CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    const CSFSMCLIST_NODE *node;
    node  = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    sys_log(log, "csfsmclist %p, pos %u: flag %s, left %u, right %u\n",
                 csfsmclist,
                 node_pos,
                 CSFSMCLIST_NODE_IS_USED(node) ? "used" : "n.a.",
                 CSFSMCLIST_NODE_LEFT_POS(node),
                 CSFSMCLIST_NODE_RIGHT_POS(node));
    return;
}

EC_BOOL csfsmclist_node_lru_update(CSFSMCLIST *csfsmclist, const uint32_t node_pos)
{
    if(EC_TRUE == csfsmclist_node_is_used(csfsmclist, node_pos))
    {
        if(node_pos != csfsmclist_head(csfsmclist))
        {
            csfsmclist_node_del(csfsmclist, node_pos);
            csfsmclist_node_add_head(csfsmclist, node_pos);
        }
    }

    return (EC_TRUE);
}

EC_BOOL csfsmclist_is_empty(const CSFSMCLIST *csfsmclist)
{
    if(0 == CSFSMCLIST_NODE_USED_NUM(csfsmclist))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL csfsmclist_is_full(const CSFSMCLIST *csfsmclist)
{
    if(CSFSMCLIST_NODE_MAX_NUM(csfsmclist) == CSFSMCLIST_NODE_USED_NUM(csfsmclist))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

uint32_t csfsmclist_max_num(const CSFSMCLIST *csfsmclist)
{
    return CSFSMCLIST_NODE_MAX_NUM(csfsmclist);
}

uint32_t csfsmclist_used_num(const CSFSMCLIST *csfsmclist)
{
    return CSFSMCLIST_NODE_USED_NUM(csfsmclist);
}

uint32_t csfsmclist_head(const CSFSMCLIST *csfsmclist)
{
    return CSFSMCLIST_HEAD(csfsmclist);
}

uint32_t csfsmclist_tail(const CSFSMCLIST *csfsmclist)
{
    return CSFSMCLIST_TAIL(csfsmclist);
}

uint32_t csfsmclist_pop_head(CSFSMCLIST *csfsmclist)
{
    uint32_t node_pos;

    if(CSFSMCLIST_ERR_POS == CSFSMCLIST_HEAD(csfsmclist))
    {
        return (CSFSMCLIST_ERR_POS);
    }

    node_pos = CSFSMCLIST_HEAD(csfsmclist);
    csfsmclist_node_del(csfsmclist, node_pos);
    return (node_pos);
}

uint32_t csfsmclist_pop_tail(CSFSMCLIST *csfsmclist)
{
    uint32_t node_pos;

    if(CSFSMCLIST_ERR_POS == CSFSMCLIST_TAIL(csfsmclist))
    {
        return (CSFSMCLIST_ERR_POS);
    }

    node_pos = CSFSMCLIST_TAIL(csfsmclist);
    csfsmclist_node_del(csfsmclist, node_pos);
    return (node_pos);
}

CSFSMCLIST *csfsmclist_new(const uint32_t max_num)
{
    CSFSMCLIST *csfsmclist;
    uint32_t size;

    size = sizeof(CSFSMCLIST) + max_num * sizeof(CSFSMCLIST_NODE);

    csfsmclist = (CSFSMCLIST *)safe_malloc(size, LOC_CSFSMCLIST_0001);
    if(NULL_PTR == csfsmclist)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmclist_init: malloc %u bytes failed\n", size);
        return (NULL_PTR);
    }

    csfsmclist_init(csfsmclist, max_num);
    return (csfsmclist);
}

EC_BOOL csfsmclist_init(CSFSMCLIST *csfsmclist, const uint32_t max_num)
{
    uint32_t node_pos;

    CSFSMCLIST_HEAD(csfsmclist) = CSFSMCLIST_ERR_POS;
    CSFSMCLIST_TAIL(csfsmclist) = CSFSMCLIST_ERR_POS;

    CSFSMCLIST_NODE_MAX_NUM(csfsmclist)  = max_num;
    CSFSMCLIST_NODE_USED_NUM(csfsmclist) = 0;

    for(node_pos = 0; node_pos < max_num; node_pos ++)
    {
        CSFSMCLIST_NODE *node;
        node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);

        csfsmclist_node_init(csfsmclist, node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL csfsmclist_free(CSFSMCLIST *csfsmclist)
{
    if(NULL_PTR != csfsmclist)
    {
        //csfsmclist_clean(csfsmclist);
        safe_free(csfsmclist, LOC_CSFSMCLIST_0002);
    }
    return (EC_TRUE);
}

EC_BOOL csfsmclist_clean(CSFSMCLIST *csfsmclist)
{
    uint32_t node_pos;

    CSFSMCLIST_HEAD(csfsmclist) = CSFSMCLIST_ERR_POS;
    CSFSMCLIST_TAIL(csfsmclist) = CSFSMCLIST_ERR_POS;

    CSFSMCLIST_NODE_USED_NUM(csfsmclist) = 0;

    for(node_pos = 0; node_pos < CSFSMCLIST_NODE_MAX_NUM(csfsmclist); node_pos ++)
    {
        CSFSMCLIST_NODE *node;
        node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);

        csfsmclist_node_clean(csfsmclist, node_pos);
    }
    return (EC_TRUE);
}

void csfsmclist_print(LOG *log, const CSFSMCLIST *csfsmclist)
{
    uint32_t node_pos;

    sys_log(log, "csfsmclist %p: max %u, used %u, head %u, tail %u\n",
                 csfsmclist,
                 CSFSMCLIST_NODE_MAX_NUM(csfsmclist),
                 CSFSMCLIST_NODE_USED_NUM(csfsmclist),
                 CSFSMCLIST_HEAD(csfsmclist),
                 CSFSMCLIST_TAIL(csfsmclist));

    node_pos = CSFSMCLIST_HEAD(csfsmclist);
    while(CSFSMCLIST_ERR_POS != node_pos)
    {
        CSFSMCLIST_NODE *node;

        csfsmclist_node_print(log, csfsmclist, node_pos);

        node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
        node_pos = CSFSMCLIST_NODE_RIGHT_POS(node);
    }
    return;
}

void csfsmclist_print_tail(LOG *log, const CSFSMCLIST *csfsmclist)
{
    uint32_t node_pos;

    sys_log(log, "csfsmclist %p: max %u, used %u, head %u, tail %u\n",
                 csfsmclist,
                 CSFSMCLIST_NODE_MAX_NUM(csfsmclist),
                 CSFSMCLIST_NODE_USED_NUM(csfsmclist),
                 CSFSMCLIST_HEAD(csfsmclist),
                 CSFSMCLIST_TAIL(csfsmclist));

    node_pos = CSFSMCLIST_TAIL(csfsmclist);
    while(CSFSMCLIST_ERR_POS != node_pos)
    {
        CSFSMCLIST_NODE *node;

        csfsmclist_node_print(log, csfsmclist, node_pos);

        node = CSFSMCLIST_FETCH_NODE(csfsmclist, node_pos);
        node_pos = CSFSMCLIST_NODE_LEFT_POS(node);
    }
    return;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

