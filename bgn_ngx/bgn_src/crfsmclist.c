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

#include "crfsmclist.h"
#include "crfsmc.h"


void crfsmclist_node_del(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    CRFSMCLIST_NODE *node;

    node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
    ASSERT(CRFSMCLIST_NODE_USED == CRFSMCLIST_NODE_USED_FLAG(node));

    if(CRFSMCLIST_HEAD(crfsmclist) == node_pos)
    {
        CRFSMCLIST_HEAD(crfsmclist) = CRFSMCLIST_NODE_RIGHT_POS(node);
    }
    else
    {
        CRFSMCLIST_NODE *left_node;

        left_node = CRFSMCLIST_FETCH_NODE(crfsmclist, CRFSMCLIST_NODE_LEFT_POS(node));
        CRFSMCLIST_NODE_RIGHT_POS(left_node) = CRFSMCLIST_NODE_RIGHT_POS(node);
    }

    if(CRFSMCLIST_TAIL(crfsmclist) == node_pos)
    {
        CRFSMCLIST_TAIL(crfsmclist) = CRFSMCLIST_NODE_LEFT_POS(node);
    }
    else
    {
        CRFSMCLIST_NODE *right_node;

        right_node = CRFSMCLIST_FETCH_NODE(crfsmclist, CRFSMCLIST_NODE_RIGHT_POS(node));
        CRFSMCLIST_NODE_LEFT_POS(right_node) = CRFSMCLIST_NODE_LEFT_POS(node);
    }

    CRFSMCLIST_NODE_LEFT_POS(node)  = CRFSMCLIST_ERR_POS;
    CRFSMCLIST_NODE_RIGHT_POS(node) = CRFSMCLIST_ERR_POS;

    CRFSMCLIST_NODE_USED_FLAG(node) = CRFSMCLIST_NODE_NOT_USED;

    CRFSMCLIST_NODE_USED_NUM(crfsmclist) --;
    return;
}

void crfsmclist_node_add_head(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    CRFSMCLIST_NODE *new_node;

    new_node  = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos );
    ASSERT(CRFSMCLIST_NODE_NOT_USED == CRFSMCLIST_NODE_USED_FLAG(new_node));

    if(CRFSMCLIST_ERR_POS == CRFSMCLIST_HEAD(crfsmclist))
    {
        CRFSMCLIST_NODE_LEFT_POS(new_node)  = CRFSMCLIST_ERR_POS;
        CRFSMCLIST_NODE_RIGHT_POS(new_node) = CRFSMCLIST_ERR_POS;
        CRFSMCLIST_HEAD(crfsmclist)         = node_pos;
    }
    else
    {
        CRFSMCLIST_NODE *left_node;

        left_node = CRFSMCLIST_FETCH_NODE(crfsmclist, CRFSMCLIST_HEAD(crfsmclist));

        CRFSMCLIST_NODE_LEFT_POS(new_node)  = CRFSMCLIST_ERR_POS;
        CRFSMCLIST_NODE_RIGHT_POS(new_node) = CRFSMCLIST_HEAD(crfsmclist);
        CRFSMCLIST_NODE_LEFT_POS(left_node) = node_pos;
        CRFSMCLIST_HEAD(crfsmclist)         = node_pos;
    }

    if(CRFSMCLIST_ERR_POS == CRFSMCLIST_TAIL(crfsmclist))
    {
        CRFSMCLIST_TAIL(crfsmclist) = node_pos;
    }

    CRFSMCLIST_NODE_USED_FLAG(new_node) = CRFSMCLIST_NODE_USED;

    CRFSMCLIST_NODE_USED_NUM(crfsmclist) ++;
    return;
}

void crfsmclist_node_add_tail(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    CRFSMCLIST_NODE *new_node;

    new_node  = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos );
    ASSERT(CRFSMCLIST_NODE_NOT_USED == CRFSMCLIST_NODE_USED_FLAG(new_node));

    if(CRFSMCLIST_ERR_POS == CRFSMCLIST_TAIL(crfsmclist))
    {
        CRFSMCLIST_NODE_LEFT_POS(new_node)  = CRFSMCLIST_ERR_POS;
        CRFSMCLIST_NODE_RIGHT_POS(new_node) = CRFSMCLIST_ERR_POS;
        CRFSMCLIST_TAIL(crfsmclist)     = node_pos;
    }
    else
    {
        CRFSMCLIST_NODE *right_node;

        right_node = CRFSMCLIST_FETCH_NODE(crfsmclist, CRFSMCLIST_TAIL(crfsmclist));

        CRFSMCLIST_NODE_LEFT_POS(new_node)    = CRFSMCLIST_TAIL(crfsmclist);
        CRFSMCLIST_NODE_RIGHT_POS(new_node)   = CRFSMCLIST_ERR_POS;
        CRFSMCLIST_NODE_RIGHT_POS(right_node) = node_pos;
        CRFSMCLIST_TAIL(crfsmclist)       = node_pos;
    }

    if(CRFSMCLIST_ERR_POS == CRFSMCLIST_HEAD(crfsmclist))
    {
        CRFSMCLIST_HEAD(crfsmclist) = node_pos;
    }

    CRFSMCLIST_NODE_USED_FLAG(new_node) = CRFSMCLIST_NODE_USED;

    CRFSMCLIST_NODE_USED_NUM(crfsmclist) ++;
    return;
}

EC_BOOL crfsmclist_node_new(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    CRFSMCLIST_NODE *node;

    node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmclist_node_new: crfsmclist %p, max %u, used %u, head %u, tail %u, node %u overflow\n",
                           crfsmclist,
                           CRFSMCLIST_NODE_MAX_NUM(crfsmclist),
                           CRFSMCLIST_NODE_USED_NUM(crfsmclist),
                           CRFSMCLIST_HEAD(crfsmclist),
                           CRFSMCLIST_TAIL(crfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    if(CRFSMCLIST_NODE_USED == CRFSMCLIST_NODE_USED_FLAG(node))
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmclist_node_new: crfsmclist %p, max %u, used %u, head %u, tail %u, node %u is already used\n",
                           crfsmclist,
                           CRFSMCLIST_NODE_MAX_NUM(crfsmclist),
                           CRFSMCLIST_NODE_USED_NUM(crfsmclist),
                           CRFSMCLIST_HEAD(crfsmclist),
                           CRFSMCLIST_TAIL(crfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    crfsmclist_node_add_head(crfsmclist, node_pos);
    return (EC_TRUE);
}

EC_BOOL crfsmclist_node_free(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    CRFSMCLIST_NODE *node;

    node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmclist_node_free: crfsmclist %p, max %u, used %u, head %u, tail %u, node %u overflow\n",
                           crfsmclist,
                           CRFSMCLIST_NODE_MAX_NUM(crfsmclist),
                           CRFSMCLIST_NODE_USED_NUM(crfsmclist),
                           CRFSMCLIST_HEAD(crfsmclist),
                           CRFSMCLIST_TAIL(crfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    if(CRFSMCLIST_NODE_NOT_USED == CRFSMCLIST_NODE_USED_FLAG(node))
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmclist_node_free: crfsmclist %p, max %u, used %u, head %u, tail %u, node %u is not used\n",
                           crfsmclist,
                           CRFSMCLIST_NODE_MAX_NUM(crfsmclist),
                           CRFSMCLIST_NODE_USED_NUM(crfsmclist),
                           CRFSMCLIST_HEAD(crfsmclist),
                           CRFSMCLIST_TAIL(crfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    crfsmclist_node_del(crfsmclist, node_pos);
    return (EC_TRUE);
}

void crfsmclist_node_init(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    CRFSMCLIST_NODE *node;

    node  = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    CRFSMCLIST_NODE_RIGHT_POS(node)  = CRFSMCLIST_ERR_POS;
    CRFSMCLIST_NODE_LEFT_POS(node)   = CRFSMCLIST_ERR_POS;
    CRFSMCLIST_NODE_USED_FLAG(node)  = CRFSMCLIST_NODE_NOT_USED;

    return;
}

void crfsmclist_node_clean(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    CRFSMCLIST_NODE *node;

    ASSERT(node_pos < CRFSMCLIST_NODE_MAX_NUM(crfsmclist));

    node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    CRFSMCLIST_NODE_RIGHT_POS(node)  = CRFSMCLIST_ERR_POS;
    CRFSMCLIST_NODE_LEFT_POS(node)   = CRFSMCLIST_ERR_POS;
    CRFSMCLIST_NODE_USED_FLAG(node)  = CRFSMCLIST_NODE_NOT_USED;

    return;
}

EC_BOOL crfsmclist_node_is_used(const CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    const CRFSMCLIST_NODE *node;
    node  = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    if(CRFSMCLIST_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void crfsmclist_node_print(LOG *log, const CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    const CRFSMCLIST_NODE *node;
    node  = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    sys_log(log, "crfsmclist %p, pos %u: flag %s, left %u, right %u\n",
                 crfsmclist,
                 node_pos,
                 CRFSMCLIST_NODE_IS_USED(node) ? "used" : "n.a.",
                 CRFSMCLIST_NODE_LEFT_POS(node),
                 CRFSMCLIST_NODE_RIGHT_POS(node));
    return;
}

EC_BOOL crfsmclist_node_lru_update(CRFSMCLIST *crfsmclist, const uint32_t node_pos)
{
    if(EC_TRUE == crfsmclist_node_is_used(crfsmclist, node_pos))
    {
        if(node_pos != crfsmclist_head(crfsmclist))
        {
            crfsmclist_node_del(crfsmclist, node_pos);
            crfsmclist_node_add_head(crfsmclist, node_pos);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsmclist_is_empty(const CRFSMCLIST *crfsmclist)
{
    if(0 == CRFSMCLIST_NODE_USED_NUM(crfsmclist))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfsmclist_is_full(const CRFSMCLIST *crfsmclist)
{
    if(CRFSMCLIST_NODE_MAX_NUM(crfsmclist) == CRFSMCLIST_NODE_USED_NUM(crfsmclist))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

uint32_t crfsmclist_max_num(const CRFSMCLIST *crfsmclist)
{
    return CRFSMCLIST_NODE_MAX_NUM(crfsmclist);
}

uint32_t crfsmclist_used_num(const CRFSMCLIST *crfsmclist)
{
    return CRFSMCLIST_NODE_USED_NUM(crfsmclist);
}

uint32_t crfsmclist_head(const CRFSMCLIST *crfsmclist)
{
    return CRFSMCLIST_HEAD(crfsmclist);
}

uint32_t crfsmclist_tail(const CRFSMCLIST *crfsmclist)
{
    return CRFSMCLIST_TAIL(crfsmclist);
}

uint32_t crfsmclist_pop_head(CRFSMCLIST *crfsmclist)
{
    uint32_t node_pos;

    if(CRFSMCLIST_ERR_POS == CRFSMCLIST_HEAD(crfsmclist))
    {
        return (CRFSMCLIST_ERR_POS);
    }

    node_pos = CRFSMCLIST_HEAD(crfsmclist);
    crfsmclist_node_del(crfsmclist, node_pos);
    return (node_pos);
}

uint32_t crfsmclist_pop_tail(CRFSMCLIST *crfsmclist)
{
    uint32_t node_pos;

    if(CRFSMCLIST_ERR_POS == CRFSMCLIST_TAIL(crfsmclist))
    {
        return (CRFSMCLIST_ERR_POS);
    }

    node_pos = CRFSMCLIST_TAIL(crfsmclist);
    crfsmclist_node_del(crfsmclist, node_pos);
    return (node_pos);
}

CRFSMCLIST *crfsmclist_new(const uint32_t max_num)
{
    CRFSMCLIST *crfsmclist;
    uint32_t size;

    size = sizeof(CRFSMCLIST) + max_num * sizeof(CRFSMCLIST_NODE);

    crfsmclist = (CRFSMCLIST *)safe_malloc(size, LOC_CRFSMCLIST_0001);
    if(NULL_PTR == crfsmclist)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmclist_init: malloc %u bytes failed\n", size);
        return (NULL_PTR);
    }

    crfsmclist_init(crfsmclist, max_num);
    return (crfsmclist);
}

EC_BOOL crfsmclist_init(CRFSMCLIST *crfsmclist, const uint32_t max_num)
{
    uint32_t node_pos;

    CRFSMCLIST_HEAD(crfsmclist) = CRFSMCLIST_ERR_POS;
    CRFSMCLIST_TAIL(crfsmclist) = CRFSMCLIST_ERR_POS;

    CRFSMCLIST_NODE_MAX_NUM(crfsmclist)  = max_num;
    CRFSMCLIST_NODE_USED_NUM(crfsmclist) = 0;

    for(node_pos = 0; node_pos < max_num; node_pos ++)
    {
        //CRFSMCLIST_NODE *node;
        //node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);

        crfsmclist_node_init(crfsmclist, node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL crfsmclist_free(CRFSMCLIST *crfsmclist)
{
    if(NULL_PTR != crfsmclist)
    {
        //crfsmclist_clean(crfsmclist);
        safe_free(crfsmclist, LOC_CRFSMCLIST_0002);
    }
    return (EC_TRUE);
}

EC_BOOL crfsmclist_clean(CRFSMCLIST *crfsmclist)
{
    uint32_t node_pos;

    CRFSMCLIST_HEAD(crfsmclist) = CRFSMCLIST_ERR_POS;
    CRFSMCLIST_TAIL(crfsmclist) = CRFSMCLIST_ERR_POS;

    CRFSMCLIST_NODE_USED_NUM(crfsmclist) = 0;

    for(node_pos = 0; node_pos < CRFSMCLIST_NODE_MAX_NUM(crfsmclist); node_pos ++)
    {
        //CRFSMCLIST_NODE *node;
        //node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);

        crfsmclist_node_clean(crfsmclist, node_pos);
    }
    return (EC_TRUE);
}

void crfsmclist_print(LOG *log, const CRFSMCLIST *crfsmclist)
{
    uint32_t node_pos;

    sys_log(log, "crfsmclist %p: max %u, used %u, head %u, tail %u\n",
                 crfsmclist,
                 CRFSMCLIST_NODE_MAX_NUM(crfsmclist),
                 CRFSMCLIST_NODE_USED_NUM(crfsmclist),
                 CRFSMCLIST_HEAD(crfsmclist),
                 CRFSMCLIST_TAIL(crfsmclist));

    node_pos = CRFSMCLIST_HEAD(crfsmclist);
    while(CRFSMCLIST_ERR_POS != node_pos)
    {
        CRFSMCLIST_NODE *node;

        crfsmclist_node_print(log, crfsmclist, node_pos);

        node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
        node_pos = CRFSMCLIST_NODE_RIGHT_POS(node);
    }
    return;
}

void crfsmclist_print_tail(LOG *log, const CRFSMCLIST *crfsmclist)
{
    uint32_t node_pos;

    sys_log(log, "crfsmclist %p: max %u, used %u, head %u, tail %u\n",
                 crfsmclist,
                 CRFSMCLIST_NODE_MAX_NUM(crfsmclist),
                 CRFSMCLIST_NODE_USED_NUM(crfsmclist),
                 CRFSMCLIST_HEAD(crfsmclist),
                 CRFSMCLIST_TAIL(crfsmclist));

    node_pos = CRFSMCLIST_TAIL(crfsmclist);
    while(CRFSMCLIST_ERR_POS != node_pos)
    {
        CRFSMCLIST_NODE *node;

        crfsmclist_node_print(log, crfsmclist, node_pos);

        node = CRFSMCLIST_FETCH_NODE(crfsmclist, node_pos);
        node_pos = CRFSMCLIST_NODE_LEFT_POS(node);
    }
    return;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

