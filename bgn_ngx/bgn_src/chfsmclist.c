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

#include "chfsmclist.h"
#include "chfsmc.h"


void chfsmclist_node_del(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    CHFSMCLIST_NODE *node;
 
    node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
    ASSERT(CHFSMCLIST_NODE_USED == CHFSMCLIST_NODE_USED_FLAG(node));

    if(CHFSMCLIST_HEAD(chfsmclist) == node_pos)
    {
        CHFSMCLIST_HEAD(chfsmclist) = CHFSMCLIST_NODE_RIGHT_POS(node);
    }
    else
    {
        CHFSMCLIST_NODE *left_node;

        left_node = CHFSMCLIST_FETCH_NODE(chfsmclist, CHFSMCLIST_NODE_LEFT_POS(node));
        CHFSMCLIST_NODE_RIGHT_POS(left_node) = CHFSMCLIST_NODE_RIGHT_POS(node); 
    }

    if(CHFSMCLIST_TAIL(chfsmclist) == node_pos)
    {
        CHFSMCLIST_TAIL(chfsmclist) = CHFSMCLIST_NODE_LEFT_POS(node);
    }
    else
    {
        CHFSMCLIST_NODE *right_node;

        right_node = CHFSMCLIST_FETCH_NODE(chfsmclist, CHFSMCLIST_NODE_RIGHT_POS(node));
        CHFSMCLIST_NODE_LEFT_POS(right_node) = CHFSMCLIST_NODE_LEFT_POS(node); 
    } 
 
    CHFSMCLIST_NODE_LEFT_POS(node)  = CHFSMCLIST_ERR_POS;
    CHFSMCLIST_NODE_RIGHT_POS(node) = CHFSMCLIST_ERR_POS;

    CHFSMCLIST_NODE_USED_FLAG(node) = CHFSMCLIST_NODE_NOT_USED;

    CHFSMCLIST_NODE_USED_NUM(chfsmclist) --;
    return; 
}

void chfsmclist_node_add_head(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    CHFSMCLIST_NODE *new_node;

    new_node  = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos );
    ASSERT(CHFSMCLIST_NODE_NOT_USED == CHFSMCLIST_NODE_USED_FLAG(new_node));

    if(CHFSMCLIST_ERR_POS == CHFSMCLIST_HEAD(chfsmclist))
    {
        CHFSMCLIST_NODE_LEFT_POS(new_node)  = CHFSMCLIST_ERR_POS;
        CHFSMCLIST_NODE_RIGHT_POS(new_node) = CHFSMCLIST_ERR_POS;
        CHFSMCLIST_HEAD(chfsmclist)         = node_pos;
    }
    else
    {
        CHFSMCLIST_NODE *left_node;

        left_node = CHFSMCLIST_FETCH_NODE(chfsmclist, CHFSMCLIST_HEAD(chfsmclist));
     
        CHFSMCLIST_NODE_LEFT_POS(new_node)  = CHFSMCLIST_ERR_POS;
        CHFSMCLIST_NODE_RIGHT_POS(new_node) = CHFSMCLIST_HEAD(chfsmclist);
        CHFSMCLIST_NODE_LEFT_POS(left_node) = node_pos;
        CHFSMCLIST_HEAD(chfsmclist)         = node_pos; 
    }

    if(CHFSMCLIST_ERR_POS == CHFSMCLIST_TAIL(chfsmclist))
    {
        CHFSMCLIST_TAIL(chfsmclist) = node_pos;
    }

    CHFSMCLIST_NODE_USED_FLAG(new_node) = CHFSMCLIST_NODE_USED;
 
    CHFSMCLIST_NODE_USED_NUM(chfsmclist) ++;
    return;
}

void chfsmclist_node_add_tail(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    CHFSMCLIST_NODE *new_node;

    new_node  = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos );
    ASSERT(CHFSMCLIST_NODE_NOT_USED == CHFSMCLIST_NODE_USED_FLAG(new_node));

    if(CHFSMCLIST_ERR_POS == CHFSMCLIST_TAIL(chfsmclist))
    {
        CHFSMCLIST_NODE_LEFT_POS(new_node)  = CHFSMCLIST_ERR_POS;
        CHFSMCLIST_NODE_RIGHT_POS(new_node) = CHFSMCLIST_ERR_POS;
        CHFSMCLIST_TAIL(chfsmclist)     = node_pos;
    }
    else
    {
        CHFSMCLIST_NODE *right_node;

        right_node = CHFSMCLIST_FETCH_NODE(chfsmclist, CHFSMCLIST_TAIL(chfsmclist));
     
        CHFSMCLIST_NODE_LEFT_POS(new_node)    = CHFSMCLIST_TAIL(chfsmclist);
        CHFSMCLIST_NODE_RIGHT_POS(new_node)   = CHFSMCLIST_ERR_POS;
        CHFSMCLIST_NODE_RIGHT_POS(right_node) = node_pos;
        CHFSMCLIST_TAIL(chfsmclist)       = node_pos; 
    }

    if(CHFSMCLIST_ERR_POS == CHFSMCLIST_HEAD(chfsmclist))
    {
        CHFSMCLIST_HEAD(chfsmclist) = node_pos;
    }

    CHFSMCLIST_NODE_USED_FLAG(new_node) = CHFSMCLIST_NODE_USED;
 
    CHFSMCLIST_NODE_USED_NUM(chfsmclist) ++;
    return;
}

EC_BOOL chfsmclist_node_new(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    CHFSMCLIST_NODE *node;
 
    node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmclist_node_new: chfsmclist %p, max %u, used %u, head %u, tail %u, node %u overflow\n",
                           chfsmclist,
                           CHFSMCLIST_NODE_MAX_NUM(chfsmclist),
                           CHFSMCLIST_NODE_USED_NUM(chfsmclist),
                           CHFSMCLIST_HEAD(chfsmclist),
                           CHFSMCLIST_TAIL(chfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    if(CHFSMCLIST_NODE_USED == CHFSMCLIST_NODE_USED_FLAG(node))
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmclist_node_new: chfsmclist %p, max %u, used %u, head %u, tail %u, node %u is already used\n",
                           chfsmclist,
                           CHFSMCLIST_NODE_MAX_NUM(chfsmclist),
                           CHFSMCLIST_NODE_USED_NUM(chfsmclist),
                           CHFSMCLIST_HEAD(chfsmclist),
                           CHFSMCLIST_TAIL(chfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    chfsmclist_node_add_head(chfsmclist, node_pos);
    return (EC_TRUE);
}

EC_BOOL chfsmclist_node_free(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    CHFSMCLIST_NODE *node;
 
    node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmclist_node_free: chfsmclist %p, max %u, used %u, head %u, tail %u, node %u overflow\n",
                           chfsmclist,
                           CHFSMCLIST_NODE_MAX_NUM(chfsmclist),
                           CHFSMCLIST_NODE_USED_NUM(chfsmclist),
                           CHFSMCLIST_HEAD(chfsmclist),
                           CHFSMCLIST_TAIL(chfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    if(CHFSMCLIST_NODE_NOT_USED == CHFSMCLIST_NODE_USED_FLAG(node))
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmclist_node_free: chfsmclist %p, max %u, used %u, head %u, tail %u, node %u is not used\n",
                           chfsmclist,
                           CHFSMCLIST_NODE_MAX_NUM(chfsmclist),
                           CHFSMCLIST_NODE_USED_NUM(chfsmclist),
                           CHFSMCLIST_HEAD(chfsmclist),
                           CHFSMCLIST_TAIL(chfsmclist),
                           node_pos);
        return (EC_FALSE);
    }

    chfsmclist_node_del(chfsmclist, node_pos);
    return (EC_TRUE);
}

void chfsmclist_node_init(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    CHFSMCLIST_NODE *node;

    node  = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos); 
    ASSERT(NULL_PTR != node);
 
    CHFSMCLIST_NODE_RIGHT_POS(node)  = CHFSMCLIST_ERR_POS;
    CHFSMCLIST_NODE_LEFT_POS(node)   = CHFSMCLIST_ERR_POS;
    CHFSMCLIST_NODE_USED_FLAG(node)  = CHFSMCLIST_NODE_NOT_USED;
 
    return;
}

void chfsmclist_node_clean(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    CHFSMCLIST_NODE *node;

    ASSERT(node_pos < CHFSMCLIST_NODE_MAX_NUM(chfsmclist));
 
    node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
    ASSERT(NULL_PTR != node);
 
    CHFSMCLIST_NODE_RIGHT_POS(node)  = CHFSMCLIST_ERR_POS;
    CHFSMCLIST_NODE_LEFT_POS(node)   = CHFSMCLIST_ERR_POS;
    CHFSMCLIST_NODE_USED_FLAG(node)  = CHFSMCLIST_NODE_NOT_USED;

    return;
}

EC_BOOL chfsmclist_node_is_used(const CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    const CHFSMCLIST_NODE *node;
    node  = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    if(CHFSMCLIST_NODE_IS_USED(node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void chfsmclist_node_print(LOG *log, const CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    const CHFSMCLIST_NODE *node;
    node  = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
    ASSERT(NULL_PTR != node);

    sys_log(log, "chfsmclist %p, pos %u: flag %s, left %u, right %u\n",
                 chfsmclist,
                 node_pos,
                 CHFSMCLIST_NODE_IS_USED(node) ? "used" : "n.a.",
                 CHFSMCLIST_NODE_LEFT_POS(node),
                 CHFSMCLIST_NODE_RIGHT_POS(node));
    return;
}

EC_BOOL chfsmclist_node_lru_update(CHFSMCLIST *chfsmclist, const uint32_t node_pos)
{
    if(EC_TRUE == chfsmclist_node_is_used(chfsmclist, node_pos))
    {
        if(node_pos != chfsmclist_head(chfsmclist))
        {
            chfsmclist_node_del(chfsmclist, node_pos);
            chfsmclist_node_add_head(chfsmclist, node_pos);
        }
    }
 
    return (EC_TRUE);
}

EC_BOOL chfsmclist_is_empty(const CHFSMCLIST *chfsmclist)
{
    if(0 == CHFSMCLIST_NODE_USED_NUM(chfsmclist))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chfsmclist_is_full(const CHFSMCLIST *chfsmclist)
{
    if(CHFSMCLIST_NODE_MAX_NUM(chfsmclist) == CHFSMCLIST_NODE_USED_NUM(chfsmclist))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

uint32_t chfsmclist_max_num(const CHFSMCLIST *chfsmclist)
{
    return CHFSMCLIST_NODE_MAX_NUM(chfsmclist);
}

uint32_t chfsmclist_used_num(const CHFSMCLIST *chfsmclist)
{
    return CHFSMCLIST_NODE_USED_NUM(chfsmclist);
}

uint32_t chfsmclist_head(const CHFSMCLIST *chfsmclist)
{
    return CHFSMCLIST_HEAD(chfsmclist);
}

uint32_t chfsmclist_tail(const CHFSMCLIST *chfsmclist)
{
    return CHFSMCLIST_TAIL(chfsmclist);
}

uint32_t chfsmclist_pop_head(CHFSMCLIST *chfsmclist)
{
    uint32_t node_pos;

    if(CHFSMCLIST_ERR_POS == CHFSMCLIST_HEAD(chfsmclist))
    {
        return (CHFSMCLIST_ERR_POS);
    }

    node_pos = CHFSMCLIST_HEAD(chfsmclist);
    chfsmclist_node_del(chfsmclist, node_pos);
    return (node_pos);
}

uint32_t chfsmclist_pop_tail(CHFSMCLIST *chfsmclist)
{
    uint32_t node_pos;

    if(CHFSMCLIST_ERR_POS == CHFSMCLIST_TAIL(chfsmclist))
    {
        return (CHFSMCLIST_ERR_POS);
    }

    node_pos = CHFSMCLIST_TAIL(chfsmclist);
    chfsmclist_node_del(chfsmclist, node_pos);
    return (node_pos);
}

CHFSMCLIST *chfsmclist_new(const uint32_t max_num)
{
    CHFSMCLIST *chfsmclist;
    uint32_t size;
 
    size = sizeof(CHFSMCLIST) + max_num * sizeof(CHFSMCLIST_NODE);

    chfsmclist = (CHFSMCLIST *)safe_malloc(size, LOC_CHFSMCLIST_0001);
    if(NULL_PTR == chfsmclist)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmclist_init: malloc %u bytes failed\n", size);
        return (NULL_PTR);
    }

    chfsmclist_init(chfsmclist, max_num);
    return (chfsmclist);
}

EC_BOOL chfsmclist_init(CHFSMCLIST *chfsmclist, const uint32_t max_num)
{
    uint32_t node_pos;

    CHFSMCLIST_HEAD(chfsmclist) = CHFSMCLIST_ERR_POS;
    CHFSMCLIST_TAIL(chfsmclist) = CHFSMCLIST_ERR_POS;

    CHFSMCLIST_NODE_MAX_NUM(chfsmclist)  = max_num;
    CHFSMCLIST_NODE_USED_NUM(chfsmclist) = 0;

    for(node_pos = 0; node_pos < max_num; node_pos ++)
    {
        CHFSMCLIST_NODE *node;
        node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);

        chfsmclist_node_init(chfsmclist, node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL chfsmclist_free(CHFSMCLIST *chfsmclist)
{
    if(NULL_PTR != chfsmclist)
    {
        //chfsmclist_clean(chfsmclist);
        safe_free(chfsmclist, LOC_CHFSMCLIST_0002);
    }
    return (EC_TRUE);
}

EC_BOOL chfsmclist_clean(CHFSMCLIST *chfsmclist)
{
    uint32_t node_pos;

    CHFSMCLIST_HEAD(chfsmclist) = CHFSMCLIST_ERR_POS;
    CHFSMCLIST_TAIL(chfsmclist) = CHFSMCLIST_ERR_POS;

    CHFSMCLIST_NODE_USED_NUM(chfsmclist) = 0;

    for(node_pos = 0; node_pos < CHFSMCLIST_NODE_MAX_NUM(chfsmclist); node_pos ++)
    {
        CHFSMCLIST_NODE *node;
        node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);

        chfsmclist_node_clean(chfsmclist, node_pos);
    }
    return (EC_TRUE);
}

void chfsmclist_print(LOG *log, const CHFSMCLIST *chfsmclist)
{
    uint32_t node_pos;

    sys_log(log, "chfsmclist %p: max %u, used %u, head %u, tail %u\n",
                 chfsmclist,
                 CHFSMCLIST_NODE_MAX_NUM(chfsmclist),
                 CHFSMCLIST_NODE_USED_NUM(chfsmclist),
                 CHFSMCLIST_HEAD(chfsmclist),
                 CHFSMCLIST_TAIL(chfsmclist));

    node_pos = CHFSMCLIST_HEAD(chfsmclist);
    while(CHFSMCLIST_ERR_POS != node_pos)
    {
        CHFSMCLIST_NODE *node;
     
        chfsmclist_node_print(log, chfsmclist, node_pos);

        node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
        node_pos = CHFSMCLIST_NODE_RIGHT_POS(node);
    }
    return;
}

void chfsmclist_print_tail(LOG *log, const CHFSMCLIST *chfsmclist)
{
    uint32_t node_pos;

    sys_log(log, "chfsmclist %p: max %u, used %u, head %u, tail %u\n",
                 chfsmclist,
                 CHFSMCLIST_NODE_MAX_NUM(chfsmclist),
                 CHFSMCLIST_NODE_USED_NUM(chfsmclist),
                 CHFSMCLIST_HEAD(chfsmclist),
                 CHFSMCLIST_TAIL(chfsmclist));

    node_pos = CHFSMCLIST_TAIL(chfsmclist);
    while(CHFSMCLIST_ERR_POS != node_pos)
    {
        CHFSMCLIST_NODE *node;
     
        chfsmclist_node_print(log, chfsmclist, node_pos);

        node = CHFSMCLIST_FETCH_NODE(chfsmclist, node_pos);
        node_pos = CHFSMCLIST_NODE_LEFT_POS(node);
    }
    return;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

