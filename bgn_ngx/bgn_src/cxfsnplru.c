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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cxfsnplru.h"
#include "cxfsnp.h"

#define CXFSNPLRU_ASSERT(condition)           ASSERT(condition)
//#define CXFSNPLRU_ASSERT(condition)           do{}while(0)

void cxfsnplru_node_init(CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    CXFSNPLRU_NODE_PREV_POS(node)   = node_pos;
    CXFSNPLRU_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cxfsnplru_node_clean(CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    CXFSNPLRU_NODE_PREV_POS(node) = node_pos;
    CXFSNPLRU_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cxfsnplru_node_clone(const CXFSNPLRU_NODE *node_src, CXFSNPLRU_NODE *node_des)
{
    CXFSNPLRU_NODE_PREV_POS(node_des) = CXFSNPLRU_NODE_PREV_POS(node_src);
    CXFSNPLRU_NODE_NEXT_POS(node_des) = CXFSNPLRU_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cxfsnplru_node_print(LOG *log, const CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cxfsnplru_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CXFSNPLRU_NODE_PREV_POS(node),
                 CXFSNPLRU_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cxfsnplru_node_is_empty(const CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CXFSNPLRU_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnplru_is_empty(const CXFSNPLRU_NODE *head)
{
    if(CXFSNPLRU_ROOT_POS == CXFSNPLRU_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- LRU list operations ---------------------------------------------*/
STATIC_CAST void __cxfsnplru_node_add(
                                CXFSNPLRU_NODE *new_node , const uint32_t new_pos,
                                CXFSNPLRU_NODE *prev_node, const uint32_t prev_pos,
                                CXFSNPLRU_NODE *next_node, const uint32_t next_pos)
{
    CXFSNPLRU_NODE_PREV_POS(next_node) = new_pos;
    CXFSNPLRU_NODE_NEXT_POS(new_node)  = next_pos;
    CXFSNPLRU_NODE_PREV_POS(new_node)  = prev_pos;
    CXFSNPLRU_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cxfsnplru_node_add_head(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPLRU_ROOT_POS != CXFSNPLRU_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CXFSNPLRU_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CXFSNPLRU_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CXFSNPLRU_NODE *head;
        CXFSNPLRU_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CXFSNPLRU_ROOT_POS;
        head     = CXFSNP_LRU_LIST(cxfsnp);

        next_pos = CXFSNPLRU_NODE_NEXT_POS(head);
        next     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnplru_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0195_CXFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] cxfsnplru_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cxfsnplru_node_add_tail(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPLRU_ROOT_POS != CXFSNPLRU_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CXFSNPLRU_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CXFSNPLRU_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CXFSNPLRU_NODE *head;
        CXFSNPLRU_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CXFSNPLRU_ROOT_POS;
        head     = CXFSNP_LRU_LIST(cxfsnp);

        prev_pos = CXFSNPLRU_NODE_PREV_POS(head);
        prev     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        __cxfsnplru_node_add(node, node_pos, prev, prev_pos, head, head_pos);

        dbg_log(SEC_0195_CXFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] cxfsnplru_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cxfsnplru_node_rmv(
                        CXFSNPLRU_NODE *prev_node, const uint32_t prev_pos,
                        CXFSNPLRU_NODE *next_node, const uint32_t next_pos)
{
    CXFSNPLRU_NODE_PREV_POS(next_node) = prev_pos;
    CXFSNPLRU_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cxfsnplru_node_move_head(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPLRU_ROOT_POS != CXFSNPLRU_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CXFSNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CXFSNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    && CXFSNPLRU_NODE_NEXT_POS(node) != CXFSNPLRU_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CXFSNPLRU_NODE *prev;
        CXFSNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CXFSNPLRU_NODE_PREV_POS(node);
        prev     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        next_pos = CXFSNPLRU_NODE_NEXT_POS(node);
        next     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnplru_node_rmv(prev, prev_pos, next, next_pos);
        cxfsnplru_node_init(node, node_pos);

        cxfsnplru_node_add_head(cxfsnp, node, node_pos);

        dbg_log(SEC_0195_CXFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] cxfsnplru_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cxfsnplru_node_move_tail(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPLRU_ROOT_POS != CXFSNPLRU_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CXFSNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CXFSNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    && CXFSNPLRU_NODE_NEXT_POS(node) != CXFSNPLRU_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CXFSNPLRU_NODE *prev;
        CXFSNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CXFSNPLRU_NODE_PREV_POS(node);
        prev     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        next_pos = CXFSNPLRU_NODE_NEXT_POS(node);
        next     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnplru_node_rmv(prev, prev_pos, next, next_pos);
        cxfsnplru_node_init(node, node_pos);

        cxfsnplru_node_add_tail(cxfsnp, node, node_pos);

        dbg_log(SEC_0195_CXFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] cxfsnplru_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cxfsnplru_node_rmv(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CXFSNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CXFSNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CXFSNPLRU_NODE *prev;
        CXFSNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CXFSNPLRU_NODE_PREV_POS(node);
        prev     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        next_pos = CXFSNPLRU_NODE_NEXT_POS(node);
        next     = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnplru_node_rmv(prev, prev_pos, next, next_pos);
        cxfsnplru_node_init(node, node_pos);

        dbg_log(SEC_0195_CXFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] cxfsnplru_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cxfsnplru_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CXFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0195_CXFSNPLRU, 0)(LOGSTDERR, "error:cxfsnplru_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CXFSNPRB_NODE  *cxfsnprb_node;
        CXFSNP_ITEM    *cxfsnp_item;

        cxfsnprb_node  = CXFSNPRB_POOL_NODE(pool, node_pos);
        cxfsnp_item    = (CXFSNP_ITEM *)cxfsnprb_node;

        CXFSNPLRU_ASSERT((void *)cxfsnp_item == (void *)cxfsnprb_node); /*address must be aligned*/

        cxfsnplru_node_init(CXFSNP_ITEM_LRU_NODE(cxfsnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0195_CXFSNPLRU, 0)(LOGSTDOUT, "info:cxfsnplru_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0195_CXFSNPLRU, 0)(LOGSTDOUT, "info:cxfsnplru_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cxfsnplru_list_print(LOG *log, const CXFSNP *cxfsnp)
{
    const CXFSNPLRU_NODE *node;
    uint32_t node_pos;

    node_pos = CXFSNPLRU_ROOT_POS;

    do
    {
        node = CXFSNP_ITEM_LRU_NODE(cxfsnp_fetch(cxfsnp, node_pos));
        cxfsnplru_node_print(log, node, node_pos);

        node_pos = CXFSNPLRU_NODE_NEXT_POS(node);

    }while(CXFSNPLRU_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
