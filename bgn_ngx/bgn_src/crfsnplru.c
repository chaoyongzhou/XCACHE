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

#include "crfsnplru.h"
#include "crfsnp.h"

#define CRFSNPLRU_ASSERT(condition)           ASSERT(condition)
//#define CRFSNPLRU_ASSERT(condition)           do{}while(0)

void crfsnplru_node_init(CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    CRFSNPLRU_NODE_PREV_POS(node)   = node_pos;
    CRFSNPLRU_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void crfsnplru_node_clean(CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    CRFSNPLRU_NODE_PREV_POS(node) = node_pos;
    CRFSNPLRU_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL crfsnplru_node_clone(const CRFSNPLRU_NODE *node_src, CRFSNPLRU_NODE *node_des)
{
    CRFSNPLRU_NODE_PREV_POS(node_des) = CRFSNPLRU_NODE_PREV_POS(node_src);
    CRFSNPLRU_NODE_NEXT_POS(node_des) = CRFSNPLRU_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void crfsnplru_node_print(LOG *log, const CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "crfsnplru_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CRFSNPLRU_NODE_PREV_POS(node),
                 CRFSNPLRU_NODE_NEXT_POS(node));

    return;
}

EC_BOOL crfsnplru_node_is_empty(const CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CRFSNPLRU_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfsnplru_is_empty(const CRFSNPLRU_NODE *head)
{
    if(CRFSNPLRU_ROOT_POS == CRFSNPLRU_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- LRU list operations ---------------------------------------------*/
STATIC_CAST void __crfsnplru_node_add(
                                CRFSNPLRU_NODE *new_node , const uint32_t new_pos,
                                CRFSNPLRU_NODE *prev_node, const uint32_t prev_pos,
                                CRFSNPLRU_NODE *next_node, const uint32_t next_pos)
{
    CRFSNPLRU_NODE_PREV_POS(next_node) = new_pos;
    CRFSNPLRU_NODE_NEXT_POS(new_node)  = next_pos;
    CRFSNPLRU_NODE_PREV_POS(new_node)  = prev_pos;
    CRFSNPLRU_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void crfsnplru_node_add_head(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CRFSNPLRU_ROOT_POS != CRFSNPLRU_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CRFSNPLRU_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CRFSNPLRU_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CRFSNPLRU_NODE *head;
        CRFSNPLRU_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CRFSNPLRU_ROOT_POS;
        head     = CRFSNP_LRU_LIST(crfsnp);

        next_pos = CRFSNPLRU_NODE_NEXT_POS(head);
        next     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, next_pos));

        __crfsnplru_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0071_CRFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] crfsnplru_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void crfsnplru_node_add_tail(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CRFSNPLRU_ROOT_POS != CRFSNPLRU_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CRFSNPLRU_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CRFSNPLRU_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CRFSNPLRU_NODE *head;
        CRFSNPLRU_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CRFSNPLRU_ROOT_POS;
        head     = CRFSNP_LRU_LIST(crfsnp);

        prev_pos = CRFSNPLRU_NODE_PREV_POS(head);
        prev     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, prev_pos));

        __crfsnplru_node_add(node, node_pos, prev, prev_pos, head, head_pos);

        dbg_log(SEC_0071_CRFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] crfsnplru_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __crfsnplru_node_rmv(
                        CRFSNPLRU_NODE *prev_node, const uint32_t prev_pos,
                        CRFSNPLRU_NODE *next_node, const uint32_t next_pos)
{
    CRFSNPLRU_NODE_PREV_POS(next_node) = prev_pos;
    CRFSNPLRU_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void crfsnplru_node_move_head(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CRFSNPLRU_ROOT_POS != CRFSNPLRU_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CRFSNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CRFSNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    && CRFSNPLRU_NODE_NEXT_POS(node) != CRFSNPLRU_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CRFSNPLRU_NODE *prev;
        CRFSNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CRFSNPLRU_NODE_PREV_POS(node);
        prev     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, prev_pos));

        next_pos = CRFSNPLRU_NODE_NEXT_POS(node);
        next     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, next_pos));

        __crfsnplru_node_rmv(prev, prev_pos, next, next_pos);
        crfsnplru_node_init(node, node_pos);

        crfsnplru_node_add_head(crfsnp, node, node_pos);

        dbg_log(SEC_0071_CRFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] crfsnplru_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void crfsnplru_node_move_tail(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CRFSNPLRU_ROOT_POS != CRFSNPLRU_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CRFSNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CRFSNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    && CRFSNPLRU_NODE_NEXT_POS(node) != CRFSNPLRU_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CRFSNPLRU_NODE *prev;
        CRFSNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CRFSNPLRU_NODE_PREV_POS(node);
        prev     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, prev_pos));

        next_pos = CRFSNPLRU_NODE_NEXT_POS(node);
        next     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, next_pos));

        __crfsnplru_node_rmv(prev, prev_pos, next, next_pos);
        crfsnplru_node_init(node, node_pos);

        crfsnplru_node_add_tail(crfsnp, node, node_pos);

        dbg_log(SEC_0071_CRFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] crfsnplru_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void crfsnplru_node_rmv(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CRFSNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CRFSNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CRFSNPLRU_NODE *prev;
        CRFSNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CRFSNPLRU_NODE_PREV_POS(node);
        prev     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, prev_pos));

        next_pos = CRFSNPLRU_NODE_NEXT_POS(node);
        next     = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, next_pos));

        __crfsnplru_node_rmv(prev, prev_pos, next, next_pos);
        crfsnplru_node_init(node, node_pos);

        dbg_log(SEC_0071_CRFSNPLRU, 9)(LOGSTDOUT, "[DEBUG] crfsnplru_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL crfsnplru_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CRFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0071_CRFSNPLRU, 0)(LOGSTDERR, "error:crfsnplru_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CRFSNPRB_NODE  *crfsnprb_node;
        CRFSNP_ITEM    *crfsnp_item;

        crfsnprb_node  = CRFSNPRB_POOL_NODE(pool, node_pos);
        crfsnp_item    = (CRFSNP_ITEM *)crfsnprb_node;

        CRFSNPLRU_ASSERT((void *)crfsnp_item == (void *)crfsnprb_node); /*address must be aligned*/

        crfsnplru_node_init(CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0071_CRFSNPLRU, 0)(LOGSTDOUT, "info:crfsnplru_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0071_CRFSNPLRU, 0)(LOGSTDOUT, "info:crfsnplru_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void crfsnplru_list_print(LOG *log, const CRFSNP *crfsnp)
{
    const CRFSNPLRU_NODE *node;
    uint32_t node_pos;

    node_pos = CRFSNPLRU_ROOT_POS;

    do
    {
        node = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, node_pos));
        crfsnplru_node_print(log, node, node_pos);

        node_pos = CRFSNPLRU_NODE_NEXT_POS(node);

    }while(CRFSNPLRU_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
