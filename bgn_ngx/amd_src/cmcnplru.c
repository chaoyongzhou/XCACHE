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

#include "cmcnplru.h"
#include "cmcnp.h"

#define CMCNPLRU_ASSERT(condition)           ASSERT(condition)
//#define CMCNPLRU_ASSERT(condition)           do{}while(0)

void cmcnplru_node_init(CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    CMCNPLRU_NODE_PREV_POS(node)   = node_pos;
    CMCNPLRU_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cmcnplru_node_clean(CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    CMCNPLRU_NODE_PREV_POS(node) = node_pos;
    CMCNPLRU_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cmcnplru_node_clone(const CMCNPLRU_NODE *node_src, CMCNPLRU_NODE *node_des)
{
    CMCNPLRU_NODE_PREV_POS(node_des) = CMCNPLRU_NODE_PREV_POS(node_src);
    CMCNPLRU_NODE_NEXT_POS(node_des) = CMCNPLRU_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cmcnplru_node_print(LOG *log, const CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cmcnplru_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CMCNPLRU_NODE_PREV_POS(node),
                 CMCNPLRU_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cmcnplru_node_is_empty(const CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CMCNPLRU_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmcnplru_is_empty(const CMCNPLRU_NODE *head)
{
    if(CMCNPLRU_ROOT_POS == CMCNPLRU_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- LRU list operations ---------------------------------------------*/
STATIC_CAST void __cmcnplru_node_add(
                                CMCNPLRU_NODE *new_node , const uint32_t new_pos,
                                CMCNPLRU_NODE *prev_node, const uint32_t prev_pos,
                                CMCNPLRU_NODE *next_node, const uint32_t next_pos)
{
    CMCNPLRU_NODE_PREV_POS(next_node) = new_pos;
    CMCNPLRU_NODE_NEXT_POS(new_node)  = next_pos;
    CMCNPLRU_NODE_PREV_POS(new_node)  = prev_pos;
    CMCNPLRU_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cmcnplru_node_add_head(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CMCNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPLRU_ROOT_POS != CMCNPLRU_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CMCNPLRU_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPLRU_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CMCNPLRU_NODE *head;
        CMCNPLRU_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CMCNPLRU_ROOT_POS;
        head     = CMCNP_LRU_LIST(cmcnp);

        next_pos = CMCNPLRU_NODE_NEXT_POS(head);
        next     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnplru_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0114_CMCNPLRU, 9)(LOGSTDOUT, "[DEBUG] cmcnplru_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cmcnplru_node_add_tail(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CMCNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPLRU_ROOT_POS != CMCNPLRU_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CMCNPLRU_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPLRU_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CMCNPLRU_NODE *head;
        CMCNPLRU_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CMCNPLRU_ROOT_POS;
        head     = CMCNP_LRU_LIST(cmcnp);

        prev_pos = CMCNPLRU_NODE_PREV_POS(head);
        prev     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, prev_pos));

        __cmcnplru_node_add(node, node_pos, prev, prev_pos, head, head_pos);

        dbg_log(SEC_0114_CMCNPLRU, 9)(LOGSTDOUT, "[DEBUG] cmcnplru_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cmcnplru_node_rmv(
                        CMCNPLRU_NODE *prev_node, const uint32_t prev_pos,
                        CMCNPLRU_NODE *next_node, const uint32_t next_pos)
{
    CMCNPLRU_NODE_PREV_POS(next_node) = prev_pos;
    CMCNPLRU_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cmcnplru_node_move_head(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CMCNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPLRU_ROOT_POS != CMCNPLRU_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CMCNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    && CMCNPLRU_NODE_NEXT_POS(node) != CMCNPLRU_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CMCNPLRU_NODE *prev;
        CMCNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPLRU_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPLRU_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnplru_node_rmv(prev, prev_pos, next, next_pos);
        cmcnplru_node_init(node, node_pos);

        cmcnplru_node_add_head(cmcnp, node, node_pos);

        dbg_log(SEC_0114_CMCNPLRU, 9)(LOGSTDOUT, "[DEBUG] cmcnplru_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cmcnplru_node_move_tail(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CMCNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPLRU_ROOT_POS != CMCNPLRU_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CMCNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    && CMCNPLRU_NODE_NEXT_POS(node) != CMCNPLRU_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CMCNPLRU_NODE *prev;
        CMCNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPLRU_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPLRU_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnplru_node_rmv(prev, prev_pos, next, next_pos);
        cmcnplru_node_init(node, node_pos);

        cmcnplru_node_add_tail(cmcnp, node, node_pos);

        dbg_log(SEC_0114_CMCNPLRU, 9)(LOGSTDOUT, "[DEBUG] cmcnplru_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cmcnplru_node_rmv(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos)
{
    if(CMCNPLRU_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CMCNPLRU_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPLRU_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CMCNPLRU_NODE *prev;
        CMCNPLRU_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPLRU_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPLRU_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnplru_node_rmv(prev, prev_pos, next, next_pos);
        cmcnplru_node_init(node, node_pos);

        dbg_log(SEC_0114_CMCNPLRU, 9)(LOGSTDOUT, "[DEBUG] cmcnplru_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cmcnplru_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CMCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0114_CMCNPLRU, 0)(LOGSTDERR, "error:cmcnplru_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CMCNPRB_NODE  *cmcnprb_node;
        CMCNP_ITEM    *cmcnp_item;

        cmcnprb_node  = CMCNPRB_POOL_NODE(pool, node_pos);
        cmcnp_item    = (CMCNP_ITEM *)cmcnprb_node;

        CMCNPLRU_ASSERT((void *)cmcnp_item == (void *)cmcnprb_node); /*address must be aligned*/

        cmcnplru_node_init(CMCNP_ITEM_LRU_NODE(cmcnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0114_CMCNPLRU, 9)(LOGSTDOUT, "info:cmcnplru_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0114_CMCNPLRU, 0)(LOGSTDOUT, "info:cmcnplru_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cmcnplru_list_print(LOG *log, const CMCNP *cmcnp)
{
    const CMCNPLRU_NODE *node;
    uint32_t node_pos;

    node_pos = CMCNPLRU_ROOT_POS;

    do
    {
        node = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, node_pos));
        cmcnplru_node_print(log, node, node_pos);

        node_pos = CMCNPLRU_NODE_NEXT_POS(node);

    }while(CMCNPLRU_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
