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
#include "task.h"
#include "cmcnpque.h"
#include "cmcnp.h"

#define CMCNPQUE_ASSERT(condition)           ASSERT(condition)
//#define CMCNPQUE_ASSERT(condition)           do{}while(0)

void cmcnpque_node_init(CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    CMCNPQUE_NODE_PREV_POS(node)   = node_pos;
    CMCNPQUE_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cmcnpque_node_clean(CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    CMCNPQUE_NODE_PREV_POS(node) = node_pos;
    CMCNPQUE_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cmcnpque_node_clone(const CMCNPQUE_NODE *node_src, CMCNPQUE_NODE *node_des)
{
    CMCNPQUE_NODE_PREV_POS(node_des) = CMCNPQUE_NODE_PREV_POS(node_src);
    CMCNPQUE_NODE_NEXT_POS(node_des) = CMCNPQUE_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cmcnpque_node_print(LOG *log, const CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cmcnpque_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CMCNPQUE_NODE_PREV_POS(node),
                 CMCNPQUE_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cmcnpque_node_is_empty(const CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CMCNPQUE_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmcnpque_is_empty(const CMCNPQUE_NODE *head)
{
    if(CMCNPQUE_ROOT_POS == CMCNPQUE_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- QUE list operations ---------------------------------------------*/
STATIC_CAST void __cmcnpque_node_add(
                                CMCNPQUE_NODE *new_node , const uint32_t new_pos,
                                CMCNPQUE_NODE *prev_node, const uint32_t prev_pos,
                                CMCNPQUE_NODE *next_node, const uint32_t next_pos)
{
    CMCNPQUE_NODE_PREV_POS(next_node) = new_pos;
    CMCNPQUE_NODE_NEXT_POS(new_node)  = next_pos;
    CMCNPQUE_NODE_PREV_POS(new_node)  = prev_pos;
    CMCNPQUE_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cmcnpque_node_add_head(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(CMCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPQUE_ROOT_POS != CMCNPQUE_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CMCNPQUE_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPQUE_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CMCNPQUE_NODE *head;
        CMCNPQUE_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CMCNPQUE_ROOT_POS;
        head     = CMCNP_QUE_LIST(cmcnp);

        next_pos = CMCNPQUE_NODE_NEXT_POS(head);
        next     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpque_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0114_CMCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cmcnpque_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cmcnpque_node_add_tail(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(SWITCH_ON == CMC_LRU_MODEL_SWITCH
    && CMCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPQUE_ROOT_POS != CMCNPQUE_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CMCNPQUE_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPQUE_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CMCNPQUE_NODE *head;
        CMCNPQUE_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CMCNPQUE_ROOT_POS;
        head     = CMCNP_QUE_LIST(cmcnp);

        prev_pos = CMCNPQUE_NODE_PREV_POS(head);
        prev     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, prev_pos));

        __cmcnpque_node_add(node, node_pos, prev, prev_pos, head, head_pos);

        dbg_log(SEC_0114_CMCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cmcnpque_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cmcnpque_node_rmv(
                        CMCNPQUE_NODE *prev_node, const uint32_t prev_pos,
                        CMCNPQUE_NODE *next_node, const uint32_t next_pos)
{
    CMCNPQUE_NODE_PREV_POS(next_node) = prev_pos;
    CMCNPQUE_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cmcnpque_node_move_head(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(SWITCH_ON == CMC_LRU_MODEL_SWITCH
    && CMCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPQUE_ROOT_POS != CMCNPQUE_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CMCNPQUE_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPQUE_NODE_PREV_POS(node) /*ensure node in list*/
    && CMCNPQUE_NODE_NEXT_POS(node) != CMCNPQUE_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CMCNPQUE_NODE *prev;
        CMCNPQUE_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPQUE_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPQUE_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpque_node_rmv(prev, prev_pos, next, next_pos);
        cmcnpque_node_init(node, node_pos);

        cmcnpque_node_add_head(cmcnp, node, node_pos);

        dbg_log(SEC_0114_CMCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cmcnpque_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cmcnpque_node_move_tail(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(SWITCH_ON == CMC_LRU_MODEL_SWITCH
    && CMCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPQUE_ROOT_POS != CMCNPQUE_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CMCNPQUE_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPQUE_NODE_PREV_POS(node) /*ensure node in list*/
    && CMCNPQUE_NODE_NEXT_POS(node) != CMCNPQUE_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CMCNPQUE_NODE *prev;
        CMCNPQUE_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPQUE_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPQUE_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpque_node_rmv(prev, prev_pos, next, next_pos);
        cmcnpque_node_init(node, node_pos);

        cmcnpque_node_add_tail(cmcnp, node, node_pos);

        dbg_log(SEC_0114_CMCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cmcnpque_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cmcnpque_node_rmv(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(CMCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CMCNPQUE_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPQUE_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CMCNPQUE_NODE *prev;
        CMCNPQUE_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPQUE_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPQUE_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpque_node_rmv(prev, prev_pos, next, next_pos);
        cmcnpque_node_init(node, node_pos);

        dbg_log(SEC_0114_CMCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cmcnpque_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cmcnpque_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CMCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0114_CMCNPQUE, 0)(LOGSTDOUT, "error:cmcnpque_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CMCNPRB_NODE  *cmcnprb_node;
        CMCNP_ITEM    *cmcnp_item;

        cmcnprb_node  = CMCNPRB_POOL_NODE(pool, node_pos);
        cmcnp_item    = (CMCNP_ITEM *)cmcnprb_node;

        CMCNPQUE_ASSERT((void *)cmcnp_item == (void *)cmcnprb_node); /*address must be aligned*/

        cmcnpque_node_init(CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0114_CMCNPQUE, 9)(LOGSTDOUT, "info:cmcnpque_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0114_CMCNPQUE, 0)(LOGSTDOUT, "info:cmcnpque_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cmcnpque_list_print(LOG *log, const CMCNP *cmcnp)
{
    const CMCNPQUE_NODE *node;
    uint32_t node_pos;

    node_pos = CMCNPQUE_ROOT_POS;

    do
    {
        node = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, node_pos));
        cmcnpque_node_print(log, node, node_pos);

        node_pos = CMCNPQUE_NODE_NEXT_POS(node);

    }while(CMCNPQUE_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
