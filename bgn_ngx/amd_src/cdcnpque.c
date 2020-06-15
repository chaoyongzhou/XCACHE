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
#include "cdcnpque.h"
#include "cdcnp.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCNPQUE_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCNPQUE_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

void cdcnpque_node_init(CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    CDCNPQUE_NODE_PREV_POS(node)   = node_pos;
    CDCNPQUE_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cdcnpque_node_clean(CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    CDCNPQUE_NODE_PREV_POS(node) = node_pos;
    CDCNPQUE_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cdcnpque_node_clone(const CDCNPQUE_NODE *node_src, CDCNPQUE_NODE *node_des)
{
    CDCNPQUE_NODE_PREV_POS(node_des) = CDCNPQUE_NODE_PREV_POS(node_src);
    CDCNPQUE_NODE_NEXT_POS(node_des) = CDCNPQUE_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cdcnpque_node_print(LOG *log, const CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cdcnpque_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CDCNPQUE_NODE_PREV_POS(node),
                 CDCNPQUE_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cdcnpque_node_is_empty(const CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CDCNPQUE_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdcnpque_is_empty(const CDCNPQUE_NODE *head)
{
    if(CDCNPQUE_ROOT_POS == CDCNPQUE_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- QUE list operations ---------------------------------------------*/
STATIC_CAST void __cdcnpque_node_add(
                                CDCNPQUE_NODE *new_node , const uint32_t new_pos,
                                CDCNPQUE_NODE *prev_node, const uint32_t prev_pos,
                                CDCNPQUE_NODE *next_node, const uint32_t next_pos)
{
    CDCNPQUE_NODE_PREV_POS(next_node) = new_pos;
    CDCNPQUE_NODE_NEXT_POS(new_node)  = next_pos;
    CDCNPQUE_NODE_PREV_POS(new_node)  = prev_pos;
    CDCNPQUE_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cdcnpque_node_add_head(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(CDCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPQUE_ROOT_POS != CDCNPQUE_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CDCNPQUE_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CDCNPQUE_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CDCNPQUE_NODE *head;
        CDCNPQUE_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CDCNPQUE_ROOT_POS;
        head     = CDCNP_QUE_LIST(cdcnp);

        next_pos = CDCNPQUE_NODE_NEXT_POS(head);
        next     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpque_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0180_CDCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cdcnpque_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpque_node_add_tail(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(SWITCH_ON == CDC_LRU_MODEL_SWITCH
    && CDCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPQUE_ROOT_POS != CDCNPQUE_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CDCNPQUE_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CDCNPQUE_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CDCNPQUE_NODE *head;
        CDCNPQUE_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CDCNPQUE_ROOT_POS;
        head     = CDCNP_QUE_LIST(cdcnp);

        prev_pos = CDCNPQUE_NODE_PREV_POS(head);
        prev     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, prev_pos));

        __cdcnpque_node_add(node, node_pos, prev, prev_pos, head, head_pos);

        dbg_log(SEC_0180_CDCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cdcnpque_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cdcnpque_node_rmv(
                        CDCNPQUE_NODE *prev_node, const uint32_t prev_pos,
                        CDCNPQUE_NODE *next_node, const uint32_t next_pos)
{
    CDCNPQUE_NODE_PREV_POS(next_node) = prev_pos;
    CDCNPQUE_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cdcnpque_node_move_head(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(SWITCH_ON == CDC_LRU_MODEL_SWITCH
    && CDCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPQUE_ROOT_POS != CDCNPQUE_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CDCNPQUE_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPQUE_NODE_PREV_POS(node) /*ensure node in list*/
    && CDCNPQUE_NODE_NEXT_POS(node) != CDCNPQUE_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CDCNPQUE_NODE *prev;
        CDCNPQUE_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPQUE_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPQUE_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpque_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpque_node_init(node, node_pos);

        cdcnpque_node_add_head(cdcnp, node, node_pos);

        dbg_log(SEC_0180_CDCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cdcnpque_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpque_node_move_tail(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(SWITCH_ON == CDC_LRU_MODEL_SWITCH
    && CDCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPQUE_ROOT_POS != CDCNPQUE_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CDCNPQUE_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPQUE_NODE_PREV_POS(node) /*ensure node in list*/
    && CDCNPQUE_NODE_NEXT_POS(node) != CDCNPQUE_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CDCNPQUE_NODE *prev;
        CDCNPQUE_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPQUE_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPQUE_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpque_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpque_node_init(node, node_pos);

        cdcnpque_node_add_tail(cdcnp, node, node_pos);

        dbg_log(SEC_0180_CDCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cdcnpque_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpque_node_rmv(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos)
{
    if(CDCNPQUE_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CDCNPQUE_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPQUE_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CDCNPQUE_NODE *prev;
        CDCNPQUE_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPQUE_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPQUE_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpque_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpque_node_init(node, node_pos);

        dbg_log(SEC_0180_CDCNPQUE, 9)(LOGSTDOUT, "[DEBUG] cdcnpque_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cdcnpque_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CDCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0180_CDCNPQUE, 0)(LOGSTDOUT, "error:cdcnpque_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CDCNPRB_NODE  *cdcnprb_node;
        CDCNP_ITEM    *cdcnp_item;

        cdcnprb_node  = CDCNPRB_POOL_NODE(pool, node_pos);
        cdcnp_item    = (CDCNP_ITEM *)cdcnprb_node;

        CDCNPQUE_ASSERT((void *)cdcnp_item == (void *)cdcnprb_node); /*address must be aligned*/

        cdcnpque_node_init(CDCNP_ITEM_QUE_NODE(cdcnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0180_CDCNPQUE, 9)(LOGSTDOUT, "info:cdcnpque_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0180_CDCNPQUE, 0)(LOGSTDOUT, "info:cdcnpque_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cdcnpque_list_print(LOG *log, const CDCNP *cdcnp)
{
    const CDCNPQUE_NODE *node;
    uint32_t node_pos;

    node_pos = CDCNPQUE_ROOT_POS;

    do
    {
        node = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, node_pos));
        cdcnpque_node_print(log, node, node_pos);

        node_pos = CDCNPQUE_NODE_NEXT_POS(node);

    }while(CDCNPQUE_ROOT_POS != node_pos);
    return;
}

UINT32 cdcnpque_count(const CDCNP *cdcnp)
{
    const CDCNPQUE_NODE *node;
    UINT32   node_num;
    uint32_t node_pos;

    node_num = 0;
    node_pos = CDCNPQUE_ROOT_POS;

    do
    {
        node = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, node_pos));
        node_num ++;

        node_pos = CDCNPQUE_NODE_NEXT_POS(node);

    }while(CDCNPQUE_ROOT_POS != node_pos);

    return (node_num);
}

void cdcnpque_walk(const CDCNP *cdcnp, void *data, EC_BOOL (*walker)(const CDCNPQUE_NODE *, const uint32_t, void *))
{
    const CDCNPQUE_NODE *node;
    uint32_t node_pos;

    node_pos = CDCNPQUE_ROOT_POS;

    do
    {
        node = CDCNP_ITEM_QUE_NODE(cdcnp_fetch(cdcnp, node_pos));

        if(EC_FALSE == walker(node, node_pos, data))
        {
            break;
        }

        node_pos = CDCNPQUE_NODE_NEXT_POS(node);

    }while(CDCNPQUE_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
