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

#include "cdcnpdeg.h"
#include "cdcnp.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCNPDEG_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCNPDEG_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

void cdcnpdeg_node_init(CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    CDCNPDEG_NODE_PREV_POS(node)   = node_pos;
    CDCNPDEG_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cdcnpdeg_node_clean(CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    CDCNPDEG_NODE_PREV_POS(node) = node_pos;
    CDCNPDEG_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cdcnpdeg_node_clone(const CDCNPDEG_NODE *node_src, CDCNPDEG_NODE *node_des)
{
    CDCNPDEG_NODE_PREV_POS(node_des) = CDCNPDEG_NODE_PREV_POS(node_src);
    CDCNPDEG_NODE_NEXT_POS(node_des) = CDCNPDEG_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cdcnpdeg_node_print(LOG *log, const CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cdcnpdeg_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CDCNPDEG_NODE_PREV_POS(node),
                 CDCNPDEG_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cdcnpdeg_node_is_empty(const CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CDCNPDEG_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdcnpdeg_is_empty(const CDCNPDEG_NODE *head)
{
    if(CDCNPDEG_ROOT_POS == CDCNPDEG_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- DEG list operations ---------------------------------------------*/
STATIC_CAST void __cdcnpdeg_node_add(
                                CDCNPDEG_NODE *new_node , const uint32_t new_pos,
                                CDCNPDEG_NODE *prev_node, const uint32_t prev_pos,
                                CDCNPDEG_NODE *next_node, const uint32_t next_pos)
{
    CDCNPDEG_NODE_PREV_POS(next_node) = new_pos;
    CDCNPDEG_NODE_NEXT_POS(new_node)  = next_pos;
    CDCNPDEG_NODE_PREV_POS(new_node)  = prev_pos;
    CDCNPDEG_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cdcnpdeg_node_add_head(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEG_ROOT_POS != CDCNPDEG_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CDCNPDEG_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CDCNPDEG_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CDCNPDEG_NODE *head;
        CDCNPDEG_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CDCNPDEG_ROOT_POS;
        head     = CDCNP_DEG_LIST(cdcnp);

        next_pos = CDCNPDEG_NODE_NEXT_POS(head);
        next     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdeg_node_add(node, node_pos, head, head_pos, next, next_pos);
        CDCNP_DEG_NODE_NUM(cdcnp) ++;

        dbg_log(SEC_0188_CDCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cdcnpdeg_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpdeg_node_add_tail(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEG_ROOT_POS != CDCNPDEG_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CDCNPDEG_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CDCNPDEG_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CDCNPDEG_NODE *head;
        CDCNPDEG_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CDCNPDEG_ROOT_POS;
        head     = CDCNP_DEG_LIST(cdcnp);

        prev_pos = CDCNPDEG_NODE_PREV_POS(head);
        prev     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, prev_pos));

        __cdcnpdeg_node_add(node, node_pos, prev, prev_pos, head, head_pos);
        CDCNP_DEG_NODE_NUM(cdcnp) ++;

        dbg_log(SEC_0188_CDCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cdcnpdeg_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cdcnpdeg_node_rmv(
                        CDCNPDEG_NODE *prev_node, const uint32_t prev_pos,
                        CDCNPDEG_NODE *next_node, const uint32_t next_pos)
{
    CDCNPDEG_NODE_PREV_POS(next_node) = prev_pos;
    CDCNPDEG_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cdcnpdeg_node_move_head(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEG_ROOT_POS != CDCNPDEG_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CDCNPDEG_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPDEG_NODE_PREV_POS(node) /*ensure node in list*/
    && CDCNPDEG_NODE_NEXT_POS(node) != CDCNPDEG_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CDCNPDEG_NODE *prev;
        CDCNPDEG_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPDEG_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPDEG_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdeg_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpdeg_node_init(node, node_pos);
        CDCNP_DEG_NODE_NUM(cdcnp) --;

        cdcnpdeg_node_add_head(cdcnp, node, node_pos);

        dbg_log(SEC_0188_CDCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cdcnpdeg_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpdeg_node_move_tail(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEG_ROOT_POS != CDCNPDEG_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CDCNPDEG_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPDEG_NODE_PREV_POS(node) /*ensure node in list*/
    && CDCNPDEG_NODE_NEXT_POS(node) != CDCNPDEG_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CDCNPDEG_NODE *prev;
        CDCNPDEG_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPDEG_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPDEG_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdeg_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpdeg_node_init(node, node_pos);
        CDCNP_DEG_NODE_NUM(cdcnp) --;

        cdcnpdeg_node_add_tail(cdcnp, node, node_pos);

        dbg_log(SEC_0188_CDCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cdcnpdeg_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpdeg_node_rmv(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CDCNPDEG_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPDEG_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CDCNPDEG_NODE *prev;
        CDCNPDEG_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPDEG_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPDEG_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdeg_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpdeg_node_init(node, node_pos);
        CDCNP_DEG_NODE_NUM(cdcnp) --;

        dbg_log(SEC_0188_CDCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cdcnpdeg_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cdcnpdeg_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CDCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0188_CDCNPDEG, 0)(LOGSTDERR, "error:cdcnpdeg_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CDCNPRB_NODE  *cdcnprb_node;
        CDCNP_ITEM    *cdcnp_item;

        cdcnprb_node  = CDCNPRB_POOL_NODE(pool, node_pos);
        cdcnp_item    = (CDCNP_ITEM *)cdcnprb_node;

        CDCNPDEG_ASSERT((void *)cdcnp_item == (void *)cdcnprb_node); /*address must be aligned*/

        cdcnpdeg_node_init(CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0188_CDCNPDEG, 9)(LOGSTDOUT, "info:cdcnpdeg_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0188_CDCNPDEG, 0)(LOGSTDOUT, "info:cdcnpdeg_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cdcnpdeg_list_print(LOG *log, const CDCNP *cdcnp)
{
    const CDCNPDEG_NODE *node;
    uint32_t node_pos;

    node_pos = CDCNPDEG_ROOT_POS;

    do
    {
        node = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, node_pos));
        cdcnpdeg_node_print(log, node, node_pos);

        node_pos = CDCNPDEG_NODE_NEXT_POS(node);

    }while(CDCNPDEG_ROOT_POS != node_pos);

    return;
}

UINT32 cdcnpdeg_count(const CDCNP *cdcnp)
{
    const CDCNPDEG_NODE *node;
    UINT32   node_num;
    uint32_t node_pos;

    node_num = 0;
    node_pos = CDCNPDEG_ROOT_POS;

    do
    {
        node = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, node_pos));
        node_num ++;

        node_pos = CDCNPDEG_NODE_NEXT_POS(node);

    }while(CDCNPDEG_ROOT_POS != node_pos);

    return (-- node_num); /*discard root item*/
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
