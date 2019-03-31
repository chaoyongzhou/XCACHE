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

#include "cmcnpdeg.h"
#include "cmcnp.h"

#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMCNPDEG_ASSERT(condition)           ASSERT(condition)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMCNPDEG_ASSERT(condition)           do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

void cmcnpdeg_node_init(CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    CMCNPDEG_NODE_PREV_POS(node)   = node_pos;
    CMCNPDEG_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cmcnpdeg_node_clean(CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    CMCNPDEG_NODE_PREV_POS(node) = node_pos;
    CMCNPDEG_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cmcnpdeg_node_clone(const CMCNPDEG_NODE *node_src, CMCNPDEG_NODE *node_des)
{
    CMCNPDEG_NODE_PREV_POS(node_des) = CMCNPDEG_NODE_PREV_POS(node_src);
    CMCNPDEG_NODE_NEXT_POS(node_des) = CMCNPDEG_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cmcnpdeg_node_print(LOG *log, const CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cmcnpdeg_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CMCNPDEG_NODE_PREV_POS(node),
                 CMCNPDEG_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cmcnpdeg_node_is_empty(const CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CMCNPDEG_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmcnpdeg_is_empty(const CMCNPDEG_NODE *head)
{
    if(CMCNPDEG_ROOT_POS == CMCNPDEG_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- DEG list operations ---------------------------------------------*/
STATIC_CAST void __cmcnpdeg_node_add(
                                CMCNPDEG_NODE *new_node , const uint32_t new_pos,
                                CMCNPDEG_NODE *prev_node, const uint32_t prev_pos,
                                CMCNPDEG_NODE *next_node, const uint32_t next_pos)
{
    CMCNPDEG_NODE_PREV_POS(next_node) = new_pos;
    CMCNPDEG_NODE_NEXT_POS(new_node)  = next_pos;
    CMCNPDEG_NODE_PREV_POS(new_node)  = prev_pos;
    CMCNPDEG_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cmcnpdeg_node_add_head(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CMCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CMCNPDEG_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPDEG_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CMCNPDEG_NODE *head;
        CMCNPDEG_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CMCNPDEG_ROOT_POS;
        head     = CMCNP_DEG_LIST(cmcnp);

        next_pos = CMCNPDEG_NODE_NEXT_POS(head);
        next     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpdeg_node_add(node, node_pos, head, head_pos, next, next_pos);
        CMCNP_DEG_NODE_NUM(cmcnp) ++;

        dbg_log(SEC_0189_CMCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cmcnpdeg_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cmcnpdeg_node_add_tail(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CMCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CMCNPDEG_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPDEG_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CMCNPDEG_NODE *head;
        CMCNPDEG_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CMCNPDEG_ROOT_POS;
        head     = CMCNP_DEG_LIST(cmcnp);

        prev_pos = CMCNPDEG_NODE_PREV_POS(head);
        prev     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, prev_pos));

        __cmcnpdeg_node_add(node, node_pos, prev, prev_pos, head, head_pos);
        CMCNP_DEG_NODE_NUM(cmcnp) ++;

        dbg_log(SEC_0189_CMCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cmcnpdeg_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cmcnpdeg_node_rmv(
                        CMCNPDEG_NODE *prev_node, const uint32_t prev_pos,
                        CMCNPDEG_NODE *next_node, const uint32_t next_pos)
{
    CMCNPDEG_NODE_PREV_POS(next_node) = prev_pos;
    CMCNPDEG_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cmcnpdeg_node_move_head(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CMCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CMCNPDEG_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPDEG_NODE_PREV_POS(node) /*ensure node in list*/
    && CMCNPDEG_NODE_NEXT_POS(node) != CMCNPDEG_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CMCNPDEG_NODE *prev;
        CMCNPDEG_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPDEG_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPDEG_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpdeg_node_rmv(prev, prev_pos, next, next_pos);
        cmcnpdeg_node_init(node, node_pos);
        CMCNP_DEG_NODE_NUM(cmcnp) --;

        cmcnpdeg_node_add_head(cmcnp, node, node_pos);

        dbg_log(SEC_0189_CMCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cmcnpdeg_node_move_head: node %p, pos %u\n", node, node_pos);
        return;
    }

    if(CMCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CMCNPDEG_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPDEG_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        cmcnpdeg_node_add_head(cmcnp, node, node_pos);
        return;
    }

    return;
}

void cmcnpdeg_node_move_tail(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CMCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CMCNPDEG_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPDEG_NODE_PREV_POS(node) /*ensure node in list*/
    && CMCNPDEG_NODE_NEXT_POS(node) != CMCNPDEG_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CMCNPDEG_NODE *prev;
        CMCNPDEG_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPDEG_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPDEG_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpdeg_node_rmv(prev, prev_pos, next, next_pos);
        cmcnpdeg_node_init(node, node_pos);
        CMCNP_DEG_NODE_NUM(cmcnp) --;

        cmcnpdeg_node_add_tail(cmcnp, node, node_pos);

        dbg_log(SEC_0189_CMCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cmcnpdeg_node_move_tail: node %p, pos %u\n", node, node_pos);
        return;
    }

    if(CMCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CMCNPDEG_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CMCNPDEG_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        cmcnpdeg_node_add_tail(cmcnp, node, node_pos);
        return;
    }

    return;
}

void cmcnpdeg_node_rmv(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos)
{
    if(CMCNPDEG_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CMCNPDEG_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CMCNPDEG_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CMCNPDEG_NODE *prev;
        CMCNPDEG_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CMCNPDEG_NODE_PREV_POS(node);
        prev     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, prev_pos));

        next_pos = CMCNPDEG_NODE_NEXT_POS(node);
        next     = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, next_pos));

        __cmcnpdeg_node_rmv(prev, prev_pos, next, next_pos);
        cmcnpdeg_node_init(node, node_pos);
        CMCNP_DEG_NODE_NUM(cmcnp) --;

        dbg_log(SEC_0189_CMCNPDEG, 9)(LOGSTDOUT, "[DEBUG] cmcnpdeg_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cmcnpdeg_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CMCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0189_CMCNPDEG, 0)(LOGSTDOUT, "error:cmcnpdeg_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CMCNPRB_NODE  *cmcnprb_node;
        CMCNP_ITEM    *cmcnp_item;

        cmcnprb_node  = CMCNPRB_POOL_NODE(pool, node_pos);
        cmcnp_item    = (CMCNP_ITEM *)cmcnprb_node;

        CMCNPDEG_ASSERT((void *)cmcnp_item == (void *)cmcnprb_node); /*address must be aligned*/

        cmcnpdeg_node_init(CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0189_CMCNPDEG, 9)(LOGSTDOUT, "info:cmcnpdeg_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0189_CMCNPDEG, 0)(LOGSTDOUT, "info:cmcnpdeg_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cmcnpdeg_list_print(LOG *log, const CMCNP *cmcnp)
{
    const CMCNPDEG_NODE *node;
    uint32_t node_pos;

    node_pos = CMCNPDEG_ROOT_POS;

    do
    {
        node = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, node_pos));
        cmcnpdeg_node_print(log, node, node_pos);

        node_pos = CMCNPDEG_NODE_NEXT_POS(node);

    }while(CMCNPDEG_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
