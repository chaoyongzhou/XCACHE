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

#include "cdcnpdel.h"
#include "cdcnp.h"

#define CDCNPDEL_ASSERT(condition)           ASSERT(condition)
//#define CDCNPDEL_ASSERT(condition)           do{}while(0)

void cdcnpdel_node_init(CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    CDCNPDEL_NODE_PREV_POS(node)   = node_pos;
    CDCNPDEL_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cdcnpdel_node_clean(CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    CDCNPDEL_NODE_PREV_POS(node) = node_pos;
    CDCNPDEL_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cdcnpdel_node_clone(const CDCNPDEL_NODE *node_src, CDCNPDEL_NODE *node_des)
{
    CDCNPDEL_NODE_PREV_POS(node_des) = CDCNPDEL_NODE_PREV_POS(node_src);
    CDCNPDEL_NODE_NEXT_POS(node_des) = CDCNPDEL_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cdcnpdel_node_print(LOG *log, const CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cdcnpdel_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CDCNPDEL_NODE_PREV_POS(node),
                 CDCNPDEL_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cdcnpdel_node_is_empty(const CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CDCNPDEL_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdcnpdel_is_empty(const CDCNPDEL_NODE *head)
{
    if(CDCNPDEL_ROOT_POS == CDCNPDEL_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- DEL list operations ---------------------------------------------*/
STATIC_CAST void __cdcnpdel_node_add(
                                CDCNPDEL_NODE *new_node , const uint32_t new_pos,
                                CDCNPDEL_NODE *prev_node, const uint32_t prev_pos,
                                CDCNPDEL_NODE *next_node, const uint32_t next_pos)
{
    CDCNPDEL_NODE_PREV_POS(next_node) = new_pos;
    CDCNPDEL_NODE_NEXT_POS(new_node)  = next_pos;
    CDCNPDEL_NODE_PREV_POS(new_node)  = prev_pos;
    CDCNPDEL_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cdcnpdel_node_add_head(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEL_ROOT_POS != CDCNPDEL_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CDCNPDEL_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CDCNPDEL_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CDCNPDEL_NODE *head;
        CDCNPDEL_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CDCNPDEL_ROOT_POS;
        head     = CDCNP_DEL_LIST(cdcnp);

        next_pos = CDCNPDEL_NODE_NEXT_POS(head);
        next     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdel_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0135_CDCNPDEL, 9)(LOGSTDOUT, "[DEBUG] cdcnpdel_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpdel_node_add_tail(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEL_ROOT_POS != CDCNPDEL_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CDCNPDEL_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CDCNPDEL_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CDCNPDEL_NODE *head;
        CDCNPDEL_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CDCNPDEL_ROOT_POS;
        head     = CDCNP_DEL_LIST(cdcnp);

        prev_pos = CDCNPDEL_NODE_PREV_POS(head);
        prev     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, prev_pos));

        __cdcnpdel_node_add(node, node_pos, prev, prev_pos, head, head_pos);

        dbg_log(SEC_0135_CDCNPDEL, 9)(LOGSTDOUT, "[DEBUG] cdcnpdel_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cdcnpdel_node_rmv(
                        CDCNPDEL_NODE *prev_node, const uint32_t prev_pos,
                        CDCNPDEL_NODE *next_node, const uint32_t next_pos)
{
    CDCNPDEL_NODE_PREV_POS(next_node) = prev_pos;
    CDCNPDEL_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cdcnpdel_node_move_head(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEL_ROOT_POS != CDCNPDEL_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CDCNPDEL_NODE_NEXT_POS(node)  /*ensure node in list*/
    && node_pos != CDCNPDEL_NODE_PREV_POS(node)  /*ensure node in list*/
    && CDCNPDEL_NODE_NEXT_POS(node) != CDCNPDEL_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CDCNPDEL_NODE *prev;
        CDCNPDEL_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPDEL_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPDEL_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdel_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpdel_node_init(node, node_pos);

        cdcnpdel_node_add_head(cdcnp, node, node_pos);

        dbg_log(SEC_0135_CDCNPDEL, 9)(LOGSTDOUT, "[DEBUG] cdcnpdel_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpdel_node_move_tail(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CDCNPDEL_ROOT_POS != CDCNPDEL_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CDCNPDEL_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPDEL_NODE_PREV_POS(node) /*ensure node in list*/
    && CDCNPDEL_NODE_NEXT_POS(node) != CDCNPDEL_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CDCNPDEL_NODE *prev;
        CDCNPDEL_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPDEL_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPDEL_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdel_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpdel_node_init(node, node_pos);

        cdcnpdel_node_add_tail(cdcnp, node, node_pos);

        dbg_log(SEC_0135_CDCNPDEL, 9)(LOGSTDOUT, "[DEBUG] cdcnpdel_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cdcnpdel_node_rmv(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CDCNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CDCNPDEL_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CDCNPDEL_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CDCNPDEL_NODE *prev;
        CDCNPDEL_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CDCNPDEL_NODE_PREV_POS(node);
        prev     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, prev_pos));

        next_pos = CDCNPDEL_NODE_NEXT_POS(node);
        next     = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, next_pos));

        __cdcnpdel_node_rmv(prev, prev_pos, next, next_pos);
        cdcnpdel_node_init(node, node_pos);

        dbg_log(SEC_0135_CDCNPDEL, 9)(LOGSTDOUT, "[DEBUG] cdcnpdel_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cdcnpdel_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CDCNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0135_CDCNPDEL, 0)(LOGSTDERR, "error:cdcnpdel_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CDCNPRB_NODE  *cdcnprb_node;
        CDCNP_ITEM    *cdcnp_item;

        cdcnprb_node  = CDCNPRB_POOL_NODE(pool, node_pos);
        cdcnp_item    = (CDCNP_ITEM *)cdcnprb_node;

        CDCNPDEL_ASSERT((void *)cdcnp_item == (void *)cdcnprb_node); /*address must be aligned*/

        cdcnpdel_node_init(CDCNP_ITEM_DEL_NODE(cdcnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0135_CDCNPDEL, 0)(LOGSTDOUT, "info:cdcnpdel_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0135_CDCNPDEL, 0)(LOGSTDOUT, "info:cdcnpdel_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cdcnpdel_list_print(LOG *log, const CDCNP *cdcnp)
{
    const CDCNPDEL_NODE *node;
    uint32_t node_pos;

    node_pos = CDCNPDEL_ROOT_POS;

    do
    {
        node = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, node_pos));
        cdcnpdel_node_print(log, node, node_pos);

        node_pos = CDCNPDEL_NODE_NEXT_POS(node);

    }while(CDCNPDEL_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
