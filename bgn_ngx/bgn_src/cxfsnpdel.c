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

#include "cxfsnpdel.h"
#include "cxfsnp.h"

#define CXFSNPDEL_ASSERT(condition)           ASSERT(condition)
//#define CXFSNPDEL_ASSERT(condition)           do{}while(0)

void cxfsnpdel_node_init(CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    CXFSNPDEL_NODE_PREV_POS(node)   = node_pos;
    CXFSNPDEL_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void cxfsnpdel_node_clean(CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    CXFSNPDEL_NODE_PREV_POS(node) = node_pos;
    CXFSNPDEL_NODE_NEXT_POS(node) = node_pos;
    return;
}

EC_BOOL cxfsnpdel_node_clone(const CXFSNPDEL_NODE *node_src, CXFSNPDEL_NODE *node_des)
{
    CXFSNPDEL_NODE_PREV_POS(node_des) = CXFSNPDEL_NODE_PREV_POS(node_src);
    CXFSNPDEL_NODE_NEXT_POS(node_des) = CXFSNPDEL_NODE_NEXT_POS(node_src);
    return (EC_TRUE);
}

void cxfsnpdel_node_print(LOG *log, const CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "cxfsnpdel_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CXFSNPDEL_NODE_PREV_POS(node),
                 CXFSNPDEL_NODE_NEXT_POS(node));

    return;
}

EC_BOOL cxfsnpdel_node_is_empty(const CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CXFSNPDEL_NODE_NEXT_POS(node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnpdel_is_empty(const CXFSNPDEL_NODE *head)
{
    if(CXFSNPDEL_ROOT_POS == CXFSNPDEL_NODE_NEXT_POS(head))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*--------------------------------------------- DEL list operations ---------------------------------------------*/
STATIC_CAST void __cxfsnpdel_node_add(
                                CXFSNPDEL_NODE *new_node , const uint32_t new_pos,
                                CXFSNPDEL_NODE *prev_node, const uint32_t prev_pos,
                                CXFSNPDEL_NODE *next_node, const uint32_t next_pos)
{
    CXFSNPDEL_NODE_PREV_POS(next_node) = new_pos;
    CXFSNPDEL_NODE_NEXT_POS(new_node)  = next_pos;
    CXFSNPDEL_NODE_PREV_POS(new_node)  = prev_pos;
    CXFSNPDEL_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void cxfsnpdel_node_add_head(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPDEL_ROOT_POS != CXFSNPDEL_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos == CXFSNPDEL_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CXFSNPDEL_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CXFSNPDEL_NODE *head;
        CXFSNPDEL_NODE *next;

        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CXFSNPDEL_ROOT_POS;
        head     = CXFSNP_DEL_LIST(cxfsnp);

        next_pos = CXFSNPDEL_NODE_NEXT_POS(head);
        next     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnpdel_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0196_CXFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] cxfsnpdel_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cxfsnpdel_node_add_tail(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPDEL_ROOT_POS != CXFSNPDEL_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos == CXFSNPDEL_NODE_NEXT_POS(node) /*ensure node not in list*/
    && node_pos == CXFSNPDEL_NODE_PREV_POS(node) /*ensure node not in list*/
    )
    {
        CXFSNPDEL_NODE *head;
        CXFSNPDEL_NODE *prev;

        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CXFSNPDEL_ROOT_POS;
        head     = CXFSNP_DEL_LIST(cxfsnp);

        prev_pos = CXFSNPDEL_NODE_PREV_POS(head);
        prev     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        __cxfsnpdel_node_add(node, node_pos, prev, prev_pos, head, head_pos);

        dbg_log(SEC_0196_CXFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] cxfsnpdel_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST void __cxfsnpdel_node_rmv(
                        CXFSNPDEL_NODE *prev_node, const uint32_t prev_pos,
                        CXFSNPDEL_NODE *next_node, const uint32_t next_pos)
{
    CXFSNPDEL_NODE_PREV_POS(next_node) = prev_pos;
    CXFSNPDEL_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void cxfsnpdel_node_move_head(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPDEL_ROOT_POS != CXFSNPDEL_NODE_PREV_POS(node) /*ensure prev node is not root node*/
    && node_pos != CXFSNPDEL_NODE_NEXT_POS(node)  /*ensure node in list*/
    && node_pos != CXFSNPDEL_NODE_PREV_POS(node)  /*ensure node in list*/
    && CXFSNPDEL_NODE_NEXT_POS(node) != CXFSNPDEL_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CXFSNPDEL_NODE *prev;
        CXFSNPDEL_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CXFSNPDEL_NODE_PREV_POS(node);
        prev     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        next_pos = CXFSNPDEL_NODE_NEXT_POS(node);
        next     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnpdel_node_rmv(prev, prev_pos, next, next_pos);
        cxfsnpdel_node_init(node, node_pos);

        cxfsnpdel_node_add_head(cxfsnp, node, node_pos);

        dbg_log(SEC_0196_CXFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] cxfsnpdel_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cxfsnpdel_node_move_tail(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && CXFSNPDEL_ROOT_POS != CXFSNPDEL_NODE_NEXT_POS(node) /*ensure next node is not root node*/
    && node_pos != CXFSNPDEL_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CXFSNPDEL_NODE_PREV_POS(node) /*ensure node in list*/
    && CXFSNPDEL_NODE_NEXT_POS(node) != CXFSNPDEL_NODE_PREV_POS(node) /*ensure validity*/
    )
    {
        CXFSNPDEL_NODE *prev;
        CXFSNPDEL_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CXFSNPDEL_NODE_PREV_POS(node);
        prev     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        next_pos = CXFSNPDEL_NODE_NEXT_POS(node);
        next     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnpdel_node_rmv(prev, prev_pos, next, next_pos);
        cxfsnpdel_node_init(node, node_pos);

        cxfsnpdel_node_add_tail(cxfsnp, node, node_pos);

        dbg_log(SEC_0196_CXFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] cxfsnpdel_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void cxfsnpdel_node_rmv(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CXFSNPDEL_ROOT_POS != node_pos /*ensure not root node*/
    && node_pos != CXFSNPDEL_NODE_NEXT_POS(node) /*ensure node in list*/
    && node_pos != CXFSNPDEL_NODE_PREV_POS(node) /*ensure node in list*/
    )
    {
        CXFSNPDEL_NODE *prev;
        CXFSNPDEL_NODE *next;

        uint32_t        prev_pos;
        uint32_t        next_pos;

        prev_pos = CXFSNPDEL_NODE_PREV_POS(node);
        prev     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, prev_pos));

        next_pos = CXFSNPDEL_NODE_NEXT_POS(node);
        next     = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, next_pos));

        __cxfsnpdel_node_rmv(prev, prev_pos, next, next_pos);
        cxfsnpdel_node_init(node, node_pos);

        dbg_log(SEC_0196_CXFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] cxfsnpdel_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL cxfsnpdel_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CXFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0196_CXFSNPDEL, 0)(LOGSTDERR, "error:cxfsnpdel_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CXFSNPRB_NODE  *cxfsnprb_node;
        CXFSNP_ITEM    *cxfsnp_item;

        cxfsnprb_node  = CXFSNPRB_POOL_NODE(pool, node_pos);
        cxfsnp_item    = (CXFSNP_ITEM *)cxfsnprb_node;

        CXFSNPDEL_ASSERT((void *)cxfsnp_item == (void *)cxfsnprb_node); /*address must be aligned*/

        cxfsnpdel_node_init(CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0196_CXFSNPDEL, 0)(LOGSTDOUT, "info:cxfsnpdel_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0196_CXFSNPDEL, 0)(LOGSTDOUT, "info:cxfsnpdel_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void cxfsnpdel_list_print(LOG *log, const CXFSNP *cxfsnp)
{
    const CXFSNPDEL_NODE *node;
    uint32_t node_pos;

    node_pos = CXFSNPDEL_ROOT_POS;

    do
    {
        node = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, node_pos));
        cxfsnpdel_node_print(log, node, node_pos);

        node_pos = CXFSNPDEL_NODE_NEXT_POS(node);

    }while(CXFSNPDEL_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
