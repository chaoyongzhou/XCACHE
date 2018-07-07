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

#include "crfsnpdel.h"
#include "crfsnp.h"

#define CRFSNPDEL_ASSERT(condition)           ASSERT(condition)
//#define CRFSNPDEL_ASSERT(condition)           do{}while(0)

void crfsnpdel_node_init(CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    CRFSNPDEL_NODE_PREV_POS(node)   = node_pos;
    CRFSNPDEL_NODE_NEXT_POS(node)   = node_pos;
    return;
}

void crfsnpdel_node_clean(CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    CRFSNPDEL_NODE_PREV_POS(node) = node_pos;
    CRFSNPDEL_NODE_NEXT_POS(node) = node_pos;
    return;
}

void crfsnpdel_node_print(LOG *log, const CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    sys_log(log, "crfsnpdel_node_print: [%u] %p: prev %u, next %u\n", node_pos, node,
                 CRFSNPDEL_NODE_PREV_POS(node),
                 CRFSNPDEL_NODE_NEXT_POS(node));

    return;
}

EC_BOOL crfsnpdel_node_is_empty(const CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(node_pos == CRFSNPDEL_NODE_NEXT_POS(node))
    {
        return ( EC_TRUE );
    }

    return ( EC_FALSE);
}

EC_BOOL crfsnpdel_is_empty(const CRFSNPDEL_NODE *head)
{
    if(CRFSNPDEL_ROOT_POS == CRFSNPDEL_NODE_NEXT_POS(head))
    {
        return ( EC_TRUE );
    }

    return ( EC_FALSE);
}

/*--------------------------------------------- DEL list operations ---------------------------------------------*/
STATIC_CAST inline void __crfsnpdel_node_add( 
                                CRFSNPDEL_NODE *new_node , const uint32_t new_pos, 
                                CRFSNPDEL_NODE *prev_node, const uint32_t prev_pos, 
                                CRFSNPDEL_NODE *next_node, const uint32_t next_pos)
{ 
    CRFSNPDEL_NODE_PREV_POS(next_node) = new_pos;
    CRFSNPDEL_NODE_NEXT_POS(new_node)  = next_pos;
    CRFSNPDEL_NODE_PREV_POS(new_node)  = prev_pos;
    CRFSNPDEL_NODE_NEXT_POS(prev_node) = new_pos;
    return;
}

void crfsnpdel_node_add_head(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPDEL_ROOT_POS != CRFSNPDEL_NODE_PREV_POS(node))
    {
        CRFSNPDEL_NODE *head;
        CRFSNPDEL_NODE *next;
        
        uint32_t        head_pos;
        uint32_t        next_pos;

        head_pos = CRFSNPDEL_ROOT_POS;
        head     = CRFSNP_DEL_LIST(crfsnp);

        next_pos = CRFSNPDEL_NODE_NEXT_POS(head);
        next     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, next_pos));
        
        __crfsnpdel_node_add(node, node_pos, head, head_pos, next, next_pos);

        dbg_log(SEC_0076_CRFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] crfsnpdel_node_add_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void crfsnpdel_node_add_tail(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPDEL_ROOT_POS != CRFSNPDEL_NODE_NEXT_POS(node))
    {
        CRFSNPDEL_NODE *head;
        CRFSNPDEL_NODE *prev;
        
        uint32_t        head_pos;
        uint32_t        prev_pos;

        head_pos = CRFSNPDEL_ROOT_POS;
        head     = CRFSNP_DEL_LIST(crfsnp);

        prev_pos = CRFSNPDEL_NODE_PREV_POS(head);
        prev     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, prev_pos));
        
        __crfsnpdel_node_add(node, node_pos, prev, prev_pos, head, head_pos);
        
        dbg_log(SEC_0076_CRFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] crfsnpdel_node_add_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

STATIC_CAST inline void __crfsnpdel_node_rmv(
                        CRFSNPDEL_NODE *prev_node, const uint32_t prev_pos, 
                        CRFSNPDEL_NODE *next_node, const uint32_t next_pos)
{   
    CRFSNPDEL_NODE_PREV_POS(next_node) = prev_pos;
    CRFSNPDEL_NODE_NEXT_POS(prev_node) = next_pos;
    return;
}

void crfsnpdel_node_move_head(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPDEL_ROOT_POS != CRFSNPDEL_NODE_PREV_POS(node))
    {
        CRFSNPDEL_NODE *prev;
        CRFSNPDEL_NODE *next;
        
        uint32_t        prev_pos;
        uint32_t        next_pos;
        
        prev_pos = CRFSNPDEL_NODE_PREV_POS(node);
        prev     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, prev_pos));

        next_pos = CRFSNPDEL_NODE_NEXT_POS(node);
        next     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, next_pos));
        
        __crfsnpdel_node_rmv(prev, prev_pos, next, next_pos);
        crfsnpdel_node_add_head(crfsnp, node, node_pos);
        
        dbg_log(SEC_0076_CRFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] crfsnpdel_node_move_head: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void crfsnpdel_node_move_tail(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(CRFSNPDEL_ROOT_POS != CRFSNPDEL_NODE_NEXT_POS(node))
    {
        CRFSNPDEL_NODE *prev;
        CRFSNPDEL_NODE *next;
        
        uint32_t        prev_pos;
        uint32_t        next_pos;
        
        prev_pos = CRFSNPDEL_NODE_PREV_POS(node);
        prev     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, prev_pos));

        next_pos = CRFSNPDEL_NODE_NEXT_POS(node);
        next     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, next_pos));
        
        __crfsnpdel_node_rmv(prev, prev_pos, next, next_pos);
        crfsnpdel_node_add_tail(crfsnp, node, node_pos);
        
        dbg_log(SEC_0076_CRFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] crfsnpdel_node_move_tail: node %p, pos %u\n", node, node_pos);
    }
    return;
}

void crfsnpdel_node_rmv(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos)
{
    if(node_pos != CRFSNPDEL_NODE_NEXT_POS(node))
    {
        CRFSNPDEL_NODE *prev;
        CRFSNPDEL_NODE *next;
        
        uint32_t        prev_pos;
        uint32_t        next_pos;
        
        prev_pos = CRFSNPDEL_NODE_PREV_POS(node);
        prev     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, prev_pos));

        next_pos = CRFSNPDEL_NODE_NEXT_POS(node);
        next     = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, next_pos));
        
        __crfsnpdel_node_rmv(prev, prev_pos, next, next_pos);
        crfsnpdel_node_init(node, node_pos);
        
        dbg_log(SEC_0076_CRFSNPDEL, 9)(LOGSTDOUT, "[DEBUG] crfsnpdel_node_rmv: node %p, pos %u\n", node, node_pos);
    }
    return;
}

EC_BOOL crfsnpdel_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof)
{
    uint32_t node_pos;

    if(CRFSNPRB_POOL_MAX_SIZE < node_max_num)
    {
        dbg_log(SEC_0076_CRFSNPDEL, 0)(LOGSTDERR, "error:crfsnpdel_pool_init: node_max_num %u overflow!\n", node_max_num);
        return (EC_FALSE);
    }

    for(node_pos = 0; node_pos < node_max_num; node_pos ++)
    {
        CRFSNPRB_NODE  *crfsnprb_node;
        CRFSNP_ITEM    *crfsnp_item;

        crfsnprb_node  = CRFSNPRB_POOL_NODE(pool, node_pos);
        crfsnp_item    = (CRFSNP_ITEM *)crfsnprb_node;
        
        CRFSNPDEL_ASSERT((void *)crfsnp_item == (void *)crfsnprb_node); /*address must be aligned*/

        crfsnpdel_node_init(CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);

        if(0 == ((node_pos + 1) % 100000))
        {
            dbg_log(SEC_0076_CRFSNPDEL, 0)(LOGSTDOUT, "info:crfsnpdel_pool_init: init node %u - %u of max %u done\n",
                               node_pos - 99999, node_pos, node_max_num);
        }
    }
    dbg_log(SEC_0076_CRFSNPDEL, 0)(LOGSTDOUT, "info:crfsnpdel_pool_init: init %u nodes done\n", node_max_num);

    return (EC_TRUE);
}

void crfsnpdel_list_print(LOG *log, const CRFSNP *crfsnp)
{
    const CRFSNPDEL_NODE *node;
    uint32_t node_pos;

    node_pos = CRFSNPDEL_ROOT_POS;

    do
    {
        node = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, node_pos));
        crfsnpdel_node_print(log, node, node_pos);

        node_pos = CRFSNPDEL_NODE_NEXT_POS(node);
        
    }while(CRFSNPDEL_ROOT_POS != node_pos);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
