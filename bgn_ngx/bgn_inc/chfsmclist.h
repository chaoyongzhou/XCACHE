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

/*chfs memcache list*/

#ifndef    _CHFSMCLIST_H
#define    _CHFSMCLIST_H

#include "type.h"

#define CHFSMCLIST_NODE_NOT_USED  ((uint32_t)0)
#define CHFSMCLIST_NODE_USED      ((uint32_t)1)

#define CHFSMCLIST_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CHFSMCLIST_MAX_SIZE        ((uint32_t)(1 << 23))/* < 2^23, about 8,000,000*/

typedef struct
{        
    uint32_t left_pos :31;/*value range: [0, 0x7FFFFFFF)*/
    uint32_t used_flag: 1;

    uint32_t right_pos:31;/*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd     : 1;
}CHFSMCLIST_NODE; /*8B*/

#define CHFSMCLIST_NODE_RIGHT_POS(node)        ((node)->right_pos)
#define CHFSMCLIST_NODE_LEFT_POS(node)         ((node)->left_pos)
#define CHFSMCLIST_NODE_USED_FLAG(node)        ((node)->used_flag)

#define CHFSMCLIST_NODE_IS_USED(node)          (CHFSMCLIST_NODE_USED == CHFSMCLIST_NODE_USED_FLAG(node))
#define CHFSMCLIST_NODE_IS_NOT_USED(node)      (CHFSMCLIST_NODE_NOT_USED == CHFSMCLIST_NODE_USED_FLAG(node))

typedef struct
{    
    uint32_t              node_max_num; /*max node number in the pool    */
    uint32_t              node_used_num;/*used node number               */
    uint32_t              list_head;    /*unused CHFSMCLIST node head: head -> ... -> null*/
    uint32_t              list_tail;    /*unused CHFSMCLIST node tail: null <- ... <- tail*/
    CHFSMCLIST_NODE       list_nodes[0];/*double links table             */
}CHFSMCLIST;

#define CHFSMCLIST_HEAD(chfsmclist)              ((chfsmclist)->list_head)
#define CHFSMCLIST_TAIL(chfsmclist)              ((chfsmclist)->list_tail)
#define CHFSMCLIST_NODE_MAX_NUM(chfsmclist)      ((chfsmclist)->node_max_num)
#define CHFSMCLIST_NODE_USED_NUM(chfsmclist)     ((chfsmclist)->node_used_num)
#define CHFSMCLIST_NODE_TBL(chfsmclist)          ((chfsmclist)->list_nodes)
#if 1
#define CHFSMCLIST_FETCH_NODE(chfsmclist, this_pos)    \
    (CHFSMCLIST_NODE_MAX_NUM(chfsmclist) > (this_pos) ? ((CHFSMCLIST_NODE *)&(chfsmclist->list_nodes[ (this_pos) ])) : NULL_PTR)
#endif

void chfsmclist_node_del(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

void chfsmclist_node_add_head(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

void chfsmclist_node_add_tail(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

EC_BOOL chfsmclist_node_new(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

EC_BOOL chfsmclist_node_free(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

void chfsmclist_node_init(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

void chfsmclist_node_clean(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

EC_BOOL chfsmclist_node_is_used(const CHFSMCLIST *chfsmclist, const uint32_t node_pos);

void chfsmclist_node_print(LOG *log, const CHFSMCLIST *chfsmclist, const uint32_t node_pos);

EC_BOOL chfsmclist_node_lru_update(CHFSMCLIST *chfsmclist, const uint32_t node_pos);

EC_BOOL chfsmclist_is_empty(const CHFSMCLIST *chfsmclist);

EC_BOOL chfsmclist_is_full(const CHFSMCLIST *chfsmclist);

uint32_t chfsmclist_max_num(const CHFSMCLIST *chfsmclist);

uint32_t chfsmclist_used_num(const CHFSMCLIST *chfsmclist);

uint32_t chfsmclist_head(const CHFSMCLIST *chfsmclist);

uint32_t chfsmclist_tail(const CHFSMCLIST *chfsmclist);

uint32_t chfsmclist_pop_head(CHFSMCLIST *chfsmclist);

uint32_t chfsmclist_pop_tail(CHFSMCLIST *chfsmclist);

CHFSMCLIST *chfsmclist_new(const uint32_t max_num);

EC_BOOL chfsmclist_init(CHFSMCLIST *chfsmclist, const uint32_t max_num);

EC_BOOL chfsmclist_free(CHFSMCLIST *chfsmclist);

EC_BOOL chfsmclist_clean(CHFSMCLIST *chfsmclist);

void chfsmclist_print(LOG *log, const CHFSMCLIST *chfsmclist);

void chfsmclist_print_tail(LOG *log, const CHFSMCLIST *chfsmclist);


#endif    /* _CHFSMCLIST_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

