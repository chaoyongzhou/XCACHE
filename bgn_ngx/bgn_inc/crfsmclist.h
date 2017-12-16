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

/*crfs memcache list*/

#ifndef    _CRFSMCLIST_H
#define    _CRFSMCLIST_H

#include "type.h"

#define CRFSMCLIST_NODE_NOT_USED  ((uint32_t)0)
#define CRFSMCLIST_NODE_USED      ((uint32_t)1)

#define CRFSMCLIST_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CRFSMCLIST_MAX_SIZE        ((uint32_t)(1 << 23))/* < 2^23, about 8,000,000*/

typedef struct
{        
    uint32_t left_pos :31;/*value range: [0, 0x7FFFFFFF)*/
    uint32_t used_flag: 1;

    uint32_t right_pos:31;/*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd     : 1;
}CRFSMCLIST_NODE; /*8B*/

#define CRFSMCLIST_NODE_RIGHT_POS(node)        ((node)->right_pos)
#define CRFSMCLIST_NODE_LEFT_POS(node)         ((node)->left_pos)
#define CRFSMCLIST_NODE_USED_FLAG(node)        ((node)->used_flag)

#define CRFSMCLIST_NODE_IS_USED(node)          (CRFSMCLIST_NODE_USED == CRFSMCLIST_NODE_USED_FLAG(node))
#define CRFSMCLIST_NODE_IS_NOT_USED(node)      (CRFSMCLIST_NODE_NOT_USED == CRFSMCLIST_NODE_USED_FLAG(node))

typedef struct
{    
    uint32_t              node_max_num; /*max node number in the pool    */
    uint32_t              node_used_num;/*used node number               */
    uint32_t              list_head;    /*unused CRFSMCLIST node head: head -> ... -> null*/
    uint32_t              list_tail;    /*unused CRFSMCLIST node tail: null <- ... <- tail*/
    CRFSMCLIST_NODE       list_nodes[0];/*double links table             */
}CRFSMCLIST;

#define CRFSMCLIST_HEAD(crfsmclist)              ((crfsmclist)->list_head)
#define CRFSMCLIST_TAIL(crfsmclist)              ((crfsmclist)->list_tail)
#define CRFSMCLIST_NODE_MAX_NUM(crfsmclist)      ((crfsmclist)->node_max_num)
#define CRFSMCLIST_NODE_USED_NUM(crfsmclist)     ((crfsmclist)->node_used_num)
#define CRFSMCLIST_NODE_TBL(crfsmclist)          ((crfsmclist)->list_nodes)
#if 1
#define CRFSMCLIST_FETCH_NODE(crfsmclist, this_pos)    \
    (CRFSMCLIST_NODE_MAX_NUM(crfsmclist) > (this_pos) ? ((CRFSMCLIST_NODE *)&(crfsmclist->list_nodes[ (this_pos) ])) : NULL_PTR)
#endif

void crfsmclist_node_del(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

void crfsmclist_node_add_head(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

void crfsmclist_node_add_tail(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

EC_BOOL crfsmclist_node_new(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

EC_BOOL crfsmclist_node_free(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

void crfsmclist_node_init(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

void crfsmclist_node_clean(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

EC_BOOL crfsmclist_node_is_used(const CRFSMCLIST *crfsmclist, const uint32_t node_pos);

void crfsmclist_node_print(LOG *log, const CRFSMCLIST *crfsmclist, const uint32_t node_pos);

EC_BOOL crfsmclist_node_lru_update(CRFSMCLIST *crfsmclist, const uint32_t node_pos);

EC_BOOL crfsmclist_is_empty(const CRFSMCLIST *crfsmclist);

EC_BOOL crfsmclist_is_full(const CRFSMCLIST *crfsmclist);

uint32_t crfsmclist_max_num(const CRFSMCLIST *crfsmclist);

uint32_t crfsmclist_used_num(const CRFSMCLIST *crfsmclist);

uint32_t crfsmclist_head(const CRFSMCLIST *crfsmclist);

uint32_t crfsmclist_tail(const CRFSMCLIST *crfsmclist);

uint32_t crfsmclist_pop_head(CRFSMCLIST *crfsmclist);

uint32_t crfsmclist_pop_tail(CRFSMCLIST *crfsmclist);

CRFSMCLIST *crfsmclist_new(const uint32_t max_num);

EC_BOOL crfsmclist_init(CRFSMCLIST *crfsmclist, const uint32_t max_num);

EC_BOOL crfsmclist_free(CRFSMCLIST *crfsmclist);

EC_BOOL crfsmclist_clean(CRFSMCLIST *crfsmclist);

void crfsmclist_print(LOG *log, const CRFSMCLIST *crfsmclist);

void crfsmclist_print_tail(LOG *log, const CRFSMCLIST *crfsmclist);


#endif    /* _CRFSMCLIST_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

