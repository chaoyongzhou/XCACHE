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

/*csfs memcache list*/

#ifndef    _CSFSMCLIST_H
#define    _CSFSMCLIST_H

#include "type.h"

#define CSFSMCLIST_NODE_NOT_USED  ((uint32_t)0)
#define CSFSMCLIST_NODE_USED      ((uint32_t)1)

#define CSFSMCLIST_ERR_POS        ((uint32_t)0x7FFFFFFF)/*31 bits*/

#define CSFSMCLIST_MAX_SIZE        ((uint32_t)(1 << 23))/* < 2^23, about 8,000,000*/

typedef struct
{        
    uint32_t left_pos :31;/*value range: [0, 0x7FFFFFFF)*/
    uint32_t used_flag: 1;

    uint32_t right_pos:31;/*value range: [0, 0x7FFFFFFF)*/
    uint32_t rsvd     : 1;
}CSFSMCLIST_NODE; /*8B*/

#define CSFSMCLIST_NODE_RIGHT_POS(node)        ((node)->right_pos)
#define CSFSMCLIST_NODE_LEFT_POS(node)         ((node)->left_pos)
#define CSFSMCLIST_NODE_USED_FLAG(node)        ((node)->used_flag)

#define CSFSMCLIST_NODE_IS_USED(node)          (CSFSMCLIST_NODE_USED == CSFSMCLIST_NODE_USED_FLAG(node))
#define CSFSMCLIST_NODE_IS_NOT_USED(node)      (CSFSMCLIST_NODE_NOT_USED == CSFSMCLIST_NODE_USED_FLAG(node))

typedef struct
{    
    uint32_t              node_max_num; /*max node number in the pool    */
    uint32_t              node_used_num;/*used node number               */
    uint32_t              list_head;    /*unused CSFSMCLIST node head: head -> ... -> null*/
    uint32_t              list_tail;    /*unused CSFSMCLIST node tail: null <- ... <- tail*/
    CSFSMCLIST_NODE       list_nodes[0];/*double links table             */
}CSFSMCLIST;

#define CSFSMCLIST_HEAD(csfsmclist)              ((csfsmclist)->list_head)
#define CSFSMCLIST_TAIL(csfsmclist)              ((csfsmclist)->list_tail)
#define CSFSMCLIST_NODE_MAX_NUM(csfsmclist)      ((csfsmclist)->node_max_num)
#define CSFSMCLIST_NODE_USED_NUM(csfsmclist)     ((csfsmclist)->node_used_num)
#define CSFSMCLIST_NODE_TBL(csfsmclist)          ((csfsmclist)->list_nodes)
#if 1
#define CSFSMCLIST_FETCH_NODE(csfsmclist, this_pos)    \
    (CSFSMCLIST_NODE_MAX_NUM(csfsmclist) > (this_pos) ? ((CSFSMCLIST_NODE *)&(csfsmclist->list_nodes[ (this_pos) ])) : NULL_PTR)
#endif

void csfsmclist_node_del(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

void csfsmclist_node_add_head(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

void csfsmclist_node_add_tail(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

EC_BOOL csfsmclist_node_new(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

EC_BOOL csfsmclist_node_free(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

void csfsmclist_node_init(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

void csfsmclist_node_clean(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

EC_BOOL csfsmclist_node_is_used(const CSFSMCLIST *csfsmclist, const uint32_t node_pos);

void csfsmclist_node_print(LOG *log, const CSFSMCLIST *csfsmclist, const uint32_t node_pos);

EC_BOOL csfsmclist_node_lru_update(CSFSMCLIST *csfsmclist, const uint32_t node_pos);

EC_BOOL csfsmclist_is_empty(const CSFSMCLIST *csfsmclist);

EC_BOOL csfsmclist_is_full(const CSFSMCLIST *csfsmclist);

uint32_t csfsmclist_max_num(const CSFSMCLIST *csfsmclist);

uint32_t csfsmclist_used_num(const CSFSMCLIST *csfsmclist);

uint32_t csfsmclist_head(const CSFSMCLIST *csfsmclist);

uint32_t csfsmclist_tail(const CSFSMCLIST *csfsmclist);

uint32_t csfsmclist_pop_head(CSFSMCLIST *csfsmclist);

uint32_t csfsmclist_pop_tail(CSFSMCLIST *csfsmclist);

CSFSMCLIST *csfsmclist_new(const uint32_t max_num);

EC_BOOL csfsmclist_init(CSFSMCLIST *csfsmclist, const uint32_t max_num);

EC_BOOL csfsmclist_free(CSFSMCLIST *csfsmclist);

EC_BOOL csfsmclist_clean(CSFSMCLIST *csfsmclist);

void csfsmclist_print(LOG *log, const CSFSMCLIST *csfsmclist);

void csfsmclist_print_tail(LOG *log, const CSFSMCLIST *csfsmclist);


#endif    /* _CSFSMCLIST_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

