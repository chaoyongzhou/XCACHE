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

#ifndef _CLISTBASE_H
#define _CLISTBASE_H

#include "list_base.h"

typedef struct
{
    LIST_NODE       node;
}CLISTBASE_NODE;

typedef struct
{
    LIST_NODE        head;
    UINT32           size;
}CLISTBASE;

typedef EC_BOOL (*CLISTBASE_NODE_DATA_CMP)(const void *, const void *);
typedef void (*CLISTBASE_NODE_DATA_HANDLER)(void *);
typedef EC_BOOL (*CLISTBASE_NODE_DATA_CLEANER)(void *);
typedef void (*CLISTBASE_NODE_DATA_PRINT)(LOG *, const void *);

typedef EC_BOOL (*CLISTBASE_NODE_DATA_WALKER)(const void *, void *);

typedef EC_BOOL (*CLISTBASE_NODE_DATA_INIT)(void *);

typedef void (*CLISTBASE_NODE_LEVEL_PRINT)(LOG *, const void *, const UINT32);


typedef EC_BOOL (*CLISTBASE_RETVAL_CHECKER)(const void *);

/*---------------------------- lock operation ----------------------------*/

#define CLISTBASE_NODE_INIT(clistbase_node) INIT_LIST_BASE_HEAD(&((clistbase_node)->node))

#define CLISTBASE_HEAD(clistbase)  (&((clistbase)->head))

#define CLISTBASE_FIRST_NODE(clistbase) list_base_entry((clistbase)->head.next, CLISTBASE_NODE, node)

#define CLISTBASE_LAST_NODE(clistbase)  list_base_entry((clistbase)->head.prev, CLISTBASE_NODE, node)

/*the null item in the clist which is not any real item*/
#define CLISTBASE_NULL_NODE(clistbase) list_base_entry(&((clistbase)->head), CLISTBASE_NODE, node)

#define CLISTBASE_IS_EMPTY(clistbase)  list_base_empty(CLISTBASE_HEAD(clistbase))

#define CLISTBASE_NODE_ADD_BACK(clistbase, data_node) list_base_add_tail(CLISTBASE_NODE_NODE(data_node), CLISTBASE_HEAD(clistbase))

#define CLISTBASE_NODE_ADD_FRONT(clistbase, data_node) list_base_add(CLISTBASE_NODE_NODE(data_node), CLISTBASE_HEAD(clistbase))

#define CLISTBASE_NODE_NODE(clistbase_node)    (&((clistbase_node)->node))

#define CLISTBASE_HEAD_INIT(clistbase) INIT_LIST_BASE_HEAD(CLISTBASE_HEAD(clistbase))

#define CLISTBASE_NODE_DATA(clistbase_node)  ((void *)(clistbase_node))

#define CLISTBASE_NODE_NEXT(clistbase_node)  list_base_entry((clistbase_node)->node.next, CLISTBASE_NODE, node)

#define CLISTBASE_NODE_PREV(clistbase_node)  list_base_entry((clistbase_node)->node.prev, CLISTBASE_NODE, node)

#define CLISTBASE_NODE_DEL(clistbase_node)   list_base_del_init(CLISTBASE_NODE_NODE(clistbase_node))

#define CLISTBASE_LOOP_PREV(clistbase, data_node) \
    for((data_node) = CLISTBASE_LAST_NODE(clistbase);  (data_node) != CLISTBASE_NULL_NODE(clistbase); (data_node) = CLISTBASE_NODE_PREV(data_node))

#define CLISTBASE_LOOP_NEXT(clistbase, data_node) \
    for((data_node) = CLISTBASE_FIRST_NODE(clistbase);  (data_node) != CLISTBASE_NULL_NODE(clistbase); (data_node) = CLISTBASE_NODE_NEXT(data_node))

#define CLISTBASE_LOOP_PREV_FROM_CUR(clistbase, data_cur, data_node) \
    for((data_node) = (data_cur);  (data_node) != CLISTBASE_NULL_NODE(clistbase); (data_node) = CLISTBASE_NODE_PREV(data_node))

#define CLISTBASE_LOOP_NEXT_FROM_CUR(clistbase, data_cur, data_node) \
    for((data_node) = (data_cur);  (data_node) != CLISTBASE_NULL_NODE(clistbase); (data_node) = CLISTBASE_NODE_NEXT(data_node))
    
/*----------------------------------------------------------------interface----------------------------------------------------------------*/
void clistbase_init(CLISTBASE *clistbase);

EC_BOOL clistbase_is_empty(const CLISTBASE *clistbase);

CLISTBASE_NODE * clistbase_push_back(CLISTBASE *clistbase, const void *data);

CLISTBASE_NODE * clistbase_push_front(CLISTBASE *clistbase, const void *data);

void *clistbase_pop_back(CLISTBASE *clistbase);

void *clistbase_pop_front(CLISTBASE *clistbase);

void *clistbase_back(const CLISTBASE *clistbase);

void *clistbase_front(const CLISTBASE *clistbase);

CLISTBASE_NODE *clistbase_first(const CLISTBASE *clistbase);

CLISTBASE_NODE *clistbase_last(const CLISTBASE *clistbase);

CLISTBASE_NODE *clistbase_next(const CLISTBASE *clistbase, const CLISTBASE_NODE *clistbase_node);

CLISTBASE_NODE *clistbase_prev(const CLISTBASE *clistbase, const CLISTBASE_NODE *clistbase_node);

void *clistbase_first_data(const CLISTBASE *clistbase);

void *clistbase_last_data(const CLISTBASE *clistbase);

UINT32 clistbase_size(const CLISTBASE *clistbase);

void clistbase_loop_front(const CLISTBASE *clistbase, EC_BOOL (*handler)(void *));

void clistbase_loop_back(const CLISTBASE *clistbase, EC_BOOL (*handler)(void *));

void clistbase_print(LOG *log, const CLISTBASE *clistbase, void (*print)(LOG *, const void *));

void clistbase_print_level(LOG *log, const CLISTBASE *clistbase, const UINT32 level, void (*print)(LOG *, const void *, const UINT32));

void clistbase_print_plain(LOG *log, const CLISTBASE *clistbase, void (*print)(LOG *, const void *));

void clistbase_print_plain_level(LOG *log, const CLISTBASE *clistbase, const UINT32 level, void (*print)(LOG *, const void *, const UINT32));

void clistbase_sprint(CSTRING *cstring, const CLISTBASE *clistbase, void (*sprint)(CSTRING *, const void *));

CLISTBASE_NODE * clistbase_search_front(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *));

CLISTBASE_NODE * clistbase_search_back(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void * clistbase_search_data_front(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void * clistbase_search_data_back(const CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void *clistbase_rmv(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node);

void *clistbase_del(CLISTBASE *clistbase, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void *clistbase_erase(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node);

/*move from current position to tail*/
EC_BOOL clistbase_move_back(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node);

/*move from current position to head*/
EC_BOOL clistbase_move_front(CLISTBASE *clistbase, CLISTBASE_NODE *clistbase_node);

void clistbase_clean(CLISTBASE *clistbase, EC_BOOL (*cleaner)(void *));

void clistbase_handover(CLISTBASE *clistbase_src, CLISTBASE *clistbase_des);

EC_BOOL clistbase_walk(const CLISTBASE *clistbase, void *data, EC_BOOL (*walker)(const void *, void *));

#endif /*_CLISTBASE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
