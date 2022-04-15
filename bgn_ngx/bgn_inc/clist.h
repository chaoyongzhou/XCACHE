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

#ifndef _CLIST_H
#define _CLIST_H

#include "list_base.h"
#include "cstring.h"
#include "cmutex.h"


#define CLIST_CODEC_ENCODER         ((UINT32) 1)
#define CLIST_CODEC_ENCODER_SIZE    ((UINT32) 2)
#define CLIST_CODEC_DECODER         ((UINT32) 3)
#define CLIST_CODEC_NEW             ((UINT32) 4)
#define CLIST_CODEC_INIT            ((UINT32) 5)
#define CLIST_CODEC_CLEAN           ((UINT32) 6)
#define CLIST_CODEC_FREE            ((UINT32) 7)
#define CLIST_CODEC_ERROR           ((UINT32)-1)

#define CLIST_CHECKER_DEFAULT       ((CLIST_RETVAL_CHECKER)clist_checker_default)

typedef struct
{
    LIST_NODE node;
    void *data;
}CLIST_DATA;


typedef struct
{
    LIST_NODE head;

    UINT32    size;

    CMUTEX    cmutex;

    UINT32    data_mm_type;

    UINT32  (*data_encoder)(const UINT32, const void *, UINT8 *, const UINT32, UINT32 *);
    UINT32  (*data_encoder_size)(const UINT32, const void *, UINT32 *);
    UINT32  (*data_decoder)(const UINT32, const UINT8 *, const UINT32, UINT32 *, void *);
    void *  (*data_new)();
    EC_BOOL (*data_init)(void *);
    EC_BOOL (*data_clean)(void *);
    EC_BOOL (*data_free)(void *);

}CLIST;

typedef void * (*CLIST_DATA_DATA_MALLOC)();
typedef void (*CLIST_DATA_DATA_CLONE)(const void *, void *);

typedef EC_BOOL (*CLIST_DATA_DATA_CMP)(const void *, const void *);
typedef void (*CLIST_DATA_DATA_HANDLER)(void *);
typedef EC_BOOL (*CLIST_DATA_DATA_CLEANER)(void *);
typedef void (*CLIST_DATA_DATA_PRINT)(LOG *, const void *);
typedef void (*CLIST_DATA_DATA_SPRINT)(CSTRING *, const void *);

typedef EC_BOOL (*CLIST_DATA_DATA_WALKER)(const void *, void *);

typedef EC_BOOL (*CLIST_DATA_MODI_CLEANER)(const UINT32, void *);

typedef UINT32  (*CLIST_DATA_ENCODER)(const UINT32, const void *, UINT8 *, const UINT32, UINT32 *);
typedef UINT32  (*CLIST_DATA_ENCODER_SIZE)(const UINT32, const void *, UINT32 *);
typedef UINT32  (*CLIST_DATA_DECODER)(const UINT32, const UINT8 *, const UINT32, UINT32 *, void *);
typedef void *  (*CLIST_DATA_NEW)();
typedef EC_BOOL (*CLIST_DATA_INIT)(void *);
typedef EC_BOOL (*CLIST_DATA_CLEAN)(void *);
typedef EC_BOOL (*CLIST_DATA_FREE)(void *);

typedef EC_BOOL (*CLIST_DATA_MODI_CMP)(const UINT32, const void *, const void *);
typedef void (*CLIST_DATA_LEVEL_PRINT)(LOG *, const void *, const UINT32);


typedef EC_BOOL (*CLIST_RETVAL_CHECKER)(const void *);

/*---------------------------- lock operation ----------------------------*/

#define CLIST_CMUTEX(clist)                           ((CMUTEX *)&((clist)->cmutex))
#define CLIST_INIT_LOCK(clist, __location__)          cmutex_init(CLIST_CMUTEX(clist), CMUTEX_PROCESS_PRIVATE, (__location__))
#define CLIST_CLEAN_LOCK(clist, __location__)         cmutex_clean(CLIST_CMUTEX(clist), (__location__))

#define CLIST_LOCK(clist, __location__)               cmutex_lock(CLIST_CMUTEX(clist), (__location__))
#define CLIST_UNLOCK(clist, __location__)             cmutex_unlock(CLIST_CMUTEX(clist), (__location__))


#define CLIST_HEAD(clist)  (&((clist)->head))

#define CLIST_FIRST_NODE(clist) list_base_entry((clist)->head.next, CLIST_DATA, node)

#define CLIST_LAST_NODE(clist)  list_base_entry((clist)->head.prev, CLIST_DATA, node)

/*the null item in the clist which is not any real item*/
#define CLIST_NULL_NODE(clist) list_base_entry(&((clist)->head), CLIST_DATA, node)

#define CLIST_IS_EMPTY(clist)  list_base_empty(CLIST_HEAD(clist))

#define CLIST_DATA_ADD_BACK(clist, data_node) list_base_add_tail(CLIST_DATA_NODE(data_node), CLIST_HEAD(clist))

#define CLIST_DATA_ADD_FRONT(clist, data_node) list_base_add(CLIST_DATA_NODE(data_node), CLIST_HEAD(clist))

#define CLIST_DATA_NODE(clist_data)    (&((clist_data)->node))

#define CLIST_HEAD_INIT(clist) INIT_LIST_BASE_HEAD(CLIST_HEAD(clist))

#define CLIST_DATA_DATA(clist_data)  ((clist_data)->data)

#define CLIST_DATA_NEXT(clist_data)  list_base_entry((clist_data)->node.next, CLIST_DATA, node)

#define CLIST_DATA_PREV(clist_data)  list_base_entry((clist_data)->node.prev, CLIST_DATA, node)

#define CLIST_DATA_DEL(clist_data)   list_base_del_init(CLIST_DATA_NODE(clist_data))

#define CLIST_LOOP_PREV(clist, data_node) \
    for((data_node) = CLIST_LAST_NODE(clist);  (data_node) != CLIST_NULL_NODE(clist); (data_node) = CLIST_DATA_PREV(data_node))

#define CLIST_LOOP_NEXT(clist, data_node) \
    for((data_node) = CLIST_FIRST_NODE(clist);  (data_node) != CLIST_NULL_NODE(clist); (data_node) = CLIST_DATA_NEXT(data_node))

#define CLIST_LOOP_PREV_FROM_CUR(clist, data_cur, data_node) \
    for((data_node) = (data_cur);  (data_node) != CLIST_NULL_NODE(clist); (data_node) = CLIST_DATA_PREV(data_node))

#define CLIST_LOOP_NEXT_FROM_CUR(clist, data_cur, data_node) \
    for((data_node) = (data_cur);  (data_node) != CLIST_NULL_NODE(clist); (data_node) = CLIST_DATA_NEXT(data_node))

/*----------------------------------------------------------------interface----------------------------------------------------------------*/

/*iterator*/
typedef struct
{
    const CLIST       *clist;
    const CLIST_DATA  *node; /*current node in clist*/
}CLIST_ITERATOR;

#define CLIST_ITERATOR_CLIST(iterator)        ((iterator)->clist)
#define CLIST_ITERATOR_NODE(iterator)         ((iterator)->node)

EC_BOOL clist_checker_default(const void * retval);

UINT32 clist_type(const CLIST *clist);

UINT32 clist_type_set(CLIST *clist, const UINT32 data_mm_type);

UINT32 clist_caller_set(CLIST *clist, const UINT32 choice, const UINT32 caller);

void   clist_codec_set(CLIST *clist, const UINT32 data_mm_type);

void * clist_codec_get(const CLIST *clist, const UINT32 choice);

void   clist_codec_clone(const CLIST *clist_src, CLIST *clist_des);

CLIST *clist_new(const UINT32 mm_type, const UINT32 location);

void clist_free(CLIST *clist, const UINT32 location);

void clist_init(CLIST *clist, const UINT32 mm_type, const UINT32 location);

UINT32 clist_init_0(CLIST *clist);

UINT32 clist_clean_0(CLIST *clist);

UINT32 clist_free_0(CLIST *clist);

void   clist_clone(const CLIST *clist_src, CLIST *clist_des, void *(*clist_data_data_malloc)(), void (*clist_data_data_clone)(const void *, void *));

EC_BOOL clist_is_empty(const CLIST *clist);

CLIST_DATA * clist_push_back(CLIST *clist, const void *data);

CLIST_DATA * clist_push_front(CLIST *clist, const void *data);

void *clist_pop_back(CLIST *clist);

void *clist_pop_front(CLIST *clist);

void *clist_back(const CLIST *clist);

void *clist_front(const CLIST *clist);

void *clist_data(const CLIST_DATA *clist_data);

CLIST_DATA *clist_first(const CLIST *clist);

CLIST_DATA *clist_last(const CLIST *clist);

CLIST_DATA *clist_next(const CLIST *clist, const CLIST_DATA *clist_data);

CLIST_DATA *clist_prev(const CLIST *clist, const CLIST_DATA *clist_data);

void *clist_first_data(const CLIST *clist);

void *clist_last_data(const CLIST *clist);

UINT32 clist_size(const CLIST *clist);

void clist_loop_front(const CLIST *clist, EC_BOOL (*handler)(void *));

void clist_loop_back(const CLIST *clist, EC_BOOL (*handler)(void *));

void clist_print(LOG *log, const CLIST *clist, void (*print)(LOG *, const void *));

void clist_print_level(LOG *log, const CLIST *clist, const UINT32 level, void (*print)(LOG *, const void *, const UINT32));

void clist_print_plain(LOG *log, const CLIST *clist, void (*print)(LOG *, const void *));

void clist_print_plain_level(LOG *log, const CLIST *clist, const UINT32 level, void (*print)(LOG *, const void *, const UINT32));

void clist_sprint(CSTRING *cstring, const CLIST *clist, void (*sprint)(CSTRING *, const void *));

void *clist_vote(const CLIST *clist, EC_BOOL (*voter)(void *, void *));

CLIST_DATA * clist_search_front(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

CLIST_DATA * clist_search_back(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void * clist_search_data_front(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void * clist_search_data_back(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

CLIST_DATA *clist_insert_front(CLIST *clist, CLIST_DATA *clist_data, const void *data);

CLIST_DATA *clist_insert_back(CLIST *clist, CLIST_DATA *clist_data, const void *data);

void *clist_rmv(CLIST *clist, CLIST_DATA *clist_data);
void *clist_del(CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));
void *clist_erase(CLIST *clist, CLIST_DATA *clist_data);

EC_BOOL clist_move_back(CLIST *clist, CLIST_DATA *clist_data);
EC_BOOL clist_move_front(CLIST *clist, CLIST_DATA *clist_data);

void clist_clean(CLIST *clist, EC_BOOL (*cleaner)(void *));

void clist_handover(CLIST *clist_src, CLIST *clist_des);

void clist_bubble_sort(CLIST *clist, EC_BOOL (*cmp)(const void *, const void *));

EC_BOOL clist_loop(CLIST *clist,
                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                     const UINT32 func_para_num, const UINT32 clist_data_pos,
                     const UINT32 handler_func_addr,...);

CLIST_DATA *clist_walk_and_insert(CLIST *clist, const void *data, EC_BOOL (*walker)(const void *, const void *));

EC_BOOL clist_walk(const CLIST *clist, void *data, EC_BOOL (*walker)(const void *, void *));
/*--------------------------------- no lock interface ---------------------------------*/
CLIST *clist_new_no_lock(const UINT32 mm_type, const UINT32 location);

void clist_free_no_lock(CLIST *clist, const UINT32 location);

void clist_init_no_lock(CLIST *clist, const UINT32 mm_type, const UINT32 location);

/*note: clone clist_src to the tail of clist_des*/
void clist_clone_no_lock(const CLIST *clist_src, CLIST *clist_des, void *(*clist_data_data_malloc)(), void (*clist_data_data_clone)(const void *, void *));

EC_BOOL clist_is_empty_no_lock(const CLIST *clist);

CLIST_DATA * clist_push_back_no_lock(CLIST *clist, const void *data);

CLIST_DATA * clist_push_front_no_lock(CLIST *clist, const void *data);

void *clist_pop_back_no_lock(CLIST *clist);

void *clist_pop_front_no_lock(CLIST *clist);

void *clist_back_no_lock(const CLIST *clist);

void *clist_front_no_lock(const CLIST *clist);

CLIST_DATA *clist_first_no_lock(const CLIST *clist);

CLIST_DATA *clist_last_no_lock(const CLIST *clist);

CLIST_DATA *clist_next_no_lock(const CLIST *clist, const CLIST_DATA *clist_data);

CLIST_DATA *clist_prev_no_lock(const CLIST *clist, const CLIST_DATA *clist_data);

void clist_loop_front_no_lock(const CLIST *clist, EC_BOOL (*handler)(void *));

void clist_loop_back_no_lock(const CLIST *clist, EC_BOOL (*handler)(void *));

void clist_print_no_lock(LOG *log, const CLIST *clist, void (*print)(LOG *, const void *));

void clist_print_level_no_lock(LOG *log, const CLIST *clist, const UINT32 level, void (*print)(LOG *, const void *, const UINT32));

void clist_sprint_no_lock(CSTRING *cstring, const CLIST *clist, void (*sprint)(CSTRING *, const void *));

/**
*   let clist is c0 < c1 < c2 < ... < ck
* where "<" is a kind of order
*   voter is the justment of the order:
* when ci < cj, voter(ci, cj) return EC_TRUE; otherwise, return EC_FALSE
* then, clist_vote will return the lowest one in the order sequence: c0
*
**/
void *clist_vote_no_lock(const CLIST *clist, EC_BOOL (*voter)(void *, void *));

CLIST_DATA * clist_search_front_no_lock(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

CLIST_DATA * clist_search_back_no_lock(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void * clist_search_data_front_no_lock(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void * clist_search_data_back_no_lock(const CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

CLIST_DATA *clist_insert_front_no_lock(CLIST *clist, CLIST_DATA *clist_data, const void *data);

CLIST_DATA *clist_insert_back_no_lock(CLIST *clist, CLIST_DATA *clist_data, const void *data);

void *clist_rmv_no_lock(CLIST *clist, CLIST_DATA *clist_data);

void *clist_del_no_lock(CLIST *clist, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void *clist_erase_no_lock(CLIST *clist, CLIST_DATA *clist_data);

void clist_clean_no_lock(CLIST *clist, EC_BOOL (*cleaner)(void *));

EC_BOOL clist_move_back_no_lock(CLIST *clist, CLIST_DATA *clist_data);

EC_BOOL clist_move_front_no_lock(CLIST *clist, CLIST_DATA *clist_data);

void clist_handover_no_lock(CLIST *clist_src, CLIST *clist_des);

void clist_bubble_sort_no_lock(CLIST *clist, EC_BOOL (*cmp)(const void *, const void *));

EC_BOOL clist_loop_no_lock(CLIST *clist,
                                 void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                                 const UINT32 func_para_num, const UINT32 clist_data_pos,
                                 const UINT32 handler_func_addr,...);

CLIST_DATA *clist_walk_and_insert_no_lock(CLIST *clist, const void *data, EC_BOOL (*walker)(const void *, const void *));

EC_BOOL clist_walk_no_lock(const CLIST *clist, void *data, EC_BOOL (*walker)(const void *, void *));

EC_BOOL clist_self_check_no_lock(CLIST *clist);


/*--------------------------------- iterator interface ---------------------------------*/
CLIST_ITERATOR *clist_iterator_front(CLIST_ITERATOR *it, const CLIST *clist);

CLIST_ITERATOR *clist_iterator_back(CLIST_ITERATOR *it, const CLIST *clist);

void           *clist_iterator_data(CLIST_ITERATOR *it);

CLIST_ITERATOR *clist_iterator_next(CLIST_ITERATOR *it);

CLIST_ITERATOR *clist_iterator_prev(CLIST_ITERATOR *it);

#endif /*_CLIST_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
