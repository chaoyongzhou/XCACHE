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

#ifndef _CVECTOR_H
#define _CVECTOR_H

#include "type.h"
#include "cmutex.h"

#define CVECTOR_ERR_POS ((UINT32)(~((UINT32)0)))

#define CVECTOR_CODEC_ENCODER         ((UINT32) 1)
#define CVECTOR_CODEC_ENCODER_SIZE    ((UINT32) 2)
#define CVECTOR_CODEC_DECODER         ((UINT32) 3)
#define CVECTOR_CODEC_INIT            ((UINT32) 4)
#define CVECTOR_CODEC_CLEAN           ((UINT32) 5)
#define CVECTOR_CODEC_FREE            ((UINT32) 6)
#define CVECTOR_CODEC_ERROR           ((UINT32)-1)

#define CVECTOR_LOCK_ENABLE           ((UINT32) 1)
#define CVECTOR_LOCK_DISABLE          ((UINT32) 2)

#define CVECTOR_CHECKER_DEFAULT       ((CVECTOR_RETVAL_CHECKER)cvector_checker_default)

typedef struct
{
    UINT32 capacity;
    UINT32 size;

    UINT32 lock_enable_flag;

    void **data;

    UINT32 data_mm_type;

    UINT32 (*data_encoder)(const UINT32, const void *, UINT8 *, const UINT32, UINT32 *);
    UINT32 (*data_encoder_size)(const UINT32, const void *, UINT32 *);
    UINT32 (*data_decoder)(const UINT32, const UINT8 *, const UINT32, UINT32 *, void *);
    UINT32 (*data_init)(void *);
    UINT32 (*data_clean)(void *);
    UINT32 (*data_free)(void *);

    //int *__m_kind;
    CMUTEX    cmutex;
}CVECTOR;

typedef void *(*CVECTOR_DATA_MALLOC)();
typedef void (*CVECTOR_DATA_CLONE)(const void *, void *);
typedef EC_BOOL (*CVECTOR_DATA_CMP)(const void *, const void *);
typedef EC_BOOL (*CVECTOR_DATA_PREV_FILTER)(const void *, const void *);
typedef EC_BOOL (*CVECTOR_DATA_POST_FILTER)(const void *, const void *);
typedef EC_BOOL (*CVECTOR_DATA_VOTER)(const void *, const void *);
typedef EC_BOOL (*CVECTOR_DATA_LOOP_HANDLER)(const void *, const void *);
typedef EC_BOOL (*CVECTOR_DATA_CLEANER)(void *);
typedef EC_BOOL (*CVECTOR_DATA_HANDLER)(void *);
typedef void (*CVECTOR_DATA_PRINT)(LOG *, const void *);
typedef void (*CVECTOR_DATA_LEVEL_PRINT)(LOG *, const void *, const UINT32);

typedef int (*CVECTOR_DATA_ICMP)(const void *, const void *);

typedef UINT32 (*CVECTOR_DATA_ENCODER)(const UINT32, const void *, UINT8 *, const UINT32, UINT32 *);
typedef UINT32 (*CVECTOR_DATA_ENCODER_SIZE)(const UINT32, const void *, UINT32 *);
typedef UINT32 (*CVECTOR_DATA_DECODER)(const UINT32, const UINT8 *, const UINT32, UINT32 *, void *);
typedef UINT32 (*CVECTOR_DATA_INIT)(void *);
typedef UINT32 (*CVECTOR_DATA_CLEAN)(void *);
typedef UINT32 (*CVECTOR_DATA_FREE)(void *);

typedef EC_BOOL (*CVECTOR_RETVAL_CHECKER)(const void *);

/*------------------ lock interface ----------------*/
#define CVECTOR_CMUTEX(cvector)                           ((CMUTEX *)&((cvector)->cmutex))
#define CVECTOR_INIT_LOCK(cvector, __location__)          cmutex_init(CVECTOR_CMUTEX(cvector), CMUTEX_PROCESS_PRIVATE, (__location__))
#define CVECTOR_CLEAN_LOCK(cvector, __location__)         cmutex_clean(CVECTOR_CMUTEX(cvector), (__location__))

#define CVECTOR_LOCK(cvector, __location__)               cmutex_lock(CVECTOR_CMUTEX(cvector), (__location__))
#define CVECTOR_UNLOCK(cvector, __location__)             cmutex_unlock(CVECTOR_CMUTEX(cvector), (__location__))

EC_BOOL cvector_checker_default(const void * retval);

CVECTOR *cvector_new(const UINT32 capacity, const UINT32 mm_type, const UINT32 location);

void   cvector_free(CVECTOR *cvector, const UINT32 location);

void   cvector_init(CVECTOR *cvector, const UINT32 capacity, const UINT32 mm_type, const EC_BOOL lock_init_flag, const UINT32 location);

UINT32 cvector_init_0(CVECTOR *cvector);

UINT32 cvector_clean_0(CVECTOR *cvector);

UINT32 cvector_free_0(CVECTOR *cvector);

EC_BOOL cvector_is_empty(const CVECTOR *cvector);

EC_BOOL cvector_expand(CVECTOR *cvector);

EC_BOOL cvector_cmp(const CVECTOR *cvector_1st, const CVECTOR *cvector_2nd, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_add(CVECTOR *cvector, const void *data);

EC_BOOL cvector_asc_cmp_default(const void *data_1, const void *data_2);

EC_BOOL cvector_desc_cmp_default(const void *data_1, const void *data_2);

UINT32 cvector_push_in_order(CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_push_in_order_no_lock(CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_push(CVECTOR *cvector, const void *data);

void *cvector_pop(CVECTOR *cvector);

void **cvector_get_addr(const CVECTOR *cvector, const UINT32 pos);

void *cvector_get(const CVECTOR *cvector, const UINT32 pos);

void *cvector_set(CVECTOR *cvector, const UINT32 pos, const void *data);

UINT32 cvector_capacity(const CVECTOR *cvector);

UINT32 cvector_size(const CVECTOR *cvector);

UINT32 cvector_type(const CVECTOR *cvector);

UINT32 cvector_type_set(CVECTOR *cvector, const UINT32 data_mm_type);

void cvector_codec_set(CVECTOR *cvector, const UINT32 data_mm_type);

void *cvector_codec_get(const CVECTOR *cvector, const UINT32 choice);

void cvector_codec_clone(const CVECTOR *cvector_src, CVECTOR *cvector_des);

void cvector_loop_front(const CVECTOR *cvector, EC_BOOL (*handler)(void *));

void cvector_loop_back(const CVECTOR *cvector, EC_BOOL (*handler)(void *));

void cvector_loop_front_with_location(const CVECTOR *cvector, EC_BOOL (*handler)(void *, const UINT32), const UINT32 location);

void cvector_loop_back_with_location(const CVECTOR *cvector, EC_BOOL (*handler)(void *, const UINT32), const UINT32 location);

UINT32 cvector_search_front(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_search_back(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_bsearch(const CVECTOR *cvector, const void *data, int (*cmp)(const void *, const void *));

UINT32 cvector_bsearch_no_lock(const CVECTOR *cvector, const void *data, int (*cmp)(const void *, const void *));

EC_BOOL cvector_qsort(const CVECTOR *cvector, int (*cmp)(const void *, const void *));

EC_BOOL cvector_qsort_no_lock(const CVECTOR *cvector, int (*cmp)(const void *, const void *));

UINT32 cvector_insert_front(CVECTOR *cvector, const void *data);

UINT32 cvector_insert_back(CVECTOR *cvector, const void *data);

UINT32 cvector_insert_pos(CVECTOR *cvector, const UINT32 pos, const void *data);

UINT32 cvector_insert_pos_no_lock(CVECTOR *cvector, const UINT32 pos, const void *data);

EC_BOOL cvector_runthrough_front(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *));

EC_BOOL cvector_runthrough_back(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *));

EC_BOOL cvector_delete(CVECTOR *cvector, const void * data);

/**
*   make cvector order as c0 < c1 < c2 < ... < ck
* where "<" is a kind of order
*   voter is the justment of the order:
* when ci < cj, voter(ci, cj) return EC_TRUE; otherwise, return EC_FALSE
* then, cvector_vote will return the lowest one in the order sequence: c0
*
**/
void *cvector_vote(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *));

UINT32 cvector_vote_pos(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *));

void *cvector_vote_with_prev_filter(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *));
void *cvector_vote_with_post_filter(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *));

/*note: clone cvector_src to the tail of cvector_des*/
void cvector_clone(const CVECTOR *cvector_src, CVECTOR *cvector_des, void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));

void cvector_clone_with_prev_filter(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));
void cvector_clone_with_post_filter(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));

void *cvector_erase(CVECTOR *cvector, const UINT32 pos);

void cvector_clean(CVECTOR *cvector, EC_BOOL (*cleaner)(void *), const UINT32 location);

void cvector_merge_with_clone(const CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));

void cvector_merge_with_move(CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *));

void cvector_merge_direct(CVECTOR *cvector_src, CVECTOR *cvector_des);

UINT32 cvector_count(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void cvector_print(LOG *log, const CVECTOR *cvector, void (*handler)(LOG *, const void *));

void cvector_print_in_plain(LOG *log, const CVECTOR *cvector, void (*handler)(LOG *, const void *));

void cvector_print_level(LOG *log, const CVECTOR *cvector, const UINT32 level, void (*print)(LOG *, const void *, const UINT32));

EC_BOOL cvector_check_all_is_true(const CVECTOR *cvector);

EC_BOOL cvector_check_one_is_true(const CVECTOR *cvector);

EC_BOOL cvector_loop(CVECTOR *cvector,
                         void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                         const UINT32 func_para_num, const UINT32 cvector_data_pos,
                         const UINT32 handler_func_addr,...);

/*---------------------------------------------------------- no lock interface ----------------------------------------------------------*/
void cvector_free_no_lock(CVECTOR *cvector, const UINT32 location);

/*note: clone cvector_src to the tail of cvector_des*/
void cvector_clone_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));

void cvector_clone_with_prev_filter_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));

void cvector_clone_with_post_filter_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));

EC_BOOL cvector_expand_no_lock(CVECTOR *cvector);

EC_BOOL cvector_cmp_no_lock(const CVECTOR *cvector_1st, const CVECTOR *cvector_2nd, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_add_no_lock(CVECTOR *cvector, const void *data);

UINT32 cvector_push_no_lock(CVECTOR *cvector, const void *data);

void *cvector_pop_no_lock(CVECTOR *cvector);

void **cvector_get_addr_no_lock(const CVECTOR *cvector, const UINT32 pos);

void *cvector_get_no_lock(const CVECTOR *cvector, const UINT32 pos);

/*return old data*/
void *cvector_set_no_lock(CVECTOR *cvector, const UINT32 pos, const void *data);

void cvector_loop_front_no_lock(const CVECTOR *cvector, EC_BOOL (*handler)(void *));

void cvector_loop_back_no_lock(const CVECTOR *cvector, EC_BOOL (*handler)(void *));

UINT32 cvector_search_front_no_lock(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_search_back_no_lock(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cvector_insert_front_no_lock(CVECTOR *cvector, const void *data);

UINT32 cvector_insert_back_no_lock(CVECTOR *cvector, const void *data);

EC_BOOL cvector_runthrough_front_no_lock(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *));

EC_BOOL cvector_runthrough_back_no_lock(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *));

EC_BOOL cvector_delete_no_lock(CVECTOR *cvector, const void * data);

/**
*   make cvector order as c0 < c1 < c2 < ... < ck
* where "<" is a kind of order
*   voter is the justment of the order:
* when ci < cj, voter(ci, cj) return EC_TRUE; otherwise, return EC_FALSE
* then, cvector_vote_no_lock will return the lowest one in the order sequence: c0
*
**/
void *cvector_vote_no_lock(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *));

UINT32 cvector_vote_pos_no_lock(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *));

/**
*   make cvector order as c0 < c1 < c2 < ... < ck
* where "<" is a kind of order
*   voter is the justment of the order:
* when ci < cj, voter(ci, cj) return EC_TRUE; otherwise, return EC_FALSE
* then, cvector_vote_no_lock will return the lowest one in the order sequence: c0
*
* filter will skip the ones which not meet ci < condition
*
**/
void *cvector_vote_with_prev_filter_no_lock(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *));

void *cvector_vote_with_post_filter_no_lock(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *));

void *cvector_erase_no_lock(CVECTOR *cvector, const UINT32 pos);

void cvector_clean_no_lock(CVECTOR *cvector, EC_BOOL (*cleaner)(void *), const UINT32 location);

void cvector_merge_with_clone_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *));

void cvector_merge_with_move_no_lock(CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *));

UINT32 cvector_count_no_lock(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void cvector_merge_direct_no_lock(CVECTOR *cvector_src, CVECTOR *cvector_des);

void cvector_print_no_lock(LOG *log, const CVECTOR *cvector, void (*handler)(LOG *, const void *));

void cvector_print_level_no_lock(LOG *log, const CVECTOR *cvector, const UINT32 level, void (*print)(LOG *, const void *, const UINT32));

EC_BOOL cvector_check_all_is_true_no_lock(const CVECTOR *cvector);

EC_BOOL cvector_check_one_is_true_no_lock(const CVECTOR *cvector);

EC_BOOL cvector_loop_no_lock(CVECTOR *cvector,
                                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                                     const UINT32 func_para_num, const UINT32 cvector_data_pos,
                                     const UINT32 handler_func_addr,...);

#endif /*_CVECTOR_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
