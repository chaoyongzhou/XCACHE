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

#ifndef _CQUEUE_H
#define _CQUEUE_H

#include "clist.h"

typedef CLIST_DATA CQUEUE_DATA;
typedef CLIST CQUEUE;

typedef CQUEUE_DATA * (*CQUEUE_DATA_MALLOC)();
typedef void (*CQUEUE_DATA_FREE)(CQUEUE_DATA *);

typedef void * (*CQUEUE_DATA_DATA_MALLOC)();
typedef void (*CQUEUE_DATA_DATA_CLONE)(const void *, void *);

typedef EC_BOOL (*CQUEUE_DATA_DATA_CMP)(const void *, const void *);
typedef void (*CQUEUE_DATA_DATA_HANDLER)(void *);
typedef EC_BOOL (*CQUEUE_DATA_DATA_CLEANER)(void *);
typedef void (*CQUEUE_DATA_DATA_PRINT)(LOG *, const void *);

typedef EC_BOOL (*CQUEUE_DATA_DATA_WALKER)(const void *, void *);

CQUEUE *cqueue_new(const UINT32 mm_type, const UINT32 location);

void cqueue_free(CQUEUE *cqueue, const UINT32 location);

void cqueue_init(CQUEUE *cqueue, const UINT32 mm_type, const UINT32 location);

EC_BOOL cqueue_is_empty(const CQUEUE *cqueue);

CQUEUE_DATA * cqueue_search(const CQUEUE *cqueue, const void *data, EC_BOOL (*cmp)(const void *, const void *));

CQUEUE_DATA * cqueue_push(CQUEUE *cqueue, void *data);

void * cqueue_pop(CQUEUE *cqueue);

void *cqueue_erase(CQUEUE *cqueue, CQUEUE_DATA *cqueue_data);

UINT32 cqueue_size(const CQUEUE *cqueue);

void *cqueue_front(const CQUEUE *cqueue);

void *cqueue_back(const CQUEUE *cqueue);

void cqueue_loop_front(const CQUEUE *cqueue, EC_BOOL (*handler)(void *));

void cqueue_loop_back(const CQUEUE *cqueue, EC_BOOL (*handler)(void *));

void cqueue_clean(CQUEUE *cqueue, EC_BOOL (*cleaner)(void *));

void cqueue_print(LOG *log, const CQUEUE *cqueue, void (*print)(LOG *, const void *));

EC_BOOL cqueue_walk(const CQUEUE *cqueue, void *data, EC_BOOL (*walker)(const void *, void *));

#endif /*_CQUEUE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
