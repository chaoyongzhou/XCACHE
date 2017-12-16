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

#ifndef _CINDEX_H
#define _CINDEX_H

#include "type.h"
#include "cmutex.h"

#define CINDEX_ERR_POS               ((UINT32)(~((UINT32)0)))
#define CINDEX_BEG_POS               ((UINT32) (0))

#define CINDEX_LOCK_ENABLE           ((UINT32) 1)
#define CINDEX_LOCK_DISABLE          ((UINT32) 2)

typedef struct
{
    UINT32 capacity;   /*index capacity at present*/
    UINT32 size;       /*how many index were used*/
    UINT32 next;       /*next possible index to be used*/

    UINT32 lock_enable_flag;

    void **data;

    UINT32 data_mm_type;

    UINT32 (*data_init)(const UINT32, void *);
    UINT32 (*data_clean)(const UINT32 , void *);
    UINT32 (*data_free)(const UINT32 , void *);

    CMUTEX    cmutex;
}CINDEX;

typedef  void *(*CINDEX_DATA_MALLOC)();
typedef  EC_BOOL (*CINDEX_DATA_CMP)(const void *, const void *);;

typedef void (*CINDEX_DATA_CLEANER)(void *);
typedef void (*CINDEX_DATA_HANDLER)(void *);
typedef  void (*CINDEX_DATA_PRINT)(LOG *, const void *);

typedef UINT32 (*CINDEX_DATA_INIT)(const UINT32, void *);
typedef UINT32 (*CINDEX_DATA_CLEAN)(const UINT32, void *);
typedef UINT32 (*CINDEX_DATA_FREE)(const UINT32, void *);

/*------------------ lock interface ----------------*/
#define CINDEX_CMUTEX(cindex)                           ((CMUTEX *)&((cindex)->cmutex))
#define CINDEX_INIT_LOCK(cindex, __location__)          cmutex_init(CINDEX_CMUTEX(cindex), CMUTEX_PROCESS_PRIVATE, (__location__))
#define CINDEX_CLEAN_LOCK(cindex, __location__)         cmutex_clean(CINDEX_CMUTEX(cindex), (__location__))

#define CINDEX_LOCK(cindex, __location__)               cmutex_lock(CINDEX_CMUTEX(cindex), (__location__))
#define CINDEX_UNLOCK(cindex, __location__)             cmutex_unlock(CINDEX_CMUTEX(cindex), (__location__))

CINDEX *cindex_new(const UINT32 capacity, const UINT32 mm_type, const UINT32 location);

void cindex_free(CINDEX *cindex, const UINT32 location);

void cindex_init(CINDEX *cindex, const UINT32 capacity, const UINT32 mm_type, const UINT32 lock_enable_flag, const UINT32 location);

UINT32 cindex_init_0(const UINT32 md_id, CINDEX *cindex);

UINT32 cindex_clean_0(const UINT32 md_id, CINDEX *cindex);

UINT32 cindex_free_0(const UINT32 md_id, CINDEX *cindex);

EC_BOOL cindex_is_empty(const CINDEX *cindex);

EC_BOOL cindex_expand(CINDEX *cindex);

UINT32 cindex_reserve(CINDEX *cindex, const void *data);

void * cindex_release(CINDEX *cindex, const UINT32 pos);

void *cindex_spy(const CINDEX *cindex, const UINT32 pos);

UINT32 cindex_capacity(const CINDEX *cindex);

UINT32 cindex_size(const CINDEX *cindex);

UINT32 cindex_next(const CINDEX *cindex);

UINT32 cindex_type(const CINDEX *cindex);

UINT32 cindex_type_set(CINDEX *cindex, const UINT32 data_mm_type);

void cindex_loop_front(const CINDEX *cindex, void (*handler)(void *));

void cindex_loop_back(const CINDEX *cindex, void (*handler)(void *));

UINT32 cindex_search_front(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cindex_search_back(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void cindex_clean(CINDEX *cindex, void (*cleaner)(void *), const UINT32 location);

void cindex_print(LOG *log, const CINDEX *cindex, void (*handler)(LOG *, const void *));

/*---------------------------------------------------------- no lock interface ----------------------------------------------------------*/
EC_BOOL cindex_expand_no_lock(CINDEX *cindex);

UINT32 cindex_reserve_no_lock(CINDEX *cindex, const void *data);

void * cindex_release_no_lock(CINDEX *cindex, const UINT32 pos);

void *cindex_spy_no_lock(const CINDEX *cindex, const UINT32 pos);

void cindex_loop_front_no_lock(const CINDEX *cindex, void (*handler)(void *));

void cindex_loop_back_no_lock(const CINDEX *cindex, void (*handler)(void *));

UINT32 cindex_search_front_no_lock(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 cindex_search_back_no_lock(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void cindex_clean_no_lock(CINDEX *cindex, void (*cleaner)(void *), const UINT32 location);

void cindex_print_no_lock(LOG *log, const CINDEX *cindex, void (*handler)(LOG *, const void *));

#endif /*_CINDEX_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

