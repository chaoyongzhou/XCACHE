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

#ifndef _CARRAY_H
#define _CARRAY_H

#include "type.h"
#include "cmutex.h"

#define CARRAY_ERR_POS ((UINT32)(~((UINT32)0)))

typedef struct
{
    UINT32 size;

    void **data;

    CMUTEX    cmutex;
}CARRAY;

typedef EC_BOOL (*CARRAY_DATA_HANDLER)(void *);
typedef EC_BOOL (*CARRAY_DATA_CMP)(const void *, const void *);
typedef EC_BOOL (*CARRAY_DATA_CLEANER)(void *);
typedef void (*CARRAY_DATA_PRINT)(void *);

#define CARRAY_CMUTEX(carray)                           ((CMUTEX *)&((carray)->cmutex))
#define CARRAY_INIT_LOCK(carray, __location__)          cmutex_init(CARRAY_CMUTEX(carray), CMUTEX_PROCESS_PRIVATE, (__location__))
#define CARRAY_CLEAN_LOCK(carray, __location__)         cmutex_clean(CARRAY_CMUTEX(carray), (__location__))

#define CARRAY_LOCK(carray, __location__)               cmutex_lock(CARRAY_CMUTEX(carray), (__location__))
#define CARRAY_UNLOCK(carray, __location__)             cmutex_unlock(CARRAY_CMUTEX(carray), (__location__))


CARRAY *carray_new(const UINT32 size, const void *init_val, const UINT32 location);

void carray_free(CARRAY *carray, const UINT32 location);

void carray_init(CARRAY *carray, const UINT32 size, const void *init_val, const UINT32 location);

EC_BOOL carray_is_empty(const CARRAY *carray);

void **carray_get_addr(const CARRAY *carray, const UINT32 pos);

void *carray_get(const CARRAY *carray, const UINT32 pos);

/*return old data*/
void *carray_set(CARRAY *carray, const UINT32 pos, const void *data);

void *carray_erase(CARRAY *carray, const UINT32 pos);

UINT32 carray_size(const CARRAY *carray);

void carray_loop_front(const CARRAY *carray, EC_BOOL (*handler)(void *));

void carray_loop_back(const CARRAY *carray, EC_BOOL (*handler)(void *));

UINT32 carray_search_front(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 carray_search_back(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void carray_clean(CARRAY *carray, EC_BOOL (*cleaner)(void *));

void carray_print(LOG *log, const CARRAY *carray, void (*print)(LOG *, const void *));

/*---------------------------------------------------------- no lock interface ----------------------------------------------------------*/
void carray_free_no_lock(CARRAY *carray, const UINT32 location);

void **carray_get_addr_no_lock(const CARRAY *carray, const UINT32 pos);

void *carray_get_no_lock(const CARRAY *carray, const UINT32 pos);

/*return old data*/
void *carray_set_no_lock(CARRAY *carray, const UINT32 pos, const void *data);

void *carray_erase_no_lock(CARRAY *carray, const UINT32 pos);

void carray_loop_front_no_lock(const CARRAY *carray, EC_BOOL (*handler)(void *));

void carray_loop_back_no_lock(const CARRAY *carray, EC_BOOL (*handler)(void *));

UINT32 carray_search_front_no_lock(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *));

UINT32 carray_search_back_no_lock(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void carray_clean_no_lock(CARRAY *carray, EC_BOOL (*cleaner)(void *));

void carray_print_no_lock(LOG *log, const CARRAY *carray, void (*print)(LOG *, const void *));

#endif /*_CARRAY_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
