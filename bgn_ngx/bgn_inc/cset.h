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

#ifndef _CSET_H
#define _CSET_H

#include <stdio.h>
#include <stdlib.h>

#include "clist.h"

typedef CLIST_DATA CSET_DATA;
typedef CLIST CSET;

typedef CSET_DATA * (*CSET_DATA_MALLOC)();
typedef void (*CSET_DATA_FREE)(CSET_DATA *);
typedef EC_BOOL (*CSET_DATA_CMP)(const void *, const void *);
typedef EC_BOOL (*CSET_DATA_HANDLER)(void *);
typedef EC_BOOL (*CSET_DATA_CLEANER)(void *);
typedef void (*CSET_DATA_PRINT)(LOG *, const void *);

#define CSET_DATA_NEXT(cset_data)  CLIST_DATA_NEXT(cset_data)

#define CSET_DATA_PREV(cset_data)  CLIST_DATA_PREV(cset_data)

#define CSET_LOOP_PREV(cset, data_node) CLIST_LOOP_PREV(cset, data_node)

#define CSET_LOOP_NEXT(cset, data_node) CLIST_LOOP_NEXT(cset, data_node)

#define CSET_DATA_DATA(cset_data)  CLIST_DATA_DATA(cset_data)

#define CSET_DATA_DEL(cset_data) CLIST_DATA_DEL(cset_data)

CSET *cset_new(const UINT32 mm_type, const UINT32 location);

void cset_free(CSET *cset, const UINT32 location);

void cset_init(CSET *cset, const UINT32 mm_type, const UINT32 location);

EC_BOOL cset_is_empty(const CSET *cset);

void * cset_search(const CSET *cset, const void *data, EC_BOOL (*cmp)(const void *, const void *));

EC_BOOL cset_add(CSET *cset, void *data, EC_BOOL (*cmp)(const void *, const void *));

void * cset_erase(CSET *cset, const void *data, EC_BOOL (*cmp)(const void *, const void *));

void * cset_del(CSET *cset, CSET_DATA *cset_data);

UINT32 cset_size(const CSET *cset);

void cset_loop(const CSET *cset, EC_BOOL (*handler)(void *));

void cset_clean(CSET *cset, EC_BOOL (*cleaner)(void *));

void cset_print(LOG *log, const CSET *cset, void (*print)(LOG *, const void *));

#endif/* _CSET_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

