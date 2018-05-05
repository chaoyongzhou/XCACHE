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

#ifndef _CSTACK_H
#define _CSTACK_H

#include "clist.h"

#define CSTACK_DATA_DATA(cstack_data)  ((cstack_data)->data)

typedef CLIST_DATA CSTACK_DATA;
typedef CLIST CSTACK;

typedef EC_BOOL (*CSTACK_DATA_DATA_CLEANER)(void *);
typedef EC_BOOL (*CSTACK_DATA_DATA_HANDLER)(void *);
typedef void (*CSTACK_DATA_DATA_PRINT)(LOG *, const void *);
typedef EC_BOOL (*CSTACK_DATA_DATA_CMP)(const void *, const void *);

typedef EC_BOOL (*CSTACK_DATA_DATA_WALKER)(const void *, void *);
CSTACK *cstack_new(const UINT32 mm_type, const UINT32 location);
void    cstack_free(CSTACK *cstack, const UINT32 location);

void    cstack_init(CSTACK *cstack, const UINT32 mm_type, const UINT32 location);
EC_BOOL cstack_is_empty(const CSTACK *cstack);

CSTACK_DATA * cstack_push(CSTACK *cstack, void *data);
void  * cstack_pop(CSTACK *cstack);
void  * cstack_top(const CSTACK *cstack);
UINT32  cstack_depth(const CSTACK *cstack);

void   cstack_loop(const CSTACK *cstack, EC_BOOL (*handler)(void *));
void   cstack_clean(CSTACK *cstack, EC_BOOL (*cleaner)(void *));
void * cstack_del(CSTACK *cstack, const void * data, EC_BOOL(* cmp)(const void *, const void *));

void   cstack_print(LOG *log, const CSTACK *cstack, void (*print)(LOG *, const void *));

EC_BOOL cstack_walk(const CSTACK *cstack, void *data, EC_BOOL (*walker)(const void *, void *));
#endif/* _CSTACK_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

