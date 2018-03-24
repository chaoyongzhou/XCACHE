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

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cset.h"

#include "mm.h"
#include "log.h"

#include "bgnctrl.h"

STATIC_CAST static EC_BOOL cset_data_cmp_default(const void * data_1, const void * data_2)
{
    if(data_1 != data_2)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CSET *cset_new(const UINT32 mm_type, const UINT32 location)
{
    return clist_new(mm_type, location);
}

void cset_free(CSET *cset, const UINT32 location)
{
    clist_free(cset, location);
    return;
}

void cset_init(CSET *cset, const UINT32 mm_type, const UINT32 location)
{
    clist_init(cset, mm_type, location);
    return;
}

EC_BOOL cset_is_empty(const CSET *cset)
{
    return clist_is_empty(cset);
}

void * cset_search(const CSET *cset, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    CSET_DATA *cset_data;
    cset_data = (CSET_DATA *) clist_search_front(cset, data, (NULL_PTR == cmp) ? cset_data_cmp_default: cmp);
    if(NULL_PTR == cset_data)
    {
        return NULL_PTR;
    }
    return CSET_DATA_DATA(cset_data);
}

EC_BOOL cset_add(CSET *cset, void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    if(NULL_PTR != clist_search_front(cset, data, (NULL_PTR == cmp) ? cset_data_cmp_default: cmp))
    {
        //dbg_log(SEC_0128_CSET, 0)(LOGSTDOUT, "error:cset_add: cset %lx, data %lx find duplicate when add\n", cset);
        return (EC_FALSE);
    }

    clist_push_back(cset, data);
    return (EC_TRUE);
}

void * cset_erase(CSET *cset, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    return clist_erase(cset, clist_search_front(cset, data, (NULL_PTR == cmp) ? cset_data_cmp_default: cmp));
}

void * cset_del(CSET *cset, CSET_DATA *cset_data)
{
    return clist_erase(cset, cset_data);
}

UINT32 cset_size(const CSET *cset)
{
    return clist_size(cset);
}

void cset_loop(const CSET *cset, EC_BOOL (*handler)(void *))
{
    clist_loop_front(cset, handler);
    return;
}

void cset_clean(CSET *cset, EC_BOOL (*cleaner)(void *))
{
    clist_clean(cset, cleaner);
    return;
}

void cset_print(LOG *log, const CSET *cset, void (*print)(LOG *, const void *))
{
    clist_print( log, cset, print);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

