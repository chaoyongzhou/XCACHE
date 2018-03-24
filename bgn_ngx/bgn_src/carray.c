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
#include "mm.h"
#include "log.h"
#include "carray.h"

#include "cmutex.h"

/*for safe reason, when data handler is not given, set to default null function*/
STATIC_CAST static EC_BOOL carray_null_default(void *data)
{
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL carray_data_cmp_default(const void *data_1, const void *data_2)
{
    if(data_1 != data_2)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CARRAY *carray_new(const UINT32 size, const void *init_val, const UINT32 location)
{
    CARRAY *carray;

    carray = (CARRAY *)SAFE_MALLOC(sizeof(CARRAY), location);
    if(carray)
    {
        carray_init(carray, size, init_val, location);
    }
    return carray;
}

void carray_free(CARRAY *carray, const UINT32 location)
{
    CARRAY_LOCK(carray, LOC_CARRAY_0001);
    if(carray->data)
    {
        SAFE_FREE(carray->data, location);
        carray->data = (void **)0;
        carray->size = 0;
    }
    CARRAY_UNLOCK(carray, LOC_CARRAY_0002);
    CARRAY_CLEAN_LOCK(carray, LOC_CARRAY_0003);
    SAFE_FREE(carray, location);
}

void carray_init(CARRAY *carray, const UINT32 size, const void *init_val, const UINT32 location)
{
    UINT32 pos;

    CARRAY_INIT_LOCK(carray, LOC_CARRAY_0004);

    if(0 == size)
    {
        carray->data = (void **)0;
        carray->size = 0;
        return;
    }

    carray->data = (void **)SAFE_MALLOC(sizeof(void *) * size, location);
    if(carray->data)
    {
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        for(pos = 0; pos < size; pos ++)
        {
            carray->data[ pos ] = (void *)init_val;
        }

        carray->size = size;

        return;
    }

    carray->size = 0;
    return;
}

EC_BOOL carray_is_empty(const CARRAY *carray)
{
    return 0 == carray->size? EC_TRUE : EC_FALSE;
}

void **carray_get_addr(const CARRAY *carray, const UINT32 pos)
{
    void **addr;

    CARRAY_LOCK(carray, LOC_CARRAY_0005);
    if(pos >= carray->size)
    {
        CARRAY_UNLOCK(carray, LOC_CARRAY_0006);
        return (void **)0;
    }

    addr = &(carray->data[ pos ]);
    CARRAY_UNLOCK(carray, LOC_CARRAY_0007);
    return (addr);
}

void *carray_get(const CARRAY *carray, const UINT32 pos)
{
    void *data;

    CARRAY_LOCK(carray, LOC_CARRAY_0008);
    if(pos >= carray->size)
    {
        CARRAY_UNLOCK(carray, LOC_CARRAY_0009);
        return (void *)0;
    }

    data = carray->data[ pos ];
    CARRAY_UNLOCK(carray, LOC_CARRAY_0010);
    return (data);
}

/*return old data*/
void *carray_set(CARRAY *carray, const UINT32 pos, const void *data)
{
    void *old_data;

    CARRAY_LOCK(carray, LOC_CARRAY_0011);
    if(pos >= carray->size)
    {
        CARRAY_UNLOCK(carray, LOC_CARRAY_0012);
        return (void *)0;
    }

    old_data = carray->data[ pos ];
    carray->data[ pos ] = (void *)data;
    CARRAY_UNLOCK(carray, LOC_CARRAY_0013);
    return old_data;
}

void *carray_erase(CARRAY *carray, const UINT32 pos)
{
    void *old_data;

    CARRAY_LOCK(carray, LOC_CARRAY_0014);
    if(pos >= carray->size)
    {
        CARRAY_UNLOCK(carray, LOC_CARRAY_0015);
        return (void *)0;
    }

    old_data = carray->data[ pos ];
    carray->data[ pos ] = (void *)0;

    CARRAY_UNLOCK(carray, LOC_CARRAY_0016);
    return old_data;
}

UINT32 carray_size(const CARRAY *carray)
{
    return carray->size;
}

void carray_loop_front(const CARRAY *carray, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    CARRAY_LOCK(carray, LOC_CARRAY_0017);
    for(pos = 0; pos < carray->size; pos ++)
    {
        handler(carray->data[ pos ]);
    }
    CARRAY_UNLOCK(carray, LOC_CARRAY_0018);
    return;
}

void carray_loop_back(const CARRAY *carray, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    CARRAY_LOCK(carray, LOC_CARRAY_0019);
    for(pos = carray->size; pos -- > 0; )
    {
        handler(carray->data[ pos ]);
    }
    CARRAY_UNLOCK(carray, LOC_CARRAY_0020);

    return;
}

UINT32 carray_search_front(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CARRAY_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = carray_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    CARRAY_LOCK(carray, LOC_CARRAY_0021);
    for(pos = 0; pos < carray->size; pos ++)
    {
        if(EC_TRUE == data_cmp(carray->data[ pos ], data))
        {
            CARRAY_UNLOCK(carray, LOC_CARRAY_0022);
            return pos;
        }
    }
    CARRAY_UNLOCK(carray, LOC_CARRAY_0023);
    return CARRAY_ERR_POS;
}

UINT32 carray_search_back(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CARRAY_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = carray_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    CARRAY_LOCK(carray, LOC_CARRAY_0024);
    for(pos = carray->size; pos -- > 0; )
    {
        if(EC_TRUE == data_cmp(carray->data[ pos ], data))
        {
            CARRAY_UNLOCK(carray, LOC_CARRAY_0025);
            return pos;
        }
    }
    CARRAY_UNLOCK(carray, LOC_CARRAY_0026);
    return CARRAY_ERR_POS;
}

void carray_clean(CARRAY *carray, EC_BOOL (*cleaner)(void *))
{
    CARRAY_LOCK(carray, LOC_CARRAY_0027);

    carray_loop_front(carray, 0 == cleaner? carray_null_default : cleaner);

    SAFE_FREE(carray->data, LOC_CARRAY_0028);
    carray->data = (void **)0;
    carray->size = 0;

    CARRAY_UNLOCK(carray, LOC_CARRAY_0029);
    return;
}

void carray_print(LOG *log, const CARRAY *carray, void (*print)(LOG *, const void *))
{
    UINT32 pos;

    CARRAY_LOCK(carray, LOC_CARRAY_0030);
    for(pos = 0; pos < carray->size; pos ++)
    {
        sys_log(log, "No. %ld: ", pos);
        if(NULL_PTR == print)
        {
            sys_log(log, "%lx\n", carray->data[ pos ]);
        }
        else
        {
            print(log, carray->data[ pos ]);
        }
    }
    CARRAY_UNLOCK(carray, LOC_CARRAY_0031);
    return;
}
/*---------------------------------------------------------- no lock interface ----------------------------------------------------------*/
void carray_free_no_lock(CARRAY *carray, const UINT32 location)
{
    if(carray->data)
    {
        SAFE_FREE(carray->data, location);
        carray->data = (void **)0;
        carray->size = 0;
    }
    CARRAY_CLEAN_LOCK(carray, LOC_CARRAY_0032);
    SAFE_FREE(carray, location);
}

void **carray_get_addr_no_lock(const CARRAY *carray, const UINT32 pos)
{
    void **addr;

    if(pos >= carray->size)
    {
        return (void **)0;
    }

    addr = &(carray->data[ pos ]);
    return (addr);
}

void *carray_get_no_lock(const CARRAY *carray, const UINT32 pos)
{
    void *data;

    if(pos >= carray->size)
    {
        return (void *)0;
    }

    data = carray->data[ pos ];
    return (data);
}

/*return old data*/
void *carray_set_no_lock(CARRAY *carray, const UINT32 pos, const void *data)
{
    void *old_data;

    if(pos >= carray->size)
    {
        return (void *)0;
    }

    old_data = carray->data[ pos ];
    carray->data[ pos ] = (void *)data;
    return old_data;
}

void *carray_erase_no_lock(CARRAY *carray, const UINT32 pos)
{
    void *old_data;

    if(pos >= carray->size)
    {
        return (void *)0;
    }

    old_data = carray->data[ pos ];
    carray->data[ pos ] = (void *)0;

    return old_data;
}

void carray_loop_front_no_lock(const CARRAY *carray, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    for(pos = 0; pos < carray->size; pos ++)
    {
        handler(carray->data[ pos ]);
    }
    return;
}

void carray_loop_back_no_lock(const CARRAY *carray, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    for(pos = carray->size; pos -- > 0; )
    {
        handler(carray->data[ pos ]);
    }

    return;
}

UINT32 carray_search_front_no_lock(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CARRAY_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = carray_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = 0; pos < carray->size; pos ++)
    {
        if(EC_TRUE == data_cmp(carray->data[ pos ], data))
        {
            return pos;
        }
    }
    return CARRAY_ERR_POS;
}

UINT32 carray_search_back_no_lock(const CARRAY *carray, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CARRAY_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = carray_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = carray->size; pos -- > 0; )
    {
        if(EC_TRUE == data_cmp(carray->data[ pos ], data))
        {
            return pos;
        }
    }
    return CARRAY_ERR_POS;
}

void carray_clean_no_lock(CARRAY *carray, EC_BOOL (*cleaner)(void *))
{
    carray_loop_front_no_lock(carray, 0 == cleaner? carray_null_default : cleaner);

    SAFE_FREE(carray->data, LOC_CARRAY_0033);
    carray->data = (void **)0;
    carray->size = 0;

    return;
}

void carray_print_no_lock(LOG *log, const CARRAY *carray, void (*print)(LOG *, const void *))
{
    UINT32 pos;

    for(pos = 0; pos < carray->size; pos ++)
    {
        sys_log(log, "No. %ld: ", pos);
        if(NULL_PTR == print)
        {
            sys_log(log, "%lx\n", carray->data[ pos ]);
        }
        else
        {
            print(log, carray->data[ pos ]);
        }
    }
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
