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
#include "cindex.h"

#include "cmutex.h"
#include "cmpic.inc"

#include "debug.h"

/*for safe reason, when data handler is not given, set to default null function*/
STATIC_CAST static void cindex_null_default(void *data)
{
    return;
}

STATIC_CAST static EC_BOOL cindex_data_cmp_default(const void * data_1, const void * data_2)
{
    if(data_1 != data_2)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CINDEX *cindex_new(const UINT32 capacity, const UINT32 mm_type, const UINT32 location)
{
    CINDEX *cindex;

    cindex = (CINDEX *)SAFE_MALLOC(sizeof(CINDEX), location);
    if(cindex)
    {
        cindex_init(cindex, capacity, mm_type, CINDEX_LOCK_ENABLE, location);
    }
    return cindex;
}

void cindex_free(CINDEX *cindex, const UINT32 location)
{
    CINDEX_LOCK(cindex, LOC_CINDEX_0001);
    if(cindex->data)
    {
        SAFE_FREE(cindex->data, location);
        cindex->data = (void **)0;
        cindex->capacity = 0;
        cindex->size = 0;
        cindex->next = CINDEX_BEG_POS;
    }
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0002);
    CINDEX_CLEAN_LOCK(cindex, LOC_CINDEX_0003);
    SAFE_FREE(cindex, location);
    return;
}

void cindex_init(CINDEX *cindex, const UINT32 capacity, const UINT32 mm_type, const UINT32 lock_enable_flag, const UINT32 location)
{
    UINT32 pos;

    if(CINDEX_LOCK_ENABLE == lock_enable_flag)
    {
        cindex->lock_enable_flag = lock_enable_flag;
        CINDEX_INIT_LOCK(cindex, LOC_CINDEX_0004);
    }
    else
    {
        if(CINDEX_LOCK_ENABLE == cindex->lock_enable_flag)
        {
            CINDEX_CLEAN_LOCK(cindex, LOC_CINDEX_0005);
        }
        cindex->lock_enable_flag = lock_enable_flag;
    }

    if(0 == capacity)
    {
        cindex->data = (void **)0;
        cindex->capacity = 0;
        cindex->size = 0;
        cindex->next = CINDEX_BEG_POS;/*xx*/
        return;
    }

    cindex->data = (void **)SAFE_MALLOC(sizeof(void *) * capacity, location);
    if(cindex->data)
    {
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        for(pos = 0; pos < capacity; pos ++)
        {
            cindex->data[ pos ] = NULL_PTR;
        }

        cindex->capacity = capacity;
        cindex->size = 0;
        cindex->next = CINDEX_BEG_POS;
        return;
    }

    cindex->capacity = 0;
    cindex->size = 0;
    cindex->next = CINDEX_BEG_POS;
    return;
}

UINT32 cindex_init_0(const UINT32 md_id, CINDEX *cindex)
{
    //dbg_log(SEC_0106_CINDEX, 3)(LOGSTDOUT, "info:cindex_init_0: cindex = %lx, cmutex = %lx\n", cindex, &(cindex->cmutex));
    cindex_init(cindex, 0, MM_END, CINDEX_LOCK_ENABLE, LOC_CINDEX_0006);
    return (0);
}

UINT32 cindex_clean_0(const UINT32 md_id, CINDEX *cindex)
{
    CINDEX_LOCK(cindex, LOC_CINDEX_0007);

    if(NULL_PTR != cindex->data_free)
    {
        UINT32 pos;

        for(pos = 0; pos < cindex->capacity; pos ++)
        {
            if(cindex->data[ pos ])
            {
                continue;
            }
            cindex->data_free(md_id, cindex->data[ pos ]);
        }
    }
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0008);

    cindex_clean(cindex, NULL_PTR, LOC_CINDEX_0009);
    return (0);
}

UINT32 cindex_free_0(const UINT32 md_id, CINDEX *cindex)
{
    cindex_clean_0(md_id, cindex);
    cindex_free(cindex, LOC_CINDEX_0010);
    return (0);
}

EC_BOOL cindex_is_empty(const CINDEX *cindex)
{
    return 0 == cindex->size? EC_TRUE : EC_FALSE;
}

EC_BOOL cindex_expand(CINDEX *cindex)
{
    UINT32 pos;
    UINT32 capacity;
    void **data;

    CINDEX_LOCK(cindex, LOC_CINDEX_0011);
    if(0 == cindex->capacity)
    {
        capacity = 128; /*default*/
        data = (void **)SAFE_MALLOC(sizeof(void *) * capacity, LOC_CINDEX_0012);
    }
    else
    {
        capacity = 2 * (cindex->capacity);/*double the old capacity*/
        data = (void **)SAFE_REALLOC(cindex->data, sizeof(void *) * (cindex->capacity), sizeof(void *) * capacity, LOC_CINDEX_0013);
    }

    if(data)
    {
        cindex->data = data;
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        for(pos = cindex->capacity; pos < capacity; pos ++)
        {
            cindex->data[ pos ] = (void *)0;
        }

        cindex->capacity = capacity;

        CINDEX_UNLOCK(cindex, LOC_CINDEX_0014);
        return (EC_TRUE);
    }

    dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_expand: failed to expand cindex %lx with capacity %ld, size %ld next %ld\n",
                        cindex, cindex->capacity, cindex->size, cindex->next);

    CINDEX_UNLOCK(cindex, LOC_CINDEX_0015);
    return (EC_FALSE);
}

UINT32 cindex_reserve(CINDEX *cindex, const void *data)
{
    UINT32 pos;
    UINT32 next;

    //dbg_log(SEC_0106_CINDEX, 5)(LOGSTDOUT, "cindex: when enter, size = %ld, capacity = %ld, next = %ld\n", cindex->size, cindex->capacity, cindex->next);
    CINDEX_LOCK(cindex, LOC_CINDEX_0016);
    if( cindex->size == cindex->capacity )
    {
        /*if failed to expand, return error code*/
        if( EC_FALSE == cindex_expand_no_lock(cindex) )
        {
            CINDEX_UNLOCK(cindex, LOC_CINDEX_0017);
            return (CINDEX_ERR_POS);
        }
        //dbg_log(SEC_0106_CINDEX, 5)(LOGSTDOUT, "cindex: after expand, size = %ld, capacity = %ld, next = %ld\n", cindex->size, cindex->capacity, cindex->next);

        pos  = cindex->size;
        next = ((pos + 1) % (cindex->capacity));

        cindex->data[ pos ] = (void *)data;
        cindex->next = next;
        cindex->size ++;

        CINDEX_UNLOCK(cindex, LOC_CINDEX_0018);
        return (pos);
    }

    pos = cindex->next;
    for(;;)
    {
        next = ((pos + 1) % (cindex->capacity));
        if(NULL_PTR == cindex->data[ pos ])
        {
            cindex->data[ pos ] = (void *)data;
            cindex->next = next;
            cindex->size ++;
            CINDEX_UNLOCK(cindex, LOC_CINDEX_0019);
            return (pos);
        }

        if(next == cindex->next)
        {
            break;
        }

        pos = next;/*move to next*/
    }

    dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_reserve: reserve index failed, cindex %lx, size %ld, capacity %ld, next %ld\n",
                        cindex, cindex->size, cindex->capacity, cindex->next);

    CINDEX_UNLOCK(cindex, LOC_CINDEX_0020);
    return (CINDEX_ERR_POS);
}

void * cindex_release(CINDEX *cindex, const UINT32 pos)
{
    void *data;

    CINDEX_LOCK(cindex, LOC_CINDEX_0021);
    if(pos >= cindex->capacity)
    {
        dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_release: release index %ld overflow, cindex %lx, size %ld, capacity %ld, next %ld\n",
                            pos,
                            cindex, cindex->size, cindex->capacity, cindex->next);

        CINDEX_UNLOCK(cindex, LOC_CINDEX_0022);
        return (NULL_PTR);
    }

    data = cindex->data[ pos ];
    if(NULL_PTR == data)/*debug to prevent from anything wrong*/
    {
        dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_release: release index %ld refer to null, cindex %lx, size %ld, capacity %ld, next %ld\n",
                            pos,
                            cindex, cindex->size, cindex->capacity, cindex->next);
        CINDEX_UNLOCK(cindex, LOC_CINDEX_0023);
        return (NULL_PTR);
    }

    cindex->data[ pos ] = NULL_PTR;
    cindex->size --;

    CINDEX_UNLOCK(cindex, LOC_CINDEX_0024);
    return (data);
}

void *cindex_spy(const CINDEX *cindex, const UINT32 pos)
{
    void *data;

    CINDEX_LOCK(cindex, LOC_CINDEX_0025);
    if(pos >= cindex->capacity)
    {
        dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_spy: spy index %ld overflow, cindex %lx, size %ld, capacity %ld, next %ld\n",
                            pos,
                            cindex, cindex->size, cindex->capacity, cindex->next);
        CINDEX_UNLOCK(cindex, LOC_CINDEX_0026);
        return (void *)0;
    }

    data = cindex->data[ pos ];
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0027);
    return (data);
}

UINT32 cindex_capacity(const CINDEX *cindex)
{
    return cindex->capacity;
}

UINT32 cindex_size(const CINDEX *cindex)
{
    return cindex->size;
}

UINT32 cindex_next(const CINDEX *cindex)
{
    return cindex->next;
}

UINT32 cindex_type(const CINDEX *cindex)
{
    return cindex->data_mm_type;
}

UINT32 cindex_type_set(CINDEX *cindex, const UINT32 data_mm_type)
{
    cindex->data_mm_type = data_mm_type;
    return (0);
}

void cindex_loop_front(const CINDEX *cindex, void (*handler)(void *))
{
    UINT32 pos;

    CINDEX_LOCK(cindex, LOC_CINDEX_0028);
    for(pos = 0; pos < cindex->capacity; pos ++)
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        handler(cindex->data[ pos ]);
    }
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0029);
    return;
}

void cindex_loop_back(const CINDEX *cindex, void (*handler)(void *))
{
    UINT32 pos;

    CINDEX_LOCK(cindex, LOC_CINDEX_0030);
    for(pos = cindex->capacity; pos -- > 0; )
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        handler(cindex->data[ pos ]);
    }
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0031);
    return;
}

UINT32 cindex_search_front(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CINDEX_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cindex_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    CINDEX_LOCK(cindex, LOC_CINDEX_0032);
    for(pos = 0; pos < cindex->capacity; pos ++)
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        if(EC_TRUE == data_cmp(cindex->data[ pos ], data))
        {
            CINDEX_UNLOCK(cindex, LOC_CINDEX_0033);
            return pos;
        }
    }
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0034);
    return CINDEX_ERR_POS;
}

UINT32 cindex_search_back(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;

    CINDEX_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cindex_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    CINDEX_LOCK(cindex, LOC_CINDEX_0035);
    for(pos = cindex->capacity; pos -- > 0; )
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        if(EC_TRUE == data_cmp(cindex->data[ pos ], data))
        {
            CINDEX_UNLOCK(cindex, LOC_CINDEX_0036);
            return pos;
        }
    }
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0037);
    return CINDEX_ERR_POS;
}

void cindex_clean(CINDEX *cindex, void (*cleaner)(void *), const UINT32 location)
{
    if( NULL_PTR != cleaner)
    {
        cindex_loop_front(cindex, cleaner);
    }

    CINDEX_LOCK(cindex, LOC_CINDEX_0038);

    if(NULL_PTR != cindex->data)
    {
        SAFE_FREE(cindex->data, location);
        cindex->data = (void **)0;
    }
    cindex->capacity = 0;
    cindex->size = 0;
    cindex->next = CINDEX_BEG_POS;

    CINDEX_UNLOCK(cindex, LOC_CINDEX_0039);

    return;
}

void cindex_print(LOG *log, const CINDEX *cindex, void (*handler)(LOG *, const void *))
{
    UINT32 pos;

    sys_log(log, "cindex %lx, size %ld, capacity %ld, next %ld\n", cindex, cindex->size, cindex->capacity, cindex->next);

    CINDEX_LOCK(cindex, LOC_CINDEX_0040);
    for(pos = 0; pos < cindex->capacity; pos ++)
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        sys_log( log, "No. %ld: ", pos);
        if(0 != handler)
        {
            (handler)(log, cindex->data[ pos ]);
        }
        else
        {
            sys_print(log, " %lx\n", cindex->data[ pos ]);
        }
    }
    CINDEX_UNLOCK(cindex, LOC_CINDEX_0041);
    return;
}

/*---------------------------------------------------------- no lock interface ----------------------------------------------------------*/
EC_BOOL cindex_expand_no_lock(CINDEX *cindex)
{
    UINT32 pos;
    UINT32 capacity;
    void **data;

    if(0 == cindex->capacity)
    {
        capacity = 128; /*default*/
        data = (void **)SAFE_MALLOC(sizeof(void *) * capacity, LOC_CINDEX_0042);
    }
    else
    {
        capacity = 2 * (cindex->capacity);/*double the old capacity*/
        data = (void **)SAFE_REALLOC(cindex->data, sizeof(void *) *(cindex->capacity), sizeof(void *) * capacity, LOC_CINDEX_0043);
    }

    if(data)
    {
        cindex->data = data;
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        for(pos = cindex->capacity; pos < capacity; pos ++)
        {
            cindex->data[ pos ] = NULL_PTR;
        }

        cindex->capacity = capacity;

        return (EC_TRUE);
    }

    dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_expand_no_lock: failed to expand cindex with capacity %ld and size %ld\n", cindex->capacity, cindex->size);

    return (EC_FALSE);
}

UINT32 cindex_reserve_no_lock(CINDEX *cindex, const void *data)
{
    UINT32 pos;
    UINT32 next;

    if( cindex->size == cindex->capacity )
    {
        /*if failed to expand, return error code*/
        if( EC_FALSE == cindex_expand_no_lock(cindex) )
        {
            return (CINDEX_ERR_POS);
        }

        pos = cindex->size;
        next = ((pos + 1) % (cindex->capacity));

        cindex->data[ pos ] = (void *)data;
        cindex->next = next;
        cindex->size ++;

        return (pos);
    }

    pos = cindex->next;
    for(;;)
    {
        next = ((pos + 1) % (cindex->capacity));
        if(NULL_PTR == cindex->data[ pos ])
        {
            cindex->data[ pos ] = (void *)data;
            cindex->next = next;
            cindex->size ++;
            return (pos);
        }

        if(next == cindex->next)
        {
            break;
        }

        pos = next;/*move to next*/
    }

    dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_reserve_no_lock: reserve index failed, cindex %lx, size %ld, capacity %ld, next %ld\n",
                        cindex, cindex->size, cindex->capacity, cindex->next);
    return (CINDEX_ERR_POS);
}

void * cindex_release_no_lock(CINDEX *cindex, const UINT32 pos)
{
    void *data;

    if(pos >= cindex->capacity)
    {
        dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_release_no_lock: release index %ld overflow, cindex %lx, size %ld, capacity %ld, next %ld\n",
                            pos,
                            cindex, cindex->size, cindex->capacity, cindex->next);
        return (NULL_PTR);
    }

    data = cindex->data[ pos ];
    if(NULL_PTR == data)/*debug to prevent from anything wrong*/
    {
        dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_release_no_lock: release index %ld refer to null, cindex %lx, size %ld, capacity %ld, next %ld\n",
                            pos,
                            cindex, cindex->size, cindex->capacity, cindex->next);
        return (NULL_PTR);
    }

    cindex->data[ pos ] = NULL_PTR;
    cindex->size --;

    return (data);
}

void *cindex_spy_no_lock(const CINDEX *cindex, const UINT32 pos)
{
    void *data;

    if(pos >= cindex->capacity)
    {
        dbg_log(SEC_0106_CINDEX, 0)(LOGSTDOUT, "error:cindex_spy_no_lock: spy index %ld overflow, cindex %lx, size %ld, capacity %ld, next %ld\n",
                            pos,
                            cindex, cindex->size, cindex->capacity, cindex->next);
        return (void *)0;
    }

    data = cindex->data[ pos ];
    return (data);
}

void cindex_loop_front_no_lock(const CINDEX *cindex, void (*handler)(void *))
{
    UINT32 pos;

    for(pos = 0; pos < cindex->capacity; pos ++)
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }
        handler(cindex->data[ pos ]);
    }
    return;
}

void cindex_loop_back_no_lock(const CINDEX *cindex, void (*handler)(void *))
{
    UINT32 pos;

    for(pos = cindex->capacity; pos -- > 0; )
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }
        handler(cindex->data[ pos ]);
    }
    return;
}

UINT32 cindex_search_front_no_lock(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CINDEX_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cindex_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = 0; pos < cindex->capacity; pos ++)
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        if(EC_TRUE == data_cmp(cindex->data[ pos ], data))
        {
            return pos;
        }
    }
    return CINDEX_ERR_POS;
}

UINT32 cindex_search_back_no_lock(const CINDEX *cindex, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;

    CINDEX_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cindex_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = cindex->capacity; pos -- > 0; )
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        if(EC_TRUE == data_cmp(cindex->data[ pos ], data))
        {
            return pos;
        }
    }
    return CINDEX_ERR_POS;
}

void cindex_clean_no_lock(CINDEX *cindex, void (*cleaner)(void *), const UINT32 location)
{
    if( NULL_PTR != cleaner)
    {
        cindex_loop_front(cindex, cleaner);
    }

    if(NULL_PTR != cindex->data)
    {
        SAFE_FREE(cindex->data, location);
        cindex->data = (void **)0;
    }
    cindex->capacity = 0;
    cindex->size = 0;
    cindex->next = CINDEX_BEG_POS;

    return;
}

void cindex_print_no_lock(LOG *log, const CINDEX *cindex, void (*handler)(LOG *, const void *))
{
    UINT32 pos;

    sys_log(log, "cindex %lx, size %ld, capacity %ld, next %ld\n", cindex, cindex->size, cindex->capacity, cindex->next);

    for(pos = 0; pos < cindex->capacity; pos ++)
    {
        if(NULL_PTR == cindex->data[ pos ])
        {
            continue;
        }

        sys_log( log, "No. %ld: ", pos);
        if(0 != handler)
        {
            (handler)(log, cindex->data[ pos ]);
        }
        else
        {
            sys_print(log, " %lx\n", cindex->data[ pos ]);
        }
    }
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

