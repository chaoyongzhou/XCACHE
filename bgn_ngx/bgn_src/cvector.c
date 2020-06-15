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
#include "cvector.h"

#include "cmutex.h"

#include "cmpic.inc"

#include "debug.h"

/*for safe reason, when data handler is not given, set to default null function*/
STATIC_CAST static void cvector_null_default(void *data)
{
    return;
}

STATIC_CAST static EC_BOOL cvector_data_cmp_default(const void * data_1, const void * data_2)
{
    if(data_1 != data_2)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL cvector_data_filter_default(const void * data_1, const void * data_2)
{
    if(data_1 != data_2)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cvector_checker_default(const void * retval)
{
    return ((EC_BOOL)retval);
}

CVECTOR *cvector_new(const UINT32 capacity, const UINT32 mm_type, const UINT32 location)
{
    CVECTOR *cvector;

    cvector = (CVECTOR *)SAFE_MALLOC(sizeof(CVECTOR), location);
    if(cvector)
    {
        cvector_init(cvector, capacity, mm_type, CVECTOR_LOCK_ENABLE, location);
    }
    return cvector;
}

void cvector_free(CVECTOR *cvector, const UINT32 location)
{
    CVECTOR_LOCK(cvector, location);
    if(cvector->data)
    {
        SAFE_FREE(cvector->data, location);
        cvector->data = (void **)0;
        cvector->capacity = 0;
        cvector->size = 0;
    }
    CVECTOR_UNLOCK(cvector, location);
    CVECTOR_CLEAN_LOCK(cvector, location);
    SAFE_FREE(cvector, location);
    return;
}

/*warn: codec should not be initialized in cvector_init because cvector_init is called when decoding*/
void cvector_init(CVECTOR *cvector, const UINT32 capacity, const UINT32 mm_type, const UINT32 lock_enable_flag, const UINT32 location)
{
    UINT32 pos;

    cvector_codec_set(cvector, mm_type);

    //cvector->__m_kind = &(CMUTEX_KIND(&(cvector->cmutex)));

    if(CVECTOR_LOCK_ENABLE == lock_enable_flag)
    {
        cvector->lock_enable_flag = lock_enable_flag;
        CVECTOR_INIT_LOCK(cvector, location);
    }
    else
    {
        if(CVECTOR_LOCK_ENABLE == cvector->lock_enable_flag)
        {
            CVECTOR_CLEAN_LOCK(cvector, location);
        }
        cvector->lock_enable_flag = lock_enable_flag;
    }

    if(0 == capacity)
    {
        cvector->data = (void **)0;
        cvector->capacity = 0;
        cvector->size = 0;
        return;
    }

    cvector->data = (void **)SAFE_MALLOC(sizeof(void *) * capacity, location);
    if(cvector->data)
    {
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        for(pos = 0; pos < capacity; pos ++)
        {
            cvector->data[ pos ] = (void *)0;
        }

        cvector->capacity = capacity;
        cvector->size = 0;
        return;
    }
    cvector->capacity = 0;
    cvector->size = 0;
    return;
}

UINT32 cvector_init_0(CVECTOR *cvector)
{
    //dbg_log(SEC_0080_CVECTOR, 3)(LOGSTDOUT, "info:cvector_init_0: cvector = %lx, cmutex = %lx\n", cvector, &(cvector->cmutex));
    cvector_init(cvector, 0, MM_END, CVECTOR_LOCK_ENABLE, LOC_CVECTOR_0001);
    return (0);
}

UINT32 cvector_clean_0(CVECTOR *cvector)
{
    /*seems it is quite NOT necessary to clean codec setting! but if set, we may be in greate trouble*/
    CVECTOR_LOCK(cvector, LOC_CVECTOR_0002);

    if(NULL_PTR != cvector->data_free)
    {
        UINT32 pos;

        for(pos = 0; pos < cvector->size; pos ++)
        {
            cvector->data_free(cvector->data[ pos ]);/*oh! free item when clean cvector!!*/
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0003);

    cvector_clean(cvector, NULL_PTR, LOC_CVECTOR_0004);
    return (0);
}

UINT32 cvector_free_0(CVECTOR *cvector)
{
    cvector_clean_0(cvector);
    cvector_free(cvector, LOC_CVECTOR_0005);
    return (0);
}

/*note: clone cvector_src to the tail of cvector_des*/
void cvector_clone(const CVECTOR *cvector_src, CVECTOR *cvector_des, void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    cvector_codec_clone(cvector_src, cvector_des);

    CVECTOR_LOCK(cvector_src, LOC_CVECTOR_0006);
    /*not necessary to lock cvector_des here*/

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            des_data = src_data;
            cvector_push(cvector_des, des_data);
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            des_data = cvector_data_malloc();
            cvector_data_clone(src_data, des_data);

            cvector_push(cvector_des, des_data);
        }
    }
    CVECTOR_UNLOCK(cvector_src, LOC_CVECTOR_0007);
    return;
}

void cvector_clone_with_prev_filter(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    CVECTOR_DATA_PREV_FILTER data_filter;

    if(NULL_PTR == filter)
    {
        data_filter = cvector_data_filter_default;
    }
    else
    {
        data_filter = filter;
    }

    cvector_codec_clone(cvector_src, cvector_des);

    CVECTOR_LOCK(cvector_src, LOC_CVECTOR_0008);
    /*not necessary to lock cvector_des here*/

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(condition, src_data))
            {
                des_data = src_data;
                cvector_push(cvector_des, des_data);
            }
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(condition, src_data))
            {
                des_data = cvector_data_malloc();
                cvector_data_clone(src_data, des_data);

                cvector_push(cvector_des, des_data);
            }
        }
    }
    CVECTOR_UNLOCK(cvector_src, LOC_CVECTOR_0009);
    return;
}

void cvector_clone_with_post_filter(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    CVECTOR_DATA_POST_FILTER data_filter;

    if(NULL_PTR == filter)
    {
        data_filter = cvector_data_filter_default;
    }
    else
    {
        data_filter = filter;
    }

    cvector_codec_clone(cvector_src, cvector_des);

    CVECTOR_LOCK(cvector_src, LOC_CVECTOR_0010);
    /*not necessary to lock cvector_des here*/

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(src_data, condition))
            {
                des_data = src_data;
                cvector_push(cvector_des, des_data);
            }
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(src_data, condition))
            {
                des_data = cvector_data_malloc();
                cvector_data_clone(src_data, des_data);

                cvector_push(cvector_des, des_data);
            }
        }
    }
    CVECTOR_UNLOCK(cvector_src, LOC_CVECTOR_0011);
    return;
}

EC_BOOL cvector_is_empty(const CVECTOR *cvector)
{
    return 0 == cvector->size? EC_TRUE : EC_FALSE;
}

EC_BOOL cvector_expand(CVECTOR *cvector)
{
    UINT32 pos;
    UINT32 capacity;
    void **data;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0012);
    if(0 == cvector->capacity)
    {
        capacity = 128; /*default*/
        data = (void **)SAFE_MALLOC(sizeof(void *) * capacity, LOC_CVECTOR_0013);
    }
    else
    {
        capacity = 2 * (cvector->capacity);/*double the old capacity*/
        data = (void **)SAFE_REALLOC(cvector->data, sizeof(void *) * (cvector->capacity), sizeof(void *) * capacity, LOC_CVECTOR_0014);
    }

    if(data)
    {
        cvector->data = data;
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        for(pos = cvector->capacity; pos < capacity; pos ++)
        {
            cvector->data[ pos ] = (void *)0;
        }

        cvector->capacity = capacity;

        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0015);
        return (EC_TRUE);
    }

    dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_expand: failed to expand cvector with capacity %ld and size %ld\n", cvector->capacity, cvector->size);

    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0016);
    return (EC_FALSE);
}

EC_BOOL cvector_cmp(const CVECTOR *cvector_1st, const CVECTOR *cvector_2nd, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    UINT32 num;
    CVECTOR_DATA_CMP data_cmp;

    num = cvector_size(cvector_1st);
    if(num != cvector_size(cvector_2nd))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = 0; pos < num; pos ++)
    {
        void *data_1st;
        void *data_2nd;

        data_1st = cvector_get(cvector_1st, pos);
        data_2nd = cvector_get(cvector_2nd, pos);

        if(EC_FALSE == data_cmp(data_1st, data_2nd))
        {
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

UINT32 cvector_add(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0017);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            cvector->data[ pos ] = (void *)data;
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0018);
            return (pos);
        }
    }

    if( pos < cvector->capacity )
    {
        cvector->data[ pos ] = (void *)data;
        cvector->size ++;

        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0019);
        return (pos);
    }

    pos = cvector_push_no_lock(cvector, data);
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0020);

    return (pos);
}

/* ensure data in cvector is in ascending order, return EC_TRUE if data_1 >= data_2, else EC_FALSE */
EC_BOOL cvector_asc_cmp_default(const void *data_1, const void *data_2)
{
    return (data_1 >= data_2) ? (EC_TRUE) : (EC_FALSE);
}

/* ensure data in cvector is in descending order, return EC_TRUE if data_1 <= data_2, else EC_FALSE */
EC_BOOL cvector_desc_cmp_default(const void *data_1, const void *data_2)
{
    return (data_1 <= data_2) ? (EC_TRUE) : (EC_FALSE);
}

UINT32 cvector_push_in_order(CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    EC_BOOL cmp_result;

    /*must not lock cvector here, otherwise, when enter if, cvector will fall in dead-lock*/
    if(cvector->size == cvector->capacity)
    {
        /*if failed to expand, return error code*/
        if(EC_FALSE == cvector_expand(cvector))
        {
            return CVECTOR_ERR_POS;
        }
    }

    if(NULL_PTR == cmp)
    {
        cmp = cvector_asc_cmp_default; /* default in increasing order */
    }
    CVECTOR_LOCK(cvector, LOC_CVECTOR_0021);
    pos = cvector->size;

    for( ; 0 < pos -- ; )
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            continue ;
        }

        cmp_result = cmp((void *)data, (void *)cvector->data[ pos ]);

        if(EC_TRUE == cmp_result) /* ok, find the correct position to push data */
        {
            break;
        }

        cvector->data[ pos + 1 ] = cvector->data[ pos ];
    }

    cvector->data[ ++ pos ] = (void *)data;
    cvector->size ++;

    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0022);
    return (pos);
}

UINT32 cvector_push_in_order_no_lock(CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    EC_BOOL cmp_result;

    /*must not lock cvector here, otherwise, when enter if, cvector will fall in dead-lock*/
    if(cvector->size == cvector->capacity)
    {
        /*if failed to expand, return error code*/
        if(EC_FALSE == cvector_expand(cvector))
        {
            return CVECTOR_ERR_POS;
        }
    }

    if(NULL_PTR == cmp)
    {
        cmp = cvector_asc_cmp_default; /* default in increasing order */
    }

    pos = cvector->size;

    for( ; 0 < pos -- ; )
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            continue ;
        }

        cmp_result = cmp((void *)data, (void *)cvector->data[ pos ]);

        if(EC_TRUE == cmp_result) /* ok, find the correct position to push data */
        {
            break;
        }

        cvector->data[ pos + 1 ] = cvector->data[ pos ];
    }

    cvector->data[ ++ pos ] = (void *)data;
    cvector->size ++;

    return (pos);
}

UINT32 cvector_push(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    /*must not lock cvector here, otherwise, when enter if, cvector will fall in dead-lock*/
    if( cvector->size == cvector->capacity )
    {
        /*if failed to expand, return error code*/
        if( EC_FALSE == cvector_expand(cvector) )
        {
            return CVECTOR_ERR_POS;
        }
    }

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0023);
    pos = cvector->size;

    cvector->data[ pos ] = (void *)data;
    cvector->size ++;

    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0024);
    return (pos);
}

void *cvector_pop(CVECTOR *cvector)
{
    void *data;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0025);
    if( 0 == cvector->size )
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0026);
        return (void *)0;
    }

    cvector->size --;
    data = cvector->data[ cvector->size ];
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0027);

    return (data);
}

void **cvector_get_addr(const CVECTOR *cvector, const UINT32 pos)
{
    void **addr;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0028);
    if(pos >= cvector->size)
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0029);
        return (void **)0;
    }

    addr = &(cvector->data[ pos ]);
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0030);
    return (addr);
}

void *cvector_get(const CVECTOR *cvector, const UINT32 pos)
{
    void *data;
    //dbg_log(SEC_0080_CVECTOR, 5)(LOGSTDOUT, "cvector_get: cvector %lx, size %ld, pos %ld\n", cvector, cvector->size, pos);
    CVECTOR_LOCK(cvector, LOC_CVECTOR_0031);
    if(pos >= cvector->size)
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0032);
        return (void *)0;
    }

    data = cvector->data[ pos ];
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0033);
    return (data);
}

/*return old data*/
void *cvector_set(CVECTOR *cvector, const UINT32 pos, const void *data)
{
    void *old_data;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0034);
    if(pos >= cvector->size)
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0035);
        return (void *)0;
    }

    old_data = cvector->data[ pos ];
    cvector->data[ pos ] = (void *)data;

    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0036);
    return old_data;
}

UINT32 cvector_capacity(const CVECTOR *cvector)
{
    return cvector->capacity;
}

UINT32 cvector_size(const CVECTOR *cvector)
{
    return cvector->size;
}

UINT32 cvector_type(const CVECTOR *cvector)
{
    return cvector->data_mm_type;
}

UINT32 cvector_type_set(CVECTOR *cvector, const UINT32 data_mm_type)
{
    cvector->data_mm_type = data_mm_type;
    return (0);
}


void cvector_codec_set(CVECTOR *cvector, const UINT32 data_mm_type)
{
    TYPE_CONV_ITEM *type_conv_item;

    //CVECTOR_LOCK(cvector, LOC_CVECTOR_0037);
    cvector->data_mm_type = data_mm_type;

    type_conv_item = dbg_query_type_conv_item_by_mm(data_mm_type);
    if(NULL_PTR != type_conv_item)
    {
        cvector->data_encoder      = (CVECTOR_DATA_ENCODER     )TYPE_CONV_ITEM_VAR_ENCODE_FUNC(type_conv_item);
        cvector->data_encoder_size = (CVECTOR_DATA_ENCODER_SIZE)TYPE_CONV_ITEM_VAR_ENCODE_SIZE(type_conv_item);
        cvector->data_decoder      = (CVECTOR_DATA_DECODER     )TYPE_CONV_ITEM_VAR_DECODE_FUNC(type_conv_item);
        cvector->data_init         = (CVECTOR_DATA_INIT        )TYPE_CONV_ITEM_VAR_INIT_FUNC(type_conv_item);
        cvector->data_clean        = (CVECTOR_DATA_CLEAN       )TYPE_CONV_ITEM_VAR_CLEAN_FUNC(type_conv_item);
        cvector->data_free         = (CVECTOR_DATA_FREE        )TYPE_CONV_ITEM_VAR_FREE_FUNC(type_conv_item);
    }
    else
    {
        cvector->data_encoder      = NULL_PTR;
        cvector->data_encoder_size = NULL_PTR;
        cvector->data_decoder      = NULL_PTR;
        cvector->data_init         = NULL_PTR;
        cvector->data_clean        = NULL_PTR;
        cvector->data_free         = NULL_PTR;
    }

    //CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0038);

    return;
}

void *cvector_codec_get(const CVECTOR *cvector, const UINT32 choice)
{
    switch(choice)
    {
        case CVECTOR_CODEC_ENCODER:
            return (void *)cvector->data_encoder;
        case CVECTOR_CODEC_ENCODER_SIZE:
            return (void *)cvector->data_encoder_size;
        case CVECTOR_CODEC_DECODER:
            return (void *)cvector->data_decoder;
        case CVECTOR_CODEC_INIT:
            return (void *)cvector->data_init;
        case CVECTOR_CODEC_CLEAN:
            return (void *)cvector->data_clean;
        case CVECTOR_CODEC_FREE:
            return (void *)cvector->data_free;
    }

    dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_codec_get: invalid choice %ld\n", choice);
    return (NULL_PTR);
}

void cvector_codec_clone(const CVECTOR *cvector_src, CVECTOR *cvector_des)
{
    /*NOTE: due to function pointer is different depending on processes or machine */
    /*      here ask current process to fetch them locally*/
    cvector_codec_set(cvector_des, cvector_src->data_mm_type);
/*
    cvector_des->data_mm_type      = cvector_src->data_mm_type     ;
    cvector_des->data_encoder      = cvector_src->data_encoder     ;
    cvector_des->data_encoder_size = cvector_src->data_encoder_size;
    cvector_des->data_decoder      = cvector_src->data_decoder     ;
    cvector_des->data_init         = cvector_src->data_init        ;
*/
    return;
}

void cvector_loop_front(const CVECTOR *cvector, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0039);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        handler(cvector->data[ pos ]);
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0040);
    return;
}

void cvector_loop_front_with_location(const CVECTOR *cvector, EC_BOOL (*handler)(void *, const UINT32), const UINT32 location)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0041);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        handler(cvector->data[ pos ], location);
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0042);
    return;
}

void cvector_loop_back(const CVECTOR *cvector, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0043);
    for(pos = cvector->size; pos -- > 0; )
    {
        handler(cvector->data[ pos ]);
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0044);
    return;
}

void cvector_loop_back_with_location(const CVECTOR *cvector, EC_BOOL (*handler)(void *, const UINT32), const UINT32 location)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0045);
    for(pos = cvector->size; pos -- > 0; )
    {
        handler(cvector->data[ pos ], location);
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0046);
    return;
}

UINT32 cvector_search_front(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CVECTOR_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0047);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == data_cmp(cvector->data[ pos ], data))
        {
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0048);
            return pos;
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0049);
    return CVECTOR_ERR_POS;
}

UINT32 cvector_search_back(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;

    CVECTOR_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0050);
    for(pos = cvector->size; pos -- > 0; )
    {
        if(EC_TRUE == data_cmp(cvector->data[ pos ], data))
        {
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0051);
            return pos;
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0052);
    return CVECTOR_ERR_POS;
}

/*binary search, refer glibc bsearch*/
/*cvector: data[0] > data[1] > ....*/
UINT32 cvector_bsearch(const CVECTOR *cvector, const void *data, int (*cmp)(const void *, const void *))
{
    UINT32  pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0050);
    pos = cvector_bsearch_no_lock(cvector, data, cmp);
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0052);

    return pos;
}

/*cvector: data[0] > data[1] > ....*/
UINT32 cvector_bsearch_no_lock(const CVECTOR *cvector, const void *data, int (*cmp)(const void *, const void *))
{
    UINT32 lo;
    UINT32 hi;
    UINT32 pos;
    int    ret;

    lo = 0;
    hi = (UINT32)cvector->size;

    while (lo < hi)
    {
        pos = (lo + hi) / 2;

        ret = cmp(cvector->data[ pos ], data);
        if(ret == 0)
        {
            return pos;
        }

        if(ret < 0)/*data < [pos]*/
        {
            lo = pos + 1;
        }
        else /*data > [pos]*/
        {
      	    hi = pos;
  	    }
    }

    return CVECTOR_ERR_POS;
}

EC_BOOL cvector_qsort(const CVECTOR *cvector, int (*cmp)(const void *, const void *))
{
    EC_BOOL     ret;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0050);
    /*result cvector: data[0] > data[1] > ....*/
    ret = cvector_qsort_no_lock(cvector, cmp);
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0050);

    return ret;
}

EC_BOOL cvector_qsort_no_lock(const CVECTOR *cvector, int (*cmp)(const void *, const void *))
{
    /*result cvector: data[0] > data[1] > ....*/
    qsort((void *)cvector->data, cvector->size, sizeof(void *), cmp);
    return (EC_TRUE);
}

UINT32 cvector_insert_front(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0053);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            cvector->data[ pos ] = (void *)data;
            cvector->size ++;
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0054);
            return (pos);
        }
    }
    pos = cvector_push_no_lock(cvector, data);
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0055);
    return (pos);
}

UINT32 cvector_insert_back(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0056);
    for(pos = cvector->size; pos -- > 0; )
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            cvector->data[ pos ] = (void *)data;
            cvector->size ++;
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0057);
            return (pos);
        }
    }
    pos = cvector_push_no_lock(cvector, data);
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0058);
    return (pos);
}

UINT32 cvector_insert_pos(CVECTOR *cvector, const UINT32 pos, const void *data)
{
    UINT32 idx;
    if( cvector->size == cvector->capacity )
    {
        /*if failed to expand, return error code*/
        if( EC_FALSE == cvector_expand(cvector) )
        {
            return CVECTOR_ERR_POS;
        }
    }

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0023);
    for(idx = cvector->size; idx > pos; idx --)
    {
        cvector->data[ idx ] = cvector->data[ idx - 1];
    }
    cvector->data[ idx ] = (void *)data;
    cvector->size ++;

    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0024);

    return (idx);
}

UINT32 cvector_insert_pos_no_lock(CVECTOR *cvector, const UINT32 pos, const void *data)
{
    UINT32 idx;
    if( cvector->size == cvector->capacity )
    {
        /*if failed to expand, return error code*/
        if( EC_FALSE == cvector_expand_no_lock(cvector) )
        {
            return CVECTOR_ERR_POS;
        }
    }

    for(idx = cvector->size; idx > pos; idx --)
    {
        cvector->data[ idx ] = cvector->data[ idx - 1];
    }
    cvector->data[ idx ] = (void *)data;
    cvector->size ++;

    return (idx);
}

EC_BOOL cvector_runthrough_front(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *))
{
    UINT32 pos;

    if(NULL_PTR == handle)
    {
        return (EC_FALSE);
    }

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0059);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_FALSE == handle(cvector->data[ pos ], pvoid))
        {
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0060);
            return (EC_FALSE);
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0061);
    return (EC_TRUE);
}

EC_BOOL cvector_runthrough_back(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *))
{
    UINT32 pos;

    if(NULL_PTR == handle)
    {
        return (EC_FALSE);
    }

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0062);
    for(pos = cvector->size; pos -- > 0; )
    {
        if(EC_TRUE == handle(cvector->data[ pos ], pvoid))
        {
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0063);
            return (EC_TRUE);
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0064);
    return (EC_TRUE);
}

EC_BOOL cvector_delete(CVECTOR *cvector, const void * data)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0065);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(data == cvector->data[ pos ])
        {
            break;
        }
    }

    if(pos >= cvector->size)
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0066);
        return (EC_FALSE);
    }

    for(; pos + 1 < cvector->size; pos ++)
    {
        cvector->data[ pos ] = cvector->data[ pos + 1 ];
    }

    cvector->data[ pos ] = NULL_PTR;
    cvector->size --;

    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0067);
    return (EC_TRUE);
}

EC_BOOL cvector_remove(CVECTOR *cvector, const void * data)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0068);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(data == cvector->data[ pos ])
        {
            cvector->data[ pos ] = NULL_PTR;
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0069);
    return (EC_TRUE);
}

/**
*   make cvector order as c0 < c1 < c2 < ... < ck
* where "<" is a kind of order
*   voter is the justment of the order:
* when ci < cj, voter(ci, cj) return EC_TRUE; otherwise, return EC_FALSE
* then, cvector_vote will return the lowest one in the order sequence: c0
*
**/
void *cvector_vote(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    void *best_data;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0070);
    if(EC_TRUE == cvector_is_empty(cvector))
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0071);
        return (void *)0;
    }

    for(best_data = cvector->data[ 0 ], pos = 1; pos < cvector->size; pos ++)
    {
        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], best_data))
        {
            best_data = cvector->data[ pos ];
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0072);
    return best_data;
}

UINT32 cvector_vote_pos(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    UINT32 best_data_pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0073);
    if(EC_TRUE == cvector_is_empty(cvector))
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0074);
        return (CVECTOR_ERR_POS);
    }

    for(best_data_pos = 0, pos = 1; pos < cvector->size; pos ++)
    {
        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], cvector->data[ best_data_pos ]))
        {
            best_data_pos = pos;
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0075);
    return (best_data_pos);
}


/**
*   make cvector order as c0 < c1 < c2 < ... < ck
* where "<" is a kind of order
*   voter is the justment of the order:
* when ci < cj, voter(ci, cj) return EC_TRUE; otherwise, return EC_FALSE
* then, cvector_vote will return the lowest one in the order sequence: c0
*
* filter will skip the ones which not meet ci < condition
*
**/
void *cvector_vote_with_prev_filter(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    void *best_data;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0076);

    best_data = NULL_PTR;
    if(EC_TRUE == cvector_is_empty(cvector))
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0077);
        return (void *)0;
    }

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == filter(condition, cvector->data[ pos ]))
        {
            best_data = cvector->data[ pos ];
            break;
        }
    }

    /*if not find any data satifying condition, then return nothing*/
    if(pos >=  cvector->size)
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0078);
        return (void *)0;
    }

    for(; pos < cvector->size; pos ++)
    {
        /*skip the ones which not meet the condition*/
        if(EC_FALSE == filter(condition, cvector->data[ pos ]))
        {
            continue;
        }

        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], best_data))
        {
            best_data = cvector->data[ pos ];
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0079);
    return (best_data);
}

void *cvector_vote_with_post_filter(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    void *best_data;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0080);

    best_data = NULL_PTR;
    if(EC_TRUE == cvector_is_empty(cvector))
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0081);
        return (void *)0;
    }

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == filter(cvector->data[ pos ], condition))
        {
            best_data = cvector->data[ pos ];
            break;
        }
    }

    /*if not find any data satifying condition, then return nothing*/
    if(pos >=  cvector->size)
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0082);
        return (void *)0;
    }

    for(; pos < cvector->size; pos ++)
    {
        /*skip the ones which not meet the condition*/
        if(EC_FALSE == filter(cvector->data[ pos ], condition))
        {
            continue;
        }

        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], best_data))
        {
            best_data = cvector->data[ pos ];
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0083);
    return (best_data);
}

void *cvector_erase(CVECTOR *cvector, const UINT32 pos)
{
    void *data;
    UINT32 cur;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0084);
    if(pos >= cvector->size)
    {
        CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0085);
        return (void *)0;
    }

    data = cvector->data[ pos ];
    for(cur = pos + 1; cur < cvector->size; cur ++)
    {
        cvector->data[ cur - 1 ] = cvector->data[ cur ];
    }

    cvector->size --;

    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0086);
    return data;
}

void cvector_clean(CVECTOR *cvector, EC_BOOL (*cleaner)(void *), const UINT32 location)
{
    /*seems it is quite NOT necessary to clean codec setting! but if set, we may be in greate trouble*/

    //dbg_log(SEC_0080_CVECTOR, 5)(LOGSTDOUT, "cvector_clean: cvector %lx, cleaner %lx, location %ld\n", cvector, cleaner, location);
    if( NULL_PTR != cleaner)
    {
        cvector_loop_front(cvector, cleaner);
    }

    CVECTOR_LOCK(cvector, location);

    if(NULL_PTR != cvector->data)
    {
        SAFE_FREE(cvector->data, location);
        cvector->data = (void **)0;
    }
    cvector->capacity = 0;
    cvector->size = 0;

    CVECTOR_UNLOCK(cvector, location);

    return;
}

/*merge cvector_src to cvector_des, cvector_src was not changed*/
void cvector_merge_with_clone(const CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    cvector_codec_clone(cvector_src, cvector_des);

    CVECTOR_LOCK(cvector_src, LOC_CVECTOR_0087);
    /*not necessary to lock cvector_des here*/

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(CVECTOR_ERR_POS == cvector_search_front(cvector_des, src_data, cvector_data_cmp))
            {
                des_data = src_data;
                cvector_push(cvector_des, des_data);
            }
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(CVECTOR_ERR_POS == cvector_search_front(cvector_des, src_data, cvector_data_cmp))
            {
                des_data = cvector_data_malloc();
                cvector_data_clone(src_data, des_data);
                cvector_push(cvector_des, des_data);
            }
        }
    }
    CVECTOR_UNLOCK(cvector_src, LOC_CVECTOR_0088);
    return;
}

/*merge cvector_src to cvector_des, cvector_src was changed*/
void cvector_merge_with_move(CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *))
{
    UINT32 pos;

    void *src_data;

    cvector_codec_clone(cvector_src, cvector_des);

    CVECTOR_LOCK(cvector_src, LOC_CVECTOR_0089);
    /*not necessary to lock cvector_des here*/

    for(pos = 0; pos < cvector_src->size; pos ++)
    {
        src_data = cvector_src->data[ pos ];
        if(CVECTOR_ERR_POS == cvector_search_front(cvector_des, src_data, cvector_data_cmp))
        {
            cvector_push(cvector_des, src_data);
            cvector_src->data[ pos ] = NULL_PTR;
        }
    }

    CVECTOR_UNLOCK(cvector_src, LOC_CVECTOR_0090);
    return;
}

void cvector_merge_direct(CVECTOR *cvector_src, CVECTOR *cvector_des)
{
    UINT32 pos;
    void *src_data;

    CVECTOR_LOCK(cvector_src, LOC_CVECTOR_0091);
    /*not necessary to lock cvector_des here*/

    for(pos = 0; pos < cvector_src->size; pos ++)
    {
        src_data = cvector_src->data[ pos ];
        if(NULL_PTR != src_data)
        {
            cvector_push(cvector_des, src_data);
            cvector_src->data[ pos ] = NULL_PTR;
        }
    }

    CVECTOR_UNLOCK(cvector_src, LOC_CVECTOR_0092);
    return;
}

UINT32 cvector_count(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    UINT32 count;

    CVECTOR_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0093);
    for(count = 0, pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == data_cmp(cvector->data[ pos ], data))
        {
            count ++;
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0094);
    return (count);
}

void cvector_print(LOG *log, const CVECTOR *cvector, void (*handler)(LOG *, const void *))
{
    UINT32 pos;

    sys_log(log, "cvector %lx, size %ld, capacity %ld\n", cvector, cvector->size, cvector->capacity);

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0095);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            sys_log( log, "cvector %lx No. %ld: (null)\n", cvector, pos);
            continue;
        }

        if(NULL_PTR == handler)
        {
            sys_log(log, "cvector %lx No. %ld: %lx\n", cvector, pos, cvector->data[ pos ]);
            continue;
        }

        sys_log(log, "cvector %lx No. %ld: ", cvector, pos);
        (handler)(log, cvector->data[ pos ]);
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0096);
    return;
}

void cvector_print_level(LOG *log, const CVECTOR *cvector, const UINT32 level, void (*print)(LOG *, const void *, const UINT32))
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0097);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        void *data;
        data = cvector->data[ pos ];

        if(NULL_PTR != print)
        {
            (print)( log, data, level );
        }
        else
        {
            sys_log(log, "No. %ld: ", pos ++);
            sys_print(log, " %lx\n", data);
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0098);
    return;
}

EC_BOOL cvector_check_all_is_true(const CVECTOR *cvector)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0099);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        UINT32 *data;
        data = (UINT32 *)(cvector->data[ pos ]);
        if(EC_FALSE == (*data))
        {
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0100);
            return (EC_FALSE);
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0101);
    return (EC_TRUE);
}

EC_BOOL cvector_check_one_is_true(const CVECTOR *cvector)
{
    UINT32 pos;

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0102);
    for(pos = 0; pos < cvector->size; pos ++)
    {
        UINT32 *data;
        data = (UINT32 *)(cvector->data[ pos ]);
        if(EC_TRUE == (*data))
        {
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0103);
            return (EC_TRUE);
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0104);
    return (EC_FALSE);
}

/*handler_func_addr format: void *func(xx,cvector data,yy, zz)*/
/*cvector_data_pos range from 0 to func_para_num - 1*/
EC_BOOL cvector_loop(CVECTOR *cvector,
                         void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                         const UINT32 func_para_num, const UINT32 cvector_data_pos,
                         const UINT32 handler_func_addr,...)
{
    UINT32 func_para_value[ MAX_NUM_OF_FUNC_PARAS ];
    UINT32 index;
    UINT32 size;
    UINT32 pos;

    va_list ap;

    if(0 == handler_func_addr)
    {
        return (EC_TRUE);
    }

    if(0 == func_para_num)
    {
        dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: func_para_num must be larger than 1\n");
        return (EC_FALSE);
    }

    if(MAX_NUM_OF_FUNC_PARAS < func_para_num)
    {
        dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: func_para_num %ld overflow which must be smaller than %ld\n",
                           func_para_num, (UINT32)MAX_NUM_OF_FUNC_PARAS);
        return (EC_FALSE);
    }

    if(cvector_data_pos >= func_para_num)
    {
        dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: invalid setting where cvector_data_pos %ld >= func_para_num %ld\n",
                           cvector_data_pos, func_para_num);
        return (EC_FALSE);
    }

    va_start(ap, handler_func_addr);
    for( index = 0; index < func_para_num; index ++ )
    {
        func_para_value[ index ] = va_arg(ap, UINT32);
    }
    va_end(ap);

    CVECTOR_LOCK(cvector, LOC_CVECTOR_0105);
    size = cvector_size(cvector);
    for(pos = 0; pos < size; pos ++)
    {
        void *data;
        data = cvector_get_no_lock(cvector, pos);

        func_para_value[ cvector_data_pos ] = (UINT32)data;

        if(EC_FALSE == dbg_caller(handler_func_addr, func_para_num, func_para_value, (UINT32 *)handler_retval_addr))
        {
            dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: dbg_caller failed\n");
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0106);
            return (EC_FALSE);
        }

        if(NULL_PTR != handler_retval_checker
        && NULL_PTR != handler_retval_addr
        && EC_FALSE == handler_retval_checker(handler_retval_addr))
        {
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0107);
            return (EC_FALSE);
        }
    }
    CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0108);

    return ( EC_TRUE );
}

/*---------------------------------------------------------- no lock interface ----------------------------------------------------------*/
void cvector_free_no_lock(CVECTOR *cvector, const UINT32 location)
{
    if(cvector->data)
    {
        SAFE_FREE(cvector->data, location);
        cvector->data = (void **)0;
        cvector->capacity = 0;
        cvector->size = 0;
    }
    CVECTOR_CLEAN_LOCK(cvector, LOC_CVECTOR_0109);
    SAFE_FREE(cvector, location);
}
/*note: clone cvector_src to the tail of cvector_des*/
void cvector_clone_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    cvector_codec_clone(cvector_src, cvector_des);

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            des_data = src_data;
            cvector_push_no_lock(cvector_des, des_data);
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            des_data = cvector_data_malloc();
            cvector_data_clone(src_data, des_data);

            cvector_push_no_lock(cvector_des, des_data);
        }
    }
    return;
}

void cvector_clone_with_prev_filter_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    CVECTOR_DATA_PREV_FILTER data_filter;

    if(NULL_PTR == filter)
    {
        data_filter = cvector_data_filter_default;
    }
    else
    {
        data_filter = filter;
    }

    cvector_codec_clone(cvector_src, cvector_des);

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(condition, src_data))
            {
                des_data = src_data;
                cvector_push_no_lock(cvector_des, des_data);
            }
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(condition, src_data))
            {
                des_data = cvector_data_malloc();
                cvector_data_clone(src_data, des_data);

                cvector_push_no_lock(cvector_des, des_data);
            }
        }
    }
    return;
}

void cvector_clone_with_post_filter_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, const void *condition, EC_BOOL (*filter)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    CVECTOR_DATA_POST_FILTER data_filter;

    if(NULL_PTR == filter)
    {
        data_filter = cvector_data_filter_default;
    }
    else
    {
        data_filter = filter;
    }

    cvector_codec_clone(cvector_src, cvector_des);

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(src_data, condition))
            {
                des_data = src_data;
                cvector_push_no_lock(cvector_des, des_data);
            }
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            if(EC_TRUE == data_filter(src_data, condition))
            {
                des_data = cvector_data_malloc();
                cvector_data_clone(src_data, des_data);

                cvector_push_no_lock(cvector_des, des_data);
            }
        }
    }

    return;
}

EC_BOOL cvector_expand_no_lock(CVECTOR *cvector)
{
    UINT32 pos;
    UINT32 capacity;
    void **data;

    if(0 == cvector->capacity)
    {
        capacity = 128; /*default*/
        data = (void **)SAFE_MALLOC(sizeof(void *) * capacity, LOC_CVECTOR_0110);
    }
    else
    {
        capacity = 2 * (cvector->capacity);/*double the old capacity*/
        data = (void **)SAFE_REALLOC(cvector->data, sizeof(void *) * (cvector->capacity), sizeof(void *) * capacity, LOC_CVECTOR_0111);
    }

    if(data)
    {
        cvector->data = data;
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        for(pos = cvector->capacity; pos < capacity; pos ++)
        {
            cvector->data[ pos ] = (void *)0;
        }

        cvector->capacity = capacity;

        return (EC_TRUE);
    }

    dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_expand_no_lock: failed to expand cvector with capacity %ld and size %ld\n", cvector->capacity, cvector->size);

    return (EC_FALSE);
}

EC_BOOL cvector_cmp_no_lock(const CVECTOR *cvector_1st, const CVECTOR *cvector_2nd, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    UINT32 num;
    CVECTOR_DATA_CMP data_cmp;

    num = cvector_size(cvector_1st);
    if(num != cvector_size(cvector_2nd))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = 0; pos < num; pos ++)
    {
        void *data_1st;
        void *data_2nd;

        data_1st = cvector_get_no_lock(cvector_1st, pos);
        data_2nd = cvector_get_no_lock(cvector_2nd, pos);

        if(EC_FALSE == data_cmp(data_1st, data_2nd))
        {
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

UINT32 cvector_add_no_lock(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            cvector->data[ pos ] = (void *)data;
            return (pos);
        }
    }

    if( pos < cvector->capacity )
    {
        cvector->data[ pos ] = (void *)data;
        cvector->size ++;

        return (pos);
    }

    pos = cvector_push_no_lock(cvector, data);

    return (pos);
}

UINT32 cvector_push_no_lock(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    /*must not lock cvector here, otherwise, when enter if, cvector will fall in dead-lock*/
    if( cvector->size == cvector->capacity )
    {
        /*if failed to expand, return error code*/
        if( EC_FALSE == cvector_expand_no_lock(cvector) )
        {
            return CVECTOR_ERR_POS;
        }
    }

    pos = cvector->size;

    cvector->data[ pos ] = (void *)data;
    cvector->size ++;

    return (pos);
}

void *cvector_pop_no_lock(CVECTOR *cvector)
{
    void *data;

    if( 0 == cvector->size )
    {
        return (void *)0;
    }

    cvector->size --;
    data = cvector->data[ cvector->size ];

    return (data);
}

void **cvector_get_addr_no_lock(const CVECTOR *cvector, const UINT32 pos)
{
    void **addr;

    if(pos >= cvector->size)
    {
        return (void **)0;
    }

    addr = &(cvector->data[ pos ]);
    return (addr);
}

void *cvector_get_no_lock(const CVECTOR *cvector, const UINT32 pos)
{
    void *data;

    if(pos >= cvector->size)
    {
        return (void *)0;
    }

    data = cvector->data[ pos ];
    return (data);
}

/*return old data*/
void *cvector_set_no_lock(CVECTOR *cvector, const UINT32 pos, const void *data)
{
    void *old_data;

    if(pos >= cvector->size)
    {
        return (void *)0;
    }

    old_data = cvector->data[ pos ];
    cvector->data[ pos ] = (void *)data;

    return old_data;
}

void cvector_loop_front_no_lock(const CVECTOR *cvector, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        handler(cvector->data[ pos ]);
    }
    return;
}

void cvector_loop_back_no_lock(const CVECTOR *cvector, EC_BOOL (*handler)(void *))
{
    UINT32 pos;

    for(pos = cvector->size; pos -- > 0; )
    {
        handler(cvector->data[ pos ]);
    }
    return;
}

UINT32 cvector_search_front_no_lock(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    CVECTOR_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == data_cmp(cvector->data[ pos ], data))
        {
            return pos;
        }
    }
    return CVECTOR_ERR_POS;
}

UINT32 cvector_search_back_no_lock(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;

    CVECTOR_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(pos = cvector->size; pos -- > 0; )
    {
        if(EC_TRUE == data_cmp(cvector->data[ pos ], data))
        {
            return pos;
        }
    }
    return CVECTOR_ERR_POS;
}

UINT32 cvector_insert_front_no_lock(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            cvector->data[ pos ] = (void *)data;
            cvector->size ++;
            return (pos);
        }
    }
    pos = cvector_push_no_lock(cvector, data);
    return (pos);
}

UINT32 cvector_insert_back_no_lock(CVECTOR *cvector, const void *data)
{
    UINT32 pos;

    for(pos = cvector->size; pos -- > 0; )
    {
        if(NULL_PTR == cvector->data[ pos ])
        {
            cvector->data[ pos ] = (void *)data;
            cvector->size ++;
            return (pos);
        }
    }
    pos = cvector_push_no_lock(cvector, data);
    return (pos);
}

EC_BOOL cvector_runthrough_front_no_lock(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *))
{
    UINT32 pos;

    if(NULL_PTR == handle)
    {
        return (EC_FALSE);
    }

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_FALSE == handle(cvector->data[ pos ], pvoid))
        {
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cvector_runthrough_back_no_lock(const CVECTOR *cvector, const void *pvoid, EC_BOOL (*handle)(const void *, const void *))
{
    UINT32 pos;

    if(NULL_PTR == handle)
    {
        return (EC_FALSE);
    }

    for(pos = cvector->size; pos -- > 0; )
    {
        if(EC_TRUE == handle(cvector->data[ pos ], pvoid))
        {
            return (EC_TRUE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cvector_delete_no_lock(CVECTOR *cvector, const void * data)
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(data == cvector->data[ pos ])
        {
            break;
        }
    }

    if(pos >= cvector->size)
    {
        return (EC_FALSE);
    }

    for(; pos + 1 < cvector->size; pos ++)
    {
        cvector->data[ pos ] = cvector->data[ pos + 1 ];
    }

    cvector->data[ pos ] = NULL_PTR;
    cvector->size --;

    return (EC_TRUE);
}

EC_BOOL cvector_remove_no_lock(CVECTOR *cvector, const void * data)
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(data == cvector->data[ pos ])
        {
            cvector->data[ pos ] = NULL_PTR;
        }
    }

    return (EC_TRUE);
}

/**
*   make cvector order as c0 < c1 < c2 < ... < ck
* where "<" is a kind of order
*   voter is the justment of the order:
* when ci < cj, voter(ci, cj) return EC_TRUE; otherwise, return EC_FALSE
* then, cvector_vote_no_lock will return the lowest one in the order sequence: c0
*
**/
void *cvector_vote_no_lock(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    void *best_data;

    if(EC_TRUE == cvector_is_empty(cvector))
    {
        return (void *)0;
    }

    for(best_data = cvector->data[ 0 ], pos = 1; pos < cvector->size; pos ++)
    {
        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], best_data))
        {
            best_data = cvector->data[ pos ];
        }
    }
    return best_data;
}

UINT32 cvector_vote_pos_no_lock(const CVECTOR *cvector, EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    UINT32 best_data_pos;

    if(EC_TRUE == cvector_is_empty(cvector))
    {
        return (CVECTOR_ERR_POS);
    }

    for(best_data_pos = 0, pos = 1; pos < cvector->size; pos ++)
    {
        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], cvector->data[ best_data_pos ]))
        {
            best_data_pos = pos;
        }
    }
    return (best_data_pos);
}

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
void *cvector_vote_with_prev_filter_no_lock(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    void *best_data;


    best_data = NULL_PTR;
    if(EC_TRUE == cvector_is_empty(cvector))
    {
        return (void *)0;
    }

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == filter(condition, cvector->data[ pos ]))
        {
            best_data = cvector->data[ pos ];
            break;
        }
    }

    /*if not find any data satifying condition, then return nothing*/
    if(pos >=  cvector->size)
    {
        return (void *)0;
    }

    for(; pos < cvector->size; pos ++)
    {
        /*skip the ones which not meet the condition*/
        if(EC_FALSE == filter(condition, cvector->data[ pos ]))
        {
            continue;
        }

        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], best_data))
        {
            best_data = cvector->data[ pos ];
        }
    }
    return (best_data);
}

void *cvector_vote_with_post_filter_no_lock(const CVECTOR *cvector, const void *condition, EC_BOOL (*filter)(const void *, const void *), EC_BOOL (*voter)(const void *, const void *))
{
    UINT32 pos;

    void *best_data;


    best_data = NULL_PTR;
    if(EC_TRUE == cvector_is_empty(cvector))
    {
        return (void *)0;
    }

    for(pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == filter(cvector->data[ pos ], condition))
        {
            best_data = cvector->data[ pos ];
            break;
        }
    }

    /*if not find any data satifying condition, then return nothing*/
    if(pos >=  cvector->size)
    {
        return (void *)0;
    }

    for(; pos < cvector->size; pos ++)
    {
        /*skip the ones which not meet the condition*/
        if(EC_FALSE == filter(cvector->data[ pos ], condition))
        {
            continue;
        }

        /*when cur is better than the best, set best = cur*/
        if(EC_TRUE == voter(cvector->data[ pos ], best_data))
        {
            best_data = cvector->data[ pos ];
        }
    }
    return (best_data);
}

void *cvector_erase_no_lock(CVECTOR *cvector, const UINT32 pos)
{
    void *data;
    UINT32 cur;

    if(pos >= cvector->size)
    {
        return (void *)0;
    }

    data = cvector->data[ pos ];
    for(cur = pos + 1; cur < cvector->size; cur ++)
    {
        cvector->data[ cur - 1 ] = cvector->data[ cur ];
    }

    cvector->size --;

    return data;
}

void cvector_clean_no_lock(CVECTOR *cvector, EC_BOOL (*cleaner)(void *), const UINT32 location)
{
    /*seems it is quite NOT necessary to clean codec setting! but if set, we may be in greate trouble*/

    //dbg_log(SEC_0080_CVECTOR, 5)(LOGSTDOUT, "cvector_clean_no_lock: cvector %lx, cleaner %lx, location %ld\n", cvector, cleaner, location);
    if( NULL_PTR != cleaner)
    {
        cvector_loop_front_no_lock(cvector, cleaner);
    }

    if(NULL_PTR != cvector->data)
    {
        SAFE_FREE(cvector->data, location);
        cvector->data = (void **)0;
    }
    cvector->capacity = 0;
    cvector->size = 0;

    return;
}


/*merge cvector_src to cvector_des, cvector_src was not changed*/
void cvector_merge_with_clone_no_lock(const CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *), void *(*cvector_data_malloc)(), void (*cvector_data_clone)(const void *, void *))
{
    UINT32 pos;

    void *src_data;
    void *des_data;

    cvector_codec_clone(cvector_src, cvector_des);

    /*not necessary to lock cvector_des here*/

    if(NULL_PTR == cvector_data_malloc || NULL_PTR == cvector_data_clone)
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            /*merge when src_data not appear in cvector_des*/
            if(CVECTOR_ERR_POS == cvector_search_front_no_lock(cvector_des, src_data, cvector_data_cmp))
            {
                des_data = src_data;
                cvector_push_no_lock(cvector_des, des_data);
            }
        }
    }
    else
    {
        for(pos = 0; pos < cvector_src->size; pos ++)
        {
            src_data = cvector_src->data[ pos ];
            /*merge when src_data not appear in cvector_des*/
            if(CVECTOR_ERR_POS == cvector_search_front_no_lock(cvector_des, src_data, cvector_data_cmp))
            {
                des_data = cvector_data_malloc();
                cvector_data_clone(src_data, des_data);
                cvector_push_no_lock(cvector_des, des_data);
            }
        }
    }
    return;
}

/*merge cvector_src to cvector_des, cvector_src was changed*/
void cvector_merge_with_move_no_lock(CVECTOR *cvector_src, CVECTOR *cvector_des, EC_BOOL (*cvector_data_cmp)(const void *, const void *))
{
    UINT32 pos;

    void *src_data;

    cvector_codec_clone(cvector_src, cvector_des);

    /*not necessary to lock cvector_des here*/

    for(pos = 0; pos < cvector_src->size; pos ++)
    {
        src_data = cvector_src->data[ pos ];
        if(CVECTOR_ERR_POS == cvector_search_front_no_lock(cvector_des, src_data, cvector_data_cmp))
        {
            cvector_push_no_lock(cvector_des, src_data);
            cvector_src->data[ pos ] = NULL_PTR;
        }
    }

    return;
}

void cvector_merge_direct_no_lock(CVECTOR *cvector_src, CVECTOR *cvector_des)
{
    UINT32 pos;
    void *src_data;

    for(pos = 0; pos < cvector_src->size; pos ++)
    {
        src_data = cvector_src->data[ pos ];
        if(NULL_PTR != src_data)
        {
            cvector_push(cvector_des, src_data);
            cvector_src->data[ pos ] = NULL_PTR;
        }
    }

    return;
}

UINT32 cvector_count_no_lock(const CVECTOR *cvector, const void *data, EC_BOOL (*cmp)(const void *, const void *))
{
    UINT32 pos;
    UINT32 count;

    CVECTOR_DATA_CMP data_cmp;

    if(NULL_PTR == cmp)
    {
        data_cmp = cvector_data_cmp_default;
    }
    else
    {
        data_cmp = cmp;
    }

    for(count = 0, pos = 0; pos < cvector->size; pos ++)
    {
        if(EC_TRUE == data_cmp(cvector->data[ pos ], data))
        {
            count ++;
        }
    }
    return (count);
}


void cvector_print_no_lock(LOG *log, const CVECTOR *cvector, void (*handler)(LOG *, const void *))
{
    UINT32 pos;

    sys_log(log, "cvector %lx, size %ld, capacity %ld\n", cvector, cvector->size, cvector->capacity);

    for(pos = 0; pos < cvector->size; pos ++)
    {
        sys_log( log, "No. %ld: ", pos);
        if(0 != handler)
        {
            (handler)(log, cvector->data[ pos ]);
        }
        else
        {
            sys_print(log, " %lx\n", cvector->data[ pos ]);
        }
    }
    return;
}

void cvector_print_level_no_lock(LOG *log, const CVECTOR *cvector, const UINT32 level, void (*print)(LOG *, const void *, const UINT32))
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        void *data;
        data = cvector->data[ pos ];

        if(NULL_PTR != print)
        {
            (print)( log, data, level );
        }
        else
        {
            sys_log(log, "No. %ld: ", pos ++);
            sys_print(log, " %lx\n", data);
        }
    }
    return;
}

EC_BOOL cvector_check_all_is_true_no_lock(const CVECTOR *cvector)
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        UINT32 *data;
        data = (UINT32 *)(cvector->data[ pos ]);
        if(EC_FALSE == (*data))
        {
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cvector_check_one_is_true_no_lock(const CVECTOR *cvector)
{
    UINT32 pos;

    for(pos = 0; pos < cvector->size; pos ++)
    {
        UINT32 *data;
        data = (UINT32 *)(cvector->data[ pos ]);
        if(EC_TRUE == (*data))
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

/*handler_func_addr format: void *func(xx,cvector data,yy, zz)*/
/*cvector_data_pos range from 0 to func_para_num - 1*/
EC_BOOL cvector_loop_no_lock(CVECTOR *cvector,
                                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                                     const UINT32 func_para_num, const UINT32 cvector_data_pos,
                                     const UINT32 handler_func_addr,...)
{
    UINT32 func_para_value[ MAX_NUM_OF_FUNC_PARAS ];
    UINT32 index;
    UINT32 size;
    UINT32 pos;

    va_list ap;

    if(0 == handler_func_addr)
    {
        return (EC_TRUE);
    }

    if(0 == func_para_num)
    {
        dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: func_para_num must be larger than 1\n");
        return (EC_FALSE);
    }

    if(MAX_NUM_OF_FUNC_PARAS < func_para_num)
    {
        dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: func_para_num %ld overflow which must be smaller than %ld\n",
                           func_para_num, (UINT32)MAX_NUM_OF_FUNC_PARAS);
        return (EC_FALSE);
    }

    if(cvector_data_pos >= func_para_num)
    {
        dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: invalid setting where cvector_data_pos %ld >= func_para_num %ld\n",
                           cvector_data_pos, func_para_num);
        return (EC_FALSE);
    }

    va_start(ap, handler_func_addr);
    for( index = 0; index < func_para_num; index ++ )
    {
        func_para_value[ index ] = va_arg(ap, UINT32);
    }
    va_end(ap);

    size = cvector_size(cvector);
    for(pos = 0; pos < size; pos ++)
    {
        void *data;
        data = cvector_get_no_lock(cvector, pos);

        func_para_value[ cvector_data_pos ] = (UINT32)data;

        if(EC_FALSE == dbg_caller(handler_func_addr, func_para_num, func_para_value, (UINT32 *)handler_retval_addr))
        {
            dbg_log(SEC_0080_CVECTOR, 0)(LOGSTDOUT, "error:cvector_loop: dbg_caller failed\n");
            CVECTOR_UNLOCK(cvector, LOC_CVECTOR_0112);
            return (EC_FALSE);
        }

        if(NULL_PTR != handler_retval_checker
        && NULL_PTR != handler_retval_addr
        && EC_FALSE == handler_retval_checker(handler_retval_addr))
        {
            return (EC_FALSE);
        }
    }

    return ( EC_TRUE );
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
