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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"
#include "cbuffer.h"
#include "chunk.h"
#include "cmpic.inc"

CHUNK *chunk_new(const uint32_t size)
{
    CHUNK *chunk;

    alloc_static_mem(MM_CHUNK, &chunk, LOC_CHUNK_0001);
    ASSERT(NULL_PTR != chunk);

    chunk_init(chunk, size);
    return(chunk);
}

EC_BOOL chunk_init(CHUNK *chunk, const uint32_t size)
{
    cbuffer_init(CHUNK_BUFFER(chunk), size);
    CHUNK_OFFSET(chunk) = 0;

    return (EC_TRUE);
}

EC_BOOL chunk_clean(CHUNK *chunk)
{
    cbuffer_clean(CHUNK_BUFFER(chunk));
    CHUNK_OFFSET(chunk) = 0;
    return (EC_TRUE);
}

EC_BOOL chunk_free(CHUNK *chunk)
{
    if (NULL_PTR != chunk)
    {
        chunk_clean(chunk);
        free_static_mem(MM_CHUNK, chunk, LOC_CHUNK_0002);

        dbg_log(SEC_0099_CHUNK, 9)(LOGSTDOUT, "[DEBUG] chunk_free: free chunk %p\n", chunk);
    }

    return (EC_TRUE);
}

EC_BOOL chunk_is_empty(const CHUNK *chunk)
{
    return cbuffer_is_empty(CHUNK_BUFFER(chunk));
}

EC_BOOL chunk_set(CHUNK *chunk, const uint8_t *data, const uint32_t len)
{
    cbuffer_set(CHUNK_BUFFER(chunk), data, len);
    CHUNK_OFFSET(chunk) = 0;

    return (EC_TRUE);
}

EC_BOOL chunk_reset(CHUNK *chunk)
{
    if (NULL_PTR != chunk)
    {
        cbuffer_reset(CHUNK_BUFFER(chunk));
    }

    CHUNK_OFFSET(chunk) = 0;
    return (EC_TRUE);
}

EC_BOOL chunk_mount(CHUNK *chunk, const uint8_t *data, const uint32_t len)
{
    cbuffer_mount(CHUNK_BUFFER(chunk), data, len);
    CHUNK_OFFSET(chunk) = 0;

    return (EC_TRUE);
}

EC_BOOL chunk_umount(CHUNK *chunk, uint8_t **data, uint32_t *len)
{
    /*data [0, offset) already used, clean them*/
    if(0 < CHUNK_OFFSET(chunk))
    {
        cbuffer_left_shift_out(CHUNK_BUFFER(chunk), NULL_PTR, CHUNK_OFFSET(chunk));
        CHUNK_OFFSET(chunk) = 0;
    }

    cbuffer_umount(CHUNK_BUFFER(chunk), data, len);
    return (EC_TRUE);
}

uint32_t chunk_size(const CHUNK *chunk)
{
    return cbuffer_size(CHUNK_BUFFER(chunk));
}

uint32_t chunk_used(const CHUNK *chunk)
{
    return cbuffer_used(CHUNK_BUFFER(chunk));
}

uint32_t chunk_room(const CHUNK *chunk)
{
    return cbuffer_room(CHUNK_BUFFER(chunk));
}

uint32_t chunk_append(CHUNK *chunk, const uint8_t *data, const uint32_t size)
{
    return cbuffer_append(CHUNK_BUFFER(chunk), data, size);
}

uint32_t chunk_append_format(CHUNK *chunk, const char *format, ...)
{
    va_list ap;
    UINT32 len;

    va_list params;

    va_start(ap, format);
    va_copy(params, ap);

    len = cbuffer_append_vformat(CHUNK_BUFFER(chunk), format, params);

    va_end(ap);

    return (len);
}

uint32_t chunk_append_vformat(CHUNK *chunk, const char *format, va_list ap)
{
    return cbuffer_append_vformat(CHUNK_BUFFER(chunk), format, ap);
}

uint32_t chunk_export(CHUNK *chunk, uint8_t *data, const uint32_t max_size)
{
    return cbuffer_export(CHUNK_BUFFER(chunk), data, max_size);
}

uint32_t chunk_shift(CHUNK *chunk, uint8_t *data, const uint32_t max_size)
{
    uint32_t used;
    uint32_t shift_size;

    used = CBUFFER_USED(CHUNK_BUFFER(chunk));
    shift_size  = DMIN(used, max_size);

    cbuffer_left_shift_out(CHUNK_BUFFER(chunk), data, shift_size);
    return (shift_size);
}

void chunk_print_chars(LOG *log, const CHUNK *chunk)
{
    cbuffer_print_chars(log, CHUNK_BUFFER(chunk));
    //sys_log(log, "chunk_print_str: offset: %lld\n", CHUNK_OFFSET(chunk));
    return;
}

void chunk_print_str(LOG *log, const CHUNK *chunk)
{
    cbuffer_print_str(log, CHUNK_BUFFER(chunk));
    //sys_log(log, "chunk_print_str: offset: %lld\n", CHUNK_OFFSET(chunk));
    return;
}

void chunk_print_info(LOG *log, const CHUNK *chunk)
{
    cbuffer_print_info(log, CHUNK_BUFFER(chunk));
    return;
}

CHUNK_MGR *chunk_mgr_new(void)
{
    CHUNK_MGR *chunk_mgr;

    alloc_static_mem(MM_CHUNK_MGR, &chunk_mgr, LOC_CHUNK_0003);
    ASSERT(NULL_PTR != chunk_mgr);

    chunk_mgr_init(chunk_mgr);
    return (chunk_mgr);
}

EC_BOOL chunk_mgr_init(CHUNK_MGR *chunk_mgr)
{
    clist_init(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), MM_CHUNK, LOC_CHUNK_0004);

    CHUNCK_MGR_NBYTES_IN(chunk_mgr)  = 0;
    CHUNCK_MGR_NBYTES_OUT(chunk_mgr) = 0;

    return (EC_TRUE);
}

EC_BOOL chunk_mgr_clean(CHUNK_MGR *chunk_mgr)
{
    dbg_log(SEC_0099_CHUNK, 9)(LOGSTDOUT, "[DEBUG] chunk_mgr_clean: chunk_mgr %p free chunks\n", chunk_mgr);

    clist_clean(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), (CLIST_DATA_DATA_CLEANER)chunk_free);

    CHUNCK_MGR_NBYTES_IN(chunk_mgr)  = 0;
    CHUNCK_MGR_NBYTES_OUT(chunk_mgr) = 0;

    return (EC_TRUE);
}

EC_BOOL chunk_mgr_free(CHUNK_MGR *chunk_mgr)
{
    if (NULL_PTR != chunk_mgr)
    {
        chunk_mgr_clean(chunk_mgr);
        free_static_mem(MM_CHUNK_MGR, chunk_mgr, LOC_CHUNK_0005);
    }

    return (EC_TRUE);
}

uint64_t chunk_mgr_total_length(const CHUNK_MGR *chunk_mgr)
{
    uint64_t len;
    CLIST_DATA *clist_data;

    len = 0;

    CLIST_LOOP_NEXT(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), clist_data)
    {
        CHUNK   *chunk;

        chunk = (CHUNK *)CLIST_DATA_DATA(clist_data);

        len += CBUFFER_USED(CHUNK_BUFFER(chunk));
    }

    return (len);
}

/*left to send length*/
uint64_t chunk_mgr_send_length(const CHUNK_MGR *chunk_mgr)
{
    uint64_t len;
    CLIST_DATA *clist_data;

    len = 0;

    CLIST_LOOP_NEXT(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), clist_data)
    {
        CHUNK   *chunk;

        chunk = (CHUNK *)CLIST_DATA_DATA(clist_data);

        ASSERT(CHUNK_OFFSET(chunk) <= CHUNK_USED(chunk));

        len += (CHUNK_USED(chunk) - CHUNK_OFFSET(chunk));
    }

    return (len);
}

EC_BOOL chunk_mgr_is_empty(const CHUNK_MGR *chunk_mgr)
{
    return clist_is_empty(CHUNCK_MGR_CHUNK_LIST(chunk_mgr));
}

UINT32 chunk_mgr_count_chunks(const CHUNK_MGR *chunk_mgr)
{
    return clist_size(CHUNCK_MGR_CHUNK_LIST(chunk_mgr));
}

CHUNK *chunk_mgr_last_chunk(const CHUNK_MGR *chunk_mgr)
{
    return (CHUNK *)clist_back(CHUNCK_MGR_CHUNK_LIST(chunk_mgr));
}

CHUNK *chunk_mgr_first_chunk(const CHUNK_MGR *chunk_mgr)
{
    return (CHUNK *)clist_front(CHUNCK_MGR_CHUNK_LIST(chunk_mgr));
}

CHUNK *chunk_mgr_pop_first_chunk(CHUNK_MGR *chunk_mgr)
{
    return (CHUNK *)clist_pop_front(CHUNCK_MGR_CHUNK_LIST(chunk_mgr));
}

EC_BOOL chunk_mgr_add_chunk(CHUNK_MGR *chunk_mgr, const CHUNK *chunk)
{
    dbg_log(SEC_0099_CHUNK, 9)(LOGSTDOUT, "[DEBUG] chunk_mgr_add_chunk: chunk_mgr %p add chunk %p\n",
                       chunk_mgr, chunk);

    clist_push_back(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), (void *)chunk);
    return (EC_TRUE);
}

EC_BOOL chunk_mgr_append_data(CHUNK_MGR *chunk_mgr, const uint8_t *data, const uint32_t size)
{
    uint32_t tsize;/*left size*/
    const uint8_t *src_data;

    src_data = data;
    for(tsize = size; 0 < tsize;)
    {
        CHUNK   *chunk;
        uint32_t burn_len;

        chunk = chunk_mgr_last_chunk(chunk_mgr);
        if(NULL_PTR == chunk || 0 == chunk_room(chunk))
        {
            uint32_t csize;
            if(tsize <= CHUNK_DEFAULT_SIZE)
            {
                csize = CHUNK_DEFAULT_SIZE;
            }
            else if(tsize <= CHUNK_SUGGEST_SIZE)
            {
                csize = CHUNK_SUGGEST_SIZE;
            }
            else
            {
                csize = CHUNK_MAX_SIZE;
            }

            chunk = chunk_new(csize);
            if(NULL_PTR == chunk)
            {
                dbg_log(SEC_0099_CHUNK, 0)(LOGSTDOUT, "error:chunk_mgr_append_data: new chunk with size %d failed\n", csize);
                return (EC_FALSE);
            }
            dbg_log(SEC_0099_CHUNK, 9)(LOGSTDOUT, "[DEBUG] chunk_mgr_append_data: new chunk with size %d done\n", csize);

            chunk_mgr_add_chunk(chunk_mgr, chunk);
        }

        burn_len = chunk_append(chunk, src_data, tsize);
        src_data += burn_len;
        tsize    -= burn_len;
    }

    return (EC_TRUE);
}

EC_BOOL chunk_mgr_append_data_min(CHUNK_MGR *chunk_mgr, const uint8_t *data, const uint32_t size, const uint32_t min_room)
{
    uint32_t tsize;/*left size*/
    const uint8_t *src_data;

    src_data = data;
    for(tsize = size; 0 < tsize;)
    {
        CHUNK   *chunk;
        uint32_t burn_len;

        chunk = chunk_mgr_last_chunk(chunk_mgr);
        if(NULL_PTR == chunk || 0 == chunk_room(chunk))
        {
            uint32_t csize;
            if(tsize <= min_room)
            {
                csize = min_room;
            }
            else
            {
                csize = tsize;
            }

            chunk = chunk_new(csize);
            if(NULL_PTR == chunk)
            {
                dbg_log(SEC_0099_CHUNK, 0)(LOGSTDOUT, "error:chunk_mgr_append_data_min: new chunk with size %d failed\n", csize);
                return (EC_FALSE);
            }
            dbg_log(SEC_0099_CHUNK, 9)(LOGSTDOUT, "[DEBUG] chunk_mgr_append_data_min: new chunk with size %d done\n", csize);

            chunk_mgr_add_chunk(chunk_mgr, chunk);
        }

        burn_len = chunk_append(chunk, src_data, tsize);
        src_data += burn_len;
        tsize    -= burn_len;
    }

    return (EC_TRUE);
}

EC_BOOL chunk_mgr_mount_data(CHUNK_MGR *chunk_mgr, const uint8_t *data, const uint32_t size)
{
    CHUNK   *chunk;

    chunk = chunk_new(0);/*do not alloc space for buffer*/
    if(NULL_PTR == chunk)
    {
        dbg_log(SEC_0099_CHUNK, 0)(LOGSTDOUT, "error:chunk_mgr_mount_data: new chunk without buffer failed\n");
        return (EC_FALSE);
    }
    chunk_mount(chunk,  data, size);

    chunk_mgr_add_chunk(chunk_mgr, chunk);
    return (EC_TRUE);
}

/*only for chunk_mgr has no or one chunk!*/
EC_BOOL chunk_mgr_umount_data(CHUNK_MGR *chunk_mgr, uint8_t **data, uint32_t *size)
{
    UINT32 chunk_num;
    CHUNK *chunk;

    chunk_num = chunk_mgr_count_chunks(chunk_mgr);
    if(1 < chunk_num)
    {
        dbg_log(SEC_0099_CHUNK, 0)(LOGSTDOUT, "error:chunk_mgr_umount_data: chunk num %ld > 1\n", chunk_num);
        return (EC_FALSE);
    }

    if(0 == chunk_num)
    {
        if(NULL_PTR != data)
        {
            (*data) = NULL_PTR;
        }
        if(NULL_PTR != size)
        {
            (*size) = 0;
        }
        return (EC_TRUE);
    }

    chunk = chunk_mgr_pop_first_chunk(chunk_mgr);
    if(NULL_PTR == chunk)
    {
        dbg_log(SEC_0099_CHUNK, 0)(LOGSTDOUT, "error:chunk_mgr_umount_data: chunk num is 1 but chunk is null\n");
        return (EC_FALSE);
    }

    chunk_umount(chunk, data, size);
    chunk_free(chunk);

    return (EC_TRUE);
}

EC_BOOL chunk_mgr_export(CHUNK_MGR *chunk_mgr, UINT8 *data, const UINT32 len, UINT32 *used)
{
    CLIST_DATA *clist_data;
    UINT32      left_len;
    uint8_t    *data_des;

    data_des = data;
    left_len = len;

    CLIST_LOOP_NEXT(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), clist_data)
    {
        CHUNK   *chunk;
        uint32_t burn_len;

        chunk = (CHUNK *)CLIST_DATA_DATA(clist_data);
        burn_len = chunk_export(chunk, data_des, (uint32_t)left_len);

        data_des += burn_len;
        left_len -= burn_len;
    }

    if(NULL_PTR != used)
    {
        (*used) = (len - left_len);
    }

    return (EC_TRUE);
}

/*shift max bytes from chunk mgr to data*/
EC_BOOL chunk_mgr_shift(CHUNK_MGR *chunk_mgr, const uint32_t data_max_len, uint8_t *data, uint32_t *size)
{
    UINT32      left_len;
    uint8_t    *data_des;

    CHUNK      *chunk;

    data_des = data;
    left_len = data_max_len;

    while(0 < left_len && NULL_PTR != (chunk = chunk_mgr_first_chunk(chunk_mgr)))
    {
        uint32_t burn_len;

        burn_len = chunk_shift(chunk, data_des, (uint32_t)left_len);

        data_des += burn_len;
        left_len -= burn_len;

        if(EC_TRUE == chunk_is_empty(chunk))
        {
            chunk_mgr_pop_first_chunk(chunk_mgr);
            chunk_free(chunk);
        }
    }

    if(NULL_PTR != size)
    {
        (*size) = (data_max_len - left_len);
    }

    return (EC_TRUE);
}

EC_BOOL chunk_mgr_dump(CHUNK_MGR *chunk_mgr, UINT8 **data, UINT32 *len)
{
    UINT32 total_len;

    CLIST_DATA *clist_data;
    UINT32      left_len;
    uint8_t    *data_des;

    total_len = chunk_mgr_total_length(chunk_mgr);
    if(0 == total_len)
    {
        (*data) = NULL_PTR;
        if(NULL_PTR != len)
        {
            (*len)  = 0;
        }
        return (EC_TRUE);
    }

    (*data) = safe_malloc(total_len, LOC_CHUNK_0006);
    if(NULL_PTR == (*data))
    {
        dbg_log(SEC_0099_CHUNK, 0)(LOGSTDOUT, "error:chunk_mgr_dump: malloc %ld bytes failed\n", total_len);
        return (EC_FALSE);
    }

    data_des = (*data);
    left_len = total_len;

    CLIST_LOOP_NEXT(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), clist_data)
    {
        CHUNK   *chunk;
        uint32_t burn_len;

        chunk = (CHUNK *)CLIST_DATA_DATA(clist_data);
        burn_len = chunk_export(chunk, data_des, (uint32_t)left_len);

        data_des += burn_len;
        left_len -= burn_len;
    }

    ASSERT(0 == left_len);

    if(NULL_PTR != len)
    {
        (*len)  = total_len;
    }
    return (EC_TRUE);
}

void chunk_mgr_print_chars(LOG *log, const CHUNK_MGR *chunk_mgr)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), clist_data)
    {
        CHUNK   *chunk;

        chunk = (CHUNK *)CLIST_DATA_DATA(clist_data);
        chunk_print_chars(log, chunk);
    }

    return;
}

void chunk_mgr_print_str(LOG *log, const CHUNK_MGR *chunk_mgr)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), clist_data)
    {
        CHUNK   *chunk;

        chunk = (CHUNK *)CLIST_DATA_DATA(clist_data);
        chunk_print_str(log, chunk);
    }

    return;
}

void chunk_mgr_print_info(LOG *log, const CHUNK_MGR *chunk_mgr)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CHUNCK_MGR_CHUNK_LIST(chunk_mgr), clist_data)
    {
        CHUNK   *chunk;

        chunk = (CHUNK *)CLIST_DATA_DATA(clist_data);
        chunk_print_info(log, chunk);
    }

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

