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

#include "cmpic.inc"

#include "cbuffer.h"

CBUFFER* cbuffer_new(const uint32_t size)
{
    CBUFFER *cbuffer;

    alloc_static_mem(MM_CBUFFER, &cbuffer, LOC_CBUFFER_0001);
    if(NULL_PTR == cbuffer)
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_new: new cbuffer failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cbuffer_init(cbuffer, size))
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_new: init cbuffer failed\n");
        free_static_mem(MM_CBUFFER, cbuffer, LOC_CBUFFER_0002);
        return (NULL_PTR);
    }

    return (cbuffer);
}

EC_BOOL cbuffer_init(CBUFFER *cbuffer, const uint32_t size)
{
    uint8_t *data;

    if(0 == size)
    {
        CBUFFER_DATA(cbuffer) = NULL_PTR;
        CBUFFER_SIZE(cbuffer) = 0;
        CBUFFER_USED(cbuffer) = 0; 

        return (EC_TRUE);
    }

    data = safe_malloc(size, LOC_CBUFFER_0003);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_init: malloc %d bytes failed\n", size);
        return (EC_FALSE);
    }

    CBUFFER_DATA(cbuffer) = data;
    CBUFFER_SIZE(cbuffer) = size;
    CBUFFER_USED(cbuffer) = 0;

    return (EC_TRUE);
}

EC_BOOL cbuffer_clean(CBUFFER *cbuffer)
{
    if(NULL_PTR != CBUFFER_DATA(cbuffer))
    {
        safe_free(CBUFFER_DATA(cbuffer), LOC_CBUFFER_0004);
        CBUFFER_DATA(cbuffer) = NULL_PTR;
    }
 
    CBUFFER_SIZE(cbuffer) = 0;
    CBUFFER_USED(cbuffer) = 0;
 
    return (EC_TRUE);
}

EC_BOOL cbuffer_free(CBUFFER *cbuffer)
{
    if(NULL_PTR != cbuffer)
    {
        cbuffer_clean(cbuffer);
        free_static_mem(MM_CBUFFER, cbuffer, LOC_CBUFFER_0005);
    }
    return (EC_TRUE);
}

EC_BOOL cbuffer_set(CBUFFER *cbuffer, const uint8_t *data, const uint32_t len)
{
    uint8_t *des;

    if(len <= CBUFFER_SIZE(cbuffer))
    {
        BCOPY(data, CBUFFER_DATA(cbuffer), len);
        CBUFFER_USED(cbuffer) = len;
        return (EC_TRUE);
    }

    if(NULL_PTR != CBUFFER_DATA(cbuffer))
    {
        safe_free(CBUFFER_DATA(cbuffer), LOC_CBUFFER_0006);
        CBUFFER_DATA(cbuffer) = NULL_PTR;
     
        CBUFFER_USED(cbuffer) = 0;
        CBUFFER_SIZE(cbuffer) = 0;
    }

    des = safe_malloc(len, LOC_CBUFFER_0007);
    if(NULL_PTR == des)
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_set: malloc %d bytes failed\n", len);
        return (EC_FALSE);
    }
    BCOPY(data, des, len);
 
    CBUFFER_DATA(cbuffer) = des;
    CBUFFER_USED(cbuffer) = len;
    CBUFFER_SIZE(cbuffer) = len;
 
    return (EC_TRUE);
}

EC_BOOL cbuffer_reset(CBUFFER *cbuffer)
{
    if(NULL_PTR != cbuffer)
    {
        CBUFFER_USED(cbuffer) = 0;     
    }
    return (EC_TRUE);
}

EC_BOOL cbuffer_clone(const CBUFFER *cbuffer_src, CBUFFER *cbuffer_des)
{
    cbuffer_reset(cbuffer_des);
    cbuffer_set(cbuffer_des, CBUFFER_DATA(cbuffer_src), CBUFFER_USED(cbuffer_src));
    return (EC_TRUE);
}

EC_BOOL cbuffer_expand(CBUFFER *cbuffer, const UINT32 location)
{
    uint32_t   size;
    uint8_t *data;

    if(0 == CBUFFER_SIZE(cbuffer))
    {
        size = CBUFFER_MIN_SIZE; /*default*/
        data = (UINT8 *)safe_malloc(size, location);
    }
    else
    {
        size = 2 * CBUFFER_SIZE(cbuffer);/*double the old capacity*/
        data = (UINT8 *)safe_realloc(CBUFFER_DATA(cbuffer), CBUFFER_SIZE(cbuffer), size, location);
    }

    if(data)
    {
        CBUFFER_DATA(cbuffer) = data;
        CBUFFER_SIZE(cbuffer) = size;

        return (EC_TRUE);
    }

    dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_expand: failed to expand cbuffer with size %d and used %d\n",
                        CBUFFER_SIZE(cbuffer), CBUFFER_USED(cbuffer));

    return (EC_FALSE);
}

EC_BOOL cbuffer_expand_to(CBUFFER *cbuffer, const uint32_t size)
{
    uint32_t len;
    uint8_t *data;

    len = (size < CBUFFER_MIN_SIZE)? CBUFFER_MIN_SIZE : size;

    if(len <= CBUFFER_SIZE(cbuffer))
    {
        /*nothing to do*/
        return (EC_TRUE);
    }

    if(0 == CBUFFER_SIZE(cbuffer))
    {
        data = (UINT8 *)safe_malloc(len, LOC_CBUFFER_0008);
    }
    else
    {
        data = (UINT8 *)safe_realloc(CBUFFER_DATA(cbuffer), CBUFFER_SIZE(cbuffer), len, LOC_CBUFFER_0009);
    }

    if(data)
    {
        CBUFFER_DATA(cbuffer) = data;
        CBUFFER_SIZE(cbuffer) = len;

        return (EC_TRUE);
    }

    dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_expand_to: failed to expand cbuffer with size %d and used %d to size %d\n",
                        CBUFFER_SIZE(cbuffer), CBUFFER_USED(cbuffer), len);

    return (EC_FALSE);
}

EC_BOOL cbuffer_push_bytes(CBUFFER *cbuffer, const uint8_t *data, const uint32_t size)
{
    if(EC_FALSE == cbuffer_expand_to(cbuffer, CBUFFER_USED(cbuffer) + size))
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_push_bytes: expand cbuffer %p to size %d failed\n",
                            cbuffer, CBUFFER_USED(cbuffer) + size);
        return (EC_FALSE);
    }

    BCOPY(data, CBUFFER_DATA(cbuffer) + CBUFFER_USED(cbuffer), size);
    CBUFFER_USED(cbuffer) += size;

    return (EC_TRUE);
}

EC_BOOL cbuffer_pop_bytes(CBUFFER *cbuffer, uint8_t *data, const uint32_t size)
{
    if(CBUFFER_USED(cbuffer) < size)
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_pop_bytes: cbuffer %p used %d < expected pop size %d\n",
                           cbuffer, CBUFFER_USED(cbuffer), size);
        return (EC_FALSE);                        
    }

    if(NULL_PTR != data)
    {
        BCOPY(CBUFFER_DATA(cbuffer) + CBUFFER_USED(cbuffer) - size, data, size);     
    }
    CBUFFER_USED(cbuffer) -= size;

    return (EC_TRUE);
}

EC_BOOL cbuffer_left_shift_out(CBUFFER *cbuffer, uint8_t *data, const uint32_t size)
{
    if(CBUFFER_USED(cbuffer) < size)
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_left_shift_out: cbuffer %p used %d < expected shift out size %d\n",
                           cbuffer, CBUFFER_USED(cbuffer), size);
        return (EC_FALSE);                        
    }

    if(NULL_PTR != data)
    {
        BCOPY(CBUFFER_DATA(cbuffer), data, size);     
    }

    if(0 < size)
    {
        BMOVE(CBUFFER_DATA(cbuffer) + size, CBUFFER_DATA(cbuffer), CBUFFER_USED(cbuffer) - size);
        CBUFFER_USED(cbuffer) -= size;
    }

    return (EC_TRUE);
}

EC_BOOL cbuffer_left_shift_in(CBUFFER *cbuffer, const uint8_t *data, const uint32_t size)
{
    if(EC_FALSE == cbuffer_expand_to(cbuffer, CBUFFER_USED(cbuffer) + size))
    {
        dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_left_shift_in: expand cbuffer %p to size %d failed\n",
                            cbuffer, CBUFFER_USED(cbuffer) + size);
        return (EC_FALSE);
    }

    BMOVE(CBUFFER_DATA(cbuffer), CBUFFER_DATA(cbuffer) + size, CBUFFER_USED(cbuffer));
    BCOPY(data, CBUFFER_DATA(cbuffer), size);
    CBUFFER_USED(cbuffer) += size;

    return (EC_TRUE);
}


EC_BOOL cbuffer_cmp_bytes(const CBUFFER *cbuffer, const uint32_t offset, const uint8_t *data, const uint32_t len)
{
    if(offset + len > CBUFFER_USED(cbuffer))
    {
        //dbg_log(SEC_0126_CBUFFER, 0)(LOGSTDOUT, "error:cbuffer_cmp_bytes: offset %d + len %d > used %d\n", offset, len, CBUFFER_USED(cbuffer));
        return (EC_FALSE);
    }

    if(0 == BCMP(CBUFFER_DATA(cbuffer) + offset, data, len))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

uint32_t cbuffer_append(CBUFFER *cbuffer, const uint8_t *data, const uint32_t size)
{
    uint32_t len;
    //dbg_log(SEC_0126_CBUFFER, 9)(LOGSTDOUT, "[DEBUG] cbuffer_append: beg: data size %d, cbuffer size %d, used %d\n", size, CBUFFER_SIZE(cbuffer), CBUFFER_USED(cbuffer));
    len = DMIN(CBUFFER_ROOM(cbuffer), size);
    BCOPY(data, CBUFFER_DATA(cbuffer) + CBUFFER_USED(cbuffer), len);
    CBUFFER_USED(cbuffer) += len;

    //dbg_log(SEC_0126_CBUFFER, 9)(LOGSTDOUT, "[DEBUG] cbuffer_append: end: data size %d, cbuffer size %d, used %d\n", size, CBUFFER_SIZE(cbuffer), CBUFFER_USED(cbuffer));

    return (len);
}

uint32_t cbuffer_append_format(CBUFFER *cbuffer, const char *format, ...)
{
    va_list ap;
    UINT32 len;

    va_list params;

    va_start(ap, format);

    va_copy(params, ap);

    len = (UINT32)vsnprintf((char *)0, 0, format, params);/*need len*/
    cbuffer_expand_to(cbuffer, len + CBUFFER_USED(cbuffer) + 1);

    len = vsnprintf((char *)(CBUFFER_DATA(cbuffer) + CBUFFER_USED(cbuffer)), CBUFFER_ROOM(cbuffer), format, ap);
    CBUFFER_USED(cbuffer) += len;
 
    va_end(ap);

    return (len);
}

uint32_t cbuffer_append_vformat(CBUFFER *cbuffer, const char *format, va_list ap)
{
    UINT32 len;
    va_list params;

    va_copy(params, ap);

    len = (UINT32)vsnprintf((char *)0, 0, format, params);/*need len*/
    cbuffer_expand_to(cbuffer, len + CBUFFER_USED(cbuffer) + 1);

    len = vsnprintf((char *)(CBUFFER_DATA(cbuffer) + CBUFFER_USED(cbuffer)), CBUFFER_ROOM(cbuffer), format, ap);
    CBUFFER_USED(cbuffer) += len;

    return (len);
}

uint32_t cbuffer_export(CBUFFER *cbuffer, uint8_t *data, const uint32_t max_size)
{
    uint32_t len;

    len = DMIN(CBUFFER_USED(cbuffer), max_size);
    BCOPY(CBUFFER_DATA(cbuffer), data, len);

    return (len);
}

uint8_t *cbuffer_data(CBUFFER *cbuffer)
{
    return CBUFFER_DATA(cbuffer);
}

uint32_t cbuffer_used(const CBUFFER *cbuffer)
{
    return CBUFFER_USED(cbuffer);
}

uint32_t cbuffer_size(const CBUFFER *cbuffer)
{
    return CBUFFER_SIZE(cbuffer);
}

uint32_t cbuffer_room(const CBUFFER *cbuffer)
{
    return CBUFFER_ROOM(cbuffer);
}

EC_BOOL cbuffer_is_empty(const CBUFFER *cbuffer)
{
    if(0 == CBUFFER_USED(cbuffer))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbuffer_mount(CBUFFER *cbuffer, const uint8_t *data, const uint32_t len)
{
    if(NULL_PTR != CBUFFER_DATA(cbuffer))
    {
        safe_free(CBUFFER_DATA(cbuffer), LOC_CBUFFER_0010);
        CBUFFER_DATA(cbuffer) = NULL_PTR;
     
        CBUFFER_USED(cbuffer) = 0;
        CBUFFER_SIZE(cbuffer) = 0;
    }

    CBUFFER_DATA(cbuffer) = (uint8_t *)data;
    CBUFFER_USED(cbuffer) = len;
    CBUFFER_SIZE(cbuffer) = len;
 
    return (EC_TRUE);
}

EC_BOOL cbuffer_umount(CBUFFER *cbuffer, uint8_t **data, uint32_t *len)
{
    if(NULL_PTR != data)
    {
        (*data) = CBUFFER_DATA(cbuffer);
    }

    if(NULL_PTR != len)
    {
        (*len) = CBUFFER_USED(cbuffer);
    }

    CBUFFER_DATA(cbuffer) = NULL_PTR;
    CBUFFER_USED(cbuffer) = 0;
    CBUFFER_SIZE(cbuffer) = 0;
 
    return (EC_TRUE); 
}

void cbuffer_print_chars(LOG *log, const CBUFFER *cbuffer)
{
    uint32_t idx;
    if(NULL_PTR == cbuffer)
    {
        sys_print(log, "<nil>\n");
        return;
    }

    if(0 == CBUFFER_USED(cbuffer) || NULL_PTR == CBUFFER_DATA(cbuffer))
    {
        sys_print(log, "(null)\n");
        return;
    }

    for(idx = 0; idx < CBUFFER_USED(cbuffer); idx ++)
    {
        sys_print(log, "[%8d] %c %02x\n", idx, CBUFFER_DATA(cbuffer)[ idx ], CBUFFER_DATA(cbuffer)[ idx ]);
    }
 
    return;
}

void cbuffer_print_str(LOG *log, const CBUFFER *cbuffer)
{
    if(NULL_PTR == cbuffer)
    {
        sys_print(log, "<nil>\n");
        return;
    }

    if(0 == CBUFFER_USED(cbuffer) || NULL_PTR == CBUFFER_DATA(cbuffer))
    {
        sys_print(log, "(null)\n");
        return;
    }
 
    sys_print(log, "%.*s\n", CBUFFER_USED(cbuffer), CBUFFER_DATA(cbuffer));
    return;
}

void cbuffer_print_info(LOG *log, const CBUFFER *cbuffer)
{
    if(NULL_PTR == cbuffer)
    {
        sys_log(log, "<nil>\n");
        return;
    }

    if(0 == CBUFFER_USED(cbuffer) || NULL_PTR == CBUFFER_DATA(cbuffer))
    {
        sys_log(log, "(null)\n");
        return;
    }
 
    sys_log(log, "data %p, used %d, size %d\n", CBUFFER_DATA(cbuffer), CBUFFER_USED(cbuffer), CBUFFER_SIZE(cbuffer));
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

