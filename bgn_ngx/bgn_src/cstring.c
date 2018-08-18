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
#include <stdarg.h>
#include <string.h>
#include "cbytes.h"

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "cmpic.inc"
#include "cstring.h"

#if 0
#define CSTRING_DEBUG(cstring) do{                                    \
    MM_AUX  *pAux;                                                    \
    pAux = (MM_AUX *)((UINT32)((cstring)->str) - sizeof(MM_AUX));    \
    ASSERT(pAux->type == get_static_mem_type((cstring)->capacity));  \
}while(0)
#endif

#if 1
#define CSTRING_DEBUG(cstring) do{}while(0)
#endif

CSTRING *cstring_new(const UINT8 *str, const UINT32 location)
{
    CSTRING *cstring;

    alloc_static_mem(MM_CSTRING, &cstring, location);
    if(cstring)
    {
        cstring->str = NULL_PTR;
        cstring_init(cstring, str);
    }
    return cstring;
}

void cstring_free(CSTRING *cstring)
{
    if(NULL_PTR != cstring)
    {
        if(cstring->str)
        {
            SAFE_FREE(cstring->str, LOC_CSTRING_0001);

            cstring->str = (UINT8 *)0;
            cstring->capacity = 0;
            cstring->len      = 0;
        }

        free_static_mem(MM_CSTRING, cstring, LOC_CSTRING_0002);
    }
    return;
}

CSTRING *cstring_new_0()
{
    CSTRING *cstring;

    alloc_static_mem(MM_CSTRING, &cstring, LOC_CSTRING_0003);
    if(cstring)
    {
        cstring->str = NULL_PTR;
        cstring_init(cstring, NULL_PTR);
    }
    return cstring;
}

void cstring_free_1(CSTRING *cstring, const UINT32 location)
{
    if(NULL_PTR != cstring)
    {
        if(cstring->str)
        {
            SAFE_FREE(cstring->str, location);

            cstring->str = (UINT8 *)0;
            cstring->capacity = 0;
            cstring->len      = 0;
        }

        free_static_mem(MM_CSTRING, cstring, location);
    }
    return;
}

void cstring_init(CSTRING *cstring, const UINT8 *str)
{
    UINT32 str_len;
//    UINT32 pos;

    if(NULL_PTR == str)
    {
        cstring->str = (UINT8 *)0;
        cstring->len      = 0;
        cstring->capacity = 0;
        return;
    }

    str_len = strlen((char *)str);

    cstring->str = (UINT8 *)SAFE_MALLOC(sizeof(UINT8) * (str_len + 1), LOC_CSTRING_0004);
    if(cstring->str)
    {
        /*note: here not call memset to set data area to zero due to finding its unstable*/
#if 0
        for(pos = 0; pos <= str_len; pos ++)/*copy the last terminal char of str*/
        {
            cstring->str[ pos ] = str[ pos ];
        }
#endif
#if 1
        BCOPY(str, cstring->str, str_len + 1);
#endif
        cstring->capacity = str_len + 1;
        cstring->len      = str_len;/*the length cover the last terminal char of str*/

        CSTRING_DEBUG(cstring);
        return;
    }

    cstring->capacity = 0;
    cstring->len      = 0;
    return;
}

void cstring_init_0(CSTRING *cstring)
{
    cstring_init(cstring, NULL_PTR);
    return;
}

void cstring_clean(CSTRING *cstring)
{
    if(NULL_PTR != cstring)
    {
        if(NULL_PTR != cstring->str)
        {
            SAFE_FREE(cstring->str, LOC_CSTRING_0005);
            cstring->str = NULL_PTR;
        }

        cstring->capacity = 0;
        cstring->len      = 0;
    }
    return;
}

void cstring_reset(CSTRING *cstring)
{
    cstring->len = 0;
    return;
}

void cstring_clone(const CSTRING *cstring_src, CSTRING *cstring_des)
{
    UINT32 pos;

    cstring_clean(cstring_des);

    if(NULL_PTR == cstring_src || 0 == cstring_src->len)
    {
        return;
    }

    cstring_des->str = (UINT8 *)SAFE_MALLOC(sizeof(UINT8) * (cstring_src->len + 1), LOC_CSTRING_0006);

    for(pos = 0; pos <= cstring_src->len; pos ++)/*clone terminal char*/
    {
        cstring_des->str[ pos ] = cstring_src->str[ pos ];
    }
    cstring_des->capacity = cstring_src->len + 1;
    cstring_des->len      = cstring_src->len;
    CSTRING_DEBUG(cstring_des);
    return;
}

EC_BOOL cstring_clone_0(const CSTRING *cstring_src, CSTRING *cstring_des)
{
    cstring_clone(cstring_src, cstring_des);
    return (EC_TRUE);
}

EC_BOOL cstring_empty(CSTRING *cstring)
{
    cstring->len = 0;
    return (EC_TRUE);
}

EC_BOOL cstring_is_empty(const CSTRING *cstring)
{
    if(NULL_PTR == cstring || 0 == cstring->len)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cstring_is_str(const CSTRING *cstring_src, const UINT8 *str)
{
    if(NULL_PTR == str)
    {
        if(EC_TRUE == cstring_is_empty(cstring_src))
        {
            return (EC_TRUE);
        }
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(cstring_src))
    {
        return (EC_FALSE);
    }

    if(STRCMP((char *)cstring_src->str, (char *)str))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cstring_is_str_ignore_case(const CSTRING *cstring_src, const UINT8 *str)
{
    /*ignoring the case of the characters*/
    if(STRCASECMP((char *)cstring_src->str, (char *)str))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cstring_is_equal_ignore_case(const CSTRING *cstring_src, const CSTRING *cstring_des)
{
    if(cstring_src == cstring_des)
    {
        return (EC_TRUE);
    }

    if(cstring_src->len != cstring_des->len)
    {
        return (EC_FALSE);
    }

    if(0 == STRNCASECMP((const char *)cstring_src->str, (const char *)cstring_des->str, cstring_src->len))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cstring_is_equal(const CSTRING *cstring_src, const CSTRING *cstring_des)
{
    if(cstring_src == cstring_des)
    {
        return (EC_TRUE);
    }

    if(cstring_src->len != cstring_des->len)
    {
        return (EC_FALSE);
    }

    if(0 == BCMP(cstring_src->str, cstring_des->str, cstring_src->len))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cstring_is_equal_n(const CSTRING *cstring_src, const CSTRING *cstring_des, const UINT32 n)
{
    UINT32 pos;
    UINT32 len_to_cmp;

    if(cstring_src == cstring_des)
    {
        return (EC_TRUE);
    }

    if((cstring_src->len >= n && cstring_des->len < n)
    || (cstring_des->len >= n && cstring_src->len < n))
    {
        return (EC_FALSE);
    }

    if(cstring_src->len >= n && cstring_des->len >= n)
    {
        if(cstring_src->len > cstring_des->len)
        {
            len_to_cmp = cstring_des->len;
        }
        else
        {
            len_to_cmp = cstring_src->len;
        }
    }
    else
    {
        len_to_cmp = n;
    }

    for(pos = 0; pos < len_to_cmp; pos ++)
    {
        if(cstring_src->str[ pos ] != cstring_des->str[ pos ])
        {
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

int cstring_cmp(const CSTRING *cstring_src, const CSTRING *cstring_des)
{
    return STRCMP((char *)cstring_src->str, (char *)cstring_des->str);
}

int cstring_cmp_ignore_case(const CSTRING *cstring_src, const CSTRING *cstring_des)
{
    return STRCASECMP((char *)cstring_src->str, (char *)cstring_des->str);
}

int cstring_ncmp(const CSTRING *cstring_src, const CSTRING *cstring_des, const UINT32 n)
{
    int ret;

    ret = STRNCMP((char *)cstring_src->str, (char *)cstring_des->str, n);
    if(0 == ret)
    {
        return (0);
    }

    if(0 < ret)
    {
        return (1);
    }

    return (-1);
}

/*Orthogonality comparision*/
int cstring_ocmp(const CSTRING *cstring_src, const CSTRING *cstring_des)
{
    return cstring_ncmp(cstring_src, cstring_des, DMIN(cstring_src->len, cstring_des->len));
}

EC_BOOL cstring_expand(CSTRING *cstring, const UINT32 location)
{
    UINT32 capacity;
    UINT8 *str;

    if(0 == cstring->capacity)
    {
        capacity = CSTRING_MIN_CAPACITY; /*default*/
        str = (UINT8 *)SAFE_MALLOC(capacity, location);
    }
    else
    {
        capacity = 2 * (cstring->capacity);/*double the old capacity*/
        str = (UINT8 *)SAFE_REALLOC(cstring->str, cstring->capacity, capacity, location);
    }

    if(str)
    {
        cstring->str = str;
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        BSET(cstring->str + cstring->capacity, '\0', capacity - cstring->capacity);
#if 0
        for(pos = cstring->capacity; pos < capacity; pos ++)
        {
            cstring->str[ pos ] = '\0';
        }
#endif
        cstring->capacity = capacity;

        CSTRING_DEBUG(cstring);

        return (EC_TRUE);
    }

    dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_expand: failed to expand cstring with capacity %ld and len %ld\n", cstring->capacity, cstring->len);

    return (EC_FALSE);
}

EC_BOOL cstring_expand_to(CSTRING *cstring, const UINT32 size, const UINT32 location)
{
    UINT32 capacity;
    UINT8 *str;

    capacity = (size < CSTRING_MIN_CAPACITY)? CSTRING_MIN_CAPACITY : size;

    if(capacity <= cstring->capacity)
    {
        /*nothing to do*/
        return (EC_TRUE);
    }

    if(0 == cstring->capacity)
    {
        str = (UINT8 *)SAFE_MALLOC(capacity, location);
    }
    else
    {
        str = (UINT8 *)SAFE_REALLOC(cstring->str, cstring->capacity, capacity, location);
    }

    if(str)
    {
        //UINT32 pos;
        cstring->str = str;
        /*note: here not call memset to set data area to zero due to finding its unstable*/
        BSET(cstring->str + cstring->capacity, '\0', capacity - cstring->capacity);
#if 0
        for(pos = cstring->capacity; pos < capacity; pos ++)
        {
            cstring->str[ pos ] = '\0';
        }
#endif
        cstring->capacity = capacity;

        CSTRING_DEBUG(cstring);
        return (EC_TRUE);
    }

    dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_expand_to: failed to expand cstring with capacity %ld and len %ld to capacity %ld\n",
                        cstring->capacity, cstring->len, capacity);

    return (EC_FALSE);
}

EC_BOOL cstring_set_capacity(CSTRING *cstring, const UINT32 capacity)
{
    UINT8 *str;
    if(0 != cstring->capacity && capacity != cstring->capacity)
    {
        SAFE_FREE(cstring->str, LOC_CSTRING_0007);
        cstring->str = (UINT8 *)0;
        cstring->capacity = 0;
    }

    cstring->len = 0;
    str = (UINT8 *)SAFE_MALLOC(sizeof(UINT8) * capacity, LOC_CSTRING_0008);
    if(str)
    {
        cstring->str = str;
        cstring->capacity = capacity;

        CSTRING_DEBUG(cstring);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

UINT32 cstring_get_capacity(const CSTRING *cstring)
{
    if(NULL_PTR == cstring)
    {
        return ((UINT32)0);
    }
    return cstring->capacity;
}

UINT32 cstring_get_len(const CSTRING *cstring)
{
    if(NULL_PTR == cstring)
    {
        return ((UINT32)0);
    }
    return cstring->len;
}

UINT32 cstring_get_room(const CSTRING *cstring)
{
    return (cstring->capacity - cstring->len);
}

UINT8 * cstring_get_str(const CSTRING *cstring)
{
    if(NULL_PTR == cstring || 0 == cstring->len)
    {
        return (UINT8 *)0;
    }
    return cstring->str;
}

EC_BOOL cstring_get_char(const CSTRING *cstring, const UINT32 pos, UINT8 *pch)
{
    if(pos >= cstring->len)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_get_char: failed to get char at %ld due to overflow where cstring capaciy %ld and len %ld\n",
                        pos, cstring->capacity, cstring->len);
        return (EC_FALSE);
    }
    (*pch) = cstring->str[ pos ];
    return (EC_TRUE);
}

EC_BOOL cstring_set_str(CSTRING *cstring, const UINT8 *str)
{
    //cstring_clean(cstring);

    if(NULL_PTR != str)
    {
        cstring->str      = (UINT8 *)str;
        cstring->len      = (UINT32)strlen((char *)str);
        cstring->capacity = cstring->len + 1;
    }
    else
    {
        cstring->str      = NULL_PTR;
        cstring->len      = 0;
        cstring->capacity = 0;
    }
    return (EC_TRUE);
}

EC_BOOL cstring_unset(CSTRING *cstring)
{
    cstring->str = NULL_PTR;
    cstring->len = 0;
    cstring->capacity = 0;
    return (EC_TRUE);
}

CBYTES *cstring_get_cbytes(const CSTRING *cstring)
{
    if(NULL_PTR != cstring->str && 0 != cstring->len)
    {
        CBYTES *cbytes;
        cbytes = cbytes_new(cstring->len/* + 1*/);
        if(NULL_PTR == cbytes)
        {
            dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_get_cbytes: new cbytes with len %ld failed\n", cstring->len + 1);
            return (NULL_PTR);
        }
        BCOPY(cstring->str, CBYTES_BUF(cbytes), cstring->len/* + 1*/);

        CSTRING_DEBUG(cstring);
        return (cbytes);
    }
    return (NULL_PTR);
}

EC_BOOL cstring_set_char(CSTRING *cstring, const UINT8 ch, const UINT32 pos)
{
    if(pos >= cstring->len)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_set_char: failed to set %c at %ld due to overflow where cstring capaciy %ld and len %ld\n",
                        ch, pos, cstring->capacity, cstring->len);
        return (EC_FALSE);
    }

   cstring->str[ pos ] = ch; /*due to cstring_expand will set the new space to '\0', here ignore pos at end of string*/
   return (EC_TRUE);
}

EC_BOOL cstring_get_cstr(const CSTRING *cstring_src, const UINT32 from, const UINT32 to, CSTRING *cstring_des)
{
    UINT32 beg_pos;
    UINT32 end_pos;
    UINT32 pos;

    UINT8 *src_pch;
    UINT8 *des_pch;

    if(from >= to)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_get_cstr: invalid sub range [%ld, %ld)\n", from, to);
        return (EC_FALSE);
    }

    beg_pos = from;
    end_pos = ((to >= cstring_src->len) ? cstring_src->len : to);

    if(beg_pos >= end_pos)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_get_cstr: sub range [%ld, %ld) overflow where cstring_src len %ld, capacity %ld\n",
                         from, to, cstring_src->len, cstring_src->capacity);
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_expand_to(cstring_des, end_pos - beg_pos + 1, LOC_CSTRING_0009))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_get_cstr: failed to expand cstring with capaciy %ld and len %ld to size %ld\n",
                        cstring_des->capacity, cstring_des->len, end_pos - beg_pos + 1);
        return (EC_FALSE);
    }

    src_pch = cstring_src->str + beg_pos;
    des_pch = cstring_des->str;
    for(pos = beg_pos; pos < end_pos; pos ++)
    {
        (*des_pch ++) = (*src_pch ++);
    }
    (*des_pch) = '\0';
    cstring_des->len = end_pos - beg_pos;

    CSTRING_DEBUG(cstring_des);

    return (EC_TRUE);
}

EC_BOOL cstring_set_word(CSTRING *cstring, const UINT32 num)
{
    cstring_format(cstring, "%ld", num);

    CSTRING_DEBUG(cstring);
    return (EC_TRUE);
}

UINT32 cstring_get_word(const CSTRING *cstring)
{
    UINT32 c;            /* current char */
    UINT32 total;        /* current total */
    UINT32 pos;

    if(0 == cstring->len || NULL_PTR == cstring->str)
    {
        return ((UINT32)0);
    }
    total = 0;
    for(pos = 0; pos < cstring->len; pos ++)
    {
        c = (UINT32)(cstring->str[ pos ]);
        if(c < '0' || c > '9')
        {
            dbg_log(SEC_0082_CSTRING, 0)(LOGSTDERR, "error:cstring_get_word: cstring %.*s found not digit char at pos %ld\n",
                            (uint32_t)cstring->len, cstring->str, pos);
            return ((UINT32)0);
        }
        total = 10 * total + (c - '0');
    }
    return (total);
}
EC_BOOL cstring_set_chars(CSTRING *cstring, const UINT8 *pchs, const UINT32 len)
{
    UINT32 pos;

    if(len + 1 < cstring->capacity)
    {
        for(pos = 0; pos < len; pos ++)
        {
            cstring->str[ pos ] = pchs[ pos ];
        }
        cstring->len = pos;
        cstring->str[ cstring->len ] = '\0';
        return (EC_TRUE);
    }

    cstring_clean(cstring);

    cstring->str = (UINT8 *)SAFE_MALLOC(len + 1, LOC_CSTRING_0010);
    if(NULL_PTR == cstring->str)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_set_chars: failed to malloc memory %ld bytes\n", len);
        return (EC_FALSE);
    }
    cstring->capacity = len + 1;
    cstring->len      = 0;

    for(pos = 0; pos < len; pos ++)
    {
        cstring->str[ pos ] = pchs[ pos ];
    }
    cstring->len = pos;
    cstring->str[ cstring->len ] = '\0';

    CSTRING_DEBUG(cstring);

    return (EC_TRUE);
}

CSTRING *cstring_make(const char *format, ...)
{
    CSTRING *cstring;

    va_list ap;
    UINT32 len;

    cstring = cstring_new(NULL_PTR, LOC_CSTRING_0011);
    if(NULL_PTR == cstring)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_make: new cstring failed\n");
        return (NULL_PTR);
    }

    //cstring_print(LOGSTDOUT, cstring);

    va_start(ap, format);

    len = (UINT32)c_vformat_len(format, ap);

    cstring_expand_to(cstring, len + cstring->len + 1, LOC_CSTRING_0012);

    len = vsnprintf((char *)(cstring->str + cstring->len), cstring->capacity - cstring->len, format, ap);
    cstring->len += len;
    //cstring->str[ len ] = '\0';
    va_end(ap);

    CSTRING_DEBUG(cstring);
    return (cstring);
}

CSTRING *cstring_make_by_word(const UINT32 num)
{
    char *str;

    str = c_word_to_str(num);
    return cstring_new((UINT8 *)str, LOC_CSTRING_0013);
}

CSTRING *cstring_make_by_ctimet(const CTIMET *ctimet)
{
    UINT32  ts_num;
    char   *ts_hex_str;

    ts_num = (UINT32)((*ctimet) & (~(UINT32_ZERO)));
    ts_hex_str = c_word_to_hex_str(ts_num);

    return cstring_new((UINT8 *)ts_hex_str, LOC_CSTRING_0014);
}

CSTRING *cstring_make_by_bytes(const UINT32 len, const UINT8 *bytes)
{
    CSTRING * cstring;

    cstring = cstring_new(NULL_PTR, LOC_CSTRING_0015);
    if(NULL_PTR == cstring)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_make_by_bytes: new cstring failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cstring_set_chars(cstring, bytes, len))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_make_by_bytes: sett chars to cstring failed\n");
        cstring_free(cstring);
        return (NULL_PTR);
    }

    CSTRING_DEBUG(cstring);
    return (cstring);
}

CSTRING *cstring_dup(const CSTRING *cstring_src)
{
    CSTRING *cstring_des;

    cstring_des = cstring_new(NULL_PTR, LOC_CSTRING_0016);
    if(NULL_PTR == cstring_des)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_dup: new cstring failed\n");
        return (NULL_PTR);
    }

    cstring_clone(cstring_src, cstring_des);
    CSTRING_DEBUG(cstring_des);
    return (cstring_des);
}

EC_BOOL cstring_erase_char(CSTRING *cstring, const UINT32 pos)
{
    UINT32 cur_pos;

    UINT8 *src_pch;
    UINT8 *des_pch;

    if(pos >= cstring->len)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_erase_char: failed to erase char at %ld due to overflow where cstring capaciy %ld and len %ld\n",
                        pos, cstring->capacity, cstring->len);
        return (EC_FALSE);
    }

    src_pch = cstring->str + pos + 1;
    des_pch = cstring->str + pos;
    for(cur_pos = pos; cur_pos < cstring->len; cur_pos ++)
    {
        (*des_pch ++) = (*src_pch ++);/*okay, the terminal char of string is moved forward too*/
    }
    cstring->len --;
    cstring->str[ cstring->len ] = '\0';

    CSTRING_DEBUG(cstring);
    return (EC_TRUE);
}


EC_BOOL cstring_append_char(CSTRING *cstring, const UINT8 ch)
{
    if(cstring->len + 1 >= cstring->capacity)
    {
        if(EC_FALSE == cstring_expand(cstring, LOC_CSTRING_0017))
        {
            dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_append_char: failed to expand cstring with capaciy %ld and len %ld\n",
                            cstring->capacity, cstring->len);
            return (EC_FALSE);
        }
        //dbg_log(SEC_0082_CSTRING, 5)(LOGSTDOUT, "[LOG] cstring_append_char: expand to capacity %ld, len %ld\n",  cstring->capacity, cstring->len);
    }

    cstring->str[ cstring->len ++ ] = ch;
    cstring->str[ cstring->len ] = '\0';

    CSTRING_DEBUG(cstring);
    return (EC_TRUE);
}

EC_BOOL cstring_append_chars(CSTRING *cstring, const UINT32 ch_num, const UINT8 *chars, const UINT32 location)
{
//    UINT32 pos;
    if(cstring->len + ch_num >= cstring->capacity)
    {
        if(EC_FALSE == cstring_expand_to(cstring, cstring->len + ch_num + 1, location))
        {
            dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_append_chars: failed to expand cstring with capaciy %ld and len %ld to size %ld\n",
                            cstring->capacity, cstring->len, cstring->len + ch_num + 1);
            return (EC_FALSE);
        }
    }
#if 0
    for(pos = 0; pos < ch_num; pos ++)
    {
        cstring->str[ cstring->len ++ ] = chars[ pos ];
    }
#endif
    if(0 < ch_num)
    {
        UINT8 *des;
        des = cstring->str + cstring->len;
        BCOPY(chars, des, ch_num);
        cstring->len += ch_num;
    }

    cstring->str[ cstring->len ] = '\0';

    CSTRING_DEBUG(cstring);
    return (EC_TRUE);
}

EC_BOOL cstring_append_str(CSTRING *cstring, const UINT8 *str)
{
    UINT32 str_len;
    //UINT32 pos;
    UINT8 *src_pch;
    UINT8 *des_pch;

    str_len = strlen((char *)str);

    if(EC_FALSE == cstring_expand_to(cstring, cstring->len + str_len + 1, LOC_CSTRING_0018))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_append_str: failed to expand cstring with capaciy %ld and len %ld to size %ld\n",
                        cstring->capacity, cstring->len, cstring->len + str_len + 1);
        return (EC_FALSE);
    }

    src_pch = (UINT8 *)str;
    des_pch = cstring->str + cstring->len;
#if 0
    for(pos = 0; pos < str_len; pos ++)
    {
        (*des_pch ++) = (*src_pch ++);
    }
#endif
#if 1
    BCOPY(src_pch, des_pch, str_len);
#endif
    cstring->len += str_len;
    cstring->str[ cstring->len ] = '\0';

    CSTRING_DEBUG(cstring);
    return (EC_TRUE);
}

EC_BOOL cstring_append_cstr(CSTRING *cstring_des, const CSTRING *cstring_src)
{
    return cstring_append_str(cstring_des, cstring_src->str);
}

EC_BOOL cstring_erase_sub_str(CSTRING *cstring, const UINT32 from, const UINT32 to)
{
    UINT32 src_pos;
    UINT32 des_pos;

    UINT32 str_len;
    UINT32 ret_len;

    str_len = cstring->len;
    des_pos = ((from >= str_len) ? str_len : from);
    src_pos = ((to >= str_len) ? str_len : to);

    if( src_pos <= des_pos )
    {
        return (EC_FALSE);
    }

    ret_len = str_len - (src_pos - des_pos);

    /*note: src_pos <= str_len means it will copy the terminal char of string to right position*/
    for(; src_pos <= str_len && des_pos < str_len; src_pos ++, des_pos ++)
    {
        cstring->str[ des_pos ] = cstring->str[ src_pos];
    }
    cstring->len = ret_len;
    cstring->str[ cstring->len ] = '\0';

    CSTRING_DEBUG(cstring);
    return (EC_TRUE);
}

EC_BOOL cstring_erase_tail_str(CSTRING *cstring, const UINT32 len)
{
    UINT32 str_len;

    str_len = cstring->len;

    if(0 == str_len)
    {
        return (EC_TRUE);
    }

    if(str_len < len)
    {
        dbg_log(SEC_0082_CSTRING, 1)(LOGSTDOUT, "warn:cstring_erase_tail_str: force cstring to empty due to its len %ld < len %ld to erase\n", str_len, len);
        cstring->str[ 0 ] = '\0';
        cstring->len = 0;
        return (EC_TRUE);
    }

    //dbg_log(SEC_0082_CSTRING, 5)(LOGSTDOUT, "\n");
    //dbg_log(SEC_0082_CSTRING, 5)(LOGSTDOUT, "cstring_erase_tail_str: %s => \n", cstring->str);

    cstring->str[ str_len - len ] = '\0';
    cstring->len = str_len - len;

    //dbg_log(SEC_0082_CSTRING, 5)(LOGSTDOUT, "cstring_erase_tail_str: %s\n", cstring->str);
    return (EC_TRUE);
}

EC_BOOL cstring_erase_tail_until(CSTRING *cstring, const UINT8 ch)
{
    UINT32 pos;
    UINT32 str_len;

    str_len = cstring->len;
    for(pos = str_len; pos -- > 0 && cstring->str[ pos ] != ch;)
    {
        /*do nothing*/
    }

    pos ++;

    if(str_len == pos)
    {
        return (EC_TRUE);
    }
    cstring->len = pos;
    cstring->str[ pos ] = '\0';

    return (EC_TRUE);
}

EC_BOOL cstring_ltrim(CSTRING *cstring, const UINT8 ch)
{
    UINT32 pos;
    UINT32 str_len;

    str_len = cstring->len;
    for(pos = 0; pos < str_len && cstring->str[ pos ] == ch; pos ++)
    {
        /*do nothing*/
    }

    if(0 == pos)
    {
        return (EC_TRUE);
    }

    return cstring_erase_sub_str(cstring, 0, pos);
}

EC_BOOL cstring_rtrim(CSTRING *cstring, const UINT8 ch)
{
    UINT32 pos;
    UINT32 str_len;

    str_len = cstring->len;
    for(pos = str_len; pos -- > 0 && cstring->str[ pos ] == ch;)
    {
        /*do nothing*/
    }

    pos ++;

    if(str_len == pos)
    {
        return (EC_TRUE);
    }
    cstring->len = pos;
    cstring->str[ pos ] = '\0';

    CSTRING_DEBUG(cstring);

    return (EC_TRUE);
}

EC_BOOL cstring_trim(CSTRING *cstring, const UINT8 ch)
{
    if(EC_FALSE == cstring_ltrim(cstring, ch))
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_rtrim(cstring, ch))
    {
        return (EC_FALSE);
    }

    CSTRING_DEBUG(cstring);

    return (EC_TRUE);
}

/*read content from fp and write into cstring, note: when have no chance to get file length when fp is pipe*/
UINT32 cstring_fread(CSTRING *cstring, FILE *fp)
{
    for(;;)
    {
        if(cstring->len == cstring->capacity)
        {
            /*expand cstring to accept left bytes in file*/
            if(EC_FALSE == cstring_expand(cstring, LOC_CSTRING_0019))
            {
                dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_fread: failed to expand cstring with capaciy %ld and len %ld\n",
                                cstring->capacity, cstring->len);
                return ((UINT32)-1);
            }
        }

        cstring->len += fread((char *)(cstring->str + cstring->len), sizeof(char), cstring->capacity - cstring->len, fp);
        if(cstring->len < cstring->capacity)/*ok, no more to read*/
        {
            cstring->str[ cstring->len ++ ] = '\0';
            break;
        }
    }
    return (0);
}

void cstring_print(LOG *log, const CSTRING *cstring)
{
    if(NULL_PTR == cstring)
    {
        sys_log(log, "(null)\n");
    }
    else if(0 == cstring->str)
    {
        sys_log(log, "cstring %p: capacity = %ld, len = %ld, str = <error:undefined string>\n",
                        cstring,
                        cstring->capacity,
                        cstring->len);
    }
    else if(0 == cstring->len)
    {
        sys_log(log, "cstring %p: capacity = %ld, len = %ld, str = <null>\n",
                        cstring,
                        cstring->capacity,
                        cstring->len);
    }
    else
    {
        sys_log(log, "cstring %p: capacity = %ld, len = %ld, str = %s\n",
                        cstring,
                        cstring->capacity,
                        cstring->len,
                        cstring->str);
    }
    return ;
}

EC_BOOL cstring_format(CSTRING *cstring, const char *format, ...)
{
    va_list ap;
    UINT32 len;

    va_start(ap, format);

    len = (UINT32)c_vformat_len(format, ap);

    if(EC_FALSE == cstring_expand_to(cstring, len + cstring->len + 1, LOC_CSTRING_0020))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_format: expand from %ld to %ld failed\n",
                    cstring->len, len + cstring->len + 1);
        va_end(ap);
        return (EC_FALSE);
    }

    len = vsnprintf((char *)(cstring->str + cstring->len), cstring->capacity - cstring->len, format, ap);
    cstring->len += len;
    //cstring->str[ len ] = '\0';
    va_end(ap);

    return (EC_TRUE);
}

EC_BOOL cstring_vformat(CSTRING *cstring, const char *format, va_list ap)
{
    UINT32 len;

    len = (UINT32)c_vformat_len(format, ap);

    if(EC_FALSE == cstring_expand_to(cstring, len + cstring->len + 1, LOC_CSTRING_0021))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_vformat: expand from %ld to %ld failed\n",
                    cstring->len, len + cstring->len + 1);
        return (EC_FALSE);
    }

    len = vsnprintf((char *)(cstring->str + cstring->len), cstring->capacity - cstring->len, format, ap);
    cstring->len += len;

    return (EC_TRUE);
}

CSTRING * cstring_load0(int fd, UINT32 *offset)
{
    UINT32   len;
    CSTRING *cstring;
    UINT8   *str;

    cstring = cstring_new(NULL_PTR, LOC_CSTRING_0022);
    if(NULL_PTR == cstring)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_load: new cstring failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_load(fd, offset, sizeof(UINT32), (UINT8 *)&len))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_load: load cstring len failed\n");
        cstring_free(cstring);
        return (NULL_PTR);
    }

    if(0 == len)
    {
        return (cstring);
    }

    str = (UINT8 *)SAFE_MALLOC(len + 1, LOC_CSTRING_0023);
    if(NULL_PTR == str)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_load: malloc %ld bytes failed\n", len + 1);
        cstring_free(cstring);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_load(fd, offset, len, (UINT8 *)str))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_load: load %ld bytes failed\n", len);
        SAFE_FREE(str, LOC_CSTRING_0024);
        cstring_free(cstring);
        return (NULL_PTR);
    }

    str[ len ] = '\0';

    cstring->str = (UINT8 *)str;
    cstring->len = len;
    cstring->capacity = len + 1;

    return (cstring);
}

EC_BOOL cstring_load(CSTRING *cstring, int fd, UINT32 *offset)
{
    UINT32   len;
    UINT8   *str;

    if(EC_FALSE == c_file_load(fd, offset, sizeof(UINT32), (UINT8 *)&len))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_load: load cstring len failed\n");
        return (EC_FALSE);
    }

    if(0 == len)
    {
        cstring_clean(cstring);
        return (EC_TRUE);
    }

    str = (UINT8 *)SAFE_MALLOC(len + 1, LOC_CSTRING_0025);
    if(NULL_PTR == str)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_load: malloc %ld bytes failed\n", len + 1);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_load(fd, offset, len, (UINT8 *)str))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_load: load %ld bytes failed\n", len);
        SAFE_FREE(str, LOC_CSTRING_0026);
        return (EC_FALSE);
    }

    cstring_clean(cstring);

    str[ len ] = '\0';

    cstring->str = (UINT8 *)str;
    cstring->len = len;
    cstring->capacity = len + 1;

    return (EC_TRUE);
}

EC_BOOL cstring_flush(const CSTRING *cstring, int fd, UINT32 *offset)
{
    UINT32   len;
    UINT8   *str;

    if(NULL_PTR == cstring)
    {
        len = 0;
        if(EC_FALSE == c_file_flush(fd, offset, sizeof(UINT32), (UINT8 *)&len))
        {
            dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_flush: flush null cstring failed\n");
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    len = cstring->len;
    if(EC_FALSE == c_file_flush(fd, offset, sizeof(UINT32), (UINT8 *)&len))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_flush: flush cstring len %ld failed\n", len);
        return (EC_FALSE);
    }

    if(0 == len)
    {
        return (EC_TRUE);
    }

    str = cstring->str;
    if(EC_FALSE == c_file_flush(fd, offset, len, str))
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_flush: flush %ld bytes failed\n", len);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}
#if 0
/***********************************************************************************************************************\
SYNOPSIS

       #include <pcre.h>

       pcre *pcre_compile(const char *pattern, int options,
            const char **errptr, int *erroffset,
            const unsigned char *tableptr);

DESCRIPTION

       This function compiles a regular expression into an internal form. Its arguments are:

         pattern       A zero-terminated string containing the
                         regular expression to be compiled
         options       Zero or more option bits
         errptr        Where to put an error message
         erroffset     Offset in pattern where error was found
         tableptr      Pointer to character tables, or NULL to
                         use the built-in default

       The option bits are:

         PCRE_ANCHORED         Force pattern anchoring
         PCRE_CASELESS         Do caseless matching
         PCRE_DOLLAR_ENDONLY   $ not to match newline at end
         PCRE_DOTALL           . matches anything including NL
         PCRE_EXTENDED         Ignore whitespace and # comments
         PCRE_EXTRA            PCRE extra features
                                 (not much use currently)
         PCRE_MULTILINE        ^ and $ match newlines within data
         PCRE_NO_AUTO_CAPTURE  Disable numbered capturing paren-
                                 theses (named ones available)
         PCRE_UNGREEDY         Invert greediness of quantifiers
         PCRE_UTF8             Run in UTF-8 mode
         PCRE_NO_UTF8_CHECK    Do not check the pattern for UTF-8
                                 validity (only relevant if
                                 PCRE_UTF8 is set)

       PCRE must be compiled with UTF-8 support in order to use PCRE_UTF8 (or PCRE_NO_UTF8_CHECK).

       The yield of the function is a pointer to a private data structure that contains the compiled pattern, or NULL if an error
       was detected.

       There is a complete description of the PCRE API in the pcreapi page.
\***********************************************************************************************************************/
/***********************************************************************************************************************\
NAME
       PCRE - Perl-compatible regular expressions

SYNOPSIS

       #include <pcre.h>

       int pcre_exec(const pcre *code, const pcre_extra *extra,
            const char *subject, int length, int startoffset,
            int options, int *ovector, int ovecsize);

DESCRIPTION

       This  function  matches  a  compiled  regular  expression against a given subject string, and returns offsets to capturing
       subexpressions. Its arguments are:

         code         Points to the compiled pattern
         extra        Points to an associated pcre_extra structure,
                        or is NULL
         subject      Points to the subject string
         length       Length of the subject string, in bytes
         startoffset  Offset in bytes in the subject at which to
                        start matching
         options      Option bits
         ovector      Points to a vector of ints for result offsets
         ovecsize     Size of the vector (a multiple of 3)

       The options are:

         PCRE_ANCHORED      Match only at the first position
         PCRE_NOTBOL        Subject is not the beginning of a line
         PCRE_NOTEOL        Subject is not the end of a line
         PCRE_NOTEMPTY      An empty string is not a valid match
         PCRE_NO_UTF8_CHECK Do not check the subject for UTF-8
                              validity (only relevant if PCRE_UTF8
                              was set at compile time)

       There is a complete description of the PCRE API in the pcreapi page.
\***********************************************************************************************************************/
EC_BOOL cstring_regex(const CSTRING *cstring, const CSTRING *pattern, CVECTOR *cvector_cstring)
{
    pcre            *re;
    const char      *error;
    int             erroffset;
    int             startoffset;
    int             option;
    int             ovector[CSTRING_OVEC_COUNT];
    int             rc;
    int             idx;

    startoffset = 0;
    option      = 0;

    re = pcre_compile((char *)(pattern->str), 0, &error, &erroffset, NULL_PTR);
    if (NULL_PTR == re)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_regex: PCRE compilation failed at offset %d: %s\n", erroffset, error);
        return (EC_FALSE);
    }

    rc = pcre_exec(re, NULL_PTR, (char *)(cstring->str), cstring->len, startoffset, option, ovector, CSTRING_OVEC_COUNT);
    if(PCRE_ERROR_NOMATCH == rc)
    {
        dbg_log(SEC_0082_CSTRING, 1)(LOGSTDOUT, "warn:cstring_regex: no matched\n");
        free(re);
        return (EC_TRUE);
    }

    if(0 > rc)
    {
        dbg_log(SEC_0082_CSTRING, 0)(LOGSTDOUT, "error:cstring_regex: matching error with str %s and pattern %s\n", (char *)(cstring->str), (char *)(pattern->str));
        free(re);
        return (EC_FALSE);
    }

    for (idx = 0; idx < rc; idx ++)
    {
        UINT32 from;
        UINT32 to;

        CSTRING *sub_cstring;

        from = ovector[ 2 * idx ];
        to   = ovector[ 2 * idx + 1];

        sub_cstring = cstring_new(NULL_PTR, LOC_CSTRING_0027);

        cstring_get_cstr(cstring, from, to, sub_cstring);

        cvector_push(cvector_cstring, (void *)sub_cstring);
    }

    return (EC_TRUE);
}
#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

