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

#include "cbloom.h"

EC_BOOL cbloom_init(CBLOOM *cbloom)
{
    UINT32 word_num;
    UINT32 word_pos;

    word_num = NBITS_TO_NWORDS(CBLOOM_MAX_NBIT(cbloom));
    for(word_pos = 0; word_pos < word_num; word_pos ++)
    {
        CBLOOM_DATA(cbloom, word_pos) = 0;
    }

    return (EC_TRUE);
}

UINT32 *cbloom_data_area(const CBLOOM *cbloom)
{
    return ((UINT32 *)CBLOOM_DATA_BUFF(cbloom));
}

UINT32 cbloom_max_nbits(const CBLOOM *cbloom)
{
    return (CBLOOM_MAX_NBIT(cbloom));
}

EC_BOOL cbloom_set_bit(CBLOOM *cbloom, const UINT32 nth_bit)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 safe_nbit;

    safe_nbit   = (nth_bit % CBLOOM_MAX_NBIT(cbloom));
    word_offset = (safe_nbit / WORDSIZE);
    bit_offset  = (safe_nbit % WORDSIZE);

    CBLOOM_DATA(cbloom, word_offset) |= ( 1 << bit_offset );
    return (EC_TRUE);
}

UINT32 cbloom_set_bit_and_ret_old(CBLOOM *cbloom, const UINT32 nth_bit, UINT32 *ret_word_offset)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 safe_nbit;

    UINT32 old;

    safe_nbit   = (nth_bit % CBLOOM_MAX_NBIT(cbloom));
    word_offset = (safe_nbit / WORDSIZE);
    bit_offset  = (safe_nbit % WORDSIZE);

    old = ( CBLOOM_DATA(cbloom, word_offset) & ( 1 << bit_offset) );
    CBLOOM_DATA(cbloom, word_offset) |= ( 1 << bit_offset );

    (*ret_word_offset) = word_offset;

    return (old);
}

UINT32 cbloom_get_bit(const CBLOOM *cbloom, const UINT32 nth_bit)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 safe_nbit;

    safe_nbit   = (nth_bit % CBLOOM_MAX_NBIT(cbloom));
    word_offset = (safe_nbit / WORDSIZE);
    bit_offset  = (safe_nbit % WORDSIZE);

    if ( 0 < ( CBLOOM_DATA(cbloom, word_offset) & ( 1 << bit_offset) ))
    {
        return (1);
    }
    return (0);
}

EC_BOOL cbloom_check_bit(const CBLOOM *cbloom, const UINT32 nth_bit)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 safe_nbit;

    safe_nbit   = (nth_bit % CBLOOM_MAX_NBIT(cbloom));
    word_offset = (safe_nbit / WORDSIZE);
    bit_offset  = (safe_nbit % WORDSIZE);

    if ( 0 < ( CBLOOM_DATA(cbloom, word_offset) & ( 1 << bit_offset) ))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbloom_next_unset_bit(const CBLOOM *cbloom, UINT32 *nth_bit)
{
    UINT32 word_offset;
    UINT32 bit_offset;
    UINT32 safe_nbit;

    safe_nbit = (*nth_bit) + 1;/*move forward*/

    for(word_offset = (safe_nbit / WORDSIZE); safe_nbit <= CBLOOM_MAX_NBIT(cbloom); word_offset ++, safe_nbit += WORDSIZE)
    {
        if((UINT32)-1 != CBLOOM_DATA(cbloom, word_offset))/*not all bits were set*/
        {
            break;
        }
    }

    for(bit_offset = (safe_nbit % WORDSIZE); bit_offset < WORDSIZE && safe_nbit <= CBLOOM_MAX_NBIT(cbloom); bit_offset ++, safe_nbit ++)
    {
        if (0 == ( CBLOOM_DATA(cbloom, word_offset) & ( 1 << bit_offset) ))/*found unset*/
        {
            (*nth_bit) = safe_nbit;
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

UINT32 cbloom_word_offset(const CBLOOM *cbloom, const UINT32 nth_bit)
{
    UINT32 word_offset;
    UINT32 safe_nbit;

    safe_nbit   = (nth_bit % CBLOOM_MAX_NBIT(cbloom));
    word_offset = (safe_nbit / WORDSIZE);

    return (word_offset);
}

STATIC_CAST static void cbloom_uint32_bitmap_header(LOG *log)
{
    UINT32 pos;

#if (32 == WORDSIZE)
    sys_print(log, "%8s %8s", "#", "HEX");
    for(pos = 0; pos < WORDSIZE; pos ++)
    {
        sys_print(log, "%2d ", pos);
    }
    sys_print(log, "\n");
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
    sys_print(log, "%8s %8s", "#", "HEX");
    for(pos = 0; pos < 32; pos ++)
    {
        sys_print(log, "%2d ", pos);
    }
    sys_print(log, "\n");

    sys_print(log, "%8s %8s", " ", " ");
    for(; pos < WORDSIZE; pos ++)
    {
        sys_print(log, "%2d ", pos);
    }
    sys_print(log, "\n");
#endif/*(64 == WORDSIZE)*/
    return;
}

STATIC_CAST static void cbloom_uint32_bitmap_print(LOG *log, const UINT32 num)
{
    UINT32 pos;
    UINT32 data;

#if (32 == WORDSIZE)
    data = num;
    sys_print(log, "%8lx ", data);
    for(pos = 0; pos < WORDSIZE; pos ++)
    {
        sys_print(log, "%2d ", (data & 1));/*from low bit to high bit*/
        data >>= 1;
    }
    sys_print(log, "\n");
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
    data = (num & 0xFFFFFFFF);
    sys_print(log, "%8lx ", data);
    for(pos = 0; pos < 32; pos ++)
    {
        sys_print(log, "%2d ", (data & 1));/*from low bit to high bit*/
        data >>= 1;
    }
    sys_print(log, "\n");

    data = (num >> 32);
    sys_print(log, "%8s %8lx ", " ", data);
    for(pos = 0; pos < 32; pos ++)
    {
        sys_print(log, "%2d ", (data & 1));/*from low bit to high bit*/
        data >>= 1;
    }
    sys_print(log, "\n");
#endif/*(64 == WORDSIZE)*/
    return;
}

void cbloom_print(LOG *log, const CBLOOM *cbloom)
{
    UINT32 pos;
    UINT32 word_num;

    word_num = (CBLOOM_MAX_NBIT(cbloom) + WORDSIZE - 1) / WORDSIZE;

    sys_log(log, "cbloom %lx: len = %ld, data bitmap:\n", cbloom, CBLOOM_MAX_NBIT(cbloom));
    cbloom_uint32_bitmap_header(log);
    for(pos = 0; pos < word_num; pos ++)
    {
        //sys_print(log, "%lx, ", CBLOOM_DATA(cbloom, pos));
        sys_print(log, "%8ld ", pos);
        cbloom_uint32_bitmap_print(log, CBLOOM_DATA(cbloom, pos));
    }
    sys_print(log, "\n");
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

