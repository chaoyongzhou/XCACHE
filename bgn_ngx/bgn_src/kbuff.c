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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <errno.h>

#include "type.h"

#include "log.h"

#include "kbuff.h"
#include "log.h"
#include "mm.h"

#define KBUFF_PRINT_BLOCK_WIDETH      8
#define KBUFF_PRINT_LINE_WIDETH      32

EC_BOOL kbuff_init(KBUFF *kbuff, const UINT32 size)
{
    UINT8 *cache;

    if(0 == size)
    {
        KBUFF_CACHE(kbuff)     = NULL_PTR;
        KBUFF_MAX_LEN(kbuff)   = 0;
        KBUFF_CUR_LEN(kbuff)   = 0;
        return (EC_TRUE);
    }

    cache = (UINT8 *)SAFE_MALLOC(size, LOC_KBUFF_0001);
    if(NULL_PTR == cache)
    {
        dbg_log(SEC_0094_KBUFF, 0)(LOGSTDOUT, "error:kbuff_init: failed to alloc %ld bytes\n", size);
        return (EC_FALSE);
    }

    KBUFF_CACHE(kbuff)     = cache;
    KBUFF_MAX_LEN(kbuff)   = size;
    KBUFF_CUR_LEN(kbuff)   = 0;
    return (EC_TRUE);
}

KBUFF * kbuff_new(const UINT32 size)
{
    KBUFF *kbuff;

    kbuff = (KBUFF *)SAFE_MALLOC(sizeof(KBUFF), LOC_KBUFF_0002);
    if(NULL_PTR == kbuff)
    {
        dbg_log(SEC_0094_KBUFF, 0)(LOGSTDOUT, "error:kbuff_new: failed to alloc KBUFF\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == kbuff_init(kbuff, size))
    {
        SAFE_FREE(kbuff, LOC_KBUFF_0003);
        return (NULL_PTR);
    }
    return (kbuff);
}

EC_BOOL kbuff_clean(KBUFF *kbuff)
{
    if(NULL_PTR != KBUFF_CACHE(kbuff))
    {
        SAFE_FREE(KBUFF_CACHE(kbuff), LOC_KBUFF_0004);
        KBUFF_CACHE(kbuff) = NULL_PTR;
    }
    KBUFF_MAX_LEN(kbuff) = 0;
    KBUFF_CUR_LEN(kbuff) = 0;
    return (EC_TRUE);
}

EC_BOOL kbuff_reset(KBUFF *kbuff)
{
    KBUFF_CUR_LEN(kbuff) = 0;
    return (EC_TRUE);
}

EC_BOOL kbuff_free(KBUFF *kbuff)
{
    if(NULL_PTR != kbuff)
    {
        kbuff_clean(kbuff);
        SAFE_FREE(kbuff, LOC_KBUFF_0005);
    }
    return (EC_TRUE);
}

EC_BOOL kbuff_resize(KBUFF *kbuff, const UINT32 size)
{
    UINT8 *   cache;

    if(NULL_PTR == KBUFF_CACHE(kbuff))
    {
        return kbuff_init(kbuff, size);
    }

    if(size <= KBUFF_MAX_LEN(kbuff))
    {
        return (EC_TRUE);
    }

    cache = (UINT8 *)SAFE_REALLOC(KBUFF_CACHE(kbuff), KBUFF_MAX_LEN(kbuff), size, LOC_KBUFF_0006);
    if(NULL_PTR == cache)
    {
        dbg_log(SEC_0094_KBUFF, 0)(LOGSTDOUT, "error:kbuff_resize: failed resize from %ld to %ld\n", KBUFF_MAX_LEN(kbuff), size);
        return (EC_FALSE);
    }
    KBUFF_CACHE(kbuff) = cache;
    return (EC_TRUE);
}

EC_BOOL kbuff_init_0(KBUFF *kbuff)
{
    KBUFF_CACHE(kbuff)     = NULL_PTR;
    KBUFF_MAX_LEN(kbuff)   = 0;
    KBUFF_CUR_LEN(kbuff)   = 0;
    return (EC_TRUE);
}

EC_BOOL kbuff_clean_0(KBUFF *kbuff)
{
    if(NULL_PTR != KBUFF_CACHE(kbuff))
    {
        SAFE_FREE(KBUFF_CACHE(kbuff), LOC_KBUFF_0007);
        KBUFF_CACHE(kbuff) = NULL_PTR;
    }

    KBUFF_MAX_LEN(kbuff) = 0;
    KBUFF_CUR_LEN(kbuff) = 0;
    return (EC_TRUE);
}

void kbuff_free_0(KBUFF *kbuff)
{
    kbuff_free(kbuff);
    return;
}

static void kbuff_print_one_char_with_alignment(LOG *log, const UINT8 ch, const UINT32 count)
{
    sys_print(LOGSTDOUT, "%02x ", ch);

    if(0 == (count % KBUFF_PRINT_BLOCK_WIDETH) && 0 != (count % KBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "   ");
    }
    if(0 == (count % KBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "\n");
    }
    return;
}

static void kbuff_print_end_with_alignment(LOG *log, const UINT32 count)
{
    if(0 != (count % KBUFF_PRINT_LINE_WIDETH))
    {
        sys_print(log, "\n");
    }
    return;
}


static void kbuff_print_cache(LOG *log, const KBUFF *kbuff)
{
    UINT32 pos;
    UINT32 count;

    dbg_log(SEC_0094_KBUFF, 5)(LOGSTDOUT, "kbuff %lx: whole cache: \n", kbuff);
    for(count = 1, pos = 0; pos < KBUFF_CUR_LEN(kbuff); count ++, pos ++)
    {
        kbuff_print_one_char_with_alignment(log, KBUFF_CACHE_CHAR(kbuff, pos), count);
    }
    kbuff_print_end_with_alignment(log, count);

    return;
}

void kbuff_print(LOG *log, const KBUFF *kbuff)
{
    dbg_log(SEC_0094_KBUFF, 5)(LOGSTDOUT, "kbuff %lx: max_len = %ld, cur_len = %ld\n", kbuff, KBUFF_MAX_LEN(kbuff), KBUFF_CUR_LEN(kbuff));

    if( 0 == KBUFF_CUR_LEN(kbuff))
    {
        dbg_log(SEC_0094_KBUFF, 5)(LOGSTDOUT, "kbuff %lx: cache: (null)\n"      , kbuff);
        return;
    }

    kbuff_print_cache(log, kbuff);

    dbg_log(SEC_0094_KBUFF, 5)(LOGSTDOUT, "max len: %ld\n", KBUFF_MAX_LEN(kbuff));
    dbg_log(SEC_0094_KBUFF, 5)(LOGSTDOUT, "cur len: %ld\n", KBUFF_CUR_LEN(kbuff));
    return;
}

UINT32 kbuff_max_len(const KBUFF *kbuff)
{
    return KBUFF_MAX_LEN(kbuff);
}

UINT32 kbuff_cur_len(const KBUFF *kbuff)
{
    return KBUFF_CUR_LEN(kbuff);
}

UINT8 *kbuff_cache(const KBUFF *kbuff)
{
    return (UINT8 *)KBUFF_CACHE(kbuff);
}

EC_BOOL kbuff_read(const KBUFF *kbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    UINT32 pos;

    /*when KBUFF_READ_POS = KBUFF_WRITE_POS, KBUFF is empty, no data to read*/
    for(pos = (*out_buff_pos); pos < out_buff_max_len &&  pos < KBUFF_CUR_LEN(kbuff); pos ++)
    {
        out_buff[ pos ] = KBUFF_CACHE_CHAR(kbuff, pos);
    }

    (*out_buff_pos) = pos;
    return (EC_TRUE);
}

EC_BOOL kbuff_write(KBUFF *kbuff, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos)
{
    UINT32 src_pos;
    UINT32 des_pos;

    if(0 == KBUFF_MAX_LEN(kbuff))
    {
        dbg_log(SEC_0094_KBUFF, 0)(LOGSTDOUT, "error:kbuff_write: kbuff %lx is empty\n", kbuff);
        return (EC_FALSE);
    }

    for(src_pos = KBUFF_CUR_LEN(kbuff), des_pos = (*in_buff_pos); src_pos < KBUFF_MAX_LEN(kbuff) &&  des_pos < in_buff_max_len; src_pos ++, des_pos ++)
    {
         KBUFF_CACHE_CHAR(kbuff, src_pos) = in_buff[ des_pos ];
    }

    KBUFF_CUR_LEN(kbuff) = src_pos;
    (*in_buff_pos)       = des_pos;
    return (EC_TRUE);
}

EC_BOOL kbuff_fread(KBUFF *kbuff, const UINT32 size, FILE *fp)
{
    UINT32 read_bytes;

    if(0 == KBUFF_MAX_LEN(kbuff))
    {
        kbuff_init(kbuff, 0);
    }

    if(EC_FALSE == kbuff_resize(kbuff, KBUFF_CUR_LEN(kbuff) + size))
    {
        dbg_log(SEC_0094_KBUFF, 1)(LOGSTDOUT, "warn:kbuff_fread: kbuff %lx with max_len = %ld, cur_len = %ld failed to resize to accept %ld bytes\n",
                           kbuff, KBUFF_MAX_LEN(kbuff), KBUFF_CUR_LEN(kbuff), size);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0094_KBUFF, 3)(LOGSTDOUT, "info:kbuff_fread: kbuff %lx, cur_len = %ld, max_len = %ld, size = %ld, fp = %lx\n", kbuff, KBUFF_CUR_LEN(kbuff), KBUFF_MAX_LEN(kbuff), size, fp);

    read_bytes = fread(KBUFF_CACHE(kbuff) + KBUFF_CUR_LEN(kbuff), 1, size, fp);
    KBUFF_CUR_LEN(kbuff) += read_bytes;
    return (EC_TRUE);
}

EC_BOOL kbuff_fwrite(const KBUFF *kbuff, FILE *fp, UINT32 *pos)
{
    UINT32 write_bytes;

    if(KBUFF_CUR_LEN(kbuff) <= (*pos))
    {
        dbg_log(SEC_0094_KBUFF, 1)(LOGSTDOUT, "warn:kbuff_fwrite: kbuff %lx with %ld bytes cannot reach position %ld\n", kbuff, KBUFF_CUR_LEN(kbuff), (*pos));
        return (EC_FALSE);
    }

    //dbg_log(SEC_0094_KBUFF, 3)(LOGSTDOUT, "info:kbuff_fwrite: kbuff %lx, cur_len = %ld, max_len = %ld, pos = %ld, fp = %lx\n", kbuff, KBUFF_CUR_LEN(kbuff), KBUFF_MAX_LEN(kbuff), (*pos), fp);

    write_bytes = fwrite(KBUFF_CACHE(kbuff) + (*pos), 1, KBUFF_CUR_LEN(kbuff) - (*pos), fp);
    (*pos) += write_bytes;
    return (EC_TRUE);
}

/*shift out tail data block*/
EC_BOOL kbuff_shift(KBUFF *kbuff, const UINT32 max_shift_data_num, UINT32 *shift_out_data_num)
{
    if(KBUFF_CUR_LEN(kbuff) <= max_shift_data_num)
    {
        (*shift_out_data_num) = KBUFF_CUR_LEN(kbuff);
        KBUFF_CUR_LEN(kbuff)  = 0;
        return (EC_TRUE);
    }

    (*shift_out_data_num) = max_shift_data_num;
    KBUFF_CUR_LEN(kbuff) -= max_shift_data_num;

    return (EC_TRUE);
}

EC_BOOL kbuff_is_full(const KBUFF *kbuff)
{
    if(KBUFF_CUR_LEN(kbuff) >= KBUFF_MAX_LEN(kbuff))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL kbuff_xchg(KBUFF *src_kbuff, KBUFF *des_kbuff)
{
    UINT32    cur_len;
    UINT32    max_len;
    UINT8 *   cache;;

    cur_len = KBUFF_CUR_LEN(src_kbuff);
    max_len = KBUFF_MAX_LEN(src_kbuff);
    cache   = KBUFF_CACHE(src_kbuff);

    KBUFF_CUR_LEN(des_kbuff) = KBUFF_CUR_LEN(src_kbuff);
    KBUFF_MAX_LEN(des_kbuff) = KBUFF_MAX_LEN(src_kbuff);
    KBUFF_CACHE(des_kbuff)   = KBUFF_CACHE(src_kbuff);

    KBUFF_CUR_LEN(src_kbuff) = cur_len;
    KBUFF_MAX_LEN(src_kbuff) = max_len;
    KBUFF_CACHE(src_kbuff)   = cache;

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

