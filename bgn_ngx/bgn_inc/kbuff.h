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

#ifndef _KBUFF_H
#define _KBUFF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "type.h"
#include "cvector.h"
#include "log.h"

typedef struct
{
    UINT32    cur_len;
    UINT32    max_len;
    UINT8 *   cache;
}KBUFF;

#define KBUFF_CUR_LEN(kbuff)                 ((kbuff)->cur_len)
#define KBUFF_MAX_LEN(kbuff)                 ((kbuff)->max_len)
#define KBUFF_CACHE(kbuff)                   ((kbuff)->cache)
#define KBUFF_CACHE_CHAR(kbuff, pos)         ((kbuff)->cache[ (pos) ])

EC_BOOL kbuff_init(KBUFF *kbuff, const UINT32 size);

KBUFF * kbuff_new(const UINT32 size);

EC_BOOL kbuff_clean(KBUFF *kbuff);

EC_BOOL kbuff_reset(KBUFF *kbuff);

EC_BOOL kbuff_free(KBUFF *kbuff);

EC_BOOL kbuff_resize(KBUFF *kbuff, const UINT32 size);

EC_BOOL kbuff_init_0(KBUFF *kbuff);

EC_BOOL kbuff_clean_0(KBUFF *kbuff);

void kbuff_free_0(KBUFF *kbuff);

void    kbuff_print(LOG *log, const KBUFF *kbuff);

UINT32  kbuff_max_len(const KBUFF *kbuff);

UINT32  kbuff_cur_len(const KBUFF *kbuff);

UINT8 * kbuff_cache(const KBUFF *kbuff);

EC_BOOL kbuff_read(const KBUFF *kbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos);

EC_BOOL kbuff_write(KBUFF *kbuff, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos);

EC_BOOL kbuff_fread(KBUFF *kbuff, const UINT32 size, FILE *fp);

EC_BOOL kbuff_fwrite(const KBUFF *kbuff, FILE *fp, UINT32 *pos);

/*shift out tail data block*/
EC_BOOL kbuff_shift(KBUFF *kbuff, const UINT32 max_shift_data_num, UINT32 *shift_out_data_num);

EC_BOOL kbuff_is_full(const KBUFF *kbuff);

EC_BOOL kbuff_xchg(KBUFF *src_kbuff, KBUFF *des_kbuff);

#endif/*_KBUFF_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
