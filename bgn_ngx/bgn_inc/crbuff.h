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

#ifndef _CRBUFF_H
#define _CRBUFF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "type.h"
#include "taskcfg.inc"

/**
*
*   when read_pos == write_pos, cache is empty
*   when write_pos - read_pos = max_len, cache is full
*   in fact, always satisfy
*      write_pos >= read_pos,
*   and
*      max_len >= write_pos - read_pos
*   when write_pos >= read_pos >= max_len, reduce write_pos, read_pos by
*      write_pos = write_pos - max_len,
*      read_pos  = read_pos  - max_len
*
**/

typedef struct
{
    UINT32    read_pos;
    UINT32    write_pos;
    UINT32    max_len;
    UINT8     cache[0];
}CRBUFF;

#define CRBUFF_READ_POS(crbuff)                ((crbuff)->read_pos)
#define CRBUFF_WRITE_POS(crbuff)               ((crbuff)->write_pos)
#define CRBUFF_MAX_LEN(crbuff)                 ((crbuff)->max_len)
#define CRBUFF_CACHE(crbuff)                   ((crbuff)->cache)
#define CRBUFF_CACHE_CHAR(crbuff, pos)         ((crbuff)->cache[ (pos) ])

EC_BOOL  crbuff_init(CRBUFF *crbuff);
CRBUFF * crbuff_new(const UINT32 size);
EC_BOOL  crbuff_clean(CRBUFF *crbuff);
EC_BOOL  crbuff_reset(CRBUFF *crbuff);
EC_BOOL  crbuff_free(CRBUFF *crbuff);
EC_BOOL  crbuff_set_max_len(CRBUFF *crbuff, const UINT32 size);
UINT32   crbuff_get_max_len(const CRBUFF *crbuff);
void     crbuff_print(LOG *log, const CRBUFF *crbuff);

UINT32   crbuff_total_write_len(const CRBUFF *crbuff);
UINT32   crbuff_total_read_len(const CRBUFF *crbuff);

UINT32   crbuff_once_write_len(const CRBUFF *crbuff);
UINT32   crbuff_once_read_len(const CRBUFF *crbuff);

EC_BOOL  crbuff_pos_reduce(CRBUFF *crbuff);

EC_BOOL  crbuff_read(CRBUFF *crbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos);
EC_BOOL  crbuff_write(CRBUFF *crbuff, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos);
EC_BOOL crbuff_shift(CRBUFF *crbuff, const UINT32 max_shift_data_num, UINT32 *shift_out_data_num);

EC_BOOL  crbuff_is_full(const CRBUFF *crbuff);
EC_BOOL  crbuff_socket_recv(CRBUFF *crbuff, int sockfd);

EC_BOOL crbuff_probe(const CRBUFF *crbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos);

#endif/*_CRBUFF_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
