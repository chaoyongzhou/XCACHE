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

#ifndef _CBLOOM_H
#define _CBLOOM_H

#include "type.h"

typedef struct
{
    UINT32  max_nbit;
    UINT32  data_buff[0];
}CBLOOM;

#define CBLOOM_MAX_NBIT(cbloom)        ((cbloom)->max_nbit)
#define CBLOOM_DATA_BUFF(cbloom)       ((cbloom)->data_buff)
#define CBLOOM_DATA(cbloom, pos)       (CBLOOM_DATA_BUFF(cbloom)[ (pos) ])

EC_BOOL cbloom_init(CBLOOM *cbloom);

UINT32 *cbloom_data_area(const CBLOOM *cbloom);

UINT32 cbloom_max_nbits(const CBLOOM *cbloom);

EC_BOOL cbloom_set_bit(CBLOOM *cbloom, const UINT32 nth_bit);

UINT32 cbloom_get_bit(const CBLOOM *cbloom, const UINT32 nth_bit);

EC_BOOL cbloom_check_bit(const CBLOOM *cbloom, const UINT32 nth_bit);

EC_BOOL cbloom_next_unset_bit(const CBLOOM *cbloom, UINT32 *nth_bit);

UINT32 cbloom_word_offset(const CBLOOM *cbloom, const UINT32 nth_bit);

UINT32 cbloom_set_bit_and_ret_old(CBLOOM *cbloom, const UINT32 nth_bit, UINT32 *ret_word_offset);

void cbloom_print(LOG *log, const CBLOOM *cbloom);

#endif/* _CBLOOM_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

