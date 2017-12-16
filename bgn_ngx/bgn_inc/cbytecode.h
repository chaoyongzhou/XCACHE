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

#ifndef _CBYTECODE_H
#define _CBYTECODE_H

#include "type.h"

EC_BOOL cbytecode_pack_uint64(const uint64_t *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL cbytecode_pack_uint64_size(const UINT32 data_num, UINT32 *size);
EC_BOOL cbytecode_unpack_uint64(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, uint64_t *out_buff, const UINT32 data_num);

EC_BOOL cbytecode_pack_uint32(const UINT32 *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL cbytecode_pack_uint32_size(const UINT32 data_num, UINT32 *size);
EC_BOOL cbytecode_unpack_uint32(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *out_buff, const UINT32 data_num);

EC_BOOL cbytecode_pack_uint32_t(const UINT32 *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL cbytecode_pack_uint32_t_size(const UINT32 data_num, UINT32 *size);
EC_BOOL cbytecode_unpack_uint32_t(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *out_buff, const UINT32 data_num);

EC_BOOL cbytecode_pack_uint16(const UINT16 *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL cbytecode_pack_uint16_size(const UINT32 data_num, UINT32 *size);
EC_BOOL cbytecode_unpack_uint16(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT16 *out_buff, const UINT32 data_num);

EC_BOOL cbytecode_pack_uint8(const UINT8 *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL cbytecode_pack_uint8_size(const UINT32 data_num, UINT32 *size);
EC_BOOL cbytecode_unpack_uint8(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *out_buff, const UINT32 data_num);

EC_BOOL cbytecode_pack_real(const REAL *in_buff, const UINT32 data_num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL cbytecode_pack_real_size(const UINT32 data_num, UINT32 *size);
EC_BOOL cbytecode_unpack_real(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, REAL *out_buff, const UINT32 data_num);

EC_BOOL cbytecode_pack(const UINT8 *in_buff, const UINT32 data_num, const UINT32 data_type, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position, const UINT32 comm);
EC_BOOL cbytecode_unpack(const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *out_buff, const UINT32 data_num, const UINT32 data_type, const UINT32 comm);
EC_BOOL cbytecode_pack_size(const UINT32 data_num, const UINT32 data_type, UINT32 *size, const UINT32 comm);

#endif /*_CBYTECODE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

