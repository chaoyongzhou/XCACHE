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

#ifndef _CCODE_H
#define _CCODE_H

#include "type.h"
#include "log.h"

#include "ccode.inc"
#include "cdbgcode.h"
#include "cbytecode.h"

#define cmpi_pack           cbytecode_pack
#define cmpi_pack_size      cbytecode_pack_size
#define cmpi_unpack         cbytecode_unpack

extern UINT32 g_host_byte_order;

#define HOST_IS_LITTLE_ENDIAN() (HOST_BYTE_ODER_IS_LITTLE_ENDIAN == (g_host_byte_order))
#define HOST_IS_BIG_ENDIAN()    (HOST_BYTE_ODER_IS_BIG_ENDIAN == (g_host_byte_order))
#define HOST_ENDIAN()           (g_host_byte_order)

EC_BOOL init_host_endian();

void print_host_endian(LOG *log);

void print_uint8_buff(LOG *log, const UINT8 *buff, const UINT32 len);

void print_uint16_buff(LOG *log, const UINT16 *buff, const UINT32 len);

void print_uint32_buff(LOG *log, const UINT32 *buff, const UINT32 len);

void print_real_buff(LOG *log, const REAL *buff, const UINT32 len);

void print_char_buff(LOG *log, const UINT8 *buff, const UINT32 len);

#endif /*_CCODE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
