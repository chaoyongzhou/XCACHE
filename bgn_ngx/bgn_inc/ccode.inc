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

#ifndef _CCODE_INC
#define _CCODE_INC

#include "type.h"

#define HOST_BYTE_ODER_IS_LITTLE_ENDIAN  ((UINT32)  1)  /*low bit save to low address , e.g., 0x04030201, in memory addr low -> high is 0x1,0x2,0x3,0x4*/
#define HOST_BYTE_ODER_IS_BIG_ENDIAN     ((UINT32)  2)  /*low bit save to high address, e.g., 0x04030201, in memory addr low -> high is 0x4,0x3,0x2,0x1*/
#define HOST_BYTE_ODER_IS_UNKNOW_ENDIAN  ((UINT32) -1)

//#define DBG_ENCODING_RULE                ((UINT32) 1)
//#define BYTE_ENCODING_RULE               ((UINT32) 2)

typedef struct
{
    EC_BOOL (*code_pack)(const UINT8 *, const UINT32, const UINT32, UINT8 *, const UINT32, UINT32 *,  const UINT32);
    EC_BOOL (*code_pack_size)(const UINT32, const UINT32, UINT32 *,  const UINT32);
    EC_BOOL (*code_unpack)(const UINT8 *, const UINT32, UINT32 *, UINT8 *, const UINT32, const UINT32,  const UINT32);
}CODE_RULE;

#endif /*_CCODE_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
