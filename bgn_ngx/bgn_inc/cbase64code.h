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

#ifndef _CBASE64CODE_H
#define _CBASE64CODE_H

#include "type.h"

EC_BOOL cbase64_encode(const UINT8 *in, const UINT32 inlen, UINT8 *out, const UINT32 max_outlen, UINT32 *outlen);

EC_BOOL cbase64_decode(const UINT8 *in, const UINT32 inlen, UINT8 *out, const UINT32 max_outlen, UINT32 *outlen);

EC_BOOL cbase64_encode_size(const UINT32 inlen, UINT32 *outlen);

#endif /*_CBASE64CODE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

