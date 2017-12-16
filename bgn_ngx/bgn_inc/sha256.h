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

#ifndef _SHA256_H
#define _SHA256_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "type.h"
#include "log.h"

typedef struct
{
    UINT32 total[2];
    UINT32 state[8];
    UINT8 buffer[64];
}sha256_context;

void sha256_starts( sha256_context *ctx );
void sha256_update( sha256_context *ctx, UINT8 *input, UINT32 length );
void sha256_finish( sha256_context *ctx, UINT8 digest[32] );

void do_sha256(const UINT8 *message,int size, UINT8 sha256sum[32]);

void sha256_print(LOG *log, const UINT8 sha256sum[32]);

#endif /* sha256.h */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

