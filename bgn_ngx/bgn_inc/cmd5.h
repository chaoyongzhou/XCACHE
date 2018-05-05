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

#ifndef _CMD5_H
#define _CMD5_H

/*
 * This is the header file for the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 */

#include "type.h"

#define CMD5_DIGEST_LEN         (16)

typedef struct
{
    uint32_t buf[4];
    uint32_t bytes[2];
    uint32_t in[16];
} CMD5_CTX;

typedef struct
{
    uint8_t sum[ CMD5_DIGEST_LEN ];
}CMD5_DIGEST;
#define CMD5_DIGEST_SUM(md5sum)  ((md5sum)->sum)

void cmd5_init(CMD5_CTX *context);
void cmd5_update(CMD5_CTX *context, const void *buf, unsigned len);
void cmd5_final(uint8_t digest[16], CMD5_CTX *context);
void cmd5_transform(uint32_t buf[4], uint32_t const in[16]);
EC_BOOL cmd5_sum(const uint32_t data_len, const uint8_t *data, uint8_t digest[ CMD5_DIGEST_LEN ]);

CMD5_DIGEST *cmd5_digest_new();

EC_BOOL cmd5_digest_init(CMD5_DIGEST *cmd5_digest);

EC_BOOL cmd5_digest_clean(CMD5_DIGEST *cmd5_digest);

EC_BOOL cmd5_digest_clone(const CMD5_DIGEST *cmd5_digest_src, CMD5_DIGEST *cmd5_digest_des);

EC_BOOL cmd5_digest_free(CMD5_DIGEST *cmd5_digest);

EC_BOOL cmd5_digest_is_equal(const CMD5_DIGEST *cmd5_digest_1st, const CMD5_DIGEST *cmd5_digest_2nd);
int     cmd5_digest_cmp(const CMD5_DIGEST *cmd5_digest_1st, const CMD5_DIGEST *cmd5_digest_2nd);

char   *cmd5_digest_hex_str(const CMD5_DIGEST *cmd5_digest);

void    cmd5_digest_print(LOG *log, const CMD5_DIGEST *cmd5_digest);

#endif /* _CMD5_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

