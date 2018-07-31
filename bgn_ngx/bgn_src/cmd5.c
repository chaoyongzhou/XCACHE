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

/*
 * This code implements the MD5 message-digest algorithm.
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

#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "type.h"
#include "cmd5.h"
#include "mm.h"
#include "cmpic.inc"

#if (__BYTE_ORDER == __BIG_ENDIAN)
void cmd5_byteswap(uint32_t * buf, unsigned words)
{
    uint8_t *p = (uint8_t *) buf;

    do
    {
        *buf++ = (uint32_t) ((unsigned) p[3] << 8 | p[2]) << 16 |
                 ((unsigned) p[1] << 8 | p[0]);
        p += 4;
    }while (--words);

    return;
}
#endif/*(__BYTE_ORDER == __BIG_ENDIAN)*/

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#define cmd5_byteswap(buf,words)
#endif/*(__BYTE_ORDER == __LITTLE_ENDIAN)*/

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void cmd5_init(CMD5_CTX *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bytes[0] = 0;
    ctx->bytes[1] = 0;
    return;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void cmd5_update(CMD5_CTX *ctx, const void *_buf, unsigned len)
{
    uint8_t const *buf = _buf;
    uint32_t t;

    /* Update byte count */

    t = ctx->bytes[0];
    if ((ctx->bytes[0] = t + len) < t)
        ctx->bytes[1]++;    /* Carry from low to high */

    t = 64 - (t & 0x3f);    /* Space available in ctx->in (at least 1) */
    if (t > len)
    {
        BCOPY(buf, (uint8_t *) ctx->in + 64 - t, len);
        return;
    }
    /* First chunk is an odd size */
    BCOPY(buf, (uint8_t *) ctx->in + 64 - t, t);
    cmd5_byteswap(ctx->in, 16);
    cmd5_transform(ctx->buf, ctx->in);
    buf += t;
    len -= t;

    /* Process data in 64-byte chunks */
    while (len >= 64)
    {
        BCOPY(buf, ctx->in, 64);
        cmd5_byteswap(ctx->in, 16);
        cmd5_transform(ctx->buf, ctx->in);
        buf += 64;
        len -= 64;
    }

    /* Handle any remaining bytes of data. */
    BCOPY(buf, ctx->in, len);

    return;
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void cmd5_final(uint8_t digest[16], CMD5_CTX *ctx)
{
    int count = ctx->bytes[0] & 0x3f;    /* Number of bytes in ctx->in */
    uint8_t *p = (uint8_t *) ctx->in + count;

    /* Set the first char of padding to 0x80.  There is always room. */
    *p++ = 0x80;

    /* Bytes of padding needed to make 56 bytes (-8..55) */
    count = 56 - 1 - count;

    if (count < 0)          /* Padding forces an extra block */
    {
        BSET(p, 0, count + 8);
        cmd5_byteswap(ctx->in, 16);
        cmd5_transform(ctx->buf, ctx->in);
        p = (uint8_t *) ctx->in;
        count = 56;
    }
    BSET(p, 0, count);
    cmd5_byteswap(ctx->in, 14);

    /* Append length in bits and transform */
    ctx->in[14] = (ctx->bytes[0] << 3);
    ctx->in[15] = ((ctx->bytes[1] << 3) | (ctx->bytes[0] >> 29));
    cmd5_transform(ctx->buf, ctx->in);

    cmd5_byteswap(ctx->buf, 4);
    BCOPY(ctx->buf, digest, 16);
    BSET(ctx, 0, sizeof(CMD5_CTX));    /* In case it's sensitive */
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f,w,x,y,z,in,s) \
     (w += f(x,y,z) + in, w = (w<<s | w>>(32-s)) + x)

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  cmd5_update blocks
 * the data and converts bytes into longwords for this routine.
 */
void cmd5_transform(uint32_t buf[4], uint32_t const in[16])
{
    register uint32_t a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;

    return;
}

EC_BOOL cmd5_sum(const uint32_t data_len, const uint8_t *data, uint8_t digest[ CMD5_DIGEST_LEN ])
{
    CMD5_CTX md5;

    cmd5_init(&md5);
    cmd5_update(&md5, (uint8_t *) data, data_len);
    cmd5_final(digest, &md5);

    return (EC_TRUE);
}

CMD5_DIGEST *cmd5_digest_new()
{
    CMD5_DIGEST *cmd5_digest;

    alloc_static_mem(MM_CMD5_DIGEST, &cmd5_digest, LOC_CMD5_0001);
    if(NULL_PTR != cmd5_digest)
    {
        cmd5_digest_init(cmd5_digest);
    }
    return (cmd5_digest);
}

EC_BOOL cmd5_digest_init(CMD5_DIGEST *cmd5_digest)
{
    BSET(CMD5_DIGEST_SUM(cmd5_digest), 0, CMD5_DIGEST_LEN);
    return (EC_TRUE);
}

EC_BOOL cmd5_digest_clean(CMD5_DIGEST *cmd5_digest)
{
    BSET(CMD5_DIGEST_SUM(cmd5_digest), 0, CMD5_DIGEST_LEN);
    return (EC_TRUE);
}

EC_BOOL cmd5_digest_clone(const CMD5_DIGEST *cmd5_digest_src, CMD5_DIGEST *cmd5_digest_des)
{
    if(NULL_PTR != cmd5_digest_src && NULL_PTR != cmd5_digest_des)
    {
        BCOPY(CMD5_DIGEST_SUM(cmd5_digest_src), CMD5_DIGEST_SUM(cmd5_digest_des), CMD5_DIGEST_LEN);
    }
    return (EC_TRUE);
}

EC_BOOL cmd5_digest_free(CMD5_DIGEST *cmd5_digest)
{
    if(NULL_PTR != cmd5_digest)
    {
        free_static_mem(MM_CMD5_DIGEST, cmd5_digest, LOC_CMD5_0002);
    }
    return (EC_TRUE);
}

EC_BOOL cmd5_digest_is_equal(const CMD5_DIGEST *cmd5_digest_1st, const CMD5_DIGEST *cmd5_digest_2nd)
{
    if(0 == BCMP(CMD5_DIGEST_SUM(cmd5_digest_1st), CMD5_DIGEST_SUM(cmd5_digest_2nd), CMD5_DIGEST_LEN))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

int cmd5_digest_cmp(const CMD5_DIGEST *cmd5_digest_1st, const CMD5_DIGEST *cmd5_digest_2nd)
{
    return BCMP(CMD5_DIGEST_SUM(cmd5_digest_1st), CMD5_DIGEST_SUM(cmd5_digest_2nd), CMD5_DIGEST_LEN);
}

char *cmd5_digest_hex_str(const CMD5_DIGEST *cmd5_digest)
{
    return c_md5_to_hex_str(CMD5_DIGEST_SUM(cmd5_digest));
}

void cmd5_digest_print(LOG *log, const CMD5_DIGEST *cmd5_digest)
{
    sys_print(log, "cmd5_digest_print: cmd5_digest %p: %s\n",
                   cmd5_digest,
                   cmd5_digest_hex_str(cmd5_digest));
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
