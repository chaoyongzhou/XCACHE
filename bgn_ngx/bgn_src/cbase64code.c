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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "type.h"
#include "log.h"
#include "mm.h"
#include "ccode.h"

static const UINT8 codes[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const UINT8 map[256] =
{
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*  0 -  11*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/* 12 -  23*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/* 24 -  35*/
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,/* 36 -  47*/
     52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,/* 48 -  59*/
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,/* 60 -  71*/
      7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,/* 72 -  83*/
     19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,/* 84 -  95*/
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,/* 96 - 107*/
     37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,/*108 - 119*/
     49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*120 - 131*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*132 - 143*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*144 - 155*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*156 - 167*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*168 - 179*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*180 - 191*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*192 - 203*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*204 - 215*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*216 - 227*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*228 - 239*/
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,/*240 - 251*/
    255, 255, 255, 255                                         /*252 - 255*/
};

EC_BOOL cbase64_encode(const UINT8 *in, const UINT32 inlen, UINT8 *out, const UINT32 max_outlen, UINT32 *outlen)
{
    UINT32 i, len2, leven;
    UINT8 *p;

    /* valid output size ? */
    len2 = 4 * ((inlen + 2) / 3);
    if (max_outlen < len2 + 1)
    {
        dbg_log(SEC_0012_CBASE64CODE, 0)(LOGSTDOUT, "error:cbase64_encode: overflow where inlen %ld, max_outlen %ld\n", inlen, max_outlen);
        return (EC_FALSE);
    }
    p = out;
    leven = 3*(inlen / 3);
    for (i = 0; i < leven; i += 3)
    {
        *p++ = codes[(in[0] >> 2) & 0x3F];
        *p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
        *p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
        *p++ = codes[in[2] & 0x3F];
        in += 3;
    }
    /* Pad it if necessary...  */
    if (i < inlen)
    {
        UINT8 a = in[0];
        UINT8 b = (i+1 < inlen) ? in[1] : 0;

        *p++ = codes[(a >> 2) & 0x3F];
        *p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
        *p++ = (i+1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
        *p++ = '=';
    }

    /* append a NULL byte */
    *p = '\0';

    /* return ok */
    *outlen = p - out;
    return (EC_TRUE);
}


EC_BOOL cbase64_decode(const UINT8 *in, const UINT32 inlen, UINT8 *out, const UINT32 max_outlen, UINT32 *outlen)
{
    UINT32 t, x, y, z;
    UINT8 c;
    int           g;

    g = 3;
    for (x = y = z = t = 0; x < inlen; x++)
    {
        c = map[in[x]&0xFF];
        if (255 == c)
        {
            continue;
        }
        /* the final = symbols are read and used to trim the remaining bytes */
        if (254 == c)
        {
            c = 0;
            /* prevent g < 0 which would potentially allow an overflow later */
            if (0 > --g)
            {
                dbg_log(SEC_0012_CBASE64CODE, 0)(LOGSTDOUT, "error:cbase64_decode: invalid packet\n");
                return (EC_FALSE);
            }
        }
        else if (3 != g)
        {
            dbg_log(SEC_0012_CBASE64CODE, 0)(LOGSTDOUT, "error:cbase64_decode: invalid packet\n");
            /* we only allow = to be at the end */
            return (EC_FALSE);
        }

        t = (t<<6)|c;

        if (4 == ++y)
        {
            if (z + g > max_outlen)
            {
                dbg_log(SEC_0012_CBASE64CODE, 0)(LOGSTDOUT, "error:cbase64_decode: overflow\n");
                return (EC_FALSE);
            }

            out[z++] = (UINT8)((t>>16)&255);
            if (1 < g)
            {
                out[z++] = (UINT8)((t>>8)&255);
            }
            if (2 < g)
            {
                out[z++] = (UINT8)(t&255);
            }
            y = t = 0;
        }
    }

    if (0 != y)
    {
        dbg_log(SEC_0012_CBASE64CODE, 0)(LOGSTDOUT, "error:cbase64_decode: invalid packet\n");
        return (EC_FALSE);
    }

    *outlen = z;
   return (EC_TRUE);
}

EC_BOOL cbase64_encode_size(const UINT32 inlen, UINT32 *outlen)
{
    (*outlen) = 4 * ((inlen + 2) / 3);
    return (EC_TRUE);
}

int cbase64_test()
{
    UINT8 plain_text[] = {0x30,0x82, 0x02, 0x03, 0x04, 0x05,0xfa, 0xfb, 0xfc, 0xff, 0xfe};
    UINT8 cipher_text[64];
    UINT8 decrypt_text[64];

    UINT32 plain_text_len  = sizeof(plain_text)/sizeof(plain_text[0]);
    UINT32 cipher_text_max_len = sizeof(cipher_text)/sizeof(cipher_text[0]);
    UINT32 decrypt_text_max_len = sizeof(decrypt_text)/sizeof(decrypt_text[0]);

    UINT32 cipher_text_len;
    UINT32 decrypt_text_len;

    print_uint8_buff(LOGSTDOUT, plain_text, plain_text_len);
    cbase64_encode(plain_text, plain_text_len, cipher_text, cipher_text_max_len, &cipher_text_len);
    print_char_buff(LOGSTDOUT, cipher_text, cipher_text_len);

    cbase64_decode(cipher_text, cipher_text_len, decrypt_text, decrypt_text_max_len, &decrypt_text_len);
    print_uint8_buff(LOGSTDOUT, decrypt_text, decrypt_text_len);

    return (0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
