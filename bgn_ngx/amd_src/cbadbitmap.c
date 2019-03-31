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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cbadbitmap.h"

static const uint8_t g_nbits_per_byte[] = {
    /*   0 -   31*/ 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  32 -   63*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  64 -   95*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  96 -  127*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 128 -  159*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 160 -  191*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 192 -  223*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 224 -  255*/ 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

CBAD_BITMAP *cbad_bitmap_new(const uint32_t nbytes, const uint32_t nbits, const uint64_t align)
{
    CBAD_BITMAP *cbad_bitmap;

    if((nbytes << 3) < nbits)
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "error:cbad_bitmap_new: "
                                                   "nbytes %u, but nbits %u > %u overflow!\n",
                                                   nbytes, nbits, (nbytes << 3));
        return (NULL_PTR);
    }

    cbad_bitmap = c_memalign_new(nbytes, align);
    if(NULL_PTR == cbad_bitmap)
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "error:cbad_bitmap_new: "
                                                   "new mem with %u bytes failed\n",
                                                   nbytes);
        return (NULL_PTR);
    }

    if(EC_FALSE == cbad_bitmap_init(cbad_bitmap, nbits))
    {
        c_memalign_free(cbad_bitmap);

        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "error:cbad_bitmap_new: "
                                                   "init bad bitmap with %u bits failed\n",
                                                   nbits);
        return (NULL_PTR);
    }

    return (cbad_bitmap);
}

EC_BOOL cbad_bitmap_free(CBAD_BITMAP *cbad_bitmap)
{
    if(NULL_PTR != cbad_bitmap)
    {
        cbad_bitmap_clean(cbad_bitmap);
        c_memalign_free(cbad_bitmap);
    }

    return (EC_TRUE);
}

EC_BOOL cbad_bitmap_init(CBAD_BITMAP *cbad_bitmap, const uint32_t nbits)
{
    uint32_t nbytes;

    nbytes = ((nbits + 7)/8);

    BSET((void *)CBAD_BITMAP_DATA(cbad_bitmap), 0, nbytes);
    CBAD_BITMAP_SIZE(cbad_bitmap) = nbytes;
    CBAD_BITMAP_USED(cbad_bitmap) = 0;

    return (EC_TRUE);
}

EC_BOOL cbad_bitmap_clean(CBAD_BITMAP *cbad_bitmap)
{
    if(NULL_PTR != cbad_bitmap)
    {
        uint32_t    size;

        size = CBAD_BITMAP_SIZE(cbad_bitmap);

        BSET((void *)CBAD_BITMAP_DATA(cbad_bitmap), 0, size);
        CBAD_BITMAP_SIZE(cbad_bitmap) = 0;
        CBAD_BITMAP_USED(cbad_bitmap) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cbad_bitmap_set(CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CBAD_BITMAP_SIZE(cbad_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "error:cbad_bitmap_set: "
                                                   "overflow bit_pos %u => byte_nth %u >= %u\n",
                                                   bit_pos,
                                                   byte_nth,
                                                   CBAD_BITMAP_SIZE(cbad_bitmap));
        return (EC_FALSE);
    }

    if(0 == (CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ] & ((uint8_t)(1 << bit_nth))))
    {
        CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ] |= ((uint8_t)(1 << bit_nth));
        CBAD_BITMAP_USED(cbad_bitmap) ++;

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cbad_bitmap_clear(CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CBAD_BITMAP_SIZE(cbad_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "error:cbad_bitmap_clear: "
                                                   "overflow bit_pos %u => byte_nth %u >= %u\n",
                                                   bit_pos,
                                                   byte_nth,
                                                   CBAD_BITMAP_SIZE(cbad_bitmap));
        return (EC_FALSE);
    }

    if(CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ] & ((uint8_t)(1 << bit_nth)))
    {
        CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ] &= ((uint8_t)(~(1 << bit_nth)));
        CBAD_BITMAP_USED(cbad_bitmap) --;

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cbad_bitmap_get(const CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos, uint8_t *bit_val)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CBAD_BITMAP_SIZE(cbad_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "error:cbad_bitmap_get: "
                                                   "overflow bit_pos %u => byte_nth %u >= %u\n",
                                                   bit_pos,
                                                   byte_nth,
                                                   CBAD_BITMAP_SIZE(cbad_bitmap));
        return (EC_FALSE);
    }

    if(0 == (CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ] & ((uint8_t)(1 << bit_nth))))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

EC_BOOL cbad_bitmap_is(const CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos, const uint8_t bit_val)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;
    uint8_t    e;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CBAD_BITMAP_SIZE(cbad_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "error:cbad_bitmap_is: "
                                                   "overflow bit_pos %u => byte_nth %u >= %u\n",
                                                   bit_pos,
                                                   byte_nth,
                                                   CBAD_BITMAP_SIZE(cbad_bitmap));
        return (EC_FALSE);
    }

    e = (CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ] & ((uint8_t)(1 << bit_nth)));

    if(0 == e && 0 == bit_val)
    {
        return (EC_TRUE);
    }

    if(0 < e && 1 == bit_val)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

uint32_t cbad_bitmap_used(const CBAD_BITMAP *cbad_bitmap)
{
    return CBAD_BITMAP_USED(cbad_bitmap);
}

/*count the num of bit 1*/
uint32_t cbad_bitmap_count(const CBAD_BITMAP *cbad_bitmap, const uint32_t s_byte_nth, const uint32_t e_byte_nth)
{
    uint32_t   byte_nth;
    uint32_t   bits_count;

    bits_count     = 0;

    for(byte_nth = s_byte_nth; byte_nth < e_byte_nth; byte_nth ++)
    {
        bits_count += g_nbits_per_byte[ CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ] ];
    }
    return (bits_count);
}

EC_BOOL cbad_bitmap_revise(CBAD_BITMAP *cbad_bitmap, const uint32_t nbits)
{
    uint32_t    bits_count;
    uint32_t    nbytes;

    nbytes     = ((nbits + 7)/8);
    bits_count = cbad_bitmap_count(cbad_bitmap, 0, nbytes);

    if(nbytes != CBAD_BITMAP_SIZE(cbad_bitmap))
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "[DEBUG] cbad_bitmap_revise: "
                                                   "revise size %u => %u\n",
                                                   CBAD_BITMAP_SIZE(cbad_bitmap), nbytes);
        CBAD_BITMAP_SIZE(cbad_bitmap) = nbytes;
    }

    if(bits_count != CBAD_BITMAP_USED(cbad_bitmap))
    {
        dbg_log(SEC_0210_CBADBITMAP, 0)(LOGSTDOUT, "[DEBUG] cbad_bitmap_revise: "
                                                   "revise used %u => %u\n",
                                                   CBAD_BITMAP_USED(cbad_bitmap), bits_count);

        CBAD_BITMAP_USED(cbad_bitmap) = bits_count;
    }

    return(EC_TRUE);
}

void cbad_bitmap_print(LOG *log, const CBAD_BITMAP *cbad_bitmap)
{
    uint32_t   byte_nth;

    sys_log(log, "[DEBUG] cbad_bitmap_print: "
                 "bad bitmap %p, nbytes %u, nbits %u, used %u\n",
                 cbad_bitmap,
                 CBAD_BITMAP_SIZE(cbad_bitmap),
                 CBAD_BITMAP_SIZE(cbad_bitmap) << 3,
                 CBAD_BITMAP_USED(cbad_bitmap));

    for(byte_nth = 0; byte_nth < CBAD_BITMAP_SIZE(cbad_bitmap); byte_nth ++)
    {
        uint32_t bit_nth;
        uint8_t  bit_val;
        uint8_t  byte_val;
        char     buff[ 128 ];
        uint32_t pos;

        byte_val = CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ];
        if(0 == byte_val)/*ignore*/
        {
            continue;
        }

        BSET(buff, 0, sizeof(buff));

        pos  = 0;
        pos += snprintf(((char *)buff) + pos, sizeof(buff) - pos, "[%8d B] ", byte_nth);

        /*print bits from Lo to Hi*/
        for(bit_nth = 0; bit_nth < BYTESIZE; bit_nth ++, byte_val >>= 1)
        {
            bit_val = (byte_val & 1);
            pos += snprintf(((char *)buff) + pos, sizeof(buff) - pos, "%u ", bit_val);
        }
        sys_log(log, "%.*s\n", pos, (char *)buff);
    }
    return;
}

void cbad_bitmap_print_brief(LOG *log, const CBAD_BITMAP *cbad_bitmap)
{
    if(NULL_PTR != cbad_bitmap)
    {
        sys_log(log, "[DEBUG] cbad_bitmap_print_brief: "
                     "bad bitmap %p, nbytes %u, nbits %u, used %u\n",
                     cbad_bitmap,
                     CBAD_BITMAP_SIZE(cbad_bitmap),
                     CBAD_BITMAP_SIZE(cbad_bitmap) << 3,
                     CBAD_BITMAP_USED(cbad_bitmap));
    }
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
