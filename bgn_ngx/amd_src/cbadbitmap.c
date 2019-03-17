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
    }

    return (EC_TRUE);
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
    }

    return (EC_TRUE);
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

void cbad_bitmap_print(LOG *log, const CBAD_BITMAP *cbad_bitmap)
{
    uint32_t   byte_nth;

    sys_print(log, "[DEBUG] cbad_bitmap_print: "
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

        byte_val = CBAD_BITMAP_DATA(cbad_bitmap)[ byte_nth ];
        if(0 == byte_val)/*ignore*/
        {
            continue;
        }

        sys_print(log, "[%8d B] ", byte_nth);

        /*print bits from Lo to Hi*/
        for(bit_nth = 0; bit_nth < BYTESIZE; bit_nth ++, byte_val >>= 1)
        {
            bit_val = (byte_val & 1);
            sys_print(log, "%u ", bit_val);
        }
        sys_print(log, "\n");
    }
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
