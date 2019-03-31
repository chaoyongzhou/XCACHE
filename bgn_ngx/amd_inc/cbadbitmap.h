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

#ifndef _CBADBITMAP_H
#define _CBADBITMAP_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

/*bitmap of bad aio-page*/
typedef struct
{
    uint32_t    size;
    uint32_t    used;
    UINT8       data[ 0 ]; /*item is start aio-page no*/
}CBAD_BITMAP;

#define CBAD_BITMAP_SIZE(cbad_bitmap)            ((cbad_bitmap)->size)
#define CBAD_BITMAP_USED(cbad_bitmap)            ((cbad_bitmap)->used)
#define CBAD_BITMAP_DATA(cbad_bitmap)            ((cbad_bitmap)->data)

CBAD_BITMAP *cbad_bitmap_new(const uint32_t nbytes, const uint32_t nbits, const uint64_t align);

EC_BOOL cbad_bitmap_free(CBAD_BITMAP *cbad_bitmap);

EC_BOOL cbad_bitmap_init(CBAD_BITMAP *cbad_bitmap, const uint32_t nbits);

EC_BOOL cbad_bitmap_clean(CBAD_BITMAP *cbad_bitmap);

EC_BOOL cbad_bitmap_set(CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos);

EC_BOOL cbad_bitmap_clear(CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos);

EC_BOOL cbad_bitmap_get(const CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos, uint8_t *bit_val);

EC_BOOL cbad_bitmap_is(const CBAD_BITMAP *cbad_bitmap, const uint32_t bit_pos, const uint8_t bit_val);

void cbad_bitmap_print(LOG *log, const CBAD_BITMAP *cbad_bitmap);

void cbad_bitmap_print_brief(LOG *log, const CBAD_BITMAP *cbad_bitmap);

uint32_t cbad_bitmap_used(const CBAD_BITMAP *cbad_bitmap);

uint32_t cbad_bitmap_count(const CBAD_BITMAP *cbad_bitmap, const uint32_t s_byte_nth, const uint32_t e_byte_nth);

EC_BOOL cbad_bitmap_revise(CBAD_BITMAP *cbad_bitmap, const uint32_t nbits);

#endif/*_CBADBITMAP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
