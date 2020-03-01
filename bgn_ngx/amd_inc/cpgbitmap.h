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

#ifndef _CPGBITMAP_H
#define _CPGBITMAP_H

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
}CPG_BITMAP;

#define CPG_BITMAP_SIZE(cpg_bitmap)            ((cpg_bitmap)->size)
#define CPG_BITMAP_USED(cpg_bitmap)            ((cpg_bitmap)->used)
#define CPG_BITMAP_DATA(cpg_bitmap)            ((cpg_bitmap)->data)

CPG_BITMAP *cpg_bitmap_new(const uint32_t nbytes, const uint32_t nbits, const uint64_t align);

EC_BOOL cpg_bitmap_free(CPG_BITMAP *cpg_bitmap);

EC_BOOL cpg_bitmap_init(CPG_BITMAP *cpg_bitmap, const uint32_t nbits);

EC_BOOL cpg_bitmap_clean(CPG_BITMAP *cpg_bitmap);

EC_BOOL cpg_bitmap_set(CPG_BITMAP *cpg_bitmap, const uint32_t bit_pos);

EC_BOOL cpg_bitmap_clear(CPG_BITMAP *cpg_bitmap, const uint32_t bit_pos);

EC_BOOL cpg_bitmap_get(const CPG_BITMAP *cpg_bitmap, const uint32_t bit_pos, uint8_t *bit_val);

EC_BOOL cpg_bitmap_is(const CPG_BITMAP *cpg_bitmap, const uint32_t bit_pos, const uint8_t bit_val);

void cpg_bitmap_print(LOG *log, const CPG_BITMAP *cpg_bitmap);

void cpg_bitmap_print_brief(LOG *log, const CPG_BITMAP *cpg_bitmap);

uint32_t cpg_bitmap_used(const CPG_BITMAP *cpg_bitmap);

uint32_t cpg_bitmap_count(const CPG_BITMAP *cpg_bitmap, const uint32_t s_byte_nth, const uint32_t e_byte_nth);

EC_BOOL cpg_bitmap_revise(CPG_BITMAP *cpg_bitmap, const uint32_t nbits);

#endif/*_CPGBITMAP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
