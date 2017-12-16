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

#ifndef _CBITMAP_H
#define _CBITMAP_H

#include "type.h"

typedef struct
{
    UINT32   max_bits;
    UINT32   cur_bits;
    UINT32   max_bytes;

    UINT32  *cache;
}CBITMAP;

#define CBITMAP_MAX_BYTES(cbitmap)      ((cbitmap)->max_bytes)
#define CBITMAP_MAX_BITS(cbitmap)       ((cbitmap)->max_bits)
#define CBITMAP_CUR_BITS(cbitmap)       ((cbitmap)->cur_bits)
#define CBITMAP_CACHE(cbitmap)          ((cbitmap)->cache)
#define CBITMAP_WORD(cbitmap, word_pos) ((cbitmap)->cache[(word_pos)])

CBITMAP *cbitmap_new(const UINT32 max_bits);
EC_BOOL  cbitmap_init(CBITMAP *cbitmap, const UINT32 max_bits);
EC_BOOL  cbitmap_clean(CBITMAP *cbitmap);
EC_BOOL  cbitmap_free(CBITMAP *cbitmap);
EC_BOOL  cbitmap_set(CBITMAP *cbitmap, const UINT32 bit_pos);
EC_BOOL  cbitmap_unset(CBITMAP *cbitmap, const UINT32 bit_pos);
EC_BOOL  cbitmap_check(const CBITMAP *cbitmap, const UINT32 bit_pos);
EC_BOOL  cbitmap_is_full(const CBITMAP *cbitmap);
EC_BOOL cbitmap_used_size(const CBITMAP *cbitmap);
EC_BOOL cbitmap_room_size(const CBITMAP *cbitmap);
EC_BOOL  cbitmap_reserve(CBITMAP *cbitmap, UINT32 *bit_pos);
EC_BOOL  cbitmap_release(CBITMAP *cbitmap, const UINT32 bit_pos);
void     cbitmap_print(LOG *log, const CBITMAP *cbitmap);

EC_BOOL  cbitmap_fexist(const UINT8 *fname);
CBITMAP *cbitmap_fcreate(const UINT32 max_bits, const UINT8 *fname);
EC_BOOL  cbitmap_flush(const CBITMAP *cbitmap, const UINT8 *fname);
CBITMAP *cbitmap_fload(const UINT8 *fname);
EC_BOOL  cbitmap_dump(const CBITMAP *cbitmap, UINT8 **buf, UINT32 *len);
CBITMAP *cbitmap_load(const UINT8 *buf, const UINT32 len);

EC_BOOL  cbitmap_dfs_exist(const CSTRING *fname_cstr, const UINT32 cdfs_md_id);
CBITMAP *cbitmap_dfs_create(const UINT32 max_bits, const CSTRING *fname_cstr, const UINT32 cdfs_md_id, const UINT32 replica_num);
EC_BOOL  cbitmap_dfs_flush(const CBITMAP *cbitmap, const CSTRING *fname_cstr, const UINT32 cdfs_md_id);
CBITMAP *cbitmap_dfs_load(const CSTRING *fname_cstr, const UINT32 cdfs_md_id);

#endif/* _CBITMAP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
