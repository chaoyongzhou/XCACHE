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

#ifndef _CHUNK_H
#define _CHUNK_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cbuffer.h"

#define CHUNK_DEFAULT_SIZE      ((uint32_t)(8 * 1024))        /*8K*/
#define CHUNK_SUGGEST_SIZE      ((uint32_t)(256 * 1024))      /*256K*/
#define CHUNK_MAX_SIZE          ((uint32_t)(1 * 1024 * 1024)) /*1M*/
 
typedef struct
{
    CBUFFER    cbuffer;/* either the storage of the mem-chunk or the read-ahead buffer */
    uint32_t   offset; /* octets sent from this chunk. the size of the chunk is mem->used - 1*/
    uint32_t   rsvd;
}CHUNK;

#define CHUNK_BUFFER(chunk)     (&((chunk)->cbuffer))
#define CHUNK_OFFSET(chunk)     ((chunk)->offset)

#define CHUNK_DATA(chunk)       (CBUFFER_DATA(CHUNK_BUFFER(chunk)))
#define CHUNK_USED(chunk)       (CBUFFER_USED(CHUNK_BUFFER(chunk)))
#define CHUNK_ROOM(chunk)       (CBUFFER_ROOM(CHUNK_BUFFER(chunk)))

typedef struct
{
    CLIST     chunk_list;
    uint64_t  nbytes_in;
    uint64_t  nbytes_out;
}CHUNK_MGR;

#define CHUNCK_MGR_CHUNK_LIST(chunk_mgr)             (&((chunk_mgr)->chunk_list))
#define CHUNCK_MGR_NBYTES_IN(chunk_mgr)              ((chunk_mgr)->nbytes_in)
#define CHUNCK_MGR_NBYTES_OUT(chunk_mgr)             ((chunk_mgr)->nbytes_out)

CHUNK *chunk_new(const uint32_t size);

EC_BOOL chunk_init(CHUNK *chunk, const uint32_t size);

EC_BOOL chunk_clean(CHUNK *chunk); 

EC_BOOL chunk_free(CHUNK *chunk); 

EC_BOOL chunk_is_empty(const CHUNK *chunk);

EC_BOOL chunk_set(CHUNK *chunk, const uint8_t *data, const uint32_t len);

EC_BOOL chunk_reset(CHUNK *chunk);

EC_BOOL chunk_mount(CHUNK *chunk, const uint8_t *data, const uint32_t len);

EC_BOOL chunk_umount(CHUNK *chunk, uint8_t **data, uint32_t *len);

uint32_t chunk_size(const CHUNK *chunk);

uint32_t chunk_used(const CHUNK *chunk);

uint32_t chunk_room(const CHUNK *chunk);

uint32_t chunk_append(CHUNK *chunk, const uint8_t *data, const uint32_t size);

uint32_t chunk_append_format(CHUNK *chunk, const char *format, ...);

uint32_t chunk_append_vformat(CHUNK *chunk, const char *format, va_list ap);

uint32_t chunk_export(CHUNK *chunk, uint8_t *data, const uint32_t max_size);

uint32_t chunk_shift(CHUNK *chunk, uint8_t *data, const uint32_t max_size);

void chunk_print_chars(LOG *log, const CHUNK *chunk);

void chunk_print_str(LOG *log, const CHUNK *chunk);

void chunk_print_info(LOG *log, const CHUNK *chunk);

CHUNK_MGR *chunk_mgr_new(void);

EC_BOOL chunk_mgr_init(CHUNK_MGR *chunk_mgr);

EC_BOOL chunk_mgr_clean(CHUNK_MGR *chunk_mgr); 

EC_BOOL chunk_mgr_free(CHUNK_MGR *chunk_mgr);

uint64_t chunk_mgr_total_length(const CHUNK_MGR *chunk_mgr);

uint64_t chunk_mgr_send_length(const CHUNK_MGR *chunk_mgr);

EC_BOOL chunk_mgr_is_empty(const CHUNK_MGR *chunk_mgr);

UINT32 chunk_mgr_count_chunks(const CHUNK_MGR *chunk_mgr);

CHUNK *chunk_mgr_last_chunk(const CHUNK_MGR *chunk_mgr);

CHUNK *chunk_mgr_first_chunk(const CHUNK_MGR *chunk_mgr);

CHUNK *chunk_mgr_pop_first_chunk(CHUNK_MGR *chunk_mgr);

EC_BOOL chunk_mgr_add_chunk(CHUNK_MGR *chunk_mgr, const CHUNK *chunk);

EC_BOOL chunk_mgr_append_data(CHUNK_MGR *chunk_mgr, const uint8_t *data, const uint32_t size);

EC_BOOL chunk_mgr_append_data_min(CHUNK_MGR *chunk_mgr, const uint8_t *data, const uint32_t size, const uint32_t min_room);

EC_BOOL chunk_mgr_export(CHUNK_MGR *chunk_mgr, UINT8 *data, const UINT32 len, UINT32 *used);

EC_BOOL chunk_mgr_shift(CHUNK_MGR *chunk_mgr, const uint32_t data_max_len, uint8_t *data, uint32_t *size);

EC_BOOL chunk_mgr_dump(CHUNK_MGR *chunk_mgr, UINT8 **data, UINT32 *len);

EC_BOOL chunk_mgr_mount_data(CHUNK_MGR *chunk_mgr, const uint8_t *data, const uint32_t size);

EC_BOOL chunk_mgr_umount_data(CHUNK_MGR *chunk_mgr, uint8_t **data, uint32_t *size);/*only for chunk_mgr has no or one chunk!*/

void chunk_mgr_print_chars(LOG *log, const CHUNK_MGR *chunk_mgr) ;

void chunk_mgr_print_str(LOG *log, const CHUNK_MGR *chunk_mgr);

void chunk_mgr_print_info(LOG *log, const CHUNK_MGR *chunk_mgr);

#endif/*_CHUNK_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

