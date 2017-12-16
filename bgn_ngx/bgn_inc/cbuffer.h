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

#ifndef _CBUFFER_H
#define _CBUFFER_H

#include "type.h"
#include "mm.h"
#include "log.h"

#define CBUFFER_MIN_SIZE      (64)


typedef struct 
{
    uint8_t *data;

    uint32_t size;
    uint32_t used;
}CBUFFER;

#define CBUFFER_DATA(cbuffer) ((cbuffer)->data)
#define CBUFFER_SIZE(cbuffer) ((cbuffer)->size)
#define CBUFFER_USED(cbuffer) ((cbuffer)->used)

#define CBUFFER_ROOM(cbuffer)   (CBUFFER_SIZE(cbuffer) - CBUFFER_USED(cbuffer))

CBUFFER* cbuffer_new(const uint32_t size); 

EC_BOOL cbuffer_init(CBUFFER *cbuffer, const uint32_t size); 

EC_BOOL cbuffer_clean(CBUFFER *cbuffer); 

EC_BOOL cbuffer_free(CBUFFER *cbuffer); 

EC_BOOL cbuffer_set(CBUFFER *cbuffer, const uint8_t *data, const uint32_t len) ;

EC_BOOL cbuffer_reset(CBUFFER *cbuffer); 

EC_BOOL cbuffer_clone(const CBUFFER *cbuffer_src, CBUFFER *cbuffer_des);

EC_BOOL cbuffer_expand(CBUFFER *cbuffer, const UINT32 location);

EC_BOOL cbuffer_expand_to(CBUFFER *cbuffer, const uint32_t size);

EC_BOOL cbuffer_push_bytes(CBUFFER *cbuffer, const uint8_t *data, const uint32_t size);

EC_BOOL cbuffer_pop_bytes(CBUFFER *cbuffer, uint8_t *data, const uint32_t size);

EC_BOOL cbuffer_left_shift_out(CBUFFER *cbuffer, uint8_t *data, const uint32_t size);

EC_BOOL cbuffer_left_shift_in(CBUFFER *cbuffer, const uint8_t *data, const uint32_t size);

EC_BOOL cbuffer_cmp_bytes(const CBUFFER *cbuffer, const uint32_t offset, const uint8_t *data, const uint32_t len);

uint32_t cbuffer_append(CBUFFER *cbuffer, const uint8_t *data, const uint32_t size);

uint32_t cbuffer_append_format(CBUFFER *cbuffer, const char *format, ...);

uint32_t cbuffer_append_vformat(CBUFFER *cbuffer, const char *format, va_list ap);

uint32_t cbuffer_export(CBUFFER *cbuffer, uint8_t *data, const uint32_t max_size);

uint8_t *cbuffer_data(CBUFFER *cbuffer);

uint32_t cbuffer_used(const CBUFFER *cbuffer);

uint32_t cbuffer_size(const CBUFFER *cbuffer);

uint32_t cbuffer_room(const CBUFFER *cbuffer);

EC_BOOL cbuffer_is_empty(const CBUFFER *cbuffer);

EC_BOOL cbuffer_mount(CBUFFER *cbuffer, const uint8_t *data, const uint32_t len);

EC_BOOL cbuffer_umount(CBUFFER *cbuffer, uint8_t **data, uint32_t *len);

void cbuffer_print_chars(LOG *log, const CBUFFER *cbuffer);

void cbuffer_print_str(LOG *log, const CBUFFER *cbuffer);

void cbuffer_print_info(LOG *log, const CBUFFER *cbuffer);

#endif/*_CBUFFER_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

