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

#ifndef _CTDNSNP_H
#define _CTDNSNP_H

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cstring.h"
#include "task.inc"
#include "chashalgo.h"
#include "ctdnsnprb.h"
#include "ctdnsnp.inc"

const char *ctdnsnp_model_str(const uint8_t ctdnsnp_model);

uint8_t ctdnsnp_model_get(const char *model_str);

EC_BOOL ctdnsnp_model_file_size(const uint8_t ctdnsnp_model, UINT32 *file_size);

EC_BOOL ctdnsnp_model_item_max_num(const uint8_t ctdnsnp_model, uint32_t *item_max_num);

CTDNSNP_ITEM *ctdnsnp_item_new();

EC_BOOL ctdnsnp_item_init(CTDNSNP_ITEM *ctdnsnp_item);

EC_BOOL ctdnsnp_item_clean(CTDNSNP_ITEM *ctdnsnp_item);

EC_BOOL ctdnsnp_item_clone(const CTDNSNP_ITEM *ctdnsnp_item_src, CTDNSNP_ITEM *ctdnsnp_item_des);

EC_BOOL ctdnsnp_item_free(CTDNSNP_ITEM *ctdnsnp_item);

EC_BOOL ctdnsnp_item_set_key(CTDNSNP_ITEM *ctdnsnp_item, const uint32_t klen, const uint8_t *key);

void ctdnsnp_item_print(LOG *log, const CTDNSNP_ITEM *ctdnsnp_item);

EC_BOOL ctdnsnp_item_load(CTDNSNP *ctdnsnp, uint32_t *offset, CTDNSNP_ITEM *ctdnsnp_item);

EC_BOOL ctdnsnp_item_flush(CTDNSNP *ctdnsnp, uint32_t *offset, const CTDNSNP_ITEM *ctdnsnp_item);

EC_BOOL ctdnsnp_item_is_key(const CTDNSNP_ITEM *ctdnsnp_item, const uint32_t klen, const uint8_t *key);

EC_BOOL ctdnsnp_item_is_tcid(const CTDNSNP_ITEM *ctdnsnp_item, const UINT32 tcid);

/*previous node with the same key*/
CTDNSNP_ITEM *ctdnsnp_item_prev(const CTDNSNP *ctdns, const CTDNSNP_ITEM *ctdnsnp_item);

/*next node with the same key*/
CTDNSNP_ITEM *ctdnsnp_item_next(const CTDNSNP *ctdns, const CTDNSNP_ITEM *ctdnsnp_item);

CTDNSNP_ITEM *ctdnsnp_item_parent(const CTDNSNP *ctdnsnp, const CTDNSNP_ITEM *ctdnsnp_item);

CTDNSNP_ITEM *ctdnsnp_item_left(const CTDNSNP *ctdnsnp, const CTDNSNP_ITEM *ctdnsnp_item);

CTDNSNP_ITEM *ctdnsnp_item_right(const CTDNSNP *ctdnsnp, const CTDNSNP_ITEM *ctdnsnp_item);

EC_BOOL ctdnsnp_header_init(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const uint8_t model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id);

EC_BOOL ctdnsnp_header_clean(CTDNSNP_HEADER *ctdnsnp_header);

CTDNSNP_HEADER *ctdnsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd);

CTDNSNP_HEADER *ctdnsnp_header_clone(CTDNSNP_HEADER *src_ctdnsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd);

CTDNSNP_HEADER *ctdnsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model);

CTDNSNP_HEADER *ctdnsnp_header_sync(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd);

CTDNSNP_HEADER *ctdnsnp_header_close(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd);

CTDNSNP *ctdnsnp_new();

EC_BOOL ctdnsnp_init(CTDNSNP *ctdnsnp);

EC_BOOL ctdnsnp_clean(CTDNSNP *ctdnsnp);

EC_BOOL ctdnsnp_free(CTDNSNP *ctdnsnp);

EC_BOOL ctdnsnp_is_full(const CTDNSNP *ctdnsnp);

void ctdnsnp_header_print(LOG *log, const CTDNSNP *ctdnsnp);

void ctdnsnp_print(LOG *log, const CTDNSNP *ctdnsnp);

uint32_t ctdnsnp_search_no_lock(CTDNSNP *ctdns, const UINT32 tcid);

uint32_t ctdnsnp_search(CTDNSNP *ctdns, const UINT32 tcid);

uint32_t ctdnsnp_insert_no_lock(CTDNSNP *ctdns, const UINT32 tcid, const UINT32 ipaddr, const uint32_t klen, const uint8_t *key);

uint32_t ctdnsnp_insert(CTDNSNP *ctdns, const UINT32 tcid, const UINT32 ipaddr, const uint32_t klen, const uint8_t *key);

CTDNSNP_ITEM *ctdnsnp_fetch(const CTDNSNP *ctdnsnp, const uint32_t node_pos);

CTDNSNP_ITEM *ctdnsnp_set(CTDNSNP *ctdns, const UINT32 tcid, const UINT32 ipaddr, const uint32_t klen, const uint8_t *key);

CTDNSNP_ITEM *ctdnsnp_get(CTDNSNP *ctdns, const UINT32 tcid);

EC_BOOL ctdnsnp_delete(CTDNSNP *ctdns, const UINT32 tcid);

CTDNSNP *ctdnsnp_open(const char *np_root_dir, const uint32_t np_id);

EC_BOOL ctdnsnp_close(CTDNSNP *ctdnsnp);

EC_BOOL ctdnsnp_sync(CTDNSNP *ctdnsnp);

CTDNSNP *ctdnsnp_clone(CTDNSNP *src_ctdnsnp, const char *np_root_dir, const uint32_t des_np_id);

CTDNSNP *ctdnsnp_create(const char *np_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id);

EC_BOOL ctdnsnp_show_item(LOG *log, const CTDNSNP *ctdnsnp, const uint32_t node_pos);

EC_BOOL ctdnsnp_tcid_num(const CTDNSNP *ctdns, UINT32 *tcid_num);

CTDNSNP *ctdnsnp_mem_create(const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id);

EC_BOOL ctdnsnp_mem_clean(CTDNSNP *ctdnsnp);

EC_BOOL ctdnsnp_mem_free(CTDNSNP *ctdnsnp);



#endif/* _CTDNSNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

