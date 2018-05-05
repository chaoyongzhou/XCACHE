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

#ifndef _CSFSNP_H
#define _CSFSNP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"

#include "cbloom.h"
#include "chashalgo.h"
#include "csfsnprb.h"
#include "csfsnp.inc"

char * csfsnp_model_str(const uint8_t csfsnp_model);

uint32_t csfsnp_model_get(const char *mod_str);

EC_BOOL csfsnp_model_file_size(const uint8_t csfsnp_model, UINT32 *file_size);

EC_BOOL csfsnp_model_item_max_num(const uint8_t csfsnp_model, uint32_t *item_max_num);

EC_BOOL csfsnp_inode_init(CSFSNP_INODE *csfsnp_inode);

EC_BOOL csfsnp_inode_clean(CSFSNP_INODE *csfsnp_inode);

EC_BOOL csfsnp_inode_clone(const CSFSNP_INODE *csfsnp_inode_src, CSFSNP_INODE *csfsnp_inode_des);

void csfsnp_inode_print(LOG *log, const CSFSNP_INODE *csfsnp_inode);

void csfsnp_inode_log_no_lock(LOG *log, const CSFSNP_INODE *csfsnp_inode);

CSFSNP_FNODE *csfsnp_fnode_new();

CSFSNP_FNODE *csfsnp_fnode_make(const CSFSNP_FNODE *csfsnp_fnode_src);

EC_BOOL csfsnp_fnode_init(CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfsnp_fnode_clean(CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfsnp_fnode_free(CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfsnp_fnode_clone(const CSFSNP_FNODE *csfsnp_fnode_src, CSFSNP_FNODE *csfsnp_fnode_des);

EC_BOOL csfsnp_fnode_check_inode_exist(const CSFSNP_INODE *inode, const CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfsnp_fnode_cmp(const CSFSNP_FNODE *csfsnp_fnode_1st, const CSFSNP_FNODE *csfsnp_fnode_2nd);

EC_BOOL csfsnp_fnode_import(const CSFSNP_FNODE *csfsnp_fnode_src, CSFSNP_FNODE *csfsnp_fnode_des);

uint32_t csfsnp_fnode_count_replica(const CSFSNP_FNODE *csfsnp_fnode);

void csfsnp_fnode_print(LOG *log, const CSFSNP_FNODE *csfsnp_fnode);

void csfsnp_fnode_log_no_lock(LOG *log, const CSFSNP_FNODE *csfsnp_fnode);

CSFSNP_ITEM *csfsnp_item_new();

EC_BOOL csfsnp_item_init(CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_clean(CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_clone(const CSFSNP_ITEM *csfsnp_item_src, CSFSNP_ITEM *csfsnp_item_des);

EC_BOOL csfsnp_item_free(CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_init_0(const UINT32 md_id, CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_clean_0(const UINT32 md_id, CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_free_0(const UINT32 md_id, CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_set_key(CSFSNP_ITEM *csfsnp_item, const uint32_t klen, const uint8_t *key);

void csfsnp_item_print(LOG *log, const CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_load(CSFSNP *csfsnp, uint32_t *offset, CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_flush(CSFSNP *csfsnp, uint32_t *offset, const CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_item_is(const CSFSNP_ITEM *csfsnp_item, const uint32_t klen, const uint8_t *key);

void csfsnp_bucket_print(LOG *log, const uint32_t *csfsnp_buckets, const uint32_t bucket_num);

EC_BOOL csfsnp_header_init(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const uint8_t model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id, const uint32_t bucket_max_num);

EC_BOOL csfsnp_header_clean(CSFSNP_HEADER *csfsnp_header);

CSFSNP *csfsnp_new();

EC_BOOL csfsnp_init(CSFSNP *csfsnp);

EC_BOOL csfsnp_clean(CSFSNP *csfsnp);

EC_BOOL csfsnp_free(CSFSNP *csfsnp);

EC_BOOL csfsnp_is_full(const CSFSNP *csfsnp);

EC_BOOL csfsnp_is_empty(const CSFSNP *csfsnp);

void csfsnp_header_print(LOG *log, const CSFSNP *csfsnp);

void csfsnp_print(LOG *log, const CSFSNP *csfsnp);

uint32_t csfsnp_search_no_lock(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path);

uint32_t csfsnp_search(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path);

uint32_t csfsnp_insert_no_lock(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path);

uint32_t csfsnp_insert(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path);

CSFSNP_ITEM *csfsnp_fetch(const CSFSNP *csfsnp, const uint32_t node_pos);

EC_BOOL csfsnp_inode_update(CSFSNP *csfsnp, CSFSNP_INODE *csfsnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL csfsnp_fnode_update(CSFSNP *csfsnp, CSFSNP_FNODE *csfsnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL csfsnp_update_all_buckets(CSFSNP *csfsnp,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL csfsnp_item_update(CSFSNP *csfsnp, CSFSNP_ITEM *csfsnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL csfsnp_update_no_lock(CSFSNP *csfsnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

CSFSNP_ITEM *csfsnp_set(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path);

CSFSNP_ITEM *csfsnp_get(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path);

EC_BOOL csfsnp_delete(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path);

EC_BOOL csfsnp_delete_item(CSFSNP *csfsnp, const uint32_t node_pos);

EC_BOOL csfsnp_umount_item(CSFSNP *csfsnp, const uint32_t node_pos);

uint32_t csfsnp_count_file_num(const CSFSNP *csfsnp);

EC_BOOL csfsnp_file_size(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_size);

EC_BOOL csfsnp_count_file_size(CSFSNP *csfsnp, uint64_t *file_size);

CSFSNP *csfsnp_open(const char *np_root_dir, const uint32_t np_id);

EC_BOOL csfsnp_close(CSFSNP *csfsnp);

EC_BOOL csfsnp_sync(CSFSNP *csfsnp);

CSFSNP *csfsnp_create(const char *np_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id);

EC_BOOL csfsnp_show_item(LOG *log, const CSFSNP_ITEM *csfsnp_item);

EC_BOOL csfsnp_show_one_bucket(LOG *log, const CSFSNP *csfsnp, const uint32_t bucket_pos);

EC_BOOL csfsnp_show_all_buckets(LOG *log, const CSFSNP *csfsnp);

CSFSNP *csfsnp_mem_create(const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num);

EC_BOOL csfsnp_mem_clean(CSFSNP *csfsnp);

EC_BOOL csfsnp_mem_free(CSFSNP *csfsnp);


#endif/* _CSFSNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

