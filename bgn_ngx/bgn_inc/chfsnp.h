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

#ifndef _CHFSNP_H
#define _CHFSNP_H

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
#include "chfsnprb.h"
#include "chfsnp.inc"

char * chfsnp_model_str(const uint8_t chfsnp_model);

uint32_t chfsnp_model_get(const char *mod_str);

EC_BOOL chfsnp_model_file_size(const uint8_t chfsnp_model, UINT32 *file_size);

EC_BOOL chfsnp_model_item_max_num(const uint8_t chfsnp_model, uint32_t *item_max_num);

EC_BOOL chfsnp_inode_init(CHFSNP_INODE *chfsnp_inode);

EC_BOOL chfsnp_inode_clean(CHFSNP_INODE *chfsnp_inode);

EC_BOOL chfsnp_inode_clone(const CHFSNP_INODE *chfsnp_inode_src, CHFSNP_INODE *chfsnp_inode_des);

void chfsnp_inode_print(LOG *log, const CHFSNP_INODE *chfsnp_inode);

void chfsnp_inode_log_no_lock(LOG *log, const CHFSNP_INODE *chfsnp_inode);

CHFSNP_FNODE *chfsnp_fnode_new();

CHFSNP_FNODE *chfsnp_fnode_make(const CHFSNP_FNODE *chfsnp_fnode_src);

EC_BOOL chfsnp_fnode_init(CHFSNP_FNODE *chfsnp_fnode);

EC_BOOL chfsnp_fnode_clean(CHFSNP_FNODE *chfsnp_fnode);

EC_BOOL chfsnp_fnode_free(CHFSNP_FNODE *chfsnp_fnode);

EC_BOOL chfsnp_fnode_clone(const CHFSNP_FNODE *chfsnp_fnode_src, CHFSNP_FNODE *chfsnp_fnode_des);

EC_BOOL chfsnp_fnode_check_inode_exist(const CHFSNP_INODE *inode, const CHFSNP_FNODE *chfsnp_fnode);

EC_BOOL chfsnp_fnode_cmp(const CHFSNP_FNODE *chfsnp_fnode_1st, const CHFSNP_FNODE *chfsnp_fnode_2nd);

EC_BOOL chfsnp_fnode_import(const CHFSNP_FNODE *chfsnp_fnode_src, CHFSNP_FNODE *chfsnp_fnode_des);

uint32_t chfsnp_fnode_count_replica(const CHFSNP_FNODE *chfsnp_fnode);

void chfsnp_fnode_print(LOG *log, const CHFSNP_FNODE *chfsnp_fnode);

void chfsnp_fnode_log_no_lock(LOG *log, const CHFSNP_FNODE *chfsnp_fnode);

CHFSNP_ITEM *chfsnp_item_new();

EC_BOOL chfsnp_item_init(CHFSNP_ITEM *chfsnp_item);

EC_BOOL chfsnp_item_clean(CHFSNP_ITEM *chfsnp_item);

EC_BOOL chfsnp_item_clone(const CHFSNP_ITEM *chfsnp_item_src, CHFSNP_ITEM *chfsnp_item_des);

EC_BOOL chfsnp_item_free(CHFSNP_ITEM *chfsnp_item);

EC_BOOL chfsnp_item_set_key(CHFSNP_ITEM *chfsnp_item, const uint32_t klen, const uint8_t *key);

void chfsnp_item_print(LOG *log, const CHFSNP_ITEM *chfsnp_item);

EC_BOOL chfsnp_item_load(CHFSNP *chfsnp, uint32_t *offset, CHFSNP_ITEM *chfsnp_item);

EC_BOOL chfsnp_item_flush(CHFSNP *chfsnp, uint32_t *offset, const CHFSNP_ITEM *chfsnp_item);

EC_BOOL chfsnp_item_is(const CHFSNP_ITEM *chfsnp_item, const uint32_t klen, const uint8_t *key);

void chfsnp_bucket_print(LOG *log, const uint32_t *chfsnp_buckets, const uint32_t bucket_num);

EC_BOOL chfsnp_header_init(CHFSNP_HEADER *chfsnp_header, const uint32_t np_id, const uint8_t model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id, const uint32_t bucket_max_num);

EC_BOOL chfsnp_header_clean(CHFSNP_HEADER *chfsnp_header);

CHFSNP *chfsnp_new();

EC_BOOL chfsnp_init(CHFSNP *chfsnp);

EC_BOOL chfsnp_clean(CHFSNP *chfsnp);

EC_BOOL chfsnp_free(CHFSNP *chfsnp);

EC_BOOL chfsnp_is_full(const CHFSNP *chfsnp);

EC_BOOL chfsnp_is_empty(const CHFSNP *chfsnp);

void chfsnp_header_print(LOG *log, const CHFSNP *chfsnp);

void chfsnp_print(LOG *log, const CHFSNP *chfsnp);

uint32_t chfsnp_search_no_lock(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path);

uint32_t chfsnp_search(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path);

uint32_t chfsnp_insert_no_lock(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path);

uint32_t chfsnp_insert(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path);

CHFSNP_ITEM *chfsnp_fetch(const CHFSNP *chfsnp, const uint32_t node_pos);

EC_BOOL chfsnp_inode_update(CHFSNP *chfsnp, CHFSNP_INODE *chfsnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL chfsnp_fnode_update(CHFSNP *chfsnp, CHFSNP_FNODE *chfsnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL chfsnp_update_all_buckets(CHFSNP *chfsnp,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL chfsnp_item_update(CHFSNP *chfsnp, CHFSNP_ITEM *chfsnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL chfsnp_update_no_lock(CHFSNP *chfsnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

CHFSNP_ITEM *chfsnp_set(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path);

CHFSNP_ITEM *chfsnp_get(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path);

EC_BOOL chfsnp_delete(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path);

EC_BOOL chfsnp_recycle(CHFSNP *chfsnp, const UINT32 max_num, CHFSNP_RECYCLE_NP *chfsnp_recycle_np, CHFSNP_RECYCLE_DN *chfsnp_recycle_dn, UINT32 *complete_num);

EC_BOOL chfsnp_retire(CHFSNP *chfsnp, const UINT32 nsec, const UINT32 expect_retire_num, const UINT32 max_step, UINT32 *complete_retire_num);

EC_BOOL chfsnp_umount_item(CHFSNP *chfsnp, const uint32_t node_pos);

uint32_t chfsnp_count_file_num(const CHFSNP *chfsnp);

EC_BOOL chfsnp_file_size(CHFSNP *chfsnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_size);

EC_BOOL chfsnp_count_file_size(CHFSNP *chfsnp, uint64_t *file_size);

CHFSNP *chfsnp_open(const char *np_root_dir, const uint32_t np_id);

EC_BOOL chfsnp_close(CHFSNP *chfsnp);

EC_BOOL chfsnp_sync(CHFSNP *chfsnp);

CHFSNP *chfsnp_create(const char *np_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id);

EC_BOOL chfsnp_show_item(LOG *log, const CHFSNP_ITEM *chfsnp_item);

EC_BOOL chfsnp_show_one_bucket(LOG *log, const CHFSNP *chfsnp, const uint32_t bucket_pos);

EC_BOOL chfsnp_show_all_buckets(LOG *log, const CHFSNP *chfsnp);

CHFSNP *chfsnp_mem_create(const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num);

EC_BOOL chfsnp_mem_clean(CHFSNP *chfsnp);

EC_BOOL chfsnp_mem_free(CHFSNP *chfsnp);


#endif/* _CHFSNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

