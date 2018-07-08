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

#ifndef _CRFSNP_H
#define _CRFSNP_H

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
#include "task.inc"
#include "chashalgo.h"
#include "crfsnprb.h"
#include "crfsnp.inc"
#include "crfsdt.h"

const char *crfsnp_model_str(const uint8_t crfsnp_model);

uint8_t crfsnp_model_get(const char *model_str);

EC_BOOL crfsnp_model_file_size(const uint8_t crfsnp_model, UINT32 *file_size);

EC_BOOL crfsnp_model_item_max_num(const uint8_t crfsnp_model, uint32_t *item_max_num);

EC_BOOL crfsnp_inode_init(CRFSNP_INODE *crfsnp_inode);

EC_BOOL crfsnp_inode_clean(CRFSNP_INODE *crfsnp_inode);

EC_BOOL crfsnp_inode_clone(const CRFSNP_INODE *crfsnp_inode_src, CRFSNP_INODE *crfsnp_inode_des);

void crfsnp_inode_print(LOG *log, const CRFSNP_INODE *crfsnp_inode);

void crfsnp_inode_log_no_lock(LOG *log, const CRFSNP_INODE *crfsnp_inode);

CRFSNP_FNODE *crfsnp_fnode_new();

CRFSNP_FNODE *crfsnp_fnode_make(const CRFSNP_FNODE *crfsnp_fnode_src);

EC_BOOL crfsnp_fnode_init(CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsnp_fnode_clean(CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsnp_fnode_free(CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsnp_fnode_clone(const CRFSNP_FNODE *crfsnp_fnode_src, CRFSNP_FNODE *crfsnp_fnode_des);

EC_BOOL crfsnp_fnode_check_inode_exist(const CRFSNP_INODE *inode, const CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsnp_fnode_cmp(const CRFSNP_FNODE *crfsnp_fnode_1st, const CRFSNP_FNODE *crfsnp_fnode_2nd);

EC_BOOL crfsnp_fnode_import(const CRFSNP_FNODE *crfsnp_fnode_src, CRFSNP_FNODE *crfsnp_fnode_des);

uint32_t crfsnp_fnode_count_replica(const CRFSNP_FNODE *crfsnp_fnode);

void crfsnp_fnode_print(LOG *log, const CRFSNP_FNODE *crfsnp_fnode);

void crfsnp_fnode_log_no_lock(LOG *log, const CRFSNP_FNODE *crfsnp_fnode);

CRFSNP_DNODE *crfsnp_dnode_new();

EC_BOOL crfsnp_dnode_init(CRFSNP_DNODE *crfsnp_dnode);

EC_BOOL crfsnp_dnode_clean(CRFSNP_DNODE *crfsnp_dnode);

EC_BOOL crfsnp_dnode_free(CRFSNP_DNODE *crfsnp_dnode);

EC_BOOL crfsnp_dnode_clone(const CRFSNP_DNODE *crfsnp_dnode_src, CRFSNP_DNODE *crfsnp_dnode_des);

CRFSNP_KEY *crfsnp_key_new();

EC_BOOL crfsnp_key_init(CRFSNP_KEY *crfsnp_key);

EC_BOOL crfsnp_key_clean(CRFSNP_KEY *crfsnp_key);

EC_BOOL crfsnp_key_clone(const CRFSNP_KEY *crfsnp_key_src, CRFSNP_KEY *crfsnp_key_des);

EC_BOOL crfsnp_key_free(CRFSNP_KEY *crfsnp_key);

EC_BOOL crfsnp_key_set(CRFSNP_KEY *crfsnp_key, const uint32_t klen, const uint8_t *key);

void    crfsnp_key_print(LOG *log, const CRFSNP_KEY *crfsnp_key);

CRFSNP_ITEM *crfsnp_item_new();

EC_BOOL crfsnp_item_init(CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_item_clean(CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_item_clone(const CRFSNP_ITEM *crfsnp_item_src, CRFSNP_ITEM *crfsnp_item_des);

EC_BOOL crfsnp_item_free(CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_item_set_key(CRFSNP_ITEM *crfsnp_item, const uint32_t klen, const uint8_t *key);

void crfsnp_item_print(LOG *log, const CRFSNP_ITEM *crfsnp_item);

void crfsnp_item_and_key_print(LOG *log, const CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_item_load(CRFSNP *crfsnp, uint32_t *offset, CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_item_flush(CRFSNP *crfsnp, uint32_t *offset, const CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_item_is(const CRFSNP_ITEM *crfsnp_item, const uint32_t klen, const uint8_t *key);

CRFSNP_ITEM *crfsnp_item_parent(const CRFSNP *crfsnp, const CRFSNP_ITEM *crfsnp_item);

CRFSNP_ITEM *crfsnp_item_left(const CRFSNP *crfsnp, const CRFSNP_ITEM *crfsnp_item);

CRFSNP_ITEM *crfsnp_item_right(const CRFSNP *crfsnp, const CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_dit_node_init(CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_dit_node_clean(CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_header_init(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const uint8_t model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id);

EC_BOOL crfsnp_header_clean(CRFSNP_HEADER *crfsnp_header);

CRFSNP_HEADER *crfsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd);

CRFSNP_HEADER *crfsnp_header_clone(CRFSNP_HEADER *src_crfsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd);

CRFSNP_HEADER *crfsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model);

CRFSNP_HEADER *crfsnp_header_sync(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd);

CRFSNP_HEADER *crfsnp_header_close(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd);

CRFSNP *crfsnp_new();

EC_BOOL crfsnp_init(CRFSNP *crfsnp);

EC_BOOL crfsnp_clean(CRFSNP *crfsnp);

EC_BOOL crfsnp_free(CRFSNP *crfsnp);

EC_BOOL crfsnp_is_full(const CRFSNP *crfsnp);

EC_BOOL crfsnp_lru_list_is_empty(const CRFSNP *crfsnp);

EC_BOOL crfsnp_del_list_is_empty(const CRFSNP *crfsnp);

void crfsnp_header_print(LOG *log, const CRFSNP *crfsnp);

void crfsnp_print(LOG *log, const CRFSNP *crfsnp);

void crfsnp_print_lru_list(LOG *log, const CRFSNP *crfsnp);

void crfsnp_print_del_list(LOG *log, const CRFSNP *crfsnp);

CRFSNP_ITEM *crfsnp_dnode_find(const CRFSNP *crfsnp, const CRFSNP_DNODE *crfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key);

uint32_t crfsnp_dnode_search(const CRFSNP *crfsnp, const CRFSNP_DNODE *crfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key);

uint32_t crfsnp_dnode_match(CRFSNP *crfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t crfsnp_dnode_insert(CRFSNP *crfsnp, const uint32_t parent_pos, const uint32_t path_seg_second_hash, const uint32_t path_seg_len, const uint8_t *path_seg, const uint32_t dir_flag);

/**
* umount one son from crfsnp_dnode,  where son is regular file item or dir item without any son
* crfsnp_dnode will be impacted on bucket and file num
**/
uint32_t crfsnp_dnode_umount_son(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, const uint32_t son_node_pos, const uint32_t second_hash, const uint32_t klen, const uint8_t *key);
EC_BOOL crfsnp_dnode_delete_dir_son(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode);

uint32_t crfsnp_match_no_lock(CRFSNP *crfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t crfsnp_match(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t crfsnp_search_no_lock(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t crfsnp_search(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t crfsnp_insert_no_lock(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t crfsnp_insert(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

CRFSNP_ITEM *crfsnp_fetch(const CRFSNP *crfsnp, const uint32_t node_pos);

EC_BOOL crfsnp_inode_update(CRFSNP *crfsnp, CRFSNP_INODE *crfsnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL crfsnp_fnode_update(CRFSNP *crfsnp, CRFSNP_FNODE *crfsnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL crfsnp_bucket_update(CRFSNP *crfsnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL crfsnp_dnode_update(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL crfsnp_item_update(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL crfsnp_update_no_lock(CRFSNP *crfsnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL crfsnp_bucket_expire(CRFSNP *crfsnp, const uint32_t node_pos);

EC_BOOL crfsnp_dnode_expire(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode);

EC_BOOL crfsnp_item_expire(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item);

EC_BOOL crfsnp_bucket_walk(CRFSNP *crfsnp, const uint32_t node_pos, CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_dnode_walk(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_item_walk(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_DIT_NODE *crfsnp_dit_node);

CRFSNP_ITEM *crfsnp_set(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

CRFSNP_ITEM *crfsnp_get(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL crfsnp_delete(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL crfsnp_expire(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL crfsnp_retire(CRFSNP *crfsnp, const UINT32 expect_retire_num, UINT32 *ret_retire_num);

EC_BOOL crfsnp_walk(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_umount_item(CRFSNP *crfsnp, const uint32_t node_pos);

EC_BOOL crfsnp_umount_item_deep(CRFSNP *crfsnp, const uint32_t node_pos);

EC_BOOL crfsnp_umount(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL crfsnp_umount_wildcard(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL crfsnp_recycle_item_file(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn);

EC_BOOL crfsnp_recycle_dnode_item(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn);

EC_BOOL crfsnp_recycle_dnode(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, const uint32_t node_pos,CRFSNP_RECYCLE_NP *crfsnp_recycle_np,  CRFSNP_RECYCLE_DN *crfsnp_recycle_dn);

EC_BOOL crfsnp_recycle_item_dir(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn);

/*note: this interface is for that crfsnp_item had umounted from parent, not need to update parent info*/
EC_BOOL crfsnp_recycle_item(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn);

EC_BOOL crfsnp_recycle(CRFSNP *crfsnp, const UINT32 max_num, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn, UINT32 *complete_num);

EC_BOOL crfsnp_path_name(const CRFSNP *crfsnp, const uint32_t node_pos, const uint32_t path_max_len, uint32_t *path_len, uint8_t *path);

EC_BOOL crfsnp_path_name_cstr(const CRFSNP *crfsnp, const uint32_t node_pos, CSTRING *path_cstr);

EC_BOOL crfsnp_seg_name(const CRFSNP *crfsnp, const uint32_t offset, const uint32_t seg_name_max_len, uint32_t *seg_name_len, uint8_t *seg_name);

EC_BOOL crfsnp_seg_name_cstr(const CRFSNP *crfsnp, const uint32_t offset, CSTRING *seg_cstr);

EC_BOOL crfsnp_list_path_vec(const CRFSNP *crfsnp, const uint32_t node_pos, CVECTOR *path_cstr_vec);

EC_BOOL crfsnp_list_seg_vec(const CRFSNP *crfsnp, const uint32_t node_pos, CVECTOR *seg_cstr_vec);

EC_BOOL crfsnp_file_num(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_num);

EC_BOOL crfsnp_file_size(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, uint64_t *file_size);

EC_BOOL crfsnp_mkdirs(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path);

CRFSNP *crfsnp_open(const char *np_root_dir, const uint32_t np_id);

EC_BOOL crfsnp_close(CRFSNP *crfsnp);

EC_BOOL crfsnp_sync(CRFSNP *crfsnp);

EC_BOOL crfsnp_create_root_item(CRFSNP *crfsnp);

CRFSNP *crfsnp_clone(CRFSNP *src_crfsnp, const char *np_root_dir, const uint32_t des_np_id);

CRFSNP *crfsnp_create(const char *np_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id);

EC_BOOL crfsnp_show_item_full_path(LOG *log, const CRFSNP *crfsnp, const uint32_t node_pos);

EC_BOOL crfsnp_show_item(LOG *log, const CRFSNP *crfsnp, const uint32_t node_pos);

EC_BOOL crfsnp_show_dir(LOG *log, const CRFSNP *crfsnp, const CRFSNP_ITEM  *crfsnp_item);

EC_BOOL crfsnp_show_path(LOG *log, CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path);

EC_BOOL crfsnp_show_dir_depth(LOG *log, const CRFSNP *crfsnp, const CRFSNP_ITEM  *crfsnp_item);

EC_BOOL crfsnp_show_item_depth(LOG *log, const CRFSNP *crfsnp, const uint32_t node_pos);

EC_BOOL crfsnp_show_path_depth(LOG *log, CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path);

EC_BOOL crfsnp_get_first_fname_of_dir(const CRFSNP *crfsnp, const CRFSNP_ITEM  *crfsnp_item, uint8_t **fname, uint32_t *dflag);

EC_BOOL crfsnp_get_first_fname_of_path(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, uint8_t **fname, uint32_t *dflag);

CRFSNP *crfsnp_mem_create(const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id);

EC_BOOL crfsnp_mem_clean(CRFSNP *crfsnp);

EC_BOOL crfsnp_mem_free(CRFSNP *crfsnp);

#endif/* _CRFSNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

