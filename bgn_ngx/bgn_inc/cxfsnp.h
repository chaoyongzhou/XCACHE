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

#ifndef _CXFSNP_H
#define _CXFSNP_H

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
#include "real.h"

#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"
#include "task.inc"
#include "chashalgo.h"
#include "cxfsnprb.h"
#include "cxfsnp.inc"
#include "cxfsop.h"

const char *cxfsnp_model_str(const uint8_t cxfsnp_model);

uint8_t cxfsnp_model_get(const char *model_str);

EC_BOOL cxfsnp_model_file_size(const uint8_t cxfsnp_model, UINT32 *file_size);

EC_BOOL cxfsnp_model_item_max_num(const uint8_t cxfsnp_model, uint32_t *item_max_num);

EC_BOOL cxfsnp_inode_init(CXFSNP_INODE *cxfsnp_inode);

EC_BOOL cxfsnp_inode_clean(CXFSNP_INODE *cxfsnp_inode);

EC_BOOL cxfsnp_inode_clone(const CXFSNP_INODE *cxfsnp_inode_src, CXFSNP_INODE *cxfsnp_inode_des);

void cxfsnp_inode_print(LOG *log, const CXFSNP_INODE *cxfsnp_inode);

void cxfsnp_inode_log_no_lock(LOG *log, const CXFSNP_INODE *cxfsnp_inode);

CXFSNP_FNODE *cxfsnp_fnode_new();

CXFSNP_FNODE *cxfsnp_fnode_make(const CXFSNP_FNODE *cxfsnp_fnode_src);

EC_BOOL cxfsnp_fnode_init(CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfsnp_fnode_clean(CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfsnp_fnode_free(CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfsnp_fnode_clone(const CXFSNP_FNODE *cxfsnp_fnode_src, CXFSNP_FNODE *cxfsnp_fnode_des);

EC_BOOL cxfsnp_fnode_check_inode_exist(const CXFSNP_INODE *inode, const CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfsnp_fnode_cmp(const CXFSNP_FNODE *cxfsnp_fnode_1st, const CXFSNP_FNODE *cxfsnp_fnode_2nd);

EC_BOOL cxfsnp_fnode_import(const CXFSNP_FNODE *cxfsnp_fnode_src, CXFSNP_FNODE *cxfsnp_fnode_des);

uint32_t cxfsnp_fnode_count_replica(const CXFSNP_FNODE *cxfsnp_fnode);

void cxfsnp_fnode_print(LOG *log, const CXFSNP_FNODE *cxfsnp_fnode);

void cxfsnp_fnode_log_no_lock(LOG *log, const CXFSNP_FNODE *cxfsnp_fnode);

CXFSNP_DNODE *cxfsnp_dnode_new();

EC_BOOL cxfsnp_dnode_init(CXFSNP_DNODE *cxfsnp_dnode);

EC_BOOL cxfsnp_dnode_clean(CXFSNP_DNODE *cxfsnp_dnode);

EC_BOOL cxfsnp_dnode_free(CXFSNP_DNODE *cxfsnp_dnode);

EC_BOOL cxfsnp_dnode_clone(const CXFSNP_DNODE *cxfsnp_dnode_src, CXFSNP_DNODE *cxfsnp_dnode_des);

CXFSNP_KEY *cxfsnp_key_new();

EC_BOOL cxfsnp_key_init(CXFSNP_KEY *cxfsnp_key);

EC_BOOL cxfsnp_key_clean(CXFSNP_KEY *cxfsnp_key);

EC_BOOL cxfsnp_key_clone(const CXFSNP_KEY *cxfsnp_key_src, CXFSNP_KEY *cxfsnp_key_des);

EC_BOOL cxfsnp_key_free(CXFSNP_KEY *cxfsnp_key);

EC_BOOL cxfsnp_key_set(CXFSNP_KEY *cxfsnp_key, const uint32_t klen, const uint8_t *key);

void    cxfsnp_key_print(LOG *log, const CXFSNP_KEY *cxfsnp_key);

CXFSNP_ATTR *cxfsnp_attr_new();

EC_BOOL cxfsnp_attr_init(CXFSNP_ATTR *cxfsnp_attr);

EC_BOOL cxfsnp_attr_clean(CXFSNP_ATTR *cxfsnp_attr);

EC_BOOL cxfsnp_attr_clone(const CXFSNP_ATTR *cxfsnp_attr_src, CXFSNP_ATTR *cxfsnp_attr_des);

EC_BOOL cxfsnp_attr_free(CXFSNP_ATTR *cxfsnp_attr);

void cxfsnp_attr_print(LOG *log, const CXFSNP_ATTR *cxfsnp_attr);

CXFSNP_ITEM *cxfsnp_item_new();

EC_BOOL cxfsnp_item_init(CXFSNP_ITEM *cxfsnp_item);

EC_BOOL cxfsnp_item_clean(CXFSNP_ITEM *cxfsnp_item);

EC_BOOL cxfsnp_item_clone(const CXFSNP_ITEM *cxfsnp_item_src, CXFSNP_ITEM *cxfsnp_item_des);

EC_BOOL cxfsnp_item_free(CXFSNP_ITEM *cxfsnp_item);

EC_BOOL cxfsnp_item_set_key(CXFSNP_ITEM *cxfsnp_item, const uint32_t klen, const uint8_t *key);

void cxfsnp_item_print(LOG *log, const CXFSNP_ITEM *cxfsnp_item);

void cxfsnp_item_and_key_print(LOG *log, const CXFSNP_ITEM *cxfsnp_item);

EC_BOOL cxfsnp_item_is(const CXFSNP_ITEM *cxfsnp_item, const uint32_t klen, const uint8_t *key);

CXFSNP_ITEM *cxfsnp_item_parent(const CXFSNP *cxfsnp, const CXFSNP_ITEM *cxfsnp_item);

CXFSNP_ITEM *cxfsnp_item_left(const CXFSNP *cxfsnp, const CXFSNP_ITEM *cxfsnp_item);

CXFSNP_ITEM *cxfsnp_item_right(const CXFSNP *cxfsnp, const CXFSNP_ITEM *cxfsnp_item);

EC_BOOL cxfsnp_dit_node_init(CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_dit_node_clean(CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_header_init(CXFSNP_HEADER *cxfsnp_header, const uint32_t np_id, const uint8_t model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id);

EC_BOOL cxfsnp_header_clean(CXFSNP_HEADER *cxfsnp_header);

CXFSNP_HEADER *cxfsnp_header_clone(CXFSNP_HEADER *src_cxfsnp_header, const uint32_t des_np_id, const UINT32 fsize, UINT8 *base);

CXFSNP_HEADER *cxfsnp_header_create(const uint32_t np_id, const uint8_t np_model, UINT8 *base);

CXFSNP_HEADER *cxfsnp_header_close(CXFSNP_HEADER *cxfsnp_header);

CXFSNP *cxfsnp_new();

EC_BOOL cxfsnp_init(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_clean(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_free(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_is_full(const CXFSNP *cxfsnp);

EC_BOOL cxfsnp_set_read_only(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_unset_read_only(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_is_read_only(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_set_op_replay(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_unset_op_replay(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_is_op_replay(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_mount_op_mgr(CXFSNP *cxfsnp, CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsnp_umount_op_mgr(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_que_list_is_empty(const CXFSNP *cxfsnp);

EC_BOOL cxfsnp_del_list_is_empty(const CXFSNP *cxfsnp);

void cxfsnp_header_print(LOG *log, const CXFSNP *cxfsnp);

void cxfsnp_print(LOG *log, const CXFSNP *cxfsnp);

void cxfsnp_print_que_list(LOG *log, const CXFSNP *cxfsnp);

void cxfsnp_print_del_list(LOG *log, const CXFSNP *cxfsnp);

CXFSNP_ITEM *cxfsnp_dnode_find(const CXFSNP *cxfsnp, const CXFSNP_DNODE *cxfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key, const uint32_t dflag);

uint32_t cxfsnp_dnode_search(const CXFSNP *cxfsnp, const CXFSNP_DNODE *cxfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key, const uint32_t dflag);

uint32_t cxfsnp_dnode_match(CXFSNP *cxfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t cxfsnp_dnode_insert(CXFSNP *cxfsnp, const uint32_t parent_pos, const uint32_t path_seg_second_hash, const uint32_t path_seg_len, const uint8_t *path_seg, const uint32_t dir_flag, uint32_t *node_pos);

/**
* umount one son from cxfsnp_dnode,  where son is regular file item or dir item without any son
* cxfsnp_dnode will be impacted on bucket and file num
**/
uint32_t cxfsnp_dnode_umount_son(const CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, const uint32_t son_node_pos, const uint32_t second_hash, const uint32_t klen, const uint8_t *key, const uint32_t dflag);
EC_BOOL cxfsnp_dnode_delete_dir_son(const CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode);

uint32_t cxfsnp_match_no_lock(CXFSNP *cxfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t cxfsnp_match(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t cxfsnp_search_no_lock(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t cxfsnp_search(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t cxfsnp_insert_no_lock(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

uint32_t cxfsnp_insert(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

CXFSNP_ITEM *cxfsnp_fetch(const CXFSNP *cxfsnp, const uint32_t node_pos);

EC_BOOL cxfsnp_inode_update(CXFSNP *cxfsnp, CXFSNP_INODE *cxfsnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cxfsnp_fnode_update(CXFSNP *cxfsnp, CXFSNP_FNODE *cxfsnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cxfsnp_bucket_update(CXFSNP *cxfsnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cxfsnp_dnode_update(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cxfsnp_item_update(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cxfsnp_update_no_lock(CXFSNP *cxfsnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cxfsnp_bucket_expire(CXFSNP *cxfsnp, const uint32_t node_pos);

EC_BOOL cxfsnp_dnode_expire(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode);

EC_BOOL cxfsnp_item_expire(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item);

EC_BOOL cxfsnp_bucket_walk(CXFSNP *cxfsnp, const uint32_t node_pos, CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_dnode_walk(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_item_walk(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_DIT_NODE *cxfsnp_dit_node);

CXFSNP_ITEM *cxfsnp_set(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

CXFSNP_ITEM *cxfsnp_get(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL cxfsnp_delete(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL cxfsnp_expire(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

REAL cxfsnp_used_ratio(const CXFSNP *cxfsnp);

EC_BOOL cxfsnp_retire(CXFSNP *cxfsnp, const UINT32 expect_retire_num, UINT32 *ret_retire_num);

EC_BOOL cxfsnp_walk(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_umount_item(CXFSNP *cxfsnp, const uint32_t node_pos);

EC_BOOL cxfsnp_umount_item_deep(CXFSNP *cxfsnp, const uint32_t node_pos);

EC_BOOL cxfsnp_umount(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL cxfsnp_umount_deep(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL cxfsnp_umount_wildcard(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL cxfsnp_umount_wildcard_deep(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

EC_BOOL cxfsnp_recycle_item_file(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn);

EC_BOOL cxfsnp_recycle_dnode_item(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn);

EC_BOOL cxfsnp_recycle_dnode(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, const uint32_t node_pos,CXFSNP_RECYCLE_NP *cxfsnp_recycle_np,  CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn);

EC_BOOL cxfsnp_recycle_item_dir(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn);

/*note: this interface is for that cxfsnp_item had umounted from parent, not need to update parent info*/
EC_BOOL cxfsnp_recycle_item(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn);

EC_BOOL cxfsnp_recycle(CXFSNP *cxfsnp, const UINT32 max_num, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn, UINT32 *complete_num);

EC_BOOL cxfsnp_path_name(const CXFSNP *cxfsnp, const uint32_t node_pos, const uint32_t path_max_len, uint32_t *path_len, uint8_t *path);

EC_BOOL cxfsnp_path_name_cstr(const CXFSNP *cxfsnp, const uint32_t node_pos, CSTRING *path_cstr);

EC_BOOL cxfsnp_seg_name(const CXFSNP *cxfsnp, const uint32_t offset, const uint32_t seg_name_max_len, uint32_t *seg_name_len, uint8_t *seg_name);

EC_BOOL cxfsnp_seg_name_cstr(const CXFSNP *cxfsnp, const uint32_t offset, CSTRING *seg_cstr);

EC_BOOL cxfsnp_list_path_vec(const CXFSNP *cxfsnp, const uint32_t node_pos, CVECTOR *path_cstr_vec);

EC_BOOL cxfsnp_list_seg_vec(const CXFSNP *cxfsnp, const uint32_t node_pos, CVECTOR *seg_cstr_vec);

EC_BOOL cxfsnp_file_num(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_num);

EC_BOOL cxfsnp_file_size(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, uint64_t *file_size);

EC_BOOL cxfsnp_mkdirs(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path);

CXFSNP *cxfsnp_open(UINT8 *base, const UINT32 size, const uint32_t np_id);

EC_BOOL cxfsnp_close(CXFSNP *cxfsnp);

EC_BOOL cxfsnp_create_root_item(CXFSNP *cxfsnp);

CXFSNP *cxfsnp_clone(CXFSNP *src_cxfsnp, UINT8 *base, const uint32_t des_np_id);

CXFSNP *cxfsnp_create(UINT8 *base, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id);

EC_BOOL cxfsnp_show_item_full_path(LOG *log, const CXFSNP *cxfsnp, const uint32_t node_pos);

EC_BOOL cxfsnp_show_item(LOG *log, const CXFSNP *cxfsnp, const uint32_t node_pos);

EC_BOOL cxfsnp_show_dir(LOG *log, const CXFSNP *cxfsnp, const CXFSNP_ITEM  *cxfsnp_item);

#endif/* _CXFSNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

