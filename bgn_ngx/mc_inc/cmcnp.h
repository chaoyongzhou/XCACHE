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

#ifndef _CMCNP_H
#define _CMCNP_H

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

#include "cmcnprb.h"
#include "cmcnp.inc"

const char *cmcnp_model_str(const uint8_t cmcnp_model);

uint8_t cmcnp_model_get(const char *model_str);

EC_BOOL cmcnp_model_file_size(const uint8_t cmcnp_model, UINT32 *file_size);

EC_BOOL cmcnp_model_item_max_num(const uint8_t cmcnp_model, uint32_t *item_max_num);

EC_BOOL cmcnp_inode_init(CMCNP_INODE *cmcnp_inode);

EC_BOOL cmcnp_inode_clean(CMCNP_INODE *cmcnp_inode);

EC_BOOL cmcnp_inode_clone(const CMCNP_INODE *cmcnp_inode_src, CMCNP_INODE *cmcnp_inode_des);

void cmcnp_inode_print(LOG *log, const CMCNP_INODE *cmcnp_inode);

void cmcnp_inode_log_no_lock(LOG *log, const CMCNP_INODE *cmcnp_inode);

CMCNP_FNODE *cmcnp_fnode_new();

CMCNP_FNODE *cmcnp_fnode_make(const CMCNP_FNODE *cmcnp_fnode_src);

EC_BOOL cmcnp_fnode_init(CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_fnode_clean(CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_fnode_free(CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_fnode_clone(const CMCNP_FNODE *cmcnp_fnode_src, CMCNP_FNODE *cmcnp_fnode_des);

EC_BOOL cmcnp_fnode_check_inode_exist(const CMCNP_INODE *inode, const CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_fnode_cmp(const CMCNP_FNODE *cmcnp_fnode_1st, const CMCNP_FNODE *cmcnp_fnode_2nd);

EC_BOOL cmcnp_fnode_import(const CMCNP_FNODE *cmcnp_fnode_src, CMCNP_FNODE *cmcnp_fnode_des);

void cmcnp_fnode_print(LOG *log, const CMCNP_FNODE *cmcnp_fnode);

void cmcnp_fnode_log_no_lock(LOG *log, const CMCNP_FNODE *cmcnp_fnode);

CMCNP_DNODE *cmcnp_dnode_new();

EC_BOOL cmcnp_dnode_init(CMCNP_DNODE *cmcnp_dnode);

EC_BOOL cmcnp_dnode_clean(CMCNP_DNODE *cmcnp_dnode);

EC_BOOL cmcnp_dnode_free(CMCNP_DNODE *cmcnp_dnode);

EC_BOOL cmcnp_dnode_clone(const CMCNP_DNODE *cmcnp_dnode_src, CMCNP_DNODE *cmcnp_dnode_des);

CMCNP_KEY *cmcnp_key_new();

EC_BOOL cmcnp_key_init(CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_key_clean(CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_key_clone(const CMCNP_KEY *cmcnp_key_src, CMCNP_KEY *cmcnp_key_des);

EC_BOOL cmcnp_key_free(CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_key_set(CMCNP_KEY *cmcnp_key, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset);

void    cmcnp_key_print(LOG *log, const CMCNP_KEY *cmcnp_key);

CMCNP_ITEM *cmcnp_item_new();

EC_BOOL cmcnp_item_init(CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_clean(CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_clone(const CMCNP_ITEM *cmcnp_item_src, CMCNP_ITEM *cmcnp_item_des);

EC_BOOL cmcnp_item_free(CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_set_key(CMCNP_ITEM *cmcnp_item, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset);

void cmcnp_item_print(LOG *log, const CMCNP_ITEM *cmcnp_item);

void cmcnp_item_and_key_print(LOG *log, const CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_is(const CMCNP_ITEM *cmcnp_item, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset);

CMCNP_ITEM *cmcnp_item_parent(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item);

CMCNP_ITEM *cmcnp_item_left(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item);

CMCNP_ITEM *cmcnp_item_right(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_header_init(CMCNP_HEADER *cmcnp_header, const uint32_t np_id, const uint8_t model);

EC_BOOL cmcnp_header_clean(CMCNP_HEADER *cmcnp_header);

CMCNP *cmcnp_new();

EC_BOOL cmcnp_init(CMCNP *cmcnp);

EC_BOOL cmcnp_clean(CMCNP *cmcnp);

EC_BOOL cmcnp_free(CMCNP *cmcnp);

EC_BOOL cmcnp_is_full(const CMCNP *cmcnp);

EC_BOOL cmcnp_lru_list_is_empty(const CMCNP *cmcnp);

EC_BOOL cmcnp_del_list_is_empty(const CMCNP *cmcnp);

void cmcnp_header_print(LOG *log, const CMCNP *cmcnp);

void cmcnp_print(LOG *log, const CMCNP *cmcnp);

void cmcnp_print_lru_list(LOG *log, const CMCNP *cmcnp);

void cmcnp_print_del_list(LOG *log, const CMCNP *cmcnp);

CMCNP_ITEM *cmcnp_dnode_find(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset);

uint32_t cmcnp_dnode_search(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key);

uint32_t cmcnp_dnode_insert(CMCNP *cmcnp, const uint32_t parent_pos,
                                    const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset,
                                    const uint32_t dir_flag);

/**
* umount one son from cmcnp_dnode,  where son is regular file item or dir item without any son
* cmcnp_dnode will be impacted on bucket and file num
**/
uint32_t cmcnp_dnode_umount_son(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, const uint32_t son_node_pos, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset);
EC_BOOL cmcnp_dnode_delete_dir_son(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode);

uint32_t cmcnp_search_no_lock(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

uint32_t cmcnp_search(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

uint32_t cmcnp_insert_no_lock(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

uint32_t cmcnp_insert(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

CMCNP_ITEM *cmcnp_fetch(const CMCNP *cmcnp, const uint32_t node_pos);

EC_BOOL cmcnp_inode_update(CMCNP *cmcnp, CMCNP_INODE *cmcnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cmcnp_fnode_update(CMCNP *cmcnp, CMCNP_FNODE *cmcnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cmcnp_bucket_update(CMCNP *cmcnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cmcnp_dnode_update(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cmcnp_item_update(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cmcnp_update_no_lock(CMCNP *cmcnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

CMCNP_ITEM *cmcnp_set(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

CMCNP_ITEM *cmcnp_get(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

CMCNP_FNODE *cmcnp_reserve(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset);

EC_BOOL cmcnp_release(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset);

EC_BOOL cmcnp_read(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_delete(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

EC_BOOL cmcnp_update(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_retire(CMCNP *cmcnp, const UINT32 expect_retire_num, UINT32 *ret_retire_num);

EC_BOOL cmcnp_umount_item(CMCNP *cmcnp, const uint32_t node_pos);

EC_BOOL cmcnp_umount_item_deep(CMCNP *cmcnp, const uint32_t node_pos);

EC_BOOL cmcnp_umount(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

EC_BOOL cmcnp_umount_deep(CMCNP *cmcnp, const uint32_t block_no, const uint16_t block_s_offset, const uint16_t block_e_offset, const uint32_t dflag);

EC_BOOL cmcnp_recycle_item_file(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle_dnode_item(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle_dnode(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, const uint32_t node_pos,CMCNP_RECYCLE_NP *cmcnp_recycle_np,  CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle_item_dir(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

/*note: this interface is for that cmcnp_item had umounted from parent, not need to update parent info*/
EC_BOOL cmcnp_recycle_item(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle(CMCNP *cmcnp, const UINT32 max_num, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn, UINT32 *complete_num);

EC_BOOL cmcnp_file_num(CMCNP *cmcnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_num);

EC_BOOL cmcnp_file_size(CMCNP *cmcnp, const uint32_t path_len, const uint8_t *path, uint64_t *file_size);

EC_BOOL cmcnp_create_root_item(CMCNP *cmcnp);

CMCNP *cmcnp_create(const uint32_t np_id, const uint8_t np_model);


#endif/* _CMCNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/


