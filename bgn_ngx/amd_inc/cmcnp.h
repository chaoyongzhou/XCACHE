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

EC_BOOL cmcnp_model_search(const UINT32 mem_disk_size /*in byte*/, uint8_t *cmcnp_model);

EC_BOOL cmcnp_inode_init(CMCNP_INODE *cmcnp_inode);

EC_BOOL cmcnp_inode_clean(CMCNP_INODE *cmcnp_inode);

EC_BOOL cmcnp_inode_clone(const CMCNP_INODE *cmcnp_inode_src, CMCNP_INODE *cmcnp_inode_des);

void cmcnp_inode_print(LOG *log, const CMCNP_INODE *cmcnp_inode);

void cmcnp_inode_log(LOG *log, const CMCNP_INODE *cmcnp_inode);

CMCNP_FNODE *cmcnp_fnode_new();

CMCNP_FNODE *cmcnp_fnode_make(const CMCNP_FNODE *cmcnp_fnode_src);

EC_BOOL cmcnp_fnode_init(CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_fnode_clean(CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_fnode_free(CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_fnode_clone(const CMCNP_FNODE *cmcnp_fnode_src, CMCNP_FNODE *cmcnp_fnode_des);

EC_BOOL cmcnp_fnode_import(const CMCNP_FNODE *cmcnp_fnode_src, CMCNP_FNODE *cmcnp_fnode_des);

void cmcnp_fnode_print(LOG *log, const CMCNP_FNODE *cmcnp_fnode);

void cmcnp_fnode_log(LOG *log, const CMCNP_FNODE *cmcnp_fnode);

CMCNP_DNODE *cmcnp_dnode_new();

EC_BOOL cmcnp_dnode_init(CMCNP_DNODE *cmcnp_dnode);

EC_BOOL cmcnp_dnode_clean(CMCNP_DNODE *cmcnp_dnode);

EC_BOOL cmcnp_dnode_free(CMCNP_DNODE *cmcnp_dnode);

EC_BOOL cmcnp_dnode_clone(const CMCNP_DNODE *cmcnp_dnode_src, CMCNP_DNODE *cmcnp_dnode_des);

CMCNP_KEY *cmcnp_key_new();

EC_BOOL cmcnp_key_init(CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_key_clean(CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_key_clone(const CMCNP_KEY *cmcnp_key_src, CMCNP_KEY *cmcnp_key_des);

EC_BOOL cmcnp_key_cmp(const CMCNP_KEY *cmcnp_key_1st, const CMCNP_KEY *cmcnp_key_2nd);

EC_BOOL cmcnp_key_free(CMCNP_KEY *cmcnp_key);

void    cmcnp_key_print(LOG *log, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_key_is_valid(const CMCNP_KEY *cmcnp_key);

uint32_t cmcnp_key_hash(const CMCNP_KEY *cmcnp_key);

CMCNP_ITEM *cmcnp_item_new();

EC_BOOL cmcnp_item_init(CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_clean(CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_clone(const CMCNP_ITEM *cmcnp_item_src, CMCNP_ITEM *cmcnp_item_des);

EC_BOOL cmcnp_item_free(CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_set_key(CMCNP_ITEM *cmcnp_item, const CMCNP_KEY *cmcnp_key);

void cmcnp_item_print(LOG *log, const CMCNP_ITEM *cmcnp_item);

void cmcnp_item_and_key_print(LOG *log, const CMCNP_ITEM *cmcnp_item);

EC_BOOL cmcnp_item_is(const CMCNP_ITEM *cmcnp_item, const CMCNP_KEY *cmcnp_key);

CMCNP_ITEM *cmcnp_item_parent(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item);

CMCNP_ITEM *cmcnp_item_left(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item);

CMCNP_ITEM *cmcnp_item_right(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item);

CMCNP_BITMAP *cmcnp_bitmap_new(const UINT32 nbits);

EC_BOOL cmcnp_bitmap_init(CMCNP_BITMAP *cmcnp_bitmap, const UINT32 size);

EC_BOOL cmcnp_bitmap_clean(CMCNP_BITMAP *cmcnp_bitmap);

EC_BOOL cmcnp_bitmap_free(CMCNP_BITMAP *cmcnp_bitmap);

EC_BOOL cmcnp_bitmap_set(CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos);

EC_BOOL cmcnp_bitmap_clear(CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos);

EC_BOOL cmcnp_bitmap_get(const CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos, uint8_t *bit_val);

EC_BOOL cmcnp_bitmap_is(const CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos, const uint8_t bit_val);

void cmcnp_bitmap_print(LOG *log, const CMCNP_BITMAP *cmcnp_bitmap);

/*count the num of bit 1*/
UINT32 cmcnp_bitmap_count_bits(const CMCNP_BITMAP *cmcnp_bitmap, const UINT32 s_bit_pos, const UINT32 e_bit_pos);

EC_BOOL cmcnp_header_init(CMCNP_HEADER *cmcnp_header, const uint32_t np_id, const uint8_t model);

EC_BOOL cmcnp_header_clean(CMCNP_HEADER *cmcnp_header);

REAL cmcnp_header_used_ratio(const CMCNP_HEADER *cmcnp_header);

REAL cmcnp_header_deg_ratio(const CMCNP_HEADER *cmcnp_header);

CMCNP *cmcnp_new();

EC_BOOL cmcnp_init(CMCNP *cmcnp);

EC_BOOL cmcnp_clean(CMCNP *cmcnp);

EC_BOOL cmcnp_free(CMCNP *cmcnp);

EC_BOOL cmcnp_is_full(const CMCNP *cmcnp);

EC_BOOL cmcnp_lru_list_is_empty(const CMCNP *cmcnp);

EC_BOOL cmcnp_del_list_is_empty(const CMCNP *cmcnp);

EC_BOOL cmcnp_deg_list_is_empty(const CMCNP *cmcnp);

EC_BOOL cmcnp_reserve_key(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_release_key(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

void cmcnp_header_print(LOG *log, const CMCNP *cmcnp);

void cmcnp_print(LOG *log, const CMCNP *cmcnp);

void cmcnp_print_lru_list(LOG *log, const CMCNP *cmcnp);

void cmcnp_print_del_list(LOG *log, const CMCNP *cmcnp);

void cmcnp_print_deg_list(LOG *log, const CMCNP *cmcnp);

void cmcnp_print_bitmap(LOG *log, const CMCNP *cmcnp);

CMCNP_ITEM *cmcnp_dnode_find(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key);

uint32_t cmcnp_dnode_search(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key);

void cmcnp_dnode_walk(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, void (*walker)(void *, const void *, const uint32_t), void *arg);

uint32_t cmcnp_dnode_find_intersected(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key);

uint32_t cmcnp_dnode_find_closest(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key);

uint32_t cmcnp_dnode_insert(CMCNP *cmcnp, const uint32_t parent_pos, const CMCNP_KEY *cmcnp_key, const uint32_t dir_flag);

/**
* umount one son from cmcnp_dnode,  where son is regular file item or dir item without any son
* cmcnp_dnode will be impacted on bucket and file num
**/
uint32_t cmcnp_dnode_umount_son(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, const uint32_t son_node_pos, const CMCNP_KEY *cmcnp_key);
EC_BOOL cmcnp_dnode_delete_dir_son(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode);

uint32_t cmcnp_search(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag);

void cmcnp_walk(CMCNP *cmcnp, void (*walker)(void *, const void *, const uint32_t), void *arg);

uint32_t cmcnp_insert(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag);

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

REAL cmcnp_used_ratio(const CMCNP *cmcnp);

REAL cmcnp_deg_ratio(const CMCNP *cmcnp);

uint32_t cmcnp_deg_num(const CMCNP *cmcnp);

CMCNP_ITEM *cmcnp_set(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag);

CMCNP_ITEM *cmcnp_get(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag);

CMCNP_FNODE *cmcnp_reserve(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_release(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_has_key(const CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_set_key(const CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_clear_key(const CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

CMCNP_FNODE *cmcnp_locate(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

CMCNP_ITEM *cmcnp_map(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_read(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_delete(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag);

EC_BOOL cmcnp_update(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const CMCNP_FNODE *cmcnp_fnode);

EC_BOOL cmcnp_set_ssd_dirty(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_set_ssd_not_dirty(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmcnp_degrade_cb_init(CMCNP_DEGRADE_CB *cmcnp_degrade_cb);

EC_BOOL cmcnp_degrade_cb_clean(CMCNP_DEGRADE_CB *cmcnp_degrade_cb);

EC_BOOL cmcnp_degrade_cb_clone(CMCNP_DEGRADE_CB *cmcnp_degrade_cb_src, CMCNP_DEGRADE_CB *cmcnp_degrade_cb_des);

EC_BOOL cmcnp_degrade_cb_set(CMCNP_DEGRADE_CB *cmcnp_degrade_cb, CMCNP_DEGRADE_CALLBACK func, void *arg);

EC_BOOL cmcnp_init_degrade_callback(CMCNP *cmcnp);

EC_BOOL cmcnp_clean_degrade_callback(CMCNP *cmcnp);

EC_BOOL cmcnp_set_degrade_callback(CMCNP *cmcnp, CMCNP_DEGRADE_CALLBACK func, void *arg);

EC_BOOL cmcnp_exec_degrade_callback(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t node_pos);

EC_BOOL cmcnp_degrade(CMCNP *cmcnp, const UINT32 scan_max_num, const UINT32 expect_degrade_num, UINT32 *complete_degrade_num);

EC_BOOL cmcnp_retire_cb_init(CMCNP_RETIRE_CB *cmcnp_retire_cb);

EC_BOOL cmcnp_retire_cb_clean(CMCNP_RETIRE_CB *cmcnp_retire_cb);

EC_BOOL cmcnp_retire_cb_clone(CMCNP_RETIRE_CB *cmcnp_retire_cb_src, CMCNP_RETIRE_CB *cmcnp_retire_cb_des);

EC_BOOL cmcnp_retire_cb_set(CMCNP_RETIRE_CB *cmcnp_retire_cb, CMCNP_RETIRE_CALLBACK func, void *arg);

EC_BOOL cmcnp_init_retire_callback(CMCNP *cmcnp);

EC_BOOL cmcnp_clean_retire_callback(CMCNP *cmcnp);

EC_BOOL cmcnp_set_retire_callback(CMCNP *cmcnp, CMCNP_RETIRE_CALLBACK func, void *arg);

EC_BOOL cmcnp_exec_retire_callback(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t node_pos);

EC_BOOL cmcnp_degrade_all(CMCNP *cmcnp, UINT32 *complete_degrade_num);

EC_BOOL cmcnp_degrade(CMCNP *cmcnp, const UINT32 scan_max_num, const UINT32 expect_degrade_num, UINT32 *complete_degrade_num);

EC_BOOL cmcnp_retire(CMCNP *cmcnp, const UINT32 scan_max_num, const UINT32 expect_retire_num, UINT32 *ret_retire_num);

EC_BOOL cmcnp_umount_item(CMCNP *cmcnp, const uint32_t node_pos);

EC_BOOL cmcnp_umount(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag);

EC_BOOL cmcnp_recycle_item_file(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle_dnode_item(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle_dnode(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, const uint32_t node_pos,CMCNP_RECYCLE_NP *cmcnp_recycle_np,  CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle_item_dir(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

/*note: this interface is for that cmcnp_item had umounted from parent, not need to update parent info*/
EC_BOOL cmcnp_recycle_item(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn);

EC_BOOL cmcnp_recycle(CMCNP *cmcnp, const UINT32 max_num, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn, UINT32 *complete_num);

EC_BOOL cmcnp_file_num(CMCNP *cmcnp, uint32_t *file_num);

EC_BOOL cmcnp_file_size(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, UINT32 *file_size);

void cmcnp_file_print(LOG *log, const CMCNP *cmcnp, const uint32_t node_pos);

EC_BOOL cmcnp_create_root_item(CMCNP *cmcnp);

CMCNP *cmcnp_create(const uint32_t np_id, const uint8_t np_model, const UINT32 key_max_num);


#endif/* _CMCNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/


