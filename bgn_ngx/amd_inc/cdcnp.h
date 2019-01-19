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

#ifndef _CDCNP_H
#define _CDCNP_H

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

#include "cdcnprb.h"
#include "cdcnp.inc"

const char *cdcnp_model_str(const uint8_t cdcnp_model);

uint8_t cdcnp_model_get(const char *model_str);

EC_BOOL cdcnp_model_file_size(const uint8_t cdcnp_model, UINT32 *file_size);

EC_BOOL cdcnp_model_item_max_num(const uint8_t cdcnp_model, uint32_t *item_max_num);

EC_BOOL cdcnp_model_search(const UINT32 ssd_disk_size /*in byte*/, uint8_t *cdcnp_model);

EC_BOOL cdcnp_inode_init(CDCNP_INODE *cdcnp_inode);

EC_BOOL cdcnp_inode_clean(CDCNP_INODE *cdcnp_inode);

EC_BOOL cdcnp_inode_clone(const CDCNP_INODE *cdcnp_inode_src, CDCNP_INODE *cdcnp_inode_des);

void cdcnp_inode_print(LOG *log, const CDCNP_INODE *cdcnp_inode);

void cdcnp_inode_log(LOG *log, const CDCNP_INODE *cdcnp_inode);

CDCNP_FNODE *cdcnp_fnode_new();

CDCNP_FNODE *cdcnp_fnode_make(const CDCNP_FNODE *cdcnp_fnode_src);

EC_BOOL cdcnp_fnode_init(CDCNP_FNODE *cdcnp_fnode);

EC_BOOL cdcnp_fnode_clean(CDCNP_FNODE *cdcnp_fnode);

EC_BOOL cdcnp_fnode_free(CDCNP_FNODE *cdcnp_fnode);

EC_BOOL cdcnp_fnode_clone(const CDCNP_FNODE *cdcnp_fnode_src, CDCNP_FNODE *cdcnp_fnode_des);

EC_BOOL cdcnp_fnode_import(const CDCNP_FNODE *cdcnp_fnode_src, CDCNP_FNODE *cdcnp_fnode_des);

void cdcnp_fnode_print(LOG *log, const CDCNP_FNODE *cdcnp_fnode);

void cdcnp_fnode_log(LOG *log, const CDCNP_FNODE *cdcnp_fnode);

CDCNP_DNODE *cdcnp_dnode_new();

EC_BOOL cdcnp_dnode_init(CDCNP_DNODE *cdcnp_dnode);

EC_BOOL cdcnp_dnode_clean(CDCNP_DNODE *cdcnp_dnode);

EC_BOOL cdcnp_dnode_free(CDCNP_DNODE *cdcnp_dnode);

EC_BOOL cdcnp_dnode_clone(const CDCNP_DNODE *cdcnp_dnode_src, CDCNP_DNODE *cdcnp_dnode_des);

CDCNP_KEY *cdcnp_key_new();

EC_BOOL cdcnp_key_init(CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_key_clean(CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_key_clone(const CDCNP_KEY *cdcnp_key_src, CDCNP_KEY *cdcnp_key_des);

EC_BOOL cdcnp_key_cmp(const CDCNP_KEY *cdcnp_key_1st, const CDCNP_KEY *cdcnp_key_2nd);

EC_BOOL cdcnp_key_free(CDCNP_KEY *cdcnp_key);

void    cdcnp_key_print(LOG *log, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_key_is_valid(const CDCNP_KEY *cdcnp_key);

uint32_t cdcnp_key_hash(const CDCNP_KEY *cdcnp_key);

CDCNP_ITEM *cdcnp_item_new();

EC_BOOL cdcnp_item_init(CDCNP_ITEM *cdcnp_item);

EC_BOOL cdcnp_item_clean(CDCNP_ITEM *cdcnp_item);

EC_BOOL cdcnp_item_clone(const CDCNP_ITEM *cdcnp_item_src, CDCNP_ITEM *cdcnp_item_des);

EC_BOOL cdcnp_item_free(CDCNP_ITEM *cdcnp_item);

EC_BOOL cdcnp_item_set_key(CDCNP_ITEM *cdcnp_item, const CDCNP_KEY *cdcnp_key);

void cdcnp_item_print(LOG *log, const CDCNP_ITEM *cdcnp_item);

void cdcnp_item_and_key_print(LOG *log, const CDCNP_ITEM *cdcnp_item);

EC_BOOL cdcnp_item_is(const CDCNP_ITEM *cdcnp_item, const CDCNP_KEY *cdcnp_key);

CDCNP_ITEM *cdcnp_item_parent(const CDCNP *cdcnp, const CDCNP_ITEM *cdcnp_item);

CDCNP_ITEM *cdcnp_item_left(const CDCNP *cdcnp, const CDCNP_ITEM *cdcnp_item);

CDCNP_ITEM *cdcnp_item_right(const CDCNP *cdcnp, const CDCNP_ITEM *cdcnp_item);

EC_BOOL cdcnp_bitmap_init(CDCNP_BITMAP *cdcnp_bitmap, const uint32_t nbits);

EC_BOOL cdcnp_bitmap_clean(CDCNP_BITMAP *cdcnp_bitmap);

EC_BOOL cdcnp_bitmap_set(CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos);

EC_BOOL cdcnp_bitmap_clear(CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos);

EC_BOOL cdcnp_bitmap_get(const CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos, uint8_t *bit_val);

EC_BOOL cdcnp_bitmap_is(const CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos, const uint8_t bit_val);

void cdcnp_bitmap_print(LOG *log, const CDCNP_BITMAP *cdcnp_bitmap);

/*count the num of bit 1*/
uint32_t cdcnp_bitmap_count_bits(const CDCNP_BITMAP *cdcnp_bitmap, const uint32_t s_bit_pos, const uint32_t e_bit_pos);

CDCNP_HEADER *cdcnp_header_new(const uint32_t np_id, const UINT32 fsize, const uint8_t np_model);

EC_BOOL cdcnp_header_init(CDCNP_HEADER *cdcnp_header, const uint32_t np_id, const uint8_t model);

EC_BOOL cdcnp_header_clean(CDCNP_HEADER *cdcnp_header);

CDCNP_HEADER *cdcnp_header_free(CDCNP_HEADER *cdcnp_header);

REAL cdcnp_header_used_ratio(const CDCNP_HEADER *cdcnp_header);

REAL cdcnp_header_deg_ratio(const CDCNP_HEADER *cdcnp_header);

CDCNP *cdcnp_new();

EC_BOOL cdcnp_init(CDCNP *cdcnp);

EC_BOOL cdcnp_clean(CDCNP *cdcnp);

EC_BOOL cdcnp_free(CDCNP *cdcnp);

EC_BOOL cdcnp_is_full(const CDCNP *cdcnp);

EC_BOOL cdcnp_lru_list_is_empty(const CDCNP *cdcnp);

EC_BOOL cdcnp_del_list_is_empty(const CDCNP *cdcnp);

EC_BOOL cdcnp_deg_list_is_empty(const CDCNP *cdcnp);

EC_BOOL cdcnp_reserve_key(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_release_key(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

void cdcnp_header_print(LOG *log, const CDCNP *cdcnp);

void cdcnp_print(LOG *log, const CDCNP *cdcnp);

void cdcnp_print_lru_list(LOG *log, const CDCNP *cdcnp);

void cdcnp_print_del_list(LOG *log, const CDCNP *cdcnp);

void cdcnp_print_deg_list(LOG *log, const CDCNP *cdcnp);

void cdcnp_print_bitmap(LOG *log, const CDCNP *cdcnp);

CDCNP_ITEM *cdcnp_dnode_find(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, const CDCNP_KEY *cdcnp_key);

uint32_t cdcnp_dnode_search(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, const CDCNP_KEY *cdcnp_key);

void cdcnp_dnode_walk(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, void (*walker)(void *, const void *, const uint32_t), void *arg);

uint32_t cdcnp_dnode_insert(CDCNP *cdcnp, const uint32_t parent_pos, const CDCNP_KEY *cdcnp_key, const uint32_t dir_flag);

/**
* umount one son from cdcnp_dnode,  where son is regular file item or dir item without any son
* cdcnp_dnode will be impacted on bucket and file num
**/
uint32_t cdcnp_dnode_umount_son(const CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, const uint32_t son_node_pos, const CDCNP_KEY *cdcnp_key);
EC_BOOL cdcnp_dnode_delete_dir_son(const CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode);

uint32_t cdcnp_search(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag);

void cdcnp_walk(CDCNP *cdcnp, void (*walker)(void *, const void *, const uint32_t), void *arg);

uint32_t cdcnp_insert(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag);

CDCNP_ITEM *cdcnp_fetch(const CDCNP *cdcnp, const uint32_t node_pos);

EC_BOOL cdcnp_inode_update(CDCNP *cdcnp, CDCNP_INODE *cdcnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cdcnp_fnode_update(CDCNP *cdcnp, CDCNP_FNODE *cdcnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cdcnp_bucket_update(CDCNP *cdcnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cdcnp_dnode_update(CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

EC_BOOL cdcnp_item_update(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

REAL cdcnp_used_ratio(const CDCNP *cdcnp);

REAL cdcnp_deg_ratio(const CDCNP *cdcnp);

uint32_t cdcnp_deg_num(const CDCNP *cdcnp);

CDCNP_ITEM *cdcnp_set(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag, uint32_t *cdcnp_item_pos);

CDCNP_ITEM *cdcnp_get(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag, uint32_t *cdcnp_item_pos);

CDCNP_ITEM *cdcnp_reserve(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, uint32_t *cdcnp_item_pos);

EC_BOOL cdcnp_release(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_has_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_set_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_clear_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_set_sata_dirty(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_set_sata_flushed(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_set_sata_not_flushed(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_lock(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

EC_BOOL cdcnp_unlock(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key);

CDCNP_ITEM *cdcnp_locate(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, uint32_t *cdcnp_item_pos);

CDCNP_ITEM *cdcnp_map(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, uint32_t *cdcnp_item_pos);

EC_BOOL cdcnp_read(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, CDCNP_FNODE *cdcnp_fnode);

EC_BOOL cdcnp_delete(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag);

EC_BOOL cdcnp_update(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const CDCNP_FNODE *cdcnp_fnode);

EC_BOOL cdcnp_degrade_cb_init(CDCNP_DEGRADE_CB *cdcnp_degrade_cb);

EC_BOOL cdcnp_degrade_cb_clean(CDCNP_DEGRADE_CB *cdcnp_degrade_cb);

EC_BOOL cdcnp_degrade_cb_clone(CDCNP_DEGRADE_CB *cdcnp_degrade_cb_src, CDCNP_DEGRADE_CB *cdcnp_degrade_cb_des);

EC_BOOL cdcnp_degrade_cb_set(CDCNP_DEGRADE_CB *cdcnp_degrade_cb, CDCNP_DEGRADE_CALLBACK func, void *arg);

EC_BOOL cdcnp_init_degrade_callback(CDCNP *cdcnp);

EC_BOOL cdcnp_clean_degrade_callback(CDCNP *cdcnp);

EC_BOOL cdcnp_set_degrade_callback(CDCNP *cdcnp, CDCNP_DEGRADE_CALLBACK func, void *arg);

EC_BOOL cdcnp_exec_degrade_callback(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t node_pos);

EC_BOOL cdcnp_degrade(CDCNP *cdcnp, const UINT32 scan_max_num, const UINT32 expect_degrade_num, UINT32 *complete_degrade_num);

EC_BOOL cdcnp_retire(CDCNP *cdcnp, const UINT32 scan_max_num, const UINT32 expect_retire_num, UINT32 *ret_retire_num);

EC_BOOL cdcnp_umount_item(CDCNP *cdcnp, const uint32_t node_pos);

EC_BOOL cdcnp_umount(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag);

EC_BOOL cdcnp_recycle_item_file(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn);

EC_BOOL cdcnp_recycle_dnode_item(CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn);

EC_BOOL cdcnp_recycle_dnode(CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, const uint32_t node_pos,CDCNP_RECYCLE_NP *cdcnp_recycle_np,  CDCNP_RECYCLE_DN *cdcnp_recycle_dn);

EC_BOOL cdcnp_recycle_item_dir(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn);

/*note: this interface is for that cdcnp_item had umounted from parent, not need to update parent info*/
EC_BOOL cdcnp_recycle_item(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn);

EC_BOOL cdcnp_recycle(CDCNP *cdcnp, const UINT32 max_num, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn, UINT32 *complete_num);

EC_BOOL cdcnp_header_load(CDCNP_HEADER *cdcnp_header, const uint32_t np_id, int fd, UINT32 *offset, const UINT32 fsize);

EC_BOOL cdcnp_header_flush(CDCNP_HEADER *cdcnp_header, const uint32_t np_id, int fd, UINT32 *offset, const UINT32 fsize);

EC_BOOL cdcnp_file_num(CDCNP *cdcnp, uint32_t *file_num);

EC_BOOL cdcnp_file_size(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, UINT32 *file_size);

void cdcnp_file_print(LOG *log, const CDCNP *cdcnp, const uint32_t node_pos);

EC_BOOL cdcnp_create_root_item(CDCNP *cdcnp);

CDCNP *cdcnp_create(const uint32_t np_id, const uint8_t np_model, const uint32_t key_max_num, UINT32 *s_offset, const UINT32 e_offset);

EC_BOOL cdcnp_erase(CDCNP *cdcnp, const uint32_t np_id, int fd, const UINT32 s_offset, const UINT32 e_offset);

EC_BOOL cdcnp_flush(CDCNP *cdcnp);

EC_BOOL cdcnp_load(CDCNP *cdcnp, const uint32_t np_id, int fd, UINT32 *s_offset, const UINT32 e_offset);


#endif/* _CDCNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/


