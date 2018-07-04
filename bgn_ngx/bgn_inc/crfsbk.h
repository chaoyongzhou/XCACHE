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

#ifndef _CRFSBK_H
#define _CRFSBK_H

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

#include "clist.h"
#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"
#include "crb.h"
#include "chashalgo.h"
#include "crfsnprb.h"
#include "crfsnp.inc"
#include "crfsbk.inc"

CRFSOP *crfsop_new();

EC_BOOL crfsop_init(CRFSOP *crfsop);

EC_BOOL crfsop_clean(CRFSOP *crfsop);

EC_BOOL crfsop_free(CRFSOP *crfsop);

EC_BOOL crfsop_set(CRFSOP *crfsop, const uint16_t op_type, const uint16_t path_type, const CSTRING *path);

int crfsop_cmp(const CRFSOP *crfsop_1st, const CRFSOP *crfsop_2nd);

void crfsop_print(LOG *log, const CRFSOP *crfsop);

EC_BOOL crfsoprec_init(CRFSOPREC *crfsoprec, const char *fname);

EC_BOOL crfsoprec_clean(CRFSOPREC *crfsoprec);

EC_BOOL crfsoprec_push(CRFSOPREC *crfsoprec, const uint16_t op_type, const uint16_t path_type, const CSTRING *path);
CRFSOP *crfsoprec_pop(CRFSOPREC *crfsoprec);

CLIST_DATA *crfsoprec_fetch(CRFSOPREC *crfsoprec, CRFSOP *crfsop);

CLIST_DATA *crfsoprec_get(CRFSOPREC *crfsoprec, const uint16_t op_type, const uint16_t path_type, const CSTRING *path);

EC_BOOL crfsoprec_rmv(CRFSOPREC *crfsoprec, const CRFSOP *crfsop);

EC_BOOL crfsoprec_del(CRFSOPREC *crfsoprec, const uint16_t op_type, const uint16_t path_type, const CSTRING *path);

void crfsoprec_print(LOG *log, const CRFSOPREC *crfsoprec);

EC_BOOL crfsoprec_export(const CRFSOPREC *crfsoprec);

EC_BOOL crfsoprec_import(CRFSOPREC *crfsoprec);

CRFSBK *crfsbk_open(const UINT32 crfs_md_id, const char *np_root_dir, const char *dn_root_dir, const uint32_t np_id, const char *crfs_op_fname);

CRFSBK *crfsbk_new(const UINT32 crfs_md_id, const char *np_root_dir, const char *dn_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const char *crfs_op_fname);

EC_BOOL crfsbk_init(CRFSBK *crfsbk, const UINT32 crfs_md_id, const char *np_root_dir, const char *dn_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const char *crfs_op_fname);

EC_BOOL crfsbk_clean(CRFSBK *crfsbk);

EC_BOOL crfsbk_free(CRFSBK *crfsbk);

EC_BOOL crfsbk_add_disk(CRFSBK *crfsbk, const uint16_t disk_no);

CRFSNP_FNODE *crfsbk_reserve_np_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, uint32_t *node_pos);

EC_BOOL crfsbk_release_np_no_lock(CRFSBK *crfsbk, const CSTRING *file_path);

EC_BOOL crfsbk_reserve_dn_no_lock(CRFSBK *crfsbk, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL crfsbk_release_dn_no_lock(CRFSBK *crfsbk, const uint32_t size, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no);

EC_BOOL crfsbk_write_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum);

EC_BOOL crfsbk_read_np_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsbk_read_dn_no_lock(CRFSBK *crfsbk, const CRFSNP_FNODE *crfsnp_fnode, CBYTES *cbytes);

EC_BOOL crfsbk_read_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL crfsbk_retire_no_lock(CRFSBK *crfsbk);

EC_BOOL crfsbk_recycle_no_lock(CRFSBK *crfsbk, const UINT32 max_num, UINT32 *complete_num);

EC_BOOL crfsbk_room_is_ok_no_lock(CRFSBK *crfsbk, const REAL level);

EC_BOOL crfsbk_write(CRFSBK *crfsbk, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum);

EC_BOOL crfsbk_read(CRFSBK *crfsbk, const CSTRING *file_path, CBYTES *cbytes);

/*remove: not record operation*/
EC_BOOL crfsbk_remove_file(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_remove_dir(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_remove(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag);

EC_BOOL crfsbk_remove_file_wildcard(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_remove_dir_wildcard(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_remove_wildcard(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag);

/*delete: record operation*/
EC_BOOL crfsbk_delete_file(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_delete_dir(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_delete(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag);

EC_BOOL crfsbk_delete_file_wildcard(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_delete_dir_wildcard(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_delete_wildcard(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag);

EC_BOOL crfsbk_retire(CRFSBK *crfsbk);

EC_BOOL crfsbk_recycle(CRFSBK *crfsbk, const UINT32 max_num, UINT32 *complete_num);

EC_BOOL crfsbk_ensure_room_safe_level(CRFSBK *crfsbk);

void crfsbk_print(LOG *log, const CRFSBK *crfsbk);

EC_BOOL crfsbk_replay_file(CRFSBK *crfsbk, const CSTRING *path);

EC_BOOL crfsbk_replay_rm_dir_op(CRFSBK *crfsbk, CRFSOP *crfsop);

EC_BOOL crfsbk_replay_wr_reg_op(CRFSBK *crfsbk, CRFSOP *crfsop);

EC_BOOL crfsbk_replay_one(CRFSBK *crfsbk, CRFSOP *crfsop);

EC_BOOL crfsbk_replay(CRFSBK *crfsbk);

EC_BOOL crfsbk_qfile(CRFSBK *crfsbk, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item);

EC_BOOL crfsbk_qdir(CRFSBK *crfsbk, const CSTRING *dir_path, CRFSNP_ITEM  *crfsnp_item);

#endif/* _CRFSBK_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

