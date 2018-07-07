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

#ifndef _CRFSNPMGR_H
#define _CRFSNPMGR_H

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
#include "cvector.h"
#include "clist.h"
#include "cmutex.h"
#include "cstring.h"

#include "chashalgo.h"
#include "crfsnp.h"
#include "crfsnprb.h"
#include "crfsdt.inc"

#define CRFSNP_DB_NAME      ((const char *)"np_cfg.dat")

typedef struct
{
    CSTRING          crfsnp_db_root_dir;           /*crfsnp database root dir*/
    CRWLOCK          crwlock;                      /*xxx unused yet xxx*/
    CMUTEX           cmutex;                       /*lock for whole crfsnp_mgr*/

    uint8_t          crfsnp_model;                  /*crfsnp model, e.g, CRFSNP_001G_MODEL*/
    uint8_t          crfsnp_2nd_chash_algo_id;
    uint16_t         rsvd1;
    uint32_t         crfsnp_item_max_num;
    uint32_t         crfsnp_max_num;                /*max np num*/
    uint32_t         rsvd2;
    CVECTOR          crfsnp_vec;                    /*item is CRFSNP*/
}CRFSNP_MGR;

#define CRFSNP_MGR_DB_ROOT_DIR(crfsnp_mgr)                    (&((crfsnp_mgr)->crfsnp_db_root_dir))
#define CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr)                (cstring_get_str(CRFSNP_MGR_DB_ROOT_DIR(crfsnp_mgr)))

#define CRFSNP_MGR_NP_MODEL(crfsnp_mgr)                        ((crfsnp_mgr)->crfsnp_model)
#define CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID(crfsnp_mgr)            ((crfsnp_mgr)->crfsnp_2nd_chash_algo_id)
#define CRFSNP_MGR_NP_ITEM_MAX_NUM(crfsnp_mgr)                 ((crfsnp_mgr)->crfsnp_item_max_num)
#define CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr)                      ((crfsnp_mgr)->crfsnp_max_num)
#define CRFSNP_MGR_NP_VEC(crfsnp_mgr)                          (&((crfsnp_mgr)->crfsnp_vec))
#define CRFSNP_MGR_NP(crfsnp_mgr, crfsnp_id)                   ((CRFSNP *)cvector_get(CRFSNP_MGR_NP_VEC(crfsnp_mgr), crfsnp_id))

/*to reduce lock operation in name node*/
#define CRFSNP_MGR_NP_GET_NO_LOCK(crfsnp_mgr, crfsnp_id) \
        ((CRFSNP *)cvector_get_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (crfsnp_id)))

#define CRFSNP_MGR_NP_SET_NO_LOCK(crfsnp_mgr, crfsnp_id, __crfsnp, location) \
        (cvector_set_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (crfsnp_id), (__crfsnp)))

#define CRFSNP_MGR_CRWLOCK(crfsnp_mgr)                          (&((crfsnp_mgr)->crwlock))
#define CRFSNP_MGR_CRWLOCK_INIT(crfsnp_mgr, location)           (crwlock_init(CRFSNP_MGR_CRWLOCK(crfsnp_mgr), CMUTEX_PROCESS_PRIVATE, location))
#define CRFSNP_MGR_CRWLOCK_CLEAN(crfsnp_mgr, location)          (crwlock_clean(CRFSNP_MGR_CRWLOCK(crfsnp_mgr), location))
#if 0
#define CRFSNP_MGR_CRWLOCK_RDLOCK(crfsnp_mgr, location)         (crwlock_rdlock(CRFSNP_MGR_CRWLOCK(crfsnp_mgr), location))
#define CRFSNP_MGR_CRWLOCK_WRLOCK(crfsnp_mgr, location)         (crwlock_wrlock(CRFSNP_MGR_CRWLOCK(crfsnp_mgr), location))
#define CRFSNP_MGR_CRWLOCK_UNLOCK(crfsnp_mgr, location)         (crwlock_unlock(CRFSNP_MGR_CRWLOCK(crfsnp_mgr), location))
#endif
#if 1
#define CRFSNP_MGR_CRWLOCK_RDLOCK(crfsnp_mgr, location)         (EC_TRUE)
#define CRFSNP_MGR_CRWLOCK_WRLOCK(crfsnp_mgr, location)         (EC_TRUE)
#define CRFSNP_MGR_CRWLOCK_UNLOCK(crfsnp_mgr, location)         (EC_TRUE)
#endif

#define CRFSNP_MGR_CMUTEX(crfsnp_mgr)                          (&((crfsnp_mgr)->cmutex))
#define CRFSNP_MGR_CMUTEX_INIT(crfsnp_mgr, location)           (cmutex_init(CRFSNP_MGR_CMUTEX(crfsnp_mgr), CMUTEX_PROCESS_PRIVATE, location))
#define CRFSNP_MGR_CMUTEX_CLEAN(crfsnp_mgr, location)          (cmutex_clean(CRFSNP_MGR_CMUTEX(crfsnp_mgr), location))

#if 1
#define CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, location)           (cmutex_lock(CRFSNP_MGR_CMUTEX(crfsnp_mgr), location))
#define CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, location)         (cmutex_unlock(CRFSNP_MGR_CMUTEX(crfsnp_mgr), location))
#endif


CRFSNP_MGR *crfsnp_mgr_new();

EC_BOOL crfsnp_mgr_init(CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_clean(CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_free(CRFSNP_MGR *crfsnp_mgr);

CRFSNP *crfsnp_mgr_open_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id);

EC_BOOL crfsnp_mgr_close_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id);

EC_BOOL crfsnp_mgr_open_np_all(CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_close_np_all(CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_load_db(CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_create_db(CRFSNP_MGR *crfsnp_mgr, const CSTRING *crfsnp_db_root_dir);

EC_BOOL crfsnp_mgr_flush_db(CRFSNP_MGR *crfsnp_mgr);

void crfsnp_mgr_print_db(LOG *log, const CRFSNP_MGR *crfsnp_mgr);

void crfsnp_mgr_print_lru_list(LOG *log, const CRFSNP_MGR *crfsnp_mgr);

void crfsnp_mgr_print_del_list(LOG *log, const CRFSNP_MGR *crfsnp_mgr);

void crfsnp_mgr_print(LOG *log, const CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_load(CRFSNP_MGR *crfsnp_mgr, const CSTRING *crfsnp_db_root_dir);

EC_BOOL crfsnp_mgr_flush(CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_show_np_lru_list(LOG *log, CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id);

EC_BOOL crfsnp_mgr_show_np_del_list(LOG *log, CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id);

EC_BOOL crfsnp_mgr_show_np(LOG *log, CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id);

EC_BOOL crfsnp_mgr_search(CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_crfsnp_id);

CRFSNP_ITEM *crfsnp_mgr_search_item(CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

CRFSNP_MGR *crfsnp_mgr_create(const uint8_t crfsnp_model,
                                const uint32_t crfsnp_disk_max_num,
                                const uint8_t  crfsnp_2nd_chash_algo_id,
                                const CSTRING *crfsnp_db_root_dir);

EC_BOOL crfsnp_mgr_exist(const CSTRING *crfsnp_db_root_dir);

CRFSNP_MGR * crfsnp_mgr_open(const CSTRING *crfsnp_db_root_dir);

EC_BOOL crfsnp_mgr_close(CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_collect_items(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *crfsnp_item_vec);

EC_BOOL crfsnp_mgr_find_dir(CRFSNP_MGR *crfsnp_mgr, const CSTRING *dir_path);

EC_BOOL crfsnp_mgr_find_file(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path);

EC_BOOL crfsnp_mgr_find(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag);

CRFSNP_FNODE *crfsnp_mgr_reserve(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path);

EC_BOOL crfsnp_mgr_release(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path);

EC_BOOL crfsnp_mgr_retire_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const UINT32 expect_num, UINT32 *complete_num);

EC_BOOL crfsnp_mgr_write(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsnp_mgr_read(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsnp_mgr_update(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsnp_mgr_umount(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag);

EC_BOOL crfsnp_mgr_umount_wildcard(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag);

EC_BOOL crfsnp_mgr_move(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_src, const CSTRING *path_des, const UINT32 dflag);

EC_BOOL crfsnp_mgr_mkdir(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path);

EC_BOOL crfsnp_mgr_list_path_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const uint32_t crfsnp_id, CVECTOR  *path_cstr_vec);

EC_BOOL crfsnp_mgr_list_seg_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const uint32_t crfsnp_id, CVECTOR  *seg_cstr_vec);

EC_BOOL crfsnp_mgr_file_num_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t crfsnp_id, UINT32 *file_num);

EC_BOOL crfsnp_mgr_file_size_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t crfsnp_id, uint64_t *file_size);

EC_BOOL crfsnp_mgr_list_path(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, CVECTOR  *path_cstr_vec);

EC_BOOL crfsnp_mgr_list_seg(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, CVECTOR  *seg_cstr_vec);

EC_BOOL crfsnp_mgr_file_num(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_num);

EC_BOOL crfsnp_mgr_file_size(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, uint64_t *file_size);

EC_BOOL crfsnp_mgr_file_expire(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr);

EC_BOOL crfsnp_mgr_dir_expire(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr);

EC_BOOL crfsnp_mgr_expire(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag);

EC_BOOL crfsnp_mgr_file_walk(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_mgr_dir_walk(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_mgr_walk(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag, CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_mgr_walk_of_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const CSTRING *path_cstr, const uint32_t dflag, CRFSNP_DIT_NODE *crfsnp_dit_node);

EC_BOOL crfsnp_mgr_file_md5sum(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, CMD5_DIGEST *md5sum);

EC_BOOL crfsnp_mgr_show_cached_np(LOG *log, const CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_show_cached_np_lru_list(LOG *log, const CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_show_cached_np_del_list(LOG *log, const CRFSNP_MGR *crfsnp_mgr);

EC_BOOL crfsnp_mgr_show_path_depth(LOG *log, CRFSNP_MGR *crfsnp_mgr, const CSTRING *path);

EC_BOOL crfsnp_mgr_show_path(LOG *log, CRFSNP_MGR *crfsnp_mgr, const CSTRING *path);

EC_BOOL crfsnp_mgr_get_first_fname_of_path(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const CSTRING *path, CSTRING *fname, uint32_t *dflag);

EC_BOOL crfsnp_mgr_recycle_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const UINT32 max_num, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn, UINT32 *complete_num);

EC_BOOL crfsnp_mgr_rdlock(CRFSNP_MGR *crfsnp_mgr, const UINT32 location);

EC_BOOL crfsnp_mgr_wrlock(CRFSNP_MGR *crfsnp_mgr, const UINT32 location);

EC_BOOL crfsnp_mgr_unlock(CRFSNP_MGR *crfsnp_mgr, const UINT32 location);

#endif/* _CRFSNPMGR_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

