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

#ifndef _CSFSNPMGR_H
#define _CSFSNPMGR_H

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
#include "cmutex.h"
#include "cstring.h"

#include "chashalgo.h"
#include "csfsnp.h"
#include "csfsnprb.h"

#define CSFSNP_DB_NAME      ((const char *)"sfsnp_cfg.db")

typedef struct
{
    CSTRING          csfsnp_db_root_dir;           /*csfsnp database root dir*/
    CRWLOCK          crwlock;
    CMUTEX           cmutex;

    uint8_t          csfsnp_model;                  /*csfsnp model, e.g, CSFSNP_001G_MODEL*/
    uint8_t          csfsnp_1st_chash_algo_id;
    uint8_t          csfsnp_2nd_chash_algo_id;
    uint8_t          rsvd1;
    uint32_t         csfsnp_item_max_num;
    uint32_t         csfsnp_max_num;                /*max np num*/
    uint32_t         rsvd2;
    CVECTOR          csfsnp_vec;                    /*item is CSFSNP*/
}CSFSNP_MGR;

#define CSFSNP_MGR_DB_ROOT_DIR(csfsnp_mgr)              (&((csfsnp_mgr)->csfsnp_db_root_dir))
#define CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr)          (cstring_get_str(CSFSNP_MGR_DB_ROOT_DIR(csfsnp_mgr)))

#define CSFSNP_MGR_NP_MODEL(csfsnp_mgr)                 ((csfsnp_mgr)->csfsnp_model)
#define CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID(csfsnp_mgr)     ((csfsnp_mgr)->csfsnp_1st_chash_algo_id)
#define CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID(csfsnp_mgr)     ((csfsnp_mgr)->csfsnp_2nd_chash_algo_id)
#define CSFSNP_MGR_NP_ITEM_MAX_NUM(csfsnp_mgr)          ((csfsnp_mgr)->csfsnp_item_max_num)
#define CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr)               ((csfsnp_mgr)->csfsnp_max_num)
#define CSFSNP_MGR_NP_VEC(csfsnp_mgr)                   (&((csfsnp_mgr)->csfsnp_vec))
#define CSFSNP_MGR_NP(csfsnp_mgr, csfsnp_id)            ((CSFSNP *)cvector_get(CSFSNP_MGR_NP_VEC(csfsnp_mgr), csfsnp_id))

#define CSFSNP_MGR_CRWLOCK(csfsnp_mgr)                          (&((csfsnp_mgr)->crwlock))
#define CSFSNP_MGR_CRWLOCK_INIT(csfsnp_mgr, location)           (crwlock_init(CSFSNP_MGR_CRWLOCK(csfsnp_mgr), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSNP_MGR_CRWLOCK_CLEAN(csfsnp_mgr, location)          (crwlock_clean(CSFSNP_MGR_CRWLOCK(csfsnp_mgr), location))
#define CSFSNP_MGR_CRWLOCK_RDLOCK(csfsnp_mgr, location)         EC_TRUE
#define CSFSNP_MGR_CRWLOCK_WRLOCK(csfsnp_mgr, location)         EC_TRUE
#define CSFSNP_MGR_CRWLOCK_UNLOCK(csfsnp_mgr, location)         EC_TRUE

#define CSFSNP_MGR_CMUTEX(csfsnp_mgr)                          (&((csfsnp_mgr)->cmutex))
#define CSFSNP_MGR_CMUTEX_INIT(csfsnp_mgr, location)           (cmutex_init(CSFSNP_MGR_CMUTEX(csfsnp_mgr), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSNP_MGR_CMUTEX_CLEAN(csfsnp_mgr, location)          (cmutex_clean(CSFSNP_MGR_CMUTEX(csfsnp_mgr), location))
#if 0
#define CSFSNP_MGR_CMUTEX_LOCK(csfsnp_mgr, location)           (cmutex_lock(CSFSNP_MGR_CMUTEX(csfsnp_mgr), location))
#define CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, location)         (cmutex_unlock(CSFSNP_MGR_CMUTEX(csfsnp_mgr), location))
#endif
#if 1
#define CSFSNP_MGR_CMUTEX_LOCK(csfsnp_mgr, location)           do{}while(0)
#define CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, location)         do{}while(0)
#endif

CSFSNP_MGR *csfsnp_mgr_new();

EC_BOOL csfsnp_mgr_init(CSFSNP_MGR *csfsnp_mgr);

EC_BOOL csfsnp_mgr_clean(CSFSNP_MGR *csfsnp_mgr);

EC_BOOL csfsnp_mgr_free(CSFSNP_MGR *csfsnp_mgr);

CSFSNP *csfsnp_mgr_open_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id);

EC_BOOL csfsnp_mgr_close_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id);

EC_BOOL csfsnp_mgr_load_db(CSFSNP_MGR *csfsnp_mgr);

EC_BOOL csfsnp_mgr_create_db(CSFSNP_MGR *csfsnp_mgr, const CSTRING *csfsnp_db_root_dir);

EC_BOOL csfsnp_mgr_flush_db(CSFSNP_MGR *csfsnp_mgr);

void csfsnp_mgr_print_db(LOG *log, const CSFSNP_MGR *csfsnp_mgr);

void csfsnp_mgr_print(LOG *log, const CSFSNP_MGR *csfsnp_mgr);

EC_BOOL csfsnp_mgr_load(CSFSNP_MGR *csfsnp_mgr, const CSTRING *csfsnp_db_root_dir);

EC_BOOL csfsnp_mgr_flush(CSFSNP_MGR *csfsnp_mgr);

EC_BOOL csfsnp_mgr_show_np(LOG *log, CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id);

EC_BOOL csfsnp_mgr_search(CSFSNP_MGR *csfsnp_mgr, const uint32_t path_len, const uint8_t *path, uint32_t *searched_csfsnp_id);

CSFSNP_ITEM *csfsnp_mgr_search_item(CSFSNP_MGR *csfsnp_mgr, const uint32_t path_len, const uint8_t *path);

CSFSNP_MGR *csfsnp_mgr_create(const uint8_t csfsnp_model, 
                                const uint32_t csfsnp_disk_max_num, 
                                const uint8_t  csfsnp_1st_chash_algo_id, 
                                const uint8_t  csfsnp_2nd_chash_algo_id, 
                                const CSTRING *csfsnp_db_root_dir);

EC_BOOL csfsnp_mgr_exist(const CSTRING *csfsnp_db_root_dir);

CSFSNP_MGR * csfsnp_mgr_open(const CSTRING *csfsnp_db_root_dir);

EC_BOOL csfsnp_mgr_close(CSFSNP_MGR *csfsnp_mgr);

EC_BOOL csfsnp_mgr_find(CSFSNP_MGR *csfsnp_mgr, const CSTRING *path);

CSFSNP_FNODE *csfsnp_mgr_reserve(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path, uint32_t *csfsnp_id);

EC_BOOL csfsnp_mgr_release(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path);

EC_BOOL csfsnp_mgr_write(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path, const CSFSNP_FNODE *csfsnp_fnode, uint32_t *csfsnp_id, uint32_t *node_pos);

EC_BOOL csfsnp_mgr_read(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path, CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfsnp_mgr_delete(CSFSNP_MGR *csfsnp_mgr, const CSTRING *path);

EC_BOOL csfsnp_mgr_delete_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t node_pos);

EC_BOOL csfsnp_mgr_file_num(CSFSNP_MGR *csfsnp_mgr, UINT32 *file_num);

EC_BOOL csfsnp_mgr_file_size(CSFSNP_MGR *csfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_size);

EC_BOOL csfsnp_mgr_show_cached_np(LOG *log, const CSFSNP_MGR *csfsnp_mgr);

EC_BOOL csfsnp_mgr_rdlock(CSFSNP_MGR *csfsnp_mgr, const UINT32 location);

EC_BOOL csfsnp_mgr_wrlock(CSFSNP_MGR *csfsnp_mgr, const UINT32 location);

EC_BOOL csfsnp_mgr_unlock(CSFSNP_MGR *csfsnp_mgr, const UINT32 location);

#endif/* _CSFSNPMGR_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

