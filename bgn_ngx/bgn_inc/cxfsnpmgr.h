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

#ifndef _CXFSNPMGR_H
#define _CXFSNPMGR_H

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
#include "real.h"

#include "chashalgo.h"

#include "camd.h"
#include "cmmap.h"

#include "cxfscfg.h"
#include "cxfsnp.h"
#include "cxfsnprb.h"
#include "cxfsop.h"

#define CXFSNP_MGR_MEM_ALIGNMENT                    (1 << 20)

#define CXFSNP_MGR_MSYNC_SIZE                       (256 << 10) /*256K*/

typedef struct
{
    int              fd;
    int              rsvd1;

    uint8_t          cxfsnp_model;                  /*cxfsnp model, e.g, CXFSNP_001G_MODEL*/
    uint8_t          cxfsnp_2nd_chash_algo_id;
    uint16_t         rsvd2;
    uint32_t         cxfsnp_item_max_num;
    uint32_t         cxfsnp_max_num;                /*max np num*/
    uint32_t         read_only_flag:1;
    uint32_t         op_replay_flag:1;
    uint32_t         rsvd3         :30;

    UINT32           cxfsnp_size;                   /*single np size*/
    UINT32           cxfsnp_s_offset;               /*np start offset*/
    UINT32           cxfsnp_e_offset;               /*np end offset*/

    UINT8           *np_cache;                      /*mem cache mounted point*/
    CVECTOR          cxfsnp_vec;                    /*item is CXFSNP*/

    CXFSOP_MGR      *np_op_mgr;
}CXFSNP_MGR;

#define CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr)                  ((cxfsnp_mgr)->read_only_flag)
#define CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr)                  ((cxfsnp_mgr)->op_replay_flag)
#define CXFSNP_MGR_FD(cxfsnp_mgr)                              ((cxfsnp_mgr)->fd)
#define CXFSNP_MGR_NP_MODEL(cxfsnp_mgr)                        ((cxfsnp_mgr)->cxfsnp_model)
#define CXFSNP_MGR_NP_2ND_CHASH_ALGO_ID(cxfsnp_mgr)            ((cxfsnp_mgr)->cxfsnp_2nd_chash_algo_id)
#define CXFSNP_MGR_NP_ITEM_MAX_NUM(cxfsnp_mgr)                 ((cxfsnp_mgr)->cxfsnp_item_max_num)
#define CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr)                      ((cxfsnp_mgr)->cxfsnp_max_num)
#define CXFSNP_MGR_NP_SIZE(cxfsnp_mgr)                         ((cxfsnp_mgr)->cxfsnp_size)
#define CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr)                     ((cxfsnp_mgr)->cxfsnp_s_offset)
#define CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr)                     ((cxfsnp_mgr)->cxfsnp_e_offset)
#define CXFSNP_MGR_NP_CACHE(cxfsnp_mgr)                        ((cxfsnp_mgr)->np_cache)
#define CXFSNP_MGR_NP_VEC(cxfsnp_mgr)                          (&((cxfsnp_mgr)->cxfsnp_vec))
#define CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id)                   ((CXFSNP *)cvector_get(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), cxfsnp_id))
#define CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr)                       ((cxfsnp_mgr)->np_op_mgr)

/*to reduce lock operation in name node*/
#define CXFSNP_MGR_NP_GET_NO_LOCK(cxfsnp_mgr, cxfsnp_id) \
        ((CXFSNP *)cvector_get_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), (cxfsnp_id)))

#define CXFSNP_MGR_NP_SET_NO_LOCK(cxfsnp_mgr, cxfsnp_id, __cxfsnp, location) \
        (cvector_set_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), (cxfsnp_id), (__cxfsnp)))

CXFSNP_MGR *cxfsnp_mgr_new();

EC_BOOL cxfsnp_mgr_init(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_clean(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_free(CXFSNP_MGR *cxfsnp_mgr);

CXFSNP *cxfsnp_mgr_open_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id);

EC_BOOL cxfsnp_mgr_close_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id);

EC_BOOL cxfsnp_mgr_open_np_all(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_close_np_all(CXFSNP_MGR *cxfsnp_mgr);

uint32_t cxfsnp_mgr_item_max_num(const CXFSNP_MGR *cxfsnp_mgr);

uint32_t cxfsnp_mgr_item_used_num(const CXFSNP_MGR *cxfsnp_mgr);

void cxfsnp_mgr_print_db(LOG *log, const CXFSNP_MGR *cxfsnp_mgr);

void cxfsnp_mgr_print_que_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr);

void cxfsnp_mgr_print_del_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr);

void cxfsnp_mgr_print(LOG *log, const CXFSNP_MGR *cxfsnp_mgr);

uint64_t cxfsnp_mgr_count_meta_size(const CXFSNP_MGR *cxfsnp_mgr);

uint64_t cxfsnp_mgr_count_delete_size(const CXFSNP_MGR *cxfsnp_mgr);

uint64_t cxfsnp_mgr_count_recycle_size(const CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_flush(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_load(CXFSNP_MGR *cxfsnp_mgr, const int cxfsnp_dev_fd, const CXFSCFG *cxfscfg);

EC_BOOL cxfsnp_mgr_show_np_que_list(LOG *log, CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id);

EC_BOOL cxfsnp_mgr_show_np_del_list(LOG *log, CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id);

EC_BOOL cxfsnp_mgr_show_np(LOG *log, CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id);

EC_BOOL cxfsnp_mgr_search(CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_cxfsnp_id);

CXFSNP_ITEM *cxfsnp_mgr_search_item(CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag);

CXFSNP_MGR *cxfsnp_mgr_create(const uint8_t cxfsnp_model,
                                  const uint32_t cxfsnp_max_num,
                                  const uint8_t  cxfsnp_2nd_chash_algo_id,
                                  const int      cxfsnp_dev_fd,
                                  const UINT32   cxfsnp_dev_size,
                                  const UINT32   cxfsnp_dev_offset);

CXFSNP_MGR * cxfsnp_mgr_open(const int cxfsnp_dev_fd, const CXFSCFG *cxfscfg);

EC_BOOL cxfsnp_mgr_close(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_dump(CXFSNP_MGR *cxfsnp_mgr, const UINT32 cxfsnp_zone_s_offset);

CMMAP_NODE *cxfsnp_mgr_create_cmmap_node(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_sync(CXFSNP_MGR *cxfsnp_mgr, CAMD_MD *camd_md, CXFSCFG *cxfscfg);

EC_BOOL cxfsnp_mgr_set_read_only(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_unset_read_only(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_is_read_only(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_set_op_replay(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_unset_op_replay(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_is_op_replay(CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_mount_op_mgr(CXFSNP_MGR *cxfsnp_mgr, CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsnp_mgr_umount_op_mgr(CXFSNP_MGR *cxfsnp_mgr);

REAL cxfsnp_mgr_used_ratio(const CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_find_dir(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *dir_path);

EC_BOOL cxfsnp_mgr_find_file(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path);

CXFSNP_FNODE *cxfsnp_mgr_reserve(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path);

EC_BOOL cxfsnp_mgr_release(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path);

EC_BOOL cxfsnp_mgr_retire_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id, const UINT32 expect_num, UINT32 *complete_num);

EC_BOOL cxfsnp_mgr_write(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfsnp_mgr_read(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path, CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfsnp_mgr_update(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfsnp_mgr_umount(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag);

EC_BOOL cxfsnp_mgr_umount_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag);

EC_BOOL cxfsnp_mgr_umount_wildcard(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag);

EC_BOOL cxfsnp_mgr_umount_wildcard_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag);

EC_BOOL cxfsnp_mgr_mkdir(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path);

EC_BOOL cxfsnp_mgr_list_path_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, const uint32_t cxfsnp_id, CVECTOR  *path_cstr_vec);

EC_BOOL cxfsnp_mgr_list_seg_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, const uint32_t cxfsnp_id, CVECTOR  *seg_cstr_vec);

EC_BOOL cxfsnp_mgr_file_num_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t cxfsnp_id, UINT32 *file_num);

EC_BOOL cxfsnp_mgr_file_size_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t cxfsnp_id, uint64_t *file_size);

EC_BOOL cxfsnp_mgr_list_path(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, CVECTOR  *path_cstr_vec);

EC_BOOL cxfsnp_mgr_list_seg(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, CVECTOR  *seg_cstr_vec);

EC_BOOL cxfsnp_mgr_file_num(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_num);

EC_BOOL cxfsnp_mgr_file_size(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, uint64_t *file_size);

EC_BOOL cxfsnp_mgr_file_expire(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr);

EC_BOOL cxfsnp_mgr_dir_expire(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr);

EC_BOOL cxfsnp_mgr_expire(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag);

EC_BOOL cxfsnp_mgr_file_walk(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_mgr_dir_walk(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_mgr_walk(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag, CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_mgr_walk_of_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id, const CSTRING *path_cstr, const uint32_t dflag, CXFSNP_DIT_NODE *cxfsnp_dit_node);

EC_BOOL cxfsnp_mgr_show_cached_np(LOG *log, const CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_show_cached_np_que_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_show_cached_np_del_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr);

EC_BOOL cxfsnp_mgr_recycle_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id, const UINT32 max_num, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn, UINT32 *complete_num);

#endif/* _CXFSNPMGR_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

