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

#ifndef _CDFSNPMGR_H
#define _CDFSNPMGR_H

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

#include "cbloom.h"
#include "chashalgo.h"
#include "cdfsnp.h"

/*the memory used to cache bloom*/
#define CDFSNP_MGR_4K_MODE              ((UINT32) 1)
#define CDFSNP_MGR_1M_MODE              ((UINT32) 2)
#define CDFSNP_MGR_2M_MODE              ((UINT32) 3)
#define CDFSNP_MGR_128M_MODE            ((UINT32) 4)
#define CDFSNP_MGR_256M_MODE            ((UINT32) 5)
#define CDFSNP_MGR_512M_MODE            ((UINT32) 6)
#define CDFSNP_MGR_1G_MODE              ((UINT32) 7)
#define CDFSNP_MGR_2G_MODE              ((UINT32) 8)
#define CDFSNP_MGR_4G_MODE              ((UINT32) 9)

/*use 4G to cache NP*/
#define CDFSNP_MGR_4K_MODE_CHACED_NP_MAX_NUM    ((UINT32)(1 << 20))
#define CDFSNP_MGR_1M_MODE_CHACED_NP_MAX_NUM    ((UINT32)(1 << 12))
#define CDFSNP_MGR_2M_MODE_CHACED_NP_MAX_NUM    ((UINT32)(1 << 11))
#define CDFSNP_MGR_128M_MODE_CHACED_NP_MAX_NUM  ((UINT32)(1 <<  5))
#define CDFSNP_MGR_256M_MODE_CHACED_NP_MAX_NUM  ((UINT32)(1 <<  4))
#define CDFSNP_MGR_512M_MODE_CHACED_NP_MAX_NUM  ((UINT32)(1 <<  3))
#define CDFSNP_MGR_1G_MODE_CHACED_NP_MAX_NUM    ((UINT32)(1 <<  2))
#define CDFSNP_MGR_2G_MODE_CHACED_NP_MAX_NUM    ((UINT32)(1 <<  1))
#define CDFSNP_MGR_4G_MODE_CHACED_NP_MAX_NUM    ((UINT32)(1 <<  0))

#define CDFSNP_MGR_DB_ROOT_DIR_MAX_SIZE           (128)   /*root of db of cdfsnp mgr                   */
#define CDFSNP_MGR_CONFIG_DB_NAME_MAX_SIZE        (256)   /*max len of /$(cdfsnp_db_root_dir)/config.db*/
#define CDFSNP_MGR_HEADER_DB_NAME_MAX_SIZE        (256)   /*max len of /$(cdfsnp_db_root_dir)/header.db*/
#define CDFSNP_MGR_CBLOOM_DB_NAME_MAX_SIZE        (256)   /*max len of /$(cdfsnp_db_root_dir)/cbloom.db*/
#define CDFSNP_MGR_LOST_FNODE_LOG_NAME_MAX_SIZE   (256)   /*max len of /$(cdfsnp_db_root_dir)/rank_{tcid}_lost_fnode.log*/
#define CDFSNP_MGR_LOST_REPLICA_LOG_NAME_MAX_SIZE (256)   /*max len of /$(cdfsnp_db_root_dir)/rank_{tcid}_lost_replica.log*/

#define CDFSNP_MGR_WRITE_ONCE_MAX_BYTES    ((UINT32)0x7FFFF000)/*2GB - 4KB*/
#define CDFSNP_MGR_READ_ONCE_MAX_BYTES     ((UINT32)0x7FFFF000)/*2GB - 4KB*/

#define CDFSNP_MGR_32BIT_MASK              ((UINT32)0xFFFFFFFF)

#define CDFSNP_MGR_ERR_PATH                ((UINT32)0xFFFFFFFF)
#define CDFSNP_MGR_ERR_OFFSET              ((UINT32)0xFFFFFFFF)

typedef struct
{
    UINT32        cdfsnp_mode;                  /*cdfsnp mode, e.g, CDFSNP_1G_MODE, CDFSNP_2G_MODE, CDFSNP_4G_MODE*/
    UINT32        cdfsnp_first_chash_algo_id;
    UINT32        cdfsnp_second_chash_algo_id;
    UINT32        cdfsnp_item_max_num;
    UINT32        cdfsnp_cbloom_row_num;
    UINT32        cdfsnp_cbloom_col_num;
    UINT32        cdfsnp_disk_max_num;          /*config max disk num*/
    UINT32        cdfsnp_support_max_num;       /*support max cdfsnp num*/
    UINT32        cdfsnp_used_max_path_layout;  /*free cdfsnp link*/
}CDFSNP_MGR_CFG;

#define CDFSNP_MGR_CFG_NP_MODE(cdfsnp_mgr_cfg)                   ((cdfsnp_mgr_cfg)->cdfsnp_mode)
#define CDFSNP_MGR_CFG_NP_FIRST_CHASH_ALGO_ID(cdfsnp_mgr_cfg)    ((cdfsnp_mgr_cfg)->cdfsnp_first_chash_algo_id)
#define CDFSNP_MGR_CFG_NP_SECOND_CHASH_ALGO_ID(cdfsnp_mgr_cfg)   ((cdfsnp_mgr_cfg)->cdfsnp_second_chash_algo_id)
#define CDFSNP_MGR_CFG_NP_ITEM_MAX_NUM(cdfsnp_mgr_cfg)           ((cdfsnp_mgr_cfg)->cdfsnp_item_max_num)
#define CDFSNP_MGR_CFG_NP_CBLOOM_ROW_NUM(cdfsnp_mgr_cfg)         ((cdfsnp_mgr_cfg)->cdfsnp_cbloom_row_num)
#define CDFSNP_MGR_CFG_NP_CBLOOM_COL_NUM(cdfsnp_mgr_cfg)         ((cdfsnp_mgr_cfg)->cdfsnp_cbloom_col_num)
#define CDFSNP_MGR_CFG_NP_DISK_MAX_NUM(cdfsnp_mgr_cfg)           ((cdfsnp_mgr_cfg)->cdfsnp_disk_max_num)
#define CDFSNP_MGR_CFG_NP_SUPPORT_MAX_NUM(cdfsnp_mgr_cfg)        ((cdfsnp_mgr_cfg)->cdfsnp_support_max_num)
#define CDFSNP_MGR_CFG_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr_cfg)   ((cdfsnp_mgr_cfg)->cdfsnp_used_max_path_layout)

typedef struct
{
    CSTRING *      cdfsnp_db_root_dir;           /*cdfsnp database root dir*/

    LOG *          cdfsnp_lost_fnode_log;        /*file to log the lost fnode which write to another remote cdfsnp mgr failed*/
    LOG *          cdfsdn_lost_replica_log;      /*file to log the lost replica which replica not meet requirement*/

    CROUTINE_MUTEX         cmutex;

    UINT32         cdfsnp_cached_max_num;
    CLIST          cdfsnp_cached_list;           /*cached cdfsnp for reading and writting, num of cdfsnp <= CDFSNP_MGR_xxx_MODE_CHACED_NP_MAX_NUM*/

    int            cdfsnp_header_tbl_fd;         /*fd of all header saved file*/
    int            cdfsnp_cbloom_tbl_fd;         /*fd of all cbloom saved file*/

    UINT32         cdfsnp_header_tbl_buff_len;   /*buff len of all header buff*/
    UINT8  *       cdfsnp_header_tbl_buff;       /*buff of all header buff    */

    UINT32         cdfsnp_cbloom_tbl_buff_len;   /*buff len of all cbloom buff*/
    UINT8  *       cdfsnp_cbloom_tbl_buff;       /*buff of all cbloom buff    */

    CVECTOR        cdfsnp_vec;                   /*load all cdfsnp image into memory*/

    CDFSNP_MGR_CFG cdfsnp_cfg;/*note:cdfsnp_cfg must play the tail of CDFSNP_MGR. ref CDFSNP_MGR_CFG definition*/
}CDFSNP_MGR;

#define CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr)              ((cdfsnp_mgr)->cdfsnp_db_root_dir)
#define CDFSNP_MGR_DB_ROOT_DIR_STR(cdfsnp_mgr)          (cstring_get_str(CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr)))

#define CDFSNP_MGR_LOST_FNODE_LOG(cdfsnp_mgr)           ((cdfsnp_mgr)->cdfsnp_lost_fnode_log)
#define CDFSNP_MGR_LOST_REPLICA_LOG(cdfsnp_mgr)         ((cdfsnp_mgr)->cdfsdn_lost_replica_log)

#define CDFSNP_MGR_CFG(cdfsnp_mgr)                      (&((cdfsnp_mgr)->cdfsnp_cfg))

#define CDFSNP_MGR_NP_MODE(cdfsnp_mgr)                  (CDFSNP_MGR_CFG_NP_MODE(CDFSNP_MGR_CFG(cdfsnp_mgr)))
#define CDFSNP_MGR_NP_FIRST_CHASH_ALGO_ID(cdfsnp_mgr)   (CDFSNP_MGR_CFG_NP_FIRST_CHASH_ALGO_ID(CDFSNP_MGR_CFG(cdfsnp_mgr)))
#define CDFSNP_MGR_NP_SECOND_CHASH_ALGO_ID(cdfsnp_mgr)  (CDFSNP_MGR_CFG_NP_SECOND_CHASH_ALGO_ID(CDFSNP_MGR_CFG(cdfsnp_mgr)))
#define CDFSNP_MGR_NP_ITEM_MAX_NUM(cdfsnp_mgr)          (CDFSNP_MGR_CFG_NP_ITEM_MAX_NUM(CDFSNP_MGR_CFG(cdfsnp_mgr)))
#define CDFSNP_MGR_NP_CBLOOM_ROW_NUM(cdfsnp_mgr)        (CDFSNP_MGR_CFG_NP_CBLOOM_ROW_NUM(CDFSNP_MGR_CFG(cdfsnp_mgr)))
#define CDFSNP_MGR_NP_CBLOOM_COL_NUM(cdfsnp_mgr)        (CDFSNP_MGR_CFG_NP_CBLOOM_COL_NUM(CDFSNP_MGR_CFG(cdfsnp_mgr)))

#define CDFSNP_MGR_NP_DISK_MAX_NUM(cdfsnp_mgr)          (CDFSNP_MGR_CFG_NP_DISK_MAX_NUM(CDFSNP_MGR_CFG(cdfsnp_mgr)))
#define CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr)       (CDFSNP_MGR_CFG_NP_SUPPORT_MAX_NUM(CDFSNP_MGR_CFG(cdfsnp_mgr)))
#define CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr)  (CDFSNP_MGR_CFG_NP_USED_MAX_PATH_LAYOUT(CDFSNP_MGR_CFG(cdfsnp_mgr)))

#define CDFSNP_MGR_IS_FULL(cdfsnp_mgr)                  (CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr) <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) + 1)

#define CDFSNP_MGR_NP_VEC(cdfsnp_mgr)                   (&((cdfsnp_mgr)->cdfsnp_vec))
#define CDFSNP_MGR_NP_CACHED_MAX_NUM(cdfsnp_mgr)        ((cdfsnp_mgr)->cdfsnp_cached_max_num)
#define CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr)           (&((cdfsnp_mgr)->cdfsnp_cached_list))
#define CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr)         ((cdfsnp_mgr)->cdfsnp_header_tbl_fd)
#define CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr)   ((cdfsnp_mgr)->cdfsnp_header_tbl_buff_len)
#define CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr)       ((cdfsnp_mgr)->cdfsnp_header_tbl_buff)
#define CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr)         ((cdfsnp_mgr)->cdfsnp_cbloom_tbl_fd)
#define CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr)   ((cdfsnp_mgr)->cdfsnp_cbloom_tbl_buff_len)
#define CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr)       ((cdfsnp_mgr)->cdfsnp_cbloom_tbl_buff)

/*to reduce lock operation in name node*/
#define CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout) ((CDFSNP *)cvector_get_no_lock(CDFSNP_MGR_NP_VEC(cdfsnp_mgr), (cdfsnp_path_layout)))


#define CDFSNP_MGR_CMUTEX(cdfsnp_mgr)                   (&((cdfsnp_mgr)->cmutex))
#define CDFSNP_MGR_INIT_LOCK(cdfsnp_mgr, location)      (croutine_mutex_init(CDFSNP_MGR_CMUTEX(cdfsnp_mgr), CMUTEX_PROCESS_PRIVATE, location))
#define CDFSNP_MGR_CLEAN_LOCK(cdfsnp_mgr, location)     (croutine_mutex_clean(CDFSNP_MGR_CMUTEX(cdfsnp_mgr), location))
#define CDFSNP_MGR_LOCK(cdfsnp_mgr, location)           (croutine_mutex_lock(CDFSNP_MGR_CMUTEX(cdfsnp_mgr), location))
#define CDFSNP_MGR_UNLOCK(cdfsnp_mgr, location)         (croutine_mutex_unlock(CDFSNP_MGR_CMUTEX(cdfsnp_mgr), location))


EC_BOOL cdfsnp_mgr_buff_flush(const int fd, const UINT32 offset, const RWSIZE wsize, const UINT8 *buff);

EC_BOOL cdfsnp_mgr_buff_load(const int fd, const UINT32 offset, const RWSIZE rsize, UINT8 *buff);

EC_BOOL cdfsnp_mgr_cfg_init(CDFSNP_MGR_CFG *cdfsnp_mgr_cfg);

EC_BOOL cdfsnp_mgr_cfg_clean(CDFSNP_MGR_CFG *cdfsnp_mgr_cfg);

CDFSNP_MGR *cdfsnp_mgr_new();

EC_BOOL cdfsnp_mgr_init(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_clean(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_free(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_load_one_header(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, CDFSNP_HEADER *cdfsnp_header);

EC_BOOL cdfsnp_mgr_flush_one_header(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, const CDFSNP_HEADER *cdfsnp_header);

EC_BOOL cdfsnp_mgr_load_one_cbloom(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, const RWSIZE rsize, CBLOOM *cdfsnp_cbloom);

EC_BOOL cdfsnp_mgr_flush_one_cbloom(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, const RWSIZE wsize, const CBLOOM *cdfsnp_cbloom);

EC_BOOL cdfsnp_mgr_load_header_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_mgr_load_cbloom_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_mgr_flush_header_db(const CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_flush_cbloom_db(const CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_close_header_db(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_close_cbloom_db(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_close_header_db_with_flush(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_close_cbloom_db_with_flush(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_create_header_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_mgr_create_cbloom_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

void    cdfsnp_mgr_print_header_db(LOG *log, const CDFSNP_MGR *cdfsnp_mgr);

void    cdfsnp_mgr_print_cbloom_db(LOG *log, const CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_load_cfg_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_mgr_create_cfg_db(const CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_mgr_flush_cfg_db(CDFSNP_MGR *cdfsnp_mgr);

void    cdfsnp_mgr_print_cfg_db(LOG *log, const CDFSNP_MGR *cdfsnp_mgr);

void    cdfsnp_mgr_print(LOG *log, const CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_log_open(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_mgr_log_close(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_load(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_mgr_link(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_cache(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_flush_np(CDFSNP_MGR *cdfsnp_mgr, const UINT32 cdfsnp_path_layout);

EC_BOOL cdfsnp_mgr_flush(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_showup_np(CDFSNP_MGR *cdfsnp_mgr, const UINT32 cdfsnp_path_layout, LOG *log);

EC_BOOL cdfsnp_mgr_swapout(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_swapin(CDFSNP_MGR *cdfsnp_mgr, const UINT32 cdfsnp_path_layout);

EC_BOOL cdfsnp_mgr_search(CDFSNP_MGR *cdfsnp_mgr, const UINT32 path_len, const UINT8 *path, const UINT32 dflag, UINT32 *searched_cdfsnp_path_layout, UINT32 *searched_offset);

EC_BOOL cdfsnp_mgr_create(const UINT32 cdfsnp_mode, const UINT32 cdfsnp_disk_max_num, const UINT32 cdfsnp_support_max_num, const UINT32 cdfsnp_first_chash_algo_id, const UINT32 cdfsnp_second_chash_algo_id, const CSTRING *cdfsnp_db_root_dir);

CDFSNP_MGR * cdfsnp_mgr_open(const CSTRING *cdfsnp_db_root_dir, const UINT32 cdfsnp_cached_max_num);

EC_BOOL cdfsnp_mgr_close(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_close_with_flush(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_collect_items(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_item_vec);

CDFSNP *cdfsnp_mgr_reserve_np_to_write(CDFSNP_MGR *cdfsnp_mgr);

EC_BOOL cdfsnp_mgr_reserve_np_to_read(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_mgr_reserve_np_to_delete(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec);

EC_BOOL cdfsnp_mgr_update_np_fnode(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const CDFSNP_FNODE *cdfsnp_fnode);

EC_BOOL cdfsnp_mgr_find_dir(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *dir_path);
EC_BOOL cdfsnp_mgr_find_file(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path);
EC_BOOL cdfsnp_mgr_find(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag);
EC_BOOL cdfsnp_mgr_write(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode);
EC_BOOL cdfsnp_mgr_read(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, CDFSNP_FNODE *cdfsnp_fnode);
EC_BOOL cdfsnp_mgr_delete(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec);
EC_BOOL cdfsnp_mgr_mkdir(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path);
EC_BOOL cdfsnp_mgr_list_path(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, CVECTOR  *path_cstr_vec);
EC_BOOL cdfsnp_mgr_list_seg(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, CVECTOR  *seg_cstr_vec);
EC_BOOL cdfsnp_mgr_file_num(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_num);
EC_BOOL cdfsnp_mgr_file_size(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_size);
EC_BOOL cdfsnp_mgr_check_replicas(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, const UINT32 replica_num, const CVECTOR *tcid_vec);
EC_BOOL cdfsnp_mgr_figure_out_block(CDFSNP_MGR *cdfsnp_mgr, const UINT32 tcid, const UINT32 path_layout, LOG *log);
EC_BOOL cdfsnp_mgr_update(CDFSNP_MGR *cdfsnp_mgr, const UINT32 src_datanode_tcid, const UINT32 src_block_path_layout, const UINT32 des_datanode_tcid, const UINT32 des_block_path_layout);

/*debug only*/
EC_BOOL cdfsnp_mgr_show_cached_np(const CDFSNP_MGR *cdfsnp_mgr, LOG *log);

#endif/* _CDFSNPMGR_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

