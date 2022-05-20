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

#ifndef _CXFS_H
#define _CXFS_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "cstrkv.h"

#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#include "real.h"

#include "cpgbitmap.h"
#include "cmmap.h"
#include "cxfscfg.h"
#include "cxfsnp.h"
#include "cxfsdn.h"
#include "cxfsnpmgr.h"
#include "cxfsop.h"

#define CXFS_MAX_MODI                       ((UINT32)1)

#define CXFS_MEM_ALIGNMENT                  (1 << 20) /*1MB*/

#define CXFS_RECYCLE_MAX_NUM                ((UINT32)~0)

/*sata disk size / page size / 8*/
#define CXFS_SATA_BAD_BITMAP_SIZE_NBYTES    ((uint32_t)(1 << (CAMD_SATA_DISK_MAX_SIZE_NBITS - CAMD_PAGE_SIZE_NBITS - 3)))
#define CXFS_SATA_BAD_BITMAP_SIZE_NBITS     ((CXFS_SATA_BAD_BITMAP_SIZE_NBYTES - 4 - 4) << 3)
#define CXFS_SATA_BAD_BITMAP_MEM_ALIGN      (1 << 20) /*align to 1MB*/

#define CXFS_STAT_INTERVAL_NSEC             ((uint64_t)1)

#if 0
/*100GB <==> 2 ops/ms suggest op size is 512B and last for one day*/
#define CXFS_OP_TABLE_DISK_MAX_SIZE_NBYTES  (((uint64_t)100) << 30)/*100GB*/
#define CXFS_OP_TABLE_DISK_MAX_USED_NBYTES  (((uint64_t) 80) << 30)/*80GB*/

#define CXFS_OP_DUMP_MCACHE_MAX_SIZE_NBYTES (((uint32_t)  2) << 20)/*2MB*/
#define CXFS_OP_DUMP_MCACHE_MAX_USED_NBYTES (((uint32_t)  1) << 20)/*1MB*/
#define CXFS_OP_DUMP_MCACHE_MAX_IDLE_NSEC   (1)                    /*idle seconds at most before next dump*/

#define CXFS_WAIT_SYNC_MAX_MSEC             (30000)  /*30s*/
#endif
#if 0
#define CXFS_OP_TABLE_DISK_MAX_SIZE_NBYTES  (((uint64_t)128) << 20)/*128MB*/
#define CXFS_OP_TABLE_DISK_MAX_USED_NBYTES  (((uint64_t) 32) << 20)/*32MB*/

#define CXFS_OP_DUMP_MCACHE_MAX_SIZE_NBYTES (((uint32_t) 32) << 20)/*32MB*/
#define CXFS_OP_DUMP_MCACHE_MAX_USED_NBYTES (((uint32_t)  1) << 20)/*1MB*/
#define CXFS_OP_DUMP_MCACHE_MAX_IDLE_NSEC   (10)                   /*idle seconds at most before next dump*/

#define CXFS_WAIT_SYNC_MAX_MSEC             (30000)  /*30s*/
#endif
#if 1
#define CXFS_OP_TABLE_DISK_MAX_SIZE_NBYTES  (((uint64_t)  1) << 30)/*1GB*/
#define CXFS_OP_TABLE_DISK_MAX_USED_NBYTES  (((uint64_t)256) << 20)/*256MB*/

#define CXFS_OP_DUMP_MCACHE_MAX_SIZE_NBYTES (((uint32_t) 32) << 20)/*32MB*/
#define CXFS_OP_DUMP_MCACHE_MAX_USED_NBYTES (((uint32_t)  8) << 20)/*8MB*/
#define CXFS_OP_DUMP_MCACHE_MAX_IDLE_NSEC   (1)                    /*idle seconds at most before next dump*/

#define CXFS_WAIT_SYNC_MAX_MSEC             (30000)  /*30s*/
#endif

/*statistics*/
typedef struct
{
    uint64_t            read_counter;
    uint64_t            read_np_succ_counter;
    uint64_t            read_np_fail_counter;
    uint64_t            read_dn_succ_counter;
    uint64_t            read_dn_fail_counter;
    uint64_t            read_nbytes;
    uint64_t            read_cost_msec;

    uint64_t            write_counter;
    uint64_t            write_np_succ_counter;
    uint64_t            write_np_fail_counter;
    uint64_t            write_dn_succ_counter;
    uint64_t            write_dn_fail_counter;
    uint64_t            write_nbytes;
    uint64_t            write_cost_msec;

    uint64_t            update_counter;
    uint64_t            update_succ_counter;
    uint64_t            update_fail_counter;
    uint64_t            update_nbytes;
    uint64_t            update_cost_msec;

    uint64_t            renew_counter;
    uint64_t            renew_succ_counter;
    uint64_t            renew_fail_counter;
    uint64_t            renew_nbytes;
    uint64_t            renew_cost_msec;

    uint64_t            delete_counter;

    uint64_t            retire_counter;
    uint64_t            retire_complete;

    uint64_t            recycle_counter;
    uint64_t            recycle_complete;
}CXFS_STAT;

#define CXFS_STAT_READ_COUNTER(cxfs_stat)           ((cxfs_stat)->read_counter)
#define CXFS_STAT_READ_NP_SUCC_COUNTER(cxfs_stat)   ((cxfs_stat)->read_np_succ_counter)
#define CXFS_STAT_READ_NP_FAIL_COUNTER(cxfs_stat)   ((cxfs_stat)->read_np_fail_counter)
#define CXFS_STAT_READ_DN_SUCC_COUNTER(cxfs_stat)   ((cxfs_stat)->read_dn_succ_counter)
#define CXFS_STAT_READ_DN_FAIL_COUNTER(cxfs_stat)   ((cxfs_stat)->read_dn_fail_counter)
#define CXFS_STAT_READ_NBYTES(cxfs_stat)            ((cxfs_stat)->read_nbytes)
#define CXFS_STAT_READ_COST_MSEC(cxfs_stat)         ((cxfs_stat)->read_cost_msec)

#define CXFS_STAT_WRITE_COUNTER(cxfs_stat)          ((cxfs_stat)->write_counter)
#define CXFS_STAT_WRITE_NP_SUCC_COUNTER(cxfs_stat)  ((cxfs_stat)->write_np_succ_counter)
#define CXFS_STAT_WRITE_NP_FAIL_COUNTER(cxfs_stat)  ((cxfs_stat)->write_np_fail_counter)
#define CXFS_STAT_WRITE_DN_SUCC_COUNTER(cxfs_stat)  ((cxfs_stat)->write_dn_succ_counter)
#define CXFS_STAT_WRITE_DN_FAIL_COUNTER(cxfs_stat)  ((cxfs_stat)->write_dn_fail_counter)
#define CXFS_STAT_WRITE_NBYTES(cxfs_stat)           ((cxfs_stat)->write_nbytes)
#define CXFS_STAT_WRITE_COST_MSEC(cxfs_stat)        ((cxfs_stat)->write_cost_msec)

#define CXFS_STAT_UPDATE_COUNTER(cxfs_stat)         ((cxfs_stat)->update_counter)
#define CXFS_STAT_UPDATE_SUCC_COUNTER(cxfs_stat)    ((cxfs_stat)->update_succ_counter)
#define CXFS_STAT_UPDATE_FAIL_COUNTER(cxfs_stat)    ((cxfs_stat)->update_fail_counter)
#define CXFS_STAT_UPDATE_NBYTES(cxfs_stat)          ((cxfs_stat)->update_nbytes)
#define CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat)       ((cxfs_stat)->update_cost_msec)

#define CXFS_STAT_RENEW_COUNTER(cxfs_stat)          ((cxfs_stat)->renew_counter)
#define CXFS_STAT_RENEW_SUCC_COUNTER(cxfs_stat)     ((cxfs_stat)->renew_succ_counter)
#define CXFS_STAT_RENEW_FAIL_COUNTER(cxfs_stat)     ((cxfs_stat)->renew_fail_counter)
#define CXFS_STAT_RENEW_NBYTES(cxfs_stat)           ((cxfs_stat)->renew_nbytes)
#define CXFS_STAT_RENEW_COST_MSEC(cxfs_stat)        ((cxfs_stat)->renew_cost_msec)

#define CXFS_STAT_DELETE_COUNTER(cxfs_stat)         ((cxfs_stat)->delete_counter)

#define CXFS_STAT_RETIRE_COUNTER(cxfs_stat)         ((cxfs_stat)->retire_counter)
#define CXFS_STAT_RETIRE_COMPLETE(cxfs_stat)        ((cxfs_stat)->retire_complete)

#define CXFS_STAT_RECYCLE_COUNTER(cxfs_stat)        ((cxfs_stat)->recycle_counter)
#define CXFS_STAT_RECYCLE_COMPLETE(cxfs_stat)       ((cxfs_stat)->recycle_complete)

#define CXFS_ERR_STATE                      ((UINT32)  0)
#define CXFS_WORK_STATE                     ((UINT32)  1)
#define CXFS_SYNC_STATE                     ((UINT32)  2)
#define CXFS_REPLAY_STATE                   ((UINT32)  4)


typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    uint32_t             read_only_flag:1;
    uint32_t             sync_flag     :1;
    uint32_t             np_sync_flag  :1;
    uint32_t             dn_sync_flag  :1;
    uint32_t             op_dump_flag  :1;
    uint32_t             op_replay_flag:1;
    uint32_t             rsvd01        :26;
    uint16_t             rsvd02;
    uint16_t             cur_disk_no;    /*for cxfs queue model*/
    UINT32               state;

    CSTRING              sata_disk_path;
    int                  sata_disk_fd;
    int                  sata_meta_fd;

    CSTRING              ssd_disk_path;
    int                  ssd_disk_fd;
    int                  ssd_meta_fd;

    CXFSCFG              cxfscfg;

    CRB_TREE             locked_files; /*item is CXFS_LOCKED_FILE*/

    CRB_TREE             wait_files;   /*item is CXFS_WAITING_FILE*/

    CXFSDN              *cxfsdn;
    CXFSNP_MGR          *cxfsnpmgr;    /*namespace pool*/

    CPG_BITMAP          *sata_bad_bitmap;
    uint32_t             sata_bad_page_num; /*save prev num of sata bad pages*/
    uint32_t             rsvd05;
    uint64_t             time_msec_next;    /*next time to sync sata bad bitmap*/

    CXFSOP_MGR          *cxfsop_mgr;
    CLIST                cxfsop_mgr_list;   /*pending op mgrs to dump*/
    UINT32               cxfsop_dump_offset;/*relative offset in op table*/
    CMMAP_NODE          *np_cmmap_node;
    CMMAP_NODE          *dn_cmmap_node;

    /*statistics*/
    CXFS_STAT            cxfs_stat;
    CXFS_STAT            cxfs_stat_saved;

    UINT32               overhead_counter;
}CXFS_MD;

#define CXFS_MD_READ_ONLY_FLAG(cxfs_md)                 ((cxfs_md)->read_only_flag)
#define CXFS_MD_SYNC_FLAG(cxfs_md)                      ((cxfs_md)->sync_flag)
#define CXFS_MD_NP_SYNC_FLAG(cxfs_md)                   ((cxfs_md)->np_sync_flag)
#define CXFS_MD_DN_SYNC_FLAG(cxfs_md)                   ((cxfs_md)->dn_sync_flag)
#define CXFS_MD_OP_DUMP_FLAG(cxfs_md)                   ((cxfs_md)->op_dump_flag)
#define CXFS_MD_OP_REPLAY_FLAG(cxfs_md)                 ((cxfs_md)->op_replay_flag)
#define CXFS_MD_CUR_DISK_NO(cxfs_md)                    ((cxfs_md)->cur_disk_no)
#define CXFS_MD_STATE(cxfs_md)                          ((cxfs_md)->state)

#define CXFS_MD_SATA_META_FD(cxfs_md)                   ((cxfs_md)->sata_meta_fd)
#define CXFS_MD_SATA_DISK_PATH(cxfs_md)                 (&((cxfs_md)->sata_disk_path))
#define CXFS_MD_SATA_DISK_FD(cxfs_md)                   ((cxfs_md)->sata_disk_fd)

#define CXFS_MD_SSD_META_FD(cxfs_md)                    ((cxfs_md)->ssd_meta_fd)
#define CXFS_MD_SSD_DISK_PATH(cxfs_md)                  (&((cxfs_md)->ssd_disk_path))
#define CXFS_MD_SSD_DISK_FD(cxfs_md)                    ((cxfs_md)->ssd_disk_fd)

#define CXFS_MD_CFG(cxfs_md)                            (&((cxfs_md)->cxfscfg))
#define CXFS_MD_LOCKED_FILES(cxfs_md)                   (&((cxfs_md)->locked_files))
#define CXFS_MD_WAIT_FILES(cxfs_md)                     (&((cxfs_md)->wait_files))
#define CXFS_MD_DN(cxfs_md)                             ((cxfs_md)->cxfsdn)
#define CXFS_MD_NPP(cxfs_md)                            ((cxfs_md)->cxfsnpmgr)
#define CXFS_MD_SATA_BAD_BITMAP(cxfs_md)                ((cxfs_md)->sata_bad_bitmap)
#define CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)              ((cxfs_md)->sata_bad_page_num)
#define CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)            ((cxfs_md)->time_msec_next)
#define CXFS_MD_NP_CMMAP_NODE(cxfs_md)                  ((cxfs_md)->np_cmmap_node)
#define CXFS_MD_DN_CMMAP_NODE(cxfs_md)                  ((cxfs_md)->dn_cmmap_node)
#define CXFS_MD_OP_MGR(cxfs_md)                         ((cxfs_md)->cxfsop_mgr)
#define CXFS_MD_OP_MGR_LIST(cxfs_md)                    (&((cxfs_md)->cxfsop_mgr_list))
#define CXFS_MD_OP_DUMP_OFFSET(cxfs_md)                 ((cxfs_md)->cxfsop_dump_offset)
#define CXFS_MD_STAT(cxfs_md)                           (&((cxfs_md)->cxfs_stat))
#define CXFS_MD_STAT_SAVED(cxfs_md)                     (&((cxfs_md)->cxfs_stat_saved))
#define CXFS_MD_OVERHEAD_COUNTER(cxfs_md)               ((cxfs_md)->overhead_counter)

typedef struct
{
    CSTRING       name; /*file name*/
    CBYTES        token;

    UINT32        expire_nsec;/*locked expire interval in seconds*/
    UINT32        start_time; /*start time in seconds*/

}CXFS_LOCKED_FILE;

#define CXFS_LOCKED_FILE_NAME(cxfs_locked_file)                       (&((cxfs_locked_file)->name))
#define CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file)                      (&((cxfs_locked_file)->token))
#define CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file)                ((cxfs_locked_file)->expire_nsec)
#define CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file)                 (((cxfs_locked_file)->start_time))

#define CXFS_LOCKED_FILE_NAME_STR(cxfs_locked_file)                   (CSTRING_STR(CXFS_LOCKED_FILE_NAME(cxfs_locked_file)))
#define CXFS_LOCKED_FILE_NAME_LEN(cxfs_locked_file)                   (CSTRING_LEN(CXFS_LOCKED_FILE_NAME(cxfs_locked_file)))

#define CXFS_LOCKED_FILE_TOKEN_BUF(cxfs_locked_file)                  (CBYTES_BUF(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file)))
#define CXFS_LOCKED_FILE_TOKEN_LEN(cxfs_locked_file)                  (CBYTES_LEN(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file)))


typedef struct
{
    CSTRING        name; /*file name*/
    CLIST          owner_list; /*who are waiting it. item is MOD_NODE*/

    UINT32         expire_nsec;/*locked expire interval in seconds*/
    UINT32         start_time; /*start time in seconds*/
}CXFS_WAIT_FILE;
#define CXFS_WAIT_FILE_NAME(cxfs_wait_file)                       (&((cxfs_wait_file)->name))
#define CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file)                 (&((cxfs_wait_file)->owner_list))

#define CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file)                ((cxfs_wait_file)->expire_nsec)
#define CXFS_WAIT_FILE_START_TIME(cxfs_wait_file)                 (((cxfs_wait_file)->start_time))

#define CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file)                   (CSTRING_STR(CXFS_WAIT_FILE_NAME(cxfs_wait_file)))
#define CXFS_WAIT_FILE_NAME_LEN(cxfs_wait_file)                   (CSTRING_LEN(CXFS_WAIT_FILE_NAME(cxfs_wait_file)))

/**
*   for test only
*
*   to query the status of CXFS Module
*
**/
void cxfs_print_module_status(const UINT32 cxfs_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CXFS module
*
*
**/
UINT32 cxfs_free_module_static_mem(const UINT32 cxfs_md_id);

/**
*
* start CXFS module
*
**/
UINT32 cxfs_start(const CSTRING *sata_disk_path, const CSTRING *ssd_disk_path);

/**
*
* retrieve CXFS module
*
**/
UINT32 cxfs_retrieve(const CSTRING *sata_disk_path, const CSTRING *ssd_disk_path);

/**
*
* end CXFS module
*
**/
void cxfs_end(const UINT32 cxfs_md_id);

/**
*
* report xfs service
*
**/
EC_BOOL cxfs_sdisc_sender(const UINT32 cxfs_md_id, CSDISC_NODE *csdisc_node);

/**
*
* gather ngx service
*
**/
EC_BOOL cxfs_sdisc_recver(const UINT32 cxfs_md_id, CSDISC_NODE *csdisc_node);

/**
*
* wait sync bit flag cleared
*
**/
EC_BOOL cxfs_sync_wait(const UINT32 cxfs_md_id);

/**
*
* process sync CXFS to disk
*
**/
EC_BOOL cxfs_sync_do(const UINT32 cxfs_md_id);

/**
*
* sync CXFS to disk
*
**/
EC_BOOL cxfs_sync(const UINT32 cxfs_md_id);

/**
*
* flush CXFS
*
**/
EC_BOOL cxfs_flush(const UINT32 cxfs_md_id);

EC_BOOL cxfs_load_sata_bad_bitmap(CXFS_MD *cxfs_md);

EC_BOOL cxfs_flush_sata_bad_bitmap(CXFS_MD *cxfs_md);

EC_BOOL cxfs_sync_sata_bad_bitmap(CXFS_MD *cxfs_md);

EC_BOOL cxfs_close_sata_bad_bitmap(CXFS_MD *cxfs_md);

EC_BOOL cxfs_stat_init(CXFS_STAT *cxfs_stat);

EC_BOOL cxfs_stat_clean(CXFS_STAT *cxfs_stat);

CXFSNP_FNODE *cxfs_fnode_new(const UINT32 cxfs_md_id);

EC_BOOL cxfs_fnode_init(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfs_fnode_clean(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode);

EC_BOOL cxfs_fnode_free(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode);

CXFS_LOCKED_FILE *cxfs_locked_file_new();

EC_BOOL cxfs_locked_file_init(CXFS_LOCKED_FILE *cxfs_locked_file);

EC_BOOL cxfs_locked_file_clean(CXFS_LOCKED_FILE *cxfs_locked_file);

EC_BOOL cxfs_locked_file_free(CXFS_LOCKED_FILE *cxfs_locked_file);

EC_BOOL cxfs_locked_file_token_gen(CXFS_LOCKED_FILE *cxfs_locked_file, const CSTRING *file_name);

EC_BOOL cxfs_locked_file_expire_set(CXFS_LOCKED_FILE *cxfs_locked_file, const UINT32 expire_nsec);

EC_BOOL cxfs_locked_file_is_expire(const CXFS_LOCKED_FILE *cxfs_locked_file);

EC_BOOL cxfs_locked_file_name_set(CXFS_LOCKED_FILE *cxfs_locked_file, const CSTRING *file_name);

int cxfs_locked_file_cmp(const CXFS_LOCKED_FILE *cxfs_locked_file_1st, const CXFS_LOCKED_FILE *cxfs_locked_file_2nd);

void cxfs_locked_file_print(LOG *log, const CXFS_LOCKED_FILE *cxfs_locked_file);

CXFS_WAIT_FILE *cxfs_wait_file_new();

EC_BOOL cxfs_wait_file_init(CXFS_WAIT_FILE *cxfs_wait_file);

EC_BOOL cxfs_wait_file_clean(CXFS_WAIT_FILE *cxfs_wait_file);

EC_BOOL cxfs_wait_file_free(CXFS_WAIT_FILE *cxfs_wait_file);

EC_BOOL cxfs_wait_file_expire_set(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 expire_nsec);

EC_BOOL cxfs_wait_file_is_expire(const CXFS_WAIT_FILE *cxfs_wait_file);

EC_BOOL cxfs_wait_file_name_set(CXFS_WAIT_FILE *cxfs_wait_file, const CSTRING *file_name);

EC_BOOL cxfs_wait_file_owner_push(CXFS_WAIT_FILE *cxfs_wait_file, const MOD_NODE *mod_node);

EC_BOOL cxfs_wait_file_owner_notify (CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag);

EC_BOOL cxfs_wait_file_owner_terminate(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag);

int cxfs_wait_file_cmp(const CXFS_WAIT_FILE *cxfs_wait_file_1st, const CXFS_WAIT_FILE *cxfs_wait_file_2nd);

void cxfs_wait_file_print(LOG *log, const CXFS_WAIT_FILE *cxfs_wait_file);

void cxfs_wait_files_print(const UINT32 cxfs_md_id, LOG *log);


EC_BOOL cxfs_set_state(const UINT32 cxfs_md_id, const UINT32 cxfs_state);
UINT32  cxfs_get_state(const UINT32 cxfs_md_id);
EC_BOOL cxfs_is_state(const UINT32 cxfs_md_id, const UINT32 cxfs_state);

EC_BOOL cxfs_set_read_only(const UINT32 cxfs_md_id);

EC_BOOL cxfs_unset_read_only(const UINT32 cxfs_md_id);

EC_BOOL cxfs_is_read_only(const UINT32 cxfs_md_id);

/**
*
*  get name node pool of the module
*
**/
CXFSNP_MGR *cxfs_get_npp(const UINT32 cxfs_md_id);

/**
*
*  get data node of the module
*
**/
CXFSDN *cxfs_get_dn(const UINT32 cxfs_md_id);

/**
*
*  get stat of the module
*
**/
CXFS_STAT *cxfs_get_stat(const UINT32 cxfs_md_id);

/**
*
*  open name node pool
*
**/
EC_BOOL cxfs_open_npp(const UINT32 cxfs_md_id);

/**
*
*  flush and close name node pool
*
**/
EC_BOOL cxfs_close_npp(const UINT32 cxfs_md_id);

/**
*
*  check this CXFS is name node pool or not
*
*
**/
EC_BOOL cxfs_is_npp(const UINT32 cxfs_md_id);

/**
*
*  check this CXFS is data node or not
*
*
**/
EC_BOOL cxfs_is_dn(const UINT32 cxfs_md_id);

/**
*
*  check this CXFS is data node and namenode or not
*
*
**/
EC_BOOL cxfs_is_npp_and_dn(const UINT32 cxfs_md_id);

/**
*
*  create name node pool
*
**/
EC_BOOL cxfs_create_npp(const UINT32 cxfs_md_id, const UINT32 cxfsnp_model, const UINT32 cxfsnp_max_num, const UINT32 cxfsnp_2nd_chash_algo_id);

/**
*
*  dump name node pool to specific np zone
*
**/
EC_BOOL cxfs_dump_npp(const UINT32 cxfs_md_id, const UINT32 np_zone_idx);

/**
*
*  create sata bad bitmap
*
**/
EC_BOOL cxfs_create_sata_bad_bitmap(const UINT32 cxfs_md_id);

/**
*  for debug only !
*  set sata bad page
*
**/
EC_BOOL cxfs_set_sata_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no);

/**
*  for debug only !
*  unset sata bad page
*
**/
EC_BOOL cxfs_unset_sata_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no);

/**
*
*  check sata bad pag
*
**/
EC_BOOL cxfs_check_sata_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no);

/**
*
*  show sata bad pag
*
**/
void cxfs_show_sata_bad_pages(const UINT32 cxfs_md_id, LOG *log);

/**
*  for debug only !
*  set ssd bad page
*
**/
EC_BOOL cxfs_set_ssd_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no);

/**
*  for debug only !
*  unset ssd bad page
*
**/
EC_BOOL cxfs_unset_ssd_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no);

/**
*
*  check ssd bad pag
*
**/
EC_BOOL cxfs_check_ssd_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no);

/**
*
*  show ssd bad pag
*
**/
void cxfs_show_ssd_bad_pages(const UINT32 cxfs_md_id, LOG *log);


/**
*
*  check existing of a dir
*
**/
EC_BOOL cxfs_find_dir(const UINT32 cxfs_md_id, const CSTRING *dir_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL cxfs_find_file(const UINT32 cxfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL cxfs_is_file(const UINT32 cxfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a dir
*
**/
EC_BOOL cxfs_is_dir(const UINT32 cxfs_md_id, const CSTRING *dir_path);

/**
*
*  reserve space from dn
*
**/
EC_BOOL cxfs_reserve_dn(const UINT32 cxfs_md_id, const UINT32 data_len, CXFSNP_FNODE *cxfsnp_fnode);

/**
*
*  release space to dn
*
**/
EC_BOOL cxfs_release_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode);

/**
*
*  recycle space to dn
*
**/
EC_BOOL cxfs_recycle_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode);

/**
*
*  reserve a file
*
**/
EC_BOOL cxfs_reserve(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 file_size);

/**
*
*  write a file
*
**/
EC_BOOL cxfs_write(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL cxfs_write_no_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

#if 0
/**
*
*  write a file in cache
*
**/
EC_BOOL cxfs_write_cache(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
#endif


/**
*
*  read a file
*
**/
EC_BOOL cxfs_read(const UINT32 cxfs_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  write a file at offset
*
**/
EC_BOOL cxfs_write_e(const UINT32 cxfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read a file from offset
*
**/
EC_BOOL cxfs_read_e(const UINT32 cxfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  truncate a file with all zero content
*
**/
EC_BOOL cxfs_truncate_file(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 file_size);

/**
*
*  dump cfg
*
**/
EC_BOOL cxfs_dump_cfg(const UINT32 cxfs_md_id);

/**
*
*  create data node
*
**/
EC_BOOL cxfs_create_dn(const UINT32 cxfs_md_id);

/**
*
*  dump data node to specific zone
*
**/
EC_BOOL cxfs_dump_dn(const UINT32 cxfs_md_id, const UINT32 dn_zone_idx);

/**
*
*  add a disk to data node
*
**/
EC_BOOL cxfs_add_disk(const UINT32 cxfs_md_id, const UINT32 disk_no);

/**
*
*  delete a disk from data node
*
**/
EC_BOOL cxfs_del_disk(const UINT32 cxfs_md_id, const UINT32 disk_no);

/**
*
*  mount a disk to data node
*
**/
EC_BOOL cxfs_mount_disk(const UINT32 cxfs_md_id, const UINT32 disk_no);

/**
*
*  umount a disk from data node
*
**/
EC_BOOL cxfs_umount_disk(const UINT32 cxfs_md_id, const UINT32 disk_no);

/**
*
*  open data node
*
**/
EC_BOOL cxfs_open_dn(const UINT32 cxfs_md_id);

/**
*
*  close data node
*
**/
EC_BOOL cxfs_close_dn(const UINT32 cxfs_md_id);

/**
*
*  export data into data node
*
**/
EC_BOOL cxfs_export_dn(const UINT32 cxfs_md_id, const CBYTES *cbytes, const CXFSNP_FNODE *cxfsnp_fnode);

/**
*
*  write data node
*
**/
EC_BOOL cxfs_write_dn(const UINT32 cxfs_md_id, const CBYTES *cbytes, CXFSNP_FNODE *cxfsnp_fnode);

/**
*
*  read data node
*
**/
EC_BOOL cxfs_read_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode, CBYTES *cbytes);

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cxfs_write_e_dn(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cxfs_read_e_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);


/**
*
*  write a fnode to name node
*
**/
EC_BOOL cxfs_write_npp(const UINT32 cxfs_md_id, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode);

/**
*
*  read a fnode from name node
*
**/
EC_BOOL cxfs_read_npp(const UINT32 cxfs_md_id, const CSTRING *file_path, CXFSNP_FNODE *cxfsnp_fnode);


/**
*
*  update a fnode to name node
*
**/
EC_BOOL cxfs_update_npp(const UINT32 cxfs_md_id, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode);

/**
*
*  reallink of path
*
**/
EC_BOOL cxfs_reallink(const UINT32 cxfs_md_id, const CSTRING *src_path, CSTRING *des_path);

/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL cxfs_renew_http_header(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val);
EC_BOOL cxfs_renew_http_headers(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr);
EC_BOOL cxfs_renew_http_headers_with_token(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *token_str);

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL cxfs_wait_http_header(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, const CSTRING *key, const CSTRING *val, UINT32 *header_ready);
EC_BOOL cxfs_wait_http_headers(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);

/**
*
*  delete file data from current dn
*
**/
EC_BOOL cxfs_delete_dn(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, const CXFSNP_ITEM *cxfsnp_item);

/**
*
*  delete a file
*
**/
EC_BOOL cxfs_delete_file(const UINT32 cxfs_md_id, const CSTRING *path);
EC_BOOL cxfs_delete_file_no_lock(const UINT32 cxfs_md_id, const CSTRING *path);
EC_BOOL cxfs_delete_file_wildcard(const UINT32 cxfs_md_id, const CSTRING *path);

/**
*
*  delete a dir from all npp and all dn
*
**/
EC_BOOL cxfs_delete_dir(const UINT32 cxfs_md_id, const CSTRING *path);
EC_BOOL cxfs_delete_dir_no_lock(const UINT32 cxfs_md_id, const CSTRING *path);
EC_BOOL cxfs_delete_dir_wildcard(const UINT32 cxfs_md_id, const CSTRING *path);

/**
*
*  update a file
*
**/
EC_BOOL cxfs_update(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL cxfs_update_no_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL cxfs_update_with_token(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *token_str);

/**
*
*  query a file
*
**/
EC_BOOL cxfs_qfile(const UINT32 cxfs_md_id, const CSTRING *file_path, CXFSNP_ITEM  *cxfsnp_item, CXFSNP_KEY *crsnp_key);

/**
*
*  query a dir
*
**/
EC_BOOL cxfs_qdir(const UINT32 cxfs_md_id, const CSTRING *dir_path, CXFSNP_ITEM  *cxfsnp_item, CXFSNP_KEY *crsnp_key);


/**
*
*  query and list full path of a file or dir of one np
*
**/
EC_BOOL cxfs_qlist_path_of_np(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 cxfsnp_id, CVECTOR  *path_cstr_vec);

/**
*
*  query and list short name of a file or dir of one np
*
**/
EC_BOOL cxfs_qlist_seg_of_np(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 cxfsnp_id, CVECTOR  *seg_cstr_vec);

/**
*
*  query and list full path of a file or dir
*
**/
EC_BOOL cxfs_qlist_path(const UINT32 cxfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);

/**
*
*  query and list short name of a file or dir
*
**/
EC_BOOL cxfs_qlist_seg(const UINT32 cxfs_md_id, const CSTRING *file_path, CVECTOR  *seg_cstr_vec);

/**
*
*  query and list full path of a file or  all files under a dir recursively
*  (looks like shell command: tree)
*
**/
EC_BOOL cxfs_qlist_tree(const UINT32 cxfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);

/**
*
*  query and list full path of a file or all files under a dir of one np
*  (looks like shell command: tree)
*
**/
EC_BOOL cxfs_qlist_tree_of_np(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);

/**
*
*  flush name node pool
*
**/
EC_BOOL cxfs_flush_npp(const UINT32 cxfs_md_id);

/**
*
*  flush data node
*
*
**/
EC_BOOL cxfs_flush_dn(const UINT32 cxfs_md_id);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cxfs_file_num(const UINT32 cxfs_md_id, const CSTRING *path_cstr, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cxfs_file_size(const UINT32 cxfs_md_id, const CSTRING *path_cstr, uint64_t *file_size);

/**
*
*  set file expired time to current time
*
**/
EC_BOOL cxfs_file_expire(const UINT32 cxfs_md_id, const CSTRING *path_cstr);

/**
*
*  get file md5sum of specific file given full path name
*
**/
EC_BOOL cxfs_file_md5sum(const UINT32 cxfs_md_id, const CSTRING *path_cstr, CMD5_DIGEST *md5sum);

/**
*
*  retire the expired locked files over 120 seconds (twice expire nsec) which are garbage
*
**/
EC_BOOL cxfs_locked_file_retire(const UINT32 cxfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num);

/*
*
* retire the expired wait files over 120 seconds which are garbage
*
*/
EC_BOOL cxfs_wait_file_retire(const UINT32 cxfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num);

/**
*
*  try to lock a file in expire_nsec seconds and return the authentication token
*
**/
EC_BOOL cxfs_file_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already);

/**
*
*  try to unlock a file with a given authentication token
*
**/
EC_BOOL cxfs_file_unlock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRING *token_str);

/**
*
*  wait file to ready
*
**/
EC_BOOL cxfs_file_wait(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, UINT32 *file_size, UINT32 *data_ready);

EC_BOOL cxfs_file_wait_ready(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, UINT32 *data_ready);

/**
*
*  wait file (range) to ready
*
**/
EC_BOOL cxfs_file_wait_e(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, UINT32 *offset, const UINT32 max_len, UINT32 *len, UINT32 *data_ready);

/**
*
*  notify all waiters
*
**/
EC_BOOL cxfs_file_notify(const UINT32 cxfs_md_id, const CSTRING *file_path);

/**
*
*  terminate all waiters
*
**/
EC_BOOL cxfs_file_terminate(const UINT32 cxfs_md_id, const CSTRING *file_path);

/**
*
*  wakeup remote waiter
*
**/
EC_BOOL cxfs_wait_file_owner_wakeup (const UINT32 cxfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
*  cancel remote waiter (over http)
*
**/
EC_BOOL cxfs_wait_file_owner_cancel (const UINT32 cxfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL cxfs_file_unlock_notify(const UINT32 cxfs_md_id, const CSTRING *file_path);

/**
*
*  mkdir in current name node pool
*
**/
EC_BOOL cxfs_mkdir(const UINT32 cxfs_md_id, const CSTRING *path_cstr);

/**
*
*  empty recycle
*
**/
EC_BOOL cxfs_recycle(const UINT32 cxfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num);

/**
*
*  check space and process retire & recycle if reach threadhold
*
**/
EC_BOOL cxfs_process_space(const UINT32 cxfs_md_id);

/**
*
*  process statistics
*
**/
EC_BOOL cxfs_process_stat(const UINT32 cxfs_md_id);

/**
*
*  check file content on data node
*
**/
EC_BOOL cxfs_check_file_content(const UINT32 cxfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr);

/**
*
*  check file content on data node
*
**/
EC_BOOL cxfs_check_file_is(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *file_content);

/**
*
*  check space [s_offset, e_offset) is used or not
*
**/
EC_BOOL cxfs_check_space_used(const UINT32 cxfs_md_id, const UINT32 s_offset, const UINT32 e_offset);

/**
*
*  check space [o_s_offset, o_e_offset) except [i_s_offset, i_e_offset) is used or not
*  where
*       o_s_offset <= i_s_offset <= i_e_offset <= o_e_offset
*
**/
EC_BOOL cxfs_check_adjacent_used(const UINT32 cxfs_md_id, const UINT32 o_s_offset, const UINT32 o_e_offset, const UINT32 i_s_offset, const UINT32 i_e_offset);

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL cxfs_show_npp(const UINT32 cxfs_md_id, LOG *log);

/**
*
*  show name node que list if it is npp
*
*
**/
EC_BOOL cxfs_show_npp_que_list(const UINT32 cxfs_md_id, LOG *log);

/**
*
*  show name node del list if it is npp
*
*
**/
EC_BOOL cxfs_show_npp_del_list(const UINT32 cxfs_md_id, LOG *log);

/**
*
*  show cxfsdn info if it is dn
*
*
**/
EC_BOOL cxfs_show_dn(const UINT32 cxfs_md_id, LOG *log);

/**
*
*  show all locked files which are used for merge-orig procedure
*
*
**/
void cxfs_locked_files_print(const UINT32 cxfs_md_id, LOG *log);


EC_BOOL cxfs_show_specific_np(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log);

EC_BOOL cxfs_show_specific_np_que_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log);

EC_BOOL cxfs_show_specific_np_del_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log);

EC_BOOL cxfs_retire(const UINT32 cxfs_md_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num);

EC_BOOL cxfs_process_op(const UINT32 cxfs_md_id);

EC_BOOL cxfs_dump_op(const UINT32 cxfs_md_id);

EC_BOOL cxfs_replay_op(const UINT32 cxfs_md_id);

EC_BOOL cxfs_pop_op(const UINT32 cxfs_md_id, const UINT32 op_size);

/**
*
*  register xfs to ngx consistent hash table
*
**/
EC_BOOL cxfs_reg_ngx(const UINT32 cxfs_md_id);

/**
*
*  activate xfs on all ngx
*  i.e., notify all ngx that I am up
*
**/
EC_BOOL cxfs_activate_ngx(const UINT32 cxfs_md_id);

/**
*
*  deactivate xfs on all ngx
*  i.e., notify all ngx that I am down
*
**/
EC_BOOL cxfs_deactivate_ngx(const UINT32 cxfs_md_id);


#endif /*_CXFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

