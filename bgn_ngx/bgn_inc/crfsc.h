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

#ifndef _CRFSC_H
#define _CRFSC_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "csocket.h"

#include "mod.inc"

#include "crfsnp.h"
#include "crfsdn.h"
#include "crfsnpmgr.h"
#include "crfsmc.h"
#include "crfsbk.h"
#include "crfsdt.h"

#define CRFSC_MAX_REPLICA_NUM                ((UINT32) 2)

#define CRFSC_DIRTAB_FNAME                   ((const char *)"dirtab.dat")

typedef struct
{
    /* used counter >= 0 */
    UINT32      usedcounter;

    CSTRING     crfs_root_dir;

    CVECTOR     crfs_vec; /*item is crfs MOD_NODE*/

    uint32_t    crfsdt_active_flag:1; /*0: active is crfsdts[0], 1: active is crfsdts[1]*/
    uint32_t    rsvd1:31;
    uint32_t    rsvd2;
    CRFSDT      crfsdts[2];   /*CRFS dir tables*/

    CROUTINE_RWLOCK     crwlock;
}CRFSC_MD;

#define CRFSC_MD_CRFS_VEC(crfsc_md)        (&((crfsc_md)->crfs_vec))
#define CRFSC_MD_ROOT_DIR(crfsc_md)        (&((crfsc_md)->crfs_root_dir))
#define CRFSC_MD_DT_ACTIVE_FLAG(crfsc_md)  ((crfsc_md)->crfsdt_active_flag)
#define CRFSC_MD_ACTIVE_DIRTAB(crfsc_md)   (&((crfsc_md)->crfsdts[ CRFSC_MD_DT_ACTIVE_FLAG(crfsc_md) ]))
#define CRFSC_MD_STANDBY_DIRTAB(crfsc_md)  (&((crfsc_md)->crfsdts[ 1 ^ CRFSC_MD_DT_ACTIVE_FLAG(crfsc_md) ]))
#define CRFSC_CRWLOCK(crfsc_md)            (&((crfsc_md)->crwlock))

#if 0
#define CRFSC_INIT_LOCK(crfsc_md, location)  (croutine_rwlock_init(CRFSC_CRWLOCK(crfsc_md), CMUTEX_PROCESS_PRIVATE, location))
#define CRFSC_CLEAN_LOCK(crfsc_md, location) (croutine_rwlock_clean(CRFSC_CRWLOCK(crfsc_md), location))

#define CRFSC_RDLOCK(crfsc_md, location)     (croutine_rwlock_rdlock(CRFSC_CRWLOCK(crfsc_md), location))
#define CRFSC_WRLOCK(crfsc_md, location)     (croutine_rwlock_wrlock(CRFSC_CRWLOCK(crfsc_md), location))
#define CRFSC_UNLOCK(crfsc_md, location)     (croutine_rwlock_unlock(CRFSC_CRWLOCK(crfsc_md), location))
#endif

#if 1
#define CRFSC_INIT_LOCK(crfsc_md, location)  (croutine_rwlock_init(CRFSC_CRWLOCK(crfsc_md), CMUTEX_PROCESS_PRIVATE, location))
#define CRFSC_CLEAN_LOCK(crfsc_md, location) (croutine_rwlock_clean(CRFSC_CRWLOCK(crfsc_md), location))
#define CRFSC_RDLOCK(crfsc_md, location)     (croutine_rwlock_rdlock(CRFSC_CRWLOCK(crfsc_md), location))
#define CRFSC_WRLOCK(crfsc_md, location)     (croutine_rwlock_wrlock(CRFSC_CRWLOCK(crfsc_md), location))
#define CRFSC_UNLOCK(crfsc_md, location)     (croutine_rwlock_unlock(CRFSC_CRWLOCK(crfsc_md), location))
#endif


typedef struct
{
    UINT32       crfsc_md_id;
    MOD_MGR     *mod_mgr;
}CRFSC_WALKER_ARG;

#define CRFSC_WALKER_ARG_MODI(crfsc_walker_arg)          ((crfsc_walker_arg)->crfsc_md_id)
#define CRFSC_WALKER_ARG_MOD_MGR(crfsc_walker_arg)       ((crfsc_walker_arg)->mod_mgr)


/**
*   for test only
*
*   to query the status of CRFSC Module
*
**/
void crfsc_print_module_status(const UINT32 crfsc_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CRFSC module
*
*
**/
UINT32 crfsc_free_module_static_mem(const UINT32 crfsc_md_id);

/**
*
* start CRFSC module
*
**/
UINT32 crfsc_start(const CSTRING *crfs_root_dir);

/**
*
* end CRFSC module
*
**/
void crfsc_end(const UINT32 crfsc_md_id);

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfsc_find_dir_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path);

EC_BOOL crfsc_find_dir(const UINT32 crfsc_md_id, const CSTRING *dir_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL crfsc_find_file_ep(const UINT32 crfsc_md_id, const CSTRING *file_path);

EC_BOOL crfsc_find_file(const UINT32 crfsc_md_id, const CSTRING *file_path);

/**
*
*  check existing of a big file
*
**/
EC_BOOL crfsc_find_file_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path);

EC_BOOL crfsc_find_file_b(const UINT32 crfsc_md_id, const CSTRING *file_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL crfsc_is_file(const UINT32 crfsc_md_id, const CSTRING *file_path);

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfsc_is_dir(const UINT32 crfsc_md_id, const CSTRING *dir_path);

/**
*
*  write a file
*
**/
EC_BOOL crfsc_write_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes);

EC_BOOL crfsc_write(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  read a file
*
**/
EC_BOOL crfsc_read_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL crfsc_read(const UINT32 crfsc_md_id, const CSTRING *file_path, CBYTES *cbytes);

/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a file at offset
*
**/
EC_BOOL crfsc_write_e_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

EC_BOOL crfsc_write_e(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file); 
*
**/
EC_BOOL crfsc_read_e_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

EC_BOOL crfsc_read_e(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/*----------------------------------- BIG FILE interface -----------------------------------*/

/**
*
*  create a big file at offset
*
**/
EC_BOOL crfsc_create_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const uint64_t *file_size);

EC_BOOL crfsc_create_b(const UINT32 crfsc_md_id, const CSTRING *file_path, const uint64_t *file_size);

/**
*
*  write a big file at offset
*
**/
EC_BOOL crfsc_write_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const CBYTES *cbytes);

EC_BOOL crfsc_write_b(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const CBYTES *cbytes);

/**
*
*  read a file from offset
*
**/
EC_BOOL crfsc_read_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const UINT32 max_len, CBYTES *cbytes);

EC_BOOL crfsc_read_b(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const UINT32 max_len, CBYTES *cbytes);

EC_BOOL crfsc_fetch_block_fd_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const uint64_t offset, uint32_t *block_size, int *block_fd);

/**
*
*  renew a fnode to name node
*
**/
EC_BOOL crfsc_renew_ep(const UINT32 crfsc_md_id, const CSTRING *file_path);

EC_BOOL crfsc_renew(const UINT32 crfsc_md_id, const CSTRING *file_path);

/**
*
*  delete a file
*
**/
EC_BOOL crfsc_delete_file_ep(const UINT32 crfsc_md_id, const CSTRING *file_path);

EC_BOOL crfsc_delete_file(const UINT32 crfsc_md_id, const CSTRING *file_path);

/**
*
*  delete a big file
*
**/
EC_BOOL crfsc_delete_file_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path);

EC_BOOL crfsc_delete_file_b(const UINT32 crfsc_md_id, const CSTRING *file_path);

/**
*
*  delete a dir from all npp and all dn
*
**/
EC_BOOL crfsc_delete_dir_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path);

EC_BOOL crfsc_delete_dir(const UINT32 crfsc_md_id, const CSTRING *dir_path);


/**
*
*  delete a file or dir from all npp and all dn
*
**/
EC_BOOL crfsc_delete(const UINT32 crfsc_md_id, const CSTRING *path, const UINT32 dflag);

/**
*
*  update a file 
*
**/
EC_BOOL crfsc_update_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes);

EC_BOOL crfsc_update(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  query a file
*
**/
EC_BOOL crfsc_qfile_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item);

EC_BOOL crfsc_qfile(const UINT32 crfsc_md_id, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL crfsc_file_size_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *file_size);

EC_BOOL crfsc_file_size(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *file_size);

/**
*
*  get bigfile store size of specific file given full path name
*
**/
EC_BOOL crfsc_store_size_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *store_size);

EC_BOOL crfsc_store_size_b(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *store_size);

/**
*
*  get file md5sum of specific file given full path name
*
**/
EC_BOOL crfsc_file_md5sum_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, CMD5_DIGEST *md5sum);

EC_BOOL crfsc_file_md5sum(const UINT32 crfsc_md_id, const CSTRING *file_path, CMD5_DIGEST *md5sum);

/**
*
*  get a seg md5sum of specific bigfile given full path name
*
**/

EC_BOOL crfsc_file_md5sum_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const UINT32 seg_no, CMD5_DIGEST *md5sum);

EC_BOOL crfsc_file_md5sum_b(const UINT32 crfsc_md_id, const CSTRING *file_path, const UINT32 seg_no, CMD5_DIGEST *md5sum);

EC_BOOL crfsc_file_mod_node(const UINT32 crfsc_md_id, const CSTRING *file_path, MOD_NODE *mod_node);

/**
*
*  empty recycle
*
**/
EC_BOOL crfsc_recycle_ep(const UINT32 crfsc_md_id);

EC_BOOL crfsc_recycle(const UINT32 crfsc_md_id);

/**
*
*  dirtab
*
**/
EC_BOOL crfsc_add_dir(const UINT32 crfsc_md_id, const UINT32 tcid, const CSTRING *path);
EC_BOOL crfsc_del_dir(const UINT32 crfsc_md_id, const UINT32 tcid, const CSTRING *path);
EC_BOOL crfsc_has_dir(const UINT32 crfsc_md_id, const UINT32 tcid, const CSTRING *path);

EC_BOOL crfsc_exist_dt(const UINT32 crfsc_md_id);
EC_BOOL crfsc_clone_dt(const UINT32 crfsc_md_id);
EC_BOOL crfsc_rollback_dt(const UINT32 crfsc_md_id);
EC_BOOL crfsc_flush_dt(const UINT32 crfsc_md_id);
EC_BOOL crfsc_load_dt(const UINT32 crfsc_md_id);
void    crfsc_print_dt(const UINT32 crfsc_md_id, LOG *log);

/**
*
*  transfer dir prepare based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_pre_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode);
EC_BOOL crfsc_trans_dir_pre(const UINT32 crfsc_md_id, const CSTRING *dir_path);

/**
*
*  transfer dir handle based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_handle_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode);
EC_BOOL crfsc_trans_dir_handle(const UINT32 crfsc_md_id, const CSTRING *dir_path);

/**
*
*  transfer dir post clean based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_post_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode);
EC_BOOL crfsc_trans_dir_post(const UINT32 crfsc_md_id, const CSTRING *dir_path);

/**
*
*  transfer dir recycle based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_recycle_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode);
EC_BOOL crfsc_trans_dir_recycle(const UINT32 crfsc_md_id, const CSTRING *dir_path);


/**
*
*  transfer dir based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_whole_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode);
EC_BOOL crfsc_trans_dir_whole(const UINT32 crfsc_md_id, const CSTRING *dir_path);

EC_BOOL crfsc_rdlock(const UINT32 crfsc_md_id, const UINT32 location);
EC_BOOL crfsc_wrlock(const UINT32 crfsc_md_id, const UINT32 location);
EC_BOOL crfsc_unlock(const UINT32 crfsc_md_id, const UINT32 location);


#endif /*_CRFSC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

