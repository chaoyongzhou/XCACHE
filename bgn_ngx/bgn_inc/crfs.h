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

#ifndef _CRFS_H
#define _CRFS_H

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

#include "crfsnp.h"
#include "crfsdn.h"
#include "crfsnpmgr.h"
#include "crfsmc.h"
#include "crfsbk.h"


#define CRFS_MAX_MODI                       ((UINT32)32)

#define CRFS_CHECK_DN_EXPIRE_IN_NSEC        ((uint32_t) 300) /*check once in 5 minutes*/

#define CRFS_MAX_REPLICA_NUM                ((UINT32) 1)

#define CRFS_FILE_PAD_CHAR                  (0x00)
//#define CRFS_FILE_PAD_CHAR                  ((uint8_t)'.')

#define CRFS_BIGFILE_MAX_SIZE               ((uint64_t)(((uint64_t)1) << 46))/*64TB*/

#define CRFS_RECYCLE_MAX_NUM                ((UINT32)~0)

#define CRFS_ERR_STATE                      ((UINT32)  0)
#define CRFS_WORK_STATE                     ((UINT32)  1)
#define CRFS_SYNC_STATE                     ((UINT32)  2)
#define CRFS_REPLAY_STATE                   ((UINT32)  4)

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;
    UINT32               state;

    CBTIMER_NODE        *cbtimer_node;

    CRB_TREE             locked_files; /*item is CRFS_LOCKED_FILE*/

    CRB_TREE             wait_files;   /*item is CRFS_WAITING_FILE*/

    MOD_MGR             *crfsdn_mod_mgr;
    MOD_MGR             *crfsnpp_mod_mgr;

    CRFSDN              *crfsdn;
    CRFSNP_MGR          *crfsnpmgr;/*namespace pool*/

    CVECTOR              crfs_neighbor_vec;/*item is MOD_NODE*/
}CRFS_MD;

#define CRFS_MD_TERMINATE_FLAG(crfs_md)    ((crfs_md)->terminate_flag)
#define CRFS_MD_STATE(crfs_md)             ((crfs_md)->state)
#define CRFS_MD_CBTIMER_NODE(crfs_md)      ((crfs_md)->cbtimer_node)
#define CRFS_MD_LOCKED_FILES(crfs_md)      (&((crfs_md)->locked_files))
#define CRFS_MD_WAIT_FILES(crfs_md)        (&((crfs_md)->wait_files))
#define CRFS_MD_DN_MOD_MGR(crfs_md)        ((crfs_md)->crfsdn_mod_mgr)
#define CRFS_MD_NPP_MOD_MGR(crfs_md)       ((crfs_md)->crfsnpp_mod_mgr)
#define CRFS_MD_DN(crfs_md)                ((crfs_md)->crfsdn)
#define CRFS_MD_NPP(crfs_md)               ((crfs_md)->crfsnpmgr)
#define CRFS_MD_NEIGHBOR_VEC(crfs_md)      (&((crfs_md)->crfs_neighbor_vec))


typedef struct
{
    CSTRING       name; /*file name*/
    CBYTES        token;

    UINT32        expire_nsec;/*lock expire interval in seconds*/
    CTIMET        start_time;
    CTIMET        last_time;

}CRFS_LOCKED_FILE;

#define CRFS_LOCKED_FILE_NAME(crfs_locked_file)                       (&((crfs_locked_file)->name))
#define CRFS_LOCKED_FILE_TOKEN(crfs_locked_file)                      (&((crfs_locked_file)->token))
#define CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file)                ((crfs_locked_file)->expire_nsec)
#define CRFS_LOCKED_FILE_START_TIME(crfs_locked_file)                 (((crfs_locked_file)->start_time))
#define CRFS_LOCKED_FILE_LAST_TIME(crfs_locked_file)                  (((crfs_locked_file)->last_time))

#define CRFS_LOCKED_FILE_NAME_STR(crfs_locked_file)                   (CSTRING_STR(CRFS_LOCKED_FILE_NAME(crfs_locked_file)))
#define CRFS_LOCKED_FILE_NAME_LEN(crfs_locked_file)                   (CSTRING_LEN(CRFS_LOCKED_FILE_NAME(crfs_locked_file)))

#define CRFS_LOCKED_FILE_TOKEN_BUF(crfs_locked_file)                  (CBYTES_BUF(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file)))
#define CRFS_LOCKED_FILE_TOKEN_LEN(crfs_locked_file)                  (CBYTES_LEN(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file)))


typedef struct
{
    CSTRING        name; /*file name*/
    CLIST          owner_list; /*who are waiting it. item is MOD_NODE*/
}CRFS_WAIT_FILE;
#define CRFS_WAIT_FILE_NAME(crfs_wait_file)                       (&((crfs_wait_file)->name))
#define CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file)                 (&((crfs_wait_file)->owner_list))

#define CRFS_WAIT_FILE_NAME_STR(crfs_wait_file)                   (CSTRING_STR(CRFS_WAIT_FILE_NAME(crfs_wait_file)))
#define CRFS_WAIT_FILE_NAME_LEN(crfs_wait_file)                   (CSTRING_LEN(CRFS_WAIT_FILE_NAME(crfs_wait_file)))

/**
*   for test only
*
*   to query the status of CRFS Module
*
**/
void crfs_print_module_status(const UINT32 crfs_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CRFS module
*
*
**/
UINT32 crfs_free_module_static_mem(const UINT32 crfs_md_id);

/**
*
* start CRFS module
*
**/
UINT32 crfs_start(const CSTRING *crfs_root_dir);

/**
*
* end CRFS module
*
**/
void crfs_end(const UINT32 crfs_md_id);

/**
*
* flush CRFS
*
**/
EC_BOOL crfs_flush(const UINT32 crfs_md_id);

UINT32 crfs_set_npp_mod_mgr(const UINT32 crfs_md_id, const MOD_MGR * src_mod_mgr);

UINT32 crfs_set_dn_mod_mgr(const UINT32 crfs_md_id, const MOD_MGR * src_mod_mgr);

MOD_MGR * crfs_get_npp_mod_mgr(const UINT32 crfs_md_id);

MOD_MGR * crfs_get_dn_mod_mgr(const UINT32 crfs_md_id);

EC_BOOL crfs_add_npp(const UINT32 crfs_md_id, const UINT32 crfsnpp_tcid, const UINT32 crfsnpp_rank);

EC_BOOL crfs_add_dn(const UINT32 crfs_md_id, const UINT32 crfsdn_tcid, const UINT32 crfsdn_rank);

CRFSNP_FNODE *crfs_fnode_new(const UINT32 crfs_md_id);

EC_BOOL crfs_fnode_init(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfs_fnode_clean(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfs_fnode_free(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode);

CRFS_LOCKED_FILE *crfs_locked_file_new();

EC_BOOL crfs_locked_file_init(CRFS_LOCKED_FILE *crfs_locked_file);

EC_BOOL crfs_locked_file_clean(CRFS_LOCKED_FILE *crfs_locked_file);

EC_BOOL crfs_locked_file_free(CRFS_LOCKED_FILE *crfs_locked_file);

EC_BOOL crfs_locked_file_token_gen(CRFS_LOCKED_FILE *crfs_locked_file, const CSTRING *file_name);

EC_BOOL crfs_locked_file_expire_set(CRFS_LOCKED_FILE *crfs_locked_file, const UINT32 expire_nsec);

EC_BOOL crfs_locked_file_is_expire(const CRFS_LOCKED_FILE *crfs_locked_file);

EC_BOOL crfs_locked_file_name_set(CRFS_LOCKED_FILE *crfs_locked_file, const CSTRING *file_name);

int crfs_locked_file_cmp(const CRFS_LOCKED_FILE *crfs_locked_file_1st, const CRFS_LOCKED_FILE *crfs_locked_file_2nd);

void crfs_locked_file_print(LOG *log, const CRFS_LOCKED_FILE *crfs_locked_file);

CRFS_WAIT_FILE *crfs_wait_file_new();

EC_BOOL crfs_wait_file_init(CRFS_WAIT_FILE *crfs_wait_file);

EC_BOOL crfs_wait_file_clean(CRFS_WAIT_FILE *crfs_wait_file);

EC_BOOL crfs_wait_file_free(CRFS_WAIT_FILE *crfs_wait_file);

EC_BOOL crfs_wait_file_name_set(CRFS_WAIT_FILE *crfs_wait_file, const CSTRING *file_name);

EC_BOOL crfs_wait_file_owner_push(CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tcid);

EC_BOOL crfs_wait_file_owner_notify (CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag);

EC_BOOL crfs_wait_file_owner_terminate(CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag);

int crfs_wait_file_cmp(const CRFS_WAIT_FILE *crfs_wait_file_1st, const CRFS_WAIT_FILE *crfs_wait_file_2nd);

void crfs_wait_file_print(LOG *log, const CRFS_WAIT_FILE *crfs_wait_file);

void crfs_wait_files_print(const UINT32 crfs_md_id, LOG *log);


EC_BOOL crfs_set_state(const UINT32 crfs_md_id, const UINT32 crfs_state);
UINT32  crfs_get_state(const UINT32 crfs_md_id);
EC_BOOL crfs_is_state(const UINT32 crfs_md_id, const UINT32 crfs_state);


/**
*
*  get name node pool of the module
*
**/
CRFSNP_MGR *crfs_get_npp(const UINT32 crfs_md_id);

/**
*
*  get data node of the module
*
**/
CRFSDN *crfs_get_dn(const UINT32 crfs_md_id);

/**
*
*  open name node pool
*
**/
EC_BOOL crfs_open_npp(const UINT32 crfs_md_id, const CSTRING *crfsnp_db_root_dir);

/**
*
*  flush and close name node pool
*
**/
EC_BOOL crfs_close_npp(const UINT32 crfs_md_id);

/**
*
*  check this CRFS is name node pool or not
*
*
**/
EC_BOOL crfs_is_npp(const UINT32 crfs_md_id);

/**
*
*  check this CRFS is data node or not
*
*
**/
EC_BOOL crfs_is_dn(const UINT32 crfs_md_id);

/**
*
*  check this CRFS is data node and namenode or not
*
*
**/
EC_BOOL crfs_is_npp_and_dn(const UINT32 crfs_md_id);

/**
*
*  create name node pool
*
**/
EC_BOOL crfs_create_npp(const UINT32 crfs_md_id,
                             const UINT32 crfsnp_model,
                             const UINT32 crfsnp_max_num,
                             const UINT32 crfsnp_2nd_chash_algo_id,
                             const CSTRING *crfsnp_db_root_dir);

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfs_find_dir(const UINT32 crfs_md_id, const CSTRING *dir_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL crfs_find_file(const UINT32 crfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL crfs_find(const UINT32 crfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL crfs_exists(const UINT32 crfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file
*
**/
EC_BOOL crfs_is_file(const UINT32 crfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfs_is_dir(const UINT32 crfs_md_id, const CSTRING *dir_path);

/**
*
*  reserve space from dn
*
**/
EC_BOOL crfs_reserve_dn(const UINT32 crfs_md_id, const UINT32 data_len, CRFSNP_FNODE *crfsnp_fnode);

/**
*
*  release space to dn
*
**/
EC_BOOL crfs_release_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode);

/**
*
*  write a file
*
**/
EC_BOOL crfs_write(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL crfs_write_no_lock(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

#if 0
/**
*
*  write a file in cache
*
**/
EC_BOOL crfs_write_cache(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
#endif


/**
*
*  read a file
*
**/
EC_BOOL crfs_read(const UINT32 crfs_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  write a file at offset
*
**/
EC_BOOL crfs_write_e(const UINT32 crfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read a file from offset
*
**/
EC_BOOL crfs_read_e(const UINT32 crfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  create data node
*
**/
EC_BOOL crfs_create_dn(const UINT32 crfs_md_id, const CSTRING *root_dir);

/**
*
*  add a disk to data node
*
**/
EC_BOOL crfs_add_disk(const UINT32 crfs_md_id, const UINT32 disk_no);

/**
*
*  delete a disk from data node
*
**/
EC_BOOL crfs_del_disk(const UINT32 crfs_md_id, const UINT32 disk_no);

/**
*
*  mount a disk to data node
*
**/
EC_BOOL crfs_mount_disk(const UINT32 crfs_md_id, const UINT32 disk_no);

/**
*
*  umount a disk from data node
*
**/
EC_BOOL crfs_umount_disk(const UINT32 crfs_md_id, const UINT32 disk_no);

/**
*
*  open data node
*
**/
EC_BOOL crfs_open_dn(const UINT32 crfs_md_id, const CSTRING *root_dir);

/**
*
*  close data node
*
**/
EC_BOOL crfs_close_dn(const UINT32 crfs_md_id);

/**
*
*  export data into data node
*
**/
EC_BOOL crfs_export_dn(const UINT32 crfs_md_id, const CBYTES *cbytes, const CRFSNP_FNODE *crfsnp_fnode);

/**
*
*  write data node
*
**/
EC_BOOL crfs_write_dn(const UINT32 crfs_md_id, const CBYTES *cbytes, CRFSNP_FNODE *crfsnp_fnode);

/**
*
*  write data node in cache
*
**/
EC_BOOL crfs_write_dn_cache(const UINT32 crfs_md_id, const CBYTES *cbytes, CRFSNP_FNODE *crfsnp_fnode);

/**
*
*  read data node
*
**/
EC_BOOL crfs_read_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode, CBYTES *cbytes);

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL crfs_write_e_dn(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL crfs_read_e_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);


/**
*
*  write a fnode to name node
*
**/
EC_BOOL crfs_write_npp(const UINT32 crfs_md_id, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode);

/**
*
*  read a fnode from name node
*
**/
EC_BOOL crfs_read_npp(const UINT32 crfs_md_id, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode);


/**
*
*  update a fnode to name node
*
**/
EC_BOOL crfs_update_npp(const UINT32 crfs_md_id, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode);

/**
*
*  renew a fnode to name node
*
**/
EC_BOOL crfs_renew(const UINT32 crfs_md_id, const CSTRING *file_path);

/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL crfs_renew_http_header(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val);
EC_BOOL crfs_renew_http_headers(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr);
EC_BOOL crfs_renew_http_headers_with_token(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *token_str);

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL crfs_wait_http_header(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready);
EC_BOOL crfs_wait_http_headers(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);

/**
*
*  delete file data from current dn
*
**/
EC_BOOL crfs_delete_dn(const UINT32 crfs_md_id, const UINT32 crfsnp_id, const CRFSNP_ITEM *crfsnp_item);

/**
*
*  delete a file
*
**/
EC_BOOL crfs_delete_file(const UINT32 crfs_md_id, const CSTRING *path);
EC_BOOL crfs_delete_file_no_lock(const UINT32 crfs_md_id, const CSTRING *path);
EC_BOOL crfs_delete_file_wildcard(const UINT32 crfs_md_id, const CSTRING *path);

/**
*
*  delete a dir from all npp and all dn
*
**/
EC_BOOL crfs_delete_dir(const UINT32 crfs_md_id, const CSTRING *path);
EC_BOOL crfs_delete_dir_no_lock(const UINT32 crfs_md_id, const CSTRING *path);
EC_BOOL crfs_delete_dir_wildcard(const UINT32 crfs_md_id, const CSTRING *path);

/**
*
*  delete a file or dir from all npp and all dn
*
**/
EC_BOOL crfs_delete(const UINT32 crfs_md_id, const CSTRING *path, const UINT32 dflag);
EC_BOOL crfs_delete_no_lock(const UINT32 crfs_md_id, const CSTRING *path, const UINT32 dflag);

/**
*
*  update a file
*
**/
EC_BOOL crfs_update(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL crfs_update_no_lock(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL crfs_update_with_token(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *token_str);

/**
*
*  query a file
*
**/
EC_BOOL crfs_qfile(const UINT32 crfs_md_id, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item, CRFSNP_KEY *crsnp_key);

/**
*
*  query a dir
*
**/
EC_BOOL crfs_qdir(const UINT32 crfs_md_id, const CSTRING *dir_path, CRFSNP_ITEM  *crfsnp_item, CRFSNP_KEY *crsnp_key);


/**
*
*  query and list full path of a file or dir of one np
*
**/
EC_BOOL crfs_qlist_path_of_np(const UINT32 crfs_md_id, const CSTRING *file_path, const UINT32 crfsnp_id, CVECTOR  *path_cstr_vec);

/**
*
*  query and list short name of a file or dir of one np
*
**/
EC_BOOL crfs_qlist_seg_of_np(const UINT32 crfs_md_id, const CSTRING *file_path, const UINT32 crfsnp_id, CVECTOR  *seg_cstr_vec);

/**
*
*  query and list full path of a file or dir
*
**/
EC_BOOL crfs_qlist_path(const UINT32 crfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);

/**
*
*  query and list short name of a file or dir
*
**/
EC_BOOL crfs_qlist_seg(const UINT32 crfs_md_id, const CSTRING *file_path, CVECTOR  *seg_cstr_vec);

/**
*
*  query and list full path of a file or  all files under a dir recursively
*  (looks like shell command: tree)
*
**/
EC_BOOL crfs_qlist_tree(const UINT32 crfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);

/**
*
*  query and list full path of a file or all files under a dir of one np
*  (looks like shell command: tree)
*
**/
EC_BOOL crfs_qlist_tree_of_np(const UINT32 crfs_md_id, const UINT32 crfsnp_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec);

/**
*
*  flush name node pool
*
**/
EC_BOOL crfs_flush_npp(const UINT32 crfs_md_id);

/**
*
*  flush data node
*
*
**/
EC_BOOL crfs_flush_dn(const UINT32 crfs_md_id);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL crfs_file_num(const UINT32 crfs_md_id, const CSTRING *path_cstr, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL crfs_file_size(const UINT32 crfs_md_id, const CSTRING *path_cstr, uint64_t *file_size);

/**
*
*  set file expired time to current time
*
**/
EC_BOOL crfs_file_expire(const UINT32 crfs_md_id, const CSTRING *path_cstr);

/**
*
*  get file md5sum of specific file given full path name
*
**/
EC_BOOL crfs_file_md5sum(const UINT32 crfs_md_id, const CSTRING *path_cstr, CMD5_DIGEST *md5sum);

/**
*
*  retire the expired locked files over 120 seconds (twice expire nsec) which are garbage
*
**/
EC_BOOL crfs_locked_file_retire(const UINT32 crfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num);

/**
*
*  try to lock a file in expire_nsec seconds and return the authentication token
*
**/
EC_BOOL crfs_file_lock(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already);

/**
*
*  try to unlock a file with a given authentication token
*
**/
EC_BOOL crfs_file_unlock(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRING *token_str);

/**
*
*  wait file to ready
*
**/
EC_BOOL crfs_file_wait(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready);

EC_BOOL crfs_file_wait_ready(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *data_ready);

/**
*
*  wait file (range) to ready
*
**/
EC_BOOL crfs_file_wait_e(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready);

/**
*
*  notify all waiters
*
**/
EC_BOOL crfs_file_notify(const UINT32 crfs_md_id, const CSTRING *file_path);

/**
*
*  terminate all waiters
*
**/
EC_BOOL crfs_file_terminate(const UINT32 crfs_md_id, const CSTRING *file_path);

/**
*
*  wakeup remote waiter
*
**/
EC_BOOL crfs_wait_file_owner_wakeup (const UINT32 crfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
*  cancel remote waiter (over http)
*
**/
EC_BOOL crfs_wait_file_owner_cancel (const UINT32 crfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL crfs_file_unlock_notify(const UINT32 crfs_md_id, const CSTRING *file_path);

/**
*
*  mkdir in current name node pool
*
**/
EC_BOOL crfs_mkdir(const UINT32 crfs_md_id, const CSTRING *path_cstr);

/**
*
*  search in current name node pool
*
**/
EC_BOOL crfs_search(const UINT32 crfs_md_id, const CSTRING *path_cstr, const UINT32 dflag);

/**
*
*  empty recycle
*
**/
EC_BOOL crfs_recycle(const UINT32 crfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num);

/**
*
*  check file content on data node
*
**/
EC_BOOL crfs_check_file_content(const UINT32 crfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr);

/**
*
*  check file content on data node
*
**/
EC_BOOL crfs_check_file_is(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *file_content);

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL crfs_show_npp(const UINT32 crfs_md_id, LOG *log);

/**
*
*  show name node lru list if it is npp
*
*
**/
EC_BOOL crfs_show_npp_lru_list(const UINT32 crfs_md_id, LOG *log);

/**
*
*  show name node del list if it is npp
*
*
**/
EC_BOOL crfs_show_npp_del_list(const UINT32 crfs_md_id, LOG *log);

/**
*
*  show crfsdn info if it is dn
*
*
**/
EC_BOOL crfs_show_dn(const UINT32 crfs_md_id, LOG *log);

/**
*
*  show all locked files which are used for merge-orig procedure
*
*
**/
void crfs_locked_files_print(const UINT32 crfs_md_id, LOG *log);


/*debug*/
EC_BOOL crfs_show_cached_np(const UINT32 crfs_md_id, LOG *log);

EC_BOOL crfs_show_cached_np_lru_list(const UINT32 crfs_md_id, LOG *log);

EC_BOOL crfs_show_cached_np_del_list(const UINT32 crfs_md_id, LOG *log);

EC_BOOL crfs_show_specific_np(const UINT32 crfs_md_id, const UINT32 crfsnp_id, LOG *log);

EC_BOOL crfs_show_specific_np_lru_list(const UINT32 crfs_md_id, const UINT32 crfsnp_id, LOG *log);

EC_BOOL crfs_show_specific_np_del_list(const UINT32 crfs_md_id, const UINT32 crfsnp_id, LOG *log); 

EC_BOOL crfs_show_path_depth(const UINT32 crfs_md_id, const CSTRING *path, LOG *log);

EC_BOOL crfs_show_path(const UINT32 crfs_md_id, const CSTRING *path, LOG *log);

EC_BOOL crfs_expire_dn(const UINT32 crfs_md_id);

EC_BOOL crfs_retire(const UINT32 crfs_md_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num);

EC_BOOL crfs_write_r(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const UINT32 replica_num);

EC_BOOL crfs_update_r(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const UINT32 replica_num);

EC_BOOL crfs_delete_r(const UINT32 crfs_md_id, const CSTRING *path, const UINT32 dflag, const UINT32 replica_num);

EC_BOOL crfs_renew_r(const UINT32 crfs_md_id, const CSTRING *file_path, const UINT32 replica_num);

#endif /*_CRFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

