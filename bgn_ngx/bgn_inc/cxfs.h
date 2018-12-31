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

#include "cxfscfg.h"
#include "cxfsnp.h"
#include "cxfsdn.h"
#include "cxfsnpmgr.h"


#define CXFS_MAX_MODI                       ((UINT32)32)

#define CXFS_CHECK_DN_EXPIRE_IN_NSEC        ((uint32_t) 300) /*check once in 5 minutes*/

#define CXFS_MAX_REPLICA_NUM                ((UINT32) 1)

#define CXFS_FILE_PAD_CHAR                  (0x00)
//#define CXFS_FILE_PAD_CHAR                  ((uint8_t)'.')

#define CXFS_MEM_ALIGNMENT                  (1 << 20) /*1MB*/

#define CXFS_RECYCLE_MAX_NUM                ((UINT32)~0)

#define CXFS_ERR_STATE                      ((UINT32)  0)
#define CXFS_WORK_STATE                     ((UINT32)  1)
#define CXFS_SYNC_STATE                     ((UINT32)  2)
#define CXFS_REPLAY_STATE                   ((UINT32)  4)


typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;
    UINT32               state;

    CSTRING              sata_disk_path;
    int                  sata_disk_fd;
    int                  rsvd01;

    CXFSCFG              cxfscfg;

    CRB_TREE             locked_files; /*item is CXFS_LOCKED_FILE*/

    CRB_TREE             wait_files;   /*item is CXFS_WAITING_FILE*/

    CXFSDN              *cxfsdn;
    CXFSNP_MGR          *cxfsnpmgr;    /*namespace pool*/


}CXFS_MD;

#define CXFS_MD_TERMINATE_FLAG(cxfs_md)    ((cxfs_md)->terminate_flag)
#define CXFS_MD_STATE(cxfs_md)             ((cxfs_md)->state)
#define CXFS_MD_SATA_DISK_PATH(cxfs_md)    (&((cxfs_md)->sata_disk_path))
#define CXFS_MD_SATA_DISK_FD(cxfs_md)      ((cxfs_md)->sata_disk_fd)
#define CXFS_MD_CFG(cxfs_md)               (&((cxfs_md)->cxfscfg))
#define CXFS_MD_LOCKED_FILES(cxfs_md)      (&((cxfs_md)->locked_files))
#define CXFS_MD_WAIT_FILES(cxfs_md)        (&((cxfs_md)->wait_files))
#define CXFS_MD_DN(cxfs_md)                ((cxfs_md)->cxfsdn)
#define CXFS_MD_NPP(cxfs_md)               ((cxfs_md)->cxfsnpmgr)


typedef struct
{
    CSTRING       name; /*file name*/
    CBYTES        token;

    UINT32        expire_nsec;/*lock expire interval in seconds*/
    CTIMET        start_time;
    CTIMET        last_time;

}CXFS_LOCKED_FILE;

#define CXFS_LOCKED_FILE_NAME(cxfs_locked_file)                       (&((cxfs_locked_file)->name))
#define CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file)                      (&((cxfs_locked_file)->token))
#define CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file)                ((cxfs_locked_file)->expire_nsec)
#define CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file)                 (((cxfs_locked_file)->start_time))
#define CXFS_LOCKED_FILE_LAST_TIME(cxfs_locked_file)                  (((cxfs_locked_file)->last_time))

#define CXFS_LOCKED_FILE_NAME_STR(cxfs_locked_file)                   (CSTRING_STR(CXFS_LOCKED_FILE_NAME(cxfs_locked_file)))
#define CXFS_LOCKED_FILE_NAME_LEN(cxfs_locked_file)                   (CSTRING_LEN(CXFS_LOCKED_FILE_NAME(cxfs_locked_file)))

#define CXFS_LOCKED_FILE_TOKEN_BUF(cxfs_locked_file)                  (CBYTES_BUF(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file)))
#define CXFS_LOCKED_FILE_TOKEN_LEN(cxfs_locked_file)                  (CBYTES_LEN(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file)))


typedef struct
{
    CSTRING        name; /*file name*/
    CLIST          owner_list; /*who are waiting it. item is MOD_NODE*/
}CXFS_WAIT_FILE;
#define CXFS_WAIT_FILE_NAME(cxfs_wait_file)                       (&((cxfs_wait_file)->name))
#define CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file)                 (&((cxfs_wait_file)->owner_list))

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
UINT32 cxfs_start(const CSTRING *cxfs_root_dir);

/**
*
* end CXFS module
*
**/
void cxfs_end(const UINT32 cxfs_md_id);

/**
*
* flush CXFS
*
**/
EC_BOOL cxfs_flush(const UINT32 cxfs_md_id);

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

EC_BOOL cxfs_wait_file_name_set(CXFS_WAIT_FILE *cxfs_wait_file, const CSTRING *file_name);

EC_BOOL cxfs_wait_file_owner_push(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tcid);

EC_BOOL cxfs_wait_file_owner_notify (CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag);

EC_BOOL cxfs_wait_file_owner_terminate(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag);

int cxfs_wait_file_cmp(const CXFS_WAIT_FILE *cxfs_wait_file_1st, const CXFS_WAIT_FILE *cxfs_wait_file_2nd);

void cxfs_wait_file_print(LOG *log, const CXFS_WAIT_FILE *cxfs_wait_file);

void cxfs_wait_files_print(const UINT32 cxfs_md_id, LOG *log);


EC_BOOL cxfs_set_state(const UINT32 cxfs_md_id, const UINT32 cxfs_state);
UINT32  cxfs_get_state(const UINT32 cxfs_md_id);
EC_BOOL cxfs_is_state(const UINT32 cxfs_md_id, const UINT32 cxfs_state);


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
*  check existing of a file or a dir
*
**/
EC_BOOL cxfs_find(const UINT32 cxfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL cxfs_exists(const UINT32 cxfs_md_id, const CSTRING *path);

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
*  create data node
*
**/
EC_BOOL cxfs_create_dn(const UINT32 cxfs_md_id);

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
*  renew a fnode to name node
*
**/
EC_BOOL cxfs_renew(const UINT32 cxfs_md_id, const CSTRING *file_path);

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
EC_BOOL cxfs_wait_http_header(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready);
EC_BOOL cxfs_wait_http_headers(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);

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
*  delete a file or dir from all npp and all dn
*
**/
EC_BOOL cxfs_delete(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 dflag);
EC_BOOL cxfs_delete_no_lock(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 dflag);

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

/**
*
*  try to lock a file in expire_nsec seconds and return the authentication token
*
**/
EC_BOOL cxfs_file_lock(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already);

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
EC_BOOL cxfs_file_wait(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready);

EC_BOOL cxfs_file_wait_ready(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *data_ready);

/**
*
*  wait file (range) to ready
*
**/
EC_BOOL cxfs_file_wait_e(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready);

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
*  search in current name node pool
*
**/
EC_BOOL cxfs_search(const UINT32 cxfs_md_id, const CSTRING *path_cstr, const UINT32 dflag);

/**
*
*  empty recycle
*
**/
EC_BOOL cxfs_recycle(const UINT32 cxfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num);

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
*  show name node pool info if it is npp
*
*
**/
EC_BOOL cxfs_show_npp(const UINT32 cxfs_md_id, LOG *log);

/**
*
*  show name node lru list if it is npp
*
*
**/
EC_BOOL cxfs_show_npp_lru_list(const UINT32 cxfs_md_id, LOG *log);

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

EC_BOOL cxfs_show_specific_np_lru_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log);

EC_BOOL cxfs_show_specific_np_del_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log);

EC_BOOL cxfs_show_path_depth(const UINT32 cxfs_md_id, const CSTRING *path, LOG *log);

EC_BOOL cxfs_show_path(const UINT32 cxfs_md_id, const CSTRING *path, LOG *log);

EC_BOOL cxfs_retire(const UINT32 cxfs_md_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num);

#endif /*_CXFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

