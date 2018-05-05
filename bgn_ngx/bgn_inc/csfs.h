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

#ifndef _CSFS_H
#define _CSFS_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "cstrkv.h"

#include "csocket.h"

#include "mod.inc"

#include "csfsnp.h"
#include "csfsdn.h"
#include "csfsnpmgr.h"
#include "csfsmc.h"

#define CSFS_RECYCLE_MAX_NUM                ((UINT32)~0)
#define CSFS_RETIRE_MAX_NUM                 ((UINT32)~0)

#define CSFS_OP_WRITE                       ((UINT8)  1)
#define CSFS_OP_READ                        ((UINT8)  2)
#define CSFS_OP_GET_WORDSIZE                ((UINT8)  3)
#define CSFS_OP_QLIST_PATH                  ((UINT8)  4)
#define CSFS_OP_MKDIR                       ((UINT8)  5)
#define CSFS_OP_EXISTS                      ((UINT8)  6)
#define CSFS_OP_IS_FILE                     ((UINT8)  7)
#define CSFS_OP_IS_DIR                      ((UINT8)  8)
#define CSFS_OP_IS_QFILE                    ((UINT8)  9)
#define CSFS_OP_IS_QDIR                     ((UINT8) 10)


typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    MOD_MGR             *csfsdn_mod_mgr;
    MOD_MGR             *csfsnpp_mod_mgr;

    CRB_TREE             locked_files; /*item is CSFS_LOCKED_FILE*/
    CROUTINE_RWLOCK      locked_files_crwlock;/*RW lock for locked_files tree*/

    CRB_TREE             wait_files;   /*item is CSFS_WAITING_FILE*/

    CSFSDN              *csfsdn;
    CSFSNP_MGR          *csfsnpmgr;/*namespace pool*/

    CSFSMC              *csfsmc;   /*memcache SFS  */

    CROUTINE_RWLOCK      crwlock;
}CSFS_MD;

#define CSFS_MD_TERMINATE_FLAG(csfs_md)    ((csfs_md)->terminate_flag)
#define CSFS_MD_LOCKED_FILES(csfs_md)      (&((csfs_md)->locked_files))
#define CSFS_MD_WAIT_FILES(csfs_md)        (&((csfs_md)->wait_files))
#define CSFS_MD_DN_MOD_MGR(csfs_md)        ((csfs_md)->csfsdn_mod_mgr)
#define CSFS_MD_NPP_MOD_MGR(csfs_md)       ((csfs_md)->csfsnpp_mod_mgr)
#define CSFS_MD_DN(csfs_md)                ((csfs_md)->csfsdn)
#define CSFS_MD_NPP(csfs_md)               ((csfs_md)->csfsnpmgr)
#define CSFS_MD_MCACHE(csfs_md)            ((csfs_md)->csfsmc)
#define CSFS_CRWLOCK(csfs_md)              (&((csfs_md)->crwlock))

#if 0
#define CSFS_INIT_LOCK(csfs_md, location)  (croutine_rwlock_init(CSFS_CRWLOCK(csfs_md), CMUTEX_PROCESS_PRIVATE, location))
#define CSFS_CLEAN_LOCK(csfs_md, location) (croutine_rwlock_clean(CSFS_CRWLOCK(csfs_md), location))

#define CSFS_RDLOCK(csfs_md, location)     (croutine_rwlock_rdlock(CSFS_CRWLOCK(csfs_md), location))
#define CSFS_WRLOCK(csfs_md, location)     (croutine_rwlock_wrlock(CSFS_CRWLOCK(csfs_md), location))
#define CSFS_UNLOCK(csfs_md, location)     (croutine_rwlock_unlock(CSFS_CRWLOCK(csfs_md), location))
#endif

#if 0
#define CSFS_INIT_LOCK(csfs_md, location)  do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFS_INIT_LOCK: CSFS_CRWLOCK %p, at %s:%ld\n", CSFS_CRWLOCK(csfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_init(CSFS_CRWLOCK(csfs_md), CMUTEX_PROCESS_PRIVATE, location);\
}while(0)

#define CSFS_CLEAN_LOCK(csfs_md, location) do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFS_CLEAN_LOCK: CSFS_CRWLOCK %p, at %s:%ld\n", CSFS_CRWLOCK(csfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_clean(CSFS_CRWLOCK(csfs_md), location);\
}while(0)

#define CSFS_RDLOCK(csfs_md, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFS_RDLOCK: CSFS_CRWLOCK %p, at %s:%ld\n", CSFS_CRWLOCK(csfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_rdlock(CSFS_CRWLOCK(csfs_md), location);\
    sys_log(LOGSTDOUT, "[DEBUG] CSFS_RDLOCK: CSFS_CRWLOCK %p, at %s:%ld done\n", CSFS_CRWLOCK(csfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
}while(0)

#define CSFS_WRLOCK(csfs_md, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFS_WRLOCK: CSFS_CRWLOCK %p, at %s:%ld\n", CSFS_CRWLOCK(csfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_wrlock(CSFS_CRWLOCK(csfs_md), location);\
    sys_log(LOGSTDOUT, "[DEBUG] CSFS_WRLOCK: CSFS_CRWLOCK %p, at %s:%ld done\n", CSFS_CRWLOCK(csfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
}while(0)
#define CSFS_UNLOCK(csfs_md, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFS_UNLOCK: CSFS_CRWLOCK %p, at %s:%ld\n", CSFS_CRWLOCK(csfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_unlock(CSFS_CRWLOCK(csfs_md), location);\
}while(0)
#endif

#if 1
#define CSFS_INIT_LOCK(csfs_md, location)  (croutine_rwlock_init(CSFS_CRWLOCK(csfs_md), CMUTEX_PROCESS_PRIVATE, location))
#define CSFS_CLEAN_LOCK(csfs_md, location) (croutine_rwlock_clean(CSFS_CRWLOCK(csfs_md), location))

#define CSFS_RDLOCK(csfs_md, location)     do{}while(0)
#define CSFS_WRLOCK(csfs_md, location)     do{}while(0)
#define CSFS_UNLOCK(csfs_md, location)     do{}while(0)
#endif


#if 1
#define CSFS_LOCKED_FILES_INIT_LOCK(csfs_md, location)  (croutine_rwlock_init(CSFS_LOCKED_FILES_CRWLOCK(csfs_md), CMUTEX_PROCESS_PRIVATE, location))
#define CSFS_LOCKED_FILES_CLEAN_LOCK(csfs_md, location) (croutine_rwlock_clean(CSFS_LOCKED_FILES_CRWLOCK(csfs_md), location))

#if 0
#define CSFS_LOCKED_FILES_RDLOCK(csfs_md, location)     (croutine_rwlock_rdlock(CSFS_LOCKED_FILES_CRWLOCK(csfs_md), location))
#define CSFS_LOCKED_FILES_WRLOCK(csfs_md, location)     (croutine_rwlock_wrlock(CSFS_LOCKED_FILES_CRWLOCK(csfs_md), location))
#define CSFS_LOCKED_FILES_UNLOCK(csfs_md, location)     (croutine_rwlock_unlock(CSFS_LOCKED_FILES_CRWLOCK(csfs_md), location))
#endif
#if 1
#define CSFS_LOCKED_FILES_RDLOCK(csfs_md, location)     do{}while(0)
#define CSFS_LOCKED_FILES_WRLOCK(csfs_md, location)     do{}while(0)
#define CSFS_LOCKED_FILES_UNLOCK(csfs_md, location)     do{}while(0)
#endif

#endif


typedef struct
{
    CSTRING       name; /*file name*/
    CBYTES        token;

    UINT32        expire_nsec;/*lock expire interval in seconds*/
    CTIMET        start_time;
    CTIMET        last_time;

}CSFS_LOCKED_FILE;

#define CSFS_LOCKED_FILE_NAME(csfs_locked_file)                       (&((csfs_locked_file)->name))
#define CSFS_LOCKED_FILE_TOKEN(csfs_locked_file)                      (&((csfs_locked_file)->token))
#define CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file)                ((csfs_locked_file)->expire_nsec)
#define CSFS_LOCKED_FILE_START_TIME(csfs_locked_file)                 (((csfs_locked_file)->start_time))
#define CSFS_LOCKED_FILE_LAST_TIME(csfs_locked_file)                  (((csfs_locked_file)->last_time))

#define CSFS_LOCKED_FILE_NAME_STR(csfs_locked_file)                   (CSTRING_STR(CSFS_LOCKED_FILE_NAME(csfs_locked_file)))
#define CSFS_LOCKED_FILE_NAME_LEN(csfs_locked_file)                   (CSTRING_LEN(CSFS_LOCKED_FILE_NAME(csfs_locked_file)))

#define CSFS_LOCKED_FILE_TOKEN_BUF(csfs_locked_file)                  (CBYTES_BUF(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file)))
#define CSFS_LOCKED_FILE_TOKEN_LEN(csfs_locked_file)                  (CBYTES_LEN(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file)))


typedef struct
{
    CSTRING        name; /*file name*/
    CLIST          owner_list; /*who are waiting it. item is MOD_NODE*/
}CSFS_WAIT_FILE;
#define CSFS_WAIT_FILE_NAME(csfs_wait_file)                       (&((csfs_wait_file)->name))
#define CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file)                 (&((csfs_wait_file)->owner_list))

#define CSFS_WAIT_FILE_NAME_STR(csfs_wait_file)                   (CSTRING_STR(CSFS_WAIT_FILE_NAME(csfs_wait_file)))
#define CSFS_WAIT_FILE_NAME_LEN(csfs_wait_file)                   (CSTRING_LEN(CSFS_WAIT_FILE_NAME(csfs_wait_file)))


/**
*   for test only
*
*   to query the status of CSFS Module
*
**/
void csfs_print_module_status(const UINT32 csfs_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CSFS module
*
*
**/
UINT32 csfs_free_module_static_mem(const UINT32 csfs_md_id);

/**
*
* start CSFS module
*
**/
UINT32 csfs_start(const CSTRING *csfsnp_root_basedir, const CSTRING *crfsdn_root_basedir);

/**
*
* end CSFS module
*
**/
void csfs_end(const UINT32 csfs_md_id);

EC_BOOL csfs_flush(const UINT32 csfs_md_id);

/*------------------------------------------------ interface for file wait ------------------------------------------------*/
CSFS_WAIT_FILE *csfs_wait_file_new();

EC_BOOL csfs_wait_file_init(CSFS_WAIT_FILE *csfs_wait_file);

EC_BOOL csfs_wait_file_clean(CSFS_WAIT_FILE *csfs_wait_file);

EC_BOOL csfs_wait_file_free(CSFS_WAIT_FILE *csfs_wait_file);

EC_BOOL csfs_wait_file_init_0(const UINT32 md_id, CSFS_WAIT_FILE *csfs_wait_file);

EC_BOOL csfs_wait_file_clean_0(const UINT32 md_id, CSFS_WAIT_FILE *csfs_wait_file);

EC_BOOL csfs_wait_file_free_0(const UINT32 md_id, CSFS_WAIT_FILE *csfs_wait_file);

int csfs_wait_file_cmp(const CSFS_WAIT_FILE *csfs_wait_file_1st, const CSFS_WAIT_FILE *csfs_wait_file_2nd);

void csfs_wait_file_print(LOG *log, const CSFS_WAIT_FILE *csfs_wait_file);

void csfs_wait_files_print(const UINT32 csfs_md_id, LOG *log);

EC_BOOL csfs_wait_file_name_set(CSFS_WAIT_FILE *csfs_wait_file, const CSTRING *file_name);

EC_BOOL csfs_wait_file_owner_push(CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tcid);

/**
*
*  wakeup remote waiter (over http)
*
**/
EC_BOOL csfs_wait_file_owner_wakeup (const UINT32 csfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

EC_BOOL csfs_wait_file_owner_notify_over_http (CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tag);

EC_BOOL csfs_wait_file_owner_notify_over_bgn (CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tag);

EC_BOOL csfs_wait_file_owner_notify(CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tag);

EC_BOOL csfs_file_wait(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready);

EC_BOOL csfs_file_wait_e(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready);

/*notify all waiters*/
EC_BOOL csfs_file_notify(const UINT32 csfs_md_id, const CSTRING *file_path);

/*------------------------------------------------ interface for file lock ------------------------------------------------*/
CSFS_LOCKED_FILE *csfs_locked_file_new();

EC_BOOL csfs_locked_file_init(CSFS_LOCKED_FILE *csfs_locked_file);

EC_BOOL csfs_locked_file_clean(CSFS_LOCKED_FILE *csfs_locked_file);

EC_BOOL csfs_locked_file_free(CSFS_LOCKED_FILE *csfs_locked_file);

EC_BOOL csfs_locked_file_init_0(const UINT32 md_id, CSFS_LOCKED_FILE *csfs_locked_file);

EC_BOOL csfs_locked_file_clean_0(const UINT32 md_id, CSFS_LOCKED_FILE *csfs_locked_file);

EC_BOOL csfs_locked_file_free_0(const UINT32 md_id, CSFS_LOCKED_FILE *csfs_locked_file);

int csfs_locked_file_cmp(const CSFS_LOCKED_FILE *csfs_locked_file_1st, const CSFS_LOCKED_FILE *csfs_locked_file_2nd);

void csfs_locked_file_print(LOG *log, const CSFS_LOCKED_FILE *csfs_locked_file);

void csfs_locked_files_print(const UINT32 csfs_md_id, LOG *log);

/*generate token from file_path with time as random*/
EC_BOOL csfs_locked_file_token_gen(CSFS_LOCKED_FILE *csfs_locked_file, const CSTRING *file_name);

EC_BOOL csfs_locked_file_expire_set(CSFS_LOCKED_FILE *csfs_locked_file, const UINT32 expire_nsec);

EC_BOOL csfs_locked_file_is_expire(const CSFS_LOCKED_FILE *csfs_locked_file);

EC_BOOL csfs_locked_file_name_set(CSFS_LOCKED_FILE *csfs_locked_file, const CSTRING *file_name);

/*retire the expired locked files over 120 seconds which are garbage*/
EC_BOOL csfs_locked_file_retire(const UINT32 csfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num);

EC_BOOL csfs_file_lock(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already);

EC_BOOL csfs_file_unlock(const UINT32 csfs_md_id, const CSTRING *file_path, const CSTRING *token_str);

/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL csfs_file_unlock_notify(const UINT32 csfs_md_id, const CSTRING *file_path);

/**
*
*   load file from SFS to memcache
*
**/
EC_BOOL csfs_cache_file(const UINT32 csfs_md_id, const CSTRING *path);


/**
*
* initialize mod mgr of CSFS module
*
**/
UINT32 csfs_set_npp_mod_mgr(const UINT32 csfs_md_id, const MOD_MGR * src_mod_mgr);

UINT32 csfs_set_dn_mod_mgr(const UINT32 csfs_md_id, const MOD_MGR * src_mod_mgr);

/**
*
* get mod mgr of CSFS module
*
**/
MOD_MGR * csfs_get_npp_mod_mgr(const UINT32 csfs_md_id);

MOD_MGR * csfs_get_dn_mod_mgr(const UINT32 csfs_md_id);

CSFSNP_FNODE *csfs_fnode_new(const UINT32 csfs_md_id);

EC_BOOL csfs_fnode_init(const UINT32 csfs_md_id, CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfs_fnode_clean(const UINT32 csfs_md_id, CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfs_fnode_free(const UINT32 csfs_md_id, CSFSNP_FNODE *csfsnp_fnode);


/**
*
*  get name node pool of the module
*
**/
CSFSNP_MGR *csfs_get_npp(const UINT32 csfs_md_id);

/**
*
*  get data node of the module
*
**/
CSFSDN *csfs_get_dn(const UINT32 csfs_md_id);

/**
*
*  open name node pool
*
**/
EC_BOOL csfs_open_npp(const UINT32 csfs_md_id, const CSTRING *csfsnp_db_root_dir);

/**
*
*  flush and close name node pool
*
**/
EC_BOOL csfs_close_npp(const UINT32 csfs_md_id);

/**
*
*  check this CSFS is name node pool or not
*
*
**/
EC_BOOL csfs_is_npp(const UINT32 csfs_md_id);

/**
*
*  check this CSFS is data node or not
*
*
**/
EC_BOOL csfs_is_dn(const UINT32 csfs_md_id);

/**
*
*  check this CSFS is data node and namenode or not
*
*
**/
EC_BOOL csfs_is_npp_and_dn(const UINT32 csfs_md_id);

/**
*
*  create name node pool
*
**/
EC_BOOL csfs_create_npp(const UINT32 csfs_md_id,
                             const UINT32 csfsnp_model,
                             const UINT32 csfsnp_max_num,
                             const CSTRING *csfsnp_db_root_dir);

EC_BOOL csfs_add_npp(const UINT32 csfs_md_id, const UINT32 csfsnpp_tcid, const UINT32 csfsnpp_rank);

EC_BOOL csfs_add_dn(const UINT32 csfs_md_id, const UINT32 csfsdn_tcid, const UINT32 csfsdn_rank);

/**
*
*  check existing of a file
*
**/
EC_BOOL csfs_find_file(const UINT32 csfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL csfs_find(const UINT32 csfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file
*
**/
EC_BOOL csfs_exists(const UINT32 csfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file
*
**/
EC_BOOL csfs_is_file(const UINT32 csfs_md_id, const CSTRING *file_path);

/**
*
*  reserve space from dn
*
**/
EC_BOOL csfs_reserve_dn(const UINT32 csfs_md_id, const UINT32 data_len, CSFSNP_FNODE *csfsnp_fnode);

/**
*
*  write a file
*
**/
EC_BOOL csfs_write(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  read a file
*
**/
EC_BOOL csfs_read(const UINT32 csfs_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL csfs_read_e(const UINT32 csfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  update a file
*  (atomic operation)
*
**/
EC_BOOL csfs_update(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL csfs_update_no_lock(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL csfs_renew_http_header(const UINT32 csfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val);

EC_BOOL csfs_renew_http_headers(const UINT32 csfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr);

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL csfs_wait_http_header(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready);

EC_BOOL csfs_wait_http_headers(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);


/**
*
*  create data node
*
**/
EC_BOOL csfs_create_dn(const UINT32 csfs_md_id, const CSTRING *root_dir);

/**
*
*  add a disk to data node
*
**/
EC_BOOL csfs_add_disk(const UINT32 csfs_md_id, const UINT32 disk_no);

/**
*
*  delete a disk from data node
*
**/
EC_BOOL csfs_del_disk(const UINT32 csfs_md_id, const UINT32 disk_no);

/**
*
*  mount a disk to data node
*
**/
EC_BOOL csfs_mount_disk(const UINT32 csfs_md_id, const UINT32 disk_no);

/**
*
*  umount a disk from data node
*
**/
EC_BOOL csfs_umount_disk(const UINT32 csfs_md_id, const UINT32 disk_no);

/**
*
*  open data node
*
**/
EC_BOOL csfs_open_dn(const UINT32 csfs_md_id, const CSTRING *root_dir);

/**
*
*  close data node
*
**/
EC_BOOL csfs_close_dn(const UINT32 csfs_md_id);

/**
*
*  export data into data node
*
**/
EC_BOOL csfs_export_dn(const UINT32 csfs_md_id, const CBYTES *cbytes, const CSFSNP_FNODE *csfsnp_fnode);

/**
*
*  write data node
*
**/
EC_BOOL csfs_write_dn(const UINT32 csfs_md_id, const CBYTES *cbytes, CSFSNP_FNODE *csfsnp_fnode);


/**
*
*  read data node
*
**/
EC_BOOL csfs_read_dn(const UINT32 csfs_md_id, const CSFSNP_FNODE *csfsnp_fnode, CBYTES *cbytes);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL csfs_read_e_dn(const UINT32 csfs_md_id, const CSFSNP_FNODE *csfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  write a fnode to name node
*
**/
EC_BOOL csfs_write_npp(const UINT32 csfs_md_id, const CSTRING *file_path, const CSFSNP_FNODE *csfsnp_fnode);

/**
*
*  read a fnode from name node
*
**/
EC_BOOL csfs_read_npp(const UINT32 csfs_md_id, const CSTRING *file_path, CSFSNP_FNODE *csfsnp_fnode);

/**
*
*  delete a file from current npp
*
**/
EC_BOOL csfs_delete_npp(const UINT32 csfs_md_id, const CSTRING *path);

/**
*
*  delete file data from current dn
*
**/
EC_BOOL csfs_delete_dn(const UINT32 csfs_md_id, const CSFSNP_FNODE *csfsnp_fnode);

/**
*
*  delete a file from all npp and all dn
*
**/
EC_BOOL csfs_delete(const UINT32 csfs_md_id, const CSTRING *path);

/**
*
*  delete a dir from all npp and all dn
*
*  warning:
*       this interface is only for specific purpose.
*       the file name looks like ${path}/${idx}
*       where ${idx} < ${max_idx}
*
**/
EC_BOOL csfs_delete_dir(const UINT32 csfs_md_id, const CSTRING *dir_path, const UINT32 max_idx);

/**
*
*  query a file
*
**/
EC_BOOL csfs_qfile(const UINT32 csfs_md_id, const CSTRING *file_path, CSFSNP_ITEM  *csfsnp_item);

/**
*
*  flush name node pool
*
**/
EC_BOOL csfs_flush_npp(const UINT32 csfs_md_id);

/**
*
*  flush data node
*
*
**/
EC_BOOL csfs_flush_dn(const UINT32 csfs_md_id);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL csfs_file_num(const UINT32 csfs_md_id, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL csfs_file_size(const UINT32 csfs_md_id, const CSTRING *path_cstr, UINT32 *file_size);

/**
*
*  search in current name node pool
*
**/
EC_BOOL csfs_search(const UINT32 csfs_md_id, const CSTRING *path_cstr);

/**
*
*  check file content on data node
*
**/
EC_BOOL csfs_check_file_content(const UINT32 csfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr);

/**
*
*  check file content on data node
*
**/
EC_BOOL csfs_check_file_is(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *file_content);

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL csfs_show_npp(const UINT32 csfs_md_id, LOG *log);

/**
*
*  show crfsdn info if it is dn
*
*
**/
EC_BOOL csfs_show_dn(const UINT32 csfs_md_id, LOG *log);

/*debug*/
EC_BOOL csfs_show_cached_np(const UINT32 csfs_md_id, LOG *log);

EC_BOOL csfs_show_specific_np(const UINT32 csfs_md_id, const UINT32 csfsnp_id, LOG *log);

/* write memory cache only but Not sfs */
EC_BOOL csfs_write_memc(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/* check whether a file is in memory cache */
EC_BOOL csfs_check_memc(const UINT32 csfs_md_id, const CSTRING *file_path);

/**
*
*  read file from memory cache only but NOT sfs
*
**/
EC_BOOL csfs_read_memc(const UINT32 csfs_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  update file in memory cache only but NOT sfs
*
**/
EC_BOOL csfs_update_memc(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  delete from memory cache only but NOT sfs
*
**/
EC_BOOL csfs_delete_memc(const UINT32 csfs_md_id, const CSTRING *path);

/**
*
*  delete file from memory cache only but NOT sfs
*
**/
EC_BOOL csfs_delete_file_memc(const UINT32 csfs_md_id, const CSTRING *path);


EC_BOOL csfs_retire(const UINT32 csfs_md_id, const UINT32 nsec, const UINT32 expect_retire_num, const UINT32 max_step_per_loop, UINT32 *complete_retire_num);

EC_BOOL csfs_recycle(const UINT32 csfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num);

EC_BOOL csfs_file_expire(const UINT32 csfs_md_id, const CSTRING *path_cstr);

#endif /*_CSFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

