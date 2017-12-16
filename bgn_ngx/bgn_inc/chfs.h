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

#ifndef _CHFS_H
#define _CHFS_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"
#include "cstrkv.h"

#include "csocket.h"

#include "mod.inc"

#include "chfsnp.h"
#include "crfsdn.h"
#include "chfsnpmgr.h"
#include "chfsmc.h"

#define CHFS_RECYCLE_MAX_NUM                ((UINT32)~0)
#define CHFS_RETIRE_MAX_NUM                 ((UINT32)~0)

#define CHFS_OP_WRITE                       ((UINT8)  1)
#define CHFS_OP_READ                        ((UINT8)  2)
#define CHFS_OP_GET_WORDSIZE                ((UINT8)  3)
#define CHFS_OP_QLIST_PATH                  ((UINT8)  4)
#define CHFS_OP_MKDIR                       ((UINT8)  5)
#define CHFS_OP_EXISTS                      ((UINT8)  6)
#define CHFS_OP_IS_FILE                     ((UINT8)  7)
#define CHFS_OP_IS_DIR                      ((UINT8)  8)
#define CHFS_OP_IS_QFILE                    ((UINT8)  9)
#define CHFS_OP_IS_QDIR                     ((UINT8) 10)

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    MOD_MGR             *chfsdn_mod_mgr;
    MOD_MGR             *chfsnpp_mod_mgr;

    CRB_TREE             locked_files; /*item is CHFS_LOCKED_FILE*/
    CROUTINE_RWLOCK      locked_files_crwlock;/*RW lock for locked_files tree*/

    CRB_TREE             wait_files;   /*item is CHFS_WAITING_FILE*/    

    CRFSDN              *crfsdn;
    CHFSNP_MGR          *chfsnpmgr;/*namespace pool*/   

    CHFSMC              *chfsmc;   /*memcache HFS  */

    CROUTINE_RWLOCK      crwlock;
}CHFS_MD;

#define CHFS_MD_TERMINATE_FLAG(chfs_md)    ((chfs_md)->terminate_flag)
#define CHFS_MD_LOCKED_FILES(chfs_md)      (&((chfs_md)->locked_files))
#define CHFS_MD_WAIT_FILES(chfs_md)        (&((chfs_md)->wait_files))
#define CHFS_MD_DN_MOD_MGR(chfs_md)        ((chfs_md)->chfsdn_mod_mgr)
#define CHFS_MD_NPP_MOD_MGR(chfs_md)       ((chfs_md)->chfsnpp_mod_mgr)
#define CHFS_MD_DN(chfs_md)                ((chfs_md)->crfsdn)
#define CHFS_MD_NPP(chfs_md)               ((chfs_md)->chfsnpmgr)
#define CHFS_MD_MCACHE(chfs_md)            ((chfs_md)->chfsmc)
#define CHFS_CRWLOCK(chfs_md)              (&((chfs_md)->crwlock))

#if 0
#define CHFS_INIT_LOCK(chfs_md, location)  (croutine_rwlock_init(CHFS_CRWLOCK(chfs_md), CMUTEX_PROCESS_PRIVATE, location))
#define CHFS_CLEAN_LOCK(chfs_md, location) (croutine_rwlock_clean(CHFS_CRWLOCK(chfs_md), location))

#define CHFS_RDLOCK(chfs_md, location)     (croutine_rwlock_rdlock(CHFS_CRWLOCK(chfs_md), location))
#define CHFS_WRLOCK(chfs_md, location)     (croutine_rwlock_wrlock(CHFS_CRWLOCK(chfs_md), location))
#define CHFS_UNLOCK(chfs_md, location)     (croutine_rwlock_unlock(CHFS_CRWLOCK(chfs_md), location))
#endif

#if 0
#define CHFS_INIT_LOCK(chfs_md, location)  do{\
    sys_log(LOGSTDOUT, "[DEBUG] CHFS_INIT_LOCK: CHFS_CRWLOCK %p, at %s:%ld\n", CHFS_CRWLOCK(chfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_init(CHFS_CRWLOCK(chfs_md), CMUTEX_PROCESS_PRIVATE, location);\
}while(0)

#define CHFS_CLEAN_LOCK(chfs_md, location) do{\
    sys_log(LOGSTDOUT, "[DEBUG] CHFS_CLEAN_LOCK: CHFS_CRWLOCK %p, at %s:%ld\n", CHFS_CRWLOCK(chfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_clean(CHFS_CRWLOCK(chfs_md), location);\
}while(0)    

#define CHFS_RDLOCK(chfs_md, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CHFS_RDLOCK: CHFS_CRWLOCK %p, at %s:%ld\n", CHFS_CRWLOCK(chfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_rdlock(CHFS_CRWLOCK(chfs_md), location);\
    sys_log(LOGSTDOUT, "[DEBUG] CHFS_RDLOCK: CHFS_CRWLOCK %p, at %s:%ld done\n", CHFS_CRWLOCK(chfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
}while(0)

#define CHFS_WRLOCK(chfs_md, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CHFS_WRLOCK: CHFS_CRWLOCK %p, at %s:%ld\n", CHFS_CRWLOCK(chfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_wrlock(CHFS_CRWLOCK(chfs_md), location);\
    sys_log(LOGSTDOUT, "[DEBUG] CHFS_WRLOCK: CHFS_CRWLOCK %p, at %s:%ld done\n", CHFS_CRWLOCK(chfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
}while(0)
#define CHFS_UNLOCK(chfs_md, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CHFS_UNLOCK: CHFS_CRWLOCK %p, at %s:%ld\n", CHFS_CRWLOCK(chfs_md), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_unlock(CHFS_CRWLOCK(chfs_md), location);\
}while(0)
#endif

#if 1
#define CHFS_INIT_LOCK(chfs_md, location)  (croutine_rwlock_init(CHFS_CRWLOCK(chfs_md), CMUTEX_PROCESS_PRIVATE, location))
#define CHFS_CLEAN_LOCK(chfs_md, location) (croutine_rwlock_clean(CHFS_CRWLOCK(chfs_md), location))

#define CHFS_RDLOCK(chfs_md, location)     do{}while(0)
#define CHFS_WRLOCK(chfs_md, location)     do{}while(0)
#define CHFS_UNLOCK(chfs_md, location)     do{}while(0)
#endif


#if 1
#define CHFS_LOCKED_FILES_INIT_LOCK(chfs_md, location)  (croutine_rwlock_init(CHFS_LOCKED_FILES_CRWLOCK(chfs_md), CMUTEX_PROCESS_PRIVATE, location))
#define CHFS_LOCKED_FILES_CLEAN_LOCK(chfs_md, location) (croutine_rwlock_clean(CHFS_LOCKED_FILES_CRWLOCK(chfs_md), location))

#if 0
#define CHFS_LOCKED_FILES_RDLOCK(chfs_md, location)     (croutine_rwlock_rdlock(CHFS_LOCKED_FILES_CRWLOCK(chfs_md), location))
#define CHFS_LOCKED_FILES_WRLOCK(chfs_md, location)     (croutine_rwlock_wrlock(CHFS_LOCKED_FILES_CRWLOCK(chfs_md), location))
#define CHFS_LOCKED_FILES_UNLOCK(chfs_md, location)     (croutine_rwlock_unlock(CHFS_LOCKED_FILES_CRWLOCK(chfs_md), location))
#endif
#if 1
#define CHFS_LOCKED_FILES_RDLOCK(chfs_md, location)     do{}while(0)
#define CHFS_LOCKED_FILES_WRLOCK(chfs_md, location)     do{}while(0)
#define CHFS_LOCKED_FILES_UNLOCK(chfs_md, location)     do{}while(0)
#endif

#endif


typedef struct
{
    CSTRING       name; /*file name*/
    CBYTES        token;

    UINT32        expire_nsec;/*lock expire interval in seconds*/
    CTIMET        start_time;
    CTIMET        last_time;

}CHFS_LOCKED_FILE;

#define CHFS_LOCKED_FILE_NAME(chfs_locked_file)                       (&((chfs_locked_file)->name))
#define CHFS_LOCKED_FILE_TOKEN(chfs_locked_file)                      (&((chfs_locked_file)->token))
#define CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file)                ((chfs_locked_file)->expire_nsec)
#define CHFS_LOCKED_FILE_START_TIME(chfs_locked_file)                 (((chfs_locked_file)->start_time))
#define CHFS_LOCKED_FILE_LAST_TIME(chfs_locked_file)                  (((chfs_locked_file)->last_time))

#define CHFS_LOCKED_FILE_NAME_STR(chfs_locked_file)                   (CSTRING_STR(CHFS_LOCKED_FILE_NAME(chfs_locked_file)))
#define CHFS_LOCKED_FILE_NAME_LEN(chfs_locked_file)                   (CSTRING_LEN(CHFS_LOCKED_FILE_NAME(chfs_locked_file)))

#define CHFS_LOCKED_FILE_TOKEN_BUF(chfs_locked_file)                  (CBYTES_BUF(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file)))
#define CHFS_LOCKED_FILE_TOKEN_LEN(chfs_locked_file)                  (CBYTES_LEN(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file)))


typedef struct
{
    CSTRING        name; /*file name*/
    CLIST          owner_list; /*who are waiting it. item is MOD_NODE*/
}CHFS_WAIT_FILE;
#define CHFS_WAIT_FILE_NAME(chfs_wait_file)                       (&((chfs_wait_file)->name))
#define CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file)                 (&((chfs_wait_file)->owner_list))

#define CHFS_WAIT_FILE_NAME_STR(chfs_wait_file)                   (CSTRING_STR(CHFS_WAIT_FILE_NAME(chfs_wait_file)))
#define CHFS_WAIT_FILE_NAME_LEN(chfs_wait_file)                   (CSTRING_LEN(CHFS_WAIT_FILE_NAME(chfs_wait_file)))

/**
*   for test only
*
*   to query the status of CHFS Module
*
**/
void chfs_print_module_status(const UINT32 chfs_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CHFS module
*
*
**/
UINT32 chfs_free_module_static_mem(const UINT32 chfs_md_id);

/**
*
* start CHFS module
*
**/
UINT32 chfs_start(const CSTRING *chfsnp_root_basedir, const CSTRING *crfsdn_root_basedir);

/**
*
* end CHFS module
*
**/
void chfs_end(const UINT32 chfs_md_id);

EC_BOOL chfs_flush(const UINT32 chfs_md_id);

/*------------------------------------------------ interface for file wait ------------------------------------------------*/
CHFS_WAIT_FILE *chfs_wait_file_new();

EC_BOOL chfs_wait_file_init(CHFS_WAIT_FILE *chfs_wait_file);

EC_BOOL chfs_wait_file_clean(CHFS_WAIT_FILE *chfs_wait_file);

EC_BOOL chfs_wait_file_free(CHFS_WAIT_FILE *chfs_wait_file);

EC_BOOL chfs_wait_file_init_0(const UINT32 md_id, CHFS_WAIT_FILE *chfs_wait_file);

EC_BOOL chfs_wait_file_clean_0(const UINT32 md_id, CHFS_WAIT_FILE *chfs_wait_file);

EC_BOOL chfs_wait_file_free_0(const UINT32 md_id, CHFS_WAIT_FILE *chfs_wait_file);

int chfs_wait_file_cmp(const CHFS_WAIT_FILE *chfs_wait_file_1st, const CHFS_WAIT_FILE *chfs_wait_file_2nd);

void chfs_wait_file_print(LOG *log, const CHFS_WAIT_FILE *chfs_wait_file);

void chfs_wait_files_print(const UINT32 chfs_md_id, LOG *log);

EC_BOOL chfs_wait_file_name_set(CHFS_WAIT_FILE *chfs_wait_file, const CSTRING *file_name);

EC_BOOL chfs_wait_file_owner_push(CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tcid);

/**
*
*  wakeup remote waiter (over http)
*
**/
EC_BOOL chfs_wait_file_owner_wakeup (const UINT32 chfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

EC_BOOL chfs_wait_file_owner_notify_over_http (CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tag);

EC_BOOL chfs_wait_file_owner_notify_over_bgn (CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tag);

EC_BOOL chfs_wait_file_owner_notify(CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tag);

EC_BOOL chfs_file_wait(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready);

EC_BOOL chfs_file_wait_e(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready);

/*notify all waiters*/
EC_BOOL chfs_file_notify(const UINT32 chfs_md_id, const CSTRING *file_path);

/*------------------------------------------------ interface for file lock ------------------------------------------------*/
CHFS_LOCKED_FILE *chfs_locked_file_new();

EC_BOOL chfs_locked_file_init(CHFS_LOCKED_FILE *chfs_locked_file);

EC_BOOL chfs_locked_file_clean(CHFS_LOCKED_FILE *chfs_locked_file);

EC_BOOL chfs_locked_file_free(CHFS_LOCKED_FILE *chfs_locked_file);

EC_BOOL chfs_locked_file_init_0(const UINT32 md_id, CHFS_LOCKED_FILE *chfs_locked_file);

EC_BOOL chfs_locked_file_clean_0(const UINT32 md_id, CHFS_LOCKED_FILE *chfs_locked_file);

EC_BOOL chfs_locked_file_free_0(const UINT32 md_id, CHFS_LOCKED_FILE *chfs_locked_file);

int chfs_locked_file_cmp(const CHFS_LOCKED_FILE *chfs_locked_file_1st, const CHFS_LOCKED_FILE *chfs_locked_file_2nd);

void chfs_locked_file_print(LOG *log, const CHFS_LOCKED_FILE *chfs_locked_file);

void chfs_locked_files_print(const UINT32 chfs_md_id, LOG *log);

/*generate token from file_path with time as random*/
EC_BOOL chfs_locked_file_token_gen(CHFS_LOCKED_FILE *chfs_locked_file, const CSTRING *file_name);

EC_BOOL chfs_locked_file_expire_set(CHFS_LOCKED_FILE *chfs_locked_file, const UINT32 expire_nsec);

EC_BOOL chfs_locked_file_is_expire(const CHFS_LOCKED_FILE *chfs_locked_file);

EC_BOOL chfs_locked_file_name_set(CHFS_LOCKED_FILE *chfs_locked_file, const CSTRING *file_name);

/*retire the expired locked files over 120 seconds which are garbage*/
EC_BOOL chfs_locked_file_retire(const UINT32 chfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num);

EC_BOOL chfs_file_lock(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already);

EC_BOOL chfs_file_unlock(const UINT32 chfs_md_id, const CSTRING *file_path, const CSTRING *token_str);

/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL chfs_file_unlock_notify(const UINT32 chfs_md_id, const CSTRING *file_path);

/**
*
*   load file from HFS to memcache
*
**/
EC_BOOL chfs_cache_file(const UINT32 chfs_md_id, const CSTRING *path);


/**
*
* initialize mod mgr of CHFS module
*
**/
UINT32 chfs_set_npp_mod_mgr(const UINT32 chfs_md_id, const MOD_MGR * src_mod_mgr);

UINT32 chfs_set_dn_mod_mgr(const UINT32 chfs_md_id, const MOD_MGR * src_mod_mgr);

/**
*
* get mod mgr of CHFS module
*
**/
MOD_MGR * chfs_get_npp_mod_mgr(const UINT32 chfs_md_id);

MOD_MGR * chfs_get_dn_mod_mgr(const UINT32 chfs_md_id);

CHFSNP_FNODE *chfs_fnode_new(const UINT32 chfs_md_id);

EC_BOOL chfs_fnode_init(const UINT32 chfs_md_id, CHFSNP_FNODE *chfsnp_fnode);

EC_BOOL chfs_fnode_clean(const UINT32 chfs_md_id, CHFSNP_FNODE *chfsnp_fnode);

EC_BOOL chfs_fnode_free(const UINT32 chfs_md_id, CHFSNP_FNODE *chfsnp_fnode);


/**
*
*  get name node pool of the module
*
**/
CHFSNP_MGR *chfs_get_npp(const UINT32 chfs_md_id);

/**
*
*  get data node of the module
*
**/
CRFSDN *chfs_get_dn(const UINT32 chfs_md_id);

/**
*
*  open name node pool
*
**/
EC_BOOL chfs_open_npp(const UINT32 chfs_md_id, const CSTRING *chfsnp_db_root_dir);

/**
*
*  flush and close name node pool
*
**/
EC_BOOL chfs_close_npp(const UINT32 chfs_md_id);

/**
*
*  check this CHFS is name node pool or not
*
*
**/
EC_BOOL chfs_is_npp(const UINT32 chfs_md_id);

/**
*
*  check this CHFS is data node or not
*
*
**/
EC_BOOL chfs_is_dn(const UINT32 chfs_md_id);

/**
*
*  check this CHFS is data node and namenode or not
*
*
**/
EC_BOOL chfs_is_npp_and_dn(const UINT32 chfs_md_id);

/**
*
*  create name node pool
*
**/
EC_BOOL chfs_create_npp(const UINT32 chfs_md_id, 
                             const UINT32 chfsnp_model, 
                             const UINT32 chfsnp_max_num, 
                             const CSTRING *chfsnp_db_root_dir);

EC_BOOL chfs_add_npp(const UINT32 chfs_md_id, const UINT32 chfsnpp_tcid, const UINT32 chfsnpp_rank);

EC_BOOL chfs_add_dn(const UINT32 chfs_md_id, const UINT32 chfsdn_tcid, const UINT32 chfsdn_rank);

/**
*
*  check existing of a file
*
**/
EC_BOOL chfs_find_file(const UINT32 chfs_md_id, const CSTRING *file_path);

/**
*
*  check existing of a file
*
**/
EC_BOOL chfs_find(const UINT32 chfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file
*
**/
EC_BOOL chfs_exists(const UINT32 chfs_md_id, const CSTRING *path);

/**
*
*  check existing of a file
*
**/
EC_BOOL chfs_is_file(const UINT32 chfs_md_id, const CSTRING *file_path);

/**
*
*  reserve space from dn
*
**/
EC_BOOL chfs_reserve_dn(const UINT32 chfs_md_id, const UINT32 data_len, CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  release space to dn
*
**/
EC_BOOL chfs_release_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  write a file
*
**/
EC_BOOL chfs_write(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  read a file
*
**/
EC_BOOL chfs_read(const UINT32 chfs_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file) 
*
**/
EC_BOOL chfs_read_e(const UINT32 chfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  update a file 
*  (atomic operation)
*
**/
EC_BOOL chfs_update(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
EC_BOOL chfs_update_no_lock(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);
/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL chfs_renew_http_header(const UINT32 chfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val);

EC_BOOL chfs_renew_http_headers(const UINT32 chfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr);

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL chfs_wait_http_header(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready);

EC_BOOL chfs_wait_http_headers(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);


/**
*
*  create data node
*
**/
EC_BOOL chfs_create_dn(const UINT32 chfs_md_id, const CSTRING *root_dir);

/**
*
*  add a disk to data node
*
**/
EC_BOOL chfs_add_disk(const UINT32 chfs_md_id, const UINT32 disk_no);

/**
*
*  delete a disk from data node
*
**/
EC_BOOL chfs_del_disk(const UINT32 chfs_md_id, const UINT32 disk_no);

/**
*
*  mount a disk to data node
*
**/
EC_BOOL chfs_mount_disk(const UINT32 chfs_md_id, const UINT32 disk_no);

/**
*
*  umount a disk from data node
*
**/
EC_BOOL chfs_umount_disk(const UINT32 chfs_md_id, const UINT32 disk_no);

/**
*
*  open data node
*
**/
EC_BOOL chfs_open_dn(const UINT32 chfs_md_id, const CSTRING *root_dir);

/**
*
*  close data node
*
**/
EC_BOOL chfs_close_dn(const UINT32 chfs_md_id);

/**
*
*  export data into data node
*
**/
EC_BOOL chfs_export_dn(const UINT32 chfs_md_id, const CBYTES *cbytes, const CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  write data node
*
**/
EC_BOOL chfs_write_dn(const UINT32 chfs_md_id, const CBYTES *cbytes, CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  write data node in cache
*
**/
EC_BOOL chfs_write_dn_cache(const UINT32 chfs_md_id, const CBYTES *cbytes, CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  read data node
*
**/
EC_BOOL chfs_read_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode, CBYTES *cbytes);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL chfs_read_e_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  write a fnode to name node
*
**/
EC_BOOL chfs_write_npp(const UINT32 chfs_md_id, const CSTRING *file_path, const CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  read a fnode from name node
*
**/
EC_BOOL chfs_read_npp(const UINT32 chfs_md_id, const CSTRING *file_path, CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  delete a file from current npp
*
**/
EC_BOOL chfs_delete_npp(const UINT32 chfs_md_id, const CSTRING *path);

/**
*
*  delete file data from current dn
*
**/
EC_BOOL chfs_delete_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode);

/**
*
*  delete a file from all npp and all dn
*
**/
EC_BOOL chfs_delete(const UINT32 chfs_md_id, const CSTRING *path);

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
EC_BOOL chfs_delete_dir(const UINT32 chfs_md_id, const CSTRING *dir_path, const UINT32 max_idx);

/**
*
*  query a file
*
**/
EC_BOOL chfs_qfile(const UINT32 chfs_md_id, const CSTRING *file_path, CHFSNP_ITEM  *chfsnp_item);

/**
*
*  flush name node pool
*
**/
EC_BOOL chfs_flush_npp(const UINT32 chfs_md_id);

/**
*
*  flush data node
*
*
**/
EC_BOOL chfs_flush_dn(const UINT32 chfs_md_id);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL chfs_file_num(const UINT32 chfs_md_id, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL chfs_file_size(const UINT32 chfs_md_id, const CSTRING *path_cstr, UINT32 *file_size);

/**
*
*  search in current name node pool
*
**/
EC_BOOL chfs_search(const UINT32 chfs_md_id, const CSTRING *path_cstr);

/**
*
*  check file content on data node
*
**/
EC_BOOL chfs_check_file_content(const UINT32 chfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr);

/**
*
*  check file content on data node
*
**/
EC_BOOL chfs_check_file_is(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *file_content);

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL chfs_show_npp(const UINT32 chfs_md_id, LOG *log);

/**
*
*  show crfsdn info if it is dn
*
*
**/
EC_BOOL chfs_show_dn(const UINT32 chfs_md_id, LOG *log);

/*debug*/
EC_BOOL chfs_show_cached_np(const UINT32 chfs_md_id, LOG *log);

EC_BOOL chfs_show_specific_np(const UINT32 chfs_md_id, const UINT32 chfsnp_id, LOG *log);

/* write memory cache only but Not hfs */
EC_BOOL chfs_write_memc(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/* check whether a file is in memory cache */
EC_BOOL chfs_check_memc(const UINT32 chfs_md_id, const CSTRING *file_path);

/**
*
*  read file from memory cache only but NOT hfs
*
**/
EC_BOOL chfs_read_memc(const UINT32 chfs_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  update file in memory cache only but NOT hfs
*
**/
EC_BOOL chfs_update_memc(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  delete from memory cache only but NOT hfs
*
**/
EC_BOOL chfs_delete_memc(const UINT32 chfs_md_id, const CSTRING *path);

/**
*
*  delete file from memory cache only but NOT hfs
*
**/
EC_BOOL chfs_delete_file_memc(const UINT32 chfs_md_id, const CSTRING *path);


EC_BOOL chfs_retire(const UINT32 chfs_md_id, const UINT32 nsec, const UINT32 expect_retire_num, const UINT32 max_step_per_loop, UINT32 *complete_retire_num);

EC_BOOL chfs_recycle(const UINT32 chfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num);

EC_BOOL chfs_file_expire(const UINT32 chfs_md_id, const CSTRING *path_cstr);

#endif /*_CHFS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

