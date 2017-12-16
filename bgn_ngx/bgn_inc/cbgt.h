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

#ifndef _CBGT_H
#define _CBGT_H

#include "type.h"
#include "mm.h"
#include "log.h"
#include "mod.inc"

#include "clist.h"
#include "cbytes.h"
#include "cbitmap.h"

#include "db_internal.h"
#include "cbtree.h"
#include "croutine.inc"

#define CBGT_MIN_NP_NUM             ((UINT32) 1)
#define CBGT_REPLICA_NUM            ((UINT32) 1)

#define CBGT_AGING_INTERVAL_NSEC    (5 * 60) /*5 mins*/

#define CBGT_REG_BUFF_MAX_SIZE      ((UINT32)64)

#define CBGT_ERR_TABLE_ID           ((UINT32)-1)
#define CBGT_ROOT_TABLE_ID          ((UINT32)10)

/*cbgt session name*/
#define CBGT_SESSION_NAME           ((UINT8 *)"hsbgt")

/*bitmap of open flags*/
#define CBGT_O_UNDEF                ((UINT32) 0)
#define CBGT_O_RDWR                 ((UINT32) 1)
#define CBGT_O_CREAT                ((UINT32) 2)

/*CBGT type*/
#define CBGT_TYPE_UNDEF                 ((UINT32) 0x00)
#define CBGT_TYPE_ROOT_SERVER           ((UINT32) 0x01)
#define CBGT_TYPE_META_SERVER           ((UINT32) 0x02)
#define CBGT_TYPE_COLF_SERVER           ((UINT32) 0x04)
#define CBGT_TYPE_USER_SERVER           ((UINT32) 0x08)
#define CBGT_TYPE_USER_CLIENT           ((UINT32) 0x10)
#define CBGT_TYPE_TABLE_SERVER          ((UINT32) 0x0F)/*cover root/meta/colf/user server*/

#define CBGT_INSERT_TRY_TIMES           (2)
#define CBGT_FETCH_TRY_TIMES            (2)
#define CBGT_DELETE_TRY_TIMES           (2)
#define CBGT_SELECT_TRY_TIMES           (1)

/*select from cached/all table*/
#define CBGT_SELECT_FROM_CACHED_TABLE   ((UINT32)1)
#define CBGT_SELECT_FROM_ALL_TABLE      ((UINT32)2)

//#define CBGT_DATA_MAX_SIZE              (64 * 1024) /*64KB*/
#define CBGT_TABLE_MAX_NUM              (128 * 1024 * 8) /*1 048 576 bits*/
//#define CBGT_TABLE_MAX_NUM              (32) /*1 048 576 bits*/
#define CBGT_RECORD_FILE_SIZE           (64)

#if (64 == WORDSIZE)
#define CBGT_CDFS_FILE_MAX_SIZE         ((UINT32)(63 * 1024 * 1024)) /*63M*/
#define CBGT_SPLIT_TRIGGER_TLEN         ((UINT32)(128 * 1024 * 1024)) /*64M*/
#endif/*(64 == WORDSIZE)*/

#if (32 == WORDSIZE)
#define CBGT_CDFS_FILE_MAX_SIZE         ((UINT32)(1 * 1024 * 1024 - 4 * 1024))  /*1M - 4K*/
#define CBGT_SPLIT_TRIGGER_TLEN         ((UINT32)(1 * 1024 * 1024))/*1M*/

#endif/*(32 == WORDSIZE)*/

#define CBGT_FILE_MIN_SIZE              ((UINT32)(64 * 1024))        /*64K*/

/*safe gap size*/
#define CBGT_RAW_DATA_FILE_SAFE_GAP     ((uint32_t)(64 * 1024))/*64KB*/
#define CBGT_RAW_IDX_FILE_SAFE_GAP      ((uint32_t)(16 * 1024))/*16KB*/

#define CBGT_ONCE_MERGE_TABLE_NUM       ((UINT32) 2)

#define CBGT_WORD_TO_UINT32(val)        ((val) & 0xFFFFFFFF)
#define CBGT_WORD_TO_UINT16(val)        ((val) & 0xFFFF)
#define CBGT_WORD_TO_UINT8(val)         ((val) & 0xFF)

typedef struct
{
    UINT32      table_id;
    MOD_NODE    mod_node;
    CBYTES      row_key;
}CBGT_REG;

#define CBGT_REG_TABLE_ID(cbgt_reg)         ((cbgt_reg)->table_id)
#define CBGT_REG_MOD_NODE(cbgt_reg)         (&((cbgt_reg)->mod_node))
#define CBGT_REG_ROW_KEY(cbgt_reg)          (&((cbgt_reg)->row_key))

#define CBGT_CRWLOCK_SWITCH     (SWITCH_ON)

typedef struct
{
    CSTRING  file_name;      /* file name of the database   */
    int      fd;
    int      rsvd;
    UINT32   table_id;      /* table id of the database    */
    UINT32   cdfs_md_id;    /* when CDFS used              */
    CBTREE  *cbtree;        /* main B+Tree                 */
    UINT32   type;          /* table server type           */

#if (SWITCH_ON == CBGT_CRWLOCK_SWITCH)
    CROUTINE_RWLOCK crwlock;
#endif/*(SWITCH_ON == GDB_CRWLOCK_SWITCH)*/

#if (SWITCH_OFF == CBGT_CRWLOCK_SWITCH)
    CROUTINE_MUTEX   cmutex;
#endif/*(SWITCH_OFF == GDB_CRWLOCK_SWITCH)*/
}CBGT_GDB;

#define CBGT_GDB_FNAME(gdb)                      (&((gdb)->file_name))
#define CBGT_GDB_FNAME_STR(gdb)                  (cstring_get_str(CBGT_GDB_FNAME(gdb)))
#define CBGT_GDB_FD(gdb)                         ((gdb)->fd)
#define CBGT_GDB_TABLE_ID(gdb)                   ((gdb)->table_id)
#define CBGT_GDB_CDFS_MD_ID(gdb)                 ((gdb)->cdfs_md_id)
#define CBGT_GDB_CBTREE(gdb)                     ((gdb)->cbtree)
#define CBGT_GDB_TYPE(gdb)                       ((gdb)->type)

#if (SWITCH_ON == CBGT_CRWLOCK_SWITCH)
#define CBGT_GDB_CRWLOCK(gdb)                    (&((gdb)->crwlock))
#define CBGT_GDB_CRWLOCK_INIT(gdb, location)     (croutine_rwlock_init(CBGT_GDB_CRWLOCK(gdb), CMUTEX_PROCESS_PRIVATE, location))
#define CBGT_GDB_CRWLOCK_CLEAN(gdb, location)    (croutine_rwlock_clean(CBGT_GDB_CRWLOCK(gdb), location))
#define CBGT_GDB_CRWLOCK_RDLOCK(gdb, location)   (croutine_rwlock_rdlock(CBGT_GDB_CRWLOCK(gdb), location))
#define CBGT_GDB_CRWLOCK_WRLOCK(gdb, location)   (croutine_rwlock_wrlock(CBGT_GDB_CRWLOCK(gdb), location))
#define CBGT_GDB_CRWLOCK_UNLOCK(gdb, location)   (croutine_rwlock_unlock(CBGT_GDB_CRWLOCK(gdb), location))
#endif/*(SWITCH_ON == CBGT_CRWLOCK_SWITCH)*/

#if (SWITCH_OFF == CBGT_CRWLOCK_SWITCH)
#define CBGT_GDB_CRWLOCK(gdb)                    (&((gdb)->cmutex))
#define CBGT_GDB_CRWLOCK_INIT(gdb, location)     (croutine_mutex_init(CBGT_GDB_CRWLOCK(gdb), CMUTEX_PROCESS_PRIVATE, location))
#define CBGT_GDB_CRWLOCK_CLEAN(gdb, location)    (croutine_mutex_clean(CBGT_GDB_CRWLOCK(gdb), location))
#define CBGT_GDB_CRWLOCK_RDLOCK(gdb, location)   (croutine_mutex_lock(CBGT_GDB_CRWLOCK(gdb), location))
#define CBGT_GDB_CRWLOCK_WRLOCK(gdb, location)   (croutine_mutex_lock(CBGT_GDB_CRWLOCK(gdb), location))
#define CBGT_GDB_CRWLOCK_UNLOCK(gdb, location)   (croutine_mutex_unlock(CBGT_GDB_CRWLOCK(gdb), location))
#endif/*(SWITCH_OFF == CBGT_CRWLOCK_SWITCH)*/

typedef struct
{
    /* used counter >= 0 */
    UINT32      usedcounter;

    MOD_MGR    *mod_mgr;

    CBGT_GDB   *gdb;

    CBITMAP    *table_id_pool;

    UINT32      type;
    UINT32      table_id;

    MOD_NODE   *parent;
    MOD_NODE   *root_mod;

    UINT32      root_table_id;

    UINT32      cdfs_md_id;

    CSTRING    *csession_name;
    UINT32      csession_md_id;

    CSTRING    *root_path;
    CBYTES     *table_name;

    CTIMET      last_access_time;
    CROUTINE_MUTEX      last_access_time_cmutex;

#if (SWITCH_ON == CBGT_CRWLOCK_SWITCH)
    CROUTINE_RWLOCK     table_crwlock;
#endif/*(SWITCH_ON == CBGT_CRWLOCK_SWITCH)*/

#if (SWITCH_OFF == CBGT_CRWLOCK_SWITCH)
    CROUTINE_MUTEX      table_crwlock;
#endif/*(SWITCH_OFF == CBGT_CRWLOCK_SWITCH)*/
    CROUTINE_MUTEX      table_id_pool_cmutex;
}CBGT_MD;

#define CBGT_MD_MOD_MGR(cbgt_md)                 ((cbgt_md)->mod_mgr)
#define CBGT_MD_GDB(cbgt_md)                     ((cbgt_md)->gdb)
#define CBGT_MD_TABLE_ID_POOL(cbgt_md)           ((cbgt_md)->table_id_pool)
#define CBGT_MD_TYPE(cbgt_md)                    ((cbgt_md)->type)
#define CBGT_MD_TABLE_ID(cbgt_md)                ((cbgt_md)->table_id)
#define CBGT_MD_PARENT_MOD(cbgt_md)              ((cbgt_md)->parent)
#define CBGT_MD_ROOT_MOD(cbgt_md)                ((cbgt_md)->root_mod)
#define CBGT_MD_ROOT_TABLE(cbgt_md)              ((cbgt_md)->root_table_id)
#define CBGT_MD_CDFS_MD_ID(cbgt_md)              ((cbgt_md)->cdfs_md_id)
#define CBGT_MD_CSESSION_NAME(cbgt_md)           ((cbgt_md)->csession_name)
#define CBGT_MD_CSESSION_MD_ID(cbgt_md)          ((cbgt_md)->csession_md_id)
#define CBGT_MD_ROOT_PATH(cbgt_md)               ((cbgt_md)->root_path)
#define CBGT_MD_ROOT_PATH_STR(cbgt_md)           (cstring_get_str(CBGT_MD_ROOT_PATH(cbgt_md)))
#define CBGT_MD_TABLE_NAME(cbgt_md)              ((cbgt_md)->table_name)
#define CBGT_MD_TABLE_CRWLOCK(cbgt_md)           (&((cbgt_md)->table_crwlock))
#define CBGT_MD_TABLE_ID_POOL_CMUTEX(cbgt_md)    (&((cbgt_md)->table_id_pool_cmutex))
#define CBGT_MD_LAST_ACCESS_TIME(cbgt_md)        (((cbgt_md)->last_access_time))
#define CBGT_MD_LAST_ACCESS_TIME_CMUTEX(cbgt_md) (&((cbgt_md)->last_access_time_cmutex))

#define CBGT_MD_INIT_LAST_ACCESS_TIME_CMUTEX(cbgt_md, location)     (croutine_mutex_init(CBGT_MD_LAST_ACCESS_TIME_CMUTEX(cbgt_md), CMUTEX_PROCESS_PRIVATE, location))
#define CBGT_MD_CLEAN_LAST_ACCESS_TIME_CMUTEX(cbgt_md, location)    (croutine_mutex_clean(CBGT_MD_LAST_ACCESS_TIME_CMUTEX(cbgt_md), location))
#define CBGT_MD_CMUTEX_LAST_ACCESS_TIME_LOCK(cbgt_md, location)     (croutine_mutex_lock(CBGT_MD_LAST_ACCESS_TIME_CMUTEX(cbgt_md), location))
#define CBGT_MD_CMUTEX_LAST_ACCESS_TIME_UNLOCK(cbgt_md, location)   (croutine_mutex_unlock(CBGT_MD_LAST_ACCESS_TIME_CMUTEX(cbgt_md), location))


#define CBGT_MD_WAS_ACCESS(cbgt_md, location)              do { \
    CBGT_MD_CMUTEX_LAST_ACCESS_TIME_LOCK(cbgt_md, location);    \
    CTIMET_GET(CBGT_MD_LAST_ACCESS_TIME(cbgt_md));              \
    CBGT_MD_CMUTEX_LAST_ACCESS_TIME_UNLOCK(cbgt_md, location);  \
}while(0)

#if (SWITCH_ON == CBGT_CRWLOCK_SWITCH)
#if 0
#define CBGT_MD_INIT_TABLE_CRWLOCK(cbgt_md, location)            (croutine_rwlock_init(CBGT_MD_TABLE_CRWLOCK(cbgt_md), CRWLOCK_PROCESS_PRIVATE, location))
#define CBGT_MD_CLEAN_TABLE_CRWLOCK(cbgt_md, location)           (croutine_rwlock_clean(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#define CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, location)          (croutine_rwlock_rdlock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#define CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, location)          (croutine_rwlock_wrlock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#define CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, location)          (croutine_rwlock_unlock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#endif
#define CBGT_MD_INIT_TABLE_CRWLOCK(cbgt_md, location)            do{\
    croutine_rwlock_init(CBGT_MD_TABLE_CRWLOCK(cbgt_md), CRWLOCK_PROCESS_PRIVATE, location);\
    /*sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: init at %s:%d\n", CBGT_MD_TABLE_CRWLOCK(cbgt_md), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));*/\
}while(0)

#define CBGT_MD_CLEAN_TABLE_CRWLOCK(cbgt_md, location)           do{\
    croutine_rwlock_clean(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location);\
    /*sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: clean at %s:%d\n", CBGT_MD_TABLE_CRWLOCK(cbgt_md), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));*/\
}while(0)

#define CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, location)          do{\
    croutine_rwlock_rdlock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location);\
    /*sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: RD lock at %s:%d\n", CBGT_MD_TABLE_CRWLOCK(cbgt_md), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));*/\
}while(0)

#define CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, location)          do{\
    croutine_rwlock_wrlock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location);\
    /*sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: WR lock at %s:%d\n", CBGT_MD_TABLE_CRWLOCK(cbgt_md), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));*/\
}while(0)

#define CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, location)          do{\
    croutine_rwlock_unlock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location);\
    /*sys_log(LOGSTDNULL, "[DEBUG] CRWLOCK %lx: unlock at %s:%d\n", CBGT_MD_TABLE_CRWLOCK(cbgt_md), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));*/\
}while(0)

#if 1
#endif
#endif/*(SWITCH_ON == CBGT_CRWLOCK_SWITCH)*/

#if (SWITCH_OFF == CBGT_CRWLOCK_SWITCH)
#define CBGT_MD_INIT_TABLE_CRWLOCK(cbgt_md, location)            (croutine_mutex_init(CBGT_MD_TABLE_CRWLOCK(cbgt_md), CMUTEX_PROCESS_PRIVATE, location))
#define CBGT_MD_CLEAN_TABLE_CRWLOCK(cbgt_md, location)           (croutine_mutex_clean(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#define CBGT_MD_CRWLOCK_TABLE_RDLOCK(cbgt_md, location)          (croutine_mutex_lock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#define CBGT_MD_CRWLOCK_TABLE_WRLOCK(cbgt_md, location)          (croutine_mutex_lock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#define CBGT_MD_CRWLOCK_TABLE_UNLOCK(cbgt_md, location)          (croutine_mutex_unlock(CBGT_MD_TABLE_CRWLOCK(cbgt_md), location))
#endif/*(SWITCH_OFF == CBGT_CRWLOCK_SWITCH)*/

#define CBGT_MD_INIT_TABLE_ID_POOL_CMUTEX(cbgt_md, location)     (croutine_mutex_init(CBGT_MD_TABLE_ID_POOL_CMUTEX(cbgt_md), CMUTEX_PROCESS_PRIVATE, location))
#define CBGT_MD_CLEAN_TABLE_ID_POOL_CMUTEX(cbgt_md, location)    (croutine_mutex_clean(CBGT_MD_TABLE_ID_POOL_CMUTEX(cbgt_md), location))
#define CBGT_MD_CMUTEX_TABLE_ID_POOL_LOCK(cbgt_md, location)     (croutine_mutex_lock(CBGT_MD_TABLE_ID_POOL_CMUTEX(cbgt_md), location))
#define CBGT_MD_CMUTEX_TABLE_ID_POOL_UNLOCK(cbgt_md, location)   (croutine_mutex_unlock(CBGT_MD_TABLE_ID_POOL_CMUTEX(cbgt_md), location))


/**
key-value structer:

Key Len (2B) | Value Len (4B) | TimeStamp (4B or 8 B) | Row Len (2B) | Column Family Len (1B) | Key Type (1B) | Row | Column Family | Column Qualifier | Value
                              |                                                                                                                        |
                              | <-------------------------------------------------------  Key  ------------------------------------------------------->|

**/
EC_BOOL __cbgt_mod_node_is_valid(const UINT32 cbgt_md_id, const MOD_NODE *mod_node);
EC_BOOL __cbgt_flush_root_record_file(const UINT32 cbgt_md_id, const CSTRING *root_path, const UINT32 root_table_id, const MOD_NODE *root_mod_node);
EC_BOOL __cbgt_load_root_record_file(const UINT32 cbgt_md_id, const CSTRING *root_path, UINT32 *root_table_id, MOD_NODE *root_mod_node);

/**
*   for test only
*
*   to query the status of CBGT Module
*
**/
void cbgt_print_module_status(const UINT32 cbgt_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CBGT module
*
*
**/
UINT32 cbgt_free_module_static_mem(const UINT32 cbgt_md_id);

/**
*
* start CBGT module
*
**/
UINT32 cbgt_start(const UINT32 server_type,
                    const UINT32 table_id,
                    const CBYTES *table_name,
                    const MOD_NODE *parent,
                    const CSTRING *root_path,
                    const UINT32 open_flags);

/**
*
* end CBGT module
*
**/
void cbgt_end(const UINT32 cbgt_md_id);

EC_BOOL cbgt_aging_handle(const UINT32 cbgt_md_id);

UINT32 cbgt_set_mod_mgr(const UINT32 cbgt_md_id, const MOD_MGR * src_mod_mgr);

MOD_MGR * cbgt_get_mod_mgr(const UINT32 cbgt_md_id);

void    cbgt_close_mod_mgr(const UINT32 cbgt_md_id);

CBGT_GDB *cbgt_gdb_new();
EC_BOOL   cbgt_gdb_init(CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_clean(CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_free(CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_load(CBGT_GDB *gdb);
CBGT_GDB *cbgt_gdb_open(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const int flags, const UINT32 cbtree_type);
CBGT_GDB *cbgt_gdb_create(const uint8_t *root_path, const word_t table_id, const word_t cdfs_md_id, const UINT32 cbtree_type);
EC_BOOL   cbgt_gdb_flush(CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_close(CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_unlink(CBGT_GDB *gdb, const CSTRING *root_path, const UINT32 table_id);
EC_BOOL   cbgt_gdb_close_without_flush(CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_del_key(CBGT_GDB *gdb, const uint8_t *key);
EC_BOOL   cbgt_gdb_insert_key(CBGT_GDB *gdb, const uint8_t *key);
EC_BOOL   cbgt_gdb_update_val(CBGT_GDB *gdb, const uint8_t *key, const uint8_t *val, const uint32_t vlen);
EC_BOOL   cbgt_gdb_is_full(const CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_is_empty(const CBGT_GDB *gdb);
EC_BOOL   cbgt_gdb_get_last_key(const CBGT_GDB *gdb, uint8_t **last_key);
EC_BOOL   cbgt_gdb_split(CBGT_GDB *old_gdb, CBGT_GDB *left_gdb);
EC_BOOL   cbgt_gdb_merge(CBGT_GDB *old_gdb, CBGT_GDB *left_gdb);
CBTREE_KEY *cbgt_gdb_search_key(const CBGT_GDB *gdb, const uint8_t *key);
void cbgt_gdb_traversal(LOG *log, const CBGT_GDB *gdb, CBTREE_KEY_PRINTER key_printer);

void    cbgt_print_status(const UINT32 cbgt_md_id, LOG *log);

EC_BOOL cbgt_is_root_server(const UINT32 cbgt_md_id);

EC_BOOL cbgt_is_meta_server(const UINT32 cbgt_md_id);

EC_BOOL cbgt_is_colf_server(const UINT32 cbgt_md_id);

EC_BOOL cbgt_is_user_server(const UINT32 cbgt_md_id);

EC_BOOL cbgt_is_user_client(const UINT32 cbgt_md_id);

/*check table_id exist on remote mod_node or not*/
EC_BOOL cbgt_check_exist(const UINT32 cbgt_md_id, const UINT32 table_id, const MOD_NODE *mod_node);

/*when CBGT module not exist, return CBGT_ERR_TABLE_ID*/
UINT32  cbgt_fetch_table_id(const UINT32 cbgt_md_id);

CBYTES *cbgt_kv_new(const UINT32 cbgt_md_id);
EC_BOOL cbgt_kv_init(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val, CBYTES *kv);
EC_BOOL cbgt_kv_clean(const UINT32 cbgt_md_id, CBYTES *kv);
EC_BOOL cbgt_kv_free(const UINT32 cbgt_md_id, CBYTES *kv);

CBYTES *cbgt_key_new(const UINT32 cbgt_md_id);
EC_BOOL cbgt_key_init(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, ctime_t ts, CBYTES *key);
EC_BOOL cbgt_key_clean(const UINT32 cbgt_md_id, CBYTES *key);
EC_BOOL cbgt_key_free(const UINT32 cbgt_md_id, CBYTES *key);

EC_BOOL cbgt_reserve_table_id(const UINT32 cbgt_md_id, UINT32 *table_id);

EC_BOOL cbgt_release_table_id(const UINT32 cbgt_md_id, const UINT32 table_id);

EC_BOOL cbgt_delete_kv_no_lock(const UINT32 cbgt_md_id, const CBYTES *key_bytes);

EC_BOOL cbgt_delete_kv(const UINT32 cbgt_md_id, const CBYTES *key_bytes);

EC_BOOL cbgt_get_root_mod_node(const UINT32 cbgt_md_id, MOD_NODE *mod_node);

EC_BOOL cbgt_merge(const UINT32 cbgt_md_id);

EC_BOOL cbgt_split(const UINT32 cbgt_md_id);

EC_BOOL cbgt_merge_table(const UINT32 cbgt_md_id, const CBYTES *left_table_name, const UINT32 left_table_id);

EC_BOOL cbgt_flush(const UINT32 cbgt_md_id);

EC_BOOL cbgt_exist_table(const UINT32 cbgt_md_id, const CBYTES *table_name);

EC_BOOL cbgt_create_table_on_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CVECTOR *col_family_name_vec);

EC_BOOL cbgt_create_colf_on_meta(const UINT32 cbgt_md_id, const CBYTES  *colf_name);

EC_BOOL cbgt_create_table_on_meta(const UINT32 cbgt_md_id, const CVECTOR *col_family_name_vec);

EC_BOOL cbgt_create_table_on_colf(const UINT32 cbgt_md_id, const CBYTES *colf_row);

EC_BOOL cbgt_get_colf_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_get_colf_table_from_meta(const UINT32 cbgt_md_id, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_get_user_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_get_user_table_from_meta(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_get_user_table_from_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_open_colf_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_open_colf_table_from_meta(const UINT32 cbgt_md_id, const CBYTES *colf, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_open_user_table_from_root(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES * row, const CBYTES *colf, const CBYTES * colq, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_open_user_table_from_meta(const UINT32 cbgt_md_id, const CBYTES * row, const CBYTES *colf, const CBYTES * colq, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_open_user_table_from_colf(const UINT32 cbgt_md_id, const CBYTES * row, const CBYTES *colf, const CBYTES * colq, CBYTES *user_table_name, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_close_rmc_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const UINT32 table_id);

EC_BOOL cbgt_close_user_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const UINT32 table_id);

void   cbgt_was_access(const UINT32 cbgt_md_id);

EC_BOOL cbgt_insert_rfqv_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val);

EC_BOOL cbgt_insert_rfqv(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val);

EC_BOOL cbgt_insert_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val);

EC_BOOL cbgt_insert(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, const CBYTES *val);

EC_BOOL cbgt_delete_from_user(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq);

EC_BOOL cbgt_delete_from_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq);

EC_BOOL cbgt_delete(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq);

EC_BOOL cbgt_insert_register_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const UINT32 table_id, const MOD_NODE *mod_node);

EC_BOOL cbgt_insert_register(const UINT32 cbgt_md_id, const CBYTES *row, const UINT32 table_id, const MOD_NODE *mod_node);

EC_BOOL cbgt_fetch_kv_from_colf_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *kv);

EC_BOOL cbgt_search_from_colf(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val);

EC_BOOL cbgt_search_from_user(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val);

EC_BOOL cbgt_search(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val);

EC_BOOL cbgt_fetch_key_no_lock(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *key_bytes);

EC_BOOL cbgt_fetch_key(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *key_bytes);

EC_BOOL cbgt_fetch_row_no_lock(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *row_bytes);

EC_BOOL cbgt_fetch_row(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, CBYTES *row_bytes);

EC_BOOL cbgt_fetch_user_table_no_lock(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *user_table_id, MOD_NODE *user_mod_node);

EC_BOOL cbgt_fetch_user_table(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, UINT32 *user_table_id, MOD_NODE *user_mod_node);

EC_BOOL cbgt_fetch_from_rmc_no_lock(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_fetch_from_rmc(const UINT32 cbgt_md_id, const CBYTES *kv_bytes, UINT32 *table_id, MOD_NODE *mod_node);

EC_BOOL cbgt_fetch_from_user(const UINT32 cbgt_md_id, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val);

EC_BOOL cbgt_fetch(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *row, const CBYTES *colf, const CBYTES *colq, CBYTES *val);

EC_BOOL cbgt_update_value_no_lock(const UINT32 cbgt_md_id, const CBYTES *key, CBYTES *val);

EC_BOOL cbgt_update_value(const UINT32 cbgt_md_id, const CBYTES *key, CBYTES *val);

EC_BOOL cbgt_mess_register_no_lock(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id);

EC_BOOL cbgt_mess_register(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id);

EC_BOOL cbgt_update_register_no_lock(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id, const MOD_NODE *mod_node);

EC_BOOL cbgt_update_register(const UINT32 cbgt_md_id, const CBYTES *key, const UINT32 table_id, const MOD_NODE *mod_node);

EC_BOOL cbgt_split_register_no_lock(const UINT32 cbgt_md_id,
                                const CBYTES *old_row  ,  const UINT32 old_table_id , const MOD_NODE *old_mod_node ,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node);

EC_BOOL cbgt_split_register(const UINT32 cbgt_md_id,
                                const CBYTES *old_row  ,  const UINT32 old_table_id , const MOD_NODE *old_mod_node ,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node);

EC_BOOL cbgt_merge_register_no_lock(const UINT32 cbgt_md_id,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node,
                                const CBYTES *des_row  , const UINT32 des_table_id  , const MOD_NODE *des_mod_node );

EC_BOOL cbgt_merge_register(const UINT32 cbgt_md_id,
                                const CBYTES *left_row , const UINT32 left_table_id , const MOD_NODE *left_mod_node,
                                const CBYTES *right_row, const UINT32 right_table_id, const MOD_NODE *right_mod_node,
                                const CBYTES *des_row  , const UINT32 des_table_id  , const MOD_NODE *des_mod_node );

EC_BOOL cbgt_report_closing(const UINT32 cbgt_md_id);

EC_BOOL cbgt_cleanup_colf_table(const UINT32 cbgt_md_id, const CBYTES *table_name);

EC_BOOL cbgt_cleanup_meta_table(const UINT32 cbgt_md_id, const CBYTES *table_name);

EC_BOOL cbgt_delete_user_table(const UINT32 cbgt_md_id, const CBYTES *table_name);

EC_BOOL cbgt_delete_colf_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf_name);

EC_BOOL cbgt_add_colf_table(const UINT32 cbgt_md_id, const CBYTES *table_name, const CBYTES *colf_name);

EC_BOOL cbgt_select_from_user(const UINT32 cbgt_md_id, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec);

EC_BOOL cbgt_select_from_colf(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec);

EC_BOOL cbgt_select_from_meta(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec);

EC_BOOL cbgt_select_from_root(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *table_pattern, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec);

EC_BOOL cbgt_select_in_meta(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CBYTES *table_name, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec);

EC_BOOL cbgt_select_in_colf(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CBYTES *table_name, const CBYTES *colf_name, const CSTRING *row_pattern,  const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec);

EC_BOOL cbgt_select(const UINT32 cbgt_md_id, const UINT32 cached_mode, const CSTRING *table_pattern, const CSTRING *row_pattern, const CSTRING *colf_pattern, const CSTRING *colq_pattern, const CSTRING *val_pattern, CVECTOR *ret_kv_vec);

void cbgt_traversal_no_lock(const UINT32 cbgt_md_id, LOG *log);

void cbgt_traversal(const UINT32 cbgt_md_id, LOG *log);

void cbgt_runthrough_no_lock(const UINT32 cbgt_md_id, LOG *log);

void cbgt_runthrough(const UINT32 cbgt_md_id, LOG *log);

void cbgt_traversal_depth(const UINT32 cbgt_md_id, LOG *log);

void cbgt_runthrough_depth(const UINT32 cbgt_md_id, LOG *log);

#endif/* _CBGT_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

