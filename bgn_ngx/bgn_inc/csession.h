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

#ifndef _CSESSION_H
#define _CSESSION_H

#include "type.h"
#include "mm.h"
#include "log.h"
#include "mod.inc"

#include "clist.h"
#include "cstring.h"
#include "cbytes.h"

#include "cmutex.h"

#define CSESSION_NEVER_EXPIRE        ((UINT32)   0)
#define CSESSION_BEGIN_ID            ((UINT32)   0)
#define CSESSION_ERROR_ID            ((UINT32)  -1)
#define CSESSION_PATH_MAX_DEPTH      ((UINT32) 256)

#define CSESSION_TIMEOUT_CHECKER_INTVAL ((UINT32) 5)    /*5 seconds*/

#define CSESSION_PATH_SEPARATORS     ((const char *)"/")

typedef struct
{
    /* used counter >= 0 */
    UINT32      usedcounter;

    MOD_MGR    *mod_mgr;
    CRWLOCK     rwlock;

    CMUTEX      session_id_pool_cmutex;
    UINT32      session_id_pool;

    CLIST       session_list;   /*session list, item type is CSESSION_NODE*/
}CSESSION_MD;

#define CSESSION_MD_MOD_MGR(csession_md)            ((csession_md)->mod_mgr)
#define CSESSION_MD_CRWLOCK(csession_md)            (&((csession_md)->rwlock))
#define CSESSION_MD_ID_POOL_CMUTEX(csession_md)     (&((csession_md)->session_id_pool_cmutex))
#define CSESSION_MD_ID_POOL(csession_md)            ((csession_md)->session_id_pool)
#define CSESSION_MD_SESSION_LIST(csession_md)       (&((csession_md)->session_list))

#define CSESSION_MD_INIT_CRWLOCK(csession_md, location)            (crwlock_init(CSESSION_MD_CRWLOCK(csession_md), CRWLOCK_PROCESS_PRIVATE, location))
#define CSESSION_MD_CLEAN_CRWLOCK(csession_md, location)           (crwlock_clean(CSESSION_MD_CRWLOCK(csession_md), location))
#define CSESSION_MD_CRWLOCK_RDLOCK(csession_md, location)          (crwlock_rdlock(CSESSION_MD_CRWLOCK(csession_md), location))
#define CSESSION_MD_CRWLOCK_WRLOCK(csession_md, location)          (crwlock_wrlock(CSESSION_MD_CRWLOCK(csession_md), location))
#define CSESSION_MD_CRWLOCK_UNLOCK(csession_md, location)          (crwlock_unlock(CSESSION_MD_CRWLOCK(csession_md), location))

#define CSESSION_MD_INIT_ID_POOL_CMUTEX(csession_md, location)     (cmutex_init(CSESSION_MD_ID_POOL_CMUTEX(csession_md), CMUTEX_PROCESS_PRIVATE, location))
#define CSESSION_MD_CLEAN_ID_POOL_CMUTEX(csession_md, location)    (cmutex_clean(CSESSION_MD_ID_POOL_CMUTEX(csession_md), location))
#define CSESSION_MD_CMUTEX_ID_POOL_LOCK(csession_md, location)     (cmutex_lock(CSESSION_MD_ID_POOL_CMUTEX(csession_md), location))
#define CSESSION_MD_CMUTEX_ID_POOL_UNLOCK(csession_md, location)   (cmutex_unlock(CSESSION_MD_ID_POOL_CMUTEX(csession_md), location))

/*one session*/
typedef struct
{
    CSTRING      name;
    UINT32       id;

    CMUTEX       cmutex;/*cmutex for updating access_time*/

    UINT32       expire_nsec;
    CTIMET       create_time; /*session created time*/
    CTIMET       access_time; /*last access time*/
    CLIST        cache_tree;  /*session cache tree, item type is CSESSION_ITEM*/
}CSESSION_NODE;

#define CSESSION_NODE_NAME(csession_node)           (&((csession_node)->name))
#define CSESSION_NODE_NAME_STR(csession_node)       (cstring_get_str(CSESSION_NODE_NAME(csession_node)))
#define CSESSION_NODE_ID(csession_node)             ((csession_node)->id)
#define CSESSION_NODE_ACCESS_CMUTEX(csession_node)  (&((csession_node)->cmutex))
#define CSESSION_NODE_EXPIRE_NSEC(csession_node)    ((csession_node)->expire_nsec)
#define CSESSION_NODE_CREATE_TIME(csession_node)    ((csession_node)->create_time)
#define CSESSION_NODE_ACCESS_TIME(csession_node)    ((csession_node)->access_time)
#define CSESSION_NODE_CACHE_TREE(csession_node)     (&((csession_node)->cache_tree))

#define CSESSION_NODE_INIT_ACCESS_CMUTEX(csession_node, location)     (cmutex_init(CSESSION_NODE_ACCESS_CMUTEX(csession_node), CMUTEX_PROCESS_PRIVATE, location))
#define CSESSION_NODE_CLEAN_ACCESS_CMUTEX(csession_node, location)    (cmutex_clean(CSESSION_NODE_ACCESS_CMUTEX(csession_node), location))
#define CSESSION_NODE_CMUTEX_ACCESS_LOCK(csession_node, location)     (cmutex_lock(CSESSION_NODE_ACCESS_CMUTEX(csession_node), location))
#define CSESSION_NODE_CMUTEX_ACCESS_UNLOCK(csession_node, location)   (cmutex_unlock(CSESSION_NODE_ACCESS_CMUTEX(csession_node), location))

/*update access time*/
#define CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, location)     do{\
    CSESSION_NODE_CMUTEX_ACCESS_LOCK(csession_node, location);\
    CTIMET_GET(CSESSION_NODE_ACCESS_TIME(csession_node));\
    CSESSION_NODE_CMUTEX_ACCESS_UNLOCK(csession_node, location);\
}while(0)

typedef struct
{
    CSTRING      key;
    CBYTES       val;
    CLIST        sub_cache_tree;/*item type is CSESSION_ITEM*/
}CSESSION_ITEM;

#define CSESSION_ITEM_KEY(csession_item)            (&((csession_item)->key))
#define CSESSION_ITEM_KEY_STR(csession_item)        (cstring_get_str(CSESSION_ITEM_KEY(csession_item)))
#define CSESSION_ITEM_VAL(csession_item)            (&((csession_item)->val))
#define CSESSION_ITEM_CHILDREN(csession_item)       (&((csession_item)->sub_cache_tree))



/**
*   for test only
*
*   to query the status of CSESSION Module
*
**/
void csession_print_module_status(const UINT32 csession_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CSESSION module
*
*
**/
UINT32 csession_free_module_static_mem(const UINT32 csession_md_id);

/**
*
* start CSESSION module
*
**/
UINT32 csession_start();

/**
*
* end CSESSION module
*
**/
void csession_end(const UINT32 csession_md_id);

void csession_print(LOG *log, const UINT32 csession_md_id, const UINT32 level);

void csession_show(const UINT32 csession_md_id, LOG *log);

CSESSION_NODE *csession_node_new(const CSTRING *name, const UINT32 expire_nsec);

EC_BOOL csession_node_init(CSESSION_NODE *csession_node);

EC_BOOL csession_node_clean(CSESSION_NODE *csession_node);

EC_BOOL csession_node_free(CSESSION_NODE *csession_node);

EC_BOOL csession_node_is_expired(const UINT32 csession_md_id, const CSESSION_NODE *csession_node, const CTIMET *cur_time);

EC_BOOL csession_node_match_name(const CSESSION_NODE *csession_node, const CSTRING *name);

EC_BOOL csession_node_match_id(const CSESSION_NODE *csession_node, const UINT32 session_id);

void csession_node_print(LOG *log, const CSESSION_NODE *csession_node, const UINT32 level);

CSESSION_ITEM *csession_item_new(const CSTRING *key, const CBYTES *val);

EC_BOOL csession_item_init(CSESSION_ITEM *csession_item);

EC_BOOL csession_item_clean(CSESSION_ITEM *csession_item);

EC_BOOL csession_item_free(CSESSION_ITEM *csession_item);

EC_BOOL csession_item_match_key(const CSESSION_ITEM *csession_item, const CSTRING *key);

EC_BOOL csession_item_match_val(const CSESSION_ITEM *csession_item, const CBYTES *val);

void csession_item_print(LOG *log, const CSESSION_ITEM *csession_item, const UINT32 level);

CSESSION_NODE *csession_search_by_name(const UINT32 csession_md_id, const CSTRING *name);

CSESSION_NODE *csession_search_by_id(const UINT32 csession_md_id, const UINT32 session_id);

EC_BOOL csession_add(const UINT32 csession_md_id, const CSTRING *name, const UINT32 expire_nsec);

EC_BOOL csession_rmv_by_name(const UINT32 csession_md_id, const CSTRING *name);

EC_BOOL csession_rmv_by_id(const UINT32 csession_md_id, const UINT32 session_id);

EC_BOOL csession_rmv_by_name_regex(const UINT32 csession_md_id, const CSTRING *session_name_regex);

EC_BOOL csession_rmv_by_id_regex(const UINT32 csession_md_id, const CSTRING *session_id_regex);

EC_BOOL csession_get_name(const UINT32 csession_md_id, const UINT32 session_id, CSTRING *session_name);

EC_BOOL csession_get_id(const UINT32 csession_md_id, const CSTRING *session_name, UINT32 *session_id);

/*note: path is the full path of key. e.g., top=root&level1=b&level2=c*/
EC_BOOL csession_set(const UINT32 csession_md_id, CSESSION_NODE *csession_node, const CSTRING *path, const CBYTES *val);

EC_BOOL csession_set_by_name(const UINT32 csession_md_id, const CSTRING *session_name, const CSTRING *path, const CBYTES *val);

EC_BOOL csession_set_by_id(const UINT32 csession_md_id, const UINT32 session_id, const CSTRING *path, const CBYTES *val);

/*note: path is the full path of key with wildcards. e.g., top=root&level1=*&level2=c*x*/
EC_BOOL csession_get(const UINT32 csession_md_id, const CSESSION_NODE *csession_node, const CSTRING *path, CLIST *csession_item_list);

EC_BOOL csession_get_by_name(const UINT32 csession_md_id, const CSTRING *session_name, const CSTRING *path, CLIST *csession_item_list);

EC_BOOL csession_get_by_id(const UINT32 csession_md_id, const UINT32 session_id, const CSTRING *path, CLIST *csession_item_list);

EC_BOOL csession_get_by_name_regex(const UINT32 csession_md_id, const CSTRING *session_name_regex, const CSTRING *path, CLIST *csession_node_list);

EC_BOOL csession_get_by_id_regex(const UINT32 csession_md_id, const CSTRING *session_id_regex, const CSTRING *path, CLIST *csession_node_list);

EC_BOOL csession_get_children(const UINT32 csession_md_id, const CSESSION_NODE *csession_node, const CSTRING *path, CLIST *csession_item_list);

EC_BOOL csession_get_children_by_name(const UINT32 csession_md_id, const CSTRING *session_name, const CSTRING *path, CLIST *csession_item_list);

EC_BOOL csession_expire_handle(const UINT32 csession_md_id);

#endif/*_CSESSION_H*/
#ifdef __cplusplus
}
#endif/*__cplusplus*/

