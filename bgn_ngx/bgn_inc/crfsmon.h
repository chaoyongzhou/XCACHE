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

#ifndef _CRFSMON_H
#define _CRFSMON_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"
#include "crb.h"

#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#include "crfs.h"
#include "crfsconhash.h"


#define CRFSMON_CONHASH_DEFAULT_HASH_ALGO       CHASH_MD5_ALGO_ID
#define CRFSMON_HOT_PATH_HASH_ALGO              CHASH_RS_ALGO_ID

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;

    CVECTOR              crfs_node_vec; /*item is CRFS_NODE*/

    CRFSCONHASH         *crfsconhash;

    CHASH_ALGO           hot_path_hash_func;
    CRB_TREE             hot_path_tree; /*item is CRFS_HOT_PATH*/
}CRFSMON_MD;

#define CRFSMON_MD_CRFS_NODE_VEC(crfsmon_md)        (&((crfsmon_md)->crfs_node_vec))
#define CRFSMON_MD_CRFSCONHASH(crfsmon_md)          ((crfsmon_md)->crfsconhash)
#define CRFSMON_MD_HOT_PATH_HASH_FUNC(crfsmon_md)   ((crfsmon_md)->hot_path_hash_func)
#define CRFSMON_MD_HOT_PATH_TREE(crfsmon_md)        (&((crfsmon_md)->hot_path_tree))

#define CRFS_NODE_IS_ERR          ((UINT32)0x0000)
#define CRFS_NODE_IS_UP           ((UINT32)0x0001)
#define CRFS_NODE_IS_DOWN         ((UINT32)0x0002)

typedef struct
{
    UINT32          tcid;
    UINT32          ipaddr;
    UINT32          port; /*ignore port!*/
    UINT32          modi;

    UINT32          state;
}CRFS_NODE;

#define CRFS_NODE_TCID(crfs_node)                ((crfs_node)->tcid)
#define CRFS_NODE_IPADDR(crfs_node)              ((crfs_node)->ipaddr)
#define CRFS_NODE_PORT(crfs_node)                ((crfs_node)->port)
#define CRFS_NODE_MODI(crfs_node)                ((crfs_node)->modi)
#define CRFS_NODE_STATE(crfs_node)               ((crfs_node)->state)

typedef struct
{
    UINT32         hash;
    CSTRING        path;/*no seg_no, not terminiate with '/'*/
}CRFS_HOT_PATH;

#define CRFS_HOT_PATH_HASH(crfs_hot_path)        ((crfs_hot_path)->hash)
#define CRFS_HOT_PATH_CSTR(crfs_hot_path)        (&((crfs_hot_path)->path))

/**
*   for test only
*
*   to query the status of CRFSMON Module
*
**/
void crfsmon_print_module_status(const UINT32 crfsmon_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CRFSMON module
*
*
**/
UINT32 crfsmon_free_module_static_mem(const UINT32 crfsmon_md_id);

/**
*
* start CRFSMON module
*
**/
UINT32 crfsmon_start();

/**
*
* end CRFSMON module
*
**/
void crfsmon_end(const UINT32 crfsmon_md_id);

CRFS_NODE *crfs_node_new();

EC_BOOL crfs_node_init(CRFS_NODE *crfs_node);

EC_BOOL crfs_node_clean(CRFS_NODE *crfs_node);

EC_BOOL crfs_node_free(CRFS_NODE *crfs_node);

EC_BOOL crfs_node_clone(const CRFS_NODE *crfs_node_src, CRFS_NODE *crfs_node_des);

EC_BOOL crfs_node_is_up(const CRFS_NODE *crfs_node);

EC_BOOL crfs_node_is_valid(const CRFS_NODE *crfs_node);

int crfs_node_cmp(const CRFS_NODE *crfs_node_1st, const CRFS_NODE *crfs_node_2nd);

const char *crfs_node_state(const CRFS_NODE *crfs_node);

void crfs_node_print(const CRFS_NODE *crfs_node, LOG *log);

void crfsmon_crfs_node_print(const UINT32 crfsmon_md_id, LOG *log);

void crfsmon_crfs_node_list(const UINT32 crfsmon_md_id, CSTRING *cstr);

EC_BOOL crfsmon_crfs_node_num(const UINT32 crfsmon_md_id, UINT32 *num);

EC_BOOL crfsmon_crfs_node_add(const UINT32 crfsmon_md_id, const CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_del(const UINT32 crfsmon_md_id, const CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_set_up(const UINT32 crfsmon_md_id, const CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_set_down(const UINT32 crfsmon_md_id, const CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_is_up(const UINT32 crfsmon_md_id, const CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_get_by_pos(const UINT32 crfsmon_md_id, const UINT32 pos, CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_get_by_tcid(const UINT32 crfsmon_md_id, const UINT32 tcid, const UINT32 modi, CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_get_by_hash(const UINT32 crfsmon_md_id, const UINT32 hash, CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_get_by_path(const UINT32 crfsmon_md_id, const uint8_t *path, const uint32_t path_len, CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_node_set_start_pos(const UINT32 crfsmon_md_id, const UINT32 start_pos);

EC_BOOL crfsmon_crfs_node_search_up(const UINT32 crfsmon_md_id, CRFS_NODE *crfs_node);

EC_BOOL crfsmon_crfs_store_http_srv_get(const UINT32 crfsmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

EC_BOOL crfsmon_crfs_store_http_srv_get_hot(const UINT32 crfsmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

/*when add a csocket_cnode (->tasks_node)*/
EC_BOOL crfsmon_callback_when_add(const UINT32 crfsmon_md_id, TASKS_NODE *tasks_node);

/*when del a csocket_cnode (->tasks_node)*/
EC_BOOL crfsmon_callback_when_del(const UINT32 crfsmon_md_id, TASKS_NODE *tasks_node);

CRFS_HOT_PATH *crfs_hot_path_new();

EC_BOOL crfs_hot_path_init(CRFS_HOT_PATH *crfs_hot_path);

EC_BOOL crfs_hot_path_clean(CRFS_HOT_PATH *crfs_hot_path);

EC_BOOL crfs_hot_path_free(CRFS_HOT_PATH *crfs_hot_path);

EC_BOOL crfs_hot_path_clone(CRFS_HOT_PATH *crfs_hot_path_des, const CRFS_HOT_PATH *crfs_hot_path_src);

int crfs_hot_path_cmp(const CRFS_HOT_PATH *crfs_hot_path_1st, const CRFS_HOT_PATH *crfs_hot_path_2nd);

void crfs_hot_path_print(const CRFS_HOT_PATH *crfs_hot_path, LOG *log);

EC_BOOL crfsmon_crfs_hot_path_add(const UINT32 crfsmon_md_id, const CSTRING *path);

EC_BOOL crfsmon_crfs_hot_path_del(const UINT32 crfsmon_md_id, const CSTRING *path);

EC_BOOL crfsmon_crfs_hot_path_exist(const UINT32 crfsmon_md_id, const CSTRING *path);

void crfsmon_crfs_hot_path_print(const UINT32 crfsmon_md_id, LOG *log);

EC_BOOL crfsmon_crfs_hot_path_load(const UINT32 crfsmon_md_id, const CSTRING *path);

EC_BOOL crfsmon_crfs_hot_path_unload(const UINT32 crfsmon_md_id);

#endif /*_CRFSMON_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

