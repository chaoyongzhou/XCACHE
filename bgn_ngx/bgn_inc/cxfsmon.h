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

#ifndef _CXFSMON_H
#define _CXFSMON_H

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

#include "cxfs.h"
#include "cxfsconhash.h"


#define CXFSMON_CONHASH_DEFAULT_HASH_ALGO       CHASH_MD5_ALGO_ID
#define CXFSMON_HOT_PATH_HASH_ALGO              CHASH_RS_ALGO_ID

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;

    CVECTOR              cxfs_node_vec; /*item is CXFS_NODE*/

    CXFSCONHASH         *cxfsconhash;

    CHASH_ALGO           hot_path_hash_func;
    CRB_TREE             hot_path_tree; /*item is CXFS_HOT_PATH*/
}CXFSMON_MD;

#define CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md)        (&((cxfsmon_md)->cxfs_node_vec))
#define CXFSMON_MD_CXFSCONHASH(cxfsmon_md)          ((cxfsmon_md)->cxfsconhash)
#define CXFSMON_MD_HOT_PATH_HASH_FUNC(cxfsmon_md)   ((cxfsmon_md)->hot_path_hash_func)
#define CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md)        (&((cxfsmon_md)->hot_path_tree))

#define CXFS_NODE_IS_ERR          ((UINT32)0x0000)
#define CXFS_NODE_IS_UP           ((UINT32)0x0001)
#define CXFS_NODE_IS_DOWN         ((UINT32)0x0002)

typedef struct
{
    UINT32          tcid;
    UINT32          ipaddr;
    UINT32          port; /*ignore port!*/
    UINT32          modi;

    UINT32          state;
}CXFS_NODE;

#define CXFS_NODE_TCID(cxfs_node)                ((cxfs_node)->tcid)
#define CXFS_NODE_IPADDR(cxfs_node)              ((cxfs_node)->ipaddr)
#define CXFS_NODE_PORT(cxfs_node)                ((cxfs_node)->port)
#define CXFS_NODE_MODI(cxfs_node)                ((cxfs_node)->modi)
#define CXFS_NODE_STATE(cxfs_node)               ((cxfs_node)->state)

typedef struct
{
    UINT32         hash;
    CSTRING        path;/*no seg_no, not terminiate with '/'*/
}CXFS_HOT_PATH;

#define CXFS_HOT_PATH_HASH(cxfs_hot_path)        ((cxfs_hot_path)->hash)
#define CXFS_HOT_PATH_CSTR(cxfs_hot_path)        (&((cxfs_hot_path)->path))

/**
*   for test only
*
*   to query the status of CXFSMON Module
*
**/
void cxfsmon_print_module_status(const UINT32 cxfsmon_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CXFSMON module
*
*
**/
UINT32 cxfsmon_free_module_static_mem(const UINT32 cxfsmon_md_id);

/**
*
* start CXFSMON module
*
**/
UINT32 cxfsmon_start();

/**
*
* end CXFSMON module
*
**/
void cxfsmon_end(const UINT32 cxfsmon_md_id);

CXFS_NODE *cxfs_node_new();

EC_BOOL cxfs_node_init(CXFS_NODE *cxfs_node);

EC_BOOL cxfs_node_clean(CXFS_NODE *cxfs_node);

EC_BOOL cxfs_node_free(CXFS_NODE *cxfs_node);

EC_BOOL cxfs_node_clone(const CXFS_NODE *cxfs_node_src, CXFS_NODE *cxfs_node_des);

EC_BOOL cxfs_node_is_up(const CXFS_NODE *cxfs_node);

EC_BOOL cxfs_node_is_valid(const CXFS_NODE *cxfs_node);

int cxfs_node_cmp(const CXFS_NODE *cxfs_node_1st, const CXFS_NODE *cxfs_node_2nd);

const char *cxfs_node_state(const CXFS_NODE *cxfs_node);

void cxfs_node_print(const CXFS_NODE *cxfs_node, LOG *log);

void cxfsmon_cxfs_node_print(const UINT32 cxfsmon_md_id, LOG *log);

void cxfsmon_cxfs_node_list(const UINT32 cxfsmon_md_id, CSTRING *cstr);

EC_BOOL cxfsmon_cxfs_node_num(const UINT32 cxfsmon_md_id, UINT32 *num);

EC_BOOL cxfsmon_cxfs_node_add(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_del(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_set_up(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_set_down(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_is_up(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_get_by_pos(const UINT32 cxfsmon_md_id, const UINT32 pos, CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_get_by_tcid(const UINT32 cxfsmon_md_id, const UINT32 tcid, const UINT32 modi, CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_get_by_hash(const UINT32 cxfsmon_md_id, const UINT32 hash, CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_get_by_path(const UINT32 cxfsmon_md_id, const uint8_t *path, const uint32_t path_len, CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_node_set_start_pos(const UINT32 cxfsmon_md_id, const UINT32 start_pos);

EC_BOOL cxfsmon_cxfs_node_search_up(const UINT32 cxfsmon_md_id, CXFS_NODE *cxfs_node);

EC_BOOL cxfsmon_cxfs_store_http_srv_get(const UINT32 cxfsmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

EC_BOOL cxfsmon_cxfs_store_http_srv_get_hot(const UINT32 cxfsmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

/*when add a csocket_cnode (->tasks_node)*/
EC_BOOL cxfsmon_callback_when_add(const UINT32 cxfsmon_md_id, TASKS_NODE *tasks_node);

/*when del a csocket_cnode (->tasks_node)*/
EC_BOOL cxfsmon_callback_when_del(const UINT32 cxfsmon_md_id, TASKS_NODE *tasks_node);

CXFS_HOT_PATH *cxfs_hot_path_new();

EC_BOOL cxfs_hot_path_init(CXFS_HOT_PATH *cxfs_hot_path);

EC_BOOL cxfs_hot_path_clean(CXFS_HOT_PATH *cxfs_hot_path);

EC_BOOL cxfs_hot_path_free(CXFS_HOT_PATH *cxfs_hot_path);

EC_BOOL cxfs_hot_path_clone(CXFS_HOT_PATH *cxfs_hot_path_des, const CXFS_HOT_PATH *cxfs_hot_path_src);

int cxfs_hot_path_cmp(const CXFS_HOT_PATH *cxfs_hot_path_1st, const CXFS_HOT_PATH *cxfs_hot_path_2nd);

void cxfs_hot_path_print(const CXFS_HOT_PATH *cxfs_hot_path, LOG *log);

EC_BOOL cxfsmon_cxfs_hot_path_add(const UINT32 cxfsmon_md_id, const CSTRING *path);

EC_BOOL cxfsmon_cxfs_hot_path_del(const UINT32 cxfsmon_md_id, const CSTRING *path);

EC_BOOL cxfsmon_cxfs_hot_path_exist(const UINT32 cxfsmon_md_id, const CSTRING *path);

void cxfsmon_cxfs_hot_path_print(const UINT32 cxfsmon_md_id, LOG *log);

EC_BOOL cxfsmon_cxfs_hot_path_load(const UINT32 cxfsmon_md_id, const CSTRING *path);

EC_BOOL cxfsmon_cxfs_hot_path_unload(const UINT32 cxfsmon_md_id);

#endif /*_CXFSMON_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

