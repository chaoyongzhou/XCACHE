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

#ifndef _CMON_H
#define _CMON_H

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

#include "chashalgo.h"
#include "cconhash.h"
#include "cmaglev.h"

#define CMON_CONHASH_DEFAULT_HASH_ALGO       CHASH_MURMUR_ALGO_ID
#define CMON_HOT_PATH_HASH_ALGO              CHASH_RS_ALGO_ID
#define CMON_HOT_PATH_MAX_NUM                (20000)
#define CMON_HOT_PATH_RECYCLE_NUM            (10)

#define CMON_CHECK_MAX_TIMES                 (64)

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;

    CVECTOR              cmon_node_vec; /*item is CMON_NODE*/

    CCONHASH            *cconhash;
    CMAGLEV             *cmaglev;

    CHASH_ALGO           hot_path_hash_func;
    CRB_TREE             hot_path_tree; /*item is CMON_HOT_PATH*/
    CLIST                hot_path_list; /*CMON_HOT_PATH list*/
}CMON_MD;

#define CMON_MD_CMON_NODE_VEC(cmon_md)        (&((cmon_md)->cmon_node_vec))
#define CMON_MD_CCONHASH(cmon_md)             ((cmon_md)->cconhash)
#define CMON_MD_CMAGLEV(cmon_md)              ((cmon_md)->cmaglev)
#define CMON_MD_HOT_PATH_HASH_FUNC(cmon_md)   ((cmon_md)->hot_path_hash_func)
#define CMON_MD_HOT_PATH_TREE(cmon_md)        (&((cmon_md)->hot_path_tree))
#define CMON_MD_HOT_PATH_LIST(cmon_md)        (&((cmon_md)->hot_path_list))

#define CMON_NODE_IS_ERR          ((UINT32)0x0000)
#define CMON_NODE_IS_UP           ((UINT32)0x0001)
#define CMON_NODE_IS_DOWN         ((UINT32)0x0002)

typedef struct
{
    UINT32          tcid;
    UINT32          ipaddr;
    UINT32          port; /*ignore port!*/
    UINT32          modi;

    UINT32          state;
}CMON_NODE;

#define CMON_NODE_TCID(cmon_node)                ((cmon_node)->tcid)
#define CMON_NODE_IPADDR(cmon_node)              ((cmon_node)->ipaddr)
#define CMON_NODE_PORT(cmon_node)                ((cmon_node)->port)
#define CMON_NODE_MODI(cmon_node)                ((cmon_node)->modi)
#define CMON_NODE_STATE(cmon_node)               ((cmon_node)->state)

typedef struct
{
    UINT32         hash;
    CSTRING        path;/*no seg_no, not terminiate with '/'*/
}CMON_HOT_PATH;

#define CMON_HOT_PATH_HASH(cmon_hot_path)        ((cmon_hot_path)->hash)
#define CMON_HOT_PATH_CSTR(cmon_hot_path)        (&((cmon_hot_path)->path))

/**
*   for test only
*
*   to query the status of CMON Module
*
**/
void cmon_print_module_status(const UINT32 cmon_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CMON module
*
*
**/
UINT32 cmon_free_module_static_mem(const UINT32 cmon_md_id);

/**
*
* start CMON module
*
**/
UINT32 cmon_start();

/**
*
* end CMON module
*
**/
void cmon_end(const UINT32 cmon_md_id);

/**
*
* set all nodes up
*
**/
EC_BOOL cmon_set_up(const UINT32 cmon_md_id);

/**
*
* set all nodes down
*
**/
EC_BOOL cmon_set_down(const UINT32 cmon_md_id);

CMON_NODE *cmon_node_new();

EC_BOOL cmon_node_init(CMON_NODE *cmon_node);

EC_BOOL cmon_node_clean(CMON_NODE *cmon_node);

EC_BOOL cmon_node_free(CMON_NODE *cmon_node);

EC_BOOL cmon_node_clone(const CMON_NODE *cmon_node_src, CMON_NODE *cmon_node_des);

EC_BOOL cmon_node_is_up(const CMON_NODE *cmon_node);

EC_BOOL cmon_node_is_valid(const CMON_NODE *cmon_node);

EC_BOOL cmon_node_cmp(const CMON_NODE *cmon_node_1st, const CMON_NODE *cmon_node_2nd);

const char *cmon_node_state(const CMON_NODE *cmon_node);

void cmon_node_print(const CMON_NODE *cmon_node, LOG *log);

void cmon_node_print_0(LOG *log, const CMON_NODE *cmon_node);

void cmon_print_nodes(const UINT32 cmon_md_id, LOG *log);

void cmon_list_nodes(const UINT32 cmon_md_id, CSTRING *cstr);

EC_BOOL cmon_count_nodes(const UINT32 cmon_md_id, UINT32 *num);

EC_BOOL cmon_add_node(const UINT32 cmon_md_id, const CMON_NODE *cmon_node);

EC_BOOL cmon_del_node(const UINT32 cmon_md_id, const CMON_NODE *cmon_node);

EC_BOOL cmon_set_node_up(const UINT32 cmon_md_id, const CMON_NODE *cmon_node);

EC_BOOL cmon_set_node_down(const UINT32 cmon_md_id, const CMON_NODE *cmon_node);

EC_BOOL cmon_check_node_up(const UINT32 cmon_md_id, const CMON_NODE *cmon_node);

EC_BOOL cmon_get_node_by_pos(const UINT32 cmon_md_id, const UINT32 pos, CMON_NODE *cmon_node);

EC_BOOL cmon_get_node_by_tcid(const UINT32 cmon_md_id, const UINT32 tcid, const UINT32 modi, CMON_NODE *cmon_node);

EC_BOOL cmon_get_node_by_hash(const UINT32 cmon_md_id, const UINT32 hash, CMON_NODE *cmon_node);

EC_BOOL cmon_get_node_by_path(const UINT32 cmon_md_id, const uint8_t *path, const uint32_t path_len, CMON_NODE *cmon_node);

EC_BOOL cmon_set_node_start_pos(const UINT32 cmon_md_id, const UINT32 start_pos);

EC_BOOL cmon_search_node_up(const UINT32 cmon_md_id, CMON_NODE *cmon_node);

EC_BOOL cmon_get_store_http_srv_of_hot(const UINT32 cmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);
EC_BOOL cmon_get_store_http_srv_of_hot_new(const UINT32 cmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

EC_BOOL cmon_get_store_http_srv(const UINT32 cmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

/*when del a csocket_cnode (->tasks_node);*/
EC_BOOL cmon_callback_when_del(const UINT32 cmon_md_id);

CMON_HOT_PATH *cmon_hot_path_new();

EC_BOOL cmon_hot_path_init(CMON_HOT_PATH *cmon_hot_path);

EC_BOOL cmon_hot_path_clean(CMON_HOT_PATH *cmon_hot_path);

EC_BOOL cmon_hot_path_free(CMON_HOT_PATH *cmon_hot_path);

EC_BOOL cmon_hot_path_clone(CMON_HOT_PATH *cmon_hot_path_des, const CMON_HOT_PATH *cmon_hot_path_src);

int cmon_hot_path_cmp(const CMON_HOT_PATH *cmon_hot_path_1st, const CMON_HOT_PATH *cmon_hot_path_2nd);

void cmon_hot_path_print(const CMON_HOT_PATH *cmon_hot_path, LOG *log);

EC_BOOL cmon_add_hot_path(const UINT32 cmon_md_id, const CSTRING *path);
EC_BOOL cmon_recycle_hot_path(CMON_MD *cmon_md);

EC_BOOL cmon_del_hot_path(const UINT32 cmon_md_id, const CSTRING *path);

EC_BOOL cmon_exist_hot_path(const UINT32 cmon_md_id, const CSTRING *path);

void cmon_print_hot_paths(const UINT32 cmon_md_id, LOG *log);

EC_BOOL cmon_load_hot_paths(const UINT32 cmon_md_id, const CSTRING *path);

EC_BOOL cmon_unload_hot_paths(const UINT32 cmon_md_id);


#endif /*_CMON_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

