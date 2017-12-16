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

#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#include "crfs.h"
#include "crfsconhash.h"


#define CRFSMON_CONHASH_DEFAULT_HASH_ALGO       CHASH_MD5_ALGO_ID

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;

    CVECTOR              crfs_node_vec; /*item is CRFS_NODE*/

    CRFSCONHASH         *crfsconhash;

}CRFSMON_MD;

#define CRFSMON_MD_CRFS_NODE_VEC(crfsmon_md)        (&((crfsmon_md)->crfs_node_vec))
#define CRFSMON_MD_CRFSCONHASH(crfsmon_md)          ((crfsmon_md)->crfsconhash)

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

EC_BOOL crfs_node_clone(CRFS_NODE *crfs_node_des, const CRFS_NODE *crfs_node_src);

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

EC_BOOL crfsmon_crfs_store_http_srv_get(const UINT32 crfsmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

/*when add a csocket_cnode (->tasks_node)*/
EC_BOOL crfsmon_callback_when_add(const UINT32 crfsmon_md_id, TASKS_NODE *tasks_node);

/*when del a csocket_cnode (->tasks_node)*/
EC_BOOL crfsmon_callback_when_del(const UINT32 crfsmon_md_id, TASKS_NODE *tasks_node);

#endif /*_CRFSMON_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

