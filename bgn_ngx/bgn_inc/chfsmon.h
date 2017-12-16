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

#ifndef _CHFSMON_H
#define _CHFSMON_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#include "chfs.h"
#include "chfsconhash.h"


#define CHFSMON_CONHASH_DEFAULT_HASH_ALGO       CHASH_MD5_ALGO_ID

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;

    CVECTOR              chfs_node_vec; /*item is CHFS_NODE*/

    CHFSCONHASH         *chfsconhash;

}CHFSMON_MD;

#define CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md)        (&((chfsmon_md)->chfs_node_vec))
#define CHFSMON_MD_CHFSCONHASH(chfsmon_md)          ((chfsmon_md)->chfsconhash)

#define CHFS_NODE_IS_ERR          ((UINT32)0x0000)
#define CHFS_NODE_IS_UP           ((UINT32)0x0001)
#define CHFS_NODE_IS_DOWN         ((UINT32)0x0002)

typedef struct
{
    UINT32          tcid;
    UINT32          ipaddr;
    UINT32          port;
    UINT32          modi;
    
    UINT32          state;
}CHFS_NODE;

#define CHFS_NODE_TCID(chfs_node)                ((chfs_node)->tcid)
#define CHFS_NODE_IPADDR(chfs_node)              ((chfs_node)->ipaddr)
#define CHFS_NODE_PORT(chfs_node)                ((chfs_node)->port)
#define CHFS_NODE_MODI(chfs_node)                ((chfs_node)->modi)
#define CHFS_NODE_STATE(chfs_node)               ((chfs_node)->state)

/**
*   for test only
*
*   to query the status of CHFSMON Module
*
**/
void chfsmon_print_module_status(const UINT32 chfsmon_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CHFSMON module
*
*
**/
UINT32 chfsmon_free_module_static_mem(const UINT32 chfsmon_md_id);

/**
*
* start CHFSMON module
*
**/
UINT32 chfsmon_start();

/**
*
* end CHFSMON module
*
**/
void chfsmon_end(const UINT32 chfsmon_md_id);

CHFS_NODE *chfs_node_new();

EC_BOOL chfs_node_init(CHFS_NODE *chfs_node);

EC_BOOL chfs_node_clean(CHFS_NODE *chfs_node);

EC_BOOL chfs_node_free(CHFS_NODE *chfs_node);

EC_BOOL chfs_node_clone(CHFS_NODE *chfs_node_des, const CHFS_NODE *chfs_node_src);

EC_BOOL chfs_node_is_up(const CHFS_NODE *chfs_node);

EC_BOOL chfs_node_is_valid(const CHFS_NODE *chfs_node);

int chfs_node_cmp(const CHFS_NODE *chfs_node_1st, const CHFS_NODE *chfs_node_2nd);

const char *chfs_node_state(const CHFS_NODE *chfs_node);

void chfs_node_print(const CHFS_NODE *chfs_node, LOG *log);

void chfsmon_chfs_node_print(const UINT32 chfsmon_md_id, LOG *log);

void chfsmon_chfs_node_list(const UINT32 chfsmon_md_id, CSTRING *cstr);

EC_BOOL chfsmon_chfs_node_num(const UINT32 chfsmon_md_id, UINT32 *num);

EC_BOOL chfsmon_chfs_node_add(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_del(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_set_up(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_set_down(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_is_up(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_get_by_pos(const UINT32 chfsmon_md_id, const UINT32 pos, CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_get_by_tcid(const UINT32 chfsmon_md_id, const UINT32 tcid, const UINT32 modi, CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_get_by_hash(const UINT32 chfsmon_md_id, const UINT32 hash, CHFS_NODE *chfs_node);

EC_BOOL chfsmon_chfs_node_get_by_path(const UINT32 chfsmon_md_id, const uint8_t *path, const uint32_t path_len, CHFS_NODE *chfs_node);


#endif /*_CHFSMON_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

