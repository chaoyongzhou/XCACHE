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

#ifndef _CSFSMON_H
#define _CSFSMON_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#include "csfs.h"
#include "csfsconhash.h"


#define CSFSMON_CONHASH_DEFAULT_HASH_ALGO       CHASH_MD5_ALGO_ID

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;

    CVECTOR              csfs_node_vec; /*item is CSFS_NODE*/

    CSFSCONHASH         *csfsconhash;

}CSFSMON_MD;

#define CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md)        (&((csfsmon_md)->csfs_node_vec))
#define CSFSMON_MD_CSFSCONHASH(csfsmon_md)          ((csfsmon_md)->csfsconhash)

#define CSFS_NODE_IS_ERR          ((UINT32)0x0000)
#define CSFS_NODE_IS_UP           ((UINT32)0x0001)
#define CSFS_NODE_IS_DOWN         ((UINT32)0x0002)

typedef struct
{
    UINT32          tcid;
    UINT32          ipaddr;
    UINT32          port;
    UINT32          modi;
    
    UINT32          state;
}CSFS_NODE;

#define CSFS_NODE_TCID(csfs_node)                ((csfs_node)->tcid)
#define CSFS_NODE_IPADDR(csfs_node)              ((csfs_node)->ipaddr)
#define CSFS_NODE_PORT(csfs_node)                ((csfs_node)->port)
#define CSFS_NODE_MODI(csfs_node)                ((csfs_node)->modi)
#define CSFS_NODE_STATE(csfs_node)               ((csfs_node)->state)

/**
*   for test only
*
*   to query the status of CSFSMON Module
*
**/
void csfsmon_print_module_status(const UINT32 csfsmon_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CSFSMON module
*
*
**/
UINT32 csfsmon_free_module_static_mem(const UINT32 csfsmon_md_id);

/**
*
* start CSFSMON module
*
**/
UINT32 csfsmon_start();

/**
*
* end CSFSMON module
*
**/
void csfsmon_end(const UINT32 csfsmon_md_id);

CSFS_NODE *csfs_node_new();

EC_BOOL csfs_node_init(CSFS_NODE *csfs_node);

EC_BOOL csfs_node_clean(CSFS_NODE *csfs_node);

EC_BOOL csfs_node_free(CSFS_NODE *csfs_node);

EC_BOOL csfs_node_clone(CSFS_NODE *csfs_node_des, const CSFS_NODE *csfs_node_src);

EC_BOOL csfs_node_is_up(const CSFS_NODE *csfs_node);

EC_BOOL csfs_node_is_valid(const CSFS_NODE *csfs_node);

int csfs_node_cmp(const CSFS_NODE *csfs_node_1st, const CSFS_NODE *csfs_node_2nd);

const char *csfs_node_state(const CSFS_NODE *csfs_node);

void csfs_node_print(const CSFS_NODE *csfs_node, LOG *log);

void csfsmon_csfs_node_print(const UINT32 csfsmon_md_id, LOG *log);

void csfsmon_csfs_node_list(const UINT32 csfsmon_md_id, CSTRING *cstr);

EC_BOOL csfsmon_csfs_node_num(const UINT32 csfsmon_md_id, UINT32 *num);

EC_BOOL csfsmon_csfs_node_add(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_del(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_set_up(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_set_down(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_is_up(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_get_by_pos(const UINT32 csfsmon_md_id, const UINT32 pos, CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_get_by_tcid(const UINT32 csfsmon_md_id, const UINT32 tcid, const UINT32 modi, CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_get_by_hash(const UINT32 csfsmon_md_id, const UINT32 hash, CSFS_NODE *csfs_node);

EC_BOOL csfsmon_csfs_node_get_by_path(const UINT32 csfsmon_md_id, const uint8_t *path, const uint32_t path_len, CSFS_NODE *csfs_node);


#endif /*_CSFSMON_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

