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

#ifndef _CTDNS_H
#define _CTDNS_H

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "cstrkv.h"

#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#include "ctdnsnp.h"
#include "ctdnsnpmgr.h"


#define CTDNS_MAX_MODI                       ((UINT32)32)

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CTDNSNP_MGR         *ctdnsnpmgr;/*namespace pool*/

}CTDNS_MD;

#define CTDNS_MD_TERMINATE_FLAG(ctdns_md)    ((ctdns_md)->terminate_flag)
#define CTDNS_MD_NPP(ctdns_md)               ((ctdns_md)->ctdnsnpmgr)


/**
*   for test only
*
*   to query the status of CTDNS Module
*
**/
void ctdns_print_module_status(const UINT32 ctdns_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CTDNS module
*
*
**/
UINT32 ctdns_free_module_static_mem(const UINT32 ctdns_md_id);

/**
*
* start CTDNS module
*
**/
UINT32 ctdns_start(const CSTRING *ctdns_root_dir);

/**
*
* end CTDNS module
*
**/
void ctdns_end(const UINT32 ctdns_md_id);

EC_BOOL ctdns_flush(const UINT32 ctdns_md_id);

/**
*
*  get name node pool of the module
*
**/
CTDNSNP_MGR *ctdns_get_npp(const UINT32 ctdns_md_id);

/**
*
*  open name node pool
*
**/
EC_BOOL ctdns_open_npp(const UINT32 ctdns_md_id, const CSTRING *ctdnsnp_db_root_dir);

/**
*
*  close name node pool
*
**/
EC_BOOL ctdns_close_npp(const UINT32 ctdns_md_id);

/**
*
*  create name node pool
*
**/
EC_BOOL ctdns_create_npp(const UINT32 ctdns_md_id,
                             const UINT32 ctdnsnp_model,
                             const UINT32 ctdnsnp_max_num,
                             const UINT32 ctdnsnp_2nd_chash_algo_id,
                             const CSTRING *ctdnsnp_db_root_dir);

/**
*
*  check existing of a tcid
*
**/
EC_BOOL ctdns_exists(const UINT32 ctdns_md_id, const UINT32 tcid);

/**
*
*  set a tcid
*
**/
EC_BOOL ctdns_set(const UINT32 ctdns_md_id, const UINT32 tcid, const UINT32 ipaddr, const CBYTES *key_cbytes);

/**
*
*  get a tcid
*
**/
EC_BOOL ctdns_get(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, CBYTES *key_cbytes);


/**
*
*  delete a tcid
*
**/
EC_BOOL ctdns_delete(const UINT32 ctdns_md_id, const UINT32 tcid);

/**
*
*  flush name node pool
*
**/
EC_BOOL ctdns_flush_npp(const UINT32 ctdns_md_id);

/**
*
*  count tcid num
*
**/
EC_BOOL ctdns_tcid_num(const UINT32 ctdns_md_id, UINT32 *tcid_num);

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL ctdns_show_npp(const UINT32 ctdns_md_id, LOG *log);



#endif /*_CTDNS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

