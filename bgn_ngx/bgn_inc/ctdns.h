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

#include "ctdnssv.h"
#include "ctdnssvmgr.h"


/*if ping elapsed time <= 10, accept it as edge node*/
#define CTDNS_EDGE_PING_MAX_NSEC    ((UINT32) 10)
#define CTDNS_EDGE_PING_MAX_MSEC    (CTDNS_EDGE_PING_MAX_NSEC * 1000)

#define CTDNS_NODE_DETECT_NSEC      ((UINT32) 1)
#define CTDNS_NODE_DETECT_MAX_FAILS ((UINT32)30)

/*suspicious service which detecting failed*/
typedef struct
{
    CSTRING     service;
    UINT32      tcid;
    UINT32      fails; /*failed times*/
}CTDNS_SUSV_NODE;

#define CTDNS_SUSV_NODE_SERVICE(ctdns_susv_node)           (&((ctdns_susv_node)->service))
#define CTDNS_SUSV_NODE_TCID(ctdns_susv_node)              ((ctdns_susv_node)->tcid)
#define CTDNS_SUSV_NODE_FAILS(ctdns_susv_node)             ((ctdns_susv_node)->fails)

typedef struct
{
    CLIST       mgr;
}CTDNS_SUSV;

#define CTDNS_SUSV_MGR(ctdns_susv)                         (&((ctdns_susv)->mgr))


typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING              root_dir;

    CTDNSNP_MGR         *ctdnsnpmgr;

    CTDNSSV_MGR         *ctdnssvmgr;

    CTDNS_SUSV           ctdns_susv;

}CTDNS_MD;

#define CTDNS_MD_TERMINATE_FLAG(ctdns_md)    ((ctdns_md)->terminate_flag)

#define CTDNS_MD_ROOT_DIR(ctdns_md)          (&((ctdns_md)->root_dir))
#define CTDNS_MD_ROOT_DIR_STR(ctdns_md)      (cstring_get_str(CTDNS_MD_ROOT_DIR(ctdns_md)))

#define CTDNS_MD_NPP(ctdns_md)               ((ctdns_md)->ctdnsnpmgr)
#define CTDNS_MD_SVP(ctdns_md)               ((ctdns_md)->ctdnssvmgr)

#define CTDNS_MD_SUSV(ctdns_md)              (&((ctdns_md)->ctdns_susv))


CSTRING *ctdns_gen_upper_service_name(const CSTRING *service_name);
CSTRING *ctdns_gen_edge_service_name(const CSTRING *service_name);

CTDNS_SUSV_NODE *ctdns_susv_node_new();

EC_BOOL ctdns_susv_node_init(CTDNS_SUSV_NODE *ctdns_susv_node);

EC_BOOL ctdns_susv_node_clean(CTDNS_SUSV_NODE *ctdns_susv_node);

EC_BOOL ctdns_susv_node_free(CTDNS_SUSV_NODE *ctdns_susv_node);

void    ctdns_susv_node_print(LOG *log, const CTDNS_SUSV_NODE *ctdns_susv_node);

EC_BOOL ctdns_susv_node_cmp(const CTDNS_SUSV_NODE *ctdns_susv_node_1st, const CTDNS_SUSV_NODE *ctdns_susv_node_2nd);

EC_BOOL ctdns_susv_init(CTDNS_SUSV *ctdns_susv);

EC_BOOL ctdns_susv_clean(CTDNS_SUSV *ctdns_susv);

void    ctdns_susv_print(LOG *log, const CTDNS_SUSV *ctdns_susv);

CTDNS_SUSV_NODE *ctdns_susv_search(CTDNS_SUSV *ctdns_susv, const CSTRING *service, const UINT32 tcid);

CTDNS_SUSV_NODE *ctdns_susv_delete(CTDNS_SUSV *ctdns_susv, const CSTRING *service, const UINT32 tcid);

EC_BOOL ctdns_susv_add(CTDNS_SUSV *ctdns_susv, const CSTRING *service, const UINT32 tcid, const UINT32 fails);


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

/**
*
*  set suspicious server to monitor
*
**/
EC_BOOL ctdns_set_susv(const UINT32 ctdns_md_id, const CSTRING *service, const UINT32 tcid, const UINT32 max_fails); 

/**
*
*  unset suspicious server from monitor
*
**/
EC_BOOL ctdns_unset_susv(const UINT32 ctdns_md_id, const CSTRING *service, const UINT32 tcid);

/**
*
*  flush npp and svp to disk
*
**/
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
                             const CSTRING *ctdnsnp_db_root_dir);

/**
*
*  check existing of a tcid
*
**/
EC_BOOL ctdns_exists_tcid(const UINT32 ctdns_md_id, const UINT32 tcid);

EC_BOOL ctdns_exists_service(const UINT32 ctdns_md_id, const CSTRING *service_name);

EC_BOOL ctdns_set_service(const UINT32 ctdns_md_id, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port, const CSTRING *service_name);

EC_BOOL ctdns_unset_service(const UINT32 ctdns_md_id, const UINT32 tcid, const CSTRING *service_name);

EC_BOOL ctdns_finger_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdns_finger_edge_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdns_finger_upper_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdns_reserve_tcid_from_service(const UINT32 ctdns_md_id, const CSTRING *service_name, UINT32 *tcid, UINT32 *port);

EC_BOOL ctdns_release_tcid_to_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid, const UINT32 port);

EC_BOOL ctdns_delete_tcid_from_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid);

EC_BOOL ctdns_delete_tcid_from_all_service(const UINT32 ctdns_md_id, const UINT32 tcid);


/**
*
*  set a tcid
*
**/
EC_BOOL ctdns_set_no_service(const UINT32 ctdns_md_id, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port);

EC_BOOL ctdns_set(const UINT32 ctdns_md_id, const UINT32 network_level, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port, const CSTRING *service_name);

/**
*
*  get a tcid
*
**/
EC_BOOL ctdns_get(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, UINT32 *port);


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
*  flush service pool
*
**/
EC_BOOL ctdns_flush_svp(const UINT32 ctdns_md_id);

/**
*
*  count tcid num
*
**/
EC_BOOL ctdns_tcid_num(const UINT32 ctdns_md_id, UINT32 *tcid_num);

/**
*
*  count node num fo specific service
*
**/
EC_BOOL ctdns_node_num(const UINT32 ctdns_md_id, const CSTRING *service_name, UINT32 *tcid_num);

/**
*
*  config a free tcid which is not used by anyone
*
**/
EC_BOOL ctdns_config_tcid(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid, const UINT32 port);

/**
*
*  reserve a tcid to use from specific service
*
**/
EC_BOOL ctdns_reserve_tcid(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 ipaddr, UINT32 *tcid, UINT32 *port); 

/**
*
*  release a used tcid to unused from specific service
*
**/
EC_BOOL ctdns_release_tcid(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid, const UINT32 port);

/**
*
*  show name node pool info
*
*
**/
EC_BOOL ctdns_show_npp(const UINT32 ctdns_md_id, LOG *log);

/**
*
*  show service pool info
*
*
**/
EC_BOOL ctdns_show_svp(const UINT32 ctdns_md_id, LOG *log);

/**
*
*  check this TDNS has namenode
*
*
**/
EC_BOOL ctdns_has_npp(const UINT32 ctdns_md_id);

/**
*
*  check this TDNS has service pool
*
*
**/
EC_BOOL ctdns_has_svp(const UINT32 ctdns_md_id);

/**
*
*  ping tcid and record the elapsed msec
*
*
**/
EC_BOOL ctdns_ping(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, UINT32 *port, UINT32 *elapsed_msec);

/**
*
*  online reporting
*
*
**/
EC_BOOL ctdns_online_notify(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name);

EC_BOOL ctdns_online(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name);

/**
*
*  offline reporting
*
*
**/
EC_BOOL ctdns_offline_notify(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name);

EC_BOOL ctdns_offline(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name);


/**
*
*  detect specific service nodes alive of service
*
*
**/
EC_BOOL ctdns_detect_service(const UINT32 ctdns_md_id, const CSTRING *service_name);

/**
*
*  detect edge nodes and upper nodes alive of service
*
*
**/
EC_BOOL ctdns_detect(const UINT32 ctdns_md_id);

/**
*
*  detect loop
*
*
**/
EC_BOOL ctdns_detect_loop(const UINT32 ctdns_md_id);

/**
*
*  detect task
*
*
**/
EC_BOOL ctdns_detect_task(const UINT32 ctdns_md_id);

#endif /*_CTDNS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

