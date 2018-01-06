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

#ifndef _CDETECT_H
#define _CDETECT_H

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"
#include "crb.h"
#include "chashalgo.h"
#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"


typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    /*import conf into orig node tree and keep updating it*/
    CRB_TREE             orig_node_tree;    /*item is CDETECT_ORIG_NODE. orgnized by domain*/

    /*detection worker do*/
    CLIST                detect_node_list; /*item is a pointer to CDETECT_ORIG_NODE [A.1]*/

    UINT32               detect_task_num;/*the living detecting task/request num*/
}CDETECT_MD;

#define CDETECT_MD_TERMINATE_FLAG(cdetect_md)    ((cdetect_md)->terminate_flag)
#define CDETECT_MD_ORIG_NODE_TREE(cdetect_md)    (&((cdetect_md)->orig_node_tree))
#define CDETECT_MD_DETECT_NODE_LIST(cdetect_md)  (&((cdetect_md)->detect_node_list))
#define CDETECT_MD_DETECT_TASK_NUM(cdetect_md)   ((cdetect_md)->detect_task_num)

#define CDETECT_ORIG_NODE_CHOICE_ERR             ((uint32_t)   0)
#define CDETECT_ORIG_NODE_CHOICE_RRB             ((uint32_t)   1) /*round-robbin*/
#define CDETECT_ORIG_NODE_CHOICE_FAST            ((uint32_t)   2) /*lowest time-cost*/
#define CDETECT_ORIG_NODE_CHOICE_RECENT          ((uint32_t)   3) /*recent/last accessed*/
#define CDETECT_ORIG_NODE_CHOICE_MS              ((uint32_t)   4) /*master-slave*/

#define CDETECT_ORIG_NODE_MAX_IP_NODES           (64)

#define CDETECT_ORIG_NODE_NOT_DETECTING          ((uint32_t) 0)
#define CDETECT_ORIG_NODE_IS_DETECTING           ((uint32_t) 1)

#define CDETECT_ORIG_NODE_DOMAIN_HASH_ALGO       AP_hash

typedef struct
{
    CSTRING             domain;                /*orig domain*/
    CSTRING             url;                   /*orig url to check*/
    CLIST               ip_nodes;              /*orig ip nodes. item is CDETECT_IP_NODE*/

    uint32_t            detect_interval_nsec;  /*orig detect interval in seconds*/ 
    uint32_t            detect_stopping_nsec;  /*orig detect stopping if no access in seconds*/

    uint32_t            status_reachable;      /*orig return such status means orig is reachable*/
    uint32_t            status_forbidden;      /*orig return such status means orig is forbidden*/
    uint32_t            choice_strategy;       /*strategy to select orig*/
    uint32_t            domain_hash;           /*hash value of domain*/     

    ctime_t             last_detect_time;      /*last detect time by worker*/
    ctime_t             last_access_time;      /*last access time by client*/
    
    CLIST_DATA         *last_reachable_ip_node;/*shortcut to last reachable ip node*/
    CLIST_DATA         *detect_orig_node;      /*shortcut to [A.1] list*/
}CDETECT_ORIG_NODE;

#define CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node)                   (&((cdetect_orig_node)->domain))
#define CDETECT_ORIG_NODE_URL(cdetect_orig_node)                      (&((cdetect_orig_node)->url))
#define CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node)                 (&((cdetect_orig_node)->ip_nodes))

#define CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node)               (cstring_get_str(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node)))
#define CDETECT_ORIG_NODE_URL_STR(cdetect_orig_node)                  (cstring_get_str(CDETECT_ORIG_NODE_URL(cdetect_orig_node)))

#define CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node)     ((cdetect_orig_node)->detect_interval_nsec)
#define CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node)     ((cdetect_orig_node)->detect_stopping_nsec)

#define CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node)         ((cdetect_orig_node)->status_reachable)
#define CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node)         ((cdetect_orig_node)->status_forbidden)
#define CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)          ((cdetect_orig_node)->choice_strategy)
#define CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node)              ((cdetect_orig_node)->domain_hash)

#define CDETECT_ORIG_NODE_LAST_DETECT_TIME(cdetect_orig_node)         ((cdetect_orig_node)->last_detect_time)
#define CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node)         ((cdetect_orig_node)->last_access_time)
#define CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node)   ((cdetect_orig_node)->last_reachable_ip_node)

#define CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node)         ((cdetect_orig_node)->detect_orig_node)

#define CDETECT_IP_NODE_STATUS_ERR              ((uint32_t)  ~0)
#define CDETECT_IP_NODE_STATUS_REACHABLE        ((uint32_t)   1)
#define CDETECT_IP_NODE_STATUS_FORBIDDEN        ((uint32_t)   2)

#define CDETECT_IP_NODE_COST_MSEC_ERR           ((uint32_t)  ~0) 
#define CDETECT_IP_NODE_PORT_DEFAULT            (80)
typedef struct
{
    UINT32             ipaddr;
    UINT32             port;
    
    uint32_t           status;
    uint32_t           detect_cost_msec;
}CDETECT_IP_NODE;

#define CDETECT_IP_NODE_IPADDR(cdetect_ip_node)                  ((cdetect_ip_node)->ipaddr)
#define CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node)              (c_word_to_ipv4(CDETECT_IP_NODE_IPADDR(cdetect_ip_node)))
#define CDETECT_IP_NODE_PORT(cdetect_ip_node)                    ((cdetect_ip_node)->port)
#define CDETECT_IP_NODE_STATUS(cdetect_ip_node)                  ((cdetect_ip_node)->status)
#define CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node)        ((cdetect_ip_node)->detect_cost_msec)


/**
*   for test only
*
*   to query the status of CDETECT Module
*
**/
void cdetect_print_module_status(const UINT32 cdetect_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CDETECT module
*
*
**/
UINT32 cdetect_free_module_static_mem(const UINT32 cdetect_md_id);

/**
*
* start CDETECT module
*
**/
UINT32 cdetect_start(const CSTRING *cdetect_conf_file);

/**
*
* end CDETECT module
*
**/
void cdetect_end(const UINT32 cdetect_md_id);

/*------------------------------------------------ interface for cdetect orig node ------------------------------------------------*/
CDETECT_ORIG_NODE *cdetect_orig_node_new();

EC_BOOL cdetect_orig_node_init(CDETECT_ORIG_NODE *cdetect_orig_node);

EC_BOOL cdetect_orig_node_clean(CDETECT_ORIG_NODE *cdetect_orig_node);

EC_BOOL cdetect_orig_node_clear(CDETECT_ORIG_NODE *cdetect_orig_node);

EC_BOOL cdetect_orig_node_free(CDETECT_ORIG_NODE *cdetect_orig_node);

int cdetect_orig_node_cmp(const CDETECT_ORIG_NODE *cdetect_orig_node_1st, const CDETECT_ORIG_NODE *cdetect_orig_node_2nd);

void cdetect_orig_node_print(LOG *log, const CDETECT_ORIG_NODE *cdetect_orig_node);

/*stop detecting or not*/
EC_BOOL cdetect_orig_node_need_stop_detecting(const CDETECT_ORIG_NODE *cdetect_orig_node);

/*stop detecting or not*/
EC_BOOL cdetect_orig_node_need_stop_detecting(const CDETECT_ORIG_NODE *cdetect_orig_node);

/*------------------------------------------------ interface for cdetect ip node ------------------------------------------------*/
CDETECT_IP_NODE *cdetect_ip_node_new();

EC_BOOL cdetect_ip_node_init(CDETECT_IP_NODE *cdetect_ip_node);

EC_BOOL cdetect_ip_node_clean(CDETECT_IP_NODE *cdetect_ip_node);

EC_BOOL cdetect_ip_node_clear(CDETECT_IP_NODE *cdetect_ip_node);

EC_BOOL cdetect_ip_node_free(CDETECT_IP_NODE *cdetect_ip_node);

void cdetect_ip_node_print(LOG *log, const CDETECT_IP_NODE *cdetect_ip_node);

void cdetect_ip_node_print_plain(LOG *log, const CDETECT_IP_NODE *cdetect_ip_node);

/**
*
*  show orig nodes
*
*
**/
EC_BOOL cdetect_show_orig_nodes(const UINT32 cdetect_md_id, LOG *log);

/**
*
*  print single orig node
*
*
**/
EC_BOOL cdetect_show_orig_node(const UINT32 cdetect_md_id, const CSTRING *domain, LOG *log);

/**
*
*  load detect conf
*
*
**/
EC_BOOL cdetect_load_conf(const UINT32 cdetect_md_id, const CSTRING *cdetect_conf_file);

/**
*
*  dns resolve
*   - return the first one in ip nodes
*
**/
EC_BOOL cdetect_dns_resolve(const UINT32 cdetect_md_id, const CSTRING *domain, UINT32 *ipaddr);

/**
*
*  start to detect domain
*
**/
EC_BOOL cdetect_start_domain(const UINT32 cdetect_md_id, const CSTRING *domain);

/**
*
*  stop to detect domain
*
**/
EC_BOOL cdetect_stop_domain(const UINT32 cdetect_md_id, const CSTRING *domain);

/**
*
*  process entry
*
**/
EC_BOOL cdetect_process(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num);

/**
*
*  process loop
*
**/
EC_BOOL cdetect_process_loop(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num);

#endif /*_CDETECT_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


