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

#ifndef _CDETECTN_H
#define _CDETECTN_H

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"
#include "crb.h"
#include "chashalgo.h"
#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"


/*CDTECT NODE MODULE*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    /*import conf into orig node tree and keep updating it*/
    CRB_TREE             orig_node_tree;    /*item is CDETECTN_ORIG_NODE. orgnized by domain*/

    /*detection worker do*/
    CLIST                detect_node_list; /*item is a pointer to CDETECTN_ORIG_NODE [A.1]*/

    UINT32               detect_task_num;/*the living detecting task/request num*/
}CDETECTN_MD;

#define CDETECTN_MD_TERMINATE_FLAG(cdetectn_md)    ((cdetectn_md)->terminate_flag)
#define CDETECTN_MD_ORIG_NODE_TREE(cdetectn_md)    (&((cdetectn_md)->orig_node_tree))
#define CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md)  (&((cdetectn_md)->detect_node_list))
#define CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md)   ((cdetectn_md)->detect_task_num)

#define CDETECTN_ORIG_NODE_CHOICE_ERR             ((uint32_t)   0)
#define CDETECTN_ORIG_NODE_CHOICE_RRB             ((uint32_t)   1) /*round-robbin*/
#define CDETECTN_ORIG_NODE_CHOICE_FAST            ((uint32_t)   2) /*lowest time-cost*/
#define CDETECTN_ORIG_NODE_CHOICE_LATEST          ((uint32_t)   3) /*latest accessed*/
#define CDETECTN_ORIG_NODE_CHOICE_MS              ((uint32_t)   4) /*master-slave*/

#define CDETECTN_ORIG_NODE_MAX_IP_NODES           (64)

#define CDETECTN_ORIG_NODE_NOT_DETECTING          ((uint32_t) 0)
#define CDETECTN_ORIG_NODE_IS_DETECTING           ((uint32_t) 1)

#define CDETECTN_ORIG_NODE_DOMAIN_HASH_ALGO       AP_hash

typedef struct
{
    CSTRING             domain;                /*orig domain*/
    CSTRING             url;                   /*orig url to check*/
    CLIST               ip_nodes;              /*orig ip nodes. item is CDETECTN_IP_NODE*/

    uint32_t            detect_interval_nsec;  /*orig detect interval in seconds*/
    uint32_t            detect_stopping_nsec;  /*orig detect stopping if no access in seconds*/

    uint32_t            reachable_status_beg;  /*orig return such status means orig is reachable*/
    uint32_t            reachable_status_end;  /*orig return such status means orig is reachable*/
    uint32_t            choice_strategy;       /*strategy to select orig*/
    uint32_t            domain_hash;           /*hash value of domain*/

    ctime_t             last_detect_time;      /*last detect time by worker*/
    ctime_t             last_access_time;      /*last access time by client*/

    CLIST_DATA         *last_reachable_ip_node;/*shortcut to last reachable ip node*/
    CLIST_DATA         *detect_orig_node;      /*shortcut to [A.1] list*/
}CDETECTN_ORIG_NODE;

#define CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node)                   (&((cdetectn_orig_node)->domain))
#define CDETECTN_ORIG_NODE_URL(cdetectn_orig_node)                      (&((cdetectn_orig_node)->url))
#define CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node)                 (&((cdetectn_orig_node)->ip_nodes))

#define CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node)               (cstring_get_str(CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node)))
#define CDETECTN_ORIG_NODE_URL_STR(cdetectn_orig_node)                  (cstring_get_str(CDETECTN_ORIG_NODE_URL(cdetectn_orig_node)))

#define CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node)     ((cdetectn_orig_node)->detect_interval_nsec)
#define CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node)     ((cdetectn_orig_node)->detect_stopping_nsec)

#define CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)     ((cdetectn_orig_node)->reachable_status_beg)
#define CDETECTN_ORIG_NODE_REACHABLE_STATUS_END(cdetectn_orig_node)     ((cdetectn_orig_node)->reachable_status_end)
#define CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)          ((cdetectn_orig_node)->choice_strategy)
#define CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node)              ((cdetectn_orig_node)->domain_hash)

#define CDETECTN_ORIG_NODE_LAST_DETECT_TIME(cdetectn_orig_node)         ((cdetectn_orig_node)->last_detect_time)
#define CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node)         ((cdetectn_orig_node)->last_access_time)
#define CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node)   ((cdetectn_orig_node)->last_reachable_ip_node)

#define CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node)         ((cdetectn_orig_node)->detect_orig_node)

#define CDETECTN_IP_NODE_STATUS_ERR              ((uint32_t)  ~0)
#define CDETECTN_IP_NODE_STATUS_REACHABLE        ((uint32_t)   1)

#define CDETECTN_IP_NODE_COST_MSEC_ERR           ((uint32_t)  ~0)
#define CDETECTN_IP_NODE_PORT_DEFAULT            (80)
typedef struct
{
    CSTRING            domain;
    UINT32             ipaddr;
    UINT32             port;

    uint32_t           status;
    uint32_t           detect_cost_msec;
}CDETECTN_IP_NODE;

#define CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)                  (&((cdetectn_ip_node)->domain))
#define CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node)              (cstring_get_str(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)))
#define CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)                  ((cdetectn_ip_node)->ipaddr)
#define CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node)              (c_word_to_ipv4(CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)))
#define CDETECTN_IP_NODE_PORT(cdetectn_ip_node)                    ((cdetectn_ip_node)->port)
#define CDETECTN_IP_NODE_STATUS(cdetectn_ip_node)                  ((cdetectn_ip_node)->status)
#define CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node)        ((cdetectn_ip_node)->detect_cost_msec)


/**
*   for test only
*
*   to query the status of CDETECTN Module
*
**/
void cdetectn_print_module_status(const UINT32 cdetectn_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CDETECTN module
*
*
**/
UINT32 cdetectn_free_module_static_mem(const UINT32 cdetectn_md_id);

/**
*
* start CDETECTN module
*
**/
UINT32 cdetectn_start();

/**
*
* end CDETECTN module
*
**/
void cdetectn_end(const UINT32 cdetectn_md_id);

/*------------------------------------------------ interface for cdetectn orig node ------------------------------------------------*/
CDETECTN_ORIG_NODE *cdetectn_orig_node_new();

EC_BOOL cdetectn_orig_node_init(CDETECTN_ORIG_NODE *cdetectn_orig_node);

EC_BOOL cdetectn_orig_node_clean(CDETECTN_ORIG_NODE *cdetectn_orig_node);

EC_BOOL cdetectn_orig_node_clear(CDETECTN_ORIG_NODE *cdetectn_orig_node);

EC_BOOL cdetectn_orig_node_free(CDETECTN_ORIG_NODE *cdetectn_orig_node);

int cdetectn_orig_node_cmp(const CDETECTN_ORIG_NODE *cdetectn_orig_node_1st, const CDETECTN_ORIG_NODE *cdetectn_orig_node_2nd);

void cdetectn_orig_node_print(LOG *log, const CDETECTN_ORIG_NODE *cdetectn_orig_node);

/*stop detecting or not*/
EC_BOOL cdetectn_orig_node_need_stop_detecting(const CDETECTN_ORIG_NODE *cdetectn_orig_node);

/*stop detecting or not*/
EC_BOOL cdetectn_orig_node_need_stop_detecting(const CDETECTN_ORIG_NODE *cdetectn_orig_node);

/*------------------------------------------------ interface for cdetectn ip node ------------------------------------------------*/
CDETECTN_IP_NODE *cdetectn_ip_node_new();

EC_BOOL cdetectn_ip_node_init(CDETECTN_IP_NODE *cdetectn_ip_node);

EC_BOOL cdetectn_ip_node_clean(CDETECTN_IP_NODE *cdetectn_ip_node);

EC_BOOL cdetectn_ip_node_clear(CDETECTN_IP_NODE *cdetectn_ip_node);

EC_BOOL cdetectn_ip_node_free(CDETECTN_IP_NODE *cdetectn_ip_node);

void cdetectn_ip_node_print(LOG *log, const CDETECTN_IP_NODE *cdetectn_ip_node);

void cdetectn_ip_node_print_plain(LOG *log, const CDETECTN_IP_NODE *cdetectn_ip_node);

/**
*
*  show orig nodes
*
*
**/
EC_BOOL cdetectn_show_orig_nodes(const UINT32 cdetectn_md_id, LOG *log);

/**
*
*  print single orig node
*
*
**/
EC_BOOL cdetectn_show_orig_node(const UINT32 cdetectn_md_id, const CSTRING *domain, LOG *log);

/*trick!*/
EC_BOOL cdetectn_parse_conf_line(const UINT32 cdetectn_md_id, const UINT32 cdetectn_conf_start, const UINT32 cdetectn_conf_end);

/**
*
*  load detect conf
*
*
**/
EC_BOOL cdetectn_load_conf(const UINT32 cdetectn_md_id, const CSTRING *cdetectn_conf_file);

/**
*
*  dns resolve
*   - return the first one in ip nodes
*
**/
EC_BOOL cdetectn_dns_resolve(const UINT32 cdetectn_md_id, const CSTRING *domain, UINT32 *ipaddr);

/**
*
*  start to detect domain
*
**/
EC_BOOL cdetectn_start_domain(const UINT32 cdetectn_md_id, const CSTRING *domain);

/**
*
*  stop to detect domain
*
**/
EC_BOOL cdetectn_stop_domain(const UINT32 cdetectn_md_id, const CSTRING *domain);

/**
*
*  process entry
*
**/
EC_BOOL cdetectn_process(const UINT32 cdetectn_md_id, const UINT32 detect_task_max_num);

/**
*
*  process loop
*
**/
EC_BOOL cdetectn_process_loop(const UINT32 cdetectn_md_id, const UINT32 detect_task_max_num);

#endif /*_CDETECTN_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


