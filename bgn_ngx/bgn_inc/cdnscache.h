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

#ifndef _CDNSCACHE_H
#define _CDNSCACHE_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "cvector.h"
#include "crb.h"

#define CDNSCACHE_MAX_RESOLVED_NUM      (16)

typedef struct
{
    uint32_t        hash;           /*hash of domain*/
    uint32_t        rsvd01;
    CSTRING         domain;

    UINT32          next_pos;       /*next use ipv4 pos*/
    CVECTOR         ipv4_vec;       /*item is UINT32(ipv4)*/

    uint64_t        expired_msec;   /*expired time in msec*/
}CDNSCACHE_NODE;

#define CDNSCACHE_NODE_HASH(cdnscache_node)             ((cdnscache_node)->hash)
#define CDNSCACHE_NODE_DOMAIN(cdnscache_node)           (&((cdnscache_node)->domain))
#define CDNSCACHE_NODE_NEXST_POS(cdnscache_node)        ((cdnscache_node)->next_pos)
#define CDNSCACHE_NODE_IPV4_VEC(cdnscache_node)         (&((cdnscache_node)->ipv4_vec))
#define CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node)     ((cdnscache_node)->expired_msec)

#define CDNSCACHE_NODE_DOMAIN_LEN(cdnscache_node)       (cstring_get_len(CDNSCACHE_NODE_DOMAIN(cdnscache_node)))
#define CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node)       ((char *)cstring_get_str(CDNSCACHE_NODE_DOMAIN(cdnscache_node)))

typedef struct
{
    CRB_TREE        dns_cache_tree;
}CDNSCACHE;

#define CDNSCACHE_RB_TREE(cdnscache)        (&((cdnscache)->dns_cache_tree))

CDNSCACHE_NODE *cdnscache_node_new();

EC_BOOL  cdnscache_node_init(CDNSCACHE_NODE *cdnscache_node);

EC_BOOL  cdnscache_node_clean(CDNSCACHE_NODE *cdnscache_node);

EC_BOOL  cdnscache_node_free(CDNSCACHE_NODE *cdnscache_node);

int cdnscache_node_cmp(const CDNSCACHE_NODE *cdnscache_node_1st, const CDNSCACHE_NODE *cdnscache_node_2nd);

void cdnscache_node_print(LOG *log, const CDNSCACHE_NODE *cdnscache_node);

EC_BOOL cdnscache_node_set_domain(CDNSCACHE_NODE *cdnscache_node, const CSTRING *domain);

EC_BOOL cdnscache_node_set_expired(CDNSCACHE_NODE *cdnscache_node, const UINT32 expired_nsec);

EC_BOOL  cdnscache_node_add_ipv4(CDNSCACHE_NODE *cdnscache_node, const UINT32 ipv4);

EC_BOOL  cdnscache_node_del_ipv4(CDNSCACHE_NODE *cdnscache_node, const UINT32 ipv4);

CDNSCACHE *cdnscache_new();

EC_BOOL  cdnscache_init(CDNSCACHE *cdnscache);

EC_BOOL  cdnscache_clean(CDNSCACHE *cdnscache);

EC_BOOL  cdnscache_free(CDNSCACHE *cdnscache);

void  cdnscache_print(LOG *log, const CDNSCACHE *cdnscache);

EC_BOOL cdnscache_add_node(CDNSCACHE *cdnscache, CDNSCACHE_NODE *cdnscache_node);

CDNSCACHE_NODE *cdnscache_get_node(CDNSCACHE *cdnscache, const CSTRING *domain);

CDNSCACHE_NODE *cdnscache_push_domain(CDNSCACHE *cdnscache, const CSTRING *domain);

EC_BOOL cdnscache_pop_domain(CDNSCACHE *cdnscache, const CSTRING *domain);

CDNSCACHE_NODE *cdnscache_search_domain(CDNSCACHE *cdnscache, const CSTRING *domain);

/*external interface*/
EC_BOOL cdnscache_dns_show(LOG *log, const char *domain);
EC_BOOL cdnscache_dns_resolve(const char *domain, UINT32 *ipv4);
EC_BOOL cdnscache_dns_retire(const char *domain, const UINT32 ipv4);

#endif/* _CDNSCACHE_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
