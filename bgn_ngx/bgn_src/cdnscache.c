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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "cparacfg.inc"
#include "task.h"

#include "chashalgo.h"
#include "cdnscache.h"


static CDNSCACHE    g_cdnscache;
static EC_BOOL      g_cdnscache_init_flag = EC_FALSE;

STATIC_CAST static UINT32 __cdnscache_domain_hash(const CSTRING *domain)
{
    return JS_hash(cstring_get_len(domain), cstring_get_str(domain));
}

CDNSCACHE_NODE *cdnscache_node_new()
{
    CDNSCACHE_NODE *cdnscache_node;

    alloc_static_mem(MM_CDNSCACHE_NODE, &cdnscache_node, LOC_CDNSCACHE_0001);
    if(NULL_PTR != cdnscache_node)
    {
        cdnscache_node_init(cdnscache_node);
    }
    return (cdnscache_node);
}

EC_BOOL  cdnscache_node_init(CDNSCACHE_NODE *cdnscache_node)
{
    CDNSCACHE_NODE_HASH(cdnscache_node) = 0;

    cstring_init(CDNSCACHE_NODE_DOMAIN(cdnscache_node), NULL_PTR);
    CDNSCACHE_NODE_NEXST_POS(cdnscache_node) = 0;

    cvector_init(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node), 4,
                MM_UINT32, CVECTOR_LOCK_DISABLE, LOC_CDNSCACHE_0002);

    CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node) = 0;

    return (EC_TRUE);
}

EC_BOOL  cdnscache_node_clean(CDNSCACHE_NODE *cdnscache_node)
{
    if(NULL_PTR != cdnscache_node)
    {
        CDNSCACHE_NODE_HASH(cdnscache_node) = 0;

        cstring_clean(CDNSCACHE_NODE_DOMAIN(cdnscache_node));
        CDNSCACHE_NODE_NEXST_POS(cdnscache_node) = 0;

        cvector_clean(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node), NULL_PTR,LOC_CDNSCACHE_0003);

        CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL  cdnscache_node_free(CDNSCACHE_NODE *cdnscache_node)
{
    if(NULL_PTR != cdnscache_node)
    {
        cdnscache_node_clean(cdnscache_node);
        free_static_mem(MM_CDNSCACHE_NODE, cdnscache_node, LOC_CDNSCACHE_0004);
    }
    return (EC_TRUE);
}

int cdnscache_node_cmp(const CDNSCACHE_NODE *cdnscache_node_1st, const CDNSCACHE_NODE *cdnscache_node_2nd)
{
    if(CDNSCACHE_NODE_HASH(cdnscache_node_1st) > CDNSCACHE_NODE_HASH(cdnscache_node_2nd))
    {
        return (1);
    }

    if(CDNSCACHE_NODE_HASH(cdnscache_node_1st) < CDNSCACHE_NODE_HASH(cdnscache_node_2nd))
    {
        return (-1);
    }

    return cstring_cmp(CDNSCACHE_NODE_DOMAIN(cdnscache_node_1st), CDNSCACHE_NODE_DOMAIN(cdnscache_node_2nd));
}

void cdnscache_node_print(LOG *log, const CDNSCACHE_NODE *cdnscache_node)
{
    if(NULL_PTR != cdnscache_node)
    {
        UINT32      pos;
        UINT32      num;

        uint64_t        time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        if(time_msec_cur < CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node))
        {
            sys_log(log, "cdnscache_node_print: "
                         "cdnscache_node %p, domain %s, hash %u, "
                         "expired %ld (left %ld ms), next %ld\n",
                         cdnscache_node,
                         CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node),
                         CDNSCACHE_NODE_HASH(cdnscache_node),
                         CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node),
                         CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node) - time_msec_cur,
                         CDNSCACHE_NODE_NEXST_POS(cdnscache_node));
        }
        else
        {
            sys_log(log, "cdnscache_node_print: "
                         "cdnscache_node %p, domain %s, hash %u, "
                         "expired %ld (left -), next %ld\n",
                         cdnscache_node,
                         CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node),
                         CDNSCACHE_NODE_HASH(cdnscache_node),
                         CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node),
                         CDNSCACHE_NODE_NEXST_POS(cdnscache_node));
        }

        num = cvector_size(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node));

        sys_log(log, "cdnscache_node_print: "
                     "cdnscache_node %p, %ld ipv4(s):\n",
                     cdnscache_node, num);

        for(pos = 0; pos < num; pos ++)
        {
            UINT32      ipv4;

            ipv4 = (UINT32)cvector_get(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node), pos);
            sys_log(log, "cdnscache_node_print: "
                         "ipv4 [%ld/%ld] %s\n",
                         pos + 1, num, c_word_to_ipv4(ipv4));
        }
    }

    return;
}

EC_BOOL cdnscache_node_set_domain(CDNSCACHE_NODE *cdnscache_node, const CSTRING *domain)
{
    if(NULL_PTR != cdnscache_node && NULL_PTR != domain)
    {
        cstring_clone(domain, CDNSCACHE_NODE_DOMAIN(cdnscache_node));

        CDNSCACHE_NODE_HASH(cdnscache_node) = __cdnscache_domain_hash(
                                                    CDNSCACHE_NODE_DOMAIN(cdnscache_node));
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdnscache_node_set_expired(CDNSCACHE_NODE *cdnscache_node, const UINT32 expired_nsec)
{
    if(NULL_PTR != cdnscache_node)
    {
        CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node) = c_get_cur_time_msec()
                                                    + DNS_CACHE_EXPIRED_NSEC * 1000;
    }

    return (EC_TRUE);
}

EC_BOOL  cdnscache_node_add_ipv4(CDNSCACHE_NODE *cdnscache_node, const UINT32 ipv4)
{
    if(NULL_PTR != cdnscache_node)
    {
#if 0
        if(CVECTOR_ERR_POS != cvector_search_front(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node),
                                                    (const void *)ipv4, NULL_PTR))
        {
            dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_node_add_ipv4: "
                                "ipv4 %s is already in domain %s\n",
                                c_word_to_ipv4(ipv4),
                                CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

            return (EC_FALSE);
        }
#endif
        cvector_push(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node), (const void *)ipv4);

        dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_node_add_ipv4: "
                            "push ipv4 %s to domain %s done\n",
                            c_word_to_ipv4(ipv4),
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL  cdnscache_node_del_ipv4(CDNSCACHE_NODE *cdnscache_node, const UINT32 ipv4)
{
    if(NULL_PTR != cdnscache_node)
    {
        UINT32  pos;

        pos = cvector_search_front(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node),
                                (const void *)ipv4, NULL_PTR);

        if(CVECTOR_ERR_POS == pos)
        {
            dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_node_del_ipv4: "
                                "ipv4 %s is not in domain %s\n",
                                c_word_to_ipv4(ipv4),
                                CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

            return (EC_TRUE);
        }

        cvector_erase(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node), pos);

        dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_node_del_ipv4: "
                            "ipv4 %s is erased from domain %s\n",
                            c_word_to_ipv4(ipv4),
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*round robbin*/
EC_BOOL  cdnscache_node_fetch_ipv4(CDNSCACHE_NODE *cdnscache_node, UINT32 *ipv4)
{
    UINT32  pos;
    UINT32  num;

    num = cvector_size(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node));
    if(0 == num)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_node_fetch_ipv4: "
                            "no ipv4 in domain %s\n",
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
        return (EC_FALSE);
    }

    pos  = CDNSCACHE_NODE_NEXST_POS(cdnscache_node) % num;

    if(NULL_PTR != ipv4)
    {
        (*ipv4) = (UINT32)cvector_get(CDNSCACHE_NODE_IPV4_VEC(cdnscache_node), pos);

        dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_node_fetch_ipv4: "
                            "ipv4 %s at pos %ld in domain %s\n",
                            c_word_to_ipv4(*ipv4),
                            pos,
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
    }

    /*round robbin: move to next*/
    CDNSCACHE_NODE_NEXST_POS(cdnscache_node) = (pos + 1) % num;

    return (EC_TRUE);
}

CDNSCACHE *cdnscache_new()
{
    CDNSCACHE *cdnscache;

    alloc_static_mem(MM_CDNSCACHE, &cdnscache, LOC_CDNSCACHE_0005);
    if(NULL_PTR != cdnscache)
    {
        cdnscache_init(cdnscache);
    }
    return (cdnscache);
}

EC_BOOL  cdnscache_init(CDNSCACHE *cdnscache)
{
    crb_tree_init(CDNSCACHE_RB_TREE(cdnscache),
                    (CRB_DATA_CMP  )cdnscache_node_cmp,
                    (CRB_DATA_FREE )cdnscache_node_free,
                    (CRB_DATA_PRINT)cdnscache_node_print);

    return (EC_TRUE);
}

EC_BOOL  cdnscache_clean(CDNSCACHE *cdnscache)
{
    if(NULL_PTR != cdnscache)
    {
        crb_tree_clean(CDNSCACHE_RB_TREE(cdnscache));
    }
    return (EC_TRUE);
}

EC_BOOL  cdnscache_free(CDNSCACHE *cdnscache)
{
    if(NULL_PTR != cdnscache)
    {
        cdnscache_clean(cdnscache);
        free_static_mem(MM_CDNSCACHE, cdnscache, LOC_CDNSCACHE_0006);
    }
    return (EC_TRUE);
}

void  cdnscache_print(LOG *log, const CDNSCACHE *cdnscache)
{
    if(NULL_PTR != cdnscache)
    {
        crb_tree_print(log, CDNSCACHE_RB_TREE(cdnscache));
    }
    return;
}

EC_BOOL cdnscache_add_node(CDNSCACHE *cdnscache, CDNSCACHE_NODE *cdnscache_node)
{
    CRB_NODE    *crb_node;

    if(0 == CDNSCACHE_NODE_HASH(cdnscache_node))
    {
        CDNSCACHE_NODE_HASH(cdnscache_node) =
                __cdnscache_domain_hash(CDNSCACHE_NODE_DOMAIN(cdnscache_node));
    }

    crb_node = crb_tree_insert_data(CDNSCACHE_RB_TREE(cdnscache), (void *)cdnscache_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_add_node: "
                            "add domain %s failed\n",
                             CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cdnscache_node) /*found duplicate*/
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_add_node: "
                            "found duplicate domain %s\n",
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
        return (EC_FALSE);
    }

    dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_add_node: "
                        "add domain %s done\n",
                         CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

    return (EC_TRUE);
}

EC_BOOL cdnscache_del_node(CDNSCACHE *cdnscache, CDNSCACHE_NODE *cdnscache_node)
{
    if(0 == CDNSCACHE_NODE_HASH(cdnscache_node))
    {
        CDNSCACHE_NODE_HASH(cdnscache_node) =
                __cdnscache_domain_hash(CDNSCACHE_NODE_DOMAIN(cdnscache_node));
    }

    if(EC_FALSE == crb_tree_delete_data(CDNSCACHE_RB_TREE(cdnscache), cdnscache_node))
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_del_node: "
                            "del domain %s failed\n",
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

        return (EC_FALSE);
    }

    dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_del_node: "
                        "del domain %s done\n",
                        CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
    return (EC_TRUE);
}

CDNSCACHE_NODE *cdnscache_get_node(CDNSCACHE *cdnscache, const CSTRING *domain)
{
    CDNSCACHE_NODE *cdnscache_node;
    CRB_NODE       *crb_node;

    cdnscache_node = cdnscache_node_new();
    if(NULL_PTR == cdnscache_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_get_node: "
                            "new cdnscache_node for domain %s failed\n",
                            (const char *)cstring_get_str(domain));

        return (NULL_PTR);
    }

    cdnscache_node_set_domain(cdnscache_node, domain);

    crb_node = crb_tree_search_data(CDNSCACHE_RB_TREE(cdnscache), cdnscache_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_get_node: "
                            "search domain %s failed\n",
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

        cdnscache_node_free(cdnscache_node);
        return (NULL_PTR);
    }

    dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_get_node: "
                        "search domain %s done\n",
                        CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

    cdnscache_node_free(cdnscache_node);
    return (CDNSCACHE_NODE *)CRB_NODE_DATA(crb_node);
}

CDNSCACHE_NODE *cdnscache_push_domain(CDNSCACHE *cdnscache, const CSTRING *domain)
{
    CDNSCACHE_NODE *cdnscache_node;
    CRB_NODE       *crb_node;

    cdnscache_node = cdnscache_node_new();
    if(NULL_PTR == cdnscache_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_push_domain: "
                            "new cdnscache_node for domain %s failed\n",
                            (const char *)cstring_get_str(domain));

        return (NULL_PTR);
    }

    cdnscache_node_set_domain(cdnscache_node, domain);

    crb_node = crb_tree_insert_data(CDNSCACHE_RB_TREE(cdnscache), (void *)cdnscache_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_push_domain: "
                            "push domain %s failed\n",
                             CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

        cdnscache_node_free(cdnscache_node);
        return (NULL_PTR);
    }

    if(CRB_NODE_DATA(crb_node) != cdnscache_node) /*found duplicate*/
    {
        dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_push_domain: "
                            "found duplicate domain %s\n",
                             CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

        cdnscache_node_free(cdnscache_node);
        return (CDNSCACHE_NODE *)CRB_NODE_DATA(crb_node);
    }

    dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_push_domain: "
                        "push domain %s done\n",
                         CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

    return (cdnscache_node);
}

EC_BOOL cdnscache_pop_domain(CDNSCACHE *cdnscache, const CSTRING *domain)
{
    CDNSCACHE_NODE *cdnscache_node;

    cdnscache_node = cdnscache_node_new();
    if(NULL_PTR == cdnscache_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_pop_domain: "
                            "new cdnscache_node for domain %s failed\n",
                            (const char *)cstring_get_str(domain));

        return (EC_FALSE);
    }

    cdnscache_node_set_domain(cdnscache_node, domain);

    if(EC_FALSE == crb_tree_delete_data(CDNSCACHE_RB_TREE(cdnscache), cdnscache_node))
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_pop_domain: "
                            "pop domain %s failed\n",
                             CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

        cdnscache_node_free(cdnscache_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_pop_domain: "
                        "pop domain %s done\n",
                         CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

    cdnscache_node_free(cdnscache_node);
    return (EC_TRUE);
}

CDNSCACHE_NODE *cdnscache_search_domain(CDNSCACHE *cdnscache, const CSTRING *domain)
{
    return cdnscache_get_node(cdnscache, domain);
}

/* ------------------------------ external interface ------------------------------ */

EC_BOOL cdnscache_dns_show(LOG *log, const char *domain)
{
    CSTRING             domain_cstr;
    CDNSCACHE_NODE     *cdnscache_node;

    if(EC_FALSE == g_cdnscache_init_flag)
    {
        cdnscache_init(&g_cdnscache);
        g_cdnscache_init_flag = EC_TRUE;
    }

    cstring_set_str(&domain_cstr, (const UINT8 *)domain);/*mount*/

    cdnscache_node = cdnscache_get_node(&g_cdnscache, &domain_cstr);
    if(NULL_PTR == cdnscache_node)
    {
        sys_log(log, "(none)\n");
        return (EC_TRUE);
    }

    cdnscache_node_print(log, cdnscache_node);

    return (EC_TRUE);
}

EC_BOOL cdnscache_dns_resolve(const char *domain, UINT32 *ipv4)
{
    CSTRING             domain_cstr;
    CDNSCACHE_NODE     *cdnscache_node;
    UINT32              ipv4s[ CDNSCACHE_MAX_RESOLVED_NUM ];
    UINT32              ipv4_num;
    UINT32              ipv4_idx;

    if(EC_FALSE == g_cdnscache_init_flag)
    {
        cdnscache_init(&g_cdnscache);
        g_cdnscache_init_flag = EC_TRUE;
    }

    cstring_set_str(&domain_cstr, (const UINT8 *)domain);/*mount*/

    cdnscache_node = cdnscache_get_node(&g_cdnscache, &domain_cstr);
    while(NULL_PTR != cdnscache_node)
    {
        uint64_t        time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        /*check expired is ok*/
        if(time_msec_cur >= CDNSCACHE_NODE_EXPIRED_MSEC(cdnscache_node))
        {
            /*note: cdnscache_node would be free*/
            cdnscache_del_node(&g_cdnscache, cdnscache_node);
            cdnscache_node = NULL_PTR;

            dbg_log(SEC_0065_CDNSCACHE, 5)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                                "expired domain %s => del\n",
                                domain);
            break;/*fall through*/
        }

        if(EC_FALSE == cdnscache_node_fetch_ipv4(cdnscache_node, ipv4))
        {
            /*note: cdnscache_node would be free*/
            cdnscache_del_node(&g_cdnscache, cdnscache_node);
            cdnscache_node = NULL_PTR;

            dbg_log(SEC_0065_CDNSCACHE, 5)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                                "fetch ipv4 from domain %s failed => del\n",
                                domain);
            break;/*fall through*/
        }

        if(NULL_PTR != ipv4)
        {
            dbg_log(SEC_0065_CDNSCACHE, 5)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                                "resolve domain %s => ip %s\n",
                                domain, c_word_to_ipv4(*ipv4));
        }

        return (EC_TRUE); /*terminate*/
    }

    if(EC_FALSE == c_dns_resolve_all(domain, (UINT32 *)ipv4s,
                                        sizeof(ipv4s)/sizeof(ipv4s[0]), &ipv4_num))
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_dns_resolve: "
                            "resolve domain %s failed\n",
                             domain);
        return (EC_FALSE);
    }

    if(0 == ipv4_num)
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_dns_resolve: "
                            "resolve domain %s but obtain nothing\n",
                             domain);
        return (EC_FALSE);
    }

    dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                        "resolve domain %s done => %ld ipv4s\n",
                         domain, ipv4_num);

    cdnscache_node = cdnscache_node_new();
    if(NULL_PTR == cdnscache_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 5)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                            "new cdnscache_node failed\n");
        return (EC_FALSE);
    }

    cdnscache_node_set_domain(cdnscache_node, &domain_cstr);
    cdnscache_node_set_expired(cdnscache_node, DNS_CACHE_EXPIRED_NSEC);

    for(ipv4_idx = 0; ipv4_idx < ipv4_num; ipv4_idx ++)
    {
        cdnscache_node_add_ipv4(cdnscache_node, ipv4s[ ipv4_idx ]);

        dbg_log(SEC_0065_CDNSCACHE, 6)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                            "add ipv4 %s to domain %s\n",
                            c_word_to_ipv4(ipv4s[ ipv4_idx ]),
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
    }

    if(NULL_PTR != ipv4)
    {
        if(EC_FALSE == cdnscache_node_fetch_ipv4(cdnscache_node, ipv4))
        {
            dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_dns_resolve: "
                                "fetch ipv4 from cdnscache_node of domain %s failed\n",
                                CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

            cdnscache_node_free(cdnscache_node);
            return (EC_FALSE);
        }

        dbg_log(SEC_0065_CDNSCACHE, 5)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                            "fetch ipv4 %s from cdnscache_node of domain %s done\n",
                            c_word_to_ipv4(*ipv4),
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));
    }

    if(EC_FALSE == cdnscache_add_node(&g_cdnscache, cdnscache_node))
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_dns_resolve: "
                            "add cdnscache_node of domain %s failed\n",
                            CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

        cdnscache_node_free(cdnscache_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0065_CDNSCACHE, 9)(LOGSTDOUT, "[DEBUG] cdnscache_dns_resolve: "
                        "add cdnscache_node of domain %s done\n",
                        CDNSCACHE_NODE_DOMAIN_STR(cdnscache_node));

    return (EC_TRUE);
}

EC_BOOL cdnscache_dns_retire(const char *domain, const UINT32 ipv4)
{
    CSTRING             domain_cstr;
    CDNSCACHE_NODE     *cdnscache_node;

    if(EC_FALSE == g_cdnscache_init_flag)
    {
        cdnscache_init(&g_cdnscache);
        g_cdnscache_init_flag = EC_TRUE;
    }

    cstring_set_str(&domain_cstr, (const UINT8 *)domain);/*mount*/

    cdnscache_node = cdnscache_get_node(&g_cdnscache, &domain_cstr);
    if(NULL_PTR == cdnscache_node)
    {
        dbg_log(SEC_0065_CDNSCACHE, 5)(LOGSTDOUT, "[DEBUG] cdnscache_dns_retire: "
                            "no domain %s => retire ipv4 %s done\n",
                            domain, c_word_to_ipv4(ipv4));
        return (EC_TRUE);
    }

    if(EC_FALSE == cdnscache_node_del_ipv4(cdnscache_node, ipv4))
    {
        dbg_log(SEC_0065_CDNSCACHE, 0)(LOGSTDOUT, "error:cdnscache_dns_retire: "
                            "domain %s retire ipv4 %s failed\n",
                            domain, c_word_to_ipv4(ipv4));
        return (EC_FALSE);
    }

    dbg_log(SEC_0065_CDNSCACHE, 5)(LOGSTDOUT, "[DEBUG] cdnscache_dns_retire: "
                        "domain %s retire ipv4 %s done\n",
                        domain, c_word_to_ipv4(ipv4));
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

