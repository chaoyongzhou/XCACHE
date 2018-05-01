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

#include "type.h"
#include "mm.h"
#include "cmisc.h"
#include "log.h"

#include "cmpic.inc"

#include "cstring.h"
#include "cvector.h"

#include "json.h"
#include "cbase64code.h"

#include "cparacfg.h"
#include "csyscfg.h"


#include "chttp.h"
#include "chttps.h"

#include "cagent.h"

#include "ctdnshttp.h"

CAGENT *cagent_new()
{
    CAGENT *cagent;

    alloc_static_mem(MM_CAGENT, &cagent, LOC_CAGENT_0001);
    if(NULL_PTR == cagent)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_new: new cagent failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cagent_init(cagent))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_new: init cagent failed\n");
        free_static_mem(MM_CAGENT, cagent, LOC_CAGENT_0002);
        return (NULL_PTR);
    }

    return (cagent);
}

EC_BOOL cagent_init(CAGENT *cagent)
{
    cstring_init(CAGENT_TDNS_HOST(cagent), NULL_PTR);

    CAGENT_TDNS_PORT(cagent)     = CMPI_ERROR_SRVPORT;

    CAGENT_RESERVED_TCID(cagent) = CMPI_ERROR_TCID;
    CAGENT_RESERVED_PORT(cagent) = CMPI_ERROR_SRVPORT;

    CAGENT_LOCAL_IPADDR(cagent)  = CMPI_ERROR_IPADDR;
    CAGENT_LOCAL_PORT(cagent)    = CMPI_ERROR_CLNTPORT;

    return (EC_TRUE);
}

EC_BOOL cagent_clean(CAGENT *cagent)
{
    cstring_clean(CAGENT_TDNS_HOST(cagent));

    CAGENT_TDNS_PORT(cagent)     = CMPI_ERROR_SRVPORT;

    CAGENT_RESERVED_TCID(cagent) = CMPI_ERROR_TCID;
    CAGENT_RESERVED_PORT(cagent) = CMPI_ERROR_SRVPORT;

    CAGENT_LOCAL_IPADDR(cagent)  = CMPI_ERROR_IPADDR;
    CAGENT_LOCAL_PORT(cagent)    = CMPI_ERROR_CLNTPORT;

    return (EC_TRUE);
}

EC_BOOL cagent_free(CAGENT *cagent)
{
    if(NULL_PTR != cagent)
    {
        cagent_clean(cagent);
        free_static_mem(MM_CAGENT, cagent, LOC_CAGENT_0003);
    }

    return (EC_TRUE);
}

void cagent_print(LOG *log, const CAGENT *cagent)
{
    sys_log(LOGSTDOUT, "cagent_print:tdns host     : %s\n", (const char *)CAGENT_TDNS_HOST_STR(cagent));
    sys_log(LOGSTDOUT, "cagent_print:tdns port     : %ld\n", CAGENT_TDNS_PORT(cagent));

    sys_log(LOGSTDOUT, "cagent_print:reserved tcid : %s\n", c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)));
    sys_log(LOGSTDOUT, "cagent_print:reserved port : %ld\n", CAGENT_RESERVED_PORT(cagent));

    sys_log(LOGSTDOUT, "cagent_print:local ipaddr  : %s\n", c_word_to_ipv4(CAGENT_LOCAL_IPADDR(cagent)));
    sys_log(LOGSTDOUT, "cagent_print:local port    : %ld\n", CAGENT_LOCAL_PORT(cagent));

    return;
}

EC_BOOL cagent_reserve_tcid(CAGENT *cagent, const char *service, const char *ipaddr)
{
    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;

    UINT32            tdns_ipaddr;
    const char      * k;
    char            * v;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    if(EC_FALSE == c_dns_resolve((const char *)CAGENT_TDNS_HOST_STR(cagent), &tdns_ipaddr))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_reserve_tcid: dns resolve '%s' failed\n",
                        (char *)CAGENT_TDNS_HOST_STR(cagent));
        return (EC_FALSE);
    }

    chttp_req_set_ipaddr_word(&chttp_req, tdns_ipaddr);
    chttp_req_set_port_word(&chttp_req, CAGENT_TDNS_PORT(cagent));

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)"/tdns/reserve");

    chttp_req_add_header(&chttp_req, (const char *)"service", service);
    chttp_req_add_header(&chttp_req, (const char *)"ip", ipaddr);

    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)CAGENT_TDNS_HOST_STR(cagent));
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    if(EC_FALSE == chttp_request_block(&chttp_req, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_reserve_tcid: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_reserve_tcid: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    k = (const char *)"tcid";
    v = chttp_rsp_get_header(&chttp_rsp, k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_reserve_tcid: rsp has no header '%s'\n",
                        k);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }
    CAGENT_RESERVED_TCID(cagent) = c_ipv4_to_word(v);

    k = (const char *)"port";
    v = chttp_rsp_get_header(&chttp_rsp, k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_reserve_tcid: rsp has no header '%s'\n",
                        k);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }
    CAGENT_RESERVED_PORT(cagent) = c_str_to_word(v);

    /*record socket ipaddr and port during http procedure*/
    CAGENT_LOCAL_IPADDR(cagent) = CHTTP_RSP_CLIENT_IPADDR(&chttp_rsp);
    CAGENT_LOCAL_PORT(cagent)   = CHTTP_RSP_CLIENT_PORT(&chttp_rsp);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0060_CAGENT, 9)(LOGSTDOUT, "[DEBUG] cagent_reserve_tcid: reserved tcid '%s', port %ld\n",
                    c_word_to_ipv4(CAGENT_RESERVED_TCID(cagent)),
                    CAGENT_RESERVED_PORT(cagent));

    return (EC_TRUE);
}

EC_BOOL cagent_release_tcid(CAGENT *cagent, const char *service, const char *tcid, const char *port)
{
    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;

    UINT32            tdns_ipaddr;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    if(EC_FALSE == c_dns_resolve((const char *)CAGENT_TDNS_HOST_STR(cagent), &tdns_ipaddr))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_release_tcid: dns resolve '%s' failed\n",
                        (char *)CAGENT_TDNS_HOST_STR(cagent));
        return (EC_FALSE);
    }

    chttp_req_set_ipaddr_word(&chttp_req, tdns_ipaddr);
    chttp_req_set_port_word(&chttp_req, CAGENT_TDNS_PORT(cagent));

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)"/tdns/release");

    chttp_req_add_header(&chttp_req, (const char *)"service", service);
    chttp_req_add_header(&chttp_req, (const char *)"tcid", tcid);
    chttp_req_add_header(&chttp_req, (const char *)"port", port);

    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)CAGENT_TDNS_HOST_STR(cagent));
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    if(EC_FALSE == chttp_request_block(&chttp_req, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_release_tcid: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_release_tcid: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0060_CAGENT, 9)(LOGSTDOUT, "[DEBUG] cagent_release_tcid: released tcid '%s', port %s\n",
                    tcid, port);

    return (EC_TRUE);
}

EC_BOOL cagent_check_config_xml(const CAGENT *cagent, const char *fname)
{
    SYS_CFG     *sys_cfg;

    if(EC_FALSE == c_file_access(fname, F_OK | R_OK))
    {
        return (EC_FALSE);
    }

    sys_cfg = sys_cfg_new();
    if(NULL_PTR == sys_cfg)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_check_config_xml: new sys_cfg failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == sys_cfg_load(sys_cfg, fname))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_check_config_xml: load %s failed\n", fname);
        sys_cfg_free(sys_cfg);
        return (EC_FALSE);
    }
    sys_cfg_free(sys_cfg);

    return (EC_TRUE);
}

SYS_CFG *cagent_gen_config(const CAGENT *cagent)
{
    SYS_CFG     *sys_cfg;
    TASKS_CFG   *tasks_cfg;

    CPARACFG    *cparacfg;

    sys_cfg = sys_cfg_new();
    if(NULL_PTR == sys_cfg)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_gen_config: new sys_cfg failed\n");
        return (NULL_PTR);
    }

    tasks_cfg = tasks_cfg_new();
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_gen_config: new tasks_cfg failed\n");
        sys_cfg_free(sys_cfg);
        return (NULL_PTR);
    }

    /*tasks*/
    TASKS_CFG_TCID(tasks_cfg)      = CAGENT_RESERVED_TCID(cagent);
    //TASKS_CFG_SRVIPADDR(tasks_cfg) = c_ipv4_to_word("127.0.0.1");
    //TASKS_CFG_SRVPORT(tasks_cfg)   = CAGENT_RESERVED_PORT(cagent);

    /*note: p2p never used a defined port*/
    TASKS_CFG_SRVIPADDR(tasks_cfg) = CAGENT_LOCAL_IPADDR(cagent); /*bind netcard indeed which is able to access T-DNS*/
    TASKS_CFG_SRVPORT(tasks_cfg)   = CAGENT_LOCAL_PORT(cagent);
    cvector_push_no_lock(TASK_CFG_TASKS_CFG_VEC(SYS_CFG_TASK_CFG(sys_cfg)), (void *)tasks_cfg);

    /*cparacfg*/
    cparacfg = cparacfg_new(CAGENT_RESERVED_TCID(cagent), CMPI_FWD_RANK);
    if(NULL_PTR == cparacfg)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_gen_config: new cparacfg failed\n");
        sys_cfg_free(sys_cfg);
        return (NULL_PTR);
    }
    cvector_push_no_lock(SYS_CFG_PARAS_CFG(sys_cfg), (void *)cparacfg);

    return (sys_cfg);
}

EC_BOOL cagent_gen_config_xml(const CAGENT *cagent, const char *fname)
{
    SYS_CFG     *sys_cfg;

    sys_cfg = cagent_gen_config(cagent);
    if(NULL_PTR == sys_cfg)
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_gen_config_xml: gen conf failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == user_log_open(LOGUSER07, fname, "w"))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_gen_config_xml: open '%s' failed\n", fname);
        sys_cfg_free(sys_cfg);
        return (EC_FALSE);
    }

    sys_cfg_print_xml(LOGUSER07, sys_cfg, 0);
    user_log_close(LOGUSER07);

    sys_cfg_free(sys_cfg);

    return (EC_TRUE);
}

EC_BOOL cagent_set_service(CAGENT *cagent, const char *network_level, const char *service, const char *tcid, const char *ipaddr, const char *port)
{
    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;

    UINT32            tdns_ipaddr;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    if(EC_FALSE == c_dns_resolve((const char *)CAGENT_TDNS_HOST_STR(cagent), &tdns_ipaddr))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_set_service: dns resolve '%s' failed\n",
                        (char *)CAGENT_TDNS_HOST_STR(cagent));
        return (EC_FALSE);
    }

    chttp_req_set_ipaddr_word(&chttp_req, tdns_ipaddr);
    chttp_req_set_port_word(&chttp_req, CAGENT_TDNS_PORT(cagent));

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)"/tdns/set");

    //chttp_req_add_header(&chttp_req, (const char *)"level", network_level);
    //chttp_req_add_header(&chttp_req, (const char *)"service", service);
    chttp_req_add_header(&chttp_req, (const char *)"tcid", tcid);
    chttp_req_add_header(&chttp_req, (const char *)"ip", ipaddr); /*my ip*/
    chttp_req_add_header(&chttp_req, (const char *)"port", port);

    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)CAGENT_TDNS_HOST_STR(cagent));
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    if(EC_FALSE == chttp_request_block(&chttp_req, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_set_service: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_set_service: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    /*record socket ipaddr and port during http procedure*/
    CAGENT_LOCAL_IPADDR(cagent) = CHTTP_RSP_CLIENT_IPADDR(&chttp_rsp);
    CAGENT_LOCAL_PORT(cagent)   = CHTTP_RSP_CLIENT_PORT(&chttp_rsp);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0060_CAGENT, 9)(LOGSTDOUT, "[DEBUG] cagent_set_service: service '%s', tcid '%s', ip '%s'\n",
                    service, tcid, ipaddr);

    return (EC_TRUE);
}

EC_BOOL cagent_set_tcid(CAGENT *cagent, const char *tcid, const char *ipaddr, const char *port)
{
    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;

    UINT32            tdns_ipaddr;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    if(EC_FALSE == c_dns_resolve((const char *)CAGENT_TDNS_HOST_STR(cagent), &tdns_ipaddr))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_set_tcid: dns resolve '%s' failed\n",
                        (char *)CAGENT_TDNS_HOST_STR(cagent));
        return (EC_FALSE);
    }

    chttp_req_set_ipaddr_word(&chttp_req, tdns_ipaddr);
    chttp_req_set_port_word(&chttp_req, CAGENT_TDNS_PORT(cagent));

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)"/tdns/set");

    chttp_req_add_header(&chttp_req, (const char *)"tcid", tcid);
    chttp_req_add_header(&chttp_req, (const char *)"ip", ipaddr); /*my ip*/
    chttp_req_add_header(&chttp_req, (const char *)"port", port);

    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)CAGENT_TDNS_HOST_STR(cagent));
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    if(EC_FALSE == chttp_request_block(&chttp_req, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_set_tcid: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0060_CAGENT, 0)(LOGSTDOUT, "error:cagent_set_tcid: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    /*record socket ipaddr and port during http procedure*/
    CAGENT_LOCAL_IPADDR(cagent) = CHTTP_RSP_CLIENT_IPADDR(&chttp_rsp);
    CAGENT_LOCAL_PORT(cagent)   = CHTTP_RSP_CLIENT_PORT(&chttp_rsp);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0060_CAGENT, 9)(LOGSTDOUT, "[DEBUG] cagent_set_tcid: bind tcid '%s', ip '%s' done\n",
                    tcid, ipaddr);

    return (EC_TRUE);
}

EC_BOOL cagent_check_p2p(const CAGENT *cagent)
{
    return (EC_FALSE);
}

EC_BOOL cagent_start_p2p(const CAGENT *cagent)
{
    return (EC_TRUE);
}

EC_BOOL cagent_stop_p2p(const CAGENT *cagent)
{
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

