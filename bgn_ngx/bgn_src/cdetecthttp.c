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
#include "log.h"
#include "cstring.h"
#include "cqueue.h"

#include "cbc.h"

#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "cepoll.h"

#include "cdetect.h"
#include "chttp.inc"
#include "chttp.h"
#include "cdetecthttp.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "findex.inc"



#if 0
#define CDETECTHTTP_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CDETECTHTTP_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CDETECTHTTP_PRINT_UINT8(info, buff, len) do{}while(0)
#define CDETECTHTTP_PRINT_CHARS(info, buff, len) do{}while(0)
#endif



#if 1
#define CDETECTHTTP_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

#if 0
#define CDETECTHTTP_ASSERT(condition) do{}while(0)
#endif

#if 1
//#define CDETECTHTTP_TIME_COST_FORMAT " BegTime:%u.%03u EndTime:%u.%03u Elapsed:%u "
#define CDETECTHTTP_TIME_COST_FORMAT " %u.%03u %u.%03u %u "
#define CDETECTHTTP_TIME_COST_VALUE(chttp_node)  \
    (uint32_t)CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node)), (uint32_t)CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)))
#endif

static EC_BOOL g_cdetecthttp_log_init = EC_FALSE;

static const CHTTP_API g_cdetecthttp_api_list[] = {
    {CONST_STR_AND_LEN("dns")           , CHTTP_METHOD_GET  , cdetecthttp_commit_resolvedns_request},
    {CONST_STR_AND_LEN("start")         , CHTTP_METHOD_GET  , cdetecthttp_commit_startdomain_request},
    {CONST_STR_AND_LEN("stop")          , CHTTP_METHOD_GET  , cdetecthttp_commit_stopdomain_request},
    {CONST_STR_AND_LEN("process")       , CHTTP_METHOD_GET  , cdetecthttp_commit_process_request},
    {CONST_STR_AND_LEN("reload")        , CHTTP_METHOD_GET  , cdetecthttp_commit_reload_request},
    {CONST_STR_AND_LEN("status")        , CHTTP_METHOD_GET  , cdetecthttp_commit_status_request},
    {CONST_STR_AND_LEN("choice")        , CHTTP_METHOD_GET  , cdetecthttp_commit_choice_request},
    {CONST_STR_AND_LEN("breathe")       , CHTTP_METHOD_GET  , cdetecthttp_commit_breathe_request},
    {CONST_STR_AND_LEN("logrotate")     , CHTTP_METHOD_GET  , cdetecthttp_commit_logrotate_request},
    {CONST_STR_AND_LEN("actsyscfg")     , CHTTP_METHOD_GET  , cdetecthttp_commit_actsyscfg_request},
    {CONST_STR_AND_LEN("paracfg")       , CHTTP_METHOD_GET  , cdetecthttp_commit_paracfg_request},
};

static const uint32_t   g_cdetecthttp_api_num = sizeof(g_cdetecthttp_api_list)/sizeof(g_cdetecthttp_api_list[0]);

EC_BOOL cdetecthttp_log_start()
{
    TASK_BRD        *task_brd;

    if(EC_TRUE == g_cdetecthttp_log_init)
    {
        return (EC_TRUE);
    }

    g_cdetecthttp_log_init = EC_TRUE;

    task_brd = task_brd_default_get();

#if 0/*support rotate*/
    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;

        log_file_name = cstring_new(NULL_PTR, LOC_CDETECTHTTP_0001);
        cstring_format(log_file_name, "%s/detect_%s_%ld.log",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        if(EC_FALSE == user_log_open(LOGUSER08, (char *)cstring_get_str(log_file_name), "a+"))/*append mode. scenario: after restart*/
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_log_start: user_log_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            cstring_free(log_file_name);
        }
    }
#endif
    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;
        LOG     *log;

        /*open log and redirect LOGUSER08 to it*/
        log_file_name = cstring_new(NULL_PTR, LOC_CDETECTHTTP_0002);
        cstring_format(log_file_name, "%s/detect_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER08, log);

            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "[DEBUG] cdetecthttp_log_start: log_file_open '%s' -> LOGUSER08 done\n",
                               (char *)cstring_get_str(log_file_name));

            cstring_free(log_file_name);
        }
    }
#if 0
    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;
        LOG     *log;

        /*open log and redirect LOGUSER08 to it*/
        log_file_name = cstring_new(NULL_PTR, LOC_CDETECTHTTP_0003);
        cstring_format(log_file_name, "%s/debug_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_log_start: log_file_open '%s' -> LOGUSER07 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER07, log);
            cstring_free(log_file_name);
        }
    }
#endif
    return (EC_TRUE);
}



/*---------------------------------------- ENTRY: HTTP COMMIT REQUEST FOR HANDLER  ----------------------------------------*/
EC_BOOL cdetecthttp_commit_request(CHTTP_NODE *chttp_node)
{
    http_parser_t *http_parser;
    uint32_t       method;

    http_parser = CHTTP_NODE_PARSER(chttp_node);

    method = chttp_method_convert(http_parser->method);
    if(CHTTP_METHOD_UNKNOWN != method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)cdetecthttp_commit_start, 2, chttp_node, (UINT32)method);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_request: "
                                                        "no croutine\n");

            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CDETECTHTTP_0002);

        return (EC_TRUE);
    }

    dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_request: "
                                                "not support http method %d yet\n",
                                                http_parser->method);
    return (EC_FALSE);/*note: this chttp_node must be discarded*/
}

EC_BOOL cdetecthttp_commit_start(CHTTP_NODE *chttp_node, const UINT32 method)
{
    const CHTTP_API       *chttp_api;
    EC_BOOL                ret;

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record xfs beg to handle time*/

    chttp_api = chttp_node_find_api(chttp_node,
                                    (const CHTTP_API *)g_cdetecthttp_api_list,
                                    g_cdetecthttp_api_num,
                                    (uint32_t)method);
    if(NULL_PTR == chttp_api)
    {
        CBUFFER               *url_cbuffer;

        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_start: "
                                                    "no api for %s:'%.*s'\n",
                                                    chttp_method_str((uint32_t)method),
                                                    CBUFFER_USED(CHTTP_NODE_ARGS(chttp_node)),
                                                    CBUFFER_DATA(CHTTP_NODE_ARGS(chttp_node)));

        url_cbuffer   = CHTTP_NODE_URL(chttp_node);
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_start: "
                                                    "invalid request %s:'%.*s'\n",
                                                    chttp_method_str((uint32_t)method),
                                                    CBUFFER_USED(url_cbuffer),
                                                    CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_NOT_ACCEPTABLE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_commit_start: invalid request %s:'%.*s'",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(url_cbuffer), CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;

        return cdetecthttp_commit_end(chttp_node, ret);
    }

    dbg_log(SEC_0045_CDETECTHTTP, 9)(LOGSTDOUT, "[DEBUG] cdetecthttp_commit_start: "
                                                "api: method %d, name %s\n",
                                                CHTTP_API_METHOD(chttp_api),
                                                CHTTP_API_NAME(chttp_api));

    ret = CHTTP_API_COMMIT(chttp_api)(chttp_node);
    return cdetecthttp_commit_end(chttp_node, ret);
}

EC_BOOL cdetecthttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result)
{
    EC_BOOL ret;

    ret = result;

    CHTTP_NODE_CROUTINE_NODE(chttp_node) = NULL_PTR; /*clear croutine mounted point*/

    if(EC_DONE == ret)
    {
        if(NULL_PTR != CHTTP_NODE_CSOCKET_CNODE(chttp_node))
        {
            CSOCKET_CNODE *csocket_cnode;

            csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

            cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            csocket_cnode_icomplete(CHTTP_NODE_CSOCKET_CNODE(chttp_node));
            return (EC_DONE);
        }

        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        CHTTP_NODE_KEEPALIVE(chttp_node) = EC_FALSE;
        chttp_node_free(chttp_node);

        return (EC_FALSE);

    }

    if(EC_FALSE == ret)
    {
        ret = chttp_commit_error_request(chttp_node);
    }

    if(EC_FALSE == ret)
    {
        CSOCKET_CNODE * csocket_cnode;

        /*umount from defer request queue if necessary*/
        chttp_defer_request_queue_erase(chttp_node);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(NULL_PTR != csocket_cnode)
        {
            CEPOLL *cepoll;
            int     sockfd;

            cepoll = TASK_BRD_CEPOLL(task_brd_default_get());
            sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

            dbg_log(SEC_0045_CDETECTHTTP, 1)(LOGSTDOUT, "[DEBUG] cdetecthttp_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
            cepoll_del_all(cepoll, sockfd);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            /* umount */
            CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

            CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;

            csocket_cnode_close(csocket_cnode);

            /*free*/
            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }

        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        /*free*/
        chttp_node_free(chttp_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL cdetecthttp_commit_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    ret = chttp_node_send_rsp(chttp_node);
    if(EC_AGAIN != ret)
    {
        return (ret);
    }

    ret = cepoll_set_event(task_brd_default_get_cepoll(),
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CEPOLL_WR_EVENT,
                           (const char *)"csocket_cnode_isend",
                           (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                           csocket_cnode);
    if(EC_FALSE == ret)
    {
        return (EC_FALSE);
    }
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;

    return (EC_AGAIN);
}

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: resolve dns ----------------------------------------*/
EC_BOOL cdetecthttp_commit_resolvedns_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_resolvedns_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_resolvedns_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_resolvedns_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_resolvedns_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_resolvedns_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_resolvedns_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_resolvedns_request(CHTTP_NODE *chttp_node)
{
    char          * domain_str;
    CSTRING         domain_cstr;

    CSOCKET_CNODE * csocket_cnode;
    UINT32          ipaddr;

    domain_str = chttp_node_get_header(chttp_node, (const char *)"domain");
    if(NULL_PTR == domain_str)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_resolvedns_request: no domain in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_resolvedns_request: no domain in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    cstring_set_str(&domain_cstr, (const UINT8 *)domain_str); /*mount only*/

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == cdetect_dns_resolve(CSOCKET_CNODE_MODI(csocket_cnode), &domain_cstr, &ipaddr))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_resolvedns_request: not found domain '%s'\n", domain_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_resolvedns_request: not found domain '%s'", domain_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

        return (EC_TRUE);
    }


    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_resolvedns_request: get domain '%s' done\n", domain_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_resolvedns_request: get domain '%s' done", domain_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"domain", domain_str);
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"ip", c_word_to_ipv4(ipaddr));

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_resolvedns_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_resolvedns_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_resolvedns_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_resolvedns_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_resolvedns_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_resolvedns_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_resolvedns_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: start domain ----------------------------------------*/
EC_BOOL cdetecthttp_commit_startdomain_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_startdomain_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_startdomain_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_startdomain_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_startdomain_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_startdomain_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_startdomain_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_startdomain_request(CHTTP_NODE *chttp_node)
{
    char          * domain_str;
    CSTRING         domain_cstr;

    CSOCKET_CNODE * csocket_cnode;

    domain_str = chttp_node_get_header(chttp_node, (const char *)"domain");
    if(NULL_PTR == domain_str)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_startdomain_request: no domain in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_startdomain_request: no domain in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&domain_cstr, (const UINT8 *)domain_str);/*mount only*/

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == cdetect_start_domain(CSOCKET_CNODE_MODI(csocket_cnode), &domain_cstr))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_startdomain_request: not found domain '%s'\n", domain_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_startdomain_request: not found domain '%s'", domain_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

        return (EC_TRUE);
    }


    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_startdomain_request: start domain '%s' done\n", domain_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_startdomain_request: start domain '%s' done", domain_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"domain", domain_str);

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_startdomain_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_startdomain_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_startdomain_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_startdomain_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_startdomain_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_startdomain_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_startdomain_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: stop domain ----------------------------------------*/
EC_BOOL cdetecthttp_commit_stopdomain_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_stopdomain_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_stopdomain_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_stopdomain_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_stopdomain_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_stopdomain_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_stopdomain_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_stopdomain_request(CHTTP_NODE *chttp_node)
{
    char          * domain_str;
    CSTRING         domain_cstr;

    CSOCKET_CNODE * csocket_cnode;

    domain_str = chttp_node_get_header(chttp_node, (const char *)"domain");
    if(NULL_PTR == domain_str)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_stopdomain_request: no domain in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_stopdomain_request: no domain in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&domain_cstr, (const UINT8 *)domain_str); /*mount only*/

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == cdetect_start_domain(CSOCKET_CNODE_MODI(csocket_cnode), &domain_cstr))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_stopdomain_request: not found domain '%s'\n", domain_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_stopdomain_request: not found domain '%s'", domain_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

        return (EC_TRUE);
    }


    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_stopdomain_request: stop domain '%s' done\n", domain_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_stopdomain_request: stop domain '%s' done", domain_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"domain", domain_str);

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_stopdomain_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_stopdomain_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_stopdomain_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_stopdomain_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_stopdomain_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_stopdomain_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_stopdomain_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: process ----------------------------------------*/
EC_BOOL cdetecthttp_commit_process_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_process_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_process_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_process_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_process_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_process_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_process_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_process_request(CHTTP_NODE *chttp_node)
{
    char          * v;
    UINT32          detect_task_max_num;

    CSOCKET_CNODE * csocket_cnode;

    v = chttp_node_get_header(chttp_node, (const char *)"max-task");
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_process_request: no domain in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_process_request: no domain in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    detect_task_max_num = c_str_to_word(v);

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == cdetect_process(CSOCKET_CNODE_MODI(csocket_cnode), detect_task_max_num))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_process_request: internal issue\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_process_request: internal issue");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }


    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_process_request: process done\n");

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_process_request: process done");

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_process_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_process_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_process_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_process_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_process_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_process_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_process_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: reload ----------------------------------------*/
EC_BOOL cdetecthttp_commit_reload_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_reload_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_reload_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_reload_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_reload_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_reload_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_reload_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_reload_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == cdetect_reload(CSOCKET_CNODE_MODI(csocket_cnode)))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_reload_request: internal issue\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_reload_request: internal issue");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }


    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_reload_request: reload done\n");

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_reload_request: reload done");

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_reload_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_reload_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_reload_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_reload_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_reload_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_reload_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_reload_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: status ----------------------------------------*/
EC_BOOL cdetecthttp_commit_status_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_status_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_status_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_status_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_status_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_status_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_status_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_status_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    const char    * status_str;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    status_str = cdetect_reload_status_str(CSOCKET_CNODE_MODI(csocket_cnode));

    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_status_request: status done\n");

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_status_request: status done");

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"status", status_str);

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_status_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_status_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_status_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_status_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_status_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_status_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_status_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: choice ----------------------------------------*/
EC_BOOL cdetecthttp_commit_choice_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_choice_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_choice_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_choice_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_choice_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_choice_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_choice_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_choice_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    UINT32          choice;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    cdetect_choice(CSOCKET_CNODE_MODI(csocket_cnode), &choice);

    dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_choice_request: choice done\n");

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_choice_request: choice done");

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"choice", c_word_to_str(choice));

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_choice_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_choice_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_choice_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_choice_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_choice_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_choice_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_choice_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: logrotate ----------------------------------------*/
EC_BOOL cdetecthttp_commit_logrotate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_logrotate_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_logrotate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_logrotate_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_logrotate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_logrotate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_logrotate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_logrotate_request(CHTTP_NODE *chttp_node)
{
    if(1)
    {
        UINT32 super_md_id;

        char  *log_index_str;
        char  *log_index_str_t;
        char  *log_index_seg[ DEFAULT_END_LOG_INDEX ];
        UINT32 log_index_seg_num;
        UINT32 log_index_seg_idx;

        super_md_id = 0;

        log_index_str = chttp_node_get_header(chttp_node, (const char *)"log-index");
        if(NULL_PTR == log_index_str)
        {
            UINT32 log_index;

            log_index = DEFAULT_USRER08_LOG_INDEX; /*default LOGUSER08*/

            if(EC_FALSE == super_rotate_log(super_md_id, log_index))
            {
                dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                return (EC_TRUE);
            }

            dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_logrotate_request: log rotate %ld done\n", log_index);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u --", CHTTP_OK);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_logrotate_request: log rotate %ld done", log_index);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

            return (EC_TRUE);
        }

        /*else*/
        log_index_str_t = c_str_dup(log_index_str);
        if(NULL_PTR == log_index_str_t)
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_logrotate_request: no memory\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_logrotate_request: no memory");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;
            return (EC_TRUE);
        }

        log_index_seg_num = c_str_split(log_index_str_t, (const char *)", \t\r",
                                        (char **)log_index_seg,
                                        sizeof(log_index_seg)/sizeof(log_index_seg[0]));


        for(log_index_seg_idx = 0; log_index_seg_idx < log_index_seg_num; log_index_seg_idx ++)
        {
            UINT32 log_index;

            log_index = c_str_to_word(log_index_seg[ log_index_seg_idx ]);

            if(EC_FALSE == super_rotate_log(super_md_id, log_index))
            {
                dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cdetecthttp_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                c_str_free(log_index_str_t);

                return (EC_TRUE);
            }
        }

        dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_logrotate_request: log rotate %s done\n", log_index_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_logrotate_request: log rotate %s done", log_index_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        c_str_free(log_index_str_t);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_logrotate_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_logrotate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_logrotate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_logrotate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_logrotate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_logrotate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: actsyscfg ----------------------------------------*/
EC_BOOL cdetecthttp_commit_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_actsyscfg_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_actsyscfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_actsyscfg_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_actsyscfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_actsyscfg_response(chttp_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_actsyscfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    if(1)
    {
        UINT32 super_md_id;

        super_md_id = 0;

        super_activate_sys_cfg(super_md_id);

        dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_actsyscfg_request done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_actsyscfg_request done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_actsyscfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_actsyscfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_actsyscfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_actsyscfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: breathe ----------------------------------------*/
EC_BOOL cdetecthttp_commit_breathe_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_breathe_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_breathe_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_breathe_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_breathe_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_breathe_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_breathe_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_breathe_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        breathing_static_mem();

        dbg_log(SEC_0045_CDETECTHTTP, 9)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_breathe_request: memory breathing done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_breathe_request: memory breathing done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_breathe_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_breathe_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_breathe_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_breathe_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_breathe_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_breathe_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: paracfg ----------------------------------------*/
EC_BOOL cdetecthttp_commit_paracfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cdetecthttp_handle_paracfg_request(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_paracfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdetecthttp_make_paracfg_response(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_paracfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cdetecthttp_commit_paracfg_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_paracfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cdetecthttp_handle_paracfg_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *rsp_content_cbytes;
    const char    *rsp_body_str;

    TASK_BRD      *task_brd;

    rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(rsp_content_cbytes);

    task_brd = task_brd_default_get();
    if(NULL_PTR != task_brd && NULL_PTR != TASK_BRD_CPARACFG(task_brd))
    {
        json_object   *cparacfg_obj;

        cparacfg_obj = json_object_new_object();

        if(NULL_PTR != cparacfg_obj)
        {
            cparacfg_json(cparacfg_obj, TASK_BRD_CPARACFG(task_brd));
        }

        rsp_body_str = json_object_to_json_string_ext(cparacfg_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, (UINT32)(strlen(rsp_body_str)/* + 1*/));

        json_object_put(cparacfg_obj);

        dbg_log(SEC_0045_CDETECTHTTP, 5)(LOGSTDOUT, "[DEBUG] cdetecthttp_handle_paracfg_request: done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CDETECT_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(rsp_content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cdetecthttp_handle_paracfg_request: done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_make_paracfg_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_paracfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_paracfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_paracfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_make_paracfg_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cdetecthttp_commit_paracfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0045_CDETECTHTTP, 0)(LOGSTDOUT, "error:cdetecthttp_commit_paracfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cdetecthttp_commit_response(chttp_node);
}
#endif


#ifdef __cplusplus
}
#endif/*__cplusplus*/

