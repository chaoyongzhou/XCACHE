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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>

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

#include "ctdns.h"
#include "chttp.inc"
#include "chttp.h"
#include "ctdnshttp.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "findex.inc"



#if 0
#define CTDNSHTTP_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CTDNSHTTP_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CTDNSHTTP_PRINT_UINT8(info, buff, len) do{}while(0)
#define CTDNSHTTP_PRINT_CHARS(info, buff, len) do{}while(0)
#endif



#if 1
#define CTDNSHTTP_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

#if 0
#define CTDNSHTTP_ASSERT(condition) do{}while(0)
#endif

#if 1
//#define CTDNSHTTP_TIME_COST_FORMAT " BegTime:%u.%03u EndTime:%u.%03u Elapsed:%u "
#define CTDNSHTTP_TIME_COST_FORMAT " %u.%03u %u.%03u %u "
#define CTDNSHTTP_TIME_COST_VALUE(chttp_node)  \
    (uint32_t)CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node)), (uint32_t)CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)))
#endif

static EC_BOOL g_ctdnshttp_log_init = EC_FALSE;

EC_BOOL ctdnshttp_log_start()
{
    TASK_BRD        *task_brd;

    if(EC_TRUE == g_ctdnshttp_log_init)
    {
        return (EC_TRUE);
    }

    g_ctdnshttp_log_init = EC_TRUE;

    task_brd = task_brd_default_get();

#if 0/*support rotate*/
    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;

        log_file_name = cstring_new(NULL_PTR, LOC_CTDNSHTTP_0001);
        cstring_format(log_file_name, "%s/tdns_%s_%ld.log",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        if(EC_FALSE == user_log_open(LOGUSER08, (char *)cstring_get_str(log_file_name), "a+"))/*append mode. scenario: after restart*/
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_log_start: user_log_open '%s' -> LOGUSER08 failed\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CTDNSHTTP_0002);
        cstring_format(log_file_name, "%s/tdns_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER08, log);

            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "[DEBUG] ctdnshttp_log_start: log_file_open '%s' -> LOGUSER08 done\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CTDNSHTTP_0003);
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
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_log_start: log_file_open '%s' -> LOGUSER07 failed\n",
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
EC_BOOL ctdnshttp_commit_request(CHTTP_NODE *chttp_node)
{
    http_parser_t *http_parser;

    http_parser = CHTTP_NODE_PARSER(chttp_node);

    if(HTTP_GET == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)ctdnshttp_commit_http_get, 1, chttp_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_request: cthread load for HTTP_GET failed\n");
            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CTDNSHTTP_0004);

        return (EC_TRUE);
    }

    if(HTTP_POST == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)ctdnshttp_commit_http_post, 1, chttp_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_request: cthread load for HTTP_POST failed\n");
            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CTDNSHTTP_0005);

        return (EC_TRUE);
    }

    if(HTTP_HEAD == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)ctdnshttp_commit_http_head, 1, chttp_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_request: cthread load for HTTP_HEAD failed\n");
            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CTDNSHTTP_0006);

        return (EC_TRUE);
    }

    dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_request: not support http method %d yet\n", http_parser->method);
    return (EC_FALSE);/*note: this chttp_node must be discarded*/
}

EC_BOOL ctdnshttp_commit_http_head(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record tdns beg to handle time*/

    if(1)
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTP_NODE_URI(chttp_node);
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_http_head: invalid uri %.*s\n", CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        ret = EC_FALSE;
    }

    return ctdnshttp_commit_end(chttp_node, ret);
}

EC_BOOL ctdnshttp_commit_http_post(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record tdns beg to handle time*/

    if(1)
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTP_NODE_URI(chttp_node);
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_http_post: invalid uri %.*s\n", CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        ret = EC_FALSE;
    }

    return ctdnshttp_commit_end(chttp_node, ret);
}

EC_BOOL ctdnshttp_commit_http_get(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_commit_http_get: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(CHTTP_NODE_URI(chttp_node)),
                        CBUFFER_DATA(CHTTP_NODE_URI(chttp_node)),
                        CBUFFER_USED(CHTTP_NODE_URI(chttp_node)));

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record tdns beg to handle time*/

    if(EC_TRUE == ctdnshttp_is_http_get_gettcid(chttp_node))
    {
        ret = ctdnshttp_commit_gettcid_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_settcid(chttp_node))
    {
        ret = ctdnshttp_commit_settcid_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_deltcid(chttp_node))
    {
        ret = ctdnshttp_commit_deltcid_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_configtcid(chttp_node))
    {
        ret = ctdnshttp_commit_configtcid_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_reservetcid(chttp_node))
    {
        ret = ctdnshttp_commit_reservetcid_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_releasetcid(chttp_node))
    {
        ret = ctdnshttp_commit_releasetcid_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_flush(chttp_node))
    {
        ret = ctdnshttp_commit_flush_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_ping(chttp_node))
    {
        ret = ctdnshttp_commit_ping_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_online(chttp_node))
    {
        ret = ctdnshttp_commit_online_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_offline(chttp_node))
    {
        ret = ctdnshttp_commit_offline_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_upper(chttp_node))
    {
        ret = ctdnshttp_commit_upper_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_edge(chttp_node))
    {
        ret = ctdnshttp_commit_edge_get_request(chttp_node);
    }
    else if(EC_TRUE == ctdnshttp_is_http_get_refresh(chttp_node))
    {
        ret = ctdnshttp_commit_refresh_get_request(chttp_node);
    }
    else
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTP_NODE_URI(chttp_node);
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_http_get: invalid uri %.*s\n",
                            CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_ERR %s %u --", "GET", CHTTP_NOT_ACCEPTABLE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_commit_http_get: invalid uri %.*s", CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;
    }

    return ctdnshttp_commit_end(chttp_node, ret);
}

EC_BOOL ctdnshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result)
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

        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

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

            dbg_log(SEC_0048_CTDNSHTTP, 1)(LOGSTDOUT, "[DEBUG] ctdnshttp_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
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

        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        /*free*/
        chttp_node_free(chttp_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL ctdnshttp_commit_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
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
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: gettcid ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_gettcid_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/get") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/get")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_gettcid(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_gettcid: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_gettcid_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_gettcid_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_gettcid_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_gettcid_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_gettcid_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_gettcid_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_gettcid_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_gettcid_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_gettcid_get_request(CHTTP_NODE *chttp_node)
{
    char          * tcid_str;

    CSOCKET_CNODE * csocket_cnode;
    UINT32          ipaddr;
    UINT32          port;

    /*tcid*/
    tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_gettcid_get_request: "
                                                  "no tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_gettcid_get_request: "
                                                  "no tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_gettcid_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_gettcid_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == ctdns_get(CSOCKET_CNODE_MODI(csocket_cnode), c_ipv4_to_word(tcid_str), &ipaddr, &port))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_gettcid_get_request: "
                                                  "not found tcid '%s'\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_gettcid_get_request: "
                                                  "not found tcid '%s'",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

        return (EC_TRUE);
    }


    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_gettcid_get_request: "
                                              "get tcid '%s' => ip '%s', port %ld done\n",
                                              tcid_str,
                                              c_word_to_ipv4(ipaddr), port);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_gettcid_get_request: "
                                              "get tcid '%s' => ip '%s', port %ld done",
                                              tcid_str,
                                              c_word_to_ipv4(ipaddr), port);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"tcid", tcid_str);
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"ip", c_word_to_ipv4(ipaddr));
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"port", c_word_to_str(port));

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_gettcid_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_gettcid_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_gettcid_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_gettcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_gettcid_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_gettcid_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_gettcid_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: set ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_settcid_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/set") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/set")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*delete small/regular file*/
EC_BOOL ctdnshttp_is_http_get_settcid(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_settcid: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_settcid_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_settcid_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_settcid_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_settcid_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_settcid_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_settcid_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_settcid_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_settcid_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_settcid_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    const char    * level_str;/*network level*/
    const char    * tcid_str;
    const char    * ipaddr_str;
    const char    * port_str;
    const char    * service_str;

    UINT32          client_ipaddr;
    UINT32          client_port;

    UINT32          reserved_port;

    CSTRING         service_cstr;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    client_ipaddr = CSOCKET_CNODE_IPADDR(csocket_cnode);
    client_port   = CSOCKET_CNODE_CLIENT_PORT(csocket_cnode);

    /*tcid*/
    tcid_str    = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "tcid absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "tcid absence");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*ip*/
    ipaddr_str  = chttp_node_get_header(chttp_node, (const char *)"ip");
    if(NULL_PTR == ipaddr_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "tcid '%s', ip absence\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "tcid '%s', ip absence",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(ipaddr_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid ip '%s' in header\n",
                                                  ipaddr_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid ip '%s' in header",
                                                  ipaddr_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*port*/
    port_str    = chttp_node_get_header(chttp_node, (const char *)"port");
    if(NULL_PTR == port_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "tcid '%s', port absence\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "tcid '%s', port absence",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(port_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid port '%s' in header\n",
                                                  port_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid port '%s' in header",
                                                  port_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_settcid_get_request: "
                                              "(tcid '%s', ip '%s'), client '%s:%ld'\n",
                                              tcid_str, ipaddr_str,
                                              c_word_to_ipv4(client_ipaddr), client_port);

    reserved_port = c_str_to_word(port_str);
    if(CMPI_ERROR_SRVPORT != reserved_port)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_settcid_get_request: "
                                                  "(tcid '%s', ip '%s'), reset client %s port %ld => %ld\n",
                                                  tcid_str, ipaddr_str, c_word_to_ipv4(client_ipaddr),
                                                  client_port, reserved_port);

        client_port = reserved_port; /*used reserved port as client port*/
    }

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        if(EC_FALSE == ctdns_set_no_service(CSOCKET_CNODE_MODI(csocket_cnode),
                                             c_ipv4_to_word(tcid_str),
                                             client_ipaddr,
                                             client_port))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                      "set (tcid '%s', ip '%s', port '%ld') failed\n",
                                                      tcid_str,
                                                      c_word_to_ipv4(client_ipaddr), client_port);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                      "set (tcid '%s', ip '%s', port '%ld') failed",
                                                      tcid_str,
                                                      c_word_to_ipv4(client_ipaddr), client_port);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            return (EC_TRUE);
        }

        dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_settcid_get_request: "
                                                  "set (tcid '%s', ip '%s', port '%ld') done\n",
                                                  tcid_str,
                                                  c_word_to_ipv4(client_ipaddr), client_port);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_settcid_get_request: "
                                                  "set (tcid '%s', ip '%s', port '%ld') done",
                                                  tcid_str,
                                                  c_word_to_ipv4(client_ipaddr), client_port);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    level_str   = chttp_node_get_header(chttp_node, (const char *)"level");
    if(NULL_PTR == level_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "network level absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "network level absence");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(level_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid level '%s' in header\n",
                                                  level_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "invalid level '%s' in header",
                                                  level_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    cstring_init(&service_cstr, NULL_PTR);
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);/*mount only*/

    if(EC_FALSE == ctdns_set(CSOCKET_CNODE_MODI(csocket_cnode),
                             c_str_to_word(level_str),
                             c_ipv4_to_word(tcid_str),
                             client_ipaddr,
                             client_port,
                             &service_cstr))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "set (network '%s', tcid '%s', ip '%s', port '%ld', service '%s') failed\n",
                                                  level_str, tcid_str,
                                                  c_word_to_ipv4(client_ipaddr), client_port,
                                                  service_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: "
                                                  "set (network '%s', tcid '%s', ip '%s', port '%ld', service '%s') failed",
                                                  level_str, tcid_str,
                                                  c_word_to_ipv4(client_ipaddr), client_port,
                                                  service_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

        return (EC_TRUE);
    }

    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_settcid_get_request: "
                                              "set (network '%s', tcid '%s', ip '%s', port '%ld', service '%s') done\n",
                                              level_str, tcid_str,
                                              c_word_to_ipv4(client_ipaddr), client_port,
                                              service_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_settcid_get_request: "
                                              "set (network '%s', tcid '%s', ip '%s', port '%ld', service '%s') done",
                                              level_str, tcid_str,
                                              c_word_to_ipv4(client_ipaddr), client_port,
                                              service_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*NAT network*/
    if(c_ipv4_to_word(ipaddr_str) == client_ipaddr)
    {
        cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"nat", (const char *)"false");
    }
    else
    {
        cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"nat", (const char *)"true");
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_settcid_get_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_settcid_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_settcid_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: deltcid ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_deltcid_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/delete") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/delete")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_deltcid(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_deltcid: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_deltcid_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_deltcid_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_deltcid_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_deltcid_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_deltcid_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_deltcid_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_deltcid_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_deltcid_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_deltcid_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    const char    * tcid_str;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    /*tcid*/
    tcid_str   = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_deltcid_get_request: "
                                                  "header 'tcid' absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_deltcid_get_request: "
                                                  "header 'tcid' absence");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_deltcid_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_deltcid_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    if(EC_FALSE == ctdns_delete(CSOCKET_CNODE_MODI(csocket_cnode), c_ipv4_to_word(tcid_str)))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_deltcid_get_request: "
                                                  "ctdns delete tcid %s failed\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_deltcid_get_request: "
                                                  "ctdns delete tcid %s failed",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

        return (EC_TRUE);
    }
    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_deltcid_get_request: "
                                              "ctdns delete tcid %s done\n",
                                              tcid_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_deltcid_get_request: "
                                              "ctdns delete tcid %s done",
                                              tcid_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_deltcid_get_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_deltcid_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_deltcid_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_deltcid_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_deltcid_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_deltcid_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: configtcid ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_configtcid_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/config") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/config")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_configtcid(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_configtcid: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_configtcid_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_configtcid_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_configtcid_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_configtcid_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_configtcid_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_configtcid_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_configtcid_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_configtcid_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_configtcid_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    const char    * service_str;
    const char    * tcid_str;
    const char    * port_str;
    CSTRING         service_cstr;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    /*service*/
    service_str   = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "header 'service' absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "header 'service' absence");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);/*mount only*/

    /*tcid*/
    tcid_str      = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "header 'tcid' absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "header 'tcid' absence");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*port*/
    port_str      = chttp_node_get_header(chttp_node, (const char *)"port");
    if(NULL_PTR == port_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "header 'port' absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "header 'port' absence");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(port_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "invalid port '%s' in header\n",
                                                  port_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "invalid port '%s' in header",
                                                  port_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    if(EC_FALSE == ctdns_config_tcid(CSOCKET_CNODE_MODI(csocket_cnode), &service_cstr,
                        c_ipv4_to_word(tcid_str), c_str_to_word(port_str)))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "ctdns config tcid %s port %s failed\n",
                                                  tcid_str, port_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_configtcid_get_request: "
                                                  "ctdns config tcid %s port %s failed",
                                                  tcid_str, port_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

        return (EC_TRUE);
    }
    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_configtcid_get_request: "
                                              "ctdns config tcid %s port %s done\n",
                                              tcid_str, port_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_configtcid_get_request: "
                                              "ctdns config tcid %s port %s done",
                                              tcid_str, port_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_configtcid_get_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_configtcid_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_configtcid_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_configtcid_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_configtcid_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_configtcid_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: reservetcid ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_reservetcid_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/reserve") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/reserve")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_reservetcid(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_reservetcid: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_reservetcid_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_reservetcid_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_reservetcid_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_reservetcid_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_reservetcid_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_reservetcid_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_reservetcid_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_reservetcid_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_reservetcid_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    char          * service_str;
    char          * ipaddr_str;

    CSTRING         service_cstr;

    UINT32          tcid;
    UINT32          port;

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);

    /*ip*/
    ipaddr_str = chttp_node_get_header(chttp_node, (const char *)"ip");
    if(NULL_PTR == ipaddr_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "no ip in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "no ip in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(ipaddr_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "invalid ip '%s' in header\n",
                                                  ipaddr_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "invalid ip '%s' in header",
                                                  ipaddr_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == ctdns_reserve_tcid(CSOCKET_CNODE_MODI(csocket_cnode), &service_cstr,
                             c_ipv4_to_word(ipaddr_str), &tcid, &port))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "reserve tcid for ip '%s' from service '%s' failed\n",
                                                  ipaddr_str, service_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_reservetcid_get_request: "
                                                  "reserve tcid for ip '%s' from service '%s' failed",
                                                  ipaddr_str, service_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

        return (EC_TRUE);
    }


    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_reservetcid_get_request: "
                                              "reserve tcid '%s' port %ld for ip '%s'from service '%s' done\n",
                                              c_word_to_ipv4(tcid), port,
                                              ipaddr_str, service_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_reservetcid_get_request: "
                                              "reserve tcid '%s' port %ld for ip '%s' from service '%s' done",
                                              c_word_to_ipv4(tcid), port,
                                              ipaddr_str, service_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"tcid", c_word_to_ipv4(tcid));
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"ip", ipaddr_str);
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"port", c_word_to_str(port));

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_reservetcid_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_reservetcid_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_reservetcid_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_reservetcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_reservetcid_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_reservetcid_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_reservetcid_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: releasetcid ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_releasetcid_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/release") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/release")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_releasetcid(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_releasetcid: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_releasetcid_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_releasetcid_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_releasetcid_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_releasetcid_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_releasetcid_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_releasetcid_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_releasetcid_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_releasetcid_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_releasetcid_get_request(CHTTP_NODE *chttp_node)
{
    char          * service_str;
    char          * tcid_str;
    char          * port_str;

    CSTRING         service_cstr;

    CSOCKET_CNODE * csocket_cnode;

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_releaseservice_get_request: "
                                                  "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_releaseservice_get_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);

    /*tcid*/
    tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "no tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "no tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*port*/
    port_str = chttp_node_get_header(chttp_node, (const char *)"port");
    if(NULL_PTR == port_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_releaseport_get_request: "
                                                  "no port in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_releaseport_get_request: "
                                                  "no port in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(port_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "invalid port '%s' in header\n",
                                                  port_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "invalid port '%s' in header",
                                                  port_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == ctdns_release_tcid(CSOCKET_CNODE_MODI(csocket_cnode), &service_cstr,
                            c_ipv4_to_word(tcid_str), c_str_to_word(port_str)))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "release service '%s' tcid '%s' port %s failed\n",
                                                  service_str, tcid_str, port_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_releasetcid_get_request: "
                                                  "release service '%s' tcid '%s' port %s failed\n",
                                                  service_str, tcid_str, port_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

        return (EC_TRUE);
    }


    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_releasetcid_get_request: "
                                              "release service '%s' tcid '%s' port %s done\n",
                                              service_str, tcid_str, port_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_releasetcid_get_request: "
                                              "release service '%s' tcid '%s' port %s done\n",
                                              service_str, tcid_str, port_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"service", service_str);
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"tcid", tcid_str);
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"port", port_str);

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_releasetcid_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_releasetcid_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_releasetcid_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_releasetcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_releasetcid_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_releasetcid_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_releasetcid_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: flush ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_flush_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/flush") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/flush")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_flush(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_flush: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_flush_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_flush_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_flush_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_flush_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_flush_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_flush_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_flush_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_flush_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_flush_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(EC_FALSE == ctdns_flush(CSOCKET_CNODE_MODI(csocket_cnode)))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_flush_get_request: "
                                                  "ctdns flush failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_flush_get_request: "
                                                  "ctdns flush failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }

    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_flush_get_request: "
                                              "ctdns flush done\n");
    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_flush_get_request: "
                                              "ctdns flush done");

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_flush_get_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_flush_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_flush_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_flush_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_flush_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_flush_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ping ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_ping_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/ping") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/ping")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_ping(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_ping: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_ping_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_ping_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_ping_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_ping_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_ping_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_ping_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_ping_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_ping_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_ping_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE      * csocket_cnode;
    char               * des_tcid_str;

    UINT32               des_tcid;
    UINT32               des_ipaddr;
    UINT32               des_port;
    UINT32               elapsed_msec;

    /*tcid*/
    des_tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == des_tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_ping_get_request: "
                                                  "ctdns ping done\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_ping_get_request: "
                                                  "ctdns ping done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(des_tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_ping_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_ping_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    des_tcid = c_ipv4_to_word(des_tcid_str);

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(EC_FALSE == ctdns_ping(CSOCKET_CNODE_MODI(csocket_cnode), des_tcid, &des_ipaddr, &des_port, &elapsed_msec))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_ping_get_request: "
                                                  "ping %s failed\n",
                                                  des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_ping_get_request: "
                                                  "ping %s failed",
                                                  des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

        return (EC_TRUE);
    }

    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_ping_get_request: "
                                              "ctdns ping %s (%s, %ld) in %ld ms done\n",
                                              des_tcid_str, c_word_to_ipv4(des_ipaddr), des_port, elapsed_msec);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_ping_get_request: "
                                              "ctdns ping %s (%s, %ld) in %ld ms done",
                                              des_tcid_str, c_word_to_ipv4(des_ipaddr), des_port, elapsed_msec);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"tcid"   , des_tcid_str);
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"ip"     , c_word_to_ipv4(des_ipaddr));
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"port"   , c_word_to_str(des_port));
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"elapsed", c_word_to_str(elapsed_msec));

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_ping_get_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_ping_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_ping_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_settcid_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_ping_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_ping_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_ping_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: online ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_online_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/online") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/online")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_online(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_online: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_online_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_online_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_online_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_online_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_online_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_online_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_online_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_online_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_online_get_request(CHTTP_NODE *chttp_node)
{
//    CSOCKET_CNODE * csocket_cnode;

    char          * network_str;
    char          * tcid_str;
    char          * service_name_str;

    CSTRING         service_name;

    MOD_NODE        recv_mod_node;

    /*service*/
    service_name_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_name_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_online_get_request: "
                                                  "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_online_get_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_name, (const UINT8 *)service_name_str); /*mount only*/

    /*network*/
    network_str = chttp_node_get_header(chttp_node, (const char *)"network");
    if(NULL_PTR == network_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_online_get_request: "
                                                  "no network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_online_get_request: "
                                                  "no network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(network_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_online_get_request: "
                                                  "invalid network '%s' in header\n",
                                                  network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_online_get_request: "
                                                  "invalid network '%s' in header",
                                                  network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*tcid*/
    tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_online_get_request: "
                                                  "no tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_online_get_request: "
                                                  "no tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_online_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_online_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0; /*only one tdns*/

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_ctdns_online, CMPI_ERROR_MODI, c_str_to_word(network_str), c_ipv4_to_word(tcid_str), &service_name);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_online_get_request: "
                                              "network %s, tcid '%s', service '%s', report online",
                                              network_str,
                                              tcid_str,
                                              service_name_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_online_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_online_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_online_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_online_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_online_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_online_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_online_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: offline ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_offline_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/offline") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/offline")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_offline(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_offline: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_offline_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_offline_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_offline_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_offline_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_offline_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_offline_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_offline_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_offline_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_offline_get_request(CHTTP_NODE *chttp_node)
{
//    CSOCKET_CNODE * csocket_cnode;

    char          * network_str;
    char          * tcid_str;
    char          * service_name_str;
    char          * on_tcid_str;

    CSTRING         service_name;

    MOD_NODE        recv_mod_node;

    /*service*/
    service_name_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_name_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_offline_get_request: "
                                                  "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_offline_get_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_name, (const UINT8 *)service_name_str); /*mount only*/

    /*network*/
    network_str = chttp_node_get_header(chttp_node, (const char *)"network");
    if(NULL_PTR == network_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_offline_get_request: "
                                                  "no network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_offline_get_request: "
                                                  "no network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(network_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_offline_get_request: "
                                                  "invalid network '%s' in header\n",
                                                  network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_offline_get_request: "
                                                  "invalid network '%s' in header",
                                                  network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*tcid*/
    tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_offline_get_request: "
                                                  "no tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_offline_get_request: "
                                                  "no tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_offline_get_request: "
                                                  "invalid tcid '%s' in header\n",
                                                  tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_offline_get_request: "
                                                  "invalid tcid '%s' in header",
                                                  tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR != on_tcid_str && EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_offline_get_request: "
                                                  "invalid on_tcid '%s' in header\n",
                                                  on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_offline_get_request: "
                                                  "invalid on_tcid '%s' in header",
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    if(NULL_PTR != on_tcid_str)
    {
        MOD_NODE_TCID(&recv_mod_node) = c_ipv4_to_word(on_tcid_str);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0; /*only one tdns*/

        task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                 &recv_mod_node,
                 NULL_PTR,
                 FI_ctdns_offline, CMPI_ERROR_MODI, c_str_to_word(network_str), c_ipv4_to_word(tcid_str), &service_name);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_offline_get_request: "
                                                  "network %s, tcid '%s', service '%s', report offline on tcid %s",
                                                  network_str,
                                                  tcid_str,
                                                  service_name_str,
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        return (EC_TRUE);
    }

    MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0; /*only one tdns*/

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_ctdns_offline, CMPI_ERROR_MODI, c_str_to_word(network_str), c_ipv4_to_word(tcid_str), &service_name);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_offline_get_request: "
                                              "network %s, tcid '%s', service '%s', report offline",
                                              network_str,
                                              tcid_str,
                                              service_name_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_offline_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_offline_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_offline_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_offline_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_offline_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_offline_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_offline_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: upper ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_upper_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/upper") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/upper")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_upper(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_upper: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_upper_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_upper_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_upper_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_upper_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_upper_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_upper_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_upper_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_upper_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_upper_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE      * csocket_cnode;

    char               * service_str;
    char               * on_tcid_str;

    CSTRING              service_cstr;

    UINT32               on_tcid;
    UINT32               max_num;

    CTDNSSV_NODE_MGR   * ctdnssv_node_mgr;

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_upper_get_request: "
                                                  "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_upper_get_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR != on_tcid_str && EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_upper_get_request: "
                                                  "invalid on_tcid '%s' in header\n",
                                                  on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_upper_get_request: "
                                                  "invalid on_tcid '%s' in header",
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    if(NULL_PTR == on_tcid_str)
    {
        on_tcid = CMPI_LOCAL_TCID;
    }
    else
    {
        on_tcid = c_ipv4_to_word(on_tcid_str);
    }

    max_num = ((UINT32)(~(UINT32)0));

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_upper_get_request: no memory\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_upper_get_request: no memory");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(CMPI_LOCAL_TCID == on_tcid)
    {
        if(EC_FALSE == ctdns_finger_upper_service(CSOCKET_CNODE_MODI(csocket_cnode), &service_cstr,
                                 max_num, ctdnssv_node_mgr))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_upper_get_request: "
                                                      "finger upper nodes of service '%s' failed\n",
                                                      service_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_upper_get_request: "
                                                      "finger upper nodes of service '%s' failed",
                                                      service_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }


        dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_upper_get_request: "
                                                  "finger upper nodes of service '%s' done\n",
                                                  service_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_upper_get_request: "
                                                  "finger upper nodes of service '%s' done",
                                                  service_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        MOD_NODE        recv_mod_node;
        EC_BOOL         ret;

        MOD_NODE_TCID(&recv_mod_node) = on_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0; /*only one tdns*/

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_ctdns_finger_upper_service, CMPI_ERROR_MODI, &service_cstr, max_num, ctdnssv_node_mgr);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_upper_get_request: "
                                                      "finger upper nodes of service '%s' on tcid '%s' failed\n",
                                                      service_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_upper_get_request: "
                                                      "finger upper nodes of service '%s' on tcid '%s' failed",
                                                      service_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_upper_get_request: "
                                                  "finger upper nodes of service '%s' on tcid '%s' done\n",
                                                  service_str, on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_upper_get_request: "
                                                  "finger upper nodes of service '%s'on tcid '%s' done",
                                                  service_str, on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    /*json encode*/
    if(EC_FALSE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        CBYTES             * rsp_content_cbytes;

        json_object        * rsp_body_obj;
        const char         * rsp_body_str;

        CLIST_DATA         * clist_data;

        rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
        cbytes_clean(rsp_content_cbytes);

        rsp_body_obj = json_object_new_array();

        CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
        {
            CTDNSSV_NODE        *ctdnssv_node;
            json_object         *ctdnssv_obj;

            ctdnssv_node = CLIST_DATA_DATA(clist_data);

            ctdnssv_obj = json_object_new_object();
            json_object_object_add(ctdnssv_obj, (const char *)"tcid",
                                   json_object_new_string(c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node))));

            json_object_object_add(ctdnssv_obj, (const char *)"ip",
                                   json_object_new_string(c_word_to_ipv4(CTDNSSV_NODE_IPADDR(ctdnssv_node))));

            json_object_object_add(ctdnssv_obj, (const char *)"port",
                                   json_object_new_string(c_word_to_str(CTDNSSV_NODE_PORT(ctdnssv_node))));

            json_object_array_add(rsp_body_obj, ctdnssv_obj);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str)/* + 1*/);

        /* free json obj */
        json_object_put(rsp_body_obj);

        dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_upper_get_request done\n");
    }

    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_upper_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_upper_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_upper_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_upper_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_upper_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_upper_get_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_upper_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_upper_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: edge ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_edge_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/edge") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/edge")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_edge(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_edge: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_edge_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_edge_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_edge_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_edge_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_edge_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_edge_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_edge_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_edge_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_edge_get_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE      * csocket_cnode;

    char               * service_str;
    char               * on_tcid_str;

    CSTRING              service_cstr;

    UINT32               on_tcid;
    UINT32               max_num;

    CTDNSSV_NODE_MGR   * ctdnssv_node_mgr;

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_edge_get_request: "
                                                  "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_edge_get_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR != on_tcid_str && EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_edge_get_request: "
                                                  "invalid on_tcid '%s' in header\n",
                                                  on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_edge_get_request: "
                                                  "invalid on_tcid '%s' in header",
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    if(NULL_PTR == on_tcid_str)
    {
        on_tcid = CMPI_LOCAL_TCID;
    }
    else
    {
        on_tcid = c_ipv4_to_word(on_tcid_str);
    }

    max_num = ((UINT32)(~(UINT32)0));

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_edge_get_request: no memory\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_edge_get_request: no memory");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(CMPI_LOCAL_TCID == on_tcid)
    {
        if(EC_FALSE == ctdns_finger_edge_service(CSOCKET_CNODE_MODI(csocket_cnode), &service_cstr,
                                 max_num, ctdnssv_node_mgr))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_edge_get_request: "
                                                      "finger edge nodes of service '%s' failed\n",
                                                      service_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_edge_get_request: "
                                                      "finger edge nodes of service '%s' failed",
                                                      service_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }


        dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_edge_get_request: "
                                                  "finger edge nodes of service '%s' done\n",
                                                  service_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_edge_get_request: "
                                                  "finger edge nodes of service '%s' done",
                                                  service_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        MOD_NODE        recv_mod_node;
        EC_BOOL         ret;

        MOD_NODE_TCID(&recv_mod_node) = on_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0; /*only one tdns*/

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_ctdns_finger_edge_service, CMPI_ERROR_MODI, &service_cstr, max_num, ctdnssv_node_mgr);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_edge_get_request: "
                                                      "finger edge nodes of service '%s' on tcid '%s' failed\n",
                                                      service_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_edge_get_request: "
                                                      "finger edge nodes of service '%s' on tcid '%s' failed",
                                                      service_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_edge_get_request: "
                                                  "finger edge nodes of service '%s' on tcid '%s' done\n",
                                                  service_str, on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_edge_get_request: "
                                                  "finger edge nodes of service '%s'on tcid '%s' done",
                                                  service_str, on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    /*json encode*/
    if(EC_FALSE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        CBYTES             * rsp_content_cbytes;

        json_object        * rsp_body_obj;
        const char         * rsp_body_str;

        CLIST_DATA         * clist_data;

        rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
        cbytes_clean(rsp_content_cbytes);

        rsp_body_obj = json_object_new_array();

        CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
        {
            CTDNSSV_NODE        *ctdnssv_node;
            json_object         *ctdnssv_obj;

            ctdnssv_node = CLIST_DATA_DATA(clist_data);

            ctdnssv_obj = json_object_new_object();
            json_object_object_add(ctdnssv_obj, (const char *)"tcid",
                                   json_object_new_string(c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node))));

            json_object_object_add(ctdnssv_obj, (const char *)"ip",
                                   json_object_new_string(c_word_to_ipv4(CTDNSSV_NODE_IPADDR(ctdnssv_node))));

            json_object_object_add(ctdnssv_obj, (const char *)"port",
                                   json_object_new_string(c_word_to_str(CTDNSSV_NODE_PORT(ctdnssv_node))));

            json_object_array_add(rsp_body_obj, ctdnssv_obj);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str)/* + 1*/);

        /* free json obj */
        json_object_put(rsp_body_obj);

        dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_edge_get_request done\n");
    }

    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_edge_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_edge_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_edge_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_edge_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_edge_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_edge_get_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_edge_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_edge_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: refresh ----------------------------------------*/
STATIC_CAST static EC_BOOL __ctdnshttp_uri_is_refresh_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/refresh") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/refresh")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_is_http_get_refresh(const CHTTP_NODE *chttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    dbg_log(SEC_0048_CTDNSHTTP, 9)(LOGSTDOUT, "[DEBUG] ctdnshttp_is_http_get_refresh: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __ctdnshttp_uri_is_refresh_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctdnshttp_commit_refresh_get_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == ctdnshttp_handle_refresh_get_request(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_refresh_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnshttp_make_refresh_get_response(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_refresh_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = ctdnshttp_commit_refresh_get_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_refresh_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL ctdnshttp_handle_refresh_get_request(CHTTP_NODE *chttp_node)
{
    //CSOCKET_CNODE      * csocket_cnode;

    char               * service_str;
    char               * path_str;
    char               * des_network_str;
    char               * des_tcid_str;
    char               * on_tcid_str;

    UINT32               des_network;
    UINT32               des_tcid;
    UINT32               on_tcid;

    CSTRING              service;
    CSTRING              path;

    EC_BOOL              ret;

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service, (const UINT8 *)service_str);/*mount only*/

    /*path*/
    path_str = chttp_node_get_header(chttp_node, (const char *)"path");
    if(NULL_PTR == path_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "no path in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "no path in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if('/' != (*path_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid path '%s' in header\n",
                                                  path_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid path '%s' in header",
                                                  path_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&path, (const UINT8 *)path_str);/*mount only*/

    /*des_network*/
    des_network_str = chttp_node_get_header(chttp_node, (const char *)"des_network");
    if(NULL_PTR == des_network_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "no des_network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "no des_network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(des_network_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid des_network '%s' in header\n",
                                                  des_network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid des_network '%s' in header",
                                                  des_network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    des_network = c_str_to_word(des_network_str);

    /*des_tcid*/
    des_tcid_str = chttp_node_get_header(chttp_node, (const char *)"des_tcid");
    if(NULL_PTR != des_tcid_str && EC_FALSE == c_ipv4_is_ok(des_tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid des_tcid '%s' in header\n",
                                                  des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid des_tcid '%s' in header",
                                                  des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    if(NULL_PTR != des_tcid_str)
    {
        des_tcid    = c_ipv4_to_word(des_tcid_str);
    }
    else
    {
        des_tcid = CMPI_ANY_TCID;
    }

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR != on_tcid_str && EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid on_tcid '%s' in header\n",
                                                  on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                  "invalid on_tcid '%s' in header",
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    if(NULL_PTR != on_tcid_str)
    {
        on_tcid = c_ipv4_to_word(on_tcid_str);
    }
    else
    {
        on_tcid = CMPI_LOCAL_TCID;
    }

    //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    /*refresh cache*/
    if(1)
    {
        MOD_NODE   recv_mod_node;

        MOD_NODE_TCID(&recv_mod_node) = on_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_ctdns_refresh_cache, CMPI_ERROR_MODI, des_network, des_tcid, &service, &path);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_refresh_get_request: "
                                                      "refresh service '%s', path '%s' to '%s' on tcid '%s' failed\n",
                                                      service_str, path_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_refresh_get_request: "
                                                      "refresh service '%s', path '%s' to '%s' on tcid '%s' failed",
                                                      service_str, path_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_refresh_get_request: "
                                              "refresh service '%s', file '%s' to '%s' on tcid '%s' done\n",
                                              service_str, path_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_refresh_get_request: "
                                              "refresh service '%s', file '%s' to '%s' on tcid '%s' done",
                                              service_str, path_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL ctdnshttp_make_refresh_get_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_refresh_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_refresh_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_refresh_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_make_refresh_get_response: make header end failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnshttp_commit_refresh_get_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_refresh_get_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return ctdnshttp_commit_response(chttp_node);
}
#endif


#ifdef __cplusplus
}
#endif/*__cplusplus*/

