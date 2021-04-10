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

#include "cp2p.h"
#include "chttp.inc"
#include "chttp.h"
#include "cp2phttp.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "findex.inc"



#if 0
#define CP2PHTTP_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CP2PHTTP_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CP2PHTTP_PRINT_UINT8(info, buff, len) do{}while(0)
#define CP2PHTTP_PRINT_CHARS(info, buff, len) do{}while(0)
#endif



#if 1
#define CP2PHTTP_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

#if 0
#define CP2PHTTP_ASSERT(condition) do{}while(0)
#endif

#if 1
//#define CP2PHTTP_TIME_COST_FORMAT " BegTime:%u.%03u EndTime:%u.%03u Elapsed:%u "
#define CP2PHTTP_TIME_COST_FORMAT " %u.%03u %u.%03u %u "
#define CP2PHTTP_TIME_COST_VALUE(chttp_node)  \
    (uint32_t)CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node)), (uint32_t)CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)))
#endif

static EC_BOOL g_cp2phttp_log_init = EC_FALSE;

static const CHTTP_API g_cp2phttp_api_list[] = {
    {CONST_STR_AND_LEN("push")            , CHTTP_METHOD_GET  , cp2phttp_commit_push_request},
    {CONST_STR_AND_LEN("flush")           , CHTTP_METHOD_GET  , cp2phttp_commit_flush_request},
    {CONST_STR_AND_LEN("online")          , CHTTP_METHOD_GET  , cp2phttp_commit_online_request},
    {CONST_STR_AND_LEN("offline")         , CHTTP_METHOD_GET  , cp2phttp_commit_offline_request},
    {CONST_STR_AND_LEN("upper")           , CHTTP_METHOD_GET  , cp2phttp_commit_upper_request},
    {CONST_STR_AND_LEN("edge")            , CHTTP_METHOD_GET  , cp2phttp_commit_edge_request},
    {CONST_STR_AND_LEN("refresh")         , CHTTP_METHOD_GET  , cp2phttp_commit_refresh_request},

    {CONST_STR_AND_LEN("upload")          , CHTTP_METHOD_POST , cp2phttp_commit_upload_request},
};

static const uint32_t   g_cp2phttp_api_num = sizeof(g_cp2phttp_api_list)/sizeof(g_cp2phttp_api_list[0]);


EC_BOOL cp2phttp_log_start()
{
    TASK_BRD        *task_brd;

    if(EC_TRUE == g_cp2phttp_log_init)
    {
        return (EC_TRUE);
    }

    g_cp2phttp_log_init = EC_TRUE;

    task_brd = task_brd_default_get();

#if 0/*support rotate*/
    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;

        log_file_name = cstring_new(NULL_PTR, LOC_CP2PHTTP_0001);
        cstring_format(log_file_name, "%s/p2p_%s_%ld.log",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        if(EC_FALSE == user_log_open(LOGUSER08, (char *)cstring_get_str(log_file_name), "a+"))/*append mode. scenario: after restart*/
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_log_start: user_log_open '%s' -> LOGUSER08 failed\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CP2PHTTP_0002);
        cstring_format(log_file_name, "%s/p2p_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER08, log);

            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "[DEBUG] cp2phttp_log_start: log_file_open '%s' -> LOGUSER08 done\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CP2PHTTP_0003);
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
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_log_start: log_file_open '%s' -> LOGUSER07 failed\n",
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
EC_BOOL cp2phttp_commit_request(CHTTP_NODE *chttp_node)
{
    http_parser_t *http_parser;
    uint32_t       method;

    http_parser = CHTTP_NODE_PARSER(chttp_node);

    method = chttp_method_convert(http_parser->method);
    if(CHTTP_METHOD_UNKNOWN != method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)cp2phttp_commit_start, 2, chttp_node, (UINT32)method);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_request: "
                                                     "no croutine\n");

            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CP2PHTTP_0004);

        return (EC_TRUE);
    }

    dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_request: "
                                             "not support http method %d yet\n",
                                             http_parser->method);
    return (EC_FALSE);/*note: this chttp_node must be discarded*/
}

EC_BOOL cp2phttp_commit_start(CHTTP_NODE *chttp_node, const UINT32 method)
{
    const CHTTP_API       *chttp_api;
    EC_BOOL                ret;

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record p2p beg to handle time*/

    chttp_api = chttp_node_find_api(chttp_node,
                                    (const CHTTP_API *)g_cp2phttp_api_list,
                                    g_cp2phttp_api_num,
                                    (uint32_t)method);
    if(NULL_PTR == chttp_api)
    {
        CBUFFER               *url_cbuffer;

        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_start: "
                                                 "no api for %s:'%.*s'\n",
                                                 chttp_method_str((uint32_t)method),
                                                 CBUFFER_USED(CHTTP_NODE_ARGS(chttp_node)),
                                                 CBUFFER_DATA(CHTTP_NODE_ARGS(chttp_node)));

        url_cbuffer   = CHTTP_NODE_URL(chttp_node);
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_start: "
                                                 "invalid request %s:'%.*s'\n",
                                                 chttp_method_str((uint32_t)method),
                                                 CBUFFER_USED(url_cbuffer),
                                                 CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_ERR %u --", CHTTP_NOT_ACCEPTABLE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_commit_start: invalid request %s:'%.*s'",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(url_cbuffer), CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;

        return cp2phttp_commit_end(chttp_node, ret);
    }

    dbg_log(SEC_0068_CP2PHTTP, 9)(LOGSTDOUT, "[DEBUG] cp2phttp_commit_start: "
                                             "api: method %d, name %s\n",
                                             CHTTP_API_METHOD(chttp_api),
                                             CHTTP_API_NAME(chttp_api));

    ret = CHTTP_API_COMMIT(chttp_api)(chttp_node);
    return cp2phttp_commit_end(chttp_node, ret);
}

EC_BOOL cp2phttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result)
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

        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

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

            dbg_log(SEC_0068_CP2PHTTP, 1)(LOGSTDOUT, "[DEBUG] cp2phttp_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
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

        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        /*free*/
        chttp_node_free(chttp_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL cp2phttp_commit_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
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
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: upload ----------------------------------------*/
EC_BOOL cp2phttp_commit_upload_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_upload_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upload_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_upload_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upload_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_upload_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upload_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_upload_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE      * csocket_cnode;

    char               * service_str;
    char               * des_fname_str;
    char               * des_tcid_str;

    CSTRING              service_cstr;
    UINT32               des_tcid;
    CSTRING              des_fname_cstr;

    CBYTES             * src_file_content;
    uint64_t             body_len;
    uint64_t             content_len;

    EC_BOOL              ret;

    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    body_len     = chttp_node_recv_len(chttp_node);

    if(content_len > body_len)
    {
        dbg_log(SEC_0068_CP2PHTTP, 1)(LOGSTDOUT, "warn:cp2phttp_handle_upload_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CP2P_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:cp2phttp_handle_upload_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_fname*/
    des_fname_str = chttp_node_get_header(chttp_node, (const char *)"des_fname");
    if(NULL_PTR == des_fname_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: no des_fname in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: no des_fname in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if('/' != (*des_fname_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: "
                                                 "invalid src_fname '%s' in header\n",
                                                 des_fname_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: "
                                                  "invalid src_fname '%s' in header",
                                                  des_fname_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_tcid*/
    des_tcid_str = chttp_node_get_header(chttp_node, (const char *)"des_tcid");
    if(NULL_PTR == des_tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: no des_tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: no des_tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(des_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: "
                                                 "invalid des_tcid '%s' in header\n",
                                                 des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: "
                                                  "invalid des_tcid '%s' in header",
                                                  des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    des_tcid = c_ipv4_to_word(des_tcid_str);

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    src_file_content = cbytes_new(0);
    if(NULL_PTR == src_file_content)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CP2P_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: new cbytes without buff failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, src_file_content, (UINT32)body_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "CP2P_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cbytes_free(src_file_content);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    cstring_init(&service_cstr, (const UINT8 *)service_str);
    cstring_init(&des_fname_cstr, (const UINT8 *)des_fname_str);

    if(CMPI_LOCAL_TCID == des_tcid)
    {
        ret = cp2p_file_upload(CSOCKET_CNODE_MODI(csocket_cnode), src_file_content, &service_cstr, &des_fname_cstr);
    }
    else
    {
        MOD_NODE        recv_mod_node;

        MOD_NODE_TCID(&recv_mod_node) = des_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;

        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cp2p_file_upload, CMPI_ERROR_MODI, src_file_content, &service_cstr, &des_fname_cstr);
    }

    cbytes_free(src_file_content);
    cstring_clean(&service_cstr);
    cstring_clean(&des_fname_cstr);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upload_request: "
                                                 "upload service '%s', file '%s' on tcid '%s' failed\n",
                                                 service_str, des_fname_str, des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upload_request: "
                                                  "upload service '%s', file '%s' on tcid '%s' failed",
                                                  service_str, des_fname_str, des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

        return (EC_TRUE);
    }

    dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_upload_request: "
                                             "upload service '%s', file '%s' on tcid '%s' done\n",
                                             service_str, des_fname_str, des_tcid_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)body_len);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_upload_request: "
                                              "upload service '%s', file '%s' on tcid '%s' done",
                                              service_str, des_fname_str, des_tcid_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_upload_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upload_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upload_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upload_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upload_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_upload_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upload_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: push ----------------------------------------*/
EC_BOOL cp2phttp_commit_push_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_push_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_push_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_push_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_push_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_push_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_push_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_push_request(CHTTP_NODE *chttp_node)
{
    //CSOCKET_CNODE      * csocket_cnode;

    char               * service_str;
    char               * src_fname_str;
    char               * des_network_str;
    char               * des_tcid_str;
    char               * on_tcid_str;

    UINT32               des_network;
    UINT32               des_tcid;
    UINT32               on_tcid;

    CP2P_FILE            cp2p_file;
    EC_BOOL              ret;

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*src_fname*/
    src_fname_str = chttp_node_get_header(chttp_node, (const char *)"src_fname");
    if(NULL_PTR == src_fname_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "no src_fname in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "no src_fname in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if('/' != (*src_fname_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "invalid src_fname '%s' in header\n",
                                                 src_fname_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "invalid src_fname '%s' in header",
                                                  src_fname_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_network*/
    des_network_str = chttp_node_get_header(chttp_node, (const char *)"des_network");
    if(NULL_PTR == des_network_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "no des_network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "no des_network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(des_network_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "invalid des_network '%s' in header\n",
                                                 des_network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "invalid des_network '%s' in header",
                                                  des_network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_tcid*/
    des_tcid_str = chttp_node_get_header(chttp_node, (const char *)"des_tcid");
    if(NULL_PTR == des_tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "no des_tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "no des_tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(des_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "invalid des_tcid '%s' in header\n",
                                                 des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "invalid des_tcid '%s' in header",
                                                  des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR == on_tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "no on_tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "no on_tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                 "invalid on_tcid '%s' in header\n",
                                                 on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                  "invalid on_tcid '%s' in header",
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    des_network = c_str_to_word(des_network_str);
    on_tcid     = c_ipv4_to_word(on_tcid_str);
    des_tcid    = c_ipv4_to_word(des_tcid_str);

    cp2p_file_init(&cp2p_file);
    cstring_init(CP2P_FILE_SERVICE_NAME(&cp2p_file), (const UINT8 *)service_str);
    cstring_init(CP2P_FILE_SRC_NAME(&cp2p_file), (const UINT8 *)src_fname_str);
    CP2P_FILE_REPORT_TCID(&cp2p_file) = on_tcid;

    /*fetch file size*/
    if(1)
    {
        CSTRING    xfs_file_path;
        MOD_NODE   recv_mod_node;
        uint64_t   file_size;

        EC_BOOL    ret;

        cstring_init(&xfs_file_path, NULL_PTR);
        cstring_format(&xfs_file_path, "/%s%s",
                        CP2P_FILE_SERVICE_NAME_STR(&cp2p_file),
                        CP2P_FILE_SRC_NAME_STR(&cp2p_file));

        MOD_NODE_TCID(&recv_mod_node) = on_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_size, CMPI_ERROR_MODI, &xfs_file_path, &file_size);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                     "fsize of service '%s', file '%s' on tcid '%s' failed\n",
                                                     service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                      "fsize of service '%s', file '%s' on tcid '%s' failed",
                                                      service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&xfs_file_path);
            cp2p_file_clean(&cp2p_file);
            return (EC_TRUE);
        }
        CP2P_FILE_SRC_SIZE(&cp2p_file) = (UINT32)file_size;

        cstring_clean(&xfs_file_path);
    }

    if(1)
    {
        CSTRING    xfs_file_path;
        MOD_NODE   recv_mod_node;

        EC_BOOL    ret;

        cstring_init(&xfs_file_path, NULL_PTR);
        cstring_format(&xfs_file_path, "/%s%s",
                        CP2P_FILE_SERVICE_NAME_STR(&cp2p_file),
                        CP2P_FILE_SRC_NAME_STR(&cp2p_file));

        MOD_NODE_TCID(&recv_mod_node) = on_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_md5sum, CMPI_ERROR_MODI, &xfs_file_path, CP2P_FILE_SRC_MD5(&cp2p_file));

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                     "md5sum of service '%s', file '%s' on tcid '%s' failed\n",
                                                     service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                      "md5sum of service '%s', file '%s' on tcid '%s' failed",
                                                      service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&xfs_file_path);
            cp2p_file_clean(&cp2p_file);
            return (EC_TRUE);
        }

        cstring_clean(&xfs_file_path);
    }

    /*push file*/
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
                 FI_cp2p_file_push, CMPI_ERROR_MODI, des_network, des_tcid, &cp2p_file);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_push_request: "
                                                     "push service '%s', file '%s' to '%s' on tcid '%s' failed\n",
                                                     service_str, src_fname_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_push_request: "
                                                      "push service '%s', file '%s' to '%s' on tcid '%s' failed",
                                                      service_str, src_fname_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cp2p_file_clean(&cp2p_file);
            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_push_request: "
                                             "push service '%s', file '%s' to '%s' on tcid '%s' done\n",
                                             service_str, src_fname_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_push_request: "
                                              "push service '%s', file '%s' to '%s' on tcid '%s' done",
                                              service_str, src_fname_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    cp2p_file_clean(&cp2p_file);
    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_push_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_push_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_push_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_push_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_push_response: make header end failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_push_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_push_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: flush ----------------------------------------*/
EC_BOOL cp2phttp_commit_flush_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_flush_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_flush_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_flush_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_flush_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_flush_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_flush_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_flush_request(CHTTP_NODE *chttp_node)
{
    //CSOCKET_CNODE      * csocket_cnode;

    char               * service_str;
    char               * src_fname_str;
    char               * des_fname_str;
    char               * des_network_str;
    char               * des_tcid_str;
    char               * on_tcid_str;

    UINT32               des_network;
    UINT32               des_tcid;
    UINT32               on_tcid;

    CP2P_FILE            cp2p_file;
    EC_BOOL              ret;

    /*service*/
    service_str = chttp_node_get_header(chttp_node, (const char *)"service");
    if(NULL_PTR == service_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*src_fname*/
    src_fname_str = chttp_node_get_header(chttp_node, (const char *)"src_fname");
    if(NULL_PTR == src_fname_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "no src_fname in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "no src_fname in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if('/' != (*src_fname_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "invalid src_fname '%s' in header\n",
                                                 src_fname_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "invalid src_fname '%s' in header",
                                                  src_fname_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_fname*/
    des_fname_str = chttp_node_get_header(chttp_node, (const char *)"des_fname");
    if(NULL_PTR == des_fname_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "no des_fname in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "no des_fname in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if('/' != (*des_fname_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "invalid des_fname '%s' in header\n",
                                                 des_fname_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "invalid des_fname '%s' in header",
                                                  des_fname_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_network*/
    des_network_str = chttp_node_get_header(chttp_node, (const char *)"des_network");
    if(NULL_PTR == des_network_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "no des_network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "no des_network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(des_network_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "invalid des_network '%s' in header\n",
                                                 des_network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "invalid des_network '%s' in header",
                                                  des_network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_tcid*/
    des_tcid_str = chttp_node_get_header(chttp_node, (const char *)"des_tcid");
    if(NULL_PTR == des_tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "no des_tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "no des_tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(des_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "invalid des_tcid '%s' in header\n",
                                                 des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "invalid des_tcid '%s' in header",
                                                  des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR == on_tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "no on_tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "no on_tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                 "invalid on_tcid '%s' in header\n",
                                                 on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                  "invalid on_tcid '%s' in header",
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    des_network = c_str_to_word(des_network_str);
    on_tcid     = c_ipv4_to_word(on_tcid_str);
    des_tcid    = c_ipv4_to_word(des_tcid_str);

    cp2p_file_init(&cp2p_file);
    cstring_init(CP2P_FILE_SERVICE_NAME(&cp2p_file), (const UINT8 *)service_str);
    cstring_init(CP2P_FILE_SRC_NAME(&cp2p_file), (const UINT8 *)src_fname_str);
    cstring_init(CP2P_FILE_DES_NAME(&cp2p_file), (const UINT8 *)des_fname_str);
    CP2P_FILE_REPORT_TCID(&cp2p_file) = on_tcid;

    /*fetch file size*/
    if(1)
    {
        CSTRING    xfs_file_path;
        MOD_NODE   recv_mod_node;
        uint64_t   file_size;

        EC_BOOL    ret;

        cstring_init(&xfs_file_path, NULL_PTR);
        cstring_format(&xfs_file_path, "/%s%s",
                        CP2P_FILE_SERVICE_NAME_STR(&cp2p_file),
                        CP2P_FILE_SRC_NAME_STR(&cp2p_file));

        MOD_NODE_TCID(&recv_mod_node) = on_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_size, CMPI_ERROR_MODI, &xfs_file_path, &file_size);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                     "fsize of service '%s', file '%s' on tcid '%s' failed\n",
                                                     service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                      "fsize of service '%s', file '%s' on tcid '%s' failed",
                                                      service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&xfs_file_path);
            cp2p_file_clean(&cp2p_file);
            return (EC_TRUE);
        }
        CP2P_FILE_SRC_SIZE(&cp2p_file) = (UINT32)file_size;

        cstring_clean(&xfs_file_path);
    }

    if(1)
    {
        CSTRING    xfs_file_path;
        MOD_NODE   recv_mod_node;

        EC_BOOL    ret;

        cstring_init(&xfs_file_path, NULL_PTR);
        cstring_format(&xfs_file_path, "/%s%s",
                        CP2P_FILE_SERVICE_NAME_STR(&cp2p_file),
                        CP2P_FILE_SRC_NAME_STR(&cp2p_file));

        MOD_NODE_TCID(&recv_mod_node) = on_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_md5sum, CMPI_ERROR_MODI, &xfs_file_path, CP2P_FILE_SRC_MD5(&cp2p_file));

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                     "md5sum of service '%s', file '%s' on tcid '%s' failed\n",
                                                     service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                      "md5sum of service '%s', file '%s' on tcid '%s' failed",
                                                      service_str, src_fname_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&xfs_file_path);
            cp2p_file_clean(&cp2p_file);
            return (EC_TRUE);
        }

        cstring_clean(&xfs_file_path);
    }

    /*flush file*/
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
                 FI_cp2p_file_flush, CMPI_ERROR_MODI, des_network, des_tcid, &cp2p_file);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_flush_request: "
                                                     "flush service '%s', file '%s' to '%s' on tcid '%s' failed\n",
                                                     service_str, src_fname_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_flush_request: "
                                                      "flush service '%s', file '%s' to '%s' on tcid '%s' failed",
                                                      service_str, src_fname_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cp2p_file_clean(&cp2p_file);
            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_flush_request: "
                                             "flush service '%s', file '%s' to '%s' on tcid '%s' done\n",
                                             service_str, src_fname_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_flush_request: "
                                              "flush service '%s', file '%s' to '%s' on tcid '%s' done",
                                              service_str, src_fname_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    cp2p_file_clean(&cp2p_file);
    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_flush_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_flush_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_flush_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_flush_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_flush_response: make header end failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_flush_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_flush_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: online ----------------------------------------*/
EC_BOOL cp2phttp_commit_online_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_online_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_online_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_online_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_online_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_online_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_online_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_online_request(CHTTP_NODE *chttp_node)
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
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_online_request: "
                                                 "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_online_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_name, (const UINT8 *)service_name_str); /*mount only*/

    /*network*/
    network_str = chttp_node_get_header(chttp_node, (const char *)"network");
    if(NULL_PTR == network_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_online_request: "
                                                 "no network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_online_request: "
                                                  "no network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(network_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_online_request: "
                                                 "invalid network '%s' in header\n",
                                                 network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_online_request: "
                                                  "invalid network '%s' in header",
                                                  network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*tcid*/
    tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_online_request: "
                                                 "no tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_online_request: "
                                                  "no tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_online_request: "
                                                 "invalid tcid '%s' in header\n",
                                                 tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_online_request: "
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
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_online_request: "
                                              "network %s, tcid '%s', service '%s', report online",
                                              network_str,
                                              tcid_str,
                                              service_name_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_online_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_online_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_online_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_online_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_online_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_online_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_online_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: offline ----------------------------------------*/
EC_BOOL cp2phttp_commit_offline_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_offline_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_offline_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_offline_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_offline_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_offline_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_offline_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_offline_request(CHTTP_NODE *chttp_node)
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
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_offline_request: "
                                                 "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_offline_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_name, (const UINT8 *)service_name_str); /*mount only*/

    /*network*/
    network_str = chttp_node_get_header(chttp_node, (const char *)"network");
    if(NULL_PTR == network_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_offline_request: "
                                                 "no network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_offline_request: "
                                                  "no network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(network_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_offline_request: "
                                                 "invalid network '%s' in header\n",
                                                 network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_offline_request: "
                                                  "invalid network '%s' in header",
                                                  network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*tcid*/
    tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_offline_request: "
                                                 "no tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_offline_request: "
                                                  "no tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_offline_request: "
                                                 "invalid tcid '%s' in header\n",
                                                 tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_offline_request: "
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
             FI_ctdns_offline, CMPI_ERROR_MODI, c_str_to_word(network_str), c_ipv4_to_word(tcid_str), &service_name);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_offline_request: "
                                              "network %s, tcid '%s', service '%s', report offline",
                                              network_str,
                                              tcid_str,
                                              service_name_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_offline_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_offline_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_offline_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_offline_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_offline_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_offline_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_offline_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: upper ----------------------------------------*/
EC_BOOL cp2phttp_commit_upper_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_upper_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upper_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_upper_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upper_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_upper_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upper_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_upper_request(CHTTP_NODE *chttp_node)
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
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upper_request: "
                                                 "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upper_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR != on_tcid_str && EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upper_request: "
                                                 "invalid on_tcid '%s' in header\n",
                                                 on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upper_request: "
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
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upper_request: no memory\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upper_request: no memory");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(CMPI_LOCAL_TCID == on_tcid)
    {
        if(EC_FALSE == ctdns_finger_upper_service(CSOCKET_CNODE_MODI(csocket_cnode), &service_cstr,
                                 max_num, ctdnssv_node_mgr))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upper_request: "
                                                     "finger upper nodes of service '%s' failed\n",
                                                     service_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upper_request: "
                                                      "finger upper nodes of service '%s' failed",
                                                      service_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }


        dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_upper_request: "
                                                 "finger upper nodes of service '%s' done\n",
                                                 service_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_upper_request: "
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
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_upper_request: "
                                                     "finger upper nodes of service '%s' on tcid '%s' failed\n",
                                                     service_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_upper_request: "
                                                      "finger upper nodes of service '%s' on tcid '%s' failed",
                                                      service_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_upper_request: "
                                                  "finger upper nodes of service '%s' on tcid '%s' done\n",
                                                  service_str, on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_upper_request: "
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

        dbg_log(SEC_0068_CP2PHTTP, 9)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_upper_request done\n");
    }

    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_upper_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upper_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upper_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upper_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upper_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_upper_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_upper_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_upper_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: edge ----------------------------------------*/
EC_BOOL cp2phttp_commit_edge_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_edge_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_edge_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_edge_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_edge_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_edge_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_edge_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_edge_request(CHTTP_NODE *chttp_node)
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
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_edge_request: "
                                                 "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_edge_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service_cstr, (const UINT8 *)service_str);

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR != on_tcid_str && EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_edge_request: "
                                                 "invalid on_tcid '%s' in header\n",
                                                 on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_edge_request: "
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
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_edge_request: no memory\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_edge_request: no memory");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    if(CMPI_LOCAL_TCID == on_tcid)
    {
        if(EC_FALSE == ctdns_finger_edge_service(CSOCKET_CNODE_MODI(csocket_cnode), &service_cstr,
                                 max_num, ctdnssv_node_mgr))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_edge_request: "
                                                      "finger edge nodes of service '%s' failed\n",
                                                      service_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_edge_request: "
                                                      "finger edge nodes of service '%s' failed",
                                                      service_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }


        dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_edge_request: "
                                                  "finger edge nodes of service '%s' done\n",
                                                  service_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_edge_request: "
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
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_edge_request: "
                                                      "finger edge nodes of service '%s' on tcid '%s' failed\n",
                                                      service_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_edge_request: "
                                                      "finger edge nodes of service '%s' on tcid '%s' failed",
                                                      service_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_edge_request: "
                                                  "finger edge nodes of service '%s' on tcid '%s' done\n",
                                                  service_str, on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_edge_request: "
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

        dbg_log(SEC_0068_CP2PHTTP, 9)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_edge_request done\n");
    }

    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_edge_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_edge_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_edge_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_edge_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_edge_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_edge_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_edge_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_edge_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: refresh ----------------------------------------*/
EC_BOOL cp2phttp_commit_refresh_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cp2phttp_handle_refresh_request(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_refresh_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cp2phttp_make_refresh_response(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_refresh_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cp2phttp_commit_refresh_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_refresh_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cp2phttp_handle_refresh_request(CHTTP_NODE *chttp_node)
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
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "no service in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "no service in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&service, (const UINT8 *)service_str);/*mount only*/

    /*path*/
    path_str = chttp_node_get_header(chttp_node, (const char *)"path");
    if(NULL_PTR == path_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "no path in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "no path in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if('/' != (*path_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "invalid path '%s' in header\n",
                                                 path_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "no path '%s' in header",
                                                  path_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    cstring_set_str(&path, (const UINT8 *)path_str);/*mount only*/

    /*des_network*/
    des_network_str = chttp_node_get_header(chttp_node, (const char *)"des_network");
    if(NULL_PTR == des_network_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "no des_network in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "no des_network in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_str_is_digit(des_network_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "invalid des_network '%s' in header\n",
                                                 des_network_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "invalid des_network '%s' in header",
                                                  des_network_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*des_tcid*/
    des_tcid_str = chttp_node_get_header(chttp_node, (const char *)"des_tcid");
    if(NULL_PTR == des_tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "no des_tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "no des_tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(des_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "invalid des_tcid '%s' in header\n",
                                                 des_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "invalid des_tcid '%s' in header",
                                                  des_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    /*on_tcid*/
    on_tcid_str = chttp_node_get_header(chttp_node, (const char *)"on_tcid");
    if(NULL_PTR == on_tcid_str)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "no on_tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "no on_tcid in header");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }
    if(EC_FALSE == c_ipv4_is_ok(on_tcid_str))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                 "invalid on_tcid '%s' in header\n",
                                                 on_tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                  "invalid on_tcid '%s' in header",
                                                  on_tcid_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        return (EC_TRUE);
    }

    //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    des_network = c_str_to_word(des_network_str);
    on_tcid     = c_ipv4_to_word(on_tcid_str);
    des_tcid    = c_ipv4_to_word(des_tcid_str);

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
                 FI_cp2p_refresh_cache, CMPI_ERROR_MODI, des_network, des_tcid, &service, &path);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_handle_refresh_request: "
                                                     "refresh service '%s', path '%s' to '%s' on tcid '%s' failed\n",
                                                     service_str, path_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cp2phttp_handle_refresh_request: "
                                                      "refresh service '%s', path '%s' to '%s' on tcid '%s' failed",
                                                      service_str, path_str, des_tcid_str, on_tcid_str);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0068_CP2PHTTP, 5)(LOGSTDOUT, "[DEBUG] cp2phttp_handle_refresh_request: "
                                             "refresh service '%s', file '%s' to '%s' on tcid '%s' done\n",
                                             service_str, path_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "P2P_SUCC %u %ld", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cp2phttp_handle_refresh_request: "
                                              "refresh service '%s', file '%s' to '%s' on tcid '%s' done",
                                              service_str, path_str, des_tcid_str, on_tcid_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cp2phttp_make_refresh_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_refresh_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_refresh_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_refresh_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_make_refresh_response: make header end failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cp2phttp_commit_refresh_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0068_CP2PHTTP, 0)(LOGSTDOUT, "error:cp2phttp_commit_refresh_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cp2phttp_commit_response(chttp_node);
}
#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

