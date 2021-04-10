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

#include "chttp.inc"
#include "chttp.h"
#include "cngx_http.h"
#include "cmon.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "findex.inc"

#if 0
#define CNGX_HTTP_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CNGX_HTTP_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CNGX_HTTP_PRINT_UINT8(info, buff, len) do{}while(0)
#define CNGX_HTTP_PRINT_CHARS(info, buff, len) do{}while(0)
#endif



#if 1
#define CNGX_HTTP_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

#if 0
#define CNGX_HTTP_ASSERT(condition) do{}while(0)
#endif

#if 1
//#define CNGX_HTTP_TIME_COST_FORMAT " BegTime:%u.%03u EndTime:%u.%03u Elapsed:%u "
#define CNGX_HTTP_TIME_COST_FORMAT " %u.%03u %u.%03u %u "
#define CNGX_HTTP_TIME_COST_VALUE(chttp_node)  \
    (uint32_t)CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node)), (uint32_t)CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)))
#endif

static EC_BOOL g_cngx_http_log_init = EC_FALSE;

static const CHTTP_API g_cngx_http_api_list[] = {
    {CONST_STR_AND_LEN("breathe")         , CHTTP_METHOD_GET  , cngx_http_commit_breathe_request},
    {CONST_STR_AND_LEN("logrotate")       , CHTTP_METHOD_GET  , cngx_http_commit_logrotate_request},
    {CONST_STR_AND_LEN("logreopen")       , CHTTP_METHOD_GET  , cngx_http_commit_logreopen_request},
    {CONST_STR_AND_LEN("activate")        , CHTTP_METHOD_GET  , cngx_http_commit_ngx_activate_request},
    {CONST_STR_AND_LEN("deactivate")      , CHTTP_METHOD_GET  , cngx_http_commit_ngx_deactivate_request},
    {CONST_STR_AND_LEN("actsyscfg")       , CHTTP_METHOD_GET  , cngx_http_commit_actsyscfg_request},
    {CONST_STR_AND_LEN("xfs_up")          , CHTTP_METHOD_GET  , cngx_http_commit_xfs_up_request},
    {CONST_STR_AND_LEN("xfs_down")        , CHTTP_METHOD_GET  , cngx_http_commit_xfs_down_request},

    {CONST_STR_AND_LEN("xfs_add")         , CHTTP_METHOD_GET  , cngx_http_commit_xfs_add_request},
    {CONST_STR_AND_LEN("xfs_del")         , CHTTP_METHOD_GET  , cngx_http_commit_xfs_del_request},
    {CONST_STR_AND_LEN("xfs_list")        , CHTTP_METHOD_GET  , cngx_http_commit_xfs_list_request},

    {CONST_STR_AND_LEN("ngx_reload_so")   , CHTTP_METHOD_GET  , cngx_http_commit_ngx_reload_so_request},
    {CONST_STR_AND_LEN("ngx_switch_so")   , CHTTP_METHOD_GET  , cngx_http_commit_ngx_switch_so_request},
    {CONST_STR_AND_LEN("ngx_show_so")     , CHTTP_METHOD_GET  , cngx_http_commit_ngx_show_so_request},
    {CONST_STR_AND_LEN("show_cmon_nodes") , CHTTP_METHOD_GET  , cngx_http_commit_ngx_show_cmon_nodes_request},
    {CONST_STR_AND_LEN("paracfg")         , CHTTP_METHOD_GET  , cngx_http_commit_paracfg_request},
};

static const uint32_t   g_cngx_http_api_num = sizeof(g_cngx_http_api_list)/sizeof(g_cngx_http_api_list[0]);


EC_BOOL cngx_http_log_start()
{
    TASK_BRD        *task_brd;

    if(EC_TRUE == g_cngx_http_log_init)
    {
        return (EC_TRUE);
    }

    g_cngx_http_log_init = EC_TRUE;

    task_brd = task_brd_default_get();

    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;
        LOG     *log;

        /*open log and redirect LOGUSER08 to it*/
        log_file_name = cstring_new(NULL_PTR, LOC_CNGX_0071);
#if 0
        cstring_format(log_file_name, "%s/ngx_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
#endif
#if 1
        cstring_format(log_file_name, "%s/xcache_ngx", (char *)TASK_BRD_LOG_PATH_STR(task_brd));
#endif

        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER08, log);

            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "[DEBUG] cngx_http_log_start: log_file_open '%s' -> LOGUSER08 done\n",
                               (char *)cstring_get_str(log_file_name));

            cstring_free(log_file_name);
        }
    }

    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;
        LOG     *log;

        /*open log and redirect LOGUSER08 to it*/
        log_file_name = cstring_new(NULL_PTR, LOC_CNGX_0072);
#if 0
        cstring_format(log_file_name, "%s/storage_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
#endif
#if 1
        cstring_format(log_file_name, "%s/xcache_storage", (char *)TASK_BRD_LOG_PATH_STR(task_brd));
#endif

        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER09, log);

            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "[DEBUG] cngx_http_log_start: log_file_open '%s' -> LOGUSER08 done\n",
                               (char *)cstring_get_str(log_file_name));

            cstring_free(log_file_name);
        }
    }
    return (EC_TRUE);
}



/*---------------------------------------- ENTRY: HTTP COMMIT REQUEST FOR HANDLER  ----------------------------------------*/
EC_BOOL cngx_http_commit_request(CHTTP_NODE *chttp_node)
{
    http_parser_t *http_parser;
    uint32_t       method;

    http_parser = CHTTP_NODE_PARSER(chttp_node);

    method = chttp_method_convert(http_parser->method);
    if(CHTTP_METHOD_UNKNOWN != method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)cngx_http_commit_start, 2, chttp_node, (UINT32)method);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_request: "
                                                      "no croutine\n");

            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CNGX_0073);

        return (EC_TRUE);
    }

    dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_request: "
                                              "not support http method %d yet\n",
                                              http_parser->method);
    return (EC_FALSE);/*note: this chttp_node must be discarded*/
}

EC_BOOL cngx_http_commit_start(CHTTP_NODE *chttp_node, const UINT32 method)
{
    const CHTTP_API       *chttp_api;
    EC_BOOL                ret;

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record xfs beg to handle time*/

    chttp_api = chttp_node_find_api(chttp_node,
                                    (const CHTTP_API *)g_cngx_http_api_list,
                                    g_cngx_http_api_num,
                                    (uint32_t)method);
    if(NULL_PTR == chttp_api)
    {
        CBUFFER               *url_cbuffer;

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_start: "
                                                  "no api for %s:'%.*s'\n",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(CHTTP_NODE_ARGS(chttp_node)),
                                                  CBUFFER_DATA(CHTTP_NODE_ARGS(chttp_node)));

        url_cbuffer   = CHTTP_NODE_URL(chttp_node);
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_start: "
                                                  "invalid request %s:'%.*s'\n",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(url_cbuffer),
                                                  CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_NOT_ACCEPTABLE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_commit_start: invalid request %s:'%.*s'",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(url_cbuffer), CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;

        return cngx_http_commit_end(chttp_node, ret);
    }

    dbg_log(SEC_0054_CNGX_HTTP, 9)(LOGSTDOUT, "[DEBUG] cngx_http_commit_start: "
                                              "api: method %d, name %s\n",
                                              CHTTP_API_METHOD(chttp_api),
                                              CHTTP_API_NAME(chttp_api));

    ret = CHTTP_API_COMMIT(chttp_api)(chttp_node);
    return cngx_http_commit_end(chttp_node, ret);
}

EC_BOOL cngx_http_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result)
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

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

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

            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
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

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        /*free*/
        chttp_node_free(chttp_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL cngx_http_commit_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
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
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: breathe ----------------------------------------*/
EC_BOOL cngx_http_commit_breathe_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_breathe_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_breathe_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_breathe_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_breathe_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_breathe_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_breathe_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_breathe_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    dbg_log(SEC_0054_CNGX_HTTP, 9)(LOGSTDOUT, "[DEBUG] cngx_http_handle_breathe_request\n");

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_breathe_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_breathe_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_breathe_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_breathe_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        //CSOCKET_CNODE * csocket_cnode;

        //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        breathing_static_mem();

        dbg_log(SEC_0054_CNGX_HTTP, 9)(LOGSTDOUT, "[DEBUG] cngx_http_handle_breathe_request: memory breathing done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_breathe_request: memory breathing done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_breathe_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_breathe_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_breathe_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_breathe_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_breathe_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_breathe_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: logrotate ----------------------------------------*/
EC_BOOL cngx_http_commit_logrotate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_logrotate_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logrotate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_logrotate_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logrotate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_logrotate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logrotate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_logrotate_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_logrotate_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_logrotate_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_logrotate_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_logrotate_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

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
                dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                return (EC_TRUE);
            }

            dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "[DEBUG] cngx_http_handle_logrotate_request: log rotate %ld done\n", log_index);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_logrotate_request: log rotate %ld done", log_index);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

            return (EC_TRUE);
        }

        /*else*/
        log_index_str_t = c_str_dup(log_index_str);
        if(NULL_PTR == log_index_str_t)
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_handle_logrotate_request: no memory\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_logrotate_request: no memory");

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
                dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                c_str_free(log_index_str_t);

                return (EC_TRUE);
            }
        }

        dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "[DEBUG] cngx_http_handle_logrotate_request: log rotate %s done\n", log_index_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_logrotate_request: log rotate %s done", log_index_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        c_str_free(log_index_str_t);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_logrotate_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_logrotate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_logrotate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_logrotate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_logrotate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logrotate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: logreopen ----------------------------------------*/
EC_BOOL cngx_http_commit_logreopen_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_logreopen_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logreopen_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_logreopen_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logreopen_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_logreopen_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logreopen_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_logreopen_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_logreopen_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_logreopen_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_logreopen_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_logreopen_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

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

            if(EC_FALSE == super_reopen_log(super_md_id, log_index))
            {
                dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_handle_logreopen_request: log reopen %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_logreopen_request: log reopen %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                return (EC_TRUE);
            }

            dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "[DEBUG] cngx_http_handle_logreopen_request: log reopen %ld done\n", log_index);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_logreopen_request: log reopen %ld done", log_index);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

            return (EC_TRUE);
        }

        /*else*/
        log_index_str_t = c_str_dup(log_index_str);
        if(NULL_PTR == log_index_str_t)
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_handle_logreopen_request: no memory\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_logreopen_request: no memory");

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

            if(EC_FALSE == super_reopen_log(super_md_id, log_index))
            {
                dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_handle_logreopen_request: log reopen %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_logreopen_request: log reopen %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                c_str_free(log_index_str_t);

                return (EC_TRUE);
            }
        }

        dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "[DEBUG] cngx_http_handle_logreopen_request: log reopen %s done\n", log_index_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_logreopen_request: log reopen %s done", log_index_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        c_str_free(log_index_str_t);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_logreopen_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_logreopen_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_logreopen_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_logreopen_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_logreopen_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_logreopen_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: actsyscfg ----------------------------------------*/
EC_BOOL cngx_http_commit_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_actsyscfg_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_actsyscfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_actsyscfg_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_actsyscfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_actsyscfg_response(chttp_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_actsyscfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_actsyscfg_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_actsyscfg_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_actsyscfg_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_actsyscfg_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        UINT32 super_md_id;

        super_md_id = 0;

        super_activate_sys_cfg(super_md_id);

        dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "[DEBUG] cngx_http_handle_actsyscfg_request done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_actsyscfg_request done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_actsyscfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_actsyscfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_actsyscfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_actsyscfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_up ----------------------------------------*/
EC_BOOL cngx_http_commit_xfs_up_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_xfs_up_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_up_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_xfs_up_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_up_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_xfs_up_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_up_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_xfs_up_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_up_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_up_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_up_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_up_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_NOT_IMPLEMENTED);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_up_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;/*useless*/

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_up_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_up_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_up_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_up_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_up_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_up_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_set_node_up(cmon_id, &cmon_node))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_up_request: set up xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_up_request: set up xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_xfs_up_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_up_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_up_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_up_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_xfs_up_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_up_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_down ----------------------------------------*/
EC_BOOL cngx_http_commit_xfs_down_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_xfs_down_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_down_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_xfs_down_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_down_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_xfs_down_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_down_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_xfs_down_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_down_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_down_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_down_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_down_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_NOT_IMPLEMENTED);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_down_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_DOWN;/*useless*/

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_down_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_down_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_down_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_down_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_down_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_down_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_set_node_down(cmon_id, &cmon_node))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_down_request: set down xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_down_request: set down xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_xfs_down_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_down_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_down_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_down_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_xfs_down_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_down_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_add ----------------------------------------*/
EC_BOOL cngx_http_commit_xfs_add_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_xfs_add_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_add_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_xfs_add_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_add_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_xfs_add_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_add_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_xfs_add_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_add_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_add_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_add_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_add_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_NOT_IMPLEMENTED);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_add_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_add_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_add_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_add_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_add_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_add_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_add_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_add_node(cmon_id, &cmon_node))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_add_request: add xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_add_request: add xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_xfs_add_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_add_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_add_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_add_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_xfs_add_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_add_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_del ----------------------------------------*/
EC_BOOL cngx_http_commit_xfs_del_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_xfs_del_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_del_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_xfs_del_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_del_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_xfs_del_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_del_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_xfs_del_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_del_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_del_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_del_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_del_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_NOT_IMPLEMENTED);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_del_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_del_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_del_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_del_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_del_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_del_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttp_node_get_header(chttp_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_xfs_del_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_del_node(cmon_id, &cmon_node))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_del_request: del xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_del_request: del xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_xfs_del_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_del_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_del_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_del_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_xfs_del_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_del_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_list ----------------------------------------*/
EC_BOOL cngx_http_commit_xfs_list_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_xfs_list_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_list_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_xfs_list_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_list_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_xfs_list_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_list_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_xfs_list_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_list_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_list_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_xfs_list_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_list_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        UINT32       cmon_id;
        CSTRING      cxfs_list_cstr;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_NOT_IMPLEMENTED);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_xfs_list_request: no cmon start");

            return (EC_TRUE);
        }

        cstring_init(&cxfs_list_cstr, NULL_PTR);

        cmon_list_nodes(cmon_id, &cxfs_list_cstr);

        cbytes_mount(content_cbytes, CSTRING_LEN(&cxfs_list_cstr), CSTRING_STR(&cxfs_list_cstr), BIT_FALSE);
        cstring_unset(&cxfs_list_cstr);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_xfs_list_request: list xfs done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_xfs_list_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_list_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_list_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_list_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_xfs_list_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_xfs_list_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_xfs_list_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ngx_reload_so ----------------------------------------*/
EC_BOOL cngx_http_commit_ngx_reload_so_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_ngx_reload_so_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_reload_so_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_ngx_reload_so_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_reload_so_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_ngx_reload_so_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_reload_so_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_ngx_reload_so_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_reload_so_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_reload_so_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_reload_so_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_reload_so_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        char        *v;
        UINT32       ngx_tcid;

        MOD_NODE     recv_mod_node;

        v = chttp_node_get_header(chttp_node, (const char *)"ngx-tcid");
        if(NULL_PTR == v)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_reload_so_request: no ngx-tcid");

            return (EC_TRUE);
        }

        if(EC_FALSE == c_ipv4_is_ok(v))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_reload_so_request: invalid ngx-tcid '%s'", v);

            return (EC_TRUE);
        }

        ngx_tcid = c_ipv4_to_word(v);
        dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_ngx_reload_so_request: header ngx-tcid %s => 0x%lx\n",
                            v, ngx_tcid);

        MOD_NODE_TCID(&recv_mod_node) = ngx_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*super_md_id = 0*/

        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                 &recv_mod_node,
                 NULL,
                 FI_super_ngx_reload_so, CMPI_ERROR_MODI);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_reload_so_request: send ngx %s done",
                                c_word_to_ipv4(ngx_tcid));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_ngx_reload_so_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_reload_so_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_reload_so_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_reload_so_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_ngx_reload_so_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_reload_so_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ngx_switch_so ----------------------------------------*/
EC_BOOL cngx_http_commit_ngx_switch_so_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_ngx_switch_so_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_switch_so_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_ngx_switch_so_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_switch_so_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_ngx_switch_so_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_switch_so_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_ngx_switch_so_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_switch_so_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_switch_so_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_switch_so_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_switch_so_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        char        *v;
        UINT32       ngx_tcid;

        MOD_NODE     recv_mod_node;

        v = chttp_node_get_header(chttp_node, (const char *)"ngx-tcid");
        if(NULL_PTR == v)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_switch_so_request: no ngx-tcid");

            return (EC_TRUE);
        }

        if(EC_FALSE == c_ipv4_is_ok(v))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_switch_so_request: invalid ngx-tcid '%s'", v);

            return (EC_TRUE);
        }

        ngx_tcid = c_ipv4_to_word(v);
        dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_ngx_switch_so_request: header ngx-tcid %s => 0x%lx\n",
                            v, ngx_tcid);

        MOD_NODE_TCID(&recv_mod_node) = ngx_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*super_md_id = 0*/

        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                 &recv_mod_node,
                 NULL,
                 FI_super_ngx_switch_so, CMPI_ERROR_MODI);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_switch_so_request: send ngx %s done",
                                c_word_to_ipv4(ngx_tcid));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_ngx_switch_so_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_switch_so_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_switch_so_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_switch_so_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_ngx_switch_so_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_switch_so_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ngx_show_so ----------------------------------------*/
EC_BOOL cngx_http_commit_ngx_show_so_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_ngx_show_so_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_so_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_ngx_show_so_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_so_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_ngx_show_so_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_so_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_ngx_show_so_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_show_so_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_show_so_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_show_so_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_show_so_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        char        *v;
        UINT32       ngx_tcid;
        LOG         *log;

        MOD_NODE     recv_mod_node;

        v = chttp_node_get_header(chttp_node, (const char *)"ngx-tcid");
        if(NULL_PTR == v)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_show_so_request: no ngx-tcid");

            return (EC_TRUE);
        }

        if(EC_FALSE == c_ipv4_is_ok(v))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_show_so_request: invalid ngx-tcid '%s'", v);

            return (EC_TRUE);
        }

        ngx_tcid = c_ipv4_to_word(v);
        dbg_log(SEC_0054_CNGX_HTTP, 1)(LOGSTDOUT, "[DEBUG] cngx_http_handle_ngx_show_so_request: header ngx-tcid %s => 0x%lx\n",
                            v, ngx_tcid);

        log = log_cstr_open();
        if(NULL_PTR == log)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_show_so_request: no memory");

            return (EC_TRUE);
        }

        MOD_NODE_TCID(&recv_mod_node) = ngx_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*super_md_id = 0*/

        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                 &recv_mod_node,
                 NULL,
                 FI_super_ngx_show_so, CMPI_ERROR_MODI, log);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_show_so_request: send ngx %s done",
                                c_word_to_ipv4(ngx_tcid));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cbytes_mount(content_cbytes,
                     cstring_get_len(LOG_CSTR(log)),
                     cstring_get_str(LOG_CSTR(log)),
                     BIT_FALSE);
        cstring_unset(LOG_CSTR(log));

        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_ngx_show_so_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_so_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_so_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_so_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_so_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_ngx_show_so_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_so_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ngx_activate ----------------------------------------*/
EC_BOOL cngx_http_commit_ngx_activate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_ngx_activate_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_activate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_ngx_activate_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_activate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_ngx_activate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_activate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_ngx_activate_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_activate_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_activate_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_activate_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_activate_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        TASK_BRD        *task_brd;

        task_brd = task_brd_default_get();

        if(EC_FALSE == cmon_set_up(TASK_BRD_CMON_ID(task_brd)))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_activate_request: set all nodes up failed");

            return (EC_TRUE);
        }

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_activate_request: set all nodes up succ");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_ngx_activate_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_activate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_activate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_activate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_ngx_activate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_activate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ngx_deactivate ----------------------------------------*/
EC_BOOL cngx_http_commit_ngx_deactivate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_ngx_deactivate_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_deactivate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_ngx_deactivate_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_deactivate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_ngx_deactivate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_deactivate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_ngx_deactivate_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_deactivate_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_deactivate_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_deactivate_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_deactivate_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        TASK_BRD        *task_brd;

        task_brd = task_brd_default_get();

        if(EC_FALSE == cmon_set_down(TASK_BRD_CMON_ID(task_brd)))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_deactivate_request: set all nodes down failed");

            return (EC_TRUE);
        }

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_deactivate_request: set all nodes down succ");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_ngx_deactivate_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_deactivate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_deactivate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_deactivate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_ngx_deactivate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_deactivate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ngx_show_cmon_nodes ----------------------------------------*/
EC_BOOL cngx_http_commit_ngx_show_cmon_nodes_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_ngx_show_cmon_nodes_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_cmon_nodes_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_ngx_show_cmon_nodes_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_cmon_nodes_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_ngx_show_cmon_nodes_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_cmon_nodes_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_ngx_show_cmon_nodes_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CNGX_HTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_show_cmon_nodes_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_show_cmon_nodes_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error: cngx_http_handle_ngx_show_cmon_nodes_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_show_cmon_nodes_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        LOG         *log;

        log = log_cstr_open();
        if(NULL_PTR == log)
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cngx_http_handle_ngx_show_cmon_nodes_request: no memory");

            return (EC_TRUE);
        }

        cmon_print_nodes(task_brd_default_get_cmon_id(), log);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFSMON_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_ngx_show_cmon_nodes_request: done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cbytes_mount(content_cbytes,
                     cstring_get_len(LOG_CSTR(log)),
                     cstring_get_str(LOG_CSTR(log)),
                     BIT_FALSE);
        cstring_unset(LOG_CSTR(log));

        log_cstr_close(log);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_ngx_show_cmon_nodes_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_cmon_nodes_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_cmon_nodes_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_cmon_nodes_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_ngx_show_cmon_nodes_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_ngx_show_cmon_nodes_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_ngx_show_cmon_nodes_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: paracfg ----------------------------------------*/
EC_BOOL cngx_http_commit_paracfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_paracfg_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_paracfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_paracfg_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_paracfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_paracfg_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_paracfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_paracfg_request(CHTTP_NODE *chttp_node)
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

        dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "[DEBUG] cngx_http_handle_paracfg_request: done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(rsp_content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_paracfg_request: done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_paracfg_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_paracfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_paracfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_paracfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_paracfg_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_paracfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_paracfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: dbgtaskcfg ----------------------------------------*/
EC_BOOL cngx_http_commit_dbgtaskcfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_http_handle_dbgtaskcfg_request(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_dbgtaskcfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_make_dbgtaskcfg_response(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_dbgtaskcfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_http_commit_dbgtaskcfg_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_dbgtaskcfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_http_handle_dbgtaskcfg_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *rsp_content_cbytes;

    TASK_BRD      *task_brd;

    rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(rsp_content_cbytes);

    task_brd = task_brd_default_get();
    if(NULL_PTR != task_brd && NULL_PTR != TASK_BRD_SYS_CFG(task_brd))
    {
        SYS_CFG       *sys_cfg;
        TASK_CFG      *task_cfg;
        LOG           *des_log;
        CSTRING       *rsp_body_cstr;

        sys_cfg  = TASK_BRD_SYS_CFG(task_brd);
        task_cfg = SYS_CFG_TASK_CFG(sys_cfg);

        des_log = log_cstr_new();

        task_cfg_print(des_log, task_cfg);

        rsp_body_cstr = LOG_CSTR(des_log);

        cbytes_set(rsp_content_cbytes, CSTRING_STR(rsp_body_cstr), CSTRING_LEN(rsp_body_cstr));

        cstring_unset(rsp_body_cstr);

        log_cstr_free(des_log);

        dbg_log(SEC_0054_CNGX_HTTP, 5)(LOGSTDOUT, "[DEBUG] cngx_http_handle_dbgtaskcfg_request: done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(rsp_content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cngx_http_handle_dbgtaskcfg_request: done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_http_make_dbgtaskcfg_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_dbgtaskcfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_dbgtaskcfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_dbgtaskcfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_make_dbgtaskcfg_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cngx_http_commit_dbgtaskcfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0054_CNGX_HTTP, 0)(LOGSTDOUT, "error:cngx_http_commit_dbgtaskcfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cngx_http_commit_response(chttp_node);
}
#endif

#if 1
#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

