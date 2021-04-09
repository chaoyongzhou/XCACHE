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

#include "cxfs.h"
#include "chttp.inc"
#include "chttp.h"
#include "cxfshttp.h"
#include "cmon.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "findex.inc"

#if 0
#define CXFSHTTP_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CXFSHTTP_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CXFSHTTP_PRINT_UINT8(info, buff, len) do{}while(0)
#define CXFSHTTP_PRINT_CHARS(info, buff, len) do{}while(0)
#endif



#if 1
#define CXFSHTTP_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

#if 0
#define CXFSHTTP_ASSERT(condition) do{}while(0)
#endif

#if 1
//#define CXFSHTTP_TIME_COST_FORMAT " BegTime:%u.%03u EndTime:%u.%03u Elapsed:%u "
#define CXFSHTTP_TIME_COST_FORMAT " %u.%03u %u.%03u %u "
#define CXFSHTTP_TIME_COST_VALUE(chttp_node)  \
    (uint32_t)CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node)), (uint32_t)CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)))
#endif

static EC_BOOL g_cxfshttp_log_init = EC_FALSE;

static const CHTTP_API g_cxfshttp_api_list[] = {
    {CONST_STR_AND_LEN("getsmf")            , CHTTP_METHOD_GET   , cxfshttp_commit_getsmf_request},
    {CONST_STR_AND_LEN("dsmf")              , CHTTP_METHOD_DELETE, cxfshttp_commit_dsmf_request},
    {CONST_STR_AND_LEN("ddir")              , CHTTP_METHOD_DELETE, cxfshttp_commit_ddir_request},
    {CONST_STR_AND_LEN("sexpire")           , CHTTP_METHOD_GET   , cxfshttp_commit_sexpire_request},
    {CONST_STR_AND_LEN("lock_req")          , CHTTP_METHOD_GET   , cxfshttp_commit_lock_req_request},
    {CONST_STR_AND_LEN("unlock_req")        , CHTTP_METHOD_GET   , cxfshttp_commit_unlock_req_request},
    {CONST_STR_AND_LEN("unlock_notify_req") , CHTTP_METHOD_GET   , cxfshttp_commit_unlock_notify_req_request},
    {CONST_STR_AND_LEN("recycle")           , CHTTP_METHOD_GET   , cxfshttp_commit_recycle_request},

    {CONST_STR_AND_LEN("flush")             , CHTTP_METHOD_GET   , cxfshttp_commit_flush_request},
    {CONST_STR_AND_LEN("retire")            , CHTTP_METHOD_GET   , cxfshttp_commit_retire_request},
    {CONST_STR_AND_LEN("setreadonly")       , CHTTP_METHOD_GET   , cxfshttp_commit_setreadonly_request},
    {CONST_STR_AND_LEN("unsetreadonly")     , CHTTP_METHOD_GET   , cxfshttp_commit_unsetreadonly_request},
    {CONST_STR_AND_LEN("isreadonly")        , CHTTP_METHOD_GET   , cxfshttp_commit_isreadonly_request},
    {CONST_STR_AND_LEN("sync")              , CHTTP_METHOD_GET   , cxfshttp_commit_sync_request},
    {CONST_STR_AND_LEN("replayop")          , CHTTP_METHOD_GET   , cxfshttp_commit_replayop_request},
    {CONST_STR_AND_LEN("breathe")           , CHTTP_METHOD_GET   , cxfshttp_commit_breathe_request},

    {CONST_STR_AND_LEN("logrotate")         , CHTTP_METHOD_GET   , cxfshttp_commit_logrotate_request},
    {CONST_STR_AND_LEN("actsyscfg")         , CHTTP_METHOD_GET   , cxfshttp_commit_actsyscfg_request},
    {CONST_STR_AND_LEN("qtree")             , CHTTP_METHOD_GET   , cxfshttp_commit_qtree_request},
    {CONST_STR_AND_LEN("status_np")         , CHTTP_METHOD_GET   , cxfshttp_commit_statusnp_request},
    {CONST_STR_AND_LEN("status_dn")         , CHTTP_METHOD_GET   , cxfshttp_commit_statusdn_request},
    {CONST_STR_AND_LEN("stat")              , CHTTP_METHOD_GET   , cxfshttp_commit_stat_request},
    {CONST_STR_AND_LEN("paracfg")           , CHTTP_METHOD_GET   , cxfshttp_commit_paracfg_request},

    {CONST_STR_AND_LEN("file_notify")       , CHTTP_METHOD_GET   , cxfshttp_commit_file_notify_request},
    {CONST_STR_AND_LEN("file_terminate")    , CHTTP_METHOD_GET   , cxfshttp_commit_file_terminate_request},
    {CONST_STR_AND_LEN("cond_wakeup")       , CHTTP_METHOD_GET   , cxfshttp_commit_cond_wakeup_request},
    {CONST_STR_AND_LEN("cond_terminate")    , CHTTP_METHOD_GET   , cxfshttp_commit_cond_terminate_request},
    {CONST_STR_AND_LEN("renew_header")      , CHTTP_METHOD_GET   , cxfshttp_commit_renew_header_request},
    {CONST_STR_AND_LEN("locked_file_retire"), CHTTP_METHOD_GET   , cxfshttp_commit_locked_file_retire_request},
    {CONST_STR_AND_LEN("wait_file_retire")  , CHTTP_METHOD_GET   , cxfshttp_commit_wait_file_retire_request},
    {CONST_STR_AND_LEN("activate")          , CHTTP_METHOD_GET   , cxfshttp_commit_activate_ngx_request},
    {CONST_STR_AND_LEN("deactivate")        , CHTTP_METHOD_GET   , cxfshttp_commit_deactivate_ngx_request},

    {CONST_STR_AND_LEN("setsmf")            , CHTTP_METHOD_POST  , cxfshttp_commit_setsmf_request},
    {CONST_STR_AND_LEN("mexpire")           , CHTTP_METHOD_POST  , cxfshttp_commit_mexpire_request},
    {CONST_STR_AND_LEN("mdsmf")             , CHTTP_METHOD_POST  , cxfshttp_commit_mdsmf_request},
    {CONST_STR_AND_LEN("mddir")             , CHTTP_METHOD_POST  , cxfshttp_commit_mddir_request},
    {CONST_STR_AND_LEN("update")            , CHTTP_METHOD_POST  , cxfshttp_commit_update_request},
    {CONST_STR_AND_LEN("renew")             , CHTTP_METHOD_POST  , cxfshttp_commit_renew_request},

    {CONST_STR_AND_LEN("meta")              , CHTTP_METHOD_HEAD , cxfshttp_commit_meta_request},
};

static const uint32_t   g_cxfshttp_api_num = sizeof(g_cxfshttp_api_list)/sizeof(g_cxfshttp_api_list[0]);

EC_BOOL cxfshttp_log_start()
{
    TASK_BRD        *task_brd;

    if(EC_TRUE == g_cxfshttp_log_init)
    {
        return (EC_TRUE);
    }

    g_cxfshttp_log_init = EC_TRUE;

    task_brd = task_brd_default_get();

    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;
        LOG     *log;

        /*open log and redirect LOGUSER08 to it*/
        log_file_name = cstring_new(NULL_PTR, LOC_CXFSHTTP_0001);
        cstring_format(log_file_name, "%s/xfs_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER08, log);

            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "[DEBUG] cxfshttp_log_start: log_file_open '%s' -> LOGUSER08 done\n",
                               (char *)cstring_get_str(log_file_name));

            cstring_free(log_file_name);
        }
    }
    return (EC_TRUE);
}


/*---------------------------------------- ENTRY: HTTP COMMIT REQUEST FOR HANDLER  ----------------------------------------*/
EC_BOOL cxfshttp_commit_request(CHTTP_NODE *chttp_node)
{
    http_parser_t *http_parser;
    uint32_t       method;

    http_parser = CHTTP_NODE_PARSER(chttp_node);

    method = chttp_method_convert(http_parser->method);
    if(CHTTP_METHOD_UNKNOWN != method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)cxfshttp_commit_start, 2, chttp_node, (UINT32)method);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_request: "
                                                     "no croutine\n");

            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CXFSHTTP_0002);

        return (EC_TRUE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_request: "
                                             "not support http method %d yet\n",
                                             http_parser->method);
    return (EC_FALSE);/*note: this chttp_node must be discarded*/
}

EC_BOOL cxfshttp_commit_start(CHTTP_NODE *chttp_node, const UINT32 method)
{
    const CHTTP_API       *chttp_api;
    EC_BOOL                ret;

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record xfs beg to handle time*/

    chttp_api = chttp_node_find_api(chttp_node,
                                    (const CHTTP_API *)g_cxfshttp_api_list,
                                    g_cxfshttp_api_num,
                                    (uint32_t)method);
    if(NULL_PTR == chttp_api)
    {
        CBUFFER               *url_cbuffer;

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_start: "
                                                 "no api for %s:'%.*s'\n",
                                                 chttp_method_str((uint32_t)method),
                                                 CBUFFER_USED(CHTTP_NODE_ARGS(chttp_node)),
                                                 CBUFFER_DATA(CHTTP_NODE_ARGS(chttp_node)));

        url_cbuffer   = CHTTP_NODE_URL(chttp_node);
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_start: "
                                                 "invalid request %s:'%.*s'\n",
                                                 chttp_method_str((uint32_t)method),
                                                 CBUFFER_USED(url_cbuffer),
                                                 CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_NOT_ACCEPTABLE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_commit_start: invalid request %s:'%.*s'",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(url_cbuffer), CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;

        return cxfshttp_commit_end(chttp_node, ret);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_start: "
                                             "api: method %d, name %s\n",
                                             CHTTP_API_METHOD(chttp_api),
                                             CHTTP_API_NAME(chttp_api));

    ret = CHTTP_API_COMMIT(chttp_api)(chttp_node);
    return cxfshttp_commit_end(chttp_node, ret);
}

EC_BOOL cxfshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result)
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

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

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

            dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
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

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        /*free*/
        chttp_node_free(chttp_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL cxfshttp_commit_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
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
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: getsmf ----------------------------------------*/
EC_BOOL cxfshttp_commit_getsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_getsmf_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_getsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_getsmf_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_getsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_getsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_getsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_getsmf_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    char          *store_offset_str;
    char          *store_size_str;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0005);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_getsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_getsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_getsmf_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_getsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_getsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_getsmf_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    store_offset_str = chttp_node_get_header(chttp_node, (const char *)"store-offset");
    if(NULL_PTR != store_offset_str)
    {
        CSOCKET_CNODE * csocket_cnode;

        uint32_t store_offset;
        uint32_t store_size;

        UINT32   offset;
        UINT32   max_len;

        store_size_str   = chttp_node_get_header(chttp_node, (const char *)"store-size");

        store_offset = c_str_to_uint32_t(store_offset_str);
        store_size   = c_str_to_uint32_t(store_size_str);/*note: when store_size_str is null, store_size is zero*/

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        offset        = store_offset;
        max_len       = store_size;

        if(EC_FALSE == cxfs_read_e(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &offset, max_len, content_cbytes))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_getsmf_request: cxfs read %s with offset %u, size %u failed\n",
                                (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_getsmf_request: cxfs read %s with offset %u, size %u failed", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_getsmf_request: cxfs read %s with offset %u, size %u done\n",
                            (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_getsmf_request: cxfs read %s with offset %u, size %u done", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else/*read whole file content*/
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_read(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_getsmf_request: cxfs read %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_getsmf_request: cxfs read %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_getsmf_request: cxfs read %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_getsmf_request: cxfs read %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_getsmf_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_getsmf_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_getsmf_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_getsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_getsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_getsmf_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_getsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_getsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif
#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: lock_req ----------------------------------------*/
EC_BOOL cxfshttp_commit_lock_req_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_lock_req_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_lock_req_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_lock_req_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_lock_req_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_lock_req_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_lock_req_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

STATIC_CAST static UINT32 __cxfshttp_convert_expires_str_to_nseconds(const char *expires_str)
{
    char *str;
    char *fields[2];
    UINT32 seg_num;
    UINT32 expires_nsec;

    str = c_str_dup(expires_str);
    if(NULL_PTR == str)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:__cxfshttp_convert_expires_str_to_nseconds: dup str '%s' failed\n", expires_str);
        return ((UINT32)0);
    }

    seg_num = c_str_split(str, ".", fields, 2);
    if(1 == seg_num)
    {
        expires_nsec = c_str_to_word(fields[0]);
        safe_free(str, LOC_CXFSHTTP_0006);
        return (expires_nsec);
    }

    if(2 == seg_num)/*if has dot, we regard client gives absolute time (in seconds)*/
    {
        UINT32 expire_when;
        CTIMET cur_time; /*type: long, unit: second*/

        /*note: ignore part after dot (million seconds)*/
        expire_when = c_str_to_word(fields[0]);

        CTIMET_GET(cur_time);

        expires_nsec = (expire_when - cur_time);

        safe_free(str, LOC_CXFSHTTP_0007);
        return (expires_nsec);
    }

    safe_free(str, LOC_CXFSHTTP_0008);
    return ((UINT32)0);
}
EC_BOOL cxfshttp_handle_lock_req_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CSTRING        token_cstr;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;
    uint8_t        auth_token_header[CMD5_DIGEST_LEN * 8];
    uint32_t       auth_token_header_len;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0009);

    cstring_init(&token_cstr, NULL_PTR);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_lock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_lock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_lock_req_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_lock_req_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_lock_req_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_lock_req_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }


    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        char    *expires_str;
        UINT32   expires_nsec;
        UINT32   locked_flag;

        expires_str  = chttp_node_get_header(chttp_node, (const char *)"Expires");
        expires_nsec = __cxfshttp_convert_expires_str_to_nseconds(expires_str);
        locked_flag  = EC_FALSE;

        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_lock_req_request: header Expires %s => %ld\n",
                                expires_str, expires_nsec);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_file_lock(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, expires_nsec, &token_cstr, &locked_flag))
        {
            dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "error:cxfshttp_handle_lock_req_request: cxfs lock %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            if(EC_TRUE == locked_flag)/*flag was set*/
            {
                cbytes_set(content_cbytes, (UINT8 *)"locked-already:true\r\n", sizeof("locked-already:true\r\n") - 1);
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_lock_req_request: cxfs lock %s failed", (char *)cstring_get_str(&path_cstr));
            }
            else /*flag was not set which means some error happen*/
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_lock_req_request: cxfs lock %s failed", (char *)cstring_get_str(&path_cstr));
            }

            cstring_clean(&path_cstr);
            cstring_clean(&token_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_lock_req_request: cxfs lock %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_lock_req_request: cxfs lock %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    auth_token_header_len = snprintf((char *)auth_token_header, sizeof(auth_token_header),
                                    "auth-token:%.*s\r\n", (uint32_t)CSTRING_LEN(&token_cstr), (char *)CSTRING_STR(&token_cstr));
    cbytes_set(content_cbytes, auth_token_header, auth_token_header_len);

    cstring_clean(&path_cstr);
    cstring_clean(&token_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_lock_req_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *token_buf;
    uint32_t       token_len;

    /*note: content carry on auth-token info but not response body*/
    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    token_buf      = CBYTES_BUF(content_cbytes);
    token_len      = (uint32_t)CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_lock_req_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_lock_req_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_lock_req_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_token(chttp_node, token_buf, token_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_lock_req_response: make response header token failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_lock_req_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_lock_req_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_lock_req_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: unlock_req ----------------------------------------*/
EC_BOOL cxfshttp_commit_unlock_req_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_unlock_req_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_req_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_unlock_req_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_req_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_unlock_req_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_req_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_unlock_req_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0010);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_unlock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_req_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_req_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_req_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_unlock_req_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        char    *auth_token_header;

        CSTRING  token_cstr;

        auth_token_header = chttp_node_get_header(chttp_node, (const char *)"auth-token");
        if(NULL_PTR == auth_token_header)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT,
                            "error:cxfshttp_handle_unlock_req_request: cxfs unlock %s failed due to header 'auth-token' absence\n",
                            (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_unlock_req_request: cxfs unlock %s failed due to header 'auth-token' absence", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        cstring_set_str(&token_cstr, (const UINT8 *)auth_token_header);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_file_unlock(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &token_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_unlock_req_request: cxfs unlock %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_unlock_req_request: cxfs unlock %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_unlock_req_request: cxfs unlock %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_unlock_req_request: cxfs unlock %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_unlock_req_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_unlock_req_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unlock_req_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unlock_req_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unlock_req_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_unlock_req_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_req_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: unlock_notify_req ----------------------------------------*/
EC_BOOL cxfshttp_commit_unlock_notify_req_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_unlock_notify_req_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_notify_req_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_unlock_notify_req_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_notify_req_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_unlock_notify_req_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_notify_req_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_unlock_notify_req_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0011);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_unlock_notify_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_notify_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_notify_req_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_notify_req_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unlock_notify_req_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_unlock_notify_req_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_file_unlock_notify(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_unlock_notify_req_request: cxfs unlock_notify %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_unlock_notify_req_request: cxfs unlock_notify %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_unlock_notify_req_request: cxfs unlock_notify %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_unlock_notify_req_request: cxfs unlock_notify %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_unlock_notify_req_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_unlock_notify_req_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unlock_notify_req_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unlock_notify_req_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unlock_notify_req_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_unlock_notify_req_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unlock_notify_req_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: recycle ----------------------------------------*/
EC_BOOL cxfshttp_commit_recycle_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_recycle_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_recycle_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_recycle_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_recycle_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_recycle_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_recycle_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_recycle_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_recycle_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_recycle_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_recycle_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_recycle_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;
        char  *max_num_per_np_str;
        UINT32 max_num_per_np;
        UINT32 complete_num;

        uint8_t  recycle_result[ 32 ];
        uint32_t recycle_result_len;

        max_num_per_np_str = chttp_node_get_header(chttp_node, (const char *)"max-num-per-np");
        max_num_per_np = c_str_to_word(max_num_per_np_str);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_recycle(CSOCKET_CNODE_MODI(csocket_cnode), max_num_per_np, &complete_num))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_recycle_request: cxfs recycle failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_recycle_request: cxfs recycle failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_recycle_request: cxfs recycle done\n");

        /*prepare response header*/
        recycle_result_len = snprintf((char *)recycle_result, sizeof(recycle_result), "recycle-completion:%ld\r\n", complete_num);
        cbytes_set(content_cbytes, recycle_result, recycle_result_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_recycle_request: cxfs recycle done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_recycle_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *recycle_result_buf;
    uint32_t       recycle_result_len;

    /*note: content carry on recycle-completion info but not response body*/
    content_cbytes    = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    recycle_result_buf = CBYTES_BUF(content_cbytes);
    recycle_result_len = (uint32_t)CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_recycle_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_recycle_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_recycle(chttp_node, recycle_result_buf, recycle_result_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_recycle_response: make response header recycle failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_recycle_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_recycle_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_recycle_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: flush ----------------------------------------*/
EC_BOOL cxfshttp_commit_flush_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_flush_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_flush_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_flush_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_flush_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_flush_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_flush_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_flush_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_flush_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_flush_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_flush_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_flush_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_flush(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_flush_request: cxfs flush failed\n");
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_flush_request: cxfs flush failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_flush_request: cxfs flush done\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_flush_request: cxfs flush done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_flush_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_flush_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_flush_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_flush_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_flush_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_flush_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: retire ----------------------------------------*/

EC_BOOL cxfshttp_commit_retire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_retire_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_retire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_retire_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_retire_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_retire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_retire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_retire_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    char          *retire_files_str;

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_retire_request\n");

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_retire_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_retire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_retire_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_retire_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    retire_files_str   = chttp_node_get_header(chttp_node, (const char *)"retire-files");
    if(NULL_PTR == retire_files_str) /*invalid retire request*/
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_retire_request: http header 'retire-files' absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_retire_request: http header 'retire-files' absence");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(NULL_PTR != retire_files_str)
    {
        CSOCKET_CNODE * csocket_cnode;

        UINT32   retire_files;
        UINT32   complete_num;

        uint8_t  retire_result[ 32 ];
        uint32_t retire_result_len;

        retire_files   = c_str_to_word(retire_files_str);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        if(EC_FALSE == cxfs_retire(CSOCKET_CNODE_MODI(csocket_cnode), retire_files, &complete_num))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_retire_request: cxfs retire with expect retire num %ld failed\n",
                                retire_files);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_retire_request: cxfs retire with expect retire num %ld failed", retire_files);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;
            return (EC_TRUE);
        }

        /*prepare response header*/
        retire_result_len = snprintf((char *)retire_result, sizeof(retire_result), "retire-completion:%ld\r\n", complete_num);
        cbytes_set(content_cbytes, retire_result, retire_result_len);

        dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_retire_request: cxfs retire with expect retire %ld, complete %ld done\n",
                            retire_files, complete_num);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_retire_request: cxfs retire with expect retire %ld, complete %ld done", retire_files, complete_num);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_retire_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *retire_result_buf;
    uint32_t       retire_result_len;

    /*note: content carry on retire-completion info but not response body*/
    content_cbytes    = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    retire_result_buf = CBYTES_BUF(content_cbytes);
    retire_result_len = (uint32_t)CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_retire_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_retire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_retire(chttp_node, retire_result_buf, retire_result_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_retire_response: make response header retire failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_retire_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_retire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_retire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: setreadonly ----------------------------------------*/
EC_BOOL cxfshttp_commit_setreadonly_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_setreadonly_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setreadonly_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_setreadonly_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setreadonly_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_setreadonly_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setreadonly_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_setreadonly_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setreadonly_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setreadonly_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setreadonly_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_setreadonly_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_set_read_only(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_setreadonly_request: cxfs setreadonly failed\n");
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_setreadonly_request: cxfs setreadonly failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_setreadonly_request: cxfs setreadonly done\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_setreadonly_request: cxfs setreadonly done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_setreadonly_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_setreadonly_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_setreadonly_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_setreadonly_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_setreadonly_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setreadonly_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: unsetreadonly ----------------------------------------*/
EC_BOOL cxfshttp_commit_unsetreadonly_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_unsetreadonly_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unsetreadonly_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_unsetreadonly_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unsetreadonly_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_unsetreadonly_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unsetreadonly_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_unsetreadonly_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unsetreadonly_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unsetreadonly_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_unsetreadonly_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_unsetreadonly_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_unset_read_only(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_unsetreadonly_request: cxfs unsetreadonly failed\n");
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_unsetreadonly_request: cxfs unsetreadonly failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_unsetreadonly_request: cxfs unsetreadonly done\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_unsetreadonly_request: cxfs unsetreadonly done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_unsetreadonly_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unsetreadonly_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unsetreadonly_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_unsetreadonly_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_unsetreadonly_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_unsetreadonly_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: isreadonly ----------------------------------------*/
EC_BOOL cxfshttp_commit_isreadonly_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_isreadonly_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_isreadonly_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_isreadonly_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_isreadonly_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_isreadonly_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_isreadonly_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_isreadonly_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_isreadonly_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_isreadonly_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_isreadonly_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_isreadonly_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_is_read_only(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_isreadonly_request: cxfs is not read-only\n");
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_isreadonly_request: cxfs is not read-only");

            cbytes_append(content_cbytes, (const UINT8 *)"read-only:false", sizeof("read-only:false") - 1);
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_isreadonly_request: cxfs is read-only\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_isreadonly_request: cxfs is read-only");

        cbytes_append(content_cbytes, (const UINT8 *)"read-only:true", sizeof("read-only:true") - 1);
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_isreadonly_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_isreadonly_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_isreadonly_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_isreadonly_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_isreadonly_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_isreadonly_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_isreadonly_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: sync ----------------------------------------*/
EC_BOOL cxfshttp_commit_sync_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_sync_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sync_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_sync_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sync_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_sync_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sync_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_sync_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_sync_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_sync_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_sync_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_sync_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_sync(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_sync_request: cxfs sync failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_sync_request: cxfs sync failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_sync_request: cxfs sync succ\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_sync_request: cxfs sync succ");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_sync_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, 0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_sync_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_sync_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_sync_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_sync_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sync_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: replayop ----------------------------------------*/
EC_BOOL cxfshttp_commit_replayop_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_replayop_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_replayop_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_replayop_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_replayop_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_replayop_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_replayop_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_replayop_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_replayop_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_replayop_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_replayop_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_replayop_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_replay_op(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_replayop_request: cxfs replayop failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_replayop_request: cxfs replayop failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_replayop_request: cxfs replayop succ\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_replayop_request: cxfs replayop succ");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_replayop_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, 0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_replayop_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_replayop_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_replayop_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_replayop_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_replayop_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: breathe ----------------------------------------*/
EC_BOOL cxfshttp_commit_breathe_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_breathe_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_breathe_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_breathe_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_breathe_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_breathe_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_breathe_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_breathe_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_breathe_request\n");

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_breathe_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_breathe_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_breathe_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_breathe_request: bad request");

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

        dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_breathe_request: memory breathing done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_breathe_request: memory breathing done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_breathe_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_breathe_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_breathe_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_breathe_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_breathe_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_breathe_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: setsmf ----------------------------------------*/
EC_BOOL cxfshttp_commit_setsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_setsmf_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_setsmf_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_setsmf_request: make response done\n");

    ret = cxfshttp_commit_setsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}


EC_BOOL cxfshttp_handle_setsmf_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);
    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);/*note: maybe request does not carry on Content-Lenght header*/
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setsmf_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                                                 CBUFFER_DATA(uri_cbuffer),
                                                 content_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_setsmf_request: path %.*s, invalid content length %"PRId64,
                                                (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                                                (char *)(CBUFFER_DATA(uri_cbuffer)),
                                                content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0012);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_setsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttp_node_recv_len(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setsmf_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_setsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_setsmf_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "warn:cxfshttp_handle_setsmf_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:cxfshttp_handle_setsmf_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_setsmf_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_setsmf_request: new cbytes without buff failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_setsmf_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_setsmf_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
#if 1
        if(EC_FALSE == cxfs_write(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_setsmf_request: cxfs write %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_setsmf_request: cxfs write %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_setsmf_request: cxfs write %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_setsmf_request: cxfs write %s done", (char *)cstring_get_str(&path_cstr));
#endif
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_setsmf_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_setsmf_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_setsmf_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_setsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_setsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_setsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_setsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: PUT, FILE OPERATOR: meta ----------------------------------------*/
EC_BOOL cxfshttp_commit_meta_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_meta_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_meta_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_meta_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_meta_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_meta_request: make response done\n");

    ret = cxfshttp_commit_meta_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_meta_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_meta_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0013);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_meta_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;
        uint64_t        file_size;

        uint8_t        file_size_header[32];
        uint32_t       file_size_header_len;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_file_size(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &file_size))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_meta_request: cxfs get size of %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_meta_request: cxfs get size of %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_meta_request: cxfs get size of %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %"PRId64, CHTTP_OK, file_size);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_meta_request: cxfs get size of %s done", (char *)cstring_get_str(&path_cstr));

        file_size_header_len = snprintf((char *)file_size_header, sizeof(file_size_header),
                                        "file-size:%"PRId64"\r\n", file_size);
        cbytes_set(content_cbytes, file_size_header, file_size_header_len);
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_meta_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_meta_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *file_size_buf;
    uint32_t       file_size_len;

    /*note: content carry on file-size info but not response body*/
    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    file_size_buf  = CBYTES_BUF(content_cbytes);
    file_size_len  = (uint32_t)CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_meta_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_meta_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_data(chttp_node, file_size_buf, file_size_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_meta_response: make response header file-size failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_meta_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_meta_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_meta_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: update ----------------------------------------*/
EC_BOOL cxfshttp_commit_update_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_update_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_update_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_update_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_update_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_update_request: make response done\n");

    ret = cxfshttp_commit_update_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_update_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_update_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);
    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(!((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_update_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                                                 CBUFFER_DATA(uri_cbuffer),
                                                 content_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_update_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_update_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_update_request: path %.*s, invalid content length %"PRId64,
                    (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                    (char *)(CBUFFER_DATA(uri_cbuffer)),content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0014);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_update_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttp_node_recv_len(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_update_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_update_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_update_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_update_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "warn:cxfshttp_handle_update_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:cxfshttp_handle_update_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_update_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_update_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_update_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_update_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
#if 1
        if(EC_FALSE == cxfs_update(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_update_request: cxfs update %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_update_request: cxfs update %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_update_request: cxfs update %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_update_request: cxfs update %s done", (char *)cstring_get_str(&path_cstr));
#endif
    }

    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_update_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_update_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_update_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_update_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_update_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_update_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_update_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: renew ----------------------------------------*/
/*renew expires setting*/
EC_BOOL cxfshttp_commit_renew_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_renew_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_renew_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_renew_request: make response done\n");

    ret = cxfshttp_commit_renew_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_renew_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);
    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                                                 CBUFFER_DATA(uri_cbuffer),
                                                 content_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_renew_request: path %.*s, invalid content length %"PRId64,
                    (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                    (char *)(CBUFFER_DATA(uri_cbuffer)),content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0015);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_renew_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttp_node_recv_len(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_renew_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "warn:cxfshttp_handle_renew_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:cxfshttp_handle_renew_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_request: new cbytes without buff failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
#if 1
        if(EC_FALSE == cxfs_update(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_request: cxfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_request: cxfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_renew_request: cxfs renew %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_renew_request: cxfs renew %s done", (char *)cstring_get_str(&path_cstr));
#endif
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_renew_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_renew_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_renew_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_renew_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_renew_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: dsmf ----------------------------------------*/
EC_BOOL cxfshttp_commit_dsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_dsmf_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_dsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_dsmf_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_dsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_dsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_dsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_dsmf_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0016);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_dsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_dsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_dsmf_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_dsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_dsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_dsmf_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
#if 1
        if(EC_FALSE == cxfs_delete_file(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_dsmf_request: cxfs delete file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_dsmf_request: cxfs delete file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_dsmf_request: cxfs delete file %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_dsmf_request: cxfs delete file %s done", (char *)cstring_get_str(&path_cstr));
#endif
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_dsmf_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_dsmf_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_dsmf_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_dsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_dsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_dsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_dsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ddir ----------------------------------------*/
EC_BOOL cxfshttp_commit_ddir_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_ddir_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_ddir_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_ddir_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_ddir_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_ddir_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_ddir_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_ddir_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0017);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_ddir_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_ddir_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_ddir_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_ddir_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_ddir_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_ddir_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
#if 1
        if(EC_FALSE == cxfs_delete_dir(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_ddir_request: cxfs delete dir %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_ddir_request: cxfs delete dir %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_ddir_request: cxfs delete dir %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_ddir_request: cxfs delete dir %s done", (char *)cstring_get_str(&path_cstr));
#endif
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_ddir_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_ddir_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_ddir_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_ddir_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_ddir_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_ddir_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_ddir_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: sexpire ----------------------------------------*/
/*expire single file*/
EC_BOOL cxfshttp_commit_sexpire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_sexpire_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sexpire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_sexpire_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sexpire_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_sexpire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sexpire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_sexpire_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0018);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_sexpire_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_sexpire_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_sexpire_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_sexpire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_sexpire_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_sexpire_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_file_expire(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_sexpire_request: cxfs exipre file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_sexpire_request: cxfs exipre file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_sexpire_request: cxfs exipre file %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_sexpire_request: cxfs exipre file %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_sexpire_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_sexpire_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_sexpire_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_sexpire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_sexpire_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_sexpire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_sexpire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mexpire ----------------------------------------*/
/*expire multiple files*/
EC_BOOL cxfshttp_commit_mexpire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_mexpire_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mexpire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_mexpire_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mexpire_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_mexpire_request: make response done\n");

    ret = cxfshttp_commit_mexpire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mexpire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_mexpire_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mexpire_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mexpire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mexpire_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_mexpire_request: invalid content length %"PRId64, content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttp_node_recv_len(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mexpire_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mexpire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mexpire_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_mexpire_request: invalid body length %"PRId64, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "warn:cxfshttp_handle_mexpire_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:cxfshttp_handle_mexpire_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "info:cxfshttp_handle_mexpire_request: request body is empty\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "info:cxfshttp_handle_mexpire_request: request body is empty");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mexpire_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mexpire_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mexpire_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mexpire_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cbytes_free(req_content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;
        json_object   * files_obj;
        json_object   * rsp_body_obj;
        const char    * rsp_body_str;
        size_t          idx;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
        cbytes_clean(rsp_content_cbytes);

        files_obj = json_tokener_parse((const char *)CBYTES_BUF(req_content_cbytes));
        if(NULL_PTR == files_obj)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mexpire_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mexpire_request: bad request %.*s",
                            (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            cbytes_free(req_content_cbytes);
            /*no response body*/
            return (EC_TRUE);
        }

        rsp_body_obj = json_object_new_array();

        for(idx = 0; idx < json_object_array_length(files_obj); idx ++)
        {
            json_object *file_obj;

            CSTRING  path_cstr;
            char    *path;

            file_obj = json_object_array_get_idx(files_obj, idx);
            if(NULL_PTR == file_obj)
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mexpire_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mexpire_request: path is null at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            if('"' == (*path))
            {
                path ++;
            }

            if('/' == (*path))
            {
                cstring_init(&path_cstr, NULL_PTR);
            }
            else
            {
                cstring_init(&path_cstr, (const UINT8 *)"/");
            }

            cstring_append_str(&path_cstr, (const UINT8 *)path);
            cstring_trim(&path_cstr, (UINT8)'"');

            if(EC_FALSE == cxfs_file_expire(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mexpire_request: cxfs expire %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mexpire_request: cxfs expire %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_mexpire_request: cxfs expire %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_mexpire_request: cxfs expire %s done", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("200"));
            }
            cstring_clean(&path_cstr);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str)/* + 1*/);

        /*free json obj*/
        json_object_put(files_obj);
        json_object_put(rsp_body_obj);
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mexpire_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_mexpire_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mexpire_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mexpire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mexpire_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mexpire_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_mexpire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mexpire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mdsmf ----------------------------------------*/
/*delete multiple files*/
EC_BOOL cxfshttp_commit_mdsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_mdsmf_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mdsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_mdsmf_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mdsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_mdsmf_request: make response done\n");

    ret = cxfshttp_commit_mdsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mdsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_mdsmf_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mdsmf_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mdsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mdsmf_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_mdsmf_request: invalid content length %"PRId64, content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttp_node_recv_len(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mdsmf_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mdsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mdsmf_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_mdsmf_request: invalid body length %"PRId64, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "warn:cxfshttp_handle_mdsmf_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:cxfshttp_handle_mdsmf_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "info:cxfshttp_handle_mdsmf_request: request body is empty\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "info:cxfshttp_handle_mdsmf_request: request body is empty");
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mdsmf_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mdsmf_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mdsmf_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mdsmf_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cbytes_free(req_content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;
        json_object   * files_obj;
        json_object   * rsp_body_obj;
        const char    * rsp_body_str;
        size_t          idx;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
        cbytes_clean(rsp_content_cbytes);

        files_obj = json_tokener_parse((const char *)CBYTES_BUF(req_content_cbytes));
        if(NULL_PTR == files_obj)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mdsmf_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mdsmf_request: bad request %.*s",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            cbytes_free(req_content_cbytes);
            /*no response body*/
            return (EC_TRUE);
        }

        rsp_body_obj = json_object_new_array();

        for(idx = 0; idx < json_object_array_length(files_obj); idx ++)
        {
            json_object *file_obj;

            CSTRING  path_cstr;
            char    *path;

            file_obj = json_object_array_get_idx(files_obj, idx);
            if(NULL_PTR == file_obj)
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mdsmf_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mdsmf_request: path is null at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            if('"' == (*path))
            {
                path ++;
            }

            if('/' == (*path))
            {
                cstring_init(&path_cstr, NULL_PTR);
            }
            else
            {
                cstring_init(&path_cstr, (const UINT8 *)"/");
            }
            cstring_append_str(&path_cstr, (const UINT8 *)path);
            cstring_trim(&path_cstr, (UINT8)'"');

            if(EC_FALSE == cxfs_delete_file(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mdsmf_request: cxfs delete %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mdsmf_request: cxfs delete %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_mdsmf_request: cxfs delete %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_mdsmf_request: cxfs delete %s done", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("200"));
            }
            cstring_clean(&path_cstr);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str)/* + 1*/);

        /*free json obj*/
        json_object_put(files_obj);
        json_object_put(rsp_body_obj);
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mdsmf_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_mdsmf_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mdsmf_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mdsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mdsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mdsmf_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_mdsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mdsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mddir ----------------------------------------*/
/*delete multiple directories*/
EC_BOOL cxfshttp_commit_mddir_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_mddir_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mddir_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_mddir_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mddir_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_mddir_request: make response done\n");

    ret = cxfshttp_commit_mddir_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mddir_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_mddir_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mddir_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mddir_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mddir_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_mddir_request: invalid content length %"PRId64, content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttp_node_recv_len(chttp_node);
    /*CXFSHTTP_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mddir_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mddir_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_mddir_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_mddir_request: invalid body length %"PRId64, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "warn:cxfshttp_handle_mddir_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:cxfshttp_handle_mddir_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "info:cxfshttp_handle_mddir_request: request body is empty\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "info:cxfshttp_handle_mddir_request: request body is empty");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mddir_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mddir_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mddir_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mddir_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cbytes_free(req_content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;
        json_object   * files_obj;
        json_object   * rsp_body_obj;
        const char    * rsp_body_str;
        size_t          idx;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
        cbytes_clean(rsp_content_cbytes);

        files_obj = json_tokener_parse((const char *)CBYTES_BUF(req_content_cbytes));
        if(NULL_PTR == files_obj)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mddir_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mddir_request: bad request %.*s",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            cbytes_free(req_content_cbytes);
            /*no response body*/
            return (EC_TRUE);
        }

        rsp_body_obj = json_object_new_array();

        for(idx = 0; idx < json_object_array_length(files_obj); idx ++)
        {
            json_object *file_obj;

            CSTRING  path_cstr;
            char    *path;

            file_obj = json_object_array_get_idx(files_obj, idx);
            if(NULL_PTR == file_obj)
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mddir_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mddir_request: path is null at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            if('"' == (*path))
            {
                path ++;
            }

            if('/' == (*path))
            {
                cstring_init(&path_cstr, NULL_PTR);
            }
            else
            {
                cstring_init(&path_cstr, (const UINT8 *)"/");
            }
            cstring_append_str(&path_cstr, (const UINT8 *)path);
            cstring_trim(&path_cstr, (UINT8)'"');

            if(EC_FALSE == cxfs_delete_dir(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
            {
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mddir_request: cxfs delete %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_mddir_request: cxfs delete %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_mddir_request: cxfs delete %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_mddir_request: cxfs delete %s done", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("200"));
            }
            cstring_clean(&path_cstr);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, (UINT32)(strlen(rsp_body_str)/* + 1*/));

        /*free json obj*/
        json_object_put(files_obj);
        json_object_put(rsp_body_obj);
    }
    else
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_mddir_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_mddir_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mddir_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mddir_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mddir_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mddir_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_mddir_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_mddir_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: logrotate ----------------------------------------*/
EC_BOOL cxfshttp_commit_logrotate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_logrotate_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_logrotate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_logrotate_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_logrotate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_logrotate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_logrotate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_logrotate_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);

    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_logrotate_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_logrotate_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_logrotate_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_logrotate_request: bad request");

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
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                return (EC_TRUE);
            }

            dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_logrotate_request: log rotate %ld done\n", log_index);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_logrotate_request: log rotate %ld done", log_index);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

            return (EC_TRUE);
        }

        /*else*/
        log_index_str_t = c_str_dup(log_index_str);
        if(NULL_PTR == log_index_str_t)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_logrotate_request: no memory\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_logrotate_request: no memory");

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
                dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                c_str_free(log_index_str_t);

                return (EC_TRUE);
            }
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_logrotate_request: log rotate %s done\n", log_index_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_logrotate_request: log rotate %s done", log_index_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        c_str_free(log_index_str_t);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_logrotate_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_logrotate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_logrotate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_logrotate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_logrotate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_logrotate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: actsyscfg ----------------------------------------*/
EC_BOOL cxfshttp_commit_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_actsyscfg_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_actsyscfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_actsyscfg_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_actsyscfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_actsyscfg_response(chttp_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_actsyscfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);

    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_actsyscfg_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_actsyscfg_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_actsyscfg_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_actsyscfg_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        UINT32 super_md_id;

        super_md_id = 0;

        super_activate_sys_cfg(super_md_id);

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_actsyscfg_request done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_actsyscfg_request done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_actsyscfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_actsyscfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_actsyscfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_actsyscfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: qtree ----------------------------------------*/
EC_BOOL cxfshttp_commit_qtree_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_qtree_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_qtree_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_qtree_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_qtree_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_qtree_response(chttp_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_qtree_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_qtree_request(CHTTP_NODE *chttp_node)
{
    CBUFFER     *uri_cbuffer;

    uint8_t     *cache_key;
    uint32_t     cache_len;

    CSTRING      path;

    UINT32       req_body_chunk_num;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path, NULL_PTR);
    cstring_append_chars(&path, cache_len, cache_key, LOC_CXFSHTTP_0019);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_qtree_request: path %s\n", (char *)cstring_get_str(&path));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_qtree_request: path %s\n", (char *)cstring_get_str(&path));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_qtree_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_qtree_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_qtree_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_qtree_request: bad request: path %s", (char *)cstring_get_str(&path));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path);

        return (EC_TRUE);
    }

    if(1)
    {
        UINT32       super_md_id;

        CBYTES      *rsp_content_cbytes;

        CVECTOR      *path_cstr_vec;

        json_object *rsp_body_obj;
        const char  *rsp_body_str;

        UINT32       pos;
        CSTRING     *path_cstr;

        super_md_id = 0;

        path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_CXFSHTTP_0020);

        if(EC_FALSE == cxfs_qlist_tree(super_md_id, &path, path_cstr_vec))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_qtree_request failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_qtree_request failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path);

            cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CXFSHTTP_0021);
            cvector_free(path_cstr_vec, LOC_CXFSHTTP_0022);

            return (EC_TRUE);
        }

        /* qtree success, get path from path_cstr_vec */

        rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
        cbytes_clean(rsp_content_cbytes);

        rsp_body_obj = json_object_new_array();

        for(pos = 0; pos < cvector_size(path_cstr_vec); pos ++)
        {
            path_cstr = (CSTRING *)cvector_get(path_cstr_vec, pos);

            if(NULL_PTR == path_cstr)
            {
                continue;
            }

            json_object_array_add(rsp_body_obj, json_object_new_string((const char *)cstring_get_str(path_cstr)));

            cvector_set(path_cstr_vec, pos, NULL_PTR);
            cstring_free(path_cstr);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str)/* + 1*/);

        dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_qtree_request done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_qtree_request done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cstring_clean(&path);

        cvector_free(path_cstr_vec, LOC_CXFSHTTP_0023);

        /* free json obj */
        json_object_put(rsp_body_obj);

    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_qtree_response(CHTTP_NODE *chttp_node)
{

    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_qtree_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_qtree_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_qtree_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_mdsmf_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_qtree_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_qtree_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, OPERATOR: statusnp ----------------------------------------*/
EC_BOOL cxfshttp_commit_statusnp_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_statusnp_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusnp_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_statusnp_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusnp_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_statusnp_request: make response done\n");

    ret = cxfshttp_commit_statusnp_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusnp_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_statusnp_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    CXFSNP_MGR    * cxfsnp_mgr;
    uint32_t        cxfsnp_num;
    uint32_t        cxfsnp_id;

    json_object   * cxfsnp_mgr_obj;
    json_object   * cxfsnp_objs;

    CBYTES        * rsp_content_cbytes;
    const char    * rsp_body_str;

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    cxfsnp_mgr = cxfs_get_npp(CSOCKET_CNODE_MODI(csocket_cnode));

    rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(rsp_content_cbytes);

    cxfsnp_mgr_obj = json_object_new_object();
    json_object_add_kv(cxfsnp_mgr_obj, "np_model", c_uint32_t_to_str(CXFSNP_MGR_NP_MODEL(cxfsnp_mgr)));
    json_object_add_kv(cxfsnp_mgr_obj, "np_num"  , c_uint32_t_to_str(CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr)));

    cxfsnp_objs = json_object_new_array();
    json_object_add_obj(cxfsnp_mgr_obj, "np", cxfsnp_objs);

    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP        * cxfsnp;
        CXFSNP_HEADER * cxfsnp_header;
        json_object   * cxfsnp_obj;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            continue;
        }

        cxfsnp_header = CXFSNP_HDR(cxfsnp);

        cxfsnp_obj = json_object_new_object();
        json_object_array_add(cxfsnp_objs, cxfsnp_obj);

        json_object_add_kv(cxfsnp_obj, "np_id", c_uint32_t_to_str(cxfsnp_id));

        json_object_add_kv(cxfsnp_obj, "file_size"    , c_word_to_str(CXFSNP_FSIZE(cxfsnp)));
        json_object_add_kv(cxfsnp_obj, "del_size"     , c_uint64_t_to_space_size_str(CXFSNP_DEL_SIZE(cxfsnp)));
        json_object_add_kv(cxfsnp_obj, "recycle_size" , c_uint64_t_to_space_size_str(CXFSNP_RECYCLE_SIZE(cxfsnp)));
        json_object_add_kv(cxfsnp_obj, "item_max_num" , c_uint32_t_to_str(CXFSNP_HEADER_ITEMS_MAX_NUM(cxfsnp_header)));
        json_object_add_kv(cxfsnp_obj, "item_used_num", c_uint32_t_to_str(CXFSNP_HEADER_ITEMS_USED_NUM(cxfsnp_header)));
     }

    rsp_body_str = json_object_to_json_string_ext(cxfsnp_mgr_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
    cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, (UINT32)(strlen(rsp_body_str)/* + 1*/));

    json_object_put(cxfsnp_mgr_obj);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_statusnp_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusnp_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusnp_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusnp_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusnp_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_statusnp_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusnp_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, OPERATOR: statusdn ----------------------------------------*/
EC_BOOL cxfshttp_commit_statusdn_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_statusdn_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusdn_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_statusdn_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusdn_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_commit_statusdn_request: make response done\n");

    ret = cxfshttp_commit_statusdn_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusdn_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_statusdn_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    CXFSDN        * cxfsdn;
    CXFSPGV       * cxfspgv;

    json_object   * cxfspgv_obj;
    json_object   * cxfspgd_objs;

    CBYTES        * rsp_content_cbytes;
    const char    * rsp_body_str;

    uint16_t        disk_no;

    /*clean body chunks*/
    chttp_node_recv_clean(chttp_node);

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    cxfsdn = cxfs_get_dn(CSOCKET_CNODE_MODI(csocket_cnode));
    cxfspgv   = CXFSDN_CXFSPGV(cxfsdn);

    rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(rsp_content_cbytes);

    cxfspgv_obj = json_object_new_object();
    json_object_add_kv(cxfspgv_obj, "disk_num"         , c_uint32_t_to_str(CXFSPGV_DISK_NUM(cxfspgv)));
    json_object_add_kv(cxfspgv_obj, "disk_max_num"     , c_uint32_t_to_str(CXFSPGV_DISK_MAX_NUM(cxfspgv)));
    json_object_add_kv(cxfspgv_obj, "page_max_num"     , c_uint64_t_to_str(CXFSPGV_PAGE_MAX_NUM(cxfspgv)));
    json_object_add_kv(cxfspgv_obj, "page_used_num"    , c_uint64_t_to_str(CXFSPGV_PAGE_USED_NUM(cxfspgv)));
    json_object_add_kv(cxfspgv_obj, "actual_used_size" , c_uint64_t_to_str(CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv)));
    json_object_add_kv(cxfspgv_obj, "assign_bitmap"    , c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));

    json_object_add_kv(cxfspgv_obj, "page_model"   , CXFSPGB_PAGE_DESC);

    cxfspgd_objs = json_object_new_array();
    json_object_add_obj(cxfspgv_obj, "disk", cxfspgd_objs);

    for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
    {
        CXFSPGD          * cxfspgd;
        json_object   * cxfspgd_obj;

        cxfspgd = CXFSPGV_DISK_NODE(cxfspgv, disk_no);
        if(NULL_PTR == cxfspgd)
        {
            continue;
        }

        cxfspgd_obj = json_object_new_object();
        json_object_array_add(cxfspgd_objs, cxfspgd_obj);

        json_object_add_kv(cxfspgd_obj, "disk_no", c_uint16_t_to_str(disk_no));

        json_object_add_kv(cxfspgd_obj, "block_num"       , c_uint16_t_to_str(CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd)));
        json_object_add_kv(cxfspgd_obj, "page_max_num"    , c_uint32_t_to_str(CXFSPGD_PAGE_MAX_NUM(cxfspgd)));
        json_object_add_kv(cxfspgd_obj, "page_used_num"   , c_uint32_t_to_str(CXFSPGD_PAGE_USED_NUM(cxfspgd)));
        json_object_add_kv(cxfspgd_obj, "actual_used_size", c_uint64_t_to_str(CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd)));

        json_object_add_kv(cxfspgd_obj, "assign_bitmap"   , c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)));
    }

    rsp_body_str = json_object_to_json_string_ext(cxfspgv_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
    cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, (UINT32)(strlen(rsp_body_str)/* + 1*/));

    json_object_put(cxfspgv_obj);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_statusdn_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusdn_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusdn_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusdn_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_statusdn_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_statusdn_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_statusdn_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: file_notify ----------------------------------------*/
EC_BOOL cxfshttp_commit_file_notify_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_file_notify_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_notify_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_file_notify_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_notify_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_file_notify_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_notify_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_file_notify_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;


    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0024);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_file_notify_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_notify_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_notify_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_notify_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_notify_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_file_notify_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_file_notify(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_file_notify_request: cxfs notify %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_file_notify_request: cxfs notify %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_file_notify_request: cxfs notify %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_file_notify_request: cxfs notify %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_file_notify_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_file_notify_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_file_notify_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_file_notify_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_file_notify_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_file_notify_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_notify_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: file_terminate ----------------------------------------*/
EC_BOOL cxfshttp_commit_file_terminate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_file_terminate_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_terminate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_file_terminate_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_terminate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_file_terminate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_terminate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_file_terminate_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;


    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0025);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_file_terminate_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_terminate_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_terminate_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_terminate_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_file_terminate_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_file_terminate_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_file_terminate(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_file_terminate_request: cxfs terminate %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_file_terminate_request: cxfs terminate %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_file_terminate_request: cxfs terminate %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_file_terminate_request: cxfs terminate %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_file_terminate_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_file_terminate_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_file_terminate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_file_terminate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_file_terminate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_file_terminate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_file_terminate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: cond_wakeup ----------------------------------------*/
EC_BOOL cxfshttp_commit_cond_wakeup_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_cond_wakeup_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_wakeup_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_cond_wakeup_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_wakeup_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_cond_wakeup_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_wakeup_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_cond_wakeup_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;


    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0026);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_cond_wakeup_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_wakeup_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_wakeup_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_wakeup_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_wakeup_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_cond_wakeup_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        //CSOCKET_CNODE * csocket_cnode;
        UINT32 tag;

        tag = MD_CXFS;

        //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == super_cond_wakeup(/*CSOCKET_CNODE_MODI(csocket_cnode)*/0, tag, &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_cond_wakeup_request: cond wakeup %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_cond_wakeup_request: cond wakeup %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_cond_wakeup_request: cond wakeup %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_cond_wakeup_request: cond wakeup %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_cond_wakeup_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_cond_wakeup_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_cond_wakeup_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_cond_wakeup_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_cond_wakeup_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_cond_wakeup_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_wakeup_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: cond_terminate ----------------------------------------*/
EC_BOOL cxfshttp_commit_cond_terminate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_cond_terminate_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_terminate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_cond_terminate_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_terminate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_cond_terminate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_terminate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_cond_terminate_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;


    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0027);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_cond_terminate_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_terminate_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_terminate_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_terminate_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_cond_terminate_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_cond_terminate_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        //CSOCKET_CNODE * csocket_cnode;
        UINT32 tag;

        tag = MD_CXFS;

        //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == super_cond_terminate(/*CSOCKET_CNODE_MODI(csocket_cnode)*/0, tag, &path_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_cond_terminate_request: cond terminate %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_cond_terminate_request: cond terminate %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_cond_terminate_request: cond terminate %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_cond_terminate_request: cond terminate %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_cond_terminate_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_cond_terminate_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_cond_terminate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_cond_terminate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_cond_terminate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_cond_terminate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_cond_terminate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: renew_header ----------------------------------------*/
EC_BOOL cxfshttp_commit_renew_header_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_renew_header_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_header_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_renew_header_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_header_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_renew_header_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_header_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_renew_header_request(CHTTP_NODE *chttp_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    CSOCKET_CNODE *csocket_cnode;
    char          *renew_num;

    CSTRKV_MGR    *cstrkv_mgr;
    uint32_t       num;
    uint32_t       idx;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CXFSHTTP_0028);

    dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_renew_header_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_header_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_header_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_header_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_renew_header_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: cxfshttp_handle_renew_header_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    renew_num  = chttp_node_get_header(chttp_node, (const char *)"renew-num");
    if(NULL_PTR == renew_num)
    {
        char    *renew_key;
        char    *renew_val;

        CSTRING  renew_key_cstr;
        CSTRING  renew_val_cstr;

        renew_key  = chttp_node_get_header(chttp_node, (const char *)"renew-key");
        if(NULL_PTR == renew_key)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to 'renew-key' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to 'renew-key' absence", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        renew_val  = chttp_node_get_header(chttp_node, (const char *)"renew-val");
        if(NULL_PTR == renew_val)
        {
#if 1
            dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_renew_header_request: cxfs renew %s would remove header ['%s'] due to 'renew-val' absence\n",
                                (char *)cstring_get_str(&path_cstr), renew_key);
#endif
#if 0
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to 'renew-val' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to 'renew-val' absence", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        cstring_set_str(&renew_key_cstr, (UINT8 *)renew_key);
        cstring_set_str(&renew_val_cstr, (UINT8 *)renew_val);

        if(EC_FALSE == cxfs_renew_http_header(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &renew_key_cstr, &renew_val_cstr))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_renew_header_request: cxfs renew %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_renew_header_request: cxfs renew %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    cstrkv_mgr = cstrkv_mgr_new();
    if(NULL_PTR == cstrkv_mgr)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to new cstrkv_mgr failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to new cstrkv_mgr failed",
                (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    num = c_str_to_uint32_t(renew_num);
    for(idx = 0; idx < num; idx ++)
    {
        char     renew_key_tag[ 16 ];
        char     renew_val_tag[ 16 ];

        char    *renew_key;
        char    *renew_val;

        snprintf(renew_key_tag, sizeof(renew_key_tag)/sizeof(renew_key_tag[ 0 ]), "renew-key-%u", idx + 1);
        snprintf(renew_val_tag, sizeof(renew_val_tag)/sizeof(renew_val_tag[ 0 ]), "renew-val-%u", idx + 1);

        renew_key  = chttp_node_get_header(chttp_node, (const char *)renew_key_tag);
        if(NULL_PTR == renew_key)
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)renew_key_tag);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to '%s' absence",
                    (char *)cstring_get_str(&path_cstr), (char *)renew_key_tag);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        renew_val  = chttp_node_get_header(chttp_node, (const char *)renew_val_tag);
        if(NULL_PTR == renew_val)
        {
#if 1
            dbg_log(SEC_0194_CXFSHTTP, 9)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_renew_header_request: cxfs renew %s would remove header ['%s'] due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), renew_key, (char *)renew_val_tag);
#endif
#if 0
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)renew_val_tag);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to '%s' absence",
                    (char *)cstring_get_str(&path_cstr), (char *)renew_val_tag);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        if(EC_FALSE == cstrkv_mgr_add_kv_str(cstrkv_mgr, renew_key, renew_val))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to add '%s:%s' failed\n",
                                (char *)cstring_get_str(&path_cstr), renew_key, renew_val);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed due to add '%s:%s' failed",
                    (char *)cstring_get_str(&path_cstr), renew_key, renew_val);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
    }

    if(EC_FALSE == cxfs_renew_http_headers(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, cstrkv_mgr))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_renew_header_request: cxfs renew %s failed", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_renew_header_request: cxfs renew %s done\n",
                        (char *)cstring_get_str(&path_cstr));

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_renew_header_request: cxfs renew %s done", (char *)cstring_get_str(&path_cstr));

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    cstrkv_mgr_free(cstrkv_mgr);
    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_renew_header_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0194_CXFSHTTP, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] cxfshttp_make_renew_header_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_renew_header_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_renew_header_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_renew_header_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_renew_header_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_renew_header_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: locked_file_retire ----------------------------------------*/
EC_BOOL cxfshttp_commit_locked_file_retire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_locked_file_retire_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_locked_file_retire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_locked_file_retire_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_locked_file_retire_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_locked_file_retire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_locked_file_retire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_locked_file_retire_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_locked_file_retire_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_locked_file_retire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_locked_file_retire_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_locked_file_retire_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        char    *retire_max_num_str;
        UINT32   retire_max_num;
        UINT32   retire_num;

        retire_max_num_str = chttp_node_get_header(chttp_node, (const char *)"retire-max-num");
        retire_max_num     = c_str_to_word(retire_max_num_str);
        retire_num         = 0;

        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_locked_file_retire_request: header retire-max-num %s => %ld\n",
                                retire_max_num_str, retire_max_num);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_locked_file_retire(CSOCKET_CNODE_MODI(csocket_cnode), retire_max_num, &retire_num))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_locked_file_retire_request failed");

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_locked_file_retire_request: complete %ld\n", retire_num);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_locked_file_retire_request: complete %ld", retire_num);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        /*prepare response header*/
        cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (char *)"retire-completion", c_word_to_str(retire_num));
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_locked_file_retire_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_locked_file_retire_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_locked_file_retire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_locked_file_retire_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_locked_file_retire_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_locked_file_retire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_locked_file_retire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: wait_file_retire ----------------------------------------*/
EC_BOOL cxfshttp_commit_wait_file_retire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_wait_file_retire_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_wait_file_retire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_wait_file_retire_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_wait_file_retire_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_wait_file_retire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_wait_file_retire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_wait_file_retire_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_wait_file_retire_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_wait_file_retire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_wait_file_retire_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_wait_file_retire_request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        char    *retire_max_num_str;
        UINT32   retire_max_num;
        UINT32   retire_num;

        retire_max_num_str = chttp_node_get_header(chttp_node, (const char *)"retire-max-num");
        retire_max_num     = c_str_to_word(retire_max_num_str);
        retire_num         = 0;

        dbg_log(SEC_0194_CXFSHTTP, 1)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_wait_file_retire_request: header retire-max-num %s => %ld\n",
                                retire_max_num_str, retire_max_num);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_wait_file_retire(CSOCKET_CNODE_MODI(csocket_cnode), retire_max_num, &retire_num))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_wait_file_retire_request failed");

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_wait_file_retire_request: complete %ld\n", retire_num);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_wait_file_retire_request: complete %ld", retire_num);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        /*prepare response header*/
        cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (char *)"retire-completion", c_word_to_str(retire_num));
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_wait_file_retire_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_wait_file_retire_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_wait_file_retire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_wait_file_retire_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_wait_file_retire_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_wait_file_retire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_wait_file_retire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: stat ----------------------------------------*/
EC_BOOL cxfshttp_commit_stat_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_stat_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_stat_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_stat_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_stat_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_stat_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_stat_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_stat_request(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE *csocket_cnode;
    CBYTES        *rsp_content_cbytes;
    const char    *rsp_body_str;

    CXFS_STAT     *cxfs_stat;
    CXFSNP_MGR    *cxfsnp_mgr;
    CXFSDN        *cxfsdn;
    CXFSPGV       *cxfspgv;

    CAMD_MD       *camd_md;
    CAMD_STAT     *camd_stat;
    CDC_MD        *cdc_md;
    CDC_STAT      *cdc_stat;
    CMC_MD        *cmc_md;
    CMC_STAT      *cmc_stat;
    CAIO_MD       *caio_md;

    TASKC_MGR     *taskc_mgr;
    char          *taskc_debug_switch;

    json_object   *cxfs_obj;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    /*debug output switch*/
    taskc_debug_switch = chttp_node_get_header(chttp_node, (const char *)"taskc_debug");

    cxfsnp_mgr = cxfs_get_npp(CSOCKET_CNODE_MODI(csocket_cnode));
    cxfsdn     = cxfs_get_dn(CSOCKET_CNODE_MODI(csocket_cnode));
    cxfspgv    = CXFSDN_CXFSPGV(cxfsdn);
    cxfs_stat  = cxfs_get_stat(CSOCKET_CNODE_MODI(csocket_cnode));

    camd_md    = NULL_PTR;
    camd_stat  = NULL_PTR;
    cdc_md     = NULL_PTR;
    cdc_stat   = NULL_PTR;
    cmc_md     = NULL_PTR;
    cmc_stat   = NULL_PTR;
    caio_md    = NULL_PTR;

    camd_md    = CXFSDN_CAMD_MD(cxfsdn);
    if(NULL_PTR != camd_md)
    {
        cdc_md  = CAMD_MD_CDC_MD(camd_md);
        cmc_md  = CAMD_MD_CMC_MD(camd_md);
        caio_md = CAMD_MD_CAIO_MD(camd_md);

        camd_stat = CAMD_MD_CAMD_STAT(camd_md);
    }

    if(NULL_PTR != cdc_md)
    {
        cdc_stat = CDC_MD_STAT(cdc_md);
    }

    if(NULL_PTR != cmc_md)
    {
        cmc_stat = CMC_MD_STAT(cmc_md);
    }

    rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(rsp_content_cbytes);

    cxfs_obj = json_object_new_object();

    if(NULL_PTR != cxfs_obj)
    {
        json_object    *cxfs_coroutine_obj;

        TASK_BRD       *task_brd;
        UINT32          idle_thread_num;
        UINT32          busy_thread_num;
        UINT32          post_thread_num;
        UINT32          total_thread_num;

        cxfs_coroutine_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "coroutine", cxfs_coroutine_obj);

        task_brd = task_brd_default_get();

        croutine_pool_num_info(TASK_REQ_CTHREAD_POOL(task_brd),
                        &idle_thread_num, &busy_thread_num, &post_thread_num, &total_thread_num);

        json_object_add_k_int64(cxfs_coroutine_obj, "co_idle_num" , (int64_t)idle_thread_num);
        json_object_add_k_int64(cxfs_coroutine_obj, "co_busy_num" , (int64_t)busy_thread_num);
        json_object_add_k_int64(cxfs_coroutine_obj, "co_post_num" , (int64_t)post_thread_num);
        json_object_add_k_int64(cxfs_coroutine_obj, "co_total_num", (int64_t)total_thread_num);
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != cxfs_stat)
    {
        json_object   *cxfs_stat_obj;

        cxfs_stat_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "access_stat", cxfs_stat_obj);

        /*read*/
        json_object_add_k_int64(cxfs_stat_obj, "ac_read_counter"         , (int64_t)CXFS_STAT_READ_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_read_np_succ_counter" , (int64_t)CXFS_STAT_READ_NP_SUCC_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_read_np_fail_counter" , (int64_t)CXFS_STAT_READ_NP_FAIL_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_read_dn_succ_counter" , (int64_t)CXFS_STAT_READ_DN_SUCC_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_read_dn_fail_counter" , (int64_t)CXFS_STAT_READ_DN_FAIL_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_read_nbytes"          , (int64_t)CXFS_STAT_READ_NBYTES(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_read_cost_msec"       , (int64_t)CXFS_STAT_READ_COST_MSEC(cxfs_stat));

        /*write*/
        json_object_add_k_int64(cxfs_stat_obj, "ac_write_counter"         , (int64_t)CXFS_STAT_WRITE_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_write_np_succ_counter" , (int64_t)CXFS_STAT_WRITE_NP_SUCC_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_write_np_fail_counter" , (int64_t)CXFS_STAT_WRITE_NP_FAIL_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_write_dn_succ_counter" , (int64_t)CXFS_STAT_WRITE_DN_SUCC_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_write_dn_fail_counter" , (int64_t)CXFS_STAT_WRITE_DN_FAIL_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_write_nbytes"          , (int64_t)CXFS_STAT_WRITE_NBYTES(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_write_cost_msec"       , (int64_t)CXFS_STAT_WRITE_COST_MSEC(cxfs_stat));

        /*delete*/
        json_object_add_k_int64(cxfs_stat_obj, "ac_delete_counter", (int64_t)CXFS_STAT_DELETE_COUNTER(cxfs_stat));
        if(NULL_PTR != cxfsnp_mgr)
        {
            uint64_t       total_size;

            total_size = cxfsnp_mgr_count_delete_size(cxfsnp_mgr);
            json_object_add_k_int64(cxfs_stat_obj, "ac_delete_nbytes", (int64_t)total_size);
        }

        /*update*/
        json_object_add_k_int64(cxfs_stat_obj, "ac_update_counter"        , (int64_t)CXFS_STAT_UPDATE_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_update_succ_counter"   , (int64_t)CXFS_STAT_UPDATE_SUCC_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_update_fail_counter"   , (int64_t)CXFS_STAT_UPDATE_FAIL_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_update_nbytes"         , (int64_t)CXFS_STAT_UPDATE_NBYTES(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_update_cost_msec"      , (int64_t)CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat));

        /*renew*/
        json_object_add_k_int64(cxfs_stat_obj, "ac_renew_counter"         , (int64_t)CXFS_STAT_RENEW_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_renew_succ_counter"    , (int64_t)CXFS_STAT_RENEW_SUCC_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_renew_fail_counter"    , (int64_t)CXFS_STAT_RENEW_FAIL_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_renew_nbytes"          , (int64_t)CXFS_STAT_RENEW_NBYTES(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_renew_cost_msec"       , (int64_t)CXFS_STAT_RENEW_COST_MSEC(cxfs_stat));

        /*retire*/
        json_object_add_k_int64(cxfs_stat_obj, "ac_retire_counter" , (int64_t)CXFS_STAT_RETIRE_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_retire_complete", (int64_t)CXFS_STAT_RETIRE_COMPLETE(cxfs_stat));

        /*recycle*/
        json_object_add_k_int64(cxfs_stat_obj, "ac_recycle_counter" , (int64_t)CXFS_STAT_RECYCLE_COUNTER(cxfs_stat));
        json_object_add_k_int64(cxfs_stat_obj, "ac_recycle_complete", (int64_t)CXFS_STAT_RECYCLE_COMPLETE(cxfs_stat));
        if(NULL_PTR != cxfsnp_mgr)
        {
            uint64_t       total_size;

            total_size = cxfsnp_mgr_count_recycle_size(cxfsnp_mgr);
            json_object_add_k_int64(cxfs_stat_obj, "ac_recycle_nbytes", (int64_t)total_size);
        }
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != cxfsnp_mgr && NULL_PTR != cxfsdn && NULL_PTR != cxfspgv)
    {
        json_object   *cxfs_comm_obj;

        cxfs_comm_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "xfs_model", cxfs_comm_obj);

        json_object_add_kv(cxfs_comm_obj      , "cxfs_lru_model_switch_desc", c_switch_to_str(CXFS_LRU_MODEL_SWITCH));
        json_object_add_k_int32(cxfs_comm_obj , "cxfs_lru_model_switch"   , SWITCH_ON == CXFS_LRU_MODEL_SWITCH?1:0);

        json_object_add_kv(cxfs_comm_obj      , "cxfs_fifo_model_switch_desc", c_switch_to_str(CXFS_FIFO_MODEL_SWITCH));
        json_object_add_k_int32(cxfs_comm_obj , "cxfs_fifo_model_switch"   , SWITCH_ON == CXFS_FIFO_MODEL_SWITCH?1:0);

        json_object_add_kv(cxfs_comm_obj      , "cxfs_camd_overhead_switch_desc", c_switch_to_str(CXFS_CAMD_OVERHEAD_SWITCH));
        json_object_add_k_int32(cxfs_comm_obj , "cxfs_camd_overhead_switch"   , SWITCH_ON == CXFS_CAMD_OVERHEAD_SWITCH?1:0);
        json_object_add_k_int32(cxfs_comm_obj , "cxfs_camd_discard_ratio"     , (int64_t)CXFS_CAMD_DISCARD_RATIO);

        json_object_add_k_int32(cxfs_comm_obj , "c_memalign_counter"          , (int64_t)c_memalign_counter());
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != cxfsnp_mgr)
    {
        json_object   *cxfs_npp_obj;

        cxfs_npp_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "namespace", cxfs_npp_obj);

        json_object_add_k_int32(cxfs_npp_obj, "np_model"            , (int32_t)CXFSNP_MGR_NP_MODEL(cxfsnp_mgr));
        json_object_add_k_int32(cxfs_npp_obj, "np_max_num"          , (int32_t)CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr));
        json_object_add_k_int64(cxfs_npp_obj, "np_size"             , (int64_t)CXFSNP_MGR_NP_SIZE(cxfsnp_mgr));
        json_object_add_k_int64(cxfs_npp_obj, "np_start_offset"     , (int64_t)CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr));
        json_object_add_k_int64(cxfs_npp_obj, "np_end_offset"       , (int64_t)CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr));
        json_object_add_k_int64(cxfs_npp_obj, "np_total_size_nbytes",
                                (int64_t)(CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr)));

        json_object_add_k_int64(cxfs_npp_obj, "np_item_max_num"     , (int64_t)cxfsnp_mgr_item_max_num(cxfsnp_mgr));
        json_object_add_k_int64(cxfs_npp_obj, "np_item_used_num"    , (int64_t)cxfsnp_mgr_item_used_num(cxfsnp_mgr));
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != cxfsdn && NULL_PTR != cxfspgv)
    {
        json_object   *cxfs_dn_obj;
        REAL           page_used_ratio;

        if(0 < CXFSPGV_PAGE_MAX_NUM(cxfspgv))
        {
            page_used_ratio = ((0.0 + CXFSPGV_PAGE_USED_NUM(cxfspgv)) / (0.0 + CXFSPGV_PAGE_MAX_NUM(cxfspgv)));
        }
        else
        {
            page_used_ratio = 0.00;
        }

        cxfs_dn_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "datanode", cxfs_dn_obj);


        json_object_add_kv(cxfs_dn_obj     , "dn_pgd_disk_choice_desc", CXFSPGD_DISK_DESC);
        json_object_add_k_int64(cxfs_dn_obj, "dn_pgd_disk_choice"     , (int64_t)(((uint64_t)1) << CXFSPGD_SIZE_NBITS));

        json_object_add_kv(cxfs_dn_obj     , "dn_pgb_page_choice_desc", CXFSPGB_PAGE_DESC);
        json_object_add_k_int64(cxfs_dn_obj, "dn_pgb_page_choice"     , (int64_t)CXFSPGB_PAGE_BYTE_SIZE);

        json_object_add_kv(cxfs_dn_obj     , "dn_bad_page_choice_desc", CXFSDN_BAD_PAGE_DESC);
        json_object_add_k_int64(cxfs_dn_obj, "dn_bad_page_choice"     , (int64_t)CXFSDN_BAD_PAGE_SIZE_NBYTES);

        json_object_add_k_int64(cxfs_dn_obj, "dn_offset"          , (int64_t)CXFSPGV_OFFSET(cxfspgv));
        json_object_add_k_int64(cxfs_dn_obj, "dn_fsize_nbytes"    , (int64_t)CXFSPGV_FSIZE(cxfspgv));
        json_object_add_k_int32(cxfs_dn_obj, "dn_disk_num"        , (int32_t)CXFSPGV_DISK_NUM(cxfspgv));
        json_object_add_k_int32(cxfs_dn_obj, "dn_disk_max_num"    , (int32_t)CXFSPGV_DISK_MAX_NUM(cxfspgv));
        json_object_add_k_int64(cxfs_dn_obj, "dn_page_max_num"    , (int64_t)CXFSPGV_PAGE_MAX_NUM(cxfspgv));
        json_object_add_k_int64(cxfs_dn_obj, "dn_page_used_num"   , (int64_t)CXFSPGV_PAGE_USED_NUM(cxfspgv));
        json_object_add_k_double(cxfs_dn_obj,"dn_page_used_ratio" , (double)page_used_ratio);
        json_object_add_k_int64(cxfs_dn_obj, "dn_used_size_nbytes", (int64_t)CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv));
        json_object_add_kv(cxfs_dn_obj     , "dn_assign_bitmap_desc", c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));
        json_object_add_k_int32(cxfs_dn_obj, "dn_assign_bitmap"     , (int32_t)CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv));
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != camd_stat)
    {
        json_object   *camd_stat_obj;

        camd_stat_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "camd_stat", camd_stat_obj);

        json_object_add_k_int64(camd_stat_obj, "camd_disk_dispatch_hit", (int64_t)CAMD_STAT_DISPATCH_HIT(camd_stat));
        json_object_add_k_int64(camd_stat_obj, "camd_disk_dispatch_miss", (int64_t)CAMD_STAT_DISPATCH_MISS(camd_stat));

        json_object_add_k_int64(camd_stat_obj, "camd_rd_page_is_aligned_counter", (int64_t)CAMD_STAT_PAGE_IS_ALIGNED_COUNTER(camd_stat, CAMD_OP_RD));
        json_object_add_k_int64(camd_stat_obj, "camd_rd_page_not_aligned_counter", (int64_t)CAMD_STAT_PAGE_NOT_ALIGNED_COUNTER(camd_stat, CAMD_OP_RD));

        json_object_add_k_int64(camd_stat_obj, "camd_wr_page_is_aligned_counter", (int64_t)CAMD_STAT_PAGE_IS_ALIGNED_COUNTER(camd_stat, CAMD_OP_WR));
        json_object_add_k_int64(camd_stat_obj, "camd_wr_page_not_aligned_counter", (int64_t)CAMD_STAT_PAGE_NOT_ALIGNED_COUNTER(camd_stat, CAMD_OP_WR));

        json_object_add_k_int64(camd_stat_obj, "camd_rd_node_is_aligned_counter", (int64_t)CAMD_STAT_NODE_IS_ALIGNED_COUNTER(camd_stat, CAMD_OP_RD));
        json_object_add_k_int64(camd_stat_obj, "camd_rd_node_not_aligned_counter", (int64_t)CAMD_STAT_NODE_NOT_ALIGNED_COUNTER(camd_stat, CAMD_OP_RD));

        json_object_add_k_int64(camd_stat_obj, "camd_wr_node_is_aligned_counter", (int64_t)CAMD_STAT_NODE_IS_ALIGNED_COUNTER(camd_stat, CAMD_OP_WR));
        json_object_add_k_int64(camd_stat_obj, "camd_wr_node_not_aligned_counter", (int64_t)CAMD_STAT_NODE_NOT_ALIGNED_COUNTER(camd_stat, CAMD_OP_WR));

        json_object_add_k_int64(camd_stat_obj, "camd_mem_reused_counter", (int64_t)CAMD_STAT_MEM_REUSED_COUNTER(camd_stat));
        json_object_add_k_int64(camd_stat_obj, "camd_mem_zcopy_counter" , (int64_t)CAMD_STAT_MEM_ZCOPY_COUNTER(camd_stat));
        json_object_add_k_int64(camd_stat_obj, "camd_mem_fcopy_counter" , (int64_t)CAMD_STAT_MEM_FCOPY_COUNTER(camd_stat));
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != cdc_stat)
    {
        json_object   *cdc_stat_obj;

        cdc_stat_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "cdc_stat", cdc_stat_obj);

        json_object_add_kv(cdc_stat_obj      , "cdc_pgd_disk_choice_desc", CDCPGD_DISK_DESC);
        json_object_add_k_int64(cdc_stat_obj, "cdc_pgd_disk_choice"    , (int64_t)(((uint64_t)1) << CDCPGD_SIZE_NBITS));

        json_object_add_kv(cdc_stat_obj      , "cdc_pgb_page_choice_desc", CDCPGB_PAGE_DESC);
        json_object_add_k_int64(cdc_stat_obj , "cdc_pgb_page_choice"    , (int64_t)CDCPGB_PAGE_SIZE_NBYTES);

        json_object_add_kv(cdc_stat_obj      , "cdc_dn_node_choice"     , CDCDN_NODE_DESC);
        json_object_add_k_int64(cdc_stat_obj , "cdc_dn_node_choice"     , (int64_t)(((uint64_t)1) << CDCDN_NODE_SIZE_NBITS));

        json_object_add_kv(cdc_stat_obj      , "cdc_lru_model_switch_desc", c_switch_to_str(CDC_LRU_MODEL_SWITCH));
        json_object_add_k_int32(cdc_stat_obj , "cdc_lru_model_switch"   , SWITCH_ON == CDC_LRU_MODEL_SWITCH?1:0);

        json_object_add_kv(cdc_stat_obj      , "cdc_fifo_model_switch_desc", c_switch_to_str(CDC_FIFO_MODEL_SWITCH));
        json_object_add_k_int32(cdc_stat_obj , "cdc_fifo_model_switch"   , SWITCH_ON == CDC_FIFO_MODEL_SWITCH?1:0);

        json_object_add_k_double(cdc_stat_obj, "cdc_used_ratio"         , (double )CDC_STAT_SSD_USED_RATIO(cdc_stat));
        json_object_add_k_double(cdc_stat_obj, "cdc_hit_ratio"          , (double )CDC_STAT_SSD_HIT_RATIO(cdc_stat));
        json_object_add_k_int64(cdc_stat_obj,  "cdc_amd_read_speed_mps" , (int64_t)CDC_STAT_AMD_READ_SPEED(cdc_stat));
        json_object_add_k_int64(cdc_stat_obj,  "cdc_amd_write_speed_mps", (int64_t)CDC_STAT_AMD_WRITE_SPEED(cdc_stat));
        json_object_add_k_double(cdc_stat_obj, "cdc_degrade_ratio"      , (double )CDC_STAT_SSD_DEGRADE_RATIO(cdc_stat));
        json_object_add_k_int64(cdc_stat_obj,  "cdc_degrade_num"        , (int64_t)CDC_STAT_SSD_DEGRADE_NUM(cdc_stat));
        json_object_add_k_int64(cdc_stat_obj,  "cdc_degrade_speed_mps"  , (int64_t)CDC_STAT_SSD_DEGRADE_SPEED(cdc_stat));

        json_object_add_k_int64(cdc_stat_obj, "cdc_disk_dispatch_hit", (int64_t)CDC_STAT_DISPATCH_HIT(cdc_stat));
        json_object_add_k_int64(cdc_stat_obj, "cdc_disk_dispatch_miss", (int64_t)CDC_STAT_DISPATCH_MISS(cdc_stat));

        json_object_add_k_int64(cdc_stat_obj, "cdc_rd_page_is_aligned_counter", (int64_t)CDC_STAT_PAGE_IS_ALIGNED_COUNTER(cdc_stat, CDC_OP_RD));
        json_object_add_k_int64(cdc_stat_obj, "cdc_rd_page_not_aligned_counter", (int64_t)CDC_STAT_PAGE_NOT_ALIGNED_COUNTER(cdc_stat, CDC_OP_RD));

        json_object_add_k_int64(cdc_stat_obj, "cdc_wr_page_is_aligned_counter", (int64_t)CDC_STAT_PAGE_IS_ALIGNED_COUNTER(cdc_stat, CDC_OP_WR));
        json_object_add_k_int64(cdc_stat_obj, "cdc_wr_page_not_aligned_counter", (int64_t)CDC_STAT_PAGE_NOT_ALIGNED_COUNTER(cdc_stat, CDC_OP_WR));

        json_object_add_k_int64(cdc_stat_obj, "cdc_rd_node_is_aligned_counter", (int64_t)CDC_STAT_NODE_IS_ALIGNED_COUNTER(cdc_stat, CDC_OP_RD));
        json_object_add_k_int64(cdc_stat_obj, "cdc_rd_node_not_aligned_counter", (int64_t)CDC_STAT_NODE_NOT_ALIGNED_COUNTER(cdc_stat, CDC_OP_RD));

        json_object_add_k_int64(cdc_stat_obj, "cdc_wr_node_is_aligned_counter", (int64_t)CDC_STAT_NODE_IS_ALIGNED_COUNTER(cdc_stat, CDC_OP_WR));
        json_object_add_k_int64(cdc_stat_obj, "cdc_wr_node_not_aligned_counter", (int64_t)CDC_STAT_NODE_NOT_ALIGNED_COUNTER(cdc_stat, CDC_OP_WR));

        json_object_add_k_int64(cdc_stat_obj, "cdc_mem_reused_counter", (int64_t)CDC_STAT_MEM_REUSED_COUNTER(cdc_stat));
        json_object_add_k_int64(cdc_stat_obj, "cdc_mem_zcopy_counter" , (int64_t)CDC_STAT_MEM_ZCOPY_COUNTER(cdc_stat));
        json_object_add_k_int64(cdc_stat_obj, "cdc_mem_fcopy_counter" , (int64_t)CDC_STAT_MEM_FCOPY_COUNTER(cdc_stat));
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != cmc_stat)
    {
        json_object   *cmc_stat_obj;

        cmc_stat_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "cmc_stat", cmc_stat_obj);

        json_object_add_k_int64(cmc_stat_obj , "cmc_mem_disk_size"       , (int64_t)CXFSDN_CAMD_MEM_DISK_SIZE);
        json_object_add_kv(cmc_stat_obj      , "cmc_pgd_disk_choice_desc", CMCPGD_DISK_DESC);
        json_object_add_k_int64(cmc_stat_obj , "cmc_pgd_disk_choice"    , (int64_t)(((uint64_t)1) << CMCPGD_SIZE_NBITS));

        json_object_add_kv(cmc_stat_obj      , "cmc_pgb_page_choice_desc", CMCPGB_PAGE_DESC);
        json_object_add_k_int64(cmc_stat_obj , "cmc_pgb_page_choice"    , (int64_t)CMCPGB_PAGE_SIZE_NBYTES);

        json_object_add_kv(cmc_stat_obj      , "cmc_dn_node_choice_desc", CMCDN_NODE_DESC);
        json_object_add_k_int64(cmc_stat_obj , "cmc_dn_node_choice"    , (int64_t)(((uint64_t)1) << CMCDN_NODE_SIZE_NBITS));

        json_object_add_kv(cmc_stat_obj      , "cmc_lru_model_switch_desc", c_switch_to_str(CMC_LRU_MODEL_SWITCH));
        json_object_add_k_int32(cmc_stat_obj , "cmc_lru_model_switch"     , SWITCH_ON == CMC_LRU_MODEL_SWITCH?1:0);

        json_object_add_kv(cmc_stat_obj      , "cmc_fifo_model_switch_desc", c_switch_to_str(CMC_FIFO_MODEL_SWITCH));
        json_object_add_k_int32(cmc_stat_obj , "cmc_fifo_model_switch"     , SWITCH_ON == CMC_FIFO_MODEL_SWITCH?1:0);

        json_object_add_k_double(cmc_stat_obj, "cmc_used_ratio"         , (double )CMC_STAT_MEM_USED_RATIO(cmc_stat));
        json_object_add_k_double(cmc_stat_obj, "cmc_hit_ratio"          , (double )CMC_STAT_MEM_HIT_RATIO(cmc_stat));
        json_object_add_k_int64(cmc_stat_obj,  "cmc_amd_read_speed_mps" , (int64_t)CMC_STAT_AMD_READ_SPEED(cmc_stat));
        json_object_add_k_int64(cmc_stat_obj,  "cmc_amd_write_speed_mps", (int64_t)CMC_STAT_AMD_WRITE_SPEED(cmc_stat));
        json_object_add_k_double(cmc_stat_obj, "cmc_degrade_ratio"      , (double )CMC_STAT_MEM_DEGRADE_RATIO(cmc_stat));
        json_object_add_k_int64(cmc_stat_obj,  "cmc_degrade_num"        , (int64_t)CMC_STAT_MEM_DEGRADE_NUM(cmc_stat));
        json_object_add_k_int64(cmc_stat_obj,  "cmc_degrade_speed_mps"  , (int64_t)CMC_STAT_MEM_DEGRADE_SPEED(cmc_stat));
    }

    if(NULL_PTR != cxfs_obj && NULL_PTR != caio_md)
    {
        CLIST_DATA    *clist_data;

        json_object   *caio_stat_obj;
        char           k[ 64 ];

        caio_stat_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "caio_stat", caio_stat_obj);

        CLIST_LOOP_NEXT(CAIO_MD_DISK_LIST(caio_md), clist_data)
        {
            CAIO_DISK       *caio_disk;
            CAIO_STAT       *caio_stat;

            caio_disk = CLIST_DATA_DATA(clist_data);
            if(NULL_PTR == caio_disk)
            {
                continue;
            }

            caio_stat = CAIO_DISK_STAT(caio_disk);

            snprintf((char *)k, sizeof(k), "%s_disk_fd", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int32(caio_stat_obj, (char *)k , (int32_t)CAIO_DISK_FD(caio_disk));

            snprintf((char *)k, sizeof(k), "%s_disk_read_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_OP_COUNTER(caio_stat, CAIO_OP_RD));

            snprintf((char *)k, sizeof(k), "%s_disk_read_nbytes", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_OP_NBYTES(caio_stat, CAIO_OP_RD));

            snprintf((char *)k, sizeof(k), "%s_disk_read_cost_msec", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_COST_MSEC(caio_stat, CAIO_OP_RD));

            snprintf((char *)k, sizeof(k), "%s_disk_write_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_OP_COUNTER(caio_stat, CAIO_OP_WR));

            snprintf((char *)k, sizeof(k), "%s_disk_write_nbytes", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_OP_NBYTES(caio_stat, CAIO_OP_WR));

            snprintf((char *)k, sizeof(k), "%s_disk_write_cost_msec", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_COST_MSEC(caio_stat, CAIO_OP_WR));

            snprintf((char *)k, sizeof(k), "%s_disk_dispatch_hit", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_DISPATCH_HIT(caio_stat));

            snprintf((char *)k, sizeof(k), "%s_disk_dispatch_miss", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_DISPATCH_MISS(caio_stat));

            snprintf((char *)k, sizeof(k), "%s_rd_page_is_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_PAGE_IS_ALIGNED_COUNTER(caio_stat, CAIO_OP_RD));

            snprintf((char *)k, sizeof(k), "%s_rd_page_not_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_PAGE_NOT_ALIGNED_COUNTER(caio_stat, CAIO_OP_RD));

            snprintf((char *)k, sizeof(k), "%s_wr_page_is_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_PAGE_IS_ALIGNED_COUNTER(caio_stat, CAIO_OP_WR));

            snprintf((char *)k, sizeof(k), "%s_wr_page_not_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_PAGE_NOT_ALIGNED_COUNTER(caio_stat, CAIO_OP_WR));

            snprintf((char *)k, sizeof(k), "%s_rd_node_is_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_NODE_IS_ALIGNED_COUNTER(caio_stat, CAIO_OP_RD));

            snprintf((char *)k, sizeof(k), "%s_rd_node_not_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_NODE_NOT_ALIGNED_COUNTER(caio_stat, CAIO_OP_RD));

            snprintf((char *)k, sizeof(k), "%s_wr_node_is_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_NODE_IS_ALIGNED_COUNTER(caio_stat, CAIO_OP_WR));

            snprintf((char *)k, sizeof(k), "%s_wr_node_not_aligned_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_NODE_NOT_ALIGNED_COUNTER(caio_stat, CAIO_OP_WR));

            snprintf((char *)k, sizeof(k), "%s_mem_reused_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_MEM_REUSED_COUNTER(caio_stat));

            snprintf((char *)k, sizeof(k), "%s_mem_zcopy_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_MEM_ZCOPY_COUNTER(caio_stat));

            snprintf((char *)k, sizeof(k), "%s_mem_fcopy_counter", CAIO_DISK_TAG(caio_disk));
            json_object_add_k_int64(caio_stat_obj, (char *)k, (int64_t)CAIO_STAT_MEM_FCOPY_COUNTER(caio_stat));
        }
    }

    taskc_mgr = taskc_mgr_new();
    if(NULL_PTR != cxfs_obj && NULL_PTR != taskc_mgr)
    {
        json_object   *taskc_stat_obj; /*task communication stat*/
        json_object   *taskc_list_obj; /*task communication list*/
        CLIST         *taskc_list;
        CLIST_DATA    *clist_data;

        super_sync_taskc_mgr(0/*super*/, taskc_mgr);
        taskc_list = TASKC_MGR_NODE_LIST(taskc_mgr);

        taskc_stat_obj = json_object_new_object();
        json_object_add_obj(cxfs_obj, "taskc_stat", taskc_stat_obj);

        json_object_add_k_int64(taskc_stat_obj, "taskc_num", (int64_t)clist_size(taskc_list));

        if(NULL_PTR != taskc_debug_switch
        && EC_TRUE == c_str_is_in(taskc_debug_switch, (const char *)":", (const char *)"on"))
        {
            taskc_list_obj = json_object_new_array();
            json_object_add_obj(taskc_stat_obj, "taskc_list", taskc_list_obj);

            CLIST_LOOP_NEXT(taskc_list, clist_data)
            {
                TASKC_NODE *taskc_node;

                json_object   *taskc_node_obj; /*task communication list*/

                taskc_node = CLIST_DATA_DATA(clist_data);

                taskc_node_obj = json_object_new_object();
                json_object_array_add(taskc_list_obj, taskc_node_obj);

                json_object_add_kv(taskc_node_obj, "tcid", c_word_to_ipv4(TASKC_NODE_TCID(taskc_node)));

                if(1)
                {
                    json_object_add_k_int64(taskc_node_obj, "comm", (int64_t)TASKC_NODE_COMM(taskc_node));
                    json_object_add_k_int64(taskc_node_obj, "size", (int64_t)TASKC_NODE_SIZE(taskc_node));
                }
            }
        }

        taskc_mgr_free(taskc_mgr);
    }

    rsp_body_str = json_object_to_json_string_ext(cxfs_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
    cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, (UINT32)(strlen(rsp_body_str)/* + 1*/));

    json_object_put(cxfs_obj);

    dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_stat_request: done\n");

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(rsp_content_cbytes));
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_stat_request: done");

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_stat_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_stat_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_stat_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_stat_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_stat_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_stat_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_stat_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: activate_ngx ----------------------------------------*/
EC_BOOL cxfshttp_commit_activate_ngx_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_activate_ngx_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_activate_ngx_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_activate_ngx_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_activate_ngx_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_activate_ngx_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_activate_ngx_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_activate_ngx_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_activate_ngx_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_activate_ngx_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_activate_ngx_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_activate_ngx_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_activate_ngx(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_activate_ngx_request: cxfs activate_ngx failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_activate_ngx_request: cxfs activate_ngx failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_activate_ngx_request: cxfs activate_ngx done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_activate_ngx_request: cxfs activate_ngx done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_activate_ngx_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_activate_ngx_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_activate_ngx_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_activate_ngx_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_activate_ngx_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_activate_ngx_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: deactivate_ngx ----------------------------------------*/
EC_BOOL cxfshttp_commit_deactivate_ngx_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_deactivate_ngx_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_deactivate_ngx_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_deactivate_ngx_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_deactivate_ngx_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_deactivate_ngx_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_deactivate_ngx_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_deactivate_ngx_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CXFSHTTP_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_deactivate_ngx_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_deactivate_ngx_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error: cxfshttp_handle_deactivate_ngx_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_deactivate_ngx_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == cxfs_deactivate_ngx(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_handle_deactivate_ngx_request: cxfs deactivate_ngx failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:cxfshttp_handle_deactivate_ngx_request: cxfs deactivate_ngx failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_deactivate_ngx_request: cxfs deactivate_ngx done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_deactivate_ngx_request: cxfs deactivate_ngx done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_deactivate_ngx_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_deactivate_ngx_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_deactivate_ngx_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_deactivate_ngx_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_deactivate_ngx_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_deactivate_ngx_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: paracfg ----------------------------------------*/
EC_BOOL cxfshttp_commit_paracfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cxfshttp_handle_paracfg_request(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_paracfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfshttp_make_paracfg_response(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_paracfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = cxfshttp_commit_paracfg_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_paracfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cxfshttp_handle_paracfg_request(CHTTP_NODE *chttp_node)
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

        dbg_log(SEC_0194_CXFSHTTP, 5)(LOGSTDOUT, "[DEBUG] cxfshttp_handle_paracfg_request: done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(rsp_content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] cxfshttp_handle_paracfg_request: done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cxfshttp_make_paracfg_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_paracfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_paracfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_paracfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_make_paracfg_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cxfshttp_commit_paracfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0194_CXFSHTTP, 0)(LOGSTDOUT, "error:cxfshttp_commit_paracfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return cxfshttp_commit_response(chttp_node);
}
#endif


#ifdef __cplusplus
}
#endif/*__cplusplus*/

