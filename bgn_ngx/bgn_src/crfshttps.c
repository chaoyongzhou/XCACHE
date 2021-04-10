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

#include "crfs.h"
#include "chttp.inc"
#include "chttp.h"
#include "chttps.inc"
#include "chttps.h"
#include "crfshttps.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "findex.inc"

#if 0
#define CRFSHTTPS_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CRFSHTTPS_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CRFSHTTPS_PRINT_UINT8(info, buff, len) do{}while(0)
#define CRFSHTTPS_PRINT_CHARS(info, buff, len) do{}while(0)
#endif



#if 1
#define CRFSHTTPS_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

#if 0
#define CRFSHTTPS_ASSERT(condition) do{}while(0)
#endif

#if 1
//#define CRFSHTTPS_TIME_COST_FORMAT " BegTime:%u.%03u EndTime:%u.%03u Elapsed:%u "
#define CRFSHTTPS_TIME_COST_FORMAT " %u.%03u %u.%03u %u "
#define CRFSHTTPS_TIME_COST_VALUE(chttp_node)  \
    (uint32_t)CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node)), (uint32_t)CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTP_NODE_START_TMV(chttp_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTP_NODE_START_TMV(chttp_node)))
#endif

static EC_BOOL g_crfshttps_log_init = EC_FALSE;

static const CHTTP_API g_crfshttps_api_list[] = {
    {CONST_STR_AND_LEN("lock_req")          , CHTTP_METHOD_GET   , crfshttps_commit_lock_req_request},
    {CONST_STR_AND_LEN("unlock_req")        , CHTTP_METHOD_GET   , crfshttps_commit_unlock_req_request},
    {CONST_STR_AND_LEN("unlock_notify_req") , CHTTP_METHOD_GET   , crfshttps_commit_unlock_notify_req_request},
    {CONST_STR_AND_LEN("breathe")           , CHTTP_METHOD_GET   , crfshttps_commit_breathe_request},
    {CONST_STR_AND_LEN("retire")            , CHTTP_METHOD_GET   , crfshttps_commit_retire_request},
    {CONST_STR_AND_LEN("recycle")           , CHTTP_METHOD_GET   , crfshttps_commit_recycle_request},
    {CONST_STR_AND_LEN("flush")             , CHTTP_METHOD_GET   , crfshttps_commit_flush_request},
    {CONST_STR_AND_LEN("getsmf")            , CHTTP_METHOD_GET   , crfshttps_commit_getsmf_request},
    {CONST_STR_AND_LEN("dsmf")              , CHTTP_METHOD_DELETE, crfshttps_commit_dsmf_request},
    {CONST_STR_AND_LEN("ddir")              , CHTTP_METHOD_DELETE, crfshttps_commit_ddir_request},
    {CONST_STR_AND_LEN("sexpire")           , CHTTP_METHOD_PATCH , crfshttps_commit_sexpire_request},

    {CONST_STR_AND_LEN("logrotate")         , CHTTP_METHOD_GET   , crfshttps_commit_logrotate_request},
    {CONST_STR_AND_LEN("actsyscfg")         , CHTTP_METHOD_GET   , crfshttps_commit_actsyscfg_request},
    {CONST_STR_AND_LEN("qtree")             , CHTTP_METHOD_GET   , crfshttps_commit_qtree_request},
    {CONST_STR_AND_LEN("file_notify")       , CHTTP_METHOD_GET   , crfshttps_commit_file_notify_request},
    {CONST_STR_AND_LEN("cond_wakeup")       , CHTTP_METHOD_GET   , crfshttps_commit_cond_wakeup_request},
    {CONST_STR_AND_LEN("renew_header")      , CHTTP_METHOD_PUT   , crfshttps_commit_renew_header_request},
    {CONST_STR_AND_LEN("locked_file_retire"), CHTTP_METHOD_GET   , crfshttps_commit_locked_file_retire_request},
    {CONST_STR_AND_LEN("paracfg")           , CHTTP_METHOD_GET   , crfshttps_commit_paracfg_request},

    {CONST_STR_AND_LEN("setsmf")            , CHTTP_METHOD_POST  , crfshttps_commit_setsmf_request},
    {CONST_STR_AND_LEN("update")            , CHTTP_METHOD_PUT   , crfshttps_commit_update_request},
    {CONST_STR_AND_LEN("renew")             , CHTTP_METHOD_PUT   , crfshttps_commit_renew_request},
    {CONST_STR_AND_LEN("mexpire")           , CHTTP_METHOD_PATCH , crfshttps_commit_mexpire_request},
    {CONST_STR_AND_LEN("mdsmf")             , CHTTP_METHOD_DELETE, crfshttps_commit_mdsmf_request},
    {CONST_STR_AND_LEN("mddir")             , CHTTP_METHOD_DELETE, crfshttps_commit_mddir_request},
};

static const uint32_t   g_crfshttps_api_num = sizeof(g_crfshttps_api_list)/sizeof(g_crfshttps_api_list[0]);


EC_BOOL crfshttps_log_start()
{
    TASK_BRD        *task_brd;

    if(EC_TRUE == g_crfshttps_log_init)
    {
        return (EC_TRUE);
    }

    g_crfshttps_log_init = EC_TRUE;

    task_brd = task_brd_default_get();

#if 0/*support rotate*/
    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;

        log_file_name = cstring_new(NULL_PTR, LOC_CRFSHTTPS_0001);
        cstring_format(log_file_name, "%s/rfs_%s_%ld.log",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        if(EC_FALSE == user_log_open(LOGUSER08, (char *)cstring_get_str(log_file_name), "a+"))/*append mode. scenario: after restart*/
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_log_start: user_log_open '%s' -> LOGUSER08 failed\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CRFSHTTPS_0002);
        cstring_format(log_file_name, "%s/rfs_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER08, log);

            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "[DEBUG] crfshttps_log_start: log_file_open '%s' -> LOGUSER08 done\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CRFSHTTPS_0003);
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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_log_start: log_file_open '%s' -> LOGUSER07 failed\n",
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

EC_BOOL crfshttps_commit_request(CHTTP_NODE *chttp_node)
{
    http_parser_t *http_parser;
    uint32_t       method;

    http_parser = CHTTP_NODE_PARSER(chttp_node);

    method = chttp_method_convert(http_parser->method);
    if(CHTTP_METHOD_UNKNOWN != method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load_preempt(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)crfshttps_commit_start, 2, chttp_node, (UINT32)method);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_request: "
                                                      "no croutine\n");

            /*return (EC_BUSY);*/
            return (EC_FALSE); /*note: do not retry to relieve system pressure*/
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSHTTPS_0002);

        return (EC_TRUE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_request: "
                                              "not support http method %d yet\n",
                                              http_parser->method);
    return (EC_FALSE);/*note: this chttp_node must be discarded*/
}

EC_BOOL crfshttps_commit_start(CHTTP_NODE *chttp_node, const UINT32 method)
{
    const CHTTP_API       *chttp_api;
    EC_BOOL                ret;

    CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node);/*record rfs beg to handle time*/

    chttp_api = chttp_node_find_api(chttp_node,
                                    (const CHTTP_API *)g_crfshttps_api_list,
                                    g_crfshttps_api_num,
                                    (uint32_t)method);
    if(NULL_PTR == chttp_api)
    {
        CBUFFER               *url_cbuffer;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_start: "
                                                  "no api for %s:'%.*s'\n",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(CHTTP_NODE_ARGS(chttp_node)),
                                                  CBUFFER_DATA(CHTTP_NODE_ARGS(chttp_node)));

        url_cbuffer   = CHTTP_NODE_URL(chttp_node);
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_start: "
                                                  "invalid request %s:'%.*s'\n",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(url_cbuffer),
                                                  CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_NOT_ACCEPTABLE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_commit_start: invalid request %s:'%.*s'",
                                                  chttp_method_str((uint32_t)method),
                                                  CBUFFER_USED(url_cbuffer), CBUFFER_DATA(url_cbuffer));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;

        return crfshttps_commit_end(chttp_node, ret);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_start: "
                                              "api: method %d, name %s\n",
                                              CHTTP_API_METHOD(chttp_api),
                                              CHTTP_API_NAME(chttp_api));

    ret = CHTTP_API_COMMIT(chttp_api)(chttp_node);
    return crfshttps_commit_end(chttp_node, ret);
}

EC_BOOL crfshttps_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result)
{
    EC_BOOL ret;

    ret = result;

    CHTTP_NODE_CROUTINE_NODE(chttp_node) = NULL_PTR; /*clear croutine mounted point*/

    if(EC_DONE == ret)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(NULL_PTR != csocket_cnode)
        {
            CEPOLL *cepoll;
            int     sockfd;

            cepoll = TASK_BRD_CEPOLL(task_brd_default_get());
            sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_end: sockfd %d done, remove all epoll events\n", sockfd);
            cepoll_del_all(cepoll, sockfd);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            /*chttp_node resume for next request handling if keep-alive*/
            chttp_node_wait_resume(chttp_node);

            return (EC_DONE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        CHTTP_NODE_KEEPALIVE(chttp_node) = EC_FALSE;
        chttp_node_free(chttp_node);

        return (EC_FALSE);
    }

    if(EC_FALSE == ret)
    {
        ret = chttps_commit_error_request(chttp_node);
    }

    if(EC_FALSE == ret)
    {
        CSOCKET_CNODE * csocket_cnode;

        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttp_node);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(NULL_PTR != csocket_cnode)
        {
            CEPOLL *cepoll;
            int     sockfd;

            cepoll = TASK_BRD_CEPOLL(task_brd_default_get());
            sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

            dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "[DEBUG] crfshttps_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
            cepoll_del_all(cepoll, sockfd);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            /* umount */
            CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

            csocket_cnode_close(csocket_cnode);

            /*free*/
            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_end: csocket_cnode of chttp_node %p is null\n", chttp_node);

        /*free*/
        chttp_node_free(chttp_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL crfshttps_commit_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
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
EC_BOOL crfshttps_commit_getsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_getsmf_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_getsmf_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_getsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_getsmf_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0007);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_getsmf_request: path %s", (char *)cstring_get_str(&path_cstr));

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

        if(EC_FALSE == crfs_read_e(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &offset, max_len, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_getsmf_request: crfs read %s with offset %u, size %u failed\n",
                                (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_getsmf_request: crfs read %s with offset %u, size %u failed", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_request: crfs read %s with offset %u, size %u done\n",
                            (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_getsmf_request: crfs read %s with offset %u, size %u done", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else/*read whole file content*/
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == crfs_read(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_getsmf_request: crfs read %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_getsmf_request: crfs read %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_request: crfs read %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_getsmf_request: crfs read %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_getsmf_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_getsmf_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_getsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: lock_req ----------------------------------------*/
EC_BOOL crfshttps_commit_lock_req_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_lock_req_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_lock_req_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_lock_req_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

STATIC_CAST static UINT32 __crfshttps_convert_expires_str_to_nseconds(const char *expires_str)
{
    char *str;
    char *fields[2];
    UINT32 seg_num;
    UINT32 expires_nsec;

    str = c_str_dup(expires_str);
    if(NULL_PTR == str)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:__crfshttps_convert_expires_str_to_nseconds: dup str '%s' failed\n", expires_str);
        return ((UINT32)0);
    }

    seg_num = c_str_split(str, ".", fields, 2);
    if(1 == seg_num)
    {
        expires_nsec = c_str_to_word(fields[0]);
        safe_free(str, LOC_CRFSHTTPS_0008);
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

        safe_free(str, LOC_CRFSHTTPS_0009);
        return (expires_nsec);
    }

    safe_free(str, LOC_CRFSHTTPS_0010);
    return ((UINT32)0);
}
EC_BOOL crfshttps_handle_lock_req_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0011);

    cstring_init(&token_cstr, NULL_PTR);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_lock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_lock_req_request: path %s", (char *)cstring_get_str(&path_cstr));

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
        expires_nsec = __crfshttps_convert_expires_str_to_nseconds(expires_str);
        locked_flag  = EC_FALSE;

        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "[DEBUG] crfshttps_handle_lock_req_request: header Expires %s => %ld\n",
                                expires_str, expires_nsec);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == crfs_file_lock(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, expires_nsec, &token_cstr, &locked_flag))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "error:crfshttps_handle_lock_req_request: crfs lock %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            if(EC_TRUE == locked_flag)/*flag was set*/
            {
                cbytes_set(content_cbytes, (UINT8 *)"locked-already:true\r\n", sizeof("locked-already:true\r\n") - 1);
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_lock_req_request: crfs lock %s failed", (char *)cstring_get_str(&path_cstr));
            }
            else /*flag was not set which means some error happen*/
            {
                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_lock_req_request: crfs lock %s failed", (char *)cstring_get_str(&path_cstr));
            }

            cstring_clean(&path_cstr);
            cstring_clean(&token_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_lock_req_request: crfs lock %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_lock_req_request: crfs lock %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    auth_token_header_len = snprintf((char *)auth_token_header, sizeof(auth_token_header),
                                    "auth-token:%.*s\r\n",
                                    (uint32_t)CSTRING_LEN(&token_cstr), (char *)CSTRING_STR(&token_cstr));
    cbytes_set(content_cbytes, auth_token_header, auth_token_header_len);

    cstring_clean(&path_cstr);
    cstring_clean(&token_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_lock_req_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *token_buf;
    uint32_t       token_len;

    /*note: content carry on auth-token info but not response body*/
    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    token_buf      = CBYTES_BUF(content_cbytes);
    token_len      = (uint32_t)CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_lock_req_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_token(chttp_node, token_buf, token_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_response: make response header token failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_lock_req_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: unlock_req ----------------------------------------*/
EC_BOOL crfshttps_commit_unlock_req_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_unlock_req_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_unlock_req_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_unlock_req_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_unlock_req_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0012);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_unlock_req_request: path %s", (char *)cstring_get_str(&path_cstr));

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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT,
                            "error:crfshttps_handle_unlock_req_request: crfs unlock %s failed due to header 'auth-token' absence\n",
                            (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_unlock_req_request: crfs unlock %s failed due to header 'auth-token' absence", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        cstring_set_str(&token_cstr, (const UINT8 *)auth_token_header);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == crfs_file_unlock(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &token_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_unlock_req_request: crfs unlock %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_unlock_req_request: crfs unlock %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_req_request: crfs unlock %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_unlock_req_request: crfs unlock %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_unlock_req_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_unlock_req_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_req_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_req_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_req_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_unlock_req_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: unlock_notify_req ----------------------------------------*/
EC_BOOL crfshttps_commit_unlock_notify_req_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_unlock_notify_req_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_unlock_notify_req_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_unlock_notify_req_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_unlock_notify_req_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0013);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_notify_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_unlock_notify_req_request: path %s", (char *)cstring_get_str(&path_cstr));

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
        if(EC_FALSE == crfs_file_unlock_notify(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_unlock_notify_req_request: crfs unlock_notify %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_unlock_notify_req_request: crfs unlock_notify %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_notify_req_request: crfs unlock_notify %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_unlock_notify_req_request: crfs unlock_notify %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_unlock_notify_req_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_unlock_notify_req_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_notify_req_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_notify_req_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_notify_req_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_unlock_notify_req_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: recycle ----------------------------------------*/
EC_BOOL crfshttps_commit_recycle_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_recycle_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_recycle_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_recycle_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_recycle_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_recycle_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_recycle_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_recycle_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_recycle_request: bad request");

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
        if(EC_FALSE == crfs_recycle(CSOCKET_CNODE_MODI(csocket_cnode), max_num_per_np, &complete_num))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_recycle_request: crfs recycle failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_recycle_request: crfs recycle failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_recycle_request: crfs recycle done\n");

        /*prepare response header*/
        recycle_result_len = snprintf((char *)recycle_result, sizeof(recycle_result), "recycle-completion:%ld\r\n", complete_num);
        cbytes_set(content_cbytes, recycle_result, recycle_result_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_recycle_request: crfs recycle done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_recycle_response(CHTTP_NODE *chttp_node)
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
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_recycle(chttp_node, recycle_result_buf, recycle_result_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_response: make response header recycle failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_recycle_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: flush ----------------------------------------*/
EC_BOOL crfshttps_commit_flush_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_flush_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_flush_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_flush_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_flush_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_flush_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_flush_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_flush_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_flush_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == crfs_flush(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_flush_request: crfs flush failed\n");
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_flush_request: crfs flush failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_flush_request: crfs flush done\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_flush_request: crfs flush done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_flush_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_flush_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_flush_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_flush_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_flush_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: retire ----------------------------------------*/
EC_BOOL crfshttps_commit_retire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_retire_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_retire_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_retire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_retire_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    char          *retire_files_str;

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_retire_request\n");

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_retire_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_retire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_retire_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_retire_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    cbytes_clean(content_cbytes);

    retire_files_str   = chttp_node_get_header(chttp_node, (const char *)"retire-files");
    if(NULL_PTR == retire_files_str) /*invalid retire request*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_retire_request: http header 'retire-files' absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_retire_request: http header 'retire-files' absence");

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

        if(EC_FALSE == crfs_retire(CSOCKET_CNODE_MODI(csocket_cnode), retire_files, &complete_num))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_retire_request: crfs retire with expect retire num %ld failed\n",
                                retire_files);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_retire_request: crfs retire with expect retire num %ld failed",
                                retire_files);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;
            return (EC_TRUE);
        }

        /*prepare response header*/
        retire_result_len = snprintf((char *)retire_result, sizeof(retire_result), "retire-completion:%ld\r\n", complete_num);
        cbytes_set(content_cbytes, retire_result, retire_result_len);

        dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_retire_request: crfs retire with expect retire %ld, complete %ld done\n",
                            retire_files, complete_num);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_retire_request: crfs retire with expect retire %ld, complete %ld done",
                            retire_files, complete_num);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_retire_response(CHTTP_NODE *chttp_node)
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
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_retire(chttp_node, retire_result_buf, retire_result_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_response: make response header retire failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_retire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: breathe ----------------------------------------*/
EC_BOOL crfshttps_commit_breathe_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_breathe_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_breathe_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_breathe_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_breathe_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_breathe_request\n");

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_breathe_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_breathe_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_breathe_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_breathe_request: bad request");

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

        dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_breathe_request: memory breathing done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_breathe_request: memory breathing done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_breathe_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_breathe_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_breathe_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_breathe_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_breathe_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: setsmf ----------------------------------------*/
EC_BOOL crfshttps_commit_setsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_setsmf_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_setsmf_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_setsmf_request: make response done\n");

    ret = crfshttps_commit_setsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}


EC_BOOL crfshttps_handle_setsmf_request(CHTTP_NODE *chttp_node)
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
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                                                 CBUFFER_DATA(uri_cbuffer),
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_setsmf_request: path %.*s, invalid content length %"PRId64,
                        (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                        (char *)(CBUFFER_DATA(uri_cbuffer)),content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0014);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_setsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttp_node_recv_len(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_setsmf_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_setsmf_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:crfshttps_handle_setsmf_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_setsmf_request: new cbytes without buff failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_setsmf_request: export body with len %ld to cbytes failed", (UINT32)body_len);

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
        if(EC_FALSE == crfs_write(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_request: crfs write %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_setsmf_request: crfs write %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_setsmf_request: crfs write %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_setsmf_request: crfs write %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_write_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_request: crfs write %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_setsmf_request: crfs write %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_setsmf_request: crfs write %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_setsmf_request: crfs write %s done", (char *)cstring_get_str(&path_cstr));
#endif
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_setsmf_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_setsmf_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_setsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_setsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_setsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: update ----------------------------------------*/
EC_BOOL crfshttps_commit_update_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_update_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_update_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_update_request: make response done\n");

    ret = crfshttps_commit_update_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_update_request(CHTTP_NODE *chttp_node)
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
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(!((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                                                 CBUFFER_DATA(uri_cbuffer),
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_update_request: path %.*s, invalid content length %"PRId64,
                        (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                        (char *)(CBUFFER_DATA(uri_cbuffer)),content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0016);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_update_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttp_node_recv_len(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_update_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_update_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:crfshttps_handle_update_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_update_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_update_request: export body with len %ld to cbytes failed", (UINT32)body_len);

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
        if(EC_FALSE == crfs_update(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_request: crfs update %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_update_request: crfs update %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_update_request: crfs update %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_update_request: crfs update %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_update_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_request: crfs update %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_update_request: crfs update %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
#endif
    }

    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_update_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_update_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_update_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_update_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_update_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: renew ----------------------------------------*/
EC_BOOL crfshttps_commit_renew_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_renew_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_renew_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_renew_request: make response done\n");

    ret = crfshttps_commit_renew_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_renew_request(CHTTP_NODE *chttp_node)
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
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                                                 CBUFFER_DATA(uri_cbuffer),
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_renew_request: path %.*s, invalid content length %"PRId64,
                        (uint32_t)(CBUFFER_USED(uri_cbuffer)),
                        (char *)(CBUFFER_DATA(uri_cbuffer)),content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer);
    cache_len = CBUFFER_USED(uri_cbuffer);

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0017);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttp_node_recv_len(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_renew_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_renew_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:crfshttps_handle_renew_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_request: new cbytes without buff failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_request: export body with len %ld to cbytes failed", (UINT32)body_len);

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
        if(EC_FALSE == crfs_renew(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_request: crfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_request: crfs renew %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_renew_request: crfs renew %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_renew_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_request: crfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
#endif
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_renew_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_renew_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: dsmf ----------------------------------------*/
EC_BOOL crfshttps_commit_dsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_dsmf_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_dsmf_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_dsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_dsmf_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0018);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_dsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_dsmf_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
#if 1
        if(EC_FALSE == crfs_delete(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_REG))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_dsmf_request: crfs delete file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_dsmf_request: crfs delete file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_dsmf_request: crfs delete file %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_dsmf_request: crfs delete file %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_delete_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_REG, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_dsmf_request: crfs delete file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_dsmf_request: crfs delete file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
#endif
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_dsmf_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_dsmf_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_dsmf_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_dsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_dsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_dsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ddir ----------------------------------------*/
EC_BOOL crfshttps_commit_ddir_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_ddir_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_ddir_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_ddir_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_ddir_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0019);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_ddir_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_ddir_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
#if 1
        if(EC_FALSE == crfs_delete(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_DIR))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_ddir_request: crfs delete dir %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_ddir_request: crfs delete dir %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_ddir_request: crfs delete dir %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_ddir_request: crfs delete dir %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_delete_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_DIR, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_ddir_request: crfs delete dir %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_ddir_request: crfs delete dir %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
#endif
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_ddir_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_ddir_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_ddir_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_ddir_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_ddir_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_ddir_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: sexpire ----------------------------------------*/
EC_BOOL crfshttps_commit_sexpire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_sexpire_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_sexpire_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_sexpire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_sexpire_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0020);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_sexpire_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_sexpire_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(1)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == crfs_file_expire(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_sexpire_request: crfs exipre file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_sexpire_request: crfs exipre file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_sexpire_request: crfs exipre file %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_sexpire_request: crfs exipre file %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_sexpire_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_sexpire_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_sexpire_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_sexpire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_sexpire_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_sexpire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mexpire ----------------------------------------*/
EC_BOOL crfshttps_commit_mexpire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_mexpire_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_mexpire_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mexpire_request: make response done\n");

    ret = crfshttps_commit_mexpire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_mexpire_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_mexpire_request: invalid content length %"PRId64, content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttp_node_recv_len(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_mexpire_request: invalid body length %"PRId64, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_mexpire_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:crfshttps_handle_mexpire_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "info:crfshttps_handle_mexpire_request: request body is empty\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "info:crfshttps_handle_mexpire_request: request body is empty");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mexpire_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mexpire_request: export body with len %ld to cbytes failed", (UINT32)body_len);

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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mexpire_request: bad request %.*s",
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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_request: path is null at %ld\n", idx);

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

            if(EC_FALSE == crfs_file_expire(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_request: crfs expire %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mexpire_request: crfs expire %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_mexpire_request: crfs expire %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_mexpire_request: crfs expire %s done", (char *)cstring_get_str(&path_cstr));

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
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_mexpire_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_mexpire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mdsmf ----------------------------------------*/
EC_BOOL crfshttps_commit_mdsmf_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_mdsmf_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_mdsmf_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mdsmf_request: make response done\n");

    ret = crfshttps_commit_mdsmf_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_mdsmf_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_mdsmf_request: invalid content length %"PRId64, content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttp_node_recv_len(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_mdsmf_request: invalid body length %"PRId64, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_mdsmf_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:crfshttps_handle_mdsmf_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "info:crfshttps_handle_mdsmf_request: request body is empty\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "info:crfshttps_handle_mdsmf_request: request body is empty");
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mdsmf_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mdsmf_request: export body with len %ld to cbytes failed", (UINT32)body_len);

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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mdsmf_request: bad request %.*s",
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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_request: path is null at %ld\n", idx);

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

            if(EC_FALSE == crfs_delete(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_REG))
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_request: crfs delete %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mdsmf_request: crfs delete %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_mdsmf_request: crfs delete %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_mdsmf_request: crfs delete %s done", (char *)cstring_get_str(&path_cstr));

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
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_mdsmf_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_mdsmf_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mddir ----------------------------------------*/
EC_BOOL crfshttps_commit_mddir_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_mddir_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_mddir_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_request: make response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mddir_request: make response done\n");

    ret = crfshttps_commit_mddir_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_mddir_request(CHTTP_NODE *chttp_node)
{
    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    content_len  = CHTTP_NODE_CONTENT_LENGTH(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_mddir_request: invalid content length %"PRId64, content_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttp_node_recv_len(chttp_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_mddir_request: invalid body length %"PRId64, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_mddir_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_PARTIAL_CONTENT);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "warn:crfshttps_handle_mddir_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "info:crfshttps_handle_mddir_request: request body is empty\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "info:crfshttps_handle_mddir_request: request body is empty");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_request: new cbytes without buff failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INSUFFICIENT_STORAGE);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mddir_request: new cbytes with len zero failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttp_node_recv_export_to_cbytes(chttp_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mddir_request: export body with len %ld to cbytes failed", (UINT32)body_len);

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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mddir_request: bad request %.*s",
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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_request: path is null at %ld\n", idx);

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

            if(EC_FALSE == crfs_delete(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_DIR))
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_request: crfs delete %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_mddir_request: crfs delete %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_mddir_request: crfs delete %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_mddir_request: crfs delete %s done", (char *)cstring_get_str(&path_cstr));

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
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_mddir_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_mddir_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: logrotate ----------------------------------------*/
EC_BOOL crfshttps_commit_logrotate_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_logrotate_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_logrotate_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_logrotate_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_logrotate_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_logrotate_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_logrotate_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_logrotate_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_logrotate_request: bad request");

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                return (EC_TRUE);
            }

            dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_logrotate_request: log rotate %ld done\n", log_index);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_logrotate_request: log rotate %ld done", log_index);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

            return (EC_TRUE);
        }

        /*else*/
        log_index_str_t = c_str_dup(log_index_str);
        if(NULL_PTR == log_index_str_t)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_logrotate_request: no memory\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_logrotate_request: no memory");

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_logrotate_request: log rotate %ld failed\n", log_index);

                CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
                CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "XFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_logrotate_request: log rotate %ld failed", log_index);

                CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

                c_str_free(log_index_str_t);

                return (EC_TRUE);
            }
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_logrotate_request: log rotate %s done\n", log_index_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_logrotate_request: log rotate %s done", log_index_str);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        c_str_free(log_index_str_t);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_logrotate_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_logrotate_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_logrotate_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_logrotate_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_logrotate_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: actsyscfg ----------------------------------------*/
EC_BOOL crfshttps_commit_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_actsyscfg_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_actsyscfg_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_actsyscfg_response(chttp_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_actsyscfg_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_actsyscfg_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_actsyscfg_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_actsyscfg_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_actsyscfg_request: bad request");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(1)
    {
        UINT32 super_md_id;

        super_md_id = 0;

        super_activate_sys_cfg(super_md_id);

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_actsyscfg_request done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_actsyscfg_request done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_actsyscfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_actsyscfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_actsyscfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_actsyscfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: qtree ----------------------------------------*/
EC_BOOL crfshttps_commit_qtree_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_qtree_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_qtree_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_qtree_response(chttp_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_qtree_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path, cache_len, cache_key, LOC_CRFSHTTPS_0021);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_qtree_request: path %s\n", (char *)cstring_get_str(&path));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_request: path %s\n", (char *)cstring_get_str(&path));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_qtree_request: bad request: path %s", (char *)cstring_get_str(&path));

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

        super_md_id = 0;

        path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_CRFSHTTPS_0022);

        if(EC_FALSE == crfs_qlist_tree(super_md_id, &path, path_cstr_vec))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_qtree_request failed\n");

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_qtree_request failed");

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path);

            cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CRFSHTTPS_0023);
            cvector_free(path_cstr_vec, LOC_CRFSHTTPS_0024);

            return (EC_TRUE);
        }

        /* qtree success, get path from path_cstr_vec */

        rsp_content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
        cbytes_clean(rsp_content_cbytes);

        rsp_body_obj = json_object_new_array();

        UINT32 pos;
        CSTRING *path_cstr;

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

        dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_qtree_request done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_qtree_request done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        cstring_clean(&path);

        cvector_free(path_cstr_vec, LOC_CRFSHTTPS_0025);

        /* free json obj */
        json_object_put(rsp_body_obj);

    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_qtree_response(CHTTP_NODE *chttp_node)
{

    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_qtree_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_qtree_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_qtree_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_qtree_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: file_notify ----------------------------------------*/
EC_BOOL crfshttps_commit_file_notify_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_file_notify_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_file_notify_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_file_notify_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_file_notify_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0026);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_notify_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_file_notify_request: path %s", (char *)cstring_get_str(&path_cstr));

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
        if(EC_FALSE == crfs_file_notify(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_file_notify_request: crfs notify %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_NOT_FOUND);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_file_notify_request: crfs notify %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_notify_request: crfs notify %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_file_notify_request: crfs notify %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_file_notify_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_file_notify_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_notify_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_notify_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_notify_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_file_notify_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: cond_wakeup ----------------------------------------*/
EC_BOOL crfshttps_commit_cond_wakeup_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_cond_wakeup_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_cond_wakeup_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_cond_wakeup_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_cond_wakeup_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0027);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_cond_wakeup_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_cond_wakeup_request: path %s", (char *)cstring_get_str(&path_cstr));

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

        tag = MD_CRFS;

        //csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == super_cond_wakeup(/*CSOCKET_CNODE_MODI(csocket_cnode)*/0, tag, &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_cond_wakeup_request: cond wakeup %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_cond_wakeup_request: cond wakeup %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_cond_wakeup_request: cond wakeup %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_cond_wakeup_request: cond wakeup %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_cond_wakeup_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_cond_wakeup_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_cond_wakeup_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_cond_wakeup_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_cond_wakeup_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_cond_wakeup_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: renew_header ----------------------------------------*/
EC_BOOL crfshttps_commit_renew_header_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_renew_header_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_renew_header_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_renew_header_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_renew_header_request(CHTTP_NODE *chttp_node)
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
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0028);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error: crfshttps_handle_renew_header_request: path %s", (char *)cstring_get_str(&path_cstr));

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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to 'renew-key' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to 'renew-key' absence", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        renew_val  = chttp_node_get_header(chttp_node, (const char *)"renew-val");
        if(NULL_PTR == renew_val)
        {
#if 1
            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_request: crfs renew %s would remove header ['%s'] due to 'renew-val' absence\n",
                                (char *)cstring_get_str(&path_cstr), renew_key);
#endif
#if 0
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to 'renew-val' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to 'renew-val' absence", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        cstring_set_str(&renew_key_cstr, (UINT8 *)renew_key);
        cstring_set_str(&renew_val_cstr, (UINT8 *)renew_val);

        if(EC_FALSE == crfs_renew_http_header(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &renew_key_cstr, &renew_val_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_request: crfs renew %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_renew_header_request: crfs renew %s done", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    cstrkv_mgr = cstrkv_mgr_new();
    if(NULL_PTR == cstrkv_mgr)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to new cstrkv_mgr failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to new cstrkv_mgr failed",
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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)renew_key_tag);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to '%s' absence",
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
            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_request: crfs renew %s would remove header ['%s'] due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), renew_key, (char *)renew_val_tag);
#endif
#if 0
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)renew_val_tag);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to '%s' absence",
                    (char *)cstring_get_str(&path_cstr), (char *)renew_val_tag);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        if(EC_FALSE == cstrkv_mgr_add_kv_str(cstrkv_mgr, renew_key, renew_val))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to add '%s:%s' failed\n",
                                (char *)cstring_get_str(&path_cstr), renew_key, renew_val);

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed due to add '%s:%s' failed",
                    (char *)cstring_get_str(&path_cstr), renew_key, renew_val);

            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
    }

    if(EC_FALSE == crfs_renew_http_headers(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, cstrkv_mgr))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_request: crfs renew %s failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_renew_header_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_request: crfs renew %s done\n",
                        (char *)cstring_get_str(&path_cstr));

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_renew_header_request: crfs renew %s done", (char *)cstring_get_str(&path_cstr));

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    cstrkv_mgr_free(cstrkv_mgr);
    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_renew_header_response(CHTTP_NODE *chttp_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTP_NODE_URI(chttp_node);
        cache_key = CBUFFER_DATA(uri_cbuffer);
        cache_len = CBUFFER_USED(uri_cbuffer);

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_renew_header_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_header_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_header_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_header_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_renew_header_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: locked_file_retire ----------------------------------------*/
EC_BOOL crfshttps_commit_locked_file_retire_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_locked_file_retire_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_locked_file_retire_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_locked_file_retire_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_locked_file_retire_request(CHTTP_NODE *chttp_node)
{
    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    req_body_chunk_num = chttp_node_recv_chunks_num(chttp_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttp_node_recv_chunks(chttp_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_locked_file_retire_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_locked_file_retire_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_locked_file_retire_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_ERR %u --", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_locked_file_retire_request");

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

        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "[DEBUG] crfshttps_handle_locked_file_retire_request: header retire-max-num %s => %ld\n",
                                retire_max_num_str, retire_max_num);

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        if(EC_FALSE == crfs_locked_file_retire(CSOCKET_CNODE_MODI(csocket_cnode), retire_max_num, &retire_num))
        {
            CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;

            CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
            CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_FAIL %u --", CHTTP_FORBIDDEN);
            CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:crfshttps_handle_locked_file_retire_request failed");

            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_locked_file_retire_request: complete %ld\n", retire_num);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u --", CHTTP_OK);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_locked_file_retire_request: complete %ld", retire_num);

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

        /*prepare response header*/
        cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (char *)"retire-completion", c_word_to_str(retire_num));
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_locked_file_retire_response(CHTTP_NODE *chttp_node)
{
    if(EC_FALSE == chttp_make_response_header_common(chttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_kvs(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_locked_file_retire_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: paracfg ----------------------------------------*/
EC_BOOL crfshttps_commit_paracfg_request(CHTTP_NODE *chttp_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_paracfg_request(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_paracfg_request: handle request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_paracfg_response(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_paracfg_request: make response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_paracfg_response(chttp_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_paracfg_request: commit response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_paracfg_request(CHTTP_NODE *chttp_node)
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

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_paracfg_request: done\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "RFS_SUCC %u %ld", CHTTP_OK, CBYTES_LEN(rsp_content_cbytes));
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] crfshttps_handle_paracfg_request: done");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_paracfg_response(CHTTP_NODE *chttp_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTP_NODE_CONTENT_CBYTES(chttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttp_make_response_header_common(chttp_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_paracfg_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
    {
        if(EC_FALSE == chttp_make_response_header_keepalive(chttp_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_paracfg_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttp_make_response_header_end(chttp_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_paracfg_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttp_make_response_body_ext(chttp_node,
                                              (uint8_t *)CBYTES_BUF(content_cbytes),
                                              (uint32_t )CBYTES_LEN(content_cbytes),
                                              (uint32_t )CBYTES_ALIGNED(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_paracfg_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_paracfg_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_paracfg_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttp_node);
}
#endif


#ifdef __cplusplus
}
#endif/*__cplusplus*/

