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
#include "chttps.inc"
#include "chttps.h"
#include "cngx_https.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "findex.inc"


#if 0
#define CNGX_HTTPS_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0056_CNGX_HTTPS, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CNGX_HTTPS_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0056_CNGX_HTTPS, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CNGX_HTTPS_PRINT_UINT8(info, buff, len) do{}while(0)
#define CNGX_HTTPS_PRINT_CHARS(info, buff, len) do{}while(0)
#endif



#if 1
#define CNGX_HTTPS_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

#if 0
#define CNGX_HTTPS_ASSERT(condition) do{}while(0)
#endif

#if 1
//#define CNGX_HTTPS_TIME_COST_FORMAT " BegTime:%u.%03u EndTime:%u.%03u Elapsed:%u "
#define CNGX_HTTPS_TIME_COST_FORMAT " %u.%03u %u.%03u %u "
#define CNGX_HTTPS_TIME_COST_VALUE(chttps_node)  \
    (uint32_t)CTMV_NSEC(CHTTPS_NODE_START_TMV(chttps_node)), (uint32_t)CTMV_MSEC(CHTTPS_NODE_START_TMV(chttps_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTPS_NODE_START_TMV(chttps_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTPS_NODE_START_TMV(chttps_node)))
#endif

static EC_BOOL g_cngx_https_log_init = EC_FALSE;

EC_BOOL cngx_https_log_start()
{
    TASK_BRD        *task_brd;

    if(EC_TRUE == g_cngx_https_log_init)
    {
        return (EC_TRUE);
    }

    g_cngx_https_log_init = EC_TRUE;

    task_brd = task_brd_default_get();

#if 0/*support rotate*/
    if(EC_TRUE == task_brd_check_is_work_tcid(TASK_BRD_TCID(task_brd)))
    {
        CSTRING *log_file_name;

        log_file_name = cstring_new(NULL_PTR, LOC_CNGX_0068);
        cstring_format(log_file_name, "%s/ngx_%s_%ld.log",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        if(EC_FALSE == user_log_open(LOGUSER08, (char *)cstring_get_str(log_file_name), "a+"))/*append mode. scenario: after restart*/
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_log_start: user_log_open '%s' -> LOGUSER08 failed\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CNGX_0069);
        cstring_format(log_file_name, "%s/ngx_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED, SWITCH_OFF,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_log_start: log_file_open '%s' -> LOGUSER08 failed\n",
                               (char *)cstring_get_str(log_file_name));
            cstring_free(log_file_name);
            /*task_brd_default_abort();*/
        }
        else
        {
            sys_log_redirect_setup(LOGUSER08, log);

            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "[DEBUG] cngx_https_log_start: log_file_open '%s' -> LOGUSER08 done\n",
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
        log_file_name = cstring_new(NULL_PTR, LOC_CNGX_0070);
        cstring_format(log_file_name, "%s/debug_%s_%ld",
                        (char *)TASK_BRD_LOG_PATH_STR(task_brd),
                        c_word_to_ipv4(TASK_BRD_TCID(task_brd)),
                        TASK_BRD_RANK(task_brd));
        log = log_file_open((char *)cstring_get_str(log_file_name), "a+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED, SWITCH_OFF,
                            LOGD_SWITCH_OFF_ENABLE, LOGD_PID_INFO_ENABLE);
        if(NULL_PTR == log)
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_log_start: log_file_open '%s' -> LOGUSER07 failed\n",
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
EC_BOOL cngx_https_commit_request(CHTTPS_NODE *chttps_node)
{
    http_parser_t *http_parser;

    http_parser = CHTTPS_NODE_PARSER(chttps_node);

    if(HTTP_GET == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)cngx_https_commit_http_get, 1, chttps_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_request: cthread load for HTTP_GET failed\n");
            return (EC_BUSY);
        }
        CHTTPS_NODE_LOG_TIME_WHEN_LOADED(chttps_node);/*record http request was loaded time in coroutine*/
        CHTTPS_NODE_CROUTINE_NODE(chttps_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CNGX_0071);

        return (EC_TRUE);
    }

    if(HTTP_POST == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)cngx_https_commit_http_post, 1, chttps_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_request: cthread load for HTTP_POST failed\n");
            return (EC_BUSY);
        }
        CHTTPS_NODE_LOG_TIME_WHEN_LOADED(chttps_node);/*record http request was loaded time in coroutine*/
        CHTTPS_NODE_CROUTINE_NODE(chttps_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CNGX_0072);

        return (EC_TRUE);
    }

    if(HTTP_HEAD == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)cngx_https_commit_http_head, 1, chttps_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_request: cthread load for HTTP_HEAD failed\n");
            return (EC_BUSY);
        }
        CHTTPS_NODE_LOG_TIME_WHEN_LOADED(chttps_node);/*record http request was loaded time in coroutine*/
        CHTTPS_NODE_CROUTINE_NODE(chttps_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CNGX_0073);

        return (EC_TRUE);
    }

    dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_request: not support http method %d yet\n", http_parser->method);
    return (EC_FALSE);/*note: this chttps_node must be discarded*/
}

EC_BOOL cngx_https_commit_http_head(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    CHTTPS_NODE_LOG_TIME_WHEN_HANDLE(chttps_node);

    if(0)
    {
        /*do nothing*/
    }
    else
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_http_head: invalid uri %.*s\n",
                        CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        ret = EC_FALSE;
    }

    return cngx_https_commit_end(chttps_node, ret);
}

EC_BOOL cngx_https_commit_http_post(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    CHTTPS_NODE_LOG_TIME_WHEN_HANDLE(chttps_node);

    if(0)
    {
        /*do nothing*/
    }
    else
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_http_post: invalid uri %.*s\n",
                        CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        ret = EC_FALSE;
    }

    return cngx_https_commit_end(chttps_node, ret);
}

EC_BOOL cngx_https_commit_http_get(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_commit_http_get: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(CHTTPS_NODE_URI(chttps_node)),
                        CBUFFER_DATA(CHTTPS_NODE_URI(chttps_node)),
                        CBUFFER_USED(CHTTPS_NODE_URI(chttps_node)));

    CHTTPS_NODE_LOG_TIME_WHEN_HANDLE(chttps_node);


    if (EC_TRUE == cngx_https_is_http_get_breathe(chttps_node))
    {
        ret = cngx_https_commit_breathe_get_request(chttps_node);
    }
    else if (EC_TRUE == cngx_https_is_http_get_logrotate(chttps_node))
    {
        ret = cngx_https_commit_logrotate_get_request(chttps_node);
    }
    else if (EC_TRUE == cngx_https_is_http_get_actsyscfg(chttps_node))
    {
        ret = cngx_https_commit_actsyscfg_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_xfs_up(chttps_node))
    {
        ret = cngx_https_commit_xfs_up_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_xfs_down(chttps_node))
    {
        ret = cngx_https_commit_xfs_down_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_xfs_add(chttps_node))
    {
        ret = cngx_https_commit_xfs_add_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_xfs_del(chttps_node))
    {
        ret = cngx_https_commit_xfs_del_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_xfs_list(chttps_node))
    {
        ret = cngx_https_commit_xfs_list_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_rfs_up(chttps_node))
    {
        ret = cngx_https_commit_rfs_up_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_rfs_down(chttps_node))
    {
        ret = cngx_https_commit_rfs_down_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_rfs_add(chttps_node))
    {
        ret = cngx_https_commit_rfs_add_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_rfs_del(chttps_node))
    {
        ret = cngx_https_commit_rfs_del_get_request(chttps_node);
    }
    else if (SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH
    && EC_TRUE == cngx_https_is_http_get_rfs_list(chttps_node))
    {
        ret = cngx_https_commit_rfs_list_get_request(chttps_node);
    }
    else
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_http_get: invalid uri %.*s\n",
                            CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_NOT_ACCEPTABLE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_commit_http_get: invalid uri %.*s",
                            CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;
    }

    return cngx_https_commit_end(chttps_node, ret);
}

EC_BOOL cngx_https_commit_end(CHTTPS_NODE *chttps_node, EC_BOOL result)
{
    EC_BOOL ret;

    ret = result;

    CHTTPS_NODE_CROUTINE_NODE(chttps_node) = NULL_PTR; /*clear croutine mounted point*/

    if(EC_DONE == ret)
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(NULL_PTR != csocket_cnode)
        {
            CEPOLL *cepoll;
            int     sockfd;

            cepoll = TASK_BRD_CEPOLL(task_brd_default_get());
            sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

            dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_commit_end: sockfd %d done, remove all epoll events\n", sockfd);
            cepoll_del_all(cepoll, sockfd);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            /*chttps_node resume for next request handling if keep-alive*/
            chttps_node_wait_resume(chttps_node);

            return (EC_DONE);
        }

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_end: csocket_cnode of chttps_node %p is null\n", chttps_node);

        CHTTPS_NODE_KEEPALIVE(chttps_node) = EC_FALSE;
        chttps_node_free(chttps_node);

        return (EC_FALSE);
    }

    if(EC_FALSE == ret)
    {
        ret = chttps_commit_error_request(chttps_node);
    }

    if(EC_FALSE == ret)
    {
        CSOCKET_CNODE * csocket_cnode;

        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttps_node);

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(NULL_PTR != csocket_cnode)
        {
            CEPOLL *cepoll;
            int     sockfd;

            cepoll = TASK_BRD_CEPOLL(task_brd_default_get());
            sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
            cepoll_del_all(cepoll, sockfd);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            /* umount */
            CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

            csocket_cnode_close(csocket_cnode);

            /*free*/
            chttps_node_free(chttps_node);
            return (EC_FALSE);
        }

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_end: csocket_cnode of chttps_node %p is null\n", chttps_node);

        /*free*/
        chttps_node_free(chttps_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL cngx_https_commit_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    ret = chttps_node_send_rsp(chttps_node, csocket_cnode);
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
STATIC_CAST static EC_BOOL __cngx_https_uri_is_breathe_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/breathe") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/breathe")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_breathe(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_breathe: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_breathe_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_breathe_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_breathe_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_breathe_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_breathe_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_breathe_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_breathe_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_breathe_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_breathe_get_request(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_handle_breathe_get_request\n");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_breathe_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_breathe_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_breathe_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_breathe_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(1)
    {
        //CSOCKET_CNODE * csocket_cnode;

        //csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        breathing_static_mem();

        dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_handle_breathe_get_request: memory breathing done\n");

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_breathe_get_request: memory breathing done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_breathe_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_breathe_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_breathe_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_breathe_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_breathe_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_breathe_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: logrotate ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_logrotate_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/logrotate") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/logrotate")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_logrotate(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_logrotate: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_logrotate_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_logrotate_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_logrotate_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_logrotate_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_logrotate_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_logrotate_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_logrotate_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_logrotate_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_logrotate_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    //uint8_t       *cache_key;
    //uint32_t       cache_len;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    //cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/logrotate");
    //cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/logrotate");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_logrotate_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_logrotate_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_logrotate_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_logrotate_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(EC_TRUE == __cngx_https_uri_is_logrotate_get_op(uri_cbuffer))
    {
        //CSOCKET_CNODE * csocket_cnode;
        UINT32 super_md_id;

        char  *log_index_str;
        UINT32 log_index;

        super_md_id = 0;
        //csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        log_index_str = chttps_node_get_header(chttps_node, (const char *)"log-index");
        if(NULL_PTR != log_index_str)
        {
            log_index = c_str_to_word(log_index_str);
        }
        else
        {
            log_index = DEFAULT_USRER08_LOG_INDEX; /*default LOGUSER08*/
        }

        if(EC_FALSE == super_rotate_log(super_md_id, log_index))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_handle_logrotate_get_request: log rotate %ld failed\n", log_index);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_logrotate_get_request: log rotate %ld failed", log_index);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0056_CNGX_HTTPS, 5)(LOGSTDOUT, "[DEBUG] cngx_https_handle_logrotate_get_request: log rotate %ld done\n", log_index);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_logrotate_get_request: log rotate %ld done", log_index);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_logrotate_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_logrotate_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_logrotate_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_logrotate_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_logrotate_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_logrotate_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: actsyscfg ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_actsyscfg_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/actsyscfg") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/actsyscfg")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_actsyscfg(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_actsyscfg: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_actsyscfg_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_actsyscfg_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_actsyscfg_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_actsyscfg_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_actsyscfg_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_actsyscfg_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_actsyscfg_get_response(chttps_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_actsyscfg_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_actsyscfg_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    //uint8_t       *cache_key;
    //uint32_t       cache_len;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    //cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/actsyscfg");
    //cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/actsyscfg");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_actsyscfg_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_actsyscfg_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_actsyscfg_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_actsyscfg_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(EC_TRUE == __cngx_https_uri_is_actsyscfg_get_op(uri_cbuffer))
    {
        UINT32 super_md_id;

        super_md_id = 0;

        super_activate_sys_cfg(super_md_id);

        dbg_log(SEC_0056_CNGX_HTTPS, 5)(LOGSTDOUT, "[DEBUG] cngx_https_handle_actsyscfg_get_request done\n");

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_actsyscfg_get_request done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_actsyscfg_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_actsyscfg_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_actsyscfg_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_actsyscfg_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_actsyscfg_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_actsyscfg_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_up ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_xfs_up_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/xfs_up") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/xfs_up")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_xfs_up(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_xfs_up: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_xfs_up_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_xfs_up_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_xfs_up_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_up_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_xfs_up_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_up_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_xfs_up_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_up_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_xfs_up_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_up_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_up_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_up_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_up_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_xfs_up_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_up_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;/*useless*/

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_up_get_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_up_get_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_up_get_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_up_get_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_up_get_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_up_get_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_set_node_up(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_up_get_request: set up xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_up_get_request: set up xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_xfs_up_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_up_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_up_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_up_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_xfs_up_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_up_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_down ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_xfs_down_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/xfs_down") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/xfs_down")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_xfs_down(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_xfs_down: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_xfs_down_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_xfs_down_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_xfs_down_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_down_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_xfs_down_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_down_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_xfs_down_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_down_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_xfs_down_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_down_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_down_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_down_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_down_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_xfs_down_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_down_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_DOWN;/*useless*/

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_down_get_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_down_get_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_down_get_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_down_get_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_down_get_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_down_get_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_set_node_down(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_down_get_request: set down xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_down_get_request: set down xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_xfs_down_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_down_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_down_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_down_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_xfs_down_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_down_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_add ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_xfs_add_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/xfs_add") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/xfs_add")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_xfs_add(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_xfs_add: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_xfs_add_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_xfs_add_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_xfs_add_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_add_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_xfs_add_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_add_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_xfs_add_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_add_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_xfs_add_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_add_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_add_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_add_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_add_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_xfs_add_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_add_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_add_get_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_add_get_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_add_get_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_add_get_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_add_get_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_add_get_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_add_node(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_add_get_request: add xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_add_get_request: add xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_xfs_add_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_add_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_add_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_add_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_xfs_add_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_add_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_del ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_xfs_del_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/xfs_del") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/xfs_del")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_xfs_del(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_xfs_del: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_xfs_del_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_xfs_del_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_xfs_del_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_del_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_xfs_del_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_del_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_xfs_del_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_del_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_xfs_del_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_del_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_del_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_del_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_del_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_xfs_del_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_del_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_del_get_request: invalid xfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_del_get_request: header xfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_del_get_request: invalid xfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_del_get_request: header xfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_del_get_request: header xfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"xfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_xfs_del_get_request: header xfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_del_node(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_del_get_request: del xfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_del_get_request: del xfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_xfs_del_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_del_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_del_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_del_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_xfs_del_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_del_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: xfs_list ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_xfs_list_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/xfs_list") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/xfs_list")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_xfs_list(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_xfs_list: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_xfs_list_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_xfs_list_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_xfs_list_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_list_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_xfs_list_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_list_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_xfs_list_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_list_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_xfs_list_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_list_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_list_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_xfs_list_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_list_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_xfs_list_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        CSTRING      cxfs_list_cstr;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_xfs_list_get_request: no cmon start");

            return (EC_TRUE);
        }

        cstring_init(&cxfs_list_cstr, NULL_PTR);

        cmon_list_nodes(cmon_id, &cxfs_list_cstr);

        cbytes_mount(content_cbytes, CSTRING_LEN(&cxfs_list_cstr), CSTRING_STR(&cxfs_list_cstr));
        cstring_unset(&cxfs_list_cstr);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "XFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_xfs_list_get_request: list xfs done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_xfs_list_get_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_list_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_list_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_list_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_xfs_list_get_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_xfs_list_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_xfs_list_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: rfs_up ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_rfs_up_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/rfs_up") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/rfs_up")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_rfs_up(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_rfs_up: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_rfs_up_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_rfs_up_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_rfs_up_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_up_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_rfs_up_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_up_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_rfs_up_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_up_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_rfs_up_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_up_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_up_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_up_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_up_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_rfs_up_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_up_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;/*useless*/

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_up_get_request: invalid rfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_up_get_request: header rfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_up_get_request: invalid rfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_up_get_request: header rfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_up_get_request: header rfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_up_get_request: header rfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_set_node_up(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_up_get_request: set up rfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_up_get_request: set up rfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_rfs_up_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_up_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_up_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_up_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_rfs_up_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_up_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: rfs_down ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_rfs_down_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/rfs_down") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/rfs_down")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_rfs_down(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_rfs_down: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_rfs_down_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_rfs_down_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_rfs_down_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_down_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_rfs_down_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_down_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_rfs_down_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_down_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_rfs_down_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_down_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_down_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_down_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_down_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_rfs_down_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_down_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_DOWN;/*useless*/

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_down_get_request: invalid rfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_down_get_request: header rfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_down_get_request: invalid rfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_down_get_request: header rfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_down_get_request: header rfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_down_get_request: header rfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_set_node_down(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_down_get_request: set down rfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_down_get_request: set down rfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_rfs_down_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_down_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_down_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_down_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_rfs_down_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_down_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: rfs_add ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_rfs_add_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/rfs_add") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/rfs_add")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_rfs_add(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_rfs_add: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_rfs_add_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_rfs_add_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_rfs_add_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_add_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_rfs_add_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_add_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_rfs_add_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_add_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_rfs_add_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_add_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_add_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_add_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_add_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_rfs_add_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_add_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/
        CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_add_get_request: invalid rfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_add_get_request: header rfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_add_get_request: invalid rfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_add_get_request: header rfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_add_get_request: header rfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_add_get_request: header rfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_add_node(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_add_get_request: add rfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_add_get_request: add rfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_rfs_add_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_add_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_add_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_add_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_rfs_add_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_add_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: rfs_del ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_rfs_del_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/rfs_del") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/rfs_del")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_rfs_del(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_rfs_del: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_rfs_del_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_rfs_del_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_rfs_del_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_del_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_rfs_del_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_del_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_rfs_del_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_del_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_rfs_del_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_del_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_del_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_del_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_del_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_rfs_del_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        char        *v;
        CMON_NODE    cmon_node;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_del_get_request: no cmon start");

            return (EC_TRUE);
        }

        cmon_node_init(&cmon_node);

        CMON_NODE_MODI(&cmon_node)   = 0; /*default*/

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-tcid");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_del_get_request: invalid rfs-tcid '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_TCID(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_del_get_request: header rfs-tcid %s => 0x%lx\n",
                                v, CMON_NODE_TCID(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-ip");
        if(NULL_PTR != v)
        {
            if(EC_FALSE == c_ipv4_is_ok(v))
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_del_get_request: invalid rfs-ip '%s'", v);

                cmon_node_clean(&cmon_node);
                return (EC_TRUE);
            }

            CMON_NODE_IPADDR(&cmon_node) = c_ipv4_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_del_get_request: header rfs-ip %s => 0x%lx\n",
                                v, CMON_NODE_IPADDR(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-port");
        if(NULL_PTR != v)
        {
            CMON_NODE_PORT(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_del_get_request: header rfs-port %s => %ld\n",
                                v, CMON_NODE_PORT(&cmon_node));
        }

        v = chttps_node_get_header(chttps_node, (const char *)"rfs-modi");
        if(NULL_PTR != v)
        {
            CMON_NODE_MODI(&cmon_node) = c_str_to_word(v);
            dbg_log(SEC_0056_CNGX_HTTPS, 1)(LOGSTDOUT, "[DEBUG] cngx_https_handle_rfs_del_get_request: header rfs-modi %s => %ld\n",
                                v, CMON_NODE_MODI(&cmon_node));
        }

        if(EC_FALSE == cmon_del_node(cmon_id, &cmon_node))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_del_get_request: del rfs %s failed", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

            cmon_node_clean(&cmon_node);
            return (EC_TRUE);
        }

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_del_get_request: del rfs %s done", c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cmon_node_clean(&cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_rfs_del_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_del_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_del_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_del_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_rfs_del_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_del_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: rfs_list ----------------------------------------*/
STATIC_CAST static EC_BOOL __cngx_https_uri_is_rfs_list_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/rfs_list") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/rfs_list")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_is_http_get_rfs_list(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0056_CNGX_HTTPS, 9)(LOGSTDOUT, "[DEBUG] cngx_https_is_http_get_rfs_list: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __cngx_https_uri_is_rfs_list_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cngx_https_commit_rfs_list_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == cngx_https_handle_rfs_list_get_request(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_list_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_https_make_rfs_list_get_response(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_list_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = cngx_https_commit_rfs_list_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_list_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL cngx_https_handle_rfs_list_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CNGX_HTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_list_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_list_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error: cngx_https_handle_rfs_list_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_list_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __cngx_https_uri_is_rfs_list_get_op(uri_cbuffer))
    {
        UINT32       cmon_id;
        CSTRING      crfs_list_cstr;

        cmon_id = task_brd_default_get_cmon_id();
        if(CMPI_ERROR_MODI == cmon_id)
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_IMPLEMENTED;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_FAIL %s %u --", "GET", CHTTP_NOT_IMPLEMENTED);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:cngx_https_handle_rfs_list_get_request: no cmon start");

            return (EC_TRUE);
        }

        cstring_init(&crfs_list_cstr, NULL_PTR);

        cmon_list_nodes(cmon_id, &crfs_list_cstr);

        cbytes_mount(content_cbytes, CSTRING_LEN(&crfs_list_cstr), CSTRING_STR(&crfs_list_cstr));
        cstring_unset(&crfs_list_cstr);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFSMON_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] cngx_https_handle_rfs_list_get_request: list rfs done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_https_make_rfs_list_get_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_list_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_list_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_list_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_make_rfs_list_get_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cngx_https_commit_rfs_list_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0056_CNGX_HTTPS, 0)(LOGSTDOUT, "error:cngx_https_commit_rfs_list_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return cngx_https_commit_response(chttps_node);
}
#endif


#ifdef __cplusplus
}
#endif/*__cplusplus*/

