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
#define CRFSHTTPS_TIME_COST_VALUE(chttps_node)  \
    (uint32_t)CTMV_NSEC(CHTTPS_NODE_START_TMV(chttps_node)), (uint32_t)CTMV_MSEC(CHTTPS_NODE_START_TMV(chttps_node)), \
    (uint32_t)CTMV_NSEC(task_brd_default_get_daytime()), (uint32_t)CTMV_MSEC(task_brd_default_get_daytime()), \
    (uint32_t)((CTMV_NSEC(task_brd_default_get_daytime()) - CTMV_NSEC(CHTTPS_NODE_START_TMV(chttps_node))) * 1000 + CTMV_MSEC(task_brd_default_get_daytime()) - CTMV_MSEC(CHTTPS_NODE_START_TMV(chttps_node)))
#endif

static EC_BOOL g_crfshttps_log_init = EC_FALSE;

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
                            LOGD_FILE_RECORD_LIMIT_ENABLED, SWITCH_OFF,
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
                            LOGD_FILE_RECORD_LIMIT_ENABLED, SWITCH_OFF,
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
EC_BOOL crfshttps_commit_request(CHTTPS_NODE *chttps_node)
{
    http_parser_t *http_parser;

    http_parser = CHTTPS_NODE_PARSER(chttps_node);

    if(HTTP_GET == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)crfshttps_commit_http_get, 1, chttps_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_request: cthread load for HTTP_GET failed\n");
            return (EC_BUSY);
        }
        CHTTPS_NODE_LOG_TIME_WHEN_LOADED(chttps_node);/*record http request was loaded time in coroutine*/
        CHTTPS_NODE_CROUTINE_NODE(chttps_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSHTTPS_0004);

        return (EC_TRUE);
    }

    if(HTTP_POST == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)crfshttps_commit_http_post, 1, chttps_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_request: cthread load for HTTP_POST failed\n");
            return (EC_BUSY);
        }
        CHTTPS_NODE_LOG_TIME_WHEN_LOADED(chttps_node);/*record http request was loaded time in coroutine*/
        CHTTPS_NODE_CROUTINE_NODE(chttps_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSHTTPS_0005);

        return (EC_TRUE);
    }

    if(HTTP_HEAD == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;

        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)crfshttps_commit_http_head, 1, chttps_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_request: cthread load for HTTP_HEAD failed\n");
            return (EC_BUSY);
        }
        CHTTPS_NODE_LOG_TIME_WHEN_LOADED(chttps_node);/*record http request was loaded time in coroutine*/
        CHTTPS_NODE_CROUTINE_NODE(chttps_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSHTTPS_0006);

        return (EC_TRUE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_request: not support http method %d yet\n", http_parser->method);
    return (EC_FALSE);/*note: this chttps_node must be discarded*/
}

EC_BOOL crfshttps_commit_http_head(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    CHTTPS_NODE_LOG_TIME_WHEN_HANDLE(chttps_node);/*record rfs beg to handle time*/

    if(EC_TRUE == crfshttps_is_http_head_getsmf(chttps_node))
    {
        ret = crfshttps_commit_getsmf_head_request(chttps_node);
    }
    else
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_http_head: invalid uri %.*s\n",
                        CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        ret = EC_FALSE;
    }

    return crfshttps_commit_end(chttps_node, ret);
}

EC_BOOL crfshttps_commit_http_post(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    CHTTPS_NODE_LOG_TIME_WHEN_HANDLE(chttps_node);/*record rfs beg to handle time*/

    if(EC_TRUE == crfshttps_is_http_post_setsmf(chttps_node))
    {
        ret = crfshttps_commit_setsmf_post_request(chttps_node);
    }
    else if(EC_TRUE == crfshttps_is_http_post_mexpire(chttps_node))
    {
        ret = crfshttps_commit_mexpire_post_request(chttps_node);
    }
    else if(EC_TRUE == crfshttps_is_http_post_mdsmf(chttps_node))
    {
        ret = crfshttps_commit_mdsmf_post_request(chttps_node);
    }
    else if(EC_TRUE == crfshttps_is_http_post_mddir(chttps_node))
    {
        ret = crfshttps_commit_mddir_post_request(chttps_node);
    }
    else if(EC_TRUE == crfshttps_is_http_post_update(chttps_node))
    {
        ret = crfshttps_commit_update_post_request(chttps_node);
    }
    else if(EC_TRUE == crfshttps_is_http_post_renew(chttps_node))
    {
        ret = crfshttps_commit_renew_post_request(chttps_node);
    }
    else
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_http_post: invalid uri %.*s\n",
                        CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        ret = EC_FALSE;
    }

    return crfshttps_commit_end(chttps_node, ret);
}

EC_BOOL crfshttps_commit_http_get(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_http_get: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(CHTTPS_NODE_URI(chttps_node)),
                        CBUFFER_DATA(CHTTPS_NODE_URI(chttps_node)),
                        CBUFFER_USED(CHTTPS_NODE_URI(chttps_node)));

    CHTTPS_NODE_LOG_TIME_WHEN_HANDLE(chttps_node);/*record rfs beg to handle time*/

    if(EC_TRUE == crfshttps_is_http_get_getsmf(chttps_node))
    {
        ret = crfshttps_commit_getsmf_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_dsmf(chttps_node))
    {
        ret = crfshttps_commit_dsmf_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_ddir(chttps_node))
    {
        ret = crfshttps_commit_ddir_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_sexpire(chttps_node))
    {
        ret = crfshttps_commit_sexpire_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_lock_req(chttps_node))
    {
        ret = crfshttps_commit_lock_req_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_unlock_req(chttps_node))
    {
        ret = crfshttps_commit_unlock_req_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_unlock_notify_req(chttps_node))
    {
        ret = crfshttps_commit_unlock_notify_req_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_recycle(chttps_node))
    {
        ret = crfshttps_commit_recycle_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_flush(chttps_node))
    {
        ret = crfshttps_commit_flush_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_retire(chttps_node))
    {
        ret = crfshttps_commit_retire_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_breathe(chttps_node))
    {
        ret = crfshttps_commit_breathe_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_logrotate(chttps_node))
    {
        ret = crfshttps_commit_logrotate_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_actsyscfg(chttps_node))
    {
        ret = crfshttps_commit_actsyscfg_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_qtree(chttps_node))
    {
        ret = crfshttps_commit_qtree_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_file_wait(chttps_node))
    {
        ret = crfshttps_commit_file_wait_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_file_notify(chttps_node))
    {
        ret = crfshttps_commit_file_notify_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_cond_wakeup(chttps_node))
    {
        ret = crfshttps_commit_cond_wakeup_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_renew_header(chttps_node))
    {
        ret = crfshttps_commit_renew_header_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_wait_header(chttps_node))
    {
        ret = crfshttps_commit_wait_header_get_request(chttps_node);
    }
    else if (EC_TRUE == crfshttps_is_http_get_locked_file_retire(chttps_node))
    {
        ret = crfshttps_commit_locked_file_retire_get_request(chttps_node);
    }
    else
    {
        CBUFFER *uri_cbuffer;

        uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_http_get: invalid uri %.*s\n",
                            CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_NOT_ACCEPTABLE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_commit_http_get: invalid uri %.*s",
                            CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;
    }

    return crfshttps_commit_end(chttps_node, ret);
}

EC_BOOL crfshttps_commit_end(CHTTPS_NODE *chttps_node, EC_BOOL result)
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

            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_end: sockfd %d done, remove all epoll events\n", sockfd);
            cepoll_del_all(cepoll, sockfd);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            /*chttps_node resume for next request handling if keep-alive*/
            chttps_node_wait_resume(chttps_node);

            return (EC_DONE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_end: csocket_cnode of chttps_node %p is null\n", chttps_node);

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

            dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "[DEBUG] crfshttps_commit_end: sockfd %d false, remove all epoll events\n", sockfd);
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

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_end: csocket_cnode of chttps_node %p is null\n", chttps_node);

        /*free*/
        chttps_node_free(chttps_node);

        return (EC_FALSE);
    }

    /*EC_TRUE, EC_DONE*/
    return (ret);
}

EC_BOOL crfshttps_commit_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;
    EC_BOOL ret;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
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
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: getsmf ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_getsmf_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/getsmf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/getsmf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_getsmf(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_getsmf: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_getsmf_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_getsmf_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_getsmf_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_getsmf_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_getsmf_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_getsmf_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    char          *store_offset_str;
    char          *store_size_str;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getsmf");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0007);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_getsmf_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_getsmf_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    store_offset_str = chttps_node_get_header(chttps_node, (const char *)"store-offset");
    if(NULL_PTR != store_offset_str)
    {
        CSOCKET_CNODE * csocket_cnode;

        uint32_t store_offset;
        uint32_t store_size;

        UINT32   offset;
        UINT32   max_len;

        store_size_str   = chttps_node_get_header(chttps_node, (const char *)"store-size");

        store_offset = c_str_to_uint32_t(store_offset_str);
        store_size   = c_str_to_uint32_t(store_size_str);/*note: when store_size_str is null, store_size is zero*/

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        offset        = store_offset;
        max_len       = store_size;

        if(EC_FALSE == crfs_read_e(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &offset, max_len, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_getsmf_get_request: crfs read %s with offset %u, size %u failed\n",
                                (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_getsmf_get_request: crfs read %s with offset %u, size %u failed", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_get_request: crfs read %s with offset %u, size %u done\n",
                            (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "GET", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_getsmf_get_request: crfs read %s with offset %u, size %u done", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }
    else/*read whole file content*/
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_read(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_getsmf_get_request: crfs read %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_getsmf_get_request: crfs read %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_get_request: crfs read %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "GET", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_getsmf_get_request: crfs read %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_getsmf_get_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getsmf");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getsmf");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_getsmf_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_get_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_getsmf_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif
#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: lock_req ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_lock_req_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/lock_req/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/lock_req/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_lock_req(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_lock_req: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_lock_req_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_lock_req_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_lock_req_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_lock_req_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_lock_req_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_get_request: commit 'GET' response failed\n");
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
EC_BOOL crfshttps_handle_lock_req_get_request(CHTTPS_NODE *chttps_node)
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

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/lock_req");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/lock_req");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0011);

    cstring_init(&token_cstr, NULL_PTR);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_lock_req_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_lock_req_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_lock_req_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }


    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_lock_req_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        char    *expires_str;
        UINT32   expires_nsec;
        UINT32   locked_flag;

        expires_str  = chttps_node_get_header(chttps_node, (const char *)"Expires");
        expires_nsec = __crfshttps_convert_expires_str_to_nseconds(expires_str);
        locked_flag  = EC_FALSE;

        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "[DEBUG] crfshttps_handle_lock_req_get_request: header Expires %s => %ld\n",
                                expires_str, expires_nsec);

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_file_lock(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, expires_nsec, &token_cstr, &locked_flag))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "error:crfshttps_handle_lock_req_get_request: crfs lock %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            if(EC_TRUE == locked_flag)/*flag was set*/
            {
                cbytes_set(content_cbytes, (UINT8 *)"locked-already:true\r\n", sizeof("locked-already:true\r\n") - 1);
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_lock_req_get_request: crfs lock %s failed", (char *)cstring_get_str(&path_cstr));
            }
            else /*flag was not set which means some error happen*/
            {
                CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_lock_req_get_request: crfs lock %s failed", (char *)cstring_get_str(&path_cstr));
            }

            cstring_clean(&path_cstr);
            cstring_clean(&token_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_lock_req_get_request: crfs lock %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_lock_req_get_request: crfs lock %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    auth_token_header_len = snprintf((char *)auth_token_header, sizeof(auth_token_header),
                                    "auth-token:%.*s\r\n",
                                    (uint32_t)CSTRING_LEN(&token_cstr), (char *)CSTRING_STR(&token_cstr));
    cbytes_set(content_cbytes, auth_token_header, auth_token_header_len);

    cstring_clean(&path_cstr);
    cstring_clean(&token_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_lock_req_get_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *token_buf;
    uint32_t       token_len;

    /*note: content carry on auth-token info but not response body*/
    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    token_buf      = CBYTES_BUF(content_cbytes);
    token_len      = (uint32_t)CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/lock_req");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/lock_req");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_lock_req_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_token(chttps_node, token_buf, token_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_get_response: make response header token failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_lock_req_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_lock_req_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_lock_req_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: unlock_req ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_unlock_req_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/unlock_req/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/unlock_req/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_unlock_req(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_unlock_req: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_unlock_req_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_unlock_req_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_unlock_req_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_unlock_req_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_unlock_req_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_unlock_req_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/unlock_req");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/unlock_req");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0012);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_req_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_req_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_unlock_req_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_unlock_req_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        char    *auth_token_header;

        CSTRING  token_cstr;

        auth_token_header = chttps_node_get_header(chttps_node, (const char *)"auth-token");
        if(NULL_PTR == auth_token_header)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT,
                            "error:crfshttps_handle_unlock_req_get_request: crfs unlock %s failed due to header 'auth-token' absence\n",
                            (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_unlock_req_get_request: crfs unlock %s failed due to header 'auth-token' absence", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        cstring_set_str(&token_cstr, (const UINT8 *)auth_token_header);

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_file_unlock(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &token_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_unlock_req_get_request: crfs unlock %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_unlock_req_get_request: crfs unlock %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_req_get_request: crfs unlock %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_unlock_req_get_request: crfs unlock %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_unlock_req_get_response(CHTTPS_NODE *chttps_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/unlock_req");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/unlock_req");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_unlock_req_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_req_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_req_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_req_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_unlock_req_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_req_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: unlock_notify_req ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_unlock_notify_req_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/unlock_notify_req/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/unlock_notify_req/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_unlock_notify_req(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_unlock_notify_req: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_unlock_notify_req_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_unlock_notify_req_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_unlock_notify_req_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_unlock_notify_req_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_unlock_notify_req_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_unlock_notify_req_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/unlock_notify_req");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/unlock_notify_req");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0013);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_notify_req_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_unlock_notify_req_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_unlock_notify_req_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_unlock_notify_req_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_file_unlock_notify(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_unlock_notify_req_get_request: crfs unlock_notify %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_unlock_notify_req_get_request: crfs unlock_notify %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_unlock_notify_req_get_request: crfs unlock_notify %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_unlock_notify_req_get_request: crfs unlock_notify %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_unlock_notify_req_get_response(CHTTPS_NODE *chttps_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/unlock_notify_req");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/unlock_notify_req");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_unlock_notify_req_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_notify_req_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_notify_req_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_unlock_notify_req_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_unlock_notify_req_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_unlock_notify_req_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: recycle ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_recycle_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/recycle") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/recycle")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_recycle(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_recycle: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_recycle_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_recycle_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_recycle_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_recycle_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_recycle_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_recycle_get_request(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    CBUFFER       *uri_cbuffer;

    //uint8_t       *cache_key;
    //uint32_t       cache_len;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    //cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/recycle");
    //cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/recycle");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_recycle_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_recycle_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_recycle_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_recycle_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_recycle_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char  *max_num_per_np_str;
        UINT32 max_num_per_np;
        UINT32 complete_num;

        uint8_t  recycle_result[ 32 ];
        uint32_t recycle_result_len;

        max_num_per_np_str = chttps_node_get_header(chttps_node, (const char *)"max-num-per-np");
        max_num_per_np = c_str_to_word(max_num_per_np_str);

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_recycle(CSOCKET_CNODE_MODI(csocket_cnode), max_num_per_np, &complete_num))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_recycle_get_request: crfs recycle failed\n");

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_recycle_get_request: crfs recycle failed");

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_recycle_get_request: crfs recycle done\n");

        /*prepare response header*/
        recycle_result_len = snprintf((char *)recycle_result, sizeof(recycle_result), "recycle-completion:%ld\r\n", complete_num);
        cbytes_set(content_cbytes, recycle_result, recycle_result_len);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_recycle_get_request: crfs recycle done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_recycle_get_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *recycle_result_buf;
    uint32_t       recycle_result_len;

    /*note: content carry on recycle-completion info but not response body*/
    content_cbytes    = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    recycle_result_buf = CBYTES_BUF(content_cbytes);
    recycle_result_len = (uint32_t)CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_recycle(chttps_node, recycle_result_buf, recycle_result_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_get_response: make response header recycle failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_recycle_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_recycle_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_recycle_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: flush ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_flush_get_op(const CBUFFER *uri_cbuffer)
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

EC_BOOL crfshttps_is_http_get_flush(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_flush: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_flush_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_flush_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_flush_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_flush_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_flush_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_flush_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    //uint8_t       *cache_key;
    //uint32_t       cache_len;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    //cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/flush");
    //cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/flush");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_flush_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_flush_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_flush_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_flush_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfshttps_uri_is_flush_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_flush(CSOCKET_CNODE_MODI(csocket_cnode)))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_flush_get_request: crfs flush failed\n");
            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_flush_get_request: crfs flush failed");

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_flush_get_request: crfs flush done\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_flush_get_request: crfs flush done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_flush_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_flush_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_flush_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_flush_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_flush_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_flush_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: retire ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_retire_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/retire") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/retire")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_retire(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_retire: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_retire_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_retire_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_retire_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_retire_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_retire_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_retire_get_request(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    char          *retire_files_str;

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_retire_get_request\n");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_retire_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_retire_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_retire_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_retire_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    retire_files_str   = chttps_node_get_header(chttps_node, (const char *)"retire-files");
    if(NULL_PTR == retire_files_str) /*invalid retire request*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_retire_get_request: http header 'retire-files' absence\n");

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_retire_get_request: http header 'retire-files' absence");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
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


        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        if(EC_FALSE == crfs_retire(CSOCKET_CNODE_MODI(csocket_cnode), retire_files, &complete_num))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_retire_get_request: crfs retire with expect retire num %ld failed\n",
                                retire_files);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_retire_get_request: crfs retire with expect retire num %ld failed",
                                retire_files);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;
            return (EC_TRUE);
        }

        /*prepare response header*/
        retire_result_len = snprintf((char *)retire_result, sizeof(retire_result), "retire-completion:%ld\r\n", complete_num);
        cbytes_set(content_cbytes, retire_result, retire_result_len);

        dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_retire_get_request: crfs retire with expect retire %ld, complete %ld done\n",
                            retire_files, complete_num);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_retire_get_request: crfs retire with expect retire %ld, complete %ld done",
                            retire_files, complete_num);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_retire_get_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *retire_result_buf;
    uint32_t       retire_result_len;

    /*note: content carry on retire-completion info but not response body*/
    content_cbytes    = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    retire_result_buf = CBYTES_BUF(content_cbytes);
    retire_result_len = (uint32_t)CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_retire(chttps_node, retire_result_buf, retire_result_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_get_response: make response header retire failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_retire_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_retire_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_retire_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: breathe ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_breathe_get_op(const CBUFFER *uri_cbuffer)
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

EC_BOOL crfshttps_is_http_get_breathe(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_breathe: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_breathe_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_breathe_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_breathe_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_breathe_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_breathe_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_breathe_get_request(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_breathe_get_request\n");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_breathe_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_breathe_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_breathe_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_breathe_get_request: bad request");

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

        dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_breathe_get_request: memory breathing done\n");

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_breathe_get_request: memory breathing done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_breathe_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_breathe_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_breathe_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_breathe_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_breathe_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_breathe_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: setsmf ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_setsmf_post_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/setsmf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/setsmf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_post_setsmf(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_post_setsmf: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_setsmf_post_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_setsmf_post_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_setsmf_post_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_post_request: handle 'SET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_setsmf_post_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_post_request: make 'SET' response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_setsmf_post_request: make 'SET' response done\n");

    ret = crfshttps_commit_setsmf_post_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_post_request: commit 'SET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}


EC_BOOL crfshttps_handle_setsmf_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    content_len  = CHTTPS_NODE_CONTENT_LENGTH(chttps_node);/*note: maybe request does not carry on Content-Lenght header*/
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_post_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf")),
                                                 CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf"),
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_post_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_setsmf_post_request: path %.*s, invalid content length %"PRId64,
                        (uint32_t)(CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf")),
                        (char *)(CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf")),content_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0014);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_setsmf_post_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttps_node_recv_len(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_post_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_setsmf_post_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_setsmf_post_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_setsmf_post_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_PARTIAL_CONTENT);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "warn:crfshttps_handle_setsmf_post_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_post_request: new cbytes without buff failed\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INSUFFICIENT_STORAGE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_setsmf_post_request: new cbytes without buff failed");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttps_node_recv_export_to_cbytes(chttps_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_post_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_setsmf_post_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttps_node_recv_clean(chttps_node);

    if(EC_TRUE == __crfshttps_uri_is_setsmf_post_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
#if 1
        if(EC_FALSE == crfs_write(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_post_request: crfs write %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_setsmf_post_request: crfs write %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_setsmf_post_request: crfs write %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "POST", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_setsmf_post_request: crfs write %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_write_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_post_request: crfs write %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_setsmf_post_request: crfs write %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_setsmf_post_request: crfs write %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "POST", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_setsmf_post_request: crfs write %s done", (char *)cstring_get_str(&path_cstr));
#endif
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_setsmf_post_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_setsmf_post_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_setsmf_post_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_setsmf_post_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_setsmf_post_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_setsmf_post_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_setsmf_post_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: PUT, FILE OPERATOR: getsmf ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_getsmf_head_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/getsmf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/getsmf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_head_getsmf(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_head_getsmf: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_getsmf_head_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}
EC_BOOL crfshttps_commit_getsmf_head_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_getsmf_head_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_head_request: handle 'SET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_getsmf_head_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_head_request: make 'SET' response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_getsmf_head_request: make 'SET' response done\n");

    ret = crfshttps_commit_getsmf_head_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_head_request: commit 'SET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_getsmf_head_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getsmf");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0015);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_head_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_getsmf_head_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        uint64_t        file_size;

        uint8_t        file_size_header[32];
        uint32_t       file_size_header_len;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_file_size(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &file_size))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_getsmf_head_request: crfs get size of %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "HEAD", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_getsmf_head_request: crfs get size of %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_getsmf_head_request: crfs get size of %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %"PRId64, "HEAD", CHTTP_OK, file_size);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_getsmf_head_request: crfs get size of %s done", (char *)cstring_get_str(&path_cstr));

        file_size_header_len = snprintf((char *)file_size_header, sizeof(file_size_header),
                                        "file-size:%"PRId64"\r\n", file_size);
        cbytes_set(content_cbytes, file_size_header, file_size_header_len);
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_getsmf_head_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_getsmf_head_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint8_t       *file_size_buf;
    uint32_t       file_size_len;

    /*note: content carry on file-size info but not response body*/
    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    file_size_buf  = CBYTES_BUF(content_cbytes);
    file_size_len  = (uint32_t)CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_head_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_head_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_data(chttps_node, file_size_buf, file_size_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_head_response: make response header file-size failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_getsmf_head_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_getsmf_head_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_getsmf_head_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: update ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_update_post_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/update/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/update/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_post_update(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_post_update: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_update_post_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_update_post_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_update_post_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_post_request: handle 'SET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_update_post_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_post_request: make 'SET' response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_update_post_request: make 'SET' response done\n");

    ret = crfshttps_commit_update_post_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_post_request: commit 'SET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_update_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    content_len  = CHTTPS_NODE_CONTENT_LENGTH(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(!((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_post_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/update")),
                                                 CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/update"),
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_post_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_update_post_request: path %.*s, invalid content length %"PRId64,
                        (uint32_t)(CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/update")),
                        (char *)(CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/update")),content_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/update");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/update");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0016);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_update_post_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttps_node_recv_len(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node); ;

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_post_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_update_post_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_update_post_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_update_post_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_PARTIAL_CONTENT);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "warn:crfshttps_handle_update_post_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_post_request: new cbytes without buff failed\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INSUFFICIENT_STORAGE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_update_post_request: new cbytes with len zero failed");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttps_node_recv_export_to_cbytes(chttps_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_post_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_update_post_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttps_node_recv_clean(chttps_node);

    if(EC_TRUE == __crfshttps_uri_is_update_post_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
#if 1
        if(EC_FALSE == crfs_update(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_post_request: crfs update %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_update_post_request: crfs update %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_update_post_request: crfs update %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "POST", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_update_post_request: crfs update %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_update_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_post_request: crfs update %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_update_post_request: crfs update %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
#endif
    }

    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_update_post_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_update_post_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_update_post_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_update_post_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_update_post_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_update_post_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_update_post_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: renew ----------------------------------------*/
/*renew expires setting*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_renew_post_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/renew/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/renew/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_post_renew(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_post_renew: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_renew_post_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_renew_post_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_renew_post_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_post_request: handle 'SET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_renew_post_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_post_request: make 'SET' response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_renew_post_request: make 'SET' response done\n");

    ret = crfshttps_commit_renew_post_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_post_request: commit 'SET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_renew_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    content_len  = CHTTPS_NODE_CONTENT_LENGTH(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_post_request: path %.*s, invalid content length %"PRId64"\n",
                                                 (uint32_t)(CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/renew")),
                                                 CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/renew"),
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_post_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_renew_post_request: path %.*s, invalid content length %"PRId64,
                        (uint32_t)(CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/renew")),
                        (char *)(CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/renew")),content_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/renew");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/renew");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0017);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_post_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    body_len = chttps_node_recv_len(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_post_request: path %s, invalid body length %"PRId64"\n",
                                                 (char *)cstring_get_str(&path_cstr),
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_post_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_renew_post_request: path %s, invalid body length %"PRId64, (char *)cstring_get_str(&path_cstr),body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_renew_post_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_PARTIAL_CONTENT);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "warn:crfshttps_handle_renew_post_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_PARTIAL_CONTENT;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new(0);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_post_request: new cbytes without buff failed\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INSUFFICIENT_STORAGE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_post_request: new cbytes without buff failed");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chttps_node_recv_export_to_cbytes(chttps_node, content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_post_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_post_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttps_node_recv_clean(chttps_node);

    if(EC_TRUE == __crfshttps_uri_is_renew_post_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
#if 1
        if(EC_FALSE == crfs_renew(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_post_request: crfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_post_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_post_request: crfs renew %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "POST", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_renew_post_request: crfs renew %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_renew_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_post_request: crfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_post_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
#endif
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_post_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_renew_post_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_post_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_post_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_post_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_renew_post_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_post_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: dsmf ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_dsmf_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/dsmf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/dsmf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*delete small/regular file*/
EC_BOOL crfshttps_is_http_get_dsmf(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_dsmf: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_dsmf_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_dsmf_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_dsmf_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_dsmf_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_dsmf_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_dsmf_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/dsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/dsmf");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0018);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_dsmf_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_dsmf_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_dsmf_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfshttps_uri_is_dsmf_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
#if 1
        if(EC_FALSE == crfs_delete(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_REG))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_dsmf_get_request: crfs delete file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_dsmf_get_request: crfs delete file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_dsmf_get_request: crfs delete file %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_dsmf_get_request: crfs delete file %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_delete_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_REG, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_dsmf_get_request: crfs delete file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_dsmf_get_request: crfs delete file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
#endif
        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_dsmf_get_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_dsmf_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_dsmf_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_dsmf_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_dsmf_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_dsmf_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_dsmf_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: ddir ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_ddir_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/ddir/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/ddir/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*delete dir*/
EC_BOOL crfshttps_is_http_get_ddir(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_ddir: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_ddir_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_ddir_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_ddir_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_ddir_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_ddir_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_ddir_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/ddir");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/ddir");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0019);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_ddir_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_ddir_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_ddir_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfshttps_uri_is_ddir_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
#if 1
        if(EC_FALSE == crfs_delete(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_DIR))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_ddir_get_request: crfs delete dir %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_ddir_get_request: crfs delete dir %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_ddir_get_request: crfs delete dir %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_ddir_get_request: crfs delete dir %s done", (char *)cstring_get_str(&path_cstr));
#endif
#if 0
        if(EC_FALSE == crfs_delete_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSNP_ITEM_FILE_IS_DIR, CRFS_MAX_REPLICA_NUM))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_ddir_get_request: crfs delete dir %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_ddir_get_request: crfs delete dir %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
#endif
        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_ddir_get_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_ddir_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_ddir_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_ddir_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_ddir_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_ddir_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_ddir_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: sexpire ----------------------------------------*/
/*expire single file*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_sexpire_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/sexpire/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/sexpire/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*expire single file*/
EC_BOOL crfshttps_is_http_get_sexpire(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_sexpire: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_sexpire_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_sexpire_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_sexpire_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_sexpire_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_sexpire_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_sexpire_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/sexpire");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/sexpire");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0020);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_sexpire_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_sexpire_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_sexpire_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfshttps_uri_is_sexpire_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_file_expire(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_sexpire_get_request: crfs exipre file %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_sexpire_get_request: crfs exipre file %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_sexpire_get_request: crfs exipre file %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_sexpire_get_request: crfs exipre file %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_sexpire_get_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_sexpire_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_sexpire_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_sexpire_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_sexpire_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_sexpire_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_sexpire_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mexpire ----------------------------------------*/
/*expire multiple files*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_mexpire_post_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/mexpire") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/mexpire")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*expire multiple files*/
EC_BOOL crfshttps_is_http_post_mexpire(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_post_mexpire: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_mexpire_post_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_mexpire_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER *uri_cbuffer;
    EC_BOOL ret;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mexpire_post_request: uri %.*s\n",
                    CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));


    if(EC_FALSE == crfshttps_handle_mexpire_post_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_post_request: handle 'SET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_mexpire_post_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_post_request: make 'SET' response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mexpire_post_request: make 'SET' response done\n");

    ret = crfshttps_commit_mexpire_post_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_post_request: commit 'SET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_mexpire_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    content_len  = CHTTPS_NODE_CONTENT_LENGTH(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_post_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_post_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_mexpire_post_request: invalid content length %"PRId64, content_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttps_node_recv_len(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_post_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mexpire_post_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_mexpire_post_request: invalid body length %"PRId64, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_mexpire_post_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_PARTIAL_CONTENT);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "warn:crfshttps_handle_mexpire_post_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "info:crfshttps_handle_mexpire_post_request: request body is empty\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "POST", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "info:crfshttps_handle_mexpire_post_request: request body is empty");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_post_request: new cbytes without buff failed\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INSUFFICIENT_STORAGE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mexpire_post_request: new cbytes with len zero failed");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttps_node_recv_export_to_cbytes(chttps_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_post_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mexpire_post_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cbytes_free(req_content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttps_node_recv_clean(chttps_node);

    if(EC_TRUE == __crfshttps_uri_is_mexpire_post_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        json_object   * files_obj;
        json_object   * rsp_body_obj;
        const char    * rsp_body_str;
        size_t          idx;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        rsp_content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
        cbytes_clean(rsp_content_cbytes);

        files_obj = json_tokener_parse((const char *)CBYTES_BUF(req_content_cbytes));
        if(NULL_PTR == files_obj)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_post_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mexpire_post_request: bad request %.*s",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_post_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_post_request: path is null at %ld\n", idx);

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_post_request: crfs expire %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_NOT_FOUND);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mexpire_post_request: crfs expire %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_mexpire_post_request: crfs expire %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "POST", CHTTP_OK);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_mexpire_post_request: crfs expire %s done", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("200"));
            }
            cstring_clean(&path_cstr);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str) + 1);

        /*free json obj*/
        json_object_put(files_obj);
        json_object_put(rsp_body_obj);
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mexpire_post_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_mexpire_post_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_post_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_post_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_post_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mexpire_post_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_mexpire_post_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mexpire_post_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mdsmf ----------------------------------------*/
/*delete multiple files*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_mdsmf_post_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/mdsmf") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/mdsmf")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*delete multiple files*/
EC_BOOL crfshttps_is_http_post_mdsmf(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_post_mdsmf: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_mdsmf_post_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_mdsmf_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER *uri_cbuffer;
    EC_BOOL ret;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mdsmf_post_request: uri %.*s\n",
                        CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));

    if(EC_FALSE == crfshttps_handle_mdsmf_post_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_post_request: handle 'SET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_mdsmf_post_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_post_request: make 'SET' response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mdsmf_post_request: make 'SET' response done\n");

    ret = crfshttps_commit_mdsmf_post_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_post_request: commit 'SET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_mdsmf_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    content_len  = CHTTPS_NODE_CONTENT_LENGTH(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_post_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_post_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_mdsmf_post_request: invalid content length %"PRId64, content_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttps_node_recv_len(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_post_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mdsmf_post_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_mdsmf_post_request: invalid body length %"PRId64, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_mdsmf_post_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_PARTIAL_CONTENT);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "warn:crfshttps_handle_mdsmf_post_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "info:crfshttps_handle_mdsmf_post_request: request body is empty\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "POST", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "info:crfshttps_handle_mdsmf_post_request: request body is empty");
        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_post_request: new cbytes without buff failed\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INSUFFICIENT_STORAGE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mdsmf_post_request: new cbytes with len zero failed");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttps_node_recv_export_to_cbytes(chttps_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_post_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mdsmf_post_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cbytes_free(req_content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttps_node_recv_clean(chttps_node);

    if(EC_TRUE == __crfshttps_uri_is_mdsmf_post_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        json_object   * files_obj;
        json_object   * rsp_body_obj;
        const char    * rsp_body_str;
        size_t          idx;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        rsp_content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
        cbytes_clean(rsp_content_cbytes);

        files_obj = json_tokener_parse((const char *)CBYTES_BUF(req_content_cbytes));
        if(NULL_PTR == files_obj)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_post_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mdsmf_post_request: bad request %.*s",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_post_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_post_request: path is null at %ld\n", idx);

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_post_request: crfs delete %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_NOT_FOUND);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mdsmf_post_request: crfs delete %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_mdsmf_post_request: crfs delete %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "POST", CHTTP_OK);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_mdsmf_post_request: crfs delete %s done", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("200"));
            }
            cstring_clean(&path_cstr);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str) + 1);

        /*free json obj*/
        json_object_put(files_obj);
        json_object_put(rsp_body_obj);
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mdsmf_post_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_mdsmf_post_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_post_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_post_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_post_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_post_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_mdsmf_post_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mdsmf_post_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: POST, FILE OPERATOR: mddir ----------------------------------------*/
/*delete multiple files*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_mddir_post_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/mddir") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/mddir")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*delete multiple files*/
EC_BOOL crfshttps_is_http_post_mddir(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_post_mddir: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_mddir_post_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_mddir_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER *uri_cbuffer;
    EC_BOOL ret;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mddir_post_request: uri %.*s\n",
                        CBUFFER_USED(uri_cbuffer), CBUFFER_DATA(uri_cbuffer));


    if(EC_FALSE == crfshttps_handle_mddir_post_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_post_request: handle 'SET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_mddir_post_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_post_request: make 'SET' response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_commit_mddir_post_request: make 'SET' response done\n");

    ret = crfshttps_commit_mddir_post_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_post_request: commit 'SET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_mddir_post_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    CBYTES        *req_content_cbytes;
    CBYTES        *rsp_content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);
    content_len  = CHTTPS_NODE_CONTENT_LENGTH(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > content_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > content_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_post_request: invalid content length %"PRId64"\n",
                                                 content_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_post_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_mddir_post_request: invalid content length %"PRId64, content_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    body_len = chttps_node_recv_len(chttps_node);
    /*CRFSHTTPS_ASSERT((uint64_t)0x100000000 > body_len);*//*not consider this scenario yet*/
    if(! ((uint64_t)0x100000000 > body_len))
    {
        CHUNK_MGR *req_body_chunks;
        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_post_request: invalid body length %"PRId64"\n",
                                                 body_len);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_post_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_mddir_post_request: chunk mgr %p str\n", req_body_chunks);
        chunk_mgr_print_str(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_mddir_post_request: invalid body length %"PRId64, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(content_len > body_len)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "warn:crfshttps_handle_mddir_post_request: content_len %"PRId64" > body_len %"PRId64"\n", content_len, body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_PARTIAL_CONTENT);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "warn:crfshttps_handle_mddir_post_request: content_len %"PRId64" > body_len %"PRId64, content_len, body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_PARTIAL_CONTENT;

        return (EC_TRUE);
    }

    if(0 == body_len)/*request carry on empty body, nothing to do*/
    {
        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "info:crfshttps_handle_mddir_post_request: request body is empty\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "POST", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "info:crfshttps_handle_mddir_post_request: request body is empty");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
        return (EC_TRUE);
    }

    req_content_cbytes = cbytes_new(0);
    if(NULL_PTR == req_content_cbytes)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_post_request: new cbytes without buff failed\n");
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INSUFFICIENT_STORAGE);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mddir_post_request: new cbytes with len zero failed");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INSUFFICIENT_STORAGE;
        return (EC_TRUE);
    }

    if(EC_FALSE == chttps_node_recv_export_to_cbytes(chttps_node, req_content_cbytes, (UINT32)body_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_post_request: export body with len %ld to cbytes failed\n",
                            (UINT32)body_len);
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mddir_post_request: export body with len %ld to cbytes failed", (UINT32)body_len);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cbytes_free(req_content_cbytes);
        return (EC_TRUE);
    }

    /*clean body chunks*/
    chttps_node_recv_clean(chttps_node);

    if(EC_TRUE == __crfshttps_uri_is_mddir_post_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        json_object   * files_obj;
        json_object   * rsp_body_obj;
        const char    * rsp_body_str;
        size_t          idx;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        rsp_content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
        cbytes_clean(rsp_content_cbytes);

        files_obj = json_tokener_parse((const char *)CBYTES_BUF(req_content_cbytes));
        if(NULL_PTR == files_obj)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_post_request: bad request %.*s\n",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));
            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "POST", CHTTP_BAD_REQUEST);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mddir_post_request: bad request %.*s",
                                    (uint32_t)CBYTES_LEN(req_content_cbytes), (char *)CBYTES_BUF(req_content_cbytes));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_post_request: invalid file at %ld\n", idx);

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
                continue;
            }

            path = (char *)json_object_to_json_string_ext(file_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
            if(NULL_PTR == path)
            {
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_post_request: path is null at %ld\n", idx);

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
                dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_post_request: crfs delete %s failed\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "POST", CHTTP_NOT_FOUND);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_mddir_post_request: crfs delete %s failed", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("404"));
            }
            else
            {
                dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_mddir_post_request: crfs delete %s done\n",
                                    (char *)cstring_get_str(&path_cstr));

                CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
                CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "POST", CHTTP_OK);
                CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_mddir_post_request: crfs delete %s done", (char *)cstring_get_str(&path_cstr));

                json_object_array_add(rsp_body_obj, json_object_new_string("200"));
            }
            cstring_clean(&path_cstr);
        }

        rsp_body_str = json_object_to_json_string_ext(rsp_body_obj, JSON_C_TO_STRING_NOSLASHESCAPE);
        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, (UINT32)(strlen(rsp_body_str) + 1));

        /*free json obj*/
        json_object_put(files_obj);
        json_object_put(rsp_body_obj);
    }
    else
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_mddir_post_request: should never reach here!\n");
        task_brd_default_abort();
    }

    cbytes_free(req_content_cbytes);

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_mddir_post_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_post_response: make response header failed\n");

        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_post_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_post_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mddir_post_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_mddir_post_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_mddir_post_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: logrotate ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_logrotate_get_op(const CBUFFER *uri_cbuffer)
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

EC_BOOL crfshttps_is_http_get_logrotate(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_logrotate: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_logrotate_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_logrotate_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_logrotate_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_logrotate_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_logrotate_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_logrotate_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    //uint8_t       *cache_key;
    //uint32_t       cache_len;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    //cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/logrotate");
    //cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/logrotate");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_logrotate_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_logrotate_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_logrotate_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_logrotate_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfshttps_uri_is_logrotate_get_op(uri_cbuffer))
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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_logrotate_get_request: log rotate %ld failed\n", log_index);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_logrotate_get_request: log rotate %ld failed", log_index);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_logrotate_get_request: log rotate %ld done\n", log_index);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_logrotate_get_request: log rotate %ld done", log_index);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_logrotate_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_logrotate_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_logrotate_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_logrotate_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_logrotate_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_logrotate_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: actsyscfg ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_actsyscfg_get_op(const CBUFFER *uri_cbuffer)
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

EC_BOOL crfshttps_is_http_get_actsyscfg(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_actsyscfg: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_actsyscfg_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_actsyscfg_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_actsyscfg_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_actsyscfg_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_actsyscfg_get_response(chttps_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_actsyscfg_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    //uint8_t       *cache_key;
    //uint32_t       cache_len;

    UINT32         req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    //cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/actsyscfg");
    //cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/actsyscfg");

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_actsyscfg_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_actsyscfg_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_actsyscfg_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_actsyscfg_get_request: bad request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfshttps_uri_is_actsyscfg_get_op(uri_cbuffer))
    {
        UINT32 super_md_id;

        super_md_id = 0;

        super_activate_sys_cfg(super_md_id);

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_actsyscfg_get_request done\n");

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_actsyscfg_get_request done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_actsyscfg_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_actsyscfg_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_actsyscfg_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_actsyscfg_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_actsyscfg_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_actsyscfg_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif


#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: qtree ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_qtree_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/qtree") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/qtree")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_qtree(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_qtree: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_qtree_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_qtree_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_qtree_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_qtree_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_qtree_get_response(chttps_node);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_qtree_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER     *uri_cbuffer;

    uint8_t     *cache_key;
    uint32_t     cache_len;

    CSTRING      path;

    UINT32       req_body_chunk_num;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/qtree");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/qtree");

    cstring_init(&path, NULL_PTR);
    cstring_append_chars(&path, cache_len, cache_key, LOC_CRFSHTTPS_0021);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_qtree_get_request: path %s\n", (char *)cstring_get_str(&path));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_get_request: path %s\n", (char *)cstring_get_str(&path));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_qtree_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_qtree_get_request: bad request: path %s", (char *)cstring_get_str(&path));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;

        cstring_clean(&path);

        return (EC_TRUE);
    }

    if(EC_TRUE == __crfshttps_uri_is_qtree_get_op(uri_cbuffer))
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
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_qtree_get_request failed\n");

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_qtree_get_request failed");

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path);

            cvector_clean(path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CRFSHTTPS_0023);
            cvector_free(path_cstr_vec, LOC_CRFSHTTPS_0024);

            return (EC_TRUE);
        }

        /* qtree success, get path from path_cstr_vec */

        rsp_content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
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

        cbytes_set(rsp_content_cbytes, (const UINT8 *)rsp_body_str, strlen(rsp_body_str) + 1);

        dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_qtree_get_request done\n");

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_qtree_get_request done");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cstring_clean(&path);

        cvector_free(path_cstr_vec, LOC_CRFSHTTPS_0025);

        /* free json obj */
        json_object_put(rsp_body_obj);

    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_qtree_get_response(CHTTPS_NODE *chttps_node)
{

    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_qtree_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_qtree_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_qtree_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_mdsmf_post_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_qtree_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_qtree_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: file_wait ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_file_wait_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/file_wait/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/file_wait/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_file_wait(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_file_wait: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_file_wait_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_file_wait_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_file_wait_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_wait_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_file_wait_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_wait_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_file_wait_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_wait_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_file_wait_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    const char    *k;
    char          *v;
    MOD_NODE       mod_node;

    char          *wait_data_str;
    char          *store_offset_str;
    char          *store_size_str;


    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/file_wait");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/file_wait");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0026);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_wait_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_wait_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_wait_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_wait_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_wait_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_file_wait_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    mod_node_init(&mod_node);

    k = (const char *)"tcid";
    v = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == v)
    {
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_file_wait_get_request: path %s, tcid absence", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }
    MOD_NODE_TCID(&mod_node) = c_ipv4_to_word(v);

    k = (const char *)"comm";
    v = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == v)
    {
        MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    }
    else
    {
        MOD_NODE_COMM(&mod_node) = c_str_to_word(v);
    }

    k = (const char *)"rank";
    v = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == v)
    {
        MOD_NODE_RANK(&mod_node) = CMPI_ANY_RANK;
    }
    else
    {
        MOD_NODE_RANK(&mod_node) = c_str_to_word(v);
    }

    wait_data_str = chttps_node_get_header(chttps_node, (const char *)"wait-data");
    if(NULL_PTR != wait_data_str && EC_FALSE == c_str_to_bool(wait_data_str))
    {
        CSOCKET_CNODE  *csocket_cnode;
        EC_BOOL         data_ready;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        data_ready    = EC_OBSCURE;/*means wait file only without reading data util file is ready and notification is sent*/

        if(EC_FALSE == crfs_file_wait(CSOCKET_CNODE_MODI(csocket_cnode), &mod_node, &path_cstr, NULL_PTR, &data_ready))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_file_wait_get_request: crfs wait %s only failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_file_wait_get_request: crfs wait %s only failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path_cstr);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_wait_get_request: crfs wait %s only done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_file_wait_get_request: crfs wait %s only done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cstrkv_mgr_add_kv_str(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node), (char *)"data-ready", c_bool_str(data_ready));

        cstring_clean(&path_cstr);

        return (EC_TRUE);
    }

    store_offset_str = chttps_node_get_header(chttps_node, (const char *)"store-offset");
    if(NULL_PTR != store_offset_str)
    {
        CSOCKET_CNODE * csocket_cnode;

        uint32_t store_offset;
        uint32_t store_size;

        UINT32   offset;
        UINT32   max_len;

        EC_BOOL  data_ready;

        store_size_str   = chttps_node_get_header(chttps_node, (const char *)"store-size");

        store_offset = c_str_to_uint32_t(store_offset_str);
        store_size   = c_str_to_uint32_t(store_size_str);/*note: when store_size_str is null, store_size is zero*/

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        offset        = store_offset;
        max_len       = store_size;
        data_ready    = EC_FALSE;

        if(EC_FALSE == crfs_file_wait_e(CSOCKET_CNODE_MODI(csocket_cnode), &mod_node, &path_cstr, &offset, max_len, content_cbytes, &data_ready))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_file_wait_get_request: crfs wait %s with offset %u, size %u failed\n",
                                (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_file_wait_get_request: crfs wait %s with offset %u, size %u failed", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_wait_get_request: crfs wait %s with offset %u, size %u done\n",
                            (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "GET", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_file_wait_get_request: crfs wait %s with offset %u, size %u done", (char *)cstring_get_str(&path_cstr), store_offset, store_size);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cstrkv_mgr_add_kv_str(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node), (char *)"data-ready", c_bool_str(data_ready));

        cstring_clean(&path_cstr);
    }
    else/*wait whole file content*/
    {
        CSOCKET_CNODE  *csocket_cnode;
        EC_BOOL         data_ready;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        data_ready    = EC_FALSE;

        if(EC_FALSE == crfs_file_wait(CSOCKET_CNODE_MODI(csocket_cnode), &mod_node, &path_cstr, content_cbytes, &data_ready))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_file_wait_get_request: crfs wait %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_file_wait_get_request: crfs wait %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_wait_get_request: crfs wait %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "GET", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_file_wait_get_request: crfs wait %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cstrkv_mgr_add_kv_str(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node), (char *)"data-ready", c_bool_str(data_ready));

        cstring_clean(&path_cstr);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_file_wait_get_response(CHTTPS_NODE *chttps_node)
{
    CBYTES        *content_cbytes;
    uint64_t       content_len;

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/file_wait");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/file_wait");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_file_wait_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, content_len))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_wait_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_wait_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_kvs(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_wait_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_wait_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    /*no data copying but data transfering*/
    if(EC_FALSE == chttps_make_response_body_ext(chttps_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_wait_get_response: make body with len %d failed\n",
                           (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }
    cbytes_umount(content_cbytes, NULL_PTR, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_file_wait_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_wait_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: file_notify ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_file_notify_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/file_notify/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/file_notify/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_file_notify(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_file_notify: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_file_notify_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_file_notify_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_file_notify_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_file_notify_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_file_notify_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_file_notify_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;


    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/file_notify");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/file_notify");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0027);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_notify_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_file_notify_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_file_notify_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_file_notify_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_file_notify(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_file_notify_get_request: crfs notify %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_file_notify_get_request: crfs notify %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_NOT_FOUND;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_file_notify_get_request: crfs notify %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "GET", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_file_notify_get_request: crfs notify %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_file_notify_get_response(CHTTPS_NODE *chttps_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/file_notify");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/file_notify");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_file_notify_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_notify_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_notify_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_notify_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_file_notify_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_file_notify_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: cond_wakeup ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_cond_wakeup_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/cond_wakeup/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/cond_wakeup/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_cond_wakeup(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_cond_wakeup: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_cond_wakeup_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_cond_wakeup_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_cond_wakeup_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_cond_wakeup_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_cond_wakeup_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_cond_wakeup_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;


    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/cond_wakeup");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/cond_wakeup");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0028);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_cond_wakeup_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_cond_wakeup_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_cond_wakeup_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_cond_wakeup_get_op(uri_cbuffer))
    {
        //CSOCKET_CNODE * csocket_cnode;
        UINT32 tag;

        tag = MD_CRFS;

        //csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == super_cond_wakeup(/*CSOCKET_CNODE_MODI(csocket_cnode)*/0, tag, &path_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_cond_wakeup_get_request: cond wakeup %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_cond_wakeup_get_request: cond wakeup %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstring_clean(&path_cstr);

            //return (EC_FALSE);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_cond_wakeup_get_request: cond wakeup %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u %ld", "GET", CHTTP_OK, CBYTES_LEN(content_cbytes));
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_cond_wakeup_get_request: cond wakeup %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_cond_wakeup_get_response(CHTTPS_NODE *chttps_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/cond_wakeup");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/cond_wakeup");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_cond_wakeup_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_cond_wakeup_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_cond_wakeup_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_cond_wakeup_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_cond_wakeup_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_cond_wakeup_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: renew_header ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_renew_header_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/renew_header/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/renew_header/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_renew_header(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_renew_header: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_renew_header_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_renew_header_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_renew_header_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_renew_header_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_renew_header_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_renew_header_get_request(CHTTPS_NODE *chttps_node)
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

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/renew_header");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/renew_header");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0029);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_renew_header_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_renew_header_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

    renew_num  = chttps_node_get_header(chttps_node, (const char *)"renew-num");
    if(NULL_PTR == renew_num)
    {
        char    *renew_key;
        char    *renew_val;

        CSTRING  renew_key_cstr;
        CSTRING  renew_val_cstr;

        renew_key  = chttps_node_get_header(chttps_node, (const char *)"renew-key");
        if(NULL_PTR == renew_key)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to 'renew-key' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to 'renew-key' absence", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        renew_val  = chttps_node_get_header(chttps_node, (const char *)"renew-val");
        if(NULL_PTR == renew_val)
        {
#if 1
            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_get_request: crfs renew %s would remove header ['%s'] due to 'renew-val' absence\n",
                                (char *)cstring_get_str(&path_cstr), renew_key);
#endif
#if 0
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to 'renew-val' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to 'renew-val' absence", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        cstring_set_str(&renew_key_cstr, (UINT8 *)renew_key);
        cstring_set_str(&renew_val_cstr, (UINT8 *)renew_val);

        if(EC_FALSE == crfs_renew_http_header(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &renew_key_cstr, &renew_val_cstr))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_get_request: crfs renew %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_renew_header_get_request: crfs renew %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    cstrkv_mgr = cstrkv_mgr_new();
    if(NULL_PTR == cstrkv_mgr)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to new cstrkv_mgr failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to new cstrkv_mgr failed",
                (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

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

        renew_key  = chttps_node_get_header(chttps_node, (const char *)renew_key_tag);
        if(NULL_PTR == renew_key)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)renew_key_tag);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to '%s' absence",
                    (char *)cstring_get_str(&path_cstr), (char *)renew_key_tag);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        renew_val  = chttps_node_get_header(chttps_node, (const char *)renew_val_tag);
        if(NULL_PTR == renew_val)
        {
#if 1
            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_get_request: crfs renew %s would remove header ['%s'] due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), renew_key, (char *)renew_val_tag);
#endif
#if 0
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)renew_val_tag);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to '%s' absence",
                    (char *)cstring_get_str(&path_cstr), (char *)renew_val_tag);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        if(EC_FALSE == cstrkv_mgr_add_kv_str(cstrkv_mgr, renew_key, renew_val))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to add '%s:%s' failed\n",
                                (char *)cstring_get_str(&path_cstr), renew_key, renew_val);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed due to add '%s:%s' failed",
                    (char *)cstring_get_str(&path_cstr), renew_key, renew_val);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
    }

    if(EC_FALSE == crfs_renew_http_headers(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, cstrkv_mgr))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_renew_header_get_request: crfs renew %s failed", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_renew_header_get_request: crfs renew %s done\n",
                        (char *)cstring_get_str(&path_cstr));

    CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
    CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_renew_header_get_request: crfs renew %s done", (char *)cstring_get_str(&path_cstr));

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    cstrkv_mgr_free(cstrkv_mgr);
    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_renew_header_get_response(CHTTPS_NODE *chttps_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/renew_header");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/renew_header");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_renew_header_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_header_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_header_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_renew_header_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_renew_header_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_renew_header_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: wait_header ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_wait_header_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/wait_header/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/wait_header/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_wait_header(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_wait_header: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_wait_header_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_wait_header_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_wait_header_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_wait_header_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_wait_header_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_wait_header_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_wait_header_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_wait_header_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_wait_header_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    UINT32         req_body_chunk_num;

    CSOCKET_CNODE *csocket_cnode;
    char          *wait_num;

    const char    *k;
    char          *v;
    MOD_NODE       mod_node;

    CSTRKV_MGR    *cstrkv_mgr;
    uint32_t       num;
    uint32_t       idx;

    EC_BOOL        header_ready;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/wait_header");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/wait_header");

    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key, LOC_CRFSHTTPS_0030);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_wait_header_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_wait_header_get_request: path %s\n", (char *)cstring_get_str(&path_cstr));

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_wait_header_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_wait_header_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_wait_header_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_wait_header_get_request: path %s", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    mod_node_init(&mod_node);

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

    k = (const char *)"tcid";
    v = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == v)
    {
        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error: crfshttps_handle_wait_header_get_request: path %s, tcid absence", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    MOD_NODE_TCID(&mod_node)= c_ipv4_to_word(v);

    k = (const char *)"comm";
    v = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == v)
    {
        MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    }
    else
    {
        MOD_NODE_COMM(&mod_node) = c_str_to_word(v);
    }

    k = (const char *)"rank";
    v = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == v)
    {
        MOD_NODE_RANK(&mod_node) = CMPI_ANY_RANK;
    }
    else
    {
        MOD_NODE_RANK(&mod_node) = c_str_to_word(v);
    }

    wait_num  = chttps_node_get_header(chttps_node, (const char *)"wait-num");
    if(NULL_PTR == wait_num)
    {
        char    *wait_key;
        char    *wait_val;

        CSTRING  wait_key_cstr;
        CSTRING  wait_val_cstr;

        wait_key  = chttps_node_get_header(chttps_node, (const char *)"wait-key");
        if(NULL_PTR == wait_key)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to 'wait-key' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to 'wait-key' absence", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        wait_val  = chttps_node_get_header(chttps_node, (const char *)"wait-val");
        if(NULL_PTR == wait_val)
        {
#if 1
            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_wait_header_get_request: crfs wait %s would remove header ['%s'] due to 'wait-val' absence\n",
                                (char *)cstring_get_str(&path_cstr), wait_key);
#endif
#if 0
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to 'wait-val' absence\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to 'wait-val' absence", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        cstring_set_str(&wait_key_cstr, (UINT8 *)wait_key);
        cstring_set_str(&wait_val_cstr, (UINT8 *)wait_val);

        if(EC_FALSE == crfs_wait_http_header(CSOCKET_CNODE_MODI(csocket_cnode), &mod_node, &path_cstr, &wait_key_cstr, &wait_val_cstr, &header_ready))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed\n",
                                (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed", (char *)cstring_get_str(&path_cstr));

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_wait_header_get_request: crfs wait %s done\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_wait_header_get_request: crfs wait %s done", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        cstrkv_mgr_add_kv_str(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node), (char *)"header-ready", c_bool_str(header_ready));

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    cstrkv_mgr = cstrkv_mgr_new();
    if(NULL_PTR == cstrkv_mgr)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to new cstrkv_mgr failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to new cstrkv_mgr failed",
                (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    num = c_str_to_uint32_t(wait_num);
    for(idx = 0; idx < num; idx ++)
    {
        char     wait_key_tag[ 16 ];
        char     wait_val_tag[ 16 ];

        char    *wait_key;
        char    *wait_val;

        snprintf(wait_key_tag, sizeof(wait_key_tag)/sizeof(wait_key_tag[ 0 ]), "wait-key-%u", idx + 1);
        snprintf(wait_val_tag, sizeof(wait_val_tag)/sizeof(wait_val_tag[ 0 ]), "wait-val-%u", idx + 1);

        wait_key  = chttps_node_get_header(chttps_node, (const char *)wait_key_tag);
        if(NULL_PTR == wait_key)
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)wait_key_tag);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to '%s' absence",
                    (char *)cstring_get_str(&path_cstr), (char *)wait_key_tag);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }

        wait_val  = chttps_node_get_header(chttps_node, (const char *)wait_val_tag);
        if(NULL_PTR == wait_val)
        {
#if 1
            dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_handle_wait_header_get_request: crfs wait %s would remove header ['%s'] due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), wait_key, (char *)wait_val_tag);
#endif
#if 0
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to '%s' absence\n",
                                (char *)cstring_get_str(&path_cstr), (char *)wait_val_tag);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to '%s' absence",
                    (char *)cstring_get_str(&path_cstr), (char *)wait_val_tag);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
#endif
        }

        if(EC_FALSE == cstrkv_mgr_add_kv_str(cstrkv_mgr, wait_key, wait_val))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to add '%s:%s' failed\n",
                                (char *)cstring_get_str(&path_cstr), wait_key, wait_val);

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed due to add '%s:%s' failed",
                    (char *)cstring_get_str(&path_cstr), wait_key, wait_val);

            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_INTERNAL_SERVER_ERROR;

            cstrkv_mgr_free(cstrkv_mgr);
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
    }

    if(EC_FALSE == crfs_wait_http_headers(CSOCKET_CNODE_MODI(csocket_cnode), &mod_node, &path_cstr, cstrkv_mgr, &header_ready))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed\n",
                            (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_wait_header_get_request: crfs wait %s failed", (char *)cstring_get_str(&path_cstr));

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_wait_header_get_request: crfs wait %s done\n",
                        (char *)cstring_get_str(&path_cstr));

    CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
    CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_wait_header_get_request: crfs wait %s done", (char *)cstring_get_str(&path_cstr));

    CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

    cstrkv_mgr_add_kv_str(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node), (char *)"header-ready", c_bool_str(header_ready));

    cstrkv_mgr_free(cstrkv_mgr);
    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_wait_header_get_response(CHTTPS_NODE *chttps_node)
{
    if(do_log(SEC_0158_CRFSHTTPS, 9))
    {
        CBUFFER       *uri_cbuffer;
        uint8_t       *cache_key;
        uint32_t       cache_len;

        uri_cbuffer    = CHTTPS_NODE_URI(chttps_node);
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/wait_header");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/wait_header");

        sys_log(LOGSTDOUT, "[DEBUG] crfshttps_make_wait_header_get_response: path %.*s\n", cache_len, cache_key);
    }

    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_wait_header_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_wait_header_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_kvs(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_file_wait_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_wait_header_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_wait_header_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_wait_header_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#if 1
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: locked_file_retire ----------------------------------------*/
STATIC_CAST static EC_BOOL __crfshttps_uri_is_locked_file_retire_get_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;

    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/locked_file_retire") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/locked_file_retire")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_is_http_get_locked_file_retire(const CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0158_CRFSHTTPS, 9)(LOGSTDOUT, "[DEBUG] crfshttps_is_http_get_locked_file_retire: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfshttps_uri_is_locked_file_retire_get_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfshttps_commit_locked_file_retire_get_request(CHTTPS_NODE *chttps_node)
{
    EC_BOOL ret;

    if(EC_FALSE == crfshttps_handle_locked_file_retire_get_request(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_get_request: handle 'GET' request failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfshttps_make_locked_file_retire_get_response(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_get_request: make 'GET' response failed\n");
        return (EC_FALSE);
    }

    ret = crfshttps_commit_locked_file_retire_get_response(chttps_node);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_get_request: commit 'GET' response failed\n");
        return (EC_FALSE);
    }

    return (ret);
}

EC_BOOL crfshttps_handle_locked_file_retire_get_request(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *uri_cbuffer;

    UINT32         req_body_chunk_num;

    CBYTES        *content_cbytes;

    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    req_body_chunk_num = chttps_node_recv_chunks_num(chttps_node);
    /*CRFSHTTPS_ASSERT(0 == req_body_chunk_num);*/
    if(!(0 == req_body_chunk_num))
    {
        CHUNK_MGR *req_body_chunks;

        req_body_chunks = chttps_node_recv_chunks(chttps_node);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_locked_file_retire_get_request: chunk num %ld\n", req_body_chunk_num);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_locked_file_retire_get_request: chunk mgr %p info\n", req_body_chunks);
        chunk_mgr_print_info(LOGSTDOUT, req_body_chunks);

        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error: crfshttps_handle_locked_file_retire_get_request: chunk mgr %p chars\n", req_body_chunks);
        chunk_mgr_print_chars(LOGSTDOUT, req_body_chunks);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_ERR %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_locked_file_retire_get_request");

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_BAD_REQUEST;
        return (EC_TRUE);
    }

    content_cbytes = CHTTPS_NODE_CONTENT_CBYTES(chttps_node);
    cbytes_clean(content_cbytes);

    if(EC_TRUE == __crfshttps_uri_is_locked_file_retire_get_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;

        char    *retire_max_num_str;
        UINT32   retire_max_num;
        UINT32   retire_num;

        retire_max_num_str = chttps_node_get_header(chttps_node, (const char *)"retire-max-num");
        retire_max_num     = c_str_to_word(retire_max_num_str);
        retire_num         = 0;

        dbg_log(SEC_0158_CRFSHTTPS, 1)(LOGSTDOUT, "[DEBUG] crfshttps_handle_locked_file_retire_get_request: header retire-max-num %s => %ld\n",
                                retire_max_num_str, retire_max_num);

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(EC_FALSE == crfs_locked_file_retire(CSOCKET_CNODE_MODI(csocket_cnode), retire_max_num, &retire_num))
        {
            CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_FORBIDDEN;

            CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
            CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
            CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "error:crfshttps_handle_locked_file_retire_get_request failed");

            return (EC_TRUE);
        }

        dbg_log(SEC_0158_CRFSHTTPS, 5)(LOGSTDOUT, "[DEBUG] crfshttps_handle_locked_file_retire_get_request: complete %ld\n", retire_num);

        CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node);
        CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, "RFS_SUCC %s %u --", "GET", CHTTP_OK);
        CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, "[DEBUG] crfshttps_handle_locked_file_retire_get_request: complete %ld", retire_num);

        CHTTPS_NODE_RSP_STATUS(chttps_node) = CHTTP_OK;

        /*prepare response header*/
        cstrkv_mgr_add_kv_str(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node), (char *)"retire-completion", c_word_to_str(retire_num));
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_make_locked_file_retire_get_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_get_response: make response header failed\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        if(EC_FALSE == chttps_make_response_header_keepalive(chttps_node))
        {
            dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_get_response: make response header keepalive failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_make_response_header_kvs(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_get_response: make header kvs failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_make_locked_file_retire_get_response: make header end failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfshttps_commit_locked_file_retire_get_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0158_CRFSHTTPS, 0)(LOGSTDOUT, "error:crfshttps_commit_locked_file_retire_get_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }

    return crfshttps_commit_response(chttps_node);
}
#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

