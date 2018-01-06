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
        log = log_file_open((char *)cstring_get_str(log_file_name), /*"a+"*/"w+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED, SWITCH_OFF,
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
        log = log_file_open((char *)cstring_get_str(log_file_name), /*"a+"*/"w+",
                            TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd),
                            LOGD_FILE_RECORD_LIMIT_ENABLED, SWITCH_OFF,
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
     
        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)ctdnshttp_commit_http_get, 1, chttp_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_request: cthread load for HTTP_GET failed\n");
            return (EC_BUSY);
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CTDNSHTTP_0004); 
     
        return (EC_TRUE);
    }

    if(HTTP_POST == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;
     
        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)ctdnshttp_commit_http_post, 1, chttp_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_request: cthread load for HTTP_POST failed\n");
            return (EC_BUSY);
        }
        CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node);/*record http request was loaded time in coroutine*/
        CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CTDNSHTTP_0005); 

        return (EC_TRUE);
    }

    if(HTTP_HEAD == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;
     
        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)ctdnshttp_commit_http_head, 1, chttp_node);
        if(NULL_PTR == croutine_node)
        {
            dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_commit_request: cthread load for HTTP_HEAD failed\n");
            return (EC_BUSY);
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
    else if (EC_TRUE == ctdnshttp_is_http_get_deltcid(chttp_node))
    {
        ret = ctdnshttp_commit_deltcid_get_request(chttp_node);
    }
    else if (EC_TRUE == ctdnshttp_is_http_get_flush(chttp_node))
    {
        ret = ctdnshttp_commit_flush_get_request(chttp_node);
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
            
            /* unmount */
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

    ret = chttp_node_send_rsp(chttp_node, csocket_cnode);
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
static EC_BOOL __ctdnshttp_uri_is_gettcid_get_op(const CBUFFER *uri_cbuffer)
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
    CBYTES          key_cbytes;    

    tcid_str = chttp_node_get_header(chttp_node, (const char *)"tcid");
    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_gettcid_get_request: no tcid in header\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_gettcid_get_request: no tcid in header");
                         
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
     
        return (EC_TRUE);
    }
    
    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    cbytes_init(&key_cbytes);

    if(EC_FALSE == ctdns_get(CSOCKET_CNODE_MODI(csocket_cnode), c_ipv4_to_word(tcid_str), &ipaddr, &key_cbytes))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_gettcid_get_request: not found tcid '%s'\n", tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_gettcid_get_request: not found tcid '%s'", tcid_str);
                         
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;

        cbytes_clean(&key_cbytes);
        return (EC_TRUE);        
    }


    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_gettcid_get_request: get tcid '%s' done\n", tcid_str);

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u %ld", "GET", CHTTP_OK, (UINT32)0);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_gettcid_get_request: get tcid '%s' done", tcid_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;

    /*prepare response header*/
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"tcid", tcid_str);
    cstrkv_mgr_add_kv_str(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"ip", c_word_to_ipv4(ipaddr));

    cstrkv_mgr_add_kv_chars(CHTTP_NODE_HEADER_OUT_KVS(chttp_node), (const char *)"service", strlen("service"), 
                                   (const char *)CBYTES_BUF(&key_cbytes), (uint32_t)CBYTES_LEN(&key_cbytes));

    cbytes_clean(&key_cbytes);

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
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: settcid ----------------------------------------*/
static EC_BOOL __ctdnshttp_uri_is_settcid_get_op(const CBUFFER *uri_cbuffer)
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
    const char    * tcid_str;
    const char    * ipaddr_str;
    const char    * key_str;

    CBYTES          key_cbytes;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    tcid_str   = chttp_node_get_header(chttp_node, (const char *)"tcid");
    ipaddr_str = chttp_node_get_header(chttp_node, (const char *)"ip");
    key_str    = chttp_node_get_header(chttp_node, (const char *)"service");

    if(NULL_PTR == tcid_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: tcid absence\n");

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: tcid absence");
                         
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
     
        return (EC_TRUE);
    }

    if(NULL_PTR == ipaddr_str)
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: tcid '%s', ip absence\n", tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_BAD_REQUEST);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: tcid '%s', ip absence", tcid_str);
                         
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_BAD_REQUEST;
     
        return (EC_TRUE);
    }        

    cbytes_init(&key_cbytes);

    if(NULL_PTR != key_str)
    {
        cbytes_mount(&key_cbytes, strlen(key_str), (const UINT8 *)key_str);
    }

    if(EC_FALSE == ctdns_set(CSOCKET_CNODE_MODI(csocket_cnode), c_ipv4_to_word(tcid_str), c_ipv4_to_word(ipaddr_str), &key_cbytes))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_settcid_get_request: set (tcid '%s', ip '%s', key '%s') failed\n", 
                        tcid_str, ipaddr_str, key_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_FORBIDDEN);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_settcid_get_request: set (tcid '%s', ip '%s', key '%s') failed", 
                        tcid_str, ipaddr_str, key_str);
                         
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_FORBIDDEN;
     
        return (EC_TRUE);
    }
   
    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_settcid_get_request: set (tcid '%s', ip '%s', key '%s') done\n",
                        tcid_str, ipaddr_str, key_str); 

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_settcid_get_request: set (tcid '%s', ip '%s', key '%s') done", 
                        tcid_str, ipaddr_str, key_str);

    CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_OK;


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
static EC_BOOL __ctdnshttp_uri_is_deltcid_get_op(const CBUFFER *uri_cbuffer)
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

    tcid_str   = chttp_node_get_header(chttp_node, (const char *)"tcid");

    if(EC_FALSE == ctdns_delete(CSOCKET_CNODE_MODI(csocket_cnode), c_ipv4_to_word(tcid_str)))
    {
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_deltcid_get_request: ctdns delete tcid %s failed\n",
                            tcid_str);

        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_NOT_FOUND);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_deltcid_get_request: ctdns delete tcid %s failed", 
                            tcid_str);
                         
        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_NOT_FOUND;
     
        return (EC_TRUE);
    }
    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_deltcid_get_request: ctdns delete tcid %s done\n",
                        tcid_str); 

    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_deltcid_get_request: ctdns delete tcid %s done", 
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
/*---------------------------------------- HTTP METHOD: GET, FILE OPERATOR: flush ----------------------------------------*/
static EC_BOOL __ctdnshttp_uri_is_flush_get_op(const CBUFFER *uri_cbuffer)
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
        dbg_log(SEC_0048_CTDNSHTTP, 0)(LOGSTDOUT, "error:ctdnshttp_handle_flush_get_request: ctdns flush failed\n");
        CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
        CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_FAIL %s %u --", "GET", CHTTP_INTERNAL_SERVER_ERROR);
        CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "error:ctdnshttp_handle_flush_get_request: ctdns flush failed");

        CHTTP_NODE_RSP_STATUS(chttp_node) = CHTTP_INTERNAL_SERVER_ERROR;

        return (EC_TRUE);
    }
 
    dbg_log(SEC_0048_CTDNSHTTP, 5)(LOGSTDOUT, "[DEBUG] ctdnshttp_handle_flush_get_request: ctdns flush done\n");
    CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node);
    CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, "TDNS_SUCC %s %u --", "GET", CHTTP_OK);
    CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, "[DEBUG] ctdnshttp_handle_flush_get_request: ctdns flush done");

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


#ifdef __cplusplus
}
#endif/*__cplusplus*/

