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

#include "cbytes.h"

#include "cmisc.h"

#include "cmpie.h"

#include "task.h"

#include "chttp.h"
#include "chttps.h"

#include "crfshttp.h"
#include "crfshttps.h"

#include "cxfshttp.h"
#include "cxfshttps.h"

#include "ccache.h"

#include "findex.inc"

/*---------------------------------------- HTTP PASER INTERFACE ----------------------------------------*/
int ccache_on_http_message_begin(http_parser_t* http_parser)
{
    CHTTP_RSP  *chttp_rsp;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_message_begin: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_message_begin: "
                                            "chttp_rsp %p, ***MESSAGE BEGIN***\n",
                                            chttp_rsp);
    return (0);
}

int ccache_on_http_headers_complete(http_parser_t* http_parser, const char* last, size_t length)
{
    CHTTP_RSP     *chttp_rsp;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_headers_complete: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_headers_complete: "
                                            "http_parser %p done\n",
                                            http_parser);
    return (0);/*succ*/
}

int ccache_on_http_message_complete(http_parser_t* http_parser)
{
    CHTTP_RSP     *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_message_complete: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_message_complete: "
                                            "http_parser %p done\n",
                                            http_parser);
    return (0);
}

int ccache_on_http_url(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_url: "
                                               "http_parser %p -> chttp_rsp is null\n",
                                               http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_url: "
                                           "chttp_rsp %p, url: %.*s\n",
                                           chttp_rsp, (uint32_t)length, at);

    return (0);
}

/*only for http response*/
int ccache_on_http_status(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_status: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    CHTTP_RSP_STATUS(chttp_rsp) = http_parser->status_code;

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_status: "
                                            "http_parser %p => status %d done\n",
                                            http_parser, http_parser->status_code);

    return (0);
}

int ccache_on_http_header_field(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;
    CSTRKV       *cstrkv;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_header_field: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_header_field: "
                                               "new cstrkv failed where header field: %.*s\n",
                                               (uint32_t)length, at);
        return (-1);
    }

    cstrkv_set_key_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CCACHE_0001);
    cstrkv_mgr_add_kv(CHTTP_RSP_HEADER(chttp_rsp), cstrkv);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_header_field: "
                                           "chttp_rsp %p, Header field: '%.*s'\n",
                                           chttp_rsp, (uint32_t)length, at);
    return (0);
}

int ccache_on_http_header_value(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;
    CSTRKV       *cstrkv;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_header_value: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    cstrkv = cstrkv_mgr_last_kv(CHTTP_RSP_HEADER(chttp_rsp));
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_header_value: "
                                               "no cstrkv existing where value field: %.*s\n",
                                               (uint32_t)length, at);
        return (-1);
    }

    cstrkv_set_val_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CCACHE_0002);
    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_header_value: "
                                           "chttp_rsp %p, Header value: '%.*s'\n",
                                           chttp_rsp, (uint32_t)length, at);

    return (0);
}

int ccache_on_http_body(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP     *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_http_body: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    cbytes_append(CHTTP_RSP_BODY(chttp_rsp), (uint8_t *)at, length);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_http_body: "
                                           "chttp_rsp %p, body len %d\n",
                                           chttp_rsp, (uint32_t)length);
    return (0);
}

EC_BOOL ccache_parse_http_header(const CBYTES *header_cbytes, CHTTP_RSP *chttp_rsp)
{
    http_parser_t                http_parser;
    http_parser_settings_t       http_parser_setting;

    uint32_t                     parsed_len;


    http_parser_init(&http_parser, HTTP_RESPONSE);
    http_parser.state = s_header_field_start;
    http_parser.data  = (void *)chttp_rsp;

    http_parser_setting.on_message_begin    = ccache_on_http_message_begin;/*xxx*/
    http_parser_setting.on_url              = ccache_on_http_url;/*xxx*/
    http_parser_setting.on_status           = ccache_on_http_status;/*xxx*/
    http_parser_setting.on_header_field     = ccache_on_http_header_field;
    http_parser_setting.on_header_value     = ccache_on_http_header_value;
    http_parser_setting.on_headers_complete = ccache_on_http_headers_complete;
    http_parser_setting.on_body             = ccache_on_http_body;
    http_parser_setting.on_message_complete = ccache_on_http_message_complete;

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_parse_http_header: to parse '%.*s'\n",
                (uint32_t)CBYTES_LEN(header_cbytes), (char *)CBYTES_BUF(header_cbytes));

    parsed_len = http_parser_execute(&http_parser, &http_parser_setting,
                                     (char *)CBYTES_BUF(header_cbytes), CBYTES_LEN(header_cbytes));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_parse_http_header: "
                                           "parsed %u, cbytes len %ld \n",
                                           parsed_len, CBYTES_LEN(header_cbytes));

    if(HPE_OK != HTTP_PARSER_ERRNO(&http_parser))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT,
                            "error:ccache_parse_http_header: "
                            "http parser encounter error "
                            "where errno = %d, name = %s, description = %s\n\n",
                            HTTP_PARSER_ERRNO(&http_parser),
                            http_errno_name(HTTP_PARSER_ERRNO(&http_parser)),
                            http_errno_description(HTTP_PARSER_ERRNO(&http_parser))
                            );
        return (EC_FALSE);
    }

    ASSERT(parsed_len == (uint32_t)CBYTES_LEN(header_cbytes));

    if(do_log(SEC_0177_CCACHE, 9))
    {
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_parse_http_header: header '%.*s' => \n",
                    (uint32_t)CBYTES_LEN(header_cbytes), (char *)CBYTES_BUF(header_cbytes));

        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}

EC_BOOL ccache_trigger_http_request_merge(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;

    /*make receiver: send to myself*/
    task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                &recv_mod_node,
                NULL_PTR, FI_super_http_request_merge, CMPI_ERROR_MODI, chttp_req, chttp_store, chttp_rsp, chttp_stat);

    return (EC_TRUE);
}

EC_BOOL ccache_file_write(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *auth_token)
{
    return ccache_file_write_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, cbytes, auth_token);
}

EC_BOOL ccache_renew_headers(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token)
{
    return ccache_renew_headers_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, cstrkv_mgr, auth_token);
}

EC_BOOL ccache_file_notify(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    return ccache_file_notify_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path);
}

EC_BOOL ccache_file_terminate(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    return ccache_file_terminate_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path);
}

EC_BOOL ccache_file_lock(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already)
{
    return ccache_file_lock_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    file_path, expire_nsec, auth_token,locked_already);
}

EC_BOOL ccache_file_unlock(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                const CSTRING *file_path, const CSTRING *auth_token)
{
    return ccache_file_unlock_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                        file_path, auth_token);
}

EC_BOOL ccache_file_read(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                            CBYTES  *cbytes)
{
    return ccache_file_read_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                        file_path, store_start_offset, store_end_offset,
                        cbytes);
}

EC_BOOL ccache_file_retire(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path)
{

    return ccache_file_retire_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                       file_path);
}

EC_BOOL ccache_file_wait(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                            UINT32 *content_length, UINT32 *data_ready)
{
    return ccache_file_wait_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                     file_path, store_start_offset, store_end_offset,
                                     content_length, data_ready);
}

EC_BOOL ccache_file_wait_and_read(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES *content_cbytes)
{
    UINT32  data_ready;
    UINT32  content_length;

    if(EC_FALSE == ccache_file_wait(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    file_path,
                                    store_start_offset, store_end_offset,
                                    &content_length, &data_ready))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_and_read: wait file '%s' from cache failed\n",
                    (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    if(EC_FALSE == data_ready)
    {
        UINT32         timeout_msec;

        UINT32         tag;

        /*timeout_msec = 60 * 1000;*/
        timeout_msec = TASK_DEFAULT_LIVE * 1000;

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            tag = MD_CXFS;
        }

        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            tag = MD_CRFS;
        }

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_and_read: cond wait '%s' => go\n",
                        (char *)cstring_get_str(file_path));
        if(EC_FALSE == super_cond_wait(0, tag, file_path, timeout_msec))
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_and_read: cond wait '%s' failed\n",
                        (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_and_read: cond wait '%s' <= back\n",
                        (char *)cstring_get_str(file_path));
    }

    if(EC_FALSE == ccache_file_read(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    file_path, store_start_offset, store_end_offset,
                                    content_cbytes))
    {
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "error:ccache_file_wait_and_read: read '%s' from cache failed\n",
                    (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_and_read: read '%s' with len %ld from cache done\n",
                (char *)cstring_get_str(file_path), CBYTES_LEN(content_cbytes));

    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_ready(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path,
                            UINT32 *data_ready)
{
    return ccache_file_wait_ready_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                           file_path,
                                           data_ready);
}

EC_BOOL ccache_wait_http_headers(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                    const CSTRING *file_path,
                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    return ccache_wait_http_headers_over_bgn(store_srv_tcid,  store_srv_ipaddr,  store_srv_port,
                                             file_path,
                                             cstrkv_mgr, header_ready);
}

EC_BOOL ccache_dir_delete(const CSTRING *file_path)
{
    return ccache_dir_delete_over_bgn(file_path);
}

EC_BOOL ccache_billing_set(const UINT32 billing_srv_ipaddr, const UINT32 billing_srv_port,
                              const CSTRING *billing_flags,
                              const CSTRING *billing_domain, const CSTRING *billing_client_type,
                              const UINT32 send_len, const UINT32 recv_len)
{
    dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_billing_set: not support bgn interface\n");
    return (EC_FALSE);
}



/*-------------------------- interact with http and bgn --------------------------*/
EC_BOOL ccache_file_write_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *auth_token)
{
    //TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;
    EC_BOOL        ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    /*make receiver*/
    //task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs or xfs*/

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_write_over_bgn: p2p: [token %s] file_path '%.*s', data %p [len %ld] => store_srv_tcid %s\n",
                (char *)cstring_get_str(auth_token),
                (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path), CBYTES_BUF(cbytes), CBYTES_LEN(cbytes),
                c_word_to_ipv4(store_srv_tcid));

    ret = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_crfs_update_with_token, CMPI_ERROR_MODI, file_path, cbytes, auth_token);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_update_with_token, CMPI_ERROR_MODI, file_path, cbytes, auth_token);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] UPDATE %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));
    }
    else
    {
        sys_log(LOGUSER09, "[SUCC] UPDATE %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));
    }

    return (ret);
}

EC_BOOL ccache_renew_headers_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token)
{
    //TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;
    EC_BOOL        ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    /*make receiver*/
    //task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs or xfs*/

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_renew_headers_over_bgn: renew headers of '%.*s' on tcid %s\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    ret = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        if(NULL_PTR != auth_token)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_crfs_renew_http_headers_with_token, CMPI_ERROR_MODI, file_path, cstrkv_mgr, auth_token);
        }
        else
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_crfs_renew_http_headers, CMPI_ERROR_MODI, file_path, cstrkv_mgr);
        }
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        if(NULL_PTR != auth_token)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cxfs_renew_http_headers_with_token, CMPI_ERROR_MODI, file_path, cstrkv_mgr, auth_token);
        }
        else
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cxfs_renew_http_headers, CMPI_ERROR_MODI, file_path, cstrkv_mgr);
        }
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] RENEWH %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));
    }
    else
    {
        sys_log(LOGUSER09, "[SUCC] RENEWH %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));
    }

    return (EC_TRUE);
}

EC_BOOL ccache_file_notify_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    //TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;

    /*make receiver*/
    //task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs or xfs*/

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_notify_over_bgn: p2p: file_path '%.*s'[NONE] => tcid %s\n",
                (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                c_word_to_ipv4(store_srv_tcid));

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                        &recv_mod_node,
                        NULL_PTR, FI_crfs_file_notify, CMPI_ERROR_MODI, file_path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                        &recv_mod_node,
                        NULL_PTR, FI_cxfs_file_notify, CMPI_ERROR_MODI, file_path);
    }

    return (EC_TRUE);
}

EC_BOOL ccache_file_terminate_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    //TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;
    EC_BOOL        ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    /*make receiver*/
    //task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs or xfs*/

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_terminate_over_bgn: p2p: file_path '%.*s'[NONE] => tcid %s\n",
                (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                c_word_to_ipv4(store_srv_tcid));

    ret = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_crfs_file_terminate, CMPI_ERROR_MODI, file_path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_file_terminate, CMPI_ERROR_MODI, file_path);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] TERMINATE %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));
    }
    else
    {
        sys_log(LOGUSER09, "[SUCC] TERMINATE %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));
    }

    return (EC_TRUE);
}

EC_BOOL ccache_file_lock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already)
{
    MOD_NODE     recv_mod_node;
    EC_BOOL      ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0 or cxfs_md_id = 0*/

    ret = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_crfs_file_lock, CMPI_ERROR_MODI, file_path, expire_nsec, auth_token, locked_already);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_lock, CMPI_ERROR_MODI, file_path, expire_nsec, auth_token, locked_already);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        if(EC_TRUE == (*locked_already))
        {
            sys_log(LOGUSER09, "[SUCC] LOCK %ld %s %s\n",
                               e_time_msec - s_time_msec,
                               c_word_to_ipv4(store_srv_tcid),
                               (char *)cstring_get_str(file_path));

            dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_lock_over_bgn: lock_req '%.*s' on %s => locked by other\n",
                            (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                            c_word_to_ipv4(store_srv_tcid));
            return (EC_TRUE);
        }

        sys_log(LOGUSER09, "[FAIL] LOCK %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    sys_log(LOGUSER09, "[SUCC] LOCK %ld %s %s\n",
                       e_time_msec - s_time_msec,
                       c_word_to_ipv4(store_srv_tcid),
                       (char *)cstring_get_str(file_path));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_lock_over_bgn: lock_req '%.*s' on %s => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_file_unlock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                           const CSTRING *file_path, const CSTRING *auth_token)
{
    MOD_NODE     recv_mod_node;
    EC_BOOL      ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0 or cxfs_md_id = 0*/

    ret = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_crfs_file_unlock, CMPI_ERROR_MODI, file_path, auth_token);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_unlock, CMPI_ERROR_MODI, file_path, auth_token);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] UNLOCK %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_unlock_over_bgn: "
                                               "unlock_req '%.*s' with token '%.*s' on %s => failed\n",
                                               (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                                               (uint32_t)CSTRING_LEN(auth_token), (char *)CSTRING_STR(auth_token),
                                               c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    sys_log(LOGUSER09, "[SUCC] UNLOCK %ld %s %s\n",
                       e_time_msec - s_time_msec,
                       c_word_to_ipv4(store_srv_tcid),
                       (char *)cstring_get_str(file_path));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_unlock_over_bgn: "
                                           "unlock_req '%.*s' with token '%.*s' on %s => OK\n",
                                           (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                                           (uint32_t)CSTRING_LEN(auth_token), (char *)CSTRING_STR(auth_token),
                                           c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_file_read_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES  *content_cbytes)
{
    MOD_NODE                     recv_mod_node;

    EC_BOOL                      ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs or xfs*/

    ret = EC_FALSE;

    if(CHTTP_SEG_ERR_OFFSET != store_start_offset
    && CHTTP_SEG_ERR_OFFSET != store_end_offset
    && store_end_offset >= store_start_offset)
    {
        UINT32                       store_offset;
        UINT32                       store_size;

        store_offset = store_start_offset;
        store_size   = store_end_offset + 1 - store_start_offset;

        s_time_msec = c_get_cur_time_msec();

        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_crfs_read_e, CMPI_ERROR_MODI, file_path, &store_offset, store_size, content_cbytes);
        }

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_read_e, CMPI_ERROR_MODI, file_path, &store_offset, store_size, content_cbytes);
        }

        e_time_msec = c_get_cur_time_msec();

        if(EC_FALSE == ret)
        {
            sys_log(LOGUSER09, "[FAIL] READE %ld %s %s\n",
                               e_time_msec - s_time_msec,
                               c_word_to_ipv4(store_srv_tcid),
                               (char *)cstring_get_str(file_path));

            dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "error:ccache_file_read_over_bgn: read_e '%s' from cache failed\n",
                        (char *)cstring_get_str(file_path));

            return (EC_FALSE);
        }

        sys_log(LOGUSER09, "[SUCC] READE %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_bgn: read_e '%s' from cache done\n",
                    (char *)cstring_get_str(file_path));

        return (EC_TRUE);
    }

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_crfs_read, CMPI_ERROR_MODI, file_path, content_cbytes);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_cxfs_read, CMPI_ERROR_MODI, file_path, content_cbytes);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] READ %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "error:ccache_file_read_over_bgn: read '%s' from cache failed\n",
                    (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    sys_log(LOGUSER09, "[SUCC] READ %ld %s %s\n",
                       e_time_msec - s_time_msec,
                       c_word_to_ipv4(store_srv_tcid),
                       (char *)cstring_get_str(file_path));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_bgn: read '%s' from cache done\n",
                (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL ccache_file_retire_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                         const CSTRING *file_path)
{
    MOD_NODE                     recv_mod_node;
    EC_BOOL                      ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0 or cxfs_md_id = 0*/

    ret = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_crfs_delete, CMPI_ERROR_MODI, file_path, (UINT32)CRFSNP_ITEM_FILE_IS_REG);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_cxfs_delete, CMPI_ERROR_MODI, file_path, (UINT32)CRFSNP_ITEM_FILE_IS_REG);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] DELETE %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_retire_over_bgn: file_retire '%s' on %s failed\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    sys_log(LOGUSER09, "[SUCC] DELETE %ld %s %s\n",
                       e_time_msec - s_time_msec,
                       c_word_to_ipv4(store_srv_tcid),
                       (char *)cstring_get_str(file_path));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_retire_over_bgn: file_retire '%s' on %s done\n",
                (char *)cstring_get_str(file_path),
                c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        UINT32 *content_length, UINT32 *data_ready)
{
    if(CHTTP_SEG_ERR_OFFSET != store_start_offset
    && CHTTP_SEG_ERR_OFFSET != store_end_offset
    && store_end_offset >= store_start_offset)
    {
        MOD_NODE                     send_mod_node;
        MOD_NODE                     recv_mod_node;
        EC_BOOL                      ret;

        UINT32                       store_offset;
        UINT32                       store_size;

        uint64_t                     s_time_msec;
        uint64_t                     e_time_msec;

        store_offset = store_start_offset;
        store_size   = store_end_offset - store_start_offset + 1;

        MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&send_mod_node) = 0;/*ignore*/

        MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0 or cxfs_md_id = 0*/

        ret = EC_FALSE;

        s_time_msec = c_get_cur_time_msec();

        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_crfs_file_wait_e, CMPI_ERROR_MODI, &send_mod_node,
                file_path, &store_offset, store_size, content_length, data_ready);
        }

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_file_wait_e, CMPI_ERROR_MODI, &send_mod_node,
                file_path, TASK_DEFAULT_LIVE, &store_offset, store_size, content_length, data_ready);
        }

        e_time_msec = c_get_cur_time_msec();

        if(EC_FALSE == ret)
        {
            sys_log(LOGUSER09, "[FAIL] WAITE %ld %s %s\n",
                               e_time_msec - s_time_msec,
                               c_word_to_ipv4(store_srv_tcid),
                               (char *)cstring_get_str(file_path));

            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_over_bgn: file_wait '%s' on %s failed\n",
                        (char *)cstring_get_str(file_path),
                        c_word_to_ipv4(store_srv_tcid));

            return (EC_FALSE);
        }

        sys_log(LOGUSER09, "[SUCC] WAITE %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_over_bgn: file_wait '%s' on %s done\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    }
    else
    {
        MOD_NODE                     send_mod_node;
        MOD_NODE                     recv_mod_node;
        EC_BOOL                      ret;

        uint64_t                     s_time_msec;
        uint64_t                     e_time_msec;

        MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&send_mod_node) = 0;/*ignore*/

        MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0 or cxfs_md_id = 0*/

        ret = EC_FALSE;

        s_time_msec = c_get_cur_time_msec();

        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_crfs_file_wait, CMPI_ERROR_MODI, &send_mod_node, file_path, content_length, data_ready);
        }

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_file_wait, CMPI_ERROR_MODI, &send_mod_node,
                file_path, TASK_DEFAULT_LIVE, content_length, data_ready);
        }

        e_time_msec = c_get_cur_time_msec();

        if(EC_FALSE == ret)
        {
            sys_log(LOGUSER09, "[FAIL] WAIT %ld %s %s\n",
                               e_time_msec - s_time_msec,
                               c_word_to_ipv4(store_srv_tcid),
                               (char *)cstring_get_str(file_path));

            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_over_bgn: file_wait '%s' on %s failed\n",
                        (char *)cstring_get_str(file_path),
                        c_word_to_ipv4(store_srv_tcid));

            return (EC_FALSE);
        }

        sys_log(LOGUSER09, "[SUCC] WAIT %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_over_bgn: file_wait '%s' on %s done\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    }
    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_ready_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                const CSTRING *file_path,
                                                UINT32 *data_ready)
{
    MOD_NODE                     send_mod_node;
    MOD_NODE                     recv_mod_node;

    EC_BOOL                      ret;
    UINT32                       data_ready_t;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&send_mod_node) = 0;/*ignore*/

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0 or cxfs_md_id = 0*/

    ret = EC_FALSE;
    data_ready_t = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_crfs_file_wait_ready, CMPI_ERROR_MODI, &send_mod_node, file_path, &data_ready_t);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_cxfs_file_wait_ready, CMPI_ERROR_MODI, &send_mod_node,
            file_path, TASK_DEFAULT_LIVE, &data_ready_t);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] WAITR %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_ready_over_bgn: file '%s' on %s failed\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    if(NULL_PTR != data_ready)
    {
        (*data_ready) = data_ready_t;
    }

    sys_log(LOGUSER09, "[SUCC] WAITR %ld %s %s\n",
                       e_time_msec - s_time_msec,
                       c_word_to_ipv4(store_srv_tcid),
                       (char *)cstring_get_str(file_path));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_ready_over_bgn: file '%s' on %s done\n",
                (char *)cstring_get_str(file_path),
                c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_wait_http_headers_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                    const CSTRING *file_path,
                                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    MOD_NODE     send_mod_node;
    MOD_NODE     recv_mod_node;
    EC_BOOL      ret;

    uint64_t                     s_time_msec;
    uint64_t                     e_time_msec;

    MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&send_mod_node) = 0;/*ignore*/

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0 or cxfs_md_id = 0*/

    ret = EC_FALSE;

    s_time_msec = c_get_cur_time_msec();

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_crfs_wait_http_headers, CMPI_ERROR_MODI, &send_mod_node,
                 file_path, cstrkv_mgr, header_ready);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_wait_http_headers, CMPI_ERROR_MODI, &send_mod_node,
                 file_path, TASK_DEFAULT_LIVE, cstrkv_mgr, header_ready);
    }

    e_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == ret)
    {
        sys_log(LOGUSER09, "[FAIL] WAITH %ld %s %s\n",
                           e_time_msec - s_time_msec,
                           c_word_to_ipv4(store_srv_tcid),
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_wait_http_headers_over_bgn: wait headers of '%.*s' on %s done => failed\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    sys_log(LOGUSER09, "[SUCC] WAITH %ld %s %s\n",
                       e_time_msec - s_time_msec,
                       c_word_to_ipv4(store_srv_tcid),
                       (char *)cstring_get_str(file_path));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_wait_http_headers_over_bgn: wait headers of '%.*s' on %s done => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_dir_delete_over_bgn(const CSTRING *file_path)
{
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        TASK_BRD    *task_brd;
        TASK_MGR    *task_mgr;

        UINT32       cmon_md_id;

        UINT32       pos;
        UINT32       num;
        EC_BOOL      ret;

        uint64_t                     s_time_msec;
        uint64_t                     e_time_msec;

        task_brd = task_brd_default_get();

        cmon_md_id = TASK_BRD_CMON_ID(task_brd);
        if(CMPI_ERROR_MODI == cmon_md_id)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: no cmon started\n");
            return (EC_FALSE);
        }

        cmon_count_nodes(cmon_md_id, &num);
        if(0 == num)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: store is empty\n");
            return (EC_FALSE);
        }

        s_time_msec = c_get_cur_time_msec();

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        for(pos = 0; pos < num; pos ++)
        {
            CMON_NODE      cmon_node;
            MOD_NODE       recv_mod_node;

            cmon_node_init(&cmon_node);
            if(EC_FALSE == cmon_get_node_by_pos(cmon_md_id, pos, &cmon_node))
            {
                cmon_node_clean(&cmon_node);
                continue;
            }

            if(EC_FALSE == cmon_node_is_up(&cmon_node))
            {
                dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: delete '%.*s' skip rfs %s which is not up\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(CMON_NODE_TCID(&cmon_node))
                        );
                cmon_node_clean(&cmon_node);
                continue;
            }

            MOD_NODE_TCID(&recv_mod_node) = CMON_NODE_TCID(&cmon_node);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs or xfs*/

            task_p2p_inc(task_mgr, 0, &recv_mod_node,
                    &ret, FI_crfs_delete_dir, CMPI_ERROR_MODI, file_path);

            cmon_node_clean(&cmon_node);
        }

        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        e_time_msec = c_get_cur_time_msec();

        sys_log(LOGUSER09, "[SUCC] DELETED %ld %s\n",
                           e_time_msec - s_time_msec,
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: rfs delete '%.*s' done\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path));

        return (EC_TRUE);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        TASK_BRD    *task_brd;
        TASK_MGR    *task_mgr;

        UINT32       cmon_md_id;

        UINT32       pos;
        UINT32       num;
        EC_BOOL      ret;

        uint64_t                     s_time_msec;
        uint64_t                     e_time_msec;

        task_brd = task_brd_default_get();

        cmon_md_id = TASK_BRD_CMON_ID(task_brd);
        if(CMPI_ERROR_MODI == cmon_md_id)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: no cmon started\n");
            return (EC_FALSE);
        }

        cmon_count_nodes(cmon_md_id, &num);
        if(0 == num)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: store is empty\n");
            return (EC_FALSE);
        }

        s_time_msec = c_get_cur_time_msec();

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        for(pos = 0; pos < num; pos ++)
        {
            CMON_NODE      cmon_node;
            MOD_NODE       recv_mod_node;

            cmon_node_init(&cmon_node);
            if(EC_FALSE == cmon_get_node_by_pos(cmon_md_id, pos, &cmon_node))
            {
                cmon_node_clean(&cmon_node);
                continue;
            }

            if(EC_FALSE == cmon_node_is_up(&cmon_node))
            {
                dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: delete '%.*s' skip xfs %s which is not up\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(CMON_NODE_TCID(&cmon_node))
                        );
                cmon_node_clean(&cmon_node);
                continue;
            }

            MOD_NODE_TCID(&recv_mod_node) = CMON_NODE_TCID(&cmon_node);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one xfs*/

            task_p2p_inc(task_mgr, 0, &recv_mod_node,
                    &ret, FI_cxfs_delete_dir, CMPI_ERROR_MODI, file_path);

            cmon_node_clean(&cmon_node);
        }

        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        e_time_msec = c_get_cur_time_msec();

        sys_log(LOGUSER09, "[SUCC] DELETED %ld %s\n",
                           e_time_msec - s_time_msec,
                           (char *)cstring_get_str(file_path));

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: xfs delete '%.*s' done\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path));

        return (EC_TRUE);
    }

    dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: not delete '%.*s' due to invalid switch\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path));
    return (EC_FALSE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

