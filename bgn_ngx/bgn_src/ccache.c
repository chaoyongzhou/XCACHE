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

#include "crfshttp.h"
#include "cxfshttp.h"

#include "ccache.h"

#include "findex.inc"

/*---------------------------------------- HTTP PASER INTERFACE ----------------------------------------*/
int ccache_on_message_begin(http_parser_t* http_parser)
{
    CHTTP_RSP  *chttp_rsp;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_message_begin: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_message_begin: "
                                            "chttp_rsp %p, ***MESSAGE BEGIN***\n",
                                            chttp_rsp);
    return (0);
}

int ccache_on_headers_complete(http_parser_t* http_parser, const char* last, size_t length)
{
    CHTTP_RSP     *chttp_rsp;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_headers_complete: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_headers_complete: "
                                            "http_parser %p done\n",
                                            http_parser);
    return (0);/*succ*/
}

int ccache_on_message_complete(http_parser_t* http_parser)
{
    CHTTP_RSP     *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_message_complete: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_message_complete: "
                                            "http_parser %p done\n",
                                            http_parser);
    return (0);
}

int ccache_on_url(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_url: "
                                               "http_parser %p -> chttp_rsp is null\n",
                                               http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_url: "
                                           "chttp_rsp %p, url: %.*s\n",
                                           chttp_rsp, (uint32_t)length, at);

    return (0);
}

/*only for http response*/
int ccache_on_status(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_status: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    CHTTP_RSP_STATUS(chttp_rsp) = http_parser->status_code;

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_status: "
                                            "http_parser %p => status %d done\n",
                                            http_parser, http_parser->status_code);

    return (0);
}

int ccache_on_header_field(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;
    CSTRKV       *cstrkv;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_header_field: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_header_field: "
                                               "new cstrkv failed where header field: %.*s\n",
                                               (uint32_t)length, at);
        return (-1);
    }

    cstrkv_set_key_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CCACHE_0001);
    cstrkv_mgr_add_kv(CHTTP_RSP_HEADER(chttp_rsp), cstrkv);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_header_field: "
                                           "chttp_rsp %p, Header field: '%.*s'\n",
                                           chttp_rsp, (uint32_t)length, at);
    return (0);
}

int ccache_on_header_value(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;
    CSTRKV       *cstrkv;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_header_value: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    cstrkv = cstrkv_mgr_last_kv(CHTTP_RSP_HEADER(chttp_rsp));
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_header_value: "
                                               "no cstrkv existing where value field: %.*s\n",
                                               (uint32_t)length, at);
        return (-1);
    }

    cstrkv_set_val_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CCACHE_0002);
    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_header_value: "
                                           "chttp_rsp %p, Header value: '%.*s'\n",
                                           chttp_rsp, (uint32_t)length, at);

    return (0);
}

int ccache_on_body(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP     *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_on_body: "
                                                "http_parser %p -> chttp_rsp is null\n",
                                                http_parser);
        return (-1);/*error*/
    }

    cbytes_append(CHTTP_RSP_BODY(chttp_rsp), (uint8_t *)at, length);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_on_body: "
                                           "chttp_rsp %p, body len %d\n",
                                           chttp_rsp, (uint32_t)length);
    return (0);
}

EC_BOOL ccache_parse_header(const CBYTES *header_cbytes, CHTTP_RSP *chttp_rsp)
{
    http_parser_t                http_parser;
    http_parser_settings_t       http_parser_setting;

    uint32_t                     parsed_len;


    http_parser_init(&http_parser, HTTP_RESPONSE);
    http_parser.state = s_header_field_start;
    http_parser.data  = (void *)chttp_rsp;

    http_parser_setting.on_message_begin    = ccache_on_message_begin;/*xxx*/
    http_parser_setting.on_url              = ccache_on_url;/*xxx*/
    http_parser_setting.on_status           = ccache_on_status;/*xxx*/
    http_parser_setting.on_header_field     = ccache_on_header_field;
    http_parser_setting.on_header_value     = ccache_on_header_value;
    http_parser_setting.on_headers_complete = ccache_on_headers_complete;
    http_parser_setting.on_body             = ccache_on_body;
    http_parser_setting.on_message_complete = ccache_on_message_complete;

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_parse_header: to parse '%.*s'\n",
                (uint32_t)CBYTES_LEN(header_cbytes), (char *)CBYTES_BUF(header_cbytes));

    parsed_len = http_parser_execute(&http_parser, &http_parser_setting,
                                     (char *)CBYTES_BUF(header_cbytes), CBYTES_LEN(header_cbytes));

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_parse_header: "
                                           "parsed %u, cbytes len %ld \n",
                                           parsed_len, CBYTES_LEN(header_cbytes));

    if(HPE_OK != HTTP_PARSER_ERRNO(&http_parser))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT,
                            "error:ccache_parse_header: "
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
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_parse_header: header '%.*s' => \n",
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
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_write_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, cbytes, auth_token);
    }

    return ccache_file_write_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, cbytes, auth_token);
}

EC_BOOL ccache_renew_headers(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_renew_headers_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, cstrkv_mgr, auth_token);
    }

    return ccache_renew_headers_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, cstrkv_mgr, auth_token);
}

EC_BOOL ccache_file_notify(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_notify_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path);
    }

    return ccache_file_notify_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path);
}

EC_BOOL ccache_file_terminate(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_terminate_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path);
    }

    return ccache_file_terminate_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path);
}

EC_BOOL ccache_file_lock(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_lock_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                        file_path, expire_nsec, auth_token,locked_already);
    }

    return ccache_file_lock_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    file_path, expire_nsec, auth_token,locked_already);
}

EC_BOOL ccache_file_unlock(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                const CSTRING *file_path, const CSTRING *auth_token)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_unlock_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                            file_path, auth_token);
    }

    return ccache_file_unlock_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                        file_path, auth_token);
}

EC_BOOL ccache_file_read(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                            CBYTES  *cbytes)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_read_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                            file_path, store_start_offset, store_end_offset,
                            cbytes);
    }

    return ccache_file_read_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                        file_path, store_start_offset, store_end_offset,
                        cbytes);
}

EC_BOOL ccache_file_retire(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_retire_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                            file_path);
    }

    return ccache_file_retire_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                       file_path);
}

EC_BOOL ccache_file_wait(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                            CBYTES *content_cbytes, UINT32 *data_ready)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_wait_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                          file_path, store_start_offset, store_end_offset,
                                          content_cbytes, data_ready);
    }

    return ccache_file_wait_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                     file_path, store_start_offset, store_end_offset,
                                     content_cbytes, data_ready);
}

EC_BOOL ccache_file_wait_and_read(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES *content_cbytes)
{
    UINT32  data_ready;

    if(EC_FALSE == ccache_file_wait(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    file_path,
                                    store_start_offset, store_end_offset,
                                    content_cbytes, &data_ready))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_and_read: wait file '%s' from cache failed\n",
                    (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    if(EC_FALSE == data_ready)
    {
        UINT32         timeout_msec;

        UINT32         tag;

        timeout_msec = 60 * 1000;

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

        if(EC_FALSE == ccache_file_read(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                        file_path, store_start_offset, store_end_offset,
                                        content_cbytes))
        {
            dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "error:ccache_file_wait_and_read: read '%s' from cache failed\n",
                        (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_and_read: read '%s' from cache done\n",
                    (char *)cstring_get_str(file_path));
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_and_read: wait_and_read '%s' with len %ld from cache done\n",
                    (char *)cstring_get_str(file_path), CBYTES_LEN(content_cbytes));

    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_ready(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path,
                            UINT32 *data_ready)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_file_wait_ready_over_http(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                                file_path,
                                                data_ready);
    }

    return ccache_file_wait_ready_over_bgn(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                           file_path,
                                           data_ready);
}

EC_BOOL ccache_wait_http_headers(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                    const CSTRING *file_path,
                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_wait_http_headers_over_http(store_srv_tcid,  store_srv_ipaddr,  store_srv_port,
                                                  file_path,
                                                  cstrkv_mgr, header_ready);
    }

    return ccache_wait_http_headers_over_bgn(store_srv_tcid,  store_srv_ipaddr,  store_srv_port,
                                             file_path,
                                             cstrkv_mgr, header_ready);
}

EC_BOOL ccache_dir_delete(const CSTRING *file_path)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_dir_delete_over_http(file_path);
    }

    return ccache_dir_delete_over_bgn(file_path);
}

EC_BOOL ccache_billing_set(const UINT32 billing_srv_ipaddr, const UINT32 billing_srv_port,
                              const CSTRING *billing_flags,
                              const CSTRING *billing_domain, const CSTRING *billing_client_type,
                              const UINT32 send_len, const UINT32 recv_len)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return ccache_billing_set_over_http(billing_srv_ipaddr, billing_srv_port,
                                            billing_flags, billing_domain, billing_client_type,
                                            send_len, recv_len);
    }

    dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_billing_set: not support bgn interface\n");
    return (EC_FALSE);
}



/*-------------------------- interact with http and bgn --------------------------*/
EC_BOOL ccache_file_write_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *auth_token)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"POST");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/update");
    cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), file_path);

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)c_word_to_str(CBYTES_LEN(cbytes)));

    cbytes_mount(CHTTP_REQ_BODY(&chttp_req), CBYTES_LEN(cbytes), CBYTES_BUF(cbytes));/*zero copy*/

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_write_over_http: store '%.*s' with size %ld to %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        CBYTES_LEN(cbytes),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        cbytes_umount(CHTTP_REQ_BODY(&chttp_req), NULL_PTR, NULL_PTR);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        if(EC_FALSE == cstring_is_empty(auth_token))
        {
            /*anyway, unlock the possible locked-file*/
            ccache_file_unlock(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, auth_token);
        }

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_write_over_http: store '%.*s' with size %ld to %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    CBYTES_LEN(cbytes),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    cbytes_umount(CHTTP_REQ_BODY(&chttp_req), NULL_PTR, NULL_PTR);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    if(EC_FALSE == cstring_is_empty(auth_token))
    {
        /*after store data, unlock the possible locked-file*/
        ccache_file_unlock(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, auth_token);
    }

    return (EC_TRUE);
}

EC_BOOL ccache_file_write_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *auth_token)
{
    //TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;
    EC_BOOL        ret;

    /*make receiver*/
    //task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs*/

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_write_over_bgn: p2p: [token %s] file_path '%.*s', data %p [len %ld] => store_srv_tcid %s\n",
                (char *)cstring_get_str(auth_token),
                (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path), CBYTES_BUF(cbytes), CBYTES_LEN(cbytes),
                c_word_to_ipv4(store_srv_tcid));

    ret = EC_FALSE;

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                &recv_mod_node,
                &ret, FI_crfs_update_with_token, CMPI_ERROR_MODI, file_path, cbytes, auth_token);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_update_with_token, CMPI_ERROR_MODI, file_path, cbytes, auth_token);
    }
    return (ret);
}

EC_BOOL ccache_renew_headers_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token)
{
    CHTTP_REQ    chttp_req_t;
    CHTTP_RSP    chttp_rsp_t;
    CLIST_DATA  *clist_data;

    uint32_t     idx;

    chttp_req_init(&chttp_req_t);
    chttp_rsp_init(&chttp_rsp_t);

    chttp_req_set_ipaddr_word(&chttp_req_t, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req_t, store_srv_port);
    chttp_req_set_method(&chttp_req_t, (const char *)"GET");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CRFSHTTP_REST_API_NAME"/renew_header");
    cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), file_path);

    chttp_req_add_header(&chttp_req_t, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req_t, (const char *)"Content-Length", (char *)"0");

    idx = 0;
    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV   *cstrkv;

        char     renew_key_tag[ 16 ];
        char     renew_val_tag[ 16 ];

        cstrkv = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        idx ++;
        snprintf(renew_key_tag, sizeof(renew_key_tag)/sizeof(renew_key_tag[ 0 ]), "renew-key-%u", idx);
        snprintf(renew_val_tag, sizeof(renew_val_tag)/sizeof(renew_val_tag[ 0 ]), "renew-val-%u", idx);

        chttp_req_add_header(&chttp_req_t, (const char *)renew_key_tag, (char *)CSTRKV_KEY_STR(cstrkv));
        chttp_req_add_header(&chttp_req_t, (const char *)renew_val_tag, (char *)CSTRKV_VAL_STR(cstrkv));
    }

    chttp_req_add_header(&chttp_req_t, (const char *)"renew-num", (char *)c_uint32_t_to_str(idx));

    if(EC_FALSE == chttp_request_basic(&chttp_req_t, NULL_PTR, &chttp_rsp_t, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_renew_headers_over_http: renew headers of '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp_t))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_renew_headers_over_http: renew headers of '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp_t));

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_renew_headers_over_http: renew headers of '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req_t);
    chttp_rsp_clean(&chttp_rsp_t);

    if(EC_FALSE == cstring_is_empty(auth_token))
    {
        /*after store data, unlock the possible locked-file*/
        ccache_file_unlock(store_srv_tcid, store_srv_ipaddr, store_srv_port, file_path, auth_token);
    }

    return (EC_TRUE);
}

EC_BOOL ccache_renew_headers_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token)
{
    //TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;
    EC_BOOL        ret;

    /*make receiver*/
    //task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs*/

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_renew_headers_over_bgn: renew headers of '%.*s' on tcid %s\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    ret = EC_FALSE;

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        if(NULL_PTR != auth_token)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                    &recv_mod_node,
                    &ret, FI_crfs_renew_http_headers_with_token, CMPI_ERROR_MODI, file_path, cstrkv_mgr, auth_token);
        }
        else
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                    &recv_mod_node,
                    &ret, FI_crfs_renew_http_headers, CMPI_ERROR_MODI, file_path, cstrkv_mgr);
        }
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        if(NULL_PTR != auth_token)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                    &recv_mod_node,
                    &ret, FI_cxfs_renew_http_headers_with_token, CMPI_ERROR_MODI, file_path, cstrkv_mgr, auth_token);
        }
        else
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                    &recv_mod_node,
                    &ret, FI_cxfs_renew_http_headers, CMPI_ERROR_MODI, file_path, cstrkv_mgr);
        }
    }
    return (EC_TRUE);
}

EC_BOOL ccache_file_notify_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/file_notify");
    cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), file_path);

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_notify_over_http: file_notify '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_notify_over_http: file_notify '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_notify_over_http: file_notify '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

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

EC_BOOL ccache_file_terminate_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/file_terminate");
    cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), file_path);

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_terminate_over_http: file_terminate '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_terminate_over_http: file_terminate '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_terminate_over_http: file_terminate '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_terminate_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path)
{
    //TASK_BRD      *task_brd;
    MOD_NODE       recv_mod_node;
    EC_BOOL        ret;

    /*make receiver*/
    //task_brd = task_brd_default_get();
    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs*/

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_terminate_over_bgn: p2p: file_path '%.*s'[NONE] => tcid %s\n",
                (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                c_word_to_ipv4(store_srv_tcid));

    ret = EC_FALSE;

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                &recv_mod_node,
                &ret, FI_crfs_file_terminate, CMPI_ERROR_MODI, file_path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_file_terminate, CMPI_ERROR_MODI, file_path);
    }
    return (EC_TRUE);
}


EC_BOOL ccache_billing_set_over_http(const UINT32 billing_srv_ipaddr, const UINT32 billing_srv_port,
                                           const CSTRING *billing_flags,
                                           const CSTRING *billing_domain, const CSTRING *billing_client_type,
                                           const UINT32 send_len, const UINT32 recv_len)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, billing_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, billing_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)"http://bill.hpcc/set_rtbilling");

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"close");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"Host" , (char *)"bill.hpcc");
    chttp_req_add_header(&chttp_req, (const char *)"bill-flags"   , (char *)CSTRING_STR(billing_flags));
    chttp_req_add_header(&chttp_req, (const char *)"bill-domain"   , (char *)CSTRING_STR(billing_domain));
    chttp_req_add_header(&chttp_req, (const char *)"client-type" , (char *)CSTRING_STR(billing_client_type));
    chttp_req_add_header(&chttp_req, (const char *)"send-bytes"  , (char *)c_word_to_str(send_len));
    chttp_req_add_header(&chttp_req, (const char *)"recv-bytes"  , (char *)c_word_to_str(recv_len));

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_billing_set_over_http: set billing of [%.*s] '%.*s' and send_len %ld, recv_len %ld failed\n",
                        (uint32_t)CSTRING_LEN(billing_client_type), (char *)CSTRING_STR(billing_client_type),
                        (uint32_t)CSTRING_LEN(billing_domain), (char *)CSTRING_STR(billing_domain),
                        send_len, recv_len);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_billing_set_over_http: set billing of [%.*s] '%.*s' and send_len %ld, recv_len %ld => status %u\n",
                        (uint32_t)CSTRING_LEN(billing_client_type), (char *)CSTRING_STR(billing_client_type),
                        (uint32_t)CSTRING_LEN(billing_domain), (char *)CSTRING_STR(billing_domain),
                        send_len, recv_len,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_billing_set_over_http: set billing of [%.*s] '%.*s' and send_len %ld, recv_len %ld => OK\n",
                    (uint32_t)CSTRING_LEN(billing_client_type), (char *)CSTRING_STR(billing_client_type),
                    (uint32_t)CSTRING_LEN(billing_domain), (char *)CSTRING_STR(billing_domain),
                    send_len, recv_len);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_lock_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    char        *v;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);


    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/lock_req");
    cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), file_path);

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"Expires", (char *)c_word_to_str(expire_nsec));
    chttp_req_add_header(&chttp_req, (const char *)"tcid", (char *)c_word_to_ipv4(task_brd_default_get_tcid()));

    (*locked_already) = EC_FALSE;

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_lock_over_http: lock_req '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_INTERNAL_SERVER_ERROR == CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_lock_over_http: lock_req '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_FORBIDDEN == CHTTP_RSP_STATUS(&chttp_rsp))/*locked already*/
    {
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_lock_over_http: lock_req '%.*s' on %s:%ld => locked by other\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        (*locked_already) = EC_TRUE;
        return (EC_TRUE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_lock_over_http: lock_req '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    v = chttp_rsp_get_header(&chttp_rsp, (const char *)"auth-token");
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_lock_over_http: lock_req '%.*s' on %s:%ld => status %u but not found auth-token\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cstring_append_str(auth_token, (const UINT8 *)v);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_lock_over_http: lock_req '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_lock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already)
{
    MOD_NODE     recv_mod_node;
    EC_BOOL      ret;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0*/

    ret = EC_FALSE;

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_crfs_file_lock, CMPI_ERROR_MODI, task_brd_default_get_tcid(),
                 file_path, expire_nsec, auth_token, locked_already);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_lock, CMPI_ERROR_MODI, task_brd_default_get_tcid(),
                 file_path, expire_nsec, auth_token, locked_already);
    }

    if(EC_FALSE == ret)
    {
        if(EC_TRUE == (*locked_already))
        {
            dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_lock_over_bgn: lock_req '%.*s' on %s => locked by other\n",
                            (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                            c_word_to_ipv4(store_srv_tcid));
            return (EC_TRUE);
        }
        return (EC_FALSE);
    }
#if 0
    if(EC_TRUE == (*locked_already))
    {
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] __chttp_request_merge_file_lock: lock_req '%.*s' on %s => locked by other\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(tcid));
        return (EC_TRUE);
    }
#endif
    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_lock_over_bgn: lock_req '%.*s' on %s => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_file_unlock_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                           const CSTRING *file_path, const CSTRING *auth_token)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/unlock_req");
    cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), file_path);

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"auth-token", (char *)auth_token);

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_unlock_over_http: unlock_req '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_unlock_over_http: unlock_req '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_unlock_over_http: unlock_req '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_unlock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                           const CSTRING *file_path, const CSTRING *auth_token)
{
    MOD_NODE     recv_mod_node;
    EC_BOOL      ret;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0*/

    ret = EC_FALSE;

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

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_unlock_over_bgn: unlock_req '%.*s' on %s => failed\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_unlock_over_bgn: unlock_req '%.*s' on %s => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_file_read_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES  *content_cbytes)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    CSTRING     *uri;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/getsmf");
    cstring_append_cstr(uri, file_path);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_http: uri '%.*s'\n",
                        (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_http: read '%.*s' from %s:%ld start ...\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(CHTTP_SEG_ERR_OFFSET != store_start_offset
    && CHTTP_SEG_ERR_OFFSET != store_end_offset
    && store_end_offset >= store_start_offset)
    {
        uint32_t store_offset;
        uint32_t store_size;

        store_offset = store_start_offset;
        store_size   = store_end_offset - store_start_offset + 1;

        chttp_req_add_header(&chttp_req, (const char *)"store-offset", (char *)c_uint32_t_to_str(store_offset));
        chttp_req_add_header(&chttp_req, (const char *)"store-size"  , (char *)c_uint32_t_to_str(store_size));
    }

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_read_over_http: read '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_http: read '%.*s' on %s:%ld back\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_read_over_http: read '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_http: read '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(EC_TRUE == chttp_rsp_has_body(&chttp_rsp))
    {
        UINT8   *body_data;
        UINT32   body_len;

        cbytes_umount(CHTTP_RSP_BODY(&chttp_rsp), &body_len, &body_data);
        cbytes_mount(content_cbytes, body_len, body_data);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_read_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES  *content_cbytes)
{
    MOD_NODE                     recv_mod_node;

    EC_BOOL                      ret;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs*/

    ret = EC_FALSE;

    if(CHTTP_SEG_ERR_OFFSET != store_start_offset
    && CHTTP_SEG_ERR_OFFSET != store_end_offset
    && store_end_offset >= store_start_offset)
    {
        UINT32                       store_offset;
        UINT32                       store_size;

        store_offset = store_start_offset;
        store_size   = store_end_offset + 1 - store_start_offset;

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

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_read_over_bgn: read_e '%s' from cache failed\n",
                        (char *)cstring_get_str(file_path));

            return (EC_FALSE);
        }

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_bgn: read_e '%s' from cache done\n",
                    (char *)cstring_get_str(file_path));

        return (EC_TRUE);
    }

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

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_read_over_bgn: read '%s' from cache failed\n",
                    (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_read_over_bgn: read '%s' from cache done\n",
                (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL ccache_file_retire_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                         const CSTRING *file_path)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    CSTRING     *uri;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/dsmf");
    cstring_append_cstr(uri, file_path);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_retire_over_http: uri '%.*s'\n",
                        (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));


    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_retire_over_http: file_retire '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_retire_over_http: file_retire '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_retire_over_http: file_retire '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_retire_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                         const CSTRING *file_path)
{
    MOD_NODE                     recv_mod_node;
    EC_BOOL                      ret;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0*/

    ret = EC_FALSE;

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

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_retire_over_bgn: file_retire '%s' on %s failed\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_retire_over_bgn: file_retire '%s' on %s done\n",
                (char *)cstring_get_str(file_path),
                c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES *content_cbytes, UINT32 *data_ready)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    CSTRING     *uri;

    char        *v;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/file_wait");
    cstring_append_cstr(uri, file_path);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_over_http: uri '%.*s'\n",
                        (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    (*data_ready) = EC_FALSE;

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"tcid", (char *)c_word_to_ipv4(task_brd_default_get_tcid()));
    chttp_req_add_header(&chttp_req, (const char *)"wait-data", (char *)"yes");

    if(CHTTP_SEG_ERR_OFFSET != store_start_offset
    && CHTTP_SEG_ERR_OFFSET != store_end_offset
    && store_end_offset >= store_start_offset)
    {
        UINT32 store_offset;
        UINT32 store_size;

        store_offset = store_start_offset;
        store_size   = store_end_offset - store_start_offset + 1;

        chttp_req_add_header(&chttp_req, (const char *)"store-offset", (char *)c_word_to_str(store_offset));
        chttp_req_add_header(&chttp_req, (const char *)"store-size", (char *)c_word_to_str(store_size));
    }

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_over_http: file_wait '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_over_http: file_wait '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    v = chttp_rsp_get_header(&chttp_rsp, (const char *)"data-ready");
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_over_http: file_wait '%.*s' on %s:%ld => status %u but not found data-ready\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    (*data_ready) = c_str_to_bool(v);

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_file_wait_over_http: file_wait '%.*s' on %s:%ld => OK, data_ready: '%s' [%ld]\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    v, (*data_ready));

    if(EC_TRUE == chttp_rsp_has_body(&chttp_rsp))
    {
        UINT8   *body_data;
        UINT32   body_len;

        cbytes_umount(CHTTP_RSP_BODY(&chttp_rsp), &body_len, &body_data);
        cbytes_mount(content_cbytes, body_len, body_data);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES *content_cbytes, UINT32 *data_ready)
{
    if(CHTTP_SEG_ERR_OFFSET != store_start_offset
    && CHTTP_SEG_ERR_OFFSET != store_end_offset
    && store_end_offset >= store_start_offset)
    {
        MOD_NODE                     recv_mod_node;
        EC_BOOL                      ret;

        UINT32                       store_offset;
        UINT32                       store_size;

        store_offset = store_start_offset;
        store_size   = store_end_offset - store_start_offset + 1;

        MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0*/

        ret = EC_FALSE;

        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_crfs_file_wait_e, CMPI_ERROR_MODI, task_brd_default_get_tcid(), file_path,
                &store_offset, store_size, content_cbytes, data_ready);
        }

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_file_wait_e, CMPI_ERROR_MODI, task_brd_default_get_tcid(), file_path,
                &store_offset, store_size, content_cbytes, data_ready);
        }

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_over_bgn: file_wait '%s' on %s failed\n",
                        (char *)cstring_get_str(file_path),
                        c_word_to_ipv4(store_srv_tcid));

            return (EC_FALSE);
        }

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_over_bgn: file_wait '%s' on %s done\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    }
    else
    {
        MOD_NODE                     recv_mod_node;
        EC_BOOL                      ret;

        MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0*/

        ret = EC_FALSE;

        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_crfs_file_wait, CMPI_ERROR_MODI, task_brd_default_get_tcid(), file_path, content_cbytes, data_ready);
        }

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_cxfs_file_wait, CMPI_ERROR_MODI, task_brd_default_get_tcid(), file_path, content_cbytes, data_ready);
        }

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_over_bgn: file_wait '%s' on %s failed\n",
                        (char *)cstring_get_str(file_path),
                        c_word_to_ipv4(store_srv_tcid));

            return (EC_FALSE);
        }

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_over_bgn: file_wait '%s' on %s done\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    }
    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_ready_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                const CSTRING *file_path,
                                                UINT32 *data_ready)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    CSTRING     *uri;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/file_wait");
    cstring_append_cstr(uri, file_path);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_ready_over_http: uri '%.*s'\n",
                        (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));


    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"tcid", (char *)c_word_to_ipv4(task_brd_default_get_tcid()));
    chttp_req_add_header(&chttp_req, (const char *)"wait-data", (char *)"no");

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_ready_over_http: file_wait '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_ready_over_http: file_wait '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(NULL_PTR != data_ready)
    {
        char    *v;
        v = chttp_rsp_get_header(&chttp_rsp, (const char *)"data-ready");
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_ready_over_http: file_wait '%.*s' on %s:%ld => status %u but not found data-ready\n",
                            (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                            c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                            CHTTP_RSP_STATUS(&chttp_rsp));

            chttp_req_clean(&chttp_req);
            chttp_rsp_clean(&chttp_rsp);
            return (EC_FALSE);
        }

        (*data_ready) = c_str_to_bool(v);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_file_wait_ready_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                const CSTRING *file_path,
                                                UINT32 *data_ready)
{
    MOD_NODE                     recv_mod_node;

    EC_BOOL                      ret;
    UINT32                       data_ready_t;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0*/

    ret = EC_FALSE;

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_crfs_file_wait_ready, CMPI_ERROR_MODI, task_brd_default_get_tcid(),
            file_path, &data_ready_t);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_cxfs_file_wait_ready, CMPI_ERROR_MODI, task_brd_default_get_tcid(),
            file_path, &data_ready_t);
    }

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_file_wait_ready_over_bgn: file_retire '%s' on %s failed\n",
                    (char *)cstring_get_str(file_path),
                    c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    if(NULL_PTR != data_ready)
    {
        (*data_ready) = data_ready_t;
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_file_wait_ready_over_bgn: file_retire '%s' on %s done\n",
                (char *)cstring_get_str(file_path),
                c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_wait_http_headers_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                    const CSTRING *file_path,
                                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    CLIST_DATA  *clist_data;
    uint32_t     idx;

    char        *v;


    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/wait_header");
    cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), file_path);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"tcid", (char *)c_word_to_ipv4(task_brd_default_get_tcid()));

    idx = 0;
    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV   *cstrkv;

        char     wait_key_tag[ 16 ];
        char     wait_val_tag[ 16 ];

        cstrkv = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        idx ++;
        snprintf(wait_key_tag, sizeof(wait_key_tag)/sizeof(wait_key_tag[ 0 ]), "wait-key-%u", idx);
        snprintf(wait_val_tag, sizeof(wait_val_tag)/sizeof(wait_val_tag[ 0 ]), "wait-val-%u", idx);

        chttp_req_add_header(&chttp_req, (const char *)wait_key_tag, (char *)CSTRKV_KEY_STR(cstrkv));
        chttp_req_add_header(&chttp_req, (const char *)wait_val_tag, (char *)CSTRKV_VAL_STR(cstrkv));
    }

    chttp_req_add_header(&chttp_req, (const char *)"wait-num", (char *)c_uint32_t_to_str(idx));

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_wait_http_headers_over_http: wait headers of '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_wait_http_headers_over_http: wait headers of '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(file_path), (char *)CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        return (EC_FALSE);
    }

    v = chttp_rsp_get_header(&chttp_rsp, (const char *)"header-ready");
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_wait_http_headers_over_http: wait headers '%.*s' on %s:%ld => status %u but not found header-ready\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    (*header_ready) = c_str_to_bool(v);

    dbg_log(SEC_0177_CCACHE, 1)(LOGSTDOUT, "[DEBUG] ccache_wait_http_headers_over_http: wait headers '%.*s' on %s:%ld => OK, header_ready: '%s' [%ld]\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    v, (*header_ready));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL ccache_wait_http_headers_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                    const CSTRING *file_path,
                                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    MOD_NODE     recv_mod_node;
    EC_BOOL      ret;

    MOD_NODE_TCID(&recv_mod_node) = store_srv_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*crfs_md_id = 0*/

    ret = EC_FALSE;

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_crfs_wait_http_headers, CMPI_ERROR_MODI, task_brd_default_get_tcid(),
                 file_path, cstrkv_mgr, header_ready);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_wait_http_headers, CMPI_ERROR_MODI, task_brd_default_get_tcid(),
                 file_path, cstrkv_mgr, header_ready);
    }

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_wait_http_headers_over_bgn: wait headers of '%.*s' on %s done => failed\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

        return (EC_FALSE);
    }

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_wait_http_headers_over_bgn: wait headers of '%.*s' on %s done => OK\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(store_srv_tcid));

    return (EC_TRUE);
}

EC_BOOL ccache_dir_delete_over_http(const CSTRING *file_path)
{
    TASK_BRD    *task_brd;
    TASK_MGR    *task_mgr;

    UINT32       crfsmon_md_id;

    UINT32       pos;
    UINT32       num;
    EC_BOOL      ret;

    task_brd = task_brd_default_get();

    crfsmon_md_id = TASK_BRD_CRFSMON_ID(task_brd);
    if(CMPI_ERROR_MODI == crfsmon_md_id)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_http: no crfsmon started\n");
        return (EC_FALSE);
    }

    crfsmon_crfs_node_num(crfsmon_md_id, &num);
    if(0 == num)
    {
        dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_http: store is empty\n");
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(pos = 0; pos < num; pos ++)
    {
        CRFS_NODE      crfs_node;
        MOD_NODE       recv_mod_node;

        crfs_node_init(&crfs_node);
        if(EC_FALSE == crfsmon_crfs_node_get_by_pos(crfsmon_md_id, pos, &crfs_node))
        {
            crfs_node_clean(&crfs_node);
            continue;
        }

        if(EC_FALSE == crfs_node_is_up(&crfs_node))
        {
            dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_http: delete '%.*s' skip rfs %s which is not up\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                    c_word_to_ipv4(CRFS_NODE_TCID(&crfs_node))
                    );
            crfs_node_clean(&crfs_node);
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

        task_p2p_inc(task_mgr, 0, &recv_mod_node,
                &ret, FI_super_delete_dir, CMPI_ERROR_MODI,
                CRFS_NODE_TCID(&crfs_node), CRFS_NODE_IPADDR(&crfs_node), CRFS_NODE_PORT(&crfs_node), file_path);

        crfs_node_clean(&crfs_node);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_http: delete '%.*s' done\n",
                    (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path));

    return (EC_TRUE);
}

EC_BOOL ccache_dir_delete_over_bgn(const CSTRING *file_path)
{
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        TASK_BRD    *task_brd;
        TASK_MGR    *task_mgr;

        UINT32       crfsmon_md_id;

        UINT32       pos;
        UINT32       num;
        EC_BOOL      ret;

        task_brd = task_brd_default_get();

        crfsmon_md_id = TASK_BRD_CRFSMON_ID(task_brd);
        if(CMPI_ERROR_MODI == crfsmon_md_id)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: no crfsmon started\n");
            return (EC_FALSE);
        }

        crfsmon_crfs_node_num(crfsmon_md_id, &num);
        if(0 == num)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: store is empty\n");
            return (EC_FALSE);
        }

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        for(pos = 0; pos < num; pos ++)
        {
            CRFS_NODE      crfs_node;
            MOD_NODE       recv_mod_node;

            crfs_node_init(&crfs_node);
            if(EC_FALSE == crfsmon_crfs_node_get_by_pos(crfsmon_md_id, pos, &crfs_node))
            {
                crfs_node_clean(&crfs_node);
                continue;
            }

            if(EC_FALSE == crfs_node_is_up(&crfs_node))
            {
                dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: delete '%.*s' skip rfs %s which is not up\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(CRFS_NODE_TCID(&crfs_node))
                        );
                crfs_node_clean(&crfs_node);
                continue;
            }

            MOD_NODE_TCID(&recv_mod_node) = CRFS_NODE_TCID(&crfs_node);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs*/

            task_p2p_inc(task_mgr, 0, &recv_mod_node,
                    &ret, FI_crfs_delete_dir, CMPI_ERROR_MODI, file_path);

            crfs_node_clean(&crfs_node);
        }

        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: delete '%.*s' done\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path));
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        TASK_BRD    *task_brd;
        TASK_MGR    *task_mgr;

        UINT32       cxfsmon_md_id;

        UINT32       pos;
        UINT32       num;
        EC_BOOL      ret;

        task_brd = task_brd_default_get();

        cxfsmon_md_id = TASK_BRD_CXFSMON_ID(task_brd);
        if(CMPI_ERROR_MODI == cxfsmon_md_id)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: no cxfsmon started\n");
            return (EC_FALSE);
        }

        cxfsmon_cxfs_node_num(cxfsmon_md_id, &num);
        if(0 == num)
        {
            dbg_log(SEC_0177_CCACHE, 0)(LOGSTDOUT, "error:ccache_dir_delete_over_bgn: store is empty\n");
            return (EC_FALSE);
        }

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        for(pos = 0; pos < num; pos ++)
        {
            CXFS_NODE      cxfs_node;
            MOD_NODE       recv_mod_node;

            cxfs_node_init(&cxfs_node);
            if(EC_FALSE == cxfsmon_cxfs_node_get_by_pos(cxfsmon_md_id, pos, &cxfs_node))
            {
                cxfs_node_clean(&cxfs_node);
                continue;
            }

            if(EC_FALSE == cxfs_node_is_up(&cxfs_node))
            {
                dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: delete '%.*s' skip xfs %s which is not up\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path),
                        c_word_to_ipv4(CXFS_NODE_TCID(&cxfs_node))
                        );
                cxfs_node_clean(&cxfs_node);
                continue;
            }

            MOD_NODE_TCID(&recv_mod_node) = CXFS_NODE_TCID(&cxfs_node);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one xfs*/

            task_p2p_inc(task_mgr, 0, &recv_mod_node,
                    &ret, FI_cxfs_delete_dir, CMPI_ERROR_MODI, file_path);

            cxfs_node_clean(&cxfs_node);
        }

        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        dbg_log(SEC_0177_CCACHE, 9)(LOGSTDOUT, "[DEBUG] ccache_dir_delete_over_bgn: delete '%.*s' done\n",
                        (uint32_t)CSTRING_LEN(file_path), CSTRING_STR(file_path));
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

