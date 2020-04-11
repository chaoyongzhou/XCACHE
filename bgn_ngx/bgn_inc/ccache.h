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

#ifndef _CCACHE_H
#define _CCACHE_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "cbytes.h"

#include "chttp.h"
#include "chttps.h"

#include "http_parser.h"

int ccache_on_http_message_begin(http_parser_t* http_parser);

int ccache_on_http_headers_complete(http_parser_t* http_parser, const char* last, size_t length);

int ccache_on_http_message_complete(http_parser_t* http_parser);

int ccache_on_http_url(http_parser_t* http_parser, const char* at, size_t length);

/*only for http response*/
int ccache_on_http_status(http_parser_t* http_parser, const char* at, size_t length);

int ccache_on_http_header_field(http_parser_t* http_parser, const char* at, size_t length);

int ccache_on_http_header_value(http_parser_t* http_parser, const char* at, size_t length);

int ccache_on_http_body(http_parser_t* http_parser, const char* at, size_t length);

EC_BOOL ccache_parse_http_header(const CBYTES *header_cbytes, CHTTP_RSP *chttp_rsp);

EC_BOOL ccache_trigger_http_request_merge(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

EC_BOOL ccache_file_write(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *auth_token);

EC_BOOL ccache_renew_headers(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token);

EC_BOOL ccache_file_notify(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path);

EC_BOOL ccache_file_terminate(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path);

EC_BOOL ccache_file_lock(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already);

EC_BOOL ccache_file_unlock(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                const CSTRING *file_path, const CSTRING *auth_token);

EC_BOOL ccache_file_read(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                            CBYTES  *cbytes);

EC_BOOL ccache_file_retire(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path);

EC_BOOL ccache_file_wait(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                            const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                            CBYTES *content_cbytes, UINT32 *data_ready);

EC_BOOL ccache_file_wait_and_read(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES *content_cbytes);

EC_BOOL ccache_file_wait_ready(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                    const CSTRING *file_path,
                                    UINT32 *data_ready);

EC_BOOL ccache_wait_http_headers(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                    const CSTRING *file_path,
                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);

EC_BOOL ccache_dir_delete(const CSTRING *file_path);

EC_BOOL ccache_billing_set(const UINT32 billing_srv_ipaddr, const UINT32 billing_srv_port,
                              const CSTRING *billing_flags,
                              const CSTRING *billing_domain, const CSTRING *billing_client_type,
                              const UINT32 send_len, const UINT32 recv_len);

/*-------------------------- interact with http and bgn --------------------------*/
EC_BOOL ccache_lock_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                   const CSTRING *file_path, const UINT32 expire_nsec,
                                   CSTRING *auth_token, UINT32 *locked_already);

EC_BOOL ccache_lock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                   const CSTRING *file_path, const UINT32 expire_nsec,
                                   CSTRING *auth_token, UINT32 *locked_already);

EC_BOOL ccache_unlock_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRING *auth_token);

EC_BOOL ccache_unlock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRING *auth_token);

EC_BOOL ccache_file_write_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *auth_token);

EC_BOOL ccache_file_write_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *auth_token);

EC_BOOL ccache_renew_headers_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token);

EC_BOOL ccache_renew_headers_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token);

EC_BOOL ccache_file_notify_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path);

EC_BOOL ccache_file_notify_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path);

EC_BOOL ccache_file_terminate_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path);

EC_BOOL ccache_file_terminate_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *file_path);

EC_BOOL ccache_billing_set_over_http(const UINT32 billing_srv_ipaddr, const UINT32 billing_srv_port,
                                           const CSTRING *billing_flags,
                                           const CSTRING *billing_domain, const CSTRING *billing_client_type,
                                           const UINT32 send_len, const UINT32 recv_len);

EC_BOOL ccache_file_lock_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already);

EC_BOOL ccache_file_lock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *auth_token, UINT32 *locked_already);

EC_BOOL ccache_file_unlock_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                           const CSTRING *file_path, const CSTRING *auth_token);

EC_BOOL ccache_file_unlock_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                           const CSTRING *file_path, const CSTRING *auth_token);

EC_BOOL ccache_file_read_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES  *content_cbytes);

EC_BOOL ccache_file_read_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES  *content_cbytes);

EC_BOOL ccache_file_retire_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                         const CSTRING *file_path);

EC_BOOL ccache_file_retire_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                         const CSTRING *file_path);

EC_BOOL ccache_file_wait_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES *content_cbytes, UINT32 *data_ready);

EC_BOOL ccache_file_wait_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                        const CSTRING *file_path, const UINT32 store_start_offset, const UINT32 store_end_offset,
                                        CBYTES *content_cbytes, UINT32 *data_ready);

EC_BOOL ccache_file_wait_ready_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                const CSTRING *file_path,
                                                UINT32 *data_ready);

EC_BOOL ccache_file_wait_ready_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                const CSTRING *file_path,
                                                UINT32 *data_ready);

EC_BOOL ccache_wait_http_headers_over_http(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                    const CSTRING *file_path,
                                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);

EC_BOOL ccache_wait_http_headers_over_bgn(const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port,
                                                    const CSTRING *file_path,
                                                    const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready);

EC_BOOL ccache_dir_delete_over_http(const CSTRING *file_path);

EC_BOOL ccache_dir_delete_over_bgn(const CSTRING *file_path);


#endif /*_CCACHE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/



