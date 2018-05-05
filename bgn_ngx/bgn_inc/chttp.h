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

#ifndef _CHTTP_H
#define _CHTTP_H

#include "type.h"
#include "debug.h"

#include "http_parser.h"
#include "cbuffer.h"
#include "chunk.h"

#include "csocket.inc"
#include "chttp.inc"
#include "csrv.h"

#define CHTTP_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC

/*---------------------------------------- INTERFACE WITH HTTP STORE  ----------------------------------------*/
CHTTP_STORE *chttp_store_new();

EC_BOOL chttp_store_init(CHTTP_STORE *chttp_store);

EC_BOOL chttp_store_clean(CHTTP_STORE *chttp_store);

EC_BOOL chttp_store_free(CHTTP_STORE *chttp_store);

EC_BOOL chttp_store_clone(const CHTTP_STORE *chttp_store_src, CHTTP_STORE *chttp_store_des);

EC_BOOL chttp_store_check(const CHTTP_STORE *chttp_store);

EC_BOOL chttp_store_srv_get(const CHTTP_STORE *chttp_store, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

EC_BOOL chttp_store_path_get(const CHTTP_STORE *chttp_store, CSTRING *path);

void    chttp_store_print(LOG *log, const CHTTP_STORE *chttp_store);

EC_BOOL chttp_store_has_cache_status_code(CHTTP_STORE *chttp_store, const uint32_t status_code);

EC_BOOL chttp_store_if_cache_status_code(CHTTP_STORE *chttp_store, const uint32_t status_code, uint32_t *expires);

EC_BOOL chttp_store_has_not_cache_status_code(CHTTP_STORE *chttp_store, const uint32_t status_code);

EC_BOOL chttp_store_has_cache_rsp_headers(CHTTP_STORE *chttp_store, const CSTRKV_MGR *rsp_headers);

EC_BOOL chttp_store_has_not_cache_rsp_headers(CHTTP_STORE *chttp_store, const CSTRKV_MGR *rsp_headers);

/*---------------------------------------- INTERFACE WITH HTTP STAT  ----------------------------------------*/
const char *chttp_status_str_get(const uint32_t http_status);

CHTTP_STAT *chttp_stat_new();

EC_BOOL chttp_stat_init(CHTTP_STAT *chttp_stat);

EC_BOOL chttp_stat_clean(CHTTP_STAT *chttp_stat);

EC_BOOL chttp_stat_free(CHTTP_STAT *chttp_stat);

EC_BOOL chttp_stat_clone(const CHTTP_STAT *chttp_stat_src, CHTTP_STAT *chttp_stat_des);

void    chttp_stat_print(LOG *log, const CHTTP_STAT *chttp_stat);

/*---------------------------------------- INTERFACE WITH HTTP NODE  ----------------------------------------*/
CHTTP_NODE *chttp_node_new(const UINT32 type);

EC_BOOL chttp_node_init(CHTTP_NODE *chttp_node, const UINT32 type);

EC_BOOL chttp_node_clean(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_free(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_clear(CHTTP_NODE *chttp_node);/*note: chttp_node_clear is ONLY for memory recycle asap before it comes to life-cycle end*/

EC_BOOL chttp_node_wait_resume(CHTTP_NODE *chttp_node);

void    chttp_node_print(LOG *log, const CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_is_chunked(const CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_is_norange(const CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_init_parser(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_recv_req(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_send_req(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_recv_rsp(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_send_rsp(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_icheck(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_complete(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_close(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_timeout(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_shutdown(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_recv(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_send(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_need_send(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_need_parse(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_has_data_in(CHTTP_NODE *chttp_node);

/*---- TODO BEG : replace these interfaces by macros*/
EC_BOOL chttp_node_recv_export_to_cbytes(CHTTP_NODE *chttp_node, CBYTES *cbytes, const UINT32 body_len);

EC_BOOL chttp_node_recv_clean(CHTTP_NODE *chttp_node);

/*for debug only*/
CHUNK_MGR *chttp_node_recv_chunks(const CHTTP_NODE *chttp_node);

/*for debug only*/
UINT32  chttp_node_recv_chunks_num(const CHTTP_NODE *chttp_node);


/*for debug only*/
UINT32  chttp_node_recv_len(const CHTTP_NODE *chttp_node);

/*for debug only*/
UINT32 chttp_node_send_len(const CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_add_header(CHTTP_NODE *chttp_node, const char *k, const char *v);

char   *chttp_node_get_header(CHTTP_NODE *chttp_node, const char *k);

EC_BOOL chttp_node_del_header(CHTTP_NODE *chttp_node, const char *k);

EC_BOOL chttp_node_renew_header(CHTTP_NODE *chttp_node, const char *k, const char *v);

EC_BOOL chttp_node_fetch_header(CHTTP_NODE *chttp_node, const char *k, CSTRKV_MGR *cstrkv_mgr);

EC_BOOL chttp_node_fetch_headers(CHTTP_NODE *chttp_node, const char *keys, CSTRKV_MGR *cstrkv_mgr);

EC_BOOL chttp_node_has_header_key(CHTTP_NODE *chttp_node, const char *k);

EC_BOOL chttp_node_has_header(CHTTP_NODE *chttp_node, const char *k, const char *v);

void    chttp_node_print_header(LOG *log, const CHTTP_NODE *chttp_node);

void    chttp_node_check_cacheable(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_adjust_seg_id(CHTTP_NODE *chttp_node);

uint64_t chttp_node_fetch_file_size(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_check_use_gzip(CHTTP_NODE *chttp_node);

/*---- TODO END : replace these interfaces by macros*/

/*---------------------------------------- HTTP HEADER PASER  ----------------------------------------*/

EC_BOOL chttp_parse_host(CHTTP_NODE *chttp_node);

EC_BOOL chttp_parse_content_length(CHTTP_NODE *chttp_node);

EC_BOOL chttp_parse_connection_keepalive(CHTTP_NODE *chttp_node);

EC_BOOL chttp_parse_uri(CHTTP_NODE *chttp_node);

EC_BOOL chttp_parse_post(CHTTP_NODE *chttp_node, const uint32_t parsed_len);

EC_BOOL chttp_parse(CHTTP_NODE *chttp_node);

EC_BOOL chttp_pause_parser(http_parser_t* http_parser);

EC_BOOL chttp_resume_parser(http_parser_t* http_parser);

/*---------------------------------------- MAKE RESPONSE ----------------------------------------*/
EC_BOOL chttp_make_response_header_protocol(CHTTP_NODE *chttp_node, const uint16_t major, const uint16_t minor, const uint32_t status);

EC_BOOL chttp_make_response_header_keepalive(CHTTP_NODE *chttp_node);

EC_BOOL chttp_make_response_header_date(CHTTP_NODE *chttp_node);

EC_BOOL chttp_make_response_header_expires(CHTTP_NODE *chttp_node);

/*general interface: append data to header buffer*/
EC_BOOL chttp_make_response_header_data(CHTTP_NODE *chttp_node, const uint8_t *data, const uint32_t len);

EC_BOOL chttp_make_response_header_token(CHTTP_NODE *chttp_node, const uint8_t *token, const uint32_t len);

EC_BOOL chttp_make_response_header_retire(CHTTP_NODE *chttp_node, const uint8_t *retire_result, const uint32_t len);

EC_BOOL chttp_make_response_header_recycle(CHTTP_NODE *chttp_node, const uint8_t *recycle_result, const uint32_t len);

EC_BOOL chttp_make_response_header_elapsed(CHTTP_NODE *chttp_node);

EC_BOOL chttp_make_response_header_content_type(CHTTP_NODE *chttp_node, const uint8_t *data, const uint32_t size);

EC_BOOL chttp_make_response_header_content_length(CHTTP_NODE *chttp_node, const uint64_t size);

EC_BOOL chttp_make_response_header_kv(CHTTP_NODE *chttp_node, const CSTRKV *cstrkv);

EC_BOOL chttp_make_response_header_kvs(CHTTP_NODE *chttp_node);

EC_BOOL chttp_make_response_header_end(CHTTP_NODE *chttp_node);

EC_BOOL chttp_make_response_body(CHTTP_NODE *chttp_node, const uint8_t *data, const uint32_t size);

/*make response body without data copying but data transfering*/
EC_BOOL chttp_make_response_body_ext(CHTTP_NODE *chttp_node, const uint8_t *data, const uint32_t size);

EC_BOOL chttp_make_response_header_common(CHTTP_NODE *chttp_node, const uint64_t body_len);

EC_BOOL chttp_make_error_response(CHTTP_NODE *chttp_node);

/*---------------------------------------- HTTP SERVER ----------------------------------------*/
CSRV * chttp_srv_start(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 md_id);

EC_BOOL chttp_srv_end(CSRV *csrv);

EC_BOOL chttp_srv_bind_modi(CSRV *csrv, const UINT32 modi);

EC_BOOL chttp_srv_accept_once(CSRV *csrv, EC_BOOL *continue_flag);

EC_BOOL chttp_srv_accept(CSRV *csrv);

/*---------------------------------------- COMMIT RESPONSE FOR EMITTING  ----------------------------------------*/
EC_BOOL chttp_commit_error_response(CHTTP_NODE *chttp_node);

EC_BOOL chttp_commit_error_request(CHTTP_NODE *chttp_node);

/*---------------------------------------- REQUEST REST LIST MANAGEMENT ----------------------------------------*/
CHTTP_REST *chttp_rest_new();

EC_BOOL chttp_rest_init(CHTTP_REST *chttp_rest);

EC_BOOL chttp_rest_clean(CHTTP_REST *chttp_rest);

EC_BOOL chttp_rest_free(CHTTP_REST *chttp_rest);

void    chttp_rest_print(LOG *log, const CHTTP_REST *chttp_rest);

EC_BOOL chttp_rest_cmp(const CHTTP_REST *chttp_rest_1st, const CHTTP_REST *chttp_rest_2nd);

EC_BOOL chttp_rest_list_push(const char *name, EC_BOOL (*commit)(CHTTP_NODE *));

CHTTP_REST *chttp_rest_list_pop(const char *name, const uint32_t len);

CHTTP_REST *chttp_rest_list_find(const char *name, const uint32_t len);

/*---------------------------------------- REQUEST DEFER QUEUE MANAGEMENT ----------------------------------------*/
EC_BOOL chttp_defer_request_queue_init();

EC_BOOL chttp_defer_request_queue_clean();

EC_BOOL chttp_defer_request_queue_is_empty();

EC_BOOL chttp_defer_request_queue_push(CHTTP_NODE *chttp_node);

EC_BOOL chttp_defer_request_queue_erase(CHTTP_NODE *chttp_node);

CHTTP_NODE *chttp_defer_request_queue_pop();

CHTTP_NODE *chttp_defer_request_queue_peek();

EC_BOOL chttp_defer_request_queue_launch(CHTTP_NODE_COMMIT_REQUEST chttp_node_commit_request);

EC_BOOL chttp_defer_request_commit(CHTTP_NODE *chttp_node);
/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * CHTTP_REQ and CHTTP_RSP interfaces
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
CHTTP_REQ *chttp_req_new();
EC_BOOL chttp_req_init(CHTTP_REQ *chttp_req);
EC_BOOL chttp_req_clean(CHTTP_REQ *chttp_req);
EC_BOOL chttp_req_free(CHTTP_REQ *chttp_req);
void    chttp_req_print(LOG *log, const CHTTP_REQ *chttp_req);
void    chttp_req_print_plain(LOG *log, const CHTTP_REQ *chttp_req);

EC_BOOL chttp_req_set_ipaddr_word(CHTTP_REQ *chttp_req, const UINT32 ipaddr);
EC_BOOL chttp_req_set_port_word(CHTTP_REQ *chttp_req, const UINT32 port);
EC_BOOL chttp_req_set_server(CHTTP_REQ *chttp_req, const char *server);
EC_BOOL chttp_req_set_ipaddr(CHTTP_REQ *chttp_req, const char *ipaddr);
EC_BOOL chttp_req_set_port(CHTTP_REQ *chttp_req, const char *port);
EC_BOOL chttp_req_set_method(CHTTP_REQ *chttp_req, const char *method);
EC_BOOL chttp_req_set_uri(CHTTP_REQ *chttp_req, const char *uri);
EC_BOOL chttp_req_add_param(CHTTP_REQ *chttp_req, const char *k, const char *v);
EC_BOOL chttp_req_has_header(CHTTP_REQ *chttp_req, const char *k, const char *v);
EC_BOOL chttp_req_add_header(CHTTP_REQ *chttp_req, const char *k, const char *v);
EC_BOOL chttp_req_add_header_chars(CHTTP_REQ *chttp_req, const char *k, const uint32_t klen, const char *v, const uint32_t vlen);
char *  chttp_req_get_header(const CHTTP_REQ *chttp_req, const char *k);
EC_BOOL chttp_req_del_header(CHTTP_REQ *chttp_req, const char *k);
EC_BOOL chttp_req_del_header_kv(CHTTP_REQ *chttp_req, const char *k, const char *v);
EC_BOOL chttp_req_renew_header(CHTTP_REQ *chttp_req, const char *k, const char *v);
EC_BOOL chttp_req_set_ca_file(CHTTP_REQ *chttp_req, const char *fname);
EC_BOOL chttp_req_set_client_certificate_file(CHTTP_REQ *chttp_req, const char *fname);
EC_BOOL chttp_req_set_client_private_key_file(CHTTP_REQ *chttp_req, const char *fname);
EC_BOOL chttp_req_set_body(CHTTP_REQ *chttp_req, const uint8_t *data, const uint32_t len);
EC_BOOL chttp_req_clone(CHTTP_REQ *chttp_req_des, const CHTTP_REQ *chttp_req_src);
EC_BOOL chttp_req_is_head_method(const CHTTP_REQ *chttp_req);
EC_BOOL chttp_req_has_body(const CHTTP_REQ *chttp_req);
EC_BOOL chttp_req_discard_body(CHTTP_REQ *chttp_req);

CHTTP_RSP *chttp_rsp_new();
EC_BOOL chttp_rsp_init(CHTTP_RSP *chttp_rsp);
EC_BOOL chttp_rsp_clean(CHTTP_RSP *chttp_rsp);
EC_BOOL chttp_rsp_free(CHTTP_RSP *chttp_rsp);
void    chttp_rsp_print(LOG *log, const CHTTP_RSP *chttp_rsp);
void    chttp_rsp_print_plain(LOG *log, const CHTTP_RSP *chttp_rsp);
EC_BOOL chttp_rsp_is_chunked(const CHTTP_RSP *chttp_rsp);
EC_BOOL chttp_rsp_is_aged(const CHTTP_RSP *chttp_rsp, const uint32_t max_age);
EC_BOOL chttp_rsp_add_header(CHTTP_RSP *chttp_rsp, const char *k, const char *v);
EC_BOOL chttp_rsp_add_header_chars(CHTTP_RSP *chttp_rsp, const char *k, const uint32_t klen, const char *v, const uint32_t vlen);
char *  chttp_rsp_get_header(const CHTTP_RSP *chttp_rsp, const char *k);
EC_BOOL chttp_rsp_del_header(CHTTP_RSP *chttp_rsp, const char *k);
EC_BOOL chttp_rsp_renew_header(CHTTP_RSP *chttp_rsp, const char *k, const char *v);
EC_BOOL chttp_rsp_merge_header(CHTTP_RSP *chttp_rsp);
EC_BOOL chttp_rsp_has_header_key(CHTTP_RSP *chttp_rsp, const char *k);
EC_BOOL chttp_rsp_has_header(CHTTP_RSP *chttp_rsp, const char *k, const char *v);
EC_BOOL chttp_rsp_fetch_header(CHTTP_RSP *chttp_rsp, const char *k, CSTRKV_MGR *cstrkv_mgr);
EC_BOOL chttp_rsp_fetch_headers(CHTTP_RSP *chttp_rsp, const char *keys, CSTRKV_MGR *cstrkv_mgr);
EC_BOOL chttp_rsp_only_headers(CHTTP_RSP *chttp_rsp, const char **keys, const UINT32 num);
EC_BOOL chttp_rsp_has_body(const CHTTP_RSP *chttp_rsp);
EC_BOOL chttp_rsp_discard_body(CHTTP_RSP *chttp_rsp);
EC_BOOL chttp_rsp_decode(CHTTP_RSP *chttp_rsp, const uint8_t *data, const uint32_t data_len);
EC_BOOL chttp_rsp_encode_header_kv(const CHTTP_RSP *chttp_rsp, const CSTRKV *kv, CBYTES *cbytes);
EC_BOOL chttp_rsp_encode_header_end(const CHTTP_RSP *chttp_rsp, CBYTES *cbytes);
EC_BOOL chttp_rsp_encode_header(const CHTTP_RSP *chttp_rsp, const CSTRKV_MGR *header, CBYTES *cbytes);
EC_BOOL chttp_rsp_encode_body(const CHTTP_RSP *chttp_rsp, const CBYTES *rsp_body, CBYTES *cbytes);
EC_BOOL chttp_rsp_encode(const CHTTP_RSP *chttp_rsp, CBYTES *cbytes);
/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Send Http Request and Handle Http Response
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttp_node_encode_req_const_str(CHTTP_NODE *chttp_node, const uint8_t *str, const UINT32 len);

EC_BOOL chttp_node_encode_req_protocol(CHTTP_NODE *chttp_node, const uint16_t version_major, const uint16_t version_minor);

EC_BOOL chttp_node_encode_req_method(CHTTP_NODE *chttp_node, const CSTRING *method);

EC_BOOL chttp_node_encode_req_header_kv(CHTTP_NODE *chttp_node, const CSTRKV *kv);

EC_BOOL chttp_node_encode_req_param_kv(CHTTP_NODE *chttp_node, const CSTRKV *kv);

EC_BOOL chttp_node_encode_req_param(CHTTP_NODE *chttp_node, const CSTRKV_MGR *param);

EC_BOOL chttp_node_encode_req_uri(CHTTP_NODE *chttp_node , const CSTRING *uri, const CSTRKV_MGR *param);

EC_BOOL chttp_node_encode_req_header_end(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_encode_req_header(CHTTP_NODE *chttp_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param, const CSTRKV_MGR *header);

EC_BOOL chttp_node_encode_req_header_line(CHTTP_NODE *chttp_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param,
                                            const uint16_t version_major, const uint16_t version_minor);
EC_BOOL chttp_node_encode_req_body(CHTTP_NODE *chttp_node, const CBYTES *req_body);

EC_BOOL chttp_node_encode_rsp_const_str(CHTTP_NODE *chttp_node, const uint8_t *str, const UINT32 len, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_protocol(CHTTP_NODE *chttp_node, const uint16_t version_major, const uint16_t version_minor, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_method(CHTTP_NODE *chttp_node, const CSTRING *method, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_status(CHTTP_NODE *chttp_node, const uint32_t status_code, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_header_kv(CHTTP_NODE *chttp_node, const CSTRKV *kv, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_param_kv(CHTTP_NODE *chttp_node, const CSTRKV *kv, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_param(CHTTP_NODE *chttp_node, const CSTRKV_MGR *param, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_uri(CHTTP_NODE *chttp_node , const CSTRING *uri, const CSTRKV_MGR *param, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_header_line(CHTTP_NODE *chttp_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param,
                                            const uint16_t version_major, const uint16_t version_minor, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_header_end(CHTTP_NODE *chttp_node, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_header(CHTTP_NODE *chttp_node, const UINT32 status_code, const CSTRKV_MGR *header, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp_body(CHTTP_NODE *chttp_node, CBYTES *cbytes);

EC_BOOL chttp_node_encode_rsp(CHTTP_NODE *chttp_node, CBYTES *cbytes);

EC_BOOL chttp_node_set_socket_callback(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_set_socket_epoll(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttp_node_connect(CHTTP_NODE *chttp_node, const UINT32 csocket_block_mode, const UINT32 ipaddr, const UINT32 port);

EC_BOOL chttp_node_disconnect(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_detach(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_clone_rsp(CHTTP_NODE *chttp_node, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

EC_BOOL chttp_node_clone_rsp_header(CHTTP_NODE *chttp_node, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

EC_BOOL chttp_node_handover_rsp(CHTTP_NODE *chttp_node, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

EC_BOOL chttp_node_filter_on_header_complete(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_store_header(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store, const uint32_t max_store_size, uint32_t *has_stored_size);
EC_BOOL chttp_node_store_body(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store, const uint32_t max_store_size, uint32_t *has_stored_size);
EC_BOOL chttp_node_store_no_body(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store);
EC_BOOL chttp_node_store_whole(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store, const uint32_t max_store_size, uint32_t *has_stored_size);
EC_BOOL chttp_node_store_no_next(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store);
EC_BOOL chttp_node_store_done_blocking(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store);
EC_BOOL chttp_node_store_done_nonblocking(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store);
EC_BOOL chttp_node_store_on_headers_complete(CHTTP_NODE *chttp_node);
EC_BOOL chttp_node_store_on_message_complete(CHTTP_NODE *chttp_node);
EC_BOOL chttp_node_store_on_body(CHTTP_NODE *chttp_node);

EC_BOOL chttp_node_renew_content_length(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store, const uint64_t content_length);

EC_BOOL chttp_node_set_billing(CHTTP_NODE *chttp_node, CHTTP_STORE *chttp_store);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Block Http Flow
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
EC_BOOL chttp_request_block(const CHTTP_REQ *chttp_req, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Basic Http Flow
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttp_request_basic(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Try to connect remote http server to check connectivity (HEALTH CHECKER)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttp_node_check(CHTTP_NODE *chttp_node, const UINT32 ipaddr, const UINT32 port);

EC_BOOL chttp_check(const CHTTP_REQ *chttp_req, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Merge Http Request (MERGE ORIGIN FLOW)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttp_request_merge(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Header Http Request (only token owner would store header to storage)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttp_request_header(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * General Http Request Entry
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttp_request(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

#endif /*_CHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

