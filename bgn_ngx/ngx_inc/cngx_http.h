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

#ifndef _CNGX_HTTP_H
#define _CNGX_HTTP_H

#include "type.h"
#include "debug.h"

#include "cstring.h"

#include "csocket.inc"
#include "task.inc"
#include "chttp.inc"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "http_parser.h"

#define CNGX_HTTP_SOCKET_TIMEOUT_NSEC      CONN_TIMEOUT_NSEC

#define CNGX_HTTP_REST_API_NAME            "ngx"

EC_BOOL cngx_http_log_start();

EC_BOOL cngx_http_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_start(CHTTP_NODE *chttp_node, const UINT32 method);
EC_BOOL cngx_http_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cngx_http_commit_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_breathe_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_breathe_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_logrotate_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_logrotate_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_logreopen_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_logreopen_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_logreopen_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_logreopen_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_actsyscfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_actsyscfg_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_xfs_up_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_up_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_up_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_up_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_xfs_down_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_down_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_down_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_down_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_xfs_add_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_add_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_add_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_add_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_xfs_del_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_del_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_del_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_del_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_xfs_list_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_list_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_list_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_list_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_ngx_reload_so_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_reload_so_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_reload_so_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_reload_so_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_ngx_switch_so_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_switch_so_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_switch_so_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_switch_so_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_ngx_show_so_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_show_so_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_show_so_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_show_so_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_ngx_activate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_activate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_activate_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_activate_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_ngx_deactivate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_deactivate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_deactivate_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_deactivate_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_ngx_show_cmon_nodes_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_show_cmon_nodes_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_show_cmon_nodes_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_show_cmon_nodes_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_paracfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_paracfg_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_dbgtaskcfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_dbgtaskcfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_dbgtaskcfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_dbgtaskcfg_response(CHTTP_NODE *chttp_node);

#endif /*_CNGX_HTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

