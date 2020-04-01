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

#define CNGX_HTTP_REST_API_NAME            "/ngx"

EC_BOOL cngx_http_log_start();

EC_BOOL cngx_http_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_http_post(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_http_get(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_http_head(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cngx_http_commit_response(CHTTP_NODE *chttp_node);
/**
    interface name rule:
    cngx_http_is_http_[get|post|put|head|delete]_<op>
    cngx_http_commit_<op>_[get|post|put|head|delete]_request
    cngx_http_handle_<op>_[get|post|put|head|delete]_request
    cngx_http_make_<op>_[get|post|put|head|delete]_response
    cngx_http_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL cngx_http_is_http_get_breathe(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_breathe_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_breathe_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_breathe_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_breathe_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_logrotate(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_logrotate_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_logrotate_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_logrotate_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_logrotate_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_actsyscfg(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_actsyscfg_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_actsyscfg_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_actsyscfg_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_actsyscfg_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_xfs_up(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_up_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_up_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_xfs_down(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_down_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_down_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_xfs_add(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_add_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_add_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_xfs_del(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_del_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_del_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_xfs_list(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_xfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_xfs_list_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_xfs_list_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_rfs_up(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_rfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_rfs_up_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_up_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_rfs_down(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_rfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_rfs_down_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_down_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_rfs_add(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_rfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_rfs_add_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_add_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_rfs_del(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_rfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_rfs_del_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_del_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_rfs_list(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_rfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_rfs_list_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_rfs_list_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_ngx_reload_so(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_reload_so_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_reload_so_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_reload_so_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_reload_so_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_ngx_switch_so(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_switch_so_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_switch_so_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_switch_so_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_switch_so_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_http_is_http_get_ngx_show_so(const CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_show_so_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_handle_ngx_show_so_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_make_ngx_show_so_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_http_commit_ngx_show_so_get_response(CHTTP_NODE *chttp_node);

#endif /*_CNGX_HTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

