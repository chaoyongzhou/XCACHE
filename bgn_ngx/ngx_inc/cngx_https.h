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

#ifndef _CNGX_HTTPS_H
#define _CNGX_HTTPS_H

#include "type.h"
#include "debug.h"

#include "cstring.h"

#include "csocket.inc"
#include "task.inc"
#include "chttps.inc"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "http_parser.h"

#define CNGX_HTTPS_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC

#define CNGX_HTTPS_REST_API_NAME            ("/ngx")

EC_BOOL cngx_https_log_start();

EC_BOOL cngx_https_commit_request(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_http_post(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_http_get(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_http_head(CHTTPS_NODE *chttps_node);

EC_BOOL cngx_https_commit_end(CHTTPS_NODE *chttp_node, EC_BOOL result);
EC_BOOL cngx_https_commit_response(CHTTPS_NODE *chttp_node);
/**
    interface name rule:
    cngx_https_is_http_[get|post|put|head|delete]_<op>
    cngx_https_commit_<op>_[get|post|put|head|delete]_request
    cngx_https_handle_<op>_[get|post|put|head|delete]_request
    cngx_https_make_<op>_[get|post|put|head|delete]_response
    cngx_https_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL cngx_https_is_http_get_breathe(const CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_breathe_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_handle_breathe_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_make_breathe_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_breathe_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cngx_https_is_http_get_logrotate(const CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_logrotate_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_handle_logrotate_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_make_logrotate_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_logrotate_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cngx_https_is_http_get_actsyscfg(const CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_actsyscfg_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_handle_actsyscfg_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_make_actsyscfg_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cngx_https_commit_actsyscfg_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cngx_https_is_http_get_xfs_up(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_up_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_up_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_up_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_up_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_xfs_down(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_down_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_down_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_down_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_down_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_xfs_add(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_add_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_add_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_add_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_add_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_xfs_del(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_del_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_del_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_del_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_del_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_xfs_list(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_list_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_list_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_list_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_list_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_rfs_up(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_up_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_rfs_up_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_rfs_up_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_up_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_rfs_down(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_down_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_rfs_down_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_rfs_down_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_down_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_rfs_add(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_add_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_rfs_add_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_rfs_add_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_add_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_rfs_del(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_del_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_rfs_del_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_rfs_del_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_del_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cngx_https_is_http_get_rfs_list(const CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_list_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_handle_rfs_list_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_make_rfs_list_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cngx_https_commit_rfs_list_get_response(CHTTPS_NODE *chttp_node);

#endif /*_CNGX_HTTPS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

