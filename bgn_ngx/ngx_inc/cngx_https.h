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

#define CNGX_HTTPS_REST_API_NAME            ("ngx")

EC_BOOL cngx_https_log_start();

EC_BOOL cngx_https_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_http_post(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_http_get(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_http_head(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cngx_https_commit_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_breathe_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_breathe_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_logrotate_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_logrotate_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_actsyscfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_actsyscfg_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_xfs_up_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_up_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_up_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_up_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_xfs_down_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_down_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_down_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_down_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_xfs_add_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_add_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_add_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_add_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_xfs_del_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_del_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_del_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_del_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_xfs_list_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_xfs_list_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_xfs_list_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_xfs_list_response(CHTTP_NODE *chttp_node);

EC_BOOL cngx_https_commit_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_handle_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_make_paracfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cngx_https_commit_paracfg_response(CHTTP_NODE *chttp_node);

#endif /*_CNGX_HTTPS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

