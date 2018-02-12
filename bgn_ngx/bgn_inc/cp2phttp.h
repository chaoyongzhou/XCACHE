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

#ifndef _CP2PHTTP_H
#define _CP2PHTTP_H

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

#define CP2PHTTP_SOCKET_TIMEOUT_NSEC      CONN_TIMEOUT_NSEC

#define CP2PHTTP_REST_API_NAME            "/p2p"

EC_BOOL cp2phttp_log_start();

EC_BOOL cp2phttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_http_post(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_http_get(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_http_head(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cp2phttp_commit_response(CHTTP_NODE *chttp_node);
/**
    interface name rule:
    cp2phttp_is_http_[get|post|put|head|delete]_<op>
    cp2phttp_commit_<op>_[get|post|put|head|delete]_request
    cp2phttp_handle_<op>_[get|post|put|head|delete]_request
    cp2phttp_make_<op>_[get|post|put|head|delete]_response
    cp2phttp_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL cp2phttp_is_http_post_upload(const CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_upload_post_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_upload_post_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_upload_post_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_upload_post_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_is_http_get_push(const CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_push_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_push_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_push_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_push_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_is_http_get_flush(const CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_flush_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_flush_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_flush_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_flush_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_is_http_get_online(const CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_online_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_online_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_online_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_online_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_is_http_get_offline(const CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_offline_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_offline_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_offline_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_offline_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_is_http_get_upper(const CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_upper_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_upper_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_upper_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_upper_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_is_http_get_edge(const CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_edge_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_edge_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_edge_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_edge_get_response(CHTTP_NODE *chttp_node);


#endif /*_CP2PHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

