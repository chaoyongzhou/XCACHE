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

#ifndef _CTDNSHTTP_H
#define _CTDNSHTTP_H

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

#define CTDNSHTTP_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC
//#define CTDNSHTTP_KEEPALIVE_SWITCH     CONN_KEEPALIVE_SWITCH

#define CTDNSHTTP_REST_API_NAME            ("/tdns")

EC_BOOL ctdnshttp_log_start();

EC_BOOL ctdnshttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_http_post(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_http_get(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_http_head(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL ctdnshttp_commit_response(CHTTP_NODE *chttp_node);
/**
    interface name rule:
    ctdnshttp_is_http_[get|post|put|head|delete]_<op>
    ctdnshttp_commit_<op>_[get|post|put|head|delete]_request
    ctdnshttp_handle_<op>_[get|post|put|head|delete]_request
    ctdnshttp_make_<op>_[get|post|put|head|delete]_response
    ctdnshttp_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL ctdnshttp_is_http_get_gettcid(const CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_gettcid_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_gettcid_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_gettcid_get_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_gettcid_get_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_is_http_get_settcid(const CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_settcid_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_settcid_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_settcid_get_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_settcid_get_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_is_http_get_deltcid(const CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_deltcid_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_deltcid_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_deltcid_get_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_deltcid_get_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_is_http_get_flush(const CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_flush_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_flush_get_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_flush_get_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_flush_get_response(CHTTP_NODE *chttp_node);

#endif /*_CTDNSHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

