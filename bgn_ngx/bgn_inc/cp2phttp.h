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

#define CP2PHTTP_REST_API_NAME            "p2p"

EC_BOOL cp2phttp_log_start();

EC_BOOL cp2phttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_http_post(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_http_put(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_http_get(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_http_head(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cp2phttp_commit_response(CHTTP_NODE *chttp_node);


EC_BOOL cp2phttp_commit_upload_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_upload_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_upload_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_upload_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_push_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_push_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_push_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_push_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_flush_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_flush_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_online_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_online_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_online_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_online_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_offline_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_offline_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_offline_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_offline_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_upper_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_upper_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_upper_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_upper_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_edge_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_edge_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_edge_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_edge_response(CHTTP_NODE *chttp_node);

EC_BOOL cp2phttp_commit_refresh_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_handle_refresh_request(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_make_refresh_response(CHTTP_NODE *chttp_node);
EC_BOOL cp2phttp_commit_refresh_response(CHTTP_NODE *chttp_node);


#endif /*_CP2PHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

