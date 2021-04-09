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

#define CTDNSHTTP_SOCKET_TIMEOUT_NSEC      CONN_TIMEOUT_NSEC

#define CTDNSHTTP_REST_API_NAME            "tdns"

#define CTDNSHTTP_HOST_DEFAULT             "y.pooapp.net"
#define CTDNSBGN_PORT_DEFAULT              "788"
#define CTDNSHTTP_PORT_DEFAULT             "789"
#define CTDNSHTTP_SERVER_DEFAULT           CTDNSHTTP_HOST_DEFAULT":"CTDNSHTTP_PORT_DEFAULT

#define CTDNSHTTP_NODES_SERVICE_NAME       "p2p.nodes" /*on T-DNS server*/

EC_BOOL ctdnshttp_log_start();

EC_BOOL ctdnshttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_start(CHTTP_NODE *chttp_node, const UINT32 method);
EC_BOOL ctdnshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL ctdnshttp_commit_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_gettcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_gettcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_gettcid_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_gettcid_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_settcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_settcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_settcid_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_settcid_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_deltcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_deltcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_deltcid_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_deltcid_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_configtcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_configtcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_configtcid_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_configtcid_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_reservetcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_reservetcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_reservetcid_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_reservetcid_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_releasetcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_releasetcid_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_releasetcid_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_releasetcid_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_flush_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_flush_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_ping_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_ping_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_ping_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_ping_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_online_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_online_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_online_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_online_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_offline_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_offline_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_offline_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_offline_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_upper_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_upper_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_upper_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_upper_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_edge_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_edge_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_edge_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_edge_response(CHTTP_NODE *chttp_node);

EC_BOOL ctdnshttp_commit_refresh_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_handle_refresh_request(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_make_refresh_response(CHTTP_NODE *chttp_node);
EC_BOOL ctdnshttp_commit_refresh_response(CHTTP_NODE *chttp_node);

#endif /*_CTDNSHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

