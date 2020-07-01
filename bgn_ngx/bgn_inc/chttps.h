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

#ifndef _CHTTPS_H
#define _CHTTPS_H

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "type.h"
#include "debug.h"

#include "http_parser.h"
#include "cbuffer.h"
#include "chunk.h"

#include "csocket.inc"
#include "chttps.inc"
#include "csrv.h"

#define CHTTPS_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC

/*---------------------------------------- INTERFACE WITH HTTP NODE  ----------------------------------------*/

EC_BOOL chttps_node_recv_req(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_send_req(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_recv_rsp(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_send_rsp(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_icheck(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_complete(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_close(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_timeout(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_shutdown(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_recv(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL chttps_node_send(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode);


/*---- TODO END : replace these interfaces by macros*/

/*---------------------------------------- HTTP SERVER ----------------------------------------*/
CSRV * chttps_srv_start(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 md_id);

EC_BOOL chttps_srv_end(CSRV *csrv);

EC_BOOL chttps_srv_bind_modi(CSRV *csrv, const UINT32 modi);

EC_BOOL chttps_srv_accept_once(CSRV *csrv, EC_BOOL *continue_flag);

EC_BOOL chttps_srv_accept(CSRV *csrv);

/*---------------------------------------- COMMIT RESPONSE FOR EMITTING  ----------------------------------------*/
EC_BOOL chttps_commit_error_response(CHTTP_NODE *chttp_node);

EC_BOOL chttps_commit_error_request(CHTTP_NODE *chttp_node);

/*---------------------------------------- REQUEST REST LIST MANAGEMENT ----------------------------------------*/

EC_BOOL chttps_rest_list_push(const char *name, EC_BOOL (*commit)(CHTTP_NODE *));

CHTTP_REST *chttps_rest_list_pop(const char *name, const uint32_t len);

CHTTP_REST *chttps_rest_list_find(const char *name, const uint32_t len);

/*---------------------------------------- REQUEST DEFER QUEUE MANAGEMENT ----------------------------------------*/

EC_BOOL chttps_defer_request_queue_init();

EC_BOOL chttps_defer_request_queue_clean();

EC_BOOL chttps_defer_request_queue_is_empty();

EC_BOOL chttps_defer_request_queue_push(CHTTP_NODE *chttp_node);

EC_BOOL chttps_defer_request_queue_erase(CHTTP_NODE *chttp_node);

CHTTP_NODE *chttps_defer_request_queue_pop();

CHTTP_NODE *chttps_defer_request_queue_peek();

EC_BOOL chttps_defer_request_queue_launch(CHTTP_NODE_COMMIT_REQUEST chttp_node_commit_request);

EC_BOOL chttps_defer_request_commit(CHTTP_NODE *chttp_node);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Send Http Request and Handle Http Response
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/


EC_BOOL chttps_node_set_socket_callback(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_reset_socket_callback(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_set_socket_epoll(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_connect(CHTTP_NODE *chttp_node, const UINT32 csocket_block_mode, const UINT32 ipaddr, const UINT32 port);

EC_BOOL chttps_node_disconnect(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_detach(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_handshake_on_client(CHTTP_NODE *chttp_node);

EC_BOOL chttps_node_handshake_on_server(CHTTP_NODE *chttp_node);


/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Block Http Flow
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
EC_BOOL chttps_request_block(const CHTTP_REQ *chttp_req, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Basic Http Flow
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request_basic(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Try to connect remote http server to check connectivity (HEALTH CHECKER)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_node_check(CHTTP_NODE *chttp_node, const UINT32 ipaddr, const UINT32 port);

EC_BOOL chttps_check(const CHTTP_REQ *chttp_req, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Merge Http Request (MERGE ORIGIN FLOW)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request_merge(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Header Http Request (only token owner would store header to storage)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request_header(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * General Http Request Entry
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);
/*----------------------------------------  CHTTPS SEND & RECV  ----------------------------------------*/

EC_BOOL chttps_ssl_send(CHTTP_NODE *chttp_node, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos);
EC_BOOL chttps_ssl_recv(CHTTP_NODE *chttp_node, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);
EC_BOOL chttps_send(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode, const UINT8 * out_buff, const UINT32 out_buff_max_len, UINT32 * pos);
EC_BOOL chttps_recv(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);

#endif /*_CHTTPS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

