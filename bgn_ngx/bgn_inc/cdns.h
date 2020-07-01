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

#ifndef _CDNS_H
#define _CDNS_H

#include "type.h"
#include "debug.h"

#include "log.h"

#include "cstring.h"
#include "cbuffer.h"

#include "csocket.inc"
#include "cdns.inc"


/*---------------------------------------- INTERFACE WITH DNS NODE  ----------------------------------------*/
EC_BOOL cdns_header_init(CDNS_HEADER *cdns_header);

EC_BOOL cdns_header_clean(CDNS_HEADER *cdns_header);

void cdns_header_print(LOG *log, const CDNS_HEADER *cdns_header);

/*---------------------------------------- INTERFACE WITH DNS NODE  ----------------------------------------*/
CDNS_NODE *cdns_node_new();

EC_BOOL cdns_node_init(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_clean(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_free(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_recv(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL cdns_node_send(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL cdns_node_need_send(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_close(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_create(CDNS_NODE *cdns_node, const CDNS_REQ * cdns_req);

EC_BOOL cdns_node_send_req(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_recv_rsp(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_disconnect(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_set_callback(CDNS_NODE *cdns_node);

EC_BOOL cdns_node_set_epoll(CDNS_NODE *cdns_node);


/*---------------------------------------- general uint16_t parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_uint16(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, uint16_t *num);

EC_BOOL cdns_make_uint16(CDNS_NODE *cdns_node, const uint16_t num);

/*---------------------------------------- DNS HEADER parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_header(const CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CDNS_HEADER *cdns_header);

EC_BOOL cdns_make_header(CDNS_NODE *cdns_node, CDNS_HEADER *cdns_header);

/*---------------------------------------- DNS HOST parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_host(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CSTRING *host);

EC_BOOL cdns_make_host(CDNS_NODE *cdns_node, const CSTRING *host);

/*---------------------------------------- DNS QUERY parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_query(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CSTRING *host, uint16_t *qt, uint16_t *qc);

EC_BOOL cdns_make_query(CDNS_NODE *cdns_node, const CSTRING *host, const uint16_t qt, const uint16_t qc);

/*---------------------------------------- DNS ANSWER parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_answer(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CSTRING *host, uint16_t *at, uint16_t *ac, uint32_t *live, uint16_t *len, UINT32 *resource);

EC_BOOL cdns_make_answer(CDNS_NODE *cdns_node, const CSTRING *host, const uint16_t at, const uint16_t ac, const uint32_t live, const UINT32 resource, const uint16_t len);

/*---------------------------------------- DNS REQ/RSP parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_rsp(CDNS_NODE *cdns_node, CDNS_RSP *cdns_rsp);

EC_BOOL cdns_make_req(CDNS_NODE *cdns_node, const CDNS_REQ *cdns_req);


/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * CDNS_REQ and CDNS_RSP interfaces
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
CDNS_REQ *cdns_req_new();

EC_BOOL cdns_req_init(CDNS_REQ *cdns_req);

EC_BOOL cdns_req_clean(CDNS_REQ *cdns_req);

EC_BOOL cdns_req_free(CDNS_REQ *cdns_req);

void    cdns_req_print(LOG *log, const CDNS_REQ *cdns_req);

EC_BOOL cdns_req_set_server(CDNS_REQ *cdns_req, const char *server);

EC_BOOL cdns_req_set_ipaddr(CDNS_REQ *cdns_req, const char *ipaddr);

EC_BOOL cdns_req_set_port(CDNS_REQ *cdns_req, const char *port);

EC_BOOL cdns_req_set_host(CDNS_REQ *cdns_req, const char *host);

CDNS_RSP *cdns_rsp_new();

EC_BOOL cdns_rsp_init(CDNS_RSP *cdns_rsp);

EC_BOOL cdns_rsp_clean(CDNS_RSP *cdns_rsp);

EC_BOOL cdns_rsp_free(CDNS_RSP *cdns_rsp);

void    cdns_rsp_print(LOG *log, const CDNS_RSP *cdns_rsp);

CDNS_RSP_NODE *cdns_rsp_node_new();

EC_BOOL cdns_rsp_node_init(CDNS_RSP_NODE *cdns_rsp_node);

EC_BOOL cdns_rsp_node_clean(CDNS_RSP_NODE *cdns_rsp_node);

EC_BOOL cdns_rsp_node_free(CDNS_RSP_NODE *cdns_rsp_node);

void    cdns_rsp_node_print(LOG *log, const CDNS_RSP_NODE *cdns_rsp_node);

EC_BOOL cdns_request_basic(const CDNS_REQ *cdns_req, CDNS_NODE_SET_CALLBACK handler, void *private_data0, void *private_data1);

EC_BOOL cdns_request(const CDNS_REQ *cdns_req, CDNS_RSP *cdns_rsp);


#endif /*_CDNS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

