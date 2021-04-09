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

#ifndef _CDETECTHTTP_H
#define _CDETECTHTTP_H

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

#define CDETECTHTTP_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC

#define CDETECTHTTP_REST_API_NAME            ("detect")

EC_BOOL cdetecthttp_log_start();

EC_BOOL cdetecthttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_start(CHTTP_NODE *chttp_node, const UINT32 method);
EC_BOOL cdetecthttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cdetecthttp_commit_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_resolvedns_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_resolvedns_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_resolvedns_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_resolvedns_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_startdomain_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_startdomain_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_startdomain_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_startdomain_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_stopdomain_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_stopdomain_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_stopdomain_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_stopdomain_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_process_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_process_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_process_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_process_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_reload_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_reload_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_reload_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_reload_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_status_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_status_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_status_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_status_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_choice_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_choice_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_choice_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_choice_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_logrotate_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_logrotate_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_actsyscfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_actsyscfg_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_breathe_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_breathe_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_paracfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_paracfg_response(CHTTP_NODE *chttp_node);

#endif /*_CDETECTHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

