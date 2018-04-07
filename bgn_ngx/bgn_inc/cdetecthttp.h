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

#define CDETECTHTTP_REST_API_NAME            ("/detect")

EC_BOOL cdetecthttp_log_start();

EC_BOOL cdetecthttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_http_post(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_http_get(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_http_head(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cdetecthttp_commit_response(CHTTP_NODE *chttp_node);
/**
    interface name rule:
    cdetecthttp_is_http_[get|post|put|head|delete]_<op>
    cdetecthttp_commit_<op>_[get|post|put|head|delete]_request
    cdetecthttp_handle_<op>_[get|post|put|head|delete]_request
    cdetecthttp_make_<op>_[get|post|put|head|delete]_response
    cdetecthttp_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL cdetecthttp_is_http_get_resolvedns(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_resolvedns_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_resolvedns_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_resolvedns_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_resolvedns_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_startdomain(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_startdomain_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_startdomain_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_startdomain_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_startdomain_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_stopdomain(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_stopdomain_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_stopdomain_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_stopdomain_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_stopdomain_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_process(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_process_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_process_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_process_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_process_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_reload(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_reload_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_reload_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_reload_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_reload_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_status(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_status_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_status_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_status_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_status_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_choice(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_choice_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_choice_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_choice_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_choice_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_logrotate(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_logrotate_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_logrotate_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_logrotate_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_logrotate_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_actsyscfg(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_actsyscfg_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_actsyscfg_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_actsyscfg_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_actsyscfg_get_response(CHTTP_NODE *chttp_node);

EC_BOOL cdetecthttp_is_http_get_breathe(const CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_breathe_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_handle_breathe_get_request(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_make_breathe_get_response(CHTTP_NODE *chttp_node);
EC_BOOL cdetecthttp_commit_breathe_get_response(CHTTP_NODE *chttp_node);
#endif /*_CDETECTHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

