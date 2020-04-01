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

#ifndef _CXFSHTTPS_H
#define _CXFSHTTPS_H

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

#define CXFSHTTPS_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC

#define CXFSHTTPS_REST_API_NAME            ("/xfs")

EC_BOOL cxfshttps_log_start();

EC_BOOL cxfshttps_commit_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_http_post(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_http_get(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_http_head(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_commit_end(CHTTPS_NODE *chttp_node, EC_BOOL result);
EC_BOOL cxfshttps_commit_response(CHTTPS_NODE *chttp_node);
/**
    interface name rule:
    cxfshttps_is_http_[get|post|put|head|delete]_<op>
    cxfshttps_commit_<op>_[get|post|put|head|delete]_request
    cxfshttps_handle_<op>_[get|post|put|head|delete]_request
    cxfshttps_make_<op>_[get|post|put|head|delete]_response
    cxfshttps_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL cxfshttps_is_http_post_setsmf(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_setsmf_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_setsmf_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_setsmf_post_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_setsmf_post_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_head_getsmf(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_getsmf_head_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_getsmf_head_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_getsmf_head_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_getsmf_head_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_lock_req(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_lock_req_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_lock_req_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_lock_req_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_lock_req_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_unlock_req(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_unlock_req_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_unlock_req_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_unlock_req_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_unlock_req_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_unlock_notify_req(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_unlock_notify_req_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_unlock_notify_req_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_unlock_notify_req_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_unlock_notify_req_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_breathe(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_breathe_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_breathe_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_breathe_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_breathe_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_retire(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_retire_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_retire_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_retire_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_retire_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_recycle(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_recycle_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_recycle_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_recycle_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_recycle_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_flush(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_flush_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_flush_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_flush_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_flush_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_getsmf(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_getsmf_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_getsmf_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_getsmf_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_getsmf_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_dsmf(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_dsmf_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_dsmf_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_dsmf_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_dsmf_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_ddir(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_ddir_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_ddir_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_ddir_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_ddir_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_sexpire(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_sexpire_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_sexpire_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_sexpire_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_sexpire_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_post_update(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_update_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_update_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_update_post_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_update_post_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_post_renew(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_renew_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_renew_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_renew_post_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_renew_post_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_post_mexpire(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_mexpire_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_mexpire_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_mexpire_post_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_mexpire_post_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_post_mdsmf(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_mdsmf_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_mdsmf_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_mdsmf_post_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_mdsmf_post_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_post_mddir(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_mddir_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_mddir_post_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_mddir_post_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_mddir_post_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_logrotate(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_logrotate_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_logrotate_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_logrotate_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_logrotate_get_response(CHTTPS_NODE *chttps_node);


EC_BOOL cxfshttps_is_http_get_actsyscfg(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_actsyscfg_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_actsyscfg_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_actsyscfg_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_actsyscfg_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_qtree(const CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_qtree_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_handle_qtree_get_request(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_make_qtree_get_response(CHTTPS_NODE *chttps_node);
EC_BOOL cxfshttps_commit_qtree_get_response(CHTTPS_NODE *chttps_node);

EC_BOOL cxfshttps_is_http_get_file_wait(const CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_file_wait_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_handle_file_wait_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_make_file_wait_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_file_wait_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cxfshttps_is_http_get_file_notify(const CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_file_notify_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_handle_file_notify_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_make_file_notify_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_file_notify_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cxfshttps_is_http_get_cond_wakeup(const CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_cond_wakeup_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_handle_cond_wakeup_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_make_cond_wakeup_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_cond_wakeup_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cxfshttps_is_http_get_renew_header(const CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_renew_header_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_handle_renew_header_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_make_renew_header_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_renew_header_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cxfshttps_is_http_get_wait_header(const CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_wait_header_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_handle_wait_header_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_make_wait_header_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_wait_header_get_response(CHTTPS_NODE *chttp_node);

EC_BOOL cxfshttps_is_http_get_locked_file_retire(const CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_locked_file_retire_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_handle_locked_file_retire_get_request(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_make_locked_file_retire_get_response(CHTTPS_NODE *chttp_node);
EC_BOOL cxfshttps_commit_locked_file_retire_get_response(CHTTPS_NODE *chttp_node);

#endif /*_CXFSHTTPS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

