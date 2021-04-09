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

#ifndef _CRFSHTTPS_H
#define _CRFSHTTPS_H

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

#define CRFSHTTPS_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC

#define CRFSHTTPS_REST_API_NAME            ("rfs")

EC_BOOL crfshttps_log_start();

EC_BOOL crfshttps_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_start(CHTTP_NODE *chttp_node, const UINT32 method);
EC_BOOL crfshttps_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL crfshttps_commit_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_setsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_setsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_setsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_setsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_lock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_lock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_lock_req_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_lock_req_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_unlock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_unlock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_unlock_req_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_unlock_req_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_unlock_notify_req_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_unlock_notify_req_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_unlock_notify_req_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_unlock_notify_req_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_breathe_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_breathe_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_retire_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_retire_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_recycle_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_recycle_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_recycle_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_recycle_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_flush_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_flush_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_getsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_getsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_getsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_getsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_dsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_dsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_dsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_dsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_ddir_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_ddir_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_ddir_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_ddir_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_sexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_sexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_sexpire_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_sexpire_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_update_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_update_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_update_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_update_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_renew_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_renew_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_renew_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_renew_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_mexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_mexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_mexpire_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_mexpire_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_mdsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_mdsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_mdsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_mdsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_mddir_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_mddir_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_mddir_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_mddir_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_logrotate_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_logrotate_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_actsyscfg_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_actsyscfg_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_qtree_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_qtree_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_qtree_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_qtree_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_file_notify_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_file_notify_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_file_notify_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_file_notify_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_cond_wakeup_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_cond_wakeup_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_cond_wakeup_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_cond_wakeup_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_renew_header_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_renew_header_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_renew_header_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_renew_header_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_locked_file_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_locked_file_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_locked_file_retire_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_locked_file_retire_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttps_commit_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_handle_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_make_paracfg_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttps_commit_paracfg_response(CHTTP_NODE *chttp_node);

#endif /*_CRFSHTTPS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

