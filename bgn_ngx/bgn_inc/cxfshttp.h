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

#ifndef _CXFSHTTP_H
#define _CXFSHTTP_H

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

#define CXFSHTTP_SOCKET_TIMEOUT_NSEC      CONN_TIMEOUT_NSEC

#define CXFSHTTP_REST_API_NAME            "xfs"

EC_BOOL cxfshttp_log_start();

EC_BOOL cxfshttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_start(CHTTP_NODE *chttp_node, const UINT32 method);
EC_BOOL cxfshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL cxfshttp_commit_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_setsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_setsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_setsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_setsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_getsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_getsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_getsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_getsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_lock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_lock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_lock_req_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_lock_req_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_unlock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_unlock_req_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_unlock_req_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_unlock_req_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_unlock_notify_req_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_unlock_notify_req_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_unlock_notify_req_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_unlock_notify_req_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_breathe_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_breathe_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_breathe_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_retire_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_retire_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_recycle_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_recycle_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_recycle_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_recycle_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_flush_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_flush_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_flush_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_setreadonly_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_setreadonly_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_setreadonly_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_setreadonly_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_unsetreadonly_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_unsetreadonly_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_unsetreadonly_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_unsetreadonly_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_isreadonly_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_isreadonly_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_isreadonly_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_isreadonly_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_sync_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_sync_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_sync_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_sync_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_replayop_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_replayop_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_replayop_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_replayop_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_dsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_dsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_dsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_dsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_ddir_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_ddir_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_ddir_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_ddir_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_sexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_sexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_sexpire_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_sexpire_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_meta_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_meta_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_meta_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_meta_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_update_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_update_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_update_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_update_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_renew_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_renew_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_renew_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_renew_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_mexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_mexpire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_mexpire_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_mexpire_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_mdsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_mdsmf_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_mdsmf_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_mdsmf_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_mddir_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_mddir_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_mddir_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_mddir_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_logrotate_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_logrotate_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_logrotate_response(CHTTP_NODE *chttp_node);


EC_BOOL cxfshttp_commit_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_actsyscfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_actsyscfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_actsyscfg_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_qtree_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_qtree_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_qtree_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_qtree_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_statusnp_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_statusnp_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_statusnp_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_statusnp_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_statusdn_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_statusdn_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_statusdn_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_statusdn_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_file_notify_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_file_notify_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_file_notify_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_file_notify_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_file_terminate_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_file_terminate_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_file_terminate_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_file_terminate_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_cond_wakeup_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_cond_wakeup_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_cond_wakeup_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_cond_wakeup_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_cond_terminate_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_cond_terminate_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_cond_terminate_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_cond_terminate_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_renew_header_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_renew_header_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_renew_header_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_renew_header_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_locked_file_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_locked_file_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_locked_file_retire_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_locked_file_retire_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_wait_file_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_wait_file_retire_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_wait_file_retire_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_wait_file_retire_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_stat_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_stat_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_stat_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_stat_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_paracfg_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_paracfg_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_paracfg_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_activate_ngx_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_activate_ngx_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_activate_ngx_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_activate_ngx_response(CHTTP_NODE *chttp_node);

EC_BOOL cxfshttp_commit_deactivate_ngx_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_handle_deactivate_ngx_request(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_make_deactivate_ngx_response(CHTTP_NODE *chttp_node);
EC_BOOL cxfshttp_commit_deactivate_ngx_response(CHTTP_NODE *chttp_node);

#endif /*_CXFSHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

