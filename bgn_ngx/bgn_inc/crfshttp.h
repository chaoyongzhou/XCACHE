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

#ifndef _CRFSHTTP_H
#define _CRFSHTTP_H

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

#define CRFSHTTP_SOCKET_TIMEOUT_NSEC      CONN_TIMEOUT_NSEC

#define CRFSHTTP_REST_API_NAME            "/rfs"

EC_BOOL crfshttp_log_start();

EC_BOOL crfshttp_commit_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_http_post(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_http_get(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_http_head(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL crfshttp_commit_response(CHTTP_NODE *chttp_node);
/**
    interface name rule:
    crfshttp_is_http_[get|post|put|head|delete]_<op>
    crfshttp_commit_<op>_[get|post|put|head|delete]_request
    crfshttp_handle_<op>_[get|post|put|head|delete]_request
    crfshttp_make_<op>_[get|post|put|head|delete]_response
    crfshttp_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL crfshttp_is_http_post_setsmf(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_setsmf_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_setsmf_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_setsmf_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_setsmf_post_response(CHTTP_NODE *chttp_node);

/* only write memory cache but NOT rfs */
EC_BOOL crfshttp_is_http_post_setsmf_memc(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_setsmf_memc_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_setsmf_memc_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_setsmf_memc_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_setsmf_memc_post_response(CHTTP_NODE *chttp_node);

/* check whether a file is in memory cache */
EC_BOOL crfshttp_is_http_get_check_memc(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_check_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_check_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_check_memc_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_check_memc_get_response(CHTTP_NODE *chttp_node);

/* read from memory cache only but NOT rfs */
EC_BOOL crfshttp_is_http_get_getsmf_memc(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_getsmf_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_getsmf_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_getsmf_memc_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_getsmf_memc_get_response(CHTTP_NODE *chttp_node);

/* update file in memory cache only but NOT rfs */
EC_BOOL crfshttp_is_http_post_update_memc(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_update_memc_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_update_memc_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_update_memc_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_update_memc_post_response(CHTTP_NODE *chttp_node);

/* delete file from memory cache only but NOT rfs */
EC_BOOL crfshttp_is_http_get_dsmf_memc(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_dsmf_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_dsmf_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_dsmf_memc_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_dsmf_memc_get_response(CHTTP_NODE *chttp_node);

/* delete dir from memory cache only but NOT rfs */
EC_BOOL crfshttp_is_http_get_ddir_memc(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_ddir_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_ddir_memc_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_ddir_memc_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_ddir_memc_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_head_getsmf(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_getsmf_head_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_getsmf_head_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_getsmf_head_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_getsmf_head_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_lock_req(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_lock_req_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_lock_req_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_lock_req_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_lock_req_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_unlock_req(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_unlock_req_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_unlock_req_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_unlock_req_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_unlock_req_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_unlock_notify_req(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_unlock_notify_req_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_unlock_notify_req_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_unlock_notify_req_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_unlock_notify_req_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_breathe(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_breathe_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_breathe_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_breathe_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_breathe_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_retire(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_retire_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_retire_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_recycle(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_recycle_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_recycle_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_recycle_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_recycle_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_flush(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_flush_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_flush_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_flush_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_flush_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_getsmf(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_getsmf_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_getsmf_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_getsmf_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_getsmf_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_dsmf(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_dsmf_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_dsmf_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_dsmf_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_dsmf_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_ddir(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_ddir_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_ddir_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_ddir_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_ddir_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_sexpire(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_sexpire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_sexpire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_sexpire_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_sexpire_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_post_update(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_update_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_update_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_update_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_update_post_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_post_renew(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_renew_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_renew_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_renew_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_renew_post_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_post_mexpire(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mexpire_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_mexpire_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_mexpire_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mexpire_post_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_post_mdsmf(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mdsmf_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_mdsmf_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_mdsmf_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mdsmf_post_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_post_mdbgf(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mdbgf_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_mdbgf_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_mdbgf_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mdbgf_post_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_post_mddir(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mddir_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_mddir_post_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_mddir_post_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_mddir_post_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_logrotate(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_logrotate_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_logrotate_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_logrotate_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_logrotate_get_response(CHTTP_NODE *chttp_node);


EC_BOOL crfshttp_is_http_get_actsyscfg(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_actsyscfg_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_actsyscfg_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_actsyscfg_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_actsyscfg_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_qtree(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_qtree_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_qtree_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_qtree_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_qtree_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_file_wait(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_file_wait_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_file_wait_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_file_wait_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_file_wait_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_file_notify(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_file_notify_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_file_notify_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_file_notify_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_file_notify_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_cond_wakeup(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_cond_wakeup_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_cond_wakeup_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_cond_wakeup_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_cond_wakeup_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_renew_header(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_renew_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_renew_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_renew_header_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_renew_header_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_wait_header(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_wait_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_wait_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_wait_header_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_wait_header_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_locked_file_retire(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_locked_file_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_locked_file_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_locked_file_retire_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_locked_file_retire_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_rfs_up(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_rfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_rfs_up_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_up_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_rfs_down(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_rfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_rfs_down_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_down_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_rfs_add(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_rfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_rfs_add_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_add_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_rfs_del(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_rfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_rfs_del_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_del_get_response(CHTTP_NODE *chttp_node);

EC_BOOL crfshttp_is_http_get_rfs_list(const CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_handle_rfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_make_rfs_list_get_response(CHTTP_NODE *chttp_node);
EC_BOOL crfshttp_commit_rfs_list_get_response(CHTTP_NODE *chttp_node);

#endif /*_CRFSHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

