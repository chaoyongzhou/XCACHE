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

#ifndef _CHFSHTTP_H
#define _CHFSHTTP_H

#include "type.h"
#include "debug.h"

#include "cstring.h"

#include "csocket.inc"
#include "task.inc"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "http_parser.h"

#define CHFSHTTP_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC
//#define CHFSHTTP_KEEPALIVE_SWITCH     CONN_KEEPALIVE_SWITCH

#define CHFSHTTP_REST_API_NAME            ("/hfs")

EC_BOOL chfshttp_log_start();

EC_BOOL chfshttp_commit_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_http_post(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_http_get(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_http_head(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL chfshttp_commit_response(CHTTP_NODE *chttp_node);
/**
    interface name rule:
    chfshttp_is_http_[get|post|put|head|delete]_<op>
    chfshttp_commit_<op>_[get|post|put|head|delete]_request
    chfshttp_handle_<op>_[get|post|put|head|delete]_request
    chfshttp_make_<op>_[get|post|put|head|delete]_response
    chfshttp_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL chfshttp_is_http_post_setsmf(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_setsmf_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_setsmf_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_setsmf_post_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_setsmf_post_response(CHTTP_NODE *chfshttp_node);

/* only write memory cache but NOT hfs */
EC_BOOL chfshttp_is_http_post_setsmf_memc(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_setsmf_memc_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_setsmf_memc_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_setsmf_memc_post_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_setsmf_memc_post_response(CHTTP_NODE *chfshttp_node);

/* check whether a file is in memory cache */
EC_BOOL chfshttp_is_http_get_check_memc(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_check_memc_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_check_memc_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_check_memc_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_check_memc_get_response(CHTTP_NODE *chfshttp_node);

/* read from memory cache only but NOT hfs */
EC_BOOL chfshttp_is_http_get_getsmf_memc(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_getsmf_memc_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_getsmf_memc_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_getsmf_memc_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_getsmf_memc_get_response(CHTTP_NODE *chfshttp_node);

/* update file in memory cache only but NOT hfs */
EC_BOOL chfshttp_is_http_post_update_memc(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_update_memc_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_update_memc_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_update_memc_post_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_update_memc_post_response(CHTTP_NODE *chfshttp_node);

/* delete file from memory cache only but NOT hfs */
EC_BOOL chfshttp_is_http_get_dsmf_memc(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_dsmf_memc_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_dsmf_memc_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_dsmf_memc_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_dsmf_memc_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_head_getsmf(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_getsmf_head_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_getsmf_head_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_getsmf_head_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_getsmf_head_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_lock_req(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_lock_req_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_lock_req_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_lock_req_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_lock_req_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_unlock_req(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_unlock_req_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_unlock_req_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_unlock_req_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_unlock_req_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_unlock_notify_req(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_unlock_notify_req_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_unlock_notify_req_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_unlock_notify_req_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_unlock_notify_req_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_breathe(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_breathe_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_breathe_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_breathe_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_breathe_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_retire(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_retire_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_retire_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_retire_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_retire_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_recycle(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_recycle_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_recycle_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_recycle_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_recycle_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_flush(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_flush_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_flush_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_flush_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_flush_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_getsmf(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_getsmf_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_getsmf_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_getsmf_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_getsmf_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_dsmf(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_dsmf_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_dsmf_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_dsmf_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_dsmf_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_ddir(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_ddir_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_ddir_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_ddir_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_ddir_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_sexpire(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_sexpire_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_sexpire_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_sexpire_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_sexpire_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_post_update(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_update_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_update_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_update_post_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_update_post_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_post_mexpire(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_mexpire_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_mexpire_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_mexpire_post_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_mexpire_post_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_post_mdsmf(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_mdsmf_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_mdsmf_post_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_mdsmf_post_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_mdsmf_post_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_logrotate(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_logrotate_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_logrotate_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_logrotate_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_logrotate_get_response(CHTTP_NODE *chfshttp_node);


EC_BOOL chfshttp_is_http_get_actsyscfg(const CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_actsyscfg_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_handle_actsyscfg_get_request(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_make_actsyscfg_get_response(CHTTP_NODE *chfshttp_node);
EC_BOOL chfshttp_commit_actsyscfg_get_response(CHTTP_NODE *chfshttp_node);

EC_BOOL chfshttp_is_http_get_file_wait(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_file_wait_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_file_wait_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_file_wait_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_file_wait_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_file_notify(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_file_notify_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_file_notify_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_file_notify_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_file_notify_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_cond_wakeup(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_cond_wakeup_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_cond_wakeup_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_cond_wakeup_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_cond_wakeup_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_renew_header(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_renew_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_renew_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_renew_header_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_renew_header_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_wait_header(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_wait_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_wait_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_wait_header_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_wait_header_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_locked_file_retire(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_locked_file_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_locked_file_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_locked_file_retire_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_locked_file_retire_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_hfs_up(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_hfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_hfs_up_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_up_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_hfs_down(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_hfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_hfs_down_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_down_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_hfs_add(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_hfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_hfs_add_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_add_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_hfs_del(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_hfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_hfs_del_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_del_get_response(CHTTP_NODE *chttp_node);

EC_BOOL chfshttp_is_http_get_hfs_list(const CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_handle_hfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_make_hfs_list_get_response(CHTTP_NODE *chttp_node);
EC_BOOL chfshttp_commit_hfs_list_get_response(CHTTP_NODE *chttp_node);

#endif /*_CHFSHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

