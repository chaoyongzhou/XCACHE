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

#ifndef _CSFSHTTP_H
#define _CSFSHTTP_H

#include "type.h"
#include "debug.h"

#include "cstring.h"

#include "csocket.inc"
#include "task.inc"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "http_parser.h"

#define CSFSHTTP_SOCKET_TIMEOUT_NSEC  CONN_TIMEOUT_NSEC
//#define CSFSHTTP_KEEPALIVE_SWITCH     CONN_KEEPALIVE_SWITCH


#define CSFSHTTP_REST_API_NAME            ("/sfs")

EC_BOOL csfshttp_log_start();

EC_BOOL csfshttp_commit_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_http_post(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_http_get(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_http_head(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_commit_end(CHTTP_NODE *chttp_node, EC_BOOL result);
EC_BOOL csfshttp_commit_response(CHTTP_NODE *chttp_node);
/**
    interface name rule:
    csfshttp_is_http_[get|post|put|head|delete]_<op>
    csfshttp_commit_<op>_[get|post|put|head|delete]_request
    csfshttp_handle_<op>_[get|post|put|head|delete]_request
    csfshttp_make_<op>_[get|post|put|head|delete]_response
    csfshttp_commit_<op>_[get|post|put|head|delete]_response
**/

EC_BOOL csfshttp_is_http_post_setsmf(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_setsmf_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_setsmf_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_setsmf_post_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_setsmf_post_response(CHTTP_NODE *csfshttp_node);

/* only write memory cache but NOT sfs */
EC_BOOL csfshttp_is_http_post_setsmf_memc(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_setsmf_memc_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_setsmf_memc_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_setsmf_memc_post_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_setsmf_memc_post_response(CHTTP_NODE *csfshttp_node);

/* check whether a file is in memory cache */
EC_BOOL csfshttp_is_http_get_check_memc(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_check_memc_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_check_memc_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_check_memc_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_check_memc_get_response(CHTTP_NODE *csfshttp_node);

/* read from memory cache only but NOT sfs */
EC_BOOL csfshttp_is_http_get_getsmf_memc(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_getsmf_memc_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_getsmf_memc_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_getsmf_memc_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_getsmf_memc_get_response(CHTTP_NODE *csfshttp_node);

/* update file in memory cache only but NOT sfs */
EC_BOOL csfshttp_is_http_post_update_memc(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_update_memc_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_update_memc_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_update_memc_post_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_update_memc_post_response(CHTTP_NODE *csfshttp_node);

/* delete file from memory cache only but NOT sfs */
EC_BOOL csfshttp_is_http_get_dsmf_memc(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_dsmf_memc_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_dsmf_memc_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_dsmf_memc_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_dsmf_memc_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_head_getsmf(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_getsmf_head_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_getsmf_head_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_getsmf_head_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_getsmf_head_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_lock_req(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_lock_req_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_lock_req_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_lock_req_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_lock_req_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_unlock_req(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_unlock_req_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_unlock_req_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_unlock_req_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_unlock_req_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_unlock_notify_req(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_unlock_notify_req_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_unlock_notify_req_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_unlock_notify_req_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_unlock_notify_req_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_breathe(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_breathe_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_breathe_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_breathe_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_breathe_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_flush(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_flush_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_flush_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_flush_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_flush_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_getsmf(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_getsmf_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_getsmf_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_getsmf_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_getsmf_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_dsmf(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_dsmf_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_dsmf_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_dsmf_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_dsmf_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_ddir(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_ddir_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_ddir_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_ddir_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_ddir_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_sexpire(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_sexpire_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_sexpire_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_sexpire_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_sexpire_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_post_update(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_update_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_update_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_update_post_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_update_post_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_post_mexpire(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_mexpire_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_mexpire_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_mexpire_post_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_mexpire_post_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_post_mdsmf(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_mdsmf_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_mdsmf_post_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_mdsmf_post_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_mdsmf_post_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_logrotate(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_logrotate_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_logrotate_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_logrotate_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_logrotate_get_response(CHTTP_NODE *csfshttp_node);


EC_BOOL csfshttp_is_http_get_actsyscfg(const CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_actsyscfg_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_handle_actsyscfg_get_request(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_make_actsyscfg_get_response(CHTTP_NODE *csfshttp_node);
EC_BOOL csfshttp_commit_actsyscfg_get_response(CHTTP_NODE *csfshttp_node);

EC_BOOL csfshttp_is_http_get_file_wait(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_file_wait_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_file_wait_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_file_wait_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_file_wait_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_file_notify(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_file_notify_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_file_notify_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_file_notify_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_file_notify_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_cond_wakeup(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_cond_wakeup_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_cond_wakeup_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_cond_wakeup_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_cond_wakeup_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_renew_header(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_renew_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_renew_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_renew_header_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_renew_header_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_wait_header(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_wait_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_wait_header_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_wait_header_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_wait_header_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_locked_file_retire(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_locked_file_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_locked_file_retire_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_locked_file_retire_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_locked_file_retire_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_sfs_up(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_sfs_up_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_sfs_up_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_up_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_sfs_down(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_sfs_down_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_sfs_down_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_down_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_sfs_add(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_sfs_add_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_sfs_add_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_add_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_sfs_del(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_sfs_del_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_sfs_del_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_del_get_response(CHTTP_NODE *chttp_node);

EC_BOOL csfshttp_is_http_get_sfs_list(const CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_handle_sfs_list_get_request(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_make_sfs_list_get_response(CHTTP_NODE *chttp_node);
EC_BOOL csfshttp_commit_sfs_list_get_response(CHTTP_NODE *chttp_node);

#endif /*_CSFSHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

