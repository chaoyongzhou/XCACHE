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

#ifndef _API_CMD_UI_H
#define _API_CMD_UI_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "type.h"
#include "clist.h"
#include "cvector.h"
#include "cstring.h"
#include "log.h"

#include "api_cmd.inc"

#define API_CMD_LINE_BUFF_SIZE                   ((UINT32) 4096) /*4k*/

EC_BOOL api_cmd_ui_init(CMD_ELEM_VEC *cmd_elem_vec, CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec);

EC_BOOL api_cmd_ui_task_preface();

EC_BOOL api_cmd_ui_init_ccond();

EC_BOOL api_cmd_ui_clean_ccond();

EC_BOOL api_cmd_ui_readline_is_disabled();

EC_BOOL api_cmd_ui_readline_is_enabled();

EC_BOOL api_cmd_ui_readline_set_disabled();

EC_BOOL api_cmd_ui_readline_set_enabled();

EC_BOOL api_cmd_ui_clear_cmd();

EC_BOOL api_cmd_ui_get_cmd();

EC_BOOL api_cmd_ui_task_once(CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec);

EC_BOOL api_cmd_ui_task();

void    api_cmd_ui_do_script(CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec, char *script_name);
void    api_cmd_ui_do_once(CMD_TREE *cmd_tree, CMD_HELP_VEC *cmd_help_vec, char *cmd_line);

EC_BOOL api_cmd_ui_dns_resolve_demo(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_dns_cache_enable(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_dns_cache_disable(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_dns_cache_set_expired_nsec(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_dns_cache_resolve(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_dns_cache_retire(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_dns_cache_show(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_activate_sys_cfg(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_activate_sys_cfg_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_sys_cfg(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_sys_cfg_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_mem(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_mem_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_mem_of_type(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_mem_all_of_type(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_diag_mem(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_diag_mem_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_diag_csocket_cnode(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_diag_csocket_cnode_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_diag_mem_of_type(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_diag_mem_all_of_type(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_clean_mem(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_clean_mem_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_breathing_mem(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_breathing_mem_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_log_level(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_log_level_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_set_log_level_tab(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_set_log_level_tab_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_set_log_level_sec(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_set_log_level_sec_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_say_hello(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_say_hello_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_say_hello_loop(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_say_hello_loop_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_switch_log(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_switch_log_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_rotate_log(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_rotate_log_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_do_test(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_enable_to_rank_node(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_enable_all_to_rank_node(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_disable_to_rank_node(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_disable_all_to_rank_node(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_queue(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_queue_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_check_slowdown(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_check_slowdown_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_client(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_client_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_route(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_route_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_thread(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_thread_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_rank_node(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_rank_node_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_rank_load(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_rank_load_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_shutdown_work(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_shutdown_work_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_shutdown_dbg(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_shutdown_dbg_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_shutdown_mon(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_shutdown_mon_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_taskcomm(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_taskcomm_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_add_route(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_del_route(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_add_conn(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_add_conn_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_run_shell(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_run_shell_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_ping_taskcomm(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_taskcfgchk_net(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_taskcfgchk_net_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_taskcfgchk_route(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_taskcfgchk_route_trace(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_sync_taskcomm_from_local(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_sync_rank_load(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_sync_rank_load_to_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_set_rank_load(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_set_rank_load_on_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_enable_task_brd(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_enable_all_task_brd(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_disable_task_brd(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_disable_all_task_brd(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_csession_add(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_rmv_by_name(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_rmv_by_id(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_set_by_name(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_rmv_by_name_regex(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_rmv_by_id_regex(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_set_by_id(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_get_by_name(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_get_by_id(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_get_by_name_regex(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_get_by_id_regex(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_csession_show(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_exec_download(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_exec_download_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_exec_upload(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_exec_upload_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_exec_shell(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_exec_shell_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_show_version(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_version_all(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_vendor(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_show_vendor_all(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_start_mcast_udp_server(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_stop_mcast_udp_server(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_status_mcast_udp_server(CMD_PARA_VEC * param);

#if 1
EC_BOOL api_cmd_ui_crfs_create_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_create_dn(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_add_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_del_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_mount_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_umount_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_open(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_close(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_read(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_write(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_mkdir(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_search(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_count_file_num(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_count_file_size(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qfile(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qdir(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qlist_path_of_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qlist_seg_of_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qlist_path(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qlist_seg(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qlist_tree_of_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_qlist_tree(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_delete_file(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_delete_dir(CMD_PARA_VEC * param);

/* for deleting root dir / only! */
EC_BOOL api_cmd_ui_crfs_delete_root_dir(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_crfs_delete_path(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_recycle(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_retire(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_flush(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_flush_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_flush_dn(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_npp_lru_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_npp_del_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_dn(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_cached_np_lru_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_cached_np_del_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_cached_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_specific_np_lru_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_specific_np_del_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_specific_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_show_locked_files(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_crfs_md5sum(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_cxfs_create_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_create_dn(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_create_sata_bad_bitmap(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_set_sata_bad_page(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_unset_sata_bad_page(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_check_sata_bad_page(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_sata_bad_pages(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_set_ssd_bad_page(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_unset_ssd_bad_page(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_check_ssd_bad_page(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_ssd_bad_pages(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_add_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_del_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_mount_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_umount_disk(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_open(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_close(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_read(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_write(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_mkdir(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_search(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_count_file_num(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_count_file_size(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qfile(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qdir(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qlist_path_of_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qlist_seg_of_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qlist_path(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qlist_seg(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qlist_tree_of_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_qlist_tree(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_delete_file(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_delete_dir(CMD_PARA_VEC * param);

/* for deleting root dir / only! */
EC_BOOL api_cmd_ui_cxfs_delete_root_dir(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_cxfs_delete_path(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_recycle(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_retire(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_flush(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_flush_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_flush_dn(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_set_read_only(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_unset_read_only(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_check_read_only(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_sync(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_replay_op(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_pop_op(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_npp_lru_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_npp_del_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_dn(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_specific_np_lru_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_specific_np_del_list(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_specific_np(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_locked_files(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_show_wait_files(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cxfs_md5sum(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_ctdns_create_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_start(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_end(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_config_tcid(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_reserve_tcid(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_release_tcid(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_get_tcid(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_get_service(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_set_no_service(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_set_has_service(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_search_tcid(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_search_service(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_count_tcid_num(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_count_node_num(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_delete(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_online(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_offline(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_show_npp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_show_svp(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ctdns_refresh_cache(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_cdetect_show_orig_nodes(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cdetect_show_orig_node(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cdetect_dns_resolve(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cdetect_process(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cdetect_process_loop(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_cp2p_load(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_upload(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_download(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_push(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_push_subnet(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_push_all(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_pull(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_delete(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_delete_subnet(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_delete_all(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_flush(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_flush_subnet(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_flush_all(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_execute_cmd(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_deliver_cmd(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_deliver_cmd_subnet(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_deliver_cmd_all(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_online(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_cp2p_offline(CMD_PARA_VEC * param);

EC_BOOL api_cmd_ui_download_file(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_upload_file(CMD_PARA_VEC * param);

#if 1
EC_BOOL api_cmd_ui_ngx_reload_so(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ngx_switch_so(CMD_PARA_VEC * param);
EC_BOOL api_cmd_ui_ngx_show_so(CMD_PARA_VEC * param);
#endif

#endif


#endif/*_API_CMD_UI_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
