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

#ifndef _TASK_H
#define _TASK_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include "task.inc"
#include "mod.h"
#include "super.h"
#include "cstring.h"
#include "ipv4pool.h"
#include "dhcp.h"
#include "crfsmc.inc"

#define CMPI_DBG_RANK      ((UINT32)  0)  /*define debug rank*/
#define CMPI_MON_RANK      ((UINT32)  0)  /*define monitor rank*/
#define CMPI_FWD_RANK      ((UINT32)  0)  /*define forward rank*/
#define CMPI_CRFS_RANK     ((UINT32)  0)  /*define crfs rank*/
#define CMPI_CRFSC_RANK    ((UINT32)  0)  /*define crfsc rank*/
#define CMPI_CXFS_RANK     ((UINT32)  0)  /*define cxfs rank*/

#define CMPI_DBG_TCID_BEG         ((UINT32) 64) /*dbg tcid beg = 0.0.0.64 */
#define CMPI_DBG_TCID_END         ((UINT32) 95) /*dbg tcid beg = 0.0.0.95 */

#define CMPI_MON_TCID_BEG         ((UINT32) 96) /*mon tcid beg = 0.0.0.96 */
#define CMPI_MON_TCID_END         ((UINT32)127) /*mon tcid beg = 0.0.0.127*/

#define CMPI_DBG_MIN_RANK_SIZE    ((UINT32)   1) /*actually, it can be 1, oh shit! superman!*/
#define CMPI_MON_MIN_RANK_SIZE    ((UINT32)   1) /*actually, it can be 1, oh shit! superman!*/
#define CMPI_WORK_MIN_RANK_SIZE   ((UINT32)   1) /*actually, it can be 1, oh shit! superman!*/

#define CMPI_LOCAL_TCID    task_brd_default_get_tcid()
#define CMPI_LOCAL_COMM    task_brd_default_get_comm()
#define CMPI_LOCAL_RANK    task_brd_default_get_rank()
#define CMPI_LOCAL_SIZE    task_brd_default_get_size()

#define TASK_REGISTER_OTHER_SERVER          ((UINT32) 0x04)
#define TASK_REGISTER_UDP_SERVER            ((UINT32) 0x08)
#define TASK_REGISTER_ALL_SERVER            ((UINT32) 0x0F)


#define TASK_DBG_ENTER(__func_name__)  do{}while(0)
#define TASK_DBG_LEAVE(__func_name__)  do{}while(0)


EC_BOOL task_node_buff_type(const UINT32 buff_size, UINT32 *buff_type);
EC_BOOL task_node_buff_alloc(TASK_NODE *task_node, const UINT32 buff_size);
EC_BOOL task_node_buff_realloc(TASK_NODE *task_node, const UINT32 new_size);
EC_BOOL task_node_buff_free(TASK_NODE *task_node);

TASK_NODE *task_node_new(const UINT32 buff_size, const UINT32 location);
EC_BOOL task_node_free(TASK_NODE *task_node);
EC_BOOL task_node_expand_to(TASK_NODE *task_node, const UINT32 new_size);

void    task_node_print(LOG *log, const TASK_NODE *task_node);
void    task_node_dbg(LOG *log, const char *info, const TASK_NODE *task_node);
EC_BOOL task_node_isend(TASK_BRD *task_brd, TASK_NODE *task_node);

TASK_RUNNER_NODE *task_runner_node_new();
EC_BOOL task_runner_node_init(TASK_RUNNER_NODE *task_runner_node);
EC_BOOL task_runner_node_clean(TASK_RUNNER_NODE *task_runner_node);
EC_BOOL task_runner_node_free(TASK_RUNNER_NODE *task_runner_node);

/*default checker*/
EC_BOOL task_default_bool_checker(const EC_BOOL ec_bool);
EC_BOOL task_default_not_null_pointer_checker(const void *pointer);

EC_BOOL task_func_init(TASK_FUNC *task_func);
EC_BOOL task_func_print(LOG *log, const TASK_FUNC *task_func);
UINT32  task_caller(TASK_FUNC *task_func, FUNC_ADDR_NODE *func_addr_node);
void    func_addr_node_print(LOG *log, const FUNC_ADDR_NODE *func_addr_node);
EC_BOOL task_req_func_para_encode(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL task_req_func_para_encode_size(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT32 *size);
EC_BOOL task_req_func_para_decode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node);

EC_BOOL task_rsp_func_para_encode(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
EC_BOOL task_rsp_func_para_encode_size(const UINT32 comm, const UINT32 func_para_num, FUNC_PARA *func_para_tbl, const FUNC_ADDR_NODE *func_addr_node, UINT32 *size);
EC_BOOL task_rsp_func_para_decode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, const UINT32 func_para_num, FUNC_PARA *task_req_func_para_tbl, const FUNC_ADDR_NODE *func_addr_node);

/*--------------------------------------------- task req interface -----------------------------------------*/
TASK_REQ *task_req_new(const UINT32 buff_size, const UINT32 task_seqno, const UINT32 sub_seqno,const UINT32 task_type, const TASK_MGR *task_mgr, const UINT32 location);
EC_BOOL task_req_free(TASK_REQ *task_req);
EC_BOOL task_req_clean(TASK_REQ *task_req);
EC_BOOL task_req_print(LOG * log, const TASK_REQ * task_req);
EC_BOOL task_req_init(TASK_REQ *task_req, const UINT32 task_seqno, const UINT32 sub_seqno,const UINT32 task_type, const TASK_MGR *task_mgr);
EC_BOOL task_req_ldb(TASK_REQ *task_req);
EC_BOOL task_req_encode_header(TASK_REQ *task_req);
EC_BOOL task_req_encode_size(const TASK_REQ *task_req, UINT32 *size);
EC_BOOL task_req_encode(TASK_REQ *task_req);
EC_BOOL task_req_decode(const UINT32 recv_comm, TASK_REQ *task_req);
EC_BOOL task_req_isend(TASK_BRD *task_brd, TASK_REQ *task_req);
UINT32  task_req_func_para_init(const UINT32 func_para_num, FUNC_PARA *func_para_tbl, va_list ap);
EC_BOOL task_req_md_mod_mgr_get(TASK_BRD *task_brd, TASK_REQ *task_req, MOD_MGR **mod_mgr);
EC_BOOL task_req_print(LOG *log, const TASK_REQ *task_req);

UINT32  task_req_time_elapsed(const TASK_REQ *task_req);
UINT32  task_req_time_left(const TASK_REQ *task_req);
EC_BOOL task_req_is_timeout(const TASK_REQ *task_req);
EC_BOOL task_req_cancel(TASK_REQ *task_req);
EC_BOOL task_req_discard(TASK_REQ *task_req);
TASK_RSP * task_req_handle(TASK_REQ *task_req);
void task_req_handle_thread(TASK_BRD *task_brd, TASK_REQ *task_req);

EC_BOOL task_req_local_handle(TASK_REQ *task_req);

/*--------------------------------------------- task rsp interface ---------------------------------------------*/
TASK_RSP * task_rsp_new(const UINT32 buff_size, const UINT32 location);
EC_BOOL task_rsp_free(TASK_RSP *task_rsp);
EC_BOOL task_rsp_clean(TASK_RSP *task_rsp);
EC_BOOL task_rsp_print(LOG *log, const TASK_RSP *task_rsp);
EC_BOOL task_rsp_init(TASK_RSP *task_rsp);
EC_BOOL task_rsp_encode_size(TASK_RSP *task_rsp, FUNC_ADDR_NODE *func_addr_node, UINT32 *size);
EC_BOOL task_rsp_encode(TASK_RSP *task_rsp);
EC_BOOL task_rsp_decode(const UINT32 recv_comm, TASK_BRD *task_brd, TASK_RSP *task_rsp, TASK_MGR **task_mgr_ret, UINT32 *ret_val_check_succ_flag);
EC_BOOL task_rsp_isend(TASK_BRD *task_brd, TASK_RSP *task_rsp);
EC_BOOL task_rsp_md_mod_mgr_get(TASK_BRD *task_brd, TASK_RSP *task_rsp, MOD_MGR **mod_mgr);

UINT32  task_rsp_time_elapsed(const TASK_RSP *task_rsp);
UINT32  task_rsp_time_left(const TASK_RSP *task_rsp);
EC_BOOL task_rsp_is_timeout(const TASK_RSP *task_rsp);

/*--------------------------------------------- task fwd interface ---------------------------------------------*/
EC_BOOL task_fwd_free(TASK_FWD *task_fwd);
EC_BOOL task_fwd_decode(const UINT32 recv_comm, TASK_FWD *task_fwd);
EC_BOOL task_fwd_isend(TASK_BRD *task_brd, TASK_FWD *task_fwd);

EC_BOOL task_fwd_is_to_local(const TASK_BRD *task_brd, const TASK_FWD *task_fwd);
EC_BOOL task_fwd_direct(TASK_BRD *task_brd, TASK_FWD *task_fwd);

/*--------------------------------------------- task any interface ---------------------------------------------*/
EC_BOOL task_any_init(TASK_ANY *task_any);
TASK_ANY *task_any_new(const UINT32 buff_size, const UINT32 location);
EC_BOOL task_any_free(TASK_ANY *task_any);
EC_BOOL task_any_decode(const UINT32 recv_comm, TASK_ANY *task_any);

/*--------------------------------------------- task rank node interface ---------------------------------------------*/
TASK_RANK_NODE * task_rank_node_new();
EC_BOOL task_rank_node_init(TASK_RANK_NODE *task_rank_node);
EC_BOOL task_rank_node_clean(TASK_RANK_NODE *task_rank_node);
EC_BOOL task_rank_node_free(TASK_RANK_NODE *task_rank_node);
EC_BOOL task_rank_node_enable(TASK_RANK_NODE *task_rank_node);
EC_BOOL task_rank_node_disable(TASK_RANK_NODE *task_rank_node);
EC_BOOL task_rank_node_reserve(TASK_RANK_NODE *task_rank_node);
void    task_rank_node_print(LOG *log, const TASK_RANK_NODE *task_rank_node);

/*--------------------------------------------- task rank tbl interface ---------------------------------------------*/
CVECTOR * task_rank_tbl_new(const UINT32 size);
EC_BOOL task_rank_tbl_clean(CVECTOR *task_rank_tbl);
EC_BOOL task_rank_tbl_free(CVECTOR *task_rank_tbl);
EC_BOOL task_rank_tbl_enable(CVECTOR *task_rank_tbl, const UINT32 rank);
EC_BOOL task_rank_tbl_disable(CVECTOR *task_rank_tbl, const UINT32 rank);
EC_BOOL task_rank_tbl_reserve(CVECTOR *task_rank_tbl, const UINT32 rank);
EC_BOOL task_rank_tbl_enable_all(CVECTOR *task_rank_tbl);
EC_BOOL task_rank_tbl_disable_all(CVECTOR *task_rank_tbl);
void    task_rank_tbl_print(LOG *log, const CVECTOR *task_rank_tbl);

/*--------------------------------------------- task rank load interface ---------------------------------------------*/
EC_BOOL task_brd_rank_load_tbl_init(TASK_BRD *task_brd);
EC_BOOL task_brd_rank_load_tbl_clean(TASK_BRD *task_brd);
EC_BOOL task_brd_rank_load_tbl_push(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const UINT32 load);
EC_BOOL task_brd_rank_load_tbl_push_all(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 size);
EC_BOOL task_brd_rank_load_tbl_pop_all(TASK_BRD *task_brd, const UINT32 tcid);
EC_BOOL task_brd_rank_load_tbl_set_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const UINT32 load);
EC_BOOL task_brd_rank_load_tbl_fast_decrease(TASK_BRD *task_brd, const UINT32 interval_nsec);

UINT32  task_brd_rank_load_tbl_get_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);
UINT32  task_brd_rank_load_tbl_get_obj(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);
UINT32  task_brd_rank_load_tbl_get_cpu(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);
UINT32  task_brd_rank_load_tbl_get_mem(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);
UINT32  task_brd_rank_load_tbl_get_dsk(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);
UINT32  task_brd_rank_load_tbl_get_net(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);

/*--------------------------------------------- task brd interface ---------------------------------------------*/
LOG * task_brd_default_init(int argc, char **argv);

EC_BOOL task_brd_exit(TASK_BRD *task_brd);

TASKS_CFG *task_brd_register_node_fetch(TASK_BRD *task_brd, const UINT32 tcid);

EC_BOOL task_brd_register_one(TASK_BRD *task_brd, const UINT32 remote_tcid, const UINT32 remote_srv_ipaddr, const UINT32 remote_srv_port, const UINT32 conn_num);

EC_BOOL task_brd_register_node(TASK_BRD *task_brd, const UINT32 tcid);

EC_BOOL task_brd_register_cluster(TASK_BRD *task_brd);

EC_BOOL task_brd_enable_coredump();

EC_BOOL task_brd_os_setting(TASK_BRD *task_brd);

EC_BOOL task_brd_os_setting_print(LOG *log);

TASK_BRD * task_brd_default_get();

UINT8 *task_brd_default_sys_cfg_xml();

UINT8 *task_brd_default_basic_cfg_xml();

CTIMET task_brd_default_get_time();

CTM *task_brd_default_get_localtime();

CTMV *task_brd_default_get_daytime();

char *task_brd_default_get_time_str();

CEPOLL *task_brd_default_get_cepoll();

EC_BOOL task_brd_default_has_detect();

TASKS_CFG *task_brd_default_get_detect();

EC_BOOL task_brd_default_set_ngx_exiting();

EC_BOOL task_brd_default_is_ngx_exiting();

CCONNP_MGR *task_brd_default_get_http_cconnp_mgr();

CTIMET task_brd_get_time(TASK_BRD *task_brd);

CTM  *task_brd_get_localtime(TASK_BRD *task_brd);

CTMV *task_brd_get_daytime(TASK_BRD *task_brd);

char *task_brd_get_time_str(TASK_BRD *task_brd);

void  task_brd_update_time(TASK_BRD *task_brd);

void  task_brd_update_time_default();

CEPOLL *task_brd_get_cepoll(TASK_BRD *task_brd);

UINT32 task_brd_default_get_ipaddr();

UINT32 task_brd_default_get_port();

UINT32 task_brd_default_get_tcid();

UINT32 task_brd_default_get_comm();

UINT32 task_brd_default_get_rank();

UINT32 task_brd_default_get_size();

UINT32 task_brd_default_get_super();

CRFSMC  *task_brd_default_get_crfsmc();

EC_BOOL task_brd_default_set_crfsmc(void *data, TASK_BRD_EXTRA_CLEANER cleanup);
EC_BOOL task_brd_set_crfsmc(TASK_BRD *task_brd, void *data, TASK_BRD_EXTRA_CLEANER cleanup);

UINT32 task_brd_default_local_taskc();

EC_BOOL task_brd_load_basic_config(TASK_BRD *task_brd, UINT32 *udp_mcast_ipaddr, UINT32 *udp_mcast_port);

EC_BOOL task_brd_mcast_config(TASK_BRD *task_brd);

EC_BOOL task_brd_wait_basic_config(TASK_BRD *task_brd, const CSTRING *bcast_dhcp_netcard_cstr, UINT32 *udp_mcast_ipaddr, UINT32 *udp_mcast_port);
EC_BOOL task_brd_wait_sys_config(TASK_BRD *task_brd, const UINT32 udp_mcast_ipaddr, const UINT32 udp_mcast_port);

EC_BOOL task_brd_wait_config(TASK_BRD *task_brd, const CSTRING *bcast_dhcp_netcard_cstr, UINT32 *this_tcid);

EC_BOOL task_brd_make_config(TASK_BRD *task_brd, const UINT32 this_tcid);

EC_BOOL task_brd_pull_config(TASK_BRD *task_brd, UINT32 *this_tcid, UINT32 *this_ipaddr, UINT32 *this_port);

EC_BOOL task_brd_is_bcast_dhcp_server(TASK_BRD *task_brd);

EC_BOOL task_brd_is_auto_bcast_dhcp_udp_server(TASK_BRD *task_brd);

EC_BOOL task_brd_start_bcast_dhcp_udp_server(TASK_BRD *task_brd);
/*
EC_BOOL task_brd_stop_bcast_dhcp_udp_server(TASK_BRD *task_brd);

EC_BOOL task_brd_status_bcast_dhcp_udp_server(TASK_BRD *task_brd);
*/
EC_BOOL task_brd_is_mcast_udp_server(TASK_BRD *task_brd);

EC_BOOL task_brd_start_mcast_udp_server(TASK_BRD *task_brd);

EC_BOOL task_brd_stop_mcast_udp_server(TASK_BRD *task_brd);

EC_BOOL task_brd_status_mcast_udp_server(TASK_BRD *task_brd);

EC_BOOL task_brd_load(TASK_BRD *task_brd);

const char * task_brd_parse_arg(int argc, const char **argv, const char *tag);

EC_BOOL task_brd_parse_args(int argc, char **argv, UINT32 *size, UINT32 *tcid, UINT32 *reg_type,
                                    UINT32   *network_level,
                                    CSTRING **sys_cfg_xml_fname_cstr,
                                    CSTRING **basic_cfg_xml_fname_cstr,
                                    CSTRING **script_fname_cstr,
                                    CSTRING **bcast_dhcp_netcard_cstr,
                                    CSTRING **log_path_cstr,
                                    CSTRING **pid_path_cstr,
                                    CSTRING **console_path_cstr,
                                    CSTRING **ssl_path_cstr,
                                    EC_BOOL  *daemon_flag);

EC_BOOL task_brd_collect_netcards(TASK_BRD *task_brd);

EC_BOOL task_brd_parse_tcid_from_netcards(TASK_BRD *task_brd, const CSET *cnetcard_set, UINT32 *tcid);

EC_BOOL task_brd_shortcut_config(TASK_BRD *task_brd);

EC_BOOL task_brd_check_is_dbg_tcid(const UINT32 tcid);

EC_BOOL task_brd_check_is_monitor_tcid(const UINT32 tcid);

EC_BOOL task_brd_check_is_work_tcid(const UINT32 tcid);

EC_BOOL task_brd_default_check_csrv_enabled();
EC_BOOL task_brd_default_check_ssrv_enabled();

UINT32  task_brd_default_get_srv_ipaddr();
UINT32  task_brd_default_get_csrv_port();

UINT32  task_brd_default_get_ssrv_port();

UINT32  task_brd_default_get_network_level();

UINT32  task_brd_default_get_crfsmon_id();
UINT32 task_brd_default_get_cxfsmon_id();

EC_BOOL task_brd_default_get_store_http_srv(const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port);

EC_BOOL task_brd_default_check_validity();

EC_BOOL task_brd_default_stop_srvs();

EC_BOOL task_brd_default_stop_logs();

EC_BOOL task_brd_default_abort();

EC_BOOL task_brd_set_abort(TASK_BRD *task_brd);

void    task_brd_set_abort_default();

EC_BOOL task_brd_is_running(TASK_BRD *task_brd);

EC_BOOL task_brd_default_is_running();

EC_BOOL task_brd_end(TASK_BRD *task_brd);

EC_BOOL task_brd_default_end();

EC_BOOL task_brd_net_add_runner(const UINT32 tcid, const UINT32 mask_nbits, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg);

EC_BOOL task_brd_range_add_runner(const UINT32 tcid_fr, const UINT32 tcid_to, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg);

EC_BOOL task_brd_default_add_runner(const UINT32 tcid, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg);

EC_BOOL task_brd_default_fork_runner(const UINT32 tcid, const UINT32 rank, const char * name, TASK_RUNNER_FUNC runner, void *arg);

EC_BOOL task_brd_default_start_runner();

EC_BOOL task_brd_default_reg_md(
                                        const UINT32 md_type, const UINT32 md_capaciy,
                                        const UINT32 *func_num_ptr, const FUNC_ADDR_NODE *func_addr_node,
                                        const UINT32 md_start_func_id, const UINT32 md_end_func_id,
                                        const UINT32 md_set_mod_mgr_func_id, void * (*md_fget_mod_mgr)(const UINT32)
                                        );

EC_BOOL task_brd_default_reg_mm(const UINT32 mm_type, const char *mm_name, const UINT32 block_num, const UINT32 type_size);

EC_BOOL task_brd_default_reg_conv(
             const UINT32 var_dbg_type, const UINT32 var_sizeof, const UINT32 var_pointer_flag, const UINT32 var_mm_type,
             const UINT32 var_init_func, const UINT32 var_clean_func, const UINT32 var_free_func,
             const UINT32 var_encode_func, const UINT32 var_decode_func, const UINT32 var_encode_size
        );

EC_BOOL task_brd_sync_taskc_mgr(const TASK_BRD *task_brd, TASKC_MGR *taskc_mgr);

EC_BOOL task_brd_sync_mod_nodes(const TASK_BRD *task_brd, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, CVECTOR *mod_node_vec);

EC_BOOL task_brd_sync_cload_node(TASK_BRD *task_brd, CLOAD_NODE *cload_node);

EC_BOOL task_brd_sync_cload_mgr(const TASK_BRD *task_brd, const CVECTOR *tcid_vec, CLOAD_MGR *cload_mgr);

EC_BOOL task_brd_wait_proc_ready(const TASK_BRD *task_brd, const UINT32 recv_tcid, const UINT32 recv_comm, const UINT32 recv_rank);

EC_BOOL task_brd_enable_slow_down(TASK_BRD *task_brd);

EC_BOOL task_brd_disable_slow_down(TASK_BRD *task_brd);

EC_BOOL task_brd_default_enable_slow_down();

EC_BOOL task_brd_default_disable_slow_down();

EC_BOOL task_brd_need_slow_down(TASK_BRD *task_brd, LOG *log, UINT32 level);

EC_BOOL task_brd_default_need_slow_down();

uint32_t task_brd_default_ngx_need_slow_down();

EC_BOOL task_brd_clean(TASK_BRD *task_brd);

EC_BOOL task_brd_free(TASK_BRD *task_brd);

TASK_BRD * task_brd_default_new();

EC_BOOL task_brd_default_free();

EC_BOOL task_brd_init(TASK_BRD          *task_brd,
                        const int          argc,
                        char             **argv,
                        const UINT32       network_level,
                        CSTRING           *sys_cfg_xml_fname_cstr,
                        CSTRING           *basic_cfg_xml_fname_cstr,
                        CSTRING           *script_fname_cstr,
                        CSTRING           *log_path_cstr,
                        CSTRING           *ssl_path_cstr);

UINT32  task_brd_get_tcid_by_ipaddr(const TASK_BRD *task_brd, const UINT32 ipaddr);

EC_BOOL task_brd_collect_tcid(const TASK_BRD *task_brd, CVECTOR *tcid_vec);

EC_BOOL task_brd_collect_ipaddr(const TASK_BRD *task_brd, CVECTOR *ipaddr_vec);

EC_BOOL task_brd_check_tcid_connected(const TASK_BRD *task_brd, const UINT32 tcid);

EC_BOOL task_cbtimer_register(TASK_BRD *task_brd, const UINT32 timeout_nsec, const UINT32 func_id, ...);

EC_BOOL task_brd_task_mgr_add(TASK_BRD *task_brd, TASK_MGR *task_mgr);
EC_BOOL task_brd_aging_list_add(TASK_BRD *task_brd, TASK_MGR *task_mgr);

EC_BOOL task_brd_mod_mgr_add(TASK_BRD *task_brd, MOD_MGR *mod_mgr);
EC_BOOL task_brd_mod_mgr_rmv(TASK_BRD *task_brd, MOD_MGR *mod_mgr);
void    task_brd_mod_mgr_list_print(LOG *log, TASK_BRD *task_brd);
EC_BOOL task_brd_mod_mgr_list_excl(TASK_BRD *task_brd, const UINT32 tcid);

void    task_brd_context_list_print(LOG *log, const TASK_BRD *task_brd);
void    task_brd_report_list_print(LOG *log, const TASK_BRD *task_brd);

EC_BOOL task_brd_default_reserve_ipv4_addr(const HARDWARE *hw, uint32_t *ipv4_addr_ret);

EC_BOOL task_brd_default_release_ipv4_addr(const HARDWARE *hw, const uint32_t ipv4_addr);

EC_BOOL task_brd_recving_queue_handle(TASK_BRD *task_brd);
EC_BOOL task_brd_sending_queue_handle(TASK_BRD *task_brd);

/*note: only task_req will come into the queue TASK_IS_RECV_QUEUE*/
EC_BOOL task_brd_is_recv_queue_handle(TASK_BRD *task_brd);

EC_BOOL task_brd_task_mgr_match(const TASK_BRD *task_brd, const TASK_RSP *task_rsp, TASK_MGR **task_mgr_ret);

EC_BOOL task_brd_discard_rsp(TASK_BRD *task_brd, TASK_RSP *task_rsp);

EC_BOOL task_brd_commit_req(TASK_BRD *task_brd, TASK_REQ *task_req);
EC_BOOL task_brd_commit_rsp(TASK_BRD *task_brd, TASK_RSP *task_rsp);
EC_BOOL task_brd_commit_fwd(TASK_BRD *task_brd, TASK_FWD *task_fwd);

EC_BOOL task_fwd_direct_no_queue(TASK_BRD *task_brd, TASK_FWD *task_fwd);

UINT32 task_brd_recving_node_handle_not_load_thread(TASK_BRD *task_brd, TASK_NODE *task_node);

TASK_BRD_PROCESS_HANDLER *task_brd_process_find(TASK_BRD *task_brd, TASK_BRD_CALLBACK func, void *arg);
EC_BOOL task_brd_process_add(TASK_BRD *task_brd, TASK_BRD_CALLBACK func, void *arg);
EC_BOOL task_brd_process_del(TASK_BRD *task_brd, TASK_BRD_CALLBACK func, void *arg);
EC_BOOL task_brd_process_init(TASK_BRD *task_brd);
EC_BOOL task_brd_process_clean(TASK_BRD *task_brd);
EC_BOOL task_brd_process_do(TASK_BRD *task_brd);

EC_BOOL task_brd_rank_load_set(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const CLOAD_STAT *cload_stat);
EC_BOOL task_brd_rank_load_set_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank, const UINT32 que_load);
EC_BOOL task_brd_rank_load_inc_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);
EC_BOOL task_brd_rank_load_dec_que(TASK_BRD *task_brd, const UINT32 tcid, const UINT32 rank);
UINT32  task_brd_rank_load_print(LOG *log, const TASK_BRD *task_brd);

void task_brd_send_task_mgr_list(TASK_BRD *task_brd);
void task_brd_recv_task_mgr_list(TASK_BRD *task_brd);
void task_brd_aging_task_mgr_list(TASK_BRD *task_brd);

EC_BOOL task_brd_broken_tcid_tbl_init(TASK_BRD *task_brd);
//EC_BOOL task_brd_broken_tcid_exist(const TASK_BRD *task_brd, const UINT32 broken_tcid);

/*--------------------------------------------- task mgr interface ---------------------------------------------*/
EC_BOOL task_mgr_init(const UINT32 seqno, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_MGR *mod_mgr, TASK_MGR *task_mgr);
UINT32  task_mgr_sub_seqno_gen(TASK_MGR *task_mgr, UINT32 *sub_seqno_new);
EC_BOOL task_mgr_clean(TASK_MGR *task_mgr);

EC_BOOL task_mgr_free(TASK_MGR *task_mgr);
EC_BOOL task_mgr_req_match(const TASK_MGR *task_mgr, const TASK_RSP *task_rsp, TASK_REQ **task_req);
EC_BOOL task_mgr_match_seqno(const TASK_MGR *task_mgr, const UINT32 seqno);
TASK_REQ * task_mgr_search_task_req_by_recver(const TASK_MGR *task_mgr, const UINT32 seqno, const UINT32 subseqno, const MOD_NODE *recv_mod_node);

EC_BOOL task_mgr_encode(TASK_BRD *task_brd, TASK_MGR *task_mgr);
EC_BOOL task_mgr_send(TASK_BRD *task_brd, TASK_MGR *task_mgr);
EC_BOOL task_mgr_recv(TASK_MGR *task_mgr);
EC_BOOL task_mgr_reschedule_to(TASK_BRD *task_brd, TASK_MGR *task_mgr, const UINT32 tcid);
EC_BOOL task_mgr_discard_to(TASK_BRD *task_brd, TASK_MGR *task_mgr, const UINT32 tcid);
EC_BOOL task_mgr_print(LOG *log, TASK_MGR *task_mgr);

UINT32  task_mgr_time_elapsed(const TASK_MGR *task_mgr);
UINT32  task_mgr_time_left(const TASK_MGR *task_mgr);
EC_BOOL task_mgr_is_timeout(const TASK_MGR *task_mgr);

/*--------------------------------------------- task context interface ---------------------------------------------*/
TASK_CONTEXT * task_context_new();
EC_BOOL task_context_init(TASK_CONTEXT *task_context);
EC_BOOL task_context_clean(TASK_CONTEXT *task_context);
EC_BOOL task_context_free(TASK_CONTEXT *task_context);

EC_BOOL task_context_handle(TASK_BRD *task_brd, const TASK_RSP *task_rsp_ret);
EC_BOOL task_context_discard_from(TASK_BRD *task_brd, const UINT32 broken_tcid);

void    task_context_print(LOG *log, const TASK_CONTEXT *task_context);

/*--------------------------------------------- task report_node interface ---------------------------------------------*/
EC_BOOL task_report_node_new(TASK_REPORT_NODE **task_report_node);
EC_BOOL task_report_node_init(TASK_REPORT_NODE *task_report_node);
EC_BOOL task_report_node_clean(TASK_REPORT_NODE *task_report_node);
EC_BOOL task_report_node_free(TASK_REPORT_NODE *task_report_node);

EC_BOOL task_report_node_gen(TASK_REPORT_NODE *task_report_node, const TASK_BRD *task_brd, const TASK_MGR *task_mgr);

void    task_report_node_print(LOG *log, const TASK_REPORT_NODE *task_report_node);

EC_BOOL task_report_node_clone(const TASK_REPORT_NODE *task_report_node_src, TASK_REPORT_NODE *task_report_node_des);

EC_BOOL task_brd_report_list_init(TASK_BRD *task_brd);
void    task_brd_report_list_add(TASK_BRD *task_brd, const TASK_MGR *task_mgr);
void    task_brd_report_list_dump(TASK_BRD *task_brd, const UINT32 num, CVECTOR *task_report_vec_des);

/*--------------------------------------------- task queue interface ---------------------------------------------*/
EC_BOOL task_queue_init(CLIST *task_queue);

/* destory task req manager */
EC_BOOL task_queue_clean(CLIST *task_queue);

EC_BOOL task_queue_add_node(CLIST *task_queue, const TASK_NODE *task_node);

EC_BOOL task_queue_rmv_node(CLIST *task_queue, const TASK_NODE *task_node);

void    task_queue_print(LOG *log, const CLIST *task_queue);

void    task_queue_link_print(LOG *log, CLIST *task_queue);

/*discard those being recved from the taskComm tcid*/
EC_BOOL task_queue_discard_from(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid);

/*discard those will send to the taskComm tcid*/
EC_BOOL task_queue_discard_to(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid);

/*process those being recved from the taskComm tcid*/
EC_BOOL task_queue_process_from(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid);

/*process those being sending to the taskComm tcid*/
EC_BOOL task_queue_process_to(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid);

/*reschedule those being recved from the taskComm tcid*/
EC_BOOL task_queue_reschedule_from(TASK_BRD *task_brd, CLIST *task_queue, const UINT32 tag, const UINT32 tcid);

/*reschedule or discard those task req sending to the taskComm tcid according to each task mgr setting*/
EC_BOOL task_mgr_list_handle_broken_taskcomm(TASK_BRD *task_brd, const UINT32 tcid);

/* load info updating interface*/
EC_BOOL load_set_when_task_req_isend(TASK_BRD *task_brd, TASK_REQ *task_req);
EC_BOOL load_set_when_task_req_is_sent(TASK_BRD *task_brd, TASK_REQ *task_req);
EC_BOOL load_set_when_task_req_commit(TASK_BRD *task_brd, TASK_REQ *task_req);
EC_BOOL load_set_when_task_rsp_isend(TASK_BRD *task_brd, TASK_RSP *task_rsp);
EC_BOOL load_set_when_task_rsp_commit(TASK_BRD *task_brd, TASK_RSP *task_rsp);
EC_BOOL load_set_when_task_rsp_is_ignore(TASK_BRD *task_brd, TASK_REQ *task_req);
EC_BOOL load_set_when_task_fwd_commit(TASK_BRD *task_brd, TASK_FWD *task_fwd);

UINT32 task_brd_que_load(const TASK_BRD *task_brd);
UINT32 task_brd_obj_load(const TASK_BRD *task_brd);
UINT32 task_brd_cpu_load(const TASK_BRD *task_brd);
UINT32 task_brd_mem_load(const TASK_BRD *task_brd);
UINT32 task_brd_dsk_load(const TASK_BRD *task_brd);
UINT32 task_brd_net_load(const TASK_BRD *task_brd);

EC_BOOL task_brd_heartbeat_once(TASK_BRD *task_brd);
EC_BOOL task_brd_heartbeat(TASK_BRD *task_brd);
EC_BOOL task_brd_cload_stat_collect(TASK_BRD *task_brd);
EC_BOOL task_brd_cload_stat_update_once(TASK_BRD *task_brd);
EC_BOOL task_brd_cload_stat_update(TASK_BRD *task_brd);
EC_BOOL task_brd_cpu_avg_stat_update_once(TASK_BRD *task_brd);


EC_BOOL task_brd_cbtimer_register(TASK_BRD *task_brd, const UINT32 expire_nsec, const UINT32 timeout_nsec, const UINT32 timeout_func_id, ...);
EC_BOOL task_brd_cbtimer_add(TASK_BRD *task_brd, const UINT8 *name,
                                     const UINT32 expire_nsec, FUNC_ADDR_NODE *task_brd_expire_func_addr_node,
                                     const UINT32 timeout_nsec, FUNC_ADDR_NODE *task_brd_timeout_func_addr_node);

EC_BOOL task_brd_cbtimer_do(TASK_BRD *task_brd);

EC_BOOL do_once(TASK_BRD *task_brd);
EC_BOOL do_slave(TASK_BRD *task_brd);
EC_BOOL do_slave_enhanced(TASK_BRD *task_brd);

/*http server*/
EC_BOOL task_brd_start_http_srv(TASK_BRD *task_brd, const UINT32 http_srv_ipaddr, const UINT32 http_srv_port);
EC_BOOL task_brd_default_start_http_srv(const UINT32 http_srv_ipaddr, const UINT32 http_srv_port);
EC_BOOL task_brd_stop_http_srv(TASK_BRD *task_brd);
EC_BOOL task_brd_default_stop_http_srv();
EC_BOOL task_brd_bind_http_srv_modi(TASK_BRD *task_brd, const UINT32 modi);
EC_BOOL task_brd_default_bind_http_srv_modi(const UINT32 modi);

/*https server*/
EC_BOOL task_brd_start_https_srv(TASK_BRD *task_brd, const UINT32 https_srv_ipaddr, const UINT32 https_srv_port);
EC_BOOL task_brd_default_start_https_srv(const UINT32 https_srv_ipaddr, const UINT32 https_srv_port);
EC_BOOL task_brd_stop_https_srv(TASK_BRD *task_brd);
EC_BOOL task_brd_default_stop_https_srv();
EC_BOOL task_brd_bind_https_srv_modi(TASK_BRD *task_brd, const UINT32 modi);
EC_BOOL task_brd_default_bind_https_srv_modi(const UINT32 modi);

EC_BOOL task_brd_default_start_csrv();

/*--------------------------------------------- external interface ---------------------------------------------*/
EC_BOOL do_slave_default();
EC_BOOL do_slave_thread_default();
EC_BOOL do_slave_wait_default(TASK_BRD *task_brd);
EC_BOOL do_cmd_default();
EC_BOOL do_mon_default();

/*broadcast to all remote mod nodes in mod mgr, ignore load balancing strategy*/
UINT32 task_bcast(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 func_id, ...);

/*start remote modules by module start entry as task req*/
/*broadcast to all remote mod nodes in mod mgr, deploy load balancing strategy*/
UINT32 task_act(const MOD_MGR *src_mod_mgr, MOD_MGR **des_mod_mgr, const UINT32 time_to_live, const UINT32 mod_num, const UINT32 load_balancing_choice, const UINT32 task_prio, const UINT32 func_id, ...);

/*stop remote modules by module end entry as task req*/
/*broadcast to all remote mod nodes in mod mgr, ignore load balancing strategy*/
UINT32 task_dea(MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 func_id, ...);

/*wait until all or respective num of task reqs of task mgr are handled and responed(if need rsp)*/
/*then return the calling point to execute*/
EC_BOOL task_wait(TASK_MGR *task_mgr, const UINT32 time_to_live, const UINT32 task_reschedule_flag, CHECKER ret_val_checker);

/*send all task reqs of task mgr without wait, and return the calling point to execute continously. no jump here*/
/*task_mgr will free automatically after collect all responses(if need rsp) or after all requests sending complete(if not need rsp)*/
EC_BOOL task_no_wait(TASK_MGR *task_mgr, const UINT32 time_to_live, const UINT32 task_reschedule_flag, CHECKER ret_val_checker);

/*new a task mgr template without task req*/
TASK_MGR * task_new(const MOD_MGR *mod_mgr, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num);

/*add task req to task mgr, the task req will send to specific recv mod_node without load balancing*/
UINT32 task_super_inc(TASK_MGR *task_mgr, const MOD_NODE  *send_mod_node, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single recv mod_node*/
UINT32 task_super_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single recv mod_node without waiting*/
UINT32 task_super_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...);

UINT32 task_p2p_inc(TASK_MGR *task_mgr, const UINT32 modi, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...);

UINT32 task_p2p(const UINT32 modi, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...);

UINT32 task_p2p_no_wait(const UINT32 modi, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const MOD_NODE *recv_mod_node, const void * func_retval_addr, const UINT32 func_id, ...);

/*add task req to task mgr, the task req will send to best mod node of mod mgr of task mgr based on load balancing strategy of mod mgr*/
UINT32 task_inc(TASK_MGR *task_mgr,const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single best mod_node of mod_mgr based on load balancing strategy of mod_mgr*/
UINT32 task_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 task_reschedule_flag, const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single best mod_node of mod_mgr based on load balancing strategy of mod_mgr without waiting*/
UINT32 task_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const void * func_retval_addr, const UINT32 func_id, ...);

/*add task req to task mgr, the task req will send to single mod_node of mod_mgr and ignore load balancing strategy of mod_mgr*/
UINT32 task_pos_inc(TASK_MGR *task_mgr, const UINT32 recv_mod_node_pos, const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single mod_node of mod_mgr and ignore load balancing strategy of mod_mgr*/
UINT32 task_pos_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32  recv_mod_node_pos, const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single mod_node of mod_mgr and ignore load balancing strategy of mod_mgr without waiting*/
UINT32 task_pos_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32  recv_mod_node_pos, const void * func_retval_addr, const UINT32 func_id, ...);

/*add task req to task mgr, the task req will send to single taskcomm of mod_mgr and load balancing of mod_nodes of the taskcomm*/
UINT32 task_tcid_inc(TASK_MGR *task_mgr, const UINT32 recv_tcid, const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single taskcomm and load balancing of mod_nodes of the taskcomm*/
UINT32 task_tcid_mono(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 recv_tcid, const void * func_retval_addr, const UINT32 func_id, ...);

/*send task req to single taskcomm and load balancing of mod_nodes of the taskcomm without waiting*/
UINT32 task_tcid_mono_no_wait(const MOD_MGR *mod_mgr, const UINT32 time_to_live, const UINT32 task_prio, const UINT32 task_need_rsp_flag, const UINT32 task_need_rsp_num, const UINT32 recv_tcid, const void * func_retval_addr, const UINT32 func_id, ...);

#endif /*_TASK_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
