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

#ifndef _SUPER_H
#define _SUPER_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "clist.h"
#include "cvector.h"
#include "tcnode.h"
#include "cload.h"
#include "cmutex.h"
#include "cmutex.h"
#include "crb.h"
#include "chttp.inc"
#include "chttps.inc"

/*bitmap of open flags*/
#define SUPER_O_RDONLY               ((UINT32)1)
#define SUPER_O_WRONLY               ((UINT32)2)
#define SUPER_O_RDWR                 ((UINT32)4)
#define SUPER_O_CREAT                ((UINT32)8)

#define SUPER_WRITE_ONCE_MAX_BYTES   ((UINT32) 8 * 1024 * 1024)/*8MB*/
#define SUPER_READ_ONCE_MAX_BYTES    ((UINT32) 8 * 1024 * 1024)/*8MB*/

#define SUPER_CMD_BUFF_MAX_SIZE      ((UINT32)256)/*bytes*/

/* SUPER MODULE Defintion: */
typedef struct
{
    UINT32      usedcounter;/* used counter >= 0 */

    CLIST       fnode_list;

    UINT32      obj_zone_size;
    CVECTOR    *obj_zone;/*test for ict*/

    CRB_TREE    cond_locks; /*super condition locks, item is SUPER_CCOND*/
}SUPER_MD;

#define SUPER_MD_FNODE_LIST(super_md)        (&((super_md)->fnode_list))
#define SUPER_MD_OBJ_ZONE(super_md)          ((super_md)->obj_zone)
#define SUPER_MD_OBJ_ZONE_SIZE(super_md)     ((super_md)->obj_zone_size)
#define SUPER_MD_COND_LOCKS(super_md)        (&((super_md)->cond_locks))

typedef struct
{
    CSTRING  fname;
    int      fd;
    int      rsvd;
    REAL     progress;
    CMUTEX   cmutex;
}SUPER_FNODE;

#define SUPER_FNODE_FNAME(super_fnode)      (&((super_fnode)->fname))
#define SUPER_FNODE_FD(super_fnode)         ((super_fnode)->fd)
#define SUPER_FNODE_PROGRESS(super_fnode)   ((super_fnode)->progress)

#define SUPER_FNODE_CMUTEX(super_fnode)     (&((super_fnode)->cmutex))
#define SUPER_FNODE_CMUTEX_INIT(super_fnode, location)    (cmutex_init(SUPER_FNODE_CMUTEX(super_fnode), CMUTEX_PROCESS_PRIVATE, location))
#define SUPER_FNODE_CMUTEX_CLEAN(super_fnode, location)   (cmutex_clean(SUPER_FNODE_CMUTEX(super_fnode), location))
#define SUPER_FNODE_CMUTEX_LOCK(super_fnode, location)    (cmutex_lock(SUPER_FNODE_CMUTEX(super_fnode), location))
#define SUPER_FNODE_CMUTEX_UNLOCK(super_fnode, location)  (cmutex_unlock(SUPER_FNODE_CMUTEX(super_fnode), location))

typedef struct
{
    UINT32          tag;  /*distinguish different usage lock*/
    CSTRING         key;  /*distinguish different lock*/
    CROUTINE_COND   cond; /*condition lock of croutine*/
}SUPER_CCOND;

#define SUPER_CCOND_TAG(super_ccond)        ((super_ccond)->tag)
#define SUPER_CCOND_KEY(super_ccond)        (&((super_ccond)->key))
#define SUPER_CCOND_COND(super_ccond)       (&((super_ccond)->cond))

#define SUPER_CCOND_KEY_STR(super_ccond)    (CSTRING_STR(SUPER_CCOND_KEY(super_ccond)))
#define SUPER_CCOND_KEY_LEN(super_ccond)    (CSTRING_LEN(SUPER_CCOND_KEY(super_ccond)))

#define SUPER_CCOND_TAG_ERR             ((UINT32)~0)

/**
*   for test only
*
*   to query the status of SUPER Module
*
**/
void super_print_module_status(const UINT32 super_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed SUPER module
*
*
**/
UINT32 super_free_module_static_mem(const UINT32 super_md_id);

/**
*
* start super module
*
**/
UINT32 super_start();

/**
*
* end super module
*
**/
void super_end(const UINT32 super_md_id);

SUPER_CCOND *super_ccond_new(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key, const UINT32 timeout_msec);

EC_BOOL super_ccond_init(const UINT32 super_md_id, SUPER_CCOND *super_ccond, const UINT32 tag, const CSTRING *key, const UINT32 timeout_msec);

EC_BOOL super_ccond_clean(const UINT32 super_md_id, SUPER_CCOND *super_ccond);

EC_BOOL super_ccond_free(const UINT32 super_md_id, SUPER_CCOND *super_ccond);

EC_BOOL super_ccond_free_0(SUPER_CCOND *super_ccond);

void    super_ccond_print(LOG *log, const SUPER_CCOND *super_ccond);

int     super_ccond_cmp(const SUPER_CCOND *super_ccond_1, const SUPER_CCOND *super_ccond_2);

SUPER_FNODE *super_fnode_new(const UINT32 super_md_id);

EC_BOOL super_fnode_init(const UINT32 super_md_id, SUPER_FNODE *super_fnode);

EC_BOOL super_fnode_clean(const UINT32 super_md_id, SUPER_FNODE *super_fnode);

EC_BOOL super_fnode_free(const UINT32 super_md_id, SUPER_FNODE *super_fnode);

SUPER_FNODE *super_search_fnode_by_fname_no_lock(const UINT32 super_md_id, const CSTRING *fname);

SUPER_FNODE *super_search_fnode_by_fname(const UINT32 super_md_id, const CSTRING *fname);

SUPER_FNODE *super_open_fnode_by_fname(const UINT32 super_md_id, const CSTRING *fname, const UINT32 open_flags);

EC_BOOL super_close_fnode_by_fname(const UINT32 super_md_id, const CSTRING *fname);


/**
*
* set taskc node info to SUPER module
*
**/
UINT32 super_set_taskc_node(const UINT32 super_md_id, const UINT32 ipaddr, const UINT32 port, const UINT32 taskc_id, const UINT32 taskc_comm, const UINT32 taskc_size);

/**
*
* get taskc node info to SUPER module
*
**/
UINT32 super_get_taskc_node(const UINT32 super_md_id, const UINT32 ipaddr, const UINT32 port, UINT32 *taskc_id, UINT32 *taskc_comm, UINT32 *taskc_size);

/**
*
* include taskc node info to SUPER module
*
**/
UINT32 super_incl_taskc_node(const UINT32 super_md_id, const UINT32 ipaddr, const UINT32 port, const int sockfd, const UINT32 taskc_id, const UINT32 taskc_comm, const UINT32 taskc_size);


/**
*
* exclude taskc node info to SUPER module
*
**/
UINT32 super_excl_taskc_node(const UINT32 super_md_id, const UINT32 tcid, const UINT32 comm);

/**
*
* sync taskc node mgr info by SUPER module
*
**/
UINT32 super_sync_taskc_mgr(const UINT32 super_md_id, TASKC_MGR *taskc_mgr);

UINT32 super_sync_cload_mgr(const UINT32 super_md_id, const CVECTOR *tcid_vec, CLOAD_MGR *des_cload_mgr);

/**
*
* check taskc node connectivity by SUPER module
*
**/
EC_BOOL super_check_tcid_connected(const UINT32 super_md_id, const UINT32 tcid);

/**
*
* check taskc node connectivity by SUPER module
*
**/
EC_BOOL super_check_ipaddr_connected(const UINT32 super_md_id, const UINT32 ipaddr);

/**
*
* activate sysconfig
* import from config.xml
* note: only add new info but never delete or override the old ones
*
**/
void super_activate_sys_cfg(const UINT32 super_md_id);

/**
*
* show current sysconfig
*
**/
void super_show_sys_cfg(const UINT32 super_md_id, LOG *log);

/**
*
* print mem statistics info of current process
*
**/
void super_show_mem(const UINT32 super_md_id, LOG *log);

/**
*
* print mem statistics info of current process
*
**/
void super_show_mem_of_type(const UINT32 super_md_id, const UINT32 type, LOG *log);

/**
*
* diagnostic mem of current process
*
**/
void super_diag_mem(const UINT32 super_md_id, LOG *log);

/**
*
* diagnostic mem of CSOCKET_CNODE of current process
*
**/
void super_diag_csocket_cnode(const UINT32 super_md_id, LOG *log);

/**
*
* diagnostic mem of current process
*
**/
void super_diag_mem_of_type(const UINT32 super_md_id, const UINT32 type, LOG *log);

/**
*
* clean mem of current process
*
**/
void super_clean_mem(const UINT32 super_md_id);

/**
*
* breathe mem of current process
*
**/
void super_breathing_mem(const UINT32 super_md_id);

/**
*
* show log level info
*
**/
void super_show_log_level_tab(const UINT32 super_md_id, LOG *log);

/**
*
* set log level
*
**/
EC_BOOL super_set_log_level_tab(const UINT32 super_md_id, const UINT32 level);

/**
*
* set log level of sector
*
**/
EC_BOOL super_set_log_level_sector(const UINT32 super_md_id, const UINT32 sector, const UINT32 level);

/**
*
* shutdown current taskComm
*
**/
void super_shutdown_taskcomm(const UINT32 super_md_id);

/**
*
* cancel a task req
*
**/
EC_BOOL super_cancel_task_req(const UINT32 super_md_id, const UINT32 seqno, const UINT32 subseqno, const MOD_NODE *recv_mod_node);

/**
*
* sync load info of current rank
*
**/
void super_sync_cload_stat(const UINT32 super_md_id, CLOAD_STAT *cload_stat);


/**
*
* sync load info of current comm
*
**/
void super_sync_cload_node(const UINT32 super_md_id, CLOAD_NODE *cload_node);

/**
*
* sync from remote taskcomms and the load info
*
*
*
**/
void super_sync_taskcomm(const UINT32 super_md_id, const UINT32 src_tcid, const UINT32 src_maski, const UINT32 src_maske, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, CVECTOR *mod_node_vec);

/**
*
* sync locally from remote taskcomms and the load info
*
*
*
**/
void super_sync_taskcomm_from_local(const UINT32 super_md_id, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, CVECTOR *mod_node_vec);
/**
*
* ping remote taskcomm with timeout
*
* if ping ack in timeout, remote taskcomm is reachable, otherwise, it is unreachable
*
**/
EC_BOOL super_ping_taskcomm(const UINT32 super_md_id);

EC_BOOL super_ping_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr);

/**
*
* show queues in current taskComm
*
**/
void super_show_queues(const UINT32 super_md_id, LOG *log);

/**
*
* list slow down checking conditions
*
**/
void super_check_slowdown(const UINT32 super_md_id, LOG *log);

/**
*
* handle broken taskcomm when current taskcomm receive notification
*
**/
void super_handle_broken_tcid_comm(const UINT32 super_md_id, const UINT32 broken_tcid, const UINT32 broken_comm);

/**
*
* when fwd rank found some broken taskcomm, then notify all ranks in current taskcomm
*
* note: here does not notify other taskcomm(s)
*
**/
void super_notify_broken_tcid_comm(const UINT32 super_md_id, const UINT32 broken_tcid, const UINT32 broken_comm);

/**
*
* when fwd rank found some broken route, then notify the src taskcomm
*
**/
void super_notify_broken_route(const UINT32 super_md_id, const UINT32 src_tcid, const UINT32 broken_tcid);

/**
*
* when fwd rank found some broken route, then register all cluster
*
**/
void super_register_cluster(const UINT32 super_md_id, const UINT32 src_tcid, const UINT32 broken_tcid);

/**
*
* show work clients of tasks_cfg of taskc_cfg of task_brd
*
**/
void super_show_work_client(const UINT32 super_md_id, LOG *log);

/**
*
* show num info of threads of tasks_cfg of taskc_cfg of task_brd
*
**/
void super_show_thread_num(const UINT32 super_md_id, LOG *log);

/**
*
* show route table of tasks_cfg of taskc_cfg of task_brd
*
**/
void super_show_route_table(const UINT32 super_md_id, LOG *log);

/**
*
* show rank node status of the rank
*
**/
void super_show_rank_node(const UINT32 super_md_id, LOG *log);

/**
*
* switch/enable rank node light to green
*
**/
void super_switch_rank_node_green(const UINT32 super_md_id, const UINT32 rank);

/**
*
* switch/disable rank node light to red
*
**/
void super_switch_rank_node_red(const UINT32 super_md_id, const UINT32 rank);

/**
*
* output log by SUPER module
*
**/
void super_show_cstring(const UINT32 super_md_id, const UINT32 tcid, const UINT32 rank, const CSTRING *cstring);

/**
*
* switch log off
*
**/
void super_switch_log_off(const UINT32 super_md_id);

/**
*
* switch log on
*
**/
void super_switch_log_on(const UINT32 super_md_id);

/**
*
* rotate log
*
**/
EC_BOOL super_rotate_log(const UINT32 super_md_id, const UINT32 log_index);

/**
*
* send http request and recv http response
*
**/
EC_BOOL super_http_request(const UINT32 super_md_id, const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/**
*
* send http request and recv http response in merge procedure
*
**/
EC_BOOL super_http_request_merge(const UINT32 super_md_id, const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat);

/**
*
* wait until current process of current taskComm is ready
*
**/
void super_wait_me_ready(const UINT32 super_md_id);

/**
*
* add route
*
**/
void super_add_route(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 maskr, const UINT32 next_tcid);

/**
*
* del route
*
**/
void super_del_route(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 maskr, const UINT32 next_tcid);

/**
*
* try to connect
*
**/
EC_BOOL super_connect(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 des_comm, const UINT32 conn_num);

/**
*
* add socket connection
*
**/
void super_add_connection(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 des_comm, const UINT32 des_srv_ipaddr, const UINT32 des_srv_port, const UINT32 conn_num);


/**
*
* execute shell command and return output as CSTRING
*
**/
void super_run_shell(const UINT32 super_md_id, const CSTRING *cmd_line, LOG *log);

/**
*
* execute shell command and return output as CSTRING
*
**/
EC_BOOL super_exec_shell(const UINT32 super_md_id, const CSTRING *cmd_line, CBYTES *cbytes);

EC_BOOL super_exec_shell_tcid_cstr(const UINT32 super_md_id, const CSTRING *tcid_cstr, const CSTRING *cmd_line, CBYTES *output_cbytes);

EC_BOOL super_exec_shell_vec(const UINT32 super_md_id, const CVECTOR *tcid_vec, const CVECTOR *cmd_line_vec, CVECTOR *output_cbytes_vec);

EC_BOOL super_exec_shell_vec_tcid_cstr(const UINT32 super_md_id, const CVECTOR *tcid_cstr_vec, const CSTRING *cmd_line, CVECTOR *output_cbytes_vec);

EC_BOOL super_exec_shell_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *cmd_line, CBYTES *output_cbytes);

EC_BOOL super_exec_shell_vec_ipaddr_cstr(const UINT32 super_md_id, const CVECTOR *ipaddr_cstr_vec, const CSTRING *cmd_line, CVECTOR *output_cbytes_vec);

/**
*
* show rank load which is used for LOAD_BALANCING_RANK
*
**/
void super_show_rank_load(const UINT32 super_md_id, LOG *log);

/**
*
* sync rank load which is used for LOAD_BALANCING_RANK
*
**/
void super_sync_rank_load(const UINT32 super_md_id, const UINT32 tcid, const UINT32 rank);

/**
*
* forcely set rank load which is used for LOAD_BALANCING_RANK
*
**/
void super_set_rank_load(const UINT32 super_md_id, const UINT32 tcid, const UINT32 rank, const CLOAD_STAT *cload_stat);

/**
*
* enable task brd by setting its load to real load
*
**/
void super_enable_task_brd(const UINT32 super_md_id);

/**
*
* disable task brd by setting its load to -1
*
**/
void super_disable_task_brd(const UINT32 super_md_id);

/**
*
* heartbeat
*
**/
void super_heartbeat_on_node(const UINT32 super_md_id, const CLOAD_NODE *cload_node);

void super_heartbeat_on_rank(const UINT32 super_md_id, const UINT32 tcid, const UINT32 comm, const UINT32 rank, const CLOAD_STAT *cload_stat);

void super_heartbeat_all(const UINT32 super_md_id, const CLOAD_MGR *cload_mgr);

void super_heartbeat_none(const UINT32 super_md_id);

void super_show_version(const UINT32 super_md_id, LOG *log);

void super_show_vendor(const UINT32 super_md_id, LOG *log);

/**
*
* OS info
*
**/
UINT32 super_get_wordsize(const UINT32 super_md_id);/*wordsize in bits*/

void super_show_wordsize(const UINT32 super_md_id, LOG *log);

/**
*
* download from local disk to remote
*
**/
EC_BOOL super_download(const UINT32 super_md_id, const CSTRING *fname, CBYTES *cbytes);

EC_BOOL super_download_tcid_cstr(const UINT32 super_md_id, const CSTRING *tcid_cstr, const CSTRING *fname, CBYTES *output_cbytes);

EC_BOOL super_download_vec_tcid_cstr(const UINT32 super_md_id, const CVECTOR *tcid_cstr_vec, const CSTRING *fname, CVECTOR *output_cbytes_vec);

EC_BOOL super_download_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *fname, CBYTES *output_cbytes);

EC_BOOL super_download_vec_ipaddr_cstr(const UINT32 super_md_id, const CVECTOR *ipaddr_cstr_vec, const CSTRING *fname, CVECTOR *output_cbytes_vec);

/**
*
* upload from remote to local disk
*
**/
EC_BOOL super_upload(const UINT32 super_md_id, const CSTRING *fname, const CBYTES *cbytes, const UINT32 backup_flag);

EC_BOOL super_upload_tcid_cstr(const UINT32 super_md_id, const CSTRING *tcid_cstr, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag);

EC_BOOL super_upload_vec_tcid_cstr(const UINT32 super_md_id, const CVECTOR *tcid_cstr_vec, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag, CVECTOR *ret_vec);

EC_BOOL super_upload_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag);

EC_BOOL super_upload_vec_ipaddr_cstr(const UINT32 super_md_id, const CVECTOR *ipaddr_cstr_vec, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag, CVECTOR *ret_vec);

EC_BOOL super_collect_vec_ipaddr_cstr(const UINT32 super_md_id, CVECTOR *ipaddr_cstr_vec);

EC_BOOL super_write_fdata(const UINT32 super_md_id, const CSTRING *fname, const UINT32 offset, const CBYTES *cbytes);

EC_BOOL super_read_fdata(const UINT32 super_md_id, const CSTRING *fname, const UINT32 offset, const UINT32 max_len, CBYTES *cbytes);

EC_BOOL super_set_progress(const UINT32 super_md_id, const CSTRING *fname, const REAL *progress);

EC_BOOL super_get_progress(const UINT32 super_md_id, const CSTRING *fname, REAL *progress);

EC_BOOL super_size_file(const UINT32 super_md_id, const CSTRING *fname, UINT32 *fsize);

EC_BOOL super_open_file(const UINT32 super_md_id, const CSTRING *fname, const UINT32 open_flags);

EC_BOOL super_close_file(const UINT32 super_md_id, const CSTRING *fname);

EC_BOOL super_rmv_file(const UINT32 super_md_id, const CSTRING *fname);

EC_BOOL super_transfer_start(const UINT32 super_md_id, const CSTRING *src_fname, const UINT32 des_tcid, const CSTRING *des_fname);

EC_BOOL super_transfer_stop(const UINT32 super_md_id, const CSTRING *src_fname, const UINT32 des_tcid, const CSTRING *des_fname);

EC_BOOL super_transfer(const UINT32 super_md_id, const CSTRING *src_fname, const UINT32 des_tcid, const CSTRING *des_fname);

EC_BOOL super_transfer_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *src_fname, const CSTRING *ipaddr_cstr, const CSTRING *des_fname);

EC_BOOL super_transfer_vec_start(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *des_tcid_vec, const CSTRING *des_fname);

EC_BOOL super_transfer_vec_stop(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *des_tcid_vec, const CSTRING *des_fname);

EC_BOOL super_transfer_vec(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *des_tcid_vec, const CSTRING *des_fname, CVECTOR *ret_vec);

EC_BOOL super_transfer_vec_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *ipaddr_cstr_vec, const CSTRING *des_fname, CVECTOR *ret_vec);

EC_BOOL super_backup(const UINT32 super_md_id, const CSTRING *fname);

EC_BOOL super_start_mcast_udp_server(const UINT32 super_md_id);

EC_BOOL super_stop_mcast_udp_server(const UINT32 super_md_id);

EC_BOOL super_status_mcast_udp_server(const UINT32 super_md_id);

EC_BOOL super_set_hostname(const UINT32 super_md_id, const CSTRING *hostname_cstr);

EC_BOOL super_get_hostname(const UINT32 super_md_id, CSTRING *hostname_cstr);

EC_BOOL super_set_hostname_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *hostname_cstr);

EC_BOOL super_get_hostname_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, CSTRING *hostname_cstr);

EC_BOOL super_exec_shell_cbtimer_reset(const UINT32 super_md_id, const CSTRING *cbtimer_name, const CSTRING *cmd_line, const UINT32 timeout);

EC_BOOL super_exec_shell_cbtimer_set(const UINT32 super_md_id, const CSTRING *cbtimer_name, const CSTRING *cmd_line, const UINT32 timeout);

EC_BOOL super_exec_shell_cbtimer_unset(const UINT32 super_md_id, const CSTRING *cbtimer_name);

EC_BOOL super_exec_shell_ipaddr_cstr_cbtimer_set(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *cbtimer_name, const CSTRING *cmd_line, const UINT32 timeout);

EC_BOOL super_exec_shell_ipaddr_cstr_cbtimer_unset(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *cbtimer_name);

EC_BOOL super_say_hello(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 des_rank, CSTRING *cstring);

EC_BOOL super_say_hello_loop(const UINT32 super_md_id, const UINT32 loops, const UINT32 des_tcid, const UINT32 des_rank);

EC_BOOL super_cond_wait(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key, const UINT32 timeout_msec);

EC_BOOL super_cond_wakeup(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key);

EC_BOOL super_cond_terminate(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key);

EC_BOOL super_cond_delete(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key);

/**
*
* store data to storage
*
**/
EC_BOOL super_http_store(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CBYTES *cbytes, const CSTRING *auth_token);
EC_BOOL super_http_store_after_ddir(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CBYTES *cbytes, const CSTRING *auth_token, const CHTTP_STORE *chttp_store);
EC_BOOL super_store_after_ddir(const UINT32 super_md_id, const UINT32 tcid, const CSTRING *path, const CBYTES *cbytes, const CSTRING *auth_token, const CHTTP_STORE *chttp_store);

/**
*
* notify local waiters  to wake up
*
**/
EC_BOOL super_notify(const UINT32 super_md_id, const UINT32 notify_flag, const CSTRING *notify_key);

/**
*
* notify remote waiters to wake up who are registered in locked-file owner list
* Note: it would not unlock the locked-file
*
**/
EC_BOOL super_unlock_notify(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
* unlock the locked-file
*
**/
EC_BOOL super_unlock(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRING *auth_token);

/**
*
* wait data on storage to be ready
*
**/
EC_BOOL super_wait_data(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, CBYTES *cbytes);
EC_BOOL super_wait_data_e(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const UINT32 store_offset, const UINT32 store_size, CBYTES *cbytes);

/**
*
* renew storage which stores http header
*
**/
EC_BOOL super_renew_header(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRING *key, const CSTRING *val);
EC_BOOL super_renew_headers(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token);
/**
*
* ask storage to notify file waiters
*
**/
EC_BOOL super_file_notify(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
* delete dir from storage
*
**/
EC_BOOL super_delete_dir(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
* delete file from storage
*
**/
EC_BOOL super_delete_file(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path);

/**
*
* set billing to billing-server (127.0.0.1:888)
*
**/
EC_BOOL super_set_billing(const UINT32 super_md_id, const UINT32 billing_srv_ipaddr, const UINT32 billing_srv_port, const CSTRING *billing_flags, const CSTRING *billing_domain, const CSTRING *billing_client_type, const UINT32 send_len, const UINT32 recv_len);

/**
*
* ngx reload bgn module so libs
*
**/
void super_ngx_reload_so(const UINT32 super_md_id);

/**
*
* ngx switch bgn module so libs
*
**/
void super_ngx_switch_so(const UINT32 super_md_id);

/**
*
* ngx show bgn module so libs
*
**/
void super_ngx_show_so(const UINT32 super_md_id, LOG *log);

/*------------------------------------------------------ test for ict -----------------------------------------------------------------------*/
EC_BOOL super_set_zone_size(const UINT32 super_md_id, const UINT32 obj_zone_size);
EC_BOOL super_load_data(const UINT32 super_md_id);
EC_BOOL super_load_data_all(const UINT32 super_md_id, const UINT32 obj_zone_num);
EC_BOOL super_get_data(const UINT32 super_md_id, const UINT32 obj_id, CVECTOR *obj_data);
EC_BOOL super_get_data_vec(const UINT32 super_md_id, const CVECTOR *obj_id_vec, CVECTOR *obj_data_vec);

EC_BOOL super_print_obj_vec(const UINT32 super_md_id, const CVECTOR *obj_vec, LOG *log);
EC_BOOL super_print_data(const UINT32 super_md_id, LOG *log);
EC_BOOL super_print_data_all(const UINT32 super_md_id, const UINT32 obj_zone_num, LOG *log);

/*------------------------------------------------------ test interface for general purpose -------------------------------------------------*/
EC_BOOL super_do_test(const UINT32 super_md_id);

EC_BOOL super_dns_resolve_demo(const UINT32 super_md_id, const CSTRING *dns_server, const CSTRING *domain);

#endif /*_SUPER_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

