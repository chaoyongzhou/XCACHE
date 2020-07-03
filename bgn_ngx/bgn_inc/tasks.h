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

#ifndef _TASKS_H
#define _TASKS_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "cstring.h"
#include "taskcfg.inc"

#include "csocket.h"
#include "ccallback.h"
#include "cmutex.h"

//#define TASKS_DBG_ENTER(__func_name__) do{sys_log(LOGSTDOUT, "enter %s\n", __func_name__);}while(0)
//#define TASKS_DBG_LEAVE(__func_name__) do{sys_log(LOGSTDOUT, "leave %s\n", __func_name__);}while(0)

#define TASKS_DBG_ENTER(__func_name__) do{}while(0)
#define TASKS_DBG_LEAVE(__func_name__) do{}while(0)

/*------------------------------------------------- taskcomm server interface -------------------------------------------------*/

EC_BOOL tasks_srv_start(TASKS_CFG *tasks_cfg);

EC_BOOL tasks_srv_close(TASKS_CFG *tasks_cfg);

EC_BOOL tasks_srv_end(TASKS_CFG *tasks_cfg);

EC_BOOL tasks_srv_accept_once(TASKS_CFG *tasks_cfg, EC_BOOL *continue_flag);

EC_BOOL tasks_srv_accept(TASKS_CFG *tasks_cfg);


/*------------------------------------------------- TASKS_NODE interface -------------------------------------------------*/
TASKS_NODE *tasks_node_new(const UINT32 srvipaddr, const UINT32 srvport, const UINT32 tcid, const UINT32 comm, const UINT32 size);

EC_BOOL tasks_node_init(TASKS_NODE *tasks_node, const UINT32 srvipaddr, const UINT32 srvport, const UINT32 tcid, const UINT32 comm, const UINT32 size);

EC_BOOL tasks_node_clean(TASKS_NODE *tasks_node);

EC_BOOL tasks_node_free(TASKS_NODE *tasks_node);

TASKS_NODE *tasks_node_new_0();

EC_BOOL tasks_node_init_0(TASKS_NODE *tasks_node);

EC_BOOL tasks_node_clone_0(const TASKS_NODE *tasks_node_src, TASKS_NODE *tasks_node_des);

EC_BOOL tasks_node_is_connected(const TASKS_NODE *tasks_node);

EC_BOOL tasks_node_is_connected_no_lock(const TASKS_NODE *tasks_node);

EC_BOOL tasks_node_is_empty(const TASKS_NODE *tasks_node);

EC_BOOL tasks_node_cmp(const TASKS_NODE *src_tasks_node, const TASKS_NODE *des_tasks_node);

EC_BOOL tasks_node_check(const TASKS_NODE *tasks_node, const CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_node_irecv(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_node_isend(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_node_iclose(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_node_heartbeat(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_node_set_epoll(TASKS_NODE *tasks_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_node_set_callback(TASKS_NODE *tasks_node, CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_node_is_tcid(const TASKS_NODE *src_tasks_node, const UINT32 tcid);

EC_BOOL tasks_node_is_ipaddr(const TASKS_NODE *src_tasks_node, const UINT32 ipaddr);

void    tasks_node_print(LOG *log, const TASKS_NODE *tasks_node);

void    tasks_node_print_csocket_cnode_list(LOG *log, const TASKS_NODE *tasks_node, UINT32 *index);

void    tasks_node_print_in_plain(LOG *log, const TASKS_NODE *tasks_node);

void    tasks_node_sprint(CSTRING *cstring, const TASKS_NODE *tasks_node);

EC_BOOL tasks_node_update_time(TASKS_NODE *tasks_node);

/*------------------------------------------------- TASKS_WORKER interface -------------------------------------------------*/
UINT32 tasks_worker_count_no_lock(const TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);

UINT32 tasks_worker_count(const TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);

TASKS_NODE    *tasks_worker_search_tasks_node_by_ipaddr(const TASKS_WORKER *tasks_worker, const UINT32 ipaddr);

TASKS_NODE    *tasks_worker_search_tasks_node_by_tcid(const TASKS_WORKER *tasks_worker, const UINT32 tcid);

TASKS_NODE *tasks_worker_search_tasks_node_by_tcid_comm(const TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 comm);

TASKS_NODE *tasks_worker_search(TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port);

UINT32  tasks_worker_search_tcid_by_ipaddr(const TASKS_WORKER *tasks_worker, const UINT32 ipaddr);

/*debug*/
EC_BOOL tasks_worker_delete(TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port);

EC_BOOL tasks_worker_check_connected_by_tcid(const TASKS_WORKER *tasks_worker, const UINT32 tcid);

EC_BOOL tasks_worker_check_connected_by_ipaddr(const TASKS_WORKER *tasks_worker, const UINT32 ipaddr);

EC_BOOL tasks_worker_add_csocket_cnode(TASKS_WORKER *tasks_worker, CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_worker_collect_tcid(const TASKS_WORKER *tasks_worker, CVECTOR *tcid_vec);

EC_BOOL tasks_worker_collect_ipaddr(const TASKS_WORKER *tasks_worker, CVECTOR *ipaddr_vec);

EC_BOOL tasks_worker_init(TASKS_WORKER *tasks_worker);

EC_BOOL tasks_worker_clean(TASKS_WORKER *tasks_worker);

void    tasks_worker_print(LOG *log, const TASKS_WORKER *tasks_worker);

void    tasks_worker_print_in_plain(LOG *log, const TASKS_WORKER *tasks_worker);

void    tasks_worker_print_csocket_cnode_list_in_plain(LOG *log, const TASKS_WORKER *tasks_worker, UINT32 *index);

EC_BOOL tasks_worker_isend_node(TASKS_WORKER *tasks_worker, const UINT32 des_tcid, const UINT32 des_comm, const UINT32 msg_tag, TASK_NODE *task_node);

EC_BOOL tasks_worker_heartbeat(TASKS_WORKER *tasks_worker);

/*------------------------------------------------- TASKS_MONITOR interface -------------------------------------------------*/
EC_BOOL tasks_monitor_add_csocket_cnode(TASKS_MONITOR *tasks_monitor, CSOCKET_CNODE *csocket_cnode);

UINT32 tasks_monitor_count_no_lock(const TASKS_MONITOR *tasks_monitor, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);

UINT32 tasks_monitor_count(const TASKS_MONITOR *tasks_monitor, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);

EC_BOOL tasks_monitor_open(TASKS_MONITOR *tasks_monitor, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);


EC_BOOL tasks_monitor_init(TASKS_MONITOR *tasks_monitor);

EC_BOOL tasks_monitor_clean(TASKS_MONITOR *tasks_monitor);

EC_BOOL tasks_monitor_is_empty(const TASKS_MONITOR *tasks_monitor);

void    tasks_monitor_print(LOG *log, const TASKS_MONITOR *tasks_monitor);

void    tasks_monitor_print_in_plain(LOG *log, const TASKS_MONITOR *tasks_monitor);


EC_BOOL tasks_handshake_isend(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_handshake_irecv(CSOCKET_CNODE *csocket_cnod);

EC_BOOL tasks_handshake_icomplete(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_handshake_ichange(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_handshake_send(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_handshake_recv(CSOCKET_CNODE *csocket_cnode);

EC_BOOL tasks_handshake_shutdown(CSOCKET_CNODE *csocket_cnode);

#endif/*_TASKS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
