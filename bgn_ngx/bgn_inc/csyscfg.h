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

#ifndef _CSYSCFG_H
#define _CSYSCFG_H

#include "type.h"
#include "clist.h"
#include "cvector.h"
#include "taskcfg.h"
#include "csyscfg.inc"

CLUSTER_NODE_CFG *cluster_node_cfg_new();

EC_BOOL cluster_node_cfg_init(CLUSTER_NODE_CFG *cluster_node_cfg);

EC_BOOL cluster_node_cfg_clean(CLUSTER_NODE_CFG *cluster_node_cfg);

EC_BOOL cluster_node_cfg_free(CLUSTER_NODE_CFG *cluster_node_cfg);

EC_BOOL cluster_node_cfg_check_tcid(const CLUSTER_NODE_CFG *cluster_node_cfg, const UINT32 tcid);

EC_BOOL cluster_node_cfg_check_rank_exist(const CLUSTER_NODE_CFG *cluster_node_cfg, const UINT32 rank);

EC_BOOL cluster_node_cfg_check_role_str(const CLUSTER_NODE_CFG *cluster_node_cfg, const char *role_str);

EC_BOOL cluster_node_cfg_check_role_cstr(const CLUSTER_NODE_CFG *cluster_node_cfg, const CSTRING *role_cstr);

EC_BOOL cluster_node_cfg_check_group_str(const CLUSTER_NODE_CFG *cluster_node_cfg, const char *group_str);

EC_BOOL cluster_node_cfg_check_group_cstr(const CLUSTER_NODE_CFG *cluster_node_cfg, const CSTRING *group_cstr);

void    cluster_node_cfg_print_xml(LOG *log, const CLUSTER_NODE_CFG *cluster_node_cfg, const UINT32 level);

CSTRING *cluster_node_cfg_get_extra_val_by_key_str(const CLUSTER_NODE_CFG *cluster_node_cfg, const char *key_str);

CSTRING *cluster_node_cfg_get_extra_val_by_key_cstr(const CLUSTER_NODE_CFG *cluster_node_cfg, const CSTRING *key_cstr);

CLUSTER_CFG *cluster_cfg_new();

EC_BOOL cluster_cfg_init(CLUSTER_CFG *cluster_cfg);

EC_BOOL cluster_cfg_clean(CLUSTER_CFG *cluster_cfg);

EC_BOOL cluster_cfg_free(CLUSTER_CFG *cluster_cfg);

EC_BOOL cluster_cfg_check_id(const CLUSTER_CFG *cluster_cfg, const UINT32 id);

EC_BOOL cluster_cfg_check_name_str(const CLUSTER_CFG *cluster_cfg, const char *name_str);

EC_BOOL cluster_cfg_check_name_cstr(const CLUSTER_CFG *cluster_cfg, const CSTRING *name_cstr);

EC_BOOL cluster_cfg_check_tcid_exist(const CLUSTER_CFG *cluster_cfg, const UINT32 tcid);

EC_BOOL cluster_cfg_check_duplicate(const CLUSTER_CFG *cluster_cfg_1st, const CLUSTER_CFG *cluster_cfg_2nd);

CLUSTER_NODE_CFG *cluster_cfg_search_by_tcid_rank(const CLUSTER_CFG *cluster_cfg, const UINT32 tcid, const UINT32 rank);

EC_BOOL cluster_cfg_collect_tcid_vec_by_group_cstr(const CLUSTER_CFG *cluster_cfg, const UINT32 model, const CSTRING *group_cstr, CVECTOR *tcid_vec);

EC_BOOL cluster_cfg_collect_tcid_vec_by_group_str(const CLUSTER_CFG *cluster_cfg, const UINT32 model, const char *group_str, CVECTOR *tcid_vec);

EC_BOOL cluster_cfg_collect_tcid_vec_by_role_cstr(const CLUSTER_CFG *cluster_cfg, const UINT32 model, const CSTRING *role_cstr, CVECTOR *tcid_vec);

EC_BOOL cluster_cfg_collect_tcid_vec_by_role_str(const CLUSTER_CFG *cluster_cfg, const UINT32 model, const char *role_str, CVECTOR *tcid_vec);

EC_BOOL cluster_cfg_collect_tcid_vec_by_role_and_group_cstr(const CLUSTER_CFG *cluster_cfg, const UINT32 model, const CSTRING *role_cstr, const CSTRING *group_cstr, CVECTOR *tcid_vec);

EC_BOOL cluster_cfg_collect_tcid_vec_by_role_and_group_str(const CLUSTER_CFG *cluster_cfg, const UINT32 model, const char *role_str, const char *group_str, CVECTOR *tcid_vec);

CSTRING *cluster_cfg_get_extra_val_by_key_str(const CLUSTER_CFG *cluster_cfg, const char *key_str);

CSTRING *cluster_cfg_get_extra_val_by_key_cstr(const CLUSTER_CFG *cluster_cfg, const CSTRING *key_cstr);

CSTRING *cluster_cfg_get_node_extra_val_by_key_str(const CLUSTER_CFG *cluster_cfg, const UINT32 tcid, const UINT32 rank, const char *key_str);

CSTRING *cluster_cfg_get_node_extra_val_by_key_cstr(const CLUSTER_CFG *cluster_cfg, const UINT32 tcid, const UINT32 rank, const CSTRING *key_cstr);

void    cluster_cfg_print_xml(LOG *log, const CLUSTER_CFG *cluster_cfg, const UINT32 level);

MCAST_CFG *mcast_cfg_new();

EC_BOOL mcast_cfg_init(MCAST_CFG *mcast_cfg);

EC_BOOL mcast_cfg_clean(MCAST_CFG *mcast_cfg);

EC_BOOL mcast_cfg_free(MCAST_CFG *mcast_cfg);

void    mcast_cfg_body_print_xml(LOG *log, const MCAST_CFG *mcast_cfg, const UINT32 level);

void    mcast_cfg_print_xml(LOG *log, const MCAST_CFG *mcast_cfg, const UINT32 level);

BCAST_DHCP_CFG *bcast_dhcp_cfg_new();

EC_BOOL bcast_dhcp_cfg_init(BCAST_DHCP_CFG *bcast_dhcp_cfg);

EC_BOOL bcast_dhcp_cfg_clean(BCAST_DHCP_CFG *bcast_dhcp_cfg);

EC_BOOL bcast_dhcp_cfg_free(BCAST_DHCP_CFG *bcast_dhcp_cfg);

void   bcast_dhcp_cfg_body_print_xml(LOG *log, const BCAST_DHCP_CFG *bcast_dhcp_cfg, const UINT32 level);

void   bcast_dhcp_cfg_print_xml(LOG *log, const BCAST_DHCP_CFG *bcast_dhcp_cfg, const UINT32 level);

void cparacfg_thread_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_csocket_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_log_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_conn_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_ssl_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_rfs_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_hfs_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_sfs_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_ngx_cfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void cparacfg_print_xml(LOG *log, const CPARACFG *cparacfg, const UINT32 level);

void paras_cfg_print_xml(LOG *log, const CVECTOR *paras_cfg, const UINT32 level);

MACIP_CFG *macip_cfg_new();

EC_BOOL macip_cfg_init(MACIP_CFG *macip_cfg);

EC_BOOL macip_cfg_clean(MACIP_CFG *macip_cfg);

EC_BOOL macip_cfg_free(MACIP_CFG *macip_cfg);

EC_BOOL macip_cfg_set(MACIP_CFG *macip_cfg, const UINT8 *mac_addr, const UINT32 ipv4_addr);

EC_BOOL macip_cfg_check_ipv4_addr(const MACIP_CFG *macip_cfg, const UINT32 ipv4_addr);

EC_BOOL macip_cfg_check_mac_addr(const MACIP_CFG *macip_cfg, const UINT8 * mac_addr);

EC_BOOL macip_cfg_has_null_mac_addr(const MACIP_CFG *macip_cfg);

void    macip_cfg_print_xml(LOG *log, const MACIP_CFG *macip_cfg, const UINT32 level);

void    macip_cfg_vec_print_xml(LOG *log, const CVECTOR *macip_cfg_vec, const UINT32 level);

SYS_CFG *sys_cfg_new();

EC_BOOL sys_cfg_init(SYS_CFG *sys_cfg);

EC_BOOL sys_cfg_clean(SYS_CFG *sys_cfg);

EC_BOOL sys_cfg_free(SYS_CFG *sys_cfg);

EC_BOOL sys_cfg_load(SYS_CFG *sys_cfg, const char *xml_fname);

CPARACFG *sys_cfg_search_cparacfg(const SYS_CFG *sys_cfg, const UINT32 tcid, const UINT32 rank);

TASKS_CFG *sys_cfg_search_tasks_cfg(const SYS_CFG *sys_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske);

TASKS_CFG *sys_cfg_search_tasks_cfg_by_ip(const SYS_CFG *sys_cfg, const UINT32 ipaddr, const UINT32 port);

TASKS_CFG *sys_cfg_search_tasks_cfg_by_netcards(const SYS_CFG *sys_cfg, const CSET *cnetcard_set);

TASKS_CFG *sys_cfg_search_tasks_cfg_by_macaddr(const SYS_CFG *sys_cfg, const UINT8 *macaddr);

TASKS_CFG *sys_cfg_search_tasks_cfg_by_csrv(const SYS_CFG *sys_cfg, const UINT32 tcid, const UINT32 csrvport);

MCAST_CFG *sys_cfg_search_mcast_cfg(const SYS_CFG *sys_cfg, const UINT32 tcid);

BCAST_DHCP_CFG *sys_cfg_search_bcast_dhcp_cfg(const SYS_CFG *sys_cfg, const UINT32 tcid);

TASK_CFG *sys_cfg_filter_task_cfg(const SYS_CFG *sys_cfg, const UINT32 tcid);

TASK_CFG *sys_cfg_get_task_cfg(const SYS_CFG *sys_cfg);

CVECTOR *sys_cfg_get_cluster_cfg_vec(const SYS_CFG *sys_cfg);

CLUSTER_CFG *sys_cfg_get_cluster_cfg_by_name_cstr(const SYS_CFG *sys_cfg, const CSTRING *name_cstr);

CLUSTER_CFG *sys_cfg_get_cluster_cfg_by_name_str(const SYS_CFG *sys_cfg, const char *name_str);

CLUSTER_CFG *sys_cfg_get_cluster_cfg_by_id(const SYS_CFG *sys_cfg, const UINT32 id);

CVECTOR *sys_cfg_get_paras_cfg(const SYS_CFG *sys_cfg);

CVECTOR *sys_cfg_get_macip_cfg_vec(const SYS_CFG *sys_cfg);

MCAST_CFG *sys_cfg_get_mcast_cfg(const SYS_CFG *sys_cfg);

BCAST_DHCP_CFG *sys_cfg_get_bcast_dhcp_cfg(const SYS_CFG *sys_cfg);

UINT32   sys_cfg_get_task_cfg_default_csrv_port(const SYS_CFG *sys_cfg);

MACIP_CFG *sys_cfg_search_macip_cfg_by_ipv4_addr(const SYS_CFG *sys_cfg, const UINT32 ipv4_addr);

MACIP_CFG *sys_cfg_search_macip_cfg_by_mac_addr(const SYS_CFG *sys_cfg, const UINT8 *mac_addr);

EC_BOOL sys_cfg_collect_hsdfs_dn_tcid_vec(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec, CVECTOR * dn_tcid_vec);

EC_BOOL sys_cfg_collect_hsdfs_np_tcid_vec(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec, CVECTOR * np_tcid_vec);

EC_BOOL sys_cfg_collect_hsdfs_client_tcid_vec(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec, CVECTOR * client_tcid_vec);

CSTRING *sys_cfg_get_hsdfs_np_root_dir(const SYS_CFG *sys_cfg, const UINT32 cluster_id);

CSTRING *sys_cfg_get_hsdfs_dn_root_dir(const SYS_CFG *sys_cfg, const UINT32 cluster_id);

CSTRING *sys_cfg_collect_hsdfs_np_root_dir(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec);

CSTRING *sys_cfg_collect_hsdfs_dn_root_dir(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec);

EC_BOOL sys_cfg_collect_hsbgt_root_tcid_vec(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec, CVECTOR * root_tcid_vec);

EC_BOOL sys_cfg_collect_hsbgt_table_tcid_vec(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec, CVECTOR * table_tcid_vec);

EC_BOOL sys_cfg_collect_hsbgt_client_tcid_vec(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec, CVECTOR * table_tcid_vec);

CSTRING *sys_cfg_get_hsbgt_root_table_dir(const SYS_CFG *sys_cfg, const UINT32 cluster_id);

CSTRING *sys_cfg_collect_hsbgt_root_table_dir(const SYS_CFG *sys_cfg, const CVECTOR *cluster_id_vec);

EC_BOOL sys_cfg_add_macip_cfg(SYS_CFG *sys_cfg, const UINT32 ipv4_addr, const UINT8 *mac_addr);

EC_BOOL sys_cfg_add_tasks_cfg(SYS_CFG *sys_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske, const UINT32 srvipaddr, const UINT32 srvport, const UINT32 csrvport, const UINT32 ssrvport);

EC_BOOL sys_cfg_flush_xml(const SYS_CFG *sys_cfg, const CSTRING *sys_cfg_xml_cstr);

void    sys_cfg_print_xml(LOG *log, const SYS_CFG *sys_cfg, const UINT32 level);


#endif/*_CSYSCFG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

