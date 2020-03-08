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

#ifndef _CXML_H
#define _CXML_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "type.h"
#include "cset.h"
#include "taskcfg.h"
#include "cparacfg.inc"

#include "csyscfg.h"

typedef EC_BOOL (*CXML_PARSE_TAG)(xmlNodePtr, const char *, void *);

xmlDocPtr cxml_new(const UINT8 *xml_doc_name);

xmlNodePtr cxml_get_root(xmlDocPtr xml_doc_ptr);

void   cxml_free(xmlDocPtr xml_doc_ptr);

EC_BOOL cxml_parse_tasks_cfg(xmlNodePtr node, TASKS_CFG *tasks_cfg);

EC_BOOL cxml_parse_taskr_cfg(xmlNodePtr node, TASKR_CFG *taskr_cfg);

EC_BOOL cxml_parse_task_cfg(xmlNodePtr node, TASK_CFG *task_cfg, const UINT32 default_tasks_cfg_port);

EC_BOOL cxml_parse_cluster_node_cfg(xmlNodePtr node, CLUSTER_NODE_CFG *cluster_node_cfg);

EC_BOOL cxml_parse_cluster_cfg(xmlNodePtr node, CLUSTER_CFG *cluster_cfg);

EC_BOOL cxml_parse_cluster_cfg_vec(xmlNodePtr node, CVECTOR *cluster_cfg_vec);

EC_BOOL cxml_parse_mcast_cfg(xmlNodePtr node, MCAST_CFG *mcast_cfg);

EC_BOOL cxml_parse_udp_mcast_cfg(xmlNodePtr node, MCAST_CFG *mcast_cfg);

EC_BOOL cxml_parse_bcast_dhcp_cfg(xmlNodePtr node, BCAST_DHCP_CFG *bcast_dhcp_cfg);

EC_BOOL cxml_parse_udp_bcast_dhcp_cfg(xmlNodePtr node, BCAST_DHCP_CFG *bcast_dhcp_cfg);

EC_BOOL cxml_parse_cparacfg_thread_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_encode_rule_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_csocket_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_log_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_rfs_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_xfs_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_hfs_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_ngx_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_conn_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_ssl_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_amd_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_para_cfg(xmlNodePtr node, CPARACFG *cparacfg);

EC_BOOL cxml_parse_cparacfg_of_specific(xmlNodePtr node, CPARACFG *cparacfg, const UINT32 tcid, const UINT32 rank);

EC_BOOL cxml_parse_macip_cfg(xmlNodePtr node, MACIP_CFG *macip_cfg);

EC_BOOL cxml_parse_macip_cfg_vec(xmlNodePtr node, CVECTOR *macip_cfg_vec);

EC_BOOL cxml_parse_sys_cfg(xmlNodePtr node, SYS_CFG *sys_cfg);

#endif/*_CXML_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

