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

#ifndef _TASKCFG_H
#define _TASKCFG_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "clist.h"
#include "cset.h"
#include "cstring.h"
#include "cvector.h"

#include "taskcfg.inc"


/*------------------------------ TASKS_CFG interface ------------------------------*/
void tasks_cfg_init(TASKS_CFG *tasks_cfg);

void tasks_cfg_clean(TASKS_CFG *tasks_cfg);

TASKS_CFG * tasks_cfg_new();

void tasks_cfg_free(TASKS_CFG *tasks_cfg);

EC_BOOL tasks_cfg_clone(const TASKS_CFG *src_tasks_cfg, TASKS_CFG *des_tasks_cfg);

EC_BOOL tasks_cfg_cmp(const TASKS_CFG *tasks_cfg_1st, TASKS_CFG *tasks_cfg_2nd);

EC_BOOL tasks_cfg_is_matched(const TASKS_CFG *tasks_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske, const UINT32 srvipaddr, const UINT32 srvport);

EC_BOOL tasks_cfg_match_ip(const TASKS_CFG *tasks_cfg, const UINT32 srvipaddr, const UINT32 srvport);

EC_BOOL tasks_cfg_match_netcards(const TASKS_CFG *tasks_cfg, const CSET *cnetcard_set);

EC_BOOL tasks_cfg_match_csrv(const TASKS_CFG *tasks_cfg, const UINT32 tcid, const UINT32 csrvport);
EC_BOOL tasks_cfg_match_ssrv(const TASKS_CFG *tasks_cfg, const UINT32 tcid, const UINT32 ssrvport);

/**
*
*   return EC_TRUE if tasks_cfg belong to the debug networks
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_dbgnet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des);

/**
*
*   return EC_TRUE if tasks_cfg belong to the monitor networks
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_monnet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des);

/**
*
*   return EC_TRUE if tasks_cfg_des belong to the internal networks of tasks_cfg_src
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_intranet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des);

/**
*
*   return EC_TRUE if tasks_cfg_des and tasks_cfg_src are in the same LAN networks
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_lannet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des);

/**
*
*   return EC_TRUE if tasks_cfg_des belong to the external networks of tasks_cfg_src
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_externet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des);

EC_BOOL tasks_cfg_add_taskr(TASKS_CFG *tasks_cfg, const TASKR_CFG *taskr_cfg);

EC_BOOL tasks_cfg_del_taskr(TASKS_CFG *tasks_cfg, const TASKR_CFG *taskr_cfg);

EC_BOOL tasks_cfg_push_add_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func);

EC_BOOL tasks_cfg_push_del_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func);

EC_BOOL tasks_cfg_erase_add_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func);

EC_BOOL tasks_cfg_erase_del_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func);


void    tasks_cfg_print(LOG *log, const TASKS_CFG *tasks_cfg);

void    tasks_cfg_print_xml(LOG *log, const TASKS_CFG *tasks_cfg, const UINT32 level);


/*------------------------------ TASKR_CFG interface ------------------------------*/
void taskr_cfg_init(TASKR_CFG *taskr_cfg);

void taskr_cfg_clean(TASKR_CFG *taskr_cfg);

TASKR_CFG * taskr_cfg_new();

void    taskr_cfg_free(TASKR_CFG *taskr_cfg);

EC_BOOL taskr_cfg_clone(const TASKR_CFG *src_taskr_cfg, TASKR_CFG *des_taskr_cfg);

EC_BOOL taskr_cfg_cmp(const TASKR_CFG *taskr_cfg_1st, const TASKR_CFG *taskr_cfg_2nd);

EC_BOOL taskr_cfg_set(TASKR_CFG *taskr_cfg, const UINT32 des_tcid, const UINT32 maskr, const UINT32 next_tcid);

void    taskr_cfg_print(LOG *log, const TASKR_CFG *taskr_cfg);

void    taskr_cfg_print_xml(LOG *log, const TASKR_CFG *taskr_cfg, const UINT32 level);

/*------------------------------ TASK_CFG interface ------------------------------*/
void task_cfg_init(TASK_CFG *task_cfg);

void task_cfg_clean(TASK_CFG *task_cfg);

TASK_CFG * task_cfg_new();

void    task_cfg_free(TASK_CFG *task_cfg);

EC_BOOL task_cfg_clone(const TASK_CFG *src_task_cfg, TASK_CFG *des_task_cfg);

EC_BOOL task_cfg_filter(const TASK_CFG *src_task_cfg, const UINT32 tcid, TASK_CFG *des_task_cfg);

UINT32  task_cfg_default_csrv_port(const TASK_CFG *task_cfg);

EC_BOOL task_cfg_check_all(const TASK_CFG *task_cfg);/*for debug only*/

TASKS_CFG *task_cfg_searchs(const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske);

TASKS_CFG *task_cfg_searchs_by_ip(const TASK_CFG *task_cfg, const UINT32 ipaddr, const UINT32 port);

TASKS_CFG *task_cfg_searchs_by_netcards(const TASK_CFG *task_cfg, const CSET *cnetcard_set);

TASKS_CFG *task_cfg_searchs_by_csrv(const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 csrvport);

void task_cfg_print(LOG *log, const TASK_CFG *task_cfg);

void task_cfg_print_xml(LOG *log, const TASK_CFG *task_cfg, const UINT32 level);


#endif /*_TASKCFG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

