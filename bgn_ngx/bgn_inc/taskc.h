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

#ifndef _TASKC_H
#define _TASKC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "type.h"
#include "mod.inc"
#include "taskcfg.h"
#include "csocket.h"

typedef struct
{
    /* used counter >= 0 */
    UINT32 usedcounter;

    MOD_MGR *mod_mgr;

    TASK_CFG  *task_cfg;
    TASKS_CFG *local_tasks_cfg;

    /*this taskComm addr info*/
    UINT32     tcid;
    UINT32     comm;
    UINT32     rank;
    UINT32     ipaddr;
    UINT32     port;

}TASKC_MD;

/**
*   for test only
*
*   to query the status of TASKC Module
*
**/
void print_taskc_status(LOG *log);

/**
*
*   free all static memory occupied by the appointed TASKC module
*
*
**/
UINT32 taskc_free_module_static_mem(const UINT32 taskc_md_id);

/**
*
* start taskc module
*
**/
UINT32 taskc_start(const TASK_CFG *src_task_cfg, const UINT32 tcid, const UINT32 comm, const UINT32 rank);

/**
*
* end taskc module
*
**/
void   taskc_end(const UINT32 taskc_md_id);

/**
*
* initialize mod mgr of TASKC module
*
**/
UINT32  taskc_set_mod_mgr(const UINT32 taskc_md_id, const MOD_MGR * src_mod_mgr);

EC_BOOL taskc_register_one(const UINT32 taskc_md_id, const UINT32 remote_tcid, const UINT32 remote_srv_ipaddr, const UINT32 remote_srv_port, const UINT32 conn_num);

EC_BOOL taskc_register_all(const UINT32 taskc_md_id);

TASK_CFG *  taskc_get_task_cfg(const UINT32 taskc_md_id);

TASKS_CFG * taskc_get_local_tasks_cfg(const UINT32 taskc_md_id);

UINT32 taskc_get_local_tcid(const UINT32 taskc_md_id);

UINT32 taskc_get_local_srvipaddr(const UINT32 taskc_md_id);

UINT32 taskc_get_local_srvport(const UINT32 taskc_md_id);


#endif/*_TASKC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

