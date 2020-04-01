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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>


#include "type.h"
#include "log.h"

#include "clist.h"
#include "cset.h"
#include "cstring.h"
#include "cmisc.h"
#include "cxml.h"
#include "cdevice.h"
#include "csocket.h"

#include "taskcfg.inc"
#include "taskcfg.h"
#include "tasks.h"
#include "task.h"

#include "cmpic.inc"

#include "crouter.h"

STATIC_CAST static void taskx_cfg_ident_print_xml(LOG *log, const UINT32 level)
{
    UINT32 idx;

    for(idx = 0; idx < level; idx ++)
    {
        sys_print(log, "    ");
    }
    return;
}

/*------------------------------ TASKS_CFG interface ------------------------------*/
void tasks_cfg_init(TASKS_CFG *tasks_cfg)
{
    TASKS_CFG_TCID(tasks_cfg)       = CMPI_ERROR_TCID;
    TASKS_CFG_MASKI(tasks_cfg)      = CMPI_ERROR_MASK;
    TASKS_CFG_MASKE(tasks_cfg)      = CMPI_ERROR_MASK;
    TASKS_CFG_SRVIPADDR(tasks_cfg)  = CMPI_ERROR_IPADDR;
    TASKS_CFG_SRVPORT(tasks_cfg)    = CMPI_ERROR_SRVPORT;
    TASKS_CFG_CSRVPORT(tasks_cfg)   = CMPI_ERROR_SRVPORT;
    TASKS_CFG_SSRVPORT(tasks_cfg)   = CMPI_ERROR_SRVPORT;
    TASKS_CFG_SRVSOCKFD(tasks_cfg)  = CMPI_ERROR_SOCKFD;

    cvector_init(TASKS_CFG_CLUSTER_VEC(tasks_cfg), 0, MM_UINT32, CVECTOR_LOCK_ENABLE, LOC_TASKCFG_0001);

    tasks_worker_init(TASKS_CFG_WORKER(tasks_cfg));
    tasks_monitor_init(TASKS_CFG_MONITOR(tasks_cfg));

    cvector_init(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), 0, MM_TASKR_CFG, CVECTOR_LOCK_ENABLE, LOC_TASKCFG_0002);

    return;
}

void tasks_cfg_clean(TASKS_CFG *tasks_cfg)
{
    tasks_worker_clean(TASKS_CFG_WORKER(tasks_cfg));
    tasks_monitor_clean(TASKS_CFG_MONITOR(tasks_cfg));

    cvector_clean(TASKS_CFG_CLUSTER_VEC(tasks_cfg), NULL_PTR, LOC_TASKCFG_0003);
    cvector_clean(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), (CVECTOR_DATA_CLEANER)taskr_cfg_free, LOC_TASKCFG_0004);

    TASKS_CFG_TCID(tasks_cfg)       = CMPI_ERROR_TCID;
    TASKS_CFG_MASKI(tasks_cfg)      = CMPI_ERROR_MASK;
    TASKS_CFG_MASKE(tasks_cfg)      = CMPI_ERROR_MASK;
    TASKS_CFG_SRVIPADDR(tasks_cfg)  = CMPI_ERROR_IPADDR;
    TASKS_CFG_SRVPORT(tasks_cfg)    = CMPI_ERROR_SRVPORT;
    TASKS_CFG_CSRVPORT(tasks_cfg)   = CMPI_ERROR_SRVPORT;
    TASKS_CFG_SSRVPORT(tasks_cfg)   = CMPI_ERROR_SRVPORT;
    TASKS_CFG_SRVSOCKFD(tasks_cfg)  = CMPI_ERROR_SOCKFD;

    return;
}

TASKS_CFG * tasks_cfg_new()
{
    TASKS_CFG *tasks_cfg;

    alloc_static_mem(MM_TASKS_CFG, &tasks_cfg, LOC_TASKCFG_0005);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0019_TASKCFG, 0)(LOGSTDOUT, "error:tasks_cfg_new: failed to alloc TASKS_CFG\n");
        return (NULL_PTR);
    }

    tasks_cfg_init(tasks_cfg);

    return (tasks_cfg);
}

void tasks_cfg_free(TASKS_CFG *tasks_cfg)
{
    tasks_cfg_clean(tasks_cfg);
    free_static_mem(MM_TASKS_CFG, tasks_cfg, LOC_TASKCFG_0006);
    return;
}

EC_BOOL tasks_cfg_clone(const TASKS_CFG *src_tasks_cfg, TASKS_CFG *des_tasks_cfg)
{
    TASKS_CFG_TCID(des_tasks_cfg)   = TASKS_CFG_TCID(src_tasks_cfg);
    TASKS_CFG_MASKI(des_tasks_cfg)  = TASKS_CFG_MASKI(src_tasks_cfg);
    TASKS_CFG_MASKE(des_tasks_cfg)  = TASKS_CFG_MASKE(src_tasks_cfg);

    TASKS_CFG_SRVIPADDR(des_tasks_cfg) = TASKS_CFG_SRVIPADDR(src_tasks_cfg);
    TASKS_CFG_SRVPORT(des_tasks_cfg)   = TASKS_CFG_SRVPORT(src_tasks_cfg);
    TASKS_CFG_CSRVPORT(des_tasks_cfg)  = TASKS_CFG_CSRVPORT(src_tasks_cfg);
    TASKS_CFG_SSRVPORT(des_tasks_cfg)  = TASKS_CFG_SSRVPORT(src_tasks_cfg);

    cvector_clone(TASKS_CFG_CLUSTER_VEC(src_tasks_cfg), TASKS_CFG_CLUSTER_VEC(des_tasks_cfg), NULL_PTR, NULL_PTR);

    cvector_clone(TASKS_CFG_TASKR_CFG_VEC(src_tasks_cfg), TASKS_CFG_TASKR_CFG_VEC(des_tasks_cfg),
                  (CVECTOR_DATA_MALLOC)taskr_cfg_new, (CVECTOR_DATA_CLONE)taskr_cfg_clone);

    /*NOTE: do not clone srvsockfd, tasks_worker and tasks_monitor which are run-time dynamic information*/
    return (EC_TRUE);
}

EC_BOOL tasks_cfg_cmp(const TASKS_CFG *tasks_cfg_1st, TASKS_CFG *tasks_cfg_2nd)
{
    if(TASKS_CFG_TCID(tasks_cfg_2nd) != TASKS_CFG_TCID(tasks_cfg_1st))
    {
        return (EC_FALSE);
    }

    if(TASKS_CFG_MASKI(tasks_cfg_2nd) != TASKS_CFG_MASKI(tasks_cfg_1st))
    {
        return (EC_FALSE);
    }

    if(TASKS_CFG_MASKE(tasks_cfg_2nd) != TASKS_CFG_MASKE(tasks_cfg_1st))
    {
        return (EC_FALSE);
    }

    if(TASKS_CFG_SRVIPADDR(tasks_cfg_2nd) != TASKS_CFG_SRVIPADDR(tasks_cfg_1st))
    {
        return (EC_FALSE);
    }

    if(TASKS_CFG_SRVPORT(tasks_cfg_2nd) != TASKS_CFG_SRVPORT(tasks_cfg_1st))
    {
        return (EC_FALSE);
    }

    if(TASKS_CFG_CSRVPORT(tasks_cfg_2nd) != TASKS_CFG_CSRVPORT(tasks_cfg_1st))
    {
        return (EC_FALSE);
    }

    if(TASKS_CFG_SSRVPORT(tasks_cfg_2nd) != TASKS_CFG_SSRVPORT(tasks_cfg_1st))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL tasks_cfg_is_matched(const TASKS_CFG *tasks_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske, const UINT32 srvipaddr, const UINT32 srvport)
{
    if(CMPI_ANY_TCID != tcid && (TASKS_CFG_TCID(tasks_cfg) & maski) != (tcid & maski))
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_TCID != tcid && (TASKS_CFG_TCID(tasks_cfg) & maske) != (tcid & maske))
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_IPADDR != srvipaddr && TASKS_CFG_SRVIPADDR(tasks_cfg) != srvipaddr)
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_SRVPORT != srvport && TASKS_CFG_SRVPORT(tasks_cfg) != srvport)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL tasks_cfg_match_ip(const TASKS_CFG *tasks_cfg, const UINT32 srvipaddr, const UINT32 srvport)
{
    if(CMPI_ANY_IPADDR != srvipaddr
    && TASKS_CFG_SRVIPADDR(tasks_cfg) != srvipaddr)
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_SRVPORT != srvport
    && TASKS_CFG_SRVPORT(tasks_cfg) != srvport
    && TASKS_CFG_CSRVPORT(tasks_cfg) != srvport
    && TASKS_CFG_SSRVPORT(tasks_cfg) != srvport
    )
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL tasks_cfg_match_netcards(const TASKS_CFG *tasks_cfg, const CSET *cnetcard_set)
{
    if(EC_FALSE == cnetcard_has_ipv4val(cnetcard_set, TASKS_CFG_SRVIPADDR(tasks_cfg)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL tasks_cfg_match_csrv(const TASKS_CFG *tasks_cfg, const UINT32 tcid, const UINT32 csrvport)
{
    if(TASKS_CFG_TCID(tasks_cfg) != tcid)
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_SRVPORT != csrvport && TASKS_CFG_CSRVPORT(tasks_cfg) != csrvport)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL tasks_cfg_match_ssrv(const TASKS_CFG *tasks_cfg, const UINT32 tcid, const UINT32 ssrvport)
{
    if(TASKS_CFG_TCID(tasks_cfg) != tcid)
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_SRVPORT != ssrvport && TASKS_CFG_SSRVPORT(tasks_cfg) != ssrvport)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}



/**
*
*   return EC_TRUE if tasks_cfg belong to the debug networks
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_dbgnet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des)
{
    if(EC_TRUE == task_brd_check_is_dbg_tcid(TASKS_CFG_TCID(tasks_cfg_src))
    || EC_TRUE == task_brd_check_is_dbg_tcid(TASKS_CFG_TCID(tasks_cfg_des)))
    {
        dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [Y] tasks_cfg_is_dbgnet: %s or %s is dbgnet\n",
                            TASKS_CFG_TCID_STR(tasks_cfg_src),
                            TASKS_CFG_TCID_STR(tasks_cfg_des));

        return (EC_TRUE);
    }

    dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [N] tasks_cfg_is_dbgnet: %s and %s are not dbgnet\n",
                        TASKS_CFG_TCID_STR(tasks_cfg_src),
                        TASKS_CFG_TCID_STR(tasks_cfg_des));
    return (EC_FALSE);
}

/**
*
*   return EC_TRUE if tasks_cfg belong to the monitor networks
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_monnet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des)
{
    if(EC_TRUE == task_brd_check_is_monitor_tcid(TASKS_CFG_TCID(tasks_cfg_src))
    || EC_TRUE == task_brd_check_is_monitor_tcid(TASKS_CFG_TCID(tasks_cfg_des)))
    {
        dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [Y] tasks_cfg_is_monnet: %s or %s is monnet\n",
                            TASKS_CFG_TCID_STR(tasks_cfg_src),
                            TASKS_CFG_TCID_STR(tasks_cfg_des));

        return (EC_TRUE);
    }

    dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [N] tasks_cfg_is_monnet: %s and %s are not monnet\n",
                        TASKS_CFG_TCID_STR(tasks_cfg_src),
                        TASKS_CFG_TCID_STR(tasks_cfg_des));
    return (EC_FALSE);
}

/**
*
*   return EC_TRUE if tasks_cfg_des belong to the internal networks of tasks_cfg_src
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_intranet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des)
{
    /*src & maski(src) == des & maski(src)*/
    if(DES_TCID_IS_INTRANET(TASKS_CFG_TCID(tasks_cfg_src), TASKS_CFG_MASKI(tasks_cfg_src), TASKS_CFG_TCID(tasks_cfg_des), TASKS_CFG_MASKE(tasks_cfg_des)))
    {
        dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [Y] tasks_cfg_is_intranet: %s & %s == %s & %s\n",
                            TASKS_CFG_TCID_STR(tasks_cfg_src), TASKS_CFG_MASKI_STR(tasks_cfg_src),
                            TASKS_CFG_TCID_STR(tasks_cfg_des), TASKS_CFG_MASKE_STR(tasks_cfg_des));
        return (EC_TRUE);
    }
    dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [N] tasks_cfg_is_intranet: %s & %s != %s & %s\n",
                        TASKS_CFG_TCID_STR(tasks_cfg_src), TASKS_CFG_MASKI_STR(tasks_cfg_src),
                        TASKS_CFG_TCID_STR(tasks_cfg_des), TASKS_CFG_MASKE_STR(tasks_cfg_des));
    return (EC_FALSE);
}

/**
*
*   return EC_TRUE if tasks_cfg_des and tasks_cfg_src are in the same LAN networks
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_lannet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des)
{
    /*src & maske(src) == des & maske(des)*/
    if(DES_TCID_IS_LANNET(TASKS_CFG_TCID(tasks_cfg_src), TASKS_CFG_MASKE(tasks_cfg_src), TASKS_CFG_TCID(tasks_cfg_des), TASKS_CFG_MASKE(tasks_cfg_des)))
    {
        dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [Y] tasks_cfg_is_lannet: %s & %s == %s & %s\n",
                            TASKS_CFG_TCID_STR(tasks_cfg_src), TASKS_CFG_MASKE_STR(tasks_cfg_src),
                            TASKS_CFG_TCID_STR(tasks_cfg_des), TASKS_CFG_MASKE_STR(tasks_cfg_des));
        return (EC_TRUE);
    }
    dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [N] tasks_cfg_is_lannet: %s & %s != %s & %s\n",
                        TASKS_CFG_TCID_STR(tasks_cfg_src), TASKS_CFG_MASKE_STR(tasks_cfg_src),
                        TASKS_CFG_TCID_STR(tasks_cfg_des), TASKS_CFG_MASKE_STR(tasks_cfg_des));
    return (EC_FALSE);
}

/**
*
*   return EC_TRUE if tasks_cfg_des belong to the external networks of tasks_cfg_src
*   otherwise, return EC_FALSE
*
**/
EC_BOOL tasks_cfg_is_externet(const TASKS_CFG *tasks_cfg_src, const TASKS_CFG *tasks_cfg_des)
{
    /*src & maske(src) == des & maske(src)*/
    if(DES_TCID_IS_EXTERNET(TASKS_CFG_TCID(tasks_cfg_src), TASKS_CFG_MASKE(tasks_cfg_src), TASKS_CFG_TCID(tasks_cfg_des), TASKS_CFG_MASKI(tasks_cfg_des)))
    {
        dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [Y] tasks_cfg_is_externet: %s & %s == %s & %s\n",
                            TASKS_CFG_TCID_STR(tasks_cfg_src), TASKS_CFG_MASKE_STR(tasks_cfg_src),
                            TASKS_CFG_TCID_STR(tasks_cfg_des), TASKS_CFG_MASKI_STR(tasks_cfg_des));
        return (EC_TRUE);
    }
    dbg_log(SEC_0019_TASKCFG, 1)(LOGSTDOUT, "[DEBUG] [N] tasks_cfg_is_externet: %s & %s != %s & %s\n",
                        TASKS_CFG_TCID_STR(tasks_cfg_src), TASKS_CFG_MASKE_STR(tasks_cfg_src),
                        TASKS_CFG_TCID_STR(tasks_cfg_des), TASKS_CFG_MASKI_STR(tasks_cfg_des));
    return (EC_FALSE);
}

EC_BOOL tasks_cfg_add_taskr(TASKS_CFG *tasks_cfg, const TASKR_CFG *taskr_cfg)
{
    if(CVECTOR_ERR_POS != cvector_search_front(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), (void *)taskr_cfg, (CVECTOR_DATA_CMP)taskr_cfg_cmp))
    {
        return (EC_FALSE);
    }

    cvector_push(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), (void *)taskr_cfg);
    return (EC_TRUE);
}

EC_BOOL tasks_cfg_del_taskr(TASKS_CFG *tasks_cfg, const TASKR_CFG *taskr_cfg)
{
    UINT32 pos;
    TASKR_CFG *taskr_cfg_del;

    pos = cvector_search_front(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), (void *)taskr_cfg, (CVECTOR_DATA_CMP)taskr_cfg_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        return (EC_FALSE);
    }

    taskr_cfg_del = (TASKR_CFG *)cvector_erase(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), pos);
    taskr_cfg_free(taskr_cfg_del);

    return (EC_TRUE);
}

EC_BOOL tasks_cfg_push_add_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func)
{
    return tasks_worker_push_add_callback(TASKS_CFG_WORKER(tasks_cfg), name, modi, func);
}

EC_BOOL tasks_cfg_push_del_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func)
{
    return tasks_worker_push_del_callback(TASKS_CFG_WORKER(tasks_cfg), name, modi, func);
}

EC_BOOL tasks_cfg_erase_add_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func)
{
    return tasks_worker_erase_add_callback(TASKS_CFG_WORKER(tasks_cfg), name, modi, func);
}

EC_BOOL tasks_cfg_erase_del_worker_callback(TASKS_CFG *tasks_cfg, const char *name, const UINT32 modi, const UINT32 func)
{
    return tasks_worker_erase_del_callback(TASKS_CFG_WORKER(tasks_cfg), name, modi, func);
}

void tasks_cfg_print(LOG *log, const TASKS_CFG *tasks_cfg)
{
    char *cluster_str;

    cluster_str = uint32_vec_to_str(TASKS_CFG_CLUSTER_VEC(tasks_cfg));
    sys_log(log, "tasks_cfg %lx:  tcid = %s, maski = %s, maske = %s, srvipaddr = %s, srvport = %ld, srvsockfd = %d, cluster = %s\n",
                    tasks_cfg,
                    TASKS_CFG_TCID_STR(tasks_cfg),
                    TASKS_CFG_MASKI_STR(tasks_cfg),
                    TASKS_CFG_MASKE_STR(tasks_cfg),
                    TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                    TASKS_CFG_SRVPORT(tasks_cfg),
                    TASKS_CFG_SRVSOCKFD(tasks_cfg),
                    (NULL_PTR == cluster_str)?(const char *)"null":cluster_str
            );
    if(NULL_PTR != cluster_str)
    {
        safe_free(cluster_str, LOC_TASKCFG_0007);
    }

    sys_log(log, "tasks_cfg: worker clients");
    tasks_worker_print(log, TASKS_CFG_WORKER(tasks_cfg));

    sys_log(log, "tasks_cfg: monitor clients");
    tasks_monitor_print(log, TASKS_CFG_MONITOR(tasks_cfg));

    return;
}

STATIC_CAST static void tasks_cfg_body_print_xml(LOG *log, const TASKS_CFG *tasks_cfg, const UINT32 level)
{
    char *cluster_str;

    cluster_str = uint32_vec_to_str(TASKS_CFG_CLUSTER_VEC(tasks_cfg));

    sys_print(log, " tcid=\"%s\""     , TASKS_CFG_TCID_STR(tasks_cfg));
    //sys_print(log, " maski=\"%s\"", TASKS_CFG_MASKI_STR(tasks_cfg));
    //sys_print(log, " maske=\"%s\"", TASKS_CFG_MASKE_STR(tasks_cfg));
    sys_print(log, " maski=\"%ld\""   , (UINT32)ipv4_subnet_mask_prefix(TASKS_CFG_MASKI(tasks_cfg)));
    sys_print(log, " maske=\"%ld\""   , (UINT32)ipv4_subnet_mask_prefix(TASKS_CFG_MASKE(tasks_cfg)));
    sys_print(log, " ipv4=\"%s\"", TASKS_CFG_SRVIPADDR_STR(tasks_cfg));
    sys_print(log, " bgn=\"%ld\"" , TASKS_CFG_SRVPORT(tasks_cfg));

    if(CMPI_ERROR_SRVPORT != TASKS_CFG_CSRVPORT(tasks_cfg))
    {
        sys_print(log, " rest=\"%ld\"", TASKS_CFG_CSRVPORT(tasks_cfg));
    }

    if(CMPI_ERROR_SRVPORT != TASKS_CFG_SSRVPORT(tasks_cfg))
    {
        sys_print(log, " ssrvport=\"%ld\"", TASKS_CFG_SSRVPORT(tasks_cfg));
    }

    if(NULL_PTR != cluster_str)
    {
        sys_print(log, " cluster=\"%s\"", cluster_str);
        safe_free(cluster_str, LOC_TASKCFG_0008);
    }
    return;
}

void tasks_cfg_print_xml(LOG *log, const TASKS_CFG *tasks_cfg, const UINT32 level)
{
    UINT32 pos;

    if(0 == cvector_size(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg)))
    {
        taskx_cfg_ident_print_xml(log, level);
        sys_print(log, "<tasks");
        tasks_cfg_body_print_xml(log, tasks_cfg, level);
        sys_print(log, "/>\n");
        return;
    }

    taskx_cfg_ident_print_xml(log, level);
    taskx_cfg_ident_print_xml(log, level);
    sys_print(log, "<tasks");
    tasks_cfg_body_print_xml(log, tasks_cfg, level);
    sys_print(log, ">\n");

    CVECTOR_LOCK(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), LOC_TASKCFG_0009);
    for(pos = 0; pos < cvector_size(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg)); pos ++)
    {
        TASKR_CFG *taskr_cfg;

        taskr_cfg = (TASKR_CFG *)cvector_get_no_lock(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), pos);
        if(NULL_PTR == taskr_cfg)
        {
            continue;
        }
        taskr_cfg_print_xml(log, taskr_cfg, level + 1);
    }
    CVECTOR_UNLOCK(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), LOC_TASKCFG_0010);

    taskx_cfg_ident_print_xml(log, level);
    sys_print(log, "</tasks>\n");
    return;
}


/*------------------------------ TASKR_CFG interface ------------------------------*/
void taskr_cfg_init(TASKR_CFG *taskr_cfg)
{
    TASKR_CFG_MASKR(taskr_cfg)      = CMPI_ERROR_MASK;
    TASKR_CFG_DES_TCID(taskr_cfg)   = CMPI_ERROR_TCID;
    TASKR_CFG_NEXT_TCID(taskr_cfg)  = CMPI_ERROR_TCID;

    return;
}

void taskr_cfg_clean(TASKR_CFG *taskr_cfg)
{
    TASKR_CFG_MASKR(taskr_cfg)      = CMPI_ERROR_MASK;
    TASKR_CFG_DES_TCID(taskr_cfg)   = CMPI_ERROR_TCID;
    TASKR_CFG_NEXT_TCID(taskr_cfg)  = CMPI_ERROR_TCID;

    return;
}

TASKR_CFG * taskr_cfg_new()
{
    TASKR_CFG *taskr_cfg;

    alloc_static_mem(MM_TASKR_CFG, &taskr_cfg, LOC_TASKCFG_0011);
    if(NULL_PTR == taskr_cfg)
    {
        dbg_log(SEC_0019_TASKCFG, 0)(LOGSTDOUT, "error:taskr_cfg_new: failed to alloc TASKR_CFG\n");
        return (NULL_PTR);
    }

    taskr_cfg_init(taskr_cfg);

    return (taskr_cfg);
}

void taskr_cfg_free(TASKR_CFG *taskr_cfg)
{
    taskr_cfg_clean(taskr_cfg);
    free_static_mem(MM_TASKR_CFG, taskr_cfg, LOC_TASKCFG_0012);
    return;
}

EC_BOOL taskr_cfg_clone(const TASKR_CFG *src_taskr_cfg, TASKR_CFG *des_taskr_cfg)
{
    TASKR_CFG_MASKR(des_taskr_cfg)     = TASKR_CFG_MASKR(src_taskr_cfg);
    TASKR_CFG_DES_TCID(des_taskr_cfg)  = TASKR_CFG_DES_TCID(src_taskr_cfg);
    TASKR_CFG_NEXT_TCID(des_taskr_cfg) = TASKR_CFG_NEXT_TCID(src_taskr_cfg);
    return (EC_TRUE);
}

EC_BOOL taskr_cfg_cmp(const TASKR_CFG *taskr_cfg_1st, const TASKR_CFG *taskr_cfg_2nd)
{
    if(CMPI_ANY_TCID != TASKR_CFG_DES_TCID(taskr_cfg_1st)
    && CMPI_ANY_TCID != TASKR_CFG_DES_TCID(taskr_cfg_2nd)
    && TASKR_CFG_DES_TCID(taskr_cfg_1st) != TASKR_CFG_DES_TCID(taskr_cfg_2nd))
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_MASK != TASKR_CFG_MASKR(taskr_cfg_1st)
    && CMPI_ANY_MASK != TASKR_CFG_MASKR(taskr_cfg_2nd)
    && TASKR_CFG_MASKR(taskr_cfg_1st) != TASKR_CFG_MASKR(taskr_cfg_2nd))
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_TCID != TASKR_CFG_NEXT_TCID(taskr_cfg_1st)
    && CMPI_ANY_TCID != TASKR_CFG_NEXT_TCID(taskr_cfg_2nd)
    && TASKR_CFG_NEXT_TCID(taskr_cfg_1st) != TASKR_CFG_NEXT_TCID(taskr_cfg_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL taskr_cfg_set(TASKR_CFG *taskr_cfg, const UINT32 des_tcid, const UINT32 maskr, const UINT32 next_tcid)
{
    TASKR_CFG_DES_TCID(taskr_cfg) = des_tcid;
    TASKR_CFG_MASKR(taskr_cfg)    = maskr;
    TASKR_CFG_NEXT_TCID(taskr_cfg)= next_tcid;

    return (EC_TRUE);
}

void taskr_cfg_print(LOG *log, const TASKR_CFG *taskr_cfg)
{
    sys_log(log, "taskr_cfg %lx:  des_tcid = %s, maskr = %s, next_tcid = %s\n",
                    taskr_cfg,
                    TASKR_CFG_DES_TCID_STR(taskr_cfg),
                    TASKR_CFG_MASKR_STR(taskr_cfg),
                    TASKR_CFG_NEXT_TCID_STR(taskr_cfg));
    return;
}

void taskr_cfg_print_xml(LOG *log, const TASKR_CFG *taskr_cfg, const UINT32 level)
{
    taskx_cfg_ident_print_xml(log, level);
    sys_print(log, "<taskr des_tcid=\"%s\" maskr=\"%s\" next_tcid=\"%s\"/>\n",
                    TASKR_CFG_DES_TCID_STR(taskr_cfg),
                    TASKR_CFG_MASKR_STR(taskr_cfg),
                    TASKR_CFG_NEXT_TCID_STR(taskr_cfg)
            );
    return;
}


/*------------------------------ TASK_CFG interface ------------------------------*/

void task_cfg_init(TASK_CFG *task_cfg)
{
    TASK_CFG_DEFAULT_TASKS_PORT(task_cfg) = CMPI_ERROR_SRVPORT;
    cvector_init(TASK_CFG_TASKS_CFG_VEC(task_cfg), 0, MM_TASKS_CFG, CVECTOR_LOCK_ENABLE, LOC_TASKCFG_0013);
    return;
}

void task_cfg_clean(TASK_CFG *task_cfg)
{
    TASK_CFG_DEFAULT_TASKS_PORT(task_cfg) = CMPI_ERROR_SRVPORT;
    cvector_clean(TASK_CFG_TASKS_CFG_VEC(task_cfg), (CVECTOR_DATA_CLEANER)tasks_cfg_free, LOC_TASKCFG_0014);
    return;
}

TASK_CFG * task_cfg_new()
{
    TASK_CFG *task_cfg;

    alloc_static_mem(MM_TASK_CFG, &task_cfg, LOC_TASKCFG_0015);
    if(NULL_PTR == task_cfg)
    {
        dbg_log(SEC_0019_TASKCFG, 0)(LOGSTDOUT, "error:task_cfg_new: failed to alloc TASK_CFG\n");
        return (NULL_PTR);
    }

    task_cfg_init(task_cfg);
    return (task_cfg);
}

void task_cfg_free(TASK_CFG *task_cfg)
{
    task_cfg_clean(task_cfg);
    free_static_mem(MM_TASK_CFG, task_cfg, LOC_TASKCFG_0016);
    return;
}

EC_BOOL task_cfg_clone(const TASK_CFG *src_task_cfg, TASK_CFG *des_task_cfg)
{
    cvector_clone(TASK_CFG_TASKS_CFG_VEC(src_task_cfg),
                  TASK_CFG_TASKS_CFG_VEC(des_task_cfg),
                  (CVECTOR_DATA_MALLOC)tasks_cfg_new,
                  (CVECTOR_DATA_CLONE)tasks_cfg_clone);
    return (EC_TRUE);
}

EC_BOOL task_cfg_filter(const TASK_CFG *src_task_cfg, const UINT32 tcid, TASK_CFG *des_task_cfg)
{
    TASKS_CFG *filtered_tasks_cfg;
    UINT32 pos;

    /*note: here should ensure only one tasks cfg with tcid in the whole src_task_cfg*/
    /*which means it is un-acceptable if have two tasks cfg with same tcid but different mask*/
    filtered_tasks_cfg = task_cfg_searchs(src_task_cfg, tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == filtered_tasks_cfg)
    {
        return (EC_TRUE);
    }

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(src_task_cfg), LOC_TASKCFG_0017);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(src_task_cfg)); pos ++)
    {
        TASKS_CFG *tasks_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(src_task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        /*clone tasks_cfg when filtered_tasks_cfg belongs to the intranet or lanmet or extrannet of it*/
        if(EC_TRUE == tasks_cfg_is_intranet(tasks_cfg, filtered_tasks_cfg)/*whether filtered_tasks_cfg belong to intranet of tasks_cfg*/
        || EC_TRUE == tasks_cfg_is_externet(tasks_cfg, filtered_tasks_cfg)/*whether filtered_tasks_cfg belong to extranet of tasks_cfg*/
        || EC_TRUE == tasks_cfg_is_lannet(tasks_cfg, filtered_tasks_cfg)  /*whether filtered_tasks_cfg belong to lannet   of tasks_cfg*/
        || EC_TRUE == tasks_cfg_is_dbgnet(tasks_cfg, filtered_tasks_cfg)
        || EC_TRUE == tasks_cfg_is_monnet(tasks_cfg, filtered_tasks_cfg)
        )
        {
            TASKS_CFG *cloned_tasks_cfg;

            cloned_tasks_cfg = tasks_cfg_new();
            if(NULL_PTR == cloned_tasks_cfg)
            {
                dbg_log(SEC_0019_TASKCFG, 0)(LOGSTDOUT, "error:task_cfg_filter: failed to new tasks cfg\n");
                CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(src_task_cfg), LOC_TASKCFG_0018);
                return (EC_FALSE);
            }

            tasks_cfg_clone(tasks_cfg, cloned_tasks_cfg);
            cvector_push(TASK_CFG_TASKS_CFG_VEC(des_task_cfg), (void *)cloned_tasks_cfg);
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(src_task_cfg), LOC_TASKCFG_0019);
    return (EC_TRUE);
}

UINT32 task_cfg_default_csrv_port(const TASK_CFG *task_cfg)
{
    return TASK_CFG_DEFAULT_TASKS_PORT(task_cfg);
}

EC_BOOL task_cfg_check_all(const TASK_CFG *task_cfg)
{
    UINT32 pos;

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0020);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *tasks_cfg;
        TASK_CFG  *des_task_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        dbg_log(SEC_0019_TASKCFG, 5)(LOGSTDOUT, "--------------------------------- check tcid %s, maski %s, maske %s -------------------------------------\n",
                    TASKS_CFG_TCID_STR(tasks_cfg),
                    TASKS_CFG_MASKI_STR(tasks_cfg),
                    TASKS_CFG_MASKE_STR(tasks_cfg)
                    );

        des_task_cfg = task_cfg_new();
        task_cfg_filter(task_cfg, TASKS_CFG_TCID(tasks_cfg), des_task_cfg);
        task_cfg_print_xml(LOGSTDOUT, des_task_cfg, 0);
        task_cfg_free(des_task_cfg);
    }

    return (EC_TRUE);
}

TASKS_CFG *task_cfg_searchs(const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske)
{
    UINT32 pos;

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0021);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *tasks_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        if(EC_TRUE == tasks_cfg_is_matched(tasks_cfg, tcid, maski, maske, CMPI_ANY_IPADDR, CMPI_ANY_SRVPORT))
        {
            CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0022);
            return (tasks_cfg);
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0023);
    return (NULL_PTR);
}

TASKS_CFG *task_cfg_searchs_by_ip(const TASK_CFG *task_cfg, const UINT32 ipaddr, const UINT32 port)
{
    UINT32 pos;

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0024);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *tasks_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        if(EC_TRUE == tasks_cfg_match_ip(tasks_cfg, ipaddr, port))
        {
            CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0025);
            return (tasks_cfg);
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0026);
    return (NULL_PTR);
}

TASKS_CFG *task_cfg_searchs_by_netcards(const TASK_CFG *task_cfg, const CSET *cnetcard_set)
{
    UINT32 pos;

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0027);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *tasks_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        if(EC_TRUE == tasks_cfg_match_netcards(tasks_cfg, cnetcard_set))
        {
            CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0028);
            return (tasks_cfg);
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0029);
    return (NULL_PTR);
}

TASKS_CFG *task_cfg_searchs_by_csrv(const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 csrvport)
{
    UINT32 pos;

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0030);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *tasks_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        if(EC_TRUE == tasks_cfg_match_csrv(tasks_cfg, tcid, csrvport))
        {
            CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0031);
            return (tasks_cfg);
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0032);
    return (NULL_PTR);
}

void task_cfg_print(LOG *log, const TASK_CFG *task_cfg)
{
    sys_log(log, "task_cfg %lx:\n", task_cfg);
    cvector_print(log, TASK_CFG_TASKS_CFG_VEC(task_cfg), (CVECTOR_DATA_PRINT)tasks_cfg_print);
    return;
}

STATIC_CAST static void task_cfg_head_print_xml(LOG *log, const TASK_CFG *task_cfg, const UINT32 level)
{
    sys_print(log, "<taskConfig");

    if(CMPI_ERROR_SRVPORT != TASK_CFG_DEFAULT_TASKS_PORT(task_cfg))
    {
        sys_print(log, " deftasksport=\"%ld\"", TASK_CFG_DEFAULT_TASKS_PORT(task_cfg));
    }
    sys_print(log, ">\n");
    return;
}

void task_cfg_print_xml(LOG *log, const TASK_CFG *task_cfg, const UINT32 level)
{
    UINT32 num;
    UINT32 pos;

    num = cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg));
    if(0 == num)
    {
        return;
    }

    taskx_cfg_ident_print_xml(log, level);
    task_cfg_head_print_xml(log, task_cfg, level);

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0033);
    for(pos = 0; pos < num; pos ++)
    {
        TASKS_CFG *tasks_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        tasks_cfg_print_xml(log, tasks_cfg, level + 1);
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFG_0034);

    taskx_cfg_ident_print_xml(log, level);
    sys_print(log, "</taskConfig>\n");
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


