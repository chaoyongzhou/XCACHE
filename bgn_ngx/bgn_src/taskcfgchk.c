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

#include "type.h"
#include "log.h"

#include "clist.h"
#include "cset.h"
#include "cstring.h"
#include "cmisc.h"
#include "cxml.h"

#include "csocket.h"

#include "taskcfg.inc"
#include "taskcfg.h"
#include "tasks.h"
#include "task.h"

#include "cmpic.inc"

#include "crouter.h"
#include "taskcfgchk.h"

STATIC_CAST static EC_BOOL taskcfgchk_conn_test(const TASK_CFG *task_cfg, const TASKS_CFG *local_tasks_cfg, const UINT32 remote_tcid);
STATIC_CAST static EC_BOOL taskcfgchk_route_test(LOG *log, const TASK_CFG *task_cfg, TASKS_CFG *src_tasks_cfg, const UINT32 des_tcid, const UINT32 max_hops);

EC_BOOL taskcfgchk_net_print(LOG *log, const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske)
{
    TASKS_CFG *local_tasks_cfg;
    UINT32 pos;

    local_tasks_cfg = task_cfg_searchs(task_cfg, tcid, maski, maske);
    if(NULL_PTR == local_tasks_cfg)
    {
        sys_log(log, "error:taskcfgchk_net_print: no tasks cfg for tcid %s maski %s, maske %s\n",
                        c_word_to_ipv4(tcid), c_word_to_ipv4(maski), c_word_to_ipv4(maske));
        return (EC_FALSE);
    }

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0001);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *remote_tasks_cfg;

        remote_tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == remote_tasks_cfg)
        {
            continue;
        }

        if(EC_TRUE == tasks_cfg_is_intranet(local_tasks_cfg, remote_tasks_cfg))
        {
            sys_log(log, "[TASKCFGCHK][I]tcid = %s, maski = %s, maske = %s, srvipaddr = %s, srvport = %ld\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        }
        if(EC_TRUE == tasks_cfg_is_externet(local_tasks_cfg, remote_tasks_cfg))
        {
            sys_log(log, "[TASKCFGCHK][E]tcid = %s, maski = %s, maske = %s, srvipaddr = %s, srvport = %ld\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        }
        if(EC_TRUE == tasks_cfg_is_lannet(local_tasks_cfg, remote_tasks_cfg))
        {
            sys_log(log, "[TASKCFGCHK][L]tcid = %s, maski = %s, maske = %s, srvipaddr = %s, srvport = %ld\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        }

        if(EC_TRUE == tasks_cfg_is_dbgnet(local_tasks_cfg, remote_tasks_cfg))
        {
            sys_log(log, "[TASKCFGCHK][D]tcid = %s, maski = %s, maske = %s, srvipaddr = %s, srvport = %ld\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        }

        if(EC_TRUE == tasks_cfg_is_monnet(local_tasks_cfg, remote_tasks_cfg))
        {
            sys_log(log, "[TASKCFGCHK][D]tcid = %s, maski = %s, maske = %s, srvipaddr = %s, srvport = %ld\n",
                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVIPADDR_STR(remote_tasks_cfg),
                            TASKS_CFG_SRVPORT(remote_tasks_cfg));
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0002);
    return (EC_TRUE);
}

EC_BOOL taskcfgchk_route_print(LOG *log, const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske)
{
    TASKS_CFG *tasks_cfg;
    UINT32 pos;

    tasks_cfg = task_cfg_searchs(task_cfg, tcid, maski, maske);
    if(NULL_PTR == tasks_cfg)
    {
        sys_log(log, "error:taskcfgchk_route_print: no tasks cfg for tcid %s maski %s, maske %s\n",
                        c_word_to_ipv4(tcid), c_word_to_ipv4(maski), c_word_to_ipv4(maske));
        return (EC_FALSE);
    }

    CVECTOR_LOCK(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), LOC_TASKCFGCHK_0003);
    for(pos = 0; pos < cvector_size(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg)); pos ++)
    {
        TASKR_CFG *taskr_cfg;

        taskr_cfg = (TASKR_CFG *)cvector_get_no_lock(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), pos);
        if(NULL_PTR == taskr_cfg)
        {
            continue;
        }

        sys_log(log, "[TASKCFGCHK] route No. %ld: des_tcid = %s, maskr = %s, next_tcid = %s\n", pos,
                    TASKR_CFG_DES_TCID_STR(taskr_cfg),
                    TASKR_CFG_MASKR_STR(taskr_cfg),
                    TASKR_CFG_NEXT_TCID_STR(taskr_cfg));
    }
    CVECTOR_UNLOCK(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), LOC_TASKCFGCHK_0004);

    return (EC_TRUE);
}

EC_BOOL taskcfgchk_conn_print(LOG *log, const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske, const UINT32 remote_tcid)
{
    TASKS_CFG *local_tasks_cfg;
    UINT32 pos;

    local_tasks_cfg = task_cfg_searchs(task_cfg, tcid, maski, maske);
    if(NULL_PTR == local_tasks_cfg)
    {
        sys_log(log, "error:taskcfgchk_conn_print: no tasks cfg for tcid %s maski %s, maske %s\n",
                        c_word_to_ipv4(tcid), c_word_to_ipv4(maski), c_word_to_ipv4(maske));
        return (EC_FALSE);
    }

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0005);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *remote_tasks_cfg;

        remote_tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == remote_tasks_cfg)
        {
            continue;
        }

        if(
           (remote_tcid == TASKS_CFG_TCID(remote_tasks_cfg))
        &&
            (
               EC_TRUE == tasks_cfg_is_intranet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_externet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_lannet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_dbgnet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_monnet(local_tasks_cfg, remote_tasks_cfg)
            )
        )
        {
            sys_log(log, "[TASKCFGCHK] tcid %s maski %s maske %s --> tcid %s maski %s maske %s\n",
                            TASKS_CFG_TCID_STR(local_tasks_cfg),
                            TASKS_CFG_MASKI_STR(local_tasks_cfg),
                            TASKS_CFG_MASKE_STR(local_tasks_cfg),

                            TASKS_CFG_TCID_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKI_STR(remote_tasks_cfg),
                            TASKS_CFG_MASKE_STR(remote_tasks_cfg)
                            );
            CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0006);
            return (EC_TRUE);
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0007);
    return (EC_FALSE);
}


STATIC_CAST static EC_BOOL taskcfgchk_conn_test(const TASK_CFG *task_cfg, const TASKS_CFG *local_tasks_cfg, const UINT32 remote_tcid)
{
    UINT32 pos;

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0008);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *remote_tasks_cfg;

        remote_tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == remote_tasks_cfg)
        {
            continue;
        }

        if(
           (remote_tcid == TASKS_CFG_TCID(remote_tasks_cfg))
        &&
            (
               EC_TRUE == tasks_cfg_is_intranet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_externet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_lannet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_dbgnet(local_tasks_cfg, remote_tasks_cfg)
            || EC_TRUE == tasks_cfg_is_monnet(local_tasks_cfg, remote_tasks_cfg)
            )
        )
        {
            CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0009);
            return (EC_TRUE);
        }
    }
    CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0010);
    return (EC_FALSE);
}


STATIC_CAST static EC_BOOL taskcfgchk_route_test(LOG *log, const TASK_CFG *task_cfg, TASKS_CFG *src_tasks_cfg, const UINT32 des_tcid, const UINT32 max_hops)
{
    UINT32 pos;

    if(EC_TRUE == taskcfgchk_conn_test(task_cfg, src_tasks_cfg, des_tcid))
    {
        sys_log(log, "[TASKCFGCHK] %s ==> %s [SUCC]\n", TASKS_CFG_TCID_STR(src_tasks_cfg), c_word_to_ipv4(des_tcid));
        return (EC_TRUE);
    }

    if(0 == max_hops)
    {
        sys_log(log, "[TASKCFGCHK] ==> %s [STOP]\n", TASKS_CFG_TCID_STR(src_tasks_cfg));
        return (EC_FALSE);
    }

    CVECTOR_LOCK(TASKS_CFG_TASKR_CFG_VEC(src_tasks_cfg), LOC_TASKCFGCHK_0011);
    for(pos = 0; pos < cvector_size(TASKS_CFG_TASKR_CFG_VEC(src_tasks_cfg)); pos ++)
    {
        TASKR_CFG *taskr_cfg;
        UINT32 taskr_cfg_mask;

        taskr_cfg = (TASKR_CFG *)cvector_get_no_lock(TASKS_CFG_TASKR_CFG_VEC(src_tasks_cfg), pos);
        if(NULL_PTR == taskr_cfg)
        {
            continue;
        }

        taskr_cfg_mask = TASKR_CFG_MASKR(taskr_cfg);

        /*when des_tcid belong to the intranet of taskr_cfg, i.e., belong to the route*/
        if((des_tcid & taskr_cfg_mask) == (TASKR_CFG_DES_TCID(taskr_cfg) & taskr_cfg_mask))
        {
            TASKS_CFG *rt_tasks_cfg;

            dbg_log(SEC_0057_TASKCFGCHK, 5)(LOGSTDNULL, "[TASKCFGCHK] %s & %s == %s & %s\n",
                            c_word_to_ipv4(des_tcid), c_word_to_ipv4(taskr_cfg_mask),
                            TASKR_CFG_DES_TCID_STR(taskr_cfg), c_word_to_ipv4(taskr_cfg_mask)
                            );

            rt_tasks_cfg = task_cfg_searchs(task_cfg, TASKR_CFG_NEXT_TCID(taskr_cfg), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == rt_tasks_cfg)
            {
                continue;
            }

            sys_log(log, "[TASKCFGCHK] %s ==> %s\n", TASKS_CFG_TCID_STR(src_tasks_cfg), TASKR_CFG_NEXT_TCID_STR(taskr_cfg));

            CVECTOR_UNLOCK(TASKS_CFG_TASKR_CFG_VEC(src_tasks_cfg), LOC_TASKCFGCHK_0012);
            if(EC_TRUE == taskcfgchk_route_test(log, task_cfg, rt_tasks_cfg, des_tcid, max_hops - 1))/*recursively*/
            {
                return (EC_TRUE);
            }
            CVECTOR_LOCK(TASKS_CFG_TASKR_CFG_VEC(src_tasks_cfg), LOC_TASKCFGCHK_0013);
        }
        else
        {
            dbg_log(SEC_0057_TASKCFGCHK, 5)(LOGSTDNULL, "[TASKCFGCHK] %s & %s != %s & %s\n",
                            c_word_to_ipv4(des_tcid), c_word_to_ipv4(taskr_cfg_mask),
                            TASKR_CFG_DES_TCID_STR(taskr_cfg), c_word_to_ipv4(taskr_cfg_mask)
                            );
        }
    }
    CVECTOR_UNLOCK(TASKS_CFG_TASKR_CFG_VEC(src_tasks_cfg), LOC_TASKCFGCHK_0014);
    return (EC_FALSE);
}

EC_BOOL taskcfgchk_route_trace(LOG *log, const TASK_CFG *task_cfg, const UINT32 src_tcid, const UINT32 src_maski, const UINT32 src_maske, const UINT32 des_tcid, const UINT32 max_hops)
{
    TASKS_CFG *src_tasks_cfg;

    src_tasks_cfg = task_cfg_searchs(task_cfg, src_tcid, src_maski, src_maske);
    if(NULL_PTR == src_tasks_cfg)
    {
        sys_log(log, "error:taskcfgchk_route_trace: no tasks cfg for src tcid %s maski %s, maske %s\n",
                        c_word_to_ipv4(src_tcid), c_word_to_ipv4(src_maski), c_word_to_ipv4(src_maske));
        return (EC_FALSE);
    }

    if(EC_FALSE == taskcfgchk_route_test(log, task_cfg, src_tasks_cfg, des_tcid, max_hops))
    {
        sys_log(log, "[TASKCFGCHK] ==> %s [FAIL]\n", c_word_to_ipv4(des_tcid));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL taskcfgchk_net_all(LOG *log, const TASK_CFG *task_cfg)
{
    UINT32 pos;

    CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_TASKCFGCHK_0015);
    for(pos = 0; pos < cvector_size(TASK_CFG_TASKS_CFG_VEC(task_cfg)); pos ++)
    {
        TASKS_CFG *tasks_cfg;
        TASK_CFG  *des_task_cfg;

        tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), pos);
        if(NULL_PTR == tasks_cfg)
        {
            continue;
        }

        sys_log(log, "[TASKCFGCHK] ------------------------------ check tcid %s, maski %s, maske %s ----------------------------------\n",
                    TASKS_CFG_TCID_STR(tasks_cfg),
                    TASKS_CFG_MASKI_STR(tasks_cfg),
                    TASKS_CFG_MASKE_STR(tasks_cfg)
                    );

        des_task_cfg = task_cfg_new();
        task_cfg_filter(task_cfg, TASKS_CFG_TCID(tasks_cfg), des_task_cfg);
        task_cfg_print_xml(log, des_task_cfg, 0);
        task_cfg_free(des_task_cfg);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

