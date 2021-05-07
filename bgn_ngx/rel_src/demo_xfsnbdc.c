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
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "type.h"
#include "mm.h"
#include "cmisc.h"
#include "task.h"
#include "mod.h"
#include "log.h"
#include "debug.h"
#include "rank.h"

#include "cstring.h"

#include "cmpic.inc"
#include "findex.inc"

#include "cxfsc.h"
#include "cxfsnbdc.h"

static CSTRING  *g_device_name = NULL_PTR; /* e.g., "/dev/nbd0" */
static CSTRING  *g_bucket_name = NULL_PTR; /* e.g., "/tmp/nbd0.dsk" */


/*parse args for cxfs*/
EC_BOOL __test_cxfsnbdc_parse_args(int argc, char **argv)
{
    int idx;

    for(idx = 0; idx < argc; idx ++)
    {
        if(0 == strcasecmp(argv[idx], "-bucket") && idx + 1 < argc)
        {
            g_bucket_name = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            ASSERT(NULL_PTR != g_bucket_name);
            continue;
        }

        if(0 == strcasecmp(argv[idx], "-device") && idx + 1 < argc)
        {
            g_device_name = cstring_new((UINT8 *)argv[idx + 1], LOC_NONE_BASE);
            ASSERT(NULL_PTR != g_device_name);
            continue;
        }
    }

     return (EC_FALSE);
}

EC_BOOL __test_cxfsnbdc_runner()
{
    UINT32      cxfsc_tcid;
    UINT32      cxfsc_modi;

    UINT32      cxfsnbdc_modi;
    MOD_NODE    recv_mod_node;

    cxfsc_tcid = CMPI_LOCAL_TCID;
    cxfsc_modi = cxfsc_start();
    ASSERT(CMPI_ERROR_MODI != cxfsc_modi);

    if(EC_FALSE == cxfsc_reg_xfs(cxfsc_modi))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfsnbdc_runner: reg xfs failed\n");
        task_brd_default_abort();
    }

    cxfsnbdc_modi = cxfsnbdc_start(g_device_name,
                                 CXFSNBD_BLOCK_SIZE,
                                 CXFSNBD_DEVICE_SIZE,
                                 CXFSNBD_TIMEOUT_NSEC,
                                 g_bucket_name,
                                 cxfsc_tcid,
                                 cxfsc_modi);

    ASSERT(CMPI_ERROR_MODI != cxfsnbdc_modi);

    MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&recv_mod_node) = cxfsnbdc_modi;

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_cxfsnbdc_bucket_launch, CMPI_ERROR_MODI);

#if 0
    if(EC_TRUE == cxfsnbdc_bucket_check(cxfsnbdc_modi))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "[DEBUG] __test_cxfsnbdc_runner: check bucket done\n");
        return (EC_TRUE);
    }

    if(EC_TRUE == cxfsnbdc_bucket_create(cxfsnbdc_modi))
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "[DEBUG] __test_cxfsnbdc_runner: create bucket done\n");
        return (EC_TRUE);
    }
    dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:__test_cxfsnbdc_runner: create bucket failed\n");
#endif
    return (EC_FALSE);
}

void __test_cxfsnbdc_launch(void *UNUSED(none))
{
    cthread_new(CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                 (const char *)"__test_cxfsnbdc_runner",
                 (UINT32)__test_cxfsnbdc_runner,
                 (UINT32)0,/*core # (ignore)*/
                 (UINT32)0 /*para num*/
                 );
    return;
}


int main_cxfsnbdc(int argc, char **argv)
{
    task_brd_default_init(argc, argv);

    if(EC_FALSE == task_brd_default_check_validity())
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_cxfsnbdc: validity checking failed\n");
        task_brd_default_abort();
        return (-1);
    }

    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_cxfsnbdc: __test_cxfsnbdc_parse_args beg\n");
    __test_cxfsnbdc_parse_args(argc, argv);
    dbg_log(SEC_0137_DEMO, 9)(LOGSTDOUT, "[DEBUG] main_cxfsnbdc: __test_cxfsnbdc_parse_args end\n");

    if(NULL_PTR == g_device_name)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_cxfsnbdc: no device name\n");
        task_brd_default_abort();
        return (-1);
    }

    if(NULL_PTR == g_bucket_name)
    {
        dbg_log(SEC_0137_DEMO, 0)(LOGSTDOUT, "error:main_cxfsnbdc: no bucket name\n");
        task_brd_default_abort();
        return (-1);
    }

    task_brd_default_fork_runner(CMPI_ANY_TCID, CMPI_ANY_RANK, (const char *)"__test_cxfsnbdc_runner",
                                (TASK_RUNNER_FUNC)__test_cxfsnbdc_runner, NULL_PTR);

    /*start the defined runner on current (tcid, rank)*/
    task_brd_default_start_runner();

    return (0);
}

int main(int argc, char **argv)
{
    return main_cxfsnbdc(argc, argv);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

