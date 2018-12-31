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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "carray.h"
#include "cvector.h"

#include "cbc.h"
#include "ctimer.h"
#include "cbtimer.h"
#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "crb.h"
#include "chttp.h"
#include "cxfshttp.h"
#include "cxfsmon.h"
#include "cxfsconhash.h"

#include "cload.h"

#include "findex.inc"

static UINT32   g_cxfsmon_xfs_node_pos = 0;

#define CXFSMON_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFSMON))

#define CXFSMON_MD_GET(cxfsmon_md_id)     ((CXFSMON_MD *)cbc_md_get(MD_CXFSMON, (cxfsmon_md_id)))

#define CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id)  \
    ((CMPI_ANY_MODI != (cxfsmon_md_id)) && ((NULL_PTR == CXFSMON_MD_GET(cxfsmon_md_id)) || (0 == (CXFSMON_MD_GET(cxfsmon_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CXFSMON Module
*
**/
void cxfsmon_print_module_status(const UINT32 cxfsmon_md_id, LOG *log)
{
    CXFSMON_MD *cxfsmon_md;
    UINT32 this_cxfsmon_md_id;

    for( this_cxfsmon_md_id = 0; this_cxfsmon_md_id < CXFSMON_MD_CAPACITY(); this_cxfsmon_md_id ++ )
    {
        cxfsmon_md = CXFSMON_MD_GET(this_cxfsmon_md_id);

        if ( NULL_PTR != cxfsmon_md && 0 < cxfsmon_md->usedcounter )
        {
            sys_log(log,"CXFSMON Module # %ld : %ld refered\n",
                    this_cxfsmon_md_id,
                    cxfsmon_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CXFSMON module
*
*
**/
UINT32 cxfsmon_free_module_static_mem(const UINT32 cxfsmon_md_id)
{
    //CXFSMON_MD  *cxfsmon_md;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_free_module_static_mem: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CXFSMON_DEBUG_SWITCH*/

    //cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    free_module_static_mem(MD_CXFSMON, cxfsmon_md_id);

    return 0;
}

/**
*
* start CXFSMON module
*
**/
UINT32 cxfsmon_start()
{
    CXFSMON_MD *cxfsmon_md;
    UINT32      cxfsmon_md_id;

    TASK_BRD   *task_brd;

    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CXFSMON , 32);

    cxfsmon_md_id = cbc_md_new(MD_CXFSMON, sizeof(CXFSMON_MD));
    if(CMPI_ERROR_MODI == cxfsmon_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CXFSMON module */
    cxfsmon_md = (CXFSMON_MD *)cbc_md_get(MD_CXFSMON, cxfsmon_md_id);
    cxfsmon_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /*initialize CXFS_NODE vector*/
    cvector_init(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), 16, MM_CXFS_NODE, CVECTOR_LOCK_DISABLE, LOC_CXFSMON_0001);

    if(SWITCH_ON == CXFSMON_CONHASH_SWITCH)
    {
        CXFSMON_MD_CXFSCONHASH(cxfsmon_md) = cxfsconhash_new(CXFSMON_CONHASH_DEFAULT_HASH_ALGO);
    }
    else
    {
        CXFSMON_MD_CXFSCONHASH(cxfsmon_md) = NULL_PTR;
    }

    CXFSMON_MD_HOT_PATH_HASH_FUNC(cxfsmon_md) = chash_algo_fetch(CXFSMON_HOT_PATH_HASH_ALGO);

    /*initialize HOT PATH RB TREE*/
    crb_tree_init(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md),
                    (CRB_DATA_CMP)cxfs_hot_path_cmp,
                    (CRB_DATA_FREE)cxfs_hot_path_free,
                    (CRB_DATA_PRINT)cxfs_hot_path_print);

    cxfsmon_md->usedcounter = 1;

    tasks_cfg_push_add_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                       (const char *)"cxfsmon_callback_when_add",
                                       cxfsmon_md_id,
                                       (UINT32)cxfsmon_callback_when_add);

    tasks_cfg_push_del_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                       (const char *)"cxfsmon_callback_when_del",
                                       cxfsmon_md_id,
                                       (UINT32)cxfsmon_callback_when_del);

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfsmon_end, cxfsmon_md_id);

    dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "[DEBUG] cxfsmon_start: start CXFSMON module #%ld\n", cxfsmon_md_id);

    if(SWITCH_ON == CXFSMONHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == cxfsmon_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_start: init cxfshttp defer request queue failed\n");
                cxfsmon_end(cxfsmon_md_id);
                return (CMPI_ERROR_MODI);
            }

            cxfshttp_log_start();
            task_brd_default_bind_http_srv_modi(cxfsmon_md_id);
            /*reuse XFS HTTP*/
            chttp_rest_list_push((const char *)CXFSHTTP_REST_API_NAME, cxfshttp_commit_request);
        }
    }
    return ( cxfsmon_md_id );
}

/**
*
* end CXFSMON module
*
**/
void cxfsmon_end(const UINT32 cxfsmon_md_id)
{
    CXFSMON_MD *cxfsmon_md;

    TASK_BRD   *task_brd;

    task_brd = task_brd_default_get();

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cxfsmon_end, cxfsmon_md_id);

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);
    if(NULL_PTR == cxfsmon_md)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_end: cxfsmon_md_id = %ld not exist.\n", cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cxfsmon_md->usedcounter )
    {
        cxfsmon_md->usedcounter --;
        return ;
    }

    if ( 0 == cxfsmon_md->usedcounter )
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_end: cxfsmon_md_id = %ld is not started.\n", cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }

    cvector_clean(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (CVECTOR_DATA_CLEANER)cxfs_node_free, LOC_CXFSMON_0002);
    if(NULL_PTR != CXFSMON_MD_CXFSCONHASH(cxfsmon_md))
    {
        cxfsconhash_free(CXFSMON_MD_CXFSCONHASH(cxfsmon_md));
        CXFSMON_MD_CXFSCONHASH(cxfsmon_md) = NULL_PTR;
    }

    CXFSMON_MD_HOT_PATH_HASH_FUNC(cxfsmon_md) = NULL_PTR;
    crb_tree_clean(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md));

    tasks_cfg_erase_add_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                      (const char *)"cxfsmon_callback_when_add",
                                      cxfsmon_md_id,
                                      (UINT32)cxfsmon_callback_when_add);

    tasks_cfg_erase_del_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                      (const char *)"cxfsmon_callback_when_del",
                                      cxfsmon_md_id,
                                      (UINT32)cxfsmon_callback_when_del);

    /* free module : */

    cxfsmon_md->usedcounter = 0;

    dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "cxfsmon_end: stop CXFSMON module #%ld\n", cxfsmon_md_id);
    cbc_md_free(MD_CXFSMON, cxfsmon_md_id);

    return ;
}

CXFS_NODE *cxfs_node_new()
{
    CXFS_NODE *cxfs_node;
    alloc_static_mem(MM_CXFS_NODE, &cxfs_node, LOC_CXFSMON_0003);
    if(NULL_PTR != cxfs_node)
    {
        cxfs_node_init(cxfs_node);
    }
    return (cxfs_node);
}

EC_BOOL cxfs_node_init(CXFS_NODE *cxfs_node)
{
    if(NULL_PTR != cxfs_node)
    {
        CXFS_NODE_TCID(cxfs_node)   = CMPI_ERROR_TCID;
        CXFS_NODE_IPADDR(cxfs_node) = CMPI_ERROR_IPADDR;
        CXFS_NODE_PORT(cxfs_node)   = CMPI_ERROR_SRVPORT;
        CXFS_NODE_MODI(cxfs_node)   = CMPI_ERROR_MODI;
        CXFS_NODE_STATE(cxfs_node)  = CXFS_NODE_IS_ERR;

    }
    return (EC_TRUE);
}

EC_BOOL cxfs_node_clean(CXFS_NODE *cxfs_node)
{
    if(NULL_PTR != cxfs_node)
    {
        CXFS_NODE_TCID(cxfs_node)   = CMPI_ERROR_TCID;
        CXFS_NODE_IPADDR(cxfs_node) = CMPI_ERROR_IPADDR;
        CXFS_NODE_PORT(cxfs_node)   = CMPI_ERROR_SRVPORT;
        CXFS_NODE_MODI(cxfs_node)   = CMPI_ERROR_MODI;
        CXFS_NODE_STATE(cxfs_node)  = CXFS_NODE_IS_ERR;

    }
    return (EC_TRUE);
}

EC_BOOL cxfs_node_free(CXFS_NODE *cxfs_node)
{
    if(NULL_PTR != cxfs_node)
    {
        cxfs_node_clean(cxfs_node);
        free_static_mem(MM_CXFS_NODE, cxfs_node, LOC_CXFSMON_0004);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_node_clone(const CXFS_NODE *cxfs_node_src, CXFS_NODE *cxfs_node_des)
{
    if(NULL_PTR != cxfs_node_src && NULL_PTR != cxfs_node_des)
    {
        CXFS_NODE_TCID(cxfs_node_des)   = CXFS_NODE_TCID(cxfs_node_src);
        CXFS_NODE_IPADDR(cxfs_node_des) = CXFS_NODE_IPADDR(cxfs_node_src);
        CXFS_NODE_PORT(cxfs_node_des)   = CXFS_NODE_PORT(cxfs_node_src);
        CXFS_NODE_MODI(cxfs_node_des)   = CXFS_NODE_MODI(cxfs_node_src);
        CXFS_NODE_STATE(cxfs_node_des)  = CXFS_NODE_STATE(cxfs_node_src);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_node_is_up(const CXFS_NODE *cxfs_node)
{
    if(CXFS_NODE_IS_UP == CXFS_NODE_STATE(cxfs_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfs_node_is_valid(const CXFS_NODE *cxfs_node)
{
    if(CMPI_ERROR_TCID == CXFS_NODE_TCID(cxfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_IPADDR == CXFS_NODE_IPADDR(cxfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_SRVPORT == CXFS_NODE_PORT(cxfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CXFS_NODE_MODI(cxfs_node))
    {
        return (EC_FALSE);
    }

    if(CXFS_NODE_IS_ERR == CXFS_NODE_STATE(cxfs_node))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

int cxfs_node_cmp(const CXFS_NODE *cxfs_node_1st, const CXFS_NODE *cxfs_node_2nd)
{
    if(CXFS_NODE_TCID(cxfs_node_1st) > CXFS_NODE_TCID(cxfs_node_2nd))
    {
        return (1);
    }

    if(CXFS_NODE_TCID(cxfs_node_1st) < CXFS_NODE_TCID(cxfs_node_2nd))
    {
        return (-1);
    }

    if(CXFS_NODE_MODI(cxfs_node_1st) > CXFS_NODE_MODI(cxfs_node_2nd))
    {
        return (1);
    }

    if(CXFS_NODE_MODI(cxfs_node_1st) < CXFS_NODE_MODI(cxfs_node_2nd))
    {
        return (-1);
    }

    return (0);
}

const char *cxfs_node_state(const CXFS_NODE *cxfs_node)
{
    if(CXFS_NODE_IS_UP == CXFS_NODE_STATE(cxfs_node))
    {
        return (const char *)"UP";
    }
    if(CXFS_NODE_IS_DOWN == CXFS_NODE_STATE(cxfs_node))
    {
        return (const char *)"DOWN";
    }

    if(CXFS_NODE_IS_ERR == CXFS_NODE_STATE(cxfs_node))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

void cxfs_node_print(const CXFS_NODE *cxfs_node, LOG *log)
{
    sys_log(log, "cxfs_node_print: cxfs_node %p: tcid %s, srv %s:%ld, modi %ld, state %s\n", cxfs_node,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );
    return;
}

void cxfsmon_cxfs_node_print(const UINT32 cxfsmon_md_id, LOG *log)
{
    CXFSMON_MD *cxfsmon_md;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_print: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    cvector_print(log, CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (CVECTOR_DATA_PRINT)cxfs_node_print);

    return;
}

void cxfsmon_cxfs_node_list(const UINT32 cxfsmon_md_id, CSTRING *cstr)
{
    CXFSMON_MD *cxfsmon_md;
    UINT32      pos;
    UINT32      num;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_list: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    num = cvector_size(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md));
    for(pos = 0; pos < num; pos ++)
    {
        CXFS_NODE *cxfs_node;
        cxfs_node = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
        if(NULL_PTR == cxfs_node)
        {
            cstring_format(cstr, "[%ld/%ld] (null)\n", pos, num);
            continue;
        }

        cstring_format(cstr,
                    "[%ld/%ld] (tcid %s, srv %s:%ld, modi %ld, state %s)\n", pos, num,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );

        dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_node_list: [%ld] cstr:\n%.*s\n", pos,
                    (uint32_t)CSTRING_LEN(cstr), (char *)CSTRING_STR(cstr));

    }

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_node_list: list result:\n%.*s\n",
                    (uint32_t)CSTRING_LEN(cstr), (char *)CSTRING_STR(cstr));
    return;
}

EC_BOOL cxfsmon_cxfs_node_num(const UINT32 cxfsmon_md_id, UINT32 *num)
{
    CXFSMON_MD *cxfsmon_md;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_num: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    (*num) = cvector_size(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md));
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_add(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_t;
    UINT32      pos;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_add: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    /*check validity*/
    if(CMPI_ERROR_TCID == CXFS_NODE_TCID(cxfs_node) || CMPI_ERROR_MODI == CXFS_NODE_MODI(cxfs_node))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "warn:cxfsmon_cxfs_node_add: cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) is invalid\n",
                    cxfs_node,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );
        return (EC_FALSE);
    }

    pos = cvector_search_front(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (const void *)cxfs_node, (CVECTOR_DATA_CMP)cxfs_node_cmp);
    if(CVECTOR_ERR_POS != pos)/*found duplicate*/
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "warn:cxfsmon_cxfs_node_add: found duplicate cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    cxfs_node,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );
        return (EC_TRUE);
    }

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), CXFS_NODE_TCID(cxfs_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_node_add: not searched tasks cfg of tcid %s\n",
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)));
        return (EC_FALSE);
    }

    cxfs_node_t = cxfs_node_new();
    if(NULL_PTR == cxfs_node_t)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_add: new cxfs_node failed before insert cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                cxfs_node,
                c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                CXFS_NODE_MODI(cxfs_node),
                cxfs_node_state(cxfs_node)
                );

        return (EC_FALSE);
    }

    cxfs_node_clone(cxfs_node, cxfs_node_t);

    CXFS_NODE_IPADDR(cxfs_node_t) = TASKS_CFG_SRVIPADDR(tasks_cfg);
    CXFS_NODE_PORT(cxfs_node_t)   = TASKS_CFG_CSRVPORT(tasks_cfg); /*http port*/

    CXFS_NODE_STATE(cxfs_node_t)  = CXFS_NODE_IS_UP;/*when initialization*/

    cvector_push(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (const void *)cxfs_node_t);

    if(NULL_PTR != CXFSMON_MD_CXFSCONHASH(cxfsmon_md))
    {
        if(EC_FALSE ==cxfsconhash_add_node(CXFSMON_MD_CXFSCONHASH(cxfsmon_md),
                                            (uint32_t)CXFS_NODE_TCID(cxfs_node_t),
                                            CXFSMON_CONHASH_REPLICAS))
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                            "error:cxfsmon_cxfs_node_add: add cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) to connhash failed\n",
                            cxfs_node_t,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                            CXFS_NODE_MODI(cxfs_node_t),
                            cxfs_node_state(cxfs_node_t)
                            );

            cvector_pop(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md));
            cxfs_node_free(cxfs_node_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                        "[DEBUG] cxfsmon_cxfs_node_add: add cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) to connhash done\n",
                        cxfs_node_t,
                        c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                        c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                        CXFS_NODE_MODI(cxfs_node_t),
                        cxfs_node_state(cxfs_node_t)
                        );
    }

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] cxfsmon_cxfs_node_add: add cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cxfs_node_t,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                    CXFS_NODE_MODI(cxfs_node_t),
                    cxfs_node_state(cxfs_node_t)
                    );
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_del(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_del: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    pos = cvector_search_front(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (const void *)cxfs_node, (CVECTOR_DATA_CMP)cxfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0206_CXFSMON, 1)(LOGSTDOUT,
                    "warn:cxfsmon_cxfs_node_del: not found cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );
        return (EC_TRUE);
    }

    cxfs_node_t = cvector_erase(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
    if(NULL_PTR == cxfs_node_t)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "warn:cxfsmon_cxfs_node_del: erase cxfs_node is null\n");
        return (EC_TRUE);
    }

    if(NULL_PTR != CXFSMON_MD_CXFSCONHASH(cxfsmon_md))
    {
        if(EC_FALSE ==cxfsconhash_del_node(CXFSMON_MD_CXFSCONHASH(cxfsmon_md),
                                            (uint32_t)CXFS_NODE_TCID(cxfs_node_t))
        )
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                            "error:cxfsmon_cxfs_node_del: del cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) from connhash failed\n",
                            cxfs_node_t,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                            CXFS_NODE_MODI(cxfs_node_t),
                            cxfs_node_state(cxfs_node_t)
                            );
        }
        else
        {
            dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] cxfsmon_cxfs_node_del: del cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) from connhash done\n",
                            cxfs_node_t,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                            CXFS_NODE_MODI(cxfs_node_t),
                            cxfs_node_state(cxfs_node_t)
                            );
        }
    }

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] cxfsmon_cxfs_node_del: erase cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cxfs_node_t,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                    CXFS_NODE_MODI(cxfs_node_t),
                    cxfs_node_state(cxfs_node_t)
                    );

    cxfs_node_free(cxfs_node_t);
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_set_up(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_set_up: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    pos = cvector_search_front(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (const void *)cxfs_node, (CVECTOR_DATA_CMP)cxfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_set_up: not found cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );
        return (EC_FALSE);
    }

    cxfs_node_t = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
    if(NULL_PTR == cxfs_node_t)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_set_up: found cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFSMON_MD_CXFSCONHASH(cxfsmon_md))
    {
        if(EC_FALSE ==cxfsconhash_up_node(CXFSMON_MD_CXFSCONHASH(cxfsmon_md),
                                            (uint32_t)CXFS_NODE_TCID(cxfs_node_t))
        )
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                            "error:cxfsmon_cxfs_node_set_up: set up cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash failed\n",
                            cxfs_node_t,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                            CXFS_NODE_MODI(cxfs_node_t),
                            cxfs_node_state(cxfs_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] cxfsmon_cxfs_node_set_up: set up cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash done\n",
                            cxfs_node_t,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                            CXFS_NODE_MODI(cxfs_node_t),
                            cxfs_node_state(cxfs_node_t)
                            );
        }
    }

    CXFS_NODE_STATE(cxfs_node_t) = CXFS_NODE_IS_UP; /*set up*/

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] cxfsmon_cxfs_node_set_up: set up cxfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cxfs_node_t,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                    CXFS_NODE_MODI(cxfs_node_t),
                    cxfs_node_state(cxfs_node_t)
                    );
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_set_down(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_set_down: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    pos = cvector_search_front(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (const void *)cxfs_node, (CVECTOR_DATA_CMP)cxfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_set_down: not found cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );
        return (EC_FALSE);
    }

    cxfs_node_t = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
    if(NULL_PTR == cxfs_node_t)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_set_down: found cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFSMON_MD_CXFSCONHASH(cxfsmon_md))
    {
        if(EC_FALSE ==cxfsconhash_down_node(CXFSMON_MD_CXFSCONHASH(cxfsmon_md),
                                            (uint32_t)CXFS_NODE_TCID(cxfs_node_t))
        )
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                            "error:cxfsmon_cxfs_node_set_down: set down cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash failed\n",
                            cxfs_node_t,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                            CXFS_NODE_MODI(cxfs_node_t),
                            cxfs_node_state(cxfs_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] cxfsmon_cxfs_node_set_down: set down cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash done\n",
                            cxfs_node_t,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                            CXFS_NODE_MODI(cxfs_node_t),
                            cxfs_node_state(cxfs_node_t)
                            );
        }
    }

    CXFS_NODE_STATE(cxfs_node_t) = CXFS_NODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] cxfsmon_cxfs_node_set_down: set down cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cxfs_node_t,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                    CXFS_NODE_MODI(cxfs_node_t),
                    cxfs_node_state(cxfs_node_t)
                    );
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_is_up(const UINT32 cxfsmon_md_id, const CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_is_up: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    pos = cvector_search_front(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (const void *)cxfs_node, (CVECTOR_DATA_CMP)cxfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_is_up: not found cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node)
                    );
        return (EC_FALSE);
    }

    cxfs_node_t = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
    if(NULL_PTR == cxfs_node_t)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_is_up: found cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                    CXFS_NODE_MODI(cxfs_node),
                    cxfs_node_state(cxfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] cxfsmon_cxfs_node_is_up: check cxfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cxfs_node_t,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                    CXFS_NODE_MODI(cxfs_node_t),
                    cxfs_node_state(cxfs_node_t)
                    );

    if(CXFS_NODE_IS_UP == CXFS_NODE_STATE(cxfs_node_t))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsmon_cxfs_node_get_by_pos(const UINT32 cxfsmon_md_id, const UINT32 pos, CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_t;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_get_by_pos: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_get_by_pos: pos is error\n");
        return (EC_FALSE);
    }

    cxfs_node_t = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
    if(NULL_PTR == cxfs_node_t)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_get_by_pos: found cxfs_node at pos %ld but it is null\n", pos);
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] cxfsmon_cxfs_node_get_by_pos: found cxfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld\n",
                    cxfs_node_t,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                    CXFS_NODE_MODI(cxfs_node_t),
                    cxfs_node_state(cxfs_node_t),
                    pos
                    );

    cxfs_node_clone(cxfs_node_t, cxfs_node);
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_get_by_tcid(const UINT32 cxfsmon_md_id, const UINT32 tcid, const UINT32 modi, CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_searched;
    CXFS_NODE   cxfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_get_by_tcid: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    CXFS_NODE_TCID(&cxfs_node_t) = tcid;
    CXFS_NODE_MODI(&cxfs_node_t) = modi;

    pos = cvector_search_front(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), (const void *)&cxfs_node_t, (CVECTOR_DATA_CMP)cxfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_get_by_tcid: not found cxfs_node with (tcid %s, modi %ld)\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    CXFS_NODE_MODI(cxfs_node)
                    );
        return (EC_FALSE);
    }

    cxfs_node_searched = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
    if(NULL_PTR == cxfs_node_searched)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                    "error:cxfsmon_cxfs_node_get_by_tcid: found cxfs_node with (tcid %s, modi %ld) at pos %ld but it is null\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                    CXFS_NODE_MODI(cxfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] cxfsmon_cxfs_node_get_by_tcid: found cxfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    cxfs_node_searched,
                    c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_searched)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_searched)), CXFS_NODE_PORT(cxfs_node_searched),
                    CXFS_NODE_MODI(cxfs_node_searched),
                    cxfs_node_state(cxfs_node_searched)
                    );

    cxfs_node_clone(cxfs_node_searched, cxfs_node);

    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_get_by_hash(const UINT32 cxfsmon_md_id, const UINT32 hash, CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;
    CXFS_NODE  *cxfs_node_t;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_node_get_by_hash: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    if(NULL_PTR != CXFSMON_MD_CXFSCONHASH(cxfsmon_md))
    {
        CXFSCONHASH_RNODE *cxfsconhash_rnode;

        cxfsconhash_rnode = cxfsconhash_lookup_rnode(CXFSMON_MD_CXFSCONHASH(cxfsmon_md), hash);
        if(NULL_PTR == cxfsconhash_rnode)
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                        "error:cxfsmon_cxfs_node_get_by_hash: lookup rnode in connhash failed where hash %ld\n", hash);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsconhash_rnode_is_up(cxfsconhash_rnode))
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                        "error:cxfsmon_cxfs_node_get_by_hash: found rnode (tcid %s, replicas %u, status %s) in connhash where hash %ld but it is not up \n",
                        c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                        CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                        cxfsconhash_rnode_status(cxfsconhash_rnode),
                        hash);
            return (EC_FALSE);
        }

        return cxfsmon_cxfs_node_get_by_tcid(cxfsmon_md_id, CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode), 0, cxfs_node);
    }
    else
    {
        UINT32      num;
        UINT32      pos;

        num  = cvector_size(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md));

        pos  = (hash % num);

        cxfs_node_t = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);
        if(NULL_PTR == cxfs_node_t)
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT,
                        "error:cxfsmon_cxfs_node_get_by_hash: found cxfs_node at pos %ld but it is null where hash %ld\n", pos, hash);
            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                        "[DEBUG] cxfsmon_cxfs_node_get_by_hash: found cxfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld where hash %ld\n",
                        cxfs_node_t,
                        c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node_t)),
                        c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node_t)), CXFS_NODE_PORT(cxfs_node_t),
                        CXFS_NODE_MODI(cxfs_node_t),
                        cxfs_node_state(cxfs_node_t),
                        pos, hash
                        );

        cxfs_node_clone(cxfs_node_t, cxfs_node);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_get_by_path(const UINT32 cxfsmon_md_id, const uint8_t *path, const uint32_t path_len, CXFS_NODE *cxfs_node)
{
    UINT32      hash;

    hash = c_crc32_short((uint8_t *)path, path_len);

    return cxfsmon_cxfs_node_get_by_hash(cxfsmon_md_id, hash, cxfs_node);
}

EC_BOOL cxfsmon_cxfs_node_set_start_pos(const UINT32 cxfsmon_md_id, const UINT32 start_pos)
{
    g_cxfsmon_xfs_node_pos = start_pos;
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_node_search_up(const UINT32 cxfsmon_md_id, CXFS_NODE *cxfs_node)
{
    CXFSMON_MD *cxfsmon_md;

    UINT32      cxfs_node_num;
    UINT32      cxfs_node_pos;

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    cxfs_node_num = cvector_size(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md));
    if(0 == cxfs_node_num)
    {
        return (EC_FALSE);
    }

    g_cxfsmon_xfs_node_pos = (g_cxfsmon_xfs_node_pos + 1) % cxfs_node_num;

    for(cxfs_node_pos = g_cxfsmon_xfs_node_pos; cxfs_node_pos < cxfs_node_num; cxfs_node_pos ++)
    {
        CXFS_NODE    *cxfs_node_t;

        cxfs_node_t = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), cxfs_node_pos);

        if(NULL_PTR != cxfs_node_t
        && EC_TRUE == cxfs_node_is_up(cxfs_node_t))
        {
            cxfs_node_clone(cxfs_node_t, cxfs_node);
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cxfsmon_cxfs_store_http_srv_get_hot(const UINT32 cxfsmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port)
{
    //CXFSMON_MD *cxfsmon_md;

    CXFS_NODE   cxfs_node;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

    char       *dirname;

    CSTRING     cache_path;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_store_http_srv_get_hot: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    /*hot cache path*/
    dirname = c_dirname((char *)cstring_get_str(path));
    if(NULL_PTR == dirname)
    {
        return (EC_FALSE);
    }

    cstring_set_str(&cache_path, (const UINT8 *)dirname);/*mount only*/

    if(EC_FALSE == cxfsmon_cxfs_hot_path_exist(cxfsmon_md_id, &cache_path))
    {
        safe_free(dirname, LOC_CXFSMON_0005);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsmon_cxfs_node_search_up(cxfsmon_md_id, &cxfs_node))
    {
        safe_free(dirname, LOC_CXFSMON_0006);
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CXFSMON, 6)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_store_http_srv_get_hot: "
                "hot path '%s' => cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                dirname,
                c_word_to_ipv4(CXFS_NODE_TCID(&cxfs_node)),
                c_word_to_ipv4(CXFS_NODE_IPADDR(&cxfs_node)), CXFS_NODE_PORT(&cxfs_node),
                CXFS_NODE_MODI(&cxfs_node),
                cxfs_node_state(&cxfs_node));

    safe_free(dirname, LOC_CXFSMON_0007);

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), CXFS_NODE_TCID(&cxfs_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_store_http_srv_get: not searched tasks cfg of tcid %s\n",
                            c_word_to_ipv4(CXFS_NODE_TCID(&cxfs_node)));
        return (EC_FALSE);
    }

    if(NULL_PTR != tcid)
    {
        (*tcid) = TASKS_CFG_TCID(tasks_cfg);
    }

    if(NULL_PTR != srv_ipaddr)
    {
        (*srv_ipaddr) = TASKS_CFG_SRVIPADDR(tasks_cfg);
    }

    if(NULL_PTR != srv_port)
    {
        (*srv_port) = TASKS_CFG_CSRVPORT(tasks_cfg); /*http port*/
    }

    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_store_http_srv_get(const UINT32 cxfsmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port)
{
    //CXFSMON_MD *cxfsmon_md;

    CXFS_NODE   cxfs_node;
    UINT32      hash;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_store_http_srv_get: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    /*hot cache path*/
    if(CXFSMON_HOT_PATH_SWITCH == SWITCH_ON
    && EC_TRUE == cxfsmon_cxfs_store_http_srv_get_hot(cxfsmon_md_id, path, tcid, srv_ipaddr, srv_port))
    {
        return (EC_TRUE);
    }

    /*not hot cache path*/
    hash = c_crc32_short(CSTRING_STR(path), (size_t)CSTRING_LEN(path));

    cxfs_node_init(&cxfs_node);
    if(EC_FALSE == cxfsmon_cxfs_node_get_by_hash(cxfsmon_md_id, hash, &cxfs_node))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_store_http_srv_get: get cxfs_node with cxfsmon_md_id %ld and hash %ld failed\n",
                    cxfsmon_md_id, hash);

        cxfs_node_clean(&cxfs_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_node_is_up(&cxfs_node))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_store_http_srv_get: cxfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) is not up\n",
                    c_word_to_ipv4(CXFS_NODE_TCID(&cxfs_node)),
                    c_word_to_ipv4(CXFS_NODE_IPADDR(&cxfs_node)), CXFS_NODE_PORT(&cxfs_node),
                    CXFS_NODE_MODI(&cxfs_node),
                    cxfs_node_state(&cxfs_node));

        cxfs_node_clean(&cxfs_node);
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), CXFS_NODE_TCID(&cxfs_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_store_http_srv_get: not searched tasks cfg of tcid %s\n",
                            c_word_to_ipv4(CXFS_NODE_TCID(&cxfs_node)));
        return (EC_FALSE);
    }

    if(NULL_PTR != tcid)
    {
        (*tcid) = TASKS_CFG_TCID(tasks_cfg);
    }

    if(NULL_PTR != srv_ipaddr)
    {
        (*srv_ipaddr) = TASKS_CFG_SRVIPADDR(tasks_cfg);
    }

    if(NULL_PTR != srv_port)
    {
        (*srv_port) = TASKS_CFG_CSRVPORT(tasks_cfg); /*http port*/
    }
    cxfs_node_clean(&cxfs_node);

    return (EC_TRUE);
}

/*when add a csocket_cnode (->tasks_node)*/
EC_BOOL cxfsmon_callback_when_add(const UINT32 cxfsmon_md_id, TASKS_NODE *tasks_node)
{
    CXFSMON_MD *cxfsmon_md;

    UINT32      pos;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_callback_when_add: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_callback_when_add: "
                        "tasks_node (tcid %s, srv %s:%ld)\n",
                        c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)),
                        c_word_to_ipv4(TASKS_NODE_SRVIPADDR(tasks_node)), TASKS_NODE_SRVPORT(tasks_node));

    for(pos = 0; pos < cvector_size(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md)); pos ++)
    {
        CXFS_NODE  *cxfs_node;

        cxfs_node = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);

        if(TASKS_NODE_TCID(tasks_node)      == CXFS_NODE_TCID(cxfs_node)
        && TASKS_NODE_SRVIPADDR(tasks_node) == CXFS_NODE_IPADDR(cxfs_node)
        && TASKS_NODE_SRVPORT(tasks_node)   == CXFS_NODE_PORT(cxfs_node))
        {
            dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] cxfsmon_callback_when_add: set up cxfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                            cxfs_node,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                            CXFS_NODE_MODI(cxfs_node),
                            cxfs_node_state(cxfs_node)
                            );
            return cxfsmon_cxfs_node_set_up(cxfsmon_md_id, cxfs_node);
        }
    }

    return (EC_TRUE);
}

/*when del a csocket_cnode (->tasks_node)*/
EC_BOOL cxfsmon_callback_when_del(const UINT32 cxfsmon_md_id, TASKS_NODE *tasks_node)
{
    CXFSMON_MD *cxfsmon_md;

    UINT32      pos;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_callback_when_del: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_callback_when_del: "
                        "tasks_node (tcid %s, srv %s:%ld)\n",
                        c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)),
                        c_word_to_ipv4(TASKS_NODE_SRVIPADDR(tasks_node)), TASKS_NODE_SRVPORT(tasks_node));

    if(EC_FALSE == cvector_is_empty(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
    {
        return (EC_TRUE);
    }

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    for(pos = 0; pos < cvector_size(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md)); pos ++)
    {
        CXFS_NODE  *cxfs_node;

        cxfs_node = cvector_get(CXFSMON_MD_CXFS_NODE_VEC(cxfsmon_md), pos);

        if(TASKS_NODE_TCID(tasks_node)      == CXFS_NODE_TCID(cxfs_node)
        && TASKS_NODE_SRVIPADDR(tasks_node) == CXFS_NODE_IPADDR(cxfs_node)
        && TASKS_NODE_SRVPORT(tasks_node)   == CXFS_NODE_PORT(cxfs_node))
        {
            dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_callback_when_del: "
                            "set down cxfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                            cxfs_node,
                            c_word_to_ipv4(CXFS_NODE_TCID(cxfs_node)),
                            c_word_to_ipv4(CXFS_NODE_IPADDR(cxfs_node)), CXFS_NODE_PORT(cxfs_node),
                            CXFS_NODE_MODI(cxfs_node),
                            cxfs_node_state(cxfs_node)
                            );
            return cxfsmon_cxfs_node_set_down(cxfsmon_md_id, cxfs_node);
        }
    }

    return (EC_TRUE);
}

CXFS_HOT_PATH *cxfs_hot_path_new()
{
    CXFS_HOT_PATH *cxfs_hot_path;

    alloc_static_mem(MM_CXFS_HOT_PATH, &cxfs_hot_path, LOC_CXFSMON_0008);
    if(NULL_PTR != cxfs_hot_path)
    {
        cxfs_hot_path_init(cxfs_hot_path);
    }
    return (cxfs_hot_path);
}

EC_BOOL cxfs_hot_path_init(CXFS_HOT_PATH *cxfs_hot_path)
{
    if(NULL_PTR != cxfs_hot_path)
    {
        CXFS_HOT_PATH_HASH(cxfs_hot_path) = 0;

        cstring_init(CXFS_HOT_PATH_CSTR(cxfs_hot_path), NULL_PTR);
    }
    return (EC_TRUE);
}

EC_BOOL cxfs_hot_path_clean(CXFS_HOT_PATH *cxfs_hot_path)
{
    if(NULL_PTR != cxfs_hot_path)
    {
        CXFS_HOT_PATH_HASH(cxfs_hot_path) = 0;

        cstring_clean(CXFS_HOT_PATH_CSTR(cxfs_hot_path));
    }
    return (EC_TRUE);
}

EC_BOOL cxfs_hot_path_free(CXFS_HOT_PATH *cxfs_hot_path)
{
    if(NULL_PTR != cxfs_hot_path)
    {
        cxfs_hot_path_clean(cxfs_hot_path);

        free_static_mem(MM_CXFS_HOT_PATH, cxfs_hot_path, LOC_CXFSMON_0009);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_hot_path_clone(CXFS_HOT_PATH *cxfs_hot_path_des, const CXFS_HOT_PATH *cxfs_hot_path_src)
{
    if(NULL_PTR != cxfs_hot_path_src && NULL_PTR != cxfs_hot_path_des)
    {
        CXFS_HOT_PATH_HASH(cxfs_hot_path_des) = CXFS_HOT_PATH_HASH(cxfs_hot_path_src);

        cstring_clone(CXFS_HOT_PATH_CSTR(cxfs_hot_path_src), CXFS_HOT_PATH_CSTR(cxfs_hot_path_des));
    }

    return (EC_TRUE);
}

int cxfs_hot_path_cmp(const CXFS_HOT_PATH *cxfs_hot_path_1st, const CXFS_HOT_PATH *cxfs_hot_path_2nd)
{
    if(CXFS_HOT_PATH_HASH(cxfs_hot_path_1st) > CXFS_HOT_PATH_HASH(cxfs_hot_path_2nd))
    {
        return (1);
    }

    if(CXFS_HOT_PATH_HASH(cxfs_hot_path_1st) < CXFS_HOT_PATH_HASH(cxfs_hot_path_2nd))
    {
        return (-1);
    }

    return cstring_cmp(CXFS_HOT_PATH_CSTR(cxfs_hot_path_1st), CXFS_HOT_PATH_CSTR(cxfs_hot_path_2nd));
}

void cxfs_hot_path_print(const CXFS_HOT_PATH *cxfs_hot_path, LOG *log)
{
    sys_log(log, "cxfs_hot_path_print: cxfs_hot_path %p: hash %u, str '%s'\n", cxfs_hot_path,
                    CXFS_HOT_PATH_HASH(cxfs_hot_path),
                    (char *)cstring_get_str(CXFS_HOT_PATH_CSTR(cxfs_hot_path))
                    );
    return;
}

EC_BOOL cxfsmon_cxfs_hot_path_add(const UINT32 cxfsmon_md_id, const CSTRING *path)
{
    CXFSMON_MD      *cxfsmon_md;

    CRB_NODE        *crb_node;
    CXFS_HOT_PATH   *cxfs_hot_path;

    UINT8            path_last_char;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_hot_path_add: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    /*check validity*/
    if(NULL_PTR == path)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_add: "
                                                "path is null\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(path))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_add: "
                                                "path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_get_char(path, cstring_get_len(path) - 1, &path_last_char)
    || '/' == (char)path_last_char)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_add: "
                                                "invalid path '%s'\n",
                                                (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    cxfs_hot_path = cxfs_hot_path_new();
    if(NULL_PTR == cxfs_hot_path)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_add: "
                                                "new cxfs_hot_path failed\n");
        return (EC_FALSE);
    }

    /*init*/
    CXFS_HOT_PATH_HASH(cxfs_hot_path) = CXFSMON_MD_HOT_PATH_HASH_FUNC(cxfsmon_md)(
                                                            cstring_get_len(path),
                                                            cstring_get_str(path));

    cstring_clone(path, CXFS_HOT_PATH_CSTR(cxfs_hot_path));

    crb_node = crb_tree_insert_data(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md), (void *)cxfs_hot_path);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_add: "
                                                "add hot path '%s' failed\n",
                                                (char *)cstring_get_str(path));
        cxfs_hot_path_free(cxfs_hot_path);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cxfs_hot_path)/*found duplicate*/
    {
        dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_add: "
                                                "found duplicated hot path '%s'\n",
                                                (char *)cstring_get_str(path));
        cxfs_hot_path_free(cxfs_hot_path);
        return (EC_TRUE);
    }

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_add: "
                                            "add hot path '%s' done\n",
                                            (char *)cstring_get_str(path));
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_hot_path_del(const UINT32 cxfsmon_md_id, const CSTRING *path)
{
    CXFSMON_MD      *cxfsmon_md;

    CRB_NODE        *crb_node_searched;
    CXFS_HOT_PATH    cxfs_hot_path_t;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_hot_path_del: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    /*init*/
    CXFS_HOT_PATH_HASH(&cxfs_hot_path_t) = CXFSMON_MD_HOT_PATH_HASH_FUNC(cxfsmon_md)(
                                                            cstring_get_len(path),
                                                            cstring_get_str(path));

    cstring_set_str(CXFS_HOT_PATH_CSTR(&cxfs_hot_path_t), cstring_get_str(path));

    crb_node_searched = crb_tree_search_data(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md), (void *)&cxfs_hot_path_t);
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0206_CXFSMON, 5)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_del: "
                                                "not found hot path '%s'\n",
                                                (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    crb_tree_delete(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md), crb_node_searched);

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_del: "
                                            "del hot path '%s' done\n",
                                            (char *)cstring_get_str(path));
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_hot_path_exist(const UINT32 cxfsmon_md_id, const CSTRING *path)
{
    CXFSMON_MD      *cxfsmon_md;

    CRB_NODE        *crb_node_searched;
    CXFS_HOT_PATH    cxfs_hot_path_t;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_hot_path_exist: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    if(EC_TRUE == crb_tree_is_empty(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md)))
    {
        return (EC_FALSE);
    }

    /*init*/
    CXFS_HOT_PATH_HASH(&cxfs_hot_path_t) = CXFSMON_MD_HOT_PATH_HASH_FUNC(cxfsmon_md)(
                                                            cstring_get_len(path),
                                                            cstring_get_str(path));

    cstring_set_str(CXFS_HOT_PATH_CSTR(&cxfs_hot_path_t), cstring_get_str(path));

    crb_node_searched = crb_tree_search_data(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md), (void *)&cxfs_hot_path_t);
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0206_CXFSMON, 5)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_exist: "
                                                "not found hot path '%s'\n",
                                                (char *)cstring_get_str(path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_exist: "
                                            "found hot path '%s'\n",
                                            (char *)cstring_get_str(path));
    return (EC_TRUE);
}

void cxfsmon_cxfs_hot_path_print(const UINT32 cxfsmon_md_id, LOG *log)
{
    CXFSMON_MD *cxfsmon_md;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_hot_path_print: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    crb_tree_print(log, CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md));

    return;
}

/*format: /<domain>/path */
STATIC_CAST static EC_BOOL __cxfsmon_parse_hot_path_line(const UINT32 cxfsmon_md_id, char *cxfsmon_host_path_start, char *cxfsmon_host_path_end)
{
    //CXFSMON_MD          *cxfsmon_md;

    char                *p;
    CSTRING              path;

    //cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    /*locate the first char which is not space*/

    for(p = cxfsmon_host_path_start;isspace(*p); p ++)
    {
        /*do nothing*/
    }

    if('\0' == (*p))
    {
        dbg_log(SEC_0206_CXFSMON, 6)(LOGSTDOUT, "[DEBUG] __cxfsmon_parse_hot_path_line: "
                                                "skip empty line '%.*s'\n",
                                                (uint32_t)(cxfsmon_host_path_end - cxfsmon_host_path_start),
                                                cxfsmon_host_path_start);
        /*skip empty line*/
        return (EC_TRUE);
    }

    if('#' == (*p))
    {
        /*skip commented line*/
        dbg_log(SEC_0206_CXFSMON, 6)(LOGSTDOUT, "[DEBUG] __cxfsmon_parse_hot_path_line: "
                                                "skip commented line '%.*s'\n",
                                                (uint32_t)(cxfsmon_host_path_end - cxfsmon_host_path_start),
                                                cxfsmon_host_path_start);
        return (EC_TRUE);
    }

    dbg_log(SEC_0206_CXFSMON, 6)(LOGSTDOUT, "[DEBUG] __cxfsmon_parse_hot_path_line: "
                                            "handle line '%.*s'\n",
                                            (uint32_t)(cxfsmon_host_path_end - cxfsmon_host_path_start),
                                            cxfsmon_host_path_start);

    c_str_trim_space(p);
    cstring_set_str(&path, (const UINT8 *)p);

    if(EC_FALSE == cxfsmon_cxfs_hot_path_add(cxfsmon_md_id, &path))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:__cxfsmon_parse_hot_path_line: "
                                                "insert '%s' failed\n",
                                                p);
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CXFSMON, 5)(LOGSTDOUT, "[DEBUG] __cxfsmon_parse_hot_path_line: "
                                            "insert '%s' done\n",
                                            p);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsmon_parse_hot_path_file(const UINT32 cxfsmon_md_id, char *cxfsmon_hot_path_start, char *cxfsmon_hot_path_end)
{
    char        *cxfsmon_hot_path_line_start;
    uint32_t     cxfsmon_hot_path_line_no;

    cxfsmon_hot_path_line_start = cxfsmon_hot_path_start;
    cxfsmon_hot_path_line_no    = 1;

    while(cxfsmon_hot_path_line_start < cxfsmon_hot_path_end)
    {
        char  *cxfsmon_hot_path_line_end;

        cxfsmon_hot_path_line_end = cxfsmon_hot_path_line_start;

        while(cxfsmon_hot_path_line_end < cxfsmon_hot_path_end)
        {
            if('\n' == (*cxfsmon_hot_path_line_end ++)) /*also works for line-terminator '\r\n'*/
            {
                break;
            }
        }

        if(cxfsmon_hot_path_line_end > cxfsmon_hot_path_end)
        {
            break;
        }

        *(cxfsmon_hot_path_line_end - 1) = '\0'; /*insert string terminator*/

        dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "error:__cxfsmon_parse_hot_path_file: "
                                                "to parse line %u# '%.*s' failed\n",
                                                cxfsmon_hot_path_line_no,
                                                (uint32_t)(cxfsmon_hot_path_line_end - cxfsmon_hot_path_line_start),
                                                cxfsmon_hot_path_line_start);

        if(EC_FALSE == __cxfsmon_parse_hot_path_line(cxfsmon_md_id, cxfsmon_hot_path_line_start, cxfsmon_hot_path_line_end))
        {
            dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:__cxfsmon_parse_hot_path_file: "
                                                    "parse line %u# '%.*s' failed\n",
                                                    cxfsmon_hot_path_line_no,
                                                    (uint32_t)(cxfsmon_hot_path_line_end - cxfsmon_hot_path_line_start),
                                                    cxfsmon_hot_path_line_start);
            return (EC_FALSE);
        }

        cxfsmon_hot_path_line_no ++;

        cxfsmon_hot_path_line_start = cxfsmon_hot_path_line_end;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_hot_path_load(const UINT32 cxfsmon_md_id, const CSTRING *path)
{
    //CXFSMON_MD  *cxfsmon_md;

    const char  *fname;
    UINT32       fsize;
    UINT32       offset;
    UINT8       *fcontent;
    int          fd;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_hot_path_load: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    if(EC_TRUE == cstring_is_empty(path))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "path is empty\n");
        return (EC_FALSE);
    }

    fname = (char *)cstring_get_str(path);

    if(EC_FALSE == c_file_exist(fname))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "file '%s' not exist\n",
                                                fname);
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_load: "
                                            "file '%s' exist\n",
                                            fname);

    if(EC_FALSE == c_file_access(fname, F_OK | R_OK))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "access file '%s' failed\n",
                                                fname);
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_load: "
                                            "access file '%s' done\n",
                                            fname);

    fd = c_file_open(fname, O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "open file '%s' failed\n",
                                                fname);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "get size of '%s' failed\n",
                                                fname);
        c_file_close(fd);
        return (EC_FALSE);
    }

    if(0 == fsize)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "file '%s' size is 0\n",
                                                fname);
        c_file_close(fd);
        return (EC_FALSE);
    }

    fcontent = safe_malloc(fsize, LOC_CXFSMON_0010);
    if(NULL_PTR == fcontent)
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "malloc %ld bytes for file '%s' failed\n",
                                                fsize, fname);
        c_file_close(fd);
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, fcontent))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "load file '%s' failed\n",
                                                fname);
        c_file_close(fd);
        safe_free(fcontent, LOC_CXFSMON_0011);
        return (EC_FALSE);
    }
    c_file_close(fd);

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_load: "
                                            "load file '%s' from disk done\n",
                                            fname);

    /*parse*/
    if(EC_FALSE == __cxfsmon_parse_hot_path_file(cxfsmon_md_id, (char *)fcontent, (char *)(fcontent + fsize)))
    {
        dbg_log(SEC_0206_CXFSMON, 0)(LOGSTDOUT, "error:cxfsmon_cxfs_hot_path_load: "
                                                "parse file '%s' failed\n",
                                                fname);
        safe_free(fcontent, LOC_CXFSMON_0012);
        return (EC_FALSE);
    }
    safe_free(fcontent, LOC_CXFSMON_0013);

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_load: "
                                            "parse file '%s' done\n",
                                            fname);
    return (EC_TRUE);
}

EC_BOOL cxfsmon_cxfs_hot_path_unload(const UINT32 cxfsmon_md_id)
{
    CXFSMON_MD  *cxfsmon_md;

#if ( SWITCH_ON == CXFSMON_DEBUG_SWITCH )
    if ( CXFSMON_MD_ID_CHECK_INVALID(cxfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsmon_cxfs_hot_path_unload: cxfsmon module #0x%lx not started.\n",
                cxfsmon_md_id);
        dbg_exit(MD_CXFSMON, cxfsmon_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfsmon_md = CXFSMON_MD_GET(cxfsmon_md_id);

    crb_tree_clean(CXFSMON_MD_HOT_PATH_TREE(cxfsmon_md));

    dbg_log(SEC_0206_CXFSMON, 9)(LOGSTDOUT, "[DEBUG] cxfsmon_cxfs_hot_path_load: "
                                            "unload done\n");
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

