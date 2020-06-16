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
#if (SWITCH_ON == NGX_BGN_SWITCH)
#include "cngx_http.h"
#endif /*(SWITCH_ON == NGX_BGN_SWITCH)*/
#include "cmon.h"
#include "cconhash.h"

#include "cload.h"

#include "findex.inc"

static UINT32   g_cmon_node_pos = 0;

#define CMON_MD_CAPACITY()                  (cbc_md_capacity(MD_CMON))

#define CMON_MD_GET(cmon_md_id)     ((CMON_MD *)cbc_md_get(MD_CMON, (cmon_md_id)))

#define CMON_MD_ID_CHECK_INVALID(cmon_md_id)  \
    ((CMPI_ANY_MODI != (cmon_md_id)) && ((NULL_PTR == CMON_MD_GET(cmon_md_id)) || (0 == (CMON_MD_GET(cmon_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CMON Module
*
**/
void cmon_print_module_status(const UINT32 cmon_md_id, LOG *log)
{
    CMON_MD    *cmon_md;
    UINT32 this_cmon_md_id;

    for( this_cmon_md_id = 0; this_cmon_md_id < CMON_MD_CAPACITY(); this_cmon_md_id ++ )
    {
        cmon_md = CMON_MD_GET(this_cmon_md_id);

        if ( NULL_PTR != cmon_md && 0 < cmon_md->usedcounter )
        {
            sys_log(log,"CMON Module # %ld : %ld refered\n",
                    this_cmon_md_id,
                    cmon_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CMON module
*
*
**/
UINT32 cmon_free_module_static_mem(const UINT32 cmon_md_id)
{
    //CMON_MD  *cmon_md;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_free_module_static_mem: cmon module #0x%lx not started.\n",
                cmon_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CMON_DEBUG_SWITCH*/

    //cmon_md = CMON_MD_GET(cmon_md_id);

    free_module_static_mem(MD_CMON, cmon_md_id);

    return 0;
}

/**
*
* start CMON module
*
**/
UINT32 cmon_start()
{
    CMON_MD    *cmon_md;
    UINT32      cmon_md_id;

    TASK_BRD   *task_brd;

    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CMON , 32);

    cmon_md_id = cbc_md_new(MD_CMON, sizeof(CMON_MD));
    if(CMPI_ERROR_MODI == cmon_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CMON module */
    cmon_md = (CMON_MD *)cbc_md_get(MD_CMON, cmon_md_id);
    cmon_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /*initialize CMON_NODE vector*/
    cvector_init(CMON_MD_CMON_NODE_VEC(cmon_md), 16, MM_CMON_NODE, CVECTOR_LOCK_DISABLE, LOC_CMON_0001);

    if(SWITCH_ON == CMON_CONHASH_SWITCH)
    {
        CMON_MD_CCONHASH(cmon_md) = cconhash_new(CMON_CONHASH_DEFAULT_HASH_ALGO);
    }
    else
    {
        CMON_MD_CCONHASH(cmon_md) = NULL_PTR;
    }

    if(SWITCH_ON == CMON_MAGLEV_SWITCH)
    {
        CMON_MD_CMAGLEV(cmon_md) = cmaglev_new();
    }
    else
    {
        CMON_MD_CMAGLEV(cmon_md) = NULL_PTR;
    }

    CMON_MD_HOT_PATH_HASH_FUNC(cmon_md) = chash_algo_fetch(CMON_HOT_PATH_HASH_ALGO);

    /*initialize HOT PATH RB TREE*/
    crb_tree_init(CMON_MD_HOT_PATH_TREE(cmon_md),
                    (CRB_DATA_CMP)cmon_hot_path_cmp,
                    (CRB_DATA_FREE)cmon_hot_path_free,
                    (CRB_DATA_PRINT)cmon_hot_path_print);

    cmon_md->usedcounter = 1;

#if 0
    tasks_cfg_push_add_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                       (const char *)"cmon_callback_when_add",
                                       cmon_md_id,
                                       (UINT32)cmon_callback_when_add);
#endif

    tasks_cfg_push_del_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                       (const char *)"cmon_callback_when_del",
                                       cmon_md_id,
                                       (UINT32)cmon_callback_when_del);

#if (SWITCH_ON == NGX_BGN_SWITCH)
    if(CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first module is allowed to launch ngx http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled()
        && NULL_PTR != task_brd_default_get_cepoll()
        && 0 == cmon_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_start: init cngx http defer request queue failed\n");
                cmon_end(cmon_md_id);
                return (CMPI_ERROR_MODI);
            }

            cngx_http_log_start();
            task_brd_default_bind_http_srv_modi(cmon_md_id);
            chttp_rest_list_push((const char *)CNGX_HTTP_REST_API_NAME, cngx_http_commit_request);
        }
    }
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cmon_end, cmon_md_id);

    dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "[DEBUG] cmon_start: start CMON module #%ld\n", cmon_md_id);

    return ( cmon_md_id );
}

/**
*
* end CMON module
*
**/
void cmon_end(const UINT32 cmon_md_id)
{
    CMON_MD    *cmon_md;

    TASK_BRD   *task_brd;

    task_brd = task_brd_default_get();

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cmon_end, cmon_md_id);

    cmon_md = CMON_MD_GET(cmon_md_id);
    if(NULL_PTR == cmon_md)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_end: cmon_md_id = %ld not exist.\n", cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cmon_md->usedcounter )
    {
        cmon_md->usedcounter --;
        return ;
    }

    if ( 0 == cmon_md->usedcounter )
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_end: cmon_md_id = %ld is not started.\n", cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }

    cvector_clean(CMON_MD_CMON_NODE_VEC(cmon_md), (CVECTOR_DATA_CLEANER)cmon_node_free, LOC_CMON_0002);
    if(NULL_PTR != CMON_MD_CCONHASH(cmon_md))
    {
        cconhash_free(CMON_MD_CCONHASH(cmon_md));
        CMON_MD_CCONHASH(cmon_md) = NULL_PTR;
    }

    if(NULL_PTR != CMON_MD_CMAGLEV(cmon_md))
    {
        cmaglev_free(CMON_MD_CMAGLEV(cmon_md));
        CMON_MD_CMAGLEV(cmon_md) = NULL_PTR;
    }

    CMON_MD_HOT_PATH_HASH_FUNC(cmon_md) = NULL_PTR;
    crb_tree_clean(CMON_MD_HOT_PATH_TREE(cmon_md));

    tasks_cfg_erase_add_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                      (const char *)"cmon_callback_when_add",
                                      cmon_md_id,
                                      (UINT32)cmon_callback_when_add);

    tasks_cfg_erase_del_worker_callback(TASK_BRD_LOCAL_TASKS_CFG(task_brd),
                                      (const char *)"cmon_callback_when_del",
                                      cmon_md_id,
                                      (UINT32)cmon_callback_when_del);

    /* free module : */

    cmon_md->usedcounter = 0;

    dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "cmon_end: stop CMON module #%ld\n", cmon_md_id);
    cbc_md_free(MD_CMON, cmon_md_id);

    return ;
}

/**
*
* set all nodes up
*
**/
EC_BOOL cmon_set_up(const UINT32 cmon_md_id)
{
    CMON_MD    *cmon_md;

    UINT32      num;
    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_set_up: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/
    cmon_md = CMON_MD_GET(cmon_md_id);

    num = cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md));
    for(pos = 0; pos < num; pos ++)
    {
        CMON_NODE *cmon_node;

        cmon_node = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
        if(NULL_PTR == cmon_node)
        {
            continue;
        }

        if(EC_FALSE == cmon_set_node_up(cmon_md_id, cmon_node))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_up: "
                        "set cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) UP failed\n",
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                        CMON_NODE_MODI(cmon_node),
                        cmon_node_state(cmon_node)
                        );
        }
        else
        {
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_set_up: "
                        "set cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) UP done\n",
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                        CMON_NODE_MODI(cmon_node),
                        cmon_node_state(cmon_node)
                        );
        }
    }

    return (EC_TRUE);
}

/**
*
* set all nodes down
*
**/
EC_BOOL cmon_set_down(const UINT32 cmon_md_id)
{
    CMON_MD    *cmon_md;

    UINT32      num;
    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_set_down: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/
    cmon_md = CMON_MD_GET(cmon_md_id);

    num = cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md));
    for(pos = 0; pos < num; pos ++)
    {
        CMON_NODE *cmon_node;

        cmon_node = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
        if(NULL_PTR == cmon_node)
        {
            continue;
        }

        if(EC_FALSE == cmon_set_node_down(cmon_md_id, cmon_node))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_down: "
                        "set cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) DOWN failed\n",
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                        CMON_NODE_MODI(cmon_node),
                        cmon_node_state(cmon_node)
                        );
        }
        else
        {
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_set_down: "
                        "set cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) DOWN done\n",
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                        CMON_NODE_MODI(cmon_node),
                        cmon_node_state(cmon_node)
                        );
        }
    }

    return (EC_TRUE);
}

CMON_NODE *cmon_node_new()
{
    CMON_NODE *cmon_node;
    alloc_static_mem(MM_CMON_NODE, &cmon_node, LOC_CMON_0003);
    if(NULL_PTR != cmon_node)
    {
        cmon_node_init(cmon_node);
    }
    return (cmon_node);
}

EC_BOOL cmon_node_init(CMON_NODE *cmon_node)
{
    if(NULL_PTR != cmon_node)
    {
        CMON_NODE_TCID(cmon_node)   = CMPI_ERROR_TCID;
        CMON_NODE_IPADDR(cmon_node) = CMPI_ERROR_IPADDR;
        CMON_NODE_PORT(cmon_node)   = CMPI_ERROR_SRVPORT;
        CMON_NODE_MODI(cmon_node)   = CMPI_ERROR_MODI;
        CMON_NODE_STATE(cmon_node)  = CMON_NODE_IS_ERR;

    }
    return (EC_TRUE);
}

EC_BOOL cmon_node_clean(CMON_NODE *cmon_node)
{
    if(NULL_PTR != cmon_node)
    {
        CMON_NODE_TCID(cmon_node)   = CMPI_ERROR_TCID;
        CMON_NODE_IPADDR(cmon_node) = CMPI_ERROR_IPADDR;
        CMON_NODE_PORT(cmon_node)   = CMPI_ERROR_SRVPORT;
        CMON_NODE_MODI(cmon_node)   = CMPI_ERROR_MODI;
        CMON_NODE_STATE(cmon_node)  = CMON_NODE_IS_ERR;

    }
    return (EC_TRUE);
}

EC_BOOL cmon_node_free(CMON_NODE *cmon_node)
{
    if(NULL_PTR != cmon_node)
    {
        cmon_node_clean(cmon_node);
        free_static_mem(MM_CMON_NODE, cmon_node, LOC_CMON_0004);
    }

    return (EC_TRUE);
}

EC_BOOL cmon_node_clone(const CMON_NODE *cmon_node_src, CMON_NODE *cmon_node_des)
{
    if(NULL_PTR != cmon_node_src && NULL_PTR != cmon_node_des)
    {
        CMON_NODE_TCID(cmon_node_des)   = CMON_NODE_TCID(cmon_node_src);
        CMON_NODE_IPADDR(cmon_node_des) = CMON_NODE_IPADDR(cmon_node_src);
        CMON_NODE_PORT(cmon_node_des)   = CMON_NODE_PORT(cmon_node_src);
        CMON_NODE_MODI(cmon_node_des)   = CMON_NODE_MODI(cmon_node_src);
        CMON_NODE_STATE(cmon_node_des)  = CMON_NODE_STATE(cmon_node_src);
    }

    return (EC_TRUE);
}

EC_BOOL cmon_node_is_up(const CMON_NODE *cmon_node)
{
    if(CMON_NODE_IS_UP == CMON_NODE_STATE(cmon_node))
    {
        TASK_BRD        *task_brd;

        task_brd = task_brd_default_get();

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd, CMON_NODE_TCID(cmon_node)))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "[DEBUG] cmon_node_is_up: "
                            "tcid %s is not connected => set down\n",
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node)));

            cmon_set_node_down(TASK_BRD_CMON_ID(task_brd), cmon_node);
            return (EC_FALSE);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmon_node_is_valid(const CMON_NODE *cmon_node)
{
    if(CMPI_ERROR_TCID == CMON_NODE_TCID(cmon_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_IPADDR == CMON_NODE_IPADDR(cmon_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_SRVPORT == CMON_NODE_PORT(cmon_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CMON_NODE_MODI(cmon_node))
    {
        return (EC_FALSE);
    }

    if(CMON_NODE_IS_ERR == CMON_NODE_STATE(cmon_node))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cmon_node_cmp(const CMON_NODE *cmon_node_1st, const CMON_NODE *cmon_node_2nd)
{
    if(CMON_NODE_TCID(cmon_node_1st) == CMON_NODE_TCID(cmon_node_2nd)
    && CMON_NODE_MODI(cmon_node_1st) == CMON_NODE_MODI(cmon_node_2nd))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

const char *cmon_node_state(const CMON_NODE *cmon_node)
{
    if(CMON_NODE_IS_UP == CMON_NODE_STATE(cmon_node))
    {
        return (const char *)"UP";
    }
    if(CMON_NODE_IS_DOWN == CMON_NODE_STATE(cmon_node))
    {
        return (const char *)"DOWN";
    }

    if(CMON_NODE_IS_ERR == CMON_NODE_STATE(cmon_node))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

void cmon_node_print(const CMON_NODE *cmon_node, LOG *log)
{
    sys_log(log, "cmon_node_print: "
                 "cmon_node %p: tcid %s, srv %s:%ld, modi %ld, state %s\n",
                 cmon_node,
                 c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                 c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                 CMON_NODE_MODI(cmon_node),
                 cmon_node_state(cmon_node)
                 );
    return;
}

void cmon_node_print_0(LOG *log, const CMON_NODE *cmon_node)
{
    cmon_node_print(cmon_node, log);
    return;
}

void cmon_print_nodes(const UINT32 cmon_md_id, LOG *log)
{
    CMON_MD    *cmon_md;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_print_nodes: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    cvector_print(log, CMON_MD_CMON_NODE_VEC(cmon_md), (CVECTOR_DATA_PRINT)cmon_node_print_0);

    return;
}

void cmon_list_nodes(const UINT32 cmon_md_id, CSTRING *cstr)
{
    CMON_MD    *cmon_md;
    UINT32      pos;
    UINT32      num;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_list_nodes: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    num = cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md));
    for(pos = 0; pos < num; pos ++)
    {
        CMON_NODE *cmon_node;
        cmon_node = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
        if(NULL_PTR == cmon_node)
        {
            cstring_format(cstr, "[%ld/%ld] (null)\n", pos, num);
            continue;
        }

        cstring_format(cstr,
                    "[%ld/%ld] (tcid %s, srv %s:%ld, modi %ld, state %s)\n", pos, num,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)),
                    CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node)
                    );

        dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_list_nodes: "
                                             "[%ld] cstr:\n%.*s\n", pos,
                                             (uint32_t)CSTRING_LEN(cstr),
                                             (char *)CSTRING_STR(cstr));

    }

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_list_nodes: "
                                         "list result:\n%.*s\n",
                                         (uint32_t)CSTRING_LEN(cstr),
                                         (char *)CSTRING_STR(cstr));
    return;
}

EC_BOOL cmon_count_nodes(const UINT32 cmon_md_id, UINT32 *num)
{
    CMON_MD    *cmon_md;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_count_nodes: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    (*num) = cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md));
    return (EC_TRUE);
}

EC_BOOL cmon_add_node(const UINT32 cmon_md_id, const CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_t;
    UINT32      pos;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_add_node: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    /*check validity*/
    if(CMPI_ERROR_TCID == CMON_NODE_TCID(cmon_node) || CMPI_ERROR_MODI == CMON_NODE_MODI(cmon_node))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "warn:cmon_add_node: "
                    "cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) is invalid\n",
                    cmon_node,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)),
                    CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node)
                    );
        return (EC_FALSE);
    }

    pos = cvector_search_front(CMON_MD_CMON_NODE_VEC(cmon_md),
                               (const void *)cmon_node,
                               (CVECTOR_DATA_CMP)cmon_node_cmp);
    if(CVECTOR_ERR_POS != pos)/*found duplicate*/
    {
        cmon_node_t = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);

        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "warn:cmon_add_node: "
                    "found duplicate cmon_node %p "
                    "(tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    cmon_node_t,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)),
                    CMON_NODE_PORT(cmon_node_t),
                    CMON_NODE_MODI(cmon_node_t),
                    cmon_node_state(cmon_node_t)
                    );
        if(CMON_NODE_IS_DOWN == CMON_NODE_STATE(cmon_node_t)
        && CMON_NODE_IS_UP == CMON_NODE_STATE(cmon_node))
        {
            cmon_set_node_up(cmon_md_id, cmon_node_t);
        }

        if(CMON_NODE_IS_UP == CMON_NODE_STATE(cmon_node_t)
        && CMON_NODE_IS_DOWN == CMON_NODE_STATE(cmon_node))
        {
            cmon_set_node_down(cmon_md_id, cmon_node_t);
        }

        return (EC_TRUE);
    }

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd),
                                         CMON_NODE_TCID(cmon_node),
                                         CMPI_ANY_MASK,
                                         CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_node: "
                            "not searched tasks cfg of tcid %s\n",
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node)));
        return (EC_FALSE);
    }

    cmon_node_t = cmon_node_new();
    if(NULL_PTR == cmon_node_t)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_node: "
                "new cmon_node failed before insert cmon_node %p "
                "(tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                cmon_node,
                c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                CMON_NODE_MODI(cmon_node),
                cmon_node_state(cmon_node)
                );

        return (EC_FALSE);
    }

    cmon_node_clone(cmon_node, cmon_node_t);

    CMON_NODE_IPADDR(cmon_node_t) = TASKS_CFG_SRVIPADDR(tasks_cfg);
    CMON_NODE_PORT(cmon_node_t)   = TASKS_CFG_SRVPORT(tasks_cfg); /*bgn port*/
    CMON_NODE_STATE(cmon_node_t)  = CMON_NODE_STATE(cmon_node);

    cvector_push(CMON_MD_CMON_NODE_VEC(cmon_md), (const void *)cmon_node_t);

    if(NULL_PTR != CMON_MD_CCONHASH(cmon_md))
    {
        if(EC_FALSE == cconhash_add_node(CMON_MD_CCONHASH(cmon_md),
                                        (uint32_t)CMON_NODE_TCID(cmon_node_t),
                                        CMON_CONHASH_REPLICAS))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_node: "
                            "add cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "to connhash failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );

            cvector_pop(CMON_MD_CMON_NODE_VEC(cmon_md));
            cmon_node_free(cmon_node_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT,
                        "[DEBUG] cmon_add_node: "
                        "add cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                        "to connhash done\n",
                        cmon_node_t,
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                        CMON_NODE_MODI(cmon_node_t),
                        cmon_node_state(cmon_node_t)
                        );
    }

    /* use tcid to add cmaglev node */
    if (NULL_PTR != CMON_MD_CMAGLEV(cmon_md))
    {
        if (EC_FALSE == cmaglev_add_node(CMON_MD_CMAGLEV(cmon_md), cmon_node_t->tcid))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_node: "
                            "add cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "to maglev failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
            cvector_pop(CMON_MD_CMON_NODE_VEC(cmon_md));
            cmon_node_free(cmon_node_t);
            return (EC_FALSE);
        }

        /*
         * update maglev, it's a little complicated that generate one time
         * after all node is added, especially when node's status change
         *
         */
        cmaglev_hash(CMON_MD_CMAGLEV(cmon_md));
        dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_add_node: "
                        "add cmon_node %p (tcid %s, srv %s:%ld, vec_size %ld, state %s) "
                        "to maglev succ\n",
                        cmon_node_t,
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                        cmaglev_count_rnode(CMON_MD_CMAGLEV(cmon_md)),
                        cmon_node_state(cmon_node_t)
                        );
    }

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_add_node: "
                    "add cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cmon_node_t,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                    CMON_NODE_MODI(cmon_node_t),
                    cmon_node_state(cmon_node_t)
                    );

    return (EC_TRUE);
}

EC_BOOL cmon_del_node(const UINT32 cmon_md_id, const CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_del_node: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    pos = cvector_search_front(CMON_MD_CMON_NODE_VEC(cmon_md),
                               (const void *)cmon_node,
                               (CVECTOR_DATA_CMP)cmon_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0023_CMON, 1)(LOGSTDOUT, "warn:cmon_del_node: "
                    "not found cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node)
                    );
        return (EC_TRUE);
    }

    cmon_node_t = cvector_erase(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
    if(NULL_PTR == cmon_node_t)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT,
                    "warn:cmon_del_node: erase cmon_node is null\n");
        return (EC_TRUE);
    }

    if(NULL_PTR != CMON_MD_CCONHASH(cmon_md))
    {
        if(EC_FALSE == cconhash_del_node(CMON_MD_CCONHASH(cmon_md),
                                        (uint32_t)CMON_NODE_TCID(cmon_node_t)))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_del_node: "
                            "del cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "from connhash failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );

            cmon_node_free(cmon_node_t);
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_del_node: "
                            "del cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "from connhash done\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
        }
    }

    if (NULL_PTR != CMON_MD_CMAGLEV(cmon_md))
    {
        if(EC_FALSE == cmaglev_del_node(CMON_MD_CMAGLEV(cmon_md),
                                        (uint32_t)CMON_NODE_TCID(cmon_node_t)))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_del_node: "
                            "del cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "from maglev failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );

            cmon_node_free(cmon_node_t);
            return (EC_FALSE);
        }

        cmaglev_hash(CMON_MD_CMAGLEV(cmon_md));
    }

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_del_node: "
                    "erase cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cmon_node_t,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                    CMON_NODE_MODI(cmon_node_t),
                    cmon_node_state(cmon_node_t)
                    );

    cmon_node_free(cmon_node_t);
    return (EC_TRUE);
}

EC_BOOL cmon_set_node_up(const UINT32 cmon_md_id, const CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_set_node_up: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    pos = cvector_search_front(CMON_MD_CMON_NODE_VEC(cmon_md),
                               (const void *)cmon_node,
                               (CVECTOR_DATA_CMP)cmon_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_up: "
                    "not found cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node)
                    );
        return (EC_FALSE);
    }

    cmon_node_t = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
    if(NULL_PTR == cmon_node_t)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_up: "
                    "found cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) "
                    "at pos %ld but it is null\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CMON_MD_CCONHASH(cmon_md))
    {
        if(EC_FALSE == cconhash_up_node(CMON_MD_CCONHASH(cmon_md),
                                            (uint32_t)CMON_NODE_TCID(cmon_node_t)))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_up: "
                            "set up cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in connhash failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "[DEBUG] cmon_set_node_up: "
                            "set up cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in connhash done\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
        }
    }

    if(NULL_PTR != CMON_MD_CMAGLEV(cmon_md))
    {
        if(EC_FALSE == cmaglev_up_node(CMON_MD_CMAGLEV(cmon_md),
                                            (uint32_t)CMON_NODE_TCID(cmon_node_t)))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_up: "
                            "set up cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in maglev failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "[DEBUG] cmon_set_node_up: "
                            "set up cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in maglev done\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
        }
    }

    CMON_NODE_STATE(cmon_node_t) = CMON_NODE_IS_UP; /*set up*/

    dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "[DEBUG] cmon_set_node_up: "
                    "set up cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cmon_node_t,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                    CMON_NODE_MODI(cmon_node_t),
                    cmon_node_state(cmon_node_t)
                    );
    return (EC_TRUE);
}

EC_BOOL cmon_set_node_down(const UINT32 cmon_md_id, const CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_set_node_down: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    pos = cvector_search_front(CMON_MD_CMON_NODE_VEC(cmon_md),
                              (const void *)cmon_node,
                              (CVECTOR_DATA_CMP)cmon_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_down: "
                    "not found cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node)
                    );
        return (EC_FALSE);
    }

    cmon_node_t = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
    if(NULL_PTR == cmon_node_t)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_down: "
                    "found cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) "
                    "at pos %ld but it is null\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CMON_MD_CCONHASH(cmon_md))
    {
        if(EC_FALSE == cconhash_down_node(CMON_MD_CCONHASH(cmon_md),
                                            (uint32_t)CMON_NODE_TCID(cmon_node_t)))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_down: "
                            "set down cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in connhash failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_set_node_down: "
                            "set down cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in connhash done\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
        }
    }

    if (NULL_PTR != CMON_MD_CMAGLEV(cmon_md))
    {
        if(EC_FALSE == cmaglev_down_node(CMON_MD_CMAGLEV(cmon_md),
                                            (uint32_t)CMON_NODE_TCID(cmon_node_t)))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_set_node_down: "
                            "set down cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in maglev failed\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_set_node_down: "
                            "set down cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                            "in maglev done\n",
                            cmon_node_t,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                            CMON_NODE_MODI(cmon_node_t),
                            cmon_node_state(cmon_node_t)
                            );
        }
    }

    CMON_NODE_STATE(cmon_node_t) = CMON_NODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_set_node_down: "
                    "set down cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cmon_node_t,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                    CMON_NODE_MODI(cmon_node_t),
                    cmon_node_state(cmon_node_t)
                    );
    return (EC_TRUE);
}

EC_BOOL cmon_check_node_up(const UINT32 cmon_md_id, const CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_check_node_up: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    pos = cvector_search_front(CMON_MD_CMON_NODE_VEC(cmon_md),
                               (const void *)cmon_node,
                               (CVECTOR_DATA_CMP)cmon_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_check_node_up: "
                    "not found cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node)
                    );
        return (EC_FALSE);
    }

    cmon_node_t = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
    if(NULL_PTR == cmon_node_t)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_check_node_up: "
                    "found cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) "
                    "at pos %ld but it is null\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                    CMON_NODE_MODI(cmon_node),
                    cmon_node_state(cmon_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_check_node_up: "
                    "check cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    cmon_node_t,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                    CMON_NODE_MODI(cmon_node_t),
                    cmon_node_state(cmon_node_t)
                    );

    if(CMON_NODE_IS_UP == CMON_NODE_STATE(cmon_node_t))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmon_get_node_by_pos(const UINT32 cmon_md_id, const UINT32 pos, CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_t;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_get_node_by_pos: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_pos: "
                                             "pos is error\n");
        return (EC_FALSE);
    }

    cmon_node_t = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
    if(NULL_PTR == cmon_node_t)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_pos: "
                    "found cmon_node at pos %ld but it is null\n", pos);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_get_node_by_pos: "
                    "found cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld\n",
                    cmon_node_t,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                    CMON_NODE_MODI(cmon_node_t),
                    cmon_node_state(cmon_node_t),
                    pos
                    );

    cmon_node_clone(cmon_node_t, cmon_node);
    return (EC_TRUE);
}

EC_BOOL cmon_get_node_by_tcid(const UINT32 cmon_md_id, const UINT32 tcid, const UINT32 modi, CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_searched;
    CMON_NODE   cmon_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_get_node_by_tcid: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    CMON_NODE_TCID(&cmon_node_t) = tcid;
    CMON_NODE_MODI(&cmon_node_t) = modi;

    pos = cvector_search_front(CMON_MD_CMON_NODE_VEC(cmon_md),
                                (const void *)&cmon_node_t,
                                (CVECTOR_DATA_CMP)cmon_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_tcid: "
                    "not found cmon_node with (tcid %s, modi %ld)\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    CMON_NODE_MODI(cmon_node)
                    );
        return (EC_FALSE);
    }

    cmon_node_searched = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
    if(NULL_PTR == cmon_node_searched)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_tcid: "
                    "found cmon_node with (tcid %s, modi %ld) at pos %ld but it is null\n",
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                    CMON_NODE_MODI(cmon_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_get_node_by_tcid: "
                    "found cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    cmon_node_searched,
                    c_word_to_ipv4(CMON_NODE_TCID(cmon_node_searched)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_searched)), CMON_NODE_PORT(cmon_node_searched),
                    CMON_NODE_MODI(cmon_node_searched),
                    cmon_node_state(cmon_node_searched)
                    );

    cmon_node_clone(cmon_node_searched, cmon_node);

    return (EC_TRUE);
}

EC_BOOL cmon_get_node_by_hash(const UINT32 cmon_md_id, const UINT32 hash, CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;
    CMON_NODE  *cmon_node_t;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_get_node_by_hash: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    if(NULL_PTR != CMON_MD_CCONHASH(cmon_md))
    {
        CCONHASH_RNODE *cconhash_rnode;

        cconhash_rnode = cconhash_lookup_rnode(CMON_MD_CCONHASH(cmon_md), hash);
        if(NULL_PTR == cconhash_rnode)
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_hash: "
                        "lookup rnode in connhash failed where hash %ld\n",
                        hash);
            return (EC_FALSE);
        }

        if(EC_FALSE == cconhash_rnode_is_up(cconhash_rnode))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_hash: "
                        "found rnode (tcid %s, replicas %u, status %s) in connhash "
                        "where hash %ld but it is not up \n",
                        c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                        CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                        cconhash_rnode_status(cconhash_rnode),
                        hash);
            return (EC_FALSE);
        }

        return cmon_get_node_by_tcid(cmon_md_id, CCONHASH_RNODE_TCID(cconhash_rnode), 0, cmon_node);
    }

    else if (NULL_PTR != CMON_MD_CMAGLEV(cmon_md))
    {
        CMAGLEV_RNODE *cmaglev_rnode;
        cmaglev_rnode = cmaglev_lookup_rnode(CMON_MD_CMAGLEV(cmon_md), hash);
        if (NULL_PTR == cmaglev_rnode)
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_hash: "
                        "lookup rnode in cmaglev failed where hash %ld\n", hash);
            return (EC_FALSE);
        }

        return cmon_get_node_by_tcid(cmon_md_id, CMAGLEV_RNODE_TCID(cmaglev_rnode), 0, cmon_node);
    }

    else
    {
        UINT32      num;
        UINT32      pos;

        num  = cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md));

        if(0 == num)
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_hash: "
                                                 "no cmon_node exist\n");
            return (EC_FALSE);
        }

        pos  = (hash % num);

        cmon_node_t = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);
        if(NULL_PTR == cmon_node_t)
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_node_by_hash: "
                        "found cmon_node at pos %ld but it is null where hash %ld\n",
                        pos, hash);
            return (EC_FALSE);
        }

        dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_get_node_by_hash: "
                        "found cmon_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) "
                        "at pos %ld where hash %ld\n",
                        cmon_node_t,
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node_t)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node_t)), CMON_NODE_PORT(cmon_node_t),
                        CMON_NODE_MODI(cmon_node_t),
                        cmon_node_state(cmon_node_t),
                        pos, hash
                        );

        cmon_node_clone(cmon_node_t, cmon_node);
    }

    return (EC_TRUE);
}

EC_BOOL cmon_get_node_by_path(const UINT32 cmon_md_id, const uint8_t *path, const uint32_t path_len, CMON_NODE *cmon_node)
{
    UINT32      hash;

    hash = c_crc32_short((uint8_t *)path, path_len);

    return cmon_get_node_by_hash(cmon_md_id, hash, cmon_node);
}

EC_BOOL cmon_set_node_start_pos(const UINT32 cmon_md_id, const UINT32 start_pos)
{
    g_cmon_node_pos = start_pos;
    return (EC_TRUE);
}

EC_BOOL cmon_search_node_up(const UINT32 cmon_md_id, CMON_NODE *cmon_node)
{
    CMON_MD    *cmon_md;

    UINT32      cmon_node_num;
    UINT32      cmon_node_pos;

    cmon_md = CMON_MD_GET(cmon_md_id);

    cmon_node_num = cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md));
    if(0 == cmon_node_num)
    {
        return (EC_FALSE);
    }

    g_cmon_node_pos = (g_cmon_node_pos + 1) % cmon_node_num;

    for(cmon_node_pos = g_cmon_node_pos; cmon_node_pos < cmon_node_num; cmon_node_pos ++)
    {
        CMON_NODE    *cmon_node_t;

        cmon_node_t = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), cmon_node_pos);

        if(NULL_PTR != cmon_node_t
        && EC_TRUE == cmon_node_is_up(cmon_node_t))
        {
            cmon_node_clone(cmon_node_t, cmon_node);
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cmon_get_store_http_srv_of_hot(const UINT32 cmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port)
{
    //CMON_MD    *cmon_md;

    CMON_NODE   cmon_node;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

    char       *dirname;

    CSTRING     cache_path;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_get_store_http_srv_of_hot: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    //cmon_md = CMON_MD_GET(cmon_md_id);

    /*hot cache path*/
    dirname = c_dirname((char *)cstring_get_str(path));
    if(NULL_PTR == dirname)
    {
        return (EC_FALSE);
    }

    cstring_set_str(&cache_path, (const UINT8 *)dirname);/*mount only*/

    if(EC_FALSE == cmon_exist_hot_path(cmon_md_id, &cache_path))
    {
        safe_free(dirname, LOC_CMON_0005);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmon_search_node_up(cmon_md_id, &cmon_node))
    {
        safe_free(dirname, LOC_CMON_0006);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CMON, 6)(LOGSTDOUT, "[DEBUG] cmon_get_store_http_srv_of_hot: "
                "hot path '%s' => cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                dirname,
                c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)),
                c_word_to_ipv4(CMON_NODE_IPADDR(&cmon_node)), CMON_NODE_PORT(&cmon_node),
                CMON_NODE_MODI(&cmon_node),
                cmon_node_state(&cmon_node));

    safe_free(dirname, LOC_CMON_0007);

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd),
                                         CMON_NODE_TCID(&cmon_node),
                                         CMPI_ANY_MASK,
                                         CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_store_http_srv_get: "
                            "not searched tasks cfg of tcid %s\n",
                            c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));
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

EC_BOOL cmon_get_store_http_srv(const UINT32 cmon_md_id, const CSTRING *path, UINT32 *tcid, UINT32 *srv_ipaddr, UINT32 *srv_port)
{
    //CMON_MD    *cmon_md;

    CMON_NODE   cmon_node;
    UINT32      hash;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

    UINT32      check_times;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_get_store_http_srv: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    //cmon_md = CMON_MD_GET(cmon_md_id);

    /*hot cache path*/
    if(CMON_HOT_PATH_SWITCH == SWITCH_ON
    && EC_TRUE == cmon_get_store_http_srv_of_hot(cmon_md_id, path, tcid, srv_ipaddr, srv_port))
    {
        return (EC_TRUE);
    }

    /*not hot cache path*/
    hash = c_crc32_short(CSTRING_STR(path), (size_t)CSTRING_LEN(path));

    cmon_node_init(&cmon_node);

    check_times = 0;
    for(;;)
    {
        check_times ++;
        if(CMON_CHECK_MAX_TIMES < check_times)
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_store_http_srv: "
                        "check times overflow for path '%.*s'\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path));

            cmon_node_clean(&cmon_node);
            return (EC_FALSE);
        }

        if(EC_FALSE == cmon_get_node_by_hash(cmon_md_id, hash, &cmon_node))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_store_http_srv: "
                        "get cmon_node with cmon_md_id %ld and hash %ld of path '%.*s' failed\n",
                        cmon_md_id, hash,
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path));

            cmon_node_clean(&cmon_node);
            return (EC_FALSE);
        }

        if(EC_TRUE == cmon_node_is_up(&cmon_node))
        {
            dbg_log(SEC_0023_CMON, 1)(LOGSTDOUT, "[DEBUG] cmon_get_store_http_srv: "
                        "cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) is up\n",
                        c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(&cmon_node)), CMON_NODE_PORT(&cmon_node),
                        CMON_NODE_MODI(&cmon_node),
                        cmon_node_state(&cmon_node));
            break;
        }

        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_store_http_srv: "
                    "cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) is not up\n",
                    c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)),
                    c_word_to_ipv4(CMON_NODE_IPADDR(&cmon_node)), CMON_NODE_PORT(&cmon_node),
                    CMON_NODE_MODI(&cmon_node),
                    cmon_node_state(&cmon_node));

        cmon_node_clean(&cmon_node);

        /*fall through*/
    }

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd),
                                         CMON_NODE_TCID(&cmon_node),
                                         CMPI_ANY_MASK,
                                         CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_get_store_http_srv: "
                                             "not searched tasks cfg of tcid %s\n",
                                             c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)));
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
    cmon_node_clean(&cmon_node);

    return (EC_TRUE);
}

/*when add a csocket_cnode (->tasks_node)*/
EC_BOOL cmon_callback_when_add(const UINT32 cmon_md_id, TASKS_NODE *tasks_node)
{
    CMON_MD    *cmon_md;

    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_callback_when_add: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_callback_when_add: "
                        "tasks_node (tcid %s, srv %s:%ld)\n",
                        c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)),
                        c_word_to_ipv4(TASKS_NODE_SRVIPADDR(tasks_node)), TASKS_NODE_SRVPORT(tasks_node));

    for(pos = 0; pos < cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md)); pos ++)
    {
        CMON_NODE  *cmon_node;

        cmon_node = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);

        dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_callback_when_add: "
                        "cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) "
                        "v.s tasks_node (tcid %s, srv %s:%ld)\n",
                        c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                        CMON_NODE_MODI(cmon_node),
                        cmon_node_state(cmon_node),
                        c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)),
                        c_word_to_ipv4(TASKS_NODE_SRVIPADDR(tasks_node)), TASKS_NODE_SRVPORT(tasks_node)
                        );

        if(TASKS_NODE_TCID(tasks_node)      == CMON_NODE_TCID(cmon_node)
        && TASKS_NODE_SRVIPADDR(tasks_node) == CMON_NODE_IPADDR(cmon_node)
        && TASKS_NODE_SRVPORT(tasks_node)   == CMON_NODE_PORT(cmon_node))
        {
#if 0
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_callback_when_add: "
                            "set up cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                            cmon_node,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                            CMON_NODE_MODI(cmon_node),
                            cmon_node_state(cmon_node)
                            );
            return cmon_set_node_up(cmon_md_id, cmon_node);
#endif
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_callback_when_add: "
                            "set down cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                            cmon_node,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                            CMON_NODE_MODI(cmon_node),
                            cmon_node_state(cmon_node)
                            );
            /*note: when xfs connect ngx, mark xfs is down but not up*/
            return cmon_set_node_down(cmon_md_id, cmon_node);
        }
    }

    return (EC_TRUE);
}

/*when del a csocket_cnode (->tasks_node)*/
EC_BOOL cmon_callback_when_del(const UINT32 cmon_md_id, TASKS_NODE *tasks_node)
{
    CMON_MD    *cmon_md;

    UINT32      pos;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_callback_when_del: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_callback_when_del: "
                        "tasks_node (tcid %s, srv %s:%ld)\n",
                        c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)),
                        c_word_to_ipv4(TASKS_NODE_SRVIPADDR(tasks_node)), TASKS_NODE_SRVPORT(tasks_node));

    if(EC_FALSE == cvector_is_empty(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
    {
        return (EC_TRUE);
    }

    cmon_md = CMON_MD_GET(cmon_md_id);

    for(pos = 0; pos < cvector_size(CMON_MD_CMON_NODE_VEC(cmon_md)); pos ++)
    {
        CMON_NODE  *cmon_node;

        cmon_node = cvector_get(CMON_MD_CMON_NODE_VEC(cmon_md), pos);

        if(TASKS_NODE_TCID(tasks_node)      == CMON_NODE_TCID(cmon_node)
        && TASKS_NODE_SRVIPADDR(tasks_node) == CMON_NODE_IPADDR(cmon_node)
        && TASKS_NODE_SRVPORT(tasks_node)   == CMON_NODE_PORT(cmon_node))
        {
            dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_callback_when_del: "
                            "set down cmon_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                            cmon_node,
                            c_word_to_ipv4(CMON_NODE_TCID(cmon_node)),
                            c_word_to_ipv4(CMON_NODE_IPADDR(cmon_node)), CMON_NODE_PORT(cmon_node),
                            CMON_NODE_MODI(cmon_node),
                            cmon_node_state(cmon_node)
                            );
            return cmon_set_node_down(cmon_md_id, cmon_node);
        }
    }

    return (EC_TRUE);
}

CMON_HOT_PATH *cmon_hot_path_new()
{
    CMON_HOT_PATH *cmon_hot_path;

    alloc_static_mem(MM_CMON_HOT_PATH, &cmon_hot_path, LOC_CMON_0008);
    if(NULL_PTR != cmon_hot_path)
    {
        cmon_hot_path_init(cmon_hot_path);
    }
    return (cmon_hot_path);
}

EC_BOOL cmon_hot_path_init(CMON_HOT_PATH *cmon_hot_path)
{
    if(NULL_PTR != cmon_hot_path)
    {
        CMON_HOT_PATH_HASH(cmon_hot_path) = 0;

        cstring_init(CMON_HOT_PATH_CSTR(cmon_hot_path), NULL_PTR);
    }
    return (EC_TRUE);
}

EC_BOOL cmon_hot_path_clean(CMON_HOT_PATH *cmon_hot_path)
{
    if(NULL_PTR != cmon_hot_path)
    {
        CMON_HOT_PATH_HASH(cmon_hot_path) = 0;

        cstring_clean(CMON_HOT_PATH_CSTR(cmon_hot_path));
    }
    return (EC_TRUE);
}

EC_BOOL cmon_hot_path_free(CMON_HOT_PATH *cmon_hot_path)
{
    if(NULL_PTR != cmon_hot_path)
    {
        cmon_hot_path_clean(cmon_hot_path);

        free_static_mem(MM_CMON_HOT_PATH, cmon_hot_path, LOC_CMON_0009);
    }

    return (EC_TRUE);
}

EC_BOOL cmon_hot_path_clone(CMON_HOT_PATH *cmon_hot_path_des, const CMON_HOT_PATH *cmon_hot_path_src)
{
    if(NULL_PTR != cmon_hot_path_src && NULL_PTR != cmon_hot_path_des)
    {
        CMON_HOT_PATH_HASH(cmon_hot_path_des) = CMON_HOT_PATH_HASH(cmon_hot_path_src);

        cstring_clone(CMON_HOT_PATH_CSTR(cmon_hot_path_src), CMON_HOT_PATH_CSTR(cmon_hot_path_des));
    }

    return (EC_TRUE);
}

int cmon_hot_path_cmp(const CMON_HOT_PATH *cmon_hot_path_1st, const CMON_HOT_PATH *cmon_hot_path_2nd)
{
    if(CMON_HOT_PATH_HASH(cmon_hot_path_1st) > CMON_HOT_PATH_HASH(cmon_hot_path_2nd))
    {
        return (1);
    }

    if(CMON_HOT_PATH_HASH(cmon_hot_path_1st) < CMON_HOT_PATH_HASH(cmon_hot_path_2nd))
    {
        return (-1);
    }

    return cstring_cmp(CMON_HOT_PATH_CSTR(cmon_hot_path_1st), CMON_HOT_PATH_CSTR(cmon_hot_path_2nd));
}

void cmon_hot_path_print(const CMON_HOT_PATH *cmon_hot_path, LOG *log)
{
    sys_log(log, "cmon_hot_path_print: "
                 "cmon_hot_path %p: hash %u, str '%s'\n",
                 cmon_hot_path,
                 CMON_HOT_PATH_HASH(cmon_hot_path),
                 (char *)cstring_get_str(CMON_HOT_PATH_CSTR(cmon_hot_path))
                 );
    return;
}

EC_BOOL cmon_add_hot_path(const UINT32 cmon_md_id, const CSTRING *path)
{
    CMON_MD         *cmon_md;

    CRB_NODE        *crb_node;
    CMON_HOT_PATH   *cmon_hot_path;

    UINT8            path_last_char;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_add_hot_path: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    /*check validity*/
    if(NULL_PTR == path)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_hot_path: "
                                             "path is null\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(path))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_hot_path: "
                                             "path is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_get_char(path, cstring_get_len(path) - 1, &path_last_char)
    || '/' == (char)path_last_char)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_hot_path: "
                                             "invalid path '%s'\n",
                                             (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    cmon_hot_path = cmon_hot_path_new();
    if(NULL_PTR == cmon_hot_path)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_hot_path: "
                                             "new cmon_hot_path failed\n");
        return (EC_FALSE);
    }

    /*init*/
    CMON_HOT_PATH_HASH(cmon_hot_path) = CMON_MD_HOT_PATH_HASH_FUNC(cmon_md)(
                                                            cstring_get_len(path),
                                                            cstring_get_str(path));

    cstring_clone(path, CMON_HOT_PATH_CSTR(cmon_hot_path));

    crb_node = crb_tree_insert_data(CMON_MD_HOT_PATH_TREE(cmon_md), (void *)cmon_hot_path);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_add_hot_path: "
                                             "add hot path '%s' failed\n",
                                             (char *)cstring_get_str(path));
        cmon_hot_path_free(cmon_hot_path);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cmon_hot_path)/*found duplicate*/
    {
        dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_add_hot_path: "
                                             "found duplicated hot path '%s'\n",
                                             (char *)cstring_get_str(path));
        cmon_hot_path_free(cmon_hot_path);
        return (EC_TRUE);
    }

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_add_hot_path: "
                                         "add hot path '%s' done\n",
                                         (char *)cstring_get_str(path));
    return (EC_TRUE);
}

EC_BOOL cmon_del_hot_path(const UINT32 cmon_md_id, const CSTRING *path)
{
    CMON_MD         *cmon_md;

    CRB_NODE        *crb_node_searched;
    CMON_HOT_PATH    cmon_hot_path_t;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_del_hot_path: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    /*init*/
    CMON_HOT_PATH_HASH(&cmon_hot_path_t) = CMON_MD_HOT_PATH_HASH_FUNC(cmon_md)(
                                                            cstring_get_len(path),
                                                            cstring_get_str(path));

    cstring_set_str(CMON_HOT_PATH_CSTR(&cmon_hot_path_t), cstring_get_str(path));

    crb_node_searched = crb_tree_search_data(CMON_MD_HOT_PATH_TREE(cmon_md), (void *)&cmon_hot_path_t);
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0023_CMON, 5)(LOGSTDOUT, "[DEBUG] cmon_del_hot_path: "
                                             "not found hot path '%s'\n",
                                             (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    crb_tree_delete(CMON_MD_HOT_PATH_TREE(cmon_md), crb_node_searched);

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_del_hot_path: "
                                         "del hot path '%s' done\n",
                                         (char *)cstring_get_str(path));
    return (EC_TRUE);
}

EC_BOOL cmon_exist_hot_path(const UINT32 cmon_md_id, const CSTRING *path)
{
    CMON_MD         *cmon_md;

    CRB_NODE        *crb_node_searched;
    CMON_HOT_PATH    cmon_hot_path_t;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_exist_hot_path: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    if(EC_TRUE == crb_tree_is_empty(CMON_MD_HOT_PATH_TREE(cmon_md)))
    {
        return (EC_FALSE);
    }

    /*init*/
    CMON_HOT_PATH_HASH(&cmon_hot_path_t) = CMON_MD_HOT_PATH_HASH_FUNC(cmon_md)(
                                                            cstring_get_len(path),
                                                            cstring_get_str(path));

    cstring_set_str(CMON_HOT_PATH_CSTR(&cmon_hot_path_t), cstring_get_str(path));

    crb_node_searched = crb_tree_search_data(CMON_MD_HOT_PATH_TREE(cmon_md), (void *)&cmon_hot_path_t);
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0023_CMON, 5)(LOGSTDOUT, "[DEBUG] cmon_exist_hot_path: "
                                             "not found hot path '%s'\n",
                                             (char *)cstring_get_str(path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_exist_hot_path: "
                                         "found hot path '%s'\n",
                                         (char *)cstring_get_str(path));
    return (EC_TRUE);
}

void cmon_print_hot_paths(const UINT32 cmon_md_id, LOG *log)
{
    CMON_MD    *cmon_md;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_print_hot_paths: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    crb_tree_print(log, CMON_MD_HOT_PATH_TREE(cmon_md));

    return;
}

/*format: /<domain>/path */
STATIC_CAST static EC_BOOL __cmon_parse_hot_path_line(const UINT32 cmon_md_id, char *cmon_host_path_start, char *cmon_host_path_end)
{
    //CMON_MD          *cmon_md;

    char                *p;
    CSTRING              path;

    //cmon_md = CMON_MD_GET(cmon_md_id);

    /*locate the first char which is not space*/

    for(p = cmon_host_path_start;isspace(*p); p ++)
    {
        /*do nothing*/
    }

    if('\0' == (*p))
    {
        dbg_log(SEC_0023_CMON, 6)(LOGSTDOUT, "[DEBUG] __cmon_parse_hot_path_line: "
                                             "skip empty line '%.*s'\n",
                                             (uint32_t)(cmon_host_path_end - cmon_host_path_start),
                                             cmon_host_path_start);
        /*skip empty line*/
        return (EC_TRUE);
    }

    if('#' == (*p))
    {
        /*skip commented line*/
        dbg_log(SEC_0023_CMON, 6)(LOGSTDOUT, "[DEBUG] __cmon_parse_hot_path_line: "
                                             "skip commented line '%.*s'\n",
                                             (uint32_t)(cmon_host_path_end - cmon_host_path_start),
                                             cmon_host_path_start);
        return (EC_TRUE);
    }

    dbg_log(SEC_0023_CMON, 6)(LOGSTDOUT, "[DEBUG] __cmon_parse_hot_path_line: "
                                         "handle line '%.*s'\n",
                                         (uint32_t)(cmon_host_path_end - cmon_host_path_start),
                                         cmon_host_path_start);

    c_str_trim_space(p);
    cstring_set_str(&path, (const UINT8 *)p);

    if(EC_FALSE == cmon_add_hot_path(cmon_md_id, &path))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:__cmon_parse_hot_path_line: "
                                             "insert '%s' failed\n",
                                             p);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CMON, 5)(LOGSTDOUT, "[DEBUG] __cmon_parse_hot_path_line: "
                                         "insert '%s' done\n",
                                         p);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cmon_parse_hot_path_file(const UINT32 cmon_md_id, char *cmon_hot_path_start, char *cmon_hot_path_end)
{
    char        *cmon_hot_path_line_start;
    uint32_t     cmon_hot_path_line_no;

    cmon_hot_path_line_start = cmon_hot_path_start;
    cmon_hot_path_line_no    = 1;

    while(cmon_hot_path_line_start < cmon_hot_path_end)
    {
        char  *cmon_hot_path_line_end;

        cmon_hot_path_line_end = cmon_hot_path_line_start;

        while(cmon_hot_path_line_end < cmon_hot_path_end)
        {
            if('\n' == (*cmon_hot_path_line_end ++)) /*also works for line-terminator '\r\n'*/
            {
                break;
            }
        }

        if(cmon_hot_path_line_end > cmon_hot_path_end)
        {
            break;
        }

        *(cmon_hot_path_line_end - 1) = '\0'; /*insert string terminator*/

        dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "error:__cmon_parse_hot_path_file: "
                                             "to parse line %u# '%.*s' failed\n",
                                             cmon_hot_path_line_no,
                                             (uint32_t)(cmon_hot_path_line_end - cmon_hot_path_line_start),
                                             cmon_hot_path_line_start);

        if(EC_FALSE == __cmon_parse_hot_path_line(cmon_md_id, cmon_hot_path_line_start, cmon_hot_path_line_end))
        {
            dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:__cmon_parse_hot_path_file: "
                                                 "parse line %u# '%.*s' failed\n",
                                                 cmon_hot_path_line_no,
                                                 (uint32_t)(cmon_hot_path_line_end - cmon_hot_path_line_start),
                                                 cmon_hot_path_line_start);
            return (EC_FALSE);
        }

        cmon_hot_path_line_no ++;

        cmon_hot_path_line_start = cmon_hot_path_line_end;
    }

    return (EC_TRUE);
}

EC_BOOL cmon_load_hot_paths(const UINT32 cmon_md_id, const CSTRING *path)
{
    //CMON_MD  *cmon_md;

    const char  *fname;
    UINT32       fsize;
    UINT32       offset;
    UINT8       *fcontent;
    int          fd;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_load_hot_paths: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    //cmon_md = CMON_MD_GET(cmon_md_id);

    if(EC_TRUE == cstring_is_empty(path))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                             "path is empty\n");
        return (EC_FALSE);
    }

    fname = (char *)cstring_get_str(path);

    if(EC_FALSE == c_file_exist(fname))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "warn:cmon_load_hot_paths: "
                                             "file '%s' not exist\n",
                                             fname);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "[DEBUG] cmon_load_hot_paths: "
                                         "file '%s' exist\n",
                                         fname);

    if(EC_FALSE == c_file_access(fname, F_OK | R_OK))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                             "access file '%s' failed\n",
                                             fname);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "[DEBUG] cmon_load_hot_paths: "
                                         "access file '%s' done\n",
                                         fname);

    fd = c_file_open(fname, O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                             "open file '%s' failed\n",
                                             fname);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                                "get size of '%s' failed\n",
                                                fname);
        c_file_close(fd);
        return (EC_FALSE);
    }

    if(0 == fsize)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                             "file '%s' size is 0\n",
                                             fname);
        c_file_close(fd);
        return (EC_FALSE);
    }

    fcontent = safe_malloc(fsize, LOC_CMON_0010);
    if(NULL_PTR == fcontent)
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                             "malloc %ld bytes for file '%s' failed\n",
                                             fsize, fname);
        c_file_close(fd);
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, fcontent))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                             "load file '%s' failed\n",
                                             fname);
        c_file_close(fd);
        safe_free(fcontent, LOC_CMON_0011);
        return (EC_FALSE);
    }
    c_file_close(fd);

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_load_hot_paths: "
                                         "load file '%s' from disk done\n",
                                         fname);

    /*parse*/
    if(EC_FALSE == __cmon_parse_hot_path_file(cmon_md_id, (char *)fcontent, (char *)(fcontent + fsize)))
    {
        dbg_log(SEC_0023_CMON, 0)(LOGSTDOUT, "error:cmon_load_hot_paths: "
                                             "parse file '%s' failed\n",
                                             fname);
        safe_free(fcontent, LOC_CMON_0012);
        return (EC_FALSE);
    }
    safe_free(fcontent, LOC_CMON_0013);

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_load_hot_paths: "
                                         "parse file '%s' done\n",
                                         fname);
    return (EC_TRUE);
}

EC_BOOL cmon_unload_hot_paths(const UINT32 cmon_md_id)
{
    CMON_MD  *cmon_md;

#if ( SWITCH_ON == CMON_DEBUG_SWITCH )
    if ( CMON_MD_ID_CHECK_INVALID(cmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmon_unload_hot_paths: cmon module #0x%lx not started.\n",
                cmon_md_id);
        dbg_exit(MD_CMON, cmon_md_id);
    }
#endif/*CMON_DEBUG_SWITCH*/

    cmon_md = CMON_MD_GET(cmon_md_id);

    crb_tree_clean(CMON_MD_HOT_PATH_TREE(cmon_md));

    dbg_log(SEC_0023_CMON, 9)(LOGSTDOUT, "[DEBUG] cmon_load_hot_paths: "
                                         "unload done\n");
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

