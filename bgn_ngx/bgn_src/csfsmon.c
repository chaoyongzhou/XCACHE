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
#include "csfsmon.h"
#include "csfsconhash.h"

#include "cload.h"

#include "findex.inc"

#define CSFSMON_MD_CAPACITY()                  (cbc_md_capacity(MD_CSFSMON))

#define CSFSMON_MD_GET(csfsmon_md_id)     ((CSFSMON_MD *)cbc_md_get(MD_CSFSMON, (csfsmon_md_id)))

#define CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id)  \
    ((CMPI_ANY_MODI != (csfsmon_md_id)) && ((NULL_PTR == CSFSMON_MD_GET(csfsmon_md_id)) || (0 == (CSFSMON_MD_GET(csfsmon_md_id)->usedcounter))))


/**
*   for test only
*
*   to query the status of CSFSMON Module
*
**/
void csfsmon_print_module_status(const UINT32 csfsmon_md_id, LOG *log)
{
    CSFSMON_MD *csfsmon_md;
    UINT32 this_csfsmon_md_id;

    for( this_csfsmon_md_id = 0; this_csfsmon_md_id < CSFSMON_MD_CAPACITY(); this_csfsmon_md_id ++ )
    {
        csfsmon_md = CSFSMON_MD_GET(this_csfsmon_md_id);

        if ( NULL_PTR != csfsmon_md && 0 < csfsmon_md->usedcounter )
        {
            sys_log(log,"CSFSMON Module # %ld : %ld refered\n",
                    this_csfsmon_md_id,
                    csfsmon_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CSFSMON module
*
*
**/
UINT32 csfsmon_free_module_static_mem(const UINT32 csfsmon_md_id)
{
    CSFSMON_MD  *csfsmon_md;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_free_module_static_mem: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CSFSMON_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    free_module_static_mem(MD_CSFSMON, csfsmon_md_id);

    return 0;
}

/**
*
* start CSFSMON module
*
**/
UINT32 csfsmon_start()
{
    CSFSMON_MD *csfsmon_md;
    UINT32      csfsmon_md_id;

    TASK_BRD   *task_brd;

    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CSFSMON , 32);
 
    csfsmon_md_id = cbc_md_new(MD_CSFSMON, sizeof(CSFSMON_MD));
    if(CMPI_ERROR_MODI == csfsmon_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CSFSMON module */
    csfsmon_md = (CSFSMON_MD *)cbc_md_get(MD_CSFSMON, csfsmon_md_id);
    csfsmon_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem(); 

    /*initialize CSFS_NODE vector*/
    cvector_init(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), 16, MM_CSFS_NODE, CVECTOR_LOCK_DISABLE, LOC_CSFSMON_0001);

    if(SWITCH_ON == CSFSMON_CONHASH_SWITCH)
    {
        CSFSMON_MD_CSFSCONHASH(csfsmon_md) = csfsconhash_new(CSFSMON_CONHASH_DEFAULT_HASH_ALGO);
    }
    else
    {
        CSFSMON_MD_CSFSCONHASH(csfsmon_md) = NULL_PTR;
    }

    csfsmon_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)csfsmon_end, csfsmon_md_id);

    dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT, "[DEBUG] csfsmon_start: start CSFSMON module #%ld\n", csfsmon_md_id);

    return ( csfsmon_md_id );
}

/**
*
* end CSFSMON module
*
**/
void csfsmon_end(const UINT32 csfsmon_md_id)
{
    CSFSMON_MD *csfsmon_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)csfsmon_end, csfsmon_md_id);

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);
    if(NULL_PTR == csfsmon_md)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT, "error:csfsmon_end: csfsmon_md_id = %ld not exist.\n", csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
 
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < csfsmon_md->usedcounter )
    {
        csfsmon_md->usedcounter --;
        return ;
    }

    if ( 0 == csfsmon_md->usedcounter )
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT, "error:csfsmon_end: csfsmon_md_id = %ld is not started.\n", csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }

    cvector_clean(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (CVECTOR_DATA_CLEANER)csfs_node_free, LOC_CSFSMON_0002);
    if(NULL_PTR != CSFSMON_MD_CSFSCONHASH(csfsmon_md))
    {
        csfsconhash_free(CSFSMON_MD_CSFSCONHASH(csfsmon_md));
        CSFSMON_MD_CSFSCONHASH(csfsmon_md) = NULL_PTR;
    }
 
    /* free module : */
    //csfsmon_free_module_static_mem(csfsmon_md_id);

    csfsmon_md->usedcounter = 0;

    dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT, "csfsmon_end: stop CSFSMON module #%ld\n", csfsmon_md_id);
    cbc_md_free(MD_CSFSMON, csfsmon_md_id);

    return ;
}

CSFS_NODE *csfs_node_new()
{
    CSFS_NODE *csfs_node;
    alloc_static_mem(MM_CSFS_NODE, &csfs_node, LOC_CSFSMON_0003);
    if(NULL_PTR != csfs_node)
    {
        csfs_node_init(csfs_node);
    }
    return (csfs_node);
}

EC_BOOL csfs_node_init(CSFS_NODE *csfs_node)
{
    if(NULL_PTR != csfs_node)
    {
        CSFS_NODE_TCID(csfs_node)   = CMPI_ERROR_TCID;
        CSFS_NODE_IPADDR(csfs_node) = CMPI_ERROR_IPADDR;
        CSFS_NODE_PORT(csfs_node)   = CMPI_ERROR_SRVPORT;
        CSFS_NODE_MODI(csfs_node)   = CMPI_ERROR_MODI;
        CSFS_NODE_STATE(csfs_node)  = CSFS_NODE_IS_ERR;
     
    }
    return (EC_TRUE);
}

EC_BOOL csfs_node_clean(CSFS_NODE *csfs_node)
{
    if(NULL_PTR != csfs_node)
    {
        CSFS_NODE_TCID(csfs_node)   = CMPI_ERROR_TCID;
        CSFS_NODE_IPADDR(csfs_node) = CMPI_ERROR_IPADDR;
        CSFS_NODE_PORT(csfs_node)   = CMPI_ERROR_SRVPORT;
        CSFS_NODE_MODI(csfs_node)   = CMPI_ERROR_MODI;
        CSFS_NODE_STATE(csfs_node)  = CSFS_NODE_IS_ERR;
     
    }
    return (EC_TRUE);
}

EC_BOOL csfs_node_free(CSFS_NODE *csfs_node)
{
    if(NULL_PTR != csfs_node)
    {
        csfs_node_clean(csfs_node);
        free_static_mem(MM_CSFS_NODE, csfs_node, LOC_CSFSMON_0004);
    }

    return (EC_TRUE);
}

EC_BOOL csfs_node_clone(CSFS_NODE *csfs_node_des, const CSFS_NODE *csfs_node_src)
{
    if(NULL_PTR != csfs_node_src && NULL_PTR != csfs_node_des)
    {
        CSFS_NODE_TCID(csfs_node_des)   = CSFS_NODE_TCID(csfs_node_src);
        CSFS_NODE_IPADDR(csfs_node_des) = CSFS_NODE_IPADDR(csfs_node_src);
        CSFS_NODE_PORT(csfs_node_des)   = CSFS_NODE_PORT(csfs_node_src);
        CSFS_NODE_MODI(csfs_node_des)   = CSFS_NODE_MODI(csfs_node_src);
        CSFS_NODE_STATE(csfs_node_des)  = CSFS_NODE_STATE(csfs_node_src);
    }

    return (EC_TRUE);
}

EC_BOOL csfs_node_is_up(const CSFS_NODE *csfs_node)
{
    if(CSFS_NODE_IS_UP == CSFS_NODE_STATE(csfs_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL csfs_node_is_valid(const CSFS_NODE *csfs_node)
{
    if(CMPI_ERROR_TCID == CSFS_NODE_TCID(csfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_IPADDR == CSFS_NODE_IPADDR(csfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_SRVPORT == CSFS_NODE_PORT(csfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CSFS_NODE_MODI(csfs_node))
    {
        return (EC_FALSE);
    }

    if(CSFS_NODE_IS_ERR == CSFS_NODE_STATE(csfs_node))
    {
        return (EC_FALSE);
    } 
    return (EC_TRUE);
}

int csfs_node_cmp(const CSFS_NODE *csfs_node_1st, const CSFS_NODE *csfs_node_2nd)
{
    if(CSFS_NODE_TCID(csfs_node_1st) > CSFS_NODE_TCID(csfs_node_2nd))
    {
        return (1);
    }

    if(CSFS_NODE_TCID(csfs_node_1st) < CSFS_NODE_TCID(csfs_node_2nd))
    {
        return (-1);
    }

    if(CSFS_NODE_MODI(csfs_node_1st) > CSFS_NODE_MODI(csfs_node_2nd))
    {
        return (1);
    }

    if(CSFS_NODE_MODI(csfs_node_1st) < CSFS_NODE_MODI(csfs_node_2nd))
    {
        return (-1);
    }

    return (0);
}

const char *csfs_node_state(const CSFS_NODE *csfs_node)
{
    if(CSFS_NODE_IS_UP == CSFS_NODE_STATE(csfs_node))
    {
        return (const char *)"UP";
    }
    if(CSFS_NODE_IS_DOWN == CSFS_NODE_STATE(csfs_node))
    {
        return (const char *)"DOWN";
    }

    if(CSFS_NODE_IS_ERR == CSFS_NODE_STATE(csfs_node))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

void csfs_node_print(const CSFS_NODE *csfs_node, LOG *log)
{
    sys_log(log, "csfs_node_print: csfs_node %p: tcid %s, srv %s:%ld, modi %ld, state %s\n", csfs_node,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );
    return;
}

void csfsmon_csfs_node_print(const UINT32 csfsmon_md_id, LOG *log)
{
    CSFSMON_MD *csfsmon_md;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_print: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    cvector_print(log, CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (CVECTOR_DATA_PRINT)csfs_node_print);
 
    return;
}

void csfsmon_csfs_node_list(const UINT32 csfsmon_md_id, CSTRING *cstr)
{
    CSFSMON_MD *csfsmon_md;
    UINT32      pos;
    UINT32      num;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_list: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    num = cvector_size(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md));
    for(pos = 0; pos < num; pos ++)
    {
        CSFS_NODE *csfs_node;
        csfs_node = cvector_get(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
        if(NULL_PTR == csfs_node)
        {
            cstring_format(cstr, "[%ld/%ld] (null)\n", pos, num);
            continue;
        }

        cstring_format(cstr,
                    "[%ld/%ld] (tcid %s, srv %s:%ld, modi %ld, state %s)\n", pos, num,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );

        dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT, "[DEBUG] csfsmon_csfs_node_list: [%ld] cstr:\n%.*s\n", pos,
                    (uint32_t)CSTRING_LEN(cstr), (char *)CSTRING_STR(cstr));  
                     
    }

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT, "[DEBUG] csfsmon_csfs_node_list: list result:\n%.*s\n",
                    (uint32_t)CSTRING_LEN(cstr), (char *)CSTRING_STR(cstr));  
    return;
}

EC_BOOL csfsmon_csfs_node_num(const UINT32 csfsmon_md_id, UINT32 *num)
{
    CSFSMON_MD *csfsmon_md;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_num: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    (*num) = cvector_size(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md));
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_add(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_t;
    UINT32      pos;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_add: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    /*check validity*/
    if(CMPI_ERROR_TCID == CSFS_NODE_TCID(csfs_node) || CMPI_ERROR_MODI == CSFS_NODE_MODI(csfs_node))
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "warn:csfsmon_csfs_node_add: csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) is invalid\n",
                    csfs_node,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );
        return (EC_FALSE);
    }

    pos = cvector_search_front(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (const void *)csfs_node, (CVECTOR_DATA_CMP)csfs_node_cmp);
    if(CVECTOR_ERR_POS != pos)/*found duplicate*/
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "warn:csfsmon_csfs_node_add: found duplicate csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    csfs_node,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );
        return (EC_TRUE);
    }

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), CSFS_NODE_TCID(csfs_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT, "error:csfsmon_csfs_node_add: not searched tasks cfg of tcid %s\n",
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)));
        return (EC_FALSE);
    }

    csfs_node_t = csfs_node_new();
    if(NULL_PTR == csfs_node_t)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                "error:csfsmon_csfs_node_add: new csfs_node failed before insert csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                csfs_node,
                c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                CSFS_NODE_MODI(csfs_node),
                csfs_node_state(csfs_node)
                );
             
        return (EC_FALSE);             
    }

    csfs_node_clone(csfs_node_t, csfs_node);

    CSFS_NODE_IPADDR(csfs_node_t) = TASKS_CFG_SRVIPADDR(tasks_cfg);
    CSFS_NODE_PORT(csfs_node_t)   = TASKS_CFG_CSRVPORT(tasks_cfg); /*http port*/
    CSFS_NODE_STATE(csfs_node_t)  = CSFS_NODE_IS_UP;/*when initialization*/

    cvector_push(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (const void *)csfs_node_t);

    if(NULL_PTR != CSFSMON_MD_CSFSCONHASH(csfsmon_md))
    {
        if(EC_FALSE ==csfsconhash_add_node(CSFSMON_MD_CSFSCONHASH(csfsmon_md),
                                            (uint32_t)CSFS_NODE_TCID(csfs_node_t),
                                            CSFSMON_CONHASH_REPLICAS))
        {
            dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                            "error:csfsmon_csfs_node_add: add csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) to connhash failed\n",
                            csfs_node_t,
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                            c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                            CSFS_NODE_MODI(csfs_node_t),
                            csfs_node_state(csfs_node_t)
                            );
                         
            cvector_pop(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md));
            csfs_node_free(csfs_node_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                        "[DEBUG] csfsmon_csfs_node_add: add csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) to connhash done\n",
                        csfs_node_t,
                        c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                        c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                        CSFS_NODE_MODI(csfs_node_t),
                        csfs_node_state(csfs_node_t)
                        );     
    }

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] csfsmon_csfs_node_add: add csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    csfs_node_t,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                    CSFS_NODE_MODI(csfs_node_t),
                    csfs_node_state(csfs_node_t)
                    ); 
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_del(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_del: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    pos = cvector_search_front(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (const void *)csfs_node, (CVECTOR_DATA_CMP)csfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0169_CSFSMON, 1)(LOGSTDOUT,
                    "warn:csfsmon_csfs_node_del: not found csfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );
        return (EC_TRUE);
    }

    csfs_node_t = cvector_erase(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
    if(NULL_PTR == csfs_node_t)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "warn:csfsmon_csfs_node_del: erase csfs_node is null\n");
        return (EC_TRUE);
    }

    if(NULL_PTR != CSFSMON_MD_CSFSCONHASH(csfsmon_md))
    {
        if(EC_FALSE ==csfsconhash_del_node(CSFSMON_MD_CSFSCONHASH(csfsmon_md),
                                            (uint32_t)CSFS_NODE_TCID(csfs_node_t))
        )
        {
            dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                            "error:csfsmon_csfs_node_del: del csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) from connhash failed\n",
                            csfs_node_t,
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                            c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                            CSFS_NODE_MODI(csfs_node_t),
                            csfs_node_state(csfs_node_t)
                            );
        }
        else
        {
            dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] csfsmon_csfs_node_del: del csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) from connhash done\n",
                            csfs_node_t,
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                            c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                            CSFS_NODE_MODI(csfs_node_t),
                            csfs_node_state(csfs_node_t)
                            );     
        }
    }

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] csfsmon_csfs_node_del: erase csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    csfs_node_t,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                    CSFS_NODE_MODI(csfs_node_t),
                    csfs_node_state(csfs_node_t)
                    );
                 
    csfs_node_free(csfs_node_t);
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_set_up(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_set_up: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    pos = cvector_search_front(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (const void *)csfs_node, (CVECTOR_DATA_CMP)csfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_set_up: not found csfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );
        return (EC_FALSE);
    }

    csfs_node_t = cvector_get(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
    if(NULL_PTR == csfs_node_t)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_set_up: found csfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CSFSMON_MD_CSFSCONHASH(csfsmon_md))
    {
        if(EC_FALSE ==csfsconhash_up_node(CSFSMON_MD_CSFSCONHASH(csfsmon_md),
                                            (uint32_t)CSFS_NODE_TCID(csfs_node_t))
        )
        {
            dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                            "error:csfsmon_csfs_node_set_up: set up csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash failed\n",
                            csfs_node_t,
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                            c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                            CSFS_NODE_MODI(csfs_node_t),
                            csfs_node_state(csfs_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] csfsmon_csfs_node_set_up: set up csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash done\n",
                            csfs_node_t,
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                            c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                            CSFS_NODE_MODI(csfs_node_t),
                            csfs_node_state(csfs_node_t)
                            );     
        }
    }
 
    CSFS_NODE_STATE(csfs_node_t) = CSFS_NODE_IS_UP; /*set up*/

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] csfsmon_csfs_node_set_up: set up csfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    csfs_node_t,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                    CSFS_NODE_MODI(csfs_node_t),
                    csfs_node_state(csfs_node_t)
                    ); 
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_set_down(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_set_down: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    pos = cvector_search_front(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (const void *)csfs_node, (CVECTOR_DATA_CMP)csfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_set_down: not found csfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );
        return (EC_FALSE);
    }

    csfs_node_t = cvector_get(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
    if(NULL_PTR == csfs_node_t)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_set_down: found csfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CSFSMON_MD_CSFSCONHASH(csfsmon_md))
    {
        if(EC_FALSE ==csfsconhash_down_node(CSFSMON_MD_CSFSCONHASH(csfsmon_md),
                                            (uint32_t)CSFS_NODE_TCID(csfs_node_t))
        )
        {
            dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                            "error:csfsmon_csfs_node_set_down: set down csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash failed\n",
                            csfs_node_t,
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                            c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                            CSFS_NODE_MODI(csfs_node_t),
                            csfs_node_state(csfs_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] csfsmon_csfs_node_set_down: set down csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash done\n",
                            csfs_node_t,
                            c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                            c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                            CSFS_NODE_MODI(csfs_node_t),
                            csfs_node_state(csfs_node_t)
                            );     
        }
    }
 
    CSFS_NODE_STATE(csfs_node_t) = CSFS_NODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] csfsmon_csfs_node_set_down: set down csfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    csfs_node_t,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                    CSFS_NODE_MODI(csfs_node_t),
                    csfs_node_state(csfs_node_t)
                    ); 
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_is_up(const UINT32 csfsmon_md_id, const CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_is_up: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    pos = cvector_search_front(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (const void *)csfs_node, (CVECTOR_DATA_CMP)csfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_is_up: not found csfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node)
                    );
        return (EC_FALSE);
    }

    csfs_node_t = cvector_get(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
    if(NULL_PTR == csfs_node_t)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_is_up: found csfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node)), CSFS_NODE_PORT(csfs_node),
                    CSFS_NODE_MODI(csfs_node),
                    csfs_node_state(csfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] csfsmon_csfs_node_is_up: check csfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    csfs_node_t,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                    CSFS_NODE_MODI(csfs_node_t),
                    csfs_node_state(csfs_node_t)
                    ); 
                 
    if(CSFS_NODE_IS_UP == CSFS_NODE_STATE(csfs_node_t))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

EC_BOOL csfsmon_csfs_node_get_by_pos(const UINT32 csfsmon_md_id, const UINT32 pos, CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_t;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_get_by_pos: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_get_by_pos: pos is error\n");
        return (EC_FALSE);
    }

    csfs_node_t = cvector_get(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
    if(NULL_PTR == csfs_node_t)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_get_by_pos: found csfs_node at pos %ld but it is null\n", pos);
        return (EC_FALSE);
    }

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] csfsmon_csfs_node_get_by_pos: found csfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld\n",
                    csfs_node_t,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                    CSFS_NODE_MODI(csfs_node_t),
                    csfs_node_state(csfs_node_t),
                    pos
                    );
                 
    csfs_node_clone(csfs_node, csfs_node_t);
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_get_by_tcid(const UINT32 csfsmon_md_id, const UINT32 tcid, const UINT32 modi, CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_searched;
    CSFS_NODE   csfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_get_by_tcid: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    CSFS_NODE_TCID(&csfs_node_t) = tcid;
    CSFS_NODE_MODI(&csfs_node_t) = modi;

    pos = cvector_search_front(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), (const void *)&csfs_node_t, (CVECTOR_DATA_CMP)csfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_get_by_tcid: not found csfs_node with (tcid %s, modi %ld)\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    CSFS_NODE_MODI(csfs_node)
                    );
        return (EC_FALSE);
    }

    csfs_node_searched = cvector_get(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
    if(NULL_PTR == csfs_node_searched)
    {
        dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                    "error:csfsmon_csfs_node_get_by_tcid: found csfs_node with (tcid %s, modi %ld) at pos %ld but it is null\n",
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node)),
                    CSFS_NODE_MODI(csfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] csfsmon_csfs_node_get_by_tcid: found csfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    csfs_node_searched,
                    c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_searched)),
                    c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_searched)), CSFS_NODE_PORT(csfs_node_searched),
                    CSFS_NODE_MODI(csfs_node_searched),
                    csfs_node_state(csfs_node_searched)
                    );

    csfs_node_clone(csfs_node, csfs_node_searched);
                 
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_get_by_hash(const UINT32 csfsmon_md_id, const UINT32 hash, CSFS_NODE *csfs_node)
{
    CSFSMON_MD *csfsmon_md;
    CSFS_NODE  *csfs_node_t;

#if ( SWITCH_ON == CSFSMON_DEBUG_SWITCH )
    if ( CSFSMON_MD_ID_CHECK_INVALID(csfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfsmon_csfs_node_get_by_hash: csfsmon module #0x%lx not started.\n",
                csfsmon_md_id);
        dbg_exit(MD_CSFSMON, csfsmon_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsmon_md = CSFSMON_MD_GET(csfsmon_md_id);

    if(NULL_PTR != CSFSMON_MD_CSFSCONHASH(csfsmon_md))
    {
        CSFSCONHASH_RNODE *csfsconhash_rnode;

        csfsconhash_rnode = csfsconhash_lookup_rnode(CSFSMON_MD_CSFSCONHASH(csfsmon_md), hash);
        if(NULL_PTR == csfsconhash_rnode)
        {
            dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                        "error:csfsmon_csfs_node_get_by_hash: lookup rnode in connhash failed where hash %ld\n", hash);
            return (EC_FALSE);
        }

        if(EC_FALSE == csfsconhash_rnode_is_up(csfsconhash_rnode))
        {
            dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                        "error:csfsmon_csfs_node_get_by_hash: found rnode (tcid %s, replicas %u, status %s) in connhash where hash %ld but it is not up \n",
                        c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                        CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                        csfsconhash_rnode_status(csfsconhash_rnode),
                        hash);
            return (EC_FALSE);
        }

        return csfsmon_csfs_node_get_by_tcid(csfsmon_md_id, CSFSCONHASH_RNODE_TCID(csfsconhash_rnode), 0, csfs_node);
    }
    else
    {
        UINT32      num;
        UINT32      pos;
 
        num  = cvector_size(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md));

        pos  = (hash % num);

        csfs_node_t = cvector_get(CSFSMON_MD_CSFS_NODE_VEC(csfsmon_md), pos);
        if(NULL_PTR == csfs_node_t)
        {
            dbg_log(SEC_0169_CSFSMON, 0)(LOGSTDOUT,
                        "error:csfsmon_csfs_node_get_by_hash: found csfs_node at pos %ld but it is null where hash %ld\n", pos, hash);
            return (EC_FALSE);
        }

        dbg_log(SEC_0169_CSFSMON, 9)(LOGSTDOUT,
                        "[DEBUG] csfsmon_csfs_node_get_by_hash: found csfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld where hash %ld\n",
                        csfs_node_t,
                        c_word_to_ipv4(CSFS_NODE_TCID(csfs_node_t)),
                        c_word_to_ipv4(CSFS_NODE_IPADDR(csfs_node_t)), CSFS_NODE_PORT(csfs_node_t),
                        CSFS_NODE_MODI(csfs_node_t),
                        csfs_node_state(csfs_node_t),
                        pos, hash
                        );
                     
        csfs_node_clone(csfs_node, csfs_node_t); 
    }
    return (EC_TRUE);
}

EC_BOOL csfsmon_csfs_node_get_by_path(const UINT32 csfsmon_md_id, const uint8_t *path, const uint32_t path_len, CSFS_NODE *csfs_node)
{
    UINT32      hash;

    hash = c_crc32_short((uint8_t *)path, path_len);

    return csfsmon_csfs_node_get_by_hash(csfsmon_md_id, hash, csfs_node);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

