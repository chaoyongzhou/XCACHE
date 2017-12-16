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
#include "chfsmon.h"
#include "chfsconhash.h"

#include "cload.h"

#include "findex.inc"

#define CHFSMON_MD_CAPACITY()                  (cbc_md_capacity(MD_CHFSMON))

#define CHFSMON_MD_GET(chfsmon_md_id)     ((CHFSMON_MD *)cbc_md_get(MD_CHFSMON, (chfsmon_md_id)))

#define CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id)  \
    ((CMPI_ANY_MODI != (chfsmon_md_id)) && ((NULL_PTR == CHFSMON_MD_GET(chfsmon_md_id)) || (0 == (CHFSMON_MD_GET(chfsmon_md_id)->usedcounter))))


/**
*   for test only
*
*   to query the status of CHFSMON Module
*
**/
void chfsmon_print_module_status(const UINT32 chfsmon_md_id, LOG *log)
{
    CHFSMON_MD *chfsmon_md;
    UINT32 this_chfsmon_md_id;

    for( this_chfsmon_md_id = 0; this_chfsmon_md_id < CHFSMON_MD_CAPACITY(); this_chfsmon_md_id ++ )
    {
        chfsmon_md = CHFSMON_MD_GET(this_chfsmon_md_id);

        if ( NULL_PTR != chfsmon_md && 0 < chfsmon_md->usedcounter )
        {
            sys_log(log,"CHFSMON Module # %u : %u refered\n",
                    this_chfsmon_md_id,
                    chfsmon_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CHFSMON module
*
*
**/
UINT32 chfsmon_free_module_static_mem(const UINT32 chfsmon_md_id)
{
    CHFSMON_MD  *chfsmon_md;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_free_module_static_mem: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CHFSMON_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    free_module_static_mem(MD_CHFSMON, chfsmon_md_id);

    return 0;
}

/**
*
* start CHFSMON module
*
**/
UINT32 chfsmon_start()
{
    CHFSMON_MD *chfsmon_md;
    UINT32      chfsmon_md_id;

    TASK_BRD   *task_brd;

    task_brd = task_brd_default_get();
 
    chfsmon_md_id = cbc_md_new(MD_CHFSMON, sizeof(CHFSMON_MD));
    if(CMPI_ERROR_MODI == chfsmon_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CHFSMON module */
    chfsmon_md = (CHFSMON_MD *)cbc_md_get(MD_CHFSMON, chfsmon_md_id);
    chfsmon_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem(); 

    /*initialize CHFS_NODE vector*/
    cvector_init(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), 16, MM_CHFS_NODE, CVECTOR_LOCK_DISABLE, LOC_CHFSMON_0001);

    if(SWITCH_ON == CHFSMON_CONHASH_SWITCH)
    {
        CHFSMON_MD_CHFSCONHASH(chfsmon_md) = chfsconhash_new(CHFSMON_CONHASH_DEFAULT_HASH_ALGO);
    }
    else
    {
        CHFSMON_MD_CHFSCONHASH(chfsmon_md) = NULL_PTR;
    }

    chfsmon_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)chfsmon_end, chfsmon_md_id);

    dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT, "[DEBUG] chfsmon_start: start CHFSMON module #%u\n", chfsmon_md_id);

    return ( chfsmon_md_id );
}

/**
*
* end CHFSMON module
*
**/
void chfsmon_end(const UINT32 chfsmon_md_id)
{
    CHFSMON_MD *chfsmon_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)chfsmon_end, chfsmon_md_id);

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);
    if(NULL_PTR == chfsmon_md)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT, "error:chfsmon_end: chfsmon_md_id = %u not exist.\n", chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
 
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < chfsmon_md->usedcounter )
    {
        chfsmon_md->usedcounter --;
        return ;
    }

    if ( 0 == chfsmon_md->usedcounter )
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT, "error:chfsmon_end: chfsmon_md_id = %u is not started.\n", chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }

    cvector_clean(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (CVECTOR_DATA_CLEANER)chfs_node_free, LOC_CHFSMON_0002);
    if(NULL_PTR != CHFSMON_MD_CHFSCONHASH(chfsmon_md))
    {
        chfsconhash_free(CHFSMON_MD_CHFSCONHASH(chfsmon_md));
        CHFSMON_MD_CHFSCONHASH(chfsmon_md) = NULL_PTR;
    }
 
    /* free module : */
    //chfsmon_free_module_static_mem(chfsmon_md_id);

    chfsmon_md->usedcounter = 0;

    dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT, "chfsmon_end: stop CHFSMON module #%u\n", chfsmon_md_id);
    cbc_md_free(MD_CHFSMON, chfsmon_md_id);

    return ;
}

CHFS_NODE *chfs_node_new()
{
    CHFS_NODE *chfs_node;
    alloc_static_mem(MM_CHFS_NODE, &chfs_node, LOC_CHFSMON_0003);
    if(NULL_PTR != chfs_node)
    {
        chfs_node_init(chfs_node);
    }
    return (chfs_node);
}

EC_BOOL chfs_node_init(CHFS_NODE *chfs_node)
{
    if(NULL_PTR != chfs_node)
    {
        CHFS_NODE_TCID(chfs_node)   = CMPI_ERROR_TCID;
        CHFS_NODE_IPADDR(chfs_node) = CMPI_ERROR_IPADDR;
        CHFS_NODE_PORT(chfs_node)   = CMPI_ERROR_SRVPORT;
        CHFS_NODE_MODI(chfs_node)   = CMPI_ERROR_MODI;
        CHFS_NODE_STATE(chfs_node)  = CHFS_NODE_IS_ERR;
     
    }
    return (EC_TRUE);
}

EC_BOOL chfs_node_clean(CHFS_NODE *chfs_node)
{
    if(NULL_PTR != chfs_node)
    {
        CHFS_NODE_TCID(chfs_node)   = CMPI_ERROR_TCID;
        CHFS_NODE_IPADDR(chfs_node) = CMPI_ERROR_IPADDR;
        CHFS_NODE_PORT(chfs_node)   = CMPI_ERROR_SRVPORT;
        CHFS_NODE_MODI(chfs_node)   = CMPI_ERROR_MODI;
        CHFS_NODE_STATE(chfs_node)  = CHFS_NODE_IS_ERR;
     
    }
    return (EC_TRUE);
}

EC_BOOL chfs_node_free(CHFS_NODE *chfs_node)
{
    if(NULL_PTR != chfs_node)
    {
        chfs_node_clean(chfs_node);
        free_static_mem(MM_CHFS_NODE, chfs_node, LOC_CHFSMON_0004);
    }

    return (EC_TRUE);
}

EC_BOOL chfs_node_clone(CHFS_NODE *chfs_node_des, const CHFS_NODE *chfs_node_src)
{
    if(NULL_PTR != chfs_node_src && NULL_PTR != chfs_node_des)
    {
        CHFS_NODE_TCID(chfs_node_des)   = CHFS_NODE_TCID(chfs_node_src);
        CHFS_NODE_IPADDR(chfs_node_des) = CHFS_NODE_IPADDR(chfs_node_src);
        CHFS_NODE_PORT(chfs_node_des)   = CHFS_NODE_PORT(chfs_node_src);
        CHFS_NODE_MODI(chfs_node_des)   = CHFS_NODE_MODI(chfs_node_src);
        CHFS_NODE_STATE(chfs_node_des)  = CHFS_NODE_STATE(chfs_node_src);
    }

    return (EC_TRUE);
}

EC_BOOL chfs_node_is_up(const CHFS_NODE *chfs_node)
{
    if(CHFS_NODE_IS_UP == CHFS_NODE_STATE(chfs_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chfs_node_is_valid(const CHFS_NODE *chfs_node)
{
    if(CMPI_ERROR_TCID == CHFS_NODE_TCID(chfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_IPADDR == CHFS_NODE_IPADDR(chfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_SRVPORT == CHFS_NODE_PORT(chfs_node))
    {
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CHFS_NODE_MODI(chfs_node))
    {
        return (EC_FALSE);
    }

    if(CHFS_NODE_IS_ERR == CHFS_NODE_STATE(chfs_node))
    {
        return (EC_FALSE);
    } 
    return (EC_TRUE);
}

int chfs_node_cmp(const CHFS_NODE *chfs_node_1st, const CHFS_NODE *chfs_node_2nd)
{
    if(CHFS_NODE_TCID(chfs_node_1st) > CHFS_NODE_TCID(chfs_node_2nd))
    {
        return (1);
    }

    if(CHFS_NODE_TCID(chfs_node_1st) < CHFS_NODE_TCID(chfs_node_2nd))
    {
        return (-1);
    }

    if(CHFS_NODE_MODI(chfs_node_1st) > CHFS_NODE_MODI(chfs_node_2nd))
    {
        return (1);
    }

    if(CHFS_NODE_MODI(chfs_node_1st) < CHFS_NODE_MODI(chfs_node_2nd))
    {
        return (-1);
    }

    return (0);
}

const char *chfs_node_state(const CHFS_NODE *chfs_node)
{
    if(CHFS_NODE_IS_UP == CHFS_NODE_STATE(chfs_node))
    {
        return (const char *)"UP";
    }
    if(CHFS_NODE_IS_DOWN == CHFS_NODE_STATE(chfs_node))
    {
        return (const char *)"DOWN";
    }

    if(CHFS_NODE_IS_ERR == CHFS_NODE_STATE(chfs_node))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

void chfs_node_print(const CHFS_NODE *chfs_node, LOG *log)
{
    sys_log(log, "chfs_node_print: chfs_node %p: tcid %s, srv %s:%ld, modi %ld, state %s\n", chfs_node,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );
    return;
}

void chfsmon_chfs_node_print(const UINT32 chfsmon_md_id, LOG *log)
{
    CHFSMON_MD *chfsmon_md;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_print: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    cvector_print(log, CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (CVECTOR_DATA_PRINT)chfs_node_print);
 
    return;
}

void chfsmon_chfs_node_list(const UINT32 chfsmon_md_id, CSTRING *cstr)
{
    CHFSMON_MD *chfsmon_md;
    UINT32      pos;
    UINT32      num;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_list: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    num = cvector_size(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md));
    for(pos = 0; pos < num; pos ++)
    {
        CHFS_NODE *chfs_node;
        chfs_node = cvector_get(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
        if(NULL_PTR == chfs_node)
        {
            cstring_format(cstr, "[%ld/%ld] (null)\n", pos, num);
            continue;
        }

        cstring_format(cstr,
                    "[%ld/%ld] (tcid %s, srv %s:%ld, modi %ld, state %s)\n", pos, num,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );

        dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT, "[DEBUG] chfsmon_chfs_node_list: [%ld] cstr:\n%.*s\n", pos,
                    (uint32_t)CSTRING_LEN(cstr), (char *)CSTRING_STR(cstr));  
                     
    }

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT, "[DEBUG] chfsmon_chfs_node_list: list result:\n%.*s\n",
                    (uint32_t)CSTRING_LEN(cstr), (char *)CSTRING_STR(cstr));  
    return;
}

EC_BOOL chfsmon_chfs_node_num(const UINT32 chfsmon_md_id, UINT32 *num)
{
    CHFSMON_MD *chfsmon_md;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_num: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    (*num) = cvector_size(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md));
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_add(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_t;
    UINT32      pos;

    TASK_BRD   *task_brd;
    TASKS_CFG  *tasks_cfg;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_add: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    /*check validity*/
    if(CMPI_ERROR_TCID == CHFS_NODE_TCID(chfs_node) || CMPI_ERROR_MODI == CHFS_NODE_MODI(chfs_node))
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "warn:chfsmon_chfs_node_add: chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) is invalid\n",
                    chfs_node,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );
        return (EC_FALSE);
    }

    pos = cvector_search_front(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (const void *)chfs_node, (CVECTOR_DATA_CMP)chfs_node_cmp);
    if(CVECTOR_ERR_POS != pos)/*found duplicate*/
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "warn:chfsmon_chfs_node_add: found duplicate chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    chfs_node,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );
        return (EC_TRUE);
    }

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), CHFS_NODE_TCID(chfs_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT, "error:chfsmon_chfs_node_add: not searched tasks cfg of tcid %s\n",
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)));
        return (EC_FALSE);
    }

    chfs_node_t = chfs_node_new();
    if(NULL_PTR == chfs_node_t)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                "error:chfsmon_chfs_node_add: new chfs_node failed before insert chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                chfs_node,
                c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                CHFS_NODE_MODI(chfs_node),
                chfs_node_state(chfs_node)
                );
             
        return (EC_FALSE);             
    }

    chfs_node_clone(chfs_node_t, chfs_node);

    CHFS_NODE_IPADDR(chfs_node_t) = TASKS_CFG_SRVIPADDR(tasks_cfg);
    CHFS_NODE_PORT(chfs_node_t)   = TASKS_CFG_CSRVPORT(tasks_cfg); /*http port*/
    CHFS_NODE_STATE(chfs_node_t)  = CHFS_NODE_IS_UP;/*when initialization*/

    cvector_push(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (const void *)chfs_node_t);

    if(NULL_PTR != CHFSMON_MD_CHFSCONHASH(chfsmon_md))
    {
        if(EC_FALSE ==chfsconhash_add_node(CHFSMON_MD_CHFSCONHASH(chfsmon_md),
                                            (uint32_t)CHFS_NODE_TCID(chfs_node_t),
                                            CHFSMON_CONHASH_REPLICAS))
        {
            dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                            "error:chfsmon_chfs_node_add: add chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) to connhash failed\n",
                            chfs_node_t,
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                            c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                            CHFS_NODE_MODI(chfs_node_t),
                            chfs_node_state(chfs_node_t)
                            );
                         
            cvector_pop(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md));
            chfs_node_free(chfs_node_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                        "[DEBUG] chfsmon_chfs_node_add: add chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) to connhash done\n",
                        chfs_node_t,
                        c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                        c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                        CHFS_NODE_MODI(chfs_node_t),
                        chfs_node_state(chfs_node_t)
                        );     
    }

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] chfsmon_chfs_node_add: add chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    chfs_node_t,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                    CHFS_NODE_MODI(chfs_node_t),
                    chfs_node_state(chfs_node_t)
                    ); 
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_del(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_del: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    pos = cvector_search_front(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (const void *)chfs_node, (CVECTOR_DATA_CMP)chfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0161_CHFSMON, 1)(LOGSTDOUT,
                    "warn:chfsmon_chfs_node_del: not found chfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );
        return (EC_TRUE);
    }

    chfs_node_t = cvector_erase(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
    if(NULL_PTR == chfs_node_t)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "warn:chfsmon_chfs_node_del: erase chfs_node is null\n");
        return (EC_TRUE);
    }

    if(NULL_PTR != CHFSMON_MD_CHFSCONHASH(chfsmon_md))
    {
        if(EC_FALSE ==chfsconhash_del_node(CHFSMON_MD_CHFSCONHASH(chfsmon_md),
                                            (uint32_t)CHFS_NODE_TCID(chfs_node_t))
        )
        {
            dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                            "error:chfsmon_chfs_node_del: del chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) from connhash failed\n",
                            chfs_node_t,
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                            c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                            CHFS_NODE_MODI(chfs_node_t),
                            chfs_node_state(chfs_node_t)
                            );
        }
        else
        {
            dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] chfsmon_chfs_node_del: del chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) from connhash done\n",
                            chfs_node_t,
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                            c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                            CHFS_NODE_MODI(chfs_node_t),
                            chfs_node_state(chfs_node_t)
                            );     
        }
    }

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] chfsmon_chfs_node_del: erase chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    chfs_node_t,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                    CHFS_NODE_MODI(chfs_node_t),
                    chfs_node_state(chfs_node_t)
                    );
                 
    chfs_node_free(chfs_node_t);
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_set_up(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_set_up: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    pos = cvector_search_front(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (const void *)chfs_node, (CVECTOR_DATA_CMP)chfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_set_up: not found chfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );
        return (EC_FALSE);
    }

    chfs_node_t = cvector_get(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
    if(NULL_PTR == chfs_node_t)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_set_up: found chfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CHFSMON_MD_CHFSCONHASH(chfsmon_md))
    {
        if(EC_FALSE ==chfsconhash_up_node(CHFSMON_MD_CHFSCONHASH(chfsmon_md),
                                            (uint32_t)CHFS_NODE_TCID(chfs_node_t))
        )
        {
            dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                            "error:chfsmon_chfs_node_set_up: set up chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash failed\n",
                            chfs_node_t,
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                            c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                            CHFS_NODE_MODI(chfs_node_t),
                            chfs_node_state(chfs_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] chfsmon_chfs_node_set_up: set up chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash done\n",
                            chfs_node_t,
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                            c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                            CHFS_NODE_MODI(chfs_node_t),
                            chfs_node_state(chfs_node_t)
                            );     
        }
    }
 
    CHFS_NODE_STATE(chfs_node_t) = CHFS_NODE_IS_UP; /*set up*/

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] chfsmon_chfs_node_set_up: set up chfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    chfs_node_t,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                    CHFS_NODE_MODI(chfs_node_t),
                    chfs_node_state(chfs_node_t)
                    ); 
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_set_down(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_set_down: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    pos = cvector_search_front(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (const void *)chfs_node, (CVECTOR_DATA_CMP)chfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_set_down: not found chfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );
        return (EC_FALSE);
    }

    chfs_node_t = cvector_get(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
    if(NULL_PTR == chfs_node_t)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_set_down: found chfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    if(NULL_PTR != CHFSMON_MD_CHFSCONHASH(chfsmon_md))
    {
        if(EC_FALSE ==chfsconhash_down_node(CHFSMON_MD_CHFSCONHASH(chfsmon_md),
                                            (uint32_t)CHFS_NODE_TCID(chfs_node_t))
        )
        {
            dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                            "error:chfsmon_chfs_node_set_down: set down chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash failed\n",
                            chfs_node_t,
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                            c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                            CHFS_NODE_MODI(chfs_node_t),
                            chfs_node_state(chfs_node_t)
                            );
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                            "[DEBUG] chfsmon_chfs_node_set_down: set down chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) in connhash done\n",
                            chfs_node_t,
                            c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                            c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                            CHFS_NODE_MODI(chfs_node_t),
                            chfs_node_state(chfs_node_t)
                            );     
        }
    }
 
    CHFS_NODE_STATE(chfs_node_t) = CHFS_NODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] chfsmon_chfs_node_set_down: set down chfs_node %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    chfs_node_t,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                    CHFS_NODE_MODI(chfs_node_t),
                    chfs_node_state(chfs_node_t)
                    ); 
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_is_up(const UINT32 chfsmon_md_id, const CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_is_up: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    pos = cvector_search_front(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (const void *)chfs_node, (CVECTOR_DATA_CMP)chfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_is_up: not found chfs_node (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node)
                    );
        return (EC_FALSE);
    }

    chfs_node_t = cvector_get(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
    if(NULL_PTR == chfs_node_t)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_is_up: found chfs_node (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld but it is null\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node)), CHFS_NODE_PORT(chfs_node),
                    CHFS_NODE_MODI(chfs_node),
                    chfs_node_state(chfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] chfsmon_chfs_node_is_up: check chfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) done\n",
                    chfs_node_t,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                    CHFS_NODE_MODI(chfs_node_t),
                    chfs_node_state(chfs_node_t)
                    ); 
                 
    if(CHFS_NODE_IS_UP == CHFS_NODE_STATE(chfs_node_t))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

EC_BOOL chfsmon_chfs_node_get_by_pos(const UINT32 chfsmon_md_id, const UINT32 pos, CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_t;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_get_by_pos: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_get_by_pos: pos is error\n");
        return (EC_FALSE);
    }

    chfs_node_t = cvector_get(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
    if(NULL_PTR == chfs_node_t)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_get_by_pos: found chfs_node at pos %ld but it is null\n", pos);
        return (EC_FALSE);
    }

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] chfsmon_chfs_node_get_by_pos: found chfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld\n",
                    chfs_node_t,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                    CHFS_NODE_MODI(chfs_node_t),
                    chfs_node_state(chfs_node_t),
                    pos
                    );
                 
    chfs_node_clone(chfs_node, chfs_node_t);
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_get_by_tcid(const UINT32 chfsmon_md_id, const UINT32 tcid, const UINT32 modi, CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_searched;
    CHFS_NODE   chfs_node_t;
    UINT32      pos;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_get_by_tcid: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    CHFS_NODE_TCID(&chfs_node_t) = tcid;
    CHFS_NODE_MODI(&chfs_node_t) = modi;

    pos = cvector_search_front(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), (const void *)&chfs_node_t, (CVECTOR_DATA_CMP)chfs_node_cmp);
    if(CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_get_by_tcid: not found chfs_node with (tcid %s, modi %ld)\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    CHFS_NODE_MODI(chfs_node)
                    );
        return (EC_FALSE);
    }

    chfs_node_searched = cvector_get(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
    if(NULL_PTR == chfs_node_searched)
    {
        dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                    "error:chfsmon_chfs_node_get_by_tcid: found chfs_node with (tcid %s, modi %ld) at pos %ld but it is null\n",
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node)),
                    CHFS_NODE_MODI(chfs_node),
                    pos
                    );
        return (EC_FALSE);
    }

    dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                    "[DEBUG] chfsmon_chfs_node_get_by_tcid: found chfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s)\n",
                    chfs_node_searched,
                    c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_searched)),
                    c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_searched)), CHFS_NODE_PORT(chfs_node_searched),
                    CHFS_NODE_MODI(chfs_node_searched),
                    chfs_node_state(chfs_node_searched)
                    );

    chfs_node_clone(chfs_node, chfs_node_searched);
                 
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_get_by_hash(const UINT32 chfsmon_md_id, const UINT32 hash, CHFS_NODE *chfs_node)
{
    CHFSMON_MD *chfsmon_md;
    CHFS_NODE  *chfs_node_t;

#if ( SWITCH_ON == CHFSMON_DEBUG_SWITCH )
    if ( CHFSMON_MD_ID_CHECK_INVALID(chfsmon_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfsmon_chfs_node_get_by_hash: chfsmon module #0x%lx not started.\n",
                chfsmon_md_id);
        dbg_exit(MD_CHFSMON, chfsmon_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsmon_md = CHFSMON_MD_GET(chfsmon_md_id);

    if(NULL_PTR != CHFSMON_MD_CHFSCONHASH(chfsmon_md))
    {
        CHFSCONHASH_RNODE *chfsconhash_rnode;

        chfsconhash_rnode = chfsconhash_lookup_rnode(CHFSMON_MD_CHFSCONHASH(chfsmon_md), hash);
        if(NULL_PTR == chfsconhash_rnode)
        {
            dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                        "error:chfsmon_chfs_node_get_by_hash: lookup rnode in connhash failed where hash %ld\n", hash);
            return (EC_FALSE);
        }

        if(EC_FALSE == chfsconhash_rnode_is_up(chfsconhash_rnode))
        {
            dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                        "error:chfsmon_chfs_node_get_by_hash: found rnode (tcid %s, replicas %u, status %s) in connhash where hash %ld but it is not up \n",
                        c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                        CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                        chfsconhash_rnode_status(chfsconhash_rnode),
                        hash);
            return (EC_FALSE);
        }

        return chfsmon_chfs_node_get_by_tcid(chfsmon_md_id, CHFSCONHASH_RNODE_TCID(chfsconhash_rnode), 0, chfs_node);
    }
    else
    {
        UINT32      num;
        UINT32      pos;
 
        num  = cvector_size(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md));

        pos  = (hash % num);

        chfs_node_t = cvector_get(CHFSMON_MD_CHFS_NODE_VEC(chfsmon_md), pos);
        if(NULL_PTR == chfs_node_t)
        {
            dbg_log(SEC_0161_CHFSMON, 0)(LOGSTDOUT,
                        "error:chfsmon_chfs_node_get_by_hash: found chfs_node at pos %ld but it is null where hash %ld\n", pos, hash);
            return (EC_FALSE);
        }

        dbg_log(SEC_0161_CHFSMON, 9)(LOGSTDOUT,
                        "[DEBUG] chfsmon_chfs_node_get_by_hash: found chfs_node_t %p (tcid %s, srv %s:%ld, modi %ld, state %s) at pos %ld where hash %ld\n",
                        chfs_node_t,
                        c_word_to_ipv4(CHFS_NODE_TCID(chfs_node_t)),
                        c_word_to_ipv4(CHFS_NODE_IPADDR(chfs_node_t)), CHFS_NODE_PORT(chfs_node_t),
                        CHFS_NODE_MODI(chfs_node_t),
                        chfs_node_state(chfs_node_t),
                        pos, hash
                        );
                     
        chfs_node_clone(chfs_node, chfs_node_t); 
    }
    return (EC_TRUE);
}

EC_BOOL chfsmon_chfs_node_get_by_path(const UINT32 chfsmon_md_id, const uint8_t *path, const uint32_t path_len, CHFS_NODE *chfs_node)
{
    UINT32      hash;

    hash = c_crc32_short((uint8_t *)path, path_len);

    return chfsmon_chfs_node_get_by_hash(chfsmon_md_id, hash, chfs_node);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

