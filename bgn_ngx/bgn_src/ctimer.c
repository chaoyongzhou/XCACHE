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

#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"

#include "ctimer.h"

#include "cmpic.inc"
#include "debug.h"

#include "task.inc"
#include "task.h"
#include "findex.inc"


static CTIMER_MD g_ctimer_md = CTIMER_MD_INITIALIZER;

#define CTIMER_MD_GET() (&g_ctimer_md)

/**
*
* start CTIMER module
*
**/
UINT32 ctimer_start(const UINT32 ctimer_expire_delta)
{
    CTIMER_MD *ctimer_md;

    /* initialize new one CTIMER module */
    ctimer_md = CTIMER_MD_GET();

    /* create a new module node */
    init_static_mem();

    ctimer_md->ctimer_node_list = clist_new(MM_IGNORE, LOC_CTIMER_0001);
    ctimer_md->ctimer_expire_delta = ctimer_expire_delta;

    CITIMER_CLEAR(&(ctimer_md->phy_citimer));
    CITIMER_CLEAR(&(ctimer_md->old_citimer));

    ctimer_md->usedcounter = 1;

    ctimer_create();

    dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_start: start CTIMER module\n");

    return (0);
}

/**
*
* end CTIMER module
*
**/
void ctimer_end()
{
    CTIMER_MD *ctimer_md;

    ctimer_md = CTIMER_MD_GET();

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < ctimer_md->usedcounter )
    {
        ctimer_md->usedcounter --;
        return ;
    }

    if ( 0 == ctimer_md->usedcounter )
    {
        dbg_log(SEC_0075_CTIMER, 0)(LOGSTDOUT,"error:ctimer_end: CTIMER is not started.\n");
        dbg_exit(MD_CTIMER, 0);
    }

    ctimer_clean();
    clist_free(ctimer_md->ctimer_node_list, LOC_CTIMER_0002);
    ctimer_md->ctimer_node_list = NULL_PTR;

    CITIMER_CLEAR(&(ctimer_md->phy_citimer));
    CITIMER_CLEAR(&(ctimer_md->old_citimer));

    ctimer_md->usedcounter = 0;

    dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_end: stop CTIMER\n");

    breathing_static_mem();

    return ;
}

/**
*
* new CTIMER_NODE
*
**/
CTIMER_NODE *ctimer_node_new()
{
    CTIMER_NODE *ctimer_node;

    alloc_static_mem(MM_CTIMER_NODE, &ctimer_node, LOC_CTIMER_0003);
    ctimer_node_init(ctimer_node);

    return (ctimer_node);
}

/**
*
* init CTIMER_NODE
*
**/
UINT32 ctimer_node_init(CTIMER_NODE *ctimer_node)
{
    CTIMER_NODE_CLEAR(ctimer_node);
    return (0);
}

/**
*
* clean CTIMER_NODE
*
**/
UINT32 ctimer_node_clean(CTIMER_NODE *ctimer_node)
{
    CTIMER_NODE_CLEAR(ctimer_node);
    return (0);
}

/**
*
* free CTIMER_NODE
*
**/
UINT32 ctimer_node_free(CTIMER_NODE *ctimer_node)
{
    ctimer_node_clean(ctimer_node);
    free_static_mem(MM_CTIMER_NODE, ctimer_node, LOC_CTIMER_0004);
    return (0);
}

/**
*
* add CTIMER_NODE
*
**/
UINT32 ctimer_node_add(CTIMER_NODE *ctimer_node, const UINT32 timeout, const void * func_retval_addr, const UINT32 func_id, ...)
{
    CTIMER_MD   *ctimer_md;
    CLIST *ctimer_node_list;

    FUNC_ADDR_NODE *func_addr_node;
    TASK_FUNC *handler;

    UINT32 mod_type;

    UINT32 para_idx;
    va_list ap;

    ctimer_md = CTIMER_MD_GET();
    ctimer_node_list = ctimer_md->ctimer_node_list;

    CTIMER_NODE_TIMEOUT(ctimer_node)  = timeout;
    CTIMER_NODE_USEDFLAG(ctimer_node) = CTIMER_NODE_NOT_USED;
    CTIMER_NODE_SETFLAG(ctimer_node)  = CTIMER_NODE_NEVER_TIMEOUT;

    mod_type = (func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0075_CTIMER, 0)(LOGSTDERR, "error:ctimer_node_add: invalid func_id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    if(0 != dbg_fetch_func_addr_node_by_index(func_id, &func_addr_node))
    {
        dbg_log(SEC_0075_CTIMER, 0)(LOGSTDOUT, "error:ctimer_node_add: failed to fetch func addr node by func id %lx\n", func_id);
        return ((UINT32)(-1));
    }

    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_add: beg===================================================================\n");
    //func_addr_node_print(LOGSTDOUT, func_addr_node);

    CTIMER_NODE_FUNC_ADDR_NODE(ctimer_node) = func_addr_node;

    handler = CTIMER_NODE_HANDLER(ctimer_node);

    handler->func_id       = func_id;
    handler->func_para_num = func_addr_node->func_para_num;
    handler->func_ret_val  = (UINT32)func_retval_addr;

    va_start(ap, func_id);
    for(para_idx = 0; para_idx < func_addr_node->func_para_num; para_idx ++ )
    {
        FUNC_PARA *func_para;

        func_para = &(handler->func_para[ para_idx ]);
        func_para->para_val = va_arg(ap, UINT32);

        //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_add: para %ld #: %lx\n", para_idx, func_para->para_val);
    }
    va_end(ap);

    clist_push_back(ctimer_node_list, (void *)ctimer_node);

    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_add: end===================================================================\n");
    return (0);
}

/**
*
* delete CTIMER_NODE
*
**/
UINT32 ctimer_node_del(CTIMER_NODE *ctimer_node)
{
    CTIMER_MD   *ctimer_md;
    CLIST *ctimer_node_list;

    ctimer_md = CTIMER_MD_GET();
    ctimer_node_list = ctimer_md->ctimer_node_list;


    clist_del(ctimer_node_list, ctimer_node, NULL_PTR);
    ctimer_node_free(ctimer_node);

    return (0);
}

/**
*
* num of CTIMER_NODE
*
**/
UINT32 ctimer_node_num()
{
    CTIMER_MD *ctimer_md;

    ctimer_md = CTIMER_MD_GET();

    return clist_size(ctimer_md->ctimer_node_list);
}

/**
*
* start CTIMER_NODE (start a timer)
*
**/
UINT32 ctimer_node_start(CTIMER_NODE *ctimer_node)
{
    CTIMER_MD   *ctimer_md;
    CITIMER     *phy_citimer;
    CITIMER     *old_citimer;

    CLIST *ctimer_node_list;
    CLIST_DATA *clist_data;

    UINT32     diff;
    UINT32     left;

    ctimer_md   = CTIMER_MD_GET();
    phy_citimer = &(ctimer_md->phy_citimer);
    old_citimer = &(ctimer_md->old_citimer);

    CTIMER_NODE_EXPIRE(ctimer_node)   = CTIMER_NODE_TIMEOUT(ctimer_node);
    CTIMER_NODE_USEDFLAG(ctimer_node) = CTIMER_NODE_USED;
    CTIMER_NODE_SETFLAG(ctimer_node)  = CTIMER_NODE_WOULD_TIMEOUT;

    getitimer(ITIMER_REAL, old_citimer);

    left = CITIMER_VALUE_GET(old_citimer);
    dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_start: left time = %ld ms\n",left);

    if( 0 == left )
    {
        CITIMER_VALUE_SET(phy_citimer, CTIMER_NODE_TIMEOUT(ctimer_node));
        CITIMER_INTERVAL_SET(phy_citimer, 0);

        setitimer(ITIMER_REAL, phy_citimer, NULL_PTR);

        dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_start: handle ctimer_node %p\n", ctimer_node);
        ctimer_node_handle(ctimer_node);

        return (0);
    }

    /*determine the first time when ctimer_node is triggered*/
    if(CTIMER_NODE_TIMEOUT(ctimer_node) > left)/*belong to (left, +)*/
    {
        CTIMER_NODE_EXPIRE(ctimer_node) = CTIMER_NODE_TIMEOUT(ctimer_node) - left;
        dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node %p: expire = %ld\n", ctimer_node, CTIMER_NODE_EXPIRE(ctimer_node));
        return (0);
    }

    if(CTIMER_NODE_TIMEOUT(ctimer_node) + ctimer_md->ctimer_expire_delta > left) /*belong to (left - delta, left]*/
    {
        CTIMER_NODE_EXPIRE(ctimer_node) = ctimer_md->ctimer_expire_delta;/*will be triggered when timer reaches*/
        dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node %p: expire = %ld\n", ctimer_node, CTIMER_NODE_EXPIRE(ctimer_node));
        return (0);
    }

    /*now CTIMER_NODE_TIMEOUT(ctimer_node) + ctimer_md->ctimer_expire_delta <= left*/
    diff = left - CTIMER_NODE_TIMEOUT(ctimer_node);/*diff >= delta*/

    ctimer_node_list = ctimer_md->ctimer_node_list;

    CLIST_LOCK(ctimer_node_list, LOC_CTIMER_0005);
    CLIST_LOOP_NEXT(ctimer_node_list, clist_data)
    {
        CTIMER_NODE *cur_ctimer_node;

        cur_ctimer_node = (CTIMER_NODE *)CLIST_DATA_DATA(clist_data);
        if( cur_ctimer_node != ctimer_node
         && CTIMER_NODE_USED == CTIMER_NODE_USEDFLAG(cur_ctimer_node)
         && CTIMER_NODE_WOULD_TIMEOUT == CTIMER_NODE_SETFLAG(cur_ctimer_node)
         )
        {
            CTIMER_NODE_EXPIRE(cur_ctimer_node) += diff;
        }
    }
    CLIST_UNLOCK(ctimer_node_list, LOC_CTIMER_0006);

    CITIMER_VALUE_SET(phy_citimer, CTIMER_NODE_TIMEOUT(ctimer_node));
    CITIMER_INTERVAL_SET(phy_citimer, 0);

    setitimer(ITIMER_REAL, phy_citimer, NULL_PTR);

    return (0);
}

/**
*
* stop CTIMER_NODE (stop a timer)
*
**/
UINT32 ctimer_node_stop(CTIMER_NODE *ctimer_node)
{
    CTIMER_NODE_USEDFLAG(ctimer_node) = CTIMER_NODE_NOT_USED;
    CTIMER_NODE_EXPIRE(ctimer_node)   = CTIMER_NODE_TIMEOUT(ctimer_node);
    CTIMER_NODE_SETFLAG(ctimer_node)  = CTIMER_NODE_NEVER_TIMEOUT;

    return (0);
}

/**
*
* handle CTIMER_NODE
*
**/
UINT32 ctimer_node_handle(CTIMER_NODE *ctimer_node)
{
    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_handle: beg===================================================================\n");
    //task_func_print(LOGSTDOUT, CTIMER_NODE_HANDLER(ctimer_node));
    task_caller(CTIMER_NODE_HANDLER(ctimer_node), CTIMER_NODE_FUNC_ADDR_NODE(ctimer_node));
    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_handle: end===================================================================\n");
    return (0);
}
STATIC_CAST static char *ctimer_get_flag_str(const UINT32 flag)
{
    switch(flag)
    {
        case CTIMER_NODE_NOT_USED:
            return (char *)"CTIMER_NODE_NOT_USED";
        case CTIMER_NODE_USED:
            return (char *)"CTIMER_NODE_USED";
        case CTIMER_NODE_NEVER_TIMEOUT:
            return (char *)"CTIMER_NODE_NEVER_TIMEOUT";
        case CTIMER_NODE_WOULD_TIMEOUT:
            return (char *)"CTIMER_NODE_WOULD_TIMEOUT";
        case CTIMER_NODE_UNDEF:
            return (char *)"CTIMER_NODE_UNDEF";
    }
    dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_get_flag_str: unknow flag %ld\n", flag);
    return (char *)"UNKNOW";
}

void ctimer_node_print(LOG *log, const CTIMER_NODE *ctimer_node)
{
    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_print: beg===================================================================\n");
    if(NULL_PTR == ctimer_node)
    {
        sys_log(log, "ctimer_node is null pointer\n");
        return;
    }

    sys_log(log, "ctimer_node %p: timeout %ld, expire %ld, usedflag %s, setflag %s\n",
                        ctimer_node, CTIMER_NODE_TIMEOUT(ctimer_node), CTIMER_NODE_EXPIRE(ctimer_node),
                        ctimer_get_flag_str(CTIMER_NODE_USEDFLAG(ctimer_node)),
                        ctimer_get_flag_str(CTIMER_NODE_SETFLAG(ctimer_node))
                        );
    sys_log(log, "ctimer_node %p: func_addr_node %lx:\n", ctimer_node, CTIMER_NODE_FUNC_ADDR_NODE(ctimer_node));
    func_addr_node_print(log, CTIMER_NODE_FUNC_ADDR_NODE(ctimer_node));

    sys_log(log, "ctimer_node %p: handler %lx:\n", ctimer_node, CTIMER_NODE_HANDLER(ctimer_node));
    task_func_print(log, CTIMER_NODE_HANDLER(ctimer_node));

    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_node_print: end===================================================================\n");

    return;
}

void ctimer_citimer_print(LOG *log, const CITIMER *citimer)
{
    sys_log(log, "citimer: it_value = {%ld, %ld}, it_interval = {%ld, %ld}\n",
                CITIMER_VALUE_SEC(citimer), CITIMER_VALUE_USEC(citimer),
                CITIMER_INTERVAL_SEC(citimer), CITIMER_INTERVAL_USEC(citimer));
    return;
}

void ctimer_print(LOG *log, const CTIMER_MD *ctimer_md)
{
    CLIST    *ctimer_node_list;
    UINT32    ctimer_expire_delta;
    UINT32    ctimer_expire_burn;
    CITIMER   *phy_citimer;
    CITIMER   *old_citimer;

    ctimer_node_list = ctimer_md->ctimer_node_list;
    phy_citimer = (CITIMER *)&(ctimer_md->phy_citimer);
    old_citimer = (CITIMER *)&(ctimer_md->old_citimer);
    ctimer_expire_delta = ctimer_md->ctimer_expire_delta;
    ctimer_expire_burn  = ctimer_md->ctimer_expire_burn;

    sys_log(log, "ctimer_node_list:\n");
    clist_print(log, ctimer_md->ctimer_node_list, (CLIST_DATA_DATA_PRINT)ctimer_node_print);

    sys_log(log, "phy_citimer: it_value = {%ld, %ld}, it_interval = {%ld, %ld}\n",
                CITIMER_VALUE_SEC(phy_citimer), CITIMER_VALUE_USEC(phy_citimer),
                CITIMER_INTERVAL_SEC(phy_citimer), CITIMER_INTERVAL_USEC(phy_citimer));

    sys_log(log, "old_citimer: it_value = {%ld, %ld}, it_interval = {%ld, %ld}\n",
                CITIMER_VALUE_SEC(old_citimer), CITIMER_VALUE_USEC(old_citimer),
                CITIMER_INTERVAL_SEC(old_citimer), CITIMER_INTERVAL_USEC(old_citimer));

    sys_log(log, "ctimer_expire_delta: %ld\n", ctimer_expire_delta);
    sys_log(log, "ctimer_expire_burn : %ld\n", ctimer_expire_burn);

    return;
}

/**
*
* update all CTIMER_NODE and trigger event if timer expired
*
**/
void ctimer_update(int signal)
{
    CTIMER_MD   *ctimer_md;
    CLIST       *ctimer_node_list;
    CLIST_DATA  *clist_data;

    UINT32       ctimer_expire_min;
    CTIMER_NODE *ctimer_node_expire_min;
    CITIMER     *phy_citimer;

    ctimer_md = CTIMER_MD_GET();
    ctimer_node_list = ctimer_md->ctimer_node_list;
    phy_citimer = &(ctimer_md->phy_citimer);

    ctimer_expire_min = ((UINT32)-1);
    ctimer_node_expire_min = NULL_PTR;

    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update: enter >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

    /*handle CTIMER_NODE whose timer expired*/
    CLIST_LOCK(ctimer_node_list, LOC_CTIMER_0007);
    CLIST_LOOP_NEXT(ctimer_node_list, clist_data)
    {
        CTIMER_NODE *ctimer_node;

        ctimer_node = (CTIMER_NODE *)CLIST_DATA_DATA(clist_data);
        if(CTIMER_NODE_NOT_USED == CTIMER_NODE_USEDFLAG(ctimer_node) || CTIMER_NODE_NEVER_TIMEOUT == CTIMER_NODE_SETFLAG(ctimer_node))
        {
            continue;
        }

        if(CTIMER_NODE_EXPIRE(ctimer_node) <= ctimer_md->ctimer_expire_delta)
        {
            /*reset expire and handle it*/
            CTIMER_NODE_EXPIRE(ctimer_node) = CTIMER_NODE_TIMEOUT(ctimer_node);

            dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update: handle ctimer_node %p\n", ctimer_node);
            ctimer_node_handle(ctimer_node);
            //ctimer_node_print(LOGSTDOUT, ctimer_node);

            /*then fall through to check next if*/
        }

        /*find the timer with min expire*/
        if(CTIMER_NODE_EXPIRE(ctimer_node) < ctimer_expire_min)
        {
            ctimer_expire_min = CTIMER_NODE_EXPIRE(ctimer_node);
            ctimer_node_expire_min = ctimer_node;
        }
    }
    CLIST_UNLOCK(ctimer_node_list, LOC_CTIMER_0008);

    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update:[ 2 ] -----------------------------------------------------------------------------\n");
    //ctimer_print(LOGSTDOUT, ctimer_md);

    /*when no CTIMER_NODE is waiting for trigger, then stop!*/
    if(NULL_PTR == ctimer_node_expire_min)
    {
        CITIMER_VALUE_SET(phy_citimer, 0);
        CITIMER_INTERVAL_SET(phy_citimer, 0);

        setitimer(ITIMER_REAL, phy_citimer, NULL_PTR);

        dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update: stop!\n");

        return;
    }

    if(NULL_PTR != ctimer_node_expire_min)
    {
        CITIMER_VALUE_SET(phy_citimer, ctimer_expire_min);
        CITIMER_INTERVAL_SET(phy_citimer, 0);

        ctimer_md->ctimer_expire_burn = ctimer_expire_min;

        CLIST_LOCK(ctimer_node_list, LOC_CTIMER_0009);
        CLIST_LOOP_NEXT(ctimer_node_list, clist_data)
        {
            CTIMER_NODE *ctimer_node;

            ctimer_node = (CTIMER_NODE *)CLIST_DATA_DATA(clist_data);
            if(CTIMER_NODE_NOT_USED == CTIMER_NODE_USEDFLAG(ctimer_node) || CTIMER_NODE_NEVER_TIMEOUT == CTIMER_NODE_SETFLAG(ctimer_node))
            {
                continue;
            }

            CTIMER_NODE_EXPIRE(ctimer_node) -= ctimer_expire_min;
        }
        CLIST_UNLOCK(ctimer_node_list, LOC_CTIMER_0010);

        //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update:[ 3 ] -----------------------------------------------------------------------------\n");
        //ctimer_print(LOGSTDOUT, ctimer_md);
    }

    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update:[ 5 ] -----------------------------------------------------------------------------\n");
    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update: phy_citimer is:\n");
    //ctimer_citimer_print(LOGSTDOUT, phy_citimer);

    setitimer(ITIMER_REAL, phy_citimer, NULL_PTR);

    //dbg_log(SEC_0075_CTIMER, 5)(LOGSTDOUT, "ctimer_update: leave <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

    return ;
}

/**
*
* create a event trigger
*
**/
UINT32 ctimer_create()
{
    CTIMER_MD   *ctimer_md;
    CITIMER     *phy_citimer;

    struct sigaction sa;

    ctimer_md = CTIMER_MD_GET();
    phy_citimer = &(ctimer_md->phy_citimer);

    /*bind signal and handler*/
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = ctimer_update;
    sigaction(SIGALRM, &sa, NULL_PTR);

    CITIMER_VALUE_SET(phy_citimer   , 0);
    CITIMER_INTERVAL_SET(phy_citimer, 0);

    setitimer(ITIMER_REAL, phy_citimer, NULL_PTR);

    return (0);
}

/**
*
* stop and clean up all CTIMER_NODE
*
**/
UINT32 ctimer_clean()
{
    CTIMER_MD   *ctimer_md;
    CITIMER     *phy_citimer;
    CLIST *ctimer_node_list;

    ctimer_md = CTIMER_MD_GET();
    ctimer_node_list = ctimer_md->ctimer_node_list;
    phy_citimer = &(ctimer_md->phy_citimer);

    CITIMER_VALUE_SET(phy_citimer, 0);
    CITIMER_INTERVAL_SET(phy_citimer, 0);

    setitimer(ITIMER_REAL, phy_citimer, NULL_PTR);

    while(EC_FALSE == clist_is_empty(ctimer_node_list))
    {
        CTIMER_NODE *ctimer_node;

        ctimer_node = (CTIMER_NODE *)clist_pop_back(ctimer_node_list);

        ctimer_node_stop(ctimer_node);
        ctimer_node_free(ctimer_node);
    }

    return (0);
}

/**
*
* get current time in msec
*
**/
UINT32 ctimer_cur_msec()
{
    struct timeval tv;
    UINT32 cur_msec;

    gettimeofday(&tv, NULL_PTR);

    cur_msec = (tv.tv_sec % 100000) * 1000 + tv.tv_usec / 1000;
    return (cur_msec);
}

/**
*
* sleep msec
*
**/
UINT32 ctimer_sleep_msec(const UINT32 msec)
{
    struct timespec tv;

    tv.tv_sec  = msec / 1000;
    tv.tv_nsec = (msec % 1000) * 1000* 1000;

    nanosleep(&tv, NULL_PTR);

    return (0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

