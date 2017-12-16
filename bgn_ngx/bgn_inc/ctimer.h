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

#ifndef _CTIMER_H
#define _CTIMER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 

#include <signal.h>
#include <time.h>  
#include <sys/time.h>

#include "type.h"
#include "clist.h"

#include "debug.h"
#include "task.inc"

#define CTIMER_NODE_NOT_USED         ((UINT32) 1)
#define CTIMER_NODE_USED             ((UINT32) 2)
#define CTIMER_NODE_NEVER_TIMEOUT    ((UINT32) 3) 
#define CTIMER_NODE_WOULD_TIMEOUT    ((UINT32) 4) 
#define CTIMER_NODE_UNDEF            ((UINT32)-1)

#define CTIMER_SIGNAL_UNDEF          ((int)-1)
#define CTIMER_PARAM_UNDEF           ((UINT32)-1)

typedef struct itimerval CITIMER;

typedef struct
{
    UINT32 timeout; /*timeout setting, unit:ms*/
    UINT32 expire;  /*internal to next interruption, unit:ms*/
    UINT32 usedflag;/*this timer is used or not*/
    UINT32 setflag; /*this timer is timeout or not*/

    FUNC_ADDR_NODE * func_addr_node;
    TASK_FUNC        handler;
}CTIMER_NODE;

typedef struct
{
    UINT32    usedcounter;
    CLIST    *ctimer_node_list;

    UINT32    ctimer_expire_delta;
    UINT32    ctimer_expire_burn;
    CITIMER   phy_citimer;
    CITIMER   old_citimer;
    
}CTIMER_MD;

#define CTIMER_MD_INITIALIZER {\
    0,              /*usedcounter        */\
    NULL_PTR,       /*ctimer_node_list   */\
    10,             /*ctimer_expire_delta*/\
    0,              /*ctimer_expire_burn */\
    {{0,0},{0,0}},  /*phy_citimer        */\
    {{0,0},{0,0}},  /*old_citimer        */\
}

#define CITIMER_VALUE_SEC(citimer)                  ((citimer)->it_value.tv_sec)
#define CITIMER_VALUE_USEC(citimer)                 ((citimer)->it_value.tv_usec)
#define CITIMER_INTERVAL_SEC(citimer)               ((citimer)->it_interval.tv_sec)
#define CITIMER_INTERVAL_USEC(citimer)              ((citimer)->it_interval.tv_usec)

#define CITIMER_VALUE_CLEAR(citimer)                do{CITIMER_VALUE_SEC(citimer) = 0; CITIMER_VALUE_USEC(citimer) = 0;}while(0)
#define CITIMER_INTERVAL_CLEAR(citimer)             do{CITIMER_INTERVAL_SEC(citimer) = 0; CITIMER_INTERVAL_USEC(citimer) = 0;}while(0)

#define CITIMER_CLEAR(citimer)                      do{CITIMER_VALUE_CLEAR(citimer); CITIMER_INTERVAL_CLEAR(citimer);}while(0)

#define CITIMER_VALUE_SET(citimer, msec)            do{CITIMER_VALUE_SEC(citimer) = (msec) /  1000; CITIMER_VALUE_USEC(citimer) = ((msec) % 1000) * 1000;}while(0)
#define CITIMER_INTERVAL_SET(citimer, msec)         do{CITIMER_INTERVAL_SEC(citimer) = (msec) /  1000; CITIMER_INTERVAL_USEC(citimer) = ((msec) % 1000) * 1000;}while(0)

/*return msec*/
#define CITIMER_VALUE_GET(citimer)                  (CITIMER_VALUE_SEC(citimer) * 1000 + CITIMER_VALUE_USEC(citimer) / 1000)
#define CITIMER_INTERVAL_GET(citimer)               (CITIMER_INTERVAL_SEC(citimer) * 1000 + CITIMER_INTERVAL_USEC(citimer) / 1000)


#define CTIMER_NODE_TIMEOUT(ctimer_node)            ((ctimer_node)->timeout)
#define CTIMER_NODE_EXPIRE(ctimer_node)             ((ctimer_node)->expire)
#define CTIMER_NODE_USEDFLAG(ctimer_node)           ((ctimer_node)->usedflag)
#define CTIMER_NODE_SETFLAG(ctimer_node)            ((ctimer_node)->setflag)
#define CTIMER_NODE_HANDLER(ctimer_node)            (&((ctimer_node)->handler))
#define CTIMER_NODE_FUNC_ADDR_NODE(ctimer_node)     ((ctimer_node)->func_addr_node)

#define CTIMER_NODE_CLEAR(ctimer_node)  do{\
    CTIMER_NODE_TIMEOUT(ctimer_node)        = 0;\
    CTIMER_NODE_EXPIRE(ctimer_node)         = 0;\
    CTIMER_NODE_USEDFLAG(ctimer_node)       = CTIMER_NODE_NOT_USED;\
    CTIMER_NODE_SETFLAG(ctimer_node)        = CTIMER_NODE_NEVER_TIMEOUT;\
    CTIMER_NODE_FUNC_ADDR_NODE(ctimer_node) = NULL_PTR;\
    task_func_init(CTIMER_NODE_HANDLER(ctimer_node));\
}while(0)

/**
*
* start CTIMER module
*
**/
UINT32 ctimer_start(const UINT32 ctimer_expire_delta);

/**
*
* end CTIMER module
*
**/
void ctimer_end();

/**
*
* new CTIMER_NODE
*
**/
CTIMER_NODE *ctimer_node_new();

/**
*
* init CTIMER_NODE
*
**/
UINT32 ctimer_node_init(CTIMER_NODE *ctimer_node);

/**
*
* clean CTIMER_NODE
*
**/
UINT32 ctimer_node_clean(CTIMER_NODE *ctimer_node);

/**
*
* free CTIMER_NODE
*
**/
UINT32 ctimer_node_free(CTIMER_NODE *ctimer_node);

/**
*
* add CTIMER_NODE
*
**/
UINT32 ctimer_node_add(CTIMER_NODE *ctimer_node, const UINT32 timeout, const void * func_retval_addr, const UINT32 func_id, ...);

/**
*
* delete CTIMER_NODE
*
**/
UINT32 ctimer_node_del(CTIMER_NODE *ctimer_node);

/**
*
* num of CTIMER_NODE
*
**/
UINT32 ctimer_node_num();

/**
*
* start CTIMER_NODE (start a timer)
*
**/
UINT32 ctimer_node_start(CTIMER_NODE *ctimer_node);

/**
*
* stop CTIMER_NODE (stop a timer)
*
**/
UINT32 ctimer_node_stop(CTIMER_NODE *ctimer_node);

/**
*
* handle CTIMER_NODE
*
**/
UINT32 ctimer_node_handle(CTIMER_NODE *ctimer_node);

/**
*
* update all CTIMER_NODE and trigger event if timer expired
*
**/
void ctimer_update(int signal);

/**
*
* create a event trigger
*
**/
UINT32 ctimer_create();

/**
*
* stop and clean up all CTIMER_NODE
*
**/
UINT32 ctimer_clean();

/**
*
* get current time in msec
*
**/
UINT32 ctimer_cur_msec();

/**
*
* sleep msec
*
**/
UINT32 ctimer_sleep_msec(const UINT32 msec);


void ctimer_node_print(LOG *log, const CTIMER_NODE *ctimer_node);
void ctimer_citimer_print(LOG *log, const CITIMER *citimer);
void ctimer_print(LOG *log, const CTIMER_MD *ctimer_md);

#endif/* _CTIMER_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

