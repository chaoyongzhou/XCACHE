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

#ifndef _CTHREAD_H
#define _CTHREAD_H

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <pthread.h>
#include <sys/syscall.h>

#include "type.h"
#include "clist.h"
#include "cvector.h"

#define ERR_CTHREAD_ID         ((UINT32) -1)
#define ERR_PID                ((pid_t)  -1)

#define CTHREAD_DETACHABLE     ((UINT32) 0x0001)
#define CTHREAD_JOINABLE       ((UINT32) 0x0010)
#define CTHREAD_PROCESS_LEVEL  ((UINT32) 0x0100)
#define CTHREAD_SYSTEM_LEVEL   ((UINT32) 0x1000)

//#define CTHREAD_STACK_SIZE_DEFAULT    (8 * 1024 * 1024)
//#define CTHREAD_GUARD_SIZE_DEFAULT    (4 * 1024)

#define CTHREAD_STACK_SIZE_DEFAULT      CROUTINE_STACK_MAX_SIZE
#define CTHREAD_GUARD_SIZE_DEFAULT      CROUTINE_STACK_GUARD_SIZE

#define CTHREAD_EXPAND_MIN_NUM        ((UINT32)16)
#define CTHREAD_SHRINK_THRESHOLD      ((UINT32)32)
#define CTHREAD_SHRINK_MIN_NUM        ((UINT32) 4)

#define CTHREAD_MAX_ARG_NUM           (16)
#define CTHREAD_MAX_CORE_NUM          ((UINT32)256) /*support core num up to*/

#define CTHREAD_ERR_CORE_ID           ((UINT32)-1)

/*bit map*/
#define CTHREAD_IS_IDLE               ((UINT32) 0x0001)
#define CTHREAD_IS_BUSY               ((UINT32) 0x0010)
#define CTHREAD_IS_DOWN               ((UINT32) 0x1100)
#define CTHREAD_LO_MASK               ((UINT32) 0x00FF)
#define CTHREAD_HI_MASK               ((UINT32) 0xFF00)

#define CTHREAD_ERR_FLAG              ((UINT32) -1)

/*get tid of the thread when standing in the pthread*/
#define CTHREAD_GET_TID()             (syscall(__NR_gettid))

#if (64 == WORDSIZE)
//#define CTHREAD_TID_OFFSET            ((UINT32)144)/*on Centos 6.0 x86_64*/
#define CTHREAD_TID_OFFSET            ((UINT32)720)/*on Centos 6.3 x86_64*/
#endif

#if (32 == WORDSIZE)
#define CTHREAD_TID_OFFSET            ((UINT32)72)/*on Centos 5.6 x86_32*/
#endif

/*get tid of the thread when standing out of the pthread*/
/*note: pid type is pthread_t*/
#define CTHREAD_FETCH_TID(pthread_id, tid_offset)      (*((pid_t *)(((unsigned char *)(pthread_id)) + (tid_offset))))

typedef pthread_t           CTHREAD_ID;
typedef pthread_attr_t      CTHREAD_ATTR;
typedef struct sched_param  CTHREAD_SCHED;

typedef void *(*CTHREAD_START_ROUTINE)(void*);
typedef void (*CTHREAD_CLEANUP_ROUTINE)(void *);

#ifdef __cplusplus
#undef __cplusplus
#define CTHREAD_CLEANUP_PUSH(thread_cancel_routine, thread_cancel_para) \
    pthread_cleanup_push((CTHREAD_CLEANUP_ROUTINE)(thread_cancel_routine), (void *)(thread_cancel_para))

#define CTHREAD_CLEANUP_POP(flag)   \
    pthread_cleanup_pop( flag )

#define CTHREAD_EXIT(ptr) \
    pthread_exit(ptr)

/*note: test cancel is for DEFERRED attribute of thread */
/* if pthread_setcanceltype set as PTHREAD_CANCEL_DEFERRED without testcancel set in flow, all pthreads will hung up when the thread cancel*/
#define CTHREAD_TEST_CANCEL() \
    pthread_testcancel()

#define __cplusplus/*restore*/
#else
#define CTHREAD_CLEANUP_PUSH(thread_cancel_routine, thread_cancel_para) \
    pthread_cleanup_push((CTHREAD_CLEANUP_ROUTINE)(thread_cancel_routine), (void *)(thread_cancel_para))

#define CTHREAD_CLEANUP_POP(flag)   \
    pthread_cleanup_pop( flag )

#define CTHREAD_EXIT(ptr) \
    pthread_exit(ptr)

/*note: test cancel is for DEFERRED attribute of thread */
/* if pthread_setcanceltype set as PTHREAD_CANCEL_DEFERRED without testcancel set in flow, all pthreads will hung up when the thread cancel*/
#define CTHREAD_TEST_CANCEL() \
    pthread_testcancel()
#endif/*__cplusplus*/
typedef struct
{
    UINT32  start_routine_addr;
    UINT32  core_id;
    UINT32  arg_num;
    UINT32  arg_list[CTHREAD_MAX_ARG_NUM];
}CTHREAD_TASK;

typedef struct
{
    CTHREAD_TASK *thread_task;

    UINT32        thread_status;

    CLIST_DATA   *thread_mounted;

    CTHREAD_ID    thread_id;
    CCOND         thread_ccond;
}CTHREAD_NODE;

typedef struct
{
    CLIST         worker_idle_list;  /*idle cthread_node list*/
    CLIST         worker_busy_list;  /*busy cthread_node list*/
    CMUTEX        worker_cmutex;     /*cmutex of cthread_pool*/

    UINT32        worker_flag;       /*flag of the cthread_nodes*/
    UINT32        worker_max_num;    /*max supported number of cthread_nodes*/

    UINT32        core_load_tbl[CTHREAD_MAX_CORE_NUM];
    UINT32        core_max_id_used;
}CTHREAD_POOL;

typedef struct
{
    CTHREAD_NODE  *cthread_node;
    CTHREAD_POOL  *cthread_pool;
}CTHREAD_BIND;

#define CTHREAD_TASK_ROUTINE(cthread_task)              ((cthread_task)->start_routine_addr)
#define CTHREAD_TASK_CORE_ID(cthread_task)              ((cthread_task)->core_id)
#define CTHREAD_TASK_ARG_NUM(cthread_task)              ((cthread_task)->arg_num)
#define CTHREAD_TASK_ARG_LIST(cthread_task)             ((cthread_task)->arg_list)
#define CTHREAD_TASK_ARG_VAL(cthread_task, arg_idx)     ((cthread_task)->arg_list[(arg_idx)])

#define CTHREAD_NODE_ID(cthread_node)                   ((cthread_node)->thread_id)
#define CTHREAD_NODE_STATUS(cthread_node)               ((cthread_node)->thread_status)
#define CTHREAD_NODE_MOUNTED(cthread_node)              ((cthread_node)->thread_mounted)
#define CTHREAD_NODE_TASK(cthread_node)                 ((cthread_node)->thread_task)
#define CTHREAD_NODE_CCOND(cthread_node)                (&((cthread_node)->thread_ccond))
#define CTHREAD_NODE_CORE_ID(cthread_node)              (CTHREAD_TASK_CORE_ID(CTHREAD_NODE_TASK(cthread_node)))

#define CTHREAD_NODE_CCOND_INIT(cthread_node, location)              (ccond_init(CTHREAD_NODE_CCOND(cthread_node), location))
#define CTHREAD_NODE_CCOND_CLEAN(cthread_node, location)             (ccond_clean(CTHREAD_NODE_CCOND(cthread_node), location))
#define CTHREAD_NODE_CCOND_RESERVE(cthread_node, counter, location)  (ccond_reserve(CTHREAD_NODE_CCOND(cthread_node), counter, location))
#define CTHREAD_NODE_CCOND_RELEASE(cthread_node, location)           (ccond_release(CTHREAD_NODE_CCOND(cthread_node), location))
#define CTHREAD_NODE_CCOND_RELEASE_ALL(cthread_node, location)       (ccond_release_all(CTHREAD_NODE_CCOND(cthread_node), location))
#define CTHREAD_NODE_CCOND_WAIT(cthread_node, location)              (ccond_wait(CTHREAD_NODE_CCOND(cthread_node), location))
#define CTHREAD_NODE_CCOND_SPY(cthread_node, location)               (ccond_spy(CTHREAD_NODE_CCOND(cthread_node), location))

#define CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool)     (&((cthread_pool)->worker_idle_list))
#define CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool)     (&((cthread_pool)->worker_busy_list))
#define CTHREAD_POOL_WORKER_CMUTEX(cthread_pool)        (&((cthread_pool)->worker_cmutex))
#define CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool)       ((cthread_pool)->worker_max_num)
#define CTHREAD_POOL_WORKER_FLAG(cthread_pool)          ((cthread_pool)->worker_flag)
#define CTHREAD_POOL_CORE_LOAD_TBL(cthread_pool)        ((cthread_pool)->core_load_tbl)
#define CTHREAD_POOL_CORE_LOAD(cthread_pool, core_id)   ((cthread_pool)->core_load_tbl[ (core_id) ])
#define CTHREAD_POOL_CORE_MAX_ID_USED(cthread_pool)     ((cthread_pool)->core_max_id_used)

#define CTHREAD_BIND_NODE(cthread_bind)                 ((cthread_bind)->cthread_node)
#define CTHREAD_BIND_POOL(cthread_bind)                 ((cthread_bind)->cthread_pool)


#if (SWITCH_ON == CTHREAD_SET_CORE_SWITCH)
#define CTHREAD_CORE_LOAD_INC(cthread_bind) do{\
    cthread_core_load_inc(cthread_bind);\
}while(0)

#define CTHREAD_CORE_LOAD_DEC(cthread_bind) do{\
    cthread_core_load_dec(cthread_bind);\
}while(0)
#endif/*(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)*/

#if (SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)
#define CTHREAD_CORE_LOAD_INC(cthread_bind) do{\
}while(0)

#define CTHREAD_CORE_LOAD_DEC(cthread_bind) do{\
}while(0)
#endif/*(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)*/


void   cthread_killme(void *args);

EC_BOOL cthread_kill(CTHREAD_ID cthread_id, int signo);

void * cthread_start(void *args);

CTHREAD_ID cthread_new(const UINT32 flag, const char *name, const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num,...);

EC_BOOL cthread_wait(CTHREAD_ID cthread_id);

EC_BOOL cthread_cancel(CTHREAD_ID cthread_id);

CTHREAD_ID cthread_create(const UINT32 flag, const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num, va_list para_list);
UINT32 cthread_caller(const UINT32 start_routine_addr, const UINT32 arg_num, UINT32 *arg_list);

CTHREAD_TASK *cthread_task_new(const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num, va_list para_list);

UINT32 cthread_task_init(CTHREAD_TASK *cthread_task, const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num, va_list para_list);

UINT32 cthread_task_clone(const CTHREAD_TASK *cthread_task_src, CTHREAD_TASK *cthread_task_des);

UINT32 cthread_task_clean(CTHREAD_TASK *cthread_task);

UINT32 cthread_task_free(CTHREAD_TASK *cthread_task);

void cthread_task_print(LOG *log, const CTHREAD_TASK *cthread_task);


CTHREAD_NODE *cthread_node_new();

UINT32 cthread_node_init(CTHREAD_NODE *cthread_node);

void * cthread_node_entry(void *args);

CTHREAD_ID cthread_node_create(CTHREAD_NODE *cthread_node, const CTHREAD_ATTR *cthread_attr, const UINT32 thread_entry_routine_addr, const UINT32 core_id, const UINT32 para_num, ...);

UINT32 cthread_node_clean(CTHREAD_NODE *cthread_node);

UINT32 cthread_node_free(CTHREAD_NODE *cthread_node);

/*note: cthread_node_shutdown will lock cthread_pool, so DO NOT call it when cthreadp_shutdown*/
UINT32 cthread_node_shutdown(CTHREAD_NODE *cthread_node, CTHREAD_POOL *cthread_pool);

UINT32 cthread_node_busy_to_idle(CTHREAD_NODE *cthread_node, CTHREAD_POOL *cthread_pool);

UINT32 cthread_node_run(CTHREAD_NODE *cthread_node, CTHREAD_POOL *cthread_pool);

void cthread_node_print(LOG *log, const CTHREAD_NODE *cthread_node);

/*create more cthread_num cthread_nodes and add them to cthread_pool*/
/*note: this function does not lock CTHREAD_POOL_WORKER_CMUTEX*/
UINT32 cthreadp_expand_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 cthread_num, const UINT32 flag);

/*create cthread_num cthread_nodes and add them to cthread_pool*/
UINT32 cthreadp_create_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 cthread_num, const UINT32 flag);

/*shrink at most max_cthread_num idle cthread_nodes from cthread_pool, return num of shrinked cthread_nodes*/
/*note: this function does not lock CTHREAD_POOL_WORKER_CMUTEX*/
UINT32 cthreadp_shrink_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 max_cthread_num_to_shrink);

CTHREAD_POOL * cthreadp_new(const UINT32 cthread_num, const UINT32 flag);

UINT32 cthreadp_init(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_clean(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_free(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_shutdown(CTHREAD_POOL *cthread_pool);

CTHREAD_NODE *cthreadp_reserve_node(CTHREAD_POOL *cthread_pool);

CTHREAD_NODE * cthreadp_reserve_no_lock(CTHREAD_POOL *cthread_pool);

CTHREAD_NODE * cthreadp_reserve(CTHREAD_POOL *cthread_pool);

CTHREAD_NODE * cthreadp_load_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 start_routine_addr, const UINT32 para_num, va_list para_list);

CTHREAD_NODE * cthreadp_load(CTHREAD_POOL *cthread_pool, const UINT32 start_routine_addr, const UINT32 para_num, ...);

EC_BOOL cthreadp_unload(CTHREAD_POOL *cthread_pool, CTHREAD_NODE *cthread_node);

UINT32 cthreadp_size_no_lock(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_idle_num_no_lock(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_busy_num_no_lock(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_num_info_no_lock(CTHREAD_POOL *cthread_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *post_num, UINT32 *total_num);

UINT32 cthreadp_size(CTHREAD_POOL *cthread_pool);

EC_BOOL cthreadp_size_reset(CTHREAD_POOL *cthread_pool, const UINT32 cthread_num);

UINT32 cthreadp_idle_num(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_busy_num(CTHREAD_POOL *cthread_pool);

UINT32 cthreadp_num_info(CTHREAD_POOL *cthread_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *post_num, UINT32 *total_num);

void cthreadp_print(LOG *log, const CTHREAD_POOL *cthread_pool);


#endif/* _CTHREAD_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

