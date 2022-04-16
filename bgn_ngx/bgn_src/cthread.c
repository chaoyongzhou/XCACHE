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
#include <stdarg.h>
#include <string.h>

#include <pthread.h>
#include <errno.h>

#include "type.h"

#include "clist.h"

#include "log.h"

#include "cmutex.h"
#include "cthread.h"

#include "task.inc"
#include "task.h"

#include "debug.h"
#include "csig.h"

/**************************************************************************************************
* note:
* ====
*
* pthread_self()     : return the current pthread/process address in some OS
* syscall(SYS_gettid): return thread id in linux OS
*
* thread pool design principle
* =============================
* 1. thread is manageed by cthread_node
* 2. cthread_node pool are created and suspend by condition lock in each cthread_node
* 3. each cthread_node own cthread_task pointer which is alloced when cthread_node creating
* 4. cthread_node pool own two lists, one is for idle cthread_nodes and the other is for
*    busy(working) cthread_nodes
* 5. when user want to ask one thread for function calling, should do
*   5.1. reserve one idle cthread_node and pop from idle list of the pool
*   5.2. load the function calling convention to cthread_task of cthread_node
*   5.3. push the cthread_node to busy list of the pool after mark the cthread_node as busy status
*   5.4. release the condition lock of cthread_node
* 6. when a function calling in thread come to end, do
*   6.1. umount the cthread_node from busy list of the pool
*   6.2. mark the chtread_node as idle status
*   6.3. push the cthread_node to idle list of the pool
* 7. when shutdown cthread_node, user can cancel it or join its ending. depend on
*   7.1. for idle cthread_node,
*       7.1.1. mark it as shutdown status
*       7.1.2. release conditon lock
*       7.1.3. the thread will terminate automatically with cleaning up fallback
*   7.2. for busy cthread_node,
*       7.2.1. mark it as shutdown status
*       7.2.2. cancel it forcely
*       7.2.3. the thread will be terminated with cleaning up fallback
* 8.
**************************************************************************************************/

UINT32 cthread_caller(const UINT32 start_routine_addr, const UINT32 arg_num, UINT32 *arg_list)
{
    UINT32 ret;

#if (16 != CTHREAD_MAX_ARG_NUM)
#error "fatal error:cthread.c: CTHREAD_MAX_ARG_NUM != 16"
#endif

    #define LOGIC_ADDR(x)       (x)
    #define PARA_VALUE(arg_list, x)    ((arg_list)[ (x) ])

    #define PARA_LIST_0(arg_list)    /*no parameter*/
    #define PARA_LIST_1(arg_list)    PARA_VALUE(arg_list, 0)
    #define PARA_LIST_2(arg_list)    PARA_LIST_1(arg_list) ,PARA_VALUE(arg_list, 1)
    #define PARA_LIST_3(arg_list)    PARA_LIST_2(arg_list) ,PARA_VALUE(arg_list, 2)
    #define PARA_LIST_4(arg_list)    PARA_LIST_3(arg_list) ,PARA_VALUE(arg_list, 3)
    #define PARA_LIST_5(arg_list)    PARA_LIST_4(arg_list) ,PARA_VALUE(arg_list, 4)
    #define PARA_LIST_6(arg_list)    PARA_LIST_5(arg_list) ,PARA_VALUE(arg_list, 5)
    #define PARA_LIST_7(arg_list)    PARA_LIST_6(arg_list) ,PARA_VALUE(arg_list, 6)
    #define PARA_LIST_8(arg_list)    PARA_LIST_7(arg_list) ,PARA_VALUE(arg_list, 7)
    #define PARA_LIST_9(arg_list)    PARA_LIST_8(arg_list) ,PARA_VALUE(arg_list, 8)
    #define PARA_LIST_10(arg_list)   PARA_LIST_9(arg_list) ,PARA_VALUE(arg_list, 9)
    #define PARA_LIST_11(arg_list)   PARA_LIST_10(arg_list),PARA_VALUE(arg_list, 10)
    #define PARA_LIST_12(arg_list)   PARA_LIST_11(arg_list),PARA_VALUE(arg_list, 11)
    #define PARA_LIST_13(arg_list)   PARA_LIST_12(arg_list),PARA_VALUE(arg_list, 12)
    #define PARA_LIST_14(arg_list)   PARA_LIST_13(arg_list),PARA_VALUE(arg_list, 13)
    #define PARA_LIST_15(arg_list)   PARA_LIST_14(arg_list),PARA_VALUE(arg_list, 14)
    #define PARA_LIST_16(arg_list)   PARA_LIST_15(arg_list),PARA_VALUE(arg_list, 15)

    #define FUNC_CALL(x, start_routine_addr, arg_list) \
            ((FUNC_TYPE_##x) LOGIC_ADDR(start_routine_addr))(PARA_LIST_##x(arg_list))

    switch(arg_num)
    {
        case 0:
            ret = FUNC_CALL(0, start_routine_addr, arg_list);
            break;
        case 1:
            ret = FUNC_CALL(1, start_routine_addr, arg_list);
            break;
        case 2:
            ret = FUNC_CALL(2, start_routine_addr, arg_list);
            break;
        case 3:
            ret = FUNC_CALL(3, start_routine_addr, arg_list);
            break;
        case 4:
            ret = FUNC_CALL(4, start_routine_addr, arg_list);
            break;
        case 5:
            ret = FUNC_CALL(5, start_routine_addr, arg_list);
            break;
        case 6:
            ret = FUNC_CALL(6, start_routine_addr, arg_list);
            break;
        case 7:
            ret = FUNC_CALL(7, start_routine_addr, arg_list);
            break;
        case 8:
            ret = FUNC_CALL(8, start_routine_addr, arg_list);
            break;
        case 9:
            ret = FUNC_CALL(9, start_routine_addr, arg_list);
            break;
        case 10:
            ret = FUNC_CALL(10, start_routine_addr, arg_list);
            break;
        case 11:
            ret = FUNC_CALL(11, start_routine_addr, arg_list);
            break;
        case 12:
            ret = FUNC_CALL(12, start_routine_addr, arg_list);
            break;
        case 13:
            ret = FUNC_CALL(13, start_routine_addr, arg_list);
            break;
        case 14:
            ret = FUNC_CALL(14, start_routine_addr, arg_list);
            break;
        case 15:
            ret = FUNC_CALL(15, start_routine_addr, arg_list);
            break;
        case 16:
            ret = FUNC_CALL(16, start_routine_addr, arg_list);
            break;
        default:
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_caller: arg num = %ld overflow\n", arg_num);
            return ((UINT32)(-1));
    }

    #undef LOGIC_ADDR
    #undef PARA_VALUE

    #undef PARA_LIST_0
    #undef PARA_LIST_1
    #undef PARA_LIST_2
    #undef PARA_LIST_3
    #undef PARA_LIST_4
    #undef PARA_LIST_5
    #undef PARA_LIST_6
    #undef PARA_LIST_7
    #undef PARA_LIST_8
    #undef PARA_LIST_9
    #undef PARA_LIST_10
    #undef PARA_LIST_11
    #undef PARA_LIST_12
    #undef PARA_LIST_13
    #undef PARA_LIST_14
    #undef PARA_LIST_15
    #undef PARA_LIST_16

    #undef FUNC_CALL

    return ( ret );
}


void cthread_killme(void *args)
{
    return;
}

EC_BOOL cthread_kill(CTHREAD_ID cthread_id, int signo)
{
    if(0 != pthread_kill(cthread_id, signo))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_kill: "
                                                "send signo %d to thread %ld failed, "
                                                "errno = %d, errstr = %s\n",
                                                signo, cthread_id,
                                                errno, strerror(errno));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL cthread_check_tcid_offset()
{
    if(CTHREAD_GET_TID() != CTHREAD_FETCH_TID(pthread_self(), CTHREAD_TID_OFFSET))
    {
        UINT32 offset;
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "fatal error:cthread_check_tcid_offset: invalid tid offset %ld, where pthread_self = %ld, got tid = %ld, fetched tid = %d\n",
                            CTHREAD_TID_OFFSET,
                            pthread_self(),
                            CTHREAD_GET_TID(),
                            CTHREAD_FETCH_TID(pthread_self(), CTHREAD_TID_OFFSET)
                            );
        for(offset = 0; offset < 1024; offset ++)
        {
            if(CTHREAD_GET_TID() == CTHREAD_FETCH_TID(pthread_self(), offset))
            {
                sys_log(LOGSTDOUT,
                        "[DEBUG] cthread_check_tcid_offset: possible tid offset is %ld, please revise definition of CTHREAD_TID_OFFSET and try it\n",
                        offset);
            }
        }
        exit(0);
    }
    return (EC_TRUE);
}

void * cthread_start(void *args)
{
    CTHREAD_TASK  *cthread_task;

    int oldstate;
    int oldtype;

    //dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthread_start: [%u] say hello, args = %lx\n", pthread_self(), args);

    /*check once when a thread is created. the checking can only happen on thread internally due to CTHREAD_GET_TID() operation*/
    //cthread_check_tcid_offset();

#if (SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)
    {
        cpu_set_t mask;
        UINT32 core_idx;
        UINT32 core_num;
        int err;

        core_num = sysconf(_SC_NPROCESSORS_ONLN);

        CPU_ZERO(&mask);
        for(core_idx = 0; core_idx < core_num; core_idx ++)
        {
            CPU_SET(core_idx, &mask);
        }

        if (0 != (err = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask)))
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_start: setaffinity of thread %ld failed: %s\n",
                                pthread_self(), strerror(err));
        }
    }
#endif/*(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)*/

    oldstate = 0;
    oldtype  = 0;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE     , &oldstate);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype );
    pthread_cleanup_push( cthread_killme, NULL_PTR );

    cthread_task = (CTHREAD_TASK *)args;

    /*now start the task*/
    cthread_caller(cthread_task->start_routine_addr, cthread_task->arg_num, cthread_task->arg_list);
    //cthread_start_routine(cthread_arg);

    free_static_mem(MM_CTHREAD_TASK, cthread_task, LOC_CTHREAD_0001);

    pthread_cleanup_pop( 1 ); /* 1 here means that cthread_killme() will surely execute at the end of task */
    pthread_exit(NULL_PTR);

    return (NULL_PTR);
}

UINT32 cthread_attr_set(CTHREAD_ATTR *cthread_attr, const UINT32 flag)
{
    if(pthread_attr_init(cthread_attr))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: init thread attr failed\n");
        return ((UINT32) -1);
    }
#if 1
    if(pthread_attr_setinheritsched(cthread_attr, PTHREAD_EXPLICIT_SCHED))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set inheritsched failed\n");
        return ((UINT32) -1);
    }

    if(pthread_attr_setschedpolicy(cthread_attr, SCHED_OTHER))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set schedpolicy failed\n");
        return ((UINT32) -1);
    }
#endif
#if 0
    if(1)
    {
        int max_priority;
        int min_priority;

        sched_get_priority_max(max_priority);
        sched_get_priority_min(min_priority);

        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "max_priority = %u, min_priority = %u\n", max_priority, min_priority);
    }

    cthread_sched.sched_priority = 0; /* SCHED_RR (MAX_PRIORITY - ((th_priority * MAX_PRIORITY) / MAX_VXWORKS_PRIORITY)) */
    if(pthread_attr_setschedparam(cthread_attr, &cthread_sched))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set schedparam failed\n");
        return ((UINT32) -1);
    }
#endif

    if(CTHREAD_DETACHABLE & flag)
    {
        if(pthread_attr_setdetachstate(cthread_attr, PTHREAD_CREATE_DETACHED))
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set DETACHED state failed\n");
            return ((UINT32) -1);
        }
    }
    else
    {
        if(pthread_attr_setdetachstate(cthread_attr, PTHREAD_CREATE_JOINABLE))
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set JOINABLE state failed\n");
            return ((UINT32) -1);
        }
    }

    if(CTHREAD_PROCESS_LEVEL & flag)
    {
        if(pthread_attr_setscope(cthread_attr, PTHREAD_SCOPE_PROCESS) && 0 != errno)
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set PROCESS scope failed, errno = %d, errstr = %s\n", errno, strerror(errno));
            return ((UINT32) -1);
        }
    }
    else
    {
        if(pthread_attr_setscope(cthread_attr, PTHREAD_SCOPE_SYSTEM) && 0 != errno)
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set SYSTEM scope failed, errno = %d, errstr = %s\n", errno, strerror(errno));
            return ((UINT32) -1);
        }
    }

    if(pthread_attr_setstacksize(cthread_attr, CTHREAD_STACK_SIZE_DEFAULT))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set stacksize failed\n");
        return ((UINT32) -1);
    }

    if(pthread_attr_setguardsize(cthread_attr, CTHREAD_GUARD_SIZE_DEFAULT))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_attr_set: set guardsize failed\n");
        return ((UINT32) -1);
    }

    return (0);
}

UINT32 cthread_attr_clean(CTHREAD_ATTR *cthread_attr)
{
    pthread_attr_destroy(cthread_attr);
    return (0);
}

void cthread_do_nothing(void *none)
{
    dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthread_do_nothing was called\n");
    return;
}

CTHREAD_ID cthread_create(const UINT32 flag, const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num, va_list para_list)
{
    CTHREAD_ATTR  cthread_attr;
    //CTHREAD_SCHED cthread_sched;
    CTHREAD_ID    cthread_id;
    CTHREAD_TASK *cthread_task;

    int err;

    if(0 != cthread_attr_set(&cthread_attr, flag))
    {
        cthread_attr_clean(&cthread_attr);
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_create: failed to set attribute\n");
        return (ERR_CTHREAD_ID);
    }

    alloc_static_mem(MM_CTHREAD_TASK, &cthread_task, LOC_CTHREAD_0002);
    if(NULL_PTR == cthread_task)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_create: alloc CTHREAD_TASK failed\n");
        return (ERR_CTHREAD_ID);
    }

    /*initialize arg table*/
    cthread_task_init(cthread_task, start_routine_addr, core_id, para_num, para_list);

    if(0 != (err = pthread_create(&cthread_id, &cthread_attr, cthread_start, (void *)cthread_task)))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_create: create thread failed: %s\n", strerror(err));
        free_static_mem(MM_CTHREAD_TASK, cthread_task, LOC_CTHREAD_0003);
        return (ERR_CTHREAD_ID);
    }

    if(cthread_attr_clean(&cthread_attr))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_create: destroy thread attr failed\n");
        //return (ERR_CTHREAD_ID);
    }

    return (cthread_id);
}

CTHREAD_ID cthread_new(const UINT32 flag, const char *name, const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num, ...)
{
    CTHREAD_ID cthread_id;

    //TASK_BRD *task_brd;

    va_list para_list;

    dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "[DEBUG] cthread_new: %s\n", name);

    cthread_check_tcid_offset();/*assert!*/

    //task_brd = task_brd_default_get();

    va_start(para_list, para_num);
    cthread_id = cthread_create(flag, start_routine_addr, core_id, para_num, para_list);
    va_end(para_list);

    return (cthread_id);
}

EC_BOOL cthread_wait(CTHREAD_ID cthread_id)
{
    int ret_val;

    ret_val = pthread_join(cthread_id, NULL_PTR);
    if( ret_val != 0 )
    {
        switch( ret_val )
        {
            case EINVAL:
            {
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_wait - EINVAL: cthread_id %ld NOT refer to a joinable thread\n", cthread_id);
                break;
            }

            case ESRCH:
            {
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_wait - ESRCH: cthread_id %ld not found\n", cthread_id);
                break;
            }

            case EDEADLK:
            {
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_wait - EDEADLK: cthread_id %ld detect deadlock\n", cthread_id);
                break;
            }

            default:
            {
                /* Unknown error */
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_wait - UNKNOWN: cthread_id %ld var detect error, error no: %d, error info: %s\n", cthread_id, ret_val, strerror(ret_val));
                break;
            }
        }
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cthread_cancel(CTHREAD_ID cthread_id)
{
    int ret_val;

    ret_val = pthread_cancel(cthread_id);
    if( ret_val != 0 )
    {
        switch( ret_val )
        {
            case ESRCH:
            {
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_cancel - ESRCH: cthread_id %ld not found\n", cthread_id);
                break;
            }

            default:
            {
                /* Unknown error */
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_cancel - UNKNOWN: cthread_id %ld var detect error, error no: %d, error info: %s\n", cthread_id, ret_val, strerror(ret_val));
                break;
            }
        }
        return (EC_FALSE);
    }

    ret_val = pthread_join(cthread_id, NULL_PTR);
    if( ret_val != 0 )
    {
        switch( ret_val )
        {
            case EINVAL:
            {
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_cancel - EINVAL: cthread_id %ld NOT refer to a joinable thread\n", cthread_id);
                break;
            }

            case ESRCH:
            {
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_cancel - ESRCH: cthread_id %ld not found\n", cthread_id);
                break;
            }

            case EDEADLK:
            {
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_cancel - EDEADLK: cthread_id %ld detect deadlock\n", cthread_id);
                break;
            }

            default:
            {
                /* Unknown error */
                dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_cancel - UNKNOWN: cthread_id %ld var detect error, error no: %d, error info: %s\n", cthread_id, ret_val, strerror(ret_val));
                break;
            }
        }
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CTHREAD_TASK *cthread_task_new(const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num, va_list para_list)
{
    CTHREAD_TASK *cthread_task;

    alloc_static_mem(MM_CTHREAD_TASK, &cthread_task, LOC_CTHREAD_0004);
    if(NULL_PTR == cthread_task)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_task_new: alloc CTHREAD_TASK failed\n");
        return (NULL_PTR);
    }

    cthread_task_init(cthread_task, start_routine_addr, core_id, para_num, para_list);
    return (cthread_task);
}

UINT32 cthread_task_init(CTHREAD_TASK *cthread_task, const UINT32 start_routine_addr, const UINT32 core_id, const UINT32 para_num, va_list para_list)
{
    UINT32 cthread_arg_idx;

    CTHREAD_TASK_ROUTINE(cthread_task) = start_routine_addr;
    for(cthread_arg_idx = 0; cthread_arg_idx < CTHREAD_MAX_ARG_NUM - 1 && cthread_arg_idx < para_num; cthread_arg_idx ++)
    {
        CTHREAD_TASK_ARG_VAL(cthread_task, cthread_arg_idx) = va_arg(para_list, UINT32);
    }
    CTHREAD_TASK_ARG_NUM(cthread_task) = cthread_arg_idx;
    CTHREAD_TASK_CORE_ID(cthread_task) = core_id;

    return (0);
}

UINT32 cthread_task_clone(const CTHREAD_TASK *cthread_task_src, CTHREAD_TASK *cthread_task_des)
{
    UINT32 cthread_arg_idx;

    CTHREAD_TASK_ROUTINE(cthread_task_des) = CTHREAD_TASK_ROUTINE(cthread_task_src);

    for(cthread_arg_idx = 0; cthread_arg_idx < CTHREAD_MAX_ARG_NUM - 1 && cthread_arg_idx < CTHREAD_TASK_ARG_NUM(cthread_task_src); cthread_arg_idx ++)
    {
        CTHREAD_TASK_ARG_VAL(cthread_task_des, cthread_arg_idx) = CTHREAD_TASK_ARG_VAL(cthread_task_src, cthread_arg_idx);
    }
    CTHREAD_TASK_ARG_NUM(cthread_task_des) = CTHREAD_TASK_ARG_NUM(cthread_task_src);
    CTHREAD_TASK_CORE_ID(cthread_task_des) = CTHREAD_TASK_CORE_ID(cthread_task_src);

    return (0);
}

UINT32 cthread_task_clean(CTHREAD_TASK *cthread_task)
{
    CTHREAD_TASK_ROUTINE(cthread_task) = 0;
    CTHREAD_TASK_ARG_NUM(cthread_task) = 0;
    CTHREAD_TASK_CORE_ID(cthread_task) = CTHREAD_ERR_CORE_ID;

    return (0);
}

UINT32 cthread_task_clear(CTHREAD_TASK *cthread_task)
{
    CTHREAD_TASK_ROUTINE(cthread_task) = 0;
    CTHREAD_TASK_ARG_NUM(cthread_task) = 0;
    //CTHREAD_TASK_CORE_ID(cthread_task) = CTHREAD_ERR_CORE_ID;

    return (0);
}

UINT32 cthread_task_free(CTHREAD_TASK *cthread_task)
{
    cthread_task_clean(cthread_task);
    free_static_mem(MM_CTHREAD_TASK, cthread_task, LOC_CTHREAD_0005);
    return (0);
}

void cthread_task_print(LOG *log, const CTHREAD_TASK *cthread_task)
{
    UINT32 arg_idx;

    sys_log(log, "cthread_task %lx: routine %lx, core id %ld, arg num %ld\n",
                cthread_task,
                CTHREAD_TASK_ROUTINE(cthread_task),
                CTHREAD_TASK_CORE_ID(cthread_task),
                CTHREAD_TASK_ARG_NUM(cthread_task)
            );

    for(arg_idx = 0; arg_idx < CTHREAD_TASK_ARG_NUM(cthread_task); arg_idx ++)
    {
        sys_log(log, "para #%ld: %lx\n", arg_idx, CTHREAD_TASK_ARG_VAL(cthread_task, arg_idx));
    }

    return;
}

STATIC_CAST static void cthread_unbind(CTHREAD_BIND *cthread_bind)
{
    CTHREAD_NODE *cthread_node;
    CTHREAD_POOL *cthread_pool;

    cthread_node = CTHREAD_BIND_NODE(cthread_bind);
    cthread_pool = CTHREAD_BIND_POOL(cthread_bind);

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0006);
    if(CTHREAD_IS_IDLE & CTHREAD_NODE_STATUS(cthread_node))
    {
        clist_rmv(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), CTHREAD_NODE_MOUNTED(cthread_node));

        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthread_unbind: free idle cthread_node %p with thread id %ld\n", cthread_node, CTHREAD_NODE_ID(cthread_node));
        cthread_node_free(cthread_node);
    }
    else if(CTHREAD_IS_BUSY & CTHREAD_NODE_STATUS(cthread_node))
    {
        clist_rmv(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool), CTHREAD_NODE_MOUNTED(cthread_node));

        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthread_unbind: free busy cthread_node %p with thread id %ld\n", cthread_node, CTHREAD_NODE_ID(cthread_node));
        cthread_node_free(cthread_node);
    }
    else
    {
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthread_unbind: free cthread_node %p with thread id %ld but status %lx\n",
                            cthread_node, CTHREAD_NODE_ID(cthread_node), CTHREAD_NODE_STATUS(cthread_node));
        cthread_node_free(cthread_node);
    }
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0007);

    safe_free(cthread_bind, LOC_CTHREAD_0008);

    return;
}

STATIC_CAST static UINT32 cthread_core_load_inc(CTHREAD_BIND *cthread_bind)
{
    UINT32 core_id;

    core_id = CTHREAD_NODE_CORE_ID(CTHREAD_BIND_NODE(cthread_bind));
    if(CTHREAD_MAX_CORE_NUM <= core_id)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_core_load_inc: invalid core id %ld\n", core_id);
        return ((UINT32)-1);
    }

    dbg_log(SEC_0016_CTHREAD, 9)(LOGSTDNULL, "[DEBUG] cthread_core_load_inc: core id %ld, load %ld ++\n",
                        core_id, CTHREAD_POOL_CORE_LOAD(CTHREAD_BIND_POOL(cthread_bind), core_id));

    CTHREAD_POOL_CORE_LOAD(CTHREAD_BIND_POOL(cthread_bind), core_id) ++;
    return (0);
}

STATIC_CAST static UINT32 cthread_core_load_dec(CTHREAD_BIND *cthread_bind)
{
    UINT32 core_id;

    core_id = CTHREAD_NODE_CORE_ID(CTHREAD_BIND_NODE(cthread_bind));
    if(CTHREAD_MAX_CORE_NUM <= core_id)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_core_load_dec: invalid core id %ld\n", core_id);
        return ((UINT32)-1);
    }

    if(0 < CTHREAD_POOL_CORE_LOAD(CTHREAD_BIND_POOL(cthread_bind), core_id))
    {
        dbg_log(SEC_0016_CTHREAD, 9)(LOGSTDNULL, "[DEBUG] cthread_core_load_dec: core id %ld, load %ld --\n",
                        core_id, CTHREAD_POOL_CORE_LOAD(CTHREAD_BIND_POOL(cthread_bind), core_id));

        CTHREAD_POOL_CORE_LOAD(CTHREAD_BIND_POOL(cthread_bind), core_id) --;
    }
    else
    {
        dbg_log(SEC_0016_CTHREAD, 9)(LOGSTDOUT, "[DEBUG] error: cthread_core_load_dec: core id %ld, load %ld --\n",
                        core_id, CTHREAD_POOL_CORE_LOAD(CTHREAD_BIND_POOL(cthread_bind), core_id));
    }
    return (0);
}

CTHREAD_NODE *cthread_node_new()
{
    CTHREAD_NODE *cthread_node;

    alloc_static_mem(MM_CTHREAD_NODE, &cthread_node, LOC_CTHREAD_0009);
    if(NULL_PTR == cthread_node)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_node_new: alloc CTHREAD_NODE failed\n");
        return (NULL_PTR);
    }

    cthread_node_init(cthread_node);

    return (cthread_node);
}

UINT32 cthread_node_init(CTHREAD_NODE *cthread_node)
{
    CTHREAD_NODE_ID(cthread_node) = ERR_CTHREAD_ID;

    CTHREAD_NODE_TASK(cthread_node)    = NULL_PTR;
    CTHREAD_NODE_STATUS(cthread_node)  = CTHREAD_IS_IDLE;
    CTHREAD_NODE_MOUNTED(cthread_node) = NULL_PTR;

    ccond_init(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0010);

    return (0);
}

void * cthread_node_entry(void *args)
{
    CTHREAD_TASK  entry_thread_task;

    int oldstate;
    int oldtype;

    /*when enter thread*/

    oldstate = 0;
    oldtype  = 0;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE     , &oldstate);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype );    /*ASYNCHRONOUS not need pthread_testcancel operation*/
    //pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype );      /*DEFERRED must have pthread_testcancel operation, otherwise, all pthread will hung up*/

    cthread_task_clone((CTHREAD_TASK  *)args, &entry_thread_task);
    cthread_task_free((CTHREAD_TASK  *)args);

#if (SWITCH_ON == CTHREAD_SET_CORE_SWITCH)
    {
        cpu_set_t mask;
        int err;

        CPU_ZERO(&mask);
        CPU_SET(CTHREAD_TASK_CORE_ID(&entry_thread_task), &mask);

        if (0 != (err = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask)))
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_node_entry: set thread to core %ld# failed: %s\n",
                                CTHREAD_TASK_CORE_ID(&entry_thread_task), strerror(err));
        }
    }
#endif/*(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)*/

    /*note: the branch (SWITCH_OFF == CTHREAD_SET_CORE_SWITCH) implemented in cthread_start()*/

#if (SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)
    {
        cpu_set_t mask;
        UINT32 core_idx;
        UINT32 core_num;
        int err;

        core_num = sysconf(_SC_NPROCESSORS_ONLN);

        CPU_ZERO(&mask);
        for(core_idx = 0; core_idx < core_num; core_idx ++)
        {
            CPU_SET(core_idx, &mask);
        }

        if (0 != (err = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask)))
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_node_entry: setaffinity of thread %ld failed: %s\n",
                                pthread_self(), strerror(err));
        }
    }
#endif/*(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)*/

    //dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "========================== cthread_node_entry: ==========================\n");
    //cthread_task_print(LOGSTDOUT, &entry_thread_task);
    cthread_caller(CTHREAD_TASK_ROUTINE(&entry_thread_task), CTHREAD_TASK_ARG_NUM(&entry_thread_task), CTHREAD_TASK_ARG_LIST(&entry_thread_task));
    return (NULL_PTR);
}

CTHREAD_ID cthread_node_create(CTHREAD_NODE *cthread_node, const CTHREAD_ATTR *cthread_attr, const UINT32 thread_entry_routine_addr, const UINT32 core_id, const UINT32 para_num, ...)
{
    CTHREAD_TASK  *entry_thread_task;

    va_list para_list;
    int err;

    va_start(para_list, para_num);
    entry_thread_task = cthread_task_new(thread_entry_routine_addr, core_id, para_num, para_list);
    va_end(para_list);

    if(NULL_PTR == entry_thread_task)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_node_create: alloc entry_thread_task failed\n");
        return (ERR_CTHREAD_ID);
    }

    CTHREAD_NODE_TASK(cthread_node) = cthread_task_new(0, core_id, 0, NULL_PTR);

    /**
    * ATTENTION:
    *
    *   the parameters of pthread_create cannot free in father process/thread
    *   because cannot determine whether the parameters will be used firstly by son thread or by father process/thread.
    *   if father free them firstly, the son thread will refer wrong and will trigger fatal error.
    *
    *   therefore, new entry_thread_task in father process/thread, and copy & free it in son thread.
    *
    **/

    if(0 != (err = pthread_create(&CTHREAD_NODE_ID(cthread_node), cthread_attr, cthread_node_entry, (void *)(entry_thread_task))))
    {
        cthread_task_free(entry_thread_task);
        cthread_task_free(CTHREAD_NODE_TASK(cthread_node));
        CTHREAD_NODE_TASK(cthread_node) = NULL_PTR;
        CTHREAD_NODE_ID(cthread_node)   = ERR_CTHREAD_ID;
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_node_create: create thread failed: %s\n", strerror(err));
        return (ERR_CTHREAD_ID);
    }

    return (CTHREAD_NODE_ID(cthread_node));
}

UINT32 cthread_node_clean(CTHREAD_NODE *cthread_node)
{
    if(ERR_CTHREAD_ID != CTHREAD_NODE_ID(cthread_node))
    {
        CTHREAD_NODE_STATUS(cthread_node) |= CTHREAD_IS_DOWN;

        ccond_release_all(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0011);

        //cthread_cancel(CTHREAD_NODE_ID(cthread_node));
        //cthread_wait(CTHREAD_NODE_ID(cthread_node));
        CTHREAD_NODE_ID(cthread_node) = ERR_CTHREAD_ID;

        CTHREAD_NODE_MOUNTED(cthread_node) = NULL_PTR;
    }

    //ccond_release_all(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0012);
    ccond_clean(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0013);

    if(NULL_PTR != CTHREAD_NODE_TASK(cthread_node))
    {
        cthread_task_free(CTHREAD_NODE_TASK(cthread_node));
        CTHREAD_NODE_TASK(cthread_node) = NULL_PTR;
    }

    return (0);
}

UINT32 cthread_node_free(CTHREAD_NODE *cthread_node)
{
    cthread_node_clean(cthread_node);
    free_static_mem(MM_CTHREAD_NODE, cthread_node, LOC_CTHREAD_0014);
    return (0);
}

/*note: cthread_node_shutdown will lock cthread_pool, so DO NOT call it when cthreadp_shutdown*/
UINT32 cthread_node_shutdown(CTHREAD_NODE *cthread_node, CTHREAD_POOL *cthread_pool)
{
    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0015);

    CTHREAD_NODE_STATUS(cthread_node) |= CTHREAD_IS_DOWN;

#if 0 /*1st method: slow but safe*/
    /*search & remove*/
    if(NULL_PTR != clist_del(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), cthread_node, NULL_PTR))
    {
        ccond_release_all(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0016);
        cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0017);
        return (0);
    }

    if(NULL_PTR != clist_del(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool), cthread_node, NULL_PTR))
    {
        cthread_cancel(CTHREAD_NODE_ID(cthread_node));
        cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0018);
        return (0);
    }

    dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_node_shutdown: neigher idle or busy cthread_node %p, status %ld, thread %ld\n",
                    cthread_node, CTHREAD_NODE_STATUS(cthread_node), CTHREAD_NODE_ID(cthread_node));

#endif

#if 1 /*2nd method: fast but unsafe*/
    if(CTHREAD_IS_IDLE & CTHREAD_NODE_STATUS(cthread_node))
    {
        clist_rmv(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), CTHREAD_NODE_MOUNTED(cthread_node));
        ccond_release_all(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0019);
        cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0020);
        return (0);
    }

    if(CTHREAD_IS_BUSY & CTHREAD_NODE_STATUS(cthread_node))
    {
        clist_rmv(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool), CTHREAD_NODE_MOUNTED(cthread_node));
        cthread_cancel(CTHREAD_NODE_ID(cthread_node));
        cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0021);
        return (0);
    }
#endif

    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0022);
    return (0);
}

UINT32 cthread_node_busy_to_idle(CTHREAD_NODE *cthread_node, CTHREAD_POOL *cthread_pool)
{
    /*move cthread_node from busy list to idle list*/
    CLIST_DATA *clist_data;

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0023);

    ccond_reserve(CTHREAD_NODE_CCOND(cthread_node), 1, LOC_CTHREAD_0024);
    clist_data = CTHREAD_NODE_MOUNTED(cthread_node);
    if(NULL_PTR != clist_data)
    {
        clist_rmv(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool), clist_data);
    }
    CTHREAD_NODE_STATUS(cthread_node)  = ((CTHREAD_NODE_STATUS(cthread_node) & CTHREAD_HI_MASK) | CTHREAD_IS_IDLE);
    CTHREAD_NODE_MOUNTED(cthread_node) = clist_push_back(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), cthread_node);

    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0025);

    return (0);
}

EC_BOOL cthread_get_core_id()
{
    cpu_set_t mask;
    UINT32 core_idx;
    UINT32 core_num;

    core_num = sysconf(_SC_NPROCESSORS_ONLN);

    CPU_ZERO(&mask);

    if (0 > pthread_getaffinity_np(pthread_self(), sizeof(mask), &mask))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_get_core_id: get thread %ld affinity failed\n", pthread_self());
        return (EC_FALSE);
    }

    for (core_idx = 0; core_idx < core_num; core_idx ++)
    {
        if (CPU_ISSET(core_idx, &mask))
        {
            dbg_log(SEC_0016_CTHREAD, 9)(LOGSTDOUT, "[DEBUG] cthread_get_core_id: thread %ld is running in processor %ld\n", pthread_self(), core_idx);
        }
    }
    return (EC_TRUE);
}

UINT32 cthread_node_run(CTHREAD_NODE *cthread_node, CTHREAD_POOL *cthread_pool)
{
    CTHREAD_TASK *cthread_task;
    CTHREAD_BIND *cthread_bind;

    /*note: cthread_bind will be free in cthread_unbind*/
    cthread_bind = safe_malloc(sizeof(CTHREAD_BIND), LOC_CTHREAD_0026);
    if(NULL_PTR == cthread_bind)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthread_node_run: malloc cthread_bind failed\n");
        return (-1);
    }

    CTHREAD_BIND_NODE(cthread_bind) = cthread_node;
    CTHREAD_BIND_POOL(cthread_bind) = cthread_pool;

    CTHREAD_CLEANUP_PUSH(cthread_unbind, cthread_bind);

#if (SWITCH_ON == CTHREAD_SET_CORE_SWITCH)
    CTHREAD_CLEANUP_PUSH(cthread_core_load_dec, cthread_bind);
#endif/*(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)*/

    for(;;)
    {
#if 0
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "[DBG] cthread_node_run: thread %ld, pthread self %u, cthread_node %p, status %ld\n",
                            CTHREAD_NODE_ID(cthread_node), pthread_self(),
                            cthread_node, CTHREAD_NODE_STATUS(cthread_node)
                );
#endif
        ccond_wait(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0027);

        CTHREAD_CORE_LOAD_INC(cthread_bind);

        //cthread_get_core_id();

        cthread_task = CTHREAD_NODE_TASK(cthread_node);

        if(CTHREAD_IS_DOWN & CTHREAD_NODE_STATUS(cthread_node))
        {
            CTHREAD_CORE_LOAD_DEC(cthread_bind);
            break;
        }

        /*as design, only busy cthread_node can reach here*/
        if(CTHREAD_IS_IDLE & CTHREAD_NODE_STATUS(cthread_node))
        {
            dbg_log(SEC_0016_CTHREAD, 1)(LOGSTDOUT, "warn:cthread_node_run: cthread node status is idle with thread %ld\n", CTHREAD_NODE_ID(cthread_node));

            /*move it from busy list to idle list*/
            cthread_node_busy_to_idle(cthread_node, cthread_pool);

            CTHREAD_CORE_LOAD_DEC(cthread_bind);
            continue;
        }

        if(NULL_PTR == CTHREAD_NODE_TASK(cthread_node))
        {
            dbg_log(SEC_0016_CTHREAD, 1)(LOGSTDOUT, "warn:cthread_node_run: busy but no task, return thread %ld to idle list\n", CTHREAD_NODE_ID(cthread_node));

            /*move it from busy list to idle list*/
            cthread_node_busy_to_idle(cthread_node, cthread_pool);

            CTHREAD_CORE_LOAD_DEC(cthread_bind);
            continue;
        }

        cthread_task = CTHREAD_NODE_TASK(cthread_node);
        cthread_caller(CTHREAD_TASK_ROUTINE(cthread_task), CTHREAD_TASK_ARG_NUM(cthread_task), CTHREAD_TASK_ARG_LIST(cthread_task));
        cthread_task_clear(cthread_task);/*do not clear core_id info*/

        /*move it from busy list to idle list*/
        cthread_node_busy_to_idle(cthread_node, cthread_pool);

        CTHREAD_CORE_LOAD_DEC(cthread_bind);
    }

    dbg_log(SEC_0016_CTHREAD, 1)(LOGSTDOUT, "warn:cthread_node_run: cthread_node %p was dying.....\n", cthread_node);

#if (SWITCH_ON == CTHREAD_SET_CORE_SWITCH)
    CTHREAD_CLEANUP_POP( 0 );
#endif/*(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)*/

    CTHREAD_CLEANUP_POP( 1 ); /* 1 here means that cthread_node_cleanup() will surely execute at the end of task */
    CTHREAD_EXIT(NULL_PTR);

    return (0);
}

void cthread_node_print(LOG *log, const CTHREAD_NODE *cthread_node)
{
    UINT32 ccond_counter;

    ccond_counter = ccond_spy((CCOND *)CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0028);
    sys_log(log, "cthread_node %p: thread id %ld, ccond counter %ld, thread task:\n",
                cthread_node,
                CTHREAD_NODE_ID(cthread_node),
                ccond_counter
                );

    //cthread_task_print(log, CTHREAD_NODE_TASK(cthread_node));

    return;
}

/*note: this function should also work for core_max_num = 1*/
STATIC_CAST static UINT32 cthreadp_unused_core_id(CTHREAD_POOL *cthread_pool, const UINT32 core_max_num, const UINT32 core_id_except)
{
    UINT32 core_id;
    core_id = CTHREAD_POOL_CORE_MAX_ID_USED(cthread_pool) + 1;

    if(core_id_except == (core_id % core_max_num))
    {
        core_id ++;
    }

    CTHREAD_POOL_CORE_MAX_ID_USED(cthread_pool) = core_id;

    return (core_id % core_max_num);
}

/*create more cthread_num cthread_nodes and add them to cthread_pool*/
/*note: this function does not lock CTHREAD_POOL_WORKER_CMUTEX*/
UINT32 cthreadp_expand_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 cthread_num, const UINT32 flag)
{
    CTHREAD_ATTR  cthread_attr;

    UINT32        cthread_idx;
    UINT32        core_max_num;
    UINT32        core_id_except;

    if(CTHREAD_ERR_FLAG == flag)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthreadp_expand_no_lock: invalid cthread flag %lx\n", flag);
        return (0);
    }

    if(0 != cthread_attr_set(&cthread_attr, flag))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthreadp_expand_no_lock: failed to set attribute\n");
        cthread_attr_clean(&cthread_attr);
        return (0);
    }

    core_max_num   = sysconf(_SC_NPROCESSORS_ONLN);
    core_id_except = (task_brd_default_get_rank() % core_max_num);

    for(cthread_idx = 0; cthread_idx < cthread_num; cthread_idx ++)
    {
        CTHREAD_NODE *cthread_node;

        cthread_node = cthread_node_new();
        if(NULL_PTR == cthread_node)
        {
            dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthreadp_expand_no_lock: failed to new # %ld CTHREAD_NODE\n", cthread_idx);
            break;
        }

        if(ERR_CTHREAD_ID == cthread_node_create(cthread_node, &cthread_attr,
                                                 (UINT32)cthread_node_run,
                                                 cthreadp_unused_core_id(cthread_pool, core_max_num, core_id_except), /*core id*/
                                                 (UINT32)2, /*para num*/
                                                 cthread_node,
                                                 cthread_pool))
        {
            cthread_node_free(cthread_node);
            dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_expand_no_lock: cthread_node_create failed while total thread %ld, support max worker num %ld\n",
                                clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool)) + clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool)),
                                CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool));
            break;
        }

        ccond_reserve(CTHREAD_NODE_CCOND(cthread_node), 1, LOC_CTHREAD_0029);

        CTHREAD_NODE_STATUS(cthread_node)  = ((CTHREAD_NODE_STATUS(cthread_node) & CTHREAD_HI_MASK) | CTHREAD_IS_IDLE);
        CTHREAD_NODE_MOUNTED(cthread_node) = clist_push_back(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), (void *)cthread_node);
    }

    cthread_attr_clean(&cthread_attr);

    return (cthread_idx);
}

/*create cthread_num cthread_nodes and add them to cthread_pool*/
UINT32 cthreadp_create_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 cthread_num, const UINT32 flag)
{
    UINT32 succ_cthread_num;

    succ_cthread_num = cthreadp_expand_no_lock(cthread_pool, DMIN(cthread_num, CTHREAD_EXPAND_MIN_NUM), flag);
    CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool) = cthread_num;
    CTHREAD_POOL_WORKER_FLAG(cthread_pool)    = flag;

    return (succ_cthread_num);
}

/*shrink at most max_cthread_num idle cthread_nodes from cthread_pool, return num of shrinked cthread_nodes*/
/*note: this function does not lock CTHREAD_POOL_WORKER_CMUTEX*/
UINT32 cthreadp_shrink_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 cthread_num_to_shrink)
{
    CTHREAD_NODE *cthread_node;
    UINT32 cthread_num_shrinked;

    for(
         cthread_num_shrinked = 0;
         cthread_num_shrinked < cthread_num_to_shrink && EC_FALSE == clist_is_empty(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
         cthread_num_shrinked ++/*, CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool) --*/
       )
    {
        cthread_node = (CTHREAD_NODE *)clist_pop_front(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
        CTHREAD_NODE_STATUS(cthread_node) |= CTHREAD_IS_DOWN;
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_shrink_no_lock: shutdown idle cthread_node %p, thread %ld\n", cthread_node, CTHREAD_NODE_ID(cthread_node));
        ccond_release_all(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0030);
        cthread_node_free(cthread_node);/*Jan 12, 2017*/
    }

    dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_shrink_no_lock report: to shrink %ld cthread_nodes, actually shrinked %ld cthread_nodes, current support max %ld cthread_nodes\n",
                        cthread_num_to_shrink, cthread_num_shrinked, CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool));
    return (cthread_num_shrinked);
}

CTHREAD_POOL * cthreadp_new(const UINT32 cthread_num, const UINT32 flag)
{
    CTHREAD_POOL *cthread_pool;

    alloc_static_mem(MM_CTHREAD_POOL, &cthread_pool, LOC_CTHREAD_0031);
    if(NULL_PTR == cthread_pool)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthreadp_new: alloc CTHREAD_POOL failed\n");
        return (NULL_PTR);
    }

    cthreadp_init(cthread_pool);
    cthreadp_create_no_lock(cthread_pool, cthread_num, flag);

    return (cthread_pool);
}

UINT32 cthreadp_init(CTHREAD_POOL *cthread_pool)
{
    UINT32 core_id;

    clist_init(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), MM_IGNORE, LOC_CTHREAD_0032);
    clist_init(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool), MM_IGNORE, LOC_CTHREAD_0033);
    cmutex_init(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), CMUTEX_PROCESS_PRIVATE, LOC_CTHREAD_0034);

    CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool) = 0;
    CTHREAD_POOL_WORKER_FLAG(cthread_pool)    = CTHREAD_ERR_FLAG;

    for(core_id = 0; core_id < CTHREAD_MAX_CORE_NUM; core_id ++)
    {
        CTHREAD_POOL_CORE_LOAD(cthread_pool, core_id) = 0;
    }

    CTHREAD_POOL_CORE_MAX_ID_USED(cthread_pool) = 0;

    return (0);
}


UINT32 cthreadp_shutdown(CTHREAD_POOL *cthread_pool)
{
    CTHREAD_NODE *cthread_node;
    UINT32 core_id;

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0035);
    //dbg_log(SEC_0016_CTHREAD, 3)(LOGSTDOUT, "info:cthreadp_shutdown enter\n");

    while(EC_FALSE == clist_is_empty(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool)))
    {
        cthread_node = (CTHREAD_NODE *)clist_pop_front(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
        CTHREAD_NODE_STATUS(cthread_node) |= CTHREAD_IS_DOWN;
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_shutdown: shutdown idle cthread_node %p, thread %ld\n", cthread_node, CTHREAD_NODE_ID(cthread_node));
        ccond_release_all(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0036);
    }

    while(EC_FALSE == clist_is_empty(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool)))
    {
        cthread_node = (CTHREAD_NODE *)clist_pop_front(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));

        CTHREAD_NODE_STATUS(cthread_node) |= CTHREAD_IS_DOWN;
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_shutdown: shutdown busy cthread_node %p, thread %ld\n", cthread_node, CTHREAD_NODE_ID(cthread_node));
        cthread_cancel(CTHREAD_NODE_ID(cthread_node));
    }

    //dbg_log(SEC_0016_CTHREAD, 3)(LOGSTDOUT, "info:cthreadp_shutdown leave\n");
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0037);

    for(core_id = 0; core_id < CTHREAD_MAX_CORE_NUM; core_id ++)
    {
        CTHREAD_POOL_CORE_LOAD(cthread_pool, core_id) = 0;
    }
    CTHREAD_POOL_CORE_MAX_ID_USED(cthread_pool) = 0;
    return (0);
}

UINT32 cthreadp_clean(CTHREAD_POOL *cthread_pool)
{
    cthreadp_shutdown(cthread_pool);
    cmutex_clean(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0038);
    return (0);
}

UINT32 cthreadp_free(CTHREAD_POOL *cthread_pool)
{
    cthreadp_clean(cthread_pool);
    free_static_mem(MM_CTHREAD_POOL, cthread_pool, LOC_CTHREAD_0039);
    return (0);
}

CTHREAD_NODE *cthreadp_reserve_node(CTHREAD_POOL *cthread_pool)
{
    CLIST_DATA *clist_data;

    CLIST_DATA *clist_data_min;
    UINT32  core_load_min;

    core_load_min  = ((UINT32)-1);/*set to max value*/
    clist_data_min = NULL_PTR;

    CLIST_LOCK(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), LOC_CTHREAD_0040);
    CLIST_LOOP_NEXT(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), clist_data)
    {
        CTHREAD_NODE *cthread_node;
        UINT32  core_load;

        cthread_node = (CTHREAD_NODE *)CLIST_DATA_DATA(clist_data);
        core_load    = CTHREAD_POOL_CORE_LOAD(cthread_pool, CTHREAD_NODE_CORE_ID(cthread_node));
        if(core_load_min > core_load)
        {
            core_load_min  = core_load;
            clist_data_min = clist_data;
        }
    }

    if(NULL_PTR != clist_data_min)
    {
        CTHREAD_NODE *cthread_node_min;
        cthread_node_min = (CTHREAD_NODE *)clist_rmv_no_lock(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), clist_data_min);
        CLIST_UNLOCK(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), LOC_CTHREAD_0041);

        return (cthread_node_min);
    }

    CLIST_UNLOCK(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), LOC_CTHREAD_0042);
    return (NULL_PTR);
}

CTHREAD_NODE * cthreadp_reserve_no_lock0(CTHREAD_POOL *cthread_pool)
{
    CTHREAD_NODE *cthread_node;
    UINT32        total_num;

    total_num = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool))
              + clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));

    if(total_num < CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool))
    {
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_reserve_no_lock: try to expand cthread num from %ld to %ld\n",
                            total_num, CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool));
        cthreadp_expand_no_lock(cthread_pool, CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool) - total_num, CTHREAD_POOL_WORKER_FLAG(cthread_pool));
    }

    if(total_num > CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool))
    {
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_reserve_no_lock: try to shrink cthread num from %ld to %ld\n",
                            total_num, CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool));

        cthreadp_shrink_no_lock(cthread_pool, total_num - CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool));
    }

#if(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)
    {
        cthread_node = cthreadp_reserve_node(cthread_pool);
    }
#endif/*(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)*/
#if(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)
    {
        //cthread_node = (CTHREAD_NODE *)clist_pop_front(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
        cthread_node = (CTHREAD_NODE *)clist_pop_back(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
    }
#endif/*(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)*/

    return (cthread_node);
}

CTHREAD_NODE * cthreadp_reserve_no_lock(CTHREAD_POOL *cthread_pool)
{
    CTHREAD_NODE *cthread_node;
    UINT32        total_num;
    UINT32        idle_num;
    UINT32        busy_num;

#if(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)
    {
        cthread_node = cthreadp_reserve_node(cthread_pool);
    }
#endif/*(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)*/
#if(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)
    {
        //cthread_node = (CTHREAD_NODE *)clist_pop_front(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
        cthread_node = (CTHREAD_NODE *)clist_pop_back(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
    }
#endif/*(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)*/

    if(NULL_PTR == cthread_node)
    {
        idle_num = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
        busy_num = clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));

        total_num = idle_num + busy_num;

        if(total_num < CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool))
        {
            UINT32 cthread_num;

            cthread_num = DMIN(CTHREAD_EXPAND_MIN_NUM, CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool) - total_num);

            dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_reserve_no_lock: try to expand cthread num from %ld to %ld\n",
                                total_num, cthread_num + total_num);
            cthreadp_expand_no_lock(cthread_pool, cthread_num, CTHREAD_POOL_WORKER_FLAG(cthread_pool));
        }

#if(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)
        {
            cthread_node = cthreadp_reserve_node(cthread_pool);
        }
#endif/*(SWITCH_ON == CTHREAD_SET_CORE_SWITCH)*/
#if(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)
        {
            //cthread_node = (CTHREAD_NODE *)clist_pop_front(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
            cthread_node = (CTHREAD_NODE *)clist_pop_back(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
        }
#endif/*(SWITCH_OFF == CTHREAD_SET_CORE_SWITCH)*/
    }

    idle_num = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
    busy_num = clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));

    total_num = idle_num + busy_num;
    if(total_num > CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool))
    {
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_reserve_no_lock: try to shrink cthread num from %ld to %ld\n",
                            total_num, CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool));

        cthreadp_shrink_no_lock(cthread_pool, total_num - CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool));
    }
#if 0
    if(CTHREAD_SHRINK_THRESHOLD <= idle_num)
    {
        dbg_log(SEC_0016_CTHREAD, 5)(LOGSTDOUT, "cthreadp_reserve_no_lock: try to shrink idle cthread num from %ld to %ld\n",
                            idle_num, idle_num - CTHREAD_SHRINK_MIN_NUM);

        cthreadp_shrink_no_lock(cthread_pool, CTHREAD_SHRINK_MIN_NUM);
    }
#endif
    return (cthread_node);
}

CTHREAD_NODE * cthreadp_reserve(CTHREAD_POOL *cthread_pool)
{
    CTHREAD_NODE *cthread_node;

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0043);
    cthread_node = cthreadp_reserve_no_lock(cthread_pool);
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0044);

    return (cthread_node);
}

CTHREAD_NODE * cthreadp_load_no_lock(CTHREAD_POOL *cthread_pool, const UINT32 start_routine_addr, const UINT32 para_num, va_list para_list)
{
    CTHREAD_NODE *cthread_node;

    cthread_node = cthreadp_reserve_no_lock(cthread_pool);
    if(NULL_PTR == cthread_node)
    {
        UINT32 idle_num;
        UINT32 busy_num;
        UINT32 post_num;
        UINT32 total_num;
        UINT32 max_num;

        cthreadp_num_info_no_lock(cthread_pool, &idle_num, &busy_num, &post_num, &total_num);
        max_num = CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool);

        dbg_log(SEC_0016_CTHREAD, 1)(LOGSTDNULL, "warn:cthreadp_load_no_lock: "
                    "failed to reserve one cthread_node where idle %ld, busy %ld, post %ld, total %ld, max %ld\n",
                    idle_num, busy_num, post_num, total_num, max_num);
        return (NULL_PTR);
    }

    if(0)
    {
        UINT32 idle_num;
        UINT32 busy_num;
        UINT32 post_num;
        UINT32 total_num;
        UINT32 max_num;

        cthreadp_num_info_no_lock(cthread_pool, &idle_num, &busy_num, &post_num, &total_num);
        max_num = CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool);

        dbg_log(SEC_0016_CTHREAD, 9)(LOGSTDOUT, "[DEBUG]cthreadp_load_no_lock: "
                    "idle %ld, busy %ld, post %ld, total %ld, max %ld\n",
                    idle_num, busy_num, post_num, total_num, max_num);
    }

    if(NULL_PTR == CTHREAD_NODE_TASK(cthread_node))
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthreadp_load_no_lock: cthread node %p task is null\n", cthread_node);

        clist_push_back(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), (void *)cthread_node);
        return (NULL_PTR);
    }

    cthread_task_init(CTHREAD_NODE_TASK(cthread_node), start_routine_addr, CTHREAD_NODE_CORE_ID(cthread_node), para_num, para_list);

    CTHREAD_NODE_STATUS(cthread_node)  = ((CTHREAD_NODE_STATUS(cthread_node) & CTHREAD_HI_MASK) | CTHREAD_IS_BUSY);
    CTHREAD_NODE_MOUNTED(cthread_node) = clist_push_back(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool), (void *)cthread_node);

    /*note: ccond_release MUST be called out of cthreadp_node, otherwise, user cannot determine when the cthread_node can be refered*/
    //ccond_release(CTHREAD_NODE_CCOND(cthread_node), LOC_CTHREAD_0045);

    return (cthread_node);
}

CTHREAD_NODE * cthreadp_load(CTHREAD_POOL *cthread_pool, const UINT32 start_routine_addr, const UINT32 para_num, ...)
{
    CTHREAD_NODE *cthread_node;
    va_list para_list;

    va_start(para_list, para_num);

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0046);
    cthread_node = cthreadp_load_no_lock(cthread_pool, start_routine_addr, para_num, para_list);
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0047);

    va_end(para_list);

    return (cthread_node);
}

EC_BOOL cthreadp_unload(CTHREAD_POOL *cthread_pool, CTHREAD_NODE *cthread_node)
{
    if(NULL_PTR == cthread_node)
    {
        dbg_log(SEC_0016_CTHREAD, 0)(LOGSTDOUT, "error:cthreadp_unload: cthread_node is null\n");
        return (EC_FALSE);
    }

    cthread_node_shutdown(cthread_node, cthread_pool);
    return (EC_TRUE);
}

UINT32 cthreadp_size_no_lock(CTHREAD_POOL *cthread_pool)
{
    UINT32 size;

    size = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool))
         + clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));

    return (size);
}

UINT32 cthreadp_idle_num_no_lock(CTHREAD_POOL *cthread_pool)
{
    UINT32 num;

    num = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));

    return (num);
}

UINT32 cthreadp_busy_num_no_lock(CTHREAD_POOL *cthread_pool)
{
    UINT32 num;

    num = clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));

    return (num);
}

UINT32 cthreadp_num_info_no_lock(CTHREAD_POOL *cthread_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *post_num, UINT32 *total_num)
{
    (*idle_num)  = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
    (*busy_num)  = clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));
    (*post_num)  = 0; /*TODO*/
    (*total_num) = (*idle_num) + (*busy_num);

    return (0);
}

UINT32 cthreadp_size(CTHREAD_POOL *cthread_pool)
{
    UINT32 size;

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0048);
    size = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool))
         + clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0049);

    return (size);
}

EC_BOOL cthreadp_size_reset(CTHREAD_POOL *cthread_pool, const UINT32 cthread_num)
{
    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0050);
    CTHREAD_POOL_WORKER_MAX_NUM(cthread_pool) = cthread_num;
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0051);

    return (EC_TRUE);
}

UINT32 cthreadp_idle_num(CTHREAD_POOL *cthread_pool)
{
    UINT32 num;

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0052);
    num = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0053);

    return (num);
}

UINT32 cthreadp_busy_num(CTHREAD_POOL *cthread_pool)
{
    UINT32 num;

    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0054);
    num = clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));
    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0055);

    return (num);
}

UINT32 cthreadp_num_info(CTHREAD_POOL *cthread_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *post_num, UINT32 *total_num)
{
    cmutex_lock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0056);
    (*idle_num)  = clist_size(CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool));
    (*busy_num)  = clist_size(CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool));
    (*post_num)  = 0; /*TODO*/
    (*total_num) = (*idle_num) + (*busy_num) + (*post_num);

    cmutex_unlock(CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0057);

    return (0);
}

void cthreadp_print(LOG *log, const CTHREAD_POOL *cthread_pool)
{
    UINT32 idle_num;
    UINT32 busy_num;
    UINT32 post_num;
    UINT32 total_num;

    cmutex_lock((CMUTEX *)CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0058);

    cthreadp_num_info_no_lock((CTHREAD_POOL *)cthread_pool, &idle_num, &busy_num, &post_num, &total_num);

    sys_log(log, "cthread_pool %lx: size %ld, idle %ld, busy %ld, post %ld\n",
                 cthread_pool, total_num, idle_num, busy_num, post_num
               );

    sys_log(log, "idle worker list:\n");
    clist_print(log, CTHREAD_POOL_WORKER_IDLE_LIST(cthread_pool), (CLIST_DATA_DATA_PRINT)cthread_node_print);

    sys_log(log, "busy worker list:\n");
    clist_print(log, CTHREAD_POOL_WORKER_BUSY_LIST(cthread_pool), (CLIST_DATA_DATA_PRINT)cthread_node_print);

    cmutex_unlock((CMUTEX *)CTHREAD_POOL_WORKER_CMUTEX(cthread_pool), LOC_CTHREAD_0059);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
