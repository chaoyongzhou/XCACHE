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
#include <ucontext.h>
#include <errno.h>

#include "type.h"
#include "log.h"
#include "task.inc"
#include "task.h"
#include "coroutine.h"


#if (64 == WORDSIZE) && ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 18)))
#define COROUTINE_FIX_BUG_SWITCH SWITCH_ON
#else
#define COROUTINE_FIX_BUG_SWITCH SWITCH_OFF
#endif

void coroutine_debug(LOG *log, const char *tip)
{
    COROUTINE_POOL *coroutine_pool;
    COROUTINE_NODE *coroutine_node_slave;
    COROUTINE_NODE *coroutine_node_self;

    coroutine_pool = TASK_BRD_CROUTINE_POOL(task_brd_default_get());
    coroutine_node_slave = coroutine_pool_get_slave(coroutine_pool);
    coroutine_node_self = coroutine_self();

    sys_log(log, "[DEBUG] %s coroutine_pool %p: idle (%p, %p, %ld), busy (%p, %p, %ld), slave %p (mounted %p), self %p (mounted %p)\n", tip,
            coroutine_pool,
            coroutine_pool->worker_idle_list.head.prev, coroutine_pool->worker_idle_list.head.next, coroutine_pool->worker_idle_list.size,
            coroutine_pool->worker_busy_list.head.prev, coroutine_pool->worker_busy_list.head.next, coroutine_pool->worker_busy_list.size,
            coroutine_node_slave, NULL_PTR == coroutine_node_slave ? NULL_PTR : COROUTINE_NODE_MOUNTED(coroutine_node_slave),
            coroutine_node_self, NULL_PTR == coroutine_node_self ? NULL_PTR : COROUTINE_NODE_MOUNTED(coroutine_node_self)
            );

    return;
}

COROUTINE_MUTEX *coroutine_mutex_new(const UINT32 location)
{
    COROUTINE_MUTEX      *coroutine_mutex;

    coroutine_mutex = (COROUTINE_MUTEX *)safe_malloc(sizeof(COROUTINE_MUTEX), LOC_COROUTINE_0001);
    if(NULL_PTR == coroutine_mutex)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_mutex_new: failed to alloc COROUTINE_MUTEX, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (NULL_PTR);
    }

    if(EC_FALSE == coroutine_mutex_init(coroutine_mutex, COROUTINE_MUTEX_IGNORE_FLAG, location))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_mutex_init: failed to init coroutine_mutex %p, called at %s:%ld\n", coroutine_mutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        safe_free(coroutine_mutex, LOC_COROUTINE_0002);
        return (NULL_PTR);
    }

    COROUTINE_MUTEX_INIT_LOCATION(coroutine_mutex);
    COROUTINE_MUTEX_SET_LOCATION(coroutine_mutex, COROUTINE_MUTEX_OP_NEW, location);

    return (coroutine_mutex);
}

EC_BOOL coroutine_mutex_init(COROUTINE_MUTEX *coroutine_mutex, const UINT32 flag, const UINT32 location)
{
    COROUTINE_MUTEX_SET_LOCATION(coroutine_mutex, COROUTINE_MUTEX_OP_INIT, location);
    COROUTINE_MUTEX_COUNTER(coroutine_mutex) = 0;
    return (EC_TRUE);
}

EC_BOOL coroutine_mutex_clean(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location)
{
    COROUTINE_MUTEX_SET_LOCATION(coroutine_mutex, COROUTINE_MUTEX_OP_CLEAN, location);
    COROUTINE_MUTEX_COUNTER(coroutine_mutex) = 0;
    return (EC_TRUE);
}

void    coroutine_mutex_free(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location)
{
    if(NULL_PTR != coroutine_mutex)
    {
        COROUTINE_MUTEX_SET_LOCATION(coroutine_mutex, COROUTINE_MUTEX_OP_FREE, location);
        coroutine_mutex_clean(coroutine_mutex, location);
        safe_free(coroutine_mutex, LOC_COROUTINE_0003);
    }
    return;
}

EC_BOOL coroutine_mutex_lock(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location)
{
    COROUTINE_NODE *coroutine_node_cur;

    COROUTINE_MUTEX_SET_LOCATION(coroutine_mutex, COROUTINE_MUTEX_OP_LOCK, location);

    coroutine_node_cur = COROUTINE_NODE_CUR_GET();
    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_MUTEX(coroutine_node_cur) = coroutine_mutex;

        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_mutex_lock: set user mutex %p to %p\n",
                            coroutine_mutex, coroutine_node_cur);
    }

    ++ COROUTINE_MUTEX_COUNTER(coroutine_mutex);

    while(1 != COROUTINE_MUTEX_COUNTER(coroutine_mutex))
    {
        if(__COROUTINE_IS_MASTER())
        {
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_mutex_lock: swap from %p to itself\n", COROUTINE_NODE_CUR_GET());
            COROUTINE_MUTEX_COUNTER(coroutine_mutex) = 1; /*reset forcibly*/
            break;
        }
        __COROUTINE_WAIT();
    }

    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_MUTEX(coroutine_node_cur) = NULL_PTR;/*clear forcibly*/
    }
    __COROUTINE_NO_WAIT();
    return (EC_TRUE);
}

EC_BOOL coroutine_mutex_unlock(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location)
{
    COROUTINE_NODE *coroutine_node_cur;

    COROUTINE_MUTEX_SET_LOCATION(coroutine_mutex, COROUTINE_MUTEX_OP_UNLOCK, location);
    //COROUTINE_ASSERT(0 < COROUTINE_MUTEX_COUNTER(coroutine_mutex));
    if(0 == COROUTINE_MUTEX_COUNTER(coroutine_mutex))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_mutex_unlock: found invalid at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        exit(0);
    }

    -- COROUTINE_MUTEX_COUNTER(coroutine_mutex);

    coroutine_node_cur = COROUTINE_NODE_CUR_GET();
    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_MUTEX(coroutine_node_cur) = NULL_PTR;/*clear forcibly*/
    }
    return (EC_TRUE);
}

COROUTINE_RWLOCK *coroutine_rwlock_new(const UINT32 location)
{
    COROUTINE_RWLOCK      *coroutine_rwlock;

    coroutine_rwlock = (COROUTINE_RWLOCK *)safe_malloc(sizeof(COROUTINE_RWLOCK), LOC_COROUTINE_0004);
    if(NULL_PTR == coroutine_rwlock)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_rwlock_new: failed to alloc COROUTINE_RWLOCK, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (NULL_PTR);
    }

    if(EC_FALSE == coroutine_rwlock_init(coroutine_rwlock, COROUTINE_RWLOCK_IGNORE_FLAG, location))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_rwlock_init: failed to init coroutine_rwlock %p, called at %s:%ld\n", coroutine_rwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        safe_free(coroutine_rwlock, LOC_COROUTINE_0005);
        return (NULL_PTR);
    }

    COROUTINE_RWLOCK_INIT_LOCATION(coroutine_rwlock);
    COROUTINE_RWLOCK_SET_LOCATION(coroutine_rwlock, COROUTINE_RWLOCK_OP_NEW, location);

    return (coroutine_rwlock);
}

EC_BOOL coroutine_rwlock_init(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 flag, const UINT32 location)
{
    COROUTINE_RWLOCK_SET_LOCATION(coroutine_rwlock, COROUTINE_RWLOCK_OP_INIT, location);
    COROUTINE_RWLOCK_READERS(coroutine_rwlock) = 0;
    COROUTINE_RWLOCK_WRITERS(coroutine_rwlock) = 0;
    return (EC_TRUE);
}

EC_BOOL coroutine_rwlock_clean(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location)
{
    COROUTINE_RWLOCK_SET_LOCATION(coroutine_rwlock, COROUTINE_RWLOCK_OP_CLEAN, location);
    COROUTINE_RWLOCK_READERS(coroutine_rwlock) = 0;
    COROUTINE_RWLOCK_WRITERS(coroutine_rwlock) = 0;
    return (EC_TRUE);
}

void    coroutine_rwlock_free(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location)
{
    if(NULL_PTR != coroutine_rwlock)
    {
        COROUTINE_RWLOCK_SET_LOCATION(coroutine_rwlock, COROUTINE_RWLOCK_OP_FREE, location);
        coroutine_rwlock_clean(coroutine_rwlock, location);
        safe_free(coroutine_rwlock, LOC_COROUTINE_0006);
    }
    return;
}

EC_BOOL coroutine_rwlock_rdlock(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location)
{
    COROUTINE_NODE *coroutine_node_cur;

    COROUTINE_RWLOCK_SET_LOCATION(coroutine_rwlock, COROUTINE_RWLOCK_OP_RDLOCK, location);
    ++ COROUTINE_RWLOCK_READERS(coroutine_rwlock);

    coroutine_node_cur = COROUTINE_NODE_CUR_GET();
    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_RWLOCK(coroutine_node_cur) = coroutine_rwlock;

        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_rwlock_rdlock: set user rwlock %p to %p\n",
                            coroutine_rwlock, coroutine_node_cur);
    }

    while(0 < COROUTINE_RWLOCK_WRITERS(coroutine_rwlock))
    {
        if(__COROUTINE_IS_MASTER())
        {
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_rwlock_rdlock: swap from %p to itself\n", COROUTINE_NODE_CUR_GET());
            COROUTINE_RWLOCK_READERS(coroutine_rwlock) = 0; /*reset forcibly*/
            break;
        }
        __COROUTINE_WAIT();
    }

    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_RWLOCK(coroutine_node_cur) = NULL_PTR;/*clear forcibly*/
    }

    __COROUTINE_NO_WAIT();
    return (EC_TRUE);
}

EC_BOOL coroutine_rwlock_wrlock(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location)
{
    COROUTINE_NODE *coroutine_node_cur;

    COROUTINE_RWLOCK_SET_LOCATION(coroutine_rwlock, COROUTINE_RWLOCK_OP_WRLOCK, location);

    coroutine_node_cur = COROUTINE_NODE_CUR_GET();
    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_RWLOCK(coroutine_node_cur) = coroutine_rwlock;

        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_rwlock_wrlock: set user rwlock %p to %p\n",
                            coroutine_rwlock, coroutine_node_cur);
    }

    while(0 < COROUTINE_RWLOCK_READERS(coroutine_rwlock) || 0 < COROUTINE_RWLOCK_WRITERS(coroutine_rwlock))
    {
        if(__COROUTINE_IS_MASTER())
        {
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_rwlock_wrlock: swap from %p to itself\n", COROUTINE_NODE_CUR_GET());
            COROUTINE_RWLOCK_READERS(coroutine_rwlock) = 0;/*reset forcibly*/
            COROUTINE_RWLOCK_WRITERS(coroutine_rwlock) = 0;/*reset forcibly*/
            break;
        }
        __COROUTINE_WAIT();
    }

    ++ COROUTINE_RWLOCK_WRITERS(coroutine_rwlock);

    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_RWLOCK(coroutine_node_cur) = NULL_PTR;/*clear forcibly*/
    }
    __COROUTINE_NO_WAIT();
    return (EC_TRUE);
}

EC_BOOL coroutine_rwlock_unlock(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location)
{
    COROUTINE_NODE *coroutine_node_cur;

    COROUTINE_RWLOCK_SET_LOCATION(coroutine_rwlock, COROUTINE_RWLOCK_OP_UNLOCK, location);
    if(0 < COROUTINE_RWLOCK_WRITERS(coroutine_rwlock))
    {
        -- COROUTINE_RWLOCK_WRITERS(coroutine_rwlock);
    }
    else
    {
        -- COROUTINE_RWLOCK_READERS(coroutine_rwlock);
    }

    coroutine_node_cur = COROUTINE_NODE_CUR_GET();
    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_RWLOCK(coroutine_node_cur) = NULL_PTR;/*clear forcibly*/
    }
    return (EC_TRUE);
}

COROUTINE_COND *coroutine_cond_new(const UINT32 timeout_msec, const UINT32 location)
{
    COROUTINE_COND      *coroutine_cond;

    alloc_static_mem(MM_COROUTINE_COND, &coroutine_cond, location);
    if(NULL_PTR == coroutine_cond)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_cond_new: failed to alloc coroutine_cond, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (NULL_PTR);
    }

    if(EC_FALSE == coroutine_cond_init(coroutine_cond, timeout_msec, location))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_cond_init: failed to init coroutine_cond %p, called at %s:%ld\n", coroutine_cond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        free_static_mem(MM_COROUTINE_COND, coroutine_cond, location);
        return (NULL_PTR);
    }

    COROUTINE_COND_INIT_LOCATION(coroutine_cond);
    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_NEW, location);
#if 0
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_new: current: %p, cond %p, counter %ld, timeout %ld ms at %s:%ld\n",
                                COROUTINE_NODE_CUR_GET(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond), timeout_msec,
                                MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
#endif
    return (coroutine_cond);
}

EC_BOOL coroutine_cond_init(COROUTINE_COND *coroutine_cond, const UINT32 timeout_msec, const UINT32 location)
{
    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_INIT, location);
    COROUTINE_COND_COUNTER(coroutine_cond)          = 0;
    COROUTINE_COND_TIMEOUT_MSEC(coroutine_cond)     = timeout_msec;
    COROUTINE_COND_TERMINATE_FLAG(coroutine_cond)   = BIT_FALSE;

    if(0 < timeout_msec)
    {
        uint64_t    time_msec_cur;

        time_msec_cur = task_brd_default_get_time_msec();
        COROUTINE_COND_S_MSEC(coroutine_cond) = time_msec_cur + 0;
        COROUTINE_COND_E_MSEC(coroutine_cond) = time_msec_cur + timeout_msec;
    }
    else
    {
        COROUTINE_COND_S_MSEC(coroutine_cond) = 0;
        COROUTINE_COND_E_MSEC(coroutine_cond) = 0;
    }

#if 1
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_init: current: %p, cond %p, counter %ld, timeout %ld ms at %s:%ld\n",
                                COROUTINE_NODE_CUR_GET(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond), timeout_msec,
                                MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
#endif
    return (EC_TRUE);
}

EC_BOOL coroutine_cond_clean(COROUTINE_COND *coroutine_cond, const UINT32 location)
{
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_clean: status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                        __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                        MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_CLEAN, location);
    COROUTINE_COND_COUNTER(coroutine_cond)        = 0;
    COROUTINE_COND_TIMEOUT_MSEC(coroutine_cond)   = 0;
    COROUTINE_COND_TERMINATE_FLAG(coroutine_cond) = BIT_FALSE;
    COROUTINE_COND_S_MSEC(coroutine_cond)         = 0;
    COROUTINE_COND_E_MSEC(coroutine_cond)         = 0;

    return (EC_TRUE);
}

void    coroutine_cond_free(COROUTINE_COND *coroutine_cond, const UINT32 location)
{
    if(NULL_PTR != coroutine_cond)
    {
#if 0
        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_free: status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                            __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                            MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
#endif
        COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_FREE, location);
        coroutine_cond_clean(coroutine_cond, location);
        free_static_mem(MM_COROUTINE_COND, coroutine_cond, LOC_COROUTINE_0007);
    }
    return;
}

EC_BOOL coroutine_cond_reserve(COROUTINE_COND *coroutine_cond, const UINT32 counter, const UINT32 location)
{
    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_RESERVE, location);
    COROUTINE_COND_COUNTER(coroutine_cond) += counter;
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_reserve: status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                                __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                                MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_TRUE);
}

EC_BOOL coroutine_cond_release(COROUTINE_COND *coroutine_cond, const UINT32 location)
{
    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_RELEASE, location);
    if(0 < COROUTINE_COND_COUNTER(coroutine_cond))
    {
        -- COROUTINE_COND_COUNTER(coroutine_cond);

        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_release: [Y] status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                                    __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                                    MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_TRUE);
    }

    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_release: [X] status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                                __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                                MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_TRUE);
}

EC_BOOL coroutine_cond_release_all(COROUTINE_COND *coroutine_cond, const UINT32 location)
{
    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_RELEASE, location);
    COROUTINE_COND_COUNTER(coroutine_cond) = 0;

    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_release_all: status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                                __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                                MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    return (EC_TRUE);
}

EC_BOOL coroutine_cond_terminate(COROUTINE_COND *coroutine_cond, const UINT32 location)
{
    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_TERMINATE, location);

    COROUTINE_COND_TERMINATE_FLAG(coroutine_cond) = BIT_TRUE;

    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_terminate: status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                                __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                                MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    return (EC_TRUE);
}

EC_BOOL coroutine_cond_set_timeout(COROUTINE_COND *coroutine_cond, const UINT32 timeout_msec)
{
    COROUTINE_COND_TIMEOUT_MSEC(coroutine_cond) = timeout_msec;

    if(0 < timeout_msec)
    {
        uint64_t    time_msec_cur;

        time_msec_cur = task_brd_default_get_time_msec();
        COROUTINE_COND_S_MSEC(coroutine_cond) = time_msec_cur + 0;
        COROUTINE_COND_E_MSEC(coroutine_cond) = time_msec_cur + timeout_msec;
    }
    return (EC_TRUE);
}

EC_BOOL coroutine_cond_is_timeout(const COROUTINE_COND *coroutine_cond)
{
    if(0 < COROUTINE_COND_TIMEOUT_MSEC(coroutine_cond))
    {
        if(task_brd_default_get_time_msec() >= COROUTINE_COND_E_MSEC(coroutine_cond))
        {
            if(do_log(SEC_0001_COROUTINE, 5))
            {
                UINT32   elapsed_msec;

                elapsed_msec = task_brd_default_get_time_msec() - COROUTINE_COND_S_MSEC(coroutine_cond);
                sys_log(LOGSTDOUT, "[DEBUG] coroutine_cond_is_timeout: elapsed %ld ms, timeout_msec %ld => timeout\n",
                                   elapsed_msec, COROUTINE_COND_TIMEOUT_MSEC(coroutine_cond));
            }

            return (EC_TRUE);
        }

        if(do_log(SEC_0001_COROUTINE, 9))
        {
            UINT32   elapsed_msec;

            elapsed_msec = task_brd_default_get_time_msec() - COROUTINE_COND_S_MSEC(coroutine_cond);
            sys_log(LOGSTDOUT, "[DEBUG] coroutine_cond_is_timeout: elapsed %ld ms, timeout_msec %ld => not timeout\n",
                               elapsed_msec, COROUTINE_COND_TIMEOUT_MSEC(coroutine_cond));
        }

        return (EC_FALSE);
    }
    return (EC_FALSE);
}

EC_BOOL coroutine_cond_is_terminate(const COROUTINE_COND *coroutine_cond)
{
    if(BIT_TRUE == COROUTINE_COND_TERMINATE_FLAG(coroutine_cond))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL coroutine_cond_wait(COROUTINE_COND *coroutine_cond, const UINT32 location)
{
    COROUTINE_NODE *coroutine_node_cur;

    COROUTINE_COND_SET_LOCATION(coroutine_cond, COROUTINE_COND_OP_WAIT, location);

    coroutine_node_cur = COROUTINE_NODE_CUR_GET();
    if(NULL_PTR != coroutine_node_cur)
    {
        COROUTINE_NODE_USER_COND(coroutine_node_cur) = coroutine_cond;

        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_wait: set user cond %p to %p\n",
                            coroutine_cond, coroutine_node_cur);
    }

    while(0 < COROUTINE_COND_COUNTER(coroutine_cond))
    {
        /*when re-enter*/
        coroutine_node_cur = COROUTINE_NODE_CUR_GET();
        if(COROUTINE_NODE_USER_COND(coroutine_node_cur) != coroutine_cond)
        {
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_cond_wait: %p cond (%p) is not user cond %p\n",
                            coroutine_node_cur, COROUTINE_NODE_USER_COND(coroutine_node_cur), coroutine_cond);
            return (EC_TRUE);
        }

        if(EC_TRUE == coroutine_cond_is_terminate(coroutine_cond))
        {
            dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_wait: __COROUTINE_NO_WAIT, status: 0x%lx, cond %p, counter %ld [terminate]\n",
                                __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond));
            COROUTINE_NODE_USER_COND(coroutine_node_cur) = NULL_PTR;/*reset forcibly*/
            __COROUTINE_NO_WAIT();
            return (EC_TERMINATE);
        }

        if(EC_TRUE == coroutine_cond_is_timeout(coroutine_cond))
        {
            dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_wait: __COROUTINE_NO_WAIT, status: 0x%lx, cond %p, counter %ld [timeout]\n",
                                __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond));
            COROUTINE_NODE_USER_COND(coroutine_node_cur) = NULL_PTR;/*reset forcibly*/
            __COROUTINE_NO_WAIT();
            return (EC_TIMEOUT);
        }

        if(__COROUTINE_IS_MASTER())
        {
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_cond_wait: swap from %p to itself [%s:%ld]\n", COROUTINE_NODE_CUR_GET(),
                            MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
            COROUTINE_COND_COUNTER(coroutine_cond) = 0;/*reset forcibly*/
            break;
        }

        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_wait: __COROUTINE_WAIT, status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                                __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                                MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

        __COROUTINE_WAIT();
    }

    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_cond_wait: __COROUTINE_NO_WAIT, status: 0x%lx, cond %p, counter %ld at %s:%ld\n",
                            __COROUTINE_STATUS(), coroutine_cond, COROUTINE_COND_COUNTER(coroutine_cond),
                            MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    COROUTINE_NODE_USER_COND(coroutine_node_cur) = NULL_PTR;/*reset forcibly*/
    __COROUTINE_NO_WAIT();
    //dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_cond_wait: now go back\n");
    return (EC_TRUE);
}

UINT32 coroutine_cond_spy(COROUTINE_COND *coroutine_cond, const UINT32 location)
{
    return COROUTINE_COND_COUNTER(coroutine_cond);
}

COROUTINE_CHECKER *coroutine_checker_new(EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CHECKER *coroutine_checker;

    alloc_static_mem(MM_COROUTINE_CHECKER, &coroutine_checker, LOC_COROUTINE_0008);
    if(NULL_PTR == coroutine_checker)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_checker_new: alloc coroutine_checker failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == coroutine_checker_init(coroutine_checker, func, arg1, arg2))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_checker_new: init coroutine_checker failed\n");
        free_static_mem(MM_COROUTINE_CHECKER, coroutine_checker, LOC_COROUTINE_0009);
        return (NULL_PTR);
    }

    return (coroutine_checker);
}

EC_BOOL coroutine_checker_init(COROUTINE_CHECKER *coroutine_checker, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CHECKER_FUNC(coroutine_checker) = func;
    COROUTINE_CHECKER_ARG1(coroutine_checker) = arg1;
    COROUTINE_CHECKER_ARG2(coroutine_checker) = arg2;
    return (EC_TRUE);
}

EC_BOOL coroutine_checker_clean(COROUTINE_CHECKER *coroutine_checker)
{
    if(NULL_PTR != coroutine_checker)
    {
        COROUTINE_CHECKER_FUNC(coroutine_checker) = NULL_PTR;
        COROUTINE_CHECKER_ARG1(coroutine_checker) = NULL_PTR;
        COROUTINE_CHECKER_ARG2(coroutine_checker) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL coroutine_checker_free(COROUTINE_CHECKER *coroutine_checker)
{
    if(NULL_PTR != coroutine_checker)
    {
        coroutine_checker_clean(coroutine_checker);
        free_static_mem(MM_COROUTINE_CHECKER, coroutine_checker, LOC_COROUTINE_0010);
    }
    return (EC_TRUE);
}

EC_BOOL coroutine_checker_cmp(const COROUTINE_CHECKER *coroutine_checker_1st, const COROUTINE_CHECKER *coroutine_checker_2nd)
{
    if(COROUTINE_CHECKER_FUNC(coroutine_checker_1st) == COROUTINE_CHECKER_FUNC(coroutine_checker_2nd)
    && COROUTINE_CHECKER_ARG1(coroutine_checker_1st) == COROUTINE_CHECKER_ARG1(coroutine_checker_2nd)
    && COROUTINE_CHECKER_ARG2(coroutine_checker_1st) == COROUTINE_CHECKER_ARG2(coroutine_checker_2nd)
    )
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

COROUTINE_CLEANER *coroutine_cleaner_new(EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CLEANER *coroutine_cleaner;

    alloc_static_mem(MM_COROUTINE_CLEANER, &coroutine_cleaner, LOC_COROUTINE_0011);
    if(NULL_PTR == coroutine_cleaner)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_cleaner_new: alloc coroutine_cleaner failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == coroutine_cleaner_init(coroutine_cleaner, func, arg1, arg2))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_cleaner_new: init coroutine_cleaner failed\n");
        free_static_mem(MM_COROUTINE_CLEANER, coroutine_cleaner, LOC_COROUTINE_0012);
        return (NULL_PTR);
    }

    return (coroutine_cleaner);
}

EC_BOOL coroutine_cleaner_init(COROUTINE_CLEANER *coroutine_cleaner, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CLEANER_FUNC(coroutine_cleaner) = func;
    COROUTINE_CLEANER_ARG1(coroutine_cleaner) = arg1;
    COROUTINE_CLEANER_ARG2(coroutine_cleaner) = arg2;
    return (EC_TRUE);
}

EC_BOOL coroutine_cleaner_clean(COROUTINE_CLEANER *coroutine_cleaner)
{
    if(NULL_PTR != coroutine_cleaner)
    {
        COROUTINE_CLEANER_FUNC(coroutine_cleaner) = NULL_PTR;
        COROUTINE_CLEANER_ARG1(coroutine_cleaner) = NULL_PTR;
        COROUTINE_CLEANER_ARG2(coroutine_cleaner) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL coroutine_cleaner_free(COROUTINE_CLEANER *coroutine_cleaner)
{
    if(NULL_PTR != coroutine_cleaner)
    {
        coroutine_cleaner_clean(coroutine_cleaner);
        free_static_mem(MM_COROUTINE_CLEANER, coroutine_cleaner, LOC_COROUTINE_0013);
    }
    return (EC_TRUE);
}

EC_BOOL coroutine_cleaner_cmp(const COROUTINE_CLEANER *coroutine_cleaner_1st, const COROUTINE_CLEANER *coroutine_cleaner_2nd)
{
    if(COROUTINE_CLEANER_FUNC(coroutine_cleaner_1st) == COROUTINE_CLEANER_FUNC(coroutine_cleaner_2nd)
    && COROUTINE_CLEANER_ARG1(coroutine_cleaner_1st) == COROUTINE_CLEANER_ARG1(coroutine_cleaner_2nd)
    && COROUTINE_CLEANER_ARG2(coroutine_cleaner_1st) == COROUTINE_CLEANER_ARG2(coroutine_cleaner_2nd)
    )
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void coroutine_cancel()
{
    COROUTINE_NODE *__master = COROUTINE_NODE_MASTER_GET();
    COROUTINE_NODE *__slave  = COROUTINE_NODE_CUR_GET();

    COROUTINE_NODE_STATUS(__slave) |= COROUTINE_IS_CANL;
    coroutine_node_swap_task(__slave, __master);

    return;
}

COROUTINE_NODE *coroutine_self()
{
    return COROUTINE_NODE_CUR_GET();
}

COROUTINE_NODE *coroutine_node_master_get()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return coroutine_pool_get_master(TASK_BRD_CROUTINE_POOL(task_brd));
}

COROUTINE_NODE *coroutine_node_cur_get()
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (NULL_PTR);
    }
    return coroutine_pool_get_current(TASK_BRD_CROUTINE_POOL(task_brd));
}

EC_BOOL coroutine_node_cur_is_cancelled()
{
    TASK_BRD *task_brd;
    COROUTINE_POOL *coroutine_pool;
    COROUTINE_NODE *coroutine_node_current;
    COROUTINE_NODE *coroutine_node_master;

    task_brd = task_brd_default_get();
    if(NULL_PTR == task_brd)
    {
        return (EC_FALSE);
    }

    coroutine_pool = TASK_BRD_CROUTINE_POOL(task_brd);
    if(NULL_PTR == coroutine_pool)
    {
        return (EC_FALSE);
    }

    coroutine_node_current = COROUTINE_POOL_CURRENT_OWNER(coroutine_pool);
    if(NULL_PTR == coroutine_node_current)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_cur_is_cancelled: current is null\n");
        return (EC_FALSE);
    }

    coroutine_node_master = COROUTINE_POOL_MASTER_OWNER(coroutine_pool);
    if(NULL_PTR == coroutine_node_master)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_cur_is_cancelled: master is null\n");
        return (EC_FALSE);
    }

    if(coroutine_node_current == coroutine_node_master)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_cur_is_cancelled: current == master (%p)\n",
                        coroutine_node_current);
        return (EC_FALSE);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node_current) & COROUTINE_IS_CANL)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

COROUTINE_NODE *coroutine_node_new(COROUTINE_NODE *coroutine_node_next)
{
    COROUTINE_NODE *coroutine_node;

    alloc_static_mem(MM_COROUTINE_NODE, &coroutine_node, LOC_COROUTINE_0014);
    if(NULL_PTR == coroutine_node)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_new: alloc COROUTINE_NODE failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == coroutine_node_init(coroutine_node, coroutine_node_next))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_new: init COROUTINE_NODE failed\n");
        free_static_mem(MM_COROUTINE_NODE, coroutine_node, LOC_COROUTINE_0015);
        return (NULL_PTR);
    }

    return (coroutine_node);
}

EC_BOOL coroutine_node_init(COROUTINE_NODE *coroutine_node, COROUTINE_NODE *coroutine_node_next)
{
    COROUTINE_NODE_STATUS(coroutine_node)  = COROUTINE_IS_IDLE;
    COROUTINE_NODE_MOUNTED(coroutine_node) = NULL_PTR;

    COROUTINE_NODE_STACK_SPACE(coroutine_node) = safe_malloc(COROUTINE_STACK_SIZE_DEFAULT, LOC_COROUTINE_0016);
    if(NULL_PTR == COROUTINE_NODE_STACK_SPACE(coroutine_node))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_init: malloc %ld bytes failed\n", (UINT32)COROUTINE_STACK_SIZE_DEFAULT);
        return (EC_FALSE);
    }
    COROUTINE_NODE_STACK_SIZE(coroutine_node) = COROUTINE_STACK_SIZE_DEFAULT;
    COROUTINE_NODE_RESUME_POINT(coroutine_node) = COROUTINE_NODE_TASK(coroutine_node_next);

    coroutine_cond_init(COROUTINE_NODE_COND(coroutine_node), 0, LOC_COROUTINE_0017);

    COROUTINE_NODE_USER_COND(coroutine_node)   = NULL_PTR;
    COROUTINE_NODE_USER_MUTEX(coroutine_node)  = NULL_PTR;
    COROUTINE_NODE_USER_RWLOCK(coroutine_node) = NULL_PTR;

    cqueue_init(COROUTINE_NODE_PREV_CHECKER_QUEUE(coroutine_node), MM_COROUTINE_CHECKER, LOC_COROUTINE_0018);
    cstack_init(COROUTINE_NODE_POST_CLEANER_STACK(coroutine_node), MM_COROUTINE_CLEANER, LOC_COROUTINE_0019);

    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_init: stack: [%p, %p)\n",
                        COROUTINE_NODE_STACK_SPACE(coroutine_node), COROUTINE_NODE_STACK_SPACE(coroutine_node) + COROUTINE_STACK_SIZE_DEFAULT);
    return (EC_TRUE);
}

UINT32 coroutine_node_clean(COROUTINE_NODE *coroutine_node)
{
    if(NULL_PTR != COROUTINE_NODE_STACK_SPACE(coroutine_node))
    {
        safe_free(COROUTINE_NODE_STACK_SPACE(coroutine_node), LOC_COROUTINE_0020);
        COROUTINE_NODE_STACK_SPACE(coroutine_node) = NULL_PTR;
    }
    COROUTINE_NODE_STACK_SIZE(coroutine_node) = 0;
    COROUTINE_NODE_STATUS(coroutine_node)  = COROUTINE_IS_DOWN;
    COROUTINE_NODE_MOUNTED(coroutine_node) = NULL_PTR;
    coroutine_cond_clean(COROUTINE_NODE_COND(coroutine_node), LOC_COROUTINE_0021);

    COROUTINE_NODE_USER_COND(coroutine_node)   = NULL_PTR;
    COROUTINE_NODE_USER_MUTEX(coroutine_node)  = NULL_PTR;
    COROUTINE_NODE_USER_RWLOCK(coroutine_node) = NULL_PTR;

    cqueue_clean(COROUTINE_NODE_PREV_CHECKER_QUEUE(coroutine_node), (CQUEUE_DATA_DATA_CLEANER)coroutine_checker_free);
    cstack_clean(COROUTINE_NODE_POST_CLEANER_STACK(coroutine_node), (CSTACK_DATA_DATA_CLEANER)coroutine_cleaner_free);
    return (0);
}

UINT32 coroutine_node_free(COROUTINE_NODE *coroutine_node)
{
    coroutine_node_clean(coroutine_node);
    free_static_mem(MM_COROUTINE_NODE, coroutine_node, LOC_COROUTINE_0022);
    return (0);
}

#if (SWITCH_ON == COROUTINE_FIX_BUG_SWITCH)

/*
*   note:
*       __coroutine_make_context is to fix glibc-2.5 bug
*       which regard the args after argc as int type (32 bits), super hit!
*       the bug has been fixed in glibc-2.18, and I do not study other glibc version
*
*    --- chaoyong.zhou
*/
STATIC_CAST static void __coroutine_make_context (ucontext_t *ucp, void (*func) (void), int argc, ...)
{
    greg_t *sp;
    va_list ap;
    int i;

    /* Generate room on stack for parameter if needed and uc_link.  */
    sp = (greg_t *) ((UINT32) ucp->uc_stack.ss_sp + ucp->uc_stack.ss_size);
    sp -= (argc > 6 ? argc - 6 : 0) + 1;
    /* Align stack and make space for trampoline address.  */
    sp = (greg_t *) ((((UINT32) sp) & -16L) - 8);

    va_start (ap, argc);
    /* Handle arguments.

     The standard says the parameters must all be int values.  This is
     an historic accident and would be done differently today.  For
     x86-64 all integer values are passed as 64-bit values and
     therefore extending the API to copy 64-bit values instead of
     32-bit ints makes sense.  It does not break existing
     functionality and it does not violate the standard which says
     that passing non-int values means undefined behavior.  */
    for (i = 0; i < argc; ++i)
    {
        switch (i)
        {
            case 0:
                ucp->uc_mcontext.gregs[REG_RDI] = va_arg (ap, greg_t);
                break;
            case 1:
                ucp->uc_mcontext.gregs[REG_RSI] = va_arg (ap, greg_t);
                break;
            case 2:
                ucp->uc_mcontext.gregs[REG_RDX] = va_arg (ap, greg_t);
                break;
            case 3:
                ucp->uc_mcontext.gregs[REG_RCX] = va_arg (ap, greg_t);
                break;
            case 4:
                ucp->uc_mcontext.gregs[REG_R8] = va_arg (ap, greg_t);
                break;
            case 5:
                ucp->uc_mcontext.gregs[REG_R9] = va_arg (ap, greg_t);
                break;
            default:
                /* Put value on stack.  */
                sp[i - 5] = va_arg (ap, greg_t);
                break;
        }
    }
    va_end (ap);
    return;
}
#endif/*(SWITCH_ON == COROUTINE_FIX_BUG_SWITCH)*/

EC_BOOL coroutine_node_make_task(COROUTINE_NODE *coroutine_node, const UINT32 start_routine_addr, const UINT32 arg_num, va_list arg_list)
{
    UINT32 _arg_list[16];
    int    _arg_num;
    int    _arg_idx;

    COROUTINE_ASSERT(16 >= arg_num);
    _arg_num = (int)arg_num;

    for(_arg_idx = 0; _arg_idx < _arg_num; _arg_idx ++)
    {
        _arg_list[ _arg_idx ] = va_arg(arg_list, UINT32);
        //dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_node_make_task: _arg_idx %d: %lx\n", _arg_idx, _arg_list[ _arg_idx ]);
    }

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

#if (SWITCH_OFF == COROUTINE_FIX_BUG_SWITCH)
    #define MAKE_CONTEXT_NO_PARA(__x__, start_routine_addr, arg_num, arg_list) \
            makecontext(COROUTINE_NODE_TASK(coroutine_node), ((void (*)(void))start_routine_addr), arg_num)

    #define MAKE_CONTEXT(__x__, start_routine_addr, arg_num, arg_list) \
            makecontext(COROUTINE_NODE_TASK(coroutine_node), ((void (*)(void))start_routine_addr), arg_num, PARA_LIST_##__x__(arg_list))

#endif /*(SWITCH_OFF == COROUTINE_FIX_BUG_SWITCH)*/

#if (SWITCH_ON == COROUTINE_FIX_BUG_SWITCH)
    #define MAKE_CONTEXT_NO_PARA(__x__, start_routine_addr, arg_num, arg_list) do{\
            makecontext(COROUTINE_NODE_TASK(coroutine_node), ((void (*)(void))start_routine_addr), arg_num);\
            __coroutine_make_context(COROUTINE_NODE_TASK(coroutine_node), ((void (*)(void))start_routine_addr), arg_num);\
        }while(0)

    #define MAKE_CONTEXT(__x__, start_routine_addr, arg_num, arg_list) do{\
            makecontext(COROUTINE_NODE_TASK(coroutine_node), ((void (*)(void))start_routine_addr), arg_num, PARA_LIST_##__x__(arg_list));\
            __coroutine_make_context(COROUTINE_NODE_TASK(coroutine_node), ((void (*)(void))start_routine_addr), arg_num, PARA_LIST_##__x__(arg_list));\
        }while(0)

#endif/*(SWITCH_ON == COROUTINE_FIX_BUG_SWITCH)*/

    switch(arg_num)
    {
        case 0:
            MAKE_CONTEXT_NO_PARA(0, start_routine_addr, _arg_num, _arg_list);
            break;
        case 1:
            MAKE_CONTEXT(1, start_routine_addr, _arg_num, _arg_list);
            break;
        case 2:
            MAKE_CONTEXT(2, start_routine_addr, _arg_num, _arg_list);
            break;
        case 3:
            MAKE_CONTEXT(3, start_routine_addr, _arg_num, _arg_list);
            break;
        case 4:
            MAKE_CONTEXT(4, start_routine_addr, _arg_num, _arg_list);
            break;
        case 5:
            MAKE_CONTEXT(5, start_routine_addr, _arg_num, _arg_list);
            break;
        case 6:
            MAKE_CONTEXT(6, start_routine_addr, _arg_num, _arg_list);
            break;
        case 7:
            MAKE_CONTEXT(7, start_routine_addr, _arg_num, _arg_list);
            break;
        case 8:
            MAKE_CONTEXT(8, start_routine_addr, _arg_num, _arg_list);
            break;
        case 9:
            MAKE_CONTEXT(9, start_routine_addr, _arg_num, _arg_list);
            break;
        case 10:
            MAKE_CONTEXT(10, start_routine_addr, _arg_num, _arg_list);
            break;
        case 11:
            MAKE_CONTEXT(11, start_routine_addr, _arg_num, _arg_list);
            break;
        case 12:
            MAKE_CONTEXT(12, start_routine_addr, _arg_num, _arg_list);
            break;
        case 13:
            MAKE_CONTEXT(13, start_routine_addr, _arg_num, _arg_list);
            break;
        case 14:
            MAKE_CONTEXT(14, start_routine_addr, _arg_num, _arg_list);
            break;
        case 15:
            MAKE_CONTEXT(15, start_routine_addr, _arg_num, _arg_list);
            break;
        case 16:
            MAKE_CONTEXT(16, start_routine_addr, _arg_num, _arg_list);
            break;
        default:
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_caller: arg num = %ld overflow\n", arg_num);
            return (EC_FALSE);
    }

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

    #undef MAKE_CONTEXT_NO_PARA
    #undef MAKE_CONTEXT

    return (EC_TRUE);
}

EC_BOOL coroutine_node_get_task(COROUTINE_NODE *coroutine_node)
{
    if(-1 == getcontext(COROUTINE_NODE_TASK(coroutine_node)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL coroutine_node_set_task(COROUTINE_NODE *coroutine_node)
{
    COROUTINE_NODE *coroutine_node_tmp;

    coroutine_node_tmp = COROUTINE_NODE_CUR_GET();/*save*/

    COROUTINE_NODE_CUR_SET(coroutine_node);
    if(-1 == setcontext(COROUTINE_NODE_TASK(coroutine_node)))
    {
        COROUTINE_NODE_CUR_SET(coroutine_node_tmp);
        return (EC_FALSE);
    }
    COROUTINE_NODE_CUR_SET(coroutine_node_tmp);
    return (EC_TRUE);
}

EC_BOOL coroutine_node_swap_task(COROUTINE_NODE *coroutine_node_save, COROUTINE_NODE *coroutine_node_to)
{
    COROUTINE_NODE *coroutine_node_tmp;
    coroutine_node_tmp = COROUTINE_NODE_CUR_GET();/*save*/

    COROUTINE_ASSERT(NULL_PTR != coroutine_node_save);
    if(NULL_PTR == coroutine_node_save)
    {
        COROUTINE_NODE_CUR_SET(coroutine_node_to);
        setcontext(COROUTINE_NODE_TASK(coroutine_node_to));
        /*never reach here*/
        COROUTINE_NODE_CUR_SET(coroutine_node_tmp);
        return (EC_TRUE);
    }

    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_swap_task: swap %p => %p, master %p\n",
                    coroutine_node_save, coroutine_node_to, COROUTINE_NODE_MASTER_GET());
    COROUTINE_NODE_CUR_SET(coroutine_node_to);

    if(0 == swapcontext(COROUTINE_NODE_TASK(coroutine_node_save), COROUTINE_NODE_TASK(coroutine_node_to)))
    {
        COROUTINE_NODE_CUR_SET(coroutine_node_tmp);
        return (EC_TRUE);
    }

    COROUTINE_NODE_CUR_SET(coroutine_node_tmp);

    dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_swap_task: swap %p => %p failed, errno = %d, errstr = %s\n",
                    coroutine_node_save, coroutine_node_to, errno, strerror(errno));
    return (EC_FALSE);
}


EC_BOOL coroutine_node_wait_and_swap_task(COROUTINE_NODE *coroutine_node_save, COROUTINE_NODE *coroutine_node_to)
{
    COROUTINE_NODE *coroutine_node_tmp;

    coroutine_node_tmp = COROUTINE_NODE_CUR_GET();/*save*/

    if(NULL_PTR == coroutine_node_save)
    {
        //setcontext(COROUTINE_NODE_TASK(coroutine_node_to));
        return (EC_TRUE);
    }

    COROUTINE_NODE_SET_WAIT_STATUS(coroutine_node_save);

    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_wait_and_swap_task: swap %p => %p, master %p\n",
                    coroutine_node_save, coroutine_node_to, COROUTINE_NODE_MASTER_GET());
    COROUTINE_NODE_CUR_SET(coroutine_node_to);
    if(0 == swapcontext(COROUTINE_NODE_TASK(coroutine_node_save), COROUTINE_NODE_TASK(coroutine_node_to)))
    {
        COROUTINE_NODE_CUR_SET(coroutine_node_tmp);
        return (EC_TRUE);
    }
    COROUTINE_NODE_CUR_SET(coroutine_node_tmp);

    dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_wait_and_swap_task: swap %p => %p failed, errno = %d, errstr = %s\n",
                    coroutine_node_save, coroutine_node_to, errno, strerror(errno));

    return (EC_FALSE);
}


/*note: coroutine_node_shutdown will lock coroutine_pool, so DO NOT call it when coroutine_pool_shutdown*/
UINT32 coroutine_node_shutdown(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool)
{
    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_node_shutdown: shutdown %p\n", coroutine_node);
    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0023);

    COROUTINE_NODE_STATUS(coroutine_node) |= COROUTINE_IS_DOWN;

    if(COROUTINE_IS_IDLE & COROUTINE_NODE_STATUS(coroutine_node))
    {
        clist_rmv_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool), COROUTINE_NODE_MOUNTED(coroutine_node));
        COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0024);
        return (0);
    }

    if(COROUTINE_IS_BUSY & COROUTINE_NODE_STATUS(coroutine_node))
    {
        clist_rmv_no_lock(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool), COROUTINE_NODE_MOUNTED(coroutine_node));
        COROUTINE_NODE_STATUS(coroutine_node) |= COROUTINE_IS_CANL;
        COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0025);
        return (0);
    }

    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0026);
    return (0);
}

/**
 *
 * scenario 1: current coroutine cancel another coroutine
 * scenario 2: current coroutine cancel itself
 *
**/
UINT32 coroutine_node_cancel(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool)
{
    COROUTINE_ASSERT(((UINT32)coroutine_node) > 0xFFFFFFFF);
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_cancel: cancel %p, status 0x%lx\n", coroutine_node, COROUTINE_NODE_STATUS(coroutine_node));
    dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_node_cancel: coroutine_node %p (mounted %p), coroutine_pool %p, status 0x%lx\n",
                coroutine_node, COROUTINE_NODE_MOUNTED(coroutine_node),
                coroutine_pool, COROUTINE_NODE_STATUS(coroutine_node));

    /*COROUTINE_COROUTINE_ASSERT(0 == (COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_WAIT));*/
    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_WAIT)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "[DEBUG] coroutine_node_cancel: delay cancel %p, status 0x%lx [IS_WAIT]\n",
                    coroutine_node, COROUTINE_NODE_STATUS(coroutine_node));
        COROUTINE_NODE_STATUS(coroutine_node) |= COROUTINE_IS_CANL;

        COROUTINE_ASSERT(((UINT32)coroutine_node) > 0xFFFFFFFF);

        if(NULL_PTR != COROUTINE_NODE_USER_COND(coroutine_node))
        {
            dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_cancel: delay cancel %p, status 0x%lx, release user cond %p [IS_WAIT]\n",
                        coroutine_node, COROUTINE_NODE_STATUS(coroutine_node), COROUTINE_NODE_USER_COND(coroutine_node));

            coroutine_cond_release_all(COROUTINE_NODE_USER_COND(coroutine_node), LOC_COROUTINE_0027);
            COROUTINE_NODE_USER_COND(coroutine_node) = NULL_PTR;

            COROUTINE_ASSERT(((UINT32)coroutine_node) > 0xFFFFFFFF);
        }

        if(NULL_PTR != COROUTINE_NODE_USER_MUTEX(coroutine_node))
        {
            dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_cancel: delay cancel %p, status 0x%lx, release user mutex %p [IS_WAIT]\n",
                        coroutine_node, COROUTINE_NODE_STATUS(coroutine_node), COROUTINE_NODE_USER_MUTEX(coroutine_node));

            coroutine_mutex_unlock(COROUTINE_NODE_USER_MUTEX(coroutine_node), LOC_COROUTINE_0028);
            COROUTINE_NODE_USER_MUTEX(coroutine_node) = NULL_PTR;
        }

        if(NULL_PTR != COROUTINE_NODE_USER_RWLOCK(coroutine_node))
        {
            dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_cancel: delay cancel %p, status 0x%lx, release user rwlock %p [IS_WAIT]\n",
                        coroutine_node, COROUTINE_NODE_STATUS(coroutine_node), COROUTINE_NODE_USER_RWLOCK(coroutine_node));

            coroutine_rwlock_unlock(COROUTINE_NODE_USER_RWLOCK(coroutine_node), LOC_COROUTINE_0029);
            COROUTINE_NODE_USER_RWLOCK(coroutine_node) = NULL_PTR;
        }

        COROUTINE_ASSERT(((UINT32)coroutine_node) > 0xFFFFFFFF);
        coroutine_node_post_cleaner_run(coroutine_node);/*xxx*/
        COROUTINE_ASSERT(((UINT32)coroutine_node) > 0xFFFFFFFF);
        /*delay cancel. such coroutine only happen on scenario: ngx->lua->bgn*/
        return (0);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_CANL)
    {
        COROUTINE_NODE_STATUS(coroutine_node) |= COROUTINE_IS_DOWN;
    }
    else
    {
        COROUTINE_NODE_STATUS(coroutine_node) |= COROUTINE_IS_CANL;
    }

    if(COROUTINE_NODE_CUR_GET() == coroutine_node) /*cancel current coroutine for event ...*/
    {
        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_cancel: self cancel %p, status 0x%lx\n",
                    coroutine_node, COROUTINE_NODE_STATUS(coroutine_node));

        COROUTINE_ASSERT(((UINT32)coroutine_node) > 0xFFFFFFFF);
        coroutine_node_post_cleaner_run(coroutine_node);/*xxxx*/
        COROUTINE_ASSERT(((UINT32)coroutine_node) > 0xFFFFFFFF);
        return (0);
    }

    coroutine_node_post_cleaner_run(coroutine_node);

    coroutine_node_busy_to_idle(coroutine_node, coroutine_pool);/*xxxx*/
    return (0);
}

EC_BOOL coroutine_node_pre_check(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool)
{
    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_node_pre_check: check %p, status 0x%lx\n",
                        coroutine_node, COROUTINE_NODE_STATUS(coroutine_node));

    if((COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_CANL)
    && (COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_WAIT))
    {
        /*this coroutine was delayed to cancel*/
        return (EC_TRUE);/*run it*/
    }

    /*if coroutine had been cancelled or shutdown, move it to idle and give up handling*/
    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_CANL)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "[DEBUG] coroutine_node_pre_check: [IS_CANL] %p\n", coroutine_node);
        COROUTINE_NODE_STATUS(coroutine_node) |= COROUTINE_IS_DOWN;
        /*fall through*/
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_DOWN)
    {
        COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_IDLE;
        coroutine_node_busy_to_idle(coroutine_node, coroutine_pool);
        return (EC_FALSE);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_IDLE) /*xx*/
    {
        COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_IDLE;
        coroutine_node_busy_to_idle(coroutine_node, coroutine_pool);
        return (EC_FALSE);
    }

    if(EC_FALSE == coroutine_node_prev_checker_run(coroutine_node))
    {
        COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_IDLE;
        coroutine_node_busy_to_idle(coroutine_node, coroutine_pool);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL coroutine_node_post_check(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool)
{
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_post_check: check %p, status 0x%lx\n", coroutine_node, COROUTINE_NODE_STATUS(coroutine_node));
    /*check coroutine status*/
    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_CANL)
    {
        dbg_log(SEC_0001_COROUTINE, 1)(LOGSTDOUT, "[DEBUG] coroutine_node_post_check: [IS_CANL] %p, status 0x%lx\n", coroutine_node, COROUTINE_NODE_STATUS(coroutine_node));
        COROUTINE_NODE_STATUS(coroutine_node) |= COROUTINE_IS_DOWN;
        /*fall through*/
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_DOWN)
    {
        COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_IDLE;
        coroutine_node_busy_to_idle(coroutine_node, coroutine_pool);
        return (EC_TRUE);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_IDLE)/*xx*/
    {
        COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_IDLE;
        coroutine_node_busy_to_idle(coroutine_node, coroutine_pool);
        return (EC_TRUE);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_WAIT)
    {
        coroutine_node_busy_to_tail(coroutine_node, coroutine_pool);
        return (EC_TRUE);
    }
#if 0
    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_BUSY)
    {
        coroutine_node_busy_to_tail(coroutine_node, coroutine_pool);
        return (EC_TRUE);
    }
#endif
    COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_IDLE;
    coroutine_node_busy_to_idle(coroutine_node, coroutine_pool);
    return (EC_TRUE);
}

UINT32 coroutine_node_busy_to_idle(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool)
{
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_busy_to_idle: %p, busy => idle\n", coroutine_node);
    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0030);

    COROUTINE_ASSERT(EC_TRUE  == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));
    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));

    if(NULL_PTR != COROUTINE_NODE_USER_COND(coroutine_node))
    {
        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_busy_to_idle: %p, busy => idle, release user cond %p\n",
                    coroutine_node, COROUTINE_NODE_USER_COND(coroutine_node));

        coroutine_cond_release_all(COROUTINE_NODE_USER_COND(coroutine_node), LOC_COROUTINE_0031);
        COROUTINE_NODE_USER_COND(coroutine_node) = NULL_PTR;
    }

    if(NULL_PTR != COROUTINE_NODE_USER_MUTEX(coroutine_node))
    {
        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_busy_to_idle: %p, busy => idle, release user mutex %p\n",
                    coroutine_node, COROUTINE_NODE_USER_MUTEX(coroutine_node));

        coroutine_mutex_unlock(COROUTINE_NODE_USER_MUTEX(coroutine_node), LOC_COROUTINE_0032);
        COROUTINE_NODE_USER_MUTEX(coroutine_node) = NULL_PTR;
    }

    if(NULL_PTR != COROUTINE_NODE_USER_RWLOCK(coroutine_node))
    {
        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_node_busy_to_idle: %p, busy => idle, release user rwlock %p\n",
                    coroutine_node, COROUTINE_NODE_USER_RWLOCK(coroutine_node));

        coroutine_rwlock_unlock(COROUTINE_NODE_USER_RWLOCK(coroutine_node), LOC_COROUTINE_0033);
        COROUTINE_NODE_USER_RWLOCK(coroutine_node) = NULL_PTR;
    }

    coroutine_node_prev_checker_release(coroutine_node);

    coroutine_node_post_cleaner_run(coroutine_node);

    clist_rmv_no_lock(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool), COROUTINE_NODE_MOUNTED(coroutine_node));
    /*COROUTINE_NODE_STATUS(coroutine_node)  = ((COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_HI_MASK) | COROUTINE_IS_IDLE);*/
    COROUTINE_NODE_STATUS(coroutine_node)  = COROUTINE_IS_IDLE;
    COROUTINE_NODE_MOUNTED(coroutine_node) = clist_push_back_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool), coroutine_node);

    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0034);

    /*debug*/
    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));
    COROUTINE_ASSERT(EC_TRUE  == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    return (0);
}

UINT32 coroutine_node_busy_to_tail(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool)
{
    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_node_busy_to_tail: %p, busy => tail\n", coroutine_node);
    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0035);

    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    COROUTINE_ASSERT(EC_TRUE  == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));

    if(1 < coroutine_pool_busy_num_no_lock(coroutine_pool))
    {
        CLIST_DATA_DEL(COROUTINE_NODE_MOUNTED(coroutine_node));
        CLIST_DATA_ADD_BACK(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool), COROUTINE_NODE_MOUNTED(coroutine_node));
        //dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_node_busy_to_tail: coroutine_node %p\n", coroutine_node);
        //coroutine_node_print(LOGSTDOUT, coroutine_node);
    }

    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    COROUTINE_ASSERT(EC_TRUE  == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));

    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0036);

    return (0);
}

EC_BOOL coroutine_node_is_runnable(const COROUTINE_NODE *coroutine_node)
{
    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_CANL)
    {
        return (EC_TRUE);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_DOWN)
    {
        return (EC_TRUE);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_WAIT)
    {
        if(NULL_PTR != COROUTINE_NODE_USER_COND(coroutine_node))
        {
            COROUTINE_COND *coroutine_cond;

            coroutine_cond = COROUTINE_NODE_USER_COND(coroutine_node);
            if(0 == COROUTINE_COND_COUNTER(coroutine_cond))
            {
                return (EC_TRUE);
            }

            if(EC_TRUE == coroutine_cond_is_terminate(coroutine_cond))
            {
                return (EC_TRUE);
            }

            if(EC_TRUE == coroutine_cond_is_timeout(coroutine_cond))
            {
                return (EC_TRUE);
            }

            return (EC_FALSE);
        }

        if(NULL_PTR != COROUTINE_NODE_USER_MUTEX(coroutine_node))
        {
            return (EC_TRUE);
        }

        if(NULL_PTR != COROUTINE_NODE_USER_RWLOCK(coroutine_node))
        {
            return (EC_TRUE);
        }
        return (EC_TRUE);
    }

    if(COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_IS_BUSY)
    {
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

void coroutine_node_print(LOG *log, const COROUTINE_NODE *coroutine_node)
{
    sys_log(log, "coroutine_node %p, status %lx, mounted %p, stack space %p, stack size %ld\n",
                coroutine_node,
                COROUTINE_NODE_STATUS(coroutine_node),
                COROUTINE_NODE_MOUNTED(coroutine_node),
                COROUTINE_NODE_STACK_SPACE(coroutine_node),
                COROUTINE_NODE_STACK_SIZE(coroutine_node)
                );

    //coroutine_task_print(log, COROUTINE_NODE_TASK(coroutine_node));

    return;
}

EC_BOOL coroutine_node_post_cleaner_push(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CLEANER *coroutine_cleaner;

    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_node_post_cleaner_push: push (%p, %p, %p) to %p\n", func, arg1, arg2, coroutine_node);
    coroutine_cleaner = coroutine_cleaner_new(func, arg1, arg2);
    if(NULL_PTR == coroutine_cleaner)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_post_cleaner_push: new coroutine_cleaner failed\n");
        return (EC_FALSE);
    }

    cstack_push(COROUTINE_NODE_POST_CLEANER_STACK(coroutine_node), (void *)coroutine_cleaner);
    return (EC_TRUE);
}

COROUTINE_CLEANER *coroutine_node_post_cleaner_pop(COROUTINE_NODE *coroutine_node)
{
    COROUTINE_CLEANER *coroutine_cleaner;

    coroutine_cleaner = cstack_pop(COROUTINE_NODE_POST_CLEANER_STACK(coroutine_node));
    if(NULL_PTR == coroutine_cleaner)
    {
        dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_node_post_cleaner_pop: no more coroutine_cleaner in stack\n");
        return (NULL_PTR);
    }
    return (coroutine_cleaner);
}

EC_BOOL coroutine_node_post_cleaner_del(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CLEANER coroutine_cleaner_t;
    COROUTINE_CLEANER *coroutine_cleaner;

    coroutine_cleaner_init(&coroutine_cleaner_t, func, arg1, arg2);

    coroutine_cleaner = cstack_del(COROUTINE_NODE_POST_CLEANER_STACK(coroutine_node), &coroutine_cleaner_t, (CSTACK_DATA_DATA_CMP)coroutine_cleaner_cmp);
    if(NULL_PTR != coroutine_cleaner)
    {
        coroutine_cleaner_free(coroutine_cleaner);
    }

    return (EC_TRUE);
}

/*pop and free and no execution*/
EC_BOOL coroutine_node_post_cleaner_pop_and_release(COROUTINE_NODE *coroutine_node)
{
    COROUTINE_CLEANER *coroutine_cleaner;
    coroutine_cleaner = coroutine_node_post_cleaner_pop(coroutine_node);
    if(NULL_PTR != coroutine_cleaner)
    {
        dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_node_post_cleaner_pop_and_release: release %p\n", coroutine_node);
        coroutine_cleaner_free(coroutine_cleaner);
    }

    return (EC_TRUE);
}

EC_BOOL coroutine_node_post_cleaner_run(COROUTINE_NODE *coroutine_node)
{
    EC_BOOL result;

    result = EC_TRUE;
    for(;;)
    {
        COROUTINE_CLEANER *coroutine_cleaner;

        coroutine_cleaner = coroutine_node_post_cleaner_pop(coroutine_node);
        if(NULL_PTR == coroutine_cleaner)
        {
            break;
        }

        dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_node_post_cleaner_run: run (%p, %p, %p) on %p\n",
                            COROUTINE_CLEANER_FUNC(coroutine_cleaner),COROUTINE_CLEANER_ARG1(coroutine_cleaner), COROUTINE_CLEANER_ARG2(coroutine_cleaner),
                            coroutine_node);

        if(NULL_PTR != COROUTINE_CLEANER_FUNC(coroutine_cleaner)
        && EC_FALSE == COROUTINE_CLEANER_FUNC(coroutine_cleaner)(
                            COROUTINE_CLEANER_ARG1(coroutine_cleaner),
                            COROUTINE_CLEANER_ARG2(coroutine_cleaner)
                        )
        )
        {
            result = EC_FALSE;
        }

        coroutine_cleaner_free(coroutine_cleaner);
    }

    return (result);
}

/*free and no execution*/
EC_BOOL coroutine_node_post_cleaner_release(COROUTINE_NODE *coroutine_node)
{
    for(;;)
    {
        COROUTINE_CLEANER *coroutine_cleaner;

        coroutine_cleaner = coroutine_node_post_cleaner_pop(coroutine_node);
        if(NULL_PTR == coroutine_cleaner)
        {
            break;
        }
        dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_node_post_cleaner_release: release %p\n", coroutine_node);
        coroutine_cleaner_free(coroutine_cleaner);
    }

    return (EC_TRUE);
}

UINT32 coroutine_node_post_cleaner_num(const COROUTINE_NODE *coroutine_node)
{
    return cstack_depth(COROUTINE_NODE_POST_CLEANER_STACK(coroutine_node));
}

EC_BOOL coroutine_node_prev_checker_push(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CHECKER *coroutine_checker;

    coroutine_checker = coroutine_checker_new(func, arg1, arg2);
    if(NULL_PTR == coroutine_checker)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_node_prev_checker_push: new coroutine_checker failed\n");
        return (EC_FALSE);
    }

    cqueue_push(COROUTINE_NODE_PREV_CHECKER_QUEUE(coroutine_node), (void *)coroutine_checker);
    return (EC_TRUE);
}

COROUTINE_CHECKER *coroutine_node_prev_checker_pop(COROUTINE_NODE *coroutine_node)
{
    COROUTINE_CHECKER *coroutine_checker;

    coroutine_checker = cqueue_pop(COROUTINE_NODE_PREV_CHECKER_QUEUE(coroutine_node));
    if(NULL_PTR == coroutine_checker)
    {
        dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_node_prev_checker_pop: no more coroutine_checker in queue\n");
        return (NULL_PTR);
    }
    return (coroutine_checker);
}

EC_BOOL coroutine_node_prev_checker_del(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2)
{
    COROUTINE_CHECKER  coroutine_checker_t;
    COROUTINE_CHECKER *coroutine_checker;

    coroutine_checker_init(&coroutine_checker_t, func, arg1, arg2);

    coroutine_checker = cstack_del(COROUTINE_NODE_PREV_CHECKER_QUEUE(coroutine_node), &coroutine_checker_t, (CSTACK_DATA_DATA_CMP)coroutine_checker_cmp);
    if(NULL_PTR != coroutine_checker)
    {
        coroutine_checker_free(coroutine_checker);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL  __coroutine_checker_run(const COROUTINE_CHECKER *coroutine_checker, UINT32 *result)
{
    if(EC_FALSE == COROUTINE_CHECKER_FUNC(coroutine_checker)(
                        COROUTINE_CHECKER_ARG1(coroutine_checker),
                        COROUTINE_CHECKER_ARG2(coroutine_checker)
                    )
    )
    {
        (*result) = EC_FALSE;
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL coroutine_node_prev_checker_run(COROUTINE_NODE *coroutine_node)
{
    EC_BOOL result;

    result = EC_TRUE;
    cqueue_walk(COROUTINE_NODE_PREV_CHECKER_QUEUE(coroutine_node), (void *)&result, (CQUEUE_DATA_DATA_WALKER)__coroutine_checker_run);
    return (result);
}

/*free and no execution*/
EC_BOOL coroutine_node_prev_checker_release(COROUTINE_NODE *coroutine_node)
{
    for(;;)
    {
        COROUTINE_CHECKER *coroutine_checker;

        coroutine_checker = coroutine_node_prev_checker_pop(coroutine_node);
        if(NULL_PTR == coroutine_checker)
        {
            break;
        }

        coroutine_checker_free(coroutine_checker);
    }

    return (EC_TRUE);
}

UINT32 coroutine_node_prev_checker_num(const COROUTINE_NODE *coroutine_node)
{
    return cqueue_size(COROUTINE_NODE_PREV_CHECKER_QUEUE(coroutine_node));
}

COROUTINE_POOL * coroutine_pool_new(const UINT32 coroutine_num, const UINT32 flag)
{
    COROUTINE_POOL *coroutine_pool;

    alloc_static_mem(MM_COROUTINE_POOL, &coroutine_pool, LOC_COROUTINE_0037);
    if(NULL_PTR == coroutine_pool)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_pool_new: alloc COROUTINE_POOL failed\n");
        return (NULL_PTR);
    }

    coroutine_pool_init(coroutine_pool);
    coroutine_pool_create(coroutine_pool, coroutine_num);

    return (coroutine_pool);
}

UINT32 coroutine_pool_init(COROUTINE_POOL *coroutine_pool)
{
    clist_init(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool), MM_IGNORE, LOC_COROUTINE_0038);
    clist_init(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool), MM_IGNORE, LOC_COROUTINE_0039);
    COROUTINE_POOL_WORKER_INIT_LOCK(coroutine_pool, LOC_COROUTINE_0040);

    COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool) = 0;
    return (0);
}

/*create coroutine_num coroutine_nodes and add them to coroutine_pool*/
UINT32 coroutine_pool_create(COROUTINE_POOL *coroutine_pool, const UINT32 coroutine_num)
{
    UINT32 succ_coroutine_num;

    succ_coroutine_num = coroutine_pool_expand(coroutine_pool, DMIN(coroutine_num, COROUTINE_EXPAND_MIN_NUM));
    COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool) += coroutine_num;

    COROUTINE_POOL_CURRENT_OWNER(coroutine_pool) = COROUTINE_POOL_MASTER_OWNER(coroutine_pool);

    dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "[DEBUG] coroutine_pool_create: master %p\n", COROUTINE_POOL_MASTER_OWNER(coroutine_pool));
    return (succ_coroutine_num);
}

UINT32 coroutine_pool_expand(COROUTINE_POOL *coroutine_pool, const UINT32 coroutine_num)
{
    UINT32        coroutine_idx;

    for(coroutine_idx = 0; coroutine_idx < coroutine_num; coroutine_idx ++)
    {
        COROUTINE_NODE *coroutine_node;

        coroutine_node = coroutine_node_new(COROUTINE_POOL_MASTER_OWNER(coroutine_pool));
        if(NULL_PTR == coroutine_node)
        {
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_pool_expand: failed to new # %ld COROUTINE_NODE\n", coroutine_idx);
            break;
        }

        /*COROUTINE_NODE_STATUS(coroutine_node)  = ((COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_HI_MASK) | COROUTINE_IS_IDLE);*/
        COROUTINE_NODE_STATUS(coroutine_node)  = COROUTINE_IS_IDLE;
        COROUTINE_NODE_MOUNTED(coroutine_node) = clist_push_back_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool), (void *)coroutine_node);

        COROUTINE_ASSERT(EC_TRUE  == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    }

    return (coroutine_idx);
}

UINT32 coroutine_pool_shrink(COROUTINE_POOL *coroutine_pool, const UINT32 coroutine_num_to_shrink)
{
    COROUTINE_NODE *coroutine_node;
    UINT32 coroutine_num_shrinked;

    for(
         coroutine_num_shrinked = 0;
         coroutine_num_shrinked < coroutine_num_to_shrink && EC_FALSE == clist_is_empty_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
         coroutine_num_shrinked ++
       )
    {
        coroutine_node = (COROUTINE_NODE *)clist_pop_front_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
        COROUTINE_NODE_STATUS(coroutine_node)  = COROUTINE_IS_DOWN;
        COROUTINE_NODE_MOUNTED(coroutine_node) = NULL_PTR; /*Jan 12, 2017*/
        coroutine_node_free(coroutine_node);/*Jan 12, 2017*/

        COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));
        COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    }

    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "coroutine_pool_shrink report: to shrink %ld coroutine_nodes, actually shrinked %ld coroutine_nodes, current support max %ld coroutine_nodes\n",
                        coroutine_num_to_shrink, coroutine_num_shrinked, COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool));
    return (coroutine_num_shrinked);
}

UINT32 coroutine_pool_shutdown(COROUTINE_POOL *coroutine_pool)
{
    COROUTINE_NODE *coroutine_node;

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0041);

    while(EC_FALSE == clist_is_empty_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool)))
    {
        coroutine_node = (COROUTINE_NODE *)clist_pop_front_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
        COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_DOWN;
        coroutine_node_free(coroutine_node);
        //dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "coroutine_pool_shutdown: shutdown idle coroutine_node %p\n", coroutine_node);
    }

    while(EC_FALSE == clist_is_empty(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool)))
    {
        coroutine_node = (COROUTINE_NODE *)clist_pop_front_no_lock(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
        COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_DOWN;
        coroutine_node_free(coroutine_node);
        //dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "coroutine_pool_shutdown: shutdown busy coroutine_node %p\n", coroutine_node);
    }

    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0042);
    return (0);
}


UINT32 coroutine_pool_clean(COROUTINE_POOL *coroutine_pool)
{
    coroutine_pool_shutdown(coroutine_pool);
    COROUTINE_POOL_WORKER_CLEAN_LOCK(coroutine_pool, LOC_COROUTINE_0043);
    return (0);
}

UINT32 coroutine_pool_free(COROUTINE_POOL *coroutine_pool)
{
    coroutine_pool_clean(coroutine_pool);
    free_static_mem(MM_COROUTINE_POOL, coroutine_pool, LOC_COROUTINE_0044);
    return (0);
}

COROUTINE_NODE * coroutine_pool_reserve_no_lock(COROUTINE_POOL *coroutine_pool)
{
    COROUTINE_NODE *coroutine_node;
    UINT32        total_num;
    UINT32        idle_num;
    UINT32        busy_num;

    coroutine_node = (COROUTINE_NODE *)clist_pop_back_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
    if(NULL_PTR == coroutine_node)
    {
        idle_num = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
        busy_num = clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));

        total_num = idle_num + busy_num;

        if(total_num < COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool))
        {
            UINT32 coroutine_num;

            coroutine_num = DMIN(COROUTINE_EXPAND_MIN_NUM, COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool) - total_num);

            dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "coroutine_pool_reserve_no_lock: try to expand coroutine num from %ld to %ld\n",
                                total_num, coroutine_num + total_num);
            coroutine_pool_expand(coroutine_pool, coroutine_num);
        }

        coroutine_node = (COROUTINE_NODE *)clist_pop_back_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
    }

    idle_num = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
    busy_num = clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));

    total_num = idle_num + busy_num;
    if(total_num > COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool))
    {
        dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "coroutine_pool_reserve_no_lock: try to shrink coroutine num from %ld to %ld\n",
                            total_num, COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool));

        coroutine_pool_shrink(coroutine_pool, total_num - COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool));
    }

    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));
    return (coroutine_node);
}

COROUTINE_NODE * coroutine_pool_reserve(COROUTINE_POOL *coroutine_pool)
{
    COROUTINE_NODE *coroutine_node;

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0045);
    coroutine_node = coroutine_pool_reserve_no_lock(coroutine_pool);
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0046);

    return (coroutine_node);
}

COROUTINE_NODE * coroutine_pool_load_no_lock(COROUTINE_POOL *coroutine_pool, const UINT32 start_routine_addr, const UINT32 para_num, va_list para_list)
{
    COROUTINE_NODE *coroutine_node;

    static uint64_t     fail_s_time_msec          = 0;     /*start time of failure*/
    static uint64_t     fail_r_time_msec          = 0;     /*last report time of failure*/
    static uint64_t     fail_counter              = 0;     /*counter of failures*/
    const  uint64_t     fail_r_interval_msec      = 10000; /*failure report interval is 10s*/

    coroutine_node = coroutine_pool_reserve_no_lock(coroutine_pool);
    if(NULL_PTR == coroutine_node)
    {
        UINT32 idle_num;
        UINT32 busy_num;
        UINT32 total_num;
        UINT32 max_num;

        uint64_t fail_c_time_msec; /*cur time of failure*/

        coroutine_pool_num_info_no_lock(coroutine_pool, &idle_num, &busy_num, &total_num);
        max_num = COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool);

        fail_counter ++;

        fail_c_time_msec = c_get_cur_time_msec();
        if(0 == fail_s_time_msec) /*failure at first time*/
        {
            fail_s_time_msec = fail_c_time_msec;
            fail_r_time_msec = fail_c_time_msec;

            /*report nothing at first failure to prevent from fluttering*/
            return (NULL_PTR);
        }

        /*compress failure report logs*/
        if(fail_c_time_msec - fail_r_time_msec >= fail_r_interval_msec)
        {
            fail_r_time_msec = fail_c_time_msec;

            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "warn:coroutine_pool_load_no_lock: "
                                                      "failed to reserve one coroutine_node "
                                                      "where idle %ld, busy %ld, total %ld, max %ld, "
                                                      "failure elapsed %lu ms, failure times %lu\n",
                                                      idle_num, busy_num, total_num, max_num,
                                                      fail_c_time_msec - fail_s_time_msec, fail_counter);

            return (NULL_PTR);
        }

        return (NULL_PTR);
    }

    if(0 < fail_s_time_msec)
    {
        /*report nothing at last failure to prevent from fluttering*/

        fail_s_time_msec = 0;
        fail_r_time_msec = 0;
        fail_counter     = 0;
    }

    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));

    COROUTINE_ASSERT(NULL_PTR != BSET(COROUTINE_NODE_STACK_SPACE(coroutine_node), 0x00, COROUTINE_NODE_STACK_SIZE(coroutine_node)));

    coroutine_node_get_task(coroutine_node); /*in order to init floating-point register only*/
    coroutine_node_make_task(coroutine_node, start_routine_addr, para_num, para_list);
    COROUTINE_NODE_COND_RESERVE(coroutine_node, 1, LOC_COROUTINE_0047);

    /*COROUTINE_NODE_STATUS(coroutine_node)  = ((COROUTINE_NODE_STATUS(coroutine_node) & COROUTINE_HI_MASK) | COROUTINE_IS_BUSY);*/
    //COROUTINE_ASSERT(COROUTINE_IS_IDLE == COROUTINE_NODE_STATUS(coroutine_node));
    COROUTINE_NODE_STATUS(coroutine_node) = COROUTINE_IS_BUSY;
    COROUTINE_NODE_MOUNTED(coroutine_node) = clist_push_back_no_lock(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool), (void *)coroutine_node);

    COROUTINE_ASSERT(EC_FALSE == coroutine_pool_check_node_is_idle(coroutine_pool, (void *)coroutine_node));
    COROUTINE_ASSERT(EC_TRUE  == coroutine_pool_check_node_is_busy(coroutine_pool, (void *)coroutine_node));

    dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_pool_load_no_lock: load %p (stack %p, size %ld, resume %p)\n",
                            coroutine_node, COROUTINE_NODE_STACK_SPACE(coroutine_node), COROUTINE_NODE_STACK_SIZE(coroutine_node), COROUTINE_NODE_RESUME_POINT(coroutine_node));
    return (coroutine_node);
}

COROUTINE_NODE * coroutine_pool_load(COROUTINE_POOL *coroutine_pool, const UINT32 start_routine_addr, const UINT32 para_num, ...)
{
    COROUTINE_NODE *coroutine_node;
    va_list para_list;

    va_start(para_list, para_num);

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0048);
    coroutine_node = coroutine_pool_load_no_lock(coroutine_pool, start_routine_addr, para_num, para_list);
#if 1
    dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_pool_load: coroutine_node %p\n", coroutine_node);
#endif
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0049);

    va_end(para_list);

    return (coroutine_node);
}

EC_BOOL coroutine_pool_unload(COROUTINE_POOL *coroutine_pool, COROUTINE_NODE *coroutine_node)
{
    if(NULL_PTR == coroutine_node)
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_pool_unload: coroutine_node is null\n");
        return (EC_FALSE);
    }

    coroutine_node_cancel(coroutine_node, coroutine_pool);
    return (EC_TRUE);
}

COROUTINE_NODE *coroutine_pool_get_master(COROUTINE_POOL *coroutine_pool)
{
    if(NULL_PTR == coroutine_pool)
    {
        return (NULL_PTR);
    }
    return COROUTINE_POOL_MASTER_OWNER(coroutine_pool);
}

EC_BOOL coroutine_pool_is_master(const COROUTINE_POOL *coroutine_pool)
{
    if(NULL_PTR == coroutine_pool
    || COROUTINE_POOL_CURRENT_OWNER(coroutine_pool) == COROUTINE_POOL_MASTER_OWNER(coroutine_pool))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

COROUTINE_NODE *coroutine_pool_get_current(COROUTINE_POOL *coroutine_pool)
{
    if(NULL_PTR == coroutine_pool)
    {
        return (NULL_PTR);
    }
    return COROUTINE_POOL_CURRENT_OWNER(coroutine_pool);
}

EC_BOOL coroutine_pool_set_current(COROUTINE_POOL *coroutine_pool, COROUTINE_NODE *coroutine_node)
{
    COROUTINE_POOL_CURRENT_OWNER(coroutine_pool) = coroutine_node;
    return (EC_TRUE);
}

COROUTINE_NODE *coroutine_pool_get_slave(COROUTINE_POOL *coroutine_pool)
{
    COROUTINE_NODE *coroutine_node;

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0050);
    coroutine_node = (COROUTINE_NODE *)clist_first_data(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0051);

    return (coroutine_node);
}

/*run the specific coroutine*/
void coroutine_pool_run_one(COROUTINE_POOL *coroutine_pool, COROUTINE_NODE *coroutine_node_master, COROUTINE_NODE *coroutine_node_slave)
{
    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_one: beg, slave %p\n", coroutine_node_slave);

    if(EC_FALSE == coroutine_node_pre_check(coroutine_node_slave, coroutine_pool))
    {
        dbg_log(SEC_0001_COROUTINE, 3)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_one: end, slave %p, pre-check return false\n", coroutine_node_slave);
        return;/*give up*/
    }

    COROUTINE_NODE_CLR_WAIT_STATUS(coroutine_node_slave);
    if(EC_FALSE == coroutine_node_swap_task(coroutine_node_master, coroutine_node_slave))
    {
        dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "error:coroutine_pool_run_one: swap from master to slave %p failed\n", coroutine_node_slave);
        coroutine_node_busy_to_tail(coroutine_node_slave, coroutine_pool);
        return;
    }

    //dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_pool_run: after  swap, master %lx, slave %lx status %lx\n", coroutine_node_master, coroutine_node_slave, COROUTINE_NODE_STATUS(coroutine_node_slave));
    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_one: end, slave %p, swap back\n", coroutine_node_slave);

    /*when swap back, coroutine_node_slave maybe busy or else. busy means it has already completed task*/
    coroutine_node_post_check(coroutine_node_slave, coroutine_pool);

    dbg_log(SEC_0001_COROUTINE, 5)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_one: end, slave %p\n", coroutine_node_slave);

    return;
}

void coroutine_pool_run_once(COROUTINE_POOL *coroutine_pool)
{
    COROUTINE_NODE *coroutine_node_master;

    UINT32 busy_num;
    UINT32 handle_num;

    coroutine_node_master = COROUTINE_POOL_MASTER_OWNER(coroutine_pool);
    coroutine_node_get_task(coroutine_node_master);

    busy_num = coroutine_pool_busy_num(coroutine_pool);
    dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_once: beg, busy_num = %ld\n", coroutine_pool_busy_num(coroutine_pool));
    for(handle_num = 0; handle_num < busy_num; handle_num ++)
    {
        COROUTINE_NODE *coroutine_node_slave;

        coroutine_node_slave = coroutine_pool_get_slave(coroutine_pool);
        if(NULL_PTR == coroutine_node_slave)
        {
            dbg_log(SEC_0001_COROUTINE, 0)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_once: busy_num = %ld, slave is null\n", coroutine_pool_busy_num(coroutine_pool));
            break;
        }
        if(EC_FALSE == coroutine_node_is_runnable(coroutine_node_slave))
        {
            coroutine_node_busy_to_tail(coroutine_node_slave, coroutine_pool);
            continue;
        }
        else
        {
            coroutine_pool_run_one(coroutine_pool, coroutine_node_master, coroutine_node_slave);
            break;
        }
    }
    dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_once: end, busy_num = %ld\n", coroutine_pool_busy_num(coroutine_pool));
    return;
}

void coroutine_pool_run_all(COROUTINE_POOL *coroutine_pool)
{
    COROUTINE_NODE *coroutine_node_master;

    UINT32 busy_num;
    UINT32 handle_num;

    coroutine_node_master = COROUTINE_POOL_MASTER_OWNER(coroutine_pool);
    /*coroutine_node_get_task(coroutine_node_master);*//*useless!*/

    task_brd_update_time(task_brd_default_get());

    busy_num = coroutine_pool_busy_num(coroutine_pool);
    dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_all: beg, busy_num = %ld\n", coroutine_pool_busy_num(coroutine_pool));
    for(handle_num = 0; handle_num < busy_num; handle_num ++)
    {
        COROUTINE_NODE *coroutine_node_slave;

        coroutine_node_slave = coroutine_pool_get_slave(coroutine_pool);
        if(NULL_PTR == coroutine_node_slave)
        {
            dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_all: busy_num = %ld, slave is null\n", coroutine_pool_busy_num(coroutine_pool));
            break;
        }

        if(EC_FALSE == coroutine_node_is_runnable(coroutine_node_slave))
        {
            coroutine_node_busy_to_tail(coroutine_node_slave, coroutine_pool);
            continue;
        }

        task_brd_update_time(task_brd_default_get());

        coroutine_pool_run_one(coroutine_pool, coroutine_node_master, coroutine_node_slave);
    }

    task_brd_update_time(task_brd_default_get());
    dbg_log(SEC_0001_COROUTINE, 9)(LOGSTDOUT, "[DEBUG] coroutine_pool_run_all: end, busy_num = %ld\n", coroutine_pool_busy_num(coroutine_pool));
    return;
}

/*endless loop*/
void coroutine_pool_run(COROUTINE_POOL *coroutine_pool)
{
    for(;;)
    {
        coroutine_pool_run_once(coroutine_pool);
    }

    return;
}

UINT32 coroutine_pool_size_no_lock(COROUTINE_POOL *coroutine_pool)
{
    UINT32 size;
    size = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool))
         + clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
    return (size);
}

UINT32 coroutine_pool_idle_num_no_lock(COROUTINE_POOL *coroutine_pool)
{
    UINT32 num;
    num = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
    return (num);
}

UINT32 coroutine_pool_busy_num_no_lock(COROUTINE_POOL *coroutine_pool)
{
    UINT32 num;
    num = clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
    return (num);
}

UINT32 coroutine_pool_num_info_no_lock(COROUTINE_POOL *coroutine_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *total_num)
{
    (*idle_num) = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
    (*busy_num) = clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
    (*total_num) = (*idle_num) + (*busy_num);

    return (0);
}

UINT32 coroutine_pool_size(COROUTINE_POOL *coroutine_pool)
{
    UINT32 size;

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0052);
    size = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool))
         + clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0053);

    return (size);
}

/*Jan 25, 2017: adjust pool size*/
EC_BOOL coroutine_pool_size_reset(COROUTINE_POOL *coroutine_pool, const UINT32 size)
{
    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0054);
    COROUTINE_POOL_WORKER_MAX_NUM(coroutine_pool) = size;
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0055);

    return (EC_TRUE);
}

UINT32 coroutine_pool_idle_num(COROUTINE_POOL *coroutine_pool)
{
    UINT32 num;

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0056);
    num = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0057);

    return (num);
}

UINT32 coroutine_pool_busy_num(COROUTINE_POOL *coroutine_pool)
{
    UINT32 num;

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0058);
    num = clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0059);

    return (num);
}

UINT32 coroutine_pool_num_info(COROUTINE_POOL *coroutine_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *total_num)
{
    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0060);
    (*idle_num) = clist_size(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool));
    (*busy_num) = clist_size(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool));
    (*total_num) = (*idle_num) + (*busy_num);
    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0061);

    return (0);
}

/*debug only*/
EC_BOOL coroutine_pool_check_node_is_idle(const COROUTINE_POOL *coroutine_pool, const COROUTINE_NODE *coroutine_node)
{
    if(NULL_PTR != clist_search_front_no_lock(COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool), (void *)coroutine_node, NULL_PTR))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*debug only*/
EC_BOOL coroutine_pool_check_node_is_busy(const COROUTINE_POOL *coroutine_pool, const COROUTINE_NODE *coroutine_node)
{
    if(NULL_PTR != clist_search_front_no_lock(COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool), (void *)coroutine_node, NULL_PTR))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


void coroutine_pool_print(LOG *log, COROUTINE_POOL *coroutine_pool)
{
    UINT32 idle_num;
    UINT32 busy_num;
    UINT32 total_num;

    COROUTINE_POOL_WORKER_LOCK(coroutine_pool, LOC_COROUTINE_0062);

    coroutine_pool_num_info_no_lock((COROUTINE_POOL *)coroutine_pool, &idle_num, &busy_num, &total_num);

    sys_log(log, "coroutine_pool %p: size %ld, idle %ld, busy %ld\n",
                 coroutine_pool, total_num, idle_num, busy_num
               );

    //sys_log(log, "idle worker list:\n");
    //clist_print(log, COROUTINE_POOL_WORKER_IDLE_LIST(coroutine_pool), (CLIST_DATA_DATA_PRINT)coroutine_node_print);

    sys_log(log, "busy worker list:\n");
    clist_print_no_lock(log, COROUTINE_POOL_WORKER_BUSY_LIST(coroutine_pool), (CLIST_DATA_DATA_PRINT)coroutine_node_print);

    sys_log(log, "master woker:\n");
    coroutine_node_print(log, COROUTINE_POOL_MASTER_OWNER(coroutine_pool));

    COROUTINE_POOL_WORKER_UNLOCK(coroutine_pool, LOC_COROUTINE_0063);
    return;
}

EC_BOOL coroutine_usleep(const UINT32 msec, const UINT32 location)
{
    COROUTINE_COND *coroutine_cond;

    coroutine_cond = coroutine_cond_new(msec, location);
    if(NULL_PTR == coroutine_cond)
    {
        return (EC_FALSE);
    }
    coroutine_cond_reserve(coroutine_cond, 1, location);
    coroutine_cond_wait(coroutine_cond, location);

    coroutine_cond_free(coroutine_cond, location);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

