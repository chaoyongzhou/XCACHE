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

#ifndef _CROUTINE_H
#define _CROUTINE_H

#if ((SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH) && (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH))
#error "error:croutine.h: cannot switch on both CROUTINE_SUPPORT_COROUTINE_SWITCH and CROUTINE_SUPPORT_CTHREAD_SWITCH !"
#endif

#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ucontext.h>

#include "type.h"
#include "log.h"
#include "coroutine.inc"
#include "coroutine.h"

#define CROUTINE_CLEANUP_PUSH(croutine_cancel_routine, croutine_cancel_para) do{}while(0)

#define CROUTINE_CLEANUP_POP(flag)   do{}while(0)

#define CROUTINE_EXIT(ptr) do{}while(0)

#define CROUTINE_TEST_CANCEL() do{}while(0)

typedef COROUTINE_MUTEX CROUTINE_MUTEX;

#define croutine_mutex_new(location)                             coroutine_mutex_new(location)

#define croutine_mutex_init(croutine_mutex, flag, location)      coroutine_mutex_init(croutine_mutex, flag, location)

#define croutine_mutex_clean(croutine_mutex, location)           coroutine_mutex_clean(croutine_mutex, location)

#define croutine_mutex_free(croutine_mutex, location)            coroutine_mutex_free(croutine_mutex, location)

//#define croutine_mutex_lock(croutine_mutex, location)            coroutine_mutex_lock(croutine_mutex, location)

//#define croutine_mutex_unlock(croutine_mutex, location)          coroutine_mutex_unlock(croutine_mutex, location)

#define croutine_mutex_lock(croutine_mutex, location)            (void)0

#define croutine_mutex_unlock(croutine_mutex, location)          (void)0


typedef COROUTINE_RWLOCK CROUTINE_RWLOCK;

#define croutine_rwlock_new(location)                            coroutine_rwlock_new(location)

#define croutine_rwlock_init(croutine_rwlock, flag, location)    coroutine_rwlock_init(croutine_rwlock, flag, location)

#define croutine_rwlock_clean(croutine_rwlock, location)         coroutine_rwlock_clean(croutine_rwlock, location)

#define croutine_rwlock_free(croutine_rwlock, location)          coroutine_rwlock_free(croutine_rwlock, location)

//#define croutine_rwlock_rdlock(croutine_rwlock, location)        coroutine_rwlock_rdlock(croutine_rwlock, location)

//#define croutine_rwlock_wrlock(croutine_rwlock, location)        coroutine_rwlock_wrlock(croutine_rwlock, location)

//#define croutine_rwlock_unlock(croutine_rwlock, location)        coroutine_rwlock_unlock(croutine_rwlock, location)

#define croutine_rwlock_rdlock(croutine_rwlock, location)        (void)0

#define croutine_rwlock_wrlock(croutine_rwlock, location)        (void)0

#define croutine_rwlock_unlock(croutine_rwlock, location)        (void)0


typedef COROUTINE_COND CROUTINE_COND;

#define croutine_cond_new(msec, location)                        coroutine_cond_new(msec, location)

#define croutine_cond_init(croutine_cond, nsec, location)        coroutine_cond_init(croutine_cond, nsec, location)

#define croutine_cond_clean(croutine_cond, location)             coroutine_cond_clean(croutine_cond, location)

#define croutine_cond_free(croutine_cond, location)              coroutine_cond_free(croutine_cond, location)

#define croutine_cond_set_timeout(croutine_cond, timeout_msec)   coroutine_cond_set_timeout(croutine_cond, timeout_msec)

#define croutine_cond_reserve(croutine_cond, counter, location)  coroutine_cond_reserve(croutine_cond, counter, location)

#define croutine_cond_release(croutine_cond, location)           coroutine_cond_release(croutine_cond, location)

#define croutine_cond_release_all(croutine_cond, location)       coroutine_cond_release_all(croutine_cond, location)

#define croutine_cond_terminate(croutine_cond, location)         coroutine_cond_terminate(croutine_cond, location)

#define croutine_cond_wait(croutine_cond, location)              coroutine_cond_wait(croutine_cond, location)

#define croutine_cond_spy(croutine_cond, location)               coroutine_cond_spy(croutine_cond, location)

typedef COROUTINE_NODE   CROUTINE_NODE;

#define CROUTINE_NODE_COND_INIT(croutine_node, nsec, location)                     COROUTINE_NODE_COND_INIT(croutine_node, nsec, location)

#define CROUTINE_NODE_COND_CLEAN(croutine_node, location)                          COROUTINE_NODE_COND_CLEAN(croutine_node, location)

#define CROUTINE_NODE_COND_RESERVE(croutine_node, counter, location)               COROUTINE_NODE_COND_RESERVE(croutine_node, counter, location)

#define CROUTINE_NODE_COND_RELEASE(croutine_node, location)                        COROUTINE_NODE_COND_RELEASE(croutine_node, location)

#define CROUTINE_NODE_COND_RELEASE_ALL(croutine_node, location)                    COROUTINE_NODE_COND_RELEASE_ALL(croutine_node, location)

#define CROUTINE_NODE_COND_WAIT(croutine_node, location)                           COROUTINE_NODE_COND_WAIT(croutine_node, location)

#define CROUTINE_NODE_COND_SPY(croutine_node, location)                            COROUTINE_NODE_COND_SPY(croutine_node, location)

#define croutine_node_shutdown(croutine_node, croutine_pool)    coroutine_node_shutdown(croutine_node, croutine_pool)

typedef COROUTINE_POOL   CROUTINE_POOL;

#define croutine_pool_new(croutine_num, flag)                    coroutine_pool_new(croutine_num, flag)

#define croutine_pool_free(__croutine_pool)                      coroutine_pool_free(__croutine_pool)

/*un-determinted parameter list*/
#define croutine_pool_load                                       coroutine_pool_load

#define croutine_pool_load_preempt                               coroutine_pool_load_preempt

#define croutine_pool_unload                                     coroutine_pool_unload

#define croutine_pool_size(__croutine_pool)                      coroutine_pool_size(__croutine_pool)

#define croutine_pool_idle_num(__croutine_pool)                  coroutine_pool_idle_num(__croutine_pool)

#define croutine_pool_busy_num(__croutine_pool)                  coroutine_pool_busy_num(__croutine_pool)

#define croutine_pool_num_info(__croutine_pool, inum, bnum, pnum, tnum)   \
        coroutine_pool_num_info(__croutine_pool, inum, bnum, pnum, tnum)

#define croutine_pool_print(log, __croutine_pool)                coroutine_pool_print(log, __croutine_pool)


#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ucontext.h>

#include "type.h"
#include "log.h"
#include "cthread.h"
#include "cmutex.h"


#define CROUTINE_CLEANUP_PUSH(croutine_cancel_routine, croutine_cancel_para)    CTHREAD_CLEANUP_PUSH(croutine_cancel_routine, croutine_cancel_para)

#define CROUTINE_CLEANUP_POP(flag)                                              CTHREAD_CLEANUP_POP(flag)

#define CROUTINE_EXIT(ptr)                                                      CTHREAD_EXIT(ptr)

#define CROUTINE_TEST_CANCEL()                                                  CTHREAD_TEST_CANCEL()


typedef CMUTEX CROUTINE_MUTEX;

#define croutine_mutex_new(location)                             cmutex_new(location)

#define croutine_mutex_init(croutine_mutex, flag, location)      cmutex_init(croutine_mutex, flag, location)

#define croutine_mutex_clean(croutine_mutex, location)           cmutex_clean(croutine_mutex, location)

#define croutine_mutex_free(croutine_mutex, location)            cmutex_free(croutine_mutex, location)

#define croutine_mutex_lock(croutine_mutex, location)            cmutex_lock(croutine_mutex, location)

#define croutine_mutex_unlock(croutine_mutex, location)          cmutex_unlock(croutine_mutex, location)


typedef CRWLOCK CROUTINE_RWLOCK;

#define croutine_rwlock_new(location)                            crwlock_new(location)

#define croutine_rwlock_init(croutine_rwlock, flag, location)    crwlock_init(croutine_rwlock, flag, location)

#define croutine_rwlock_clean(croutine_rwlock, location)         crwlock_clean(croutine_rwlock, location)

#define croutine_rwlock_free(croutine_rwlock, location)          crwlock_free(croutine_rwlock, location)

#define croutine_rwlock_rdlock(croutine_rwlock, location)        crwlock_rdlock(croutine_rwlock, location)

#define croutine_rwlock_wrlock(croutine_rwlock, location)        crwlock_wrlock(croutine_rwlock, location)

#define croutine_rwlock_unlock(croutine_rwlock, location)        crwlock_unlock(croutine_rwlock, location)


typedef CCOND CROUTINE_COND;

#define croutine_cond_new(msec, location)                        ccond_new(location) /*ignore timeout nsec*/

#define croutine_cond_init(croutine_cond, nsec, location)        ccond_init(croutine_cond, location) /*ignore timeout nsec*/

#define croutine_cond_clean(croutine_cond, location)             ccond_clean(croutine_cond, location)

#define croutine_cond_free(croutine_cond, location)              ccond_free(croutine_cond, location)

#define croutine_cond_set_timeout(croutine_cond, timeout_msec)   do{}while(0)

#define croutine_cond_reserve(croutine_cond, counter, location)  ccond_reserve(croutine_cond, counter, location)

#define croutine_cond_release(croutine_cond, location)           ccond_release(croutine_cond, location)

#define croutine_cond_release_all(croutine_cond, location)       ccond_release_all(croutine_cond, location)

#define croutine_cond_terminate(croutine_cond, location)         ccond_terminate(croutine_cond, location)

#define croutine_cond_wait(croutine_cond, location)              ccond_wait(croutine_cond, location)

#define croutine_cond_spy(croutine_cond, location)               ccond_spy(croutine_cond, location)


typedef CTHREAD_NODE   CROUTINE_NODE;

#define CROUTINE_NODE_COND_INIT(croutine_node, nsec, location)                     CTHREAD_NODE_CCOND_INIT(croutine_node, nsec, location)

#define CROUTINE_NODE_COND_CLEAN(croutine_node, location)                          CTHREAD_NODE_CCOND_CLEAN(croutine_node, location)

#define CROUTINE_NODE_COND_RESERVE(croutine_node, counter, location)               CTHREAD_NODE_CCOND_RESERVE(croutine_node, counter, location)

#define CROUTINE_NODE_COND_RELEASE(croutine_node, location)                        CTHREAD_NODE_CCOND_RELEASE(croutine_node, location)

#define CROUTINE_NODE_COND_RELEASE_ALL(croutine_node, location)                    CTHREAD_NODE_CCOND_RELEASE_ALL(croutine_node, location)

#define CROUTINE_NODE_COND_WAIT(croutine_node, location)                           CTHREAD_NODE_CCOND_WAIT(croutine_node, location)

#define CROUTINE_NODE_COND_SPY(croutine_node, location)                            CTHREAD_NODE_CCOND_SPY(croutine_node, location)

#define croutine_node_shutdown(croutine_node, croutine_pool)    cthread_node_shutdown(croutine_node, croutine_pool)

typedef CTHREAD_POOL   CROUTINE_POOL;

#define croutine_pool_new(croutine_num, flag)                    cthreadp_new(croutine_num, flag)

#define croutine_pool_free(__croutine_pool)                      cthreadp_free(__croutine_pool)

/*un-determinted parameter list*/
#define croutine_pool_load                                       cthreadp_load

#define croutine_pool_load_preempt                               cthreadp_load

#define croutine_pool_unload                                     cthreadp_unload

#define croutine_pool_size(__croutine_pool)                      cthreadp_size(__croutine_pool)

#define croutine_pool_idle_num(__croutine_pool)                  cthreadp_idle_num(__croutine_pool)

#define croutine_pool_busy_num(__croutine_pool)                  cthreadp_busy_num(__croutine_pool)

#define croutine_pool_num_info(__croutine_pool, inum, bnum, pnum, tnum)   \
        cthreadp_num_info(__croutine_pool, inum, bnum, pnum, tnum)

#define croutine_pool_print(log, __croutine_pool)                cthreadp_print(log, __croutine_pool)

#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/


#endif/*_CROUTINE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

