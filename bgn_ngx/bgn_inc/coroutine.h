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

#ifndef _COROUTINE_H
#define _COROUTINE_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ucontext.h>

#include "type.h"
#include "log.h"
#include "coroutine.inc"


#if 0
#define COROUTINE_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error: assert failed at %s:%d\n", __FILE__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#else
#define COROUTINE_ASSERT(condition)            do{}while(0)
#endif

#define COROUTINE_NODE_MASTER_GET()              (coroutine_node_master_get())
#define COROUTINE_NODE_CUR_GET()                 (coroutine_node_cur_get())

#define COROUTINE_NODE_CUR_SET(coroutine_node)   (coroutine_pool_set_current(TASK_BRD_CROUTINE_POOL(task_brd_default_get()), coroutine_node))

#define __COROUTINE_IS_MASTER()                  (EC_TRUE == coroutine_pool_is_master(TASK_BRD_CROUTINE_POOL(task_brd_default_get())))

#define __COROUTINE_WAIT() do {                                      \
    COROUTINE_NODE *__master = COROUTINE_NODE_MASTER_GET();          \
    COROUTINE_NODE *__slave  = COROUTINE_NODE_CUR_GET();             \
    coroutine_node_wait_and_swap_task(__slave, __master);            \
} while(0)


#define __COROUTINE_NO_WAIT() do{                                    \
    if(!__COROUTINE_IS_MASTER()) {                                   \
        COROUTINE_NODE_CLR_WAIT_STATUS(COROUTINE_NODE_CUR_GET());    \
    }                                                                \
}while(0)

#define __COROUTINE_STATUS()          (NULL_PTR == COROUTINE_NODE_CUR_GET() ? 0xFFFF : COROUTINE_NODE_STATUS(COROUTINE_NODE_CUR_GET()))

//#define __COROUTINE_WAS_CANCELLED()   (__COROUTINE_STATUS() & COROUTINE_IS_CANL)
#define __COROUTINE_WAS_CANCELLED()   (EC_TRUE == coroutine_node_cur_is_cancelled())

#define __COROUTINE_CATCH_EXCEPTION()  if(__COROUTINE_WAS_CANCELLED()) {

#define __COROUTINE_HANDLE_EXCEPTION() } do{}while(0)

#define __COROUTINE_TERMINATE()        __COROUTINE_WAIT();} do{}while(0)

#define __COROUTINE_IF_EXCEPTION()     if(__COROUTINE_WAS_CANCELLED())

/**
* e.g.
*   __COROUTINE_CATCH_EXCEPTION()
*  {
*
*   <clean up code>
*
*  }__COROUTINE_TERMINATE();
**/


#define COROUTINE_CLEANUP_PUSH(coroutine_cancel_routine, coroutine_cancel_para) do{}while(0)

#define COROUTINE_CLEANUP_POP(flag)   do{}while(0)

#define COROUTINE_EXIT(ptr) do{}while(0)

#define COROUTINE_TEST_CANCEL() do{}while(0)

void coroutine_debug(LOG *log, const char *tip);

COROUTINE_MUTEX *coroutine_mutex_new(const UINT32 location);

EC_BOOL coroutine_mutex_init(COROUTINE_MUTEX *coroutine_mutex, const UINT32 flag, const UINT32 location);

EC_BOOL coroutine_mutex_clean(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location);

void    coroutine_mutex_free(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location);

EC_BOOL coroutine_mutex_lock(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location);

EC_BOOL coroutine_mutex_unlock(COROUTINE_MUTEX *coroutine_mutex, const UINT32 location);

COROUTINE_RWLOCK *coroutine_rwlock_new(const UINT32 location);

EC_BOOL coroutine_rwlock_init(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 flag, const UINT32 location);

EC_BOOL coroutine_rwlock_clean(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location);

void    coroutine_rwlock_free(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location);

EC_BOOL coroutine_rwlock_rdlock(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location);

EC_BOOL coroutine_rwlock_wrlock(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location);

EC_BOOL coroutine_rwlock_unlock(COROUTINE_RWLOCK *coroutine_rwlock, const UINT32 location);

COROUTINE_COND *coroutine_cond_new(const UINT32 timeout_msec, const UINT32 location);

EC_BOOL coroutine_cond_init(COROUTINE_COND *coroutine_cond, const UINT32 timeout_msec, const UINT32 location);

EC_BOOL coroutine_cond_clean(COROUTINE_COND *coroutine_cond, const UINT32 location);

void    coroutine_cond_free(COROUTINE_COND *coroutine_cond, const UINT32 location);

EC_BOOL coroutine_cond_reserve(COROUTINE_COND *coroutine_cond, const UINT32 counter, const UINT32 location);

EC_BOOL coroutine_cond_release(COROUTINE_COND *coroutine_cond, const UINT32 location);

EC_BOOL coroutine_cond_release_all(COROUTINE_COND *coroutine_cond, const UINT32 location);

EC_BOOL coroutine_cond_terminate(COROUTINE_COND *coroutine_cond, const UINT32 location);

EC_BOOL coroutine_cond_wait(COROUTINE_COND *coroutine_cond, const UINT32 location);

UINT32  coroutine_cond_spy(COROUTINE_COND *coroutine_cond, const UINT32 location);

EC_BOOL coroutine_cond_set_timeout(COROUTINE_COND *coroutine_cond, const UINT32 timeout_msec);

EC_BOOL coroutine_cond_is_timeout(const COROUTINE_COND *coroutine_cond);

EC_BOOL coroutine_cond_is_terminate(const COROUTINE_COND *coroutine_cond);

COROUTINE_CHECKER *coroutine_checker_new(EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);

EC_BOOL coroutine_checker_init(COROUTINE_CHECKER *coroutine_checker, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);

EC_BOOL coroutine_checker_clean(COROUTINE_CHECKER *coroutine_checker);

EC_BOOL coroutine_checker_free(COROUTINE_CHECKER *coroutine_checker);

EC_BOOL coroutine_checker_cmp(const COROUTINE_CHECKER *coroutine_checker_1st, const COROUTINE_CHECKER *coroutine_checker_2nd);

COROUTINE_CLEANER *coroutine_cleaner_new(EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);

EC_BOOL coroutine_cleaner_init(COROUTINE_CLEANER *coroutine_cleaner, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);

EC_BOOL coroutine_cleaner_clean(COROUTINE_CLEANER *coroutine_cleaner);

EC_BOOL coroutine_cleaner_free(COROUTINE_CLEANER *coroutine_cleaner);

EC_BOOL coroutine_cleaner_cmp(const COROUTINE_CLEANER *coroutine_cleaner_1st, const COROUTINE_CLEANER *coroutine_cleaner_2nd);

void coroutine_cancel();

COROUTINE_NODE *coroutine_self();

COROUTINE_NODE *coroutine_node_master_get();

COROUTINE_NODE *coroutine_node_cur_get();

EC_BOOL coroutine_node_cur_is_cancelled();

COROUTINE_NODE *coroutine_node_new(COROUTINE_NODE *coroutine_node_next);

EC_BOOL coroutine_node_init(COROUTINE_NODE *coroutine_node, COROUTINE_NODE *coroutine_node_next);

UINT32 coroutine_node_clean(COROUTINE_NODE *coroutine_node);

UINT32 coroutine_node_free(COROUTINE_NODE *coroutine_node);

EC_BOOL coroutine_node_make_task(COROUTINE_NODE *coroutine_node, const UINT32 start_routine_addr, const UINT32 arg_num, va_list arg_list);

EC_BOOL coroutine_node_get_task(COROUTINE_NODE *coroutine_node);

EC_BOOL coroutine_node_set_task(COROUTINE_NODE *coroutine_node);

EC_BOOL coroutine_node_swap_task(COROUTINE_NODE *coroutine_node_save, COROUTINE_NODE *coroutine_node_to);

EC_BOOL coroutine_node_wait_and_swap_task(COROUTINE_NODE *coroutine_node_save, COROUTINE_NODE *coroutine_node_to);

UINT32 coroutine_node_shutdown(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_node_cancel(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool);

EC_BOOL coroutine_node_pre_check(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool);

EC_BOOL coroutine_node_post_check(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_node_busy_to_idle(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_node_busy_to_tail(COROUTINE_NODE *coroutine_node, COROUTINE_POOL *coroutine_pool);

EC_BOOL coroutine_node_is_runnable(const COROUTINE_NODE *coroutine_node);

void coroutine_node_print(LOG *log, const COROUTINE_NODE *coroutine_node);

EC_BOOL coroutine_node_post_cleaner_push(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);
COROUTINE_CLEANER *coroutine_node_post_cleaner_pop(COROUTINE_NODE *coroutine_node);
EC_BOOL coroutine_node_post_cleaner_del(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);
EC_BOOL coroutine_node_post_cleaner_pop_and_release(COROUTINE_NODE *coroutine_node);
EC_BOOL coroutine_node_post_cleaner_run(COROUTINE_NODE *coroutine_node);
EC_BOOL coroutine_node_post_cleaner_release(COROUTINE_NODE *coroutine_node);
UINT32  coroutine_node_post_cleaner_num(const COROUTINE_NODE *coroutine_node);

EC_BOOL coroutine_node_prev_checker_push(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);
COROUTINE_CHECKER *coroutine_node_prev_checker_pop(COROUTINE_NODE *coroutine_node);
EC_BOOL coroutine_node_prev_checker_del(COROUTINE_NODE *coroutine_node, EC_BOOL (*func)(void *, void *), void *arg1, void *arg2);
EC_BOOL coroutine_node_prev_checker_run(COROUTINE_NODE *coroutine_node);
EC_BOOL coroutine_node_prev_checker_release(COROUTINE_NODE *coroutine_node);
UINT32  coroutine_node_prev_checker_num(const COROUTINE_NODE *coroutine_node);

COROUTINE_POOL * coroutine_pool_new(const UINT32 coroutine_num, const UINT32 flag);

UINT32 coroutine_pool_init(COROUTINE_POOL *coroutine_pool);

/*create coroutine_num coroutine_nodes and add them to coroutine_pool*/
UINT32 coroutine_pool_create(COROUTINE_POOL *coroutine_pool, const UINT32 coroutine_num);

UINT32 coroutine_pool_expand(COROUTINE_POOL *coroutine_pool, const UINT32 coroutine_num);

UINT32 coroutine_pool_shrink(COROUTINE_POOL *coroutine_pool, const UINT32 coroutine_num_to_shrink);

UINT32 coroutine_pool_shutdown(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_clean(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_free(COROUTINE_POOL *coroutine_pool);

COROUTINE_NODE * coroutine_pool_reserve_no_lock(COROUTINE_POOL *coroutine_pool);

COROUTINE_NODE * coroutine_pool_reserve(COROUTINE_POOL *coroutine_pool);

COROUTINE_NODE * coroutine_pool_load_no_lock(COROUTINE_POOL *coroutine_pool, const UINT32 start_routine_addr, const UINT32 para_num, va_list para_list);

COROUTINE_NODE * coroutine_pool_load(COROUTINE_POOL *coroutine_pool, const UINT32 start_routine_addr, const UINT32 para_num, ...);

EC_BOOL coroutine_pool_unload(COROUTINE_POOL *coroutine_pool, COROUTINE_NODE *coroutine_node);

COROUTINE_NODE *coroutine_pool_get_master(COROUTINE_POOL *coroutine_pool);

EC_BOOL coroutine_pool_is_master(const COROUTINE_POOL *coroutine_pool);

COROUTINE_NODE *coroutine_pool_get_current(COROUTINE_POOL *coroutine_pool);

EC_BOOL coroutine_pool_set_current(COROUTINE_POOL *coroutine_pool, COROUTINE_NODE *coroutine_node);

COROUTINE_NODE *coroutine_pool_get_slave(COROUTINE_POOL *coroutine_pool);

void coroutine_pool_run_one(COROUTINE_POOL *coroutine_pool, COROUTINE_NODE *coroutine_node_master, COROUTINE_NODE *coroutine_node_slave);

void coroutine_pool_run_once(COROUTINE_POOL *coroutine_pool);

void coroutine_pool_run_all(COROUTINE_POOL *coroutine_pool);

/*endless loop*/
void coroutine_pool_run(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_size_no_lock(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_idle_num_no_lock(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_busy_num_no_lock(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_num_info_no_lock(COROUTINE_POOL *coroutine_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *total_num);

UINT32 coroutine_pool_size(COROUTINE_POOL *coroutine_pool);

EC_BOOL coroutine_pool_size_reset(COROUTINE_POOL *coroutine_pool, const UINT32 size);

UINT32 coroutine_pool_idle_num(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_busy_num(COROUTINE_POOL *coroutine_pool);

UINT32 coroutine_pool_num_info(COROUTINE_POOL *coroutine_pool, UINT32 *idle_num, UINT32 *busy_num, UINT32 *total_num);

void coroutine_pool_print(LOG *log, COROUTINE_POOL *coroutine_pool);

/*debug only*/
EC_BOOL coroutine_pool_check_node_is_idle(const COROUTINE_POOL *coroutine_pool, const COROUTINE_NODE *coroutine_node);

/*debug only*/
EC_BOOL coroutine_pool_check_node_is_busy(const COROUTINE_POOL *coroutine_pool, const COROUTINE_NODE *coroutine_node);

EC_BOOL coroutine_usleep(const UINT32 msec, const UINT32 location);

#endif/*_COROUTINE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

