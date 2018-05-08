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
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include "type.h"

#include "mm.h"
#include "log.h"

#include "bgnctrl.h"
#include "crb.h"
#include "cthread.h"

/**********************************************************************************************************************************************\
test_mutext.c
=============

scenario 1:
==========
usage: <init|clean|lock|unlock|print|quit>
choice> clean
error:mutex_clean - EBUSY: mutex bff0ce60 is locked or in use by another thread
mutex_print: mutex bff0ce60: __m_reserved = 134513750, __m_count = -1074737352, __m_owner = 12343474, __m_kind = 134513336
choice> print
mutex_print: mutex bff0ce60: __m_reserved = 134513750, __m_count = -1074737352, __m_owner = 12343474, __m_kind = 134513336
choice> init
mutex_print: mutex bff0ce60: __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1
choice> unlock
mutex_print: mutex bff0ce60: __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1
choice> lock
mutex_print: mutex bff0ce60: __m_reserved = 1, __m_count = 1, __m_owner = 15045, __m_kind = 1
choice> lock
mutex_print: mutex bff0ce60: __m_reserved = 1, __m_count = 2, __m_owner = 15045, __m_kind = 1
choice> lock
mutex_print: mutex bff0ce60: __m_reserved = 1, __m_count = 3, __m_owner = 15045, __m_kind = 1
choice> lock
mutex_print: mutex bff0ce60: __m_reserved = 1, __m_count = 4, __m_owner = 15045, __m_kind = 1
choice> clean
error:mutex_clean - EBUSY: mutex bff0ce60 is locked or in use by another thread
mutex_print: mutex bff0ce60: __m_reserved = 1, __m_count = 4, __m_owner = 15045, __m_kind = 1
choice> unlock
mutex_print: mutex bff0ce60: __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1
choice> unlock
mutex_print: mutex bff0ce60: __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1
choice> unlock
mutex_print: mutex bff0ce60: __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1
choice> clean
mutex_print: mutex bff0ce60: __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1
choice>

scenario 2:
===========
usage: <init|clean|lock|unlock|print|quit>
choice> lock
==> hung on without info

result notes:
============
1. mutex MUST be initialized and then be used
    1.1 if lock some un-initialized mutex, fatal error will happen and the program is hang on
    1.2 after initialize, mutex is set as
            __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1

2. mutex can be locked many times (recursive attribute) as well as __m_count increase and __m_reserved keep 1
            __m_reserved = 1, __m_count = 4, __m_owner = 15045, __m_kind = 1

3. mutex unlock will clean up __m_reserved, __m_count and __m_owner, i.e., restore to the state of initialization
    before unlock:
            __m_reserved = 1, __m_count = 4, __m_owner = 15045, __m_kind = 1
    after unlock:
            __m_reserved = 0, __m_count = 0, __m_owner = 0, __m_kind = 1

4. mutex can be unlocked many times after it is initialized

5. mutex is able to clean only if it is not locked


summary:
=======
1. after initialize, __m_kind =1
2. when  lock, must __m_kind = 1
3. after lock, __m_reserved = 1
4. when  unlock, must __m_kind = 1
5. after unlock, __m_reserved = 0, __m_count = 0
6. when clean, must __m_reserved = 0

note: __m_kind = 1 means CMUTEX_RECURSIVE_NP is set
\**********************************************************************************************************************************************/

#if (SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)

static CMUTEX_POOL g_cmutex_pool;

static EC_BOOL cmutex_log_switch = EC_FALSE;

//#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
#define cmutex_dbg_log(SECTION, LEVEL)  !do_log(SECTION, LEVEL) ? (void) 0 : cmutex_log_null
//#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/

//#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
//#define cmutex_dbg_log(SECTION, LEVEL) dbg_log(SECTION, LEVEL)
//#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

int cmutex_log_null(LOG *log, const char * format, ...)
{
    return 0;
}

STATIC_CAST static void cmutex_print(const char *info, const CMUTEX *cmutex)
{
    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "[tid %ld] %s: cmutex %p : __m_reserved = %d, __m_count = %d, __m_owner = %d, __m_kind = %d\n",
                        CTHREAD_GET_TID(), info, cmutex,
                        CMUTEX_RESERVED(cmutex),
                        CMUTEX_COUNT(cmutex),
                        CMUTEX_OWNER(cmutex),
                        CMUTEX_KIND(cmutex)
            );
    return;
}
STATIC_CAST static EC_BOOL cmutex_check(const CMUTEX *cmutex, const UINT32 op, const UINT32 location)
{
    switch(op)
    {
        case CMUTEX_OP_NEW:
            break;
        case CMUTEX_OP_INIT:
            if(0 != CMUTEX_COUNT(cmutex))
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error: cmutex %p : op = %ld, __m_reserved = %d, __m_count = %d, __m_owner = %d, __m_kind = %d, at %s:%ld\n",
                                    cmutex, op,
                                    CMUTEX_RESERVED(cmutex),
                                    CMUTEX_COUNT(cmutex),
                                    CMUTEX_OWNER(cmutex),
                                    CMUTEX_KIND(cmutex),
                                    MM_LOC_FILE_NAME(location),
                                    MM_LOC_LINE_NO(location)
                        );
                CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_check", cmutex);
                return (EC_FALSE);
            }
            break;
        case CMUTEX_OP_FREE:
            if(0 != CMUTEX_COUNT(cmutex))
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error: cmutex %p : op = %ld, __m_reserved = %d, __m_count = %d, __m_owner = %d, __m_kind = %d, at %s:%ld\n",
                                    cmutex, op,
                                    CMUTEX_RESERVED(cmutex),
                                    CMUTEX_COUNT(cmutex),
                                    CMUTEX_OWNER(cmutex),
                                    CMUTEX_KIND(cmutex),
                                    MM_LOC_FILE_NAME(location),
                                    MM_LOC_LINE_NO(location)
                        );
                CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_check", cmutex);
                return (EC_FALSE);
            }
            break;
        case CMUTEX_OP_CLEAN:
            if(0 != CMUTEX_COUNT(cmutex))
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error: cmutex %p : op = %ld, __m_reserved = %d, __m_count = %d, __m_owner = %d, __m_kind = %d, at %s:%ld\n",
                                    cmutex, op,
                                    CMUTEX_RESERVED(cmutex),
                                    CMUTEX_COUNT(cmutex),
                                    CMUTEX_OWNER(cmutex),
                                    CMUTEX_KIND(cmutex),
                                    MM_LOC_FILE_NAME(location),
                                    MM_LOC_LINE_NO(location)
                        );
                CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_check", cmutex);
                return (EC_FALSE);
            }
            break;
        case CMUTEX_OP_LOCK:
            if(0 != CMUTEX_COUNT(cmutex))
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error: cmutex %p : op = %ld, __m_reserved = %d, __m_count = %d, __m_owner = %d, __m_kind = %d, at %s:%ld\n",
                                    cmutex, op,
                                    CMUTEX_RESERVED(cmutex),
                                    CMUTEX_COUNT(cmutex),
                                    CMUTEX_OWNER(cmutex),
                                    CMUTEX_KIND(cmutex),
                                    MM_LOC_FILE_NAME(location),
                                    MM_LOC_LINE_NO(location)
                        );
                CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_check", cmutex);
                return (EC_FALSE);
            }
            break;
        case CMUTEX_OP_UNLOCK:
            if(0 == CMUTEX_COUNT(cmutex))
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error: cmutex %p : op = %ld, __m_reserved = %d, __m_count = %d, __m_owner = %d, __m_kind = %d, at %s:%ld\n",
                                    cmutex, op,
                                    CMUTEX_RESERVED(cmutex),
                                    CMUTEX_COUNT(cmutex),
                                    CMUTEX_OWNER(cmutex),
                                    CMUTEX_KIND(cmutex),
                                    MM_LOC_FILE_NAME(location),
                                    MM_LOC_LINE_NO(location)
                        );
                CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_check", cmutex);
                return (EC_FALSE);
            }
            break;
    }

    return (EC_TRUE);
}

EC_BOOL cmutex_attr_set(CMUTEX_ATTR  *mutex_attr, const UINT32 flag, const UINT32 location)
{
    int ret_val;

    ret_val = pthread_mutexattr_init(mutex_attr);
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case ENOMEM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - ENOMEM: Insufficient memory to create the mutex attributes object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - UNKNOWN: Error detected when mutexattr init, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }

        return (ret_val);
    }

    if(CMUTEX_PROCESS_PRIVATE & flag)
    {
        ret_val = pthread_mutexattr_setpshared(mutex_attr, PTHREAD_PROCESS_PRIVATE);
        if( 0 != ret_val )
        {
            switch( ret_val )
            {
                case EINVAL:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - EINVAL: value specified for argument -pshared- is INCORRECT, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }

                default:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - UNKNOWN: error detected when setpshared, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }
            }

            return (ret_val);
        }
    }

    if(CMUTEX_PROCESS_SHARED & flag)
    {
        ret_val = pthread_mutexattr_setpshared(mutex_attr, PTHREAD_PROCESS_SHARED);
        if( 0 != ret_val )
        {
            switch( ret_val )
            {
                case EINVAL:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - EINVAL: value specified for argument -pshared- is INCORRECT, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }

                default:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - UNKNOWN: error detected when setpshared, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }
            }

            return (ret_val);
        }
    }

    if(CMUTEX_TIMED_NP & flag)
    {
        /*Initialize the mutex attribute called 'type' to PTHREAD_MUTEX_RECURSIVE_NP,
        so that a thread can recursively lock a mutex if needed. */
        ret_val = pthread_mutexattr_settype(mutex_attr, PTHREAD_MUTEX_TIMED_NP);
        if( 0 != ret_val )
        {
            switch( ret_val )
            {
                case EINVAL:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - EINVAL: value specified for argument -type- is INCORRECT, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }

                default:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - UNKNOWN: error detected when settype, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }
            }

            return (ret_val);
        }
    }

    //if(CMUTEX_RECURSIVE_NP & flag)
    else
    {
        /*Initialize the mutex attribute called 'type' to PTHREAD_MUTEX_RECURSIVE_NP,
        so that a thread can recursively lock a mutex if needed. */
        ret_val = pthread_mutexattr_settype(mutex_attr, PTHREAD_MUTEX_RECURSIVE_NP);
        if( 0 != ret_val )
        {
            switch( ret_val )
            {
                case EINVAL:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - EINVAL: value specified for argument -type- is INCORRECT, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }

                default:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_attr_set - UNKNOWN: error detected when settype, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }
            }

            return (ret_val);
        }
    }

    //pthread_mutexattr_setprotocol(mutex_attr, PTHREAD_PRIO_NONE);

    return (ret_val);

}

CMUTEX *cmutex_new(const UINT32 flag, const UINT32 location)
{
    CMUTEX      *cmutex;

    cmutex = (CMUTEX *)SAFE_MALLOC(sizeof(CMUTEX), LOC_CMUTEX_0001);
    if(NULL_PTR == cmutex)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_new: failed to alloc CMUTEX, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (NULL_PTR);
    }

    if(EC_FALSE == cmutex_init(cmutex, flag, location))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_init: failed to init cmutex %p, called at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        SAFE_FREE(cmutex, LOC_CMUTEX_0002);
        return (NULL_PTR);
    }

    //CMUTEX_INIT_LOCATION(cmutex);
    CMUTEX_SET_LOCATION(cmutex, CMUTEX_OP_NEW, location);

    CMUTEX_CHECK_LOCK_VALIDITY(cmutex, CMUTEX_OP_NEW, location);

    return (cmutex);
}

EC_BOOL cmutex_init(CMUTEX *cmutex, const UINT32 flag, const UINT32 location)
{
    CMUTEX_ATTR  mutex_attr;
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] cmutex_init: cmutex %p: lock at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    CMUTEX_INIT_LOCATION(cmutex);
    //CMUTEX_CHECK_LOCK_VALIDITY(cmutex, CMUTEX_OP_INIT, location);


    CMUTEX_SET_LOCATION(cmutex, CMUTEX_OP_INIT, location);

    ret_val = cmutex_attr_set(&mutex_attr, flag, location);
    if( 0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_init: failed to set mutex attribute\n");
        return (EC_FALSE);
    }

    /* Creating and Initializing the mutex with the above stated mutex attributes */
    ret_val = pthread_mutex_init(CMUTEX_MUTEX(cmutex), &mutex_attr);
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case EAGAIN:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_new - EAGAIN: System resources(other than memory) are unavailable, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EPERM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_new - EPERM: Doesn't have privilige to perform this operation, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_new - EINVAL: mutex_attr doesn't refer a valid condition variable attribute object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EFAULT:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_new - EFAULT: Mutex or mutex_attr is an invalid pointer, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case ENOMEM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_new - ENOMEM: Insufficient memory exists to initialize the mutex, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_new - UNKNOWN: Error detected when mutex init, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }

        return (EC_FALSE);
    }

    //cmutex_pool_add(cmutex_pool_default_get(), cmutex);
    return (EC_TRUE);
}

void cmutex_free(CMUTEX *cmutex, const UINT32 location)
{
    CMUTEX_CHECK_LOCK_VALIDITY(cmutex, CMUTEX_OP_FREE, location);

    CMUTEX_SET_LOCATION(cmutex, CMUTEX_OP_FREE, location);
    cmutex_clean(cmutex, LOC_CMUTEX_0003);
    SAFE_FREE(cmutex, LOC_CMUTEX_0004);
}

void cmutex_clean(CMUTEX *cmutex, const UINT32 location)
{

    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] cmutex_clean: cmutex %p: lock at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    CMUTEX_CHECK_LOCK_VALIDITY(cmutex, CMUTEX_OP_CLEAN, location);

    /*when clean, must __m_reserved = 0*/
    if(0 != CMUTEX_RESERVED(cmutex))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_clean: cmutex %p:invalid reserved value found at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        CMUTEX_PRINT_LOCK_INFO(LOGSTDOUT, CMUTEX_OP_CLEAN, cmutex);
        return;
    }

    CMUTEX_SET_LOCATION(cmutex, CMUTEX_OP_CLEAN, location);

    ret_val = pthread_mutex_destroy(CMUTEX_MUTEX(cmutex));
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_clean - EINVAL: cmutex %p doesn't refer to an initialized mutex, called at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_clean - EBUSY: cmutex %p is locked or in use by another thread, called at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_clean - UNKNOWN: cmutex %p detect error, error no: %d, called at %s:%ld\n", cmutex, ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
    }

    //cmutex_pool_rmv(cmutex_pool_default_get(), cmutex);
    return;
}

EC_BOOL cmutex_lock(CMUTEX *cmutex, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] cmutex_lock: cmutex %p: lock at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    CMUTEX_CHECK_LOCK_VALIDITY(cmutex, CMUTEX_OP_LOCK, location);
#if 1
    /*when  lock, must __m_kind = 1*/
    if(PTHREAD_MUTEX_RECURSIVE_NP != CMUTEX_KIND(cmutex))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_lock: cmutex %p: invalid kind value %d found at %s:%ld\n", cmutex, CMUTEX_KIND(cmutex), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        CMUTEX_PRINT_LOCK_INFO(LOGSTDOUT, CMUTEX_OP_LOCK, cmutex);
        CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_lock", cmutex);
        return (EC_FALSE);
    }
#endif
    if(NULL_PTR == cmutex)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_lock: refuse to lock null cmutex, called at %s:%ld, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    if(EC_TRUE == cmutex_log_switch)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 5)(LOGSTDOUT, "cmutex_lock:lock %p at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    }

    if(1 < CMUTEX_COUNT(cmutex))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 1)(LOGSTDOUT, "warn:cmutex_lock: lock %p recursively at %s:%ld, depth = %ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location), CMUTEX_COUNT(cmutex));
        CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_lock", cmutex);
    }

    ret_val = pthread_mutex_lock(CMUTEX_MUTEX(cmutex));
    if(0 != ret_val)
    {
        switch(ret_val)
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_lock - EINVAL: cmutex NOT an initialized object, called at %s:%ld, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EDEADLK:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_lock - EDEADLK: deadlock is detected or current thread already owns the cmutex, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case ETIMEDOUT:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_lock - ETIMEDOUT: failed to lock cmutex before the specified timeout expired , called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_lock - EBUSY: failed to lock cmutex due to busy , called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_lock - UNKNOWN: error detected, errno %d, errstr %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
        return (EC_FALSE);
    }

    CMUTEX_SET_LOCATION(cmutex, CMUTEX_OP_LOCK, location);
    return (EC_TRUE);
}

EC_BOOL cmutex_unlock(CMUTEX *cmutex, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] cmutex_unlock: cmutex %p: lock at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    CMUTEX_CHECK_LOCK_VALIDITY(cmutex, CMUTEX_OP_UNLOCK, location);
#if 1
    /*when  unlock, must __m_kind = 1*/
    if(1 != CMUTEX_KIND(cmutex))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_unlock: cmutex %p: invalid kind value found at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        CMUTEX_PRINT_LOCK_INFO(LOGSTDOUT, CMUTEX_OP_UNLOCK, cmutex);
        CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_unlock", cmutex);
        return (EC_FALSE);
    }
#endif
    if(NULL_PTR == cmutex)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_unlock: refuse to unlock null cmutex, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    if(EC_TRUE == cmutex_log_switch)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 5)(LOGSTDOUT, "cmutex_unlock:unlock %p at %s:%ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    }

    if(0 == CMUTEX_COUNT(cmutex))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_unlock: lock %p found conflict at %s:%ld, depth = %ld\n", cmutex, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location), CMUTEX_COUNT(cmutex));
        CMUTEX_PRINT_LOCATION(LOGSTDOUT, "cmutex_unlock", cmutex);
    }

    ret_val = pthread_mutex_unlock(CMUTEX_MUTEX(cmutex));
    if(0 != ret_val)
    {
        switch(ret_val)
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_unlock - EINVAL: cmutex NOT an initialized object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EPERM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_unlock - EPERM: current thread does not hold a lock on cmutex, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:cmutex_unlock - UNKNOWN: error detected, errno %d, errstr %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
        return (EC_FALSE);
    }

    //CMUTEX_SET_LOCATION(cmutex, CMUTEX_OP_UNLOCK, location);
    CMUTEX_SET_LOCATION(cmutex, CMUTEX_OP_UNLOCK, LOC_NONE_BASE);
    return (EC_TRUE);
}

STATIC_CAST static void ccond_print_var(const char *info, const CCOND *ccond)
{
    const pthread_cond_t  *var;
    var = CCOND_VAR(ccond);
    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "[tid %ld] %s: ccond %p counter %ld, var: __lock = %d, __futex = %d, __total_seq = %d, __wakeup_seq = %d, __woken_seq = %d, __nwaiters =%d\n",
                        CTHREAD_GET_TID(), info, ccond, CCOND_COUNTER(ccond),
                        var->__data.__lock,
                        var->__data.__futex,
                        var->__data.__total_seq,
                        var->__data.__wakeup_seq,
                        var->__data.__woken_seq,
                        var->__data.__nwaiters
            );
    return;
}

CCOND *ccond_new(const UINT32 location)
{
    CCOND      *ccond;

    ccond = (CCOND *)SAFE_MALLOC(sizeof(CCOND), LOC_CMUTEX_0005);
    if(NULL_PTR == ccond)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_new: failed to alloc CCOND, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (NULL_PTR);
    }

    if(EC_FALSE == ccond_init(ccond, location))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_new: failed to init ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        SAFE_FREE(ccond, LOC_CMUTEX_0006);
        return (NULL_PTR);
    }

    CCOND_INIT_LOCATION(ccond);
    CCOND_SET_LOCATION(ccond, CCOND_OP_NEW, location);

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND] new %p, location %ld\n", ccond, location);
    return (ccond);
}

EC_BOOL ccond_init(CCOND *ccond, const UINT32 location)
{
    CMUTEX_ATTR mutex_attr;
    int ret_val;

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] init %p, location %ld\n", CTHREAD_GET_TID(), ccond, location);
    CCOND_SET_LOCATION(ccond, CCOND_OP_INIT, location);

    ret_val = cmutex_attr_set(&mutex_attr, CMUTEX_PROCESS_PRIVATE | CMUTEX_RECURSIVE_NP, location);
    if( 0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init: failed to set mutex attribute\n");
        return (EC_FALSE);
    }

    ret_val = pthread_cond_init(CCOND_VAR(ccond), NULL_PTR);
    if(0 != ret_val)
    {
        switch(ret_val)
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - EINVAL: cmutex NOT an initialized object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - EBUSY: failed to lock cmutex due to busy, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - UNKNOWN: error detected, errno %d, errstr %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
        return (EC_FALSE);
    }

    ret_val = pthread_mutex_init(CCOND_MUTEX(ccond), &mutex_attr);
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case EAGAIN:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - EAGAIN: System resources(other than memory) are unavailable, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EPERM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - EPERM: Doesn't have privilige to perform this operation, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - EINVAL: mutex_attr doesn't refer a valid condition variable attribute object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EFAULT:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - EFAULT: Mutex or mutex_attr is an invalid pointer, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case ENOMEM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - ENOMEM: Insufficient memory exists to initialize the mutex, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_init - UNKNOWN: Error detected when mutex init, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }

        return (EC_FALSE);
    }

    CCOND_COUNTER(ccond) = 0;

    CCOND_TERMINATE_FLAG(ccond) = BIT_FALSE;

    //pthread_mutexattr_destroy(&mutex_attr);

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] init %p, location %ld, __nwaiters %d, __kind %d\n", CTHREAD_GET_TID(), ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);

    //cmutex_print("[DEBUG][CCOND] init", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] init", ccond);
    return (EC_TRUE);
}

void ccond_free(CCOND *ccond, const UINT32 location)
{
    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] free %p, location %ld\n", CTHREAD_GET_TID(), ccond, location);
    CCOND_SET_LOCATION(ccond, CCOND_OP_FREE, location);
    ccond_clean(ccond, LOC_CMUTEX_0007);

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] free %p, location %ld, __nwaiters %d, __kind %d\n", CTHREAD_GET_TID(), ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] free", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] free", ccond);
    SAFE_FREE(ccond, LOC_CMUTEX_0008);
}

EC_BOOL ccond_clean(CCOND *ccond, const UINT32 location)
{
    int ret_val;

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] clean %p, location %ld\n", CTHREAD_GET_TID(), ccond, location);
    CCOND_SET_LOCATION(ccond, CCOND_OP_CLEAN, location);

    ret_val = pthread_mutex_destroy(CCOND_MUTEX(ccond));
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_clean - EINVAL: ccond %p mutex doesn't refer to an initialized mutex, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_clean - EBUSY: ccond %p mutex is locked or in use by another thread, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_clean - UNKNOWN: ccond %p mutex detect error, error no: %d, called at %s:%ld\n", ccond, ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
    }

    ret_val = pthread_cond_destroy(CCOND_VAR(ccond));
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_clean - EINVAL: ccond %p var doesn't refer to an initialized cond var, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_clean - EBUSY: ccond %p var is locked or in use by another thread, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_clean - UNKNOWN: ccond %p var detect error, error no: %d, called at %s:%ld\n", ccond, ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
    }

    CCOND_COUNTER(ccond) = 0;
    CCOND_TERMINATE_FLAG(ccond) = BIT_FALSE;

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] clean %p, location %ld, __nwaiters %d, __kind %d\n", CTHREAD_GET_TID(), ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] clean", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] clean", ccond);
    return (EC_TRUE);
}

EC_BOOL ccond_wait(CCOND *ccond, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] ccond_wait: ccond %p: wait at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] wait %p, location %ld\n", CTHREAD_GET_TID(), ccond, location);
    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] wait %p, location %ld, __nwaiters %d, __kind %d [1]\n", CTHREAD_GET_TID(), ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] wait[1]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] wait[1]", ccond);

#if 1
    ret_val = pthread_mutex_lock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_wait: failed to lock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }
#endif

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] wait %p, location %ld, __nwaiters %d, __kind %d [2]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] wait[2]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] wait[2]", ccond);
    CCOND_SET_LOCATION(ccond, CCOND_OP_WAIT, location);

    /*when reserved*/
    while(0 < CCOND_COUNTER(ccond))
    {
        //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] wait %p, location %ld, __nwaiters %d [3]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters);
        //cmutex_print("[DEBUG][CCOND] wait[3]", CCOND_MUTEX(ccond));
        //ccond_print_var("[DEBUG][CCOND] wait[3]", ccond);
        ret_val = pthread_cond_wait(CCOND_VAR(ccond), CCOND_MUTEX(ccond));
        if(0 != ret_val)
        {
            cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_wait: something wrong, error no: %d, error info: %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        }
    }
#if 1
    ret_val = pthread_mutex_unlock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_wait: failed to unlock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }
 #endif

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] wait %p, location %ld, __nwaiters %d, __kind %d [4]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] wait[4]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] wait[4]", ccond);
    return (EC_TRUE);
}

EC_BOOL ccond_reserve(CCOND *ccond, const UINT32 counter, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] ccond_reserve: ccond %p: reserve at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] reserve %p, location %ld, counter %ld\n", CTHREAD_GET_TID(),ccond, location, counter);
    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] reserve %p, location %ld, __nwaiters %d, __kind %d [1]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] reserve[1]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] reserve[1]", ccond);

    ret_val = pthread_mutex_lock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_reserve: failed to lock mutex of ccond %p with counter %ld, called at %s:%ld\n", ccond, counter, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    CCOND_SET_LOCATION(ccond, CCOND_OP_RESERVE, location);

    //CCOND_COUNTER(ccond) = counter;
    CCOND_COUNTER(ccond) += counter;

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] reserve %p, location %ld, __nwaiters %d, __kind %d [2]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] reserve[2]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] reserve[2]", ccond);

    ret_val = pthread_mutex_unlock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_reserve: failed to unlock mutex of ccond %p with counter %ld, called at %s:%ld\n", ccond, counter, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] reserve %p, location %ld, __nwaiters %d, __kind %d [3]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] reserve[3]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] reserve[3]", ccond);
    return (EC_TRUE);
}

EC_BOOL ccond_release(CCOND *ccond, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] ccond_release: ccond %p: release at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release %p, location %ld\n", CTHREAD_GET_TID(),ccond, location);
    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release %p, location %ld, __nwaiters %d, __kind %d [1]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release[1]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release[1]", ccond);

    ret_val = pthread_mutex_lock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_release: failed to lock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    CCOND_SET_LOCATION(ccond, CCOND_OP_RELEASE, location);

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release %p, location %ld, __nwaiters %d, __kind %d [2]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release[2]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release[2]", ccond);

    if(0 < CCOND_COUNTER(ccond))
    {
        -- CCOND_COUNTER(ccond);
    }

    if(0 == CCOND_COUNTER(ccond))
    {
        ret_val = pthread_cond_signal(CCOND_VAR(ccond));
        if(0 != ret_val)
        {
            cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_release: something wrong, error no: %d, error info: %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        }
    }

    ret_val = pthread_mutex_unlock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_release: failed to unlock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release %p, location %ld, __nwaiters %d, __kind %d [3]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release[3]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release[3]", ccond);
    return (EC_TRUE);
}

EC_BOOL ccond_release_all(CCOND *ccond, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] ccond_release_all: ccond %p: release at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld\n", CTHREAD_GET_TID(),ccond, location);
    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld, __nwaiters %d, __kind %d [1]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release_all[1]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release_all[1]", ccond);

    ret_val = pthread_mutex_lock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_release_all: failed to lock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    CCOND_SET_LOCATION(ccond, CCOND_OP_RELEASE, location);

    -- CCOND_COUNTER(ccond);

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld, __nwaiters %d, __kind %d [2]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release_all[2]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release_all[2]", ccond);

    if(0 == CCOND_COUNTER(ccond))
    {
        ret_val = pthread_cond_broadcast(CCOND_VAR(ccond));/*broadcast to all*/
        if(0 != ret_val)
        {
            cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_release_all: something wrong, error no: %d, error info: %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        }
    }

    ret_val = pthread_mutex_unlock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_release_all: failed to unlock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld, __nwaiters %d, __kind %d [3]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release_all[3]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release_all[3]", ccond);

    return (EC_TRUE);
}

EC_BOOL ccond_terminate(CCOND *ccond, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] ccond_terminate: ccond %p: release at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld\n", CTHREAD_GET_TID(),ccond, location);
    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld, __nwaiters %d, __kind %d [1]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release_all[1]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release_all[1]", ccond);

    CCOND_TERMINATE_FLAG(ccond) = BIT_TRUE;

    ret_val = pthread_mutex_lock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_terminate: failed to lock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    CCOND_SET_LOCATION(ccond, CCOND_OP_RELEASE, location);

    -- CCOND_COUNTER(ccond);

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld, __nwaiters %d, __kind %d [2]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release_all[2]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release_all[2]", ccond);

    if(0 == CCOND_COUNTER(ccond))
    {
        ret_val = pthread_cond_broadcast(CCOND_VAR(ccond));/*broadcast to all*/
        if(0 != ret_val)
        {
            cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_terminate: something wrong, error no: %d, error info: %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        }
    }

    ret_val = pthread_mutex_unlock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_terminate: failed to unlock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND][tid %ld] release_all %p, location %ld, __nwaiters %d, __kind %d [3]\n", CTHREAD_GET_TID(),ccond, location, ccond->var.__data.__nwaiters, CCOND_MUTEX(ccond)->__data.__kind);
    //cmutex_print("[DEBUG][CCOND] release_all[3]", CCOND_MUTEX(ccond));
    //ccond_print_var("[DEBUG][CCOND] release_all[3]", ccond);

    return (EC_TRUE);
}

/*spy on the current times*/
UINT32 ccond_spy(CCOND *ccond, const UINT32 location)
{
    UINT32 times;
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] ccond_spy: ccond %p: spy at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND] spy %p, location %ld\n", ccond, location);

    ret_val = pthread_mutex_lock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_spy: failed to lock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (ERR_CCOND_TIMES);
    }

    times = CCOND_COUNTER(ccond);

    ret_val = pthread_mutex_unlock(CCOND_MUTEX(ccond));
    if(0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:ccond_spy: failed to unlock mutex of ccond %p, called at %s:%ld\n", ccond, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (ERR_CCOND_TIMES);
    }

    //sys_log(LOGSTDOUT, "[DEBUG][CCOND] spy %p, location %ld, __nwaiters %d\n", ccond, location, ccond->var.__data.__nwaiters);
    return (times);
}

EC_BOOL cmutex_node_init(CMUTEX_NODE *cmutex_node)
{
    CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node) = NULL_PTR;
    CMUTEX_NODE_USED_FLAG(cmutex_node) = CMUTEX_NODE_IS_NOT_USED;
    return (EC_TRUE);
}

EC_BOOL cmutex_node_clean(CMUTEX_NODE *cmutex_node)
{
    CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node) = NULL_PTR;
    CMUTEX_NODE_USED_FLAG(cmutex_node) = CMUTEX_NODE_IS_NOT_USED;
    return (EC_TRUE);
}

void cmutex_node_print(LOG *log, CMUTEX_NODE *cmutex_node)
{
    sys_print(log, "cmutex %p, owner %ld\n",
                    CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node),
                    CMUTEX_OWNER((CMUTEX *)CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node)));
    return;
}

EC_BOOL cmutex_bucket_init(CMUTEX_BUCKET *cmutex_bucket)
{
    UINT32 cmutex_node_idx;

    SPINLOCK_INIT(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));

    for(cmutex_node_idx = 0; cmutex_node_idx < CMUTEX_NODE_MAX_NUM; cmutex_node_idx ++)
    {
        CMUTEX_NODE *cmutex_node;
        cmutex_node = CMUTEX_BUCKET_NODE(cmutex_bucket, cmutex_node_idx);
        cmutex_node_init(cmutex_node);
    }
    return (EC_TRUE);
}

EC_BOOL cmutex_bucket_clean(CMUTEX_BUCKET *cmutex_bucket)
{
    UINT32 cmutex_node_idx;

    for(cmutex_node_idx = 0; cmutex_node_idx < CMUTEX_NODE_MAX_NUM; cmutex_node_idx ++)
    {
        CMUTEX_NODE *cmutex_node;
        cmutex_node = CMUTEX_BUCKET_NODE(cmutex_bucket, cmutex_node_idx);
        cmutex_node_clean(cmutex_node);
    }

    SPINLOCK_CLEAN(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));
    return (EC_TRUE);
}

EC_BOOL cmutex_bucket_add(CMUTEX_BUCKET *cmutex_bucket, CMUTEX *cmutex)
{
    UINT32 cmutex_node_idx;

    SPINLOCK_LOCK(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));
    for(cmutex_node_idx = 0; cmutex_node_idx < CMUTEX_NODE_MAX_NUM; cmutex_node_idx ++)
    {
        CMUTEX_NODE *cmutex_node;
        cmutex_node = CMUTEX_BUCKET_NODE(cmutex_bucket, cmutex_node_idx);

        if(CMUTEX_NODE_IS_NOT_USED == CMUTEX_NODE_USED_FLAG(cmutex_node))
        {
            CMUTEX_NODE_USED_FLAG(cmutex_node) = CMUTEX_NODE_IS_USED;
            CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node)  = cmutex;
            CMUTEX_RECORD_NODE(cmutex) = cmutex_node;

            SPINLOCK_UNLOCK(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));
            return (EC_TRUE);
        }
    }
    SPINLOCK_UNLOCK(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));
    return (EC_FALSE);
}

void cmutex_bucket_print(LOG *log, CMUTEX_BUCKET *cmutex_bucket)
{
    UINT32 cmutex_node_idx;

    SPINLOCK_LOCK(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));
    for(cmutex_node_idx = 0; cmutex_node_idx < CMUTEX_NODE_MAX_NUM; cmutex_node_idx ++)
    {
        CMUTEX_NODE *cmutex_node;
        cmutex_node = CMUTEX_BUCKET_NODE(cmutex_bucket, cmutex_node_idx);
        if(CMUTEX_NODE_IS_USED == CMUTEX_NODE_USED_FLAG(cmutex_node))
        {
            sys_print(log, "\t %8ld# ");
            cmutex_node_print(log, cmutex_node);
        }
    }
    SPINLOCK_UNLOCK(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));
    return;
}

EC_BOOL cmutex_pool_init(CMUTEX_POOL *cmutex_pool)
{
    UINT32 cmutex_bucket_idx;

    for(cmutex_bucket_idx = 0; cmutex_bucket_idx < CMUTEX_BUCKET_MAX_NUM; cmutex_bucket_idx ++)
    {
        CMUTEX_BUCKET *cmutex_bucket;
        cmutex_bucket = CMUTEX_POOL_BUCKET_BY_IDX(cmutex_pool, cmutex_bucket_idx);
        cmutex_bucket_init(cmutex_bucket);
    }
    return (EC_TRUE);
}

EC_BOOL cmutex_pool_clean(CMUTEX_POOL *cmutex_pool)
{
    UINT32 cmutex_bucket_idx;

    for(cmutex_bucket_idx = 0; cmutex_bucket_idx < CMUTEX_BUCKET_MAX_NUM; cmutex_bucket_idx ++)
    {
        CMUTEX_BUCKET *cmutex_bucket;
        cmutex_bucket = CMUTEX_POOL_BUCKET_BY_IDX(cmutex_pool, cmutex_bucket_idx);
        cmutex_bucket_clean(cmutex_bucket);
    }
    return (EC_TRUE);
}

EC_BOOL cmutex_pool_add(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex)
{
    CMUTEX_BUCKET *cmutex_bucket;

    cmutex_bucket = CMUTEX_POOL_BUCKET_BY_OWNER(cmutex_pool, CMUTEX_OWNER(cmutex));
    return cmutex_bucket_add(cmutex_bucket, cmutex);
}

EC_BOOL cmutex_pool_rmv(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex)
{
    CMUTEX_NODE *cmutex_node;

    cmutex_node = CMUTEX_RECORD_NODE(cmutex);
    if(NULL_PTR != cmutex_node)
    {
        cmutex_node_clean(cmutex_node);
        CMUTEX_RECORD_NODE(cmutex) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cmutex_pool_reset_one(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex)
{
    cmutex_pool_rmv(cmutex_pool, cmutex);
    CMUTEX_RESET(cmutex, CMUTEX_PROCESS_PRIVATE);/*not change the init location info*/
    return (EC_TRUE);
}

EC_BOOL cmutex_pool_reset_all(CMUTEX_POOL *cmutex_pool, const UINT32 old_owner)
{
    CMUTEX_BUCKET *cmutex_bucket;
    UINT32 cmutex_node_idx;

    cmutex_bucket = CMUTEX_POOL_BUCKET_BY_OWNER(cmutex_pool, old_owner);
    SPINLOCK_LOCK(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));

    for(cmutex_node_idx = 0; cmutex_node_idx < CMUTEX_NODE_MAX_NUM; cmutex_node_idx ++)
    {
        CMUTEX_NODE *cmutex_node;
        cmutex_node = CMUTEX_BUCKET_NODE(cmutex_bucket, cmutex_node_idx);

        if(CMUTEX_NODE_IS_USED == CMUTEX_NODE_USED_FLAG(cmutex_node) && old_owner == CMUTEX_OWNER((CMUTEX *)CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node)))
        {
            CMUTEX *cmutex;
            cmutex = (CMUTEX *)CMUTEX_NODE_RECORDED_CMUTEX(cmutex_node);

            cmutex_node_clean(cmutex_node);
            CMUTEX_RECORD_NODE(cmutex) = NULL_PTR;

            CMUTEX_RESET(cmutex, CMUTEX_PROCESS_PRIVATE); /*not change the init location info*/
        }
    }
    SPINLOCK_UNLOCK(CMUTEX_BUCKET_SPINLOCK(cmutex_bucket));
    return (EC_TRUE);
}

void cmutex_pool_print(LOG *log, CMUTEX_POOL *cmutex_pool)
{
    UINT32 cmutex_bucket_idx;

    for(cmutex_bucket_idx = 0; cmutex_bucket_idx < CMUTEX_BUCKET_MAX_NUM; cmutex_bucket_idx ++)
    {
        CMUTEX_BUCKET *cmutex_bucket;
        cmutex_bucket = CMUTEX_POOL_BUCKET_BY_IDX(cmutex_pool, cmutex_bucket_idx);
        cmutex_bucket_print(log, cmutex_bucket);
    }
    return;
}

CMUTEX_POOL *cmutex_pool_default_get()
{
    return (&g_cmutex_pool);
}

EC_BOOL crwlock_attr_set(CRWLOCK_ATTR  *rwlock_attr, const UINT32 flag, const UINT32 location)
{
    int ret_val;

    ret_val = pthread_rwlockattr_init(rwlock_attr);
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case ENOMEM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_attr_set - ENOMEM: Insufficient memory to create the rwlock attributes object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_attr_set - EINVAL: value specified for argument -pshared- is INCORRECT, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_attr_set - UNKNOWN: Error detected when rwlockattr init, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }

        return (ret_val);
    }

    if(CRWLOCK_PROCESS_PRIVATE == flag)
    {
        ret_val = pthread_rwlockattr_setpshared(rwlock_attr, PTHREAD_PROCESS_PRIVATE);
        if( 0 != ret_val )
        {
            switch( ret_val )
            {
                case EINVAL:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_attr_set - EINVAL: value specified for argument -pshared- is INCORRECT, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }

                default:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_attr_set - UNKNOWN: error detected when setpshared, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }
            }

            return (ret_val);
        }
    }

    if(CRWLOCK_PROCESS_SHARED == flag)
    {
        ret_val = pthread_rwlockattr_setpshared(rwlock_attr, PTHREAD_PROCESS_SHARED);
        if( 0 != ret_val )
        {
            switch( ret_val )
            {
                case EINVAL:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_attr_set - EINVAL: value specified for argument -pshared- is INCORRECT, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }

                default:
                {
                    cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_attr_set - UNKNOWN: error detected when setpshared, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                    break;
                }
            }

            return (ret_val);
        }
    }

    return (ret_val);

}

CRWLOCK *crwlock_new(const UINT32 flag, const UINT32 location)
{
    CRWLOCK      *crwlock;

    crwlock = (CRWLOCK *)SAFE_MALLOC(sizeof(CRWLOCK), LOC_CMUTEX_0009);
    if(NULL_PTR == crwlock)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_new: failed to alloc CRWLOCK, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (NULL_PTR);
    }

    if(EC_FALSE == crwlock_init(crwlock, flag, location))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_init: failed to init crwlock %p, called at %s:%ld\n", crwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        SAFE_FREE(crwlock, LOC_CMUTEX_0010);
        return (NULL_PTR);
    }

    CRWLOCK_INIT_LOCATION(crwlock);
    CRWLOCK_SET_LOCATION(crwlock, CRWLOCK_OP_NEW, location);

    CRWLOCK_CHECK_LOCK_VALIDITY(crwlock, CRWLOCK_OP_NEW, location);

    return (crwlock);
}

EC_BOOL crwlock_init(CRWLOCK *crwlock, const UINT32 flag, const UINT32 location)
{
    CRWLOCK_ATTR  rwlock_attr;
    int ret_val;

    //CRWLOCK_CHECK_LOCK_VALIDITY(crwlock, CRWLOCK_OP_INIT, location);

    CRWLOCK_SET_LOCATION(crwlock, CRWLOCK_OP_INIT, location);

    ret_val = crwlock_attr_set(&rwlock_attr, flag, location);
    if( 0 != ret_val)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_init: failed to set rwlock attribute\n");
        return (EC_FALSE);
    }

    /* Creating and Initializing the rwlock with the above stated rwlock attributes */
    ret_val = pthread_rwlock_init(CRWLOCK_RWLOCK(crwlock), &rwlock_attr);
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case EAGAIN:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_new - EAGAIN: System resources(other than memory) are unavailable, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EPERM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_new - EPERM: Doesn't have privilige to perform this operation, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_new - EINVAL: rwlock_attr doesn't refer a valid condition variable attribute object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_new - EBUSY: The implementation has detected an attempt to destroy the object referenced by rwlock while it is locked., called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case ENOMEM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_new - ENOMEM: Insufficient memory exists to initialize the rwlock, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_new - UNKNOWN: Error detected when rwlock init, error no: %d, called at %s:%ld\n", ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }

        return (EC_FALSE);
    }

    //crwlock_pool_add(crwlock_pool_default_get(), crwlock);
    return (EC_TRUE);
}

void crwlock_free(CRWLOCK *crwlock, const UINT32 location)
{
    CRWLOCK_CHECK_LOCK_VALIDITY(crwlock, CRWLOCK_OP_FREE, location);

    CRWLOCK_SET_LOCATION(crwlock, CRWLOCK_OP_FREE, location);
    crwlock_clean(crwlock, LOC_CMUTEX_0011);
    SAFE_FREE(crwlock, LOC_CMUTEX_0012);
}

void crwlock_clean(CRWLOCK *crwlock, const UINT32 location)
{
    int ret_val;

    CRWLOCK_CHECK_LOCK_VALIDITY(crwlock, CRWLOCK_OP_CLEAN, location);

    /*when clean, must __m_reserved = 0*/
    if(0 != CRWLOCK_NR_READER(crwlock) || 0 != CRWLOCK_NR_READER_QUEUED(crwlock) || 0 != CRWLOCK_NR_WRITER_QUEUED(crwlock))
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_clean: crwlock %p:invalid status found at %s:%ld\n", crwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        CRWLOCK_PRINT_LOCK_INFO(LOGSTDOUT, CRWLOCK_OP_CLEAN, crwlock);
        return;
    }

    CRWLOCK_SET_LOCATION(crwlock, CRWLOCK_OP_CLEAN, location);

    ret_val = pthread_rwlock_destroy(CRWLOCK_RWLOCK(crwlock));
    if( 0 != ret_val )
    {
        switch( ret_val )
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_clean - EINVAL: crwlock %p doesn't refer to an initialized rwlock, called at %s:%ld\n", crwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_clean - EBUSY: crwlock %p is locked or in use by another thread, called at %s:%ld\n", crwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EAGAIN:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_clean - EAGAIN: System resources(other than memory) are unavailable, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EPERM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_clean - EPERM: Doesn't have privilige to perform this operation, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case ENOMEM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_clean - ENOMEM: Insufficient memory exists to initialize the rwlock, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                /* Unknown error */
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_clean - UNKNOWN: crwlock %p detect error, error no: %d, called at %s:%ld\n", crwlock, ret_val, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
        CRWLOCK_PRINT_LOCATION(LOGSTDOUT, "crwlock_clean", crwlock);
    }

    //crwlock_pool_rmv(crwlock_pool_default_get(), crwlock);
    return;
}

EC_BOOL crwlock_rdlock(CRWLOCK *crwlock, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] crwlock_rdlock: crwlock %p: rdlock at %s:%ld\n", crwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    CRWLOCK_CHECK_LOCK_VALIDITY(crwlock, CRWLOCK_OP_RDLOCK, location);

    if(NULL_PTR == crwlock)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_rdlock: refuse to lock null crwlock, called at %s:%ld, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    ret_val = pthread_rwlock_rdlock(CRWLOCK_RWLOCK(crwlock));
    if(0 != ret_val)
    {
        switch(ret_val)
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_rdlock - EINVAL: crwlock NOT an initialized object, called at %s:%ld, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EDEADLK:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_rdlock - EDEADLK: deadlock is detected or current thread already owns the crwlock, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EAGAIN:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_rdlock - EAGAIN: The read lock could not be acquired because the maximum number of read locks for rwlock has been exceeded, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_rdlock - EBUSY: failed to lock crwlock due to busy , called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_rdlock - UNKNOWN: error detected, errno %d, errstr %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
        CRWLOCK_PRINT_LOCATION(LOGSTDOUT, "crwlock_rdlock", crwlock);
        return (EC_FALSE);
    }

    CRWLOCK_SET_LOCATION(crwlock, CRWLOCK_OP_RDLOCK, location);
    return (EC_TRUE);
}

EC_BOOL crwlock_wrlock(CRWLOCK *crwlock, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] crwlock_wrlock: crwlock %p: wrlock at %s:%ld\n", crwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

    CRWLOCK_CHECK_LOCK_VALIDITY(crwlock, CRWLOCK_OP_WRLOCK, location);

    if(NULL_PTR == crwlock)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_wrlock: refuse to lock null crwlock, called at %s:%ld, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    ret_val = pthread_rwlock_wrlock(CRWLOCK_RWLOCK(crwlock));
    if(0 != ret_val)
    {
        switch(ret_val)
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_wrlock - EINVAL: crwlock NOT an initialized object, called at %s:%ld, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EDEADLK:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_wrlock - EDEADLK: deadlock is detected or current thread already owns the crwlock, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EBUSY:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_wrlock - EBUSY: failed to lock crwlock due to busy , called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_wrlock - UNKNOWN: error detected, errno %d, errstr %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }

        CRWLOCK_PRINT_LOCATION(LOGSTDOUT, "crwlock_wrlock", crwlock);
        return (EC_FALSE);
    }

    CRWLOCK_SET_LOCATION(crwlock, CRWLOCK_OP_WRLOCK, location);
    return (EC_TRUE);
}

EC_BOOL crwlock_unlock(CRWLOCK *crwlock, const UINT32 location)
{
    int ret_val;

    cmutex_dbg_log(SEC_0083_CMUTEX, 9)(LOGSTDOUT, "[DEBUG] crwlock_unlock: crwlock %p: unlock at %s:%ld\n", crwlock, MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    CRWLOCK_CHECK_LOCK_VALIDITY(crwlock, CRWLOCK_OP_UNLOCK, location);

    if(NULL_PTR == crwlock)
    {
        cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_unlock: refuse to unlock null crwlock, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    ret_val = pthread_rwlock_unlock(CRWLOCK_RWLOCK(crwlock));
    if(0 != ret_val)
    {
        switch(ret_val)
        {
            case EINVAL:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_unlock - EINVAL: crwlock NOT an initialized object, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            case EPERM:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_unlock - EPERM: current thread does not hold a lock on crwlock, called at %s:%ld\n", MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }

            default:
            {
                cmutex_dbg_log(SEC_0083_CMUTEX, 0)(LOGSTDOUT, "error:crwlock_unlock - UNKNOWN: error detected, errno %d, errstr %s, called at %s:%ld\n", ret_val, strerror(ret_val), MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
                break;
            }
        }
        CRWLOCK_PRINT_LOCATION(LOGSTDOUT, "crwlock_unlock", crwlock);
        return (EC_FALSE);
    }

    CRWLOCK_SET_LOCATION(crwlock, CRWLOCK_OP_UNLOCK, location);
    return (EC_TRUE);
}

#endif/*(SWITCH_OFF == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/

#if (SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)
CMUTEX *cmutex_new(const UINT32 flag, const UINT32 location)
{
    return (NULL_PTR);
}

void    cmutex_free(CMUTEX *cmutex, const UINT32 location)
{
    return;
}

EC_BOOL cmutex_init(CMUTEX *cmutex, const UINT32 flag, const UINT32 location)
{
    return (EC_FALSE);
}

void    cmutex_clean(CMUTEX *cmutex, const UINT32 location)
{
    return;
}

EC_BOOL cmutex_lock(CMUTEX *cmutex, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_unlock(CMUTEX *cmutex, const UINT32 location)
{
    return (EC_FALSE);
}


CCOND  *ccond_new(const UINT32 location)
{
    return (NULL_PTR);
}

EC_BOOL ccond_init(CCOND *ccond, const UINT32 location)
{
    return (EC_FALSE);
}

void    ccond_free(CCOND *ccond, const UINT32 location)
{
    return;
}

EC_BOOL ccond_clean(CCOND *ccond, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL ccond_wait(CCOND *ccond, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL ccond_reserve(CCOND *ccond, const UINT32 counter, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL ccond_release(CCOND *ccond, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL ccond_release_all(CCOND *ccond, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL ccond_terminate(CCOND *ccond, const UINT32 location)
{
    return (EC_FALSE);
}

/*spy on the current times*/
UINT32  ccond_spy(CCOND *ccond, const UINT32 location)
{
    return ((UINT32)~0);
}


EC_BOOL cmutex_node_init(CMUTEX_NODE *cmutex_node)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_node_clean(CMUTEX_NODE *cmutex_node)
{
    return (EC_FALSE);
}

void    cmutex_node_print(LOG *log, CMUTEX_NODE *cmutex_node)
{
    return;
}

EC_BOOL cmutex_bucket_init(CMUTEX_BUCKET *cmutex_bucket)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_bucket_clean(CMUTEX_BUCKET *cmutex_bucket)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_bucket_add(CMUTEX_BUCKET *cmutex_bucket, CMUTEX *cmutex)
{
    return (EC_FALSE);
}

void    cmutex_bucket_print(LOG *log, CMUTEX_BUCKET *cmutex_bucket)
{
    return;
}

EC_BOOL cmutex_pool_init(CMUTEX_POOL *cmutex_pool)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_pool_clean(CMUTEX_POOL *cmutex_pool)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_pool_add(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_pool_rmv(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_pool_reset_one(CMUTEX_POOL *cmutex_pool, CMUTEX *cmutex)
{
    return (EC_FALSE);
}

EC_BOOL cmutex_pool_reset_all(CMUTEX_POOL *cmutex_pool, const UINT32 old_owner)
{
    return (EC_FALSE);
}

void    cmutex_pool_print(LOG *log, CMUTEX_POOL *cmutex_pool)
{
    return;
}

CMUTEX_POOL *cmutex_pool_default_get()
{
    return (NULL_PTR);
}

CRWLOCK *crwlock_new(const UINT32 flag, const UINT32 location)
{
    return (NULL_PTR);
}

EC_BOOL crwlock_init(CRWLOCK *crwlock, const UINT32 flag, const UINT32 location)
{
    return (EC_FALSE);
}

void    crwlock_free(CRWLOCK *crwlock, const UINT32 location)
{
    return;
}

void    crwlock_clean(CRWLOCK *crwlock, const UINT32 location)
{
    return;
}

EC_BOOL crwlock_rdlock(CRWLOCK *crwlock, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL crwlock_wrlock(CRWLOCK *crwlock, const UINT32 location)
{
    return (EC_FALSE);
}

EC_BOOL crwlock_unlock(CRWLOCK *crwlock, const UINT32 location)
{
    return (EC_FALSE);
}

#endif/*(SWITCH_ON == CROUTINE_SUPPORT_SINGLE_CTHREAD_SWITCH)*/


#ifdef __cplusplus
}
#endif/*__cplusplus*/

