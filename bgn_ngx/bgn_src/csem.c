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

#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <semaphore.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmpic.inc"

#include "csem.h"


/*initialises the unnamed semaphore*/
EC_BOOL csem_unamed_init(CSEM *csem, const int pshared, const uint32_t value, const UINT32 location)
{
    if(0 == sem_init(CSEM_SEM(csem), pshared, value))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_unamed_init: csem %p pshared %d value %u failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem, pshared, value,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_unamed_lock(CSEM *csem, const UINT32 location)
{
    if(0 == sem_wait(CSEM_SEM(csem)))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_unamed_lock: unlock csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_unamed_trylock(CSEM *csem, const UINT32 location)
{
    if(0 == sem_trywait(CSEM_SEM(csem)))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_unamed_trylock: unlock csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

/*increments  (unlocks/post)  the semaphore*/
EC_BOOL csem_unamed_unlock(CSEM *csem, const UINT32 location)
{
    if(0 == sem_post(CSEM_SEM(csem)))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_unamed_unlock: lock csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}


/*destroys the unnamed semaphore*/
EC_BOOL csem_unamed_clean(CSEM *csem, const UINT32 location)
{
    if(0 == sem_destroy(CSEM_SEM(csem)))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_unamed_clean: clean csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

CSEM *csem_named_new(const uint8_t *name, const UINT32 location)
{
    CSEM  *csem;

    alloc_static_mem(MM_CSEM, &csem, location);
    if(NULL_PTR == csem)
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_new: new csem failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csem_named_init(csem, name, location))
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_new: init csem %p with name %s failed\n", csem, name);
        free_static_mem(MM_CSEM, csem, location);
        return (NULL_PTR);
    }

    return (csem);
}

EC_BOOL csem_named_init(CSEM  *csem, const uint8_t *name, const UINT32 location)
{
    CSEM_SEM(csem) = SEM_FAILED;

    if(NULL_PTR == name)
    {
        CSEM_NAME_CSTR(csem) = NULL_PTR;
        return (EC_TRUE);
    }

    CSEM_NAME_CSTR(csem) = cstring_new(name, location);
    if(NULL_PTR == CSEM_NAME_CSTR(csem))
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_init: new cstring for csem %p failed\n", csem);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csem_named_clean(CSEM *csem, const UINT32 location)
{
    uint8_t *sem_name;

    /*close*/
    if(EC_FALSE == csem_named_close(csem, location))
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_clean: close csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                           csem,
                           errno, strerror(errno),
                           MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    if(NULL_PTR == CSEM_NAME_CSTR(csem))
    {
        return (EC_TRUE);
    }

    /*unlink*/
    sem_name = cstring_get_str(CSEM_NAME_CSTR(csem));
    if(EC_FALSE == csem_named_unlink(sem_name, location))
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_clean: unlink sem %s failed where errno = %d, errstr = %s at %s:%ld\n",
                           sem_name,
                           errno, strerror(errno),
                           MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    cstring_free(CSEM_NAME_CSTR(csem));
    CSEM_NAME_CSTR(csem) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL csem_named_free(CSEM *csem, const UINT32 location)
{
    if(NULL_PTR != csem)
    {
        csem_named_clean(csem, location);
        free_static_mem(MM_CSEM, csem, location);
    }
    return (EC_TRUE);
}

/*for named semaphore: creates  a  new  POSIX  semaphore  or  opens  an existing semaphore.*/
EC_BOOL csem_named_open(CSEM *csem, const uint8_t *name, const int oflag, const mode_t mode, const uint32_t value, const UINT32 location)
{
    sem_t  *sem;

    if(NULL_PTR != CSEM_NAME_CSTR(csem))
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_open: csem %p has already set name %s at %s:%ld\n",
                           csem, cstring_get_str(CSEM_NAME_CSTR(csem)),
                           MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    CSEM_NAME_CSTR(csem) = cstring_new(name, location);
    if(NULL_PTR == CSEM_NAME_CSTR(csem))
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_open: new cstring for csem %p failed where name %s\n", csem, name);
        return (EC_FALSE);
    }

    sem = sem_open((const char *)name, oflag, mode, value);
    if(SEM_FAILED == sem)
    {
        dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_open: open sem of %s oflag %d mode_t %o value %u failed where errno = %d, errstr = %s at %s:%ld\n",
                           name, oflag, mode, value,
                           errno, strerror(errno),
                           MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
        return (EC_FALSE);
    }

    CSEM_SEM(csem) = sem;
    return (EC_TRUE);
}

/*closes  the  named  semaphore*/
EC_BOOL csem_named_close(CSEM *csem, const UINT32 location)
{
    if(0 == sem_close(CSEM_SEM(csem)))
    {
        CSEM_SEM(csem) = SEM_FAILED;
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_close: close csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_named_lock(CSEM *csem, const UINT32 location)
{
    if(0 == sem_wait(CSEM_SEM(csem)))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_lock: unlock csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_named_trylock(CSEM *csem, const UINT32 location)
{
    if(0 == sem_trywait(CSEM_SEM(csem)))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_trylock: unlock csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

/*increments  (unlocks/post)  the semaphore*/
EC_BOOL csem_named_unlock(CSEM *csem, const UINT32 location)
{
    if(0 == sem_post(CSEM_SEM(csem)))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_unlock: lock csem %p failed where errno = %d, errstr = %s at %s:%ld\n",
                       csem,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

/*removes  the named semaphore*/
EC_BOOL csem_named_unlink(const uint8_t *name, const UINT32 location)
{
    if(NULL_PTR == name)
    {
        dbg_log(SEC_0029_CSEM, 1)(LOGSTDOUT, "warn:csem_named_unlink: unlink sem name is null at %s:%ld\n",
                           MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));

        return (EC_TRUE);
    }

    if(0 == sem_unlink((char *)name))
    {
        return (EC_TRUE);
    }
    dbg_log(SEC_0029_CSEM, 0)(LOGSTDOUT, "error:csem_named_unlink: unlink sem %s failed where errno = %d, errstr = %s at %s:%ld\n",
                       name,
                       errno, strerror(errno),
                       MM_LOC_FILE_NAME(location), MM_LOC_LINE_NO(location));
    return (EC_FALSE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

