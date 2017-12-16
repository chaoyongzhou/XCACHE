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

#ifndef _CSEM_H
#define _CSEM_H

#include <semaphore.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"


//typedef sem_t CSEM;
typedef struct
{
    sem_t      *sem;
    CSTRING    *name;
}CSEM;

#define CSEM_SEM(csem)          (csem->sem)
#define CSEM_NAME_CSTR(csem)    (csem->name)

/**
*
* if pshared = 0, share semaphore in threads of a process
* if pshared != 0, share semaphore in processes
*
**/
#define CSEM_THREAD_SHARED      ((int) 0)
#define CSEM_PROCESS_SHARED     ((int) 1)

/*initialises the unnamed semaphore*/
EC_BOOL csem_unamed_init(CSEM *csem, const int pshared, const uint32_t value, const UINT32 location);

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_unamed_lock(CSEM *csem, const UINT32 location);

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_unamed_trylock(CSEM *csem, const UINT32 location);

/*increments  (unlocks/post)  the semaphore*/
EC_BOOL csem_unamed_unlock(CSEM *csem, const UINT32 location);

/*destroys the unnamed semaphore*/
EC_BOOL csem_unamed_clean(CSEM *csem, const UINT32 location);

CSEM *  csem_named_new(const uint8_t *name, const UINT32 location);
EC_BOOL csem_named_init(CSEM  *csem, const uint8_t *name, const UINT32 location);
EC_BOOL csem_named_clean(CSEM *csem, const UINT32 location);
EC_BOOL csem_named_free(CSEM *csem, const UINT32 location);

/*for named semaphore: creates  a  new  POSIX  semaphore  or  opens  an existing semaphore.*/
EC_BOOL csem_named_open(CSEM *csem, const uint8_t *name, const int oflag, const mode_t mode, const uint32_t value, const UINT32 location);

/*closes  the  named  semaphore*/
EC_BOOL csem_named_close(CSEM *csem, const UINT32 location);

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_named_lock(CSEM *csem, const UINT32 location);

/*decrements  (locks)  the  semaphore*/
EC_BOOL csem_named_trylock(CSEM *csem, const UINT32 location);

/*increments  (unlocks/post)  the semaphore*/
EC_BOOL csem_named_unlock(CSEM *csem, const UINT32 location);

/*removes  the named semaphore*/
EC_BOOL csem_named_unlink(const uint8_t *name, const UINT32 location);

#endif/* _CSEM_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
