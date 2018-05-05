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

#ifndef _CRFSMC_INC
#define _CRFSMC_INC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"

#include "chashalgo.h"
#include "crfsnp.inc"
#include "cpgd.h"
#include "crfsmclist.h"

#define CRFSMC_NP_ID     ((uint32_t) 0x1000)
#define CRFSMC_DISK_NO   ((uint32_t) 0x2000)

#define CRFSMC_ROOM_SAFE_LEVEL   ((REAL) 0.80) /*80%*/

#define CRFSMC_RECYCLE_MAX_NUM   ((UINT32)~0)

typedef struct
{
    UINT32             crfs_md_id;
    CRFSNP            *crfsnp; /*np in mem cache       */
    CPGD              *cpgd;   /*page disk in mem cache*/
    CRFSMCLIST        *mclist; /*mem NP item list: LRU */

    uint8_t           *mcache; /*mem cache*/

    CROUTINE_RWLOCK    crwlock;
}CRFSMC;

#define CRFSMC_CRFS_MD_ID(crfsmc)  ((crfsmc)->crfs_md_id)
#define CRFSMC_NP(crfsmc)          ((crfsmc)->crfsnp)
#define CRFSMC_PGD(crfsmc)         ((crfsmc)->cpgd)
#define CRFSMC_LIST(crfsmc)        ((crfsmc)->mclist)
#define CRFSMC_MCACHE(crfsmc)      ((crfsmc)->mcache)
#define CRFSMC_CRWLOCK(crfsmc)     (&((crfsmc)->crwlock))

#define CRFSMC_INIT_LOCK(crfsmc, location)  (croutine_rwlock_init(CRFSMC_CRWLOCK(crfsmc), CMUTEX_PROCESS_PRIVATE, location))
#define CRFSMC_CLEAN_LOCK(crfsmc, location) (croutine_rwlock_clean(CRFSMC_CRWLOCK(crfsmc), location))

#define CRFSMC_RDLOCK(crfsmc, location)     (croutine_rwlock_rdlock(CRFSMC_CRWLOCK(crfsmc), location))
#define CRFSMC_WRLOCK(crfsmc, location)     (croutine_rwlock_wrlock(CRFSMC_CRWLOCK(crfsmc), location))
#define CRFSMC_UNLOCK(crfsmc, location)     (croutine_rwlock_unlock(CRFSMC_CRWLOCK(crfsmc), location))

#endif/* _CRFSMC_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

