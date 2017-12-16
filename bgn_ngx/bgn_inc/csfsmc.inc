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

#ifndef _CSFSMC_INC
#define _CSFSMC_INC

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
#include "csfsnp.h"
#include "cpgd.h"
#include "csfsmclist.h"
#include "croutine.h"

#define CSFSMC_NP_ID     ((uint32_t) 0x1000)
#define CSFSMC_DISK_NO   ((uint32_t) 0x2000)

#define CSFSMC_ROOM_SAFE_LEVEL   ((REAL) 0.80) /*80%*/

#define CSFSMC_RECYCLE_MAX_NUM   ((UINT32)~0)

typedef struct
{
    UINT32             csfs_md_id;
    CSFSNP            *csfsnp; /*np in mem cache       */
    CPGD              *cpgd;   /*page disk in mem cache*/
    CSFSMCLIST        *mclist; /*mem NP item list: LRU */

    uint8_t           *mcache; /*mem cache*/

    CROUTINE_RWLOCK    crwlock;
}CSFSMC;

#define CSFSMC_CSFS_MD_ID(csfsmc)  ((csfsmc)->csfs_md_id)
#define CSFSMC_NP(csfsmc)          ((csfsmc)->csfsnp)
#define CSFSMC_PGD(csfsmc)         ((csfsmc)->cpgd)
#define CSFSMC_LIST(csfsmc)        ((csfsmc)->mclist)
#define CSFSMC_MCACHE(csfsmc)      ((csfsmc)->mcache)
#define CSFSMC_CRWLOCK(csfsmc)     (&((csfsmc)->crwlock))

#define CSFSMC_INIT_LOCK(csfsmc, location)  (croutine_rwlock_init(CSFSMC_CRWLOCK(csfsmc), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSMC_CLEAN_LOCK(csfsmc, location) (croutine_rwlock_clean(CSFSMC_CRWLOCK(csfsmc), location))

#if 0
#define CSFSMC_RDLOCK(csfsmc, location)     (croutine_rwlock_rdlock(CSFSMC_CRWLOCK(csfsmc), location))
#define CSFSMC_WRLOCK(csfsmc, location)     (croutine_rwlock_wrlock(CSFSMC_CRWLOCK(csfsmc), location))
#define CSFSMC_UNLOCK(csfsmc, location)     (croutine_rwlock_unlock(CSFSMC_CRWLOCK(csfsmc), location))
#endif

#if 1
#define CSFSMC_RDLOCK(csfsmc, location)     do{}while(0)
#define CSFSMC_WRLOCK(csfsmc, location)     do{}while(0)
#define CSFSMC_UNLOCK(csfsmc, location)     do{}while(0)
#endif


#endif/* _CSFSMC_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

