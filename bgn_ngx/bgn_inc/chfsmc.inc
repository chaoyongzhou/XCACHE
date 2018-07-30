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

#ifndef _CHFSMC_INC
#define _CHFSMC_INC

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
#include "chfsnp.h"
#include "cpgd.h"
#include "chfsmclist.h"
#include "croutine.h"

#define CHFSMC_NP_ID     ((uint32_t) 0x1000)
#define CHFSMC_DISK_NO   ((uint32_t) 0x2000)

#define CHFSMC_ROOM_SAFE_LEVEL   ((REAL) 0.80) /*80%*/

#define CHFSMC_RECYCLE_MAX_NUM   ((UINT32)~0)

typedef struct
{
    UINT32             chfs_md_id;
    CHFSNP            *chfsnp; /*np in mem cache       */
    CPGD              *cpgd;   /*page disk in mem cache*/
    CHFSMCLIST        *mclist; /*mem NP item list: LRU */

    uint8_t           *mcache; /*mem cache*/
}CHFSMC;

#define CHFSMC_CHFS_MD_ID(chfsmc)  ((chfsmc)->chfs_md_id)
#define CHFSMC_NP(chfsmc)          ((chfsmc)->chfsnp)
#define CHFSMC_PGD(chfsmc)         ((chfsmc)->cpgd)
#define CHFSMC_LIST(chfsmc)        ((chfsmc)->mclist)
#define CHFSMC_MCACHE(chfsmc)      ((chfsmc)->mcache)


#endif/* _CHFSMC_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

