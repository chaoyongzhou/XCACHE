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
}CSFSMC;

#define CSFSMC_CSFS_MD_ID(csfsmc)  ((csfsmc)->csfs_md_id)
#define CSFSMC_NP(csfsmc)          ((csfsmc)->csfsnp)
#define CSFSMC_PGD(csfsmc)         ((csfsmc)->cpgd)
#define CSFSMC_LIST(csfsmc)        ((csfsmc)->mclist)
#define CSFSMC_MCACHE(csfsmc)      ((csfsmc)->mcache)

#endif/* _CSFSMC_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

