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

#ifndef _CPARACFG_H
#define _CPARACFG_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "type.h"

#include "cparacfg.inc"
#include "cxml.h"
#include "task.h"

CPARACFG *cparacfg_new(const UINT32 this_tcid, const UINT32 this_rank);

EC_BOOL cparacfg_clean(CPARACFG *cparacfg);

EC_BOOL cparacfg_free(CPARACFG *cparacfg);

EC_BOOL cparacfg_init(CPARACFG *cparacfg, const UINT32 this_tcid, const UINT32 this_rank);

EC_BOOL cparacfg_clone(const CPARACFG *cparacfg_src, CPARACFG *cparacfg_des);

EC_BOOL cparacfg_validity_check(const CPARACFG *cparacfg);

EC_BOOL cparacfg_cmp(const CPARACFG *cparacfg_1st, const CPARACFG *cparacfg_2nd);

void cparacfg_print(LOG *log, const CPARACFG *cparacfg);


#endif/*_CPARACFG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
