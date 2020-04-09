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

#if (SWITCH_ON == NGX_BGN_SWITCH)

#ifndef _CNGX_XFS_H
#define _CNGX_XFS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#include "type.h"
#include "log.h"
#include "cstring.h"


/*
*
* actually ask xfs to register ngx in order to obtain real comm of xfs
*
*/
EC_BOOL cngx_reg_xfs(const UINT32 xfs_tcid);


#endif /*_CNGX_XFS_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
#ifdef __cplusplus
}
#endif/*__cplusplus*/

