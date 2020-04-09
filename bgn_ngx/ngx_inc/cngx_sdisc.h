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

#ifndef _CNGX_SDISC_H
#define _CNGX_SDISC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#include "type.h"
#include "log.h"
#include "cstring.h"


EC_BOOL cngx_sdisc_push_sender(void *cycle);

EC_BOOL cngx_sdisc_push_recver(void *cycle);

#endif /*_CNGX_SDISC_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
#ifdef __cplusplus
}
#endif/*__cplusplus*/

