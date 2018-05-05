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

#ifndef _TASKCFGCHK_H
#define _TASKCFGCHK_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "clist.h"
#include "cset.h"
#include "cstring.h"
#include "cvector.h"

#include "taskcfg.inc"
#include "taskcfg.h"

EC_BOOL taskcfgchk_net_print(LOG *log, const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske);

EC_BOOL taskcfgchk_route_print(LOG *log, const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske);

EC_BOOL taskcfgchk_conn_print(LOG *log, const TASK_CFG *task_cfg, const UINT32 tcid, const UINT32 maski, const UINT32 maske, const UINT32 remote_tcid);

EC_BOOL taskcfgchk_route_trace(LOG *log, const TASK_CFG *task_cfg, const UINT32 src_tcid, const UINT32 src_maski, const UINT32 src_maske, const UINT32 des_tcid, const UINT32 max_hops);

EC_BOOL taskcfgchk_net_all(LOG *log, const TASK_CFG *task_cfg);

#endif /*_TASKCFGCHK_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
