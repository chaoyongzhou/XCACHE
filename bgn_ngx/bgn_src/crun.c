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

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "cstring.h"
#include "crun.h"
#include "log.h"

UINT32 usr_run_01(const CSTRING *cstring)
{
    dbg_log(SEC_0138_CRUN, 5)(LOGSTDOUT, "usr_run_01: cstring: %s\n", (char *)cstring_get_str(cstring));
    return (0);
}

UINT32 usr_run_02(const CSTRING *cstring_01, const CSTRING *cstring_02, CSTRING *cstring_03)
{
    dbg_log(SEC_0138_CRUN, 5)(LOGSTDOUT, "usr_run_02: cstring_01: %s\n", (char *)cstring_get_str(cstring_01));
    dbg_log(SEC_0138_CRUN, 5)(LOGSTDOUT, "usr_run_02: cstring_02: %s\n", (char *)cstring_get_str(cstring_02));

    cstring_append_cstr(cstring_03, cstring_01);
    cstring_append_cstr(cstring_03, cstring_02);

    return (0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

