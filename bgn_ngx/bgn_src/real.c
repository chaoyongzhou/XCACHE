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

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmpic.inc"

UINT32 real_init(REAL *real)
{
    (*real) = 0.0;
    return (0);
}

UINT32 real_clean(REAL *real)
{
    (*real) = 0.0;
    return (0);
}

UINT32 real_free(REAL *real)
{
    free_static_mem(MM_REAL, real, LOC_REAL_0001);
    return (0);
}

REAL * real_new()
{
    REAL *real;
    alloc_static_mem(MM_REAL, &real, LOC_REAL_0002);

    (*real) = 0.0;
    return (real);
}

void real_print(LOG *log, const REAL *real)
{
    sys_log(log, "%.2f\n", (*real));
    return;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

