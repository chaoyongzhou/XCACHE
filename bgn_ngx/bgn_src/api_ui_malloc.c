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
#include "mm.h"
#include "log.h"
#include "api_ui_log.h"

void *api_ui_malloc(size_t size, const UINT32 location)
{
    void*           mem_allocated_ptr = NULL;
    mem_allocated_ptr = SAFE_MALLOC(size, location);
    //dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_malloc: mem_allocated_ptr = %lx\n", mem_allocated_ptr);
    return(void*)(mem_allocated_ptr);
}

void api_ui_free(void *ptr, const UINT32 location)
{
    if(ptr)
    {
        //dbg_log(SEC_0010_API, 5)(LOGSTDOUT, "api_ui_free: ptr = %lx\n", ptr);
        SAFE_FREE(ptr, location);
    }

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

