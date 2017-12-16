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

#ifndef _API_UI_MALLOC_H
#define _API_UI_MALLOC_H


#include "type.h"

void *api_ui_malloc(size_t size, const UINT32 location);

void api_ui_free(void *ptr, const UINT32 location);

#endif  /* _API_UI_MALLOC_H */

#ifdef __cplusplus
}
#endif /* _cplusplus */

