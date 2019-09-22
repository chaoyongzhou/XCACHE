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

//=====================================================================
//
// FastMemcpy.c - skywind3000@163.com, 2015
//
// feature:
// 50% speed up in avg. vs standard memcpy (tested in vc2012/gcc5.1)
//
//=====================================================================
#ifndef __FAST_MEMCPY_H__
#define __FAST_MEMCPY_H__

#include <stdlib.h>

//---------------------------------------------------------------------
// main routine
//---------------------------------------------------------------------
void* fast_memcpy(void *destination, const void *source, size_t size);


#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

