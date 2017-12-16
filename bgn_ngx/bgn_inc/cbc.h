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

#ifndef _CBC_H
#define _CBC_H

#include "type.h"
#include "cvector.h"

EC_BOOL cbc_new(const UINT32 size);

EC_BOOL cbc_free();

UINT32 cbc_size();

EC_BOOL cbc_md_reg(const UINT32 md_type, const UINT32 md_capaciy);

EC_BOOL cbc_md_unreg(const UINT32 md_type);

EC_BOOL cbc_md_unreg_all();

UINT32 cbc_md_capacity(const UINT32 md_type);

UINT32 cbc_md_num(const UINT32 md_type);

void *cbc_md_get(const UINT32 md_type, const UINT32 pos);

UINT32 cbc_md_add(const UINT32 md_type, const void *md);

void * cbc_md_del(const UINT32 md_type, const UINT32 pos);

UINT32 cbc_md_new(const UINT32 md_type, const UINT32 sizeof_md);

EC_BOOL cbc_md_free(const UINT32 md_type, const UINT32 pos);

UINT32  cbc_sum();
EC_BOOL cbc_print(LOG *log);

#endif /*_CBC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

