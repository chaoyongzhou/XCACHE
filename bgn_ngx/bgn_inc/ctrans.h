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

#ifndef _CTRANS_H
#define _CTRANS_H

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "crb.h"
#include "chashalgo.h"
#include "cmd5.h"
#include "mod.inc"

#include "cfile.h"


#define CTRANS_SEG_SIZE_DEFAULT          ((UINT32)1 * 1024 * 1024) /*1MB*/
#define CTRANS_SEG_CONCURRENCE_DEFAULT   ((UINT32)1)               /*concurrent coroutine num*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    UINT32               seg_size;
    UINT32               seg_concurrence;

    UINT32               local_cfile_md_id;
    UINT32               remote_cfile_md_id;
    UINT32               remote_tcid;
}CTRANS_MD;

#define CTRANS_MD_TERMINATE_FLAG(ctrans_md)             ((ctrans_md)->terminate_flag)
#define CTRANS_MD_SEG_SIZE(ctrans_md)                   ((ctrans_md)->seg_size)
#define CTRANS_MD_SEG_CONCURRENCE(ctrans_md)            ((ctrans_md)->seg_concurrence)
#define CTRANS_MD_LOCAL_CFILE_MODI(ctrans_md)           ((ctrans_md)->local_cfile_md_id)
#define CTRANS_MD_REMOTE_CFILE_MODI(ctrans_md)          ((ctrans_md)->remote_cfile_md_id)
#define CTRANS_MD_REMOTE_TCID(ctrans_md)                ((ctrans_md)->remote_tcid)

/**
*   for test only
*
*   to query the status of CTRANS Module
*
**/
void ctrans_print_module_status(const UINT32 ctrans_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CTRANS module
*
*
**/
UINT32 ctrans_free_module_static_mem(const UINT32 ctrans_md_id);

/**
*
* start CTRANS module
*
**/
UINT32 ctrans_start(const UINT32 des_tcid, const UINT32 seg_size, const UINT32 seg_concurrence);

/**
*
* end CTRANS module
*
**/
void ctrans_end(const UINT32 ctrans_md_id);

/**
*
* transfer file segment
*
**/
EC_BOOL ctrans_seg(const UINT32 ctrans_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path, const UINT32 seg_offset, const UINT32 seg_size);

/**
*
* transfer file
*
**/
EC_BOOL ctrans_file(const UINT32 ctrans_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path);

#endif /*_CTRANS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


