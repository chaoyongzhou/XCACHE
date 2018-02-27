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

#ifndef _CFILE_H
#define _CFILE_H

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "crb.h"
#include "chashalgo.h"
#include "cmd5.h"
#include "mod.inc"

#define CFILE_NODES_MAX_NUM          ((UINT32)1024)        

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

}CFILE_MD;

#define CFILE_MD_TERMINATE_FLAG(cfile_md)    ((cfile_md)->terminate_flag)

/**
*   for test only
*
*   to query the status of CFILE Module
*
**/
void cfile_print_module_status(const UINT32 cfile_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CFILE module
*
*
**/
UINT32 cfile_free_module_static_mem(const UINT32 cfile_md_id);

/**
*
* start CFILE module
*
**/
UINT32 cfile_start();

/**
*
* end CFILE module
*
**/
void cfile_end(const UINT32 cfile_md_id);

/**
*
*  check file existing
*
*
**/
EC_BOOL cfile_exists(const UINT32 cfile_md_id, const CSTRING *file_path);

/**
*
*  file size
*
*
**/
EC_BOOL cfile_size(const UINT32 cfile_md_id, const CSTRING *file_path, UINT32 *file_size);

/**
*
*  file md5
*
*
**/
EC_BOOL cfile_md5(const UINT32 cfile_md_id, const CSTRING *file_path, CMD5_DIGEST *file_md5sum);
/**
*
*  load whole file
*
*
**/
EC_BOOL cfile_load(const UINT32 cfile_md_id, const CSTRING *file_path, CBYTES *file_content);

/**
*
*  update file content
*
*
**/
EC_BOOL cfile_update(const UINT32 cfile_md_id, const CSTRING *file_path, const CBYTES *file_content);

/**
*
*  remove file
*
*
**/
EC_BOOL cfile_remove(const UINT32 cfile_md_id, const CSTRING *file_path);

/**
*
*  rename/move file
*
*
**/
EC_BOOL cfile_rename(const UINT32 cfile_md_id, const CSTRING *src_file_path, const CSTRING *des_file_path);

#endif /*_CFILE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


