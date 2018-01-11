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

#ifndef _CP2P_H
#define _CP2P_H

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "crb.h"
#include "chashalgo.h"
#include "cmd5.h"
#include "csocket.h"
#include "cbtimer.h"
#include "mod.inc"

#define CP2P_NODES_MAX_NUM          ((UINT32)10240)        

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    UINT32               crfs_modi;
    UINT32               ctdns_modi;

}CP2P_MD;

#define CP2P_MD_TERMINATE_FLAG(cp2p_md)    ((cp2p_md)->terminate_flag)
#define CP2P_MD_CRFS_MODI(cp2p_md)         ((cp2p_md)->crfs_modi)
#define CP2P_MD_CTDNS_MODI(cp2p_md)        ((cp2p_md)->ctdns_modi)

typedef struct
{
    CSTRING              service_name;
    CSTRING              src_file_name;
    UINT32               src_file_size;
    CMD5_DIGEST          src_file_md5;
    CSTRING              des_file_name; /*full path*/
}CP2P_FILE;

#define CP2P_SERVICE_NAME(cp2p_file)            (&((cp2p_file)->service_name))
#define CP2P_SRC_FILE_NAME(cp2p_file)           (&((cp2p_file)->src_file_name))
#define CP2P_SRC_FILE_SIZE(cp2p_file)           ((cp2p_file)->src_file_size)
#define CP2P_SRC_FILE_MD5(cp2p_file)            (&((cp2p_file)->src_file_md5))
#define CP2P_DES_FILE_NAME(cp2p_file)           (&((cp2p_file)->des_file_name))

#define CP2P_SERVICE_NAME_STR(cp2p_file)        (cstring_get_str(CP2P_SERVICE_NAME(cp2p_file)))
#define CP2P_SRC_FILE_NAME_STR(cp2p_file)       (cstring_get_str(CP2P_SRC_FILE_NAME(cp2p_file)))
#define CP2P_DES_FILE_NAME_STR(cp2p_file)       (cstring_get_str(CP2P_DES_FILE_NAME(cp2p_file)))

/**
*   for test only
*
*   to query the status of CP2P Module
*
**/
void cp2p_print_module_status(const UINT32 cp2p_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CP2P module
*
*
**/
UINT32 cp2p_free_module_static_mem(const UINT32 cp2p_md_id);

/**
*
* start CP2P module
*
**/
UINT32 cp2p_start(const CSTRING * crfs_root_dir, const CSTRING * ctdns_root_dir);

/**
*
* end CP2P module
*
**/
void cp2p_end(const UINT32 cp2p_md_id);

/*------------------------------------------------ interface of file delivery ------------------------------------------------*/
CP2P_FILE *cp2p_file_new();

EC_BOOL cp2p_file_init(CP2P_FILE *cp2p_file);

EC_BOOL cp2p_file_clean(CP2P_FILE *cp2p_file);

EC_BOOL cp2p_file_free(CP2P_FILE *cp2p_file);

int     cp2p_file_cmp(const CP2P_FILE *cp2p_file_1st, const CP2P_FILE *cp2p_file_2nd);

void    cp2p_file_print(LOG *log, const CP2P_FILE *cp2p_file);

/**
*
*  compare the expected downloading file and local file
*  
*
**/
EC_BOOL cp2p_download_file_exists(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file);

/**
*
*  download file, store it to disk as des dir and notify src after completion
*  
*  note: need de-duplication
*
**/
EC_BOOL cp2p_download_file_ep(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  download file, store it to (RFS) storage and notify src after completion
*
**/
EC_BOOL cp2p_download_file(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  notify completion of downloading file
*
**/
EC_BOOL cp2p_download_completion(const UINT32 cp2p_md_id, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  notify of downloading file
*
**/
EC_BOOL cp2p_download_notify(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  broadcast notification of downloading file to all members of service
*
**/
EC_BOOL cp2p_download_broadcast(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file);

/**
*
*  upload file to RFS storage
*
**/
EC_BOOL cp2p_upload_file(const UINT32 cp2p_md_id, const CSTRING *src_file, const CSTRING *service_name, const CSTRING *des_file);

#endif /*_CP2P_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


