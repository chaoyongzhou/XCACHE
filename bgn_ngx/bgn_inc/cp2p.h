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

#define CP2P_NODES_MAX_NUM          ((UINT32)1024)        

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    UINT32               network_level;
    UINT32               network_tcid;

    UINT32               crfs_modi;
    UINT32               ctdns_modi;

}CP2P_MD;

#define CP2P_MD_TERMINATE_FLAG(cp2p_md)    ((cp2p_md)->terminate_flag)

#define CP2P_MD_NETWORK_LEVEL(cp2p_md)     ((cp2p_md)->network_level)
#define CP2P_MD_NETWORK_TCID(cp2p_md)      ((cp2p_md)->network_tcid)

#define CP2P_MD_CRFS_MODI(cp2p_md)         ((cp2p_md)->crfs_modi)
#define CP2P_MD_CTDNS_MODI(cp2p_md)        ((cp2p_md)->ctdns_modi)


typedef struct
{
    CSTRING              service_name;
   
    CSTRING              src_file_name;
    CSTRING              des_file_name; /*full path*/
    
    UINT32               src_file_size;
    CMD5_DIGEST          src_file_md5;

    UINT32               report_tcid;   /*report to tcid*/
    
}CP2P_FILE;

#define CP2P_FILE_SERVICE_NAME(cp2p_file)       (&((cp2p_file)->service_name))

#define CP2P_FILE_SRC_NAME(cp2p_file)           (&((cp2p_file)->src_file_name))
#define CP2P_FILE_DES_NAME(cp2p_file)           (&((cp2p_file)->des_file_name))

#define CP2P_FILE_SRC_SIZE(cp2p_file)           ((cp2p_file)->src_file_size)
#define CP2P_FILE_SRC_MD5(cp2p_file)            (&((cp2p_file)->src_file_md5))

#define CP2P_FILE_REPORT_TCID(cp2p_file)        ((cp2p_file)->report_tcid)

#define CP2P_FILE_SERVICE_NAME_STR(cp2p_file)   (cstring_get_str(CP2P_FILE_SERVICE_NAME(cp2p_file)))
#define CP2P_FILE_SRC_NAME_STR(cp2p_file)       (cstring_get_str(CP2P_FILE_SRC_NAME(cp2p_file)))
#define CP2P_FILE_DES_NAME_STR(cp2p_file)       (cstring_get_str(CP2P_FILE_DES_NAME(cp2p_file)))

#define CP2P_FILE_SRC_MD5_DIGEST(cp2p_file)     (CMD5_DIGEST_SUM(CP2P_FILE_SRC_MD5(cp2p_file)))
#define CP2P_FILE_SRC_MD5_DIGEST_STR(cp2p_file) (c_md5_to_hex_str(CP2P_FILE_SRC_MD5_DIGEST(cp2p_file)))

typedef struct
{
    CSTRING              service_name;
    CSTRING              command_line;
}CP2P_CMD;

#define CP2P_CMD_SERVICE_NAME(cp2p_cmd)         (&((cp2p_cmd)->service_name))
#define CP2P_CMD_COMMAND_LINE(cp2p_cmd)         (&((cp2p_cmd)->command_line))

#define CP2P_CMD_SERVICE_NAME_STR(cp2p_cmd)     (cstring_get_str(CP2P_CMD_SERVICE_NAME(cp2p_cmd)))
#define CP2P_CMD_COMMAND_LINE_STR(cp2p_cmd)     (cstring_get_str(CP2P_CMD_COMMAND_LINE(cp2p_cmd)))

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

EC_BOOL cp2p_file_clone(const CP2P_FILE *cp2p_file_src, CP2P_FILE *cp2p_file_des);

int     cp2p_file_cmp(const CP2P_FILE *cp2p_file_1st, const CP2P_FILE *cp2p_file_2nd);

EC_BOOL cp2p_file_is(const CP2P_FILE *cp2p_file, const CBYTES *file_content);

void    cp2p_file_print(LOG *log, const CP2P_FILE *cp2p_file);

/**
*
*  compare the expected downloading file and local file
*  
*
**/
EC_BOOL cp2p_file_exists_local(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file);


/**
*
*  check p2p file existing in storage
*
*
**/
EC_BOOL cp2p_file_exists(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file);

/**
*
*  notify edges under current network to push p2p file
*
**/
EC_BOOL cp2p_file_push_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  notify edges under current network to flush p2p file
*
**/
EC_BOOL cp2p_file_flush_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  notify upper nodes of current network to report p2p file is ready or deleted
*
**/
EC_BOOL cp2p_file_report_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  notify edge nodes under current network to delete p2p file
*
**/
EC_BOOL cp2p_file_delete_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  download p2p file from tcid
*
*
**/
EC_BOOL cp2p_file_download(const UINT32 cp2p_md_id, const UINT32 src_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  push p2p file to storage
*
*  note: des_tcid maybe ANY TCID
*
**/
EC_BOOL cp2p_file_push(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  pull p2p file from upper
*
*
**/
EC_BOOL cp2p_file_pull(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file);

/**
*
*  delete p2p file from src tcid
*
*
**/
EC_BOOL cp2p_file_delete(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  dump p2p file to local disk if the file exists in storage
*
*
**/
EC_BOOL cp2p_file_dump(const UINT32 cp2p_md_id, const CP2P_FILE *cp2p_file);

/**
*
*  flush p2p file to local disk
*
*  if the p2p file does not exist in storage, pull it
*
**/
EC_BOOL cp2p_file_flush(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  report to src tcid that p2p file is ready
*
*
**/
EC_BOOL cp2p_file_report(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_FILE *cp2p_file);

/**
*
*  load a local file to storage
*
**/
EC_BOOL cp2p_file_load(const UINT32 cp2p_md_id, const CSTRING *src_file, const CSTRING *service_name, const CSTRING *des_file);

/**
*
*  upload file content to storage
*
**/
EC_BOOL cp2p_file_upload(const UINT32 cp2p_md_id, const CBYTES *src_file_content, const CSTRING *service_name, const CSTRING *des_file);

/*------------------------------------------------ interface of command execution ------------------------------------------------*/
CP2P_CMD *cp2p_cmd_new();

EC_BOOL cp2p_cmd_init(CP2P_CMD *cp2p_cmd);

EC_BOOL cp2p_cmd_clean(CP2P_CMD *cp2p_cmd);

EC_BOOL cp2p_cmd_free(CP2P_CMD *cp2p_cmd);

int cp2p_cmd_cmp(const CP2P_CMD *cp2p_cmd_1st, const CP2P_CMD *cp2p_cmd_2nd);

void cp2p_cmd_print(LOG *log, const CP2P_CMD *cp2p_cmd);

/**
*
*  execute command
*
*
**/
EC_BOOL cp2p_cmd_execute(const UINT32 cp2p_md_id, const CP2P_CMD *cp2p_cmd);

/**
*
*  notify edges under current network to deliver p2p cmd
*
**/
EC_BOOL cp2p_cmd_deliver_notify(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_CMD *cp2p_cmd); 

/**
*
*  deliver command
*
**/
EC_BOOL cp2p_cmd_deliver(const UINT32 cp2p_md_id, const UINT32 des_network, const UINT32 des_tcid, const CP2P_CMD *cp2p_cmd);

/*------------------------------------------------ interface of reporter ------------------------------------------------*/
/**
*
*  report p2p online
*
**/
EC_BOOL cp2p_online_report(const UINT32 cp2p_md_id, const CSTRING *service_name);

#endif /*_CP2P_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


