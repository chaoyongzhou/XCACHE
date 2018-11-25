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

#ifndef _CMC_H
#define _CMC_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"

#include "cmcnp.h"
#include "cmcdn.h"

#define CMC_RECYCLE_MAX_NUM                ((UINT32)~0)

#define CMC_TRY_RETIRE_MAX_NUM             (128)
#define CMC_TRY_RECYCLE_MAX_NUM            (128)
typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;
    
    CMCDN               *cmcdn;
    CMCNP               *cmcnp;
}CMC_MD;

#define CMC_MD_TERMINATE_FLAG(cmc_md)    ((cmc_md)->terminate_flag)
#define CMC_MD_DN(cmc_md)                ((cmc_md)->cmcdn)
#define CMC_MD_NP(cmc_md)                ((cmc_md)->cmcnp)


/**
*   for test only
*
*   to query the status of CMC Module
*
**/
void cmc_print_module_status(const UINT32 cmc_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CMC module
*
*
**/
UINT32 cmc_free_module_static_mem(const UINT32 cmc_md_id);

/**
*
* start CMC module
*
**/
UINT32 cmc_start(const UINT32 np_model, const UINT32 disk_num);

/**
*
* end CMC module
*
**/
void cmc_end(const UINT32 cmc_md_id);

/**
*
*  create name node
*
**/
EC_BOOL cmc_create_np(const UINT32 cmc_md_id, const UINT32 cmcnp_model);

/**
*
*  close name node
*
**/
EC_BOOL cmc_close_np(const UINT32 cmc_md_id);

/**
*
*  create data node
*
**/
EC_BOOL cmc_create_dn(const UINT32 cmc_md_id, const UINT32 disk_num);

/**
*
*  close data node
*
**/
EC_BOOL cmc_close_dn(const UINT32 cmc_md_id);

/**
*
*  find intersected range
*
**/
EC_BOOL cmc_find_intersected(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key);

/**
*
*  find closest range
*
**/
EC_BOOL cmc_find_closest(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, CMCNP_KEY *cmcnp_key_closest);

/**
*
*  reserve space from dn
*
**/
EC_BOOL cmc_reserve_dn(const UINT32 cmc_md_id, const UINT32 data_len, CMCNP_FNODE *cmcnp_fnode);

/**
*
*  release space to dn
*
**/
EC_BOOL cmc_release_dn(const UINT32 cmc_md_id, const CMCNP_FNODE *cmcnp_fnode);

/**
*
*  write a file
*
**/
EC_BOOL cmc_write(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes);

/**
*
*  read a file
*
**/
EC_BOOL cmc_read(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, CBYTES *cbytes);

/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a file at offset
*
**/
EC_BOOL cmc_write_e(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL cmc_read_e(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  export data into data node
*
**/
EC_BOOL cmc_export_dn(const UINT32 cmc_md_id, const CBYTES *cbytes, const CMCNP_FNODE *cmcnp_fnode);

/**
*
*  write data node
*
**/
EC_BOOL cmc_write_dn(const UINT32 cmc_md_id, const CBYTES *cbytes, CMCNP_FNODE *cmcnp_fnode);

/**
*
*  read data node
*
**/
EC_BOOL cmc_read_dn(const UINT32 cmc_md_id, const CMCNP_FNODE *cmcnp_fnode, CBYTES *cbytes);

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cmc_write_e_dn(const UINT32 cmc_md_id, CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cmc_read_e_dn(const UINT32 cmc_md_id, const CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  delete all intersected file
*
**/
EC_BOOL cmc_delete_intersected(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key);

/**
*
*  delete a file
*
**/
EC_BOOL cmc_delete(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key);

EC_BOOL cmc_update(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cmc_file_num(const UINT32 cmc_md_id, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cmc_file_size(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, UINT32 *file_size);

/**
*
*  search in current name node
*
**/
EC_BOOL cmc_search(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key);

/**
*
*  empty recycle
*
**/
EC_BOOL cmc_recycle(const UINT32 cmc_md_id, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  show name node
*
*
**/
EC_BOOL cmc_show_np(const UINT32 cmc_md_id, LOG *log);

/**
*
*  show name node LRU
*
*
**/
EC_BOOL cmc_show_np_lru_list(const UINT32 cmc_md_id, LOG *log);

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cmc_show_np_del_list(const UINT32 cmc_md_id, LOG *log);

/**
*
*  show cmcdn info if it is dn
*
*
**/
EC_BOOL cmc_show_dn(const UINT32 cmc_md_id, LOG *log);

/**
*
*  retire files
*
**/
EC_BOOL cmc_retire(const UINT32 cmc_md_id, const UINT32 max_num, UINT32 *complete_num);

#endif /*_CMC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

