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

#define CMC_MAX_MODI                       ((UINT32)64)

#define CMC_RECYCLE_MAX_NUM                ((UINT32)~0)

#define CMC_TRY_RETIRE_MAX_NUM             (128)
#define CMC_TRY_RECYCLE_MAX_NUM            (128)
typedef struct
{
    CMCDN              *cmcdn;
    CMCNP              *cmcnp;
}CMC_MD;

#define CMC_MD_DN(cmc_md)                ((cmc_md)->cmcdn)
#define CMC_MD_NP(cmc_md)                ((cmc_md)->cmcnpmgr)


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
UINT32 cmc_start(const CSTRING *cmc_root_dir);

/**
*
* end CMC module
*
**/
void cmc_end(const UINT32 cmc_md_id);


/**
*
*  create name node pool
*
**/
EC_BOOL cmc_create_npp(const UINT32 cmc_md_id, const UINT32 cmcnp_model);

/**
*
*  check file existence
*
**/
EC_BOOL cmc_find(const UINT32 cmc_md_id, const CSTRING *file_path);


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
EC_BOOL cmc_write(const UINT32 cmc_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  read a file
*
**/
EC_BOOL cmc_read(const UINT32 cmc_md_id, const CSTRING *file_path, CBYTES *cbytes);

/**
*
*  write a file at offset
*
**/
EC_BOOL cmc_write_e(const UINT32 cmc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read a file from offset
*
**/
EC_BOOL cmc_read_e(const UINT32 cmc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  create data node
*
**/
EC_BOOL cmc_create_dn(const UINT32 cmc_md_id, const CSTRING *root_dir);

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
*  delete a file
*
**/
EC_BOOL cmc_delete(const UINT32 cmc_md_id, const CSTRING *path);

/**
*
*  update a file
*
**/
EC_BOOL cmc_update(const UINT32 cmc_md_id, const CSTRING *file_path, const CBYTES *cbytes);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cmc_file_num(const UINT32 cmc_md_id, const CSTRING *path_cstr, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cmc_file_size(const UINT32 cmc_md_id, const CSTRING *path_cstr, uint64_t *file_size);

/**
*
*  search in current name node pool
*
**/
EC_BOOL cmc_search(const UINT32 cmc_md_id, const CSTRING *path_cstr, const UINT32 dflag);

/**
*
*  empty recycle
*
**/
EC_BOOL cmc_recycle(const UINT32 cmc_md_id, const UINT32 max_num_per_np, UINT32 *complete_num);

/**
*
*  show name node
*
*
**/
EC_BOOL cmc_show_np(const UINT32 cmc_md_id, LOG *log);

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
EC_BOOL cmc_retire(const UINT32 cmc_md_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num);


#endif /*_CMC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

