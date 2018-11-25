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

#define CMC_TRY_RETIRE_MAX_NUM             (2)
#define CMC_TRY_RECYCLE_MAX_NUM            (128)
typedef struct
{
    CMCDN              *cmcdn;
    CMCNP              *cmcnp;
}CMC_MD;

#define CMC_MD_DN(cmc_md)                ((cmc_md)->cmcdn)
#define CMC_MD_NP(cmc_md)                ((cmc_md)->cmcnp)

/**
*
* start CMC module
*
**/
CMC_MD *cmc_start(const UINT32 rdisk_size/*in GB*/, const UINT32 vdisk_size /*in MB*/);

/**
*
* end CMC module
*
**/
void cmc_end(CMC_MD *cmc_md);

/**
*
* print CMC module
*
**/
void cmc_print(LOG *log, const CMC_MD *cmc_md);

/**
*
* recycle deleted or retired space
*
**/
void cmc_process(CMC_MD *cmc_md);

/**
*
*  create name node
*
**/
EC_BOOL cmc_create_np(CMC_MD *cmc_md, const UINT32 cmcnp_model, const UINT32 key_max_num);

/**
*
*  close name node
*
**/
EC_BOOL cmc_close_np(CMC_MD *cmc_md);

/**
*
*  create data node
*
**/
EC_BOOL cmc_create_dn(CMC_MD *cmc_md, const UINT32 disk_num);

/**
*
*  close data node
*
**/
EC_BOOL cmc_close_dn(CMC_MD *cmc_md);

/**
*
*  find intersected range
*
**/
EC_BOOL cmc_find_intersected(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key);

/**
*
*  find closest range
*
**/
EC_BOOL cmc_find_closest(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, CMCNP_KEY *cmcnp_key_closest);


/**
*
*  reserve space from dn
*
**/
EC_BOOL cmc_reserve_dn(CMC_MD *cmc_md, const UINT32 data_len, CMCNP_FNODE *cmcnp_fnode);

/**
*
*  release space to dn
*
**/
EC_BOOL cmc_release_dn(CMC_MD *cmc_md, const CMCNP_FNODE *cmcnp_fnode);

/**
*
*  locate a file and return base address of the first page
*
**/
UINT8 *cmc_file_locate(CMC_MD *cmc_md, UINT32 *offset, const UINT32 rsize);

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cmc_file_read(CMC_MD *cmc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff);

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cmc_file_write(CMC_MD *cmc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff);

/**
*
*  delete a file (POSIX style interface)
*
**/
EC_BOOL cmc_file_delete(CMC_MD *cmc_md, UINT32 *offset, const UINT32 dsize);

/**
*
*  set file flush flag which means flush it to ssd when retire
*
**/
EC_BOOL cmc_file_set_flush(CMC_MD *cmc_md, UINT32 *offset, const UINT32 wsize);

/**
*
*  locate a page
*
**/
UINT8 *cmc_page_locate(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key);

/**
*
*  write a page
*
**/
EC_BOOL cmc_page_write(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes);

/**
*
*  read a page
*
**/
EC_BOOL cmc_page_read(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, CBYTES *cbytes);

/**
*
*  write a page at offset
*
**/
EC_BOOL cmc_page_write_e(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read a page from offset
*
**/
EC_BOOL cmc_page_read_e(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);


/**
*
*  export data into data node
*
**/
EC_BOOL cmc_export_dn(CMC_MD *cmc_md, const CBYTES *cbytes, const CMCNP_FNODE *cmcnp_fnode);

/**
*
*  write data node
*
**/
EC_BOOL cmc_write_dn(CMC_MD *cmc_md, const CBYTES *cbytes, CMCNP_FNODE *cmcnp_fnode);


/**
*
*  read data node
*
**/
EC_BOOL cmc_read_dn(CMC_MD *cmc_md, const CMCNP_FNODE *cmcnp_fnode, CBYTES *cbytes);

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cmc_write_e_dn(CMC_MD *cmc_md, CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cmc_read_e_dn(CMC_MD *cmc_md, const CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  delete all intersected file
*
**/
EC_BOOL cmc_delete_intersected(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key);

/**
*
*  delete a page
*
**/
EC_BOOL cmc_page_delete(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key);

/**
*
*  update a page
*
**/
EC_BOOL cmc_page_update(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cmc_file_num(CMC_MD *cmc_md, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cmc_file_size(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key, uint64_t *file_size);

/**
*
*  search in current name node
*
**/
EC_BOOL cmc_search(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key);

/**
*
*  empty recycle
*
**/
EC_BOOL cmc_recycle(CMC_MD *cmc_md, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  retire files
*
**/
EC_BOOL cmc_retire(CMC_MD *cmc_md, const UINT32 max_num, UINT32 *complete_num);

EC_BOOL cmc_set_retire_callback(CMC_MD *cmc_md, CMCNP_RETIRE_CALLBACK func, void *arg);

/**
*
*  show name node
*
*
**/
EC_BOOL cmc_show_np(const CMC_MD *cmc_md, LOG *log);

/**
*
*  show name node LRU
*
*
**/
EC_BOOL cmc_show_np_lru_list(const CMC_MD *cmc_md, LOG *log);

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cmc_show_np_del_list(const CMC_MD *cmc_md, LOG *log);

/**
*
*  show name node BITMAP
*
*
**/
EC_BOOL cmc_show_np_bitmap(const CMC_MD *cmc_md, LOG *log);

/**
*
*  show cmcdn info if it is dn
*
*
**/
EC_BOOL cmc_show_dn(const CMC_MD *cmc_md, LOG *log);

/**
*
*  show all files
*
**/

EC_BOOL cmc_show_files(const CMC_MD *cmc_md, LOG *log);

#endif /*_CMC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

