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

#include "cparacfg.h"

#if 0
#define CMC_TRY_RETIRE_MAX_NUM             (8)
#define CMC_TRY_RECYCLE_MAX_NUM            (128)
#define CMC_SCAN_RETIRE_MAX_NUM            (256)

#define CMC_PROCESS_DEGRADE_MAX_NUM        (8)
#define CMC_SCAN_DEGRADE_MAX_NUM           (256)

#define CMC_RETIRE_HI_RATIO                (0.90) /*90%*/
#define CMC_RETIRE_MD_RATIO                (0.85) /*85%*/
#define CMC_RETIRE_LO_RATIO                (0.80) /*80%*/
#endif

#define CMC_TRAFFIC_10MB                   (((uint64_t)10) << 23) /*10Mbps*/
#define CMC_TRAFFIC_20MB                   (((uint64_t)20) << 23) /*20Mbps*/
#define CMC_TRAFFIC_30MB                   (((uint64_t)30) << 23) /*30Mbps*/
#define CMC_TRAFFIC_40MB                   (((uint64_t)40) << 23) /*40Mbps*/

#define CMC_DEGRADE_TRAFFIC_10MB           (((uint64_t)10) << 23) /*10Mbps*/
#define CMC_DEGRADE_TRAFFIC_15MB           (((uint64_t)15) << 23) /*15Mbps*/
#define CMC_DEGRADE_TRAFFIC_20MB           (((uint64_t)20) << 23) /*20Mbps*/
#define CMC_DEGRADE_TRAFFIC_25MB           (((uint64_t)25) << 23) /*25Mbps*/
#define CMC_DEGRADE_TRAFFIC_30MB           (((uint64_t)30) << 23) /*30Mbps*/
#define CMC_DEGRADE_TRAFFIC_32MB           (((uint64_t)32) << 23) /*32Mbps*/
#define CMC_DEGRADE_TRAFFIC_36MB           (((uint64_t)36) << 23) /*36Mbps*/
#define CMC_DEGRADE_TRAFFIC_40MB           (((uint64_t)40) << 23) /*40Mbps*/

#define CMC_READ_TRAFFIC_05MB              (((uint64_t) 5) << 23) /* 5Mbps*/
#define CMC_READ_TRAFFIC_10MB              (((uint64_t)10) << 23) /*10Mbps*/

#define CMC_WRITE_TRAFFIC_05MB             (((uint64_t) 5) << 23) /* 5Mbps*/
#define CMC_WRITE_TRAFFIC_10MB             (((uint64_t)10) << 23) /*10Mbps*/

typedef struct
{
    CMCDN              *cmcdn;
    CMCNP              *cmcnp;

    uint32_t            fc_max_speed_flag:1;/*enable flow control in max speed, */
                                            /*i.e., flush data from mem to ssd in max speed*/
    uint32_t            rsvd01:31;
    uint32_t            rsvd02;
}CMC_MD;

#define CMC_MD_DN(cmc_md)                ((cmc_md)->cmcdn)
#define CMC_MD_NP(cmc_md)                ((cmc_md)->cmcnp)
#define CMC_MD_FC_MAX_SPEED_FLAG(cmc_md) ((cmc_md)->fc_max_speed_flag)

/**
*
* start CMC module
*
**/
CMC_MD *cmc_start(const UINT32 mem_disk_size /*in byte*/, const UINT32 sata_disk_size/*in byte*/);

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
* try to quit cmc
*
**/
EC_BOOL cmc_try_quit(CMC_MD *cmc_md);

/**
*
* flow control enable max speed
*
**/
EC_BOOL cmc_flow_control_enable_max_speed(CMC_MD *cmc_md);

/**
*
* flow control disable max speed
*
**/
EC_BOOL cmc_flow_control_disable_max_speed(CMC_MD *cmc_md);

/**
*
* recycle deleted or retired space
*
**/
void cmc_process(CMC_MD *cmc_md, const uint64_t mem_traffic_bps, REAL  mem_hit_ratio,
                     const uint64_t amd_read_traffic_bps, const uint64_t amd_write_traffic_bps);

/**
*
*  degrade pages of cmc module
*
**/
void cmc_process_degrades(CMC_MD *cmc_md, const uint64_t degrade_traffic_bps,
                                 const UINT32 scan_max_num,
                                 const UINT32 expect_degrade_num,
                                 UINT32 *complete_degrade_num);

/**
*
*  degrade all pages of cmc module
*
**/
void cmc_process_all_degrades(CMC_MD *cmc_md);

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
*  find item
*
**/
CMCNP_ITEM *cmc_find(CMC_MD *cmc_md, const CMCNP_KEY *cmcnp_key);

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
*  set file ssd dirty flag which means flush it to ssd later
*
**/
EC_BOOL cmc_file_set_ssd_dirty(CMC_MD *cmc_md, UINT32 *offset, const UINT32 wsize);

/**
*
*  unset file ssd dirty flag which means cmc should not flush it to ssd
*
**/
EC_BOOL cmc_file_set_ssd_not_dirty(CMC_MD *cmc_md, UINT32 *offset, const UINT32 wsize);

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
*  name node used ratio
*
**/
REAL cmc_used_ratio(CMC_MD *cmc_md);

/**
*
*  name node deg ratio
*
**/
REAL cmc_deg_ratio(CMC_MD *cmc_md);

/**
*
*  name node deg num
*
**/
uint32_t cmc_deg_num(CMC_MD *cmc_md);

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

/**
*
*  degrade files
*
**/
EC_BOOL cmc_degrade(CMC_MD *cmc_md, const UINT32 max_num, UINT32 *complete_num);

EC_BOOL cmc_set_degrade_callback(CMC_MD *cmc_md, CMCNP_DEGRADE_CALLBACK func, void *arg);

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
*  show name node DEG
*
*
**/
EC_BOOL cmc_show_np_deg_list(const CMC_MD *cmc_md, LOG *log);

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

