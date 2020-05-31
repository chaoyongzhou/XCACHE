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

#include "cmmap.h"

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

#define CMC_TRAFFIC_008MB                  (((uint64_t)  8) << 23) /* 8Mbps*/
#define CMC_TRAFFIC_016MB                  (((uint64_t) 16) << 23) /* 16Mbps*/
#define CMC_TRAFFIC_024MB                  (((uint64_t) 24) << 23) /* 24Mbps*/
#define CMC_TRAFFIC_032MB                  (((uint64_t) 32) << 23) /* 32Mbps*/
#define CMC_TRAFFIC_036MB                  (((uint64_t) 36) << 23) /* 36Mbps*/
#define CMC_TRAFFIC_040MB                  (((uint64_t) 40) << 23) /* 40Mbps*/
#define CMC_TRAFFIC_048MB                  (((uint64_t) 48) << 23) /* 48Mbps*/
#define CMC_TRAFFIC_056MB                  (((uint64_t) 56) << 23) /* 56Mbps*/
#define CMC_TRAFFIC_064MB                  (((uint64_t) 64) << 23) /* 64Mbps*/
#define CMC_TRAFFIC_072MB                  (((uint64_t) 72) << 23) /* 72Mbps*/
#define CMC_TRAFFIC_096MB                  (((uint64_t) 96) << 23) /* 96Mbps*/
#define CMC_TRAFFIC_128MB                  (((uint64_t)128) << 23) /*128Mbps*/

#define CMC_DEGRADE_TRAFFIC_008MB          (((uint64_t)  8) << 23) /* 8Mbps*/
#define CMC_DEGRADE_TRAFFIC_012MB          (((uint64_t) 12) << 23) /* 12Mbps*/
#define CMC_DEGRADE_TRAFFIC_016MB          (((uint64_t) 16) << 23) /* 16Mbps*/
#define CMC_DEGRADE_TRAFFIC_020MB          (((uint64_t) 20) << 23) /* 20Mbps*/
#define CMC_DEGRADE_TRAFFIC_024MB          (((uint64_t) 24) << 23) /* 24Mbps*/
#define CMC_DEGRADE_TRAFFIC_028MB          (((uint64_t) 28) << 23) /* 28Mbps*/
#define CMC_DEGRADE_TRAFFIC_032MB          (((uint64_t) 32) << 23) /* 32Mbps*/
#define CMC_DEGRADE_TRAFFIC_036MB          (((uint64_t) 36) << 23) /* 36Mbps*/
#define CMC_DEGRADE_TRAFFIC_040MB          (((uint64_t) 40) << 23) /* 40Mbps*/
#define CMC_DEGRADE_TRAFFIC_048MB          (((uint64_t) 48) << 23) /* 48Mbps*/
#define CMC_DEGRADE_TRAFFIC_056MB          (((uint64_t) 56) << 23) /* 56Mbps*/
#define CMC_DEGRADE_TRAFFIC_064MB          (((uint64_t) 64) << 23) /* 64Mbps*/
#define CMC_DEGRADE_TRAFFIC_072MB          (((uint64_t) 72) << 23) /* 72Mbps*/
#define CMC_DEGRADE_TRAFFIC_096MB          (((uint64_t) 96) << 23) /* 96Mbps*/
#define CMC_DEGRADE_TRAFFIC_128MB          (((uint64_t)128) << 23) /*128Mbps*/

//#define CMC_DEGRADE_TRAFFIC_QUIT           (CMC_DEGRADE_TRAFFIC_032MB)
#define CMC_DEGRADE_TRAFFIC_QUIT           (CMC_DEGRADE_TRAFFIC_128MB)

//#define CMC_DEGRADE_TRAFFIC_RESTART      (CMC_DEGRADE_TRAFFIC_032MB)
#define CMC_DEGRADE_TRAFFIC_RESTART        (CMC_DEGRADE_TRAFFIC_128MB)

//#define CMC_DEGRADE_TRAFFIC_MAX            (CMC_DEGRADE_TRAFFIC_032MB
#define CMC_DEGRADE_TRAFFIC_MAX            (CMC_DEGRADE_TRAFFIC_128MB)

#define CMC_DEGRADE_SSD                    ((uint32_t)0x0001)
#define CMC_DEGRADE_SATA                   ((uint32_t)0x0010)

typedef struct
{
    REAL                mem_used_ratio;
    REAL                mem_hit_ratio;

    uint64_t            amd_read_traffic_mps;   /*MB/s*/
    uint64_t            amd_write_traffic_mps;  /*MB/s*/

    REAL                mem_deg_ratio;
    uint32_t            mem_deg_num;
    uint32_t            rsvd01;
    uint64_t            mem_degrade_traffic_mps;
}CMC_STAT;

#define CMC_STAT_MEM_USED_RATIO(cmc_stat)               ((cmc_stat)->mem_used_ratio)
#define CMC_STAT_MEM_HIT_RATIO(cmc_stat)                ((cmc_stat)->mem_hit_ratio)
#define CMC_STAT_AMD_READ_SPEED(cmc_stat)               ((cmc_stat)->amd_read_traffic_mps)
#define CMC_STAT_AMD_WRITE_SPEED(cmc_stat)              ((cmc_stat)->amd_write_traffic_mps)
#define CMC_STAT_MEM_DEGRADE_RATIO(cmc_stat)            ((cmc_stat)->mem_deg_ratio)
#define CMC_STAT_MEM_DEGRADE_NUM(cmc_stat)              ((cmc_stat)->mem_deg_num)
#define CMC_STAT_MEM_DEGRADE_SPEED(cmc_stat)            ((cmc_stat)->mem_degrade_traffic_mps)

typedef struct
{
    CMCDN              *cmcdn;
    CMCNP              *cmcnp;

    CMMAP_NODE         *cmmap_node;        /*mounted point. inheritted from camd*/

    /*for degrade callback*/
    CMCNP_DEGRADE_CB    np_degrade_cb;

    uint32_t            fc_max_speed_flag:1;/*enable flow control in max speed, */
                                            /*i.e., flush data from mem to ssd in max speed*/
    uint32_t            shm_np_flag      :1;/*cmc np is in shared memory*/
    uint32_t            shm_dn_flag      :1;/*cmc dn is in shared memory*/
    uint32_t            read_only_flag   :1;/*cmc is read-only if set*/
    uint32_t            rsvd01           :28;

    uint8_t             rsvd02;
    uint8_t             np_model;
    uint16_t            vdisk_num;

    UINT32              key_max_num;

    CMC_STAT            stat;
}CMC_MD;

#define CMC_MD_DN(cmc_md)                             ((cmc_md)->cmcdn)
#define CMC_MD_NP(cmc_md)                             ((cmc_md)->cmcnp)
#define CMC_MD_CMMAP_NODE(cmc_md)                     ((cmc_md)->cmmap_node)
#define CMC_MD_NP_DEGRADE_CB(cmc_md)                  (&((cmc_md)->np_degrade_cb))
#define CMC_MD_FC_MAX_SPEED_FLAG(cmc_md)              ((cmc_md)->fc_max_speed_flag)
#define CMC_MD_SHM_NP_FLAG(cmc_md)                    ((cmc_md)->shm_np_flag)
#define CMC_MD_SHM_DN_FLAG(cmc_md)                    ((cmc_md)->shm_dn_flag)
#define CMC_MD_RDONLY_FLAG(cmc_md)                    ((cmc_md)->read_only_flag)
#define CMC_MD_NP_MODEL(cmc_md)                       ((cmc_md)->np_model)
#define CMC_MD_VDISK_NUM(cmc_md)                      ((cmc_md)->vdisk_num)
#define CMC_MD_KEY_MAX_NUM(cmc_md)                    ((cmc_md)->key_max_num)
#define CMC_MD_STAT(cmc_md)                           (&((cmc_md)->stat))


EC_BOOL cmc_stat_init(CMC_STAT  *cmc_stat);
EC_BOOL cmc_stat_clean(CMC_STAT  *cmc_stat);

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
* cleanup cmc name node and data node
*
**/
EC_BOOL cmc_clean(CMC_MD *cmc_md);

/**
*
* create cmc name node and data node
*
**/
EC_BOOL cmc_create(CMC_MD *cmc_md);

/**
*
* create cmc name node and data node in shm
*
**/
EC_BOOL cmc_create_shm(CMC_MD *cmc_md);

/**
*
* open cmc name node and data node in shm
*
**/
EC_BOOL cmc_open_shm(CMC_MD *cmc_md);

/*mount mmap node*/
EC_BOOL cmc_mount_mmap(CMC_MD *cmc_md, CMMAP_NODE *cmmap_node);

/*umount mmap node*/
EC_BOOL cmc_umount_mmap(CMC_MD *cmc_md);

/*get mmap node*/
CMMAP_NODE *cmc_get_mmap(CMC_MD *cmc_md);

/**
*
* try to quit cmc
*
**/
EC_BOOL cmc_try_quit(CMC_MD *cmc_md);

EC_BOOL cmc_try_restart(CMC_MD *cmc_md);

EC_BOOL cmc_set_read_only(CMC_MD *cmc_md);

EC_BOOL cmc_unset_read_only(CMC_MD *cmc_md);

EC_BOOL cmc_is_read_only(const CMC_MD *cmc_md);

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
void cmc_process(CMC_MD *cmc_md, const uint64_t mem_traffic_write_bps, const uint64_t ssd_traffic_read_bps, const uint64_t ssd_traffic_write_bps,
        REAL  mem_hit_ratio, const uint64_t amd_read_traffic_bps, const uint64_t amd_write_traffic_bps);

void cmc_process_no_degrade(CMC_MD *cmc_md);

/**
*
*  degrade pages of cmc module
*
**/
void cmc_process_degrades(CMC_MD *cmc_md, const uint64_t degrade_traffic_bps,
                                 const uint64_t ssd_traffic_read_bps,
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
EC_BOOL cmc_create_np(CMC_MD *cmc_md);

/**
*
*  create name node in shared memory
*
**/
EC_BOOL cmc_create_np_shm(CMC_MD *cmc_md);

/**
*
*  open name node in shared memory
*
**/
EC_BOOL cmc_open_np_shm(CMC_MD *cmc_md);

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
EC_BOOL cmc_create_dn(CMC_MD *cmc_md);

/**
*
*  create data node in shared memory
*
**/
EC_BOOL cmc_create_dn_shm(CMC_MD *cmc_md);

/**
*
*  open data node in shared memory
*
**/
EC_BOOL cmc_open_dn_shm(CMC_MD *cmc_md);

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

EC_BOOL cmc_set_degrade_callback(CMC_MD *cmc_md, const uint32_t flags, CMCNP_DEGRADE_CALLBACK func, void *arg);

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
*  show name node QUE
*
*
**/
EC_BOOL cmc_show_np_que_list(const CMC_MD *cmc_md, LOG *log);

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

