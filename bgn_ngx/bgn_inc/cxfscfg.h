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

#ifndef _CXFSCFG_H
#define _CXFSCFG_H

#include "type.h"
#include "cxfscfg.h"

#include "camd.h"

#define CXFSCFG_MAGIC_VAL                  ((UINT32)0x3141592653589793) /* 3.14159 26535 89793*/

#define CXFSCFG_SIZE                       (256 * 1024) /*256KB*/

#define CXFSCFG_ALIGNMENT                  (1 << 20)    /*1MB*/

#define CXFSCFG_TAIL_SIZE_MIN              (1 << 30)    /*1GB*/

typedef struct
{
    UINT32           s_offset;               /*zone start offset on sata disk*/
    UINT32           e_offset;               /*zone end offset on sata disk*/
}CXFSZONE;

#define CXFSZONE_S_OFFSET(cxfszone)                    ((cxfszone)->s_offset)
#define CXFSZONE_E_OFFSET(cxfszone)                    ((cxfszone)->e_offset)

typedef struct
{
    UINT32           magic;                     /*magic number*/

    UINT32           offset;                    /*cfg offset on disk*/

    UINT32           sata_meta_size;            /*sata meta size in bytes*/
    UINT32           sata_disk_size;            /*sata disk size in bytes*/
    UINT32           sata_disk_offset;          /*sata data cache start offset in sata disk. align to 32G*/

    UINT32           sata_vdisk_size;           /*sata virtual disk size in bytes*/
    UINT32           sata_vdisk_num;            /*sata virtual disk num*/

    UINT32           np_size;                   /*size per np*/
    uint8_t          np_model;                  /*cxfsnp model, e.g, CXFSNP_001G_MODEL*/
    uint8_t          np_2nd_chash_algo_id;
    uint16_t         rsvd1;
    uint32_t         np_item_max_num;           /*item max num per np*/
    uint32_t         np_max_num;                /*max np num*/

    UINT32           dn_zone_size;              /*dn zone size (meta data size)*/

    UINT32           op_s_offset;               /*operation log start offset on sata disk*/
    UINT32           op_e_offset;               /*operation log end offset on sata disk*/

    UINT32           np_zone_s_offset;          /*np zone start offset on sata disk, cover active np and standby np*/
    UINT32           np_zone_e_offset;          /*np zone end offset on sata disk, cover active np and standby np*/
    CXFSZONE         np_zone[2];                /*active np and standby np*/
    UINT32           np_zone_idx;               /*active np zone index, range in [0, 1]*/

    UINT32           dn_zone_s_offset;          /*dn zone start offset on sata disk, cover active dn and standby dn*/
    UINT32           dn_zone_e_offset;          /*dn zone end offset on sata disk, cover active dn and standby dn*/
    CXFSZONE         dn_zone[2];                /*active dn and standby dn*/
    UINT32           dn_zone_idx;               /*active dn zone index, range in [0, 1]*/

    UINT32           ssd_meta_size;             /*ssd meta size in bytes*/
    UINT32           ssd_disk_size;             /*ssd disk size in bytes*/
    UINT32           ssd_disk_offset;           /*ssd cache start offset in ssd disk*/

    /*dynamic data*/
    uint64_t         op_dump_time_msec;         /*the latest op dump succ time*/
}CXFSCFG;

#define CXFSCFG_MAGIC(cxfscfg)                         ((cxfscfg)->magic)

#define CXFSCFG_OFFSET(cxfscfg)                        ((cxfscfg)->offset)

#define CXFSCFG_SATA_META_SIZE(cxfscfg)                ((cxfscfg)->sata_meta_size)
#define CXFSCFG_SATA_DISK_SIZE(cxfscfg)                ((cxfscfg)->sata_disk_size)
#define CXFSCFG_SATA_DISK_OFFSET(cxfscfg)              ((cxfscfg)->sata_disk_offset)

#define CXFSCFG_SATA_VDISK_SIZE(cxfscfg)               ((cxfscfg)->sata_vdisk_size)
#define CXFSCFG_SATA_VDISK_NUM(cxfscfg)                ((cxfscfg)->sata_vdisk_num)

#define CXFSCFG_NP_SIZE(cxfscfg)                       ((cxfscfg)->np_size)
#define CXFSCFG_NP_MODEL(cxfscfg)                      ((cxfscfg)->np_model)
#define CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg)          ((cxfscfg)->np_2nd_chash_algo_id)
#define CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg)               ((cxfscfg)->np_item_max_num)
#define CXFSCFG_NP_MAX_NUM(cxfscfg)                    ((cxfscfg)->np_max_num)

#define CXFSCFG_DN_ZONE_SIZE(cxfscfg)                  ((cxfscfg)->dn_zone_size)

#define CXFSCFG_OP_S_OFFSET(cxfscfg)                   ((cxfscfg)->op_s_offset)
#define CXFSCFG_OP_E_OFFSET(cxfscfg)                   ((cxfscfg)->op_e_offset)

#define CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)              ((cxfscfg)->np_zone_s_offset)
#define CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg)              ((cxfscfg)->np_zone_e_offset)
#define CXFSCFG_NP_ZONE(cxfscfg, idx)                  (&((cxfscfg)->np_zone[ (idx) ]))
#define CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg)            ((cxfscfg)->np_zone_idx)
#define CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg)           (1 ^ CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg))

#define CXFSCFG_NP_ZONE_SWITCH(cxfscfg)                \
    do{                                                \
        CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg) ^= 1;      \
    }while(0)


#define CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg)              ((cxfscfg)->dn_zone_s_offset)
#define CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg)              ((cxfscfg)->dn_zone_e_offset)
#define CXFSCFG_DN_ZONE(cxfscfg, idx)                  (&((cxfscfg)->dn_zone[ (idx) ]))
#define CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg)            ((cxfscfg)->dn_zone_idx)
#define CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg)           (1 ^ CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg))
#define CXFSCFG_DN_ZONE_SWITCH(cxfscfg)                \
    do{                                                \
        CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg) ^= 1;      \
    }while(0)


#define CXFSCFG_SSD_META_SIZE(cxfscfg)                 ((cxfscfg)->ssd_meta_size)
#define CXFSCFG_SSD_DISK_SIZE(cxfscfg)                 ((cxfscfg)->ssd_disk_size)
#define CXFSCFG_SSD_DISK_OFFSET(cxfscfg)               ((cxfscfg)->ssd_disk_offset)

#define CXFSCFG_OP_DUMP_TIME_MSEC(cxfscfg)             ((cxfscfg)->op_dump_time_msec)
#define CXFSCFG_OP_DUMP_TIME_MSEC_STR(cxfscfg)         (c_get_time_msec_str(CXFSCFG_OP_DUMP_TIME_MSEC(cxfscfg)))


EC_BOOL cxfscfg_init(CXFSCFG *cxfscfg);

EC_BOOL cxfscfg_clean(CXFSCFG *cxfscfg);

void cxfscfg_print(LOG *log, const CXFSCFG *cxfscfg);

EC_BOOL cxfscfg_compute_offset(const UINT32 sata_disk_size, const UINT32 vdisk_size, UINT32 *offset);

EC_BOOL cxfscfg_load(CXFSCFG *cxfscfg, int fd, const UINT32 offset);

EC_BOOL cxfscfg_flush(const CXFSCFG *cxfscfg, int fd);

EC_BOOL cxfscfg_dump(const CXFSCFG *cxfscfg, CAMD_MD *camd_md);

#endif /*_CXFSCFG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

