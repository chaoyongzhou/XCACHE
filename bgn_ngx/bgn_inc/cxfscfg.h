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

#define CXFSCFG_MAGIC_NUM                  ((UINT32)0x3141592653589793) /* 3.14159 26535 89793*/

#define CXFSCFG_SIZE                       (256 * 1024) /*256KB*/

#define CXFSCFG_ALIGNMENT                  (1 << 20)    /*1MB*/

typedef struct
{
    UINT32           magic;                     /*magic number*/

    UINT32           sata_disk_size;

    UINT32           np_s_offset;               /*np start offset on sata disk*/
    UINT32           np_e_offset;               /*np end offset on sata disk*/
    UINT32           np_size;                   /*size per np*/
    uint8_t          np_model;                  /*cxfsnp model, e.g, CXFSNP_001G_MODEL*/
    uint8_t          np_2nd_chash_algo_id;
    uint16_t         rsvd1;
    uint32_t         np_item_max_num;           /*item max num per np*/
    uint32_t         np_max_num;                /*max np num*/

    UINT32           dn_s_offset;               /*dn start offset on sata disk*/
    UINT32           dn_e_offset;               /*dn end offset on sata disk*/
    UINT32           dn_size;                   /*dn size*/
}CXFSCFG;

#define CXFSCFG_MAGIC(cxfscfg)                         ((cxfscfg)->magic)

#define CXFSCFG_SATA_DISK_SIZE(cxfscfg)                ((cxfscfg)->sata_disk_size)

#define CXFSCFG_NP_S_OFFSET(cxfscfg)                   ((cxfscfg)->np_s_offset)
#define CXFSCFG_NP_E_OFFSET(cxfscfg)                   ((cxfscfg)->np_e_offset)
#define CXFSCFG_NP_SIZE(cxfscfg)                       ((cxfscfg)->np_size)
#define CXFSCFG_NP_MODEL(cxfscfg)                      ((cxfscfg)->np_model)
#define CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg)          ((cxfscfg)->np_2nd_chash_algo_id)
#define CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg)               ((cxfscfg)->np_item_max_num)
#define CXFSCFG_NP_MAX_NUM(cxfscfg)                    ((cxfscfg)->np_max_num)

#define CXFSCFG_DN_S_OFFSET(cxfscfg)                   ((cxfscfg)->dn_s_offset)
#define CXFSCFG_DN_E_OFFSET(cxfscfg)                   ((cxfscfg)->dn_e_offset)
#define CXFSCFG_DN_SIZE(cxfscfg)                       ((cxfscfg)->dn_size)


EC_BOOL cxfscfg_init(CXFSCFG *cxfscfg);

EC_BOOL cxfscfg_clean(CXFSCFG *cxfscfg);

void cxfscfg_print(LOG *log, const CXFSCFG *cxfscfg);

EC_BOOL cxfscfg_load(CXFSCFG *cxfscfg, int fd);

EC_BOOL cxfscfg_flush(const CXFSCFG *cxfscfg, int fd);

#endif /*_CXFSCFG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

