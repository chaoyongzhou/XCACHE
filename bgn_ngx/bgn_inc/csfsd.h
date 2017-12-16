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

#ifndef    _CSFSD_H
#define    _CSFSD_H

#include "type.h"
#include "csfsb.h"

/*for 64MB-block*/
#define CSFSD_064MB_BLOCK_NUM  ((uint16_t)(1 <<  0))
#define CSFSD_128MB_BLOCK_NUM  ((uint16_t)(1 <<  1))
#define CSFSD_256MB_BLOCK_NUM  ((uint16_t)(1 <<  2))
#define CSFSD_512MB_BLOCK_NUM  ((uint16_t)(1 <<  3))
#define CSFSD_001GB_BLOCK_NUM  ((uint16_t)(1 <<  4))
#define CSFSD_002GB_BLOCK_NUM  ((uint16_t)(1 <<  5))
#define CSFSD_004GB_BLOCK_NUM  ((uint16_t)(1 <<  6))
#define CSFSD_008GB_BLOCK_NUM  ((uint16_t)(1 <<  7))
#define CSFSD_016GB_BLOCK_NUM  ((uint16_t)(1 <<  8))
#define CSFSD_032GB_BLOCK_NUM  ((uint16_t)(1 <<  9))
#define CSFSD_064GB_BLOCK_NUM  ((uint16_t)(1 << 10))
#define CSFSD_128GB_BLOCK_NUM  ((uint16_t)(1 << 11))
#define CSFSD_256GB_BLOCK_NUM  ((uint16_t)(1 << 12))
#define CSFSD_512GB_BLOCK_NUM  ((uint16_t)(1 << 13))
#define CSFSD_001TB_BLOCK_NUM  ((uint16_t)(1 << 14))

#define CSFSD_ERROR_BLOCK_NUM  ((uint16_t)        0)

/*************************************************************
*    CSFSD_MAX_BLOCK_NUM   : how many blocks per disk
*************************************************************/

#define CSFSD_TEST_SCENARIO_256M_DISK     (1)
#define CSFSD_TEST_SCENARIO_512M_DISK     (2)
#define CSFSD_TEST_SCENARIO_032G_DISK     (3)
#define CSFSD_TEST_SCENARIO_512G_DISK     (4)
#define CSFSD_TEST_SCENARIO_001T_DISK     (5)

#if (32 == WORDSIZE)
#define CSFSD_DEBUG_CHOICE CSFSD_TEST_SCENARIO_512M_DISK
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
//#define CSFSD_DEBUG_CHOICE CSFSD_TEST_SCENARIO_256M_DISK
//#define CSFSD_DEBUG_CHOICE CSFSD_TEST_SCENARIO_032G_DISK
//#define CSFSD_DEBUG_CHOICE CSFSD_TEST_SCENARIO_512G_DISK
#define CSFSD_DEBUG_CHOICE CSFSD_TEST_SCENARIO_001T_DISK
#endif/*(64 == WORDSIZE)*/

#if (CSFSD_TEST_SCENARIO_001T_DISK == CSFSD_DEBUG_CHOICE)
#define CSFSD_MAX_BLOCK_NUM               (CSFSD_001TB_BLOCK_NUM)
#endif/*(CSFSD_TEST_SCENARIO_001T_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_512G_DISK == CSFSD_DEBUG_CHOICE)
#define CSFSD_DEBUG_GB_PER_DISK           (512)
#define CSFSD_MAX_BLOCK_NUM               (CSFSD_512GB_BLOCK_NUM)
#endif/*(CSFSD_TEST_SCENARIO_032G_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_256M_DISK == CSFSD_DEBUG_CHOICE)
#define CSFSD_DEBUG_MB_PER_DISK           (256)
#define CSFSD_MAX_BLOCK_NUM               (CSFSD_256MB_BLOCK_NUM)
#endif/*(CSFSD_TEST_SCENARIO_256M_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_512M_DISK == CSFSD_DEBUG_CHOICE)
#define CSFSD_DEBUG_MB_PER_DISK           (512)
#define CSFSD_MAX_BLOCK_NUM               (CSFSD_512MB_BLOCK_NUM)
#endif/*(CSFSD_TEST_SCENARIO_512M_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_032G_DISK == CSFSD_DEBUG_CHOICE)
#define CSFSD_DEBUG_GB_PER_DISK           (32)
#define CSFSD_MAX_BLOCK_NUM               (CSFSD_032GB_BLOCK_NUM)
#endif/*(CSFSD_TEST_SCENARIO_032G_DISK == CSFSD_DEBUG_CHOICE)*/

#define CSFSD_HDR_PAD_SIZE                (4088)

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    uint16_t       block_num;
    uint16_t       rsvd01;
    uint32_t       rsvd02;
}CSFSD_CFG;

#define CSFSD_CFG_MODEL_STR(csfsd_cfg)     ((csfsd_cfg)->model_str)
#define CSFSD_CFG_ALIAS_STR(csfsd_cfg)     ((csfsd_cfg)->alias_str)
#define CSFSD_CFG_BLOCK_NUM(csfsd_cfg)     ((csfsd_cfg)->block_num)


#define CSFSD_PAGE_NOT_USED                ((uint32_t)0)
#define CSFSD_PAGE_USED                    ((uint32_t)1)

typedef struct
{
    uint16_t     sfsd_block_max_num; /*max block number */    
    uint16_t     rsvd01;
    uint32_t     sfsd_page_max_num;  /*max pages number */
}CSFSD_HDR;/*4k-alignment*/

#define CSFSD_HDR_BLOCK_MAX_NUM(csfsd_hdr)                        ((csfsd_hdr)->sfsd_block_max_num)
#define CSFSD_HDR_PAGE_MAX_NUM(csfsd_hdr)                         ((csfsd_hdr)->sfsd_page_max_num)


typedef struct
{
    int                sfsd_fd;
    uint32_t           sfsd_fsize;
    uint8_t           *sfsd_fname;
    
    CSFSD_HDR         *sfsd_hdr;

    CSFSB             *sfsd_block_tbl[ CSFSD_MAX_BLOCK_NUM ];

    /*name node handlers*/
    uint32_t           np_node_err_pos;
    uint32_t           rsvd;
    CSFSNP_RECYCLE     np_node_recycle;
    void              *npp;
}CSFSD;

#define CSFSD_FD(csfsd)                                            ((csfsd)->sfsd_fd)
#define CSFSD_FNAME(csfsd)                                         ((csfsd)->sfsd_fname)
#define CSFSD_FSIZE(csfsd)                                         ((csfsd)->sfsd_fsize)
#define CSFSD_HEADER(csfsd)                                        ((csfsd)->sfsd_hdr)

#define CSFSD_NP_NODE_ERR_POS(csfsd)                               ((csfsd)->np_node_err_pos)
#define CSFSD_NP_NODE_RECYCLE(csfsd)                               ((csfsd)->np_node_recycle)
#define CSFSD_NPP(csfsd)                                           ((csfsd)->npp)

#define CSFSD_BLOCK_MAX_NUM(csfsd)                                 (CSFSD_HDR_BLOCK_MAX_NUM(CSFSD_HEADER(csfsd)))
#define CSFSD_PAGE_MAX_NUM(csfsd)                                  (CSFSD_HDR_PAGE_MAX_NUM(CSFSD_HEADER(csfsd)))

#define CSFSD_BLOCK_TBL(csfsd)                                     ((csfsd)->sfsd_block_tbl) 
#define CSFSD_BLOCK_NODE(csfsd, block_no)                          ((csfsd)->sfsd_block_tbl[ (block_no) ]) 



const char *csfsd_model_str(const uint16_t sfsd_block_num);
uint16_t csfsd_model_get(const char *model_str);

CSFSD_HDR *csfsd_hdr_mem_new(CSFSD *csfsd, const uint16_t block_num);

EC_BOOL csfsd_hdr_mem_clean(CSFSD *csfsd);

EC_BOOL csfsd_hdr_mem_free(CSFSD *csfsd);

CSFSD_HDR *csfsd_hdr_new(CSFSD *csfsd, const uint16_t block_num);

EC_BOOL csfsd_hdr_free(CSFSD *csfsd);

CSFSD_HDR *csfsd_hdr_open(CSFSD *csfsd);

EC_BOOL csfsd_hdr_close(CSFSD *csfsd);

EC_BOOL csfsd_hdr_sync(CSFSD *csfsd);

CSFSD *csfsd_new(const uint8_t *csfsd_fname, const uint16_t block_num, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *np);

EC_BOOL csfsd_free(CSFSD *csfsd);

EC_BOOL csfsd_exist(const uint8_t *csfsd_fname);

EC_BOOL csfsd_rmv(const uint8_t *csfsd_fname);

CSFSD *csfsd_open(const uint8_t *csfsd_fname);

EC_BOOL csfsd_close(CSFSD *csfsd);

EC_BOOL csfsd_sync(CSFSD *csfsd);

/* one disk = 1TB */
EC_BOOL csfsd_init(CSFSD *csfsd);

EC_BOOL csfsd_clean(CSFSD *csfsd);

EC_BOOL csfsd_set_np(CSFSD *csfsd, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp);

EC_BOOL csfsd_new_space(CSFSD *csfsd, const uint16_t page_num, uint16_t *block_no, uint16_t *page_no);

EC_BOOL csfsd_bind(CSFSD *csfsd, const uint16_t block_no, const uint16_t page_no, const uint32_t np_id, const uint32_t np_node_pos);

EC_BOOL csfsd_flush_size(const CSFSD *csfsd, UINT32 *size);

EC_BOOL csfsd_flush(const CSFSD *csfsd, int fd, UINT32 *offset);

EC_BOOL csfsd_load(CSFSD *csfsd, int fd, UINT32 *offset);

void csfsd_print(LOG *log, const CSFSD *csfsd);


/* ---- debug ---- */
EC_BOOL csfsd_debug_cmp(const CSFSD *csfsd_1st, const CSFSD *csfsd_2nd);


/*-------------------------------------------- DISK in memory --------------------------------------------*/
CSFSD *csfsd_mem_new(const uint16_t block_num);

EC_BOOL csfsd_mem_free(CSFSD *csfsd);


#endif    /* _CSFSD_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
