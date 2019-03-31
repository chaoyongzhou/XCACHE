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

#ifndef    _CDCPGV_H
#define    _CDCPGV_H

#include "type.h"
#include "cdcpgrb.h"
#include "cdcpgd.h"


/*CDC support up to 1TB where 1TB = 2^40 B*/
#define CDCPGV_MAX_BLOCK_NUM              (UINT32_ONE << (40 - CDCPGB_SIZE_NBITS))
#define CDCPGV_MAX_DISK_NUM               ((uint16_t)(CDCPGV_MAX_BLOCK_NUM / CDCPGD_MAX_BLOCK_NUM))

#define CDCPGV_ERR_OFFSET                 ((UINT32)~0)

typedef struct
{
    /*header range: [start, end)*/
    UINT32          base_s_offset;       /*start offset of this header*/
    UINT32          base_e_offset;       /*end offset of this header (aligned to one page)*/

    UINT32          node_num;

    /*disk storage range: [start, end)*/
    UINT32          node_s_offset;       /*start offset of disk storage (aligned to one block)*/
    UINT32          node_e_offset;       /*end offset of disk storage (aligned to one block). end = start + len*/

    uint16_t        pgv_assign_bitmap;   /*when some page model can provide pages or can borrow from upper, set bit to 1*/
    uint16_t        pgv_disk_num;        /*current disk number support up to*/
    uint32_t        rsvd1;

    uint64_t        pgv_page_max_num;    /*max pages number */
    uint64_t        pgv_page_used_num;   /*used pages number*/
    uint64_t        pgv_actual_used_size;/*actual used bytes*/

    uint16_t        pgv_disk_rb_root_pos[ CDCPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t        rsvd2;

    CDCPGRB_POOL    pgv_disk_rb_pool;
}CDCPGV_HDR;

#define CDCPGV_HDR_CDCPGRB_POOL(cdcpgv_hdr)                         (&((cdcpgv_hdr)->pgv_disk_rb_pool))
#define CDCPGV_HDR_DISK_CDCPGRB_ROOT_POS_TBL(cdcpgv_hdr)            ((cdcpgv_hdr)->pgv_disk_rb_root_pos)
#define CDCPGV_HDR_DISK_CDCPGRB_ROOT_POS(cdcpgv_hdr, page_model)    ((cdcpgv_hdr)->pgv_disk_rb_root_pos[ (page_model) ])
#define CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)                             ((cdcpgv_hdr)->node_num)
#define CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr)                        ((cdcpgv_hdr)->base_s_offset)
#define CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr)                        ((cdcpgv_hdr)->base_e_offset)
#define CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr)                        ((cdcpgv_hdr)->node_s_offset)
#define CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr)                        ((cdcpgv_hdr)->node_e_offset)
#define CDCPGV_HDR_ASSIGN_BITMAP(cdcpgv_hdr)                        ((cdcpgv_hdr)->pgv_assign_bitmap)
#define CDCPGV_HDR_PAGE_DISK_NUM(cdcpgv_hdr)                        ((cdcpgv_hdr)->pgv_disk_num)
#define CDCPGV_HDR_PAGE_MAX_NUM(cdcpgv_hdr)                         ((cdcpgv_hdr)->pgv_page_max_num)
#define CDCPGV_HDR_PAGE_USED_NUM(cdcpgv_hdr)                        ((cdcpgv_hdr)->pgv_page_used_num)
#define CDCPGV_HDR_PAGE_ACTUAL_USED_SIZE(cdcpgv_hdr)                ((cdcpgv_hdr)->pgv_actual_used_size)

#define CDCPGV_HDR_SIZE     (sizeof(CDCPGV_HDR) + sizeof(CDCPGRB_NODE) * CDCPGV_MAX_DISK_NUM)

typedef struct
{
    uint32_t        pgv_size;
    uint32_t        rsvd1;
    CDCPGV_HDR     *pgv_hdr;    /*mount point of m_base of cdcdn */
    CDCPGD         *pgv_disk_tbl[ CDCPGV_MAX_DISK_NUM ];
}CDCPGV;

#define CDCPGV_SIZE(cdcpgv)                                          ((cdcpgv)->pgv_size)
#define CDCPGV_HEADER(cdcpgv)                                        ((cdcpgv)->pgv_hdr)
#define CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv)                        (CDCPGV_HDR_CDCPGRB_POOL(CDCPGV_HEADER(cdcpgv)))
#define CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS_TBL(cdcpgv)          (CDCPGV_HDR_DISK_CDCPGRB_ROOT_POS_TBL(CDCPGV_HEADER(cdcpgv)))
#define CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model)  (CDCPGV_HDR_DISK_CDCPGRB_ROOT_POS(CDCPGV_HEADER(cdcpgv), page_model))
#define CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)                      (CDCPGV_HDR_ASSIGN_BITMAP(CDCPGV_HEADER(cdcpgv)))
#define CDCPGV_PAGE_DISK_NUM(cdcpgv)                                 (CDCPGV_HDR_PAGE_DISK_NUM(CDCPGV_HEADER(cdcpgv)))
#define CDCPGV_PAGE_MAX_NUM(cdcpgv)                                  (CDCPGV_HDR_PAGE_MAX_NUM(CDCPGV_HEADER(cdcpgv)))
#define CDCPGV_PAGE_USED_NUM(cdcpgv)                                 (CDCPGV_HDR_PAGE_USED_NUM(CDCPGV_HEADER(cdcpgv)))
#define CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv)                         (CDCPGV_HDR_PAGE_ACTUAL_USED_SIZE(CDCPGV_HEADER(cdcpgv)))
#define CDCPGV_DISK_TBL(cdcpgv)                                      ((cdcpgv)->pgv_disk_tbl)
#define CDCPGV_DISK_CDCPGD(cdcpgv, disk_no)                          ((cdcpgv)->pgv_disk_tbl[ disk_no ])
#define CDCPGV_DISK_NODE(cdcpgv, disk_no)                            ((CDCPGV_MAX_DISK_NUM <= (disk_no)) ? NULL_PTR : CDCPGV_DISK_CDCPGD(cdcpgv, disk_no))

UINT8 *cdcpgv_mcache_new(const UINT32 size);

void cdcpgv_mcache_free(UINT8 *base);

EC_BOOL cdcpgv_hdr_init(CDCPGV *cdcpgv);

EC_BOOL cdcpgv_hdr_new(CDCPGV *cdcpgv);

EC_BOOL cdcpgv_hdr_free(CDCPGV *cdcpgv);

EC_BOOL cdcpgv_hdr_close(CDCPGV *cdcpgv);

REAL cdcpgv_hdr_used_ratio(const CDCPGV *cdcpgv);

EC_BOOL cdcpgv_hdr_max_size(UINT32 *size);

CDCPGV *cdcpgv_new();

EC_BOOL cdcpgv_free(CDCPGV *cdcpgv);

/* one page cache disk = 32GB */
EC_BOOL cdcpgv_init(CDCPGV *cdcpgv);

void cdcpgv_clean(CDCPGV *cdcpgv);

EC_BOOL cdcpgv_clear(CDCPGV *cdcpgv);

CDCPGV *cdcpgv_open();

EC_BOOL cdcpgv_close(CDCPGV *cdcpgv);

EC_BOOL cdcpgv_add_disk(CDCPGV *cdcpgv, const uint16_t disk_no, UINT8 *base, UINT32 *pos);

EC_BOOL cdcpgv_del_disk(CDCPGV *cdcpgv, const uint16_t disk_no);

EC_BOOL cdcpgv_new_space_from_disk(CDCPGV *cdcpgv, const uint32_t size, const uint16_t disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cdcpgv_new_space(CDCPGV *cdcpgv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cdcpgv_free_space(CDCPGV *cdcpgv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cdcpgv_is_full(const CDCPGV *cdcpgv);

EC_BOOL cdcpgv_is_empty(const CDCPGV *cdcpgv);

EC_BOOL cdcpgv_aligned_size(UINT32 *size, const UINT32 mask);

EC_BOOL cdcpgv_max_size(UINT32 *size);

EC_BOOL cdcpgv_load(CDCPGV *cdcpgv, UINT8 *base, UINT32 *pos);

EC_BOOL cdcpgv_check(const CDCPGV *cdcpgv);

void cdcpgv_print(LOG *log, const CDCPGV *cdcpgv);

REAL cdcpgv_used_ratio(const CDCPGV *cdcpgv);


/* ---- debug ---- */
EC_BOOL cdcpgv_debug_cmp(const CDCPGV *cdcpgv_1st, const CDCPGV *cdcpgv_2nd);


#endif    /* _CDCPGV_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
