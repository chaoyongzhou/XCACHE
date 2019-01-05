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

#ifndef    _CMCPGV_H
#define    _CMCPGV_H

#include "type.h"
#include "cmcpgrb.h"
#include "cmcpgd.h"


#define CMCPGV_MAX_DISK_NUM               (12)

typedef struct
{
    uint16_t        pgv_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/
    uint16_t        pgv_disk_num;      /*current disk number support up to*/
    uint32_t        rsvd1;

    uint64_t        pgv_page_max_num; /*max pages number */
    uint64_t        pgv_page_used_num;/*used pages number*/
    uint64_t        pgv_actual_used_size;/*actual used bytes*/

    uint16_t        pgv_disk_rb_root_pos[ CMCPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t        rsvd2;

    CMCPGRB_POOL    pgv_disk_rb_pool;
}CMCPGV_HDR;

#define CMCPGV_HDR_CMCPGRB_POOL(cmcpgv_hdr)                         (&((cmcpgv_hdr)->pgv_disk_rb_pool))
#define CMCPGV_HDR_DISK_CMCPGRB_ROOT_POS_TBL(cmcpgv_hdr)            ((cmcpgv_hdr)->pgv_disk_rb_root_pos)
#define CMCPGV_HDR_DISK_CMCPGRB_ROOT_POS(cmcpgv_hdr, page_model)    ((cmcpgv_hdr)->pgv_disk_rb_root_pos[ (page_model) ])
#define CMCPGV_HDR_ASSIGN_BITMAP(cmcpgv_hdr)                        ((cmcpgv_hdr)->pgv_assign_bitmap)
#define CMCPGV_HDR_PAGE_DISK_NUM(cmcpgv_hdr)                        ((cmcpgv_hdr)->pgv_disk_num)
#define CMCPGV_HDR_PAGE_MAX_NUM(cmcpgv_hdr)                         ((cmcpgv_hdr)->pgv_page_max_num)
#define CMCPGV_HDR_PAGE_USED_NUM(cmcpgv_hdr)                        ((cmcpgv_hdr)->pgv_page_used_num)
#define CMCPGV_HDR_PAGE_ACTUAL_USED_SIZE(cmcpgv_hdr)                ((cmcpgv_hdr)->pgv_actual_used_size)

#define CMCPGV_HDR_SIZE     (sizeof(CMCPGV_HDR) + sizeof(CMCPGRB_NODE) * CMCPGV_MAX_DISK_NUM)

typedef struct
{
    uint32_t        pgv_size;
    uint32_t        rsvd1;
    CMCPGV_HDR     *pgv_hdr;
    CMCPGD         *pgv_disk_tbl[CMCPGV_MAX_DISK_NUM];
}CMCPGV;

#define CMCPGV_SIZE(cmcpgv)                                          ((cmcpgv)->pgv_size)
#define CMCPGV_HEADER(cmcpgv)                                        ((cmcpgv)->pgv_hdr)
#define CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv)                        (CMCPGV_HDR_CMCPGRB_POOL(CMCPGV_HEADER(cmcpgv)))
#define CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS_TBL(cmcpgv)          (CMCPGV_HDR_DISK_CMCPGRB_ROOT_POS_TBL(CMCPGV_HEADER(cmcpgv)))
#define CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model)  (CMCPGV_HDR_DISK_CMCPGRB_ROOT_POS(CMCPGV_HEADER(cmcpgv), page_model))
#define CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)                      (CMCPGV_HDR_ASSIGN_BITMAP(CMCPGV_HEADER(cmcpgv)))
#define CMCPGV_PAGE_DISK_NUM(cmcpgv)                                 (CMCPGV_HDR_PAGE_DISK_NUM(CMCPGV_HEADER(cmcpgv)))
#define CMCPGV_PAGE_MAX_NUM(cmcpgv)                                  (CMCPGV_HDR_PAGE_MAX_NUM(CMCPGV_HEADER(cmcpgv)))
#define CMCPGV_PAGE_USED_NUM(cmcpgv)                                 (CMCPGV_HDR_PAGE_USED_NUM(CMCPGV_HEADER(cmcpgv)))
#define CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv)                         (CMCPGV_HDR_PAGE_ACTUAL_USED_SIZE(CMCPGV_HEADER(cmcpgv)))
#define CMCPGV_DISK_TBL(cmcpgv)                                      ((cmcpgv)->pgv_disk_tbl)
#define CMCPGV_DISK_CMCPGD(cmcpgv, disk_no)                          ((cmcpgv)->pgv_disk_tbl[ disk_no ])
#define CMCPGV_DISK_NODE(cmcpgv, disk_no)                            ((CMCPGV_MAX_DISK_NUM <= (disk_no)) ? NULL_PTR : CMCPGV_DISK_CMCPGD(cmcpgv, disk_no))


EC_BOOL cmcpgv_hdr_init(CMCPGV *cmcpgv);

CMCPGV_HDR *cmcpgv_hdr_new(CMCPGV *cmcpgv);

EC_BOOL cmcpgv_hdr_free(CMCPGV *cmcpgv);

REAL cmcpgv_hdr_used_ratio(const CMCPGV *cmcpgv);

EC_BOOL cmcpgv_free(CMCPGV *cmcpgv);

/* one page cache disk = 32GB */
EC_BOOL cmcpgv_init(CMCPGV *cmcpgv);

void cmcpgv_clean(CMCPGV *cmcpgv);

EC_BOOL cmcpgv_add_disk(CMCPGV *cmcpgv, const uint16_t disk_no);

EC_BOOL cmcpgv_del_disk(CMCPGV *cmcpgv, const uint16_t disk_no);

EC_BOOL cmcpgv_new_space_from_disk(CMCPGV *cmcpgv, const uint32_t size, const uint16_t disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cmcpgv_new_space(CMCPGV *cmcpgv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cmcpgv_free_space(CMCPGV *cmcpgv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cmcpgv_is_full(const CMCPGV *cmcpgv);

EC_BOOL cmcpgv_is_empty(const CMCPGV *cmcpgv);

EC_BOOL cmcpgv_check(const CMCPGV *cmcpgv);

REAL cmcpgv_used_ratio(const CMCPGV *cmcpgv);

void cmcpgv_print(LOG *log, const CMCPGV *cmcpgv);

CMCPGV *cmcpgv_new();

EC_BOOL cmcpgv_free(CMCPGV *cmcpgv);

/* ---- debug ---- */
EC_BOOL cmcpgv_debug_cmp(const CMCPGV *cmcpgv_1st, const CMCPGV *cmcpgv_2nd);


#endif    /* _CMCPGV_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
