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

#ifndef    _CSFSV_H
#define    _CSFSV_H

#include "type.h"
#include "csfsd.h"
#include "csfsb.h"

#define CSFSV_001TB_DISK_NUM  ((uint16_t)(1 <<  0))
#define CSFSV_002TB_DISK_NUM  ((uint16_t)(1 <<  1))
#define CSFSV_004TB_DISK_NUM  ((uint16_t)(1 <<  2))
#define CSFSV_008TB_DISK_NUM  ((uint16_t)(1 <<  3))
#define CSFSV_016TB_DISK_NUM  ((uint16_t)(1 <<  4))
#define CSFSV_032TB_DISK_NUM  ((uint16_t)(1 <<  5))
#define CSFSV_064TB_DISK_NUM  ((uint16_t)(1 <<  6))

#define CSFSV_MAX_DISK_NUM               (CSFSV_064TB_DISK_NUM)

#define CSFSV_HDR_PAD_SIZE                (4088)


typedef struct
{
    /*disk pointer*/
    uint16_t     sfsv_cur_disk_no;
    uint16_t     sfsv_cur_block_no;
    uint16_t     sfsv_cur_page_no;

    uint16_t     sfsv_disk_num;      /*current disk number support up to*/

    uint8_t      rsvd01[CSFSV_HDR_PAD_SIZE];
}CSFSV_HDR;/*4k-alignment*/

#define CSFSV_HDR_CUR_DISK_NO(csfsv_hdr)                          ((csfsv_hdr)->sfsv_cur_disk_no)
#define CSFSV_HDR_CUR_BLOCK_NO(csfsv_hdr)                         ((csfsv_hdr)->sfsv_cur_block_no)
#define CSFSV_HDR_CUR_PAGE_NO(csfsv_hdr)                          ((csfsv_hdr)->sfsv_cur_page_no)
#define CSFSV_HDR_DISK_NUM(csfsv_hdr)                             ((csfsv_hdr)->sfsv_disk_num)


typedef struct
{
    int                 sfsv_fd;
    int                 rsvd1;
    uint8_t            *sfsv_fname;
    uint32_t            sfsv_fsize;
    uint32_t            rsvd2;
    CSFSV_HDR          *sfsv_hdr;
    CSFSD              *sfsv_disk_tbl[CSFSV_MAX_DISK_NUM];

    /*name node handlers*/
    uint32_t           np_node_err_pos;
    uint32_t           rsvd3;
    CSFSNP_RECYCLE     np_node_recycle;
    void              *npp;
}CSFSV;

#define CSFSV_FD(csfsv)                                            ((csfsv)->sfsv_fd)
#define CSFSV_FNAME(csfsv)                                         ((csfsv)->sfsv_fname)
#define CSFSV_FSIZE(csfsv)                                         ((csfsv)->sfsv_fsize)
#define CSFSV_HEADER(csfsv)                                        ((csfsv)->sfsv_hdr)
#define CSFSV_CUR_DISK_NO(csfsv)                                   (CSFSV_HDR_CUR_DISK_NO(CSFSV_HEADER(csfsv)))
#define CSFSV_CUR_BLOCK_NO(csfsv)                                  (CSFSV_HDR_CUR_BLOCK_NO(CSFSV_HEADER(csfsv)))
#define CSFSV_CUR_PAGE_NO(csfsv)                                   (CSFSV_HDR_CUR_PAGE_NO(CSFSV_HEADER(csfsv)))
#define CSFSV_DISK_NUM(csfsv)                                      (CSFSV_HDR_DISK_NUM(CSFSV_HEADER(csfsv)))
#define CSFSV_DISK_TBL(csfsv)                                      ((csfsv)->sfsv_disk_tbl)
#define CSFSV_DISK_CSFSD(csfsv, disk_no)                            ((csfsv)->sfsv_disk_tbl[ disk_no ])

#define CSFSV_NP_NODE_ERR_POS(csfsv)                               ((csfsv)->np_node_err_pos)
#define CSFSV_NP_NODE_RECYCLE(csfsv)                               ((csfsv)->np_node_recycle)
#define CSFSV_NPP(csfsv)                                           ((csfsv)->npp)

#define CSFSV_DISK_NODE(csfsv, disk_no)                            ((CSFSV_MAX_DISK_NUM <= (disk_no)) ? NULL_PTR : CSFSV_DISK_CSFSD(csfsv, disk_no))


EC_BOOL csfsv_hdr_init(CSFSV *csfsv);

EC_BOOL csfsv_hdr_clean(CSFSV *csfsv);

CSFSV_HDR *csfsv_hdr_create(CSFSV *csfsv);

CSFSV_HDR *csfsv_hdr_open(CSFSV *csfsv);

EC_BOOL csfsv_hdr_close(CSFSV *csfsv);

EC_BOOL csfsv_hdr_sync(CSFSV *csfsv);

CSFSV *csfsv_new(const uint8_t *csfsv_dat_file, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp);

EC_BOOL csfsv_free(CSFSV *csfsv);

CSFSV *csfsv_open(const uint8_t *csfsv_fname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp);

EC_BOOL csfsv_close(CSFSV *csfsv);

EC_BOOL csfsv_sync(CSFSV *csfsv);

/* one disk = 1TB */
EC_BOOL csfsv_init(CSFSV *csfsv);

EC_BOOL csfsv_clean(CSFSV *csfsv);

EC_BOOL csfsv_set_np(CSFSV *csfsv, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp);

EC_BOOL csfsv_add_disk(CSFSV *csfsv, const uint16_t disk_no);

EC_BOOL csfsv_del_disk(CSFSV *csfsv, const uint16_t disk_no);

EC_BOOL csfsv_mount_disk(CSFSV *csfsv, const uint16_t disk_no);

EC_BOOL csfsv_umount_disk(CSFSV *csfsv, const uint16_t disk_no);

EC_BOOL csfsv_new_space(CSFSV *csfsv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL csfsv_bind(CSFSV *csfsv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t np_id, const uint32_t np_node_pos);

EC_BOOL csfsv_flush_size(const CSFSV *csfsv, UINT32 *size);

EC_BOOL csfsv_flush(const CSFSV *csfsv, int fd, UINT32 *offset);

EC_BOOL csfsv_load(CSFSV *csfsv, int fd, UINT32 *offset);

void csfsv_print(LOG *log, const CSFSV *csfsv);


#endif    /* _CSFSV_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
