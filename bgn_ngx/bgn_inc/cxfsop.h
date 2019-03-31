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

#ifndef _CXFSOP_H
#define _CXFSOP_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "real.h"

#include "camd.h"

#define CXFSOP_CHOICE_NP        ((uint16_t)0)
#define CXFSOP_CHOICE_DN        ((uint16_t)1)

#define CXFSOP_NP_ERR_OP        ((uint16_t)0x00)
#define CXFSOP_NP_ADD_OP        ((uint16_t)0x01)  /*reserve operation*/
#define CXFSOP_NP_DEL_OP        ((uint16_t)0x02)  /*release operation*/
#define CXFSOP_NP_UPD_OP        ((uint16_t)0x03)  /*update operation*/

#define CXFSOP_DN_ERR_OP        ((uint16_t)0x0000)
#define CXFSOP_DN_RSV_OP        ((uint16_t)0x0001) /*reserve space operation*/
#define CXFSOP_DN_REL_OP        ((uint16_t)0x0002) /*release space operation*/

#define CXFSOP_MAGIC_NUM        (0x27182818)       /*e*/

typedef struct
{
    /*8B*/
    uint64_t            time;          /*operation log recording time*/

    /*4B*/
    uint32_t            magic;

    /*2B*/
    uint16_t            choice   :1;    /*np or dn*/
    uint16_t            op       :2;    /*operation*/
    uint16_t            size     :12;   /*total size including header, key and optional fnode. size < 4KB*/
    uint16_t            rsvd01   :1;

    /*2B*/
    uint16_t            rsvd02;
}CXFSOP_COMM_HDR;/*16B*/

#define CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)           ((cxfsop_comm_hdr)->time)
#define CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr)          ((cxfsop_comm_hdr)->magic)
#define CXFSOP_COMM_HDR_CHOICE(cxfsop_comm_hdr)         ((cxfsop_comm_hdr)->choice)
#define CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)             ((cxfsop_comm_hdr)->op)
#define CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr)           ((cxfsop_comm_hdr)->size)

typedef struct
{
    /*8B*/
    uint64_t            time;          /*operation log recording time*/

    /*4B*/
    uint32_t            magic;

    /*2B*/
    uint16_t            choice   :1;    /*np or dn*/
    uint16_t            op       :2;    /*operation*/
    uint16_t            size     :12;   /*total size including header, key and optional fnode. size < 4KB*/
    uint16_t            wildcard :1;

    /*2B*/
    uint16_t            dflag    :4;
    uint16_t            klen     :12;   /*key/path len < 4KB*/
    uint8_t             key[ 0 ];
    /* note: next is CXFSOP_NP_FNODE if dflag is REG FILE */
}CXFSOP_NP_HDR;/*>=16B*/

#define CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)           ((cxfsop_np_hdr)->time)
#define CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)          ((cxfsop_np_hdr)->magic)
#define CXFSOP_NP_HDR_CHOICE(cxfsop_np_hdr)         ((cxfsop_np_hdr)->choice)
#define CXFSOP_NP_HDR_OP(cxfsop_np_hdr)             ((cxfsop_np_hdr)->op)
#define CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)           ((cxfsop_np_hdr)->size)
#define CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr)       ((cxfsop_np_hdr)->wildcard)

#define CXFSOP_NP_HDR_DFLAG(cxfsop_np_hdr)          ((cxfsop_np_hdr)->dflag)
#define CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)           ((cxfsop_np_hdr)->klen)
#define CXFSOP_NP_HDR_KEY(cxfsop_np_hdr)            ((cxfsop_np_hdr)->key)

typedef struct
{
    /*8B*/
    uint64_t            time;       /*operation log recording time*/

    /*4B*/
    uint32_t            magic;

    /*2B*/
    uint16_t            choice   :1;    /*np or dn*/
    uint16_t            op       :2;    /*operation*/
    uint16_t            size     :12;   /*total size including header, key and optional fnode. size < 4KB*/
    uint16_t            rsvd01   :1;

    /*10B*/
    uint16_t            disk_no;
    uint16_t            block_no;
    uint16_t            page_no;
    uint32_t            data_len;
}CXFSOP_DN_NODE;/*24B*/

#define CXFSOP_DN_NODE_TIME(cxfsop_dn_node)           ((cxfsop_dn_node)->time)
#define CXFSOP_DN_NODE_MAGIC(cxfsop_dn_node)          ((cxfsop_dn_node)->magic)
#define CXFSOP_DN_NODE_CHOICE(cxfsop_dn_node)         ((cxfsop_dn_node)->choice)
#define CXFSOP_DN_NODE_OP(cxfsop_dn_node)             ((cxfsop_dn_node)->op)
#define CXFSOP_DN_NODE_SIZE(cxfsop_dn_node)           ((cxfsop_dn_node)->size)

#define CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node)        ((cxfsop_dn_node)->disk_no)
#define CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node)       ((cxfsop_dn_node)->block_no)
#define CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node)        ((cxfsop_dn_node)->page_no)
#define CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node)       ((cxfsop_dn_node)->data_len)

typedef struct
{
    uint32_t            file_size:28;    /*data/value length <= 64M = 2^26B*/
    uint32_t            rsvd01   :4;
    uint16_t            disk_no;        /*file in disk no*/
    uint16_t            block_no;       /*file in block no*/
    uint16_t            page_no;        /*file start from page no*/
    uint16_t            rsvd02;
    uint32_t            rsvd03;
}CXFSOP_NP_FNODE;/*16B*/

#define CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode)         ((cxfsop_np_fnode)->file_size)
#define CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode)        ((cxfsop_np_fnode)->disk_no)
#define CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode)       ((cxfsop_np_fnode)->block_no)
#define CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode)        ((cxfsop_np_fnode)->page_no)

typedef struct
{
    uint64_t            size;    /*max size in bytes of data*/
    uint64_t            used;    /*used size in bytes of data*/
    void               *data;

    CAMD_MD            *camd;
}CXFSOP_MGR;

#define CXFSOP_MGR_SIZE(cxfsop_mgr)          ((cxfsop_mgr)->size)
#define CXFSOP_MGR_USED(cxfsop_mgr)          ((cxfsop_mgr)->used)
#define CXFSOP_MGR_DATA(cxfsop_mgr)          ((cxfsop_mgr)->data)
#define CXFSOP_MGR_CAMD(cxfsop_mgr)          ((cxfsop_mgr)->camd)


const char *cxfsop_mgr_np_op_str(const uint32_t op);

const char *cxfsop_mgr_dn_op_str(const uint32_t op);

CXFSOP_MGR *cxfsop_mgr_new();

EC_BOOL cxfsop_mgr_init(CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsop_mgr_clean(CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsop_mgr_free(CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsop_mgr_make(CXFSOP_MGR *cxfsop_mgr, const uint64_t size);

CXFSOP_MGR *cxfsop_mgr_create(const uint32_t size);

EC_BOOL cxfsop_mgr_mount_data(CXFSOP_MGR *cxfsop_mgr, const uint64_t size, void *data);

EC_BOOL cxfsop_mgr_umount_data(CXFSOP_MGR *cxfsop_mgr, uint64_t *size, void **data);

void cxfsop_mgr_print(LOG *log, const CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsop_mgr_is_full(const CXFSOP_MGR *cxfsop_mgr);

uint64_t cxfsop_mgr_size(const CXFSOP_MGR *cxfsop_mgr);

uint64_t cxfsop_mgr_used(const CXFSOP_MGR *cxfsop_mgr);

REAL cxfsop_mgr_used_ratio(const CXFSOP_MGR *cxfsop_mgr);

uint64_t cxfsop_mgr_room(const CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsop_mgr_mount_camd(CXFSOP_MGR *cxfsop_mgr, CAMD_MD *camd_md);

EC_BOOL cxfsop_mgr_umount_camd(CXFSOP_MGR *cxfsop_mgr);

EC_BOOL cxfsop_mgr_scan(CXFSOP_MGR *cxfsop_mgr,
                             const uint64_t      op_seg_zone_size_nbytes,
                             uint64_t           *s_op_offset,   /*OUT*/
                             uint64_t           *e_op_offset,   /*OUT*/
                             uint64_t           *s_op_time_msec,/*IN & OUT*/
                             uint64_t           *e_op_time_msec);

EC_BOOL cxfsop_mgr_dump(CXFSOP_MGR *cxfsop_mgr, UINT32 *offset);

EC_BOOL cxfsop_mgr_pad(CXFSOP_MGR *cxfsop_mgr, UINT32 *offset, const UINT32 size);

EC_BOOL cxfsop_mgr_np_push_dir_add_op(CXFSOP_MGR         *cxfsop_mgr,
                                                const uint32_t      klen,
                                                const uint8_t      *key);

EC_BOOL cxfsop_mgr_np_push_dir_delete_op(CXFSOP_MGR         *cxfsop_mgr,
                                                   const uint32_t      klen,
                                                   const uint8_t      *key);

EC_BOOL cxfsop_mgr_np_push_dir_wildcard_delete_op(CXFSOP_MGR      *cxfsop_mgr,
                                                              const uint32_t   klen,
                                                              const uint8_t   *key);

EC_BOOL cxfsop_mgr_np_push_file_add_op(CXFSOP_MGR      *cxfsop_mgr,
                                                 const uint32_t   klen,
                                                 const uint8_t   *key,
                                                 const uint32_t   file_size,
                                                 const uint16_t   disk_no,
                                                 const uint16_t   block_no,
                                                 const uint16_t   page_no);

EC_BOOL cxfsop_mgr_np_push_file_delete_op(CXFSOP_MGR        *cxfsop_mgr,
                                                   const uint32_t     klen,
                                                   const uint8_t     *key);

EC_BOOL cxfsop_mgr_np_push_file_wildcard_delete_op(CXFSOP_MGR       *cxfsop_mgr,
                                                               const uint32_t   klen,
                                                               const uint8_t   *key);

EC_BOOL cxfsop_mgr_np_push_file_update_op(CXFSOP_MGR      *cxfsop_mgr,
                                                    const uint32_t   klen,
                                                    const uint8_t   *key,
                                                    const uint32_t   file_size,
                                                    const uint16_t   disk_no,
                                                    const uint16_t   block_no,
                                                    const uint16_t   page_no);

EC_BOOL cxfsop_mgr_dn_push_reserve_op(CXFSOP_MGR      *cxfsop_mgr,
                                                const uint32_t   data_size,
                                                const uint16_t   disk_no,
                                                const uint16_t   block_no,
                                                const uint16_t   page_no);

EC_BOOL cxfsop_mgr_dn_push_release_op(CXFSOP_MGR *cxfsop_mgr,
                                                const uint32_t   data_size,
                                                const uint16_t   disk_no,
                                                const uint16_t   block_no,
                                                const uint16_t   page_no);

#endif/* _CXFSOP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

