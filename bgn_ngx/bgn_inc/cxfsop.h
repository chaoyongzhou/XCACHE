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

/*4 bits, [0, 16]*/
#define CXFSOP_ERR_OP           ((uint16_t)0x0)
#define CXFSOP_NP_F_ADD_OP      ((uint16_t)0x1)  /*np reserve file operation*/
#define CXFSOP_NP_F_DEL_OP      ((uint16_t)0x2)  /*np release file operation*/
#define CXFSOP_NP_F_UPD_OP      ((uint16_t)0x3)  /*np update file operation*/
#define CXFSOP_NP_D_ADD_OP      ((uint16_t)0x4)  /*np reserve dir operation*/
#define CXFSOP_NP_D_DEL_OP      ((uint16_t)0x5)  /*np release dir operation*/
#define CXFSOP_NP_I_RET_OP      ((uint16_t)0x6)  /*np retire item operation*/
#define CXFSOP_NP_I_REC_OP      ((uint16_t)0x7)  /*np recycle item operation*/
#define CXFSOP_DN_RSV_OP        ((uint16_t)0x8)  /*dn reserve space operation*/
#define CXFSOP_DN_REL_OP        ((uint16_t)0x9)  /*dn release space operation*/
#define CXFSOP_DN_REC_OP        ((uint16_t)0xA)  /*dn recycle space operation*/

#define CXFSOP_MAGIC_NUM        (0x27182818)       /*e*/

#define CXFSOP_KEY_MAX_LEN      (((uint16_t) 4) << 10) /*4KB*/
#define CXFSOP_HDR_MAX_LEN      (((uint16_t) 4) << 10) /*4KB*/
#define CXFSOP_SEARCH_MAX_LEN   (((uint64_t)16) << 10) /*16KB = 4 * 4KB*/

#define CXFSOP_PAGE_SIZE_NBITS           ((uint64_t)18) /*256K*/
#define CXFSOP_PAGE_SIZE_NBYTES          ((uint64_t)(1 << CXFSOP_PAGE_SIZE_NBITS))
#define CXFSOP_PAGE_SIZE_MASK            (CXFSOP_PAGE_SIZE_NBYTES - 1)

typedef struct
{
    /*8B*/
    uint64_t            time;          /*operation log recording time*/

    /*4B*/
    uint32_t            magic;

    /*2B*/
    uint16_t            op       :4;    /*operation*/
    uint16_t            size     :12;   /*total size including header, key and optional fnode. size < 4KB*/

    /*2B*/
    uint16_t            rsvd02;
}CXFSOP_COMM_HDR;/*16B*/

#define CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)           ((cxfsop_comm_hdr)->time)
#define CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr)          ((cxfsop_comm_hdr)->magic)
#define CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr)             ((cxfsop_comm_hdr)->op)
#define CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr)           ((cxfsop_comm_hdr)->size)

typedef struct
{
    /*8B*/
    uint64_t            time;          /*operation log recording time*/

    /*4B*/
    uint32_t            magic;

    /*2B*/
    uint16_t            op       :4;    /*operation*/
    uint16_t            size     :12;   /*total size including header, key and optional fnode. size < 4KB*/

    /*2B*/
    uint16_t            wildcard :1;
    uint16_t            klen     :11;   /*key/path len < 2KB*/
    uint16_t            rsvd     :4;
    uint8_t             key[ 0 ];
    /* note: next is CXFSOP_NP_FNODE if dflag is REG FILE */
}CXFSOP_NP_HDR;/*>=16B*/

#define CXFSOP_NP_HDR_TIME(cxfsop_np_hdr)           ((cxfsop_np_hdr)->time)
#define CXFSOP_NP_HDR_MAGIC(cxfsop_np_hdr)          ((cxfsop_np_hdr)->magic)
#define CXFSOP_NP_HDR_OP(cxfsop_np_hdr)             ((cxfsop_np_hdr)->op)
#define CXFSOP_NP_HDR_SIZE(cxfsop_np_hdr)           ((cxfsop_np_hdr)->size)

#define CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr)       ((cxfsop_np_hdr)->wildcard)
#define CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr)           ((cxfsop_np_hdr)->klen)
#define CXFSOP_NP_HDR_KEY(cxfsop_np_hdr)            ((cxfsop_np_hdr)->key)

typedef struct
{
    /*8B*/
    uint64_t            time;
          /*operation log recording time*/

    /*4B*/
    uint32_t            magic;

    /*2B*/
    uint16_t            op       :4;    /*operation*/
    uint16_t            size     :12;   /*total size including header, key and optional fnode. size < 4KB*/

    /*4B*/
    uint32_t            np_id;
    uint32_t            node_pos;

    /*6B*/
    uint16_t            rsvd02;
    uint16_t            rsvd03;
    uint16_t            rsvd04;
}CXFSOP_NP_ITEM;/*24B*/

#define CXFSOP_NP_ITEM_TIME(cxfsop_np_item)           ((cxfsop_np_item)->time)
#define CXFSOP_NP_ITEM_MAGIC(cxfsop_np_item)          ((cxfsop_np_item)->magic)
#define CXFSOP_NP_ITEM_OP(cxfsop_np_item)             ((cxfsop_np_item)->op)
#define CXFSOP_NP_ITEM_SIZE(cxfsop_np_item)           ((cxfsop_np_item)->size)

#define CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item)          ((cxfsop_np_item)->np_id)
#define CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item)       ((cxfsop_np_item)->node_pos)

typedef struct
{
    /*8B*/
    uint64_t            time;       /*operation log recording time*/

    /*4B*/
    uint32_t            magic;

    /*2B*/
    uint16_t            op       :4;    /*operation*/
    uint16_t            size     :12;   /*total size including header, key and optional fnode. size < 4KB*/

    /*10B*/
    uint16_t            disk_no;
    uint16_t            block_no;
    uint16_t            page_no;
    uint32_t            data_len;
}CXFSOP_DN_NODE;/*24B*/

#define CXFSOP_DN_NODE_TIME(cxfsop_dn_node)           ((cxfsop_dn_node)->time)
#define CXFSOP_DN_NODE_MAGIC(cxfsop_dn_node)          ((cxfsop_dn_node)->magic)
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

    void               *camd;
}CXFSOP_MGR;

#define CXFSOP_MGR_SIZE(cxfsop_mgr)          ((cxfsop_mgr)->size)
#define CXFSOP_MGR_USED(cxfsop_mgr)          ((cxfsop_mgr)->used)
#define CXFSOP_MGR_DATA(cxfsop_mgr)          ((cxfsop_mgr)->data)
#define CXFSOP_MGR_CAMD(cxfsop_mgr)          ((cxfsop_mgr)->camd)

const char *cxfsop_mgr_op_str(const uint32_t op);

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

EC_BOOL cxfsop_mgr_mount_camd(CXFSOP_MGR *cxfsop_mgr, void *camd_md);

EC_BOOL cxfsop_mgr_umount_camd(CXFSOP_MGR *cxfsop_mgr);

void *cxfsop_mgr_search(CXFSOP_MGR *cxfsop_mgr, void *cur, const uint64_t max_scope_len);

EC_BOOL cxfsop_mgr_scan(CXFSOP_MGR *cxfsop_mgr,
                             uint64_t           *s_op_offset,   /*OUT*/
                             uint64_t           *e_op_offset,   /*OUT*/
                             uint64_t           *s_op_time_msec,/*IN & OUT*/
                             uint64_t           *e_op_time_msec);

EC_BOOL cxfsop_mgr_dump(CXFSOP_MGR *cxfsop_mgr, UINT32 *offset);

EC_BOOL cxfsop_mgr_pad(CXFSOP_MGR *cxfsop_mgr, UINT32 *offset, const UINT32 size);

EC_BOOL cxfsop_mgr_np_push_dir_add_op(CXFSOP_MGR         *cxfsop_mgr,
                                                const uint16_t      klen,
                                                const uint8_t      *key);

EC_BOOL cxfsop_mgr_np_push_dir_delete_op(CXFSOP_MGR         *cxfsop_mgr,
                                                   const uint16_t      klen,
                                                   const uint8_t      *key);

EC_BOOL cxfsop_mgr_np_push_dir_wildcard_delete_op(CXFSOP_MGR      *cxfsop_mgr,
                                                              const uint16_t   klen,
                                                              const uint8_t   *key);

EC_BOOL cxfsop_mgr_np_push_file_add_op(CXFSOP_MGR      *cxfsop_mgr,
                                                 const uint16_t   klen,
                                                 const uint8_t   *key,
                                                 const uint32_t   file_size,
                                                 const uint16_t   disk_no,
                                                 const uint16_t   block_no,
                                                 const uint16_t   page_no);

EC_BOOL cxfsop_mgr_np_push_file_delete_op(CXFSOP_MGR        *cxfsop_mgr,
                                                   const uint16_t     klen,
                                                   const uint8_t     *key);

EC_BOOL cxfsop_mgr_np_push_file_wildcard_delete_op(CXFSOP_MGR       *cxfsop_mgr,
                                                               const uint16_t   klen,
                                                               const uint8_t   *key);

EC_BOOL cxfsop_mgr_np_push_file_update_op(CXFSOP_MGR      *cxfsop_mgr,
                                                    const uint16_t   klen,
                                                    const uint8_t   *key,
                                                    const uint32_t   file_size,
                                                    const uint16_t   disk_no,
                                                    const uint16_t   block_no,
                                                    const uint16_t   page_no);


EC_BOOL cxfsop_mgr_np_push_item_retire(CXFSOP_MGR      *cxfsop_mgr,
                                                const uint32_t   np_id,
                                                const uint32_t   node_pos);

EC_BOOL cxfsop_mgr_np_push_item_recycle(CXFSOP_MGR      *cxfsop_mgr,
                                                 const uint32_t   np_id,
                                                 const uint32_t   node_pos);

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

EC_BOOL cxfsop_mgr_dn_push_recycle_op(CXFSOP_MGR *cxfsop_mgr,
                                                const uint32_t   data_size,
                                                const uint16_t   disk_no,
                                                const uint16_t   block_no,
                                                const uint16_t   page_no);
#endif/* _CXFSOP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

