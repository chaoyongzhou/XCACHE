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

#ifndef _CAMD_H
#define _CAMD_H

#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"
#include "crb.h"

#include "cparacfg.h"

#include "coroutine.inc"
#include "cpgbitmap.h"

#include "caio.h"
#include "cmc.h"
#include "cdc.h"
#include "cdio.h"

#include "cfc.h"

#include "cmmap.h"

/*AMD: aio + mem cache + disk cache*/

#define CAMD_OP_ERR                                     ((UINT32)0x0000) /*bitmap: 0000*/
#define CAMD_OP_RD                                      ((UINT32)0x0001) /*bitmap: 0001*/
#define CAMD_OP_WR                                      ((UINT32)0x0002) /*bitmap: 0010*/


/*note: mmap max size >= 8713816128  B (i.e.,  8 GB, 118 MB, 146 KB,  64 B)*/
/*      total of 8 AMDs: 69710529024 B (i.e., 64 GB, 945 MB, 144 KB, 512 B)*/
/*      thus, tmpfs is suggested to 65GB or more                          */
#define CAMD_MMAP_MAX_SIZE_NBYTES                       (((uint64_t)9) << 30) /*9GB*/
#define CAMD_SHM_FILE_SIZE_NBYTES                       (((uint64_t)1) << 30) /*1GB*/

/*ssd bad page size in bytes = ssd disk size in bytes / (8 * page size in bytges)*/
#define CAMD_SSD_BAD_PAGE_BITMAP_SIZE_NBYTES            ((uint32_t)(1 << (CAMD_SSD_DISK_MAX_SIZE_NBITS - CMCPGB_PAGE_SIZE_NBITS - 3)))
#define CAMD_SSD_BAD_PAGE_BITMAP_SIZE_NBITS             ((CAMD_SSD_BAD_PAGE_BITMAP_SIZE_NBYTES - 4 - 4) << 3)

/*sata bad page size in bytes = sata disk size in bytes / (8 * page size in bytges)*/
#define CAMD_SATA_BAD_PAGE_BITMAP_SIZE_NBYTES           ((uint32_t)(1 << (CAMD_SATA_DISK_MAX_SIZE_NBITS - CMCPGB_PAGE_SIZE_NBITS - 3)))
#define CAMD_SATA_BAD_PAGE_BITMAP_SIZE_NBITS            ((CAMD_SATA_BAD_PAGE_BITMAP_SIZE_NBYTES - 4 - 4) << 3)

#define CAMD_MEM_ALIGNMENT                              (UINT32_ONE << 20) /*1MB alignment*/

#define CAMD_MEM_CACHE_ALIGN_SIZE_NBYTES                (CMCPGB_PAGE_SIZE_NBYTES)
#define CAMD_PROCESS_EVENT_ONCE_NUM                     (128)

#define CAMD_AIO_TIMEOUT_NSEC_DEFAULT                   (3600)
#define CAMD_DIO_TIMEOUT_NSEC_DEFAULT                   (3600)

//#define CAMD_MEM_CACHE_MAX_NUM                          ((UINT32)512) /*128MB for 256K-page*/
#define CAMD_MEM_CACHE_MAX_NUM                          ((UINT32)~0)/*no limitation*/

#define CAMD_FLOW_CONTROL_NSEC                          (1) /*flow control per second*/

#define CAMD_PAGE_TREE_IDX_ERR                          ((UINT32)~0)

#define CAMD_NOT_RETRIEVE_BAD_BITMAP                    ((UINT32)0)
#define CAMD_RETRIEVE_BAD_BITMAP                        ((UINT32)1)

typedef struct
{
    char            *camd_dir;

    CAIO_MD         *caio_md;
    CMC_MD          *cmc_md;
    CDC_MD          *cdc_md;
    CDIO_MD         *cdio_md;

    UINT32           seq_no;            /*sequence number factory*/

    CLIST            req_list;          /*item is CAMD_REQ. reading & writing request list in order*/
    CRB_TREE         page_tree[2];      /*item is CAMD_PAGE. working page tree*/
    UINT32           page_tree_idx;     /*page tree active index, range in [0, 1]*/

    CLIST            post_event_reqs;   /*item is CAMD_REQ */
    CLIST            post_file_reqs;    /*item is CAMD_FILE_REQ*/

    uint32_t         force_dio_flag :1;
    uint32_t         read_only_flag :1; /*camd is read-only if set*/
    uint32_t         restart_flag   :1; /*camd is restarting if set*/
    uint32_t         dontdump_flag  :1; /*camd not flush or dump if set*/
    uint32_t         rsvd01         :28;
    uint32_t         rsvd02;

    int              sata_disk_fd;
    int              ssd_disk_fd;

    CPG_BITMAP      *ssd_bad_bitmap;    /*ssd bad aio-page bitmap*/
    CPG_BITMAP      *sata_bad_bitmap;   /*sata bad aio-page bitmap*/
    uint32_t         ssd_bad_page_num;  /*save prev num of ssd bad pages*/
    uint32_t         sata_bad_page_num; /*save prev num of sata bad pages*/

    CMMAP_NODE      *cmmap_node;

    CFC              sata_read_flow_control;      /*sata flush bps*/
    CFC              sata_write_flow_control;     /*sata flush bps*/
    CFC              ssd_write_flow_control;      /*ssd flush bps */
    CFC              ssd_read_flow_control;
    CFC              mem_write_flow_control;      /*mem flush bps */
    CFC              amd_read_flow_control;       /*amd read bps  */
    CFC              amd_write_flow_control;      /*amd write bps */

    CIOSTAT          mem_iostat;
    CIOSTAT          ssd_iostat;
}CAMD_MD;

#define CAMD_MD_DIR(camd_md)                            ((camd_md)->camd_dir)
#define CAMD_MD_CAIO_MD(camd_md)                        ((camd_md)->caio_md)
#define CAMD_MD_CMC_MD(camd_md)                         ((camd_md)->cmc_md)
#define CAMD_MD_CDC_MD(camd_md)                         ((camd_md)->cdc_md)
#define CAMD_MD_CDIO_MD(camd_md)                        ((camd_md)->cdio_md)
#define CAMD_MD_SEQ_NO(camd_md)                         ((camd_md)->seq_no)
#define CAMD_MD_REQ_LIST(camd_md)                       (&((camd_md)->req_list))
#define CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md)           ((camd_md)->page_tree_idx)
#define CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md)          (1 ^ CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md))
#define CAMD_MD_PAGE_TREE(camd_md, idx)                 (&((camd_md)->page_tree[ (idx) ]))
#define CAMD_MD_POST_EVENT_REQS(camd_md)                (&((camd_md)->post_event_reqs))
#define CAMD_MD_POST_FILE_REQS(camd_md)                 (&((camd_md)->post_file_reqs))
#define CAMD_MD_FORCE_DIO_FLAG(camd_md)                 ((camd_md)->force_dio_flag)
#define CAMD_MD_RDONLY_FLAG(camd_md)                    ((camd_md)->read_only_flag)
#define CAMD_MD_RESTART_FLAG(camd_md)                   ((camd_md)->restart_flag)
#define CAMD_MD_DONTDUMP_FLAG(camd_md)                  ((camd_md)->dontdump_flag)
#define CAMD_MD_SATA_DISK_FD(camd_md)                   ((camd_md)->sata_disk_fd)
#define CAMD_MD_SSD_DISK_FD(camd_md)                    ((camd_md)->ssd_disk_fd)
#define CAMD_MD_SSD_BAD_BITMAP(camd_md)                 ((camd_md)->ssd_bad_bitmap)
#define CAMD_MD_SATA_BAD_BITMAP(camd_md)                ((camd_md)->sata_bad_bitmap)
#define CAMD_MD_SSD_BAD_PAGE_NUM(camd_md)               ((camd_md)->ssd_bad_page_num)
#define CAMD_MD_SATA_BAD_PAGE_NUM(camd_md)              ((camd_md)->sata_bad_page_num)

#define CAMD_MD_CMMAP_NODE(camd_md)                     ((camd_md)->cmmap_node)

#define CAMD_MD_SATA_READ_FC(camd_md)                   (&((camd_md)->sata_read_flow_control))
#define CAMD_MD_SATA_WRITE_FC(camd_md)                  (&((camd_md)->sata_write_flow_control))
#define CAMD_MD_SSD_READ_FC(camd_md)                    (&((camd_md)->ssd_read_flow_control))
#define CAMD_MD_SSD_WRITE_FC(camd_md)                   (&((camd_md)->ssd_write_flow_control))
#define CAMD_MD_MEM_WRITE_FC(camd_md)                   (&((camd_md)->mem_write_flow_control))
#define CAMD_MD_AMD_READ_FC(camd_md)                    (&((camd_md)->amd_read_flow_control))
#define CAMD_MD_AMD_WRITE_FC(camd_md)                   (&((camd_md)->amd_write_flow_control))

#define CAMD_MD_MEM_IOSTAT(camd_md)                     (&((camd_md)->mem_iostat))
#define CAMD_MD_SSD_IOSTAT(camd_md)                     (&((camd_md)->ssd_iostat))

#define CAMD_MD_SWITCH_PAGE_TREE(camd_md)               \
    do{                                                 \
        CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md) ^= 1;     \
    }while(0)


typedef struct
{
    int                     fd;
    int                     rsvd01;

    UINT32                  f_s_offset;
    UINT32                  f_e_offset;

    UINT32                  f_t_offset;             /*temporary offset*/

    UINT32                  op;                     /*reading or writing*/

    UINT32                  timeout_nsec;           /*timeout in seconds*/

    uint32_t                ssd_dirty_flag   :1;    /*page should flush to ssd later*/
    uint32_t                ssd_loaded_flag  :1;    /*page was loaded from ssd*/
    uint32_t                ssd_loading_flag :1;    /*page is loading from ssd*/

    uint32_t                sata_dirty_flag  :1;    /*page should flush to sata later*/
    uint32_t                sata_loaded_flag :1;    /*page was loaded from sata*/
    uint32_t                sata_loading_flag:1;    /*page is loading from sata*/

    uint32_t                mem_flushed_flag :1;    /*page is flushed to mem*/
    uint32_t                mem_cache_flag   :1;    /*page is shortcut to mem cache page*/
    uint32_t                rsvd02           :24;
    uint32_t                rsvd03;

    UINT8                  *m_cache;                /*cache for one page*/

    CLIST                   owners;                 /*item is CAMD_NODE*/

    CAMD_MD                *camd_md;                /*shortcut: point to camd module*/

    /*shortcut*/
    CRB_NODE               *mounted_pages;          /*mount point in page tree of camd module*/
    UINT32                  mounted_tree_idx;       /*mount in which page tree*/
}CAMD_PAGE;

#define CAMD_PAGE_FD(camd_page)                         ((camd_page)->fd)

#define CAMD_PAGE_F_S_OFFSET(camd_page)                 ((camd_page)->f_s_offset)
#define CAMD_PAGE_F_E_OFFSET(camd_page)                 ((camd_page)->f_e_offset)

#define CAMD_PAGE_F_T_OFFSET(camd_page)                 ((camd_page)->f_t_offset)

#define CAMD_PAGE_OP(camd_page)                         ((camd_page)->op)

#define CAMD_PAGE_TIMEOUT_NSEC(camd_page)               ((camd_page)->timeout_nsec)

#define CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)             ((camd_page)->ssd_dirty_flag)
#define CAMD_PAGE_SSD_LOADED_FLAG(camd_page)            ((camd_page)->ssd_loaded_flag)
#define CAMD_PAGE_SSD_LOADING_FLAG(camd_page)           ((camd_page)->ssd_loading_flag)

#define CAMD_PAGE_SATA_DIRTY_FLAG(camd_page)            ((camd_page)->sata_dirty_flag)
#define CAMD_PAGE_SATA_LOADED_FLAG(camd_page)           ((camd_page)->sata_loaded_flag)
#define CAMD_PAGE_SATA_LOADING_FLAG(camd_page)          ((camd_page)->sata_loading_flag)

#define CAMD_PAGE_MEM_FLUSHED_FLAG(camd_page)           ((camd_page)->mem_flushed_flag)
#define CAMD_PAGE_MEM_CACHE_FLAG(camd_page)             ((camd_page)->mem_cache_flag)

#define CAMD_PAGE_M_CACHE(camd_page)                    ((camd_page)->m_cache)
#define CAMD_PAGE_OWNERS(camd_page)                     (&((camd_page)->owners))
#define CAMD_PAGE_CAMD_MD(camd_page)                    ((camd_page)->camd_md)
#define CAMD_PAGE_MOUNTED_PAGES(camd_page)              ((camd_page)->mounted_pages)
#define CAMD_PAGE_MOUNTED_TREE_IDX(camd_page)           ((camd_page)->mounted_tree_idx)

typedef void (*CAMD_EVENT_HANDLER)(void *);

typedef struct
{
    CAIO_CB                 caio_cb;

    UINT32                  seq_no;             /*unique sequence number of request*/
    UINT32                  op;                 /*reading or writing*/

    UINT32                  sub_seq_num;        /*sub request number*/
    UINT32                  node_num;           /*working node number*/
    UINT32                  succ_num;           /*complete nodes number*/
    UINT32                  u_e_offset;         /*upper offset at most in file*/

    CAMD_MD                *camd_md;            /*shortcut: point to camd module*/
    int                     fd;                 /*inherited from application*/
    int                     rsvd01;
    UINT8                  *m_cache;            /*inherited from camd page*/
    UINT8                  *m_buff;             /*inherited from application*/
    UINT32                 *offset;             /*inherited from application*/
    UINT32                  f_s_offset;         /*start offset in file*/
    UINT32                  f_e_offset;         /*end offset in file*/
    UINT32                  timeout_nsec;       /*timeout in seconds*/
    uint64_t                next_access_ms;     /*next access in msec*/

    uint64_t                s_msec;             /*start time in msec*/
    uint64_t                e_msec;             /*end time in msec*/

    CAMD_EVENT_HANDLER      post_event_handler;
    CLIST_DATA             *mounted_post_event_reqs;   /*mount point in post event reqs of camd md*/

    CLIST                   nodes;              /*item is CAMD_NODE*/

    /*shortcut*/
    CLIST_DATA             *mounted_reqs;       /*mount point in req list of camd module*/
}CAMD_REQ;

#define CAMD_REQ_CAIO_CB(camd_req)                      (&((camd_req)->caio_cb))

#define CAMD_REQ_SEQ_NO(camd_req)                       ((camd_req)->seq_no)
#define CAMD_REQ_OP(camd_req)                           ((camd_req)->op)
#define CAMD_REQ_SUB_SEQ_NUM(camd_req)                  ((camd_req)->sub_seq_num)

#define CAMD_REQ_NODE_NUM(camd_req)                     ((camd_req)->node_num)
#define CAMD_REQ_SUCC_NUM(camd_req)                     ((camd_req)->succ_num)
#define CAMD_REQ_U_E_OFFSET(camd_req)                   ((camd_req)->u_e_offset)

#define CAMD_REQ_CAMD_MD(camd_req)                      ((camd_req)->camd_md)
#define CAMD_REQ_FD(camd_req)                           ((camd_req)->fd)
#define CAMD_REQ_M_CACHE(camd_req)                      ((camd_req)->m_cache)
#define CAMD_REQ_M_BUFF(camd_req)                       ((camd_req)->m_buff)
#define CAMD_REQ_OFFSET(camd_req)                       ((camd_req)->offset)
#define CAMD_REQ_F_S_OFFSET(camd_req)                   ((camd_req)->f_s_offset)
#define CAMD_REQ_F_E_OFFSET(camd_req)                   ((camd_req)->f_e_offset)
#define CAMD_REQ_TIMEOUT_NSEC(camd_req)                 ((camd_req)->timeout_nsec)
#define CAMD_REQ_NTIME_MS(camd_req)                     ((camd_req)->next_access_ms)

#define CAMD_REQ_S_MSEC(camd_req)                       ((camd_req)->s_msec)
#define CAMD_REQ_E_MSEC(camd_req)                       ((camd_req)->e_msec)

#define CAMD_REQ_POST_EVENT_HANDLER(camd_req)           ((camd_req)->post_event_handler)
#define CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req)      ((camd_req)->mounted_post_event_reqs)

#define CAMD_REQ_NODES(camd_req)                        (&((camd_req)->nodes))
#define CAMD_REQ_MOUNTED_REQS(camd_req)                 ((camd_req)->mounted_reqs)

typedef struct
{
    CAMD_REQ               *camd_req;           /*shortcut: point to parent request*/
    CAMD_PAGE              *camd_page;          /*shortcut: point to owning page*/

    UINT32                  seq_no;             /*inherited from camd req*/
    UINT32                  sub_seq_no;         /*mark the order in camd req*/
    UINT32                  sub_seq_num;        /*shortcut for debug purpose. inherited from camd req*/
    UINT32                  op;                 /*reading or writing*/

    CAMD_MD                *camd_md;            /*shortcut: point to camd module*/
    int                     fd;                 /*inherited from application*/
    int                     rsvd01;
    UINT8                  *m_cache;            /*inherited from camd page*/
    UINT8                  *m_buff;             /*inherited from application*/
    UINT32                  f_s_offset;         /*start offset in file*/
    UINT32                  f_e_offset;         /*end offset in file*/
    UINT32                  b_s_offset;         /*start offset in page*/
    UINT32                  b_e_offset;         /*end offset in page*/
    UINT32                  timeout_nsec;       /*timeout in seconds*/
    uint64_t                next_access_ms;     /*next access in msec*/

    /*shortcut*/
    CLIST_DATA             *mounted_nodes;      /*mount point in nodes of camd req*/
    CLIST_DATA             *mounted_owners;     /*mount point in owners of camd page*/
}CAMD_NODE;

#define CAMD_NODE_CAMD_REQ(camd_node)                   ((camd_node)->camd_req)
#define CAMD_NODE_CAMD_PAGE(camd_node)                  ((camd_node)->camd_page)
#define CAMD_NODE_SEQ_NO(camd_node)                     ((camd_node)->seq_no)
#define CAMD_NODE_SUB_SEQ_NO(camd_node)                 ((camd_node)->sub_seq_no)
#define CAMD_NODE_SUB_SEQ_NUM(camd_node)                ((camd_node)->sub_seq_num)
#define CAMD_NODE_OP(camd_node)                         ((camd_node)->op)
#define CAMD_NODE_CAMD_MD(camd_node)                    ((camd_node)->camd_md)
#define CAMD_NODE_FD(camd_node)                         ((camd_node)->fd)
#define CAMD_NODE_M_CACHE(camd_node)                    ((camd_node)->m_cache)
#define CAMD_NODE_M_BUFF(camd_node)                     ((camd_node)->m_buff)
#define CAMD_NODE_F_S_OFFSET(camd_node)                 ((camd_node)->f_s_offset)
#define CAMD_NODE_F_E_OFFSET(camd_node)                 ((camd_node)->f_e_offset)
#define CAMD_NODE_B_S_OFFSET(camd_node)                 ((camd_node)->b_s_offset)
#define CAMD_NODE_B_E_OFFSET(camd_node)                 ((camd_node)->b_e_offset)
#define CAMD_NODE_TIMEOUT_NSEC(camd_node)               ((camd_node)->timeout_nsec)
#define CAMD_NODE_NTIME_MS(camd_node)                   ((camd_node)->next_access_ms)
#define CAMD_NODE_MOUNTED_NODES(camd_node)              ((camd_node)->mounted_nodes)
#define CAMD_NODE_MOUNTED_OWNERS(camd_node)             ((camd_node)->mounted_owners)


typedef struct
{
    int                     fd;
    int                     rsvd01;

    UINT32                  f_s_offset;
    UINT32                  f_e_offset;

    UINT32                  f_t_offset;             /*temporary offset*/

    UINT32                  timeout_nsec;           /*timeout in seconds*/

    CDCNP_KEY               cdcnp_key;
    UINT8                  *m_buff;                 /*data loaded from ssd and then flush to sata*/

    CAMD_MD                *camd_md;                /*shortcut: point to camd module*/
}CAMD_SATA;

#define CAMD_SATA_FD(camd_sata)                         ((camd_sata)->fd)

#define CAMD_SATA_F_S_OFFSET(camd_sata)                 ((camd_sata)->f_s_offset)
#define CAMD_SATA_F_E_OFFSET(camd_sata)                 ((camd_sata)->f_e_offset)
#define CAMD_SATA_F_T_OFFSET(camd_sata)                 ((camd_sata)->f_t_offset)

#define CAMD_SATA_TIMEOUT_NSEC(camd_sata)               ((camd_sata)->timeout_nsec)
#define CAMD_SATA_CDCNP_KEY(camd_sata)                  (&((camd_sata)->cdcnp_key))
#define CAMD_SATA_M_BUFF(camd_sata)                     ((camd_sata)->m_buff)
#define CAMD_SATA_CAMD_MD(camd_sata)                    ((camd_sata)->camd_md)

typedef struct
{
    UINT32                  f_s_offset;
    UINT32                  f_e_offset;

    UINT32                  timeout_nsec;           /*timeout in seconds*/

    CMCNP_KEY               cmcnp_key;

    CAMD_MD                *camd_md;                /*shortcut: point to camd module*/
}CAMD_SSD;

#define CAMD_SSD_F_S_OFFSET(camd_ssd)                 ((camd_ssd)->f_s_offset)
#define CAMD_SSD_F_E_OFFSET(camd_ssd)                 ((camd_ssd)->f_e_offset)

#define CAMD_SSD_TIMEOUT_NSEC(camd_ssd)               ((camd_ssd)->timeout_nsec)
#define CAMD_SSD_CMCNP_KEY(camd_ssd)                  (&((camd_ssd)->cmcnp_key))
#define CAMD_SSD_CAMD_MD(camd_ssd)                    ((camd_ssd)->camd_md)

#define CAMD_FILE_REQ_OP_ERR                            ((UINT32)0x0000) /*bitmap: 0000*/
#define CAMD_FILE_REQ_OP_RD                             ((UINT32)0x0001) /*bitmap: 0001*/
#define CAMD_FILE_REQ_OP_WR                             ((UINT32)0x0002) /*bitmap: 0010*/
#define CAMD_FILE_REQ_OP_AIO_RD                         ((UINT32)0x0004) /*bitmap: 0100*/
#define CAMD_FILE_REQ_OP_AIO_WR                         ((UINT32)0x0008) /*bitmap: 1000*/

typedef struct
{
    UINT32              file_op;        /*CAMD_OP_xx*/

    int                 fd;
    int                 rsvd01;
    UINT32             *offset;         /*mounted of application*/
    UINT32              rwsize;
    UINT8              *buff;           /*mounted of application*/

    CAIO_CB             caio_cb;

}CAMD_FILE_REQ;

#define CAMD_FILE_REQ_OP(camd_file_req)             ((camd_file_req)->file_op)
#define CAMD_FILE_REQ_FD(camd_file_req)             ((camd_file_req)->fd)
#define CAMD_FILE_REQ_OFFSET(camd_file_req)         ((camd_file_req)->offset)
#define CAMD_FILE_REQ_RWSIZE(camd_file_req)         ((camd_file_req)->rwsize)
#define CAMD_FILE_REQ_BUFF(camd_file_req)           ((camd_file_req)->buff)
#define CAMD_FILE_REQ_CAIO_CB(camd_file_req)        (&((camd_file_req)->caio_cb))

#define CAMD_COND_RESULT_ERROR                        ((UINT32)~0)
#define CAMD_COND_RESULT_COMPLETE                     ((UINT32) 0)
#define CAMD_COND_RESULT_TIMEOUT                      ((UINT32) 1)
#define CAMD_COND_RESULT_TERMINATE                    ((UINT32) 2)

typedef struct
{
    COROUTINE_COND         ccond;
    UINT32                 result;
}CAMD_COND;

#define CAMD_COND_CCOND(camd_cond)                    (&((camd_cond)->ccond))
#define CAMD_COND_RESULT(camd_cond)                   ((camd_cond)->result)

/*----------------------------------- camd page interface -----------------------------------*/

void camd_mem_cache_counter_print(LOG *log);

CAMD_PAGE *camd_page_new();

EC_BOOL camd_page_init(CAMD_PAGE *camd_page);

EC_BOOL camd_page_clean(CAMD_PAGE *camd_page);

EC_BOOL camd_page_free(CAMD_PAGE *camd_page);

void camd_page_print(LOG *log, const CAMD_PAGE *camd_page);

int camd_page_cmp(const CAMD_PAGE *camd_page_1st, const CAMD_PAGE *camd_page_2nd);

EC_BOOL camd_page_add_node(CAMD_PAGE *camd_page, CAMD_NODE *camd_node);

EC_BOOL camd_page_del_node(CAMD_PAGE *camd_page, CAMD_NODE *camd_node);

EC_BOOL camd_page_cleanup_nodes(CAMD_PAGE *camd_page);

CAMD_NODE *camd_page_pop_node_front(CAMD_PAGE *camd_page);

CAMD_NODE *camd_page_pop_node_back(CAMD_PAGE *camd_page);

EC_BOOL camd_page_timeout(CAMD_PAGE *camd_page);

EC_BOOL camd_page_terminate(CAMD_PAGE *camd_page);

EC_BOOL camd_page_complete(CAMD_PAGE *camd_page);

/*process when page is in mem cache*/
EC_BOOL camd_page_process(CAMD_PAGE *camd_page, const UINT32 retry_page_tree_idx);

EC_BOOL camd_page_load_sata_aio_timeout(CAMD_PAGE *camd_page);

EC_BOOL camd_page_load_sata_aio_terminate(CAMD_PAGE *camd_page);

EC_BOOL camd_page_load_sata_aio_complete(CAMD_PAGE *camd_page);

/*load page from sata to mem cache*/
EC_BOOL camd_page_load_sata_aio(CAMD_PAGE *camd_page);

EC_BOOL camd_page_notify_timeout(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_sata_aio_timeout(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_sata_aio_terminate(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_sata_aio_complete(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_sata_aio(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_sata_dio(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_ssd_aio_timeout(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_ssd_aio_terminate(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_ssd_aio_complete(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_ssd_aio(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_ssd_dio(CAMD_PAGE *camd_page);

EC_BOOL camd_page_flush_mem(CAMD_PAGE *camd_page);

EC_BOOL camd_page_purge_ssd(CAMD_PAGE *camd_page);

EC_BOOL camd_page_load_ssd_aio_timeout(CAMD_PAGE *camd_page);

EC_BOOL camd_page_load_ssd_aio_terminate(CAMD_PAGE *camd_page);

EC_BOOL camd_page_load_ssd_aio_complete(CAMD_PAGE *camd_page);

/*load page from ssd to mem cache*/
EC_BOOL camd_page_load_ssd_aio(CAMD_PAGE *camd_page);

/*----------------------------------- camd node interface -----------------------------------*/

CAMD_NODE *camd_node_new();

EC_BOOL camd_node_init(CAMD_NODE *camd_node);

EC_BOOL camd_node_clean(CAMD_NODE *camd_node);

EC_BOOL camd_node_free(CAMD_NODE *camd_node);

EC_BOOL camd_node_is(const CAMD_NODE *camd_node, const UINT32 sub_seq_no);

void camd_node_print(LOG *log, const CAMD_NODE *camd_node);

EC_BOOL camd_node_timeout(CAMD_NODE *camd_node);

EC_BOOL camd_node_terminate(CAMD_NODE *camd_node);

EC_BOOL camd_node_complete(CAMD_NODE *camd_node);

/*----------------------------------- camd req interface -----------------------------------*/

CAMD_REQ *camd_req_new();

EC_BOOL camd_req_init(CAMD_REQ *camd_req);

EC_BOOL camd_req_clean(CAMD_REQ *camd_req);

EC_BOOL camd_req_free(CAMD_REQ *camd_req);

EC_BOOL camd_req_exec_timeout_handler(CAMD_REQ *camd_req);

EC_BOOL camd_req_exec_terminate_handler(CAMD_REQ *camd_req);

EC_BOOL camd_req_exec_complete_handler(CAMD_REQ *camd_req);

EC_BOOL camd_req_set_post_event(CAMD_REQ *camd_req, CAMD_EVENT_HANDLER handler);

EC_BOOL camd_req_del_post_event(CAMD_REQ *camd_req);

EC_BOOL camd_req_is(const CAMD_REQ *camd_req, const UINT32 seq_no);

void camd_req_print(LOG *log, const CAMD_REQ *camd_req);

EC_BOOL camd_req_cleanup_nodes(CAMD_REQ *camd_req);

EC_BOOL camd_req_push_node_back(CAMD_REQ *camd_req, CAMD_NODE *camd_node);

CAMD_NODE *camd_req_pop_node_back(CAMD_REQ *camd_req);

EC_BOOL camd_req_push_node_front(CAMD_REQ *camd_req, CAMD_NODE *camd_node);

EC_BOOL camd_req_del_node(CAMD_REQ *camd_req, CAMD_NODE *camd_node);

EC_BOOL camd_req_reorder_sub_seq_no(CAMD_REQ *camd_req);

EC_BOOL camd_req_make_read_op(CAMD_REQ *camd_req);

EC_BOOL camd_req_make_write_op(CAMD_REQ *camd_req);

EC_BOOL camd_req_make_read(CAMD_REQ *camd_req);

EC_BOOL camd_req_make_write(CAMD_REQ *camd_req);

EC_BOOL camd_req_timeout(CAMD_REQ *camd_req);

EC_BOOL camd_req_terminate(CAMD_REQ *camd_req);

EC_BOOL camd_req_complete(CAMD_REQ *camd_req);

EC_BOOL camd_req_dispatch_node(CAMD_REQ *camd_req, CAMD_NODE *camd_node);

EC_BOOL camd_req_cancel_node(CAMD_REQ *camd_req, CAMD_NODE *camd_node);

/*----------------------------------- camd file req interface -----------------------------------*/

CAMD_FILE_REQ *camd_file_req_new();

EC_BOOL camd_file_req_init(CAMD_FILE_REQ *camd_file_req);

EC_BOOL camd_file_req_clean(CAMD_FILE_REQ *camd_file_req);

EC_BOOL camd_file_req_free(CAMD_FILE_REQ *camd_file_req);

void camd_file_req_print(LOG *log, const CAMD_FILE_REQ *camd_file_req);

/*----------------------------------- camd module interface -----------------------------------*/

CAMD_MD *camd_start(const char *camd_shm_root_dir,
                       const int sata_disk_fd, const UINT32 sata_disk_size /*in byte*/,
                       const UINT32 mem_disk_size /*in byte*/,
                       const int ssd_disk_fd, const UINT32 ssd_disk_offset, const UINT32 ssd_disk_size/*in byte*/);

void camd_end(CAMD_MD *camd_md);

void camd_restart(CAMD_MD *camd_md);

EC_BOOL camd_set_read_only(CAMD_MD *camd_md);

EC_BOOL camd_unset_read_only(CAMD_MD *camd_md);

EC_BOOL camd_is_read_only(const CAMD_MD *camd_md);

EC_BOOL camd_set_dontdump(CAMD_MD *camd_md);

EC_BOOL camd_unset_dontdump(CAMD_MD *camd_md);

EC_BOOL camd_is_dontdump(CAMD_MD *camd_md);

EC_BOOL camd_create(CAMD_MD *camd_md, const UINT32 retrieve_bad_bitmap_flag);

EC_BOOL camd_create_shm(CAMD_MD *camd_md, const UINT32 retrieve_bad_bitmap_flag);

EC_BOOL camd_load(CAMD_MD *camd_md);

EC_BOOL camd_load_shm(CAMD_MD *camd_md);

EC_BOOL camd_dump_shm(CAMD_MD *camd_md);

EC_BOOL camd_restore_shm(CAMD_MD *camd_md);

EC_BOOL camd_retrieve_shm(CAMD_MD *camd_md);

EC_BOOL camd_enable_dio(CAMD_MD *camd_md, const int disk_fd, const UINT32 disk_offset, const UINT32 disk_size);

EC_BOOL camd_disable_dio(CAMD_MD *camd_md);

void camd_print(LOG *log, const CAMD_MD *camd_md);

int camd_get_eventfd(CAMD_MD *camd_md);

EC_BOOL camd_event_handler(CAMD_MD *camd_md);

/*for cdc aio*/
int camd_cdc_get_eventfd(CAMD_MD *camd_md);

/*for cdc aio*/
EC_BOOL camd_cdc_event_handler(CAMD_MD *camd_md);

/*for cdio aio*/
int camd_cdio_get_eventfd(CAMD_MD *camd_md);

/*for cdio aio*/
EC_BOOL camd_cdio_event_handler(CAMD_MD *camd_md);

EC_BOOL camd_try_quit(CAMD_MD *camd_md);

EC_BOOL camd_try_restart(CAMD_MD *camd_md);

EC_BOOL camd_poll(CAMD_MD *camd_md);

/*for debug only!*/
EC_BOOL camd_poll_debug(CAMD_MD *camd_md);

void camd_process(CAMD_MD *camd_md);

void camd_process_ssd_bad_bitmap(CAMD_MD *camd_md);

void camd_process_no_degrade(CAMD_MD *camd_md);

void camd_process_reqs(CAMD_MD *camd_md);

void camd_process_timeout_reqs(CAMD_MD *camd_md);

void camd_process_pages(CAMD_MD *camd_md);

void camd_process_page(CAMD_MD *camd_md, CAMD_PAGE *camd_page);

void camd_process_events(CAMD_MD *camd_md);

void camd_process_post_event_reqs(CAMD_MD *camd_md, const UINT32 process_event_max_num);

EC_BOOL camd_is_barried(CAMD_MD *camd_md);

void camd_process_files(CAMD_MD *camd_md);

void camd_process_post_file_reqs(CAMD_MD *camd_md);

void camd_show_pages(LOG *log, const CAMD_MD *camd_md);

void camd_show_page(LOG *log, const CAMD_MD *camd_md, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset);

void camd_show_reqs(LOG *log, const CAMD_MD *camd_md);

void camd_show_req(LOG *log, const CAMD_MD *camd_md, const UINT32 seq_no);

void camd_show_post_event_reqs(LOG *log, const CAMD_MD *camd_md);

void camd_show_node(LOG *log, const CAMD_MD *camd_md, const UINT32 seq_no, const UINT32 sub_seq_no);

EC_BOOL camd_submit_req(CAMD_MD *camd_md, CAMD_REQ *camd_req);

EC_BOOL camd_add_req(CAMD_MD *camd_md, CAMD_REQ *camd_req);

EC_BOOL camd_del_req(CAMD_MD *camd_md, CAMD_REQ *camd_req);

EC_BOOL camd_make_req_op(CAMD_MD *camd_md, CAMD_REQ *camd_req);

EC_BOOL camd_dispatch_req(CAMD_MD *camd_md, CAMD_REQ *camd_req);

EC_BOOL camd_cancel_req(CAMD_MD *camd_md, CAMD_REQ *camd_req);

UINT32 camd_count_page_num(const CAMD_MD *camd_md, const UINT32 page_tree_idx);

EC_BOOL camd_add_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, CAMD_PAGE *camd_page);

EC_BOOL camd_del_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, CAMD_PAGE *camd_page);

EC_BOOL camd_has_page(CAMD_MD *camd_md, const UINT32 page_tree_idx);

CAMD_PAGE *camd_pop_first_page(CAMD_MD *camd_md, const UINT32 page_tree_idx);

CAMD_PAGE *camd_pop_last_page(CAMD_MD *camd_md, const UINT32 page_tree_idx);

CAMD_PAGE *camd_search_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset);

EC_BOOL camd_cleanup_pages(CAMD_MD *camd_md, const UINT32 page_tree_idx);

EC_BOOL camd_cleanup_reqs(CAMD_MD *camd_md);

EC_BOOL camd_cleanup_post_event_reqs(CAMD_MD *camd_md);

EC_BOOL camd_cleanup_post_file_reqs(CAMD_MD *camd_md);

CAMD_REQ *camd_search_req(CAMD_MD *camd_md, const UINT32 seq_no);

EC_BOOL camd_has_post_file_req(CAMD_MD *camd_md);

void camd_show_post_file_reqs(LOG *log, const CAMD_MD *camd_md);

CAMD_SSD *camd_ssd_new();

EC_BOOL camd_ssd_init(CAMD_SSD *camd_ssd);

EC_BOOL camd_ssd_clean(CAMD_SSD *camd_ssd);

EC_BOOL camd_ssd_free(CAMD_SSD *camd_ssd);

void camd_ssd_print(LOG *log, const CAMD_SSD *camd_ssd);

EC_BOOL camd_ssd_flush_timeout(CAMD_SSD *camd_ssd);

EC_BOOL camd_ssd_flush_terminate(CAMD_SSD *camd_ssd);

EC_BOOL camd_ssd_flush_complete(CAMD_SSD *camd_ssd);

/*flush one page when cmc retire it*/
EC_BOOL camd_ssd_flush(CAMD_MD *camd_md, const CMCNP_KEY *cmcnp_key, const CMCNP_ITEM *cmcnp_item,
                            const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no);

CAMD_SATA *camd_sata_new();

EC_BOOL camd_sata_init(CAMD_SATA *camd_sata);

EC_BOOL camd_sata_clean(CAMD_SATA *camd_sata);

EC_BOOL camd_sata_free(CAMD_SATA *camd_sata);

void camd_sata_print(LOG *log, const CAMD_SATA *camd_sata);

/*aio flush timeout*/
EC_BOOL camd_sata_flush_timeout(CAMD_SATA *camd_sata);

/*aio flush terminate*/
EC_BOOL camd_sata_flush_terminate(CAMD_SATA *camd_sata);

/*aio flush complete*/
EC_BOOL camd_sata_flush_complete(CAMD_SATA *camd_sata);

/*flush ssd page to sata when cdc scan lru list before retire it*/
EC_BOOL camd_sata_flush(CAMD_MD *camd_md, const CDCNP_KEY *cdcnp_key);

/*flush mem cache page to sata timeout*/
EC_BOOL camd_sata_degrade_timeout(CAMD_SATA *camd_sata);

/*flush mem cache page to sata terminate*/
EC_BOOL camd_sata_degrade_terminate(CAMD_SATA *camd_sata);

/*flush mem cache page to sata complete*/
EC_BOOL camd_sata_degrade_complete(CAMD_SATA *camd_sata);

/*flush one page to sata when cmc scan deg list*/
EC_BOOL camd_sata_degrade(CAMD_MD *camd_md, const CMCNP_KEY *cmcnp_key, const CMCNP_ITEM *cmcnp_item,
                            const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no);

EC_BOOL camd_create_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_create_ssd_bad_bitmap_shm(CAMD_MD *camd_md);

EC_BOOL camd_load_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_load_ssd_bad_bitmap_shm(CAMD_MD *camd_md);

EC_BOOL camd_retrieve_ssd_bad_bitmap_shm(CAMD_MD *camd_md);

EC_BOOL camd_flush_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_sync_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_close_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_revise_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_clean_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_free_ssd_bad_bitmap(CAMD_MD *camd_md);

EC_BOOL camd_mount_sata_bad_bitmap(CAMD_MD *camd_md, CPG_BITMAP *sata_bad_bitmap);

EC_BOOL camd_umount_sata_bad_bitmap(CAMD_MD *camd_md);

/*for debug only*/
EC_BOOL camd_set_ssd_bad_page(CAMD_MD *camd_md, const uint32_t page_no);

/*for debug only*/
EC_BOOL camd_is_ssd_bad_page(CAMD_MD *camd_md, const uint32_t page_no);

/*for debug only*/
EC_BOOL camd_clear_ssd_bad_page(CAMD_MD *camd_md, const uint32_t page_no);

/*for debug only*/
EC_BOOL camd_set_sata_bad_page(CAMD_MD *camd_md, const uint32_t page_no);

/*for debug only*/
EC_BOOL camd_is_sata_bad_page(CAMD_MD *camd_md, const uint32_t page_no);

/*for debug only*/
EC_BOOL camd_clear_sata_bad_page(CAMD_MD *camd_md, const uint32_t page_no);

/*------------------------ cmad cond interface ----------------------------*/

CAMD_COND *camd_cond_new(const UINT32 timeout_msec, const UINT32 location);

EC_BOOL camd_cond_init(CAMD_COND *camd_cond, const UINT32 timeout_msec, const UINT32 location);

EC_BOOL camd_cond_clean(CAMD_COND *camd_cond, const UINT32 location);

EC_BOOL camd_cond_free(CAMD_COND *camd_cond, const UINT32 location);

EC_BOOL camd_cond_reserve(CAMD_COND *camd_cond, const UINT32 counter, const UINT32 location);

EC_BOOL camd_cond_release(CAMD_COND *camd_cond, const UINT32 location);

EC_BOOL camd_cond_wait(CAMD_COND *camd_cond, const UINT32 location);

/*----------------------------------- camd external interface -----------------------------------*/

EC_BOOL camd_file_read_aio_do(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_read_aio(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_write_aio_do(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_write_aio(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_read_dio_aio(CAMD_MD *camd_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_write_dio_aio(CAMD_MD *camd_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_read(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff);

EC_BOOL camd_file_read_do(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_write(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff);

EC_BOOL camd_file_write_do(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL camd_file_delete(CAMD_MD *camd_md, UINT32 *offset, const UINT32 dsize);

EC_BOOL camd_file_read_dio(CAMD_MD *camd_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff);

EC_BOOL camd_file_write_dio(CAMD_MD *camd_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff);

#endif /*_CAMD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
