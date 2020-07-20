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

#ifndef _CAIO_H
#define _CAIO_H

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/aio_abi.h>
#include <fcntl.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"
#include "crb.h"

#include "cpgbitmap.h"

#include "cfc.h"

#define CAIO_512B_MODEL   ((uint8_t) 0)
#define CAIO_001K_MODEL   ((uint8_t) 1)
#define CAIO_002K_MODEL   ((uint8_t) 2)
#define CAIO_004K_MODEL   ((uint8_t) 3)
#define CAIO_008K_MODEL   ((uint8_t) 4)
#define CAIO_016K_MODEL   ((uint8_t) 5)
#define CAIO_032K_MODEL   ((uint8_t) 6)
#define CAIO_064K_MODEL   ((uint8_t) 7)
#define CAIO_128K_MODEL   ((uint8_t) 8)
#define CAIO_256K_MODEL   ((uint8_t) 9)
#define CAIO_512K_MODEL   ((uint8_t)10)
#define CAIO_001M_MODEL   ((uint8_t)11)

#define CAIO_MODEL_DEFAULT (CAIO_256K_MODEL)
#define CAIO_MODEL_ERR     ((uint8_t)~0)

#define CAIO_512B_BLOCK_SIZE_NBIT   ( 9)
#define CAIO_512B_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_512B_BLOCK_SIZE_NBIT)
#define CAIO_512B_BLOCK_SIZE_MASK   (CAIO_512B_BLOCK_SIZE_NBYTE - 1)

#define CAIO_001K_BLOCK_SIZE_NBIT   (10)
#define CAIO_001K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_001K_BLOCK_SIZE_NBIT)
#define CAIO_001K_BLOCK_SIZE_MASK   (CAIO_001K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_002K_BLOCK_SIZE_NBIT   (11)
#define CAIO_002K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_002K_BLOCK_SIZE_NBIT)
#define CAIO_002K_BLOCK_SIZE_MASK   (CAIO_002K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_004K_BLOCK_SIZE_NBIT   (12)
#define CAIO_004K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_004K_BLOCK_SIZE_NBIT)
#define CAIO_004K_BLOCK_SIZE_MASK   (CAIO_004K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_008K_BLOCK_SIZE_NBIT   (13)
#define CAIO_008K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_008K_BLOCK_SIZE_NBIT)
#define CAIO_008K_BLOCK_SIZE_MASK   (CAIO_008K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_016K_BLOCK_SIZE_NBIT   (14)
#define CAIO_016K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_016K_BLOCK_SIZE_NBIT)
#define CAIO_016K_BLOCK_SIZE_MASK   (CAIO_016K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_032K_BLOCK_SIZE_NBIT   (15)
#define CAIO_032K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_032K_BLOCK_SIZE_NBIT)
#define CAIO_032K_BLOCK_SIZE_MASK   (CAIO_032K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_064K_BLOCK_SIZE_NBIT   (16)
#define CAIO_064K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_064K_BLOCK_SIZE_NBIT)
#define CAIO_064K_BLOCK_SIZE_MASK   (CAIO_064K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_128K_BLOCK_SIZE_NBIT   (17)
#define CAIO_128K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_128K_BLOCK_SIZE_NBIT)
#define CAIO_128K_BLOCK_SIZE_MASK   (CAIO_128K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_256K_BLOCK_SIZE_NBIT   (18)
#define CAIO_256K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_256K_BLOCK_SIZE_NBIT)
#define CAIO_256K_BLOCK_SIZE_MASK   (CAIO_256K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_512K_BLOCK_SIZE_NBIT   (19)
#define CAIO_512K_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_512K_BLOCK_SIZE_NBIT)
#define CAIO_512K_BLOCK_SIZE_MASK   (CAIO_512K_BLOCK_SIZE_NBYTE - 1)

#define CAIO_001M_BLOCK_SIZE_NBIT   (20)
#define CAIO_001M_BLOCK_SIZE_NBYTE  (UINT32_ONE << CAIO_001M_BLOCK_SIZE_NBIT)
#define CAIO_001M_BLOCK_SIZE_MASK   (CAIO_001M_BLOCK_SIZE_NBYTE - 1)

#define CAIO_REQ_MAX_NUM                (128)

#define CAIO_EVENT_MAX_NUM              (128)

#define CAIO_PROCESS_EVENT_ONCE_NUM     (128)

#define CAIO_REQ_QUEUE_MAX_LEN          (2048) /*overhead judgement*/

//#define CAIO_MEM_CACHE_MAX_NUM          ((UINT32)1024) /*256MB for 256K-page*/
#define CAIO_MEM_CACHE_MAX_NUM          ((UINT32)~0)/*no limitation*/

#define CAIO_OP_RD                                      ((UINT32)0x0000)
#define CAIO_OP_WR                                      ((UINT32)0x0001)
#define CAIO_OP_ERR                                     ((UINT32)0xFFFF)

#define CAIO_STAT_INTERVAL_NSEC                         ((uint64_t)1)

#define CAIO_TIMEOUT_NSEC_DEFAULT                       (3600) /*second*/

#define CAIO_PAGE_IDX_ERR                               ((UINT32)~0)
#define CAIO_PAGE_NO_ERR                                ((uint32_t)~0)

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    UINT32         block_size_nbits; /*TODO: rename block to page*/
    UINT32         block_size_nbytes;
    UINT32         block_size_mask;
}CAIO_CFG;

#define CAIO_CFG_MODEL_STR(caio_cfg)              ((caio_cfg)->model_str)
#define CAIO_CFG_ALIAS_STR(caio_cfg)              ((caio_cfg)->alias_str)
#define CAIO_CFG_BLOCK_SIZE_NBITS(caio_cfg)       ((caio_cfg)->block_size_nbits)
#define CAIO_CFG_BLOCK_SIZE_NBYTES(caio_cfg)      ((caio_cfg)->block_size_nbytes)
#define CAIO_CFG_BLOCK_SIZE_MASK(caio_cfg)        ((caio_cfg)->block_size_mask)

typedef EC_BOOL (*CAIO_CALLBACK)(void *);

typedef struct
{
    CAIO_CALLBACK       func;
    void               *arg;
}CAIO_CB_HANDLER;

#define CAIO_CB_HANDLER_FUNC(caio_cb_handler)           ((caio_cb_handler)->func)
#define CAIO_CB_HANDLER_ARG(caio_cb_handler)            ((caio_cb_handler)->arg)

typedef struct
{
    UINT32                  timeout_nsec;
    CAIO_CB_HANDLER         timeout_handler;
    CAIO_CB_HANDLER         terminate_handler;
    CAIO_CB_HANDLER         complete_handler;
}CAIO_CB;

#define CAIO_CB_TIMEOUT_NSEC(caio_cb)                   ((caio_cb)->timeout_nsec)
#define CAIO_CB_TERMINATE_HANDLER(caio_cb)              (&((caio_cb)->terminate_handler))
#define CAIO_CB_TIMEOUT_HANDLER(caio_cb)                (&((caio_cb)->timeout_handler))
#define CAIO_CB_COMPLETE_HANDLER(caio_cb)               (&((caio_cb)->complete_handler))

typedef struct
{
    uint64_t                 next_time_msec;               /*next time calculating statistics*/
    uint64_t                 op_counter[ 2 ];              /*RD, WR*/
    uint64_t                 op_nbytes [ 2 ];              /*RD, WR*/
    uint64_t                 cost_msec [ 2 ];              /*RD, WR*/
    uint64_t                 dispatch_hit;                 /*dispatch node and hit existing page*/
    uint64_t                 dispatch_miss;                /*dispatch node but not hit existing page*/
    uint64_t                 page_is_aligned_counter[2];   /*RD, WR, page [f_s_offset, f_e_offset] is aligned*/
    uint64_t                 page_not_aligned_counter[2];  /*RD, WR, page [f_s_offset, f_e_offset] is not aligned*/
    uint64_t                 node_is_aligned_counter[2];   /*RD, WR, node [b_s_offset, b_e_offset] and buff addr are aligned*/
    uint64_t                 node_not_aligned_counter[2];  /*RD, WR, node [b_s_offset, b_e_offset] or buff addr are not aligned*/
    uint64_t                 mem_reused_counter;
    uint64_t                 mem_zcopy_counter;            /*zero copy counter*/
    uint64_t                 mem_fcopy_counter;            /*fast copy counter*/
}CAIO_STAT;

#define CAIO_STAT_NEXT_TIME_MSEC(caio_stat)               ((caio_stat)->next_time_msec)
#define CAIO_STAT_OP_COUNTER(caio_stat, op)               ((caio_stat)->op_counter[ (op) ])
#define CAIO_STAT_OP_NBYTES(caio_stat, op)                ((caio_stat)->op_nbytes[ (op) ])
#define CAIO_STAT_COST_MSEC(caio_stat, op)                ((caio_stat)->cost_msec[ (op) ])

#define CAIO_STAT_DISPATCH_HIT(caio_stat)                 ((caio_stat)->dispatch_hit)
#define CAIO_STAT_DISPATCH_MISS(caio_stat)                ((caio_stat)->dispatch_miss)

#define CAIO_STAT_PAGE_IS_ALIGNED_COUNTER(caio_stat, op)  ((caio_stat)->page_is_aligned_counter[ (op) ])
#define CAIO_STAT_PAGE_NOT_ALIGNED_COUNTER(caio_stat, op) ((caio_stat)->page_not_aligned_counter[ (op) ])
#define CAIO_STAT_NODE_IS_ALIGNED_COUNTER(caio_stat, op)  ((caio_stat)->node_is_aligned_counter[ (op) ])
#define CAIO_STAT_NODE_NOT_ALIGNED_COUNTER(caio_stat, op) ((caio_stat)->node_not_aligned_counter[ (op) ])

#define CAIO_STAT_MEM_REUSED_COUNTER(caio_stat)           ((caio_stat)->mem_reused_counter)
#define CAIO_STAT_MEM_ZCOPY_COUNTER(caio_stat)            ((caio_stat)->mem_zcopy_counter)
#define CAIO_STAT_MEM_FCOPY_COUNTER(caio_stat)            ((caio_stat)->mem_fcopy_counter)

typedef struct
{
    int                      fd;
    int                      rsvd;

    const char              *tag;

    UINT32                  *max_req_num;
    UINT32                   cur_req_num;
    UINT32                   submit_req_num; /*record submit aio request num this time temporarily*/

    CPG_BITMAP              *bad_bitmap; /*mounted point. inheritted from camd*/

    /*statistics*/
    CAIO_STAT                caio_stat;
    CAIO_STAT                caio_stat_saved;
}CAIO_DISK;

#define CAIO_DISK_FD(caio_disk)                         ((caio_disk)->fd)
#define CAIO_DISK_TAG(caio_disk)                        ((caio_disk)->tag)
#define CAIO_DISK_MAX_REQ_NUM(caio_disk)                ((caio_disk)->max_req_num)
#define CAIO_DISK_CUR_REQ_NUM(caio_disk)                ((caio_disk)->cur_req_num)
#define CAIO_DISK_SUBMIT_REQ_NUM(caio_disk)             ((caio_disk)->submit_req_num)
#define CAIO_DISK_BAD_BITMAP(caio_disk)                 ((caio_disk)->bad_bitmap)
#define CAIO_DISK_STAT(caio_disk)                       (&((caio_disk)->caio_stat))
#define CAIO_DISK_STAT_SAVED(caio_disk)                 (&((caio_disk)->caio_stat_saved))

typedef void (*CAIO_EVENT_HANDLER)(void *);

typedef struct
{
    UINT32           model;             /*CAIO_xxxx_MODEL*/

    UINT32           req_seq_no;        /*req sequence number factory of aio requests*/
    UINT32           submit_seq_no;     /*sequence number factory of aio submit action*/

    uint32_t         read_only_flag:1;  /*caio is read-only if set*/
    uint32_t         rsvd01:31;

    int              aio_eventfd;
    aio_context_t    aio_context;       /*8B*/

    CLIST            disk_list;         /*item is CAIO_DISK*/

    CLIST            req_list;          /*item is CAIO_REQ. reading & writing request list in order*/
    CLIST            page_list[2];      /*item is CAIO_PAGE. working page list*/
    CRB_TREE         page_tree[2];      /*item is CAIO_PAGE. working page tree*/
    UINT32           page_active_idx;   /*page list/tree active index, range in [0, 1]*/

    CRB_TREE         req_timeout_tree;

    CLIST            post_event_reqs;   /*item is CAIO_REQ */
}CAIO_MD;

#define CAIO_MD_MODEL(caio_md)                          ((caio_md)->model)

#define CAIO_MD_REQ_SEQ_NO(caio_md)                     ((caio_md)->req_seq_no)
#define CAIO_MD_SUBMIT_SEQ_NO(caio_md)                  ((caio_md)->submit_seq_no)

#define CAIO_MD_RDONLY_FLAG(caio_md)                    ((caio_md)->read_only_flag)

#define CAIO_MD_AIO_EVENTFD(caio_md)                    ((caio_md)->aio_eventfd)
#define CAIO_MD_AIO_CONTEXT(caio_md)                    ((caio_md)->aio_context)

#define CAIO_MD_DISK_LIST(caio_md)                      (&((caio_md)->disk_list))

#define CAIO_MD_REQ_LIST(caio_md)                       (&((caio_md)->req_list))
#define CAIO_MD_PAGE_ACTIVE_IDX(caio_md)                ((caio_md)->page_active_idx)
#define CAIO_MD_PAGE_STANDBY_IDX(caio_md)               (1 ^ CAIO_MD_PAGE_ACTIVE_IDX(caio_md))
#define CAIO_MD_PAGE_LIST(caio_md, idx)                 (&((caio_md)->page_list[ (idx) ]))
#define CAIO_MD_PAGE_TREE(caio_md, idx)                 (&((caio_md)->page_tree[ (idx) ]))

#define CAIO_MD_REQ_TIMEOUT_TREE(caio_md)               (&((caio_md)->req_timeout_tree))

#define CAIO_MD_POST_EVENT_REQS(caio_md)                (&((caio_md)->post_event_reqs))

#define CAIO_MD_SWITCH_PAGE_LIST(caio_md)               \
    do{                                                 \
        CAIO_MD_PAGE_ACTIVE_IDX(caio_md) ^= 1;     \
    }while(0)

typedef struct
{
    uint32_t                working_flag     :1;    /*page is reading or writing disk*/
    uint32_t                mem_cache_flag   :1;    /*page is shortcut to mem cache page*/
    uint32_t                mem_reused_flag  :1;
    uint32_t                rsvd01           :29;
    int                     fd;

    UINT32                  f_s_offset;
    UINT32                  f_e_offset;
    uint32_t                page_no;
    uint32_t                rsvd02;

    UINT32                  op;                     /*reading or writing*/

    struct iocb             aiocb;                  /*64B*/

    /*UINT32                  timeout_nsec; */          /*timeout in seconds*/

    UINT8                  *m_cache;                /*cache for one page*/

    CLIST                   owners;                 /*item is CAIO_NODE*/

    CAIO_MD                *caio_md;                /*shortcut: point to caio module*/
    CAIO_DISK              *caio_disk;              /*shortcut: page in which disk*/

    /*shortcut*/

    CLIST_DATA             *mounted_list;           /*mount point in page list of caio module*/
    CRB_NODE               *mounted_tree;           /*mount point in page tree of caio module*/
    UINT32                  mounted_idx;            /*mount in which page idx*/

    /*statistics*/
    uint64_t                submit_usec;            /*for debug only*/
    uint64_t                s_msec;
    uint64_t                e_msec;
}CAIO_PAGE;

#define CAIO_PAGE_WORKING_FLAG(caio_page)               ((caio_page)->working_flag)
#define CAIO_PAGE_MEM_CACHE_FLAG(caio_page)             ((caio_page)->mem_cache_flag)
#define CAIO_PAGE_MEM_REUSED_FLAG(caio_page)            ((caio_page)->mem_reused_flag)

#define CAIO_PAGE_FD(caio_page)                         ((caio_page)->fd)
#define CAIO_PAGE_F_S_OFFSET(caio_page)                 ((caio_page)->f_s_offset)
#define CAIO_PAGE_F_E_OFFSET(caio_page)                 ((caio_page)->f_e_offset)
#define CAIO_PAGE_NO(caio_page)                         ((caio_page)->page_no)

#define CAIO_PAGE_OP(caio_page)                         ((caio_page)->op)
#define CAIO_PAGE_AIOCB(caio_page)                      (&((caio_page)->aiocb))

#define CAIO_PAGE_M_CACHE(caio_page)                    ((caio_page)->m_cache)

#define CAIO_PAGE_OWNERS(caio_page)                     (&((caio_page)->owners))

#define CAIO_PAGE_CAIO_MD(caio_page)                    ((caio_page)->caio_md)
#define CAIO_PAGE_CAIO_DISK(caio_page)                  ((caio_page)->caio_disk)

#define CAIO_PAGE_SUBMIT_USEC(caio_page)                ((caio_page)->submit_usec)
#define CAIO_PAGE_S_MSEC(caio_page)                     ((caio_page)->s_msec)
#define CAIO_PAGE_E_MSEC(caio_page)                     ((caio_page)->e_msec)

#define CAIO_PAGE_MOUNTED_LIST(caio_page)               ((caio_page)->mounted_list)
#define CAIO_PAGE_MOUNTED_TREE(caio_page)               ((caio_page)->mounted_tree)
#define CAIO_PAGE_MOUNTED_IDX(caio_page)                ((caio_page)->mounted_idx)

#define CAIO_AIOCB_PAGE(__aiocb)     \
        ((CAIO_PAGE *)((char *)(__aiocb)-(unsigned long)(&((CAIO_PAGE *)0)->aiocb)))

typedef struct
{
    UINT32                  model;              /*CAIO_xxxx_MODEL*/

    UINT32                  seq_no;             /*unique sequence number of request*/
    UINT32                  op;                 /*reading or writing*/

    UINT32                  sub_seq_num;        /*sub request number*/
    UINT32                  succ_num;           /*complete nodes number*/
    UINT32                  u_e_offset;         /*upper offset at most in file*/

    CAIO_MD                *caio_md;            /*shortcut: point to caio module*/
    int                     fd;                 /*inherited from application*/
    int                     rsvd01;
    UINT8                  *m_cache;            /*inherited from application*/
    UINT8                  *m_buff;             /*inherited from application*/
    UINT32                 *offset;             /*inherited from application*/
    UINT32                  f_s_offset;         /*start offset in file*/
    UINT32                  f_e_offset;         /*end offset in file*/
    UINT32                  timeout_nsec;       /*timeout in seconds*/
    uint64_t                next_access_ms;     /*next access in msec*/

    uint64_t                s_msec;             /*start time in msec*/
    uint64_t                e_msec;             /*end time in msec*/

    CAIO_EVENT_HANDLER      post_event_handler;
    CLIST_DATA             *mounted_post_event_reqs;   /*mount point in post event reqs of caio md*/

    CLIST                   nodes;              /*item is CAIO_NODE*/

    /*shortcut*/
    CLIST_DATA             *mounted_list;      /*mount point in req list of caio module*/
    CRB_NODE               *mounted_timeout;

    CAIO_CB                 callback;
}CAIO_REQ;

#define CAIO_REQ_CB(caio_req)                           (&((caio_req)->callback))

#define CAIO_REQ_MODEL(caio_req)                        ((caio_req)->model)
#define CAIO_REQ_SEQ_NO(caio_req)                       ((caio_req)->seq_no)
#define CAIO_REQ_OP(caio_req)                           ((caio_req)->op)
#define CAIO_REQ_SUB_SEQ_NUM(caio_req)                  ((caio_req)->sub_seq_num)

#define CAIO_REQ_SUCC_NUM(caio_req)                     ((caio_req)->succ_num)
#define CAIO_REQ_U_S_OFFSET(caio_req)                   ((caio_req)->u_e_offset)

#define CAIO_REQ_CAIO_MD(caio_req)                      ((caio_req)->caio_md)
#define CAIO_REQ_FD(caio_req)                           ((caio_req)->fd)
#define CAIO_REQ_M_CACHE(caio_req)                      ((caio_req)->m_cache)
#define CAIO_REQ_M_BUFF(caio_req)                       ((caio_req)->m_buff)
#define CAIO_REQ_OFFSET(caio_req)                       ((caio_req)->offset)
#define CAIO_REQ_F_S_OFFSET(caio_req)                   ((caio_req)->f_s_offset)
#define CAIO_REQ_F_E_OFFSET(caio_req)                   ((caio_req)->f_e_offset)
#define CAIO_REQ_TIMEOUT_NSEC(caio_req)                 ((caio_req)->timeout_nsec)
#define CAIO_REQ_NTIME_MS(caio_req)                     ((caio_req)->next_access_ms)

#define CAIO_REQ_S_MSEC(caio_req)                       ((caio_req)->s_msec)
#define CAIO_REQ_E_MSEC(caio_req)                       ((caio_req)->e_msec)

#define CAIO_REQ_POST_EVENT_HANDLER(caio_req)           ((caio_req)->post_event_handler)
#define CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req)      ((caio_req)->mounted_post_event_reqs)

#define CAIO_REQ_NODES(caio_req)                        (&((caio_req)->nodes))
#define CAIO_REQ_MOUNTED_LIST(caio_req)                 ((caio_req)->mounted_list)
#define CAIO_REQ_MOUNTED_TIMEOUT(caio_req)              ((caio_req)->mounted_timeout)


typedef struct
{
    CAIO_REQ               *caio_req;           /*shortcut: point to parent request*/
    CAIO_PAGE              *caio_page;          /*shortcut: point to owning page*/

    UINT32                  seq_no;             /*inherited from caio req*/
    UINT32                  sub_seq_no;         /*mark the order in caio req*/
    UINT32                  sub_seq_num;        /*shortcut for debug purpose. inherited from caio req*/
    UINT32                  op;                 /*reading or writing*/

    CAIO_MD                *caio_md;            /*shortcut*/

    int                     fd;                 /*inherited from application*/
    int                     rsvd01;
    UINT8                  *m_cache;            /*inherited from caio page*/
    UINT8                  *m_buff;             /*inherited from application*/
    UINT32                  f_s_offset;         /*start offset in file*/
    UINT32                  f_e_offset;         /*end offset in file*/
    UINT32                  b_s_offset;         /*start offset in page*/
    UINT32                  b_e_offset;         /*end offset in page*/
    UINT32                  timeout_nsec;       /*timeout in seconds*/
    uint64_t                next_access_ms;     /*next access in msec*/

    /*shortcut*/
    CLIST_DATA             *mounted_nodes;      /*mount point in nodes of caio req*/
    CLIST_DATA             *mounted_owners;     /*mount point in owners of caio page*/
}CAIO_NODE;

#define CAIO_NODE_CAIO_REQ(caio_node)                   ((caio_node)->caio_req)
#define CAIO_NODE_CAIO_PAGE(caio_node)                  ((caio_node)->caio_page)
#define CAIO_NODE_SEQ_NO(caio_node)                     ((caio_node)->seq_no)
#define CAIO_NODE_SUB_SEQ_NO(caio_node)                 ((caio_node)->sub_seq_no)
#define CAIO_NODE_SUB_SEQ_NUM(caio_node)                ((caio_node)->sub_seq_num)
#define CAIO_NODE_OP(caio_node)                         ((caio_node)->op)
#define CAIO_NODE_CAIO_MD(caio_node)                    ((caio_node)->caio_md)
#define CAIO_NODE_FD(caio_node)                         ((caio_node)->fd)
#define CAIO_NODE_M_CACHE(caio_node)                    ((caio_node)->m_cache)
#define CAIO_NODE_M_BUFF(caio_node)                     ((caio_node)->m_buff)
#define CAIO_NODE_F_S_OFFSET(caio_node)                 ((caio_node)->f_s_offset)
#define CAIO_NODE_F_E_OFFSET(caio_node)                 ((caio_node)->f_e_offset)
#define CAIO_NODE_B_S_OFFSET(caio_node)                 ((caio_node)->b_s_offset)
#define CAIO_NODE_B_E_OFFSET(caio_node)                 ((caio_node)->b_e_offset)
#define CAIO_NODE_TIMEOUT_NSEC(caio_node)               ((caio_node)->timeout_nsec)
#define CAIO_NODE_NTIME_MS(caio_node)                   ((caio_node)->next_access_ms)
#define CAIO_NODE_MOUNTED_NODES(caio_node)              ((caio_node)->mounted_nodes)
#define CAIO_NODE_MOUNTED_OWNERS(caio_node)             ((caio_node)->mounted_owners)

/*----------------------------------- caio callback interface -----------------------------------*/
void caio_mem_cache_counter_print(LOG *log);

EC_BOOL caio_cb_handler_init(CAIO_CB_HANDLER *caio_cb_handler);

EC_BOOL caio_cb_handler_clean(CAIO_CB_HANDLER *caio_cb_handler);

EC_BOOL caio_cb_handler_set(CAIO_CB_HANDLER *caio_cb_handler, CAIO_CALLBACK func, void *arg);

EC_BOOL caio_cb_handler_clone(const CAIO_CB_HANDLER *caio_cb_handler_src, CAIO_CB_HANDLER *caio_cb_handler_des);

void caio_cb_handler_print(LOG *log, const CAIO_CB_HANDLER *caio_cb_handler);

EC_BOOL caio_cb_handler_exec(CAIO_CB_HANDLER *caio_cb_handler);

EC_BOOL caio_cb_init(CAIO_CB *caio_cb);

EC_BOOL caio_cb_clean(CAIO_CB *caio_cb);

EC_BOOL caio_cb_set_timeout_handler(CAIO_CB *caio_cb, const UINT32 timeout_nsec, CAIO_CALLBACK func, void *arg);

EC_BOOL caio_cb_set_terminate_handler(CAIO_CB *caio_cb, CAIO_CALLBACK func, void *arg);

EC_BOOL caio_cb_set_complete_handler(CAIO_CB *caio_cb, CAIO_CALLBACK func, void *arg);

EC_BOOL caio_cb_exec_timeout_handler(CAIO_CB *caio_cb);

EC_BOOL caio_cb_exec_terminate_handler(CAIO_CB *caio_cb);

EC_BOOL caio_cb_exec_complete_handler(CAIO_CB *caio_cb);

EC_BOOL caio_cb_clone(const CAIO_CB *caio_cb_src, CAIO_CB *caio_cb_des);

void caio_cb_print(LOG *log, const CAIO_CB *caio_cb);

/*----------------------------------- caio stat interface -----------------------------------*/
EC_BOOL caio_stat_init(CAIO_STAT *caio_stat);

EC_BOOL caio_stat_clean(CAIO_STAT *caio_stat);

/*----------------------------------- caio disk interface -----------------------------------*/

CAIO_DISK *caio_disk_new();

EC_BOOL caio_disk_init(CAIO_DISK *caio_disk);

EC_BOOL caio_disk_clean(CAIO_DISK *caio_disk);

EC_BOOL caio_disk_free(CAIO_DISK *caio_disk);

void caio_disk_print(LOG *log, const CAIO_DISK *caio_disk);

EC_BOOL caio_disk_is_fd(const CAIO_DISK *caio_disk, const int fd);

EC_BOOL caio_disk_set_bad_page(CAIO_DISK *caio_disk, const uint32_t page_no);

EC_BOOL caio_disk_clear_bad_page(CAIO_DISK *caio_disk, const uint32_t page_no);

EC_BOOL caio_disk_check_bad_page(CAIO_DISK *caio_disk, const uint32_t page_no);

/*----------------------------------- caio page interface -----------------------------------*/

CAIO_PAGE *caio_page_new();

EC_BOOL caio_page_init(CAIO_PAGE *caio_page);

EC_BOOL caio_page_clean(CAIO_PAGE *caio_page);

EC_BOOL caio_page_free(CAIO_PAGE *caio_page);

void caio_page_print(LOG *log, const CAIO_PAGE *caio_page);

void caio_page_print_range(LOG *log, const CAIO_PAGE *caio_page);

EC_BOOL caio_page_list_cmp(const CAIO_PAGE *caio_page_1st, const CAIO_PAGE *caio_page_2nd);

int caio_page_tree_cmp(const CAIO_PAGE *caio_page_1st, const CAIO_PAGE *caio_page_2nd);

EC_BOOL caio_page_is_aligned(CAIO_PAGE *caio_page, const UINT32 size, const UINT32 align);

EC_BOOL caio_page_add_node(CAIO_PAGE *caio_page, CAIO_NODE *caio_node);

EC_BOOL caio_page_del_node(CAIO_PAGE *caio_page, CAIO_NODE *caio_node);

CAIO_NODE *caio_page_first_node(CAIO_PAGE *caio_page);

EC_BOOL caio_page_cleanup_nodes(CAIO_PAGE *caio_page);

CAIO_NODE *caio_page_pop_node_front(CAIO_PAGE *caio_page);

CAIO_NODE *caio_page_pop_node_back(CAIO_PAGE *caio_page);

EC_BOOL caio_page_terminate(CAIO_PAGE *caio_page);

EC_BOOL caio_page_complete(CAIO_PAGE *caio_page);

/*----------------------------------- caio node interface -----------------------------------*/

CAIO_NODE *caio_node_new();

EC_BOOL caio_node_init(CAIO_NODE *caio_node);

EC_BOOL caio_node_clean(CAIO_NODE *caio_node);

EC_BOOL caio_node_free(CAIO_NODE *caio_node);

EC_BOOL caio_node_is(const CAIO_NODE *caio_node, const UINT32 sub_seq_no);

EC_BOOL caio_node_is_aligned(CAIO_NODE *caio_node, const UINT32 size, const UINT32 align);

void caio_node_print(LOG *log, const CAIO_NODE *caio_node);

EC_BOOL caio_node_timeout(CAIO_NODE *caio_node);

EC_BOOL caio_node_terminate(CAIO_NODE *caio_node);

EC_BOOL caio_node_complete(CAIO_NODE *caio_node);

/*----------------------------------- caio req interface -----------------------------------*/

CAIO_REQ *caio_req_new();

EC_BOOL caio_req_init(CAIO_REQ *caio_req);

EC_BOOL caio_req_clean(CAIO_REQ *caio_req);

EC_BOOL caio_req_free(CAIO_REQ *caio_req);

EC_BOOL caio_req_exec_timeout_handler(CAIO_REQ *caio_req);

EC_BOOL caio_req_exec_terminate_handler(CAIO_REQ *caio_req);

EC_BOOL caio_req_exec_complete_handler(CAIO_REQ *caio_req);

EC_BOOL caio_req_set_post_event(CAIO_REQ *caio_req, CAIO_EVENT_HANDLER handler);

EC_BOOL caio_req_del_post_event(CAIO_REQ *caio_req);

EC_BOOL caio_req_is(const CAIO_REQ *caio_req, const UINT32 seq_no);

int caio_req_timeout_cmp(const CAIO_REQ *caio_req_1st, const CAIO_REQ *caio_req_2nd);

void caio_req_print(LOG *log, const CAIO_REQ *caio_req);

EC_BOOL caio_req_cleanup_nodes(CAIO_REQ *caio_req);

EC_BOOL caio_req_push_node_back(CAIO_REQ *caio_req, CAIO_NODE *caio_node);

CAIO_NODE *caio_req_pop_node_back(CAIO_REQ *caio_req);

EC_BOOL caio_req_push_node_front(CAIO_REQ *caio_req, CAIO_NODE *caio_node);

CAIO_NODE *caio_req_pop_node_front(CAIO_REQ *caio_req);

EC_BOOL caio_req_del_node(CAIO_REQ *caio_req, CAIO_NODE *caio_node);

EC_BOOL caio_req_reorder_sub_seq_no(CAIO_REQ *caio_req);

EC_BOOL caio_req_make_read_op(CAIO_REQ *caio_req);

EC_BOOL caio_req_make_write_op(CAIO_REQ *caio_req);

EC_BOOL caio_req_make_read(CAIO_REQ *caio_req);

EC_BOOL caio_req_make_write(CAIO_REQ *caio_req);

EC_BOOL caio_req_timeout(CAIO_REQ *caio_req);

EC_BOOL caio_req_terminate(CAIO_REQ *caio_req);

EC_BOOL caio_req_complete(CAIO_REQ *caio_req);

EC_BOOL caio_req_dispatch_node(CAIO_REQ *caio_req, CAIO_NODE *caio_node);

EC_BOOL caio_req_cancel_node(CAIO_REQ *caio_req, CAIO_NODE *caio_node);

/*----------------------------------- caio module interface -----------------------------------*/

CAIO_MD *caio_start(const UINT32 model);

void caio_end(CAIO_MD *caio_md);

void caio_print(LOG *log, const CAIO_MD *caio_md);

/*for debug only*/
UINT32 caio_block_size_nbytes(const CAIO_MD *caio_md);

/*for debug only*/
UINT32 caio_block_size_nbits(const CAIO_MD *caio_md);

/*for debug only*/
UINT32 caio_block_size_mask(const CAIO_MD *caio_md);

EC_BOOL caio_event_handler(CAIO_MD *caio_md);

int caio_get_eventfd(CAIO_MD *caio_md);

EC_BOOL caio_try_quit(CAIO_MD *caio_md);

EC_BOOL caio_try_restart(CAIO_MD *caio_md);

EC_BOOL caio_set_read_only(CAIO_MD *caio_md);

EC_BOOL caio_unset_read_only(CAIO_MD *caio_md);

EC_BOOL caio_is_read_only(const CAIO_MD *caio_md);

/*for debug*/
EC_BOOL caio_poll(CAIO_MD *caio_md);

EC_BOOL caio_is_overhead(CAIO_MD *caio_md);

void caio_process(CAIO_MD *caio_md);

void caio_process_stat(CAIO_MD *caio_md);

void caio_process_reqs(CAIO_MD *caio_md);

/*check and process timeout reqs*/
void caio_process_timeout_reqs(CAIO_MD *caio_md);

void caio_process_pages(CAIO_MD *caio_md);

void caio_process_events(CAIO_MD *caio_md);

void caio_process_post_event_reqs(CAIO_MD *caio_md, const UINT32 process_event_max_num);

EC_BOOL caio_has_post_event_req(CAIO_MD *caio_md);

EC_BOOL caio_has_event(CAIO_MD *caio_md);

EC_BOOL caio_has_req(CAIO_MD *caio_md);

EC_BOOL caio_has_wr_req(CAIO_MD *caio_md);

void caio_show_pages(LOG *log, const CAIO_MD *caio_md);

void caio_show_post_event_reqs(LOG *log, const CAIO_MD *caio_md);

void caio_show_page(LOG *log, const CAIO_MD *caio_md, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset);

void caio_show_disks(LOG *log, const CAIO_MD *caio_md);

void caio_show_reqs(LOG *log, const CAIO_MD *caio_md);

void caio_show_req(LOG *log, const CAIO_MD *caio_md, const UINT32 seq_no);

void caio_show_node(LOG *log, const CAIO_MD *caio_md, const UINT32 seq_no, const UINT32 sub_seq_no);

EC_BOOL caio_submit_req(CAIO_MD *caio_md, CAIO_REQ *caio_req);

EC_BOOL caio_add_req(CAIO_MD *caio_md, CAIO_REQ *caio_req);

EC_BOOL caio_del_req(CAIO_MD *caio_md, CAIO_REQ *caio_req);

EC_BOOL caio_make_req_op(CAIO_MD *caio_md, CAIO_REQ *caio_req);

EC_BOOL caio_dispatch_req(CAIO_MD *caio_md, CAIO_REQ *caio_req);

EC_BOOL caio_cancel_req(CAIO_MD *caio_md, CAIO_REQ *caio_req);

UINT32 caio_count_page_num(const CAIO_MD *caio_md, const UINT32 page_choice_idx);

EC_BOOL caio_add_page(CAIO_MD *caio_md, const UINT32 page_choice_idx, CAIO_PAGE *caio_page);

EC_BOOL caio_del_page(CAIO_MD *caio_md, const UINT32 page_choice_idx, CAIO_PAGE *caio_page);

EC_BOOL caio_has_page(CAIO_MD *caio_md, const UINT32 page_choice_idx);

EC_BOOL caio_has_wr_page(CAIO_MD *caio_md, const UINT32 page_choice_idx);

CAIO_PAGE *caio_pop_first_page(CAIO_MD *caio_md, const UINT32 page_choice_idx);

CAIO_PAGE *caio_pop_last_page(CAIO_MD *caio_md, const UINT32 page_choice_idx);

CAIO_PAGE *caio_search_page(CAIO_MD *caio_md, const UINT32 page_choice_idx, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset);

EC_BOOL caio_cleanup_reqs(CAIO_MD *caio_md);

EC_BOOL caio_cleanup_pages(CAIO_MD *caio_md, const UINT32 page_choice_idx);

EC_BOOL caio_cleanup_post_event_reqs(CAIO_MD *caio_md);

CAIO_REQ *caio_search_req(CAIO_MD *caio_md, const UINT32 seq_no);

EC_BOOL caio_add_disk(CAIO_MD *caio_md, const int fd, const char *tag, UINT32 *max_req_num);

EC_BOOL caio_del_disk(CAIO_MD *caio_md, const int fd);

CAIO_DISK *caio_find_disk(CAIO_MD *caio_md, const int fd);

EC_BOOL caio_mount_disk_bad_bitmap(CAIO_MD *caio_md, const int fd, CPG_BITMAP *cpg_bitmap);

EC_BOOL caio_umount_disk_bad_bitmap(CAIO_MD *caio_md, const int fd);

EC_BOOL caio_is_disk_bad_page(CAIO_MD *caio_md, const int fd, const uint32_t page_no);

EC_BOOL caio_set_disk_bad_page(CAIO_MD *caio_md, const int fd, const uint32_t page_no);

EC_BOOL caio_clear_disk_bad_page(CAIO_MD *caio_md, const int fd, const uint32_t page_no);

UINT32 caio_count_req_num(CAIO_MD *caio_md);

/*----------------------------------- caio external interface -----------------------------------*/

EC_BOOL caio_file_read(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL caio_file_write(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff, CAIO_CB *caio_cb);


#endif /*_CAIO_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
