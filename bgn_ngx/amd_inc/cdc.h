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

#ifndef _CDC_H
#define _CDC_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"

#include "cdcnp.h"
#include "cdcdn.h"

#include "caio.h"

#include "cparacfg.h"

#define CDC_ERR_OFFSET                                 ((UINT32)~0)

#define CDC_OP_ERR                                     ((UINT32)0x0000) /*bitmap: 00*/
#define CDC_OP_RD                                      ((UINT32)0x0001) /*bitmap: 01*/
#define CDC_OP_WR                                      ((UINT32)0x0002) /*bitmap: 10*/
#define CDC_OP_RW                                      ((UINT32)0x0003) /*bitmap: 11*/

#define CDC_AIO_TIMEOUT_NSEC_DEFAULT                   (30)

#define CDC_AIO_FAIL_MAX_NUM                           (60) /*max fail 60 times*/

//#define CDC_MEM_CACHE_MAX_NUM                          ((UINT32)4096) /*1GB for 256K-page*/
#define CDC_MEM_CACHE_MAX_NUM                          ((UINT32)~0) /*no limitation*/

#define CDC_MEM_CACHE_ALIGN_SIZE_NBYTES                (1 << 10) /*align to 1KB*/
#define CDC_PROCESS_EVENT_ONCE_NUM                     (128)

#if 0
#define CDC_TRY_RETIRE_MAX_NUM                         (8)
#define CDC_TRY_RECYCLE_MAX_NUM                        (128)
#define CDC_SCAN_RETIRE_MAX_NUM                        (128)

#define CDC_PROCESS_DEGRADE_MAX_NUM                    (8) /*2 ssd for 1 sata*/
#define CDC_SCAN_DEGRADE_MAX_NUM                       (256)

#define CDC_RETIRE_HI_RATIO                            (0.8) /*80%*/
#define CDC_RETIRE_MD_RATIO                            (0.7) /*70%*/
#define CDC_RETIRE_LO_RATIO                            (0.5) /*50%*/
#endif
#define CDC_DEGRADE_TRAFFIC_10MB                       (((uint64_t)10) << 23) /*10MBps*/
#define CDC_DEGRADE_TRAFFIC_20MB                       (((uint64_t)20) << 23) /*20MBps*/
#define CDC_DEGRADE_TRAFFIC_30MB                       (((uint64_t)30) << 23) /*30MBps*/
#define CDC_DEGRADE_TRAFFIC_40MB                       (((uint64_t)40) << 23) /*40MBps*/

#define CDC_READ_TRAFFIC_05MB                          (((uint64_t) 5) << 23) /* 5MBps*/
#define CDC_READ_TRAFFIC_10MB                          (((uint64_t)10) << 23) /*10MBps*/
#define CDC_READ_TRAFFIC_15MB                          (((uint64_t)15) << 23) /*15MBps*/

#define CDC_WRITE_TRAFFIC_05MB                         (((uint64_t) 5) << 23) /* 5MBps*/
#define CDC_WRITE_TRAFFIC_10MB                         (((uint64_t)10) << 23) /*10MBps*/
#define CDC_WRITE_TRAFFIC_15MB                         (((uint64_t)15) << 23) /*15MBps*/


#define CDC_PAGE_TREE_IDX_ERR                          ((UINT32)~0)

typedef struct
{
    int                 ssd_fd;
    int                 sata_fd;

    UINT32              s_offset;
    UINT32              e_offset;
    UINT32              c_offset; /*temporary*/

    UINT32              key_max_num;

    CDCDN              *cdcdn;
    CDCNP              *cdcnp;

    CAIO_MD            *caio_md;

    UINT32              seq_no;            /*sequence number factory*/

    CLIST               req_list;          /*item is CXC_REQ. reading & writing request list in order*/
    CRB_TREE            page_tree[2];      /*item is CXC_PAGE. working page tree*/
    UINT32              page_tree_idx;     /*page tree active index, range in [0, 1]*/

    CLIST               post_event_reqs;   /*item is CXC_REQ */

    /*for degrade callback*/
    CDCNP_DEGRADE_CB    np_degrade_cb;

    uint32_t            fc_max_speed_flag:1;/*enable flow control in max speed, */
                                            /*i.e., flush data from ssd to sata in max speed*/
    uint32_t            rsvd01:31;
    uint32_t            rsvd02;

}CDC_MD;

#define CDC_MD_SSD_FD(cdc_md)                         ((cdc_md)->ssd_fd)
#define CDC_MD_SATA_FD(cdc_md)                        ((cdc_md)->sata_fd)
#define CDC_MD_S_OFFSET(cdc_md)                       ((cdc_md)->s_offset)
#define CDC_MD_E_OFFSET(cdc_md)                       ((cdc_md)->e_offset)
#define CDC_MD_C_OFFSET(cdc_md)                       ((cdc_md)->c_offset)
#define CDC_MD_KEY_MAX_NUM(cdc_md)                    ((cdc_md)->key_max_num)
#define CDC_MD_DN(cdc_md)                             ((cdc_md)->cdcdn)
#define CDC_MD_NP(cdc_md)                             ((cdc_md)->cdcnp)
#define CDC_MD_NP_DEGRADE_CB(cdc_md)                  (&((cdc_md)->np_degrade_cb))
#define CDC_MD_CAIO_MD(cdc_md)                        ((cdc_md)->caio_md)

#define CDC_MD_FC_MAX_SPEED_FLAG(cdc_md)              ((cdc_md)->fc_max_speed_flag)

#define CDC_MD_SEQ_NO(cdc_md)                         ((cdc_md)->seq_no)
#define CDC_MD_REQ_LIST(cdc_md)                       (&((cdc_md)->req_list))
#define CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md)           ((cdc_md)->page_tree_idx)
#define CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md)          (1 ^ CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md))
#define CDC_MD_PAGE_TREE(cdc_md, idx)                 (&((cdc_md)->page_tree[ (idx) ]))
#define CDC_MD_POST_EVENT_REQS(cdc_md)                (&((cdc_md)->post_event_reqs))

#define CDC_MD_SWITCH_PAGE_TREE(cdc_md)               \
    do{                                               \
        CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) ^= 1;     \
    }while(0)

typedef struct
{
    int                     fd;
    int                     rsvd01;

    UINT32                  f_s_offset;
    UINT32                  f_e_offset;

    UINT32                  d_s_offset;             /*start offset in ssd*/
    UINT32                  d_e_offset;             /*end offset in ssd*/
    UINT32                  d_t_offset;             /*temporary offset*/

    UINT32                  op;                     /*reading or writing*/

    UINT32                  timeout_nsec;           /*timeout in seconds*/

    uint32_t                dirty_flag       :1;    /*page was changed by writing op*/
    uint32_t                ssd_loaded_flag  :1;    /*page was loaded from ssd*/
    uint32_t                ssd_loading_flag :1;    /*page is loading from ssd*/
    uint32_t                ssd_flushing_flag:1;    /*page is flushing to ssd */
    uint32_t                mem_cache_flag   :1;    /*page is shortcut to mem cache page*/
    uint32_t                sata_dirty_flag  :1;    /*inherited from cdc node*/
    uint32_t                rsvd02           :26;

    uint32_t                fail_counter;

    UINT8                  *m_cache;                /*cache for one page*/
    CDCNP_ITEM             *cdcnp_item;             /*shortcut: point to item of the page*/
    uint32_t                cdcnp_item_pos;
    uint32_t                rsvd03;

    CLIST                   owners;                 /*item is CDC_NODE*/

    CDC_MD                 *cdc_md;                 /*shortcut: point to cdc module*/

    /*shortcut*/
    CRB_NODE               *mounted_pages;          /*mount point in page tree of cdc module*/
    UINT32                  mounted_tree_idx;       /*mount in which page tree*/
}CDC_PAGE;

#define CDC_PAGE_FD(cdc_page)                         ((cdc_page)->fd)

#define CDC_PAGE_F_S_OFFSET(cdc_page)                 ((cdc_page)->f_s_offset)
#define CDC_PAGE_F_E_OFFSET(cdc_page)                 ((cdc_page)->f_e_offset)

#define CDC_PAGE_D_S_OFFSET(cdc_page)                 ((cdc_page)->d_s_offset)
#define CDC_PAGE_D_E_OFFSET(cdc_page)                 ((cdc_page)->d_e_offset)
#define CDC_PAGE_D_T_OFFSET(cdc_page)                 ((cdc_page)->d_t_offset)

#define CDC_PAGE_OP(cdc_page)                         ((cdc_page)->op)

#define CDC_PAGE_TIMEOUT_NSEC(cdc_page)               ((cdc_page)->timeout_nsec)
#define CDC_PAGE_DIRTY_FLAG(cdc_page)                 ((cdc_page)->dirty_flag)
#define CDC_PAGE_SSD_LOADED_FLAG(cdc_page)            ((cdc_page)->ssd_loaded_flag)
#define CDC_PAGE_SSD_LOADING_FLAG(cdc_page)           ((cdc_page)->ssd_loading_flag)
#define CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page)          ((cdc_page)->ssd_flushing_flag)
#define CDC_PAGE_MEM_CACHE_FLAG(cdc_page)             ((cdc_page)->mem_cache_flag)
#define CDC_PAGE_SATA_DIRTY_FLAG(cdc_page)            ((cdc_page)->sata_dirty_flag)

#define CDC_PAGE_FAIL_COUNTER(cdc_page)               ((cdc_page)->fail_counter)

#define CDC_PAGE_M_CACHE(cdc_page)                    ((cdc_page)->m_cache)
#define CDC_PAGE_CDCNP_ITEM(cdc_page)                 ((cdc_page)->cdcnp_item)
#define CDC_PAGE_CDCNP_ITEM_POS(cdc_page)             ((cdc_page)->cdcnp_item_pos)
#define CDC_PAGE_OWNERS(cdc_page)                     (&((cdc_page)->owners))
#define CDC_PAGE_CDC_MD(cdc_page)                     ((cdc_page)->cdc_md)
#define CDC_PAGE_MOUNTED_PAGES(cdc_page)              ((cdc_page)->mounted_pages)
#define CDC_PAGE_MOUNTED_TREE_IDX(cdc_page)           ((cdc_page)->mounted_tree_idx)

typedef void (*CDC_EVENT_HANDLER)(void *);

typedef struct
{
    CAIO_CB                 caio_cb;

    UINT32                  seq_no;             /*unique sequence number of request*/
    UINT32                  op;                 /*reading or writing*/

    UINT32                  sub_seq_num;        /*sub request number*/
    UINT32                  node_num;           /*working node number*/
    UINT32                  succ_num;           /*complete nodes number*/
    UINT32                  u_e_offset;         /*upper offset at most in file*/

    CDC_MD                 *cdc_md;             /*shortcut: point to cdc module*/
    int                     fd;                 /*inherited from application*/
    uint32_t                detached_flag  :1;  /*write in detached model if set to 1*/
    uint32_t                keep_lru_flag  :1;  /*do not modify cdc np lru info if set to 1*/
    uint32_t                sata_dirty_flag:1;  /*inherited from application*/
    uint32_t                rsvd01         :29;
    UINT8                  *m_cache;            /*inherited from cdc page. not used yet!*/
    UINT8                  *m_buff;             /*inherited from application*/
    UINT32                 *offset;             /*inherited from application*/
    UINT32                  f_s_offset;         /*start offset in file*/
    UINT32                  f_e_offset;         /*end offset in file*/
    UINT32                  timeout_nsec;       /*timeout in seconds*/
    uint64_t                next_access_ms;     /*next access in msec*/

    CDC_EVENT_HANDLER       post_event_handler;
    CLIST_DATA             *mounted_post_event_reqs;   /*mount point in post event reqs of cdc md*/

    CLIST                   nodes;              /*item is CDC_NODE*/

    /*shortcut*/
    CLIST_DATA             *mounted_reqs;      /*mount point in req list of cdc module*/
}CDC_REQ;

#define CDC_REQ_CAIO_CB(cdc_req)                      (&((cdc_req)->caio_cb))

#define CDC_REQ_SEQ_NO(cdc_req)                       ((cdc_req)->seq_no)
#define CDC_REQ_OP(cdc_req)                           ((cdc_req)->op)
#define CDC_REQ_SUB_SEQ_NUM(cdc_req)                  ((cdc_req)->sub_seq_num)

#define CDC_REQ_NODE_NUM(cdc_req)                     ((cdc_req)->node_num)
#define CDC_REQ_SUCC_NUM(cdc_req)                     ((cdc_req)->succ_num)
#define CDC_REQ_U_E_OFFSET(cdc_req)                   ((cdc_req)->u_e_offset)

#define CDC_REQ_CDC_MD(cdc_req)                       ((cdc_req)->cdc_md)
#define CDC_REQ_FD(cdc_req)                           ((cdc_req)->fd)
#define CDC_REQ_DETACHED_FLAG(cdc_req)                ((cdc_req)->detached_flag)
#define CDC_REQ_KEEP_LRU_FLAG(cdc_req)                ((cdc_req)->keep_lru_flag)
#define CDC_REQ_SATA_DIRTY_FLAG(cdc_req)              ((cdc_req)->sata_dirty_flag)
#define CDC_REQ_M_CACHE(cdc_req)                      ((cdc_req)->m_cache)
#define CDC_REQ_M_BUFF(cdc_req)                       ((cdc_req)->m_buff)
#define CDC_REQ_OFFSET(cdc_req)                       ((cdc_req)->offset)
#define CDC_REQ_F_S_OFFSET(cdc_req)                   ((cdc_req)->f_s_offset)
#define CDC_REQ_F_E_OFFSET(cdc_req)                   ((cdc_req)->f_e_offset)
#define CDC_REQ_TIMEOUT_NSEC(cdc_req)                 ((cdc_req)->timeout_nsec)
#define CDC_REQ_NTIME_MS(cdc_req)                     ((cdc_req)->next_access_ms)

#define CDC_REQ_POST_EVENT_HANDLER(cdc_req)           ((cdc_req)->post_event_handler)
#define CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req)      ((cdc_req)->mounted_post_event_reqs)

#define CDC_REQ_NODES(cdc_req)                        (&((cdc_req)->nodes))
#define CDC_REQ_MOUNTED_REQS(cdc_req)                 ((cdc_req)->mounted_reqs)

typedef struct
{
    CDC_REQ                *cdc_req;            /*shortcut: point to parent request*/
    CDC_PAGE               *cdc_page;           /*shortcut: point to owning page*/

    UINT32                  seq_no;             /*inherited from cdc req*/
    UINT32                  sub_seq_no;         /*mark the order in cdc req*/
    UINT32                  sub_seq_num;        /*shortcut for debug purpose. inherited from cdc req*/
    UINT32                  op;                 /*reading or writing*/

    CDC_MD                 *cdc_md;             /*shortcut: point to cdc module*/
    int                     fd;                 /*inherited from application*/
    uint32_t                m_buf_flag     :1;  /*m_buf should be free if set 1*/
    uint32_t                sata_dirty_flag:1;  /*inherited from cdc req*/
    uint32_t                rsvd01         :30;
    UINT8                  *m_cache;            /*inherited from cdc page*/
    UINT8                  *m_buff;             /*inherited from application*/
    UINT32                  f_s_offset;         /*start offset in file*/
    UINT32                  f_e_offset;         /*end offset in file*/
    UINT32                  b_s_offset;         /*start offset in page*/
    UINT32                  b_e_offset;         /*end offset in page*/
    UINT32                  timeout_nsec;       /*timeout in seconds*/
    uint64_t                next_access_ms;     /*next access in msec*/

    /*shortcut*/
    CLIST_DATA             *mounted_nodes;      /*mount point in nodes of cdc req*/
    CLIST_DATA             *mounted_owners;     /*mount point in owners of cdc page*/
}CDC_NODE;

#define CDC_NODE_CDC_REQ(cdc_node)                    ((cdc_node)->cdc_req)
#define CDC_NODE_CDC_PAGE(cdc_node)                   ((cdc_node)->cdc_page)
#define CDC_NODE_SEQ_NO(cdc_node)                     ((cdc_node)->seq_no)
#define CDC_NODE_SUB_SEQ_NO(cdc_node)                 ((cdc_node)->sub_seq_no)
#define CDC_NODE_SUB_SEQ_NUM(cdc_node)                ((cdc_node)->sub_seq_num)
#define CDC_NODE_OP(cdc_node)                         ((cdc_node)->op)
#define CDC_NODE_CDC_MD(cdc_node)                     ((cdc_node)->cdc_md)
#define CDC_NODE_FD(cdc_node)                         ((cdc_node)->fd)
#define CDC_NODE_M_CACHE(cdc_node)                    ((cdc_node)->m_cache)
#define CDC_NODE_M_BUFF(cdc_node)                     ((cdc_node)->m_buff)
#define CDC_NODE_M_BUFF_FLAG(cdc_node)                ((cdc_node)->m_buf_flag)
#define CDC_NODE_SATA_DIRTY_FLAG(cdc_node)            ((cdc_node)->sata_dirty_flag)
#define CDC_NODE_F_S_OFFSET(cdc_node)                 ((cdc_node)->f_s_offset)
#define CDC_NODE_F_E_OFFSET(cdc_node)                 ((cdc_node)->f_e_offset)
#define CDC_NODE_B_S_OFFSET(cdc_node)                 ((cdc_node)->b_s_offset)
#define CDC_NODE_B_E_OFFSET(cdc_node)                 ((cdc_node)->b_e_offset)
#define CDC_NODE_TIMEOUT_NSEC(cdc_node)               ((cdc_node)->timeout_nsec)
#define CDC_NODE_NTIME_MS(cdc_node)                   ((cdc_node)->next_access_ms)
#define CDC_NODE_MOUNTED_NODES(cdc_node)              ((cdc_node)->mounted_nodes)
#define CDC_NODE_MOUNTED_OWNERS(cdc_node)             ((cdc_node)->mounted_owners)



/**
*
* start CDC module
*
**/
CDC_MD *cdc_start(const int ssd_fd, const UINT32 ssd_offset, const UINT32 ssd_disk_size/*in byte*/,
                    const int sata_fd, const UINT32 sata_disk_size/*in byte*/);

/**
*
* end CDC module
*
**/
void cdc_end(CDC_MD *cdc_md);

/**
*
* erase CDC
*
**/
EC_BOOL cdc_erase(CDC_MD *cdc_md);

/**
*
* create CDC
*
**/
EC_BOOL cdc_create(CDC_MD *cdc_md);

/**
*
* load CDC
*
**/
EC_BOOL cdc_load(CDC_MD *cdc_md);

/**
*
* flush CDC
*
**/
EC_BOOL cdc_flush(CDC_MD *cdc_md);

/**
*
* print CDC module
*
**/
void cdc_print(LOG *log, const CDC_MD *cdc_md);

/**
*
* bind CAIO module to CDC module
*
**/
EC_BOOL cdc_bind_aio(CDC_MD *cdc_md, CAIO_MD *caio_md);

/**
*
* unbind CAIO module from CDC module
*
**/
EC_BOOL cdc_unbind_aio(CDC_MD *cdc_md);

int cdc_get_eventfd(CDC_MD *cdc_md);

EC_BOOL cdc_event_handler(CDC_MD *cdc_md);


/**
*
* try to quit cdc
*
**/
EC_BOOL cdc_try_quit(CDC_MD *cdc_md);

/**
*
* flow control enable max speed
*
**/
EC_BOOL cdc_flow_control_enable_max_speed(CDC_MD *cdc_md);

/**
*
* flow control disable max speed
*
**/
EC_BOOL cdc_flow_control_disable_max_speed(CDC_MD *cdc_md);


/*for debug*/
EC_BOOL cdc_poll(CDC_MD *cdc_md);

/*for debug only!*/
EC_BOOL cdc_poll_debug(CDC_MD *cdc_md);

/**
*
*  create name node
*
**/
EC_BOOL cdc_create_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset, const UINT32 key_max_num);

/**
*
*  erase name node
*
**/
EC_BOOL cdc_erase_np(CDC_MD *cdc_md, const UINT32 s_offset, const UINT32 e_offset);

/**
*
*  close name node
*
**/
EC_BOOL cdc_close_np(CDC_MD *cdc_md);

/**
*
*  load name node from disk
*
**/
EC_BOOL cdc_load_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset);

/**
*
*  flush name node to disk
*
**/
EC_BOOL cdc_flush_np(CDC_MD *cdc_md);

/**
*
*  create data node
*
**/
EC_BOOL cdc_create_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset);

/**
*
*  load data node from disk
*
**/
EC_BOOL cdc_load_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset);

/**
*
*  flush data node to disk
*
**/
EC_BOOL cdc_flush_dn(CDC_MD *cdc_md);

/**
*
*  close data node
*
**/
EC_BOOL cdc_close_dn(CDC_MD *cdc_md);


/**
*
*  reserve space from dn
*
**/
EC_BOOL cdc_reserve_dn(CDC_MD *cdc_md, const UINT32 data_len, CDCNP_FNODE *cdcnp_fnode);

/**
*
*  release space to dn
*
**/
EC_BOOL cdc_release_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode);

/**
*
*  find item
*
**/
CDCNP_ITEM *cdc_find(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key);

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_read(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff);

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_write(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff);

/**
*
*  delete a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_delete(CDC_MD *cdc_md, UINT32 *offset, const UINT32 dsize);

/**
*
*  set file sata dirty flag which means cdc should flush it to sata later
*
**/
EC_BOOL cdc_file_set_sata_dirty(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize);

/**
*
*  set file sata flushed flag which means cdc should not flush it to sata
*
**/
EC_BOOL cdc_file_set_sata_flushed(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize);

/**
*
*  set file sata not flushed flag which means cdc should flush it to sata later
*
**/
EC_BOOL cdc_file_set_sata_not_flushed(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize);


/**
*
*  reserve a page
*
**/
EC_BOOL cdc_page_reserve(CDC_MD *cdc_md, CDC_PAGE *cdc_page, const CDCNP_KEY *cdcnp_key);

/**
*
*  release a page
*
**/
EC_BOOL cdc_page_release(CDC_MD *cdc_md, CDC_PAGE *cdc_page, const CDCNP_KEY *cdcnp_key);

/**
*
*  write a page
*
**/
EC_BOOL cdc_page_write(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes);

/**
*
*  read a page
*
**/
EC_BOOL cdc_page_read(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CBYTES *cbytes);

/**
*
*  write a page at offset
*
**/
EC_BOOL cdc_page_write_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read a page from offset
*
**/
EC_BOOL cdc_page_read_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  export data into data node
*
**/
EC_BOOL cdc_export_dn(CDC_MD *cdc_md, const CBYTES *cbytes, const CDCNP_FNODE *cdcnp_fnode);

/**
*
*  write data node
*
**/
EC_BOOL cdc_write_dn(CDC_MD *cdc_md, const CBYTES *cbytes, CDCNP_FNODE *cdcnp_fnode);

/**
*
*  read data node
*
**/
EC_BOOL cdc_read_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, CBYTES *cbytes);

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cdc_write_e_dn(CDC_MD *cdc_md, CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes);

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cdc_read_e_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes);

/**
*
*  delete a page
*
**/
EC_BOOL cdc_page_delete(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key);

/**
*
*  update a page
*
**/
EC_BOOL cdc_page_update(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes);

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cdc_file_num(CDC_MD *cdc_md, UINT32 *file_num);

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cdc_file_size(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, uint64_t *file_size);

/**
*
*  name node used ratio
*
**/
REAL cdc_used_ratio(CDC_MD *cdc_md);

/**
*
*  name node deg ratio
*
**/
REAL cdc_deg_ratio(CDC_MD *cdc_md);

/**
*
*  name node deg num
*
**/
uint32_t cdc_deg_num(CDC_MD *cdc_md);

/**
*
*  search in current name node
*
**/
EC_BOOL cdc_search(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key);

/**
*
*  empty recycle
*
**/
EC_BOOL cdc_recycle(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  retire files
*
**/
EC_BOOL cdc_retire(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  degrade files
*
**/
EC_BOOL cdc_degrade(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  set callback for degrading from ssd to sata
*
**/
EC_BOOL cdc_set_degrade_callback(CDC_MD *cdc_md, CDCNP_DEGRADE_CALLBACK func, void *arg);

/**
*
*  show name node
*
*
**/
EC_BOOL cdc_show_np(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show name node LRU
*
*
**/
EC_BOOL cdc_show_np_lru_list(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cdc_show_np_del_list(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show name node DEG
*
*
**/
EC_BOOL cdc_show_np_deg_list(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show name node BITMAP
*
*
**/
EC_BOOL cdc_show_np_bitmap(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show cdcdn info if it is dn
*
*
**/
EC_BOOL cdc_show_dn(const CDC_MD *cdc_md, LOG *log);

/**
*
*  show all files
*
**/

EC_BOOL cdc_show_files(const CDC_MD *cdc_md, LOG *log);

/*-------------------------------------------- cdc aio interface --------------------------------------------*/


/*----------------------------------- cdc page interface -----------------------------------*/

void cdc_mem_cache_counter_print(LOG *log);

CDC_PAGE *cdc_page_new();

EC_BOOL cdc_page_init(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_clean(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_free(CDC_PAGE *cdc_page);

void cdc_page_print(LOG *log, const CDC_PAGE *cdc_page);

int cdc_page_cmp(const CDC_PAGE *cdc_page_1st, const CDC_PAGE *cdc_page_2nd);

EC_BOOL cdc_page_map(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_locate(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_add_node(CDC_PAGE *cdc_page, CDC_NODE *cdc_node);

EC_BOOL cdc_page_del_node(CDC_PAGE *cdc_page, CDC_NODE *cdc_node);

EC_BOOL cdc_page_cleanup_nodes(CDC_PAGE *cdc_page);

CDC_NODE *cdc_page_pop_node_front(CDC_PAGE *cdc_page);

CDC_NODE *cdc_page_pop_node_back(CDC_PAGE *cdc_page);

/*process when page is in mem cache*/
EC_BOOL cdc_page_process(CDC_PAGE *cdc_page, const UINT32 retry_page_tree_idx);

EC_BOOL cdc_page_load_aio_timeout(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_load_aio_terminate(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_load_aio_complete(CDC_PAGE *cdc_page);

/*async model: load page from disk to mem cache*/
EC_BOOL cdc_page_load_aio(CDC_PAGE *cdc_page);

/*sync model: load page from disk to mem cache*/
EC_BOOL cdc_page_load(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_notify_timeout(CDC_PAGE *cdc_page);

/*aio flush timeout*/
EC_BOOL cdc_page_flush_aio_timeout(CDC_PAGE *cdc_page);

/*aio flush terminate*/
EC_BOOL cdc_page_flush_aio_terminate(CDC_PAGE *cdc_page);

/*aio flush complete*/
EC_BOOL cdc_page_flush_aio_complete(CDC_PAGE *cdc_page);

/*async model: flush page to ssd*/
EC_BOOL cdc_page_flush_aio(CDC_PAGE *cdc_page);

/*sync model: flush page to ssd*/
EC_BOOL cdc_page_flush(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_lock(CDC_PAGE *cdc_page);

EC_BOOL cdc_page_unlock(CDC_PAGE *cdc_page);

/*----------------------------------- cdc node interface -----------------------------------*/

CDC_NODE *cdc_node_new();

EC_BOOL cdc_node_init(CDC_NODE *cdc_node);

EC_BOOL cdc_node_clean(CDC_NODE *cdc_node);

EC_BOOL cdc_node_free(CDC_NODE *cdc_node);

EC_BOOL cdc_node_is(const CDC_NODE *cdc_node, const UINT32 sub_seq_no);

void cdc_node_print(LOG *log, const CDC_NODE *cdc_node);

EC_BOOL cdc_node_timeout(CDC_NODE *cdc_node);

EC_BOOL cdc_node_terminate(CDC_NODE *cdc_node);

EC_BOOL cdc_node_complete(CDC_NODE *cdc_node);

/*----------------------------------- cdc req interface -----------------------------------*/

CDC_REQ *cdc_req_new();

EC_BOOL cdc_req_init(CDC_REQ *cdc_req);

EC_BOOL cdc_req_clean(CDC_REQ *cdc_req);

EC_BOOL cdc_req_free(CDC_REQ *cdc_req);

EC_BOOL cdc_req_exec_timeout_handler(CDC_REQ *cdc_req);

EC_BOOL cdc_req_exec_terminate_handler(CDC_REQ *cdc_req);

EC_BOOL cdc_req_exec_complete_handler(CDC_REQ *cdc_req);

EC_BOOL cdc_req_set_post_event(CDC_REQ *cdc_req, CDC_EVENT_HANDLER handler);

EC_BOOL cdc_req_del_post_event(CDC_REQ *cdc_req);

EC_BOOL cdc_req_is(const CDC_REQ *cdc_req, const UINT32 seq_no);

void cdc_req_print(LOG *log, const CDC_REQ *cdc_req);

EC_BOOL cdc_req_cleanup_nodes(CDC_REQ *cdc_req);

EC_BOOL cdc_req_push_node_back(CDC_REQ *cdc_req, CDC_NODE *cdc_node);

CDC_NODE *cdc_req_pop_node_back(CDC_REQ *cdc_req);

EC_BOOL cdc_req_push_node_front(CDC_REQ *cdc_req, CDC_NODE *cdc_node);

EC_BOOL cdc_req_del_node(CDC_REQ *cdc_req, CDC_NODE *cdc_node);

EC_BOOL cdc_req_reorder_sub_seq_no(CDC_REQ *cdc_req);

EC_BOOL cdc_req_make_read_op(CDC_REQ *cdc_req);

EC_BOOL cdc_req_make_write_op(CDC_REQ *cdc_req);

EC_BOOL cdc_req_make_read(CDC_REQ *cdc_req);

EC_BOOL cdc_req_make_write(CDC_REQ *cdc_req);

EC_BOOL cdc_req_timeout(CDC_REQ *cdc_req);

EC_BOOL cdc_req_terminate(CDC_REQ *cdc_req);

EC_BOOL cdc_req_complete(CDC_REQ *cdc_req);

EC_BOOL cdc_req_dispatch_node(CDC_REQ *cdc_req, CDC_NODE *cdc_node);

EC_BOOL cdc_req_cancel_node(CDC_REQ *cdc_req, CDC_NODE *cdc_node);

/*----------------------------------- cdc module interface -----------------------------------*/


void cdc_process(CDC_MD *cdc_md, const uint64_t ssd_traffic_bps,
                 const uint64_t amd_read_traffic_bps, const uint64_t amd_write_traffic_bps,
                 const uint64_t sata_read_traffic_bps, const uint64_t sata_write_traffic_bps);

void cdc_process_degrades(CDC_MD *cdc_md, const uint64_t degrade_traffic_bps, const UINT32 scan_max_num, const UINT32 expect_degrade_num, UINT32 *complete_degrade_num);

void cdc_process_reqs(CDC_MD *cdc_md);

void cdc_process_timeout_reqs(CDC_MD *cdc_md);

void cdc_process_pages(CDC_MD *cdc_md);

void cdc_process_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page);

void cdc_process_events(CDC_MD *cdc_md);

void cdc_process_post_event_reqs(CDC_MD *cdc_md, const UINT32 process_event_max_num);

EC_BOOL cdc_has_event(CDC_MD *cdc_md);

EC_BOOL cdc_has_req(CDC_MD *cdc_md);

EC_BOOL cdc_lock_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page);

EC_BOOL cdc_unlock_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page);

EC_BOOL cdc_locate_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page);

EC_BOOL cdc_map_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page);

EC_BOOL cdc_reserve_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page);

EC_BOOL cdc_release_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page);

void cdc_show_pages(LOG *log, const CDC_MD *cdc_md);

void cdc_show_page(LOG *log, const CDC_MD *cdc_md, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset);

void cdc_show_reqs(LOG *log, const CDC_MD *cdc_md);

void cdc_show_req(LOG *log, const CDC_MD *cdc_md, const UINT32 seq_no);

void cdc_show_post_event_reqs(LOG *log, const CDC_MD *cdc_md);

void cdc_show_node(LOG *log, const CDC_MD *cdc_md, const UINT32 seq_no, const UINT32 sub_seq_no);

EC_BOOL cdc_submit_req(CDC_MD *cdc_md, CDC_REQ *cdc_req);

EC_BOOL cdc_add_req(CDC_MD *cdc_md, CDC_REQ *cdc_req);

EC_BOOL cdc_del_req(CDC_MD *cdc_md, CDC_REQ *cdc_req);

EC_BOOL cdc_make_req_op(CDC_MD *cdc_md, CDC_REQ *cdc_req);

EC_BOOL cdc_dispatch_req(CDC_MD *cdc_md, CDC_REQ *cdc_req);

EC_BOOL cdc_cancel_req(CDC_MD *cdc_md, CDC_REQ *cdc_req);

EC_BOOL cdc_add_page(CDC_MD *cdc_md, const UINT32 page_tree_idx, CDC_PAGE *cdc_page);

EC_BOOL cdc_del_page(CDC_MD *cdc_md, const UINT32 page_tree_idx, CDC_PAGE *cdc_page);

EC_BOOL cdc_has_page(CDC_MD *cdc_md, const UINT32 page_tree_idx);

CDC_PAGE *cdc_pop_first_page(CDC_MD *cdc_md, const UINT32 page_tree_idx);

CDC_PAGE *cdc_pop_last_page(CDC_MD *cdc_md, const UINT32 page_tree_idx);

CDC_PAGE *cdc_search_page(CDC_MD *cdc_md, const UINT32 page_tree_idx, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset);

EC_BOOL cdc_cleanup_pages(CDC_MD *cdc_md, const UINT32 page_tree_idx);

EC_BOOL cdc_cleanup_reqs(CDC_MD *cdc_md);

EC_BOOL cdc_cleanup_post_event_reqs(CDC_MD *cdc_md);

EC_BOOL cdc_has_post_event_reqs(CDC_MD *cdc_md);

CDC_REQ *cdc_search_req(CDC_MD *cdc_md, const UINT32 seq_no);

/*----------------------------------- cdc external interface -----------------------------------*/

EC_BOOL cdc_file_load_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL cdc_file_read_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

EC_BOOL cdc_file_write_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, const uint32_t sata_dirty_flag, CAIO_CB *caio_cb);


#endif /*_CDC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

