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

#ifndef _CPROC_H
#define _CPROC_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "type.h"

#include "mm.h"
#include "log.h"
#include "task.inc"

#include "csbuff.h"

#define CPROC_SUPPORT_MAX_COMM_SIZE     ((UINT32)128)

//#define CPROC_DATA_CACHE_MAX_SIZE       (UINT32_ONE << 20)  /*1M*/
//#define CPROC_DATA_CACHE_MAX_SIZE       (UINT32_ONE << 21)  /*2M*/
#define CPROC_DATA_CACHE_MAX_SIZE       (UINT32_ONE << 22)  /*4M*/

#define CPROC_RANK_IS_NOT_READY         ((UINT32) 1)
#define CPROC_RANK_IS_READY             ((UINT32) 2)
#define CPROC_RANK_IS_BROKEN            ((UINT32) 3)
#define CPROC_RANK_IS_ERR               ((UINT32)-1)

#define CPROC_DATA_AREA_IS_READING      ((UINT32) 1)
#define CPROC_DATA_AREA_IS_WRITING      ((UINT32) 2)
#define CPROC_DATA_AREA_IS_IDLE         ((UINT32) 3)

#define CPROC_IS_ABORTED               ((UINT32) 1)
#define CPROC_IS_RUNNING               ((UINT32) 2)

struct _TASK_NODE;

/*state of each process/rank*/
typedef struct
{
    UINT32     status;
}CPROC_STAT;

#define CPROC_STAT_STATUS(cproc_stat)                   ((cproc_stat)->status)

/*item[a][b]: rank a => rank b*/
typedef struct
{
    UINT32     row_rank;
    UINT32     col_rank;

    struct _TASK_NODE *incoming_task_node;   /*be recving task node*/
    CLIST      sedning_task_node_queue;/*task node queues*/
    CSBUFF     csbuff;
    UINT8      cache[CPROC_DATA_CACHE_MAX_SIZE];
}CPROC_ITEM;

#define CPROC_ITEM_ROW_RANK(cproc_item)             ((cproc_item)->row_rank)
#define CPROC_ITEM_COL_RANK(cproc_item)             ((cproc_item)->col_rank)

#define CPROC_ITEM_INCOMING_TASK_NODE(cproc_item)   ((cproc_item)->incoming_task_node)
#define CPROC_ITEM_SENDING_QUEUE(cproc_item)        (&((cproc_item)->sedning_task_node_queue))
#define CPROC_ITEM_CSBUFF(cproc_item)               (&((cproc_item)->csbuff))

#define CPROC_DATA_ITEM_TOTAL_SIZE                  (sizeof(CPROC_ITEM))

typedef struct
{
    UINT32      abort_flag;  /*abort flag*/

    UINT32      comm;
    UINT32      size;
    UINT32      tcid;

    CPROC_STAT  stat[CPROC_SUPPORT_MAX_COMM_SIZE];/*per process stat*/

    CPROC_ITEM  item[0];  /*per item in data area: cmutex + flag + read_pos + write_pos + max_len + cache[CPROC_DATA_AREA_MAX_SIZE]*/
}CPROC;

#define CPROC_ABORT_FLAG(cproc)                                 ((cproc)->abort_flag)
#define CPROC_COMM(cproc)                                       ((cproc)->comm)
#define CPROC_SIZE(cproc)                                       ((cproc)->size)
#define CPROC_TCID(cproc)                                       ((cproc)->tcid)
#define CPROC_RANK_STAT(cproc, rank)                            (&((cproc)->stat[(rank)]))
#define CPROC_RANK_STATUS(cproc, rank)                          (CPROC_STAT_STATUS(CPROC_RANK_STAT(cproc, rank)))
#define CPROC_ITEM(cproc, src_rank, des_rank)                   (&((cproc)->item[(src_rank) * CPROC_SIZE(cproc) + (des_rank)]))
#define CPROC_CSBUFF(cproc, src_rank, des_rank)                 (CPROC_ITEM_CSBUFF(CPROC_ITEM(cproc, src_rank, des_rank)))

#define CPROC_TOTAL_SIZE(comm_size) (sizeof(CPROC) + CPROC_DATA_ITEM_TOTAL_SIZE * (comm_size) * (comm_size))

EC_BOOL cproc_stat_init(CPROC_STAT *cproc_stat);

EC_BOOL cproc_stat_clean(CPROC_STAT *cproc_stat);

CPROC * cproc_new(const UINT32 comm, const UINT32 size, const UINT32 tcid, UINT32 *this_rank);

/*parent init cproc*/
EC_BOOL cproc_init(CPROC *cproc, const UINT32 comm, const UINT32 size, const UINT32 tcid);

EC_BOOL cproc_clean(CPROC *cproc);

EC_BOOL cproc_free(CPROC *cproc);

EC_BOOL cproc_abort(CPROC *cproc);

void    cproc_abort_default();

EC_BOOL cproc_init_by_rank(CPROC *cproc, const UINT32 src_rank);

EC_BOOL cproc_clean_by_rank(CPROC *cproc, const UINT32 src_rank);

/*parent check all children ready or not*/
EC_BOOL cproc_check_ready(const CPROC *cproc);

/*parent wait until all children ready*/
EC_BOOL cproc_wait_ready(const CPROC *cproc);

EC_BOOL cproc_send(CPROC *cproc, CPROC_ITEM *cproc_item, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos);

EC_BOOL cproc_recv(CPROC *cproc, CPROC_ITEM *cproc_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos);

EC_BOOL cproc_probe(CPROC *cproc, CPROC_ITEM *cproc_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos);

UINT32 cproc_probe_read_len(CPROC *cproc, CPROC_ITEM *cproc_item);

EC_BOOL cproc_isend(CPROC *cproc, const UINT32 recv_rank, const UINT32 msg_tag, struct _TASK_NODE *task_node);

struct _TASK_NODE *cproc_fetch_task_node(CPROC *cproc, CPROC_ITEM *cproc_item);

/*to fix a incomplete task_node, when complete, return EC_TRUE, otherwise, return EC_FALSE yet*/
EC_BOOL cproc_fix_task_node(CPROC *cproc, CPROC_ITEM *cproc_item, struct _TASK_NODE *task_node);

EC_BOOL cproc_isend_node(CPROC *cproc, CPROC_ITEM *cproc_item, struct _TASK_NODE *task_node);

EC_BOOL cproc_irecv_node(CPROC *cproc, CPROC_ITEM *cproc_item, CLIST *save_to_list);

EC_BOOL cproc_isend_on_item(CPROC *cproc, CPROC_ITEM *cproc_item);

EC_BOOL cproc_irecv_on_item(CPROC *cproc, CPROC_ITEM *cproc_item, CLIST *save_to_list);

EC_BOOL cproc_sending_handle(CPROC *cproc);

EC_BOOL cproc_recving_handle(CPROC *cproc, CLIST *save_to_list);

#endif /*_CPROC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

