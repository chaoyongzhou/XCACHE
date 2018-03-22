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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>

#include "type.h"

#include "mm.h"
#include "log.h"
#include "clist.h"

#include "task.inc"
#include "task.h"
#include "cmpic.inc"
#include "cmpie.h"
#include "csbuff.h"
#include "cproc.h"

#if 1
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 __pos__;\
    dbg_log(SEC_0085_CPROC, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos__ = 0; __pos__ < len; __pos__ ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ __pos__ ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif

STATIC_CAST static void cproc_bind_spec_core(const UINT32 rank)
{
    UINT32 core_max_num;
    UINT32 core_idx;
    cpu_set_t mask;

    core_max_num = sysconf(_SC_NPROCESSORS_ONLN);
    core_idx     = (rank % core_max_num);

    CPU_ZERO(&mask);
    CPU_SET(core_idx, &mask);

    if (0 > sched_setaffinity(0/*current process*/, sizeof(mask), &mask))
    {
        fprintf(stderr, "error: cproc_bind_spec_core: bind rank %ld to core %ld failed\n", rank, core_idx);
    }
    return;
}

STATIC_CAST static void cproc_bind_all_core(const UINT32 rank)
{
    UINT32 core_max_num;
    UINT32 core_idx;
    cpu_set_t mask;

    core_max_num = sysconf(_SC_NPROCESSORS_ONLN);

    CPU_ZERO(&mask);

    for(core_idx = 0; core_idx < core_max_num; core_idx ++)
    {
        CPU_SET(core_idx, &mask);
    }

    if (0 > sched_setaffinity(0/*current process*/, sizeof(mask), &mask))
    {
        fprintf(stderr, "error: cproc_bind_all_core: bind rank %ld to all core failed\n", rank);
    }
    return;
}

STATIC_CAST static void cproc_bind_none_core(const UINT32 rank)
{
    return;
}

EC_BOOL cproc_stat_init(CPROC_STAT *cproc_stat)
{
    CPROC_STAT_STATUS(cproc_stat) = CPROC_RANK_IS_ERR;
    return (EC_TRUE);
}

EC_BOOL cproc_stat_clean(CPROC_STAT *cproc_stat)
{
    CPROC_STAT_STATUS(cproc_stat) = CPROC_RANK_IS_ERR;
    return (EC_TRUE);
}

CPROC * cproc_new(const UINT32 comm, const UINT32 size, const UINT32 tcid, UINT32 *this_rank)
{
    UINT32 data_area_len;
    CPROC *cproc;

    UINT32 rank;

    data_area_len = CPROC_TOTAL_SIZE(size);

    cproc = (CPROC *)mmap(NULL_PTR, data_area_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if(MAP_FAILED == cproc)
    {
        fprintf(stdout, "cproc_new: mmap failed, errno = %d, errorstr = %s\n", errno, strerror(errno));
        return (NULL_PTR);
    }

    cproc_init(cproc, comm, size, tcid);/*initialize the common part for all ranks*/

    for(rank = 1; rank < size; rank ++)
    {
        pid_t  pid;

        pid = fork();
        if(-1 == pid)
        {
            fprintf(stdout, "error:cproc_new: parent create child failed\n");
            return (cproc);
        }

        if(0 == pid)/*child process*/
        {
            //cproc_bind_spec_core(rank);
            //cproc_bind_all_core(rank);
            //cproc_bind_none_core(rank);
#if 0
            fprintf(stdout, "[DEBUG] cproc_new: child %ld: pid %d, comm = %ld, size = %ld, data_area_len = %ld\n",
                                rank, getpid(), CPROC_COMM(cproc), CPROC_SIZE(cproc), data_area_len);
#endif
            cproc_init_by_rank(cproc, rank);

            (*this_rank) = rank;

            //TASK_BRD_COMM(task_brd) = comm;
            //TASK_BRD_TCID(task_brd) = tcid;
            //TASK_BRD_RANK(task_brd) = rank;

            CPROC_RANK_STATUS(cproc, rank) = CPROC_RANK_IS_READY;/*at last set ready status*/
            cproc_wait_ready(cproc);
            return (cproc);
        }
    }

    //cproc_bind_spec_core(0);
    cproc_init_by_rank(cproc, 0);

    (*this_rank) = 0;

    //TASK_BRD_COMM(task_brd) = comm;
    //TASK_BRD_TCID(task_brd) = tcid;
    //TASK_BRD_RANK(task_brd) = 0;

    CPROC_RANK_STATUS(cproc, 0) = CPROC_RANK_IS_READY;/*at last set ready status*/

    /*parent process*/
    cproc_wait_ready(cproc);
#if 0
    fprintf(stdout, "[DEBUG] cproc_new: parent %ld: pid %d, comm = %ld, size = %ld, data_area_len = %ld\n",
                        0, getpid(), CPROC_COMM(cproc), CPROC_SIZE(cproc), data_area_len);
#endif
    return (cproc);
}

EC_BOOL cproc_abort(CPROC *cproc)
{
    CPROC_ABORT_FLAG(cproc) = CPROC_IS_ABORTED;
    return (EC_TRUE);
}

void cproc_abort_default()
{
    CPROC *cproc;
    cproc = TASK_BRD_CPROC(task_brd_default_get());
    if(NULL_PTR != cproc)
    {
        cproc_abort(cproc);
    }
    return;
}

/*parent init cproc*/
EC_BOOL cproc_init(CPROC *cproc, const UINT32 comm, const UINT32 size, const UINT32 tcid)
{
    UINT32 rank;

    for(rank = 0; rank < CPROC_SIZE(cproc); rank ++)
    {
        cproc_stat_init(CPROC_RANK_STAT(cproc, rank));
    }

    CPROC_ABORT_FLAG(cproc) = CPROC_IS_RUNNING;
    CPROC_COMM(cproc) = comm;
    CPROC_SIZE(cproc) = size;
    CPROC_TCID(cproc) = tcid;

    atexit(cproc_abort_default);

    return (EC_TRUE);
}

EC_BOOL cproc_clean(CPROC *cproc)
{
    UINT32 rank;

    for(rank = 0; rank < CPROC_SIZE(cproc); rank ++)
    {
        cproc_stat_clean(CPROC_RANK_STAT(cproc, rank));
    }

    CPROC_COMM(cproc) = CMPI_ERROR_COMM;
    CPROC_SIZE(cproc) = 0;
    CPROC_TCID(cproc) = CMPI_ERROR_TCID;

    return (EC_TRUE);
}

EC_BOOL cproc_init_by_rank(CPROC *cproc, const UINT32 src_rank)
{
    UINT32 des_rank;

    for(des_rank = 0; des_rank < CPROC_SIZE(cproc); des_rank ++)
    {
        CPROC_ITEM *cproc_item;

        /***********************************************************************
            src_rank is the owner of (src_rank, des_rank) TO_SEND/SENDING QUEUE
            src_rank is the owner of (des_rank, src_rank) RECVING/IS_RECV QUEUE
        thus,
            any rank can reach send/recv data by (src_rank, des_rank)

        ***********************************************************************/

        cproc_item = CPROC_ITEM(cproc, src_rank, des_rank);
        CPROC_ITEM_ROW_RANK(cproc_item) = src_rank;
        CPROC_ITEM_COL_RANK(cproc_item) = des_rank;

        csbuff_init(CPROC_ITEM_CSBUFF(cproc_item), CMUTEX_PROCESS_SHARED/*CMUTEX_PROCESS_PRIVATE*/);
        csbuff_set_max_len(CPROC_ITEM_CSBUFF(cproc_item), CPROC_DATA_CACHE_MAX_SIZE);
        clist_init(CPROC_ITEM_SENDING_QUEUE(cproc_item), MM_IGNORE, LOC_CPROC_0001);

        cproc_item = CPROC_ITEM(cproc, des_rank, src_rank);
        CPROC_ITEM_INCOMING_TASK_NODE(cproc_item) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cproc_clean_by_rank(CPROC *cproc, const UINT32 src_rank)
{
    UINT32 des_rank;

    for(des_rank = 0; des_rank < CPROC_SIZE(cproc); des_rank ++)
    {
        CPROC_ITEM *cproc_item;

        cproc_item = CPROC_ITEM(cproc, src_rank, des_rank);
        csbuff_clean(CPROC_ITEM_CSBUFF(cproc_item));
        clist_clean(CPROC_ITEM_SENDING_QUEUE(cproc_item), (CLIST_DATA_DATA_CLEANER)task_node_free);

        cproc_item = CPROC_ITEM(cproc, des_rank, src_rank);
        task_node_free(CPROC_ITEM_INCOMING_TASK_NODE(cproc_item));
        CPROC_ITEM_INCOMING_TASK_NODE(cproc_item) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cproc_free(CPROC *cproc)
{
    if(NULL_PTR != cproc)
    {
        cproc_clean_by_rank(cproc, TASK_BRD_RANK(task_brd_default_get()));
        cproc_clean(cproc);
        munmap(cproc, CPROC_TOTAL_SIZE(CPROC_SIZE(cproc)));
    }
    return (EC_TRUE);
}

/*parent check all children ready or not*/
EC_BOOL cproc_check_ready(const CPROC *cproc)
{
    UINT32 rank;
    for(rank = 0; rank < CPROC_SIZE(cproc); rank ++)
    {
        if(CPROC_RANK_IS_READY != CPROC_RANK_STATUS(cproc, rank))
        {
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

/*parent wait until all children ready*/
EC_BOOL cproc_wait_ready(const CPROC *cproc)
{
   while(EC_FALSE == cproc_check_ready(cproc))
   {
        /*do nothing*/
   }
   return (EC_TRUE);
}

EC_BOOL cproc_send(CPROC *cproc, CPROC_ITEM *cproc_item, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *in_buff_pos)
{
    return csbuff_write(CPROC_ITEM_CSBUFF(cproc_item), in_buff, in_buff_max_len, in_buff_pos);
}

EC_BOOL cproc_recv(CPROC *cproc, CPROC_ITEM *cproc_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    return csbuff_read(CPROC_ITEM_CSBUFF(cproc_item), out_buff, out_buff_max_len, out_buff_pos);
}

EC_BOOL cproc_probe(CPROC *cproc, CPROC_ITEM *cproc_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *out_buff_pos)
{
    return csbuff_probe(CPROC_ITEM_CSBUFF(cproc_item), out_buff, out_buff_max_len, out_buff_pos);
}

UINT32 cproc_probe_read_len(CPROC *cproc, CPROC_ITEM *cproc_item)
{
    return csbuff_total_read_len(CPROC_ITEM_CSBUFF(cproc_item));
}

EC_BOOL cproc_isend(CPROC *cproc, const UINT32 recv_rank, const UINT32 msg_tag, TASK_NODE *task_node)
{
    CPROC_ITEM *cproc_item;
    UINT32 msg_len;
    UINT32 pos;

    /*check validity*/
    if(recv_rank >= CPROC_SIZE(cproc))
    {
        dbg_log(SEC_0085_CPROC, 0)(LOGSTDOUT, "error:cproc_isend: invalid recv rank %ld where communicator size is %ld\n", recv_rank, CPROC_SIZE(cproc));
        return (EC_FALSE);
    }

    cproc_item = CPROC_ITEM(cproc, CMPI_LOCAL_RANK, recv_rank);
#if 0
    dbg_log(SEC_0085_CPROC, 9)(LOGSTDOUT, "[DEBUG] cproc_isend: to send task_node %lx (pos %ld, len %ld) on cproc_item %lx (row %ld, col %ld) while send_rank = %ld, recv_rank = %ld\n",
                        task_node, TASK_NODE_BUFF_POS(task_node), TASK_NODE_BUFF_LEN(task_node),
                        cproc_item, CPROC_ITEM_ROW_RANK(cproc_item), CPROC_ITEM_COL_RANK(cproc_item), CMPI_LOCAL_RANK, recv_rank);
#endif
    msg_len = TASK_NODE_BUFF_LEN(task_node);
    pos = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)    
    cmpi_encode_uint32(CMPI_LOCAL_COMM, msg_len, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &pos);
    cmpi_encode_uint32(CMPI_LOCAL_COMM, msg_tag, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &pos);
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)    
    cmpi_encode_uint32_compressed_uint32_t(CMPI_LOCAL_COMM, msg_len, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &pos);
    cmpi_encode_uint32_compressed_uint8_t(CMPI_LOCAL_COMM, msg_tag, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &pos);
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    cproc_isend_node(cproc, cproc_item, task_node);
    return (EC_TRUE);
}

TASK_NODE *cproc_fetch_task_node(CPROC *cproc, CPROC_ITEM *cproc_item)
{
    UINT32    size;

    size = csocket_encode_actual_size();

    if(size <= cproc_probe_read_len(cproc, cproc_item))
    {
        UINT32  pos;

        UINT32  len;
        UINT32  tag;
        UINT8   out_buff[32];
        UINT32  out_size;

        TASK_NODE *task_node;
        TASK_BRD *task_brd;

        out_size = 0;
        if(EC_FALSE == cproc_probe(cproc, cproc_item, out_buff, size, &out_size))
        {
            return (NULL_PTR);
        }

        //dbg_log(SEC_0085_CPROC, 9)(LOGSTDOUT, "[DEBUG] cproc_fetch_task_node: [rank: %ld => %ld] out_size = %ld\n", CPROC_ITEM_ROW_RANK(cproc_item), CPROC_ITEM_COL_RANK(cproc_item),out_size);
        //PRINT_BUFF("[DEBUG] cproc_fetch_task_node: ", out_buff, out_size);

        task_brd = task_brd_default_get();

        pos = 0;
#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)        
        cmpi_decode_uint32(TASK_BRD_COMM(task_brd), out_buff, out_size, &pos, &len);
        cmpi_decode_uint32(TASK_BRD_COMM(task_brd), out_buff, out_size, &pos, &tag);
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)        
        cmpi_decode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), out_buff, out_size, &pos, &len);
        cmpi_decode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd), out_buff, out_size, &pos, &tag);
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

        //dbg_log(SEC_0085_CPROC, 9)(LOGSTDOUT, "[DEBUG] cproc_fetch_task_node: len = %ld, tag = %ld\n", len, tag);

        task_node = task_node_new(len, LOC_CPROC_0002);
        if(NULL_PTR == task_node)
        {
            dbg_log(SEC_0085_CPROC, 0)(LOGSTDOUT, "error:cproc_fetch_task_node: new task_node with %ld bytes failed\n", len);
            return (NULL_PTR);
        }

        TASK_NODE_TAG(task_node) = tag;

        cproc_recv(cproc, cproc_item, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &(TASK_NODE_BUFF_POS(task_node)));
        return (task_node);
    }
    return (NULL_PTR);
}

/*to fix a incomplete task_node, when complete, return EC_TRUE, otherwise, return EC_FALSE yet*/
EC_BOOL cproc_fix_task_node(CPROC *cproc, CPROC_ITEM *cproc_item, TASK_NODE *task_node)
{
    cproc_recv(cproc, cproc_item, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &(TASK_NODE_BUFF_POS(task_node)));

    /*when complete csocket_request, return EC_TRUE*/
    if(TASK_NODE_BUFF_LEN(task_node) == TASK_NODE_BUFF_POS(task_node))
    {
        return (EC_TRUE);
    }
    /*otherwise*/
    return (EC_FALSE);
}

EC_BOOL cproc_isend_node(CPROC *cproc, CPROC_ITEM *cproc_item, TASK_NODE *task_node)
{
    clist_push_back(CPROC_ITEM_SENDING_QUEUE(cproc_item), (void *)task_node);
    return (EC_TRUE);
}

EC_BOOL cproc_irecv_node(CPROC *cproc, CPROC_ITEM *cproc_item, CLIST *save_to_list)
{
    TASK_NODE *task_node;

    task_node = CPROC_ITEM_INCOMING_TASK_NODE(cproc_item);
    if(NULL_PTR != task_node)
    {
        if(EC_FALSE == cproc_fix_task_node(cproc, cproc_item, task_node))
        {
            return (EC_TRUE);
        }
        clist_push_back(save_to_list, (void *)task_node);/*here task node not decoded yet*/
        TASK_NODE_COMP(task_node) = TASK_WAS_RECV;
        CPROC_ITEM_INCOMING_TASK_NODE(cproc_item) = NULL_PTR;
    }

    for(;;)
    {
        task_node = cproc_fetch_task_node(cproc, cproc_item);
        if(NULL_PTR == task_node)
        {
            break;
        }

        if(TASK_NODE_BUFF_POS(task_node) == TASK_NODE_BUFF_LEN(task_node))
        {
            clist_push_back(save_to_list, (void *)task_node); /*here task node not decoded yet*/
            TASK_NODE_COMP(task_node) = TASK_WAS_RECV;
            //dbg_log(SEC_0085_CPROC, 9)(LOGSTDOUT, "[DEBUG] cproc_irecv_node: save incomded task_node\n");
        }
        else
        {
            CPROC_ITEM_INCOMING_TASK_NODE(cproc_item) = task_node;
            //dbg_log(SEC_0085_CPROC, 9)(LOGSTDOUT, "[DEBUG] cproc_irecv_node: save incoming task_node\n");
            /*terminate this loop*/
            break;
        }
    }
    return (EC_TRUE);
}

EC_BOOL cproc_isend_on_item(CPROC *cproc, CPROC_ITEM *cproc_item)
{
    CLIST *sending_queue;
    TASK_NODE *task_node;

    sending_queue = CPROC_ITEM_SENDING_QUEUE(cproc_item);
    while(NULL_PTR != (task_node = (TASK_NODE *)clist_first_data(sending_queue)))
    {
        //task_node_dbg(LOGSTDOUT, "cproc isend node:", task_node);
        cproc_send(cproc, cproc_item, TASK_NODE_BUFF(task_node), TASK_NODE_BUFF_LEN(task_node), &(TASK_NODE_BUFF_POS(task_node)));
        if(TASK_NODE_BUFF_POS(task_node) == TASK_NODE_BUFF_LEN(task_node))
        {
            clist_pop_front(sending_queue);
            TASK_NODE_COMP(task_node) = TASK_WAS_SENT;
        }
        else
        {
            break;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cproc_irecv_on_item(CPROC *cproc, CPROC_ITEM *cproc_item, CLIST *save_to_list)
{
    return cproc_irecv_node(cproc, cproc_item, save_to_list);
}

EC_BOOL cproc_sending_handle(CPROC *cproc)
{
    UINT32 send_rank;
    UINT32 recv_rank;

    send_rank = TASK_BRD_RANK(task_brd_default_get());
    for(recv_rank = 0; recv_rank < CPROC_SIZE(cproc); recv_rank ++)
    {
        CPROC_ITEM *cproc_item;

        cproc_item = CPROC_ITEM(cproc, send_rank, recv_rank);
#if 0
        dbg_log(SEC_0085_CPROC, 9)(LOGSTDNULL, "[DEBUG] cproc_sending_handle: check cproc_item %lx: send_rank %ld, recv_rank %ld, while row %ld, col %ld\n",
                            cproc_item, send_rank, recv_rank, CPROC_ITEM_ROW_RANK(cproc_item), CPROC_ITEM_COL_RANK(cproc_item));
#endif
        cproc_isend_on_item(cproc, cproc_item);
    }
    return (EC_TRUE);
}

EC_BOOL cproc_recving_handle(CPROC *cproc, CLIST *save_to_list)
{
    UINT32 send_rank;
    UINT32 recv_rank;

    //dbg_log(SEC_0085_CPROC, 5)(LOGSTDOUT, "cproc_recving_handle: pid %d cproc %lx\n", getpid(), cproc);

    recv_rank = TASK_BRD_RANK(task_brd_default_get());
    for(send_rank = 0; send_rank < CPROC_SIZE(cproc); send_rank ++)
    {
        CPROC_ITEM *cproc_item;
        cproc_item = CPROC_ITEM(cproc, send_rank, recv_rank);
        cproc_irecv_on_item(cproc, cproc_item, save_to_list);
    }
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


