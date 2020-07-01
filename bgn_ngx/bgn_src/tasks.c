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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "type.h"

#include "log.h"

#include "clist.h"
#include "cstring.h"
#include "cset.h"
#include "cmisc.h"
#include "taskcfg.h"
#include "csocket.h"
#include "ccallback.h"

#include "cmpic.inc"
#include "cmpie.h"
#include "crbuff.h"
#include "tasks.h"
#include "task.h"
#include "crouter.h"
#include "cbase64code.h"
#include "cepoll.h"
#include "ccallback.h"

#include "findex.inc"

#if 0
#define TASKS_ASSERT(condition)   ASSERT(condition)
#else
#define TASKS_ASSERT(condition)   do{}while(0)
#endif

#if 0
#define PRINT_BUFF(info, buff, len) do{\
    UINT32 __pos;\
    dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "%s[Length = %ld]: ", info, len);\
    for(__pos = 0; __pos < (len); __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%x,", ((UINT8 *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, len) do{}while(0)
#endif

/**
*
*   start one server
*
**/
EC_BOOL tasks_srv_start(TASKS_CFG *tasks_cfg)
{
    if(EC_FALSE == csocket_srv_start(TASKS_CFG_SRVIPADDR(tasks_cfg),TASKS_CFG_SRVPORT(tasks_cfg),
                                    CSOCKET_IS_NONBLOCK_MODE,
                                    &(TASKS_CFG_SRVSOCKFD(tasks_cfg))))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDERR, "error:tasks_srv_start: "
                                              "failed to start server %s:%ld\n",
                                              TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                                              TASKS_CFG_SRVPORT(tasks_cfg));
        return (EC_FALSE);
    }

    cepoll_set_event(task_brd_default_get_cepoll(),
                      TASKS_CFG_SRVSOCKFD(tasks_cfg),
                      CEPOLL_RD_EVENT,
                      (const char *)"tasks_srv_accept",
                      (CEPOLL_EVENT_HANDLER)tasks_srv_accept,
                      (void *)tasks_cfg);

    dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "[DEBUG] tasks_srv_start: "
                                          "start server %s:%ld:%d\n",
                                          TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                                          TASKS_CFG_SRVPORT(tasks_cfg),
                                          TASKS_CFG_SRVSOCKFD(tasks_cfg));

    return (EC_TRUE);
}

/**
*
* close server listen port
*
**/
EC_BOOL tasks_srv_close(TASKS_CFG *tasks_cfg)
{
    if(CMPI_ERROR_SOCKFD != TASKS_CFG_SRVSOCKFD(tasks_cfg))
    {
        cepoll_del_all(task_brd_default_get_cepoll(), TASKS_CFG_SRVSOCKFD(tasks_cfg));
        cepoll_clear_node(task_brd_default_get_cepoll(), TASKS_CFG_SRVSOCKFD(tasks_cfg));

        if(EC_FALSE == csocket_srv_end(TASKS_CFG_SRVSOCKFD(tasks_cfg)))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDERR, "error:tasks_srv_close: "
                                                  "close server on %s:%ld:%d failed\n",
                                                  TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                                                  TASKS_CFG_SRVPORT(tasks_cfg),
                                                  TASKS_CFG_SRVSOCKFD(tasks_cfg));
            return (EC_FALSE);
        }

        dbg_log(SEC_0121_TASKS, 5)(LOGSTDERR, "[DEBUG] tasks_srv_close: "
                                              "close server on %s:%ld:%d done\n",
                                              TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                                              TASKS_CFG_SRVPORT(tasks_cfg),
                                              TASKS_CFG_SRVSOCKFD(tasks_cfg));


        TASKS_CFG_SRVSOCKFD(tasks_cfg) = CMPI_ERROR_SOCKFD;
    }

    return (EC_TRUE);
}

/**
*
*   stop one server
*   1. stop all connection to this server
*   2. stop server itself
*
**/
EC_BOOL tasks_srv_end(TASKS_CFG *tasks_cfg)
{
    if(CMPI_ERROR_SOCKFD != TASKS_CFG_SRVSOCKFD(tasks_cfg)
    && EC_FALSE == tasks_srv_close(tasks_cfg))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDERR, "error:tasks_srv_end: "
                                              "close server on %s:%ld:%d failed\n",
                                              TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                                              TASKS_CFG_SRVPORT(tasks_cfg),
                                              TASKS_CFG_SRVSOCKFD(tasks_cfg));
        return (EC_FALSE);
    }

    tasks_worker_clean(TASKS_CFG_WORKER(tasks_cfg));
    tasks_monitor_clean(TASKS_CFG_MONITOR(tasks_cfg));
    return (EC_TRUE);
}

/**
*
*   server accept a new connection
*   1. accept a new connection if has
*   2. create a client node with remote client ip info (note: server unknow remote client port info at present)
*   3. add the client node to client set of server
*
**/
EC_BOOL tasks_srv_accept_once(TASKS_CFG *tasks_cfg, EC_BOOL *continue_flag)
{
    UINT32          client_ipaddr;
    UINT32          client_port;

    EC_BOOL         ret;
    int             client_conn_sockfd;

    ret = csocket_accept(TASKS_CFG_SRVSOCKFD(tasks_cfg), &(client_conn_sockfd), CSOCKET_IS_NONBLOCK_MODE, &(client_ipaddr), &(client_port));
    if(EC_TRUE == ret)
    {
        CSOCKET_CNODE *csocket_cnode;

        dbg_log(SEC_0121_TASKS, 2)(LOGSTDOUT, "[DEBUG] tasks_srv_accept_once: "
                                              "handle new sockfd %d\n",
                                              client_conn_sockfd);

        csocket_cnode = csocket_cnode_new(LOC_TASKS_0001);/*here do not know the remote client srv port*/
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_srv_accept_once:"
                                                  "new csocket cnode failed for sockfd %d, "
                                                  "hence close it\n",
                                                  client_conn_sockfd);
            csocket_close(client_conn_sockfd);
            //return (EC_FALSE);
            return (EC_TRUE); /*ignore error*/
        }

        CSOCKET_CNODE_SOCKFD(csocket_cnode) = client_conn_sockfd;
        CSOCKET_CNODE_TYPE(csocket_cnode )  = CSOCKET_TYPE_TCP;
        CSOCKET_CNODE_IPADDR(csocket_cnode) = client_ipaddr;

        /*server does not know which taskComm this client belongs to*/
        if(EC_FALSE == tasks_monitor_add_csocket_cnode(TASKS_CFG_MONITOR(tasks_cfg), csocket_cnode))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_srv_accept_once: "
                                                  "server %s:%ld:%d accept "
                                                  "new client %s:%d failed\n",
                                                  TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                                                  TASKS_CFG_SRVPORT(tasks_cfg),
                                                  TASKS_CFG_SRVSOCKFD(tasks_cfg),
                                                  c_word_to_ipv4(client_ipaddr),
                                                  client_conn_sockfd);

            csocket_cnode_free(csocket_cnode);
            (*continue_flag) = ret;
            return (EC_TRUE);
        }

        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_srv_accept_once: "
                                              "server %s:%ld:%d accept new client %s:%d\n",
                                              TASKS_CFG_SRVIPADDR_STR(tasks_cfg),
                                              TASKS_CFG_SRVPORT(tasks_cfg),
                                              TASKS_CFG_SRVSOCKFD(tasks_cfg),
                                              c_word_to_ipv4(client_ipaddr),
                                              client_conn_sockfd);
    }

    (*continue_flag) = ret;

    return (EC_TRUE);
}

EC_BOOL tasks_srv_accept(TASKS_CFG *tasks_cfg)
{
    UINT32   idx;
    UINT32   num;
    EC_BOOL  continue_flag;

    num = SRV_ACCEPT_MAX_NUM;
    for(idx = 0; idx < num; idx ++)
    {
        if(EC_FALSE == tasks_srv_accept_once(tasks_cfg, &continue_flag))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_srv_accept: "
                                                  "accept No. %ld client failed "
                                                  "where expect %ld clients\n",
                                                  idx, num);
            return (EC_FALSE);
        }

        if(EC_FALSE == continue_flag)
        {
            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_srv_accept: "
                                                  "accept No. %ld client terminate "
                                                  "where expect %ld clients\n",
                                                  idx, num);
            break;
        }
    }

    return (EC_TRUE);
}

TASKS_NODE *tasks_node_new(const UINT32 srvipaddr, const UINT32 srvport, const UINT32 tcid, const UINT32 comm, const UINT32 size)
{
    TASKS_NODE *tasks_node;

    alloc_static_mem(MM_TASKS_NODE, &tasks_node, LOC_TASKS_0002);
    if(NULL_PTR == tasks_node)
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_node_new: "
                                              "failed to alloc tasks node\n");
        return (NULL_PTR);
    }

    tasks_node_init(tasks_node, srvipaddr, srvport, tcid, comm, size);
    return (tasks_node);
}

EC_BOOL tasks_node_init(TASKS_NODE *tasks_node, const UINT32 srvipaddr, const UINT32 srvport, const UINT32 tcid, const UINT32 comm, const UINT32 size)
{
    TASKS_NODE_SRVIPADDR(tasks_node) = srvipaddr;
    TASKS_NODE_SRVPORT(tasks_node)   = srvport;
    TASKS_NODE_TCID(tasks_node)      = tcid;
    TASKS_NODE_COMM(tasks_node)      = comm;
    TASKS_NODE_SIZE(tasks_node)      = size;
    TASKS_NODE_LOAD(tasks_node)      = 0;

    TASKS_NODE_USED(tasks_node)      = BIT_TRUE;

    CTIMET_GET(TASKS_NODE_LAST_UPDATE_TIME(tasks_node));
    CTIMET_GET(TASKS_NODE_LAST_SEND_TIME(tasks_node));

    cvector_init(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), 0, MM_CSOCKET_CNODE, CVECTOR_LOCK_ENABLE, LOC_TASKS_0003);

    clist_init(TASKS_NODE_SENDING_LIST(tasks_node), MM_TASK_NODE, LOC_TASKS_0004);

    ccallback_node_init(TASKS_NODE_ON_RECV_CB(tasks_node));
    ccallback_node_init(TASKS_NODE_ON_SEND_CB(tasks_node));
    ccallback_node_init(TASKS_NODE_ON_TIMEOUT_CB(tasks_node));
    ccallback_node_init(TASKS_NODE_ON_TERMINATE_CB(tasks_node));
    ccallback_node_init(TASKS_NODE_ON_CLEANUP_CB(tasks_node));

    return (EC_TRUE);
}

EC_BOOL tasks_node_clean(TASKS_NODE *tasks_node)
{
    cvector_clean(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (CVECTOR_DATA_CLEANER)csocket_cnode_close_and_clean_event, LOC_TASKS_0005);

    clist_clean(TASKS_NODE_SENDING_LIST(tasks_node), NULL_PTR); /*it is temporary list. never free its data part*/

    TASKS_NODE_SRVIPADDR(tasks_node) = CMPI_ERROR_IPADDR;
    TASKS_NODE_SRVPORT(tasks_node)   = CMPI_ERROR_SRVPORT;;
    TASKS_NODE_TCID(tasks_node)      = CMPI_ERROR_TCID;
    TASKS_NODE_COMM(tasks_node)      = CMPI_ERROR_COMM;
    TASKS_NODE_SIZE(tasks_node)      = 0;
    TASKS_NODE_LOAD(tasks_node)      = 0;

    TASKS_NODE_USED(tasks_node)      = BIT_FALSE;

    //CTIMET_GET(TASKS_NODE_LAST_UPDATE_TIME(tasks_node));
    //CTIMET_GET(TASKS_NODE_LAST_SEND_TIME(tasks_node));

    ccallback_node_clean(TASKS_NODE_ON_RECV_CB(tasks_node));
    ccallback_node_clean(TASKS_NODE_ON_SEND_CB(tasks_node));
    ccallback_node_clean(TASKS_NODE_ON_TIMEOUT_CB(tasks_node));
    ccallback_node_clean(TASKS_NODE_ON_TERMINATE_CB(tasks_node));
    ccallback_node_clean(TASKS_NODE_ON_CLEANUP_CB(tasks_node));
    return (EC_TRUE);
}

EC_BOOL tasks_node_free(TASKS_NODE *tasks_node)
{
    if(NULL_PTR != tasks_node)
    {
        if(BIT_TRUE == TASKS_NODE_USED(tasks_node))
        {
            tasks_node_clean(tasks_node);
            free_static_mem(MM_TASKS_NODE, tasks_node, LOC_TASKS_0006);
        }
    }
    return (EC_TRUE);
}

TASKS_NODE *tasks_node_new_0()
{
    return tasks_node_new(CMPI_ERROR_IPADDR, CMPI_ERROR_SRVPORT, CMPI_ERROR_TCID, CMPI_ERROR_COMM, 0);
}

EC_BOOL tasks_node_init_0(TASKS_NODE *tasks_node)
{
    return tasks_node_init(tasks_node, CMPI_ERROR_IPADDR, CMPI_ERROR_SRVPORT, CMPI_ERROR_TCID, CMPI_ERROR_COMM, 0);
}

EC_BOOL tasks_node_clone_0(const TASKS_NODE *tasks_node_src, TASKS_NODE *tasks_node_des)
{
    TASKS_NODE_SRVIPADDR(tasks_node_des) = TASKS_NODE_SRVIPADDR(tasks_node_src);
    TASKS_NODE_SRVPORT(tasks_node_des)   = TASKS_NODE_SRVPORT(tasks_node_src);
    TASKS_NODE_TCID(tasks_node_des)      = TASKS_NODE_TCID(tasks_node_src);
    TASKS_NODE_COMM(tasks_node_des)      = TASKS_NODE_COMM(tasks_node_src);
    TASKS_NODE_SIZE(tasks_node_des)      = TASKS_NODE_SIZE(tasks_node_src);

    TASKS_NODE_USED(tasks_node_des)      = TASKS_NODE_USED(tasks_node_src);

    /*left was ignored ...*/
    return (EC_TRUE);
}

EC_BOOL tasks_node_is_connected(const TASKS_NODE *tasks_node)
{
    UINT32 pos;

    CVECTOR_LOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0008);
    for(pos = 0; pos < cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)); pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get_no_lock(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), pos);
        if(NULL_PTR == csocket_cnode)
        {
            continue;
        }

        /*regard tasks_node is connected if exist any one connected csocket_cnode*/
        if(EC_TRUE == csocket_cnode_is_connected(csocket_cnode))
        {
            CVECTOR_UNLOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0009);
            return (EC_TRUE);
        }
    }
    CVECTOR_UNLOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0010);
    return (EC_FALSE);
}

EC_BOOL tasks_node_is_connected_no_lock(const TASKS_NODE *tasks_node)
{
    UINT32 pos;

    for(pos = 0; pos < cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)); pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get_no_lock(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), pos);
        if(NULL_PTR == csocket_cnode)
        {
            continue;
        }

        /*regard tasks_node is connected if exist any one connected csocket_cnode*/
        if(EC_TRUE == csocket_cnode_is_connected(csocket_cnode))
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL tasks_node_is_empty(const TASKS_NODE *tasks_node)
{
    UINT32 pos;

    CVECTOR_LOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0011);
    for(pos = 0; pos < cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)); pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get_no_lock(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), pos);
        if(NULL_PTR != csocket_cnode)
        {
            CVECTOR_UNLOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0012);
            return (EC_FALSE);
        }
    }
    CVECTOR_UNLOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0013);
    return (EC_TRUE);
}

EC_BOOL tasks_node_cmp(const TASKS_NODE *src_tasks_node, const TASKS_NODE *des_tasks_node)
{
    if(TASKS_NODE_SRVIPADDR(src_tasks_node) != TASKS_NODE_SRVIPADDR(des_tasks_node))
    {
        return (EC_FALSE);
    }

    if(TASKS_NODE_SRVPORT(src_tasks_node) != TASKS_NODE_SRVPORT(des_tasks_node))
    {
        return (EC_FALSE);
    }

    if(TASKS_NODE_TCID(src_tasks_node) != TASKS_NODE_TCID(des_tasks_node))
    {
        return (EC_FALSE);
    }

    if(TASKS_NODE_COMM(src_tasks_node) != TASKS_NODE_COMM(des_tasks_node))
    {
        return (EC_FALSE);
    }

    if(TASKS_NODE_SIZE(src_tasks_node) != TASKS_NODE_SIZE(des_tasks_node))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL tasks_node_check(const TASKS_NODE *tasks_node, const CSOCKET_CNODE *csocket_cnode)
{
    if(TASKS_NODE_TCID(tasks_node) != CSOCKET_CNODE_TCID(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "warn:tasks_node_check: "
                                              "tcid mismatched: %s <---> %s\n",
                                              TASKS_NODE_TCID_STR(tasks_node),
                                              CSOCKET_CNODE_TCID_STR(csocket_cnode));
        return (EC_FALSE);
    }

    if(TASKS_NODE_COMM(tasks_node) != CSOCKET_CNODE_COMM(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "warn:tasks_node_check: "
                                              "comm mismatched: %ld <---> %ld\n",
                                              TASKS_NODE_COMM(tasks_node),
                                              CSOCKET_CNODE_COMM(csocket_cnode));
        return (EC_FALSE);
    }

    if(TASKS_NODE_SIZE(tasks_node) != CSOCKET_CNODE_SIZE(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "warn:tasks_node_check: "
                                              "size mismatched: %ld <---> %ld\n",
                                              TASKS_NODE_SIZE(tasks_node),
                                              CSOCKET_CNODE_SIZE(csocket_cnode));
        return (EC_FALSE);
    }

    /*warning: tasks_node ip 10.63.101.59, csocket_cnode ip 127.0.0.1, but all local ip*/
    if(EC_FALSE == c_ipv4_is_local(TASKS_NODE_SRVIPADDR(tasks_node))
    || EC_FALSE == c_ipv4_is_local(CSOCKET_CNODE_IPADDR(csocket_cnode)))
    {
        if(TASKS_NODE_SRVIPADDR(tasks_node) != CSOCKET_CNODE_IPADDR(csocket_cnode))
        {
            dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "warn:tasks_node_check: "
                                                  "ipaddr mismatched: %s <---> %s\n",
                                                  TASKS_NODE_SRVIPADDR_STR(tasks_node),
                                                  CSOCKET_CNODE_IPADDR_STR(csocket_cnode));
            return (EC_FALSE);
        }
    }

    if(TASKS_NODE_SRVPORT(tasks_node) != CSOCKET_CNODE_SRVPORT(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "warn:tasks_node_check: "
                                              "port mismatched: %ld <---> %ld\n",
                                              TASKS_NODE_SRVPORT(tasks_node),
                                              CSOCKET_CNODE_SRVPORT(csocket_cnode));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*tasks_node of worker*/
EC_BOOL tasks_node_irecv(CSOCKET_CNODE *csocket_cnode)
{
    TASK_BRD        *task_brd;
    CLIST           *save_to_list;

    TASKS_NODE      *tasks_node;

    task_brd     = task_brd_default_get();

    TASKS_ASSERT(CSOCKET_CNODE_XCHG_TASKC_NODE == CSOCKET_CNODE_STATUS(csocket_cnode));

    tasks_node = CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode);

    TASKS_ASSERT(TASKS_NODE_TCID(tasks_node) == CSOCKET_CNODE_TCID(csocket_cnode));
    TASKS_ASSERT(TASKS_NODE_COMM(tasks_node) == CSOCKET_CNODE_COMM(csocket_cnode));

    /*tasks_node is worker*/
    save_to_list = TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE);

    for(;;)
    {
        TASK_NODE  *task_node;

        /*handle incoming task_node*/
        task_node = CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode);
        if(NULL_PTR != task_node)
        {
            /*if fix cannot complete the task_node, CRBUFF has no data to handle => terminate*/
            if(EC_FALSE == csocket_cnode_fix_task_node(csocket_cnode, task_node))
            {
                dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                                      "sockfd %d fix task node %p not completed\n",
                                                      CSOCKET_CNODE_SOCKFD(csocket_cnode), task_node);
                /*terminate*/
                break;
            }

            /*update last access time*/
            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: update last access time\n");
            tasks_node_update_time(tasks_node);

            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                                  "sockfd %d fix task node %p done "
                                                  "[len %ld (0x%lx), save_to_list %p]\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode), task_node,
                                                  TASK_NODE_BUFF_LEN(task_node), TASK_NODE_BUFF_LEN(task_node),
                                                  save_to_list);

            /*otherwise, remove it from INCOMING list and push it to INCOMED list*/
            CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = NULL_PTR;
            clist_push_back(save_to_list, (void *)task_node);
            TASK_NODE_COMP(task_node) = TASK_WAS_RECV;
        }

        /*handle next task_node*/
        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                              "before fetch, pkt pos = %ld\n",
                                              CSOCKET_CNODE_PKT_POS(csocket_cnode));
        task_node = csocket_fetch_task_node(csocket_cnode);
        if(NULL_PTR == task_node)
        {
            //dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: fetch nothing\n");
            break;
        }

        /*update last access time*/
        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                              "update last access time\n");
        tasks_node_update_time(tasks_node);

        if(TASK_NODE_BUFF_POS(task_node) == TASK_NODE_BUFF_LEN(task_node))
        {
            /*push complete task_node to INCOMED list*/
            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                                  "sockfd %d push task_node %p to incomed list\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode), task_node);
            clist_push_back(save_to_list, (void *)task_node);
            TASK_NODE_COMP(task_node) = TASK_WAS_RECV;
        }
        else
        {
            /*push incomplete task_node to INCOMING list*/
            CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = (void *)task_node;

            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                                  "sockfd %d push task_node %p to incoming list\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode), task_node);
            /*terminate this loop*/
            break;
        }
    }

    /*sometime, e.g., tasks_node_irecv->csocket_fetch_task_node set csocket_cnode disconnected */
    /*but tasks_node_irecv return EC_TRUE, thus need to return EC_FALSE to cepoll_handle*/
    if(EC_FALSE == csocket_is_connected(CSOCKET_CNODE_SOCKFD(csocket_cnode)))
    {
        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                              "sockfd %d RD was broken\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(EC_FALSE == CSOCKET_CNODE_IS_CONNECTED(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_irecv: "
                                              "sockfd %d RD was set to disconnected\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL tasks_node_isend(CSOCKET_CNODE *csocket_cnode)
{
    TASKS_NODE *tasks_node;
    TASK_NODE  *task_node;

    tasks_node = CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode);

    task_node = CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode);
    if(NULL_PTR == task_node)
    {
        task_node = clist_pop_front(TASKS_NODE_SENDING_LIST(tasks_node));/*FIFO*/
        CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = task_node;

        /*when mount csockt_cnode to sending, clear timer*/
        if(NULL_PTR != task_node
        && EC_TRUE == ctimeout_node_is_used(TASK_NODE_ON_SEND_TIMEOUT_CB(task_node)))
        {
            TASK_BRD    *task_brd;

            task_brd = task_brd_default_get();

            ctimeout_tree_del_timer(TASK_BRD_CTIMEOUT_TREE(task_brd),
                                    TASK_NODE_ON_SEND_TIMEOUT_CB(task_node));

            ctimeout_node_clean(TASK_NODE_ON_SEND_TIMEOUT_CB(task_node));
        }
    }

    if(NULL_PTR == task_node)
    {
        if(BIT_TRUE == CSOCKET_CNODE_WRITING(csocket_cnode))
        {
            /*clear WR event*/
            cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_isend: "
                                                  "sockfd %d del WR event done\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode));
        }
        return (EC_TRUE);
    }

    dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_isend: "
                                          "[beg] "
                                          "sockfd %d, task_node %p, pos %ld, len %ld\n",
                                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                          task_node,
                                          TASK_NODE_BUFF_POS(task_node),
                                          TASK_NODE_BUFF_LEN(task_node));

    if(TASK_NODE_BUFF_POS(task_node) != TASK_NODE_BUFF_LEN(task_node))
    {
        if(EC_FALSE == csocket_isend_task_node(csocket_cnode, task_node))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "[DEBUG] tasks_node_isend: "
                                                  "sockfd %d WR events trigger disconnected\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode));

            CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR; /*umount*/
            CSOCKET_CNODE_SET_DISCONNECTED(csocket_cnode);

            ccallback_node_run(TASK_NODE_ON_SEND_FAIL_CB(task_node));

            /*when reach here, task_node may be not accessable*/
            return (EC_FALSE);
        }

        /*update last access time*/
        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_isend: "
                                              "update last access time\n");
        tasks_node_update_time(tasks_node);
    }

    /*when data sending completed, end this sending loop*/
    if(TASK_NODE_BUFF_POS(task_node) == TASK_NODE_BUFF_LEN(task_node))
    {
        TASK_NODE_COMP(task_node) = TASK_WAS_SENT;
        CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR;

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_isend: "
                                              "[end] [succ] "
                                              "sockfd %d, task_node %p, pos %ld, len %ld\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                              task_node,
                                              TASK_NODE_BUFF_POS(task_node),
                                              TASK_NODE_BUFF_LEN(task_node));

        ccallback_node_run(TASK_NODE_ON_SEND_SUCC_CB(task_node));

        /*when reach here, task_node may be not accessable*/
        return (EC_TRUE);
    }

    if(EC_FALSE == csocket_is_connected(CSOCKET_CNODE_SOCKFD(csocket_cnode)))/*Jan 13, 2017*/
    {
        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_isend: "
                                              "sockfd %d WR had been disconnected\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));

        if(NULL_PTR != CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode))
        {
            task_node = CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode);
            CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR; /*umount*/

            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_isend: "
                                                  "[end] [disconnected] "
                                                  "sockfd %d, task_node %p, pos %ld, len %ld\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                                  task_node,
                                                  TASK_NODE_BUFF_POS(task_node),
                                                  TASK_NODE_BUFF_LEN(task_node));

            ccallback_node_run(TASK_NODE_ON_SEND_FAIL_CB(task_node));

            /*when reach here, task_node may be not accessable*/
            return (EC_FALSE);
        }

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*close one socket in the tasks*/
EC_BOOL tasks_node_iclose(CSOCKET_CNODE *csocket_cnode)
{
    TASK_BRD        *task_brd;
    TASKS_CFG       *tasks_cfg;
    TASKS_WORKER    *tasks_worker;

    TASKS_NODE      *tasks_node;

    TASKS_ASSERT(NULL_PTR != csocket_cnode);

    tasks_node = CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode);
    TASKS_ASSERT(NULL_PTR != tasks_node);

    task_brd        = task_brd_default_get();
    tasks_cfg       = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    tasks_worker    = TASKS_CFG_WORKER(tasks_cfg);

    dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "[DEBUG] tasks_node_iclose: "
                                          "close sockfd %d on tcid %s, comm %ld, vec size %ld\n",
                                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                          TASKS_NODE_TCID_STR(tasks_node),
                                          TASKS_NODE_COMM(tasks_node),
                                          cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)));

    /*remove csocket_cnode from work if existing*/
    cvector_delete(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode);
    CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode) = NULL_PTR;

    /*free recving task_node*/
    if(NULL_PTR != CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode))
    {
        /*note: recving task_node has no callback*/
        task_node_free(CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode));
        CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = NULL_PTR;
    }

    /*clear mounting*/
    if(NULL_PTR != CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode))
    {
        TASK_NODE       *task_node;

        /*reset sending task_node*/
        task_node = CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode);
        CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR;

        clist_del(TASKS_NODE_SENDING_LIST(tasks_node), (void *)task_node, NULL_PTR);
        TASKS_ASSERT(TASK_NODE_BUFF_POS(task_node) != TASK_NODE_BUFF_LEN(task_node));

        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "[DEBUG] tasks_node_iclose: "
                                              "close sockfd %d on tcid %s, "
                                              "send fail: task_node %p (tag %ld, pos %ld, len %ld)\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                              TASKS_NODE_TCID_STR(tasks_node),
                                              task_node,
                                              TASK_NODE_TAG(task_node),
                                              TASK_NODE_BUFF_POS(task_node),
                                              TASK_NODE_BUFF_LEN(task_node));

        TASKS_ASSERT(TAG_TASK_REQ == TASK_NODE_TAG(task_node)
            || TAG_TASK_RSP == TASK_NODE_TAG(task_node)
            || TAG_TASK_FWD == TASK_NODE_TAG(task_node));

        ccallback_node_run(TASK_NODE_ON_SEND_FAIL_CB(task_node));
    }

    if(0 == cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
    {
        TASK_NODE       *task_node;

        cvector_remove(TASKS_WORKER_NODES(tasks_worker), (void *)tasks_node);

        while(NULL_PTR != (task_node = clist_pop_front(TASKS_NODE_SENDING_LIST(tasks_node))))
        {
            dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_node_iclose: "
                                                  "close sockfd %d on tcid %s, "
                                                  "send cleanup: task_node %p (tag %ld, pos %ld, len %ld)\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                                  TASKS_NODE_TCID_STR(tasks_node),
                                                  task_node,
                                                  TASK_NODE_TAG(task_node),
                                                  TASK_NODE_BUFF_POS(task_node),
                                                  TASK_NODE_BUFF_LEN(task_node));

            TASKS_ASSERT(TAG_TASK_REQ == TASK_NODE_TAG(task_node)
                || TAG_TASK_RSP == TASK_NODE_TAG(task_node)
                || TAG_TASK_FWD == TASK_NODE_TAG(task_node));

            ccallback_node_run(TASK_NODE_ON_SEND_FAIL_CB(task_node));
        }

        ccallback_node_run(TASKS_WORKER_DEL_NODE_CB(tasks_worker));

        tasks_node_free(tasks_node);
    }

    dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "[DEBUG] tasks_node_iclose: "
                                          "close sockfd %d\n",
                                          CSOCKET_CNODE_SOCKFD(csocket_cnode));

    csocket_cnode_close(csocket_cnode);

    return (EC_TRUE);
}

EC_BOOL tasks_node_heartbeat(CSOCKET_CNODE *csocket_cnode)
{
    TASK_BRD     *task_brd;
    MOD_NODE      send_mod_node;
    MOD_NODE      recv_mod_node;

    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_node_heartbeat: "
                                              "sockfd %d was broken\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));

        //CSOCKET_CNODE_CLOSING(csocket_cnode) = BIT_TRUE;
        CSOCKET_CNODE_LOOPING(csocket_cnode) = BIT_FALSE;

        if(NULL_PTR != CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode))
        {
            task_node_free(CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode));
            CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = NULL_PTR;
        }

        if(NULL_PTR != CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode))
        {
            task_node_free(CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode));
            CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR;
        }
        return (EC_FALSE);
    }

    dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_node_heartbeat: "
                                          "sockfd %d, tcid %s trigger heartbeat\n",
                                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                          CSOCKET_CNODE_TCID_STR(csocket_cnode));

    cepoll_set_event(task_brd_default_get_cepoll(),
                  CSOCKET_CNODE_SOCKFD(csocket_cnode),
                  CEPOLL_RD_EVENT,
                  (const char *)"csocket_cnode_irecv",
                  (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                  (void *)csocket_cnode);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;

    cepoll_set_event(task_brd_default_get_cepoll(),
                      CSOCKET_CNODE_SOCKFD(csocket_cnode),
                      CEPOLL_WR_EVENT,
                      (const char *)"csocket_cnode_isend",
                      (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                      (void *)csocket_cnode);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;

    task_brd = task_brd_default_get();

    MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&send_mod_node) = 0;
    MOD_NODE_HOPS(&send_mod_node) = 0;
    MOD_NODE_LOAD(&send_mod_node) = 0/*TASK_BRD_LOAD(task_brd)*/;

    MOD_NODE_TCID(&recv_mod_node) = CSOCKET_CNODE_TCID(csocket_cnode);
    MOD_NODE_COMM(&recv_mod_node) = CSOCKET_CNODE_COMM(csocket_cnode);
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;
    MOD_NODE_HOPS(&recv_mod_node) = 0;
    MOD_NODE_LOAD(&recv_mod_node) = 0;

    task_p2p_no_wait(MOD_NODE_MODI(&send_mod_node),
                    TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                    &recv_mod_node,
                    NULL_PTR, FI_super_heartbeat_none, CMPI_ERROR_MODI);

    return (EC_TRUE);
}

EC_BOOL tasks_node_set_callback(TASKS_NODE *tasks_node, CSOCKET_CNODE *csocket_cnode)
{
    if(CSOCKET_CNODE_XCHG_TASKC_NODE == CSOCKET_CNODE_STATUS(csocket_cnode))
    {
        /*set worker callback, tasks_node is in local_tasks_cfg->tasks_worker*/

        CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode) = tasks_node;

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_set_callback: "
                                              "[XCHG] sockfd %d (tasks_node %p), set callback\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                              CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode));

        csocket_cnode_set_recv_callback(csocket_cnode,
                                         (const char *)"tasks_node_irecv",
                                         (void *)csocket_cnode,
                                         (void *)tasks_node_irecv);

        csocket_cnode_set_send_callback(csocket_cnode,
                                         (const char *)"tasks_node_isend",
                                         (void *)csocket_cnode,
                                         (void *)tasks_node_isend);

        csocket_cnode_set_close_callback(csocket_cnode,
                                         (const char *)"tasks_node_iclose",
                                         (void *)csocket_cnode,
                                         (void *)tasks_node_iclose);

        csocket_cnode_set_timeout_callback(csocket_cnode,
                                         (const char *)"tasks_node_heartbeat",
                                         (void *)csocket_cnode,
                                         (void *)tasks_node_heartbeat);
        CSOCKET_CNODE_LOOPING(csocket_cnode) = BIT_TRUE; /*when timeout, not close it*/

        csocket_cnode_set_shutdown_callback(csocket_cnode,
                                         (const char *)"tasks_node_iclose",
                                         (void *)csocket_cnode,
                                         (void *)tasks_node_iclose);
    }
    else
    {
        /*set monitor callback, tasks_node is in local_tasks_cfg->tasks_monitor*/

        TASKS_ASSERT(TASKS_NODE_TCID(tasks_node) == CSOCKET_CNODE_TCID(csocket_cnode));

        /*node: csocket_cnode point to tasks_node which may be changed after handshake*/
        CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode) = tasks_node;

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_set_callback: "
                                              "[not XCHG] sockfd %d (tasks_node %p)\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                              CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode));

        csocket_cnode_set_recv_callback(csocket_cnode,
                                         (const char *)"tasks_handshake_recv",
                                         (void *)csocket_cnode,
                                         (void *)tasks_handshake_recv);

        csocket_cnode_set_send_callback(csocket_cnode,
                                         (const char *)"tasks_handshake_send",
                                         (void *)csocket_cnode,
                                         (void *)tasks_handshake_send);

        csocket_cnode_set_close_callback(csocket_cnode,
                                         (const char *)"tasks_handshake_shutdown",
                                         (void *)csocket_cnode,
                                         (void *)tasks_handshake_shutdown);

        csocket_cnode_set_timeout_callback(csocket_cnode,
                                         (const char *)"tasks_handshake_shutdown",
                                         (void *)csocket_cnode,
                                         (void *)tasks_handshake_shutdown);

        csocket_cnode_set_shutdown_callback(csocket_cnode,
                                         (const char *)"tasks_handshake_shutdown",
                                         (void *)csocket_cnode,
                                         (void *)tasks_handshake_shutdown);
    }

    return (EC_TRUE);
}

EC_BOOL tasks_node_set_epoll(TASKS_NODE *tasks_node, CSOCKET_CNODE *csocket_cnode)
{
    TASKS_ASSERT(NULL_PTR != tasks_node);

    /*worker*/
    if(CSOCKET_CNODE_XCHG_TASKC_NODE == CSOCKET_CNODE_STATUS(csocket_cnode))
    {
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          (const char *)"csocket_cnode_irecv",
                          (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;

        if(EC_FALSE == clist_is_empty(TASKS_NODE_SENDING_LIST(tasks_node)))
        {
            cepoll_set_event(task_brd_default_get_cepoll(),
                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                              CEPOLL_WR_EVENT,
                              (const char *)"csocket_cnode_isend",
                              (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                              (void *)csocket_cnode);
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        }
    }

    /*monitor*/
    else
    {
        if(0 == (CSOCKET_CNODE_RCVD_TASKC_NODE & CSOCKET_CNODE_STATUS(csocket_cnode)))
        {
            cepoll_set_event(task_brd_default_get_cepoll(),
                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                              CEPOLL_RD_EVENT,
                              (const char *)"csocket_cnode_irecv",
                              (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                              (void *)csocket_cnode);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
        }

        if(0 == (CSOCKET_CNODE_SENT_TASKC_NODE & CSOCKET_CNODE_STATUS(csocket_cnode))
        || EC_FALSE == clist_is_empty(TASKS_NODE_SENDING_LIST(tasks_node)))
        {
            cepoll_set_event(task_brd_default_get_cepoll(),
                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                              CEPOLL_WR_EVENT,
                              (const char *)"csocket_cnode_isend",
                              (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                              (void *)csocket_cnode);
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        }
    }

    cepoll_set_shutdown(task_brd_default_get_cepoll(),
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       (const char *)"csocket_cnode_iclose",
                       (CEPOLL_EVENT_HANDLER)csocket_cnode_ishutdown,
                       (void *)csocket_cnode);

    cepoll_set_timeout(task_brd_default_get_cepoll(),
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       (uint32_t)CONN_TIMEOUT_NSEC,
                       (const char *)"csocket_cnode_itimeout",
                       (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                       (void *)csocket_cnode);

    return (EC_TRUE);
}

EC_BOOL tasks_node_is_tcid(const TASKS_NODE *src_tasks_node, const UINT32 tcid)
{
    if(tcid == TASKS_NODE_TCID(src_tasks_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL tasks_node_is_ipaddr(const TASKS_NODE *src_tasks_node, const UINT32 ipaddr)
{
    if(ipaddr == TASKS_NODE_SRVIPADDR(src_tasks_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void tasks_node_print(LOG *log, const TASKS_NODE *tasks_node)
{
    CVECTOR     *csocket_cnode_vec;
    UINT32       pos;

    csocket_cnode_vec = (CVECTOR *)TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node);
    CVECTOR_LOCK(csocket_cnode_vec, LOC_TASKS_0014);
    for(pos = 0; pos < cvector_size(csocket_cnode_vec); pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get_no_lock(csocket_cnode_vec, pos);
        if(NULL_PTR == csocket_cnode)
        {
            sys_log(log, "csocket_cnode_vec %lx No. %ld: (null)\n", csocket_cnode_vec, pos);
            continue;
        }

        sys_log(log, "csocket_cnode_vec %lx No. %ld: "
                     "srvipaddr %s, srvport %ld, tcid %s, comm %ld, size %ld, sockfd %d\n",
                     csocket_cnode_vec, pos,
                     TASKS_NODE_SRVIPADDR_STR(tasks_node),
                     TASKS_NODE_SRVPORT(tasks_node),
                     TASKS_NODE_TCID_STR(tasks_node),
                     TASKS_NODE_COMM(tasks_node),
                     TASKS_NODE_SIZE(tasks_node),
                     CSOCKET_CNODE_SOCKFD(csocket_cnode)
                );
    }
    CVECTOR_UNLOCK(csocket_cnode_vec, LOC_TASKS_0015);
    return ;
}

void tasks_node_print_csocket_cnode_list(LOG *log, const TASKS_NODE *tasks_node, UINT32 *index)
{
    CVECTOR     *csocket_cnode_vec;
    UINT32       pos;

    csocket_cnode_vec = (CVECTOR *)TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node);
    CVECTOR_LOCK(csocket_cnode_vec, LOC_TASKS_0016);
    for(pos = 0; pos < cvector_size(csocket_cnode_vec); pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get_no_lock(csocket_cnode_vec, pos);
        if(NULL_PTR == csocket_cnode)
        {
            sys_log(log, "No. %ld: (csocket cnode is null)\n", (*index) ++);
            continue;
        }

        sys_log(log, "No. %ld: srvipaddr %s, srvport %ld, tcid %s, comm %ld, size %ld, sockfd %d\n",
                    (*index) ++,
                    TASKS_NODE_SRVIPADDR_STR(tasks_node),
                    TASKS_NODE_SRVPORT(tasks_node),
                    TASKS_NODE_TCID_STR(tasks_node),
                    TASKS_NODE_COMM(tasks_node),
                    TASKS_NODE_SIZE(tasks_node),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode)
                );
    }
    CVECTOR_UNLOCK(csocket_cnode_vec, LOC_TASKS_0017);
    return ;
}

void tasks_node_print_in_plain(LOG *log, const TASKS_NODE *tasks_node)
{
    UINT32      pos;
    UINT32      csocket_cnode_num;

    CVECTOR_LOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0018);
    csocket_cnode_num = cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node));
    sys_print(log, "srvipaddr %s, srvport %ld, tcid %s, comm %ld, size %ld, sockfd ",
                    TASKS_NODE_SRVIPADDR_STR(tasks_node),
                    TASKS_NODE_SRVPORT(tasks_node),
                    TASKS_NODE_TCID_STR(tasks_node),
                    TASKS_NODE_COMM(tasks_node),
                    TASKS_NODE_SIZE(tasks_node)
            );
    for(pos = 0; pos < csocket_cnode_num; pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get_no_lock(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), pos);
        if(NULL_PTR == csocket_cnode)
        {
            continue;
        }

        if(pos + 1 >= csocket_cnode_num)
        {
            sys_print(log, "%d\n",CSOCKET_CNODE_SOCKFD(csocket_cnode));
        }
        else
        {
            sys_print(log, "%d:",CSOCKET_CNODE_SOCKFD(csocket_cnode));
        }
    }
    CVECTOR_UNLOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0019);
    return ;
}

void tasks_node_sprint(CSTRING *cstring, const TASKS_NODE *tasks_node)
{
    UINT32      pos;
    UINT32      csocket_cnode_num;

    CVECTOR_LOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0020);
    csocket_cnode_num = cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node));
    cstring_format(cstring, "srvipaddr %s, srvport %ld, tcid %s, comm %ld, size %ld, sockfd ",
                TASKS_NODE_SRVIPADDR_STR(tasks_node),
                TASKS_NODE_SRVPORT(tasks_node),
                TASKS_NODE_TCID_STR(tasks_node),
                TASKS_NODE_COMM(tasks_node),
                TASKS_NODE_SIZE(tasks_node)
            );
    for(pos = 0; pos < csocket_cnode_num; pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get_no_lock(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), pos);
        if(NULL_PTR == csocket_cnode)
        {
            continue;
        }

        if(pos + 1 >= csocket_cnode_num)
        {
            cstring_format(cstring, "%d\n",CSOCKET_CNODE_SOCKFD(csocket_cnode));
        }
        else
        {
            cstring_format(cstring, "%d:",CSOCKET_CNODE_SOCKFD(csocket_cnode));
        }
    }
    CVECTOR_UNLOCK(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), LOC_TASKS_0021);
    return ;
}

EC_BOOL tasks_node_update_time(TASKS_NODE *tasks_node)
{
    CTIMET_GET(TASKS_NODE_LAST_UPDATE_TIME(tasks_node));/*update*/

    if(do_log(SEC_0121_TASKS, 9))
    {
        CTM             *last_update_tm;
        CTM             *last_end_tm;

        last_update_tm = CTIMET_TO_TM(TASKS_NODE_LAST_UPDATE_TIME(tasks_node));
        last_end_tm    = CTIMET_TO_TM(TASKS_NODE_LAST_SEND_TIME(tasks_node));

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_node_update_time: "
                                              "[tcid %s comm %ld] "
                                              "last update time: %02d:%02d:%02d, "
                                              "last send time: %02d:%02d:%02d\n",
                                              TASKS_NODE_TCID_STR(tasks_node),
                                              TASKS_NODE_COMM(tasks_node),
                                              CTM_HOUR(last_update_tm),
                                              CTM_MIN(last_update_tm),
                                              CTM_SEC(last_update_tm),

                                              CTM_HOUR(last_end_tm),
                                              CTM_MIN(last_end_tm ),
                                              CTM_SEC(last_end_tm )
            );
    }
    return (EC_TRUE);
}

EC_BOOL tasks_worker_node_trigger(TASKS_NODE *tasks_node)
{
    TASK_BRD        *task_brd;
    MOD_NODE         send_mod_node;

    UINT32           heartbeat_interval;
    UINT32           elapsed_time_from_last_update;
    UINT32           elapsed_time_from_last_send;
    CTIMET           cur;

    task_brd = task_brd_default_get();

    MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&send_mod_node) = 0;
    MOD_NODE_HOPS(&send_mod_node) = 0;
    MOD_NODE_LOAD(&send_mod_node) = 0/*TASK_BRD_LOAD(task_brd)*/;

    heartbeat_interval = (UINT32)CSOCKET_HEARTBEAT_INTVL_NSEC;

    CTIMET_GET(cur);

    elapsed_time_from_last_update = lrint(CTIMET_DIFF(TASKS_NODE_LAST_UPDATE_TIME(tasks_node), cur));
    elapsed_time_from_last_send   = lrint(CTIMET_DIFF(TASKS_NODE_LAST_SEND_TIME(tasks_node), cur));

    if(3 * heartbeat_interval <= elapsed_time_from_last_update)
    {
        MOD_NODE recv_mod_node;
        CTM   *last_update_tm;
        CTM   *last_end_tm;
        CTM   *cur_tm;

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_p2p_no_wait(MOD_NODE_MODI(&send_mod_node),
                        TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                        &recv_mod_node,
                        NULL_PTR, FI_super_notify_broken_tcid_comm, CMPI_ERROR_MODI,
                        TASKS_NODE_TCID(tasks_node), TASKS_NODE_COMM(tasks_node));

        last_update_tm = CTIMET_TO_TM(TASKS_NODE_LAST_UPDATE_TIME(tasks_node));
        last_end_tm    = CTIMET_TO_TM(TASKS_NODE_LAST_SEND_TIME(tasks_node));
        cur_tm         = CTIMET_TO_TM(cur);

        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_worker_node_trigger: "
                "[tcid %s comm %ld] last update time: %02d:%02d:%02d, "
                "last send time: %02d:%02d:%02d, "
                "cur time: %02d:%02d:%02d, "
                "CSOCKET_HEARTBEAT_INTVL_NSEC = (%ld), "
                "elapsed from last update: %ld, "
                "elapsed from last send: %ld, "
                "trigger broken\n",
                TASKS_NODE_TCID_STR(tasks_node),
                TASKS_NODE_COMM(tasks_node),
                CTM_HOUR(last_update_tm),
                CTM_MIN(last_update_tm ),
                CTM_SEC(last_update_tm ),

                CTM_HOUR(last_end_tm  ),
                CTM_MIN(last_end_tm   ),
                CTM_SEC(last_end_tm   ),

                CTM_HOUR(cur_tm),
                CTM_MIN(cur_tm ),
                CTM_SEC(cur_tm ),

                heartbeat_interval, elapsed_time_from_last_update, elapsed_time_from_last_send
            );

        return (EC_FALSE);
    }

    if(/*heartbeat_interval <= elapsed_time_from_last_update && */heartbeat_interval <= elapsed_time_from_last_send && (SWITCH_ON == RANK_HEARTBEAT_NODE_SWITCH))
    {
        MOD_NODE recv_mod_node;
        CLOAD_NODE *cload_node;

        CTM   *last_update_tm;
        CTM   *last_end_tm;
        CTM   *cur_tm;

        MOD_NODE_TCID(&recv_mod_node) = TASKS_NODE_TCID(tasks_node);
        MOD_NODE_COMM(&recv_mod_node) = TASKS_NODE_COMM(tasks_node);
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        cload_node = cload_mgr_search(TASK_BRD_CLOAD_MGR(task_brd), TASK_BRD_TCID(task_brd), TASK_BRD_COMM(task_brd));
        if(NULL_PTR == cload_node)
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_node_trigger: "
                                                  "cload node of tcid %s not exist\n",
                                                  TASK_BRD_TCID_STR(task_brd));
            return (EC_FALSE);
        }

        task_p2p_no_wait(MOD_NODE_MODI(&send_mod_node),
                        TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                        &recv_mod_node,
                        NULL_PTR, FI_super_heartbeat_on_node, CMPI_ERROR_MODI, cload_node);

        last_update_tm = CTIMET_TO_TM(TASKS_NODE_LAST_UPDATE_TIME(tasks_node));
        last_end_tm    = CTIMET_TO_TM(TASKS_NODE_LAST_SEND_TIME(tasks_node));
        cur_tm         = CTIMET_TO_TM(cur);

        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_worker_node_trigger: "
                "[tcid %s comm %ld] last update time: %02d:%02d:%02d, "
                "last send time: %02d:%02d:%02d, "
                "cur time: %02d:%02d:%02d, "
                "CSOCKET_HEARTBEAT_INTVL_NSEC = (%ld), "
                "elapsed from last update: %ld, "
                "elapsed from last send: %ld, "
                "trigger heartbeat\n",
                TASKS_NODE_TCID_STR(tasks_node),
                TASKS_NODE_COMM(tasks_node),
                CTM_HOUR(last_update_tm),
                CTM_MIN(last_update_tm ),
                CTM_SEC(last_update_tm ),

                CTM_HOUR(last_end_tm  ),
                CTM_MIN(last_end_tm   ),
                CTM_SEC(last_end_tm   ),

                CTM_HOUR(cur_tm),
                CTM_MIN(cur_tm ),
                CTM_SEC(cur_tm ),

                heartbeat_interval, elapsed_time_from_last_update, elapsed_time_from_last_send
            );

        CTIMET_GET(TASKS_NODE_LAST_SEND_TIME(tasks_node));
        return (EC_TRUE);
    }

    if(/*heartbeat_interval <= elapsed_time_from_last_update && */heartbeat_interval <= elapsed_time_from_last_send && (SWITCH_OFF == RANK_HEARTBEAT_NODE_SWITCH))
    {
        MOD_NODE recv_mod_node;

        CTM   *last_update_tm;
        CTM   *last_end_tm;
        CTM   *cur_tm;


        MOD_NODE_TCID(&recv_mod_node) = TASKS_NODE_TCID(tasks_node);
        MOD_NODE_COMM(&recv_mod_node) = TASKS_NODE_COMM(tasks_node);
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_p2p_no_wait(MOD_NODE_MODI(&send_mod_node),
                        TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                        &recv_mod_node,
                        NULL_PTR, FI_super_heartbeat_none, CMPI_ERROR_MODI);

        last_update_tm = CTIMET_TO_TM(TASKS_NODE_LAST_UPDATE_TIME(tasks_node));
        last_end_tm    = CTIMET_TO_TM(TASKS_NODE_LAST_SEND_TIME(tasks_node));
        cur_tm         = CTIMET_TO_TM(cur);

        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_worker_node_trigger: "
                "[tcid %s comm %ld] last update time: %02d:%02d:%02d, "
                "last send time: %02d:%02d:%02d, "
                "cur time: %02d:%02d:%02d, "
                "CSOCKET_HEARTBEAT_INTVL_NSEC = (%ld), "
                "elapsed from last update: %ld, "
                "elapsed from last send: %ld, "
                "trigger heartbeat\n",
                TASKS_NODE_TCID_STR(tasks_node),
                TASKS_NODE_COMM(tasks_node),
                CTM_HOUR(last_update_tm),
                CTM_MIN(last_update_tm ),
                CTM_SEC(last_update_tm ),

                CTM_HOUR(last_end_tm  ),
                CTM_MIN(last_end_tm   ),
                CTM_SEC(last_end_tm   ),

                CTM_HOUR(cur_tm),
                CTM_MIN(cur_tm ),
                CTM_SEC(cur_tm ),

                heartbeat_interval, elapsed_time_from_last_update, elapsed_time_from_last_send
            );

        CTIMET_GET(TASKS_NODE_LAST_SEND_TIME(tasks_node));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

UINT32 tasks_worker_count_no_lock(const TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;
    UINT32              count;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    for(count = 0, pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE      *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(tcid       == TASKS_NODE_TCID(tasks_node)
        && srv_ipaddr == TASKS_NODE_SRVIPADDR(tasks_node)
        && srv_port   == TASKS_NODE_SRVPORT(tasks_node)
        )
        {
            count += cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node));
        }
    }

    return (count);
}

UINT32 tasks_worker_count(const TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    UINT32 count;

    CVECTOR_LOCK(TASKS_WORKER_NODES(tasks_worker), LOC_TASKS_0022);
    count = tasks_worker_count_no_lock(tasks_worker, tcid, srv_ipaddr, srv_port);
    CVECTOR_UNLOCK(TASKS_WORKER_NODES(tasks_worker), LOC_TASKS_0023);

    return (count);
}

TASKS_NODE *tasks_worker_search_tasks_node_by_ipaddr(const TASKS_WORKER *tasks_worker, const UINT32 ipaddr)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0024);
    for(pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(ipaddr == TASKS_NODE_SRVIPADDR(tasks_node))
        {
            CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0025);
            return (tasks_node);
        }
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0026);
    return (NULL_PTR);
}


TASKS_NODE *tasks_worker_search_tasks_node_by_tcid(const TASKS_WORKER *tasks_worker, const UINT32 tcid)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0027);
    for(pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }
#if 0
        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_worker_search_tasks_node_by_tcid: cmp tcid: %s <---> %s\n",
                        c_word_to_ipv4(tcid), c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)));
#endif
        if(tcid == TASKS_NODE_TCID(tasks_node))
        {
            CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0028);
            return (tasks_node);
        }
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0029);
    return (NULL_PTR);
}

TASKS_NODE *tasks_worker_search_tasks_node_by_tcid_comm(const TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 comm)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0030);
    for(pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(tcid == TASKS_NODE_TCID(tasks_node)
        && (comm == TASKS_NODE_COMM(tasks_node) || CMPI_ANY_COMM == comm))
        {
            CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0031);
            return (tasks_node);
        }
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0032);
    return (NULL_PTR);
}

UINT32 tasks_worker_search_tcid_by_ipaddr(const TASKS_WORKER *tasks_worker, const UINT32 ipaddr)
{
    TASKS_NODE *tasks_node;

    tasks_node = tasks_worker_search_tasks_node_by_ipaddr(tasks_worker, ipaddr);
    if(NULL_PTR == tasks_node)
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_search_tcid_by_ipaddr: "
                                              "failed to find tasks_node of ipaddr %s\n",
                                              c_word_to_ipv4(ipaddr));
        return (CMPI_ERROR_TCID);
    }

    return (TASKS_NODE_TCID(tasks_node));
}

TASKS_NODE *tasks_worker_search(TASKS_WORKER *tasks_worker, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port)
{
    UINT32      pos;

    for(pos = 0; pos < cvector_size(TASKS_WORKER_NODES(tasks_worker)); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = cvector_get(TASKS_WORKER_NODES(tasks_worker), pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(tcid   == TASKS_NODE_TCID(tasks_node)
        && ipaddr == TASKS_NODE_SRVIPADDR(tasks_node)
        && port   == TASKS_NODE_SRVPORT(tasks_node))
        {
            return (tasks_node);
        }
    }

    return (NULL_PTR);
}

EC_BOOL tasks_worker_check_connected_by_tcid(const TASKS_WORKER *tasks_worker, const UINT32 tcid)
{
    TASKS_NODE *tasks_node;

    if(tcid == task_brd_default_get_tcid())
    {
        dbg_log(SEC_0121_TASKS, 3)(LOGSTDOUT, "[DEBUG] tasks_worker_check_connected_by_tcid: "
                                              "check myself tcid %s\n",
                                              c_word_to_ipv4(tcid));
        return (EC_TRUE);
    }

    tasks_node = tasks_worker_search_tasks_node_by_tcid(tasks_worker, tcid);
    if(NULL_PTR == tasks_node)
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "error:tasks_worker_check_connected_by_tcid: "
                                              "failed to find tasks_node of tcid %s\n",
                                              c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    if(EC_FALSE == tasks_node_is_connected(tasks_node))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "warn:tasks_worker_check_connected_by_tcid: "
                                              "tcid %s is NOT connected\n",
                                              c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }
    dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_worker_check_connected_by_tcid: "
                                          "tcid %s is connected\n",
                                          c_word_to_ipv4(tcid));
    return (EC_TRUE);
}

EC_BOOL tasks_worker_check_connected_by_ipaddr(const TASKS_WORKER *tasks_worker, const UINT32 ipaddr)
{
    TASKS_NODE *tasks_node;

    if(ipaddr == task_brd_default_get_ipaddr())
    {
        dbg_log(SEC_0121_TASKS, 3)(LOGSTDOUT, "info:tasks_worker_checker_connected_by_ipaddr: "
                                              "check myself ipaddr %s\n",
                                              c_word_to_ipv4(ipaddr));
        return (EC_TRUE);
    }

    tasks_node = tasks_worker_search_tasks_node_by_ipaddr(tasks_worker, ipaddr);
    if(NULL_PTR == tasks_node)
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_checker_connected_by_ipaddr: "
                                              "failed to find tasks_node of ipaddr %s\n",
                                              c_word_to_ipv4(ipaddr));
        return (EC_FALSE);
    }

    if(EC_FALSE == tasks_node_is_connected(tasks_node))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "warn:tasks_worker_checker_connected_by_ipaddr: "
                                              "ipaddr %s is NOT connected\n",
                                              c_word_to_ipv4(ipaddr));
        return (EC_FALSE);
    }
    dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "tasks_worker_checker_connected_by_ipaddr: "
                                          "ipaddr %s is connected\n",
                                          c_word_to_ipv4(ipaddr));
    return (EC_TRUE);
}

EC_BOOL tasks_worker_add_csocket_cnode(TASKS_WORKER *tasks_worker, CSOCKET_CNODE *csocket_cnode)
{
    TASKS_NODE *tasks_node;

    TASKS_ASSERT(CMPI_ANY_COMM != CSOCKET_CNODE_COMM(csocket_cnode));
    TASKS_ASSERT(CMPI_ERROR_COMM != CSOCKET_CNODE_COMM(csocket_cnode));

    tasks_node = tasks_worker_search_tasks_node_by_tcid_comm(tasks_worker,
                                                             CSOCKET_CNODE_TCID(csocket_cnode),
                                                             CSOCKET_CNODE_COMM(csocket_cnode));
    if(NULL_PTR != tasks_node)
    {
        /*debug only*/
        if(0 && EC_FALSE == tasks_node_check(tasks_node, csocket_cnode))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_add_csocket_cnode: "
                                "tasks_node and csocket_cnode does not match\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_worker_add_csocket_cnode "
                                "[old] tasks_node %p (tcid %s, comm %ld, ip %s, port %ld) ADD "
                                "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d\n",
                                tasks_node,
                                TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node),
                                TASKS_NODE_SRVIPADDR_STR(tasks_node), TASKS_NODE_SRVPORT(tasks_node),
                                csocket_cnode,
                                CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                                CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                                CSOCKET_CNODE_SOCKFD(csocket_cnode)
                                );

        tasks_node_set_callback(tasks_node, csocket_cnode);

        /*update tasks_node comm if necessary*/
        if(CMPI_ANY_COMM == TASKS_NODE_COMM(tasks_node)
        && CMPI_ANY_COMM != CSOCKET_CNODE_COMM(csocket_cnode)
        && EC_TRUE == cvector_is_empty(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
        {
            TASKS_NODE_COMM(tasks_node) = CSOCKET_CNODE_COMM(csocket_cnode);

            dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_worker_add_csocket_cnode "
                                    "[update comm] tasks_node %p (tcid %s, comm %ld, ip %s, port %ld) ADD "
                                    "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d\n",
                                    tasks_node,
                                    TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node),
                                    TASKS_NODE_SRVIPADDR_STR(tasks_node), TASKS_NODE_SRVPORT(tasks_node),
                                    csocket_cnode,
                                    CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                                    CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                                    CSOCKET_CNODE_SOCKFD(csocket_cnode)
                                    );
        }

        cvector_push(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode);

        ccallback_node_run(TASKS_WORKER_ADD_NODE_CB(tasks_worker));

        if(0 < CSOCKET_CNODE_SOCKFD(csocket_cnode))
        {
            tasks_node_set_epoll(tasks_node, csocket_cnode);
        }
        return (EC_TRUE);
    }

    tasks_node = tasks_node_new(CSOCKET_CNODE_IPADDR(csocket_cnode),
                                CSOCKET_CNODE_SRVPORT(csocket_cnode),
                                CSOCKET_CNODE_TCID(csocket_cnode),
                                CSOCKET_CNODE_COMM(csocket_cnode),
                                CSOCKET_CNODE_SIZE(csocket_cnode));
    if(NULL_PTR == tasks_node)
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_add_csocket_cnode: "
                                              "new tasks_node failed\n");
        return (EC_FALSE);
    }

    TASKS_ASSERT(TASKS_NODE_COMM(tasks_node) == CSOCKET_CNODE_COMM(csocket_cnode));

    dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_worker_add_csocket_cnode "
                            "[new] tasks_node %p (tcid %s, comm %ld, ip %s, port %ld) ADD "
                            "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d\n",
                            tasks_node,
                            TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node),
                            TASKS_NODE_SRVIPADDR_STR(tasks_node), TASKS_NODE_SRVPORT(tasks_node),
                            csocket_cnode,
                            CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                            CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                            CSOCKET_CNODE_SOCKFD(csocket_cnode)
                            );

    /*note: when reach here, tasks_node and csocket_cnode always match*/
    tasks_node_set_callback(tasks_node, csocket_cnode);

#if 0
    /*update tasks_node comm if necessary*/
    if(CMPI_ANY_COMM == TASKS_NODE_COMM(tasks_node)
    && CMPI_ANY_COMM != CSOCKET_CNODE_COMM(csocket_cnode)
    && EC_TRUE == cvector_is_empty(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
    {
        TASKS_NODE_COMM(tasks_node) = CSOCKET_CNODE_COMM(csocket_cnode);
    }
#endif

    /*add csocket_cnode to tasks_node*/
    cvector_push(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode);

    dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_worker_add_csocket_cnode: "
                          "add sockfd %d to tasks_node %p (tcid %s, comm %ld, ip %s, port %ld)\n",
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          tasks_node,
                          TASKS_NODE_TCID_STR(tasks_node),
                          TASKS_NODE_COMM(tasks_node),
                          TASKS_NODE_SRVIPADDR_STR(tasks_node),
                          TASKS_NODE_SRVPORT(tasks_node));

    /*add tasks_node to tasks_work   */
    cvector_push(TASKS_WORKER_NODES(tasks_worker), (void *)tasks_node);

    ccallback_node_run(TASKS_WORKER_ADD_NODE_CB(tasks_worker));

    if(0 < CSOCKET_CNODE_SOCKFD(csocket_cnode))
    {
        tasks_node_set_epoll(tasks_node, csocket_cnode);
    }
    return (EC_TRUE);
}

EC_BOOL tasks_worker_collect_tcid(const TASKS_WORKER *tasks_worker, CVECTOR *tcid_vec)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0033);
    for(pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE *tasks_node;
        UINT32 tcid;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        tcid = TASKS_NODE_TCID(tasks_node);
        if(CVECTOR_ERR_POS == cvector_search_front_no_lock(tcid_vec, (void *)tcid, (CVECTOR_DATA_CMP)tasks_node_is_tcid))
        {
            cvector_push_no_lock(tcid_vec, (void *)tcid);
        }
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0034);
    return (EC_TRUE);
}

EC_BOOL tasks_worker_collect_ipaddr(const TASKS_WORKER *tasks_worker, CVECTOR *ipaddr_vec)
{
    const CVECTOR     *tasks_nodes;
    UINT32             pos;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0035);
    for(pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE *tasks_node;
        UINT32 ipaddr;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        ipaddr = TASKS_NODE_SRVIPADDR(tasks_node);
        if(CVECTOR_ERR_POS == cvector_search_front_no_lock(ipaddr_vec, (void *)ipaddr, NULL_PTR))
        {
            cvector_push_no_lock(ipaddr_vec, (void *)ipaddr);
        }
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0036);
    return (EC_TRUE);
}

EC_BOOL tasks_worker_init(TASKS_WORKER *tasks_worker)
{
    cvector_init(TASKS_WORKER_NODES(tasks_worker), 0, MM_TASKS_NODE, CVECTOR_LOCK_ENABLE, LOC_TASKS_0037);

    ccallback_node_init(TASKS_WORKER_ADD_NODE_CB(tasks_worker));
    ccallback_node_init(TASKS_WORKER_DEL_NODE_CB(tasks_worker));

    return (EC_TRUE);
}

EC_BOOL tasks_worker_clean(TASKS_WORKER *tasks_worker)
{
    ccallback_node_run(TASKS_WORKER_CLEANUP_CB(tasks_worker));
    ccallback_node_clean(TASKS_WORKER_CLEANUP_CB(tasks_worker));

    ccallback_node_clean(TASKS_WORKER_ADD_NODE_CB(tasks_worker));
    ccallback_node_clean(TASKS_WORKER_DEL_NODE_CB(tasks_worker));

    cvector_clean(TASKS_WORKER_NODES(tasks_worker),
                    (CVECTOR_DATA_CLEANER)tasks_node_free,
                    LOC_TASKS_0038);

    return (EC_TRUE);
}


void tasks_worker_print(LOG *log, const TASKS_WORKER *tasks_worker)
{
    sys_log(log, "tasks_worker %lx: nodes:\n", tasks_worker);
    cvector_print(log, TASKS_WORKER_NODES(tasks_worker), (CVECTOR_DATA_PRINT)tasks_node_print);

    return ;
}

void tasks_worker_print_in_plain(LOG *log, const TASKS_WORKER *tasks_worker)
{
    UINT32 index;

    index = 0;
    tasks_worker_print_csocket_cnode_list_in_plain(log, tasks_worker, &index);

    return;
}

void tasks_worker_print_csocket_cnode_list_in_plain(LOG *log, const TASKS_WORKER *tasks_worker, UINT32 *index)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0039);
    for(pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "No. %ld: (tasks node is null)\n", (*index) ++);
            continue;
        }
        tasks_node_print_csocket_cnode_list(log, tasks_node, index);
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0040);
    return;
}

EC_BOOL tasks_node_set_writable(TASKS_NODE  *tasks_node)
{
    UINT32       num;
    UINT32       pos;

    EC_BOOL      ret;

    ret = EC_FALSE;

    num = cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node));

    for(pos = 0; pos < num; pos ++)
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = (CSOCKET_CNODE *)cvector_get(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), pos);
        if(NULL_PTR == csocket_cnode)
        {
            continue;
        }

        if(TASKS_NODE_COMM(tasks_node) == CSOCKET_CNODE_COMM(csocket_cnode)
            || CMPI_ANY_COMM == TASKS_NODE_COMM(tasks_node)
            || CMPI_ANY_COMM == CSOCKET_CNODE_COMM(csocket_cnode))
        {
            if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
            {
                continue;
            }

            if(BIT_FALSE == CSOCKET_CNODE_WRITING(csocket_cnode))
            {
                /*May 3,2017*/
                cepoll_set_event(task_brd_default_get_cepoll(),
                                  CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                  CEPOLL_WR_EVENT,
                                  (const char *)"csocket_cnode_isend",
                                  (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                                  (void *)csocket_cnode);
                CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
            }

            ret = EC_TRUE;
            continue;
        }
    }

    return (ret);
}

EC_BOOL tasks_worker_isend_node(TASKS_WORKER *tasks_worker, const UINT32 des_tcid, const UINT32 des_comm, const UINT32 msg_tag, TASK_NODE *task_node)
{
    TASKS_NODE  *tasks_node;

    tasks_node = tasks_worker_search_tasks_node_by_tcid_comm(tasks_worker, des_tcid, des_comm);
    if(NULL_PTR == tasks_node)
    {
        TASKS_CFG *remote_tasks_cfg;

        TASKS_ASSERT(TASK_REQ_SENDAGN != TASK_NODE_STATUS(task_node));

        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_isend_node: "
                        "des_tcid %s not exit where "
                        "(tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld), "
                        "with priority %ld, type %ld, tag %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        c_word_to_ipv4(des_tcid),
                        TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                        TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                        TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                        TASK_NODE_TAG(task_node),
                        TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                        TASK_NODE_FUNC_ID(task_node)
                        );

        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "lost route: "
                        "from (tcid %s,comm %ld,rank %ld,modi %ld) to (tcid %s,comm %ld,rank %ld,modi %ld) "
                        "with priority %ld, type %ld, tag %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx\n",
                        TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                        TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),
                        TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                        TASK_NODE_TAG(task_node),
                        TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                        TASK_NODE_FUNC_ID(task_node)
                        );

        /*if tcid is registered in sys cfg*/
        remote_tasks_cfg = task_brd_register_node_fetch(task_brd_default_get(), des_tcid);
        if(NULL_PTR != remote_tasks_cfg)
        {
            MOD_NODE        recv_mod_node;

            MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
            MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

            task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                             &recv_mod_node,
                             NULL_PTR,
                             FI_super_add_connection, CMPI_ERROR_MODI, des_tcid, des_comm,
                             TASKS_CFG_SRVIPADDR(remote_tasks_cfg), TASKS_CFG_SRVPORT(remote_tasks_cfg),
                             (UINT32)CSOCKET_CNODE_NUM);

            /*return (EC_AGAIN);*/
            return (EC_FALSE);
        }

        /*if supporting T-DNS, resolve tcid*/
        if(TDNS_RESOLVE_SWITCH == SWITCH_ON)
        {
            MOD_NODE        recv_mod_node;

            MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
            MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

            task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                             &recv_mod_node,
                             NULL_PTR,
                             FI_super_connect, CMPI_ERROR_MODI, des_tcid, des_comm, (UINT32)1/*CSOCKET_CNODE_NUM*/);

            /*return (EC_AGAIN);*/
            return (EC_FALSE);
        }

        return (EC_FALSE);
    }

    dbg_log(SEC_0121_TASKS, 7)(LOGSTDOUT, "[DEBUG] tasks_worker_isend_node: "
                                          "tcid %s comm %ld own %ld connections\n",
                                          TASKS_NODE_TCID_STR(tasks_node),
                                          TASKS_NODE_COMM(tasks_node),
                                          cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)));

    if(NULL_PTR != tasks_node
    && 0 == cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_isend_node: "
                    "tcid %s comm %ld has no connections, register again\n",
                    TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node));

        cvector_remove(TASKS_WORKER_NODES(tasks_worker), (void *)tasks_node);

        ccallback_node_run(TASKS_WORKER_DEL_NODE_CB(tasks_worker));

        tasks_node_free(tasks_node);

        return (EC_FALSE);
    }

    if(EC_FALSE == tasks_node_set_writable(tasks_node))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_worker_isend_node: "
                    "tcid %s comm %ld has no connection alive, register again\n",
                    TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node));

        /*register remote tcid if none or insufficient connections*/
        /*task_brd_register_node(task_brd_default_get(), TASKS_NODE_TCID(tasks_node));*//*no meaningful*/

        return (EC_FALSE);
    }

    /*note: task_node is only mounted to sending list*/
    clist_push_back(TASKS_NODE_SENDING_LIST(tasks_node), (void *)task_node);
    if(CMPI_ANY_COMM == TASK_NODE_RECV_COMM(task_node))
    {
        TASK_NODE_RECV_COMM(task_node) = TASKS_NODE_COMM(tasks_node);

        task_any_encode(TASK_NODE_ANY(task_node));
    }
    dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "[DEBUG] tasks_worker_isend_node: "
                        "task_node %p (tcid %s,comm %ld,rank %ld,modi %ld) -> (tcid %s,comm %ld,rank %ld,modi %ld), "
                        "with priority %ld, type %ld, tag %ld, seqno %lx.%lx.%lx, subseqno %ld, func id %lx "
                        "OVER tasks_node %p (tcid %s comm %ld, %ld conn)\n",
                        task_node,
                        TASK_NODE_SEND_TCID_STR(task_node), TASK_NODE_SEND_COMM(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEND_MODI(task_node),
                        TASK_NODE_RECV_TCID_STR(task_node), TASK_NODE_RECV_COMM(task_node), TASK_NODE_RECV_RANK(task_node), TASK_NODE_RECV_MODI(task_node),

                        TASK_NODE_PRIO(task_node), TASK_NODE_TYPE(task_node),
                        TASK_NODE_TAG(task_node),
                        TASK_NODE_SEND_TCID(task_node), TASK_NODE_SEND_RANK(task_node), TASK_NODE_SEQNO(task_node), TASK_NODE_SUB_SEQNO(task_node),
                        TASK_NODE_FUNC_ID(task_node),

                        tasks_node,
                        TASKS_NODE_TCID_STR(tasks_node),
                        TASKS_NODE_COMM(tasks_node),
                        cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)));

    return (EC_TRUE);
}


/***********************************************************************************************************************
*
*   WARNING: THIS INTERFACE IS OBSOLETE AND IS WRONG !!!
*
*   we cannot loop task_node because when multiple task_nodes map to the same csocket_cnode,
*   terrible may happen.
*
*   when the csocket_cnode is congested and does not send out the whole data of the previous task_node,
*   loop will move forward. if some next task_node map to this csocket_cnode, and bingo! at the same time,
*   the csocket_cnode dismiss congestion state, tasks_worker_isend1 will start to send data of this next task_node,
*   but the previous task_node does not complete data sending out! disorder happen!
*
*   hence, the conclusion is we cannot loop task_node, but loop tasks_node or csocket_cnode!
*
*
***********************************************************************************************************************/



EC_BOOL tasks_worker_heartbeat(TASKS_WORKER *tasks_worker)
{
    TASK_BRD    *task_brd;
    CVECTOR     *tasks_nodes;
    UINT32       pos;

    tasks_nodes = TASKS_WORKER_NODES(tasks_worker);

    task_brd = task_brd_default_get();

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0041);
    for(pos = 0; pos < cvector_size(tasks_nodes); /*pos ++*/)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            pos ++;
            continue;
        }

        if(TASKS_NODE_TCID(tasks_node) == TASK_BRD_TCID(task_brd))
        {
            pos ++;
            continue;
        }

        if(EC_FALSE == tasks_worker_node_trigger(tasks_node))
        {
            cvector_erase_no_lock(tasks_nodes, pos);
            tasks_node_free(tasks_node);
            continue;
        }
        else
        {
            pos ++;
        }
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0042);

    return (EC_TRUE);
}

TASKS_NODE *tasks_monitor_search_tasks_node_by_tcid(const TASKS_MONITOR *tasks_monitor, const UINT32 tcid)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;

    tasks_nodes = TASKS_MONITOR_NODES(tasks_monitor);

    CVECTOR_LOCK(tasks_nodes, LOC_TASKS_0043);
    for(pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_monitor_search_tasks_node_by_tcid: "
                                              "cmp tcid: %s <---> %s\n",
                                              c_word_to_ipv4(tcid),
                                              c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)));

        if(tcid == TASKS_NODE_TCID(tasks_node))
        {
            CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0044);
            return (tasks_node);
        }
    }
    CVECTOR_UNLOCK(tasks_nodes, LOC_TASKS_0045);
    return (NULL_PTR);
}

EC_BOOL tasks_monitor_add_csocket_cnode(TASKS_MONITOR *tasks_monitor, CSOCKET_CNODE *csocket_cnode)
{
    TASKS_NODE *tasks_node;

    tasks_node = tasks_monitor_search_tasks_node_by_tcid(tasks_monitor, CSOCKET_CNODE_TCID(csocket_cnode));
    if(NULL_PTR != tasks_node)
    {
#if 0
        /*debug only*/
        if(EC_FALSE == tasks_node_check(tasks_node, csocket_cnode))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_monitor_add_csocket_cnode: tasks_node and csocket_cnode does not match\n");
            return (EC_FALSE);
        }
#endif
        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_monitor_add_csocket_cnode "
                                "[old] tasks_node %p (tcid %s, comm %ld, ip %s, port %ld) ADD "
                                "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d\n",
                                tasks_node,
                                TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node),
                                TASKS_NODE_SRVIPADDR_STR(tasks_node), TASKS_NODE_SRVPORT(tasks_node),
                                csocket_cnode,
                                CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                                CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                                CSOCKET_CNODE_SOCKFD(csocket_cnode)
                                );

        tasks_node_set_callback(tasks_node, csocket_cnode);

        cvector_push(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode);

        ccallback_node_run(TASKS_MONITOR_ADD_NODE_CB(tasks_monitor));

        tasks_node_set_epoll(tasks_node, csocket_cnode);
        return (EC_TRUE);
    }

    tasks_node = tasks_node_new(CSOCKET_CNODE_IPADDR(csocket_cnode),
                                CSOCKET_CNODE_SRVPORT(csocket_cnode),
                                CSOCKET_CNODE_TCID(csocket_cnode),
                                CSOCKET_CNODE_COMM(csocket_cnode),
                                CSOCKET_CNODE_SIZE(csocket_cnode));
    if(NULL_PTR == tasks_node)
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_monitor_add_csocket_cnode: "
                                              "new tasks_node failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_monitor_add_csocket_cnode "
                            "[new] tasks_node %p (tcid %s, comm %ld, ip %s, port %ld) ADD "
                            "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d\n",
                            tasks_node,
                            TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node),
                            TASKS_NODE_SRVIPADDR_STR(tasks_node), TASKS_NODE_SRVPORT(tasks_node),
                            csocket_cnode,
                            CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                            CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                            CSOCKET_CNODE_SOCKFD(csocket_cnode)
                            );

    /*note: when reach here, tasks_node and csocket_cnode always match (warn:tcid matched, but comm maybe ANY)*/
    tasks_node_set_callback(tasks_node, csocket_cnode);

    /*add csocket_cnode to tasks_node*/
    cvector_push(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode);

    /*add tasks_node to tasks_monitor*/
    cvector_push(TASKS_MONITOR_NODES(tasks_monitor), (void *)tasks_node);

    ccallback_node_run(TASKS_MONITOR_ADD_NODE_CB(tasks_monitor));

    tasks_node_set_epoll(tasks_node, csocket_cnode);
    return (EC_TRUE);
}

UINT32 tasks_monitor_count_no_lock(const TASKS_MONITOR *tasks_monitor, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    const CVECTOR      *tasks_nodes;
    UINT32              pos;
    UINT32              count;

    tasks_nodes = TASKS_MONITOR_NODES(tasks_monitor);

    for(count = 0, pos = 0; pos < cvector_size(tasks_nodes); pos ++)
    {
        TASKS_NODE      *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(tasks_nodes, pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(tcid       == TASKS_NODE_TCID(tasks_node)
        && srv_ipaddr == TASKS_NODE_SRVIPADDR(tasks_node)
        && srv_port   == TASKS_NODE_SRVPORT(tasks_node)
        )
        {
            count += cvector_size(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node));
        }
    }

    return (count);
}

UINT32 tasks_monitor_count(const TASKS_MONITOR *tasks_monitor, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    UINT32 count;

    CVECTOR_LOCK(TASKS_MONITOR_NODES(tasks_monitor), LOC_TASKS_0046);
    count = tasks_monitor_count_no_lock(tasks_monitor, tcid, srv_ipaddr, srv_port);
    CVECTOR_UNLOCK(TASKS_MONITOR_NODES(tasks_monitor), LOC_TASKS_0047);

    return (count);
}

/**
*
*   open one client connection to remote server
*   1. connect to remote server with server ip & port info
*   2. add the client connection to client set of server
*   3. add the client to FD SET of server to monitor
*
**/
EC_BOOL tasks_monitor_open(TASKS_MONITOR *tasks_monitor, const UINT32 tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    CSOCKET_CNODE   *csocket_cnode;
    UINT32           client_ipaddr;
    UINT32           client_port;
    int              client_sockfd;

    if(EC_FALSE == csocket_client_start(srv_ipaddr, srv_port, CSOCKET_IS_NONBLOCK_MODE, &client_sockfd, &client_ipaddr, &client_port))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "error:tasks_monitor_open: "
                                              "failed to connect server %s:%ld\n",
                                              c_word_to_ipv4(srv_ipaddr), srv_port);
        return (EC_FALSE);
    }

    if(EC_FALSE == csocket_is_connected(client_sockfd))
    {
        dbg_log(SEC_0121_TASKS, 1)(LOGSTDOUT, "error:tasks_monitor_open: "
                                              "socket %d to server %s:%ld is not connected\n",
                                              client_sockfd, c_word_to_ipv4(srv_ipaddr), srv_port);
        csocket_client_end(client_sockfd);
        return (EC_FALSE);
    }

    if(do_log(SEC_0121_TASKS, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] tasks_monitor_open: client tcp stat:\n");
        csocket_tcpi_stat_print(LOGSTDOUT, client_sockfd);
    }

    csocket_cnode = csocket_cnode_new(LOC_TASKS_0048);/*client save remote server ipaddr and srvport info*/
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_monitor_open:new "
                                              "csocket cnode failed\n");
        csocket_client_end(client_sockfd);
        return (EC_FALSE);
    }

    CSOCKET_CNODE_TCID(csocket_cnode  )         = tcid;
    CSOCKET_CNODE_COMM(csocket_cnode  )         = CMPI_ANY_COMM;
    CSOCKET_CNODE_SOCKFD(csocket_cnode)         = client_sockfd;
    CSOCKET_CNODE_TYPE(csocket_cnode )          = CSOCKET_TYPE_TCP;
    CSOCKET_CNODE_IPADDR(csocket_cnode)         = srv_ipaddr;
    CSOCKET_CNODE_SRVPORT(csocket_cnode)        = srv_port;
    CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode)  = client_ipaddr;
    CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)    = client_port;

    tasks_monitor_add_csocket_cnode(tasks_monitor, csocket_cnode);

    dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "[DEBUG] tasks_monitor_open: "
                                          "sockfd %d is connecting to server %s:%ld\n",
                                          client_sockfd, c_word_to_ipv4(srv_ipaddr), srv_port);

    return (EC_TRUE);
}

EC_BOOL tasks_monitor_init(TASKS_MONITOR *tasks_monitor)
{
    cvector_init(TASKS_MONITOR_NODES(tasks_monitor), 0, MM_TASKS_NODE, CVECTOR_LOCK_ENABLE, LOC_TASKS_0049);

    ccallback_node_init(TASKS_MONITOR_ADD_NODE_CB(tasks_monitor));
    ccallback_node_init(TASKS_MONITOR_DEL_NODE_CB(tasks_monitor));
    ccallback_node_init(TASKS_MONITOR_CLEANUP_CB(tasks_monitor));

    return (EC_TRUE);
}

EC_BOOL tasks_monitor_clean(TASKS_MONITOR *tasks_monitor)
{
    ccallback_node_run(TASKS_MONITOR_CLEANUP_CB(tasks_monitor));
    ccallback_node_clean(TASKS_MONITOR_CLEANUP_CB(tasks_monitor));

    ccallback_node_clean(TASKS_MONITOR_ADD_NODE_CB(tasks_monitor));
    ccallback_node_clean(TASKS_MONITOR_DEL_NODE_CB(tasks_monitor));

    cvector_clean(TASKS_MONITOR_NODES(tasks_monitor),
                    (CVECTOR_DATA_CLEANER)tasks_node_free,
                    LOC_TASKS_0050);
    return (EC_TRUE);
}

EC_BOOL tasks_monitor_is_empty(const TASKS_MONITOR *tasks_monitor)
{
    if(EC_TRUE == cvector_is_empty(TASKS_MONITOR_NODES(tasks_monitor)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void tasks_monitor_print(LOG *log, const TASKS_MONITOR *tasks_monitor)
{
    sys_log(log, "tasks_monitor %lx: nodes:\n", tasks_monitor);
    cvector_print(log, TASKS_MONITOR_NODES(tasks_monitor), (CVECTOR_DATA_PRINT)tasks_node_print);

    return ;
}

/*---------------------------------- handshake ----------------------------------*/
STATIC_CAST static TASK_NODE *__tasks_handshake_encode()
{
    TASK_NODE *task_node;

    UINT8     *data_buff;
    UINT32     data_num;
    UINT32     pos;

    UINT32     data_tag;

    TASK_BRD  *task_brd;

    task_brd = task_brd_default_get();

    data_tag = 0;
    data_num = csocket_encode_actual_size() + xmod_node_encode_actual_size();

    task_node = task_node_new(data_num, LOC_TASKS_0051);
    if(NULL_PTR == task_node)
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:__tasks_handshake_encode: "
                                              "new task_node failed\n");
        return (NULL_PTR);
    }
    TASK_NODE_TAG(task_node) = TAG_TASK_REQ;/*trick on task_node_free*/

    data_buff = TASK_NODE_BUFF(task_node);

    pos = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32(TASK_BRD_COMM(task_brd), data_num, data_buff, data_num, &pos);           /*no useful info*/
    cmpi_encode_uint32(TASK_BRD_COMM(task_brd), data_tag, data_buff, data_num, &pos);           /*no useful info*/

    cmpi_encode_uint32(TASK_BRD_COMM(task_brd), TASK_BRD_TCID(task_brd), data_buff, data_num, &pos);/*payload info*/
    cmpi_encode_uint32(TASK_BRD_COMM(task_brd), TASK_BRD_COMM(task_brd), data_buff, data_num, &pos);/*payload info*/
    cmpi_encode_uint32(TASK_BRD_COMM(task_brd), TASK_BRD_SIZE(task_brd), data_buff, data_num, &pos);/*payload info*/
    cmpi_encode_uint32(TASK_BRD_COMM(task_brd), TASK_BRD_PORT(task_brd), data_buff, data_num, &pos);/*payload info*/
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_encode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), data_num, data_buff, data_num, &pos);           /*no useful info*/
    cmpi_encode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd), data_tag, data_buff, data_num, &pos);           /*no useful info*/

    cmpi_encode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), TASK_BRD_TCID(task_brd), data_buff, data_num, &pos);/*payload info*/
    cmpi_encode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), TASK_BRD_COMM(task_brd), data_buff, data_num, &pos);/*payload info*/
    cmpi_encode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd), TASK_BRD_SIZE(task_brd), data_buff, data_num, &pos);/*payload info*/
    cmpi_encode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), TASK_BRD_PORT(task_brd), data_buff, data_num, &pos);/*payload info*/
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/


    return (task_node);
}

STATIC_CAST static EC_BOOL __tasks_handshake_decode(TASK_NODE *task_node, CSOCKET_CNODE *csocket_cnode)
{
    TASK_BRD    *task_brd;

    UINT8       *data_buff;
    UINT32       data_num;

    UINT32       discard_data_num;
    UINT32       discard_data_tag;
    UINT32       position;

    UINT32       port;
    UINT32       tcid;
    UINT32       comm;
    UINT32       size;

    task_brd = task_brd_default_get();

    data_buff = TASK_NODE_BUFF(task_node);
    data_num  = TASK_NODE_BUFF_LEN(task_node);

    position = 0;

#if (SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &(discard_data_num));
    cmpi_decode_uint32(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &(discard_data_tag));

    cmpi_decode_uint32(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &tcid);
    cmpi_decode_uint32(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &comm);
    cmpi_decode_uint32(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &size);
    cmpi_decode_uint32(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &port);
#endif/*(SWITCH_OFF == TASK_HEADER_COMPRESSED_SWITCH)*/

#if (SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)
    cmpi_decode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &(discard_data_num));
    cmpi_decode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd) , data_buff, data_num, &position, &(discard_data_tag));

    cmpi_decode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &tcid);
    cmpi_decode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &comm);
    cmpi_decode_uint32_compressed_uint8_t(TASK_BRD_COMM(task_brd) , data_buff, data_num, &position, &size);
    cmpi_decode_uint32_compressed_uint32_t(TASK_BRD_COMM(task_brd), data_buff, data_num, &position, &port);
#endif/*(SWITCH_ON == TASK_HEADER_COMPRESSED_SWITCH)*/

    /*c*/
    if(CMPI_ANY_TCID != CSOCKET_CNODE_TCID(csocket_cnode)
    && CMPI_ERROR_TCID != CSOCKET_CNODE_TCID(csocket_cnode) /*for accepted client*/
    && tcid != CSOCKET_CNODE_TCID(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:__tasks_handshake_decode: "
                    "TCID NOT MATCHED: "
                    "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d "
                    "vs decoded (tcid %s, comm %ld, size %ld, port %ld) "
                    "=> pls check config carefully!\n",
                    csocket_cnode,
                    CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                    CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    c_word_to_ipv4(tcid), comm, size, port
                    );

         task_brd_default_abort();
    }

    if(CMPI_ANY_SRVPORT != CSOCKET_CNODE_SRVPORT(csocket_cnode)
    && CMPI_ERROR_SRVPORT != CSOCKET_CNODE_SRVPORT(csocket_cnode)
    && port != CSOCKET_CNODE_SRVPORT(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:__tasks_handshake_decode: "
                    "PORT NOT MATCHED: "
                    "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d "
                    "vs decoded (tcid %s, comm %ld, size %ld, port %ld) "
                    "=> pls check config carefully!\n",
                    csocket_cnode,
                    CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                    CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    c_word_to_ipv4(tcid), comm, size, port
                    );

         task_brd_default_abort();
    }

    CSOCKET_CNODE_TCID(csocket_cnode)       = tcid;
    CSOCKET_CNODE_COMM(csocket_cnode)       = comm;
    CSOCKET_CNODE_SIZE(csocket_cnode)       = size;
    CSOCKET_CNODE_SRVPORT(csocket_cnode)    = port;

    return (EC_TRUE);
}

EC_BOOL tasks_handshake_ichange(CSOCKET_CNODE *csocket_cnode)
{
    TASKS_NODE       *tasks_node;

    tasks_node = CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode);

    TASKS_ASSERT(NULL_PTR != tasks_node);

    if(NULL_PTR != tasks_node
    && (TASKS_NODE_TCID(tasks_node) != CSOCKET_CNODE_TCID(csocket_cnode)
    || TASKS_NODE_COMM(tasks_node) != CSOCKET_CNODE_COMM(csocket_cnode))) /*tasks_node was changed*/
    {
        TASK_BRD         *task_brd;
        TASKS_CFG        *tasks_cfg;

        TASKS_MONITOR    *tasks_monitor;
        TASKS_WORKER     *tasks_worker;

        task_brd      = task_brd_default_get();
        tasks_cfg     = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

        tasks_monitor = TASKS_CFG_MONITOR(tasks_cfg);
        tasks_worker  = TASKS_CFG_WORKER(tasks_cfg);

        cvector_delete(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode);
        CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode) = NULL_PTR;

        /*Jun 26, 2020*/
        if(EC_TRUE == cvector_is_empty(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
        {
            cvector_delete(TASKS_MONITOR_NODES(tasks_monitor), (void *)tasks_node);
            tasks_node_free(tasks_node);
        }

        if(CSOCKET_CNODE_XCHG_TASKC_NODE != CSOCKET_CNODE_STATUS(csocket_cnode))
        {
            tasks_monitor_add_csocket_cnode(tasks_monitor, csocket_cnode);

            dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_handshake_ichange: "
                                                  "sockfd %d change to monitor\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode));
        }
        else
        {
            tasks_worker_add_csocket_cnode(tasks_worker, csocket_cnode);

            dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_handshake_ichange: "
                                                  "sockfd %d change to worker\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode));
        }
    }

    return (EC_TRUE);
}
EC_BOOL tasks_handshake_isend(CSOCKET_CNODE *csocket_cnode)
{
    TASK_NODE *task_node;

    task_node = CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode);
    if(NULL_PTR == task_node)
    {
        task_node = __tasks_handshake_encode();
        if(NULL_PTR == task_node)
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_isend: "
                                                  "make task_node failed\n");
            return (EC_FALSE);
        }

        /*when sending on socket does not complete, add request to monitor list*/
        CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = (void *)task_node;
    }

    if(TASK_NODE_BUFF_POS(task_node) != TASK_NODE_BUFF_LEN(task_node))
    {
        /*try to send the left data*/
        if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_isend: "
                                                  "sockfd %d was broken\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode));

            CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR;
            task_node_free(task_node); /*this is handshake task_node*/
            return (EC_FALSE);
        }

        if(EC_FALSE == csocket_cnode_send(csocket_cnode,
                                           TASK_NODE_BUFF(task_node),
                                           TASK_NODE_BUFF_LEN(task_node),
                                           &(TASK_NODE_BUFF_POS(task_node))))
        {
            dbg_log(SEC_0121_TASKS, 0)(LOGSTDERR, "error:tasks_handshake_isend: "
                                                  "sockfd %d isend failed\n",
                                                  CSOCKET_CNODE_SOCKFD(csocket_cnode));

            CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR;
            task_node_free(task_node); /*this is handshake task_node*/
            return (EC_FALSE);
        }

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_isend: "
                                              "sockfd %d send pos %ld len %ld\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                              TASK_NODE_BUFF_POS(task_node),
                                              TASK_NODE_BUFF_LEN(task_node));
    }

    if(TASK_NODE_BUFF_POS(task_node) == TASK_NODE_BUFF_LEN(task_node))
    {
        CSOCKET_CNODE_STATUS(csocket_cnode) |= CSOCKET_CNODE_SENT_TASKC_NODE;

        CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode) = NULL_PTR;
        task_node_free(task_node); /*this is handshake task_node*/
    }

    return (EC_TRUE);
}

EC_BOOL tasks_handshake_irecv(CSOCKET_CNODE *csocket_cnode)
{
    TASK_NODE  *task_node;

    dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_irecv: "
                                          "sockfd %d RD events triggered\n",
                                          CSOCKET_CNODE_SOCKFD(csocket_cnode));

    /*handle incoming task_node*/
    task_node = CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode);
    if(NULL_PTR != task_node)
    {
        /*if fix cannot complete the task_node, CRBUFF has no data to handle, so terminate*/
        if(EC_FALSE == csocket_cnode_fix_task_node(csocket_cnode, task_node))
        {
            if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
            {
                dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_irecv: "
                                                      "sockfd %d was broken\n",
                                                      CSOCKET_CNODE_SOCKFD(csocket_cnode));

                CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = NULL_PTR;
                task_node_free(task_node);
                return (EC_FALSE);
            }

            /*wait for next irecv*/
            return (EC_TRUE);
        }

        CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = NULL_PTR;

        TASK_NODE_COMP(task_node) = TASK_WAS_RECV;

        /*fall through*/
    }
    else
    {
        /*handle next task_node*/
        task_node = csocket_fetch_task_node(csocket_cnode);
        if(NULL_PTR == task_node)
        {
            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_irecv: "
                                                  "task_node is null\n");

            if(0 == CSOCKET_CNODE_PKT_POS(csocket_cnode))
            {
                dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_irecv: "
                                                      "pkt pos is 0\n");
                return (EC_FALSE);
            }

            if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
            {
                dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_irecv: "
                                                      "sockfd %d was broken\n",
                                                      CSOCKET_CNODE_SOCKFD(csocket_cnode));
                return (EC_FALSE);
            }

            if(EC_FALSE == CSOCKET_CNODE_IS_CONNECTED(csocket_cnode))
            {
                dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_irecv: "
                                                      "sockfd %d was set to disconnected\n",
                                                      CSOCKET_CNODE_SOCKFD(csocket_cnode));

                return (EC_FALSE);
            }

            return (EC_TRUE);
        }

        TASK_NODE_TAG(task_node) = TAG_TASK_REQ;/*trick on task_node_free*/

        if(TASK_NODE_BUFF_POS(task_node) == TASK_NODE_BUFF_LEN(task_node))
        {
            TASK_NODE_COMP(task_node) = TASK_WAS_RECV;
            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_irecv: "
                                                  "pos %ld, len %ld => incomed\n",
                                                  TASK_NODE_BUFF_POS(task_node),
                                                  TASK_NODE_BUFF_LEN(task_node));

            /*fall through*/
        }
        else
        {
            if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
            {
                dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_irecv: "
                                                      "sockfd %d was broken\n",
                                                      CSOCKET_CNODE_SOCKFD(csocket_cnode));

                task_node_free(task_node);
                return (EC_FALSE);
            }

            /*incomplete task_node*/
            CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = (void *)task_node;

            dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_irecv: "
                                                  "pos %ld, len %ld => incoming\n",
                                                  TASK_NODE_BUFF_POS(task_node),
                                                  TASK_NODE_BUFF_LEN(task_node));

            return (EC_TRUE);
        }
    }

    TASKS_ASSERT(NULL_PTR == CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode));
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_irecv: "
                                              "sockfd %d was broken\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));

        task_node_free(task_node);
        return (EC_FALSE);
    }

    TASKS_ASSERT(NULL_PTR != task_node);
    TASKS_ASSERT(TASK_WAS_RECV == TASK_NODE_COMP(task_node));

    __tasks_handshake_decode(task_node, csocket_cnode);
    CSOCKET_CNODE_STATUS(csocket_cnode) |= CSOCKET_CNODE_RCVD_TASKC_NODE;

    task_node_free(task_node);

    tasks_handshake_ichange(csocket_cnode);

    return (EC_TRUE);
}

EC_BOOL tasks_handshake_send(CSOCKET_CNODE *csocket_cnode)
{
    //TASKS_ASSERT(TASKS_NODE_TCID(tasks_node) == CSOCKET_CNODE_TCID(csocket_cnode));
    if(CSOCKET_CNODE_SENT_TASKC_NODE & CSOCKET_CNODE_STATUS(csocket_cnode))
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == tasks_handshake_isend(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_send: "
                                              "sockfd %d isend task_node failed\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(CSOCKET_CNODE_SENT_TASKC_NODE & CSOCKET_CNODE_STATUS(csocket_cnode))
    {
        cepoll_del_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_WR_EVENT);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_send: "
                                              "sockfd %d del WR event done\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));

        /*check if handshake complete*/
        return tasks_handshake_icomplete(csocket_cnode);
    }

    /*wait to send again*/
    return (EC_TRUE);
}

EC_BOOL tasks_handshake_recv(CSOCKET_CNODE *csocket_cnode)
{
    //TASKS_ASSERT(TASKS_NODE_TCID(tasks_node) == CSOCKET_CNODE_TCID(csocket_cnode));
    if(CSOCKET_CNODE_RCVD_TASKC_NODE & CSOCKET_CNODE_STATUS(csocket_cnode))
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == tasks_handshake_irecv(csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "error:tasks_handshake_recv: "
                                              "sockfd %d irecv task_node failed\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(CSOCKET_CNODE_RCVD_TASKC_NODE & CSOCKET_CNODE_STATUS(csocket_cnode)
    && 0 == (CSOCKET_CNODE_SENT_TASKC_NODE & CSOCKET_CNODE_STATUS(csocket_cnode)))
    {
        cepoll_del_event(task_brd_default_get_cepoll(),
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;

        dbg_log(SEC_0121_TASKS, 9)(LOGSTDOUT, "[DEBUG] tasks_handshake_recv: "
                                              "sockfd %d del RD event done (tasks_node %p)\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                              CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode));


        /*check if handshake complete*/
        //return tasks_handshake_icomplete(csocket_cnode);
    }

    /*wait to recv again*/
    return (EC_TRUE);
}

EC_BOOL tasks_handshake_icomplete(CSOCKET_CNODE *csocket_cnode)
{
    TASK_BRD         *task_brd;
    TASKS_CFG        *tasks_cfg;

    TASKS_MONITOR    *tasks_monitor;
    TASKS_WORKER     *tasks_worker;
    TASKS_NODE       *tasks_node;

    if(CSOCKET_CNODE_XCHG_TASKC_NODE != CSOCKET_CNODE_STATUS(csocket_cnode))
    {
        return (EC_TRUE);
    }

    task_brd      = task_brd_default_get();
    tasks_cfg     = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

    tasks_monitor = TASKS_CFG_MONITOR(tasks_cfg);
    tasks_worker  = TASKS_CFG_WORKER(tasks_cfg);

    tasks_node    = CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode);

    if(EC_TRUE == cvector_delete(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode))
    {
        dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_handshake_icomplete "
                        "[monitor] tasks_node %p (tcid %s, comm %ld, ip %s, port %ld) DEL "
                        "csocket_cnode %p (tcid %s, comm %ld, ip %s, port %ld) sockfd %d\n",
                        tasks_node,
                        TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node),
                        TASKS_NODE_SRVIPADDR_STR(tasks_node), TASKS_NODE_SRVPORT(tasks_node),
                        csocket_cnode,
                        CSOCKET_CNODE_TCID_STR(csocket_cnode), CSOCKET_CNODE_COMM(csocket_cnode),
                        CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode)
                        );

        /*callback and epoll will be reset during add csocket_cnode*/
        tasks_worker_add_csocket_cnode(tasks_worker, csocket_cnode);
    }

    if(EC_TRUE == cvector_is_empty(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
    {
        cvector_delete(TASKS_MONITOR_NODES(tasks_monitor), (void *)tasks_node);
        tasks_node_free(tasks_node);
    }

    dbg_log(SEC_0121_TASKS, 5)(LOGSTDOUT, "[DEBUG] tasks_handshake_icomplete: "
                                          "sockfd %d done\n",
                                          CSOCKET_CNODE_SOCKFD(csocket_cnode));

    return (EC_TRUE);
}

EC_BOOL tasks_handshake_shutdown(CSOCKET_CNODE *csocket_cnode)
{
    if(NULL_PTR != csocket_cnode)
    {
        TASKS_NODE  *tasks_node;

        tasks_node = CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        /*remove csocket_cnode if existing*/
        cvector_delete(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node), (void *)csocket_cnode);

        if(NULL_PTR != CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode))
        {
            task_node_free(CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode));
            CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode) = NULL_PTR;
        }

        if(EC_TRUE == cvector_is_empty(TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)))
        {
            TASK_BRD         *task_brd;
            TASKS_CFG        *tasks_cfg;

            TASKS_MONITOR    *tasks_monitor;
            TASKS_WORKER     *tasks_worker;

            task_brd      = task_brd_default_get();
            tasks_cfg     = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

            tasks_monitor = TASKS_CFG_MONITOR(tasks_cfg);
            tasks_worker  = TASKS_CFG_WORKER(tasks_cfg);

            if(CSOCKET_CNODE_XCHG_TASKC_NODE != CSOCKET_CNODE_STATUS(csocket_cnode))
            {
                cvector_remove(TASKS_MONITOR_NODES(tasks_monitor), (void *)tasks_node);
            }
            else
            {
                cvector_remove(TASKS_WORKER_NODES(tasks_worker), (void *)tasks_node);
            }

            CSOCKET_CNODE_MOUNTED_POINT(csocket_cnode) = NULL_PTR;

            tasks_node_free(tasks_node);
        }

        dbg_log(SEC_0121_TASKS, 0)(LOGSTDOUT, "[DEBUG] tasks_handshake_shutdown: "
                                              "close sockfd %d\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));
        csocket_cnode_close(csocket_cnode);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
