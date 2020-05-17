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

#ifndef _TASKCFG_INC
#define _TASKCFG_INC

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "type.h"
#include "clist.h"
#include "cstring.h"
#include "cvector.h"
#include "crouter.inc"
#include "ccallback.h"


typedef fd_set FD_CSET;

#define SOCKFD_SET(fd_cset) (fd_cset)

#define BITS_TO_MASK(nbits)  (0 == (nbits)? 0 : ((0xffffffff) << (32 - (nbits))))

#define TASKS_CFG_DEFAULT_MASKI     ((UINT32) 32)
#define TASKS_CFG_DEFAULT_MASKE     ((UINT32) 16)

/*des_tcid belong to intranet of src_tcid: src & maski(src) == des & maski(src)*/
#define DES_TCID_IS_INTRANET(src_tcid, src_maski, des_tcid, des_maske) (((src_tcid) & (src_maski)) == ((des_tcid) & (des_maske)))

/*des_tcid belong to lannet of src_tcid: src & maske(src) == des & maske(des)*/
#define DES_TCID_IS_LANNET(src_tcid, src_maske, des_tcid, des_maske) (((src_tcid) & (src_maske)) == ((des_tcid) & (des_maske)))

/*des_tcid belong to extranet of src_tcid: src & maske(src) == des & maske(src)*/
#define DES_TCID_IS_EXTERNET(src_tcid, src_maske, des_tcid, des_maski) (((src_tcid) & (src_maske)) == ((des_tcid) & (des_maski)))

typedef struct
{
    UINT32                         srv_ipaddr;
    UINT32                         srv_port;

    UINT32                         srv_tcid;
}TASKS_SRV;

#define TASKS_SRV_IPADDR(tasks_srv)       ((tasks_srv)->srv_ipaddr)
#define TASKS_SRV_PORT(tasks_srv)         ((tasks_srv)->srv_port)
#define TASKS_SRV_TCID(tasks_srv)         ((tasks_srv)->srv_tcid)

/*remote task server node*/
typedef struct
{
    UINT32      srvipaddr;   /*remote tasks node srv ipaddr*/
    UINT32      srvport;     /*remote tasks node srv port*/
    UINT32      tcid;        /*remote tasks node tcid*/
    UINT32      comm;        /*remote tasks node communicator*/
    UINT32      size;        /*remote tasks node communicator size*/

    UINT32      load;        /*load of sending direction*/

    uint32_t    used:1;
    uint32_t    rsvd01 :31;
    uint32_t    rsvd02;

    CTIMET      last_update_time;   /*last update time. update when send or recv heartbeat successfully*/
    CTIMET      last_send_time;     /*last send heartbeat time*/

    CVECTOR     csocket_cnode_vec;/*csocket cnodes connecting to remote tasks node*/

    CLIST       sending_list;   /*be sending data. item is TASK_NODE, mount only*//*FIFO*/
}TASKS_NODE;

#define TASKS_NODE_SRVIPADDR(tasks_node)                    ((tasks_node)->srvipaddr)
#define TASKS_NODE_SRVIPADDR_STR(tasks_node)                (c_word_to_ipv4(TASKS_NODE_SRVIPADDR(tasks_node)))
#define TASKS_NODE_SRVPORT(tasks_node)                      ((tasks_node)->srvport)
#define TASKS_NODE_TCID(tasks_node)                         ((tasks_node)->tcid)
#define TASKS_NODE_TCID_STR(tasks_node)                     (c_word_to_ipv4(TASKS_NODE_TCID(tasks_node)))
#define TASKS_NODE_COMM(tasks_node)                         ((tasks_node)->comm)
#define TASKS_NODE_SIZE(tasks_node)                         ((tasks_node)->size)
#define TASKS_NODE_LOAD(tasks_node)                         ((tasks_node)->load)
#define TASKS_NODE_USED(tasks_node)                         ((tasks_node)->used)
#define TASKS_NODE_LAST_UPDATE_TIME(tasks_node)             (((tasks_node)->last_update_time))
#define TASKS_NODE_LAST_SEND_TIME(tasks_node)               (((tasks_node)->last_send_time))
#define TASKS_NODE_CSOCKET_CNODE_VEC(tasks_node)            (&((tasks_node)->csocket_cnode_vec))
#define TASKS_NODE_SENDING_LIST(tasks_node)                 (&((tasks_node)->sending_list))

typedef EC_BOOL (*TASKS_WORKER_ADD_CALLBACK)(const UINT32 modi, TASKS_NODE *tasks_node);/*call when add a worker (csocket_cnode -> tasks_node)*/
typedef EC_BOOL (*TASKS_WORKER_DEL_CALLBACK)(const UINT32 modi, TASKS_NODE *tasks_node);/*call when del a worker (csocket_cnode -> tasks_node)*/

typedef struct
{
    CVECTOR                  tasks_nodes;   /*item is TASKS_NODE*/

    /*call back interface*/
    CCALLBACK_LIST           add_callback_list;
    CCALLBACK_LIST           del_callback_list;
}TASKS_WORKER;

#define TASKS_WORKER_NODES(tasks_worker)                 (&((tasks_worker)->tasks_nodes))
#define TASKS_WORKER_ADD_CALLBACK_LIST(tasks_worker)     (&((tasks_worker)->add_callback_list))
#define TASKS_WORKER_DEL_CALLBACK_LIST(tasks_worker)     (&((tasks_worker)->del_callback_list))

typedef EC_BOOL (*TASKS_MONITOR_ADD_CALLBACK)(const UINT32 modi, TASKS_NODE *tasks_node);/*call when add a monitor (csocket_cnode -> tasks_node)*/
typedef EC_BOOL (*TASKS_MONITOR_DEL_CALLBACK)(const UINT32 modi, TASKS_NODE *tasks_node);/*call when del a monitor (csocket_cnode -> tasks_node)*/


typedef struct
{
    CVECTOR  tasks_nodes;   /*item is TASKS_NODE*/

    /*call back interface*/
    CCALLBACK_LIST           add_callback_list;
    CCALLBACK_LIST           del_callback_list;
}TASKS_MONITOR;

#define TASKS_MONITOR_NODES(tasks_monitor)               (&((tasks_monitor)->tasks_nodes))
#define TASKS_MONITOR_ADD_CALLBACK_LIST(tasks_monitor)   (&((tasks_monitor)->add_callback_list))
#define TASKS_MONITOR_DEL_CALLBACK_LIST(tasks_monitor)   (&((tasks_monitor)->del_callback_list))

/*TASK SERVER CONFIG*/
typedef struct
{
    UINT32          tcid;         /*taskcomm id*/
    UINT32          maski;        /*taskcomm mask for internal network,including sub network(sons) and LAN network(brothers)*/
    UINT32          maske;        /*taskcomm mask for external network,including upper network(parent)*/

    UINT32          srvipaddr;    /*taskcomm srv ipaddr, for local or remote*/
    UINT32          srvport;      /*taskcomm srv port  , for local or remote*/

    UINT32          csrvport;     /*when valid, will start csrv on it*/
    CVECTOR         cluster_vec;  /*belong to these clusters, item is cluster id (UINT32)*/

    UINT32          ssrvport;     /*when valid, will start https on it: ssl server*/

    int             srvsockfd;    /*[ONLY FOR LOCAL TASKS CFG] local taskcomm srv listening sockfd */
    int             rsvd;

    TASKS_WORKER    tasks_worker; /*[ONLY FOR LOCAL TASKS CFG] working clients: remote taskcomm connection to local taskcomm : tasks_node vector  */
    TASKS_MONITOR   tasks_monitor;/*[ONLY FOR LOCAL TASKS CFG] monitoring clients: remote taskcomm connection to local taskcomm: csocket_cnode vector*/

    CVECTOR  taskr_cfg_vec;
}TASKS_CFG;

#define TASKS_CFG_TCID(tasks_cfg)                  ((tasks_cfg)->tcid)
#define TASKS_CFG_TCID_STR(tasks_cfg)              (c_word_to_ipv4(TASKS_CFG_TCID(tasks_cfg)))
#define TASKS_CFG_MASKI(tasks_cfg)                 ((tasks_cfg)->maski)
#define TASKS_CFG_MASKI_STR(tasks_cfg)             (c_word_to_ipv4(TASKS_CFG_MASKI(tasks_cfg)))
#define TASKS_CFG_MASKE(tasks_cfg)                 ((tasks_cfg)->maske)
#define TASKS_CFG_MASKE_STR(tasks_cfg)             (c_word_to_ipv4(TASKS_CFG_MASKE(tasks_cfg)))
#define TASKS_CFG_SRVIPADDR(tasks_cfg)             ((tasks_cfg)->srvipaddr)
#define TASKS_CFG_SRVIPADDR_STR(tasks_cfg)         (c_word_to_ipv4(TASKS_CFG_SRVIPADDR(tasks_cfg)))
#define TASKS_CFG_SRVPORT(tasks_cfg)               ((tasks_cfg)->srvport)
#define TASKS_CFG_CSRVPORT(tasks_cfg)              ((tasks_cfg)->csrvport)
#define TASKS_CFG_SSRVPORT(tasks_cfg)              ((tasks_cfg)->ssrvport)
#define TASKS_CFG_CLUSTER_VEC(tasks_cfg)           (&((tasks_cfg)->cluster_vec))

#define TASKS_CFG_SRVSOCKFD(tasks_cfg)             ((tasks_cfg)->srvsockfd)
#define TASKS_CFG_WORKER(tasks_cfg)                (&((tasks_cfg)->tasks_worker))
#define TASKS_CFG_MONITOR(tasks_cfg)               (&((tasks_cfg)->tasks_monitor))

#define TASKS_CFG_TASKR_CFG_VEC(tasks_cfg)         (&(tasks_cfg->taskr_cfg_vec))

#define TASKS_WORK_BASE_TASKS_CFG_ENTRY(tasks_worker_ptr) \
    ((TASKS_CFG *)((char *)(tasks_worker_ptr)-(unsigned long)(&((TASKS_CFG *)0)->tasks_worker)))


/*TASK ROUTE CONFIG*/
typedef struct
{
    UINT32  des_tcid;        /*des remote taskcomm id   */
    UINT32  maskr;           /*route mask               */
    UINT32  next_tcid;       /*next remote taskcomm id  */
}TASKR_CFG;

#define TASKR_CFG_DES_TCID(taskr_cfg)              ((taskr_cfg)->des_tcid)
#define TASKR_CFG_DES_TCID_STR(taskr_cfg)          (c_word_to_ipv4(TASKR_CFG_DES_TCID(taskr_cfg)))
#define TASKR_CFG_NEXT_TCID(taskr_cfg)             ((taskr_cfg)->next_tcid)
#define TASKR_CFG_NEXT_TCID_STR(taskr_cfg)         (c_word_to_ipv4(TASKR_CFG_NEXT_TCID(taskr_cfg)))
#define TASKR_CFG_MASKR(taskr_cfg)                 ((taskr_cfg)->maskr)
#define TASKR_CFG_MASKR_STR(taskr_cfg)             (c_word_to_ipv4(TASKR_CFG_MASKR(taskr_cfg)))

/*TASK CONFIG*/
typedef struct
{
    UINT32   default_tasks_port;/*default server port for all tasks_cfg*/
    CVECTOR  tasks_cfg_vec;/*item type is TASKS_CFG*/
}TASK_CFG;

#define TASK_CFG_DEFAULT_TASKS_PORT(task_cfg)      ((task_cfg)->default_tasks_port)
#define TASK_CFG_TASKS_CFG_VEC(task_cfg)           (&((task_cfg)->tasks_cfg_vec))

/*TASK COMM*/
typedef struct
{
    UINT32 tcid;
    UINT32 comm;
    UINT32 rank;

    UINT32 modi;
}TASKC_ADDR;

#define TASKC_ADDR_TCID(taskc_addr)            ((taskc_addr)->tcid)
#define TASKC_ADDR_COMM(taskc_addr)            ((taskc_addr)->comm)
#define TASKC_ADDR_RANK(taskc_addr)            ((taskc_addr)->rank)
#define TASKC_ADDR_MODI(taskc_addr)            ((taskc_addr)->modi)

#define SEND_TASKC_ADDR_TCID(send_taskc_addr)       (TASKC_ADDR_TCID(send_taskc_addr))
#define SEND_TASKC_ADDR_TCID_STR(send_taskc_addr)   (c_word_to_ipv4(SEND_TASKC_ADDR_TCID(send_taskc_addr)))
#define SEND_TASKC_ADDR_COMM(send_taskc_addr)       (TASKC_ADDR_COMM(send_taskc_addr))
#define SEND_TASKC_ADDR_RANK(send_taskc_addr)       (TASKC_ADDR_RANK(send_taskc_addr))
#define SEND_TASKC_ADDR_MODI(send_taskc_addr)       (TASKC_ADDR_MODI(send_taskc_addr))


#endif /*_TASKCFG_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

