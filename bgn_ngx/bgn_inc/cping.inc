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

#ifndef _CPING_INC
#define _CPING_INC

#include "type.h"
#include "log.h"

#include "croutine.h"

#include "csocket.inc"

typedef struct
{
    UINT32                    srv_ipaddr;
    UINT32                    srv_port;

    uint32_t                  complete:1;
    uint32_t                  rsvd01:31;
    uint32_t                  rsvd02;

    CSOCKET_CNODE            *csocket_cnode;

    CROUTINE_COND            *croutine_cond;/*croutine condition lock, used when trigger ping request */

    uint32_t                  s_nsec; /*start time in second*/
    uint32_t                  s_msec; /*start time in micro-second*/

    uint32_t                  e_nsec; /*end time in second*/
    uint32_t                  e_msec; /*end time in micro-second*/      
}CPING_NODE;

#define CPING_NODE_SRV_IPADDR(cping_node)               ((cping_node)->srv_ipaddr)
#define CPING_NODE_SRV_PORT(cping_node)                 ((cping_node)->srv_port)

#define CPING_NODE_COMPLETE_FLAG(cping_node)            ((cping_node)->complete)

#define CPING_NODE_CSOCKET_CNODE(cping_node)            ((cping_node)->csocket_cnode)

#define CPING_NODE_CROUTINE_COND(cping_node)            ((cping_node)->croutine_cond)

#define CPING_NODE_S_NSEC(cping_node)                   ((cping_node)->s_nsec)
#define CPING_NODE_S_MSEC(cping_node)                   ((cping_node)->s_msec)

#define CPING_NODE_E_NSEC(cping_node)                   ((cping_node)->e_nsec)
#define CPING_NODE_E_MSEC(cping_node)                   ((cping_node)->e_msec)

#define CPING_NODE_SRV_IPADDR_STR(cping_node)           (c_word_to_ipv4(CPING_NODE_SRV_IPADDR(cping_node)))

#define CPING_NODE_REQ_TIME_WHEN_START(cping_node) do{                                       \
    CPING_NODE_S_NSEC(cping_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CPING_NODE_S_MSEC(cping_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)

#define CPING_NODE_REQ_TIME_WHEN_END(cping_node) do{                                         \
    CPING_NODE_E_NSEC(cping_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CPING_NODE_E_MSEC(cping_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)

#define CPING_NODE_REQ_ELAPSED_MSEC(cping_node)                                              \
    ((uint32_t)((CPING_NODE_E_NSEC(cping_node) - CPING_NODE_S_NSEC(cping_node)) * 1000 + CPING_NODE_E_MSEC(cping_node) - CPING_NODE_S_MSEC(cping_node)))

#endif /*_CPING_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
