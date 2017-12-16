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

#ifndef _CEPOLL_INC
#define _CEPOLL_INC

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/epoll.h>
#include <errno.h>

#include "type.h"
#include "csocket.inc"
#include "clist.h"
#include "crb.h"
#include "cmutex.h"
#include "cparacfg.inc"

#define CEPOLL_IN        ((uint32_t)0x00000001)
#define CEPOLL_PRI       ((uint32_t)0x00000002)
#define CEPOLL_OUT       ((uint32_t)0x00000004)
#define CEPOLL_RDNORM    ((uint32_t)0x00000040)
#define CEPOLL_RDBAND    ((uint32_t)0x00000080)
#define CEPOLL_WRNORM    ((uint32_t)0x00000100)
#define CEPOLL_WRBAND    ((uint32_t)0x00000200)
#define CEPOLL_MSG       ((uint32_t)0x00000400)
#define CEPOLL_ERR       ((uint32_t)0x00000008)
#define CEPOLL_HUP       ((uint32_t)0x00000010)

#if 0
#define CEPOLL_TIMEOUT   ((uint32_t)0x00010000)/*extension*/
#define CEPOLL_SHUTDOWN  ((uint32_t)0x00020000)/*extension*/
#endif

#define CEPOLL_ET        ((uint32_t)0x80000000)
#define CEPOLL_ONESHOT   ((uint32_t)0x40000000)

#define CEPOLL_CTL_ADD  ((int)1)
#define CEPOLL_CTL_DEL  ((int)2)
#define CEPOLL_CTL_MOD  ((int)3)

#define CEPOLL_RD_EVENT   (CEPOLL_IN)
#define CEPOLL_WR_EVENT   (CEPOLL_OUT)
#define CEPOLL_ERR_EVENT  (CEPOLL_ERR)
#define CEPOLL_HUP_EVENT  (CEPOLL_HUP)
#if 0
#define CEPOLL_TO_EVENT   (CEPOLL_TIMEOUT)
#define CEPOLL_SD_EVENT   (CEPOLL_SHUTDOWN)
#endif

#if 0
typedef union epoll_data
{
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

struct epoll_event
{
  uint32_t events;      /* Epoll events */
  epoll_data_t data;    /* User data variable */
} __attribute__ ((__packed__));
#endif
typedef epoll_data_t CEPOLL_DATA;
typedef struct epoll_event  CEPOLL_EVENT;

#if 0
typedef union {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} CEPOLL_DATA;


typedef struct
{
    uint32_t    events;         /* Epoll events/type */
    CEPOLL_DATA data;
}CEPOLL_EVENT;
#endif
#define CEPOLL_EVENT_TYPE(cepoll_event)      ((cepoll_event)->events)
#define CEPOLL_EVENT_FD(cepoll_event)        ((cepoll_event)->data.fd)

#define CEPOLL_MAX_FD_NUM  (819200)
//#define CEPOLL_MAX_FD_NUM  (344800)
//#define CEPOLL_MAX_FD_NUM  (2048)

#define CEPOLL_DIR_RD      ((UINT32) 0)
#define CEPOLL_DIR_WR      ((UINT32) 1)
#define CEPOLL_DIR_END     ((UINT32) 2)

#define CEPOLL_NODE_NOT_USED_FLAG      ((uint16_t) 0)
#define CEPOLL_NODE_IS_USED_FLAG       ((uint16_t) 1)

#define CRFSCHTTP_TIMEOUT_MAX_NUM      CONN_TIMEOUT_MAX_NUM_PER_LOOP


typedef EC_BOOL (*CEPOLL_EVENT_HANDLER)(void *);
typedef EC_BOOL (*CEPOLL_LOOP_HANDLER)(void *);

typedef struct
{
    uint32_t   events;
    uint32_t   timeout;/*timeout in second*/
    int        sockfd;
    uint16_t   used_flag;
    uint16_t   counter;/*counter to distinguish cepoll_node which are inserted at same time*/ 
    
    CTIMET     next_access_time;  /*next access in second*/
    
    CRB_NODE  *crb_node;

    const char          *rd_name;
    const char          *wr_name;
    const char          *timeout_name;
    const char          *shutdown_name;
    const char          *complete_name;
        
    void                *rd_arg;
    void                *wr_arg;
    void                *timeout_arg;
    void                *shutdown_arg;
    void                *complete_arg;

    CEPOLL_EVENT_HANDLER rd_handler;        /*triggered by read event*/    
    CEPOLL_EVENT_HANDLER wr_handler;        /*triggered by write event*/    
    CEPOLL_EVENT_HANDLER timeout_handler;   /*triggered by timeout*/
    CEPOLL_EVENT_HANDLER shutdown_handler;  /*triggered by error or exception*/
    CEPOLL_EVENT_HANDLER complete_handler;  /*triggered by done or complete succ*/
}CEPOLL_NODE;

#define CEPOLL_NODE_SOCKFD(cepoll_node)              ((cepoll_node)->sockfd)
#define CEPOLL_NODE_USED_FLAG(cepoll_node)           ((cepoll_node)->used_flag)
#define CEPOLL_NODE_EVENTS(cepoll_node)              ((cepoll_node)->events)
#define CEPOLL_NODE_NTIME_TS(cepoll_node)            ((cepoll_node)->next_access_time)
#define CEPOLL_NODE_TIMEOUT_NSEC(cepoll_node)        ((cepoll_node)->timeout)
#define CEPOLL_NODE_CRB_NODE(cepoll_node)            ((cepoll_node)->crb_node)
#define CEPOLL_NODE_COUNTER(cepoll_node)             ((cepoll_node)->counter)

#define CEPOLL_NODE_RD_NAME(cepoll_node)             ((cepoll_node)->rd_name)
#define CEPOLL_NODE_WR_NAME(cepoll_node)             ((cepoll_node)->wr_name)
#define CEPOLL_NODE_TIMEOUT_NAME(cepoll_node)        ((cepoll_node)->timeout_name)
#define CEPOLL_NODE_SHUTDOWN_NAME(cepoll_node)       ((cepoll_node)->shutdown_name)
#define CEPOLL_NODE_COMPLETE_NAME(cepoll_node)       ((cepoll_node)->complete_name)

#define CEPOLL_NODE_RD_ARG(cepoll_node)              ((cepoll_node)->rd_arg)
#define CEPOLL_NODE_WR_ARG(cepoll_node)              ((cepoll_node)->wr_arg)
#define CEPOLL_NODE_TIMEOUT_ARG(cepoll_node)         ((cepoll_node)->timeout_arg)
#define CEPOLL_NODE_SHUTDOWN_ARG(cepoll_node)        ((cepoll_node)->shutdown_arg)
#define CEPOLL_NODE_COMPLETE_ARG(cepoll_node)        ((cepoll_node)->complete_arg)

#define CEPOLL_NODE_RD_HANDLER(cepoll_node)          ((cepoll_node)->rd_handler)
#define CEPOLL_NODE_WR_HANDLER(cepoll_node)          ((cepoll_node)->wr_handler)
#define CEPOLL_NODE_TIMEOUT_HANDLER(cepoll_node)     ((cepoll_node)->timeout_handler)
#define CEPOLL_NODE_SHUTDOWN_HANDLER(cepoll_node)    ((cepoll_node)->shutdown_handler)
#define CEPOLL_NODE_COMPLETE_HANDLER(cepoll_node)    ((cepoll_node)->complete_handler)


typedef struct
{
    int                  epoll_fd;
    int                  epoll_event_num;/*max epoll event num*/    
    CEPOLL_EVENT        *epoll_event_tab;/*used by epoll*/
    CEPOLL_NODE         *epoll_node_tab; /*nodes table in array*/

    const char          *epoll_loop_name;
    CEPOLL_LOOP_HANDLER  epoll_loop_handler;
    void                *epoll_loop_arg;

    CMUTEX               cmutex;/*for epoll_timeout_tree*/

    uint16_t             counter;/*counter to distinguish cepoll_node which are inserted at same time*/ 
    uint8_t              rsvd[3];
    CRB_TREE             epoll_timeout_tree;/*timeout in order*/
}CEPOLL;

#define CEPOLL_FD(cepoll)                   ((cepoll)->epoll_fd)
#define CEPOLL_EVENT_NUM(cepoll)            ((cepoll)->epoll_event_num)
#define CEPOLL_EVENT_TAB(cepoll)            ((cepoll)->epoll_event_tab)
#define CEPOLL_NODE_TAB(cepoll)             ((cepoll)->epoll_node_tab)
#define CEPOLL_LOOP_NAME(cepoll)            ((cepoll)->epoll_loop_name)
#define CEPOLL_LOOP_HANDLER(cepoll)         ((cepoll)->epoll_loop_handler)
#define CEPOLL_LOOP_ARG(cepoll)             ((cepoll)->epoll_loop_arg)
#define CEPOLL_CMUTEX(cepoll)               (&((cepoll)->cmutex))
#define CEPOLL_COUNTER(cepoll)              ((cepoll)->counter)
#define CEPOLL_TIMEOUT_TREE(cepoll)         (&((cepoll)->epoll_timeout_tree))

#define CEPOLL_FETCH_EVENT(cepoll, pos)     (&((cepoll)->epoll_event_tab[ pos ]))
#define CEPOLL_FETCH_NODE(cepoll, fd)       (&((cepoll)->epoll_node_tab[ fd ]))


#define CEPOLL_INIT_LOCK(cepoll, location)  (cmutex_init(CEPOLL_CMUTEX(cepoll), CMUTEX_PROCESS_PRIVATE, location))
#define CEPOLL_CLEAN_LOCK(cepoll, location) (cmutex_clean(CEPOLL_CMUTEX(cepoll), location))
#define CEPOLL_LOCK(cepoll, location)       (cmutex_lock(CEPOLL_CMUTEX(cepoll), location))
#define CEPOLL_UNLOCK(cepoll, location)     (cmutex_unlock(CEPOLL_CMUTEX(cepoll), location))


#endif/*_CEPOLL_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
