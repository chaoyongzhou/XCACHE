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

#ifndef _CSOCKET_INC
#define _CSOCKET_INC

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "type.h"
#include "cstring.h"
#include "crbuff.h"
#include "cbuffer.h"
#include "cbytes.h"
#include "task.inc"

#include "crb.h"

#include "taskcfg.h"
#include "taskcfg.inc"
#include "mod.inc"

#include "ccallback.h"

#ifdef __APPLE__
#include <netinet/tcp_fsm.h>
#define CSOCKET_TCP_ESTABLISHED         TCPS_ESTABLISHED
#define CSOCKET_TCP_SYN_SENT            TCPS_SYN_SENT
#define CSOCKET_TCP_SYN_RECV            TCPS_SYN_RECEIVED
#define CSOCKET_TCP_FIN_WAIT1           TCPS_FIN_WAIT_1
#define CSOCKET_TCP_FIN_WAIT2           TCPS_FIN_WAIT_2
#define CSOCKET_TCP_TIME_WAIT           TCPS_TIME_WAIT
#define CSOCKET_TCP_CLOSE               TCPS_CLOSED
#define CSOCKET_TCP_CLOSE_WAIT          TCPS_CLOSE_WAIT
#define CSOCKET_TCP_LAST_ACK            TCPS_LAST_ACK
#define CSOCKET_TCP_LISTEN              TCPS_LISTEN
#define CSOCKET_TCP_CLOSING             TCPS_CLOSING

#define CSOCKET_TCP_INFO                TCP_CONNECTION_INFO

typedef struct tcp_connection_info      CSOCKET_TCPI;

#define CSOCKET_SOL_SOCKET              SOL_SOCKET
#define CSOCKET_SOL_TCP                 SOL_SOCKET

#define CSOCKET_TCP_KEEPIDLE            TCP_KEEPALIVE

/*--- same part ---*/
#define CSOCKET_TCP_NODELAY             TCP_NODELAY
#define CSOCKET_SO_LINGER               SO_LINGER
#define CSOCKET_TCP_KEEPINTVL           TCP_KEEPINTVL
#define CSOCKET_TCP_KEEPCNT             TCP_KEEPCNT
#define CSOCKET_SO_KEEPALIVE            SO_KEEPALIVE
#define CSOCKET_SO_REUSEADDR            SO_REUSEADDR
#define CSOCKET_SO_BINDTODEVICE         SO_BINDTODEVICE
#define CSOCKET_SO_SNDTIMEO             SO_SNDTIMEO
#define CSOCKET_SO_RCVTIMEO             SO_RCVTIMEO
#define CSOCKET_SO_RCVLOWAT             SO_RCVLOWAT
#define CSOCKET_SO_SNDLOWAT             SO_SNDLOWAT
#define CSOCKET_SO_REUSEPORT            SO_REUSEPORT
#define CSOCKET_SO_SNDBUF               SO_SNDBUF
#define CSOCKET_SO_RCVBUF               SO_RCVBUF
#define CSOCKET_SO_BROADCAST            SO_BROADCAST
#define CSOCKET_SO_ERROR                SO_ERROR
#define CSOCKET_IPPROTO_TCP             IPPROTO_TCP
#define CSOCKET_IPPROTO_IP              IPPROTO_IP
#define CSOCKET_IP_MULTICAST_LOOP       IP_MULTICAST_LOOP
#define CSOCKET_IP_ADD_MEMBERSHIP       IP_ADD_MEMBERSHIP
#define CSOCKET_IP_DROP_MEMBERSHIP      IP_DROP_MEMBERSHIP

#endif /*__APPLE__*/

#ifdef __linux__
#define CSOCKET_TCP_ESTABLISHED         TCP_ESTABLISHED
#define CSOCKET_TCP_SYN_SENT            TCP_SYN_SENT
#define CSOCKET_TCP_SYN_RECV            TCP_SYN_RECV
#define CSOCKET_TCP_FIN_WAIT1           TCP_FIN_WAIT1
#define CSOCKET_TCP_FIN_WAIT2           TCP_FIN_WAIT2
#define CSOCKET_TCP_TIME_WAIT           TCP_TIME_WAIT
#define CSOCKET_TCP_CLOSE               TCP_CLOSE
#define CSOCKET_TCP_CLOSE_WAIT          TCP_CLOSE_WAIT
#define CSOCKET_TCP_LAST_ACK            TCP_LAST_ACK
#define CSOCKET_TCP_LISTEN              TCP_LISTEN
#define CSOCKET_TCP_CLOSING             TCP_CLOSING

#define CSOCKET_TCP_INFO                TCP_INFO

typedef struct tcp_info                 CSOCKET_TCPI;

#define CSOCKET_SOL_SOCKET              SOL_SOCKET
#define CSOCKET_SOL_TCP                 SOL_TCP

#define CSOCKET_TCP_KEEPIDLE            TCP_KEEPIDLE

/*--- same part ---*/
#define CSOCKET_TCP_NODELAY             TCP_NODELAY
#define CSOCKET_SO_LINGER               SO_LINGER
#define CSOCKET_TCP_KEEPINTVL           TCP_KEEPINTVL
#define CSOCKET_TCP_KEEPCNT             TCP_KEEPCNT
#define CSOCKET_SO_KEEPALIVE            SO_KEEPALIVE
#define CSOCKET_SO_REUSEADDR            SO_REUSEADDR
#define CSOCKET_SO_BINDTODEVICE         SO_BINDTODEVICE
#define CSOCKET_SO_SNDTIMEO             SO_SNDTIMEO
#define CSOCKET_SO_RCVTIMEO             SO_RCVTIMEO
#define CSOCKET_SO_RCVLOWAT             SO_RCVLOWAT
#define CSOCKET_SO_SNDLOWAT             SO_SNDLOWAT
#define CSOCKET_SO_REUSEPORT            SO_REUSEPORT
#define CSOCKET_SO_SNDBUF               SO_SNDBUF
#define CSOCKET_SO_RCVBUF               SO_RCVBUF
#define CSOCKET_SO_BROADCAST            SO_BROADCAST
#define CSOCKET_SO_ERROR                SO_ERROR
#define CSOCKET_IPPROTO_TCP             IPPROTO_TCP
#define CSOCKET_IPPROTO_IP              IPPROTO_IP
#define CSOCKET_IP_MULTICAST_LOOP       IP_MULTICAST_LOOP
#define CSOCKET_IP_ADD_MEMBERSHIP       IP_ADD_MEMBERSHIP
#define CSOCKET_IP_DROP_MEMBERSHIP      IP_DROP_MEMBERSHIP
#endif /*__linux__*/


#define CSOCKET_TYPE_ERR                 ((uint32_t)0x00)
#define CSOCKET_TYPE_TCP                 ((uint32_t)0x01)
#define CSOCKET_TYPE_UDP                 ((uint32_t)0x02)

#define CSOCKET_BUFF_MAX_LEN             ((UINT32)(1 << 30)) /*1 GB*/

#define CSOCKET_BACKLOG                  (81920) /*SOMAXCONN = 128 is a system default constant*/

/*note: CSOCKET_CNODE_XCHG_TASKC_NODE = CSOCKET_CNODE_SENT_TASKC_NODE | CSOCKET_CNODE_RCVD_TASKC_NODE*/
#define CSOCKET_CNODE_NONA_TASKC_NODE       ((UINT32) 0)
#define CSOCKET_CNODE_SENT_TASKC_NODE       ((UINT32) 1)
#define CSOCKET_CNODE_RCVD_TASKC_NODE       ((UINT32) 2)
#define CSOCKET_CNODE_XCHG_TASKC_NODE       ((UINT32) 3)

#define CSOCKET_CNODE_PKT_HDR_SIZE          ((UINT32)32)

#define CSOCKET_IS_BLOCK_MODE               ((UINT32) 1)
#define CSOCKET_IS_NONBLOCK_MODE            ((UINT32) 2)

#define CSOCKET_READING_FLAG                ((UINT32) 1)
#define CSOCKET_WRITING_FLAG                ((UINT32) 2)

#define CSOCKET_UDP_PACKET_DATA_SIZE        ((uint16_t)256)/*256 bytes*/
#define CSOCKET_UDP_PACKET_HEADER_SIZE      (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t))


typedef struct _CSOCKET_CNODE
{
    UINT32              ipaddr;
    UINT32              srvport;
    UINT32              tcid;
    UINT32              comm;
    UINT32              size;
    int                 sockfd;
    uint32_t            type:16;
    uint32_t            unix_domain:1; /*unix domain socket*/
    uint32_t            is_used:1;
    uint32_t            writing:1;
    uint32_t            reading:1;
    uint32_t            reusing:1;/*re-use*/
    uint32_t            closing:1;/*if closing = 1, reusing would be ignore*/
    uint32_t            pending:1;/*wait resume*/
    uint32_t            looping:1;/*timeout looping*/
    uint32_t            nonblock:1;
    uint32_t            rsvd   :7;

    UINT32              client_ipaddr;
    UINT32              client_port;

    UINT32              send_once_max_size;
    UINT32              recv_once_max_size;

    /*the status to exchange taskc_node with remote*/
    UINT32              status; /*counter for monitor client up to 2: send local taskc_node info to remote, recv remote taskc_node info from remote*/

    UINT32              load;  /*load in sending direction*/

    union
    {
        struct
        {
            UINT8       pkt_hdr[CSOCKET_CNODE_PKT_HDR_SIZE];
            UINT32      pkt_pos;/*when pos reaches csocket_encode_actual_size, header is ready*/
        }pkt;

        struct
        {
            void       *ptr;
            UINT32      modi;
        }ext;
    }u;

    void               *recving_task_node;/*be incoming data*/
    void               *sending_task_node;/*be sending data*/

    CCALLBACK_LIST      recv_callback_list;    /*after data recv complete*/
    CCALLBACK_LIST      send_callback_list;    /*after data sent complete*/
    CCALLBACK_LIST      complete_callback_list;/*after procedure complete*/
    CCALLBACK_LIST      close_callback_list;   /*before connection close*/
    CCALLBACK_LIST      shutdown_callback_list;/*before connection shutdown (force close)*/
    CCALLBACK_LIST      timeout_callback_list; /*when connection timeout*/
}CSOCKET_CNODE;

#define CSOCKET_CNODE_IPADDR(csocket_cnode)                  ((csocket_cnode)->ipaddr)
#define CSOCKET_CNODE_SRVPORT(csocket_cnode)                 ((csocket_cnode)->srvport)
#define CSOCKET_CNODE_TCID(csocket_cnode)                    ((csocket_cnode)->tcid)
#define CSOCKET_CNODE_TCID_STR(csocket_cnode)                (c_word_to_ipv4(CSOCKET_CNODE_TCID(csocket_cnode)))
#define CSOCKET_CNODE_COMM(csocket_cnode)                    ((csocket_cnode)->comm)
#define CSOCKET_CNODE_SIZE(csocket_cnode)                    ((csocket_cnode)->size)
#define CSOCKET_CNODE_SOCKFD(csocket_cnode)                  ((csocket_cnode)->sockfd)
#define CSOCKET_CNODE_TYPE(csocket_cnode)                    ((csocket_cnode)->type)
#define CSOCKET_CNODE_UNIX(csocket_cnode)                    ((csocket_cnode)->unix_domain)

#define CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode)           ((csocket_cnode)->client_ipaddr)
#define CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)             ((csocket_cnode)->client_port)

#define CSOCKET_CNODE_IS_USED(csocket_cnode)                 ((csocket_cnode)->is_used)
#define CSOCKET_CNODE_WRITING(csocket_cnode)                 ((csocket_cnode)->writing)
#define CSOCKET_CNODE_READING(csocket_cnode)                 ((csocket_cnode)->reading)
#define CSOCKET_CNODE_REUSING(csocket_cnode)                 ((csocket_cnode)->reusing)
#define CSOCKET_CNODE_CLOSING(csocket_cnode)                 ((csocket_cnode)->closing)
#define CSOCKET_CNODE_PENDING(csocket_cnode)                 ((csocket_cnode)->pending)
#define CSOCKET_CNODE_LOOPING(csocket_cnode)                 ((csocket_cnode)->looping)

#define CSOCKET_CNODE_NONBLOCK(csocket_cnode)                ((csocket_cnode)->nonblock)

#define CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode)      ((csocket_cnode)->send_once_max_size)
#define CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode)      ((csocket_cnode)->recv_once_max_size)

#define CSOCKET_CNODE_STATUS(csocket_cnode)                  ((csocket_cnode)->status)
#define CSOCKET_CNODE_RETRIES(csocket_cnode)                 ((csocket_cnode)->status)/*reuse status field*/

#define CSOCKET_CNODE_LOAD(csocket_cnode)                    ((csocket_cnode)->load)

#define CSOCKET_CNODE_IPADDR_STR(csocket_cnode)              (c_word_to_ipv4(CSOCKET_CNODE_IPADDR(csocket_cnode)))
#define CSOCKET_CNODE_PKT_HDR(csocket_cnode)                 ((csocket_cnode)->u.pkt.pkt_hdr)
#define CSOCKET_CNODE_PKT_HDR_BYTE(csocket_cnode, pos)       ((csocket_cnode)->u.pkt.pkt_hdr[pos])
#define CSOCKET_CNODE_PKT_POS(csocket_cnode)                 ((csocket_cnode)->u.pkt.pkt_pos)
#define CSOCKET_CNODE_PTR(csocket_cnode)                     ((csocket_cnode)->u.ext.ptr)
#define CSOCKET_CNODE_MODI(csocket_cnode)                    ((csocket_cnode)->u.ext.modi)

#define CSOCKET_CNODE_RECVING_TASK_NODE(csocket_cnode)       ((csocket_cnode)->recving_task_node)
#define CSOCKET_CNODE_SENDING_TASK_NODE(csocket_cnode)       ((csocket_cnode)->sending_task_node)

#define CSOCKET_CNODE_RECV_CALLBACK_LIST(csocket_cnode)      (&((csocket_cnode)->recv_callback_list))
#define CSOCKET_CNODE_SEND_CALLBACK_LIST(csocket_cnode)      (&((csocket_cnode)->send_callback_list))
#define CSOCKET_CNODE_COMPLETE_CALLBACK_LIST(csocket_cnode)  (&((csocket_cnode)->complete_callback_list))
#define CSOCKET_CNODE_CLOSE_CALLBACK_LIST(csocket_cnode)     (&((csocket_cnode)->close_callback_list))
#define CSOCKET_CNODE_SHUTDOWN_CALLBACK_LIST(csocket_cnode)  (&((csocket_cnode)->shutdown_callback_list))
#define CSOCKET_CNODE_TIMEOUT_CALLBACK_LIST(csocket_cnode)   (&((csocket_cnode)->timeout_callback_list))

#define CSOCKET_CNODE_SET_DISCONNECTED(csocket_cnode)        ((csocket_cnode)->rsvd = 1)
#define CSOCKET_CNODE_SET_CONNECTED(csocket_cnode)           ((csocket_cnode)->rsvd = 0)

#define CSOCKET_CNODE_IS_CONNECTED(csocket_cnode)            (0 == (csocket_cnode)->rsvd? EC_TRUE : EC_FALSE)

//typedef EC_BOOL (*CSOCKET_CNODE_SETUP_CALLBACK)(UINT32 data, CSOCKET_CNODE *csocket_cnode);
typedef EC_BOOL (*CSOCKET_CNODE_RECV_CALLBACK)(UINT32 data, CSOCKET_CNODE *csocket_cnode);
typedef EC_BOOL (*CSOCKET_CNODE_SEND_CALLBACK)(UINT32 data, CSOCKET_CNODE *csocket_cnode);
typedef EC_BOOL (*CSOCKET_CNODE_COMPLETE_CALLBACK)(UINT32 data, CSOCKET_CNODE *csocket_cnode);
typedef EC_BOOL (*CSOCKET_CNODE_CLOSE_CALLBACK)(UINT32 data, CSOCKET_CNODE *csocket_cnode);
typedef EC_BOOL (*CSOCKET_CNODE_SHUTDOWN_CALLBACK)(UINT32 data, CSOCKET_CNODE *csocket_cnode);
typedef EC_BOOL (*CSOCKET_CNODE_TIMEOUT_CALLBACK)(UINT32 data, CSOCKET_CNODE *csocket_cnode);

#endif/*_CSOCKET_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

