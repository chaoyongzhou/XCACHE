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

/*-------- self-discovery of service based on udp multicast --------*/

#ifndef _CSDISC_H
#define _CSDISC_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>

#include "type.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"

#define CSDISC_MCAST_FLAG_BIND_NIC            ((uint32_t)0x0001)
#define CSDISC_MCAST_FLAG_REUSE_ADDR          ((uint32_t)0x0002)
#define CSDISC_MCAST_FLAG_ENABALE_LOOP        ((uint32_t)0x0004)
#define CSDISC_MCAST_FLAG_JOIN_MEMBERSHIP     ((uint32_t)0x0008)
#define CSDISC_MCAST_FLAG_BIND_IP_PORT        ((uint32_t)0x0010)
#define CSDISC_MCAST_FLAG_NONBLOCK            ((uint32_t)0x0020)

#define CSDISC_MCAST_PACKET_MAX_SIZE          ((uint32_t)1024)

typedef struct
{
    CSTRING             mcast_eth_name;     /*nic name*/
    UINT32              mcast_ipaddr;       /*mcast ipaddr*/
    UINT32              mcast_port;         /*mcast port*/

    uint32_t            mcast_flags;        /*udp socket setting flags*/
    int                 mcast_sockfd;       /*udp socket*/

    struct sockaddr_in  mcast_sockaddr;     /*used by sender*/
    socklen_t           mcast_socklen;      /*used by sender*/
    uint32_t            rsvd01;

    CLIST               sender_list;        /*item is CSDISC_SENDER*/
    CLIST               recver_list;        /*item is CSDISC_RECVER*/
}CSDISC_NODE;

#define CSDISC_NODE_MCAST_ETH_NAME(csdisc_node)          (&((csdisc_node)->mcast_eth_name))
#define CSDISC_NODE_MCAST_IPADDR(csdisc_node)            ((csdisc_node)->mcast_ipaddr)
#define CSDISC_NODE_MCAST_PORT(csdisc_node)              ((csdisc_node)->mcast_port)
#define CSDISC_NODE_MCAST_FLAGS(csdisc_node)             ((csdisc_node)->mcast_flags)
#define CSDISC_NODE_MCAST_SOCKFD(csdisc_node)            ((csdisc_node)->mcast_sockfd)
#define CSDISC_NODE_MCAST_SOCKADDR(csdisc_node)          (&((csdisc_node)->mcast_sockaddr))
#define CSDISC_NODE_MCAST_SOCKLEN(csdisc_node)           ((csdisc_node)->mcast_socklen)
#define CSDISC_NODE_MCAST_SENDER_LIST(csdisc_node)       (&((csdisc_node)->sender_list))
#define CSDISC_NODE_MCAST_RECVER_LIST(csdisc_node)       (&((csdisc_node)->recver_list))

typedef EC_BOOL (*CSDISC_SENDER_FUNC)(void *, CSDISC_NODE *);

typedef struct
{
    void                    *obj;
    CSDISC_SENDER_FUNC       func;
}CSDISC_SENDER;

#define CSDISC_SENDER_OBJ(csdisc_sender)                  ((csdisc_sender)->obj)
#define CSDISC_SENDER_FUNC(csdisc_sender)                 ((csdisc_sender)->func)

typedef EC_BOOL (*CSDISC_RECVER_FUNC)(void *, CSDISC_NODE *);

typedef struct
{
    void                    *obj;
    CSDISC_RECVER_FUNC       func;
}CSDISC_RECVER;

#define CSDISC_RECVER_OBJ(csdisc_recver)                  ((csdisc_recver)->obj)
#define CSDISC_RECVER_FUNC(csdisc_recver)                 ((csdisc_recver)->func)

CSDISC_SENDER *csdisc_sender_new();

EC_BOOL csdisc_sender_init(CSDISC_SENDER *csdisc_sender);

EC_BOOL csdisc_sender_clean(CSDISC_SENDER *csdisc_sender);

EC_BOOL csdisc_sender_free(CSDISC_SENDER *csdisc_sender);

CSDISC_RECVER *csdisc_recver_new();

EC_BOOL csdisc_recver_init(CSDISC_RECVER *csdisc_recver);

EC_BOOL csdisc_recver_clean(CSDISC_RECVER *csdisc_recver);

EC_BOOL csdisc_recver_free(CSDISC_RECVER *csdisc_recver);

CSDISC_NODE *csdisc_node_new();

EC_BOOL csdisc_node_init(CSDISC_NODE *csdisc_node);

EC_BOOL csdisc_node_clean(CSDISC_NODE *csdisc_node);

EC_BOOL csdisc_node_free(CSDISC_NODE *csdisc_node);

EC_BOOL csdisc_node_set_flags(CSDISC_NODE *csdisc_node, const uint32_t flags);

CSDISC_NODE *csdisc_node_make(const CSTRING *mcast_eth_name,
                                    const UINT32   mcast_ipaddr,
                                    const UINT32   mcast_port,
                                    const uint32_t mcast_flags);

/*push back*/
EC_BOOL csdisc_node_push_sender(CSDISC_NODE *csdisc_node, CSDISC_SENDER_FUNC func, void *obj);

/*push back*/
EC_BOOL csdisc_node_push_recver(CSDISC_NODE *csdisc_node, CSDISC_RECVER_FUNC func, void *obj);

EC_BOOL csdisc_node_walk_sender(CSDISC_NODE *csdisc_node);

EC_BOOL csdisc_node_walk_recver(CSDISC_NODE *csdisc_node);

EC_BOOL csdisc_node_send_packet(CSDISC_NODE *csdisc_node,
                                        const uint8_t *packet_data,
                                        const uint32_t packet_len);

EC_BOOL csdisc_node_recv_packet(CSDISC_NODE *csdisc_node,
                                        uint8_t *packet_data,
                                        const uint32_t packet_max_len,
                                        uint32_t *packet_len);

EC_BOOL csdisc_node_send(CSDISC_NODE *csdisc_node);

EC_BOOL csdisc_node_recv(CSDISC_NODE *csdisc_node);

CSDISC_NODE *csdisc_node_start(const CSTRING *mcast_eth_name,
                                    const UINT32  mcast_ipaddr,
                                    const UINT32  mcast_port);

EC_BOOL csdisc_node_end(CSDISC_NODE *csdisc_node);


#endif/*_CSDISC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
