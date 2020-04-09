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

#include "cmpic.inc"
#include "cstring.h"
#include "clist.h"

#include "csocket.h"

#include "csdisc.h"

/*-------- self-discovery of service based on udp multicast --------*/

CSDISC_SENDER *csdisc_sender_new()
{
    CSDISC_SENDER *csdisc_sender;

    alloc_static_mem(MM_CSDISC_SENDER, &csdisc_sender, LOC_CSDISC_0001);
    if(NULL_PTR == csdisc_sender)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_sender_new: new csdisc_sender failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csdisc_sender_init(csdisc_sender))
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_sender_new: init csdisc_sender failed\n");
        free_static_mem(MM_CSDISC_SENDER, csdisc_sender, LOC_CSDISC_0002);
        return (NULL_PTR);
    }

    return (csdisc_sender);
}

EC_BOOL csdisc_sender_init(CSDISC_SENDER *csdisc_sender)
{
    if(NULL_PTR != csdisc_sender)
    {
       CSDISC_SENDER_OBJ(csdisc_sender)  = NULL_PTR;
       CSDISC_SENDER_FUNC(csdisc_sender) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL csdisc_sender_clean(CSDISC_SENDER *csdisc_sender)
{
    if(NULL_PTR != csdisc_sender)
    {
       CSDISC_SENDER_OBJ(csdisc_sender)  = NULL_PTR;
       CSDISC_SENDER_FUNC(csdisc_sender) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL csdisc_sender_free(CSDISC_SENDER *csdisc_sender)
{
    if(NULL_PTR != csdisc_sender)
    {
        csdisc_sender_clean(csdisc_sender);
        free_static_mem(MM_CSDISC_SENDER, csdisc_sender, LOC_CSDISC_0003);
    }

    return (EC_TRUE);
}

CSDISC_RECVER *csdisc_recver_new()
{
    CSDISC_RECVER *csdisc_recver;

    alloc_static_mem(MM_CSDISC_RECVER, &csdisc_recver, LOC_CSDISC_0004);
    if(NULL_PTR == csdisc_recver)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_recver_new: new csdisc_recver failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csdisc_recver_init(csdisc_recver))
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_recver_new: init csdisc_recver failed\n");
        free_static_mem(MM_CSDISC_RECVER, csdisc_recver, LOC_CSDISC_0005);
        return (NULL_PTR);
    }

    return (csdisc_recver);
}

EC_BOOL csdisc_recver_init(CSDISC_RECVER *csdisc_recver)
{
    if(NULL_PTR != csdisc_recver)
    {
       CSDISC_RECVER_OBJ(csdisc_recver)  = NULL_PTR;
       CSDISC_RECVER_FUNC(csdisc_recver) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL csdisc_recver_clean(CSDISC_RECVER *csdisc_recver)
{
    if(NULL_PTR != csdisc_recver)
    {
       CSDISC_RECVER_OBJ(csdisc_recver)  = NULL_PTR;
       CSDISC_RECVER_FUNC(csdisc_recver) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL csdisc_recver_free(CSDISC_RECVER *csdisc_recver)
{
    if(NULL_PTR != csdisc_recver)
    {
        csdisc_recver_clean(csdisc_recver);
        free_static_mem(MM_CSDISC_RECVER, csdisc_recver, LOC_CSDISC_0006);
    }

    return (EC_TRUE);
}

CSDISC_NODE *csdisc_node_new()
{
    CSDISC_NODE *csdisc_node;

    alloc_static_mem(MM_CSDISC_NODE, &csdisc_node, LOC_CSDISC_0007);
    if(NULL_PTR == csdisc_node)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_new: new csdisc_node failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csdisc_node_init(csdisc_node))
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_new: init csdisc_node failed\n");
        free_static_mem(MM_CSDISC_NODE, csdisc_node, LOC_CSDISC_0008);
        return (NULL_PTR);
    }

    return (csdisc_node);
}

EC_BOOL csdisc_node_init(CSDISC_NODE *csdisc_node)
{
    if(NULL_PTR != csdisc_node)
    {
        uint32_t    socklen;

        cstring_init(CSDISC_NODE_MCAST_ETH_NAME(csdisc_node), NULL_PTR);

        CSDISC_NODE_MCAST_IPADDR(csdisc_node) = CMPI_ERROR_IPADDR;
        CSDISC_NODE_MCAST_PORT(csdisc_node)   = CMPI_ERROR_SRVPORT;
        CSDISC_NODE_MCAST_FLAGS(csdisc_node)  = 0;
        CSDISC_NODE_MCAST_SOCKFD(csdisc_node) = ERR_FD;

        socklen = sizeof(struct sockaddr_in);

        CSDISC_NODE_MCAST_SOCKLEN(csdisc_node) = socklen;
        BSET(CSDISC_NODE_MCAST_SOCKADDR(csdisc_node), 0, socklen);

        clist_init(CSDISC_NODE_MCAST_SENDER_LIST(csdisc_node), MM_CSDISC_SENDER, LOC_CSDISC_0009);
        clist_init(CSDISC_NODE_MCAST_RECVER_LIST(csdisc_node), MM_CSDISC_RECVER, LOC_CSDISC_0010);
    }

    return (EC_TRUE);
}

EC_BOOL csdisc_node_clean(CSDISC_NODE *csdisc_node)
{
    if(NULL_PTR != csdisc_node)
    {
        uint32_t    socklen;

        cstring_clean(CSDISC_NODE_MCAST_ETH_NAME(csdisc_node));

        CSDISC_NODE_MCAST_IPADDR(csdisc_node) = CMPI_ERROR_IPADDR;
        CSDISC_NODE_MCAST_PORT(csdisc_node)   = CMPI_ERROR_SRVPORT;
        CSDISC_NODE_MCAST_FLAGS(csdisc_node)  = 0;

        if(0 < CSDISC_NODE_MCAST_SOCKFD(csdisc_node))
        {
            csocket_close(CSDISC_NODE_MCAST_SOCKFD(csdisc_node));
        }

        CSDISC_NODE_MCAST_SOCKFD(csdisc_node) = CMPI_ERROR_SOCKFD;

        socklen = sizeof(struct sockaddr_in);

        CSDISC_NODE_MCAST_SOCKLEN(csdisc_node) = 0;
        BSET(CSDISC_NODE_MCAST_SOCKADDR(csdisc_node), 0, socklen);

        clist_clean(CSDISC_NODE_MCAST_SENDER_LIST(csdisc_node), (CLIST_DATA_DATA_CLEANER)csdisc_sender_free);
        clist_clean(CSDISC_NODE_MCAST_RECVER_LIST(csdisc_node), (CLIST_DATA_DATA_CLEANER)csdisc_recver_free);
    }

    return (EC_TRUE);
}

EC_BOOL csdisc_node_free(CSDISC_NODE *csdisc_node)
{
    if(NULL_PTR != csdisc_node)
    {
        csdisc_node_clean(csdisc_node);
        free_static_mem(MM_CSDISC_NODE, csdisc_node, LOC_CSDISC_0011);
    }

    return (EC_TRUE);
}

EC_BOOL csdisc_node_set_flags(CSDISC_NODE *csdisc_node, const uint32_t flags)
{
    int     sockfd;

    sockfd = CSDISC_NODE_MCAST_SOCKFD(csdisc_node);
    if(ERR_FD == sockfd)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: no sockfd\n");
        return (EC_FALSE);
    }

    if(CSDISC_MCAST_FLAG_BIND_NIC & flags)
    {
        CSTRING     *eth_name;

        eth_name = CSDISC_NODE_MCAST_ETH_NAME(csdisc_node);
        if(EC_TRUE == cstring_is_empty(eth_name))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d eth name is empty\n",
                                                   sockfd);
            return (EC_FALSE);
        }

        if(EC_FALSE == csocket_bind_nic(sockfd,
                                        (char *)cstring_get_str(eth_name),
                                        (uint32_t)cstring_get_len(eth_name)))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d bind '%s' failed\n",
                                                   sockfd,
                                                   (char *)cstring_get_str(eth_name));
            return (EC_FALSE);
        }

        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_set_flags: "
                                               "sockfd %d bind '%s' done\n",
                                               sockfd,
                                               (char *)cstring_get_str(eth_name));
    }

    if(CSDISC_MCAST_FLAG_REUSE_ADDR & flags)
    {
        if(EC_FALSE == csocket_enable_reuse_addr(sockfd))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d reuse addr failed\n",
                                                   sockfd);
            return (EC_FALSE);
        }

        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_set_flags: "
                                               "sockfd %d reuse addr succ\n",
                                               sockfd);
    }

    if(CSDISC_MCAST_FLAG_ENABALE_LOOP & flags)
    {
        if(EC_FALSE == csocket_enable_mcast_loop(sockfd))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d enable mcast loop failed\n",
                                                   sockfd);
            return (EC_FALSE);
        }

        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_set_flags: "
                                               "sockfd %d enable mcast loop succ\n",
                                               sockfd);
    }
    else
    {
        if(EC_FALSE == csocket_disable_mcast_loop(sockfd))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d disable mcast loop failed\n",
                                                   sockfd);
            return (EC_FALSE);
        }

        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_set_flags: "
                                               "sockfd %d enable mcast loop succ\n",
                                               sockfd);
    }

    if(CSDISC_MCAST_FLAG_JOIN_MEMBERSHIP & flags)
    {
        UINT32      mcast_ipaddr;

        mcast_ipaddr = CSDISC_NODE_MCAST_IPADDR(csdisc_node);
        if(EC_FALSE == csocket_join_mcast(sockfd, mcast_ipaddr))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d join mcast '%s' failed\n",
                                                   sockfd,
                                                   c_word_to_ipv4(mcast_ipaddr));
            return (EC_FALSE);
        }

        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_set_flags: "
                                               "sockfd %d join mcast '%s' done\n",
                                               sockfd,
                                               c_word_to_ipv4(mcast_ipaddr));
    }

    if(CSDISC_MCAST_FLAG_BIND_IP_PORT & flags)
    {
        UINT32      mcast_ipaddr;
        UINT32      mcast_port;

        mcast_ipaddr = CSDISC_NODE_MCAST_IPADDR(csdisc_node);
        mcast_port   = CSDISC_NODE_MCAST_PORT(csdisc_node);
        if(EC_FALSE == csocket_bind_mcast(sockfd, mcast_ipaddr, mcast_port))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d bind mcast '%s:%ld' failed\n",
                                                   sockfd,
                                                   c_word_to_ipv4(mcast_ipaddr),
                                                   mcast_port);
            return (EC_FALSE);
        }

        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_set_flags: "
                                               "sockfd %d bind mcast '%s:%ld' done\n",
                                               sockfd,
                                               c_word_to_ipv4(mcast_ipaddr),
                                               mcast_port);
    }

    if(CSDISC_MCAST_FLAG_NONBLOCK & flags)
    {
        if(EC_FALSE == csocket_nonblock_enable(sockfd))
        {
            dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_set_flags: "
                                                   "sockfd %d enable nonblock failed\n",
                                                   sockfd);
            return (EC_FALSE);
        }

        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_set_flags: "
                                               "sockfd %d enable nonblock succ\n",
                                               sockfd);
    }

    CSDISC_NODE_MCAST_FLAGS(csdisc_node) = flags;
    return (EC_TRUE);
}

CSDISC_NODE *csdisc_node_make(const CSTRING *mcast_eth_name,
                                    const UINT32   mcast_ipaddr,
                                    const UINT32   mcast_port,
                                    const uint32_t mcast_flags)
{
    CSDISC_NODE            *csdisc_node;
    struct sockaddr_in     *mcast_sockaddr;
    int                     sockfd;

    /* create socket */
    sockfd = csocket_open(AF_INET, SOCK_DGRAM, 0);
    if(0 > sockfd)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDERR, "error:csdisc_node_make: "
                                               "socket error\n");
        return ( NULL_PTR );
    }

    csdisc_node = csdisc_node_new();
    if(NULL_PTR == csdisc_node)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_make: "
                                               "new csdisc_node failed\n");
        csocket_close(sockfd);
        return (NULL_PTR);
    }

    cstring_clone(mcast_eth_name, CSDISC_NODE_MCAST_ETH_NAME(csdisc_node));
    CSDISC_NODE_MCAST_IPADDR(csdisc_node) = mcast_ipaddr;
    CSDISC_NODE_MCAST_PORT(csdisc_node)   = mcast_port;
    CSDISC_NODE_MCAST_SOCKFD(csdisc_node) = sockfd;

    if(EC_FALSE == csdisc_node_set_flags(csdisc_node, mcast_flags))
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_make: "
                                               "csdisc_node set flags %#x failed\n",
                                               mcast_flags);
        csdisc_node_free(csdisc_node);
        return (NULL_PTR);
    }

    /*make sockaddr*/
    mcast_sockaddr = CSDISC_NODE_MCAST_SOCKADDR(csdisc_node);

    mcast_sockaddr->sin_family      = AF_INET;
    mcast_sockaddr->sin_addr.s_addr = inet_addr(c_word_to_ipv4(mcast_ipaddr));
    /*mcast_sockaddr->sin_addr.s_addr = INADDR_ANY;*/
    mcast_sockaddr->sin_port        = htons(atoi(c_word_to_str(mcast_port)));

    CSDISC_NODE_MCAST_SOCKLEN(csdisc_node) = sizeof(struct sockaddr_in);

    return (csdisc_node);
}

/*push back*/
EC_BOOL csdisc_node_push_sender(CSDISC_NODE *csdisc_node, CSDISC_SENDER_FUNC func, void *obj)
{
    CSDISC_SENDER *csdisc_sender;

    csdisc_sender = csdisc_sender_new();
    if(NULL_PTR == csdisc_sender)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_push_sender: "
                                               "new sender failed\n");

        return (EC_FALSE);
    }

    CSDISC_SENDER_OBJ(csdisc_sender)    = obj;
    CSDISC_SENDER_FUNC(csdisc_sender)   = func;

    clist_push_back(CSDISC_NODE_MCAST_SENDER_LIST(csdisc_node), (void *)csdisc_sender);

    return (EC_TRUE);
}

/*push back*/
EC_BOOL csdisc_node_push_recver(CSDISC_NODE *csdisc_node, CSDISC_RECVER_FUNC func, void *obj)
{
    CSDISC_RECVER *csdisc_recver;

    csdisc_recver = csdisc_recver_new();
    if(NULL_PTR == csdisc_recver)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_push_recver: "
                                               "new recver failed\n");

        return (EC_FALSE);
    }

    CSDISC_RECVER_OBJ(csdisc_recver)    = obj;
    CSDISC_RECVER_FUNC(csdisc_recver)   = func;

    clist_push_back(CSDISC_NODE_MCAST_RECVER_LIST(csdisc_node), (void *)csdisc_recver);

    return (EC_TRUE);
}

EC_BOOL csdisc_node_walk_sender(CSDISC_NODE *csdisc_node)
{
    CLIST_DATA      *clist_data;

    CLIST_LOOP_NEXT(CSDISC_NODE_MCAST_SENDER_LIST(csdisc_node), clist_data)
    {
        CSDISC_SENDER *csdisc_sender;

        csdisc_sender = CLIST_DATA_DATA(clist_data);

        if(NULL_PTR != CSDISC_SENDER_FUNC(csdisc_sender))
        {
            CSDISC_SENDER_FUNC(csdisc_sender)(
                        CSDISC_SENDER_OBJ(csdisc_sender),
                        csdisc_node);
        }
    }

    return (EC_TRUE);
}

EC_BOOL csdisc_node_walk_recver(CSDISC_NODE *csdisc_node)
{
    CLIST_DATA      *clist_data;

    CLIST_LOOP_NEXT(CSDISC_NODE_MCAST_RECVER_LIST(csdisc_node), clist_data)
    {
        CSDISC_RECVER *csdisc_recver;

        csdisc_recver = CLIST_DATA_DATA(clist_data);

        if(NULL_PTR != CSDISC_RECVER_FUNC(csdisc_recver))
        {
            CSDISC_RECVER_FUNC(csdisc_recver)(
                        CSDISC_RECVER_OBJ(csdisc_recver),
                        csdisc_node);
        }
    }

    return (EC_TRUE);
}

EC_BOOL csdisc_node_send_packet(CSDISC_NODE *csdisc_node,
                                        const uint8_t *packet_data,
                                        const uint32_t packet_len)
{
    int                  sockfd;
    uint32_t             packet_sent_len;

    if(CSDISC_MCAST_PACKET_MAX_SIZE < packet_len)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_send_packet: "
                                               "packet len %u > packet max size %u\n",
                                               packet_len, CSDISC_MCAST_PACKET_MAX_SIZE);

        return (EC_FALSE);
    }

    sockfd = CSDISC_NODE_MCAST_SOCKFD(csdisc_node);
    if(ERR_FD == sockfd)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_send_packet: "
                                               "no mcast sockfd\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == csocket_sendto(sockfd,
                                  CSDISC_NODE_MCAST_SOCKADDR(csdisc_node),
                                  CSDISC_NODE_MCAST_SOCKLEN(csdisc_node),
                                  packet_data, packet_len, &packet_sent_len))
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_send_packet: "
                                               "mcast sockfd %d send data %p, len %u but failed\n",
                                               sockfd, packet_data, packet_len);

        return (EC_FALSE);
    }

    if(packet_len != packet_sent_len)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_send_packet: "
                                               "mcast sockfd %d send data %p, len %u but sent %d\n",
                                               sockfd, packet_data, packet_len, packet_sent_len);

        return (EC_FALSE);
    }

    dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_send_packet: "
                                           "mcast sockfd %d send data %p, len %u done\n",
                                           sockfd, packet_data, packet_len);

    return (EC_TRUE);
}

EC_BOOL csdisc_node_recv_packet(CSDISC_NODE *csdisc_node,
                                        uint8_t *packet_data,
                                        const uint32_t packet_max_len,
                                        uint32_t *packet_len)
{
    int                  sockfd;
    uint32_t             packet_recv_max_len;
    uint32_t             packet_recv_len;

    sockfd = CSDISC_NODE_MCAST_SOCKFD(csdisc_node);
    if(ERR_FD == sockfd)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_recv_packet: "
                                               "no mcast sockfd\n");

        return (EC_FALSE);
    }

    if(CSDISC_MCAST_PACKET_MAX_SIZE < packet_max_len)
    {
        packet_recv_max_len = CSDISC_MCAST_PACKET_MAX_SIZE;

        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "warn:csdisc_node_recv_packet: "
                                               "mcast sockfd %d recv data %p, "
                                               "packet max len %u > packet max size %u => adjust\n",
                                               sockfd, packet_data,
                                               packet_max_len, CSDISC_MCAST_PACKET_MAX_SIZE);
    }
    else
    {
        packet_recv_max_len = packet_max_len;
    }

    if(EC_FALSE == csocket_recvfrom(sockfd, packet_data, packet_recv_max_len, &packet_recv_len))
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDOUT, "error:csdisc_node_recv_packet: "
                                               "mcast sockfd %d recv data %p, max len %u but failed\n",
                                               sockfd, packet_data, packet_recv_max_len);

        return (EC_FALSE);
    }

    if(0 < packet_recv_len)
    {
        dbg_log(SEC_0058_CSDISC, 5)(LOGSTDOUT, "[DEBUG] csdisc_node_recv_packet: "
                                               "mcast sockfd %d recv data %p, max len %u, recv %u done\n",
                                               sockfd, packet_data, packet_recv_max_len, packet_recv_len);
    }

    if(NULL_PTR != packet_len)
    {
        (*packet_len) = packet_recv_len;
    }

    return (EC_TRUE);
}

EC_BOOL csdisc_node_send(CSDISC_NODE *csdisc_node)
{
    return csdisc_node_walk_sender(csdisc_node);
}

EC_BOOL csdisc_node_recv(CSDISC_NODE *csdisc_node)
{
    return csdisc_node_walk_recver(csdisc_node);
}

CSDISC_NODE *csdisc_node_start(const CSTRING *mcast_eth_name,
                                    const UINT32  mcast_ipaddr,
                                    const UINT32  mcast_port)
{
    CSDISC_NODE            *csdisc_node;
    uint32_t                mcast_flags;

    mcast_flags = 0;

    if(EC_FALSE == cstring_is_empty(mcast_eth_name))
    {
        mcast_flags |= CSDISC_MCAST_FLAG_BIND_NIC;
    }

    mcast_flags |= CSDISC_MCAST_FLAG_REUSE_ADDR;
    mcast_flags |= CSDISC_MCAST_FLAG_ENABALE_LOOP;
    mcast_flags |= CSDISC_MCAST_FLAG_JOIN_MEMBERSHIP; /*for recver only?*/
    mcast_flags |= CSDISC_MCAST_FLAG_BIND_IP_PORT;
    mcast_flags |= CSDISC_MCAST_FLAG_NONBLOCK;

    csdisc_node = csdisc_node_make(mcast_eth_name, mcast_ipaddr, mcast_port, mcast_flags);
    if(NULL_PTR == csdisc_node)
    {
        dbg_log(SEC_0058_CSDISC, 0)(LOGSTDERR, "error:csdisc_node_start: "
                                               "make failed\n");
        return ( NULL_PTR );
    }

    dbg_log(SEC_0058_CSDISC, 5)(LOGSTDERR, "[DEBUG] csdisc_node_start: "
                                           "make done\n");

    return (csdisc_node);
}

EC_BOOL csdisc_node_end(CSDISC_NODE *csdisc_node)
{
    csdisc_node_free(csdisc_node);

    dbg_log(SEC_0058_CSDISC, 5)(LOGSTDERR, "[DEBUG] csdisc_node_end: "
                                           "done\n");
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
