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
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/if_packet.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "type.h"

#include "mm.h"
#include "log.h"

#include "clist.h"
#include "cvector.h"

#include "cmisc.h"

#include "cbc.h"
#include "task.h"
#include "taskc.h"
#include "tasks.h"
#include "super.h"

#include "cxml.h"
#include "cparacfg.inc"
#include "cparacfg.h"

#include "csig.h"

#include "cthread.h"

#include "cdevice.h"
#include "csys.h"
#include "ccode.h"

#include "dhcp.h"
#include "ipv4pool.h"

#include "findex.inc"

#include "db_internal.h"


/*LPF: Linux Packet Filter*/

const char * default_net_card = "eth0";

static uint16_t DHCP_LOCAL_PORT;

void dhcp_set_local_port(const uint16_t local_port)
{
    DHCP_LOCAL_PORT = local_port;
}

uint16_t dhcp_get_local_port()
{
    return (DHCP_LOCAL_PORT);
}

/*NOTE: get from or put in buffer, all data is already in network byte order*/
STATIC_CAST static uint8_t __dhcp_get8(const uint8_t *buffer, uint32_t *counter)
{
    uint8_t i = buffer[*counter];
    (*counter)++;
    return i;
}

STATIC_CAST static uint16_t __dhcp_get16(const uint8_t *buffer, uint32_t *counter)
{
    uint16_t s;
    memcpy(&s, buffer + *counter, sizeof(uint16_t));
    *counter += sizeof(uint16_t);
    return s;
}

STATIC_CAST static uint32_t __dhcp_get32(const uint8_t *buffer, uint32_t *counter)
{
    uint32_t l;
    memcpy(&l, buffer + *counter, sizeof(uint32_t));
    *counter += sizeof(uint32_t);
    return l;
}

STATIC_CAST static void  __dhcp_get8s(uint8_t *buffer, uint32_t *counter, uint8_t *data, const uint32_t len)
{
    memcpy(data, buffer + *counter, len);
    *counter += len;
}

STATIC_CAST static void __dhcp_put8(uint8_t *buffer, uint32_t *counter, uint8_t c)
{
    buffer[*counter] = c;
    (*counter)++;
}

STATIC_CAST static void __dhcp_put16(uint8_t *buffer, uint32_t *counter, uint16_t s)
{
    memcpy(buffer + *counter, &s, sizeof(uint16_t));
    *counter += sizeof(uint16_t);
}

STATIC_CAST static void __dhcp_put32(uint8_t *buffer, uint32_t *counter, uint32_t l)
{
    memcpy(buffer + *counter, &l, sizeof(uint32_t));
    *counter += sizeof(uint32_t);
}

STATIC_CAST static void __dhcp_put8s(uint8_t *buffer, uint32_t *counter, const uint8_t *data, const uint32_t len)
{
    memcpy(buffer + *counter, data, len);
    *counter += len;
}

STATIC_CAST static uint32_t __dhcp_checksum (unsigned char *buf, unsigned nbytes, uint32_t sum)
{
    unsigned i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (nbytes & ~1U); i += 2)
    {
        sum += (uint16_t) ntohs(*((uint16_t *)(buf + i)));
        /* Add carry. */
        if (sum > 0xFFFF)
        {
            sum -= 0xFFFF;
        }
    }

    /* If there's a single byte left over, __dhcp_checksum it, too.   Network
       byte order is big-endian, so the remaining byte is the high byte. */
    if (i < nbytes)
    {
        sum += buf [i] << 8;
        /* Add carry. */
        if (sum > 0xFFFF)
        {
            sum -= 0xFFFF;
        }
    }

    return sum;
}

STATIC_CAST static uint32_t __dhcp_wrapsum (uint32_t sum)
{
    sum = ~sum & 0xFFFF;
    return htons(sum);
}

/*note: the input des_ip, des_mask and gateway should be in network byte order*/
STATIC_CAST static EC_BOOL __dhcp_if_add_route(int sock, const char *netcard, const uint32_t des_ip, const uint32_t des_mask, const uint32_t gateway)
{
    struct rtentry rt;
    struct sockaddr_in *sa;
    sa_family_t domain;

    domain = AF_INET;/*xxx*/
#if 0
    socklen_t info_len;

    info_len = sizeof(domain);

    if( 0 != getsockopt( sock, SOL_SOCKET, SO_DOMAIN, (char *)&domain, &info_len ) )
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDERR, "error: __dhcp_if_add_route: socket %d failed to get DOMAIN\n", sock);
        return (EC_FALSE);
    }
#endif
    memset(&rt, 0, sizeof(struct rtentry));

    /*des ipaddr*/
    sa = (struct sockaddr_in *)&(rt.rt_dst);
    sa->sin_family      = domain;
    sa->sin_addr.s_addr = des_ip;

    /*des subnet mask*/
    sa = (struct sockaddr_in *)&(rt.rt_genmask);
    sa->sin_family      = domain;
    sa->sin_addr.s_addr = des_mask;

    /*gateway ipaddr*/
    sa = (struct sockaddr_in *)&(rt.rt_gateway);
    sa->sin_family      = domain;
    sa->sin_addr.s_addr = gateway;

    rt.rt_flags |= RTF_UP;
    rt.rt_dev    = (char *)netcard;

    if (ioctl(sock, SIOCADDRT, &rt) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:__dhcp_if_add_route: add route of dev %s failed, errno = %d, errstr = %s\n",
                            netcard, errno, strerror(errno));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

INET_INFO *dhcp_if_new(const char *netcard_name, const uint32_t rbuf_max)
{
    INET_INFO *info;
    info = (INET_INFO *)SAFE_MALLOC(sizeof(INET_INFO), LOC_DHCP_0001);
    if(info)
    {
        if(EC_FALSE == dhcp_if_init(info, netcard_name, rbuf_max))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_new: init failed\n");
            SAFE_FREE(info, LOC_DHCP_0002);
            return (NULL_PTR);
        }
    }
    return (info);
}

EC_BOOL dhcp_if_init(INET_INFO *info, const char *netcard_name, const uint32_t rbuf_max)
{
    memset(info, 0, sizeof(INET_INFO));

    if(0 < rbuf_max)
    {
        info->rbuf = (unsigned char *)SAFE_MALLOC(rbuf_max, LOC_DHCP_0003);
        if(NULL_PTR == info->rbuf)
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_init: alloc %d bytes failed\n", rbuf_max);
            return (EC_FALSE);
        }
        memset(info->rbuf, 0, rbuf_max);
    }
    info->rbuf_max = rbuf_max;

    strcpy( info->name              , netcard_name);

    info->rfdesc = -1;
    info->wfdesc = -1;
    return (EC_TRUE);
}

EC_BOOL dhcp_if_clean(INET_INFO *info)
{
    if(NULL_PTR != info->rbuf)
    {
        SAFE_FREE(info->rbuf, LOC_DHCP_0004);
        info->rbuf = NULL_PTR;
        info->rbuf_max = 0;
    }
    dhcp_if_deregister_recv(info);
    dhcp_if_deregister_send(info);

    return (EC_TRUE);
}

void dhcp_if_free(INET_INFO *info)
{
    dhcp_if_clean(info);
    SAFE_FREE(info, LOC_DHCP_0005);
    return;
}


int dhcp_if_register_lpf (INET_INFO *info)
{
    int sock;
    struct sockaddr sa;

    /* Make an LPF socket. */
    sock = csocket_open(PF_PACKET, SOCK_PACKET, htons((short)ETH_P_ALL));
    if (sock < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDERR, "error:dhcp_if_register_lpf: failed to create raw socket!\n");
        return (-1);
    }

    strcpy(info->ifr_hw.ifr_name, info->name);

    /* Bind to the interface name */
    memset (&sa, 0, sizeof sa);
    sa.sa_family = AF_PACKET;
    strncpy (sa.sa_data, (const char *)&(info->ifr_hw), sizeof(sa.sa_data));
    if (0 != bind (sock, &sa, sizeof sa))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDERR, "dhcp_if_register_lpf: bind error! errno = %d, errstr = %s\n",
                           errno, strerror(errno) );
        close(sock);
        return (-1);
    }

    dhcp_if_get_info(info->name, info);

    //dhcp_print_hw_addr(LOGSTDOUT, &info->hw_address);

    return (sock);
}

EC_BOOL dhcp_if_register_recv (INET_INFO *info)
{
    /* Open a LPF device and hang it on this interface... */
    info->rfdesc = dhcp_if_register_lpf (info);
    if(-1 == info->rfdesc)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void dhcp_if_deregister_recv (INET_INFO *info)
{
    /* for LPF this is simple, packet filters are removed when sockets
       are closed */
    if(-1 != info->rfdesc)
    {
        close (info->rfdesc);
        info->rfdesc = -1;
    }
    return;
}

EC_BOOL dhcp_if_register_send (INET_INFO *info)
{
    info->wfdesc = dhcp_if_register_lpf (info);
    if(-1 == info->wfdesc)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void dhcp_if_deregister_send (INET_INFO *info)
{
    /* don't need to close twice if we are using lpf for sending and
    receiving */
    if(-1 != info->wfdesc)
    {
        close (info->wfdesc);
        info->wfdesc = -1;
    }
    return;
}

HARDWARE *dhcp_if_get_hw_addr(const INET_INFO *info)
{
    return (HARDWARE *)&(info->hw_address);
}

uint32_t dhcp_if_get_subnet_mask(const INET_INFO *info)
{
    const struct sockaddr_in *sa;
    sa = (const struct sockaddr_in *)&(info->ifr_mask.ifr_netmask);
    return (sa->sin_addr.s_addr);
}

uint32_t dhcp_if_get_bcast_addr(const INET_INFO *info)
{
    const struct sockaddr_in *sa;
    sa = (const struct sockaddr_in *)&(info->ifr_bcast.ifr_broadaddr);
    return (sa->sin_addr.s_addr);
}

uint32_t dhcp_if_get_ipv4_addr(const INET_INFO *info)
{
    const struct sockaddr_in *sa;
    sa = (const struct sockaddr_in *)&(info->ifr_ipv4.ifr_addr);
    return (sa->sin_addr.s_addr);
}

uint32_t dhcp_if_get_mcast_addr(const INET_INFO *info)
{
    const struct sockaddr_in *sa;
    sa = (const struct sockaddr_in *)&(info->mcast);
    return (sa->sin_addr.s_addr);
}

uint16_t dhcp_if_get_mcast_port(const INET_INFO *info)
{
    const struct sockaddr_in *sa;
    sa = (const struct sockaddr_in *)&(info->mcast);
    return (sa->sin_port);
}

EC_BOOL dhcp_if_enable_onboot(const char *netcard, const INET_INFO *info)
{
    char ifcfg_fname[IFCFG_FNAME_MAX];
    char script[IFCFG_SCRIPT_MAX];
    uint32_t pos;
    uint32_t prefix;

    const HARDWARE *hw;
    uint32_t ipv4_addr;
    uint32_t subnet_mask;

    FILE *fp;

    hw          = dhcp_if_get_hw_addr(info);
    ipv4_addr   = dhcp_if_get_ipv4_addr(info);
    subnet_mask = dhcp_if_get_subnet_mask(info);

    prefix = ipv4_subnet_mask_prefix(ntohl(subnet_mask));

    pos = 0;
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "DEVICE=\"%s\"\n", netcard);
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "ONBOOT=\"yes\"\n");
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "HWADDR=%02X:%02X:%02X:%02X:%02X:%02X\n",
                    hw->hbuf[1],hw->hbuf[2],hw->hbuf[3],hw->hbuf[4],hw->hbuf[5],hw->hbuf[6]);
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "TYPE=Ethernet\n");
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "BOOTPROTO=none\n");
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "IPADDR=%s\n", c_uint32_t_ntos(ipv4_addr));
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "PREFIX=%d\n", prefix);
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "DEFROUTE=yes\n");
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "IPV4_FAILURE_FATAL=yes\n");
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "IPV6INIT=no\n");
    pos += snprintf(&(script[ pos ]), IFCFG_SCRIPT_MAX - pos, "NAME=\"%s\"\n", netcard);

    //dbg_log(SEC_0084_DHCP, 5)(LOGSTDOUT, "script:\n%s\n", script);

    snprintf(ifcfg_fname, IFCFG_FNAME_MAX, "/etc/sysconfig/network-scripts/ifcfg-%s", netcard);
    fp = fopen(ifcfg_fname, "w");
    if(NULL_PTR == fp)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_enable_onboot: open file %s to write failed, errno = %d, errstr = %s\n",
                           ifcfg_fname, errno, strerror(errno));
        return (EC_FALSE);
    }
    fprintf(fp, "%s", (char *)script);
    fclose(fp);
    return (EC_TRUE);
}

EC_BOOL dhcp_if_set_mcast_route(int sock, const char *netcard)
{
    /*set default route info*/
    if(EC_FALSE == __dhcp_if_add_route(sock, netcard,
                                        c_uint32_t_ston(DHCP_DEFAULT_MCAST_ROUTE_IPADDR_STR),
                                        c_uint32_t_ston(DHCP_DEFAULT_MCAST_ROUTE_MASK_STR),
                                        c_uint32_t_ston(DHCP_DEFAULT_MCAST_ROUTE_GATEWAY_STR)))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_mcast_route: add default route des=%s, mask=%s, gw=%s info failed for %s\n",
                            DHCP_DEFAULT_MCAST_ROUTE_IPADDR_STR,
                            DHCP_DEFAULT_MCAST_ROUTE_MASK_STR,
                            DHCP_DEFAULT_MCAST_ROUTE_GATEWAY_STR,
                            netcard);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_if_get_info(const char *netcard, INET_INFO *info)
{
    int sock;

    sock = csocket_open(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_get_info: Can't create socket for %s\n", netcard);
        return (EC_FALSE);
    }

    /*get netcard hw addr*/
    if(EC_FALSE == dhcp_if_get_hw_addr_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_get_info: get hardware address info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    /*get ipv4 addr*/
    if(EC_FALSE == dhcp_if_get_ipv4_addr_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_get_info: get ipv4 address info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    /*get subnet mask*/
    if(EC_FALSE == dhcp_if_get_subnet_mask_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_get_info: get subnet mask info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    /*get broadcast address*/
    if(EC_FALSE == dhcp_if_get_bcast_addr_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_get_info: get broadcast address info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    close(sock);
    return (EC_TRUE);
}

EC_BOOL dhcp_if_set_info(const char *netcard, INET_INFO *info)
{
    int sock;

    sock = csocket_open(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_info: Can't create socket for %s\n", netcard);
        return (EC_FALSE);
    }

    /*set ipv4 addr*/
    if(EC_FALSE == dhcp_if_set_ipv4_addr_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_info: set ipv4 address info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    /*set subnet mask*/
    if(EC_FALSE == dhcp_if_set_subnet_mask_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_info: set subnet mask info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    /*set broadcast address*/
    if(EC_FALSE == dhcp_if_set_bcast_addr_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_info: set broadcast address info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

#if 1/*for CDLinux*/
    /*set default route info*/
    if(EC_FALSE == dhcp_if_set_mcast_route(sock, netcard))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_info: add default route info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }
#endif
    close(sock);
    return (EC_TRUE);
}

EC_BOOL dhcp_if_chk_info(const char *netcard, const INET_INFO *info)
{
    int sock;

    sock = csocket_open(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_info: Can't create socket for %s\n", netcard);
        return (EC_FALSE);
    }

    /*get ipv4 addr*/
    if(EC_FALSE == dhcp_if_chk_ipv4_addr_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_info: chk ipv4 address info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    /*get subnet mask*/
    if(EC_FALSE == dhcp_if_chk_subnet_mask_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_info: chk subnet mask info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    /*get broadcast address*/
    if(EC_FALSE == dhcp_if_chk_bcast_addr_info(sock, netcard, info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_info: chk broadcast address info failed for %s\n", netcard);
        close(sock);
        return (EC_FALSE);
    }

    close(sock);
    return (EC_TRUE);
}

EC_BOOL dhcp_if_get_hw_addr_info(int sock, const char *netcard, INET_INFO *info)
{
    struct ifreq *ifr_hw;
    struct sockaddr *sa;

    ifr_hw = &(info->ifr_hw);

    /*get netcard hw addr*/
    memset(ifr_hw, 0, sizeof(struct ifreq));
    strcpy(ifr_hw->ifr_name, netcard);
    if (ioctl(sock, SIOCGIFHWADDR, ifr_hw) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT,"error:dhcp_if_get_hw_addr_info: getting hardware address failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    sa = &(ifr_hw->ifr_hwaddr);
    switch (sa->sa_family)
    {
        case ARPHRD_ETHER:
            info->hw_address.hlen = 7;
            info->hw_address.hbuf[0] = HTYPE_ETHER;
            memcpy(&(info->hw_address.hbuf[1]), sa->sa_data, 6);
            break;
        default:
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT,"error:dhcp_if_get_hw_addr_info: Unsupported device type %ld for %s\n",
                              (long int)sa->sa_family, netcard);
            return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_if_get_subnet_mask_info(int sock, const char *netcard, INET_INFO *info)
{
    struct ifreq *ifr_mask;

    ifr_mask = &(info->ifr_mask);

    memset(ifr_mask, 0, sizeof(struct ifreq));
    strcpy(ifr_mask->ifr_name, netcard);

    if (ioctl(sock, SIOCGIFNETMASK, ifr_mask) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_get_subnet_mask_info: getting subnet mask failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL dhcp_if_set_subnet_mask_info(int sock, const char *netcard, const INET_INFO *info)
{
    struct ifreq ifr_mask;

    memset(&ifr_mask, 0, sizeof(struct ifreq));
    strcpy(ifr_mask.ifr_name, netcard);
    memcpy(&(ifr_mask.ifr_netmask ), &(info->ifr_mask.ifr_netmask ), sizeof(struct sockaddr_in));

    if (ioctl(sock, SIOCSIFNETMASK, &ifr_mask) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_subnet_mask_info: set subnet mask failed for %s, errno = %d, errstr = %s\n",
                            netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_if_chk_subnet_mask_info(int sock, const char *netcard, const INET_INFO *info)
{
    struct ifreq ifr_mask;
    struct sockaddr_in *sa_1st;
    struct sockaddr_in *sa_2nd;

    memset(&ifr_mask, 0, sizeof(struct ifreq));
    strcpy(ifr_mask.ifr_name, netcard);

    if (ioctl(sock, SIOCGIFNETMASK, &ifr_mask) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_subnet_mask_info: getting subnet mask failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    sa_1st = ( struct sockaddr_in * )&(ifr_mask.ifr_netmask );
    sa_2nd = ( struct sockaddr_in * )&(info->ifr_mask.ifr_netmask);
    if(sa_1st->sin_addr.s_addr != sa_2nd->sin_addr.s_addr)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_subnet_mask_info: got %s subnet mask %s != %s\n",
                            netcard, c_inet_ntos(&(sa_1st->sin_addr)), c_inet_ntos(&(sa_2nd->sin_addr)));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


EC_BOOL dhcp_if_get_bcast_addr_info(int sock, const char *netcard, INET_INFO *info)
{
    struct ifreq *ifr_bcast;

    ifr_bcast = &(info->ifr_bcast);

    memset(ifr_bcast, 0, sizeof(struct ifreq));
    strcpy(ifr_bcast->ifr_name, netcard);

    if (ioctl(sock, SIOCGIFBRDADDR, ifr_bcast) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_get_bcast_addr_info: getting broadcast address failed for %s, errno = %d, errstr = %s\n",
                            netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    if(0)
    {
        struct sockaddr_in *sa;
        sa = ((struct sockaddr_in *)&(info->ifr_bcast.ifr_broadaddr));

        dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_if_get_bcast_addr_info: bcast family %d port %d %s\n",
                            sa->sin_family, sa->sin_port, c_inet_ntos(&(sa->sin_addr))
                            );
    }
    return (EC_TRUE);
}

EC_BOOL dhcp_if_set_bcast_addr_info(int sock, const char *netcard, const INET_INFO *info)
{
    struct ifreq ifr_bcast;

    memset(&ifr_bcast, 0, sizeof(struct ifreq));
    strcpy(ifr_bcast.ifr_name, netcard);
    memcpy(&(ifr_bcast.ifr_broadaddr), &(info->ifr_bcast.ifr_broadaddr), sizeof(struct sockaddr_in));

    if (ioctl(sock, SIOCSIFBRDADDR, &ifr_bcast) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT,"error:dhcp_if_set_bcast_addr_info: set broadcast address failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_if_chk_bcast_addr_info(int sock, const char *netcard, const INET_INFO *info)
{
    struct ifreq ifr_bcast;
    struct sockaddr_in *sa_1st;
    struct sockaddr_in *sa_2nd;

    memset(&ifr_bcast, 0, sizeof(struct ifreq));
    strcpy(ifr_bcast.ifr_name, netcard);

    if (ioctl(sock, SIOCGIFBRDADDR, &ifr_bcast) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_bcast_addr_info: getting broadcast failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    sa_1st = ( struct sockaddr_in * )&(ifr_bcast.ifr_broadaddr );
    sa_2nd = ( struct sockaddr_in * )&(info->ifr_bcast.ifr_broadaddr );
    if(sa_1st->sin_addr.s_addr != sa_2nd->sin_addr.s_addr)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_bcast_addr_info: got %s broadcast %s != %s\n",
                            netcard, c_inet_ntos(&(sa_1st->sin_addr)), c_inet_ntos(&(sa_2nd->sin_addr)));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_if_get_ipv4_addr_info(int sock, const char *netcard, INET_INFO *info)
{
    struct ifreq *ifr_ipv4;

    ifr_ipv4 = &(info->ifr_ipv4);

    memset(ifr_ipv4, 0, sizeof(struct ifreq));
    strcpy(ifr_ipv4->ifr_name, netcard);

    if (ioctl(sock, SIOCGIFADDR, ifr_ipv4) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT,"error:dhcp_if_get_ipv4_addr_info: getting ipv4 address failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    if(1)
    {
        struct sockaddr_in *sa;
        sa = ((struct sockaddr_in *)&(info->ifr_ipv4.ifr_addr));

        dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_if_get_ipv4_addr_info: ipv4 family %d port %d %s\n",
                            sa->sin_family, sa->sin_port, c_inet_ntos(&(sa->sin_addr))
                            );
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_if_set_ipv4_addr_info(int sock, const char *netcard, const INET_INFO *info)
{
    struct ifreq ifr_ipv4;

    memset(&ifr_ipv4, 0, sizeof(struct ifreq));
    strcpy(ifr_ipv4.ifr_name, netcard);
    memcpy(&(ifr_ipv4.ifr_addr ), &(info->ifr_ipv4.ifr_addr), sizeof(struct sockaddr_in));

    if (ioctl(sock, SIOCSIFADDR, &ifr_ipv4) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_set_ipv4_addr_info: set ipv4 address failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_if_chk_ipv4_addr_info(int sock, const char *netcard, const INET_INFO *info)
{
    struct ifreq ifr_ipv4;
    struct sockaddr_in *sa_1st;
    struct sockaddr_in *sa_2nd;

    memset(&ifr_ipv4, 0, sizeof(struct ifreq));
    strcpy(ifr_ipv4.ifr_name, netcard);

    if (ioctl(sock, SIOCGIFADDR, &ifr_ipv4) < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_ipv4_addr_info: getting ipv4 address failed for %s, errno = %d, errstr = %s\n",
                           netcard, errno, strerror(errno));
        return (EC_FALSE);
    }

    sa_1st = ( struct sockaddr_in * )&(ifr_ipv4.ifr_broadaddr );
    sa_2nd = ( struct sockaddr_in * )&(info->ifr_ipv4.ifr_broadaddr );
    if(sa_1st->sin_addr.s_addr != sa_2nd->sin_addr.s_addr)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_chk_ipv4_addr_info: got %s ipv4 address %s != %s\n",
                            netcard, c_inet_ntos(&(sa_1st->sin_addr)), c_inet_ntos(&(sa_2nd->sin_addr)));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void dhcp_if_assemble_eth_header (
                                        const INET_INFO *inet_info,
                                        unsigned char *buf,
                                        unsigned *bufix,
                                        const HARDWARE *to)
{
    ISC_ETH_HEADER eh;

    if (to && to->hlen == 7) /* XXX */
    {
        memcpy (eh.ether_dhost, &to->hbuf [1], sizeof eh.ether_dhost);
    }
    else
    {
        memset (eh.ether_dhost, 0xff, sizeof (eh.ether_dhost));
    }
    if (inet_info->hw_address.hlen - 1 == sizeof (eh.ether_shost))
    {
        memcpy (eh.ether_shost, &inet_info->hw_address.hbuf [1], sizeof (eh.ether_shost));
    }
    else
    {
        memset (eh.ether_shost, 0x00, sizeof (eh.ether_shost));
    }
    eh.ether_type = htons (ETHERTYPE_IP);

    memcpy (&buf [*bufix], &eh, ETHER_HEADER_SIZE);
    *bufix += ETHER_HEADER_SIZE;
    return;
}

void dhcp_if_assemble_hw_header (
                                const INET_INFO *inet_info,
                                unsigned char *buf,
                                unsigned *bufix,
                                const HARDWARE *to)
{
    dhcp_if_assemble_eth_header (inet_info, buf, bufix, to);
    return;
}

void dhcp_if_assemble_udp_ip_header (
                                    const INET_INFO *inet_info,
                                    unsigned char *buf,
                                    unsigned *bufix,
                                    uint32_t from,
                                    uint32_t to,
                                    uint32_t dport,
                                    unsigned char *data,
                                    unsigned len)
{
    IP_HEADER ip;
    UDP_HEADER udp;

    memset (&ip, 0, sizeof ip);

    /* Fill out the IP header */
    IP_V_SET (&ip, 4);
    IP_HL_SET (&ip, 20);
    ip.ip_tos = IPTOS_LOWDELAY;
    ip.ip_len = htons(sizeof(ip) + sizeof(udp) + len);
    ip.ip_id  = 0;
    ip.ip_off = 0;
    ip.ip_ttl = 128;
    ip.ip_p   = IPPROTO_UDP;
    ip.ip_sum = 0;
    ip.ip_src.s_addr = from;
    ip.ip_dst.s_addr = to;

    /* Checksum the IP header... */
    ip.ip_sum = __dhcp_wrapsum (__dhcp_checksum ((unsigned char *)&ip, sizeof ip, 0));

    /* Copy the ip header into the buffer... */
    memcpy (&buf [*bufix], &ip, sizeof ip);
    *bufix += sizeof ip;

    /* Fill out the UDP header */
    udp.uh_sport = htons(dhcp_get_local_port());    /* XXX */
    udp.uh_dport = dport;            /* XXX */
    udp.uh_ulen = htons(sizeof(udp) + len);
    memset (&udp.uh_sum, 0, sizeof udp.uh_sum);

    /* Compute UDP checksums, including the ``pseudo-header'', the UDP
       header and the data. */

    udp.uh_sum =
        __dhcp_wrapsum (__dhcp_checksum ((unsigned char *)&udp, sizeof udp,
                   __dhcp_checksum (data, len,
                         __dhcp_checksum ((unsigned char *)
                               &ip.ip_src,
                               2 * sizeof ip.ip_src,
                               IPPROTO_UDP +
                               (uint32_t)
                               ntohs (udp.uh_ulen)))));

    /* Copy the udp header into the buffer... */
    memcpy (&buf [*bufix], &udp, sizeof udp);
    *bufix += sizeof udp;
}

ssize_t dhcp_if_decode_hw_header (
                                INET_INFO *inet_info,
                                unsigned char *buf,
                                unsigned bufix,
                                HARDWARE *from)
{
    return dhcp_if_decode_eth_header (inet_info, buf, bufix, from);
}

ssize_t dhcp_if_decode_eth_header (
                                        INET_INFO *inet_info,
                                        unsigned char *buf,
                                        unsigned bufix,
                                        HARDWARE *from)
{
  ISC_ETH_HEADER eh;

  memcpy (&eh, buf + bufix, ETHER_HEADER_SIZE);

  memcpy (&from->hbuf[1], eh.ether_shost, sizeof(eh.ether_shost));
  from->hbuf[0] = ARPHRD_ETHER;
  from->hlen = (sizeof eh.ether_shost) + 1;

  return ETHER_HEADER_SIZE;
}

ssize_t dhcp_if_decode_udp_ip_header(
                                     INET_INFO *inet_info,
                                     unsigned char *buf,
                                     unsigned bufix,
                                     struct sockaddr_in *from,
                                     unsigned buflen,
                                     unsigned *rbuflen)
{
  unsigned char *data;
  IP_HEADER ip;
  UDP_HEADER udp;
  unsigned char *upp, *endbuf;
  uint32_t ip_len, ulen, pkt_len;
  uint32_t sum, usum;
  static int ip_packets_seen;
  static int ip_packets_bad_checksum;
  static int udp_packets_seen;
  static int udp_packets_bad_checksum;
  static int udp_packets_length_checked;
  static int udp_packets_length_overflow;
  unsigned len;

  /* Designate the end of the input buffer for bounds checks. */
  endbuf = buf + bufix + buflen;

  /* Assure there is at least an IP header there. */
  if ((buf + bufix + sizeof(ip)) > endbuf)
  {
      return -1;
  }
  /* Copy the IP header into a stack aligned structure for inspection.
   * There may be bits in the IP header that we're not decoding, so we
   * copy out the bits we grok and skip ahead by ip.ip_hl * 4.
   */
  upp = buf + bufix;
  memcpy(&ip, upp, sizeof(ip));
  ip_len = (*upp & 0x0f) << 2;
  upp += ip_len;

  /* Check the IP packet length. */
  pkt_len = ntohs(ip.ip_len);
  if (pkt_len > buflen)
  {
    return -1;
  }
  /* Assure after ip_len bytes that there is enough room for a UDP header. */
  if ((upp + sizeof(udp)) > endbuf)
  {
      return -1;
  }

  /* Copy the UDP header into a stack aligned structure for inspection. */
  memcpy(&udp, upp, sizeof(udp));

  ulen = ntohs(udp.uh_ulen);
  if (ulen < sizeof(udp))
  {
    return -1;
  }

  udp_packets_length_checked++;
  if ((upp + ulen) > endbuf)
  {
    udp_packets_length_overflow++;
    if ((udp_packets_length_checked > 4) &&
        ((udp_packets_length_checked / udp_packets_length_overflow) < 2))
     {
        dbg_log(SEC_0084_DHCP, 5)(LOGSTDNULL, "dhcp_if_decode_udp_ip_header: %d udp packets in %d too long - dropped\n",
             udp_packets_length_overflow,
             udp_packets_length_checked);
        udp_packets_length_overflow = 0;
        udp_packets_length_checked = 0;
    }
    return -1;
  }

  if ((ulen < sizeof(udp)) || ((upp + ulen) > endbuf))
  {
    return -1;
  }

  /* Check the IP header __dhcp_checksum - it should be zero. */
  ++ip_packets_seen;
  if (__dhcp_wrapsum (__dhcp_checksum (buf + bufix, ip_len, 0)))
  {
      ++ip_packets_bad_checksum;
      if (ip_packets_seen > 4 && (ip_packets_seen / ip_packets_bad_checksum) < 2)
      {
          dbg_log(SEC_0084_DHCP, 5)(LOGSTDNULL, "dhcp_if_decode_udp_ip_header: %d bad IP checksums seen in %d packets\n",
                ip_packets_bad_checksum, ip_packets_seen);
          ip_packets_seen = ip_packets_bad_checksum = 0;
      }
      return -1;
  }

  /* Copy out the IP source address... */
  memcpy(&from->sin_addr, &ip.ip_src, 4);

  /* Compute UDP checksums, including the ``pseudo-header'', the UDP
     header and the data.   If the UDP __dhcp_checksum field is zero, we're
     not supposed to do a __dhcp_checksum. */

  data = upp + sizeof(udp);
  len = ulen - sizeof(udp);

  usum = udp.uh_sum;
  udp.uh_sum = 0;

  /* XXX: We have to pass &udp, because we have to zero the __dhcp_checksum
   * field before calculating the sum...'upp' isn't zeroed.
   */
  sum = __dhcp_wrapsum(__dhcp_checksum((unsigned char *)&udp, sizeof(udp),
             __dhcp_checksum(data, len,
                  __dhcp_checksum((unsigned char *)&ip.ip_src, 8, IPPROTO_UDP + ulen))));

  udp_packets_seen++;
  if (usum && usum != sum)
  {
      udp_packets_bad_checksum++;
      if (udp_packets_seen > 4 && (udp_packets_seen / udp_packets_bad_checksum) < 2)
      {
          dbg_log(SEC_0084_DHCP, 5)(LOGSTDOUT, "dhcp_if_decode_udp_ip_header: %d bad udp checksums in %d packets\n",
                udp_packets_bad_checksum, udp_packets_seen);
          udp_packets_seen = udp_packets_bad_checksum = 0;
      }
      return -1;
  }

  /* Copy out the port... */
  memcpy (&from->sin_port, &udp.uh_sport, sizeof udp.uh_sport);

  /* Save the length of the UDP payload. */
  if (rbuflen != NULL)
    *rbuflen = len;

  /* Return the index to the UDP payload. */
  return ip_len + sizeof udp;
}

ssize_t dhcp_if_send ( const INET_INFO *inet_info,
                            const uint8_t *data,
                            const size_t len,
                            const struct in_addr from,
                            const struct sockaddr_in *to,
                            const HARDWARE *hto)
{
    unsigned hbufp = 0, ibufp = 0;
    unsigned char hh [16];
    unsigned char ih [1536];
    unsigned char *buf = (unsigned char *)ih;
    struct sockaddr_pkt sa;
    int result;
    int fudge;

    /* Assemble the headers... */
    dhcp_if_assemble_hw_header (inet_info, (unsigned char *)hh, &hbufp, hto);
    fudge = hbufp % 4;            /* IP header must be word-aligned. */
    memcpy (buf + fudge, (unsigned char *)hh, hbufp);
    ibufp = hbufp + fudge;
    dhcp_if_assemble_udp_ip_header (inet_info, buf, &ibufp,
                                from.s_addr,
                                to->sin_addr.s_addr, to->sin_port,
                                (unsigned char *)data, len);
    memcpy (buf + ibufp, data, len);

    /* For some reason, SOCK_PACKET sockets can't be connected,
       so we have to do a sentdo every time. */
    memset (&sa, 0, sizeof(sa));
    sa.spkt_family = AF_PACKET;
    strncpy ((char *)sa.spkt_device, (const char *)&(inet_info->ifr_hw), sizeof(sa.spkt_device));
    sa.spkt_protocol = htons(ETH_P_IP);

    result = sendto(inet_info->wfdesc,
                     buf + fudge, ibufp + len - fudge, 0,
                     (const struct sockaddr *)&sa, sizeof(sa));
    if (result < 0)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_send: errno = %d, errstr = %s [fudge = %d, len %d]\n",
                            errno, strerror(errno), fudge, (int)(ibufp + len - fudge));
    }
    return result;
}

ssize_t dhcp_if_recv ( INET_INFO *inet_info,
                            unsigned char *buf,
                            size_t len,
                            struct sockaddr_in *from,
                            HARDWARE *hfrom)
{
    int length = 0;
    int offset = 0;
    unsigned char ibuf [1536];
    unsigned bufix = 0;
    unsigned paylen;

    length = read(inet_info->rfdesc, ibuf, sizeof(ibuf));
    if (length <= 0)
    {
        return length;
    }

    bufix = 0;
    /* Decode the physical header... */
    offset = dhcp_if_decode_hw_header (inet_info, ibuf, bufix, hfrom);

    /* If a physical layer __dhcp_checksum failed (dunno of any
       physical layer that supports this, but WTH), skip this
       packet. */
    if (offset < 0)
    {
        return 0;
    }

    bufix += offset;
    length -= offset;

    /* Decode the IP and UDP headers... */
    offset = dhcp_if_decode_udp_ip_header (inet_info, ibuf, bufix, from, (unsigned)length, &paylen);

    /* If the IP or UDP __dhcp_checksum was bad, skip the packet... */
    if (offset < 0)
    {
        return 0;
    }

    bufix += offset;
    length -= offset;

    if ((unsigned)length < paylen)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_recv: Internal inconsistency, errno = %d, errstr = %s\n",
                            errno, strerror(errno));
    }

    /* Copy out the data in the packet... */
    memcpy(buf, &ibuf[bufix], paylen);
    return paylen;
}

EC_BOOL dhcp_if_check_ipv4_defined(const char *netcard)
{
    INET_INFO *info;
    int sock;
    uint32_t ipv4_addr;

    info = dhcp_if_new(netcard, 0);
    if(NULL_PTR == info)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_check_ipv4_defined: new inet_info for %s failed\n", netcard);
        return (EC_FALSE);
    }

    sock = dhcp_if_register_lpf(info);
    if(-1 == sock)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_check_ipv4_defined: register lpf for %s failed\n", netcard);
        dhcp_if_free(info);
        return (EC_FALSE);
    }

    ipv4_addr = dhcp_if_get_ipv4_addr(info);
    if(0 == ipv4_addr)
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_if_check_ipv4_defined: ipv4 addr for %s not defined\n", netcard);
        close(sock);
        dhcp_if_free(info);
        return (EC_FALSE);
    }

    dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_if_check_ipv4_defined: %s defined ipv4 addr %s\n", netcard, c_uint32_t_ntos(ipv4_addr));

    close(sock);
    dhcp_if_free(info);
    return (EC_TRUE);
}

void dhcp_print_hw_addr(LOG *log, const HARDWARE *hw)
{
    switch(hw->hbuf[0])
    {
        case HTYPE_ETHER:
        dbg_log(SEC_0084_DHCP, 5)(LOGSTDOUT, "hw addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
                            hw->hbuf[1],hw->hbuf[2],hw->hbuf[3],hw->hbuf[4],hw->hbuf[5],hw->hbuf[6]);
        break;
        default:
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_print_hw_addr:invalid hw type %d\n", hw->hbuf[0]);
    }
    return;
}

EC_BOOL dhcp_packet_set_caddr(DHCP_PACKET *dhcp_pkt, const HARDWARE *hw)
{
    switch(hw->hbuf[0])
    {
        case HTYPE_ETHER:
        dhcp_pkt->htype = HTYPE_ETHER;
        dhcp_pkt->hlen  = 6;
        memcpy(dhcp_pkt->chaddr, hw->hbuf + 1, 6);
        return (EC_TRUE);
        default:
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_set_caddr:invalid hw type %d\n", hw->hbuf[0]);
    }
    return (EC_FALSE);
}

EC_BOOL dhcp_packet_get_caddr(const DHCP_PACKET *dhcp_pkt, HARDWARE *hw)
{
    switch(dhcp_pkt->htype)
    {
        case HTYPE_ETHER:
        if(6 != dhcp_pkt->hlen)
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_get_caddr: invalid hlen %d != 6\n", dhcp_pkt->hlen);
            return (EC_FALSE);
        }

        hw->hbuf[0] = HTYPE_ETHER;
        memcpy(hw->hbuf + 1, dhcp_pkt->chaddr, 6);
        return (EC_TRUE);
        default:
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_get_caddr:invalid hw type %d\n", dhcp_pkt->htype);
    }
    return (EC_FALSE);
}

EC_BOOL dhcp_packet_chk_caddr(const DHCP_PACKET *dhcp_pkt, const HARDWARE *hw)
{
    if(dhcp_pkt->htype != hw->hbuf[0])
    {
        return (EC_FALSE);
    }

    switch(dhcp_pkt->htype)
    {
        case HTYPE_ETHER:
        if(0 != memcmp(dhcp_pkt->chaddr, hw->hbuf + 1, 6))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_chk_caddr: chk chaddr failed\n");
            return (EC_FALSE);
        }
        break;
        default:
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_chk_caddr:invalid hw type %d\n", dhcp_pkt->htype);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL dhcp_packet_get_options(const DHCP_PACKET *dhcp_pkt, INET_INFO *info)
{
    uint32_t counter;
    uint8_t  code;
    const uint8_t *buffer;
    struct sockaddr_in *sa;

    buffer  = (const uint8_t *)(dhcp_pkt->options);
    counter = 0;

    if(0 != memcmp(buffer + counter, DHCP_OPTIONS_COOKIE, strlen(DHCP_OPTIONS_COOKIE)))
    {
        return (EC_FALSE);
    }

    counter += strlen(DHCP_OPTIONS_COOKIE);

    for(; 0 != (code = __dhcp_get8(buffer, &counter));)
    {
        -- counter; /*adjust*/
        switch(code)
        {
            case DHO_SUBNET_MASK:
            {
                sa = (struct sockaddr_in *)&(info->ifr_mask.ifr_netmask);
                sa->sin_addr.s_addr = dhcp_packet_get_subnet_mask(dhcp_pkt, &counter);
                sa->sin_family = AF_INET;

                break;
            }
            case DHO_BROADCAST_ADDRESS:/*bcast address*/
            {
                sa = (struct sockaddr_in *)&(info->ifr_bcast.ifr_broadaddr);
                sa->sin_addr.s_addr = dhcp_packet_get_bcast_addr(dhcp_pkt, &counter);
                sa->sin_family = AF_INET;

                break;
            }
            case DHO_MULTICAST_ADDRESS:/*mcast address*/
            {
                sa = (struct sockaddr_in *)&(info->mcast);
                sa->sin_addr.s_addr = dhcp_packet_get_mcast_addr(dhcp_pkt, &counter);
                sa->sin_family = AF_INET;

                break;
            }
            case DHO_MULTICAST_PORT:/*mcast port*/
            {
                sa = (struct sockaddr_in *)&(info->mcast);
                sa->sin_port = dhcp_packet_get_mcast_port(dhcp_pkt, &counter);
                sa->sin_family = AF_INET;

                break;
            }
            default:
            {
                dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_get_options: invalid code %d\n", code);
                return (EC_FALSE);
            }
        }
    }
    return (EC_TRUE);
}

void dhcp_packet_print_chaddr(LOG *log, const DHCP_PACKET *dhcp_pkt)
{
    uint8_t pos;

    sys_print(log, "htype %d, chaddr: ", dhcp_pkt->htype);
    for(pos = 0; pos + 1 < dhcp_pkt->hlen; pos ++)
    {
        sys_print(log, "%02X:", dhcp_pkt->chaddr[ pos ]);
    }
    if(pos < dhcp_pkt->hlen)
    {
        sys_print(log, "%02X", dhcp_pkt->chaddr[ pos ]);
    }
    sys_print(log, " ");
    //sys_print(log, "\n");
    return;
}

void dhcp_packet_print_options(LOG *log, const DHCP_PACKET *dhcp_pkt)
{
    uint32_t pos;
    uint32_t end;

    end = strlen(DHCP_OPTIONS_COOKIE);
    sys_print(log, "options: ");
    for(pos = 0; pos < end; pos ++)
    {
        sys_print(log, "%c", dhcp_pkt->options[pos]);
    }
    return;
}

EC_BOOL dhcp_packet_set_cookie(DHCP_PACKET *dhcp_pkt, uint32_t *offset)
{
    uint32_t len;
    assert(0 == (*offset));

    len =  strlen(DHCP_OPTIONS_COOKIE);
    __dhcp_put8s(dhcp_pkt->options, offset, (uint8_t *)DHCP_OPTIONS_COOKIE, len);
    return (EC_TRUE);
}

char *  dhcp_packet_get_cookie(const DHCP_PACKET *dhcp_pkt, uint32_t *offset)
{
    assert(0 == (*offset));
    (*offset) = strlen(DHCP_OPTIONS_COOKIE);
    return (char *)dhcp_pkt->options;
}

EC_BOOL dhcp_packet_chk_cookie(const DHCP_PACKET *dhcp_pkt)
{
    if(0 == memcmp(dhcp_pkt->options, DHCP_OPTIONS_COOKIE, strlen(DHCP_OPTIONS_COOKIE)))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*subnet mask is in network byte order*/
EC_BOOL dhcp_packet_set_subnet_mask(DHCP_PACKET *dhcp_pkt, const uint32_t subnet_mask, uint32_t *offset)
{
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)DHO_SUBNET_MASK);
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)4);
    __dhcp_put32(dhcp_pkt->options, offset, subnet_mask);
    return (EC_TRUE);
}

uint32_t dhcp_packet_get_subnet_mask(const DHCP_PACKET *dhcp_pkt, uint32_t *offset)
{
    uint8_t code;
    uint8_t len;

    code = __dhcp_get8(dhcp_pkt->options, offset);
    len  = __dhcp_get8(dhcp_pkt->options, offset);
    assert(DHO_SUBNET_MASK == code);
    assert(4 == len);
    return __dhcp_get32(dhcp_pkt->options, offset);
}

EC_BOOL dhcp_packet_set_bcast_addr(DHCP_PACKET *dhcp_pkt, const uint32_t bcast_addr, uint32_t *offset)
{
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)DHO_BROADCAST_ADDRESS);
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)4);
    __dhcp_put32(dhcp_pkt->options, offset, bcast_addr);
    return (EC_TRUE);
}

uint32_t dhcp_packet_get_bcast_addr(const DHCP_PACKET *dhcp_pkt, uint32_t *offset)
{
    uint8_t code;
    uint8_t len;

    code = __dhcp_get8(dhcp_pkt->options, offset);
    len  = __dhcp_get8(dhcp_pkt->options, offset);

    assert(DHO_BROADCAST_ADDRESS == code);
    assert(4 == len);
    return __dhcp_get32(dhcp_pkt->options, offset);
}

EC_BOOL dhcp_packet_set_mcast_addr(DHCP_PACKET *dhcp_pkt, const uint32_t mcast_addr, uint32_t *offset)
{
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)DHO_MULTICAST_ADDRESS);
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)4);
    __dhcp_put32(dhcp_pkt->options, offset, mcast_addr);
    return (EC_TRUE);
}

uint32_t dhcp_packet_get_mcast_addr(const DHCP_PACKET *dhcp_pkt, uint32_t *offset)
{
    uint8_t code;
    uint8_t len;

    code = __dhcp_get8(dhcp_pkt->options, offset);
    len  = __dhcp_get8(dhcp_pkt->options, offset);

    assert(DHO_MULTICAST_ADDRESS == code);
    assert(4 == len);
    return __dhcp_get32(dhcp_pkt->options, offset);
}

EC_BOOL dhcp_packet_set_mcast_port(DHCP_PACKET *dhcp_pkt, const uint16_t mcast_port, uint32_t *offset)
{
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)DHO_MULTICAST_PORT);
    __dhcp_put8(dhcp_pkt->options, offset, (uint8_t)2);
    __dhcp_put16(dhcp_pkt->options, offset, mcast_port);
    return (EC_TRUE);
}

uint16_t dhcp_packet_get_mcast_port(const DHCP_PACKET *dhcp_pkt, uint32_t *offset)
{
    uint8_t code;
    uint8_t len;

    code = __dhcp_get8(dhcp_pkt->options, offset);
    len  = __dhcp_get8(dhcp_pkt->options, offset);

    assert(DHO_MULTICAST_PORT == code);
    assert(2 == len);
    return __dhcp_get16(dhcp_pkt->options, offset);
}

EC_BOOL  dhcp_packet_set_client_addr(DHCP_PACKET *dhcp_pkt, const uint32_t ipaddr)
{
    dhcp_pkt->yiaddr.s_addr = ipaddr;
    return (EC_TRUE);
}

uint32_t dhcp_packet_get_client_addr(const DHCP_PACKET *dhcp_pkt)
{
    return (dhcp_pkt->yiaddr.s_addr);
}

EC_BOOL   dhcp_packet_set_server_addr(DHCP_PACKET *dhcp_pkt, const uint32_t ipaddr)
{
    dhcp_pkt->siaddr.s_addr = ipaddr;
    return (EC_TRUE);
}

uint32_t dhcp_packet_get_server_addr(const DHCP_PACKET *dhcp_pkt)
{
    return (dhcp_pkt->siaddr.s_addr);
}

EC_BOOL   dhcp_packet_set_server_name(DHCP_PACKET *dhcp_pkt, const char * server_name)
{
    if(server_name && server_name[0])
    {
        uint32_t len;
        len = DMIN(strlen(server_name), DHCP_SNAME_LEN);
        memcpy(dhcp_pkt->sname, server_name, len);
    }
    return (EC_TRUE);
}

char * dhcp_packet_get_server_name(const DHCP_PACKET *dhcp_pkt)
{
    return ((char *)dhcp_pkt->sname);
}

EC_BOOL dhcp_packet_filter(const DHCP_PACKET *dhcp_pkt, const uint8_t op)
{
    if(op == dhcp_pkt->op)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


EC_BOOL dhcp_packet_send(const DHCP_PACKET *dhcp_pkt, const uint16_t des_port, const INET_INFO *info)
{
    struct in_addr from;
    struct sockaddr_in sockaddr_broadcast;

    size_t  pkt_len;
    ssize_t sent_len;

    from.s_addr = INADDR_ANY;

    sockaddr_broadcast.sin_family      = AF_INET;
    sockaddr_broadcast.sin_port        = htons(des_port);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;/*client*/

    pkt_len  = sizeof(DHCP_PACKET);
    sent_len = dhcp_if_send (info,
                            (uint8_t *)dhcp_pkt,
                            pkt_len,
                            from,
                            &sockaddr_broadcast,
                            (HARDWARE *)0);

    //dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_packet_send: send %d bytes (pkt_len = %d)\n", sent_len, pkt_len);

    if(0 < sent_len)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL dhcp_packet_recv(DHCP_PACKET **recv_dhcp_pkt, INET_INFO *recv_info)
{
    HARDWARE hfrom;
    struct sockaddr_in sockaddr_broadcast;
    DHCP_PACKET *dhcp_pkt;

    memset(&sockaddr_broadcast, 0, sizeof(sockaddr_broadcast));

    memset(recv_info->rbuf, 0, recv_info->rbuf_max);
    memset(&hfrom, 0, sizeof(HARDWARE));

    recv_info->rbuf_len = dhcp_if_recv(recv_info,
                                      recv_info->rbuf,
                                      recv_info->rbuf_max,
                                      &sockaddr_broadcast,
                                      &hfrom);

    if(0 >= recv_info->rbuf_len)
    {
        //dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_packet_recv: recv nothing, len %d\n", recv_info->rbuf_len);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_packet_recv: recv %d bytes\n", recv_info->rbuf_len);

    dhcp_pkt = (DHCP_PACKET *)(recv_info->rbuf);

    if(EC_FALSE == dhcp_packet_get_options(dhcp_pkt, recv_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDNULL, "error:dhcp_packet_recv: get options failed\n");
        return (EC_FALSE);
    }
    (*recv_dhcp_pkt) = dhcp_pkt;
    return (EC_TRUE);
}

/*req packet is from client to server*/
EC_BOOL dhcp_req_packet_set(DHCP_PACKET *dhcp_pkt, const INET_INFO *info)
{
    uint32_t offset;

    memset(dhcp_pkt, 0, sizeof(DHCP_PACKET));

    dhcp_pkt->op = BOOTREQUEST;
    dhcp_pkt->flags |= htons(BOOTP_BROADCAST);

    dhcp_packet_set_caddr(dhcp_pkt, &(info->hw_address));

    offset = 0;
    dhcp_packet_set_cookie(dhcp_pkt, &offset);

    return(EC_TRUE);
}

EC_BOOL dhcp_req_packet_chk(const DHCP_PACKET *dhcp_pkt)
{
    if(BOOTREQUEST != dhcp_pkt->op)
    {
        dbg_log(SEC_0084_DHCP, 1)(LOGSTDOUT, "warn:dhcp_req_packet_chk: invalid op %d\n", dhcp_pkt->op);
        return (EC_FALSE);
    }

    if(EC_FALSE == dhcp_packet_chk_cookie(dhcp_pkt))
    {
        dbg_log(SEC_0084_DHCP, 1)(LOGSTDOUT, "warn:dhcp_req_packet_chk: invalid cookie\n");
        return (EC_FALSE);
    }

    if(HTYPE_ETHER != dhcp_pkt->htype)
    {
        dbg_log(SEC_0084_DHCP, 1)(LOGSTDOUT, "warn:dhcp_req_packet_chk: invalid htype %d\n", dhcp_pkt->htype);
        return (EC_FALSE);
    }

    if(6 != dhcp_pkt->hlen)
    {
        dbg_log(SEC_0084_DHCP, 1)(LOGSTDOUT, "warn:dhcp_req_packet_chk: invalid hlen %d\n", dhcp_pkt->hlen);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*rsp packet is from server to client*/
EC_BOOL dhcp_rsp_packet_set(DHCP_PACKET *dhcp_pkt, const INET_INFO *info,
                                    const uint32_t client_ipaddr, const HARDWARE *client_hw_addr)
{
    uint32_t offset;
    struct sockaddr_in *sa;

    memset(dhcp_pkt, 0, sizeof(DHCP_PACKET));

    dhcp_pkt->op = BOOTREPLY;
    dhcp_pkt->flags |= htons(BOOTP_BROADCAST);

    dhcp_packet_set_server_addr(dhcp_pkt, htonl(INADDR_ANY));
    dhcp_packet_set_client_addr(dhcp_pkt, client_ipaddr);
    dhcp_packet_set_caddr(dhcp_pkt, client_hw_addr);

    offset = 0;
    dhcp_packet_set_cookie(dhcp_pkt, &offset);

    sa = ((struct sockaddr_in *)&(info->ifr_mask.ifr_netmask));
    dhcp_packet_set_subnet_mask(dhcp_pkt, sa->sin_addr.s_addr, &offset);

    sa = ((struct sockaddr_in *)&(info->ifr_bcast.ifr_broadaddr));
    dhcp_packet_set_bcast_addr(dhcp_pkt, sa->sin_addr.s_addr, &offset);

    sa = (struct sockaddr_in *)&(info->mcast);
    dhcp_packet_set_mcast_addr(dhcp_pkt, sa->sin_addr.s_addr, &offset);
    dhcp_packet_set_mcast_port(dhcp_pkt, sa->sin_port       , &offset);

    return(EC_TRUE);
}

EC_BOOL dhcp_rsp_packet_chk(const DHCP_PACKET *dhcp_pkt, const INET_INFO *info)
{
    if(BOOTREPLY != dhcp_pkt->op)
    {
        dbg_log(SEC_0084_DHCP, 1)(LOGSTDOUT, "warn:dhcp_rsp_packet_chk: invalid op %d\n", dhcp_pkt->op);
        return (EC_FALSE);
    }

    if(EC_FALSE == dhcp_packet_chk_cookie(dhcp_pkt))
    {
        dbg_log(SEC_0084_DHCP, 1)(LOGSTDOUT, "warn:dhcp_rsp_packet_chk: invalid cookie\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == dhcp_packet_chk_caddr(dhcp_pkt, &(info->hw_address)))
    {
        dbg_log(SEC_0084_DHCP, 1)(LOGSTDOUT, "warn:dhcp_rsp_packet_chk: invalid hw addr\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_req_packet_handle(const DHCP_PACKET *req_dhcp_pkt, const INET_INFO *info, DHCP_PACKET *rsp_dhcp_pkt)
{
    HARDWARE client_hw_addr;
    uint32_t client_ipv4_addr;

    if(EC_FALSE == dhcp_packet_get_caddr(req_dhcp_pkt, &client_hw_addr))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_req_packet_handle: get client hw addr from req dhcp packet failed\n");
        return (EC_FALSE);
    }

    //TODO: reserve client ipaddr from ipaddr pool
    memset(rsp_dhcp_pkt, 0, sizeof(DHCP_PACKET));
    if(EC_FALSE == reserve_ipv4_addr(&client_hw_addr, &client_ipv4_addr))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_req_packet_handle: reserve client ipv4 addr from pool failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == dhcp_rsp_packet_set(rsp_dhcp_pkt, info, client_ipv4_addr, &client_hw_addr))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_req_packet_handle: set rsp dhcp packet failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL dhcp_rsp_packet_handle(const DHCP_PACKET *rsp_dhcp_pkt, INET_INFO *recv_inet_info)
{
    struct sockaddr_in *ipv4_addr_sa;

    ipv4_addr_sa = (struct sockaddr_in *)&(recv_inet_info->ifr_ipv4.ifr_addr);
    ipv4_addr_sa->sin_addr.s_addr = dhcp_packet_get_client_addr(rsp_dhcp_pkt);
    ipv4_addr_sa->sin_family = AF_INET;

    if(EC_FALSE == dhcp_packet_get_options(rsp_dhcp_pkt, recv_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_rsp_packet_handle: get options failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_rsp_packet_handle: client %s, mask %s, bcast %s, mcast %s:%d\n",
                         c_uint32_t_ntos(dhcp_if_get_ipv4_addr(recv_inet_info)),
                         c_uint32_t_ntos(dhcp_if_get_subnet_mask(recv_inet_info)),
                         c_uint32_t_ntos(dhcp_if_get_bcast_addr(recv_inet_info)),
                         c_uint32_t_ntos(dhcp_if_get_mcast_addr(recv_inet_info)),
                         ntohs(dhcp_if_get_mcast_port(recv_inet_info))
                         );

#if 1
    if(EC_FALSE == dhcp_if_set_info(recv_inet_info->name, recv_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_rsp_packet_handle: set netcard recv_inet_info failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == dhcp_if_chk_info(recv_inet_info->name, recv_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_rsp_packet_handle: chk netcard recv_inet_info failed\n");
        return (EC_FALSE);
    }

#if 0/*not suitable for CDLinux*/
    if(EC_FALSE == dhcp_if_enable_onboot(recv_inet_info->name, recv_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_rsp_packet_handle: enable netcard onboot failed\n");
        return (EC_FALSE);
    }
#endif
    return (EC_TRUE);
#else
    dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_rsp_packet_handle: NOT SET IPADDR TO NETCARD!\n");
    return (EC_FALSE);
#endif
}

DHCP_PACKET * dhcp_client_wait_rsp(const INET_INFO *send_inet_info, INET_INFO *recv_inet_info)
{
    DHCP_PACKET *rsp_dhcp_pkt;
    CTIMET start;
    CTIMET cur;

    c_time(&start);
    for(c_time(&cur); CTIMET_DIFF(start, cur) < 0.0 + 3/*3 seconds*/; c_time(&cur))
    {
        if(EC_FALSE == dhcp_packet_recv(&rsp_dhcp_pkt, recv_inet_info))
        {
            //dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: recv rsp dhcp packet failed\n");
            continue;
        }

        if(EC_FALSE == dhcp_packet_filter(rsp_dhcp_pkt, BOOTREPLY))
        {
            continue;
        }

        //dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_client_do: after recv rsp dhcp packet\n");

        if(EC_TRUE == dhcp_rsp_packet_chk(rsp_dhcp_pkt, send_inet_info))
        {
            return (rsp_dhcp_pkt);
        }

        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: chk rsp dhcp packet failed\n");
        //usleep(10);
    }

    return (NULL_PTR);
}

EC_BOOL dhcp_server_do(const char *netcard, const UINT32 mcast_addr, const UINT32 mcast_port)
{
    INET_INFO *send_inet_info;
    INET_INFO *recv_inet_info;
    uint32_t _mcast_addr;
    uint16_t _mcast_port;

    dhcp_set_local_port(DHCP_SERVER_PORT);

    send_inet_info = dhcp_if_new(netcard, DHCP_PACKET_BUFF_MAX);
    assert(NULL_PTR != send_inet_info);
    if(EC_FALSE == dhcp_if_register_send(send_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_server_do: register dhcp send failed\n");
        dhcp_if_free(send_inet_info);
        return (EC_FALSE);
    }

    recv_inet_info = dhcp_if_new(netcard, DHCP_PACKET_BUFF_MAX);
    assert(NULL_PTR != recv_inet_info);
    if(EC_FALSE == dhcp_if_register_recv(recv_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_server_do: register dhcp recv failed\n");
        dhcp_if_free(recv_inet_info);
        return (EC_FALSE);
    }

    //TODO: query mcast info
    _mcast_addr = (uint32_t)mcast_addr;
    _mcast_port = (uint16_t)mcast_port;
    send_inet_info->mcast.sin_family = AF_INET;
    send_inet_info->mcast.sin_port   = htons(_mcast_port);/*<65535*/
    send_inet_info->mcast.sin_addr.s_addr = htonl(_mcast_addr);

    dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_server_do: start bcast on netcard %s with mcast %s:%ld\n",
                        netcard, c_word_to_ipv4(mcast_addr), mcast_port);

    for(;;)
    {
        DHCP_PACKET  *req_dhcp_pkt;
        DHCP_PACKET   rsp_dhcp_pkt;

        if(EC_FALSE == dhcp_packet_recv(&req_dhcp_pkt, recv_inet_info))
        {
            //dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_server_do: recv req dhcp packet failed\n");
            continue;
        }

        if(EC_FALSE == dhcp_packet_filter(req_dhcp_pkt, BOOTREQUEST))
        {
            continue;
        }

        dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_server_do: after recv req dhcp packet\n");

        if(EC_FALSE == dhcp_req_packet_chk(req_dhcp_pkt))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_server_do: chk req dhcp packet failed\n");
            continue;
        }

        if(EC_FALSE == dhcp_req_packet_handle(req_dhcp_pkt, send_inet_info, &rsp_dhcp_pkt))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_server_do: handle req dhcp packet failed\n");
            continue;
        }

        dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_server_do: after handle req dhcp packet\n");

        if(EC_FALSE == dhcp_packet_send(&rsp_dhcp_pkt, DHCP_CLIENT_PORT, send_inet_info))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_server_do: send rsp dhcp packet failed\n");
            continue;
        }

        dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_server_do: after send rsp dhcp packet\n");

        /*start mcast udp server*/
        super_start_mcast_udp_server(0);

        //sleep(1);
    }
    dhcp_if_free(send_inet_info);
    dhcp_if_free(recv_inet_info);
    return (EC_TRUE);
}

EC_BOOL dhcp_client_do(const char *netcard, UINT32 *mcast_addr, UINT32 *mcast_port)
{
    INET_INFO *send_inet_info;
    INET_INFO *recv_inet_info;

    dhcp_set_local_port(DHCP_CLIENT_PORT);

    send_inet_info = dhcp_if_new(netcard, DHCP_PACKET_BUFF_MAX);
    assert(NULL_PTR != send_inet_info);
    if(EC_FALSE == dhcp_if_register_send(send_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: register dhcp send failed\n");
        dhcp_if_free(send_inet_info);
        return (EC_FALSE);
    }

    recv_inet_info = dhcp_if_new(netcard, DHCP_PACKET_BUFF_MAX);
    assert(NULL_PTR != recv_inet_info);
    if(EC_FALSE == dhcp_if_register_recv(recv_inet_info))
    {
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: register dhcp recv failed\n");
        dhcp_if_free(recv_inet_info);
        return (EC_FALSE);
    }

    for(;;)
    {
        DHCP_PACKET  req_dhcp_pkt;
        DHCP_PACKET *rsp_dhcp_pkt;

        //sleep(1);

        if(EC_FALSE == dhcp_req_packet_set(&req_dhcp_pkt, send_inet_info))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: set req dhcp packet failed\n");
            continue;
        }

        if(EC_FALSE == dhcp_packet_send(&req_dhcp_pkt, DHCP_SERVER_PORT, send_inet_info))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: send req dhcp packet failed\n");
            continue;
        }
        dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_client_do: after send req dhcp packet\n");

        rsp_dhcp_pkt = dhcp_client_wait_rsp(send_inet_info, recv_inet_info);
        if(NULL_PTR == rsp_dhcp_pkt)
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: wait rsp dhcp packet failed\n");
            continue;
        }
        dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: after wait rsp dhcp packet\n");

        if(EC_FALSE == dhcp_rsp_packet_chk(rsp_dhcp_pkt, send_inet_info))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: chk rsp dhcp packet failed\n");
            continue;
        }

        if(EC_FALSE == dhcp_rsp_packet_handle(rsp_dhcp_pkt, recv_inet_info))
        {
            dbg_log(SEC_0084_DHCP, 0)(LOGSTDOUT, "error:dhcp_client_do: handle rsp dhcp packet failed\n");
            continue;
        }
        dbg_log(SEC_0084_DHCP, 9)(LOGSTDOUT, "[DEBUG] dhcp_client_do: after handle rsp dhcp packet\n");

        /*terminate*/
        break;
        //sleep(1);
    }

    (*mcast_addr) = ntohl(dhcp_if_get_mcast_addr(recv_inet_info));
    (*mcast_port) = ntohs(dhcp_if_get_mcast_port(recv_inet_info));

    dhcp_if_free(send_inet_info);
    dhcp_if_free(recv_inet_info);
    return(EC_TRUE);
}

EC_BOOL reserve_ipv4_addr(const HARDWARE *hw, uint32_t *ipv4_addr)
{
    return task_brd_default_reserve_ipv4_addr(hw, ipv4_addr);
}

EC_BOOL release_ipv4_addr(const HARDWARE *hw, const uint32_t ipv4_addr)
{
    return task_brd_default_release_ipv4_addr(hw, ipv4_addr);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/


