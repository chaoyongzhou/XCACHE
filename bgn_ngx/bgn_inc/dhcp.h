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

#ifndef _DHCP_H
#define _DHCP_H

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

#include "type.h"

#define DHCP_PACKET_BUFF_MAX        (4096)
#define IFCFG_FNAME_MAX             (256)
#define IFCFG_SCRIPT_MAX            (1024)

#define DHCP_DEFAULT_MCAST_ROUTE_IPADDR_STR  ((const char *)"239.2.11.71")
#define DHCP_DEFAULT_MCAST_ROUTE_MASK_STR    ((const char *)"255.255.255.255")
#define DHCP_DEFAULT_MCAST_ROUTE_GATEWAY_STR ((const char *)"0.0.0.0")

typedef struct
{
    uint8_t hlen;
    uint8_t hbuf [17];
}HARDWARE;

#define INTERFACE_REQUESTED  1
#define INTERFACE_AUTOMATIC  2
#define INTERFACE_RUNNING    4
#define INTERFACE_DOWNSTREAM 8
#define INTERFACE_UPSTREAM   16
#define INTERFACE_STREAMS    (INTERFACE_DOWNSTREAM | INTERFACE_UPSTREAM)


typedef struct
{
    HARDWARE hw_address;

    char name [IFNAMSIZ];     /* Its name... */
    int index;                /* Its if_nametoindex(). */
    int rfdesc;               /* Its read file descriptor. */
    int wfdesc;               /* Its write file descriptor, if different. */
    unsigned char *rbuf;      /* Read buffer, if required. */
    unsigned int   rbuf_max;  /* Size of read buffer. */

    //ssize_t rbuf_offset;      /* Current offset into buffer. range {0, ....}*/
    ssize_t rbuf_len;         /* Length of data in buffer. range {-1, 0, ....}*/

    /*hansoul note: in order to support more protocols, */
    /*we use the general structer to represent address info*/
    struct ifreq ifr_hw;      /* Pointer to ifreq struct. used when send packet */
    struct ifreq ifr_ipv4;    /* in network byte order*/
    struct ifreq ifr_mask;    /* in network byte order*/
    struct ifreq ifr_bcast;   /* in network byte order*/
    struct sockaddr_in mcast; /* in network byte order*/
}INET_INFO;

#define DHCP_UDP_OVERHEAD    (20 + /* IP header */            \
                              8)   /* UDP header */

#define DHCP_SNAME_LEN        64
#define DHCP_FILE_LEN         128
#define DHCP_FIXED_NON_UDP    236
#define DHCP_FIXED_LEN        (DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
                        /* Everything but options. */
#define BOOTP_MIN_LEN         300

#define DHCP_MTU_MAX          1500
#define DHCP_MTU_MIN          576

#define DHCP_MAX_OPTION_LEN   (DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN   (DHCP_MTU_MIN - DHCP_FIXED_LEN)

#if 0
/* Internet address. */
struct in_addr {
        __u32   s_addr;
};
#endif

#if 0
struct sockaddr_in {
  sa_family_t           sin_family;     /* Address family               */
  unsigned short int    sin_port;       /* Port number                  */
  struct in_addr        sin_addr;       /* Internet address             */

  /* Pad to size of `struct sockaddr'. */
  unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct in_addr)];
};
#endif

#if 0
struct sockaddr {
        sa_family_t     sa_family;      /* address family, AF_xxx       */
        char            sa_data[14];    /* 14 bytes of protocol address */
};
#endif

#if 0
struct ifreq
{
#define IFHWADDRLEN     6
        union
        {
                char    ifrn_name[IFNAMSIZ];            /* if name, e.g. "en0" */
        } ifr_ifrn;

        union {
                struct  sockaddr ifru_addr;
                struct  sockaddr ifru_dstaddr;
                struct  sockaddr ifru_broadaddr;
                struct  sockaddr ifru_netmask;
                struct  sockaddr ifru_hwaddr;
                short   ifru_flags;
                int     ifru_ivalue;
                int     ifru_mtu;
                struct  ifmap ifru_map;
                char    ifru_slave[IFNAMSIZ];   /* Just fits the size */
                char    ifru_newname[IFNAMSIZ];
                void *  ifru_data;
                struct  if_settings ifru_settings;
        } ifr_ifru;
};

#define ifr_name        ifr_ifrn.ifrn_name      /* interface name       */
#define ifr_hwaddr      ifr_ifru.ifru_hwaddr    /* MAC address          */
#define ifr_addr        ifr_ifru.ifru_addr      /* address              */
#define ifr_dstaddr     ifr_ifru.ifru_dstaddr   /* other end of p-p lnk */
#define ifr_broadaddr   ifr_ifru.ifru_broadaddr /* broadcast address    */
#define ifr_netmask     ifr_ifru.ifru_netmask   /* interface net mask   */
#define ifr_flags       ifr_ifru.ifru_flags     /* flags                */
#define ifr_metric      ifr_ifru.ifru_ivalue    /* metric               */
#define ifr_mtu         ifr_ifru.ifru_mtu       /* mtu                  */
#define ifr_map         ifr_ifru.ifru_map       /* device map           */
#define ifr_slave       ifr_ifru.ifru_slave     /* slave device         */
#define ifr_data        ifr_ifru.ifru_data      /* for use by interface */
#define ifr_ifindex     ifr_ifru.ifru_ivalue    /* interface index      */
#define ifr_bandwidth   ifr_ifru.ifru_ivalue    /* link bandwidth       */
#define ifr_qlen        ifr_ifru.ifru_ivalue    /* Queue length         */
#define ifr_newname     ifr_ifru.ifru_newname   /* New name             */
#define ifr_settings    ifr_ifru.ifru_settings  /* Device/proto settings*/
#endif

typedef struct
{
    uint8_t  op;             /* 0: Message opcode/type: BOOTREQUEST or BOOTREPLY */
    uint8_t  htype;          /* 1: Hardware addr type (net/if_types.h) */
    uint8_t  hlen;           /* 2: Hardware addr length */
    uint8_t  hops;           /* 3: Number of relay agent hops from client */
    uint32_t xid;            /* 4: Transaction ID */
    uint16_t secs;           /* 8: Seconds since client started looking */
    uint16_t flags;          /* 10: Flag bits */
    struct in_addr ciaddr;    /* 12: Client IP address (if already in use) */
    struct in_addr yiaddr;    /* 16: Client IP address */
    struct in_addr siaddr;    /* 18: IP address of next server to talk to */
    struct in_addr giaddr;    /* 20: DHCP relay agent IP address */
    unsigned char chaddr [16];    /* 24: Client hardware address */
    char sname [DHCP_SNAME_LEN];  /* 40: Server name */
    char file [DHCP_FILE_LEN];    /* 104: Boot filename */
    unsigned char options [DHCP_MAX_OPTION_LEN];/* 212: Optional parameters(actual length dependent on MTU). */
}DHCP_PACKET;

/* BOOTP (rfc951) message types */
#define BOOTREQUEST    1
#define BOOTREPLY      2

#define BOOTP_BROADCAST 0x8000

#define DHCP_OPTIONS_COOKIE    ((const char *)"\143\202\123\143")

/*
 * Ethernet address - 6 octets
 * this is only used by the ethers(3) functions.
 */
typedef struct
{
    uint8_t ether_addr_octet[6];
}ETH_ADDR;

/*
 * Structure of a 10Mb/s Ethernet header.
 */
#ifndef ETHER_ADDR_LEN
#define    ETHER_ADDR_LEN    6
#endif/*ETHER_ADDR_LEN*/

typedef struct
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
}ISC_ETH_HEADER;

#define       ETHERTYPE_PUP           0x0200  /* PUP protocol */
#define       ETHERTYPE_IP            0x0800  /* IP protocol */
#define       ETHERTYPE_ARP           0x0806  /* address resolution protocol */

#define ETHER_HEADER_SIZE (ETHER_ADDR_LEN * 2 + sizeof (uint16_t))


/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
typedef struct
{
    uint16_t uh_sport;      /* source port */
    uint16_t uh_dport;      /* destination port */
    uint16_t uh_ulen;       /* udp length */
    uint16_t uh_sum;        /* udp checksum */
}UDP_HEADER;

#define    IPVERSION    4

/*
 * Structure of an internet header, naked of options.
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
#define IP_DF      0x4000            /* dont fragment flag */
#define IP_MF      0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */

typedef struct
{
    uint8_t  ip_fvhl;       /* header length, version */
    uint8_t  ip_tos;        /* type of service */
    int16_t  ip_len;        /* total length */
    uint16_t ip_id;         /* identification */
    int16_t  ip_off;        /* fragment offset field */
    uint8_t  ip_ttl;        /* time to live */
    uint8_t  ip_p;          /* protocol */
    uint16_t ip_sum;        /* checksum */
    struct in_addr ip_src;   /* source address */
    struct in_addr ip_dst;   /* dest address */
}IP_HEADER;

#define IP_V(iph)           ((iph)->ip_fvhl >> 4)
#define IP_HL(iph)          (((iph)->ip_fvhl & 0x0F) << 2)
#define IP_V_SET(iph,x)     ((iph)->ip_fvhl = ((iph)->ip_fvhl & 0x0F) | ((x) << 4))
#define IP_HL_SET(iph,x)    ((iph)->ip_fvhl = ((iph)->ip_fvhl & 0xF0) | (((x) >> 2) & 0x0F))

#define IP_MAXPACKET    65535        /* maximum packet size */

/*
 * Definitions for IP type of service (ip_tos)
 */
#define IPTOS_LOWDELAY       0x10
#define IPTOS_THROUGHPUT     0x08
#define IPTOS_RELIABILITY    0x04

/* Possible values for hardware type (htype) field... */
#define HTYPE_ETHER    1               /* Ethernet 10Mbps              */
#define HTYPE_IEEE802  6               /* IEEE 802.2 Token Ring...    */
#define HTYPE_FDDI     8               /* FDDI...            */

#define DHCP_CLIENT_PORT       ((uint16_t) 546)
#define DHCP_SERVER_PORT       ((uint16_t) 547)

/* DHCP Option codes: */
#define DHO_PAD                          ((uint8_t)    0)
#define DHO_SUBNET_MASK                  ((uint8_t)    1)
#define DHO_TIME_OFFSET                  ((uint8_t)    2)
#define DHO_ROUTERS                      ((uint8_t)    3)
#define DHO_TIME_SERVERS                 ((uint8_t)    4)
#define DHO_NAME_SERVERS                 ((uint8_t)    5)
#define DHO_DOMAIN_NAME_SERVERS          ((uint8_t)    6)
#define DHO_LOG_SERVERS                  ((uint8_t)    7)
#define DHO_COOKIE_SERVERS               ((uint8_t)    8)
#define DHO_LPR_SERVERS                  ((uint8_t)    9)
#define DHO_IMPRESS_SERVERS              ((uint8_t)   10)
#define DHO_RESOURCE_LOCATION_SERVERS    ((uint8_t)   11)
#define DHO_HOST_NAME                    ((uint8_t)   12)
#define DHO_BOOT_SIZE                    ((uint8_t)   13)
#define DHO_MERIT_DUMP                   ((uint8_t)   14)
#define DHO_DOMAIN_NAME                  ((uint8_t)   15)
#define DHO_SWAP_SERVER                  ((uint8_t)   16)
#define DHO_ROOT_PATH                    ((uint8_t)   17)
#define DHO_EXTENSIONS_PATH              ((uint8_t)   18)
#define DHO_IP_FORWARDING                ((uint8_t)   19)
#define DHO_NON_LOCAL_SOURCE_ROUTING     ((uint8_t)   20)
#define DHO_POLICY_FILTER                ((uint8_t)   21)
#define DHO_MAX_DGRAM_REASSEMBLY         ((uint8_t)   22)
#define DHO_DEFAULT_IP_TTL               ((uint8_t)   23)
#define DHO_PATH_MTU_AGING_TIMEOUT       ((uint8_t)   24)
#define DHO_PATH_MTU_PLATEAU_TABLE       ((uint8_t)   25)
#define DHO_INTERFACE_MTU                ((uint8_t)   26)
#define DHO_ALL_SUBNETS_LOCAL            ((uint8_t)   27)
#define DHO_BROADCAST_ADDRESS            ((uint8_t)   28)
#define DHO_PERFORM_MASK_DISCOVERY       ((uint8_t)   29)
#define DHO_MASK_SUPPLIER                ((uint8_t)   30)
#define DHO_ROUTER_DISCOVERY             ((uint8_t)   31)
#define DHO_ROUTER_SOLICITATION_ADDRESS  ((uint8_t)   32)
#define DHO_STATIC_ROUTES                ((uint8_t)   33)
#define DHO_TRAILER_ENCAPSULATION        ((uint8_t)   34)
#define DHO_ARP_CACHE_TIMEOUT            ((uint8_t)   35)
#define DHO_IEEE802_3_ENCAPSULATION      ((uint8_t)   36)
#define DHO_DEFAULT_TCP_TTL              ((uint8_t)   37)
#define DHO_TCP_KEEPALIVE_INTERVAL       ((uint8_t)   38)
#define DHO_TCP_KEEPALIVE_GARBAGE        ((uint8_t)   39)
#define DHO_NIS_DOMAIN                   ((uint8_t)   40)
#define DHO_NIS_SERVERS                  ((uint8_t)   41)
#define DHO_NTP_SERVERS                  ((uint8_t)   42)
#define DHO_VENDOR_ENCAPSULATED_OPTIONS  ((uint8_t)   43)
#define DHO_NETBIOS_NAME_SERVERS         ((uint8_t)   44)
#define DHO_NETBIOS_DD_SERVER            ((uint8_t)   45)
#define DHO_NETBIOS_NODE_TYPE            ((uint8_t)   46)
#define DHO_NETBIOS_SCOPE                ((uint8_t)   47)
#define DHO_FONT_SERVERS                 ((uint8_t)   48)
#define DHO_X_DISPLAY_MANAGER            ((uint8_t)   49)
#define DHO_DHCP_REQUESTED_ADDRESS       ((uint8_t)   50)
#define DHO_DHCP_LEASE_TIME              ((uint8_t)   51)
#define DHO_DHCP_OPTION_OVERLOAD         ((uint8_t)   52)
#define DHO_DHCP_MESSAGE_TYPE            ((uint8_t)   53)
#define DHO_DHCP_SERVER_IDENTIFIER       ((uint8_t)   54)
#define DHO_DHCP_PARAMETER_REQUEST_LIST  ((uint8_t)   55)
#define DHO_DHCP_MESSAGE                 ((uint8_t)   56)
#define DHO_DHCP_MAX_MESSAGE_SIZE        ((uint8_t)   57)
#define DHO_DHCP_RENEWAL_TIME            ((uint8_t)   58)
#define DHO_DHCP_REBINDING_TIME          ((uint8_t)   59)
#define DHO_VENDOR_CLASS_IDENTIFIER      ((uint8_t)   60)
#define DHO_DHCP_CLIENT_IDENTIFIER       ((uint8_t)   61)
#define DHO_NWIP_DOMAIN_NAME             ((uint8_t)   62)
#define DHO_NWIP_SUBOPTIONS              ((uint8_t)   63)
#define DHO_USER_CLASS                   ((uint8_t)   77)
#define DHO_FQDN                         ((uint8_t)   81)
#define DHO_DHCP_AGENT_OPTIONS           ((uint8_t)   82)
#define DHO_AUTHENTICATE                 ((uint8_t)   90)/* RFC3118, was 210 */
#define DHO_CLIENT_LAST_TRANSACTION_TIME ((uint8_t)   91)
#define DHO_ASSOCIATED_IP                ((uint8_t)   92)
#define DHO_SUBNET_SELECTION             ((uint8_t)  118)/* RFC3011! */
#define DHO_DOMAIN_SEARCH                ((uint8_t)  119)/* RFC3397 */
#define DHO_VIVCO_SUBOPTIONS             ((uint8_t)  124)
#define DHO_VIVSO_SUBOPTIONS             ((uint8_t)  125)
#define DHO_MULTICAST_ADDRESS            ((uint8_t)  129)/*Hansoul*/
#define DHO_MULTICAST_PORT               ((uint8_t)  130)/*Hansoul*/
#define DHO_END                          ((uint8_t)  255)

void dhcp_set_local_port(const uint16_t local_port);

uint16_t dhcp_get_local_port();

INET_INFO *dhcp_if_new(const char *netcard_name, const uint32_t rbuf_max);

EC_BOOL dhcp_if_init(INET_INFO *info, const char *netcard_name, const uint32_t rbuf_max);

EC_BOOL dhcp_if_clean(INET_INFO *info);

void dhcp_if_free(INET_INFO *info);

int dhcp_if_register_lpf (INET_INFO *info);

EC_BOOL dhcp_if_register_recv (INET_INFO *info);

void    dhcp_if_deregister_recv (INET_INFO *info);

EC_BOOL dhcp_if_register_send (INET_INFO *info);

void    dhcp_if_deregister_send (INET_INFO *info);

HARDWARE *dhcp_if_get_hw_addr(const INET_INFO *info);

uint32_t dhcp_if_get_subnet_mask(const INET_INFO *info);

uint32_t dhcp_if_get_bcast_addr(const INET_INFO *info);

uint32_t dhcp_if_get_ipv4_addr(const INET_INFO *info);

uint32_t dhcp_if_get_mcast_addr(const INET_INFO *info);

uint16_t dhcp_if_get_mcast_port(const INET_INFO *info);

EC_BOOL dhcp_if_enable_onboot(const char *netcard, const INET_INFO *info);

EC_BOOL dhcp_if_set_mcast_route(int sock, const char *netcard);

EC_BOOL dhcp_if_get_info(const char *netcard, INET_INFO *info);

EC_BOOL dhcp_if_set_info(const char *netcard, INET_INFO *info);

EC_BOOL dhcp_if_chk_info(const char *netcard, const INET_INFO *info);

EC_BOOL dhcp_if_get_hw_addr_info(int sock, const char *netcard, INET_INFO *info);

EC_BOOL dhcp_if_get_subnet_mask_info(int sock, const char *netcard, INET_INFO *info);

EC_BOOL dhcp_if_set_subnet_mask_info(int sock, const char *netcard, const INET_INFO *info);

EC_BOOL dhcp_if_chk_subnet_mask_info(int sock, const char *netcard, const INET_INFO *info);

EC_BOOL dhcp_if_get_bcast_addr_info(int sock, const char *netcard, INET_INFO *info);

EC_BOOL dhcp_if_set_bcast_addr_info(int sock, const char *netcard, const INET_INFO *info);

EC_BOOL dhcp_if_chk_bcast_addr_info(int sock, const char *netcard, const INET_INFO *info);

EC_BOOL dhcp_if_get_ipv4_addr_info(int sock, const char *netcard, INET_INFO *info);

EC_BOOL dhcp_if_set_ipv4_addr_info(int sock, const char *netcard, const INET_INFO *info);

EC_BOOL dhcp_if_chk_ipv4_addr_info(int sock, const char *netcard, const INET_INFO *info);

void dhcp_if_assemble_eth_header (
                                        const INET_INFO *inet_info,
                                        unsigned char *buf,
                                        unsigned *bufix,
                                        const HARDWARE *to);

void dhcp_if_assemble_hw_header (
                                const INET_INFO *inet_info,
                                unsigned char *buf,
                                unsigned *bufix,
                                const HARDWARE *to);

void dhcp_if_assemble_udp_ip_header (
                                    const INET_INFO *inet_info,
                                    unsigned char *buf,
                                    unsigned *bufix,
                                    uint32_t from,
                                    uint32_t to,
                                    uint32_t dport,
                                    unsigned char *data,
                                    unsigned len);

ssize_t dhcp_if_decode_hw_header (
                                INET_INFO *inet_info,
                                unsigned char *buf,
                                unsigned bufix,
                                HARDWARE *from);

ssize_t dhcp_if_decode_eth_header (
                                        INET_INFO *inet_info,
                                        unsigned char *buf,
                                        unsigned bufix,
                                        HARDWARE *from);

ssize_t dhcp_if_decode_udp_ip_header(
                                     INET_INFO *inet_info,
                                     unsigned char *buf,
                                     unsigned bufix,
                                     struct sockaddr_in *from,
                                     unsigned buflen,
                                     unsigned *rbuflen);

ssize_t dhcp_if_send ( const INET_INFO *inet_info,
                                    const uint8_t *data,
                                    const size_t len,
                                    const struct in_addr from,
                                    const struct sockaddr_in *to,
                                    const HARDWARE *hto);

ssize_t dhcp_if_recv ( INET_INFO *inet_info,
                                    unsigned char *buf,
                                    size_t len,
                                    struct sockaddr_in *from,
                                    HARDWARE *hfrom);

EC_BOOL dhcp_if_check_ipv4_defined(const char *netcard);

void dhcp_print_hw_addr(LOG *log, const HARDWARE *hw);

EC_BOOL dhcp_packet_set_caddr(DHCP_PACKET *dhcp_pkt, const HARDWARE *hw);

EC_BOOL dhcp_packet_get_caddr(const DHCP_PACKET *dhcp_pkt, HARDWARE *hw);

EC_BOOL dhcp_packet_chk_caddr(const DHCP_PACKET *dhcp_pkt, const HARDWARE *hw);

EC_BOOL dhcp_packet_get_options(const DHCP_PACKET *dhcp_pkt, INET_INFO *info);

void dhcp_packet_print_chaddr(LOG *log, const DHCP_PACKET *dhcp_pkt);

void dhcp_packet_print_options(LOG *log, const DHCP_PACKET *dhcp_pkt);

EC_BOOL dhcp_packet_set_cookie(DHCP_PACKET *dhcp_pkt, uint32_t *offset);

char *  dhcp_packet_get_cookie(const DHCP_PACKET *dhcp_pkt, uint32_t *offset);

EC_BOOL dhcp_packet_chk_cookie(const DHCP_PACKET *dhcp_pkt);

/*subnet mask is in network byte order*/
EC_BOOL dhcp_packet_set_subnet_mask(DHCP_PACKET *dhcp_pkt, const uint32_t subnet_mask, uint32_t *offset);

uint32_t dhcp_packet_get_subnet_mask(const DHCP_PACKET *dhcp_pkt, uint32_t *offset);

EC_BOOL dhcp_packet_set_bcast_addr(DHCP_PACKET *dhcp_pkt, const uint32_t bcast_addr, uint32_t *offset);

uint32_t dhcp_packet_get_bcast_addr(const DHCP_PACKET *dhcp_pkt, uint32_t *offset);

EC_BOOL dhcp_packet_set_mcast_addr(DHCP_PACKET *dhcp_pkt, const uint32_t mcast_addr, uint32_t *offset);

uint32_t dhcp_packet_get_mcast_addr(const DHCP_PACKET *dhcp_pkt, uint32_t *offset);

EC_BOOL dhcp_packet_set_mcast_port(DHCP_PACKET *dhcp_pkt, const uint16_t mcast_port, uint32_t *offset);

uint16_t dhcp_packet_get_mcast_port(const DHCP_PACKET *dhcp_pkt, uint32_t *offset);

EC_BOOL  dhcp_packet_set_client_addr(DHCP_PACKET *dhcp_pkt, const uint32_t ipaddr);

uint32_t dhcp_packet_get_client_addr(const DHCP_PACKET *dhcp_pkt);

EC_BOOL   dhcp_packet_set_server_addr(DHCP_PACKET *dhcp_pkt, const uint32_t ipaddr);

uint32_t dhcp_packet_get_server_addr(const DHCP_PACKET *dhcp_pkt);

EC_BOOL   dhcp_packet_set_server_name(DHCP_PACKET *dhcp_pkt, const char * server_name);

char * dhcp_packet_get_server_name(const DHCP_PACKET *dhcp_pkt);

EC_BOOL dhcp_packet_filter(const DHCP_PACKET *dhcp_pkt, const uint8_t op);

EC_BOOL dhcp_packet_send(const DHCP_PACKET *dhcp_pkt, const uint16_t des_port, const INET_INFO *info);

EC_BOOL dhcp_packet_recv(DHCP_PACKET **recv_dhcp_pkt, INET_INFO *recv_info);

/*req packet is from client to server*/
EC_BOOL dhcp_req_packet_set(DHCP_PACKET *dhcp_pkt, const INET_INFO *info);

EC_BOOL dhcp_req_packet_chk(const DHCP_PACKET *dhcp_pkt);

/*rsp packet is from server to client*/
EC_BOOL dhcp_rsp_packet_set(DHCP_PACKET *dhcp_pkt, const INET_INFO *info,
                                    const uint32_t client_ipaddr, const HARDWARE *client_hw_addr);

EC_BOOL dhcp_rsp_packet_chk(const DHCP_PACKET *dhcp_pkt, const INET_INFO *info);

EC_BOOL dhcp_req_packet_handle(const DHCP_PACKET *req_dhcp_pkt, const INET_INFO *info, DHCP_PACKET *rsp_dhcp_pkt);

EC_BOOL dhcp_rsp_packet_handle(const DHCP_PACKET *rsp_dhcp_pkt, INET_INFO *recv_inet_info);

DHCP_PACKET * dhcp_client_wait_rsp(const INET_INFO *send_inet_info, INET_INFO *recv_inet_info);

EC_BOOL dhcp_server_do(const char *netcard, const UINT32 mcast_addr, const UINT32 mcast_port);

EC_BOOL dhcp_client_do(const char *netcard, UINT32 *mcast_addr, UINT32 *mcast_port);

EC_BOOL reserve_ipv4_addr(const HARDWARE *hw, uint32_t *ipv4_addr);

EC_BOOL release_ipv4_addr(const HARDWARE *hw, const uint32_t ipv4_addr);

#endif/* _DHCP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/


