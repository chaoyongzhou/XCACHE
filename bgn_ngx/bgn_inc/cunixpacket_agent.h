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

/*----------------------------------------------------------------------------*\
 *                             LOG AGENT                                      *
 *              based on unix domain socket with unix packet                  *
\*----------------------------------------------------------------------------*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)

#ifndef _CUNIXPACKET_AGENT_H
#define _CUNIXPACKET_AGENT_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "ctimeout.h"

#include "chttp.h"

#include "cbuffer.h"

#define CUNIXPACKET_AGENT_MODULE_NAME                          ("cunixpacket")

#if 0
#define CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN                      ("www.logagent.com")
#define CUNIXPACKET_AGENT_HTTP_REQ_URI                         ("/logs")
#define CUNIXPACKET_AGENT_HTTP_REQ_OP                          ("log")
#define CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN                   ("4d0c1b2513cb82263814e10bf2f136ed")
#define CUNIXPACKET_AGENT_HTTP_REQ_EXPIRED_NSEC                (15)

#define CUNIXPACKET_AGENT_UDS_PACKET_MAX_SIZE                  ((uint32_t)( 4 << 10)) /*4KB*/
#define CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE                  ((uint32_t)(64 << 10)) /*64KB*/

#define CUNIXPACKET_AGENT_UDS_PACKET_CACHE_MAX_NUM             ((uint32_t)1024)
#define CUNIXPACKET_AGENT_UDS_PACKET_SENT_MAX_NUM              ((uint32_t)16)
#define CUNIXPACKET_AGENT_UDS_PACKET_RECV_MAX_NUM              ((uint32_t)256) /*once recv 256 packets from uds*/
#endif

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *uds_path;

    int                  uds_listen_socket;         /*socket listen on uds path*/
    uint32_t             uds_packet_sending:1;      /*bit flag of sending uds packet to remote http server*/
    uint32_t             rsvd:31;
    CLIST                uds_packet_list;           /*item is CBUFFER and max length is fixed 64KB*/
}CUNIXPACKET_AGENT_MD;

#define CUNIXPACKET_AGENT_MD_TERMINATE_FLAG(cunixpacket_agent_md)               ((cunixpacket_agent_md)->terminate_flag)

#define CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md)                     ((cunixpacket_agent_md)->uds_path)
#define CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md)                 (cstring_get_str(CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md)))

#define CUNIXPACKET_AGENT_MD_UDS_PACKET_SENDING(cunixpacket_agent_md)           ((cunixpacket_agent_md)->uds_packet_sending)

#define CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md)            ((cunixpacket_agent_md)->uds_listen_socket)
#define CUNIXPACKET_AGENT_MD_UDS_PACKET_LIST(cunixpacket_agent_md)              (&((cunixpacket_agent_md)->uds_packet_list))

typedef struct
{
    UINT32          uds_agent_modi;
    int             uds_data_socket;
    int             rsvd;
}CUNIXPACKET_AGENT_NODE;

#define CUNIXPACKET_AGENT_NODE_UDS_MODI(cunixpacket_agent_node)                 ((cunixpacket_agent_node)->uds_agent_modi)
#define CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node)               ((cunixpacket_agent_node)->uds_data_socket)

/**
*   for test only
*
*   to query the status of CUNIXPACKET_AGENT Module
*
**/
void cunixpacket_agent_print_module_status(const UINT32 cunixpacket_agent_md_id, LOG *log);

/**
*
* register CUNIXPACKET_AGENT module
*
**/
EC_BOOL cunixpacket_agent_reg();

/**
*
* unregister CUNIXPACKET_AGENT module
*
**/
EC_BOOL cunixpacket_agent_unreg();

/**
*
* start CUNIXPACKET_AGENT module
*
**/
UINT32 cunixpacket_agent_start(const CSTRING *uds_path);

/**
*
* end CUNIXPACKET_AGENT module
*
**/
void cunixpacket_agent_end(const UINT32 cunixpacket_agent_md_id);

CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node_new();

EC_BOOL cunixpacket_agent_node_init(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node);

EC_BOOL cunixpacket_agent_node_clean(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node);

EC_BOOL cunixpacket_agent_node_free(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node);

/**
*
* listen on unix domain socket with unixpacket and accept new connection
*
**/
EC_BOOL cunixpacket_agent_accept(const UINT32 cunixpacket_agent_md_id);

/**
*
* send all packet data to remote http server
*
**/
EC_BOOL cunixpacket_agent_process_packet(const UINT32 cunixpacket_agent_md_id);


EC_BOOL cunixpacket_agent_process(const UINT32 cunixpacket_agent_md_id);


#endif /*_CUNIXPACKET_AGENT_H*/

#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


