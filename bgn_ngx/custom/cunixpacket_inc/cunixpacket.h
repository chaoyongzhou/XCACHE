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
 *                             LOG RELAY                                      *
 *              based on unix domain socket with unix packet                  *
\*----------------------------------------------------------------------------*/

#if (SWITCH_ON == NGX_BGN_SWITCH)

#ifndef _CUNIXPACKET_H
#define _CUNIXPACKET_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "ctimeout.h"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"

#define CUNIXPACKET_MODULE_NAME                          ("cunixpacket")

#define CUNIXPACKET_UDS_TIMEOUT_NSEC_DEFAULT             (60)
#define CUNIXPACKET_UDS_EXPIRED_NSEC_DEFAULT             (60)
#define CUNIXPACKET_UDS_CONNECT_NSEC_DEFAULT             (10)
#define CUNIXPACKET_UDS_MAX_PACKETS_DEFAULT              (1024)

/*unix domain socket path*/
#define CUNIXPACKET_CNGX_VAR_UDS_PATH                    ("c_unixpacket_domain_socket_path")

/*uds socket timeout/idle in second*/
#define CUNIXPACKET_CNGX_VAR_UDS_TIMEOUT_NSEC            ("c_unixpacket_domain_socket_timeout_nsec")

/*uds expired in second*/
#define CUNIXPACKET_CNGX_VAR_UDS_EXPIRED_NSEC            ("c_unixpacket_domain_socket_expired_nsec")

/*uds connect in second*/
#define CUNIXPACKET_CNGX_VAR_UDS_CONNECT_NSEC            ("c_unixpacket_domain_socket_connect_nsec")

/*max data packets in uds node*/
#define CUNIXPACKET_CNGX_VAR_UDS_MAX_PACKETS             ("c_unixpacket_domain_socket_max_packets")

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *uds_path;

    ngx_http_request_t  *ngx_http_req;

    /*--- parse from cngx http request ---*/
    uint32_t             cngx_debug_switch_on_flag :1; /*if debug mode indicated in cngx http req*/
    uint32_t             rsvd01                    :31;
    uint32_t             rsvd02;

    UINT32               content_length;
    UINT32               sent_body_size;

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/
}CUNIXPACKET_MD;

#define CUNIXPACKET_MD_TERMINATE_FLAG(cunixpacket_md)               ((cunixpacket_md)->terminate_flag)

#define CUNIXPACKET_MD_UDS_PATH(cunixpacket_md)                     ((cunixpacket_md)->uds_path)
#define CUNIXPACKET_MD_UDS_PATH_STR(cunixpacket_md)                 (cstring_get_str(CUNIXPACKET_MD_UDS_PATH(cunixpacket_md)))

#define CUNIXPACKET_MD_NGX_HTTP_REQ(cunixpacket_md)                 ((cunixpacket_md)->ngx_http_req)

#define CUNIXPACKET_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cunixpacket_md)    ((cunixpacket_md)->cngx_debug_switch_on_flag)

#define CUNIXPACKET_MD_CONTENT_LENGTH(cunixpacket_md)               ((cunixpacket_md)->content_length)

#define CUNIXPACKET_MD_SENT_BODY_SIZE(cunixpacket_md)               ((cunixpacket_md)->sent_body_size)

#define CUNIXPACKET_MD_NGX_LOC(cunixpacket_md)                      ((cunixpacket_md)->ngx_loc)
#define CUNIXPACKET_MD_NGX_RC(cunixpacket_md)                       ((cunixpacket_md)->ngx_rc)

typedef struct
{
    CSTRING             *uds_path;
    int                  uds_socket;
    uint32_t             uds_is_polling:1;          /*polling flag*/
    uint32_t             uds_is_connected:1;        /*connected flag*/
    uint32_t             rsvd:30;
    CLIST                uds_packet_list;           /*item is CBYTES*/

    uint32_t             uds_max_packets;           /*max packet num*/
    uint32_t             uds_timeout_nsec;          /*timeout in second*/
    uint32_t             uds_connect_nsec;          /*connect in second*/
    uint32_t             uds_expired_nsec;          /*expired in second*/

    uint64_t             uds_expired_timestamp;     /*next expired timestamp in second*/
    uint64_t             uds_connect_timestamp;     /*next connect timestamp in second*/
}CUNIXPACKET_UDS_NODE;

#define CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node)             ((cunixpacket_uds_node)->uds_path)
#define CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node)         (cstring_get_str(CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node)))
#define CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node)           ((cunixpacket_uds_node)->uds_socket)
#define CUNIXPACKET_UDS_NODE_IS_POLLING(cunixpacket_uds_node)       ((cunixpacket_uds_node)->uds_is_polling)
#define CUNIXPACKET_UDS_NODE_IS_CONNECTED(cunixpacket_uds_node)     ((cunixpacket_uds_node)->uds_is_connected)
#define CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node)      (&((cunixpacket_uds_node)->uds_packet_list))
#define CUNIXPACKET_UDS_NODE_MAX_PACKETS(cunixpacket_uds_node)      ((cunixpacket_uds_node)->uds_max_packets)
#define CUNIXPACKET_UDS_NODE_TIMEOUT_NSEC(cunixpacket_uds_node)     ((cunixpacket_uds_node)->uds_timeout_nsec)
#define CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node)     ((cunixpacket_uds_node)->uds_connect_nsec)
#define CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node)     ((cunixpacket_uds_node)->uds_expired_nsec)
#define CUNIXPACKET_UDS_NODE_EXPIRED_TS(cunixpacket_uds_node)       ((cunixpacket_uds_node)->uds_expired_timestamp)
#define CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node)       ((cunixpacket_uds_node)->uds_connect_timestamp)


/**
*   for test only
*
*   to query the status of CUNIXPACKET Module
*
**/
void cunixpacket_print_module_status(const UINT32 cunixpacket_md_id, LOG *log);

/**
*
* register CUNIXPACKET module
*
**/
EC_BOOL cunixpacket_reg();

/**
*
* unregister CUNIXPACKET module
*
**/
EC_BOOL cunixpacket_unreg();

/**
*
* start CUNIXPACKET module
*
**/
UINT32 cunixpacket_start(ngx_http_request_t *r);

/**
*
* end CUNIXPACKET module
*
**/
void cunixpacket_end(const UINT32 cunixpacket_md_id);

EC_BOOL cunixpacket_get_ngx_rc(const UINT32 cunixpacket_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cunixpacket_set_ngx_rc(const UINT32 cunixpacket_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cunixpacket_override_ngx_rc(const UINT32 cunixpacket_md_id, const ngx_int_t rc, const UINT32 location);

CUNIXPACKET_UDS_NODE *cunixpacket_uds_node_new();

/* one page block = 64MB */
EC_BOOL cunixpacket_uds_node_init(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node);

EC_BOOL cunixpacket_uds_node_clean(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node);

EC_BOOL cunixpacket_uds_node_free(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node);

EC_BOOL cunixpacket_uds_list_init();

EC_BOOL cunixpacket_uds_list_cleanup();

EC_BOOL cunixpacket_uds_list_destroy(const UINT32 UNUSED(none));

EC_BOOL cunixpacket_uds_node_shutdown(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node);

EC_BOOL cunixpacket_uds_node_timeout(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node);

CUNIXPACKET_UDS_NODE *cunixpacket_uds_list_search(const CSTRING *cunixpacket_uds_path);

CUNIXPACKET_UDS_NODE *cunixpacket_uds_list_add(const CSTRING *cunixpacket_uds_path, int cunixpacket_uds_socket);

EC_BOOL cunixpacket_process(const UINT32 UNUSED(none));

/**
*
* send data to unix domain socket with unixpacket
*
**/
EC_BOOL cunixpacket_send_packet(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node);

/**
*
* cache data which would be sent to unix domain socket with unixpacket
*
**/
EC_BOOL cunixpacket_send_handler(const UINT32 cunixpacket_md_id);

EC_BOOL cunixpacket_content_handler(const UINT32 cunixpacket_md_id);

EC_BOOL cunixpacket_content_send_response(const UINT32 cunixpacket_md_id);

#endif /*_CUNIXPACKET_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


