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

#ifndef _CDNS_INC
#define _CDNS_INC

#include "type.h"
#include "debug.h"

#include "croutine.h"

#include "cbuffer.h"
#include "chunk.h"
#include "csocket.inc"
#include "cstrkv.h"


/*DNS Parser Control*/
#define CDNS_PASER_PAUSED        ((int) 1)
#define CDNS_PASER_RESUME        ((int) 0)

#define CDNS_IN_BUF_SIZE         ((uint32_t)(1 * 1024))
#define CDNS_OUT_BUF_SIZE        ((uint32_t)(4 * 1024))

/*DNS query type*/
#define CDNS_QT_A                ((uint16_t)  1) /*A record, ipv4*/
#define CDNS_QT_NS               ((uint16_t)  2) /*Name Serve*/
#define CDNS_QT_CNAME            ((uint16_t)  5) /*CNAME, alias*/
#define CDNS_QT_SOA              ((uint16_t)  6) /*start OA*/
#define CDNS_QT_WKS              ((uint16_t) 11) /*net work server*/
#define CDNS_QT_PTR              ((uint16_t) 12) /*pointer, ip => domain*/
#define CDNS_QT_HINFO            ((uint16_t) 13) /*host info*/
#define CDNS_QT_MX               ((uint16_t) 15) /*email exchange*/
#define CDNS_QT_AAAA             ((uint16_t) 28) /*ipv6*/
#define CDNS_QT_AXFR             ((uint16_t)252) /*whole sector*/
#define CDNS_QT_ANY              ((uint16_t)255) /*all records*/

/*DNS query classification*/
#define CDNS_QC_INET             ((uint16_t)  1)

struct _CSOCKET_CNODE;

typedef struct
{
    uint32_t    key;
    const char *val;
}CDNS_KV;

#define CDNS_KV_KEY(cdns_kv)        ((cdns_kv)->key)
#define CDNS_KV_VAL(cdns_kv)        ((cdns_kv)->val)

typedef struct
{
    UINT32      ipaddr;
    UINT32      port;

    CSTRING     host;
}CDNS_REQ;

#define CDNS_REQ_IPADDR(cdns_req)     ((cdns_req)->ipaddr)
#define CDNS_REQ_IPADDR_STR(cdns_req) (c_word_to_ipv4(CDNS_REQ_IPADDR(cdns_req)))
#define CDNS_REQ_PORT(cdns_req)       ((cdns_req)->port)
#define CDNS_REQ_HOST(cdns_req)       (&((cdns_req)->host))
#define CDNS_REQ_HOST_STR(cdns_req)   (cstring_get_str(CDNS_REQ_HOST(cdns_req)))

typedef struct
{
    CSTRING     host;
    CSTRING     ipaddr;
}CDNS_RSP_NODE;

#define CDNS_RSP_NODE_HOST(cdns_rsp_node)              (&((cdns_rsp_node)->host))
#define CDNS_RSP_NODE_HOST_STR(cdns_rsp_node)          (CSTRING_STR(CDNS_RSP_NODE_HOST(cdns_rsp_node)))
#define CDNS_RSP_NODE_HOST_LEN(cdns_rsp_node)          (CSTRING_LEN(CDNS_RSP_NODE_HOST(cdns_rsp_node)))
#define CDNS_RSP_NODE_IPADDR(cdns_rsp_node)            (&((cdns_rsp_node)->ipaddr))
#define CDNS_RSP_NODE_IPADDR_STR(cdns_rsp_node)        (CSTRING_STR(CDNS_RSP_NODE_IPADDR(cdns_rsp_node)))
#define CDNS_RSP_NODE_IPADDR_LEN(cdns_rsp_node)        (CSTRING_LEN(CDNS_RSP_NODE_IPADDR(cdns_rsp_node)))

typedef CLIST CDNS_RSP;

struct _CSOCKET_CNODE;

typedef struct
{
    /*header: 12B*/
    uint16_t                  id;

    /*bit order: from Lo to Hi*/
    uint16_t                  flag_qr    :1; /*  Lo */
    uint16_t                  flag_opcode:4; /*  |  */
    uint16_t                  flag_aa    :1; /*  |  */
    uint16_t                  flag_tc    :1; /*  |  */
    uint16_t                  flag_rd    :1; /*  |  */
    uint16_t                  flag_ra    :1; /*  |  */
    uint16_t                  flag_zero  :3; /*  |  */
    uint16_t                  flag_rcode :4; /*  Hi */

    uint16_t                  q_num; /*query number*/
    uint16_t                  r_num; /*resource number*/
    uint16_t                  o_num; /*oauth number*/
    uint16_t                  e_num; /*extra number*/
}CDNS_HEADER;
#define CDNS_HEADER_ID(cdns_header)             ((cdns_header)->id)
#define CDNS_HEADER_FLAG_QR(cdns_header)        ((cdns_header)->flag_qr)
#define CDNS_HEADER_FLAG_OPCODE(cdns_header)    ((cdns_header)->flag_opcode)
#define CDNS_HEADER_FLAG_AA(cdns_header)        ((cdns_header)->flag_aa)
#define CDNS_HEADER_FLAG_TC(cdns_header)        ((cdns_header)->flag_tc)
#define CDNS_HEADER_FLAG_RD(cdns_header)        ((cdns_header)->flag_rd)
#define CDNS_HEADER_FLAG_RA(cdns_header)        ((cdns_header)->flag_ra)
#define CDNS_HEADER_FLAG_ZERO(cdns_header)      ((cdns_header)->flag_zero)
#define CDNS_HEADER_FLAG_RCODE(cdns_header)     ((cdns_header)->flag_rcode)
#define CDNS_HEADER_Q_NUM(cdns_header)          ((cdns_header)->q_num)
#define CDNS_HEADER_R_NUM(cdns_header)          ((cdns_header)->r_num)
#define CDNS_HEADER_O_NUM(cdns_header)          ((cdns_header)->o_num)
#define CDNS_HEADER_E_NUM(cdns_header)          ((cdns_header)->e_num)

typedef struct _CDNS_NODE
{
    CROUTINE_NODE            *croutine_node; /*croutine mounted point*/

    CROUTINE_COND            *croutine_cond;/*croutine condition lock, used when trigger dns request */

    CBUFFER                   i_buf;    /*io buffer used by dns. socket read buff, and the input buff of dns_parser*/
    CHUNK                     send_buf; /*io buffer used by dns*/

    struct _CSOCKET_CNODE    *csocket_cnode;
    //CQUEUE_DATA              *cqueue_data; /*crfsdns_node mounted point in request defer queue*/

    CDNS_REQ                 *cdns_req;
    CDNS_RSP                 *cdns_rsp;

    uint16_t                  id;
    uint16_t                  rsvd1;
    uint32_t                  rsvd2:30;
    uint32_t                  recv_complete:1;/*flag*/
    uint32_t                  coroutine_restore:1;/*flag*/
    UINT32                    query_len;

    /*extension*/
    EC_BOOL (*set_callback)(struct _CSOCKET_CNODE *, struct _CDNS_NODE *);
}CDNS_NODE;

#define CDNS_NODE_CROUTINE_NODE(cdns_node)       ((cdns_node)->croutine_node)
#define CDNS_NODE_CROUTINE_COND(cdns_node)       ((cdns_node)->croutine_cond)

#define CDNS_NODE_IN_BUF(cdns_node)              (&((cdns_node)->i_buf))
#define CDNS_NODE_SEND_BUF(cdns_node)            (&((cdns_node)->send_buf))

#define CDNS_NODE_CSOCKET_CNODE(cdns_node)       ((cdns_node)->csocket_cnode)

#define CDNS_NODE_REQ(cdns_node)                 ((cdns_node)->cdns_req)
#define CDNS_NODE_RSP(cdns_node)                 ((cdns_node)->cdns_rsp)
#define CDNS_NODE_QLEN(cdns_node)                ((cdns_node)->query_len)
#define CDNS_NODE_ID(cdns_node)                  ((cdns_node)->id)

#define CDNS_NODE_RECV_COMPLETE(cdns_node)       ((cdns_node)->recv_complete)
#define CDNS_NODE_COROUTINE_RESTORE(cdns_node)   ((cdns_node)->coroutine_restore)

#define CDNS_NODE_SET_CALLBACK_FUNC(cdns_node)   ((cdns_node)->set_callback)

typedef EC_BOOL (*CDNS_NODE_SET_CALLBACK)(struct _CSOCKET_CNODE *, struct _CDNS_NODE *);

#endif /*_CDNS_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

