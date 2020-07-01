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

#ifndef _CSRV_H
#define _CSRV_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "csocket.inc"

#include "cssl.h"

struct _CSOCKET_CNODE;
struct _TASK_FUNC;

typedef  EC_BOOL (*CSRV_INIT_CSOCKET_CNODE)(const UINT32, struct _CSOCKET_CNODE *);
typedef  EC_BOOL (*CSRV_ADD_CSOCKET_CNODE)(const UINT32, struct _CSOCKET_CNODE *);
typedef  EC_BOOL (*CSRV_DEL_CSOCKET_CNODE)(const UINT32, struct _CSOCKET_CNODE *);

typedef  EC_BOOL (*CSRV_RD_HANDLER_FUNC)(struct _CSOCKET_CNODE *);
typedef  EC_BOOL (*CSRV_WR_HANDLER_FUNC)(struct _CSOCKET_CNODE *);
typedef  EC_BOOL (*CSRV_TIMEOUT_HANDLER_FUNC)(struct _CSOCKET_CNODE *);
typedef  EC_BOOL (*CSRV_COMPLETE_HANDLER_FUNC)(struct _CSOCKET_CNODE *);
typedef  EC_BOOL (*CSRV_CLOSE_HANDLER_FUNC)(struct _CSOCKET_CNODE *);

typedef struct
{
    UINT32      srv_ipaddr;
    UINT32      srv_port;
    int         srv_sockfd;
    uint32_t    timeout;/*in second*/
    UINT32      md_id;

    int         srv_unix_sockfd; /*unix domain socket*/
    int         rsvd;

    CSRV_INIT_CSOCKET_CNODE       init_csocket_cnode;
    CSRV_ADD_CSOCKET_CNODE        add_csocket_cnode;
    CSRV_DEL_CSOCKET_CNODE        del_csocket_cnode;

    const char *                  rd_name;
    const char *                  wr_name;
    const char *                  timeout_name;
    const char *                  complete_name;
    const char *                  close_name;

    CSRV_RD_HANDLER_FUNC          rd_handler;
    CSRV_WR_HANDLER_FUNC          wr_handler;
    CSRV_TIMEOUT_HANDLER_FUNC     timeout_handler;
    CSRV_COMPLETE_HANDLER_FUNC    complete_handler;
    CSRV_CLOSE_HANDLER_FUNC       close_handler;

    CSSL_NODE                    *cssl_node; /*for server over TLS. note: SSL is not used but SSL_CTX is used on server*/
}CSRV;

#define CSRV_IPADDR(csrv)               ((csrv)->srv_ipaddr)
#define CSRV_PORT(csrv)                 ((csrv)->srv_port)
#define CSRV_SOCKFD(csrv)               ((csrv)->srv_sockfd)
#define CSRV_UNIX_SOCKFD(csrv)          ((csrv)->srv_unix_sockfd)
#define CSRV_MD_ID(csrv)                ((csrv)->md_id)
#define CSRV_TIMEOUT_NSEC(csrv)         ((csrv)->timeout)

#define CSRV_INIT_CSOCKET_CNODE(csrv)   ((csrv)->init_csocket_cnode)
#define CSRV_ADD_CSOCKET_CNODE(csrv)    ((csrv)->add_csocket_cnode)
#define CSRV_DEL_CSOCKET_CNODE(csrv)    ((csrv)->del_csocket_cnode)

#define CSRV_RD_NAME(csrv)              ((csrv)->rd_name)
#define CSRV_WR_NAME(csrv)              ((csrv)->wr_name)
#define CSRV_TIMEOUT_NAME(csrv)         ((csrv)->timeout_name)
#define CSRV_COMPLETE_NAME(csrv)        ((csrv)->complete_name)
#define CSRV_CLOSE_NAME(csrv)           ((csrv)->close_name)

#define CSRV_RD_EVENT_HANDLER(csrv)     ((csrv)->rd_handler)
#define CSRV_WR_EVENT_HANDLER(csrv)     ((csrv)->wr_handler)
#define CSRV_TIMEOUT_HANDLER(csrv)      ((csrv)->timeout_handler)
#define CSRV_COMPLETE_HANDLER(csrv)     ((csrv)->complete_handler)
#define CSRV_CLOSE_HANDLER(csrv)        ((csrv)->close_handler)

#define CSRV_CSSL_NODE(csrv)            ((csrv)->cssl_node)

CSRV *csrv_new();

EC_BOOL csrv_init(CSRV *csrv);

EC_BOOL csrv_clean(CSRV *csrv);

EC_BOOL csrv_free(CSRV *csrv);

CSRV * csrv_start(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 md_id);

EC_BOOL csrv_end(CSRV *csrv);

EC_BOOL csrv_set_init_csocket_cnode_handler(CSRV *csrv, CSRV_INIT_CSOCKET_CNODE init_csocket_cnode);

EC_BOOL csrv_set_add_csocket_cnode_handler(CSRV *csrv, CSRV_ADD_CSOCKET_CNODE add_csocket_cnode);

EC_BOOL csrv_set_del_csocket_cnode_handler(CSRV *csrv, CSRV_DEL_CSOCKET_CNODE del_csocket_cnode);

EC_BOOL csrv_set_read_handler(CSRV *csrv, const char *name, CSRV_RD_HANDLER_FUNC handler);

EC_BOOL csrv_set_write_handler(CSRV *csrv, const char *name, CSRV_WR_HANDLER_FUNC handler);

EC_BOOL csrv_set_timeout_handler(CSRV *csrv, const uint32_t timeout_nsec, const char *name, CSRV_TIMEOUT_HANDLER_FUNC handler);

EC_BOOL csrv_set_complete_handler(CSRV *csrv, const char *name, CSRV_COMPLETE_HANDLER_FUNC handler);

EC_BOOL csrv_set_close_handler(CSRV *csrv, const char *name, CSRV_CLOSE_HANDLER_FUNC handler);

EC_BOOL csrv_accept_once(CSRV *csrv, EC_BOOL *continue_flag);

EC_BOOL csrv_accept(CSRV *csrv);


#endif/*_CSRV_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
