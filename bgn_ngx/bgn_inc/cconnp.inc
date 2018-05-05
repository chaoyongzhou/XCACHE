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

#ifndef _CCONNP_INC
#define _CCONNP_INC

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
#include "clist.h"
#include "crb.h"
#include "csocket.inc"

/*connection pool*/
typedef struct
{
    UINT32                         srv_ipaddr;
    UINT32                         srv_port;

    UINT32                         srv_tcid;
    UINT32                         srv_comm;
    UINT32                         srv_size;

    CQUEUE                         idle_conn_queue; /*FIFO*/
}CCONNP;

#define CCONNP_SRV_IPADDR(cconnp)                    ((cconnp)->srv_ipaddr)
#define CCONNP_SRV_PORT(cconnp)                      ((cconnp)->srv_port)

#define CCONNP_SRV_IPADDR_STR(cconnp)                c_word_to_ipv4(CCONNP_SRV_IPADDR(cconnp))

#define CCONNP_SRV_TCID(cconnp)                      ((cconnp)->srv_tcid)
#define CCONNP_SRV_COMM(cconnp)                      ((cconnp)->srv_comm)
#define CCONNP_SRV_SIZE(cconnp)                      ((cconnp)->srv_size)

#define CCONNP_SRV_TCID_STR(cconnp)                  c_word_to_ipv4(CCONNP_SRV_TCID(cconnp))

#define CCONNP_IDLE_CONN_QUEUE(cconnp)               (&((cconnp)->idle_conn_queue))

/*manager of several connection pool*/
typedef struct
{
    CRB_TREE             cconnp_tree; /*item is CCONNP*/
}CCONNP_MGR;

#define CCONNP_MGR_TREE(cconnp_mgr)                  (&((cconnp_mgr)->cconnp_tree))

#endif/*_CCONNP_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

