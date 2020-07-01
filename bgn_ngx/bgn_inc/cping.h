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

#ifndef _CPING_H
#define _CPING_H

#include "type.h"
#include "log.h"

#include "cping.inc"

CPING_NODE *cping_node_new();

EC_BOOL cping_node_init(CPING_NODE *cping_node);

EC_BOOL cping_node_clean(CPING_NODE *cping_node);

EC_BOOL cping_node_free(CPING_NODE *cping_node);

void    cping_node_print(LOG *log, const CPING_NODE *cping_node);

EC_BOOL cping_node_icheck(CPING_NODE *cping_node);

EC_BOOL cping_node_complete(CPING_NODE *cping_node);

EC_BOOL cping_node_shutdown(CPING_NODE *cping_node);

EC_BOOL cping_node_close(CPING_NODE *cping_node);

/*disconnect socket connection*/
EC_BOOL cping_node_disconnect(CPING_NODE *cping_node);

EC_BOOL cping_node_set_socket_callback(CPING_NODE *cping_node);

EC_BOOL cping_node_set_socket_epoll(CPING_NODE *cping_node);

EC_BOOL cping_node_check(CPING_NODE *cping_node);

EC_BOOL cping_check(const UINT32 srv_ipaddr, const UINT32 srv_port, UINT32 *elapsed_msec);


#endif /*_CPING_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
