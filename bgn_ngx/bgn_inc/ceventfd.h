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

#ifndef _CEVENTFD_H
#define _CEVENTFD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

typedef struct
{
    int              event_fd;
    uint32_t         event_flag:1;      /*0: not in epoll, 1: in epoll*/
    uint32_t         rsvd0:31;

    uint32_t         rsvd1;
}CEVENTFD_NODE;

#define CEVENTFD_NODE_FD(ceventfd_node)         ((ceventfd_node)->event_fd)
#define CEVENTFD_NODE_FLAG(ceventfd_node)       ((ceventfd_node)->event_flag)


CEVENTFD_NODE *ceventfd_node_new();

EC_BOOL ceventfd_node_init(CEVENTFD_NODE *ceventfd_node);

EC_BOOL ceventfd_node_clean(CEVENTFD_NODE *ceventfd_node);

void    ceventfd_node_free(CEVENTFD_NODE *ceventfd_node);

EC_BOOL ceventfd_node_dummy(CEVENTFD_NODE *ceventfd_node);

EC_BOOL ceventfd_node_notify(CEVENTFD_NODE *ceventfd_node);


#endif /*_CEVENTFD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
