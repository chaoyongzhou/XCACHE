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

#ifndef _CEPOLL_H
#define _CEPOLL_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/epoll.h>
#include <errno.h>

#include "type.h"
#include "csocket.h"
#include "cepoll.inc"

CEPOLL *cepoll_new(const int epoll_max_event_num);

EC_BOOL cepoll_init(CEPOLL *cepoll, const int epoll_max_event_num);

EC_BOOL cepoll_clean(CEPOLL *cepoll);

EC_BOOL cepoll_free(CEPOLL *cepoll);

EC_BOOL cepoll_add(CEPOLL *cepoll, const int sockfd, const uint32_t events);

EC_BOOL cepoll_del(CEPOLL *cepoll, const int sockfd, const uint32_t events);

EC_BOOL cepoll_mod(CEPOLL *cepoll, const int sockfd, const uint32_t events);

EC_BOOL cepoll_set_reader(CEPOLL *cepoll, const int sockfd, const char *name, CEPOLL_EVENT_HANDLER rd_handler, void *arg);

EC_BOOL cepoll_set_writer(CEPOLL *cepoll, const int sockfd, const char *name, CEPOLL_EVENT_HANDLER wr_handler, void *arg);

EC_BOOL cepoll_set_complete(CEPOLL *cepoll, const int sockfd, const char *name, CEPOLL_EVENT_HANDLER complete_handler, void *arg);

EC_BOOL cepoll_set_shutdown(CEPOLL *cepoll, const int sockfd, const char *name, CEPOLL_EVENT_HANDLER shutdown_handler, void *arg);

EC_BOOL cepoll_set_timeout(CEPOLL *cepoll, const int sockfd, const uint32_t timeout_nsec, const char *name, CEPOLL_EVENT_HANDLER timeout_handler, void *arg);
  
EC_BOOL cepoll_del_events(CEPOLL *cepoll, const int sockfd, const uint32_t events);

EC_BOOL cepoll_del_event(CEPOLL *cepoll, const int sockfd, const uint32_t event);

EC_BOOL cepoll_set_event(CEPOLL *cepoll, const int sockfd, const uint32_t event, const char *name, CEPOLL_EVENT_HANDLER handler, void *arg);

EC_BOOL cepoll_del_all(CEPOLL *cepoll, const int sockfd);

EC_BOOL cepoll_clear_node(CEPOLL *cepoll, const int sockfd);

EC_BOOL cepoll_set_used(CEPOLL *cepoll, const int sockfd);

EC_BOOL cepoll_set_not_used(CEPOLL *cepoll, const int sockfd);

EC_BOOL cepoll_update_atime(CEPOLL *cepoll, const int sockfd);

EC_BOOL cepoll_set_events(CEPOLL *cepoll, const int sockfd, const uint32_t events);

EC_BOOL cepoll_set_loop_handler(CEPOLL *cepoll, const char *name, CEPOLL_LOOP_HANDLER handler, void *arg);

EC_BOOL cepoll_handle(CEPOLL *cepoll,  const int sockfd, const uint32_t events, CEPOLL_NODE  *cepoll_node);

EC_BOOL cepoll_timeout(CEPOLL *cepoll);

EC_BOOL cepoll_loop(CEPOLL *cepoll);

EC_BOOL cepoll_wait(CEPOLL *cepoll, int timeout_ms);


#endif/*_CEPOLL_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
