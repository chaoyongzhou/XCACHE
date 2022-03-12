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

#ifndef _CSOCKET_H
#define _CSOCKET_H

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
#include "crbuff.h"
#include "cbytes.h"
#include "task.inc"

#include "taskcfg.h"
#include "taskcfg.inc"
#include "mod.inc"
#include "task.inc"
#include "csocket.inc"

#include "ccallback.h"

struct _TASK_NODE;

void    csocket_tcpi_stat_print(LOG *log, const int sockfd);

void    sockfd_print(LOG *log, const void *data);

EC_BOOL csocket_cnode_init(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_clean(CSOCKET_CNODE *csocket_cnode);

CSOCKET_CNODE * csocket_cnode_new(const UINT32 location);

EC_BOOL csocket_cnode_free(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_set_recv_callback(CSOCKET_CNODE *csocket_cnode, const char *name, void *data, void *func);

EC_BOOL csocket_cnode_set_send_callback(CSOCKET_CNODE *csocket_cnode, const char *name, void *data, void *func);

EC_BOOL csocket_cnode_set_complete_callback(CSOCKET_CNODE *csocket_cnode, const char *name, void *data, void *func);

EC_BOOL csocket_cnode_set_close_callback(CSOCKET_CNODE *csocket_cnode, const char *name, void *data, void *func);

EC_BOOL csocket_cnode_set_shutdown_callback(CSOCKET_CNODE *csocket_cnode, const char *name, void *data, void *func);

EC_BOOL csocket_cnode_set_timeout_callback(CSOCKET_CNODE *csocket_cnode, const char *name, void *data, void *func);

EC_BOOL csocket_cnode_clean_recv_callback(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_clean_send_callback(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_clean_complete_callback(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_clean_close_callback(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_clean_shutdown_callback(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_clean_timeout_callback(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_close(CSOCKET_CNODE *csocket_cnode);

CSOCKET_CNODE * csocket_cnode_unix_new(const UINT32 tcid, const int sockfd, const uint32_t type, const UINT32 ipaddr, const UINT32 srvport);

void    csocket_cnode_close_and_clean_event(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_set_disconnected(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_irecv(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_isend(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_icomplete(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_ishutdown(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_iclose(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_itimeout(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_is_nonblock(const CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_is_connected(const CSOCKET_CNODE *csocket_cnode);

void    csocket_cnode_print(LOG *log, const CSOCKET_CNODE *csocket_cnode);

const char *csocket_cnode_tcpi_stat_desc(const CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_cnode_send(CSOCKET_CNODE *csocket_cnode, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos);

EC_BOOL csocket_cnode_recv(CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);

EC_BOOL csocket_cnode_udp_send(CSOCKET_CNODE *csocket_cnode, const UINT8 * out_buff, const UINT32 out_buff_max_len, UINT32 * pos);

EC_BOOL csocket_cnode_udp_recv(CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);

EC_BOOL csocket_fd_clean(FD_CSET *sockfd_set);

EC_BOOL csocket_fd_set(const int sockfd, FD_CSET *sockfd_set, int *max_sockfd);

EC_BOOL csocket_fd_isset(const int sockfd, FD_CSET *sockfd_set);

EC_BOOL csocket_fd_clr(const int sockfd, FD_CSET *sockfd_set);

EC_BOOL csocket_fd_clone(FD_CSET *src_sockfd_set, FD_CSET *des_sockfd_set);

EC_BOOL csocket_client_addr_init( const UINT32 srv_ipaddr, const UINT32 srv_port, struct sockaddr_in *srv_addr);

EC_BOOL csocket_nonblock_enable(int sockfd);

EC_BOOL csocket_nonblock_disable(int sockfd);

EC_BOOL csocket_is_nonblock(const int sockfd);

EC_BOOL csocket_nagle_disable(int sockfd);

EC_BOOL csocket_quick_ack_enable(int sockfd);

EC_BOOL csocket_finish_enable(int sockfd);

EC_BOOL csocket_reset_enable(int sockfd);

EC_BOOL csocket_set_sendbuf_size(int sockfd, const int size);

EC_BOOL csocket_set_recvbuf_size(int sockfd, const int size);

EC_BOOL csocket_enable_keepalive(int sockfd);

EC_BOOL csocket_disable_keepalive(int sockfd);

EC_BOOL csocket_bind_nic(int sockfd, const char *eth_name, const uint32_t eth_name_len);

EC_BOOL csocket_enable_reuse_addr(int sockfd);

EC_BOOL csocket_disable_reuse_addr(int sockfd);

EC_BOOL csocket_enable_mcast_loop(int sockfd);

EC_BOOL csocket_disable_mcast_loop(int sockfd);

EC_BOOL csocket_bind_mcast(int sockfd, const UINT32 ipaddr, const UINT32 port);

EC_BOOL csocket_optimize(int sockfd, const UINT32 csocket_block_mode);

EC_BOOL csocket_srv_optimize(int sockfd, const UINT32 csocket_block_mode);

EC_BOOL csocket_udp_optimize(int sockfd);

EC_BOOL csocket_listen(const UINT32 srv_ipaddr, const UINT32 srv_port, int *srv_sockfd);

EC_BOOL csocket_ipaddr_and_port(const int sockfd, UINT32 *ipaddr, UINT32 *port);

EC_BOOL csocket_connect(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd, UINT32 *client_ipaddr, UINT32 *client_port);

UINT32  csocket_state(const int sockfd);

const char *csocket_tcpi_stat_desc(const int sockfd);

EC_BOOL csocket_is_established(const int sockfd);

EC_BOOL csocket_is_connected(const int sockfd);

EC_BOOL csocket_is_closed(const int sockfd);

EC_BOOL csocket_accept(const int srv_sockfd, int *conn_sockfd, const UINT32 csocket_block_mode, UINT32 *client_ipaddr, UINT32 *client_port);

EC_BOOL csocket_get_peer_port(const int sockfd, UINT32 *peer_port);

EC_BOOL csocket_udp_create( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd );

EC_BOOL csocket_start_udp_bcast_sender( const UINT32 bcast_fr_ipaddr, const UINT32 bcast_port, int *srv_sockfd );

EC_BOOL csocket_stop_udp_bcast_sender( const int sockfd );

EC_BOOL csocket_start_udp_bcast_recver( const UINT32 bcast_to_ipaddr, const UINT32 bcast_port, int *srv_sockfd );

EC_BOOL csocket_stop_udp_bcast_recver( const int sockfd );

EC_BOOL csocket_udp_bcast_send(const UINT32 bcast_fr_ipaddr, const UINT32 bcast_to_ipaddr, const UINT32 bcast_port, const UINT8 *data, const UINT32 dlen);

EC_BOOL csocket_udp_bcast_sendto(const int sockfd, const UINT32 bcast_to_ipaddr, const UINT32 bcast_port, const UINT8 *data, const UINT32 dlen);

EC_BOOL csocket_udp_bcast_recvfrom(const int sockfd, const UINT32 bcast_fr_ipaddr, const UINT32 bcast_port, UINT8 *data, const UINT32 max_dlen, UINT32 *dlen);

EC_BOOL csocket_start_udp_mcast_sender( const UINT32 mcast_ipaddr, const UINT32 srv_port, int *srv_sockfd );

EC_BOOL csocket_stop_udp_mcast_sender( const int sockfd, const UINT32 mcast_ipaddr );

EC_BOOL csocket_start_udp_mcast_recver( const UINT32 mcast_ipaddr, const UINT32 srv_port, int *srv_sockfd );

EC_BOOL csocket_stop_udp_mcast_recver( const int sockfd, const UINT32 mcast_ipaddr );

EC_BOOL csocket_join_mcast(const int sockfd, const UINT32 mcast_ipaddr);

EC_BOOL csocket_drop_mcast(const int sockfd, const UINT32 mcast_ipaddr);

EC_BOOL csocket_udp_mcast_sendto(const int sockfd, const UINT32 mcast_ipaddr, const UINT32 mcast_port, const UINT8 *data, const UINT32 dlen);

EC_BOOL csocket_udp_mcast_recvfrom(const int sockfd, const UINT32 mcast_ipaddr, const UINT32 mcast_port, UINT8 *data, const UINT32 max_dlen, UINT32 *dlen);

EC_BOOL csocket_sendto(const int sockfd, struct sockaddr_in *addr, socklen_t addr_len,
                            const uint8_t *data, const uint32_t len, uint32_t *complete_len);

EC_BOOL csocket_recvfrom(const int sockfd, uint8_t *data, const uint32_t data_max_len, uint32_t *data_len);

EC_BOOL csocket_udp_sendto(const int sockfd, const UINT32 mcast_ipaddr, const UINT32 mcast_port, const UINT8 *data, const UINT32 dlen);

EC_BOOL csocket_udp_write(const int sockfd, const UINT32 ipaddr, const UINT32 port, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos);

EC_BOOL csocket_udp_read(const int sockfd, const UINT32 ipaddr, const UINT32 port, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);

EC_BOOL csocket_send_confirm(const int srv_sockfd);

EC_BOOL csocket_recv_confirm(const int srv_sockfd);

EC_BOOL csocket_select(const int sockfd_boundary, FD_CSET *read_sockfd_set, FD_CSET *write_sockfd_set, FD_CSET *except_sockfd_set, struct timeval *timeout, int *retval);

EC_BOOL csocket_shutdown( const int sockfd, const int flag );

int     csocket_open(int domain, int type, int protocol);

EC_BOOL csocket_close( const int sockfd );

int     csocket_errno();

EC_BOOL csocket_is_eagain();

EC_BOOL csocket_no_ierror(const int sockfd);

EC_BOOL csocket_can_write(const int sockfd, int *ret);

EC_BOOL csocket_can_read(const int sockfd, int *ret);

EC_BOOL csocket_isend(const int sockfd, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);

EC_BOOL csocket_irecv(const int sockfd, UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position);

EC_BOOL csocket_send(const int sockfd, const UINT8 *out_buff, const UINT32 out_buff_expect_len);

EC_BOOL csocket_recv(const int sockfd, UINT8 *in_buff, const UINT32 in_buff_expect_len);

EC_BOOL csocket_write(const int sockfd, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos);

EC_BOOL csocket_read(const int sockfd, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);

EC_BOOL csocket_sendfile(const int sockfd, const int fd, const UINT32 out_buff_max_len, UINT32 *pos);

EC_BOOL csocket_isend_task_node(CSOCKET_CNODE *csocket_cnode, struct _TASK_NODE *task_node);

EC_BOOL csocket_irecv_task_node(CSOCKET_CNODE *csocket_cnode, struct _TASK_NODE *task_node);

/*to fix a incomplete csocket_request, when complete, return EC_TRUE, otherwise, return EC_FALSE yet*/
EC_BOOL csocket_cnode_fix_task_node(CSOCKET_CNODE *csocket_cnode, struct _TASK_NODE *task_node);


/*fetch a complete or incomplete csocket_request, caller should check the result*/
struct _TASK_NODE *csocket_fetch_task_node(CSOCKET_CNODE *csocket_cnode);

EC_BOOL csocket_srv_start( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *srv_sockfd );

EC_BOOL csocket_srv_end(const int srv_sockfd);

EC_BOOL csocket_client_start( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd, UINT32 *client_ipaddr, UINT32 *client_port );

EC_BOOL csocket_client_end(const int client_sockfd);

UINT32 csocket_encode_actual_size();

UINT32 xmod_node_encode_actual_size();


EC_BOOL csocket_unix_optimize(int sockfd);

EC_BOOL csocket_unix_listen( const UINT32 srv_ipaddr, const UINT32 srv_port, int *srv_sockfd );

EC_BOOL csocket_unix_connect( const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 csocket_block_mode, int *client_sockfd );

EC_BOOL csocket_unix_accept(const int srv_sockfd, int *conn_sockfd, const UINT32 csocket_block_mode);


EC_BOOL csocket_unixpacket_optimize(int sockfd);

EC_BOOL csocket_unixpacket_connect( const char *unix_domain_socket_path, const UINT32 csocket_block_mode, int *client_sockfd );

EC_BOOL csocket_unixpacket_listen(const char *unix_domain_socket_path, int *srv_sockfd);

EC_BOOL csocket_unixpacket_accept(const int srv_sockfd, int *conn_sockfd, const UINT32 csocket_block_mode);

EC_BOOL csocket_unixpacket_send(const int sockfd, const UINT8 *out_buff, const UINT32 out_buff_len, UINT32 *out_buff_pos);

EC_BOOL csocket_unixpacket_recv(const int sockfd, UINT8 *in_buff, const UINT32 in_buff_len, UINT32 *in_buff_pos);

#endif/*_CSOCKET_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

