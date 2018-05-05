#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

#ifndef _CSSL_H
#define _CSSL_H

#include "type.h"

#include "cssl.inc"
#include "csocket.inc"

CSSL_NODE* cssl_node_new();

EC_BOOL cssl_init();

EC_BOOL cssl_node_init(CSSL_NODE *cssl_node);

EC_BOOL cssl_node_clean(CSSL_NODE *cssl_node);

EC_BOOL cssl_node_free(CSSL_NODE *cssl_node);

EC_BOOL cssl_node_load_certificate(CSSL_NODE *cssl_node, const char *file);

EC_BOOL cssl_node_load_private_key(CSSL_NODE *cssl_node, const char *file);

EC_BOOL cssl_node_check_private_key(CSSL_NODE *cssl_node);

EC_BOOL cssl_node_create_ctx(CSSL_NODE *cssl_node);

EC_BOOL cssl_node_create_ssl(CSSL_NODE *cssl_node);

EC_BOOL cssl_node_bind_socket(CSSL_NODE *cssl_node, const int sockfd);

CSSL_NODE * cssl_node_make_on_client(const int sockfd, const char *ca_file, const char *client_cert_file, const char *client_privkey_file);

CSSL_NODE * cssl_node_make_on_server(CSSL_NODE *cssl_node_srv, const int client_sockfd);

EC_BOOL cssl_node_handshake(CSSL_NODE *cssl_node);

EC_BOOL cssl_node_connect(CSSL_NODE *cssl_node); /* for client */

EC_BOOL cssl_node_accept(CSSL_NODE *cssl_node); /* for server */

EC_BOOL cssl_node_recv(CSSL_NODE *cssl_node, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos);

EC_BOOL cssl_node_send(CSSL_NODE *cssl_node, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos);

void cssl_node_print_certificate(LOG *log, const CSSL_NODE *cssl_node);


#endif/*_CSSL_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
