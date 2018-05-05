#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

#ifndef _CSSL_INC
#define _CSSL_INC

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "type.h"
#include "cstring.h"

#define  SSL_SUCC          ((int) 1)

typedef struct _CSSL_NODE
{
    UINT32                  type; /* server:0 or client:1 */
    SSL                    *ssl;
    SSL_CTX                *ctx;

    CSTRING                 ca_file;

    /*if set client certificate and private key, */
    /*client certificate would be sent to server and server check client validity*/
    CSTRING                 client_cert_file;   /*client certificate file*/
    CSTRING                 client_privkey_file;/*client private key file*/
}CSSL_NODE;

#define CSSL_NODE_TYPE(cssl_node)                   ((cssl_node)->type)
#define CSSL_NODE_SSL(cssl_node)                    ((cssl_node)->ssl)
#define CSSL_NODE_SSL_CTX(cssl_node)                ((cssl_node)->ctx)
#define CSSL_NODE_CA_FILE(cssl_node)                (&((cssl_node)->ca_file))
#define CSSL_NODE_CLIENT_CERT_FILE(cssl_node)       (&((cssl_node)->client_cert_file))
#define CSSL_NODE_CLIENT_PRIVKEY_FILE(cssl_node)    (&((cssl_node)->client_privkey_file))


#define CSSL_NODE_SERVER_TYPE                       ((UINT32) 0)
#define CSSL_NODE_CLIENT_TYPE                       ((UINT32) 1)
#define CSSL_NODE_UNKNOWN_TYPE                      ((UINT32)-1)

#define EC_AGAIN_SSL_WANT_WRITE                     (((UINT32)0x1000) | EC_AGAIN)
#define EC_AGAIN_SSL_WANT_READ                      (((UINT32)0x2000) | EC_AGAIN)

#endif/*_CSSL_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
