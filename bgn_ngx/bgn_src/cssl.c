#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmpic.inc"

#include "csocket.h"

#include "cssl.h"

EC_BOOL g_cssl_init_flag = EC_FALSE;

#if 1
#define CSSL_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error:assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#else
#define CSSL_ASSERT(condition) do{}while(0)
#endif

EC_BOOL cssl_init()
{
    if(EC_FALSE == g_cssl_init_flag)
    {
        SSL_library_init(); 
        OpenSSL_add_all_algorithms(); 
        SSL_load_error_strings();

        g_cssl_init_flag = EC_TRUE;
    }

    return (EC_TRUE);
}

CSSL_NODE *cssl_node_new()
{
    CSSL_NODE *cssl_node;

    alloc_static_mem(MM_CSSL_NODE, &cssl_node, LOC_CSSL_0001);
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_new: new cssl_node failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cssl_node_init(cssl_node))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_new: init cssl_node failed\n");
        free_static_mem(MM_CSSL_NODE, cssl_node, LOC_CSSL_0002);
        return (NULL_PTR);
    }

    return (cssl_node);
}

EC_BOOL cssl_node_init(CSSL_NODE *cssl_node)
{
    cssl_init();
 
    if(NULL_PTR != cssl_node)
    {
        CSSL_NODE_TYPE(cssl_node)           = CSSL_NODE_UNKNOWN_TYPE;
        CSSL_NODE_SSL(cssl_node)            = NULL_PTR;  
        CSSL_NODE_SSL_CTX(cssl_node)        = NULL_PTR;

        cstring_init(CSSL_NODE_CA_FILE(cssl_node), NULL_PTR);
        cstring_init(CSSL_NODE_CLIENT_CERT_FILE(cssl_node), NULL_PTR);
        cstring_init(CSSL_NODE_CLIENT_PRIVKEY_FILE(cssl_node), NULL_PTR);
    }
 
    return (EC_TRUE);
}

EC_BOOL cssl_node_clean(CSSL_NODE *cssl_node)
{
    if(NULL_PTR != cssl_node)
    {
        if(NULL_PTR != CSSL_NODE_SSL(cssl_node))
        {
            SSL_shutdown(CSSL_NODE_SSL(cssl_node));
            SSL_free(CSSL_NODE_SSL(cssl_node));
            CSSL_NODE_SSL(cssl_node) = NULL_PTR;
        }

        if(NULL_PTR != CSSL_NODE_SSL_CTX(cssl_node))
        {
            SSL_CTX_free(CSSL_NODE_SSL_CTX(cssl_node));
            CSSL_NODE_SSL_CTX(cssl_node) = NULL_PTR;
        }

        cstring_clean(CSSL_NODE_CA_FILE(cssl_node));
        cstring_clean(CSSL_NODE_CLIENT_CERT_FILE(cssl_node));
        cstring_clean(CSSL_NODE_CLIENT_PRIVKEY_FILE(cssl_node));

        CSSL_NODE_TYPE(cssl_node) = CSSL_NODE_UNKNOWN_TYPE;
    }
 
    return (EC_TRUE);
}

EC_BOOL cssl_node_free(CSSL_NODE *cssl_node)
{
    if(NULL_PTR != cssl_node)
    {
        cssl_node_clean(cssl_node);
        free_static_mem(MM_CSSL_NODE, cssl_node, LOC_CSSL_0003);
    }

    return (EC_TRUE);
}

EC_BOOL cssl_node_load_certificate(CSSL_NODE *cssl_node, const char *file)
{
    SSL_CTX *ctx;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ctx = CSSL_NODE_SSL_CTX(cssl_node);
    if(NULL_PTR == ctx)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_load_certificate: ctx is null\n");
        return (EC_FALSE);
    }

    if(SSL_SUCC != SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_load_certificate: load certificate file %s failed\n", file);
        return (EC_FALSE);
    }

    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_load_certificate: load certificate file %s done\n", file);

    return (EC_TRUE);
}

EC_BOOL cssl_node_load_private_key(CSSL_NODE *cssl_node, const char *file)
{
    SSL_CTX *ctx;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ctx = CSSL_NODE_SSL_CTX(cssl_node);
    if(NULL_PTR == ctx)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_load_private_key: ctx does not exist\n");
        return (EC_FALSE);
    }

    if(SSL_SUCC != SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_load_private_key: load private key file %s failed\n", file);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cssl_node_check_private_key(CSSL_NODE *cssl_node)
{
    SSL_CTX *ctx;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ctx = CSSL_NODE_SSL_CTX(cssl_node);
    if(NULL_PTR == ctx)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_check_private_key: ctx does not exist\n");
        return (EC_FALSE);
    }

    if(SSL_SUCC != SSL_CTX_check_private_key(ctx))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_check_private_key: invalid private key\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cssl_node_create_ctx(CSSL_NODE *cssl_node)
{
    SSL_CTX *ctx;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    if(CSSL_NODE_SERVER_TYPE == CSSL_NODE_TYPE(cssl_node)) /* server */
    {
        ctx = SSL_CTX_new(SSLv23_server_method());
        if(NULL_PTR == ctx)
        {
            dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_create_ctx: new server ctx failed\n");
            return (EC_FALSE);
        }

        CSSL_NODE_SSL_CTX(cssl_node) = ctx;

        dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_create_ctx: new server ctx done\n");
        return (EC_TRUE);
    }

    if(CSSL_NODE_CLIENT_TYPE == CSSL_NODE_TYPE(cssl_node)) /* client */
    {
        ctx = SSL_CTX_new(SSLv23_client_method());
        if(NULL_PTR == ctx)
        {
            dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_create_ctx: new client ctx failed\n");
            return (EC_FALSE);
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL_PTR);

        if(EC_TRUE == cstring_is_empty(CSSL_NODE_CA_FILE(cssl_node)))
        {
            SSL_CTX_set_default_verify_paths(ctx);
        }
        else
        {  
            const char *ca_certificate;

            ca_certificate = (const char *)cstring_get_str(CSSL_NODE_CA_FILE(cssl_node));
            SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL_PTR);
        }
      
        dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_create_ctx: set to verify peer\n");

        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

        CSSL_NODE_SSL_CTX(cssl_node) = ctx;

        if(EC_FALSE == cstring_is_empty(CSSL_NODE_CLIENT_CERT_FILE(cssl_node))
        && EC_FALSE == cstring_is_empty(CSSL_NODE_CLIENT_PRIVKEY_FILE(cssl_node)))
        {
            const char      *client_cert;
            const char      *client_privkey;

            client_cert     = (const char *)cstring_get_str(CSSL_NODE_CLIENT_CERT_FILE(cssl_node));
            client_privkey  = (const char *)cstring_get_str(CSSL_NODE_CLIENT_PRIVKEY_FILE(cssl_node));
            
            if(EC_FALSE == cssl_node_load_certificate(cssl_node, client_cert))
            {
                dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_create_ctx: load client certificate '%s' failed\n", 
                                client_cert);
                return (EC_FALSE);            
            }

            if(EC_FALSE == cssl_node_load_private_key(cssl_node, client_privkey))
            {
                dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_create_ctx: load client private key '%s' failed\n", 
                                client_privkey);
                return (EC_FALSE);            
            }
            
            if(EC_FALSE == cssl_node_check_private_key(cssl_node))
            {
                dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_create_ctx: check client certificate '%s' and private key '%s' failed\n", 
                                client_cert, client_privkey);
                return (EC_FALSE);            
            }

            dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_create_ctx: check client certificate '%s' and private key '%s' done\n", 
                            client_cert, client_privkey);            
        }
        
        dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_create_ctx: new client ctx done\n");
        return (EC_TRUE);
    }

    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_create_ctx: invalid type %ld of cssl_node\n", CSSL_NODE_TYPE(cssl_node));
    return (EC_FALSE);
}

EC_BOOL cssl_node_create_ssl(CSSL_NODE *cssl_node)
{
    SSL *ssl;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    if(NULL_PTR == CSSL_NODE_SSL_CTX(cssl_node))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_create_ssl: ctx does not exist\n");
        return (EC_FALSE);
    }

    ssl = SSL_new(CSSL_NODE_SSL_CTX(cssl_node));
    if(NULL_PTR == ssl)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_create_ssl: new SSL failed\n");
        return (EC_FALSE);
    }

    if(CSSL_NODE_CLIENT_TYPE == CSSL_NODE_TYPE(cssl_node))
    {
        SSL_set_connect_state (ssl);
    }

    if(CSSL_NODE_SERVER_TYPE == CSSL_NODE_TYPE(cssl_node))
    {
        SSL_set_accept_state (ssl);
    }

    CSSL_NODE_SSL(cssl_node) = ssl;
    return (EC_TRUE);
}

EC_BOOL cssl_node_bind_socket(CSSL_NODE *cssl_node, const int sockfd)
{
    SSL *ssl;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ssl = CSSL_NODE_SSL(cssl_node);
    if(NULL_PTR == ssl)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_bind_socket: SSL does not exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csocket_is_connected(sockfd))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_bind_socket: socket %d is not connected\n");
        csocket_close(sockfd);
        return (EC_FALSE);
    }

    if(SSL_SUCC != SSL_set_fd(ssl, sockfd))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_bind_socket: bind SSL to socket %d failed\n", sockfd);
        return (EC_FALSE);
    }

    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_bind_socket: bind ssl %p and sockfd %d done\n", ssl, sockfd);

    return (EC_TRUE);
}

static EC_BOOL __cssl_node_make_on_client(CSSL_NODE *cssl_node, const int sockfd)
{
    if(EC_FALSE == cssl_node_create_ctx(cssl_node))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:__cssl_node_make_on_client: sockfd %d, create ctx failed\n", sockfd);
        return (EC_FALSE);
    }
    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] __cssl_node_make_on_client: sockfd %d, create ctx done\n", sockfd);

    if(EC_FALSE == cssl_node_create_ssl(cssl_node))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:__cssl_node_make_on_client: sockfd %d, create ssl failed\n", sockfd);
        return (EC_FALSE);
    }
    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] __cssl_node_make_on_client: sockfd %d, create ssl done\n", sockfd);

    if(EC_FALSE == cssl_node_bind_socket(cssl_node, sockfd))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:__cssl_node_make_on_client: ssl bind socket %d failed\n", sockfd);
        return (EC_FALSE);
    }
    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] __cssl_node_make_on_client: sockfd %d, bind ssl done\n", sockfd);
 
    return (EC_TRUE);
}

/*on client side*/
CSSL_NODE * cssl_node_make_on_client(const int sockfd, const char *ca_file, const char *client_cert_file, const char *client_privkey_file)
{
    CSSL_NODE *cssl_node;

    cssl_node = cssl_node_new();
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_make_on_client: new cssl_node failed\n");
        return (NULL_PTR);
    }

    CSSL_NODE_TYPE(cssl_node) = CSSL_NODE_CLIENT_TYPE;
    if(NULL_PTR != ca_file)
    {
        cstring_append_str(CSSL_NODE_CA_FILE(cssl_node), (const UINT8 *)ca_file);
    }

    if(NULL_PTR != client_cert_file)
    {
        cstring_append_str(CSSL_NODE_CLIENT_CERT_FILE(cssl_node), (const UINT8 *)client_cert_file);
    }

    if(NULL_PTR != client_privkey_file)
    {
        cstring_append_str(CSSL_NODE_CLIENT_PRIVKEY_FILE(cssl_node), (const UINT8 *)client_privkey_file);
    }    
    
    if(EC_FALSE == __cssl_node_make_on_client(cssl_node, sockfd))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_make_on_client: make cssl_node on client failed\n");
        cssl_node_free(cssl_node);
        return (NULL_PTR);
    }

    return (cssl_node);
}

static EC_BOOL __cssl_node_make_on_server(CSSL_NODE *cssl_node, const int sockfd)
{
    ASSERT(NULL_PTR != CSSL_NODE_SSL_CTX(cssl_node));

    if(EC_FALSE == cssl_node_create_ssl(cssl_node))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:__cssl_node_make_on_server: sockfd %d, create ssl failed\n", sockfd);
        return (EC_FALSE);
    }
    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] __cssl_node_make_on_server: sockfd %d, create ssl done\n", sockfd);

    if(EC_FALSE == cssl_node_bind_socket(cssl_node, sockfd))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:__cssl_node_make_on_server: ssl bind socket %d failed\n", sockfd);
        return (EC_FALSE);
    }
    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] __cssl_node_make_on_server: sockfd %d, bind ssl done\n", sockfd);
 
    return (EC_TRUE);
}

/*on server side*/
CSSL_NODE * cssl_node_make_on_server(CSSL_NODE *cssl_node_srv, const int client_sockfd)
{
    CSSL_NODE *cssl_node;

    cssl_node = cssl_node_new();
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_make_on_server: new cssl_node failed\n");
        return (NULL_PTR);
    }

    CSSL_NODE_TYPE(cssl_node) = CSSL_NODE_SERVER_TYPE;

    /*bind server ctx*/
    CSSL_NODE_SSL_CTX(cssl_node) = CSSL_NODE_SSL_CTX(cssl_node_srv);

    if(EC_FALSE == __cssl_node_make_on_server(cssl_node, client_sockfd))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_make_on_server: make cssl_node on client failed\n");

        /*unbind server ctx*/
        CSSL_NODE_SSL_CTX(cssl_node) = NULL_PTR;
 
        cssl_node_free(cssl_node);
        return (NULL_PTR);
    }
 
    /*unbind server ctx*/
    CSSL_NODE_SSL_CTX(cssl_node) = NULL_PTR;
 
    return (cssl_node);
}

EC_BOOL cssl_node_handshake(CSSL_NODE *cssl_node)
{
    SSL *ssl;
    int  ret;
    int  err;

    UINT32 ssl_errno;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ssl = CSSL_NODE_SSL(cssl_node);
    if(NULL_PTR == ssl)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_handshake: ssl does not exist\n");
        return (EC_FALSE);
    }

    /*handshake succ*/
    ret = SSL_do_handshake(ssl);
    if(SSL_SUCC == ret)
    {   
#if 0    
        if(X509_V_OK != SSL_get_verify_result(ssl))
        {
            dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_handshake: handshake verify certifacate failed\n");
            return (EC_FALSE);
        }
#endif
        dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_handshake: handshake done\n");
        return (EC_TRUE);
    }

    err = SSL_get_error(ssl, ret);
    if(SSL_ERROR_WANT_WRITE == err)
    {
        /*TODO: wait WR event*/
        dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_handshake: handshake again: want write\n");
        return (EC_AGAIN_SSL_WANT_WRITE);
    }

    if(SSL_ERROR_WANT_READ == err)
    {
        /*TODO: wait RD event*/
        dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_handshake: handshake again: want read\n");
        return (EC_AGAIN_SSL_WANT_READ);
    }

    ssl_errno = ERR_get_error();
    dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_handshake: handshake failed, err = %d, '%s:%s:%s'\n",
                    err, ERR_lib_error_string(ssl_errno), ERR_func_error_string(ssl_errno), ERR_reason_error_string(ssl_errno));
    
    return (EC_FALSE);
}

EC_BOOL cssl_node_connect(CSSL_NODE *cssl_node) /* for client */
{
    SSL *ssl;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ssl = CSSL_NODE_SSL(cssl_node);
    if(NULL_PTR == ssl)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_connect: SSL does not exist\n");
        return (EC_FALSE);
    }

    /**
     *  When beginning a new handshake, the SSL engine must know whether it must call the connect (client) or accept (server) routines. Even though it may be clear from
     *  the method chosen, whether client or server mode was requested, the handshake routines must be explicitly set.
     *
     *  When using the SSL_connect(3) or SSL_accept(3) routines, the correct handshake routines are automatically set. When performing a transparent negotiation using
     *  SSL_write(3) or SSL_read(3), the handshake routines must be explicitly set in advance using either SSL_set_connect_state() or SSL_set_accept_state().
    **/
    if(SSL_SUCC != SSL_connect(ssl))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_connect: SSL_connect failed\n");
        return (EC_FALSE);
    }

    /*handshake succ*/

    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_connect: SSL_connect done\n");
    return (EC_TRUE);
}

EC_BOOL cssl_node_accept(CSSL_NODE *cssl_node) /* for server */
{
    SSL *ssl;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ssl = CSSL_NODE_SSL(cssl_node);
    if(NULL_PTR == ssl)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_accept: SSL does not exist\n");
        return (EC_FALSE);
    }

    if(SSL_SUCC != SSL_accept(ssl))
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_accept: SSL_accept failed\n");
        return (EC_FALSE);
    }

    /*handshake succ*/
 
    dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_accept: SSL_accept done\n");
    return (EC_TRUE);
}

EC_BOOL cssl_node_recv(CSSL_NODE *cssl_node, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    SSL     *ssl;
    size_t  once_recv_len;
    //size_t  need_recv_len;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ssl = CSSL_NODE_SSL(cssl_node);
    if(NULL_PTR == ssl)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_recv: SSL does not exist\n");
        return (EC_FALSE);
    }

    once_recv_len = (size_t)(in_buff_expect_len - (*pos));
    if(0 >= once_recv_len)/*no free space to recv*/
    {
        return (EC_TRUE);
    }

    /* read until completation, or buffer is full */
    for(; 0 < once_recv_len; once_recv_len = (size_t)(in_buff_expect_len - (*pos)))
    {
             
        ssize_t  ret;
        int      err;

        once_recv_len = DMIN(once_max_size, once_recv_len);

        /* SSL_read */
        ret = SSL_read(ssl, (void *)(in_buff + (*pos)), once_recv_len);
        if(0 < ret)
        {
            dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_recv: read in %d bytes\n", ret);
#if 0
            if(do_log(SEC_0156_CSSL, 9))
            {
                dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_recv: read buff is\n");
                cssl_print_chars(LOGSTDOUT, in_buff, *pos, ret);
            }
#endif         
            (*pos) += (UINT32)ret;     
            continue;
        }

        err = SSL_get_error(ssl, ret);
        if(SSL_ERROR_WANT_WRITE == err)
        {
            /*TODO:xxx*/
            dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_recv: want write => false\n");
            return (EC_FALSE);
        }
        else if(SSL_ERROR_WANT_READ == err)
        {
            dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_recv: want read => true\n");
            return (EC_AGAIN_SSL_WANT_READ);
        }
        else if (SSL_ERROR_ZERO_RETURN == err || 0 == ERR_peek_error())
        {
            dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_recv: read => done\n");
            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_recv: unknown => false, err = %d\n", err);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cssl_node_send(CSSL_NODE *cssl_node, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos)
{
    SSL *ssl;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ssl = CSSL_NODE_SSL(cssl_node);
    if(NULL_PTR == ssl)
    {
        dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_send: SSL does not exist\n");
        return (EC_FALSE);
    }

    for(;;)
    {
        UINT32   once_sent_len;
        ssize_t  ret;
        int      err;

        once_sent_len = out_buff_max_len - (*pos);
        if(0 == once_sent_len)
        {
            return (EC_TRUE);
        }

        once_sent_len = DMIN(once_max_size, once_sent_len);

        /* use SSL_write */
        ret = SSL_write(ssl, (void *)(out_buff + (*pos)), once_sent_len);
        if(0 < ret)
        {
            //dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] chttps_ssl_write: sent out %ld bytes\n", ret);
            (*pos) += (UINT32)ret;
            continue;
        }

        err = SSL_get_error(ssl, ret);
        if(SSL_ERROR_WANT_WRITE == err)
        {
            dbg_log(SEC_0156_CSSL, 9)(LOGSTDOUT, "[DEBUG] cssl_node_send: want write => true\n");
            return (EC_AGAIN_SSL_WANT_WRITE);
        }
        else if(SSL_ERROR_WANT_READ == err)
        {
            /*TODO:xxx*/
            dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_send: want read => false\n");
            return (EC_FALSE);
        }
        else
        {
            dbg_log(SEC_0156_CSSL, 0)(LOGSTDOUT, "error:cssl_node_send: unknown => false, err = %d\n", err);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

void cssl_node_print_certificate(LOG *log, const CSSL_NODE *cssl_node)
{
    SSL     *ssl;
    X509     *certificate;
    char    *name_str;

    CSSL_ASSERT(NULL_PTR != cssl_node);

    ssl = CSSL_NODE_SSL(cssl_node);
    if(NULL_PTR == ssl)
    {
        sys_log(log, "error:cssl_node_print_certificate: SSL does not exist\n");
        return;
    }

    certificate = SSL_get_peer_certificate(ssl);
    if(NULL_PTR == certificate)
    {
        sys_log(log, "error:cssl_node_print_certificate: no certificate information\n");
        return;
    }

    name_str = X509_NAME_oneline(X509_get_subject_name(certificate), 0, 0);
    sys_log(log, "[DEBUG] cssl_node_print_certificate: subject_name: %s\n", name_str);
    free(name_str);

    name_str = X509_NAME_oneline(X509_get_issuer_name(certificate), 0, 0);
    sys_log(log, "[DEBUG] cssl_node_print_certificate: issuer_name: %s\n", name_str);
    free(name_str);

    X509_free(certificate);

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
