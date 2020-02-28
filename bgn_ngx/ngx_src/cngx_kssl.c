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

#if (SWITCH_ON == NGX_BGN_SWITCH && SWITCH_ON == NGX_KSSL_SWITCH)

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cmisc.h"

#include "task.h"

#include "cmpie.h"

#include "crb.h"
#include "chashalgo.h"

#include "chttp.h"
#include "chttps.h"

#include "cngx.h"
#include "cngx_headers.h"

#include "cngx_kssl.h"

#include "ngx_http_bgn_kssl.h"

CRB_TREE             g_cngx_kssl_files;   /*item is CNGX_KSSL_NODE*/
EC_BOOL              g_cngx_kssl_files_init_flag = EC_FALSE;

CNGX_KSSL_NODE *cngx_kssl_node_new()
{
    CNGX_KSSL_NODE *cngx_kssl_node;

    alloc_static_mem(MM_CNGX_KSSL_NODE, &cngx_kssl_node, LOC_CNGX_0066);
    if(NULL_PTR != cngx_kssl_node)
    {
        cngx_kssl_node_init(cngx_kssl_node);
    }
    return (cngx_kssl_node);
}

EC_BOOL cngx_kssl_node_init(CNGX_KSSL_NODE *cngx_kssl_node)
{
    cstring_init(CNGX_KSSL_NODE_FNAME(cngx_kssl_node), NULL_PTR);
    cbytes_init(CNGX_KSSL_NODE_CONTENT(cngx_kssl_node));

    CNGX_KSSL_NODE_HASH(cngx_kssl_node) = CNGX_KSSL_NODE_ERR_HASH;

    return (EC_TRUE);
}

EC_BOOL cngx_kssl_node_clean(CNGX_KSSL_NODE *cngx_kssl_node)
{
    cstring_clean(CNGX_KSSL_NODE_FNAME(cngx_kssl_node));
    cbytes_clean(CNGX_KSSL_NODE_CONTENT(cngx_kssl_node));

    CNGX_KSSL_NODE_HASH(cngx_kssl_node) = CNGX_KSSL_NODE_ERR_HASH;

    return (EC_TRUE);
}

EC_BOOL cngx_kssl_node_free(CNGX_KSSL_NODE *cngx_kssl_node)
{
    if(NULL_PTR != cngx_kssl_node)
    {
        cngx_kssl_node_clean(cngx_kssl_node);
        free_static_mem(MM_CNGX_KSSL_NODE, cngx_kssl_node, LOC_CNGX_0067);
    }
    return (EC_TRUE);
}

int cngx_kssl_node_cmp(const CNGX_KSSL_NODE *cngx_kssl_node_1st, const CNGX_KSSL_NODE *cngx_kssl_node_2nd)
{
    if(CNGX_KSSL_NODE_HASH(cngx_kssl_node_1st) > CNGX_KSSL_NODE_HASH(cngx_kssl_node_2nd))
    {
        return (1);
    }

    if(CNGX_KSSL_NODE_HASH(cngx_kssl_node_1st) < CNGX_KSSL_NODE_HASH(cngx_kssl_node_2nd))
    {
        return (-1);
    }

    return cstring_cmp(CNGX_KSSL_NODE_FNAME(cngx_kssl_node_1st), CNGX_KSSL_NODE_FNAME(cngx_kssl_node_2nd));
}

void cngx_kssl_node_print(LOG *log, const CNGX_KSSL_NODE *cngx_kssl_node)
{
    if(NULL_PTR != cngx_kssl_node)
    {
        sys_log(log, "cngx_kssl_node_print %p: file %s, hash %ld, content len %ld\n",
                      cngx_kssl_node,
                      (char *)CNGX_KSSL_NODE_FNAME_STR(cngx_kssl_node),
                      CNGX_KSSL_NODE_HASH(cngx_kssl_node),
                      CBYTES_LEN(CNGX_KSSL_NODE_CONTENT(cngx_kssl_node))
                      );
    }

    return;
}

void cngx_kssl_nodes_print(LOG *log)
{
    crb_tree_print(log, &g_cngx_kssl_files);

    return;
}

CRB_TREE *cngx_kssl_nodes_get()
{
    return (&g_cngx_kssl_files);
}

EC_BOOL cngx_kssl_nodes_is_init()
{
    return (g_cngx_kssl_files_init_flag);
}

EC_BOOL cngx_kssl_nodes_set_init()
{
    g_cngx_kssl_files_init_flag = EC_TRUE;
    return (EC_TRUE);
}

EC_BOOL cngx_kssl_nodes_init()
{
    if(EC_FALSE == cngx_kssl_nodes_is_init())
    {
        crb_tree_init(cngx_kssl_nodes_get(),
                (CRB_DATA_CMP  )cngx_kssl_node_cmp,
                (CRB_DATA_FREE )cngx_kssl_node_free,
                (CRB_DATA_PRINT)cngx_kssl_node_print);

        cngx_kssl_nodes_set_init();
    }

    return (EC_TRUE);
}

EC_BOOL cngx_kssl_nodes_add(const char *fname, const CBYTES *content)
{
    CNGX_KSSL_NODE   *cngx_kssl_node;
    CRB_NODE         *crb_node;

    if(NULL_PTR == fname || NULL_PTR == content || 0 == CBYTES_LEN(content))
    {
        return (EC_FALSE);
    }

    cngx_kssl_nodes_init();

    cngx_kssl_node = cngx_kssl_node_new();
    if(NULL_PTR == cngx_kssl_node)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_nodes_add: "
                                             "new cngx_kssl_node failed\n");
        return (EC_FALSE);
    }

    /*init*/
    cstring_append_str(CNGX_KSSL_NODE_FNAME(cngx_kssl_node), (const UINT8 *)fname);
    CNGX_KSSL_NODE_HASH(cngx_kssl_node) = CNGX_KSSL_NODE_HASH_ALGO(strlen(fname), (const UINT8 *)fname);
    cbytes_append(CNGX_KSSL_NODE_CONTENT(cngx_kssl_node), CBYTES_BUF(content), CBYTES_LEN(content));

    /*insert*/
    crb_node = crb_tree_insert_data(cngx_kssl_nodes_get(), (void *)cngx_kssl_node);/*compare fname*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_nodes_add: "
                                             "insert '%s' to nodes failed\n",
                                            (char *)CNGX_KSSL_NODE_FNAME_STR(cngx_kssl_node));
        cngx_kssl_node_free(cngx_kssl_node);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cngx_kssl_node)/*found duplicate*/
    {
        CNGX_KSSL_NODE *cngx_kssl_node_duplicate;

        cngx_kssl_node_duplicate = (CNGX_KSSL_NODE *)CRB_NODE_DATA(crb_node);

        cngx_kssl_node_free(cngx_kssl_node); /*no useful*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_nodes_add: "
                                             "found duplicate '%s' in nodes\n",
                                             (char *)CNGX_KSSL_NODE_FNAME_STR(cngx_kssl_node_duplicate));
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_nodes_add: "
                                         "add '%s' to nodes done\n",
                                         (char *)CNGX_KSSL_NODE_FNAME_STR(cngx_kssl_node));

    return (EC_TRUE);
}

CBYTES *cngx_kssl_nodes_search(const char *fname)
{
    CNGX_KSSL_NODE   *cngx_kssl_node;
    CNGX_KSSL_NODE   *cngx_kssl_node_found;
    CRB_NODE         *crb_node;

    if(NULL_PTR == fname)
    {
        return (NULL_PTR);
    }

    cngx_kssl_nodes_init();

    cngx_kssl_node = cngx_kssl_node_new();
    if(NULL_PTR == cngx_kssl_node)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_nodes_search: "
                                             "new cngx_kssl_node failed\n");
        return (NULL_PTR);
    }

    /*init*/
    cstring_append_str(CNGX_KSSL_NODE_FNAME(cngx_kssl_node), (const UINT8 *)fname);
    CNGX_KSSL_NODE_HASH(cngx_kssl_node) = CNGX_KSSL_NODE_HASH_ALGO(strlen(fname), (const UINT8 *)fname);

    crb_node = crb_tree_search_data(cngx_kssl_nodes_get(), (void *)cngx_kssl_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_nodes_search: "
                                             "not found node of '%s'\n",
                                            (char *)CNGX_KSSL_NODE_FNAME_STR(cngx_kssl_node));
        cngx_kssl_node_free(cngx_kssl_node);
        return (NULL_PTR);
    }

    cngx_kssl_node_free(cngx_kssl_node);

    cngx_kssl_node_found = CRB_NODE_DATA(crb_node);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_nodes_search: "
                                         "found node of '%s'\n",
                                        (char *)CNGX_KSSL_NODE_FNAME_STR(cngx_kssl_node_found));

    return CNGX_KSSL_NODE_CONTENT(cngx_kssl_node_found);
}

EC_BOOL cngx_kssl_cache_handler(SSL_CTX *ssl_ctx, BIO *in, const char *fname, UINT32 *fsize)
{
    CBYTES      *content;

    content = cngx_kssl_nodes_search(fname);
    if(NULL_PTR == content)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_cache_handler: "
                                             "MISS '%s'\n",
                                             fname);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_cache_handler: "
                                         "HIT '%s'\n",
                                         fname);

    if(0 >= in->method->bwrite(in, (const char *)CBYTES_BUF(content), (int)CBYTES_LEN(content)))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_cache_handler: "
                                             "BIO write %d bytes failed for '%s'\n",
                                             (int)CBYTES_LEN(content),
                                             fname);
        return (EC_FALSE);
    }

    (*fsize) = CBYTES_LEN(content);

    return (EC_TRUE);
}

EC_BOOL cngx_kssl_debug_handler(SSL_CTX *ssl_ctx, BIO *in, const char *fname, UINT32 *fsize)
{
    static  uint8_t     kssl[1 * 1024 * 1024];
    UINT32              fsize_t;
    UINT32              offset;
    int                 fd;

    fd = c_file_open(fname, O_RDONLY, 0666);
    ASSERT(-1 != fd);
    ASSERT(EC_TRUE == c_file_size(fd, &fsize_t));

    offset = 0;
    ASSERT(EC_TRUE == c_file_read(fd, &offset, fsize_t, (uint8_t *)kssl));
    ASSERT(offset == fsize_t);
    c_file_close(fd);

    ASSERT(0 < in->method->bwrite(in, (const char *)kssl, fsize_t));

    (*fsize) = fsize_t;

    return (EC_TRUE);
}

EC_BOOL cngx_kssl_https_handler(SSL_CTX *ssl_ctx, BIO *in, const char *fname, UINT32 *fsize)
{
    ngx_http_bgn_kssl_srv_conf_t    *kscf;

    const char                      *kssl_server_ca_file;
    const char                      *kssl_server;
    int                              kssl_port;
    const char                      *kssl_client_certificate_file;
    const char                      *kssl_client_private_key_file;

    CHTTP_REQ                        chttp_req;
    CHTTP_RSP                        chttp_rsp;
    CBYTES                          *rsp_body;

    kscf = ngx_ssl_get_server_conf(ssl_ctx);

    kssl_server_ca_file          = (const char *)kscf->kssl_server_ca_file.data;
    kssl_server                  = (const char *)kscf->kssl_server_ipaddr.data;
    kssl_port                    = (int         )kscf->kssl_server_port;

    kssl_client_certificate_file = (const char *)kscf->kssl_client_certificate.data;
    kssl_client_private_key_file = (const char *)kscf->kssl_client_certificate_key.data;

    ASSERT(NULL_PTR != kssl_server);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_https_handler: "
                                         "ca: %s\n",
                                         kssl_server_ca_file);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_https_handler: "
                                         "server: %s\n",
                                         kssl_server);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_https_handler: "
                                         "server port: %d\n",
                                         kssl_port);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_https_handler: "
                                         "client certificate: %s\n",
                                         kssl_client_certificate_file);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_https_handler: "
                                         "client private key: %s\n",
                                         kssl_client_private_key_file);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, c_ipv4_to_word(kssl_server));
    chttp_req_set_port_word(&chttp_req, kssl_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req   , (const char *)"/");
    chttp_req_set_uri(&chttp_req   , (const char *)fname);

    chttp_req_add_header(&chttp_req, (const char *)"Host"          , (const char *)"www.pki.com");
    chttp_req_add_header(&chttp_req, (const char *)"Accept"        , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection"    , (const char *)/*"close"*/"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Type"  , (const char *)"application/x-www-form-urlencoded");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    if(NULL_PTR != kssl_server_ca_file)
    {
        chttp_req_set_ca_file(&chttp_req, kssl_server_ca_file);
    }

    if(NULL_PTR != kssl_client_certificate_file)
    {
        chttp_req_set_client_certificate_file(&chttp_req, kssl_client_certificate_file);
    }

    if(NULL_PTR != kssl_client_private_key_file)
    {
        chttp_req_set_client_private_key_file(&chttp_req, kssl_client_private_key_file);
    }

    if(EC_FALSE == chttps_request(&chttp_req, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_https_handler: "
                                             "https request failed for '%s'\n",
                                             fname);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    chttp_req_clean(&chttp_req); /*no useful*/

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_https_handler: "
                                             "https request return %u for '%s'\n",
                                             CHTTP_RSP_STATUS(&chttp_rsp),
                                             fname);

        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    rsp_body = CHTTP_RSP_BODY(&chttp_rsp);

    if(0 == CBYTES_LEN(rsp_body))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_https_handler: "
                                             "https response body is empty for '%s'\n",
                                             fname);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_https_handler: "
                                         "https response body %ld bytes for '%s'\n",
                                         CBYTES_LEN(rsp_body),
                                         fname);

    if(0 >= in->method->bwrite(in, (const char *)CBYTES_BUF(rsp_body), (int)CBYTES_LEN(rsp_body)))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_https_handler: "
                                             "BIO write %d bytes failed for '%s'\n",
                                             (int)CBYTES_LEN(rsp_body),
                                             fname);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    (*fsize) = CBYTES_LEN(rsp_body);

    if(kscf->kssl_cache)/*cache default is on*/
    {
        /*cache it if necessary*/
        cngx_kssl_nodes_add(fname, rsp_body);
    }

    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL cngx_kssl_handler(SSL_CTX *ssl_ctx, BIO *in, const char *fname, UINT32 *fsize)
{
    ngx_http_bgn_kssl_srv_conf_t    *kscf;

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_handler: "
                                         "fname: %s\n",
                                         fname);

    kscf = ngx_ssl_get_server_conf(ssl_ctx);

    if(kscf->kssl_debug)
    {
        return cngx_kssl_debug_handler(ssl_ctx, in, fname, fsize);
    }

    if(kscf->kssl_cache)/*cache default is on*/
    {
        /*search cache at first*/
        if(EC_TRUE == cngx_kssl_cache_handler(ssl_ctx, in, fname, fsize))
        {
            return (EC_TRUE);
        }
    }

    return cngx_kssl_https_handler(ssl_ctx, in, fname, fsize);
}

int cngx_kssl_callback(SSL_CTX *ssl_ctx, BIO *in, const char *fname)
{
    UINT32  fsize;

    if(EC_FALSE == cngx_kssl_handler(ssl_ctx, in, fname, &fsize))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_kssl_callback: "
                                             "load file '%s' failed\n",
                                             fname);
        return (-1);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_kssl_callback: "
                                         "load file '%s' done\n",
                                         fname);
    return ((int)fsize);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH && SWITCH_ON == NGX_KSSL_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
