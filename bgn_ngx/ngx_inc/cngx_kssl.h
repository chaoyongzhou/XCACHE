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

#ifndef _CNGX_KSSL_H
#define _CNGX_KSSL_H

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "crb.h"
#include "chashalgo.h"

#define CNGX_KSSL_NODE_ERR_HASH         (0)
#define CNGX_KSSL_NODE_HASH_ALGO        MD5_hash

typedef struct
{
    CSTRING         fname;
    UINT32          hash;    /*hash of fname*/

    CBYTES          content; /*file content*/
}CNGX_KSSL_NODE;

#define CNGX_KSSL_NODE_FNAME(cngx_kssl_node)            (&((cngx_kssl_node)->fname))
#define CNGX_KSSL_NODE_HASH(cngx_kssl_node)             ((cngx_kssl_node)->hash)
#define CNGX_KSSL_NODE_CONTENT(cngx_kssl_node)          (&((cngx_kssl_node)->content))

#define CNGX_KSSL_NODE_FNAME_STR(cngx_kssl_node)        (cstring_get_str(CNGX_KSSL_NODE_FNAME(cngx_kssl_node)))

CNGX_KSSL_NODE *cngx_kssl_node_new();

EC_BOOL cngx_kssl_node_init(CNGX_KSSL_NODE *cngx_kssl_node);

EC_BOOL cngx_kssl_node_clean(CNGX_KSSL_NODE *cngx_kssl_node);

EC_BOOL cngx_kssl_node_free(CNGX_KSSL_NODE *cngx_kssl_node);

int cngx_kssl_node_cmp(const CNGX_KSSL_NODE *cngx_kssl_node_1st, const CNGX_KSSL_NODE *cngx_kssl_node_2nd);

void cngx_kssl_node_print(LOG *log, const CNGX_KSSL_NODE *cngx_kssl_node);

void cngx_kssl_nodes_print(LOG *log);

CRB_TREE *cngx_kssl_nodes_get();

EC_BOOL cngx_kssl_nodes_is_init();

EC_BOOL cngx_kssl_nodes_set_init();

EC_BOOL cngx_kssl_nodes_init();

EC_BOOL cngx_kssl_nodes_add(const char *fname, const CBYTES *content);

CBYTES *cngx_kssl_nodes_search(const char *fname);

int cngx_kssl_callback(SSL_CTX *ssl_ctx, BIO *in, const char *fname);

#endif /*_CNGX_KSSL_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH && SWITCH_ON == NGX_KSSL_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

