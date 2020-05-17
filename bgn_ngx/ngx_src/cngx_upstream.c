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

#if (SWITCH_ON == NGX_BGN_SWITCH)

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_request.h>

#include "ngx_http_bgn_common.h"
#include "ngx_http_bgn_directive.h"

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cngx_upstream.h"

EC_BOOL cngx_upstream_exist(ngx_http_request_t *r)
{
    ngx_http_bgn_loc_conf_t     *blcf;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    if(NULL_PTR == blcf || 0 == blcf->bgn_upstream.active) {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_upstream_get_name(ngx_http_request_t *r, u_char **str, uint32_t *len)
{
    ngx_http_bgn_loc_conf_t                 *blcf;
    ngx_str_t                               *name;
    ngx_http_upstream_t                     *u;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    if(NULL_PTR == blcf || 0 == blcf->bgn_upstream.active) {
        return (EC_FALSE);
    }

    u = r->upstream;
    if (NULL_PTR == u) {
        u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));

        if (NULL_PTR == u) {
            return (EC_FALSE);
        }

        u->peer.log = r->connection->log;
        r->upstream = u; /*arm upstream*/
    }

    if(NULL_PTR == blcf->bgn_upstream.proxy_lengths) {
        name = &(blcf->bgn_upstream.vars.host_header);
    }
    else {
        if(NULL_PTR == u->resolved) {
            if (ngx_http_bgn_proxy_eval(r, blcf) != NGX_OK) {
                return (EC_FALSE);
            }
        }
        name = &(u->resolved->host);
    }

    if(NULL_PTR != str) {
        (*str) = name->data;
    }

    if(NULL_PTR != len) {
        (*len) = name->len;
    }

    return (EC_TRUE);
}

#if (NGX_HTTP_UPSTREAM_RBTREE)
ngx_http_upstream_srv_conf_t *
cngx_upstream_rbtree_lookup(ngx_http_upstream_main_conf_t *umcf,
    ngx_str_t *host)
{
    uint32_t                        hash;
    ngx_int_t                       rc;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_upstream_srv_conf_t   *uscf;

    node = umcf->rbtree.root;
    sentinel = umcf->rbtree.sentinel;

    hash = ngx_crc32_short(host->data, host->len);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* node_key == node->key */

        uscf = (ngx_http_upstream_srv_conf_t *) node;

        rc = ngx_memn2cmp(host->data, uscf->host.data,
                          host->len, uscf->host.len);

        if (rc == 0) {
            return (uscf);
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return (NULL_PTR);
}
#endif

ngx_http_upstream_srv_conf_t *
cngx_upstream_search(ngx_http_request_t *r, ngx_str_t *host)
{
    ngx_http_upstream_main_conf_t           *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);

#if (NGX_HTTP_UPSTREAM_RBTREE)
    {
        ngx_http_upstream_srv_conf_t            *uscf;
        ngx_list_part_t                         *part;
        ngx_http_upstream_srv_conf_t           **uscfp;
        ngx_uint_t                               i;

        uscf = cngx_upstream_rbtree_lookup(umcf, host);

        if (uscf != NULL_PTR) {
            return uscf;
        }

        /*else*/

        part = &umcf->implicit_upstreams.part;
        uscfp = part->elts;

        for (i = 0; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL_PTR) {
                    break;
                }

                part = part->next;
                uscfp = part->elts;
                i = 0;
            }
            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                return uscf;
            }
        }
    }
#endif
    {
        ngx_http_upstream_srv_conf_t            *uscf;
        ngx_http_upstream_srv_conf_t           **uscfp;
        ngx_uint_t                               i;

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                return uscf;
            }
        }
    }

    return NULL_PTR;
}

/*ngx_http_upstream_create*/
EC_BOOL cngx_upstream_fetch(ngx_http_request_t *r, UINT32 *ipaddr, UINT32 *port)
{
    ngx_http_upstream_t                     *u;
    ngx_http_upstream_srv_conf_t            *uscf;

    ngx_http_bgn_loc_conf_t                 *blcf;
    ngx_str_t                               *name; /*upstream name*/

    ngx_url_t                                url;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    if(0 == blcf->bgn_upstream.active) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: no \"upstream_by_bgn\"");

        return (EC_FALSE);
    }

    u = r->upstream;
    if (NULL_PTR == u) {
        u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));

        if (NULL_PTR == u) {
            return (EC_FALSE);
        }

        u->peer.log = r->connection->log;
        r->upstream = u; /*arm upstream*/
    }

    if(NULL_PTR == blcf->bgn_upstream.proxy_lengths) {
        ngx_memzero(&url, sizeof(ngx_url_t));

        /*if url has domain or ip:port*/
        if (ngx_http_bgn_url_eval(r, blcf, &url) == NGX_OK) {
            if(ipaddr) {
                struct sockaddr_in   *sin;
                u_char               *p;

                sin = (struct sockaddr_in *) &url.sockaddr;
                p   = (u_char *) &sin->sin_addr;
                *ipaddr = (((uint32_t)p[0]) << 24)
                        | (((uint32_t)p[1]) << 16)
                        | (((uint32_t)p[2]) <<  8)
                        | (((uint32_t)p[3]) <<  0);
            }

            if(port) {
                in_port_t   in_port;

                in_port = ngx_inet_get_port((struct sockaddr *)&url.sockaddr);
                if(0 != in_port) {
                    (*port) = (uint16_t)in_port;
                }
            }

            return (EC_TRUE);
        }

        /*else*/

        if (url.host.len == 0 || url.host.data == NULL) {
            return (EC_FALSE);
        }

        /*if url is upstream name*/
        name = &url.host;
    }
    else {
        if(NULL_PTR == u->resolved) {
            if (ngx_http_bgn_proxy_eval(r, blcf) != NGX_OK) {
                return (EC_FALSE);
            }
        }
        name = &(u->resolved->host);
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "[cngx] cngx_upstream_fetch: blcf url %V, upstream %V",
                  &(blcf->bgn_upstream.url), name);

    uscf = u->upstream;

    if(NULL_PTR == uscf
    || uscf->host.len != name->len
    || 0 != ngx_strncasecmp(uscf->host.data, name->data, name->len))
    {
        uscf = cngx_upstream_search(r, name);
        if(NULL_PTR == uscf) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[cngx] cngx_upstream_fetch: no upstream '%V'",
                          name);

            return (EC_FALSE);
        }

        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: matched upstream %V", name);

        u->upstream = uscf; /*arm upstream srv conf*/
    }

    /*e.g., ngx_http_upstream_init_keepalive_peer*/
    if(NGX_OK != uscf->peer.init(r, uscf)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: upstream %V init peer failed",
                      &(uscf->host));
        return (EC_FALSE);
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "[cngx] cngx_upstream_fetch: upstream %V init peer done",
                  &(uscf->host));

    /*e.g., ngx_http_upstream_get_keepalive_peer*/
    if(NGX_OK != r->upstream->peer.get(&u->peer, u->peer.data)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: upstream %V get peer failed",
                      &(uscf->host));
        return (EC_FALSE);
    }

    if(NULL_PTR == u->peer.name || 1 == u->peer.down) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: upstream %V get empty or down peer",
                      &(uscf->host));
        return (EC_FALSE);
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "[cngx] cngx_upstream_fetch: upstream %V get peer done => name:%V",
                  &(uscf->host), u->peer.name);


    if(NULL_PTR == u->peer.sockaddr) {
        ngx_addr_t *addr;

        addr = ngx_pcalloc(r->pool, sizeof(ngx_addr_t));
        if(NULL_PTR == addr) {
            return (EC_FALSE);
        }

        if(NGX_OK != ngx_parse_addr_port(r->pool, addr,
                                u->peer.name->data, u->peer.name->len)) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "[cngx] cngx_upstream_fetch: upstream %V parse peer '%V' failed",
                          &(uscf->host), u->peer.name);
            return (EC_FALSE);
        }

        u->peer.sockaddr = addr->sockaddr;
        u->peer.socklen  = addr->socklen;
    }

    if(AF_INET != u->peer.sockaddr->sa_family) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: upstream %V peer '%V' => unknow proto family %d",
                      &(uscf->host), u->peer.name, u->peer.sockaddr->sa_family);
        return (EC_FALSE);
    }

    if(NULL_PTR != ipaddr) {
        struct sockaddr_in   *sin;
        u_char               *p;

        sin = (struct sockaddr_in *) u->peer.sockaddr;
        p   = (u_char *) &sin->sin_addr;
        *ipaddr = (((UINT32)p[0]) << 24)
                | (((UINT32)p[1]) << 16)
                | (((UINT32)p[2]) <<  8)
                | (((UINT32)p[3]) <<  0);

        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: upstream %V parse peer '%V' => ipaddr %ld (%s)",
                      &(uscf->host), u->peer.name, (*ipaddr), c_word_to_ipv4(*ipaddr));
    }

    if(NULL_PTR != port) {
        in_port_t   in_port;

        in_port = ngx_inet_get_port(u->peer.sockaddr);
        if(0 != in_port) {
            (*port) = in_port;
        }

        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "[cngx] cngx_upstream_fetch: upstream %V parse peer '%V' => port %d",
                      &(uscf->host), u->peer.name, in_port);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_upstream_set_down(ngx_http_request_t *r)
{
    ngx_http_upstream_t                     *u;
    ngx_http_upstream_srv_conf_t            *uscf;
    ngx_peer_connection_t                   *pc;

    u = r->upstream;

    if(NULL_PTR == u || NULL_PTR == u->upstream) {
        return (EC_FALSE);
    }

    uscf = u->upstream;
    pc   = &u->peer;

    if(NULL_PTR != uscf->peer.data) {
        ngx_http_upstream_rr_peers_t            *peers;
        ngx_http_upstream_rr_peer_t             *peer;

        for(peers = uscf->peer.data, peer = peers->peer; NULL_PTR != peer; peer = peer->next) {
            /*
             * warning: check ngx_http_upstream_get_round_robin_peer() indicating that
             * pc name would be peer name (pc->name = &peer->name) or peers name (pc->name = peers->name)
             * thus cannot finger out peer by name but by sockaddr.
             *
             */

            if(pc->sockaddr == peer->sockaddr && 0 == peer->down) {
                peer->down = 1;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "[cngx] cngx_upstream_set_down: upstream '%V' set peer '%V' down",
                              &(uscf->host), &(peer->name));
                return (EC_TRUE);
            }
        }
    }

    return (EC_FALSE);
}

EC_BOOL cngx_upstream_set_up(ngx_http_request_t *r)
{
    ngx_http_upstream_t                     *u;
    ngx_http_upstream_srv_conf_t            *uscf;
    ngx_peer_connection_t                   *pc;

    u = r->upstream;

    if(NULL_PTR == u || NULL_PTR == u->upstream) {
        return (EC_FALSE);
    }

    uscf = u->upstream;
    pc   = &u->peer;

    if(NULL_PTR != uscf->peer.data) {
        ngx_http_upstream_rr_peers_t            *peers;
        ngx_http_upstream_rr_peer_t             *peer;

        for(peers = uscf->peer.data, peer = peers->peer; NULL_PTR != peer; peer = peer->next) {
            /*
             * warning: check ngx_http_upstream_get_round_robin_peer() indicating that
             * pc name would be peer name (pc->name = &peer->name) or peers name (pc->name = peers->name)
             * thus cannot finger out peer by name but by sockaddr.
             *
             */

            if(pc->sockaddr == peer->sockaddr && 1 == peer->down) {
                peer->down = 0;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "[cngx] cngx_upstream_set_down: upstream '%V' set peer '%V' up",
                              &(uscf->host), &(peer->name));
                return (EC_TRUE);
            }
        }
    }

    return (EC_FALSE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
