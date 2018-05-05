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

#ifndef _CEXPAT_H
#define _CEXPAT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <expat.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"
#include "cbuffer.h"

#define uri_XML         "http://www.w3.org/XML/1998/namespace"

/* known namespace uri */
#define uri_STREAMS     "http://etherx.jabber.org/streams"
#define uri_CLIENT      "jabber:client"
#define uri_SERVER      "jabber:server"
#define uri_DIALBACK    "jabber:server:dialback"
#define uri_DIALBACK_L	22	/* strlen(uri_DIALBACK) */
#define uri_URN_DIALBACK "urn:xmpp:features:dialback"
#define uri_TLS         "urn:ietf:params:xml:ns:xmpp-tls"
#define uri_SASL        "urn:ietf:params:xml:ns:xmpp-sasl"
#define uri_BIND        "urn:ietf:params:xml:ns:xmpp-bind"
#define uri_XSESSION    "urn:ietf:params:xml:ns:xmpp-session"
#define uri_COMPRESS    "http://jabber.org/protocol/compress"
#define uri_COMPRESS_FEATURE "http://jabber.org/features/compress"
#define uri_ACK         "http://www.xmpp.org/extensions/xep-0198.html#ns"
#define uri_IQAUTH      "http://jabber.org/features/iq-auth"
#define uri_IQREGISTER  "http://jabber.org/features/iq-register"
#define uri_STREAM_ERR  "urn:ietf:params:xml:ns:xmpp-streams"
#define uri_STANZA_ERR  "urn:ietf:params:xml:ns:xmpp-stanzas"
#define uri_COMPONENT   "http://jabberd.jabberstudio.org/ns/component/1.0"
#define uri_SESSION     "http://jabberd.jabberstudio.org/ns/session/1.0"
#define uri_RESOLVER    "http://jabberd.jabberstudio.org/ns/resolver/1.0"
#define uri_XDATA       "jabber:x:data"
#define uri_OOB         "jabber:x:oob"
#define uri_ADDRESS_FEATURE "http://affinix.com/jabber/address"
#define uri_ROSTERVER   "urn:xmpp:features:rosterver"

/* these are used by SM mainly */
#define uri_AUTH        "jabber:iq:auth"
#define uri_REGISTER    "jabber:iq:register"
#define uri_ROSTER      "jabber:iq:roster"
#define uri_AGENTS      "jabber:iq:agents"
#define uri_DELAY       "jabber:x:delay"
#define uri_URN_DELAY   "urn:xmpp:delay"
#define uri_TIME        "jabber:iq:time"
#define urn_TIME        "urn:xmpp:time"
#define uri_VERSION     "jabber:iq:version"
#define uri_BROWSE      "jabber:iq:browse"
#define uri_EVENT       "jabber:x:event"
#define uri_GATEWAY     "jabber:iq:gateway"
#define uri_EXPIRE      "jabber:x:expire"
#define uri_PRIVACY     "jabber:iq:privacy"
#define urn_BLOCKING    "urn:xmpp:blocking"
#define urn_BLOCKING_ERR "urn:xmpp:blocking:errors"
#define uri_SEARCH      "jabber:iq:search"
#define urn_PING        "urn:xmpp:ping"
#define uri_DISCO       "http://jabber.org/protocol/disco"
#define uri_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define uri_DISCO_INFO  "http://jabber.org/protocol/disco#info"
#define uri_SERVERINFO  "http://jabber.org/network/serverinfo"
#define urn_SOFTWAREINFO "urn:xmpp:dataforms:softwareinfo"

#define uri_AMP                         "http://jabber.org/protocol/amp"
#define uri_AMP_ERRORS                  "http://jabber.org/protocol/amp#errors"
#define uri_AMP_ACTION_DROP             "http://jabber.org/protocol/amp?action=drop"
#define uri_AMP_ACTION_ERROR            "http://jabber.org/protocol/amp?action=error"
#define uri_AMP_ACTION_NOTIFY           "http://jabber.org/protocol/amp?action=notify"
#define uri_AMP_CONDITION_DELIVER       "http://jabber.org/protocol/amp?condition=deliver"
#define uri_AMP_CONDITION_EXPIREAT      "http://jabber.org/protocol/amp?condition=expire-at"
#define uri_AMP_CONDITION_MATCHRESOURCE "http://jabber.org/protocol/amp?condition=match-resource"

#define    state_STREAM_RECEIVED  ((uint32_t)0)  /* stream start received (server) */
#define    state_STREAM_SENT      ((uint32_t)1)  /* stream start sent (client) */
#define    state_STREAM           ((uint32_t)2)  /* stream established */
#define    state_OPEN             ((uint32_t)3)  /* auth completed (normal stream operation) */
#define    state_CLOSING          ((uint32_t)4)  /* ready to close (send event_CLOSED to app) */
#define    state_CLOSED           ((uint32_t)5)  /* closed (same as NONE, but can't be used any more) */

/* stream errors */
#define stream_err_BAD_FORMAT               (0)
#define stream_err_BAD_NAMESPACE_PREFIX     (1)
#define stream_err_CONFLICT                 (2)
#define stream_err_CONNECTION_TIMEOUT       (3)
#define stream_err_HOST_GONE                (4)
#define stream_err_HOST_UNKNOWN             (5)
#define stream_err_IMPROPER_ADDRESSING      (6)
#define stream_err_INTERNAL_SERVER_ERROR    (7)
#define stream_err_INVALID_FROM             (8)
#define stream_err_INVALID_ID               (9)
#define stream_err_INVALID_NAMESPACE        (10)
#define stream_err_INVALID_XML              (11)
#define stream_err_NOT_AUTHORIZED           (12)
#define stream_err_POLICY_VIOLATION         (13)
#define stream_err_REMOTE_CONNECTION_FAILED (14)
#define stream_err_RESTRICTED_XML           (15)
#define stream_err_RESOURCE_CONSTRAINT      (16)
#define stream_err_SEE_OTHER_HOST           (17)
#define stream_err_SYSTEM_SHUTDOWN          (18)
#define stream_err_UNDEFINED_CONDITION      (19)
#define stream_err_UNSUPPORTED_ENCODING     (20)
#define stream_err_UNSUPPORTED_STANZA_TYPE  (21)
#define stream_err_UNSUPPORTED_VERSION      (22)
#define stream_err_XML_NOT_WELL_FORMED      (23)
#define stream_err_LAST                     (24)


#define CEXPAT_PATH_MAX_DEPTH               (32)

typedef struct
{
    CSTRING   name;
    CSTRING   val;
}CEXPAT_ATTR;

#define CEXPAT_ATTR_NAME(cexpat_attr)      (&((cexpat_attr)->name))
#define CEXPAT_ATTR_VAL(cexpat_attr)       (&((cexpat_attr)->val))
#define CEXPAT_ATTR_NAME_STR(cexpat_attr)  ((char *)cstring_get_str(CEXPAT_ATTR_NAME(cexpat_attr)))
#define CEXPAT_ATTR_VAL_STR(cexpat_attr)   ((char *)cstring_get_str(CEXPAT_ATTR_VAL(cexpat_attr)))

typedef struct _CEXPAT_NODE
{
    struct _CEXPAT_NODE     *parent;
    CLIST                    children; /*attribute list, item is CEXPAT_NODE*/

    CSTRING                  name;
    CBYTES                  *cdata;    /*cdata*/
    CLIST                    attr_list;/*attribute list, item is CEXPAT_ATTR*/
}CEXPAT_NODE;

#define CEXPAT_NODE_PARENT(cexpat_node)    ((cexpat_node)->parent)
#define CEXPAT_NODE_CHILDREN(cexpat_node)  (&((cexpat_node)->children))
#define CEXPAT_NODE_NAME(cexpat_node)      (&((cexpat_node)->name))
#define CEXPAT_NODE_CDATA(cexpat_node)     ((cexpat_node)->cdata)
#define CEXPAT_NODE_ATTRS(cexpat_node)     (&((cexpat_node)->attr_list))

#define CEXPAT_NODE_NAME_STR(cexpat_node)  ((char *)cstring_get_str(CEXPAT_NODE_NAME(cexpat_node)))
#define CEXPAT_NODE_CDATA_LEN(cexpat_node)  (CBYTES_LEN(CEXPAT_NODE_CDATA(cexpat_node)))
#define CEXPAT_NODE_CDATA_BUF(cexpat_node)  ((char *)CBYTES_BUF(CEXPAT_NODE_CDATA(cexpat_node)))

#define CEXPAT_PARSE_SUCC                 ((uint16_t) 0)
#define CEXPAT_PARSE_FAIL                 ((uint16_t) 1)

#define CEXPAT_PARSE_HEADER_IS_DONE       ((uint16_t) 1)
#define CEXPAT_PARSE_HEADER_NOT_DONE      ((uint16_t) 0)

typedef struct
{
    XML_Parser   xml_parser;
    CEXPAT_NODE *root_node;
    CEXPAT_NODE *cur_node;

    uint32_t     depth;/*depth recorder*/
    uint16_t     fail; /*fail flag*/
    uint16_t     header_done; /*header reached flag*/
}CEXPAT_PARSER;

#define CEXPAT_PARSER_XML_PARSER(cexpat_parser)  ((cexpat_parser)->xml_parser)
#define CEXPAT_PARSER_ROOT_NODE(cexpat_parser)   ((cexpat_parser)->root_node)
#define CEXPAT_PARSER_CUR_NODE(cexpat_parser)    ((cexpat_parser)->cur_node)
#define CEXPAT_PARSER_DEPTH(cexpat_parser)       ((cexpat_parser)->depth)
#define CEXPAT_PARSER_FAIL(cexpat_parser)        ((cexpat_parser)->fail)
#define CEXPAT_PARSER_HEADER_DONE(cexpat_parser) ((cexpat_parser)->header_done)


CEXPAT_ATTR *cexpat_attr_new();

EC_BOOL cexpat_attr_init(CEXPAT_ATTR *cexpat_attr);

EC_BOOL cexpat_attr_clean(CEXPAT_ATTR *cexpat_attr);

EC_BOOL cexpat_attr_free(CEXPAT_ATTR *cexpat_attr);

CEXPAT_ATTR *cexpat_attr_make(const uint8_t *name, const uint8_t *val);

void cexpat_attr_print(LOG *log, const CEXPAT_ATTR *cexpat_attr);

void cexpat_attr_print_level(LOG *log, const CEXPAT_ATTR *cexpat_attr, const UINT32 level);

void cexpat_attr_print_xml(LOG *log, const CEXPAT_ATTR *cexpat_attr);

void cexpat_node_attrs_print(LOG *log, const CEXPAT_NODE *cexpat_node);

void cexpat_node_attrs_print_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level);

void cexpat_node_attrs_print_xml(LOG *log, const CEXPAT_NODE *cexpat_node);

CEXPAT_NODE *cexpat_node_new();

EC_BOOL cexpat_node_init(CEXPAT_NODE *cexpat_node);

EC_BOOL cexpat_node_clean(CEXPAT_NODE *cexpat_node);

EC_BOOL cexpat_node_free(CEXPAT_NODE *cexpat_node);

CEXPAT_NODE *cexpat_node_make(const uint8_t *name);

EC_BOOL cexpat_node_set_name(CEXPAT_NODE *cexpat_node, const uint8_t *name);

EC_BOOL cexpat_node_add_attr(CEXPAT_NODE *cexpat_node, const uint8_t *attr_name, const uint8_t *attr_val);

EC_BOOL cexpat_node_add_child(CEXPAT_NODE *cexpat_node, const CEXPAT_NODE *cexpat_node_child);

EC_BOOL cexpat_node_set_cdata(CEXPAT_NODE *cexpat_node, const CBYTES *cdata);

EC_BOOL cexpat_node_clone_attr(const CEXPAT_NODE *cexpat_node_src, CEXPAT_NODE *cexpat_node_des, const uint8_t *attr_name);

EC_BOOL cexpat_node_xclone_attr(const CEXPAT_NODE *cexpat_node_src, CEXPAT_NODE *cexpat_node_des, const uint8_t *attr_name_src, const uint8_t *attr_name_des);

void cexpat_node_print(LOG *log, const CEXPAT_NODE *cexpat_node);

void cexpat_node_print_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level);

void cexpat_node_depth_print(LOG *log, const CEXPAT_NODE *cexpat_node);

void cexpat_node_depth_print_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level);

void cexpat_node_print_xml_beg(LOG *log, const CEXPAT_NODE *cexpat_node);

void cexpat_node_print_xml_end(LOG *log, const CEXPAT_NODE *cexpat_node);

void cexpat_node_print_xml_level_beg(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level);

void cexpat_node_print_xml_level_end(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level);

void cexpat_node_depth_print_xml(LOG *log, const CEXPAT_NODE *cexpat_node);

void cexpat_node_depth_print_xml_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level);

EC_BOOL cexpat_parser_init(CEXPAT_PARSER *cexpat_parser);

EC_BOOL cexpat_parser_clean(CEXPAT_PARSER *cexpat_parser);

EC_BOOL cexpat_parser_clear(CEXPAT_PARSER *cexpat_parser);

EC_BOOL cexpat_parser_open(CEXPAT_PARSER *cexpat_parser);

EC_BOOL cexpat_parser_close(CEXPAT_PARSER *cexpat_parser);

EC_BOOL cexpat_node_parse(CEXPAT_PARSER *cexpat_parser, const uint8_t *buf, uint32_t len);

EC_BOOL cexpat_attr_encode_xml(const CEXPAT_ATTR *cexpat_attr, CBUFFER *cbuffer);

EC_BOOL cexpat_node_attrs_encode_xml(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer);

EC_BOOL cexpat_node_encode_xml_beg(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer);

EC_BOOL cexpat_node_encode_xml_end(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer);

EC_BOOL cexpat_node_encode_xml(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer, const EC_BOOL scope_closed);

EC_BOOL cexpat_attr_match(const CEXPAT_ATTR *cexpat_attr, const uint8_t *attr_name);

const CSTRING *cexpat_find_attr(const CEXPAT_NODE *cexpat_node, const uint8_t *attr_name);

EC_BOOL cexpat_node_match(const CEXPAT_NODE *cexpat_node, const uint8_t *node_name);

const CEXPAT_NODE *cexpat_find_child_node(const CEXPAT_NODE *cexpat_node, const uint8_t *node_name);

const CEXPAT_NODE *cexpat_find_node_by_fields(const CEXPAT_NODE *cexpat_node, const uint8_t **fields, const UINT32 field_num);

const CEXPAT_NODE *cexpat_find_node_by_path(const CEXPAT_NODE *cexpat_node, const uint8_t *path, const uint8_t *delim);

const CSTRING *cexpat_find_attr_by_fields(const CEXPAT_NODE *cexpat_node, const uint8_t **fields, const UINT32 field_num);

const CSTRING *cexpat_find_attr_by_path(const CEXPAT_NODE *cexpat_node, const uint8_t *path, const uint8_t *delim);

const CBYTES *cexpat_find_cdata_by_fields(const CEXPAT_NODE *cexpat_node, const uint8_t **fields, const UINT32 field_num);

const CBYTES *cexpat_find_cdata_by_path(const CEXPAT_NODE *cexpat_node, const uint8_t *path, const uint8_t *delim);


#endif/*_CEXPAT_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


