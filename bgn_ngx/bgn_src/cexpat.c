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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"
#include "cbuffer.h"
#include "cexpat.h"

#if 0
static const char *g_cexpat_stream_errors[] =
{
    "bad-format",
    "bad-namespace-prefix",
    "conflict",
    "connection-timeout",
    "host-gone",
    "host-unknown",
    "improper-addressing",
    "internal-server-error",
    "invalid-from",
    "invalid-id",
    "invalid-namespace",
    "invalid-xml",
    "not-authorized",
    "policy-violation",
    "remote-connection-failed",
    "restricted-xml",
    "resource-constraint",
    "see-other-host",
    "system-shutdown",
    "undefined-condition",
    "unsupported-encoding",
    "unsupported-stanza-type",
    "unsupported-version",
    "xml-not-well-formed",
    NULL_PTR
};
#endif
CEXPAT_ATTR *cexpat_attr_new()
{
    CEXPAT_ATTR *cexpat_attr;

    alloc_static_mem(MM_CEXPAT_ATTR, &cexpat_attr, LOC_CEXPAT_0001);
    if(NULL_PTR == cexpat_attr)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_attr_new: new cexpat_attr failed\n");
        return (NULL_PTR);
    }

    cexpat_attr_init(cexpat_attr);
    return (cexpat_attr);
}

EC_BOOL cexpat_attr_init(CEXPAT_ATTR *cexpat_attr)
{
    cstring_init(CEXPAT_ATTR_NAME(cexpat_attr), NULL_PTR);
    cstring_init(CEXPAT_ATTR_VAL(cexpat_attr), NULL_PTR);
 
    return (EC_TRUE);
}

static EC_BOOL __cexpat_attr_make(CEXPAT_ATTR *cexpat_attr, const uint8_t *name, const uint8_t *val)
{
    cstring_init(CEXPAT_ATTR_NAME(cexpat_attr), name);
    cstring_init(CEXPAT_ATTR_VAL(cexpat_attr), val);
 
    return (EC_TRUE);
}

EC_BOOL cexpat_attr_clean(CEXPAT_ATTR *cexpat_attr)
{
    cstring_clean(CEXPAT_ATTR_NAME(cexpat_attr));
    cstring_clean(CEXPAT_ATTR_VAL(cexpat_attr));
 
    return (EC_TRUE);
}

EC_BOOL cexpat_attr_free(CEXPAT_ATTR *cexpat_attr)
{
    if(NULL_PTR != cexpat_attr)
    {
        cexpat_attr_clean(cexpat_attr);
        free_static_mem(MM_CEXPAT_ATTR, cexpat_attr, LOC_CEXPAT_0002);
    }
    return (EC_TRUE);
}

CEXPAT_ATTR *cexpat_attr_make(const uint8_t *name, const uint8_t *val)
{
    CEXPAT_ATTR *cexpat_attr;

    alloc_static_mem(MM_CEXPAT_ATTR, &cexpat_attr, LOC_CEXPAT_0003);
    if(NULL_PTR == cexpat_attr)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_attr_make: new cexpat_attr failed\n");
        return (NULL_PTR);
    }

    __cexpat_attr_make(cexpat_attr, name, val);

    return (cexpat_attr);
}

void cexpat_attr_print(LOG *log, const CEXPAT_ATTR *cexpat_attr)
{
    sys_log(log, "attr %p: name = [%s], val = [%s]\n",
                     cexpat_attr,
                     CEXPAT_ATTR_NAME_STR(cexpat_attr),
                     CEXPAT_ATTR_VAL_STR(cexpat_attr));
    return;
}

void cexpat_attr_print_level(LOG *log, const CEXPAT_ATTR *cexpat_attr, const UINT32 level)
{
    c_indent_print(log, level);
    sys_log(log, "attr %p: name = [%s], val = [%s]\n",
                     cexpat_attr,
                     CEXPAT_ATTR_NAME_STR(cexpat_attr),
                     CEXPAT_ATTR_VAL_STR(cexpat_attr));
    return;
}

void cexpat_attr_print_xml(LOG *log, const CEXPAT_ATTR *cexpat_attr)
{
    sys_print(log, " %s='%s'",
                 CEXPAT_ATTR_NAME_STR(cexpat_attr),
                 CEXPAT_ATTR_VAL_STR(cexpat_attr));
    return;
}

void cexpat_node_attrs_print(LOG *log, const CEXPAT_NODE *cexpat_node)
{
    const CLIST *cexpat_attr_list;

    cexpat_attr_list = CEXPAT_NODE_ATTRS(cexpat_node);
    if(EC_FALSE == clist_is_empty(cexpat_attr_list))
    {
        clist_print(log, cexpat_attr_list, (CLIST_DATA_DATA_PRINT)cexpat_attr_print);
    }
    return; 
}

void cexpat_node_attrs_print_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level)
{
    const CLIST *cexpat_attr_list;

    cexpat_attr_list = CEXPAT_NODE_ATTRS(cexpat_node);
    if(EC_FALSE == clist_is_empty(cexpat_attr_list))
    {
        clist_print_level(log, cexpat_attr_list, level, (CLIST_DATA_LEVEL_PRINT)cexpat_attr_print_level);
    }
    return; 
}

void cexpat_node_attrs_print_xml(LOG *log, const CEXPAT_NODE *cexpat_node)
{
    const CLIST *cexpat_attr_list;

    cexpat_attr_list = CEXPAT_NODE_ATTRS(cexpat_node);
    if(EC_FALSE == clist_is_empty(cexpat_attr_list))
    {
        clist_print_plain(log, cexpat_attr_list, (CLIST_DATA_DATA_PRINT)cexpat_attr_print_xml);
    }
    return; 
}

void cexpat_attr_list_print_xml(LOG *log, const CLIST *cexpat_attr_list)
{
    if(EC_FALSE == clist_is_empty(cexpat_attr_list))
    {
        clist_print_plain(log, cexpat_attr_list, (CLIST_DATA_DATA_PRINT)cexpat_attr_print_xml);
    }
    return;
}

CEXPAT_NODE *cexpat_node_new()
{
    CEXPAT_NODE *cexpat_node;

    alloc_static_mem(MM_CEXPAT_NODE, &cexpat_node, LOC_CEXPAT_0004);
    if(NULL_PTR == cexpat_node)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_node_new: new cexpat_node failed\n");
        return (NULL_PTR);
    }

    cexpat_node_init(cexpat_node);
    return (cexpat_node);
}

EC_BOOL cexpat_node_init(CEXPAT_NODE *cexpat_node)
{
    CEXPAT_NODE_PARENT(cexpat_node) = NULL_PTR;
    clist_init(CEXPAT_NODE_CHILDREN(cexpat_node), MM_CEXPAT_NODE, LOC_CEXPAT_0005);
 
    cstring_init(CEXPAT_NODE_NAME(cexpat_node), NULL_PTR);

    CEXPAT_NODE_CDATA(cexpat_node) = NULL_PTR;
    clist_init(CEXPAT_NODE_ATTRS(cexpat_node), MM_CEXPAT_ATTR, LOC_CEXPAT_0006);
 
    return (EC_TRUE);
}

static EC_BOOL __cexpat_node_make(CEXPAT_NODE *cexpat_node, const uint8_t *name)
{
    CEXPAT_NODE_PARENT(cexpat_node) = NULL_PTR;
    clist_init(CEXPAT_NODE_CHILDREN(cexpat_node), MM_CEXPAT_NODE, LOC_CEXPAT_0007);
 
    cstring_init(CEXPAT_NODE_NAME(cexpat_node), name);

    CEXPAT_NODE_CDATA(cexpat_node) = NULL_PTR;
    clist_init(CEXPAT_NODE_ATTRS(cexpat_node), MM_CEXPAT_ATTR, LOC_CEXPAT_0008);
 
    return (EC_TRUE);
}

EC_BOOL cexpat_node_clean(CEXPAT_NODE *cexpat_node)
{
    CEXPAT_NODE_PARENT(cexpat_node) = NULL_PTR;
    clist_clean(CEXPAT_NODE_CHILDREN(cexpat_node), (CLIST_DATA_DATA_CLEANER)cexpat_node_free);
 
    cstring_clean(CEXPAT_NODE_NAME(cexpat_node));

    if(NULL_PTR != CEXPAT_NODE_CDATA(cexpat_node))
    {
        cbytes_free(CEXPAT_NODE_CDATA(cexpat_node));
        CEXPAT_NODE_CDATA(cexpat_node) = NULL_PTR;
    }

    clist_clean(CEXPAT_NODE_ATTRS(cexpat_node), (CLIST_DATA_DATA_CLEANER)cexpat_attr_free);
 
    return (EC_TRUE);
}

EC_BOOL cexpat_node_free(CEXPAT_NODE *cexpat_node)
{
    if(NULL_PTR != cexpat_node)
    {
        cexpat_node_clean(cexpat_node);
        free_static_mem(MM_CEXPAT_NODE, cexpat_node, LOC_CEXPAT_0009);
    }
    return (EC_TRUE);
}

CEXPAT_NODE *cexpat_node_make(const uint8_t *name)
{
    CEXPAT_NODE *cexpat_node;

    alloc_static_mem(MM_CEXPAT_NODE, &cexpat_node, LOC_CEXPAT_0010);
    if(NULL_PTR == cexpat_node)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_node_make: new cexpat_node failed\n");
        return (NULL_PTR);
    }

    __cexpat_node_make(cexpat_node, name);

    return (cexpat_node);
}

EC_BOOL cexpat_node_set_name(CEXPAT_NODE *cexpat_node, const uint8_t *name)
{
    cstring_init(CEXPAT_NODE_NAME(cexpat_node), name);
    return (EC_TRUE);
}

EC_BOOL cexpat_node_add_attr(CEXPAT_NODE *cexpat_node, const uint8_t *attr_name, const uint8_t *attr_val)
{
    CEXPAT_ATTR *cexpat_attr;

    cexpat_attr = cexpat_attr_make(attr_name, attr_val);
    if(NULL_PTR == cexpat_attr)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_node_add_attr: make cexpat_attr [%s]=[%s] failed\n",
                            (const char *)attr_name, (const char *)attr_val);
        return (EC_FALSE);
    }

    clist_push_back(CEXPAT_NODE_ATTRS(cexpat_node), (void *)cexpat_attr);
    return (EC_TRUE);
}

EC_BOOL cexpat_node_add_child(CEXPAT_NODE *cexpat_node, const CEXPAT_NODE *cexpat_node_child)
{
    if(NULL_PTR != cexpat_node_child)
    {
        clist_push_back(CEXPAT_NODE_CHILDREN(cexpat_node), (void *)cexpat_node_child);
    }
    return (EC_TRUE);
}

EC_BOOL cexpat_node_set_cdata(CEXPAT_NODE *cexpat_node, const CBYTES *cdata)
{
    CEXPAT_NODE_CDATA(cexpat_node) = (CBYTES *)cdata;
    return (EC_TRUE);
}

EC_BOOL cexpat_node_clone_attr(const CEXPAT_NODE *cexpat_node_src, CEXPAT_NODE *cexpat_node_des, const uint8_t *attr_name)
{
    const CSTRING *attr_val_cstr;

    attr_val_cstr = cexpat_find_attr(cexpat_node_src, (const uint8_t *)attr_name);
    if(NULL_PTR == attr_val_cstr)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_node_clone_attr: not find attr [%s] in src node %p\n",
                           (const char *)attr_name, cexpat_node_src);
        return (EC_FALSE);
    }

    return cexpat_node_add_attr(cexpat_node_des, attr_name, cstring_get_str(attr_val_cstr));
}

EC_BOOL cexpat_node_xclone_attr(const CEXPAT_NODE *cexpat_node_src, CEXPAT_NODE *cexpat_node_des, const uint8_t *attr_name_src, const uint8_t *attr_name_des)
{
    const CSTRING *attr_val_cstr;

    attr_val_cstr = cexpat_find_attr(cexpat_node_src, (const uint8_t *)attr_name_src);
    if(NULL_PTR == attr_val_cstr)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_node_xclone_attr: not find attr [%s] in src node %p\n",
                           (const char *)attr_name_src, cexpat_node_src);                        
        return (EC_FALSE);
    }

    return cexpat_node_add_attr(cexpat_node_des, attr_name_des, cstring_get_str(attr_val_cstr));
}

void cexpat_node_print(LOG *log, const CEXPAT_NODE *cexpat_node)
{
    sys_log(log, "node %p: name = [%s]\n", cexpat_node, CEXPAT_NODE_NAME_STR(cexpat_node));

    cexpat_node_attrs_print(log, cexpat_node);
    if(NULL_PTR != CEXPAT_NODE_CDATA(cexpat_node))
    {
        sys_log(log, "node %p: cdata = [%.*s]\n",
                      cexpat_node,
                      CEXPAT_NODE_CDATA_LEN(cexpat_node),
                      CEXPAT_NODE_CDATA_BUF(cexpat_node));
    }
    return;
}

void cexpat_node_print_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level)
{
    c_indent_print(log, level);
    sys_log(log, "node %p: name = [%s]\n", cexpat_node, CEXPAT_NODE_NAME_STR(cexpat_node));

    cexpat_node_attrs_print_level(log, cexpat_node, level);
    if(NULL_PTR != CEXPAT_NODE_CDATA(cexpat_node))
    {
        c_indent_print(log, level);
        sys_log(log, "node %p: cdata = [%.*s]\n",
                     cexpat_node,
                     CEXPAT_NODE_CDATA_LEN(cexpat_node),
                     CEXPAT_NODE_CDATA_BUF(cexpat_node));
    }
    return;
}

void cexpat_node_depth_print(LOG *log, const CEXPAT_NODE *cexpat_node)
{
    cexpat_node_print(log, cexpat_node);
    if(EC_FALSE == clist_is_empty(CEXPAT_NODE_CHILDREN(cexpat_node)))
    {
        clist_print(log, CEXPAT_NODE_CHILDREN(cexpat_node), (CLIST_DATA_DATA_PRINT)cexpat_node_depth_print);
    }
    return;
}

void cexpat_node_depth_print_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level)
{
    cexpat_node_print_level(log, cexpat_node, level);
    if(EC_FALSE == clist_is_empty(CEXPAT_NODE_CHILDREN(cexpat_node)))
    {
        clist_print_level(log, CEXPAT_NODE_CHILDREN(cexpat_node), level + 1, (CLIST_DATA_LEVEL_PRINT)cexpat_node_depth_print_level);
    }
    return;
}

void cexpat_node_print_xml_beg(LOG *log, const CEXPAT_NODE *cexpat_node)
{
    if(NULL_PTR != CEXPAT_NODE_CDATA(cexpat_node))
    {
        sys_print(log, "<%s", CEXPAT_NODE_NAME_STR(cexpat_node));

        cexpat_node_attrs_print_xml(log, cexpat_node);
        sys_print(log, ">");

        sys_print(log, "%.*s</%s>\n",
                       CEXPAT_NODE_CDATA_LEN(cexpat_node),
                       CEXPAT_NODE_CDATA_BUF(cexpat_node),
                       CEXPAT_NODE_NAME_STR(cexpat_node));                    
    }
    else
    {
        sys_print(log, "<%s", CEXPAT_NODE_NAME_STR(cexpat_node));

        cexpat_node_attrs_print_xml(log, cexpat_node);
        sys_print(log, ">\n"); 
    }
    return;
}

void cexpat_node_print_xml_end(LOG *log, const CEXPAT_NODE *cexpat_node)
{
    if(NULL_PTR == CEXPAT_NODE_CDATA(cexpat_node))
    {
        sys_print(log, "</%s>\n", CEXPAT_NODE_NAME_STR(cexpat_node));
    }
    return;
}

void cexpat_node_print_xml_level_beg(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level)
{
    if(NULL_PTR != CEXPAT_NODE_CDATA(cexpat_node))
    {
        c_indent_print(log, level);
        sys_print(log, "<%s", CEXPAT_NODE_NAME_STR(cexpat_node));

        cexpat_node_attrs_print_xml(log, cexpat_node);
        sys_print(log, ">");

        sys_print(log, "%.*s</%s>\n",
                       CEXPAT_NODE_CDATA_LEN(cexpat_node),
                       CEXPAT_NODE_CDATA_BUF(cexpat_node),
                       CEXPAT_NODE_NAME_STR(cexpat_node));                    
    }
    else
    {
        c_indent_print(log, level);
        sys_print(log, "<%s", CEXPAT_NODE_NAME_STR(cexpat_node));

        cexpat_node_attrs_print_xml(log, cexpat_node);
        sys_print(log, ">\n"); 
    }
    return;
}

void cexpat_node_print_xml_level_end(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level)
{
    if(NULL_PTR == CEXPAT_NODE_CDATA(cexpat_node))
    {
        c_indent_print(log, level);
        sys_print(log, "</%s>\n", CEXPAT_NODE_NAME_STR(cexpat_node));
    }
    return;
}

void cexpat_node_depth_print_xml(LOG *log, const CEXPAT_NODE *cexpat_node)
{
    cexpat_node_print_xml_beg(log, cexpat_node);
    if(EC_FALSE == clist_is_empty(CEXPAT_NODE_CHILDREN(cexpat_node)))
    {
        clist_print_plain(log, CEXPAT_NODE_CHILDREN(cexpat_node), (CLIST_DATA_DATA_PRINT)cexpat_node_depth_print_xml);
    }
    cexpat_node_print_xml_end(log, cexpat_node);
    return;
}

void cexpat_node_depth_print_xml_level(LOG *log, const CEXPAT_NODE *cexpat_node, const UINT32 level)
{
    cexpat_node_print_xml_level_beg(log, cexpat_node, level);
    if(EC_FALSE == clist_is_empty(CEXPAT_NODE_CHILDREN(cexpat_node)))
    {
        clist_print_plain_level(log, CEXPAT_NODE_CHILDREN(cexpat_node), level + 1,
                          (CLIST_DATA_LEVEL_PRINT)cexpat_node_depth_print_xml_level);
    }
    cexpat_node_print_xml_level_end(log, cexpat_node, level);
    return;
}

static void __cexpat_node_parse_start(void *arg, const char *name, const char **attrs)
{
    CEXPAT_PARSER  *cexpat_parser;
    CEXPAT_NODE    *cexpat_node_new;
    CEXPAT_NODE    *cexpat_node_cur;
    const char    **attr;

    cexpat_parser = (CEXPAT_PARSER *)arg;

    if(CEXPAT_PARSE_FAIL == CEXPAT_PARSER_FAIL(cexpat_parser))
    {
        return;
    }

    cexpat_node_cur = CEXPAT_PARSER_CUR_NODE(cexpat_parser);

    if(0 && do_log(SEC_0148_CEXPAT, 9))
    {
        if(NULL_PTR != cexpat_node_cur)
        {
            sys_log(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_start: cur %p, name = [%s]\n",
                               cexpat_node_cur, CEXPAT_NODE_NAME_STR(cexpat_node_cur));
        }
        else
        {
            sys_log(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_start: cur is null\n");
        }
    }
    cexpat_node_new = cexpat_node_make((const uint8_t *)name);
    if(NULL_PTR == cexpat_node_new)
    {
        CEXPAT_PARSER_FAIL(cexpat_parser) = CEXPAT_PARSE_FAIL;
     
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:__cexpat_node_parse_start: make cexpat_node_new failed\n");
        return;
    }

    for(attr = attrs; NULL_PTR != attr[ 0 ]; attr += 2)
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] __cexpat_node_parse_start: new %p, attr is name [%s], val [%s]\n",
                          cexpat_node_new, attr[0], attr[1]);
        cexpat_node_add_attr(cexpat_node_new, (const uint8_t *)attr[ 0 ], (const uint8_t *)attr[ 1 ]);
    }

    if(NULL_PTR != cexpat_node_cur)
    {
        cexpat_node_add_child(cexpat_node_cur, cexpat_node_new);
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] __cexpat_node_parse_start: node %p, add child %p which name [%s]\n",
                          cexpat_node_cur, cexpat_node_new, CEXPAT_NODE_NAME_STR(cexpat_node_new));     
    }

    CEXPAT_NODE_PARENT(cexpat_node_new)   = cexpat_node_cur;
    CEXPAT_PARSER_CUR_NODE(cexpat_parser) = cexpat_node_new;
    CEXPAT_PARSER_DEPTH(cexpat_parser) ++;

    if(NULL_PTR == CEXPAT_PARSER_ROOT_NODE(cexpat_parser))
    {
        CEXPAT_PARSER_ROOT_NODE(cexpat_parser) = cexpat_node_new;
    }

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] __cexpat_node_parse_start: root %p, [%p -> %p]\n",
                       CEXPAT_PARSER_ROOT_NODE(cexpat_parser), cexpat_node_cur, cexpat_node_new);

    return;
}

static void __cexpat_node_parse_end(void *arg, const char *name)
{
    CEXPAT_PARSER  *cexpat_parser;
    CEXPAT_NODE    *cexpat_node;
 
    cexpat_parser = (CEXPAT_PARSER *)arg;
    cexpat_node   = CEXPAT_PARSER_CUR_NODE(cexpat_parser);

    CEXPAT_PARSER_CUR_NODE(cexpat_parser) = CEXPAT_NODE_PARENT(cexpat_node);
    CEXPAT_PARSER_DEPTH(cexpat_parser) --;

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_end: name = [%s]\n", name);
    return;
}

static void __cexpat_node_parse_cdata(void *arg, const char *str, int len)
{
    CEXPAT_PARSER *cexpat_parser;
    CEXPAT_NODE   *cexpat_node;
    CBYTES        *cdata;
    const char    *str_t;
    int            len_t;
 
    cexpat_parser = (CEXPAT_PARSER *)arg;
    cexpat_node   = CEXPAT_PARSER_CUR_NODE(cexpat_parser);

    if(CEXPAT_PARSE_FAIL == CEXPAT_PARSER_FAIL(cexpat_parser))
    {
        return;
    }

    str_t = c_str_skip_space(str, str + len);
    if(NULL_PTR == str_t)
    {
        /*ignore empty cdata*/
        return;
    }

    len_t = len - (str_t - str);
    ASSERT(0 < len_t && len_t <= len);

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_cdata: node %p, name = [%s], cdata: (%p, %d) -> (%p, %d)\n",
                       cexpat_node, CEXPAT_NODE_NAME_STR(cexpat_node), str, len, str_t, len_t);
 
    cdata = cbytes_make_by_bytes(len_t, (const uint8_t *)str_t);
    if(NULL_PTR == cdata)
    {
        CEXPAT_PARSER_FAIL(cexpat_parser) = CEXPAT_PARSE_FAIL;
     
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:__cexpat_node_parse_cdata: node %p, make cstring '%.*s' failed\n", cexpat_node, len, str);
        return;
    }

    CEXPAT_NODE_CDATA(cexpat_node) = cdata;

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_cdata: node %p, name = [%s] cdata = [%.*s]\n",
                       cexpat_node, CEXPAT_NODE_NAME_STR(cexpat_node), len_t, str_t);

    return;
}

static void __cexpat_node_entity_declaration(void *arg, const char *entityName,
                                          int is_parameter_entity, const char *value,
                                          int value_length, const char *base,
                                          const char *systemId, const char *publicId,
                                          const char *notationName)
{
    CEXPAT_PARSER  *cexpat_parser;
 
    cexpat_parser  = (CEXPAT_PARSER *)arg;

    XML_StopParser(CEXPAT_PARSER_XML_PARSER(cexpat_parser), XML_FALSE);
    return;
}

static void __cexpat_node_parse_header(void *arg, const char *str, int len)
{
    CEXPAT_PARSER *cexpat_parser;
    CEXPAT_NODE   *cexpat_node;
    char          *str_dup;
    char          *fields[4];
    UINT32         field_num;
    UINT32         field_idx;

    cexpat_parser = (CEXPAT_PARSER *)arg;
    cexpat_node   = CEXPAT_PARSER_CUR_NODE(cexpat_parser); 

    str_dup = c_str_dup(str);

    if(NULL_PTR != cexpat_node)
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_header: node %p, name = [%s] chars = [%.*s]\n",
                           cexpat_node, CEXPAT_NODE_NAME_STR(cexpat_node), len, str_dup);
    }
    else
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_header: node %p, chars = [%.*s]\n",
                           cexpat_node, len, str_dup); 
    }

    /*<?xml version="1.0"?>*/
    field_num = c_str_split(str_dup, (const char *)" =\"'", (char **)fields, sizeof(fields)/sizeof(fields[0]));
    if(do_log(SEC_0148_CEXPAT, 9))
    {
        for(field_idx = 0; field_idx < field_num; field_idx ++)
        {
            sys_log(LOGSTDOUT, "[DEBUG] __cexpat_node_parse_header: [%ld] %s\n", field_idx, fields[ field_idx ]);
        }
    }

    safe_free(str_dup, LOC_CEXPAT_0011);

    ASSERT(4 == field_num);

    field_idx = 0;

    if(0 != STRCMP(fields[ field_idx ++ ], (const char *)"<?xml"))
    {
        return;
    }

    if(0 != STRCMP(fields[ field_idx ++ ], (const char *)"version"))
    {
        return;
    } 

    if(0 != STRCMP(fields[ field_idx ++ ], (const char *)"1.0"))
    {
        return;
    } 

    if(0 != STRCMP(fields[ field_idx ++ ], (const char *)"?>"))
    {
        return;
    }

    /*header is reached*/
    if(CEXPAT_PARSE_HEADER_NOT_DONE == CEXPAT_PARSER_HEADER_DONE(cexpat_parser))
    {
        CEXPAT_PARSER_HEADER_DONE(cexpat_parser) = CEXPAT_PARSE_HEADER_IS_DONE;
        XML_SetElementHandler(CEXPAT_PARSER_XML_PARSER(cexpat_parser), __cexpat_node_parse_start, __cexpat_node_parse_end); 
    }

    return;
}

EC_BOOL cexpat_attr_encode_xml(const CEXPAT_ATTR *cexpat_attr, CBUFFER *cbuffer)
{
    cbuffer_append_format(cbuffer, " %s='%s'",
                                   CEXPAT_ATTR_NAME_STR(cexpat_attr),
                                   CEXPAT_ATTR_VAL_STR(cexpat_attr));

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] cexpat_attr_encode_xml result: \n[%.*s]\n",
                       CBUFFER_USED(cbuffer), CBUFFER_DATA(cbuffer));                                 
    return (EC_TRUE);
}

EC_BOOL cexpat_node_attrs_encode_xml(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer)
{
    CLIST *cexpat_attr_list;

    cexpat_attr_list = (CLIST *)CEXPAT_NODE_ATTRS(cexpat_node);
    if(EC_FALSE == clist_is_empty(cexpat_attr_list))
    {
        UINT32 ret;
        clist_loop(cexpat_attr_list, (void *)&ret, CLIST_CHECKER_DEFAULT,
                   (UINT32)2,
                   (UINT32)0,
                   (UINT32)cexpat_attr_encode_xml, NULL_PTR, cbuffer);
    }

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] cexpat_node_attrs_encode_xml result: \n[%.*s]\n",
                       CBUFFER_USED(cbuffer), CBUFFER_DATA(cbuffer));  
    return (EC_TRUE); 
}

EC_BOOL cexpat_node_encode_xml_beg(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer)
{
    if(NULL_PTR != CEXPAT_NODE_CDATA(cexpat_node))
    {
        cbuffer_append_format(cbuffer, "<%s", CEXPAT_NODE_NAME_STR(cexpat_node));

        cexpat_node_attrs_encode_xml(cexpat_node, cbuffer);
        cbuffer_append(cbuffer, (const uint8_t *)">", (uint32_t)CONST_STR_LEN(">"));

        cbuffer_append_format(cbuffer, "%.*s</%s>",
                       CEXPAT_NODE_CDATA_LEN(cexpat_node),
                       CEXPAT_NODE_CDATA_BUF(cexpat_node),
                       CEXPAT_NODE_NAME_STR(cexpat_node));                    
    }
    else
    {
        cbuffer_append_format(cbuffer, "<%s", CEXPAT_NODE_NAME_STR(cexpat_node));

        cexpat_node_attrs_encode_xml(cexpat_node, cbuffer);
        cbuffer_append(cbuffer, (const uint8_t *)">", (uint32_t)CONST_STR_LEN(">"));
    }

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] cexpat_node_encode_xml_beg result: \n[%.*s]\n",
                       CBUFFER_USED(cbuffer), CBUFFER_DATA(cbuffer));    
    return (EC_TRUE);
}

EC_BOOL cexpat_node_encode_xml_end(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer)
{
    if(NULL_PTR == CEXPAT_NODE_CDATA(cexpat_node))
    {
        cbuffer_append_format(cbuffer, "</%s>", CEXPAT_NODE_NAME_STR(cexpat_node));
    }
 
    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] cexpat_node_encode_xml_end result: \n[%.*s]\n",
                       CBUFFER_USED(cbuffer), CBUFFER_DATA(cbuffer)); 
    return (EC_TRUE);
}

EC_BOOL cexpat_node_encode_xml(const CEXPAT_NODE *cexpat_node, CBUFFER *cbuffer, const EC_BOOL scope_closed)
{
    cexpat_node_encode_xml_beg(cexpat_node, cbuffer);
    if(EC_FALSE == clist_is_empty(CEXPAT_NODE_CHILDREN(cexpat_node)))
    {
        UINT32 ret;
        clist_loop((CLIST *)CEXPAT_NODE_CHILDREN(cexpat_node), (void *)&ret, CLIST_CHECKER_DEFAULT,
                   (UINT32)3,
                   (UINT32)0,
                   (UINT32)cexpat_node_encode_xml, NULL_PTR, cbuffer, EC_TRUE);
    }

    if(EC_TRUE == scope_closed)
    {
        cexpat_node_encode_xml_end(cexpat_node, cbuffer);
    }

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDNULL, "[DEBUG] cexpat_node_encode_xml result: \n[%.*s]\n",
                       CBUFFER_USED(cbuffer), CBUFFER_DATA(cbuffer));
    return (EC_TRUE);
}

EC_BOOL cexpat_attr_match(const CEXPAT_ATTR *cexpat_attr, const uint8_t *attr_name)
{
    if(0 == STRCASECMP(CEXPAT_ATTR_NAME_STR(cexpat_attr), (char *)attr_name))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

const CSTRING *cexpat_find_attr(const CEXPAT_NODE *cexpat_node, const uint8_t *attr_name)
{
    CLIST_DATA  *clist_data;
    const CEXPAT_ATTR *cexpat_attr;

    clist_data = clist_search_front(CEXPAT_NODE_ATTRS(cexpat_node), (void *)attr_name, (CLIST_DATA_DATA_CMP)cexpat_attr_match);
    if(NULL_PTR == clist_data)
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_attr: find attr [%s] faild\n", (char *)attr_name);
        return (NULL_PTR);
    }

    cexpat_attr = (const CEXPAT_ATTR *)CLIST_DATA_DATA(clist_data);
    return (CEXPAT_ATTR_VAL(cexpat_attr));
}

EC_BOOL cexpat_node_match(const CEXPAT_NODE *cexpat_node, const uint8_t *node_name)
{
    if(0 == STRCASECMP(CEXPAT_NODE_NAME_STR(cexpat_node), (char *)node_name))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

const CEXPAT_NODE *cexpat_find_child_node(const CEXPAT_NODE *cexpat_node, const uint8_t *node_name)
{
    CLIST_DATA  *clist_data;
    clist_data = clist_search_front(CEXPAT_NODE_CHILDREN(cexpat_node), (void *)node_name, (CLIST_DATA_DATA_CMP)cexpat_node_match);
    if(NULL_PTR == clist_data)
    {
        return (NULL_PTR);
    }

    return (const CEXPAT_NODE *)CLIST_DATA_DATA(clist_data);
}

const CEXPAT_NODE *cexpat_find_node_by_fields(const CEXPAT_NODE *cexpat_node, const uint8_t **fields, const UINT32 field_num)
{
    const CEXPAT_NODE *cexpat_node_cur;
    UINT32 field_idx;

    cexpat_node_cur = cexpat_node;
    field_idx = 0;

    if(EC_FALSE == cexpat_node_match(cexpat_node_cur, fields[ field_idx ]))
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_node_by_fields: find node [%s] faild\n", fields[ field_idx ]);
        return (NULL_PTR);
    }
 
    for( ++ field_idx; field_idx < field_num; field_idx ++)
    {
        cexpat_node_cur = cexpat_find_child_node(cexpat_node_cur, fields[ field_idx ]);
        if(NULL_PTR == cexpat_node_cur)
        {
            dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_node_by_fields: find child node [%s] faild\n", fields[ field_idx ]);
            return (NULL_PTR);
        }     
    }

    return (cexpat_node_cur);
}

const CEXPAT_NODE *cexpat_find_node_by_path(const CEXPAT_NODE *cexpat_node, const uint8_t *path, const uint8_t *delim)
{
    char    *path_t;
    uint8_t *fields[ CEXPAT_PATH_MAX_DEPTH ];
    UINT32   field_num;

    path_t = c_str_dup((const char *)path);
    if(NULL_PTR == path_t)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_find_node_by_path: dup path [%s] faild\n", (char *)path);
        return (NULL_PTR);
    }

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_node_by_path: path [%s]\n", (char *)path);
 
    field_num = c_str_split(path_t, (const char *)delim, (char **)fields, CEXPAT_PATH_MAX_DEPTH);
    safe_free(path_t, LOC_CEXPAT_0012);
 
    return cexpat_find_node_by_fields(cexpat_node, (const uint8_t **)fields, field_num);
}

const CSTRING *cexpat_find_attr_by_fields(const CEXPAT_NODE *cexpat_node, const uint8_t **fields, const UINT32 field_num)
{
    const CEXPAT_NODE *cexpat_node_cur;
    UINT32 field_idx;

    /*check validity*/
    if(1 >= field_num)
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "error:cexpat_find_attr_by_fields: invalid field_num %ld\n", field_num);
        return (NULL_PTR);
    }
 
    cexpat_node_cur = cexpat_node;
    field_idx = 0;

    if(EC_FALSE == cexpat_node_match(cexpat_node_cur, fields[ field_idx ]))
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_attr_by_fields: find node [%s] faild\n", fields[ field_idx ]);
        return (NULL_PTR);
    }
 
    for( ++ field_idx; field_idx < field_num - 1; field_idx ++)
    {
        cexpat_node_cur = cexpat_find_child_node(cexpat_node_cur, fields[ field_idx ]);
        if(NULL_PTR == cexpat_node_cur)
        {
            dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_attr_by_fields: find child node [%s] faild\n", fields[ field_idx ]);
            return (NULL_PTR);
        }     
    }

    if(do_log(SEC_0148_CEXPAT, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cexpat_find_attr_by_fields: try to find attr [%s] in node\n", (char *)fields[ field_idx ]);
        cexpat_node_depth_print_xml(LOGSTDOUT, cexpat_node_cur);
    }

    return cexpat_find_attr(cexpat_node_cur, fields[ field_idx ]);
}

const CSTRING *cexpat_find_attr_by_path(const CEXPAT_NODE *cexpat_node, const uint8_t *path, const uint8_t *delim)
{
    char    *path_t;
    uint8_t *fields[ CEXPAT_PATH_MAX_DEPTH ];
    UINT32   field_num;

    path_t = c_str_dup((const char *)path);
    if(NULL_PTR == path_t)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_find_attr_by_path: dup path [%s] faild\n", (char *)path);
        return (NULL_PTR);
    }
 
    field_num = c_str_split(path_t, (const char *)delim, (char **)fields, CEXPAT_PATH_MAX_DEPTH);
    safe_free(path_t, LOC_CEXPAT_0013);
 
    return cexpat_find_attr_by_fields(cexpat_node, (const uint8_t **)fields, field_num);
}

const CBYTES *cexpat_find_cdata_by_fields(const CEXPAT_NODE *cexpat_node, const uint8_t **fields, const UINT32 field_num)
{
    const CEXPAT_NODE *cexpat_node_cur;
    UINT32 field_idx;

    /*check validity*/
    if(0 == field_num)
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "error:cexpat_find_cdata_by_fields: invalid field_num %ld\n", field_num);
        return (NULL_PTR);
    }
 
    cexpat_node_cur = cexpat_node;
    field_idx = 0;

    if(EC_FALSE == cexpat_node_match(cexpat_node_cur, fields[ field_idx ]))
    {
        dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_cdata_by_fields: find node [%s] faild\n", fields[ field_idx ]);
        return (NULL_PTR);
    }
 
    for( ++ field_idx; field_idx < field_num; field_idx ++)
    {
        cexpat_node_cur = cexpat_find_child_node(cexpat_node_cur, fields[ field_idx ]);
        if(NULL_PTR == cexpat_node_cur)
        {
            dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_find_cdata_by_fields: find child node [%s] faild\n", fields[ field_idx ]);
            return (NULL_PTR);
        }     
    }

    if(0 && do_log(SEC_0148_CEXPAT, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cexpat_find_cdata_by_fields: try to find cdata [%s] in node\n", (char *)fields[ field_idx - 1]);
        cexpat_node_depth_print_xml(LOGSTDOUT, cexpat_node_cur);
    } 

    return CEXPAT_NODE_CDATA(cexpat_node_cur);
}

const CBYTES *cexpat_find_cdata_by_path(const CEXPAT_NODE *cexpat_node, const uint8_t *path, const uint8_t *delim)
{
    char    *path_t;
    uint8_t *fields[ CEXPAT_PATH_MAX_DEPTH ];
    UINT32   field_num;

    path_t = c_str_dup((const char *)path);
    if(NULL_PTR == path_t)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error:cexpat_find_cdata_by_path: dup path [%s] faild\n", (char *)path);
        return (NULL_PTR);
    }
 
    field_num = c_str_split(path_t, (const char *)delim, (char **)fields, CEXPAT_PATH_MAX_DEPTH);
    safe_free(path_t, LOC_CEXPAT_0014);
 
    return cexpat_find_cdata_by_fields(cexpat_node, (const uint8_t **)fields, field_num);
}

EC_BOOL cexpat_parser_init(CEXPAT_PARSER *cexpat_parser)
{
    CEXPAT_PARSER_XML_PARSER(cexpat_parser)        = NULL_PTR;
    CEXPAT_PARSER_ROOT_NODE(cexpat_parser)         = NULL_PTR;
    CEXPAT_PARSER_CUR_NODE(cexpat_parser)          = NULL_PTR;
    CEXPAT_PARSER_DEPTH(cexpat_parser)             = 0;
    CEXPAT_PARSER_FAIL(cexpat_parser)              = CEXPAT_PARSE_SUCC; /*default is succ*/
    CEXPAT_PARSER_HEADER_DONE(cexpat_parser)       = CEXPAT_PARSE_HEADER_NOT_DONE;

    return (EC_TRUE);
}

EC_BOOL cexpat_parser_clean(CEXPAT_PARSER *cexpat_parser)
{
    CEXPAT_PARSER_XML_PARSER(cexpat_parser)        = NULL_PTR;
    CEXPAT_PARSER_ROOT_NODE(cexpat_parser)         = NULL_PTR;
    CEXPAT_PARSER_CUR_NODE(cexpat_parser)          = NULL_PTR;
    CEXPAT_PARSER_DEPTH(cexpat_parser)             = 0;
    CEXPAT_PARSER_FAIL(cexpat_parser)              = CEXPAT_PARSE_SUCC; /*default is succ*/
    CEXPAT_PARSER_HEADER_DONE(cexpat_parser)       = CEXPAT_PARSE_HEADER_NOT_DONE;

    return (EC_TRUE);
}

EC_BOOL cexpat_parser_clear(CEXPAT_PARSER *cexpat_parser)
{
    //CEXPAT_PARSER_XML_PARSER(cexpat_parser)        = NULL_PTR;
    CEXPAT_PARSER_ROOT_NODE(cexpat_parser)         = NULL_PTR;
    CEXPAT_PARSER_CUR_NODE(cexpat_parser)          = NULL_PTR;
    CEXPAT_PARSER_DEPTH(cexpat_parser)             = 0;
    CEXPAT_PARSER_FAIL(cexpat_parser)              = CEXPAT_PARSE_SUCC; /*default is succ*/
    //CEXPAT_PARSER_HEADER_DONE(cexpat_parser)       = CEXPAT_PARSE_HEADER_NOT_DONE;

    return (EC_TRUE);
}

EC_BOOL cexpat_parser_open(CEXPAT_PARSER *cexpat_parser)
{
    XML_Parser  xml_parser;
 
    xml_parser = XML_ParserCreate(NULL_PTR);
    if(NULL_PTR == xml_parser)
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error: cexpat_parser_open: XML_ParserCreate failed\n");
        return (EC_FALSE);
    }

    XML_SetUserData(xml_parser, (void *)cexpat_parser);
    XML_SetDefaultHandler(xml_parser, __cexpat_node_parse_header);
    /**
    *    void XMLCALL XML_SetReturnNSTriplet(XML_Parser parser, int do_nst);
    *
    *  This function only has an effect when using a parser created with XML_ParserCreateNS, i.e. when namespace processing is in effect.
    *
    **/
    //XML_SetReturnNSTriplet(xml_parser, 1);
    XML_SetEntityDeclHandler(xml_parser, (void *) __cexpat_node_entity_declaration);
    XML_SetCharacterDataHandler(xml_parser, __cexpat_node_parse_cdata); 

    CEXPAT_PARSER_XML_PARSER(cexpat_parser) = xml_parser;

    return (EC_TRUE);
}

EC_BOOL cexpat_parser_close(CEXPAT_PARSER *cexpat_parser)
{
    if(NULL_PTR != CEXPAT_PARSER_XML_PARSER(cexpat_parser))
    {
        XML_ParserFree(CEXPAT_PARSER_XML_PARSER(cexpat_parser));
        CEXPAT_PARSER_XML_PARSER(cexpat_parser) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cexpat_node_parse(CEXPAT_PARSER *cexpat_parser, const uint8_t *buf, uint32_t len)
{
    int is_final;

    is_final = 0;
    if(XML_STATUS_ERROR == XML_Parse(CEXPAT_PARSER_XML_PARSER(cexpat_parser), (char *)buf, len, is_final))
    {
        dbg_log(SEC_0148_CEXPAT, 0)(LOGSTDOUT, "error: cexpat_node_parse: XML_Parse FAIL\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0148_CEXPAT, 9)(LOGSTDOUT, "[DEBUG] cexpat_node_parse: XML_Parse SUCC\n");
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

