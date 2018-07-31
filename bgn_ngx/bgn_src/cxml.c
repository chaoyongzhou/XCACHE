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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "cvector.h"
#include "cset.h"

#include "cxml.h"
#include "taskcfg.h"
#include "cparacfg.inc"
#include "cparacfg.h"
#include "cmpic.inc"
#include "cbtimer.h"
#include "cmisc.h"

#include "cdfs.h"
#include "cbgt.h"
#include "crfsnp.inc"
#include "crfsnp.h"
#include "cpgd.h"

#include "task.h"
#include "csyscfg.inc"
#include "csyscfg.h"

/*text node example: <a>xxx</a>*/
#define XML_IS_TEXT_NODE(cur)   (xmlNodeIsText(cur))

#define XML_SKIP_TEXT_NODE(cur) if(XML_IS_TEXT_NODE(cur))  { continue; }

#define XML_RANK_SEPARATOR       ((char *)":;, \t\n\r")
#define XML_CLUSTER_SEPARATOR    ((char *)":;, \t\n\r")

STATIC_CAST static EC_BOOL __cxml_parse_tag_uint16_t(xmlNodePtr node, const char *tag, uint16_t *data)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*data) = c_str_to_uint16_t((char *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_uint32_t(xmlNodePtr node, const char *tag, uint32_t *data)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*data) = c_str_to_uint32_t((char *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}


STATIC_CAST static EC_BOOL __cxml_parse_tag_uint32(xmlNodePtr node, const char *tag, UINT32 *data)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*data) = c_str_to_word((char *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_int(xmlNodePtr node, const char *tag, int *data)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*data) = c_str_to_int((char *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_rank(xmlNodePtr node, const char *tag, UINT32 *rank)
{
    return __cxml_parse_tag_uint32(node, tag, rank);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_tcid(xmlNodePtr node, const char *tag, UINT32 *tcid)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*tcid) = c_ipv4_to_word((char *)attr_val);
        //dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] __cxml_parse_tag_tcid: %s -> %ld -> %s\n", attr_val, (*tcid), c_word_to_ipv4(*tcid));
        xmlFree(attr_val);

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_ipv4_addr(xmlNodePtr node, const char *tag, UINT32 *ipv4_addr)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*ipv4_addr) = c_ipv4_to_word((char *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_srv_port(xmlNodePtr node, const char *tag, UINT32 *srv_port)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*srv_port) = c_port_to_word((char *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_ipv4_mask(xmlNodePtr node, const char *tag, UINT32 *ipv4_mask)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        if(NULL_PTR != strchr((char *)attr_val, '.'))
        {
            (*ipv4_mask) = c_ipv4_to_word((char *)attr_val);
        }
        else
        {
            (*ipv4_mask) = BITS_TO_MASK(c_str_to_word((char *)attr_val));
        }
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_cstr(xmlNodePtr node, const char *tag, CSTRING *cstring)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        cstring_clean(cstring);
        cstring_init(cstring, (UINT8 *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_switch(xmlNodePtr node, const char *tag, UINT32 *switch_state)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        (*switch_state) = c_str_to_switch((char *)attr_val);
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_np_model(xmlNodePtr node, const char *tag, uint8_t *np_model)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;
        uint8_t  np_model_t;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);

        np_model_t = crfsnp_model_get((const char *)attr_val);
        if(CRFSNP_ERR_MODEL != np_model_t)
        {
            (*np_model) = np_model_t;
            xmlFree(attr_val);
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_dn_model(xmlNodePtr node, const char *tag, uint16_t *pgd_block_num)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;
        uint16_t pgd_block_num_t;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);

        pgd_block_num_t = cpgd_model_get((const char *)attr_val);
        if(CPGD_ERROR_BLOCK_NUM != pgd_block_num_t)
        {
            (*pgd_block_num) = pgd_block_num_t;
            xmlFree(attr_val);
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_encode_rule(xmlNodePtr node, const char *tag, UINT32 *encode_rule)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        if(
           0 == strcasecmp((char *)attr_val, (char *)"DBG_ENCODING_RULE")
        || 0 == strcasecmp((char *)attr_val, (char *)"DBG_ENCODING")
        )
        {
            (*encode_rule) = DBG_ENCODING_RULE;
        }
        else if(
           0 == strcasecmp((char *)attr_val, (char *)"BYTE_ENCODING_RULE")
        || 0 == strcasecmp((char *)attr_val, (char *)"BYTE_ENCODING")
        )
        {
            (*encode_rule) = BYTE_ENCODING_RULE;
        }
        else
        {
            (*encode_rule) = ((UINT32)-1);
        }
        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_mac_addr(xmlNodePtr node, const char *tag, UINT8 *mac_addr)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);

        if(EC_FALSE == str_to_mac_addr((char *)attr_val, mac_addr))
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_tag_mac_addr: invalid mac addr %s\n", (char *)attr_val);
            xmlFree(attr_val);

            return (EC_FALSE);
        }

        xmlFree(attr_val);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_bool(xmlNodePtr node, const char *tag, EC_BOOL *bflag)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        if(0 == strcasecmp((char *)attr_val, "true"))
        {
            (*bflag) = EC_TRUE;
        }
        else
        {
            (*bflag) = EC_FALSE;
        }

        xmlFree(attr_val);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_mcast_auto_boot_flag(xmlNodePtr node, const char *tag, UINT32 *mcast_auto_boot_flag)
{
    EC_BOOL bflag;

    bflag = EC_FALSE;/*init default val*/
    if(EC_FALSE == __cxml_parse_tag_bool(node, tag, &bflag))
    {
        return (EC_FALSE);
    }

    if(EC_TRUE == bflag)
    {
        (*mcast_auto_boot_flag) = MCAST_SRV_WILL_AUTO_BOOTUP;
    }
    else
    {
        (*mcast_auto_boot_flag) = MCAST_SRV_NOT_AUTO_BOOTUP;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxml_parse_mcast_type(xmlNodePtr node, const char *tag, UINT32 *mcast_type)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        if(0 == strcasecmp((char *)attr_val, "master"))
        {
            (*mcast_type) = MCAST_TYPE_IS_MASTER;
        }
        else if(0 == strcasecmp((char *)attr_val, "slave"))
        {
            (*mcast_type) = MCAST_TYPE_IS_SLAVE;
        }
        else
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_mcast_type: invalid type %s\n", (char *)attr_val);
            xmlFree(attr_val);
            return (EC_FALSE);
        }

        xmlFree(attr_val);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_cluster_model(xmlNodePtr node, const char *tag, UINT32 *cluster_model)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        if(0 == strcasecmp((char *)attr_val, "master_slave"))
        {
            (*cluster_model) = MODEL_TYPE_MASTER_SLAVE;
        }
        else if(0 == strcasecmp((char *)attr_val, "cross"))
        {
            (*cluster_model) = MODEL_TYPE_CROSS_CONNEC;
        }
        else if(0 == strcasecmp((char *)attr_val, "hsdfs"))
        {
            (*cluster_model) = MODEL_TYPE_HSDFS_CONNEC;
        }
        else if(0 == strcasecmp((char *)attr_val, "hsbgt"))
        {
            (*cluster_model) = MODEL_TYPE_HSBGT_CONNEC;
        }
        else if(0 == strcasecmp((char *)attr_val, "hsrfs"))
        {
            (*cluster_model) = MODEL_TYPE_HSRFS_CONNEC;
        }
        else
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_cluster_model: invalid type %s\n", (char *)attr_val);
            xmlFree(attr_val);
            return (EC_FALSE);
        }

        xmlFree(attr_val);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_cluster_extra(xmlNodePtr node, const char *tag, CMAP *extras)
{
    //dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] __cxml_parse_cluster_extra: check tag %s\n", tag);
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;
        CSTRING *key;
        CSTRING *val;

        //dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] __cxml_parse_cluster_extra: check tag %s [DONE]\n", tag);

        attr_val = xmlGetProp(node, (const xmlChar*)tag);

        key = cstring_new((const UINT8 *)tag, LOC_CXML_0001);
        if(NULL_PTR == key)
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_cluster_extra: new key cstring failed\n");
            xmlFree(attr_val);
            return (EC_FALSE);
        }

        val = cstring_new((const UINT8 *)attr_val, LOC_CXML_0002);
        if(NULL_PTR == val)
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_cluster_extra: new val cstring failed\n");
            cstring_free(key);
            xmlFree(attr_val);
            return (EC_FALSE);
        }

        if(EC_FALSE == cmap_add(extras, (void *)key, (void *)val, LOC_CXML_0003))
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_cluster_extra: add extra failed\n");
            cstring_free(key);
            cstring_free(val);
            xmlFree(attr_val);
            return (EC_FALSE);
        }

        xmlFree(attr_val);
        return (EC_TRUE);
    }

    //dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] __cxml_parse_cluster_extra: check tag %s [FAIL]\n", tag);
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_bcast_dhcp_type(xmlNodePtr node, const char *tag, UINT32 *dhcp_type)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);
        if(0 == strcasecmp((char *)attr_val, "master"))
        {
            (*dhcp_type) = BCAST_DHCP_TYPE_IS_MASTER;
        }
        else if(0 == strcasecmp((char *)attr_val, "slave"))
        {
            (*dhcp_type) = BCAST_DHCP_TYPE_IS_SLAVE;
        }
        else
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_bcast_dhcp_type: invalid type %s\n", (char *)attr_val);
            xmlFree(attr_val);
            return (EC_FALSE);
        }
        xmlFree(attr_val);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_bcast_dhcp_auto_boot_flag(xmlNodePtr node, const char *tag, UINT32 *bcast_dhcp_auto_boot_flag)
{
    EC_BOOL bflag;

    bflag = EC_FALSE;/*init default val*/
    if(EC_FALSE == __cxml_parse_tag_bool(node, tag, &bflag))
    {
        return (EC_FALSE);
    }

    if(EC_TRUE == bflag)
    {
        (*bcast_dhcp_auto_boot_flag) = BCAST_DHCP_SRV_WILL_AUTO_BOOTUP;
    }
    else
    {
        (*bcast_dhcp_auto_boot_flag) = BCAST_DHCP_SRV_NOT_AUTO_BOOTUP;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_uint32_range(char *attr_val, CVECTOR *uint32_vec)
{
    char *fields[32];
    int field_num;

    UINT32 beg_num;
    UINT32 end_num;
    UINT32 cur_num;

    field_num = c_str_split((char *)attr_val, (const char *)"-", fields, sizeof(fields)/sizeof(fields[0]));
    if(0 == field_num)
    {
        return (EC_TRUE);
    }
    /*e.g. 3-10 <==> 3-5-8-10*/
    beg_num = c_str_to_word(fields[0]);
    end_num = c_str_to_word(fields[field_num - 1]);

    for(cur_num = beg_num; cur_num <= end_num; cur_num ++)/*close range scope*/
    {
        /* ensure the data in vector is in order */
        cvector_push_in_order(uint32_vec, (void *)cur_num, (CVECTOR_DATA_CMP)cvector_asc_cmp_default);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_uint32_vec(xmlNodePtr node, const char *tag, const char *separator, CVECTOR *uint32_vec)
{
    ASSERT(MM_UINT32 == uint32_vec->data_mm_type);

    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        char *fields[32];
        int field_num;
        int field_pos;

        attr_val = xmlGetProp(node, (const xmlChar*)tag);

        field_num = c_str_split((char *)attr_val, separator, fields, sizeof(fields)/sizeof(fields[0]));
        for(field_pos = 0; field_pos < field_num; field_pos ++)
        {
            if(NULL_PTR != strchr((char *)fields[field_pos], '-'))
            {
                __cxml_parse_tag_uint32_range(fields[field_pos], uint32_vec);
            }
            else
            {
                UINT32 num;
                num = c_str_to_word(fields[field_pos]);
                cvector_push(uint32_vec, (void *)num);
            }
        }

        xmlFree(attr_val);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_rank_vec(xmlNodePtr node, const char *tag, CVECTOR *rank_vec)
{
    __cxml_parse_tag_uint32_vec(node, tag, XML_RANK_SEPARATOR, rank_vec);
    if(0 == cvector_size(rank_vec))
    {
        UINT32 rank;
        rank = 0;/*default*/
        cvector_push(rank_vec, (void *)rank);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_cluster_vec(xmlNodePtr node, const char *tag, CVECTOR *cluster_vec)
{
    __cxml_parse_tag_uint32_vec(node, tag, XML_CLUSTER_SEPARATOR, cluster_vec);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxml_parse_any_of_tags(xmlNodePtr node, const char *tags_str, void *data, CXML_PARSE_TAG tag_parser)
{
    char  buf[256];
    char *tags[32];
    int tag_num;
    int tag_pos;

    if(strlen(tags_str) >= sizeof(buf)/sizeof(buf[0]))
    {
        dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_any_of_tags: tags str '%s' overflow\n", tags_str);
        return (EC_FALSE);
    }

    BCOPY(tags_str, buf, strlen(tags_str) + 1);

    tag_num = c_str_split((char *)buf, (const char *)":", tags, sizeof(tags)/sizeof(tags[0]));

    for(tag_pos = 0; tag_pos < tag_num; tag_pos ++)
    {
        if(EC_TRUE == tag_parser(node, tags[ tag_pos ], data))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_all_of_tags(xmlNodePtr node, const char *tags_str, void *data, CXML_PARSE_TAG tag_parser)
{
    char  buf[256];
    char *tags[32];
    int tag_num;
    int tag_pos;

    if(strlen(tags_str) >= sizeof(buf)/sizeof(buf[0]))
    {
        dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_all_of_tags: tags str '%s' overflow\n", tags_str);
        return (EC_FALSE);
    }

    BCOPY(tags_str, buf, strlen(tags_str) + 1);

    tag_num = c_str_split((char *)buf, (const char *)":", tags, sizeof(tags)/sizeof(tags[0]));

    for(tag_pos = 0; tag_pos < tag_num; tag_pos ++)
    {
        tag_parser(node, tags[ tag_pos ], data);
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxml_parse_log_level(xmlNodePtr node, char *log_level_str, UINT32 *log_level_tab, const UINT32 log_level_tab_size)
{
    char  *fields[2];
    int    field_num;
    UINT32 log_level;

    /*fields[field_pos] format is: ALL:9 or 1-100:5 or 1:4 etc.*/
    field_num = c_str_split((char *)log_level_str, (const char *)":", fields, sizeof(fields)/sizeof(fields[0]));
    ASSERT(2 == field_num);

    //sys_log(LOGSTDOUT, "[DEBUG] __cxml_parse_log_level: log_level_str: %s\n", log_level_str);

    log_level = c_str_to_word(fields[ 1 ]);
    //sys_log(LOGSTDOUT, "[DEBUG] __cxml_parse_log_level: log_level: %ld\n", log_level);

    if(0 == strcasecmp(fields[ 0 ], (const char *)"all"))
    {
        dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] __cxml_parse_log_level: set all to log level %ld\n", log_level);
        log_level_tab_set_all(log_level_tab, log_level_tab_size, log_level);
        return (EC_TRUE);
    }

    if(NULL_PTR != strchr((char *)fields[ 0 ], '-'))
    {
        CVECTOR sector_vec;
        UINT32  sector_pos;

        cvector_init(&sector_vec, 0, MM_UINT32, CVECTOR_LOCK_DISABLE, LOC_CXML_0004);

        __cxml_parse_tag_uint32_range(fields[ 0 ], &sector_vec);

        for(sector_pos = 0; sector_pos < cvector_size(&sector_vec); sector_pos ++)
        {
            UINT32 log_sector;

            log_sector = (UINT32)cvector_get_no_lock(&sector_vec, sector_pos);
            log_level_set(log_level_tab, log_level_tab_size, log_sector, log_level);
        }

        cvector_clean_no_lock(&sector_vec, NULL_PTR, LOC_CXML_0005);
    }
    else
    {
        UINT32 log_sector;

        log_sector = c_str_to_word(fields[ 0 ]);
        log_level_set(log_level_tab, log_level_tab_size, log_sector, log_level);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxml_parse_tag_log_level_tab(xmlNodePtr node, const char *tag, UINT32 *log_level_tab, const UINT32 log_level_tab_size)
{
    if(xmlHasProp(node, (const xmlChar*)tag))
    {
        xmlChar *attr_val;

        char **fields;
        int field_num;
        int field_pos;

        dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] __cxml_parse_tag_log_level_tab: parse %s\n", tag);

        fields = (char **)safe_malloc(log_level_tab_size * sizeof(char *), LOC_CXML_0006);
        if(NULL_PTR == fields)
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:__cxml_parse_tag_log_level_tab: malloc %ld char pointer failed\n", log_level_tab_size);
            return (EC_FALSE);
        }

        attr_val = xmlGetProp(node, (const xmlChar*)tag);

        field_num = c_str_split((char *)attr_val, (const char *)", \t\r\n", fields, log_level_tab_size);
        for(field_pos = 0; field_pos < field_num; field_pos ++)
        {
            dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] __cxml_parse_tag_log_level_tab: parse %s, %s\n", tag, (char *)fields[field_pos]);
            __cxml_parse_log_level(node, (char *)fields[field_pos], log_level_tab, log_level_tab_size);
        }

        safe_free(fields, LOC_CXML_0007);
        xmlFree(attr_val);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

xmlDocPtr cxml_new(const UINT8 *xml_doc_name)
{
    xmlDocPtr xml_doc_ptr;

    xml_doc_ptr = xmlParseFile((const char *)xml_doc_name);
    if(NULL_PTR == xml_doc_ptr)
    {
        dbg_log(SEC_0046_CXML, 5)(LOGSTDOUT, "cxml_new: failed to parse %s\n", (const char *)xml_doc_name);
        return ((xmlDocPtr)0);
    }
    return (xml_doc_ptr);
}

xmlNodePtr cxml_get_root(xmlDocPtr xml_doc_ptr)
{
    xmlNodePtr xml_node_ptr;

    xml_node_ptr = xmlDocGetRootElement(xml_doc_ptr);
    if(NULL_PTR == xml_node_ptr)
    {
        dbg_log(SEC_0046_CXML, 5)(LOGSTDOUT, "cxml_get_root: empty document\n");
        return ((xmlNodePtr)0);
    }
    return (xml_node_ptr);
}

void cxml_free(xmlDocPtr xml_doc_ptr)
{
    xmlFreeDoc(xml_doc_ptr);
    return;
}

EC_BOOL cxml_parse_tasks_cfg(xmlNodePtr node, TASKS_CFG *tasks_cfg)
{
    xmlNodePtr cur;

    __cxml_parse_tag_tcid(node, (const char *)"tcid", &(TASKS_CFG_TCID(tasks_cfg)));

    __cxml_parse_tag_ipv4_mask(node, (const char *)"maski", &(TASKS_CFG_MASKI(tasks_cfg)));
    __cxml_parse_tag_ipv4_mask(node, (const char *)"maske", &(TASKS_CFG_MASKE(tasks_cfg)));

    __cxml_parse_any_of_tags(node, (const char *)"srvipaddr:ipaddr:ip:ipv4", &(TASKS_CFG_SRVIPADDR(tasks_cfg)), (CXML_PARSE_TAG)__cxml_parse_tag_ipv4_addr);
    __cxml_parse_any_of_tags(node, (const char *)"srvport:sport:port"      , &(TASKS_CFG_SRVPORT(tasks_cfg)), (CXML_PARSE_TAG)__cxml_parse_tag_srv_port);
    __cxml_parse_any_of_tags(node, (const char *)"csrvport:cport"          , &(TASKS_CFG_CSRVPORT(tasks_cfg)), (CXML_PARSE_TAG)__cxml_parse_tag_srv_port);
    __cxml_parse_any_of_tags(node, (const char *)"ssrvport:sport"          , &(TASKS_CFG_SSRVPORT(tasks_cfg)), (CXML_PARSE_TAG)__cxml_parse_tag_srv_port);

    __cxml_parse_tag_cluster_vec(node, (const char *)"cluster", TASKS_CFG_CLUSTER_VEC(tasks_cfg));

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"taskr"))
        {
            TASKR_CFG *taskr_cfg;
            //dbg_log(SEC_0046_CXML, 5)(LOGSTDOUT,"cxml_parse_tasks_cfg: [%s]\n", cur->name);

            taskr_cfg = taskr_cfg_new();
            if(NULL_PTR == taskr_cfg)
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_tasks_cfg: new taskr_cfg failed\n");
                return (EC_FALSE);
            }
            if(EC_FALSE == cxml_parse_taskr_cfg(cur, taskr_cfg))
            {
                taskr_cfg_free(taskr_cfg);
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_tasks_cfg: parse taskr_cfg failed\n");
                return (EC_FALSE);
            }
            cvector_push(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), (void *)taskr_cfg);
        }
    }

    /*shit! when tcid not configured, we set tcid to ipaddr and maski,maske to default*/
    if(CMPI_ERROR_TCID == TASKS_CFG_TCID(tasks_cfg))
    {
        TASKS_CFG_TCID(tasks_cfg)  = TASKS_CFG_SRVIPADDR(tasks_cfg);
        dbg_log(SEC_0046_CXML, 1)(LOGSTDNULL, "warn:cxml_parse_tasks_cfg: set tcid to %s same as ipaddr due to no tcid configuration\n",
                            TASKS_CFG_TCID_STR(tasks_cfg));
    }

    if(CMPI_ERROR_IPADDR == TASKS_CFG_SRVIPADDR(tasks_cfg))
    {
        TASKS_CFG_SRVIPADDR(tasks_cfg)  = TASKS_CFG_TCID(tasks_cfg);
        dbg_log(SEC_0046_CXML, 1)(LOGSTDNULL, "warn:cxml_parse_tasks_cfg: set srvipaddr to %s same as tcid default due to no srvipaddr configuration\n",
                            TASKS_CFG_SRVIPADDR_STR(tasks_cfg));
    }

    if(CMPI_ERROR_MASK == TASKS_CFG_MASKI(tasks_cfg))
    {
        TASKS_CFG_MASKI(tasks_cfg) = BITS_TO_MASK(TASKS_CFG_DEFAULT_MASKI);
        dbg_log(SEC_0046_CXML, 1)(LOGSTDNULL, "warn:cxml_parse_tasks_cfg: set maski to default %s\n", TASKS_CFG_MASKI_STR(tasks_cfg));
    }

    if(CMPI_ERROR_MASK == TASKS_CFG_MASKE(tasks_cfg))
    {
        TASKS_CFG_MASKE(tasks_cfg) = BITS_TO_MASK(TASKS_CFG_DEFAULT_MASKE);
        dbg_log(SEC_0046_CXML, 1)(LOGSTDNULL, "warn:cxml_parse_tasks_cfg: set maske to default %s\n", TASKS_CFG_MASKE_STR(tasks_cfg));
    }

    return (EC_TRUE);
}

EC_BOOL cxml_parse_taskr_cfg(xmlNodePtr node, TASKR_CFG *taskr_cfg)
{
    __cxml_parse_tag_tcid     (node, (char *)"des_tcid" , &(TASKR_CFG_DES_TCID(taskr_cfg)));
    __cxml_parse_tag_ipv4_mask(node, (char *)"maskr"    , &(TASKR_CFG_MASKR(taskr_cfg)));
    __cxml_parse_tag_tcid     (node, (char *)"next_tcid", &(TASKR_CFG_NEXT_TCID(taskr_cfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_task_cfg(xmlNodePtr node, TASK_CFG *task_cfg, const UINT32 default_tasks_cfg_port)
{
    xmlNodePtr cur;

    if(0 != xmlStrcmp(node->name, (const xmlChar*)"taskConfig"))
    {
        dbg_log(SEC_0046_CXML, 9)(LOGSTDNULL, "error:cxml_parse_task_cfg: found no taskConfig\n");
        return (EC_FALSE);
    }

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"tasks"))
        {
            TASKS_CFG *tasks_cfg;
            //dbg_log(SEC_0046_CXML, 5)(LOGSTDOUT,"cxml_parse_task_cfg: [%s]\n", cur->name);

            tasks_cfg = tasks_cfg_new();
            if(NULL_PTR == tasks_cfg)
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_task_cfg: new tasks_cfg failed\n");
                return (EC_FALSE);
            }

            if(EC_FALSE == cxml_parse_tasks_cfg(cur, tasks_cfg))
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_task_cfg: parse tasks_cfg failed\n");
                tasks_cfg_free(tasks_cfg);
                return (EC_FALSE);
            }

            if(CMPI_ERROR_SRVPORT == TASKS_CFG_SRVPORT(tasks_cfg))
            {
                TASKS_CFG_SRVPORT(tasks_cfg) = default_tasks_cfg_port;
            }

            CVECTOR_LOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_CXML_0008);
            if(CVECTOR_ERR_POS == cvector_search_front_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), (void *)tasks_cfg, (CVECTOR_DATA_CMP)tasks_cfg_cmp))
            {
                cvector_push_no_lock(TASK_CFG_TASKS_CFG_VEC(task_cfg), (void *)tasks_cfg);
            }
            else
            {
                tasks_cfg_free(tasks_cfg);
            }
            CVECTOR_UNLOCK(TASK_CFG_TASKS_CFG_VEC(task_cfg), LOC_CXML_0009);
            continue;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cluster_node_cfg(xmlNodePtr node, CLUSTER_NODE_CFG *cluster_node_cfg)
{
    __cxml_parse_tag_cstr(node, (const char *)"role", CLUSTER_NODE_CFG_ROLE(cluster_node_cfg));
    __cxml_parse_all_of_tags(node, (const char *)"npdir:dndir:group", (void *)CLUSTER_NODE_CFG_EXTRAS(cluster_node_cfg), (CXML_PARSE_TAG)__cxml_parse_cluster_extra);
    __cxml_parse_tag_tcid(node, (const char *)"tcid", &(CLUSTER_NODE_CFG_TCID(cluster_node_cfg)));
    __cxml_parse_tag_rank_vec(node, (const char *)"rank", CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg));
    return (EC_TRUE);
}

EC_BOOL cxml_parse_cluster_cfg(xmlNodePtr node, CLUSTER_CFG *cluster_cfg)
{
    xmlNodePtr cur;

    __cxml_parse_tag_uint32(node, (const char *)"id", &(CLUSTER_CFG_ID(cluster_cfg)));
    __cxml_parse_tag_cstr(node, (const char *)"name", CLUSTER_CFG_NAME(cluster_cfg));
    __cxml_parse_cluster_model(node, (const char *)"model", &(CLUSTER_CFG_MODEL(cluster_cfg)));

    __cxml_parse_all_of_tags(node, (const char *)"npdir:dndir:roottabledir", (void *)CLUSTER_CFG_EXTRAS(cluster_cfg), (CXML_PARSE_TAG)__cxml_parse_cluster_extra);

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"node"))
        {
            CLUSTER_NODE_CFG *cluster_node_cfg;

            cluster_node_cfg = cluster_node_cfg_new();
            if(NULL_PTR == cluster_node_cfg)
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_cluster_cfg: new cluster_node_cfg failed\n");
                return (EC_FALSE);
            }
            if(EC_FALSE == cxml_parse_cluster_node_cfg(cur, cluster_node_cfg))
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_cluster_cfg: parse cluster_node_cfg failed\n");
                cluster_node_cfg_free(cluster_node_cfg);
                return (EC_FALSE);
            }
            cvector_push(CLUSTER_CFG_NODES(cluster_cfg), (void *)cluster_node_cfg);
            continue;
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxml_parse_cluster_cfg_vec(xmlNodePtr node, CVECTOR *cluster_cfg_vec)
{
    xmlNodePtr cur;

    //dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] cxml_parse_cluster_cfg_vec: enter\n");

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"cluster"))
        {
            CLUSTER_CFG *cluster_cfg;

            cluster_cfg = cluster_cfg_new();
            if(NULL_PTR == cluster_cfg)
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_cluster_cfg_vec: new cluster_cfg failed\n");
                return (EC_FALSE);
            }

            if(EC_FALSE == cxml_parse_cluster_cfg(cur, cluster_cfg))
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_cluster_cfg_vec: parse cluster_cfg failed\n");
                cluster_cfg_free(cluster_cfg);
                return (EC_FALSE);
            }

            if(CVECTOR_ERR_POS != cvector_search_front(cluster_cfg_vec, (void *)cluster_cfg, (CVECTOR_DATA_CMP)cluster_cfg_check_duplicate))
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_cluster_cfg_vec: found cluster id=%ld or name=%s duplicate\n",
                                    CLUSTER_CFG_ID(cluster_cfg), (char *)CLUSTER_CFG_NAME_STR(cluster_cfg));
                cluster_cfg_free(cluster_cfg);
                return (EC_FALSE);
            }
            //dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG]cxml_parse_cluster_cfg_vec: cluster_cfg is\n");
            //cluster_cfg_print_xml(LOGSTDOUT, cluster_cfg, 0);
            cvector_push(cluster_cfg_vec, (void *)cluster_cfg);
            continue;
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxml_parse_mcast_cfg(xmlNodePtr node, MCAST_CFG *mcast_cfg)
{
    mcast_cfg_init(mcast_cfg);

     __cxml_parse_tag_tcid(node, (const char *)"tcid", &(MCAST_CFG_TCID(mcast_cfg)));

     __cxml_parse_mcast_type(node, (const char *)"type", &(MCAST_CFG_TYPE(mcast_cfg)));

    __cxml_parse_any_of_tags(node, (const char *)"srvipaddr:ipaddr:ipv4:ip", &(MCAST_CFG_IPADDR(mcast_cfg)), (CXML_PARSE_TAG)__cxml_parse_tag_ipv4_addr);
    __cxml_parse_any_of_tags(node, (const char *)"srvport:port"            , &(MCAST_CFG_PORT(mcast_cfg)  ), (CXML_PARSE_TAG)__cxml_parse_tag_srv_port);

    __cxml_parse_tag_uint32(node, (const char *)"timeout", &(MCAST_CFG_TIMEOUT(mcast_cfg)));
    __cxml_parse_tag_uint32(node, (const char *)"expire" , &(MCAST_CFG_EXPIRE(mcast_cfg)));

    __cxml_parse_mcast_auto_boot_flag(node, (const char *)"auto", &(MCAST_CFG_AUTO_FLAG(mcast_cfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_udp_mcast_cfg(xmlNodePtr node, MCAST_CFG *mcast_cfg)
{
    xmlNodePtr cur;

    dbg_log(SEC_0046_CXML, 5)(LOGSTDNULL,"cxml_parse_udp_mcast_cfg: [%s]\n", node->name);
    if(0 != xmlStrcmp(node->name, (const xmlChar*)"udpMulticastConfig"))
    {
        dbg_log(SEC_0046_CXML, 9)(LOGSTDNULL, "error:cxml_parse_udp_mcast_cfg: found no udpMulticastConfig\n");
        return (EC_FALSE);
    }

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"udp"))
        {
            cxml_parse_mcast_cfg(cur, mcast_cfg);
            continue;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxml_parse_bcast_dhcp_cfg(xmlNodePtr node, BCAST_DHCP_CFG *bcast_dhcp_cfg)
{
    bcast_dhcp_cfg_init(bcast_dhcp_cfg);

    __cxml_parse_tag_tcid(node, (const char *)"tcid", &(BCAST_DHCP_CFG_TCID(bcast_dhcp_cfg)));

    __cxml_parse_bcast_dhcp_type(node, (const char *)"type", &(BCAST_DHCP_CFG_TYPE(bcast_dhcp_cfg)));

    __cxml_parse_tag_cstr(node, (const char *)"eth", BCAST_DHCP_NETCARD(bcast_dhcp_cfg));
    __cxml_parse_tag_ipv4_addr(node, (const char *)"subnet", &(BCAST_DHCP_CFG_SUBNET(bcast_dhcp_cfg)));

    __cxml_parse_tag_ipv4_mask(node, (const char *)"mask", &(BCAST_DHCP_CFG_MASK(bcast_dhcp_cfg)));

    __cxml_parse_bcast_dhcp_auto_boot_flag(node, (const char *)"auto", &(BCAST_DHCP_CFG_AUTO_FLAG(bcast_dhcp_cfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_udp_bcast_dhcp_cfg(xmlNodePtr node, BCAST_DHCP_CFG *bcast_dhcp_cfg)
{
    xmlNodePtr cur;

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"dhcp"))
        {
            cxml_parse_bcast_dhcp_cfg(cur, bcast_dhcp_cfg);
            continue;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_thread_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_uint32(node, (const char *)"maxReqThreadNum"          , &(CPARACFG_TASK_REQ_THREAD_MAX_NUM(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"maxRspThreadNum"          , &(CPARACFG_TASK_RSP_THREAD_MAX_NUM(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"maxStackSize"             , &(CPARACFG_CTHREAD_STACK_MAX_SIZE(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"stackGuardSize"           , &(CPARACFG_CTHREAD_STACK_GUARD_SIZE(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"taskSlowDownMsec"         , &(CPARACFG_TASK_SLOW_DOWN_MSEC(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"taskNotSlowDownMaxTimes"  , &(CPARACFG_TASK_NOT_SLOW_DOWN_MAX_TIMES(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"taskReqHandleThreadSwitch", &(CPARACFG_TASK_REQ_HANDLE_THREAD_SWITCH(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"taskReqDecodeThreadSwitch", &(CPARACFG_TASK_REQ_DECODE_THREAD_SWITCH(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"taskRspDecodeThreadSwitch", &(CPARACFG_TASK_RSP_DECODE_THREAD_SWITCH(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"taskFwdDecodeThreadSwitch", &(CPARACFG_TASK_FWD_DECODE_THREAD_SWITCH(cparacfg)));

    __cxml_parse_tag_switch(node, (const char *)"ngxBgnOverHttpSwitch"     , &(CPARACFG_NGX_BGN_OVER_HTTP_SWITCH(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_encode_rule_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_switch(node, (const char *)"base64EncodeSwitch", &(CPARACFG_CBASE64_ENCODE_SWITCH(cparacfg)));
    __cxml_parse_tag_encode_rule(node, (const char *)"taskEncodeRule", &(CPARACFG_TASK_ENCODING_RULE(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_csocket_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_int(node, (const char *)"sendBuffSize" , &(CPARACFG_CSOCKET_SO_SNDBUFF_SIZE(cparacfg)));
    __cxml_parse_tag_int(node, (const char *)"recvBuffSize" , &(CPARACFG_CSOCKET_SO_RCVBUFF_SIZE(cparacfg)));

    __cxml_parse_tag_int(node, (const char *)"sendLowAtSize", &(CPARACFG_CSOCKET_SO_SNDLOWAT_SIZE(cparacfg)));
    __cxml_parse_tag_int(node, (const char *)"recvLowAtSize", &(CPARACFG_CSOCKET_SO_RCVLOWAT_SIZE(cparacfg)));

    __cxml_parse_tag_int(node, (const char *)"sendTimeoutNsec" , &(CPARACFG_CSOCKET_SO_SNDTIMEO_NSEC(cparacfg)));
    __cxml_parse_tag_int(node, (const char *)"recvTimeoutNsec" , &(CPARACFG_CSOCKET_SO_RCVTIMEO_NSEC(cparacfg)));

    __cxml_parse_tag_switch(node, (const char *)"tcpKeepAliveSwitch" , &(CPARACFG_CSOCKET_SO_KEEPALIVE_SWITCH(cparacfg)));

    __cxml_parse_tag_int(node, (const char *)"tcpKeepIdleNsec" , &(CPARACFG_CSOCKET_TCP_KEEPIDLE_NSEC(cparacfg)));
    __cxml_parse_tag_int(node, (const char *)"tcpKeepIntvlNsec", &(CPARACFG_CSOCKET_TCP_KEEPINTVL_NSEC(cparacfg)));
    __cxml_parse_tag_int(node, (const char *)"tcpKeepCntTimes" , &(CPARACFG_CSOCKET_TCP_KEEPCNT_TIMES(cparacfg)));

    __cxml_parse_tag_switch(node, (const char *)"unixDomainIpcSwitch" , &(CPARACFG_CSOCKET_UNIX_DOMAIN_SWITCH(cparacfg)));

    __cxml_parse_tag_uint32(node, (const char *)"sendOnceMaxSize"   , &(CPARACFG_CSOCKET_SEND_ONCE_MAX_SIZE(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"recvOnceMaxSize"   , &(CPARACFG_CSOCKET_RECV_ONCE_MAX_SIZE(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"connectionNum"     , &(CPARACFG_CSOCKET_CNODE_NUM(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"heartbeatIntvlNsec", &(CPARACFG_CSOCKET_HEARTBEAT_INTVL_NSEC(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_log_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_uint32(node, (const char *)"logMaxRecords", &(CPARACFG_FILE_LOG_MAX_RECORDS(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"logNameWithDataSwitch", &(CPARACFG_FILE_LOG_NAME_WITH_DATE_SWITCH(cparacfg)));
    __cxml_parse_tag_log_level_tab(node, (const char *)"logLevel", CPARACFG_LOG_LEVEL_TAB(cparacfg), SEC_NONE_END);

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_rfs_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_uint32(node, (const char *)"rfsNpRetireMaxNum" , &(CPARACFG_CRFSNP_TRY_RETIRE_MAX_NUM(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"rfsNpRecycleMaxNum", &(CPARACFG_CRFSNP_TRY_RECYCLE_MAX_NUM(cparacfg)));

    __cxml_parse_tag_switch(node, (const char *)"rfsNpCacheInMemSwitch", &(CPARACFG_CRFSNP_CACHE_IN_MEM_SWITCH(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"rfsDnCacheInMemSwitch", &(CPARACFG_CRFSDN_CACHE_IN_MEM_SWITCH(cparacfg)));
    
    __cxml_parse_tag_uint32_t(node, (const char *)"httpReqNumPerLoop"  , &(CPARACFG_RFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_hfs_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_switch(node, (const char *)"memcacheSwitch"     , &(CPARACFG_CHFS_MEMC_SWITCH(cparacfg)));
    __cxml_parse_tag_np_model(node, (const char *)"memcacheNpModel"  , &(CPARACFG_CHFS_MEMC_NP_MODEL(cparacfg)));
    __cxml_parse_tag_dn_model(node, (const char *)"memcacheDnModel"  , &(CPARACFG_CHFS_MEMC_CPGD_BLOCK_NUM(cparacfg)));
    __cxml_parse_tag_uint32_t(node, (const char *)"memcacheBucketNum", &(CPARACFG_CHFS_MEMC_BUCKET_NUM(cparacfg)));
    __cxml_parse_tag_uint32_t(node, (const char *)"httpReqNumPerLoop", &(CPARACFG_HFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_sfs_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_switch(node, (const char *)"memcacheSwitch"     , &(CPARACFG_CSFS_MEMC_SWITCH(cparacfg)));
    __cxml_parse_tag_np_model(node, (const char *)"memcacheNpModel"  , &(CPARACFG_CSFS_MEMC_NP_MODEL(cparacfg)));
    __cxml_parse_tag_dn_model(node, (const char *)"memcacheDnModel"  , &(CPARACFG_CSFS_MEMC_CSFSD_BLOCK_NUM(cparacfg)));
    __cxml_parse_tag_uint32_t(node, (const char *)"memcacheBucketNum", &(CPARACFG_CSFS_MEMC_BUCKET_NUM(cparacfg)));
    __cxml_parse_tag_uint32_t(node, (const char *)"httpReqNumPerLoop", &(CPARACFG_SFS_HTTP_REQ_NUM_PER_LOOP(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_ngx_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_switch(node, (const char *)"rfsConhashSwitch"     , &(CPARACFG_CRFSMON_CONHASH_SWITCH(cparacfg)));
    __cxml_parse_tag_uint16_t(node, (const char *)"rfsConhashReplicas" , &(CPARACFG_CRFSMON_CONHASH_REPLICAS(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"rfsHotPathSwitch"     , &(CPARACFG_CRFSMON_HOT_PATH_SWITCH(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"hfsConhashSwitch"     , &(CPARACFG_CHFSMON_CONHASH_SWITCH(cparacfg)));
    __cxml_parse_tag_uint16_t(node, (const char *)"hfsConhashReplicas" , &(CPARACFG_CHFSMON_CONHASH_REPLICAS(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"sfsConhashSwitch"     , &(CPARACFG_CSFSMON_CONHASH_SWITCH(cparacfg)));
    __cxml_parse_tag_uint16_t(node, (const char *)"sfsConhashReplicas" , &(CPARACFG_CSFSMON_CONHASH_REPLICAS(cparacfg)));
    __cxml_parse_tag_uint32_t(node, (const char *)"outputBlockingLowAt", &(CPARACFG_NGX_LUA_OUTPUT_BLOCKING_LOWAT(cparacfg)));
    __cxml_parse_tag_uint32_t(node, (const char *)"epollTimeoutMsec"   , &(CPARACFG_NGX_EPOLL_TIMEOUT_MSEC(cparacfg)));
    __cxml_parse_tag_uint32_t(node, (const char *)"httpReqNumPerLoop"  , &(CPARACFG_NGX_HTTP_REQ_NUM_PER_LOOP(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_conn_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    //__cxml_parse_tag_switch(node, (const char *)"keepaliveSwitch", &(CPARACFG_CONN_KEEPALIVE_SWITCH(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"connTimeoutNsec"        , &(CPARACFG_CONN_TIMEOUT_NSEC(cparacfg)));
    __cxml_parse_tag_uint32(node, (const char *)"timeoutMaxNumPerLoop"   , &(CPARACFG_TIMEOUT_MAX_NUM_PER_LOOP(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"highPrecisionTimeSwitch", &(CPARACFG_HIGH_PRECISION_TIME_SWITCH(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"tdnsResolveSwitch"      , &(CPARACFG_TDNS_RESOLVE_SWITCH(cparacfg)));
    __cxml_parse_tag_switch(node, (const char *)"tdnsResolveTimeoutNsec" , &(CPARACFG_TDNS_RESOLVE_TIMEOUT_NSEC(cparacfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_ssl_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    __cxml_parse_tag_cstr(node, (const char *)"certificate", CPARACFG_SSL_CERTIFICATE_FILE_NAME_CSTR(cparacfg));
    __cxml_parse_tag_cstr(node, (const char *)"privateKey" , CPARACFG_SSL_PRIVATE_KEY_FILE_NAME_CSTR(cparacfg));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL cxml_parse_cparacfg_tcid_rank(xmlNodePtr node, UINT32 *tcid, UINT32 *rank)
{
    if(EC_FALSE == __cxml_parse_tag_tcid(node, (const char *)"tcid", tcid))
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == __cxml_parse_tag_rank(node, (const char *)"rank", rank))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_para_cfg(xmlNodePtr node, CPARACFG *cparacfg)
{
    xmlNodePtr cur;

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"threadConfig"))
        {
            cxml_parse_cparacfg_thread_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"encodeConfig"))
        {
            cxml_parse_cparacfg_encode_rule_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"socketConfig"))
        {
            cxml_parse_cparacfg_csocket_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"logConfig"))
        {
            cxml_parse_cparacfg_log_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"connConfig"))
        {
            cxml_parse_cparacfg_conn_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"sslConfig"))
        {
            cxml_parse_cparacfg_ssl_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"rfsConfig"))
        {
            cxml_parse_cparacfg_rfs_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"hfsConfig"))
        {
            cxml_parse_cparacfg_hfs_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"sfsConfig"))
        {
            cxml_parse_cparacfg_sfs_cfg(cur, cparacfg);
            continue;
        }
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"ngxConfig"))
        {
            cxml_parse_cparacfg_ngx_cfg(cur, cparacfg);
            continue;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxml_parse_cparacfg_of_specific(xmlNodePtr node, CPARACFG *cparacfg, const UINT32 tcid, const UINT32 rank)
{
    UINT32 cur_tcid;
    UINT32 cur_rank;

    dbg_log(SEC_0046_CXML, 5)(LOGSTDNULL,"cxml_parse_cparacfg_of_specific: [%s]\n", node->name);

    if(EC_FALSE == cxml_parse_cparacfg_tcid_rank(node, &cur_tcid, &cur_rank))
    {
        dbg_log(SEC_0046_CXML, 9)(LOGSTDNULL, "error:cxml_parse_cparacfg_of_specific: no tcid or rank in sysConfig\n");
        return (EC_FALSE);
    }

    if(
        (CMPI_ANY_TCID == cur_tcid || tcid == cur_tcid)
     && (CMPI_ANY_RANK == cur_rank || rank == cur_rank)
     )
    {
        CPARACFG_TCID(cparacfg) = tcid;
        CPARACFG_RANK(cparacfg) = rank;
        return cxml_parse_cparacfg_para_cfg(node, cparacfg);
    }

    dbg_log(SEC_0046_CXML, 9)(LOGSTDNULL, "error:cxml_parse_cparacfg_of_specific: no sysConfig for tcid %s rank %ld\n", c_word_to_ipv4(tcid), rank);
    return (EC_FALSE);
}

EC_BOOL cxml_parse_para_cfgx(xmlNodePtr node, CVECTOR *paras_cfg)
{
    UINT32 tcid;
    CVECTOR rank_vec;
    UINT32  pos;

    __cxml_parse_tag_tcid(node, (const char *)"tcid", &tcid);

    cvector_init(&rank_vec, 0, MM_UINT32, CVECTOR_LOCK_ENABLE, LOC_CXML_0010);
    __cxml_parse_tag_rank_vec(node, (const char *)"rank", &rank_vec);

    for(pos = 0; pos < cvector_size(&rank_vec); pos ++)
    {
        UINT32 rank;
        UINT32 cparacfg_pos;
        CPARACFG *cparacfg;

        rank = (UINT32)cvector_get_no_lock(&rank_vec, pos);
        dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] cxml_parse_para_cfg: parse cparacfg of tcid %s rank %ld\n", c_word_to_ipv4(tcid), rank);

        cparacfg = cparacfg_new(tcid, rank);
        if(NULL_PTR == cparacfg)
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_para_cfg: new cparacfg failed\n");
            cvector_clean_no_lock(&rank_vec, NULL_PTR, LOC_CXML_0011);
            return (EC_FALSE);
        }

        /*init cparacfg log level table*/
        if(CMPI_LOCAL_TCID == tcid && CMPI_LOCAL_RANK == rank)
        {
            /*copy from g_log_level table ...*/
            log_level_export(CPARACFG_LOG_LEVEL_TAB(cparacfg), SEC_NONE_END);
        }
        else
        {
            log_level_tab_init(CPARACFG_LOG_LEVEL_TAB(cparacfg), SEC_NONE_END, LOG_ERR_DBG_LEVEL);
        }

        if(EC_FALSE == cxml_parse_cparacfg_para_cfg(node, cparacfg))
        {
            dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_para_cfg: parse cparacfg failed\n");
            cparacfg_free(cparacfg);
            cvector_clean_no_lock(&rank_vec, NULL_PTR, LOC_CXML_0012);
            return (EC_FALSE);
        }

        CVECTOR_LOCK(paras_cfg, LOC_CXML_0013);
        cparacfg_pos = cvector_search_front_no_lock(paras_cfg, (void *)cparacfg, (CVECTOR_DATA_CMP)cparacfg_cmp);
        if(CVECTOR_ERR_POS == cparacfg_pos)
        {
            cvector_push_no_lock(paras_cfg, (void *)cparacfg);
        }
        else
        {
            CPARACFG *cparacfg_old;
            cparacfg_old = (CPARACFG *)cvector_get_no_lock(paras_cfg, cparacfg_pos);

            dbg_log(SEC_0046_CXML, 1)(LOGSTDOUT, "info:cxml_parse_para_cfg: renew cparacfg of tcid %s, rank %ld\n",
                                      c_word_to_ipv4(tcid), rank);

            dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] cxml_parse_para_cfg: clone [%p -> %p]\n", cparacfg, cparacfg_old);

            cparacfg_clone(cparacfg, cparacfg_old);
            log_level_import_from(CPARACFG_LOG_LEVEL_TAB(cparacfg), CPARACFG_LOG_LEVEL_TAB(cparacfg_old), SEC_NONE_END);

            cparacfg_free(cparacfg);
        }
        CVECTOR_UNLOCK(paras_cfg, LOC_CXML_0014);
    }
    cvector_clean_no_lock(&rank_vec, NULL_PTR, LOC_CXML_0015);

    return (EC_TRUE);

}

STATIC_CAST static CPARACFG *__cxml_parse_para_cfg_search_cparacfg_no_lock(CVECTOR *paras_cfg, const UINT32 tcid, const UINT32 rank)
{
    UINT32 pos;

    for(pos = 0; pos < cvector_size(paras_cfg); pos ++)
    {
        CPARACFG *cparacfg;

        cparacfg = (CPARACFG *)cvector_get_no_lock(paras_cfg, pos);
        if(tcid == CPARACFG_TCID(cparacfg) && rank == CPARACFG_RANK(cparacfg))
        {
            return (cparacfg);
        }
    }
    return (NULL_PTR);
}

EC_BOOL cxml_parse_para_cfg(xmlNodePtr node, CVECTOR *paras_cfg)
{
    UINT32 tcid;
    CVECTOR rank_vec;
    UINT32  pos;

    __cxml_parse_tag_tcid(node, (const char *)"tcid", &tcid);

    cvector_init(&rank_vec, 0, MM_UINT32, CVECTOR_LOCK_ENABLE, LOC_CXML_0016);
    __cxml_parse_tag_rank_vec(node, (const char *)"rank", &rank_vec);

    CVECTOR_LOCK(paras_cfg, LOC_CXML_0017);
    for(pos = 0; pos < cvector_size(&rank_vec); pos ++)
    {
        UINT32    rank;
        CPARACFG *cparacfg;

        rank = (UINT32)cvector_get_no_lock(&rank_vec, pos);
        dbg_log(SEC_0046_CXML, 9)(LOGSTDOUT, "[DEBUG] cxml_parse_para_cfg: parse cparacfg of tcid %s rank %ld\n", c_word_to_ipv4(tcid), rank);

        cparacfg = __cxml_parse_para_cfg_search_cparacfg_no_lock(paras_cfg, tcid, rank);
        if(NULL_PTR != cparacfg)
        {
            /*CPARACFG_LOG_LEVEL_TAB(cparacfg) keep unchanged before paring*/

            if(EC_FALSE == cxml_parse_cparacfg_para_cfg(node, cparacfg))
            {
                CVECTOR_UNLOCK(paras_cfg, LOC_CXML_0018);

                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_para_cfg: parse cparacfg failed\n");
                cvector_clean_no_lock(&rank_vec, NULL_PTR, LOC_CXML_0019);
                return (EC_FALSE);
            }
        }
        else
        {
            cparacfg = cparacfg_new(tcid, rank);
            if(NULL_PTR == cparacfg)
            {
                CVECTOR_UNLOCK(paras_cfg, LOC_CXML_0020);

                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_para_cfg: new cparacfg failed\n");
                cvector_clean_no_lock(&rank_vec, NULL_PTR, LOC_CXML_0021);
                return (EC_FALSE);
            }
            /*CPARACFG_LOG_LEVEL_TAB(cparacfg) was set to default*/
            if(EC_FALSE == cxml_parse_cparacfg_para_cfg(node, cparacfg))
            {
                CVECTOR_UNLOCK(paras_cfg, LOC_CXML_0022);

                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_para_cfg: parse cparacfg failed\n");
                cparacfg_free(cparacfg);
                cvector_clean_no_lock(&rank_vec, NULL_PTR, LOC_CXML_0023);
                return (EC_FALSE);
            }

            cvector_push_no_lock(paras_cfg, (void *)cparacfg);
        }
    }
    CVECTOR_UNLOCK(paras_cfg, LOC_CXML_0024);
    cvector_clean_no_lock(&rank_vec, NULL_PTR, LOC_CXML_0025);

    return (EC_TRUE);

}

EC_BOOL cxml_parse_paras_cfg(xmlNodePtr node, CVECTOR *paras_cfg)
{
    xmlNodePtr cur;

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"paraConfig"))
        {
            cxml_parse_para_cfg(cur, paras_cfg);
            continue;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxml_parse_macip_cfg(xmlNodePtr node, MACIP_CFG *macip_cfg)
{
    __cxml_parse_any_of_tags(node, (const char *)"ipaddr:ipv4:ip", &(MACIP_CFG_IPV4_ADDR(macip_cfg)), (CXML_PARSE_TAG)__cxml_parse_tag_ipv4_addr);

    __cxml_parse_any_of_tags(node, (const char *)"macaddr:mac", MACIP_CFG_MAC_ADDR(macip_cfg), (CXML_PARSE_TAG)__cxml_parse_tag_mac_addr);

    return (EC_TRUE);
}

EC_BOOL cxml_parse_macip_cfg_vec(xmlNodePtr node, CVECTOR *macip_cfg_vec)
{
    xmlNodePtr cur;

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);
        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"map"))
        {
            MACIP_CFG *macip_cfg;

            macip_cfg = macip_cfg_new();
            if(NULL_PTR == macip_cfg)
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_macip_cfg_vec: new macip_cfg failed\n");
                return (EC_FALSE);
            }

            if(EC_FALSE == cxml_parse_macip_cfg(cur, macip_cfg))
            {
                dbg_log(SEC_0046_CXML, 0)(LOGSTDOUT, "error:cxml_parse_macip_cfg_vec: parse one macip_cfg failed\n");
                macip_cfg_free(macip_cfg);
            }
            else
            {
                cvector_push_no_lock(macip_cfg_vec, (void *)macip_cfg);
            }
            continue;
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL cxml_parse_task_cfg_default_tasks_cfg_port(xmlNodePtr node, TASK_CFG *task_cfg)
{
    __cxml_parse_tag_uint32(node, (const char *)"deftasksport", &(TASK_CFG_DEFAULT_TASKS_PORT(task_cfg)));

    return (EC_TRUE);
}

EC_BOOL cxml_parse_sys_cfg(xmlNodePtr node, SYS_CFG *sys_cfg)
{
    xmlNodePtr cur;

    //dbg_log(SEC_0046_CXML, 5)(LOGSTDOUT,"cxml_parse_sys_cfg: node [%s]\n", node->name);

    for(cur = node->xmlChildrenNode; NULL_PTR != cur; cur = cur->next)
    {
        XML_SKIP_TEXT_NODE(cur);

        //dbg_log(SEC_0046_CXML, 5)(LOGSTDOUT,"cxml_parse_sys_cfg: cur [%s]\n", cur->name);

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"taskConfig"))
        {
            cxml_parse_task_cfg_default_tasks_cfg_port(cur, SYS_CFG_TASK_CFG(sys_cfg));

            cxml_parse_task_cfg(cur, SYS_CFG_TASK_CFG(sys_cfg), TASK_CFG_DEFAULT_TASKS_PORT(SYS_CFG_TASK_CFG(sys_cfg)));
            continue;
        }

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"clusters"))
        {
            cxml_parse_cluster_cfg_vec(cur, SYS_CFG_CLUSTER_VEC(sys_cfg));
            continue;
        }

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"udpMulticastConfig"))
        {
            cxml_parse_udp_mcast_cfg(cur, SYS_CFG_MCAST_CFG(sys_cfg));
            continue;
        }

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"udpBroadcastDHCPConfig"))
        {
            cxml_parse_udp_bcast_dhcp_cfg(cur, SYS_CFG_BCAST_DHCP_CFG(sys_cfg));
            continue;
        }

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"parasConfig"))
        {
            cxml_parse_paras_cfg(cur, SYS_CFG_PARAS_CFG(sys_cfg));
            continue;
        }

        if(0 == xmlStrcmp(cur->name, (const xmlChar*)"macIpMapsConfig"))
        {
            cxml_parse_macip_cfg_vec(cur, SYS_CFG_MACIP_CFG_VEC(sys_cfg));
            continue;
        }
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

