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
#include "cmpic.inc"
#include "cstring.h"
#include "cmisc.h"
#include "task.inc"
#include "task.h"

#include "chashalgo.h"

#include "ctdnssvrb.h"
#include "ctdnssv.h"

#include "findex.inc"

static CTDNSSV_CFG g_ctdnssv_cfg_tbl[] = {
    {(const char *)"512K", (const char *)"CTDNSSV_512K_MODEL", CTDNSSV_512K_CFG_FILE_SIZE,  CTDNSSV_512K_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"1M"  , (const char *)"CTDNSSV_001M_MODEL", CTDNSSV_001M_CFG_FILE_SIZE,  CTDNSSV_001M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2M"  , (const char *)"CTDNSSV_002M_MODEL", CTDNSSV_002M_CFG_FILE_SIZE,  CTDNSSV_002M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"4M"  , (const char *)"CTDNSSV_004M_MODEL", CTDNSSV_004M_CFG_FILE_SIZE,  CTDNSSV_004M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"8M"  , (const char *)"CTDNSSV_008M_MODEL", CTDNSSV_008M_CFG_FILE_SIZE,  CTDNSSV_008M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"16M" , (const char *)"CTDNSSV_016M_MODEL", CTDNSSV_016M_CFG_FILE_SIZE,  CTDNSSV_016M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"32M" , (const char *)"CTDNSSV_032M_MODEL", CTDNSSV_032M_CFG_FILE_SIZE,  CTDNSSV_032M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"64M" , (const char *)"CTDNSSV_064M_MODEL", CTDNSSV_064M_CFG_FILE_SIZE,  CTDNSSV_064M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"128M", (const char *)"CTDNSSV_128M_MODEL", CTDNSSV_128M_CFG_FILE_SIZE,  CTDNSSV_128M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"256M", (const char *)"CTDNSSV_256M_MODEL", CTDNSSV_256M_CFG_FILE_SIZE,  CTDNSSV_256M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"512M", (const char *)"CTDNSSV_512M_MODEL", CTDNSSV_512M_CFG_FILE_SIZE,  CTDNSSV_512M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"1G"  , (const char *)"CTDNSSV_001G_MODEL", CTDNSSV_001G_CFG_FILE_SIZE,  CTDNSSV_001G_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2G"  , (const char *)"CTDNSSV_002G_MODEL", CTDNSSV_002G_CFG_FILE_SIZE,  CTDNSSV_002G_CFG_ITEM_MAX_NUM, 0 },
#if (64 == WORDSIZE)
    {(const char *)"4G"  , (const char *)"CTDNSSV_004G_MODEL", CTDNSSV_004G_CFG_FILE_SIZE,  CTDNSSV_004G_CFG_ITEM_MAX_NUM, 0 },
#endif/*(64 == WORDSIZE)*/
};

static uint8_t g_ctdnssv_cfg_tbl_len = (uint8_t)(sizeof(g_ctdnssv_cfg_tbl)/sizeof(g_ctdnssv_cfg_tbl[0]));

static CTDNSSVRB_NODE *__ctdnssvrb_node(CTDNSSVRB_POOL *pool, const uint32_t node_pos)
{
    if(CTDNSSVRB_POOL_NODE_MAX_NUM(pool) > node_pos)
    {
        CTDNSSVRB_NODE *node;
     
        node = (CTDNSSVRB_NODE *)((void *)(pool->rb_nodes) + node_pos * CTDNSSVRB_POOL_NODE_SIZEOF(pool));
     
        dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] __ctdnssvrb_node: pool %p, rb_nodes %p, node_pos %u  -> node %p\n",
                           pool, (void *)(pool->rb_nodes), node_pos, node);
        return (node);
    }
    return (NULL_PTR);
}


const char *ctdnssv_model_str(const uint8_t ctdnssv_model)
{
    CTDNSSV_CFG *ctdnssv_cfg;
    if(ctdnssv_model >= g_ctdnssv_cfg_tbl_len)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_model_str: invalid ctdnssv mode %u\n", ctdnssv_model);
        return (const char *)"unkown";
    }
    ctdnssv_cfg = &(g_ctdnssv_cfg_tbl[ ctdnssv_model ]);
    return CTDNSSV_CFG_MODEL_STR(ctdnssv_cfg);
}

uint8_t ctdnssv_model_get(const char *model_str)
{
    uint8_t ctdnssv_model;

    for(ctdnssv_model = 0; ctdnssv_model < g_ctdnssv_cfg_tbl_len; ctdnssv_model ++)
    {
        CTDNSSV_CFG *ctdnssv_cfg;
        ctdnssv_cfg = &(g_ctdnssv_cfg_tbl[ ctdnssv_model ]);

        if(0 == strcasecmp(CTDNSSV_CFG_MODEL_STR(ctdnssv_cfg), model_str))
        {
            return (ctdnssv_model);
        }
    }
    return (CTDNSSV_ERR_MODEL);
}

EC_BOOL ctdnssv_model_file_size(const uint8_t ctdnssv_model, UINT32 *file_size)
{
    CTDNSSV_CFG *ctdnssv_cfg;
    if(ctdnssv_model >= g_ctdnssv_cfg_tbl_len)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_model_file_size: invalid ctdnssv mode %u\n", ctdnssv_model);
        return (EC_FALSE);
    }
    ctdnssv_cfg = &(g_ctdnssv_cfg_tbl[ ctdnssv_model ]);
    (*file_size) = CTDNSSV_CFG_FILE_SIZE(ctdnssv_cfg);
    return (EC_TRUE);
}

EC_BOOL ctdnssv_model_item_max_num(const uint8_t ctdnssv_model, uint32_t *item_max_num)
{
    CTDNSSV_CFG *ctdnssv_cfg;
    if(ctdnssv_model >= g_ctdnssv_cfg_tbl_len)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_model_item_max_num: invalid ctdnssv mode %u\n", ctdnssv_model);
        return (EC_FALSE);
    }
    ctdnssv_cfg = &(g_ctdnssv_cfg_tbl[ ctdnssv_model ]);
    (*item_max_num) = CTDNSSV_CFG_ITEM_MAX_NUM(ctdnssv_cfg);
    return (EC_TRUE);
}

static char *ctdnssv_fname_gen(const char *root_dir, const char *sname)
{
    char    *fname;
    uint32_t len;

    if(NULL_PTR == root_dir)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_fname_gen: root_dir is null\n");
        return (NULL_PTR);
    }

    len = strlen(root_dir) + 1 + strlen(sname) + strlen((const char *)CTDNSSV_POSTFIX) + 1;

    fname = safe_malloc(len, LOC_CTDNSSV_0001);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_fname_gen: malloc %u bytes failed\n", len);
        return (NULL_PTR);
    }
    snprintf(fname, len, "%s/%s%s", root_dir, sname, CTDNSSV_POSTFIX);
    dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_fname_gen: service fname %s\n", fname);
    return (fname);
}

CTDNSSV_ITEM *ctdnssv_item_new()
{
    CTDNSSV_ITEM *ctdnssv_item;

    alloc_static_mem(MM_CTDNSSV_ITEM, &ctdnssv_item, LOC_CTDNSSV_0002);
    if(NULL_PTR != ctdnssv_item)
    {
        ctdnssv_item_init(ctdnssv_item);
    }
    return (ctdnssv_item);
}

EC_BOOL ctdnssv_item_init(CTDNSSV_ITEM *ctdnssv_item)
{
    CTDNSSV_ITEM_TCID(ctdnssv_item)             = CMPI_ERROR_TCID;
    CTDNSSV_ITEM_IPADDR(ctdnssv_item)           = CMPI_ERROR_IPADDR;

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL ctdnssv_item_clean(CTDNSSV_ITEM *ctdnssv_item)
{
    CTDNSSV_ITEM_TCID(ctdnssv_item)             = CMPI_ERROR_TCID;
    CTDNSSV_ITEM_IPADDR(ctdnssv_item)           = CMPI_ERROR_IPADDR;
    
    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL ctdnssv_item_clone(const CTDNSSV_ITEM *ctdnssv_item_src, CTDNSSV_ITEM *ctdnssv_item_des)
{
    if(NULL_PTR == ctdnssv_item_src)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_item_clone: ctdnssv_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == ctdnssv_item_des)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_item_clone: ctdnssv_item_des is null\n");
        return (EC_FALSE);
    }

    CTDNSSV_ITEM_TCID(ctdnssv_item_des)        = CTDNSSV_ITEM_TCID(ctdnssv_item_src);
    CTDNSSV_ITEM_IPADDR(ctdnssv_item_des)      = CTDNSSV_ITEM_IPADDR(ctdnssv_item_src);

    /*give up copying parent_pos !*/
    return (EC_TRUE);
}

EC_BOOL ctdnssv_item_free(CTDNSSV_ITEM *ctdnssv_item)
{
    if(NULL_PTR != ctdnssv_item)
    {
        ctdnssv_item_clean(ctdnssv_item);
        free_static_mem(MM_CTDNSSV_ITEM, ctdnssv_item, LOC_CTDNSSV_0003);
    }
    return (EC_TRUE);
}

void ctdnssv_item_print(LOG *log, const CTDNSSV_ITEM *ctdnssv_item)
{
    sys_print(log, "ctdnssv_item %p: tcid %s, ip %s\n",
                    ctdnssv_item,
                    c_word_to_ipv4(CTDNSSV_ITEM_TCID(ctdnssv_item)),
                    c_word_to_ipv4(CTDNSSV_ITEM_IPADDR(ctdnssv_item))
                    );
   
    return;
}

EC_BOOL ctdnssv_item_load(CTDNSSV *ctdnssv, uint32_t *offset, CTDNSSV_ITEM *ctdnssv_item)
{
    RWSIZE rsize;
    UINT32 offset_t;

    offset_t = (*offset);
    rsize = sizeof(CTDNSSV_ITEM);
    if(EC_FALSE == c_file_load(CTDNSSV_FD(ctdnssv), &offset_t, rsize, (UINT8 *)ctdnssv_item))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_item_load: load item from offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL ctdnssv_item_flush(CTDNSSV *ctdnssv, uint32_t *offset, const CTDNSSV_ITEM *ctdnssv_item)
{
    RWSIZE wsize;
    UINT32 offset_t;

    offset_t = (*offset);
    wsize = sizeof(CTDNSSV_ITEM);
    if(EC_FALSE == c_file_flush(CTDNSSV_FD(ctdnssv), &offset_t, wsize, (UINT8 *)ctdnssv_item))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_item_load: flush item to offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL ctdnssv_item_is_tcid(const CTDNSSV_ITEM *ctdnssv_item, const UINT32 tcid)
{
    if(tcid !=  CTDNSSV_ITEM_TCID(ctdnssv_item))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CTDNSSV_ITEM *ctdnssv_item_parent(const CTDNSSV *ctdnssv, const CTDNSSV_ITEM *ctdnssv_item)
{
    uint32_t parent_pos;

    parent_pos = CTDNSSVRB_NODE_PARENT_POS(CTDNSSV_ITEM_RB_NODE(ctdnssv_item));
    if(CTDNSSVRB_ERR_POS == parent_pos)
    {
        return (NULL_PTR);
    }

    return ctdnssv_fetch(ctdnssv, parent_pos);
}

CTDNSSV_ITEM *ctdnssv_item_left(const CTDNSSV *ctdnssv, const CTDNSSV_ITEM *ctdnssv_item)
{
    uint32_t left_pos;

    left_pos = CTDNSSVRB_NODE_LEFT_POS(CTDNSSV_ITEM_RB_NODE(ctdnssv_item));
    if(CTDNSSVRB_ERR_POS == left_pos)
    {
        return (NULL_PTR);
    }

    return ctdnssv_fetch(ctdnssv, left_pos);
}

CTDNSSV_ITEM *ctdnssv_item_right(const CTDNSSV *ctdnssv, const CTDNSSV_ITEM *ctdnssv_item)
{
    uint32_t right_offset;

    right_offset = CTDNSSVRB_NODE_RIGHT_POS(CTDNSSV_ITEM_RB_NODE(ctdnssv_item));
    if(CTDNSSVRB_ERR_POS == right_offset)
    {
        return (NULL_PTR);
    }

    return ctdnssv_fetch(ctdnssv, right_offset);
}

CTDNSSV_NODE *ctdnssv_node_new()
{
    CTDNSSV_NODE *ctdnssv_node;

    alloc_static_mem(MM_CTDNSSV_NODE, &ctdnssv_node, LOC_CTDNSSV_0004);
    if(NULL_PTR != ctdnssv_node)
    {
        ctdnssv_node_init(ctdnssv_node);
    }
    return (ctdnssv_node);
}

EC_BOOL ctdnssv_node_init(CTDNSSV_NODE *ctdnssv_node)
{
    CTDNSSV_NODE_TCID(ctdnssv_node)             = CMPI_ERROR_TCID;
    CTDNSSV_NODE_IPADDR(ctdnssv_node)           = CMPI_ERROR_IPADDR;
    CTDNSSV_NODE_PORT(ctdnssv_node)             = CMPI_ERROR_SRVPORT;
    
    return (EC_TRUE);
}

EC_BOOL ctdnssv_node_clean(CTDNSSV_NODE *ctdnssv_node)
{
    CTDNSSV_NODE_TCID(ctdnssv_node)             = CMPI_ERROR_TCID;
    CTDNSSV_NODE_IPADDR(ctdnssv_node)           = CMPI_ERROR_IPADDR;
    CTDNSSV_NODE_PORT(ctdnssv_node)             = CMPI_ERROR_SRVPORT;
    
    return (EC_TRUE);
}

EC_BOOL ctdnssv_node_clone(const CTDNSSV_NODE *ctdnssv_node_src, CTDNSSV_NODE *ctdnssv_node_des)
{
    if(NULL_PTR == ctdnssv_node_src)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_node_clone: ctdnssv_node_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == ctdnssv_node_des)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_node_clone: ctdnssv_node_des is null\n");
        return (EC_FALSE);
    }

    CTDNSSV_NODE_TCID(ctdnssv_node_des)        = CTDNSSV_NODE_TCID(ctdnssv_node_src);
    CTDNSSV_NODE_IPADDR(ctdnssv_node_des)      = CTDNSSV_NODE_IPADDR(ctdnssv_node_src);
    CTDNSSV_NODE_PORT(ctdnssv_node_des)        = CTDNSSV_NODE_PORT(ctdnssv_node_src);

    /*give up copying parent_pos !*/
    return (EC_TRUE);
}

EC_BOOL ctdnssv_node_free(CTDNSSV_NODE *ctdnssv_node)
{
    if(NULL_PTR != ctdnssv_node)
    {
        ctdnssv_node_clean(ctdnssv_node);
        free_static_mem(MM_CTDNSSV_NODE, ctdnssv_node, LOC_CTDNSSV_0005);
    }
    return (EC_TRUE);
}

void ctdnssv_node_print(LOG *log, const CTDNSSV_NODE *ctdnssv_node)
{
    sys_print(log, "ctdnssv_node %p: tcid %s, ip %s, port %ld\n",
                    ctdnssv_node,
                    c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                    c_word_to_ipv4(CTDNSSV_NODE_IPADDR(ctdnssv_node)),
                    CTDNSSV_NODE_PORT(ctdnssv_node)
                    );
   
    return;
}

CTDNSSV_NODE_MGR *ctdnssv_node_mgr_new()
{
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;

    alloc_static_mem(MM_CTDNSSV_NODE_MGR, &ctdnssv_node_mgr, LOC_CTDNSSV_0006);
    if(NULL_PTR != ctdnssv_node_mgr)
    {
        ctdnssv_node_mgr_init(ctdnssv_node_mgr);
    }
    return (ctdnssv_node_mgr);
}

EC_BOOL ctdnssv_node_mgr_init(CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    clist_init(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), MM_CTDNSSV_NODE, LOC_CTDNSSV_0007);
    
    return (EC_TRUE);
}

EC_BOOL ctdnssv_node_mgr_clean(CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    clist_clean(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), (CLIST_DATA_DATA_CLEANER)ctdnssv_node_free);
    
    return (EC_TRUE);
}

EC_BOOL ctdnssv_node_mgr_free(CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    if(NULL_PTR != ctdnssv_node_mgr)
    {
        ctdnssv_node_mgr_clean(ctdnssv_node_mgr);
        free_static_mem(MM_CTDNSSV_NODE_MGR, ctdnssv_node_mgr, LOC_CTDNSSV_0008);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnssv_node_mgr_is_empty(const CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    return clist_is_empty(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr));
}

void ctdnssv_node_mgr_print(LOG *log, const CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    sys_print(log, "ctdnssv_node_mgr %p: nodes:\n",
                    ctdnssv_node_mgr);
    clist_print(log, CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), (CLIST_DATA_DATA_PRINT)ctdnssv_node_print);
    return;
}

EC_BOOL ctdnssv_header_load(CTDNSSV *ctdnssv, uint32_t *offset, CTDNSSV_HEADER *ctdnssv_header)
{
    RWSIZE rsize;
    UINT32 offset_t;

    offset_t = (*offset);
    rsize    = sizeof(CTDNSSV_HEADER);
    if(EC_FALSE == c_file_load(CTDNSSV_FD(ctdnssv), &offset_t, rsize, (UINT8 *)ctdnssv_header))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_header_load: load service_header from offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

static CTDNSSV_HEADER *__ctdnssv_header_new(const UINT32 fsize, int fd, const uint8_t model)
{
    CTDNSSV_HEADER *ctdnssv_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    ctdnssv_header = (CTDNSSV_HEADER *)safe_malloc(fsize, LOC_CTDNSSV_0009);
    if(NULL_PTR == ctdnssv_header)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:__ctdnssv_header_new: new service_header with %u bytes for fd %d failed\n",
                           fsize, fd);
        return (NULL_PTR);
    }  

    ctdnssv_model_item_max_num(model, &node_max_num);
    node_sizeof = sizeof(CTDNSSV_ITEM);

    /*init RB Nodes*/ 
    ctdnssvrb_pool_init(CTDNSSV_HEADER_NODES_POOL(ctdnssv_header), node_max_num, node_sizeof);
 
    return (ctdnssv_header);
}

EC_BOOL ctdnssv_header_flush(CTDNSSV *ctdnssv, uint32_t *offset, const CTDNSSV_HEADER *ctdnssv_header)
{
    RWSIZE wsize;
    UINT32 offset_t;

    offset_t = (*offset);
    wsize    = sizeof(CTDNSSV_HEADER);
    if(EC_FALSE == c_file_flush(CTDNSSV_FD(ctdnssv), &offset_t, wsize, (UINT8 *)ctdnssv_header))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_header_load: flush service_header to offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL ctdnssv_header_is(const CTDNSSV_HEADER *ctdnssv_header, const uint32_t sname_len, const uint8_t *sname)
{
    if(sname_len !=  CTDNSSV_HEADER_SNAME_LEN(ctdnssv_header))
    {
        return (EC_FALSE);
    }

    return BCMP(sname, CTDNSSV_HEADER_SNAME(ctdnssv_header), sname_len);
}

static CTDNSSV_HEADER *__ctdnssv_header_load(const UINT32 fsize, int fd)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(fsize, LOC_CTDNSSV_0010);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:__ctdnssv_header_load: malloc %u bytes failed for fd %d\n",
                            fsize, fd);
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, buff))
    {
        safe_free(buff, LOC_CTDNSSV_0011);
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:__ctdnssv_header_load: load %u bytes failed for fd %d\n",
                            fsize, fd);
        return (NULL_PTR);
    }

    return ((CTDNSSV_HEADER *)buff);
}

static CTDNSSV_HEADER *__ctdnssv_header_open(const UINT32 fsize, int fd)
{
    CTDNSSV_HEADER *ctdnssv_header;

    ctdnssv_header = (CTDNSSV_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == ctdnssv_header)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:__ctdnssv_header_open: mmap with fd %d failed, errno = %d, errstr = %s\n",
                           fd, errno, strerror(errno));
        return (NULL_PTR);
    }
 
    return (ctdnssv_header);
}

static CTDNSSV_HEADER * __ctdnssv_header_flush(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnssv_header)
    {
        UINT32 offset;

        offset = 0;     
        if(EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)ctdnssv_header))
        {
            dbg_log(SEC_0051_CTDNSSV, 1)(LOGSTDOUT, "warn:__ctdnssv_header_flush: flush ctdnssv_hdr of fd %d with size %u failed\n",
                               fd, fsize);
        }
    } 
    return (ctdnssv_header);
}

static CTDNSSV_HEADER *__ctdnssv_header_free(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnssv_header)
    {
        UINT32 offset;

        offset = 0;
        if(
           ERR_FD != fd
        && EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)ctdnssv_header)
        )
        {
            dbg_log(SEC_0051_CTDNSSV, 1)(LOGSTDOUT, "warn:__ctdnssv_header_free: flush ctdnssv_hdr of fd %d with size %u failed\n",
                               fd, fsize);
        }

        safe_free(ctdnssv_header, LOC_CTDNSSV_0012);
    }
 
    /*ctdnssv_header cannot be accessed again*/
    return (NULL_PTR);
}

static CTDNSSV_HEADER *__ctdnssv_header_create(const UINT32 fsize, int fd, const uint8_t model)
{
    CTDNSSV_HEADER *ctdnssv_header;
    uint32_t                node_max_num;
    uint32_t                node_sizeof;
 
    ctdnssv_header = (CTDNSSV_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == ctdnssv_header)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:__ctdnssv_header_create: mmap fd %d failed, errno = %d, errstr = %s\n",
                           fd, errno, strerror(errno));
        return (NULL_PTR);
    }  

    ctdnssv_model_item_max_num(model, &node_max_num);
    node_sizeof = sizeof(CTDNSSV_ITEM);
    ASSERT(32 == node_sizeof);

    /*init service*/
    //TODO:
    
    /*init RB Nodes*/
    ctdnssvrb_pool_init(CTDNSSV_HEADER_NODES_POOL(ctdnssv_header), node_max_num, node_sizeof);
 
    return (ctdnssv_header);
}

static CTDNSSV_HEADER * __ctdnssv_header_sync(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnssv_header)
    {
        if(0 != msync(ctdnssv_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "warn:__ctdnssv_header_sync: sync ctdnssv_hdr of fd %d with size %u failed\n",
                               fd, fsize);
        }
        else
        {
            dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] __ctdnssv_header_sync: sync ctdnssv_hdr of fd %d with size %u done\n",
                               fd, fsize);
        }    
    } 
    return (ctdnssv_header);
}

static CTDNSSV_HEADER *__ctdnssv_header_close(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnssv_header)
    {
        if(0 != msync(ctdnssv_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "warn:__ctdnssv_header_close: sync ctdnssv_hdr of fd %d with size %u failed\n",
                               fd, fsize);
        }
        else
        {
            dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] __ctdnssv_header_close: sync ctdnssv_hdr of fd %d with size %u done\n",
                               fd, fsize);
        }
        if(0 != munmap(ctdnssv_header, fsize))
        {
            dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "warn:__ctdnssv_header_close: munmap ctdnssv of fd %d with size %u failed\n",
                               fd, fsize);
        }
        else
        {
            dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] __ctdnssv_header_close: munmap ctdnssv of fd %d with size %u done\n",
                               fd, fsize);
        }
    }
 
    /*ctdnssv_header cannot be accessed again*/
    return (NULL_PTR);
}


CTDNSSV_HEADER *ctdnssv_header_open(const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CTDNS_SP_CACHE_IN_MEM)
    {
        return __ctdnssv_header_load(fsize, fd);
    }

    return __ctdnssv_header_open(fsize, fd);
}

CTDNSSV_HEADER *ctdnssv_header_create(const UINT32 fsize, int fd, const uint8_t model)
{
    if(SWITCH_ON == CTDNS_SP_CACHE_IN_MEM)
    {
        return __ctdnssv_header_new(fsize, fd, model);
    }

    return __ctdnssv_header_create(fsize, fd, model);
}

CTDNSSV_HEADER *ctdnssv_header_sync(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CTDNS_SP_CACHE_IN_MEM)
    {
        return __ctdnssv_header_flush(ctdnssv_header, fsize, fd);
    }

    return __ctdnssv_header_sync(ctdnssv_header, fsize, fd); 
}

CTDNSSV_HEADER *ctdnssv_header_close(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CTDNS_SP_CACHE_IN_MEM)
    {
        return __ctdnssv_header_free(ctdnssv_header, fsize, fd);
    }

    return __ctdnssv_header_close(ctdnssv_header, fsize, fd);
}

CTDNSSV *ctdnssv_new()
{
    CTDNSSV *ctdnssv;

    alloc_static_mem(MM_CTDNSSV, &ctdnssv, LOC_CTDNSSV_0013);
    if(NULL_PTR != ctdnssv)
    {
        ctdnssv_init(ctdnssv);
    }
    return (ctdnssv);
}

EC_BOOL ctdnssv_init(CTDNSSV *ctdnssv)
{
    CTDNSSV_FNAME(ctdnssv)            = NULL_PTR;
    CTDNSSV_FD(ctdnssv)               = ERR_FD;
    CTDNSSV_FSIZE(ctdnssv)            = 0;
    CTDNSSV_HDR(ctdnssv)              = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL ctdnssv_clean(CTDNSSV *ctdnssv)
{
    if(NULL_PTR != CTDNSSV_FNAME(ctdnssv))
    {
        safe_free(CTDNSSV_FNAME(ctdnssv), LOC_CTDNSSV_0014);
        CTDNSSV_FNAME(ctdnssv) = NULL_PTR;
    }
    
    CTDNSSV_FD(ctdnssv)               = ERR_FD;
    CTDNSSV_FSIZE(ctdnssv)            = 0;
    
    /*note:do nothing on pool*/

    return (EC_TRUE);
}

EC_BOOL ctdnssv_free(CTDNSSV *ctdnssv)
{
    if(NULL_PTR != ctdnssv)
    {
        ctdnssv_clean(ctdnssv);
        free_static_mem(MM_CTDNSSV, ctdnssv, LOC_CTDNSSV_0015);
    }
    return (EC_TRUE);
}

void ctdnssv_print(LOG *log, const CTDNSSV *ctdnssv)
{
    if(NULL_PTR != CTDNSSV_HDR(ctdnssv))
    {
        sys_print(log, "ctdnssv %p: fname %s, fsize %ld, sname %s, max %u, used %u\n",
                        ctdnssv,
                        (char *)CTDNSSV_FNAME(ctdnssv),
                        CTDNSSV_FSIZE(ctdnssv),
                        (char *)CTDNSSV_SNAME(ctdnssv),
                        CTDNSSV_NODES_MAX_NUM(ctdnssv),
                        CTDNSSV_NODES_USED_NUM(ctdnssv));
    }
    else
    {
        sys_print(log, "ctdnssv %p: fname %s, fsize %ld, sname %s, header (null)\n",
                        ctdnssv,
                        (char *)CTDNSSV_FNAME(ctdnssv),
                        CTDNSSV_FSIZE(ctdnssv),
                        (char *)CTDNSSV_SNAME(ctdnssv));
    }
    return;
}

CTDNSSV *ctdnssv_open(const char *service_fname)
{
    UINT32                   fsize;
    CTDNSSV         *ctdnssv;
    CTDNSSV_HEADER  *ctdnssv_header;
    int                      fd;
    
    if(EC_FALSE == c_file_access(service_fname, F_OK))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_open: service file %s not exist\n", service_fname);
        return (NULL_PTR);
    }

    fd = c_file_open(service_fname, O_RDWR, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_open: open service file %s failed\n", service_fname);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_open: get size of %s failed\n", service_fname);
        c_file_close(fd);
        return (NULL_PTR);
    }
    dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_open: service file %s, fsize %ld\n", service_fname, fsize);

    ctdnssv_header = ctdnssv_header_open(fsize, fd);
    if(NULL_PTR == ctdnssv_header)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_open: open service file %s failed\n", service_fname);
        c_file_close(fd);
        return (NULL_PTR);
    } 

    ctdnssv = ctdnssv_new();
    if(NULL_PTR == ctdnssv)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_open: new service of file %s failed\n", service_fname);
        c_file_close(fd);
        ctdnssv_header_close(ctdnssv_header, fsize, fd);
        return (NULL_PTR);
    }

    CTDNSSV_HDR(ctdnssv) = ctdnssv_header;

    CTDNSSV_FD(ctdnssv)    = fd;
    CTDNSSV_FSIZE(ctdnssv) = fsize;
    CTDNSSV_FNAME(ctdnssv) = (uint8_t *)service_fname;/*xxx*/

    return (ctdnssv);
}

EC_BOOL ctdnssv_close(CTDNSSV *ctdnssv)
{
    if(NULL_PTR != ctdnssv)
    {
        dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_close: close service '%s' beg\n",
                        (char *)CTDNSSV_FNAME(ctdnssv));
        if(NULL_PTR != CTDNSSV_HDR(ctdnssv))
        {
            ctdnssv_header_close(CTDNSSV_HDR(ctdnssv), 
                                         CTDNSSV_FSIZE(ctdnssv), 
                                         CTDNSSV_FD(ctdnssv));
            CTDNSSV_HDR(ctdnssv) = NULL_PTR;
        }
        dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_close: close service '%s' end\n",
                        (char *)CTDNSSV_FNAME(ctdnssv));
                        
        ctdnssv_free(ctdnssv);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnssv_sync(CTDNSSV *ctdnssv)
{
    if(NULL_PTR != ctdnssv && NULL_PTR != CTDNSSV_HDR(ctdnssv))
    {
        ctdnssv_header_sync(CTDNSSV_HDR(ctdnssv), 
                                    CTDNSSV_FSIZE(ctdnssv), 
                                    CTDNSSV_FD(ctdnssv));
    }
    return (EC_TRUE);
}

CTDNSSV *ctdnssv_create(const char *sp_root_dir, const char *sname, const uint8_t model)
{
    CTDNSSV         *ctdnssv;
    CTDNSSV_HEADER  *ctdnssv_header;
    char                    *ctdnssv_fname;
    
    UINT32                   fsize;
    int                      fd;
    uint32_t                 item_max_num;

    ASSERT(8 * 1024 == ((unsigned long)(&(((CTDNSSV_HEADER *)0)->nodes_pool.rb_nodes))));
    ASSERT(8 * 1024 == sizeof(CTDNSSV_HEADER));

    if(EC_FALSE == ctdnssv_model_file_size(model, &fsize))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: invalid model %u\n", model);
        return (NULL_PTR);
    }

    if(EC_FALSE == ctdnssv_model_item_max_num(model, &item_max_num))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: invalid model %u\n", model);
        return (NULL_PTR);
    } 

    ctdnssv_fname = ctdnssv_fname_gen(sp_root_dir, sname);
    if(NULL_PTR == ctdnssv_fname)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: generate ctdnssv_fname of %s, root_dir %s failed\n", sname, sp_root_dir);
        return (NULL_PTR);
    }
 
    if(EC_TRUE == c_file_access(ctdnssv_fname, F_OK))/*exist*/
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: servce %s '%s' exist already\n", sname, ctdnssv_fname);
        safe_free(ctdnssv_fname, LOC_CTDNSSV_0016);
        return (NULL_PTR);
    }

    fd = c_file_open(ctdnssv_fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: cannot create service file %s\n", ctdnssv_fname);
        safe_free(ctdnssv_fname, LOC_CTDNSSV_0017);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_truncate(fd, fsize))
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: truncate service file %s to size %u failed\n", ctdnssv_fname, fsize);
        safe_free(ctdnssv_fname, LOC_CTDNSSV_0018);
        c_file_close(fd);
        return (NULL_PTR);
    }

    ctdnssv_header = ctdnssv_header_create(fsize, fd, model);
    if(NULL_PTR == ctdnssv_header)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: open ctdnssv file %s failed\n", ctdnssv_fname);
        safe_free(ctdnssv_fname, LOC_CTDNSSV_0019);
        c_file_close(fd);
        return (NULL_PTR);
    }

    CTDNSSV_HEADER_SNAME_LEN(ctdnssv_header) = strlen(sname);
    BCOPY(sname, CTDNSSV_HEADER_SNAME(ctdnssv_header), strlen(sname));

    ctdnssv = ctdnssv_new();
    if(NULL_PTR == ctdnssv)
    {
        dbg_log(SEC_0051_CTDNSSV, 0)(LOGSTDOUT, "error:ctdnssv_create: new ctdnssv %s failed\n", sname);
        safe_free(ctdnssv_fname, LOC_CTDNSSV_0020);
        c_file_close(fd);
        ctdnssv_header_close(ctdnssv_header, fsize, fd);
        return (NULL_PTR);
    }
    CTDNSSV_HDR(ctdnssv)   = ctdnssv_header;

    CTDNSSV_FD(ctdnssv)    = fd;
    CTDNSSV_FSIZE(ctdnssv) = fsize;
    CTDNSSV_FNAME(ctdnssv) = (uint8_t *)ctdnssv_fname;

    dbg_log(SEC_0051_CTDNSSV, 9)(LOGSTDOUT, "[DEBUG] ctdnssv_create: create service %s done\n", sname);

    return (ctdnssv);
}

EC_BOOL ctdnssv_delete(CTDNSSV *ctdnssv, const UINT32 tcid)
{
    CTDNSSVRB_POOL            *ctdnssv_pool;
    uint32_t                   node_pos;
 
    ctdnssv_pool = CTDNSSV_NODES_POOL(ctdnssv);
    return ctdnssvrb_tree_delete_data(ctdnssv_pool, &(CTDNSSVRB_POOL_ROOT_POS(ctdnssv_pool)), tcid, &node_pos);
}

EC_BOOL ctdnssv_is_service(const CTDNSSV *ctdnssv, const CSTRING *service_name)
{
    uint32_t    service_name_len;

    service_name_len = (uint32_t)CSTRING_LEN(service_name);
    if(service_name_len !=  CTDNSSV_SNAME_LEN(ctdnssv))
    {
        return (EC_FALSE);
    }

    return BCMP(CSTRING_STR(service_name), CTDNSSV_SNAME(ctdnssv), service_name_len);
}

EC_BOOL ctdnssv_is_full(const CTDNSSV *ctdnssv)
{
    CTDNSSVRB_POOL *pool;

    pool = CTDNSSV_NODES_POOL(ctdnssv);
    return ctdnssvrb_pool_is_full(pool);
}

EC_BOOL ctdnssv_insert(CTDNSSV *ctdnssv, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port)
{
    CTDNSSVRB_POOL            *ctdnssv_pool;
    uint32_t                   node_pos;

    ctdnssv_pool = CTDNSSV_NODES_POOL(ctdnssv);

    if(EC_TRUE == ctdnssvrb_tree_insert_data(ctdnssv_pool, &(CTDNSSVRB_POOL_ROOT_POS(ctdnssv_pool)), tcid, &node_pos))
    {
        CTDNSSV_ITEM *ctdnssv_item;

        ctdnssv_item = ctdnssv_fetch(ctdnssv, node_pos);

        CTDNSSV_ITEM_TCID(ctdnssv_item)   = tcid;
        CTDNSSV_ITEM_IPADDR(ctdnssv_item) = ipaddr;
        CTDNSSV_ITEM_PORT(ctdnssv_item)   = (uint32_t)port;
        return (EC_TRUE);
    } 
    
    return (EC_FALSE);
}

CTDNSSV_ITEM *ctdnssv_fetch(const CTDNSSV *ctdnssv, const uint32_t node_pos)
{
    if(CTDNSSVRB_ERR_POS != node_pos)
    {
        const CTDNSSVRB_POOL *pool;
        const CTDNSSVRB_NODE *node;

        pool = CTDNSSV_NODES_POOL(ctdnssv);
        node = CTDNSSVRB_POOL_NODE(pool, node_pos);
        if(NULL_PTR != node)
        {
            return (CTDNSSV_ITEM *)CTDNSSV_RB_NODE_ITEM(node);
        }
    }
    return (NULL_PTR);
}

uint32_t ctdnssv_search(CTDNSSV *ctdnssv, const UINT32 tcid)
{
    CTDNSSVRB_POOL    *ctdnssv_pool;
    
    uint32_t           node_pos;

    ctdnssv_pool      = CTDNSSV_NODES_POOL(ctdnssv);

    node_pos = ctdnssvrb_tree_search_data(ctdnssv_pool, CTDNSSVRB_POOL_ROOT_POS(ctdnssv_pool), tcid);
    
    return (node_pos);
}

CTDNSSV_ITEM *ctdnssv_set(CTDNSSV *ctdnssv, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port)
{
    return ctdnssv_fetch(ctdnssv, ctdnssv_insert(ctdnssv, tcid, ipaddr, port));
}

CTDNSSV_ITEM *ctdnssv_get(CTDNSSV *ctdnssv, const UINT32 tcid)
{
    return ctdnssv_fetch(ctdnssv, ctdnssv_search(ctdnssv, tcid));
}

static EC_BOOL __ctdnssv_finger(CTDNSSV *ctdnssv, const uint32_t node_pos, UINT32 *left_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    CTDNSSVRB_POOL    *ctdnssv_pool;
    CTDNSSVRB_NODE    *node;

    CTDNSSV_ITEM      *ctdnssv_item;
    CTDNSSV_NODE      *ctdnssv_node;

    if(0 == (*left_num) || CTDNSSVRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    ctdnssv_pool = CTDNSSV_NODES_POOL(ctdnssv);
 
    node = CTDNSSVRB_POOL_NODE(ctdnssv_pool, node_pos);
    ctdnssv_item = (CTDNSSV_ITEM *)CTDNSSV_RB_NODE_ITEM(node);

    ctdnssv_node = ctdnssv_node_new();
    if(NULL_PTR == ctdnssv_node)
    {
        return (EC_FALSE);
    }

    CTDNSSV_NODE_TCID(ctdnssv_node)   = CTDNSSV_ITEM_TCID(ctdnssv_item);
    CTDNSSV_NODE_IPADDR(ctdnssv_node) = CTDNSSV_ITEM_IPADDR(ctdnssv_item);
    CTDNSSV_NODE_PORT(ctdnssv_node)   = CTDNSSV_ITEM_PORT(ctdnssv_item);

    clist_push_back(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), (void *)ctdnssv_node);
    (*left_num) --;

    if(0 < (*left_num) && CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_LEFT_POS(node))
    {
        __ctdnssv_finger(ctdnssv, CTDNSSVRB_NODE_LEFT_POS(node), left_num, ctdnssv_node_mgr);
    }

    if(0 < (*left_num) && CTDNSSVRB_ERR_POS != CTDNSSVRB_NODE_RIGHT_POS(node))
    {
        __ctdnssv_finger(ctdnssv, CTDNSSVRB_NODE_RIGHT_POS(node), left_num, ctdnssv_node_mgr);
    } 
 
    return (EC_TRUE);
}

EC_BOOL ctdnssv_finger(CTDNSSV *ctdnssv, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    CTDNSSVRB_POOL  *ctdnssv_pool;
    UINT32           left_num;
    
    left_num     = max_num;
    ctdnssv_pool = CTDNSSV_NODES_POOL(ctdnssv);

    return __ctdnssv_finger(ctdnssv, CTDNSSVRB_POOL_ROOT_POS(ctdnssv_pool), &left_num, ctdnssv_node_mgr);
}

EC_BOOL ctdnssv_pop(CTDNSSV *ctdnssv, UINT32 *tcid, UINT32 *ipaddr, UINT32 *port)
{
    CTDNSSVRB_POOL  *ctdnssv_pool;
    CTDNSSV_ITEM    *ctdnssv_item;
    uint32_t         node_pos;

    ctdnssv_pool = CTDNSSV_NODES_POOL(ctdnssv);

    node_pos = CTDNSSVRB_POOL_ROOT_POS(ctdnssv_pool);
    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    ctdnssv_item = ctdnssv_fetch(ctdnssv, node_pos);

    if(NULL_PTR != tcid)
    {
        (*tcid) = CTDNSSV_ITEM_TCID(ctdnssv_item);
    }

    if(NULL_PTR != ipaddr)
    {
        (*ipaddr) = CTDNSSV_ITEM_IPADDR(ctdnssv_item);
    }

    if(NULL_PTR != port)
    {
        (*port) = CTDNSSV_ITEM_PORT(ctdnssv_item);
    }
    
    ctdnssvrb_tree_delete(ctdnssv_pool, &(CTDNSSVRB_POOL_ROOT_POS(ctdnssv_pool)), node_pos);

    return (EC_TRUE);
}

EC_BOOL ctdnssv_show_item(LOG *log, const CTDNSSV *ctdnssv, const uint32_t node_pos)
{
    const CTDNSSVRB_POOL *pool;
    const CTDNSSV_ITEM   *ctdnssv_item;
    const CTDNSSVRB_NODE *node;

    if(CTDNSSVRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CTDNSSV_NODES_POOL(ctdnssv);

    node  = CTDNSSVRB_POOL_NODE(pool, node_pos); 

    /*itself*/
    ctdnssv_item = ctdnssv_fetch(ctdnssv, node_pos);

    ctdnssv_item_print(log, ctdnssv_item);
 
    return (EC_TRUE);
}

EC_BOOL ctdnssv_node_num(const CTDNSSV *ctdnssv, UINT32 *node_num)
{
    CTDNSSV_HEADER    *ctdnssv_header;
    CTDNSSVRB_POOL    *ctdnssv_pool;
    
    ctdnssv_header    = CTDNSSV_HDR(ctdnssv);
    ctdnssv_pool      = CTDNSSV_HEADER_NODES_POOL(ctdnssv_header);

    (*node_num) = CTDNSSVRB_POOL_NODE_USED_NUM(ctdnssv_pool);
    return (EC_TRUE);    
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

