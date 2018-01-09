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
#include "cmutex.h"
#include "cstring.h"
#include "cmisc.h"
#include "task.inc"
#include "task.h"

#include "cbloom.h"

#include "chashalgo.h"
#include "cstack.h"
#include "cmd5.h"

#include "ctdnsnprb.h"
#include "ctdnsnp.h"

#include "findex.inc"

static CTDNSNP_CFG g_ctdnsnp_cfg_tbl[] = {
    {(const char *)"8M"  , (const char *)"CTDNSNP_008M_MODEL", CTDNSNP_008M_CFG_FILE_SIZE,  CTDNSNP_008M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"16M" , (const char *)"CTDNSNP_016M_MODEL", CTDNSNP_016M_CFG_FILE_SIZE,  CTDNSNP_016M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"32M" , (const char *)"CTDNSNP_032M_MODEL", CTDNSNP_032M_CFG_FILE_SIZE,  CTDNSNP_032M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"64M" , (const char *)"CTDNSNP_064M_MODEL", CTDNSNP_064M_CFG_FILE_SIZE,  CTDNSNP_064M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"128M", (const char *)"CTDNSNP_128M_MODEL", CTDNSNP_128M_CFG_FILE_SIZE,  CTDNSNP_128M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"256M", (const char *)"CTDNSNP_256M_MODEL", CTDNSNP_256M_CFG_FILE_SIZE,  CTDNSNP_256M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"512M", (const char *)"CTDNSNP_512M_MODEL", CTDNSNP_512M_CFG_FILE_SIZE,  CTDNSNP_512M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"1G"  , (const char *)"CTDNSNP_001G_MODEL", CTDNSNP_001G_CFG_FILE_SIZE,  CTDNSNP_001G_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2G"  , (const char *)"CTDNSNP_002G_MODEL", CTDNSNP_002G_CFG_FILE_SIZE,  CTDNSNP_002G_CFG_ITEM_MAX_NUM, 0 },
#if (64 == WORDSIZE)
    {(const char *)"4G"  , (const char *)"CTDNSNP_004G_MODEL", CTDNSNP_004G_CFG_FILE_SIZE,  CTDNSNP_004G_CFG_ITEM_MAX_NUM, 0 },
#endif/*(64 == WORDSIZE)*/
};

static uint8_t g_ctdnsnp_cfg_tbl_len = (uint8_t)(sizeof(g_ctdnsnp_cfg_tbl)/sizeof(g_ctdnsnp_cfg_tbl[0]));

static CTDNSNPRB_NODE *__ctdnsnprb_node(CTDNSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CTDNSNPRB_POOL_NODE_MAX_NUM(pool) > node_pos)
    {
        CTDNSNPRB_NODE *node;
     
        node = (CTDNSNPRB_NODE *)((void *)(pool->rb_nodes) + node_pos * CTDNSNPRB_POOL_NODE_SIZEOF(pool));
     
        dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] __ctdnsnprb_node: pool %p, rb_nodes %p, node_pos %u  -> node %p\n",
                           pool, (void *)(pool->rb_nodes), node_pos, node);
        return (node);
    }
    return (NULL_PTR);
}


const char *ctdnsnp_model_str(const uint8_t ctdnsnp_model)
{
    CTDNSNP_CFG *ctdnsnp_cfg;
    if(ctdnsnp_model >= g_ctdnsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_model_str: invalid ctdnsnp mode %u\n", ctdnsnp_model);
        return (const char *)"unkown";
    }
    ctdnsnp_cfg = &(g_ctdnsnp_cfg_tbl[ ctdnsnp_model ]);
    return CTDNSNP_CFG_MODEL_STR(ctdnsnp_cfg);
}

uint8_t ctdnsnp_model_get(const char *model_str)
{
    uint8_t ctdnsnp_model;

    for(ctdnsnp_model = 0; ctdnsnp_model < g_ctdnsnp_cfg_tbl_len; ctdnsnp_model ++)
    {
        CTDNSNP_CFG *ctdnsnp_cfg;
        ctdnsnp_cfg = &(g_ctdnsnp_cfg_tbl[ ctdnsnp_model ]);

        if(0 == strcasecmp(CTDNSNP_CFG_MODEL_STR(ctdnsnp_cfg), model_str))
        {
            return (ctdnsnp_model);
        }
    }
    return (CTDNSNP_ERR_MODEL);
}

EC_BOOL ctdnsnp_model_file_size(const uint8_t ctdnsnp_model, UINT32 *file_size)
{
    CTDNSNP_CFG *ctdnsnp_cfg;
    if(ctdnsnp_model >= g_ctdnsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_model_file_size: invalid ctdnsnp mode %u\n", ctdnsnp_model);
        return (EC_FALSE);
    }
    ctdnsnp_cfg = &(g_ctdnsnp_cfg_tbl[ ctdnsnp_model ]);
    (*file_size) = CTDNSNP_CFG_FILE_SIZE(ctdnsnp_cfg);
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_model_item_max_num(const uint8_t ctdnsnp_model, uint32_t *item_max_num)
{
    CTDNSNP_CFG *ctdnsnp_cfg;
    if(ctdnsnp_model >= g_ctdnsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_model_item_max_num: invalid ctdnsnp mode %u\n", ctdnsnp_model);
        return (EC_FALSE);
    }
    ctdnsnp_cfg = &(g_ctdnsnp_cfg_tbl[ ctdnsnp_model ]);
    (*item_max_num) = CTDNSNP_CFG_ITEM_MAX_NUM(ctdnsnp_cfg);
    return (EC_TRUE);
}

static char *ctdnsnp_fname_gen(const char *root_dir, const uint32_t np_id)
{
    char    *fname;
    uint32_t len;

    if(NULL_PTR == root_dir)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_fname_gen: root_dir is null\n");
        return (NULL_PTR);
    }

    len = strlen(root_dir) + strlen("/np0000.dat") + 1;

    fname = safe_malloc(len, LOC_CTDNSNP_0001);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_fname_gen: malloc %u bytes failed\n", len);
        return (NULL_PTR);
    }
    snprintf(fname, len, "%s/np%04X.dat", root_dir, np_id);
    dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_fname_gen: np_id %u => np fname %s\n", np_id, fname);
    return (fname);
}

CTDNSNP_ITEM *ctdnsnp_item_new()
{
    CTDNSNP_ITEM *ctdnsnp_item;

    alloc_static_mem(MM_CTDNSNP_ITEM, &ctdnsnp_item, LOC_CTDNSNP_0002);
    if(NULL_PTR != ctdnsnp_item)
    {
        ctdnsnp_item_init(ctdnsnp_item);
    }
    return (ctdnsnp_item);
}

EC_BOOL ctdnsnp_item_init(CTDNSNP_ITEM *ctdnsnp_item)
{
    CTDNSNP_ITEM_TCID(ctdnsnp_item)             = CMPI_ERROR_TCID;
    CTDNSNP_ITEM_IPADDR(ctdnsnp_item)           = CMPI_ERROR_IPADDR;
    CTDNSNP_ITEM_PORT(ctdnsnp_item)             = CMPI_ERROR_SRVPORT;

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_item_clean(CTDNSNP_ITEM *ctdnsnp_item)
{
    CTDNSNP_ITEM_TCID(ctdnsnp_item)             = CMPI_ERROR_TCID;
    CTDNSNP_ITEM_IPADDR(ctdnsnp_item)           = CMPI_ERROR_IPADDR;
    CTDNSNP_ITEM_PORT(ctdnsnp_item)             = CMPI_ERROR_SRVPORT;
    
    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_item_clone(const CTDNSNP_ITEM *ctdnsnp_item_src, CTDNSNP_ITEM *ctdnsnp_item_des)
{
    if(NULL_PTR == ctdnsnp_item_src)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_item_clone: ctdnsnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == ctdnsnp_item_des)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_item_clone: ctdnsnp_item_des is null\n");
        return (EC_FALSE);
    }

    CTDNSNP_ITEM_TCID(ctdnsnp_item_des)        = CTDNSNP_ITEM_TCID(ctdnsnp_item_src);
    CTDNSNP_ITEM_IPADDR(ctdnsnp_item_des)      = CTDNSNP_ITEM_IPADDR(ctdnsnp_item_src);
    CTDNSNP_ITEM_PORT(ctdnsnp_item_des)        = CTDNSNP_ITEM_PORT(ctdnsnp_item_src);

    /*give up copying parent_pos !*/
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_item_free(CTDNSNP_ITEM *ctdnsnp_item)
{
    if(NULL_PTR != ctdnsnp_item)
    {
        ctdnsnp_item_clean(ctdnsnp_item);
        free_static_mem(MM_CTDNSNP_ITEM, ctdnsnp_item, LOC_CTDNSNP_0003);
    }
    return (EC_TRUE);
}

void ctdnsnp_item_print(LOG *log, const CTDNSNP_ITEM *ctdnsnp_item)
{
    sys_print(log, "ctdnsnp_item %p: tcid %s, ip %s, port %u\n",
                    ctdnsnp_item,
                    c_word_to_ipv4(CTDNSNP_ITEM_TCID(ctdnsnp_item)),
                    c_word_to_ipv4(CTDNSNP_ITEM_IPADDR(ctdnsnp_item)),
                    CTDNSNP_ITEM_PORT(ctdnsnp_item));
   
    return;
}

EC_BOOL ctdnsnp_item_load(CTDNSNP *ctdnsnp, uint32_t *offset, CTDNSNP_ITEM *ctdnsnp_item)
{
    RWSIZE rsize;
    UINT32 offset_t;

    offset_t = (*offset);
    rsize = sizeof(CTDNSNP_ITEM);
    if(EC_FALSE == c_file_load(CTDNSNP_FD(ctdnsnp), &offset_t, rsize, (UINT8 *)ctdnsnp_item))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_item_load: load item from offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_item_flush(CTDNSNP *ctdnsnp, uint32_t *offset, const CTDNSNP_ITEM *ctdnsnp_item)
{
    RWSIZE wsize;
    UINT32 offset_t;

    offset_t = (*offset);
    wsize = sizeof(CTDNSNP_ITEM);
    if(EC_FALSE == c_file_flush(CTDNSNP_FD(ctdnsnp), &offset_t, wsize, (UINT8 *)ctdnsnp_item))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_item_load: flush item to offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_item_is_tcid(const CTDNSNP_ITEM *ctdnsnp_item, const UINT32 tcid)
{
    if(tcid !=  CTDNSNP_ITEM_TCID(ctdnsnp_item))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CTDNSNP_ITEM *ctdnsnp_item_parent(const CTDNSNP *ctdnsnp, const CTDNSNP_ITEM *ctdnsnp_item)
{
    uint32_t parent_pos;

    parent_pos = CTDNSNPRB_NODE_PARENT_POS(CTDNSNP_ITEM_RB_NODE(ctdnsnp_item));
    if(CTDNSNPRB_ERR_POS == parent_pos)
    {
        return (NULL_PTR);
    }

    return ctdnsnp_fetch(ctdnsnp, parent_pos);
}

CTDNSNP_ITEM *ctdnsnp_item_left(const CTDNSNP *ctdnsnp, const CTDNSNP_ITEM *ctdnsnp_item)
{
    uint32_t left_pos;

    left_pos = CTDNSNPRB_NODE_LEFT_POS(CTDNSNP_ITEM_RB_NODE(ctdnsnp_item));
    if(CTDNSNPRB_ERR_POS == left_pos)
    {
        return (NULL_PTR);
    }

    return ctdnsnp_fetch(ctdnsnp, left_pos);
}

CTDNSNP_ITEM *ctdnsnp_item_right(const CTDNSNP *ctdnsnp, const CTDNSNP_ITEM *ctdnsnp_item)
{
    uint32_t right_offset;

    right_offset = CTDNSNPRB_NODE_RIGHT_POS(CTDNSNP_ITEM_RB_NODE(ctdnsnp_item));
    if(CTDNSNPRB_ERR_POS == right_offset)
    {
        return (NULL_PTR);
    }

    return ctdnsnp_fetch(ctdnsnp, right_offset);
}

static CTDNSNP_HEADER *__ctdnsnp_header_load(const uint32_t np_id, const UINT32 fsize, int fd)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(fsize, LOC_CTDNSNP_0004);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:__ctdnsnp_header_load: malloc %u bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, buff))
    {
        safe_free(buff, LOC_CTDNSNP_0005);
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:__ctdnsnp_header_load: load %u bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    return ((CTDNSNP_HEADER *)buff);
}

static CTDNSNP_HEADER *__ctdnsnp_header_dup(CTDNSNP_HEADER *src_ctdnsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    CTDNSNP_HEADER *des_ctdnsnp_header;

    des_ctdnsnp_header = (CTDNSNP_HEADER *)safe_malloc(fsize, LOC_CTDNSNP_0006);
    if(NULL_PTR == des_ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:__ctdnsnp_header_dup: new header with %u bytes for np %u fd %d failed\n",
                           fsize, des_np_id, fd);
        return (NULL_PTR);
    }  

    BCOPY(src_ctdnsnp_header, des_ctdnsnp_header, fsize);

    CTDNSNP_HEADER_NP_ID(des_ctdnsnp_header)  = des_np_id;
    return (des_ctdnsnp_header);
}

static CTDNSNP_HEADER *__ctdnsnp_header_new(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t model)
{
    CTDNSNP_HEADER *ctdnsnp_header;
    uint32_t        node_max_num;
    uint32_t        node_sizeof;

    ctdnsnp_header = (CTDNSNP_HEADER *)safe_malloc(fsize, LOC_CTDNSNP_0007);
    if(NULL_PTR == ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:__ctdnsnp_header_new: new header with %u bytes for np %u fd %d failed\n",
                           fsize, np_id, fd);
        return (NULL_PTR);
    }  

    CTDNSNP_HEADER_NP_ID(ctdnsnp_header)     = np_id;
    CTDNSNP_HEADER_NP_MODEL(ctdnsnp_header)  = model;

    ctdnsnp_model_item_max_num(model, &node_max_num);
    node_sizeof = sizeof(CTDNSNP_ITEM);

    /*init RB Nodes*/ 
    ctdnsnprb_pool_init(CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header), node_max_num, node_sizeof);
 
    return (ctdnsnp_header);
}

static CTDNSNP_HEADER * __ctdnsnp_header_flush(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnsnp_header)
    {
        UINT32 offset;

        offset = 0;     
        if(EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)ctdnsnp_header))
        {
            dbg_log(SEC_0022_CTDNSNP, 1)(LOGSTDOUT, "warn:__ctdnsnp_header_flush: flush ctdnsnp_hdr of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }
    } 
    return (ctdnsnp_header);
}

static CTDNSNP_HEADER *__ctdnsnp_header_free(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnsnp_header)
    {
        UINT32 offset;

        offset = 0;
        if(
           ERR_FD != fd
        && EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)ctdnsnp_header)
        )
        {
            dbg_log(SEC_0022_CTDNSNP, 1)(LOGSTDOUT, "warn:__ctdnsnp_header_free: flush ctdnsnp_hdr of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }

        safe_free(ctdnsnp_header, LOC_CTDNSNP_0008);
    }
 
    /*ctdnsnp_header cannot be accessed again*/
    return (NULL_PTR);
}


static CTDNSNP_HEADER *__ctdnsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd)
{
    CTDNSNP_HEADER *ctdnsnp_header;

    ctdnsnp_header = (CTDNSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:__ctdnsnp_header_open: mmap np %u with fd %d failed, errno = %d, errstr = %s\n",
                           np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }
 
    return (ctdnsnp_header);
}

static CTDNSNP_HEADER *__ctdnsnp_header_clone(const CTDNSNP_HEADER *src_ctdnsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    CTDNSNP_HEADER *des_ctdnsnp_header;
 
    des_ctdnsnp_header = (CTDNSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == des_ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:__ctdnsnp_header_clone: mmap np %u with fd %d failed, errno = %d, errstr = %s\n",
                           des_np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }  

    BCOPY(src_ctdnsnp_header, des_ctdnsnp_header, fsize);

    CTDNSNP_HEADER_NP_ID(des_ctdnsnp_header)  = des_np_id;
 
    return (des_ctdnsnp_header);
}

static CTDNSNP_HEADER *__ctdnsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t model)
{
    CTDNSNP_HEADER *ctdnsnp_header;
    
    uint32_t        node_max_num;
    uint32_t        node_sizeof;
 
    ctdnsnp_header = (CTDNSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:__ctdnsnp_header_create: mmap np %u with fd %d failed, errno = %d, errstr = %s\n",
                           np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }  

    CTDNSNP_HEADER_NP_ID(ctdnsnp_header)     = np_id;
    CTDNSNP_HEADER_NP_MODEL(ctdnsnp_header)  = model;

    ctdnsnp_model_item_max_num(model, &node_max_num);
    node_sizeof = sizeof(CTDNSNP_ITEM);
    ASSERT(32 == node_sizeof);

    /*init RB Nodes*/
    ctdnsnprb_pool_init(CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header), node_max_num, node_sizeof);
 
    return (ctdnsnp_header);
}

static CTDNSNP_HEADER * __ctdnsnp_header_sync(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnsnp_header)
    {
        if(0 != msync(ctdnsnp_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "warn:__ctdnsnp_header_sync: sync ctdnsnp_hdr of np %u %d with size %u failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] __ctdnsnp_header_sync: sync ctdnsnp_hdr of np %u %d with size %u done\n",
                               np_id, fd, fsize);
        }    
    } 
    return (ctdnsnp_header);
}

static CTDNSNP_HEADER *__ctdnsnp_header_close(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != ctdnsnp_header)
    {
        if(0 != msync(ctdnsnp_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "warn:__ctdnsnp_header_close: sync ctdnsnp_hdr of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] __ctdnsnp_header_close: sync ctdnsnp_hdr of np %u fd %d with size %u done\n",
                               np_id, fd, fsize);
        }
        if(0 != munmap(ctdnsnp_header, fsize))
        {
            dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "warn:__ctdnsnp_header_close: munmap ctdnsnp of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] __ctdnsnp_header_close: munmap ctdnsnp of np %u fd %d with size %u done\n",
                               np_id, fd, fsize);
        }
    }
 
    /*ctdnsnp_header cannot be accessed again*/
    return (NULL_PTR);
}

EC_BOOL ctdnsnp_header_init(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const uint8_t model)
{
    CTDNSNP_HEADER_NP_ID(ctdnsnp_header)            = np_id;
    CTDNSNP_HEADER_NP_MODEL(ctdnsnp_header)         = model;

    //TODO:

    /*do nothing on CTDNSNPRB_POOL pool*/
 
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_header_clean(CTDNSNP_HEADER *ctdnsnp_header)
{
    CTDNSNP_HEADER_NP_ID(ctdnsnp_header)                 = CTDNSNP_ERR_ID;
    CTDNSNP_HEADER_NP_MODEL(ctdnsnp_header)              = CTDNSNP_ERR_MODEL;
 
    /*do nothing on CTDNSNPRB_POOL pool*/

    return (EC_TRUE);
}

CTDNSNP_HEADER *ctdnsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CTDNS_NP_CACHE_IN_MEM)
    {
        return __ctdnsnp_header_load(np_id, fsize, fd);
    }

    return __ctdnsnp_header_open(np_id, fsize, fd);
}

CTDNSNP_HEADER *ctdnsnp_header_clone(CTDNSNP_HEADER *src_ctdnsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CTDNS_NP_CACHE_IN_MEM)
    {
        return __ctdnsnp_header_dup(src_ctdnsnp_header, des_np_id, fsize, fd);
    }

    return __ctdnsnp_header_clone(src_ctdnsnp_header, des_np_id, fsize, fd);
}


CTDNSNP_HEADER *ctdnsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t model)
{
    if(SWITCH_ON == CTDNS_NP_CACHE_IN_MEM)
    {
        return __ctdnsnp_header_new(np_id, fsize, fd, model);
    }

    return __ctdnsnp_header_create(np_id, fsize, fd, model);
}

CTDNSNP_HEADER *ctdnsnp_header_sync(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CTDNS_NP_CACHE_IN_MEM)
    {
        return __ctdnsnp_header_flush(ctdnsnp_header, np_id, fsize, fd);
    }

    return __ctdnsnp_header_sync(ctdnsnp_header, np_id, fsize, fd); 
}

CTDNSNP_HEADER *ctdnsnp_header_close(CTDNSNP_HEADER *ctdnsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CTDNS_NP_CACHE_IN_MEM)
    {
        return __ctdnsnp_header_free(ctdnsnp_header, np_id, fsize, fd);
    }

    return __ctdnsnp_header_close(ctdnsnp_header, np_id, fsize, fd);
}

void ctdnsnp_header_print(LOG *log, const CTDNSNP *ctdnsnp)
{
    const CTDNSNP_HEADER *ctdnsnp_header;

    ctdnsnp_header = CTDNSNP_HDR(ctdnsnp);

    sys_log(log, "np_id %u, model %u, item max num %u, item used num %u\n",
                CTDNSNP_HEADER_NP_ID(ctdnsnp_header),
                CTDNSNP_HEADER_NP_MODEL(ctdnsnp_header),
                CTDNSNP_HEADER_ITEMS_MAX_NUM(ctdnsnp_header),
                CTDNSNP_HEADER_ITEMS_USED_NUM(ctdnsnp_header)
        );   

    ctdnsnprb_pool_print(log, CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header));
    return;
}

CTDNSNP *ctdnsnp_new()
{
    CTDNSNP *ctdnsnp;

    alloc_static_mem(MM_CTDNSNP, &ctdnsnp, LOC_CTDNSNP_0009);
    if(NULL_PTR != ctdnsnp)
    {
        ctdnsnp_init(ctdnsnp);
    }
    return (ctdnsnp);
}

EC_BOOL ctdnsnp_init(CTDNSNP *ctdnsnp)
{ 
    CTDNSNP_FD(ctdnsnp)              = ERR_FD;
    CTDNSNP_FSIZE(ctdnsnp)           = 0;
    CTDNSNP_FNAME(ctdnsnp)           = NULL_PTR;
    CTDNSNP_HDR(ctdnsnp)             = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_clean(CTDNSNP *ctdnsnp)
{
    if(NULL_PTR != CTDNSNP_HDR(ctdnsnp))
    {
        ctdnsnp_header_close(CTDNSNP_HDR(ctdnsnp), CTDNSNP_ID(ctdnsnp), CTDNSNP_FSIZE(ctdnsnp), CTDNSNP_FD(ctdnsnp));
        CTDNSNP_HDR(ctdnsnp) = NULL_PTR;
    }
 
    if(ERR_FD != CTDNSNP_FD(ctdnsnp))
    {
        c_file_close(CTDNSNP_FD(ctdnsnp));
        CTDNSNP_FD(ctdnsnp) = ERR_FD;
    }

    CTDNSNP_FSIZE(ctdnsnp) = 0;

    if(NULL_PTR != CTDNSNP_FNAME(ctdnsnp))
    {
        safe_free(CTDNSNP_FNAME(ctdnsnp), LOC_CTDNSNP_0010);
        CTDNSNP_FNAME(ctdnsnp) = NULL_PTR;
    }

    CTDNSNP_HDR(ctdnsnp) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_free(CTDNSNP *ctdnsnp)
{
    if(NULL_PTR != ctdnsnp)
    {
        ctdnsnp_clean(ctdnsnp);
        free_static_mem(MM_CTDNSNP, ctdnsnp, LOC_CTDNSNP_0011);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_is_full(const CTDNSNP *ctdnsnp)
{
    CTDNSNPRB_POOL *pool;

    pool = CTDNSNP_ITEMS_POOL(ctdnsnp);
    return ctdnsnprb_pool_is_full(pool);
}

void ctdnsnp_print(LOG *log, const CTDNSNP *ctdnsnp)
{
    sys_log(log, "ctdnsnp %p: np_id %u, fname %s, fsize %lu\n",
                 ctdnsnp,
                 CTDNSNP_ID(ctdnsnp),
                 CTDNSNP_FNAME(ctdnsnp),
                 CTDNSNP_FSIZE(ctdnsnp)
                 );
              
    sys_log(log, "ctdnsnp %p: header: \n", ctdnsnp);
    ctdnsnp_header_print(log, ctdnsnp);
    return;
}


uint32_t ctdnsnp_search_no_lock(CTDNSNP *ctdnsnp, const UINT32 tcid)
{
    CTDNSNPRB_POOL    *ctdnsnp_pool;
    
    uint32_t           node_pos;

    ctdnsnp_pool      = CTDNSNP_ITEMS_POOL(ctdnsnp);

    node_pos = ctdnsnprb_tree_search_data(ctdnsnp_pool, CTDNSNPRB_POOL_ROOT_POS(ctdnsnp_pool), tcid);
    
    return (node_pos);
}

uint32_t ctdnsnp_search(CTDNSNP *ctdnsnp, const UINT32 tcid)
{
    return ctdnsnp_search_no_lock(ctdnsnp, tcid);
}

uint32_t ctdnsnp_insert_no_lock(CTDNSNP *ctdnsnp, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port)
{
    CTDNSNP_HEADER    *ctdnsnp_header;
    CTDNSNPRB_POOL    *ctdnsnp_pool;
    
    uint32_t           node_pos;

    ctdnsnp_header = CTDNSNP_HDR(ctdnsnp);
    ASSERT(NULL_PTR != ctdnsnp_header);

    ctdnsnp_pool = CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header);
    ASSERT(NULL_PTR != ctdnsnp_pool);

    if(EC_TRUE == ctdnsnprb_tree_insert_data(ctdnsnp_pool, &(CTDNSNPRB_POOL_ROOT_POS(ctdnsnp_pool)), tcid, &node_pos))
    {
        CTDNSNP_ITEM *ctdnsnp_item;

        ctdnsnp_item = ctdnsnp_fetch(ctdnsnp, node_pos);

        CTDNSNP_ITEM_TCID(ctdnsnp_item)   = tcid;
        CTDNSNP_ITEM_IPADDR(ctdnsnp_item) = ipaddr;
        CTDNSNP_ITEM_PORT(ctdnsnp_item)   = (uint32_t)port;
        
        return (node_pos);
    }

    if(CTDNSNPRB_ERR_POS != node_pos) /*found duplicate*/
    {
        CTDNSNP_ITEM *ctdnsnp_item;

        ctdnsnp_item = ctdnsnp_fetch(ctdnsnp, node_pos);
        
        if(tcid == CTDNSNP_ITEM_TCID(ctdnsnp_item)
        && ipaddr == CTDNSNP_ITEM_IPADDR(ctdnsnp_item)
        && (uint32_t)port == CTDNSNP_ITEM_PORT(ctdnsnp_item))
        {
            return (node_pos);
        }
        
        return (CTDNSNPRB_ERR_POS);
    }

    return (CTDNSNPRB_ERR_POS);
}

uint32_t ctdnsnp_insert(CTDNSNP *ctdnsnp, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port)
{
    return ctdnsnp_insert_no_lock(ctdnsnp, tcid, ipaddr, port);
}

CTDNSNP_ITEM *ctdnsnp_fetch(const CTDNSNP *ctdnsnp, const uint32_t node_pos)
{
    if(CTDNSNPRB_ERR_POS != node_pos)
    {
        const CTDNSNPRB_POOL *pool;
        const CTDNSNPRB_NODE *node;

        pool = CTDNSNP_ITEMS_POOL(ctdnsnp);
        node = CTDNSNPRB_POOL_NODE(pool, node_pos);
        if(NULL_PTR != node)
        {
            return (CTDNSNP_ITEM *)CTDNSNP_RB_NODE_ITEM(node);
        }
    }
    //dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "[DEBUG] ctdnsnp_fetch: np %u, fetch ctdnsnprb node %u failed\n", CTDNSNP_ID(ctdnsnp), node_pos);
    return (NULL_PTR);
}

CTDNSNP_ITEM *ctdnsnp_set(CTDNSNP *ctdnsnp, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port)
{
    return ctdnsnp_fetch(ctdnsnp, ctdnsnp_insert(ctdnsnp, tcid, ipaddr, port));
}

CTDNSNP_ITEM *ctdnsnp_get(CTDNSNP *ctdnsnp, const UINT32 tcid)
{
    return ctdnsnp_fetch(ctdnsnp, ctdnsnp_search(ctdnsnp, tcid));
}

EC_BOOL ctdnsnp_delete(CTDNSNP *ctdnsnp, const UINT32 tcid)
{
    CTDNSNPRB_POOL *ctdnsnp_pool;
    uint32_t        node_pos;

    ctdnsnp_pool = CTDNSNP_ITEMS_POOL(ctdnsnp);
    return ctdnsnprb_tree_delete_data(ctdnsnp_pool, &(CTDNSNPRB_POOL_ROOT_POS(ctdnsnp_pool)), tcid, &node_pos);
}

CTDNSNP *ctdnsnp_open(const char *np_root_dir, const uint32_t np_id)
{
    UINT32           fsize;
    char            *np_fname;
    CTDNSNP         *ctdnsnp;
    CTDNSNP_HEADER  *ctdnsnp_header;
    int fd;

    np_fname = ctdnsnp_fname_gen(np_root_dir, np_id);
    if(NULL_PTR == np_fname)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_open: generate np fname from np_root_dir %s failed\n", np_root_dir);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_access(np_fname, F_OK))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_open: np %s not exist, try to create it\n", np_fname);
        safe_free(np_fname, LOC_CTDNSNP_0012);
        return (NULL_PTR);
    }

    fd = c_file_open(np_fname, O_RDWR, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_open: open ctdnsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CTDNSNP_0013);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_open: get size of %s failed\n", np_fname);
        safe_free(np_fname, LOC_CTDNSNP_0014);
        c_file_close(fd);
        return (NULL_PTR);
    }
    dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_open: np %u, fsize %ld\n", np_id, fsize);

    ctdnsnp_header = ctdnsnp_header_open(np_id, fsize, fd);
    if(NULL_PTR == ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_open: open ctdnsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CTDNSNP_0015);
        c_file_close(fd);
        return (NULL_PTR);
    } 

    ctdnsnp = ctdnsnp_new();
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_open: new ctdnsnp %u failed\n", np_id);
        safe_free(np_fname, LOC_CTDNSNP_0016);
        c_file_close(fd);
        ctdnsnp_header_close(ctdnsnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }

    CTDNSNP_HDR(ctdnsnp) = ctdnsnp_header;

    CTDNSNP_FD(ctdnsnp)    = fd;
    CTDNSNP_FSIZE(ctdnsnp) = fsize;
    CTDNSNP_FNAME(ctdnsnp) = (uint8_t *)np_fname;

    ASSERT(np_id == CTDNSNP_HEADER_NP_ID(ctdnsnp_header));
    return (ctdnsnp);
}

EC_BOOL ctdnsnp_close(CTDNSNP *ctdnsnp)
{
    if(NULL_PTR != ctdnsnp)
    {
        uint32_t np_id;

        np_id = CTDNSNP_ID(ctdnsnp); /*save np np_id info due to CTDNSNP_HDR will be destoried immediately*/
     
        dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_close: close np %u beg\n", np_id);

        if(NULL_PTR != CTDNSNP_HDR(ctdnsnp))
        {
            ctdnsnp_header_close(CTDNSNP_HDR(ctdnsnp), CTDNSNP_ID(ctdnsnp), CTDNSNP_FSIZE(ctdnsnp), CTDNSNP_FD(ctdnsnp));
            CTDNSNP_HDR(ctdnsnp) = NULL_PTR;
        }
        dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_close: close np %u end\n", np_id);
        ctdnsnp_free(ctdnsnp);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_sync(CTDNSNP *ctdnsnp)
{
    if(NULL_PTR != ctdnsnp && NULL_PTR != CTDNSNP_HDR(ctdnsnp))
    {
        ctdnsnp_header_sync(CTDNSNP_HDR(ctdnsnp), CTDNSNP_ID(ctdnsnp), CTDNSNP_FSIZE(ctdnsnp), CTDNSNP_FD(ctdnsnp));
    }
    return (EC_TRUE);
}

CTDNSNP *ctdnsnp_clone(CTDNSNP *src_ctdns, const char *np_root_dir, const uint32_t des_np_id)
{
    CTDNSNP         *des_ctdns;
    CTDNSNP_HEADER  *src_ctdnsnp_header;
    CTDNSNP_HEADER  *des_ctdnsnp_header;
    char            *des_np_fname;
    int              fd;
    UINT32           fsize;

    src_ctdnsnp_header = CTDNSNP_HDR(src_ctdns);
    fsize = CTDNSNP_FSIZE(src_ctdns);

    des_np_fname = ctdnsnp_fname_gen(np_root_dir, des_np_id);
    if(NULL_PTR == des_np_fname)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_clone: generate des_np_fname of np %u, root_dir %s failed\n", des_np_id, np_root_dir);
        return (NULL_PTR);
    }
 
    if(EC_TRUE == c_file_access(des_np_fname, F_OK))/*exist*/
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_clone: np %u exist already\n", des_np_id);
        safe_free(des_np_fname, LOC_CTDNSNP_0017);
        return (NULL_PTR);
    }

    fd = c_file_open(des_np_fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_clone: cannot create np %s\n", des_np_fname);
        safe_free(des_np_fname, LOC_CTDNSNP_0018);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_truncate(fd, fsize))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_clone: truncate np %s to size %u failed\n", des_np_fname, fsize);
        safe_free(des_np_fname, LOC_CTDNSNP_0019);
        c_file_close(fd);
        return (NULL_PTR);
    }

    /*clone*/
    des_ctdnsnp_header = ctdnsnp_header_clone(src_ctdnsnp_header, des_np_id, fsize, fd);
    if(NULL_PTR == des_ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_clone: open ctdnsnp file %s failed\n", des_np_fname);
        safe_free(des_np_fname, LOC_CTDNSNP_0020);
        c_file_close(fd);
        return (NULL_PTR);
    }

    des_ctdns = ctdnsnp_new();
    if(NULL_PTR == des_ctdns)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_clone: new ctdnsnp %u failed\n", des_np_id);
        safe_free(des_np_fname, LOC_CTDNSNP_0021);     
        ctdnsnp_header_close(des_ctdnsnp_header, des_np_id, fsize, fd);
        c_file_close(fd);
        return (NULL_PTR);
    }
    CTDNSNP_HDR(des_ctdns) = des_ctdnsnp_header;

    CTDNSNP_FD(des_ctdns)    = fd;
    CTDNSNP_FSIZE(des_ctdns) = fsize;
    CTDNSNP_FNAME(des_ctdns) = (uint8_t *)des_np_fname;

    ASSERT(des_np_id == CTDNSNP_HEADER_NP_ID(des_ctdnsnp_header)); 

    dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_clone: clone np %u done\n", des_np_id);

    return (des_ctdns);
}

CTDNSNP *ctdnsnp_create(const char *np_root_dir, const uint32_t np_id, const uint8_t model)
{
    CTDNSNP         *ctdnsnp;
    CTDNSNP_HEADER  *ctdnsnp_header;
    char            *np_fname;
    
    UINT32           fsize;
    int              fd;
    uint32_t         item_max_num;

    ASSERT(8 * 1024 == ((unsigned long)(&(((CTDNSNP_HEADER *)0)->pool.rb_nodes))));
    ASSERT(8 * 1024 == sizeof(CTDNSNP_HEADER));

    if(32 != sizeof(CTDNSNP_ITEM))
    {
        ASSERT(0 == ((unsigned long)(&(((CTDNSNP_ITEM *)0)->rb_node))));
        ASSERT(16 == ((unsigned long)(&(((CTDNSNP_ITEM *)0)->tcid))));
        ASSERT(24 == ((unsigned long)(&(((CTDNSNP_ITEM *)0)->ipaddr))));
    }
    ASSERT(32 == sizeof(CTDNSNP_ITEM));

    if(EC_FALSE == ctdnsnp_model_file_size(model, &fsize))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: invalid model %u\n", model);
        return (NULL_PTR);
    }

    if(EC_FALSE == ctdnsnp_model_item_max_num(model, &item_max_num))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: invalid model %u\n", model);
        return (NULL_PTR);
    } 

    np_fname = ctdnsnp_fname_gen(np_root_dir, np_id);
    if(NULL_PTR == np_fname)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: generate np_fname of np %u, root_dir %s failed\n", np_id, np_root_dir);
        return (NULL_PTR);
    }
 
    if(EC_TRUE == c_file_access(np_fname, F_OK))/*exist*/
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: np %u '%s' exist already\n", np_id, np_fname);
        safe_free(np_fname, LOC_CTDNSNP_0022);
        return (NULL_PTR);
    }

    fd = c_file_open(np_fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: cannot create np %s\n", np_fname);
        safe_free(np_fname, LOC_CTDNSNP_0023);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_truncate(fd, fsize))
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: truncate np %s to size %u failed\n", np_fname, fsize);
        safe_free(np_fname, LOC_CTDNSNP_0024);
        c_file_close(fd);
        return (NULL_PTR);
    }

    ctdnsnp_header = ctdnsnp_header_create(np_id, fsize, fd, model);
    if(NULL_PTR == ctdnsnp_header)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: open ctdnsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CTDNSNP_0025);
        c_file_close(fd);
        return (NULL_PTR);
    }

    ctdnsnp = ctdnsnp_new();
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0022_CTDNSNP, 0)(LOGSTDOUT, "error:ctdnsnp_create: new ctdnsnp %u failed\n", np_id);
        safe_free(np_fname, LOC_CTDNSNP_0026);
        c_file_close(fd);
        ctdnsnp_header_close(ctdnsnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }
    CTDNSNP_HDR(ctdnsnp)   = ctdnsnp_header;
   
    CTDNSNP_FD(ctdnsnp)    = fd;
    CTDNSNP_FSIZE(ctdnsnp) = fsize;
    CTDNSNP_FNAME(ctdnsnp) = (uint8_t *)np_fname;

    ASSERT(np_id == CTDNSNP_HEADER_NP_ID(ctdnsnp_header)); 

    dbg_log(SEC_0022_CTDNSNP, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_create: create np %u done\n", np_id);

    return (ctdnsnp);
}

EC_BOOL ctdnsnp_show_item(LOG *log, const CTDNSNP *ctdnsnp, const uint32_t node_pos)
{
    const CTDNSNPRB_POOL *pool;
    const CTDNSNP_ITEM   *ctdnsnp_item;
    const CTDNSNPRB_NODE *node;

    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CTDNSNP_ITEMS_POOL(ctdnsnp);

    node  = CTDNSNPRB_POOL_NODE(pool, node_pos); 

    /*itself*/
    ctdnsnp_item = ctdnsnp_fetch(ctdnsnp, node_pos);

    ctdnsnp_item_print(log, ctdnsnp_item);
 
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_tcid_num(const CTDNSNP *ctdnsnp, UINT32 *tcid_num)
{
    CTDNSNP_HEADER    *ctdnsnp_header;
    CTDNSNPRB_POOL    *ctdnsnp_pool;
    
    ctdnsnp_header    = CTDNSNP_HDR(ctdnsnp);
    ctdnsnp_pool      = CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header);

    (*tcid_num) = CTDNSNPRB_POOL_NODE_USED_NUM(ctdnsnp_pool);
    return (EC_TRUE);    
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

