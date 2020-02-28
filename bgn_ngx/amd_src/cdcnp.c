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
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cdcpgrb.h"
#include "cdcpgb.h"
#include "cdcnprb.h"
#include "cdcnplru.h"
#include "cdcnpdel.h"
#include "cdcnpdeg.h"
#include "cdcnp.h"
#include "cmmap.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCNP_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCNP_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

static CDCNP_CFG g_cdcnp_cfg_tbl[] = {
    {(const char *)"8M"  , (const char *)"CDCNP_008M_MODEL", CDCNP_008M_CFG_FILE_SIZE,  CDCNP_008M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"16M" , (const char *)"CDCNP_016M_MODEL", CDCNP_016M_CFG_FILE_SIZE,  CDCNP_016M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"32M" , (const char *)"CDCNP_032M_MODEL", CDCNP_032M_CFG_FILE_SIZE,  CDCNP_032M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"64M" , (const char *)"CDCNP_064M_MODEL", CDCNP_064M_CFG_FILE_SIZE,  CDCNP_064M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"128M", (const char *)"CDCNP_128M_MODEL", CDCNP_128M_CFG_FILE_SIZE,  CDCNP_128M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"256M", (const char *)"CDCNP_256M_MODEL", CDCNP_256M_CFG_FILE_SIZE,  CDCNP_256M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"512M", (const char *)"CDCNP_512M_MODEL", CDCNP_512M_CFG_FILE_SIZE,  CDCNP_512M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"1G"  , (const char *)"CDCNP_001G_MODEL", CDCNP_001G_CFG_FILE_SIZE,  CDCNP_001G_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2G"  , (const char *)"CDCNP_002G_MODEL", CDCNP_002G_CFG_FILE_SIZE,  CDCNP_002G_CFG_ITEM_MAX_NUM, 0 },
#if (64 == WORDSIZE)
    {(const char *)"4G"  , (const char *)"CDCNP_004G_MODEL", CDCNP_004G_CFG_FILE_SIZE,  CDCNP_004G_CFG_ITEM_MAX_NUM, 0 },
#endif/*(64 == WORDSIZE)*/
};

static uint8_t g_cdcnp_cfg_tbl_len = (uint8_t)(sizeof(g_cdcnp_cfg_tbl)/sizeof(g_cdcnp_cfg_tbl[0]));

static const uint8_t g_nbits_per_byte[] = {
    /*   0 -   31*/ 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    /*  32 -   63*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  64 -   95*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /*  96 -  127*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 128 -  159*/ 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    /* 160 -  191*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 192 -  223*/ 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    /* 224 -  255*/ 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

STATIC_CAST static CDCNPRB_NODE *__cdcnprb_node(CDCNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CDCNPRB_POOL_NODE_MAX_NUM(pool) > node_pos)
    {
        CDCNPRB_NODE *node;

        node = (CDCNPRB_NODE *)((void *)(pool->rb_nodes) + node_pos * CDCNPRB_POOL_NODE_SIZEOF(pool));

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] __cdcnprb_node: pool %p, rb_nodes %p, node_pos %u  -> node %p\n",
                           pool, (void *)(pool->rb_nodes), node_pos, node);
        return (node);
    }
    return (NULL_PTR);
}


const char *cdcnp_model_str(const uint8_t cdcnp_model)
{
    CDCNP_CFG *cdcnp_cfg;
    if(cdcnp_model >= g_cdcnp_cfg_tbl_len)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_model_str: invalid cdcnp mode %u\n", cdcnp_model);
        return (const char *)"unkown";
    }
    cdcnp_cfg = &(g_cdcnp_cfg_tbl[ cdcnp_model ]);
    return CDCNP_CFG_MODEL_STR(cdcnp_cfg);
}

uint8_t cdcnp_model_get(const char *model_str)
{
    uint8_t cdcnp_model;

    for(cdcnp_model = 0; cdcnp_model < g_cdcnp_cfg_tbl_len; cdcnp_model ++)
    {
        CDCNP_CFG *cdcnp_cfg;
        cdcnp_cfg = &(g_cdcnp_cfg_tbl[ cdcnp_model ]);

        if(0 == strcasecmp(CDCNP_CFG_MODEL_STR(cdcnp_cfg), model_str))
        {
            return (cdcnp_model);
        }
    }
    return (CDCNP_ERR_MODEL);
}

EC_BOOL cdcnp_model_file_size(const uint8_t cdcnp_model, UINT32 *file_size)
{
    CDCNP_CFG *cdcnp_cfg;
    if(cdcnp_model >= g_cdcnp_cfg_tbl_len)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_model_file_size: invalid cdcnp mode %u\n", cdcnp_model);
        return (EC_FALSE);
    }
    cdcnp_cfg = &(g_cdcnp_cfg_tbl[ cdcnp_model ]);
    (*file_size) = CDCNP_CFG_FILE_SIZE(cdcnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cdcnp_model_item_max_num(const uint8_t cdcnp_model, uint32_t *item_max_num)
{
    CDCNP_CFG *cdcnp_cfg;
    if(cdcnp_model >= g_cdcnp_cfg_tbl_len)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_model_item_max_num: invalid cdcnp mode %u\n", cdcnp_model);
        return (EC_FALSE);
    }
    cdcnp_cfg = &(g_cdcnp_cfg_tbl[ cdcnp_model ]);
    (*item_max_num) = CDCNP_CFG_ITEM_MAX_NUM(cdcnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cdcnp_model_search(const UINT32 ssd_disk_size /*in byte*/, uint8_t *cdcnp_model)
{
    UINT32      np_fsize;
    UINT8       cdcnp_model_t;

    /*np file size = ((rdisk size) / (page size)) * (item size)*/
    np_fsize = ((ssd_disk_size >> CDCPGB_PAGE_SIZE_NBITS) << CDCNP_ITEM_SIZE_NBITS);

    for(cdcnp_model_t = 0; cdcnp_model_t < g_cdcnp_cfg_tbl_len; cdcnp_model_t ++)
    {
        CDCNP_CFG *cdcnp_cfg;
        cdcnp_cfg = &(g_cdcnp_cfg_tbl[ cdcnp_model_t ]);

        if(0 < CDCNP_CFG_ITEM_MAX_NUM(cdcnp_cfg)
        && np_fsize <= CDCNP_CFG_FILE_SIZE(cdcnp_cfg))
        {
            (*cdcnp_model) = cdcnp_model_t;

            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_model_search: "
                                                  "ssd disk size %ld => np model %u, "
                                                  "where page size %u, item size %u\n",
                                                  ssd_disk_size, (*cdcnp_model),
                                                  (uint32_t)(1 << CDCPGB_PAGE_SIZE_NBITS),
                                                  (uint32_t)(1 << CDCNP_ITEM_SIZE_NBITS));
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cdcnp_inode_init(CDCNP_INODE *cdcnp_inode)
{
    CDCNP_INODE_DISK_NO(cdcnp_inode)    = CDCPGRB_ERR_POS;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = CDCPGRB_ERR_POS;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = CDCPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cdcnp_inode_clean(CDCNP_INODE *cdcnp_inode)
{
    CDCNP_INODE_DISK_NO(cdcnp_inode)    = CDCPGRB_ERR_POS;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = CDCPGRB_ERR_POS;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = CDCPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cdcnp_inode_clone(const CDCNP_INODE *cdcnp_inode_src, CDCNP_INODE *cdcnp_inode_des)
{
    CDCNP_INODE_DISK_NO(cdcnp_inode_des)    = CDCNP_INODE_DISK_NO(cdcnp_inode_src);
    CDCNP_INODE_BLOCK_NO(cdcnp_inode_des)   = CDCNP_INODE_BLOCK_NO(cdcnp_inode_src);
    CDCNP_INODE_PAGE_NO(cdcnp_inode_des)    = CDCNP_INODE_PAGE_NO(cdcnp_inode_src);

    return (EC_TRUE);
}

void cdcnp_inode_print(LOG *log, const CDCNP_INODE *cdcnp_inode)
{
    sys_print(log, "(disk %u, block %u, page %u)\n",
                    CDCNP_INODE_DISK_NO(cdcnp_inode),
                    CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                    CDCNP_INODE_PAGE_NO(cdcnp_inode)
                    );
    return;
}

void cdcnp_inode_log(LOG *log, const CDCNP_INODE *cdcnp_inode)
{
    sys_print(log, "(disk %u, block %u, page %u)\n",
                    CDCNP_INODE_DISK_NO(cdcnp_inode),
                    CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                    CDCNP_INODE_PAGE_NO(cdcnp_inode)
                    );
    return;
}

CDCNP_FNODE *cdcnp_fnode_new()
{
    CDCNP_FNODE *cdcnp_fnode;
    alloc_static_mem(MM_CDCNP_FNODE, &cdcnp_fnode, LOC_CDCNP_0001);
    if(NULL_PTR != cdcnp_fnode)
    {
        cdcnp_fnode_init(cdcnp_fnode);
    }
    return (cdcnp_fnode);
}

CDCNP_FNODE *cdcnp_fnode_make(const CDCNP_FNODE *cdcnp_fnode_src)
{
    CDCNP_FNODE *cdcnp_fnode_des;
    alloc_static_mem(MM_CDCNP_FNODE, &cdcnp_fnode_des, LOC_CDCNP_0002);
    if(NULL_PTR != cdcnp_fnode_des)
    {
        cdcnp_fnode_clone(cdcnp_fnode_src, cdcnp_fnode_des);
    }
    return (cdcnp_fnode_des);
}

EC_BOOL cdcnp_fnode_init(CDCNP_FNODE *cdcnp_fnode)
{
    uint16_t pos;

    CDCNP_FNODE_PAGENUM(cdcnp_fnode)            = 0;
    CDCNP_FNODE_REPNUM(cdcnp_fnode)             = 0;

    for(pos = 0; pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_init(CDCNP_FNODE_INODE(cdcnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_clean(CDCNP_FNODE *cdcnp_fnode)
{
    uint16_t pos;

    CDCNP_FNODE_PAGENUM(cdcnp_fnode)            = 0;
    CDCNP_FNODE_REPNUM(cdcnp_fnode)             = 0;

    for(pos = 0; pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_clean(CDCNP_FNODE_INODE(cdcnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_free(CDCNP_FNODE *cdcnp_fnode)
{
    if(NULL_PTR != cdcnp_fnode)
    {
        cdcnp_fnode_clean(cdcnp_fnode);
        free_static_mem(MM_CDCNP_FNODE, cdcnp_fnode, LOC_CDCNP_0003);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_clone(const CDCNP_FNODE *cdcnp_fnode_src, CDCNP_FNODE *cdcnp_fnode_des)
{
    uint16_t pos;

    CDCNP_FNODE_PAGENUM(cdcnp_fnode_des)            = CDCNP_FNODE_PAGENUM(cdcnp_fnode_src);
    CDCNP_FNODE_REPNUM(cdcnp_fnode_des)             = CDCNP_FNODE_REPNUM(cdcnp_fnode_src);

    for(pos = 0; pos < CDCNP_FNODE_REPNUM(cdcnp_fnode_src) && pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_clone(CDCNP_FNODE_INODE(cdcnp_fnode_src, pos), CDCNP_FNODE_INODE(cdcnp_fnode_des, pos));
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_import(const CDCNP_FNODE *cdcnp_fnode_src, CDCNP_FNODE *cdcnp_fnode_des)
{
    uint16_t src_pos;
    uint16_t des_pos;

    for(src_pos = 0, des_pos = 0; src_pos < CDCNP_FNODE_REPNUM(cdcnp_fnode_src) && src_pos < CDCNP_FILE_REPLICA_MAX_NUM; src_pos ++)
    {
        CDCNP_INODE *cdcnp_inode_src;

        cdcnp_inode_src = (CDCNP_INODE *)CDCNP_FNODE_INODE(cdcnp_fnode_src, src_pos);
        if(CDCPGRB_ERR_POS != CDCNP_INODE_DISK_NO(cdcnp_inode_src)
        && CDCPGRB_ERR_POS != CDCNP_INODE_BLOCK_NO(cdcnp_inode_src)
        && CDCPGRB_ERR_POS != CDCNP_INODE_PAGE_NO(cdcnp_inode_src)
        )
        {
            CDCNP_INODE *cdcnp_inode_des;

            cdcnp_inode_des = CDCNP_FNODE_INODE(cdcnp_fnode_des, des_pos);
            if(cdcnp_inode_src != cdcnp_inode_des)
            {
                cdcnp_inode_clone(cdcnp_inode_src, cdcnp_inode_des);
            }

            des_pos ++;
        }
    }

    CDCNP_FNODE_PAGENUM(cdcnp_fnode_des) = CDCNP_FNODE_PAGENUM(cdcnp_fnode_src);
    CDCNP_FNODE_REPNUM(cdcnp_fnode_des)  = des_pos;

    return (EC_TRUE);
}

void cdcnp_fnode_print(LOG *log, const CDCNP_FNODE *cdcnp_fnode)
{
    uint16_t pos;

    sys_log(log, "cdcnp_fnode %p: page num %u, replica num %u, hash %x\n",
                 cdcnp_fnode,
                 CDCNP_FNODE_PAGENUM(cdcnp_fnode),
                 CDCNP_FNODE_REPNUM(cdcnp_fnode)
                 );

    for(pos = 0; pos < CDCNP_FNODE_REPNUM(cdcnp_fnode) && pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_print(log, CDCNP_FNODE_INODE(cdcnp_fnode, pos));
    }
    return;
}

void cdcnp_fnode_log(LOG *log, const CDCNP_FNODE *cdcnp_fnode)
{
    uint16_t pos;

    sys_print_no_lock(log, "page num %u, replica %u\n",
                           CDCNP_FNODE_PAGENUM(cdcnp_fnode),
                           CDCNP_FNODE_REPNUM(cdcnp_fnode)
                           );

    for(pos = 0; pos < CDCNP_FNODE_REPNUM(cdcnp_fnode) && pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_log(log, CDCNP_FNODE_INODE(cdcnp_fnode, pos));
    }
    sys_print_no_lock(log, "\n");

    return;
}

CDCNP_DNODE *cdcnp_dnode_new()
{
    CDCNP_DNODE *cdcnp_dnode;

    alloc_static_mem(MM_CDCNP_DNODE, &cdcnp_dnode, LOC_CDCNP_0004);
    if(NULL_PTR != cdcnp_dnode)
    {
        cdcnp_dnode_init(cdcnp_dnode);
    }
    return (cdcnp_dnode);

}

EC_BOOL cdcnp_dnode_init(CDCNP_DNODE *cdcnp_dnode)
{
    CDCNP_DNODE_FILE_NUM(cdcnp_dnode) = 0;
    CDCNP_DNODE_ROOT_POS(cdcnp_dnode) = CDCNPRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cdcnp_dnode_clean(CDCNP_DNODE *cdcnp_dnode)
{
    CDCNP_DNODE_FILE_NUM(cdcnp_dnode) = 0;
    CDCNP_DNODE_ROOT_POS(cdcnp_dnode) = CDCNPRB_ERR_POS;

    return (EC_TRUE);
}

EC_BOOL cdcnp_dnode_free(CDCNP_DNODE *cdcnp_dnode)
{
    if(NULL_PTR != cdcnp_dnode)
    {
        cdcnp_dnode_clean(cdcnp_dnode);
        free_static_mem(MM_CDCNP_DNODE, cdcnp_dnode, LOC_CDCNP_0005);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_dnode_clone(const CDCNP_DNODE *cdcnp_dnode_src, CDCNP_DNODE *cdcnp_dnode_des)
{
    CDCNP_DNODE_FILE_NUM(cdcnp_dnode_des) = CDCNP_DNODE_FILE_NUM(cdcnp_dnode_src);
    CDCNP_DNODE_ROOT_POS(cdcnp_dnode_des) = CDCNP_DNODE_ROOT_POS(cdcnp_dnode_src);
    return (EC_TRUE);
}

CDCNP_KEY *cdcnp_key_new()
{
    CDCNP_KEY *cdcnp_key;

    alloc_static_mem(MM_CDCNP_KEY, &cdcnp_key, LOC_CDCNP_0006);
    if(NULL_PTR != cdcnp_key)
    {
        cdcnp_key_init(cdcnp_key);
    }
    return (cdcnp_key);
}

EC_BOOL cdcnp_key_init(CDCNP_KEY *cdcnp_key)
{
    CDCNP_KEY_S_PAGE(cdcnp_key) = CDCNP_KEY_S_PAGE_ERR;
    CDCNP_KEY_E_PAGE(cdcnp_key) = CDCNP_KEY_S_PAGE_ERR;

    return (EC_TRUE);
}

EC_BOOL cdcnp_key_clean(CDCNP_KEY *cdcnp_key)
{
    CDCNP_KEY_S_PAGE(cdcnp_key) = CDCNP_KEY_S_PAGE_ERR;
    CDCNP_KEY_E_PAGE(cdcnp_key) = CDCNP_KEY_S_PAGE_ERR;

    return (EC_TRUE);
}

EC_BOOL cdcnp_key_clone(const CDCNP_KEY *cdcnp_key_src, CDCNP_KEY *cdcnp_key_des)
{
    if(NULL_PTR == cdcnp_key_src)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_key_clone: cdcnp_key_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdcnp_key_des)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_key_clone: cdcnp_key_des is null\n");
        return (EC_FALSE);
    }

    CDCNP_KEY_S_PAGE(cdcnp_key_des) = CDCNP_KEY_S_PAGE(cdcnp_key_src);
    CDCNP_KEY_E_PAGE(cdcnp_key_des) = CDCNP_KEY_E_PAGE(cdcnp_key_src);

    return (EC_TRUE);
}

EC_BOOL cdcnp_key_cmp(const CDCNP_KEY *cdcnp_key_1st, const CDCNP_KEY *cdcnp_key_2nd)
{
    if(CDCNP_KEY_S_PAGE(cdcnp_key_1st) != CDCNP_KEY_S_PAGE(cdcnp_key_2nd))
    {
        return (EC_FALSE);
    }

    if(CDCNP_KEY_E_PAGE(cdcnp_key_1st) != CDCNP_KEY_E_PAGE(cdcnp_key_2nd))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_key_free(CDCNP_KEY *cdcnp_key)
{
    if(NULL_PTR != cdcnp_key)
    {
        cdcnp_key_clean(cdcnp_key);
        free_static_mem(MM_CDCNP_KEY, cdcnp_key, LOC_CDCNP_0007);
    }
    return (EC_TRUE);
}

void cdcnp_key_print(LOG *log, const CDCNP_KEY *cdcnp_key)
{
    sys_log(log, "key: [%u, %u)\n",
                 CDCNP_KEY_S_PAGE(cdcnp_key),
                 CDCNP_KEY_E_PAGE(cdcnp_key));

    return;
}

EC_BOOL cdcnp_key_is_valid(const CDCNP_KEY *cdcnp_key)
{
    if(CDCNP_KEY_S_PAGE(cdcnp_key) < CDCNP_KEY_E_PAGE(cdcnp_key))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

uint32_t cdcnp_key_hash(const CDCNP_KEY *cdcnp_key)
{
     uint32_t hash = 1315423911;

     hash ^= ((hash << 5) + CDCNP_KEY_S_PAGE(cdcnp_key) + (hash >> 2));
     hash ^= ((hash << 5) + CDCNP_KEY_E_PAGE(cdcnp_key) + (hash >> 2));

     return (hash & 0x7FFFFFFF);
}

CDCNP_ITEM *cdcnp_item_new()
{
    CDCNP_ITEM *cdcnp_item;

    alloc_static_mem(MM_CDCNP_ITEM, &cdcnp_item, LOC_CDCNP_0008);
    if(NULL_PTR != cdcnp_item)
    {
        cdcnp_item_init(cdcnp_item);
    }
    return (cdcnp_item);
}

EC_BOOL cdcnp_item_init(CDCNP_ITEM *cdcnp_item)
{
    CDCNP_ITEM_DIR_FLAG(cdcnp_item)             = CDCNP_ITEM_FILE_IS_ERR;
    CDCNP_ITEM_USED_FLAG(cdcnp_item)            = CDCNP_ITEM_IS_NOT_USED;
    CDCNP_ITEM_PARENT_POS(cdcnp_item)           = CDCNPRB_ERR_POS;/*fix*/

    CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item)      = BIT_FALSE;
    CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item)      = BIT_FALSE;
    CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item)   = BIT_FALSE;
    CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)    = BIT_FALSE;

    CDCNP_ITEM_DEG_TIMES(cdcnp_item)            = 0;

    cdcnp_fnode_init(CDCNP_ITEM_FNODE(cdcnp_item));

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cdcnp_item_clean(CDCNP_ITEM *cdcnp_item)
{
    CDCNP_ITEM_DIR_FLAG(cdcnp_item)             = CDCNP_ITEM_FILE_IS_ERR;
    CDCNP_ITEM_USED_FLAG(cdcnp_item)            = CDCNP_ITEM_IS_NOT_USED;
    CDCNP_ITEM_PARENT_POS(cdcnp_item)           = CDCNPRB_ERR_POS;/*fix bug: break pointer to parent*/

    CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item)      = BIT_FALSE;
    CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item)      = BIT_FALSE;
    CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item)   = BIT_FALSE;
    CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)    = BIT_FALSE;

    CDCNP_ITEM_DEG_TIMES(cdcnp_item)            = 0;
    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cdcnp_item_clone(const CDCNP_ITEM *cdcnp_item_src, CDCNP_ITEM *cdcnp_item_des)
{
    if(NULL_PTR == cdcnp_item_src)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_item_clone: cdcnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdcnp_item_des)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_item_clone: cdcnp_item_des is null\n");
        return (EC_FALSE);
    }

    CDCNP_ITEM_USED_FLAG(cdcnp_item_des)            = CDCNP_ITEM_USED_FLAG(cdcnp_item_src);
    CDCNP_ITEM_DIR_FLAG(cdcnp_item_des)             = CDCNP_ITEM_DIR_FLAG(cdcnp_item_src);
    CDCNP_ITEM_PARENT_POS(cdcnp_item_des)           = CDCNP_ITEM_PARENT_POS(cdcnp_item_src);

    CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item_des)      = CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item_src);
    CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item_des)      = CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item_src);
    CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item_des)   = CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item_src);
    CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item_des)    = CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item_src);

    CDCNP_ITEM_DEG_TIMES(cdcnp_item_des)            = CDCNP_ITEM_DEG_TIMES(cdcnp_item_src);

    cdcnplru_node_clone(CDCNP_ITEM_LRU_NODE(cdcnp_item_src), CDCNP_ITEM_LRU_NODE(cdcnp_item_des));
    cdcnpdel_node_clone(CDCNP_ITEM_DEL_NODE(cdcnp_item_src), CDCNP_ITEM_DEL_NODE(cdcnp_item_des));
    cdcnpdeg_node_clone(CDCNP_ITEM_DEG_NODE(cdcnp_item_src), CDCNP_ITEM_DEG_NODE(cdcnp_item_des));

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item_src))
    {
        cdcnp_fnode_clone(CDCNP_ITEM_FNODE(cdcnp_item_src), CDCNP_ITEM_FNODE(cdcnp_item_des));
    }
    else if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item_src))
    {
        cdcnp_dnode_clone(CDCNP_ITEM_DNODE(cdcnp_item_src), CDCNP_ITEM_DNODE(cdcnp_item_des));
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_item_free(CDCNP_ITEM *cdcnp_item)
{
    if(NULL_PTR != cdcnp_item)
    {
        cdcnp_item_clean(cdcnp_item);
        free_static_mem(MM_CDCNP_ITEM, cdcnp_item, LOC_CDCNP_0009);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_item_set_key(CDCNP_ITEM *cdcnp_item, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ITEM_S_PAGE(cdcnp_item) = CDCNP_KEY_S_PAGE(cdcnp_key);
    CDCNP_ITEM_E_PAGE(cdcnp_item) = CDCNP_KEY_E_PAGE(cdcnp_key);

    return (EC_TRUE);
}

STATIC_CAST static const char *__cdcnp_item_dir_flag_str(const uint32_t dir_flag)
{
    switch(dir_flag)
    {
        case CDCNP_ITEM_FILE_IS_DIR:
            return (const char *)"D";
        case CDCNP_ITEM_FILE_IS_REG:
            return (const char *)"F";
    }

    return (const char *)"UFO";
}

/*without key print*/
void cdcnp_item_print(LOG *log, const CDCNP_ITEM *cdcnp_item)
{
    uint16_t pos;

    sys_print(log, "cdcnp_item %p: flag 0x%x [%s], stat %u, "
                   "ssd locked flag %u, "
                   "sata dirty flag %u, sata flushing flag %u, sata flushed flag %u, "
                   "deg times %u, "
                   "parent %u, lru node (%u, %u), del node (%u, %u), deg node (%u, %u)\n",
                    cdcnp_item,
                    CDCNP_ITEM_DIR_FLAG(cdcnp_item), __cdcnp_item_dir_flag_str(CDCNP_ITEM_DIR_FLAG(cdcnp_item)),
                    CDCNP_ITEM_USED_FLAG(cdcnp_item),
                    CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item),
                    CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item),
                    CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item),
                    CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item),
                    CDCNP_ITEM_DEG_TIMES(cdcnp_item),
                    CDCNP_ITEM_PARENT_POS(cdcnp_item),
                    CDCNPLRU_NODE_PREV_POS(CDCNP_ITEM_LRU_NODE(cdcnp_item)),
                    CDCNPLRU_NODE_NEXT_POS(CDCNP_ITEM_LRU_NODE(cdcnp_item)),
                    CDCNPDEL_NODE_PREV_POS(CDCNP_ITEM_DEL_NODE(cdcnp_item)),
                    CDCNPDEL_NODE_NEXT_POS(CDCNP_ITEM_DEL_NODE(cdcnp_item)),
                    CDCNPDEG_NODE_PREV_POS(CDCNP_ITEM_DEG_NODE(cdcnp_item)),
                    CDCNPDEG_NODE_NEXT_POS(CDCNP_ITEM_DEG_NODE(cdcnp_item))
                    );

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;

        cdcnp_fnode = (CDCNP_FNODE *)CDCNP_ITEM_FNODE(cdcnp_item);
        sys_log(log, "page num %u, replica num %u\n",
                        CDCNP_FNODE_PAGENUM(cdcnp_fnode),
                        CDCNP_FNODE_REPNUM(cdcnp_fnode)
                        );
        sys_log(log, "inode:\n");
        for(pos = 0; pos < CDCNP_FNODE_REPNUM(cdcnp_fnode) && pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            CDCNP_INODE *cdcnp_inode;

            cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, pos);
            cdcnp_inode_print(log, cdcnp_inode);
            //sys_print(log, "\n");
        }
    }

    if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_DNODE *cdcnp_dnode;

        cdcnp_dnode = (CDCNP_DNODE *)CDCNP_ITEM_DNODE(cdcnp_item);
        sys_log(log, "file num: %u, dir root pos: %u\n",
                     CDCNP_DNODE_FILE_NUM(cdcnp_dnode),
                     CDCNP_DNODE_ROOT_POS(cdcnp_dnode));
    }

    return;
}

void cdcnp_item_and_key_print(LOG *log, const CDCNP_ITEM *cdcnp_item)
{
    uint16_t pos;

    sys_print(log, "cdcnp_item %p: flag 0x%x [%s], stat %u, "
                   "ssd locked flag %u, "
                   "sata dirty flag %u, sata flushing flag %u, sata flushed flag %u, deg times %u, ",
                   cdcnp_item,
                   CDCNP_ITEM_DIR_FLAG(cdcnp_item), __cdcnp_item_dir_flag_str(CDCNP_ITEM_DIR_FLAG(cdcnp_item)),
                   CDCNP_ITEM_USED_FLAG(cdcnp_item),
                   CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item),
                   CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item),
                   CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item),
                   CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item),
                   CDCNP_ITEM_DEG_TIMES(cdcnp_item));

    sys_log(log, "key: [%u, %u)\n",
                 CDCNP_ITEM_S_PAGE(cdcnp_item),
                 CDCNP_ITEM_E_PAGE(cdcnp_item));

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;

        cdcnp_fnode = (CDCNP_FNODE *)CDCNP_ITEM_FNODE(cdcnp_item);
        sys_log(log, "page num %u, replica num %u\n",
                        CDCNP_FNODE_PAGENUM(cdcnp_fnode),
                        CDCNP_FNODE_REPNUM(cdcnp_fnode)
                        );
        for(pos = 0; pos < CDCNP_FNODE_REPNUM(cdcnp_fnode) && pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            CDCNP_INODE *cdcnp_inode;

            cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, pos);
            cdcnp_inode_print(log, cdcnp_inode);
            //sys_print(log, "\n");
        }
    }

    if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_DNODE *cdcnp_dnode;

        cdcnp_dnode = (CDCNP_DNODE *)CDCNP_ITEM_DNODE(cdcnp_item);
        sys_log(log, "file num: %u, dir root pos: %u\n",
                     CDCNP_DNODE_FILE_NUM(cdcnp_dnode),
                     CDCNP_DNODE_ROOT_POS(cdcnp_dnode));
    }

    return;
}

EC_BOOL cdcnp_item_is(const CDCNP_ITEM *cdcnp_item, const CDCNP_KEY *cdcnp_key)
{
    if(CDCNP_KEY_S_PAGE(cdcnp_key) != CDCNP_ITEM_S_PAGE(cdcnp_item))
    {
        return (EC_FALSE);
    }

    if(CDCNP_KEY_E_PAGE(cdcnp_key) != CDCNP_ITEM_E_PAGE(cdcnp_item))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CDCNP_ITEM *cdcnp_item_parent(const CDCNP *cdcnp, const CDCNP_ITEM *cdcnp_item)
{
    uint32_t parent_pos;

    parent_pos = CDCNPRB_NODE_PARENT_POS(CDCNP_ITEM_RB_NODE(cdcnp_item));
    if(CDCNPRB_ERR_POS == parent_pos)
    {
        return (NULL_PTR);
    }

    return cdcnp_fetch(cdcnp, parent_pos);
}

CDCNP_ITEM *cdcnp_item_left(const CDCNP *cdcnp, const CDCNP_ITEM *cdcnp_item)
{
    uint32_t left_pos;

    left_pos = CDCNPRB_NODE_LEFT_POS(CDCNP_ITEM_RB_NODE(cdcnp_item));
    if(CDCNPRB_ERR_POS == left_pos)
    {
        return (NULL_PTR);
    }

    return cdcnp_fetch(cdcnp, left_pos);
}

CDCNP_ITEM *cdcnp_item_right(const CDCNP *cdcnp, const CDCNP_ITEM *cdcnp_item)
{
    uint32_t right_offset;

    right_offset = CDCNPRB_NODE_RIGHT_POS(CDCNP_ITEM_RB_NODE(cdcnp_item));
    if(CDCNPRB_ERR_POS == right_offset)
    {
        return (NULL_PTR);
    }

    return cdcnp_fetch(cdcnp, right_offset);
}

EC_BOOL cdcnp_bitmap_init(CDCNP_BITMAP *cdcnp_bitmap, const uint32_t nbits)
{
    uint32_t nbytes;

    nbytes = ((nbits + 7)/8);

    if(CDCNP_BITMAP_SIZE_NBYTES <= ((UINT32)nbytes))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_init: "
                                              "nbits %u => nbytes %u > %ld overflow!\n",
                                              nbits, nbytes, CDCNP_BITMAP_SIZE_NBYTES);
        return (EC_FALSE);
    }

    BSET((void *)CDCNP_BITMAP_DATA(cdcnp_bitmap), 0, nbytes);
    CDCNP_BITMAP_SIZE(cdcnp_bitmap) = nbytes;

    return (EC_TRUE);
}

EC_BOOL cdcnp_bitmap_clean(CDCNP_BITMAP *cdcnp_bitmap)
{
    if(NULL_PTR != cdcnp_bitmap)
    {
        uint32_t    size;

        size = CDCNP_BITMAP_SIZE(cdcnp_bitmap);

        BSET((void *)CDCNP_BITMAP_DATA(cdcnp_bitmap), 0, size);
        CDCNP_BITMAP_SIZE(cdcnp_bitmap) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_bitmap_set(CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCNP_BITMAP_SIZE(cdcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_set: overflow bit_pos %u > %u\n",
                        bit_pos, CDCNP_BITMAP_SIZE(cdcnp_bitmap));
        return (EC_FALSE);
    }

    CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ] |= (uint8_t)(1 << bit_nth);

    return (EC_TRUE);
}

EC_BOOL cdcnp_bitmap_clear(CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCNP_BITMAP_SIZE(cdcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_clear: overflow bit_pos %u > %u\n",
                        bit_pos, CDCNP_BITMAP_SIZE(cdcnp_bitmap));
        return (EC_FALSE);
    }

    if(0 == (CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_clear: it_pos %u was NOT set!\n",
                        bit_pos);
        return (EC_FALSE);
    }

    CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ] &= (uint8_t)(~(1 << bit_nth));

    return (EC_TRUE);
}

EC_BOOL cdcnp_bitmap_get(const CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos, uint8_t *bit_val)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCNP_BITMAP_SIZE(cdcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_get: overflow bit_pos %u > %u\n",
                        bit_pos, CDCNP_BITMAP_SIZE(cdcnp_bitmap));
        return (EC_FALSE);
    }

    if(0 == (CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_bitmap_is(const CDCNP_BITMAP *cdcnp_bitmap, const uint32_t bit_pos, const uint8_t bit_val)
{
    uint32_t   byte_nth;
    uint32_t   bit_nth;
    uint8_t    e;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CDCNP_BITMAP_SIZE(cdcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_is: overflow bit_pos %u > %u\n",
                        bit_pos, CDCNP_BITMAP_SIZE(cdcnp_bitmap));
        return (EC_FALSE);
    }

    e = (CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ] & (uint8_t)(1 << bit_nth));

    if(0 == e && 0 == bit_val)
    {
        return (EC_TRUE);
    }

    if(0 < e && 1 == bit_val)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void cdcnp_bitmap_print(LOG *log, const CDCNP_BITMAP *cdcnp_bitmap)
{
    uint32_t   byte_nth;

    for(byte_nth = 0; byte_nth < CDCNP_BITMAP_SIZE(cdcnp_bitmap); byte_nth ++)
    {
        uint32_t bit_nth;
        uint8_t  bit_val;
        uint8_t  byte_val;

        byte_val = CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ];
        if(0 == byte_val)/*ignore*/
        {
            continue;
        }

        sys_print(log, "[%8d B] ", byte_nth);

        /*print bits from Lo to Hi*/
        for(bit_nth = 0; bit_nth < BYTESIZE; bit_nth ++, byte_val >>= 1)
        {
            bit_val = (byte_val & 1);
            sys_print(log, "%u ", bit_val);
        }
        sys_print(log, "\n");
    }
    return;
}

/*count the num of bit 1*/
uint32_t cdcnp_bitmap_count_bits(const CDCNP_BITMAP *cdcnp_bitmap, const uint32_t s_bit_pos, const uint32_t e_bit_pos)
{
    uint32_t   s_byte_nth;
    uint32_t   e_byte_nth;

    uint32_t   byte_nth;
    uint32_t   bits_count;

    s_byte_nth     = (s_bit_pos & (~7));
    e_byte_nth     = (e_bit_pos + 7) & (~7);
    bits_count     = 0;

    for(byte_nth = s_byte_nth; byte_nth < e_byte_nth; byte_nth ++)
    {
        bits_count += g_nbits_per_byte[ CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ] ];
    }
    return (bits_count);
}

CDCNP_HEADER *cdcnp_header_new(const uint32_t np_id, const UINT32 fsize, const uint8_t np_model)
{
    CDCNP_HEADER *cdcnp_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    node_max_num = 0;

    cdcnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CDCNP_ITEM);

    if(0 == node_max_num)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_header_new: "
                                              "np model %u => node max num = %u is invalid\n",
                                              np_model, node_max_num);
        return (NULL_PTR);
    }

    cdcnp_header = (CDCNP_HEADER *)c_memalign_new(fsize, CDCPGB_PAGE_SIZE_NBYTES);
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_header_new: "
                                              "new header with %ld bytes for np %u failed\n",
                                              fsize, np_id);
        return (NULL_PTR);
    }

    CDCNP_HEADER_NP_ID(cdcnp_header)        = np_id;
    CDCNP_HEADER_MODEL(cdcnp_header)        = np_model;
    CDCNP_HEADER_DEG_NODE_NUM(cdcnp_header) = 0;

    /*init RB Nodes*/
    cdcnprb_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init LRU nodes*/
    cdcnplru_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cdcnpdel_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init DEG nodes*/
    cdcnpdeg_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    return (cdcnp_header);
}

CDCNP_HEADER *cdcnp_header_free(CDCNP_HEADER *cdcnp_header)
{
    if(NULL_PTR != cdcnp_header)
    {
        c_memalign_free(cdcnp_header);
    }

    /*cdcnp_header cannot be accessed again*/
    return (NULL_PTR);
}

CDCNP_HEADER *cdcnp_header_close(CDCNP_HEADER *cdcnp_header)
{
    /*do nothing*/

    /*cdcnp_header cannot be accessed again*/
    return (NULL_PTR);
}

EC_BOOL cdcnp_header_init(CDCNP_HEADER *cdcnp_header, const uint32_t np_id, const uint8_t model)
{
    CDCNP_HEADER_NP_ID(cdcnp_header)         = np_id;
    CDCNP_HEADER_MODEL(cdcnp_header)         = model;

    /*do nothing on lru list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CDCNPRB_POOL pool*/

    return (EC_TRUE);
}

EC_BOOL cdcnp_header_clean(CDCNP_HEADER *cdcnp_header)
{
    CDCNP_HEADER_NP_ID(cdcnp_header)              = CDCNP_ERR_ID;
    CDCNP_HEADER_MODEL(cdcnp_header)              = CDCNP_ERR_MODEL;

    /*do nothing on lru list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CDCNPRB_POOL pool*/

    return (EC_TRUE);
}

REAL cdcnp_header_used_ratio(const CDCNP_HEADER *cdcnp_header)
{
    if(0 < CDCNP_HEADER_ITEMS_MAX_NUM(cdcnp_header))
    {
        REAL node_used_num;
        REAL node_max_num;

        node_used_num = (CDCNP_HEADER_ITEMS_USED_NUM(cdcnp_header) + 0.0);
        node_max_num  = (CDCNP_HEADER_ITEMS_MAX_NUM(cdcnp_header)  + 0.0);

        return (node_used_num / node_max_num);
    }

    return (0.0);
}

REAL cdcnp_header_deg_ratio(const CDCNP_HEADER *cdcnp_header)
{
    if(0 < CDCNP_HEADER_ITEMS_USED_NUM(cdcnp_header))
    {
        REAL node_used_num;
        REAL deg_node_num;

        node_used_num = (CDCNP_HEADER_ITEMS_USED_NUM(cdcnp_header) + 0.0);
        deg_node_num  = (CDCNP_HEADER_DEG_NODE_NUM(cdcnp_header)  + 0.0);

        return (deg_node_num / node_used_num);
    }

    return (0.0);
}

CDCNP *cdcnp_new()
{
    CDCNP *cdcnp;

    alloc_static_mem(MM_CDCNP, &cdcnp, LOC_CDCNP_0010);
    if(NULL_PTR != cdcnp)
    {
        cdcnp_init(cdcnp);
    }
    return (cdcnp);
}

EC_BOOL cdcnp_init(CDCNP *cdcnp)
{
    CDCNP_RDONLY_FLAG(cdcnp)     = BIT_FALSE;
    CDCNP_DONTDUMP_FLAG(cdcnp)   = BIT_FALSE;
    CDCNP_FD(cdcnp)              = ERR_FD;
    CDCNP_S_OFFSET(cdcnp)        = CDCNP_OFFSET_ERR;
    CDCNP_E_OFFSET(cdcnp)        = CDCNP_OFFSET_ERR;
    CDCNP_FNAME(cdcnp)           = NULL_PTR;
    CDCNP_DEL_SIZE(cdcnp)        = 0;
    CDCNP_RECYCLE_SIZE(cdcnp)    = 0;
    CDCNP_BITMAP(cdcnp)          = NULL_PTR;
    CDCNP_HDR(cdcnp)             = NULL_PTR;
    CDCNP_LRU_LIST(cdcnp)        = NULL_PTR;
    CDCNP_DEL_LIST(cdcnp)        = NULL_PTR;
    CDCNP_DEG_LIST(cdcnp)        = NULL_PTR;

    cdcnp_init_degrade_callback(cdcnp);

    return (EC_TRUE);
}

EC_BOOL cdcnp_clean(CDCNP *cdcnp)
{
    if(NULL_PTR != CDCNP_HDR(cdcnp))
    {
        cdcnp_header_free(CDCNP_HDR(cdcnp));
        CDCNP_HDR(cdcnp) = NULL_PTR;
    }
    CDCNP_BITMAP(cdcnp)          = NULL_PTR;

    CDCNP_RDONLY_FLAG(cdcnp)     = BIT_FALSE;
    CDCNP_DONTDUMP_FLAG(cdcnp)   = BIT_FALSE;
    CDCNP_FD(cdcnp)              = ERR_FD;
    CDCNP_S_OFFSET(cdcnp)        = CDCNP_OFFSET_ERR;
    CDCNP_E_OFFSET(cdcnp)        = CDCNP_OFFSET_ERR;

    CDCNP_ASSERT(NULL_PTR == CDCNP_FNAME(cdcnp));

    CDCNP_DEL_SIZE(cdcnp)        = 0;
    CDCNP_RECYCLE_SIZE(cdcnp)    = 0;

    CDCNP_LRU_LIST(cdcnp)        = NULL_PTR;
    CDCNP_DEL_LIST(cdcnp)        = NULL_PTR;
    CDCNP_DEG_LIST(cdcnp)        = NULL_PTR;

    cdcnp_clean_degrade_callback(cdcnp);

    return (EC_TRUE);
}

EC_BOOL cdcnp_free(CDCNP *cdcnp)
{
    if(NULL_PTR != cdcnp)
    {
        cdcnp_clean(cdcnp);
        free_static_mem(MM_CDCNP, cdcnp, LOC_CDCNP_0011);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_close(CDCNP *cdcnp)
{
    if(NULL_PTR != cdcnp)
    {
        if(NULL_PTR != CDCNP_HDR(cdcnp))
        {
            cdcnp_header_close(CDCNP_HDR(cdcnp));
            CDCNP_HDR(cdcnp) = NULL_PTR;
        }

        return cdcnp_free(cdcnp);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_set_read_only(CDCNP *cdcnp)
{
    if(BIT_TRUE == CDCNP_RDONLY_FLAG(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_set_read_only: "
                                              "cdcnp was already set already read-only\n");

        return (EC_FALSE);
    }

    CDCNP_RDONLY_FLAG(cdcnp) = BIT_TRUE;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_set_read_only: "
                                          "set cdcnp read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdcnp_unset_read_only(CDCNP *cdcnp)
{
    if(BIT_FALSE == CDCNP_RDONLY_FLAG(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_unset_read_only: "
                                              "cdcnp was not set read-only\n");

        return (EC_FALSE);
    }

    CDCNP_RDONLY_FLAG(cdcnp) = BIT_FALSE;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_unset_read_only: "
                                          "unset cdcnp read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdcnp_is_read_only(const CDCNP *cdcnp)
{
    if(BIT_FALSE == CDCNP_RDONLY_FLAG(cdcnp))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_set_dontdump(CDCNP *cdcnp)
{
    if(BIT_TRUE == CDCNP_DONTDUMP_FLAG(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_set_dontdump: "
                                              "cdcnp was already set do-no-dump\n");

        return (EC_FALSE);
    }

    CDCNP_DONTDUMP_FLAG(cdcnp) = BIT_TRUE;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_set_dontdump: "
                                          "set cdcnp do-no-dump\n");

    return (EC_TRUE);
}

EC_BOOL cdcnp_unset_dontdump(CDCNP *cdcnp)
{
    if(BIT_FALSE == CDCNP_DONTDUMP_FLAG(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_unset_dontdump: "
                                              "cdcnp was not set do-no-dump\n");

        return (EC_FALSE);
    }

    CDCNP_DONTDUMP_FLAG(cdcnp) = BIT_FALSE;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_unset_dontdump: "
                                          "unset cdcnp do-no-dump\n");

    return (EC_TRUE);
}

EC_BOOL cdcnp_is_dontdump(const CDCNP *cdcnp)
{
    if(BIT_FALSE == CDCNP_DONTDUMP_FLAG(cdcnp))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_is_full(const CDCNP *cdcnp)
{
    CDCNPRB_POOL *pool;

    pool = CDCNP_ITEMS_POOL(cdcnp);
    return cdcnprb_pool_is_full(pool);
}

EC_BOOL cdcnp_lru_list_is_empty(const CDCNP *cdcnp)
{
    return cdcnplru_is_empty(CDCNP_LRU_LIST(cdcnp));
}

EC_BOOL cdcnp_del_list_is_empty(const CDCNP *cdcnp)
{
    return cdcnpdel_is_empty(CDCNP_DEL_LIST(cdcnp));
}

EC_BOOL cdcnp_deg_list_is_empty(const CDCNP *cdcnp)
{
    return cdcnpdeg_is_empty(CDCNP_DEG_LIST(cdcnp));
}

EC_BOOL cdcnp_reserve_key(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    UINT32      page_no;

    for(page_no = CDCNP_KEY_S_PAGE(cdcnp_key);
        page_no < CDCNP_KEY_E_PAGE(cdcnp_key);
        page_no ++)
    {
        cdcnp_bitmap_set(CDCNP_BITMAP(cdcnp), page_no);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_release_key(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    UINT32      page_no;

    for(page_no = CDCNP_KEY_S_PAGE(cdcnp_key);
        page_no < CDCNP_KEY_E_PAGE(cdcnp_key);
        page_no ++)
    {
        cdcnp_bitmap_clear(CDCNP_BITMAP(cdcnp), page_no);
    }

    return (EC_TRUE);
}

void cdcnp_header_print(LOG *log, const CDCNP *cdcnp)
{
    const CDCNP_HEADER *cdcnp_header;

    cdcnp_header = CDCNP_HDR(cdcnp);

    sys_log(log, "np %u, model %u, item max num %u, item used num %u, deg node num %u\n",
                CDCNP_HEADER_NP_ID(cdcnp_header),
                CDCNP_HEADER_MODEL(cdcnp_header),
                CDCNP_HEADER_ITEMS_MAX_NUM(cdcnp_header),
                CDCNP_HEADER_ITEMS_USED_NUM(cdcnp_header),
                CDCNP_HEADER_DEG_NODE_NUM(cdcnp_header)
        );

    cdcnprb_pool_print(log, CDCNP_HEADER_ITEMS_POOL(cdcnp_header));
    return;
}

void cdcnp_print(LOG *log, const CDCNP *cdcnp)
{
    sys_log(log, "cdcnp %p: np %u, fname %s, fd %d\n",
                 cdcnp,
                 CDCNP_ID(cdcnp),
                 CDCNP_FNAME(cdcnp),
                 CDCNP_FD(cdcnp));

    sys_log(log, "cdcnp %p: np %u, range [%ld, %ld), file size %ld, del size %llu, recycle size %llu\n",
                 cdcnp,
                 CDCNP_ID(cdcnp),
                 CDCNP_S_OFFSET(cdcnp),CDCNP_E_OFFSET(cdcnp),
                 CDCNP_E_OFFSET(cdcnp) - CDCNP_S_OFFSET(cdcnp),
                 CDCNP_DEL_SIZE(cdcnp),
                 CDCNP_RECYCLE_SIZE(cdcnp)
                 );

    sys_log(log, "cdcnp %p: header: \n", cdcnp);
    cdcnp_header_print(log, cdcnp);
    return;
}

void cdcnp_print_lru_list(LOG *log, const CDCNP *cdcnp)
{
    sys_log(log, "cdcnp_print_lru_list: cdcnp %p: lru list: \n", cdcnp);
    cdcnplru_list_print(log, cdcnp);
    return;
}

void cdcnp_print_del_list(LOG *log, const CDCNP *cdcnp)
{
    sys_log(log, "cdcnp_print_del_list: cdcnp %p: del list: \n", cdcnp);
    cdcnpdel_list_print(log, cdcnp);
    return;
}

void cdcnp_print_deg_list(LOG *log, const CDCNP *cdcnp)
{
    sys_log(log, "cdcnp_print_deg_list: cdcnp %p: deg list: \n", cdcnp);
    cdcnpdeg_list_print(log, cdcnp);
    return;
}

void cdcnp_print_bitmap(LOG *log, const CDCNP *cdcnp)
{
    sys_log(log, "cdcnp_print_del_list: cdcnp %p: bitmap: \n", cdcnp);
    cdcnp_bitmap_print(log, CDCNP_BITMAP(cdcnp));
    return;
}

CDCNP_ITEM *cdcnp_dnode_find(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, const CDCNP_KEY *cdcnp_key)
{
    const CDCNPRB_POOL *pool;
    uint32_t root_pos;
    uint32_t node_pos;

    pool     = CDCNP_ITEMS_POOL(cdcnp);
    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);

    node_pos = cdcnprb_tree_search_data(pool, root_pos, cdcnp_key);

    if(CDCNPRB_ERR_POS != node_pos)
    {
        const CDCNPRB_NODE *node;
        const CDCNP_ITEM   *item;

        node = CDCNPRB_POOL_NODE(pool, node_pos);
        item = CDCNP_RB_NODE_ITEM(node);

        return (CDCNP_ITEM *)(item);
    }

    return (NULL_PTR);
}

uint32_t cdcnp_dnode_search(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, const CDCNP_KEY *cdcnp_key)
{
    const CDCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CDCNP_ITEMS_POOL(cdcnp);
    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);

    return cdcnprb_tree_search_data(pool, root_pos, cdcnp_key);
}

void cdcnp_dnode_walk(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, void (*walker)(void *, const void *, const uint32_t), void *arg)
{
    const CDCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CDCNP_ITEMS_POOL(cdcnp);
    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);

    cdcnprb_inorder_walk(pool, root_pos, walker, arg, (const void *)cdcnp);
    return;
}

uint32_t cdcnp_dnode_insert(CDCNP *cdcnp, const uint32_t parent_pos, const CDCNP_KEY *cdcnp_key, const uint32_t dir_flag)
{
    uint32_t insert_offset;
    uint32_t root_pos;

    CDCNP_ITEM *cdcnp_item_parent;
    CDCNP_ITEM *cdcnp_item_insert;

    CDCNP_DNODE *cdcnp_dnode_parent;

    if(CDCNP_ITEM_FILE_IS_REG != dir_flag
    && CDCNP_ITEM_FILE_IS_DIR != dir_flag)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_dnode_insert: invalid input dir flag %x\n", dir_flag);
        return (CDCNPRB_ERR_POS);
    }

    if(EC_TRUE == cdcnp_is_full(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 5)(LOGSTDOUT, "error:cdcnp_dnode_insert: cdcnp is full\n");
        return (CDCNPRB_ERR_POS);
    }

    cdcnp_item_parent = cdcnp_fetch(cdcnp, parent_pos);/*must be dnode*/
    if(NULL_PTR == cdcnp_item_parent)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_dnode_insert: fetch parent item failed where parent offset %u\n", parent_pos);
        return (CDCNPRB_ERR_POS);
    }

    cdcnp_dnode_parent = CDCNP_ITEM_DNODE(cdcnp_item_parent);
    if(CDCNP_ITEM_FILE_IS_DIR != CDCNP_ITEM_DIR_FLAG(cdcnp_item_parent)
    || CDCNP_ITEM_IS_NOT_USED == CDCNP_ITEM_USED_FLAG(cdcnp_item_parent))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_dnode_insert: invalid dir flag %u or stat %u\n",
                            CDCNP_ITEM_DIR_FLAG(cdcnp_item_parent),
                            CDCNP_ITEM_USED_FLAG(cdcnp_item_parent));
        return (CDCNPRB_ERR_POS);
    }

    /*insert the item to parent and update parent*/
    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode_parent);

    //dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_dnode_insert: cdcnp %p, header %p, pool %p\n", cdcnp, CDCNP_HDR(cdcnp), CDCNP_ITEMS_POOL(cdcnp));

    if(EC_FALSE == cdcnprb_tree_insert_data(CDCNP_ITEMS_POOL(cdcnp), &root_pos, cdcnp_key, &insert_offset))
    {
        dbg_log(SEC_0129_CDCNP, 1)(LOGSTDOUT, "warn:cdcnp_dnode_insert: found duplicate rb node with root %u at node %u\n", root_pos, insert_offset);
        return (insert_offset);
    }
    cdcnp_item_insert = cdcnp_fetch(cdcnp, insert_offset);

    /*fill in cdcnp_item_insert*/
    cdcnp_item_set_key(cdcnp_item_insert, cdcnp_key);
    CDCNP_ITEM_PARENT_POS(cdcnp_item_insert) = parent_pos;

    if(CDCNP_ITEM_FILE_IS_REG == dir_flag)
    {
        cdcnp_fnode_init(CDCNP_ITEM_FNODE(cdcnp_item_insert));
        CDCNP_ITEM_DIR_FLAG(cdcnp_item_insert) = CDCNP_ITEM_FILE_IS_REG;
    }
    else if(CDCNP_ITEM_FILE_IS_DIR == dir_flag)
    {
        cdcnp_dnode_init(CDCNP_ITEM_DNODE(cdcnp_item_insert));
        CDCNP_ITEM_DIR_FLAG(cdcnp_item_insert) = CDCNP_ITEM_FILE_IS_DIR;
    }

    CDCNP_ITEM_USED_FLAG(cdcnp_item_insert)             = CDCNP_ITEM_IS_USED;
    CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item_insert)       = BIT_FALSE;
    CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item_insert)       = BIT_FALSE;
    CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item_insert)    = BIT_FALSE;
    CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item_insert)     = BIT_FALSE;
    CDCNP_ITEM_DEG_TIMES(cdcnp_item_insert)             = 0;

    CDCNP_DNODE_ROOT_POS(cdcnp_dnode_parent) = root_pos;
    CDCNP_DNODE_FILE_NUM(cdcnp_dnode_parent) ++;

    return (insert_offset);
}

/**
* umount one son from cdcnp_dnode,  where son is regular file item or dir item without any son
* cdcnp_dnode will be impacted on bucket and file num
**/
uint32_t cdcnp_dnode_umount_son(const CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, const uint32_t son_node_pos, const CDCNP_KEY *cdcnp_key)
{
    CDCNPRB_POOL        *pool;
    const CDCNP_ITEM    *son_cdcnp_item;
    const CDCNP_KEY     *son_cdcnp_key;

    son_cdcnp_item = cdcnp_fetch(cdcnp, son_node_pos);
    son_cdcnp_key  = CDCNP_ITEM_KEY(son_cdcnp_item);

    if(EC_TRUE == cdcnp_key_cmp(cdcnp_key, son_cdcnp_key))
    {
        uint32_t root_pos;

        root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);

        pool = CDCNP_ITEMS_POOL(cdcnp);
        cdcnprb_tree_erase(pool, son_node_pos, &root_pos); /*erase but not recycle node_pos ...*/

        CDCNP_DNODE_ROOT_POS(cdcnp_dnode) = root_pos;
        CDCNP_DNODE_FILE_NUM(cdcnp_dnode) --;
    }

    return (son_node_pos);
}

/*delete single item from dnode*/
STATIC_CAST static EC_BOOL __cdcnp_dnode_delete_item(const CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, CDCNP_ITEM *cdcnp_item)
{
    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        cdcnp_item_clean(cdcnp_item);
        CDCNP_DNODE_FILE_NUM(cdcnp_dnode) --;
    }

    else if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        cdcnp_dnode_delete_dir_son(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item));/*recursively*/
        cdcnp_item_clean(cdcnp_item);
        CDCNP_DNODE_FILE_NUM(cdcnp_dnode) --;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_dnode_delete_all_items(const CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, const uint32_t node_pos)
{
    CDCNPRB_POOL *pool;
    CDCNPRB_NODE *node;
    CDCNP_ITEM   *item;

    pool = CDCNP_ITEMS_POOL(cdcnp);

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        __cdcnp_dnode_delete_all_items(cdcnp, cdcnp_dnode, CDCNPRB_NODE_LEFT_POS(node));
    }

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        __cdcnp_dnode_delete_all_items(cdcnp, cdcnp_dnode, CDCNPRB_NODE_RIGHT_POS(node));
    }

    item = CDCNP_RB_NODE_ITEM(node);
    __cdcnp_dnode_delete_item(cdcnp, cdcnp_dnode, item);

    /*cdcnprb recycle the rbnode, do not use cdcnprb_tree_delete which will change the tree structer*/
    cdcnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

/*delete one dir son, not including cdcnp_dnode itself*/
EC_BOOL cdcnp_dnode_delete_dir_son(const CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode)
{
    uint32_t root_pos;

    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);
    if(CDCNPRB_ERR_POS != root_pos)
    {
        __cdcnp_dnode_delete_all_items(cdcnp, cdcnp_dnode, root_pos);
        CDCNP_DNODE_ROOT_POS(cdcnp_dnode) = CDCNPRB_ERR_POS;
    }
    return (EC_TRUE);
}

uint32_t cdcnp_search(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    CDCNP_ITEM  *cdcnp_item;
    uint32_t     node_pos;

    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cdcnp_item = cdcnp_fetch(cdcnp, CDCNPRB_ROOT_POS);
    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    node_pos = cdcnp_dnode_search(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item), cdcnp_key);

    return (node_pos);
}

void cdcnp_walk(CDCNP *cdcnp, void (*walker)(void *, const void *, const uint32_t), void *arg)
{
    CDCNP_ITEM  *cdcnp_item;

    /*root item*/
    cdcnp_item = cdcnp_fetch(cdcnp, CDCNPRB_ROOT_POS);
    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    cdcnp_dnode_walk(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item), walker, arg);

    return;
}

/**
*
* if dflag is DIR or REG or BIG, ignore seg_no
* if dlfag is SEG, seg_no will be used
*
**/
uint32_t cdcnp_insert(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    uint32_t node_pos;

    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    node_pos = cdcnp_dnode_insert(cdcnp, CDCNPRB_ROOT_POS, cdcnp_key, dflag);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_insert: np %u, insert at node_pos %u\n",
                        CDCNP_ID(cdcnp), node_pos);

    return (node_pos);
}

CDCNP_ITEM *cdcnp_fetch(const CDCNP *cdcnp, const uint32_t node_pos)
{
    if(CDCNPRB_ERR_POS != node_pos)
    {
        const CDCNPRB_POOL *pool;
        const CDCNPRB_NODE *node;

        pool = CDCNP_ITEMS_POOL(cdcnp);
        node = CDCNPRB_POOL_NODE(pool, node_pos);
        if(NULL_PTR != node)
        {
            return (CDCNP_ITEM *)CDCNP_RB_NODE_ITEM(node);
        }
    }
    //dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_fetch: np %u, fetch cdcnprb node %u failed\n", CDCNP_ID(cdcnp), node_pos);
    return (NULL_PTR);
}

EC_BOOL cdcnp_inode_update(CDCNP *cdcnp, CDCNP_INODE *cdcnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(src_disk_no  == CDCNP_INODE_DISK_NO(cdcnp_inode)
    && src_block_no == CDCNP_INODE_BLOCK_NO(cdcnp_inode)
    && src_page_no  == CDCNP_INODE_PAGE_NO(cdcnp_inode))
    {
        CDCNP_INODE_DISK_NO(cdcnp_inode)  = des_disk_no;
        CDCNP_INODE_BLOCK_NO(cdcnp_inode) = des_block_no;
        CDCNP_INODE_PAGE_NO(cdcnp_inode)  = des_page_no;
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_update(CDCNP *cdcnp, CDCNP_FNODE *cdcnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint16_t replica;

    for(replica = 0; replica < CDCNP_FNODE_REPNUM(cdcnp_fnode); replica ++)
    {
        cdcnp_inode_update(cdcnp, CDCNP_FNODE_INODE(cdcnp_fnode, replica),
                            src_disk_no, src_block_no, src_page_no,
                            des_disk_no, des_block_no, des_page_no);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_bucket_update(CDCNP * cdcnp, CDCNPRB_POOL *pool, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CDCNPRB_NODE *node;
    CDCNP_ITEM   *item;

    if(CDCNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        __cdcnp_bucket_update(cdcnp, pool, CDCNPRB_NODE_LEFT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    item = CDCNP_RB_NODE_ITEM(node);

    cdcnp_item_update(cdcnp, item,
                       src_disk_no, src_block_no, src_page_no,
                       des_disk_no, des_block_no, des_page_no);


    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        __cdcnp_bucket_update(cdcnp, pool, CDCNPRB_NODE_RIGHT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_bucket_update(CDCNP *cdcnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CDCNPRB_POOL *pool;
    pool = CDCNP_ITEMS_POOL(cdcnp);

    return __cdcnp_bucket_update(cdcnp, pool, node_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);
}

EC_BOOL cdcnp_dnode_update(CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    uint32_t root_pos;

    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);
    if(EC_FALSE == cdcnp_bucket_update(cdcnp, root_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_dnode_update: update root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_item_update(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(CDCNP_ITEM_IS_NOT_USED == CDCNP_ITEM_USED_FLAG(cdcnp_item))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_item_update: item was not used\n");
        return (EC_FALSE);
    }

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        return cdcnp_fnode_update(cdcnp, CDCNP_ITEM_FNODE(cdcnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        return cdcnp_dnode_update(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_item_update: invalid item dflag %u\n", CDCNP_ITEM_DIR_FLAG(cdcnp_item));
    return (EC_FALSE);
}

REAL cdcnp_used_ratio(const CDCNP *cdcnp)
{
    if(NULL_PTR != CDCNP_HDR(cdcnp))
    {
        return cdcnp_header_used_ratio(CDCNP_HDR(cdcnp));
    }

    return (0.0);
}

REAL cdcnp_deg_ratio(const CDCNP *cdcnp)
{
    if(NULL_PTR != CDCNP_HDR(cdcnp))
    {
        return cdcnp_header_deg_ratio(CDCNP_HDR(cdcnp));
    }

    return (0.0);
}

uint32_t cdcnp_deg_num(const CDCNP *cdcnp)
{
    if(NULL_PTR != CDCNP_HDR(cdcnp))
    {
        return CDCNP_DEG_NODE_NUM(cdcnp);
    }

    return (0);
}

CDCNP_ITEM *cdcnp_set(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag, uint32_t *cdcnp_item_pos)
{
    uint32_t     node_pos;
    CDCNP_ITEM  *cdcnp_item;

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_set: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (NULL_PTR);
    }

    node_pos = cdcnp_insert(cdcnp, cdcnp_key, dflag);
    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
    if(NULL_PTR != cdcnp_item)
    {
        if(EC_FALSE == cdcnp_key_cmp(cdcnp_key, CDCNP_ITEM_KEY(cdcnp_item)))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_set: mismatched key [%u, %u) ! = [%u, %u)=> not override\n",
                            CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key),
                            CDCNP_KEY_S_PAGE(CDCNP_ITEM_KEY(cdcnp_item)), CDCNP_KEY_E_PAGE(CDCNP_ITEM_KEY(cdcnp_item)));
            return (NULL_PTR);
        }

        /*ensure only item of regular file enter LRU list*/
        if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
        {
            CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item) = BIT_FALSE;

            cdcnplru_node_add_head(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);
        }

        if(NULL_PTR != cdcnp_item_pos)
        {
            (*cdcnp_item_pos) = node_pos;
        }

        return (cdcnp_item);
    }
    return (NULL_PTR);
}

CDCNP_ITEM *cdcnp_get(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag, uint32_t *cdcnp_item_pos)
{
    CDCNP_ITEM *cdcnp_item;
    uint32_t    node_pos;

    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    node_pos = cdcnp_search(cdcnp, cdcnp_key, dflag);

    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
    if(NULL_PTR != cdcnp_item)
    {
        if(NULL_PTR != cdcnp_item_pos)
        {
            (*cdcnp_item_pos) = node_pos;
        }
        return (cdcnp_item);
    }

    return (NULL_PTR);
}

CDCNP_ITEM *cdcnp_reserve(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, uint32_t *cdcnp_item_pos)
{
    CDCNP_ITEM *cdcnp_item;

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_reserve: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (NULL_PTR);
    }

    cdcnp_item = cdcnp_set(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG, cdcnp_item_pos);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_reserve: set to np failed\n");
        return (NULL_PTR);
    }

    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    cdcnp_reserve_key(cdcnp, CDCNP_ITEM_KEY(cdcnp_item));

    /*not import fnode yet*/
    return (cdcnp_item);
}

EC_BOOL cdcnp_release(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_release: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_delete(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_release: delete from np failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_has_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ASSERT(NULL_PTR != CDCNP_BITMAP(cdcnp));

    return cdcnp_bitmap_is(CDCNP_BITMAP(cdcnp), CDCNP_KEY_S_PAGE(cdcnp_key), (uint8_t)1);
}

EC_BOOL cdcnp_set_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ASSERT(NULL_PTR != CDCNP_BITMAP(cdcnp));

    return cdcnp_bitmap_set(CDCNP_BITMAP(cdcnp), CDCNP_KEY_S_PAGE(cdcnp_key));
}

EC_BOOL cdcnp_clear_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ASSERT(NULL_PTR != CDCNP_BITMAP(cdcnp));

    return cdcnp_bitmap_clear(CDCNP_BITMAP(cdcnp), CDCNP_KEY_S_PAGE(cdcnp_key));
}

EC_BOOL cdcnp_set_sata_dirty(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item  = cdcnp_fetch(cdcnp, node_pos);

        CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item) = BIT_TRUE;/*set sata dirty*/

        /*add cdc DEG list*/
        cdcnpdeg_node_add_head(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_set_sata_flushed(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item  = cdcnp_fetch(cdcnp, node_pos);

        CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item) = BIT_FALSE;/*set not flushing*/

        if(BIT_FALSE == CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item))
        {
            CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)  = BIT_TRUE; /*set flushed*/

            /*degrade already, remove it from DEG list*/
            cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
        }
        else
        {
            /*if sata dirty flag is set during flushing to sata, */
            /*then do not clear dirty flag and clear flushed flag to trigger degrading once more*/
            CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)  = BIT_FALSE; /*set not flushed*/

            /*add cdc DEG list again*/
            cdcnpdeg_node_add_head(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
        }

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_set_sata_not_flushed(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item  = cdcnp_fetch(cdcnp, node_pos);

        CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item) = BIT_FALSE; /*set no flushing*/
        CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)  = BIT_FALSE; /*set not flushed*/

        /*keep sata dirty flag unchanged*/
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_lock(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item  = cdcnp_fetch(cdcnp, node_pos);

        CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item) = BIT_TRUE;

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_unlock(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item  = cdcnp_fetch(cdcnp, node_pos);

        CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item) = BIT_FALSE;

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*do not modify LRU*/
CDCNP_ITEM *cdcnp_locate(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, uint32_t *cdcnp_item_pos)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

        if(NULL_PTR != cdcnp_item_pos)
        {
            (*cdcnp_item_pos) = node_pos;
        }

        return (cdcnp_item);
    }
    return (NULL_PTR);
}

CDCNP_ITEM *cdcnp_map(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, uint32_t *cdcnp_item_pos)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

        if(EC_FALSE == cdcnp_is_read_only(cdcnp))
        {
            cdcnplru_node_move_head(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);

            /*move it if exist*/
            cdcnpdeg_node_move_head(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
        }

        if(NULL_PTR != cdcnp_item_pos)
        {
            (*cdcnp_item_pos) = node_pos;
        }

        return (cdcnp_item);
    }
    return (NULL_PTR);
}

EC_BOOL cdcnp_read(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, CDCNP_FNODE *cdcnp_fnode)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM    *cdcnp_item;

        cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
        if(NULL_PTR != cdcnp_fnode)
        {
            cdcnp_fnode_import(CDCNP_ITEM_FNODE(cdcnp_item), cdcnp_fnode);
        }

        if(EC_FALSE == cdcnp_is_read_only(cdcnp))
        {
            cdcnplru_node_move_head(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);

            /*move it if exist*/
            cdcnpdeg_node_move_head(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
        }

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_update(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const CDCNP_FNODE *cdcnp_fnode)
{
    uint32_t node_pos;

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_update: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (EC_FALSE);
    }

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM *cdcnp_item;

        cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
        cdcnplru_node_move_head(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);

        /*move it if exist*/
        cdcnpdeg_node_move_head(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);

        return cdcnp_fnode_import(cdcnp_fnode, CDCNP_ITEM_FNODE(cdcnp_item));
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_delete(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    CDCNP_ITEM *cdcnp_item;
    uint32_t node_pos;

    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_delete: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (EC_FALSE);
    }

    node_pos = cdcnp_search(cdcnp, cdcnp_key, dflag);
    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

    if(NULL_PTR == cdcnp_item)
    {
        return (EC_FALSE);
    }

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)  = BIT_TRUE;

        if(CDCNPRB_ERR_POS != CDCNP_ITEM_PARENT_POS(cdcnp_item))
        {
            CDCNP_ITEM  *cdcnp_item_parent;
            uint32_t     node_pos_t;

            cdcnp_item_parent = cdcnp_fetch(cdcnp, CDCNP_ITEM_PARENT_POS(cdcnp_item));
            node_pos_t = cdcnp_dnode_umount_son(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item_parent), node_pos,
                                                  CDCNP_ITEM_KEY(cdcnp_item));

            //CDCNP_ASSERT(CDCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CDCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CDCNP_ITEM_PARENT_POS(cdcnp_item) = CDCNPRB_ERR_POS; /*fix*/

                cdcnprb_node_free(CDCNP_ITEMS_POOL(cdcnp), node_pos);

                cdcnp_release_key(cdcnp, CDCNP_ITEM_KEY(cdcnp_item));
                cdcnplru_node_rmv(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);
                cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);

                /*WARNING: do not add to DEL list*/
            }
            else
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_delete: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CDCNP_ID(cdcnp),
                                node_pos, CDCNP_ITEM_PARENT_POS(cdcnp_item), node_pos_t);

                CDCNP_ITEM_PARENT_POS(cdcnp_item) = CDCNPRB_ERR_POS; /*fix*/
            }
        }

        cdcnp_item_clean(cdcnp_item); /*clean up at once*/

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_degrade_cb_init(CDCNP_DEGRADE_CB *cdcnp_degrade_cb)
{
    CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb) = NULL_PTR;
    CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdcnp_degrade_cb_clean(CDCNP_DEGRADE_CB *cdcnp_degrade_cb)
{
    CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb) = NULL_PTR;
    CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdcnp_degrade_cb_clone(CDCNP_DEGRADE_CB *cdcnp_degrade_cb_src, CDCNP_DEGRADE_CB *cdcnp_degrade_cb_des)
{
    CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb_des) = CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb_src);
    CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb_des)  = CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb_src);

    return (EC_TRUE);
}

EC_BOOL cdcnp_degrade_cb_set(CDCNP_DEGRADE_CB *cdcnp_degrade_cb, CDCNP_DEGRADE_CALLBACK func, void *arg)
{
    CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb) = func;
    CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb)  = arg;

    return (EC_TRUE);
}

EC_BOOL cdcnp_init_degrade_callback(CDCNP *cdcnp)
{
    return cdcnp_degrade_cb_init(CDCNP_DEGRADE_CB(cdcnp));
}

EC_BOOL cdcnp_clean_degrade_callback(CDCNP *cdcnp)
{
    return cdcnp_degrade_cb_clean(CDCNP_DEGRADE_CB(cdcnp));
}

EC_BOOL cdcnp_set_degrade_callback(CDCNP *cdcnp, CDCNP_DEGRADE_CALLBACK func, void *arg)
{
    return cdcnp_degrade_cb_set(CDCNP_DEGRADE_CB(cdcnp), func, arg);
}

EC_BOOL cdcnp_exec_degrade_callback(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t node_pos)
{
    CDCNP_ITEM          *cdcnp_item;
    CDCNP_FNODE         *cdcnp_fnode;
    CDCNP_INODE         *cdcnp_inode;
    CDCNP_DEGRADE_CB    *cdcnp_degrade_cb;

    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_exec_degrade_callback:"
                                              "item %u is null\n",
                                              node_pos);
        return (EC_FALSE);
    }

    cdcnp_degrade_cb = CDCNP_DEGRADE_CB(cdcnp);
    if(NULL_PTR == CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb)
    || NULL_PTR == CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb))
    {
        dbg_log(SEC_0129_CDCNP, 1)(LOGSTDOUT, "warn:cdcnp_exec_degrade_callback:"
                                              "callback func %p or callback arg %p is null\n",
                                              CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb),
                                              CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb));

        return (EC_FALSE);
    }

    if(CDCNP_ITEM_FILE_IS_REG != CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_exec_degrade_callback:"
                                              "item %u is dir\n",
                                              node_pos);
        cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
        return (EC_FALSE);
    }

    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

    if(BIT_TRUE == CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item))
    {
        dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "[DEBUG] cdcnp_exec_degrade_callback:"
                                              "degrade callback at key [%u, %u), "
                                              "disk %u, block %u, page %u is locked\n",
                                              CDCNP_KEY_S_PAGE(cdcnp_key),
                                              CDCNP_KEY_E_PAGE(cdcnp_key),
                                              CDCNP_INODE_DISK_NO(cdcnp_inode),
                                              CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                              CDCNP_INODE_PAGE_NO(cdcnp_inode));
        return (EC_FALSE);/*xxx*/
    }

    if(BIT_TRUE == CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item))
    {
        dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "[DEBUG] cdcnp_exec_degrade_callback:"
                                              "degrade callback at key [%u, %u), "
                                              "disk %u, block %u, page %u is flushing\n",
                                              CDCNP_KEY_S_PAGE(cdcnp_key),
                                              CDCNP_KEY_E_PAGE(cdcnp_key),
                                              CDCNP_INODE_DISK_NO(cdcnp_inode),
                                              CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                              CDCNP_INODE_PAGE_NO(cdcnp_inode));
        return (EC_FALSE);/*xxx*/
    }

    if(BIT_TRUE == CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item))
    {
        dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "[DEBUG] cdcnp_exec_degrade_callback:"
                                              "degrade callback at key [%u, %u), "
                                              "disk %u, block %u, page %u was flushed\n",
                                              CDCNP_KEY_S_PAGE(cdcnp_key),
                                              CDCNP_KEY_E_PAGE(cdcnp_key),
                                              CDCNP_INODE_DISK_NO(cdcnp_inode),
                                              CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                              CDCNP_INODE_PAGE_NO(cdcnp_inode));
        return (EC_FALSE);/*xxx*/
    }

    CDCNP_ITEM_DEG_TIMES(cdcnp_item) ++;
    if(0 == CDCNP_ITEM_DEG_TIMES(cdcnp_item)) /*exception*/
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "fatal error:cdcnp_exec_degrade_callback:"
                                              "degrade callback at key [%u, %u), "
                                              "disk %u, block %u, page %u => deg reach max times!\n",
                                              CDCNP_KEY_S_PAGE(cdcnp_key),
                                              CDCNP_KEY_E_PAGE(cdcnp_key),
                                              CDCNP_INODE_DISK_NO(cdcnp_inode),
                                              CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                              CDCNP_INODE_PAGE_NO(cdcnp_inode));

        CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item) = BIT_FALSE; /*force to clear dirty flag!*/
        cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
        return (EC_FALSE);/*xxx*/
    }

    if(EC_FALSE == CDCNP_DEGRADE_CB_FUNC(cdcnp_degrade_cb)(
                                  CDCNP_DEGRADE_CB_ARG(cdcnp_degrade_cb),
                                  cdcnp_key))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_exec_degrade_callback:"
                                              "degrade callback at key [%u, %u), "
                                              "disk %u, block %u, page %u failed\n",
                                              CDCNP_KEY_S_PAGE(cdcnp_key),
                                              CDCNP_KEY_E_PAGE(cdcnp_key),
                                              CDCNP_INODE_DISK_NO(cdcnp_inode),
                                              CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                              CDCNP_INODE_PAGE_NO(cdcnp_inode));
        return (EC_FALSE);
    }

    CDCNP_ITEM_DEG_TIMES(cdcnp_item)          = 0;          /*reset counter*/
    CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item) = BIT_TRUE;   /*set flushing flag*/
    CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item)    = BIT_FALSE;  /*clear dirty flag*/
    cdcnpdeg_node_move_head(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_exec_degrade_callback:"
                                          "degrade callback at key [%u, %u), "
                                          "disk %u, block %u, page %u done\n",
                                          CDCNP_KEY_S_PAGE(cdcnp_key),
                                          CDCNP_KEY_E_PAGE(cdcnp_key),
                                          CDCNP_INODE_DISK_NO(cdcnp_inode),
                                          CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                          CDCNP_INODE_PAGE_NO(cdcnp_inode));

    return (EC_TRUE);
}

EC_BOOL cdcnp_degrade(CDCNP *cdcnp, const UINT32 scan_max_num, const UINT32 expect_degrade_num, UINT32 *complete_degrade_num)
{
    CDCNPDEG_NODE   cdcnpdeg_node;
    UINT32          degrade_num;
    UINT32          scan_num;

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_degrade: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (EC_FALSE);
    }

    for(scan_num = 0, degrade_num = 0, cdcnpdeg_node_clone(CDCNP_DEG_LIST(cdcnp), &cdcnpdeg_node);
        scan_num < scan_max_num && degrade_num < expect_degrade_num
     && CDCNPDEG_ROOT_POS != CDCNPDEG_NODE_PREV_POS(&cdcnpdeg_node);
        scan_num ++)
    {
        CDCNP_ITEM      *cdcnp_item;
        CDCNP_KEY       *cdcnp_key; /*for debug*/
        UINT32           f_s_offset;
        UINT32           f_e_offset;
        uint32_t         node_pos;

        node_pos      = CDCNPDEG_NODE_PREV_POS(&cdcnpdeg_node);
        cdcnp_item    = cdcnp_fetch(cdcnp, node_pos);

        cdcnp_key = CDCNP_ITEM_KEY(cdcnp_item);
        f_s_offset = (((UINT32)CDCNP_KEY_S_PAGE(cdcnp_key)) << CDCPGB_PAGE_SIZE_NBITS);
        f_e_offset = (((UINT32)CDCNP_KEY_E_PAGE(cdcnp_key)) << CDCPGB_PAGE_SIZE_NBITS);

        /*cloned and saved for safe reason*/
        cdcnpdeg_node_clone(CDCNP_ITEM_DEG_NODE(cdcnp_item), &cdcnpdeg_node);

        CDCNP_ASSERT(EC_TRUE == cdcnprb_node_is_used(CDCNP_ITEMS_POOL(cdcnp), node_pos));
        CDCNP_ASSERT(CDCNP_ITEM_IS_USED == CDCNP_ITEM_USED_FLAG(cdcnp_item));

        if(CDCNP_ITEM_FILE_IS_REG != CDCNP_ITEM_DIR_FLAG(cdcnp_item))
        {
            continue;
        }

        if(BIT_TRUE == CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item))
        {
            dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "[DEBUG] cdcnp_degrade: "
                            "np %u node_pos %d [REG] [%ld, %ld) is locked\n",
                            CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);
            continue;
        }

        if(BIT_FALSE == CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item))
        {
            dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "[DEBUG] cdcnp_degrade: "
                            "np %u node_pos %d [REG] [%ld, %ld) is not diry\n",
                            CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);

            /*degrade ignored, remove it from DEG list*/
            cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
            continue;
        }

        if(BIT_TRUE == CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item))
        {
            dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "[DEBUG] cdcnp_degrade: "
                            "np %u node_pos %d [REG] [%ld, %ld) is flushing\n",
                            CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);
            continue;
        }

        if(BIT_TRUE == CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item))
        {
            dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "[DEBUG] cdcnp_degrade: "
                            "np %u node_pos %d [REG] [%ld, %ld) dirty & flushed => not flushed\n",
                            CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);

            CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)  = BIT_FALSE; /*reset not flushed*/
            /*fall through*/
        }

        if(EC_FALSE == cdcnp_exec_degrade_callback(cdcnp, CDCNP_ITEM_KEY(cdcnp_item), node_pos))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_degrade: "
                            "np %u node_pos %d [REG] [%ld, %ld) failed\n",
                            CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);
            continue;
        }

        dbg_log(SEC_0129_CDCNP, 6)(LOGSTDOUT, "[DEBUG] cdcnp_degrade: "
                        "np %u node_pos %d [REG] [%ld, %ld) degrade done\n",
                        CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);

        degrade_num ++;
    }

    if(NULL_PTR != complete_degrade_num)
    {
        (*complete_degrade_num) = degrade_num;
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_retire(CDCNP *cdcnp, const UINT32 scan_max_num, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CDCNPLRU_NODE   cdcnplru_node;
    UINT32          retire_num;
    UINT32          scan_num;

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_retire: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (EC_FALSE);
    }

    for(scan_num = 0, retire_num = 0, cdcnplru_node_clone(CDCNP_LRU_LIST(cdcnp), &cdcnplru_node);
        scan_num < scan_max_num && retire_num < expect_retire_num
     && CDCNPLRU_ROOT_POS != CDCNPLRU_NODE_PREV_POS(&cdcnplru_node);
        scan_num ++)
    {
        CDCNP_ITEM *cdcnp_item;
        uint32_t    node_pos;

        node_pos      = CDCNPLRU_NODE_PREV_POS(&cdcnplru_node);
        cdcnp_item    = cdcnp_fetch(cdcnp, node_pos);

        /*note: CDCNP_ITEM_LRU_NODE would be cleanup when umount item*/
        cdcnplru_node_clone(CDCNP_ITEM_LRU_NODE(cdcnp_item), &cdcnplru_node); /*cloned and saved*/

        CDCNP_ASSERT(EC_TRUE == cdcnprb_node_is_used(CDCNP_ITEMS_POOL(cdcnp), node_pos));
        CDCNP_ASSERT(CDCNP_ITEM_IS_USED == CDCNP_ITEM_USED_FLAG(cdcnp_item));

        if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
        {
            CDCNP_KEY      *cdcnp_key; /*for debug*/
            UINT32          f_s_offset;
            UINT32          f_e_offset;

            cdcnp_key = CDCNP_ITEM_KEY(cdcnp_item);

            f_s_offset = (((UINT32)CDCNP_KEY_S_PAGE(cdcnp_key)) << CDCPGB_PAGE_SIZE_NBITS);
            f_e_offset = (((UINT32)CDCNP_KEY_E_PAGE(cdcnp_key)) << CDCPGB_PAGE_SIZE_NBITS);

            if(BIT_TRUE == CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item))
            {
                dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "warn:cdcnp_retire: "
                                "np %u node_pos %d [REG] [%ld, %ld) is dirty yet\n",
                                CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);

                /*speed up degrade*/
                cdcnpdeg_node_move_tail(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
                continue;
            }

            if(BIT_TRUE == CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item))
            {
                dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "warn:cdcnp_retire: "
                                "np %u node_pos %d [REG] [%ld, %ld) locked yet\n",
                                CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);
                continue;
            }

            if(BIT_TRUE == CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item))
            {
                dbg_log(SEC_0129_CDCNP, 7)(LOGSTDOUT, "warn:cdcnp_retire: "
                                "np %u node_pos %d [REG] [%ld, %ld) is flushing yet\n",
                                CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);
                continue;
            }

            /*retire file*/
            if(EC_FALSE == cdcnp_umount_item(cdcnp, node_pos))
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retire: "
                                "np %u node_pos %d [REG] [%ld, %ld) failed\n",
                                CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);
                return (EC_FALSE);
            }

            dbg_log(SEC_0129_CDCNP, 6)(LOGSTDOUT, "[DEBUG] cdcnp_retire: "
                            "np %u node_pos %d [REG] [%ld, %ld) retire done\n",
                            CDCNP_ID(cdcnp), node_pos, f_s_offset, f_e_offset);
            retire_num ++;
            continue;
        }
    }

    if(NULL_PTR != complete_retire_num)
    {
        (*complete_retire_num) = retire_num;
    }

    return (EC_TRUE);
}

/*reset possible locked flag and flushing flag after retrieve*/
EC_BOOL cdcnp_reset(CDCNP *cdcnp)
{
    CDCNPLRU_NODE  *cdcnplru_node;
    UINT32          locked_num;
    UINT32          flushing_num;
    UINT32          degrading_num; /*incomplete degrade items num*/
    uint32_t        node_pos;

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_reset: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (EC_FALSE);
    }

    locked_num      = 0;
    flushing_num    = 0;
    degrading_num   = 0;
    node_pos        = CDCNPLRU_ROOT_POS;

    do
    {
        CDCNP_ITEM *cdcnp_item;

        cdcnp_item    = cdcnp_fetch(cdcnp, node_pos);
        cdcnplru_node = CDCNP_ITEM_LRU_NODE(cdcnp_item);

        if(EC_FALSE == cdcnprb_node_is_used(CDCNP_ITEMS_POOL(cdcnp), node_pos))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_reset: "
                                                  "np %u node_pos %d, rb node is not used\n",
                                                  CDCNP_ID(cdcnp), node_pos);
            return (EC_FALSE);
        }

        if(CDCNP_ITEM_IS_NOT_USED == CDCNP_ITEM_USED_FLAG(cdcnp_item))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_reset: "
                                                  "np %u node_pos %d, item is not used\n",
                                                  CDCNP_ID(cdcnp), node_pos);
            return (EC_FALSE);
        }

        if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
        {
            if(BIT_TRUE == CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item))
            {
                locked_num ++;

                CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item) = BIT_FALSE;
            }

            if(BIT_TRUE == CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item))
            {
                flushing_num ++;

                CDCNP_ITEM_SATA_FLUSHING_FLAG(cdcnp_item) = BIT_FALSE;

                CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)  = BIT_FALSE;

                CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item)    = BIT_TRUE;
            }

            if(0 < CDCNP_ITEM_DEG_TIMES(cdcnp_item))
            {
                degrading_num ++;

                CDCNP_ITEM_DEG_TIMES(cdcnp_item) = 0;
            }
        }

        node_pos = CDCNPLRU_NODE_NEXT_POS(cdcnplru_node);

    }while(CDCNPLRU_ROOT_POS != node_pos);

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_reset: "
                                          "reset locked %ld, reset flushing %ld, reset degrading %ld\n",
                                          locked_num, flushing_num, degrading_num);

    return (EC_TRUE);
}

EC_BOOL cdcnp_umount_item(CDCNP *cdcnp, const uint32_t node_pos)
{
    CDCNP_ITEM *cdcnp_item;

    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

    if(NULL_PTR == cdcnp_item)
    {
        return (EC_FALSE);
    }

    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;

        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
        CDCNP_DEL_SIZE(cdcnp) += (UINT32)(((UINT32)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);

        CDCNP_ITEM_SATA_FLUSHED_FLAG(cdcnp_item)    = BIT_TRUE;

        if(CDCNPRB_ERR_POS != CDCNP_ITEM_PARENT_POS(cdcnp_item))
        {
            CDCNP_ITEM   *cdcnp_item_parent;
            CDCNP_DNODE  *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CDCNP_ITEM_PARENT_POS(cdcnp_item);
            cdcnp_item_parent  = cdcnp_fetch(cdcnp, parent_node_pos);
            parent_dnode       = CDCNP_ITEM_DNODE(cdcnp_item_parent);

            node_pos_t = cdcnp_dnode_umount_son(cdcnp, parent_dnode, node_pos, CDCNP_ITEM_KEY(cdcnp_item));

            if(CDCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CDCNP_ITEM_PARENT_POS(cdcnp_item) = CDCNPRB_ERR_POS; /*fix*/

                cdcnp_release_key(cdcnp, CDCNP_ITEM_KEY(cdcnp_item));

                cdcnplru_node_rmv(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);
                cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
                cdcnpdel_node_add_tail(cdcnp, CDCNP_ITEM_DEL_NODE(cdcnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_umount_item: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CDCNP_ID(cdcnp),
                                node_pos, CDCNP_ITEM_PARENT_POS(cdcnp_item), node_pos_t);
                CDCNP_ITEM_PARENT_POS(cdcnp_item) = CDCNPRB_ERR_POS; /*fix*/
            }
        }
        else
        {
            cdcnp_release_key(cdcnp, CDCNP_ITEM_KEY(cdcnp_item));

            cdcnplru_node_rmv(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);
            cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);
            cdcnpdel_node_add_tail(cdcnp, CDCNP_ITEM_DEL_NODE(cdcnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdcnp_umount(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    uint32_t node_pos;

    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    CDCNP_ASSERT(EC_FALSE == cdcnp_is_read_only(cdcnp));

    node_pos = cdcnp_search(cdcnp, cdcnp_key, dflag);

    if(EC_FALSE == cdcnp_umount_item(cdcnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_file_num(CDCNP *cdcnp, uint32_t *file_num)
{
    CDCNP_ITEM  *cdcnp_item;
    CDCNP_DNODE *cdcnp_dnode;

    cdcnp_item = cdcnp_fetch(cdcnp, CDCNPRB_ROOT_POS);
    CDCNP_ASSERT(NULL_PTR != cdcnp_item);
    CDCNP_ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    cdcnp_dnode = CDCNP_ITEM_DNODE(cdcnp_item);

    (*file_num) = CDCNP_DNODE_FILE_NUM(cdcnp_dnode);
    return (EC_TRUE);
}

EC_BOOL cdcnp_file_size(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, UINT32 *file_size)
{
    CDCNP_ITEM *cdcnp_item;

    cdcnp_item = cdcnp_get(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG, NULL_PTR);
    if(NULL_PTR == cdcnp_item)
    {
        (*file_size) = 0;
        return (EC_FALSE);
    }

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;
        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);

        (*file_size) = (UINT32)(((UINT32)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);
        return (EC_TRUE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_file_size: np %u, invalid dflg %x\n", CDCNP_ID(cdcnp), CDCNP_ITEM_DIR_FLAG(cdcnp_item));
    return (EC_FALSE);
}

void cdcnp_file_print(LOG *log, const CDCNP *cdcnp, const uint32_t node_pos)
{
    CDCNP_ITEM *cdcnp_item;

    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
    if(NULL_PTR == cdcnp_item)
    {
        return;
    }

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;
        CDCNP_KEY   *cdcnp_key;

        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
        cdcnp_key   = CDCNP_ITEM_KEY(cdcnp_item);

        cdcnp_key_print(log, cdcnp_key);
        cdcnp_fnode_print(log, cdcnp_fnode);
        return;
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_file_print: np %u, invalid dflg %x\n",
                    CDCNP_ID(cdcnp), CDCNP_ITEM_DIR_FLAG(cdcnp_item));
    return;
}

EC_BOOL cdcnp_create_root_item(CDCNP *cdcnp)
{
    CDCNP_ITEM  *cdcnp_item;
    CDCNP_KEY    cdcnp_key;
    uint32_t     root_pos;
    uint32_t     insert_pos;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = CDCNP_KEY_S_PAGE_ERR;
    CDCNP_KEY_E_PAGE(&cdcnp_key) = CDCNP_KEY_E_PAGE_ERR;

    root_pos = CDCNPRB_ERR_POS;

    if(EC_FALSE == cdcnprb_tree_insert_data(CDCNP_ITEMS_POOL(cdcnp), &root_pos, &cdcnp_key, &insert_pos))
    {
        dbg_log(SEC_0129_CDCNP, 1)(LOGSTDOUT, "warn:cdcnp_create_root_item: insert create item failed\n");
        return (EC_FALSE);
    }

    if(0 != insert_pos)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_root_item: insert root item at pos %u is not zero!\n", insert_pos);
        return (EC_FALSE);
    }

    if(0 != root_pos)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_root_item: root_pos %u is not zero!\n", root_pos);
        return (EC_FALSE);
    }

    cdcnp_item = cdcnp_fetch(cdcnp, insert_pos);

    CDCNP_ITEM_DIR_FLAG(cdcnp_item)       = CDCNP_ITEM_FILE_IS_DIR;
    CDCNP_ITEM_USED_FLAG(cdcnp_item)      = CDCNP_ITEM_IS_USED;
    CDCNP_ITEM_DEG_TIMES(cdcnp_item)      = 0;
    CDCNP_ITEM_PARENT_POS(cdcnp_item)     = CDCNPRB_ERR_POS;

    CDCNP_ITEM_S_PAGE(cdcnp_item)         = CDCNP_KEY_S_PAGE_ERR;
    CDCNP_ITEM_E_PAGE(cdcnp_item)         = CDCNP_KEY_E_PAGE_ERR;

    cdcnp_dnode_init(CDCNP_ITEM_DNODE(cdcnp_item));

    return (EC_TRUE);
}

/*------------------------------------------------ recycle -----------------------------------------*/
/*recycle dn only!*/
EC_BOOL cdcnp_recycle_item_file(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn)
{
    CDCNP_FNODE *cdcnp_fnode;

    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
    if(EC_FALSE == CDCNP_RECYCLE_DN_FUNC(cdcnp_recycle_dn)(CDCNP_RECYCLE_DN_ARG1(cdcnp_recycle_dn), cdcnp_fnode))
    {
        CDCNP_INODE *cdcnp_inode;

        cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_recycle_item_file: recycle dn (disk %u, block %u, page %u, page num %u) failed\n",
                            CDCNP_INODE_DISK_NO(cdcnp_inode),
                            CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                            CDCNP_INODE_PAGE_NO(cdcnp_inode),
                            CDCNP_FNODE_PAGENUM(cdcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR != cdcnp_recycle_np)
    {
        CDCNP_RECYCLE_NP_FUNC(cdcnp_recycle_np)(CDCNP_RECYCLE_NP_ARG1(cdcnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_recycle_dnode_item(CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn)
{
    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        cdcnp_recycle_item_file(cdcnp, cdcnp_item, node_pos, cdcnp_recycle_np, cdcnp_recycle_dn);
        CDCNP_DNODE_FILE_NUM(cdcnp_dnode) --;

        /*this file is under a deleted directory in deep. it may be still in LRU list.*/
        cdcnplru_node_rmv(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);
        cdcnpdeg_node_rmv(cdcnp, CDCNP_ITEM_DEG_NODE(cdcnp_item), node_pos);

        cdcnp_item_clean(cdcnp_item);
        return (EC_TRUE);
    }

    if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        cdcnp_recycle_item_dir(cdcnp, cdcnp_item, node_pos, cdcnp_recycle_np, cdcnp_recycle_dn);/*recursively*/
        CDCNP_DNODE_FILE_NUM(cdcnp_dnode) --;

        cdcnp_item_clean(cdcnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_recycle_dnode_item: invalid dflag 0x%x\n", CDCNP_ITEM_DIR_FLAG(cdcnp_item));
    return (EC_FALSE);
}

EC_BOOL cdcnp_recycle_dnode(CDCNP *cdcnp, CDCNP_DNODE *cdcnp_dnode, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn)
{
    CDCNPRB_POOL *pool;
    CDCNPRB_NODE *node;
    CDCNP_ITEM   *item;

    pool = CDCNP_ITEMS_POOL(cdcnp);

    node  = CDCNPRB_POOL_NODE(pool, node_pos);
    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_LEFT_POS(node))
    {
        cdcnp_recycle_dnode(cdcnp, cdcnp_dnode, CDCNPRB_NODE_LEFT_POS(node), cdcnp_recycle_np, cdcnp_recycle_dn);
    }

    if(CDCNPRB_ERR_POS != CDCNPRB_NODE_RIGHT_POS(node))
    {
        cdcnp_recycle_dnode(cdcnp, cdcnp_dnode, CDCNPRB_NODE_RIGHT_POS(node), cdcnp_recycle_np, cdcnp_recycle_dn);
    }

    item = CDCNP_RB_NODE_ITEM(node);
    cdcnp_recycle_dnode_item(cdcnp, cdcnp_dnode, item, node_pos, cdcnp_recycle_np, cdcnp_recycle_dn);

    /*cdcnprb recycle the rbnode, do not use cdcnprb_tree_delete which will change the tree structer*/
    cdcnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

EC_BOOL cdcnp_recycle_item_dir(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn)
{
    CDCNP_DNODE *cdcnp_dnode;
    uint32_t root_pos;

    cdcnp_dnode = CDCNP_ITEM_DNODE(cdcnp_item);

    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);
    if(CDCNPRB_ERR_POS != root_pos)
    {
        cdcnp_recycle_dnode(cdcnp, cdcnp_dnode, root_pos, cdcnp_recycle_np, cdcnp_recycle_dn);
        CDCNP_DNODE_ROOT_POS(cdcnp_dnode) = CDCNPRB_ERR_POS;
    }

    if(NULL_PTR != cdcnp_recycle_np)
    {
        CDCNP_RECYCLE_NP_FUNC(cdcnp_recycle_np)(CDCNP_RECYCLE_NP_ARG1(cdcnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

/*note: this interface is for that cdcnp_item had umounted from parent, not need to update parent info*/
EC_BOOL cdcnp_recycle_item(CDCNP *cdcnp, CDCNP_ITEM *cdcnp_item, const uint32_t node_pos, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn)
{
    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;
        CDCNP_KEY   *cdcnp_key;

        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
        cdcnp_key   = CDCNP_ITEM_KEY(cdcnp_item);

        if(EC_FALSE == cdcnp_recycle_item_file(cdcnp, cdcnp_item, node_pos, cdcnp_recycle_np, cdcnp_recycle_dn))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_recycle_item: recycle regular file failed where cdcnp_item is\n");
            cdcnp_item_and_key_print(LOGSTDOUT, cdcnp_item);

            /*should never reach here*/
            cdcnp_item_clean(cdcnp_item);

            return (EC_FALSE);
        }

        dbg_log(SEC_0129_CDCNP, 6)(LOGSTDOUT, "[DEBUG] cdcnp_recycle_item: recycle [%ld, %ld) done\n",
                        ((UINT32)CDCNP_KEY_S_PAGE(cdcnp_key)) << CDCPGB_PAGE_SIZE_NBITS,
                        ((UINT32)CDCNP_KEY_E_PAGE(cdcnp_key)) << CDCPGB_PAGE_SIZE_NBITS);

        CDCNP_RECYCLE_SIZE(cdcnp) += (UINT32)(((UINT32)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);

        /*note: this file is in DEL list so that it must not be in LRU list*/

        cdcnp_item_clean(cdcnp_item);
        return (EC_TRUE);
    }

    if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        cdcnp_recycle_item_dir(cdcnp, cdcnp_item, node_pos, cdcnp_recycle_np, cdcnp_recycle_dn);/*recursively*/

        cdcnp_item_clean(cdcnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_recycle_item: invalid dflag 0x%x\n", CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    /*should never reach here*/
    cdcnp_item_clean(cdcnp_item);

    return (EC_FALSE);
}

EC_BOOL cdcnp_recycle(CDCNP *cdcnp, const UINT32 max_num, CDCNP_RECYCLE_NP *cdcnp_recycle_np, CDCNP_RECYCLE_DN *cdcnp_recycle_dn, UINT32 *complete_num)
{
    CDCNPDEL_NODE  *cdcnpdel_node_head;
    //CDCNP_HEADER   *cdcnp_header;

    uint32_t         left_num;

    if(EC_TRUE == cdcnp_is_read_only(cdcnp))
    {
        dbg_log(SEC_0129_CDCNP, 3)(LOGSTDOUT, "error:cdcnp_recycle: np %u is read-only\n",
                                              CDCNP_ID(cdcnp));
        return (EC_FALSE);
    }

    cdcnpdel_node_head = CDCNP_DEL_LIST(cdcnp);

    //cdcnp_header = CDCNP_HDR(cdcnp);
    left_num = UINT32_TO_INT32(max_num);

    if(0 == left_num)
    {
        /*items never beyond the max value of uint32_t*/
        left_num = ((uint32_t)~0);
    }

    (*complete_num) = 0;
    while((0 < left_num --) && (EC_FALSE == cdcnp_del_list_is_empty(cdcnp)))
    {
        CDCNP_ITEM   *cdcnp_item;
        uint32_t       node_pos;

        node_pos = CDCNPDEL_NODE_NEXT_POS(cdcnpdel_node_head);

        cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

        CDCNP_ASSERT(CDCNPRB_ERR_POS == CDCNP_ITEM_PARENT_POS(cdcnp_item));

        if(EC_FALSE == cdcnp_recycle_item(cdcnp, cdcnp_item, node_pos, cdcnp_recycle_np, cdcnp_recycle_dn))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_recycle: recycle item %u # failed\n", node_pos);

            /*should never reach here*/
            cdcnpdel_node_rmv(cdcnp, CDCNP_ITEM_DEL_NODE(cdcnp_item), node_pos);

            cdcnprb_node_free(CDCNP_ITEMS_POOL(cdcnp), node_pos);/*recycle rb node(item node)*/
            return (EC_FALSE);
        }

        cdcnpdel_node_rmv(cdcnp, CDCNP_ITEM_DEL_NODE(cdcnp_item), node_pos);

        cdcnprb_node_free(CDCNP_ITEMS_POOL(cdcnp), node_pos);/*recycle rb node(item node)*/

        (*complete_num) ++;

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_recycle: recycle item %u # done\n", node_pos);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_header_load(CDCNP_HEADER *cdcnp_header, const uint32_t np_id, int fd, UINT32 *offset, const UINT32 fsize)
{
    if(EC_FALSE == c_file_pread(fd, offset, fsize, (UINT8 *)cdcnp_header))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_header_load: "
                                              "load %ld bytes failed of np %u from fd %d\n",
                                              fsize, np_id, fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_header_flush(CDCNP_HEADER *cdcnp_header, const uint32_t np_id, int fd, UINT32 *offset, const UINT32 fsize)
{
    if(NULL_PTR != cdcnp_header)
    {
        if(EC_FALSE == c_file_pwrite(fd, offset, fsize, (const UINT8 *)cdcnp_header))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_header_flush: "
                                                  "flush cdcnp_hdr %p of np %u to fd %d with fsize %ld failed\n",
                                                  cdcnp_header, np_id, fd, fsize);
            return (EC_FALSE);
        }

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_header_flush: "
                                              "flush cdcnp_hdr %p of np %u (magic %#x) to fd %d with size %ld done\n",
                                              cdcnp_header, np_id, CDCNP_HEADER_MAGIC(cdcnp_header), fd, fsize);
        return (EC_TRUE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_erase(CDCNP *cdcnp, const uint32_t np_id, int fd, const UINT32 s_offset, const UINT32 e_offset)
{
    UINT32        f_s_offset;
    UINT32        f_e_offset;

    UINT32        offset;
    UINT8        *data;
    UINT32        data_len;

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_erase: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != cdcnp && NULL_PTR != CDCNP_HDR(cdcnp))
    {
        CDCNP_HEADER    *cdcnp_header;

        cdcnp_header = CDCNP_HDR(cdcnp);

        CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_ERR_MAGIC_NUM;
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_erase: erase np header magic done\n");
    }

    f_s_offset = VAL_ALIGN_NEXT(s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/

    /*read np id and np model => file size => load whole*/
    if(f_s_offset + 8 > f_e_offset)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_erase: "
                                              "[%ld, %ld) => invalid range [%ld, %ld)\n",
                                              s_offset, e_offset,
                                              f_s_offset, f_e_offset);
        return (EC_FALSE);
    }

    data_len = CDCPGB_PAGE_SIZE_NBYTES;
    data = (UINT8 *)c_memalign_new(data_len, (UINT32)CDCPGB_PAGE_SIZE_NBYTES);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_erase: "
                                              "new %ld bytes for np %u failed\n",
                                              (UINT32)CDCPGB_PAGE_SIZE_NBYTES, np_id);
        return (EC_FALSE);
    }

    BSET(data, 0xFF, data_len);

    offset = f_s_offset;
    if(EC_FALSE == c_file_pwrite(fd, &offset, data_len, (UINT8 *)data))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_erase: "
                                              "erase %ld bytes from fd %d, offset %ld failed\n",
                                              data_len, fd, f_s_offset);
        c_memalign_free(data);
        return (EC_FALSE);
    }

    c_memalign_free(data);

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_erase: "
                                          "erase %ld bytes from fd %d, offset %ld done\n",
                                          data_len, fd, f_s_offset);
    return (EC_TRUE);
}

EC_BOOL cdcnp_load_basic(CDCNP *cdcnp, int fd, const UINT32 offset,
                              uint32_t *magic, uint32_t *np_id, uint8_t *np_model)
{
    UINT8        *data;
    UINT32        data_len;
    UINT32        s_offset;

    data_len = CDCPGB_PAGE_SIZE_NBYTES;
    data = (UINT8 *)c_memalign_new(data_len, (UINT32)CDCPGB_PAGE_SIZE_NBYTES);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_basic: "
                                              "new %ld bytes failed\n",
                                              (UINT32)CDCPGB_PAGE_SIZE_NBYTES);
        return (EC_FALSE);
    }

    s_offset = offset;

    if(EC_FALSE == c_file_pread(fd, &s_offset, data_len, (UINT8 *)data))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_basic: "
                                              "load %ld bytes from fd %d, offset %ld failed\n",
                                              data_len, fd, offset);
        c_memalign_free(data);
        return (EC_FALSE);
    }

    (*magic)    = CDCNP_HEADER_MAGIC((CDCNP_HEADER *)data);
    (*np_id)    = CDCNP_HEADER_NP_ID((CDCNP_HEADER *)data);
    (*np_model) = CDCNP_HEADER_MODEL((CDCNP_HEADER *)data);

    c_memalign_free(data);

    return (EC_TRUE);
}

EC_BOOL cdcnp_load(CDCNP *cdcnp, const uint32_t np_id, int fd, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP_HEADER *cdcnp_header;
    CDCNP_BITMAP *cdcnp_bitmap;
    UINT32        f_s_offset;
    UINT32        f_e_offset;

    UINT32        offset;

    UINT32        np_size;
    uint32_t      magic_t;
    uint32_t      np_id_t;
    uint8_t       np_model_t;

    CDCNP_ASSERT(NULL_PTR != cdcnp);

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: no fd\n");
        return (EC_FALSE);
    }

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/

    /*read np id and np model => file size => load whole*/
    if(f_s_offset + 8 > f_e_offset)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                              "[%ld, %ld) => invalid range [%ld, %ld)\n",
                                              (*s_offset), e_offset,
                                              f_s_offset, f_e_offset);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_load_basic(cdcnp, fd, f_s_offset, &magic_t, &np_id_t, &np_model_t))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                              "load basic of np %u failed\n",
                                              np_id);
        return (EC_FALSE);
    }

    /*trick: check np id*/
    if(np_id != np_id_t)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                              "np id mismatched: given %u, stored %u "
                                              "from fd %d, offset %ld\n",
                                              np_id, np_id_t,
                                              fd, f_s_offset);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                          "np id %u matched "
                                          "from fd %d, offset %ld\n",
                                          np_id,
                                          fd, f_s_offset);

    /*trick: check magic number*/
    if(CDCNP_MAGIC_NUM != magic_t)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                              "np magic mismatched: stored %#x != %#x "
                                              "from fd %d, offset %ld\n",
                                              magic_t,
                                              CDCNP_MAGIC_NUM,
                                              fd, f_s_offset);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                          "np magic %#x matched "
                                          "from fd %d, offset %ld\n",
                                          magic_t,
                                          fd, f_s_offset);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                          "np_id %u, np_model %u from fd %d, offset %ld\n",
                                          np_id, np_model_t, fd, f_s_offset);

    if(EC_FALSE == cdcnp_model_file_size(np_model_t, &np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: invalid np_model_t %u\n", np_model_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                          "np_model_t %u, np_size %ld\n",
                                          np_model_t, np_size);

    CDCNP_ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
    np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));

    offset = f_s_offset;

    cdcnp_header = cdcnp_header_new(np_id, np_size, np_model_t);
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                              "new header for np %u, size %ld, model %u failed\n",
                                              np_id, np_size, np_model_t);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_header_load(cdcnp_header, np_id, fd, &offset, np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                              "load np %u from fd %d, offset %ld failed\n",
                                              np_id, fd, f_s_offset);
        cdcnp_header_free(cdcnp_header);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                          "load np %u from fd %d, offset %ld, size %ld done\n",
                                          np_id, fd, f_s_offset, np_size);

    CDCNP_ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));
    CDCNP_ASSERT(np_model_t == CDCNP_HEADER_MODEL(cdcnp_header));
    CDCNP_ASSERT(CDCNP_MAGIC_NUM == CDCNP_HEADER_MAGIC(cdcnp_header));
    CDCNP_ASSERT(f_s_offset + np_size == offset);

    cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);

    CDCNP_HDR(cdcnp)    = cdcnp_header;
    CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;

    /*shortcut*/
    CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
    CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));
    CDCNP_DEG_LIST(cdcnp) = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, CDCNPDEG_ROOT_POS));

    CDCNP_S_OFFSET(cdcnp) = f_s_offset;
    CDCNP_E_OFFSET(cdcnp) = f_s_offset + np_size;
    CDCNP_FNAME(cdcnp)    = NULL_PTR;

    (*s_offset) = f_s_offset + np_size;

    /*erase magic number which would be overrided after flush successfully*/
    if(1)
    {
        UINT32        offset_erase;
        UINT8        *data;
        UINT32        data_len;

        offset_erase = f_s_offset;

        CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_ERR_MAGIC_NUM;/*set to invalid magic temporarily*/

        /*alignment*/
        data     = (UINT8 *)cdcnp_header;
        data_len = CDCPGB_PAGE_SIZE_NBYTES;

        if(EC_FALSE == c_file_pwrite(fd, &offset_erase, data_len, data))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                                  "erase np magic from fd %d, offset %ld failed\n",
                                                  fd, offset_erase);

            CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM; /*restore to valid magic*/
            return (EC_FALSE);
        }

        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                              "erase np magic temporarily from fd %d, offset %ld done\n",
                                              fd, offset_erase);

        CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM; /*restore to valid magic*/
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                          "load np %u, fsize %ld from fd %d, offset %ld => %ld done\n",
                                          CDCNP_HEADER_NP_ID(cdcnp_header),
                                          np_size, fd, f_s_offset, offset);

    return (EC_TRUE);
}

EC_BOOL cdcnp_load_basic_shm(CDCNP *cdcnp, CMMAP_NODE *cmmap_node,
                              uint32_t *magic, uint32_t *np_id, uint8_t *np_model)
{
    UINT8        *data;
    UINT32        data_len;

    data_len = CDCPGB_PAGE_SIZE_NBYTES;
    data = (UINT8 *)c_memalign_new(data_len, (UINT32)CDCPGB_PAGE_SIZE_NBYTES);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_basic_shm: "
                                              "new %ld bytes failed\n",
                                              (UINT32)CDCPGB_PAGE_SIZE_NBYTES);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmmap_node_peek(cmmap_node, data_len, (UINT8 *)data))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_basic_shm: "
                                              "load %ld bytes failed\n",
                                              data_len);
        c_memalign_free(data);
        return (EC_FALSE);
    }

    (*magic)    = CDCNP_HEADER_MAGIC((CDCNP_HEADER *)data);
    (*np_id)    = CDCNP_HEADER_NP_ID((CDCNP_HEADER *)data);
    (*np_model) = CDCNP_HEADER_MODEL((CDCNP_HEADER *)data);

    c_memalign_free(data);

    return (EC_TRUE);
}

EC_BOOL cdcnp_load_shm(CDCNP *cdcnp, CMMAP_NODE *cmmap_node, const uint32_t np_id, int fd, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP_HEADER *cdcnp_header;
    CDCNP_BITMAP *cdcnp_bitmap;
    UINT32        f_s_offset;
    UINT32        f_e_offset;

    UINT32        np_size;

    uint32_t      magic_t;
    uint32_t      np_id_t;
    uint8_t       np_model_t;

    CDCNP_ASSERT(NULL_PTR != cdcnp);

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: no fd\n");
        return (EC_FALSE);
    }

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/

    /*read np id and np model => file size => load whole*/
    if(f_s_offset + 8 > f_e_offset)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: "
                                              "[%ld, %ld) => invalid range [%ld, %ld)\n",
                                              (*s_offset), e_offset,
                                              f_s_offset, f_e_offset);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_load_basic_shm(cdcnp, cmmap_node, &magic_t, &np_id_t, &np_model_t))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: "
                                              "load basic of np %u failed\n",
                                              np_id);
        return (EC_FALSE);
    }

    /*trick: check np id*/
    if(np_id != np_id_t)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: "
                                              "np id mismatched: shm stored %u != %u\n",
                                              np_id_t, np_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: "
                                          "np id %u matched\n",
                                          np_id);

    /*trick: check magic number*/
    if(CDCNP_MAGIC_NUM != magic_t)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: "
                                              "np magic mismatched: shm stored %#x != %#x\n",
                                              magic_t, CDCNP_MAGIC_NUM);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: "
                                          "np magic %#x matched\n",
                                          magic_t);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: "
                                          "np_id %u, np_model %u\n",
                                          np_id_t, np_model_t);

    if(EC_FALSE == cdcnp_model_file_size(np_model_t, &np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: invalid np_model %u\n", np_model_t);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: "
                                          "np_model %u, np_size %ld\n",
                                          np_model_t, np_size);

    CDCNP_ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
    np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));


    /*not truncate => map it*/
    cdcnp_header = cmmap_node_alloc(cmmap_node, np_size, CDCNP_MEM_ALIGNMENT, "cdc np header");
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: "
                                              "mmap np %u failed\n",
                                              np_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: "
                                          "load np %u done\n",
                                          np_id);

    CDCNP_ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));
    CDCNP_ASSERT(np_model_t == CDCNP_HEADER_MODEL(cdcnp_header));
    CDCNP_ASSERT(CDCNP_MAGIC_NUM == CDCNP_HEADER_MAGIC(cdcnp_header));

    cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);

    CDCNP_HDR(cdcnp)    = cdcnp_header;
    CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;

    /*shortcut*/
    CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
    CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));
    CDCNP_DEG_LIST(cdcnp) = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, CDCNPDEG_ROOT_POS));

    CDCNP_S_OFFSET(cdcnp) = f_s_offset;
    CDCNP_E_OFFSET(cdcnp) = f_s_offset + np_size;
    CDCNP_FNAME(cdcnp)    = NULL_PTR;

    sys_log(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: np is\n");
    cdcnp_header_print(LOGSTDOUT, cdcnp);

    (*s_offset) = f_s_offset + np_size;

    /*erase magic number which would be overrided after flush successfully*/
    if(1)
    {
        UINT32        offset_erase;
        UINT8        *data;
        UINT32        data_len;

        offset_erase = f_s_offset;

        CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_ERR_MAGIC_NUM;/*set to invalid magic temporarily*/

        /*alignment*/
        data     = (UINT8 *)cdcnp_header;
        data_len = CDCPGB_PAGE_SIZE_NBYTES;

        if(EC_FALSE == c_file_pwrite(fd, &offset_erase, data_len, data))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_shm: "
                                                  "erase np magic from fd %d, offset %ld failed\n",
                                                  fd, offset_erase);

            CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM; /*restore to valid magic*/
            return (EC_FALSE);
        }

        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: "
                                              "erase np magic temporarily from fd %d, offset %ld done\n",
                                              fd, offset_erase);

        CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM; /*restore to valid magic*/
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_shm: "
                                          "load np %u done\n",
                                          CDCNP_HEADER_NP_ID(cdcnp_header));

    return (EC_TRUE);
}

/*retrieve np from ssd*/
EC_BOOL cdcnp_retrieve_shm(CDCNP *cdcnp, CMMAP_NODE *cmmap_node, const uint32_t np_id, int fd, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP_HEADER *cdcnp_header;
    CDCNP_BITMAP *cdcnp_bitmap;
    UINT32        f_s_offset;
    UINT32        f_e_offset;

    UINT32        offset;

    UINT32        np_size;

    uint32_t      magic_t;
    uint32_t      np_id_t;
    uint8_t       np_model_t;

    CDCNP_ASSERT(NULL_PTR != cdcnp);

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: no fd\n");
        return (EC_FALSE);
    }

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/

    /*read np id and np model => file size => load whole*/
    if(f_s_offset + 8 > f_e_offset)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: "
                                              "[%ld, %ld) => invalid range [%ld, %ld)\n",
                                              (*s_offset), e_offset,
                                              f_s_offset, f_e_offset);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_load_basic(cdcnp, fd, f_s_offset, &magic_t, &np_id_t, &np_model_t))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: "
                                              "load basic of np %u failed\n",
                                              np_id);
        return (EC_FALSE);
    }

    /*trick: check np id*/
    if(np_id != np_id_t)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: "
                                              "np id mismatched: shm stored %u != %u\n",
                                              np_id_t, np_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                          "np id %u matched\n",
                                          np_id);

    /*trick: check magic number*/
    if(CDCNP_MAGIC_NUM != magic_t)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: "
                                              "np magic mismatched: shm stored %#x != %#x\n",
                                              magic_t, CDCNP_MAGIC_NUM);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                          "np magic %#x matched\n",
                                          magic_t);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                          "np_id %u, np_model %u\n",
                                          np_id_t, np_model_t);

    if(EC_FALSE == cdcnp_model_file_size(np_model_t, &np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: invalid np_model %u\n", np_model_t);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                          "np_model %u, np_size %ld\n",
                                          np_model_t, np_size);

    CDCNP_ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
    np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));

    /*not truncate => map it*/
    cdcnp_header = cmmap_node_alloc(cmmap_node, np_size, CDCNP_MEM_ALIGNMENT, "cdc np header");
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: "
                                              "mmap np %u failed\n",
                                              np_id);
        return (EC_FALSE);
    }

    offset = f_s_offset;

    if(EC_FALSE == cdcnp_header_load(cdcnp_header, np_id, fd, &offset, np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: "
                                              "load np %u from fd %d, offset %ld failed\n",
                                              np_id, fd, f_s_offset);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                          "load np %u from fd %d, offset %ld, size %ld done\n",
                                          np_id, fd, f_s_offset, np_size);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                          "load np %u done\n",
                                          np_id);

    CDCNP_ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));
    CDCNP_ASSERT(np_model_t == CDCNP_HEADER_MODEL(cdcnp_header));
    CDCNP_ASSERT(CDCNP_MAGIC_NUM == CDCNP_HEADER_MAGIC(cdcnp_header));
    CDCNP_ASSERT(f_s_offset + np_size == offset);

    cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);

    CDCNP_HDR(cdcnp)    = cdcnp_header;
    CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;

    /*shortcut*/
    CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
    CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));
    CDCNP_DEG_LIST(cdcnp) = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, CDCNPDEG_ROOT_POS));

    CDCNP_S_OFFSET(cdcnp) = f_s_offset;
    CDCNP_E_OFFSET(cdcnp) = f_s_offset + np_size;
    CDCNP_FNAME(cdcnp)    = NULL_PTR;

    sys_log(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: np is\n");
    cdcnp_header_print(LOGSTDOUT, cdcnp);

    (*s_offset) = f_s_offset + np_size;

    /*erase magic number which would be overrided after flush successfully*/
    if(1)
    {
        UINT32        offset_erase;
        UINT8        *data;
        UINT32        data_len;

        offset_erase = f_s_offset;

        CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_ERR_MAGIC_NUM;/*set to invalid magic temporarily*/

        /*alignment*/
        data     = (UINT8 *)cdcnp_header;
        data_len = CDCPGB_PAGE_SIZE_NBYTES;

        if(EC_FALSE == c_file_pwrite(fd, &offset_erase, data_len, data))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retrieve_shm: "
                                                  "erase np magic from fd %d, offset %ld failed\n",
                                                  fd, offset_erase);

            CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM; /*restore to valid magic*/
            return (EC_FALSE);
        }

        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                              "erase np magic temporarily from fd %d, offset %ld done\n",
                                              fd, offset_erase);

        CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM; /*restore to valid magic*/
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_retrieve_shm: "
                                          "load np %u done\n",
                                          CDCNP_HEADER_NP_ID(cdcnp_header));

    return (EC_TRUE);
}

EC_BOOL cdcnp_flush(CDCNP *cdcnp)
{
    if(NULL_PTR != cdcnp)
    {
        CDCNP_HEADER *cdcnp_header;
        UINT32        offset;
        UINT32        size;

        cdcnp_header = CDCNP_HDR(cdcnp);
        if(NULL_PTR == cdcnp_header)
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush: np header is null\n");
            return (EC_FALSE);
        }

        if(ERR_FD == CDCNP_FD(cdcnp))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush: no fd\n");
            return (EC_FALSE);
        }

        if(BIT_TRUE == CDCNP_DONTDUMP_FLAG(cdcnp))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush: "
                                                  "asked not to flush\n");
            return (EC_FALSE);
        }

        CDCNP_ASSERT(0 == (CDCNP_S_OFFSET(cdcnp) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
        CDCNP_ASSERT(0 == (CDCNP_E_OFFSET(cdcnp) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

        offset = CDCNP_S_OFFSET(cdcnp);
        size   = CDCNP_E_OFFSET(cdcnp) - CDCNP_S_OFFSET(cdcnp);

        if(EC_FALSE == cdcnp_header_flush(cdcnp_header,
                                          CDCNP_HEADER_NP_ID(cdcnp_header),
                                          CDCNP_FD(cdcnp), &offset, size))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush: "
                                                  "flush np %u to fd %d, offset %ld, size %ld failed\n",
                                                  CDCNP_HEADER_NP_ID(cdcnp_header),
                                                  CDCNP_FD(cdcnp),
                                                  CDCNP_S_OFFSET(cdcnp),
                                                  size);
            return (EC_FALSE);
        }

        CDCNP_ASSERT(offset == CDCNP_E_OFFSET(cdcnp));

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_flush: "
                                              "flush np %u (magic %#x) to fd %d, offset %ld => %ld, size %ld done\n",
                                              CDCNP_HEADER_NP_ID(cdcnp_header),
                                              CDCNP_HEADER_MAGIC(cdcnp_header),
                                              CDCNP_FD(cdcnp),
                                              CDCNP_S_OFFSET(cdcnp), offset,
                                              size);
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

/*-------------------------------------------- NP in memory --------------------------------------------*/
CDCNP *cdcnp_create(const uint32_t np_id, const uint8_t np_model, const uint32_t key_max_num, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP           *cdcnp;
    CDCNP_BITMAP    *cdcnp_bitmap;
    CDCNP_HEADER    *cdcnp_header;
    UINT32           f_s_offset;
    UINT32           f_e_offset;
    UINT32           np_size;

    if(EC_FALSE == cdcnp_model_file_size(np_model, &np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_create: "
                                          "np_model %u, np_size %ld\n",
                                          np_model, np_size);

    CDCNP_ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
    np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));      /*align to one page*/

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/

    if(f_e_offset < f_s_offset + np_size)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: "
                                              "model %u, np_size %ld => range [%ld, %ld) cannot accept np\n",
                                              np_model, np_size,
                                              f_s_offset, f_e_offset);
        return (NULL_PTR);
    }

    cdcnp_header = cdcnp_header_new(np_id, np_size, np_model);
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: new cdcnp header failed\n");
        return (NULL_PTR);
    }

    CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM;

    cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);
    if(EC_FALSE == cdcnp_bitmap_init(cdcnp_bitmap, key_max_num))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: np %u init bitmap failed\n", np_id);
        cdcnp_header_free(cdcnp_header);

        return (NULL_PTR);
    }

    cdcnp = cdcnp_new();
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: new np %u failed\n", np_id);
        cdcnp_header_free(cdcnp_header);

        return (NULL_PTR);
    }
    CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;
    CDCNP_HDR(cdcnp)    = cdcnp_header;

    /*shortcut*/
    CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
    CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));
    CDCNP_DEG_LIST(cdcnp) = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, CDCNPDEG_ROOT_POS));

    CDCNP_FD(cdcnp)        = ERR_FD;
    CDCNP_S_OFFSET(cdcnp)  = f_s_offset;
    CDCNP_E_OFFSET(cdcnp)  = f_s_offset + np_size;
    CDCNP_FNAME(cdcnp)     = NULL_PTR;

    (*s_offset) = f_s_offset + np_size;

    CDCNP_ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));

    /*create root item*/
    cdcnp_create_root_item(cdcnp);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_create: create np %u done\n", np_id);

    return (cdcnp);
}

CDCNP *cdcnp_create_shm(CMMAP_NODE *cmmap_node, const uint32_t np_id, const uint8_t np_model, const uint32_t key_max_num, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP           *cdcnp;
    CDCNP_BITMAP    *cdcnp_bitmap;
    CDCNP_HEADER    *cdcnp_header;
    UINT32           f_s_offset;
    UINT32           f_e_offset;
    UINT32           np_size;
    uint32_t         node_max_num;
    uint32_t         node_sizeof;

    if(EC_FALSE == cdcnp_model_file_size(np_model, &np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_shm: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_create_shm: "
                                          "np_model %u, np_size %ld\n",
                                          np_model, np_size);

    CDCNP_ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
    np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));      /*align to one page*/

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/

    if(f_e_offset < f_s_offset + np_size)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_shm: "
                                              "model %u, np_size %ld => range [%ld, %ld) cannot accept np\n",
                                              np_model, np_size,
                                              f_s_offset, f_e_offset);
        return (NULL_PTR);
    }

    cdcnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CDCNP_ITEM);

    if(0 == node_max_num)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_shm: "
                                              "np model %u => node max num = %u is invalid\n",
                                              np_model, node_max_num);
        return (NULL_PTR);
    }


    cdcnp_header = cmmap_node_alloc(cmmap_node, np_size, CDCNP_MEM_ALIGNMENT, "cdc np header");
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_shm: "
                                              "create np failed\n");
        return (NULL_PTR);
    }

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_create_shm: "
                                          "create header %p, size %ld done\n",
                                          cdcnp_header, np_size);

    CDCNP_HEADER_NP_ID(cdcnp_header)        = np_id;
    CDCNP_HEADER_MODEL(cdcnp_header)        = np_model;
    CDCNP_HEADER_DEG_NODE_NUM(cdcnp_header) = 0;

    /*init RB Nodes*/
    cdcnprb_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init LRU nodes*/
    cdcnplru_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cdcnpdel_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init DEG nodes*/
    cdcnpdeg_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    CDCNP_HEADER_MAGIC(cdcnp_header) = CDCNP_MAGIC_NUM;

    cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);
    if(EC_FALSE == cdcnp_bitmap_init(cdcnp_bitmap, key_max_num))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_shm: np %u init bitmap failed\n", np_id);

        return (NULL_PTR);
    }

    cdcnp = cdcnp_new();
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create_shm: new np %u failed\n", np_id);

        return (NULL_PTR);
    }
    CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;
    CDCNP_HDR(cdcnp)    = cdcnp_header;

    /*shortcut*/
    CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
    CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));
    CDCNP_DEG_LIST(cdcnp) = CDCNP_ITEM_DEG_NODE(cdcnp_fetch(cdcnp, CDCNPDEG_ROOT_POS));

    CDCNP_FD(cdcnp)        = ERR_FD;
    CDCNP_S_OFFSET(cdcnp)  = f_s_offset;
    CDCNP_E_OFFSET(cdcnp)  = f_s_offset + np_size;
    CDCNP_FNAME(cdcnp)     = NULL_PTR;

    (*s_offset) = f_s_offset + np_size;

    CDCNP_ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));

    /*create root item*/
    cdcnp_create_root_item(cdcnp);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_create_shm: create np %u done\n", np_id);


    return (cdcnp);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/


