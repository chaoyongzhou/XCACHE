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
#include "cdcnp.h"

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

EC_BOOL cdcnp_model_search(const UINT32 rdisk_size /*in byte*/, uint8_t *cdcnp_model)
{
    UINT32      np_fsize;
    UINT8       cdcnp_model_t;

    /*np file size = ((rdisk size) / (page size)) * (item size)*/
    np_fsize = ((rdisk_size >> CDCPGB_PAGE_SIZE_NBITS) << CDCNP_ITEM_SIZE_NBITS);

    for(cdcnp_model_t = 0; cdcnp_model_t < g_cdcnp_cfg_tbl_len; cdcnp_model_t ++)
    {
        CDCNP_CFG *cdcnp_cfg;
        cdcnp_cfg = &(g_cdcnp_cfg_tbl[ cdcnp_model_t ]);

        if(np_fsize <= CDCNP_CFG_FILE_SIZE(cdcnp_cfg))
        {
            (*cdcnp_model) = cdcnp_model_t;

            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "[DEBUG] cdcnp_model_search: "
                                                  "rdisk size %ld => np model %u, "
                                                  "where page size %u, item size %u\n",
                                                  rdisk_size, (*cdcnp_model),
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
    uint32_t pos;

    CDCNP_FNODE_FILESZ(cdcnp_fnode) = 0;
    CDCNP_FNODE_REPNUM(cdcnp_fnode) = 0;
    CDCNP_FNODE_HASH(cdcnp_fnode)   = 0;

    for(pos = 0; pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_init(CDCNP_FNODE_INODE(cdcnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_clean(CDCNP_FNODE *cdcnp_fnode)
{
    uint32_t pos;

    CDCNP_FNODE_FILESZ(cdcnp_fnode) = 0;
    CDCNP_FNODE_REPNUM(cdcnp_fnode) = 0;
    CDCNP_FNODE_HASH(cdcnp_fnode)   = 0;

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
    uint32_t pos;

    CDCNP_FNODE_FILESZ(cdcnp_fnode_des) = CDCNP_FNODE_FILESZ(cdcnp_fnode_src);
    CDCNP_FNODE_REPNUM(cdcnp_fnode_des) = CDCNP_FNODE_REPNUM(cdcnp_fnode_src);
    CDCNP_FNODE_HASH(cdcnp_fnode_des)   = CDCNP_FNODE_HASH(cdcnp_fnode_src);

    for(pos = 0; pos < CDCNP_FNODE_REPNUM(cdcnp_fnode_src) && pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_clone(CDCNP_FNODE_INODE(cdcnp_fnode_src, pos), CDCNP_FNODE_INODE(cdcnp_fnode_des, pos));
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_check_inode_exist(const CDCNP_INODE *inode, const CDCNP_FNODE *cdcnp_fnode)
{
    uint32_t replica_pos;

    for(replica_pos = 0; replica_pos < CDCNP_FNODE_REPNUM(cdcnp_fnode); replica_pos ++)
    {
        if( CDCNP_INODE_DISK_NO(inode)    == CDCNP_FNODE_INODE_DISK_NO(cdcnp_fnode, replica_pos)
         && CDCNP_INODE_BLOCK_NO(inode)   == CDCNP_FNODE_INODE_BLOCK_NO(cdcnp_fnode, replica_pos)
         && CDCNP_INODE_PAGE_NO(inode)    == CDCNP_FNODE_INODE_PAGE_NO(cdcnp_fnode, replica_pos)
        )
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_fnode_cmp(const CDCNP_FNODE *cdcnp_fnode_1st, const CDCNP_FNODE *cdcnp_fnode_2nd)
{
    uint32_t replica_pos;

    if(NULL_PTR == cdcnp_fnode_1st && NULL_PTR == cdcnp_fnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cdcnp_fnode_1st || NULL_PTR == cdcnp_fnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CDCNP_FNODE_REPNUM(cdcnp_fnode_1st) != CDCNP_FNODE_REPNUM(cdcnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CDCNP_FNODE_FILESZ(cdcnp_fnode_1st) != CDCNP_FNODE_FILESZ(cdcnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CDCNP_FNODE_HASH(cdcnp_fnode_1st) != CDCNP_FNODE_HASH(cdcnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    for(replica_pos = 0; replica_pos < CDCNP_FNODE_REPNUM(cdcnp_fnode_1st); replica_pos ++)
    {
        if(EC_FALSE == cdcnp_fnode_check_inode_exist(CDCNP_FNODE_INODE(cdcnp_fnode_1st, replica_pos), cdcnp_fnode_2nd))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_fnode_import(const CDCNP_FNODE *cdcnp_fnode_src, CDCNP_FNODE *cdcnp_fnode_des)
{
    uint32_t src_pos;
    uint32_t des_pos;

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

    CDCNP_FNODE_FILESZ(cdcnp_fnode_des) = CDCNP_FNODE_FILESZ(cdcnp_fnode_src);
    CDCNP_FNODE_REPNUM(cdcnp_fnode_des) = des_pos;
    CDCNP_FNODE_HASH(cdcnp_fnode_des)   = CDCNP_FNODE_HASH(cdcnp_fnode_src);
    return (EC_TRUE);
}

void cdcnp_fnode_print(LOG *log, const CDCNP_FNODE *cdcnp_fnode)
{
    uint32_t pos;

    sys_log(log, "cdcnp_fnode %p: file size %u, replica num %u, hash %x\n",
                    cdcnp_fnode,
                    CDCNP_FNODE_FILESZ(cdcnp_fnode),
                    CDCNP_FNODE_REPNUM(cdcnp_fnode),
                    CDCNP_FNODE_HASH(cdcnp_fnode)
                    );

    for(pos = 0; pos < CDCNP_FNODE_REPNUM(cdcnp_fnode) && pos < CDCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdcnp_inode_print(log, CDCNP_FNODE_INODE(cdcnp_fnode, pos));
    }
    return;
}

void cdcnp_fnode_log(LOG *log, const CDCNP_FNODE *cdcnp_fnode)
{
    uint32_t pos;

    sys_print_no_lock(log, "size %u, replica %u, hash %x",
                    CDCNP_FNODE_FILESZ(cdcnp_fnode),
                    CDCNP_FNODE_REPNUM(cdcnp_fnode),
                    CDCNP_FNODE_HASH(cdcnp_fnode)
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
    CDCNP_ITEM_DIR_FLAG(cdcnp_item)         = CDCNP_ITEM_FILE_IS_ERR;
    CDCNP_ITEM_USED_FLAG(cdcnp_item)        = CDCNP_ITEM_IS_NOT_USED;
    CDCNP_ITEM_PARENT_POS(cdcnp_item)       = CDCNPRB_ERR_POS;/*fix*/

    cdcnp_fnode_init(CDCNP_ITEM_FNODE(cdcnp_item));

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cdcnp_item_clean(CDCNP_ITEM *cdcnp_item)
{
    CDCNP_ITEM_DIR_FLAG(cdcnp_item)         = CDCNP_ITEM_FILE_IS_ERR;
    CDCNP_ITEM_USED_FLAG(cdcnp_item)        = CDCNP_ITEM_IS_NOT_USED;
    CDCNP_ITEM_PARENT_POS(cdcnp_item)       = CDCNPRB_ERR_POS;/*fix bug: break pointer to parent*/

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

    CDCNP_ITEM_USED_FLAG(cdcnp_item_des)   =  CDCNP_ITEM_USED_FLAG(cdcnp_item_src);
    CDCNP_ITEM_DIR_FLAG(cdcnp_item_des)    =  CDCNP_ITEM_DIR_FLAG(cdcnp_item_src);
    CDCNP_ITEM_PARENT_POS(cdcnp_item_des)  = CDCNP_ITEM_PARENT_POS(cdcnp_item_src);

    cdcnplru_node_clone(CDCNP_ITEM_LRU_NODE(cdcnp_item_src), CDCNP_ITEM_LRU_NODE(cdcnp_item_des));
    cdcnpdel_node_clone(CDCNP_ITEM_DEL_NODE(cdcnp_item_src), CDCNP_ITEM_DEL_NODE(cdcnp_item_des));

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
    uint32_t pos;

    sys_print(log, "cdcnp_item %p: flag 0x%x [%s], stat %u "
                   "parent %u, lru node (%u, %u), del node (%u, %u)\n",
                    cdcnp_item,
                    CDCNP_ITEM_DIR_FLAG(cdcnp_item), __cdcnp_item_dir_flag_str(CDCNP_ITEM_DIR_FLAG(cdcnp_item)),
                    CDCNP_ITEM_USED_FLAG(cdcnp_item),
                    CDCNP_ITEM_PARENT_POS(cdcnp_item),
                    CDCNPLRU_NODE_PREV_POS(CDCNP_ITEM_LRU_NODE(cdcnp_item)),
                    CDCNPLRU_NODE_NEXT_POS(CDCNP_ITEM_LRU_NODE(cdcnp_item)),
                    CDCNPDEL_NODE_PREV_POS(CDCNP_ITEM_DEL_NODE(cdcnp_item)),
                    CDCNPDEL_NODE_NEXT_POS(CDCNP_ITEM_DEL_NODE(cdcnp_item))
                    );

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;

        cdcnp_fnode = (CDCNP_FNODE *)CDCNP_ITEM_FNODE(cdcnp_item);
        sys_log(log, "file size %u, replica num %u, hash %x\n",
                        CDCNP_FNODE_FILESZ(cdcnp_fnode),
                        CDCNP_FNODE_REPNUM(cdcnp_fnode),
                        CDCNP_FNODE_HASH(cdcnp_fnode)
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
    uint32_t pos;

    sys_print(log, "cdcnp_item %p: flag 0x%x [%s], stat %u\n",
                    cdcnp_item,
                    CDCNP_ITEM_DIR_FLAG(cdcnp_item), __cdcnp_item_dir_flag_str(CDCNP_ITEM_DIR_FLAG(cdcnp_item)),
                    CDCNP_ITEM_USED_FLAG(cdcnp_item)
                    );

    sys_log(log, "key: [%u, %u)\n",
                 CDCNP_ITEM_S_PAGE(cdcnp_item),
                 CDCNP_ITEM_E_PAGE(cdcnp_item));

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;

        cdcnp_fnode = (CDCNP_FNODE *)CDCNP_ITEM_FNODE(cdcnp_item);
        sys_log(log, "file size %u, replica num %u, hash %x\n",
                        CDCNP_FNODE_FILESZ(cdcnp_fnode),
                        CDCNP_FNODE_REPNUM(cdcnp_fnode),
                        CDCNP_FNODE_HASH(cdcnp_fnode)
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
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_set: overflow bit_pos %ld > %ld\n",
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
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_clear: overflow bit_pos %ld > %ld\n",
                        bit_pos, CDCNP_BITMAP_SIZE(cdcnp_bitmap));
        return (EC_FALSE);
    }

    if(0 == (CDCNP_BITMAP_DATA(cdcnp_bitmap)[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_clear: it_pos %ld was NOT set!\n",
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
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_get: overflow bit_pos %ld > %ld\n",
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
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_bitmap_is: overflow bit_pos %ld > %ld\n",
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

CDCNP_AIO *cdcnp_aio_new()
{
    CDCNP_AIO *cdcnp_aio;

    alloc_static_mem(MM_CDCNP_AIO, &cdcnp_aio, LOC_CDCNP_0010);
    if(NULL_PTR != cdcnp_aio)
    {
        cdcnp_aio_init(cdcnp_aio);
        return (cdcnp_aio);
    }
    return (cdcnp_aio);
}

EC_BOOL cdcnp_aio_init(CDCNP_AIO *cdcnp_aio)
{
    CDCNP_AIO_CDCNP(cdcnp_aio)          = NULL_PTR;
    CDCNP_AIO_NP_ID(cdcnp_aio)          = CDCNP_ERR_ID;
    CDCNP_AIO_NP_MODEL(cdcnp_aio)       = CDCNP_ERR_MODEL;
    CDCNP_AIO_NP_SIZE(cdcnp_aio)        = 0;
    CDCNP_AIO_FD(cdcnp_aio)             = ERR_FD;
    CDCNP_AIO_I_S_OFFSET(cdcnp_aio)     = NULL_PTR;
    CDCNP_AIO_F_S_OFFSET(cdcnp_aio)     = CDCNP_OFFSET_ERR;
    CDCNP_AIO_F_E_OFFSET(cdcnp_aio)     = CDCNP_OFFSET_ERR;
    CDCNP_AIO_S_OFFSET(cdcnp_aio)       = CDCNP_OFFSET_ERR;
    CDCNP_AIO_E_OFFSET(cdcnp_aio)       = CDCNP_OFFSET_ERR;
    CDCNP_AIO_C_OFFSET(cdcnp_aio)       = CDCNP_OFFSET_ERR;
    CDCNP_AIO_M_BUFF(cdcnp_aio)         = NULL_PTR;

    BSET(CDCNP_AIO_M_DATA(cdcnp_aio), 0xCD, 8);

    caio_cb_init(CDCNP_AIO_CAIO_CB(cdcnp_aio));

    return (EC_TRUE);
}

EC_BOOL cdcnp_aio_clean(CDCNP_AIO *cdcnp_aio)
{
    CDCNP_AIO_CDCNP(cdcnp_aio)          = NULL_PTR;
    CDCNP_AIO_NP_ID(cdcnp_aio)          = CDCNP_ERR_ID;
    CDCNP_AIO_NP_MODEL(cdcnp_aio)       = CDCNP_ERR_MODEL;
    CDCNP_AIO_NP_SIZE(cdcnp_aio)        = 0;
    CDCNP_AIO_FD(cdcnp_aio)             = ERR_FD;
    CDCNP_AIO_I_S_OFFSET(cdcnp_aio)     = NULL_PTR;
    CDCNP_AIO_F_S_OFFSET(cdcnp_aio)     = CDCNP_OFFSET_ERR;
    CDCNP_AIO_F_E_OFFSET(cdcnp_aio)     = CDCNP_OFFSET_ERR;
    CDCNP_AIO_S_OFFSET(cdcnp_aio)       = CDCNP_OFFSET_ERR;
    CDCNP_AIO_E_OFFSET(cdcnp_aio)       = CDCNP_OFFSET_ERR;
    CDCNP_AIO_C_OFFSET(cdcnp_aio)       = CDCNP_OFFSET_ERR;
    CDCNP_AIO_M_BUFF(cdcnp_aio)         = NULL_PTR;

    BSET(CDCNP_AIO_M_DATA(cdcnp_aio), 0xCD, 8);

    caio_cb_clean(CDCNP_AIO_CAIO_CB(cdcnp_aio));

    return (EC_TRUE);
}

EC_BOOL cdcnp_aio_free(CDCNP_AIO *cdcnp_aio)
{
    if(NULL_PTR != cdcnp_aio)
    {
        cdcnp_aio_clean(cdcnp_aio);
        free_static_mem(MM_CDCNP_AIO, cdcnp_aio, LOC_CDCNP_0011);
    }
    return (EC_TRUE);
}

void cdcnp_aio_print(LOG *log, const CDCNP_AIO *cdcnp_aio)
{
    if(NULL_PTR != cdcnp_aio)
    {
        sys_log(log, "cdcnp_aio_print: cdcnp_aio %p: np %u, model %s, size %ld, "
                     "file range [%ld, %ld), "
                     "aio range [%ld, %ld), reached %ld\n",
                     cdcnp_aio,
                     CDCNP_AIO_NP_ID(cdcnp_aio),
                     cdcnp_model_str(CDCNP_AIO_NP_MODEL(cdcnp_aio)),
                     CDCNP_AIO_NP_SIZE(cdcnp_aio),
                     CDCNP_AIO_F_S_OFFSET(cdcnp_aio),
                     CDCNP_AIO_F_E_OFFSET(cdcnp_aio),
                     CDCNP_AIO_S_OFFSET(cdcnp_aio),
                     CDCNP_AIO_E_OFFSET(cdcnp_aio),
                     CDCNP_AIO_C_OFFSET(cdcnp_aio));
    }
    return;
}

CDCNP_HEADER *cdcnp_header_new(const uint32_t np_id, const UINT32 fsize, const uint8_t np_model)
{
    CDCNP_HEADER *cdcnp_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    cdcnp_header = (CDCNP_HEADER *)c_memalign_new(fsize, CAIO_SECTOR_SIZE_NBYTE);
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_header_new: "
                                              "new header with %ld bytes for np %u failed\n",
                                              fsize, np_id);
        return (NULL_PTR);
    }

    CDCNP_HEADER_NP_ID(cdcnp_header)  = np_id;
    CDCNP_HEADER_MODEL(cdcnp_header)  = np_model;

    cdcnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CDCNP_ITEM);

    /*init RB Nodes*/
    cdcnprb_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init LRU nodes*/
    cdcnplru_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cdcnpdel_pool_init(CDCNP_HEADER_ITEMS_POOL(cdcnp_header), node_max_num, node_sizeof);

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

CDCNP *cdcnp_new()
{
    CDCNP *cdcnp;

    alloc_static_mem(MM_CDCNP, &cdcnp, LOC_CDCNP_0012);
    if(NULL_PTR != cdcnp)
    {
        cdcnp_init(cdcnp);
    }
    return (cdcnp);
}

EC_BOOL cdcnp_init(CDCNP *cdcnp)
{
    CDCNP_FD(cdcnp)              = ERR_FD;
    CDCNP_S_OFFSET(cdcnp)        = CDCNP_OFFSET_ERR;
    CDCNP_E_OFFSET(cdcnp)        = CDCNP_OFFSET_ERR;
    CDCNP_FNAME(cdcnp)           = NULL_PTR;
    CDCNP_CAIO_MD(cdcnp)         = NULL_PTR;
    CDCNP_DEL_SIZE(cdcnp)        = 0;
    CDCNP_RECYCLE_SIZE(cdcnp)    = 0;
    CDCNP_BITMAP(cdcnp)          = NULL_PTR;
    CDCNP_HDR(cdcnp)             = NULL_PTR;
    CDCNP_LRU_LIST(cdcnp)        = NULL_PTR;
    CDCNP_DEL_LIST(cdcnp)        = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdcnp_clean(CDCNP *cdcnp)
{
    if(NULL_PTR != CDCNP_HDR(cdcnp))
    {
        cdcnp_header_free(CDCNP_HDR(cdcnp));
        CDCNP_HDR(cdcnp) = NULL_PTR;
    }
    CDCNP_BITMAP(cdcnp)       = NULL_PTR;

    CDCNP_FD(cdcnp)           = ERR_FD;
    CDCNP_S_OFFSET(cdcnp)     = CDCNP_OFFSET_ERR;
    CDCNP_E_OFFSET(cdcnp)     = CDCNP_OFFSET_ERR;

    ASSERT(NULL_PTR == CDCNP_FNAME(cdcnp));
    CDCNP_CAIO_MD(cdcnp)      = NULL_PTR;

    CDCNP_DEL_SIZE(cdcnp)     = 0;
    CDCNP_RECYCLE_SIZE(cdcnp) = 0;

    CDCNP_LRU_LIST(cdcnp)     = NULL_PTR;
    CDCNP_DEL_LIST(cdcnp)     = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdcnp_free(CDCNP *cdcnp)
{
    if(NULL_PTR != cdcnp)
    {
        cdcnp_clean(cdcnp);
        free_static_mem(MM_CDCNP, cdcnp, LOC_CDCNP_0013);
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

    sys_log(log, "np %u, model %u, item max num %u, item used num %u\n",
                CDCNP_HEADER_NP_ID(cdcnp_header),
                CDCNP_HEADER_MODEL(cdcnp_header),
                CDCNP_HEADER_ITEMS_MAX_NUM(cdcnp_header),
                CDCNP_HEADER_ITEMS_USED_NUM(cdcnp_header)
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

uint32_t cdcnp_dnode_find_intersected(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, const CDCNP_KEY *cdcnp_key)
{
    const CDCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CDCNP_ITEMS_POOL(cdcnp);
    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);

    return cdcnprb_tree_find_intersected_data(pool, root_pos, cdcnp_key);
}

uint32_t cdcnp_dnode_find_closest(const CDCNP *cdcnp, const CDCNP_DNODE *cdcnp_dnode, const CDCNP_KEY *cdcnp_key)
{
    const CDCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CDCNP_ITEMS_POOL(cdcnp);
    root_pos = CDCNP_DNODE_ROOT_POS(cdcnp_dnode);

    return cdcnprb_tree_find_closest_data(pool, root_pos, cdcnp_key);
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
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_dnode_insert: cdcnp is full\n");
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

    CDCNP_ITEM_USED_FLAG(cdcnp_item_insert) = CDCNP_ITEM_IS_USED;

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

    ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cdcnp_item = cdcnp_fetch(cdcnp, CDCNPRB_ROOT_POS);
    ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    node_pos = cdcnp_dnode_search(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item), cdcnp_key);

    return (node_pos);
}

void cdcnp_walk(CDCNP *cdcnp, void (*walker)(void *, const void *, const uint32_t), void *arg)
{
    CDCNP_ITEM  *cdcnp_item;

    /*root item*/
    cdcnp_item = cdcnp_fetch(cdcnp, CDCNPRB_ROOT_POS);
    ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    cdcnp_dnode_walk(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item), walker, arg);

    return;
}

uint32_t cdcnp_find_intersected(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    CDCNP_ITEM  *cdcnp_item;
    uint32_t     node_pos;

    ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cdcnp_item = cdcnp_fetch(cdcnp, CDCNPRB_ROOT_POS);
    ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    node_pos = cdcnp_dnode_find_intersected(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item), cdcnp_key);

    return (node_pos);
}

uint32_t cdcnp_find_closest(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    CDCNP_ITEM  *cdcnp_item;
    uint32_t     node_pos;

    ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cdcnp_item = cdcnp_fetch(cdcnp, CDCNPRB_ROOT_POS);
    ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    node_pos = cdcnp_dnode_find_closest(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item), cdcnp_key);

    return (node_pos);
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

    ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

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
    uint32_t replica;

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

CDCNP_ITEM *cdcnp_set(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    uint32_t     node_pos;
    CDCNP_ITEM  *cdcnp_item;

    node_pos = cdcnp_insert(cdcnp, cdcnp_key, dflag);
    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
    if(NULL_PTR != cdcnp_item)
    {
        if(EC_FALSE == cdcnp_key_cmp(cdcnp_key, CDCNP_ITEM_KEY(cdcnp_item)))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_set: mismatched key [%ld, %ld) ! = [%ld, %ld)=> not override\n",
                            CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key),
                            CDCNP_KEY_S_PAGE(CDCNP_ITEM_KEY(cdcnp_item)), CDCNP_KEY_E_PAGE(CDCNP_ITEM_KEY(cdcnp_item)));
            return (NULL_PTR);
        }

        /*ensure only item of regular file enter LRU list*/
        if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
        {
            cdcnplru_node_add_head(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);
        }
        return (cdcnp_item);
    }
    return (NULL_PTR);
}

CDCNP_ITEM *cdcnp_get(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    return cdcnp_fetch(cdcnp, cdcnp_search(cdcnp, cdcnp_key, dflag));
}

CDCNP_FNODE *cdcnp_reserve(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ITEM *cdcnp_item;

    cdcnp_item = cdcnp_set(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_reserve: set to np failed\n");
        return (NULL_PTR);
    }

    ASSERT(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    cdcnp_reserve_key(cdcnp, CDCNP_ITEM_KEY(cdcnp_item));

    /*not import yet*/
    return CDCNP_ITEM_FNODE(cdcnp_item);
}

EC_BOOL cdcnp_release(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    if(EC_FALSE == cdcnp_delete(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_release: delete from np failed\n");
        return (EC_FALSE);
    }

    cdcnp_release_key(cdcnp, cdcnp_key);

    return (EC_TRUE);
}

EC_BOOL cdcnp_has_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    ASSERT(NULL_PTR != CDCNP_BITMAP(cdcnp));

    return cdcnp_bitmap_is(CDCNP_BITMAP(cdcnp), CDCNP_KEY_S_PAGE(cdcnp_key), (uint8_t)1);
}

EC_BOOL cdcnp_set_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    ASSERT(NULL_PTR != CDCNP_BITMAP(cdcnp));

    return cdcnp_bitmap_set(CDCNP_BITMAP(cdcnp), CDCNP_KEY_S_PAGE(cdcnp_key));
}

EC_BOOL cdcnp_clear_key(const CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key)
{
    ASSERT(NULL_PTR != CDCNP_BITMAP(cdcnp));

    return cdcnp_bitmap_clear(CDCNP_BITMAP(cdcnp), CDCNP_KEY_S_PAGE(cdcnp_key));
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

        cdcnplru_node_move_head(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_update(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const CDCNP_FNODE *cdcnp_fnode)
{
    uint32_t node_pos;

    node_pos = cdcnp_search(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM *cdcnp_item;

        cdcnp_item = cdcnp_fetch(cdcnp, node_pos);
        cdcnplru_node_move_head(cdcnp, CDCNP_ITEM_LRU_NODE(cdcnp_item), node_pos);
        return cdcnp_fnode_import(cdcnp_fnode, CDCNP_ITEM_FNODE(cdcnp_item));
    }
    return (EC_FALSE);
}

EC_BOOL cdcnp_delete(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    CDCNP_ITEM *cdcnp_item;
    uint32_t node_pos;

    ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

    node_pos = cdcnp_search(cdcnp, cdcnp_key, dflag);
    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

    if(NULL_PTR == cdcnp_item)
    {
        return (EC_FALSE);
    }

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        if(CDCNPRB_ERR_POS != CDCNP_ITEM_PARENT_POS(cdcnp_item))
        {
            CDCNP_ITEM  *cdcnp_item_parent;
            uint32_t     node_pos_t;

            cdcnp_item_parent = cdcnp_fetch(cdcnp, CDCNP_ITEM_PARENT_POS(cdcnp_item));
            node_pos_t = cdcnp_dnode_umount_son(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item_parent), node_pos,
                                                  CDCNP_ITEM_KEY(cdcnp_item));

            //ASSERT(CDCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CDCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                cdcnprb_node_free(CDCNP_ITEMS_POOL(cdcnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_delete: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CDCNP_ID(cdcnp),
                                node_pos, CDCNP_ITEM_PARENT_POS(cdcnp_item), node_pos_t);

                CDCNP_ITEM_PARENT_POS(cdcnp_item) = CDCNPRB_ERR_POS; /*fix*/
            }
        }

        cdcnp_item_clean(cdcnp_item);

        return (EC_TRUE);
    }

    if(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        if(CDCNPRB_ERR_POS != CDCNP_ITEM_PARENT_POS(cdcnp_item))
        {
            CDCNP_ITEM *cdcnp_item_parent;
            uint32_t     node_pos_t;

            cdcnp_item_parent = cdcnp_fetch(cdcnp, CDCNP_ITEM_PARENT_POS(cdcnp_item));

            node_pos_t = cdcnp_dnode_umount_son(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item_parent), node_pos,
                                                CDCNP_ITEM_KEY(cdcnp_item));

            //ASSERT(CDCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CDCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                cdcnp_dnode_delete_dir_son(cdcnp, CDCNP_ITEM_DNODE(cdcnp_item));

                cdcnprb_node_free(CDCNP_ITEMS_POOL(cdcnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_delete: np %u, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CDCNP_ID(cdcnp),
                                node_pos, CDCNP_ITEM_PARENT_POS(cdcnp_item), node_pos_t);

                CDCNP_ITEM_PARENT_POS(cdcnp_item) = CDCNPRB_ERR_POS; /*fix*/
            }
        }

        cdcnp_item_clean(cdcnp_item);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcnp_retire(CDCNP *cdcnp, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CDCNPLRU_NODE  *cdcnplru_node_head;
    UINT32   retire_num;

    cdcnplru_node_head = CDCNP_LRU_LIST(cdcnp);

    for(retire_num = 0; retire_num < expect_retire_num && EC_FALSE == cdcnp_lru_list_is_empty(cdcnp);)
    {
        uint32_t node_pos;

        CDCNP_ITEM *cdcnp_item;

        node_pos = CDCNPLRU_NODE_PREV_POS(cdcnplru_node_head);
        cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

        ASSERT(EC_TRUE == cdcnprb_node_is_used(CDCNP_ITEMS_POOL(cdcnp), node_pos));
        ASSERT(CDCNP_ITEM_IS_USED == CDCNP_ITEM_USED_FLAG(cdcnp_item));

        ASSERT(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

        if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
        {
            /*retire file*/
            if(EC_FALSE == cdcnp_umount_item(cdcnp, node_pos))
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_retire: np %u node_pos %d [REG] failed\n",
                                CDCNP_ID(cdcnp), node_pos);
                return (EC_FALSE);
            }

            dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_retire: np %u node_pos %d [REG] done\n",
                            CDCNP_ID(cdcnp), node_pos);
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

EC_BOOL cdcnp_umount_item(CDCNP *cdcnp, const uint32_t node_pos)
{
    CDCNP_ITEM *cdcnp_item;

    cdcnp_item = cdcnp_fetch(cdcnp, node_pos);

    if(NULL_PTR == cdcnp_item)
    {
        return (EC_FALSE);
    }

    ASSERT(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;

        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
        CDCNP_DEL_SIZE(cdcnp) += CDCNP_FNODE_FILESZ(cdcnp_fnode);

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
            cdcnpdel_node_add_tail(cdcnp, CDCNP_ITEM_DEL_NODE(cdcnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdcnp_umount(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, const uint32_t dflag)
{
    uint32_t node_pos;

    ASSERT(CDCNP_ITEM_FILE_IS_REG == dflag);

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
    ASSERT(NULL_PTR != cdcnp_item);
    ASSERT(CDCNP_ITEM_FILE_IS_DIR == CDCNP_ITEM_DIR_FLAG(cdcnp_item));

    cdcnp_dnode = CDCNP_ITEM_DNODE(cdcnp_item);

    (*file_num) = CDCNP_DNODE_FILE_NUM(cdcnp_dnode);
    return (EC_TRUE);
}

EC_BOOL cdcnp_file_size(CDCNP *cdcnp, const CDCNP_KEY *cdcnp_key, UINT32 *file_size)
{
    CDCNP_ITEM *cdcnp_item;

    cdcnp_item = cdcnp_get(cdcnp, cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cdcnp_item)
    {
        (*file_size) = 0;
        return (EC_FALSE);
    }

    if(CDCNP_ITEM_FILE_IS_REG == CDCNP_ITEM_DIR_FLAG(cdcnp_item))
    {
        CDCNP_FNODE *cdcnp_fnode;
        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);

        (*file_size) = CDCNP_FNODE_FILESZ(cdcnp_fnode);
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
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_recycle_item_file: recycle dn (disk %u, block %u, page %u, size %u) failed\n",
                            CDCNP_INODE_DISK_NO(cdcnp_inode),
                            CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                            CDCNP_INODE_PAGE_NO(cdcnp_inode),
                            CDCNP_FNODE_FILESZ(cdcnp_fnode));
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

        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);

        if(EC_FALSE == cdcnp_recycle_item_file(cdcnp, cdcnp_item, node_pos, cdcnp_recycle_np, cdcnp_recycle_dn))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_recycle_item: recycle regular file failed where cdcnp_item is\n");
            cdcnp_item_and_key_print(LOGSTDOUT, cdcnp_item);

            /*should never reach here*/
            cdcnp_item_clean(cdcnp_item);

            return (EC_FALSE);
        }

        /*CDCNP_DEL_SIZE(cdcnp) -= CDCNP_FNODE_FILESZ(cdcnp_fnode);*/
        CDCNP_RECYCLE_SIZE(cdcnp) += CDCNP_FNODE_FILESZ(cdcnp_fnode);

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

        ASSERT(CDCNPRB_ERR_POS == CDCNP_ITEM_PARENT_POS(cdcnp_item));

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
    if(EC_FALSE == c_file_load(fd, offset, fsize, (UINT8 *)cdcnp_header))
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
        if(EC_FALSE == c_file_flush(fd, offset, fsize, (const UINT8 *)cdcnp_header))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_header_flush: "
                                                  "flush cdcnp_hdr %p of np %u to fd %d with fsize %ld failed\n",
                                                  cdcnp_header, np_id, fd, fsize);
            return (EC_FALSE);
        }

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_header_flush: "
                                              "flush cdcnp_hdr %p of np %u to fd %d with size %ld done\n",
                                              cdcnp_header, np_id, fd, fsize);
        return (EC_TRUE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcnp_load(CDCNP *cdcnp, const uint32_t np_id, int fd, UINT32 *s_offset, UINT32 e_offset)
{
    if(NULL_PTR != cdcnp)
    {
        CDCNP_HEADER *cdcnp_header;
        CDCNP_BITMAP *cdcnp_bitmap;
        UINT32        f_s_offset;
        UINT32        f_e_offset;

        UINT32        offset;
        UINT8        *data;
        UINT32        data_len;

        UINT32        np_size;
        uint8_t       np_model;

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

        data_len = CAIO_SECTOR_SIZE_NBYTE;
        data = (UINT8 *)c_memalign_new(data_len, (UINT32)CAIO_SECTOR_SIZE_NBYTE);
        if(NULL_PTR == data)
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                                  "new %ld bytes for np %u failed\n",
                                                  (UINT32)CAIO_SECTOR_SIZE_NBYTE, np_id);
            return (EC_FALSE);
        }

        offset = f_s_offset;
        if(EC_FALSE == c_file_load(fd, &offset, data_len, (UINT8 *)data))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                                  "load %ld bytes from fd %d, offset %ld failed\n",
                                                  data_len, fd, f_s_offset);
            c_memalign_free(data);
            return (EC_FALSE);
        }

        /*trick*/
        if(np_id != CDCNP_HEADER_NP_ID((CDCNP_HEADER *)data))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                                  "np mismatched: given %u, stored %u "
                                                  "from fd %d, offset %ld\n",
                                                  np_id, CDCNP_HEADER_NP_ID((CDCNP_HEADER *)data),
                                                  fd, f_s_offset);
            c_memalign_free(data);
            return (EC_FALSE);
        }

        np_model = CDCNP_HEADER_MODEL((CDCNP_HEADER *)data);

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                              "np_id %u, np_model %u from fd %d, offset %ld\n",
                                              np_id, np_model, fd, f_s_offset);

        if(EC_FALSE == cdcnp_model_file_size(np_model, &np_size))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: invalid np_model %u\n", np_model);

            c_memalign_free(data);
            return (EC_FALSE);
        }

        c_memalign_free(data);

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                              "np_model %u, np_size %ld\n",
                                              np_model, np_size);

        ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
        np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));

        offset = f_s_offset;

        cdcnp_header = cdcnp_header_new(np_id, np_size, np_model);
        if(NULL_PTR == cdcnp_header)
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load: "
                                                  "malloc %ld bytes failed for loading np %u from fd %d\n",
                                                  np_size, np_id, fd);
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

        ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));
        ASSERT(np_model == CDCNP_HEADER_MODEL(cdcnp_header));
        ASSERT(f_s_offset + np_size == offset);

        cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);

        CDCNP_HDR(cdcnp)    = cdcnp_header;
        CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;

        /*shortcut*/
        CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
        CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));

        CDCNP_S_OFFSET(cdcnp) = f_s_offset;
        CDCNP_E_OFFSET(cdcnp) = f_s_offset + np_size;
        CDCNP_FNAME(cdcnp)    = NULL_PTR;

        (*s_offset) = f_s_offset + np_size;

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load: "
                                              "load np %u, fsize %ld from fd %d, offset %ld => %ld done\n",
                                              CDCNP_HEADER_NP_ID(cdcnp_header),
                                              np_size, fd, f_s_offset, offset);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_load_aio_2nd_timeout(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB      caio_cb;
    //CDCNP       *cdcnp;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_load_aio_2nd_timeout: "
                                          "load np from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));
    //cdcnp = CDCNP_AIO_CDCNP(cdcnp_aio);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_load_aio_2nd_terminate(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB      caio_cb;
    //CDCNP       *cdcnp;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_load_aio_terminate: "
                                          "load cdcpgv from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));
    //cdcnp = CDCNP_AIO_CDCNP(cdcnp_aio);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_terminate_handler(&caio_cb);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_load_aio_2nd_complete(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB          caio_cb;
    CDCNP           *cdcnp;
    CDCNP_HEADER    *cdcnp_header;
    CDCNP_BITMAP    *cdcnp_bitmap;

    dbg_log(SEC_0129_CDCNP, 1)(LOGSTDOUT, "[DEBUG] __cdcnp_load_aio_2nd_complete: "
                                          "load cdcpgv from offset %ld, size %ld done, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));
    cdcnp = CDCNP_AIO_CDCNP(cdcnp_aio);

    ASSERT(NULL_PTR != CDCNP_CAIO_MD(cdcnp));

    cdcnp_header = (CDCNP_HEADER *)CDCNP_AIO_M_BUFF(cdcnp_aio);

    ASSERT(CDCNP_AIO_NP_ID(cdcnp_aio)    == CDCNP_HEADER_NP_ID(cdcnp_header));
    ASSERT(CDCNP_AIO_NP_MODEL(cdcnp_aio) == CDCNP_HEADER_MODEL(cdcnp_header));
    ASSERT(CDCNP_AIO_F_S_OFFSET(cdcnp_aio) + CDCNP_AIO_NP_SIZE(cdcnp_aio) == CDCNP_AIO_C_OFFSET(cdcnp_aio));

    cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);

    CDCNP_HDR(cdcnp)    = cdcnp_header;
    CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;

    /*shortcut*/
    CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
    CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));

    CDCNP_S_OFFSET(cdcnp) = CDCNP_AIO_F_S_OFFSET(cdcnp_aio);
    CDCNP_E_OFFSET(cdcnp) = CDCNP_AIO_F_E_OFFSET(cdcnp_aio);
    CDCNP_FNAME(cdcnp)    = NULL_PTR;

    (*CDCNP_AIO_I_S_OFFSET(cdcnp_aio)) = CDCNP_AIO_E_OFFSET(cdcnp_aio);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] __cdcnp_load_aio_2nd_complete: "
                                          "load np %u, fsize %ld from fd %d, offset %ld => %ld done\n",
                                          CDCNP_HEADER_NP_ID(cdcnp_header),
                                          CDCNP_AIO_NP_SIZE(cdcnp_aio),
                                          CDCNP_AIO_FD(cdcnp_aio),
                                          CDCNP_AIO_F_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_complete_handler(&caio_cb);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_load_aio_1st_timeout(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB      caio_cb;
    //CDCNP       *cdcnp;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_load_aio_1st_timeout: "
                                          "load np from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));
    //cdcnp = CDCNP_AIO_CDCNP(cdcnp_aio);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_load_aio_1st_terminate(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB      caio_cb;
    //CDCNP       *cdcnp;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_load_aio_terminate: "
                                          "load cdcpgv from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));
    //cdcnp = CDCNP_AIO_CDCNP(cdcnp_aio);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_terminate_handler(&caio_cb);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_load_aio_1st_complete(CDCNP_AIO *cdcnp_aio)
{
    CDCNP           *cdcnp;
    CDCNP_HEADER    *cdcnp_header;

    CAIO_CB          caio_cb;

    UINT32           np_size;
    uint8_t          np_model;

    dbg_log(SEC_0129_CDCNP, 1)(LOGSTDOUT, "[DEBUG] __cdcnp_load_aio_1st_complete: "
                                          "load cdcpgv from offset %ld, size %ld done, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));
    cdcnp = CDCNP_AIO_CDCNP(cdcnp_aio);

    ASSERT(NULL_PTR != CDCNP_CAIO_MD(cdcnp));

    /*trick*/
    if(CDCNP_AIO_NP_ID(cdcnp_aio) != CDCNP_HEADER_NP_ID((CDCNP_HEADER *)CDCNP_AIO_M_DATA(cdcnp_aio)))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_load_aio_1st_complete: "
                                              "np mismatched: given %u, stored %u "
                                              "from fd %d, offset %ld\n",
                                              CDCNP_AIO_NP_ID(cdcnp_aio),
                                              CDCNP_HEADER_NP_ID((CDCNP_HEADER *)CDCNP_AIO_M_DATA(cdcnp_aio)),
                                              CDCNP_AIO_FD(cdcnp_aio),
                                              CDCNP_AIO_F_S_OFFSET(cdcnp_aio));

        caio_cb_init(&caio_cb);
        caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

        cdcnp_aio_free(cdcnp_aio);

        caio_cb_exec_terminate_handler(&caio_cb);
        return (EC_FALSE);
    }

    np_model = CDCNP_HEADER_MODEL((CDCNP_HEADER *)CDCNP_AIO_M_DATA(cdcnp_aio));

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] __cdcnp_load_aio_1st_complete: "
                                          "np_id %u, np_model %ld from fd %d, offset %ld\n",
                                          CDCNP_AIO_NP_ID(cdcnp_aio),
                                          np_model,
                                          CDCNP_AIO_FD(cdcnp_aio),
                                          CDCNP_AIO_F_S_OFFSET(cdcnp_aio));

    if(EC_FALSE == cdcnp_model_file_size(np_model, &np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_load_aio_1st_complete: "
                                              "invalid np_model %u\n",
                                              np_model);

        caio_cb_init(&caio_cb);
        caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

        cdcnp_aio_free(cdcnp_aio);

        caio_cb_exec_terminate_handler(&caio_cb);
        return (EC_FALSE);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] __cdcnp_load_aio_1st_complete: "
                                          "np_model %u, np_size %ld\n",
                                          np_model, np_size);

    ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
    np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));

    cdcnp_header = (CDCNP_HEADER *)safe_malloc(np_size, LOC_CDCNP_0014);
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_load_aio_1st_complete: "
                                              "malloc %ld bytes failed for loading np %u from fd %d\n",
                                              np_size,
                                              CDCNP_AIO_NP_ID(cdcnp_aio),
                                              CDCNP_AIO_FD(cdcnp_aio));

        caio_cb_init(&caio_cb);
        caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

        cdcnp_aio_free(cdcnp_aio);

        caio_cb_exec_terminate_handler(&caio_cb);
        return (EC_FALSE);
    }

    /*set cdcnp aio*/
    CDCNP_AIO_NP_MODEL(cdcnp_aio) = np_model;
    CDCNP_AIO_NP_SIZE(cdcnp_aio)  = np_size;
    CDCNP_AIO_E_OFFSET(cdcnp_aio) = CDCNP_AIO_S_OFFSET(cdcnp_aio) + np_size;
    CDCNP_AIO_C_OFFSET(cdcnp_aio) = CDCNP_AIO_S_OFFSET(cdcnp_aio);
    CDCNP_AIO_M_BUFF(cdcnp_aio)   = (UINT8 *)cdcnp_header;

    /*set caio callback*/
    caio_cb_init(&caio_cb);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CDCNP_AIO_TIMEOUT_NSEC /*seconds*/,
                                (CAIO_CALLBACK)__cdcnp_load_aio_2nd_timeout, (void *)cdcnp_aio);

    caio_cb_set_terminate_handler(&caio_cb, (CAIO_CALLBACK)__cdcnp_load_aio_2nd_terminate, (void *)cdcnp_aio);
    caio_cb_set_complete_handler(&caio_cb, (CAIO_CALLBACK)__cdcnp_load_aio_2nd_complete, (void *)cdcnp_aio);


    caio_file_read(CDCNP_CAIO_MD(cdcnp), CDCNP_AIO_FD(cdcnp_aio),
                   &CDCNP_AIO_C_OFFSET(cdcnp_aio),
                   CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                   CDCNP_AIO_M_BUFF(cdcnp_aio),
                   &caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdcnp_load_aio(CDCNP *cdcnp, const uint32_t np_id, int fd, UINT32 *s_offset, UINT32 e_offset, CAIO_CB *caio_cb)
{
    if(NULL_PTR != cdcnp)
    {
        UINT32        f_s_offset;
        UINT32        f_e_offset;

        if(ERR_FD == fd)
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: no fd\n");
            return (EC_FALSE);
        }

        ASSERT(NULL_PTR != CDCNP_CAIO_MD(cdcnp));

        f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
        f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/

        if(NULL_PTR == CDCNP_CAIO_MD(cdcnp))
        {
            CDCNP_HEADER *cdcnp_header;
            CDCNP_BITMAP *cdcnp_bitmap;

            UINT32        offset;

            UINT32        np_size;
            uint8_t       np_model;

            UINT8         data[ 8 ];
            UINT32        data_len;

            /*read np id and np model => file size => load whole*/
            data_len = sizeof(data)/sizeof(data[ 0 ]);

            if(f_s_offset + data_len > f_e_offset)
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: "
                                                      "[%ld, %ld) => invalid range [%ld, %ld)\n",
                                                      (*s_offset), e_offset,
                                                      f_s_offset, f_e_offset);
                return (EC_FALSE);
            }

            offset = f_s_offset;

            if(EC_FALSE == c_file_load(fd, &offset, data_len, (UINT8 *)data))
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: "
                                                      "load %ld bytes from fd %d, offset %ld failed\n",
                                                      data_len, fd, f_s_offset);
                return (EC_FALSE);
            }

            /*trick*/
            if(np_id != CDCNP_HEADER_NP_ID((CDCNP_HEADER *)data))
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: "
                                                      "np mismatched: given %u, stored %u "
                                                      "from fd %d, offset %ld\n",
                                                      np_id, CDCNP_HEADER_NP_ID((CDCNP_HEADER *)data),
                                                      fd, f_s_offset);
                return (EC_FALSE);
            }

            np_model = CDCNP_HEADER_MODEL((CDCNP_HEADER *)data);

            dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_aio: "
                                                  "np_id %u, np_model %u from fd %d, offset %ld\n",
                                                  np_id, np_model, fd, f_s_offset);

            if(EC_FALSE == cdcnp_model_file_size(np_model, &np_size))
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: invalid np_model %u\n", np_model);
                return (EC_FALSE);
            }

            dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_aio: "
                                                  "np_model %u, np_size %ld\n",
                                                  np_model, np_size);

            ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
            np_size = VAL_ALIGN_NEXT(np_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));

            offset = f_s_offset;

            cdcnp_header = (CDCNP_HEADER *)safe_malloc(np_size, LOC_CDCNP_0015);
            if(NULL_PTR == cdcnp_header)
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: "
                                                      "malloc %ld bytes failed for loading np %u from fd %d\n",
                                                      np_size, np_id, fd);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdcnp_header_load(cdcnp_header, np_id, fd, &offset, np_size))
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: "
                                                      "load np %u from fd %d, offset %ld failed\n",
                                                      np_id, fd, f_s_offset);
                safe_free((void *)cdcnp_header, LOC_CDCNP_0016);
                return (EC_FALSE);
            }

            dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_aio: "
                                                  "load np %u from fd %d, offset %ld, size %ld done\n",
                                                  np_id, fd, f_s_offset, np_size);

            ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));
            ASSERT(np_model == CDCNP_HEADER_MODEL(cdcnp_header));
            ASSERT(f_s_offset + np_size == offset);

            cdcnp_bitmap = CDCNP_HEADER_BITMAP(cdcnp_header);

            CDCNP_HDR(cdcnp)    = cdcnp_header;
            CDCNP_BITMAP(cdcnp) = cdcnp_bitmap;

            /*shortcut*/
            CDCNP_LRU_LIST(cdcnp) = CDCNP_ITEM_LRU_NODE(cdcnp_fetch(cdcnp, CDCNPLRU_ROOT_POS));
            CDCNP_DEL_LIST(cdcnp) = CDCNP_ITEM_DEL_NODE(cdcnp_fetch(cdcnp, CDCNPDEL_ROOT_POS));

            CDCNP_S_OFFSET(cdcnp) = f_s_offset;
            CDCNP_E_OFFSET(cdcnp) = f_s_offset + np_size;
            CDCNP_FNAME(cdcnp)    = NULL_PTR;

            (*s_offset) = f_s_offset + np_size;

            dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_load_aio: "
                                                  "load np %u, fsize %ld from fd %d, offset %ld => %ld done\n",
                                                  CDCNP_HEADER_NP_ID(cdcnp_header),
                                                  np_size, fd, f_s_offset, offset);
        }
        else
        {
            CAIO_CB     caio_cb_t;
            CDCNP_AIO  *cdcnp_aio;

            /*set cdcnp aio*/
            cdcnp_aio = cdcnp_aio_new();
            if(NULL_PTR == cdcnp_aio)
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_load_aio: new cdcnp_aio failed\n");

                return (EC_FALSE);
            }

            CDCNP_AIO_CDCNP(cdcnp_aio)          = cdcnp;
            CDCNP_AIO_NP_ID(cdcnp_aio)          = np_id;
            CDCNP_AIO_FD(cdcnp_aio)             = fd;
            CDCNP_AIO_I_S_OFFSET(cdcnp_aio)     = s_offset;
            CDCNP_AIO_F_S_OFFSET(cdcnp_aio)     = f_s_offset;
            CDCNP_AIO_F_E_OFFSET(cdcnp_aio)     = f_e_offset;
            CDCNP_AIO_S_OFFSET(cdcnp_aio)       = f_s_offset;
            CDCNP_AIO_E_OFFSET(cdcnp_aio)       = f_s_offset + 8;
            CDCNP_AIO_C_OFFSET(cdcnp_aio)       = f_s_offset;
            CDCNP_AIO_M_BUFF(cdcnp_aio)         = NULL_PTR;

            caio_cb_clone(caio_cb, CDCNP_AIO_CAIO_CB(cdcnp_aio));

            /*set caio callback*/
            caio_cb_init(&caio_cb_t);

            caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCNP_AIO_TIMEOUT_NSEC /*seconds*/,
                                        (CAIO_CALLBACK)__cdcnp_load_aio_1st_timeout, (void *)cdcnp_aio);

            caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcnp_load_aio_1st_terminate, (void *)cdcnp_aio);
            caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcnp_load_aio_1st_complete, (void *)cdcnp_aio);

            /*send aio request*/
            caio_file_read(CDCNP_CAIO_MD(cdcnp), CDCNP_FD(cdcnp),
                            &CDCNP_AIO_C_OFFSET(cdcnp_aio),
                            CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                            CDCNP_AIO_M_DATA(cdcnp_aio),
                            &caio_cb_t);
        }

        return (EC_TRUE);
    }

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

        ASSERT(0 == (CDCNP_S_OFFSET(cdcnp) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
        ASSERT(0 == (CDCNP_E_OFFSET(cdcnp) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

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

        ASSERT(offset == CDCNP_E_OFFSET(cdcnp));

        dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_flush: "
                                              "flush np %u to fd %d, offset %ld => %ld, size %ld done\n",
                                              CDCNP_HEADER_NP_ID(cdcnp_header),
                                              CDCNP_FD(cdcnp),
                                              CDCNP_S_OFFSET(cdcnp), offset,
                                              size);
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_flush_aio_timeout(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB      caio_cb;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_flush_aio_timeout: "
                                          "flush np from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_flush_aio_terminate(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB      caio_cb;

    dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:__cdcnp_flush_aio_terminate: "
                                          "flush cdcpgv from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_terminate_handler(&caio_cb);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcnp_flush_aio_complete(CDCNP_AIO *cdcnp_aio)
{
    CAIO_CB      caio_cb;
    CDCNP       *cdcnp;

    dbg_log(SEC_0129_CDCNP, 1)(LOGSTDOUT, "[DEBUG] __cdcnp_flush_aio_complete: "
                                          "flush cdcpgv from offset %ld, size %ld done, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_C_OFFSET(cdcnp_aio),
                                          CDCNP_AIO_E_OFFSET(cdcnp_aio));

    ASSERT(NULL_PTR != CDCNP_AIO_CDCNP(cdcnp_aio));
    cdcnp = CDCNP_AIO_CDCNP(cdcnp_aio);

    ASSERT(NULL_PTR != CDCNP_CAIO_MD(cdcnp));

    ASSERT(CDCNP_AIO_C_OFFSET(cdcnp_aio) == CDCNP_E_OFFSET(cdcnp));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCNP_AIO_CAIO_CB(cdcnp_aio), &caio_cb);

    cdcnp_aio_free(cdcnp_aio);

    caio_cb_exec_complete_handler(&caio_cb);
    return (EC_TRUE);
}


EC_BOOL cdcnp_flush_aio(CDCNP *cdcnp, CAIO_CB *caio_cb)
{
    if(NULL_PTR != cdcnp)
    {
        CDCNP_HEADER *cdcnp_header;

        cdcnp_header = CDCNP_HDR(cdcnp);
        if(NULL_PTR == cdcnp_header)
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush_aio: np header is null\n");
            return (EC_FALSE);
        }

        if(ERR_FD == CDCNP_FD(cdcnp))
        {
            dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush_aio: no fd\n");
            return (EC_FALSE);
        }

        ASSERT(NULL_PTR != CDCNP_CAIO_MD(cdcnp));

        ASSERT(0 == (CDCNP_S_OFFSET(cdcnp) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
        ASSERT(0 == (CDCNP_E_OFFSET(cdcnp) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

        if(NULL_PTR == CDCNP_CAIO_MD(cdcnp))
        {
            UINT32        offset;
            UINT32        size;

            offset = CDCNP_S_OFFSET(cdcnp);
            size   = CDCNP_E_OFFSET(cdcnp) - CDCNP_S_OFFSET(cdcnp);

            if(EC_FALSE == cdcnp_header_flush(cdcnp_header,
                                              CDCNP_HEADER_NP_ID(cdcnp_header),
                                              CDCNP_FD(cdcnp), &offset, size))
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush_aio: "
                                                      "flush np %u to fd %d, offset %ld, size %ld failed\n",
                                                      CDCNP_HEADER_NP_ID(cdcnp_header),
                                                      CDCNP_FD(cdcnp),
                                                      CDCNP_S_OFFSET(cdcnp),
                                                      size);
                return (EC_FALSE);
            }

            ASSERT(offset == CDCNP_E_OFFSET(cdcnp));

            dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_flush_aio: "
                                                  "flush np %u to fd %d, offset %ld => %ld, size %ld done\n",
                                                  CDCNP_HEADER_NP_ID(cdcnp_header),
                                                  CDCNP_FD(cdcnp),
                                                  CDCNP_S_OFFSET(cdcnp), offset,
                                                  size);
        }
        else
        {
            CAIO_CB     caio_cb_t;
            CDCNP_AIO  *cdcnp_aio;

            /*set cdcnp aio*/
            cdcnp_aio = cdcnp_aio_new();
            if(NULL_PTR == cdcnp_aio)
            {
                dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_flush_aio: new cdcnp_aio failed\n");

                return (EC_FALSE);
            }

            CDCNP_AIO_CDCNP(cdcnp_aio)          = cdcnp;
            CDCNP_AIO_NP_ID(cdcnp_aio)          = CDCNP_HEADER_NP_ID(cdcnp_header);
            CDCNP_AIO_FD(cdcnp_aio)             = CDCNP_FD(cdcnp);
            CDCNP_AIO_S_OFFSET(cdcnp_aio)       = CDCNP_S_OFFSET(cdcnp);
            CDCNP_AIO_E_OFFSET(cdcnp_aio)       = CDCNP_E_OFFSET(cdcnp);
            CDCNP_AIO_C_OFFSET(cdcnp_aio)       = CDCNP_S_OFFSET(cdcnp);
            CDCNP_AIO_M_BUFF(cdcnp_aio)         = (UINT8 *)cdcnp_header;

            caio_cb_clone(caio_cb, CDCNP_AIO_CAIO_CB(cdcnp_aio));

            /*set caio callback*/
            caio_cb_init(&caio_cb_t);

            caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCNP_AIO_TIMEOUT_NSEC /*seconds*/,
                                        (CAIO_CALLBACK)__cdcnp_flush_aio_timeout, (void *)cdcnp_aio);

            caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcnp_flush_aio_terminate, (void *)cdcnp_aio);
            caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcnp_flush_aio_complete, (void *)cdcnp_aio);

            /*send aio request*/
            caio_file_write(CDCNP_CAIO_MD(cdcnp), CDCNP_FD(cdcnp),
                            &CDCNP_AIO_C_OFFSET(cdcnp_aio),
                            CDCNP_AIO_E_OFFSET(cdcnp_aio) - CDCNP_AIO_S_OFFSET(cdcnp_aio),
                            CDCNP_AIO_M_BUFF(cdcnp_aio),
                            &caio_cb_t);
        }

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
    //uint32_t         item_max_num;

    if(EC_FALSE == cdcnp_model_file_size(np_model, &np_size))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_create: "
                                          "np_model %u, np_size %ld\n",
                                          np_model, np_size);

    ASSERT(0 == (np_size & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
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

#if 0
    if(EC_FALSE == cdcnp_model_item_max_num(np_model, &item_max_num))
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }
#endif

    cdcnp_header = cdcnp_header_new(np_id, np_size, np_model);
    if(NULL_PTR == cdcnp_header)
    {
        dbg_log(SEC_0129_CDCNP, 0)(LOGSTDOUT, "error:cdcnp_create: new cdcnp header failed\n");
        return (NULL_PTR);
    }

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

    CDCNP_FD(cdcnp)        = ERR_FD;
    CDCNP_S_OFFSET(cdcnp)  = f_s_offset;
    CDCNP_E_OFFSET(cdcnp)  = f_s_offset + np_size;
    CDCNP_FNAME(cdcnp)     = NULL_PTR;

    (*s_offset) = f_s_offset + np_size;

    ASSERT(np_id == CDCNP_HEADER_NP_ID(cdcnp_header));

    /*create root item*/
    cdcnp_create_root_item(cdcnp);

    dbg_log(SEC_0129_CDCNP, 9)(LOGSTDOUT, "[DEBUG] cdcnp_create: create np %u done\n", np_id);

    return (cdcnp);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/


