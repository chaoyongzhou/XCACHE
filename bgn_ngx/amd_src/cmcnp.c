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

#include "cmc.h"
#include "cmcpgrb.h"
#include "cmcpgb.h"
#include "cmcnprb.h"
#include "cmcnpque.h"
#include "cmcnpdel.h"
#include "cmcnpdeg.h"
#include "cmcnp.h"
#include "cmmap.h"

#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMCNP_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMCNP_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

static CMCNP_CFG g_cmcnp_cfg_tbl[] = {
    {(const char *)"1M"  , (const char *)"CMCNP_001M_MODEL", CMCNP_001M_CFG_FILE_SIZE,  CMCNP_001M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2M"  , (const char *)"CMCNP_002M_MODEL", CMCNP_002M_CFG_FILE_SIZE,  CMCNP_002M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"4M"  , (const char *)"CMCNP_004M_MODEL", CMCNP_004M_CFG_FILE_SIZE,  CMCNP_004M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"8M"  , (const char *)"CMCNP_008M_MODEL", CMCNP_008M_CFG_FILE_SIZE,  CMCNP_008M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"16M" , (const char *)"CMCNP_016M_MODEL", CMCNP_016M_CFG_FILE_SIZE,  CMCNP_016M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"32M" , (const char *)"CMCNP_032M_MODEL", CMCNP_032M_CFG_FILE_SIZE,  CMCNP_032M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"64M" , (const char *)"CMCNP_064M_MODEL", CMCNP_064M_CFG_FILE_SIZE,  CMCNP_064M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"128M", (const char *)"CMCNP_128M_MODEL", CMCNP_128M_CFG_FILE_SIZE,  CMCNP_128M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"256M", (const char *)"CMCNP_256M_MODEL", CMCNP_256M_CFG_FILE_SIZE,  CMCNP_256M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"512M", (const char *)"CMCNP_512M_MODEL", CMCNP_512M_CFG_FILE_SIZE,  CMCNP_512M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"1G"  , (const char *)"CMCNP_001G_MODEL", CMCNP_001G_CFG_FILE_SIZE,  CMCNP_001G_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2G"  , (const char *)"CMCNP_002G_MODEL", CMCNP_002G_CFG_FILE_SIZE,  CMCNP_002G_CFG_ITEM_MAX_NUM, 0 },
#if (64 == WORDSIZE)
    {(const char *)"4G"  , (const char *)"CMCNP_004G_MODEL", CMCNP_004G_CFG_FILE_SIZE,  CMCNP_004G_CFG_ITEM_MAX_NUM, 0 },
#endif/*(64 == WORDSIZE)*/
};

static uint8_t g_cmcnp_cfg_tbl_len = (uint8_t)(sizeof(g_cmcnp_cfg_tbl)/sizeof(g_cmcnp_cfg_tbl[0]));

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

STATIC_CAST static CMCNPRB_NODE *__cmcnprb_node(CMCNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CMCNPRB_POOL_NODE_MAX_NUM(pool) > node_pos)
    {
        CMCNPRB_NODE *node;

        node = (CMCNPRB_NODE *)((void *)(pool->rb_nodes) + node_pos * CMCNPRB_POOL_NODE_SIZEOF(pool));

        dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] __cmcnprb_node: pool %p, rb_nodes %p, node_pos %u  -> node %p\n",
                           pool, (void *)(pool->rb_nodes), node_pos, node);
        return (node);
    }
    return (NULL_PTR);
}


const char *cmcnp_model_str(const uint8_t cmcnp_model)
{
    CMCNP_CFG *cmcnp_cfg;
    if(cmcnp_model >= g_cmcnp_cfg_tbl_len)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_model_str: invalid cmcnp mode %u\n", cmcnp_model);
        return (const char *)"unkown";
    }
    cmcnp_cfg = &(g_cmcnp_cfg_tbl[ cmcnp_model ]);
    return CMCNP_CFG_MODEL_STR(cmcnp_cfg);
}

uint8_t cmcnp_model_get(const char *model_str)
{
    uint8_t cmcnp_model;

    for(cmcnp_model = 0; cmcnp_model < g_cmcnp_cfg_tbl_len; cmcnp_model ++)
    {
        CMCNP_CFG *cmcnp_cfg;
        cmcnp_cfg = &(g_cmcnp_cfg_tbl[ cmcnp_model ]);

        if(0 == strcasecmp(CMCNP_CFG_MODEL_STR(cmcnp_cfg), model_str))
        {
            return (cmcnp_model);
        }
    }
    return (CMCNP_ERR_MODEL);
}

EC_BOOL cmcnp_model_file_size(const uint8_t cmcnp_model, UINT32 *file_size)
{
    CMCNP_CFG *cmcnp_cfg;
    if(cmcnp_model >= g_cmcnp_cfg_tbl_len)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_model_file_size: invalid cmcnp mode %u\n", cmcnp_model);
        return (EC_FALSE);
    }
    cmcnp_cfg = &(g_cmcnp_cfg_tbl[ cmcnp_model ]);
    (*file_size) = CMCNP_CFG_FILE_SIZE(cmcnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cmcnp_model_item_max_num(const uint8_t cmcnp_model, uint32_t *item_max_num)
{
    CMCNP_CFG *cmcnp_cfg;
    if(cmcnp_model >= g_cmcnp_cfg_tbl_len)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_model_item_max_num: invalid cmcnp mode %u\n", cmcnp_model);
        return (EC_FALSE);
    }
    cmcnp_cfg = &(g_cmcnp_cfg_tbl[ cmcnp_model ]);
    (*item_max_num) = CMCNP_CFG_ITEM_MAX_NUM(cmcnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cmcnp_model_search(const UINT32 mem_disk_size /*in byte*/, uint8_t *cmcnp_model)
{
    UINT32      np_fsize;
    UINT8       cmcnp_model_t;

    /*np file size = ((rdisk size) / (page size)) * (item size)*/
    np_fsize = ((mem_disk_size >> CMCPGB_PAGE_SIZE_NBITS) << CMCNP_ITEM_SIZE_NBITS);

    for(cmcnp_model_t = 0; cmcnp_model_t < g_cmcnp_cfg_tbl_len; cmcnp_model_t ++)
    {
        CMCNP_CFG *cmcnp_cfg;
        cmcnp_cfg = &(g_cmcnp_cfg_tbl[ cmcnp_model_t ]);

        if(0 < CMCNP_CFG_ITEM_MAX_NUM(cmcnp_cfg)
        && np_fsize <= CMCNP_CFG_FILE_SIZE(cmcnp_cfg))
        {
            (*cmcnp_model) = cmcnp_model_t;

            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_model_search: "
                                                  "mem disk size %ld bytes => np model %u, "
                                                  "where page size %u, item size %u\n",
                                                  mem_disk_size, (*cmcnp_model),
                                                  (uint32_t)(1 << CMCPGB_PAGE_SIZE_NBITS),
                                                  (uint32_t)(1 << CMCNP_ITEM_SIZE_NBITS));
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cmcnp_inode_init(CMCNP_INODE *cmcnp_inode)
{
    CMCNP_INODE_DISK_NO(cmcnp_inode)    = CMCPGRB_ERR_POS;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = CMCPGRB_ERR_POS;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = CMCPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cmcnp_inode_clean(CMCNP_INODE *cmcnp_inode)
{
    CMCNP_INODE_DISK_NO(cmcnp_inode)    = CMCPGRB_ERR_POS;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = CMCPGRB_ERR_POS;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = CMCPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cmcnp_inode_clone(const CMCNP_INODE *cmcnp_inode_src, CMCNP_INODE *cmcnp_inode_des)
{
    CMCNP_INODE_DISK_NO(cmcnp_inode_des)    = CMCNP_INODE_DISK_NO(cmcnp_inode_src);
    CMCNP_INODE_BLOCK_NO(cmcnp_inode_des)   = CMCNP_INODE_BLOCK_NO(cmcnp_inode_src);
    CMCNP_INODE_PAGE_NO(cmcnp_inode_des)    = CMCNP_INODE_PAGE_NO(cmcnp_inode_src);

    return (EC_TRUE);
}

void cmcnp_inode_print(LOG *log, const CMCNP_INODE *cmcnp_inode)
{
    sys_print(log, "(disk %u, block %u, page %u)\n",
                    CMCNP_INODE_DISK_NO(cmcnp_inode),
                    CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                    CMCNP_INODE_PAGE_NO(cmcnp_inode)
                    );
    return;
}

void cmcnp_inode_log(LOG *log, const CMCNP_INODE *cmcnp_inode)
{
    sys_print(log, "(disk %u, block %u, page %u)\n",
                    CMCNP_INODE_DISK_NO(cmcnp_inode),
                    CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                    CMCNP_INODE_PAGE_NO(cmcnp_inode)
                    );
    return;
}

CMCNP_FNODE *cmcnp_fnode_new()
{
    CMCNP_FNODE *cmcnp_fnode;
    alloc_static_mem(MM_CMCNP_FNODE, &cmcnp_fnode, LOC_CMCNP_0001);
    if(NULL_PTR != cmcnp_fnode)
    {
        cmcnp_fnode_init(cmcnp_fnode);
    }
    return (cmcnp_fnode);
}

CMCNP_FNODE *cmcnp_fnode_make(const CMCNP_FNODE *cmcnp_fnode_src)
{
    CMCNP_FNODE *cmcnp_fnode_des;
    alloc_static_mem(MM_CMCNP_FNODE, &cmcnp_fnode_des, LOC_CMCNP_0002);
    if(NULL_PTR != cmcnp_fnode_des)
    {
        cmcnp_fnode_clone(cmcnp_fnode_src, cmcnp_fnode_des);
    }
    return (cmcnp_fnode_des);
}

EC_BOOL cmcnp_fnode_init(CMCNP_FNODE *cmcnp_fnode)
{
    uint16_t pos;

    CMCNP_FNODE_PAGENUM(cmcnp_fnode)            = 0;
    CMCNP_FNODE_REPNUM(cmcnp_fnode)             = 0;

    for(pos = 0; pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_init(CMCNP_FNODE_INODE(cmcnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_clean(CMCNP_FNODE *cmcnp_fnode)
{
    uint16_t pos;

    CMCNP_FNODE_PAGENUM(cmcnp_fnode)            = 0;
    CMCNP_FNODE_REPNUM(cmcnp_fnode)             = 0;

    for(pos = 0; pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_clean(CMCNP_FNODE_INODE(cmcnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_free(CMCNP_FNODE *cmcnp_fnode)
{
    if(NULL_PTR != cmcnp_fnode)
    {
        cmcnp_fnode_clean(cmcnp_fnode);
        free_static_mem(MM_CMCNP_FNODE, cmcnp_fnode, LOC_CMCNP_0003);
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_clone(const CMCNP_FNODE *cmcnp_fnode_src, CMCNP_FNODE *cmcnp_fnode_des)
{
    uint16_t pos;

    CMCNP_FNODE_PAGENUM(cmcnp_fnode_des)            = CMCNP_FNODE_PAGENUM(cmcnp_fnode_src);
    CMCNP_FNODE_REPNUM(cmcnp_fnode_des)             = CMCNP_FNODE_REPNUM(cmcnp_fnode_src);

    for(pos = 0; pos < CMCNP_FNODE_REPNUM(cmcnp_fnode_src) && pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_clone(CMCNP_FNODE_INODE(cmcnp_fnode_src, pos), CMCNP_FNODE_INODE(cmcnp_fnode_des, pos));
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_import(const CMCNP_FNODE *cmcnp_fnode_src, CMCNP_FNODE *cmcnp_fnode_des)
{
    uint16_t src_pos;
    uint16_t des_pos;

    for(src_pos = 0, des_pos = 0; src_pos < CMCNP_FNODE_REPNUM(cmcnp_fnode_src) && src_pos < CMCNP_FILE_REPLICA_MAX_NUM; src_pos ++)
    {
        CMCNP_INODE *cmcnp_inode_src;

        cmcnp_inode_src = (CMCNP_INODE *)CMCNP_FNODE_INODE(cmcnp_fnode_src, src_pos);
        if(CMCPGRB_ERR_POS != CMCNP_INODE_DISK_NO(cmcnp_inode_src)
        && CMCPGRB_ERR_POS != CMCNP_INODE_BLOCK_NO(cmcnp_inode_src)
        && CMCPGRB_ERR_POS != CMCNP_INODE_PAGE_NO(cmcnp_inode_src)
        )
        {
            CMCNP_INODE *cmcnp_inode_des;

            cmcnp_inode_des = CMCNP_FNODE_INODE(cmcnp_fnode_des, des_pos);
            if(cmcnp_inode_src != cmcnp_inode_des)
            {
                cmcnp_inode_clone(cmcnp_inode_src, cmcnp_inode_des);
            }

            des_pos ++;
        }
    }

    CMCNP_FNODE_PAGENUM(cmcnp_fnode_des)            = CMCNP_FNODE_PAGENUM(cmcnp_fnode_src);
    CMCNP_FNODE_REPNUM(cmcnp_fnode_des)             = des_pos;

    return (EC_TRUE);
}

void cmcnp_fnode_print(LOG *log, const CMCNP_FNODE *cmcnp_fnode)
{
    uint16_t pos;

    sys_log(log, "cmcnp_fnode %p: page num %u, replica num %u\n",
                 cmcnp_fnode,
                 CMCNP_FNODE_PAGENUM(cmcnp_fnode),
                 CMCNP_FNODE_REPNUM(cmcnp_fnode)
                 );

    for(pos = 0; pos < CMCNP_FNODE_REPNUM(cmcnp_fnode) && pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_print(log, CMCNP_FNODE_INODE(cmcnp_fnode, pos));
    }
    return;
}

void cmcnp_fnode_log(LOG *log, const CMCNP_FNODE *cmcnp_fnode)
{
    uint16_t pos;

    sys_print_no_lock(log, "page num %u, replica %u\n",
               CMCNP_FNODE_PAGENUM(cmcnp_fnode),
               CMCNP_FNODE_REPNUM(cmcnp_fnode)
               );

    for(pos = 0; pos < CMCNP_FNODE_REPNUM(cmcnp_fnode) && pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_log(log, CMCNP_FNODE_INODE(cmcnp_fnode, pos));
    }
    sys_print_no_lock(log, "\n");

    return;
}

CMCNP_DNODE *cmcnp_dnode_new()
{
    CMCNP_DNODE *cmcnp_dnode;

    alloc_static_mem(MM_CMCNP_DNODE, &cmcnp_dnode, LOC_CMCNP_0004);
    if(NULL_PTR != cmcnp_dnode)
    {
        cmcnp_dnode_init(cmcnp_dnode);
    }
    return (cmcnp_dnode);

}

EC_BOOL cmcnp_dnode_init(CMCNP_DNODE *cmcnp_dnode)
{
    CMCNP_DNODE_FILE_NUM(cmcnp_dnode) = 0;
    CMCNP_DNODE_ROOT_POS(cmcnp_dnode) = CMCNPRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cmcnp_dnode_clean(CMCNP_DNODE *cmcnp_dnode)
{
    CMCNP_DNODE_FILE_NUM(cmcnp_dnode) = 0;
    CMCNP_DNODE_ROOT_POS(cmcnp_dnode) = CMCNPRB_ERR_POS;

    return (EC_TRUE);
}

EC_BOOL cmcnp_dnode_free(CMCNP_DNODE *cmcnp_dnode)
{
    if(NULL_PTR != cmcnp_dnode)
    {
        cmcnp_dnode_clean(cmcnp_dnode);
        free_static_mem(MM_CMCNP_DNODE, cmcnp_dnode, LOC_CMCNP_0005);
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_dnode_clone(const CMCNP_DNODE *cmcnp_dnode_src, CMCNP_DNODE *cmcnp_dnode_des)
{
    CMCNP_DNODE_FILE_NUM(cmcnp_dnode_des) = CMCNP_DNODE_FILE_NUM(cmcnp_dnode_src);
    CMCNP_DNODE_ROOT_POS(cmcnp_dnode_des) = CMCNP_DNODE_ROOT_POS(cmcnp_dnode_src);
    return (EC_TRUE);
}

CMCNP_KEY *cmcnp_key_new()
{
    CMCNP_KEY *cmcnp_key;

    alloc_static_mem(MM_CMCNP_KEY, &cmcnp_key, LOC_CMCNP_0006);
    if(NULL_PTR != cmcnp_key)
    {
        cmcnp_key_init(cmcnp_key);
    }
    return (cmcnp_key);
}

EC_BOOL cmcnp_key_init(CMCNP_KEY *cmcnp_key)
{
    CMCNP_KEY_S_PAGE(cmcnp_key) = CMCNP_KEY_S_PAGE_ERR;
    CMCNP_KEY_E_PAGE(cmcnp_key) = CMCNP_KEY_S_PAGE_ERR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_key_clean(CMCNP_KEY *cmcnp_key)
{
    CMCNP_KEY_S_PAGE(cmcnp_key) = CMCNP_KEY_S_PAGE_ERR;
    CMCNP_KEY_E_PAGE(cmcnp_key) = CMCNP_KEY_S_PAGE_ERR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_key_clone(const CMCNP_KEY *cmcnp_key_src, CMCNP_KEY *cmcnp_key_des)
{
    if(NULL_PTR == cmcnp_key_src)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_key_clone: cmcnp_key_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cmcnp_key_des)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_key_clone: cmcnp_key_des is null\n");
        return (EC_FALSE);
    }

    CMCNP_KEY_S_PAGE(cmcnp_key_des) = CMCNP_KEY_S_PAGE(cmcnp_key_src);
    CMCNP_KEY_E_PAGE(cmcnp_key_des) = CMCNP_KEY_E_PAGE(cmcnp_key_src);

    return (EC_TRUE);
}

EC_BOOL cmcnp_key_cmp(const CMCNP_KEY *cmcnp_key_1st, const CMCNP_KEY *cmcnp_key_2nd)
{
    if(CMCNP_KEY_S_PAGE(cmcnp_key_1st) != CMCNP_KEY_S_PAGE(cmcnp_key_2nd))
    {
        return (EC_FALSE);
    }

    if(CMCNP_KEY_E_PAGE(cmcnp_key_1st) != CMCNP_KEY_E_PAGE(cmcnp_key_2nd))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_key_free(CMCNP_KEY *cmcnp_key)
{
    if(NULL_PTR != cmcnp_key)
    {
        cmcnp_key_clean(cmcnp_key);
        free_static_mem(MM_CMCNP_KEY, cmcnp_key, LOC_CMCNP_0007);
    }
    return (EC_TRUE);
}

void cmcnp_key_print(LOG *log, const CMCNP_KEY *cmcnp_key)
{
    sys_log(log, "key: [%u, %u)\n",
                 CMCNP_KEY_S_PAGE(cmcnp_key),
                 CMCNP_KEY_E_PAGE(cmcnp_key));

    return;
}

EC_BOOL cmcnp_key_is_valid(const CMCNP_KEY *cmcnp_key)
{
    if(CMCNP_KEY_S_PAGE(cmcnp_key) < CMCNP_KEY_E_PAGE(cmcnp_key))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

uint32_t cmcnp_key_hash(const CMCNP_KEY *cmcnp_key)
{
     uint32_t hash = 1315423911;

     hash ^= ((hash << 5) + CMCNP_KEY_S_PAGE(cmcnp_key) + (hash >> 2));
     hash ^= ((hash << 5) + CMCNP_KEY_E_PAGE(cmcnp_key) + (hash >> 2));

     return (hash & 0x7FFFFFFF);
}

CMCNP_ITEM *cmcnp_item_new()
{
    CMCNP_ITEM *cmcnp_item;

    alloc_static_mem(MM_CMCNP_ITEM, &cmcnp_item, LOC_CMCNP_0008);
    if(NULL_PTR != cmcnp_item)
    {
        cmcnp_item_init(cmcnp_item);
    }
    return (cmcnp_item);
}

EC_BOOL cmcnp_item_init(CMCNP_ITEM *cmcnp_item)
{
    CMCNP_ITEM_DIR_FLAG(cmcnp_item)         = CMCNP_ITEM_FILE_IS_ERR;
    CMCNP_ITEM_USED_FLAG(cmcnp_item)        = CMCNP_ITEM_IS_NOT_USED;

    CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item)   = BIT_FALSE;
    CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item)  = BIT_FALSE;

    CMCNP_ITEM_DEG_TIMES(cmcnp_item)        = 0;

    CMCNP_ITEM_PARENT_POS(cmcnp_item)       = CMCNPRB_ERR_POS;/*fix*/

    cmcnp_fnode_init(CMCNP_ITEM_FNODE(cmcnp_item));

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cmcnp_item_clean(CMCNP_ITEM *cmcnp_item)
{
    CMCNP_ITEM_DIR_FLAG(cmcnp_item)         = CMCNP_ITEM_FILE_IS_ERR;
    CMCNP_ITEM_USED_FLAG(cmcnp_item)        = CMCNP_ITEM_IS_NOT_USED;

    CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item)   = BIT_FALSE;
    CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item)  = BIT_FALSE;

    CMCNP_ITEM_DEG_TIMES(cmcnp_item)        = 0;

    CMCNP_ITEM_PARENT_POS(cmcnp_item)       = CMCNPRB_ERR_POS;/*fix bug: break pointer to parent*/

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cmcnp_item_clone(const CMCNP_ITEM *cmcnp_item_src, CMCNP_ITEM *cmcnp_item_des)
{
    if(NULL_PTR == cmcnp_item_src)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_item_clone: cmcnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cmcnp_item_des)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_item_clone: cmcnp_item_des is null\n");
        return (EC_FALSE);
    }

    CMCNP_ITEM_USED_FLAG(cmcnp_item_des)       =  CMCNP_ITEM_USED_FLAG(cmcnp_item_src);
    CMCNP_ITEM_DIR_FLAG(cmcnp_item_des)        =  CMCNP_ITEM_DIR_FLAG(cmcnp_item_src);

    CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item_des)  = CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item_src);
    CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item_des) = CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item_src);

    CMCNP_ITEM_DEG_TIMES(cmcnp_item_des)       = CMCNP_ITEM_DEG_TIMES(cmcnp_item_src);

    CMCNP_ITEM_PARENT_POS(cmcnp_item_des)      = CMCNP_ITEM_PARENT_POS(cmcnp_item_src);

    cmcnpque_node_clone(CMCNP_ITEM_QUE_NODE(cmcnp_item_src), CMCNP_ITEM_QUE_NODE(cmcnp_item_des));
    cmcnpdel_node_clone(CMCNP_ITEM_DEL_NODE(cmcnp_item_src), CMCNP_ITEM_DEL_NODE(cmcnp_item_des));
    cmcnpdeg_node_clone(CMCNP_ITEM_DEG_NODE(cmcnp_item_src), CMCNP_ITEM_DEG_NODE(cmcnp_item_des));

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item_src))
    {
        cmcnp_fnode_clone(CMCNP_ITEM_FNODE(cmcnp_item_src), CMCNP_ITEM_FNODE(cmcnp_item_des));
    }
    else if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item_src))
    {
        cmcnp_dnode_clone(CMCNP_ITEM_DNODE(cmcnp_item_src), CMCNP_ITEM_DNODE(cmcnp_item_des));
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_item_free(CMCNP_ITEM *cmcnp_item)
{
    if(NULL_PTR != cmcnp_item)
    {
        cmcnp_item_clean(cmcnp_item);
        free_static_mem(MM_CMCNP_ITEM, cmcnp_item, LOC_CMCNP_0009);
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_item_set_key(CMCNP_ITEM *cmcnp_item, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_ITEM_S_PAGE(cmcnp_item) = CMCNP_KEY_S_PAGE(cmcnp_key);
    CMCNP_ITEM_E_PAGE(cmcnp_item) = CMCNP_KEY_E_PAGE(cmcnp_key);

    return (EC_TRUE);
}

STATIC_CAST static const char *__cmcnp_item_dir_flag_str(const uint32_t dir_flag)
{
    switch(dir_flag)
    {
        case CMCNP_ITEM_FILE_IS_DIR:
            return (const char *)"D";
        case CMCNP_ITEM_FILE_IS_REG:
            return (const char *)"F";
    }

    return (const char *)"UFO";
}

/*without key print*/
void cmcnp_item_print(LOG *log, const CMCNP_ITEM *cmcnp_item)
{
    uint16_t pos;

    sys_print(log, "cmcnp_item %p: flag 0x%x [%s], stat %u, "
                   "ssd dirty flag %u, sata dirty flag %u, "
                   "deg times %u, "
                   "parent %u, que node (%u, %u), del node (%u, %u), deg node (%u, %u)\n",
                    cmcnp_item,
                    CMCNP_ITEM_DIR_FLAG(cmcnp_item), __cmcnp_item_dir_flag_str(CMCNP_ITEM_DIR_FLAG(cmcnp_item)),
                    CMCNP_ITEM_USED_FLAG(cmcnp_item),
                    CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item),
                    CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item),
                    CMCNP_ITEM_DEG_TIMES(cmcnp_item),
                    CMCNP_ITEM_PARENT_POS(cmcnp_item),
                    CMCNPQUE_NODE_PREV_POS(CMCNP_ITEM_QUE_NODE(cmcnp_item)),
                    CMCNPQUE_NODE_NEXT_POS(CMCNP_ITEM_QUE_NODE(cmcnp_item)),
                    CMCNPDEL_NODE_PREV_POS(CMCNP_ITEM_DEL_NODE(cmcnp_item)),
                    CMCNPDEL_NODE_NEXT_POS(CMCNP_ITEM_DEL_NODE(cmcnp_item)),
                    CMCNPDEG_NODE_PREV_POS(CMCNP_ITEM_DEG_NODE(cmcnp_item)),
                    CMCNPDEG_NODE_NEXT_POS(CMCNP_ITEM_DEG_NODE(cmcnp_item))
                    );

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;

        cmcnp_fnode = (CMCNP_FNODE *)CMCNP_ITEM_FNODE(cmcnp_item);
        sys_log(log, "page num %u, replica num %u\n",
                     CMCNP_FNODE_PAGENUM(cmcnp_fnode),
                     CMCNP_FNODE_REPNUM(cmcnp_fnode)
                     );
        sys_log(log, "inode:\n");
        for(pos = 0; pos < CMCNP_FNODE_REPNUM(cmcnp_fnode) && pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            CMCNP_INODE *cmcnp_inode;

            cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, pos);
            cmcnp_inode_print(log, cmcnp_inode);
            //sys_print(log, "\n");
        }
    }

    if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_DNODE *cmcnp_dnode;

        cmcnp_dnode = (CMCNP_DNODE *)CMCNP_ITEM_DNODE(cmcnp_item);
        sys_log(log, "file num: %u, dir root pos: %u\n",
                     CMCNP_DNODE_FILE_NUM(cmcnp_dnode),
                     CMCNP_DNODE_ROOT_POS(cmcnp_dnode));
    }

    return;
}

void cmcnp_item_and_key_print(LOG *log, const CMCNP_ITEM *cmcnp_item)
{
    uint16_t pos;

    sys_print(log, "cmcnp_item %p: flag 0x%x [%s], stat %u, "
                   "ssd dirty flag %u, sata dirty flag %u, deg times %u\n",
                   cmcnp_item,
                   CMCNP_ITEM_DIR_FLAG(cmcnp_item), __cmcnp_item_dir_flag_str(CMCNP_ITEM_DIR_FLAG(cmcnp_item)),
                   CMCNP_ITEM_USED_FLAG(cmcnp_item),
                   CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item),
                   CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item),
                   CMCNP_ITEM_DEG_TIMES(cmcnp_item)
                   );

    sys_log(log, "key: [%u, %u)\n",
                 CMCNP_ITEM_S_PAGE(cmcnp_item),
                 CMCNP_ITEM_E_PAGE(cmcnp_item));

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;

        cmcnp_fnode = (CMCNP_FNODE *)CMCNP_ITEM_FNODE(cmcnp_item);

        sys_log(log, "page num %u, replica num %u\n",
                     CMCNP_FNODE_PAGENUM(cmcnp_fnode),
                     CMCNP_FNODE_REPNUM(cmcnp_fnode)
                     );
        for(pos = 0; pos < CMCNP_FNODE_REPNUM(cmcnp_fnode) && pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            CMCNP_INODE *cmcnp_inode;

            cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, pos);
            cmcnp_inode_print(log, cmcnp_inode);
            //sys_print(log, "\n");
        }
    }

    if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_DNODE *cmcnp_dnode;

        cmcnp_dnode = (CMCNP_DNODE *)CMCNP_ITEM_DNODE(cmcnp_item);
        sys_log(log, "file num: %u, dir root pos: %u\n",
                     CMCNP_DNODE_FILE_NUM(cmcnp_dnode),
                     CMCNP_DNODE_ROOT_POS(cmcnp_dnode));
    }

    return;
}

EC_BOOL cmcnp_item_is(const CMCNP_ITEM *cmcnp_item, const CMCNP_KEY *cmcnp_key)
{
    if(CMCNP_KEY_S_PAGE(cmcnp_key) != CMCNP_ITEM_S_PAGE(cmcnp_item))
    {
        return (EC_FALSE);
    }

    if(CMCNP_KEY_E_PAGE(cmcnp_key) != CMCNP_ITEM_E_PAGE(cmcnp_item))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CMCNP_ITEM *cmcnp_item_parent(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item)
{
    uint32_t parent_pos;

    parent_pos = CMCNPRB_NODE_PARENT_POS(CMCNP_ITEM_RB_NODE(cmcnp_item));
    if(CMCNPRB_ERR_POS == parent_pos)
    {
        return (NULL_PTR);
    }

    return cmcnp_fetch(cmcnp, parent_pos);
}

CMCNP_ITEM *cmcnp_item_left(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item)
{
    uint32_t left_pos;

    left_pos = CMCNPRB_NODE_LEFT_POS(CMCNP_ITEM_RB_NODE(cmcnp_item));
    if(CMCNPRB_ERR_POS == left_pos)
    {
        return (NULL_PTR);
    }

    return cmcnp_fetch(cmcnp, left_pos);
}

CMCNP_ITEM *cmcnp_item_right(const CMCNP *cmcnp, const CMCNP_ITEM *cmcnp_item)
{
    uint32_t right_offset;

    right_offset = CMCNPRB_NODE_RIGHT_POS(CMCNP_ITEM_RB_NODE(cmcnp_item));
    if(CMCNPRB_ERR_POS == right_offset)
    {
        return (NULL_PTR);
    }

    return cmcnp_fetch(cmcnp, right_offset);
}

CMCNP_BITMAP *cmcnp_bitmap_new(const UINT32 nbits)
{
    CMCNP_BITMAP *cmcnp_bitmap;
    UINT32        nbytes;

    alloc_static_mem(MM_CMCNP_BITMAP, &cmcnp_bitmap, LOC_CMCNP_0010);
    if(NULL_PTR == cmcnp_bitmap)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_new: malloc cmcnp_bitmap failed\n");
        return (NULL_PTR);
    }

    nbytes = ((nbits + 7) / 8);

    if(EC_FALSE == cmcnp_bitmap_init(cmcnp_bitmap, nbytes))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_new: init cmcnp_bitmap failed\n");
        free_static_mem(MM_CMCNP_BITMAP, cmcnp_bitmap, LOC_CMCNP_0011);
        return (NULL_PTR);
    }

    return (cmcnp_bitmap);
}

EC_BOOL cmcnp_bitmap_init(CMCNP_BITMAP *cmcnp_bitmap, const UINT32 size)
{
    void  *data;

    data = safe_malloc(size, LOC_CMCNP_0012);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_init: malloc %ld bytes failed\n",
                            size);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_mlock(data, size))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_init: mlock %p, size %ld failed\n",
                            data, size);

        safe_free(data, LOC_CMCNP_0013);
        return (EC_FALSE);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_bitmap_init: mlock %p, size %ld done\n",
                        data, size);

    BSET(data, 0, size);

    CMCNP_BITMAP_DATA(cmcnp_bitmap) = data;
    CMCNP_BITMAP_SIZE(cmcnp_bitmap) = size;

    return (EC_TRUE);
}

EC_BOOL cmcnp_bitmap_clean(CMCNP_BITMAP *cmcnp_bitmap)
{
    if(NULL_PTR != cmcnp_bitmap)
    {
        if(NULL_PTR != CMCNP_BITMAP_DATA(cmcnp_bitmap))
        {
            void  *data;
            UINT32 size;

            data = (void *)CMCNP_BITMAP_DATA(cmcnp_bitmap);
            size = CMCNP_BITMAP_SIZE(cmcnp_bitmap);

            if(EC_FALSE == c_munlock(data, size))
            {
                dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_clean: "
                                                      "munlock %p, size %ld failed\n",
                                                      data, size);
            }
            else
            {
                dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_bitmap_clean: "
                                                      "munlock %p, size %ld done\n",
                                                      data, size);
            }

            safe_free(data, LOC_CMCNP_0014);

            CMCNP_BITMAP_DATA(cmcnp_bitmap) = NULL_PTR;
        }
        CMCNP_BITMAP_SIZE(cmcnp_bitmap) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_bitmap_free(CMCNP_BITMAP *cmcnp_bitmap)
{
    if(NULL_PTR != cmcnp_bitmap)
    {
        cmcnp_bitmap_clean(cmcnp_bitmap);
        free_static_mem(MM_CMCNP_BITMAP, cmcnp_bitmap, LOC_CMCNP_0015);
    }
    return (EC_TRUE);
}

CMCNP_BITMAP *cmcnp_bitmap_create(CMMAP_NODE *cmmap_node, const uint32_t np_id, const UINT32 nbits)
{
    CMCNP_BITMAP *cmcnp_bitmap;
    void         *data;
    UINT32        nbytes;

    alloc_static_mem(MM_CMCNP_BITMAP, &cmcnp_bitmap, LOC_CMCNP_0016);
    if(NULL_PTR == cmcnp_bitmap)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_create: "
                                              "malloc cmcnp_bitmap failed\n");
        return (NULL_PTR);
    }


    nbytes = ((nbits + 7) / 8);

    data = cmmap_node_alloc(cmmap_node, nbytes, CMCNP_MEM_ALIGNMENT, "cmc np bitmap");
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_create: "
                                              "create np %u bitmap failed\n",
                                              np_id);
        free_static_mem(MM_CMCNP_BITMAP, cmcnp_bitmap, LOC_CMCNP_0017);
        return (NULL_PTR);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_bitmap_create: "
                                          "create np %u bitmap done\n",
                                          np_id);

    BSET(data, 0, nbytes);

    CMCNP_BITMAP_DATA(cmcnp_bitmap) = data;
    CMCNP_BITMAP_SIZE(cmcnp_bitmap) = nbytes;

    return (cmcnp_bitmap);
}

CMCNP_BITMAP *cmcnp_bitmap_open(CMMAP_NODE *cmmap_node, const uint32_t np_id, const UINT32 nbits)
{
    CMCNP_BITMAP    *cmcnp_bitmap;
    void            *data;
    UINT32           nbytes;

    alloc_static_mem(MM_CMCNP_BITMAP, &cmcnp_bitmap, LOC_CMCNP_0018);
    if(NULL_PTR == cmcnp_bitmap)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_open: "
                                              "malloc cmcnp_bitmap failed\n");
        return (NULL_PTR);
    }

    nbytes = ((nbits + 7) / 8);

    data = cmmap_node_alloc(cmmap_node, nbytes, CMCNP_MEM_ALIGNMENT, "cmc np bitmap");
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_open: "
                                              "open np bitmap %u failed\n",
                                              np_id);
        free_static_mem(MM_CMCNP_BITMAP, cmcnp_bitmap, LOC_CMCNP_0019);
        return (NULL_PTR);
    }

    dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_bitmap_open: "
                                          "open np bitmap %u done\n",
                                          np_id);

    /*not reset data*/

    CMCNP_BITMAP_DATA(cmcnp_bitmap) = data;
    CMCNP_BITMAP_SIZE(cmcnp_bitmap) = nbytes;

    return (cmcnp_bitmap);
}

EC_BOOL cmcnp_bitmap_close(CMCNP_BITMAP *cmcnp_bitmap)
{
    if(NULL_PTR != cmcnp_bitmap)
    {
        if(NULL_PTR != CMCNP_BITMAP_DATA(cmcnp_bitmap))
        {
            CMCNP_BITMAP_DATA(cmcnp_bitmap) = NULL_PTR;
        }
        CMCNP_BITMAP_SIZE(cmcnp_bitmap) = 0;

        cmcnp_bitmap_free(cmcnp_bitmap);
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_bitmap_set(CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos)
{
    UINT32   byte_nth;
    UINT32   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCNP_BITMAP_SIZE(cmcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_set:"
                                              "overflow bit_pos %ld => nbytes %ld >= %ld\n",
                                              bit_pos, byte_nth,
                                              CMCNP_BITMAP_SIZE(cmcnp_bitmap));
        return (EC_FALSE);
    }

    CMCNP_BITMAP_DATA(cmcnp_bitmap)[ byte_nth ] |= (uint8_t)(1 << bit_nth);

    return (EC_TRUE);
}

EC_BOOL cmcnp_bitmap_clear(CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos)
{
    UINT32   byte_nth;
    UINT32   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCNP_BITMAP_SIZE(cmcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_clear: "
                                              "overflow bit_pos %ld => nbytes %ld >= %ld\n",
                                              bit_pos, byte_nth,
                                              CMCNP_BITMAP_SIZE(cmcnp_bitmap));
        return (EC_FALSE);
    }

    if(0 == (CMCNP_BITMAP_DATA(cmcnp_bitmap)[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_clear: it_pos %ld was NOT set!\n",
                        bit_pos);
        return (EC_FALSE);
    }

    CMCNP_BITMAP_DATA(cmcnp_bitmap)[ byte_nth ] &= (uint8_t)(~(1 << bit_nth));

    return (EC_TRUE);
}

EC_BOOL cmcnp_bitmap_get(const CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos, uint8_t *bit_val)
{
    UINT32   byte_nth;
    UINT32   bit_nth;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCNP_BITMAP_SIZE(cmcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_get: "
                                              "overflow bit_pos %ld => nbytes %ld >= %ld\n",
                                              bit_pos, byte_nth,
                                              CMCNP_BITMAP_SIZE(cmcnp_bitmap));
        return (EC_FALSE);
    }

    if(0 == (CMCNP_BITMAP_DATA(cmcnp_bitmap)[ byte_nth ] & (uint8_t)(1 << bit_nth)))
    {
        (*bit_val) = 0;
    }
    else
    {
        (*bit_val) = 1;
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_bitmap_is(const CMCNP_BITMAP *cmcnp_bitmap, const UINT32 bit_pos, const uint8_t bit_val)
{
    UINT32   byte_nth;
    UINT32   bit_nth;
    uint8_t  e;

    byte_nth = (bit_pos >> 3); /*bit_pos / 8*/
    bit_nth  = (bit_pos & 7);  /*bit_pos % 8*/

    if(CMCNP_BITMAP_SIZE(cmcnp_bitmap) <= byte_nth)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_bitmap_is: "
                                              "overflow bit_pos %ld => nbytes %ld >= %ld\n",
                                              bit_pos, byte_nth,
                                              CMCNP_BITMAP_SIZE(cmcnp_bitmap));
        return (EC_FALSE);
    }

    e = (CMCNP_BITMAP_DATA(cmcnp_bitmap)[ byte_nth ] & (uint8_t)(1 << bit_nth));

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

void cmcnp_bitmap_print(LOG *log, const CMCNP_BITMAP *cmcnp_bitmap)
{
    UINT32   byte_nth;

    for(byte_nth = 0; byte_nth < CMCNP_BITMAP_SIZE(cmcnp_bitmap); byte_nth ++)
    {
        UINT32 bit_nth;
        uint8_t  bit_val;
        uint8_t  byte_val;

        byte_val = CMCNP_BITMAP_DATA(cmcnp_bitmap)[ byte_nth ];
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
UINT32 cmcnp_bitmap_count_bits(const CMCNP_BITMAP *cmcnp_bitmap, const UINT32 s_bit_pos, const UINT32 e_bit_pos)
{
    UINT32   s_byte_nth;
    UINT32   e_byte_nth;

    UINT32   byte_nth;
    UINT32   bits_count;

    s_byte_nth     = (s_bit_pos & (~7));
    e_byte_nth     = (e_bit_pos + 7) & (~7);
    bits_count     = 0;

    for(byte_nth = s_byte_nth; byte_nth < e_byte_nth; byte_nth ++)
    {
        bits_count += g_nbits_per_byte[ CMCNP_BITMAP_DATA(cmcnp_bitmap)[ byte_nth ] ];
    }
    return (bits_count);
}

STATIC_CAST static CMCNP_HEADER * __cmcnp_header_sync(CMCNP_HEADER *cmcnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != cmcnp_header)
    {
        if(0 != msync(cmcnp_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "warn:__cmcnp_header_sync: "
                                "sync cmcnp_hdr of np %u %d with size %ld failed\n",
                                np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] __cmcnp_header_sync: "
                                "sync cmcnp_hdr of np %u %d with size %ld done\n",
                                np_id, fd, fsize);
        }
    }
    return (cmcnp_header);
}

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_create(CMMAP_NODE *cmmap_node, const uint32_t np_id, const uint8_t np_model, const UINT32 fsize)
{
    CMCNP_HEADER    *cmcnp_header;
    uint32_t         node_max_num;
    uint32_t         node_sizeof;

    cmcnp_header = cmmap_node_alloc(cmmap_node, fsize, CMCNP_MEM_ALIGNMENT, "cmc np header");
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_create: "
                                              "create np %u header failed\n",
                                              np_id);
        return (NULL_PTR);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] __cmcnp_header_create: "
                                          "create np %u header done\n",
                                          np_id);

    CMCNP_HEADER_NP_ID(cmcnp_header)        = np_id;
    CMCNP_HEADER_MODEL(cmcnp_header)        = np_model;
    CMCNP_HEADER_DEG_NODE_NUM(cmcnp_header) = 0;

    cmcnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CMCNP_ITEM);

    /*init RB Nodes*/
    cmcnprb_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init QUE nodes*/
    cmcnpque_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cmcnpdel_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init DEG nodes*/
    cmcnpdeg_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    return (cmcnp_header);
}

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_open(CMMAP_NODE *cmmap_node, const uint32_t np_id, const uint8_t np_model, const UINT32 fsize)
{
    CMCNP_HEADER    *cmcnp_header;

    cmcnp_header = cmmap_node_alloc(cmmap_node, fsize, CMCNP_MEM_ALIGNMENT, "cmc np header");
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_open: "
                                              "load np %u failed\n",
                                              np_id);

        return (NULL_PTR);
    }

    dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] __cmcnp_header_open: "
                                          "load np %u done\n",
                                          np_id);
    return (cmcnp_header);
}

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_close(CMCNP_HEADER *cmcnp_header, const uint32_t np_id, const UINT32 fsize)
{
    /*do nothing*/

    /*cmcnp_header cannot be accessed again*/
    return (NULL_PTR);
}

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_new(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model)
{
    CMCNP_HEADER *cmcnp_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    cmcnp_header = (CMCNP_HEADER *)safe_malloc(fsize, LOC_CMCNP_0020);
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_new: new header with %ld bytes for np %u fd %d failed\n",
                           fsize, np_id, fd);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_mlock((void *)cmcnp_header, fsize))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_new: mlock %p, size %ld failed\n",
                            cmcnp_header, fsize);

        safe_free(cmcnp_header, LOC_CMCNP_0021);
        return (NULL_PTR);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] __cmcnp_header_new: mlock %p, size %ld done\n",
                        cmcnp_header, fsize);

    CMCNP_HEADER_NP_ID(cmcnp_header)        = np_id;
    CMCNP_HEADER_MODEL(cmcnp_header)        = np_model;
    CMCNP_HEADER_DEG_NODE_NUM(cmcnp_header) = 0;

    cmcnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CMCNP_ITEM);

    /*init RB Nodes*/
    cmcnprb_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init QUE nodes*/
    cmcnpque_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cmcnpdel_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init DEG nodes*/
    cmcnpdeg_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] __cmcnp_header_new: np %u, model %u, size %ld, nodes %u\n",
                                          np_id, np_model, fsize, node_max_num);
    return (cmcnp_header);
}

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_free(CMCNP_HEADER *cmcnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != cmcnp_header)
    {
        UINT32 offset;

        offset = 0;
        if(
           ERR_FD != fd
        && EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)cmcnp_header)
        )
        {
            dbg_log(SEC_0111_CMCNP, 1)(LOGSTDOUT, "warn:__cmcnp_header_free: flush cmcnp_hdr of np %u fd %d with size %ld failed\n",
                               np_id, fd, fsize);
        }

        if(EC_FALSE == c_munlock((void *)cmcnp_header, fsize))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_free: munlock %p, size %ld failed\n",
                                cmcnp_header, fsize);
        }
        else
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] __cmcnp_header_free: munlock %p, size %ld done\n",
                                cmcnp_header, fsize);
        }

        safe_free(cmcnp_header, LOC_CMCNP_0022);
    }

    /*cmcnp_header cannot be accessed again*/
    return (NULL_PTR);
}

EC_BOOL cmcnp_header_init(CMCNP_HEADER *cmcnp_header, const uint32_t np_id, const uint8_t model)
{
    CMCNP_HEADER_NP_ID(cmcnp_header)         = np_id;
    CMCNP_HEADER_MODEL(cmcnp_header)         = model;

    /*do nothing on que list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CMCNPRB_POOL pool*/

    return (EC_TRUE);
}

EC_BOOL cmcnp_header_clean(CMCNP_HEADER *cmcnp_header)
{
    CMCNP_HEADER_NP_ID(cmcnp_header)              = CMCNP_ERR_ID;
    CMCNP_HEADER_MODEL(cmcnp_header)              = CMCNP_ERR_MODEL;

    /*do nothing on que list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CMCNPRB_POOL pool*/

    return (EC_TRUE);
}

REAL cmcnp_header_used_ratio(const CMCNP_HEADER *cmcnp_header)
{
    if(0 < CMCNP_HEADER_ITEMS_MAX_NUM(cmcnp_header))
    {
        REAL node_used_num;
        REAL node_max_num;

        node_used_num = (CMCNP_HEADER_ITEMS_USED_NUM(cmcnp_header) + 0.0);
        node_max_num  = (CMCNP_HEADER_ITEMS_MAX_NUM(cmcnp_header)  + 0.0);

        return (node_used_num / node_max_num);
    }

    return (0.0);
}

REAL cmcnp_header_deg_ratio(const CMCNP_HEADER *cmcnp_header)
{
    if(0 < CMCNP_HEADER_ITEMS_USED_NUM(cmcnp_header))
    {
        REAL node_used_num;
        REAL deg_node_num;

        node_used_num = (CMCNP_HEADER_ITEMS_USED_NUM(cmcnp_header) + 0.0);
        deg_node_num  = (CMCNP_HEADER_DEG_NODE_NUM(cmcnp_header)  + 0.0);

        return (deg_node_num / node_used_num);
    }

    return (0.0);
}

CMCNP *cmcnp_new()
{
    CMCNP *cmcnp;

    alloc_static_mem(MM_CMCNP, &cmcnp, LOC_CMCNP_0023);
    if(NULL_PTR != cmcnp)
    {
        cmcnp_init(cmcnp);
    }
    return (cmcnp);
}

EC_BOOL cmcnp_init(CMCNP *cmcnp)
{
    CMCNP_RDONLY_FLAG(cmcnp)     = BIT_FALSE;
    CMCNP_FD(cmcnp)              = ERR_FD;
    CMCNP_FSIZE(cmcnp)           = 0;
    CMCNP_FNAME(cmcnp)           = NULL_PTR;
    CMCNP_DEL_SIZE(cmcnp)        = 0;
    CMCNP_RECYCLE_SIZE(cmcnp)    = 0;
    CMCNP_BITMAP(cmcnp)          = NULL_PTR;
    CMCNP_HDR(cmcnp)             = NULL_PTR;
    CMCNP_QUE_LIST(cmcnp)        = NULL_PTR;
    CMCNP_DEL_LIST(cmcnp)        = NULL_PTR;
    CMCNP_DEG_LIST(cmcnp)        = NULL_PTR;

    cmcnp_retire_cb_init(CMCNP_RETIRE_CB(cmcnp));
    cmcnp_degrade_cb_init(CMCNP_DEGRADE_CB(cmcnp));

    return (EC_TRUE);
}

EC_BOOL cmcnp_is_full(const CMCNP *cmcnp)
{
    CMCNPRB_POOL *pool;

    pool = CMCNP_ITEMS_POOL(cmcnp);
    return cmcnprb_pool_is_full(pool);
}

EC_BOOL cmcnp_que_list_is_empty(const CMCNP *cmcnp)
{
    return cmcnpque_is_empty(CMCNP_QUE_LIST(cmcnp));
}

EC_BOOL cmcnp_del_list_is_empty(const CMCNP *cmcnp)
{
    return cmcnpdel_is_empty(CMCNP_DEL_LIST(cmcnp));
}

EC_BOOL cmcnp_deg_list_is_empty(const CMCNP *cmcnp)
{
    return cmcnpdeg_is_empty(CMCNP_DEG_LIST(cmcnp));
}

EC_BOOL cmcnp_reserve_key(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    uint32_t      page_no;

    for(page_no = CMCNP_KEY_S_PAGE(cmcnp_key);
        page_no < CMCNP_KEY_E_PAGE(cmcnp_key);
        page_no ++)
    {
        if(EC_FALSE == cmcnp_bitmap_set(CMCNP_BITMAP(cmcnp), page_no))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_reserve_key: set page %u failed\n", page_no);

            /*rollback*/
            while(page_no -- > CMCNP_KEY_S_PAGE(cmcnp_key))
            {
                cmcnp_bitmap_clear(CMCNP_BITMAP(cmcnp), page_no);
            }

            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_release_key(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    uint32_t      page_no;

    for(page_no = CMCNP_KEY_S_PAGE(cmcnp_key);
        page_no < CMCNP_KEY_E_PAGE(cmcnp_key);
        page_no ++)
    {
        cmcnp_bitmap_clear(CMCNP_BITMAP(cmcnp), page_no);
    }

    return (EC_TRUE);
}

void cmcnp_header_print(LOG *log, const CMCNP *cmcnp)
{
    const CMCNP_HEADER *cmcnp_header;

    cmcnp_header = CMCNP_HDR(cmcnp);

    sys_log(log, "np %u, model %u, item max num %u, item used num %u, deg node num %u\n",
                CMCNP_HEADER_NP_ID(cmcnp_header),
                CMCNP_HEADER_MODEL(cmcnp_header),
                CMCNP_HEADER_ITEMS_MAX_NUM(cmcnp_header),
                CMCNP_HEADER_ITEMS_USED_NUM(cmcnp_header),
                CMCNP_HEADER_DEG_NODE_NUM(cmcnp_header)
        );

    cmcnprb_pool_print(log, CMCNP_HEADER_ITEMS_POOL(cmcnp_header));
    return;
}

void cmcnp_print(LOG *log, const CMCNP *cmcnp)
{
    sys_log(log, "cmcnp %p: np %u, fname %s\n",
                 cmcnp,
                 CMCNP_ID(cmcnp),
                 CMCNP_FNAME(cmcnp)
                 );

    sys_log(log, "cmcnp %p: np %u, fsize %lu, del size %llu, recycle size %llu\n",
                 cmcnp,
                 CMCNP_ID(cmcnp),
                 CMCNP_FSIZE(cmcnp),
                 CMCNP_DEL_SIZE(cmcnp),
                 CMCNP_RECYCLE_SIZE(cmcnp)
                 );

    sys_log(log, "cmcnp %p: header: \n", cmcnp);
    cmcnp_header_print(log, cmcnp);
    return;
}

void cmcnp_print_que_list(LOG *log, const CMCNP *cmcnp)
{
    sys_log(log, "cmcnp_print_que_list: cmcnp %p: que list: \n", cmcnp);
    cmcnpque_list_print(log, cmcnp);
    return;
}

void cmcnp_print_del_list(LOG *log, const CMCNP *cmcnp)
{
    sys_log(log, "cmcnp_print_del_list: cmcnp %p: del list: \n", cmcnp);
    cmcnpdel_list_print(log, cmcnp);
    return;
}

void cmcnp_print_deg_list(LOG *log, const CMCNP *cmcnp)
{
    sys_log(log, "cmcnp_print_deg_list: cmcnp %p: deg list: \n", cmcnp);
    cmcnpdeg_list_print(log, cmcnp);
    return;
}

void cmcnp_print_bitmap(LOG *log, const CMCNP *cmcnp)
{
    sys_log(log, "cmcnp_print_bitmap: cmcnp %p: bitmap: \n", cmcnp);
    cmcnp_bitmap_print(log, CMCNP_BITMAP(cmcnp));
    return;
}

CMCNP_ITEM *cmcnp_dnode_find(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key)
{
    const CMCNPRB_POOL *pool;
    uint32_t root_pos;
    uint32_t node_pos;

    pool     = CMCNP_ITEMS_POOL(cmcnp);
    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);

    node_pos = cmcnprb_tree_search_data(pool, root_pos, cmcnp_key);

    if(CMCNPRB_ERR_POS != node_pos)
    {
        const CMCNPRB_NODE *node;
        const CMCNP_ITEM   *item;

        node = CMCNPRB_POOL_NODE(pool, node_pos);
        item = CMCNP_RB_NODE_ITEM(node);

        return (CMCNP_ITEM *)(item);
    }

    return (NULL_PTR);
}

uint32_t cmcnp_dnode_search(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key)
{
    const CMCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CMCNP_ITEMS_POOL(cmcnp);
    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);

    return cmcnprb_tree_search_data(pool, root_pos, cmcnp_key);
}

void cmcnp_dnode_walk(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, void (*walker)(void *, const void *, const uint32_t), void *arg)
{
    const CMCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CMCNP_ITEMS_POOL(cmcnp);
    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);

    cmcnprb_inorder_walk(pool, root_pos, walker, arg, (const void *)cmcnp);
    return;
}

uint32_t cmcnp_dnode_find_intersected(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key)
{
    const CMCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CMCNP_ITEMS_POOL(cmcnp);
    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);

    return cmcnprb_tree_find_intersected_data(pool, root_pos, cmcnp_key);
}

uint32_t cmcnp_dnode_find_closest(const CMCNP *cmcnp, const CMCNP_DNODE *cmcnp_dnode, const CMCNP_KEY *cmcnp_key)
{
    const CMCNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CMCNP_ITEMS_POOL(cmcnp);
    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);

    return cmcnprb_tree_find_closest_data(pool, root_pos, cmcnp_key);
}

uint32_t cmcnp_dnode_insert(CMCNP *cmcnp, const uint32_t parent_pos, const CMCNP_KEY *cmcnp_key, const uint32_t dir_flag)
{
    uint32_t insert_offset;
    uint32_t root_pos;

    CMCNP_ITEM *cmcnp_item_parent;
    CMCNP_ITEM *cmcnp_item_insert;

    CMCNP_DNODE *cmcnp_dnode_parent;

    if(CMCNP_ITEM_FILE_IS_REG != dir_flag
    && CMCNP_ITEM_FILE_IS_DIR != dir_flag)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_dnode_insert: invalid input dir flag %x\n", dir_flag);
        return (CMCNPRB_ERR_POS);
    }

    if(EC_TRUE == cmcnp_is_full(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_dnode_insert: cmcnp is full\n");
        return (CMCNPRB_ERR_POS);
    }

    cmcnp_item_parent = cmcnp_fetch(cmcnp, parent_pos);/*must be dnode*/
    if(NULL_PTR == cmcnp_item_parent)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_dnode_insert: fetch parent item failed where parent offset %u\n", parent_pos);
        return (CMCNPRB_ERR_POS);
    }

    cmcnp_dnode_parent = CMCNP_ITEM_DNODE(cmcnp_item_parent);
    if(CMCNP_ITEM_FILE_IS_DIR != CMCNP_ITEM_DIR_FLAG(cmcnp_item_parent)
    || CMCNP_ITEM_IS_NOT_USED == CMCNP_ITEM_USED_FLAG(cmcnp_item_parent))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_dnode_insert: invalid dir flag %u or stat %u\n",
                            CMCNP_ITEM_DIR_FLAG(cmcnp_item_parent),
                            CMCNP_ITEM_USED_FLAG(cmcnp_item_parent));
        return (CMCNPRB_ERR_POS);
    }

    /*insert the item to parent and update parent*/
    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode_parent);

    //dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_dnode_insert: cmcnp %p, header %p, pool %p\n", cmcnp, CMCNP_HDR(cmcnp), CMCNP_ITEMS_POOL(cmcnp));

    if(EC_FALSE == cmcnprb_tree_insert_data(CMCNP_ITEMS_POOL(cmcnp), &root_pos, cmcnp_key, &insert_offset))
    {
        dbg_log(SEC_0111_CMCNP, 1)(LOGSTDOUT, "warn:cmcnp_dnode_insert: found duplicate rb node with root %u at node %u\n", root_pos, insert_offset);
        return (insert_offset);
    }
    cmcnp_item_insert = cmcnp_fetch(cmcnp, insert_offset);

    /*fill in cmcnp_item_insert*/
    cmcnp_item_set_key(cmcnp_item_insert, cmcnp_key);
    CMCNP_ITEM_PARENT_POS(cmcnp_item_insert) = parent_pos;

    if(CMCNP_ITEM_FILE_IS_REG == dir_flag)
    {
        cmcnp_fnode_init(CMCNP_ITEM_FNODE(cmcnp_item_insert));
        CMCNP_ITEM_DIR_FLAG(cmcnp_item_insert) = CMCNP_ITEM_FILE_IS_REG;
    }
    else if(CMCNP_ITEM_FILE_IS_DIR == dir_flag)
    {
        cmcnp_dnode_init(CMCNP_ITEM_DNODE(cmcnp_item_insert));
        CMCNP_ITEM_DIR_FLAG(cmcnp_item_insert) = CMCNP_ITEM_FILE_IS_DIR;
    }

    CMCNP_ITEM_USED_FLAG(cmcnp_item_insert) = CMCNP_ITEM_IS_USED;
    CMCNP_ITEM_DEG_TIMES(cmcnp_item_insert) = 0;

    CMCNP_DNODE_ROOT_POS(cmcnp_dnode_parent) = root_pos;
    CMCNP_DNODE_FILE_NUM(cmcnp_dnode_parent) ++;

    return (insert_offset);
}

/**
* umount one son from cmcnp_dnode,  where son is regular file item or dir item without any son
* cmcnp_dnode will be impacted on bucket and file num
**/
uint32_t cmcnp_dnode_umount_son(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, const uint32_t son_node_pos, const CMCNP_KEY *cmcnp_key)
{
    CMCNPRB_POOL        *pool;
    const CMCNP_ITEM    *son_cmcnp_item;
    const CMCNP_KEY     *son_cmcnp_key;

    son_cmcnp_item = cmcnp_fetch(cmcnp, son_node_pos);
    son_cmcnp_key  = CMCNP_ITEM_KEY(son_cmcnp_item);

    if(EC_TRUE == cmcnp_key_cmp(cmcnp_key, son_cmcnp_key))
    {
        uint32_t root_pos;

        root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);

        pool = CMCNP_ITEMS_POOL(cmcnp);
        cmcnprb_tree_erase(pool, son_node_pos, &root_pos); /*erase but not recycle node_pos ...*/

        CMCNP_DNODE_ROOT_POS(cmcnp_dnode) = root_pos;
        CMCNP_DNODE_FILE_NUM(cmcnp_dnode) --;
    }

    return (son_node_pos);
}

/*delete single item from dnode*/
STATIC_CAST static EC_BOOL __cmcnp_dnode_delete_item(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, CMCNP_ITEM *cmcnp_item)
{
    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        cmcnp_item_clean(cmcnp_item);
        CMCNP_DNODE_FILE_NUM(cmcnp_dnode) --;
    }

    else if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        cmcnp_dnode_delete_dir_son(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item));/*recursively*/
        cmcnp_item_clean(cmcnp_item);
        CMCNP_DNODE_FILE_NUM(cmcnp_dnode) --;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cmcnp_dnode_delete_all_items(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, const uint32_t node_pos)
{
    CMCNPRB_POOL *pool;
    CMCNPRB_NODE *node;
    CMCNP_ITEM   *item;

    pool = CMCNP_ITEMS_POOL(cmcnp);

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        __cmcnp_dnode_delete_all_items(cmcnp, cmcnp_dnode, CMCNPRB_NODE_LEFT_POS(node));
    }

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        __cmcnp_dnode_delete_all_items(cmcnp, cmcnp_dnode, CMCNPRB_NODE_RIGHT_POS(node));
    }

    item = CMCNP_RB_NODE_ITEM(node);
    __cmcnp_dnode_delete_item(cmcnp, cmcnp_dnode, item);

    /*cmcnprb recycle the rbnode, do not use cmcnprb_tree_delete which will change the tree structer*/
    cmcnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

/*delete one dir son, not including cmcnp_dnode itself*/
EC_BOOL cmcnp_dnode_delete_dir_son(const CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode)
{
    uint32_t root_pos;

    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);
    if(CMCNPRB_ERR_POS != root_pos)
    {
        __cmcnp_dnode_delete_all_items(cmcnp, cmcnp_dnode, root_pos);
        CMCNP_DNODE_ROOT_POS(cmcnp_dnode) = CMCNPRB_ERR_POS;
    }
    return (EC_TRUE);
}

uint32_t cmcnp_search(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    CMCNP_ITEM  *cmcnp_item;
    uint32_t     node_pos;

    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cmcnp_item = cmcnp_fetch(cmcnp, CMCNPRB_ROOT_POS);
    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    node_pos = cmcnp_dnode_search(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item), cmcnp_key);

    return (node_pos);
}

void cmcnp_walk(CMCNP *cmcnp, void (*walker)(void *, const void *, const uint32_t), void *arg)
{
    CMCNP_ITEM  *cmcnp_item;

    /*root item*/
    cmcnp_item = cmcnp_fetch(cmcnp, CMCNPRB_ROOT_POS);
    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    cmcnp_dnode_walk(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item), walker, arg);

    return;
}

/**
*
* if dflag is DIR or REG or BIG, ignore seg_no
* if dlfag is SEG, seg_no will be used
*
**/
uint32_t cmcnp_insert(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    uint32_t node_pos;

    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    node_pos = cmcnp_dnode_insert(cmcnp, CMCNPRB_ROOT_POS, cmcnp_key, dflag);

    dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_insert: np %u, insert at node_pos %u\n",
                        CMCNP_ID(cmcnp), node_pos);

    return (node_pos);
}

CMCNP_ITEM *cmcnp_fetch(const CMCNP *cmcnp, const uint32_t node_pos)
{
    if(CMCNPRB_ERR_POS != node_pos)
    {
        const CMCNPRB_POOL *pool;
        const CMCNPRB_NODE *node;

        pool = CMCNP_ITEMS_POOL(cmcnp);
        node = CMCNPRB_POOL_NODE(pool, node_pos);
        if(NULL_PTR != node)
        {
            return (CMCNP_ITEM *)CMCNP_RB_NODE_ITEM(node);
        }
    }
    //dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_fetch: np %u, fetch cmcnprb node %u failed\n", CMCNP_ID(cmcnp), node_pos);
    return (NULL_PTR);
}

EC_BOOL cmcnp_inode_update(CMCNP *cmcnp, CMCNP_INODE *cmcnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(src_disk_no  == CMCNP_INODE_DISK_NO(cmcnp_inode)
    && src_block_no == CMCNP_INODE_BLOCK_NO(cmcnp_inode)
    && src_page_no  == CMCNP_INODE_PAGE_NO(cmcnp_inode))
    {
        CMCNP_INODE_DISK_NO(cmcnp_inode)  = des_disk_no;
        CMCNP_INODE_BLOCK_NO(cmcnp_inode) = des_block_no;
        CMCNP_INODE_PAGE_NO(cmcnp_inode)  = des_page_no;
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_update(CMCNP *cmcnp, CMCNP_FNODE *cmcnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint16_t replica;

    for(replica = 0; replica < CMCNP_FNODE_REPNUM(cmcnp_fnode); replica ++)
    {
        cmcnp_inode_update(cmcnp, CMCNP_FNODE_INODE(cmcnp_fnode, replica),
                            src_disk_no, src_block_no, src_page_no,
                            des_disk_no, des_block_no, des_page_no);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cmcnp_bucket_update(CMCNP * cmcnp, CMCNPRB_POOL *pool, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CMCNPRB_NODE *node;
    CMCNP_ITEM   *item;

    if(CMCNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        __cmcnp_bucket_update(cmcnp, pool, CMCNPRB_NODE_LEFT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    item = CMCNP_RB_NODE_ITEM(node);

    cmcnp_item_update(cmcnp, item,
                       src_disk_no, src_block_no, src_page_no,
                       des_disk_no, des_block_no, des_page_no);


    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        __cmcnp_bucket_update(cmcnp, pool, CMCNPRB_NODE_RIGHT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_bucket_update(CMCNP *cmcnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CMCNPRB_POOL *pool;
    pool = CMCNP_ITEMS_POOL(cmcnp);

    return __cmcnp_bucket_update(cmcnp, pool, node_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);
}

EC_BOOL cmcnp_dnode_update(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    uint32_t root_pos;

    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);
    if(EC_FALSE == cmcnp_bucket_update(cmcnp, root_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_dnode_update: update root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_item_update(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(CMCNP_ITEM_IS_NOT_USED == CMCNP_ITEM_USED_FLAG(cmcnp_item))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_item_update: item was not used\n");
        return (EC_FALSE);
    }

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        return cmcnp_fnode_update(cmcnp, CMCNP_ITEM_FNODE(cmcnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        return cmcnp_dnode_update(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_item_update: invalid item dflag %u\n", CMCNP_ITEM_DIR_FLAG(cmcnp_item));
    return (EC_FALSE);
}

REAL cmcnp_used_ratio(const CMCNP *cmcnp)
{
    if(NULL_PTR != CMCNP_HDR(cmcnp))
    {
        return cmcnp_header_used_ratio(CMCNP_HDR(cmcnp));
    }

    return (0.0);
}

REAL cmcnp_deg_ratio(const CMCNP *cmcnp)
{
    if(NULL_PTR != CMCNP_HDR(cmcnp))
    {
        return cmcnp_header_deg_ratio(CMCNP_HDR(cmcnp));
    }

    return (0.0);
}

uint32_t cmcnp_deg_num(const CMCNP *cmcnp)
{
    if(NULL_PTR != CMCNP_HDR(cmcnp))
    {
        return CMCNP_DEG_NODE_NUM(cmcnp);
    }

    return (0);
}

CMCNP_ITEM *cmcnp_set(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    uint32_t     node_pos;
    CMCNP_ITEM  *cmcnp_item;

    if(EC_TRUE == cmcnp_is_read_only(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_set: np %u is read-only\n",
                                              CMCNP_ID(cmcnp));
        return (NULL_PTR);
    }

    node_pos = cmcnp_insert(cmcnp, cmcnp_key, dflag);
    cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
    if(NULL_PTR != cmcnp_item)
    {
        if(EC_FALSE == cmcnp_key_cmp(cmcnp_key, CMCNP_ITEM_KEY(cmcnp_item)))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_set: mismatched key [%u, %u) ! = [%u, %u)=> not override\n",
                            CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key),
                            CMCNP_KEY_S_PAGE(CMCNP_ITEM_KEY(cmcnp_item)), CMCNP_KEY_E_PAGE(CMCNP_ITEM_KEY(cmcnp_item)));
            return (NULL_PTR);
        }

        /*ensure only item of regular file enter QUE list*/
        if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
        {
            cmcnpque_node_add_head(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);

            cmcnpdeg_node_add_head(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
        }
        return (cmcnp_item);
    }
    return (NULL_PTR);
}

CMCNP_ITEM *cmcnp_get(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    return cmcnp_fetch(cmcnp, cmcnp_search(cmcnp, cmcnp_key, dflag));
}

CMCNP_FNODE *cmcnp_reserve(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_ITEM *cmcnp_item;

    if(EC_TRUE == cmcnp_is_read_only(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_reserve: np %u is read-only\n",
                                              CMCNP_ID(cmcnp));
        return (NULL_PTR);
    }

    cmcnp_item = cmcnp_set(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cmcnp_item)
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_reserve: set to np failed\n");
        return (NULL_PTR);
    }

    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    if(EC_FALSE == cmcnp_reserve_key(cmcnp, CMCNP_ITEM_KEY(cmcnp_item)))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_reserve: reserve [%u, %u) failed\n",
                                              CMCNP_ITEM_S_PAGE(cmcnp_item), CMCNP_ITEM_E_PAGE(cmcnp_item));

        cmcnp_delete(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
        return (NULL_PTR);
    }

    /*not import yet*/
    return CMCNP_ITEM_FNODE(cmcnp_item);
}

EC_BOOL cmcnp_release(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    if(EC_TRUE == cmcnp_is_read_only(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_release: np %u is read-only\n",
                                              CMCNP_ID(cmcnp));
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_delete(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_release: delete from np failed\n");
        return (EC_FALSE);
    }

    cmcnp_release_key(cmcnp, cmcnp_key);

    return (EC_TRUE);
}

EC_BOOL cmcnp_has_key(const CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_ASSERT(NULL_PTR != CMCNP_BITMAP(cmcnp));

    return cmcnp_bitmap_is(CMCNP_BITMAP(cmcnp), CMCNP_KEY_S_PAGE(cmcnp_key), (uint8_t)1);
}

EC_BOOL cmcnp_set_key(const CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_ASSERT(NULL_PTR != CMCNP_BITMAP(cmcnp));

    return cmcnp_bitmap_set(CMCNP_BITMAP(cmcnp), CMCNP_KEY_S_PAGE(cmcnp_key));
}

EC_BOOL cmcnp_clear_key(const CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_ASSERT(NULL_PTR != CMCNP_BITMAP(cmcnp));

    return cmcnp_bitmap_clear(CMCNP_BITMAP(cmcnp), CMCNP_KEY_S_PAGE(cmcnp_key));
}

CMCNP_FNODE *cmcnp_locate(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    uint32_t node_pos;

    node_pos = cmcnp_search(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNP_ITEM    *cmcnp_item;

        cmcnp_item = cmcnp_fetch(cmcnp, node_pos);

        if(EC_FALSE == cmcnp_is_read_only(cmcnp))
        {
            cmcnpque_node_move_head(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);

            /*move it if exist*/
            cmcnpdeg_node_move_head(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
        }

        return (CMCNP_ITEM_FNODE(cmcnp_item));
    }
    return (NULL_PTR);
}

CMCNP_ITEM *cmcnp_map(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    uint32_t node_pos;

    node_pos = cmcnp_search(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNP_ITEM    *cmcnp_item;

        cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
        if(EC_FALSE == cmcnp_is_read_only(cmcnp))
        {
            cmcnpque_node_move_head(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);

            /*move it if exist*/
            cmcnpdeg_node_move_head(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
        }
        return (cmcnp_item);
    }
    return (NULL_PTR);
}

EC_BOOL cmcnp_read(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, CMCNP_FNODE *cmcnp_fnode)
{
    uint32_t node_pos;

    node_pos = cmcnp_search(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNP_ITEM    *cmcnp_item;

        cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
        if(NULL_PTR != cmcnp_fnode)
        {
            cmcnp_fnode_import(CMCNP_ITEM_FNODE(cmcnp_item), cmcnp_fnode);
        }

        if(EC_FALSE == cmcnp_is_read_only(cmcnp))
        {
            cmcnpque_node_move_head(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);

            /*move it if exist*/
            cmcnpdeg_node_move_head(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
        }
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcnp_update(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const CMCNP_FNODE *cmcnp_fnode)
{
    uint32_t node_pos;

    CMCNP_ASSERT(EC_FALSE == cmcnp_is_read_only(cmcnp));

    node_pos = cmcnp_search(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNP_ITEM *cmcnp_item;

        cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
        cmcnpque_node_move_head(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);
        cmcnpdeg_node_move_head(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);

        return cmcnp_fnode_import(cmcnp_fnode, CMCNP_ITEM_FNODE(cmcnp_item));
    }
    return (EC_FALSE);
}

EC_BOOL cmcnp_delete(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    CMCNP_ITEM *cmcnp_item;
    uint32_t node_pos;

    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    node_pos = cmcnp_search(cmcnp, cmcnp_key, dflag);
    cmcnp_item = cmcnp_fetch(cmcnp, node_pos);

    if(NULL_PTR == cmcnp_item)
    {
        return (EC_FALSE);
    }

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        if(CMCNPRB_ERR_POS != CMCNP_ITEM_PARENT_POS(cmcnp_item))
        {
            CMCNP_ITEM  *cmcnp_item_parent;
            uint32_t     node_pos_t;

            cmcnp_item_parent = cmcnp_fetch(cmcnp, CMCNP_ITEM_PARENT_POS(cmcnp_item));
            node_pos_t = cmcnp_dnode_umount_son(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item_parent), node_pos,
                                                  CMCNP_ITEM_KEY(cmcnp_item));

            //CMCNP_ASSERT(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                cmcnprb_node_free(CMCNP_ITEMS_POOL(cmcnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_delete: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CMCNP_ID(cmcnp),
                                node_pos, CMCNP_ITEM_PARENT_POS(cmcnp_item), node_pos_t);

                CMCNP_ITEM_PARENT_POS(cmcnp_item) = CMCNPRB_ERR_POS; /*fix*/
            }
        }

        cmcnp_item_clean(cmcnp_item);

        return (EC_TRUE);
    }

    if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        if(CMCNPRB_ERR_POS != CMCNP_ITEM_PARENT_POS(cmcnp_item))
        {
            CMCNP_ITEM *cmcnp_item_parent;
            uint32_t     node_pos_t;

            cmcnp_item_parent = cmcnp_fetch(cmcnp, CMCNP_ITEM_PARENT_POS(cmcnp_item));

            node_pos_t = cmcnp_dnode_umount_son(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item_parent), node_pos,
                                                CMCNP_ITEM_KEY(cmcnp_item));

            //CMCNP_ASSERT(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                cmcnp_dnode_delete_dir_son(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item));

                cmcnprb_node_free(CMCNP_ITEMS_POOL(cmcnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_delete: np %u, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CMCNP_ID(cmcnp),
                                node_pos, CMCNP_ITEM_PARENT_POS(cmcnp_item), node_pos_t);

                CMCNP_ITEM_PARENT_POS(cmcnp_item) = CMCNPRB_ERR_POS; /*fix*/
            }
        }

        cmcnp_item_clean(cmcnp_item);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_set_read_only(CMCNP *cmcnp)
{
    if(BIT_TRUE == CMCNP_RDONLY_FLAG(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_set_read_only: "
                                              "cmcnp is set already read-only\n");

        return (EC_FALSE);
    }

    CMCNP_RDONLY_FLAG(cmcnp) = BIT_TRUE;

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_set_read_only: "
                                          "set cmcnp read-only\n");

    return (EC_TRUE);
}

EC_BOOL cmcnp_unset_read_only(CMCNP *cmcnp)
{
    if(BIT_FALSE == CMCNP_RDONLY_FLAG(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_unset_read_only: "
                                              "cmcnp was not set read-only\n");

        return (EC_FALSE);
    }

    CMCNP_RDONLY_FLAG(cmcnp) = BIT_FALSE;

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_unset_read_only: "
                                          "unset cmcnp read-only\n");

    return (EC_TRUE);
}

EC_BOOL cmcnp_is_read_only(const CMCNP *cmcnp)
{
    if(BIT_FALSE == CMCNP_RDONLY_FLAG(cmcnp))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


EC_BOOL cmcnp_set_ssd_dirty(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    uint32_t node_pos;

    CMCNP_ASSERT(EC_FALSE == cmcnp_is_read_only(cmcnp));

    node_pos = cmcnp_search(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNP_ITEM  *cmcnp_item;

        cmcnp_item  = cmcnp_fetch(cmcnp, node_pos);

        CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item) = BIT_TRUE;

        cmcnpdeg_node_add_head(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcnp_set_ssd_not_dirty(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    uint32_t node_pos;

    CMCNP_ASSERT(EC_FALSE == cmcnp_is_read_only(cmcnp));

    node_pos = cmcnp_search(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNP_ITEM  *cmcnp_item;

        cmcnp_item  = cmcnp_fetch(cmcnp, node_pos);

        CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item) = BIT_FALSE;

        cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcnp_degrade_cb_init(CMCNP_DEGRADE_CB *cmcnp_degrade_cb)
{
    CMCNP_DEGRADE_CB_SSD_FLAG(cmcnp_degrade_cb)     = BIT_FALSE;
    CMCNP_DEGRADE_CB_SATA_FLAG(cmcnp_degrade_cb)    = BIT_FALSE;

    CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb)         = NULL_PTR;
    CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb)          = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_degrade_cb_clean(CMCNP_DEGRADE_CB *cmcnp_degrade_cb)
{
    CMCNP_DEGRADE_CB_SSD_FLAG(cmcnp_degrade_cb)     = BIT_FALSE;
    CMCNP_DEGRADE_CB_SATA_FLAG(cmcnp_degrade_cb)    = BIT_FALSE;

    CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb)         = NULL_PTR;
    CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb)          = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_degrade_cb_clone(CMCNP_DEGRADE_CB *cmcnp_degrade_cb_src, CMCNP_DEGRADE_CB *cmcnp_degrade_cb_des)
{
    CMCNP_DEGRADE_CB_SSD_FLAG(cmcnp_degrade_cb_des)     = CMCNP_DEGRADE_CB_SSD_FLAG(cmcnp_degrade_cb_src);
    CMCNP_DEGRADE_CB_SATA_FLAG(cmcnp_degrade_cb_des)    = CMCNP_DEGRADE_CB_SATA_FLAG(cmcnp_degrade_cb_src);

    CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb_des)         = CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb_src);
    CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb_des)          = CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb_src);

    return (EC_TRUE);
}

EC_BOOL cmcnp_degrade_cb_set(CMCNP_DEGRADE_CB *cmcnp_degrade_cb, const uint32_t flags, CMCNP_DEGRADE_CALLBACK func, void *arg)
{
    if(CMCNP_DEGRADE_SSD & flags)
    {
        CMCNP_DEGRADE_CB_SSD_FLAG(cmcnp_degrade_cb)     = BIT_TRUE;
    }
    else
    {
        CMCNP_DEGRADE_CB_SSD_FLAG(cmcnp_degrade_cb)     = BIT_FALSE;
    }

    if(CMCNP_DEGRADE_SATA & flags)
    {
        CMCNP_DEGRADE_CB_SATA_FLAG(cmcnp_degrade_cb)    = BIT_TRUE;
    }
    else
    {
        CMCNP_DEGRADE_CB_SATA_FLAG(cmcnp_degrade_cb)    = BIT_FALSE;
    }

    CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb) = func;
    CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb)  = arg;

    return (EC_TRUE);
}

EC_BOOL cmcnp_init_degrade_callback(CMCNP *cmcnp)
{
    return cmcnp_degrade_cb_init(CMCNP_DEGRADE_CB(cmcnp));
}

EC_BOOL cmcnp_clean_degrade_callback(CMCNP *cmcnp)
{
    return cmcnp_degrade_cb_clean(CMCNP_DEGRADE_CB(cmcnp));
}

EC_BOOL cmcnp_set_degrade_callback(CMCNP *cmcnp, const uint32_t flags, CMCNP_DEGRADE_CALLBACK func, void *arg)
{
    return cmcnp_degrade_cb_set(CMCNP_DEGRADE_CB(cmcnp), flags, func, arg);
}

EC_BOOL cmcnp_exec_degrade_callback(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t node_pos)
{
    CMCNP_ITEM          *cmcnp_item;
    CMCNP_FNODE         *cmcnp_fnode;
    CMCNP_INODE         *cmcnp_inode;
    CMCNP_DEGRADE_CB    *cmcnp_degrade_cb;

    CMCNP_ASSERT(EC_FALSE == cmcnp_is_read_only(cmcnp));

    cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
    if(NULL_PTR == cmcnp_item)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_exec_degrade_callback:"
                                              "item %u is null\n",
                                              node_pos);
        return (EC_FALSE);
    }

    cmcnp_degrade_cb = CMCNP_DEGRADE_CB(cmcnp);
    if(NULL_PTR == CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb)
    || NULL_PTR == CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb))
    {
        dbg_log(SEC_0111_CMCNP, 1)(LOGSTDOUT, "warn:cmcnp_exec_degrade_callback:"
                                              "callback func %p or callback arg %p is null\n",
                                              CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb),
                                              CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb));

        return (EC_FALSE);
    }

    if(CMCNP_ITEM_FILE_IS_REG != CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_exec_degrade_callback:"
                                              "item %u is dir\n",
                                              node_pos);
        cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
        return (EC_FALSE);
    }

    cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    /*degrade to ssd*/
    if(BIT_TRUE == CMCNP_DEGRADE_CB_SSD_FLAG(cmcnp_degrade_cb))
    {
        if(BIT_FALSE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item))
        {
            dbg_log(SEC_0111_CMCNP, 7)(LOGSTDOUT, "[DEBUG] cmcnp_exec_degrade_callback:"
                                                  "[ssd] degrade callback at key [%u, %u), "
                                                  "disk %u, block %u, page %u was flushed\n",
                                                  CMCNP_KEY_S_PAGE(cmcnp_key),
                                                  CMCNP_KEY_E_PAGE(cmcnp_key),
                                                  CMCNP_INODE_DISK_NO(cmcnp_inode),
                                                  CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                                  CMCNP_INODE_PAGE_NO(cmcnp_inode));

            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            return (EC_FALSE);/*xxx*/
        }

        CMCNP_ITEM_DEG_TIMES(cmcnp_item) ++;
        if(0 == CMCNP_ITEM_DEG_TIMES(cmcnp_item)) /*exception*/
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "fatal error:cmcnp_exec_degrade_callback:"
                                                  "[ssd] degrade callback at key [%u, %u), "
                                                  "disk %u, block %u, page %u => deg reach max times!\n",
                                                  CMCNP_KEY_S_PAGE(cmcnp_key),
                                                  CMCNP_KEY_E_PAGE(cmcnp_key),
                                                  CMCNP_INODE_DISK_NO(cmcnp_inode),
                                                  CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                                  CMCNP_INODE_PAGE_NO(cmcnp_inode));

            CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item) = BIT_FALSE; /*force to clear flag!*/
            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            return (EC_FALSE);/*xxx*/
        }

        if(EC_FALSE == CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb)(
                                      CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb),
                                      cmcnp_key,
                                      cmcnp_item,
                                      CMCNP_INODE_DISK_NO(cmcnp_inode),
                                      CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                      CMCNP_INODE_PAGE_NO(cmcnp_inode)))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_exec_degrade_callback:"
                                                  "[ssd] degrade callback at key [%u, %u), "
                                                  "disk %u, block %u, page %u failed\n",
                                                  CMCNP_KEY_S_PAGE(cmcnp_key),
                                                  CMCNP_KEY_E_PAGE(cmcnp_key),
                                                  CMCNP_INODE_DISK_NO(cmcnp_inode),
                                                  CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                                  CMCNP_INODE_PAGE_NO(cmcnp_inode));
            return (EC_FALSE);
        }

        CMCNP_ITEM_DEG_TIMES(cmcnp_item)      = 0;         /*reset counter*/
        CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item) = BIT_FALSE; /*clear flag*/
        cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);

        dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_exec_degrade_callback:"
                                              "[ssd] degrade callback at key [%u, %u), "
                                              "disk %u, block %u, page %u done\n",
                                              CMCNP_KEY_S_PAGE(cmcnp_key),
                                              CMCNP_KEY_E_PAGE(cmcnp_key),
                                              CMCNP_INODE_DISK_NO(cmcnp_inode),
                                              CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                              CMCNP_INODE_PAGE_NO(cmcnp_inode));
    }

    /*degrade to sata*/
    else if(BIT_TRUE == CMCNP_DEGRADE_CB_SATA_FLAG(cmcnp_degrade_cb))
    {
        ASSERT(BIT_TRUE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item));

        if(BIT_FALSE == CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item))
        {
            dbg_log(SEC_0111_CMCNP, 7)(LOGSTDOUT, "[DEBUG] cmcnp_exec_degrade_callback:"
                                                  "[sata] degrade callback at key [%u, %u), "
                                                  "disk %u, block %u, page %u was flushed\n",
                                                  CMCNP_KEY_S_PAGE(cmcnp_key),
                                                  CMCNP_KEY_E_PAGE(cmcnp_key),
                                                  CMCNP_INODE_DISK_NO(cmcnp_inode),
                                                  CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                                  CMCNP_INODE_PAGE_NO(cmcnp_inode));

            CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item) = BIT_FALSE; /*trick! following sata dirty flag!*/

            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            return (EC_TRUE);/*xxx*/
        }

        CMCNP_ITEM_DEG_TIMES(cmcnp_item) ++;
        if(0 == CMCNP_ITEM_DEG_TIMES(cmcnp_item)) /*exception*/
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "fatal error:cmcnp_exec_degrade_callback:"
                                                  "[sata] degrade callback at key [%u, %u), "
                                                  "disk %u, block %u, page %u => deg reach max times!\n",
                                                  CMCNP_KEY_S_PAGE(cmcnp_key),
                                                  CMCNP_KEY_E_PAGE(cmcnp_key),
                                                  CMCNP_INODE_DISK_NO(cmcnp_inode),
                                                  CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                                  CMCNP_INODE_PAGE_NO(cmcnp_inode));

            CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item) = BIT_FALSE; /*force to clear flag!*/
            CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item)  = BIT_FALSE; /*trick! following sata dirty flag!*/

            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            return (EC_FALSE);/*xxx*/
        }

        if(EC_FALSE == CMCNP_DEGRADE_CB_FUNC(cmcnp_degrade_cb)(
                                      CMCNP_DEGRADE_CB_ARG(cmcnp_degrade_cb),
                                      cmcnp_key,
                                      cmcnp_item,
                                      CMCNP_INODE_DISK_NO(cmcnp_inode),
                                      CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                      CMCNP_INODE_PAGE_NO(cmcnp_inode)))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_exec_degrade_callback:"
                                                  "[sata] degrade callback at key [%u, %u), "
                                                  "disk %u, block %u, page %u failed\n",
                                                  CMCNP_KEY_S_PAGE(cmcnp_key),
                                                  CMCNP_KEY_E_PAGE(cmcnp_key),
                                                  CMCNP_INODE_DISK_NO(cmcnp_inode),
                                                  CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                                  CMCNP_INODE_PAGE_NO(cmcnp_inode));
            return (EC_FALSE);
        }

        CMCNP_ITEM_DEG_TIMES(cmcnp_item)       = 0;         /*reset counter*/
        CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item) = BIT_FALSE; /*clear flag*/
        CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item)  = BIT_FALSE; /*trick! following sata dirty flag!*/
        cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);

        dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_exec_degrade_callback:"
                                              "[sata] degrade callback at key [%u, %u), "
                                              "disk %u, block %u, page %u done\n",
                                              CMCNP_KEY_S_PAGE(cmcnp_key),
                                              CMCNP_KEY_E_PAGE(cmcnp_key),
                                              CMCNP_INODE_DISK_NO(cmcnp_inode),
                                              CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                              CMCNP_INODE_PAGE_NO(cmcnp_inode));
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_degrade(CMCNP *cmcnp, const UINT32 scan_max_num, const UINT32 expect_degrade_num, const uint64_t ssd_traffic_read_bps, UINT32 *complete_degrade_num)
{
    CMCNPDEG_NODE   cmcnpdeg_node;
    UINT32          degrade_num;
    UINT32          scan_num;

    if(EC_TRUE == cmcnp_is_read_only(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_degrade: np %u is read-only\n",
                                              CMCNP_ID(cmcnp));
        return (EC_FALSE);
    }

    for(scan_num = 0, degrade_num = 0, cmcnpdeg_node_clone(CMCNP_DEG_LIST(cmcnp), &cmcnpdeg_node);
        scan_num < scan_max_num && degrade_num < expect_degrade_num
     && CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_PREV_POS(&cmcnpdeg_node);
        scan_num ++)
    {
        CMCNP_ITEM      *cmcnp_item;
        uint32_t         node_pos;

        node_pos      = CMCNPDEG_NODE_PREV_POS(&cmcnpdeg_node);
        cmcnp_item    = cmcnp_fetch(cmcnp, node_pos);

        /*cloned and saved for safe reason*/
        cmcnpdeg_node_clone(CMCNP_ITEM_DEG_NODE(cmcnp_item), &cmcnpdeg_node);

        CMCNP_ASSERT(EC_TRUE == cmcnprb_node_is_used(CMCNP_ITEMS_POOL(cmcnp), node_pos));
        CMCNP_ASSERT(CMCNP_ITEM_IS_USED == CMCNP_ITEM_USED_FLAG(cmcnp_item));

        if(CMCNP_ITEM_FILE_IS_REG != CMCNP_ITEM_DIR_FLAG(cmcnp_item))
        {
            continue;
        }

        if(BIT_FALSE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item))
        {
            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            continue;
        }

        if(CMC_DEGRADE_TRAFFIC_048MB < ssd_traffic_read_bps)
        {
            if(BIT_TRUE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item)
                && BIT_FALSE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item))
            {
                cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
                CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item) = BIT_FALSE;
                continue;
            }
        }

        if(EC_FALSE == cmcnp_exec_degrade_callback(cmcnp, CMCNP_ITEM_KEY(cmcnp_item), node_pos))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_degrade: np %u node_pos %d [REG] failed\n",
                            CMCNP_ID(cmcnp), node_pos);
            continue;
        }

        dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_degrade: np %u node_pos %d [REG] done\n",
                        CMCNP_ID(cmcnp), node_pos);

        degrade_num ++;
    }

    if(NULL_PTR != complete_degrade_num)
    {
        (*complete_degrade_num) = degrade_num;
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_degrade_all(CMCNP *cmcnp, UINT32 *complete_degrade_num)
{
    CMCNPDEG_NODE   cmcnpdeg_node;
    UINT32          degrade_num;

    if(EC_TRUE == cmcnp_is_read_only(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_degrade_all: np %u is read-only\n",
                                              CMCNP_ID(cmcnp));
        return (EC_FALSE);
    }

    degrade_num   = 0;

    cmcnpdeg_node_clone(CMCNP_DEG_LIST(cmcnp), &cmcnpdeg_node);

    while(CMCNPDEG_ROOT_POS != CMCNPDEG_NODE_PREV_POS(&cmcnpdeg_node))
    {
        CMCNP_ITEM      *cmcnp_item;
        uint32_t         node_pos;

        node_pos      = CMCNPDEG_NODE_PREV_POS(&cmcnpdeg_node);
        cmcnp_item    = cmcnp_fetch(cmcnp, node_pos);

        /*cloned and saved for safe reason*/
        cmcnpdeg_node_clone(CMCNP_ITEM_DEG_NODE(cmcnp_item), &cmcnpdeg_node);

        CMCNP_ASSERT(EC_TRUE == cmcnprb_node_is_used(CMCNP_ITEMS_POOL(cmcnp), node_pos));
        CMCNP_ASSERT(CMCNP_ITEM_IS_USED == CMCNP_ITEM_USED_FLAG(cmcnp_item));

        if(CMCNP_ITEM_FILE_IS_REG != CMCNP_ITEM_DIR_FLAG(cmcnp_item))
        {
            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            continue;
        }

        if(BIT_FALSE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item))
        {
            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            continue;
        }

        if(EC_FALSE == cmcnp_exec_degrade_callback(cmcnp, CMCNP_ITEM_KEY(cmcnp_item), node_pos))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_degrade_all: np %u node_pos %d [REG] failed\n",
                            CMCNP_ID(cmcnp), node_pos);
            continue;
        }

        dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_degrade_all: np %u node_pos %d [REG] done\n",
                        CMCNP_ID(cmcnp), node_pos);

        degrade_num ++;
    }

    if(NULL_PTR != complete_degrade_num)
    {
        (*complete_degrade_num) = degrade_num;
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_retire_cb_init(CMCNP_RETIRE_CB *cmcnp_retire_cb)
{
    CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb) = NULL_PTR;
    CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_retire_cb_clean(CMCNP_RETIRE_CB *cmcnp_retire_cb)
{
    CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb) = NULL_PTR;
    CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_retire_cb_clone(CMCNP_RETIRE_CB *cmcnp_retire_cb_src, CMCNP_RETIRE_CB *cmcnp_retire_cb_des)
{
    CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb_des) = CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb_src);
    CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb_des)  = CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb_src);

    return (EC_TRUE);
}

EC_BOOL cmcnp_retire_cb_set(CMCNP_RETIRE_CB *cmcnp_retire_cb, CMCNP_RETIRE_CALLBACK func, void *arg)
{
    CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb) = func;
    CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb)  = arg;

    return (EC_TRUE);
}

EC_BOOL cmcnp_init_retire_callback(CMCNP *cmcnp)
{
    CMCNP_RETIRE_CB     *cmcnp_retire_cb;

    cmcnp_retire_cb = CMCNP_RETIRE_CB(cmcnp);

    CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb) = NULL_PTR;
    CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_clean_retire_callback(CMCNP *cmcnp)
{
    CMCNP_RETIRE_CB     *cmcnp_retire_cb;

    cmcnp_retire_cb = CMCNP_RETIRE_CB(cmcnp);

    CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb) = NULL_PTR;
    CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_set_retire_callback(CMCNP *cmcnp, CMCNP_RETIRE_CALLBACK func, void *arg)
{
    CMCNP_RETIRE_CB     *cmcnp_retire_cb;

    cmcnp_retire_cb = CMCNP_RETIRE_CB(cmcnp);

    CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb) = func;
    CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb)  = arg;

    return (EC_TRUE);
}

EC_BOOL cmcnp_exec_retire_callback(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t node_pos)
{
    CMCNP_ITEM          *cmcnp_item;
    CMCNP_FNODE         *cmcnp_fnode;
    CMCNP_INODE         *cmcnp_inode;
    CMCNP_RETIRE_CB     *cmcnp_retire_cb;

    CMCNP_ASSERT(EC_FALSE == cmcnp_is_read_only(cmcnp));

    cmcnp_retire_cb = CMCNP_RETIRE_CB(cmcnp);
    if(NULL_PTR == CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb)
    || NULL_PTR == CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb))
    {
        dbg_log(SEC_0111_CMCNP, 7)(LOGSTDOUT, "warn:cmcnp_exec_retire_callback:"
                                              "callback func %p or callback arg %p is null\n",
                                              CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb),
                                              CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb));
        return (EC_FALSE);
    }

    cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
    if(NULL_PTR == cmcnp_item)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_exec_retire_callback:"
                                              "item %u is null\n",
                                              node_pos);
        return (EC_FALSE);
    }

    if(CMCNP_ITEM_FILE_IS_REG != CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_exec_retire_callback:"
                                              "item %u is dir\n",
                                              node_pos);
        return (EC_FALSE);
    }

    cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    if(BIT_FALSE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item))
    {
        cmcnpdeg_node_move_tail(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
        return (EC_TRUE);
    }

    if(EC_FALSE == CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb)(
                                  CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb),
                                  cmcnp_key,
                                  CMCNP_INODE_DISK_NO(cmcnp_inode),
                                  CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                  CMCNP_INODE_PAGE_NO(cmcnp_inode)))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_exec_retire_callback:"
                                              "retire callback at key [%u, %u), "
                                              "disk %u, block %u, page %u failed\n",
                                              CMCNP_KEY_S_PAGE(cmcnp_key),
                                              CMCNP_KEY_E_PAGE(cmcnp_key),
                                              CMCNP_INODE_DISK_NO(cmcnp_inode),
                                              CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                              CMCNP_INODE_PAGE_NO(cmcnp_inode));
        return (EC_FALSE);
    }

    dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_exec_retire_callback:"
                                          "retire callback at key [%u, %u), "
                                          "disk %u, block %u, page %u done\n",
                                          CMCNP_KEY_S_PAGE(cmcnp_key),
                                          CMCNP_KEY_E_PAGE(cmcnp_key),
                                          CMCNP_INODE_DISK_NO(cmcnp_inode),
                                          CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                                          CMCNP_INODE_PAGE_NO(cmcnp_inode));

    return (EC_TRUE);
}

EC_BOOL cmcnp_retire(CMCNP *cmcnp, const UINT32 scan_max_num, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CMCNPQUE_NODE   cmcnpque_node;
    UINT32          retire_num;
    UINT32          scan_num;

    if(EC_TRUE == cmcnp_is_read_only(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_retire: np %u is read-only\n",
                                              CMCNP_ID(cmcnp));
        return (EC_FALSE);
    }

    for(scan_num = 0, retire_num = 0, cmcnpque_node_clone(CMCNP_QUE_LIST(cmcnp), &cmcnpque_node);
        scan_num < scan_max_num && retire_num < expect_retire_num
     && CMCNPQUE_ROOT_POS != CMCNPQUE_NODE_PREV_POS(&cmcnpque_node);
        scan_num ++)
    {
        CMCNP_ITEM *cmcnp_item;
        uint32_t    node_pos;

        node_pos      = CMCNPQUE_NODE_PREV_POS(&cmcnpque_node);
        cmcnp_item    = cmcnp_fetch(cmcnp, node_pos);

        /*note: CMCNP_ITEM_QUE_NODE would be cleanup when umount item*/
        cmcnpque_node_clone(CMCNP_ITEM_QUE_NODE(cmcnp_item), &cmcnpque_node); /*cloned and saved*/
        CMCNP_ASSERT(EC_TRUE == cmcnprb_node_is_used(CMCNP_ITEMS_POOL(cmcnp), node_pos));
        CMCNP_ASSERT(CMCNP_ITEM_IS_USED == CMCNP_ITEM_USED_FLAG(cmcnp_item));

        if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
        {
            CMCNP_KEY       *cmcnp_key;

            cmcnp_key   = CMCNP_ITEM_KEY(cmcnp_item);

            if(BIT_TRUE == CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item))
            {
                dbg_log(SEC_0111_CMCNP, 7)(LOGSTDOUT, "warn:cmcnp_retire: np %u node_pos %d [REG] not flushed yet\n",
                                CMCNP_ID(cmcnp), node_pos);

                /*speed up degrade*/
                cmcnpdeg_node_move_tail(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
                continue;
            }

            /*retire file*/
            if(EC_FALSE == cmcnp_umount_item(cmcnp, node_pos))
            {
                dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_retire: np %u node_pos %d [REG] failed\n",
                                CMCNP_ID(cmcnp), node_pos);
                return (EC_FALSE);
            }

            dbg_log(SEC_0111_CMCNP, 6)(LOGSTDOUT, "[DEBUG] cmcnp_retire: retire [%ld, %ld) done\n",
                            ((UINT32)CMCNP_KEY_S_PAGE(cmcnp_key)) << CMCPGB_PAGE_SIZE_NBITS,
                            ((UINT32)CMCNP_KEY_E_PAGE(cmcnp_key)) << CMCPGB_PAGE_SIZE_NBITS);

            dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_retire: np %u node_pos %d [REG] done\n",
                            CMCNP_ID(cmcnp), node_pos);
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


EC_BOOL cmcnp_umount_item(CMCNP *cmcnp, const uint32_t node_pos)
{
    CMCNP_ITEM *cmcnp_item;

    cmcnp_item = cmcnp_fetch(cmcnp, node_pos);

    if(NULL_PTR == cmcnp_item)
    {
        return (EC_FALSE);
    }

    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;

        cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);
        CMCNP_DEL_SIZE(cmcnp) += (UINT32)(((UINT32)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);

        if(CMCNPRB_ERR_POS != CMCNP_ITEM_PARENT_POS(cmcnp_item))
        {
            CMCNP_ITEM   *cmcnp_item_parent;
            CMCNP_DNODE  *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CMCNP_ITEM_PARENT_POS(cmcnp_item);
            cmcnp_item_parent  = cmcnp_fetch(cmcnp, parent_node_pos);
            parent_dnode       = CMCNP_ITEM_DNODE(cmcnp_item_parent);

            node_pos_t = cmcnp_dnode_umount_son(cmcnp, parent_dnode, node_pos, CMCNP_ITEM_KEY(cmcnp_item));

            if(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CMCNP_ITEM_PARENT_POS(cmcnp_item) = CMCNPRB_ERR_POS; /*fix*/

                cmcnp_exec_retire_callback(cmcnp, CMCNP_ITEM_KEY(cmcnp_item), node_pos);

                CMCNP_ASSERT(EC_FALSE == cmcnp_is_read_only(cmcnp));

                cmcnp_release_key(cmcnp, CMCNP_ITEM_KEY(cmcnp_item));
                cmcnpque_node_rmv(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);
                cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
                cmcnpdel_node_add_tail(cmcnp, CMCNP_ITEM_DEL_NODE(cmcnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_umount_item: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CMCNP_ID(cmcnp),
                                node_pos, CMCNP_ITEM_PARENT_POS(cmcnp_item), node_pos_t);
                CMCNP_ITEM_PARENT_POS(cmcnp_item) = CMCNPRB_ERR_POS; /*fix*/
            }
        }
        else
        {
            cmcnp_exec_retire_callback(cmcnp, CMCNP_ITEM_KEY(cmcnp_item), node_pos);

            CMCNP_ASSERT(EC_FALSE == cmcnp_is_read_only(cmcnp));

            cmcnp_release_key(cmcnp, CMCNP_ITEM_KEY(cmcnp_item));
            cmcnpque_node_rmv(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);
            cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);
            cmcnpdel_node_add_tail(cmcnp, CMCNP_ITEM_DEL_NODE(cmcnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmcnp_umount(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    uint32_t node_pos;

    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    node_pos = cmcnp_search(cmcnp, cmcnp_key, dflag);

    if(EC_FALSE == cmcnp_umount_item(cmcnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_file_num(CMCNP *cmcnp, uint32_t *file_num)
{
    CMCNP_ITEM  *cmcnp_item;
    CMCNP_DNODE *cmcnp_dnode;

    cmcnp_item = cmcnp_fetch(cmcnp, CMCNPRB_ROOT_POS);
    CMCNP_ASSERT(NULL_PTR != cmcnp_item);
    CMCNP_ASSERT(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    cmcnp_dnode = CMCNP_ITEM_DNODE(cmcnp_item);

    (*file_num) = CMCNP_DNODE_FILE_NUM(cmcnp_dnode);
    return (EC_TRUE);
}

EC_BOOL cmcnp_file_size(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, UINT32 *file_size)
{
    CMCNP_ITEM *cmcnp_item;

    cmcnp_item = cmcnp_get(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cmcnp_item)
    {
        (*file_size) = 0;
        return (EC_FALSE);
    }

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;
        cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);

        (*file_size) = (UINT32)(((UINT32)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);
        return (EC_TRUE);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_file_size: np %u, invalid dflg %x\n", CMCNP_ID(cmcnp), CMCNP_ITEM_DIR_FLAG(cmcnp_item));
    return (EC_FALSE);
}

void cmcnp_file_print(LOG *log, const CMCNP *cmcnp, const uint32_t node_pos)
{
    CMCNP_ITEM *cmcnp_item;

    cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
    if(NULL_PTR == cmcnp_item)
    {
        return;
    }

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;
        CMCNP_KEY   *cmcnp_key;

        cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);
        cmcnp_key   = CMCNP_ITEM_KEY(cmcnp_item);

        cmcnp_key_print(log, cmcnp_key);
        cmcnp_fnode_print(log, cmcnp_fnode);
        return;
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_file_print: np %u, invalid dflg %x\n",
                    CMCNP_ID(cmcnp), CMCNP_ITEM_DIR_FLAG(cmcnp_item));
    return;
}

EC_BOOL cmcnp_create_root_item(CMCNP *cmcnp)
{
    CMCNP_ITEM  *cmcnp_item;
    CMCNP_KEY    cmcnp_key;
    uint32_t     root_pos;
    uint32_t     insert_pos;

    CMCNP_KEY_S_PAGE(&cmcnp_key) = CMCNP_KEY_S_PAGE_ERR;
    CMCNP_KEY_E_PAGE(&cmcnp_key) = CMCNP_KEY_E_PAGE_ERR;

    root_pos = CMCNPRB_ERR_POS;

    if(EC_FALSE == cmcnprb_tree_insert_data(CMCNP_ITEMS_POOL(cmcnp), &root_pos, &cmcnp_key, &insert_pos))
    {
        dbg_log(SEC_0111_CMCNP, 1)(LOGSTDOUT, "warn:cmcnp_create_root_item: insert create item failed\n");
        return (EC_FALSE);
    }

    if(0 != insert_pos)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create_root_item: insert root item at pos %u is not zero!\n", insert_pos);
        return (EC_FALSE);
    }

    if(0 != root_pos)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create_root_item: root_pos %u is not zero!\n", root_pos);
        return (EC_FALSE);
    }

    cmcnp_item = cmcnp_fetch(cmcnp, insert_pos);

    CMCNP_ITEM_DIR_FLAG(cmcnp_item)       = CMCNP_ITEM_FILE_IS_DIR;
    CMCNP_ITEM_USED_FLAG(cmcnp_item)      = CMCNP_ITEM_IS_USED;
    CMCNP_ITEM_DEG_TIMES(cmcnp_item)      = 0;
    CMCNP_ITEM_PARENT_POS(cmcnp_item)     = CMCNPRB_ERR_POS;

    CMCNP_ITEM_S_PAGE(cmcnp_item)         = CMCNP_KEY_S_PAGE_ERR;
    CMCNP_ITEM_E_PAGE(cmcnp_item)         = CMCNP_KEY_E_PAGE_ERR;

    cmcnp_dnode_init(CMCNP_ITEM_DNODE(cmcnp_item));

    return (EC_TRUE);
}

/*------------------------------------------------ recycle -----------------------------------------*/
/*recycle dn only!*/
EC_BOOL cmcnp_recycle_item_file(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn)
{
    CMCNP_FNODE *cmcnp_fnode;

    cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);
    if(EC_FALSE == CMCNP_RECYCLE_DN_FUNC(cmcnp_recycle_dn)(CMCNP_RECYCLE_DN_ARG1(cmcnp_recycle_dn), cmcnp_fnode))
    {
        CMCNP_INODE *cmcnp_inode;

        cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_recycle_item_file: recycle dn (disk %u, block %u, page %u, page num %u) failed\n",
                            CMCNP_INODE_DISK_NO(cmcnp_inode),
                            CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                            CMCNP_INODE_PAGE_NO(cmcnp_inode),
                            CMCNP_FNODE_PAGENUM(cmcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR != cmcnp_recycle_np)
    {
        CMCNP_RECYCLE_NP_FUNC(cmcnp_recycle_np)(CMCNP_RECYCLE_NP_ARG1(cmcnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_recycle_dnode_item(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn)
{
    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        cmcnp_recycle_item_file(cmcnp, cmcnp_item, node_pos, cmcnp_recycle_np, cmcnp_recycle_dn);
        CMCNP_DNODE_FILE_NUM(cmcnp_dnode) --;

        /*this file is under a deleted directory in deep. it may be still in QUE list.*/
        cmcnpque_node_rmv(cmcnp, CMCNP_ITEM_QUE_NODE(cmcnp_item), node_pos);

        cmcnpdeg_node_rmv(cmcnp, CMCNP_ITEM_DEG_NODE(cmcnp_item), node_pos);

        cmcnp_item_clean(cmcnp_item);
        return (EC_TRUE);
    }

    if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        cmcnp_recycle_item_dir(cmcnp, cmcnp_item, node_pos, cmcnp_recycle_np, cmcnp_recycle_dn);/*recursively*/
        CMCNP_DNODE_FILE_NUM(cmcnp_dnode) --;

        cmcnp_item_clean(cmcnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_recycle_dnode_item: invalid dflag 0x%x\n", CMCNP_ITEM_DIR_FLAG(cmcnp_item));
    return (EC_FALSE);
}

EC_BOOL cmcnp_recycle_dnode(CMCNP *cmcnp, CMCNP_DNODE *cmcnp_dnode, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn)
{
    CMCNPRB_POOL *pool;
    CMCNPRB_NODE *node;
    CMCNP_ITEM   *item;

    pool = CMCNP_ITEMS_POOL(cmcnp);

    node  = CMCNPRB_POOL_NODE(pool, node_pos);
    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_LEFT_POS(node))
    {
        cmcnp_recycle_dnode(cmcnp, cmcnp_dnode, CMCNPRB_NODE_LEFT_POS(node), cmcnp_recycle_np, cmcnp_recycle_dn);
    }

    if(CMCNPRB_ERR_POS != CMCNPRB_NODE_RIGHT_POS(node))
    {
        cmcnp_recycle_dnode(cmcnp, cmcnp_dnode, CMCNPRB_NODE_RIGHT_POS(node), cmcnp_recycle_np, cmcnp_recycle_dn);
    }

    item = CMCNP_RB_NODE_ITEM(node);
    cmcnp_recycle_dnode_item(cmcnp, cmcnp_dnode, item, node_pos, cmcnp_recycle_np, cmcnp_recycle_dn);

    /*cmcnprb recycle the rbnode, do not use cmcnprb_tree_delete which will change the tree structer*/
    cmcnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

EC_BOOL cmcnp_recycle_item_dir(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn)
{
    CMCNP_DNODE *cmcnp_dnode;
    uint32_t root_pos;

    cmcnp_dnode = CMCNP_ITEM_DNODE(cmcnp_item);

    root_pos = CMCNP_DNODE_ROOT_POS(cmcnp_dnode);
    if(CMCNPRB_ERR_POS != root_pos)
    {
        cmcnp_recycle_dnode(cmcnp, cmcnp_dnode, root_pos, cmcnp_recycle_np, cmcnp_recycle_dn);
        CMCNP_DNODE_ROOT_POS(cmcnp_dnode) = CMCNPRB_ERR_POS;
    }

    if(NULL_PTR != cmcnp_recycle_np)
    {
        CMCNP_RECYCLE_NP_FUNC(cmcnp_recycle_np)(CMCNP_RECYCLE_NP_ARG1(cmcnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

/*note: this interface is for that cmcnp_item had umounted from parent, not need to update parent info*/
EC_BOOL cmcnp_recycle_item(CMCNP *cmcnp, CMCNP_ITEM *cmcnp_item, const uint32_t node_pos, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn)
{
    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;

        cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);

        if(EC_FALSE == cmcnp_recycle_item_file(cmcnp, cmcnp_item, node_pos, cmcnp_recycle_np, cmcnp_recycle_dn))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_recycle_item: recycle regular file failed where cmcnp_item is\n");
            cmcnp_item_and_key_print(LOGSTDOUT, cmcnp_item);

            /*should never reach here*/
            cmcnp_item_clean(cmcnp_item);

            return (EC_FALSE);
        }

        CMCNP_RECYCLE_SIZE(cmcnp) += (UINT32)(((UINT32)CMCNP_FNODE_PAGENUM(cmcnp_fnode)) << CMCPGB_PAGE_SIZE_NBITS);

        /*note: this file is in DEL list so that it must not be in QUE list*/

        cmcnp_item_clean(cmcnp_item);
        return (EC_TRUE);
    }

    if(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        cmcnp_recycle_item_dir(cmcnp, cmcnp_item, node_pos, cmcnp_recycle_np, cmcnp_recycle_dn);/*recursively*/

        cmcnp_item_clean(cmcnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_recycle_item: invalid dflag 0x%x\n", CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    /*should never reach here*/
    cmcnp_item_clean(cmcnp_item);

    return (EC_FALSE);
}

EC_BOOL cmcnp_recycle(CMCNP *cmcnp, const UINT32 max_num, CMCNP_RECYCLE_NP *cmcnp_recycle_np, CMCNP_RECYCLE_DN *cmcnp_recycle_dn, UINT32 *complete_num)
{
    CMCNPDEL_NODE  *cmcnpdel_node_head;
    //CMCNP_HEADER   *cmcnp_header;

    uint32_t         left_num;

    if(EC_TRUE == cmcnp_is_read_only(cmcnp))
    {
        dbg_log(SEC_0111_CMCNP, 3)(LOGSTDOUT, "error:cmcnp_recycle: np %u is read-only\n",
                                              CMCNP_ID(cmcnp));
        return (EC_FALSE);
    }

    cmcnpdel_node_head = CMCNP_DEL_LIST(cmcnp);

    //cmcnp_header = CMCNP_HDR(cmcnp);
    left_num = UINT32_TO_INT32(max_num);

    if(0 == left_num)
    {
        /*items never beyond the max value of uint32_t*/
        left_num = ((uint32_t)~0);
    }

    (*complete_num) = 0;
    while((0 < left_num --) && (EC_FALSE == cmcnp_del_list_is_empty(cmcnp)))
    {
        CMCNP_ITEM   *cmcnp_item;
        uint32_t       node_pos;

        node_pos = CMCNPDEL_NODE_NEXT_POS(cmcnpdel_node_head);

        cmcnp_item = cmcnp_fetch(cmcnp, node_pos);

        CMCNP_ASSERT(CMCNPRB_ERR_POS == CMCNP_ITEM_PARENT_POS(cmcnp_item));

        if(EC_FALSE == cmcnp_recycle_item(cmcnp, cmcnp_item, node_pos, cmcnp_recycle_np, cmcnp_recycle_dn))
        {
            dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_recycle: recycle item %u # failed\n", node_pos);

            /*should never reach here*/
            cmcnpdel_node_rmv(cmcnp, CMCNP_ITEM_DEL_NODE(cmcnp_item), node_pos);

            cmcnprb_node_free(CMCNP_ITEMS_POOL(cmcnp), node_pos);/*recycle rb node(item node)*/
            return (EC_FALSE);
        }

        cmcnpdel_node_rmv(cmcnp, CMCNP_ITEM_DEL_NODE(cmcnp_item), node_pos);

        cmcnprb_node_free(CMCNP_ITEMS_POOL(cmcnp), node_pos);/*recycle rb node(item node)*/

        (*complete_num) ++;

        dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_recycle: recycle item %u # done\n", node_pos);
    }

    return (EC_TRUE);
}


/*-------------------------------------------- NP in memory --------------------------------------------*/
CMCNP *cmcnp_create(const uint32_t np_id, const uint8_t np_model, const UINT32 key_max_num)
{
    CMCNP           *cmcnp;
    CMCNP_BITMAP    *cmcnp_bitmap;
    CMCNP_HEADER    *cmcnp_header;
    int              fd;
    UINT32           fsize;

    fd = ERR_FD;

    if(EC_FALSE == cmcnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    cmcnp_header = __cmcnp_header_new(np_id, fsize, fd, np_model);
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: new cmcnp header failed\n");
        return (NULL_PTR);
    }

    cmcnp_bitmap = cmcnp_bitmap_new(key_max_num);
    if(NULL_PTR == cmcnp_bitmap)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: new cmcnp bitmap failed\n");
        __cmcnp_header_free(cmcnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }
    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_create: create cmcnp bitmap %ld nbits done\n", key_max_num);

    cmcnp = cmcnp_new();
    if(NULL_PTR == cmcnp)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: new cmcnp %u failed\n", np_id);
        cmcnp_bitmap_free(cmcnp_bitmap);
        __cmcnp_header_free(cmcnp_header, np_id, fsize, fd);

        return (NULL_PTR);
    }
    CMCNP_BITMAP(cmcnp)   = cmcnp_bitmap;
    CMCNP_HDR(cmcnp)      = cmcnp_header;

    /*shortcut*/
    CMCNP_QUE_LIST(cmcnp) = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, CMCNPQUE_ROOT_POS));
    CMCNP_DEL_LIST(cmcnp) = CMCNP_ITEM_DEL_NODE(cmcnp_fetch(cmcnp, CMCNPDEL_ROOT_POS));
    CMCNP_DEG_LIST(cmcnp) = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, CMCNPDEG_ROOT_POS));

    CMCNP_RDONLY_FLAG(cmcnp)    = BIT_FALSE;
    CMCNP_FD(cmcnp)             = fd;
    CMCNP_FSIZE(cmcnp)          = fsize;
    CMCNP_FNAME(cmcnp)          = NULL_PTR;

    CMCNP_ASSERT(np_id == CMCNP_HEADER_NP_ID(cmcnp_header));

    /*create root item*/
    cmcnp_create_root_item(cmcnp);

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_create: create np %u done\n", np_id);

    return (cmcnp);
}

CMCNP *cmcnp_create_shm(CMMAP_NODE *cmmap_node, const uint32_t np_id, const uint8_t np_model, const UINT32 key_max_num)
{
    CMCNP           *cmcnp;
    CMCNP_BITMAP    *cmcnp_bitmap;
    CMCNP_HEADER    *cmcnp_header;
    UINT32           fsize;

    if(EC_FALSE == cmcnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create_shm: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    cmcnp_header = __cmcnp_header_create(cmmap_node, np_id, np_model, fsize);
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create_shm: create header of np %u failed\n", np_id);
        return (NULL_PTR);
    }

    cmcnp_bitmap = cmcnp_bitmap_create(cmmap_node, np_id, key_max_num);
    if(NULL_PTR == cmcnp_bitmap)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create_shm: create bitmap of np %u failed\n", np_id);

        __cmcnp_header_close(cmcnp_header, np_id, fsize);
        return (NULL_PTR);
    }

    cmcnp = cmcnp_new();
    if(NULL_PTR == cmcnp)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create_shm: new cmcnp %u failed\n", np_id);

        cmcnp_bitmap_close(cmcnp_bitmap);
        __cmcnp_header_close(cmcnp_header, np_id, fsize);

        return (NULL_PTR);
    }
    CMCNP_BITMAP(cmcnp)   = cmcnp_bitmap;
    CMCNP_HDR(cmcnp)      = cmcnp_header;

    CMCNP_RDONLY_FLAG(cmcnp)    = BIT_FALSE;
    CMCNP_FD(cmcnp)             = ERR_FD;
    CMCNP_FSIZE(cmcnp)          = fsize;
    CMCNP_FNAME(cmcnp)          = NULL_PTR;

    CMCNP_ASSERT(np_id == CMCNP_HEADER_NP_ID(cmcnp_header));

    /*shortcut*/
    CMCNP_QUE_LIST(cmcnp) = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, CMCNPQUE_ROOT_POS));
    CMCNP_DEL_LIST(cmcnp) = CMCNP_ITEM_DEL_NODE(cmcnp_fetch(cmcnp, CMCNPDEL_ROOT_POS));
    CMCNP_DEG_LIST(cmcnp) = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, CMCNPDEG_ROOT_POS));

    ASSERT(0 == CMCNP_HEADER_ITEMS_USED_NUM(cmcnp_header));

    /*create root item*/
    cmcnp_create_root_item(cmcnp);

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_create_shm: create np %u done\n", np_id);

    return (cmcnp);
}

CMCNP *cmcnp_open_shm(CMMAP_NODE *cmmap_node, const uint32_t np_id, const uint8_t np_model, const UINT32 key_max_num)
{
    CMCNP           *cmcnp;
    CMCNP_BITMAP    *cmcnp_bitmap;
    CMCNP_HEADER    *cmcnp_header;
    UINT32           fsize;

    if(EC_FALSE == cmcnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_open_shm: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    cmcnp_header = __cmcnp_header_open(cmmap_node, np_id, np_model, fsize);
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_open_shm: open header of np %u failed\n", np_id);
        return (NULL_PTR);
    }

    cmcnp_bitmap = cmcnp_bitmap_open(cmmap_node, np_id, key_max_num);
    if(NULL_PTR == cmcnp_bitmap)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_open_shm: open bitmap of np %u failed\n", np_id);
        return (NULL_PTR);
    }

    cmcnp = cmcnp_new();
    if(NULL_PTR == cmcnp)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_open_shm: new cmcnp %u failed\n", np_id);

        cmcnp_bitmap_close(cmcnp_bitmap);
        __cmcnp_header_close(cmcnp_header, np_id, fsize);

        return (NULL_PTR);
    }
    CMCNP_BITMAP(cmcnp)   = cmcnp_bitmap;
    CMCNP_HDR(cmcnp)      = cmcnp_header;

    CMCNP_RDONLY_FLAG(cmcnp)    = BIT_FALSE;
    CMCNP_FD(cmcnp)             = ERR_FD;
    CMCNP_FSIZE(cmcnp)          = fsize;
    CMCNP_FNAME(cmcnp)          = NULL_PTR;

    CMCNP_ASSERT(np_id == CMCNP_HEADER_NP_ID(cmcnp_header));

    /*shortcut*/
    CMCNP_QUE_LIST(cmcnp) = CMCNP_ITEM_QUE_NODE(cmcnp_fetch(cmcnp, CMCNPQUE_ROOT_POS));
    CMCNP_DEL_LIST(cmcnp) = CMCNP_ITEM_DEL_NODE(cmcnp_fetch(cmcnp, CMCNPDEL_ROOT_POS));
    CMCNP_DEG_LIST(cmcnp) = CMCNP_ITEM_DEG_NODE(cmcnp_fetch(cmcnp, CMCNPDEG_ROOT_POS));

    if(do_log(SEC_0111_CMCNP, 0))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_open_shm: np %u is\n", np_id);
        cmcnp_print(LOGSTDOUT, cmcnp);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "[DEBUG] cmcnp_open_shm: open np %u done\n", np_id);

    return (cmcnp);
}

EC_BOOL cmcnp_clean(CMCNP *cmcnp)
{
    if(NULL_PTR != CMCNP_BITMAP(cmcnp))
    {
        cmcnp_bitmap_free(CMCNP_BITMAP(cmcnp));
        CMCNP_BITMAP(cmcnp) = NULL_PTR;
    }

    if(NULL_PTR != CMCNP_HDR(cmcnp))
    {
        __cmcnp_header_free(CMCNP_HDR(cmcnp), CMCNP_ID(cmcnp), CMCNP_FSIZE(cmcnp), CMCNP_FD(cmcnp));
        CMCNP_HDR(cmcnp) = NULL_PTR;
    }

    CMCNP_ASSERT(ERR_FD == CMCNP_FD(cmcnp));

    CMCNP_FSIZE(cmcnp) = 0;

    CMCNP_ASSERT(NULL_PTR == CMCNP_FNAME(cmcnp));

    CMCNP_DEL_SIZE(cmcnp)     = 0;
    CMCNP_RECYCLE_SIZE(cmcnp) = 0;

    CMCNP_QUE_LIST(cmcnp) = NULL_PTR;
    CMCNP_DEL_LIST(cmcnp) = NULL_PTR;
    CMCNP_DEG_LIST(cmcnp) = NULL_PTR;

    cmcnp_retire_cb_clean(CMCNP_RETIRE_CB(cmcnp));
    cmcnp_degrade_cb_clean(CMCNP_DEGRADE_CB(cmcnp));

    return (EC_TRUE);
}

EC_BOOL cmcnp_free(CMCNP *cmcnp)
{
    if(NULL_PTR != cmcnp)
    {
        cmcnp_clean(cmcnp);
        free_static_mem(MM_CMCNP, cmcnp, LOC_CMCNP_0024);
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_close(CMCNP *cmcnp)
{
    if(NULL_PTR != cmcnp)
    {
        if(NULL_PTR != CMCNP_BITMAP(cmcnp))
        {
            cmcnp_bitmap_close(CMCNP_BITMAP(cmcnp));
            CMCNP_BITMAP(cmcnp) = NULL_PTR;
        }

        if(NULL_PTR != CMCNP_HDR(cmcnp))
        {
            __cmcnp_header_close(CMCNP_HDR(cmcnp), CMCNP_ID(cmcnp), CMCNP_FSIZE(cmcnp));
            CMCNP_HDR(cmcnp) = NULL_PTR;
        }

        return cmcnp_free(cmcnp);
    }
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


