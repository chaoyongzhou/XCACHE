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

#include "cmcpgrb.h"
#include "cmcpgb.h"
#include "cmcnprb.h"
#include "cmcnplru.h"
#include "cmcnpdel.h"
#include "cmcnp.h"

static CMCNP_CFG g_cmcnp_cfg_tbl[] = {
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
    uint32_t pos;

    CMCNP_FNODE_FILESZ(cmcnp_fnode) = 0;
    CMCNP_FNODE_REPNUM(cmcnp_fnode) = 0;
    CMCNP_FNODE_HASH(cmcnp_fnode)   = 0;

    for(pos = 0; pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_init(CMCNP_FNODE_INODE(cmcnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_clean(CMCNP_FNODE *cmcnp_fnode)
{
    uint32_t pos;

    CMCNP_FNODE_FILESZ(cmcnp_fnode) = 0;
    CMCNP_FNODE_REPNUM(cmcnp_fnode) = 0;
    CMCNP_FNODE_HASH(cmcnp_fnode)   = 0;

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
    uint32_t pos;

    CMCNP_FNODE_FILESZ(cmcnp_fnode_des) = CMCNP_FNODE_FILESZ(cmcnp_fnode_src);
    CMCNP_FNODE_REPNUM(cmcnp_fnode_des) = CMCNP_FNODE_REPNUM(cmcnp_fnode_src);
    CMCNP_FNODE_HASH(cmcnp_fnode_des)   = CMCNP_FNODE_HASH(cmcnp_fnode_src);

    for(pos = 0; pos < CMCNP_FNODE_REPNUM(cmcnp_fnode_src) && pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_clone(CMCNP_FNODE_INODE(cmcnp_fnode_src, pos), CMCNP_FNODE_INODE(cmcnp_fnode_des, pos));
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_check_inode_exist(const CMCNP_INODE *inode, const CMCNP_FNODE *cmcnp_fnode)
{
    uint32_t replica_pos;

    for(replica_pos = 0; replica_pos < CMCNP_FNODE_REPNUM(cmcnp_fnode); replica_pos ++)
    {
        if( CMCNP_INODE_DISK_NO(inode)    == CMCNP_FNODE_INODE_DISK_NO(cmcnp_fnode, replica_pos)
         && CMCNP_INODE_BLOCK_NO(inode)   == CMCNP_FNODE_INODE_BLOCK_NO(cmcnp_fnode, replica_pos)
         && CMCNP_INODE_PAGE_NO(inode)    == CMCNP_FNODE_INODE_PAGE_NO(cmcnp_fnode, replica_pos)
        )
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL cmcnp_fnode_cmp(const CMCNP_FNODE *cmcnp_fnode_1st, const CMCNP_FNODE *cmcnp_fnode_2nd)
{
    uint32_t replica_pos;

    if(NULL_PTR == cmcnp_fnode_1st && NULL_PTR == cmcnp_fnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cmcnp_fnode_1st || NULL_PTR == cmcnp_fnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CMCNP_FNODE_REPNUM(cmcnp_fnode_1st) != CMCNP_FNODE_REPNUM(cmcnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CMCNP_FNODE_FILESZ(cmcnp_fnode_1st) != CMCNP_FNODE_FILESZ(cmcnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CMCNP_FNODE_HASH(cmcnp_fnode_1st) != CMCNP_FNODE_HASH(cmcnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    for(replica_pos = 0; replica_pos < CMCNP_FNODE_REPNUM(cmcnp_fnode_1st); replica_pos ++)
    {
        if(EC_FALSE == cmcnp_fnode_check_inode_exist(CMCNP_FNODE_INODE(cmcnp_fnode_1st, replica_pos), cmcnp_fnode_2nd))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cmcnp_fnode_import(const CMCNP_FNODE *cmcnp_fnode_src, CMCNP_FNODE *cmcnp_fnode_des)
{
    uint32_t src_pos;
    uint32_t des_pos;

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

    CMCNP_FNODE_FILESZ(cmcnp_fnode_des) = CMCNP_FNODE_FILESZ(cmcnp_fnode_src);
    CMCNP_FNODE_REPNUM(cmcnp_fnode_des) = des_pos;
    CMCNP_FNODE_HASH(cmcnp_fnode_des)   = CMCNP_FNODE_HASH(cmcnp_fnode_src);
    return (EC_TRUE);
}

void cmcnp_fnode_print(LOG *log, const CMCNP_FNODE *cmcnp_fnode)
{
    uint32_t pos;

    sys_log(log, "cmcnp_fnode %p: file size %u, replica num %u, hash %x\n",
                    cmcnp_fnode,
                    CMCNP_FNODE_FILESZ(cmcnp_fnode),
                    CMCNP_FNODE_REPNUM(cmcnp_fnode),
                    CMCNP_FNODE_HASH(cmcnp_fnode)
                    );

    for(pos = 0; pos < CMCNP_FNODE_REPNUM(cmcnp_fnode) && pos < CMCNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cmcnp_inode_print(log, CMCNP_FNODE_INODE(cmcnp_fnode, pos));
    }
    return;
}

void cmcnp_fnode_log(LOG *log, const CMCNP_FNODE *cmcnp_fnode)
{
    uint32_t pos;

    sys_print_no_lock(log, "size %u, replica %u, hash %x",
                    CMCNP_FNODE_FILESZ(cmcnp_fnode),
                    CMCNP_FNODE_REPNUM(cmcnp_fnode),
                    CMCNP_FNODE_HASH(cmcnp_fnode)
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
    CMCNP_ITEM_PARENT_POS(cmcnp_item)       = CMCNPRB_ERR_POS;/*fix*/

    cmcnp_fnode_init(CMCNP_ITEM_FNODE(cmcnp_item));

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cmcnp_item_clean(CMCNP_ITEM *cmcnp_item)
{
    CMCNP_ITEM_DIR_FLAG(cmcnp_item)         = CMCNP_ITEM_FILE_IS_ERR;
    CMCNP_ITEM_USED_FLAG(cmcnp_item)        = CMCNP_ITEM_IS_NOT_USED;
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

    CMCNP_ITEM_USED_FLAG(cmcnp_item_des)   =  CMCNP_ITEM_USED_FLAG(cmcnp_item_src);
    CMCNP_ITEM_DIR_FLAG(cmcnp_item_des)    =  CMCNP_ITEM_DIR_FLAG(cmcnp_item_src);
    CMCNP_ITEM_PARENT_POS(cmcnp_item_des)  = CMCNP_ITEM_PARENT_POS(cmcnp_item_src);

    cmcnplru_node_clone(CMCNP_ITEM_LRU_NODE(cmcnp_item_src), CMCNP_ITEM_LRU_NODE(cmcnp_item_des));
    cmcnpdel_node_clone(CMCNP_ITEM_DEL_NODE(cmcnp_item_src), CMCNP_ITEM_DEL_NODE(cmcnp_item_des));

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
    uint32_t pos;

    sys_print(log, "cmcnp_item %p: flag 0x%x [%s], stat %u "
                   "parent %u, lru node (%u, %u), del node (%u, %u)\n",
                    cmcnp_item,
                    CMCNP_ITEM_DIR_FLAG(cmcnp_item), __cmcnp_item_dir_flag_str(CMCNP_ITEM_DIR_FLAG(cmcnp_item)),
                    CMCNP_ITEM_USED_FLAG(cmcnp_item),
                    CMCNP_ITEM_PARENT_POS(cmcnp_item),
                    CMCNPLRU_NODE_PREV_POS(CMCNP_ITEM_LRU_NODE(cmcnp_item)),
                    CMCNPLRU_NODE_NEXT_POS(CMCNP_ITEM_LRU_NODE(cmcnp_item)),
                    CMCNPDEL_NODE_PREV_POS(CMCNP_ITEM_DEL_NODE(cmcnp_item)),
                    CMCNPDEL_NODE_NEXT_POS(CMCNP_ITEM_DEL_NODE(cmcnp_item))
                    );

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;

        cmcnp_fnode = (CMCNP_FNODE *)CMCNP_ITEM_FNODE(cmcnp_item);
        sys_log(log, "file size %u, replica num %u, hash %x\n",
                        CMCNP_FNODE_FILESZ(cmcnp_fnode),
                        CMCNP_FNODE_REPNUM(cmcnp_fnode),
                        CMCNP_FNODE_HASH(cmcnp_fnode)
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
    uint32_t pos;

    sys_print(log, "cmcnp_item %p: flag 0x%x [%s], stat %u\n",
                    cmcnp_item,
                    CMCNP_ITEM_DIR_FLAG(cmcnp_item), __cmcnp_item_dir_flag_str(CMCNP_ITEM_DIR_FLAG(cmcnp_item)),
                    CMCNP_ITEM_USED_FLAG(cmcnp_item)
                    );

    sys_log(log, "key: [%u, %u)\n",
                 CMCNP_ITEM_S_PAGE(cmcnp_item),
                 CMCNP_ITEM_E_PAGE(cmcnp_item));

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;

        cmcnp_fnode = (CMCNP_FNODE *)CMCNP_ITEM_FNODE(cmcnp_item);
        sys_log(log, "file size %u, replica num %u, hash %x\n",
                        CMCNP_FNODE_FILESZ(cmcnp_fnode),
                        CMCNP_FNODE_REPNUM(cmcnp_fnode),
                        CMCNP_FNODE_HASH(cmcnp_fnode)
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

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_load(const uint32_t np_id, const UINT32 fsize, int fd)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(fsize, LOC_CMCNP_0010);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_load: malloc %ld bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, buff))
    {
        safe_free(buff, LOC_CMCNP_0011);
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_load: load %ld bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    return ((CMCNP_HEADER *)buff);
}

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_dup(CMCNP_HEADER *src_cmcnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    CMCNP_HEADER *des_cmcnp_header;

    des_cmcnp_header = (CMCNP_HEADER *)safe_malloc(fsize, LOC_CMCNP_0012);
    if(NULL_PTR == des_cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_dup: new header with %ld bytes for np %u fd %d failed\n",
                           fsize, des_np_id, fd);
        return (NULL_PTR);
    }

    BCOPY(src_cmcnp_header, des_cmcnp_header, fsize);

    CMCNP_HEADER_NP_ID(des_cmcnp_header)  = des_np_id;
    return (des_cmcnp_header);
}

STATIC_CAST static CMCNP_HEADER *__cmcnp_header_new(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model)
{
    CMCNP_HEADER *cmcnp_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    cmcnp_header = (CMCNP_HEADER *)safe_malloc(fsize, LOC_CMCNP_0013);
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:__cmcnp_header_new: new header with %ld bytes for np %u fd %d failed\n",
                           fsize, np_id, fd);
        return (NULL_PTR);
    }

    CMCNP_HEADER_NP_ID(cmcnp_header)  = np_id;
    CMCNP_HEADER_MODEL(cmcnp_header)  = np_model;

    cmcnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CMCNP_ITEM);

    /*init RB Nodes*/
    cmcnprb_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init LRU nodes*/
    cmcnplru_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cmcnpdel_pool_init(CMCNP_HEADER_ITEMS_POOL(cmcnp_header), node_max_num, node_sizeof);

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

        safe_free(cmcnp_header, LOC_CMCNP_0014);
    }

    /*cmcnp_header cannot be accessed again*/
    return (NULL_PTR);
}

EC_BOOL cmcnp_header_init(CMCNP_HEADER *cmcnp_header, const uint32_t np_id, const uint8_t model)
{
    CMCNP_HEADER_NP_ID(cmcnp_header)         = np_id;
    CMCNP_HEADER_MODEL(cmcnp_header)         = model;

    /*do nothing on lru list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CMCNPRB_POOL pool*/

    return (EC_TRUE);
}

EC_BOOL cmcnp_header_clean(CMCNP_HEADER *cmcnp_header)
{
    CMCNP_HEADER_NP_ID(cmcnp_header)              = CMCNP_ERR_ID;
    CMCNP_HEADER_MODEL(cmcnp_header)              = CMCNP_ERR_MODEL;

    /*do nothing on lru list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CMCNPRB_POOL pool*/

    return (EC_TRUE);
}

CMCNP *cmcnp_new()
{
    CMCNP *cmcnp;

    alloc_static_mem(MM_CMCNP, &cmcnp, LOC_CMCNP_0015);
    if(NULL_PTR != cmcnp)
    {
        cmcnp_init(cmcnp);
    }
    return (cmcnp);
}

EC_BOOL cmcnp_init(CMCNP *cmcnp)
{
    CMCNP_FD(cmcnp)              = ERR_FD;
    CMCNP_FSIZE(cmcnp)           = 0;
    CMCNP_FNAME(cmcnp)           = NULL_PTR;
    CMCNP_DEL_SIZE(cmcnp)        = 0;
    CMCNP_RECYCLE_SIZE(cmcnp)    = 0;
    CMCNP_LRU_LIST(cmcnp)        = NULL_PTR;
    CMCNP_DEL_LIST(cmcnp)        = NULL_PTR;
    CMCNP_HDR(cmcnp)             = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_is_full(const CMCNP *cmcnp)
{
    CMCNPRB_POOL *pool;

    pool = CMCNP_ITEMS_POOL(cmcnp);
    return cmcnprb_pool_is_full(pool);
}

EC_BOOL cmcnp_lru_list_is_empty(const CMCNP *cmcnp)
{
    return cmcnplru_is_empty(CMCNP_LRU_LIST(cmcnp));
}

EC_BOOL cmcnp_del_list_is_empty(const CMCNP *cmcnp)
{
    return cmcnpdel_is_empty(CMCNP_DEL_LIST(cmcnp));
}

void cmcnp_header_print(LOG *log, const CMCNP *cmcnp)
{
    const CMCNP_HEADER *cmcnp_header;

    cmcnp_header = CMCNP_HDR(cmcnp);

    sys_log(log, "np %u, model %u, item max num %u, item used num %u\n",
                CMCNP_HEADER_NP_ID(cmcnp_header),
                CMCNP_HEADER_MODEL(cmcnp_header),
                CMCNP_HEADER_ITEMS_MAX_NUM(cmcnp_header),
                CMCNP_HEADER_ITEMS_USED_NUM(cmcnp_header)
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

void cmcnp_print_lru_list(LOG *log, const CMCNP *cmcnp)
{
    sys_log(log, "cmcnp_print_lru_list: cmcnp %p: lru list: \n", cmcnp);
    cmcnplru_list_print(log, cmcnp);
    return;
}

void cmcnp_print_del_list(LOG *log, const CMCNP *cmcnp)
{
    sys_log(log, "cmcnp_print_del_list: cmcnp %p: del list: \n", cmcnp);
    cmcnpdel_list_print(log, cmcnp);
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
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_dnode_insert: cmcnp is full\n");
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

    ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cmcnp_item = cmcnp_fetch(cmcnp, CMCNPRB_ROOT_POS);
    ASSERT(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    node_pos = cmcnp_dnode_search(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item), cmcnp_key);

    return (node_pos);
}

uint32_t cmcnp_find_intersected(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    CMCNP_ITEM  *cmcnp_item;
    uint32_t     node_pos;

    ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cmcnp_item = cmcnp_fetch(cmcnp, CMCNPRB_ROOT_POS);
    ASSERT(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    node_pos = cmcnp_dnode_find_intersected(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item), cmcnp_key);

    return (node_pos);
}

uint32_t cmcnp_find_closest(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    CMCNP_ITEM  *cmcnp_item;
    uint32_t     node_pos;

    ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    /*root item*/
    cmcnp_item = cmcnp_fetch(cmcnp, CMCNPRB_ROOT_POS);
    ASSERT(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    node_pos = cmcnp_dnode_find_closest(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item), cmcnp_key);

    return (node_pos);
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

    ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

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
    uint32_t replica;

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

EC_BOOL cmcnp_update_no_lock(CMCNP *cmcnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t offset;
    CMCNP_ITEM *cmcnp_item;

    offset = 0;/*the first item is root directory*/
    cmcnp_item = cmcnp_fetch(cmcnp, offset);
    return cmcnp_item_update(cmcnp, cmcnp_item,
                              src_disk_no, src_block_no, src_page_no,
                              des_disk_no, des_block_no, des_page_no);    /*recursively*/
}

CMCNP_ITEM *cmcnp_set(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    uint32_t     node_pos;
    CMCNP_ITEM  *cmcnp_item;

    node_pos = cmcnp_insert(cmcnp, cmcnp_key, dflag);
    cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
    if(NULL_PTR != cmcnp_item)
    {
        /*ensure only item of regular file enter LRU list*/
        if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
        {
            cmcnplru_node_add_head(cmcnp, CMCNP_ITEM_LRU_NODE(cmcnp_item), node_pos);
        }
        return (cmcnp_item);
    }
    return (NULL_PTR);
}

CMCNP_ITEM *cmcnp_get(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

    return cmcnp_fetch(cmcnp, cmcnp_search(cmcnp, cmcnp_key, dflag));
}

CMCNP_FNODE *cmcnp_reserve(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    CMCNP_ITEM *cmcnp_item;

    cmcnp_item = cmcnp_set(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cmcnp_item)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_reserve: set to np failed\n");
        return (NULL_PTR);
    }

    ASSERT(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    /*not import yet*/
    return CMCNP_ITEM_FNODE(cmcnp_item);
}

EC_BOOL cmcnp_release(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key)
{
    if(EC_FALSE == cmcnp_delete(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_release: delete from np failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
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

        cmcnplru_node_move_head(cmcnp, CMCNP_ITEM_LRU_NODE(cmcnp_item), node_pos);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcnp_update(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const CMCNP_FNODE *cmcnp_fnode)
{
    uint32_t node_pos;

    node_pos = cmcnp_search(cmcnp, cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS != node_pos)
    {
        CMCNP_ITEM *cmcnp_item;

        cmcnp_item = cmcnp_fetch(cmcnp, node_pos);
        cmcnplru_node_move_head(cmcnp, CMCNP_ITEM_LRU_NODE(cmcnp_item), node_pos);
        return cmcnp_fnode_import(cmcnp_fnode, CMCNP_ITEM_FNODE(cmcnp_item));
    }
    return (EC_FALSE);
}

EC_BOOL cmcnp_delete(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    CMCNP_ITEM *cmcnp_item;
    uint32_t node_pos;

    ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

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
            node_pos_t    = cmcnp_dnode_umount_son(cmcnp, CMCNP_ITEM_DNODE(cmcnp_item_parent), node_pos,
                                                  CMCNP_ITEM_KEY(cmcnp_item));

            //ASSERT(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
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

            //ASSERT(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
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

EC_BOOL cmcnp_retire(CMCNP *cmcnp, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CMCNPLRU_NODE  *cmcnplru_node_head;
    UINT32   retire_num;

    cmcnplru_node_head = CMCNP_LRU_LIST(cmcnp);

    for(retire_num = 0; retire_num < expect_retire_num && EC_FALSE == cmcnp_lru_list_is_empty(cmcnp);)
    {
        uint32_t node_pos;

        CMCNP_ITEM *cmcnp_item;

        node_pos = CMCNPLRU_NODE_PREV_POS(cmcnplru_node_head);
        cmcnp_item = cmcnp_fetch(cmcnp, node_pos);

        ASSERT(EC_TRUE == cmcnprb_node_is_used(CMCNP_ITEMS_POOL(cmcnp), node_pos));
        ASSERT(CMCNP_ITEM_IS_USED == CMCNP_ITEM_USED_FLAG(cmcnp_item));

        ASSERT(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

        if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
        {
            /*retire file*/
            if(EC_FALSE == cmcnp_umount_item(cmcnp, node_pos))
            {
                dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_retire: np %u node_pos %d [REG] failed\n",
                                CMCNP_ID(cmcnp), node_pos);
                return (EC_FALSE);
            }

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

    ASSERT(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

    if(CMCNP_ITEM_FILE_IS_REG == CMCNP_ITEM_DIR_FLAG(cmcnp_item))
    {
        CMCNP_FNODE *cmcnp_fnode;

        cmcnp_fnode = CMCNP_ITEM_FNODE(cmcnp_item);
        CMCNP_DEL_SIZE(cmcnp) += CMCNP_FNODE_FILESZ(cmcnp_fnode);

        if(CMCNPRB_ERR_POS != CMCNP_ITEM_PARENT_POS(cmcnp_item))
        {
            CMCNP_ITEM  *cmcnp_item_parent;
            CMCNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CMCNP_ITEM_PARENT_POS(cmcnp_item);
            cmcnp_item_parent  = cmcnp_fetch(cmcnp, parent_node_pos);
            parent_dnode       = CMCNP_ITEM_DNODE(cmcnp_item_parent);

            node_pos_t = cmcnp_dnode_umount_son(cmcnp, parent_dnode, node_pos, CMCNP_ITEM_KEY(cmcnp_item));

            if(CMCNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CMCNP_ITEM_PARENT_POS(cmcnp_item) = CMCNPRB_ERR_POS; /*fix*/

                cmcnplru_node_rmv(cmcnp, CMCNP_ITEM_LRU_NODE(cmcnp_item), node_pos);
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
            cmcnplru_node_rmv(cmcnp, CMCNP_ITEM_LRU_NODE(cmcnp_item), node_pos);
            cmcnpdel_node_add_tail(cmcnp, CMCNP_ITEM_DEL_NODE(cmcnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmcnp_umount(CMCNP *cmcnp, const CMCNP_KEY *cmcnp_key, const uint32_t dflag)
{
    uint32_t node_pos;

    ASSERT(CMCNP_ITEM_FILE_IS_REG == dflag);

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
    ASSERT(NULL_PTR != cmcnp_item);
    ASSERT(CMCNP_ITEM_FILE_IS_DIR == CMCNP_ITEM_DIR_FLAG(cmcnp_item));

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

        (*file_size) = CMCNP_FNODE_FILESZ(cmcnp_fnode);
        return (EC_TRUE);
    }

    dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_file_size: np %u, invalid dflg %x\n", CMCNP_ID(cmcnp), CMCNP_ITEM_DIR_FLAG(cmcnp_item));
    return (EC_FALSE);
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
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_recycle_item_file: recycle dn (disk %u, block %u, page %u, size %u) failed\n",
                            CMCNP_INODE_DISK_NO(cmcnp_inode),
                            CMCNP_INODE_BLOCK_NO(cmcnp_inode),
                            CMCNP_INODE_PAGE_NO(cmcnp_inode),
                            CMCNP_FNODE_FILESZ(cmcnp_fnode));
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

        /*this file is under a deleted directory in deep. it may be still in LRU list.*/
        cmcnplru_node_rmv(cmcnp, CMCNP_ITEM_LRU_NODE(cmcnp_item), node_pos);

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

        /*CMCNP_DEL_SIZE(cmcnp) -= CMCNP_FNODE_FILESZ(cmcnp_fnode);*/
        CMCNP_RECYCLE_SIZE(cmcnp) += CMCNP_FNODE_FILESZ(cmcnp_fnode);

        /*note: this file is in DEL list so that it must not be in LRU list*/

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

        ASSERT(CMCNPRB_ERR_POS == CMCNP_ITEM_PARENT_POS(cmcnp_item));

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
CMCNP *cmcnp_create(const uint32_t np_id, const uint8_t np_model)
{
    CMCNP  *cmcnp;
    CMCNP_HEADER * cmcnp_header;
    int      fd;
    UINT32   fsize;
    uint32_t item_max_num;

    fd = ERR_FD;

    if(EC_FALSE == cmcnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    if(EC_FALSE == cmcnp_model_item_max_num(np_model, &item_max_num))
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    cmcnp_header = __cmcnp_header_new(np_id, fsize, fd, np_model);
    if(NULL_PTR == cmcnp_header)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: new mem cmcnp failed\n");
        return (NULL_PTR);
    }

    cmcnp = cmcnp_new();
    if(NULL_PTR == cmcnp)
    {
        dbg_log(SEC_0111_CMCNP, 0)(LOGSTDOUT, "error:cmcnp_create: new cmcnp %u failed\n", np_id);
        __cmcnp_header_free(cmcnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }
    CMCNP_HDR(cmcnp) = cmcnp_header;

    /*shortcut*/
    CMCNP_LRU_LIST(cmcnp) = CMCNP_ITEM_LRU_NODE(cmcnp_fetch(cmcnp, CMCNPLRU_ROOT_POS));
    CMCNP_DEL_LIST(cmcnp) = CMCNP_ITEM_DEL_NODE(cmcnp_fetch(cmcnp, CMCNPDEL_ROOT_POS));

    CMCNP_FD(cmcnp)    = fd;
    CMCNP_FSIZE(cmcnp) = fsize;
    CMCNP_FNAME(cmcnp) = NULL_PTR;

    ASSERT(np_id == CMCNP_HEADER_NP_ID(cmcnp_header));

    /*create root item*/
    cmcnp_create_root_item(cmcnp);

    dbg_log(SEC_0111_CMCNP, 9)(LOGSTDOUT, "[DEBUG] cmcnp_create: create np %u done\n", np_id);

    return (cmcnp);
}

EC_BOOL cmcnp_clean(CMCNP *cmcnp)
{
    if(NULL_PTR != CMCNP_HDR(cmcnp))
    {
        __cmcnp_header_free(CMCNP_HDR(cmcnp), CMCNP_ID(cmcnp), CMCNP_FSIZE(cmcnp), CMCNP_FD(cmcnp));
        CMCNP_HDR(cmcnp) = NULL_PTR;
    }

    ASSERT(ERR_FD == CMCNP_FD(cmcnp));

    CMCNP_FSIZE(cmcnp) = 0;

    ASSERT(NULL_PTR == CMCNP_FNAME(cmcnp));

    CMCNP_DEL_SIZE(cmcnp)     = 0;
    CMCNP_RECYCLE_SIZE(cmcnp) = 0;

    CMCNP_HDR(cmcnp) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcnp_free(CMCNP *cmcnp)
{
    if(NULL_PTR != cmcnp)
    {
        cmcnp_clean(cmcnp);
        free_static_mem(MM_CMCNP, cmcnp, LOC_CMCNP_0016);
    }
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/


