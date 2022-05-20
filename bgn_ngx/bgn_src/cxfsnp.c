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
#include "real.h"
#include "cmpic.inc"
#include "cmutex.h"
#include "cstring.h"
#include "cmisc.h"
#include "task.inc"
#include "task.h"

#include "cbloom.h"

#include "chashalgo.h"
#include "cdsk.h"
#include "cstack.h"
#include "cmd5.h"

#include "cxfspgrb.h"
#include "cxfspgb.h"
#include "cxfsnprb.h"
#include "cxfsnpque.h"
#include "cxfsnpdel.h"
#include "cxfsnpkey.h"
#include "cxfsnpattr.h"
#include "cxfsnp.h"
#include "cxfsop.h"

#include "findex.inc"

static CXFSNP_CFG g_cxfsnp_cfg_tbl[] = {
    {(const char *)"8M"  , (const char *)"CXFSNP_008M_MODEL", CXFSNP_008M_CFG_FILE_SIZE,  CXFSNP_008M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"16M" , (const char *)"CXFSNP_016M_MODEL", CXFSNP_016M_CFG_FILE_SIZE,  CXFSNP_016M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"32M" , (const char *)"CXFSNP_032M_MODEL", CXFSNP_032M_CFG_FILE_SIZE,  CXFSNP_032M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"64M" , (const char *)"CXFSNP_064M_MODEL", CXFSNP_064M_CFG_FILE_SIZE,  CXFSNP_064M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"128M", (const char *)"CXFSNP_128M_MODEL", CXFSNP_128M_CFG_FILE_SIZE,  CXFSNP_128M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"256M", (const char *)"CXFSNP_256M_MODEL", CXFSNP_256M_CFG_FILE_SIZE,  CXFSNP_256M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"512M", (const char *)"CXFSNP_512M_MODEL", CXFSNP_512M_CFG_FILE_SIZE,  CXFSNP_512M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"1G"  , (const char *)"CXFSNP_001G_MODEL", CXFSNP_001G_CFG_FILE_SIZE,  CXFSNP_001G_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2G"  , (const char *)"CXFSNP_002G_MODEL", CXFSNP_002G_CFG_FILE_SIZE,  CXFSNP_002G_CFG_ITEM_MAX_NUM, 0 },
#if (64 == WORDSIZE)
    {(const char *)"4G"  , (const char *)"CXFSNP_004G_MODEL", CXFSNP_004G_CFG_FILE_SIZE,  CXFSNP_004G_CFG_ITEM_MAX_NUM, 0 },
#endif/*(64 == WORDSIZE)*/
};

static uint8_t g_cxfsnp_cfg_tbl_len = (uint8_t)(sizeof(g_cxfsnp_cfg_tbl)/sizeof(g_cxfsnp_cfg_tbl[0]));

STATIC_CAST static CXFSNPRB_NODE *__cxfsnprb_node(CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CXFSNPRB_POOL_NODE_MAX_NUM(pool) > node_pos)
    {
        CXFSNPRB_NODE *node;

        node = (CXFSNPRB_NODE *)((void *)(pool->rb_nodes) + node_pos * CXFSNPRB_POOL_NODE_SIZEOF(pool));

        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] __cxfsnprb_node: pool %p, rb_nodes %p, node_pos %u  -> node %p\n",
                           pool, (void *)(pool->rb_nodes), node_pos, node);
        return (node);
    }
    return (NULL_PTR);
}


const char *cxfsnp_model_str(const uint8_t cxfsnp_model)
{
    CXFSNP_CFG *cxfsnp_cfg;
    if(cxfsnp_model >= g_cxfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_model_str: invalid cxfsnp mode %u\n", cxfsnp_model);
        return (const char *)"unkown";
    }
    cxfsnp_cfg = &(g_cxfsnp_cfg_tbl[ cxfsnp_model ]);
    return CXFSNP_CFG_MODEL_STR(cxfsnp_cfg);
}

uint8_t cxfsnp_model_get(const char *model_str)
{
    uint8_t cxfsnp_model;

    for(cxfsnp_model = 0; cxfsnp_model < g_cxfsnp_cfg_tbl_len; cxfsnp_model ++)
    {
        CXFSNP_CFG *cxfsnp_cfg;
        cxfsnp_cfg = &(g_cxfsnp_cfg_tbl[ cxfsnp_model ]);

        if(0 == strcasecmp(CXFSNP_CFG_MODEL_STR(cxfsnp_cfg), model_str))
        {
            return (cxfsnp_model);
        }
    }
    return (CXFSNP_ERR_MODEL);
}

EC_BOOL cxfsnp_model_file_size(const uint8_t cxfsnp_model, UINT32 *file_size)
{
    CXFSNP_CFG *cxfsnp_cfg;
    if(cxfsnp_model >= g_cxfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_model_file_size: invalid cxfsnp mode %u\n", cxfsnp_model);
        return (EC_FALSE);
    }
    cxfsnp_cfg = &(g_cxfsnp_cfg_tbl[ cxfsnp_model ]);
    (*file_size) = CXFSNP_CFG_FILE_SIZE(cxfsnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cxfsnp_model_item_max_num(const uint8_t cxfsnp_model, uint32_t *item_max_num)
{
    CXFSNP_CFG *cxfsnp_cfg;
    if(cxfsnp_model >= g_cxfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_model_item_max_num: invalid cxfsnp mode %u\n", cxfsnp_model);
        return (EC_FALSE);
    }
    cxfsnp_cfg = &(g_cxfsnp_cfg_tbl[ cxfsnp_model ]);
    (*item_max_num) = CXFSNP_CFG_ITEM_MAX_NUM(cxfsnp_cfg);
    return (EC_TRUE);
}

STATIC_CAST static uint32_t cxfsnp_path_seg_len(const uint8_t *full_path, const uint32_t full_path_len, const uint8_t *path_seg_beg)
{
    uint8_t *ptr;

    if(path_seg_beg < full_path || path_seg_beg >= full_path + full_path_len)
    {
        return (0);
    }

    for(ptr = (uint8_t *)path_seg_beg; ptr < full_path + full_path_len && '/' != (*ptr); ptr ++)
    {
        /*do nothing*/
    }

    return (ptr - path_seg_beg);
}

EC_BOOL cxfsnp_inode_init(CXFSNP_INODE *cxfsnp_inode)
{
    CXFSNP_INODE_DISK_NO(cxfsnp_inode)    = CXFSPGRB_ERR_POS;
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)   = CXFSPGRB_ERR_POS;
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)    = CXFSPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cxfsnp_inode_clean(CXFSNP_INODE *cxfsnp_inode)
{
    CXFSNP_INODE_DISK_NO(cxfsnp_inode)    = CXFSPGRB_ERR_POS;
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)   = CXFSPGRB_ERR_POS;
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)    = CXFSPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cxfsnp_inode_clone(const CXFSNP_INODE *cxfsnp_inode_src, CXFSNP_INODE *cxfsnp_inode_des)
{
    CXFSNP_INODE_DISK_NO(cxfsnp_inode_des)    = CXFSNP_INODE_DISK_NO(cxfsnp_inode_src);
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode_des)   = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode_src);
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode_des)    = CXFSNP_INODE_PAGE_NO(cxfsnp_inode_src);

    return (EC_TRUE);
}

void cxfsnp_inode_print(LOG *log, const CXFSNP_INODE *cxfsnp_inode)
{
    sys_print(log, "(disk %u, block %u, page %u)\n",
                    CXFSNP_INODE_DISK_NO(cxfsnp_inode),
                    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode),
                    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)
                    );
    return;
}

void cxfsnp_inode_log_no_lock(LOG *log, const CXFSNP_INODE *cxfsnp_inode)
{
    sys_print_no_lock(log, "(disk %u, block %u, page %u)\n",
                    CXFSNP_INODE_DISK_NO(cxfsnp_inode),
                    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode),
                    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)
                    );
    return;
}

CXFSNP_FNODE *cxfsnp_fnode_new()
{
    CXFSNP_FNODE *cxfsnp_fnode;
    alloc_static_mem(MM_CXFSNP_FNODE, &cxfsnp_fnode, LOC_CXFSNP_0001);
    if(NULL_PTR != cxfsnp_fnode)
    {
        cxfsnp_fnode_init(cxfsnp_fnode);
    }
    return (cxfsnp_fnode);
}

CXFSNP_FNODE *cxfsnp_fnode_make(const CXFSNP_FNODE *cxfsnp_fnode_src)
{
    CXFSNP_FNODE *cxfsnp_fnode_des;
    alloc_static_mem(MM_CXFSNP_FNODE, &cxfsnp_fnode_des, LOC_CXFSNP_0002);
    if(NULL_PTR != cxfsnp_fnode_des)
    {
        cxfsnp_fnode_clone(cxfsnp_fnode_src, cxfsnp_fnode_des);
    }
    return (cxfsnp_fnode_des);
}

EC_BOOL cxfsnp_fnode_init(CXFSNP_FNODE *cxfsnp_fnode)
{
    uint32_t pos;

    CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = 0;
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 0;

    for(pos = 0; pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cxfsnp_inode_init(CXFSNP_FNODE_INODE(cxfsnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_fnode_clean(CXFSNP_FNODE *cxfsnp_fnode)
{
    uint32_t pos;

    CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = 0;
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 0;

    for(pos = 0; pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cxfsnp_inode_clean(CXFSNP_FNODE_INODE(cxfsnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_fnode_free(CXFSNP_FNODE *cxfsnp_fnode)
{
    if(NULL_PTR != cxfsnp_fnode)
    {
        cxfsnp_fnode_clean(cxfsnp_fnode);
        free_static_mem(MM_CXFSNP_FNODE, cxfsnp_fnode, LOC_CXFSNP_0003);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_fnode_clone(const CXFSNP_FNODE *cxfsnp_fnode_src, CXFSNP_FNODE *cxfsnp_fnode_des)
{
    uint32_t pos;

    CXFSNP_FNODE_FILESZ(cxfsnp_fnode_des) = CXFSNP_FNODE_FILESZ(cxfsnp_fnode_src);
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode_des) = CXFSNP_FNODE_REPNUM(cxfsnp_fnode_src);

    for(pos = 0; pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode_src) && pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cxfsnp_inode_clone(CXFSNP_FNODE_INODE(cxfsnp_fnode_src, pos), CXFSNP_FNODE_INODE(cxfsnp_fnode_des, pos));
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_fnode_check_inode_exist(const CXFSNP_INODE *inode, const CXFSNP_FNODE *cxfsnp_fnode)
{
    uint32_t replica_pos;

    for(replica_pos = 0; replica_pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode); replica_pos ++)
    {
        if( CXFSNP_INODE_DISK_NO(inode)    == CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, replica_pos)
         && CXFSNP_INODE_BLOCK_NO(inode)   == CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, replica_pos)
         && CXFSNP_INODE_PAGE_NO(inode)    == CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, replica_pos)
        )
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL cxfsnp_fnode_cmp(const CXFSNP_FNODE *cxfsnp_fnode_1st, const CXFSNP_FNODE *cxfsnp_fnode_2nd)
{
    uint32_t replica_pos;

    if(NULL_PTR == cxfsnp_fnode_1st && NULL_PTR == cxfsnp_fnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cxfsnp_fnode_1st || NULL_PTR == cxfsnp_fnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CXFSNP_FNODE_REPNUM(cxfsnp_fnode_1st) != CXFSNP_FNODE_REPNUM(cxfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CXFSNP_FNODE_FILESZ(cxfsnp_fnode_1st) != CXFSNP_FNODE_FILESZ(cxfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    for(replica_pos = 0; replica_pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode_1st); replica_pos ++)
    {
        if(EC_FALSE == cxfsnp_fnode_check_inode_exist(CXFSNP_FNODE_INODE(cxfsnp_fnode_1st, replica_pos), cxfsnp_fnode_2nd))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_fnode_import(const CXFSNP_FNODE *cxfsnp_fnode_src, CXFSNP_FNODE *cxfsnp_fnode_des)
{
    uint32_t src_pos;
    uint32_t des_pos;

    for(src_pos = 0, des_pos = 0; src_pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode_src) && src_pos < CXFSNP_FILE_REPLICA_MAX_NUM; src_pos ++)
    {
        CXFSNP_INODE *cxfsnp_inode_src;

        cxfsnp_inode_src = (CXFSNP_INODE *)CXFSNP_FNODE_INODE(cxfsnp_fnode_src, src_pos);
        if(CXFSPGRB_ERR_POS != CXFSNP_INODE_DISK_NO(cxfsnp_inode_src)
        && CXFSPGRB_ERR_POS != CXFSNP_INODE_BLOCK_NO(cxfsnp_inode_src)
        && CXFSPGRB_ERR_POS != CXFSNP_INODE_PAGE_NO(cxfsnp_inode_src)
        )
        {
            CXFSNP_INODE *cxfsnp_inode_des;

            cxfsnp_inode_des = CXFSNP_FNODE_INODE(cxfsnp_fnode_des, des_pos);
            if(cxfsnp_inode_src != cxfsnp_inode_des)
            {
                cxfsnp_inode_clone(cxfsnp_inode_src, cxfsnp_inode_des);
            }

            des_pos ++;
        }
    }

    CXFSNP_FNODE_FILESZ(cxfsnp_fnode_des) = CXFSNP_FNODE_FILESZ(cxfsnp_fnode_src);
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode_des) = des_pos;
    return (EC_TRUE);
}

uint32_t cxfsnp_fnode_count_replica(const CXFSNP_FNODE *cxfsnp_fnode)
{
    uint32_t pos;
    uint32_t count;

    for(pos = 0, count = 0; pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode) && pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        CXFSNP_INODE *cxfsnp_inode;

        cxfsnp_inode = (CXFSNP_INODE *)CXFSNP_FNODE_INODE(cxfsnp_fnode, pos);
        if(CXFSPGRB_ERR_POS != CXFSNP_INODE_DISK_NO(cxfsnp_inode)
        && CXFSPGRB_ERR_POS != CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)
        && CXFSPGRB_ERR_POS != CXFSNP_INODE_PAGE_NO(cxfsnp_inode)
        )
        {
            count ++;
        }
    }
    return (count);
}

void cxfsnp_fnode_print(LOG *log, const CXFSNP_FNODE *cxfsnp_fnode)
{
    uint32_t pos;

    if(0 < CXFSNP_FNODE_REPNUM(cxfsnp_fnode))
    {
        sys_log(log, "[DEBUG] cxfsnp_fnode %p: file size %u, replica num %u, ",
                        cxfsnp_fnode,
                        CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                        CXFSNP_FNODE_REPNUM(cxfsnp_fnode));

        for(pos = 0; pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode) && pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            cxfsnp_inode_print(log, CXFSNP_FNODE_INODE(cxfsnp_fnode, pos));
        }
    }
    else
    {
        sys_log(log, "[DEBUG] cxfsnp_fnode %p: file size %u, replica num %u\n",
                        cxfsnp_fnode,
                        CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                        CXFSNP_FNODE_REPNUM(cxfsnp_fnode));
    }

    return;
}

void cxfsnp_fnode_log_no_lock(LOG *log, const CXFSNP_FNODE *cxfsnp_fnode)
{
    uint32_t pos;

    sys_print_no_lock(log, "size %u, replica %u",
                    CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                    CXFSNP_FNODE_REPNUM(cxfsnp_fnode));

    for(pos = 0; pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode) && pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cxfsnp_inode_log_no_lock(log, CXFSNP_FNODE_INODE(cxfsnp_fnode, pos));
    }
    sys_print_no_lock(log, "\n");

    return;
}

CXFSNP_DNODE *cxfsnp_dnode_new()
{
    CXFSNP_DNODE *cxfsnp_dnode;

    alloc_static_mem(MM_CXFSNP_DNODE, &cxfsnp_dnode, LOC_CXFSNP_0004);
    if(NULL_PTR != cxfsnp_dnode)
    {
        cxfsnp_dnode_init(cxfsnp_dnode);
    }
    return (cxfsnp_dnode);

}

EC_BOOL cxfsnp_dnode_init(CXFSNP_DNODE *cxfsnp_dnode)
{
    CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode) = 0;
    CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode)  = 0;
    CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode)  = CXFSNPRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cxfsnp_dnode_clean(CXFSNP_DNODE *cxfsnp_dnode)
{
    CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode) = 0;
    CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode)  = 0;
    CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode) = CXFSNPRB_ERR_POS;

    return (EC_TRUE);
}

EC_BOOL cxfsnp_dnode_free(CXFSNP_DNODE *cxfsnp_dnode)
{
    if(NULL_PTR != cxfsnp_dnode)
    {
        cxfsnp_dnode_clean(cxfsnp_dnode);
        free_static_mem(MM_CXFSNP_DNODE, cxfsnp_dnode, LOC_CXFSNP_0005);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_dnode_clone(const CXFSNP_DNODE *cxfsnp_dnode_src, CXFSNP_DNODE *cxfsnp_dnode_des)
{
    CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode_des) = CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode_src);
    CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode_des)  = CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode_src);
    CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode_des)  = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode_src);
    return (EC_TRUE);
}

CXFSNP_KEY *cxfsnp_key_new()
{
    CXFSNP_KEY *cxfsnp_key;

    alloc_static_mem(MM_CXFSNP_KEY, &cxfsnp_key, LOC_CXFSNP_0006);
    if(NULL_PTR != cxfsnp_key)
    {
        cxfsnp_key_init(cxfsnp_key);
    }
    return (cxfsnp_key);
}

EC_BOOL cxfsnp_key_init(CXFSNP_KEY *cxfsnp_key)
{
    CXFSNP_KEY_LEN(cxfsnp_key) = 0;
    BSET(CXFSNP_KEY_NAME(cxfsnp_key), '\0', CXFSNP_KEY_MAX_SIZE);
    return (EC_TRUE);
}

EC_BOOL cxfsnp_key_clean(CXFSNP_KEY *cxfsnp_key)
{
    CXFSNP_KEY_LEN(cxfsnp_key) = 0;

    /*optimize: item would be initialized when allocated. refer: cxfsnp_dnode_insert*/
    CXFSNP_KEY_NAME(cxfsnp_key)[ 0 ] = '\0';

    return (EC_TRUE);
}

EC_BOOL cxfsnp_key_clone(const CXFSNP_KEY *cxfsnp_key_src, CXFSNP_KEY *cxfsnp_key_des)
{
    if(NULL_PTR == cxfsnp_key_src)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_key_clone: cxfsnp_key_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cxfsnp_key_des)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_key_clone: cxfsnp_key_des is null\n");
        return (EC_FALSE);
    }

    CXFSNP_KEY_LEN(cxfsnp_key_des) =  CXFSNP_KEY_LEN(cxfsnp_key_src);

    BCOPY(CXFSNP_KEY_NAME(cxfsnp_key_src), CXFSNP_KEY_NAME(cxfsnp_key_des), CXFSNP_KEY_LEN(cxfsnp_key_src));
    return (EC_TRUE);
}

EC_BOOL cxfsnp_key_free(CXFSNP_KEY *cxfsnp_key)
{
    if(NULL_PTR != cxfsnp_key)
    {
        cxfsnp_key_clean(cxfsnp_key);
        free_static_mem(MM_CXFSNP_KEY, cxfsnp_key, LOC_CXFSNP_0007);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_key_set(CXFSNP_KEY *cxfsnp_key, const uint32_t klen, const uint8_t *key)
{
    BCOPY(key, CXFSNP_KEY_NAME(cxfsnp_key), klen);
    CXFSNP_KEY_LEN(cxfsnp_key) = (uint8_t)klen;

    return (EC_TRUE);
}

void cxfsnp_key_print(LOG *log, const CXFSNP_KEY *cxfsnp_key)
{
    sys_log(log, "klen: %u, key: %.*s\n",
                 CXFSNP_KEY_LEN(cxfsnp_key),
                 CXFSNP_KEY_LEN(cxfsnp_key), CXFSNP_KEY_NAME(cxfsnp_key));

    return;
}

CXFSNP_ATTR *cxfsnp_attr_new()
{
    CXFSNP_ATTR *cxfsnp_attr;

    alloc_static_mem(MM_CXFSNP_ATTR, &cxfsnp_attr, LOC_CXFSNP_0008);
    if(NULL_PTR != cxfsnp_attr)
    {
        cxfsnp_attr_init(cxfsnp_attr);
    }
    return (cxfsnp_attr);
}

EC_BOOL cxfsnp_attr_init(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr)      = CXFSNP_ATTR_NOT_LINK;
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)      = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)       = CXFSNP_ATTR_FILE_IS_ERR;
        CXFSNP_ATTR_MODE(cxfsnp_attr)           = 0;
        CXFSNP_ATTR_UID(cxfsnp_attr)            = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)            = 0;
        CXFSNP_ATTR_DEV(cxfsnp_attr)            = 0;
        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)      = 0;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)      = 0;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)      = 0;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr)     = 0;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr)     = 0;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr)     = 0;
        CXFSNP_ATTR_SLINK(cxfsnp_attr)          = 0;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)          = 0;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)       = CXFSNP_ATTR_ERR_INO;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_attr_clean(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr)      = CXFSNP_ATTR_NOT_LINK;
        CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr)      = CXFSNP_ATTR_NOT_HIDE;
        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)       = CXFSNP_ATTR_FILE_IS_ERR;
        CXFSNP_ATTR_MODE(cxfsnp_attr)           = 0;
        CXFSNP_ATTR_UID(cxfsnp_attr)            = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)            = 0;
        CXFSNP_ATTR_DEV(cxfsnp_attr)            = 0;
        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)      = 0;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)      = 0;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)      = 0;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr)     = 0;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr)     = 0;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr)     = 0;
        CXFSNP_ATTR_SLINK(cxfsnp_attr)          = 0;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)          = 0;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)       = CXFSNP_ATTR_ERR_INO;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_attr_clone(const CXFSNP_ATTR *cxfsnp_attr_src, CXFSNP_ATTR *cxfsnp_attr_des)
{
    if(NULL_PTR == cxfsnp_attr_src)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_attr_clone: cxfsnp_attr_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cxfsnp_attr_des)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_attr_clone: cxfsnp_attr_des is null\n");
        return (EC_FALSE);
    }

    CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_des)      = CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr_src);
    CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_des)      = CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_src);
    CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_des)       = CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr_src);
    CXFSNP_ATTR_MODE(cxfsnp_attr_des)           = CXFSNP_ATTR_MODE(cxfsnp_attr_src);
    CXFSNP_ATTR_UID(cxfsnp_attr_des)            = CXFSNP_ATTR_UID(cxfsnp_attr_src);
    CXFSNP_ATTR_GID(cxfsnp_attr_des)            = CXFSNP_ATTR_GID(cxfsnp_attr_src);
    CXFSNP_ATTR_DEV(cxfsnp_attr_des)            = CXFSNP_ATTR_DEV(cxfsnp_attr_src);
    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr_des)      = CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr_src);
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr_des)      = CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr_src);
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr_des)      = CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr_src);
    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr_des)     = CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr_src);
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr_des)     = CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr_src);
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr_des)     = CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr_src);
    CXFSNP_ATTR_SLINK(cxfsnp_attr_des)          = CXFSNP_ATTR_SLINK(cxfsnp_attr_src);
    CXFSNP_ATTR_NLINK(cxfsnp_attr_des)          = CXFSNP_ATTR_NLINK(cxfsnp_attr_src);
    CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_des)       = CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_src);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_attr_free(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        cxfsnp_attr_clean(cxfsnp_attr);
        free_static_mem(MM_CXFSNP_ATTR, cxfsnp_attr, LOC_CXFSNP_0009);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_attr_set_file(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;

        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)   = CXFSNP_ATTR_FILE_IS_REG;

        CXFSNP_ATTR_MODE(cxfsnp_attr)       = S_IFREG
                                            | (S_IRWXU & ~S_IXUSR) /*owner: rw-*/
                                            | (S_IRWXG & ~S_IXGRP) /*group: rw-*/
                                            | (S_IRWXO & ~S_IXOTH) /*other: rw-*/
                                            ;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)   = CXFSNP_ATTR_ERR_INO;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;
        CXFSNP_ATTR_SLINK(cxfsnp_attr)      = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_attr_set_dir(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;

        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)   = CXFSNP_ATTR_FILE_IS_DIR;

        /*0755*/
        CXFSNP_ATTR_MODE(cxfsnp_attr)       = S_IFDIR
                                            | S_IRWXU              /*owner: rwx*/
                                            | (S_IRWXG & ~S_IWGRP) /*group: r-x*/
                                            | (S_IRWXO & ~S_IWOTH) /*other: r-x*/
                                            ;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)   = CXFSNP_ATTR_ERR_INO;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 2; /*. and ..*/
        CXFSNP_ATTR_SLINK(cxfsnp_attr)      = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_attr_set_file_symlink(CXFSNP_ATTR *cxfsnp_attr, const uint64_t next_ino)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;

        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)   = CXFSNP_ATTR_FILE_IS_REG;

        CXFSNP_ATTR_MODE(cxfsnp_attr)       = S_IFLNK
                                            | (S_IRWXU & ~S_IXUSR) /*owner: rw-*/
                                            | (S_IRWXG & ~S_IXGRP) /*group: rw-*/
                                            | (S_IRWXO & ~S_IXOTH) /*other: rw-*/
                                            ;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)   = next_ino;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;
        CXFSNP_ATTR_SLINK(cxfsnp_attr)      ++;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_attr_set_dir_symlink(CXFSNP_ATTR *cxfsnp_attr, const uint64_t next_ino)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;

        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)   = CXFSNP_ATTR_FILE_IS_DIR;

        /*0755*/
        CXFSNP_ATTR_MODE(cxfsnp_attr)       = S_IFLNK
                                            | S_IRWXU              /*owner: rwx*/
                                            | (S_IRWXG & ~S_IWGRP) /*group: r-x*/
                                            | (S_IRWXO & ~S_IWOTH) /*other: r-x*/
                                            ;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)   = next_ino;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 2; /*. and ..*/
        CXFSNP_ATTR_SLINK(cxfsnp_attr)      ++;
    }

    return (EC_TRUE);
}

/*hard link*/
EC_BOOL cxfsnp_attr_set_file_link(CXFSNP_ATTR *cxfsnp_attr, const uint64_t next_ino)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;

        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)   = CXFSNP_ATTR_FILE_IS_REG;

        CXFSNP_ATTR_MODE(cxfsnp_attr)       = S_IFREG
                                            | (S_IRWXU & ~S_IXUSR) /*owner: rw-*/
                                            | (S_IRWXG & ~S_IXGRP) /*group: rw-*/
                                            | (S_IRWXO & ~S_IXOTH) /*other: rw-*/
                                            ;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)   = next_ino;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = CXFSNP_ATTR_ERR_NLINK;
        CXFSNP_ATTR_SLINK(cxfsnp_attr)      = 0;
    }

    return (EC_TRUE);
}

/*hard link*/
EC_BOOL cxfsnp_attr_set_dir_link(CXFSNP_ATTR *cxfsnp_attr, const uint64_t next_ino)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;

        CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr)   = CXFSNP_ATTR_FILE_IS_DIR;

        /*0755*/
        CXFSNP_ATTR_MODE(cxfsnp_attr)       = S_IFDIR
                                            | S_IRWXU              /*owner: rwx*/
                                            | (S_IRWXG & ~S_IWGRP) /*group: r-x*/
                                            | (S_IRWXO & ~S_IWOTH) /*other: r-x*/
                                            ;

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr)   = next_ino;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = CXFSNP_ATTR_ERR_NLINK;
        CXFSNP_ATTR_SLINK(cxfsnp_attr)      = 0;
    }

    return (EC_TRUE);
}

/*hard link*/
EC_BOOL cxfsnp_attr_inc_link(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr
    && CXFSNP_ATTR_ERR_NLINK != CXFSNP_ATTR_NLINK(cxfsnp_attr))
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      ++;
    }

    return (EC_TRUE);
}

/*hard link*/
EC_BOOL cxfsnp_attr_dec_link(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr
    && 0 < CXFSNP_ATTR_NLINK(cxfsnp_attr)
    && CXFSNP_ATTR_ERR_NLINK != CXFSNP_ATTR_NLINK(cxfsnp_attr))
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      --;
    }

    return (EC_TRUE);
}


EC_BOOL cxfsnp_attr_update_time(CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        uint64_t         nsec;   /*seconds*/
        uint64_t         nanosec;/*nanosecond*/

        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    }

    return (EC_TRUE);
}

void cxfsnp_attr_print(LOG *log, const CXFSNP_ATTR *cxfsnp_attr)
{
    if(NULL_PTR != cxfsnp_attr)
    {
        sys_print(log, "cxfsnp_attr %p: "
                       "link %#x, hide %#x, dir %#x, "
                       "mode %#o, uid %u, gid %u, dev %#x, "
                       "slink %u, nlink %u, next_ino %lu, "
                       "access (%lu.%u), "
                       "modified (%lu.%u), "
                       "change (%lu.%u)\n",
                       cxfsnp_attr,
                       CXFSNP_ATTR_LINK_FLAG(cxfsnp_attr),
                       CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr),
                       CXFSNP_ATTR_DIR_FLAG(cxfsnp_attr),
                       CXFSNP_ATTR_MODE(cxfsnp_attr),
                       CXFSNP_ATTR_UID(cxfsnp_attr),
                       CXFSNP_ATTR_GID(cxfsnp_attr),
                       CXFSNP_ATTR_DEV(cxfsnp_attr),
                       CXFSNP_ATTR_SLINK(cxfsnp_attr),
                       CXFSNP_ATTR_NLINK(cxfsnp_attr),
                       CXFSNP_ATTR_NEXT_INO(cxfsnp_attr),
                       CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr), CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr),
                       CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr), CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr),
                       CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr), CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr));
    }
}

CXFSNP_ITEM *cxfsnp_item_new()
{
    CXFSNP_ITEM *cxfsnp_item;

    alloc_static_mem(MM_CXFSNP_ITEM, &cxfsnp_item, LOC_CXFSNP_0010);
    if(NULL_PTR != cxfsnp_item)
    {
        cxfsnp_item_init(cxfsnp_item);
    }
    return (cxfsnp_item);
}

EC_BOOL cxfsnp_item_init(CXFSNP_ITEM *cxfsnp_item)
{
    CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)         = CXFSNP_ITEM_FILE_IS_ERR;
    CXFSNP_ITEM_USED_FLAG(cxfsnp_item)        = CXFSNP_ITEM_IS_NOT_USED;
    CXFSNP_ITEM_PARENT_POS(cxfsnp_item)       = CXFSNPRB_ERR_POS;/*fix*/
    CXFSNP_ITEM_SECOND_HASH(cxfsnp_item)      = 0;

    cxfsnp_fnode_init(CXFSNP_ITEM_FNODE(cxfsnp_item));

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cxfsnp_item_clean(CXFSNP_ITEM *cxfsnp_item)
{
    CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)         = CXFSNP_ITEM_FILE_IS_ERR;
    CXFSNP_ITEM_USED_FLAG(cxfsnp_item)        = CXFSNP_ITEM_IS_NOT_USED;
    CXFSNP_ITEM_PARENT_POS(cxfsnp_item)       = CXFSNPRB_ERR_POS;/*fix bug: break pointer to parent*/
    CXFSNP_ITEM_SECOND_HASH(cxfsnp_item)      = 0;

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL cxfsnp_item_clone(const CXFSNP_ITEM *cxfsnp_item_src, CXFSNP_ITEM *cxfsnp_item_des)
{
    if(NULL_PTR == cxfsnp_item_src)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_clone: cxfsnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cxfsnp_item_des)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_clone: cxfsnp_item_des is null\n");
        return (EC_FALSE);
    }

    CXFSNP_ITEM_USED_FLAG(cxfsnp_item_des)    =  CXFSNP_ITEM_USED_FLAG(cxfsnp_item_src);
    CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_des)     =  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_src);
    CXFSNP_ITEM_KEY_SOFFSET(cxfsnp_item_des)  = CXFSNP_ITEM_KEY_SOFFSET(cxfsnp_item_src);
    CXFSNP_ITEM_ATTR_SOFFSET(cxfsnp_item_des) = CXFSNP_ITEM_ATTR_SOFFSET(cxfsnp_item_src);
    CXFSNP_ITEM_PARENT_POS(cxfsnp_item_des)   = CXFSNP_ITEM_PARENT_POS(cxfsnp_item_src);
    CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_des)  = CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_src);

    cxfsnpque_node_clone(CXFSNP_ITEM_QUE_NODE(cxfsnp_item_src), CXFSNP_ITEM_QUE_NODE(cxfsnp_item_des));
    cxfsnpdel_node_clone(CXFSNP_ITEM_DEL_NODE(cxfsnp_item_src), CXFSNP_ITEM_DEL_NODE(cxfsnp_item_des));

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_src))
    {
        cxfsnp_fnode_clone(CXFSNP_ITEM_FNODE(cxfsnp_item_src), CXFSNP_ITEM_FNODE(cxfsnp_item_des));
    }
    else if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_src))
    {
        cxfsnp_dnode_clone(CXFSNP_ITEM_DNODE(cxfsnp_item_src), CXFSNP_ITEM_DNODE(cxfsnp_item_des));
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_item_free(CXFSNP_ITEM *cxfsnp_item)
{
    if(NULL_PTR != cxfsnp_item)
    {
        cxfsnp_item_clean(cxfsnp_item);
        free_static_mem(MM_CXFSNP_ITEM, cxfsnp_item, LOC_CXFSNP_0011);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_item_set_key(CXFSNP_ITEM *cxfsnp_item, const uint32_t klen, const uint8_t *key)
{
    BCOPY(key, CXFSNP_ITEM_KNAME(cxfsnp_item), (uint8_t)klen);
    CXFSNP_ITEM_KLEN(cxfsnp_item) = (uint8_t)klen;

    return (EC_TRUE);
}

STATIC_CAST static const char *__cxfsnp_item_dir_flag_str(const uint32_t dir_flag)
{
    switch(dir_flag)
    {
        case CXFSNP_ITEM_FILE_IS_DIR:
            return (const char *)"D";
        case CXFSNP_ITEM_FILE_IS_REG:
            return (const char *)"F";
    }

    return (const char *)"UFO";
}

/*without key print*/
void cxfsnp_item_print(LOG *log, const CXFSNP_ITEM *cxfsnp_item)
{
    uint32_t pos;

    sys_print(log, "cxfsnp_item %p: flag 0x%x [%s], stat %u, hash %u, "
                   "key soffset %u, attr soffset %u, parent %u, que node (%u, %u), del node (%u, %u)\n",
                    cxfsnp_item,
                    CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), __cxfsnp_item_dir_flag_str(CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)),
                    CXFSNP_ITEM_USED_FLAG(cxfsnp_item),
                    CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                    CXFSNP_ITEM_KEY_SOFFSET(cxfsnp_item),
                    CXFSNP_ITEM_ATTR_SOFFSET(cxfsnp_item),
                    CXFSNP_ITEM_PARENT_POS(cxfsnp_item),
                    CXFSNPQUE_NODE_PREV_POS(CXFSNP_ITEM_QUE_NODE(cxfsnp_item)),
                    CXFSNPQUE_NODE_NEXT_POS(CXFSNP_ITEM_QUE_NODE(cxfsnp_item)),
                    CXFSNPDEL_NODE_PREV_POS(CXFSNP_ITEM_DEL_NODE(cxfsnp_item)),
                    CXFSNPDEL_NODE_NEXT_POS(CXFSNP_ITEM_DEL_NODE(cxfsnp_item))
                    );

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;

        cxfsnp_fnode = (CXFSNP_FNODE *)CXFSNP_ITEM_FNODE(cxfsnp_item);
        sys_log(log, "file size %u, replica num %u\n",
                        CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                        CXFSNP_FNODE_REPNUM(cxfsnp_fnode));
        sys_log(log, "inode:\n");
        for(pos = 0; pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode) && pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            CXFSNP_INODE *cxfsnp_inode;

            cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, pos);
            cxfsnp_inode_print(log, cxfsnp_inode);
            //sys_print(log, "\n");
        }
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_DNODE *cxfsnp_dnode;

        cxfsnp_dnode = (CXFSNP_DNODE *)CXFSNP_ITEM_DNODE(cxfsnp_item);
        sys_log(log, "file size: %lu, file num: %u, dir root pos: %u\n",
                     CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode),
                     CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode),
                     CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode));
    }

    return;
}

void cxfsnp_item_and_key_print(LOG *log, const CXFSNP_ITEM *cxfsnp_item)
{
    uint32_t pos;

    sys_print(log, "cxfsnp_item %p: flag 0x%x [%s], stat %u, klen %u, hash %u\n",
                    cxfsnp_item,
                    CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), __cxfsnp_item_dir_flag_str(CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)),
                    CXFSNP_ITEM_USED_FLAG(cxfsnp_item),
                    CXFSNP_ITEM_KLEN(cxfsnp_item),
                    CXFSNP_ITEM_SECOND_HASH(cxfsnp_item)
                    );

    sys_log(log, "key: %.*s\n", CXFSNP_ITEM_KLEN(cxfsnp_item), CXFSNP_ITEM_KNAME(cxfsnp_item));
    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;

        cxfsnp_fnode = (CXFSNP_FNODE *)CXFSNP_ITEM_FNODE(cxfsnp_item);
        sys_log(log, "file size %u, replica num %u\n",
                        CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                        CXFSNP_FNODE_REPNUM(cxfsnp_fnode));
        for(pos = 0; pos < CXFSNP_FNODE_REPNUM(cxfsnp_fnode) && pos < CXFSNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            CXFSNP_INODE *cxfsnp_inode;

            cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, pos);
            cxfsnp_inode_print(log, cxfsnp_inode);
            //sys_print(log, "\n");
        }
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_DNODE *cxfsnp_dnode;

        cxfsnp_dnode = (CXFSNP_DNODE *)CXFSNP_ITEM_DNODE(cxfsnp_item);
        sys_log(log, "file size: %lu, file num: %u, dir root pos: %u\n",
                     CXFSNP_DNODE_FILE_SIZE(cxfsnp_dnode),
                     CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode),
                     CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode));
    }

    return;
}

EC_BOOL cxfsnp_item_cmp(const CXFSNP_ITEM *cxfsnp_item_src, const CXFSNP_ITEM *cxfsnp_item_des)
{
    if(CXFSNP_KEY_MAX_SIZE < CXFSNP_ITEM_KLEN(cxfsnp_item_src)
    && CXFSNP_KEY_MAX_SIZE >= CXFSNP_ITEM_KLEN(cxfsnp_item_des))
    {
        return (EC_FALSE);
    }

    if(CXFSNP_KEY_MAX_SIZE >= CXFSNP_ITEM_KLEN(cxfsnp_item_src)
    && CXFSNP_KEY_MAX_SIZE < CXFSNP_ITEM_KLEN(cxfsnp_item_des))
    {
        return (EC_FALSE);
    }

    return cxfsnp_item_is(cxfsnp_item_src,
                          CXFSNP_ITEM_KLEN(cxfsnp_item_des),
                          CXFSNP_ITEM_KNAME(cxfsnp_item_des));
}

EC_BOOL cxfsnp_item_is(const CXFSNP_ITEM *cxfsnp_item, const uint32_t klen, const uint8_t *key)
{
    if(CXFSNP_KEY_MAX_SIZE < klen)/*overflow key*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        if(md5_len != CXFSNP_ITEM_KLEN(cxfsnp_item))
        {
            return (EC_FALSE);
        }

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(klen, key);

        if(0 != memcmp((void *)md5_str, (void *)CXFSNP_ITEM_KNAME(cxfsnp_item), md5_len))
        {
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(klen !=  CXFSNP_ITEM_KLEN(cxfsnp_item))
    {
        return (EC_FALSE);
    }

    if(0 != strncmp((char *)key, (char *)CXFSNP_ITEM_KNAME(cxfsnp_item), klen))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CXFSNP_ITEM *cxfsnp_item_rb_parent(const CXFSNP *cxfsnp, const CXFSNP_ITEM *cxfsnp_item)
{
    uint32_t parent_pos;

    parent_pos = CXFSNPRB_NODE_PARENT_POS(CXFSNP_ITEM_RB_NODE(cxfsnp_item));
    if(CXFSNPRB_ERR_POS == parent_pos)
    {
        return (NULL_PTR);
    }

    return cxfsnp_fetch(cxfsnp, parent_pos);
}

CXFSNP_ITEM *cxfsnp_item_rb_left(const CXFSNP *cxfsnp, const CXFSNP_ITEM *cxfsnp_item)
{
    uint32_t left_pos;

    left_pos = CXFSNPRB_NODE_LEFT_POS(CXFSNP_ITEM_RB_NODE(cxfsnp_item));
    if(CXFSNPRB_ERR_POS == left_pos)
    {
        return (NULL_PTR);
    }

    return cxfsnp_fetch(cxfsnp, left_pos);
}

CXFSNP_ITEM *cxfsnp_item_rb_right(const CXFSNP *cxfsnp, const CXFSNP_ITEM *cxfsnp_item)
{
    uint32_t right_offset;

    right_offset = CXFSNPRB_NODE_RIGHT_POS(CXFSNP_ITEM_RB_NODE(cxfsnp_item));
    if(CXFSNPRB_ERR_POS == right_offset)
    {
        return (NULL_PTR);
    }

    return cxfsnp_fetch(cxfsnp, right_offset);
}

EC_BOOL cxfsnp_dit_node_init(CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    UINT32 idx;

    CXFSNP_DIT_NODE_HANDLER(cxfsnp_dit_node)    = NULL_PTR;
    CXFSNP_DIT_NODE_CUR_NP_ID(cxfsnp_dit_node)  = CXFSNP_ERR_ID;
    CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node)  = CXFSNP_ERR_DEPTH;
    cstack_init(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node), MM_CXFSNP_ITEM, LOC_CXFSNP_0012);

    for(idx = 0; idx < CXFSNP_DIT_ARGS_MAX_NUM; idx ++)
    {
        CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, idx) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_dit_node_clean(CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    UINT32 idx;

    CXFSNP_DIT_NODE_HANDLER(cxfsnp_dit_node)    = NULL_PTR;
    CXFSNP_DIT_NODE_CUR_NP_ID(cxfsnp_dit_node)  = CXFSNP_ERR_ID;
    CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node)  = CXFSNP_ERR_DEPTH;
    cstack_clean(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node), NULL_PTR); /*never cleanup cxfsnp_item*/

    for(idx = 0; idx < CXFSNP_DIT_ARGS_MAX_NUM; idx ++)
    {
        CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, idx) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static CXFSNP_HEADER *__cxfsnp_header_load(const uint32_t np_id, const UINT32 fsize, int fd)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(fsize, LOC_CXFSNP_0013);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_header_load: malloc %ld bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, buff))
    {
        safe_free(buff, LOC_CXFSNP_0014);
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_header_load: load %ld bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    return ((CXFSNP_HEADER *)buff);
}

STATIC_CAST static CXFSNP_HEADER *__cxfsnp_header_dup(CXFSNP_HEADER *src_cxfsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    CXFSNP_HEADER *des_cxfsnp_header;

    des_cxfsnp_header = (CXFSNP_HEADER *)safe_malloc(fsize, LOC_CXFSNP_0015);
    if(NULL_PTR == des_cxfsnp_header)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_header_dup: new header with %ld bytes for np %u fd %d failed\n",
                           fsize, des_np_id, fd);
        return (NULL_PTR);
    }

    BCOPY(src_cxfsnp_header, des_cxfsnp_header, fsize);

    CXFSNP_HEADER_NP_ID(des_cxfsnp_header)  = des_np_id;
    return (des_cxfsnp_header);
}

STATIC_CAST static CXFSNP_HEADER *__cxfsnp_header_new(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model)
{
    CXFSNP_HEADER *cxfsnp_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    cxfsnp_header = (CXFSNP_HEADER *)safe_malloc(fsize, LOC_CXFSNP_0016);
    if(NULL_PTR == cxfsnp_header)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_header_new: new header with %ld bytes for np %u fd %d failed\n",
                           fsize, np_id, fd);
        return (NULL_PTR);
    }

    CXFSNP_HEADER_NP_ID(cxfsnp_header)  = np_id;
    CXFSNP_HEADER_MODEL(cxfsnp_header)  = np_model;

    cxfsnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CXFSNP_ITEM);

    /*init RB Nodes*/
    cxfsnprb_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

    /*init QUE nodes*/
    cxfsnpque_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cxfsnpdel_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

    /*init key table*/
    cxfsnpkey_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

#if (SWITCH_ON == CXFSNP_ATTR_SWITCH)
    /*init attr table*/
    cxfsnpattr_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);
#endif/*(SWITCH_ON == CXFSNP_ATTR_SWITCH)*/

    return (cxfsnp_header);
}

STATIC_CAST static CXFSNP_HEADER *__cxfsnp_header_free(CXFSNP_HEADER *cxfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != cxfsnp_header)
    {
        UINT32 offset;

        offset = 0;
        if(
           ERR_FD != fd
        && EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)cxfsnp_header)
        )
        {
            dbg_log(SEC_0197_CXFSNP, 1)(LOGSTDOUT, "warn:__cxfsnp_header_free: flush cxfsnp_hdr of np %u fd %d with size %ld failed\n",
                               np_id, fd, fsize);
        }

        safe_free(cxfsnp_header, LOC_CXFSNP_0017);
    }

    /*cxfsnp_header cannot be accessed again*/
    return (NULL_PTR);
}

STATIC_CAST static CXFSNP_HEADER *__cxfsnp_header_clone(const CXFSNP_HEADER *src_cxfsnp_header, const uint32_t des_np_id, const UINT32 fsize, UINT8 *base)
{
    CXFSNP_HEADER *des_cxfsnp_header;

    des_cxfsnp_header = (CXFSNP_HEADER *)base;

    BCOPY(src_cxfsnp_header, des_cxfsnp_header, fsize);

    CXFSNP_HEADER_NP_ID(des_cxfsnp_header)  = des_np_id;

    return (des_cxfsnp_header);
}

EC_BOOL cxfsnp_header_init(CXFSNP_HEADER *cxfsnp_header, const uint32_t np_id, const uint8_t model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id)
{
    CXFSNP_HEADER_NP_ID(cxfsnp_header)         = np_id;
    CXFSNP_HEADER_MODEL(cxfsnp_header)         = model;

    CXFSNP_HEADER_2ND_CHASH_ALGO_ID(cxfsnp_header)  = second_chash_algo_id;

    /*do nothing on que list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CXFSNPRB_POOL pool*/

    return (EC_TRUE);
}

EC_BOOL cxfsnp_header_clean(CXFSNP_HEADER *cxfsnp_header)
{
    CXFSNP_HEADER_NP_ID(cxfsnp_header)              = CXFSNP_ERR_ID;
    CXFSNP_HEADER_MODEL(cxfsnp_header)              = CXFSNP_ERR_MODEL;

    CXFSNP_HEADER_2ND_CHASH_ALGO_ID(cxfsnp_header)  = CHASH_ERR_ALGO_ID;

    /*do nothing on que list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CXFSNPRB_POOL pool*/

    return (EC_TRUE);
}

CXFSNP_HEADER *cxfsnp_header_clone(CXFSNP_HEADER *src_cxfsnp_header, const uint32_t des_np_id, const UINT32 fsize, UINT8 *base)
{
    CXFSNP_HEADER *des_cxfsnp_header;

    des_cxfsnp_header = (CXFSNP_HEADER *)base;

    BCOPY(src_cxfsnp_header, des_cxfsnp_header, fsize);

    CXFSNP_HEADER_NP_ID(des_cxfsnp_header)  = des_np_id;

    return (des_cxfsnp_header);
}

CXFSNP_HEADER *cxfsnp_header_create(const uint32_t np_id, const uint8_t np_model, UINT8 *base)
{
    CXFSNP_HEADER  *cxfsnp_header;
    uint32_t        node_max_num;
    uint32_t        node_sizeof;

    cxfsnp_header = (CXFSNP_HEADER *)base;

    CXFSNP_HEADER_NP_ID(cxfsnp_header)  = np_id;
    CXFSNP_HEADER_MODEL(cxfsnp_header)  = np_model;

    node_max_num = 0;

    cxfsnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CXFSNP_ITEM);

    /*init RB Nodes*/
    cxfsnprb_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

    /*init QUE nodes*/
    cxfsnpque_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    cxfsnpdel_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

    /*init key table*/
    cxfsnpkey_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);

#if (SWITCH_ON == CXFSNP_ATTR_SWITCH)
    /*init attr table*/
    cxfsnpattr_pool_init(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header), node_max_num, node_sizeof);
#endif/*(SWITCH_ON == CXFSNP_ATTR_SWITCH)*/

    return (cxfsnp_header);
}

CXFSNP_HEADER *cxfsnp_header_close(CXFSNP_HEADER *cxfsnp_header)
{
    /*do nothing*/
    return (cxfsnp_header);
}

CXFSNP *cxfsnp_new()
{
    CXFSNP *cxfsnp;

    alloc_static_mem(MM_CXFSNP, &cxfsnp, LOC_CXFSNP_0018);
    if(NULL_PTR != cxfsnp)
    {
        cxfsnp_init(cxfsnp);
    }
    return (cxfsnp);
}

EC_BOOL cxfsnp_init(CXFSNP *cxfsnp)
{
    CXFSNP_READ_ONLY_FLAG(cxfsnp)  = BIT_FALSE;
    CXFSNP_OP_REPLAY_FLAG(cxfsnp)  = BIT_FALSE;

    CXFSNP_FSIZE(cxfsnp)           = 0;
    CXFSNP_DEL_SIZE(cxfsnp)        = 0;
    CXFSNP_RECYCLE_SIZE(cxfsnp)    = 0;
    CXFSNP_QUE_LIST(cxfsnp)        = NULL_PTR;
    CXFSNP_DEL_LIST(cxfsnp)        = NULL_PTR;

    CXFSNP_HDR(cxfsnp)             = NULL_PTR;
    CXFSNP_OP_MGR(cxfsnp)          = NULL_PTR;

    CXFSNP_2ND_CHASH_ALGO(cxfsnp)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cxfsnp_clean(CXFSNP *cxfsnp)
{
    CXFSNP_HDR(cxfsnp)             = NULL_PTR;
    CXFSNP_OP_MGR(cxfsnp)          = NULL_PTR;

    CXFSNP_READ_ONLY_FLAG(cxfsnp)  = BIT_FALSE;
    CXFSNP_OP_REPLAY_FLAG(cxfsnp)  = BIT_FALSE;
    CXFSNP_FSIZE(cxfsnp)           = 0;

    CXFSNP_DEL_SIZE(cxfsnp)        = 0;
    CXFSNP_RECYCLE_SIZE(cxfsnp)    = 0;

    CXFSNP_QUE_LIST(cxfsnp)        = NULL_PTR;
    CXFSNP_DEL_LIST(cxfsnp)        = NULL_PTR;
    CXFSNP_HDR(cxfsnp)             = NULL_PTR;

    CXFSNP_2ND_CHASH_ALGO(cxfsnp)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cxfsnp_free(CXFSNP *cxfsnp)
{
    if(NULL_PTR != cxfsnp)
    {
        cxfsnp_clean(cxfsnp);
        free_static_mem(MM_CXFSNP, cxfsnp, LOC_CXFSNP_0019);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_is_full(const CXFSNP *cxfsnp)
{
    CXFSNPRB_POOL *pool;

    pool = CXFSNP_ITEMS_POOL(cxfsnp);
    return cxfsnprb_pool_is_full(pool);
}

EC_BOOL cxfsnp_set_read_only(CXFSNP *cxfsnp)
{
    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_set_read_only: "
                                               "np is in read-only mode\n");
        return (EC_FALSE);
    }

    CXFSNP_READ_ONLY_FLAG(cxfsnp) = BIT_TRUE;

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_set_read_only: "
                                           "np set read-only done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_unset_read_only(CXFSNP *cxfsnp)
{
    if(BIT_FALSE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_unset_read_only: "
                                               "np is not in read-only mode\n");
        return (EC_FALSE);
    }

    CXFSNP_READ_ONLY_FLAG(cxfsnp) = BIT_FALSE;

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_unset_read_only: "
                                           "np unset read-only done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_is_read_only(CXFSNP *cxfsnp)
{
    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_set_op_replay(CXFSNP *cxfsnp)
{
    if(BIT_TRUE == CXFSNP_OP_REPLAY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_set_op_replay: "
                                               "np is in op-replay mode\n");
        return (EC_FALSE);
    }

    CXFSNP_OP_REPLAY_FLAG(cxfsnp) = BIT_TRUE;

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_set_op_replay: "
                                           "np set op-replay done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_unset_op_replay(CXFSNP *cxfsnp)
{
    if(BIT_FALSE == CXFSNP_OP_REPLAY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_unset_op_replay: "
                                               "np is not in op-replay mode\n");
        return (EC_FALSE);
    }

    CXFSNP_OP_REPLAY_FLAG(cxfsnp) = BIT_FALSE;

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_unset_op_replay: "
                                           "np unset op-replay done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_is_op_replay(CXFSNP *cxfsnp)
{
    if(BIT_TRUE == CXFSNP_OP_REPLAY_FLAG(cxfsnp))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_mount_op_mgr(CXFSNP *cxfsnp, CXFSOP_MGR *cxfsop_mgr)
{
    if(NULL_PTR != CXFSNP_OP_MGR(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_mount_op_mgr: "
                                               "op mgr exists\n");
        return (EC_FALSE);
    }

    CXFSNP_OP_MGR(cxfsnp) = cxfsop_mgr;

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mount_op_mgr: "
                                           "mount op mgr %p done\n",
                                           cxfsop_mgr);
    return (EC_TRUE);
}

EC_BOOL cxfsnp_umount_op_mgr(CXFSNP *cxfsnp)
{
    if(NULL_PTR == CXFSNP_OP_MGR(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_op_mgr: "
                                               "op mgr not exist\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_umount_op_mgr: "
                                           "umount op mgr %p done\n",
                                           CXFSNP_OP_MGR(cxfsnp));

    CXFSNP_OP_MGR(cxfsnp) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cxfsnp_que_list_is_empty(const CXFSNP *cxfsnp)
{
    return cxfsnpque_is_empty(CXFSNP_QUE_LIST(cxfsnp));
}

EC_BOOL cxfsnp_del_list_is_empty(const CXFSNP *cxfsnp)
{
    return cxfsnpdel_is_empty(CXFSNP_DEL_LIST(cxfsnp));
}

void cxfsnp_header_print(LOG *log, const CXFSNP *cxfsnp)
{
    const CXFSNP_HEADER *cxfsnp_header;

    cxfsnp_header = CXFSNP_HDR(cxfsnp);

    sys_log(log, "np %u, model %u, hash algo %u, item max num %u, item used num %u\n",
                CXFSNP_HEADER_NP_ID(cxfsnp_header),
                CXFSNP_HEADER_MODEL(cxfsnp_header),
                CXFSNP_HEADER_2ND_CHASH_ALGO_ID(cxfsnp_header),
                CXFSNP_HEADER_ITEMS_MAX_NUM(cxfsnp_header),
                CXFSNP_HEADER_ITEMS_USED_NUM(cxfsnp_header)
        );

    cxfsnprb_pool_print(log, CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header));
    return;
}

void cxfsnp_print(LOG *log, const CXFSNP *cxfsnp)
{
    sys_log(log, "cxfsnp %p: np %u, fsize %lu, del size %llu, recycle size %llu\n",
                 cxfsnp,
                 CXFSNP_ID(cxfsnp),
                 CXFSNP_FSIZE(cxfsnp),
                 CXFSNP_DEL_SIZE(cxfsnp),
                 CXFSNP_RECYCLE_SIZE(cxfsnp)
                 );

    sys_log(log, "cxfsnp %p: header: \n", cxfsnp);
    cxfsnp_header_print(log, cxfsnp);
    return;
}

void cxfsnp_print_que_list(LOG *log, const CXFSNP *cxfsnp)
{
    sys_log(log, "cxfsnp_print_que_list: cxfsnp %p: que list: \n", cxfsnp);
    cxfsnpque_list_print(log, cxfsnp);
    return;
}

void cxfsnp_print_del_list(LOG *log, const CXFSNP *cxfsnp)
{
    sys_log(log, "cxfsnp_print_del_list: cxfsnp %p: del list: \n", cxfsnp);
    cxfsnpdel_list_print(log, cxfsnp);
    return;
}

CXFSNP_ITEM *cxfsnp_dnode_find(const CXFSNP *cxfsnp, const CXFSNP_DNODE *cxfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key, const uint32_t dflag)
{
    const CXFSNPRB_POOL *pool;
    uint32_t root_pos;
    uint32_t node_pos;

    pool     = CXFSNP_ITEMS_POOL(cxfsnp);
    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);

    if(CXFSNP_KEY_MAX_SIZE < klen)/*overflow key*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(klen, key);
        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        node_pos = cxfsnprb_tree_search_data(pool, root_pos, second_hash, md5_len, md5_str, dflag);
    }
    else
    {
        node_pos = cxfsnprb_tree_search_data(pool, root_pos, second_hash, klen, key, dflag);
    }

    if(CXFSNPRB_ERR_POS != node_pos)
    {
        const CXFSNPRB_NODE *node;
        const CXFSNP_ITEM   *item;

        node = CXFSNPRB_POOL_NODE(pool, node_pos);
        item = CXFSNP_RB_NODE_ITEM(node);

        return (CXFSNP_ITEM *)(item);
    }

    return (NULL_PTR);
}

uint32_t cxfsnp_dnode_search(const CXFSNP *cxfsnp, const CXFSNP_DNODE *cxfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key, const uint32_t dflag)
{
    const CXFSNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CXFSNP_ITEMS_POOL(cxfsnp);
    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);

    if(CXFSNP_KEY_MAX_SIZE < klen)/*overflow key*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(klen, key);
        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        return cxfsnprb_tree_search_data(pool, root_pos, second_hash, md5_len, md5_str, dflag);
    }

    return cxfsnprb_tree_search_data(pool, root_pos, second_hash, klen, key, dflag);
}

uint32_t cxfsnp_dnode_match(CXFSNP *cxfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    const CXFSNPRB_POOL *pool;
    uint32_t             node_pos;

    pool     = CXFSNP_ITEMS_POOL(cxfsnp);
    node_pos = root_pos;

    if(CXFSNPRB_ERR_POS != node_pos)
    {
        const CXFSNPRB_NODE *node;
        uint32_t             node_pos_t;

        node = CXFSNPRB_POOL_NODE(pool, node_pos);

        node_pos_t = cxfsnp_match_no_lock(cxfsnp, node_pos, path_len, path, dflag);
        if(CXFSNPRB_ERR_POS != node_pos_t)
        {
            return (node_pos_t);
        }

        node_pos_t = cxfsnp_dnode_match(cxfsnp, CXFSNPRB_NODE_LEFT_POS(node), path_len, path, dflag);
        if(CXFSNPRB_ERR_POS != node_pos_t)
        {
            return (node_pos_t);
        }

        node_pos_t = cxfsnp_dnode_match(cxfsnp, CXFSNPRB_NODE_RIGHT_POS(node), path_len, path, dflag);
        if(CXFSNPRB_ERR_POS != node_pos_t)
        {
            return (node_pos_t);
        }
    }

    return (CXFSNPRB_ERR_POS);
}

uint32_t cxfsnp_dnode_insert(CXFSNP *cxfsnp, const uint32_t parent_pos,
                                    const uint32_t path_seg_second_hash,
                                    const uint32_t path_seg_len, const uint8_t *path_seg,
                                    const uint32_t dir_flag,
                                    uint32_t *node_pos)
{
    uint32_t insert_pos;
    uint32_t root_pos;

    CXFSNP_ITEM *cxfsnp_item_parent;
    CXFSNP_ITEM *cxfsnp_item_insert;

    CXFSNP_DNODE *cxfsnp_dnode_parent;

    ASSERT(NULL_PTR != node_pos);
    (*node_pos) = CXFSNPRB_ERR_POS;

    if(CXFSNP_ITEM_FILE_IS_REG != dir_flag
    && CXFSNP_ITEM_FILE_IS_DIR != dir_flag)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_dnode_insert: invalid input dir flag %x\n", dir_flag);
        return (EC_FALSE);
    }

    if(EC_TRUE == cxfsnp_is_full(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_dnode_insert: cxfsnp is full\n");
        return (EC_FALSE);
    }

    cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_pos);/*must be dnode*/
    if(NULL_PTR == cxfsnp_item_parent)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_dnode_insert: fetch parent item failed where parent offset %u\n", parent_pos);
        return (EC_FALSE);
    }

    cxfsnp_dnode_parent = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);
    if(CXFSNP_ITEM_FILE_IS_DIR != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_parent)
    || CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item_parent))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_dnode_insert: invalid dir flag %u or stat %u\n",
                            CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_parent),
                            CXFSNP_ITEM_USED_FLAG(cxfsnp_item_parent));
        return (EC_FALSE);
    }

    /*insert the item to parent and update parent*/
    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode_parent);

    //dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_dnode_insert: cxfsnp %p, header %p, pool %p\n", cxfsnp, CXFSNP_HDR(cxfsnp), CXFSNP_ITEMS_POOL(cxfsnp));

    if(CXFSNP_KEY_MAX_SIZE < path_seg_len)/*overflow path seg*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(path_seg_len, path_seg);
        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        if(EC_FALSE == cxfsnprb_tree_insert_data(CXFSNP_ITEMS_POOL(cxfsnp), &root_pos,
                                                 path_seg_second_hash,
                                                 md5_len, md5_str,
                                                 dir_flag,
                                                 &insert_pos))
        {
            dbg_log(SEC_0197_CXFSNP, 1)(LOGSTDOUT, "warn:cxfsnp_dnode_insert: found duplicate rb node with root %u at node %u\n", root_pos, insert_pos);
            (*node_pos) = insert_pos;
            return (EC_FALSE);
        }
        cxfsnp_item_insert = cxfsnp_fetch(cxfsnp, insert_pos);

        /*fill in cxfsnp_item_insert*/
        cxfsnp_item_set_key(cxfsnp_item_insert, md5_len, md5_str);
        CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_insert) = path_seg_second_hash;
        CXFSNP_ITEM_PARENT_POS(cxfsnp_item_insert)  = parent_pos;
    }
    else
    {
        if(EC_FALSE == cxfsnprb_tree_insert_data(CXFSNP_ITEMS_POOL(cxfsnp), &root_pos,
                                                 path_seg_second_hash,
                                                 path_seg_len, path_seg,
                                                 dir_flag,
                                                 &insert_pos))
        {
            dbg_log(SEC_0197_CXFSNP, 1)(LOGSTDOUT, "warn:cxfsnp_dnode_insert: found duplicate rb node with root %u at node %u\n", root_pos, insert_pos);
            (*node_pos) = insert_pos;
            return (EC_FALSE);
        }
        cxfsnp_item_insert = cxfsnp_fetch(cxfsnp, insert_pos);

        /*fill in cxfsnp_item_insert*/
        cxfsnp_item_set_key(cxfsnp_item_insert, path_seg_len, path_seg);
        CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_insert) = path_seg_second_hash;
        CXFSNP_ITEM_PARENT_POS(cxfsnp_item_insert)  = parent_pos;
    }

    if(CXFSNP_ITEM_FILE_IS_REG == dir_flag)
    {
        cxfsnp_fnode_init(CXFSNP_ITEM_FNODE(cxfsnp_item_insert));
        CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_insert) = CXFSNP_ITEM_FILE_IS_REG;
    }
    else if(CXFSNP_ITEM_FILE_IS_DIR == dir_flag)
    {
        cxfsnp_dnode_init(CXFSNP_ITEM_DNODE(cxfsnp_item_insert));
        CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_insert) = CXFSNP_ITEM_FILE_IS_DIR;

        if(SWITCH_ON == CXFSFUSE_SWITCH)
        {
            cxfsnp_attr_init(CXFSNP_ITEM_ATTR(cxfsnp_item_insert));
        }

        if(SWITCH_ON == CXFSFUSE_SWITCH)
        {
            CXFSNP_ATTR *cxfsnp_attr_parent;
            uint64_t     nsec;   /*seconds*/
            uint64_t     nanosec;/*nanosecond*/

            c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

            cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(CXFSNP_DNODE_ITEM(cxfsnp_dnode_parent));
            CXFSNP_ATTR_NLINK(cxfsnp_attr_parent) ++;

            CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr_parent)  = (uint64_t)nsec;
            CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr_parent)  = (uint64_t)nsec;
            CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr_parent) = (uint32_t)nanosec;
            CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr_parent) = (uint32_t)nanosec;
        }
    }

    CXFSNP_ITEM_USED_FLAG(cxfsnp_item_insert) = CXFSNP_ITEM_IS_USED;

    CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode_parent)   = root_pos;
    CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode_parent)  ++;

    (*node_pos) = insert_pos;

    return (EC_TRUE);
}

/**
* umount one son from cxfsnp_dnode,  where son is regular file item or dir item without any son
* cxfsnp_dnode will be impacted on bucket and file num
**/
uint32_t cxfsnp_dnode_umount_son(const CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, const uint32_t son_node_pos, const uint32_t second_hash, const uint32_t klen, const uint8_t *key, const uint32_t dflag)
{
    CXFSNPRB_POOL *pool;
    uint32_t       root_pos;
    uint32_t       node_pos;

    node_pos = cxfsnp_dnode_search(cxfsnp, cxfsnp_dnode, second_hash, klen, key, dflag);
    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (CXFSNPRB_ERR_POS);
    }

    if(node_pos == son_node_pos)
    {
        root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);

        pool = CXFSNP_ITEMS_POOL(cxfsnp);
        cxfsnprb_tree_erase(pool, node_pos, &root_pos); /*erase but not recycle node_pos ...*/

        CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode) = root_pos;
        CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode) --;

        if(SWITCH_ON == CXFSFUSE_SWITCH && CXFSNP_ITEM_FILE_IS_DIR == dflag)
        {
            CXFSNP_ATTR *cxfsnp_attr;
            uint64_t     nsec;   /*seconds*/
            uint64_t     nanosec;/*nanosecond*/

            c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

            cxfsnp_attr = CXFSNP_ITEM_ATTR(CXFSNP_DNODE_ITEM(cxfsnp_dnode));
            CXFSNP_ATTR_NLINK(cxfsnp_attr) --;

            CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
            CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        }
    }

    return (node_pos);
}

/*delete single item from dnode*/
STATIC_CAST static EC_BOOL __cxfsnp_dnode_delete_item(const CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, CXFSNP_ITEM *cxfsnp_item)
{
    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cxfsnp_item_clean(cxfsnp_item);
        CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode) --;
    }

    else if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cxfsnp_dnode_delete_dir_son(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item));/*recursively*/
        cxfsnp_item_clean(cxfsnp_item);
        CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode) --;

        if(SWITCH_ON == CXFSFUSE_SWITCH)
        {
            CXFSNP_ATTR *cxfsnp_attr;
            uint64_t     nsec;   /*seconds*/
            uint64_t     nanosec;/*nanosecond*/

            c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

            cxfsnp_attr = CXFSNP_ITEM_ATTR(CXFSNP_DNODE_ITEM(cxfsnp_dnode));
            CXFSNP_ATTR_NLINK(cxfsnp_attr) --;

            CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
            CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsnp_dnode_delete_all_items(const CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, const uint32_t node_pos)
{
    CXFSNPRB_POOL *pool;
    CXFSNPRB_NODE *node;
    CXFSNP_ITEM   *item;

    pool = CXFSNP_ITEMS_POOL(cxfsnp);

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        __cxfsnp_dnode_delete_all_items(cxfsnp, cxfsnp_dnode, CXFSNPRB_NODE_LEFT_POS(node));
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        __cxfsnp_dnode_delete_all_items(cxfsnp, cxfsnp_dnode, CXFSNPRB_NODE_RIGHT_POS(node));
    }

    item = CXFSNP_RB_NODE_ITEM(node);
    __cxfsnp_dnode_delete_item(cxfsnp, cxfsnp_dnode, item);

    /*cxfsnprb recycle the rbnode, do not use cxfsnprb_tree_delete which will change the tree structer*/
    cxfsnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

/*delete one dir son, not including cxfsnp_dnode itself*/
EC_BOOL cxfsnp_dnode_delete_dir_son(const CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode)
{
    uint32_t root_pos;

    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
    if(CXFSNPRB_ERR_POS != root_pos)
    {
        __cxfsnp_dnode_delete_all_items(cxfsnp, cxfsnp_dnode, root_pos);
        CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode) = CXFSNPRB_ERR_POS;
    }
    return (EC_TRUE);
}

uint32_t cxfsnp_match_no_lock(CXFSNP *cxfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;
    uint32_t path_seg_len;
    uint8_t *path_seg_beg;
    uint8_t *path_seg_end;

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_match_no_lock: np %u, invalid path '%.*s'\n",
                        CXFSNP_ID(cxfsnp), path_len, path);
        return (CXFSNPRB_ERR_POS);
    }

    node_pos = root_pos;/*the first item starting from*/

    if(CXFSNPRB_ROOT_POS == node_pos)
    {
        path_seg_beg = (uint8_t *)path;
        path_seg_len = 0;
        path_seg_end = (uint8_t *)(path_seg_beg + path_seg_len + 1);/*path always start with '/'*/
    }
    else
    {
        path_seg_beg = (uint8_t *)(path + 1);
        path_seg_len = cxfsnp_path_seg_len(path, path_len, path_seg_beg);
        path_seg_end = path_seg_beg + path_seg_len + 1;
    }

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, item pos %u [%.*s]\n", CXFSNP_ID(cxfsnp), node_pos, path_len, path);
    while(CXFSNPRB_ERR_POS != node_pos)
    {
        CXFSNP_ITEM *cxfsnp_item;

        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDNULL, "[DEBUG] cxfsnp_match_no_lock: np %u, node_pos %u, item pos %u\n",
                            CXFSNP_ID(cxfsnp), node_pos, (uint32_t)(node_pos / sizeof(CXFSNP_ITEM)));

        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
        if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_match_no_lock: np %u, item at node_pos %u was not used\n", CXFSNP_ID(cxfsnp), node_pos);
            return (CXFSNPRB_ERR_POS);
        }

        /*if path_seg is wildcard '*', matched. otherwise, check item key matched or not*/
        if(1 != path_seg_len || '*' != (char)(*path_seg_beg))
        {
            if(EC_FALSE == cxfsnp_item_is(cxfsnp_item, path_seg_len, path_seg_beg))
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_match_no_lock: np %u, check failed where path seg: %.*s [%u]\n",
                                    CXFSNP_ID(cxfsnp), path_seg_len, path_seg_beg, path_seg_len);
                return (CXFSNPRB_ERR_POS);
            }
            dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, check succ where path seg: '%.*s' [%u]\n",
                                CXFSNP_ID(cxfsnp), path_seg_len, path_seg_beg, path_seg_len);
        }

        /*when matched and reached the last path seg*/
        if(path_len <= (uint32_t)(path_seg_end - path))
        {
            dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] [target dflag %u] cxfsnp_match_no_lock: np %u, "
                                "matched and reached end where path_len %u, len from path to path_seg_end is %u, node_pos %u [%.*s]\n",
                                dflag, CXFSNP_ID(cxfsnp), path_len, (uint32_t)(path_seg_end - path), node_pos, path_len, path);

            if(dflag == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
            {
                rlog(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, return node_pos %u, target dflag %u, item dflag %u\n",
                                    CXFSNP_ID(cxfsnp), node_pos, dflag, CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
                return (node_pos);
            }

            return (CXFSNPRB_ERR_POS);
        }

        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))/*no more to search*/
        {
            rlog(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, return err_pos, target dflag %u, item dflag %u\n",
                                CXFSNP_ID(cxfsnp), dflag, CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
            return (CXFSNPRB_ERR_POS);
        }

        if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))/*search sons*/
        {
            rlog(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, item is dir\n",
                                CXFSNP_ID(cxfsnp));

            path_seg_beg = (uint8_t *)path_seg_end;
            path_seg_len = cxfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            if(1 == path_seg_len && '*' == (char)(*path_seg_beg))
            {
                rlog(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, [*] left path: '%.*s'\n",
                                    CXFSNP_ID(cxfsnp), path_len - (path_seg_beg - 1 - path), path_seg_beg - 1);

                node_pos = cxfsnp_dnode_match(cxfsnp, CXFSNP_DNODE_ROOT_POS(CXFSNP_ITEM_DNODE(cxfsnp_item)),
                                    path_len - (path_seg_beg - 1 - path), path_seg_beg - 1, dflag);

                rlog(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, [*] node_pos %u\n",
                                    CXFSNP_ID(cxfsnp), node_pos);

                return (node_pos);
            }
            else
            {
                uint32_t path_seg_2nd_hash;

                path_seg_2nd_hash = CXFSNP_2ND_CHASH_ALGO_COMPUTE(cxfsnp, path_seg_len, path_seg_beg);
                node_pos          = cxfsnp_dnode_search(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item),
                                                           path_seg_2nd_hash,
                                                           path_seg_len, path_seg_beg,
                                                           dflag);

                rlog(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, [searched] node_pos %u\n",
                                    CXFSNP_ID(cxfsnp), node_pos);
            }
            if(CXFSNPRB_ERR_POS == node_pos)/*Oops!*/
            {
                dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_match_no_lock: np %u, node_pos is err_pos, return\n",
                                    CXFSNP_ID(cxfsnp));
                return (CXFSNPRB_ERR_POS);
            }
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_match_no_lock_item: np %u, invalid item dir flag %u at node_pos %u\n",
                                CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), node_pos);
            break;
        }
    }

    return (CXFSNPRB_ERR_POS);
}

uint32_t cxfsnp_match(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    node_pos = cxfsnp_match_no_lock(cxfsnp, CXFSNPRB_ROOT_POS, path_len, path, dflag);

    return (node_pos);
}

uint32_t cxfsnp_search_no_lock(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;
    uint32_t path_seg_len;
    uint8_t *path_seg_beg;
    uint8_t *path_seg_end;

    path_seg_beg = (uint8_t *)path;
    path_seg_len = 0;
    path_seg_end = (uint8_t *)(path_seg_beg + path_seg_len + 1);/*path always start with '/'*/

    node_pos = 0;/*the first item is root directory*/
    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_search_no_lock: np %u, item pos %u [%.*s]\n",
                        CXFSNP_ID(cxfsnp), node_pos, path_len, path);
    while(CXFSNPRB_ERR_POS != node_pos)
    {
        CXFSNP_ITEM *cxfsnp_item;

        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDNULL, "[DEBUG] cxfsnp_search_no_lock: np %u, node_pos %u, item pos %u\n",
                            CXFSNP_ID(cxfsnp), node_pos, (uint32_t)(node_pos / sizeof(CXFSNP_ITEM)));

        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
        if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_search_no_lock: np %u, item at node_pos %u was not used\n", CXFSNP_ID(cxfsnp), node_pos);
            return (CXFSNPRB_ERR_POS);
        }

        /*check validity and consistence*/
        if(0 && EC_FALSE == cxfsnp_item_is(cxfsnp_item, path_seg_len, path_seg_beg))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_search_no_lock: np %u, check failed where path seg: %.*s\n",
                                CXFSNP_ID(cxfsnp), path_seg_len, path_seg_beg);
            return (CXFSNPRB_ERR_POS);
        }

        /*when matched and reached the last path seg*/
        if(path_len <= (uint32_t)(path_seg_end - path))
        {
            dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] [target dflag %u] cxfsnp_search_no_lock: np %u, "
                                "matched and reached end where path_len %u, len from path to path_seg_end is %u, node_pos %u [%.*s]\n",
                                dflag, CXFSNP_ID(cxfsnp), path_len, (uint32_t)(path_seg_end - path), node_pos, path_len, path);

            if(dflag == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
            {
                return (node_pos);
            }

            return (CXFSNPRB_ERR_POS);
        }

        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))/*no more to search*/
        {
            return (CXFSNPRB_ERR_POS);
        }

        if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))/*search sons*/
        {
            uint32_t path_seg_2nd_hash;

            path_seg_beg = (uint8_t *)path_seg_end;
            path_seg_len = cxfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            path_seg_2nd_hash = CXFSNP_2ND_CHASH_ALGO_COMPUTE(cxfsnp, path_seg_len, path_seg_beg);

            if(path_len <= (uint32_t)(path_seg_end - path)) /*last seg*/
            {
                node_pos = cxfsnp_dnode_search(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item),
                                               path_seg_2nd_hash,
                                               path_seg_len, path_seg_beg,
                                               dflag);
            }
            else /*not last seg*/
            {
                node_pos = cxfsnp_dnode_search(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item),
                                               path_seg_2nd_hash,
                                               path_seg_len, path_seg_beg,
                                               CXFSNP_ITEM_FILE_IS_DIR);
            }

            if(CXFSNPRB_ERR_POS == node_pos)/*Oops!*/
            {
                return (CXFSNPRB_ERR_POS);
            }
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_search_no_lock_item: np %u, invalid item dir flag %u at node_pos %u\n",
                                CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), node_pos);
            break;
        }
    }

    return (CXFSNPRB_ERR_POS);
}

uint32_t cxfsnp_search(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    node_pos = cxfsnp_search_no_lock(cxfsnp, path_len, path, dflag);

    return (node_pos);
}

uint32_t cxfsnp_insert_no_lock(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;
    uint32_t path_seg_len;
    uint8_t *path_seg_beg;
    uint8_t *path_seg_end;

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                            "np %u, invalid path %.*s\n",
                            CXFSNP_ID(cxfsnp), path_len, path);
        return (CXFSNPRB_ERR_POS);
    }

    path_seg_beg = (uint8_t *)path;
    path_seg_len = 0;
    path_seg_end = (uint8_t *)(path_seg_beg + path_seg_len + 1);/*path always start with '/'*/

    node_pos = 0;/*the first item is root directory*/
    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_insert_no_lock: "
                        "np %u, item pos %u [%.*s]\n",
                        CXFSNP_ID(cxfsnp), node_pos, path_len, path);
    while(CXFSNPRB_ERR_POS != node_pos)
    {
        CXFSNP_ITEM *cxfsnp_item;

        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDNULL, "[DEBUG] cxfsnp_insert_no_lock: "
                            "np %u, node_pos %u, item pos %u\n",
                            CXFSNP_ID(cxfsnp), node_pos, (uint32_t)(node_pos / sizeof(CXFSNP_ITEM)));

        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
        if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                                "np %u, item was not used at node_pos %u\n",
                                CXFSNP_ID(cxfsnp), node_pos);
            return (CXFSNPRB_ERR_POS);
        }

        /*check validity and consistence*/
        if(0 && EC_FALSE == cxfsnp_item_is(cxfsnp_item, path_seg_len, path_seg_beg))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                                "np %u, check failed where path seg: %.*s\n",
                                CXFSNP_ID(cxfsnp), path_seg_len, path_seg_beg);
            return (CXFSNPRB_ERR_POS);
        }

        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                                "np %u, find regular file has same key: %.*s at node_pos %u \n",
                                CXFSNP_ID(cxfsnp),
                                CXFSNP_ITEM_KLEN(cxfsnp_item), CXFSNP_ITEM_KNAME(cxfsnp_item),
                                node_pos);

            return (CXFSNPRB_ERR_POS);
        }

        if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))/*insert as son*/
        {
            uint32_t path_seg_2nd_hash;

            path_seg_beg = (uint8_t *)path_seg_end;
            path_seg_len = cxfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            /*
             * the 2nd hash compute path seg and result is set to CXFSNPRB_NODE_DATA
             * which would be compared in nprb tree searching.
             *
             * therefore, if one path seg len is more than 63B, its kname is its md5 value
             * and if the other path seg is equal to md5 value, its kname is same as md5 value,
             * they are not matched due to its CXFSNPRB_NODE_DATA is different.
             *
             * long-path-seg, kname = md5(long-path-seg), data = SecondHash(kname)
             * short-path-seg = md5(long-path-seg), kname = short-path-seg , data = SecondHash(kname)
             * => data is different
             *
             */
            path_seg_2nd_hash = CXFSNP_2ND_CHASH_ALGO_COMPUTE(cxfsnp, path_seg_len, path_seg_beg);

            if(path_len <= (uint32_t)(path_seg_end - path)) /*last seg*/
            {
                if(EC_TRUE == cxfsnp_dnode_insert(cxfsnp, node_pos,
                                           path_seg_2nd_hash, path_seg_len, path_seg_beg,
                                           dflag, &node_pos))
                {
                    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_insert_no_lock: "
                                        "np %u, insert [%.*s] done\n",
                                        CXFSNP_ID(cxfsnp), path_len, path);

                    return (node_pos);
                }

                /*else*/

                if(CXFSNPRB_ERR_POS != node_pos)
                {
                    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                                        "np %u, find duplicate key: %.*s\n",
                                        CXFSNP_ID(cxfsnp),
                                        path_seg_len, path_seg_beg);
                }

                if(CXFSNPRB_ERR_POS == node_pos)
                {
                    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                                        "np %u, insert key: %.*s failed\n",
                                        CXFSNP_ID(cxfsnp),
                                        path_seg_len, path_seg_beg);
                }

                return (CXFSNPRB_ERR_POS);
            }
            else /*not last seg*/
            {
                if(EC_TRUE == cxfsnp_dnode_insert(cxfsnp, node_pos,
                                          path_seg_2nd_hash, path_seg_len, path_seg_beg,
                                          CXFSNP_ITEM_FILE_IS_DIR, &node_pos))
                {
                    continue;
                }

                /*else*/

                if(CXFSNPRB_ERR_POS != node_pos)
                {
                    continue;
                }

                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                                    "np %u, insert dir key: %.*s failed\n",
                                    CXFSNP_ID(cxfsnp),
                                    path_seg_len, path_seg_beg);

                return (CXFSNPRB_ERR_POS);
            }
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert_no_lock: "
                                "np %u, invalid item dir flag %u at node_pos %u\n",
                                CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item),
                                node_pos);
            break;
        }
    }

    return (CXFSNPRB_ERR_POS);
}

uint32_t cxfsnp_insert(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_insert: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (CXFSNPRB_ERR_POS);
    }

    node_pos = cxfsnp_insert_no_lock(cxfsnp, path_len, path, dflag);

    return (node_pos);
}

CXFSNP_ITEM *cxfsnp_fetch(const CXFSNP *cxfsnp, const uint32_t node_pos)
{
    if(CXFSNPRB_ERR_POS != node_pos)
    {
        const CXFSNPRB_POOL *pool;
        const CXFSNPRB_NODE *node;

        pool = CXFSNP_ITEMS_POOL(cxfsnp);
        node = CXFSNPRB_POOL_NODE(pool, node_pos);
        if(NULL_PTR != node)
        {
            return (CXFSNP_ITEM *)CXFSNP_RB_NODE_ITEM(node);
        }
    }
    return (NULL_PTR);
}

EC_BOOL cxfsnp_inode_update(CXFSNP *cxfsnp, CXFSNP_INODE *cxfsnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(src_disk_no  == CXFSNP_INODE_DISK_NO(cxfsnp_inode)
    && src_block_no == CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)
    && src_page_no  == CXFSNP_INODE_PAGE_NO(cxfsnp_inode))
    {
        CXFSNP_INODE_DISK_NO(cxfsnp_inode)  = des_disk_no;
        CXFSNP_INODE_BLOCK_NO(cxfsnp_inode) = des_block_no;
        CXFSNP_INODE_PAGE_NO(cxfsnp_inode)  = des_page_no;
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_fnode_update(CXFSNP *cxfsnp, CXFSNP_FNODE *cxfsnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t replica;

    for(replica = 0; replica < CXFSNP_FNODE_REPNUM(cxfsnp_fnode); replica ++)
    {
        cxfsnp_inode_update(cxfsnp, CXFSNP_FNODE_INODE(cxfsnp_fnode, replica),
                            src_disk_no, src_block_no, src_page_no,
                            des_disk_no, des_block_no, des_page_no);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsnp_bucket_update(CXFSNP * cxfsnp, CXFSNPRB_POOL *pool, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CXFSNPRB_NODE *node;
    CXFSNP_ITEM   *item;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        __cxfsnp_bucket_update(cxfsnp, pool, CXFSNPRB_NODE_LEFT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    item = CXFSNP_RB_NODE_ITEM(node);

    cxfsnp_item_update(cxfsnp, item,
                       src_disk_no, src_block_no, src_page_no,
                       des_disk_no, des_block_no, des_page_no);


    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        __cxfsnp_bucket_update(cxfsnp, pool, CXFSNPRB_NODE_RIGHT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_bucket_update(CXFSNP *cxfsnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CXFSNPRB_POOL *pool;
    pool = CXFSNP_ITEMS_POOL(cxfsnp);

    return __cxfsnp_bucket_update(cxfsnp, pool, node_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);
}

EC_BOOL cxfsnp_dnode_update(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    uint32_t root_pos;

    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
    if(EC_FALSE == cxfsnp_bucket_update(cxfsnp, root_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_dnode_update: update root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_item_update(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_update: item was not used\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        return cxfsnp_fnode_update(cxfsnp, CXFSNP_ITEM_FNODE(cxfsnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        return cxfsnp_dnode_update(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_update: invalid item dflag %u\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
    return (EC_FALSE);
}

EC_BOOL cxfsnp_update_no_lock(CXFSNP *cxfsnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t offset;
    CXFSNP_ITEM *cxfsnp_item;

    offset = 0;/*the first item is root directory*/
    cxfsnp_item = cxfsnp_fetch(cxfsnp, offset);
    return cxfsnp_item_update(cxfsnp, cxfsnp_item,
                              src_disk_no, src_block_no, src_page_no,
                              des_disk_no, des_block_no, des_page_no);    /*recursively*/
}

STATIC_CAST static EC_BOOL __cxfsnp_bucket_expire(CXFSNP * cxfsnp, CXFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CXFSNPRB_NODE *node;
    CXFSNP_ITEM   *item;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        __cxfsnp_bucket_expire(cxfsnp, pool, CXFSNPRB_NODE_LEFT_POS(node));
    }

    item = CXFSNP_RB_NODE_ITEM(node);

    cxfsnp_item_expire(cxfsnp, item);


    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        __cxfsnp_bucket_expire(cxfsnp, pool, CXFSNPRB_NODE_RIGHT_POS(node));
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_bucket_expire(CXFSNP *cxfsnp, const uint32_t node_pos)
{
    CXFSNPRB_POOL *pool;
    pool = CXFSNP_ITEMS_POOL(cxfsnp);

    return __cxfsnp_bucket_expire(cxfsnp, pool, node_pos);
}

EC_BOOL cxfsnp_dnode_expire(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode)
{
    uint32_t root_pos;

    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
    if(EC_FALSE == cxfsnp_bucket_expire(cxfsnp, root_pos))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_dnode_expire: expire root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_item_expire(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item)
{
    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_expire: item was not used\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_expire: obsolete interface\n");
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        return cxfsnp_dnode_expire(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item));
    }

    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_expire: invalid item dflag %u\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfsnp_bucket_walk(CXFSNP * cxfsnp, CXFSNPRB_POOL *pool, const uint32_t node_pos, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    CXFSNPRB_NODE *node;
    CXFSNP_ITEM   *item;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        __cxfsnp_bucket_walk(cxfsnp, pool, CXFSNPRB_NODE_LEFT_POS(node), cxfsnp_dit_node);
    }

    item = CXFSNP_RB_NODE_ITEM(node);

    cxfsnp_item_walk(cxfsnp, item, node_pos, cxfsnp_dit_node);

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        __cxfsnp_bucket_walk(cxfsnp, pool, CXFSNPRB_NODE_RIGHT_POS(node), cxfsnp_dit_node);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_bucket_walk(CXFSNP *cxfsnp, const uint32_t node_pos, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    CXFSNPRB_POOL *pool;
    pool = CXFSNP_ITEMS_POOL(cxfsnp);

    return __cxfsnp_bucket_walk(cxfsnp, pool, node_pos, cxfsnp_dit_node);
}

EC_BOOL cxfsnp_dnode_walk(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    uint32_t root_pos;

    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
    if(EC_FALSE == cxfsnp_bucket_walk(cxfsnp, root_pos, cxfsnp_dit_node))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_dnode_walk: walk root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_item_walk(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_walk: item %u was not used\n", node_pos);
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cstack_push(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node), (void *)cxfsnp_item);
        CXFSNP_DIT_NODE_HANDLER(cxfsnp_dit_node)(cxfsnp_dit_node, cxfsnp, cxfsnp_item, node_pos);
        cstack_pop(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node));
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        EC_BOOL ret;

        cstack_push(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node), (void *)cxfsnp_item);
        CXFSNP_DIT_NODE_HANDLER(cxfsnp_dit_node)(cxfsnp_dit_node, cxfsnp, cxfsnp_item, node_pos);

        if(0 < CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node))
        {
            CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node) --;
            ret = cxfsnp_dnode_walk(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item), cxfsnp_dit_node);
            CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node) ++;
        }
        else
        {
            ret = EC_TRUE;
        }

        cstack_pop(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node));

        return (ret);
    }

    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_item_walk: invalid item dflag %u\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
    return (EC_FALSE);
}

CXFSNP_ITEM *cxfsnp_set(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t     node_pos;
    CXFSNP_ITEM *cxfsnp_item;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_set: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (NULL_PTR);
    }

    node_pos = cxfsnp_insert(cxfsnp, path_len, path, dflag);
    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    if(NULL_PTR != cxfsnp_item)
    {
        /*ensure only item of regular file enter QUE list*/
        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            cxfsnpque_node_add_head(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
        }

        return (cxfsnp_item);
    }
    return (NULL_PTR);
}

CXFSNP_ITEM *cxfsnp_get(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (NULL_PTR);
        }

        return cxfsnp_fetch(cxfsnp, cxfsnp_search(cxfsnp, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR));
    }
    return cxfsnp_fetch(cxfsnp, cxfsnp_search(cxfsnp, path_len, path, dflag));
}

EC_BOOL cxfsnp_delete(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    CXFSNP_ITEM *cxfsnp_item;
    uint32_t node_pos;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_delete: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_delete: np %u, invalid path %.*s\n", CXFSNP_ID(cxfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR);
        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    }
    else
    {
        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len, path, dflag);
        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    }

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM *cxfsnp_item_parent;
            uint32_t     node_pos_t;

            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, CXFSNP_ITEM_PARENT_POS(cxfsnp_item));
            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item_parent), node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                cxfsnprb_node_free(CXFSNP_ITEMS_POOL(cxfsnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_delete: np %u, path %.*s, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp), path_len, (char *)path,
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);

                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }
        }

        cxfsnp_item_clean(cxfsnp_item);

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM *cxfsnp_item_parent;
            uint32_t     node_pos_t;

            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item_parent), node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                cxfsnp_dnode_delete_dir_son(cxfsnp, CXFSNP_ITEM_DNODE(cxfsnp_item));

                cxfsnprb_node_free(CXFSNP_ITEMS_POOL(cxfsnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_delete: np %u, path %.*s, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp), path_len, (char *)path,
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);

                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }
        }

        cxfsnp_item_clean(cxfsnp_item);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_expire(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    CXFSNP_ITEM *cxfsnp_item;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_expire: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_expire: np %u, invalid path %.*s\n", CXFSNP_ID(cxfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (EC_FALSE);
        }

        cxfsnp_item = cxfsnp_fetch(cxfsnp, cxfsnp_search_no_lock(cxfsnp, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR));
    }
    else
    {
        cxfsnp_item = cxfsnp_fetch(cxfsnp, cxfsnp_search_no_lock(cxfsnp, path_len, path, dflag));
    }

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_item_expire(cxfsnp, cxfsnp_item))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

REAL cxfsnp_used_ratio(const CXFSNP *cxfsnp)
{
    const CXFSNP_HEADER *cxfsnp_header;
    REAL                 items_used_num;
    REAL                 items_max_num;

    cxfsnp_header = CXFSNP_HDR(cxfsnp);

    ASSERT(0 < CXFSNP_HEADER_ITEMS_MAX_NUM(cxfsnp_header));

    items_used_num = 0.0 + CXFSNP_HEADER_ITEMS_USED_NUM(cxfsnp_header);
    items_max_num  = 0.0 + CXFSNP_HEADER_ITEMS_MAX_NUM(cxfsnp_header);

    return (items_used_num) / (items_max_num);
}

EC_BOOL cxfsnp_retire(CXFSNP *cxfsnp, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CXFSNPQUE_NODE  *cxfsnpque_node_head;
    UINT32   retire_num;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_retire: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    cxfsnpque_node_head = CXFSNP_QUE_LIST(cxfsnp);

    for(retire_num = 0; retire_num < expect_retire_num && EC_FALSE == cxfsnp_que_list_is_empty(cxfsnp);)
    {
        uint32_t node_pos;

        CXFSNP_ITEM *cxfsnp_item;

        node_pos = CXFSNPQUE_NODE_PREV_POS(cxfsnpque_node_head);
        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

        ASSERT(EC_TRUE == cxfsnprb_node_is_used(CXFSNP_ITEMS_POOL(cxfsnp), node_pos));
        ASSERT(CXFSNP_ITEM_IS_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item));

        ASSERT(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            /*retire file*/
            if(EC_FALSE == cxfsnp_umount_item_deep(cxfsnp, node_pos))
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_retire: np %u node_pos %d [REG] failed\n",
                                CXFSNP_ID(cxfsnp), node_pos);
                return (EC_FALSE);
            }

            if(BIT_FALSE == CXFSNP_OP_REPLAY_FLAG(cxfsnp)
            && NULL_PTR != CXFSNP_OP_MGR(cxfsnp))
            {
                cxfsop_mgr_np_push_item_retire(CXFSNP_OP_MGR(cxfsnp), CXFSNP_ID(cxfsnp), node_pos);
            }

            dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_retire: np %u node_pos %d [REG] done\n",
                            CXFSNP_ID(cxfsnp), node_pos);
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

EC_BOOL cxfsnp_walk(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    CXFSNP_ITEM *cxfsnp_item;
    uint32_t     node_pos;

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_walk: np %u, invalid path %.*s\n", CXFSNP_ID(cxfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR);
        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    }
    else
    {
        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len, path, dflag);
        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    }

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_item_walk(cxfsnp, cxfsnp_item, node_pos, cxfsnp_dit_node))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*hide but not delete or recycle*/
EC_BOOL cxfsnp_hide_item(CXFSNP *cxfsnp, const uint32_t node_pos)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;

        cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);
        CXFSNP_DEL_SIZE(cxfsnp) += CXFSNP_FNODE_FILESZ(cxfsnp_fnode);

        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            //ASSERT(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_parent)); /*debug*/
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS;

                //cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
                //cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_hide_item: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS;
            }
        }

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            //ASSERT(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_parent)); /*debug*/
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS;

                ////cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
                //cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_hide_item: np %u, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS;
            }
        }
        else
        {
            ////cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
            //cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*delete and recycle later the hidden item*/
EC_BOOL cxfsnp_delete_hidden_item(CXFSNP *cxfsnp, const uint32_t node_pos)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

    ASSERT(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

    cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
    cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_umount_item(CXFSNP *cxfsnp, const uint32_t node_pos)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

#if 0
    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && 0 == CXFSNP_ITEM_KLEN(cxfsnp_item))
    {

        return (EC_TRUE);
    }
#endif

    if(0 == node_pos
    && CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && 0 == CXFSNP_ITEM_KLEN(cxfsnp_item))
    {
        const CXFSNPRB_POOL *pool;
        CXFSNP_DNODE        *cxfsnp_dnode;

        pool            = CXFSNP_ITEMS_POOL(cxfsnp);
        cxfsnp_dnode    = CXFSNP_ITEM_DNODE(cxfsnp_item);

        for(;;)
        {
            uint32_t         root_pos;
            uint32_t         first_node_pos;

            CXFSNP_ITEM     *cxfsnp_item_first;

            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_DNODE    *parent_dnode;
            uint32_t         parent_node_pos;
            uint32_t         node_pos_t;

            root_pos            = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
            if(CXFSNPRB_ERR_POS == root_pos)
            {
                break;
            }

            first_node_pos      = cxfsnprb_tree_first_node(pool, root_pos);
            cxfsnp_item_first   = cxfsnp_fetch(cxfsnp, first_node_pos);
            if(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first))
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item: np %u, root %u, first node %u => no parent\n",
                                    CXFSNP_ID(cxfsnp), root_pos, first_node_pos);
                break;
            }

            parent_node_pos     = CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first);

            cxfsnp_item_parent  = cxfsnp_fetch(cxfsnp, parent_node_pos);
            parent_dnode        = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t  = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, first_node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_first),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item_first),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item_first),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_first));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t);

            if(CXFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first) = CXFSNPRB_ERR_POS; /*fix*/

                cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item_first), first_node_pos);
                cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item_first), first_node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item: np %u, found inconsistency: [ANY] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                first_node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first), node_pos_t);

                CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first) = CXFSNPRB_ERR_POS; /*fix*/
                break; /*terminate loop*/
            }
        }

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;

        cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);
        CXFSNP_DEL_SIZE(cxfsnp) += CXFSNP_FNODE_FILESZ(cxfsnp_fnode);

        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            //ASSERT(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_parent)); /*debug*/
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/

                cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
                cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }
        }
        else
        {
            cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
            cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            //ASSERT(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_parent)); /*debug*/
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/

                //cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
                cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item: np %u, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }
        }
        else
        {
            //cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
            cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_umount_item_deep(CXFSNP *cxfsnp, const uint32_t node_pos)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }
#if 0
    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && 0 == CXFSNP_ITEM_KLEN(cxfsnp_item))
    {
        return (EC_TRUE);
    }
#endif

    if(0 == node_pos
    && CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && 0 == CXFSNP_ITEM_KLEN(cxfsnp_item))
    {
        const CXFSNPRB_POOL *pool;
        CXFSNP_DNODE        *cxfsnp_dnode;

        pool            = CXFSNP_ITEMS_POOL(cxfsnp);
        cxfsnp_dnode    = CXFSNP_ITEM_DNODE(cxfsnp_item);

        for(;;)
        {
            uint32_t         root_pos;
            uint32_t         first_node_pos;

            CXFSNP_ITEM     *cxfsnp_item_first;
            CXFSNP_ITEM     *cxfsnp_item_parent;
            CXFSNP_DNODE    *parent_dnode;
            uint32_t         parent_node_pos;
            uint32_t         node_pos_t;

            root_pos            = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
            if(CXFSNPRB_ERR_POS == root_pos)
            {
                break;
            }

            first_node_pos      = cxfsnprb_tree_first_node(pool, root_pos);
            cxfsnp_item_first   = cxfsnp_fetch(cxfsnp, first_node_pos);
            if(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first))
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item_deep: np %u, root %u, first node %u => no parent\n",
                                    CXFSNP_ID(cxfsnp), root_pos, first_node_pos);
                break;
            }

            parent_node_pos     = CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first);
            cxfsnp_item_parent  = cxfsnp_fetch(cxfsnp, parent_node_pos);
            parent_dnode        = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t  = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, first_node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item_first),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item_first),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item_first),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_first));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t);

            if(CXFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first) = CXFSNPRB_ERR_POS; /*fix*/

                cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item_first), first_node_pos);
                cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item_first), first_node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item_deep: np %u, found inconsistency: [ANY] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                first_node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first), node_pos_t);

                CXFSNP_ITEM_PARENT_POS(cxfsnp_item_first) = CXFSNPRB_ERR_POS; /*fix*/

                break; /*terminate loop*/
            }

             /* We now delete the root dir /, this branch means root dir / is already empty (this leads to the root_pos */
             /*   = CXFSNPRB_ERR_POS in next loop), so we can ignore it */
#if 0
            if(0 == CXFSNP_DNODE_FILE_NUM(parent_dnode))
            {
                /*recursively umount parent if it is empty directory*/
                return cxfsnp_umount_item_deep(cxfsnp, parent_node_pos);
            }
#endif
        }

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;

        cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);
        CXFSNP_DEL_SIZE(cxfsnp) += CXFSNP_FNODE_FILESZ(cxfsnp_fnode);

        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(SWITCH_ON == CXFSFUSE_SWITCH
            && CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ATTR *cxfsnp_attr_parent;
                uint64_t     nsec;   /*seconds*/
                uint64_t     nanosec;/*nanosecond*/

                c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

                cxfsnp_attr_parent = CXFSNP_ITEM_ATTR(cxfsnp_item_parent);

                CXFSNP_DNODE_FILE_SIZE(parent_dnode) -= (uint64_t)CXFSNP_FNODE_FILESZ(cxfsnp_fnode);

                CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr_parent)  = (uint64_t)nsec;
                CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr_parent)  = (uint64_t)nsec;
                CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr_parent) = (uint32_t)nanosec;
                CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr_parent) = (uint32_t)nanosec;
            }

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/

                cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
                cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item_deep: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);

                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }

            if(SWITCH_OFF == CXFSFUSE_SWITCH
            && 0 == CXFSNP_DNODE_FILE_NUM(parent_dnode))
            {
                /*recursively umount parent if it is empty directory*/
                return cxfsnp_umount_item_deep(cxfsnp, parent_node_pos);
            }
        }
        else
        {
            cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
            cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            //ASSERT(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/

                //cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
                cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_item_deep: np %u, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CXFSNP_ID(cxfsnp),
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);

                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }

            if(SWITCH_OFF == CXFSFUSE_SWITCH
            && 0 == CXFSNP_DNODE_FILE_NUM(parent_dnode))
            {
                /*recursively umount parent if it is empty directory*/
                return cxfsnp_umount_item_deep(cxfsnp, parent_node_pos);
            }
        }
        else
        {
            //cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
            cxfsnpdel_node_add_tail(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_umount(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount: np %u, invalid path %.*s\n", CXFSNP_ID(cxfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))/*directory*/
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR);
    }
    else/*regular file*/
    {
        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len, path, dflag);
    }

    if(EC_FALSE == cxfsnp_umount_item(cxfsnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_umount_deep(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_deep: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_deep: np %u, invalid path %.*s\n", CXFSNP_ID(cxfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))/*directory*/
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR);
    }
    else/*regular file*/
    {
        node_pos = cxfsnp_search_no_lock(cxfsnp, path_len, path, dflag);
    }

    /*note: use deep umount to recycle empty directory here*/
    if(EC_FALSE == cxfsnp_umount_item_deep(cxfsnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/* path has wildcard seg '*' */
EC_BOOL cxfsnp_umount_wildcard(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_wildcard: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_wildcard: np %u, invalid path %.*s\n", CXFSNP_ID(cxfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))/*directory*/
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = cxfsnp_match_no_lock(cxfsnp, CXFSNPRB_ROOT_POS, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR);
    }
    else/*regular file*/
    {
        node_pos = cxfsnp_match_no_lock(cxfsnp, CXFSNPRB_ROOT_POS, path_len, path, dflag);
    }

    if(EC_FALSE == cxfsnp_umount_item(cxfsnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_umount_wildcard_deep(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_wildcard_deep: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    if('/' != (*path))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_umount_wildcard_deep: np %u, invalid path %.*s\n", CXFSNP_ID(cxfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))/*directory*/
    {
        if(CXFSNP_ITEM_FILE_IS_DIR != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = cxfsnp_match_no_lock(cxfsnp, CXFSNPRB_ROOT_POS, path_len - 1, path, CXFSNP_ITEM_FILE_IS_DIR);
    }
    else/*regular file*/
    {
        node_pos = cxfsnp_match_no_lock(cxfsnp, CXFSNPRB_ROOT_POS, path_len, path, dflag);
    }

    /*note: use deep umount to recycle empty directory here*/
    if(EC_FALSE == cxfsnp_umount_item_deep(cxfsnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*umount but not remove*/
EC_BOOL cxfsnp_tear_item(CXFSNP *cxfsnp, const uint32_t node_pos)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

    if(0 == node_pos
    && CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && 0 == CXFSNP_ITEM_KLEN(cxfsnp_item))
    {
        /*do nothing*/
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;

        cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);

        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS;
                CXFSNP_DNODE_FILE_SIZE(parent_dnode) -= CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_tear_item: "
                                "found inconsistency: [REG] node %u, parent %u => %u\n",
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS;
            }
        }

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        if(CXFSNPRB_ERR_POS != CXFSNP_ITEM_PARENT_POS(cxfsnp_item))
        {
            CXFSNP_ITEM  *cxfsnp_item_parent;
            CXFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
            cxfsnp_item_parent = cxfsnp_fetch(cxfsnp, parent_node_pos);
            parent_dnode       = CXFSNP_ITEM_DNODE(cxfsnp_item_parent);

            node_pos_t    = cxfsnp_dnode_umount_son(cxfsnp, parent_dnode, node_pos,
                                                  CXFSNP_ITEM_SECOND_HASH(cxfsnp_item),
                                                  CXFSNP_ITEM_KLEN(cxfsnp_item),
                                                  CXFSNP_ITEM_KNAME(cxfsnp_item),
                                                  CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

            if(CXFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }
            else
            {
                dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_tear_item: "
                                "found inconsistency: [DIR] node %u, parent %u => %u\n",
                                node_pos, CXFSNP_ITEM_PARENT_POS(cxfsnp_item), node_pos_t);
                CXFSNP_ITEM_PARENT_POS(cxfsnp_item) = CXFSNPRB_ERR_POS; /*fix*/
            }
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_path_name(const CXFSNP *cxfsnp, const uint32_t node_pos, const uint32_t path_max_len, uint32_t *path_len, uint8_t *path)
{
    CSTACK   *cstack;
    uint32_t  cur_node_pos;
    uint32_t  cur_path_len;

    cstack = cstack_new(MM_IGNORE, LOC_CXFSNP_0020);

    cur_node_pos = node_pos;
    while(CXFSNPRB_ERR_POS != cur_node_pos)
    {
        CXFSNP_ITEM *cxfsnp_item;
        UINT32 cur_node_pos_t;

        cur_node_pos_t = cur_node_pos;
        cstack_push(cstack, (void *)cur_node_pos_t);

        cxfsnp_item = cxfsnp_fetch(cxfsnp, cur_node_pos);
        cur_node_pos = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
    }

    cur_path_len = 0;
    path[ 0 ] = '\0';

    while(EC_FALSE == cstack_is_empty(cstack) && cur_path_len < path_max_len)
    {
        CXFSNP_ITEM *cxfsnp_item;
        UINT32       cur_node_pos_t;

        cur_node_pos_t = (UINT32)cstack_pop(cstack);
        cur_node_pos   = (uint32_t)cur_node_pos_t;
        cxfsnp_item    = cxfsnp_fetch(cxfsnp, cur_node_pos);

        if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            cur_path_len += snprintf((char *)path + cur_path_len, path_max_len - cur_path_len, "%.*s/",
                                    CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            cur_path_len += snprintf((char *)path + cur_path_len, path_max_len - cur_path_len, "%.*s",
                                    CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_path_name: np %u, invalid dir flag %u at node %u\n",
                                CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), cur_node_pos);
        }
    }

    (*path_len) = cur_path_len;
    path[ cur_path_len ] = '\0';

    cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
    cstack_free(cstack, LOC_CXFSNP_0021);
    return (EC_TRUE);
}

EC_BOOL cxfsnp_path_name_cstr(const CXFSNP *cxfsnp, const uint32_t node_pos, CSTRING *path_cstr)
{
    CSTACK *cstack;
    uint32_t  cur_node_pos;

    cstack = cstack_new(MM_IGNORE, LOC_CXFSNP_0022);

    cur_node_pos = node_pos;
    while(CXFSNPRB_ERR_POS != cur_node_pos)
    {
        CXFSNP_ITEM *cxfsnp_item;

        cstack_push(cstack, (void *)(uintptr_t)cur_node_pos);

        cxfsnp_item  = cxfsnp_fetch(cxfsnp, cur_node_pos);
        cur_node_pos = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
    }

    while(EC_FALSE == cstack_is_empty(cstack))
    {
        CXFSNP_ITEM *cxfsnp_item;

        cur_node_pos = (uint32_t)(uintptr_t)cstack_pop(cstack);
        cxfsnp_item  = cxfsnp_fetch(cxfsnp, cur_node_pos);

        if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            cstring_format(path_cstr, "%.*s/", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            cstring_format(path_cstr, "%.*s", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_path_name_cstr: "
                                                   "np %u, invalid dir flag %u at node %u\n",
                                                   CXFSNP_ID(cxfsnp),
                                                   CXFSNP_ITEM_DIR_FLAG(cxfsnp_item),
                                                   cur_node_pos);
        }
    }

    cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
    cstack_free(cstack, LOC_CXFSNP_0023);
    return (EC_TRUE);
}

EC_BOOL cxfsnp_relative_path_name_cstr(const CXFSNP *cxfsnp, const uint32_t node_pos_src, const uint32_t node_pos_des, CSTRING *path_cstr)
{
    CSTACK   *cstack;
    uint32_t  node_pos_parent_src;
    uint32_t  node_pos_parent_des;
    uint32_t  node_pos_parent_tmp; /*convergence point*/

    cstack = cstack_new(MM_IGNORE, LOC_CXFSNP_0024);

    node_pos_parent_src = node_pos_src;
    node_pos_parent_des = node_pos_des;
    while(CXFSNPRB_ERR_POS != node_pos_parent_src)
    {
        CXFSNP_ITEM *cxfsnp_item_parent_src;

        while(CXFSNPRB_ERR_POS != node_pos_parent_des
        && node_pos_parent_src != node_pos_parent_des)
        {
            CXFSNP_ITEM *cxfsnp_item_parent_des;

            cxfsnp_item_parent_des = cxfsnp_fetch(cxfsnp, node_pos_parent_des);
            node_pos_parent_des    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item_parent_des);
        }

        if(node_pos_parent_src == node_pos_parent_des)
        {
            break;
        }

        node_pos_parent_des = node_pos_des;/*reset*/

        cxfsnp_item_parent_src = cxfsnp_fetch(cxfsnp, node_pos_parent_src);
        node_pos_parent_src    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item_parent_src);
    }

    if(node_pos_parent_src != node_pos_parent_des)
    {
        cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
        cstack_free(cstack, LOC_CXFSNP_0025);

        return (EC_FALSE);
    }

    node_pos_parent_tmp = node_pos_parent_src;

    node_pos_parent_des = node_pos_des;
    while(CXFSNPRB_ERR_POS != node_pos_parent_des
    && node_pos_parent_tmp != node_pos_parent_des)
    {
        CXFSNP_ITEM *cxfsnp_item_parent_des;

        cstack_push(cstack, (void *)(uintptr_t)node_pos_parent_des);

        cxfsnp_item_parent_des = cxfsnp_fetch(cxfsnp, node_pos_parent_des);
        node_pos_parent_des    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item_parent_des);
    }

    node_pos_parent_src = node_pos_src;
    while(CXFSNPRB_ERR_POS != node_pos_parent_src
    && node_pos_parent_tmp != node_pos_parent_src)
    {
        CXFSNP_ITEM *cxfsnp_item_parent_src;

        if(node_pos_parent_src != node_pos_src)/*skip src itself*/
        {
            cstack_push(cstack, (void *)(uintptr_t)CXFSNPRB_ERR_POS); /*mark*/
        }
        cxfsnp_item_parent_src = cxfsnp_fetch(cxfsnp, node_pos_parent_src);
        node_pos_parent_src    = CXFSNP_ITEM_PARENT_POS(cxfsnp_item_parent_src);
    }

    while(EC_FALSE == cstack_is_empty(cstack))
    {
        CXFSNP_ITEM *cxfsnp_item_cur;
        uint32_t     cur_node_pos;

        cur_node_pos     = (uint32_t)(uintptr_t)cstack_pop(cstack);
        cxfsnp_item_cur  = cxfsnp_fetch(cxfsnp, cur_node_pos);

        if(NULL_PTR == cxfsnp_item_cur)
        {
            cstring_format(path_cstr, "../");
        }
        else if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_cur))
        {
            cstring_format(path_cstr, "%.*s/", CXFSNP_ITEM_KLEN(cxfsnp_item_cur),
                                              (char *)CXFSNP_ITEM_KNAME(cxfsnp_item_cur));
        }
        else if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_cur))
        {
            cstring_format(path_cstr, "%.*s", CXFSNP_ITEM_KLEN(cxfsnp_item_cur),
                                             (char *)CXFSNP_ITEM_KNAME(cxfsnp_item_cur));
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_relative_path_name_cstr: "
                                                   "np %u, invalid dir flag %u at node %u\n",
                                                   CXFSNP_ID(cxfsnp),
                                                   CXFSNP_ITEM_DIR_FLAG(cxfsnp_item_cur),
                                                   cur_node_pos);
        }
    }

    cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
    cstack_free(cstack, LOC_CXFSNP_0026);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_path_seg_stack(const CXFSNP *cxfsnp, const uint32_t node_pos, CSTACK *cstack)
{
    if(NULL_PTR != cstack)
    {
        uint32_t  cur_node_pos;

        cur_node_pos = node_pos;
        while(CXFSNPRB_ERR_POS != cur_node_pos)
        {
            CXFSNP_ITEM *cxfsnp_item;

            cstack_push(cstack, (void *)(uintptr_t)cur_node_pos);

            cxfsnp_item  = cxfsnp_fetch(cxfsnp, cur_node_pos);
            cur_node_pos = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_path_seg_join(const CXFSNP *cxfsnp, CSTACK *cstack, CSTRING *path_cstr)
{
    while(EC_FALSE == cstack_is_empty(cstack))
    {
        CXFSNP_ITEM *cxfsnp_item;
        uint32_t     node_pos;

        node_pos     = (uint32_t)(uintptr_t)cstack_pop(cstack);
        cxfsnp_item  = cxfsnp_fetch(cxfsnp, node_pos);

        if(NULL_PTR == cxfsnp_item)
        {
            cstring_format(path_cstr, "../");
        }
        else if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            cstring_format(path_cstr, "%.*s/", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            cstring_format(path_cstr, "%.*s", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_path_seg_join: "
                                                   "np %u, invalid dir flag %u at pos %u\n",
                                                   CXFSNP_ID(cxfsnp),
                                                   CXFSNP_ITEM_DIR_FLAG(cxfsnp_item),
                                                   node_pos);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_seg_name(const CXFSNP *cxfsnp, const uint32_t offset, const uint32_t seg_name_max_len, uint32_t *seg_name_len, uint8_t *seg_name)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, offset);

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        (*seg_name_len) = snprintf((char *)seg_name, seg_name_max_len, "%.*s/",
                                CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        return (EC_TRUE);
    }
    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        (*seg_name_len) = snprintf((char *)seg_name, seg_name_max_len, "%.*s",
                                CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        return (EC_TRUE);
    }

    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_seg_name: np %u, invalid dir flag %u at offset %u\n",
                        CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), offset);
    return (EC_FALSE);
}

EC_BOOL cxfsnp_seg_name_cstr(const CXFSNP *cxfsnp, const uint32_t offset, CSTRING *seg_cstr)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, offset);
    if(NULL_PTR == cxfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cstring_format(seg_cstr, "%.*s/", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        return (EC_TRUE);
    }
    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cstring_format(seg_cstr, "%.*s", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        return (EC_TRUE);
    }

    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_seg_name_cstr: np %u, invalid dir flag %u at offset %u\n",
                        CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), offset);
    return (EC_FALSE);
}


STATIC_CAST static EC_BOOL __cxfsnp_list_path_vec(const CXFSNP *cxfsnp, const uint32_t node_pos, const uint8_t *prev_path_str, CVECTOR *path_cstr_vec)
{
    const CXFSNPRB_POOL *pool;
    const CXFSNPRB_NODE *node;
    CSTRING *full_path_cstr;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CXFSNP_ITEMS_POOL(cxfsnp);

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        __cxfsnp_list_path_vec(cxfsnp, CXFSNPRB_NODE_LEFT_POS(node), prev_path_str, path_cstr_vec);
    }

    full_path_cstr = cstring_new(prev_path_str, LOC_CXFSNP_0027);
    if(NULL_PTR == full_path_cstr)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_list_path_vec: np %u, new cstring from %s failed\n",
                            CXFSNP_ID(cxfsnp), prev_path_str);
        return (EC_FALSE);
    }

    cxfsnp_seg_name_cstr(cxfsnp, node_pos, full_path_cstr);

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_list_path_vec: np %u, node_pos son %u, %s\n",
                        CXFSNP_ID(cxfsnp), node_pos, (char *)cstring_get_str(full_path_cstr));

    if(CVECTOR_ERR_POS == cvector_search_front(path_cstr_vec, (void *)full_path_cstr, (CVECTOR_DATA_CMP)cstring_is_equal))
    {
        cvector_push(path_cstr_vec, (void *)full_path_cstr);
    }
    else
    {
        cstring_free(full_path_cstr);
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        __cxfsnp_list_path_vec(cxfsnp, CXFSNPRB_NODE_RIGHT_POS(node), prev_path_str, path_cstr_vec);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_list_path_vec(const CXFSNP *cxfsnp, const uint32_t node_pos, CVECTOR *path_cstr_vec)
{
    CXFSNP_ITEM *cxfsnp_item;
    CSTRING *path_cstr;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_list_path_vec: np %u, item is null at node_pos %u\n", CXFSNP_ID(cxfsnp), node_pos);
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && CXFSNP_ITEM_FILE_IS_DIR != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_list_path_vec: np %u, invalid dir flag %u at node_pos %u\n",
                            CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), node_pos);
        return (EC_FALSE);
    }

    path_cstr = cstring_new(NULL_PTR, LOC_CXFSNP_0028);
    if(NULL_PTR == path_cstr)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_list_path_vec: np %u, new path cstr failed\n", CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    cxfsnp_path_name_cstr(cxfsnp, node_pos, path_cstr);

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        if(CVECTOR_ERR_POS == cvector_search_front(path_cstr_vec, (void *)path_cstr, (CVECTOR_DATA_CMP)cstring_is_equal))
        {
            cvector_push(path_cstr_vec, (void *)path_cstr);
        }
        else
        {
            cstring_free(path_cstr);
        }

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_DNODE *cxfsnp_dnode;
        uint32_t son_node_pos;

        cxfsnp_dnode = (CXFSNP_DNODE *)CXFSNP_ITEM_DNODE(cxfsnp_item);

        son_node_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDNULL, "[DEBUG] cxfsnp_list_path_vec: np %u, node_pos son %u\n",
                            CXFSNP_ID(cxfsnp), son_node_pos);

        __cxfsnp_list_path_vec(cxfsnp, son_node_pos, cstring_get_str(path_cstr), path_cstr_vec);

        cstring_free(path_cstr);

        return (EC_TRUE);
    }

    /*never reach here*/
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfsnp_list_seg_vec(const CXFSNP *cxfsnp, const uint32_t node_pos, CVECTOR *path_cstr_vec)
{
    const CXFSNPRB_POOL *pool;
    const CXFSNPRB_NODE *node;
    CSTRING *seg_name_cstr;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CXFSNP_ITEMS_POOL(cxfsnp);

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        __cxfsnp_list_seg_vec(cxfsnp, CXFSNPRB_NODE_LEFT_POS(node), path_cstr_vec);
    }

    seg_name_cstr = cstring_new(NULL_PTR, LOC_CXFSNP_0029);
    if(NULL_PTR == seg_name_cstr)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_list_seg_vec: "
                            "np %u, new cstring failed\n",
                            CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    cxfsnp_seg_name_cstr(cxfsnp, node_pos, seg_name_cstr);

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_list_path_vec: "
                        "np %u, node_pos son %u\n",
                        CXFSNP_ID(cxfsnp), node_pos);

    if(CVECTOR_ERR_POS == cvector_search_front(path_cstr_vec, (void *)seg_name_cstr, (CVECTOR_DATA_CMP)cstring_is_equal))
    {
        cvector_push(path_cstr_vec, (void *)seg_name_cstr);
    }
    else
    {
        cstring_free(seg_name_cstr);
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        __cxfsnp_list_seg_vec(cxfsnp, CXFSNPRB_NODE_RIGHT_POS(node), path_cstr_vec);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_list_seg_vec(const CXFSNP *cxfsnp, const uint32_t node_pos, CVECTOR *seg_cstr_vec)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_list_seg_vec: np %u, item is null at node_pos %u\n",
                            CXFSNP_ID(cxfsnp), node_pos);
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && CXFSNP_ITEM_FILE_IS_DIR != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_list_seg_vec: np %u, invalid dir flag %u at node_pos %u\n",
                            CXFSNP_ID(cxfsnp), CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), node_pos);
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CSTRING *seg_name_cstr;

        seg_name_cstr = cstring_new(NULL_PTR, LOC_CXFSNP_0030);
        if(NULL_PTR == seg_name_cstr)
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_list_seg_vec: np %u, new seg str failed\n", CXFSNP_ID(cxfsnp));
            return (EC_FALSE);
        }

        cxfsnp_seg_name_cstr(cxfsnp, node_pos, seg_name_cstr);

        if(CVECTOR_ERR_POS == cvector_search_front(seg_cstr_vec, (void *)seg_name_cstr, (CVECTOR_DATA_CMP)cstring_is_equal))
        {
            cvector_push(seg_cstr_vec, (void *)seg_name_cstr);
        }
        else
        {
            cstring_free(seg_name_cstr);
        }
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_DNODE *cxfsnp_dnode;
        uint32_t son_node_pos;

        cxfsnp_dnode = (CXFSNP_DNODE *)CXFSNP_ITEM_DNODE(cxfsnp_item);

        son_node_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
        __cxfsnp_list_seg_vec(cxfsnp, son_node_pos, seg_cstr_vec);

        return (EC_TRUE);
    }

    /*never reach here*/
    return (EC_FALSE);
}

EC_BOOL cxfsnp_file_num(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_num)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_get(cxfsnp, path_len, path, CXFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR != cxfsnp_item)
    {
        (*file_num) = 1;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_get(cxfsnp, path_len, path, CXFSNP_ITEM_FILE_IS_DIR);
    if(NULL_PTR != cxfsnp_item)
    {
        CXFSNP_DNODE *cxfsnp_dnode;
        cxfsnp_dnode = CXFSNP_ITEM_DNODE(cxfsnp_item);

        (*file_num) = CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode);
        return (EC_TRUE);
    }

    (*file_num) = 0;
    return (EC_FALSE);
}

EC_BOOL cxfsnp_file_size(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path, uint64_t *file_size)
{
    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp_item = cxfsnp_get(cxfsnp, path_len, path, CXFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR != cxfsnp_item)
    {
        CXFSNP_FNODE *cxfsnp_fnode;
        cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);

        (*file_size) = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
        return (EC_TRUE);
    }

    (*file_size) = 0;
    return (EC_FALSE);
}

EC_BOOL cxfsnp_mkdirs(CXFSNP *cxfsnp, const uint32_t path_len, const uint8_t *path)
{
    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_mkdirs: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    if(CXFSNPRB_ERR_POS == cxfsnp_insert(cxfsnp, path_len, path, CXFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_mkdirs: mkdirs %.*s failed\n", path_len, (char *)path);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CXFSNP *cxfsnp_open(UINT8 *base, const UINT32 size, const uint32_t np_id)
{
    CXFSNP        *cxfsnp;
    CXFSNP_HEADER *cxfsnp_header;

    cxfsnp_header = (CXFSNP_HEADER *)(base);

    cxfsnp = cxfsnp_new();
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_open: new np%u failed\n", np_id);
        cxfsnp_header_close(cxfsnp_header );
        return (NULL_PTR);
    }

    CXFSNP_HDR(cxfsnp) = cxfsnp_header;

    /*shortcut*/
    CXFSNP_QUE_LIST(cxfsnp) = CXFSNP_ITEM_QUE_NODE(cxfsnp_fetch(cxfsnp, CXFSNPQUE_ROOT_POS));
    CXFSNP_DEL_LIST(cxfsnp) = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, CXFSNPDEL_ROOT_POS));

    CXFSNP_2ND_CHASH_ALGO(cxfsnp) = chash_algo_fetch(CXFSNP_HEADER_2ND_CHASH_ALGO_ID(cxfsnp_header));

    CXFSNP_FSIZE(cxfsnp) = size;

    ASSERT(np_id == CXFSNP_HEADER_NP_ID(cxfsnp_header));

    return (cxfsnp);
}

EC_BOOL cxfsnp_close(CXFSNP *cxfsnp)
{
    if(NULL_PTR != cxfsnp)
    {
        uint32_t np_id;

        np_id = CXFSNP_ID(cxfsnp); /*save np id info due to CXFSNP_HDR will be destoried immediately*/

        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_close: close np %u beg\n", np_id);
        if(NULL_PTR != CXFSNP_HDR(cxfsnp))
        {
            cxfsnp_header_close(CXFSNP_HDR(cxfsnp));

            CXFSNP_QUE_LIST(cxfsnp) = NULL_PTR;
            CXFSNP_DEL_LIST(cxfsnp) = NULL_PTR;
            CXFSNP_HDR(cxfsnp)      = NULL_PTR;
        }

        CXFSNP_FSIZE(cxfsnp) = 0;

        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_close: close np %u end\n", np_id);
        cxfsnp_free(cxfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_create_root_item(CXFSNP *cxfsnp)
{
    CXFSNP_ITEM *cxfsnp_item;
    uint32_t     second_hash;
    uint32_t     root_pos;
    uint32_t     insert_pos;
    uint32_t     klen;
    uint8_t      key[ 1 ];

    root_pos = CXFSNPRB_ERR_POS;
    second_hash = 0;
    klen = 0;
    key[0] = '\0';

    if(EC_FALSE == cxfsnprb_tree_insert_data(CXFSNP_ITEMS_POOL(cxfsnp), &root_pos,
                                             second_hash,
                                             klen, (uint8_t *)key,
                                             CXFSNP_ITEM_FILE_IS_DIR,
                                             &insert_pos))
    {
        dbg_log(SEC_0197_CXFSNP, 1)(LOGSTDOUT, "warn:cxfsnp_create_root_item: insert create item failed\n");
        return (EC_FALSE);
    }

    if(0 != insert_pos)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_create_root_item: insert root item at pos %u is not zero!\n", insert_pos);
        return (EC_FALSE);
    }

    if(0 != root_pos)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_create_root_item: root_pos %u is not zero!\n", root_pos);
        return (EC_FALSE);
    }

    cxfsnp_item = cxfsnp_fetch(cxfsnp, insert_pos);

    CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)         = CXFSNP_ITEM_FILE_IS_DIR;
    CXFSNP_ITEM_USED_FLAG(cxfsnp_item)        = CXFSNP_ITEM_IS_USED;
    CXFSNP_ITEM_KLEN(cxfsnp_item)             = (uint8_t)klen;
    CXFSNP_ITEM_PARENT_POS(cxfsnp_item)       = CXFSNPRB_ERR_POS;

    /******************************************************************************************************/
    /*when enable this branch, qlist can query root dir "/"; otherwise, qlist query it will return nothing*/
    /*if enable this branch, qlist "/" will run-through all np which is time-cost operation!!!            */
    /******************************************************************************************************/

    //CXFSNP_ITEM_KNAME(cxfsnp_item)[ 0 ] = '/';/*deprecated*/
    CXFSNP_ITEM_KNAME(cxfsnp_item)[ 0 ] = key[ 0 ];
    CXFSNP_ITEM_SECOND_HASH(cxfsnp_item) = second_hash;

    cxfsnp_dnode_init(CXFSNP_ITEM_DNODE(cxfsnp_item));

    if(SWITCH_ON == CXFSFUSE_SWITCH)
    {
        cxfsnp_attr_set_dir(CXFSNP_ITEM_ATTR(cxfsnp_item));
    }

    return (EC_TRUE);
}

CXFSNP *cxfsnp_clone(CXFSNP *src_cxfsnp, UINT8 *base, const uint32_t des_np_id)
{
    CXFSNP        *des_cxfsnp;
    CXFSNP_HEADER *src_cxfsnp_header;
    CXFSNP_HEADER *des_cxfsnp_header;
    UINT32         fsize;

    src_cxfsnp_header = CXFSNP_HDR(src_cxfsnp);
    fsize = CXFSNP_FSIZE(src_cxfsnp);

    /*clone*/
    des_cxfsnp_header = cxfsnp_header_clone(src_cxfsnp_header, des_np_id, fsize, base);
    if(NULL_PTR == des_cxfsnp_header)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_clone: clone np %u failed\n", des_np_id);
        return (NULL_PTR);
    }

    des_cxfsnp = cxfsnp_new();
    if(NULL_PTR == des_cxfsnp)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_clone: new np %u failed\n", des_np_id);
        cxfsnp_header_close(des_cxfsnp_header);
        return (NULL_PTR);
    }
    CXFSNP_HDR(des_cxfsnp) = des_cxfsnp_header;

    /*shortcut*/
    CXFSNP_QUE_LIST(des_cxfsnp) = CXFSNP_ITEM_QUE_NODE(cxfsnp_fetch(des_cxfsnp, CXFSNPQUE_ROOT_POS));
    CXFSNP_DEL_LIST(des_cxfsnp) = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(des_cxfsnp, CXFSNPDEL_ROOT_POS));

    CXFSNP_2ND_CHASH_ALGO(des_cxfsnp) = chash_algo_fetch(CXFSNP_HEADER_2ND_CHASH_ALGO_ID(des_cxfsnp_header));

    CXFSNP_READ_ONLY_FLAG(des_cxfsnp) = CXFSNP_READ_ONLY_FLAG(src_cxfsnp);

    CXFSNP_FSIZE(des_cxfsnp) = fsize;

    ASSERT(des_np_id == CXFSNP_HEADER_NP_ID(des_cxfsnp_header));

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_clone: clone np %u done\n", des_np_id);

    return (des_cxfsnp);
}

CXFSNP *cxfsnp_create(UINT8 *base, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id)
{
    CXFSNP         *cxfsnp;
    CXFSNP_HEADER  *cxfsnp_header;
    UINT32          fsize;

    //ASSERT(CXFSNP_ITEM_SIZEOF == sizeof(CXFSNP_HEADER));
    ASSERT(256 == ((unsigned long)(&(((CXFSNP_HEADER *)0)->pool.rb_nodes))));

    if(EC_FALSE == cxfsnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    cxfsnp_header = cxfsnp_header_create(np_id, np_model, base);
    if(NULL_PTR == cxfsnp_header)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_create: create np %u failed\n", np_id);
        return (NULL_PTR);
    }
    CXFSNP_HEADER_2ND_CHASH_ALGO_ID(cxfsnp_header) = hash_2nd_algo_id;

    cxfsnp = cxfsnp_new();
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_create: new np %u failed\n", np_id);
        cxfsnp_header_close(cxfsnp_header);
        return (NULL_PTR);
    }
    CXFSNP_HDR(cxfsnp) = cxfsnp_header;

    /*shortcut*/
    CXFSNP_QUE_LIST(cxfsnp) = CXFSNP_ITEM_QUE_NODE(cxfsnp_fetch(cxfsnp, CXFSNPQUE_ROOT_POS));
    CXFSNP_DEL_LIST(cxfsnp) = CXFSNP_ITEM_DEL_NODE(cxfsnp_fetch(cxfsnp, CXFSNPDEL_ROOT_POS));

    CXFSNP_2ND_CHASH_ALGO(cxfsnp) = chash_algo_fetch(CXFSNP_HEADER_2ND_CHASH_ALGO_ID(cxfsnp_header));

    CXFSNP_FSIZE(cxfsnp) = fsize;

    ASSERT(np_id == CXFSNP_HEADER_NP_ID(cxfsnp_header));

    /*create root item*/
    cxfsnp_create_root_item(cxfsnp);

    dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_create: create np %u done\n", np_id);

    return (cxfsnp);
}

STATIC_CAST static EC_BOOL __cxfsnp_get_item_full_path(const CXFSNP *cxfsnp, const uint32_t node_pos, uint8_t **full_path, uint32_t *dflag)
{
    uint8_t *path;
    uint32_t path_len;
    uint32_t path_max_len;
    CSTACK  *cstack;

    CXFSNP_ITEM  *cxfsnp_item;
    uint32_t      cur_node_pos;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    path = safe_malloc(CXFSNP_PATH_MAX_LEN, LOC_CXFSNP_0031);
    if(NULL_PTR == path)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_get_item_full_path: malloc %u bytes failed\n", CXFSNP_PATH_MAX_LEN);
        return (EC_FALSE);
    }

    cstack = cstack_new(MM_IGNORE, LOC_CXFSNP_0032);
    if(NULL_PTR == cstack)
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_get_item_full_path: new cstack failed\n");
        safe_free(path, LOC_CXFSNP_0033);
        return (EC_FALSE);
    }
    cur_node_pos = node_pos;

    while(CXFSNPRB_ERR_POS != cur_node_pos)
    {
        UINT32 cur_node_pos_t;

        cur_node_pos_t = cur_node_pos;
        cstack_push(cstack, (void *)cur_node_pos_t);
        cxfsnp_item  = cxfsnp_fetch(cxfsnp, cur_node_pos);
        cur_node_pos = CXFSNP_ITEM_PARENT_POS(cxfsnp_item);
    }

    path[ 0 ] = '\0';
    path_len = 0;
    path_max_len = CXFSNP_PATH_MAX_LEN;

    while(EC_FALSE == cstack_is_empty(cstack))
    {
        UINT32 cur_node_pos_t;
        cur_node_pos_t = (UINT32)cstack_pop(cstack);
        cur_node_pos   = (uint32_t)cur_node_pos_t;
        cxfsnp_item    = cxfsnp_fetch(cxfsnp, cur_node_pos);

        if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            path_len += snprintf((char *)path + path_len, path_max_len - path_len, "%.*s/", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            path_len += snprintf((char *)path + path_len, path_max_len - path_len, "%.*s", CXFSNP_ITEM_KLEN(cxfsnp_item), (char *)CXFSNP_ITEM_KNAME(cxfsnp_item));
        }
        else
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_get_item_full_path: invalid dir flag %u at node_pos %u\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), cur_node_pos);
        }
        if(path_len >= path_max_len)
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_get_item_full_path: path overflow\n");
        }
        //sys_print(log, "%s [klen %u, node_pos %u]\n", (char *)path, CXFSNP_ITEM_KLEN(cxfsnp_item), node_pos);
    }

    cstack_free(cstack, LOC_CXFSNP_0034);

    if(path_len >= path_max_len)
    {
        path[path_max_len - 1] = '\0';
        path[path_max_len - 2] = '.';
        path[path_max_len - 3] = '.';
        path[path_max_len - 4] = '.';
    }
    else
    {
        path[path_len] = '\0';
    }

    cxfsnp_item = cxfsnp_fetch(cxfsnp, cur_node_pos);

    if(NULL_PTR != dflag)
    {
        (*dflag) = CXFSNP_ITEM_DIR_FLAG(cxfsnp_item);
    }

    (*full_path) = path;

    return (EC_TRUE);
}

EC_BOOL cxfsnp_show_item_full_path(LOG *log, const CXFSNP *cxfsnp, const uint32_t node_pos)
{
    uint8_t  *path;
    uint32_t  dflag;

    if(EC_FALSE == __cxfsnp_get_item_full_path(cxfsnp, node_pos, &path, &dflag))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_show_item_full_path: get item %u full path failed\n", node_pos);
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        sys_log(log, "dir : %s\n", path);
    }
    else if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        sys_log(log, "file: %s\n", path);
    }
    else
    {
        sys_log(log, "err: %s\n", path);
    }

    safe_free(path, LOC_CXFSNP_0035);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsnp_show_item(LOG *log, const CXFSNP *cxfsnp, const uint32_t node_pos)
{
    //const CXFSNPRB_POOL *pool;
    const CXFSNP_ITEM   *cxfsnp_item;
    //const CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    //pool = CXFSNP_ITEMS_POOL(cxfsnp);

    //node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    /*itself*/
    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_show_item: item not used\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && CXFSNP_ITEM_FILE_IS_REG != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        sys_log(log, "error:__cxfsnp_show_item: invalid dir flag %u\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
        return (EC_FALSE);
    }

    cxfsnp_show_item_full_path(log, cxfsnp, node_pos);

    /*do not show subdirectories*/
    return (EC_TRUE);
}

EC_BOOL cxfsnp_show_item(LOG *log, const CXFSNP *cxfsnp, const uint32_t node_pos)
{
    //const CXFSNPRB_POOL *pool;
    const CXFSNP_ITEM   *cxfsnp_item;
    //const CXFSNPRB_NODE *node;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    //pool = CXFSNP_ITEMS_POOL(cxfsnp);

    //node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    /*itself*/
    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_show_item: item not used\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && CXFSNP_ITEM_FILE_IS_REG != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        sys_log(log, "error:cxfsnp_show_item: invalid dir flag %u\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
        return (EC_FALSE);
    }

    cxfsnp_show_item_full_path(log, cxfsnp, node_pos);

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cxfsnp_show_dir(log, cxfsnp, cxfsnp_item);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_show_dir(LOG *log, const CXFSNP *cxfsnp, const CXFSNP_ITEM  *cxfsnp_item)
{
    CXFSNP_DNODE *cxfsnp_dnode;
    uint32_t root_pos;

    cxfsnp_dnode = (CXFSNP_DNODE *)CXFSNP_ITEM_DNODE(cxfsnp_item);
    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
    cxfsnp_show_item_full_path(log, cxfsnp, root_pos);


    return (EC_TRUE);
}


/*------------------------------------------------ recycle -----------------------------------------*/
/*recycle dn only!*/
EC_BOOL cxfsnp_recycle_item_file(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn)
{
    CXFSNP_FNODE *cxfsnp_fnode;

    cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);
    if(EC_FALSE == CXFSNP_RECYCLE_DN_FUNC(cxfsnp_recycle_dn)(CXFSNP_RECYCLE_DN_ARG1(cxfsnp_recycle_dn), cxfsnp_fnode))
    {
        CXFSNP_INODE *cxfsnp_inode;

        cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_recycle_item_file: recycle dn (disk %u, block %u, page %u, size %u) failed\n",
                            CXFSNP_INODE_DISK_NO(cxfsnp_inode),
                            CXFSNP_INODE_BLOCK_NO(cxfsnp_inode),
                            CXFSNP_INODE_PAGE_NO(cxfsnp_inode),
                            CXFSNP_FNODE_FILESZ(cxfsnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR != cxfsnp_recycle_np)
    {
        CXFSNP_RECYCLE_NP_FUNC(cxfsnp_recycle_np)(CXFSNP_RECYCLE_NP_ARG1(cxfsnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_recycle_dnode_item(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn)
{
    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cxfsnp_recycle_item_file(cxfsnp, cxfsnp_item, node_pos, cxfsnp_recycle_np, cxfsnp_recycle_dn);
        CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode) --;

        /*this file is under a deleted directory in deep. it may be still in QUE list.*/
        cxfsnpque_node_rmv(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);

        cxfsnp_item_clean(cxfsnp_item);
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cxfsnp_recycle_item_dir(cxfsnp, cxfsnp_item, node_pos, cxfsnp_recycle_np, cxfsnp_recycle_dn);/*recursively*/
        CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode) --;

        if(SWITCH_ON == CXFSFUSE_SWITCH)
        {
            CXFSNP_ATTR *cxfsnp_attr;
            uint64_t     nsec;   /*seconds*/
            uint64_t     nanosec;/*nanosecond*/

            c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

            cxfsnp_attr = CXFSNP_ITEM_ATTR(CXFSNP_DNODE_ITEM(cxfsnp_dnode));
            CXFSNP_ATTR_NLINK(cxfsnp_attr) --;

            CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
            CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
            CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        }

        cxfsnp_item_clean(cxfsnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:__cxfsnp_recycle_dnode_item: invalid dflag 0x%x\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
    return (EC_FALSE);
}

EC_BOOL cxfsnp_recycle_dnode(CXFSNP *cxfsnp, CXFSNP_DNODE *cxfsnp_dnode, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn)
{
    CXFSNPRB_POOL *pool;
    CXFSNPRB_NODE *node;
    CXFSNP_ITEM   *item;

    pool = CXFSNP_ITEMS_POOL(cxfsnp);

    node  = CXFSNPRB_POOL_NODE(pool, node_pos);
    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_LEFT_POS(node))
    {
        cxfsnp_recycle_dnode(cxfsnp, cxfsnp_dnode, CXFSNPRB_NODE_LEFT_POS(node), cxfsnp_recycle_np, cxfsnp_recycle_dn);
    }

    if(CXFSNPRB_ERR_POS != CXFSNPRB_NODE_RIGHT_POS(node))
    {
        cxfsnp_recycle_dnode(cxfsnp, cxfsnp_dnode, CXFSNPRB_NODE_RIGHT_POS(node), cxfsnp_recycle_np, cxfsnp_recycle_dn);
    }

    item = CXFSNP_RB_NODE_ITEM(node);
    cxfsnp_recycle_dnode_item(cxfsnp, cxfsnp_dnode, item, node_pos, cxfsnp_recycle_np, cxfsnp_recycle_dn);

    /*cxfsnprb recycle the rbnode, do not use cxfsnprb_tree_delete which will change the tree structer*/
    cxfsnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_recycle_item_dir(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn)
{
    CXFSNP_DNODE *cxfsnp_dnode;
    uint32_t root_pos;

    cxfsnp_dnode = CXFSNP_ITEM_DNODE(cxfsnp_item);

    root_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
    if(CXFSNPRB_ERR_POS != root_pos)
    {
        cxfsnp_recycle_dnode(cxfsnp, cxfsnp_dnode, root_pos, cxfsnp_recycle_np, cxfsnp_recycle_dn);
        CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode) = CXFSNPRB_ERR_POS;
    }

    if(NULL_PTR != cxfsnp_recycle_np)
    {
        CXFSNP_RECYCLE_NP_FUNC(cxfsnp_recycle_np)(CXFSNP_RECYCLE_NP_ARG1(cxfsnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

/*note: this interface is for that cxfsnp_item had umounted from parent, not need to update parent info*/
EC_BOOL cxfsnp_recycle_item(CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn)
{
    if(SWITCH_ON == CXFSFUSE_SWITCH
    && CXFSNP_ATTR_LINK_HARD_TAIL == CXFSNP_ATTR_LINK_FLAG(CXFSNP_ITEM_ATTR(cxfsnp_item)))
    {
        if(CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(CXFSNP_ITEM_ATTR(cxfsnp_item))
        && 0 < CXFSNP_ATTR_NLINK(CXFSNP_ITEM_ATTR(cxfsnp_item)))
        {
            ASSERT(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

            /*keep unchanged*/
            return (EC_TRUE);
        }

        if(CXFSNP_ATTR_NOT_HIDE == CXFSNP_ATTR_HIDE_FLAG(CXFSNP_ITEM_ATTR(cxfsnp_item))
        && 1 < CXFSNP_ATTR_NLINK(CXFSNP_ITEM_ATTR(cxfsnp_item)))
        {
            /*keep unchanged*/
            return (EC_TRUE);
        }
    }

    if(SWITCH_ON == CXFSFUSE_SWITCH
    && CXFSNP_ATTR_LINK_HARD_MID == CXFSNP_ATTR_LINK_FLAG(CXFSNP_ITEM_ATTR(cxfsnp_item)))
    {
        CXFSNP_ATTR     *cxfsnp_attr;

        CXFSNP_ITEM     *cxfsnp_item_link;
        CXFSNP_ATTR     *cxfsnp_attr_link;
        uint64_t         ino_link;
        uint32_t         node_pos_link;

        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        cxfsnp_item_link = cxfsnp_item;
        cxfsnp_attr_link = cxfsnp_attr;

        ino_link      = CXFSNP_ATTR_ERR_INO;
        node_pos_link = CXFSNPRB_ERR_POS;

        while(CXFSNP_ATTR_ERR_INO != CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_link))
        {
            ino_link         = CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_link);
            node_pos_link    = CXFSNP_ATTR_INO_FETCH_NODE_POS(ino_link);

            ASSERT(CXFSNP_ATTR_INO_FETCH_NP_ID(ino_link) == CXFSNP_ID(cxfsnp));

            cxfsnp_item_link = cxfsnp_fetch(cxfsnp, node_pos_link);
            cxfsnp_attr_link = CXFSNP_ITEM_ATTR(cxfsnp_item_link);
        }

        CXFSNP_ATTR_NEXT_INO(cxfsnp_attr) = CXFSNP_ATTR_ERR_INO; /*break hard link*/

        if(CXFSNP_ATTR_ERR_INO != ino_link
        && CXFSNPRB_ERR_POS != node_pos_link)
        {
            CXFSNP_ATTR_NLINK(cxfsnp_attr_link) --;

            if(0 == CXFSNP_ATTR_NLINK(cxfsnp_attr_link))
            {
                ASSERT(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item_link));
                ASSERT(CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_link));

                cxfsnp_delete_hidden_item(cxfsnp, node_pos_link);
                dbg_log(SEC_0197_CXFSNP, 1)(LOGSTDOUT, "[DEBUG] cxfsnp_recycle_item: "
                                                       "delete hide hard link item %lu\n",
                                                       ino_link);
            }
        }
    }

    if(SWITCH_ON == CXFSFUSE_SWITCH
    && CXFSNP_ATTR_LINK_SOFT == CXFSNP_ATTR_LINK_FLAG(CXFSNP_ITEM_ATTR(cxfsnp_item)))
    {
        CXFSNP_ATTR     *cxfsnp_attr;

        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        if(CXFSNP_ATTR_ERR_INO != CXFSNP_ATTR_NEXT_INO(CXFSNP_ITEM_ATTR(cxfsnp_item))) /*soft link middle*/
        {
            CXFSNP_ITEM     *cxfsnp_item_link;
            CXFSNP_ATTR     *cxfsnp_attr_link;
            uint64_t         ino_link;
            uint32_t         node_pos_link;

            cxfsnp_item_link = cxfsnp_item;
            cxfsnp_attr_link = cxfsnp_attr;

            ino_link         = CXFSNP_ATTR_NEXT_INO(cxfsnp_attr_link);
            node_pos_link    = CXFSNP_ATTR_INO_FETCH_NODE_POS(ino_link);

            ASSERT(CXFSNP_ATTR_INO_FETCH_NP_ID(ino_link) == CXFSNP_ID(cxfsnp));

            cxfsnp_item_link = cxfsnp_fetch(cxfsnp, node_pos_link);
            cxfsnp_attr_link = CXFSNP_ITEM_ATTR(cxfsnp_item_link);

            CXFSNP_ATTR_NEXT_INO(cxfsnp_attr) = CXFSNP_ATTR_ERR_INO; /*break soft link*/

            CXFSNP_ATTR_SLINK(cxfsnp_attr_link) --;

            if(0 == CXFSNP_ATTR_SLINK(cxfsnp_attr_link)
            && CXFSNP_ATTR_IS_HIDE == CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr_link))
            {
                ASSERT(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item_link));

                cxfsnp_delete_hidden_item(cxfsnp, node_pos_link);
                dbg_log(SEC_0197_CXFSNP, 1)(LOGSTDOUT, "[DEBUG] cxfsnp_recycle_item: "
                                                       "delete hide soft link item %lu\n",
                                                       ino_link);
            }

            if(0 < CXFSNP_ATTR_SLINK(cxfsnp_attr)) /*others are linking to it*/
            {
                CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr) = CXFSNP_ATTR_IS_HIDE;
                cxfsnp_hide_item(cxfsnp, node_pos);

                /*keep it*/
                return (EC_TRUE);
            }
        }
        else /*soft link tail*/
        {
            if(0 < CXFSNP_ATTR_SLINK(cxfsnp_attr)) /*others are linking to it*/
            {
                CXFSNP_ATTR_HIDE_FLAG(cxfsnp_attr) = CXFSNP_ATTR_IS_HIDE;
                cxfsnp_hide_item(cxfsnp, node_pos);

                /*keep unchanged*/
                return (EC_TRUE);
            }
        }
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;

        cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);

        if(EC_FALSE == cxfsnp_recycle_item_file(cxfsnp, cxfsnp_item, node_pos, cxfsnp_recycle_np, cxfsnp_recycle_dn))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_recycle_item: recycle regular file failed where cxfsnp_item is\n");
            cxfsnp_item_and_key_print(LOGSTDOUT, cxfsnp_item);

            /*should never reach here*/
            cxfsnp_item_clean(cxfsnp_item);

            return (EC_FALSE);
        }

        /*CXFSNP_DEL_SIZE(cxfsnp) -= CXFSNP_FNODE_FILESZ(cxfsnp_fnode);*/
        CXFSNP_RECYCLE_SIZE(cxfsnp) += CXFSNP_FNODE_FILESZ(cxfsnp_fnode);

        /*note: this file is in DEL list so that it must not be in QUE list*/

        cxfsnp_item_clean(cxfsnp_item);
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        cxfsnp_recycle_item_dir(cxfsnp, cxfsnp_item, node_pos, cxfsnp_recycle_np, cxfsnp_recycle_dn);/*recursively*/

        cxfsnp_item_clean(cxfsnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_recycle_item: invalid dflag 0x%x\n", CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

    /*should never reach here*/
    cxfsnp_item_clean(cxfsnp_item);

    return (EC_FALSE);
}

EC_BOOL cxfsnp_recycle(CXFSNP *cxfsnp, const UINT32 max_num, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn, UINT32 *complete_num)
{
    CXFSNPDEL_NODE  *cxfsnpdel_node_head;
    //CXFSNP_HEADER   *cxfsnp_header;

    uint32_t         left_num;

    if(BIT_TRUE == CXFSNP_READ_ONLY_FLAG(cxfsnp))
    {
        dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_recycle: np %u is read-only\n",
                                               CXFSNP_ID(cxfsnp));
        return (EC_FALSE);
    }

    cxfsnpdel_node_head = CXFSNP_DEL_LIST(cxfsnp);

    //cxfsnp_header = CXFSNP_HDR(cxfsnp);
    left_num = UINT32_TO_INT32(max_num);

    if(0 == left_num)
    {
        /*items never beyond the max value of uint32_t*/
        left_num = ((uint32_t)~0);
    }

    (*complete_num) = 0;
    while((0 < left_num --) && (EC_FALSE == cxfsnp_del_list_is_empty(cxfsnp)))
    {
        CXFSNP_ITEM   *cxfsnp_item;
        uint32_t       node_pos;

        node_pos = CXFSNPDEL_NODE_NEXT_POS(cxfsnpdel_node_head);

        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

        ASSERT(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

        if(EC_FALSE == cxfsnp_recycle_item(cxfsnp, cxfsnp_item, node_pos, cxfsnp_recycle_np, cxfsnp_recycle_dn))
        {
            dbg_log(SEC_0197_CXFSNP, 0)(LOGSTDOUT, "error:cxfsnp_recycle: recycle item %u # failed\n", node_pos);

            /*should never reach here*/
            cxfsnpdel_node_rmv(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);

            cxfsnprb_node_free(CXFSNP_ITEMS_POOL(cxfsnp), node_pos);/*recycle rb node(item node)*/
            return (EC_FALSE);
        }

        cxfsnpdel_node_rmv(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);

        cxfsnprb_node_free(CXFSNP_ITEMS_POOL(cxfsnp), node_pos);/*recycle rb node(item node)*/

        if(BIT_FALSE == CXFSNP_OP_REPLAY_FLAG(cxfsnp)
        && NULL_PTR != CXFSNP_OP_MGR(cxfsnp))
        {
            cxfsop_mgr_np_push_item_recycle(CXFSNP_OP_MGR(cxfsnp), CXFSNP_ID(cxfsnp), node_pos);
        }

        (*complete_num) ++;

        dbg_log(SEC_0197_CXFSNP, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_recycle: recycle item %u # done\n", node_pos);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

