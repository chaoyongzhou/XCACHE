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

#include "cpgrb.h"
#include "cpgb.h"
#include "crfsnprb.h"
#include "crfsnplru.h"
#include "crfsnpdel.h"
#include "crfsnp.h"
#include "crfsdt.h"
#include "crfsconhash.h"
#include "findex.inc"

static CRFSNP_CFG g_crfsnp_cfg_tbl[] = {
    {(const char *)"8M"  , (const char *)"CRFSNP_008M_MODEL", CRFSNP_008M_CFG_FILE_SIZE,  CRFSNP_008M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"16M" , (const char *)"CRFSNP_016M_MODEL", CRFSNP_016M_CFG_FILE_SIZE,  CRFSNP_016M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"32M" , (const char *)"CRFSNP_032M_MODEL", CRFSNP_032M_CFG_FILE_SIZE,  CRFSNP_032M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"64M" , (const char *)"CRFSNP_064M_MODEL", CRFSNP_064M_CFG_FILE_SIZE,  CRFSNP_064M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"128M", (const char *)"CRFSNP_128M_MODEL", CRFSNP_128M_CFG_FILE_SIZE,  CRFSNP_128M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"256M", (const char *)"CRFSNP_256M_MODEL", CRFSNP_256M_CFG_FILE_SIZE,  CRFSNP_256M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"512M", (const char *)"CRFSNP_512M_MODEL", CRFSNP_512M_CFG_FILE_SIZE,  CRFSNP_512M_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"1G"  , (const char *)"CRFSNP_001G_MODEL", CRFSNP_001G_CFG_FILE_SIZE,  CRFSNP_001G_CFG_ITEM_MAX_NUM, 0 },
    {(const char *)"2G"  , (const char *)"CRFSNP_002G_MODEL", CRFSNP_002G_CFG_FILE_SIZE,  CRFSNP_002G_CFG_ITEM_MAX_NUM, 0 },
#if (64 == WORDSIZE)
    {(const char *)"4G"  , (const char *)"CRFSNP_004G_MODEL", CRFSNP_004G_CFG_FILE_SIZE,  CRFSNP_004G_CFG_ITEM_MAX_NUM, 0 },
#endif/*(64 == WORDSIZE)*/
};

static uint8_t g_crfsnp_cfg_tbl_len = (uint8_t)(sizeof(g_crfsnp_cfg_tbl)/sizeof(g_crfsnp_cfg_tbl[0]));

STATIC_CAST static CRFSNPRB_NODE *__crfsnprb_node(CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    if(CRFSNPRB_POOL_NODE_MAX_NUM(pool) > node_pos)
    {
        CRFSNPRB_NODE *node;

        node = (CRFSNPRB_NODE *)((void *)(pool->rb_nodes) + node_pos * CRFSNPRB_POOL_NODE_SIZEOF(pool));

        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] __crfsnprb_node: pool %p, rb_nodes %p, node_pos %u  -> node %p\n",
                           pool, (void *)(pool->rb_nodes), node_pos, node);
        return (node);
    }
    return (NULL_PTR);
}


const char *crfsnp_model_str(const uint8_t crfsnp_model)
{
    CRFSNP_CFG *crfsnp_cfg;
    if(crfsnp_model >= g_crfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_model_str: invalid crfsnp mode %u\n", crfsnp_model);
        return (const char *)"unkown";
    }
    crfsnp_cfg = &(g_crfsnp_cfg_tbl[ crfsnp_model ]);
    return CRFSNP_CFG_MODEL_STR(crfsnp_cfg);
}

uint8_t crfsnp_model_get(const char *model_str)
{
    uint8_t crfsnp_model;

    for(crfsnp_model = 0; crfsnp_model < g_crfsnp_cfg_tbl_len; crfsnp_model ++)
    {
        CRFSNP_CFG *crfsnp_cfg;
        crfsnp_cfg = &(g_crfsnp_cfg_tbl[ crfsnp_model ]);

        if(0 == strcasecmp(CRFSNP_CFG_MODEL_STR(crfsnp_cfg), model_str))
        {
            return (crfsnp_model);
        }
    }
    return (CRFSNP_ERR_MODEL);
}

EC_BOOL crfsnp_model_file_size(const uint8_t crfsnp_model, UINT32 *file_size)
{
    CRFSNP_CFG *crfsnp_cfg;
    if(crfsnp_model >= g_crfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_model_file_size: invalid crfsnp mode %u\n", crfsnp_model);
        return (EC_FALSE);
    }
    crfsnp_cfg = &(g_crfsnp_cfg_tbl[ crfsnp_model ]);
    (*file_size) = CRFSNP_CFG_FILE_SIZE(crfsnp_cfg);
    return (EC_TRUE);
}

EC_BOOL crfsnp_model_item_max_num(const uint8_t crfsnp_model, uint32_t *item_max_num)
{
    CRFSNP_CFG *crfsnp_cfg;
    if(crfsnp_model >= g_crfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_model_item_max_num: invalid crfsnp mode %u\n", crfsnp_model);
        return (EC_FALSE);
    }
    crfsnp_cfg = &(g_crfsnp_cfg_tbl[ crfsnp_model ]);
    (*item_max_num) = CRFSNP_CFG_ITEM_MAX_NUM(crfsnp_cfg);
    return (EC_TRUE);
}

STATIC_CAST static char *crfsnp_fname_gen(const char *root_dir, const uint32_t np_id)
{
    char *fname;
    uint32_t len;

    if(NULL_PTR == root_dir)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_fname_gen: root_dir is null\n");
        return (NULL_PTR);
    }

    len = strlen(root_dir) + strlen("/np0000.dat") + 1;

    fname = safe_malloc(len, LOC_CRFSNP_0001);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_fname_gen: malloc %u bytes failed\n", len);
        return (NULL_PTR);
    }
    snprintf(fname, len, "%s/np%04X.dat", root_dir, np_id);
    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_fname_gen: np_id %u => np fname %s\n", np_id, fname);
    return (fname);
}

STATIC_CAST static uint32_t crfsnp_path_seg_len(const uint8_t *full_path, const uint32_t full_path_len, const uint8_t *path_seg_beg)
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

EC_BOOL crfsnp_inode_init(CRFSNP_INODE *crfsnp_inode)
{
    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_NOT_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = CPGRB_ERR_POS;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = CPGRB_ERR_POS;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = CPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL crfsnp_inode_clean(CRFSNP_INODE *crfsnp_inode)
{
    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_NOT_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = CPGRB_ERR_POS;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = CPGRB_ERR_POS;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = CPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL crfsnp_inode_clone(const CRFSNP_INODE *crfsnp_inode_src, CRFSNP_INODE *crfsnp_inode_des)
{
    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode_des) = CRFSNP_INODE_CACHE_FLAG(crfsnp_inode_src);
    CRFSNP_INODE_DISK_NO(crfsnp_inode_des)    = CRFSNP_INODE_DISK_NO(crfsnp_inode_src);
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode_des)   = CRFSNP_INODE_BLOCK_NO(crfsnp_inode_src);
    CRFSNP_INODE_PAGE_NO(crfsnp_inode_des)    = CRFSNP_INODE_PAGE_NO(crfsnp_inode_src);

    return (EC_TRUE);
}

void crfsnp_inode_print(LOG *log, const CRFSNP_INODE *crfsnp_inode)
{
    sys_print(log, "(cache %u, disk %u, block %u, page %u)\n",
                    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode),
                    CRFSNP_INODE_DISK_NO(crfsnp_inode),
                    CRFSNP_INODE_BLOCK_NO(crfsnp_inode),
                    CRFSNP_INODE_PAGE_NO(crfsnp_inode)
                    );
    return;
}

void crfsnp_inode_log_no_lock(LOG *log, const CRFSNP_INODE *crfsnp_inode)
{
    sys_print_no_lock(log, "(cache %u, disk %u, block %u, page %u)\n",
                    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode),
                    CRFSNP_INODE_DISK_NO(crfsnp_inode),
                    CRFSNP_INODE_BLOCK_NO(crfsnp_inode),
                    CRFSNP_INODE_PAGE_NO(crfsnp_inode)
                    );
    return;
}

CRFSNP_FNODE *crfsnp_fnode_new()
{
    CRFSNP_FNODE *crfsnp_fnode;
    alloc_static_mem(MM_CRFSNP_FNODE, &crfsnp_fnode, LOC_CRFSNP_0002);
    if(NULL_PTR != crfsnp_fnode)
    {
        crfsnp_fnode_init(crfsnp_fnode);
    }
    return (crfsnp_fnode);
}

CRFSNP_FNODE *crfsnp_fnode_make(const CRFSNP_FNODE *crfsnp_fnode_src)
{
    CRFSNP_FNODE *crfsnp_fnode_des;
    alloc_static_mem(MM_CRFSNP_FNODE, &crfsnp_fnode_des, LOC_CRFSNP_0003);
    if(NULL_PTR != crfsnp_fnode_des)
    {
        crfsnp_fnode_clone(crfsnp_fnode_src, crfsnp_fnode_des);
    }
    return (crfsnp_fnode_des);
}

EC_BOOL crfsnp_fnode_init(CRFSNP_FNODE *crfsnp_fnode)
{
    uint32_t pos;

    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = 0;
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 0;
    CRFSNP_FNODE_HASH(crfsnp_fnode)   = 0;

    for(pos = 0; pos < CRFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        crfsnp_inode_init(CRFSNP_FNODE_INODE(crfsnp_fnode, pos));
    }
    BSET(CRFSNP_FNODE_MD5SUM(crfsnp_fnode), 0, CMD5_DIGEST_LEN);
    return (EC_TRUE);
}

EC_BOOL crfsnp_fnode_clean(CRFSNP_FNODE *crfsnp_fnode)
{
    uint32_t pos;

    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = 0;
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 0;
    CRFSNP_FNODE_HASH(crfsnp_fnode)   = 0;

    for(pos = 0; pos < CRFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        crfsnp_inode_clean(CRFSNP_FNODE_INODE(crfsnp_fnode, pos));
    }
    BSET(CRFSNP_FNODE_MD5SUM(crfsnp_fnode), 0, CMD5_DIGEST_LEN);
    return (EC_TRUE);
}

EC_BOOL crfsnp_fnode_free(CRFSNP_FNODE *crfsnp_fnode)
{
    if(NULL_PTR != crfsnp_fnode)
    {
        crfsnp_fnode_clean(crfsnp_fnode);
        free_static_mem(MM_CRFSNP_FNODE, crfsnp_fnode, LOC_CRFSNP_0004);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_fnode_clone(const CRFSNP_FNODE *crfsnp_fnode_src, CRFSNP_FNODE *crfsnp_fnode_des)
{
    uint32_t pos;

    CRFSNP_FNODE_FILESZ(crfsnp_fnode_des) = CRFSNP_FNODE_FILESZ(crfsnp_fnode_src);
    CRFSNP_FNODE_REPNUM(crfsnp_fnode_des) = CRFSNP_FNODE_REPNUM(crfsnp_fnode_src);
    CRFSNP_FNODE_HASH(crfsnp_fnode_des)   = CRFSNP_FNODE_HASH(crfsnp_fnode_src);

    for(pos = 0; pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode_src) && pos < CRFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        crfsnp_inode_clone(CRFSNP_FNODE_INODE(crfsnp_fnode_src, pos), CRFSNP_FNODE_INODE(crfsnp_fnode_des, pos));
    }
    BCOPY(CRFSNP_FNODE_MD5SUM(crfsnp_fnode_src), CRFSNP_FNODE_MD5SUM(crfsnp_fnode_des), CMD5_DIGEST_LEN);
    return (EC_TRUE);
}

EC_BOOL crfsnp_fnode_check_inode_exist(const CRFSNP_INODE *inode, const CRFSNP_FNODE *crfsnp_fnode)
{
    uint32_t replica_pos;

    for(replica_pos = 0; replica_pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode); replica_pos ++)
    {
        if(
            CRFSNP_INODE_CACHE_FLAG(inode) == CRFSNP_FNODE_CACHE_FLAG(crfsnp_fnode, replica_pos)
         && CRFSNP_INODE_DISK_NO(inode)    == CRFSNP_FNODE_INODE_DISK_NO(crfsnp_fnode, replica_pos)
         && CRFSNP_INODE_BLOCK_NO(inode)   == CRFSNP_FNODE_INODE_BLOCK_NO(crfsnp_fnode, replica_pos)
         && CRFSNP_INODE_PAGE_NO(inode)    == CRFSNP_FNODE_INODE_PAGE_NO(crfsnp_fnode, replica_pos)
        )
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL crfsnp_fnode_cmp(const CRFSNP_FNODE *crfsnp_fnode_1st, const CRFSNP_FNODE *crfsnp_fnode_2nd)
{
    uint32_t replica_pos;

    if(NULL_PTR == crfsnp_fnode_1st && NULL_PTR == crfsnp_fnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == crfsnp_fnode_1st || NULL_PTR == crfsnp_fnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CRFSNP_FNODE_REPNUM(crfsnp_fnode_1st) != CRFSNP_FNODE_REPNUM(crfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CRFSNP_FNODE_FILESZ(crfsnp_fnode_1st) != CRFSNP_FNODE_FILESZ(crfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CRFSNP_FNODE_HASH(crfsnp_fnode_1st) != CRFSNP_FNODE_HASH(crfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    for(replica_pos = 0; replica_pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode_1st); replica_pos ++)
    {
        if(EC_FALSE == crfsnp_fnode_check_inode_exist(CRFSNP_FNODE_INODE(crfsnp_fnode_1st, replica_pos), crfsnp_fnode_2nd))
        {
            return (EC_FALSE);
        }
    }

    if(0 != BCMP(CRFSNP_FNODE_MD5SUM(crfsnp_fnode_1st), CRFSNP_FNODE_MD5SUM(crfsnp_fnode_2nd), CMD5_DIGEST_LEN))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_fnode_import(const CRFSNP_FNODE *crfsnp_fnode_src, CRFSNP_FNODE *crfsnp_fnode_des)
{
    uint32_t src_pos;
    uint32_t des_pos;

    for(src_pos = 0, des_pos = 0; src_pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode_src) && src_pos < CRFSNP_FILE_REPLICA_MAX_NUM; src_pos ++)
    {
        CRFSNP_INODE *crfsnp_inode_src;

        crfsnp_inode_src = (CRFSNP_INODE *)CRFSNP_FNODE_INODE(crfsnp_fnode_src, src_pos);
        if(CPGRB_ERR_POS != CRFSNP_INODE_DISK_NO(crfsnp_inode_src)
        && CPGRB_ERR_POS != CRFSNP_INODE_BLOCK_NO(crfsnp_inode_src)
        && CPGRB_ERR_POS != CRFSNP_INODE_PAGE_NO(crfsnp_inode_src)
        )
        {
            CRFSNP_INODE *crfsnp_inode_des;

            crfsnp_inode_des = CRFSNP_FNODE_INODE(crfsnp_fnode_des, des_pos);
            if(crfsnp_inode_src != crfsnp_inode_des)
            {
                crfsnp_inode_clone(crfsnp_inode_src, crfsnp_inode_des);
            }

            des_pos ++;
        }
    }

    BCOPY(CRFSNP_FNODE_MD5SUM(crfsnp_fnode_src), CRFSNP_FNODE_MD5SUM(crfsnp_fnode_des), CMD5_DIGEST_LEN);

    CRFSNP_FNODE_FILESZ(crfsnp_fnode_des) = CRFSNP_FNODE_FILESZ(crfsnp_fnode_src);
    CRFSNP_FNODE_REPNUM(crfsnp_fnode_des) = des_pos;
    CRFSNP_FNODE_HASH(crfsnp_fnode_des)   = CRFSNP_FNODE_HASH(crfsnp_fnode_src);
    return (EC_TRUE);
}

char *crfsnp_fnode_md5sum_str(const CRFSNP_FNODE *crfsnp_fnode)
{
    if(SWITCH_ON == CRFS_MD5_SWITCH)
    {
        return c_md5_to_hex_str(CRFSNP_FNODE_MD5SUM(crfsnp_fnode));
    }
    /*else*/
    return (NULL_PTR);
}

uint32_t crfsnp_fnode_count_replica(const CRFSNP_FNODE *crfsnp_fnode)
{
    uint32_t pos;
    uint32_t count;

    for(pos = 0, count = 0; pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode) && pos < CRFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        CRFSNP_INODE *crfsnp_inode;

        crfsnp_inode = (CRFSNP_INODE *)CRFSNP_FNODE_INODE(crfsnp_fnode, pos);
        if(CPGRB_ERR_POS != CRFSNP_INODE_DISK_NO(crfsnp_inode)
        && CPGRB_ERR_POS != CRFSNP_INODE_BLOCK_NO(crfsnp_inode)
        && CPGRB_ERR_POS != CRFSNP_INODE_PAGE_NO(crfsnp_inode)
        )
        {
            count ++;
        }
    }
    return (count);
}

void crfsnp_fnode_print(LOG *log, const CRFSNP_FNODE *crfsnp_fnode)
{
    uint32_t pos;

    sys_log(log, "crfsnp_fnode %p: file size %u, replica num %u, hash %x, md5 %s\n",
                    crfsnp_fnode,
                    CRFSNP_FNODE_FILESZ(crfsnp_fnode),
                    CRFSNP_FNODE_REPNUM(crfsnp_fnode),
                    CRFSNP_FNODE_HASH(crfsnp_fnode),
                    crfsnp_fnode_md5sum_str(crfsnp_fnode)
                    );

    for(pos = 0; pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode) && pos < CRFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        crfsnp_inode_print(log, CRFSNP_FNODE_INODE(crfsnp_fnode, pos));
    }
    return;
}

void crfsnp_fnode_log_no_lock(LOG *log, const CRFSNP_FNODE *crfsnp_fnode)
{
    uint32_t pos;

    sys_print_no_lock(log, "size %u, replica %u, hash %x, md5 %s",
                    CRFSNP_FNODE_FILESZ(crfsnp_fnode),
                    CRFSNP_FNODE_REPNUM(crfsnp_fnode),
                    CRFSNP_FNODE_HASH(crfsnp_fnode),
                    crfsnp_fnode_md5sum_str(crfsnp_fnode)
                    );

    for(pos = 0; pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode) && pos < CRFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        crfsnp_inode_log_no_lock(log, CRFSNP_FNODE_INODE(crfsnp_fnode, pos));
    }
    sys_print_no_lock(log, "\n");

    return;
}

CRFSNP_DNODE *crfsnp_dnode_new()
{
    CRFSNP_DNODE *crfsnp_dnode;

    alloc_static_mem(MM_CRFSNP_DNODE, &crfsnp_dnode, LOC_CRFSNP_0005);
    if(NULL_PTR != crfsnp_dnode)
    {
        crfsnp_dnode_init(crfsnp_dnode);
    }
    return (crfsnp_dnode);

}

EC_BOOL crfsnp_dnode_init(CRFSNP_DNODE *crfsnp_dnode)
{
    CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) = 0;
    CRFSNP_DNODE_ROOT_POS(crfsnp_dnode) = CRFSNPRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL crfsnp_dnode_clean(CRFSNP_DNODE *crfsnp_dnode)
{
    CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) = 0;
    CRFSNP_DNODE_ROOT_POS(crfsnp_dnode) = CRFSNPRB_ERR_POS;

    return (EC_TRUE);
}

EC_BOOL crfsnp_dnode_free(CRFSNP_DNODE *crfsnp_dnode)
{
    if(NULL_PTR != crfsnp_dnode)
    {
        crfsnp_dnode_clean(crfsnp_dnode);
        free_static_mem(MM_CRFSNP_DNODE, crfsnp_dnode, LOC_CRFSNP_0006);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_dnode_clone(const CRFSNP_DNODE *crfsnp_dnode_src, CRFSNP_DNODE *crfsnp_dnode_des)
{
    CRFSNP_DNODE_FILE_NUM(crfsnp_dnode_des) = CRFSNP_DNODE_FILE_NUM(crfsnp_dnode_src);
    CRFSNP_DNODE_ROOT_POS(crfsnp_dnode_des) = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode_src);
    return (EC_TRUE);
}

CRFSNP_ITEM *crfsnp_item_new()
{
    CRFSNP_ITEM *crfsnp_item;

    alloc_static_mem(MM_CRFSNP_ITEM, &crfsnp_item, LOC_CRFSNP_0009);
    if(NULL_PTR != crfsnp_item)
    {
        crfsnp_item_init(crfsnp_item);
    }
    return (crfsnp_item);
}

EC_BOOL crfsnp_item_init(CRFSNP_ITEM *crfsnp_item)
{
    CRFSNP_ITEM_DIR_FLAG(crfsnp_item)         = CRFSNP_ITEM_FILE_IS_ERR;
    CRFSNP_ITEM_USED_FLAG(crfsnp_item)        = CRFSNP_ITEM_IS_NOT_USED;
    CRFSNP_ITEM_PARENT_POS(crfsnp_item)       = CRFSNPRB_ERR_POS;/*fix*/
    CRFSNP_ITEM_KLEN(crfsnp_item)             = 0;
    CRFSNP_ITEM_CREATE_TIME(crfsnp_item)      = 0;
    CRFSNP_ITEM_SECOND_HASH(crfsnp_item)      = 0;

    BSET(CRFSNP_ITEM_KEY(crfsnp_item), '\0', CRFSNP_KEY_MAX_SIZE);

    crfsnp_fnode_init(CRFSNP_ITEM_FNODE(crfsnp_item));

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL crfsnp_item_clean(CRFSNP_ITEM *crfsnp_item)
{
    CRFSNP_ITEM_DIR_FLAG(crfsnp_item)         = CRFSNP_ITEM_FILE_IS_ERR;
    CRFSNP_ITEM_USED_FLAG(crfsnp_item)        = CRFSNP_ITEM_IS_NOT_USED;
    CRFSNP_ITEM_PARENT_POS(crfsnp_item)       = CRFSNPRB_ERR_POS;/*fix bug: break pointer to parent*/
    CRFSNP_ITEM_KLEN(crfsnp_item)             = 0;
    CRFSNP_ITEM_CREATE_TIME(crfsnp_item)      = 0;
    CRFSNP_ITEM_SECOND_HASH(crfsnp_item)      = 0;

#if 0
    BSET(CRFSNP_ITEM_KEY(crfsnp_item), '\0', CRFSNP_KEY_MAX_SIZE);
    crfsnp_fnode_clean(CRFSNP_ITEM_FNODE(crfsnp_item));
#endif
    /*optimize: item would be initialized when allocated. refer: crfsnp_dnode_insert*/
    CRFSNP_ITEM_KEY(crfsnp_item)[ 0 ] = '\0';

    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL crfsnp_item_clone(const CRFSNP_ITEM *crfsnp_item_src, CRFSNP_ITEM *crfsnp_item_des)
{
    if(NULL_PTR == crfsnp_item_src)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_clone: crfsnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == crfsnp_item_des)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_clone: crfsnp_item_des is null\n");
        return (EC_FALSE);
    }

    CRFSNP_ITEM_DIR_FLAG(crfsnp_item_des)    =  CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src);
    CRFSNP_ITEM_USED_FLAG(crfsnp_item_des)   =  CRFSNP_ITEM_USED_FLAG(crfsnp_item_src);
    CRFSNP_ITEM_KLEN(crfsnp_item_des)        =  CRFSNP_ITEM_KLEN(crfsnp_item_src);
    CRFSNP_ITEM_SECOND_HASH(crfsnp_item_des) = CRFSNP_ITEM_SECOND_HASH(crfsnp_item_src);

    BCOPY(CRFSNP_ITEM_KEY(crfsnp_item_src), CRFSNP_ITEM_KEY(crfsnp_item_des), CRFSNP_ITEM_KLEN(crfsnp_item_src));

    /*give up copying parent_pos !*/

    CRFSNP_ITEM_CREATE_TIME(crfsnp_item_des) = CRFSNP_ITEM_CREATE_TIME(crfsnp_item_src);

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src))
    {
        crfsnp_fnode_clone(CRFSNP_ITEM_FNODE(crfsnp_item_src), CRFSNP_ITEM_FNODE(crfsnp_item_des));
    }
    else if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src))
    {
        crfsnp_dnode_clone(CRFSNP_ITEM_DNODE(crfsnp_item_src), CRFSNP_ITEM_DNODE(crfsnp_item_des));
    }

    return (EC_TRUE);
}

/*note: not override the key info in des!*/
EC_BOOL crfsnp_item_move(const CRFSNP_ITEM *crfsnp_item_src, CRFSNP_ITEM *crfsnp_item_des)
{
    if(NULL_PTR == crfsnp_item_src)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_move: crfsnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == crfsnp_item_des)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_move: crfsnp_item_des is null\n");
        return (EC_FALSE);
    }

    CRFSNP_ITEM_DIR_FLAG(crfsnp_item_des)    =  CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src);
    CRFSNP_ITEM_USED_FLAG(crfsnp_item_des)   =  CRFSNP_ITEM_USED_FLAG(crfsnp_item_src);
    //CRFSNP_ITEM_KLEN(crfsnp_item_des)        =  CRFSNP_ITEM_KLEN(crfsnp_item_src);

    //BCOPY(CRFSNP_ITEM_KEY(crfsnp_item_src), CRFSNP_ITEM_KEY(crfsnp_item_des), CRFSNP_ITEM_KLEN(crfsnp_item_src));

    //dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_item_move: crfsnp_item_src key: %.*s\n", CRFSNP_ITEM_KLEN(crfsnp_item_src), CRFSNP_ITEM_KEY(crfsnp_item_src));
    //dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_item_move: crfsnp_item_des key: %.*s\n", CRFSNP_ITEM_KLEN(crfsnp_item_des), CRFSNP_ITEM_KEY(crfsnp_item_des));

    /*give up copying parent_pos !*/

    CRFSNP_ITEM_CREATE_TIME(crfsnp_item_des) = CRFSNP_ITEM_CREATE_TIME(crfsnp_item_src);
    CRFSNP_ITEM_SECOND_HASH(crfsnp_item_des) = CRFSNP_ITEM_SECOND_HASH(crfsnp_item_src);

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src))
    {
        crfsnp_fnode_clone(CRFSNP_ITEM_FNODE(crfsnp_item_src), CRFSNP_ITEM_FNODE(crfsnp_item_des));
    }
    else if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src))
    {
        crfsnp_dnode_clone(CRFSNP_ITEM_DNODE(crfsnp_item_src), CRFSNP_ITEM_DNODE(crfsnp_item_des));
    }
    
    return (EC_TRUE);
}

EC_BOOL crfsnp_item_free(CRFSNP_ITEM *crfsnp_item)
{
    if(NULL_PTR != crfsnp_item)
    {
        crfsnp_item_clean(crfsnp_item);
        free_static_mem(MM_CRFSNP_ITEM, crfsnp_item, LOC_CRFSNP_0010);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_item_set_key(CRFSNP_ITEM *crfsnp_item, const uint32_t klen, const uint8_t *key)
{
    BCOPY(key, CRFSNP_ITEM_KEY(crfsnp_item), klen);
    CRFSNP_ITEM_KLEN(crfsnp_item) = klen;

    return (EC_TRUE);
}

STATIC_CAST static const char *__crfsnp_item_dir_flag_str(const uint32_t dir_flag)
{
    switch(dir_flag)
    {
        case CRFSNP_ITEM_FILE_IS_DIR:
            return (const char *)"D";
        case CRFSNP_ITEM_FILE_IS_REG:
            return (const char *)"F";
        case CRFSNP_ITEM_FILE_IS_PIP:
            return (const char *)"P";
        case CRFSNP_ITEM_FILE_IS_LNK:
            return (const char *)"L";
        case CRFSNP_ITEM_FILE_IS_SCK:
            return (const char *)"S";
        case CRFSNP_ITEM_FILE_IS_CHR:
            return (const char *)"C";
        case CRFSNP_ITEM_FILE_IS_BLK:
            return (const char *)"B";
    }

    return (const char *)"UFO";
}

void crfsnp_item_print(LOG *log, const CRFSNP_ITEM *crfsnp_item)
{
    uint32_t pos;

    sys_print(log, "crfsnp_item %p: flag 0x%x [%s], stat %u, klen %u, create time %u, hash %u\n",
                    crfsnp_item,
                    CRFSNP_ITEM_DIR_FLAG(crfsnp_item), __crfsnp_item_dir_flag_str(CRFSNP_ITEM_DIR_FLAG(crfsnp_item)),
                    CRFSNP_ITEM_USED_FLAG(crfsnp_item),
                    CRFSNP_ITEM_KLEN(crfsnp_item),
                    CRFSNP_ITEM_CREATE_TIME(crfsnp_item),
                    CRFSNP_ITEM_SECOND_HASH(crfsnp_item)
                    );

    sys_log(log, "key: %.*s\n", CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_FNODE *crfsnp_fnode;

        crfsnp_fnode = (CRFSNP_FNODE *)CRFSNP_ITEM_FNODE(crfsnp_item);
        sys_log(log, "file size %u, replica num %u, hash %x, md5 %s\n",
                        CRFSNP_FNODE_FILESZ(crfsnp_fnode),
                        CRFSNP_FNODE_REPNUM(crfsnp_fnode),
                        CRFSNP_FNODE_HASH(crfsnp_fnode),
                        crfsnp_fnode_md5sum_str(crfsnp_fnode)
                        );
        for(pos = 0; pos < CRFSNP_FNODE_REPNUM(crfsnp_fnode) && pos < CRFSNP_FILE_REPLICA_MAX_NUM; pos ++)
        {
            CRFSNP_INODE *crfsnp_inode;

            crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, pos);
            crfsnp_inode_print(log, crfsnp_inode);
            //sys_print(log, "\n");
        }
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_DNODE *crfsnp_dnode;

        crfsnp_dnode = (CRFSNP_DNODE *)CRFSNP_ITEM_DNODE(crfsnp_item);
        sys_log(log, "file num: %u, dir root pos: %u\n",
                     CRFSNP_DNODE_FILE_NUM(crfsnp_dnode),
                     CRFSNP_DNODE_ROOT_POS(crfsnp_dnode));
    }

    return;
}

EC_BOOL crfsnp_item_load(CRFSNP *crfsnp, uint32_t *offset, CRFSNP_ITEM *crfsnp_item)
{
    RWSIZE rsize;
    UINT32 offset_t;

    offset_t = (*offset);
    rsize = sizeof(CRFSNP_ITEM);
    if(EC_FALSE == c_file_load(CRFSNP_FD(crfsnp), &offset_t, rsize, (UINT8 *)crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_load: load item from offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL crfsnp_item_flush(CRFSNP *crfsnp, uint32_t *offset, const CRFSNP_ITEM *crfsnp_item)
{
    RWSIZE wsize;
    UINT32 offset_t;

    offset_t = (*offset);
    wsize = sizeof(CRFSNP_ITEM);
    if(EC_FALSE == c_file_flush(CRFSNP_FD(crfsnp), &offset_t, wsize, (UINT8 *)crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_load: flush item to offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL crfsnp_item_is(const CRFSNP_ITEM *crfsnp_item, const uint32_t klen, const uint8_t *key)
{
    if(CRFSNP_KEY_MAX_SIZE < klen)/*overflow key*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        if(md5_len != CRFSNP_ITEM_KLEN(crfsnp_item))
        {
            return (EC_FALSE);
        }

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(klen, key);

        if(0 != memcmp((void *)md5_str, (void *)CRFSNP_ITEM_KEY(crfsnp_item), md5_len))
        {
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    if(klen !=  CRFSNP_ITEM_KLEN(crfsnp_item))
    {
        return (EC_FALSE);
    }

    if(0 != strncmp((char *)key, (char *)CRFSNP_ITEM_KEY(crfsnp_item), klen))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CRFSNP_ITEM *crfsnp_item_parent(const CRFSNP *crfsnp, const CRFSNP_ITEM *crfsnp_item)
{
    uint32_t parent_pos;

    parent_pos = CRFSNPRB_NODE_PARENT_POS(CRFSNP_ITEM_RB_NODE(crfsnp_item));
    if(CRFSNPRB_ERR_POS == parent_pos)
    {
        return (NULL_PTR);
    }

    return crfsnp_fetch(crfsnp, parent_pos);
}

CRFSNP_ITEM *crfsnp_item_left(const CRFSNP *crfsnp, const CRFSNP_ITEM *crfsnp_item)
{
    uint32_t left_pos;

    left_pos = CRFSNPRB_NODE_LEFT_POS(CRFSNP_ITEM_RB_NODE(crfsnp_item));
    if(CRFSNPRB_ERR_POS == left_pos)
    {
        return (NULL_PTR);
    }

    return crfsnp_fetch(crfsnp, left_pos);
}

CRFSNP_ITEM *crfsnp_item_right(const CRFSNP *crfsnp, const CRFSNP_ITEM *crfsnp_item)
{
    uint32_t right_offset;

    right_offset = CRFSNPRB_NODE_RIGHT_POS(CRFSNP_ITEM_RB_NODE(crfsnp_item));
    if(CRFSNPRB_ERR_POS == right_offset)
    {
        return (NULL_PTR);
    }

    return crfsnp_fetch(crfsnp, right_offset);
}

EC_BOOL crfsnp_dit_node_init(CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    UINT32 idx;

    CRFSNP_DIT_NODE_HANDLER(crfsnp_dit_node) = NULL_PTR;
    cstack_init(CRFSNP_DIT_NODE_STACK(crfsnp_dit_node), MM_CRFSNP_ITEM, LOC_CRFSNP_0011);

    for(idx = 0; idx < CRFSNP_DIT_ARGS_MAX_NUM; idx ++)
    {
        CRFSNP_DIT_NODE_ARG(crfsnp_dit_node, idx) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_dit_node_clean(CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    UINT32 idx;

    CRFSNP_DIT_NODE_HANDLER(crfsnp_dit_node) = NULL_PTR;
    cstack_clean(CRFSNP_DIT_NODE_STACK(crfsnp_dit_node), NULL_PTR); /*never cleanup crfsnp_item*/

    for(idx = 0; idx < CRFSNP_DIT_ARGS_MAX_NUM; idx ++)
    {
        CRFSNP_DIT_NODE_ARG(crfsnp_dit_node, idx) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_load(const uint32_t np_id, const UINT32 fsize, int fd)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(fsize, LOC_CRFSNP_0012);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_header_load: malloc %ld bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, buff))
    {
        safe_free(buff, LOC_CRFSNP_0013);
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_header_load: load %ld bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    return ((CRFSNP_HEADER *)buff);
}

STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_dup(CRFSNP_HEADER *src_crfsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    CRFSNP_HEADER *des_crfsnp_header;

    des_crfsnp_header = (CRFSNP_HEADER *)safe_malloc(fsize, LOC_CRFSNP_0014);
    if(NULL_PTR == des_crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_header_dup: new header with %ld bytes for np %u fd %d failed\n",
                           fsize, des_np_id, fd);
        return (NULL_PTR);
    }

    BCOPY(src_crfsnp_header, des_crfsnp_header, fsize);

    CRFSNP_HEADER_NP_ID(des_crfsnp_header)  = des_np_id;
    return (des_crfsnp_header);
}

STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_new(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model)
{
    CRFSNP_HEADER *crfsnp_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    crfsnp_header = (CRFSNP_HEADER *)safe_malloc(fsize, LOC_CRFSNP_0015);
    if(NULL_PTR == crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_header_new: new header with %ld bytes for np %u fd %d failed\n",
                           fsize, np_id, fd);
        return (NULL_PTR);
    }

    CRFSNP_HEADER_NP_ID(crfsnp_header)  = np_id;
    CRFSNP_HEADER_MODEL(crfsnp_header)  = np_model;

    crfsnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CRFSNP_ITEM);
    
    /*init RB Nodes*/
    crfsnprb_pool_init(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header), node_max_num, node_sizeof);

    /*init LRU nodes*/
    crfsnplru_pool_init(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    crfsnpdel_pool_init(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header), node_max_num, node_sizeof); 
    
    return (crfsnp_header);
}

STATIC_CAST static CRFSNP_HEADER * __crfsnp_header_flush(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != crfsnp_header)
    {
        UINT32 offset;

        offset = 0;
        if(EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)crfsnp_header))
        {
            dbg_log(SEC_0081_CRFSNP, 1)(LOGSTDOUT, "warn:__crfsnp_header_flush: flush crfsnp_hdr of np %u fd %d with size %ld failed\n",
                               np_id, fd, fsize);
        }
    }
    return (crfsnp_header);
}

STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_free(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != crfsnp_header)
    {
        UINT32 offset;

        offset = 0;
        if(
           ERR_FD != fd
        && EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)crfsnp_header)
        )
        {
            dbg_log(SEC_0081_CRFSNP, 1)(LOGSTDOUT, "warn:__crfsnp_header_free: flush crfsnp_hdr of np %u fd %d with size %ld failed\n",
                               np_id, fd, fsize);
        }

        safe_free(crfsnp_header, LOC_CRFSNP_0016);
    }

    /*crfsnp_header cannot be accessed again*/
    return (NULL_PTR);
}


STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd)
{
    CRFSNP_HEADER *crfsnp_header;

    crfsnp_header = (CRFSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_header_open: mmap np %u with fd %d failed, errno = %d, errstr = %s\n",
                           np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }

    return (crfsnp_header);
}

STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_clone(const CRFSNP_HEADER *src_crfsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    CRFSNP_HEADER *des_crfsnp_header;

    des_crfsnp_header = (CRFSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == des_crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_header_clone: mmap np %u with fd %d failed, errno = %d, errstr = %s\n",
                           des_np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }

    BCOPY(src_crfsnp_header, des_crfsnp_header, fsize);

    CRFSNP_HEADER_NP_ID(des_crfsnp_header)  = des_np_id;

    return (des_crfsnp_header);
}

STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model)
{
    CRFSNP_HEADER *crfsnp_header;
    uint32_t node_max_num;
    uint32_t node_sizeof;

    crfsnp_header = (CRFSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_header_create: mmap np %u with fd %d failed, errno = %d, errstr = %s\n",
                           np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }

    CRFSNP_HEADER_NP_ID(crfsnp_header)  = np_id;
    CRFSNP_HEADER_MODEL(crfsnp_header)  = np_model;

    crfsnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CRFSNP_ITEM);

    /*init RB Nodes*/
    crfsnprb_pool_init(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header), node_max_num, node_sizeof);

    /*init LRU nodes*/
    crfsnplru_pool_init(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header), node_max_num, node_sizeof);

    /*init DEL nodes*/
    crfsnpdel_pool_init(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header), node_max_num, node_sizeof); 
    
    return (crfsnp_header);
}

STATIC_CAST static CRFSNP_HEADER * __crfsnp_header_sync(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != crfsnp_header)
    {
        if(0 != msync(crfsnp_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "warn:__crfsnp_header_sync: sync crfsnp_hdr of np %u %d with size %ld failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_header_sync: sync crfsnp_hdr of np %u %d with size %ld done\n",
                               np_id, fd, fsize);
        }
    }
    return (crfsnp_header);
}

STATIC_CAST static CRFSNP_HEADER *__crfsnp_header_close(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(NULL_PTR != crfsnp_header)
    {
        if(0 != msync(crfsnp_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "warn:__crfsnp_header_close: sync crfsnp_hdr of np %u fd %d with size %ld failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_header_close: sync crfsnp_hdr of np %u fd %d with size %ld done\n",
                               np_id, fd, fsize);
        }
        if(0 != munmap(crfsnp_header, fsize))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "warn:__crfsnp_header_close: munmap crfsnp of np %u fd %d with size %ld failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_header_close: munmap crfsnp of np %u fd %d with size %ld done\n",
                               np_id, fd, fsize);
        }
    }

    /*crfsnp_header cannot be accessed again*/
    return (NULL_PTR);
}

EC_BOOL crfsnp_header_init(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const uint8_t model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id)
{
    CRFSNP_HEADER_NP_ID(crfsnp_header)         = np_id;
    CRFSNP_HEADER_MODEL(crfsnp_header)         = model;

    CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header)  = second_chash_algo_id;

    /*do nothing on lru list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CRFSNPRB_POOL pool*/

    return (EC_TRUE);
}

EC_BOOL crfsnp_header_clean(CRFSNP_HEADER *crfsnp_header)
{
    CRFSNP_HEADER_NP_ID(crfsnp_header)              = CRFSNP_ERR_ID;
    CRFSNP_HEADER_MODEL(crfsnp_header)              = CRFSNP_ERR_MODEL;

    CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header)  = CHASH_ERR_ALGO_ID;

    /*do nothing on lru list*/
    /*do nothing on del list*/
    /*do nothing on bitmap*/
    /*do nothing on CRFSNPRB_POOL pool*/

    return (EC_TRUE);
}

CRFSNP_HEADER *crfsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CRFS_NP_CACHE_IN_MEM)
    {
        return __crfsnp_header_load(np_id, fsize, fd);
    }

    return __crfsnp_header_open(np_id, fsize, fd);
}

CRFSNP_HEADER *crfsnp_header_clone(CRFSNP_HEADER *src_crfsnp_header, const uint32_t des_np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CRFS_NP_CACHE_IN_MEM)
    {
        return __crfsnp_header_dup(src_crfsnp_header, des_np_id, fsize, fd);
    }

    return __crfsnp_header_clone(src_crfsnp_header, des_np_id, fsize, fd);
}


CRFSNP_HEADER *crfsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model)
{
    if(SWITCH_ON == CRFS_NP_CACHE_IN_MEM)
    {
        return __crfsnp_header_new(np_id, fsize, fd, np_model);
    }

    return __crfsnp_header_create(np_id, fsize, fd, np_model);
}

CRFSNP_HEADER *crfsnp_header_sync(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CRFS_NP_CACHE_IN_MEM)
    {
        return __crfsnp_header_flush(crfsnp_header, np_id, fsize, fd);
    }

    return __crfsnp_header_sync(crfsnp_header, np_id, fsize, fd);
}

CRFSNP_HEADER *crfsnp_header_close(CRFSNP_HEADER *crfsnp_header, const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CRFS_NP_CACHE_IN_MEM)
    {
        return __crfsnp_header_free(crfsnp_header, np_id, fsize, fd);
    }

    return __crfsnp_header_close(crfsnp_header, np_id, fsize, fd);
}

CRFSNP *crfsnp_new()
{
    CRFSNP *crfsnp;

    alloc_static_mem(MM_CRFSNP, &crfsnp, LOC_CRFSNP_0017);
    if(NULL_PTR != crfsnp)
    {
        crfsnp_init(crfsnp);
    }
    return (crfsnp);
}

EC_BOOL crfsnp_init(CRFSNP *crfsnp)
{
    CRFSNP_FD(crfsnp)              = ERR_FD;
    CRFSNP_FSIZE(crfsnp)           = 0;
    CRFSNP_FNAME(crfsnp)           = NULL_PTR;
    CRFSNP_DEL_SIZE(crfsnp)        = 0;
    CRFSNP_RECYCLE_SIZE(crfsnp)    = 0;
    CRFSNP_LRU_LIST(crfsnp)        = NULL_PTR;
    CRFSNP_DEL_LIST(crfsnp)        = NULL_PTR;    
    CRFSNP_HDR(crfsnp)             = NULL_PTR;

    CRFSNP_2ND_CHASH_ALGO(crfsnp)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL crfsnp_clean(CRFSNP *crfsnp)
{
    if(NULL_PTR != CRFSNP_HDR(crfsnp))
    {
        crfsnp_header_close(CRFSNP_HDR(crfsnp), CRFSNP_ID(crfsnp), CRFSNP_FSIZE(crfsnp), CRFSNP_FD(crfsnp));
        CRFSNP_HDR(crfsnp) = NULL_PTR;
    }

    if(ERR_FD != CRFSNP_FD(crfsnp))
    {
        c_file_close(CRFSNP_FD(crfsnp));
        CRFSNP_FD(crfsnp) = ERR_FD;
    }

    CRFSNP_FSIZE(crfsnp) = 0;

    if(NULL_PTR != CRFSNP_FNAME(crfsnp))
    {
        safe_free(CRFSNP_FNAME(crfsnp), LOC_CRFSNP_0019);
        CRFSNP_FNAME(crfsnp) = NULL_PTR;
    }

    CRFSNP_DEL_SIZE(crfsnp)     = 0;
    CRFSNP_RECYCLE_SIZE(crfsnp) = 0;

    CRFSNP_LRU_LIST(crfsnp) = NULL_PTR;
    CRFSNP_DEL_LIST(crfsnp) = NULL_PTR;
    CRFSNP_HDR(crfsnp)      = NULL_PTR;

    CRFSNP_2ND_CHASH_ALGO(crfsnp) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL crfsnp_free(CRFSNP *crfsnp)
{
    if(NULL_PTR != crfsnp)
    {
        crfsnp_clean(crfsnp);
        free_static_mem(MM_CRFSNP, crfsnp, LOC_CRFSNP_0021);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_is_full(const CRFSNP *crfsnp)
{
    CRFSNPRB_POOL *pool;

    pool = CRFSNP_ITEMS_POOL(crfsnp);
    return crfsnprb_pool_is_full(pool);
}

EC_BOOL crfsnp_lru_list_is_empty(const CRFSNP *crfsnp)
{
    return crfsnplru_is_empty(CRFSNP_LRU_LIST(crfsnp));
}

EC_BOOL crfsnp_del_list_is_empty(const CRFSNP *crfsnp)
{
    return crfsnpdel_is_empty(CRFSNP_DEL_LIST(crfsnp));
}

void crfsnp_header_print(LOG *log, const CRFSNP *crfsnp)
{
    const CRFSNP_HEADER *crfsnp_header;

    crfsnp_header = CRFSNP_HDR(crfsnp);

    sys_log(log, "np %u, model %u, hash algo %u, item max num %u, item used num %u\n",
                CRFSNP_HEADER_NP_ID(crfsnp_header),
                CRFSNP_HEADER_MODEL(crfsnp_header),
                CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header),
                CRFSNP_HEADER_ITEMS_MAX_NUM(crfsnp_header),
                CRFSNP_HEADER_ITEMS_USED_NUM(crfsnp_header)
        );

    crfsnprb_pool_print(log, CRFSNP_HEADER_ITEMS_POOL(crfsnp_header));
    return;
}

void crfsnp_print(LOG *log, const CRFSNP *crfsnp)
{
    sys_log(log, "crfsnp %p: np %u, fname %s\n",
                 crfsnp,
                 CRFSNP_ID(crfsnp),
                 CRFSNP_FNAME(crfsnp)
                 );

    sys_log(log, "crfsnp %p: np %u, fsize %lu, del size %llu, recycle size %llu\n",
                 crfsnp,
                 CRFSNP_ID(crfsnp),
                 CRFSNP_FSIZE(crfsnp),
                 CRFSNP_DEL_SIZE(crfsnp),
                 CRFSNP_RECYCLE_SIZE(crfsnp)
                 );

    sys_log(log, "crfsnp %p: header: \n", crfsnp);
    crfsnp_header_print(log, crfsnp);
    return;
}

void crfsnp_print_lru_list(LOG *log, const CRFSNP *crfsnp)
{
    sys_log(log, "crfsnp_print_lru_list: crfsnp %p: lru list: \n", crfsnp);
    crfsnplru_list_print(log, crfsnp);
    return;
}

void crfsnp_print_del_list(LOG *log, const CRFSNP *crfsnp)
{
    sys_log(log, "crfsnp_print_del_list: crfsnp %p: del list: \n", crfsnp);
    crfsnpdel_list_print(log, crfsnp);
    return;
}

CRFSNP_ITEM *crfsnp_dnode_find(const CRFSNP *crfsnp, const CRFSNP_DNODE *crfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    const CRFSNPRB_POOL *pool;
    uint32_t root_pos;
    uint32_t node_pos;

    pool     = CRFSNP_ITEMS_POOL(crfsnp);
    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);

    if(CRFSNP_KEY_MAX_SIZE < klen)/*overflow key*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(klen, key);
        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        node_pos = crfsnprb_tree_search_data(pool, root_pos, second_hash, md5_len, md5_str);
    }
    else
    {
        node_pos = crfsnprb_tree_search_data(pool, root_pos, second_hash, klen, key);
    }

    if(CRFSNPRB_ERR_POS != node_pos)
    {
        const CRFSNPRB_NODE *node;
        const CRFSNP_ITEM   *item;

        node = CRFSNPRB_POOL_NODE(pool, node_pos);
        item = CRFSNP_RB_NODE_ITEM(node);

        return (CRFSNP_ITEM *)(item);
    }

    return (NULL_PTR);
}

uint32_t crfsnp_dnode_search(const CRFSNP *crfsnp, const CRFSNP_DNODE *crfsnp_dnode, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    const CRFSNPRB_POOL *pool;
    uint32_t root_pos;

    pool     = CRFSNP_ITEMS_POOL(crfsnp);
    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);

    if(CRFSNP_KEY_MAX_SIZE < klen)/*overflow key*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(klen, key);
        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        return crfsnprb_tree_search_data(pool, root_pos, second_hash, md5_len, md5_str);
    }

    return crfsnprb_tree_search_data(pool, root_pos, second_hash, klen, key);
}

uint32_t crfsnp_dnode_match(CRFSNP *crfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    const CRFSNPRB_POOL *pool;
    uint32_t             node_pos;

    pool     = CRFSNP_ITEMS_POOL(crfsnp);
    node_pos = root_pos;

    if(CRFSNPRB_ERR_POS != node_pos)
    {
        const CRFSNPRB_NODE *node;
        uint32_t             node_pos_t;

        node = CRFSNPRB_POOL_NODE(pool, node_pos);

        node_pos_t = crfsnp_match_no_lock(crfsnp, node_pos, path_len, path, dflag);
        if(CRFSNPRB_ERR_POS != node_pos_t)
        {
            return (node_pos_t);
        }

        node_pos_t = crfsnp_dnode_match(crfsnp, CRFSNPRB_NODE_LEFT_POS(node), path_len, path, dflag);
        if(CRFSNPRB_ERR_POS != node_pos_t)
        {
            return (node_pos_t);
        }

        node_pos_t = crfsnp_dnode_match(crfsnp, CRFSNPRB_NODE_RIGHT_POS(node), path_len, path, dflag);
        if(CRFSNPRB_ERR_POS != node_pos_t)
        {
            return (node_pos_t);
        }
    }

    return (CRFSNPRB_ERR_POS);
}

uint32_t crfsnp_dnode_insert(CRFSNP *crfsnp, const uint32_t parent_pos,
                                    const uint32_t path_seg_second_hash,
                                    const uint32_t path_seg_len, const uint8_t *path_seg,
                                    const uint32_t dir_flag)
{
    uint32_t insert_offset;
    uint32_t root_pos;

    CRFSNP_ITEM *crfsnp_item_parent;
    CRFSNP_ITEM *crfsnp_item_insert;

    CRFSNP_DNODE *crfsnp_dnode_parent;

    if(CRFSNP_ITEM_FILE_IS_REG != dir_flag
    && CRFSNP_ITEM_FILE_IS_DIR != dir_flag)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_dnode_insert: invalid input dir flag %x\n", dir_flag);
        return (CRFSNPRB_ERR_POS);
    }

    if(EC_TRUE == crfsnp_is_full(crfsnp))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_dnode_insert: crfsnp is full\n");
        return (CRFSNPRB_ERR_POS);
    }

    crfsnp_item_parent = crfsnp_fetch(crfsnp, parent_pos);/*must be dnode*/
    if(NULL_PTR == crfsnp_item_parent)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_dnode_insert: fetch parent item failed where parent offset %u\n", parent_pos);
        return (CRFSNPRB_ERR_POS);
    }

    crfsnp_dnode_parent = CRFSNP_ITEM_DNODE(crfsnp_item_parent);
    if(CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item_parent)
    || CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item_parent))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_dnode_insert: invalid dir flag %u or stat %u\n",
                            CRFSNP_ITEM_DIR_FLAG(crfsnp_item_parent),
                            CRFSNP_ITEM_USED_FLAG(crfsnp_item_parent));
        return (CRFSNPRB_ERR_POS);
    }

    /*insert the item to parent and update parent*/
    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode_parent);

    //dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_dnode_insert: crfsnp %p, header %p, pool %p\n", crfsnp, CRFSNP_HDR(crfsnp), CRFSNP_ITEMS_POOL(crfsnp));

    if(CRFSNP_KEY_MAX_SIZE < path_seg_len)/*overflow path seg*/
    {
        uint8_t     *md5_str;
        uint32_t     md5_len;

        md5_str = (uint8_t *)c_md5_sum_to_hex_str(path_seg_len, path_seg);
        md5_len = (uint32_t )(2 * CMD5_DIGEST_LEN);

        if(EC_FALSE == crfsnprb_tree_insert_data(CRFSNP_ITEMS_POOL(crfsnp), &root_pos, path_seg_second_hash, md5_len, md5_str, &insert_offset))
        {
            dbg_log(SEC_0081_CRFSNP, 1)(LOGSTDOUT, "warn:crfsnp_dnode_insert: found duplicate rb node with root %u at node %u\n", root_pos, insert_offset);
            return (insert_offset);
        }
        crfsnp_item_insert = crfsnp_fetch(crfsnp, insert_offset);

        /*fill in crfsnp_item_insert*/
        crfsnp_item_set_key(crfsnp_item_insert, md5_len, md5_str);
        CRFSNP_ITEM_SECOND_HASH(crfsnp_item_insert) = path_seg_second_hash;
        CRFSNP_ITEM_PARENT_POS(crfsnp_item_insert)  = parent_pos;
    }
    else
    {
        if(EC_FALSE == crfsnprb_tree_insert_data(CRFSNP_ITEMS_POOL(crfsnp), &root_pos, path_seg_second_hash, path_seg_len, path_seg, &insert_offset))
        {
            dbg_log(SEC_0081_CRFSNP, 1)(LOGSTDOUT, "warn:crfsnp_dnode_insert: found duplicate rb node with root %u at node %u\n", root_pos, insert_offset);
            return (insert_offset);
        }
        crfsnp_item_insert = crfsnp_fetch(crfsnp, insert_offset);

        /*fill in crfsnp_item_insert*/
        crfsnp_item_set_key(crfsnp_item_insert, path_seg_len, path_seg);
        CRFSNP_ITEM_SECOND_HASH(crfsnp_item_insert) = path_seg_second_hash;
        CRFSNP_ITEM_PARENT_POS(crfsnp_item_insert)  = parent_pos;
    }

    if(CRFSNP_ITEM_FILE_IS_REG == dir_flag)
    {
        crfsnp_fnode_init(CRFSNP_ITEM_FNODE(crfsnp_item_insert));
        CRFSNP_ITEM_DIR_FLAG(crfsnp_item_insert) = CRFSNP_ITEM_FILE_IS_REG;
    }
    else if(CRFSNP_ITEM_FILE_IS_DIR == dir_flag)
    {
        crfsnp_dnode_init(CRFSNP_ITEM_DNODE(crfsnp_item_insert));
        CRFSNP_ITEM_DIR_FLAG(crfsnp_item_insert) = CRFSNP_ITEM_FILE_IS_DIR;
    }
    
    CRFSNP_ITEM_USED_FLAG(crfsnp_item_insert) = CRFSNP_ITEM_IS_USED;

    CRFSNP_DNODE_ROOT_POS(crfsnp_dnode_parent) = root_pos;
    CRFSNP_DNODE_FILE_NUM(crfsnp_dnode_parent) ++;
    return (insert_offset);
}

/**
* umount one son from crfsnp_dnode,  where son is regular file item or dir item without any son
* crfsnp_dnode will be impacted on bucket and file num
**/
uint32_t crfsnp_dnode_umount_son(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, const uint32_t son_node_pos, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    CRFSNPRB_POOL *pool;
    uint32_t       root_pos;
    uint32_t       node_pos;

    node_pos = crfsnp_dnode_search(crfsnp, crfsnp_dnode, second_hash, klen, key);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (CRFSNPRB_ERR_POS);
    }

    if(node_pos == son_node_pos)
    {
        root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);

        pool = CRFSNP_ITEMS_POOL(crfsnp);
        crfsnprb_tree_erase(pool, node_pos, &root_pos); /*erase but not recycle node_pos ...*/

        CRFSNP_DNODE_ROOT_POS(crfsnp_dnode) = root_pos;
        CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) --;
    }

    return (node_pos);
}

/*delete single item from dnode*/
STATIC_CAST static EC_BOOL __crfsnp_dnode_delete_item(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, CRFSNP_ITEM *crfsnp_item)
{
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_item_clean(crfsnp_item);
        CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) --;
    }

    else if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_dnode_delete_dir_son(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item));/*recursively*/
        crfsnp_item_clean(crfsnp_item);
        CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) --;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsnp_dnode_delete_all_items(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, const uint32_t node_pos)
{
    CRFSNPRB_POOL *pool;
    CRFSNPRB_NODE *node;
    CRFSNP_ITEM   *item;

    pool = CRFSNP_ITEMS_POOL(crfsnp);

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        __crfsnp_dnode_delete_all_items(crfsnp, crfsnp_dnode, CRFSNPRB_NODE_LEFT_POS(node));
    }

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        __crfsnp_dnode_delete_all_items(crfsnp, crfsnp_dnode, CRFSNPRB_NODE_RIGHT_POS(node));
    }

    item = CRFSNP_RB_NODE_ITEM(node);
    __crfsnp_dnode_delete_item(crfsnp, crfsnp_dnode, item);

    /*crfsnprb recycle the rbnode, do not use crfsnprb_tree_delete which will change the tree structer*/
    crfsnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

/*delete one dir son, not including crfsnp_dnode itself*/
EC_BOOL crfsnp_dnode_delete_dir_son(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode)
{
    uint32_t root_pos;

    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(CRFSNPRB_ERR_POS != root_pos)
    {
        __crfsnp_dnode_delete_all_items(crfsnp, crfsnp_dnode, root_pos);
        CRFSNP_DNODE_ROOT_POS(crfsnp_dnode) = CRFSNPRB_ERR_POS;
    }
    return (EC_TRUE);
}
#if 1
/*delete one item from dnode, if item is dnode, it must be empty*/
STATIC_CAST static EC_BOOL __crfsnp_dnode_delete_single_item(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, CRFSNP_ITEM *crfsnp_item, CRFSNP_ITEM *crfsnp_item_del)
{
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_item_clone(crfsnp_item, crfsnp_item_del);

        crfsnp_item_clean(crfsnp_item);
        CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) --;
    }

    else if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_dnode_delete_dir_single_son(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item), crfsnp_item_del);/*recursively*/
        if(0 == CRFSNP_DNODE_FILE_NUM(CRFSNP_ITEM_DNODE(crfsnp_item)))
        {
            crfsnp_item_clean(crfsnp_item);
            CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) --;
        }
    }

    return (EC_TRUE);
}

/*delete one dir son, not including crfsnp_dnode itself*/
EC_BOOL crfsnp_dnode_delete_dir_single_son(const CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, CRFSNP_ITEM *crfsnp_item_del)
{
    uint32_t root_pos;

    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(CRFSNPRB_ERR_POS != root_pos)
    {
        CRFSNPRB_POOL *pool;
        CRFSNPRB_NODE *node;
        CRFSNP_ITEM   *item;

        pool = CRFSNP_ITEMS_POOL(crfsnp);
        node = CRFSNPRB_POOL_NODE(pool, root_pos);
        item = CRFSNP_RB_NODE_ITEM(node);

        __crfsnp_dnode_delete_single_item(crfsnp, crfsnp_dnode, item, crfsnp_item_del);

        crfsnprb_tree_delete(pool, &root_pos, root_pos);
        CRFSNP_DNODE_ROOT_POS(crfsnp_dnode) = root_pos;
    }

    return (EC_TRUE);
}
#endif

uint32_t crfsnp_match_no_lock(CRFSNP *crfsnp, const uint32_t root_pos, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;
    uint32_t path_seg_len;
    uint8_t *path_seg_beg;
    uint8_t *path_seg_end;

    if('/' != (*path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_match_no_lock: np %u, invalid path '%.*s'\n",
                        CRFSNP_ID(crfsnp), path_len, path);
        return (CRFSNPRB_ERR_POS);
    }

    node_pos = root_pos;/*the first item starting from*/

    if(CRFSNPRB_ROOT_POS == node_pos)
    {
        path_seg_beg = (uint8_t *)path;
        path_seg_len = 0;
        path_seg_end = (uint8_t *)(path_seg_beg + path_seg_len + 1);/*path always start with '/'*/
    }
    else
    {
        path_seg_beg = (uint8_t *)(path + 1);
        path_seg_len = crfsnp_path_seg_len(path, path_len, path_seg_beg);
        path_seg_end = path_seg_beg + path_seg_len + 1;
    }

    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, item pos %u [%.*s]\n", CRFSNP_ID(crfsnp), node_pos, path_len, path);
    while(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;

        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDNULL, "[DEBUG] crfsnp_match_no_lock: np %u, node_pos %u, item pos %u\n",
                            CRFSNP_ID(crfsnp), node_pos, (uint32_t)(node_pos / sizeof(CRFSNP_ITEM)));

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_match_no_lock: np %u, item at node_pos %u was not used\n", CRFSNP_ID(crfsnp), node_pos);
            return (CRFSNPRB_ERR_POS);
        }

        /*if path_seg is wildcard '*', matched. otherwise, check item key matched or not*/
        if(1 != path_seg_len || '*' != (char)(*path_seg_beg))
        {
            if(EC_FALSE == crfsnp_item_is(crfsnp_item, path_seg_len, path_seg_beg))
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_match_no_lock: np %u, check failed where path seg: %.*s [%u]\n",
                                    CRFSNP_ID(crfsnp), path_seg_len, path_seg_beg, path_seg_len);
                return (CRFSNPRB_ERR_POS);
            }
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, check succ where path seg: '%.*s' [%u]\n",
                                CRFSNP_ID(crfsnp), path_seg_len, path_seg_beg, path_seg_len);
        }

        /*when matched and reached the last path seg*/
        if(path_len <= (uint32_t)(path_seg_end - path))
        {
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] [target dflag %u] crfsnp_match_no_lock: np %u, "
                                "matched and reached end where path_len %u, len from path to path_seg_end is %u, node_pos %u [%.*s]\n",
                                dflag, CRFSNP_ID(crfsnp), path_len, (uint32_t)(path_seg_end - path), node_pos, path_len, path);

            if(CRFSNP_ITEM_FILE_IS_ANY == dflag || dflag == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
            {
                rlog(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, return node_pos %u, target dflag %u, item dflag %u\n",
                                    CRFSNP_ID(crfsnp), node_pos, dflag, CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
                return (node_pos);
            }

            return (CRFSNPRB_ERR_POS);
        }

        if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))/*no more to search*/
        {
            rlog(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, return err_pos, target dflag %u, item dflag %u\n",
                                CRFSNP_ID(crfsnp), dflag, CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
            return (CRFSNPRB_ERR_POS);
        }

        if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))/*search sons*/
        {
            rlog(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, item is dir\n",
                                CRFSNP_ID(crfsnp));

            path_seg_beg = (uint8_t *)path_seg_end;
            path_seg_len = crfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            if(1 == path_seg_len && '*' == (char)(*path_seg_beg))
            {
                rlog(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, [*] left path: '%.*s'\n",
                                    CRFSNP_ID(crfsnp), path_len - (path_seg_beg - 1 - path), path_seg_beg - 1);

                node_pos = crfsnp_dnode_match(crfsnp, CRFSNP_DNODE_ROOT_POS(CRFSNP_ITEM_DNODE(crfsnp_item)),
                                    path_len - (path_seg_beg - 1 - path), path_seg_beg - 1, dflag);

                rlog(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, [*] node_pos %u\n",
                                    CRFSNP_ID(crfsnp), node_pos);

                return (node_pos);
            }
            else
            {
                uint32_t path_seg_2nd_hash;

                path_seg_2nd_hash = CRFSNP_2ND_CHASH_ALGO_COMPUTE(crfsnp, path_seg_len, path_seg_beg);
                node_pos          = crfsnp_dnode_search(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item),
                                                           path_seg_2nd_hash,
                                                           path_seg_len, path_seg_beg);

                rlog(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, [searched] node_pos %u\n",
                                    CRFSNP_ID(crfsnp), node_pos);
            }
            if(CRFSNPRB_ERR_POS == node_pos)/*Oops!*/
            {
                dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_match_no_lock: np %u, node_pos is err_pos, return\n",
                                    CRFSNP_ID(crfsnp));
                return (CRFSNPRB_ERR_POS);
            }
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_match_no_lock_item: np %u, invalid item dir flag %u at node_pos %u\n",
                                CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), node_pos);
            break;
        }
    }

    return (CRFSNPRB_ERR_POS);
}

uint32_t crfsnp_match(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    node_pos = crfsnp_match_no_lock(crfsnp, CRFSNPRB_ROOT_POS, path_len, path, dflag);

    return (node_pos);
}

uint32_t crfsnp_search_no_lock(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;
    uint32_t path_seg_len;
    uint8_t *path_seg_beg;
    uint8_t *path_seg_end;

    path_seg_beg = (uint8_t *)path;
    path_seg_len = 0;
    path_seg_end = (uint8_t *)(path_seg_beg + path_seg_len + 1);/*path always start with '/'*/

    node_pos = 0;/*the first item is root directory*/
    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_search_no_lock: np %u, item pos %u [%.*s]\n",
                        CRFSNP_ID(crfsnp), node_pos, path_len, path);
    while(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;

        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDNULL, "[DEBUG] crfsnp_search_no_lock: np %u, node_pos %u, item pos %u\n",
                            CRFSNP_ID(crfsnp), node_pos, (uint32_t)(node_pos / sizeof(CRFSNP_ITEM)));

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_search_no_lock: np %u, item at node_pos %u was not used\n", CRFSNP_ID(crfsnp), node_pos);
            return (CRFSNPRB_ERR_POS);
        }

        if(EC_FALSE == crfsnp_item_is(crfsnp_item, path_seg_len, path_seg_beg))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_search_no_lock: np %u, check failed where path seg: %.*s\n",
                                CRFSNP_ID(crfsnp), path_seg_len, path_seg_beg);
            return (CRFSNPRB_ERR_POS);
        }

        /*when matched and reached the last path seg*/
        if(path_len <= (uint32_t)(path_seg_end - path))
        {
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] [target dflag %u] crfsnp_search_no_lock: np %u, "
                                "matched and reached end where path_len %u, len from path to path_seg_end is %u, node_pos %u [%.*s]\n",
                                dflag, CRFSNP_ID(crfsnp), path_len, (uint32_t)(path_seg_end - path), node_pos, path_len, path);

            if(CRFSNP_ITEM_FILE_IS_ANY == dflag || dflag == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
            {
                return (node_pos);
            }

            return (CRFSNPRB_ERR_POS);
        }

        if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))/*no more to search*/
        {
            return (CRFSNPRB_ERR_POS);
        }

        if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))/*search sons*/
        {
            uint32_t path_seg_2nd_hash;

            path_seg_beg = (uint8_t *)path_seg_end;
            path_seg_len = crfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            path_seg_2nd_hash = CRFSNP_2ND_CHASH_ALGO_COMPUTE(crfsnp, path_seg_len, path_seg_beg);
            node_pos          = crfsnp_dnode_search(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item),
                                                       path_seg_2nd_hash,
                                                       path_seg_len, path_seg_beg);
            if(CRFSNPRB_ERR_POS == node_pos)/*Oops!*/
            {
                return (CRFSNPRB_ERR_POS);
            }
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_search_no_lock_item: np %u, invalid item dir flag %u at node_pos %u\n",
                                CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), node_pos);
            break;
        }
    }

    return (CRFSNPRB_ERR_POS);
}

uint32_t crfsnp_search(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    node_pos = crfsnp_search_no_lock(crfsnp, path_len, path, dflag);

    return (node_pos);
}

/**
*
* if dflag is DIR or REG or BIG, ignore seg_no
* if dlfag is SEG, seg_no will be used
*
**/
uint32_t crfsnp_insert_no_lock(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;
    uint32_t path_seg_len;
    uint8_t *path_seg_beg;
    uint8_t *path_seg_end;

    if('/' != (*path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_insert_no_lock: np %u, invalid path %.*s\n",
                            CRFSNP_ID(crfsnp), path_len, path);
        return (CRFSNPRB_ERR_POS);
    }

    path_seg_end = (uint8_t *)(path + 1);/*path always start with '/'*/

    node_pos = 0;/*the first item is root directory*/
    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_insert_no_lock: np %u, node_pos %u [%.*s]\n", CRFSNP_ID(crfsnp), node_pos, path_len, path);
    while(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;

        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_insert_no_lock: np %u, node_pos %u\n", CRFSNP_ID(crfsnp), node_pos);

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_insert_no_lock: np %u, node_pos %u,  dir flag %u\n",
                            CRFSNP_ID(crfsnp), node_pos, CRFSNP_ITEM_DIR_FLAG(crfsnp_item));

        if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_insert_no_lock: np %u, find regular file at node_pos %u has same key: %.*s\n",
                                CRFSNP_ID(crfsnp), node_pos, CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));

            return (CRFSNPRB_ERR_POS);
        }

        else if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            uint32_t path_seg_2nd_hash;
            uint32_t parent_node_pos;

            path_seg_beg = (uint8_t *)path_seg_end;
            path_seg_len = crfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_insert_no_lock: path_seg_len %u\n", path_seg_len);
#if 0
            if(CRFSNP_KEY_MAX_SIZE < path_seg_len)
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_insert_no_lock: path_seg_len %u overflow\n", path_seg_len);
                return (CRFSNPRB_ERR_POS);
            }
#endif
            path_seg_2nd_hash = CRFSNP_2ND_CHASH_ALGO_COMPUTE(crfsnp, path_seg_len, path_seg_beg);
            parent_node_pos   = crfsnp_dnode_search(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item),
                                                    path_seg_2nd_hash,
                                                    path_seg_len, path_seg_beg);
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_insert_no_lock: np %u, searched node_pos %u, path_seg_len %u, path_seg_beg: %s\n",
                                CRFSNP_ID(crfsnp),
                                node_pos,
                                path_seg_len, path_seg_beg
                                );
            if(CRFSNPRB_ERR_POS != parent_node_pos)
            {
                node_pos = parent_node_pos;
                continue;
            }

            if(path_len > (uint32_t)(path_seg_end - path))/*create dnode item under parent crfsnp_item*/
            {
                node_pos = crfsnp_dnode_insert(crfsnp,
                                            node_pos,
                                            path_seg_2nd_hash,
                                            path_seg_len,
                                            path_seg_beg,
                                            CRFSNP_ITEM_FILE_IS_DIR
                                            );
                continue;
            }
            else/*create fnode item under parent crfsnp_item*/
            {
                node_pos = crfsnp_dnode_insert(crfsnp,
                                            node_pos,
                                            path_seg_2nd_hash,
                                            path_seg_len,
                                            path_seg_beg,
                                            /*CRFSNP_ITEM_FILE_IS_REG*/dflag
                                            );

                dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_insert_no_lock: np %u, insert at node_pos %u [%.*s]\n",
                                    CRFSNP_ID(crfsnp), node_pos, path_len, path);

                return (node_pos);
            }
        }

        else
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_insert_no_lock: np %u, invalid item dir flag %u at node_pos %u\n",
                                CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), node_pos);
            break;
        }
    }

    return (CRFSNPRB_ERR_POS);
}

uint32_t crfsnp_insert(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    node_pos = crfsnp_insert_no_lock(crfsnp, path_len, path, dflag);

    return (node_pos);
}

CRFSNP_ITEM *crfsnp_fetch(const CRFSNP *crfsnp, const uint32_t node_pos)
{
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        const CRFSNPRB_POOL *pool;
        const CRFSNPRB_NODE *node;

        pool = CRFSNP_ITEMS_POOL(crfsnp);
        node = CRFSNPRB_POOL_NODE(pool, node_pos);
        if(NULL_PTR != node)
        {
            return (CRFSNP_ITEM *)CRFSNP_RB_NODE_ITEM(node);
        }
    }
    //dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "[DEBUG] crfsnp_fetch: np %u, fetch crfsnprb node %u failed\n", CRFSNP_ID(crfsnp), node_pos);
    return (NULL_PTR);
}

EC_BOOL crfsnp_inode_update(CRFSNP *crfsnp, CRFSNP_INODE *crfsnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(src_disk_no  == CRFSNP_INODE_DISK_NO(crfsnp_inode)
    && src_block_no == CRFSNP_INODE_BLOCK_NO(crfsnp_inode)
    && src_page_no  == CRFSNP_INODE_PAGE_NO(crfsnp_inode))
    {
        CRFSNP_INODE_DISK_NO(crfsnp_inode)  = des_disk_no;
        CRFSNP_INODE_BLOCK_NO(crfsnp_inode) = des_block_no;
        CRFSNP_INODE_PAGE_NO(crfsnp_inode)  = des_page_no;
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_fnode_update(CRFSNP *crfsnp, CRFSNP_FNODE *crfsnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t replica;

    for(replica = 0; replica < CRFSNP_FNODE_REPNUM(crfsnp_fnode); replica ++)
    {
        crfsnp_inode_update(crfsnp, CRFSNP_FNODE_INODE(crfsnp_fnode, replica),
                            src_disk_no, src_block_no, src_page_no,
                            des_disk_no, des_block_no, des_page_no);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsnp_bucket_update(CRFSNP * crfsnp, CRFSNPRB_POOL *pool, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CRFSNPRB_NODE *node;
    CRFSNP_ITEM   *item;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        __crfsnp_bucket_update(crfsnp, pool, CRFSNPRB_NODE_LEFT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    item = CRFSNP_RB_NODE_ITEM(node);

    crfsnp_item_update(crfsnp, item,
                       src_disk_no, src_block_no, src_page_no,
                       des_disk_no, des_block_no, des_page_no);


    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        __crfsnp_bucket_update(crfsnp, pool, CRFSNPRB_NODE_RIGHT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_bucket_update(CRFSNP *crfsnp, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CRFSNPRB_POOL *pool;
    pool = CRFSNP_ITEMS_POOL(crfsnp);

    return __crfsnp_bucket_update(crfsnp, pool, node_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);
}

EC_BOOL crfsnp_dnode_update(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    uint32_t root_pos;

    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(EC_FALSE == crfsnp_bucket_update(crfsnp, root_pos,
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_dnode_update: update root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_item_update(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_update: item was not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        return crfsnp_fnode_update(crfsnp, CRFSNP_ITEM_FNODE(crfsnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        return crfsnp_dnode_update(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no);

    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_update: invalid item dflag %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

EC_BOOL crfsnp_update_no_lock(CRFSNP *crfsnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t offset;
    CRFSNP_ITEM *crfsnp_item;

    offset = 0;/*the first item is root directory*/
    crfsnp_item = crfsnp_fetch(crfsnp, offset);
    return crfsnp_item_update(crfsnp, crfsnp_item,
                              src_disk_no, src_block_no, src_page_no,
                              des_disk_no, des_block_no, des_page_no);    /*recursively*/
}

STATIC_CAST static EC_BOOL __crfsnp_bucket_expire(CRFSNP * crfsnp, CRFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CRFSNPRB_NODE *node;
    CRFSNP_ITEM   *item;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        __crfsnp_bucket_expire(crfsnp, pool, CRFSNPRB_NODE_LEFT_POS(node));
    }

    item = CRFSNP_RB_NODE_ITEM(node);

    crfsnp_item_expire(crfsnp, item);


    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        __crfsnp_bucket_expire(crfsnp, pool, CRFSNPRB_NODE_RIGHT_POS(node));
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_bucket_expire(CRFSNP *crfsnp, const uint32_t node_pos)
{
    CRFSNPRB_POOL *pool;
    pool = CRFSNP_ITEMS_POOL(crfsnp);

    return __crfsnp_bucket_expire(crfsnp, pool, node_pos);
}

EC_BOOL crfsnp_dnode_expire(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode)
{
    uint32_t root_pos;

    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(EC_FALSE == crfsnp_bucket_expire(crfsnp, root_pos))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_dnode_expire: expire root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_item_expire(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item)
{
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_expire: item was not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_expire: obsolete interface\n");
        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        return crfsnp_dnode_expire(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item));
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_expire: invalid item dflag %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __crfsnp_bucket_walk(CRFSNP * crfsnp, CRFSNPRB_POOL *pool, const uint32_t node_pos, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    CRFSNPRB_NODE *node;
    CRFSNP_ITEM   *item;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        __crfsnp_bucket_walk(crfsnp, pool, CRFSNPRB_NODE_LEFT_POS(node), crfsnp_dit_node);
    }

    item = CRFSNP_RB_NODE_ITEM(node);

    crfsnp_item_walk(crfsnp, item, node_pos, crfsnp_dit_node);

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        __crfsnp_bucket_walk(crfsnp, pool, CRFSNPRB_NODE_RIGHT_POS(node), crfsnp_dit_node);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_bucket_walk(CRFSNP *crfsnp, const uint32_t node_pos, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    CRFSNPRB_POOL *pool;
    pool = CRFSNP_ITEMS_POOL(crfsnp);

    return __crfsnp_bucket_walk(crfsnp, pool, node_pos, crfsnp_dit_node);
}

EC_BOOL crfsnp_dnode_walk(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    uint32_t root_pos;

    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(EC_FALSE == crfsnp_bucket_walk(crfsnp, root_pos, crfsnp_dit_node))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_dnode_walk: walk root_pos %u failed\n", root_pos);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_item_walk(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_walk: item was not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cstack_push(CRFSNP_DIT_NODE_STACK(crfsnp_dit_node), (void *)crfsnp_item);
        CRFSNP_DIT_NODE_HANDLER(crfsnp_dit_node)(crfsnp_dit_node, crfsnp, crfsnp_item, node_pos);
        cstack_pop(CRFSNP_DIT_NODE_STACK(crfsnp_dit_node));
        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        EC_BOOL ret;

        cstack_push(CRFSNP_DIT_NODE_STACK(crfsnp_dit_node), (void *)crfsnp_item);
        CRFSNP_DIT_NODE_HANDLER(crfsnp_dit_node)(crfsnp_dit_node, crfsnp, crfsnp_item, node_pos);
        ret = crfsnp_dnode_walk(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item), crfsnp_dit_node);
        cstack_pop(CRFSNP_DIT_NODE_STACK(crfsnp_dit_node));

        return (ret);
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_item_walk: invalid item dflag %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

CRFSNP_ITEM *crfsnp_set(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t     node_pos;
    CRFSNP_ITEM *crfsnp_item;

    node_pos = crfsnp_insert(crfsnp, path_len, path, dflag);
    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(NULL_PTR != crfsnp_item)
    {
        crfsnplru_node_add_head(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
        return (crfsnp_item);
    }
    return (NULL_PTR);
}

CRFSNP_ITEM *crfsnp_get(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CRFSNP_ITEM_FILE_IS_DIR != dflag && CRFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (NULL_PTR);
        }

        return crfsnp_fetch(crfsnp, crfsnp_search(crfsnp, path_len - 1, path, CRFSNP_ITEM_FILE_IS_DIR));
    }
    return crfsnp_fetch(crfsnp, crfsnp_search(crfsnp, path_len, path, dflag));
}

EC_BOOL crfsnp_delete(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    CRFSNP_ITEM *crfsnp_item;
    uint32_t node_pos;

    if('/' != (*path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_delete: np %u, invalid path %.*s\n", CRFSNP_ID(crfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CRFSNP_ITEM_FILE_IS_DIR != dflag && CRFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = crfsnp_search_no_lock(crfsnp, path_len - 1, path, CRFSNP_ITEM_FILE_IS_DIR);
        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    }
    else
    {
        node_pos = crfsnp_search_no_lock(crfsnp, path_len, path, dflag);
        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    }

    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {        
        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item))
        {
            CRFSNP_ITEM *crfsnp_item_parent;
            uint32_t     node_pos_t;

            crfsnp_item_parent = crfsnp_fetch(crfsnp, CRFSNP_ITEM_PARENT_POS(crfsnp_item));
            node_pos_t    = crfsnp_dnode_umount_son(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item_parent), node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));

            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                crfsnprb_node_free(CRFSNP_ITEMS_POOL(crfsnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_delete: np %u, path %.*s, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp), path_len, (char *)path,
                                node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item), node_pos_t);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/
            }
        }

        crfsnp_item_clean(crfsnp_item);

        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item))
        {
            CRFSNP_ITEM *crfsnp_item_parent;
            uint32_t     node_pos_t;

            crfsnp_item_parent = crfsnp_fetch(crfsnp, CRFSNP_ITEM_PARENT_POS(crfsnp_item));

            node_pos_t    = crfsnp_dnode_umount_son(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item_parent), node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));

            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);
            if(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                crfsnp_dnode_delete_dir_son(crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item));

                crfsnprb_node_free(CRFSNP_ITEMS_POOL(crfsnp), node_pos);
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_delete: np %u, path %.*s, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp), path_len, (char *)path,
                                node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item), node_pos_t);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/
            }
        }

        crfsnp_item_clean(crfsnp_item);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_expire(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    CRFSNP_ITEM *crfsnp_item;

    if('/' != (*path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_expire: np %u, invalid path %.*s\n", CRFSNP_ID(crfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CRFSNP_ITEM_FILE_IS_DIR != dflag && CRFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (EC_FALSE);
        }

        crfsnp_item = crfsnp_fetch(crfsnp, crfsnp_search_no_lock(crfsnp, path_len - 1, path, CRFSNP_ITEM_FILE_IS_DIR));
    }
    else
    {
        crfsnp_item = crfsnp_fetch(crfsnp, crfsnp_search_no_lock(crfsnp, path_len, path, dflag));
    }

    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_item_expire(crfsnp, crfsnp_item))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_retire(CRFSNP *crfsnp, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CRFSNPLRU_NODE  *crfsnplru_node_head;
    UINT32   retire_num;

    crfsnplru_node_head = CRFSNP_LRU_LIST(crfsnp);

    for(retire_num = 0; retire_num < expect_retire_num && EC_FALSE == crfsnp_lru_list_is_empty(crfsnp);)
    {
        uint32_t node_pos;
        
        CRFSNP_ITEM *crfsnp_item;

        node_pos = CRFSNPLRU_NODE_PREV_POS(crfsnplru_node_head);
        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);

        /*note: not scan unused node*/
        /*scenario: when np created and rb nodes initialized, item used-flag was not set yet...*/
        if(EC_FALSE == crfsnprb_node_is_used(CRFSNP_ITEMS_POOL(crfsnp), node_pos))
        {
            /*not used item*/
            crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
            continue;
        }
        
        if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
        {
            /*not used item*/
            crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
            continue;
        }        

        if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            /*retire it*/
            if(EC_FALSE == crfsnp_umount_item(crfsnp, node_pos))
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_retire: np %u node_pos %d [REG] failed\n",
                                CRFSNP_ID(crfsnp), node_pos);            
                return (EC_FALSE);
            }

            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_retire: np %u node_pos %d [REG] done\n",
                            CRFSNP_ID(crfsnp), node_pos);
            retire_num ++;
            continue;
        }

        if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            /*retire it despite of dir empty or not*/
            if(EC_FALSE == crfsnp_umount_item(crfsnp, node_pos))
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_retire: np %u node_pos %d [DIR] failed\n",
                                CRFSNP_ID(crfsnp), node_pos);            
                return (EC_FALSE);
            }

            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_retire: np %u node_pos %d [DIR] done\n",
                            CRFSNP_ID(crfsnp), node_pos);
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

EC_BOOL crfsnp_walk(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    CRFSNP_ITEM *crfsnp_item;
    uint32_t     node_pos;

    if('/' != (*path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_walk: np %u, invalid path %.*s\n", CRFSNP_ID(crfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CRFSNP_ITEM_FILE_IS_DIR != dflag && CRFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = crfsnp_search_no_lock(crfsnp, path_len - 1, path, CRFSNP_ITEM_FILE_IS_DIR);
        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    }
    else
    {
        node_pos = crfsnp_search_no_lock(crfsnp, path_len, path, dflag);
        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    }

    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_item_walk(crfsnp, crfsnp_item, node_pos, crfsnp_dit_node))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_move(CRFSNP *src_crfsnp, CRFSNP *des_crfsnp,
                          const uint32_t src_path_len, const uint8_t *src_path,
                          const uint32_t des_path_len, const uint8_t *des_path,
                          const uint32_t dflag)
{
    CRFSNP_ITEM *crfsnp_item_src;
    CRFSNP_ITEM *crfsnp_item_des;
    uint32_t     node_pos_src;
    uint32_t     node_pos_des;

    //dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_move: src_crfsnp %p, des_crfsnp %p, %s -> %s\n", src_crfsnp, des_crfsnp, (char *)src_path, (char *)des_path);

    ASSERT(src_crfsnp == des_crfsnp);/*otherwise, des_crfsnp should be locked in this function*/

    if('/' != (*src_path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_move: np %u, invalid src_path %.*s\n", CRFSNP_ID(src_crfsnp), src_path_len, (char *)src_path);
        return (EC_FALSE);
    }

    if('/' != (*des_path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_move: np %u, invalid des_path %.*s\n", CRFSNP_ID(src_crfsnp), des_path_len, (char *)des_path);
        return (EC_FALSE);
    }

    if(src_path_len > 0 && '/' == *(src_path + src_path_len - 1))/*directory*/
    {
        if(CRFSNP_ITEM_FILE_IS_DIR != dflag && CRFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (EC_FALSE);
        }

        node_pos_src = crfsnp_search_no_lock(src_crfsnp, src_path_len - 1, src_path, CRFSNP_ITEM_FILE_IS_DIR);
        crfsnp_item_src = crfsnp_fetch(src_crfsnp, node_pos_src);
    }
    else/*regular file*/
    {
        node_pos_src = crfsnp_search_no_lock(src_crfsnp, src_path_len, src_path, dflag);
        crfsnp_item_src = crfsnp_fetch(src_crfsnp, node_pos_src);
    }

    if(NULL_PTR == crfsnp_item_src)
    {
        return (EC_FALSE);
    }

    //dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_move: des crfsnp %p, header %p, %s -> %s\n", des_crfsnp, CRFSNP_HDR(des_crfsnp), (char *)src_path, (char *)des_path);

    /*insert to des np*/
    node_pos_des = crfsnp_insert_no_lock(des_crfsnp, des_path_len, des_path, dflag);
    if(CRFSNPRB_ERR_POS == node_pos_des)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_move: insert %.*s with dflag %x failed\n", des_path_len, des_path, dflag);
        return (EC_FALSE);
    }
    crfsnp_item_des = crfsnp_fetch(des_crfsnp, node_pos_des);

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src))
    {
        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item_src))
        {
            CRFSNP_ITEM *crfsnp_item_parent;
            uint32_t node_pos;

            crfsnp_item_parent = crfsnp_fetch(src_crfsnp, CRFSNP_ITEM_PARENT_POS(crfsnp_item_src));

            node_pos    = crfsnp_dnode_umount_son(src_crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item_parent), node_pos_src,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item_src),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item_src), CRFSNP_ITEM_KEY(crfsnp_item_src));
            //ASSERT(CRFSNPRB_ERR_POS != node_pos && node_pos_src == node_pos);

            if(CRFSNPRB_ERR_POS != node_pos && node_pos_src == node_pos)
            {
                crfsnp_item_move(crfsnp_item_src, crfsnp_item_des);
                crfsnp_item_clean(crfsnp_item_src);
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_move: np %u, path %.*s, found inconsistency: [REG] src node %u, parent %u => %u\n",
                                CRFSNP_ID(src_crfsnp), src_path_len, (char *)src_path,
                                node_pos_src, CRFSNP_ITEM_PARENT_POS(crfsnp_item_src), node_pos);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item_src) = CRFSNPRB_ERR_POS; /*fix*/
            }
        }

        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_src))
    {
        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item_src))
        {
            CRFSNP_ITEM *crfsnp_item_parent;
            uint32_t node_pos;

            crfsnp_item_parent = crfsnp_fetch(src_crfsnp, CRFSNP_ITEM_PARENT_POS(crfsnp_item_src));

            node_pos    = crfsnp_dnode_umount_son(src_crfsnp, CRFSNP_ITEM_DNODE(crfsnp_item_parent), node_pos_src,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item_src),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item_src), CRFSNP_ITEM_KEY(crfsnp_item_src));
            //ASSERT(CRFSNPRB_ERR_POS != node_pos && node_pos_src == node_pos);

            if(CRFSNPRB_ERR_POS != node_pos && node_pos_src == node_pos)
            {
                crfsnp_item_move(crfsnp_item_src, crfsnp_item_des);
                crfsnp_item_clean(crfsnp_item_src);
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_move: np %u, path %.*s, found inconsistency: [DIR] src node %u, parent %u => %u\n",
                                CRFSNP_ID(src_crfsnp), src_path_len, (char *)src_path,
                                node_pos_src, CRFSNP_ITEM_PARENT_POS(crfsnp_item_src), node_pos);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item_src) = CRFSNPRB_ERR_POS; /*fix*/
            }
        }

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_umount_item(CRFSNP *crfsnp, const uint32_t node_pos)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);

    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }

#if 0
    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && 0 == CRFSNP_ITEM_KLEN(crfsnp_item))
    {

        return (EC_TRUE);
    }
#endif

    if(0 == node_pos
    && CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && 0 == CRFSNP_ITEM_KLEN(crfsnp_item))
    {
        const CRFSNPRB_POOL *pool;
        CRFSNP_DNODE        *crfsnp_dnode;

        pool            = CRFSNP_ITEMS_POOL(crfsnp);
        crfsnp_dnode    = CRFSNP_ITEM_DNODE(crfsnp_item);

        for(;;)
        {
            uint32_t         root_pos;
            uint32_t         first_node_pos;

            CRFSNP_ITEM     *crfsnp_item_first;

            CRFSNP_ITEM     *crfsnp_item_parent;
            CRFSNP_DNODE    *parent_dnode;
            uint32_t         parent_node_pos;
            uint32_t         node_pos_t;

            root_pos            = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
            if(CRFSNPRB_ERR_POS == root_pos)
            {
                break;
            }

            first_node_pos      = crfsnprb_tree_first_node(pool, root_pos);
            crfsnp_item_first   = crfsnp_fetch(crfsnp, first_node_pos);
            if(CRFSNPRB_ERR_POS == CRFSNP_ITEM_PARENT_POS(crfsnp_item_first))
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item: np %u, root %u, first node %u => no parent\n",
                                    CRFSNP_ID(crfsnp), root_pos, first_node_pos);
                break;
            }

            parent_node_pos     = CRFSNP_ITEM_PARENT_POS(crfsnp_item_first);

            crfsnp_item_parent  = crfsnp_fetch(crfsnp, parent_node_pos);
            parent_dnode        = CRFSNP_ITEM_DNODE(crfsnp_item_parent);

            node_pos_t  = crfsnp_dnode_umount_son(crfsnp, parent_dnode, first_node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item_first),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item_first), CRFSNP_ITEM_KEY(crfsnp_item_first));

            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t);

            if(CRFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t)
            {
                CRFSNP_ITEM_PARENT_POS(crfsnp_item_first) = CRFSNPRB_ERR_POS; /*fix*/

                crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item_first), first_node_pos);
                crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item_first), first_node_pos);
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item: np %u, found inconsistency: [ANY] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp),
                                first_node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item_first), node_pos_t);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item_first) = CRFSNPRB_ERR_POS; /*fix*/
                break; /*terminate loop*/
            }
        }

        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_FNODE *crfsnp_fnode;

        crfsnp_fnode = CRFSNP_ITEM_FNODE(crfsnp_item);
        CRFSNP_DEL_SIZE(crfsnp) += CRFSNP_FNODE_FILESZ(crfsnp_fnode);

        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item))
        {
            CRFSNP_ITEM  *crfsnp_item_parent;
            CRFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CRFSNP_ITEM_PARENT_POS(crfsnp_item);
            crfsnp_item_parent = crfsnp_fetch(crfsnp, parent_node_pos);
            //ASSERT(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_parent)); /*debug*/
            parent_dnode       = CRFSNP_ITEM_DNODE(crfsnp_item_parent);

            node_pos_t    = crfsnp_dnode_umount_son(crfsnp, parent_dnode, node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));
            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp),
                                node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item), node_pos_t);
                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/
            }
        }

        crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
        crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);        

        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item))
        {
            CRFSNP_ITEM  *crfsnp_item_parent;
            CRFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CRFSNP_ITEM_PARENT_POS(crfsnp_item);
            crfsnp_item_parent = crfsnp_fetch(crfsnp, parent_node_pos);
            //ASSERT(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item_parent)); /*debug*/
            parent_dnode       = CRFSNP_ITEM_DNODE(crfsnp_item_parent);

            node_pos_t    = crfsnp_dnode_umount_son(crfsnp, parent_dnode, node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));

            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item: np %u, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp),
                                node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item), node_pos_t);
                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/
            }
        }

        crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
        crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfsnp_umount_item_deep(CRFSNP *crfsnp, const uint32_t node_pos)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);

    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }
#if 0
    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && 0 == CRFSNP_ITEM_KLEN(crfsnp_item))
    {
        return (EC_TRUE);
    }
#endif

    if(0 == node_pos
    && CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && 0 == CRFSNP_ITEM_KLEN(crfsnp_item))
    {
        const CRFSNPRB_POOL *pool;
        CRFSNP_DNODE        *crfsnp_dnode;

        pool            = CRFSNP_ITEMS_POOL(crfsnp);
        crfsnp_dnode    = CRFSNP_ITEM_DNODE(crfsnp_item);

        for(;;)
        {
            uint32_t         root_pos;
            uint32_t         first_node_pos;

            CRFSNP_ITEM     *crfsnp_item_first;
            CRFSNP_ITEM     *crfsnp_item_parent;
            CRFSNP_DNODE    *parent_dnode;
            uint32_t         parent_node_pos;
            uint32_t         node_pos_t;

            root_pos            = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
            if(CRFSNPRB_ERR_POS == root_pos)
            {
                break;
            }

            first_node_pos      = crfsnprb_tree_first_node(pool, root_pos);
            crfsnp_item_first   = crfsnp_fetch(crfsnp, first_node_pos);
            if(CRFSNPRB_ERR_POS == CRFSNP_ITEM_PARENT_POS(crfsnp_item_first))
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item_deep: np %u, root %u, first node %u => no parent\n",
                                    CRFSNP_ID(crfsnp), root_pos, first_node_pos);
                break;
            }

            parent_node_pos     = CRFSNP_ITEM_PARENT_POS(crfsnp_item_first);
            crfsnp_item_parent  = crfsnp_fetch(crfsnp, parent_node_pos);
            parent_dnode        = CRFSNP_ITEM_DNODE(crfsnp_item_parent);

            node_pos_t  = crfsnp_dnode_umount_son(crfsnp, parent_dnode, first_node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item_first),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item_first), CRFSNP_ITEM_KEY(crfsnp_item_first));

            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t);

            if(CRFSNPRB_ERR_POS != node_pos_t && first_node_pos == node_pos_t)
            {
                CRFSNP_ITEM_PARENT_POS(crfsnp_item_first) = CRFSNPRB_ERR_POS; /*fix*/

                crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item_first), first_node_pos);
                crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item_first), first_node_pos);                
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item_deep: np %u, found inconsistency: [ANY] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp),
                                first_node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item_first), node_pos_t);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item_first) = CRFSNPRB_ERR_POS; /*fix*/

                crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item_first), first_node_pos);
                crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item_first), first_node_pos);                

                break; /*terminate loop*/
            }

             /* We now delete the root dir /, this branch means root dir / is already empty (this leads to the root_pos */
             /*   = CRFSNPRB_ERR_POS in next loop), so we can ignore it */
#if 0
            if(0 == CRFSNP_DNODE_FILE_NUM(parent_dnode))
            {
                /*recursively umount parent if it is empty directory*/
                return crfsnp_umount_item_deep(crfsnp, parent_node_pos);
            }
#endif
        }

        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_FNODE *crfsnp_fnode;

        crfsnp_fnode = CRFSNP_ITEM_FNODE(crfsnp_item);
        CRFSNP_DEL_SIZE(crfsnp) += CRFSNP_FNODE_FILESZ(crfsnp_fnode);

        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item))
        {
            CRFSNP_ITEM  *crfsnp_item_parent;
            CRFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CRFSNP_ITEM_PARENT_POS(crfsnp_item);
            crfsnp_item_parent = crfsnp_fetch(crfsnp, parent_node_pos);
            parent_dnode       = CRFSNP_ITEM_DNODE(crfsnp_item_parent);

            node_pos_t    = crfsnp_dnode_umount_son(crfsnp, parent_dnode, node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));
            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/

                crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
                crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);                
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item_deep: np %u, found inconsistency: [REG] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp),
                                node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item), node_pos_t);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/

                crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
                crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);                
            }

            if(0 == CRFSNP_DNODE_FILE_NUM(parent_dnode))
            {
                /*recursively umount parent if it is empty directory*/
                return crfsnp_umount_item_deep(crfsnp, parent_node_pos);
            }
        }
        else
        {
            crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
            crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        if(CRFSNPRB_ERR_POS != CRFSNP_ITEM_PARENT_POS(crfsnp_item))
        {
            CRFSNP_ITEM  *crfsnp_item_parent;
            CRFSNP_DNODE *parent_dnode;
            uint32_t      parent_node_pos;
            uint32_t      node_pos_t;

            parent_node_pos    = CRFSNP_ITEM_PARENT_POS(crfsnp_item);
            crfsnp_item_parent = crfsnp_fetch(crfsnp, parent_node_pos);
            parent_dnode       = CRFSNP_ITEM_DNODE(crfsnp_item_parent);

            node_pos_t    = crfsnp_dnode_umount_son(crfsnp, parent_dnode, node_pos,
                                                  CRFSNP_ITEM_SECOND_HASH(crfsnp_item),
                                                  CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KEY(crfsnp_item));

            //ASSERT(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t);

            if(CRFSNPRB_ERR_POS != node_pos_t && node_pos == node_pos_t)
            {
                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/

                crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
                crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);                
            }
            else
            {
                dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_item_deep: np %u, found inconsistency: [DIR] node %u, parent %u => %u\n",
                                CRFSNP_ID(crfsnp),
                                node_pos, CRFSNP_ITEM_PARENT_POS(crfsnp_item), node_pos_t);

                CRFSNP_ITEM_PARENT_POS(crfsnp_item) = CRFSNPRB_ERR_POS; /*fix*/

                crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
                crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);                
            }

            if(0 == CRFSNP_DNODE_FILE_NUM(parent_dnode))
            {
                /*recursively umount parent if it is empty directory*/
                return crfsnp_umount_item_deep(crfsnp, parent_node_pos);
            }
        }
        else
        {
            crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);
            crfsnpdel_node_add_tail(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfsnp_umount(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    if('/' != (*path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount: np %u, invalid path %.*s\n", CRFSNP_ID(crfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))/*directory*/
    {
        if(CRFSNP_ITEM_FILE_IS_DIR != dflag && CRFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = crfsnp_search_no_lock(crfsnp, path_len - 1, path, CRFSNP_ITEM_FILE_IS_DIR);
    }
    else/*regular file*/
    {
        node_pos = crfsnp_search_no_lock(crfsnp, path_len, path, dflag);
    }

    if(EC_FALSE == crfsnp_umount_item(crfsnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/* path has wildcard seg '*' */
EC_BOOL crfsnp_umount_wildcard(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t node_pos;

    if('/' != (*path))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_umount_wildcard: np %u, invalid path %.*s\n", CRFSNP_ID(crfsnp), path_len, (char *)path);
        return (EC_FALSE);
    }

    if(path_len > 0 && '/' == *(path + path_len - 1))/*directory*/
    {
        if(CRFSNP_ITEM_FILE_IS_DIR != dflag && CRFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (EC_FALSE);
        }

        node_pos = crfsnp_match_no_lock(crfsnp, CRFSNPRB_ROOT_POS, path_len - 1, path, CRFSNP_ITEM_FILE_IS_DIR);
    }
    else/*regular file*/
    {
        node_pos = crfsnp_match_no_lock(crfsnp, CRFSNPRB_ROOT_POS, path_len, path, dflag);
    }

    if(EC_FALSE == crfsnp_umount_item(crfsnp, node_pos))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_path_name(const CRFSNP *crfsnp, const uint32_t node_pos, const uint32_t path_max_len, uint32_t *path_len, uint8_t *path)
{
    CSTACK   *cstack;
    uint32_t  cur_node_pos;
    uint32_t  cur_path_len;

    cstack = cstack_new(MM_IGNORE, LOC_CRFSNP_0061);

    cur_node_pos = node_pos;
    while(CRFSNPRB_ERR_POS != cur_node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;
        UINT32 cur_node_pos_t;

        cur_node_pos_t = cur_node_pos;
        cstack_push(cstack, (void *)cur_node_pos_t);

        crfsnp_item = crfsnp_fetch(crfsnp, cur_node_pos);
        cur_node_pos = CRFSNP_ITEM_PARENT_POS(crfsnp_item);
    }

    cur_path_len = 0;
    path[ 0 ] = '\0';

    while(EC_FALSE == cstack_is_empty(cstack) && cur_path_len < path_max_len)
    {
        CRFSNP_ITEM *crfsnp_item;
        UINT32       cur_node_pos_t;

        cur_node_pos_t = (UINT32)cstack_pop(cstack);
        cur_node_pos   = (uint32_t)cur_node_pos_t;
        crfsnp_item    = crfsnp_fetch(crfsnp, cur_node_pos);

        if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            cur_path_len += snprintf((char *)path + cur_path_len, path_max_len - cur_path_len, "%.*s/",
                                    CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        }
        else if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            cur_path_len += snprintf((char *)path + cur_path_len, path_max_len - cur_path_len, "%.*s",
                                    CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_path_name: np %u, invalid dir flag %u at offset %u\n",
                                CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), cur_node_pos);
        }
    }

    (*path_len) = cur_path_len;
    path[ cur_path_len ] = '\0';

    cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
    cstack_free(cstack, LOC_CRFSNP_0062);
    return (EC_TRUE);
}

EC_BOOL crfsnp_path_name_cstr(const CRFSNP *crfsnp, const uint32_t node_pos, CSTRING *path_cstr)
{
    CSTACK *cstack;
    uint32_t  cur_node_pos;

    cstack = cstack_new(MM_IGNORE, LOC_CRFSNP_0063);

    cur_node_pos = node_pos;
    while(CRFSNPRB_ERR_POS != cur_node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;
        UINT32       cur_node_pos_t;

        cur_node_pos_t = cur_node_pos;
        cstack_push(cstack, (void *)cur_node_pos_t);

        crfsnp_item = crfsnp_fetch(crfsnp, cur_node_pos);
        cur_node_pos  = CRFSNP_ITEM_PARENT_POS(crfsnp_item);
    }

    while(EC_FALSE == cstack_is_empty(cstack))
    {
        CRFSNP_ITEM *crfsnp_item;
        UINT32       cur_node_pos_t;

        cur_node_pos_t = (UINT32)cstack_pop(cstack);
        cur_node_pos   = (uint32_t)cur_node_pos_t;
        crfsnp_item    = crfsnp_fetch(crfsnp, cur_node_pos);

        if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            cstring_format(path_cstr, "%.*s/", CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        }
        else if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            cstring_format(path_cstr, "%.*s", CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_path_name_cstr: np %u, invalid dir flag %u at offset %u\n",
                                CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), cur_node_pos);
        }
    }

    cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
    cstack_free(cstack, LOC_CRFSNP_0064);
    return (EC_TRUE);
}

EC_BOOL crfsnp_seg_name(const CRFSNP *crfsnp, const uint32_t offset, const uint32_t seg_name_max_len, uint32_t *seg_name_len, uint8_t *seg_name)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_fetch(crfsnp, offset);

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        (*seg_name_len) = snprintf((char *)seg_name, seg_name_max_len, "%.*s/",
                                CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        return (EC_TRUE);
    }
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        (*seg_name_len) = snprintf((char *)seg_name, seg_name_max_len, "%.*s",
                                CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        return (EC_TRUE);
    }
    
    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_seg_name: np %u, invalid dir flag %u at offset %u\n",
                        CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), offset);
    return (EC_FALSE);
}

EC_BOOL crfsnp_seg_name_cstr(const CRFSNP *crfsnp, const uint32_t offset, CSTRING *seg_cstr)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_fetch(crfsnp, offset);
    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cstring_format(seg_cstr, "%.*s/", CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        return (EC_TRUE);
    }
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        cstring_format(seg_cstr, "%.*s", CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        return (EC_TRUE);
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_seg_name_cstr: np %u, invalid dir flag %u at offset %u\n",
                        CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), offset);
    return (EC_FALSE);
}


STATIC_CAST static EC_BOOL __crfsnp_list_path_vec(const CRFSNP *crfsnp, const uint32_t node_pos, const uint8_t *prev_path_str, CVECTOR *path_cstr_vec)
{
    const CRFSNPRB_POOL *pool;
    const CRFSNPRB_NODE *node;
    CSTRING *full_path_cstr;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CRFSNP_ITEMS_POOL(crfsnp);

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        __crfsnp_list_path_vec(crfsnp, CRFSNPRB_NODE_LEFT_POS(node), prev_path_str, path_cstr_vec);
    }

    full_path_cstr = cstring_new(prev_path_str, LOC_CRFSNP_0065);
    if(NULL_PTR == full_path_cstr)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_list_path_vec: np %u, new cstring from %s failed\n",
                            CRFSNP_ID(crfsnp), prev_path_str);
        return (EC_FALSE);
    }

    crfsnp_seg_name_cstr(crfsnp, node_pos, full_path_cstr);

    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_list_path_vec: np %u, node_pos son %u, %s\n",
                        CRFSNP_ID(crfsnp), node_pos, (char *)cstring_get_str(full_path_cstr));

    if(CVECTOR_ERR_POS == cvector_search_front(path_cstr_vec, (void *)full_path_cstr, (CVECTOR_DATA_CMP)cstring_is_equal))
    {
        cvector_push(path_cstr_vec, (void *)full_path_cstr);
    }
    else
    {
        cstring_free(full_path_cstr);
    }

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        __crfsnp_list_path_vec(crfsnp, CRFSNPRB_NODE_RIGHT_POS(node), prev_path_str, path_cstr_vec);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_list_path_vec(const CRFSNP *crfsnp, const uint32_t node_pos, CVECTOR *path_cstr_vec)
{
    CRFSNP_ITEM *crfsnp_item;
    CSTRING *path_cstr;

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(NULL_PTR == crfsnp_item)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_list_path_vec: np %u, item is null at node_pos %u\n", CRFSNP_ID(crfsnp), node_pos);
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_list_path_vec: np %u, invalid dir flag %u at node_pos %u\n",
                            CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), node_pos);
        return (EC_FALSE);
    }

    path_cstr = cstring_new(NULL_PTR, LOC_CRFSNP_0066);
    if(NULL_PTR == path_cstr)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_list_path_vec: np %u, new path cstr failed\n", CRFSNP_ID(crfsnp));
        return (EC_FALSE);
    }

    crfsnp_path_name_cstr(crfsnp, node_pos, path_cstr);

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
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

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_DNODE *crfsnp_dnode;
        uint32_t son_node_pos;

        crfsnp_dnode = (CRFSNP_DNODE *)CRFSNP_ITEM_DNODE(crfsnp_item);

        son_node_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDNULL, "[DEBUG] crfsnp_list_path_vec: np %u, node_pos son %u\n",
                            CRFSNP_ID(crfsnp), son_node_pos);
        __crfsnp_list_path_vec(crfsnp, son_node_pos, cstring_get_str(path_cstr), path_cstr_vec);


        cstring_free(path_cstr);
        return (EC_TRUE);
    }

    /*never reach here*/
    return (EC_FALSE);
}

EC_BOOL crfsnp_list_seg_vec(const CRFSNP *crfsnp, const uint32_t node_pos, CVECTOR *seg_cstr_vec)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(NULL_PTR == crfsnp_item)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_list_seg_vec: np %u, item is null at node_pos %u\n",
                            CRFSNP_ID(crfsnp), node_pos);
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_list_seg_vec: np %u, invalid dir flag %u at node_pos %u\n",
                            CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item), node_pos);
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CSTRING *seg_name_cstr;

        seg_name_cstr = cstring_new(NULL_PTR, LOC_CRFSNP_0067);
        if(NULL_PTR == seg_name_cstr)
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_list_seg_vec: np %u, new seg str failed\n", CRFSNP_ID(crfsnp));
            return (EC_FALSE);
        }

        crfsnp_seg_name_cstr(crfsnp, node_pos, seg_name_cstr);

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

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_DNODE *crfsnp_dnode;
        uint32_t son_node_pos;

        crfsnp_dnode = (CRFSNP_DNODE *)CRFSNP_ITEM_DNODE(crfsnp_item);

        son_node_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
        crfsnp_list_path_vec(crfsnp, son_node_pos, seg_cstr_vec);

        return (EC_TRUE);
    }

    /*never reach here*/
    return (EC_FALSE);
}

EC_BOOL crfsnp_file_num(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_num)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_get(crfsnp, path_len, path, CRFSNP_ITEM_FILE_IS_ANY);
    if(NULL_PTR == crfsnp_item)
    {
        (*file_num) = 0;
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        (*file_num) = 1;
        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_DNODE *crfsnp_dnode;
        crfsnp_dnode = CRFSNP_ITEM_DNODE(crfsnp_item);

        (*file_num) = CRFSNP_DNODE_FILE_NUM(crfsnp_dnode);
        return (EC_TRUE);
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_file_num: np %u, invalid dflg %x\n", CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

EC_BOOL crfsnp_file_size(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, uint64_t *file_size)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_get(crfsnp, path_len, path, CRFSNP_ITEM_FILE_IS_ANY);
    if(NULL_PTR == crfsnp_item)
    {
        (*file_size) = 0;
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_FNODE *crfsnp_fnode;
        crfsnp_fnode = CRFSNP_ITEM_FNODE(crfsnp_item);

        (*file_size) = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
        return (EC_TRUE);
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_file_size: np %u, invalid dflg %x\n", CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

EC_BOOL crfsnp_file_md5sum(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, CMD5_DIGEST *md5sum)
{
    CRFSNP_ITEM *crfsnp_item;

    crfsnp_item = crfsnp_get(crfsnp, path_len, path, CRFSNP_ITEM_FILE_IS_ANY);
    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_FNODE *crfsnp_fnode;
        crfsnp_fnode = CRFSNP_ITEM_FNODE(crfsnp_item);

        if(do_log(SEC_0081_CRFSNP, 9))
        {
            dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_file_md5sum: file '%.*s' => fnode\n", path_len, path);
            crfsnp_fnode_print(LOGSTDOUT, crfsnp_fnode);
        }

        BCOPY(CRFSNP_FNODE_MD5SUM(crfsnp_fnode), CMD5_DIGEST_SUM(md5sum), CMD5_DIGEST_LEN);
        return (EC_TRUE);
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_file_md5sum: np %u, invalid dflg %x\n", CRFSNP_ID(crfsnp), CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

EC_BOOL crfsnp_mkdirs(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path)
{
    if(CRFSNPRB_ERR_POS == crfsnp_insert(crfsnp, path_len, path, CRFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_mkdirs: mkdirs %.*s failed\n", path_len, (char *)path);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CRFSNP *crfsnp_open(const char *np_root_dir, const uint32_t np_id)
{
    UINT32 fsize;
    char *np_fname;
    CRFSNP *crfsnp;
    CRFSNP_HEADER *crfsnp_header;
    int fd;

    np_fname = crfsnp_fname_gen(np_root_dir, np_id);
    if(NULL_PTR == np_fname)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_open: generate np fname from np_root_dir %s failed\n", np_root_dir);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_access(np_fname, F_OK))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_open: np %s not exist, try to create it\n", np_fname);
        safe_free(np_fname, LOC_CRFSNP_0069);
        return (NULL_PTR);
    }

    fd = c_file_open(np_fname, O_RDWR, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_open: open crfsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CRFSNP_0070);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_open: get size of %s failed\n", np_fname);
        safe_free(np_fname, LOC_CRFSNP_0071);
        c_file_close(fd);
        return (NULL_PTR);
    }
    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_open: np %u, fsize %ld\n", np_id, fsize);

    crfsnp_header = crfsnp_header_open(np_id, fsize, fd);
    if(NULL_PTR == crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_open: open crfsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CRFSNP_0072);
        c_file_close(fd);
        return (NULL_PTR);
    }

    crfsnp = crfsnp_new();
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_open: new crfsnp %u failed\n", np_id);
        safe_free(np_fname, LOC_CRFSNP_0073);
        c_file_close(fd);
        crfsnp_header_close(crfsnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }

    CRFSNP_HDR(crfsnp) = crfsnp_header;

    /*shortcut*/
    CRFSNP_LRU_LIST(crfsnp) = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, CRFSNPLRU_ROOT_POS));
    CRFSNP_DEL_LIST(crfsnp) = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, CRFSNPDEL_ROOT_POS));
    
    CRFSNP_2ND_CHASH_ALGO(crfsnp) = chash_algo_fetch(CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header));

    CRFSNP_FD(crfsnp)    = fd;
    CRFSNP_FSIZE(crfsnp) = fsize;
    CRFSNP_FNAME(crfsnp) = (uint8_t *)np_fname;

    ASSERT(np_id == CRFSNP_HEADER_NP_ID(crfsnp_header));

    return (crfsnp);
}

EC_BOOL crfsnp_close(CRFSNP *crfsnp)
{
    if(NULL_PTR != crfsnp)
    {
        uint32_t np_id;

        np_id = CRFSNP_ID(crfsnp); /*save np id info due to CRFSNP_HDR will be destoried immediately*/

        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_close: close np %u beg\n", np_id);
        if(NULL_PTR != CRFSNP_HDR(crfsnp))
        {
            crfsnp_header_close(CRFSNP_HDR(crfsnp), CRFSNP_ID(crfsnp), CRFSNP_FSIZE(crfsnp), CRFSNP_FD(crfsnp));

            CRFSNP_LRU_LIST(crfsnp) = NULL_PTR;
            CRFSNP_DEL_LIST(crfsnp) = NULL_PTR;
            CRFSNP_HDR(crfsnp)      = NULL_PTR;
        }
        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_close: close np %u end\n", np_id);
        crfsnp_free(crfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_sync(CRFSNP *crfsnp)
{
    if(NULL_PTR != crfsnp && NULL_PTR != CRFSNP_HDR(crfsnp))
    {
        crfsnp_header_sync(CRFSNP_HDR(crfsnp), CRFSNP_ID(crfsnp), CRFSNP_FSIZE(crfsnp), CRFSNP_FD(crfsnp));
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_create_root_item(CRFSNP *crfsnp)
{
    CRFSNP_ITEM *crfsnp_item;
    uint32_t     second_hash;
    uint32_t     root_pos;
    uint32_t     insert_pos;
    uint32_t     klen;
    uint8_t      key[ 1 ];

    root_pos = CRFSNPRB_ERR_POS;
    second_hash = 0;
    klen = 0;
    key[0] = '\0';

    if(EC_FALSE == crfsnprb_tree_insert_data(CRFSNP_ITEMS_POOL(crfsnp), &root_pos, second_hash, klen, (uint8_t *)key, &insert_pos))
    {
        dbg_log(SEC_0081_CRFSNP, 1)(LOGSTDOUT, "warn:crfsnp_create_root_item: insert create item failed\n");
        return (EC_FALSE);
    }

    if(0 != insert_pos)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create_root_item: insert root item at pos %u is not zero!\n", insert_pos);
        return (EC_FALSE);
    }

    if(0 != root_pos)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create_root_item: root_pos %u is not zero!\n", root_pos);
        return (EC_FALSE);
    }

    crfsnp_item = crfsnp_fetch(crfsnp, insert_pos);

    CRFSNP_ITEM_DIR_FLAG(crfsnp_item)         = CRFSNP_ITEM_FILE_IS_DIR;
    CRFSNP_ITEM_USED_FLAG(crfsnp_item)        = CRFSNP_ITEM_IS_USED;
    CRFSNP_ITEM_KLEN(crfsnp_item)             = klen;
    CRFSNP_ITEM_PARENT_POS(crfsnp_item)       = CRFSNPRB_ERR_POS;

    /******************************************************************************************************/
    /*when enable this branch, qlist can query root dir "/"; otherwise, qlist query it will return nothing*/
    /*if enable this branch, qlist "/" will run-through all np which is time-cost operation!!!            */
    /******************************************************************************************************/

    //CRFSNP_ITEM_KEY(crfsnp_item)[ 0 ] = '/';/*deprecated*/
    CRFSNP_ITEM_KEY(crfsnp_item)[ 0 ] = key[ 0 ];
    CRFSNP_ITEM_SECOND_HASH(crfsnp_item) = second_hash;

    crfsnp_dnode_init(CRFSNP_ITEM_DNODE(crfsnp_item));

    return (EC_TRUE);
}

CRFSNP *crfsnp_clone(CRFSNP *src_crfsnp, const char *np_root_dir, const uint32_t des_np_id)
{
    CRFSNP  *des_crfsnp;
    CRFSNP_HEADER *src_crfsnp_header;
    CRFSNP_HEADER *des_crfsnp_header;
    char    *des_np_fname;
    int      fd;
    UINT32   fsize;

    src_crfsnp_header = CRFSNP_HDR(src_crfsnp);
    fsize = CRFSNP_FSIZE(src_crfsnp);

    des_np_fname = crfsnp_fname_gen(np_root_dir, des_np_id);
    if(NULL_PTR == des_np_fname)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_clone: generate des_np_fname of np %u, root_dir %s failed\n", des_np_id, np_root_dir);
        return (NULL_PTR);
    }

    if(EC_TRUE == c_file_access(des_np_fname, F_OK))/*exist*/
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_clone: np %u exist already\n", des_np_id);
        safe_free(des_np_fname, LOC_CRFSNP_0074);
        return (NULL_PTR);
    }

    fd = c_file_open(des_np_fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_clone: cannot create np %s\n", des_np_fname);
        safe_free(des_np_fname, LOC_CRFSNP_0075);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_truncate(fd, fsize))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_clone: truncate np %s to size %ld failed\n", des_np_fname, fsize);
        safe_free(des_np_fname, LOC_CRFSNP_0076);
        c_file_close(fd);
        return (NULL_PTR);
    }

    /*clone*/
    des_crfsnp_header = crfsnp_header_clone(src_crfsnp_header, des_np_id, fsize, fd);
    if(NULL_PTR == des_crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_clone: open crfsnp file %s failed\n", des_np_fname);
        safe_free(des_np_fname, LOC_CRFSNP_0077);
        c_file_close(fd);
        return (NULL_PTR);
    }

    des_crfsnp = crfsnp_new();
    if(NULL_PTR == des_crfsnp)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_clone: new crfsnp %u failed\n", des_np_id);
        safe_free(des_np_fname, LOC_CRFSNP_0078);
        crfsnp_header_close(des_crfsnp_header, des_np_id, fsize, fd);
        c_file_close(fd);
        return (NULL_PTR);
    }
    CRFSNP_HDR(des_crfsnp) = des_crfsnp_header;

    /*shortcut*/
    CRFSNP_LRU_LIST(des_crfsnp) = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(des_crfsnp, CRFSNPLRU_ROOT_POS));
    CRFSNP_DEL_LIST(des_crfsnp) = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(des_crfsnp, CRFSNPDEL_ROOT_POS));
    
    CRFSNP_2ND_CHASH_ALGO(des_crfsnp) = chash_algo_fetch(CRFSNP_HEADER_2ND_CHASH_ALGO_ID(des_crfsnp_header));

    CRFSNP_FD(des_crfsnp)    = fd;
    CRFSNP_FSIZE(des_crfsnp) = fsize;
    CRFSNP_FNAME(des_crfsnp) = (uint8_t *)des_np_fname;

    ASSERT(des_np_id == CRFSNP_HEADER_NP_ID(des_crfsnp_header));

    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_clone: clone np %u done\n", des_np_id);

    return (des_crfsnp);
}

CRFSNP *crfsnp_create(const char *np_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id)
{
    CRFSNP  *crfsnp;
    CRFSNP_HEADER * crfsnp_header;
    char    *np_fname;
    int      fd;
    UINT32   fsize;
    uint32_t item_max_num;

    //ASSERT(CRFSNP_ITEM_SIZEOF == sizeof(CRFSNP_HEADER));
    ASSERT(512 == ((unsigned long)(&(((CRFSNP_HEADER *)0)->pool.rb_nodes))));

    if(EC_FALSE == crfsnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    if(EC_FALSE == crfsnp_model_item_max_num(np_model, &item_max_num))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    np_fname = crfsnp_fname_gen(np_root_dir, np_id);
    if(NULL_PTR == np_fname)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: generate np_fname of np %u, root_dir %s failed\n", np_id, np_root_dir);
        return (NULL_PTR);
    }

    if(EC_TRUE == c_file_access(np_fname, F_OK))/*exist*/
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: np %u '%s' exist already\n", np_id, np_fname);
        safe_free(np_fname, LOC_CRFSNP_0079);
        return (NULL_PTR);
    }

    fd = c_file_open(np_fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: cannot create np %s\n", np_fname);
        safe_free(np_fname, LOC_CRFSNP_0080);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_truncate(fd, fsize))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: truncate np %s to size %ld failed\n", np_fname, fsize);
        safe_free(np_fname, LOC_CRFSNP_0081);
        c_file_close(fd);
        return (NULL_PTR);
    }

    crfsnp_header = crfsnp_header_create(np_id, fsize, fd, np_model);
    if(NULL_PTR == crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: open crfsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CRFSNP_0082);
        c_file_close(fd);
        return (NULL_PTR);
    }
    CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header) = hash_2nd_algo_id;

    crfsnp = crfsnp_new();
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_create: new crfsnp %u failed\n", np_id);
        safe_free(np_fname, LOC_CRFSNP_0083);
        c_file_close(fd);
        crfsnp_header_close(crfsnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }
    CRFSNP_HDR(crfsnp) = crfsnp_header;

    /*shortcut*/
    CRFSNP_LRU_LIST(crfsnp) = CRFSNP_ITEM_LRU_NODE(crfsnp_fetch(crfsnp, CRFSNPLRU_ROOT_POS));
    CRFSNP_DEL_LIST(crfsnp) = CRFSNP_ITEM_DEL_NODE(crfsnp_fetch(crfsnp, CRFSNPDEL_ROOT_POS));

    CRFSNP_2ND_CHASH_ALGO(crfsnp) = chash_algo_fetch(CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header));

    CRFSNP_FD(crfsnp)    = fd;
    CRFSNP_FSIZE(crfsnp) = fsize;
    CRFSNP_FNAME(crfsnp) = (uint8_t *)np_fname;

    ASSERT(np_id == CRFSNP_HEADER_NP_ID(crfsnp_header));

    /*create root item*/
    crfsnp_create_root_item(crfsnp);

    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_create: create np %u done\n", np_id);

    return (crfsnp);
}

STATIC_CAST static EC_BOOL __crfsnp_get_item_full_path(const CRFSNP *crfsnp, const uint32_t node_pos, uint8_t **full_path, uint32_t *dflag)
{
    uint8_t *path;
    uint32_t path_len;
    uint32_t path_max_len;
    CSTACK  *cstack;

    CRFSNP_ITEM  *crfsnp_item;
    uint32_t      cur_node_pos;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    path = safe_malloc(CRFSNP_PATH_MAX_LEN, LOC_CRFSNP_0084);
    if(NULL_PTR == path)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_get_item_full_path: malloc %u bytes failed\n", CRFSNP_PATH_MAX_LEN);
        return (EC_FALSE);
    }

    cstack = cstack_new(MM_IGNORE, LOC_CRFSNP_0085);
    if(NULL_PTR == cstack)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_get_item_full_path: new cstack failed\n");
        safe_free(path, LOC_CRFSNP_0086);
        return (EC_FALSE);
    }
    cur_node_pos = node_pos;

    while(CRFSNPRB_ERR_POS != cur_node_pos)
    {
        UINT32 cur_node_pos_t;

        cur_node_pos_t = cur_node_pos;
        cstack_push(cstack, (void *)cur_node_pos_t);
        crfsnp_item  = crfsnp_fetch(crfsnp, cur_node_pos);
        cur_node_pos = CRFSNP_ITEM_PARENT_POS(crfsnp_item);
    }

    path[ 0 ] = '\0';
    path_len = 0;
    path_max_len = CRFSNP_PATH_MAX_LEN;

    while(EC_FALSE == cstack_is_empty(cstack))
    {
        UINT32 cur_node_pos_t;
        cur_node_pos_t = (UINT32)cstack_pop(cstack);
        cur_node_pos   = (uint32_t)cur_node_pos_t;
        crfsnp_item    = crfsnp_fetch(crfsnp, cur_node_pos);

        if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            path_len += snprintf((char *)path + path_len, path_max_len - path_len, "%.*s/", CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        }
        else if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            path_len += snprintf((char *)path + path_len, path_max_len - path_len, "%.*s", CRFSNP_ITEM_KLEN(crfsnp_item), (char *)CRFSNP_ITEM_KEY(crfsnp_item));
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_get_item_full_path: invalid dir flag %u at node_pos %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item), cur_node_pos);
        }
        if(path_len >= path_max_len)
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_get_item_full_path: path overflow\n");
        }
        //sys_print(log, "%s [klen %u, node_pos %u]\n", (char *)path, CRFSNP_ITEM_KLEN(crfsnp_item), node_pos);
    }

    cstack_free(cstack, LOC_CRFSNP_0087);

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

    crfsnp_item = crfsnp_fetch(crfsnp, cur_node_pos);

    if(NULL_PTR != dflag)
    {
        (*dflag) = CRFSNP_ITEM_DIR_FLAG(crfsnp_item);
    }

    (*full_path) = path;

    return (EC_TRUE);
}

EC_BOOL crfsnp_show_item_full_path(LOG *log, const CRFSNP *crfsnp, const uint32_t node_pos)
{
    uint8_t  *path;
    uint32_t  dflag;

    if(EC_FALSE == __crfsnp_get_item_full_path(crfsnp, node_pos, &path, &dflag))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_show_item_full_path: get item %u full path failed\n", node_pos);
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        sys_log(log, "dir : %s\n", path);
    }
    else if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        sys_log(log, "file: %s\n", path);
    }
    else
    {
        sys_log(log, "err: %s\n", path);
    }

    safe_free(path, LOC_CRFSNP_0088);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsnp_show_item(LOG *log, const CRFSNP *crfsnp, const uint32_t node_pos)
{
    const CRFSNPRB_POOL *pool;
    const CRFSNP_ITEM   *crfsnp_item;
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CRFSNP_ITEMS_POOL(crfsnp);

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    /*itself*/
    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_show_item: item not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        sys_log(log, "error:__crfsnp_show_item: invalid dir flag %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
        return (EC_FALSE);
    }

    crfsnp_show_item_full_path(log, crfsnp, node_pos);

    /*do not show subdirectories*/
    return (EC_TRUE);
}

EC_BOOL crfsnp_show_item(LOG *log, const CRFSNP *crfsnp, const uint32_t node_pos)
{
    const CRFSNPRB_POOL *pool;
    const CRFSNP_ITEM   *crfsnp_item;
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CRFSNP_ITEMS_POOL(crfsnp);

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    /*itself*/
    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_show_item: item not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        sys_log(log, "error:crfsnp_show_item: invalid dir flag %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
        return (EC_FALSE);
    }

    crfsnp_show_item_full_path(log, crfsnp, node_pos);

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_show_dir(log, crfsnp, crfsnp_item);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_show_dir(LOG *log, const CRFSNP *crfsnp, const CRFSNP_ITEM  *crfsnp_item)
{
    CRFSNP_DNODE *crfsnp_dnode;
    uint32_t root_pos;

    crfsnp_dnode = (CRFSNP_DNODE *)CRFSNP_ITEM_DNODE(crfsnp_item);
    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    crfsnp_show_item_full_path(log, crfsnp, root_pos);


    return (EC_TRUE);
}

EC_BOOL crfsnp_show_dir_depth(LOG *log, const CRFSNP *crfsnp, const CRFSNP_ITEM  *crfsnp_item)
{
    CRFSNP_DNODE *crfsnp_dnode;
    uint32_t root_pos;

    crfsnp_dnode = (CRFSNP_DNODE *)CRFSNP_ITEM_DNODE(crfsnp_item);
    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    crfsnp_show_item_depth(log, crfsnp, root_pos);

    return (EC_TRUE);
}

EC_BOOL crfsnp_show_item_depth(LOG *log, const CRFSNP *crfsnp, const uint32_t node_pos)
{
    const CRFSNPRB_POOL *pool;
    const CRFSNP_ITEM   *crfsnp_item;
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CRFSNP_ITEMS_POOL(crfsnp);

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    /*left subtree*/
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        crfsnp_show_item_depth(log, crfsnp, CRFSNPRB_NODE_LEFT_POS(node));
    }

    /*itself*/
    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_show_item_depth: item not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_show_item_depth: invalid dir flag %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
        return (EC_FALSE);
    }

    crfsnp_show_item_full_path(log, crfsnp, node_pos);
    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_show_dir_depth(log, crfsnp, crfsnp_item);
    }

    /*right subtree*/
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        crfsnp_show_item_depth(log, crfsnp, CRFSNPRB_NODE_RIGHT_POS(node));
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_show_path_depth(LOG *log, CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path)
{
    uint32_t node_pos;

    node_pos = crfsnp_search(crfsnp, path_len, path, CRFSNP_ITEM_FILE_IS_ANY);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_show_path_depth: not found path %.*s\n", path_len, (char *)path);
        return (EC_FALSE);
    }

    return crfsnp_show_item_depth(log, crfsnp, node_pos);
}

EC_BOOL crfsnp_show_path(LOG *log, CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path)
{
    uint32_t node_pos;

    node_pos = crfsnp_search(crfsnp, path_len, path, CRFSNP_ITEM_FILE_IS_ANY);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_show_path: not found path %.*s\n", path_len, (char *)path);
        return (EC_FALSE);
    }

    return crfsnp_show_item(log, crfsnp, node_pos);
}

STATIC_CAST static EC_BOOL __crfsnp_get_first_fname_of_item(const CRFSNP *crfsnp, const uint32_t node_pos, uint8_t **fname, uint32_t *dflag)
{
    const CRFSNPRB_POOL *pool;
    const CRFSNP_ITEM   *crfsnp_item;
    const CRFSNPRB_NODE *node;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_FALSE);
    }

    pool = CRFSNP_ITEMS_POOL(crfsnp);

    node = CRFSNPRB_POOL_NODE(pool, node_pos);

    /*itself*/
    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_get_first_fname_of_item: item not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item)
    && CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_get_first_fname_of_item: invalid dir flag %u\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        if(EC_TRUE == crfsnp_get_first_fname_of_dir(crfsnp, crfsnp_item, fname, dflag))
        {
            return (EC_TRUE);
        }

        /*else: fall through ...*/
    }

    if(EC_FALSE == __crfsnp_get_item_full_path(crfsnp, node_pos, fname, dflag))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_get_first_fname_of_item: get full path of item %u failed\n", node_pos);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_get_first_fname_of_dir(const CRFSNP *crfsnp, const CRFSNP_ITEM  *crfsnp_item, uint8_t **fname, uint32_t *dflag)
{
    CRFSNP_DNODE *crfsnp_dnode;
    uint32_t root_pos;

    crfsnp_dnode = (CRFSNP_DNODE *)CRFSNP_ITEM_DNODE(crfsnp_item);
    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(EC_TRUE == __crfsnp_get_first_fname_of_item(crfsnp, root_pos, fname, dflag))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfsnp_get_first_fname_of_path(CRFSNP *crfsnp, const uint32_t path_len, const uint8_t *path, uint8_t **fname, uint32_t *dflag)
{
    uint32_t node_pos;

    node_pos = crfsnp_search(crfsnp, path_len, path, CRFSNP_ITEM_FILE_IS_ANY);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_get_first_fname_of_path: not found path %.*s\n", path_len, (char *)path);
        return (EC_FALSE);
    }

    return __crfsnp_get_first_fname_of_item(crfsnp, node_pos, fname, dflag);
}

/*------------------------------------------------ recycle -----------------------------------------*/
/*recycle dn only!*/
EC_BOOL crfsnp_recycle_item_file(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn)
{
    CRFSNP_FNODE *crfsnp_fnode;

    crfsnp_fnode = CRFSNP_ITEM_FNODE(crfsnp_item);
    if(EC_FALSE == CRFSNP_RECYCLE_DN_FUNC(crfsnp_recycle_dn)(CRFSNP_RECYCLE_DN_ARG1(crfsnp_recycle_dn), crfsnp_fnode))
    {
        CRFSNP_INODE *crfsnp_inode;

        crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_recycle_item_file: recycle dn (disk %u, block %u, page %u, size %u) failed\n",
                            CRFSNP_INODE_DISK_NO(crfsnp_inode),
                            CRFSNP_INODE_BLOCK_NO(crfsnp_inode),
                            CRFSNP_INODE_PAGE_NO(crfsnp_inode),
                            CRFSNP_FNODE_FILESZ(crfsnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR != crfsnp_recycle_np)
    {
        CRFSNP_RECYCLE_NP_FUNC(crfsnp_recycle_np)(CRFSNP_RECYCLE_NP_ARG1(crfsnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_recycle_dnode_item(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn)
{
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_recycle_item_file(crfsnp, crfsnp_item, node_pos, crfsnp_recycle_np, crfsnp_recycle_dn);
        CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) --;

        crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);

        crfsnp_item_clean(crfsnp_item);
        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_recycle_item_dir(crfsnp, crfsnp_item, node_pos, crfsnp_recycle_np, crfsnp_recycle_dn);/*recursively*/
        CRFSNP_DNODE_FILE_NUM(crfsnp_dnode) --;

        crfsnp_item_clean(crfsnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:__crfsnp_recycle_dnode_item: invalid dflag 0x%x\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

EC_BOOL crfsnp_recycle_dnode(CRFSNP *crfsnp, CRFSNP_DNODE *crfsnp_dnode, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn)
{
    CRFSNPRB_POOL *pool;
    CRFSNPRB_NODE *node;
    CRFSNP_ITEM   *item;

    pool = CRFSNP_ITEMS_POOL(crfsnp);

    node  = CRFSNPRB_POOL_NODE(pool, node_pos);
    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_LEFT_POS(node))
    {
        crfsnp_recycle_dnode(crfsnp, crfsnp_dnode, CRFSNPRB_NODE_LEFT_POS(node), crfsnp_recycle_np, crfsnp_recycle_dn);
    }

    if(CRFSNPRB_ERR_POS != CRFSNPRB_NODE_RIGHT_POS(node))
    {
        crfsnp_recycle_dnode(crfsnp, crfsnp_dnode, CRFSNPRB_NODE_RIGHT_POS(node), crfsnp_recycle_np, crfsnp_recycle_dn);
    }

    item = CRFSNP_RB_NODE_ITEM(node);
    crfsnp_recycle_dnode_item(crfsnp, crfsnp_dnode, item, node_pos, crfsnp_recycle_np, crfsnp_recycle_dn);

    /*crfsnprb recycle the rbnode, do not use crfsnprb_tree_delete which will change the tree structer*/
    crfsnprb_node_free(pool, node_pos);

    return (EC_TRUE);
}

EC_BOOL crfsnp_recycle_item_dir(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn)
{
    CRFSNP_DNODE *crfsnp_dnode;
    uint32_t root_pos;

    crfsnp_dnode = CRFSNP_ITEM_DNODE(crfsnp_item);

    root_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(CRFSNPRB_ERR_POS != root_pos)
    {
        crfsnp_recycle_dnode(crfsnp, crfsnp_dnode, root_pos, crfsnp_recycle_np, crfsnp_recycle_dn);
        CRFSNP_DNODE_ROOT_POS(crfsnp_dnode) = CRFSNPRB_ERR_POS;
    }

    if(NULL_PTR != crfsnp_recycle_np)
    {
        CRFSNP_RECYCLE_NP_FUNC(crfsnp_recycle_np)(CRFSNP_RECYCLE_NP_ARG1(crfsnp_recycle_np), node_pos);
    }
    return (EC_TRUE);
}

/*note: this interface is for that crfsnp_item had umounted from parent, not need to update parent info*/
EC_BOOL crfsnp_recycle_item(CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn)
{
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CRFSNP_FNODE *crfsnp_fnode;

        crfsnp_fnode = CRFSNP_ITEM_FNODE(crfsnp_item);

        if(EC_FALSE == crfsnp_recycle_item_file(crfsnp, crfsnp_item, node_pos, crfsnp_recycle_np, crfsnp_recycle_dn))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_recycle_item: recycle regular file failed where crfsnp_item is\n");
            crfsnp_item_print(LOGSTDOUT, crfsnp_item);
            return (EC_FALSE);
        }

        /*CRFSNP_DEL_SIZE(crfsnp) -= CRFSNP_FNODE_FILESZ(crfsnp_fnode);*/
        CRFSNP_RECYCLE_SIZE(crfsnp) += CRFSNP_FNODE_FILESZ(crfsnp_fnode);

        crfsnplru_node_rmv(crfsnp, CRFSNP_ITEM_LRU_NODE(crfsnp_item), node_pos);

        crfsnp_item_clean(crfsnp_item);
        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        crfsnp_recycle_item_dir(crfsnp, crfsnp_item, node_pos, crfsnp_recycle_np, crfsnp_recycle_dn);/*recursively*/

        crfsnp_item_clean(crfsnp_item);

        return (EC_TRUE);
    }

    dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_recycle_item: invalid dflag 0x%x\n", CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    return (EC_FALSE);
}

EC_BOOL crfsnp_recycle(CRFSNP *crfsnp, const UINT32 max_num, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn, UINT32 *complete_num)
{
    CRFSNPDEL_NODE  *crfsnpdel_node_head;
    CRFSNP_HEADER   *crfsnp_header;

    uint32_t         left_num;

    crfsnpdel_node_head = CRFSNP_DEL_LIST(crfsnp);

    crfsnp_header = CRFSNP_HDR(crfsnp);
    left_num = UINT32_TO_INT32(max_num);

    if(0 == left_num)
    {
        /*items never beyond the max value of uint32_t*/
        left_num = ((uint32_t)~0);
    }

    (*complete_num) = 0;
    while((0 < left_num --) && (EC_FALSE == crfsnp_del_list_is_empty(crfsnp)))
    {
        CRFSNP_ITEM   *crfsnp_item;
        uint32_t       node_pos;

        node_pos = CRFSNPDEL_NODE_NEXT_POS(crfsnpdel_node_head);

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        if(EC_FALSE == crfsnp_recycle_item(crfsnp, crfsnp_item, node_pos, crfsnp_recycle_np, crfsnp_recycle_dn))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_recycle: recycle item %u # failed\n", node_pos);
            return (EC_FALSE);
        }

        crfsnpdel_node_rmv(crfsnp, CRFSNP_ITEM_DEL_NODE(crfsnp_item), node_pos);

        crfsnprb_node_free(CRFSNP_ITEMS_POOL(crfsnp), node_pos);/*recycle rb node(item node)*/

        (*complete_num) ++;

        dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_recycle: recycle item %u # done\n", node_pos);
    }

    return (EC_TRUE);
}

/*--------------------------------------------------------------------------------------------------------------*/

EC_BOOL crfsnp_collect_items_no_lock(CRFSNP *crfsnp, const CSTRING *path, const UINT32 dflag, CVECTOR *crfsnp_item_vec)
{
    uint32_t     node_pos;
    CRFSNP_ITEM *crfsnp_item;

    node_pos = crfsnp_search_no_lock(crfsnp, cstring_get_len(path), cstring_get_str(path), dflag);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item_collected;

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);

        crfsnp_item_collected = crfsnp_item_new();
        crfsnp_item_clone(crfsnp_item, crfsnp_item_collected);

        cvector_push_no_lock(crfsnp_item_vec, (void *)crfsnp_item_collected);
    }

    return (EC_TRUE);
}

/*-------------------------------------------- NP in memory --------------------------------------------*/
CRFSNP *crfsnp_mem_create(const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id)
{
    CRFSNP  *crfsnp;
    CRFSNP_HEADER * crfsnp_header;
    int      fd;
    UINT32   fsize;
    uint32_t item_max_num;

    fd = ERR_FD;

    if(EC_FALSE == crfsnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_mem_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    if(EC_FALSE == crfsnp_model_item_max_num(np_model, &item_max_num))
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_mem_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    crfsnp_header = __crfsnp_header_new(np_id, fsize, fd, np_model);
    if(NULL_PTR == crfsnp_header)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_mem_create: new mem crfsnp failed\n");
        return (NULL_PTR);
    }
    CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header) = hash_2nd_algo_id;

    crfsnp = crfsnp_new();
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "error:crfsnp_mem_create: new crfsnp %u failed\n", np_id);
        __crfsnp_header_free(crfsnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }
    CRFSNP_HDR(crfsnp) = crfsnp_header;

    CRFSNP_2ND_CHASH_ALGO(crfsnp) = chash_algo_fetch(CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header));

    CRFSNP_FD(crfsnp)    = fd;
    CRFSNP_FSIZE(crfsnp) = fsize;
    CRFSNP_FNAME(crfsnp) = NULL_PTR;

    ASSERT(np_id == CRFSNP_HEADER_NP_ID(crfsnp_header));

    /*create root item*/
    crfsnp_create_root_item(crfsnp);

    dbg_log(SEC_0081_CRFSNP, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mem_create: create np %u done\n", np_id);

    return (crfsnp);
}

EC_BOOL crfsnp_mem_clean(CRFSNP *crfsnp)
{
    if(NULL_PTR != CRFSNP_HDR(crfsnp))
    {
        __crfsnp_header_free(CRFSNP_HDR(crfsnp), CRFSNP_ID(crfsnp), CRFSNP_FSIZE(crfsnp), CRFSNP_FD(crfsnp));
        CRFSNP_HDR(crfsnp) = NULL_PTR;
    }

    ASSERT(ERR_FD == CRFSNP_FD(crfsnp));

    CRFSNP_FSIZE(crfsnp) = 0;

    ASSERT(NULL_PTR == CRFSNP_FNAME(crfsnp));

    CRFSNP_DEL_SIZE(crfsnp)     = 0;
    CRFSNP_RECYCLE_SIZE(crfsnp) = 0;

    CRFSNP_HDR(crfsnp) = NULL_PTR;

    CRFSNP_2ND_CHASH_ALGO(crfsnp) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL crfsnp_mem_free(CRFSNP *crfsnp)
{
    if(NULL_PTR != crfsnp)
    {
        crfsnp_mem_clean(crfsnp);
        free_static_mem(MM_CRFSNP, crfsnp, LOC_CRFSNP_0100);
    }
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

