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

#include "task.h"

#include "cbloom.h"

#include "chashalgo.h"
#include "cdsk.h"
#include "cstack.h"
#include "cmd5.h"

#include "cpgrb.h"
#include "csfsnprb.h"
#include "csfsnp.h"

static CSFSNP_CFG g_csfsnp_cfg_tbl[] = {
    {"CSFSNP_008M_MODEL", CSFSNP_008M_CFG_FILE_SIZE,  CSFSNP_008M_CFG_ITEM_MAX_NUM, 0 },
    {"CSFSNP_016M_MODEL", CSFSNP_016M_CFG_FILE_SIZE,  CSFSNP_016M_CFG_ITEM_MAX_NUM, 0 },
    {"CSFSNP_032M_MODEL", CSFSNP_032M_CFG_FILE_SIZE,  CSFSNP_032M_CFG_ITEM_MAX_NUM, 0 },
    {"CSFSNP_064M_MODEL", CSFSNP_064M_CFG_FILE_SIZE,  CSFSNP_064M_CFG_ITEM_MAX_NUM, 0 },
    {"CSFSNP_128M_MODEL", CSFSNP_128M_CFG_FILE_SIZE,  CSFSNP_128M_CFG_ITEM_MAX_NUM, 0 },
    {"CSFSNP_256M_MODEL", CSFSNP_256M_CFG_FILE_SIZE,  CSFSNP_256M_CFG_ITEM_MAX_NUM, 0 },
    {"CSFSNP_512M_MODEL", CSFSNP_512M_CFG_FILE_SIZE,  CSFSNP_512M_CFG_ITEM_MAX_NUM, 0 },
    {"CSFSNP_001G_MODEL", CSFSNP_001G_CFG_FILE_SIZE,  CSFSNP_001G_CFG_ITEM_MAX_NUM, 0 },
};

static uint8_t g_csfsnp_cfg_tbl_len = (uint8_t)(sizeof(g_csfsnp_cfg_tbl)/sizeof(g_csfsnp_cfg_tbl[0]));

STATIC_CAST static uint32_t __csfsnp_bucket_insert(CSFSNP *csfsnp, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key);

STATIC_CAST static EC_BOOL __csfsnp_bucket_delete(CSFSNP *csfsnp, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key);

STATIC_CAST static EC_BOOL __csfsnp_bucket_delete_item(CSFSNP *csfsnp, const uint32_t bucket_pos, const uint32_t node_pos);

STATIC_CAST static EC_BOOL __csfsnp_delete_one_bucket(CSFSNP *csfsnp, const uint32_t bucket_pos);

STATIC_CAST static EC_BOOL __csfsnp_delete_all_buckets(CSFSNP *csfsnp);

STATIC_CAST static EC_BOOL __csfsnp_update_one_bucket(CSFSNP *csfsnp, const uint32_t bucket_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no);

STATIC_CAST static uint32_t __csfsnp_bucket_search(const CSFSNP *csfsnp, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key);

STATIC_CAST static void __csfsnp_print_hash(LOG *log, const uint32_t path_len, const uint8_t *path, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    uint32_t idx;

    sys_print(log, "%.*s => (%X, %X, ", path_len, path, first_hash, second_hash);
    for(idx = 0; idx < klen; idx ++)
    {
        sys_print(log, "%X", (uint8_t)key[ idx ]);
    }
    sys_print(log, ")\n");
}

char * csfsnp_model_str(const uint8_t csfsnp_model)
{
    CSFSNP_CFG *csfsnp_cfg;
    if(csfsnp_model >= g_csfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_model_str: invalid csfsnp mode %u\n", csfsnp_model);
        return (NULL_PTR);
    }
    csfsnp_cfg = &(g_csfsnp_cfg_tbl[ csfsnp_model ]);
    return CSFSNP_CFG_MOD_STR(csfsnp_cfg);
}

uint32_t csfsnp_model_get(const char *mod_str)
{
    uint8_t csfsnp_model;

    for(csfsnp_model = 0; csfsnp_model < g_csfsnp_cfg_tbl_len; csfsnp_model ++)
    {
        CSFSNP_CFG *csfsnp_cfg;
        csfsnp_cfg = &(g_csfsnp_cfg_tbl[ csfsnp_model ]);

        if(0 == strcasecmp(CSFSNP_CFG_MOD_STR(csfsnp_cfg), mod_str))
        {
            return (csfsnp_model);
        }
    }
    return (CSFSNP_ERR_MODEL);
}

EC_BOOL csfsnp_model_file_size(const uint8_t csfsnp_model, UINT32 *file_size)
{
    CSFSNP_CFG *csfsnp_cfg;
    if(csfsnp_model >= g_csfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_model_file_size: invalid csfsnp mode %u\n", csfsnp_model);
        return (EC_FALSE);
    }
    csfsnp_cfg = &(g_csfsnp_cfg_tbl[ csfsnp_model ]);
    (*file_size) = CSFSNP_CFG_FILE_SIZE(csfsnp_cfg);
    return (EC_TRUE);
}

EC_BOOL csfsnp_model_item_max_num(const uint8_t csfsnp_model, uint32_t *item_max_num)
{
    CSFSNP_CFG *csfsnp_cfg;
    if(csfsnp_model >= g_csfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_model_item_max_num: invalid csfsnp mode %u\n", csfsnp_model);
        return (EC_FALSE);
    }
    csfsnp_cfg = &(g_csfsnp_cfg_tbl[ csfsnp_model ]);
    (*item_max_num) = CSFSNP_CFG_ITEM_MAX_NUM(csfsnp_cfg);
    return (EC_TRUE);
}

STATIC_CAST static char *__csfsnp_fname_gen(const char *root_dir, const uint32_t np_id)
{
    char *fname;
    uint32_t len;

    if(NULL_PTR == root_dir)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_fname_gen: root_dir is null\n");
        return (NULL_PTR);
    }

    len = strlen(root_dir) + strlen("/sfsnp_XXXX.dat") + 1;

    fname = safe_malloc(len, LOC_CSFSNP_0001);
    if(NULL_PTR == fname)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_fname_gen: malloc %u bytes failed\n", len);
        return (NULL_PTR);
    }
    snprintf(fname, len, "%s/sfsnp_%04X.dat", root_dir, np_id);
    return (fname);
}

STATIC_CAST static uint32_t __csfsnp_path_seg_len(const uint8_t *full_path, const uint32_t full_path_len, const uint8_t *path_seg_beg)
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

STATIC_CAST static EC_BOOL __csfsnp_path_hash(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path, const uint32_t digest_max_len, uint8_t *digest, uint32_t *path_1st_hash, uint32_t *path_2nd_hash)
{
    ASSERT(CMD5_DIGEST_LEN == digest_max_len);
    cmd5_sum(path_len, path, digest);
 
    (*path_1st_hash) = CSFSNP_1ST_CHASH_ALGO_COMPUTE(csfsnp, path_len, path);
    (*path_2nd_hash) = CSFSNP_2ND_CHASH_ALGO_COMPUTE(csfsnp, path_len, path); 

    return (EC_TRUE);
}

EC_BOOL csfsnp_inode_init(CSFSNP_INODE *csfsnp_inode)
{
    CSFSNP_INODE_DISK_NO(csfsnp_inode)  = CPGRB_ERR_POS;
    CSFSNP_INODE_BLOCK_NO(csfsnp_inode) = CPGRB_ERR_POS;
    CSFSNP_INODE_PAGE_NO(csfsnp_inode)  = CPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL csfsnp_inode_clean(CSFSNP_INODE *csfsnp_inode)
{
    CSFSNP_INODE_DISK_NO(csfsnp_inode)  = CPGRB_ERR_POS;
    CSFSNP_INODE_BLOCK_NO(csfsnp_inode) = CPGRB_ERR_POS;
    CSFSNP_INODE_PAGE_NO(csfsnp_inode)  = CPGRB_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL csfsnp_inode_clone(const CSFSNP_INODE *csfsnp_inode_src, CSFSNP_INODE *csfsnp_inode_des)
{
    CSFSNP_INODE_DISK_NO(csfsnp_inode_des)  = CSFSNP_INODE_DISK_NO(csfsnp_inode_src);
    CSFSNP_INODE_BLOCK_NO(csfsnp_inode_des) = CSFSNP_INODE_BLOCK_NO(csfsnp_inode_src);
    CSFSNP_INODE_PAGE_NO(csfsnp_inode_des)  = CSFSNP_INODE_PAGE_NO(csfsnp_inode_src);

    return (EC_TRUE);
}

void csfsnp_inode_print(LOG *log, const CSFSNP_INODE *csfsnp_inode)
{
    sys_log(log, "csfsnp_inode_print: csfsnp_inode %p: (disk %u, block %u, page %u)\n",
                    csfsnp_inode,
                    CSFSNP_INODE_DISK_NO(csfsnp_inode),
                    CSFSNP_INODE_BLOCK_NO(csfsnp_inode),
                    CSFSNP_INODE_PAGE_NO(csfsnp_inode)
                    );
    return;
}

void csfsnp_inode_log_no_lock(LOG *log, const CSFSNP_INODE *csfsnp_inode)
{
    sys_print_no_lock(log, "(disk %u, block %u, page %u)\n",
                    CSFSNP_INODE_DISK_NO(csfsnp_inode),
                    CSFSNP_INODE_BLOCK_NO(csfsnp_inode),
                    CSFSNP_INODE_PAGE_NO(csfsnp_inode)
                    );
    return;
}

CSFSNP_FNODE *csfsnp_fnode_new()
{
    CSFSNP_FNODE *csfsnp_fnode;
    alloc_static_mem(MM_CSFSNP_FNODE, &csfsnp_fnode, LOC_CSFSNP_0002);
    if(NULL_PTR != csfsnp_fnode)
    {
        csfsnp_fnode_init(csfsnp_fnode);
    }
    return (csfsnp_fnode);

}

CSFSNP_FNODE *csfsnp_fnode_make(const CSFSNP_FNODE *csfsnp_fnode_src)
{
    CSFSNP_FNODE *csfsnp_fnode_des;
    alloc_static_mem(MM_CSFSNP_FNODE, &csfsnp_fnode_des, LOC_CSFSNP_0003);
    if(NULL_PTR != csfsnp_fnode_des)
    {
        csfsnp_fnode_clone(csfsnp_fnode_src, csfsnp_fnode_des);
    }
    return (csfsnp_fnode_des);
}

EC_BOOL csfsnp_fnode_init(CSFSNP_FNODE *csfsnp_fnode)
{
    uint32_t pos;

    CSFSNP_FNODE_FILESZ(csfsnp_fnode) = 0;
    CSFSNP_FNODE_REPNUM(csfsnp_fnode) = 0;

    for(pos = 0; pos < CSFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        csfsnp_inode_init(CSFSNP_FNODE_INODE(csfsnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_fnode_clean(CSFSNP_FNODE *csfsnp_fnode)
{
    uint32_t pos;

    CSFSNP_FNODE_FILESZ(csfsnp_fnode) = 0;
    CSFSNP_FNODE_REPNUM(csfsnp_fnode) = 0;

    for(pos = 0; pos < CSFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        csfsnp_inode_clean(CSFSNP_FNODE_INODE(csfsnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_fnode_free(CSFSNP_FNODE *csfsnp_fnode)
{
    if(NULL_PTR != csfsnp_fnode)
    {
        csfsnp_fnode_clean(csfsnp_fnode);
        free_static_mem(MM_CSFSNP_FNODE, csfsnp_fnode, LOC_CSFSNP_0004);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_fnode_clone(const CSFSNP_FNODE *csfsnp_fnode_src, CSFSNP_FNODE *csfsnp_fnode_des)
{
    uint32_t pos;

    CSFSNP_FNODE_FILESZ(csfsnp_fnode_des) = CSFSNP_FNODE_FILESZ(csfsnp_fnode_src);
    CSFSNP_FNODE_REPNUM(csfsnp_fnode_des) = CSFSNP_FNODE_REPNUM(csfsnp_fnode_src);

    for(pos = 0; pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode_src) && pos < CSFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        csfsnp_inode_clone(CSFSNP_FNODE_INODE(csfsnp_fnode_src, pos), CSFSNP_FNODE_INODE(csfsnp_fnode_des, pos));
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_fnode_check_inode_exist(const CSFSNP_INODE *inode, const CSFSNP_FNODE *csfsnp_fnode)
{
    uint32_t replica_pos;

    for(replica_pos = 0; replica_pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode); replica_pos ++)
    {
        if(
            CSFSNP_INODE_DISK_NO(inode)  == CSFSNP_FNODE_INODE_DISK_NO(csfsnp_fnode, replica_pos)
         && CSFSNP_INODE_BLOCK_NO(inode) == CSFSNP_FNODE_INODE_BLOCK_NO(csfsnp_fnode, replica_pos)
         && CSFSNP_INODE_PAGE_NO(inode)  == CSFSNP_FNODE_INODE_PAGE_NO(csfsnp_fnode, replica_pos)
        )
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL csfsnp_fnode_cmp(const CSFSNP_FNODE *csfsnp_fnode_1st, const CSFSNP_FNODE *csfsnp_fnode_2nd)
{
    uint32_t replica_pos;

    if(NULL_PTR == csfsnp_fnode_1st && NULL_PTR == csfsnp_fnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == csfsnp_fnode_1st || NULL_PTR == csfsnp_fnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CSFSNP_FNODE_REPNUM(csfsnp_fnode_1st) != CSFSNP_FNODE_REPNUM(csfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CSFSNP_FNODE_FILESZ(csfsnp_fnode_1st) != CSFSNP_FNODE_FILESZ(csfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }
 
    for(replica_pos = 0; replica_pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode_1st); replica_pos ++)
    {
        if(EC_FALSE == csfsnp_fnode_check_inode_exist(CSFSNP_FNODE_INODE(csfsnp_fnode_1st, replica_pos), csfsnp_fnode_2nd))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL csfsnp_fnode_import(const CSFSNP_FNODE *csfsnp_fnode_src, CSFSNP_FNODE *csfsnp_fnode_des)
{
    uint32_t src_pos;
    uint32_t des_pos;

    for(src_pos = 0, des_pos = 0; src_pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode_src) && src_pos < CSFSNP_FILE_REPLICA_MAX_NUM; src_pos ++)
    {
        CSFSNP_INODE *csfsnp_inode_src;

        csfsnp_inode_src = (CSFSNP_INODE *)CSFSNP_FNODE_INODE(csfsnp_fnode_src, src_pos);
        if(CPGRB_ERR_POS != CSFSNP_INODE_DISK_NO(csfsnp_inode_src)
        && CPGRB_ERR_POS != CSFSNP_INODE_BLOCK_NO(csfsnp_inode_src)
        && CPGRB_ERR_POS != CSFSNP_INODE_PAGE_NO(csfsnp_inode_src)
        )
        {
            CSFSNP_INODE *csfsnp_inode_des;

            csfsnp_inode_des = CSFSNP_FNODE_INODE(csfsnp_fnode_des, des_pos);
            if(csfsnp_inode_src != csfsnp_inode_des)
            {
                csfsnp_inode_clone(csfsnp_inode_src, csfsnp_inode_des);
            }

            des_pos ++;
        }
    }

    CSFSNP_FNODE_FILESZ(csfsnp_fnode_des) = CSFSNP_FNODE_FILESZ(csfsnp_fnode_src);
    CSFSNP_FNODE_REPNUM(csfsnp_fnode_des) = des_pos;
    return (EC_TRUE);
}

uint32_t csfsnp_fnode_count_replica(const CSFSNP_FNODE *csfsnp_fnode)
{
    uint32_t pos;
    uint32_t count;

    for(pos = 0, count = 0; pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode) && pos < CSFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        CSFSNP_INODE *csfsnp_inode;

        csfsnp_inode = (CSFSNP_INODE *)CSFSNP_FNODE_INODE(csfsnp_fnode, pos);
        if(CPGRB_ERR_POS != CSFSNP_INODE_DISK_NO(csfsnp_inode)
        && CPGRB_ERR_POS != CSFSNP_INODE_BLOCK_NO(csfsnp_inode)
        && CPGRB_ERR_POS != CSFSNP_INODE_PAGE_NO(csfsnp_inode)
        )
        {
            count ++;
        }
    }
    return (count);
}

void csfsnp_fnode_print(LOG *log, const CSFSNP_FNODE *csfsnp_fnode)
{
    uint32_t pos;

    sys_log(log, "csfsnp_fnode %p: file size %u, replica num %u\n",
                    csfsnp_fnode,
                    CSFSNP_FNODE_FILESZ(csfsnp_fnode),
                    CSFSNP_FNODE_REPNUM(csfsnp_fnode)
                    );

    for(pos = 0; pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode) && pos < CSFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        csfsnp_inode_print(log, CSFSNP_FNODE_INODE(csfsnp_fnode, pos));
    }
    return;
}

void csfsnp_fnode_log_no_lock(LOG *log, const CSFSNP_FNODE *csfsnp_fnode)
{
    uint32_t pos;

    sys_print_no_lock(log, "size %u, replica %u",
                    CSFSNP_FNODE_FILESZ(csfsnp_fnode),
                    CSFSNP_FNODE_REPNUM(csfsnp_fnode));

    for(pos = 0; pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode) && pos < CSFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        csfsnp_inode_log_no_lock(log, CSFSNP_FNODE_INODE(csfsnp_fnode, pos));
    }
    sys_print_no_lock(log, "\n");

    return;
}

CSFSNP_ITEM *csfsnp_item_new()
{
    CSFSNP_ITEM *csfsnp_item;

    alloc_static_mem(MM_CSFSNP_ITEM, &csfsnp_item, LOC_CSFSNP_0005);
    if(NULL_PTR != csfsnp_item)
    {
        csfsnp_item_init(csfsnp_item);
    }
    return (csfsnp_item);
}

EC_BOOL csfsnp_item_init(CSFSNP_ITEM *csfsnp_item)
{
    CSFSNP_ITEM_C_TIME(csfsnp_item)  = 0;
 
    CSFSNP_ITEM_KLEN(csfsnp_item)    = 0;
    BSET(CSFSNP_ITEM_KEY(csfsnp_item), '\0', CSFSNP_KEY_MAX_SIZE);

    CSFSNP_ITEM_BUCKET_POS(csfsnp_item) = CSFSNPRB_ERR_POS;
    CSFSNP_ITEM_STAT(csfsnp_item)       = CSFSNP_ITEM_STAT_IS_NOT_USED;

    csfsnp_fnode_init(CSFSNP_ITEM_FNODE(csfsnp_item));
 
    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL csfsnp_item_clean(CSFSNP_ITEM *csfsnp_item)
{
    CSFSNP_ITEM_C_TIME(csfsnp_item)  = 0;
 
    CSFSNP_ITEM_KLEN(csfsnp_item)    = 0;
    BSET(CSFSNP_ITEM_KEY(csfsnp_item), '\0', CSFSNP_KEY_MAX_SIZE);

    CSFSNP_ITEM_BUCKET_POS(csfsnp_item) = CSFSNPRB_ERR_POS;
    CSFSNP_ITEM_STAT(csfsnp_item)       = CSFSNP_ITEM_STAT_IS_NOT_USED;
 
    csfsnp_fnode_clean(CSFSNP_ITEM_FNODE(csfsnp_item));
 
    /*note:do nothing on rb_node*/

    return (EC_TRUE);
}

EC_BOOL csfsnp_item_clone(const CSFSNP_ITEM *csfsnp_item_src, CSFSNP_ITEM *csfsnp_item_des)
{
    if(NULL_PTR == csfsnp_item_src)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_item_clone: csfsnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == csfsnp_item_des)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_item_clone: csfsnp_item_des is null\n");
        return (EC_FALSE);
    }

    CSFSNP_ITEM_C_TIME(csfsnp_item_des)     = CSFSNP_ITEM_C_TIME(csfsnp_item_src);

    CSFSNP_ITEM_KLEN(csfsnp_item_des)       = CSFSNP_ITEM_KLEN(csfsnp_item_src);

    BCOPY(CSFSNP_ITEM_KEY(csfsnp_item_src), CSFSNP_ITEM_KEY(csfsnp_item_des), CSFSNP_ITEM_KLEN(csfsnp_item_src));

    CSFSNP_ITEM_BUCKET_POS(csfsnp_item_des) = CSFSNP_ITEM_BUCKET_POS(csfsnp_item_src);
    CSFSNP_ITEM_STAT(csfsnp_item_des)       = CSFSNP_ITEM_STAT(csfsnp_item_src);
  
    csfsnp_fnode_clone(CSFSNP_ITEM_FNODE(csfsnp_item_src), CSFSNP_ITEM_FNODE(csfsnp_item_des));
 
    return (EC_TRUE);
}

EC_BOOL csfsnp_item_free(CSFSNP_ITEM *csfsnp_item)
{
    if(NULL_PTR != csfsnp_item)
    {
        csfsnp_item_clean(csfsnp_item);
        free_static_mem(MM_CSFSNP_ITEM, csfsnp_item, LOC_CSFSNP_0006);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_item_init_0(const UINT32 md_id, CSFSNP_ITEM *csfsnp_item)
{
    return csfsnp_item_init(csfsnp_item);
}

EC_BOOL csfsnp_item_clean_0(const UINT32 md_id, CSFSNP_ITEM *csfsnp_item)
{
    return csfsnp_item_clean(csfsnp_item);
}

EC_BOOL csfsnp_item_free_0(const UINT32 md_id, CSFSNP_ITEM *csfsnp_item)
{
    return csfsnp_item_free(csfsnp_item);
}

EC_BOOL csfsnp_item_set_key(CSFSNP_ITEM *csfsnp_item, const uint32_t klen, const uint8_t *key)
{
    BCOPY(key, CSFSNP_ITEM_KEY(csfsnp_item), klen);
    CSFSNP_ITEM_KLEN(csfsnp_item) = klen;

    return (EC_TRUE);
}

void csfsnp_item_print(LOG *log, const CSFSNP_ITEM *csfsnp_item)
{
    const CSFSNP_FNODE *csfsnp_fnode;
    const uint8_t *key;
    uint32_t       pos;

    sys_log(log, "csfsnp_item_print: csfsnp_item %p: create time: %s\n",
                    csfsnp_item,
                    c_http_time(CSFSNP_ITEM_C_TIME(csfsnp_item))
                    );

    sys_log(log, "csfsnp_item_print: csfsnp_item %p: stat %u, k_len %u, bucket_pos %u\n",
                    csfsnp_item,
                    CSFSNP_ITEM_STAT(csfsnp_item),
                    CSFSNP_ITEM_KLEN(csfsnp_item),
                    CSFSNP_ITEM_BUCKET_POS(csfsnp_item)
                    );

    key = CSFSNP_ITEM_KEY(csfsnp_item);
    sys_log(log, "csfsnp_item_print: csfsnp_item %p: key: [len = %u] %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
                 csfsnp_item,
                 CSFSNP_ITEM_KLEN(csfsnp_item),
                 key[ 0 ], key[ 1 ], key[ 2 ], key[ 3 ],
                 key[ 4 ], key[ 5 ], key[ 6 ], key[ 7 ],
                 key[ 8 ], key[ 9 ], key[ 10 ], key[ 11 ],
                 key[ 12 ], key[ 13 ], key[ 14 ], key[ 15 ]);

    csfsnp_fnode = CSFSNP_ITEM_FNODE(csfsnp_item);
    sys_log(log, "csfsnp_item_print: csfsnp_item %p: file size %u, replica num %u\n",
                csfsnp_item,
                CSFSNP_FNODE_FILESZ(csfsnp_fnode),
                CSFSNP_FNODE_REPNUM(csfsnp_fnode)
                );
    for(pos = 0; pos < CSFSNP_FNODE_REPNUM(csfsnp_fnode); pos ++)
    {
        const CSFSNP_INODE *csfsnp_inode;

        csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, pos);
        csfsnp_inode_print(log, csfsnp_inode);
        //sys_print(log, "\n");
    }

    return;
}

EC_BOOL csfsnp_item_load(CSFSNP *csfsnp, uint32_t *offset, CSFSNP_ITEM *csfsnp_item)
{
    RWSIZE rsize;
    UINT32 offset_t;

    offset_t = (*offset);
    rsize = sizeof(CSFSNP_ITEM);
    if(EC_FALSE == c_file_load(CSFSNP_FD(csfsnp), &offset_t, rsize, (UINT8 *)csfsnp_item))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_item_load: load item from offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL csfsnp_item_flush(CSFSNP *csfsnp, uint32_t *offset, const CSFSNP_ITEM *csfsnp_item)
{
    RWSIZE wsize;
    UINT32 offset_t;

    offset_t = (*offset);
    wsize = sizeof(CSFSNP_ITEM);
    if(EC_FALSE == c_file_flush(CSFSNP_FD(csfsnp), &offset_t, wsize, (UINT8 *)csfsnp_item))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_item_load: flush item to offset %u failed\n", *offset);
        return (EC_FALSE);
    }

    (*offset) = (uint32_t)offset_t;

    return (EC_TRUE);
}

EC_BOOL csfsnp_item_is(const CSFSNP_ITEM *csfsnp_item, const uint32_t klen, const uint8_t *key)
{
    if(klen !=  CSFSNP_ITEM_KLEN(csfsnp_item))
    {
        return (EC_FALSE);
    }

    if(0 != strncmp((char *)key, (char *)CSFSNP_ITEM_KEY(csfsnp_item), klen))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static CSFSNP_HEADER *__csfsnp_header_new(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model, const uint32_t bucket_max_num)
{
    CSFSNP_HEADER *csfsnp_header;
    uint32_t      *bucket;
    uint32_t       node_max_num;
    uint32_t       node_sizeof;
    uint32_t       bucket_pos;
    UINT32         bucket_offset;
    UINT32         expect_fsize;

    csfsnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CSFSNP_ITEM);

    bucket_offset = (UINT32)(sizeof(CSFSNP_HEADER) + node_max_num * sizeof(CSFSNP_ITEM));
    expect_fsize  = (UINT32)(bucket_offset + bucket_max_num * sizeof(uint32_t));

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_new: fsize %lu, expect_fsize %lu, where node_max_num %u, "
                       "node_sizeof %u, sizeof(CSFSNP_HEADER) %u, sizeof(CSFSNP_ITEM) %u\n",
                        fsize, expect_fsize, node_max_num, node_sizeof, sizeof(CSFSNP_HEADER), sizeof(CSFSNP_ITEM));

    if(expect_fsize > fsize)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_header_new: fsize %lu, but expect_fsize %lu, where node_max_num %u, "
                           "node_sizeof %u, sizeof(CSFSNP_HEADER) %u, sizeof(CSFSNP_ITEM) %u\n",
                            fsize, expect_fsize, node_max_num, node_sizeof, sizeof(CSFSNP_HEADER), sizeof(CSFSNP_ITEM));
        return (NULL_PTR);
    }

    csfsnp_header = (CSFSNP_HEADER *)safe_malloc(fsize, LOC_CSFSNP_0007);
    if(NULL_PTR == csfsnp_header)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_header_new: new header with %u bytes for np %u fd %d failed\n",
                           fsize, np_id, fd);
        return (NULL_PTR);
    }

    CSFSNP_HEADER_NP_ID(csfsnp_header)     = np_id;
    CSFSNP_HEADER_NP_MODEL(csfsnp_header)  = np_model;

    /*init rb nodes*/ 
    csfsnprb_pool_init(CSFSNP_HEADER_ITEMS_POOL(csfsnp_header), node_max_num, node_sizeof);

    /*init buckets*/
    CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header)  = bucket_offset;
    CSFSNP_HEADER_BUCKET_MAX_NUM(csfsnp_header) = bucket_max_num;

    bucket = (uint32_t *)(((uint8_t *)csfsnp_header) + bucket_offset);
    //dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_new: bucket %p\n", bucket);
    for(bucket_pos = 0; bucket_pos < bucket_max_num; bucket_pos ++)
    {
        *(bucket + bucket_pos) = CSFSNPRB_ERR_POS;
    } 

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_new: new header of np %u with model %u, bucket max num %u done\n",
                        np_id, np_model, bucket_max_num);
 
    return (csfsnp_header);
}

STATIC_CAST static CSFSNP_HEADER *__csfsnp_header_load(const uint32_t np_id, const UINT32 fsize, int fd)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(fsize, LOC_CSFSNP_0008);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_header_load: malloc %u bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, buff))
    {
        safe_free(buff, LOC_CSFSNP_0009);
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_header_load: load %u bytes failed for np %u, fd %d\n",
                            fsize, np_id, fd);
        return (NULL_PTR);
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_load: load header of np %u done\n", np_id); 

    return ((CSFSNP_HEADER *)buff);
}

STATIC_CAST static CSFSNP_HEADER * __csfsnp_header_flush(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const UINT32 fsize, const int fd)
{
    if(NULL_PTR != csfsnp_header)
    {
        UINT32 offset;

        offset = 0;     
        if(EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)csfsnp_header))
        {
            dbg_log(SEC_0173_CSFSNP, 1)(LOGSTDOUT, "warn:__csfsnp_header_flush: flush header of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_flush: flush header of np %u done\n", np_id); 
        }
    } 
    return (csfsnp_header);
}

STATIC_CAST static CSFSNP_HEADER *__csfsnp_header_free(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const UINT32 fsize, const int fd)
{
    if(NULL_PTR != csfsnp_header)
    {
        UINT32 offset;

        offset = 0;
        if(
           ERR_FD != fd
        && EC_FALSE == c_file_flush(fd, &offset, fsize, (const UINT8 *)csfsnp_header)
        )
        {
            dbg_log(SEC_0173_CSFSNP, 1)(LOGSTDOUT, "warn:__csfsnp_header_free: flush header of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }

        safe_free(csfsnp_header, LOC_CSFSNP_0010);

        dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_free: free header of np %u done\n", np_id); 
    }
 
    /*csfsnp_header cannot be accessed again*/
    return (NULL_PTR);
}


STATIC_CAST static CSFSNP_HEADER *__csfsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd)
{
    CSFSNP_HEADER *csfsnp_header;

    csfsnp_header = (CSFSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == csfsnp_header)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_header_open: mmap np %u with fd %d failed, errno = %d, errorstr = %s\n",
                           np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_open: mmap header of np %u done\n", np_id);
 
    return (csfsnp_header);
}

STATIC_CAST static CSFSNP_HEADER *__csfsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model, const uint32_t bucket_max_num)
{
    CSFSNP_HEADER *csfsnp_header;
    uint32_t *bucket;
    uint32_t node_max_num;
    uint32_t node_sizeof;
    uint32_t bucket_pos;
    UINT32   bucket_offset;
    UINT32   expect_fsize; 

    csfsnp_model_item_max_num(np_model, &node_max_num);
    node_sizeof = sizeof(CSFSNP_ITEM);

    bucket_offset = (UINT32)(sizeof(CSFSNP_HEADER) + node_max_num * sizeof(CSFSNP_ITEM));
    expect_fsize  = (UINT32)(bucket_offset + bucket_max_num * sizeof(uint32_t));

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_create: fsize %lu, expect_fsize %lu, where node_max_num %u, "
                       "node_sizeof %u, sizeof(CSFSNP_HEADER) %u, sizeof(CSFSNP_ITEM) %u\n",
                        fsize, expect_fsize, node_max_num, node_sizeof, sizeof(CSFSNP_HEADER), sizeof(CSFSNP_ITEM));

    if(expect_fsize > fsize)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_header_create: fsize %lu, but expect_fsize %lu, where node_max_num %u, "
                           "node_sizeof %u, sizeof(CSFSNP_HEADER) %u, sizeof(CSFSNP_ITEM) %u\n",
                            fsize, expect_fsize, node_max_num, node_sizeof, sizeof(CSFSNP_HEADER), sizeof(CSFSNP_ITEM));
        return (NULL_PTR);
    }

    csfsnp_header = (CSFSNP_HEADER *)mmap(NULL_PTR, fsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == csfsnp_header)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_header_open: mmap np %u with fd %d failed, errno = %d, errorstr = %s\n",
                           np_id, fd, errno, strerror(errno));
        return (NULL_PTR);
    }  

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_create: fsize %lu, node_max_num %u, node_sizeof %u\n", fsize, node_max_num, node_sizeof);

    CSFSNP_HEADER_NP_ID(csfsnp_header)    = np_id;
    CSFSNP_HEADER_NP_MODEL(csfsnp_header) = np_model;

    /*init rb nodes*/ 
    csfsnprb_pool_init(CSFSNP_HEADER_ITEMS_POOL(csfsnp_header), node_max_num, node_sizeof);

    /*init buckets*/
    CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header)  = bucket_offset;
    CSFSNP_HEADER_BUCKET_MAX_NUM(csfsnp_header) = bucket_max_num;

    bucket = (uint32_t *)(((uint8_t *)csfsnp_header) + bucket_offset);
    //dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_create: bucket %p\n", bucket);
    for(bucket_pos = 0; bucket_pos < bucket_max_num; bucket_pos ++)
    {
        *(bucket + bucket_pos) = CSFSNPRB_ERR_POS;
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_create: mmap header of np %u with model %u, bucket max num %u done\n",
                        np_id, np_model, bucket_max_num);
                     
    return (csfsnp_header);
}

STATIC_CAST static CSFSNP_HEADER * __csfsnp_header_sync(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const UINT32 fsize, const int fd)
{
    if(NULL_PTR != csfsnp_header)
    {
        if(0 != msync(csfsnp_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0173_CSFSNP, 1)(LOGSTDOUT, "warn:__csfsnp_header_sync: sync header of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }
        else
        {
            dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_sync: sync header of np %u fd %d with size %u done\n",
                               np_id, fd, fsize);
        }        
    } 
    return (csfsnp_header);
}

STATIC_CAST static CSFSNP_HEADER *__csfsnp_header_close(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const UINT32 fsize, const int fd)
{
    if(NULL_PTR != csfsnp_header)
    {
        if(0 != msync(csfsnp_header, fsize, MS_SYNC))
        {
            dbg_log(SEC_0173_CSFSNP, 1)(LOGSTDOUT, "warn:__csfsnp_header_close: sync header of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }
     
        if(0 != munmap(csfsnp_header, fsize))
        {
            dbg_log(SEC_0173_CSFSNP, 1)(LOGSTDOUT, "warn:__csfsnp_header_close: munmap header of np %u fd %d with size %u failed\n",
                               np_id, fd, fsize);
        }
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_header_close: close header of np %u done\n", np_id);
 
    /*csfsnp_header cannot be accessed again*/
    return (NULL_PTR);
}

CSFSNP_HEADER *csfsnp_header_create(const uint32_t np_id, const UINT32 fsize, int fd, const uint8_t np_model, const uint32_t bucket_max_num)
{
    if(SWITCH_ON == CSFS_NP_CACHE_IN_MEM)
    {
        return __csfsnp_header_new(np_id, fsize, fd, np_model, bucket_max_num);
    }

    return __csfsnp_header_create(np_id, fsize, fd, np_model, bucket_max_num);
}

CSFSNP_HEADER *csfsnp_header_sync(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const UINT32 fsize, const int fd)
{
    if(SWITCH_ON == CSFS_NP_CACHE_IN_MEM)
    {
        return __csfsnp_header_flush(csfsnp_header, np_id, fsize, fd);
    }

    return __csfsnp_header_sync(csfsnp_header, np_id, fsize, fd); 
}

CSFSNP_HEADER *csfsnp_header_open(const uint32_t np_id, const UINT32 fsize, int fd)
{
    if(SWITCH_ON == CSFS_NP_CACHE_IN_MEM)
    {
        return __csfsnp_header_load(np_id, fsize, fd);
    }

    return __csfsnp_header_open(np_id, fsize, fd);
}

CSFSNP_HEADER *csfsnp_header_close(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const UINT32 fsize, const int fd)
{
    if(SWITCH_ON == CSFS_NP_CACHE_IN_MEM)
    {
        return __csfsnp_header_free(csfsnp_header, np_id, fsize, fd);
    }

    return __csfsnp_header_close(csfsnp_header, np_id, fsize, fd);
}

EC_BOOL csfsnp_header_init(CSFSNP_HEADER *csfsnp_header, const uint32_t np_id, const uint8_t np_model, const uint8_t first_chash_algo_id, const uint8_t second_chash_algo_id, const uint32_t bucket_max_num)
{
    uint32_t node_max_num;
 
    CSFSNP_HEADER_NP_ID(csfsnp_header)         = np_id;
    CSFSNP_HEADER_NP_MODEL(csfsnp_header)      = np_model;
 
    CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header)  = first_chash_algo_id;
    CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)  = second_chash_algo_id;

    csfsnp_model_item_max_num(np_model, &node_max_num);
 
    CSFSNP_HEADER_BUCKET_MAX_NUM(csfsnp_header)     = bucket_max_num;

    /*do nothing on CSFSNPRB_POOL pool*/

    return (EC_TRUE);
}

EC_BOOL csfsnp_header_clean(CSFSNP_HEADER *csfsnp_header)
{
    CSFSNP_HEADER_NP_ID(csfsnp_header)              = CSFSNP_ERR_ID;
    CSFSNP_HEADER_NP_MODEL(csfsnp_header)           = CSFSNP_ERR_MODEL;
 
    CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header)  = CHASH_ERR_ALGO_ID;
    CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)  = CHASH_ERR_ALGO_ID;

    CSFSNP_HEADER_BUCKET_MAX_NUM(csfsnp_header)     = 0;

    /*do nothing on CSFSNPRB_POOL pool*/

    return (EC_TRUE);
}

CSFSNP *csfsnp_new()
{
    CSFSNP *csfsnp;

    alloc_static_mem(MM_CSFSNP, &csfsnp, LOC_CSFSNP_0011);
    if(NULL_PTR != csfsnp)
    {
        csfsnp_init(csfsnp);
    }
    return (csfsnp);
}

EC_BOOL csfsnp_init(CSFSNP *csfsnp)
{ 
    CSFSNP_FD(csfsnp)               = ERR_FD;
    CSFSNP_FSIZE(csfsnp)            = 0;
    CSFSNP_FNAME(csfsnp)            = NULL_PTR;
    CSFSNP_RETIRE_NODE_POS(csfsnp)  = CSFSNPRB_ERR_POS;
    CSFSNP_DEL_SIZE(csfsnp)         = 0;
    CSFSNP_RECYCLE_SIZE(csfsnp)     = 0;
    CSFSNP_HDR(csfsnp)              = NULL_PTR;
    CSFSNP_BUCKET_ADDR(csfsnp)      = NULL_PTR;

    CSFSNP_1ST_CHASH_ALGO(csfsnp)   = NULL_PTR;
    CSFSNP_2ND_CHASH_ALGO(csfsnp)   = NULL_PTR;

    CSFSNP_INIT_LOCK(csfsnp, LOC_CSFSNP_0012);

    return (EC_TRUE);
}

EC_BOOL csfsnp_clean(CSFSNP *csfsnp)
{
    if(NULL_PTR != CSFSNP_HDR(csfsnp))
    {
        csfsnp_header_close(CSFSNP_HDR(csfsnp), CSFSNP_ID(csfsnp), CSFSNP_FSIZE(csfsnp), CSFSNP_FD(csfsnp));
        CSFSNP_HDR(csfsnp) = NULL_PTR;
    }
 
    if(ERR_FD != CSFSNP_FD(csfsnp))
    {
        c_file_close(CSFSNP_FD(csfsnp));
        CSFSNP_FD(csfsnp) = ERR_FD;
    }

    if(NULL_PTR != CSFSNP_FNAME(csfsnp))
    {
        safe_free(CSFSNP_FNAME(csfsnp), LOC_CSFSNP_0013);
        CSFSNP_FNAME(csfsnp) = NULL_PTR;
    }

    CSFSNP_FSIZE(csfsnp)            = 0;

    CSFSNP_RETIRE_NODE_POS(csfsnp)  = CSFSNPRB_ERR_POS;
    CSFSNP_DEL_SIZE(csfsnp)         = 0;
    CSFSNP_RECYCLE_SIZE(csfsnp)     = 0; 

    CSFSNP_BUCKET_ADDR(csfsnp)      = NULL_PTR;

    CSFSNP_1ST_CHASH_ALGO(csfsnp)   = NULL_PTR;
    CSFSNP_2ND_CHASH_ALGO(csfsnp)   = NULL_PTR;

    CSFSNP_CLEAN_LOCK(csfsnp, LOC_CSFSNP_0014);

    return (EC_TRUE);
}

EC_BOOL csfsnp_free(CSFSNP *csfsnp)
{
    if(NULL_PTR != csfsnp)
    {
        csfsnp_clean(csfsnp);
        free_static_mem(MM_CSFSNP, csfsnp, LOC_CSFSNP_0015);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_is_full(const CSFSNP *csfsnp)
{
    CSFSNPRB_POOL *pool;

    pool = CSFSNP_ITEMS_POOL(csfsnp);
    return csfsnprb_pool_is_full(pool);
}

EC_BOOL csfsnp_is_empty(const CSFSNP *csfsnp)
{
    CSFSNPRB_POOL *pool;

    pool = CSFSNP_ITEMS_POOL(csfsnp);
    return csfsnprb_pool_is_empty(pool);
}

void csfsnp_header_print(LOG *log, const CSFSNP *csfsnp)
{
    const CSFSNP_HEADER *csfsnp_header;

    csfsnp_header = CSFSNP_HDR(csfsnp);

    sys_log(log, "np %u, model %u, item max num %u, item used num %u, item del num %u, bucket max num %u, bucket offset %u, 1st hash algo %u, 2nd hash algo %u\n",
                CSFSNP_HEADER_NP_ID(csfsnp_header),
                CSFSNP_HEADER_NP_MODEL(csfsnp_header),
                CSFSNP_HEADER_ITEMS_MAX_NUM(csfsnp_header) ,
                CSFSNP_HEADER_ITEMS_USED_NUM(csfsnp_header) ,
                CSFSNP_HEADER_DEL_ITEMS_CUR_NUM(csfsnp_header),
                CSFSNP_HEADER_BUCKET_MAX_NUM(csfsnp_header),
                CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header),
                CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header),
                CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)
        );

    if(0)/*debug*/
    {
        csfsnprb_pool_print(log, CSFSNP_HEADER_ITEMS_POOL(csfsnp_header));

        csfsnp_show_all_buckets(log, csfsnp);
    }
    return;
}

void csfsnp_print(LOG *log, const CSFSNP *csfsnp)
{
    sys_log(log, "csfsnp %p: np %u, fname %s, fsize %u, delete %"PRId64"\n",
                 csfsnp,
                 CSFSNP_ID(csfsnp),
                 CSFSNP_FNAME(csfsnp),
                 CSFSNP_FSIZE(csfsnp),
                 CSFSNP_DEL_SIZE(csfsnp)
                 );

    sys_log(log, "csfsnp %p: header: \n", csfsnp);
    csfsnp_header_print(log, csfsnp);
    return;
}

void csfsnp_bucket_print(LOG *log, const uint32_t *csfsnp_buckets, const uint32_t bucket_num)
{
    uint32_t pos;

    for(pos = 0; pos < bucket_num; pos ++)
    {
        sys_log(log, "bucket %u#: offset %u\n", pos, *(csfsnp_buckets + pos));
    }
    return;
}

STATIC_CAST static const CSFSNP_ITEM *__csfsnp_bucket_find(const CSFSNP *csfsnp, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    const CSFSNPRB_POOL *pool;
    uint32_t bucket_pos;
    uint32_t root_pos;
    uint32_t node_pos;

    pool       = CSFSNP_ITEMS_POOL(csfsnp);
    bucket_pos = CSFSNP_BUCKET_POS(csfsnp, first_hash);
    root_pos   = CSFSNP_BUCKET(csfsnp, bucket_pos);

    node_pos = csfsnprb_tree_search_data(pool, root_pos, second_hash, klen, key);
    if(CSFSNPRB_ERR_POS != node_pos)
    {
        const CSFSNPRB_NODE *node;
        const CSFSNP_ITEM   *item;
     
        node = CSFSNPRB_POOL_NODE(pool, node_pos);
        item = CSFSNP_RB_NODE_ITEM(node);

        return (item);
    }

    return (NULL_PTR);
}

STATIC_CAST static uint32_t __csfsnp_bucket_search(const CSFSNP *csfsnp, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    const CSFSNPRB_POOL *pool;
    uint32_t bucket_pos;
    uint32_t root_pos;

    pool       = CSFSNP_ITEMS_POOL(csfsnp);
    bucket_pos = CSFSNP_BUCKET_POS(csfsnp, first_hash);
    root_pos   = CSFSNP_BUCKET(csfsnp, bucket_pos);
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_bucket_search: bucket %u, root %u\n", bucket_pos, root_pos);
    return csfsnprb_tree_search_data(pool, root_pos, second_hash, klen, key);
}

STATIC_CAST static uint32_t __csfsnp_bucket_insert(CSFSNP *csfsnp, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    uint32_t insert_offset;
    uint32_t bucket_pos;
    uint32_t root_pos;

    if(EC_TRUE == csfsnp_is_full(csfsnp))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_bucket_insert: csfsnp is full\n");
        return (CSFSNPRB_ERR_POS);
    }

    /*insert the item*/
    bucket_pos = CSFSNP_BUCKET_POS(csfsnp, first_hash);
    root_pos   = CSFSNP_BUCKET(csfsnp, bucket_pos);

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_bucket_insert: bucket %u, root %u\n", bucket_pos, root_pos);

    if(EC_FALSE == csfsnprb_tree_insert_data(CSFSNP_ITEMS_POOL(csfsnp), &root_pos, second_hash, klen, key, &insert_offset))
    {
        /*dbg_log(SEC_0173_CSFSNP, 1)(LOGSTDOUT, "warn:__csfsnp_bucket_insert: found duplicate rb node with root %u at node %u\n", root_pos, insert_offset);*/
        /*return (insert_offset);*/

        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_bucket_insert: found duplicate at node %u where bucket %u, root %u\n",
                        insert_offset, bucket_pos, root_pos);
        return (CSFSNPRB_ERR_POS);
    }
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_bucket_insert: bucket %u, root %u => %u\n", bucket_pos, CSFSNP_BUCKET(csfsnp, bucket_pos), root_pos);
    CSFSNP_BUCKET(csfsnp, bucket_pos) = root_pos; 
    return (insert_offset);
}

STATIC_CAST static EC_BOOL __csfsnp_bucket_delete(CSFSNP *csfsnp, const uint32_t first_hash, const uint32_t second_hash, const uint32_t klen, const uint8_t *key)
{
    CSFSNP_ITEM *csfsnp_item;
 
    uint32_t node_pos;
    uint32_t bucket_pos;
    uint32_t root_pos;

    if(EC_TRUE == csfsnp_is_empty(csfsnp))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:__csfsnp_bucket_delete: csfsnp is empty\n");
        return (EC_FALSE);
    }

    /*delete the item*/
    bucket_pos = CSFSNP_BUCKET_POS(csfsnp, first_hash);
    root_pos   = CSFSNP_BUCKET(csfsnp, bucket_pos);

    node_pos = csfsnprb_tree_search_data(CSFSNP_ITEMS_POOL(csfsnp), root_pos, second_hash, klen, key);
    if(CSFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0173_CSFSNP, 1)(LOGSTDOUT, "warn:__csfsnp_bucket_delete: found nothing from bucket %u, root %u\n", bucket_pos, root_pos);
        return (EC_FALSE);
    }

    csfsnprb_tree_delete(CSFSNP_ITEMS_POOL(csfsnp), &root_pos, node_pos);
 
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_bucket_delete: bucket %u: root %u => %u\n", bucket_pos, CSFSNP_BUCKET(csfsnp, bucket_pos), root_pos);
    CSFSNP_BUCKET(csfsnp, bucket_pos) = root_pos;

    csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
    if(NULL_PTR != csfsnp_item)
    {
        CSFSNP_FNODE *csfsnp_fnode;

        csfsnp_fnode = CSFSNP_ITEM_FNODE(csfsnp_item);
        CSFSNP_DEL_SIZE(csfsnp) += CSFSNP_FNODE_FILESZ(csfsnp_fnode);
        CSFSNP_HEADER_DEL_ITEMS_CUR_NUM(CSFSNP_HDR(csfsnp)) ++;
     
        csfsnp_item_clean(csfsnp_item);
    }
 
    return (EC_TRUE);
}

/*delete single item from bucket*/
STATIC_CAST static EC_BOOL __csfsnp_bucket_delete_item(CSFSNP *csfsnp, const uint32_t bucket_pos, const uint32_t node_pos)
{
    CSFSNP_ITEM *csfsnp_item;
    uint32_t     root_pos;

    ASSERT(CSFSNPRB_ERR_POS != bucket_pos);
    ASSERT(CSFSNPRB_ERR_POS != node_pos);

    root_pos = CSFSNP_BUCKET(csfsnp, bucket_pos);

    csfsnprb_tree_delete(CSFSNP_ITEMS_POOL(csfsnp), &root_pos, node_pos);
 
    CSFSNP_BUCKET(csfsnp, bucket_pos) = root_pos;

    csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
    if(NULL_PTR != csfsnp_item)
    {
        CSFSNP_FNODE *csfsnp_fnode;

        csfsnp_fnode = CSFSNP_ITEM_FNODE(csfsnp_item);
        CSFSNP_DEL_SIZE(csfsnp) += CSFSNP_FNODE_FILESZ(csfsnp_fnode); 
        CSFSNP_HEADER_DEL_ITEMS_CUR_NUM(CSFSNP_HDR(csfsnp)) ++;

        csfsnp_item_clean(csfsnp_item);
    } 
 
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_delete_one_bucket(CSFSNP *csfsnp, const uint32_t bucket_pos)
{
    while(CSFSNPRB_ERR_POS != CSFSNP_BUCKET(csfsnp, bucket_pos))
    {
        uint32_t node_pos;

        node_pos = CSFSNP_BUCKET(csfsnp, bucket_pos);
        __csfsnp_bucket_delete_item(csfsnp, bucket_pos, node_pos);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_delete_all_buckets(CSFSNP *csfsnp)
{
    uint32_t bucket_num;
    uint32_t bucket_pos;

    bucket_num = CSFSNP_BUCKET_MAX_NUM(csfsnp);
    for(bucket_pos = 0; bucket_pos < bucket_num; bucket_pos ++)
    {
        __csfsnp_delete_one_bucket(csfsnp, bucket_pos);
    }
    return (EC_TRUE);
}

uint32_t csfsnp_search_no_lock(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path)
{
    uint8_t  digest[ CMD5_DIGEST_LEN ];
    uint32_t path_1st_hash;
    uint32_t path_2nd_hash; 

    __csfsnp_path_hash(csfsnp, path_len, path, CMD5_DIGEST_LEN, digest, &path_1st_hash, &path_2nd_hash);

    if(do_log(SEC_0173_CSFSNP, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfsnp_search_no_lock: ");
        __csfsnp_print_hash(LOGSTDOUT, path_len, path, path_1st_hash, path_2nd_hash, CMD5_DIGEST_LEN, digest);
    }
 
    return __csfsnp_bucket_search(csfsnp, path_1st_hash, path_2nd_hash, CMD5_DIGEST_LEN, digest);
}

uint32_t csfsnp_search(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path)
{
    uint32_t node_pos;

    CSFSNP_RDLOCK(csfsnp, LOC_CSFSNP_0016);
    node_pos = csfsnp_search_no_lock(csfsnp, path_len, path);
    CSFSNP_UNLOCK(csfsnp, LOC_CSFSNP_0017);

    return (node_pos);
}

uint32_t csfsnp_insert_no_lock(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path)
{
    CSFSNP_ITEM *csfsnp_item;

    uint8_t  digest[ CMD5_DIGEST_LEN ];
    uint32_t path_1st_hash;
    uint32_t path_2nd_hash;
    uint32_t node_pos;

    __csfsnp_path_hash(csfsnp, path_len, path, CMD5_DIGEST_LEN, digest, &path_1st_hash, &path_2nd_hash);

    if(do_log(SEC_0173_CSFSNP, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfsnp_insert_no_lock: ");
        __csfsnp_print_hash(LOGSTDOUT, path_len, path, path_1st_hash, path_2nd_hash, CMD5_DIGEST_LEN, digest);
    }
 
    node_pos = __csfsnp_bucket_insert(csfsnp, path_1st_hash, path_2nd_hash, CMD5_DIGEST_LEN, digest);
    if(CSFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_insert_no_lock: insert '%.*s' failed\n", path_len, path);
        return (CSFSNPRB_ERR_POS);
    }
 
    csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
    csfsnp_item_set_key(csfsnp_item, CMD5_DIGEST_LEN, digest);
    csfsnp_fnode_init(CSFSNP_ITEM_FNODE(csfsnp_item));
    CSFSNP_ITEM_STAT(csfsnp_item)       = CSFSNP_ITEM_STAT_IS_USED;
    CSFSNP_ITEM_BUCKET_POS(csfsnp_item) = CSFSNP_BUCKET_POS(csfsnp, path_1st_hash);

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_insert_no_lock: insert '%.*s' at %u done\n", path_len, path, node_pos);

    return (node_pos);
}

uint32_t csfsnp_insert(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path)
{
    uint32_t node_pos;

    CSFSNP_WRLOCK(csfsnp, LOC_CSFSNP_0018);
    node_pos = csfsnp_insert_no_lock(csfsnp, path_len, path);
    CSFSNP_UNLOCK(csfsnp, LOC_CSFSNP_0019);

    return (node_pos);
}

CSFSNP_ITEM *csfsnp_fetch(const CSFSNP *csfsnp, const uint32_t node_pos)
{
    if(CSFSNPRB_ERR_POS != node_pos)
    {
        const CSFSNPRB_POOL *pool;
        const CSFSNPRB_NODE *node;

        pool = CSFSNP_ITEMS_POOL(csfsnp);
        node = CSFSNPRB_POOL_NODE(pool, node_pos);
        if(NULL_PTR != node)
        {
            return (CSFSNP_ITEM *)CSFSNP_RB_NODE_ITEM(node);
        }
    }
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_fetch: np %u, fetch node %u failed\n", CSFSNP_ID(csfsnp), node_pos);
    return (NULL_PTR);
}

EC_BOOL csfsnp_inode_update(CSFSNP *csfsnp, CSFSNP_INODE *csfsnp_inode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(src_disk_no  == CSFSNP_INODE_DISK_NO(csfsnp_inode)
    && src_block_no == CSFSNP_INODE_BLOCK_NO(csfsnp_inode)
    && src_page_no  == CSFSNP_INODE_PAGE_NO(csfsnp_inode))
    {
        CSFSNP_INODE_DISK_NO(csfsnp_inode)  = des_disk_no;
        CSFSNP_INODE_BLOCK_NO(csfsnp_inode) = des_block_no;
        CSFSNP_INODE_PAGE_NO(csfsnp_inode)  = des_page_no;
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_fnode_update(CSFSNP *csfsnp, CSFSNP_FNODE *csfsnp_fnode,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t replica;

    for(replica = 0; replica < CSFSNP_FNODE_REPNUM(csfsnp_fnode); replica ++)
    {
        csfsnp_inode_update(csfsnp, CSFSNP_FNODE_INODE(csfsnp_fnode, replica),
                            src_disk_no, src_block_no, src_page_no,
                            des_disk_no, des_block_no, des_page_no);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_bucket_update(CSFSNP * csfsnp, CSFSNPRB_POOL *pool, const uint32_t node_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CSFSNPRB_NODE *node;
    CSFSNP_ITEM   *item;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        __csfsnp_bucket_update(csfsnp, pool, CSFSNPRB_NODE_LEFT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    }

    item = CSFSNP_RB_NODE_ITEM(node);

    csfsnp_item_update(csfsnp, item,
                       src_disk_no, src_block_no, src_page_no,
                       des_disk_no, des_block_no, des_page_no);


    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        __csfsnp_bucket_update(csfsnp, pool, CSFSNPRB_NODE_RIGHT_POS(node),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);
    } 
 
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_update_one_bucket(CSFSNP *csfsnp, const uint32_t bucket_pos,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    CSFSNPRB_POOL *pool;
    pool = CSFSNP_ITEMS_POOL(csfsnp);

    return __csfsnp_bucket_update(csfsnp, pool, CSFSNP_BUCKET(csfsnp, bucket_pos),
                                   src_disk_no, src_block_no, src_page_no,
                                   des_disk_no, des_block_no, des_page_no); 
}

EC_BOOL csfsnp_update_all_buckets(CSFSNP *csfsnp,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t bucket_num;
    uint32_t bucket_pos;

    bucket_num = CSFSNP_BUCKET_MAX_NUM(csfsnp); 
    for(bucket_pos = 0; bucket_pos < bucket_num; bucket_pos ++)
    {
        if(EC_FALSE == __csfsnp_update_one_bucket(csfsnp, bucket_pos,
                                       src_disk_no, src_block_no, src_page_no,
                                       des_disk_no, des_block_no, des_page_no))
        {
            dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_update_all_buckets: update bucket %u failed\n", bucket_pos);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_item_update(CSFSNP *csfsnp, CSFSNP_ITEM *csfsnp_item,
                                   const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                                   const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)
{
    if(CSFSNP_ITEM_STAT_IS_NOT_USED == CSFSNP_ITEM_STAT(csfsnp_item))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_item_update: item was not used\n");
        return (EC_FALSE);
    }

    return csfsnp_fnode_update(csfsnp, CSFSNP_ITEM_FNODE(csfsnp_item),
                               src_disk_no, src_block_no, src_page_no,
                               des_disk_no, des_block_no, des_page_no);    
}

EC_BOOL csfsnp_update_no_lock(CSFSNP *csfsnp,
                               const uint16_t src_disk_no, const uint16_t src_block_no, const uint16_t src_page_no,
                               const uint16_t des_disk_no, const uint16_t des_block_no, const uint16_t des_page_no)

{
    uint32_t offset;
    CSFSNP_ITEM *csfsnp_item;

    offset = 0;/*the first item is root directory*/
    csfsnp_item = csfsnp_fetch(csfsnp, offset);
    return csfsnp_item_update(csfsnp, csfsnp_item,
                              src_disk_no, src_block_no, src_page_no,
                              des_disk_no, des_block_no, des_page_no);    /*recursively*/
}


CSFSNP_ITEM *csfsnp_set(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path)
{
    return csfsnp_fetch(csfsnp, csfsnp_insert(csfsnp, path_len, path));
}

CSFSNP_ITEM *csfsnp_get(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path)
{
    return csfsnp_fetch(csfsnp, csfsnp_search(csfsnp, path_len, path));
}

EC_BOOL csfsnp_delete(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path)
{
    uint8_t  digest[ CMD5_DIGEST_LEN ];
 
    uint32_t path_1st_hash;
    uint32_t path_2nd_hash;

    __csfsnp_path_hash(csfsnp, path_len, path, CMD5_DIGEST_LEN, digest, &path_1st_hash, &path_2nd_hash);

    CSFSNP_WRLOCK(csfsnp, LOC_CSFSNP_0020);
 
    if(EC_FALSE == __csfsnp_bucket_delete(csfsnp, path_1st_hash, path_2nd_hash, CMD5_DIGEST_LEN, digest))
    {
        CSFSNP_UNLOCK(csfsnp, LOC_CSFSNP_0021);

        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_delete: delete '%.*s' failed\n", path_len, path);
        return (EC_FALSE);
    }
    CSFSNP_UNLOCK(csfsnp, LOC_CSFSNP_0022);
 
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_delete: delete '%.*s' done\n", path_len, path);
    return (EC_TRUE);
}

EC_BOOL csfsnp_delete_item(CSFSNP *csfsnp, const uint32_t node_pos)
{
    CSFSNP_ITEM   *csfsnp_item;

    csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
    if(NULL_PTR == csfsnp_item)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_delete_item: invalid node_pos %u\n", node_pos);
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfsnp_bucket_delete_item(csfsnp, CSFSNP_ITEM_BUCKET_POS(csfsnp_item), node_pos))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_delete_item: delete node_pos %u from bucket %u failed\n",
                    node_pos, CSFSNP_ITEM_BUCKET_POS(csfsnp_item));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsnp_umount_item(CSFSNP *csfsnp, const uint32_t node_pos)
{
    CSFSNP_ITEM *csfsnp_item;

    csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
    if(NULL_PTR == csfsnp_item)
    {
        return (EC_FALSE);
    } 

    __csfsnp_bucket_delete_item(csfsnp, CSFSNP_ITEM_BUCKET_POS(csfsnp_item), node_pos);

    return (EC_TRUE);
}

uint32_t csfsnp_count_file_num(const CSFSNP *csfsnp)
{
    return CSFSNP_ITEMS_USED_NUM(csfsnp);
}

EC_BOOL csfsnp_file_size(CSFSNP *csfsnp, const uint32_t path_len, const uint8_t *path, uint32_t *file_size)
{
    CSFSNP_ITEM *csfsnp_item;

    csfsnp_item = csfsnp_get(csfsnp, path_len, path);
    if(NULL_PTR == csfsnp_item)
    {
        (*file_size) = 0;
        return (EC_FALSE);
    }

    (*file_size) = CSFSNP_ITEM_F_SIZE(csfsnp_item);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_count_bucket_file_size(CSFSNP * csfsnp, CSFSNPRB_POOL *pool, const uint32_t node_pos, uint64_t *file_size)
{
    CSFSNPRB_NODE *node;
    CSFSNP_ITEM   *item;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        __csfsnp_count_bucket_file_size(csfsnp, pool, CSFSNPRB_NODE_LEFT_POS(node), file_size);
    }

    item = CSFSNP_RB_NODE_ITEM(node);
    (*file_size) += CSFSNP_ITEM_F_SIZE(item);

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        __csfsnp_count_bucket_file_size(csfsnp, pool, CSFSNPRB_NODE_RIGHT_POS(node), file_size);
    } 
 
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_count_one_bucket_file_size(CSFSNP *csfsnp, const uint32_t bucket_pos, uint64_t *file_size)
{
    CSFSNPRB_POOL *pool;
    pool = CSFSNP_ITEMS_POOL(csfsnp);

    return __csfsnp_count_bucket_file_size(csfsnp, pool, bucket_pos, file_size);
}

EC_BOOL csfsnp_count_file_size(CSFSNP *csfsnp, uint64_t *file_size)
{
    uint32_t bucket_num;
    uint32_t bucket_pos;

    bucket_num = CSFSNP_BUCKET_MAX_NUM(csfsnp);
    for(bucket_pos = 0; bucket_pos < bucket_num; bucket_pos ++)
    {
        __csfsnp_count_one_bucket_file_size(csfsnp, bucket_pos, file_size);
    }
    return (EC_TRUE);
}

CSFSNP *csfsnp_open(const char *np_root_dir, const uint32_t np_id)
{
    UINT32 fsize;
    char *np_fname;
    CSFSNP *csfsnp;
    CSFSNP_HEADER *csfsnp_header;
    int fd;

    np_fname = __csfsnp_fname_gen(np_root_dir, np_id);
    if(NULL_PTR == np_fname)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_open: generate np fname from np_root_dir %s failed\n", np_root_dir);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_access(np_fname, F_OK))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_open: np %s not exist, pls create it at first\n", np_fname);
        safe_free(np_fname, LOC_CSFSNP_0023);
        return (NULL_PTR);
    }

    fd = c_file_open(np_fname, O_RDWR, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_open: open csfsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CSFSNP_0024);
        return (NULL_PTR);
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_open: np %u, open file %s done\n", np_id, np_fname);

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_open: get size of %s failed\n", np_fname);
        safe_free(np_fname, LOC_CSFSNP_0025);
        c_file_close(fd);
        return (NULL_PTR);
    } 

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_open: np %u, file size %lu\n", np_id, fsize);

    csfsnp_header = csfsnp_header_open(np_id, fsize, fd);
    if(NULL_PTR == csfsnp_header)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_open: open csfsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CSFSNP_0026);
        c_file_close(fd);
        return (NULL_PTR);
    } 

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_open: np %u, open header done\n", np_id);

    csfsnp = csfsnp_new();
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_open: new csfsnp %u failed\n", np_id);
        safe_free(np_fname, LOC_CSFSNP_0027);
        csfsnp_header_close(csfsnp_header, np_id, fsize, fd);
        c_file_close(fd);
        return (NULL_PTR);
    }

    CSFSNP_HDR(csfsnp) = csfsnp_header;
    CSFSNP_BUCKET_ADDR(csfsnp)= (uint32_t *)(((uint8_t *)csfsnp_header) + CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header));

    CSFSNP_1ST_CHASH_ALGO(csfsnp) = chash_algo_fetch(CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header));
    CSFSNP_2ND_CHASH_ALGO(csfsnp) = chash_algo_fetch(CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)); 

    CSFSNP_FD(csfsnp)    = fd;
    CSFSNP_FSIZE(csfsnp) = fsize;
    CSFSNP_FNAME(csfsnp) = (uint8_t *)np_fname;

    ASSERT(np_id == CSFSNP_HEADER_NP_ID(csfsnp_header));

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_open: open csfsnp %u from %s done\n", np_id, np_fname);

    return (csfsnp);
}

EC_BOOL csfsnp_close(CSFSNP *csfsnp)
{
    if(NULL_PTR != csfsnp)
    {
        if(NULL_PTR != CSFSNP_HDR(csfsnp))
        {
            csfsnp_header_close(CSFSNP_HDR(csfsnp), CSFSNP_ID(csfsnp), CSFSNP_FSIZE(csfsnp), CSFSNP_FD(csfsnp));
            CSFSNP_HDR(csfsnp) = NULL_PTR;
        }
        csfsnp_free(csfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_sync(CSFSNP *csfsnp)
{
    if(NULL_PTR != csfsnp && NULL_PTR != CSFSNP_HDR(csfsnp))
    {
        csfsnp_header_sync(CSFSNP_HDR(csfsnp), CSFSNP_ID(csfsnp), CSFSNP_FSIZE(csfsnp), CSFSNP_FD(csfsnp));
    }
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_sync: sync csfsnp %p done\n", csfsnp);
    return (EC_TRUE);
}

CSFSNP *csfsnp_create(const char *np_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id)
{
    CSFSNP          *csfsnp;
    CSFSNP_HEADER   *csfsnp_header;
    char            *np_fname;
    UINT32           fsize;
    uint32_t         bucket_max_num;
    int              fd;

    if(EC_FALSE == csfsnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_create: np %u: np model %u => fsize %ld\n", np_id, np_model, fsize);

    np_fname = __csfsnp_fname_gen(np_root_dir, np_id);
    if(NULL_PTR == np_fname)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_create: generate np_fname of np %u, root_dir %s failed\n", np_id, np_root_dir);
        return (NULL_PTR);
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_create: np %u => np fname %s\n", np_id, np_fname);
 
    if(EC_TRUE == c_file_access(np_fname, F_OK))/*exist*/
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_create: np %u exist already\n", np_id);
        safe_free(np_fname, LOC_CSFSNP_0028);
        return (NULL_PTR);
    }

    fd = c_file_open(np_fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_create: cannot create np %s\n", np_fname);
        safe_free(np_fname, LOC_CSFSNP_0029);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_truncate(fd, fsize))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_create: truncate np %s to size %lu failed\n", np_fname, fsize);
        safe_free(np_fname, LOC_CSFSNP_0030);
        c_file_close(fd);
        return (NULL_PTR);
    }

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_create: truncate np %s to size %lu done\n", np_fname, fsize);

    bucket_max_num = CSFSNP_BUCKET_NUM;

    csfsnp_header = __csfsnp_header_create(np_id, fsize, fd, np_model, bucket_max_num);
    if(NULL_PTR == csfsnp_header)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_create: open csfsnp file %s failed\n", np_fname);
        safe_free(np_fname, LOC_CSFSNP_0031);
        c_file_close(fd);
        return (NULL_PTR);
    }
    CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header) = hash_1st_algo_id;
    CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header) = hash_2nd_algo_id; 

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_create: np %u: create header done\n", np_id);

    csfsnp = csfsnp_new();
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_create: new csfsnp %u failed\n", np_id);
        safe_free(np_fname, LOC_CSFSNP_0032);
        __csfsnp_header_close(csfsnp_header, np_id, fsize, fd);
        c_file_close(fd);
        return (NULL_PTR);
    }
    CSFSNP_HDR(csfsnp) = csfsnp_header;
 
    CSFSNP_BUCKET_ADDR(csfsnp) = (uint32_t *)(((uint8_t *)csfsnp_header) + CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header));
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_create: csfsnp_header = %p, offset = %u, bucket addr %p\n",
                        csfsnp_header, CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header), CSFSNP_BUCKET_ADDR(csfsnp));

    CSFSNP_1ST_CHASH_ALGO(csfsnp) = chash_algo_fetch(CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header));
    CSFSNP_2ND_CHASH_ALGO(csfsnp) = chash_algo_fetch(CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)); 

    CSFSNP_FD(csfsnp)    = fd;
    CSFSNP_FSIZE(csfsnp) = fsize;
    CSFSNP_FNAME(csfsnp) = (uint8_t *)np_fname;

    ASSERT(np_id == CSFSNP_HEADER_NP_ID(csfsnp_header)); 

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_create: create np %u done\n", np_id);

    return (csfsnp);
}

EC_BOOL csfsnp_show_item(LOG *log, const CSFSNP_ITEM *csfsnp_item)
{
    if(CSFSNP_ITEM_STAT_IS_NOT_USED == CSFSNP_ITEM_STAT(csfsnp_item))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_show_item: item %p not used\n", csfsnp_item);
        return (EC_FALSE);
    }

    csfsnp_item_print(log, csfsnp_item);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_show_one_bucket(LOG *log, const CSFSNP * csfsnp, const CSFSNPRB_POOL *pool, const uint32_t node_pos)
{
    CSFSNPRB_NODE *node;
    CSFSNP_ITEM   *item;

    if(CSFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }
 
    node  = CSFSNPRB_POOL_NODE(pool, node_pos); 
    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_LEFT_POS(node))
    {
        __csfsnp_show_one_bucket(log, csfsnp, pool, CSFSNPRB_NODE_LEFT_POS(node));
    }

    item = CSFSNP_RB_NODE_ITEM(node);
    csfsnp_show_item(log, item);

    if(CSFSNPRB_ERR_POS != CSFSNPRB_NODE_RIGHT_POS(node))
    {
        __csfsnp_show_one_bucket(log, csfsnp, pool, CSFSNPRB_NODE_RIGHT_POS(node));
    } 
 
    return (EC_TRUE);
}


EC_BOOL csfsnp_show_one_bucket(LOG *log, const CSFSNP *csfsnp, const uint32_t bucket_pos)
{
    const CSFSNPRB_POOL *pool;
    pool = CSFSNP_ITEMS_POOL(csfsnp);
 
    return __csfsnp_show_one_bucket(log, csfsnp, pool, CSFSNP_BUCKET(csfsnp, bucket_pos));
}


EC_BOOL csfsnp_show_all_buckets(LOG *log, const CSFSNP *csfsnp)
{
    uint32_t bucket_num;
    uint32_t bucket_pos;

    bucket_num = CSFSNP_BUCKET_MAX_NUM(csfsnp);

    for(bucket_pos = 0; bucket_pos < bucket_num; bucket_pos ++)
    {
        csfsnp_show_one_bucket(log, csfsnp, bucket_pos);
    }

    return (EC_TRUE);
}

/*-------------------------------------------- NP in memory --------------------------------------------*/
CSFSNP *csfsnp_mem_create(const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num)
{
    CSFSNP         *csfsnp;
    CSFSNP_HEADER  *csfsnp_header;
    UINT32          fsize;
    int             fd;

    fd = ERR_FD;

    if(EC_FALSE == csfsnp_model_file_size(np_model, &fsize))
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_mem_create: invalid np_model %u\n", np_model);
        return (NULL_PTR);
    }

    csfsnp_header = __csfsnp_header_new(np_id, fsize, fd, np_model, bucket_max_num);
    if(NULL_PTR == csfsnp_header)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_mem_create: new mem csfsnp failed\n");
        return (NULL_PTR);
    }

    csfsnp = csfsnp_new();
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0173_CSFSNP, 0)(LOGSTDOUT, "error:csfsnp_mem_create: new csfsnp %u failed\n", np_id);
        __csfsnp_header_free(csfsnp_header, np_id, fsize, fd);
        return (NULL_PTR);
    }
    CSFSNP_HDR(csfsnp) = csfsnp_header;
 
    CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header)  = hash_1st_algo_id;
    CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)  = hash_2nd_algo_id;

    CSFSNP_BUCKET_ADDR(csfsnp) = (uint32_t *)(((uint8_t *)csfsnp_header) + CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header));
    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mem_create: csfsnp_header = %p, offset = %u, bucket addr %p\n",
                        csfsnp_header, CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header), CSFSNP_BUCKET_ADDR(csfsnp));

    CSFSNP_1ST_CHASH_ALGO(csfsnp) = chash_algo_fetch(CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header));
    CSFSNP_2ND_CHASH_ALGO(csfsnp) = chash_algo_fetch(CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)); 

    CSFSNP_FD(csfsnp)    = fd;
    CSFSNP_FSIZE(csfsnp) = fsize;
    CSFSNP_FNAME(csfsnp) = NULL_PTR;

    dbg_log(SEC_0173_CSFSNP, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mem_create: create np %u done\n", np_id);

    return (csfsnp);
}

EC_BOOL csfsnp_mem_clean(CSFSNP *csfsnp)
{
    if(NULL_PTR != CSFSNP_HDR(csfsnp))
    {
        __csfsnp_header_free(CSFSNP_HDR(csfsnp), CSFSNP_ID(csfsnp), CSFSNP_FSIZE(csfsnp), CSFSNP_FD(csfsnp));
        CSFSNP_HDR(csfsnp) = NULL_PTR;
    }

    ASSERT(ERR_FD == CSFSNP_FD(csfsnp));

    CSFSNP_FSIZE(csfsnp) = 0;

    ASSERT(NULL_PTR == CSFSNP_FNAME(csfsnp));

    CSFSNP_DEL_SIZE(csfsnp)     = 0;
    CSFSNP_RECYCLE_SIZE(csfsnp) = 0;

    CSFSNP_RETIRE_NODE_POS(csfsnp) = CSFSNPRB_ERR_POS;

    CSFSNP_HDR(csfsnp) = NULL_PTR;

    CSFSNP_CLEAN_LOCK(csfsnp, LOC_CSFSNP_0033);

    CSFSNP_1ST_CHASH_ALGO(csfsnp) = NULL_PTR;
    CSFSNP_2ND_CHASH_ALGO(csfsnp) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL csfsnp_mem_free(CSFSNP *csfsnp)
{
    if(NULL_PTR != csfsnp)
    {
        csfsnp_mem_clean(csfsnp);
        free_static_mem(MM_CSFSNP, csfsnp, LOC_CSFSNP_0034);
    }
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

