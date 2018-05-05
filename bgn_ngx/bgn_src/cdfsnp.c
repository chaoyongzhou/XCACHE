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

#include "cbloom.h"
#include "cdfsnp.h"
#include "chashalgo.h"
#include "cdsk.h"
#include "cstack.h"

static CDFSNP_CFG g_cdfsnp_cfg_tbl[] = {
/*CDFSNP_4K_MODE  */{"CDFSNP_4K_MODE"  , CDFSNP_4K_CFG_FILE_SIZE  ,  CDFSNP_4K_CFG_ITEM_MAX_NUM  ,  CDFSNP_4K_CFG_BLOOM_ROW_NUM  ,  CDFSNP_4K_CFG_BLOOM_COL_NUM  },
/*CDFSNP_64K_MODE */{"CDFSNP_64K_MODE" , CDFSNP_64K_CFG_FILE_SIZE ,  CDFSNP_64K_CFG_ITEM_MAX_NUM ,  CDFSNP_64K_CFG_BLOOM_ROW_NUM ,  CDFSNP_64K_CFG_BLOOM_COL_NUM },
/*CDFSNP_1M_MODE  */{"CDFSNP_1M_MODE"  , CDFSNP_1M_CFG_FILE_SIZE  ,  CDFSNP_1M_CFG_ITEM_MAX_NUM  ,  CDFSNP_1M_CFG_BLOOM_ROW_NUM  ,  CDFSNP_1M_CFG_BLOOM_COL_NUM  },
/*CDFSNP_2M_MODE  */{"CDFSNP_2M_MODE"  , CDFSNP_2M_CFG_FILE_SIZE  ,  CDFSNP_2M_CFG_ITEM_MAX_NUM  ,  CDFSNP_2M_CFG_BLOOM_ROW_NUM  ,  CDFSNP_2M_CFG_BLOOM_COL_NUM  },
/*CDFSNP_128M_MODE*/{"CDFSNP_128M_MODE", CDFSNP_128M_CFG_FILE_SIZE,  CDFSNP_128M_CFG_ITEM_MAX_NUM,  CDFSNP_128M_CFG_BLOOM_ROW_NUM,  CDFSNP_128M_CFG_BLOOM_COL_NUM},
/*CDFSNP_256M_MODE*/{"CDFSNP_256M_MODE", CDFSNP_256M_CFG_FILE_SIZE,  CDFSNP_256M_CFG_ITEM_MAX_NUM,  CDFSNP_256M_CFG_BLOOM_ROW_NUM,  CDFSNP_256M_CFG_BLOOM_COL_NUM},
/*CDFSNP_512M_MODE*/{"CDFSNP_512M_MODE", CDFSNP_512M_CFG_FILE_SIZE,  CDFSNP_512M_CFG_ITEM_MAX_NUM,  CDFSNP_512M_CFG_BLOOM_ROW_NUM,  CDFSNP_512M_CFG_BLOOM_COL_NUM},
/*CDFSNP_1G_MODE  */{"CDFSNP_1G_MODE"  , CDFSNP_1G_CFG_FILE_SIZE  ,  CDFSNP_1G_CFG_ITEM_MAX_NUM  ,  CDFSNP_1G_CFG_BLOOM_ROW_NUM  ,  CDFSNP_1G_CFG_BLOOM_COL_NUM  },
/*CDFSNP_2G_MODE  */{"CDFSNP_2G_MODE"  , CDFSNP_2G_CFG_FILE_SIZE  ,  CDFSNP_2G_CFG_ITEM_MAX_NUM  ,  CDFSNP_2G_CFG_BLOOM_ROW_NUM  ,  CDFSNP_2G_CFG_BLOOM_COL_NUM  },
#if (64 == WORDSIZE)
/*CDFSNP_4G_MODE  */{"CDFSNP_4G_MODE"  , CDFSNP_4G_CFG_FILE_SIZE  ,  CDFSNP_4G_CFG_ITEM_MAX_NUM  ,  CDFSNP_4G_CFG_BLOOM_ROW_NUM  ,  CDFSNP_4G_CFG_BLOOM_COL_NUM  },
#endif/*(64 == WORDSIZE)*/
};

static UINT32 g_cdfsnp_cfg_tbl_len = sizeof(g_cdfsnp_cfg_tbl)/sizeof(g_cdfsnp_cfg_tbl[0]);

#define CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, fname) do{\
    if((offset) % sizeof(CDFSNP_ITEM))\
    {\
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:%s: not aligned item offset %ld\n", (char *)fname, (offset));\
    }\
}while(0)

EC_BOOL cdfsnp_mode_str(const UINT32 cdfsnp_mode, char **mod_str)
{
    CDFSNP_CFG *cdfsnp_cfg;
    if(cdfsnp_mode >= g_cdfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_mode_str: invalid cdfsnp mode %ld\n", cdfsnp_mode);
        return (EC_FALSE);
    }
    cdfsnp_cfg = &(g_cdfsnp_cfg_tbl[ cdfsnp_mode ]);
    (*mod_str) = CDFSNP_CFG_MOD_STR(cdfsnp_cfg);
    return (EC_TRUE);
}

UINT32 cdfsnp_mode_get(const char *mod_str)
{
    UINT32 cdfsnp_mode;

    for(cdfsnp_mode = 0; cdfsnp_mode < g_cdfsnp_cfg_tbl_len; cdfsnp_mode ++)
    {
        CDFSNP_CFG *cdfsnp_cfg;
        cdfsnp_cfg = &(g_cdfsnp_cfg_tbl[ cdfsnp_mode ]);

        if(0 == strcasecmp(CDFSNP_CFG_MOD_STR(cdfsnp_cfg), mod_str))
        {
            return (cdfsnp_mode);
        }
    }
    return (CDFSNP_ERR_MODE);
}

EC_BOOL cdfsnp_mode_file_size(const UINT32 cdfsnp_mode, UINT32 *file_size)
{
    CDFSNP_CFG *cdfsnp_cfg;
    if(cdfsnp_mode >= g_cdfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_mode_file_size: invalid cdfsnp mode %ld\n", cdfsnp_mode);
        return (EC_FALSE);
    }
    cdfsnp_cfg = &(g_cdfsnp_cfg_tbl[ cdfsnp_mode ]);
    (*file_size) = CDFSNP_CFG_FILE_SIZE(cdfsnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mode_item_max_num(const UINT32 cdfsnp_mode, UINT32 *item_max_num)
{
    CDFSNP_CFG *cdfsnp_cfg;
    if(cdfsnp_mode >= g_cdfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_mode_item_max_num: invalid cdfsnp mode %ld\n", cdfsnp_mode);
        return (EC_FALSE);
    }
    cdfsnp_cfg = &(g_cdfsnp_cfg_tbl[ cdfsnp_mode ]);
    (*item_max_num) = CDFSNP_CFG_ITEM_MAX_NUM(cdfsnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mode_bloom_row_num(const UINT32 cdfsnp_mode, UINT32 *bloom_row_num)
{
    CDFSNP_CFG *cdfsnp_cfg;
    if(cdfsnp_mode >= g_cdfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_mode_bloom_row_num: invalid cdfsnp mode %ld\n", cdfsnp_mode);
        return (EC_FALSE);
    }
    cdfsnp_cfg = &(g_cdfsnp_cfg_tbl[ cdfsnp_mode ]);
    (*bloom_row_num) = CDFSNP_CFG_BLOOM_ROW_NUM(cdfsnp_cfg);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mode_bloom_col_num(const UINT32 cdfsnp_mode, UINT32 *bloom_col_num)
{
    CDFSNP_CFG *cdfsnp_cfg;
    if(cdfsnp_mode >= g_cdfsnp_cfg_tbl_len)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_mode_bloom_col_num: invalid cdfsnp mode %ld\n", cdfsnp_mode);
        return (EC_FALSE);
    }
    cdfsnp_cfg = &(g_cdfsnp_cfg_tbl[ cdfsnp_mode ]);
    (*bloom_col_num) = CDFSNP_CFG_BLOOM_COL_NUM(cdfsnp_cfg);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL cdfsnp_create_dir(const char *dir_name)
{
    return c_dir_create(dir_name);
}

STATIC_CAST static EC_BOOL cdfsnp_dname_gen(const char *root_dir, const UINT32 disk_num, const UINT32 block_path_layout, char *path, const UINT32 max_len)
{
    CDSK_SHARD cdsk_shard;

    cdsk_pathlayout_to_shard(block_path_layout, disk_num, &cdsk_shard);

    snprintf(path, max_len, "%s/dsk%ld/%ld/%ld/%ld/",
                root_dir,
                CDSK_SHARD_DISK_ID(&cdsk_shard),
                CDFSNP_PATH_LAYOUT_DIR0_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSNP_PATH_LAYOUT_DIR1_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSNP_PATH_LAYOUT_DIR2_NO(CDSK_SHARD_PATH_ID(&cdsk_shard))
                );
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL cdfsnp_fname_gen(const char *root_dir, const UINT32 disk_num, const UINT32 cdfsnp_path_layout, char *path, const UINT32 max_len)
{
    CDSK_SHARD cdsk_shard;

    cdsk_pathlayout_to_shard(cdfsnp_path_layout, disk_num, &cdsk_shard);

    snprintf(path, max_len, "%s/dsk%ld/%ld/%ld/%ld/%ld",
                root_dir,
                CDSK_SHARD_DISK_ID(&cdsk_shard),
                CDFSNP_PATH_LAYOUT_DIR0_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSNP_PATH_LAYOUT_DIR1_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSNP_PATH_LAYOUT_DIR2_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSNP_PATH_LAYOUT_DIR3_NO(CDSK_SHARD_PATH_ID(&cdsk_shard))
                );
    return (EC_TRUE);
}

void cdfsnp_init_buff(UINT8 *buff, const UINT32 len)
{
    UINT32 pos;

    for(pos = 0; pos < len; pos ++)
    {
        buff[ pos ] = '\0';
    }
    return;
}

void cdfsnp_clean_buff(UINT8 *buff, const UINT32 len)
{
    UINT32 pos;

    for(pos = 0; pos < len; pos ++)
    {
        buff[ pos ] = '\0';
    }
    return;
}

void cdfsnp_copy_buff(const UINT8 *src_buff, const UINT32 src_len, UINT8 *des_buff, const UINT32 max_len, UINT32 *len)
{
    UINT32 pos;

    for(pos = 0; pos < src_len && pos < max_len; pos ++)
    {
        des_buff[ pos ] = src_buff[ pos ];
    }
    (*len) = pos;
    return;
}

void cdfsnp_print_buff_0(LOG *log, const UINT8 *buff, const UINT32 len)
{
    UINT32 pos;

    for(pos = 0; pos < len; pos ++)
    {
        sys_print(log, "%02x,", buff[ pos ]);
    }
    return;
}

void cdfsnp_print_buff(LOG *log, const UINT8 *buff, const UINT32 len)
{
    sys_print(log, "%.*s", (uint32_t)len, (char *)buff);
    return;
}

STATIC_CAST static UINT32 cdfsnp_path_seg_len(const UINT8 *full_path, const UINT32 full_path_len, const UINT8 *path_seg_beg)
{
    UINT8 *ptr;

    if(path_seg_beg < full_path || path_seg_beg >= full_path + full_path_len)
    {
        return (0);
    }

    for(ptr = (UINT8 *)path_seg_beg; ptr < full_path + full_path_len && '/' != (*ptr); ptr ++)
    {
        /*do nothing*/
    }

    return (ptr - path_seg_beg);
}

#if 0
CDFSNP_INODE *cdfsnp_inode_new()
{
    CDFSNP_INODE *cdfsnp_inode;

    alloc_static_mem(MM_CDFSNP_INODE, &cdfsnp_inode, LOC_CDFSNP_0001);
    cdfsnp_inode_init(cdfsnp_inode);
    return (cdfsnp_inode);
}
#endif
EC_BOOL cdfsnp_inode_init(CDFSNP_INODE *cdfsnp_inode)
{
    CDFSNP_INODE_TCID(cdfsnp_inode) = CMPI_ERROR_TCID;
    CDFSNP_INODE_PATH(cdfsnp_inode) = CDFSNP_ERR_PATH;
    CDFSNP_INODE_FOFF(cdfsnp_inode) = CDFSNP_ERR_FOFF;
    return (EC_TRUE);
}

EC_BOOL cdfsnp_inode_clean(CDFSNP_INODE *cdfsnp_inode)
{
    CDFSNP_INODE_TCID(cdfsnp_inode) = CMPI_ERROR_TCID;
    CDFSNP_INODE_PATH(cdfsnp_inode) = CDFSNP_ERR_PATH;
    CDFSNP_INODE_FOFF(cdfsnp_inode) = CDFSNP_ERR_FOFF;
    return (EC_TRUE);
}
#if 0
EC_BOOL cdfsnp_inode_free(CDFSNP_INODE *cdfsnp_inode)
{
    if(NULL_PTR != cdfsnp_inode)
    {
        cdfsnp_inode_clean(cdfsnp_inode);
        free_static_mem(MM_CDFSNP_INODE, cdfsnp_inode, LOC_CDFSNP_0002);
    }
    return (EC_TRUE);
}
#endif
EC_BOOL cdfsnp_inode_clone(const CDFSNP_INODE *cdfsnp_inode_src, CDFSNP_INODE *cdfsnp_inode_des)
{
    CDFSNP_INODE_TCID(cdfsnp_inode_des) = CDFSNP_INODE_TCID(cdfsnp_inode_src);
    CDFSNP_INODE_PATH(cdfsnp_inode_des) = (CDFSNP_INODE_PATH(cdfsnp_inode_src) & CDFSNP_32BIT_MASK);
    CDFSNP_INODE_FOFF(cdfsnp_inode_des) = (CDFSNP_INODE_FOFF(cdfsnp_inode_src) & CDFSNP_32BIT_MASK);
    return (EC_TRUE);
}

void cdfsnp_inode_print(LOG *log, const CDFSNP_INODE *cdfsnp_inode)
{
    sys_print(log, "(tcid %s, path %lx, offset %ld)\n",
                 c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode)),
                 (CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK),
                 (CDFSNP_INODE_FOFF(cdfsnp_inode) & CDFSNP_32BIT_MASK)
             );
    return;
}

void cdfsnp_inode_log_no_lock(LOG *log, const CDFSNP_INODE *cdfsnp_inode)
{
    sys_print_no_lock(log, "(tcid %s, path %ld, offset %ld),",
                 c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode)),
                 (CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK),
                 (CDFSNP_INODE_FOFF(cdfsnp_inode) & CDFSNP_32BIT_MASK)
             );
    return;
}

CDFSNP_FNODE *cdfsnp_fnode_new()
{
    CDFSNP_FNODE *cdfsnp_fnode;
    alloc_static_mem(MM_CDFSNP_FNODE, &cdfsnp_fnode, LOC_CDFSNP_0003);
    if(NULL_PTR != cdfsnp_fnode)
    {
        cdfsnp_fnode_init(cdfsnp_fnode);
    }
    return (cdfsnp_fnode);

}

CDFSNP_FNODE *cdfsnp_fnode_make(const CDFSNP_FNODE *cdfsnp_fnode_src)
{
    CDFSNP_FNODE *cdfsnp_fnode_des;
    alloc_static_mem(MM_CDFSNP_FNODE, &cdfsnp_fnode_des, LOC_CDFSNP_0004);
    if(NULL_PTR != cdfsnp_fnode_des)
    {
        cdfsnp_fnode_clone(cdfsnp_fnode_src, cdfsnp_fnode_des);
    }
    return (cdfsnp_fnode_des);
}

EC_BOOL cdfsnp_fnode_init(CDFSNP_FNODE *cdfsnp_fnode)
{
    UINT32 pos;

    //CDFSNP_FNODE_ROFF(cdfsnp_fnode)   = CDFSNP_ITEM_ERR_OFFSET;
    CDFSNP_FNODE_FILESZ(cdfsnp_fnode) = 0;
    CDFSNP_FNODE_REPNUM(cdfsnp_fnode) = 0;
    CDFSNP_FNODE_TRUNCF(cdfsnp_fnode) = CDFSNP_FNODE_IS_NOT_TRUNCATED;
    CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode) = 0;

    for(pos = 0; pos < CDFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdfsnp_inode_init(CDFSNP_FNODE_INODE(cdfsnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_fnode_clean(CDFSNP_FNODE *cdfsnp_fnode)
{
    UINT32 pos;

    //CDFSNP_FNODE_ROFF(cdfsnp_fnode)   = CDFSNP_ITEM_ERR_OFFSET;
    CDFSNP_FNODE_FILESZ(cdfsnp_fnode) = 0;
    CDFSNP_FNODE_REPNUM(cdfsnp_fnode) = 0;
    CDFSNP_FNODE_TRUNCF(cdfsnp_fnode) = CDFSNP_FNODE_IS_NOT_TRUNCATED;
    CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode) = 0;

    for(pos = 0; pos < CDFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdfsnp_inode_clean(CDFSNP_FNODE_INODE(cdfsnp_fnode, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_fnode_free(CDFSNP_FNODE *cdfsnp_fnode)
{
    if(NULL_PTR != cdfsnp_fnode)
    {
        cdfsnp_fnode_clean(cdfsnp_fnode);
        free_static_mem(MM_CDFSNP_FNODE, cdfsnp_fnode, LOC_CDFSNP_0005);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_fnode_clone(const CDFSNP_FNODE *cdfsnp_fnode_src, CDFSNP_FNODE *cdfsnp_fnode_des)
{
    UINT32 pos;

    CDFSNP_FNODE_ROFF(cdfsnp_fnode_des)   = CDFSNP_FNODE_ROFF(cdfsnp_fnode_src);
    CDFSNP_FNODE_FILESZ(cdfsnp_fnode_des) = CDFSNP_FNODE_FILESZ(cdfsnp_fnode_src);
    CDFSNP_FNODE_REPNUM(cdfsnp_fnode_des) = CDFSNP_FNODE_REPNUM(cdfsnp_fnode_src);
    CDFSNP_FNODE_TRUNCF(cdfsnp_fnode_des) = CDFSNP_FNODE_TRUNCF(cdfsnp_fnode_src);
    CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode_des) = CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode_src);

    for(pos = 0; pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode_src) && pos < CDFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdfsnp_inode_clone(CDFSNP_FNODE_INODE(cdfsnp_fnode_src, pos), CDFSNP_FNODE_INODE(cdfsnp_fnode_des, pos));
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_fnode_check_inode_exist(const CDFSNP_INODE *inode, const CDFSNP_FNODE *cdfsnp_fnode)
{
    UINT32 replica_pos;

    for(replica_pos = 0; replica_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode); replica_pos ++)
    {
        if(
            CDFSNP_INODE_TCID(inode) == CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, replica_pos)
         && CDFSNP_INODE_PATH(inode) == CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, replica_pos)
         && CDFSNP_INODE_FOFF(inode) == CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, replica_pos)
        )
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL cdfsnp_fnode_cmp(const CDFSNP_FNODE *cdfsnp_fnode_1st, const CDFSNP_FNODE *cdfsnp_fnode_2nd)
{
    UINT32 replica_pos;

    if(NULL_PTR == cdfsnp_fnode_1st && NULL_PTR == cdfsnp_fnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cdfsnp_fnode_1st || NULL_PTR == cdfsnp_fnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CDFSNP_FNODE_REPNUM(cdfsnp_fnode_1st) != CDFSNP_FNODE_REPNUM(cdfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CDFSNP_FNODE_FILESZ(cdfsnp_fnode_1st) != CDFSNP_FNODE_FILESZ(cdfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }
    if(CDFSNP_FNODE_TRUNCF(cdfsnp_fnode_1st) != CDFSNP_FNODE_TRUNCF(cdfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }

    if(CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode_1st) != CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }
/*
    if(CDFSNP_FNODE_ROFF(cdfsnp_fnode_1st) != CDFSNP_FNODE_ROFF(cdfsnp_fnode_2nd))
    {
        return (EC_FALSE);
    }
*/
    for(replica_pos = 0; replica_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode_1st); replica_pos ++)
    {
        if(EC_FALSE == cdfsnp_fnode_check_inode_exist(CDFSNP_FNODE_INODE(cdfsnp_fnode_1st, replica_pos), cdfsnp_fnode_2nd))
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_fnode_import(const CDFSNP_FNODE *cdfsnp_fnode_src, CDFSNP_FNODE *cdfsnp_fnode_des)
{
    UINT32 src_pos;
    UINT32 des_pos;

    for(src_pos = 0, des_pos = 0; src_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode_src) && src_pos < CDFSNP_FILE_REPLICA_MAX_NUM; src_pos ++)
    {
        CDFSNP_INODE *cdfsnp_inode_src;

        cdfsnp_inode_src = (CDFSNP_INODE *)CDFSNP_FNODE_INODE(cdfsnp_fnode_src, src_pos);
        if(CDFSNP_ERR_PATH != CDFSNP_INODE_PATH(cdfsnp_inode_src) && CDFSNP_ERR_FOFF != CDFSNP_INODE_FOFF(cdfsnp_inode_src))
        {
            CDFSNP_INODE *cdfsnp_inode_des;

            cdfsnp_inode_des = CDFSNP_FNODE_INODE(cdfsnp_fnode_des, des_pos);
            if(cdfsnp_inode_src != cdfsnp_inode_des)
            {
                cdfsnp_inode_clone(cdfsnp_inode_src, cdfsnp_inode_des);
            }

            des_pos ++;
        }
    }

    CDFSNP_FNODE_FILESZ(cdfsnp_fnode_des) = CDFSNP_FNODE_FILESZ(cdfsnp_fnode_src);
    CDFSNP_FNODE_TRUNCF(cdfsnp_fnode_des) = CDFSNP_FNODE_TRUNCF(cdfsnp_fnode_src);
    CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode_des) = CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode_src);
    CDFSNP_FNODE_REPNUM(cdfsnp_fnode_des) = des_pos;
    return (EC_TRUE);
}

UINT32 cdfsnp_fnode_count_replica(const CDFSNP_FNODE *cdfsnp_fnode)
{
    UINT32 pos;
    UINT32 count;

    for(pos = 0, count = 0; pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && pos < CDFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        CDFSNP_INODE *cdfsnp_inode;

        cdfsnp_inode = (CDFSNP_INODE *)CDFSNP_FNODE_INODE(cdfsnp_fnode, pos);
        if(CDFSNP_ERR_PATH != (CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK)
        && CDFSNP_ERR_FOFF != (CDFSNP_INODE_FOFF(cdfsnp_inode) & CDFSNP_32BIT_MASK))
        {
            count ++;
        }
    }
    return (count);
}

void cdfsnp_fnode_print(LOG *log, const CDFSNP_FNODE *cdfsnp_fnode)
{
    UINT32 pos;

    sys_log(log, "cdfsnp_fnode %p: file size %ld, replica num %ld, trunc flag %ld, actual fsize %ld\n",
                    cdfsnp_fnode,
                    CDFSNP_FNODE_FILESZ(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                    CDFSNP_FNODE_REPNUM(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                    CDFSNP_FNODE_TRUNCF(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                    CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode) & CDFSNP_32BIT_MASK
                    );

    for(pos = 0; pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && pos < CDFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdfsnp_inode_print(log, CDFSNP_FNODE_INODE(cdfsnp_fnode, pos));
    }
    return;
}

void cdfsnp_fnode_log_no_lock(LOG *log, const CDFSNP_FNODE *cdfsnp_fnode)
{
    UINT32 pos;

    sys_print_no_lock(log, "size %ld, replica %ld, trunc %ld, actfsz %ld",
                    CDFSNP_FNODE_FILESZ(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                    CDFSNP_FNODE_REPNUM(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                    CDFSNP_FNODE_TRUNCF(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                    CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode) & CDFSNP_32BIT_MASK);

    for(pos = 0; pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && pos < CDFSNP_FILE_REPLICA_MAX_NUM; pos ++)
    {
        cdfsnp_inode_log_no_lock(log, CDFSNP_FNODE_INODE(cdfsnp_fnode, pos));
    }
    sys_print_no_lock(log, "\n");

    return;
}

CDFSNP_DNODE *cdfsnp_dnode_new()
{
    CDFSNP_DNODE *cdfsnp_dnode;

    alloc_static_mem(MM_CDFSNP_DNODE, &cdfsnp_dnode, LOC_CDFSNP_0006);
    if(NULL_PTR != cdfsnp_dnode)
    {
        cdfsnp_dnode_init(cdfsnp_dnode);
    }
    return (cdfsnp_dnode);

}

EC_BOOL cdfsnp_dnode_init(CDFSNP_DNODE *cdfsnp_dnode)
{
    UINT32 pos;

    //CDFSNP_DNODE_ROFF(cdfsnp_dnode)     = CDFSNP_ITEM_ERR_OFFSET;
    CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode) = 0;

    for(pos = 0; pos < CDFSNP_DIR_BUCKET_MAX_NUM; pos ++)
    {
        CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, pos) = (CDFSNP_BUCKET)(CDFSNP_ITEM_ERR_OFFSET & CDFSNP_32BIT_MASK);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_dnode_clean(CDFSNP_DNODE *cdfsnp_dnode)
{
    UINT32 pos;

    //CDFSNP_DNODE_ROFF(cdfsnp_dnode)     = CDFSNP_ITEM_ERR_OFFSET;
    CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode) = 0;

    for(pos = 0; pos < CDFSNP_DIR_BUCKET_MAX_NUM; pos ++)
    {
        CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, pos) = (CDFSNP_BUCKET)(CDFSNP_ITEM_ERR_OFFSET & CDFSNP_32BIT_MASK);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_dnode_free(CDFSNP_DNODE *cdfsnp_dnode)
{
    if(NULL_PTR != cdfsnp_dnode)
    {
        cdfsnp_dnode_clean(cdfsnp_dnode);
        free_static_mem(MM_CDFSNP_DNODE, cdfsnp_dnode, LOC_CDFSNP_0007);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_dnode_clone(const CDFSNP_DNODE *cdfsnp_dnode_src, CDFSNP_DNODE *cdfsnp_dnode_des)
{
    UINT32 pos;

    CDFSNP_DNODE_ROFF(cdfsnp_dnode_des)     = CDFSNP_DNODE_ROFF(cdfsnp_dnode_src);
    CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode_des) = CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode_src);
    for(pos = 0; pos < CDFSNP_DIR_BUCKET_MAX_NUM; pos ++)
    {
        CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode_des, pos) = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode_src, pos);
    }
    return (EC_TRUE);
}

CDFSNP_ITEM *cdfsnp_item_new()
{
    CDFSNP_ITEM *cdfsnp_item;

    alloc_static_mem(MM_CDFSNP_ITEM, &cdfsnp_item, LOC_CDFSNP_0008);
    if(NULL_PTR != cdfsnp_item)
    {
        cdfsnp_item_init(cdfsnp_item);
    }
    return (cdfsnp_item);
}

EC_BOOL cdfsnp_item_init(CDFSNP_ITEM *cdfsnp_item)
{
    CDFSNP_ITEM_DFLG(cdfsnp_item)             = CDFSNP_ITEM_FILE_IS_ERR;
    CDFSNP_ITEM_STAT(cdfsnp_item)             = CDFSNP_ITEM_STAT_IS_NOT_USED;
    CDFSNP_ITEM_KLEN(cdfsnp_item)             = 0;
    CDFSNP_ITEM_PARENT(cdfsnp_item)           = CDFSNP_ITEM_ERR_OFFSET;
    CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item)       = CDFSNP_ITEM_ERR_OFFSET;

    BSET(CDFSNP_ITEM_KEY(cdfsnp_item), '\0', CDFSNP_KEY_MAX_SIZE);

    cdfsnp_dnode_init(CDFSNP_ITEM_DNODE(cdfsnp_item));

    return (EC_TRUE);
}

EC_BOOL cdfsnp_item_clean(CDFSNP_ITEM *cdfsnp_item)
{
    CDFSNP_ITEM_DFLG(cdfsnp_item)             = CDFSNP_ITEM_FILE_IS_ERR;
    CDFSNP_ITEM_STAT(cdfsnp_item)             = CDFSNP_ITEM_STAT_IS_NOT_USED;
    CDFSNP_ITEM_KLEN(cdfsnp_item)             = 0;
    CDFSNP_ITEM_PARENT(cdfsnp_item)           = CDFSNP_ITEM_ERR_OFFSET;
    CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item)       = CDFSNP_ITEM_ERR_OFFSET;

    BSET(CDFSNP_ITEM_KEY(cdfsnp_item), '\0', CDFSNP_KEY_MAX_SIZE);

    cdfsnp_dnode_clean(CDFSNP_ITEM_DNODE(cdfsnp_item));

    return (EC_TRUE);
}

EC_BOOL cdfsnp_item_clone(const CDFSNP_ITEM *cdfsnp_item_src, CDFSNP_ITEM *cdfsnp_item_des)
{
    UINT32 pos;

    if(NULL_PTR == cdfsnp_item_src)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_clone: cdfsnp_item_src is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdfsnp_item_des)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_clone: cdfsnp_item_des is null\n");
        return (EC_FALSE);
    }

    CDFSNP_ITEM_DFLG(cdfsnp_item_des)        =  CDFSNP_ITEM_DFLG(cdfsnp_item_src);
    CDFSNP_ITEM_STAT(cdfsnp_item_des)        =  CDFSNP_ITEM_STAT(cdfsnp_item_src);
    CDFSNP_ITEM_KLEN(cdfsnp_item_des)        =  CDFSNP_ITEM_KLEN(cdfsnp_item_src);
    CDFSNP_ITEM_PARENT(cdfsnp_item_des)      =  CDFSNP_ITEM_PARENT(cdfsnp_item_src);
    CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item_des)  =  CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item_src);

    for(pos = 0; pos < CDFSNP_ITEM_KLEN(cdfsnp_item_src); pos ++)
    {
        CDFSNP_ITEM_KEY(cdfsnp_item_des)[ pos ] = CDFSNP_ITEM_KEY(cdfsnp_item_src)[ pos ];
    }

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item_src))
    {
        cdfsnp_fnode_clone(CDFSNP_ITEM_FNODE(cdfsnp_item_src), CDFSNP_ITEM_FNODE(cdfsnp_item_des));
    }
    else if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item_src))
    {
        cdfsnp_dnode_clone(CDFSNP_ITEM_DNODE(cdfsnp_item_src), CDFSNP_ITEM_DNODE(cdfsnp_item_des));
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_item_free(CDFSNP_ITEM *cdfsnp_item)
{
    if(NULL_PTR != cdfsnp_item)
    {
        cdfsnp_item_clean(cdfsnp_item);
        free_static_mem(MM_CDFSNP_ITEM, cdfsnp_item, LOC_CDFSNP_0009);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_item_set_key(CDFSNP_ITEM *cdfsnp_item, const UINT32 klen, const UINT8 *key)
{
    UINT32 pos;

    for(pos = 0; pos < klen && pos < CDFSNP_KEY_MAX_SIZE; pos ++)
    {
        CDFSNP_ITEM_KEY(cdfsnp_item)[ pos ] = key[ pos ];
    }
    CDFSNP_ITEM_KLEN(cdfsnp_item) = pos;

    return (EC_TRUE);
}

void cdfsnp_item_print(LOG *log, const CDFSNP_ITEM *cdfsnp_item)
{
    UINT32 pos;

    sys_print(log, "cdfsnp_item %p: flag %ld, stat %ld, klen %ld, parent %ld, shash next %ld\n",
                    cdfsnp_item,
                    CDFSNP_ITEM_DFLG(cdfsnp_item),
                    CDFSNP_ITEM_STAT(cdfsnp_item),
                    CDFSNP_ITEM_KLEN(cdfsnp_item),
                    CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK,
                    CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item) & CDFSNP_32BIT_MASK
                    );

    sys_log(log, "key: ");
    for(pos = 0; pos < CDFSNP_ITEM_KLEN(cdfsnp_item); pos ++)
    {
        sys_print(log, "%c", (char)(CDFSNP_ITEM_KEY(cdfsnp_item)[ pos ]));
    }
    sys_print(log, "\n");

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_DNODE *cdfsnp_dnode;

        cdfsnp_dnode = (CDFSNP_DNODE *)CDFSNP_ITEM_DNODE(cdfsnp_item);
        sys_log(log, "file num: %ld\n", CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode));

#if 0
        sys_log(log, "bucket: ");
        for(pos = 0; pos < CDFSNP_DIR_BUCKET_MAX_NUM; pos ++)
        {
            sys_print(log, "%ld,", CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, pos));
        }
        sys_print(log, "\n");
#endif
    }

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_FNODE *cdfsnp_fnode;

        cdfsnp_fnode = (CDFSNP_FNODE *)CDFSNP_ITEM_FNODE(cdfsnp_item);
        sys_log(log, "file size %ld, replica num %ld, actual fsize %ld\n",
                        CDFSNP_FNODE_FILESZ(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                        CDFSNP_FNODE_REPNUM(cdfsnp_fnode) & CDFSNP_32BIT_MASK,
                        CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode) & CDFSNP_32BIT_MASK
                        );
        for(pos = 0; pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode); pos ++)
        {
            CDFSNP_INODE *cdfsnp_inode;

            cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, pos);
            cdfsnp_inode_print(log, cdfsnp_inode);
            //sys_print(log, "\n");
        }
    }

    return;
}

EC_BOOL cdfsnp_item_load(CDFSNP *cdfsnp, const UINT32 offset, CDFSNP_ITEM *cdfsnp_item)
{
    RWSIZE rsize;

    if(ERR_SEEK == lseek(CDFSNP_FD(cdfsnp), offset, SEEK_SET))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    rsize = sizeof(CDFSNP_ITEM);
    if(rsize != read(CDFSNP_FD(cdfsnp), cdfsnp_item, rsize))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_load: load item from offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_item_flush(CDFSNP *cdfsnp, const UINT32 offset, const CDFSNP_ITEM *cdfsnp_item)
{
    RWSIZE wsize;

    if(ERR_SEEK == lseek(CDFSNP_FD(cdfsnp), offset, SEEK_SET))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    wsize = sizeof(CDFSNP_ITEM);
    if(wsize != write(CDFSNP_FD(cdfsnp), cdfsnp_item, wsize))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_flush: flush item to offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_item_check(const CDFSNP_ITEM *cdfsnp_item, const UINT32 klen, const UINT8 *key)
{
    if(klen !=  CDFSNP_ITEM_KLEN(cdfsnp_item))
    {
        return (EC_FALSE);
    }

    if(0 != strncmp((char *)key, (char *)CDFSNP_ITEM_KEY(cdfsnp_item), klen))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*   return -1 when (klen, key, second hash) <  cdfsnp item
*   return  1 when (klen, key, second hash) >  cdfsnp item
*   return  0 when (klen, key, second hash) == cdfsnp item
**/
int cdfsnp_item_cmp(const CDFSNP_ITEM *cdfsnp_item, const UINT32 klen, const UINT8 *key)
{
    int cmp;

    cmp = strncmp((char *)key, (char *)CDFSNP_ITEM_KEY(cdfsnp_item), klen);
    if(0 != cmp)
    {
        return (cmp);
    }

    if(klen < CDFSNP_ITEM_KLEN(cdfsnp_item))
    {
        return ((int)-1);
    }

    if(klen > CDFSNP_ITEM_KLEN(cdfsnp_item))
    {
        return ((int) 1);
    }

    return (0);
}

void cdfsnp_bucket_print(LOG *log, const UINT32 *cdfsnp_buckets)
{
    UINT32 pos;

    for(pos = 0; pos < CDFSNP_DIR_BUCKET_MAX_NUM; pos ++)
    {
        sys_log(log, "bucket %ld#: offset %ld\n", pos, *(cdfsnp_buckets + pos));
    }
    return;
}

EC_BOOL cdfsnp_bucket_load(CDFSNP *cdfsnp, const UINT32 offset, UINT32 *cdfsnp_buckets)
{
    RWSIZE rsize;

    if(ERR_SEEK == lseek(CDFSNP_FD(cdfsnp), offset, SEEK_SET))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_bucket_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    rsize = CDFSNP_DIR_BUCKET_MAX_NUM * sizeof(UINT32);
    if(rsize != read(CDFSNP_FD(cdfsnp), cdfsnp_buckets, rsize))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_bucket_load: load bucket from offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_bucket_flush(const CDFSNP *cdfsnp, const UINT32 offset, const UINT32 *cdfsnp_buckets)
{
    RWSIZE wsize;

    if(ERR_SEEK == lseek(CDFSNP_FD(cdfsnp), offset, SEEK_SET))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_bucket_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    wsize = CDFSNP_DIR_BUCKET_MAX_NUM * sizeof(UINT32);
    if(wsize != write(CDFSNP_FD(cdfsnp), cdfsnp_buckets, wsize))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_bucket_flush: flush bucket to offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_header_init(CDFSNP_HEADER *cdfsnp_header, const UINT32 disk_max_num, const UINT32 item_max_num, const UINT32 item_cur_num, const UINT32 bloom_row_num, const UINT32 bloom_col_num, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id)
{
    CDFSNP_HEADER_IMNUM(cdfsnp_header)         = item_max_num;
    CDFSNP_HEADER_ICNUM(cdfsnp_header)         = item_cur_num;

    CDFSNP_HEADER_BMROW(cdfsnp_header)         = bloom_row_num;
    CDFSNP_HEADER_BMCOL(cdfsnp_header)         = bloom_col_num;

    CDFSNP_HEADER_FSIZE(cdfsnp_header)         = item_max_num * sizeof(CDFSNP_ITEM);
    CDFSNP_HEADER_ROFF(cdfsnp_header)          = CDFSNP_ITEM_ERR_OFFSET;

    CDFSNP_HEADER_DISK_MAX_NUM(cdfsnp_header)          = disk_max_num;
    CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header)   = first_chash_algo_id;
    CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header)  = second_chash_algo_id;

    if(item_max_num <= item_cur_num)
    {
        CDFSNP_HEADER_STATE(cdfsnp_header) = CDFSNP_STATE_RDONLY;
    }
    else
    {
        CDFSNP_HEADER_STATE(cdfsnp_header) = CDFSNP_STATE_RDWR;
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_header_clone(const CDFSNP_HEADER *cdfsnp_header_src, CDFSNP_HEADER *cdfsnp_header_des)
{
    CDFSNP_HEADER_IMNUM(cdfsnp_header_des)        = CDFSNP_HEADER_IMNUM(cdfsnp_header_src);
    CDFSNP_HEADER_ICNUM(cdfsnp_header_des)        = CDFSNP_HEADER_ICNUM(cdfsnp_header_src);

    CDFSNP_HEADER_BMROW(cdfsnp_header_des)        = CDFSNP_HEADER_BMROW(cdfsnp_header_src);
    CDFSNP_HEADER_BMCOL(cdfsnp_header_des)        = CDFSNP_HEADER_BMCOL(cdfsnp_header_src);

    CDFSNP_HEADER_FSIZE(cdfsnp_header_des)        = CDFSNP_HEADER_FSIZE(cdfsnp_header_src);
    CDFSNP_HEADER_ROFF(cdfsnp_header_des)         = CDFSNP_HEADER_FSIZE(cdfsnp_header_src);

    CDFSNP_HEADER_DISK_MAX_NUM(cdfsnp_header_des)          = CDFSNP_HEADER_DISK_MAX_NUM(cdfsnp_header_src);
    CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header_des)   = CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header_src) ;
    CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header_des)  = CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header_src);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_header_clean(CDFSNP_HEADER *cdfsnp_header)
{
    CDFSNP_HEADER_IMNUM(cdfsnp_header)   = 0;
    CDFSNP_HEADER_ICNUM(cdfsnp_header)   = 0;

    CDFSNP_HEADER_BMROW(cdfsnp_header)   = 0;
    CDFSNP_HEADER_BMCOL(cdfsnp_header)   = 0;

    CDFSNP_HEADER_FSIZE(cdfsnp_header)   = 0;
    CDFSNP_HEADER_ROFF(cdfsnp_header)    = CDFSNP_ITEM_ERR_OFFSET;

    CDFSNP_HEADER_DISK_MAX_NUM(cdfsnp_header)          = 0;
    CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header)   = CHASH_ERR_ALGO_ID;
    CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header)  = CHASH_ERR_ALGO_ID;

    CDFSNP_HEADER_STATE(cdfsnp_header) = CDFSNP_STATE_ERR;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_header_is_valid(const CDFSNP_HEADER *cdfsnp_header, const UINT32 item_min_num)
{
    if(item_min_num > CDFSNP_HEADER_ICNUM(cdfsnp_header))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_header_is_valid: invalid item cur num %ld < %ld\n",
                            (UINT32)CDFSNP_HEADER_ICNUM(cdfsnp_header), item_min_num);
        return (EC_FALSE);
    }

    if(
        CDFSNP_HEADER_ICNUM(cdfsnp_header) > CDFSNP_HEADER_IMNUM(cdfsnp_header)
    )
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_header_is_valid: invalid item cur num %ld to max num %ld\n",
                            (UINT32)CDFSNP_HEADER_ICNUM(cdfsnp_header),
                            (UINT32)CDFSNP_HEADER_IMNUM(cdfsnp_header));
        return (EC_FALSE);
    }

    if(
         CDFSNP_HEADER_IMNUM(cdfsnp_header) * sizeof(CDFSNP_ITEM)
        != CDFSNP_HEADER_FSIZE(cdfsnp_header)
    )
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_header_is_valid: invalid file size %ld to item max num %ld\n",
                            (UINT32)CDFSNP_HEADER_FSIZE(cdfsnp_header),
                            (UINT32)CDFSNP_HEADER_IMNUM(cdfsnp_header));
        return (EC_FALSE);
    }

    if(0 < (CDFSNP_HEADER_FSIZE(cdfsnp_header) >> (WORDSIZE - 1)))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_header_is_valid: file size %ld overflow\n",
                            CDFSNP_HEADER_FSIZE(cdfsnp_header));
        return (EC_FALSE);
    }

    if(0 == CDFSNP_HEADER_DISK_MAX_NUM(cdfsnp_header))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_header_is_valid: disk max num is zero\n");
        return (EC_FALSE);
    }

    if(CHASH_ERR_ALGO_ID == CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_header_is_valid: invalid first hash algo id %ld\n",
                            (UINT32)CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header));
        return (EC_FALSE);
    }

    if(CHASH_ERR_ALGO_ID == CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_header_is_valid: invalid second hash algo id %ld\n",
                            (UINT32)CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_header_create(CDFSNP_HEADER *cdfsnp_header, const UINT32 cdfsnp_mode, const UINT32 disk_max_num, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id)
{
    UINT32 cdfsnp_item_max_num;
    UINT32 cdfsnp_item_cur_num;
    UINT32 cdfsnp_bloom_row_num;
    UINT32 cdfsnp_bloom_col_num;

    if(
        EC_FALSE == cdfsnp_mode_item_max_num(cdfsnp_mode , &cdfsnp_item_max_num)
     || EC_FALSE == cdfsnp_mode_bloom_row_num(cdfsnp_mode, &cdfsnp_bloom_row_num)
     || EC_FALSE == cdfsnp_mode_bloom_col_num(cdfsnp_mode, &cdfsnp_bloom_col_num)
    )
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_init_header: invalid cdfsnp mode %ld\n", cdfsnp_mode);
        return (EC_FALSE);
    }

    cdfsnp_item_cur_num = 0;
    return cdfsnp_header_init(cdfsnp_header,
                               disk_max_num,
                               cdfsnp_item_max_num,
                               cdfsnp_item_cur_num,
                               cdfsnp_bloom_row_num,
                               cdfsnp_bloom_col_num,
                               first_chash_algo_id,
                               second_chash_algo_id);
}


EC_BOOL cdfsnp_cbloom_is_set(const CDFSNP *cdfsnp, const UINT32 first_hash, const UINT32 second_hash)
{
    UINT32 row_idx;
    UINT32 col_idx;
    UINT32 bit_pos;

    row_idx = CDFSNP_BLOOM_ROW_IDX(cdfsnp, first_hash);
    col_idx = CDFSNP_BLOOM_COL_IDX(cdfsnp, second_hash);

    bit_pos = (row_idx * CDFSNP_BMROW(cdfsnp) + CDFSNP_BMCOL(cdfsnp));
    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_cbloom_is_set: (first hash %ld, second hash %ld) => (row idx %ld, col idx %ld) => (bit pos %ld) => %ld\n",
                        first_hash, second_hash, row_idx, col_idx, bit_pos, bit_pos % CBLOOM_MAX_NBIT(CDFSNP_CBLOOM(cdfsnp)));
    return cbloom_check_bit(CDFSNP_CBLOOM(cdfsnp), bit_pos);
}

EC_BOOL cdfsnp_cbloom_set(CDFSNP *cdfsnp, const UINT32 first_hash, const UINT32 second_hash)
{
    UINT32 row_idx;
    UINT32 col_idx;
    UINT32 bit_pos;

    row_idx = CDFSNP_BLOOM_ROW_IDX(cdfsnp, first_hash);
    col_idx = CDFSNP_BLOOM_COL_IDX(cdfsnp, second_hash);

    bit_pos = (row_idx * CDFSNP_BMROW(cdfsnp) + CDFSNP_BMCOL(cdfsnp));
    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_cbloom_set: (first hash %ld, second hash %ld) => (row idx %ld, col idx %ld) => (bit pos %ld) => %ld\n",
                        first_hash, second_hash, row_idx, col_idx, bit_pos, bit_pos % CBLOOM_MAX_NBIT(CDFSNP_CBLOOM(cdfsnp)));

    return cbloom_set_bit(CDFSNP_CBLOOM(cdfsnp), bit_pos);
}


CDFSNP *cdfsnp_new(const UINT32 cdfsnp_path_layout, const CDFSNP_HEADER *cdfsnp_header, const CBLOOM *cdfsnp_cbloom)
{
    CDFSNP *cdfsnp;

    alloc_static_mem(MM_CDFSNP, &cdfsnp, LOC_CDFSNP_0010);
    if(NULL_PTR != cdfsnp)
    {
        cdfsnp_init(cdfsnp, cdfsnp_path_layout, cdfsnp_header, cdfsnp_cbloom);
    }
    return (cdfsnp);
}

EC_BOOL cdfsnp_init(CDFSNP *cdfsnp, const UINT32 cdfsnp_path_layout, const CDFSNP_HEADER *cdfsnp_header, const CBLOOM *cdfsnp_cbloom)
{
    CDFSNP_PATH_LAYOUT(cdfsnp) = cdfsnp_path_layout;

    CDFSNP_READER_NUM(cdfsnp) = 0;

    CDFSNP_FD(cdfsnp) = ERR_FD;

    CDFSNP_HDR(cdfsnp)    = (CDFSNP_HEADER *)cdfsnp_header;
    CDFSNP_CBLOOM(cdfsnp) = (CBLOOM *)cdfsnp_cbloom;

    CDFSNP_ITEM_VEC(cdfsnp) = NULL_PTR;

    CDFSNP_INIT_LOCK(cdfsnp, LOC_CDFSNP_0011);

    CDFSNP_FIRST_CHASH_ALGO(cdfsnp)  = chash_algo_fetch(CDFSNP_FIRST_CHASH_ALGO_ID(cdfsnp));
    CDFSNP_SECOND_CHASH_ALGO(cdfsnp) = chash_algo_fetch(CDFSNP_SECOND_CHASH_ALGO_ID(cdfsnp));

    CDFSNP_BASE_BUFF(cdfsnp) = NULL_PTR;
    CDFSNP_BASE_BUFF_LEN(cdfsnp) = 0;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_clean(CDFSNP *cdfsnp)
{
    if(ERR_FD != CDFSNP_FD(cdfsnp))
    {
        c_file_close(CDFSNP_FD(cdfsnp));
        CDFSNP_FD(cdfsnp) = ERR_FD;
    }

    CDFSNP_HDR(cdfsnp) = NULL_PTR;
    CDFSNP_CBLOOM(cdfsnp) = NULL_PTR;

    CDFSNP_ITEM_VEC(cdfsnp) = NULL_PTR;

    CDFSNP_CLEAN_LOCK(cdfsnp, LOC_CDFSNP_0012);

    CDFSNP_FIRST_CHASH_ALGO(cdfsnp) = NULL_PTR;
    CDFSNP_SECOND_CHASH_ALGO(cdfsnp) = NULL_PTR;

    if(NULL_PTR != CDFSNP_BASE_BUFF(cdfsnp))
    {
        SAFE_FREE(CDFSNP_BASE_BUFF(cdfsnp), LOC_CDFSNP_0013);
        CDFSNP_BASE_BUFF(cdfsnp) = NULL_PTR;
    }

    CDFSNP_BASE_BUFF_LEN(cdfsnp) = 0;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_swapout(CDFSNP *cdfsnp)
{
    if(ERR_FD != CDFSNP_FD(cdfsnp))
    {
        c_file_close(CDFSNP_FD(cdfsnp));
        CDFSNP_FD(cdfsnp) = ERR_FD;
    }

    //CDFSNP_HDR(cdfsnp) = NULL_PTR;
    //CDFSNP_CBLOOM(cdfsnp) = NULL_PTR;

    CDFSNP_ITEM_VEC(cdfsnp) = NULL_PTR;

    //CDFSNP_CLEAN_LOCK(cdfsnp, LOC_CDFSNP_0014);

    //CDFSNP_FIRST_CHASH_ALGO(cdfsnp) = NULL_PTR;
    //CDFSNP_SECOND_CHASH_ALGO(cdfsnp) = NULL_PTR;

    if(NULL_PTR != CDFSNP_BASE_BUFF(cdfsnp))
    {
        SAFE_FREE(CDFSNP_BASE_BUFF(cdfsnp), LOC_CDFSNP_0015);
        CDFSNP_BASE_BUFF(cdfsnp) = NULL_PTR;
    }

    CDFSNP_BASE_BUFF_LEN(cdfsnp) = 0;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_free(CDFSNP *cdfsnp)
{
    if(NULL_PTR != cdfsnp)
    {
        cdfsnp_clean(cdfsnp);
        free_static_mem(MM_CDFSNP, cdfsnp, LOC_CDFSNP_0016);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_is_full(const CDFSNP *cdfsnp)
{
    if(CDFSNP_ICNUM(cdfsnp) >= CDFSNP_IMNUM(cdfsnp))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void cdfsnp_print_header(LOG *log, const CDFSNP *cdfsnp)
{
    CDFSNP_HEADER *cdfsnp_header;

    cdfsnp_header = (CDFSNP_HEADER *)CDFSNP_HDR(cdfsnp);

    sys_log(log, "item max num %ld, item cur num %ld, bloom rnum %ld, bloom cnum %ld, roff %ld, fsize %ld, 1st hash algo %ld, 2nd hash algo %ld, state %lx\n",
                CDFSNP_HEADER_IMNUM(cdfsnp_header) ,
                CDFSNP_HEADER_ICNUM(cdfsnp_header) ,

                CDFSNP_HEADER_BMROW(cdfsnp_header),
                CDFSNP_HEADER_BMCOL(cdfsnp_header),

                CDFSNP_HEADER_ROFF(cdfsnp_header),

                CDFSNP_HEADER_FSIZE(cdfsnp_header),

                CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header),
                CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header),

                CDFSNP_HEADER_STATE(cdfsnp_header)
        );
    return;
}

void cdfsnp_print_cbloom(LOG *log, const CDFSNP *cdfsnp)
{
    cbloom_print(log, CDFSNP_CBLOOM(cdfsnp));
}

void cdfsnp_print(LOG *log, const CDFSNP *cdfsnp)
{
    sys_log(log, "cdfsnp %p: path layout: %ld\n", cdfsnp, CDFSNP_PATH_LAYOUT(cdfsnp));

    sys_log(log, "cdfsnp %p: header: \n", cdfsnp);
    cdfsnp_print_header(log, cdfsnp);
#if 0
    sys_log(log, "cdfsnp %p: bloom filter: \n", cdfsnp);
    cbloom_print(log, CDFSNP_CBLOOM(cdfsnp) );
    sys_print(log, "\n");
 #endif
    return;
}

EC_BOOL cdfsnp_buff_flush(const CDFSNP *cdfsnp, const UINT32 offset, const RWSIZE wsize, const UINT8 *buff)
{
    RWSIZE csize;/*write completed size*/
    RWSIZE osize;/*write once size*/

    if(ERR_SEEK == lseek(CDFSNP_FD(cdfsnp), offset, SEEK_SET))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_buff_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    for(csize = 0, osize = CDFSNP_WRITE_ONCE_MAX_BYTES; csize < wsize; csize += osize)
    {
        if(csize + osize > wsize)
        {
            osize = wsize - csize;
        }

        if(osize != write(CDFSNP_FD(cdfsnp), buff + csize, osize))
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_buff_flush: flush buff to offset %ld failed where wsize %ld, csize %ld, osize %ld, errno %d, errstr %s\n",
                                offset, wsize, csize, osize, errno, strerror(errno));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_buff_load(const CDFSNP *cdfsnp, const UINT32 offset, const RWSIZE rsize, UINT8 *buff)
{
    RWSIZE csize;/*read completed size*/
    RWSIZE osize;/*read once size*/

    if(ERR_SEEK == lseek(CDFSNP_FD(cdfsnp), offset, SEEK_SET))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_buff_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    for(csize = 0, osize = CDFSNP_READ_ONCE_MAX_BYTES; csize < rsize; csize += osize)
    {
        if(csize + osize > rsize)
        {
            osize = rsize - csize;
        }

        if(osize != read(CDFSNP_FD(cdfsnp), buff + csize, osize))
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_buff_load: load buff from offset %ld failed where rsize %ld, csize %ld, osize %ld, errno %d, errstr %s\n",
                                offset, rsize, csize, osize, errno, strerror(errno));
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0058_CDFSNP, 5)(LOGSTDOUT, "cdfsnp_buff_load: load %ld bytes\n", rsize);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_link(CDFSNP *cdfsnp, const UINT32 base_buff_len, const UINT8 *base_buff)
{
    CDFSNP_ITEM_VEC(cdfsnp) = (CDFSNP_ITEM *)(base_buff);

    CDFSNP_BASE_BUFF_LEN(cdfsnp) = base_buff_len;
    CDFSNP_BASE_BUFF(cdfsnp) = (UINT8 *)base_buff;

    return (EC_TRUE);
}

CDFSNP_ITEM *cdfsnp_dnode_find(const CDFSNP *cdfsnp, const CDFSNP_DNODE *cdfsnp_dnode, const UINT32 second_hash, const UINT32 klen, const UINT8 *key)
{
    UINT32 offset;

    offset = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, CDFSNP_BUCKET_POS(second_hash));

    while(CDFSNP_ITEM_ERR_OFFSET != offset)
    {
        CDFSNP_ITEM *cdfsnp_item;

        CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, "cdfsnp_dnode_find");

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
        if(EC_TRUE == cdfsnp_item_check(cdfsnp_item, klen, key))
        {
            return (cdfsnp_item);
        }

        offset = (CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item) & CDFSNP_32BIT_MASK);
    }

    return (NULL_PTR);
}

UINT32 cdfsnp_dnode_search(const CDFSNP *cdfsnp, const CDFSNP_DNODE *cdfsnp_dnode, const UINT32 second_hash, const UINT32 klen, const UINT8 * key)
{
    UINT32 offset;

    offset = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, CDFSNP_BUCKET_POS(second_hash));

    while(CDFSNP_ITEM_ERR_OFFSET != offset)
    {
        CDFSNP_ITEM *cdfsnp_item;

        CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, "cdfsnp_dnode_search");

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
        if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item))
        {
            return (CDFSNP_ITEM_ERR_OFFSET);
        }

        if(EC_TRUE == cdfsnp_item_check(cdfsnp_item, klen, key))
        {
            return (offset);
        }

        offset = (CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item) & CDFSNP_32BIT_MASK);
        dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_dnode_search: shash next %lx => offset %lx\n",
                        (UINT32)CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item), offset);
    }

    return (CDFSNP_ITEM_ERR_OFFSET);
}

UINT32 cdfsnp_dnode_insert(CDFSNP *cdfsnp, const UINT32 parent_offset, const UINT32 path_seg_len, const UINT8 *path_seg, const UINT32 path_seg_second_hash, const UINT32 dir_flag, const UINT32 path_len, const UINT8 *path)
{
    UINT32 insert_offset;
    UINT32 bucket_pos;

    CDFSNP_ITEM *cdfsnp_item_parent;
    CDFSNP_ITEM *cdfsnp_item_insert;

    CDFSNP_DNODE *cdfsnp_dnode_parent;

    UINT32 first_hash;
    UINT32 second_hash;

    if(CDFSNP_ITEM_FILE_IS_REG != dir_flag && CDFSNP_ITEM_FILE_IS_DIR != dir_flag)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_insert: invalid input dir flag %ld\n", dir_flag);
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    if(EC_TRUE == cdfsnp_is_full(cdfsnp))
    {
        CDFSNP_SET_RDONLY(cdfsnp);
        CDFSNP_SET_NOT_RDWR(cdfsnp);

        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_insert: cdfsnp is full\n");
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    cdfsnp_item_parent = cdfsnp_fetch(cdfsnp, parent_offset);/*must be dnode*/
    if(NULL_PTR == cdfsnp_item_parent)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_insert: fetch parent item failed where parent offset %ld\n", parent_offset);
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    cdfsnp_dnode_parent = CDFSNP_ITEM_DNODE(cdfsnp_item_parent);
    if(CDFSNP_ITEM_FILE_IS_DIR != CDFSNP_ITEM_DFLG(cdfsnp_item_parent) || CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item_parent))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_insert: invalid dir flag %ld or stat %ld\n",
                        (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item_parent),
                        (UINT32)CDFSNP_ITEM_STAT(cdfsnp_item_parent));
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    if(CDFSNP_DNODE_IS_FULL(cdfsnp_dnode_parent))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_insert: parent item at offset %ld is full\n", parent_offset);
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    /*reserve one item to insert*/
    cdfsnp_item_insert = cdfsnp_reserve_item_no_lock(cdfsnp);
    if(NULL_PTR == cdfsnp_item_insert)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_insert: reserve item from np failed\n");
        return (CDFSNP_ITEM_ERR_OFFSET);
    }
    insert_offset = CDFSNP_GET_ITEM_OFFSET(cdfsnp, cdfsnp_item_insert);

    bucket_pos = CDFSNP_BUCKET_POS(path_seg_second_hash);

    /*fill in cdfsnp_item_insert*/
    cdfsnp_item_set_key(cdfsnp_item_insert, path_seg_len, path_seg);
    CDFSNP_ITEM_PARENT(cdfsnp_item_insert) = (parent_offset & CDFSNP_32BIT_MASK);

    if(CDFSNP_ITEM_FILE_IS_REG == dir_flag)
    {
        cdfsnp_fnode_init(CDFSNP_ITEM_FNODE(cdfsnp_item_insert));
        CDFSNP_ITEM_DFLG(cdfsnp_item_insert) = CDFSNP_ITEM_FILE_IS_REG;
    }
    else
    {
        cdfsnp_dnode_init(CDFSNP_ITEM_DNODE(cdfsnp_item_insert));
        CDFSNP_ITEM_DFLG(cdfsnp_item_insert) = CDFSNP_ITEM_FILE_IS_DIR;
    }

    CDFSNP_ITEM_STAT(cdfsnp_item_insert) = CDFSNP_ITEM_STAT_IS_CACHED;

    //CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0017);
    /*before link the item to parent, check parent is full or not again*/
    if(CDFSNP_DNODE_IS_FULL(cdfsnp_dnode_parent))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_insert: parent item at offset %ld is full\n", parent_offset);
        cdfsnp_release_item_no_lock(cdfsnp, cdfsnp_item_insert);
        //CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0018);
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    /*link the item to parent and update parent*/
    CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item_insert) = (CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode_parent, bucket_pos) & CDFSNP_32BIT_MASK);
    CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode_parent, bucket_pos) = (CDFSNP_BUCKET)(insert_offset & CDFSNP_32BIT_MASK);
    CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode_parent) ++;

    /*when reach here, item was inserted into parent*/
    //CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0019);

    first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, path_seg - path + path_seg_len, path);
    second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_seg - path + path_seg_len, path);

    /*update cdfsnp*/
    cdfsnp_cbloom_set(cdfsnp, first_hash, second_hash);

    CDFSNP_SET_UPDATED(cdfsnp);

    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_dnode_insert: set bloom where path is ");
    sys_print(LOGSTDNULL, "%.*s ", (uint32_t)path_len, path);
    sys_print(LOGSTDNULL, " and path to seg is %.*s\n", (uint32_t)(path_seg - path + path_seg_len), path);

    if(EC_TRUE == cdfsnp_is_full(cdfsnp))
    {
        CDFSNP_SET_RDONLY(cdfsnp);
        CDFSNP_SET_NOT_RDWR(cdfsnp);
    }

    return (insert_offset);
}

/**
* umount one son from cdfsnp_dnode,  where son is regular file item or dir item without any son
* cdfsnp_dnode will be impacted on bucket and file num
**/
CDFSNP_ITEM * cdfsnp_dnode_umount_son(const CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, const UINT32 second_hash, const UINT32 klen, const UINT8 * key)
{
    CDFSNP_ITEM *pre_cdfsnp_item;
    UINT32 cur_offset;

    pre_cdfsnp_item = NULL_PTR;
    cur_offset = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, CDFSNP_BUCKET_POS(second_hash));

    while(CDFSNP_ITEM_ERR_OFFSET != cur_offset)
    {
        CDFSNP_ITEM *cur_cdfsnp_item;

        CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, cur_offset, "cdfsnp_dnode_umount_son");

        cur_cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + cur_offset);
        if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cur_cdfsnp_item))
        {
            return (NULL_PTR);
        }

        if(EC_TRUE == cdfsnp_item_check(cur_cdfsnp_item, klen, key))/*found it*/
        {
            UINT32 shash_next;
            shash_next = (CDFSNP_ITEM_SHASH_NEXT(cur_cdfsnp_item) & CDFSNP_32BIT_MASK);

            if(NULL_PTR == pre_cdfsnp_item)/*okay, the deleted item is the first item of this bucket*/
            {
                CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, CDFSNP_BUCKET_POS(second_hash)) = shash_next;
            }
            else
            {
                CDFSNP_ITEM_SHASH_NEXT(pre_cdfsnp_item) = shash_next; /*link prev and next*/
            }

            CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode) --;
            //cdfsnp_item_clean(cur_cdfsnp_item);

            /*return cur_cdfsnp_item to np*/
            CDFSNP_ITEM_ROFF(cur_cdfsnp_item) = CDFSNP_ROFF(cdfsnp);
            CDFSNP_ROFF(cdfsnp) = cur_offset;
            CDFSNP_ICNUM(cdfsnp) --;

            return (cur_cdfsnp_item);
        }

        pre_cdfsnp_item = cur_cdfsnp_item;
        cur_offset = (CDFSNP_ITEM_SHASH_NEXT(cur_cdfsnp_item) & CDFSNP_32BIT_MASK);
        dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_dnode_umount_son: shash next %lx => cur_offset %lx\n",
                        (UINT32)CDFSNP_ITEM_SHASH_NEXT(cur_cdfsnp_item), cur_offset);
    }

    return (NULL_PTR);
}

EC_BOOL cdfsnp_dnode_delete_one_bucket(const CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, const UINT32 bucket_pos, CVECTOR *cdfsnp_fnode_vec)
{
    while(CDFSNP_ITEM_ERR_OFFSET != CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, bucket_pos))
    {
        UINT32 offset;
        CDFSNP_ITEM *cdfsnp_item;

        offset = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, bucket_pos);
        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);

        if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            UINT32 second_hash;

            second_hash = CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item);

            if(NULL_PTR != cdfsnp_fnode_vec)
            {
                cvector_push_no_lock(cdfsnp_fnode_vec, cdfsnp_fnode_make(CDFSNP_ITEM_FNODE(cdfsnp_item)));
            }

            cdfsnp_item_clean(cdfsnp_item);
            CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, bucket_pos) = second_hash;
            CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode) --;

            /*return cur_cdfsnp_item to np*/
            CDFSNP_ITEM_ROFF(cdfsnp_item) = CDFSNP_ROFF(cdfsnp);
            CDFSNP_ROFF(cdfsnp) = offset;
            CDFSNP_ICNUM(cdfsnp) --;
        }

        else if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            UINT32 second_hash;

            second_hash = CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item);

            cdfsnp_dnode_delete_dir_son(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item), cdfsnp_fnode_vec);/*recursively*/
            cdfsnp_item_clean(cdfsnp_item);
            CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, bucket_pos) = second_hash;
            CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode) --;

            /*return cur_cdfsnp_item to np*/
            CDFSNP_ITEM_ROFF(cdfsnp_item) = CDFSNP_ROFF(cdfsnp);
            CDFSNP_ROFF(cdfsnp) = offset;
            CDFSNP_ICNUM(cdfsnp) --;
        }

        else
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_delete_one_bucket: invald cdfsnp item flag %ld at offset %d\n",
                                (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item),
                                (uint32_t)CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, bucket_pos));
        }
    }
    return (EC_TRUE);
}

/*delete one dir son, not including cdfsnp_dnode itself*/
EC_BOOL cdfsnp_dnode_delete_dir_son(const CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, CVECTOR *cdfsnp_fnode_vec)
{
    UINT32 bucket_pos;

    for(bucket_pos = 0; bucket_pos < CDFSNP_DIR_BUCKET_MAX_NUM; bucket_pos ++)
    {
        cdfsnp_dnode_delete_one_bucket(cdfsnp, cdfsnp_dnode, bucket_pos, cdfsnp_fnode_vec);
    }
    return (EC_TRUE);
}

CDFSNP_ITEM *cdfsnp_item_parent(const CDFSNP *cdfsnp, const CDFSNP_ITEM *cdfsnp_item)
{
    UINT32 offset;

    offset = (CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK);
    if(CDFSNP_ITEM_ERR_OFFSET == offset)
    {
        return (NULL_PTR);
    }

    CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, "cdfsnp_item_parent");

    return cdfsnp_fetch(cdfsnp, offset);
}

UINT32 cdfsnp_search_with_hash_no_lock(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag, const UINT32 first_hash, const UINT32 second_hash)
{
    UINT32 offset;
    UINT32 path_seg_len;
    UINT8 *path_seg_beg;
    UINT8 *path_seg_end;

    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] ========================= cdfsnp_search_with_hash_no_lock start =====================\n");

    if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_search_with_hash_no_lock: bloom was not set in np %ld where path: ", CDFSNP_PATH_LAYOUT(cdfsnp));
        sys_print(LOGSTDOUT, "%.*s\n", (uint32_t)path_len, path);
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    if(CDFSNP_IS_NOT_CACHED(cdfsnp) || NULL_PTR == CDFSNP_BASE_BUFF(cdfsnp))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_search_with_hash_no_lock: np %ld invalid state %lx or base buff %p\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp), CDFSNP_BASE_BUFF(cdfsnp));
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    path_seg_beg = (UINT8 *)path;
    path_seg_len = 0;
    path_seg_end = (UINT8 *)(path_seg_beg + path_seg_len + 1);/*path always start with '/'*/

    offset = 0;/*the first item is root directory*/
    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_search_with_hash_no_lock: np %ld, item offset %ld\n", CDFSNP_PATH_LAYOUT(cdfsnp), offset);
    while(CDFSNP_ITEM_ERR_OFFSET != offset)
    {
        CDFSNP_ITEM *cdfsnp_item;

        dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_search_with_hash_no_lock: np %ld, offset %ld, item pos %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), offset, (offset / sizeof(CDFSNP_ITEM)));

        CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, "cdfsnp_search_with_hash_no_lock");

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
        if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item))
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_search_with_hash_no_lock: np %ld, item at offset %ld was not used\n",
                                CDFSNP_PATH_LAYOUT(cdfsnp), offset);
            return (CDFSNP_ITEM_ERR_OFFSET);
        }

        if(EC_FALSE == cdfsnp_item_check(cdfsnp_item, path_seg_len, path_seg_beg))
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_search_with_hash_no_lock: np %ld, check failed where path seg: ", CDFSNP_PATH_LAYOUT(cdfsnp));
            sys_print(LOGSTDOUT, "%.*s\n", (uint32_t)path_seg_len, path_seg_beg);
            return (CDFSNP_ITEM_ERR_OFFSET);
        }

        /*when matched and reached the last path seg*/
#if 1
        if(path_len <= (UINT32)(path_seg_end - path))
        {
            dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] [target dflag %ld] cdfsnp_search_with_hash_no_lock: np %ld, matched and reached end where path_len %ld, len from path to path_seg_end is %ld, offset %ld\n",
                                dflag, CDFSNP_PATH_LAYOUT(cdfsnp), path_len, path_seg_end - path, offset);

            if(CDFSNP_ITEM_FILE_IS_ANY == dflag || dflag == CDFSNP_ITEM_DFLG(cdfsnp_item))
            {
                return (offset);
            }

            return (CDFSNP_ITEM_ERR_OFFSET);
        }
#endif

        if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))/*no more to search*/
        {
            return (CDFSNP_ITEM_ERR_OFFSET);
        }

        if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))/*search sons*/
        {
            UINT32 path_seg_second_hash;

            path_seg_beg = (UINT8 *)path_seg_end;
            path_seg_len = cdfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            path_seg_second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_seg_len, path_seg_beg);
            offset = cdfsnp_dnode_search(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item), path_seg_second_hash, path_seg_len, path_seg_beg);
            if(CDFSNP_ITEM_ERR_OFFSET == offset)/*Oops!*/
            {
                return (CDFSNP_ITEM_ERR_OFFSET);
            }
        }
        else
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_search_with_hash_no_lock_item: np %ld, invalid item dir flag %ld at offset %ld\n",
                                CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), offset);
            break;
        }
    }

    return (CDFSNP_ITEM_ERR_OFFSET);
}

EC_BOOL cdfsnp_check_cbloom(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path)
{
    UINT32 first_hash;
    UINT32 second_hash;

    first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path);
    second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path);

    return cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash);
}

UINT32 cdfsnp_search_no_lock(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag)
{
    UINT32 first_hash;
    UINT32 second_hash;
    UINT32 offset;

    first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path);
    second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path);

    offset = cdfsnp_search_with_hash_no_lock(cdfsnp, path_len, path, dflag, first_hash, second_hash);
    return (offset);
}

UINT32 cdfsnp_search(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag)
{
    UINT32 offset;

    CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0020);
    offset = cdfsnp_search_no_lock(cdfsnp, path_len, path, dflag);
    CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0021);

    return (offset);
}

UINT32 cdfsnp_insert_no_lock(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag)
{
    UINT32 offset;
    UINT32 path_seg_len;
    UINT8 *path_seg_beg;
    UINT8 *path_seg_end;

    if('/' != (*path))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_insert: np %ld, invalid path ", CDFSNP_PATH_LAYOUT(cdfsnp));
        sys_print(LOGSTDOUT, "%.*s\n", (uint32_t)path_len, path);
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    if(CDFSNP_IS_NOT_CACHED(cdfsnp) || NULL_PTR == CDFSNP_BASE_BUFF(cdfsnp))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_insert: np %ld invalid state %lx or base buff %p\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp), CDFSNP_BASE_BUFF(cdfsnp));
        return (CDFSNP_ITEM_ERR_OFFSET);
    }

    path_seg_end = (UINT8 *)(path + 1);/*path always start with '/'*/

    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_insert: np header is\n");
    cdfsnp_print_header(LOGSTDNULL, cdfsnp);

    offset = 0;/*the first item is root directory*/
    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_insert: np %ld, item offset %ld\n", CDFSNP_PATH_LAYOUT(cdfsnp), offset);
    while(CDFSNP_ITEM_ERR_OFFSET != offset && offset + sizeof(CDFSNP_ITEM) <= CDFSNP_FSIZE(cdfsnp))
    {
        CDFSNP_ITEM *cdfsnp_item;

        dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_insert: np %ld, offset %ld, item pos %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), offset, (offset / sizeof(CDFSNP_ITEM)));

        CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, "cdfsnp_insert");

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
        dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_insert: np %ld, item %ld# dir flag %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), (offset / sizeof(CDFSNP_ITEM)), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item));
        if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_insert: np %ld, find regular file at offset %ld has same key: ",
                                CDFSNP_PATH_LAYOUT(cdfsnp), offset);
            sys_print(LOGSTDOUT, "%.*s\n", (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));

            return (CDFSNP_ITEM_ERR_OFFSET);
        }

        if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            UINT32 path_seg_second_hash;

            path_seg_beg = (UINT8 *)path_seg_end;
            path_seg_len = cdfsnp_path_seg_len(path, path_len, path_seg_beg);
            path_seg_end = path_seg_beg + path_seg_len + 1;

            path_seg_second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_seg_len, path_seg_beg);
            offset = cdfsnp_dnode_search(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item), path_seg_second_hash, path_seg_len, path_seg_beg);
            dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_insert: np %ld, searched offset %ld => item %ld#(mod %ld), path_seg_len %ld, path_seg_beg: %s\n",
                                CDFSNP_PATH_LAYOUT(cdfsnp),
                                offset,
                                (offset / sizeof(CDFSNP_ITEM)),
                                (offset % sizeof(CDFSNP_ITEM)),
                                path_seg_len, path_seg_beg
                                );
            if(CDFSNP_ITEM_ERR_OFFSET != offset)
            {
                continue;
            }

            if(path_len > (UINT32)(path_seg_end - path))/*create dnode item under parent cdfsnp_item*/
            {
                offset = cdfsnp_dnode_insert(cdfsnp,
                                            (((UINT8 *)cdfsnp_item) - CDFSNP_BASE_BUFF(cdfsnp)),
                                            path_seg_len,
                                            path_seg_beg,
                                            path_seg_second_hash,
                                            CDFSNP_ITEM_FILE_IS_DIR,
                                            path_len,
                                            path
                                            );
                continue;
            }
            else/*create fnode item under parent cdfsnp_item*/
            {
                offset = cdfsnp_dnode_insert(cdfsnp,
                                           (((UINT8 *)cdfsnp_item) - CDFSNP_BASE_BUFF(cdfsnp)),
                                            path_seg_len,
                                            path_seg_beg,
                                            path_seg_second_hash,
                                            /*CDFSNP_ITEM_FILE_IS_REG*/dflag,
                                            path_len,
                                            path
                                            );
                return (offset);
            }
        }
        else
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_insert: np %ld, invalid item dir flag %ld at offset %ld\n",
                                CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), offset);
            break;
        }
    }

    //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNP_0022);
    return (CDFSNP_ITEM_ERR_OFFSET);
}

UINT32 cdfsnp_insert(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag)
{
    UINT32 offset;

    CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0023);
    offset = cdfsnp_insert_no_lock(cdfsnp, path_len, path, dflag);
    CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0024);

    return (offset);
}

CDFSNP_ITEM *cdfsnp_fetch(const CDFSNP *cdfsnp, const UINT32 offset)
{
    if(CDFSNP_ITEM_ERR_OFFSET != offset && 0 == (offset % sizeof(CDFSNP_ITEM)))
    {
        //CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, "cdfsnp_fetch");
        return (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
    }
    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_fetch: np %ld, failed where offset %ld, sizeof(CDFSNP_ITEM) %ld, mod result %ld\n",
                        CDFSNP_PATH_LAYOUT(cdfsnp), offset, sizeof(CDFSNP_ITEM), (offset % sizeof(CDFSNP_ITEM)));
    return (NULL_PTR);
}

EC_BOOL cdfsnp_inode_update(CDFSNP *cdfsnp, CDFSNP_INODE *cdfsnp_inode, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout)
{
    if(src_dn_tcid == CDFSNP_INODE_TCID(cdfsnp_inode) && src_path_layout == CDFSNP_INODE_PATH(cdfsnp_inode))
    {
        CDFSNP_INODE_TCID(cdfsnp_inode) = des_tcid;
        CDFSNP_INODE_PATH(cdfsnp_inode) = des_path_layout;
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_fnode_update(CDFSNP *cdfsnp, CDFSNP_FNODE *cdfsnp_fnode, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout)
{
    UINT32 replica;

    for(replica = 0; replica < CDFSNP_FNODE_REPNUM(cdfsnp_fnode); replica ++)
    {
        cdfsnp_inode_update(cdfsnp, CDFSNP_FNODE_INODE(cdfsnp_fnode, replica), src_dn_tcid, src_path_layout, des_tcid, des_path_layout);
    }
    return (EC_FALSE);
}

EC_BOOL cdfsnp_bucket_update(CDFSNP *cdfsnp, const CDFSNP_BUCKET bucket, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout)
{
    UINT32 offset;

    offset = bucket;

    while(CDFSNP_ITEM_ERR_OFFSET != offset)
    {
        CDFSNP_ITEM *cdfsnp_item;

        CDFSNP_ITEM_OFFSET_ASSERT(cdfsnp, offset, "cdfsnp_bucket_update");

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
        if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item))
        {
            dbg_log(SEC_0058_CDFSNP, 5)(LOGSTDOUT, "cdfsnp_bucket_update: item at offset %ld was not used\n", offset);
            return (EC_FALSE);
        }

        if(EC_FALSE == cdfsnp_item_update(cdfsnp, cdfsnp_item, src_dn_tcid, src_path_layout, des_tcid, des_path_layout))
        {
            dbg_log(SEC_0058_CDFSNP, 5)(LOGSTDOUT, "cdfsnp_bucket_update: item at offset %ld update failed\n", offset);
            return (EC_FALSE);
        }

        offset = (CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item) & CDFSNP_32BIT_MASK);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_dnode_update(CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout)
{
    UINT32 bucket_pos;
    for(bucket_pos = 0; bucket_pos < CDFSNP_DIR_BUCKET_MAX_NUM; bucket_pos ++)
    {
        if(EC_FALSE == cdfsnp_bucket_update(cdfsnp, CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, bucket_pos), src_dn_tcid, src_path_layout, des_tcid, des_path_layout))
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_dnode_update: update bucket %ld failed\n",
                            bucket_pos);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_item_update(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout)
{
    if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_update: item was not used\n");
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        return cdfsnp_fnode_update(cdfsnp, CDFSNP_ITEM_FNODE(cdfsnp_item), src_dn_tcid, src_path_layout, des_tcid, des_path_layout);
    }

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        return cdfsnp_dnode_update(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item), src_dn_tcid, src_path_layout, des_tcid, des_path_layout);
    }

    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_item_update: invalid item dflag %ld\n",
                    (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item));
    return (EC_FALSE);
}

EC_BOOL cdfsnp_update_no_lock(CDFSNP *cdfsnp, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout)
{
    UINT32 offset;
    CDFSNP_ITEM *cdfsnp_item;

    if(CDFSNP_IS_NOT_CACHED(cdfsnp) || NULL_PTR == CDFSNP_BASE_BUFF(cdfsnp))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_update_no_lock: np %ld invalid state %lx or base buff %p\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp), CDFSNP_BASE_BUFF(cdfsnp));
        return (EC_FALSE);
    }

    offset = 0;/*the first item is root directory*/
    cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
    return cdfsnp_item_update(cdfsnp, cdfsnp_item, src_dn_tcid, src_path_layout, des_tcid, des_path_layout);/*recursively*/
}

/*reserve one item from np*/
CDFSNP_ITEM *cdfsnp_reserve_item(CDFSNP *cdfsnp)
{
    UINT32 offset;
    CDFSNP_ITEM *cdfsnp_item;

    CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0025);
    offset = CDFSNP_ROFF(cdfsnp);
    if(CDFSNP_ITEM_ERR_OFFSET != offset && offset + sizeof(CDFSNP_ITEM) <= CDFSNP_FSIZE(cdfsnp) && 0 == (offset % sizeof(CDFSNP_ITEM)))
    {
        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
        dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_reserve_item: roff %ld => %ld\n",
                            (UINT32)CDFSNP_ROFF(cdfsnp),
                            (UINT32)CDFSNP_ITEM_ROFF(cdfsnp_item));
        CDFSNP_ROFF(cdfsnp) = CDFSNP_ITEM_ROFF(cdfsnp_item);/*cdfsnp roff move to next*/
        CDFSNP_ITEM_ROFF(cdfsnp_item) = CDFSNP_ITEM_ERR_OFFSET;/*xxx*/
        CDFSNP_ICNUM(cdfsnp) ++;

        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0026);
        return (cdfsnp_item);
    }

    CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0027);
    return (NULL_PTR);
}

CDFSNP_ITEM *cdfsnp_reserve_item_no_lock(CDFSNP *cdfsnp)
{
    UINT32 offset;
    CDFSNP_ITEM *cdfsnp_item;

    offset = CDFSNP_ROFF(cdfsnp);
    if(CDFSNP_ITEM_ERR_OFFSET != offset && offset + sizeof(CDFSNP_ITEM) <= CDFSNP_FSIZE(cdfsnp) && 0 == (offset % sizeof(CDFSNP_ITEM)))
    {
        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);

        CDFSNP_ROFF(cdfsnp) = CDFSNP_ITEM_ROFF(cdfsnp_item);/*cdfsnp roff move to next*/
        CDFSNP_ITEM_ROFF(cdfsnp_item) = CDFSNP_ITEM_ERR_OFFSET;/*xxx*/
        CDFSNP_ICNUM(cdfsnp) ++;
        return (cdfsnp_item);
    }

    return (NULL_PTR);
}

/*return one item to np*/
EC_BOOL cdfsnp_release_item(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item)
{
    UINT32 offset;

    offset = CDFSNP_GET_ITEM_OFFSET(cdfsnp, cdfsnp_item);
    if(offset <= CDFSNP_FSIZE(cdfsnp) && 0 == (offset % sizeof(CDFSNP_ITEM)))
    {
        CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0028);
        CDFSNP_ITEM_ROFF(cdfsnp_item) = CDFSNP_ROFF(cdfsnp);
        CDFSNP_ROFF(cdfsnp) = offset;
        CDFSNP_ICNUM(cdfsnp) --;
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0029);
        return (EC_TRUE);
    }
    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_release_item: invalid offset %ld where fsize %ld\n", offset, CDFSNP_FSIZE(cdfsnp));
    return (EC_FALSE);
}

EC_BOOL cdfsnp_release_item_no_lock(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item)
{
    UINT32 offset;

    offset = CDFSNP_GET_ITEM_OFFSET(cdfsnp, cdfsnp_item);
    if(offset <= CDFSNP_FSIZE(cdfsnp) && 0 == (offset % sizeof(CDFSNP_ITEM)))
    {
        CDFSNP_ITEM_ROFF(cdfsnp_item) = CDFSNP_ROFF(cdfsnp);
        CDFSNP_ROFF(cdfsnp) = offset;
        CDFSNP_ICNUM(cdfsnp) --;
        return (EC_TRUE);
    }
    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_release_item_no_lock: invalid offset %ld where fsize %ld\n", offset, CDFSNP_FSIZE(cdfsnp));
    return (EC_FALSE);
}

CDFSNP_ITEM *cdfsnp_set(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag)
{
    return cdfsnp_fetch(cdfsnp, cdfsnp_insert(cdfsnp, path_len, path, dflag));
}

CDFSNP_ITEM *cdfsnp_get(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag)
{
    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CDFSNP_ITEM_FILE_IS_DIR != dflag && CDFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (NULL_PTR);
        }

        return cdfsnp_fetch(cdfsnp, cdfsnp_search(cdfsnp, path_len - 1, path, CDFSNP_ITEM_FILE_IS_DIR));
    }
    return cdfsnp_fetch(cdfsnp, cdfsnp_search(cdfsnp, path_len, path, dflag));
}

EC_BOOL cdfsnp_del(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec)
{
    CDFSNP_ITEM *cdfsnp_item;

    if(path_len > 0 && '/' == *(path + path_len - 1))
    {
        if(CDFSNP_ITEM_FILE_IS_DIR != dflag && CDFSNP_ITEM_FILE_IS_ANY != dflag)
        {
            return (EC_FALSE);
        }

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0030);
        cdfsnp_item = cdfsnp_fetch(cdfsnp, cdfsnp_search_no_lock(cdfsnp, path_len - 1, path, CDFSNP_ITEM_FILE_IS_DIR));
    }
    else
    {
        CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0031);
        cdfsnp_item = cdfsnp_fetch(cdfsnp, cdfsnp_search_no_lock(cdfsnp, path_len, path, dflag));
    }

    if(NULL_PTR == cdfsnp_item)
    {
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0032);
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_ITEM *cdfsnp_item_parent;
        CDFSNP_ITEM *cdfsnp_item_son;
        UINT32 second_hash;

        cdfsnp_item_parent = cdfsnp_fetch(cdfsnp, CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK);
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        cdfsnp_item_son = cdfsnp_dnode_umount_son(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item_parent),
                                                  second_hash,
                                                  CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        if(NULL_PTR != cdfsnp_fnode_vec)
        {
            cvector_push_no_lock(cdfsnp_fnode_vec, cdfsnp_fnode_make(CDFSNP_ITEM_FNODE(cdfsnp_item_son)));
        }
        cdfsnp_item_clean(cdfsnp_item_son);
        CDFSNP_SET_UPDATED(cdfsnp);/*cdfsnp was changed, update state*/
    }

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_ITEM *cdfsnp_item_parent;
        CDFSNP_ITEM *cdfsnp_item_son;
        UINT32 second_hash;

        cdfsnp_item_parent = cdfsnp_fetch(cdfsnp, CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK);
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        cdfsnp_item_son = cdfsnp_dnode_umount_son(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item_parent),
                                                  second_hash,
                                                  CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        cdfsnp_dnode_delete_dir_son(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item_son), cdfsnp_fnode_vec);
        cdfsnp_item_clean(cdfsnp_item_son);
        CDFSNP_SET_UPDATED(cdfsnp);/*cdfsnp was changed, update state*/
    }

    CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0033);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_del_item(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item, CVECTOR *cdfsnp_fnode_vec)
{
    CDFSNP_LOCK(cdfsnp, LOC_CDFSNP_0034);

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_ITEM *cdfsnp_item_parent;
        CDFSNP_ITEM *cdfsnp_item_son;
        UINT32 second_hash;

        cdfsnp_item_parent = cdfsnp_fetch(cdfsnp, CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK);
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        cdfsnp_item_son = cdfsnp_dnode_umount_son(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item_parent),
                                                  second_hash,
                                                  CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        if(NULL_PTR != cdfsnp_fnode_vec)
        {
            cvector_push_no_lock(cdfsnp_fnode_vec, cdfsnp_fnode_make(CDFSNP_ITEM_FNODE(cdfsnp_item_son)));
        }
        cdfsnp_item_clean(cdfsnp_item_son);
        CDFSNP_SET_UPDATED(cdfsnp);/*cdfsnp was changed, update state*/
    }

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_ITEM *cdfsnp_item_parent;
        CDFSNP_ITEM *cdfsnp_item_son;
        UINT32 second_hash;

        cdfsnp_item_parent = cdfsnp_fetch(cdfsnp, CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK);
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        cdfsnp_item_son = cdfsnp_dnode_umount_son(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item_parent),
                                                  second_hash,
                                                  CDFSNP_ITEM_KLEN(cdfsnp_item), CDFSNP_ITEM_KEY(cdfsnp_item));
        cdfsnp_dnode_delete_dir_son(cdfsnp, CDFSNP_ITEM_DNODE(cdfsnp_item_son), cdfsnp_fnode_vec);
        cdfsnp_item_clean(cdfsnp_item_son);
        CDFSNP_SET_UPDATED(cdfsnp);/*cdfsnp was changed, update state*/
    }

    CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNP_0035);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_path_name(const CDFSNP *cdfsnp, const UINT32 offset, const UINT32 path_max_len, UINT32 *path_len, UINT8 *path)
{
    CSTACK *cstack;
    UINT32  cur_offset;
    UINT32  cur_path_len;

    cstack = cstack_new(MM_IGNORE, LOC_CDFSNP_0036);

    cur_offset = offset;
    while(CDFSNP_ITEM_ERR_OFFSET != cur_offset)
    {
        CDFSNP_ITEM *cdfsnp_item;

        cstack_push(cstack, (void *)cur_offset);

        cdfsnp_item = cdfsnp_fetch(cdfsnp, cur_offset);
        cur_offset = (CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK);
    }

    cur_path_len = 0;
    path[ 0 ] = '\0';

    while(EC_FALSE == cstack_is_empty(cstack) && cur_path_len < path_max_len)
    {
        CDFSNP_ITEM *cdfsnp_item;

        cur_offset = (UINT32)cstack_pop(cstack);
        cdfsnp_item = cdfsnp_fetch(cdfsnp, cur_offset);

        if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            cur_path_len += snprintf((char *)path + cur_path_len, path_max_len - cur_path_len, "%.*s/",
                                (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        }
        else if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            cur_path_len += snprintf((char *)path + cur_path_len, path_max_len - cur_path_len, "%.*s",
                                (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        }
        else
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_path_name: np %ld, invalid dir flag %ld at offset %ld\n",
                                CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), cur_offset);
        }
    }

    (*path_len) = cur_path_len;
    path[ cur_path_len ] = '\0';

    cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
    cstack_free(cstack, LOC_CDFSNP_0037);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_path_name_cstr(const CDFSNP *cdfsnp, const UINT32 offset, CSTRING *path_cstr)
{
    CSTACK *cstack;
    UINT32  cur_offset;

    cstack = cstack_new(MM_IGNORE, LOC_CDFSNP_0038);

    cur_offset = offset;
    while(CDFSNP_ITEM_ERR_OFFSET != cur_offset)
    {
        CDFSNP_ITEM *cdfsnp_item;

        cstack_push(cstack, (void *)cur_offset);

        cdfsnp_item = cdfsnp_fetch(cdfsnp, cur_offset);
        cur_offset = (CDFSNP_ITEM_PARENT(cdfsnp_item) & CDFSNP_32BIT_MASK);
    }

    while(EC_FALSE == cstack_is_empty(cstack))
    {
        CDFSNP_ITEM *cdfsnp_item;

        cur_offset = (UINT32)cstack_pop(cstack);
        cdfsnp_item = cdfsnp_fetch(cdfsnp, cur_offset);

        if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            cstring_format(path_cstr, "%.*s/", (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        }
        else if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            cstring_format(path_cstr, "%.*s", (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        }
        else
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_path_name_cstr: np %ld, invalid dir flag %ld at offset %ld\n",
                                CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), cur_offset);
        }
    }

    cstack_clean(cstack, NULL_PTR);/*cleanup for safe reason*/
    cstack_free(cstack, LOC_CDFSNP_0039);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_seg_name(const CDFSNP *cdfsnp, const UINT32 offset, const UINT32 seg_name_max_len, UINT32 *seg_name_len, UINT8 *seg_name)
{
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp_item = cdfsnp_fetch(cdfsnp, offset);

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        (*seg_name_len) = snprintf((char *)seg_name, seg_name_max_len, "%.*s/",
                            (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        return (EC_TRUE);
    }
    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        (*seg_name_len) = snprintf((char *)seg_name, seg_name_max_len, "%.*s",
                            (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        return (EC_TRUE);
    }

    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_seg_name: np %ld, invalid dir flag %ld at offset %ld\n",
                        CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), offset);
    return (EC_FALSE);
}

EC_BOOL cdfsnp_seg_name_cstr(const CDFSNP *cdfsnp, const UINT32 offset, CSTRING *seg_cstr)
{
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp_item = cdfsnp_fetch(cdfsnp, offset);
    if(NULL_PTR == cdfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        cstring_format(seg_cstr, "%.*s/", (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        return (EC_TRUE);
    }
    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        cstring_format(seg_cstr, "%.*s", (uint32_t)CDFSNP_ITEM_KLEN(cdfsnp_item), (char *)CDFSNP_ITEM_KEY(cdfsnp_item));
        return (EC_TRUE);
    }

    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_seg_name_cstr: np %ld, invalid dir flag %ld at offset %ld\n",
                        CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), offset);
    return (EC_FALSE);
}

EC_BOOL cdfsnp_list_path_vec(const CDFSNP *cdfsnp, const UINT32 offset, CVECTOR *path_cstr_vec)
{
    CDFSNP_ITEM *cdfsnp_item;
    CSTRING *path_cstr;

    cdfsnp_item = cdfsnp_fetch(cdfsnp, offset);
    if(NULL_PTR == cdfsnp_item)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_path_vec: np %ld, item is null at offset %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), offset);
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG != CDFSNP_ITEM_DFLG(cdfsnp_item) && CDFSNP_ITEM_FILE_IS_DIR != CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_path_vec: np %ld, invalid dir flag %ld at offset %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), offset);
        return (EC_FALSE);
    }

    path_cstr = cstring_new(NULL_PTR, LOC_CDFSNP_0040);
    if(NULL_PTR == path_cstr)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_path_vec: np %ld, new path cstr failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));
        return (EC_FALSE);
    }

    cdfsnp_path_name_cstr(cdfsnp, offset, path_cstr);

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
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

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_DNODE *cdfsnp_dnode;
        UINT32 cdfsnp_bucket_pos;

        cdfsnp_dnode = (CDFSNP_DNODE *)CDFSNP_ITEM_DNODE(cdfsnp_item);
        for(cdfsnp_bucket_pos = 0; cdfsnp_bucket_pos < CDFSNP_DIR_BUCKET_MAX_NUM; cdfsnp_bucket_pos ++)
        {
            UINT32 offset_son;

            offset_son = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, cdfsnp_bucket_pos);
            dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_list_path_vec: np %ld, cdfsnp_bucket_posn = %ld, offset son %ld\n",
                                CDFSNP_PATH_LAYOUT(cdfsnp), cdfsnp_bucket_pos, offset_son);
            while(CDFSNP_ITEM_ERR_OFFSET != offset_son)
            {
                CDFSNP_ITEM  *cdfsnp_item_son;
                CSTRING *full_path_cstr;

                cdfsnp_item_son = cdfsnp_fetch(cdfsnp, offset_son);
                if(NULL_PTR == cdfsnp_item_son)
                {
                    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_path_vec: np %ld, fetch failed where offset_son = %ld\n",
                                       CDFSNP_PATH_LAYOUT(cdfsnp), offset_son);
                    return (EC_FALSE);
                }

                full_path_cstr = cstring_new(cstring_get_str(path_cstr), LOC_CDFSNP_0041);
                if(NULL_PTR == full_path_cstr)
                {
                    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_path_vec: np %ld, new full path failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));
                    return (EC_FALSE);
                }

                cdfsnp_seg_name_cstr(cdfsnp, offset_son, full_path_cstr);

                dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDNULL, "[DEBUG] cdfsnp_list_path_vec: np %ld, offset son %ld, %s\n",
                                    CDFSNP_PATH_LAYOUT(cdfsnp), offset_son, (char *)cstring_get_str(full_path_cstr));

                if(CVECTOR_ERR_POS == cvector_search_front(path_cstr_vec, (void *)full_path_cstr, (CVECTOR_DATA_CMP)cstring_is_equal))
                {
                    cvector_push(path_cstr_vec, (void *)full_path_cstr);
                }
                else
                {
                    cstring_free(full_path_cstr);
                }

                offset_son = (CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item_son) & CDFSNP_32BIT_MASK);
            }
        }

        cstring_free(path_cstr);
        return (EC_TRUE);
    }
    /*never reach here*/
    return (EC_FALSE);
}

EC_BOOL cdfsnp_list_seg_vec(const CDFSNP *cdfsnp, const UINT32 offset, CVECTOR *seg_cstr_vec)
{
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp_item = cdfsnp_fetch(cdfsnp, offset);
    if(NULL_PTR == cdfsnp_item)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_seg_vec: np %ld, item is null at offset %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), offset);
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG != CDFSNP_ITEM_DFLG(cdfsnp_item) && CDFSNP_ITEM_FILE_IS_DIR != CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_seg_vec: np %ld, invalid dir flag %ld at offset %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item), offset);
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CSTRING *seg_name_cstr;

        seg_name_cstr = cstring_new(NULL_PTR, LOC_CDFSNP_0042);
        if(NULL_PTR == seg_name_cstr)
        {
            dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_seg_vec: np %ld, new seg str failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));
            return (EC_FALSE);
        }

        cdfsnp_seg_name_cstr(cdfsnp, offset, seg_name_cstr);

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

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_DNODE *cdfsnp_dnode;
        UINT32 cdfsnp_bucket_pos;

        cdfsnp_dnode = (CDFSNP_DNODE *)CDFSNP_ITEM_DNODE(cdfsnp_item);
        for(cdfsnp_bucket_pos = 0; cdfsnp_bucket_pos < CDFSNP_DIR_BUCKET_MAX_NUM; cdfsnp_bucket_pos ++)
        {
            UINT32 offset_son;

            offset_son = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, cdfsnp_bucket_pos);
            while(CDFSNP_ITEM_ERR_OFFSET != offset_son)
            {
                CDFSNP_ITEM  *cdfsnp_item_son;
                CSTRING *seg_name_cstr;

                cdfsnp_item_son = cdfsnp_fetch(cdfsnp, offset_son);

                seg_name_cstr = cstring_new(NULL_PTR, LOC_CDFSNP_0043);
                if(NULL_PTR == seg_name_cstr)
                {
                    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_list_seg_vec: np %ld, new seg str failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));
                    return (EC_FALSE);
                }

                cdfsnp_seg_name_cstr(cdfsnp, offset_son, seg_name_cstr);
                dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_list_seg_vec: offset_son %ld, seg_name_cstr %s\n", offset_son, (char *)cstring_get_str(seg_name_cstr));

                if(CVECTOR_ERR_POS == cvector_search_front(seg_cstr_vec, (void *)seg_name_cstr, (CVECTOR_DATA_CMP)cstring_is_equal))
                {
                    cvector_push(seg_cstr_vec, (void *)seg_name_cstr);
                }
                else
                {
                    cstring_free(seg_name_cstr);
                }

                offset_son = (CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item_son) & CDFSNP_32BIT_MASK);
            }
        }

        return (EC_TRUE);
    }

    /*never reach here*/
    return (EC_FALSE);
}

EC_BOOL cdfsnp_file_num(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, UINT32 *file_num)
{
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp_item = cdfsnp_get(cdfsnp, path_len, path, CDFSNP_ITEM_FILE_IS_ANY);
    if(NULL_PTR == cdfsnp_item)
    {
        (*file_num) = 0;
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        (*file_num) = 1;
        return (EC_TRUE);
    }

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_DNODE *cdfsnp_dnode;
        cdfsnp_dnode = CDFSNP_ITEM_DNODE(cdfsnp_item);

        (*file_num) = (CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode) & CDFSNP_32BIT_MASK);
        return (EC_TRUE);
    }

    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_file_num: np %ld, invalid dflg %lx\n",
                    CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item));
    return (EC_FALSE);
}

EC_BOOL cdfsnp_file_size(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, UINT32 *file_size)
{
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp_item = cdfsnp_get(cdfsnp, path_len, path, CDFSNP_ITEM_FILE_IS_ANY);
    if(NULL_PTR == cdfsnp_item)
    {
        (*file_size) = 0;
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        CDFSNP_FNODE *cdfsnp_fnode;
        cdfsnp_fnode = CDFSNP_ITEM_FNODE(cdfsnp_item);

        (*file_size) = CDFSNP_FNODE_FILESZ(cdfsnp_fnode);
        return (EC_TRUE);
    }

    dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_file_size: np %ld, invalid dflg %lx\n",
                    CDFSNP_PATH_LAYOUT(cdfsnp), (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item));
    return (EC_FALSE);
}

EC_BOOL cdfsnp_mkdirs(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path)
{
    if(CDFSNP_ITEM_ERR_OFFSET == cdfsnp_insert(cdfsnp, path_len, path, CDFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_mkdirs: mkdirs %.*s failed\n", (uint32_t)path_len, (char *)path);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_flush(const CDFSNP *cdfsnp)
{
    UINT32 wsize;

    wsize = CDFSNP_FSIZE(cdfsnp);
    if(wsize > CDFSNP_BASE_BUFF_LEN(cdfsnp))/*adjust wsize if need*/
    {
        wsize = CDFSNP_BASE_BUFF_LEN(cdfsnp);
    }

    if(0 < (wsize >> (WORDSIZE - 1)))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_flush: np %ld, wsize %lx overflow\n",
                        CDFSNP_PATH_LAYOUT(cdfsnp), wsize);
        return (EC_FALSE);
    }

    return cdfsnp_buff_flush(cdfsnp, 0, (RWSIZE)wsize, CDFSNP_BASE_BUFF(cdfsnp));
}

EC_BOOL cdfsnp_load(CDFSNP *cdfsnp)
{
    CDFSNP_HEADER *cdfsnp_header;

    UINT8 *base_buff;
    UINT32 base_buff_len;

    cdfsnp_header = CDFSNP_HDR(cdfsnp);

    if(EC_FALSE == cdfsnp_header_is_valid(cdfsnp_header, (UINT32)1))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_load: np %ld, corrupted header\n", CDFSNP_PATH_LAYOUT(cdfsnp));
        return (EC_FALSE);
    }

#if 1
    dbg_log(SEC_0058_CDFSNP, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_load: np %ld, header is:\n", CDFSNP_PATH_LAYOUT(cdfsnp));
    cdfsnp_print_header(LOGSTDOUT, cdfsnp);
#endif

    base_buff_len = CDFSNP_HEADER_FSIZE(cdfsnp_header);
    base_buff = (UINT8 *)SAFE_MALLOC(base_buff_len, LOC_CDFSNP_0044);
    if(NULL_PTR == base_buff)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_load: np %ld, alloc whole file memory failed where file size %ld\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_HEADER_FSIZE(cdfsnp_header));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_buff_load(cdfsnp, 0, base_buff_len, base_buff))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_load: np %ld, load %ld bytes failed\n", CDFSNP_PATH_LAYOUT(cdfsnp), base_buff_len);
        SAFE_FREE(base_buff, LOC_CDFSNP_0045);
        return (EC_FALSE);
    }

    /*link*/
    cdfsnp_link(cdfsnp, base_buff_len, base_buff);

    CDFSNP_FIRST_CHASH_ALGO(cdfsnp)  = chash_algo_fetch(CDFSNP_FIRST_CHASH_ALGO_ID(cdfsnp));
    CDFSNP_SECOND_CHASH_ALGO(cdfsnp) = chash_algo_fetch(CDFSNP_SECOND_CHASH_ALGO_ID(cdfsnp));

    return (EC_TRUE);
}

EC_BOOL cdfsnp_unlink(const char *dbname)
{
    if (NULL_PTR == dbname)
    {
        return (EC_FALSE);
    }

    if( 0 != unlink(dbname))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_open(CDFSNP *cdfsnp, const char *cdfsnp_db_root_dir, UINT32 *create_flag)
{
    UINT8  cdfsnp_name[ CDFSNP_NAME_MAX_SIZE ];

    cdfsnp_fname_gen(cdfsnp_db_root_dir, CDFSNP_DISK_MAX_NUM(cdfsnp), CDFSNP_PATH_LAYOUT(cdfsnp), (char *)cdfsnp_name, CDFSNP_NAME_MAX_SIZE);

    if(0 != access((char *)cdfsnp_name, F_OK))
    {
        dbg_log(SEC_0058_CDFSNP, 1)(LOGSTDOUT, "warn:cdfsnp_open: np %s not exist, try to create it\n", cdfsnp_name);

        (*create_flag) = CDFSNP_O_CREATE;
        return cdfsnp_create(cdfsnp, cdfsnp_db_root_dir);
    }

    CDFSNP_FD(cdfsnp) = c_file_open((char *)cdfsnp_name, O_RDWR, 0666);
    if(ERR_FD == CDFSNP_FD(cdfsnp))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_open: open cdfsnp file %s failed\n", cdfsnp_name);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_load(cdfsnp))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_open: load cdfsnp file %s failed\n", cdfsnp_name);
        c_file_close(CDFSNP_FD(cdfsnp));
        CDFSNP_FD(cdfsnp) = ERR_FD;
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_close(CDFSNP *cdfsnp)
{
    cdfsnp_free(cdfsnp);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_close_with_flush(CDFSNP *cdfsnp)
{
    cdfsnp_flush(cdfsnp);
    cdfsnp_close(cdfsnp);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_create_root_item(CDFSNP *cdfsnp)
{
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_ITEM_VEC(cdfsnp) + 0);

    CDFSNP_ITEM_DFLG(cdfsnp_item)             = CDFSNP_ITEM_FILE_IS_DIR;
    CDFSNP_ITEM_STAT(cdfsnp_item)             = CDFSNP_ITEM_STAT_IS_CACHED;
    CDFSNP_ITEM_KLEN(cdfsnp_item)             = 0;
    CDFSNP_ITEM_PARENT(cdfsnp_item)           = CDFSNP_ITEM_ERR_OFFSET;
    CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item)       = CDFSNP_ITEM_ERR_OFFSET;

    //CDFSNP_ITEM_KEY(cdfsnp_item)[ 0 ] = '/';/*deprecated*/
    CDFSNP_ITEM_KEY(cdfsnp_item)[ 0 ] = '\0';

    /******************************************************************************************************/
    /*when enable this branch, qlist can query root dir "/"; otherwise, qlist query it will return nothing*/
    /*if enable this branch, qlist "/" will run-through all np which is time-cost operation!!!            */
    /******************************************************************************************************/
    if(1)
    {
        UINT32 first_hash;
        UINT32 second_hash;

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, 1, (UINT8 *)"/");
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, 1, (UINT8 *)"/");
        //dbg_log(SEC_0058_CDFSNP, 0)(LOGCONSOLE, "[DEBUG] cdfsnp_create_root_item: id %ld, algo %lx, first_hash  = %ld\n", CDFSNP_FIRST_CHASH_ALGO_ID(cdfsnp), CDFSNP_FIRST_CHASH_ALGO(cdfsnp), first_hash);
        //dbg_log(SEC_0058_CDFSNP, 0)(LOGCONSOLE, "[DEBUG] cdfsnp_create_root_item: id %ld, algo %lx, second_hash = %ld\n", CDFSNP_SECOND_CHASH_ALGO_ID(cdfsnp), CDFSNP_SECOND_CHASH_ALGO(cdfsnp), second_hash);

        /*update cdfsnp*/
        cdfsnp_cbloom_set(cdfsnp, first_hash, second_hash);
    }

    CDFSNP_ICNUM(cdfsnp) ++;
    CDFSNP_ROFF(cdfsnp) += sizeof(CDFSNP_ITEM);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_create(CDFSNP *cdfsnp, const char *cdfsnp_db_root_dir)
{
    UINT8  path[ CDFSNP_NAME_MAX_SIZE ];
    UINT32 cdfsnp_item_pos;
    UINT8 *base_buff;
    UINT32 base_buff_len;

    cdfsnp_dname_gen(cdfsnp_db_root_dir, CDFSNP_DISK_MAX_NUM(cdfsnp), CDFSNP_PATH_LAYOUT(cdfsnp), (char *)path, CDFSNP_NAME_MAX_SIZE);
    if(EC_FALSE == cdfsnp_create_dir((char *)path))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_create: create np dir %s failed\n", (char *)path);
        return (EC_FALSE);
    }

    cdfsnp_fname_gen(cdfsnp_db_root_dir, CDFSNP_DISK_MAX_NUM(cdfsnp), CDFSNP_PATH_LAYOUT(cdfsnp), (char *)path, CDFSNP_NAME_MAX_SIZE);
    if(0 == access((char *)path, F_OK))/*exist*/
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_create: np %s exist already\n", (char *)path);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_header_is_valid(CDFSNP_HDR(cdfsnp), (UINT32)0))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_create: create header is invalid\n");
        return (EC_FALSE);
    }

    CDFSNP_FD(cdfsnp) = c_file_open((char *)path, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CDFSNP_FD(cdfsnp))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_create: cannot create np %s\n", (char *)path);
        return (EC_FALSE);
    }

    base_buff_len = CDFSNP_FSIZE(cdfsnp);
    base_buff = (UINT8 *)SAFE_MALLOC(base_buff_len, LOC_CDFSNP_0046);
    if(NULL_PTR == base_buff)
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_create: alloc buff failed where buff len %ld\n", base_buff_len);
        c_file_close(CDFSNP_FD(cdfsnp));
        CDFSNP_FD(cdfsnp) = ERR_FD;
        return (EC_FALSE);
    }

    cdfsnp_link(cdfsnp, base_buff_len, base_buff);

    /*init item vec*/
    for(cdfsnp_item_pos = 0; cdfsnp_item_pos < CDFSNP_IMNUM(cdfsnp); cdfsnp_item_pos ++)
    {
        CDFSNP_ITEM *cdfsnp_item;

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_ITEM_VEC(cdfsnp) + cdfsnp_item_pos);
        cdfsnp_item_init(cdfsnp_item);

        CDFSNP_ITEM_ROFF(cdfsnp_item) = (cdfsnp_item_pos + 1) * sizeof(CDFSNP_ITEM);
    }
    CDFSNP_ROFF(cdfsnp) = 0;/*point to the first cdfsnp_item*/

    /*create root item*/
    cdfsnp_create_root_item(cdfsnp);

#if 1
    if(EC_FALSE == cdfsnp_buff_flush(cdfsnp, (UINT32)0, CDFSNP_FSIZE(cdfsnp), CDFSNP_BASE_BUFF(cdfsnp)))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_create: create cdfsnp file %s failed\n", (char *)path);
        return (EC_FALSE);
    }
    /*note: header will be flushed after return*/
#endif

    //CDFSNP_SET_CACHED(cdfsnp);
    //CDFSNP_SET_UPDATED(cdfsnp);
    //CDFSNP_SET_RDWR(cdfsnp);

    return (EC_TRUE);
}

STATIC_CAST static UINT32 cdfsnp_figured_block_find_uclosed_offset(const CVECTOR *cdfsnp_inode_vec, const UINT32 offset)
{
    UINT32 pos;
    UINT32 closed_offset;
    UINT32 closed_pos;

    closed_offset = (UINT32)-1;
    closed_pos = CVECTOR_ERR_POS;

    for(pos = 0; pos < cvector_size(cdfsnp_inode_vec); pos ++)
    {
        CDFSNP_INODE *cdfsnp_inode;
        cdfsnp_inode = (CDFSNP_INODE *)cvector_get(cdfsnp_inode_vec, pos);

        if(offset <= CDFSNP_INODE_FOFF(cdfsnp_inode) && CDFSNP_INODE_FOFF(cdfsnp_inode) < closed_offset)
        {
            closed_offset = CDFSNP_INODE_FOFF(cdfsnp_inode);
            closed_pos = pos;
        }
    }
    return (closed_pos);
}

STATIC_CAST static void cdfsnp_figured_block_sort_print(LOG *log, const CVECTOR *file_size_vec, const CVECTOR *cdfsnp_inode_vec)
{
    UINT32 prev_offset;
    UINT32 prev_file_size;
    UINT32 offset;
    UINT32 pos;

    prev_offset = 0;
    prev_file_size = 0;

    offset = 0;
    while(CVECTOR_ERR_POS != (pos = cdfsnp_figured_block_find_uclosed_offset(cdfsnp_inode_vec, offset)))
    {
        CDFSNP_INODE *cdfsnp_inode;
        UINT32 file_size;

        cdfsnp_inode = (CDFSNP_INODE *)cvector_get(cdfsnp_inode_vec, pos);
        file_size    = (UINT32)cvector_get(file_size_vec, pos);

        if(prev_offset + prev_file_size == CDFSNP_INODE_FOFF(cdfsnp_inode))
        {
            sys_log(log, "file size: %8ld, (tcid %s, path %lx, offset %ld) \n",
                         file_size,
                         c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode)),
                         (CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK),
                         (CDFSNP_INODE_FOFF(cdfsnp_inode) & CDFSNP_32BIT_MASK)
                     );
        }
        else
        {
            sys_log(log, "file size: %8ld, (tcid %s, path %lx, offset %ld)       [X]\n",
                         file_size,
                         c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode)),
                         (CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK),
                         (CDFSNP_INODE_FOFF(cdfsnp_inode) & CDFSNP_32BIT_MASK)
                     );
        }

        prev_file_size = file_size;
        prev_offset    = CDFSNP_INODE_FOFF(cdfsnp_inode);

        offset         = prev_offset + 1;/*trick*/
    }
    return;
}

EC_BOOL cdfsnp_figure_out_block(const CDFSNP *cdfsnp, const UINT32 tcid, const UINT32 path_layout, LOG *log)
{
    UINT32 offset;

    CVECTOR *file_size_vec;
    CVECTOR *cdfsnp_inode_vec;

    file_size_vec    = cvector_new(0, MM_UINT32, LOC_CDFSNP_0047);
    cdfsnp_inode_vec = cvector_new(0, MM_CDFSNP_INODE, LOC_CDFSNP_0048);

    for(offset = 0; offset + sizeof(CDFSNP_ITEM) <= CDFSNP_FSIZE(cdfsnp); offset += sizeof(CDFSNP_ITEM))
    {
        CDFSNP_ITEM  *cdfsnp_item;
        CDFSNP_FNODE *cdfsnp_fnode;
        UINT32 cdfsnp_inode_pos;

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset);
        if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item))
        {
            continue;
        }

        if(CDFSNP_ITEM_FILE_IS_REG != CDFSNP_ITEM_DFLG(cdfsnp_item))/*no more to search*/
        {
            continue;
        }

        cdfsnp_fnode = CDFSNP_ITEM_FNODE(cdfsnp_item);
        for(cdfsnp_inode_pos = 0; cdfsnp_inode_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode); cdfsnp_inode_pos ++)
        {
            CDFSNP_INODE *cdfsnp_inode;

            cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, cdfsnp_inode_pos);
            if(
                (CMPI_ANY_TCID == tcid || tcid == CDFSNP_INODE_TCID(cdfsnp_inode))
             && path_layout == (CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK)
            )
            {
                UINT32 fsize;
                fsize = CDFSNP_FNODE_FILESZ(cdfsnp_fnode);
                cvector_push(file_size_vec, (void *)fsize);
                cvector_push(cdfsnp_inode_vec, (void *)cdfsnp_inode);
                //sys_log(log, "file size: %8ld, ", CDFSNP_FNODE_FILESZ(cdfsnp_fnode));
                //cdfsnp_inode_print(log, cdfsnp_inode);

                break;
            }
        }
    }

    cdfsnp_figured_block_sort_print(log, file_size_vec, cdfsnp_inode_vec);

    cvector_free(file_size_vec, LOC_CDFSNP_0049);
    cvector_free(cdfsnp_inode_vec, LOC_CDFSNP_0050);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_show_item_full_path(LOG *log, const CDFSNP *cdfsnp, const UINT32 offset)
{
    UINT8 path[1024];
    UINT32 path_len;
    UINT32 path_max_len;
    CSTACK *cstack;

    CDFSNP_ITEM   cdfsnp_item_tmp;
    UINT32 offset_cur;

    cstack = cstack_new(MM_IGNORE, LOC_CDFSNP_0051);
    offset_cur = offset;

    while(CDFSNP_ITEM_ERR_OFFSET != offset_cur)
    {
        cstack_push(cstack, (void *)offset_cur);

        if(EC_FALSE == cdfsnp_item_load((CDFSNP *)cdfsnp, offset_cur, &cdfsnp_item_tmp))
        {
            sys_log(log, "error:cdfsnp_show_item_full_path: [1]load item failed\n");
            return (EC_FALSE);
        }

        offset_cur = (CDFSNP_ITEM_PARENT(&cdfsnp_item_tmp) & CDFSNP_32BIT_MASK);
    }

    path[ 0 ] = '\0';
    path_len = 0;
    path_max_len = sizeof(path)/sizeof(path[0]);

    while(EC_FALSE == cstack_is_empty(cstack))
    {
        offset_cur = (UINT32)cstack_pop(cstack);

        if(EC_FALSE == cdfsnp_item_load((CDFSNP *)cdfsnp, offset_cur, &cdfsnp_item_tmp))
        {
            sys_log(log, "error:cdfsnp_show_item_full_path: [2]load item failed\n");
            return (EC_FALSE);
        }

        //path[ path_len ++ ] = '/';
        //cdfsnp_copy_buff(CDFSNP_ITEM_KEY(&cdfsnp_item_tmp), CDFSNP_ITEM_KLEN(&cdfsnp_item_tmp), path + path_len, path_max_len - path_len, &len);
        //path_len += len;
        //sys_log(log, "%s ==> ", (char *)path);
        if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(&cdfsnp_item_tmp))
        {
            path_len += snprintf((char *)path + path_len, path_max_len - path_len, "%.*s/", (uint32_t)CDFSNP_ITEM_KLEN(&cdfsnp_item_tmp), (char *)CDFSNP_ITEM_KEY(&cdfsnp_item_tmp));
        }
        else if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(&cdfsnp_item_tmp))
        {
            path_len += snprintf((char *)path + path_len, path_max_len - path_len, "%.*s", (uint32_t)CDFSNP_ITEM_KLEN(&cdfsnp_item_tmp), (char *)CDFSNP_ITEM_KEY(&cdfsnp_item_tmp));
        }
        else
        {
            sys_log(log, "error:cdfsnp_show_item_full_path: invalid dir flag %ld at offset\n", CDFSNP_ITEM_DFLG(&cdfsnp_item_tmp), offset_cur);
        }
        if(path_len >= path_max_len)
        {
            sys_log(log, "error:cdfsnp_show_item_full_path: path overflow\n");
        }
        //sys_print(log, "%s [klen %ld, offset %ld]\n", (char *)path, CDFSNP_ITEM_KLEN(&cdfsnp_item_tmp), offset);
    }

    cstack_free(cstack, LOC_CDFSNP_0052);

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

    if(EC_FALSE == cdfsnp_item_load((CDFSNP *)cdfsnp, offset, &cdfsnp_item_tmp))
    {
        sys_log(log, "error:cdfsnp_show_item_full_path: [3]load item failed\n");
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(&cdfsnp_item_tmp))
    {
        sys_log(log, "dir : %s\n", path);
    }
    else if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(&cdfsnp_item_tmp))
    {
        sys_log(log, "file: %s\n", path);
    }
    else
    {
        sys_log(log, "err: %s\n", path);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_show_dir_depth(LOG *log, const CDFSNP *cdfsnp, const CDFSNP_ITEM  *cdfsnp_item)
{
    CDFSNP_DNODE *cdfsnp_dnode;
    UINT32 cdfsnp_bucket_pos;

    cdfsnp_dnode = (CDFSNP_DNODE *)CDFSNP_ITEM_DNODE(cdfsnp_item);
    for(cdfsnp_bucket_pos = 0; cdfsnp_bucket_pos < CDFSNP_DIR_BUCKET_MAX_NUM; cdfsnp_bucket_pos ++)
    {
        UINT32 bucket;

        bucket = CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, cdfsnp_bucket_pos);
        cdfsnp_show_item_depth(log, cdfsnp, bucket);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_show_item_depth(LOG *log, const CDFSNP *cdfsnp, const UINT32 offset)
{
    CDFSNP_ITEM   cdfsnp_item_t;
    CDFSNP_ITEM  *cdfsnp_item;

    if(CDFSNP_ITEM_ERR_OFFSET == offset)
    {
        return (EC_TRUE);
    }

    cdfsnp_item = &cdfsnp_item_t;
    if(EC_FALSE == cdfsnp_item_load((CDFSNP *)cdfsnp, offset, cdfsnp_item))
    {
        sys_log(log, "error:cdfsnp_show_item_depth: load item failed\n");
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item))
    {
        dbg_log(SEC_0058_CDFSNP, 0)(LOGSTDOUT, "error:cdfsnp_show_item_depth: item not used\n");
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_DIR != CDFSNP_ITEM_DFLG(cdfsnp_item) && CDFSNP_ITEM_FILE_IS_REG != CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        sys_log(log, "error:cdfsnp_show_item_depth: invalid dir flag %ld\n", CDFSNP_ITEM_DFLG(cdfsnp_item));
        return (EC_FALSE);
    }

    sys_log(log, "item offset %ld: ", offset );
    //cdfsnp_item_print(log, cdfsnp_item);
    cdfsnp_show_item_full_path(log, cdfsnp, offset);

    if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        cdfsnp_show_dir_depth(log, cdfsnp, cdfsnp_item);
    }

    if(CDFSNP_ITEM_ERR_OFFSET != CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item))
    {
        cdfsnp_show_item_depth(log, cdfsnp, CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item));
    }

    return (EC_TRUE);
}

#if 0
EC_BOOL cdfsnp_show_depth(LOG *log, const char *dbname)
{
    CDFSNP_HEADER  cdfsnp_header_t;
    CDFSNP_HEADER *cdfsnp_header;

    CBLOOM *cbloom;
    UINT32  max_nbits;
    UINT8  *data_area;

    RWSIZE rwsize;
    CDFSNP cdfsnp;

    int db_fd;

    cdfsnp_header = &cdfsnp_header_t;

    if(0 != access(dbname, F_OK))/*exist*/
    {
        sys_log(log, "error:cdfsnp_show_depth: db %s not exist\n", dbname);
        return (EC_FALSE);
    }

    db_fd = c_file_open(dbname, O_RDWR, 0666);
    if(ERR_FD == db_fd)
    {
        sys_log(log, "error:cdfsnp_show_depth: cannot open db %s\n", dbname);
        return (EC_FALSE);
    }

    /*load header*/
    if(ERR_SEEK == lseek(db_fd, 0, SEEK_SET))
    {
        sys_log(log, "error:cdfsnp_show_depth: seek BEG failed\n");
        return (EC_FALSE);
    }

    rwsize = sizeof(CDFSNP_HEADER);
    if(rwsize != read(db_fd, cdfsnp_header, rwsize))
    {
        sys_log(log, "error:cdfsnp_show_depth: load header failed\n");
        return (EC_FALSE);
    }

    sys_log(log, "header: ");
    cdfsnp_print_header(log, cdfsnp);
    sys_print(log, "\n");

    /*load bloom filter*/
    if(ERR_SEEK == lseek(db_fd, CDFSNP_HEADER_BMOFF(cdfsnp_header), SEEK_SET))
    {
        sys_log(log, "error:cdfsnp_show_depth: seek boff failed\n");
        return (EC_FALSE);
    }

    max_nbits = (CDFSNP_HEADER_BMROW(cdfsnp_header) * CDFSNP_HEADER_BMCOL(cdfsnp_header));
    data_area = (UINT8 *)SAFE_MALLOC(sizeof(UINT32) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(max_nbits)), LOC_CDFSNP_0053);
    if(NULL_PTR == data_area)
    {
        sys_log(log, "error:cdfsnp_show_depth: alloc %ld bytes failed\n", NWORDS_TO_NBYTES(NBITS_TO_NWORDS(max_nbits)));
        return (EC_FALSE);
    }

    rwsize = CDFSNP_HEADER_IOFF(cdfsnp_header) - CDFSNP_HEADER_BMOFF(cdfsnp_header);
    if(rwsize != read(db_fd, data_area, rwsize))
    {
        sys_log(log, "error:cdfsnp_show_depth: load bloom failed where rwsize = %ld\n", rwsize);
        return (EC_FALSE);
    }

    cbloom = (CBLOOM *)data_area;

    sys_log(log, "bloom: ");
    cbloom_print(log, cbloom);

    SAFE_FREE(data_area, LOC_CDFSNP_0054);

    CDFSNP_FD(&cdfsnp) = db_fd;/*trick*/

    cdfsnp_show_item_depth(log, &cdfsnp, 0);

    return (EC_TRUE);

}

EC_BOOL cdfsnp_show(LOG *log, const char *dbname)
{
    CDFSNP_HEADER  cdfsnp_header_t;
    CDFSNP_HEADER *cdfsnp_header;

    CBLOOM *cbloom;
    UINT32  max_nbits;
    UINT8  *data_area;

    RWSIZE rwsize;
    UINT32  offset;
    UINT32  cdfsnp_item_pos;

    int db_fd;

    cdfsnp_header = &cdfsnp_header_t;

    if(0 != access(dbname, F_OK))/*exist*/
    {
        sys_log(log, "error:cdfsnp_show: db %s not exist\n", dbname);
        return (EC_FALSE);
    }

    db_fd = c_file_open(dbname, O_RDWR, 0666);
    if(ERR_FD == db_fd)
    {
        sys_log(log, "error:cdfsnp_show: cannot open db %s\n", dbname);
        return (EC_FALSE);
    }

    /*load header*/
    if(ERR_SEEK == lseek(db_fd, 0, SEEK_SET))
    {
        sys_log(log, "error:cdfsnp_show: seek BEG failed\n");
        c_file_close(db_fd);
        return (EC_FALSE);
    }

    rwsize = sizeof(CDFSNP_HEADER);
    if(rwsize != read(db_fd, cdfsnp_header, rwsize))
    {
        sys_log(log, "error:cdfsnp_show: load header failed\n");
        c_file_close(db_fd);
        return (EC_FALSE);
    }

    sys_log(log, "header: ");
    cdfsnp_print_header(log, cdfsnp);
    sys_print(log, "\n");

    /*load bloom filter*/
    if(ERR_SEEK == lseek(db_fd, CDFSNP_HEADER_BMOFF(cdfsnp_header), SEEK_SET))
    {
        sys_log(log, "error:cdfsnp_show: seek boff failed\n");
        c_file_close(db_fd);
        return (EC_FALSE);
    }

    max_nbits = (CDFSNP_HEADER_BMROW(cdfsnp_header) * CDFSNP_HEADER_BMCOL(cdfsnp_header));
    data_area = (UINT8 *)SAFE_MALLOC(sizeof(UINT32) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(max_nbits)), LOC_CDFSNP_0055);
    if(NULL_PTR == data_area)
    {
        sys_log(log, "error:cdfsnp_show: alloc %ld bytes failed\n", NWORDS_TO_NBYTES(NBITS_TO_NWORDS(max_nbits)));
        c_file_close(db_fd);
        return (EC_FALSE);
    }

    rwsize = CDFSNP_HEADER_IOFF(cdfsnp_header) - CDFSNP_HEADER_BMOFF(cdfsnp_header);
    if(rwsize != read(db_fd, data_area, rwsize))
    {
        sys_log(log, "error:cdfsnp_show: load bloom failed where rwsize = %ld\n", rwsize);
        c_file_close(db_fd);
        SAFE_FREE(data_area, LOC_CDFSNP_0056);
        return (EC_FALSE);
    }

    cbloom = (CBLOOM *)data_area;

    sys_log(log, "bloom: ");
    cbloom_print(log, cbloom);

    SAFE_FREE(data_area, LOC_CDFSNP_0057);

    rwsize = sizeof(CDFSNP_ITEM);
    for(offset = CDFSNP_HEADER_IOFF(cdfsnp_header), cdfsnp_item_pos = 0;
        offset < CDFSNP_HEADER_EOFF(cdfsnp_header) && cdfsnp_item_pos < CDFSNP_HEADER_ICNUM(cdfsnp_header);
        offset += rwsize, cdfsnp_item_pos ++)
    {
        CDFSNP_ITEM    cdfsnp_item_t;
        CDFSNP_ITEM   *cdfsnp_item;

        cdfsnp_item = &cdfsnp_item_t;

        if(ERR_SEEK == lseek(db_fd, offset, SEEK_SET))
        {
            sys_log(log, "error:cdfsnp_show: seek item %ld# failed where offset = %ld\n", cdfsnp_item_pos, offset);
            c_file_close(db_fd);
            return (EC_FALSE);
        }

        if (rwsize != read(db_fd, cdfsnp_item, rwsize))
        {
            sys_log(log, "error:cdfsnp_show: load item %ld# failed\n", cdfsnp_item_pos);
            c_file_close(db_fd);
            return (EC_FALSE);
        }
        sys_log(log, "item %ld#, offset %ld: ", cdfsnp_item_pos, offset);
        cdfsnp_item_print(log, cdfsnp_item);
    }

    c_file_close(db_fd);
    return (EC_TRUE);

}

#endif
#ifdef __cplusplus
}
#endif/*__cplusplus*/

