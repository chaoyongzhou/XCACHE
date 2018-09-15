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
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "task.h"

#include "cmisc.h"
#include "real.h"

#include "db_internal.h"

#include "cpgrb.h"
#include "cpgb.h"
#include "cpgd.h"

/*page-cache disk:1TB = 2^14 page-cache block*/

/************************************************************************************************
  comment:
  ========
   1. if one block can assign max pages with page model, then put the block into page model
      RB tree of disk
   2. one block was in at most one RB tree
************************************************************************************************/

#if (SWITCH_ON == CRFS_ASSERT_SWITCH)
#define CPGD_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CRFS_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CRFS_ASSERT_SWITCH)
#define CPGD_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CRFS_ASSERT_SWITCH)*/

static CPGD_CFG g_cpgd_cfg_tbl[] = {
    {(const char *)"64M"  , (const char *)"CPGD_064MB_BLOCK_NUM", CPGD_064MB_BLOCK_NUM, 0, 0 },
    {(const char *)"128M" , (const char *)"CPGD_128MB_BLOCK_NUM", CPGD_128MB_BLOCK_NUM, 0, 0 },
    {(const char *)"256M" , (const char *)"CPGD_256MB_BLOCK_NUM", CPGD_256MB_BLOCK_NUM, 0, 0 },
    {(const char *)"512M" , (const char *)"CPGD_512MB_BLOCK_NUM", CPGD_512MB_BLOCK_NUM, 0, 0 },
    {(const char *)"1G"   , (const char *)"CPGD_001GB_BLOCK_NUM", CPGD_001GB_BLOCK_NUM, 0, 0 },
    {(const char *)"2G"   , (const char *)"CPGD_002GB_BLOCK_NUM", CPGD_002GB_BLOCK_NUM, 0, 0 },
    {(const char *)"4G"   , (const char *)"CPGD_004GB_BLOCK_NUM", CPGD_004GB_BLOCK_NUM, 0, 0 },
    {(const char *)"8G"   , (const char *)"CPGD_008GB_BLOCK_NUM", CPGD_008GB_BLOCK_NUM, 0, 0 },
    {(const char *)"16G"  , (const char *)"CPGD_016GB_BLOCK_NUM", CPGD_016GB_BLOCK_NUM, 0, 0 },
    {(const char *)"32G"  , (const char *)"CPGD_032GB_BLOCK_NUM", CPGD_032GB_BLOCK_NUM, 0, 0 },
    {(const char *)"64G"  , (const char *)"CPGD_064GB_BLOCK_NUM", CPGD_064GB_BLOCK_NUM, 0, 0 },
    {(const char *)"128G" , (const char *)"CPGD_128GB_BLOCK_NUM", CPGD_128GB_BLOCK_NUM, 0, 0 },
    {(const char *)"256G" , (const char *)"CPGD_256GB_BLOCK_NUM", CPGD_256GB_BLOCK_NUM, 0, 0 },
    {(const char *)"512G" , (const char *)"CPGD_512GB_BLOCK_NUM", CPGD_512GB_BLOCK_NUM, 0, 0 },
    {(const char *)"1T"   , (const char *)"CPGD_001TB_BLOCK_NUM", CPGD_001TB_BLOCK_NUM, 0, 0 },
};

static uint8_t g_cpgd_cfg_tbl_len = (uint8_t)(sizeof(g_cpgd_cfg_tbl)/sizeof(g_cpgd_cfg_tbl[0]));

const char *cpgd_model_str(const uint16_t pgd_block_num)
{
    uint8_t cpgd_model;

    for(cpgd_model = 0; cpgd_model < g_cpgd_cfg_tbl_len; cpgd_model ++)
    {
        CPGD_CFG *cpgd_cfg;

        cpgd_cfg = &(g_cpgd_cfg_tbl[ cpgd_model ]);
        if(pgd_block_num == CPGD_CFG_BLOCK_NUM(cpgd_cfg))
        {
            return CPGD_CFG_MODEL_STR(cpgd_cfg);
        }
    }

    return (const char *)"unkown";
}

uint16_t cpgd_model_get(const char *model_str)
{
    uint8_t cpgd_model;

    for(cpgd_model = 0; cpgd_model < g_cpgd_cfg_tbl_len; cpgd_model ++)
    {
        CPGD_CFG *cpgd_cfg;
        cpgd_cfg = &(g_cpgd_cfg_tbl[ cpgd_model ]);

        if(0 == strcasecmp(CPGD_CFG_MODEL_STR(cpgd_cfg), model_str))
        {
            return CPGD_CFG_BLOCK_NUM(cpgd_cfg);
        }
    }
    return (CPGD_ERROR_BLOCK_NUM);
}

STATIC_CAST static uint16_t __cpgd_page_model_first_block(const CPGD *cpgd, const uint16_t page_model)
{
    uint16_t node_pos;
    const CPGRB_NODE *node;

    node_pos = cpgrb_tree_first_node(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd), CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model));
    if(CPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:__cpgd_page_model_first_block: no free page in page model %u\n", page_model);
        return (CPGRB_ERR_POS);
    }

    node = CPGRB_POOL_NODE(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd), node_pos);
    return (CPGRB_NODE_DATA(node));
}

STATIC_CAST static uint16_t __cpgd_page_model_get(const CPGD *cpgd, const uint16_t assign_bitmap)
{
    uint16_t page_model;
    uint16_t e;

    for(page_model = 0, e = 1; CPGB_MODEL_NUM > page_model && 0 == (assign_bitmap & e); page_model ++, e <<= 1)
    {
      /*do nothing*/
    }
    return (page_model);
}

STATIC_CAST static CPGB *__cpgd_block(CPGD *cpgd, const uint16_t  block_no)
{
    return (CPGB *)(((void *)CPGD_HEADER(cpgd)) + CPGD_HDR_SIZE + block_no * CPGB_SIZE);
}


CPGD_HDR *cpgd_hdr_mem_new(CPGD *cpgd, const uint16_t block_num)
{
    CPGD_HDR *cpgd_hdr;
    uint16_t  page_model;

    cpgd_hdr = safe_malloc(CPGD_FSIZE(cpgd), LOC_CPGD_0001);
    if(NULL_PTR == cpgd_hdr)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_mem_new: malloc %u bytes failed\n",
                           CPGD_FSIZE(cpgd));
        return (NULL_PTR);
    }

    if(EC_FALSE == cpgrb_pool_init(CPGD_HDR_CPGRB_POOL(cpgd_hdr), block_num))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_hdr_mem_new: init cpgrb pool failed where block_num = %u\n", block_num);
        safe_free(cpgd_hdr, LOC_CPGD_0002);
        return (NULL_PTR);
    }

    for(page_model = 0; CPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CPGD_HDR_BLOCK_CPGRB_ROOT_POS(cpgd_hdr, page_model) = CPGRB_ERR_POS;
    }

    CPGD_HDR_ASSIGN_BITMAP(cpgd_hdr) = 0;

    CPGD_HDR_PAGE_BLOCK_MAX_NUM(cpgd_hdr) = block_num;

    /*statistics*/
    CPGD_HDR_PAGE_MAX_NUM(cpgd_hdr)          = block_num * CPGD_BLOCK_PAGE_NUM;
    CPGD_HDR_PAGE_USED_NUM(cpgd_hdr)         = 0;
    CPGD_HDR_PAGE_ACTUAL_USED_SIZE(cpgd_hdr) = 0;

    return (cpgd_hdr);
}

EC_BOOL cpgd_hdr_mem_free(CPGD *cpgd)
{
    if(NULL_PTR != CPGD_HEADER(cpgd))
    {
        safe_free(CPGD_HEADER(cpgd), LOC_CPGD_0003);
        CPGD_HEADER(cpgd) = NULL_PTR;
    }

    return (EC_TRUE);
}

CPGD_HDR *cpgd_hdr_new(CPGD *cpgd, const uint16_t block_num)
{
    void *address;
    UINT32 align;

    CPGD_HDR *cpgd_hdr;
    uint16_t  page_model;

    /*align address to 1MB*/
    align = ((UINT32)(UINT32_ONE << 20));

    address = c_mmap_aligned_addr(CPGD_FSIZE(cpgd), align);
    if(NULL_PTR == address)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_new: fetch mmap aligned addr of file %s with fd %d fsize %ld align %ld failed\n",
                           (char *)CPGD_FNAME(cpgd), CPGD_FD(cpgd), CPGD_FSIZE(cpgd), align);
        return (NULL_PTR);
    }

    cpgd_hdr = (CPGD_HDR *)mmap(address, CPGD_FSIZE(cpgd), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, CPGD_FD(cpgd), 0);
    if(MAP_FAILED == cpgd_hdr)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_new: mmap file %s failed, errno = %d, errstr = %s\n",
                           (char *)CPGD_FNAME(cpgd), errno, strerror(errno));
        return (NULL_PTR);
    }

    if(EC_FALSE == cpgrb_pool_init(CPGD_HDR_CPGRB_POOL(cpgd_hdr), block_num))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_hdr_new: init cpgrb pool failed where block_num = %u\n", block_num);
        munmap(cpgd_hdr, CPGD_FSIZE(cpgd));
        return (NULL_PTR);
    }

    for(page_model = 0; CPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CPGD_HDR_BLOCK_CPGRB_ROOT_POS(cpgd_hdr, page_model) = CPGRB_ERR_POS;
    }

    CPGD_HDR_ASSIGN_BITMAP(cpgd_hdr) = 0;

    CPGD_HDR_PAGE_BLOCK_MAX_NUM(cpgd_hdr) = block_num;

    /*statistics*/
    CPGD_HDR_PAGE_MAX_NUM(cpgd_hdr)          = block_num * CPGD_BLOCK_PAGE_NUM;
    CPGD_HDR_PAGE_USED_NUM(cpgd_hdr)         = 0;
    CPGD_HDR_PAGE_ACTUAL_USED_SIZE(cpgd_hdr) = 0;

    return (cpgd_hdr);
}

EC_BOOL cpgd_hdr_free(CPGD *cpgd)
{
    if(NULL_PTR != CPGD_HEADER(cpgd))
    {
        if(0 != msync(CPGD_HEADER(cpgd), CPGD_FSIZE(cpgd), MS_SYNC))
        {
            dbg_log(SEC_0041_CPGD, 1)(LOGSTDOUT, "warn:cpgd_hdr_free: sync cpgd_hdr of %s with size %u failed\n",
                               CPGD_FNAME(cpgd), CPGD_FSIZE(cpgd));
        }

        if(0 != munmap(CPGD_HEADER(cpgd), CPGD_FSIZE(cpgd)))
        {
            dbg_log(SEC_0041_CPGD, 1)(LOGSTDOUT, "warn:cpgd_hdr_free: munmap cpgd of %s with size %u failed\n",
                               CPGD_FNAME(cpgd), CPGD_FSIZE(cpgd));
        }

        CPGD_HEADER(cpgd) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static CPGD_HDR *__cpgd_hdr_open(CPGD *cpgd)
{
    void *address;
    UINT32 align;

    CPGD_HDR *cpgd_hdr;

    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] __cpgd_hdr_open: fsize %u\n", CPGD_FSIZE(cpgd));

    /*align address to 1MB*/
    align = ((UINT32)(UINT32_ONE << 20));

    address = c_mmap_aligned_addr(CPGD_FSIZE(cpgd), align);
    if(NULL_PTR == address)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:__cpgd_hdr_open: fetch mmap aligned addr of file %s with fd %d fsize %ld align %ld failed\n",
                           (char *)CPGD_FNAME(cpgd), CPGD_FD(cpgd), CPGD_FSIZE(cpgd), align);
        return (NULL_PTR);
    }

    cpgd_hdr = (CPGD_HDR *)mmap(address, CPGD_FSIZE(cpgd), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, CPGD_FD(cpgd), 0);
    if(MAP_FAILED == cpgd_hdr)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:__cpgd_hdr_open: mmap file %s with fd %d failed, errno = %d, errstr = %s\n",
                           (char *)CPGD_FNAME(cpgd), CPGD_FD(cpgd), errno, strerror(errno));
        return (NULL_PTR);
    }

    return (cpgd_hdr);
}

STATIC_CAST static EC_BOOL __cpgd_hdr_close(CPGD *cpgd)
{
    if(NULL_PTR != CPGD_HEADER(cpgd))
    {
        if(0 != msync(CPGD_HEADER(cpgd), CPGD_FSIZE(cpgd), MS_SYNC))
        {
            dbg_log(SEC_0041_CPGD, 1)(LOGSTDOUT, "warn:__cpgd_hdr_close: sync cpgd_hdr of %s with size %u failed\n",
                               CPGD_FNAME(cpgd), CPGD_FSIZE(cpgd));
        }

        if(0 != munmap(CPGD_HEADER(cpgd), CPGD_FSIZE(cpgd)))
        {
            dbg_log(SEC_0041_CPGD, 1)(LOGSTDOUT, "warn:__cpgd_hdr_close: munmap cpgd of %s with size %u failed\n",
                               CPGD_FNAME(cpgd), CPGD_FSIZE(cpgd));
        }

        CPGD_HEADER(cpgd) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cpgd_hdr_sync(CPGD *cpgd)
{
    if(NULL_PTR != CPGD_HEADER(cpgd))
    {
        if(0 != msync(CPGD_HEADER(cpgd), CPGD_FSIZE(cpgd), MS_SYNC))
        {
            dbg_log(SEC_0041_CPGD, 1)(LOGSTDOUT, "warn:__cpgd_hdr_sync: sync cpgd_hdr of %s with size %u failed\n",
                               CPGD_FNAME(cpgd), CPGD_FSIZE(cpgd));
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static CPGD_HDR *__cpgd_hdr_load(CPGD *cpgd)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(CPGD_FSIZE(cpgd), LOC_CPGD_0004);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:__cpgd_hdr_load: malloc %u bytes failed for fd %d\n", CPGD_FSIZE(cpgd), CPGD_FD(cpgd));
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(CPGD_FD(cpgd), &offset, CPGD_FSIZE(cpgd), buff))
    {
        safe_free(buff, LOC_CPGD_0005);
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:__cpgd_hdr_load: load %u bytes failed for fd %d\n", CPGD_FSIZE(cpgd), CPGD_FD(cpgd));
        return (NULL_PTR);
    }

    return ((CPGD_HDR *)buff);
}


STATIC_CAST static EC_BOOL __cpgd_hdr_free(CPGD *cpgd)
{
    if(NULL_PTR != CPGD_HEADER(cpgd))
    {
        UINT32 offset;

        offset = 0;
        if(EC_FALSE == c_file_flush(CPGD_FD(cpgd), &offset, CPGD_FSIZE(cpgd), (const UINT8 *)CPGD_HEADER(cpgd)))
        {
            dbg_log(SEC_0041_CPGD, 1)(LOGSTDOUT, "warn:__cpgd_hdr_free: flush cpgd_hdr to fd %d with size %u failed\n",
                               CPGD_FD(cpgd), CPGD_FSIZE(cpgd));

            safe_free(CPGD_HEADER(cpgd), LOC_CPGD_0006);
            CPGD_HEADER(cpgd) = NULL_PTR;
            return (EC_FALSE);
        }

        safe_free(CPGD_HEADER(cpgd), LOC_CPGD_0007);
        CPGD_HEADER(cpgd) = NULL_PTR;
    }

    /*cpgv_hdr cannot be accessed again*/
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cpgd_hdr_flush(CPGD *cpgd)
{
    if(NULL_PTR != CPGD_HEADER(cpgd))
    {
        UINT32 offset;

        offset = 0;
        if(EC_FALSE == c_file_flush(CPGD_FD(cpgd), &offset, CPGD_FSIZE(cpgd), (const UINT8 *)CPGD_HEADER(cpgd)))
        {
            dbg_log(SEC_0041_CPGD, 1)(LOGSTDOUT, "warn:__cpgd_hdr_flush: flush cpgd_hdr to fd %d with size %u failed\n",
                        CPGD_FD(cpgd), CPGD_FSIZE(cpgd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

CPGD_HDR *cpgd_hdr_open(CPGD *cpgd)
{
    if(SWITCH_ON == CRFSDN_CACHE_IN_MEM_SWITCH)
    {
        return __cpgd_hdr_load(cpgd);
    }

    return __cpgd_hdr_open(cpgd);
}

EC_BOOL cpgd_hdr_close(CPGD *cpgd)
{
    if(SWITCH_ON == CRFSDN_CACHE_IN_MEM_SWITCH)
    {
        return __cpgd_hdr_free(cpgd);
    }
    return __cpgd_hdr_close(cpgd);
}

EC_BOOL cpgd_hdr_sync(CPGD *cpgd)
{
    if(SWITCH_ON == CRFSDN_CACHE_IN_MEM_SWITCH)
    {
        return __cpgd_hdr_flush(cpgd);
    }

    return __cpgd_hdr_sync(cpgd);
}

EC_BOOL cpgd_hdr_flush_size(const CPGD_HDR *cpgd_hdr, UINT32 *size)
{
    (*size) += CPGD_HDR_SIZE;
    return (EC_TRUE);
}

EC_BOOL cpgd_hdr_flush(const CPGD_HDR *cpgd_hdr, int fd, UINT32 *offset)
{
    UINT32 osize;/*flush once size*/

    /*flush CPGD_HDR_ASSIGN_BITMAP*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGD_HDR_ASSIGN_BITMAP(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: flush CPGD_HDR_ASSIGN_BITMAP at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGD_HDR_PAGE_BLOCK_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_BLOCK_MAX_NUM(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: flush CPGD_HDR_PAGE_BLOCK_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd1*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: pad %ld bytes at offset %ld of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGD_HDR_PAGE_MAX_NUM*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_MAX_NUM(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: flush CPGD_HDR_PAGE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGD_HDR_PAGE_USED_NUM*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_USED_NUM(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: flush CPGD_HDR_PAGE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGD_HDR_PAGE_ACTUAL_USED_SIZE*/
    osize = sizeof(uint64_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_ACTUAL_USED_SIZE(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: flush CPGD_HDR_PAGE_ACTUAL_USED_SIZE at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS_TBL*/
    osize = CPGB_MODEL_MAX_NUM * sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)CPGD_HDR_BLOCK_CPGRB_ROOT_POS_TBL(cpgd_hdr)))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: flush CPGD_HDR_BLOCK_CPGRB_ROOT_POS_TBL at offset %ld of fd %d failed\n",
                            (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd2*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: pad %ld bytes at offset %ld of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rbtree pool*/
    if(EC_FALSE == cpgrb_flush(CPGD_HDR_CPGRB_POOL(cpgd_hdr), fd, offset))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_flush: flush CPGD_HDR_CPGRB_POOL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cpgd_hdr_load(CPGD_HDR *cpgd_hdr, int fd, UINT32 *offset)
{
    UINT32 osize;/*load once size*/

    /*load CPGD_HDR_ASSIGN_BITMAP*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGD_HDR_ASSIGN_BITMAP(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_load: load CPGD_HDR_ASSIGN_BITMAP at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGD_HDR_PAGE_BLOCK_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_BLOCK_MAX_NUM(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_load: load CPGD_HDR_PAGE_BLOCK_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd1*/
    (*offset) += sizeof(uint32_t);

    /*load CPGD_HDR_PAGE_MAX_NUM*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_MAX_NUM(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_load: load CPGD_HDR_PAGE_MAX_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGD_HDR_PAGE_USED_NUM*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_USED_NUM(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_load: load CPGD_HDR_PAGE_USED_NUM at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGD_HDR_PAGE_ACTUAL_USED_SIZE*/
    osize = sizeof(uint64_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CPGD_HDR_PAGE_ACTUAL_USED_SIZE(cpgd_hdr))))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_load: load CPGD_HDR_PAGE_ACTUAL_USED_SIZE at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGD_HDR_BLOCK_CPGRB_ROOT_POS_TBL*/
    osize = CPGB_MODEL_MAX_NUM * sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)CPGD_HDR_BLOCK_CPGRB_ROOT_POS_TBL(cpgd_hdr)))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_load: load CPGD_HDR_BLOCK_CPGRB_ROOT_POS_TBL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd2*/
    (*offset) += sizeof(uint16_t);

    /*load rbtree pool*/
    if(EC_FALSE == cpgrb_load(CPGD_HDR_CPGRB_POOL(cpgd_hdr), fd, offset))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_hdr_load: load CPGD_HDR_CPGRB_POOL at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CPGD *cpgd_new(const uint8_t *cpgd_fname, const uint16_t block_num)
{
    CPGD      *cpgd;
    uint16_t   block_no;

    if(CPGD_MAX_BLOCK_NUM < block_num)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_new: block_num %u overflow\n", block_num);
        return (NULL_PTR);
    }

    if(EC_TRUE == c_file_access((const char *)cpgd_fname, F_OK))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_new: %s already exist\n", cpgd_fname);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CPGD, &cpgd, LOC_CPGD_0008);
    if(NULL_PTR == cpgd)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_new:malloc cpgd failed\n");
        return (NULL_PTR);
    }

    cpgd_init(cpgd);

    CPGD_FNAME(cpgd) = (uint8_t *)c_str_dup((char *)cpgd_fname);
    if(NULL_PTR == CPGD_FNAME(cpgd))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_new:str dup %s failed\n", cpgd_fname);
        cpgd_free(cpgd);
        return (NULL_PTR);
    }

    CPGD_FD(cpgd) = c_file_open((const char *)cpgd_fname, O_RDWR | O_SYNC | O_CREAT, 0666);
    if(ERR_FD == CPGD_FD(cpgd))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_new: create %s failed\n", cpgd_fname);
        cpgd_free(cpgd);
        return (NULL_PTR);
    }

    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new: CPGD_HDR_SIZE %ld, block_num %u, CPGB_SIZE %ld, sizeof(off_t) = %ld\n",
                        CPGD_HDR_SIZE, block_num, CPGB_SIZE, sizeof(off_t));

    CPGD_FSIZE(cpgd) = CPGD_HDR_SIZE + block_num * CPGB_SIZE;
    if(EC_FALSE == c_file_truncate(CPGD_FD(cpgd), CPGD_FSIZE(cpgd)))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_new: truncate %s to %u bytes failed\n", cpgd_fname, CPGD_FSIZE(cpgd));
        cpgd_free(cpgd);
        return (NULL_PTR);
    }

    CPGD_HEADER(cpgd) = cpgd_hdr_new(cpgd, block_num);
    if(NULL_PTR == CPGD_HEADER(cpgd))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_new: new cpgd header of file %s failed\n", cpgd_fname);
        cpgd_free(cpgd);
        return (NULL_PTR);
    }

    /*init blocks*/
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CPGD_BLOCK_CPGB(cpgd, block_no) = __cpgd_block(cpgd, block_no);
        cpgb_init(CPGD_BLOCK_CPGB(cpgd, block_no), CPGD_BLOCK_PAGE_MODEL);
        cpgd_add_block(cpgd, block_no, CPGD_BLOCK_PAGE_MODEL);

        if(0 == ((block_no + 1) % 1000))
        {
            dbg_log(SEC_0041_CPGD, 3)(LOGSTDOUT, "info:cpgd_new: init block %u - %u of file %s done\n", block_no - 999, block_no, cpgd_fname);
        }
    }
    dbg_log(SEC_0041_CPGD, 3)(LOGSTDOUT, "info:cpgd_new: init %u blocks of file %s done\n", block_num, cpgd_fname);

    return (cpgd);
}

EC_BOOL cpgd_free(CPGD *cpgd)
{
    if(NULL_PTR != cpgd)
    {
        UINT32 block_num;
        UINT32 block_no;

        /*clean blocks*/
        block_num = CPGD_PAGE_BLOCK_MAX_NUM(cpgd);
        for(block_no = 0; block_no < block_num; block_no ++)
        {
            CPGD_BLOCK_CPGB(cpgd, block_no) = NULL_PTR;
        }

        cpgd_hdr_free(cpgd);

        if(ERR_FD != CPGD_FD(cpgd))
        {
            c_file_close(CPGD_FD(cpgd));
            CPGD_FD(cpgd) = ERR_FD;
        }

        if(NULL_PTR != CPGD_FNAME(cpgd))
        {
            safe_free(CPGD_FNAME(cpgd), LOC_CPGD_0009);
            CPGD_FNAME(cpgd) = NULL_PTR;
        }

        free_static_mem(MM_CPGD, cpgd, LOC_CPGD_0010);
    }

    return (EC_TRUE);
}

EC_BOOL cpgd_exist(const uint8_t *cpgd_fname)
{
    return c_file_access((const char *)cpgd_fname, F_OK);
}

EC_BOOL cpgd_rmv(const uint8_t *cpgd_fname)
{
    return c_file_unlink((const char *)cpgd_fname);
}

CPGD *cpgd_open(const uint8_t *cpgd_fname)
{
    CPGD      *cpgd;

    uint16_t  block_num;
    uint16_t  block_no;

    UINT32    fsize;

    alloc_static_mem(MM_CPGD, &cpgd, LOC_CPGD_0011);
    if(NULL_PTR == cpgd)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_open:malloc cpgd failed\n");
        return (NULL_PTR);
    }

    cpgd_init(cpgd);

    CPGD_FNAME(cpgd) = (uint8_t *)c_str_dup((const char *)cpgd_fname);
    if(NULL_PTR == CPGD_FNAME(cpgd))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_open:str dup %s failed\n", cpgd_fname);
        cpgd_close(cpgd);
        return (NULL_PTR);
    }

    CPGD_FD(cpgd) = c_file_open((const char *)cpgd_fname, O_RDWR | O_SYNC , 0666);
    if(ERR_FD == CPGD_FD(cpgd))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_open: open %s failed\n", cpgd_fname);
        cpgd_close(cpgd);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_size(CPGD_FD(cpgd), &fsize))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_open: get size of %s failed\n", cpgd_fname);
        cpgd_close(cpgd);
        return (NULL_PTR);
    }
    CPGD_FSIZE(cpgd) = (uint32_t)fsize;

    CPGD_HEADER(cpgd) = cpgd_hdr_open(cpgd);
    if(NULL_PTR == CPGD_HEADER(cpgd))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_open: open cpgd header of file %s failed\n", cpgd_fname);
        cpgd_close(cpgd);
        return (NULL_PTR);
    }

    /*init blocks*/
    block_num = CPGD_PAGE_BLOCK_MAX_NUM(cpgd);
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CPGD_BLOCK_CPGB(cpgd, block_no) = __cpgd_block(cpgd, block_no);
    }

    return (cpgd);
}

EC_BOOL cpgd_close(CPGD *cpgd)
{
    if(NULL_PTR != cpgd)
    {
        UINT32 block_num;
        UINT32 block_no;

        /*clean blocks*/
        if(NULL_PTR != CPGD_HEADER(cpgd))
        {
            block_num = CPGD_PAGE_BLOCK_MAX_NUM(cpgd);
            for(block_no = 0; block_no < block_num; block_no ++)
            {
                CPGD_BLOCK_CPGB(cpgd, block_no) = NULL_PTR;
            }
        }

        cpgd_hdr_close(cpgd);

        if(ERR_FD != CPGD_FD(cpgd))
        {
            c_file_close(CPGD_FD(cpgd));
            CPGD_FD(cpgd) = ERR_FD;
        }

        if(NULL_PTR != CPGD_FNAME(cpgd))
        {
            safe_free(CPGD_FNAME(cpgd), LOC_CPGD_0012);
            CPGD_FNAME(cpgd) = NULL_PTR;
        }

        free_static_mem(MM_CPGD, cpgd, LOC_CPGD_0013);
    }
    return (EC_TRUE);
}

EC_BOOL cpgd_sync(CPGD *cpgd)
{
    if(NULL_PTR != cpgd)
    {
        cpgd_hdr_sync(cpgd);
    }
    return (EC_TRUE);
}

/* one disk = 1TB */
EC_BOOL cpgd_init(CPGD *cpgd)
{
    uint16_t block_no;

    CPGD_FD(cpgd)    = ERR_FD;
    CPGD_FNAME(cpgd) = NULL_PTR;
    CPGD_FSIZE(cpgd) = 0;
    CPGD_HEADER(cpgd)= NULL_PTR;

    for(block_no = 0; block_no < CPGD_MAX_BLOCK_NUM; block_no ++)
    {
        CPGD_BLOCK_CPGB(cpgd, block_no) = NULL_PTR;
    }
    return (EC_TRUE);
}

/*note: cpgd_clean is for not applying mmap*/
void cpgd_clean(CPGD *cpgd)
{
    uint16_t page_model;
    uint16_t block_no;

    if(ERR_FD != CPGD_FD(cpgd))
    {
        c_file_close(CPGD_FD(cpgd));
        CPGD_FD(cpgd) = ERR_FD;
    }

    if(NULL_PTR != CPGD_FNAME(cpgd))
    {
        safe_free(CPGD_FNAME(cpgd), LOC_CPGD_0014);
        CPGD_FNAME(cpgd) = NULL_PTR;
    }

    if(NULL_PTR == CPGD_HEADER(cpgd))
    {
        return;
    }

    cpgrb_pool_clean(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd));

    for(page_model = 0; CPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model) = CPGRB_ERR_POS;
    }

    for(block_no = 0; block_no < CPGD_PAGE_BLOCK_MAX_NUM(cpgd); block_no ++)
    {
        if(NULL_PTR != CPGD_BLOCK_CPGB(cpgd, block_no))
        {
            safe_free(CPGD_BLOCK_CPGB(cpgd, block_no), LOC_CPGD_0015);
            CPGD_BLOCK_CPGB(cpgd, block_no) = NULL_PTR;
        }
    }
    CPGD_PAGE_BLOCK_MAX_NUM(cpgd)           = 0;

    CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd)     = 0;
    CPGD_PAGE_MAX_NUM(cpgd)                 = 0;
    CPGD_PAGE_USED_NUM(cpgd)                = 0;
    CPGD_PAGE_ACTUAL_USED_SIZE(cpgd)        = 0;

    safe_free(CPGD_HEADER(cpgd), LOC_CPGD_0016);
    CPGD_HEADER(cpgd) = NULL_PTR;

    return;
}

/*add one free block into pool*/
EC_BOOL cpgd_add_block(CPGD *cpgd, const uint16_t block_no, const uint16_t page_model)
{
    if(CPGD_PAGE_BLOCK_MAX_NUM(cpgd) <= block_no)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_add_block: block_no %u overflow where block max num is %u\n", block_no, CPGD_PAGE_BLOCK_MAX_NUM(cpgd));
        return (EC_FALSE);
    }

    /*insert block_no to rbtree*/
    if(CPGRB_ERR_POS == cpgrb_tree_insert_data(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd), &(CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model)), block_no))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_add_block: add block_no %u to rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd) |= (uint16_t)(~((1 << page_model) - 1)) & CPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free block from pool*/
EC_BOOL cpgd_del_block(CPGD *cpgd, const uint16_t block_no, const uint16_t page_model)
{
    /*del block_no from rbtree*/
    if(CPGRB_ERR_POS == cpgrb_tree_delete_data(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd), &(CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model)), block_no))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_del_block: del block_no %u from rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cpgrb_tree_is_empty(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd), CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model_t))/*this page-model is empty*/
        )
        {
            CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cpgd_assign_block(CPGD *cpgd, uint16_t *page_model, uint16_t *block_no)
{
    uint16_t block_no_t;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd) & mask))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:__cpgd_assign_block: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd), mask);
        return (EC_FALSE);
    }

    while(CPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cpgrb_tree_is_empty(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd), CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:__cpgd_assign_block: no free block available from page model %u\n", *page_model);
        return (EC_FALSE);
    }

    block_no_t = __cpgd_page_model_first_block(cpgd, page_model_t);
    if(CPGRB_ERR_POS == block_no_t)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:__cpgd_assign_block: no free block in page model %u\n", page_model_t);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;
    (*block_no)   = block_no_t;

    return (EC_TRUE);
}

EC_BOOL cpgd_new_space(CPGD *cpgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no)
{
    CPGB    *cpgb;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t e;
    uint16_t t;
    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t block_no_t;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CPGD_ASSERT(0 < size);

    if(CPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CPGB_PAGE_BYTE_SIZE - 1) >> CPGB_PAGE_BIT_SIZE);
    //dbg_log(SEC_0041_CPGD, 9)(LOGSTDNULL, "[DEBUG] cpgd_new_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CPGD_ASSERT(CPGB_064MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    //dbg_log(SEC_0041_CPGD, 9)(LOGSTDNULL, "[DEBUG] cpgd_new_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    //dbg_log(SEC_0041_CPGD, 9)(LOGSTDNULL, "[DEBUG] cpgd_new_space: page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   page_num_need, page_model, (uint16_t)(1 << (CPGB_MODEL_NUM - 1 - page_model)));

    for(;;)/*Oops! fix inconsistency between cpgd and cpgb*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;

        if(EC_FALSE == __cpgd_assign_block(cpgd, &page_model_t, &block_no_t))
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_new_space: assign one block from page model %u failed\n", page_model_t);
            return (EC_FALSE);
        }

        cpgb = CPGD_BLOCK_NODE(cpgd, block_no_t);
        pgb_assign_bitmap_old = CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb);

        if(EC_TRUE == cpgb_new_space(cpgb, size, &page_no_t))
        {
            page_model = page_model_t; /*re-init page_model*/
            break;
        }

        /*find inconsistent, fix it!*/
        cpgd_del_block(cpgd, block_no_t, page_model_t);

        while(CPGB_MODEL_NUM > page_model_t
           && 0 == (pgb_assign_bitmap_old & (uint16_t)(1 << page_model_t))
           )
        {
             page_model_t ++;
        }
        CPGD_ASSERT(CPGB_MODEL_NUM > page_model_t);
        cpgd_add_block(cpgd, block_no_t, page_model_t);

        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "warn:cpgd_new_space: block %u relocation to page model %u\n", block_no_t, page_model_t);
    }

    pgb_assign_bitmap_new = CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb);

    //dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new_space: block_no_t %u: pgb bitmap %x => %x\n", block_no_t, pgb_assign_bitmap_old, pgb_assign_bitmap_new);

    /*pgb_assign_bitmap changes may make pgd_assign_bitmap changes*/
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        //dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new_space: before delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb)),
        //                    c_uint16_t_to_bin_str(CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd)));

        cpgd_del_block(cpgd, block_no_t, page_model);

        //dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new_space: after  delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb)),
        //                    c_uint16_t_to_bin_str(CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd)));

        if(EC_FALSE == cpgb_is_full(cpgb))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CPGB_MODEL_NUM > page_model_t
               && 0 == (pgb_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }
            CPGD_ASSERT(CPGB_MODEL_NUM > page_model_t);
            //dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            cpgd_add_block(cpgd, block_no_t, page_model_t);
            //dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new_space: block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
            //                    block_no_t,
            //                    c_uint16_t_to_bin_str(CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb)),
            //                    c_uint16_t_to_bin_str(CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CPGD_PAGE_USED_NUM(cpgd)         += page_num_need;
    CPGD_PAGE_ACTUAL_USED_SIZE(cpgd) += size;

    CPGD_ASSERT(EC_TRUE == cpgd_check(cpgd));

    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new_space: pgd_page_used_num %u due to increment %u\n",
                        CPGD_PAGE_USED_NUM(cpgd), page_num_need);
    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_new_space: pgd_actual_used_size %"PRId64" due to increment %u\n",
                        CPGD_PAGE_ACTUAL_USED_SIZE(cpgd), size);

    return (EC_TRUE);
}

EC_BOOL cpgd_free_space(CPGD *cpgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    CPGB    *cpgb;

    uint16_t page_num_used;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CPGD_ASSERT(0 < size);

    if(CPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    cpgb = CPGD_BLOCK_NODE(cpgd, block_no);
    pgb_assign_bitmap_old = CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb);

    if(EC_FALSE == cpgb_free_space(cpgb, page_no, size))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_free_space: block_no %u free space of page_no %u, size %u failed\n",
                           block_no, page_no, size);
        return (EC_FALSE);
    }

    pgb_assign_bitmap_new = CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb);
#if 0
    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_free_space: cpgd %p, block %u, asssign bitmap %s -> %s\n",
                       cpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_old),
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_new));
#endif
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        uint16_t page_model_old;
        uint16_t page_model_new;

        page_model_old = __cpgd_page_model_get(cpgd, pgb_assign_bitmap_old);
        page_model_new = __cpgd_page_model_get(cpgd, pgb_assign_bitmap_new);
#if 0
        dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_free_space: cpgd %p, block %u, old asssign bitmap %s = page model %u\n",
                       cpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_old), page_model_old);

        dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_free_space: cpgd %p, block %u, new asssign bitmap %s = page model %u\n",
                       cpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_new), page_model_new);
#endif
        if(CPGB_MODEL_NUM > page_model_old)
        {
            cpgd_del_block(cpgd, block_no, page_model_old);
        }

        if(EC_FALSE == cpgd_add_block(cpgd, block_no, page_model_new))
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_free_space: add block %d, page_model_new %u failed, fix it!\n",
                                block_no, page_model_new);
            abort();
        }
    }

    page_num_used = (uint16_t)((size + CPGB_PAGE_BYTE_SIZE - 1) >> CPGB_PAGE_BIT_SIZE);

    CPGD_PAGE_USED_NUM(cpgd)         -= page_num_used;
    CPGD_PAGE_ACTUAL_USED_SIZE(cpgd) -= size;

    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_free_space: pgd_page_used_num %u due to decrement %u\n",
                        CPGD_PAGE_USED_NUM(cpgd), page_num_used);
    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_free_space: pgd_actual_used_size %"PRId64" due to decrement %u\n",
                        CPGD_PAGE_ACTUAL_USED_SIZE(cpgd), size);

    return (EC_TRUE);
}

EC_BOOL cpgd_is_full(const CPGD *cpgd)
{
    if(CPGD_PAGE_USED_NUM(cpgd) == CPGD_PAGE_MAX_NUM(cpgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cpgd_is_empty(const CPGD *cpgd)
{
    if(0 == CPGD_PAGE_USED_NUM(cpgd) && 0 < CPGD_PAGE_MAX_NUM(cpgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*compute cpgd current page model support up to*/
uint16_t cpgd_page_model(const CPGD *cpgd)
{
    uint16_t page_model;
    uint16_t pgd_assign_bitmap;
    uint16_t e;

    pgd_assign_bitmap = CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd);
    for(page_model = 0, e = 1; CPGB_MODEL_NUM > page_model && 0 == (pgd_assign_bitmap & e); e <<= 1, page_model ++)
    {
        /*do nothing*/
    }

    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_page_model: cpgd %p: assign bitmap %s ==> page_model %u\n",
                       cpgd, c_uint16_t_to_bin_str(pgd_assign_bitmap), page_model);

    return (page_model);
}

EC_BOOL cpgd_flush_size(const CPGD *cpgd, UINT32 *size)
{
    uint16_t block_no;

    cpgd_hdr_flush_size(CPGD_HEADER(cpgd), size);

    for(block_no = 0; block_no < CPGD_PAGE_BLOCK_MAX_NUM(cpgd); block_no ++)
    {
        cpgb_flush_size(CPGD_BLOCK_NODE(cpgd, block_no), size);
    }
    return (EC_TRUE);
}

EC_BOOL cpgd_flush(const CPGD *cpgd, int fd, UINT32 *offset)
{
    uint16_t block_no;

    /*flush CPGD_HEADER*/
    if(EC_FALSE == cpgd_hdr_flush(CPGD_HEADER(cpgd), fd, offset))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_flush: flush CPGD_HEADER at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CPGD_BLOCK_NODE table*/
    for(block_no = 0; block_no < CPGD_PAGE_BLOCK_MAX_NUM(cpgd); block_no ++)
    {
        if(EC_FALSE == cpgb_flush(CPGD_BLOCK_NODE(cpgd, block_no), fd, offset))
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_flush: flush CPGD_BLOCK_NODE of block_no %u at offset %ld of fd %d failed\n",
                                block_no, (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cpgd_load(CPGD *cpgd, int fd, UINT32 *offset)
{
    uint16_t block_no;

    if(NULL_PTR == CPGD_HEADER(cpgd))
    {
        CPGD_HEADER(cpgd) = safe_malloc(CPGD_HDR_SIZE, LOC_CPGD_0017);
        if(NULL_PTR == CPGD_HEADER(cpgd))
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_load: malloc CPGD_HDR failed\n");
            return (EC_FALSE);
        }
    }

    /*load rbtree pool*/
    if(EC_FALSE == cpgd_hdr_load(CPGD_HEADER(cpgd), fd, offset))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_load: load CPGD_HEADER at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load CPGD_BLOCK_NODE table*/
    for(block_no = 0; block_no < CPGD_PAGE_BLOCK_MAX_NUM(cpgd); block_no ++)
    {
        if(NULL_PTR == CPGD_BLOCK_NODE(cpgd, block_no))
        {
            CPGD_BLOCK_CPGB(cpgd, block_no) = safe_malloc(CPGB_SIZE, LOC_CPGD_0018);
            if(NULL_PTR == CPGD_BLOCK_CPGB(cpgd, block_no))
            {
                dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_load: malloc block %u failed\n", block_no);
                return (EC_FALSE);
            }
        }
        if(EC_FALSE == cpgb_load(CPGD_BLOCK_CPGB(cpgd, block_no), fd, offset))
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_load: load CPGD_BLOCK_NODE of block_no %u at offset %ld of fd %d failed\n",
                                block_no, (*offset), fd);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cpgd_check(const CPGD *cpgd)
{
    uint16_t  pgd_assign_bitmap;
    uint16_t  pgb_assign_bitmap;/*all pgb's bitmap*/
    uint16_t  block_no;
    uint16_t  block_num;

    uint64_t  pgd_actual_used_size;
    uint64_t  pgb_actual_used_size;/*all pgb's used size*/

    uint32_t  pgd_page_max_num;
    uint32_t  pgb_page_max_num;/*all pgb's page max num*/

    uint32_t  pgd_page_used_num;
    uint32_t  pgb_page_used_num;/*all pgb's page used num*/

    pgd_assign_bitmap    = CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd);
    pgd_actual_used_size = CPGD_PAGE_ACTUAL_USED_SIZE(cpgd);
    pgd_page_max_num     = CPGD_PAGE_MAX_NUM(cpgd);
    pgd_page_used_num    = CPGD_PAGE_USED_NUM(cpgd);
    block_num = CPGD_PAGE_BLOCK_MAX_NUM(cpgd);

    pgb_assign_bitmap    = 0;
    pgb_actual_used_size = 0;
    pgb_page_max_num     = 0;
    pgb_page_used_num    = 0;

    for(block_no = 0; block_no < block_num; block_no ++)
    {
        pgb_assign_bitmap    |= CPGB_PAGE_MODEL_ASSIGN_BITMAP(CPGD_BLOCK_NODE(cpgd, block_no));
        pgb_actual_used_size += CPGB_PAGE_ACTUAL_USED_SIZE(CPGD_BLOCK_NODE(cpgd, block_no));
        pgb_page_max_num     += CPGB_PAGE_MAX_NUM(CPGD_BLOCK_NODE(cpgd, block_no));
        pgb_page_used_num    += CPGB_PAGE_USED_NUM(CPGD_BLOCK_NODE(cpgd, block_no));
    }

    if(pgd_assign_bitmap != pgb_assign_bitmap)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_check: inconsistent bitmap: pgd_assign_bitmap = %s, pgb_assign_bitmap = %s\n",
                           c_uint16_t_to_bin_str(pgd_assign_bitmap), c_uint16_t_to_bin_str(pgb_assign_bitmap));
        return (EC_FALSE);
    }

    if(pgd_actual_used_size != pgb_actual_used_size)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_check: inconsistent actual used size: pgd_actual_used_size = %"PRId64", pgb_actual_used_size = %"PRId64"\n",
                            pgd_actual_used_size, pgb_actual_used_size);
        return (EC_FALSE);
    }

    if(pgd_page_max_num != pgb_page_max_num)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_check: inconsistent page max num: pgd_page_max_num = %u, pgb_page_max_num = %u\n",
                            pgd_page_max_num, pgb_page_max_num);
        return (EC_FALSE);
    }

    if(pgd_page_used_num != pgb_page_used_num)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_check: inconsistent page used num: pgd_page_used_num = %u, pgb_page_used_num = %u\n",
                            pgd_page_used_num, pgb_page_used_num);
        return (EC_FALSE);
    }

    /*check block table*/
    for(block_no = 0; block_no < CPGD_PAGE_BLOCK_MAX_NUM(cpgd); block_no ++)
    {
        if(EC_FALSE == cpgb_check(CPGD_BLOCK_NODE(cpgd, block_no)))
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_check: check CPGD_BLOCK_NODE of block_no %u failed\n", block_no);
            return (EC_FALSE);
        }
    }
    dbg_log(SEC_0041_CPGD, 5)(LOGSTDOUT, "cpgd_check: cpgd %p check passed\n", cpgd);
    return (EC_TRUE);
}

void cpgd_print(LOG *log, const CPGD *cpgd)
{
    uint16_t  page_model;
    char     *page_desc;
    REAL      used_size;
    REAL      occupied_size;
    REAL      ratio_size;
    REAL      ratio_page;

    CPGD_ASSERT(NULL_PTR != cpgd);

    //cpgrb_pool_print(log, CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd));

    if(0)
    {
        for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
        {
            sys_log(log, "cpgd_print: page_model %u, block root_pos %u\n",
                         page_model,
                         CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model));
            cpgrb_tree_print(log, CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd), CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model));
            sys_log(log, "----------------------------------------------------------\n");
        }
    }
    used_size     = (0.0 + CPGD_PAGE_ACTUAL_USED_SIZE(cpgd));
    occupied_size = (0.0 + (((uint64_t)CPGD_PAGE_USED_NUM(cpgd)) << CPGB_PAGE_BIT_SIZE));
    ratio_size    = (EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size));

    ratio_page    = ((0.0 + CPGD_PAGE_USED_NUM(cpgd)) / (0.0 + CPGD_PAGE_MAX_NUM(cpgd)));

    if(CPGB_PAGE_BIT_SIZE == CPGB_PAGE_4K_BIT_SIZE)
    {
        page_desc = "4K-page";
    }

    if(CPGB_PAGE_BIT_SIZE == CPGB_PAGE_8K_BIT_SIZE)
    {
        page_desc = "8K-page";
    }

    if(CPGB_PAGE_BIT_SIZE == CPGB_PAGE_16M_BIT_SIZE)
    {
        page_desc = "16M-page";
    }

    if(CPGB_PAGE_BIT_SIZE == CPGB_PAGE_32M_BIT_SIZE)
    {
        page_desc = "32M-page";
    }
/*
    sys_log(log, "cpgd_print: cpgd %p, ratio %.2f\n",
                 cpgd,
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );
*/
    sys_log(log, "cpgd_print: cpgd %p, block num %u, %s, page max num %u, page used num %u, page ratio %.2f, actual used size %"PRId64", size ratio %.2f\n",
                 cpgd,
                 CPGD_PAGE_BLOCK_MAX_NUM(cpgd),
                 page_desc,
                 CPGD_PAGE_MAX_NUM(cpgd),
                 CPGD_PAGE_USED_NUM(cpgd),
                 ratio_page,
                 CPGD_PAGE_ACTUAL_USED_SIZE(cpgd),
                 ratio_size
                 );

    sys_log(log, "cpgd_print: cpgd %p, assign bitmap %s \n",
                 cpgd,
                 c_uint16_t_to_bin_str(CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd))
                 );

    if(0)
    {
        for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++)
        {
            if(CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd) & (1 << page_model))
            {
                sys_log(log, "cpgd_print: cpgd %p, model %u has page to assign\n", cpgd, page_model);
            }
            else
            {
                sys_log(log, "cpgd_print: cpgd %p, model %u no  page to assign\n", cpgd, page_model);
            }
        }
    }

    if(0)
    {
        uint16_t  block_no;
        for(block_no = 0; block_no < CPGD_PAGE_BLOCK_MAX_NUM(cpgd); block_no ++)
        {
            sys_log(log, "cpgd_print: block %u is\n", block_no);
            cpgb_print(log, CPGD_BLOCK_NODE(cpgd, block_no));
        }
    }

    return;
}

/* ---- debug ---- */
EC_BOOL cpgd_debug_cmp(const CPGD *cpgd_1st, const CPGD *cpgd_2nd)
{
    uint16_t page_model;
    uint16_t block_no;

    /*cpgrb pool*/
    if(EC_FALSE == cpgrb_debug_cmp(CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd_1st), CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd_2nd)))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_debug_cmp: inconsistent cpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd_1st, page_model);
        root_pos_2nd = CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*assign bitmap*/
    if(CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd_1st) != CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd_1st))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_debug_cmp: inconsistent CPGD_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd_1st), CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd_2nd));
        return (EC_FALSE);
    }

    /*block max num*/
    if(CPGD_PAGE_BLOCK_MAX_NUM(cpgd_1st) != CPGD_PAGE_BLOCK_MAX_NUM(cpgd_1st))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_debug_cmp: inconsistent CPGD_PAGE_BLOCK_MAX_NUM: %u != %u\n",
                            CPGD_PAGE_BLOCK_MAX_NUM(cpgd_1st), CPGD_PAGE_BLOCK_MAX_NUM(cpgd_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CPGD_PAGE_MAX_NUM(cpgd_1st) != CPGD_PAGE_MAX_NUM(cpgd_1st))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_debug_cmp: inconsistent CPGD_PAGE_MAX_NUM: %u != %u\n",
                            CPGD_PAGE_MAX_NUM(cpgd_1st), CPGD_PAGE_BLOCK_MAX_NUM(cpgd_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CPGD_PAGE_USED_NUM(cpgd_1st) != CPGD_PAGE_USED_NUM(cpgd_1st))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_debug_cmp: inconsistent CPGD_PAGE_USED_NUM: %u != %u\n",
                            CPGD_PAGE_USED_NUM(cpgd_1st), CPGD_PAGE_USED_NUM(cpgd_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CPGD_PAGE_ACTUAL_USED_SIZE(cpgd_1st) != CPGD_PAGE_ACTUAL_USED_SIZE(cpgd_1st))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDERR, "error:cpgd_debug_cmp: inconsistent CPGD_PAGE_ACTUAL_USED_SIZE: %"PRId64" != %"PRId64"\n",
                            CPGD_PAGE_ACTUAL_USED_SIZE(cpgd_1st), CPGD_PAGE_ACTUAL_USED_SIZE(cpgd_2nd));
        return (EC_FALSE);
    }

    /*block cpgb*/
    for(block_no = 0; block_no < CPGD_PAGE_BLOCK_MAX_NUM(cpgd_1st); block_no ++)
    {
        if(EC_FALSE == cpgb_debug_cmp(CPGD_BLOCK_NODE(cpgd_1st, block_no), CPGD_BLOCK_NODE(cpgd_2nd, block_no)))
        {
            dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_debug_cmp: inconsistent CPGD_BLOCK_NODE at block_no %u\n", block_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/*-------------------------------------------- DISK in memory --------------------------------------------*/
CPGD *cpgd_mem_new(const uint16_t block_num)
{
    CPGD      *cpgd;
    uint16_t   block_no;

    if(CPGD_MAX_BLOCK_NUM < block_num)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_mem_new: block_num %u overflow\n", block_num);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CPGD, &cpgd, LOC_CPGD_0019);
    if(NULL_PTR == cpgd)
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_mem_new:malloc cpgd failed\n");
        return (NULL_PTR);
    }

    cpgd_init(cpgd);

    CPGD_FNAME(cpgd) = NULL_PTR;

    CPGD_FD(cpgd) = ERR_FD;

    dbg_log(SEC_0041_CPGD, 9)(LOGSTDOUT, "[DEBUG] cpgd_mem_new: CPGD_HDR_SIZE %ld, block_num %u, CPGB_SIZE %ld, sizeof(off_t) = %ld\n",
                        CPGD_HDR_SIZE, block_num, CPGB_SIZE, sizeof(off_t));

    CPGD_FSIZE(cpgd) = CPGD_HDR_SIZE + block_num * CPGB_SIZE;

    CPGD_HEADER(cpgd) = cpgd_hdr_mem_new(cpgd, block_num);
    if(NULL_PTR == CPGD_HEADER(cpgd))
    {
        dbg_log(SEC_0041_CPGD, 0)(LOGSTDOUT, "error:cpgd_mem_new: new cpgd header failed\n");
        cpgd_free(cpgd);
        return (NULL_PTR);
    }

    /*init blocks*/
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CPGD_BLOCK_CPGB(cpgd, block_no) = __cpgd_block(cpgd, block_no);
        cpgb_init(CPGD_BLOCK_CPGB(cpgd, block_no), CPGD_BLOCK_PAGE_MODEL);
        cpgd_add_block(cpgd, block_no, CPGD_BLOCK_PAGE_MODEL);

        if(0 == ((block_no + 1) % 1000))
        {
            dbg_log(SEC_0041_CPGD, 3)(LOGSTDOUT, "info:cpgd_mem_new: init block %u - %u done\n", block_no - 999, block_no);
        }
    }
    dbg_log(SEC_0041_CPGD, 3)(LOGSTDOUT, "info:cpgd_mem_new: init %u blocks done\n", block_num);

    return (cpgd);
}

EC_BOOL cpgd_mem_free(CPGD *cpgd)
{
    if(NULL_PTR != cpgd)
    {
        UINT32 block_num;
        UINT32 block_no;

        /*clean blocks*/
        block_num = CPGD_PAGE_BLOCK_MAX_NUM(cpgd);
        for(block_no = 0; block_no < block_num; block_no ++)
        {
            CPGD_BLOCK_CPGB(cpgd, block_no) = NULL_PTR;
        }

        cpgd_hdr_mem_free(cpgd);

        ASSERT(ERR_FD == CPGD_FD(cpgd));

        ASSERT(NULL_PTR == CPGD_FNAME(cpgd));

        free_static_mem(MM_CPGD, cpgd, LOC_CPGD_0020);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

