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

#include "cmisc.h"
#include "real.h"

#include "csfsb.h"
#include "csfsd.h"

/*page disk:1TB = 2^14 page block*/

#if 1
#define CSFSD_ASSERT(cond)   ASSERT(cond)
#endif

#if 0
#define CSFSD_ASSERT(cond)   do{}while(0)
#endif

static CSFSD_CFG g_csfsd_cfg_tbl[] = {
    {(const char *)"64M"  , (const char *)"CSFSD_064MB_BLOCK_NUM", CSFSD_064MB_BLOCK_NUM, 0, 0 },
    {(const char *)"128M" , (const char *)"CSFSD_128MB_BLOCK_NUM", CSFSD_128MB_BLOCK_NUM, 0, 0 },
    {(const char *)"256M" , (const char *)"CSFSD_256MB_BLOCK_NUM", CSFSD_256MB_BLOCK_NUM, 0, 0 },
    {(const char *)"512M" , (const char *)"CSFSD_512MB_BLOCK_NUM", CSFSD_512MB_BLOCK_NUM, 0, 0 },
    {(const char *)"1G"   , (const char *)"CSFSD_001GB_BLOCK_NUM", CSFSD_001GB_BLOCK_NUM, 0, 0 },
    {(const char *)"2G"   , (const char *)"CSFSD_002GB_BLOCK_NUM", CSFSD_002GB_BLOCK_NUM, 0, 0 },
    {(const char *)"4G"   , (const char *)"CSFSD_004GB_BLOCK_NUM", CSFSD_004GB_BLOCK_NUM, 0, 0 },
    {(const char *)"8G"   , (const char *)"CSFSD_008GB_BLOCK_NUM", CSFSD_008GB_BLOCK_NUM, 0, 0 },
    {(const char *)"16G"  , (const char *)"CSFSD_016GB_BLOCK_NUM", CSFSD_016GB_BLOCK_NUM, 0, 0 },
    {(const char *)"32G"  , (const char *)"CSFSD_032GB_BLOCK_NUM", CSFSD_032GB_BLOCK_NUM, 0, 0 },
    {(const char *)"64G"  , (const char *)"CSFSD_064GB_BLOCK_NUM", CSFSD_064GB_BLOCK_NUM, 0, 0 },
    {(const char *)"128G" , (const char *)"CSFSD_128GB_BLOCK_NUM", CSFSD_128GB_BLOCK_NUM, 0, 0 },
    {(const char *)"256G" , (const char *)"CSFSD_256GB_BLOCK_NUM", CSFSD_256GB_BLOCK_NUM, 0, 0 },
    {(const char *)"512G" , (const char *)"CSFSD_512GB_BLOCK_NUM", CSFSD_512GB_BLOCK_NUM, 0, 0 },
    {(const char *)"1T"   , (const char *)"CSFSD_001TB_BLOCK_NUM", CSFSD_001TB_BLOCK_NUM, 0, 0 },
};

static uint8_t g_csfsd_cfg_tbl_len = (uint8_t)(sizeof(g_csfsd_cfg_tbl)/sizeof(g_csfsd_cfg_tbl[0]));

const char *csfsd_model_str(const uint16_t pgd_block_num)
{
    uint8_t csfsd_model;

    for(csfsd_model = 0; csfsd_model < g_csfsd_cfg_tbl_len; csfsd_model ++)
    {
        CSFSD_CFG *csfsd_cfg;

        csfsd_cfg = &(g_csfsd_cfg_tbl[ csfsd_model ]);
        if(pgd_block_num == CSFSD_CFG_BLOCK_NUM(csfsd_cfg))
        {
            return CSFSD_CFG_MODEL_STR(csfsd_cfg);
        }
    }

    return (const char *)"unkown";
}

uint16_t csfsd_model_get(const char *model_str)
{
    uint8_t csfsd_model;

    for(csfsd_model = 0; csfsd_model < g_csfsd_cfg_tbl_len; csfsd_model ++)
    {
        CSFSD_CFG *csfsd_cfg;
        csfsd_cfg = &(g_csfsd_cfg_tbl[ csfsd_model ]);

        if(0 == strcasecmp(CSFSD_CFG_MODEL_STR(csfsd_cfg), model_str))
        {
            return CSFSD_CFG_BLOCK_NUM(csfsd_cfg);
        }
    }
    return (CSFSD_ERROR_BLOCK_NUM);
}

STATIC_CAST static CSFSB *__csfsd_block(CSFSD *csfsd, const uint16_t  block_no)
{
    return (CSFSB *)(((void *)CSFSD_HEADER(csfsd)) + sizeof(CSFSD_HDR) + block_no * sizeof(CSFSB));
}

STATIC_CAST static EC_BOOL __csfsd_hdr_init(CSFSD_HDR *csfsd_hdr, const uint16_t block_num)
{
    if(NULL_PTR != csfsd_hdr)
    {
        uint32_t page_max_num;

        page_max_num  = block_num;
        page_max_num *= CSFSB_PAGE_NUM;

        CSFSD_HDR_BLOCK_MAX_NUM(csfsd_hdr) = block_num;
        CSFSD_HDR_PAGE_MAX_NUM(csfsd_hdr)  = page_max_num;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsd_hdr_clean(CSFSD_HDR *csfsd_hdr)
{
    if(NULL_PTR != csfsd_hdr)
    {
        CSFSD_HDR_BLOCK_MAX_NUM(csfsd_hdr) = 0;
        CSFSD_HDR_PAGE_MAX_NUM(csfsd_hdr)  = 0;
    }
    return (EC_TRUE);
}

STATIC_CAST static CSFSD_HDR *__csfsd_hdr_open(CSFSD *csfsd)
{
    CSFSD_HDR *csfsd_hdr;
    uint16_t   block_num;
    uint16_t   block_no;

    dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "[DEBUG] __csfsd_hdr_open: fsize %u\n", CSFSD_FSIZE(csfsd));

    csfsd_hdr = (CSFSD_HDR *)mmap(NULL_PTR, CSFSD_FSIZE(csfsd), PROT_READ | PROT_WRITE, MAP_SHARED, CSFSD_FD(csfsd), 0);
    if(MAP_FAILED == csfsd_hdr)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:__csfsd_hdr_open: mmap file %s with fd %d failed, errno = %d, errstr = %s\n",
                           (char *)CSFSD_FNAME(csfsd), CSFSD_FD(csfsd), errno, strerror(errno));
        return (NULL_PTR);
    }

    block_num = CSFSD_HDR_BLOCK_MAX_NUM(csfsd_hdr);

    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CSFSB *csfsb;

        csfsb = (CSFSB *)(((void *)csfsd_hdr) + sizeof(CSFSD_HDR) + sizeof(CSFSB) * block_no);

        CSFSD_BLOCK_NODE(csfsd, block_no) = csfsb;

        if(do_log(SEC_0165_CSFSD, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] __csfsd_hdr_open: block %u is\n", block_no);
            csfsb_print(LOGSTDOUT, csfsb);
        }
    }
    return (csfsd_hdr);
}

STATIC_CAST static EC_BOOL __csfsd_hdr_close(CSFSD *csfsd)
{
    if(NULL_PTR != CSFSD_HEADER(csfsd))
    {
        if(0 != msync(CSFSD_HEADER(csfsd), CSFSD_FSIZE(csfsd), MS_SYNC))
        {
            dbg_log(SEC_0165_CSFSD, 1)(LOGSTDOUT, "warn:__csfsd_hdr_close: sync csfsd_hdr of %s with size %u failed\n",
                               CSFSD_FNAME(csfsd), CSFSD_FSIZE(csfsd));
        }

        if(0 != munmap(CSFSD_HEADER(csfsd), CSFSD_FSIZE(csfsd)))
        {
            dbg_log(SEC_0165_CSFSD, 1)(LOGSTDOUT, "warn:__csfsd_hdr_close: munmap csfsd of %s with size %u failed\n",
                               CSFSD_FNAME(csfsd), CSFSD_FSIZE(csfsd));
        }

        CSFSD_HEADER(csfsd) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsd_hdr_sync(CSFSD *csfsd)
{
    if(NULL_PTR != CSFSD_HEADER(csfsd))
    {
        if(do_log(SEC_0165_CSFSD, 9))
        {
            uint16_t     block_num;
            uint16_t     block_no;

            block_num = CSFSD_HDR_BLOCK_MAX_NUM(CSFSD_HEADER(csfsd));

            sys_log(LOGSTDOUT, "[DEBUG] __csfsd_hdr_sync: csfsd %p, fsize %u, block_num %u\n",
                                csfsd, CSFSD_FSIZE(csfsd), block_num);

            for(block_no = 0; block_no < block_num; block_no ++)
            {
                CSFSB *csfsb;

                csfsb = (CSFSB *)(((void *)CSFSD_HEADER(csfsd)) + sizeof(CSFSD_HDR) + sizeof(CSFSB) * block_no);

                sys_log(LOGSTDOUT, "[DEBUG] __csfsd_hdr_sync: block %u is\n", block_no);
                csfsb_print(LOGSTDOUT, csfsb);
            }
        }

        if(0 != msync(CSFSD_HEADER(csfsd), CSFSD_FSIZE(csfsd), MS_SYNC))
        {
            dbg_log(SEC_0165_CSFSD, 1)(LOGSTDOUT, "warn:__csfsd_hdr_sync: sync csfsd_hdr of %s with size %u failed\n",
                               CSFSD_FNAME(csfsd), CSFSD_FSIZE(csfsd));
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static CSFSD_HDR *__csfsd_hdr_load(CSFSD *csfsd)
{
    uint8_t     *buff;
    CSFSD_HDR   *csfsd_hdr;
    UINT32       offset;
    uint16_t     block_num;
    uint16_t     block_no;

    buff = (uint8_t *)safe_malloc(CSFSD_FSIZE(csfsd), LOC_CSFSD_0001);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:__csfsd_hdr_load: malloc %u bytes failed for fd %d\n", CSFSD_FSIZE(csfsd), CSFSD_FD(csfsd));
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(CSFSD_FD(csfsd), &offset, CSFSD_FSIZE(csfsd), buff))
    {
        safe_free(buff, LOC_CSFSD_0002);
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:__csfsd_hdr_load: load %u bytes failed for fd %d\n", CSFSD_FSIZE(csfsd), CSFSD_FD(csfsd));
        return (NULL_PTR);
    }

    csfsd_hdr = (CSFSD_HDR *)buff;

    block_num = CSFSD_HDR_BLOCK_MAX_NUM(csfsd_hdr);

    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CSFSB *csfsb;

        csfsb = (CSFSB *)(((void *)csfsd_hdr) + sizeof(CSFSD_HDR) + sizeof(CSFSB) * block_no);

        CSFSD_BLOCK_NODE(csfsd, block_no) = csfsb;

        if(do_log(SEC_0165_CSFSD, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] __csfsd_hdr_load: block %u is\n", block_no);
            csfsb_print(LOGSTDOUT, csfsb);
        }
    }
    return (csfsd_hdr);
}


STATIC_CAST static EC_BOOL __csfsd_hdr_free(CSFSD *csfsd)
{
    if(NULL_PTR != CSFSD_HEADER(csfsd))
    {
        UINT32 offset;

        offset = 0;
        if(EC_FALSE == c_file_flush(CSFSD_FD(csfsd), &offset, CSFSD_FSIZE(csfsd), (const UINT8 *)CSFSD_HEADER(csfsd)))
        {
            dbg_log(SEC_0165_CSFSD, 1)(LOGSTDOUT, "warn:__csfsd_hdr_free: flush csfsd_hdr to fd %d with size %u failed\n",
                               CSFSD_FD(csfsd), CSFSD_FSIZE(csfsd));

            safe_free(CSFSD_HEADER(csfsd), LOC_CSFSD_0003);
            CSFSD_HEADER(csfsd) = NULL_PTR;
            return (EC_FALSE);
        }

        safe_free(CSFSD_HEADER(csfsd), LOC_CSFSD_0004);
        CSFSD_HEADER(csfsd) = NULL_PTR;
    }

    /*cpgv_hdr cannot be accessed again*/
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsd_hdr_flush(CSFSD *csfsd)
{
    if(NULL_PTR != CSFSD_HEADER(csfsd))
    {
        UINT32 offset;

        offset = 0;
        if(EC_FALSE == c_file_flush(CSFSD_FD(csfsd), &offset, CSFSD_FSIZE(csfsd), (const UINT8 *)CSFSD_HEADER(csfsd)))
        {
            dbg_log(SEC_0165_CSFSD, 1)(LOGSTDOUT, "warn:__csfsd_hdr_flush: flush csfsd_hdr to fd %d with size %u failed\n",
                        CSFSD_FD(csfsd), CSFSD_FSIZE(csfsd));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

CSFSD_HDR *csfsd_hdr_new(CSFSD *csfsd, const uint16_t block_num)
{
    CSFSD_HDR *csfsd_hdr;
    uint16_t   block_no;

    csfsd_hdr = (CSFSD_HDR *)mmap(NULL_PTR, CSFSD_FSIZE(csfsd), PROT_READ | PROT_WRITE, MAP_SHARED, CSFSD_FD(csfsd), 0);
    if(MAP_FAILED == csfsd_hdr)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_new: mmap file %s failed, errno = %d, errstr = %s\n",
                           (char *)CSFSD_FNAME(csfsd), errno, strerror(errno));
        return (NULL_PTR);
    }

    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CSFSB *csfsb;

        csfsb = (CSFSB *)(((void *)csfsd_hdr) + sizeof(CSFSD_HDR) + sizeof(CSFSB) * block_no);
        csfsb_init(csfsb, CSFSD_NP_NODE_ERR_POS(csfsd));

        if(do_log(SEC_0165_CSFSD, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] csfsd_hdr_new: block %u is\n", block_no);
            csfsb_print(LOGSTDOUT, csfsb);
        }
    }

    __csfsd_hdr_init(csfsd_hdr, block_num);

    return (csfsd_hdr);
}

EC_BOOL csfsd_hdr_free(CSFSD *csfsd)
{
    if(NULL_PTR != CSFSD_HEADER(csfsd))
    {
        if(0 != msync(CSFSD_HEADER(csfsd), CSFSD_FSIZE(csfsd), MS_SYNC))
        {
            dbg_log(SEC_0165_CSFSD, 1)(LOGSTDOUT, "warn:csfsd_hdr_free: sync csfsd_hdr of %s with size %u failed\n",
                               CSFSD_FNAME(csfsd), CSFSD_FSIZE(csfsd));
        }

        if(0 != munmap(CSFSD_HEADER(csfsd), CSFSD_FSIZE(csfsd)))
        {
            dbg_log(SEC_0165_CSFSD, 1)(LOGSTDOUT, "warn:csfsd_hdr_free: munmap csfsd of %s with size %u failed\n",
                               CSFSD_FNAME(csfsd), CSFSD_FSIZE(csfsd));
        }

        CSFSD_HEADER(csfsd) = NULL_PTR;
    }

    return (EC_TRUE);
}



CSFSD_HDR *csfsd_hdr_open(CSFSD *csfsd)
{
    if(SWITCH_ON == CSFS_DN_CACHE_IN_MEM)
    {
        return __csfsd_hdr_load(csfsd);
    }

    return __csfsd_hdr_open(csfsd);
}

EC_BOOL csfsd_hdr_close(CSFSD *csfsd)
{
    if(SWITCH_ON == CSFS_DN_CACHE_IN_MEM)
    {
        return __csfsd_hdr_free(csfsd);
    }
    return __csfsd_hdr_close(csfsd);
}

EC_BOOL csfsd_hdr_sync(CSFSD *csfsd)
{
    if(SWITCH_ON == CSFS_DN_CACHE_IN_MEM)
    {
        return __csfsd_hdr_flush(csfsd);
    }

    return __csfsd_hdr_sync(csfsd);
}

EC_BOOL csfsd_hdr_flush_size(const CSFSD_HDR *csfsd_hdr, UINT32 *size)
{
    (*size) += sizeof(CSFSD_HDR);
    return (EC_TRUE);
}

EC_BOOL csfsd_hdr_flush(const CSFSD_HDR *csfsd_hdr, int fd, UINT32 *offset)
{
    UINT32 osize;/*flush once size*/
    DEBUG(UINT32 offset_saved = *offset;);

    /*flush CSFSD_HDR_BLOCK_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSD_HDR_BLOCK_MAX_NUM(csfsd_hdr))))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_flush: flush CSFSD_HDR_BLOCK_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd01*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_flush: pad %u bytes at offset %u of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CSFSD_HDR_PAGE_MAX_NUM*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSD_HDR_PAGE_MAX_NUM(csfsd_hdr))))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_flush: flush CSFSD_HDR_PAGE_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd02*/
    osize = CSFSD_HDR_PAD_SIZE * sizeof(uint8_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_flush: pad %u bytes at offset %u of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    }

    DEBUG(CSFSD_ASSERT(sizeof(CSFSD_HDR) == (*offset) - offset_saved));

    return (EC_TRUE);
}

EC_BOOL csfsd_hdr_load(CSFSD_HDR *csfsd_hdr, int fd, UINT32 *offset)
{
    UINT32 osize;/*load once size*/

    /*load CSFSD_HDR_BLOCK_MAX_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSD_HDR_BLOCK_MAX_NUM(csfsd_hdr))))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_load: load CSFSD_HDR_BLOCK_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd01*/
    (*offset) += sizeof(uint16_t);

    /*load CSFSD_HDR_PAGE_MAX_NUM*/
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSD_HDR_PAGE_MAX_NUM(csfsd_hdr))))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_load: load CSFSD_HDR_PAGE_MAX_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*skip rsvd02*/
    (*offset) += CSFSD_HDR_PAD_SIZE * sizeof(uint8_t);

    return (EC_TRUE);
}

CSFSD_HDR *csfsd_hdr_mem_new(CSFSD *csfsd, const uint16_t block_num)
{
    CSFSD_HDR *csfsd_hdr;

    csfsd_hdr = safe_malloc(CSFSD_FSIZE(csfsd), LOC_CSFSD_0005);
    if(NULL_PTR == csfsd_hdr)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_hdr_mem_new: malloc %ld bytes failed\n",
                           CSFSD_FSIZE(csfsd));
        return (NULL_PTR);
    }

    __csfsd_hdr_init(csfsd_hdr, block_num);

    return (csfsd_hdr);
}

EC_BOOL csfsd_hdr_mem_free(CSFSD *csfsd)
{
    if(NULL_PTR != CSFSD_HEADER(csfsd))
    {
        __csfsd_hdr_clean(CSFSD_HEADER(csfsd));

        safe_free(CSFSD_HEADER(csfsd), LOC_CSFSD_0006);
        CSFSD_HEADER(csfsd) = NULL_PTR;
    }

    return (EC_TRUE);
}

CSFSD *csfsd_new(const uint8_t *csfsd_fname, const uint16_t block_num, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *np)
{
    CSFSD      *csfsd;

    if(CSFSD_MAX_BLOCK_NUM < block_num)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new: block_num %u overflow\n", block_num);
        return (NULL_PTR);
    }

    if(EC_TRUE == c_file_access((const char *)csfsd_fname, F_OK))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new: %s already exist\n", csfsd_fname);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CSFSD, &csfsd, LOC_CSFSD_0007);
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new:malloc csfsd failed\n");
        return (NULL_PTR);
    }

    csfsd_init(csfsd);
    csfsd_set_np(csfsd, np_node_err_pos, np_node_recycle, np);

    CSFSD_FNAME(csfsd) = (uint8_t *)c_str_dup((char *)csfsd_fname);
    if(NULL_PTR == CSFSD_FNAME(csfsd))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new:str dup %s failed\n", csfsd_fname);
        csfsd_free(csfsd);
        return (NULL_PTR);
    }

    CSFSD_FD(csfsd) = c_file_open((const char *)csfsd_fname, O_RDWR | O_SYNC | O_CREAT, 0666);
    if(ERR_FD == CSFSD_FD(csfsd))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new: create %s failed\n", csfsd_fname);
        csfsd_free(csfsd);
        return (NULL_PTR);
    }

    dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "[DEBUG] csfsd_new: sizeof(CSFSD_HDR) %u, block_num %u\n",
                        sizeof(CSFSD_HDR), block_num);

    CSFSD_FSIZE(csfsd) = sizeof(CSFSD_HDR) + sizeof(CSFSB) * block_num;
    if(EC_FALSE == c_file_truncate(CSFSD_FD(csfsd), CSFSD_FSIZE(csfsd)))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new: truncate %s to %u bytes failed\n", csfsd_fname, CSFSD_FSIZE(csfsd));
        csfsd_free(csfsd);
        return (NULL_PTR);
    }

    CSFSD_HEADER(csfsd) = csfsd_hdr_new(csfsd, block_num);
    if(NULL_PTR == CSFSD_HEADER(csfsd))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new: new csfsd header of file %s failed\n", csfsd_fname);
        csfsd_free(csfsd);
        return (NULL_PTR);
    }

    dbg_log(SEC_0165_CSFSD, 3)(LOGSTDOUT, "info:csfsd_new: init %u blocks of file %s done\n", block_num, csfsd_fname);

    return (csfsd);
}

EC_BOOL csfsd_free(CSFSD *csfsd)
{
    if(NULL_PTR != csfsd)
    {
        csfsd_hdr_free(csfsd);

        if(ERR_FD != CSFSD_FD(csfsd))
        {
            c_file_close(CSFSD_FD(csfsd));
            CSFSD_FD(csfsd) = ERR_FD;
        }

        if(NULL_PTR != CSFSD_FNAME(csfsd))
        {
            safe_free(CSFSD_FNAME(csfsd), LOC_CSFSD_0008);
            CSFSD_FNAME(csfsd) = NULL_PTR;
        }

        free_static_mem(MM_CSFSD, csfsd, LOC_CSFSD_0009);
    }

    return (EC_TRUE);
}

EC_BOOL csfsd_exist(const uint8_t *csfsd_fname)
{
    return c_file_access((const char *)csfsd_fname, F_OK);
}

EC_BOOL csfsd_rmv(const uint8_t *csfsd_fname)
{
    return c_file_unlink((const char *)csfsd_fname);
}

CSFSD *csfsd_open(const uint8_t *csfsd_fname)
{
    CSFSD      *csfsd;

    UINT32      fsize;

    alloc_static_mem(MM_CSFSD, &csfsd, LOC_CSFSD_0010);
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_open:malloc csfsd failed\n");
        return (NULL_PTR);
    }

    csfsd_init(csfsd);

    CSFSD_FNAME(csfsd) = (uint8_t *)c_str_dup((const char *)csfsd_fname);
    if(NULL_PTR == CSFSD_FNAME(csfsd))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_open:str dup %s failed\n", csfsd_fname);
        csfsd_close(csfsd);
        return (NULL_PTR);
    }

    CSFSD_FD(csfsd) = c_file_open((const char *)csfsd_fname, O_RDWR | O_SYNC , 0666);
    if(ERR_FD == CSFSD_FD(csfsd))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_open: open %s failed\n", csfsd_fname);
        csfsd_close(csfsd);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_size(CSFSD_FD(csfsd), &fsize))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_open: get size of %s failed\n", csfsd_fname);
        csfsd_close(csfsd);
        return (NULL_PTR);
    }
    CSFSD_FSIZE(csfsd) = (uint32_t)fsize;

    CSFSD_HEADER(csfsd) = csfsd_hdr_open(csfsd);
    if(NULL_PTR == CSFSD_HEADER(csfsd))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_open: open csfsd header of file %s failed\n", csfsd_fname);
        csfsd_close(csfsd);
        return (NULL_PTR);
    }

    return (csfsd);
}

EC_BOOL csfsd_close(CSFSD *csfsd)
{
    if(NULL_PTR != csfsd)
    {
        csfsd_hdr_close(csfsd);

        if(ERR_FD != CSFSD_FD(csfsd))
        {
            c_file_close(CSFSD_FD(csfsd));
            CSFSD_FD(csfsd) = ERR_FD;
        }

        if(NULL_PTR != CSFSD_FNAME(csfsd))
        {
            safe_free(CSFSD_FNAME(csfsd), LOC_CSFSD_0011);
            CSFSD_FNAME(csfsd) = NULL_PTR;
        }

        free_static_mem(MM_CSFSD, csfsd, LOC_CSFSD_0012);
    }
    return (EC_TRUE);
}

EC_BOOL csfsd_sync(CSFSD *csfsd)
{
    if(NULL_PTR != csfsd)
    {
        csfsd_hdr_sync(csfsd);
    }
    return (EC_TRUE);
}

/* one disk = 1TB */
EC_BOOL csfsd_init(CSFSD *csfsd)
{
    if(NULL_PTR != csfsd)
    {
        CSFSD_FD(csfsd)    = ERR_FD;
        CSFSD_FNAME(csfsd) = NULL_PTR;
        CSFSD_FSIZE(csfsd) = 0;
        CSFSD_HEADER(csfsd)= NULL_PTR;
    }

    return (EC_TRUE);
}

/*note: csfsd_clean is for not applying mmap*/
EC_BOOL csfsd_clean(CSFSD *csfsd)
{
    if(NULL_PTR != csfsd)
    {
        if(ERR_FD != CSFSD_FD(csfsd))
        {
            c_file_close(CSFSD_FD(csfsd));
            CSFSD_FD(csfsd) = ERR_FD;
        }

        if(NULL_PTR != CSFSD_FNAME(csfsd))
        {
            safe_free(CSFSD_FNAME(csfsd), LOC_CSFSD_0013);
            CSFSD_FNAME(csfsd) = NULL_PTR;
        }

        if(NULL_PTR != CSFSD_HEADER(csfsd))
        {
            __csfsd_hdr_clean(CSFSD_HEADER(csfsd));
        }

        safe_free(CSFSD_HEADER(csfsd), LOC_CSFSD_0014);
        CSFSD_HEADER(csfsd) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL csfsd_set_np(CSFSD *csfsd, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp)
{
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_set_np: csfsd is null\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != np_node_recycle);
    ASSERT(NULL_PTR != npp);

    CSFSD_NP_NODE_ERR_POS(csfsd) = np_node_err_pos;
    CSFSD_NP_NODE_RECYCLE(csfsd) = np_node_recycle;
    CSFSD_NPP(csfsd)             = npp;

    return (EC_TRUE);
}

EC_BOOL csfsd_new_space(CSFSD *csfsd, const uint16_t page_num, uint16_t *block_no, uint16_t *page_no)
{
    uint16_t block_no_t;
    uint16_t page_no_t;

    block_no_t = (*block_no);
    page_no_t  = (*page_no);

    for(; block_no_t < CSFSD_MAX_BLOCK_NUM; block_no_t ++, page_no_t = 0)
    {
        CSFSB *csfsb;

        csfsb = CSFSD_BLOCK_TBL(csfsd)[ block_no_t ];
        if(NULL_PTR == csfsb)
        {
            dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_new_space: block %u is null\n", block_no_t);
            continue;
        }

        dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "[DEBUG] csfsd_new_space: page_num %u, try on block %u, page %u\n",
                    page_num, block_no_t, page_no_t);

        if(EC_TRUE == csfsb_new_space(csfsb, page_num, page_no_t,
                                      CSFSD_NP_NODE_ERR_POS(csfsd),
                                      CSFSD_NP_NODE_RECYCLE(csfsd),
                                      CSFSD_NPP(csfsd)
                                      )
         )
        {
            (*block_no) = block_no_t;
            (*page_no)  = page_no_t;

            return (EC_TRUE);
        }

        dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "error:csfsd_new_space: page_num %u, block %u, page %u failed\n",
                    page_num, block_no_t, page_no_t);
    }

    return (EC_FALSE);
}

EC_BOOL csfsd_bind(CSFSD *csfsd, const uint16_t block_no, const uint16_t page_no, const uint32_t np_id, const uint32_t np_node_pos)
{
    CSFSB *csfsb;

    csfsb = CSFSD_BLOCK_TBL(csfsd)[ block_no ];
    if(NULL_PTR == csfsb)
    {
        dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "error:csfsd_bind: block %u is null\n", block_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsb_bind(csfsb, page_no, np_id, np_node_pos))
    {
        dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "error:csfsd_bind: bind (block %u, page %u) and (np %u, pos %u) failed\n",
                    block_no, page_no, np_id, np_node_pos);
        return (EC_FALSE);
    }

    dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "[DEBUG] csfsd_bind: bind (block %u, page %u) and (np %u, pos %u) done\n",
                    block_no, page_no, np_id, np_node_pos);

    return (EC_TRUE);
}

EC_BOOL csfsd_flush_size(const CSFSD *csfsd, UINT32 *size)
{
    csfsd_hdr_flush_size(CSFSD_HEADER(csfsd), size);
    return (EC_TRUE);
}

EC_BOOL csfsd_flush(const CSFSD *csfsd, int fd, UINT32 *offset)
{
    /*flush CSFSD_HEADER*/
    if(EC_FALSE == csfsd_hdr_flush(CSFSD_HEADER(csfsd), fd, offset))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_flush: flush CSFSD_HEADER at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsd_load(CSFSD *csfsd, int fd, UINT32 *offset)
{
    if(NULL_PTR == CSFSD_HEADER(csfsd))
    {
        CSFSD_HEADER(csfsd) = safe_malloc(sizeof(CSFSD_HDR), LOC_CSFSD_0015);
        if(NULL_PTR == CSFSD_HEADER(csfsd))
        {
            dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_load: malloc CSFSD_HDR failed\n");
            return (EC_FALSE);
        }
    }

    /*load CSFSD_HEADER*/
    if(EC_FALSE == csfsd_hdr_load(CSFSD_HEADER(csfsd), fd, offset))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_load: load CSFSD_HEADER at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void csfsd_print(LOG *log, const CSFSD *csfsd)
{
    CSFSD_ASSERT(NULL_PTR != csfsd);

    sys_log(log, "csfsd_print: csfsd %p, fname %s, block num %u, page max num %u\n",
                 csfsd,
                 (char *)CSFSD_FNAME(csfsd),
                 CSFSD_BLOCK_MAX_NUM(csfsd),
                 CSFSD_PAGE_MAX_NUM(csfsd)
                 );

    if(0)
    {
        uint16_t  block_no;
        for(block_no = 0; block_no < CSFSD_MAX_BLOCK_NUM; block_no ++)
        {
            sys_log(log, "csfsd_print: block %u is\n", block_no);
            csfsb_print(log, CSFSD_BLOCK_NODE(csfsd, block_no));
        }
    }

    return;
}

/*-------------------------------------------- DISK in memory --------------------------------------------*/
CSFSD *csfsd_mem_new(const uint16_t block_num)
{
    CSFSD      *csfsd;
    uint16_t   block_no;

    if(CSFSD_MAX_BLOCK_NUM < block_num)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_mem_new: block_num %u overflow\n", block_num);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CSFSD, &csfsd, LOC_CSFSD_0016);
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_mem_new:malloc csfsd failed\n");
        return (NULL_PTR);
    }

    csfsd_init(csfsd);

    CSFSD_FNAME(csfsd) = NULL_PTR;

    CSFSD_FD(csfsd) = ERR_FD;

    dbg_log(SEC_0165_CSFSD, 9)(LOGSTDOUT, "[DEBUG] csfsd_mem_new: sizeof(CSFSD_HDR) %u, block_num %u, sizeof(CSFSB) %u, sizeof(off_t) = %u\n",
                        sizeof(CSFSD_HDR), block_num, sizeof(CSFSB), sizeof(off_t));

    CSFSD_FSIZE(csfsd) = sizeof(CSFSD_HDR) + block_num * sizeof(CSFSB);

    CSFSD_HEADER(csfsd) = csfsd_hdr_mem_new(csfsd, block_num);
    if(NULL_PTR == CSFSD_HEADER(csfsd))
    {
        dbg_log(SEC_0165_CSFSD, 0)(LOGSTDOUT, "error:csfsd_mem_new: new csfsd header failed\n");
        csfsd_free(csfsd);
        return (NULL_PTR);
    }

    /*init blocks*/
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CSFSD_BLOCK_NODE(csfsd, block_no) = __csfsd_block(csfsd, block_no);
        csfsb_init(CSFSD_BLOCK_NODE(csfsd, block_no), CSFSD_NP_NODE_ERR_POS(csfsd));

        if(0 == ((block_no + 1) % 1000))
        {
            dbg_log(SEC_0165_CSFSD, 3)(LOGSTDOUT, "info:csfsd_mem_new: init block %u - %u done\n", block_no - 999, block_no);
        }
    }
    dbg_log(SEC_0165_CSFSD, 3)(LOGSTDOUT, "info:csfsd_mem_new: init %u blocks done\n", block_num);

    return (csfsd);
}

EC_BOOL csfsd_mem_free(CSFSD *csfsd)
{
    if(NULL_PTR != csfsd)
    {
        UINT32 block_num;
        UINT32 block_no;

        /*clean blocks*/
        block_num = CSFSD_BLOCK_MAX_NUM(csfsd);
        for(block_no = 0; block_no < block_num; block_no ++)
        {
            CSFSD_BLOCK_NODE(csfsd, block_no) = NULL_PTR;
        }

        csfsd_hdr_mem_free(csfsd);

        ASSERT(ERR_FD == CSFSD_FD(csfsd));

        ASSERT(NULL_PTR == CSFSD_FNAME(csfsd));

        free_static_mem(MM_CSFSD, csfsd, LOC_CSFSD_0017);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

