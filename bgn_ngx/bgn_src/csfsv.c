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

#include "csfsv.h"
#include "csfsd.h"
#include "csfsb.h"

/*page disk:1TB = 2^14 page block*/


#if 1
#define CSFSV_ASSERT(cond)   ASSERT(cond)
#endif

#if 0
#define CSFSV_ASSERT(cond)   do{}while(0)
#endif

#define DEBUG_COUNT_CSFSV_HDR_PAD_SIZE()                 \
                                (sizeof(CSFSV_HDR)       \
                                 - 4 * sizeof(uint16_t)) \

#define ASSERT_CSFSV_HDR_PAD_SIZE() \
    CSFSV_ASSERT( CSFSV_HDR_PAD_SIZE == DEBUG_COUNT_CSFSV_HDR_PAD_SIZE())

STATIC_CAST static uint8_t *__csfsv_new_disk_fname(const CSFSV *csfsv, const uint16_t disk_no)
{
    char *csfsd_dname;
    char *csfsd_fname;
    char  disk_fname[ 32 ];

    if(NULL_PTR == CSFSV_FNAME(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:__csfsv_new_disk_fname: csfsv fname is null\n");
        return (NULL_PTR);
    }
 
    csfsd_dname = c_dirname((const char *)CSFSV_FNAME(csfsv));
    if(NULL_PTR == csfsd_dname)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:__csfsv_new_disk_fname: dname of csfsv fname %s is null\n", (const char *)CSFSV_FNAME(csfsv));
        return (NULL_PTR);
    }

    /*disk fname format: ${CSFSV_DIR}/dsk${disk_no}.dat*/
    snprintf(disk_fname, sizeof(disk_fname)/sizeof(disk_fname[ 0 ]), "/dsk%04X.dat", disk_no);

    csfsd_fname = c_str_cat(csfsd_dname, disk_fname);
    if(NULL_PTR == csfsd_fname)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:__csfsv_new_disk_fname: str cat %s and %s failed\n", csfsd_dname, disk_fname);
        safe_free(csfsd_dname, LOC_CSFSV_0001);
        return (NULL_PTR);
    }
 
    safe_free(csfsd_dname, LOC_CSFSV_0002);
    return ((uint8_t *)csfsd_fname);
}

STATIC_CAST static EC_BOOL __csfsv_free_disk_fname(const CSFSV *csfsv, uint8_t *csfsd_fname)
{
    if(NULL_PTR != csfsd_fname)
    {
        safe_free(csfsd_fname, LOC_CSFSV_0003);
    }
    return (EC_TRUE);
} 

STATIC_CAST static CSFSV_HDR *__csfsv_hdr_load(CSFSV *csfsv)
{
    uint8_t *buff;
    UINT32   offset;

    buff = (uint8_t *)safe_malloc(CSFSV_FSIZE(csfsv), LOC_CSFSV_0004);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:__csfsv_hdr_load: malloc %u bytes failed for fd %d\n", CSFSV_FSIZE(csfsv), CSFSV_FD(csfsv));
        return (NULL_PTR);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(CSFSV_FD(csfsv), &offset, CSFSV_FSIZE(csfsv), buff))
    {
        safe_free(buff, LOC_CSFSV_0005);
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:__csfsv_hdr_load: load %u bytes failed for fd %d\n", CSFSV_FSIZE(csfsv), CSFSV_FD(csfsv));
        return (NULL_PTR);
    }

    return ((CSFSV_HDR *)buff);
}

STATIC_CAST static EC_BOOL __csfsv_hdr_flush(CSFSV *csfsv)
{
    if(NULL_PTR != CSFSV_HEADER(csfsv))
    {
        UINT32 offset;

        offset = 0;     
        if(EC_FALSE == c_file_flush(CSFSV_FD(csfsv), &offset, CSFSV_FSIZE(csfsv), (const UINT8 *)CSFSV_HEADER(csfsv)))
        {
            dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:__csfsv_hdr_flush: flush csfsv_hdr to fd %d with size %u failed\n",
                        CSFSV_FD(csfsv), CSFSV_FSIZE(csfsv));
            return (EC_FALSE);
        }
    } 
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsv_hdr_free(CSFSV *csfsv)
{
    if(NULL_PTR != CSFSV_HEADER(csfsv))
    {
        UINT32 offset;

        offset = 0;
        if(EC_FALSE == c_file_flush(CSFSV_FD(csfsv), &offset, CSFSV_FSIZE(csfsv), (const UINT8 *)CSFSV_HEADER(csfsv)))
        {
            dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:__csfsv_hdr_free: flush csfsv_hdr to fd %d with size %u failed\n",
                               CSFSV_FD(csfsv), CSFSV_FSIZE(csfsv));

            safe_free(CSFSV_HEADER(csfsv), LOC_CSFSV_0006);
            CSFSV_HEADER(csfsv) = NULL_PTR;
            return (EC_FALSE);
        }

        safe_free(CSFSV_HEADER(csfsv), LOC_CSFSV_0007);
        CSFSV_HEADER(csfsv) = NULL_PTR;
    }
 
    /*csfsv_hdr cannot be accessed again*/
    return (EC_TRUE);
}

STATIC_CAST static CSFSV_HDR *__csfsv_hdr_new(CSFSV *csfsv)
{
    CSFSV_HDR *csfsv_hdr;

    ASSERT_CSFSV_HDR_PAD_SIZE();

    csfsv_hdr = (CSFSV_HDR *)safe_malloc(CSFSV_FSIZE(csfsv), LOC_CSFSV_0008);
    if(NULL_PTR == csfsv_hdr)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:__csfsv_hdr_new: new header with %u bytes failed\n", CSFSV_FSIZE(csfsv));
        return (NULL_PTR);
    }

    CSFSV_HEADER(csfsv) = csfsv_hdr;

    if(EC_FALSE == csfsv_hdr_init(csfsv))
    {
        CSFSV_HEADER(csfsv) = NULL_PTR;
     
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDERR, "error:__csfsv_hdr_new: init csfsv failed\n");
        safe_free(csfsv_hdr, LOC_CSFSV_0009);
     
        return (NULL_PTR);
    }
 
 
    return (csfsv_hdr);
}

CSFSV_HDR *csfsv_hdr_create(CSFSV *csfsv)
{
    CSFSV_HDR *csfsv_hdr;

    ASSERT_CSFSV_HDR_PAD_SIZE();

    csfsv_hdr = (CSFSV_HDR *)mmap(NULL_PTR, CSFSV_FSIZE(csfsv), PROT_READ | PROT_WRITE, MAP_SHARED, CSFSV_FD(csfsv), 0);
    if(MAP_FAILED == csfsv_hdr)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_create: mmap file %s failed, errno = %d, errstr = %s\n",
                           (char *)CSFSV_FNAME(csfsv), errno, strerror(errno));
        return (NULL_PTR);
    }

    CSFSV_HEADER(csfsv) = csfsv_hdr;

    if(EC_FALSE == csfsv_hdr_init(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDERR, "error:csfsv_hdr_create: init csfsv failed\n");
        munmap(csfsv_hdr, CSFSV_FSIZE(csfsv));
        return (NULL_PTR);
    }
 
    return (csfsv_hdr);
}

EC_BOOL csfsv_hdr_init(CSFSV *csfsv)
{
    if(NULL_PTR != CSFSV_HEADER(csfsv))
    {
        CSFSV_HDR *csfsv_hdr;

        csfsv_hdr = CSFSV_HEADER(csfsv);

        CSFSV_HDR_CUR_DISK_NO(csfsv_hdr)  = 0;
        CSFSV_HDR_CUR_BLOCK_NO(csfsv_hdr) = 0;
        CSFSV_HDR_CUR_PAGE_NO(csfsv_hdr)  = 0;
        CSFSV_HDR_DISK_NUM(csfsv_hdr)     = 0;
    }

    return (EC_TRUE);
}

EC_BOOL csfsv_hdr_clean(CSFSV *csfsv)
{
    if(NULL_PTR != CSFSV_HEADER(csfsv))
    {
        CSFSV_HDR *csfsv_hdr;

        csfsv_hdr = CSFSV_HEADER(csfsv);

        CSFSV_HDR_CUR_DISK_NO(csfsv_hdr)  = 0;
        CSFSV_HDR_CUR_BLOCK_NO(csfsv_hdr) = 0;
        CSFSV_HDR_CUR_PAGE_NO(csfsv_hdr)  = 0;
        CSFSV_HDR_DISK_NUM(csfsv_hdr)     = 0;
    }

    return (EC_TRUE);
}

STATIC_CAST static CSFSV_HDR *__csfsv_hdr_open(CSFSV *csfsv)
{
    CSFSV_HDR *csfsv_hdr;

    ASSERT_CSFSV_HDR_PAD_SIZE();

    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] __csfsv_hdr_open: fsize %u\n", CSFSV_FSIZE(csfsv));

    csfsv_hdr = (CSFSV_HDR *)mmap(NULL_PTR, CSFSV_FSIZE(csfsv), PROT_READ | PROT_WRITE, MAP_SHARED, CSFSV_FD(csfsv), 0);
    if(MAP_FAILED == csfsv_hdr)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:__csfsv_hdr_open: mmap file %s with fd %d failed, errno = %d, errstr = %s\n",
                           (char *)CSFSV_FNAME(csfsv), CSFSV_FD(csfsv), errno, strerror(errno));
        return (NULL_PTR);
    }
 
    return (csfsv_hdr);
}

CSFSV_HDR *csfsv_hdr_open(CSFSV *csfsv)
{
    if(SWITCH_ON == CSFS_DN_CACHE_IN_MEM)
    {
        return __csfsv_hdr_load(csfsv);
    }

    return __csfsv_hdr_open(csfsv);
}

STATIC_CAST static EC_BOOL __csfsv_hdr_close(CSFSV *csfsv)
{
    if(NULL_PTR != CSFSV_HEADER(csfsv))
    {
        if(0 != msync(CSFSV_HEADER(csfsv), CSFSV_FSIZE(csfsv), MS_SYNC))
        {
            dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:__csfsv_hdr_close: sync csfsv_hdr of %s with size %u failed\n",
                               CSFSV_FNAME(csfsv), CSFSV_FSIZE(csfsv));
        }
     
        if(0 != munmap(CSFSV_HEADER(csfsv), CSFSV_FSIZE(csfsv)))
        {
            dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:__csfsv_hdr_close: munmap csfsv of %s with size %u failed\n",
                               CSFSV_FNAME(csfsv), CSFSV_FSIZE(csfsv));
        }
    
        CSFSV_HEADER(csfsv) = NULL_PTR;     
    }

    return (EC_TRUE);
}

EC_BOOL csfsv_hdr_close(CSFSV *csfsv)
{
    if(SWITCH_ON == CSFS_DN_CACHE_IN_MEM)
    {
        return __csfsv_hdr_free(csfsv);
    }

    return __csfsv_hdr_close(csfsv);
}

STATIC_CAST static EC_BOOL __csfsv_hdr_sync(CSFSV *csfsv)
{
    if(NULL_PTR != CSFSV_HEADER(csfsv))
    {
        if(0 != msync(CSFSV_HEADER(csfsv), CSFSV_FSIZE(csfsv), MS_SYNC))
        {
            dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:__csfsv_hdr_sync: sync csfsv_hdr of %s with size %u failed\n",
                               CSFSV_FNAME(csfsv), CSFSV_FSIZE(csfsv));
        }     
    }

    return (EC_TRUE);
}

EC_BOOL csfsv_hdr_sync(CSFSV *csfsv)
{
    if(SWITCH_ON == CSFS_DN_CACHE_IN_MEM)
    {
        return __csfsv_hdr_flush(csfsv);
    }

    return __csfsv_hdr_sync(csfsv);
}

EC_BOOL csfsv_hdr_flush_size(const CSFSV_HDR *csfsv_hdr, UINT32 *size)
{
    (*size) += sizeof(CSFSV_HDR);
    return (EC_TRUE);
}

EC_BOOL csfsv_hdr_flush(const CSFSV_HDR *csfsv_hdr, int fd, UINT32 *offset)
{
    UINT32 osize;/*flush once size*/

    DEBUG(UINT32 offset_saved = *offset;);
 
    /*flush CSFSV_HDR_CUR_DISK_NO*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSV_HDR_CUR_DISK_NO(csfsv_hdr))))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_flush: flush CSFSV_HDR_CUR_DISK_NO at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CSFSV_HDR_CUR_BLOCK_NO*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSV_HDR_CUR_BLOCK_NO(csfsv_hdr))))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_flush: flush CSFSV_HDR_CUR_BLOCK_NO at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush CSFSV_HDR_CUR_PAGE_NO*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSV_HDR_CUR_PAGE_NO(csfsv_hdr))))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_flush: flush CSFSV_HDR_CUR_PAGE_NO at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 

    /*flush CSFSV_HDR_DISK_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSV_HDR_DISK_NUM(csfsv_hdr))))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_flush: flush CSFSV_HDR_DISK_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    /*skip rsvd01*/
    osize = CSFSV_HDR_PAD_SIZE * sizeof(uint8_t);
    if(EC_FALSE == c_file_pad(fd, offset, osize, FILE_PAD_CHAR))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_flush: pad %ld bytes at offset %u of fd %d failed\n", osize, (*offset), fd);
        return (EC_FALSE);
    } 

    DEBUG(CSFSV_ASSERT(sizeof(CSFSV_HDR) == (*offset) - offset_saved));

    return (EC_TRUE);
}

EC_BOOL csfsv_hdr_load(CSFSV_HDR *csfsv_hdr, int fd, UINT32 *offset)
{
    UINT32 osize;/*load once size*/

    /*load CSFSV_HDR_CUR_DISK_NO*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&CSFSV_HDR_CUR_DISK_NO(csfsv_hdr)))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_load: load CSFSV_HDR_CUR_DISK_NO at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 

    /*load CSFSV_HDR_CUR_BLOCK_NO*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&CSFSV_HDR_CUR_BLOCK_NO(csfsv_hdr)))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_load: load CSFSV_HDR_CUR_BLOCK_NO at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 


    /*load CSFSV_HDR_CUR_PAGE_NO*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&CSFSV_HDR_CUR_PAGE_NO(csfsv_hdr)))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_load: load CSFSV_HDR_CUR_PAGE_NO at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 


    /*load CSFSV_HDR_DISK_NUM*/
    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&CSFSV_HDR_DISK_NUM(csfsv_hdr)))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_hdr_load: load CSFSV_HDR_DISK_NUM at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 

    /*skip rsvd01*/
    (*offset) += CSFSV_HDR_PAD_SIZE * sizeof(uint8_t);

    return (EC_TRUE);
}

CSFSV *csfsv_new(const uint8_t *csfsv_fname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp)
{
    CSFSV      *csfsv;

    if(EC_TRUE == c_file_access((const char *)csfsv_fname, F_OK))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_new: %s already exist\n", csfsv_fname);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CSFSV, &csfsv, LOC_CSFSV_0010);
    if(NULL_PTR == csfsv)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_new:malloc csfsv failed\n");
        return (NULL_PTR);
    }

    csfsv_init(csfsv);
    csfsv_set_np(csfsv, np_node_err_pos, np_node_recycle, npp);

    CSFSV_FNAME(csfsv) = (uint8_t *)c_str_dup((char *)csfsv_fname);
    if(NULL_PTR == CSFSV_FNAME(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_new:str dup %s failed\n", csfsv_fname);
        csfsv_free(csfsv);
        return (NULL_PTR);
    }

    CSFSV_FD(csfsv) = c_file_open((const char *)csfsv_fname, O_RDWR | O_SYNC | O_CREAT, 0666);
    if(ERR_FD == CSFSV_FD(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_new: create %s failed\n", csfsv_fname);
        csfsv_free(csfsv);
        return (NULL_PTR);
    }

    CSFSV_FSIZE(csfsv) = sizeof(CSFSV_HDR);
    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] sizeof(CSFSV_HDR) = %u\n", sizeof(CSFSV_HDR));
    if(EC_FALSE == c_file_truncate(CSFSV_FD(csfsv), CSFSV_FSIZE(csfsv)))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_new: truncate %s to %u bytes failed\n", csfsv_fname, CSFSV_FSIZE(csfsv));
        csfsv_free(csfsv);
        return (NULL_PTR);
    }

    CSFSV_HEADER(csfsv) = csfsv_hdr_create(csfsv);
    if(NULL_PTR == CSFSV_HEADER(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_new: new csfsv header of file %s failed\n", csfsv_fname);
        csfsv_free(csfsv);
        return (NULL_PTR);
    }

    if(do_log(SEC_0164_CSFSV, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfsv_new: csfsv %p is\n", csfsv);
        csfsv_print(LOGSTDOUT, csfsv);
    }

    return (csfsv);
}

EC_BOOL csfsv_free(CSFSV *csfsv)
{
    if(NULL_PTR != csfsv)
    {
        csfsv_hdr_close(csfsv);

        if(ERR_FD != CSFSV_FD(csfsv))
        {
            c_file_close(CSFSV_FD(csfsv));
            CSFSV_FD(csfsv) = ERR_FD;
        }

        if(NULL_PTR != CSFSV_FNAME(csfsv))
        {
            safe_free(CSFSV_FNAME(csfsv), LOC_CSFSV_0011);
            CSFSV_FNAME(csfsv) = NULL_PTR;
        }

        free_static_mem(MM_CSFSV, csfsv, LOC_CSFSV_0012);
    }

    return (EC_TRUE);
}

CSFSV *csfsv_open(const uint8_t *csfsv_fname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp)
{
    CSFSV      *csfsv;
 
    uint16_t    disk_no;

    UINT32      fsize;
 
    if(EC_FALSE == c_file_access((const char *)csfsv_fname, F_OK))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_open: %s not exist\n", csfsv_fname);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CSFSV, &csfsv, LOC_CSFSV_0013);
    if(NULL_PTR == csfsv)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_open:malloc csfsv failed\n");
        return (NULL_PTR);
    }

    csfsv_init(csfsv);
    csfsv_set_np(csfsv, np_node_err_pos, np_node_recycle, npp);

    CSFSV_FNAME(csfsv) = (uint8_t *)c_str_dup((const char *)csfsv_fname);
    if(NULL_PTR == CSFSV_FNAME(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_open:str dup %s failed\n", csfsv_fname);
        csfsv_close(csfsv);
        return (NULL_PTR);
    }

    CSFSV_FD(csfsv) = c_file_open((const char *)csfsv_fname, O_RDWR | O_SYNC , 0666);
    if(ERR_FD == CSFSV_FD(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_open: open %s failed\n", csfsv_fname);
        csfsv_close(csfsv);
        return (NULL_PTR);
    }
    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_open: open %s done\n", csfsv_fname);

    if(EC_FALSE == c_file_size(CSFSV_FD(csfsv), &(fsize)))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_open: get size of %s failed\n", csfsv_fname);
        csfsv_close(csfsv);
        return (NULL_PTR);
    }
    CSFSV_FSIZE(csfsv) = (uint32_t)fsize;
    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_open: %s size = %ld\n", csfsv_fname, fsize);

    CSFSV_HEADER(csfsv) = csfsv_hdr_open(csfsv);
    if(NULL_PTR == CSFSV_HEADER(csfsv))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_open: open csfsv header of file %s failed\n", csfsv_fname);
        csfsv_close(csfsv);
        return (NULL_PTR);
    }

    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_open: %s, disk num %u\n", csfsv_fname, CSFSV_DISK_NUM(csfsv));

    /*mount disks*/
    for(disk_no = 0; disk_no < CSFSV_DISK_NUM(csfsv); disk_no ++)
    {
        /*try to mount the disk. ignore any failure*/
        csfsv_mount_disk(csfsv, disk_no);
    }
 
    return (csfsv);
}

EC_BOOL csfsv_close(CSFSV *csfsv)
{
    if(NULL_PTR != csfsv)
    {
        uint16_t disk_no;
     
        /*clean disks*/
        for(disk_no = 0; disk_no < CSFSV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CSFSV_DISK_CSFSD(csfsv, disk_no))
            {
                csfsd_close(CSFSV_DISK_CSFSD(csfsv, disk_no));
                CSFSV_DISK_CSFSD(csfsv, disk_no) = NULL_PTR;
            }
        }
 
        csfsv_hdr_close(csfsv);

        if(ERR_FD != CSFSV_FD(csfsv))
        {
            c_file_close(CSFSV_FD(csfsv));
            CSFSV_FD(csfsv) = ERR_FD;
        }

        if(NULL_PTR != CSFSV_FNAME(csfsv))
        {
            safe_free(CSFSV_FNAME(csfsv), LOC_CSFSV_0014);
            CSFSV_FNAME(csfsv) = NULL_PTR;
        }

        free_static_mem(MM_CSFSV, csfsv, LOC_CSFSV_0015);
    }
    return (EC_TRUE);
}

EC_BOOL csfsv_sync(CSFSV *csfsv)
{
    if(NULL_PTR != csfsv)
    {
        uint16_t disk_no;
     
        /*clean disks*/
        for(disk_no = 0; disk_no < CSFSV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CSFSV_DISK_CSFSD(csfsv, disk_no))
            {
                csfsd_sync(CSFSV_DISK_CSFSD(csfsv, disk_no));
            }
        }
 
        csfsv_hdr_sync(csfsv);
    }
    return (EC_TRUE);
}

/* one disk = 1TB */
EC_BOOL csfsv_init(CSFSV *csfsv)
{
    if(NULL_PTR != csfsv)
    {
        uint16_t disk_no;

        CSFSV_FD(csfsv)    = ERR_FD;
        CSFSV_FNAME(csfsv) = NULL_PTR;
        CSFSV_FSIZE(csfsv) = 0;
        CSFSV_HEADER(csfsv)= NULL_PTR;

        for(disk_no = 0; disk_no < CSFSV_MAX_DISK_NUM; disk_no ++)
        {
            CSFSV_DISK_CSFSD(csfsv, disk_no) = NULL_PTR;
        }

        //CSFSV_NP_NODE_ERR_POS(csfsv) = xxx;
        CSFSV_NP_NODE_RECYCLE(csfsv) = NULL_PTR;
        CSFSV_NPP(csfsv)             = NULL_PTR;
    }
    return (EC_TRUE);
}

/*note: csfsv_clean is for not applying mmap*/
EC_BOOL csfsv_clean(CSFSV *csfsv)
{
    uint16_t disk_no;

    if(ERR_FD != CSFSV_FD(csfsv))
    {
        c_file_close(CSFSV_FD(csfsv));
        CSFSV_FD(csfsv) = ERR_FD;
    }

    if(NULL_PTR != CSFSV_FNAME(csfsv))
    {
        safe_free(CSFSV_FNAME(csfsv), LOC_CSFSV_0016);
        CSFSV_FNAME(csfsv) = NULL_PTR;
    }

    for(disk_no = 0; disk_no < CSFSV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CSFSV_DISK_CSFSD(csfsv, disk_no))
        {        
            safe_free(CSFSV_DISK_CSFSD(csfsv, disk_no), LOC_CSFSV_0017);
            CSFSV_DISK_CSFSD(csfsv, disk_no) = NULL_PTR;
        }
    }

    //CSFSV_NP_NODE_ERR_POS(csfsv) = xxx;
    CSFSV_NP_NODE_RECYCLE(csfsv) = NULL_PTR;
    CSFSV_NPP(csfsv)             = NULL_PTR; 

    if(NULL_PTR != CSFSV_HEADER(csfsv))
    {
        csfsv_hdr_clean(csfsv);
        safe_free(CSFSV_HEADER(csfsv), LOC_CSFSV_0018);
        CSFSV_HEADER(csfsv) = NULL_PTR;
    }
 
    return (EC_TRUE); 
}

EC_BOOL csfsv_set_np(CSFSV *csfsv, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp)
{
    if(NULL_PTR == csfsv)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_set_np: csfsv is null\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != np_node_recycle);
    ASSERT(NULL_PTR != npp);

    CSFSV_NP_NODE_ERR_POS(csfsv) = np_node_err_pos;
    CSFSV_NP_NODE_RECYCLE(csfsv) = np_node_recycle;
    CSFSV_NPP(csfsv)             = npp;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsv_rmv_disk(CSFSV *csfsv, const uint16_t disk_no)
{
    uint8_t *csfsd_fname;

    csfsd_fname = __csfsv_new_disk_fname(csfsv, disk_no);
    if(NULL_PTR == csfsd_fname)
    {
        dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:__csfsv_rmv_disk: new disk %u fname failed, suggest remove it manually\n", disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsd_rmv(csfsd_fname))
    {
        dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:__csfsv_rmv_disk: rmv disk %u csfsd %s failed, suggest remove it manually\n", disk_no, (char *)csfsd_fname);
        __csfsv_free_disk_fname(csfsv, csfsd_fname);
        return (EC_FALSE);
    }
 
    __csfsv_free_disk_fname(csfsv, csfsd_fname);

    return (EC_TRUE);
}

EC_BOOL csfsv_add_disk(CSFSV *csfsv, const uint16_t disk_no)
{
    uint8_t *csfsd_fname;
    CSFSD *csfsd;

    if(CSFSV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_add_disk: disk %u overflow the max disk num %u\n", disk_no, CSFSV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    if(NULL_PTR != CSFSV_DISK_CSFSD(csfsv, disk_no))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_add_disk: disk %u already exist\n", disk_no);
        return (EC_FALSE);
    }

    csfsd_fname = __csfsv_new_disk_fname(csfsv, disk_no);
    if(NULL_PTR == csfsd_fname)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_add_disk: new disk %u fname failed\n", disk_no);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0164_CSFSV, 3)(LOGSTDOUT, "info:csfsv_add_disk: try to create disk %s ...\n", csfsd_fname);
 
    csfsd = csfsd_new(csfsd_fname, CSFSD_MAX_BLOCK_NUM, CSFSV_NP_NODE_ERR_POS(csfsv), CSFSV_NP_NODE_RECYCLE(csfsv), CSFSV_NPP(csfsv));
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_add_disk: create disk %u failed\n", disk_no);
        __csfsv_free_disk_fname(csfsv, csfsd_fname);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0164_CSFSV, 3)(LOGSTDOUT, "info:csfsv_add_disk: create disk %s done\n", csfsd_fname); 
    __csfsv_free_disk_fname(csfsv, csfsd_fname);

    /*add disk to volume*/
    CSFSV_DISK_CSFSD(csfsv, disk_no) = csfsd;
    CSFSV_DISK_NUM(csfsv) ++;

    return (EC_TRUE);
}

EC_BOOL csfsv_del_disk(CSFSV *csfsv, const uint16_t disk_no)
{
    CSFSD    *csfsd;

    if(CSFSV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_del_disk: disk %u overflow the max disk num %u\n", disk_no, CSFSV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    csfsd = CSFSV_DISK_CSFSD(csfsv, disk_no);
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_del_disk: disk %u not exist\n", disk_no);
        return (EC_FALSE);
    }

    /*adjust csfsv statistics*/
    CSFSV_DISK_NUM(csfsv) --;
    CSFSV_DISK_CSFSD(csfsv, disk_no) = NULL_PTR;

    csfsd_close(csfsd); 

    if(EC_FALSE == __csfsv_rmv_disk(csfsv, disk_no))
    {
        dbg_log(SEC_0164_CSFSV, 1)(LOGSTDOUT, "warn:csfsv_del_disk: rmv disk %u failed, should remove it manually\n", disk_no);
    }
 
    return (EC_TRUE);
}

EC_BOOL csfsv_mount_disk(CSFSV *csfsv, const uint16_t disk_no)
{
    uint8_t *csfsd_fname;
    CSFSD    *csfsd;

    if(CSFSV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_mount_disk: disk %u overflow the max disk num %u\n", disk_no, CSFSV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    if(NULL_PTR != CSFSV_DISK_CSFSD(csfsv, disk_no))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_mount_disk: disk %u already exist\n", disk_no);
        return (EC_FALSE);
    }

    csfsd_fname = __csfsv_new_disk_fname(csfsv, disk_no);
    if(NULL_PTR == csfsd_fname)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_mount_disk: new disk %u fname failed\n", disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsd_exist(csfsd_fname))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_mount_disk: disk %u at %s not exist\n", disk_no, csfsd_fname);
        __csfsv_free_disk_fname(csfsv, csfsd_fname);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0164_CSFSV, 3)(LOGSTDOUT, "info:csfsv_mount_disk: try to mount disk %u from %s ...\n", disk_no, csfsd_fname);
    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_mount_disk: check CSFSD_MAX_BLOCK_NUM = %d\n", CSFSD_MAX_BLOCK_NUM);
 
    csfsd = csfsd_open(csfsd_fname);
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_mount_disk: open disk %u from %s failed\n", disk_no, csfsd_fname);
        __csfsv_free_disk_fname(csfsv, csfsd_fname);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0164_CSFSV, 3)(LOGSTDOUT, "info:csfsv_mount_disk: open disk %s done\n", csfsd_fname); 
    __csfsv_free_disk_fname(csfsv, csfsd_fname);

    csfsd_set_np(csfsd, CSFSV_NP_NODE_ERR_POS(csfsv), CSFSV_NP_NODE_RECYCLE(csfsv), CSFSV_NPP(csfsv));

    /*add disk to volume*/
    CSFSV_DISK_CSFSD(csfsv, disk_no) = csfsd;

    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_mount_disk: disk %u done\n", disk_no); 

    return (EC_TRUE);
}

EC_BOOL csfsv_umount_disk(CSFSV *csfsv, const uint16_t disk_no)
{
    CSFSD    *csfsd;

    if(CSFSV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_umount_disk: disk %u overflow the max disk num %u\n", disk_no, CSFSV_MAX_DISK_NUM);
        return (EC_FALSE);
    } 

    csfsd = CSFSV_DISK_CSFSD(csfsv, disk_no);
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_umount_disk: disk %u not exist\n", disk_no);
        return (EC_FALSE);
    }
 
    CSFSV_DISK_CSFSD(csfsv, disk_no) = NULL_PTR;
 
    csfsd_close(csfsd);
 
    return (EC_TRUE);
}

EC_BOOL csfsv_new_space(CSFSV *csfsv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CSFSD    *csfsd;
 
    uint16_t page_num;
 
    uint16_t disk_no_t;
    uint16_t block_no_t;
    uint16_t page_no_t;
 
    CSFSV_ASSERT(0 < size);

    if(CSFSB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDERR, "error:csfsv_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num = (uint16_t)((size + CSFSB_PAGE_BYTE_SIZE - 1) >> CSFSB_PAGE_BIT_SIZE);

    disk_no_t  = CSFSV_CUR_DISK_NO(csfsv);
    block_no_t = CSFSV_CUR_BLOCK_NO(csfsv);
    page_no_t  = CSFSV_CUR_PAGE_NO(csfsv);

    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_new_space: page_num %u, (%u, %u, %u)\n",
                page_num, disk_no_t, block_no_t, page_no_t);

    do
    {
        csfsd = CSFSV_DISK_NODE(csfsv, disk_no_t);
        if(NULL_PTR != csfsd)
        {
            if(EC_TRUE == csfsd_new_space(csfsd, page_num, &block_no_t, &page_no_t))
            {
                dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_new_space: size %u, disk %u done\n", size, disk_no_t);

                (*disk_no)  = disk_no_t;
                (*block_no) = block_no_t;
                (*page_no)  = page_no_t;

                dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_new_space: page_num %u, (%u, %u, %u) => (%u, %u, %u)\n",
                            page_num,
                            CSFSV_CUR_DISK_NO(csfsv), CSFSV_CUR_BLOCK_NO(csfsv), CSFSV_CUR_PAGE_NO(csfsv),
                            disk_no_t, block_no_t, page_no_t + page_num);

                /**
                 *
                 * WARNING:
                 *  when new space from csfsd, the data from current location (disk_no, block_no, page_no) had been lost,
                 *  and space is ready (free) to accept new data.
                 *  but if current location updated and write datanode failed later, the space would never be used due to
                 *  current location is changed.
                 *
                 **/
                CSFSV_CUR_DISK_NO(csfsv)  = disk_no_t;
                CSFSV_CUR_BLOCK_NO(csfsv) = block_no_t;
                CSFSV_CUR_PAGE_NO(csfsv)  = page_no_t + page_num;
             
                return (EC_TRUE);
            }
        }
        dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_new_space: size %u, disk %u failed\n", size, disk_no_t);

        disk_no_t  = (disk_no_t + 1) % CSFSV_DISK_NUM(csfsv);
        block_no_t = 0;
        page_no_t  = 0;

        dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_new_space: size %u, move to next disk %u\n", size, disk_no_t);
    }while(disk_no_t != CSFSV_CUR_DISK_NO(csfsv) && block_no_t != CSFSV_CUR_BLOCK_NO(csfsv) && page_no_t != CSFSV_CUR_PAGE_NO(csfsv));

    return (EC_FALSE);
}

EC_BOOL csfsv_bind(CSFSV *csfsv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t np_id, const uint32_t np_node_pos)
{
    CSFSD    *csfsd;

    csfsd = CSFSV_DISK_NODE(csfsv, disk_no);
    if(NULL_PTR == csfsd)
    {
        dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "error:csfsv_bind: disk %u is null\n", disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsd_bind(csfsd, block_no, page_no, np_id, np_node_pos))
    {
        dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "error:csfsv_bind: bind (disk %u, block %u, page %u) and (np %u, pos %u) failed\n",
                    disk_no, block_no, page_no, np_id, np_node_pos);
        return (EC_FALSE);
    }

    dbg_log(SEC_0164_CSFSV, 9)(LOGSTDOUT, "[DEBUG] csfsv_bind: bind (disk %u, block %u, page %u) and (np %u, pos %u) done\n",
                    disk_no, block_no, page_no, np_id, np_node_pos);

    return (EC_TRUE);
}

EC_BOOL csfsv_flush_size(const CSFSV *csfsv, UINT32 *size)
{
    uint16_t disk_no;

    csfsv_hdr_flush_size(CSFSV_HEADER(csfsv), size); 
 
    for(disk_no = 0; disk_no < CSFSV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CSFSV_DISK_NODE(csfsv, disk_no))
        {
            (*size) += sizeof(uint16_t);/*disk_no*/     
            csfsd_flush_size(CSFSV_DISK_NODE(csfsv, disk_no), size);
        }
    }
    return (EC_TRUE);
}

EC_BOOL csfsv_flush(const CSFSV *csfsv, int fd, UINT32 *offset)
{
    UINT32   osize;
    uint16_t disk_no; 

    DEBUG(UINT32 offset_saved = *offset;);

    /*flush CSFSV_HEADER*/
    if(EC_FALSE == csfsv_hdr_flush(CSFSV_HEADER(csfsv), fd, offset))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_flush: flush CSFSV_HEADER at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    DEBUG(CSFSV_ASSERT(sizeof(CSFSV_HDR) == (*offset) - offset_saved));

    /*flush CSFSV_DISK_NODE table*/
    for(disk_no = 0; disk_no < CSFSV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR == CSFSV_DISK_NODE(csfsv, disk_no))
        {
            continue;
        }

        /*flush disk_no*/
        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(disk_no)))
        {
            dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_flush: flush disk_no at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }     

        /*flush disk*/
        if(EC_FALSE == csfsd_flush(CSFSV_DISK_NODE(csfsv, disk_no), fd, offset))
        {
            dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_flush: flush CSFSV_DISK_NODE of disk_no %u at offset %u of fd %d failed\n",
                                disk_no, (*offset), fd);
            return (EC_FALSE);
        }
    }
 
    return (EC_TRUE);
}

EC_BOOL csfsv_load(CSFSV *csfsv, int fd, UINT32 *offset)
{
    UINT32   osize;
 
    uint16_t disk_num;
    uint16_t disk_idx; 
    uint16_t disk_no;

    if(NULL_PTR == CSFSV_HEADER(csfsv))
    {
        CSFSV_HEADER(csfsv) = safe_malloc(sizeof(CSFSV_HDR), LOC_CSFSV_0019);
        if(NULL_PTR == CSFSV_HEADER(csfsv))
        {
            dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_load: malloc CSFSV_HDR failed\n");
            return (EC_FALSE);
        }
    }

    /*load rbtree pool*/
    if(EC_FALSE == csfsv_hdr_load(CSFSV_HEADER(csfsv), fd, offset))
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_load: load CSFSV_HEADER at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    disk_num = CSFSV_DISK_NUM(csfsv);
    if(CSFSV_MAX_DISK_NUM <= disk_num)
    {
        dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_load: loaded disk_num %u overflow!\n", disk_num);
        return (EC_FALSE);
    }

    for(disk_no = 0; disk_no < CSFSV_MAX_DISK_NUM; disk_no ++)
    {
        CSFSV_DISK_CSFSD(csfsv, disk_no) = NULL_PTR;
    }

    /*load CSFSV_DISK_NODE table*/
    for(disk_idx = 0; disk_idx < disk_num; disk_idx ++)
    {
        /*load disk_no*/
        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(disk_no)))
        {
            dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_load: load disk_no at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }  

        if(CSFSV_MAX_DISK_NUM <= disk_no)
        {
            dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_load: loaded disk_no %u overflow!\n", disk_no);
            return (EC_FALSE);
        }     
     
        CSFSV_DISK_CSFSD(csfsv, disk_no) = safe_malloc(sizeof(CSFSD), LOC_CSFSV_0020);
        if(NULL_PTR == CSFSV_DISK_CSFSD(csfsv, disk_no))
        {
            dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_load: malloc block %u failed\n", disk_no);
            return (EC_FALSE);
        }
     
        if(EC_FALSE == csfsd_load(CSFSV_DISK_CSFSD(csfsv, disk_no), fd, offset))
        {
            dbg_log(SEC_0164_CSFSV, 0)(LOGSTDOUT, "error:csfsv_load: load CSFSV_DISK_NODE of disk_no %u at offset %u of fd %d failed\n",
                                disk_no, (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

void csfsv_print(LOG *log, const CSFSV *csfsv)
{
    CSFSV_ASSERT(NULL_PTR != csfsv);
 
    sys_log(log, "csfsv_print: csfsv %p, disk num %u, cur (disk %u, block %u, page %u)\n", csfsv,
                 CSFSV_DISK_NUM(csfsv),
                 CSFSV_CUR_DISK_NO(csfsv), CSFSV_CUR_BLOCK_NO(csfsv), CSFSV_CUR_PAGE_NO(csfsv));

    if(1)
    {
        uint16_t  disk_no;
        for(disk_no = 0; disk_no < CSFSV_DISK_NUM(csfsv); disk_no ++)
        {
            if(NULL_PTR != CSFSV_DISK_NODE(csfsv, disk_no))
            {
                sys_log(log, "csfsv_print: csfsv %p, disk %u is\n", csfsv, disk_no);
                csfsd_print(log, CSFSV_DISK_NODE(csfsv, disk_no));
            }
        }
    }

    return; 
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

