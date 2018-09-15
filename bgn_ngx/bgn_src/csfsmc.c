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

#include "chashalgo.h"
#include "cdsk.h"
#include "cstack.h"
#include "cmd5.h"

#include "cpgrb.h"
#include "cpgd.h"
#include "csfsnprb.h"
#include "csfsnp.h"
#include "csfsmc.h"
#include "csfs.h"
#include "csfsmclist.h"

CSFSMC *csfsmc_new(const UINT32 csfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num)
{
    CSFSMC *csfsmc;

    csfsmc = (CSFSMC *)safe_malloc(sizeof(CSFSMC), LOC_CSFSMC_0001);
    if(NULL_PTR == csfsmc)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_new: new csfsmc failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csfsmc_init(csfsmc, csfs_md_id, np_id, np_model, hash_1st_algo_id, hash_2nd_algo_id, bucket_max_num, block_num))
    {
        safe_free(csfsmc, LOC_CSFSMC_0002);
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_new: init csfsmc failed\n");
        return (NULL_PTR);
    }

    return (csfsmc);
}

EC_BOOL csfsmc_init(CSFSMC *csfsmc, const UINT32 csfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num)
{
    CSFSNP            *csfsnp;
    CPGD              *cpgd;
    CSFSMCLIST        *mclist;
    uint32_t           mclist_max_num;
    UINT32             mcache_size;

    csfsnp = csfsnp_mem_create(np_id, np_model, hash_1st_algo_id, hash_2nd_algo_id, bucket_max_num);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_init: create mem np %u with model %u, hash %u failed\n",
                           np_id, np_model, hash_2nd_algo_id);
        return (EC_FALSE);
    }

    cpgd = cpgd_mem_new(block_num);
    if(NULL_PTR == cpgd)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_init: new mem pgd with %u blocks failed\n", block_num);
        csfsnp_mem_free(csfsnp);
        return (EC_FALSE);
    }

    mclist_max_num = CSFSNP_ITEMS_MAX_NUM(csfsnp);

    mclist = csfsmclist_new(mclist_max_num);
    if(NULL_PTR == mclist)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_init: new csfsmclist with %u nodes failed\n", mclist_max_num);
        cpgd_mem_free(cpgd);
        csfsnp_mem_free(csfsnp);
        return (EC_FALSE);
    }

    mcache_size = ((UINT32)block_num) * CPGD_BLOCK_PAGE_NUM * CPGB_PAGE_BYTE_SIZE;
    CSFSMC_MCACHE(csfsmc) = safe_malloc(mcache_size, LOC_CSFSMC_0003);
    if(NULL_PTR == CSFSMC_MCACHE(csfsmc))
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_init: new mcache with %ld bytes failed\n", mcache_size);
        csfsmclist_free(mclist);
        cpgd_mem_free(cpgd);
        csfsnp_mem_free(csfsnp);
        return (EC_FALSE);
    }

    CSFSMC_CSFS_MD_ID(csfsmc) = csfs_md_id;
    CSFSMC_NP(csfsmc)         = csfsnp;
    CSFSMC_PGD(csfsmc)        = cpgd;
    CSFSMC_LIST(csfsmc)       = mclist;

    return (EC_TRUE);
}

EC_BOOL csfsmc_clean(CSFSMC *csfsmc)
{
    ASSERT(NULL_PTR != csfsmc);

    if(NULL_PTR != CSFSMC_NP(csfsmc))
    {
        csfsnp_mem_free(CSFSMC_NP(csfsmc));
        CSFSMC_NP(csfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CSFSMC_PGD(csfsmc))
    {
        cpgd_mem_free(CSFSMC_PGD(csfsmc));
        CSFSMC_PGD(csfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CSFSMC_LIST(csfsmc))
    {
        csfsmclist_free(CSFSMC_LIST(csfsmc));
        CSFSMC_LIST(csfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CSFSMC_MCACHE(csfsmc))
    {
        safe_free(CSFSMC_MCACHE(csfsmc), LOC_CSFSMC_0004);
        CSFSMC_MCACHE(csfsmc) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL csfsmc_free(CSFSMC *csfsmc)
{
    if(NULL_PTR != csfsmc)
    {
        csfsmc_clean(csfsmc);
        safe_free(csfsmc, LOC_CSFSMC_0005);
    }

    return (EC_TRUE);
}

CSFSNP_FNODE *csfsmc_reserve_np_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, uint32_t *node_pos)
{
    CSFSNP *csfsnp;
    CSFSNP_ITEM *csfsnp_item;
    uint32_t node_pos_t;

    csfsnp = CSFSMC_NP(csfsmc);

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_reserve_np_no_lock: set mem np beg\n");

    node_pos_t = csfsnp_insert(csfsnp, cstring_get_len(file_path), cstring_get_str(file_path));
    if(CSFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_reserve_np_no_lock: insert file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_reserve_np_no_lock: insert file %s to node_pos %u done\n",
                        (char *)cstring_get_str(file_path), node_pos_t);

    csfsnp_item = csfsnp_fetch(csfsnp, node_pos_t);

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_reserve_np_no_lock: set mem np end\n");

    if(do_log(SEC_0174_CSFSMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfsmc_reserve_np_no_lock: reserved csfsnp_item %p is\n", csfsnp_item);
        csfsnp_item_print(LOGSTDOUT, csfsnp_item);
    }

    (*node_pos) = node_pos_t;

    /*not import yet*/
    return CSFSNP_ITEM_FNODE(csfsnp_item);
}

EC_BOOL csfsmc_release_np_no_lock(CSFSMC *csfsmc, const CSTRING *file_path)
{
    CSFSNP *csfsnp;

    csfsnp = CSFSMC_NP(csfsmc);

    if(EC_FALSE == csfsnp_delete(csfsnp, cstring_get_len(file_path), cstring_get_str(file_path)))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_release_np_no_lock: delete file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsmc_reserve_dn_no_lock(CSFSMC *csfsmc, const uint32_t size, uint16_t *block_no, uint16_t *page_no)
{
    CPGD *cpgd;

    cpgd = CSFSMC_PGD(csfsmc);

    if(EC_FALSE == cpgd_new_space(cpgd, size, block_no, page_no))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDERR, "error:csfsmc_reserve_dn_no_lock: reserve size %u failed\n", size);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsmc_release_dn_no_lock(CSFSMC *csfsmc, const uint32_t size, const uint16_t block_no, const uint16_t page_no)
{
    CPGD *cpgd;

    cpgd = CSFSMC_PGD(csfsmc);

    if(EC_FALSE == cpgd_free_space(cpgd, block_no, page_no, size))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_release_dn_no_lock: release space of block_no %u, page_no %u, size %u failed\n",
                           block_no, page_no, size);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsmc_release_dn_no_lock(CSFSMC *csfsmc, const CSFSNP_FNODE *csfsnp_fnode)
{
    const CSFSNP_INODE *csfsnp_inode;

    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);

    /*note: disk_no was ignored*/
    return csfsmc_release_dn_no_lock(csfsmc,
                                     CSFSNP_FNODE_FILESZ(csfsnp_fnode),
                                     CSFSNP_INODE_BLOCK_NO(csfsnp_inode),
                                     CSFSNP_INODE_PAGE_NO(csfsnp_inode));
}


EC_BOOL csfsmc_import_dn_no_lock(CSFSMC *csfsmc, const CBYTES *cbytes, const CSFSNP_FNODE *csfsnp_fnode)
{
    const CSFSNP_INODE *csfsnp_inode;

    uint32_t size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    size = (uint32_t)CBYTES_LEN(cbytes);

    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    block_no = CSFSNP_INODE_BLOCK_NO(csfsnp_inode);
    page_no  = CSFSNP_INODE_PAGE_NO(csfsnp_inode) ;

    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    BCOPY(CBYTES_BUF(cbytes), CSFSMC_MCACHE(csfsmc) + offset, size);

    return (EC_TRUE);
}

/*for debug only*/
STATIC_CAST static REAL __csfsmc_room_ratio(CSFSMC *csfsmc)
{
    CPGD *cpgd;
    double ratio;

    cpgd = CSFSMC_PGD(csfsmc);
    ratio = (CPGD_PAGE_USED_NUM(cpgd) + 0.0) / (CPGD_PAGE_MAX_NUM(cpgd)  + 0.0);
    return (ratio);
}

EC_BOOL csfsmc_room_is_ok_no_lock(CSFSMC *csfsmc, const REAL level)
{
    //CSFSNP   *csfsnp;
    CPGD     *cpgd;

    uint64_t  used_page;
    uint64_t  max_page;
    double    ratio;

    cpgd   = CSFSMC_PGD(csfsmc);
    //csfsnp = CSFSMC_NP(csfsmc);

    used_page = (uint64_t)CPGD_PAGE_USED_NUM(cpgd);
    max_page  = (uint64_t)CPGD_PAGE_MAX_NUM(cpgd);

    ratio = (used_page + 0.0) / (max_page  + 0.0);

    if(ratio < level)
    {
        return (EC_TRUE); /*ok*/
    }
    return (EC_FALSE);/*NOT ok*/
}

EC_BOOL csfsmc_write_dn_no_lock(CSFSMC *csfsmc, CSFSNP_FNODE *csfsnp_fnode, const CBYTES *cbytes )
{
    CSFSNP_INODE *csfsnp_inode;

    uint32_t size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    size = (uint32_t)cbytes_len(cbytes);

    if(EC_FALSE == csfsmc_reserve_dn_no_lock(csfsmc, size, &block_no, &page_no))
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_write_dn_no_lock: freserve dn with size %u failed\n", size);
        return (EC_FALSE);
    }

    csfsnp_fnode_init(csfsnp_fnode);
    CSFSNP_FNODE_FILESZ(csfsnp_fnode) = size;
    CSFSNP_FNODE_REPNUM(csfsnp_fnode) = 1;

    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    //CSFSNP_INODE_CACHE_FLAG(csfsnp_inode) = CSFSDN_DATA_NOT_IN_CACHE;
    CSFSNP_INODE_DISK_NO(csfsnp_inode)    = CSFSMC_DISK_NO;
    CSFSNP_INODE_BLOCK_NO(csfsnp_inode)   = block_no;
    CSFSNP_INODE_PAGE_NO(csfsnp_inode)    = page_no;

    /*import data to memcache*/
    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_write_dn_no_lock: size %u, block %u, page %u, offset %ld\n",
                       size, block_no, page_no, offset);
    BCOPY(CBYTES_BUF(cbytes), CSFSMC_MCACHE(csfsmc) + offset, size);

    return (EC_TRUE);
}

EC_BOOL csfsmc_write_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    CSFSNP_FNODE *csfsnp_fnode;
    uint32_t  node_pos;

    csfsnp_fnode = csfsmc_reserve_np_no_lock(csfsmc, file_path, &node_pos);

    if(NULL_PTR == csfsnp_fnode)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_write_no_lock: file %s reserve np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsmc_write_dn_no_lock(csfsmc, csfsnp_fnode, cbytes ))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_write_no_lock: file %s write dn failed\n",
                           (char *)cstring_get_str(file_path));
        csfsmc_release_np_no_lock(csfsmc, file_path);
        return (EC_FALSE);
    }

    /*add to memcache*/
    csfsmclist_node_add_head(CSFSMC_LIST(csfsmc), node_pos);

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_write_no_lock: write to mem cache at %u done\n", node_pos);

    return (EC_TRUE);
}

EC_BOOL csfsmc_read_np_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, CSFSNP_FNODE *csfsnp_fnode, uint32_t *node_pos)
{
    CSFSNP *csfsnp;

    uint32_t node_pos_t;

    csfsnp = CSFSMC_NP(csfsmc);

    node_pos_t = csfsnp_search_no_lock(csfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path));
    if(CSFSNPRB_ERR_POS != node_pos_t)
    {
        CSFSMCLIST * csfsmclist;

        if(NULL_PTR != csfsnp_fnode)
        {
            CSFSNP_ITEM *csfsnp_item;
            csfsnp_item = csfsnp_fetch(csfsnp, node_pos_t);
            csfsnp_fnode_import(CSFSNP_ITEM_FNODE(csfsnp_item), csfsnp_fnode);
        }

        if(NULL_PTR != node_pos)
        {
            (*node_pos) = node_pos_t;
        }

        /*update LRU list*/
        csfsmclist = CSFSMC_LIST(csfsmc);

        csfsmclist_node_lru_update(csfsmclist, node_pos_t);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/* check whether np is in memcache only, do not read np or change the lru list */
EC_BOOL csfsmc_check_np(CSFSMC *csfsmc, const CSTRING *file_path)
{
    CSFSNP *csfsnp;
    uint32_t node_pos_t;

    csfsnp = CSFSMC_NP(csfsmc);
    node_pos_t = csfsnp_search_no_lock(csfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path));

    if(CSFSNPRB_ERR_POS != node_pos_t) /* file is in memcache */
    {
        return (EC_TRUE);
    }
    /* file is NOT in memcache */
    return (EC_FALSE);
}

EC_BOOL csfsmc_read_e_dn_no_lock(CSFSMC *csfsmc, const CSFSNP_FNODE *csfsnp_fnode, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    const CSFSNP_INODE *csfsnp_inode;

    uint32_t file_size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;
    UINT32   max_len;

    file_size    = CSFSNP_FNODE_FILESZ(csfsnp_fnode);
    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    block_no = CSFSNP_INODE_BLOCK_NO(csfsnp_inode);
    page_no  = CSFSNP_INODE_PAGE_NO(csfsnp_inode) ;

    if(0 == store_size)
    {
        cbytes_clean(cbytes);
        return (EC_TRUE);
    }

    if((*store_offset) >= file_size)
    {
        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_read_e_dn_no_lock: read file failed due to offset %ld overflow file size %u\n",
                           (*store_offset), file_size);
        return (EC_FALSE);
    }

    if((*store_offset) + store_size >= file_size)
    {
        max_len = file_size - (*store_offset);
    }
    else
    {
        max_len = store_size;
    }

    /*export data from memcache*/
    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE))
            + (*store_offset);

    if(CBYTES_LEN(cbytes) < max_len)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CSFSMC_0006);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len, LOC_CSFSMC_0007);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    BCOPY(CSFSMC_MCACHE(csfsmc) + offset, CBYTES_BUF(cbytes), max_len);
    CBYTES_LEN(cbytes) = max_len;

    (*store_offset) += max_len;

    return (EC_TRUE);
}

EC_BOOL csfsmc_read_dn_no_lock(CSFSMC *csfsmc, const CSFSNP_FNODE *csfsnp_fnode, CBYTES *cbytes)
{
    const CSFSNP_INODE *csfsnp_inode;

    uint32_t file_size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    file_size    = CSFSNP_FNODE_FILESZ(csfsnp_fnode);
    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    block_no = CSFSNP_INODE_BLOCK_NO(csfsnp_inode);
    page_no  = CSFSNP_INODE_PAGE_NO(csfsnp_inode) ;

    /*export data from memcache*/
    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CSFSMC_0008);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CSFSMC_0009);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    BCOPY(CSFSMC_MCACHE(csfsmc) + offset, CBYTES_BUF(cbytes), file_size);
    CBYTES_LEN(cbytes) = file_size;

    return (EC_TRUE);
}


EC_BOOL csfsmc_read_e_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    CSFSNP_FNODE csfsnp_fnode;

    csfsnp_fnode_init(&csfsnp_fnode);

    if(EC_FALSE == csfsmc_read_np_no_lock(csfsmc, file_path, &csfsnp_fnode, NULL_PTR))
    {
        dbg_log(SEC_0174_CSFSMC, 5)(LOGSTDOUT, "warn:csfsmc_read_e_no_lock: read file %s from np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsmc_read_e_dn_no_lock(csfsmc, &csfsnp_fnode, store_offset, store_size, cbytes))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_read_e_no_lock: read file %s from dn failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsmc_file_size_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, uint64_t *file_size)
{
    CSFSNP  *csfsnp;
    uint32_t cur_file_size;

    EC_BOOL ret;

    csfsnp = CSFSMC_NP(csfsmc);

    ret = csfsnp_file_size(csfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cur_file_size);
    if(EC_FALSE== ret)
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_file_size_no_lock: get size of file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    (*file_size) = cur_file_size;

    return (EC_TRUE);
}

EC_BOOL csfsmc_read_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, CBYTES *cbytes)
{
    CSFSNP_FNODE csfsnp_fnode;

    csfsnp_fnode_init(&csfsnp_fnode);

    if(EC_FALSE == csfsmc_read_np_no_lock(csfsmc, file_path, &csfsnp_fnode, NULL_PTR))
    {
        dbg_log(SEC_0174_CSFSMC, 5)(LOGSTDOUT, "warn:csfsmc_read_no_lock: read file %s from np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsmc_read_dn_no_lock(csfsmc, &csfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_read_dn_no_lock: read file %s from dn failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsmc_update_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    CSFSNP       *csfsnp;
    CSFSNP_ITEM  *csfsnp_item;
    CSFSNP_FNODE *csfsnp_fnode;

    uint32_t node_pos;

    if(EC_FALSE == csfsmc_read_np_no_lock(csfsmc, file_path, NULL_PTR, &node_pos))
    {
         /*
          * before write to mem cache, ensure there is enough room
          * discard the lru node if needed
          */
        csfsmc_ensure_room_safe_level_no_lock(csfsmc);/*LRU retire & recycle*/

        return csfsmc_write_no_lock(csfsmc, file_path, cbytes );
    }

    /*
     * EC_TRUE == csfsmc_read_np_no_lock(csfsmc, file_path, NULL_PTR, &node_pos)
     * means it can find the np corresponding to the file_path,
     * at this moment, the node_pos of np has been added to the head of csfsmclist, by csfsmclist_node_lru_update.

     * then, release the dn
     * and try to write dn
     */
    csfsnp = CSFSMC_NP(csfsmc);

    csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
    csfsnp_fnode = CSFSNP_ITEM_FNODE(csfsnp_item);

    __csfsmc_release_dn_no_lock(csfsmc, csfsnp_fnode);

    if(EC_FALSE == csfsmc_write_dn_no_lock(csfsmc, csfsnp_fnode, cbytes ))
    {
        CSFSMCLIST *csfsmclist;

        dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_update_dn_no_lock: update file %s to dn failed\n",
                           (char *)cstring_get_str(file_path));

        /*
         * When trying to write dn failed,
         * how to deal with np?
         * Should remove np from mem cache?

         * Because dn has been released and new content should be written to dn, but it failed,
         * so np should also remove from mem cache, right?
         */

        csfsmclist = CSFSMC_LIST(csfsmc);

        csfsmclist_pop_head(csfsmclist);

        /* np is got by csfsmc_reserve_np_no_lock, when data first written to mem cache */
        csfsmc_release_np_no_lock(csfsmc, file_path);

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*recycle from csfsmclist if need*/
STATIC_CAST static EC_BOOL __csfsmc_recycle_np_no_lock(CSFSMC *csfsmc, const uint32_t node_pos)
{
    CSFSNP      *csfsnp;
    CSFSMCLIST  *csfsmclist;

    CSFSNP_ITEM *csfsnp_item;

    csfsnp     = CSFSMC_NP(csfsmc);
    csfsmclist = CSFSMC_LIST(csfsmc);

    csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
    if(NULL_PTR == csfsnp_item)
    {
        return (EC_FALSE);
    }

    if(EC_TRUE == csfsmclist_node_is_used(csfsmclist, node_pos))
    {
        csfsmclist_node_del(csfsmclist, node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL csfsmc_delete_no_lock(CSFSMC *csfsmc, const CSTRING *file_path)
{
    CSFSNP *csfsnp;

    csfsnp = CSFSMC_NP(csfsmc);

    if(EC_FALSE != csfsnp_delete(csfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path)))
    {
        dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_delete_no_lock: delete path %s adone\n",
                           (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_delete_no_lock: not found path %s\n",
                   (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL csfsmc_retire_no_lock(CSFSMC *csfsmc)
{
    CSFSNP     *csfsnp;
    CSFSMCLIST *csfsmclist;
    uint32_t node_pos;

    /*retire the oldest from LRU list*/
    csfsnp     = CSFSMC_NP(csfsmc);
    csfsmclist = CSFSMC_LIST(csfsmc);

    node_pos = csfsmclist_pop_tail(csfsmclist);

    if(CSFSMCLIST_ERR_POS != node_pos)
    {
        UINT32  complete_num;

        csfsnp_umount_item(csfsnp, node_pos);

        complete_num = 0;
        csfsmc_recycle_no_lock(csfsmc, CSFSMC_RECYCLE_MAX_NUM, &complete_num);
        dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_retire_no_lock: recycle %ld done\n",
                           complete_num);

        return (EC_TRUE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_retire_no_lock: no cached to recycle\n");
    return (EC_TRUE);
}

EC_BOOL csfsmc_recycle_no_lock(CSFSMC *csfsmc, const UINT32 max_num, UINT32 *complete_num)
{
    dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_recycle_no_lock: obsolete interface\n");
    return (EC_FALSE);
}

EC_BOOL csfsmc_write(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    if(EC_FALSE == csfsmc_write_no_lock(csfsmc, file_path, cbytes ))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_write: write %s with %ld bytes failed\n",
                           (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_write: write %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL csfsmc_read(CSFSMC *csfsmc, const CSTRING *file_path, CBYTES *cbytes)
{
    if(EC_FALSE == csfsmc_read_no_lock(csfsmc, file_path, cbytes))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_read: read %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_read: read %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL csfsmc_read_e(CSFSMC *csfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    if(EC_FALSE == csfsmc_read_e_no_lock(csfsmc, file_path, store_offset, store_size, cbytes))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_read_e: read %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_read_e: read %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL csfsmc_file_size(CSFSMC *csfsmc, const CSTRING *file_path, uint64_t *file_size)
{
    if(EC_FALSE == csfsmc_file_size_no_lock(csfsmc, file_path, file_size))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_file_size: get size of file %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_file_size: get size of file %s done, file size = %"PRId64"\n",
                       (char *)cstring_get_str(file_path), (*file_size));

    return (EC_TRUE);
}

EC_BOOL csfsmc_update(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    if(EC_FALSE == csfsmc_update_no_lock(csfsmc, file_path, cbytes ))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_update: update %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_update: update %s done\n",
                       (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL csfsmc_delete(CSFSMC *csfsmc, const CSTRING *file_path)
{
    if(EC_FALSE == csfsmc_delete_no_lock(csfsmc, file_path))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_delete: delete %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_delete: delete %s done\n",
                       (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL csfsmc_retire(CSFSMC *csfsmc)
{
    if(EC_FALSE == csfsmc_retire_no_lock(csfsmc))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_retire: retire failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_retire: retire done\n");
    return (EC_TRUE);
}

EC_BOOL csfsmc_recycle(CSFSMC *csfsmc, const UINT32 max_num, UINT32 *complete_num)
{
    if(EC_FALSE == csfsmc_recycle_no_lock(csfsmc, max_num, complete_num))
    {
        dbg_log(SEC_0174_CSFSMC, 1)(LOGSTDOUT, "error:csfsmc_recycle: recycle failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_recycle: recycle done\n");
    return (EC_TRUE);
}

void csfsmc_print(LOG *log, const CSFSMC *csfsmc)
{
    sys_print(log, "csfsmc_print: csfsmc %p: csfs_md_id %ld, csfsnp %p, cpgd %p, csfsmclist %p, mcache %p\n",
             csfsmc, CSFSMC_CSFS_MD_ID(csfsmc), CSFSMC_NP(csfsmc), CSFSMC_PGD(csfsmc), CSFSMC_LIST(csfsmc), CSFSMC_MCACHE(csfsmc));

    sys_print(log, "csfsmc_print: csfsmc %p: csfsnp %p:\n", csfsmc, CSFSMC_NP(csfsmc));
    csfsnp_print(log, CSFSMC_NP(csfsmc));

    sys_print(log, "csfsmc_print: csfsmc %p: cpgd %p:\n", csfsmc, CSFSMC_PGD(csfsmc));
    cpgd_print(log, CSFSMC_PGD(csfsmc));

    sys_print(log, "csfsmc_print: csfsmc %p: csfsmclist %p:\n", csfsmc, CSFSMC_LIST(csfsmc));
    csfsmclist_print(log, CSFSMC_LIST(csfsmc));

    return;
}

EC_BOOL csfsmc_ensure_room_safe_level(CSFSMC *csfsmc)
{
    if(EC_FALSE == csfsmc_ensure_room_safe_level_no_lock(csfsmc))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsmc_ensure_room_safe_level_no_lock(CSFSMC *csfsmc)
{
    uint32_t retire_times;

    retire_times = 0;

    while(EC_FALSE == csfsmc_room_is_ok_no_lock(csfsmc, CSFSMC_ROOM_SAFE_LEVEL))
    {
        if(EC_FALSE == csfsmc_retire_no_lock(csfsmc)) /* retire & recycle, always return EC_TRUE */
        {
            /* will never reach here */
            csfsmc_recycle_no_lock(csfsmc, CSFSMC_RECYCLE_MAX_NUM, NULL_PTR);

            dbg_log(SEC_0174_CSFSMC, 0)(LOGSTDOUT, "error:csfsmc_ensure_room_safe_level_no_lock: retire failed\n");
            return (EC_FALSE);
        }

        retire_times ++;
    }

    if(0 < retire_times)
    {
        dbg_log(SEC_0174_CSFSMC, 9)(LOGSTDOUT, "[DEBUG] csfsmc_ensure_room_safe_level_no_lock: retire times %u\n", retire_times);
        csfsmc_recycle_no_lock(csfsmc, CSFSMC_RECYCLE_MAX_NUM, NULL_PTR);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

