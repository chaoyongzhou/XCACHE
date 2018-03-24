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
#include "crfsnprb.h"
#include "crfsnp.inc"
#include "crfsnp.h"
#include "crfsmc.h"
#include "crfs.h"
#include "crfsmclist.h"

CRFSMC *crfsmc_new(const UINT32 crfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const uint16_t block_num)
{
    CRFSMC *crfsmc;

    crfsmc = (CRFSMC *)safe_malloc(sizeof(CRFSMC), LOC_CRFSMC_0001);
    if(NULL_PTR == crfsmc)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_new: new crfsmc failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == crfsmc_init(crfsmc, crfs_md_id, np_id, np_model, hash_2nd_algo_id, block_num))
    {
        safe_free(crfsmc, LOC_CRFSMC_0002);
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_new: init crfsmc failed\n");
        return (NULL_PTR);
    }

    return (crfsmc);
}

EC_BOOL crfsmc_init(CRFSMC *crfsmc, const UINT32 crfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const uint16_t block_num)
{
    CRFSNP            *crfsnp;
    CPGD              *cpgd;
    CRFSMCLIST        *mclist;
    uint32_t           mclist_max_num;
    UINT32             mcache_size;

    crfsnp = crfsnp_mem_create(np_id, np_model, hash_2nd_algo_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_init: create mem np %u with model %u, hash %u failed\n",
                           np_id, np_model, hash_2nd_algo_id);
        return (EC_FALSE);
    }

    cpgd = cpgd_mem_new(block_num);
    if(NULL_PTR == cpgd)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_init: new mem pgd with %u blocks failed\n", block_num);
        crfsnp_mem_free(crfsnp);
        return (EC_FALSE);
    }

    mclist_max_num = CRFSNP_ITEMS_MAX_NUM(crfsnp);

    mclist = crfsmclist_new(mclist_max_num);
    if(NULL_PTR == mclist)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_init: new crfsmclist with %u nodes failed\n", mclist_max_num);
        cpgd_mem_free(cpgd);
        crfsnp_mem_free(crfsnp);
        return (EC_FALSE);
    }

    mcache_size = ((UINT32)block_num) * CPGD_BLOCK_PAGE_NUM * CPGB_PAGE_BYTE_SIZE;
    CRFSMC_MCACHE(crfsmc) = safe_malloc(mcache_size, LOC_CRFSMC_0003);
    if(NULL_PTR == CRFSMC_MCACHE(crfsmc))
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_init: new mcache with %ld bytes failed\n", mcache_size);
        crfsmclist_free(mclist);
        cpgd_mem_free(cpgd);
        crfsnp_mem_free(crfsnp);
        return (EC_FALSE);
    }

    CRFSMC_CRFS_MD_ID(crfsmc) = crfs_md_id;
    CRFSMC_NP(crfsmc)         = crfsnp;
    CRFSMC_PGD(crfsmc)        = cpgd;
    CRFSMC_LIST(crfsmc)       = mclist;

    CRFSMC_INIT_LOCK(crfsmc, LOC_CRFSMC_0004);

    return (EC_TRUE);
}

EC_BOOL crfsmc_clean(CRFSMC *crfsmc)
{
    ASSERT(NULL_PTR != crfsmc);

    if(NULL_PTR != CRFSMC_NP(crfsmc))
    {
        crfsnp_mem_free(CRFSMC_NP(crfsmc));
        CRFSMC_NP(crfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CRFSMC_PGD(crfsmc))
    {
        cpgd_mem_free(CRFSMC_PGD(crfsmc));
        CRFSMC_PGD(crfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CRFSMC_LIST(crfsmc))
    {
        crfsmclist_free(CRFSMC_LIST(crfsmc));
        CRFSMC_LIST(crfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CRFSMC_MCACHE(crfsmc))
    {
        safe_free(CRFSMC_MCACHE(crfsmc), LOC_CRFSMC_0005);
        CRFSMC_MCACHE(crfsmc) = NULL_PTR;
    }

    CRFSMC_CLEAN_LOCK(crfsmc, LOC_CRFSMC_0006);

    return (EC_TRUE);
}

EC_BOOL crfsmc_free(CRFSMC *crfsmc)
{
    if(NULL_PTR != crfsmc)
    {
        crfsmc_clean(crfsmc);
        safe_free(crfsmc, LOC_CRFSMC_0007);
    }

    return (EC_TRUE);
}

CRFSNP_FNODE *crfsmc_reserve_np_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, uint32_t *node_pos)
{
    CRFSNP *crfsnp;
    CRFSNP_ITEM *crfsnp_item;
    uint32_t node_pos_t;

    crfsnp = CRFSMC_NP(crfsmc);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_reserve_np_no_lock: set mem np beg\n");

    node_pos_t = crfsnp_insert(crfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(CRFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_reserve_np_no_lock: insert file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_reserve_np_no_lock: insert file %s to node_pos %u done\n",
                        (char *)cstring_get_str(file_path), node_pos_t);

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos_t);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_reserve_np_no_lock: set mem np end\n");

    if(CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_reserve_np_no_lock: file path %s is not regular file\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    CRFSNP_ITEM_CREATE_TIME(crfsnp_item) = 0/*task_brd_default_get_time()*/;

    if(do_log(SEC_0140_CRFSMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfsmc_reserve_np_no_lock: reserved crfsnp_item %p is\n", crfsnp_item);
        crfsnp_item_print(LOGSTDOUT, crfsnp_item);
    }

    (*node_pos) = node_pos_t;

    /*not import yet*/
    return CRFSNP_ITEM_FNODE(crfsnp_item);
}

EC_BOOL crfsmc_release_np_no_lock(CRFSMC *crfsmc, const CSTRING *file_path)
{
    CRFSNP *crfsnp;

    crfsnp = CRFSMC_NP(crfsmc);

    if(EC_FALSE == crfsnp_delete(crfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_release_np_no_lock: delete file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsmc_reserve_dn_no_lock(CRFSMC *crfsmc, const uint32_t size, uint16_t *block_no, uint16_t *page_no)
{
    CPGD *cpgd;

    cpgd = CRFSMC_PGD(crfsmc);

    if(EC_FALSE == cpgd_new_space(cpgd, size, block_no, page_no))
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDERR, "error:crfsmc_reserve_dn_no_lock: reserve size %u failed\n", size);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsmc_release_dn_no_lock(CRFSMC *crfsmc, const uint32_t size, const uint16_t block_no, const uint16_t page_no)
{
    CPGD *cpgd;

    cpgd = CRFSMC_PGD(crfsmc);

    if(EC_FALSE == cpgd_free_space(cpgd, block_no, page_no, size))
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_release_dn_no_lock: release space of block_no %u, page_no %u, size %u failed\n",
                           block_no, page_no, size);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsmc_release_dn_no_lock(CRFSMC *crfsmc, const CRFSNP_FNODE *crfsnp_fnode)
{
    const CRFSNP_INODE *crfsnp_inode;

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);

    /*note: disk_no was ignored*/
    return crfsmc_release_dn_no_lock(crfsmc,
                                     CRFSNP_FNODE_FILESZ(crfsnp_fnode),
                                     CRFSNP_INODE_BLOCK_NO(crfsnp_inode),
                                     CRFSNP_INODE_PAGE_NO(crfsnp_inode));
}


EC_BOOL crfsmc_import_dn_no_lock(CRFSMC *crfsmc, const CBYTES *cbytes, const CRFSNP_FNODE *crfsnp_fnode)
{
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    size = (uint32_t)CBYTES_LEN(cbytes);

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    BCOPY(CBYTES_BUF(cbytes), CRFSMC_MCACHE(crfsmc) + offset, size);

    return (EC_TRUE);
}

/*for debug only*/
REAL crfsmc_room_ratio(CRFSMC *crfsmc)
{
    CPGD *cpgd;
    double ratio;

    cpgd = CRFSMC_PGD(crfsmc);
    ratio = (CPGD_PAGE_USED_NUM(cpgd) + 0.0) / (CPGD_PAGE_MAX_NUM(cpgd)  + 0.0);
    return (ratio);
}

EC_BOOL crfsmc_room_is_ok_no_lock(CRFSMC *crfsmc, const REAL level)
{
    CRFSNP   *crfsnp;
    CPGD     *cpgd;

    uint64_t  used_page;
    uint64_t  max_page;
    double    ratio;

    cpgd   = CRFSMC_PGD(crfsmc);
    crfsnp = CRFSMC_NP(crfsmc);

    used_page = (uint64_t)CPGD_PAGE_USED_NUM(cpgd);
    max_page  = (uint64_t)CPGD_PAGE_MAX_NUM(cpgd);

    ratio = (used_page + 0.0) / (max_page  + 0.0);

    if(ratio < level)
    {
        return (EC_TRUE); /*ok*/
    }
    return (EC_FALSE);/*NOT ok*/
}

EC_BOOL crfsmc_write_dn_no_lock(CRFSMC *crfsmc, CRFSNP_FNODE *crfsnp_fnode, const CBYTES *cbytes, const uint8_t *md5sum)
{
    CRFSNP_INODE *crfsnp_inode;

    uint32_t size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    size = (uint32_t)cbytes_len(cbytes);

    if(EC_FALSE == crfsmc_reserve_dn_no_lock(crfsmc, size, &block_no, &page_no))
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_write_dn_no_lock: freserve dn with size %u failed\n", size);
        return (EC_FALSE);
    }

    crfsnp_fnode_init(crfsnp_fnode);
    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = size;
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 1;

    if(SWITCH_ON == CRFS_MD5_SWITCH && NULL_PTR != md5sum)
    {
        BCOPY(md5sum, CRFSNP_FNODE_MD5SUM(crfsnp_fnode), CMD5_DIGEST_LEN);
    }

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_NOT_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = CRFSMC_DISK_NO;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = block_no;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = page_no;

    /*import data to memcache*/
    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_write_dn_no_lock: size %u, block %u, page %u, offset %ld\n",
                       size, block_no, page_no, offset);
    BCOPY(CBYTES_BUF(cbytes), CRFSMC_MCACHE(crfsmc) + offset, size);

    return (EC_TRUE);
}

EC_BOOL crfsmc_write_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum)
{
    CRFSNP_FNODE *crfsnp_fnode;
    uint32_t  node_pos;

    crfsnp_fnode = crfsmc_reserve_np_no_lock(crfsmc, file_path, &node_pos);

    if(NULL_PTR == crfsnp_fnode)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_write_no_lock: file %s reserve np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsmc_write_dn_no_lock(crfsmc, crfsnp_fnode, cbytes, md5sum))
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_write_no_lock: file %s write dn failed\n",
                           (char *)cstring_get_str(file_path));
        crfsmc_release_np_no_lock(crfsmc, file_path);
        return (EC_FALSE);
    }

    /*add to memcache*/
    crfsmclist_node_add_head(CRFSMC_LIST(crfsmc), node_pos);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_write_no_lock: write to mem cache at %u done\n", node_pos);

    return (EC_TRUE);
}

EC_BOOL crfsmc_read_np_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode, uint32_t *node_pos)
{
    CRFSNP *crfsnp;

    uint32_t node_pos_t;

    crfsnp = CRFSMC_NP(crfsmc);

    node_pos_t = crfsnp_search_no_lock(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(CRFSNPRB_ERR_POS != node_pos_t)
    {
        CRFSMCLIST * crfsmclist;

        if(NULL_PTR != crfsnp_fnode)
        {
            CRFSNP_ITEM *crfsnp_item;
            crfsnp_item = crfsnp_fetch(crfsnp, node_pos_t);
            crfsnp_fnode_import(CRFSNP_ITEM_FNODE(crfsnp_item), crfsnp_fnode);
        }

        if(NULL_PTR != node_pos)
        {
            (*node_pos) = node_pos_t;
        }

        /*update LRU list*/
        crfsmclist = CRFSMC_LIST(crfsmc);

        crfsmclist_node_lru_update(crfsmclist, node_pos_t);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/* check whether np is in memcache only, do not read np or change the lru list */
EC_BOOL crfsmc_check_np(CRFSMC *crfsmc, const CSTRING *file_path)
{
    CRFSNP *crfsnp;
    uint32_t node_pos_t;

    CRFSMC_RDLOCK(crfsmc, LOC_CRFSMC_0008);

    crfsnp = CRFSMC_NP(crfsmc);
    node_pos_t = crfsnp_search_no_lock(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);

    if(CRFSNPRB_ERR_POS != node_pos_t) /* file is in memcache */
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0009);
        return (EC_TRUE);
    }
    /* file is NOT in memcache */
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0010);
    return (EC_FALSE);
}

EC_BOOL crfsmc_read_e_dn_no_lock(CRFSMC *crfsmc, const CRFSNP_FNODE *crfsnp_fnode, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;
    UINT32   max_len;

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    if(0 == store_size)
    {
        cbytes_clean(cbytes);
        return (EC_TRUE);
    }

    if((*store_offset) >= file_size)
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_read_e_dn_no_lock: read file failed due to offset %ld overflow file size %ld\n",
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
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CRFSMC_0011);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len, LOC_CRFSMC_0012);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    BCOPY(CRFSMC_MCACHE(crfsmc) + offset, CBYTES_BUF(cbytes), max_len);
    CBYTES_LEN(cbytes) = max_len;

    (*store_offset) += max_len;

    return (EC_TRUE);
}

EC_BOOL crfsmc_read_dn_no_lock(CRFSMC *crfsmc, const CRFSNP_FNODE *crfsnp_fnode, CBYTES *cbytes)
{
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    /*export data from memcache*/
    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CRFSMC_0013);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CRFSMC_0014);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    BCOPY(CRFSMC_MCACHE(crfsmc) + offset, CBYTES_BUF(cbytes), file_size);
    CBYTES_LEN(cbytes) = file_size;

    return (EC_TRUE);
}


EC_BOOL crfsmc_read_e_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    CRFSNP_FNODE crfsnp_fnode;

    crfsnp_fnode_init(&crfsnp_fnode);

    if(EC_FALSE == crfsmc_read_np_no_lock(crfsmc, file_path, &crfsnp_fnode, NULL_PTR))
    {
        dbg_log(SEC_0140_CRFSMC, 5)(LOGSTDOUT, "warn:crfsmc_read_e_no_lock: read file %s from np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsmc_read_e_dn_no_lock(crfsmc, &crfsnp_fnode, store_offset, store_size, cbytes))
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_read_e_no_lock: read file %s from dn failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsmc_file_size_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, uint64_t *file_size)
{
    CRFSNP  *crfsnp;
    uint64_t cur_file_size;

    EC_BOOL ret;

    crfsnp = CRFSMC_NP(crfsmc);

    ret = crfsnp_file_size(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cur_file_size);
    if(EC_FALSE== ret)
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_file_size_no_lock: get size of file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    (*file_size) = cur_file_size;

    return (EC_TRUE);
}

EC_BOOL crfsmc_read_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, CBYTES *cbytes)
{
    CRFSNP_FNODE crfsnp_fnode;

    crfsnp_fnode_init(&crfsnp_fnode);

    if(EC_FALSE == crfsmc_read_np_no_lock(crfsmc, file_path, &crfsnp_fnode, NULL_PTR))
    {
        dbg_log(SEC_0140_CRFSMC, 5)(LOGSTDOUT, "warn:crfsmc_read_no_lock: read file %s from np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsmc_read_dn_no_lock(crfsmc, &crfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_read_dn_no_lock: read file %s from dn failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsmc_update_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum)
{
    CRFSNP       *crfsnp;
    CRFSNP_ITEM  *crfsnp_item;
    CRFSNP_FNODE *crfsnp_fnode;

    uint32_t node_pos;

    if(EC_FALSE == crfsmc_read_np_no_lock(crfsmc, file_path, NULL_PTR, &node_pos))
    {
         /*
          * before write to mem cache, ensure there is enough room
          * discard the lru node if needed
          */
        crfsmc_ensure_room_safe_level_no_lock(crfsmc);/*LRU retire & recycle*/

        return crfsmc_write_no_lock(crfsmc, file_path, cbytes, md5sum);
    }

    /*
     * EC_TRUE == crfsmc_read_np_no_lock(crfsmc, file_path, NULL_PTR, &node_pos)
     * means it can find the np corresponding to the file_path,
     * at this moment, the node_pos of np has been added to the head of crfsmclist, by crfsmclist_node_lru_update.

     * then, release the dn
     * and try to write dn
     */
    crfsnp = CRFSMC_NP(crfsmc);

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    crfsnp_fnode = CRFSNP_ITEM_FNODE(crfsnp_item);

    __crfsmc_release_dn_no_lock(crfsmc, crfsnp_fnode);

    if(EC_FALSE == crfsmc_write_dn_no_lock(crfsmc, crfsnp_fnode, cbytes, md5sum))
    {
        CRFSMCLIST *crfsmclist;

        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_update_dn_no_lock: update file %s to dn failed\n",
                           (char *)cstring_get_str(file_path));

        /*
         * When trying to write dn failed,
         * how to deal with np?
         * Should remove np from mem cache?

         * Because dn has been released and new content should be written to dn, but it failed,
         * so np should also remove from mem cache, right?
         */

        crfsmclist = CRFSMC_LIST(crfsmc);

        crfsmclist_pop_head(crfsmclist);

        /* np is got by crfsmc_reserve_np_no_lock, when data first written to mem cache */
        crfsmc_release_np_no_lock(crfsmc, file_path);

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*recycle from crfsmclist if need*/
STATIC_CAST static EC_BOOL __crfsmc_recycle_np_no_lock(CRFSMC *crfsmc, const uint32_t node_pos)
{
    CRFSNP      *crfsnp;
    CRFSMCLIST  *crfsmclist;

    CRFSNP_ITEM *crfsnp_item;

    crfsnp     = CRFSMC_NP(crfsmc);
    crfsmclist = CRFSMC_LIST(crfsmc);

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    if(NULL_PTR == crfsnp_item)
    {
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        if(EC_TRUE == crfsmclist_node_is_used(crfsmclist, node_pos))
        {
            crfsmclist_node_del(crfsmclist, node_pos);
        }
        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_BIG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        return (EC_FALSE);
    }

    return (EC_FALSE);
}

EC_BOOL crfsmc_delete_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, const UINT32 dflag)
{
    CRFSNP *crfsnp;
    uint32_t node_pos;

    crfsnp = CRFSMC_NP(crfsmc);

    node_pos = crfsnp_search_no_lock(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), dflag);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        UINT32  complete_num;

        crfsnp_umount_item_deep(crfsnp, node_pos);

        complete_num = 0;
        crfsmc_recycle_no_lock(crfsmc, CRFSMC_RECYCLE_MAX_NUM, &complete_num);
        dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete_no_lock: delete path %s with dflag %ld and recycle %ld done\n",
                           (char *)cstring_get_str(file_path), dflag, complete_num);
        return (EC_TRUE);
    }

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete_no_lock: not found path %s with dflag %ld\n",
                   (char *)cstring_get_str(file_path), dflag);
    return (EC_TRUE);
}

EC_BOOL crfsmc_delete_wildcard_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, const UINT32 dflag)
{
    CRFSNP *crfsnp;
    uint32_t node_pos;

    crfsnp = CRFSMC_NP(crfsmc);

    node_pos = crfsnp_match_no_lock(crfsnp, CRFSNPRB_ROOT_POS, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), dflag);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        UINT32  complete_num;

        crfsnp_umount_item_deep(crfsnp, node_pos);

        complete_num = 0;
        crfsmc_recycle_no_lock(crfsmc, CRFSMC_RECYCLE_MAX_NUM, &complete_num);
        dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete_wildcard_no_lock: delete path %s with dflag %ld and recycle %ld done\n",
                           (char *)cstring_get_str(file_path), dflag, complete_num);
        return (EC_TRUE);
    }

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete_wildcard_no_lock: not found path %s with dflag %ld\n",
                   (char *)cstring_get_str(file_path), dflag);
    return (EC_TRUE);
}


EC_BOOL crfsmc_retire_no_lock(CRFSMC *crfsmc)
{
    CRFSNP     *crfsnp;
    CRFSMCLIST *crfsmclist;
    uint32_t node_pos;

    /*retire the oldest from LRU list*/
    crfsnp     = CRFSMC_NP(crfsmc);
    crfsmclist = CRFSMC_LIST(crfsmc);

    node_pos = crfsmclist_pop_tail(crfsmclist);

    if(CRFSMCLIST_ERR_POS != node_pos)
    {
        UINT32  complete_num;

        crfsnp_umount_item_deep(crfsnp, node_pos);

        complete_num = 0;
        crfsmc_recycle_no_lock(crfsmc, CRFSMC_RECYCLE_MAX_NUM, &complete_num);
        dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_retire_no_lock: recycle %ld done\n",
                           complete_num);

        return (EC_TRUE);
    }

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_retire_no_lock: no cached to recycle\n");
    return (EC_TRUE);
}

EC_BOOL crfsmc_recycle_no_lock(CRFSMC *crfsmc, const UINT32 max_num, UINT32 *complete_num)
{
    CRFSNP     *crfsnp;
    CRFSNP_RECYCLE_DN crfsnp_recycle_dn;
    CRFSNP_RECYCLE_NP crfsnp_recycle_np;

    crfsnp     = CRFSMC_NP(crfsmc);

    CRFSNP_RECYCLE_DN_ARG1(&crfsnp_recycle_dn)   = (UINT32)crfsmc;
    CRFSNP_RECYCLE_DN_FUNC(&crfsnp_recycle_dn)   = (CRFSNP_RECYCLE_DN_FUNC)__crfsmc_release_dn_no_lock;

    CRFSNP_RECYCLE_NP_ARG1(&crfsnp_recycle_np)   = (UINT32)crfsmc;
    CRFSNP_RECYCLE_NP_FUNC(&crfsnp_recycle_np)   = (CRFSNP_RECYCLE_NP_FUNC)__crfsmc_recycle_np_no_lock;

    if(EC_FALSE == crfsnp_recycle(crfsnp, max_num, &crfsnp_recycle_np, &crfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_recycle_no_lock: recycle failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsmc_write(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum)
{
    CRFSMC_WRLOCK(crfsmc, LOC_CRFSMC_0015);
    if(EC_FALSE == crfsmc_write_no_lock(crfsmc, file_path, cbytes, md5sum))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0016);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_write: write %s with %ld bytes failed\n",
                           (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0017);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_write: write %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL crfsmc_read(CRFSMC *crfsmc, const CSTRING *file_path, CBYTES *cbytes)
{
    CRFSMC_RDLOCK(crfsmc, LOC_CRFSMC_0018);
    if(EC_FALSE == crfsmc_read_no_lock(crfsmc, file_path, cbytes))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0019);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_read: read %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0020);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_read: read %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL crfsmc_read_e(CRFSMC *crfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    CRFSMC_RDLOCK(crfsmc, LOC_CRFSMC_0021);
    if(EC_FALSE == crfsmc_read_e_no_lock(crfsmc, file_path, store_offset, store_size, cbytes))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0022);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_read_e: read %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0023);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_read_e: read %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL crfsmc_file_size(CRFSMC *crfsmc, const CSTRING *file_path, uint64_t *file_size)
{
    CRFSMC_RDLOCK(crfsmc, LOC_CRFSMC_0024);
    if(EC_FALSE == crfsmc_file_size_no_lock(crfsmc, file_path, file_size))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0025);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_file_size: get size of file %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0026);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_file_size: get size of file %s done, file size = %"PRId64"\n",
                       (char *)cstring_get_str(file_path), (*file_size));

    return (EC_TRUE);
}

EC_BOOL crfsmc_update(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum)
{
    CRFSMC_WRLOCK(crfsmc, LOC_CRFSMC_0027);
    if(EC_FALSE == crfsmc_update_no_lock(crfsmc, file_path, cbytes, md5sum))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0028);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_update: update %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0029);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_update: update %s done\n",
                       (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL crfsmc_delete(CRFSMC *crfsmc, const CSTRING *file_path, const UINT32 dflag)
{
    CRFSMC_WRLOCK(crfsmc, LOC_CRFSMC_0030);
    if(EC_FALSE == crfsmc_delete_no_lock(crfsmc, file_path, dflag))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0031);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_delete: delete %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0032);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete: delete %s done\n",
                       (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL crfsmc_delete_wildcard(CRFSMC *crfsmc, const CSTRING *file_path, const UINT32 dflag)
{
    UINT32 count;

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete_wildcard: delete %s start ...\n",
                       (char *)cstring_get_str(file_path));

    count = 0;
    CRFSMC_WRLOCK(crfsmc, LOC_CRFSMC_0033);
    while(EC_TRUE == crfsmc_delete_wildcard_no_lock(crfsmc, file_path, dflag))
    {
        count ++;

        dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete_wildcard: delete %s: %ld\n",
                           (char *)cstring_get_str(file_path), count);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0034);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_delete_wildcard: delete %s done, complete %ld\n",
                       (char *)cstring_get_str(file_path), count);

    return (EC_TRUE);
}

EC_BOOL crfsmc_retire(CRFSMC *crfsmc)
{
    CRFSMC_WRLOCK(crfsmc, LOC_CRFSMC_0035);
    if(EC_FALSE == crfsmc_retire_no_lock(crfsmc))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0036);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_retire: retire failed\n");
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0037);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_retire: retire done\n");
    return (EC_TRUE);
}

EC_BOOL crfsmc_recycle(CRFSMC *crfsmc, const UINT32 max_num, UINT32 *complete_num)
{
    CRFSMC_WRLOCK(crfsmc, LOC_CRFSMC_0038);
    if(EC_FALSE == crfsmc_recycle_no_lock(crfsmc, max_num, complete_num))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0039);
        dbg_log(SEC_0140_CRFSMC, 1)(LOGSTDOUT, "error:crfsmc_recycle: recycle failed\n");
        return (EC_FALSE);
    }
    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0040);

    dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_recycle: recycle done\n");
    return (EC_TRUE);
}

void crfsmc_print(LOG *log, const CRFSMC *crfsmc)
{
    sys_print(log, "crfsmc_print: crfsmc %p: crfs_md_id %ld, crfsnp %p, cpgd %p, crfsmclist %p, mcache %p\n",
             crfsmc, CRFSMC_CRFS_MD_ID(crfsmc), CRFSMC_NP(crfsmc), CRFSMC_PGD(crfsmc), CRFSMC_LIST(crfsmc), CRFSMC_MCACHE(crfsmc));

    sys_print(log, "crfsmc_print: crfsmc %p: crfsnp %p:\n", crfsmc, CRFSMC_NP(crfsmc));
    crfsnp_print(log, CRFSMC_NP(crfsmc));

    sys_print(log, "crfsmc_print: crfsmc %p: cpgd %p:\n", crfsmc, CRFSMC_PGD(crfsmc));
    cpgd_print(log, CRFSMC_PGD(crfsmc));

    sys_print(log, "crfsmc_print: crfsmc %p: crfsmclist %p:\n", crfsmc, CRFSMC_LIST(crfsmc));
    crfsmclist_print(log, CRFSMC_LIST(crfsmc));

    return;
}

EC_BOOL crfsmc_ensure_room_safe_level(CRFSMC *crfsmc)
{
    CRFSMC_WRLOCK(crfsmc, LOC_CRFSMC_0041);
    if(EC_FALSE == crfsmc_ensure_room_safe_level_no_lock(crfsmc))
    {
        CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0042);
        return (EC_FALSE);
    }

    CRFSMC_UNLOCK(crfsmc, LOC_CRFSMC_0043);
    return (EC_TRUE);
}

EC_BOOL crfsmc_ensure_room_safe_level_no_lock(CRFSMC *crfsmc)
{
    uint32_t retire_times;

    retire_times = 0;

    while(EC_FALSE == crfsmc_room_is_ok_no_lock(crfsmc, CRFSMC_ROOM_SAFE_LEVEL))
    {
        if(EC_FALSE == crfsmc_retire_no_lock(crfsmc)) /* retire & recycle, always return EC_TRUE */
        {
            /* will never reach here */
            crfsmc_recycle_no_lock(crfsmc, CRFSMC_RECYCLE_MAX_NUM, NULL_PTR);

            dbg_log(SEC_0140_CRFSMC, 0)(LOGSTDOUT, "error:crfsmc_ensure_room_safe_level_no_lock: retire failed\n");
            return (EC_FALSE);
        }

        retire_times ++;
    }

    if(0 < retire_times)
    {
        dbg_log(SEC_0140_CRFSMC, 9)(LOGSTDOUT, "[DEBUG] crfsmc_ensure_room_safe_level_no_lock: retire times %u\n", retire_times);
        crfsmc_recycle_no_lock(crfsmc, CRFSMC_RECYCLE_MAX_NUM, NULL_PTR);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

