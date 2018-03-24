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
#include "chfsnprb.h"
#include "chfsnp.h"
#include "chfsmc.h"
#include "chfs.h"
#include "chfsmclist.h"

CHFSMC *chfsmc_new(const UINT32 chfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num)
{
    CHFSMC *chfsmc;

    chfsmc = (CHFSMC *)safe_malloc(sizeof(CHFSMC), LOC_CHFSMC_0001);
    if(NULL_PTR == chfsmc)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_new: new chfsmc failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == chfsmc_init(chfsmc, chfs_md_id, np_id, np_model, hash_1st_algo_id, hash_2nd_algo_id, bucket_max_num, block_num))
    {
        safe_free(chfsmc, LOC_CHFSMC_0002);
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_new: init chfsmc failed\n");
        return (NULL_PTR);
    }

    return (chfsmc);
}

EC_BOOL chfsmc_init(CHFSMC *chfsmc, const UINT32 chfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num)
{
    CHFSNP            *chfsnp;
    CPGD              *cpgd;
    CHFSMCLIST        *mclist;
    uint32_t           mclist_max_num;
    UINT32             mcache_size;

    chfsnp = chfsnp_mem_create(np_id, np_model, hash_1st_algo_id, hash_2nd_algo_id, bucket_max_num);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_init: create mem np %u with model %u, hash %u failed\n",
                           np_id, np_model, hash_2nd_algo_id);
        return (EC_FALSE);
    }

    cpgd = cpgd_mem_new(block_num);
    if(NULL_PTR == cpgd)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_init: new mem pgd with %u blocks failed\n", block_num);
        chfsnp_mem_free(chfsnp);
        return (EC_FALSE);
    }

    mclist_max_num = CHFSNP_ITEMS_MAX_NUM(chfsnp);

    mclist = chfsmclist_new(mclist_max_num);
    if(NULL_PTR == mclist)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_init: new chfsmclist with %u nodes failed\n", mclist_max_num);
        cpgd_mem_free(cpgd);
        chfsnp_mem_free(chfsnp);
        return (EC_FALSE);
    }

    mcache_size = ((UINT32)block_num) * CPGD_BLOCK_PAGE_NUM * CPGB_PAGE_BYTE_SIZE;
    CHFSMC_MCACHE(chfsmc) = safe_malloc(mcache_size, LOC_CHFSMC_0003);
    if(NULL_PTR == CHFSMC_MCACHE(chfsmc))
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_init: new mcache with %ld bytes failed\n", mcache_size);
        chfsmclist_free(mclist);
        cpgd_mem_free(cpgd);
        chfsnp_mem_free(chfsnp);
        return (EC_FALSE);
    }

    CHFSMC_CHFS_MD_ID(chfsmc) = chfs_md_id;
    CHFSMC_NP(chfsmc)         = chfsnp;
    CHFSMC_PGD(chfsmc)        = cpgd;
    CHFSMC_LIST(chfsmc)       = mclist;

    CHFSMC_INIT_LOCK(chfsmc, LOC_CHFSMC_0004);

    return (EC_TRUE);
}

EC_BOOL chfsmc_clean(CHFSMC *chfsmc)
{
    ASSERT(NULL_PTR != chfsmc);

    if(NULL_PTR != CHFSMC_NP(chfsmc))
    {
        chfsnp_mem_free(CHFSMC_NP(chfsmc));
        CHFSMC_NP(chfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CHFSMC_PGD(chfsmc))
    {
        cpgd_mem_free(CHFSMC_PGD(chfsmc));
        CHFSMC_PGD(chfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CHFSMC_LIST(chfsmc))
    {
        chfsmclist_free(CHFSMC_LIST(chfsmc));
        CHFSMC_LIST(chfsmc) = NULL_PTR;
    }

    if(NULL_PTR != CHFSMC_MCACHE(chfsmc))
    {
        safe_free(CHFSMC_MCACHE(chfsmc), LOC_CHFSMC_0005);
        CHFSMC_MCACHE(chfsmc) = NULL_PTR;
    }

    CHFSMC_CLEAN_LOCK(chfsmc, LOC_CHFSMC_0006);

    return (EC_TRUE);
}

EC_BOOL chfsmc_free(CHFSMC *chfsmc)
{
    if(NULL_PTR != chfsmc)
    {
        chfsmc_clean(chfsmc);
        safe_free(chfsmc, LOC_CHFSMC_0007);
    }

    return (EC_TRUE);
}

CHFSNP_FNODE *chfsmc_reserve_np_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, uint32_t *node_pos)
{
    CHFSNP *chfsnp;
    CHFSNP_ITEM *chfsnp_item;
    uint32_t node_pos_t;

    chfsnp = CHFSMC_NP(chfsmc);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_reserve_np_no_lock: set mem np beg\n");

    node_pos_t = chfsnp_insert(chfsnp, cstring_get_len(file_path), cstring_get_str(file_path));
    if(CHFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_reserve_np_no_lock: insert file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_reserve_np_no_lock: insert file %s to node_pos %u done\n",
                        (char *)cstring_get_str(file_path), node_pos_t);

    chfsnp_item = chfsnp_fetch(chfsnp, node_pos_t);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_reserve_np_no_lock: set mem np end\n");

    if(do_log(SEC_0160_CHFSMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chfsmc_reserve_np_no_lock: reserved chfsnp_item %p is\n", chfsnp_item);
        chfsnp_item_print(LOGSTDOUT, chfsnp_item);
    }

    (*node_pos) = node_pos_t;

    /*not import yet*/
    return CHFSNP_ITEM_FNODE(chfsnp_item);
}

EC_BOOL chfsmc_release_np_no_lock(CHFSMC *chfsmc, const CSTRING *file_path)
{
    CHFSNP *chfsnp;

    chfsnp = CHFSMC_NP(chfsmc);

    if(EC_FALSE == chfsnp_delete(chfsnp, cstring_get_len(file_path), cstring_get_str(file_path)))
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_release_np_no_lock: delete file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsmc_reserve_dn_no_lock(CHFSMC *chfsmc, const uint32_t size, uint16_t *block_no, uint16_t *page_no)
{
    CPGD *cpgd;

    cpgd = CHFSMC_PGD(chfsmc);

    if(EC_FALSE == cpgd_new_space(cpgd, size, block_no, page_no))
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDERR, "error:chfsmc_reserve_dn_no_lock: reserve size %u failed\n", size);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsmc_release_dn_no_lock(CHFSMC *chfsmc, const uint32_t size, const uint16_t block_no, const uint16_t page_no)
{
    CPGD *cpgd;

    cpgd = CHFSMC_PGD(chfsmc);

    if(EC_FALSE == cpgd_free_space(cpgd, block_no, page_no, size))
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_release_dn_no_lock: release space of block_no %u, page_no %u, size %u failed\n",
                           block_no, page_no, size);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfsmc_release_dn_no_lock(CHFSMC *chfsmc, const CHFSNP_FNODE *chfsnp_fnode)
{
    const CHFSNP_INODE *chfsnp_inode;

    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);

    /*note: disk_no was ignored*/
    return chfsmc_release_dn_no_lock(chfsmc,
                                     CHFSNP_FNODE_FILESZ(chfsnp_fnode),
                                     CHFSNP_INODE_BLOCK_NO(chfsnp_inode),
                                     CHFSNP_INODE_PAGE_NO(chfsnp_inode));
}


EC_BOOL chfsmc_import_dn_no_lock(CHFSMC *chfsmc, const CBYTES *cbytes, const CHFSNP_FNODE *chfsnp_fnode)
{
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    size = (uint32_t)CBYTES_LEN(cbytes);

    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    BCOPY(CBYTES_BUF(cbytes), CHFSMC_MCACHE(chfsmc) + offset, size);

    return (EC_TRUE);
}

EC_BOOL chfsmc_room_is_ok_no_lock(CHFSMC *chfsmc, const REAL level)
{
    CHFSNP   *chfsnp;
    CPGD     *cpgd;

    uint64_t  used_page;
    uint64_t  max_page;
    double    ratio;

    cpgd   = CHFSMC_PGD(chfsmc);
    chfsnp = CHFSMC_NP(chfsmc);

    used_page = (uint64_t)CPGD_PAGE_USED_NUM(cpgd);
    max_page  = (uint64_t)CPGD_PAGE_MAX_NUM(cpgd);

    ratio = (used_page + 0.0) / (max_page  + 0.0);

    if(ratio < level)
    {
        return (EC_TRUE); /*ok*/
    }
    return (EC_FALSE);/*NOT ok*/
}

EC_BOOL chfsmc_write_dn_no_lock(CHFSMC *chfsmc, CHFSNP_FNODE *chfsnp_fnode, const CBYTES *cbytes )
{
    CHFSNP_INODE *chfsnp_inode;

    uint32_t size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    size = (uint32_t)cbytes_len(cbytes);

    if(EC_FALSE == chfsmc_reserve_dn_no_lock(chfsmc, size, &block_no, &page_no))
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_write_dn_no_lock: freserve dn with size %u failed\n", size);
        return (EC_FALSE);
    }

    chfsnp_fnode_init(chfsnp_fnode);
    CHFSNP_FNODE_FILESZ(chfsnp_fnode) = size;
    CHFSNP_FNODE_REPNUM(chfsnp_fnode) = 1;

    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    //CHFSNP_INODE_CACHE_FLAG(chfsnp_inode) = CHFSDN_DATA_NOT_IN_CACHE;
    CHFSNP_INODE_DISK_NO(chfsnp_inode)    = CHFSMC_DISK_NO;
    CHFSNP_INODE_BLOCK_NO(chfsnp_inode)   = block_no;
    CHFSNP_INODE_PAGE_NO(chfsnp_inode)    = page_no;

    /*import data to memcache*/
    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_write_dn_no_lock: size %u, block %u, page %u, offset %ld\n",
                       size, block_no, page_no, offset);
    BCOPY(CBYTES_BUF(cbytes), CHFSMC_MCACHE(chfsmc) + offset, size);

    return (EC_TRUE);
}

EC_BOOL chfsmc_write_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    CHFSNP_FNODE *chfsnp_fnode;
    uint32_t  node_pos;

    chfsnp_fnode = chfsmc_reserve_np_no_lock(chfsmc, file_path, &node_pos);

    if(NULL_PTR == chfsnp_fnode)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_write_no_lock: file %s reserve np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsmc_write_dn_no_lock(chfsmc, chfsnp_fnode, cbytes ))
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_write_no_lock: file %s write dn failed\n",
                           (char *)cstring_get_str(file_path));
        chfsmc_release_np_no_lock(chfsmc, file_path);
        return (EC_FALSE);
    }

    /*add to memcache*/
    chfsmclist_node_add_head(CHFSMC_LIST(chfsmc), node_pos);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_write_no_lock: write to mem cache at %u done\n", node_pos);

    return (EC_TRUE);
}

EC_BOOL chfsmc_read_np_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, CHFSNP_FNODE *chfsnp_fnode, uint32_t *node_pos)
{
    CHFSNP *chfsnp;

    uint32_t node_pos_t;

    chfsnp = CHFSMC_NP(chfsmc);

    node_pos_t = chfsnp_search_no_lock(chfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path));
    if(CHFSNPRB_ERR_POS != node_pos_t)
    {
        CHFSMCLIST * chfsmclist;

        if(NULL_PTR != chfsnp_fnode)
        {
            CHFSNP_ITEM *chfsnp_item;
            chfsnp_item = chfsnp_fetch(chfsnp, node_pos_t);
            chfsnp_fnode_import(CHFSNP_ITEM_FNODE(chfsnp_item), chfsnp_fnode);
        }

        if(NULL_PTR != node_pos)
        {
            (*node_pos) = node_pos_t;
        }

        /*update LRU list*/
        chfsmclist = CHFSMC_LIST(chfsmc);

        chfsmclist_node_lru_update(chfsmclist, node_pos_t);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/* check whether np is in memcache only, do not read np or change the lru list */
EC_BOOL chfsmc_check_np(CHFSMC *chfsmc, const CSTRING *file_path)
{
    CHFSNP *chfsnp;
    uint32_t node_pos_t;

    CHFSMC_RDLOCK(chfsmc, LOC_CHFSMC_0008);

    chfsnp = CHFSMC_NP(chfsmc);
    node_pos_t = chfsnp_search_no_lock(chfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path));

    if(CHFSNPRB_ERR_POS != node_pos_t) /* file is in memcache */
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0009);
        return (EC_TRUE);
    }
    /* file is NOT in memcache */
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0010);
    return (EC_FALSE);
}

EC_BOOL chfsmc_read_e_dn_no_lock(CHFSMC *chfsmc, const CHFSNP_FNODE *chfsnp_fnode, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t file_size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;
    UINT32   max_len;

    file_size    = CHFSNP_FNODE_FILESZ(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    if(0 == store_size)
    {
        cbytes_clean(cbytes);
        return (EC_TRUE);
    }

    if((*store_offset) >= file_size)
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_read_e_dn_no_lock: read file failed due to offset %ld overflow file size %ld\n",
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
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CHFSMC_0011);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len, LOC_CHFSMC_0012);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    BCOPY(CHFSMC_MCACHE(chfsmc) + offset, CBYTES_BUF(cbytes), max_len);
    CBYTES_LEN(cbytes) = max_len;

    (*store_offset) += max_len;

    return (EC_TRUE);
}

EC_BOOL chfsmc_read_dn_no_lock(CHFSMC *chfsmc, const CHFSNP_FNODE *chfsnp_fnode, CBYTES *cbytes)
{
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t file_size;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    file_size    = CHFSNP_FNODE_FILESZ(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    /*export data from memcache*/
    offset  = ((UINT32)(block_no)) * (CPGB_064MB_PAGE_NUM << CPGB_PAGE_BIT_SIZE)
            + (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CHFSMC_0013);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CHFSMC_0014);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    BCOPY(CHFSMC_MCACHE(chfsmc) + offset, CBYTES_BUF(cbytes), file_size);
    CBYTES_LEN(cbytes) = file_size;

    return (EC_TRUE);
}


EC_BOOL chfsmc_read_e_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    CHFSNP_FNODE chfsnp_fnode;

    chfsnp_fnode_init(&chfsnp_fnode);

    if(EC_FALSE == chfsmc_read_np_no_lock(chfsmc, file_path, &chfsnp_fnode, NULL_PTR))
    {
        dbg_log(SEC_0160_CHFSMC, 5)(LOGSTDOUT, "warn:chfsmc_read_e_no_lock: read file %s from np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsmc_read_e_dn_no_lock(chfsmc, &chfsnp_fnode, store_offset, store_size, cbytes))
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_read_e_no_lock: read file %s from dn failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsmc_file_size_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, uint64_t *file_size)
{
    CHFSNP  *chfsnp;
    uint32_t cur_file_size;

    EC_BOOL ret;

    chfsnp = CHFSMC_NP(chfsmc);

    ret = chfsnp_file_size(chfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cur_file_size);
    if(EC_FALSE== ret)
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_file_size_no_lock: get size of file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    (*file_size) = cur_file_size;

    return (EC_TRUE);
}

EC_BOOL chfsmc_read_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, CBYTES *cbytes)
{
    CHFSNP_FNODE chfsnp_fnode;

    chfsnp_fnode_init(&chfsnp_fnode);

    if(EC_FALSE == chfsmc_read_np_no_lock(chfsmc, file_path, &chfsnp_fnode, NULL_PTR))
    {
        dbg_log(SEC_0160_CHFSMC, 5)(LOGSTDOUT, "warn:chfsmc_read_no_lock: read file %s from np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsmc_read_dn_no_lock(chfsmc, &chfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_read_dn_no_lock: read file %s from dn failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsmc_update_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    CHFSNP       *chfsnp;
    CHFSNP_ITEM  *chfsnp_item;
    CHFSNP_FNODE *chfsnp_fnode;

    uint32_t node_pos;

    if(EC_FALSE == chfsmc_read_np_no_lock(chfsmc, file_path, NULL_PTR, &node_pos))
    {
         /*
          * before write to mem cache, ensure there is enough room
          * discard the lru node if needed
          */
        chfsmc_ensure_room_safe_level_no_lock(chfsmc);/*LRU retire & recycle*/

        return chfsmc_write_no_lock(chfsmc, file_path, cbytes );
    }

    /*
     * EC_TRUE == chfsmc_read_np_no_lock(chfsmc, file_path, NULL_PTR, &node_pos)
     * means it can find the np corresponding to the file_path,
     * at this moment, the node_pos of np has been added to the head of chfsmclist, by chfsmclist_node_lru_update.

     * then, release the dn
     * and try to write dn
     */
    chfsnp = CHFSMC_NP(chfsmc);

    chfsnp_item = chfsnp_fetch(chfsnp, node_pos);
    chfsnp_fnode = CHFSNP_ITEM_FNODE(chfsnp_item);

    __chfsmc_release_dn_no_lock(chfsmc, chfsnp_fnode);

    if(EC_FALSE == chfsmc_write_dn_no_lock(chfsmc, chfsnp_fnode, cbytes ))
    {
        CHFSMCLIST *chfsmclist;

        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_update_dn_no_lock: update file %s to dn failed\n",
                           (char *)cstring_get_str(file_path));

        /*
         * When trying to write dn failed,
         * how to deal with np?
         * Should remove np from mem cache?

         * Because dn has been released and new content should be written to dn, but it failed,
         * so np should also remove from mem cache, right?
         */

        chfsmclist = CHFSMC_LIST(chfsmc);

        chfsmclist_pop_head(chfsmclist);

        /* np is got by chfsmc_reserve_np_no_lock, when data first written to mem cache */
        chfsmc_release_np_no_lock(chfsmc, file_path);

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*recycle from chfsmclist if need*/
STATIC_CAST static EC_BOOL __chfsmc_recycle_np_no_lock(CHFSMC *chfsmc, const uint32_t node_pos)
{
    CHFSNP      *chfsnp;
    CHFSMCLIST  *chfsmclist;

    CHFSNP_ITEM *chfsnp_item;

    chfsnp     = CHFSMC_NP(chfsmc);
    chfsmclist = CHFSMC_LIST(chfsmc);

    chfsnp_item = chfsnp_fetch(chfsnp, node_pos);
    if(NULL_PTR == chfsnp_item)
    {
        return (EC_FALSE);
    }

    if(EC_TRUE == chfsmclist_node_is_used(chfsmclist, node_pos))
    {
        chfsmclist_node_del(chfsmclist, node_pos);
    }
    return (EC_TRUE);
}

EC_BOOL chfsmc_delete_no_lock(CHFSMC *chfsmc, const CSTRING *file_path)
{
    CHFSNP *chfsnp;
    uint32_t node_pos;

    chfsnp = CHFSMC_NP(chfsmc);

    node_pos = chfsnp_search_no_lock(chfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path));
    if(CHFSNPRB_ERR_POS != node_pos)
    {
        UINT32  complete_num;

        chfsnp_umount_item(chfsnp, node_pos);

        complete_num = 0;
        chfsmc_recycle_no_lock(chfsmc, CHFSMC_RECYCLE_MAX_NUM, &complete_num);
        dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_delete_no_lock: delete path %s and recycle %ld done\n",
                           (char *)cstring_get_str(file_path), complete_num);
        return (EC_TRUE);
    }

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_delete_no_lock: not found path %s\n",
                   (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL chfsmc_retire_no_lock(CHFSMC *chfsmc)
{
    CHFSNP     *chfsnp;
    CHFSMCLIST *chfsmclist;
    uint32_t node_pos;

    /*retire the oldest from LRU list*/
    chfsnp     = CHFSMC_NP(chfsmc);
    chfsmclist = CHFSMC_LIST(chfsmc);

    node_pos = chfsmclist_pop_tail(chfsmclist);

    if(CHFSMCLIST_ERR_POS != node_pos)
    {
        UINT32  complete_num;

        chfsnp_umount_item(chfsnp, node_pos);

        complete_num = 0;
        chfsmc_recycle_no_lock(chfsmc, CHFSMC_RECYCLE_MAX_NUM, &complete_num);
        dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_retire_no_lock: recycle %ld done\n",
                           complete_num);

        return (EC_TRUE);
    }

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_retire_no_lock: no cached to recycle\n");
    return (EC_TRUE);
}

EC_BOOL chfsmc_recycle_no_lock(CHFSMC *chfsmc, const UINT32 max_num, UINT32 *complete_num)
{
    CHFSNP     *chfsnp;
    CHFSNP_RECYCLE_DN chfsnp_recycle_dn;
    CHFSNP_RECYCLE_NP chfsnp_recycle_np;

    chfsnp     = CHFSMC_NP(chfsmc);

    CHFSNP_RECYCLE_DN_ARG1(&chfsnp_recycle_dn)   = (UINT32)chfsmc;
    CHFSNP_RECYCLE_DN_FUNC(&chfsnp_recycle_dn)   = (CHFSNP_RECYCLE_DN_FUNC)__chfsmc_release_dn_no_lock;

    CHFSNP_RECYCLE_NP_ARG1(&chfsnp_recycle_np)   = (UINT32)chfsmc;
    CHFSNP_RECYCLE_NP_FUNC(&chfsnp_recycle_np)   = (CHFSNP_RECYCLE_NP_FUNC)__chfsmc_recycle_np_no_lock;

    if(EC_FALSE == chfsnp_recycle(chfsnp, max_num, &chfsnp_recycle_np, &chfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_recycle_no_lock: recycle failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chfsmc_write(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    CHFSMC_WRLOCK(chfsmc, LOC_CHFSMC_0015);
    if(EC_FALSE == chfsmc_write_no_lock(chfsmc, file_path, cbytes ))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0016);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_write: write %s with %ld bytes failed\n",
                           (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0017);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_write: write %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL chfsmc_read(CHFSMC *chfsmc, const CSTRING *file_path, CBYTES *cbytes)
{
    CHFSMC_RDLOCK(chfsmc, LOC_CHFSMC_0018);
    if(EC_FALSE == chfsmc_read_no_lock(chfsmc, file_path, cbytes))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0019);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_read: read %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0020);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_read: read %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL chfsmc_read_e(CHFSMC *chfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    CHFSMC_RDLOCK(chfsmc, LOC_CHFSMC_0021);
    if(EC_FALSE == chfsmc_read_e_no_lock(chfsmc, file_path, store_offset, store_size, cbytes))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0022);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_read_e: read %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0023);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_read_e: read %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL chfsmc_file_size(CHFSMC *chfsmc, const CSTRING *file_path, uint64_t *file_size)
{
    CHFSMC_RDLOCK(chfsmc, LOC_CHFSMC_0024);
    if(EC_FALSE == chfsmc_file_size_no_lock(chfsmc, file_path, file_size))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0025);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_file_size: get size of file %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0026);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_file_size: get size of file %s done, file size = %"PRId64"\n",
                       (char *)cstring_get_str(file_path), (*file_size));

    return (EC_TRUE);
}

EC_BOOL chfsmc_update(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes )
{
    CHFSMC_WRLOCK(chfsmc, LOC_CHFSMC_0027);
    if(EC_FALSE == chfsmc_update_no_lock(chfsmc, file_path, cbytes ))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0028);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_update: update %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0029);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_update: update %s done\n",
                       (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL chfsmc_delete(CHFSMC *chfsmc, const CSTRING *file_path)
{
    CHFSMC_WRLOCK(chfsmc, LOC_CHFSMC_0030);
    if(EC_FALSE == chfsmc_delete_no_lock(chfsmc, file_path))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0031);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_delete: delete %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0032);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_delete: delete %s done\n",
                       (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL chfsmc_retire(CHFSMC *chfsmc)
{
    CHFSMC_WRLOCK(chfsmc, LOC_CHFSMC_0033);
    if(EC_FALSE == chfsmc_retire_no_lock(chfsmc))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0034);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_retire: retire failed\n");
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0035);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_retire: retire done\n");
    return (EC_TRUE);
}

EC_BOOL chfsmc_recycle(CHFSMC *chfsmc, const UINT32 max_num, UINT32 *complete_num)
{
    CHFSMC_WRLOCK(chfsmc, LOC_CHFSMC_0036);
    if(EC_FALSE == chfsmc_recycle_no_lock(chfsmc, max_num, complete_num))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0037);
        dbg_log(SEC_0160_CHFSMC, 1)(LOGSTDOUT, "error:chfsmc_recycle: recycle failed\n");
        return (EC_FALSE);
    }
    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0038);

    dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_recycle: recycle done\n");
    return (EC_TRUE);
}

void chfsmc_print(LOG *log, const CHFSMC *chfsmc)
{
    sys_print(log, "chfsmc_print: chfsmc %p: chfs_md_id %ld, chfsnp %p, cpgd %p, chfsmclist %p, mcache %p\n",
             chfsmc, CHFSMC_CHFS_MD_ID(chfsmc), CHFSMC_NP(chfsmc), CHFSMC_PGD(chfsmc), CHFSMC_LIST(chfsmc), CHFSMC_MCACHE(chfsmc));

    sys_print(log, "chfsmc_print: chfsmc %p: chfsnp %p:\n", chfsmc, CHFSMC_NP(chfsmc));
    chfsnp_print(log, CHFSMC_NP(chfsmc));

    sys_print(log, "chfsmc_print: chfsmc %p: cpgd %p:\n", chfsmc, CHFSMC_PGD(chfsmc));
    cpgd_print(log, CHFSMC_PGD(chfsmc));

    sys_print(log, "chfsmc_print: chfsmc %p: chfsmclist %p:\n", chfsmc, CHFSMC_LIST(chfsmc));
    chfsmclist_print(log, CHFSMC_LIST(chfsmc));

    return;
}

EC_BOOL chfsmc_ensure_room_safe_level(CHFSMC *chfsmc)
{
    CHFSMC_WRLOCK(chfsmc, LOC_CHFSMC_0039);
    if(EC_FALSE == chfsmc_ensure_room_safe_level_no_lock(chfsmc))
    {
        CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0040);
        return (EC_FALSE);
    }

    CHFSMC_UNLOCK(chfsmc, LOC_CHFSMC_0041);
    return (EC_TRUE);
}

EC_BOOL chfsmc_ensure_room_safe_level_no_lock(CHFSMC *chfsmc)
{
    uint32_t retire_times;

    retire_times = 0;

    while(EC_FALSE == chfsmc_room_is_ok_no_lock(chfsmc, CHFSMC_ROOM_SAFE_LEVEL))
    {
        if(EC_FALSE == chfsmc_retire_no_lock(chfsmc)) /* retire & recycle, always return EC_TRUE */
        {
            /* will never reach here */
            chfsmc_recycle_no_lock(chfsmc, CHFSMC_RECYCLE_MAX_NUM, NULL_PTR);

            dbg_log(SEC_0160_CHFSMC, 0)(LOGSTDOUT, "error:chfsmc_ensure_room_safe_level_no_lock: retire failed\n");
            return (EC_FALSE);
        }

        retire_times ++;
    }

    if(0 < retire_times)
    {
        dbg_log(SEC_0160_CHFSMC, 9)(LOGSTDOUT, "[DEBUG] chfsmc_ensure_room_safe_level_no_lock: retire times %u\n", retire_times);
        chfsmc_recycle_no_lock(chfsmc, CHFSMC_RECYCLE_MAX_NUM, NULL_PTR);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

