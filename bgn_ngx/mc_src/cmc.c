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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>

#include <sys/stat.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cmc.h"


static CMC_MD g_cmc_md[ CMC_MAX_MODI ];
static UINT32 g_cmc_md_pos = 0;

#define CMC_MD_CAPACITY()         (CMC_MAX_MODI)

#define CMD_MD_NEW()              (g_cmc_md_pos ++)
#define CMD_MD_FREE(cmc_md_id)    do{}while(0)

#define CMC_MD_GET(cmc_md_id)     ((CMC_MD *)&g_cmc_md[ (cmc_md_id) ])

STATIC_CAST static CMCNP_FNODE * __cmc_reserve_np(const UINT32 cmc_md_id, const CSTRING *file_path);
STATIC_CAST static EC_BOOL __cmc_release_np(const UINT32 cmc_md_id, const CSTRING *file_path);


/**
*
* start CMC module
*
**/
UINT32 cmc_start()
{
    CMC_MD  *cmc_md;
    UINT32   cmc_md_id;

    cmc_md_id = CMD_MD_NEW();

    /*check validity*/
    if(CMC_MAX_MODI < cmc_md_id)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_start: cmc_md_id %ld overflow\n", cmc_md_id);

        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CMC module */
    cmc_md = CMC_MD_GET(cmc_md_id);

    /* create a new module node */
    init_static_mem();

    CMC_MD_DN(cmc_md) = NULL_PTR;
    CMC_MD_NP(cmc_md) = NULL_PTR;

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_start: start CMC module #%ld\n", cmc_md_id);

    return ( cmc_md_id );
}

/**
*
* end CMC module
*
**/
void cmc_end(const UINT32 cmc_md_id)
{
    CMC_MD *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);
    if(NULL_PTR == cmc_md)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_end: cmc_md_id = %ld not exist.\n", cmc_md_id);
        return;
    }

    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        cmcdn_free(CMC_MD_DN(cmc_md));
        CMC_MD_DN(cmc_md) = NULL_PTR;
    }

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        cmcnp_free(CMC_MD_NP(cmc_md));
        CMC_MD_NP(cmc_md) = NULL_PTR;
    }

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "cmc_end: stop CMC module #%ld\n", cmc_md_id);
    CMD_MD_FREE(cmc_md_id);

    return ;
}

/**
*
*  create name node pool
*
**/
EC_BOOL cmc_create_np(const UINT32 cmc_md_id, const UINT32 cmcnp_model)
{
    CMC_MD *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: np already exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(cmcnp_model))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: cmcnp_model %u is invalid\n", (uint32_t)cmcnp_model);
        return (EC_FALSE);
    }

    CMC_MD_NP(cmc_md) = cmcnp_create((uint8_t ) cmcnp_model);
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: create np failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


/**
*
*  check file existence
*
**/
EC_BOOL cmc_find(const UINT32 cmc_md_id, const CSTRING *file_path)
{
    CMC_MD    *cmc_md;
    EC_BOOL    ret;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_find: np was not open\n");
        return (EC_FALSE);
    }

    ret = cmcnp_search(CMC_MD_NP(cmc_md), file_path, CMCNP_ITEM_FILE_IS_REG);
    return (ret);
}


/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __cmc_reserve_hash_dn(const UINT32 cmc_md_id, const UINT32 data_len, const uint32_t path_hash, CMCNP_FNODE *cmcnp_fnode)
{
    CMC_MD      *cmc_md;
    CMCNP_INODE *cmcnp_inode;
    CPGV        *cpgv;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint16_t fail_tries;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CMCDN_CMCPGV(CMC_MD_DN(cmc_md)))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cpgv = CMCDN_CMCPGV(CMC_MD_DN(cmc_md));
    if(NULL_PTR == CPGV_HEADER(cpgv))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CPGV_PAGE_DISK_NUM(cpgv))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: pgv has no disk yet\n");
        return (EC_FALSE);
    }

    fail_tries = 0;
    for(;;)
    {
        size    = (uint32_t)(data_len);
        disk_no = (uint16_t)(path_hash % CPGV_PAGE_DISK_NUM(cpgv));

        if(EC_TRUE == cpgv_new_space_from_disk(cpgv, size, disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        /*try again*/
        if(EC_TRUE == cpgv_new_space(cpgv, size, &disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        fail_tries ++;

        if(1 < fail_tries) /*try once only*/
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: "
                                                 "new %ld bytes space from vol failed\n",
                                                 data_len);
            return (EC_FALSE);
        }

        /*try to retire & recycle some files*/
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "warn:__cmc_reserve_hash_dn: "
                                             "no %ld bytes space, try to retire & recycle\n",
                                             data_len);
        cmc_retire(cmc_md_id, (UINT32)CMC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cmc_recycle(cmc_md_id, (UINT32)CMC_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    cmcnp_fnode_init(cmcnp_fnode);
    CMCNP_FNODE_FILESZ(cmcnp_fnode) = size;
    CMCNP_FNODE_REPNUM(cmcnp_fnode) = 1;

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    CMCNP_INODE_DISK_NO(cmcnp_inode)    = disk_no;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = block_no;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL cmc_reserve_dn(const UINT32 cmc_md_id, const UINT32 data_len, CMCNP_FNODE *cmcnp_fnode)
{
    CMC_MD      *cmc_md;
    CMCNP_INODE *cmcnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    if(EC_FALSE == cpgv_new_space(CMCDN_CMCPGV(CMC_MD_DN(cmc_md)), size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: new %ld bytes space from vol failed\n", data_len);
        return (EC_FALSE);
    }

    cmcnp_fnode_init(cmcnp_fnode);
    CMCNP_FNODE_FILESZ(cmcnp_fnode) = size;
    CMCNP_FNODE_REPNUM(cmcnp_fnode) = 1;

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    CMCNP_INODE_DISK_NO(cmcnp_inode)    = disk_no;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = block_no;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  release space to dn
*
**/
EC_BOOL cmc_release_dn(const UINT32 cmc_md_id, const CMCNP_FNODE *cmcnp_fnode)
{
    CMC_MD *cmc_md;
    const CMCNP_INODE *cmcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size    = CMCNP_FNODE_FILESZ(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    if(CPGB_CACHE_MAX_BYTE_SIZE < file_size)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: file_size %u overflow\n", file_size);
        return (EC_FALSE);
    }

    /*refer __cmc_write: when file size is zero, only reserve np but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_release_dn: file_size is zero\n");
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    if(EC_FALSE == cpgv_free_space(CMCDN_CMCPGV(CMC_MD_DN(cmc_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_release_dn: remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write a file
*
**/
STATIC_CAST static EC_BOOL __cmc_write(const UINT32 cmc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    //CMC_MD      *cmc_md;
    CMCNP_FNODE  *cmcnp_fnode;
    uint32_t      path_hash;

    //cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode = __cmc_reserve_np(cmc_md_id, file_path);
    if(NULL_PTR == cmcnp_fnode)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_write: file %s reserve np failed\n", (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    /*calculate hash value of file_path*/
    path_hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cmcnp_fnode_init(cmcnp_fnode);
        CMCNP_FNODE_HASH(cmcnp_fnode) = path_hash;

        if(do_log(SEC_0118_CMC, 1))
        {
            sys_log(LOGSTDOUT, "warn:__cmc_write: write file %s with zero len to dn where fnode is \n", (char *)cstring_get_str(file_path));
            cmcnp_fnode_print(LOGSTDOUT, cmcnp_fnode);
        }

        return (EC_TRUE);
    }

    if(EC_FALSE == __cmc_reserve_hash_dn(cmc_md_id, CBYTES_LEN(cbytes), path_hash, cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_write: reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __cmc_release_np(cmc_md_id, file_path);

        return (EC_FALSE);
    }

    if(EC_FALSE == cmc_export_dn(cmc_md_id, cbytes, cmcnp_fnode))
    {
        cmc_release_dn(cmc_md_id, cmcnp_fnode);

        __cmc_release_np(cmc_md_id, file_path);

        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_write: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    CMCNP_FNODE_HASH(cmcnp_fnode) = path_hash;

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cmc_write: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        cmcnp_fnode_print(LOGSTDOUT, cmcnp_fnode);
    }

    return (EC_TRUE);
}


EC_BOOL cmc_write(const UINT32 cmc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    return __cmc_write(cmc_md_id, file_path, cbytes);
}

EC_BOOL cmc_read(const UINT32 cmc_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE   cmcnp_fnode;

    cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode_init(&cmcnp_fnode);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read: read file %s start\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), file_path, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_read: read file %s from np failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read: read file %s from np done\n", (char *)cstring_get_str(file_path));

    /*exception*/
    if(0 == CMCNP_FNODE_FILESZ(&cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_read: read file %s with zero len from np and fnode %p is \n", (char *)cstring_get_str(file_path), &cmcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cmc_read_dn(cmc_md_id, &cmcnp_fnode, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read: read file %s from dn failed where fnode is \n", (char *)cstring_get_str(file_path));
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_FALSE);
    }

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_read: read file %s with size %ld done\n",
                            (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
    }
    return (EC_TRUE);
}

/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a file at offset
*
**/
EC_BOOL cmc_write_e(const UINT32 cmc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE   cmcnp_fnode;
    uint32_t      file_old_size;

    cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode_init(&cmcnp_fnode);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), file_path, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e: read file %s from np failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    file_old_size = CMCNP_FNODE_FILESZ(&cmcnp_fnode);

    if(EC_FALSE == cmc_write_e_dn(cmc_md_id, &cmcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e: offset write to dn failed\n");
        return (EC_FALSE);
    }

    if(file_old_size != CMCNP_FNODE_FILESZ(&cmcnp_fnode))
    {
        if(EC_FALSE == cmcnp_update(CMC_MD_NP(cmc_md), file_path, &cmcnp_fnode))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e: offset write file %s to np failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL cmc_read_e(const UINT32 cmc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE   cmcnp_fnode;

    cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode_init(&cmcnp_fnode);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), file_path, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e: read file %s from np failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_read_e: read file %s from np and fnode %p is \n",
                           (char *)cstring_get_str(file_path),
                           &cmcnp_fnode);
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
    }

    /*exception*/
    if(0 == CMCNP_FNODE_FILESZ(&cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_read_e: read file %s with zero len from np and fnode %p is \n", (char *)cstring_get_str(file_path), &cmcnp_fnode);
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cmc_read_e_dn(cmc_md_id, &cmcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e: offset read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL cmc_export_dn(const UINT32 cmc_md_id, const CBYTES *cbytes, const CMCNP_FNODE *cmcnp_fnode)
{
    CMC_MD            *cmc_md;
    const CMCNP_INODE *cmcnp_inode;

    UINT32   offset;
    UINT32   data_len;
    //uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    cmc_md = CMC_MD_GET(cmc_md_id);

    data_len = DMIN(CBYTES_LEN(cbytes), CMCNP_FNODE_FILESZ(cmcnp_fnode));

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: CBYTES_LEN %u or CMCNP_FNODE_FILESZ %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CMCNP_FNODE_FILESZ(cmcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    //size = (uint32_t)data_len;

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == cmcdn_write_o(CMC_MD_DN(cmc_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: write %ld bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    //dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_export_dn: write %ld bytes to disk %u block %u page %u done\n",
    //                    data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL cmc_write_dn(const UINT32 cmc_md_id, const CBYTES *cbytes, CMCNP_FNODE *cmcnp_fnode)
{
    CMC_MD      *cmc_md;
    CMCNP_INODE *cmcnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: no dn was open\n");
        return (EC_FALSE);
    }

    cmcnp_fnode_init(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    if(EC_FALSE == cmcdn_write_p(CMC_MD_DN(cmc_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CMCNP_INODE_DISK_NO(cmcnp_inode)    = disk_no;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode)   = block_no;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)    = page_no;

    CMCNP_FNODE_FILESZ(cmcnp_fnode) = CBYTES_LEN(cbytes);
    CMCNP_FNODE_REPNUM(cmcnp_fnode) = 1;

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL cmc_read_dn(const UINT32 cmc_md_id, const CMCNP_FNODE *cmcnp_fnode, CBYTES *cbytes)
{
    CMC_MD            *cmc_md;
    const CMCNP_INODE *cmcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CMCNP_FNODE_REPNUM(cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = CMCNP_FNODE_FILESZ(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    //dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CMC_0005);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CMC_0006);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cmcdn_read_p(CMC_MD_DN(cmc_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                           file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cmc_write_e_dn(const UINT32 cmc_md_id, CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CMC_MD      *cmc_md;
    CMCNP_INODE *cmcnp_inode;

    uint32_t file_size;
    uint32_t file_max_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: offset %ld + buff len (or file size) %ld = %ld overflow\n",
                            (*offset), CBYTES_LEN(cbytes), (*offset) + CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size   = CMCNP_FNODE_FILESZ(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CPGB_PAGE_BYTE_SIZE - 1) >> CPGB_PAGE_BIT_SIZE) << CPGB_PAGE_BIT_SIZE);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: offset %ld overflow due to file max size is %u\n", (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(EC_FALSE == cmcdn_write_e(CMC_MD_DN(cmc_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    (*offset) += max_len_t;
    if((*offset) > file_size)
    {
        /*update file size info*/
        CMCNP_FNODE_FILESZ(cmcnp_fnode) = (uint32_t)(*offset);
    }

    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cmc_read_e_dn(const UINT32 cmc_md_id, const CMCNP_FNODE *cmcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CMC_MD            *cmc_md;
    const CMCNP_INODE *cmcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CMCNP_FNODE_REPNUM(cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = CMCNP_FNODE_FILESZ(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: due to offset %ld >= file size %u\n", (*offset), file_size);
        return (EC_FALSE);
    }

    offset_t = (uint32_t)(*offset);
    if(0 == max_len)
    {
        max_len_t = file_size - offset_t;
    }
    else
    {
        max_len_t = DMIN(max_len, file_size - offset_t);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read_e_dn: file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    if(CBYTES_LEN(cbytes) < max_len_t)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CMC_0007);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CMC_0008);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cmcdn_read_e(CMC_MD_DN(cmc_md), disk_no, block_no, page_no, offset_t, max_len_t, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: read %ld bytes from disk %u, block %u, offset %u failed\n",
                           max_len_t, disk_no, block_no, offset_t);
        return (EC_FALSE);
    }

    (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}

/**
*
*  reserve a fnode from name node
*
**/
STATIC_CAST static CMCNP_FNODE * __cmc_reserve_np(const UINT32 cmc_md_id, const CSTRING *file_path)
{
    CMC_MD      *cmc_md;
    CMCNP_FNODE *cmcnp_fnode;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_np: np was not open\n");
        return (NULL_PTR);
    }

    cmcnp_fnode = cmcnp_reserve(CMC_MD_NP(cmc_md), file_path);
    if(NULL_PTR == cmcnp_fnode)
    {
        /*try to retire & recycle some files*/
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "warn:__cmc_reserve_np: no name node accept file %s, try to retire & recycle\n",
                            (char *)cstring_get_str(file_path));
        cmc_retire(cmc_md_id, (UINT32)CMC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cmc_recycle(cmc_md_id, (UINT32)CMC_TRY_RECYCLE_MAX_NUM, NULL_PTR);

        /*try again*/
        cmcnp_fnode = cmcnp_reserve(CMC_MD_NP(cmc_md), file_path);
        if(NULL_PTR == cmcnp_fnode)/*Oops!*/
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_np: no name node accept file %s\n",
                                (char *)cstring_get_str(file_path));
            return (NULL_PTR);
        }
    }

    return (cmcnp_fnode);
}


/**
*
*  release a fnode from name node
*
**/
STATIC_CAST static EC_BOOL __cmc_release_np(const UINT32 cmc_md_id, const CSTRING *file_path)
{
    CMC_MD      *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_release_np: np was not open\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cmcnp_release(CMC_MD_NP(cmc_md), file_path))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_release_np: release file %s from np failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


/**
*
*  delete a file
*
**/
EC_BOOL cmc_delete(const UINT32 cmc_md_id, const CSTRING *path)
{
    CMC_MD      *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_delete: np was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_delete: cmc_md_id %ld, path %s ...\n",
                        cmc_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == cmcnp_umount_deep(CMC_MD_NP(cmc_md), path, CMCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_delete: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_delete: cmc_md_id %ld, path %s done\n",
                        cmc_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL cmc_update(const UINT32 cmc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CMC_MD      *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), file_path, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == cmc_write(cmc_md_id, file_path, cbytes))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_update: write file %s failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_update: write file %s done\n", (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }


    /*file exist, update it*/
    if(EC_FALSE == cmc_delete(cmc_md_id, file_path))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_update: delete old file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_update: delete old file %s done\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == cmc_write(cmc_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_update: write new file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_update: write new file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cmc_file_num(const UINT32 cmc_md_id, const CSTRING *path_cstr, UINT32 *file_num)
{
    CMC_MD      *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_file_num: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_file_num(CMC_MD_NP(cmc_md), path_cstr, file_num))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_num: get file num of path '%s' failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cmc_file_size(const UINT32 cmc_md_id, const CSTRING *path_cstr, uint64_t *file_size)
{
    CMC_MD      *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_file_size: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_file_size(CMC_MD_NP(cmc_md), path_cstr, file_size))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_size: cmcnp mgr get size of %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_size: file %s, size %ld\n",
                             (char *)cstring_get_str(path_cstr),
                             (*file_size));
    return (EC_TRUE);
}

/**
*
*  search in current name node pool
*
**/
EC_BOOL cmc_search(const UINT32 cmc_md_id, const CSTRING *path_cstr, const UINT32 dflag)
{
    CMC_MD       *cmc_md;
    uint32_t      cmcnp_id;

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_search: cmc_md_id %ld, path %s, dflag %lx\n", cmc_md_id, (char *)cstring_get_str(path_cstr), dflag);

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_search: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_search(CMC_MD_NP(cmc_md), (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag, &cmcnp_id))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_search: search '%s' with dflag %lx failed\n", (char *)cstring_get_str(path_cstr), dflag);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL cmc_recycle(const UINT32 cmc_md_id, const UINT32 max_num_per_np, UINT32 *complete_num)
{
    CMC_MD          *cmc_md;
    CMCNP_RECYCLE_DN cmcnp_recycle_dn;
    UINT32           complete_recycle_num;

    dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "[DEBUG] cmc_recycle: recycle beg\n");

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_recycle: np was not open\n");
        return (EC_FALSE);
    }

    CMCNP_RECYCLE_DN_ARG1(&cmcnp_recycle_dn)   = cmc_md_id;
    CMCNP_RECYCLE_DN_FUNC(&cmcnp_recycle_dn)   = cmc_release_dn;    

    complete_recycle_num = 0;/*initialization*/

    if(EC_FALSE == cmcnp_recycle(CMC_MD_NP(cmc_md),  max_num_per_np, NULL_PTR, &cmcnp_recycle_dn, &complete_recycle_num))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_recycle: recycle np failed\n");
        return (EC_FALSE);
    }
    
    dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "[DEBUG] cmc_recycle: recycle end where complete %ld\n", complete_recycle_num);

    if(NULL_PTR != complete_num)
    {
        (*complete_num) = complete_recycle_num;
    }
    return (EC_TRUE);
}


/**
*
*  show name node 
*
*
**/
EC_BOOL cmc_show_np(const UINT32 cmc_md_id, LOG *log)
{
    CMC_MD *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print(log, CMC_MD_NP(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show cmcdn info if it is dn
*
*
**/
EC_BOOL cmc_show_dn(const UINT32 cmc_md_id, LOG *log)
{
    CMC_MD *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcdn_print(log, CMC_MD_DN(cmc_md));

    return (EC_TRUE);
}


/**
*
*  retire files
*
**/
EC_BOOL cmc_retire(const UINT32 cmc_md_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CMC_MD      *cmc_md;

    UINT32       total_num;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_retire: np was not open\n");
        return (EC_FALSE);
    }

    cmcnp_retire(CMC_MD_NP(cmc_md), expect_retire_num, complete_retire_num);

    if(NULL_PTR != complete_retire_num)
    {
        (*complete_retire_num) = total_num;
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_retire: retire done where complete %ld\n", total_num);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

