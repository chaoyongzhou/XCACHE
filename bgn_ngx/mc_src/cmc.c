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

#include "debug.h"

#include "cmisc.h"
#include "cbc.h"
#include "csig.h"
#include "cbytes.h"
#include "cmc.h"

#define CMC_MD_CAPACITY()                  (cbc_md_capacity(MD_CMC))

#define CMC_MD_GET(cmc_md_id)     ((CMC_MD *)cbc_md_get(MD_CMC, (cmc_md_id)))

#define CMC_MD_ID_CHECK_INVALID(cmc_md_id)  \
    ((CMPI_ANY_MODI != (cmc_md_id)) && ((NULL_PTR == CMC_MD_GET(cmc_md_id)) || (0 == (CMC_MD_GET(cmc_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CMC Module
*
**/
void cmc_print_module_status(const UINT32 cmc_md_id, LOG *log)
{
    CMC_MD *cmc_md;
    UINT32 this_cmc_md_id;

    for( this_cmc_md_id = 0; this_cmc_md_id < CMC_MD_CAPACITY(); this_cmc_md_id ++ )
    {
        cmc_md = CMC_MD_GET(this_cmc_md_id);

        if ( NULL_PTR != cmc_md && 0 < cmc_md->usedcounter )
        {
            sys_log(log,"CMC Module # %ld : %ld refered\n",
                    this_cmc_md_id,
                    cmc_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CMC module
*
*
**/
UINT32 cmc_free_module_static_mem(const UINT32 cmc_md_id)
{
    //CMC_MD  *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_free_module_static_mem: cmc module #%ld not started.\n",
                cmc_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CMC_DEBUG_SWITCH*/

    //cmc_md = CMC_MD_GET(cmc_md_id);

    free_module_static_mem(MD_CMC, cmc_md_id);

    return 0;
}

/**
*
* start CMC module
*
**/
UINT32 cmc_start(const UINT32 np_model, const UINT32 disk_num)
{
    CMC_MD  *cmc_md;
    UINT32   cmc_md_id;

    init_static_mem();

    cbc_md_reg(MD_CMC, 32);

    cmc_md_id = cbc_md_new(MD_CMC, sizeof(CMC_MD));
    if(CMPI_ERROR_MODI == cmc_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CMC module */

    cmc_md = (CMC_MD *)cbc_md_get(MD_CMC, cmc_md_id);
    cmc_md->usedcounter   = 0;

    CMC_MD_DN(cmc_md) = NULL_PTR;
    CMC_MD_NP(cmc_md) = NULL_PTR;

    cmc_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cmc_end, cmc_md_id);

    if(EC_FALSE == cmc_create_np(cmc_md_id, np_model))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_start: CMC module #%ld create np failed\n", cmc_md_id);
        cmc_end(cmc_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == cmc_create_dn(cmc_md_id, disk_num))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_start: CMC module #%ld create dn failed\n", cmc_md_id);
        cmc_end(cmc_md_id);
        return (CMPI_ERROR_MODI);
    }

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "[DEBUG] cmc_start: start CMC module #%ld\n", cmc_md_id);

    return (cmc_md_id);
}

/**
*
* end CMC module
*
**/
void cmc_end(const UINT32 cmc_md_id)
{
    CMC_MD      *cmc_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cmc_end, cmc_md_id);

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == cmc_md)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_end: CMC module #%ld not exist.\n", cmc_md_id);
        return;
    }

    cmc_close_np(cmc_md_id);
    cmc_close_dn(cmc_md_id);

    dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "cmc_end: stop CMC module #%ld\n", cmc_md_id);
    cbc_md_free(MD_CMC, cmc_md_id);

    return;
}

/**
*
*  create name node
*
**/
EC_BOOL cmc_create_np(const UINT32 cmc_md_id, const UINT32 cmcnp_model)
{
    CMC_MD      *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_create_np: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: cmc %ld np already exist\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(cmcnp_model))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: cmc %ld cmcnp_model %ld is invalid\n",
                        cmc_md_id, cmcnp_model);
        return (EC_FALSE);
    }

    CMC_MD_NP(cmc_md) = cmcnp_create((uint32_t)0/*cmcnp_id*/, (uint8_t)cmcnp_model);
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_np: cmc %ld create np failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  close name node
*
**/
EC_BOOL cmc_close_np(const UINT32 cmc_md_id)
{
    CMC_MD      *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_close_np: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR != CMC_MD_NP(cmc_md))
    {
        cmcnp_free(CMC_MD_NP(cmc_md));
        CMC_MD_NP(cmc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}


/**
*
*  create data node
*
**/
EC_BOOL cmc_create_dn(const UINT32 cmc_md_id, const UINT32 disk_num)
{
    CMC_MD      *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_create_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_dn: cmc %ld dn already exist\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_num))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_dn: cmc %ld disk_num %ld is invalid\n",
                        cmc_md_id, disk_num);
        return (EC_FALSE);
    }

    CMC_MD_DN(cmc_md) = cmcdn_create((uint16_t)disk_num);
    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_create_dn: cmc %ld create dn failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL cmc_close_dn(const UINT32 cmc_md_id)
{
    CMC_MD      *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_close_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR != CMC_MD_DN(cmc_md))
    {
        cmcdn_free(CMC_MD_DN(cmc_md));
        CMC_MD_DN(cmc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static void __cmc_find_intersected_print(const CMCNP_KEY *cmcnp_key, const CMCNP_KEY *cmcnp_key_intersected, const CMCNP_KEY *cmcnp_key_next)
{
    sys_log(LOGSTDOUT, "[DEBUG] __cmc_find_intersected_print: key [%u, %u), intersected [%u, %u), next [%u, %u)\n",
                       CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key),
                       CMCNP_KEY_S_PAGE(cmcnp_key_intersected), CMCNP_KEY_E_PAGE(cmcnp_key_intersected),
                       CMCNP_KEY_S_PAGE(cmcnp_key_next), CMCNP_KEY_E_PAGE(cmcnp_key_next));
}
/**
*
*  find intersected range
*
**/
EC_BOOL cmc_find_intersected(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key)
{
    CMC_MD           *cmc_md;

    CMCNP_ITEM       *cmcnp_item_intersected;
    CMCNP_KEY        *cmcnp_key_intersected;
    uint32_t          node_pos_intersected;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_find_intersected: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_find_intersected: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    node_pos_intersected = cmcnp_find_intersected(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS == node_pos_intersected)
    {
        return (EC_FALSE);
    }

    cmcnp_item_intersected = cmcnp_fetch(CMC_MD_NP(cmc_md), node_pos_intersected);
    if(NULL_PTR == cmcnp_item_intersected)
    {
        return (EC_FALSE);
    }

    cmcnp_key_intersected = CMCNP_ITEM_KEY(cmcnp_item_intersected);

    if(CMCNP_KEY_S_PAGE(cmcnp_key) >= CMCNP_KEY_S_PAGE(cmcnp_key_intersected))
    {
        if(CMCNP_KEY_E_PAGE(cmcnp_key) >= CMCNP_KEY_E_PAGE(cmcnp_key_intersected))
        {
            CMCNP_KEY  cmcnp_key_next;

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key_intersected);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key);

            __cmc_find_intersected_print(cmcnp_key, cmcnp_key_intersected, &cmcnp_key_next);

            cmc_find_intersected(cmc_md_id, &cmcnp_key_next);

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key_intersected);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key);
            __cmc_find_intersected_print(cmcnp_key, cmcnp_key_intersected, &cmcnp_key_next);

            cmc_find_intersected(cmc_md_id, &cmcnp_key_next);
        }
        else
        {
            /*no next*/
        }
    }
    else
    {
        if(CMCNP_KEY_E_PAGE(cmcnp_key) >= CMCNP_KEY_E_PAGE(cmcnp_key_intersected))
        {
            CMCNP_KEY  cmcnp_key_next;

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key_intersected);
            __cmc_find_intersected_print(cmcnp_key, cmcnp_key_intersected, &cmcnp_key_next);

            cmc_find_intersected(cmc_md_id, &cmcnp_key_next);

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key_intersected);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key);
            __cmc_find_intersected_print(cmcnp_key, cmcnp_key_intersected, &cmcnp_key_next);

            cmc_find_intersected(cmc_md_id, &cmcnp_key_next);
        }
        else
        {
            CMCNP_KEY  cmcnp_key_next;

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key_intersected);
            __cmc_find_intersected_print(cmcnp_key, cmcnp_key_intersected, &cmcnp_key_next);

            cmc_find_intersected(cmc_md_id, &cmcnp_key_next);
        }
    }

    return (EC_TRUE);
}

/**
*
*  find closest range
*
**/
EC_BOOL cmc_find_closest(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, CMCNP_KEY *cmcnp_key_closest)
{
    CMC_MD           *cmc_md;
    uint32_t          node_pos_closest;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_find_closest: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_find_closest: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    node_pos_closest = cmcnp_find_closest(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS == node_pos_closest)
    {
        return (EC_FALSE);
    }

    if(NULL_PTR != cmcnp_key_closest)
    {
        const CMCNP_ITEM *cmcnp_item_closest;

        cmcnp_item_closest = cmcnp_fetch(CMC_MD_NP(cmc_md), node_pos_closest);
        if(NULL_PTR == cmcnp_item_closest)
        {
            return (EC_FALSE);
        }
        cmcnp_key_clone(CMCNP_ITEM_KEY(cmcnp_item_closest), cmcnp_key_closest);
    }

    return (EC_TRUE);
}


/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __cmc_reserve_hash_dn(const UINT32 cmc_md_id, const UINT32 data_len, const uint32_t path_hash, CMCNP_FNODE *cmcnp_fnode)
{
    CMC_MD            *cmc_md;
    CMCNP_INODE       *cmcnp_inode;
    CMCPGV            *cmcpgv;

    uint32_t           size;
    uint16_t           disk_no;
    uint16_t           block_no;
    uint16_t           page_no;
    uint16_t           fail_tries;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: cmc %ld data_len %ld overflow\n",
                        cmc_md_id, data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: cmc %ld no dn was open\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(NULL_PTR == CMCDN_CMCPGV(CMC_MD_DN(cmc_md)))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: cmc %ld no pgv exist\n", cmc_md_id);
        return (EC_FALSE);
    }

    cmcpgv = CMCDN_CMCPGV(CMC_MD_DN(cmc_md));
    if(NULL_PTR == CMCPGV_HEADER(cmcpgv))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: cmc %ld pgv header is null\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(0 == CMCPGV_PAGE_DISK_NUM(cmcpgv))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: cmc %ld pgv has no disk yet\n", cmc_md_id);
        return (EC_FALSE);
    }

    fail_tries = 0;
    for(;;)
    {
        size    = (uint32_t)(data_len);
        disk_no = (uint16_t)(path_hash % CMCPGV_PAGE_DISK_NUM(cmcpgv));

        if(EC_TRUE == cmcpgv_new_space_from_disk(cmcpgv, size, disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        /*try again*/
        if(EC_TRUE == cmcpgv_new_space(cmcpgv, size, &disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        fail_tries ++;

        if(1 < fail_tries) /*try once only*/
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_hash_dn: "
                                                "cmc %ld new %ld bytes space from vol failed\n",
                                                cmc_md_id, data_len);
            return (EC_FALSE);
        }

        /*try to retire & recycle some files*/
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "warn:__cmc_reserve_hash_dn: "
                                            "cmc %ld no %ld bytes space, try to retire & recycle\n",
                                            cmc_md_id, data_len);
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
    CMC_MD            *cmc_md;
    CMCNP_INODE       *cmcnp_inode;

    uint32_t           size;
    uint16_t           disk_no;
    uint16_t           block_no;
    uint16_t           page_no;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_reserve_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: cmc %ld, data_len %ld overflow\n",
                        cmc_md_id, data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: cmc %ld no dn was open\n", cmc_md_id);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    if(EC_FALSE == cmcpgv_new_space(CMCDN_CMCPGV(CMC_MD_DN(cmc_md)), size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_reserve_dn: "
                        "cmc %ld new %ld bytes space from vol failed\n",
                        cmc_md_id, data_len);
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
    CMC_MD            *cmc_md;
    const CMCNP_INODE *cmcnp_inode;

    uint32_t           file_size;
    uint16_t           disk_no;
    uint16_t           block_no;
    uint16_t           page_no;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_release_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: cmc %ld no dn was open\n", cmc_md_id);
        return (EC_FALSE);
    }

    file_size    = CMCNP_FNODE_FILESZ(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < file_size)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: cmc %ld file_size %u overflow\n",
                        cmc_md_id, file_size);
        return (EC_FALSE);
    }

    /*refer cmc_write: when file size is zero, only reserve np but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_release_dn: cmc %ld file_size is zero\n", cmc_md_id);
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    if(EC_FALSE == cmcpgv_free_space(CMCDN_CMCPGV(CMC_MD_DN(cmc_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_release_dn: "
                        "cmc %ld free %u bytes to vol failed where disk %u, block %u, page %u\n",
                        cmc_md_id,
                        file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_release_dn: "
                    "cmc %ld remove file fsize %u, disk %u, block %u, page %u done\n",
                    cmc_md_id,
                    file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  reserve a fnode from name node
*
**/
STATIC_CAST static CMCNP_FNODE * __cmc_reserve_np(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE  *cmcnp_fnode;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_np: cmc %ld np was not open\n", cmc_md_id);
        return (NULL_PTR);
    }

    cmcnp_fnode = cmcnp_reserve(CMC_MD_NP(cmc_md), cmcnp_key);
    if(NULL_PTR == cmcnp_fnode)
    {
        /*try to retire & recycle some files*/
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "warn:__cmc_reserve_np: "
                        "cmc %ld no name node accept key, try to retire & recycle\n",
                        cmc_md_id);
        cmc_retire(cmc_md_id, (UINT32)CMC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cmc_recycle(cmc_md_id, (UINT32)CMC_TRY_RECYCLE_MAX_NUM, NULL_PTR);

        /*try again*/
        cmcnp_fnode = cmcnp_reserve(CMC_MD_NP(cmc_md), cmcnp_key);
        if(NULL_PTR == cmcnp_fnode)/*Oops!*/
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_reserve_np: cmc %ld no name node accept key\n", cmc_md_id);
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
STATIC_CAST static EC_BOOL __cmc_release_np(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key)
{
    CMC_MD       *cmc_md;

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_release_np: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_release(CMC_MD_NP(cmc_md), cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:__cmc_release_np: cmc %ld release key from np failed\n", cmc_md_id);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


/**
*
*  write a file
*
**/
EC_BOOL cmc_write(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE  *cmcnp_fnode;
    UINT32        page_num;
    UINT32        space_len;
    uint32_t      path_hash;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_write: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode = __cmc_reserve_np(cmc_md_id, cmcnp_key);
    if(NULL_PTR == cmcnp_fnode)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write: cmc %ld reserve np failed\n", cmc_md_id);

        return (EC_FALSE);
    }

    path_hash = cmcnp_key_hash(cmcnp_key);

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cmcnp_fnode_init(cmcnp_fnode);
        CMCNP_FNODE_HASH(cmcnp_fnode) = path_hash;

        if(do_log(SEC_0118_CMC, 1))
        {
            sys_log(LOGSTDOUT, "warn:cmc_write: cmc %ld write with zero len to dn where fnode is \n", cmc_md_id);
            cmcnp_fnode_print(LOGSTDOUT, cmcnp_fnode);
        }

        return (EC_TRUE);
    }

    /*note: when reserve space from data node, the length depends on cmcnp_key but not cbytes*/
    page_num  = (CMCNP_KEY_E_PAGE(cmcnp_key) - CMCNP_KEY_S_PAGE(cmcnp_key));
    space_len = (page_num << CMCPGB_PAGE_BIT_SIZE);

    if(EC_FALSE == __cmc_reserve_hash_dn(cmc_md_id, space_len, path_hash, cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write: cmc %ld reserve dn %u bytes failed\n",
                        cmc_md_id, (uint32_t)CBYTES_LEN(cbytes));

        __cmc_release_np(cmc_md_id, cmcnp_key);

        return (EC_FALSE);
    }

    if(EC_FALSE == cmc_export_dn(cmc_md_id, cbytes, cmcnp_fnode))
    {
        cmc_release_dn(cmc_md_id, cmcnp_fnode);

        __cmc_release_np(cmc_md_id, cmcnp_key);

        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write: cmc %ld export content to dn failed\n", cmc_md_id);

        return (EC_FALSE);
    }

    CMCNP_FNODE_HASH(cmcnp_fnode) = path_hash;

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_write: cmc %ld write to dn where fnode is \n", cmc_md_id);
        cmcnp_fnode_print(LOGSTDOUT, cmcnp_fnode);
    }

    return (EC_TRUE);
}

/**
*
*  read a file
*
**/
EC_BOOL cmc_read(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, CBYTES *cbytes)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE   cmcnp_fnode;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_read: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode_init(&cmcnp_fnode);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_read: cmc %ld read from np failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read: cmc %ld read from np done\n", cmc_md_id);

    /*exception*/
    if(0 == CMCNP_FNODE_FILESZ(&cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_read: cmc %ld read with zero len from np\n", cmc_md_id);
        return (EC_TRUE);
    }

    if(EC_FALSE == cmc_read_dn(cmc_md_id, &cmcnp_fnode, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read: cmc %ld read from dn failed where fnode is \n", cmc_md_id);
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_FALSE);
    }

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_read: cmc %ld read with size %ld done\n", cmc_md_id, cbytes_len(cbytes));
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
EC_BOOL cmc_write_e(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE   cmcnp_fnode;
    uint32_t      file_old_size;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_write_e: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode_init(&cmcnp_fnode);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e: cmc %ld read from np failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    file_old_size = CMCNP_FNODE_FILESZ(&cmcnp_fnode);

    if(EC_FALSE == cmc_write_e_dn(cmc_md_id, &cmcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e: cmc %ld offset write to dn failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(file_old_size != CMCNP_FNODE_FILESZ(&cmcnp_fnode))
    {
        if(EC_FALSE == cmcnp_update(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e: cmc %ld offset write to np failed\n", cmc_md_id);
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
EC_BOOL cmc_read_e(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CMC_MD       *cmc_md;
    CMCNP_FNODE   cmcnp_fnode;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_read_e: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    cmcnp_fnode_init(&cmcnp_fnode);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, &cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e: cmc %ld read from np failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(do_log(SEC_0118_CMC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmc_read_e: cmc %ld read from np and fnode is\n",
                           cmc_md_id);
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
    }

    /*exception*/
    if(0 == CMCNP_FNODE_FILESZ(&cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_read_e: "
                        "cmc %ld read with zero len from np and fnode  is\n",
                        cmc_md_id);
        cmcnp_fnode_print(LOGSTDOUT, &cmcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cmc_read_e_dn(cmc_md_id, &cmcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e: "
                        "cmc %ld, offset read from dn failed where fnode is\n",
                        cmc_md_id);
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

    UINT32             offset;
    UINT32             data_len;
    //uint32_t           size;

    uint16_t           disk_no;
    uint16_t           block_no;
    uint16_t           page_no;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_export_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    data_len = DMIN(CBYTES_LEN(cbytes), CMCNP_FNODE_FILESZ(cmcnp_fnode));

    if(CMCPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: "
                        "cmc %ld, CBYTES_LEN %u or CMCNP_FNODE_FILESZ %u overflow\n",
                        cmc_md_id, (uint32_t)CBYTES_LEN(cbytes), CMCNP_FNODE_FILESZ(cmcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    //size = (uint32_t)data_len;

    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no     = CMCNP_INODE_DISK_NO(cmcnp_inode);
    block_no    = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no     = CMCNP_INODE_PAGE_NO(cmcnp_inode);

    offset  = (((UINT32)(page_no)) << (CMCPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == cmcdn_write_o(CMC_MD_DN(cmc_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_export_dn: "
                        "cmc %ld write %ld bytes to disk %u block %u page %u failed\n",
                        cmc_md_id,
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

    uint16_t     disk_no;
    uint16_t     block_no;
    uint16_t     page_no;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_write_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: "
                        "cmc %ld, buff len (or file size) %ld overflow\n",
                        cmc_md_id, CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: cmc %ld no dn was open\n", cmc_md_id);
        return (EC_FALSE);
    }

    cmcnp_fnode_init(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);

    if(EC_FALSE == cmcdn_write_p(CMC_MD_DN(cmc_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_dn: "
                        "cmc %ld write %ld bytes to dn failed\n",
                        cmc_md_id, CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CMCNP_INODE_DISK_NO(cmcnp_inode)  = disk_no;
    CMCNP_INODE_BLOCK_NO(cmcnp_inode) = block_no;
    CMCNP_INODE_PAGE_NO(cmcnp_inode)  = page_no;

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

    uint32_t           file_size;
    uint16_t           disk_no;
    uint16_t           block_no;
    uint16_t           page_no;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_read_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: cmc %ld dn is null\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(0 == CMCNP_FNODE_REPNUM(cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: cmc %ld no replica\n", cmc_md_id);
        return (EC_FALSE);
    }

    file_size   = CMCNP_FNODE_FILESZ(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no     = CMCNP_INODE_DISK_NO(cmcnp_inode);
    block_no    = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no     = CMCNP_INODE_PAGE_NO(cmcnp_inode);

    //dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CMC_0001);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CMC_0002);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cmcdn_read_p(CMC_MD_DN(cmc_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_dn: "
                        "cmc %ld, read %u bytes from disk %u, block %u, page %u failed\n",
                        cmc_md_id,
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

    uint32_t     file_size;
    uint32_t     file_max_size;
    uint16_t     disk_no;
    uint16_t     block_no;
    uint16_t     page_no;
    uint32_t     offset_t;

    UINT32       max_len_t;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_write_e_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: "
                        "cmc %ld, offset %ld + buff len (or file size) %ld = %ld overflow\n",
                        cmc_md_id,
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
    disk_no     = CMCNP_INODE_DISK_NO(cmcnp_inode);
    block_no    = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no     = CMCNP_INODE_PAGE_NO(cmcnp_inode);

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CMCPGB_PAGE_BYTE_SIZE - 1) >> CMCPGB_PAGE_BIT_SIZE) << CMCPGB_PAGE_BIT_SIZE);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: "
                        "cmc %ld, offset %ld overflow due to file max size is %u\n",
                        cmc_md_id, (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(EC_FALSE == cmcdn_write_e(CMC_MD_DN(cmc_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_write_e_dn: "
                        "cmc %ld write %ld bytes to dn failed\n",
                        cmc_md_id, CBYTES_LEN(cbytes));
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

    uint32_t           file_size;
    uint16_t           disk_no;
    uint16_t           block_no;
    uint16_t           page_no;
    uint32_t           offset_t;

    UINT32             max_len_t;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_read_e_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: cmc %ld dn is null\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(0 == CMCNP_FNODE_REPNUM(cmcnp_fnode))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: cmc %ld, no replica\n", cmc_md_id);
        return (EC_FALSE);
    }

    file_size   = CMCNP_FNODE_FILESZ(cmcnp_fnode);
    cmcnp_inode = CMCNP_FNODE_INODE(cmcnp_fnode, 0);
    disk_no  = CMCNP_INODE_DISK_NO(cmcnp_inode) ;
    block_no = CMCNP_INODE_BLOCK_NO(cmcnp_inode);
    page_no  = CMCNP_INODE_PAGE_NO(cmcnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: cmc %ld, offset %ld >= file size %u\n",
                        cmc_md_id,
                        (*offset), file_size);
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

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_read_e_dn: "
                    "cmc %ld file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                    cmc_md_id,
                    file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    if(CBYTES_LEN(cbytes) < max_len_t)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CMC_0003);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CMC_0004);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cmcdn_read_e(CMC_MD_DN(cmc_md), disk_no, block_no, page_no, offset_t, max_len_t, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_read_e_dn: "
                        "cmc %ld read %ld bytes from disk %u, block %u, offset %u failed\n",
                        cmc_md_id,
                        max_len_t, disk_no, block_no, offset_t);
        return (EC_FALSE);
    }

    (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}


/**
*
*  delete all intersected file
*
**/
EC_BOOL cmc_delete_intersected(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key)
{
    CMC_MD           *cmc_md;
    CMCNP_ITEM       *cmcnp_item_intersected;
    CMCNP_KEY        *cmcnp_key_intersected;
    uint32_t          node_pos_intersected;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_delete_intersected: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_delete_intersected: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    node_pos_intersected = cmcnp_find_intersected(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS == node_pos_intersected)
    {
        /*not found*/
        return (EC_TRUE);
    }

    cmcnp_item_intersected = cmcnp_fetch(CMC_MD_NP(cmc_md), node_pos_intersected);
    if(NULL_PTR == cmcnp_item_intersected)
    {
        return (EC_FALSE);
    }

    cmcnp_key_intersected = CMCNP_ITEM_KEY(cmcnp_item_intersected);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_delete_intersected: "
                    "cmc %ld key [%u, %u), intersected [%u, %u) => delete\n",
                    cmc_md_id,
                    CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key),
                    CMCNP_KEY_S_PAGE(cmcnp_key_intersected), CMCNP_KEY_E_PAGE(cmcnp_key_intersected));

    if(EC_FALSE == cmcnp_umount_item(CMC_MD_NP(cmc_md), node_pos_intersected))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_delete_intersected: cmc %ld umount node %u failed\n",
                        cmc_md_id, node_pos_intersected);
        return (EC_FALSE);
    }

    if(CMCNP_KEY_S_PAGE(cmcnp_key) >= CMCNP_KEY_S_PAGE(cmcnp_key_intersected))
    {
        if(CMCNP_KEY_E_PAGE(cmcnp_key) >= CMCNP_KEY_E_PAGE(cmcnp_key_intersected))
        {
            CMCNP_KEY  cmcnp_key_next;

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key_intersected);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key);

            cmc_delete_intersected(cmc_md_id, &cmcnp_key_next);

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key_intersected);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key);

            cmc_delete_intersected(cmc_md_id, &cmcnp_key_next);
        }
        else
        {
            /*no next*/
        }
    }
    else
    {
        if(CMCNP_KEY_E_PAGE(cmcnp_key) >= CMCNP_KEY_E_PAGE(cmcnp_key_intersected))
        {
            CMCNP_KEY  cmcnp_key_next;

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key_intersected);

            cmc_delete_intersected(cmc_md_id, &cmcnp_key_next);

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key_intersected);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_E_PAGE(cmcnp_key);

            cmc_delete_intersected(cmc_md_id, &cmcnp_key_next);
        }
        else
        {
            CMCNP_KEY  cmcnp_key_next;

            CMCNP_KEY_S_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key);
            CMCNP_KEY_E_PAGE(&cmcnp_key_next) = CMCNP_KEY_S_PAGE(cmcnp_key_intersected);

            cmc_delete_intersected(cmc_md_id, &cmcnp_key_next);
        }
    }

    return (EC_TRUE);
}

/**
*
*  delete a file
*
**/
EC_BOOL cmc_delete(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key)
{
    CMC_MD      *cmc_md;
    uint32_t     node_pos;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_delete: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_delete: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    node_pos = cmcnp_search(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG);
    if(CMCNPRB_ERR_POS == node_pos)
    {
        /*not found*/

        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_delete: cmc %ld, not found key [%u, %u)\n",
                            cmc_md_id, CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));

        return (EC_TRUE);
    }

    if(EC_FALSE == cmcnp_umount_item(CMC_MD_NP(cmc_md), node_pos))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_delete: umount failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_delete: cmc %ld, key [%u, %u) done\n",
                        cmc_md_id, CMCNP_KEY_S_PAGE(cmcnp_key), CMCNP_KEY_E_PAGE(cmcnp_key));

    return (EC_TRUE);
}

EC_BOOL cmc_update(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, const CBYTES *cbytes)
{
    CMC_MD      *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_update: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(EC_FALSE == cmcnp_read(CMC_MD_NP(cmc_md), cmcnp_key, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == cmc_write(cmc_md_id, cmcnp_key, cbytes))
        {
            dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_update: cmc %ld write failed\n", cmc_md_id);
            return (EC_FALSE);
        }
        dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_update: cmc %ld write done\n", cmc_md_id);
        return (EC_TRUE);
    }


    /*file exist, update it*/
    if(EC_FALSE == cmc_delete(cmc_md_id, cmcnp_key))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_update: cmc %ld delete old failed\n", cmc_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_update: cmc %ld delete old done\n", cmc_md_id);

    if(EC_FALSE == cmc_write(cmc_md_id, cmcnp_key, cbytes))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_update: cmc %ld write new failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_update: cmc %ld write new done\n", cmc_md_id);

    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cmc_file_num(const UINT32 cmc_md_id, UINT32 *file_num)
{
    CMC_MD      *cmc_md;
    uint32_t     file_num_t;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_file_num: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_file_num: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_file_num(CMC_MD_NP(cmc_md), &file_num_t))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_num: cmc %ld np get file num of key failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(NULL_PTR != file_num)
    {
        (*file_num) = file_num_t;
    }
    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cmc_file_size(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key, UINT32 *file_size)
{
    CMC_MD      *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_file_size: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_file_size: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmcnp_file_size(CMC_MD_NP(cmc_md), cmcnp_key, file_size))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_file_size: cmc %ld np get size of key failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_file_size: cmc %ld, key ..., size %ld\n",
                     cmc_md_id, (*file_size));
    return (EC_TRUE);
}

/**
*
*  search in current name node
*
**/
EC_BOOL cmc_search(const UINT32 cmc_md_id, const CMCNP_KEY *cmcnp_key)
{
    CMC_MD      *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_search: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_search: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    if(CMCNPRB_ERR_POS == cmcnp_search(CMC_MD_NP(cmc_md), cmcnp_key, CMCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_search: cmc %ld search failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL cmc_recycle(const UINT32 cmc_md_id, const UINT32 max_num, UINT32 *complete_num)
{
    CMC_MD          *cmc_md;
    CMCNP_RECYCLE_DN cmcnp_recycle_dn;
    UINT32           complete_recycle_num;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_recycle: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_recycle: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    CMCNP_RECYCLE_DN_ARG1(&cmcnp_recycle_dn)   = cmc_md_id;
    CMCNP_RECYCLE_DN_FUNC(&cmcnp_recycle_dn)   = cmc_release_dn;

    complete_recycle_num = 0;/*initialization*/

    if(EC_FALSE == cmcnp_recycle(CMC_MD_NP(cmc_md),  max_num, NULL_PTR, &cmcnp_recycle_dn, &complete_recycle_num))
    {
        dbg_log(SEC_0118_CMC, 0)(LOGSTDOUT, "error:cmc_recycle: cmc %ld recycle np failed\n", cmc_md_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "[DEBUG] cmc_recycle: cmc %ld recycle end where complete %ld\n",
                    cmc_md_id, complete_recycle_num);

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
    CMC_MD          *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_show_np: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

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
*  show name node LRU
*
*
**/
EC_BOOL cmc_show_np_lru_list(const UINT32 cmc_md_id, LOG *log)
{
    CMC_MD          *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_show_np_lru_list: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print_lru_list(log, CMC_MD_NP(cmc_md));

    return (EC_TRUE);
}

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cmc_show_np_del_list(const UINT32 cmc_md_id, LOG *log)
{
    CMC_MD          *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_show_np_del_list: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cmcnp_print_del_list(log, CMC_MD_NP(cmc_md));

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
    CMC_MD          *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_show_dn: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

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
EC_BOOL cmc_retire(const UINT32 cmc_md_id, const UINT32 max_num, UINT32 *complete_num)
{
    CMC_MD          *cmc_md;

#if ( SWITCH_ON == CMC_DEBUG_SWITCH )
    if ( CMC_MD_ID_CHECK_INVALID(cmc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmc_retire: cmc module #%ld not started.\n",
                cmc_md_id);
        cmc_print_module_status(cmc_md_id, LOGSTDOUT);
        dbg_exit(MD_CMC, cmc_md_id);
    }
#endif/*CMC_DEBUG_SWITCH*/

    cmc_md = CMC_MD_GET(cmc_md_id);

    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0118_CMC, 1)(LOGSTDOUT, "warn:cmc_retire: cmc %ld np was not open\n", cmc_md_id);
        return (EC_FALSE);
    }

    cmcnp_retire(CMC_MD_NP(cmc_md), max_num, complete_num);

    dbg_log(SEC_0118_CMC, 9)(LOGSTDOUT, "[DEBUG] cmc_retire: cmc %ld retire done where complete %ld\n",
                    cmc_md_id, (*complete_num));

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

