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
#include <errno.h>

#include <sys/stat.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "carray.h"
#include "cvector.h"

#include "cbc.h"

#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"
#include "chttp.h"
#include "csfs.h"
#include "csfshttp.h"
#include "csfsmc.h"
#include "cmd5.h"
#include "cbase64code.h"

#include "findex.inc"

#define CSFS_MD_CAPACITY()                  (cbc_md_capacity(MD_CSFS))

#define CSFS_MD_GET(csfs_md_id)     ((CSFS_MD *)cbc_md_get(MD_CSFS, (csfs_md_id)))

#define CSFS_MD_ID_CHECK_INVALID(csfs_md_id)  \
    ((CMPI_ANY_MODI != (csfs_md_id)) && ((NULL_PTR == CSFS_MD_GET(csfs_md_id)) || (0 == (CSFS_MD_GET(csfs_md_id)->usedcounter))))

STATIC_CAST static EC_BOOL __csfs_write_npp(const UINT32 csfs_md_id, const CSTRING *file_path, const CSFSNP_FNODE *csfsnp_fnode, uint32_t *crfsnp_id, uint32_t *node_pos);

/**
*   for test only
*
*   to query the status of CSFS Module
*
**/
void csfs_print_module_status(const UINT32 csfs_md_id, LOG *log)
{
    CSFS_MD *csfs_md;
    UINT32 this_csfs_md_id;

    for( this_csfs_md_id = 0; this_csfs_md_id < CSFS_MD_CAPACITY(); this_csfs_md_id ++ )
    {
        csfs_md = CSFS_MD_GET(this_csfs_md_id);

        if ( NULL_PTR != csfs_md && 0 < csfs_md->usedcounter )
        {
            sys_log(log,"CSFS Module # %ld : %ld refered\n",
                    this_csfs_md_id,
                    csfs_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CSFS module
*
*
**/
UINT32 csfs_free_module_static_mem(const UINT32 csfs_md_id)
{
    CSFS_MD  *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_free_module_static_mem: csfs module #0x%lx not started.\n",
                csfs_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    free_module_static_mem(MD_CSFS, csfs_md_id);

    return 0;
}

/**
*
* start CSFS module
*
**/
UINT32 csfs_start(const CSTRING *csfsnp_root_basedir, const CSTRING *csfsdn_root_basedir)
{
    CSFS_MD *csfs_md;
    UINT32   csfs_md_id;

    TASK_BRD *task_brd;
    EC_BOOL   ret;

    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CSFS    , 32);

    csfs_md_id = cbc_md_new(MD_CSFS, sizeof(CSFS_MD));
    if(CMPI_ERROR_MODI == csfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CSFS module */
    csfs_md = (CSFS_MD *)cbc_md_get(MD_CSFS, csfs_md_id);
    csfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /*initialize LOCK_REQ file RB TREE*/
    crb_tree_init(CSFS_MD_LOCKED_FILES(csfs_md),
                    (CRB_DATA_CMP)csfs_locked_file_cmp,
                    (CRB_DATA_FREE)csfs_locked_file_free,
                    (CRB_DATA_PRINT)csfs_locked_file_print);

    /*initialize WAIT file RB TREE*/
    crb_tree_init(CSFS_MD_WAIT_FILES(csfs_md),
                    (CRB_DATA_CMP)csfs_wait_file_cmp,
                    (CRB_DATA_FREE)csfs_wait_file_free,
                    (CRB_DATA_PRINT)csfs_wait_file_print);

    CSFS_MD_DN_MOD_MGR(csfs_md)  = mod_mgr_new(csfs_md_id, /*LOAD_BALANCING_LOOP*//*LOAD_BALANCING_MOD*/LOAD_BALANCING_QUE);
    CSFS_MD_NPP_MOD_MGR(csfs_md) = mod_mgr_new(csfs_md_id, /*LOAD_BALANCING_LOOP*//*LOAD_BALANCING_MOD*/LOAD_BALANCING_QUE);

    CSFS_MD_DN(csfs_md)  = NULL_PTR;
    CSFS_MD_NPP(csfs_md) = NULL_PTR;

    ret = EC_TRUE;
    do
    {
        CSTRING *csfsnp_root_dir;
        if(EC_FALSE == ret || NULL_PTR == csfsnp_root_basedir || EC_TRUE == cstring_is_empty(csfsnp_root_basedir))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: ret is false or csfsnp_root_basedir is invalid\n");
            break;
        }

        csfsnp_root_dir = cstring_make("%s/sfs%02ld", (char *)cstring_get_str(csfsnp_root_basedir), csfs_md_id);
        if(NULL_PTR == csfsnp_root_dir)
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: new csfsnp_root_dir failed\n");
            break;
        }

        if(EC_FALSE == csfsnp_mgr_exist(csfsnp_root_dir))
        {
            cstring_free(csfsnp_root_dir);
            break;
        }

        CSFS_MD_NPP(csfs_md) = csfsnp_mgr_open(csfsnp_root_dir);
        if(NULL_PTR == CSFS_MD_NPP(csfs_md))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: open npp from root dir %s failed\n", (char *)cstring_get_str(csfsnp_root_dir));
            cstring_free(csfsnp_root_dir);
            ret = EC_FALSE;
            break;
        }

        cstring_free(csfsnp_root_dir);
    }while(0);

    do
    {
        CSTRING *csfsdn_root_dir;
        if(EC_FALSE == ret || NULL_PTR == csfsdn_root_basedir || EC_TRUE == cstring_is_empty(csfsdn_root_basedir))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: ret is false or csfsdn_root_basedir is invalid\n");
            break;
        }

        csfsdn_root_dir = cstring_make("%s/sfs%02ld", (char *)cstring_get_str(csfsdn_root_basedir), csfs_md_id);
        if(NULL_PTR == csfsdn_root_dir)
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: new csfsdn_root_dir failed\n");
            break;
        }

        if(EC_FALSE == csfsdn_exist((char *)cstring_get_str(csfsdn_root_dir)))
        {
            cstring_free(csfsdn_root_dir);
            break;
        }

        CSFS_MD_DN(csfs_md) = csfsdn_open((char *)cstring_get_str(csfsdn_root_dir),
                                        CSFSNPRB_ERR_POS,
                                        (CSFSNP_RECYCLE)csfsnp_mgr_delete_np,
                                        (void *)CSFS_MD_NPP(csfs_md));
        if(NULL_PTR == CSFS_MD_DN(csfs_md))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: open dn from root dir %s failed\n", (char *)cstring_get_str(csfsdn_root_dir));
            cstring_free(csfsdn_root_dir);
            ret = EC_FALSE;
            break;
        }

        cstring_free(csfsdn_root_dir);
    }while(0);

    if(SWITCH_ON == CSFS_MEMC_SWITCH && EC_TRUE == ret)
    {
        CSFS_MD_MCACHE(csfs_md) = csfsmc_new(csfs_md_id,
                                             CSFSMC_NP_ID, CSFS_MEMC_NP_MODEL,
                                             CHASH_AP_ALGO_ID,
                                             CHASH_JS_ALGO_ID,
                                             CSFS_MEMC_BUCKET_NUM,
                                             CSFS_MEMC_CSFSD_BLOCK_NUM);
        if(NULL_PTR == CSFS_MD_MCACHE(csfs_md))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: new memcache failed\n");
            ret = EC_FALSE;
        }
    }
    else
    {
        CSFS_MD_MCACHE(csfs_md) = NULL_PTR;
    }

    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CSFS_MD_DN(csfs_md))
        {
            csfsdn_close(CSFS_MD_DN(csfs_md));
            CSFS_MD_DN(csfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CSFS_MD_NPP(csfs_md))
        {
            csfsnp_mgr_close(CSFS_MD_NPP(csfs_md));
            CSFS_MD_NPP(csfs_md) = NULL_PTR;
        }

        crb_tree_clean(CSFS_MD_LOCKED_FILES(csfs_md));
        crb_tree_clean(CSFS_MD_WAIT_FILES(csfs_md));

        cbc_md_free(MD_CSFS, csfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    csfs_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)csfs_end, csfs_md_id);

    dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "csfs_start: start CSFS module #%ld\n", csfs_md_id);

    CSFS_INIT_LOCK(csfs_md, LOC_CSFS_0001);

    if(SWITCH_ON == CSFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CSFS module is allowed to launch sfs http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == csfs_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: init csfshttp defer request queue failed\n");
                csfs_end(csfs_md_id);
                return (CMPI_ERROR_MODI);
            }

            csfshttp_log_start();
            task_brd_default_bind_http_srv_modi(csfs_md_id);
            chttp_rest_list_push((const char *)CSFSHTTP_REST_API_NAME, csfshttp_commit_request);
        }

        /*https server*/
#if 0
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled() && 0 == csfs_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_start: init csfshttp defer request queue failed\n");
                csfs_end(csfs_md_id);
                return (CMPI_ERROR_MODI);
            }
            csfshttps_log_start();
            task_brd_default_bind_https_srv_modi(csfs_md_id);
            chttps_rest_list_push((const char *)CSFSHTTPS_REST_API_NAME, csfshttps_commit_request);
        }
#endif

    }
    return ( csfs_md_id );
}

/**
*
* end CSFS module
*
**/
void csfs_end(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)csfs_end, csfs_md_id);

    csfs_md = CSFS_MD_GET(csfs_md_id);
    if(NULL_PTR == csfs_md)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT,"error:csfs_end: csfs_md_id = %ld not exist.\n", csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < csfs_md->usedcounter )
    {
        csfs_md->usedcounter --;
        return ;
    }

    if ( 0 == csfs_md->usedcounter )
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT,"error:csfs_end: csfs_md_id = %ld is not started.\n", csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }

#if 0
    /*stop server*/
    if(SWITCH_ON == CSFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CSFS module is allowed to launch sfs http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == csfs_md_id)
        {
            task_brd_default_stop_http_srv();
            chttp_defer_request_queue_clean();
        }
    }
#endif
    /* if nobody else occupied the module,then free its resource */
    if(NULL_PTR != CSFS_MD_MCACHE(csfs_md))
    {
        csfsmc_free(CSFS_MD_MCACHE(csfs_md));
        CSFS_MD_MCACHE(csfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CSFS_MD_DN(csfs_md))
    {
        csfsdn_close(CSFS_MD_DN(csfs_md));
        CSFS_MD_DN(csfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CSFS_MD_NPP(csfs_md))
    {
        csfsnp_mgr_close(CSFS_MD_NPP(csfs_md));
        CSFS_MD_NPP(csfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CSFS_MD_DN_MOD_MGR(csfs_md))
    {
        mod_mgr_free(CSFS_MD_DN_MOD_MGR(csfs_md));
        CSFS_MD_DN_MOD_MGR(csfs_md)  = NULL_PTR;
    }

    if(NULL_PTR != CSFS_MD_NPP_MOD_MGR(csfs_md))
    {
        mod_mgr_free(CSFS_MD_NPP_MOD_MGR(csfs_md));
        CSFS_MD_NPP_MOD_MGR(csfs_md)  = NULL_PTR;
    }

    crb_tree_clean(CSFS_MD_LOCKED_FILES(csfs_md));
    crb_tree_clean(CSFS_MD_WAIT_FILES(csfs_md));

    /* free module : */
    //csfs_free_module_static_mem(csfs_md_id);

    csfs_md->usedcounter = 0;
    CSFS_CLEAN_LOCK(csfs_md, LOC_CSFS_0002);

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "csfs_end: stop CSFS module #%ld\n", csfs_md_id);
    cbc_md_free(MD_CSFS, csfs_md_id);

    return ;
}

EC_BOOL csfs_flush(const UINT32 csfs_md_id)
{
    CSFS_MD  *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_flush: csfs module #0x%lx not started.\n",
                csfs_md_id);
        csfs_print_module_status(csfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(EC_FALSE == csfs_flush_npp(csfs_md_id))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_flush: flush npp failed!\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csfs_flush_dn(csfs_md_id))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_flush: flush dn failed!\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "[DEBUG] csfs_flush: flush done\n");
    return (EC_TRUE);
}


/**
*
* initialize mod mgr of CSFS module
*
**/
UINT32 csfs_set_npp_mod_mgr(const UINT32 csfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CSFS_MD *csfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_set_npp_mod_mgr: csfs module #0x%lx not started.\n",
                csfs_md_id);
        csfs_print_module_status(csfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    des_mod_mgr = CSFS_MD_NPP_MOD_MGR(csfs_md);

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "csfs_set_npp_mod_mgr: md_id %d, input src_mod_mgr %lx\n", csfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of csfsnp_tcid_vec and csfsnp_tcid_vec*/
    mod_mgr_limited_clone(csfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "====================================csfs_set_npp_mod_mgr: des_mod_mgr %lx beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "====================================csfs_set_npp_mod_mgr: des_mod_mgr %lx end====================================\n", des_mod_mgr);

    return (0);
}

UINT32 csfs_set_dn_mod_mgr(const UINT32 csfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CSFS_MD *csfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_set_dn_mod_mgr: csfs module #0x%lx not started.\n",
                csfs_md_id);
        csfs_print_module_status(csfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    des_mod_mgr = CSFS_MD_DN_MOD_MGR(csfs_md);

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "csfs_set_dn_mod_mgr: md_id %d, input src_mod_mgr %lx\n", csfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of csfsnp_tcid_vec and csfsnp_tcid_vec*/
    mod_mgr_limited_clone(csfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "====================================csfs_set_dn_mod_mgr: des_mod_mgr %lx beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "====================================csfs_set_dn_mod_mgr: des_mod_mgr %lx end====================================\n", des_mod_mgr);

    return (0);
}

/**
*
* get mod mgr of CSFS module
*
**/
MOD_MGR * csfs_get_npp_mod_mgr(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    csfs_md = CSFS_MD_GET(csfs_md_id);
    return CSFS_MD_NPP_MOD_MGR(csfs_md);
}

MOD_MGR * csfs_get_dn_mod_mgr(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    csfs_md = CSFS_MD_GET(csfs_md_id);
    return CSFS_MD_DN_MOD_MGR(csfs_md);
}

CSFSNP_FNODE *csfs_fnode_new(const UINT32 csfs_md_id)
{
    return csfsnp_fnode_new();
}

EC_BOOL csfs_fnode_init(const UINT32 csfs_md_id, CSFSNP_FNODE *csfsnp_fnode)
{
    return csfsnp_fnode_init(csfsnp_fnode);
}

EC_BOOL csfs_fnode_clean(const UINT32 csfs_md_id, CSFSNP_FNODE *csfsnp_fnode)
{
    return csfsnp_fnode_clean(csfsnp_fnode);
}

EC_BOOL csfs_fnode_free(const UINT32 csfs_md_id, CSFSNP_FNODE *csfsnp_fnode)
{
    return csfsnp_fnode_free(csfsnp_fnode);
}

/**
*
*  get name node pool of the module
*
**/
CSFSNP_MGR *csfs_get_npp(const UINT32 csfs_md_id)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_get_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    return CSFS_MD_NPP(csfs_md);
}

/**
*
*  get data node of the module
*
**/
CSFSDN *csfs_get_dn(const UINT32 csfs_md_id)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_get_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    return CSFS_MD_DN(csfs_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL csfs_open_npp(const UINT32 csfs_md_id, const CSTRING *csfsnp_db_root_dir)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_open_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR != CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_open_npp: npp was open\n");
        return (EC_FALSE);
    }

    CSFS_MD_NPP(csfs_md) = csfsnp_mgr_open(csfsnp_db_root_dir);
    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_open_npp: open npp from root dir %s failed\n", (char *)cstring_get_str(csfsnp_db_root_dir));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  close name node pool
*
**/
EC_BOOL csfs_close_npp(const UINT32 csfs_md_id)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_close_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_close_npp: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_close(CSFS_MD_NPP(csfs_md));
    CSFS_MD_NPP(csfs_md) = NULL_PTR;
    return (EC_TRUE);
}

/**
*
*  check this CSFS is name node pool or not
*
*
**/
EC_BOOL csfs_is_npp(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_is_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CSFS is data node or not
*
*
**/
EC_BOOL csfs_is_dn(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_is_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CSFS is data node and namenode or not
*
*
**/
EC_BOOL csfs_is_npp_and_dn(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_is_npp_and_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md) || NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfs_check_is_uint8_t(const UINT32 num)
{
    if(0 == (num >> 8))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __csfs_check_is_uint16_t(const UINT32 num)
{
    if(0 == (num >> 16))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __csfs_check_is_uint32_t(const UINT32 num)
{
#if (32 == WORDSIZE)
    return (EC_TRUE);
#endif /*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
    if(32 == WORDSIZE || 0 == (num >> 32))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
#endif /*(64 == WORDSIZE)*/
}

/**
*
*  create name node pool
*
**/
EC_BOOL csfs_create_npp(const UINT32 csfs_md_id,
                             const UINT32 csfsnp_model,
                             const UINT32 csfsnp_max_num,
                             const CSTRING *csfsnp_db_root_dir)
{
    CSFS_MD *csfs_md;

    UINT32 csfsnp_1st_chash_algo_id;
    UINT32 csfsnp_2nd_chash_algo_id;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_create_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR != CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_create_npp: npp already exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfs_check_is_uint8_t(csfsnp_model))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_create_npp: csfsnp_model %u is invalid\n", csfsnp_model);
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfs_check_is_uint32_t(csfsnp_max_num))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_create_npp: csfsnp_disk_max_num %u is invalid\n", csfsnp_max_num);
        return (EC_FALSE);
    }

    csfsnp_1st_chash_algo_id = CHASH_RS_ALGO_ID;
    csfsnp_2nd_chash_algo_id = CHASH_JS_ALGO_ID;

    CSFS_MD_NPP(csfs_md) = csfsnp_mgr_create((uint8_t ) csfsnp_model,
                                             (uint32_t) csfsnp_max_num,
                                             (uint8_t ) csfsnp_1st_chash_algo_id,
                                             (uint8_t ) csfsnp_2nd_chash_algo_id,
                                             csfsnp_db_root_dir);
    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_create_npp: create npp failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfs_add_npp(const UINT32 csfs_md_id, const UINT32 csfsnpp_tcid, const UINT32 csfsnpp_rank)
{
    CSFS_MD   *csfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_add_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, csfsnpp_tcid))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_add_npp: csfsnpp_tcid %s not connected\n", c_word_to_ipv4(csfsnpp_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(csfsnpp_tcid, CMPI_ANY_COMM, csfsnpp_rank, 0, CSFS_MD_NPP_MOD_MGR(csfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), csfsnpp_tcid, csfsnpp_rank, 0);

    return (EC_TRUE);
}

EC_BOOL csfs_add_dn(const UINT32 csfs_md_id, const UINT32 csfsdn_tcid, const UINT32 csfsdn_rank)
{
    CSFS_MD   *csfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_add_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, csfsdn_tcid))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_add_dn: csfsdn_tcid %s not connected\n", c_word_to_ipv4(csfsdn_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(csfsdn_tcid, CMPI_ANY_COMM, csfsdn_rank, (UINT32)0, CSFS_MD_DN_MOD_MGR(csfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), csfsdn_tcid, csfsdn_rank, 0);

    return (EC_TRUE);
}


/**
*
*  check existing of a file
*
**/
EC_BOOL csfs_find_file(const UINT32 csfs_md_id, const CSTRING *file_path)
{
    CSFS_MD   *csfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_find_file: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_find_file: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0003);
    ret = csfsnp_mgr_find(CSFS_MD_NPP(csfs_md), file_path);
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0004);
    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL csfs_find(const UINT32 csfs_md_id, const CSTRING *path)
{
    CSFS_MD   *csfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_find: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_find: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0005);
    ret = csfsnp_mgr_find(CSFS_MD_NPP(csfs_md), path);
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0006);

    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL csfs_exists(const UINT32 csfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_exists: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    return csfs_find(csfs_md_id, path);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL csfs_is_file(const UINT32 csfs_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_is_file: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    return csfs_find_file(csfs_md_id, file_path);;
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL csfs_reserve_dn(const UINT32 csfs_md_id, const UINT32 data_len, CSFSNP_FNODE *csfsnp_fnode)
{
    CSFS_MD      *csfs_md;
    CSFSNP_INODE *csfsnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_reserve_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_reserve_dn: data_len %u overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    csfsdn_wrlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0007);
    if(EC_FALSE == csfsv_new_space(CSFSDN_CSFSV(CSFS_MD_DN(csfs_md)), size, &disk_no, &block_no, &page_no))
    {
        csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0008);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_reserve_dn: new %u bytes space from vol failed\n", data_len);
        return (EC_FALSE);
    }
    csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0009);

    csfsnp_fnode_init(csfsnp_fnode);
    CSFSNP_FNODE_FILESZ(csfsnp_fnode) = size;
    CSFSNP_FNODE_REPNUM(csfsnp_fnode) = 1;

    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    CSFSNP_INODE_DISK_NO(csfsnp_inode)    = disk_no;
    CSFSNP_INODE_BLOCK_NO(csfsnp_inode)   = block_no;
    CSFSNP_INODE_PAGE_NO(csfsnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  write a file (version 0.2)
*
**/
STATIC_CAST static EC_BOOL __csfs_write(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CSFS_MD      *csfs_md;
    CSFSNP_FNODE  csfsnp_fnode;
    CSFSNP_INODE *csfsnp_inode;
    uint32_t      crfsnp_id;
    uint32_t      node_pos;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__csfs_write: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] __csfs_write: write file %s, len %ld BEG\n",
                        (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    csfs_md = CSFS_MD_GET(csfs_md_id);

    csfsnp_fnode_init(&csfsnp_fnode);

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        csfsnp_fnode_init(&csfsnp_fnode);

        if(do_log(SEC_0167_CSFS, 1))
        {
            sys_log(LOGSTDOUT, "warn:__csfs_write: write file %s with zero len to dn where fnode is \n", (char *)cstring_get_str(file_path));
            csfsnp_fnode_print(LOGSTDOUT, &csfsnp_fnode);
        }

        CSFS_WRLOCK(csfs_md, LOC_CSFS_0010);
        if(EC_FALSE == __csfs_write_npp(csfs_md_id, file_path, &csfsnp_fnode, NULL_PTR, NULL_PTR))
        {
            CSFS_UNLOCK(csfs_md, LOC_CSFS_0011);
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write: write file %s to npp failed\n", (char *)cstring_get_str(file_path));

            /*notify all waiters*/
            csfs_file_notify(csfs_md_id, file_path); /*patch*/
            return (EC_FALSE);
        }
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0012);

        /*notify all waiters*/
        csfs_file_notify(csfs_md_id, file_path); /*patch*/

        return (EC_TRUE);
    }

    if(EC_FALSE == csfs_reserve_dn(csfs_md_id, CBYTES_LEN(cbytes), &csfsnp_fnode))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write: reserve dn %u bytes for file %s failed\n",
                            CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        csfs_file_notify(csfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    if(EC_FALSE == csfs_export_dn(csfs_md_id, cbytes, &csfsnp_fnode))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        csfs_file_notify(csfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    if(do_log(SEC_0167_CSFS, 9))
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] __csfs_write: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        csfsnp_fnode_print(LOGSTDOUT, &csfsnp_fnode);
    }

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDNULL, "[DEBUG] __csfs_write: write file %s is %.*s\n",
                        (char *)cstring_get_str(file_path), DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));

    CSFS_WRLOCK(csfs_md, LOC_CSFS_0013);
    if(EC_FALSE == __csfs_write_npp(csfs_md_id, file_path, &csfsnp_fnode, &crfsnp_id, &node_pos))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0014);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write: write file %s to npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        csfs_file_notify(csfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    csfsnp_inode = CSFSNP_FNODE_INODE(&csfsnp_fnode, 0);

    if(EC_FALSE == csfsv_bind(CSFSDN_CSFSV(CSFS_MD_DN(csfs_md)),
                               CSFSNP_INODE_DISK_NO(csfsnp_inode),
                               CSFSNP_INODE_BLOCK_NO(csfsnp_inode),
                               CSFSNP_INODE_PAGE_NO(csfsnp_inode),
                               crfsnp_id, node_pos))
   {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0015);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write: file %s bind dn and npp failed\n", (char *)cstring_get_str(file_path));

        csfs_delete_npp(csfs_md_id, file_path);

        /*notify all waiters*/
        csfs_file_notify(csfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    CSFS_UNLOCK(csfs_md, LOC_CSFS_0016);

    /*notify all waiters*/
    csfs_file_notify(csfs_md_id, file_path); /*patch*/

    return (EC_TRUE);
}

EC_BOOL csfs_write(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    return __csfs_write(csfs_md_id, file_path, cbytes);
}

/**
*
*  read a file
*
**/
EC_BOOL csfs_read(const UINT32 csfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CSFS_MD      *csfs_md;
    CSFSNP_FNODE  csfsnp_fnode;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_read: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfsnp_fnode_init(&csfsnp_fnode);

    csfs_md = CSFS_MD_GET(csfs_md_id);

    CSFS_RDLOCK(csfs_md, LOC_CSFS_0017);
    if(EC_FALSE == csfs_read_npp(csfs_md_id, file_path, &csfsnp_fnode))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0018);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0167_CSFS, 9))
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_read: read file %s from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &csfsnp_fnode);
        csfsnp_fnode_print(LOGSTDOUT, &csfsnp_fnode);
    }

    if(EC_FALSE == csfs_read_dn(csfs_md_id, &csfsnp_fnode, cbytes))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0019);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read: read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
        csfsnp_fnode_print(LOGSTDOUT, &csfsnp_fnode);
        return (EC_FALSE);
    }
    CSFS_UNLOCK(csfs_md, LOC_CSFS_0020);

    return (EC_TRUE);
}


/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL csfs_read_e(const UINT32 csfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CSFS_MD      *csfs_md;
    CSFSNP_FNODE  csfsnp_fnode;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_read_e: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    csfsnp_fnode_init(&csfsnp_fnode);
#if 0
    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        UINT32 offset_t;

        offset_t = (*offset);
        if(EC_TRUE == csfsmc_read_e(CSFS_MD_MCACHE(csfs_md), file_path, offset, max_len, cbytes))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_read_e: read file %s at offset %ld and max len %ld with size %ld from memcache done\n",
                               (char *)cstring_get_str(file_path), offset_t, max_len, cbytes_len(cbytes));
            return (EC_TRUE);
        }
    }
#endif
    CSFS_RDLOCK(csfs_md, LOC_CSFS_0021);

    if(EC_FALSE == csfs_read_npp(csfs_md_id, file_path, &csfsnp_fnode))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0022);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0167_CSFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfs_read_e: read file %s from npp and fnode %p is \n",
                           (char *)cstring_get_str(file_path),
                           &csfsnp_fnode);
        csfsnp_fnode_print(LOGSTDOUT, &csfsnp_fnode);
    }

    /*exception*/
    if(0 == CSFSNP_FNODE_FILESZ(&csfsnp_fnode))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_read_e: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &csfsnp_fnode);
        csfsnp_fnode_print(LOGSTDOUT, &csfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == csfs_read_e_dn(csfs_md_id, &csfsnp_fnode, offset, max_len, cbytes))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0023);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_e: offset read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
        csfsnp_fnode_print(LOGSTDOUT, &csfsnp_fnode);
        return (EC_FALSE);
    }

    CSFS_UNLOCK(csfs_md, LOC_CSFS_0024);
    return (EC_TRUE);
}

/**
*
*  update a file
*  (atomic operation)
*
**/
EC_BOOL csfs_update(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_update: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
#if 0
    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        if(EC_TRUE == csfsmc_update(CSFS_MD_MCACHE(csfs_md), file_path, cbytes, NULL_PTR))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update: update file %s with size %ld to memcache done\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        }
    }
#endif
    CSFS_WRLOCK(csfs_md, LOC_CSFS_0025);
    if(EC_FALSE == csfs_update_no_lock(csfs_md_id, file_path, cbytes))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0026);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_update: update file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CSFS_UNLOCK(csfs_md, LOC_CSFS_0027);
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update: update file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL csfs_update_no_lock(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_update_no_lock: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(EC_FALSE == csfs_read_npp(csfs_md_id, file_path, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == csfs_write(csfs_md_id, file_path, cbytes))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_update_no_lock: write file %s failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update_no_lock: write file %s done\n", (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }


    /*file exist, update it*/
    if(EC_FALSE == csfs_delete(csfs_md_id, file_path))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_update_no_lock: delete old file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update_no_lock: delete old file %s done\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == csfs_write(csfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_update_no_lock: write new file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update_no_lock: write new file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL csfs_renew_http_header(const UINT32 csfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    char         *v;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_renew_http_header: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == csfs_read(csfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);

        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRING_STR(key));
    if(NULL_PTR == v)
    {
        chttp_rsp_add_header(&chttp_rsp, (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));
    }
    else
    {
        chttp_rsp_renew_header(&chttp_rsp, (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));
    }

    cbytes_clean(&cbytes);
    if(EC_FALSE == chttp_rsp_encode(&chttp_rsp, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_header: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfs_update(csfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_header: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_renew_http_header: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));


    /*notify all waiters*/
    csfs_file_notify(csfs_md_id, file_path);
    return (EC_TRUE);
}

EC_BOOL csfs_renew_http_headers(const UINT32 csfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_renew_http_headers: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == csfs_read(csfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV       *cstrkv;
        char         *v;

        cstrkv = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv));
        if(NULL_PTR == v)
        {
            chttp_rsp_add_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
        }
        else
        {
            chttp_rsp_renew_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
        }

        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_renew_http_headers: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    cbytes_clean(&cbytes);
    if(EC_FALSE == chttp_rsp_encode(&chttp_rsp, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_headers: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfs_update(csfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_renew_http_headers: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_renew_http_headers: '%s' renew headers done\n",
                (char *)CSTRING_STR(file_path));

    /*notify all waiters*/
    csfs_file_notify(csfs_md_id, file_path);

    return (EC_TRUE);
}

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL csfs_wait_http_header(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_wait_http_header: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == csfs_read(csfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_wait_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_wait_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);

    (*header_ready) = EC_TRUE;
    do
    {
        char         *v;

        v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRING_STR(key));
        if(NULL_PTR == v)
        {
            (*header_ready) = EC_FALSE;
            break;
        }

        if(NULL_PTR != CSTRING_STR(val) && 0 != STRCASECMP((char *)CSTRING_STR(val), v))
        {
            (*header_ready) = EC_FALSE;
            break;
        }
    }while(0);

    chttp_rsp_clean(&chttp_rsp);

    if(EC_TRUE == (*header_ready))
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_wait_http_header: '%s' wait header '%s':'%s' => ready\n",
                    (char *)CSTRING_STR(file_path),
                    (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

        return (EC_TRUE);
    }

    if(EC_FALSE == csfs_file_wait(csfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_wait_http_header: '%s' wait header '%s':'%s' => OK\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

    return (EC_TRUE);
}

EC_BOOL csfs_wait_http_headers(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_wait_http_headers: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == csfs_read(csfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_wait_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_wait_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);

    (*header_ready) = EC_TRUE;
    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV       *cstrkv;
        char         *v;

        cstrkv = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv));
        if(NULL_PTR == v)
        {
            (*header_ready) = EC_FALSE;
            break;
        }

        if(NULL_PTR != CSTRKV_VAL_STR(cstrkv) && 0 != STRCASECMP((char *)CSTRKV_VAL_STR(cstrkv), v))
        {
            (*header_ready) = EC_FALSE;
            break;
        }

        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_wait_http_headers: '%s' wait '%s':'%s' done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    chttp_rsp_clean(&chttp_rsp);

    if(EC_TRUE == (*header_ready))
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_wait_http_headers: '%s' headers => ready\n",
                (char *)CSTRING_STR(file_path));

        return (EC_TRUE);
    }

    if(EC_FALSE == csfs_file_wait(csfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_wait_http_headers: '%s' wait headers => OK\n",
                (char *)CSTRING_STR(file_path));

    return (EC_TRUE);
}


/*------------------------------------------------ interface for file wait ------------------------------------------------*/
CSFS_WAIT_FILE *csfs_wait_file_new()
{
    CSFS_WAIT_FILE *csfs_wait_file;
    alloc_static_mem(MM_CSFS_WAIT_FILE, &csfs_wait_file, LOC_CSFS_0028);
    if(NULL_PTR != csfs_wait_file)
    {
        csfs_wait_file_init(csfs_wait_file);
    }
    return (csfs_wait_file);
}

EC_BOOL csfs_wait_file_init(CSFS_WAIT_FILE *csfs_wait_file)
{
    cstring_init(CSFS_WAIT_FILE_NAME(csfs_wait_file), NULL_PTR);

    clist_init(CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file), MM_MOD_NODE, LOC_CSFS_0029);

    return (EC_TRUE);
}

EC_BOOL csfs_wait_file_clean(CSFS_WAIT_FILE *csfs_wait_file)
{
    cstring_clean(CSFS_WAIT_FILE_NAME(csfs_wait_file));
    clist_clean(CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file), (CLIST_DATA_DATA_CLEANER)mod_node_free);
    return (EC_TRUE);
}

EC_BOOL csfs_wait_file_free(CSFS_WAIT_FILE *csfs_wait_file)
{
    if(NULL_PTR != csfs_wait_file)
    {
        csfs_wait_file_clean(csfs_wait_file);
        free_static_mem(MM_CSFS_WAIT_FILE, csfs_wait_file, LOC_CSFS_0030);
    }
    return (EC_TRUE);
}

EC_BOOL csfs_wait_file_init_0(const UINT32 md_id, CSFS_WAIT_FILE *csfs_wait_file)
{
    return csfs_wait_file_init(csfs_wait_file);
}

EC_BOOL csfs_wait_file_clean_0(const UINT32 md_id, CSFS_WAIT_FILE *csfs_wait_file)
{
    return csfs_wait_file_clean(csfs_wait_file);
}

EC_BOOL csfs_wait_file_free_0(const UINT32 md_id, CSFS_WAIT_FILE *csfs_wait_file)
{
    if(NULL_PTR != csfs_wait_file)
    {
        csfs_wait_file_clean(csfs_wait_file);
        free_static_mem(MM_CSFS_WAIT_FILE, csfs_wait_file, LOC_CSFS_0031);
    }
    return (EC_TRUE);
}

int csfs_wait_file_cmp(const CSFS_WAIT_FILE *csfs_wait_file_1st, const CSFS_WAIT_FILE *csfs_wait_file_2nd)
{
    return cstring_cmp(CSFS_WAIT_FILE_NAME(csfs_wait_file_1st), CSFS_WAIT_FILE_NAME(csfs_wait_file_2nd));
}

void csfs_wait_file_print(LOG *log, const CSFS_WAIT_FILE *csfs_wait_file)
{
    if(NULL_PTR != csfs_wait_file)
    {
        sys_log(log, "csfs_wait_file_print %p: file %s, owner list: ",
                        csfs_wait_file,
                        (char *)CSFS_WAIT_FILE_NAME_STR(csfs_wait_file)
                        );
        clist_print(log, CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file),(CLIST_DATA_DATA_PRINT)mod_node_print);
    }

    return;
}

void csfs_wait_files_print(const UINT32 csfs_md_id, LOG *log)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_wait_files_print: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    crb_tree_print(log, CSFS_MD_WAIT_FILES(csfs_md));

    return;
}

EC_BOOL csfs_wait_file_name_set(CSFS_WAIT_FILE *csfs_wait_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CSFS_WAIT_FILE_NAME(csfs_wait_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfs_wait_file_owner_cmp(const MOD_NODE *mod_node, const UINT32 tcid)
{
    if(MOD_NODE_TCID(mod_node) == tcid)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL csfs_wait_file_owner_push(CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tcid)
{
    CLIST *owner_list;

    owner_list = CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file);
    if(
       CMPI_ERROR_TCID != tcid
    && CMPI_ANY_TCID != tcid
    && NULL_PTR == clist_search_data_front(owner_list, (void *)tcid, (CLIST_DATA_DATA_CMP)__csfs_wait_file_owner_cmp)
    )
    {
        MOD_NODE *mod_node;

        mod_node = mod_node_new();
        if(NULL_PTR == mod_node)
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_wait_file_owner_push: new mod_node failed\n");
            return (EC_FALSE);
        }

        MOD_NODE_TCID(mod_node) = tcid;
        MOD_NODE_COMM(mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(mod_node) = 0;/*SUPER modi always be 0*/

        clist_push_back(owner_list, (void *)mod_node);

        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_wait_file_owner_push: push %s to file '%.*s'\n",
                    c_word_to_ipv4(tcid), CSFS_WAIT_FILE_NAME_LEN(csfs_wait_file), CSFS_WAIT_FILE_NAME_STR(csfs_wait_file));
    }

    return (EC_TRUE);
}

/**
*
*  wakeup remote waiter (over http)
*
**/
EC_BOOL csfs_wait_file_owner_wakeup (const UINT32 csfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    CSFS_MD     *csfs_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_wait_file_owner_wakeup: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CSFSHTTP_REST_API_NAME"/cond_wakeup");
    cstring_append_cstr(uri, path);

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_wait_file_owner_wakeup: req uri '%.*s' done\n",
                CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld failed\n",
                        CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "[DEBUG] csfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld done => status %u\n",
                    CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL csfs_wait_file_owner_notify_over_http (CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file)))
    {
        TASK_BRD *task_brd;
        TASK_MGR *task_mgr;
        MOD_NODE  recv_mod_node;
        EC_BOOL   ret; /*ignore it*/

        task_brd = task_brd_default_get();

        /*all tasks own same recv_mod_node*/
        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one csfs module*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE   *mod_node;
            TASKS_CFG  *remote_tasks_cfg;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), MOD_NODE_TCID(mod_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "info:csfs_wait_file_owner_notify: not found tasks_cfg of node %s\n", c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
                mod_node_free(mod_node);
                continue;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, &recv_mod_node,
                        &ret,
                        FI_csfs_wait_file_owner_wakeup,
                        CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                        TASKS_CFG_CSRVPORT(remote_tasks_cfg),
                        CSFS_WAIT_FILE_NAME(csfs_wait_file));

            dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] csfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CSFS_WAIT_FILE_NAME_STR(csfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] csfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CSFS_WAIT_FILE_NAME_STR(csfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL csfs_wait_file_owner_notify_over_bgn (CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file)))
    {
        TASK_MGR *task_mgr;
        EC_BOOL   ret; /*ignore it*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE *mod_node;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CSFS_WAIT_FILE_OWNER_LIST(csfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node, &ret, FI_super_cond_wakeup, CMPI_ERROR_MODI, tag, CSFS_WAIT_FILE_NAME(csfs_wait_file));

            dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] csfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CSFS_WAIT_FILE_NAME_STR(csfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] csfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CSFS_WAIT_FILE_NAME_STR(csfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL csfs_wait_file_owner_notify(CSFS_WAIT_FILE *csfs_wait_file, const UINT32 tag)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return csfs_wait_file_owner_notify_over_http(csfs_wait_file, tag);
    }

    return csfs_wait_file_owner_notify_over_bgn(csfs_wait_file, tag);
}

STATIC_CAST static EC_BOOL __csfs_file_wait(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path)
{
    CSFS_MD          *csfs_md;

    CRB_NODE         *crb_node;
    CSFS_WAIT_FILE   *csfs_wait_file;

    csfs_md = CSFS_MD_GET(csfs_md_id);

    csfs_wait_file = csfs_wait_file_new();
    if(NULL_PTR == csfs_wait_file)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_file_wait: new csfs_wait_file failed\n");
        return (EC_FALSE);
    }

    csfs_wait_file_name_set(csfs_wait_file, file_path);

    crb_node = crb_tree_insert_data(CSFS_MD_WAIT_FILES(csfs_md), (void *)csfs_wait_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_file_wait: insert file %s to wait files tree failed\n",
                                (char *)cstring_get_str(file_path));
        csfs_wait_file_free(csfs_wait_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != csfs_wait_file)/*found duplicate*/
    {
        CSFS_WAIT_FILE *csfs_wait_file_duplicate;

        csfs_wait_file_duplicate = (CSFS_WAIT_FILE *)CRB_NODE_DATA(crb_node);

        csfs_wait_file_free(csfs_wait_file); /*no useful*/

        /*when found the file had been wait, register remote owner to it*/
        csfs_wait_file_owner_push(csfs_wait_file_duplicate, tcid);

        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] __csfs_file_wait: push %s to duplicated file '%s' in wait files tree done\n",
                            c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*register remote token owner to it*/
    csfs_wait_file_owner_push(csfs_wait_file, tcid);

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] __csfs_file_wait: push %s to inserted file %s in wait files tree done\n",
                        c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL csfs_file_wait(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_wait: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == csfs_read(csfs_md_id, file_path, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __csfs_file_wait(csfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfs_file_wait_e(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_wait: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == csfs_read_e(csfs_md_id, file_path, offset, max_len, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __csfs_file_wait(csfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*notify all waiters*/
EC_BOOL csfs_file_notify(const UINT32 csfs_md_id, const CSTRING *file_path)
{
    CSFS_MD          *csfs_md;

    CSFS_WAIT_FILE   *csfs_wait_file;
    CSFS_WAIT_FILE   *csfs_wait_file_found;
    CRB_NODE         *crb_node;
    UINT32            tag;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_notify: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    csfs_wait_file = csfs_wait_file_new();
    if(NULL_PTR == csfs_wait_file)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_file_notify: new csfs_wait_file failed\n");
        return (EC_FALSE);
    }

    csfs_wait_file_name_set(csfs_wait_file, file_path);

    crb_node = crb_tree_search_data(CSFS_MD_WAIT_FILES(csfs_md), (void *)csfs_wait_file);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_file_notify: not found waiters of file '%s'\n",
                        (char *)CSTRING_STR(file_path));
        csfs_wait_file_free(csfs_wait_file);
        return (EC_TRUE);
    }

    csfs_wait_file_free(csfs_wait_file);

    csfs_wait_file_found = CRB_NODE_DATA(crb_node);
    tag = MD_CSFS;

    if(EC_FALSE == csfs_wait_file_owner_notify (csfs_wait_file_found, tag))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_file_notify: notify waiters of file '%s' failed\n",
                        (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    crb_tree_delete(CSFS_MD_WAIT_FILES(csfs_md), crb_node);

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_file_notify: notify waiters of file '%s' done\n",
                    (char *)CSTRING_STR(file_path));
    return (EC_TRUE);
}

/*------------------------------------------------ interface for file lock ------------------------------------------------*/
CSFS_LOCKED_FILE *csfs_locked_file_new()
{
    CSFS_LOCKED_FILE *csfs_locked_file;
    alloc_static_mem(MM_CSFS_LOCKED_FILE, &csfs_locked_file, LOC_CSFS_0032);
    if(NULL_PTR != csfs_locked_file)
    {
        csfs_locked_file_init(csfs_locked_file);
    }
    return (csfs_locked_file);
}

EC_BOOL csfs_locked_file_init(CSFS_LOCKED_FILE *csfs_locked_file)
{
    cstring_init(CSFS_LOCKED_FILE_NAME(csfs_locked_file), NULL_PTR);
    cbytes_init(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file));

    CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL csfs_locked_file_clean(CSFS_LOCKED_FILE *csfs_locked_file)
{
    cstring_clean(CSFS_LOCKED_FILE_NAME(csfs_locked_file));
    cbytes_clean(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file));

    CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL csfs_locked_file_free(CSFS_LOCKED_FILE *csfs_locked_file)
{
    if(NULL_PTR != csfs_locked_file)
    {
        csfs_locked_file_clean(csfs_locked_file);
        free_static_mem(MM_CSFS_LOCKED_FILE, csfs_locked_file, LOC_CSFS_0033);
    }
    return (EC_TRUE);
}

EC_BOOL csfs_locked_file_init_0(const UINT32 md_id, CSFS_LOCKED_FILE *csfs_locked_file)
{
    return csfs_locked_file_init(csfs_locked_file);
}

EC_BOOL csfs_locked_file_clean_0(const UINT32 md_id, CSFS_LOCKED_FILE *csfs_locked_file)
{
    return csfs_locked_file_clean(csfs_locked_file);
}

EC_BOOL csfs_locked_file_free_0(const UINT32 md_id, CSFS_LOCKED_FILE *csfs_locked_file)
{
    if(NULL_PTR != csfs_locked_file)
    {
        csfs_locked_file_clean(csfs_locked_file);
        free_static_mem(MM_CSFS_LOCKED_FILE, csfs_locked_file, LOC_CSFS_0034);
    }
    return (EC_TRUE);
}

int csfs_locked_file_cmp(const CSFS_LOCKED_FILE *csfs_locked_file_1st, const CSFS_LOCKED_FILE *csfs_locked_file_2nd)
{
    return cstring_cmp(CSFS_LOCKED_FILE_NAME(csfs_locked_file_1st), CSFS_LOCKED_FILE_NAME(csfs_locked_file_2nd));
}

void csfs_locked_file_print(LOG *log, const CSFS_LOCKED_FILE *csfs_locked_file)
{
    if(NULL_PTR != csfs_locked_file)
    {
        sys_log(log, "csfs_locked_file_print %p: file %s, expire %ld seconds\n",
                        csfs_locked_file,
                        (char *)CSFS_LOCKED_FILE_NAME_STR(csfs_locked_file),
                        CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file)
                        );
        sys_log(log, "csfs_locked_file_print %p: file %s, token ",
                        csfs_locked_file,
                        (char *)CSFS_LOCKED_FILE_NAME_STR(csfs_locked_file)
                        );
        cbytes_print_chars(log, CSFS_LOCKED_FILE_TOKEN(csfs_locked_file));

        sys_log(log, "csfs_locked_file_print %p: file %s\n",
                        csfs_locked_file,
                        (char *)CSFS_LOCKED_FILE_NAME_STR(csfs_locked_file)
                        );
    }

    return;
}

void csfs_locked_files_print(const UINT32 csfs_md_id, LOG *log)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_locked_files_print: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    crb_tree_print(log, CSFS_MD_LOCKED_FILES(csfs_md));

    return;
}

/*generate token from file_path with time as random*/
EC_BOOL csfs_locked_file_token_gen(CSFS_LOCKED_FILE *csfs_locked_file, const CSTRING *file_name)
{
    uint8_t  digest[ CMD5_DIGEST_LEN ];
    CSTRING  cstr;

    cstring_init(&cstr, cstring_get_str(file_name));

    cstring_append_str(&cstr, (const UINT8 *)TASK_BRD_TIME_STR(task_brd_default_get()));

    cmd5_sum(cstring_get_len(&cstr), cstring_get_str(&cstr), digest);
    cstring_clean(&cstr);

    cbytes_set(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file), (const UINT8 *)digest, CMD5_DIGEST_LEN);

    return (EC_TRUE);
}

EC_BOOL csfs_locked_file_expire_set(CSFS_LOCKED_FILE *csfs_locked_file, const UINT32 expire_nsec)
{
    CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file) = expire_nsec;

    CTIMET_GET(CSFS_LOCKED_FILE_START_TIME(csfs_locked_file));
    CTIMET_GET(CSFS_LOCKED_FILE_LAST_TIME(csfs_locked_file));

    return (EC_TRUE);
}

EC_BOOL csfs_locked_file_is_expire(const CSFS_LOCKED_FILE *csfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CSFS_LOCKED_FILE_LAST_TIME(csfs_locked_file), cur_time);
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_locked_file_is_expire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file));
    if(diff_nsec >= 0.0 + CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csfs_locked_file_name_set(CSFS_LOCKED_FILE *csfs_locked_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CSFS_LOCKED_FILE_NAME(csfs_locked_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfs_locked_file_need_retire(const CSFS_LOCKED_FILE *csfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CSFS_LOCKED_FILE_LAST_TIME(csfs_locked_file), cur_time);
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] __csfs_locked_file_need_retire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file));
    if(diff_nsec >= 0.0 + 2 * CSFS_LOCKED_FILE_EXPIRE_NSEC(csfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __csfs_locked_file_retire(CRB_TREE *crbtree, const CRB_NODE *node)
{
    CSFS_LOCKED_FILE *csfs_locked_file;

    if(NULL_PTR == node)
    {
        return (EC_FALSE);
    }

    csfs_locked_file = CRB_NODE_DATA(node);
    if(EC_TRUE == __csfs_locked_file_need_retire(csfs_locked_file))
    {
        dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] __csfs_locked_file_retire: file %s was retired\n",
                            (char *)cstring_get_str(CSFS_LOCKED_FILE_NAME(csfs_locked_file)));

        crb_tree_delete(crbtree, (CRB_NODE *)node);
        return (EC_TRUE);/*succ and terminate*/
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_TRUE == __csfs_locked_file_retire(crbtree, CRB_NODE_LEFT(node)))
        {
            return (EC_TRUE);
        }
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_TRUE == __csfs_locked_file_retire(crbtree, CRB_NODE_RIGHT(node)))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*retire the expired locked files over 120 seconds which are garbage*/
EC_BOOL csfs_locked_file_retire(const UINT32 csfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num)
{
    CSFS_MD      *csfs_md;
    CRB_TREE     *crbtree;
    UINT32        retire_idx;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_locked_file_retire: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    crbtree = CSFS_MD_LOCKED_FILES(csfs_md);

    for(retire_idx = 0; retire_idx < retire_max_num; retire_idx ++)
    {
        if(EC_FALSE == __csfs_locked_file_retire(crbtree, CRB_TREE_ROOT(crbtree)))
        {
            break;/*no more to retire, terminate*/
        }
    }

    if(NULL_PTR != retire_num)
    {
        (*retire_num) = retire_idx;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfs_file_lock(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CBYTES *token, UINT32 *locked_already)
{
    CSFS_MD          *csfs_md;

    CRB_NODE         *crb_node;
    CSFS_LOCKED_FILE *csfs_locked_file;

    csfs_md = CSFS_MD_GET(csfs_md_id);

    csfs_locked_file = csfs_locked_file_new();
    if(NULL_PTR == csfs_locked_file)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_file_lock: new csfs_locked_file failed\n");
        return (EC_FALSE);
    }

    csfs_locked_file_name_set(csfs_locked_file, file_path);
    csfs_locked_file_token_gen(csfs_locked_file, file_path);/*generate token from file_path with time as random*/
    csfs_locked_file_expire_set(csfs_locked_file, expire_nsec);

    crb_node = crb_tree_insert_data(CSFS_MD_LOCKED_FILES(csfs_md), (void *)csfs_locked_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_file_lock: insert file %s to locked files tree failed\n",
                                (char *)cstring_get_str(file_path));
        csfs_locked_file_free(csfs_locked_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != csfs_locked_file)/*found duplicate*/
    {
        CSFS_LOCKED_FILE *csfs_locked_file_duplicate;

        csfs_locked_file_duplicate = (CSFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node);

        if(EC_FALSE == csfs_locked_file_is_expire(csfs_locked_file_duplicate))
        {
            dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] __csfs_file_lock: file %s already in locked files tree\n",
                                (char *)cstring_get_str(file_path));

            csfs_locked_file_free(csfs_locked_file); /*no useful*/

            (*locked_already) = EC_TRUE;/*means file had been locked by someone else*/
            return (EC_FALSE);
        }

        CRB_NODE_DATA(crb_node) = csfs_locked_file; /*mount new*/

        csfs_locked_file_free(csfs_locked_file_duplicate); /*free the duplicate which is also old*/

        cbytes_clone(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file), token);

        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] __csfs_file_lock: update file %s to locked files tree done\n",
                            (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*now csfs_locked_file_tmp already insert and mount into tree*/
    cbytes_clone(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file), token);

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] __csfs_file_lock: insert file %s to locked files tree done\n",
                        (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL csfs_file_lock(const UINT32 csfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already)
{
    CSFS_MD      *csfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_lock: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    cbytes_init(&token_cbyte);

    CSFS_LOCKED_FILES_WRLOCK(csfs_md, LOC_CSFS_0035);
    if(EC_FALSE == __csfs_file_lock(csfs_md_id, tcid, file_path, expire_nsec, &token_cbyte, locked_already))
    {
        CSFS_LOCKED_FILES_UNLOCK(csfs_md, LOC_CSFS_0036);
        return (EC_FALSE);
    }

    CSFS_LOCKED_FILES_UNLOCK(csfs_md, LOC_CSFS_0037);

    cbase64_encode(CBYTES_BUF(&token_cbyte), CBYTES_LEN(&token_cbyte), auth_token, sizeof(auth_token), &auth_token_len);
    cstring_append_chars(token_str, auth_token_len, auth_token, LOC_CSFS_0038);
    cbytes_clean(&token_cbyte);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfs_file_unlock(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *token)
{
    CSFS_MD          *csfs_md;

    CRB_NODE         *crb_node_searched;

    CSFS_LOCKED_FILE *csfs_locked_file_tmp;
    CSFS_LOCKED_FILE *csfs_locked_file_searched;

    csfs_md = CSFS_MD_GET(csfs_md_id);

    csfs_locked_file_tmp = csfs_locked_file_new();
    if(NULL_PTR == csfs_locked_file_tmp)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_file_unlock: new CSFS_LOCKED_FILE failed\n");
        return (EC_FALSE);
    }

    csfs_locked_file_name_set(csfs_locked_file_tmp, file_path);

    crb_node_searched = crb_tree_search_data(CSFS_MD_LOCKED_FILES(csfs_md), (void *)csfs_locked_file_tmp);/*compare name*/
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] __csfs_file_unlock: file %s not in locked files tree\n",
                                (char *)cstring_get_str(file_path));
        csfs_locked_file_free(csfs_locked_file_tmp);
        return (EC_FALSE);
    }

    csfs_locked_file_free(csfs_locked_file_tmp); /*no useful*/

    csfs_locked_file_searched = (CSFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node_searched);

    /*if expired already, remove it as garbage, despite of token comparsion*/
    if(EC_TRUE == csfs_locked_file_is_expire(csfs_locked_file_searched))
    {
        crb_tree_delete(CSFS_MD_LOCKED_FILES(csfs_md), crb_node_searched);
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "info:__csfs_file_unlock: remove expired locked file %s\n",
                        (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*if exist, compare token. if not exist, unlock by force!*/
    if(NULL_PTR != token && EC_FALSE == cbytes_cmp(CSFS_LOCKED_FILE_TOKEN(csfs_locked_file_searched), token))
    {
        if(do_log(SEC_0167_CSFS, 9))
        {
            sys_log(LOGSTDOUT, "warn:__csfs_file_unlock: file %s, searched token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, CSFS_LOCKED_FILE_TOKEN(csfs_locked_file_searched));

            sys_log(LOGSTDOUT, "warn:__csfs_file_unlock: file %s, but input token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, token);
        }
        return (EC_FALSE);
    }

    if(do_log(SEC_0167_CSFS, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __csfs_file_unlock: file %s notify ...\n",
                                (char *)cstring_get_str(file_path));

        sys_log(LOGSTDOUT, "[DEBUG] __csfs_file_unlock: searched file:\n");
        csfs_locked_file_print(LOGSTDOUT, csfs_locked_file_searched);
    }

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] __csfs_file_unlock: file %s notify ... done\n",
                            (char *)cstring_get_str(file_path));

    crb_tree_delete(CSFS_MD_LOCKED_FILES(csfs_md), crb_node_searched);

    dbg_log(SEC_0167_CSFS, 5)(LOGSTDOUT, "[DEBUG] __csfs_file_unlock: file %s unlocked\n",
                            (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL csfs_file_unlock(const UINT32 csfs_md_id, const CSTRING *file_path, const CSTRING *token_str)
{
    CSFS_MD      *csfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_unlock: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    cbase64_decode((UINT8 *)CSTRING_STR(token_str), CSTRING_LEN(token_str), auth_token, sizeof(auth_token), &auth_token_len);
    cbytes_mount(&token_cbyte, auth_token_len, auth_token);
#if 0
    if(do_log(SEC_0167_CSFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfs_file_unlock: auth_token str: %.*s\n", CSTRING_LEN(token_str), CSTRING_STR(token_str));
        sys_log(LOGSTDOUT, "[DEBUG] csfs_file_unlock: auth_token str => token: ");
        cbytes_print_chars(LOGSTDOUT, &token_cbyte);

        sys_log(LOGSTDOUT, "[DEBUG] csfs_file_unlock: all locked files are: \n");
        csfs_locked_files_print(csfs_md_id, LOGSTDOUT);
    }
#endif
    CSFS_LOCKED_FILES_WRLOCK(csfs_md, LOC_CSFS_0039);
    if(EC_FALSE == __csfs_file_unlock(csfs_md_id, file_path, &token_cbyte))
    {
        cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
        CSFS_LOCKED_FILES_UNLOCK(csfs_md, LOC_CSFS_0040);
        return (EC_FALSE);
    }

    CSFS_LOCKED_FILES_UNLOCK(csfs_md, LOC_CSFS_0041);

    cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
    return (EC_TRUE);
}


/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL csfs_file_unlock_notify(const UINT32 csfs_md_id, const CSTRING *file_path)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_unlock_notify: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_file_unlock_notify: obsolete interface!!!!\n");

    return (EC_FALSE);
}

/**
*
*   load file from SFS to memcache
*
**/
EC_BOOL csfs_cache_file(const UINT32 csfs_md_id, const CSTRING *path)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_cache_file: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        CBYTES cbytes;

        cbytes_init(&cbytes);

        if(EC_FALSE == csfs_read(csfs_md_id, path, &cbytes))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_cache_file: read file %s from sfs failed\n",
                                   (char *)cstring_get_str(path));
            cbytes_clean(&cbytes);
            return (EC_FALSE);
        }
#if 0
        if(EC_FALSE == csfsmc_update(CSFS_MD_MCACHE(csfs_md), path, &cbytes, NULL_PTR))
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_cache_file: update file %s to memcache failed\n",
                                   (char *)cstring_get_str(path));
            cbytes_clean(&cbytes);
            return (EC_FALSE);
        }
#endif
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_cache_file: cache file %s done\n",
                                   (char *)cstring_get_str(path));
        cbytes_clean(&cbytes);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}


/**
*
*  create data node
*
**/
EC_BOOL csfs_create_dn(const UINT32 csfs_md_id, const CSTRING *root_dir)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_create_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    if(NULL_PTR != CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_create_dn: dn already exist\n");
        return (EC_FALSE);
    }

    CSFS_MD_DN(csfs_md) = csfsdn_create((char *)cstring_get_str(root_dir),
                                        CSFSNPRB_ERR_POS,
                                        (CSFSNP_RECYCLE)csfsnp_mgr_delete_np,
                                        (void *)CSFS_MD_NPP(csfs_md));
    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_create_dn: create dn failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  add a disk to data node
*
**/
EC_BOOL csfs_add_disk(const UINT32 csfs_md_id, const UINT32 disk_no)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_add_disk: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_add_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_add_disk: disk_no %u is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CSFS_WRLOCK(csfs_md, LOC_CSFS_0042);
    if(EC_FALSE == csfsdn_add_disk(CSFS_MD_DN(csfs_md), (uint16_t)disk_no))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0043);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_add_disk: add disk %u to dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CSFS_UNLOCK(csfs_md, LOC_CSFS_0044);
    return (EC_TRUE);
}

/**
*
*  delete a disk from data node
*
**/
EC_BOOL csfs_del_disk(const UINT32 csfs_md_id, const UINT32 disk_no)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_del_disk: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_del_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_del_disk: disk_no %u is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CSFS_WRLOCK(csfs_md, LOC_CSFS_0045);
    if(EC_FALSE == csfsdn_del_disk(CSFS_MD_DN(csfs_md), (uint16_t)disk_no))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0046);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_del_disk: del disk %u from dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CSFS_UNLOCK(csfs_md, LOC_CSFS_0047);
    return (EC_TRUE);
}

/**
*
*  mount a disk to data node
*
**/
EC_BOOL csfs_mount_disk(const UINT32 csfs_md_id, const UINT32 disk_no)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_mount_disk: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_mount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_mount_disk: disk_no %u is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CSFS_WRLOCK(csfs_md, LOC_CSFS_0048);
    if(EC_FALSE == csfsdn_mount_disk(CSFS_MD_DN(csfs_md), (uint16_t)disk_no))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0049);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_mount_disk: mount disk %u to dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CSFS_UNLOCK(csfs_md, LOC_CSFS_0050);
    return (EC_TRUE);
}

/**
*
*  umount a disk from data node
*
**/
EC_BOOL csfs_umount_disk(const UINT32 csfs_md_id, const UINT32 disk_no)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_umount_disk: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);
    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_umount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_umount_disk: disk_no %u is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CSFS_WRLOCK(csfs_md, LOC_CSFS_0051);
    if(EC_FALSE == csfsdn_umount_disk(CSFS_MD_DN(csfs_md), (uint16_t)disk_no))
    {
        CSFS_UNLOCK(csfs_md, LOC_CSFS_0052);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_umount_disk: umount disk %u from dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CSFS_UNLOCK(csfs_md, LOC_CSFS_0053);
    return (EC_TRUE);
}


/**
*
*  open data node
*
**/
EC_BOOL csfs_open_dn(const UINT32 csfs_md_id, const CSTRING *root_dir)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_open_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_open_dn: try to open dn %s  ...\n", (char *)cstring_get_str(root_dir));

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR != CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_open_dn: dn was open\n");
        return (EC_FALSE);
    }

    CSFS_MD_DN(csfs_md) = csfsdn_open((char *)cstring_get_str(root_dir),
                                        CSFSNPRB_ERR_POS,
                                        (CSFSNP_RECYCLE)csfsnp_mgr_delete_np,
                                        (void *)CSFS_MD_NPP(csfs_md));
    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_open_dn: open dn with root dir %s failed\n", (char *)cstring_get_str(root_dir));
        return (EC_FALSE);
    }
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_open_dn: open dn %s\n", (char *)cstring_get_str(root_dir));
    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL csfs_close_dn(const UINT32 csfs_md_id)
{
    CSFS_MD   *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_close_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_close_dn: no dn was open\n");
        return (EC_FALSE);
    }

    csfsdn_close(CSFS_MD_DN(csfs_md));
    CSFS_MD_DN(csfs_md) = NULL_PTR;
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_close_dn: dn was closed\n");

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL csfs_export_dn(const UINT32 csfs_md_id, const CBYTES *cbytes, const CSFSNP_FNODE *csfsnp_fnode)
{
    CSFS_MD      *csfs_md;
    const CSFSNP_INODE *csfsnp_inode;

    UINT32   offset;
    UINT32   data_len;
    uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_export_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    data_len = DMIN(CBYTES_LEN(cbytes), CSFSNP_FNODE_FILESZ(csfsnp_fnode));

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_export_dn: CBYTES_LEN %u or CSFSNP_FNODE_FILESZ %u overflow\n",
                            CBYTES_LEN(cbytes), CSFSNP_FNODE_FILESZ(csfsnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)data_len;

    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    disk_no  = CSFSNP_INODE_DISK_NO(csfsnp_inode) ;
    block_no = CSFSNP_INODE_BLOCK_NO(csfsnp_inode);
    page_no  = CSFSNP_INODE_PAGE_NO(csfsnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == csfsdn_write_o(CSFS_MD_DN(csfs_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_export_dn: write %u bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_export_dn: write %u bytes to disk %u block %u page %u done\n",
                        data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL csfs_write_dn(const UINT32 csfs_md_id, const CBYTES *cbytes, CSFSNP_FNODE *csfsnp_fnode)
{
    CSFS_MD      *csfs_md;
    CSFSNP_INODE *csfsnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_write_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_write_dn: buff len (or file size) %u overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    csfsdn_wrlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0054);
    if(EC_FALSE == csfsdn_write_p(CSFS_MD_DN(csfs_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0055);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_write_dn: write %u bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }
    csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0056);

    csfsnp_fnode_init(csfsnp_fnode);
    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    CSFSNP_INODE_DISK_NO(csfsnp_inode)  = disk_no;
    CSFSNP_INODE_BLOCK_NO(csfsnp_inode) = block_no;
    CSFSNP_INODE_PAGE_NO(csfsnp_inode)  = page_no;

    CSFSNP_FNODE_FILESZ(csfsnp_fnode) = CBYTES_LEN(cbytes);
    CSFSNP_FNODE_REPNUM(csfsnp_fnode) = 1;

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL csfs_read_dn(const UINT32 csfs_md_id, const CSFSNP_FNODE *csfsnp_fnode, CBYTES *cbytes)
{
    CSFS_MD *csfs_md;
    const CSFSNP_INODE *csfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_read_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CSFSNP_FNODE_REPNUM(csfsnp_fnode))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CSFSNP_FNODE_FILESZ(csfsnp_fnode);
    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    disk_no  = CSFSNP_INODE_DISK_NO(csfsnp_inode) ;
    block_no = CSFSNP_INODE_BLOCK_NO(csfsnp_inode);
    page_no  = CSFSNP_INODE_PAGE_NO(csfsnp_inode) ;

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_read_dn: file file %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CSFS_0057);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CSFS_0058);
        CBYTES_LEN(cbytes) = 0;
    }

    csfsdn_rdlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0059);
    if(EC_FALSE == csfsdn_read_p(CSFS_MD_DN(csfs_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0060);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                           file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0061);
    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL csfs_read_e_dn(const UINT32 csfs_md_id, const CSFSNP_FNODE *csfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CSFS_MD *csfs_md;
    const CSFSNP_INODE *csfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_read_e_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CSFSNP_FNODE_REPNUM(csfsnp_fnode))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CSFSNP_FNODE_FILESZ(csfsnp_fnode);
    csfsnp_inode = CSFSNP_FNODE_INODE(csfsnp_fnode, 0);
    disk_no  = CSFSNP_INODE_DISK_NO(csfsnp_inode) ;
    block_no = CSFSNP_INODE_BLOCK_NO(csfsnp_inode);
    page_no  = CSFSNP_INODE_PAGE_NO(csfsnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:crfs_read_e_dn: due to offset %u >= file size %u\n", (*offset), file_size);
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

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] crfs_read_e_dn: file size %u, disk %u, block %u, page %u, offset %u, max len %u\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CSFS_0062);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CSFS_0063);
        CBYTES_LEN(cbytes) = 0;
    }

    csfsdn_rdlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0064);
    if(EC_FALSE == csfsdn_read_e(CSFS_MD_DN(csfs_md), disk_no, block_no, page_no, offset_t, max_len_t, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0065);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_e_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                           max_len_t, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0066);

     (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}

/**
*
*  write a fnode to name node
*
**/
EC_BOOL csfs_write_npp(const UINT32 csfs_md_id, const CSTRING *file_path, const CSFSNP_FNODE *csfsnp_fnode)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_write_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_write_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(0 == CSFSNP_FNODE_REPNUM(csfsnp_fnode))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_write_npp: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_wrlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0067);
    if(EC_FALSE == csfsnp_mgr_write(CSFS_MD_NPP(csfs_md), file_path, csfsnp_fnode, NULL_PTR, NULL_PTR))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0068);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_write_npp: no name node accept file %s with %u replicas\n",
                            (char *)cstring_get_str(file_path), CSFSNP_FNODE_REPNUM(csfsnp_fnode));
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0069);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfs_write_npp(const UINT32 csfs_md_id, const CSTRING *file_path, const CSFSNP_FNODE *csfsnp_fnode, uint32_t *crfsnp_id, uint32_t *node_pos)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__csfs_write_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(0 == CSFSNP_FNODE_REPNUM(csfsnp_fnode))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write_npp: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_wrlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0070);
    if(EC_FALSE == csfsnp_mgr_write(CSFS_MD_NPP(csfs_md), file_path, csfsnp_fnode, crfsnp_id, node_pos))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0071);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:__csfs_write_npp: no name node accept file %s with %u replicas\n",
                            (char *)cstring_get_str(file_path), CSFSNP_FNODE_REPNUM(csfsnp_fnode));
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0072);
    return (EC_TRUE);
}

/**
*
*  read a fnode from name node
*
**/
EC_BOOL csfs_read_npp(const UINT32 csfs_md_id, const CSTRING *file_path, CSFSNP_FNODE *csfsnp_fnode)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_read_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_read_npp: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0073);
    if(EC_FALSE == csfsnp_mgr_read(CSFS_MD_NPP(csfs_md), file_path, csfsnp_fnode))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0074);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_read_npp: csfsnp mgr read %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0075);

    return (EC_TRUE);
}

/**
*
*  delete a file from current npp
*
**/
EC_BOOL csfs_delete_npp(const UINT32 csfs_md_id, const CSTRING *path)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_delete_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_delete_npp: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_wrlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0076);
    if(EC_FALSE == csfsnp_mgr_delete(CSFS_MD_NPP(csfs_md), path))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0077);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_delete_npp: delete '%s' failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0078);

    return (EC_TRUE);
}


/**
*
*  delete file data from current dn
*
**/
EC_BOOL csfs_delete_dn(const UINT32 csfs_md_id, const CSFSNP_FNODE *csfsnp_fnode)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_delete_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_delete_dn: obsolete interface\n");

    return (EC_TRUE);
}

/**
*
*  delete a file from all npp and all dn
*
**/
EC_BOOL csfs_delete(const UINT32 csfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_delete: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    /*delete inodes*/
    if(EC_FALSE == csfs_delete_npp(csfs_md_id, path))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_delete: delete %s from npp failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_delete: delete %s done\n", (char *)cstring_get_str(path));
    return (EC_TRUE);
}

/**
*
*  delete a dir from all npp and all dn
*
*  warning:
*       this interface is only for specific purpose.
*       the file name looks like ${path}/${idx}
*       where ${idx} <= ${max_idx}
*       i.e., seg: 0 (header), 1,2,...,max_idx
*
**/
EC_BOOL csfs_delete_dir(const UINT32 csfs_md_id, const CSTRING *dir_path, const UINT32 max_idx)
{
    CSTRING    file_path;
    UINT32     idx;

    CSTRING   *dir_path_dup;
    MOD_NODE   recv_mod_node;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_delete_dir: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    dir_path_dup = cstring_dup(dir_path);
    if(NULL_PTR == dir_path_dup)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_delete_dir: dup '%s' failed\n", (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    if('/' != c_str_last_char((char *)cstring_get_str(dir_path_dup)))
    {
        cstring_append_char(dir_path_dup, (const UINT8)'/');
    }

    cstring_init(&file_path, NULL_PTR);

    MOD_NODE_TCID(&recv_mod_node) = task_brd_default_get_tcid();
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = task_brd_default_get_rank();
    MOD_NODE_MODI(&recv_mod_node) = csfs_md_id;

    for(idx = 0; idx <= max_idx; idx ++)
    {
        char    *file_path_str;
        EC_BOOL  ret;

        file_path_str = c_str_cat((char *)cstring_get_str(dir_path_dup), c_word_to_str(idx));
        if(NULL_PTR == file_path_str)
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_delete_dir: cat '%s' and '%ld' failed\n", (char *)cstring_get_str(dir_path_dup), idx);

            cstring_free(dir_path_dup);
            return (EC_FALSE);
        }
        cstring_set_str(&file_path, (UINT8 *)file_path_str);

#if 0
        /*delete inode*/
        if(EC_TRUE == csfs_delete_npp(csfs_md_id, &file_path))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_delete_dir: delete file '%s' done\n", (char *)cstring_get_str(&file_path));
        }
#endif
#if 1
        /*delete inode [optimized]*/
        task_p2p(csfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_csfs_delete, CMPI_ERROR_MODI, &file_path);
#endif
        cstring_clean(&file_path);
    }

    cstring_free(dir_path_dup);

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_delete_dir: delete dir '%s' done\n", (char *)cstring_get_str(dir_path));
    return (EC_TRUE);
}

/**
*
*  query a file
*
**/
EC_BOOL csfs_qfile(const UINT32 csfs_md_id, const CSTRING *file_path, CSFSNP_ITEM  *csfsnp_item)
{
    CSFS_MD      *csfs_md;
    CSFSNP_ITEM  *csfsnp_item_src;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_qfile: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_qfile: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0079);
    csfsnp_item_src = csfsnp_mgr_search_item(CSFS_MD_NPP(csfs_md),
                                             (uint32_t)cstring_get_len(file_path),
                                             cstring_get_str(file_path));
    if(NULL_PTR == csfsnp_item_src)
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0080);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_qfile: query file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0081);

    csfsnp_item_clone(csfsnp_item_src, csfsnp_item);

    return (EC_TRUE);
}

/**
*
*  flush name node pool
*
**/
EC_BOOL csfs_flush_npp(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_flush_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_flush_npp: npp was not open\n");
        return (EC_TRUE);
    }

    csfsnp_mgr_wrlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0082);
    if(EC_FALSE == csfsnp_mgr_flush(CSFS_MD_NPP(csfs_md)))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0083);

        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_flush_npp: flush failed\n");
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0084);
    return (EC_TRUE);
}

/**
*
*  flush data node
*
*
**/
EC_BOOL csfs_flush_dn(const UINT32 csfs_md_id)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_flush_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_flush_dn: dn is null\n");
        return (EC_FALSE);
    }

    csfsdn_wrlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0085);
    if(EC_FALSE == csfsdn_flush(CSFS_MD_DN(csfs_md)))
    {
        csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0086);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_flush_dn: flush dn failed\n");
        return (EC_FALSE);
    }
    csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0087);

    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL csfs_file_num(const UINT32 csfs_md_id, UINT32 *file_num)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_num: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_file_num: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_wrlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0088);
    if(EC_FALSE == csfsnp_mgr_file_num(CSFS_MD_NPP(csfs_md), file_num))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0089);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_file_num: count total file num failed\n");
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0090);

    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL csfs_file_size(const UINT32 csfs_md_id, const CSTRING *path_cstr, UINT32 *file_size)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_size: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_file_size: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_wrlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0091);
    if(EC_FALSE == csfsnp_mgr_file_size(CSFS_MD_NPP(csfs_md), path_cstr, file_size))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0092);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_file_size: count total file size failed\n");
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0093);
    return (EC_TRUE);
}

/**
*
*  search in current name node pool
*
**/
EC_BOOL csfs_search(const UINT32 csfs_md_id, const CSTRING *path_cstr)
{
    CSFS_MD      *csfs_md;
    uint32_t      csfsnp_id;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_search: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_search: npp was not open\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0094);
    if(EC_FALSE == csfsnp_mgr_search(CSFS_MD_NPP(csfs_md), (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &csfsnp_id))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0095);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_search: search '%s' failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0096);

    return (EC_TRUE);
}

/**
*
*  check file content on data node
*
**/
EC_BOOL csfs_check_file_content(const UINT32 csfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr)
{
    CSFS_MD *csfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_check_file_content: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_content: dn is null\n");
        return (EC_FALSE);
    }

    ASSERT(EC_TRUE == __csfs_check_is_uint16_t(disk_no));
    ASSERT(EC_TRUE == __csfs_check_is_uint16_t(block_no));
    ASSERT(EC_TRUE == __csfs_check_is_uint16_t(page_no));

    cbytes = cbytes_new(file_size);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_content: new csfs buff with len %u failed\n", file_size);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsdn_read_p(CSFS_MD_DN(csfs_md), (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no, file_size,
                                  CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_content: read %u bytes from disk %u, block %u, page %u failed\n",
                            file_size, disk_no, block_no, page_no);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < cstring_get_len(file_content_cstr))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_content: read %u bytes from disk %u, block %u, page %u to buff len %u less than cstring len %u to compare\n",
                            file_size, disk_no, block_no, page_no,
                            CBYTES_LEN(cbytes), cstring_get_len(file_content_cstr));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    len = cstring_get_len(file_content_cstr);

    buff = CBYTES_BUF(cbytes);
    str  = cstring_get_str(file_content_cstr);

    for(pos = 0; pos < len; pos ++)
    {
        if(buff[ pos ] != str[ pos ])
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_content: char at pos %u not matched\n", pos);
            sys_print(LOGSTDOUT, "read buff: %.*s\n", len, buff);
            sys_print(LOGSTDOUT, "expected : %.*s\n", len, str);

            cbytes_free(cbytes);
            return (EC_FALSE);
        }
    }

    cbytes_free(cbytes);
    return (EC_TRUE);
}

/**
*
*  check file content on data node
*
**/
EC_BOOL csfs_check_file_is(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *file_content)
{
    CSFS_MD *csfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_check_file_is: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_is: dn is null\n");
        return (EC_FALSE);
    }

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_is: new cbytes failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csfs_read(csfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_is: read file %s failed\n", (char *)cstring_get_str(file_path));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) != CBYTES_LEN(file_content))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_is: mismatched len: file %s read len %u which should be %u\n",
                            (char *)cstring_get_str(file_path),
                            CBYTES_LEN(cbytes), CBYTES_LEN(file_content));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    len  = CBYTES_LEN(file_content);

    buff = CBYTES_BUF(cbytes);
    str  = CBYTES_BUF(file_content);

    for(pos = 0; pos < len; pos ++)
    {
        if(buff[ pos ] != str[ pos ])
        {
            dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_check_file_is: char at pos %u not matched\n", pos);
            sys_print(LOGSTDOUT, "read buff: %.*s\n", len, buff);
            sys_print(LOGSTDOUT, "expected : %.*s\n", len, str);

            cbytes_free(cbytes);
            return (EC_FALSE);
        }
    }

    cbytes_free(cbytes);
    return (EC_TRUE);
}

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL csfs_show_npp(const UINT32 csfs_md_id, LOG *log)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_show_npp: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0097);

    csfsnp_mgr_print(log, CSFS_MD_NPP(csfs_md));

    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0098);

    return (EC_TRUE);
}

/**
*
*  show csfsdn info if it is dn
*
*
**/
EC_BOOL csfs_show_dn(const UINT32 csfs_md_id, LOG *log)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_show_dn: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_DN(csfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    csfsdn_rdlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0099);
    csfsdn_print(log, CSFS_MD_DN(csfs_md));
    csfsdn_unlock(CSFS_MD_DN(csfs_md), LOC_CSFS_0100);

    return (EC_TRUE);
}

/*debug*/
EC_BOOL csfs_show_cached_np(const UINT32 csfs_md_id, LOG *log)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_show_cached_np: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0101);
    if(EC_FALSE == csfsnp_mgr_show_cached_np(log, CSFS_MD_NPP(csfs_md)))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0102);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_show_cached_np: show cached np but failed\n");
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0103);

    return (EC_TRUE);
}

EC_BOOL csfs_show_specific_np(const UINT32 csfs_md_id, const UINT32 csfsnp_id, LOG *log)
{
    CSFS_MD *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_show_specific_np: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfs_check_is_uint32_t(csfsnp_id))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_show_specific_np: csfsnp_id %u is invalid\n", csfsnp_id);
        return (EC_FALSE);
    }

    csfsnp_mgr_rdlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0104);
    if(EC_FALSE == csfsnp_mgr_show_np(log, CSFS_MD_NPP(csfs_md), (uint32_t)csfsnp_id))
    {
        csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0105);
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_show_cached_np: show np %u but failed\n", csfsnp_id);
        return (EC_FALSE);
    }
    csfsnp_mgr_unlock(CSFS_MD_NPP(csfs_md), LOC_CSFS_0106);

    return (EC_TRUE);
}

/* write memory cache only but Not sfs */
EC_BOOL csfs_write_memc(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_write_memc: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    CSFS_MD      *csfs_md;
    csfs_md = CSFS_MD_GET(csfs_md_id);

    /* ensure CSFS_MEMC_SWITCH is on */
    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        if(EC_TRUE == csfsmc_write(CSFS_MD_MCACHE(csfs_md), file_path, cbytes))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_write_memc: write file %s with size %ld to memcache done\n",
                (char *)cstring_get_str(file_path), cbytes_len(cbytes));

            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_write_memc: write file %s with size %ld to memcache failed\n",
                (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        }
    }
    else
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_write_memc: there is no memcache because CSFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // write to memcache failed, or CSFS_MEMC_SWITCH is off
}


/* check whether a file is in memory cache */
EC_BOOL csfs_check_memc(const UINT32 csfs_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_check_memc: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    CSFS_MD      *csfs_md;
    csfs_md = CSFS_MD_GET(csfs_md_id);

    /* ensure CSFS_MEMC_SWITCH is on */
    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        if(EC_TRUE == csfsmc_check_np(CSFS_MD_MCACHE(csfs_md), file_path))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_check_memc: file %s is in memcache\n",
                               (char *)cstring_get_str(file_path));
            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_check_memc: file %s is NOT in memcache\n",
                               (char *)cstring_get_str(file_path));
        }
    }
    else
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_check_memc: there is no memcache because CSFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // check path from memcache failed, or CSFS_MEMC_SWITCH is off
}

/**
*
*  read file from memory cache only but NOT sfs
*
**/
EC_BOOL csfs_read_memc(const UINT32 csfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_read_memc: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    CSFS_MD      *csfs_md;
    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        if(EC_TRUE == csfsmc_read(CSFS_MD_MCACHE(csfs_md), file_path, cbytes))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_read_memc: read file %s with size %ld from memcache done\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));
            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_read_memc: read file %s from memcache failed\n",
                               (char *)cstring_get_str(file_path));
        }
    }
    else
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_read_memc: there is no memcache because CSFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // read from memcache failed, or CSFS_MEMC_SWITCH is off
}

/**
*
*  update file in memory cache only but NOT sfs
*
**/
EC_BOOL csfs_update_memc(const UINT32 csfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_update_memc: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        if(EC_TRUE == csfsmc_update(CSFS_MD_MCACHE(csfs_md), file_path, cbytes))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update_memc: update file %s with size %ld to memcache done\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));

            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update_memc: update file %s with size %ld to memcache failed\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        }
    }
    else
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_update_memc: there is no memcache because CSFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // update to memcache failed, or CSFS_MEMC_SWITCH is off
}

/**
*
*  delete from memory cache only but NOT sfs
*
**/
EC_BOOL csfs_delete_memc(const UINT32 csfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_delete_memc: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    return csfs_delete_file_memc(csfs_md_id, path);
}

/**
*
*  delete file from memory cache only but NOT sfs
*
**/
EC_BOOL csfs_delete_file_memc(const UINT32 csfs_md_id, const CSTRING *path)
{
    CSFS_MD      *csfs_md;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_delete_file_memc: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(SWITCH_ON == CSFS_MEMC_SWITCH)
    {
        if(EC_TRUE == csfsmc_delete(CSFS_MD_MCACHE(csfs_md), path))
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_delete_file_memc: delete file %s from memcache done\n",
                               (char *)cstring_get_str(path));

            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_delete_file_memc: delete file %s from memcache failed\n",
                               (char *)cstring_get_str(path));
        }
    }
    else
    {
        dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_delete_file_memc: there is no memcache because CSFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE);
}

/**
*
*  retire regular files created before n seconds
*  note:
*    expect_retire_num is for per csfsnp but not all csfsnp(s)
*
**/
EC_BOOL csfs_retire(const UINT32 csfs_md_id, const UINT32 nsec, const UINT32 expect_retire_num, const UINT32 max_step_per_loop, UINT32 *complete_retire_num)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_retire: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_retire: obsolete interface!\n");

    return (EC_FALSE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL csfs_recycle(const UINT32 csfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num)
{
#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_recycle: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_recycle: obsolete interface\n");

    return (EC_FALSE);
}

/**
*
*  set file expired time to current time
*
**/
EC_BOOL csfs_file_expire(const UINT32 csfs_md_id, const CSTRING *path_cstr)
{
    CSFS_MD      *csfs_md;
    CSTRING       key;
    CSTRING       val;

#if ( SWITCH_ON == CSFS_DEBUG_SWITCH )
    if ( CSFS_MD_ID_CHECK_INVALID(csfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csfs_file_expire: csfs module #0x%lx not started.\n",
                csfs_md_id);
        dbg_exit(MD_CSFS, csfs_md_id);
    }
#endif/*CSFS_DEBUG_SWITCH*/

    csfs_md = CSFS_MD_GET(csfs_md_id);

    if(NULL_PTR == CSFS_MD_NPP(csfs_md))
    {
        dbg_log(SEC_0167_CSFS, 1)(LOGSTDOUT, "warn:csfs_file_expire: npp was not open\n");
        return (EC_FALSE);
    }

    cstring_init(&key, (const UINT8 *)"Expires");
    cstring_init(&val, (const UINT8 *)c_http_time(task_brd_default_get_time()));

    if(EC_FALSE == csfs_renew_http_header(csfs_md_id, path_cstr, &key, &val))
    {
        dbg_log(SEC_0167_CSFS, 0)(LOGSTDOUT, "error:csfs_file_expire: expire %s failed\n", (char *)cstring_get_str(path_cstr));
        cstring_clean(&key);
        cstring_clean(&val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0167_CSFS, 9)(LOGSTDOUT, "[DEBUG] csfs_file_expire: expire %s done\n", (char *)cstring_get_str(path_cstr));
    cstring_clean(&key);
    cstring_clean(&val);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
