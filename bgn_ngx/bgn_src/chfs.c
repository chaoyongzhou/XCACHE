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
#include "chfs.h"
#include "chfshttp.h"
#include "chfsmc.h"
#include "cload.h"
#include "cmd5.h"
#include "cbase64code.h"

#include "findex.inc"

#define CHFS_MD_CAPACITY()                  (cbc_md_capacity(MD_CHFS))

#define CHFS_MD_GET(chfs_md_id)     ((CHFS_MD *)cbc_md_get(MD_CHFS, (chfs_md_id)))

#define CHFS_MD_ID_CHECK_INVALID(chfs_md_id)  \
    ((CMPI_ANY_MODI != (chfs_md_id)) && ((NULL_PTR == CHFS_MD_GET(chfs_md_id)) || (0 == (CHFS_MD_GET(chfs_md_id)->usedcounter))))

/**
*
*  delete file data from current dn
*
**/
STATIC_CAST static EC_BOOL __chfs_delete_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode);

/**
*   for test only
*
*   to query the status of CHFS Module
*
**/
void chfs_print_module_status(const UINT32 chfs_md_id, LOG *log)
{
    CHFS_MD *chfs_md;
    UINT32 this_chfs_md_id;

    for( this_chfs_md_id = 0; this_chfs_md_id < CHFS_MD_CAPACITY(); this_chfs_md_id ++ )
    {
        chfs_md = CHFS_MD_GET(this_chfs_md_id);

        if ( NULL_PTR != chfs_md && 0 < chfs_md->usedcounter )
        {
            sys_log(log,"CHFS Module # %ld : %ld refered\n",
                    this_chfs_md_id,
                    chfs_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CHFS module
*
*
**/
UINT32 chfs_free_module_static_mem(const UINT32 chfs_md_id)
{
    CHFS_MD  *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_free_module_static_mem: chfs module #%ld not started.\n",
                chfs_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    free_module_static_mem(MD_CHFS, chfs_md_id);

    return 0;
}

/**
*
* start CHFS module
*
**/
UINT32 chfs_start(const CSTRING *chfsnp_root_basedir, const CSTRING *crfsdn_root_basedir)
{
    CHFS_MD *chfs_md;
    UINT32   chfs_md_id;

    TASK_BRD *task_brd;
    EC_BOOL   ret;

    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CHFS    , 32);

    chfs_md_id = cbc_md_new(MD_CHFS, sizeof(CHFS_MD));
    if(CMPI_ERROR_MODI == chfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CHFS module */
    chfs_md = (CHFS_MD *)cbc_md_get(MD_CHFS, chfs_md_id);
    chfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /*initialize LOCK_REQ file RB TREE*/
    crb_tree_init(CHFS_MD_LOCKED_FILES(chfs_md),
                    (CRB_DATA_CMP)chfs_locked_file_cmp,
                    (CRB_DATA_FREE)chfs_locked_file_free,
                    (CRB_DATA_PRINT)chfs_locked_file_print);

    /*initialize WAIT file RB TREE*/
    crb_tree_init(CHFS_MD_WAIT_FILES(chfs_md),
                    (CRB_DATA_CMP)chfs_wait_file_cmp,
                    (CRB_DATA_FREE)chfs_wait_file_free,
                    (CRB_DATA_PRINT)chfs_wait_file_print);

    CHFS_MD_DN_MOD_MGR(chfs_md)  = mod_mgr_new(chfs_md_id, /*LOAD_BALANCING_LOOP*//*LOAD_BALANCING_MOD*/LOAD_BALANCING_QUE);
    CHFS_MD_NPP_MOD_MGR(chfs_md) = mod_mgr_new(chfs_md_id, /*LOAD_BALANCING_LOOP*//*LOAD_BALANCING_MOD*/LOAD_BALANCING_QUE);

    CHFS_MD_DN(chfs_md)  = NULL_PTR;
    CHFS_MD_NPP(chfs_md) = NULL_PTR;

    ret = EC_TRUE;
    do
    {
        CSTRING *chfsnp_root_dir;
        if(EC_FALSE == ret || NULL_PTR == chfsnp_root_basedir || EC_TRUE == cstring_is_empty(chfsnp_root_basedir))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: ret is false or chfsnp_root_basedir is invalid\n");
            ret = EC_FALSE;
            break;
        }

        chfsnp_root_dir = cstring_make("%s/hfs%02ld", (char *)cstring_get_str(chfsnp_root_basedir), chfs_md_id);
        if(NULL_PTR == chfsnp_root_dir)
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: new chfsnp_root_dir failed\n");
            ret = EC_FALSE;
            break;
        }

        if(EC_FALSE == chfsnp_mgr_exist(chfsnp_root_dir))
        {
            cstring_free(chfsnp_root_dir);
            ret = EC_FALSE;
            break;
        }

        CHFS_MD_NPP(chfs_md) = chfsnp_mgr_open(chfsnp_root_dir);
        if(NULL_PTR == CHFS_MD_NPP(chfs_md))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: open npp from root dir %s failed\n", (char *)cstring_get_str(chfsnp_root_dir));
            cstring_free(chfsnp_root_dir);
            ret = EC_FALSE;
            break;
        }

        cstring_free(chfsnp_root_dir);
    }while(0);

    do
    {
        CSTRING *crfsdn_root_dir;
        if(EC_FALSE == ret || NULL_PTR == crfsdn_root_basedir || EC_TRUE == cstring_is_empty(crfsdn_root_basedir))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: ret is false or crfsdn_root_basedir is invalid\n");
            ret = EC_FALSE;
            break;
        }

        crfsdn_root_dir = cstring_make("%s/hfs%02ld", (char *)cstring_get_str(crfsdn_root_basedir), chfs_md_id);
        if(NULL_PTR == crfsdn_root_dir)
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: new crfsdn_root_dir failed\n");
            ret = EC_FALSE;
            break;
        }

        if(EC_FALSE == crfsdn_exist((char *)cstring_get_str(crfsdn_root_dir)))
        {
            cstring_free(crfsdn_root_dir);
            ret = EC_FALSE;
            break;
        }

        CHFS_MD_DN(chfs_md) = crfsdn_open((char *)cstring_get_str(crfsdn_root_dir));
        if(NULL_PTR == CHFS_MD_DN(chfs_md))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: open dn from root dir %s failed\n", (char *)cstring_get_str(crfsdn_root_dir));
            cstring_free(crfsdn_root_dir);
            ret = EC_FALSE;
            break;
        }

        cstring_free(crfsdn_root_dir);
    }while(0);

    if(SWITCH_ON == CHFS_MEMC_SWITCH && EC_TRUE == ret)
    {
        CHFS_MD_MCACHE(chfs_md) = chfsmc_new(chfs_md_id,
                                             CHFSMC_NP_ID, CHFS_MEMC_NP_MODEL,
                                             CHASH_AP_ALGO_ID,
                                             CHASH_JS_ALGO_ID,
                                             CHFS_MEMC_BUCKET_NUM,
                                             CHFS_MEMC_CPGD_BLOCK_NUM);
        if(NULL_PTR == CHFS_MD_MCACHE(chfs_md))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: new memcache failed\n");
            ret = EC_FALSE;
        }
    }
    else
    {
        CHFS_MD_MCACHE(chfs_md) = NULL_PTR;
    }

    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CHFS_MD_DN(chfs_md))
        {
            crfsdn_close(CHFS_MD_DN(chfs_md));
            CHFS_MD_DN(chfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CHFS_MD_NPP(chfs_md))
        {
            chfsnp_mgr_close(CHFS_MD_NPP(chfs_md));
            CHFS_MD_NPP(chfs_md) = NULL_PTR;
        }

        crb_tree_clean(CHFS_MD_LOCKED_FILES(chfs_md));
        crb_tree_clean(CHFS_MD_WAIT_FILES(chfs_md));

        cbc_md_free(MD_CHFS, chfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    chfs_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)chfs_end, chfs_md_id);

    dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "chfs_start: start CHFS module #%ld\n", chfs_md_id);

    CHFS_INIT_LOCK(chfs_md, LOC_CHFS_0001);

    if(SWITCH_ON == CHFS_DN_DEFER_WRITE_SWITCH && SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    {
        UINT32 core_max_num;
        UINT32 flush_thread_idx;

        CHFS_MD_TERMINATE_FLAG(chfs_md) = EC_FALSE;
        core_max_num = sysconf(_SC_NPROCESSORS_ONLN);

        ASSERT(0 < CHFS_DN_DEFER_WRITE_THREAD_NUM);

        for(flush_thread_idx = 0; flush_thread_idx < CHFS_DN_DEFER_WRITE_THREAD_NUM; flush_thread_idx ++)
        {
            cthread_new(CTHREAD_JOINABLE | CTHREAD_SYSTEM_LEVEL,
                    (const char *)"crfsdn_flush_cache_nodes",
                    (UINT32)crfsdn_flush_cache_nodes,
                    (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                    (UINT32)2,/*para num*/
                    (UINT32)(&(CHFS_MD_DN(chfs_md))),
                    (UINT32)&(CHFS_MD_TERMINATE_FLAG(chfs_md))
                    );
        }
    }

    if(SWITCH_ON == CHFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CHFS module is allowed to launch hfs http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == chfs_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: init chfshttp defer request queue failed\n");
                chfs_end(chfs_md_id);
                return (CMPI_ERROR_MODI);
            }

            chfshttp_log_start();
            task_brd_default_bind_http_srv_modi(chfs_md_id);
            chttp_rest_list_push((const char *)CHFSHTTP_REST_API_NAME, chfshttp_commit_request);
        }

        /*https server*/
#if 0
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled() && 0 == chfs_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_start: init chfshttp defer request queue failed\n");
                chfs_end(chfs_md_id);
                return (CMPI_ERROR_MODI);
            }

            chfshttps_log_start();
            task_brd_default_bind_https_srv_modi(csfs_md_id);
            chttps_rest_list_push((const char *)CHFSHTTPS_REST_API_NAME, chfshttps_commit_request);
        }
#endif

    }
    return ( chfs_md_id );
}

/**
*
* end CHFS module
*
**/
void chfs_end(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)chfs_end, chfs_md_id);

    chfs_md = CHFS_MD_GET(chfs_md_id);
    if(NULL_PTR == chfs_md)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT,"error:chfs_end: chfs_md_id = %ld not exist.\n", chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < chfs_md->usedcounter )
    {
        chfs_md->usedcounter --;
        return ;
    }

    if ( 0 == chfs_md->usedcounter )
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT,"error:chfs_end: chfs_md_id = %ld is not started.\n", chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#if 0
    /*stop server*/
    if(SWITCH_ON == CHFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CHFS module is allowed to launch hfs http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == chfs_md_id)
        {
            task_brd_default_stop_http_srv();
            chttp_defer_request_queue_clean();
        }
    }
#endif
    /* if nobody else occupied the module,then free its resource */
    if(NULL_PTR != CHFS_MD_MCACHE(chfs_md))
    {
        chfsmc_free(CHFS_MD_MCACHE(chfs_md));
        CHFS_MD_MCACHE(chfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CHFS_MD_DN(chfs_md))
    {
        crfsdn_close(CHFS_MD_DN(chfs_md));
        CHFS_MD_DN(chfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CHFS_MD_NPP(chfs_md))
    {
        chfsnp_mgr_close(CHFS_MD_NPP(chfs_md));
        CHFS_MD_NPP(chfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CHFS_MD_DN_MOD_MGR(chfs_md))
    {
        mod_mgr_free(CHFS_MD_DN_MOD_MGR(chfs_md));
        CHFS_MD_DN_MOD_MGR(chfs_md)  = NULL_PTR;
    }

    if(NULL_PTR != CHFS_MD_NPP_MOD_MGR(chfs_md))
    {
        mod_mgr_free(CHFS_MD_NPP_MOD_MGR(chfs_md));
        CHFS_MD_NPP_MOD_MGR(chfs_md)  = NULL_PTR;
    }

    crb_tree_clean(CHFS_MD_LOCKED_FILES(chfs_md));
    crb_tree_clean(CHFS_MD_WAIT_FILES(chfs_md));

    /* free module : */
    //chfs_free_module_static_mem(chfs_md_id);

    chfs_md->usedcounter = 0;
    CHFS_CLEAN_LOCK(chfs_md, LOC_CHFS_0002);

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "chfs_end: stop CHFS module #%ld\n", chfs_md_id);
    cbc_md_free(MD_CHFS, chfs_md_id);

    return ;
}

EC_BOOL chfs_flush(const UINT32 chfs_md_id)
{
    CHFS_MD  *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_flush: chfs module #%ld not started.\n",
                chfs_md_id);
        chfs_print_module_status(chfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(EC_FALSE == chfs_flush_npp(chfs_md_id))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_flush: flush npp failed!\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chfs_flush_dn(chfs_md_id))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_flush: flush dn failed!\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "[DEBUG] chfs_flush: flush done\n");
    return (EC_TRUE);
}


/**
*
* initialize mod mgr of CHFS module
*
**/
UINT32 chfs_set_npp_mod_mgr(const UINT32 chfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CHFS_MD *chfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_set_npp_mod_mgr: chfs module #%ld not started.\n",
                chfs_md_id);
        chfs_print_module_status(chfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    des_mod_mgr = CHFS_MD_NPP_MOD_MGR(chfs_md);

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "chfs_set_npp_mod_mgr: md_id %ld, input src_mod_mgr %p\n", chfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of chfsnp_tcid_vec and chfsnp_tcid_vec*/
    mod_mgr_limited_clone(chfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "====================================chfs_set_npp_mod_mgr: des_mod_mgr %p beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "====================================chfs_set_npp_mod_mgr: des_mod_mgr %p end====================================\n", des_mod_mgr);

    return (0);
}

UINT32 chfs_set_dn_mod_mgr(const UINT32 chfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CHFS_MD *chfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_set_dn_mod_mgr: chfs module #%ld not started.\n",
                chfs_md_id);
        chfs_print_module_status(chfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    des_mod_mgr = CHFS_MD_DN_MOD_MGR(chfs_md);

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "chfs_set_dn_mod_mgr: md_id %ld, input src_mod_mgr %p\n", chfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of chfsnp_tcid_vec and chfsnp_tcid_vec*/
    mod_mgr_limited_clone(chfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "====================================chfs_set_dn_mod_mgr: des_mod_mgr %p beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "====================================chfs_set_dn_mod_mgr: des_mod_mgr %p end====================================\n", des_mod_mgr);

    return (0);
}

/**
*
* get mod mgr of CHFS module
*
**/
MOD_MGR * chfs_get_npp_mod_mgr(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    chfs_md = CHFS_MD_GET(chfs_md_id);
    return CHFS_MD_NPP_MOD_MGR(chfs_md);
}

MOD_MGR * chfs_get_dn_mod_mgr(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    chfs_md = CHFS_MD_GET(chfs_md_id);
    return CHFS_MD_DN_MOD_MGR(chfs_md);
}

CHFSNP_FNODE *chfs_fnode_new(const UINT32 chfs_md_id)
{
    return chfsnp_fnode_new();
}

EC_BOOL chfs_fnode_init(const UINT32 chfs_md_id, CHFSNP_FNODE *chfsnp_fnode)
{
    return chfsnp_fnode_init(chfsnp_fnode);
}

EC_BOOL chfs_fnode_clean(const UINT32 chfs_md_id, CHFSNP_FNODE *chfsnp_fnode)
{
    return chfsnp_fnode_clean(chfsnp_fnode);
}

EC_BOOL chfs_fnode_free(const UINT32 chfs_md_id, CHFSNP_FNODE *chfsnp_fnode)
{
    return chfsnp_fnode_free(chfsnp_fnode);
}

/**
*
*  get name node pool of the module
*
**/
CHFSNP_MGR *chfs_get_npp(const UINT32 chfs_md_id)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_get_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    return CHFS_MD_NPP(chfs_md);
}

/**
*
*  get data node of the module
*
**/
CRFSDN *chfs_get_dn(const UINT32 chfs_md_id)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_get_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    return CHFS_MD_DN(chfs_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL chfs_open_npp(const UINT32 chfs_md_id, const CSTRING *chfsnp_db_root_dir)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_open_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR != CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_open_npp: npp was open\n");
        return (EC_FALSE);
    }

    CHFS_MD_NPP(chfs_md) = chfsnp_mgr_open(chfsnp_db_root_dir);
    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_open_npp: open npp from root dir %s failed\n", (char *)cstring_get_str(chfsnp_db_root_dir));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  close name node pool
*
**/
EC_BOOL chfs_close_npp(const UINT32 chfs_md_id)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_close_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_close_npp: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_close(CHFS_MD_NPP(chfs_md));
    CHFS_MD_NPP(chfs_md) = NULL_PTR;
    return (EC_TRUE);
}

/**
*
*  check this CHFS is name node pool or not
*
*
**/
EC_BOOL chfs_is_npp(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_is_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CHFS is data node or not
*
*
**/
EC_BOOL chfs_is_dn(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_is_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CHFS is data node and namenode or not
*
*
**/
EC_BOOL chfs_is_npp_and_dn(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_is_npp_and_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md) || NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfs_check_is_uint8_t(const UINT32 num)
{
    if(0 == (num >> 8))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __chfs_check_is_uint16_t(const UINT32 num)
{
    if(0 == (num >> 16))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __chfs_check_is_uint32_t(const UINT32 num)
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
EC_BOOL chfs_create_npp(const UINT32 chfs_md_id,
                             const UINT32 chfsnp_model,
                             const UINT32 chfsnp_max_num,
                             const CSTRING *chfsnp_db_root_dir)
{
    CHFS_MD *chfs_md;

    UINT32 chfsnp_1st_chash_algo_id;
    UINT32 chfsnp_2nd_chash_algo_id;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_create_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR != CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_create_npp: npp already exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __chfs_check_is_uint8_t(chfsnp_model))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_create_npp: chfsnp_model %ld is invalid\n", chfsnp_model);
        return (EC_FALSE);
    }

    if(EC_FALSE == __chfs_check_is_uint32_t(chfsnp_max_num))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_create_npp: chfsnp_disk_max_num %ld is invalid\n", chfsnp_max_num);
        return (EC_FALSE);
    }

    chfsnp_1st_chash_algo_id = CHASH_RS_ALGO_ID;
    chfsnp_2nd_chash_algo_id = CHASH_JS_ALGO_ID;

    CHFS_MD_NPP(chfs_md) = chfsnp_mgr_create((uint8_t ) chfsnp_model,
                                             (uint32_t) chfsnp_max_num,
                                             (uint8_t ) chfsnp_1st_chash_algo_id,
                                             (uint8_t ) chfsnp_2nd_chash_algo_id,
                                             chfsnp_db_root_dir);
    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_create_npp: create npp failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfs_add_npp(const UINT32 chfs_md_id, const UINT32 chfsnpp_tcid, const UINT32 chfsnpp_rank)
{
    CHFS_MD   *chfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_add_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, chfsnpp_tcid))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_add_npp: chfsnpp_tcid %s not connected\n", c_word_to_ipv4(chfsnpp_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(chfsnpp_tcid, CMPI_ANY_COMM, chfsnpp_rank, 0, CHFS_MD_NPP_MOD_MGR(chfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), chfsnpp_tcid, chfsnpp_rank, 0);

    return (EC_TRUE);
}

EC_BOOL chfs_add_dn(const UINT32 chfs_md_id, const UINT32 chfsdn_tcid, const UINT32 chfsdn_rank)
{
    CHFS_MD   *chfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_add_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, chfsdn_tcid))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_add_dn: chfsdn_tcid %s not connected\n", c_word_to_ipv4(chfsdn_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(chfsdn_tcid, CMPI_ANY_COMM, chfsdn_rank, (UINT32)0, CHFS_MD_DN_MOD_MGR(chfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), chfsdn_tcid, chfsdn_rank, 0);

    return (EC_TRUE);
}


/**
*
*  check existing of a file
*
**/
EC_BOOL chfs_find_file(const UINT32 chfs_md_id, const CSTRING *file_path)
{
    CHFS_MD   *chfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_find_file: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_find_file: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0003);
    ret = chfsnp_mgr_find(CHFS_MD_NPP(chfs_md), file_path);
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0004);
    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL chfs_find(const UINT32 chfs_md_id, const CSTRING *path)
{
    CHFS_MD   *chfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_find: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_find: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0005);
    ret = chfsnp_mgr_find(CHFS_MD_NPP(chfs_md), path);
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0006);

    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL chfs_exists(const UINT32 chfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_exists: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    return chfs_find(chfs_md_id, path);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL chfs_is_file(const UINT32 chfs_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_is_file: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    return chfs_find_file(chfs_md_id, file_path);;
}

/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __chfs_reserve_hash_dn(const UINT32 chfs_md_id, const UINT32 data_len, const CSTRING *file_path, CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD      *chfs_md;
    CHFSNP_INODE *chfsnp_inode;
    CPGV         *cpgv;

    uint32_t path_hash;
    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__chfs_reserve_hash_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_reserve_hash_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_reserve_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFSDN_CPGV(CHFS_MD_DN(chfs_md)))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_reserve_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cpgv = CRFSDN_CPGV(CHFS_MD_DN(chfs_md));
    if(NULL_PTR == CPGV_HEADER(cpgv))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_reserve_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CPGV_PAGE_DISK_NUM(cpgv))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_reserve_hash_dn: pgv has no disk yet\n");
        return (EC_FALSE);
    }

    /*calculate hash value of file_path*/
    path_hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

    size    = (uint32_t)(data_len);
    disk_no = (uint16_t)(path_hash % CPGV_PAGE_DISK_NUM(cpgv));

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_reserve_hash_dn: disk num %u, path_hash %u => disk_no %u\n",
                CPGV_PAGE_DISK_NUM(cpgv), path_hash, disk_no);

    if(EC_FALSE == cpgv_new_space_from_disk(cpgv, size, disk_no, &block_no, &page_no))
    {
        /*try again*/
        if(EC_FALSE == cpgv_new_space(cpgv, size, &disk_no, &block_no, &page_no))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_reserve_hash_dn: new %ld bytes space from vol failed\n", data_len);
            return (EC_FALSE);
        }
    }

    chfsnp_fnode_init(chfsnp_fnode);
    CHFSNP_FNODE_FILESZ(chfsnp_fnode) = size;
    CHFSNP_FNODE_REPNUM(chfsnp_fnode) = 1;

    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    //CHFSNP_INODE_CACHE_FLAG(chfsnp_inode) = CHFSDN_DATA_NOT_IN_CACHE;
    CHFSNP_INODE_DISK_NO(chfsnp_inode)    = disk_no;
    CHFSNP_INODE_BLOCK_NO(chfsnp_inode)   = block_no;
    CHFSNP_INODE_PAGE_NO(chfsnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL chfs_reserve_dn(const UINT32 chfs_md_id, const UINT32 data_len, CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD      *chfs_md;
    CHFSNP_INODE *chfsnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_reserve_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_reserve_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    if(EC_FALSE == cpgv_new_space(CRFSDN_CPGV(CHFS_MD_DN(chfs_md)), size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_reserve_dn: new %ld bytes space from vol failed\n", data_len);
        return (EC_FALSE);
    }

    chfsnp_fnode_init(chfsnp_fnode);
    CHFSNP_FNODE_FILESZ(chfsnp_fnode) = size;
    CHFSNP_FNODE_REPNUM(chfsnp_fnode) = 1;

    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    CHFSNP_INODE_DISK_NO(chfsnp_inode)    = disk_no;
    CHFSNP_INODE_BLOCK_NO(chfsnp_inode)   = block_no;
    CHFSNP_INODE_PAGE_NO(chfsnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  release space to dn
*
**/
EC_BOOL chfs_release_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD *chfs_md;
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_release_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_release_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < CHFSNP_FNODE_FILESZ(chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_release_dn: CHFSNP_FNODE_FILESZ %u overflow\n", CHFSNP_FNODE_FILESZ(chfsnp_fnode));
        return (EC_FALSE);
    }

    file_size    = CHFSNP_FNODE_FILESZ(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    disk_no  = CHFSNP_INODE_DISK_NO(chfsnp_inode) ;
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    if(EC_FALSE == cpgv_free_space(CRFSDN_CPGV(CHFS_MD_DN(chfs_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_release_dn: free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_release_dn: remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write a file (version 0.2)
*
**/
STATIC_CAST static EC_BOOL __chfs_write(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CHFS_MD      *chfs_md;
    CHFSNP_FNODE  chfsnp_fnode;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__chfs_write: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfsnp_fnode_init(&chfsnp_fnode);

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        chfsnp_fnode_init(&chfsnp_fnode);

        if(do_log(SEC_0023_CHFS, 1))
        {
            sys_log(LOGSTDOUT, "warn:__chfs_write: write file %s with zero len to dn where fnode is \n", (char *)cstring_get_str(file_path));
            chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);
        }

        CHFS_WRLOCK(chfs_md, LOC_CHFS_0016);
        if(EC_FALSE == chfs_write_npp(chfs_md_id, file_path, &chfsnp_fnode))
        {
            CHFS_UNLOCK(chfs_md, LOC_CHFS_0017);
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_write: write file %s to npp failed\n", (char *)cstring_get_str(file_path));

            /*notify all waiters*/
            chfs_file_notify(chfs_md_id, file_path); /*patch*/
            return (EC_FALSE);
        }
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0018);

        /*notify all waiters*/
        chfs_file_notify(chfs_md_id, file_path); /*patch*/

        return (EC_TRUE);
    }

    if(EC_FALSE == __chfs_reserve_hash_dn(chfs_md_id, CBYTES_LEN(cbytes), file_path, &chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_write: reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        chfs_file_notify(chfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    if(EC_FALSE == chfs_export_dn(chfs_md_id, cbytes, &chfsnp_fnode))
    {
        chfs_release_dn(chfs_md_id, &chfsnp_fnode);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_write: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        chfs_file_notify(chfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    if(do_log(SEC_0023_CHFS, 9))
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_write: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDNULL, "[DEBUG] __chfs_write: write file %s is %.*s\n",
                        (char *)cstring_get_str(file_path), (uint32_t)DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0019);
    if(EC_FALSE == chfs_write_npp(chfs_md_id, file_path, &chfsnp_fnode))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0020);
        chfs_release_dn(chfs_md_id, &chfsnp_fnode);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_write: write file %s to npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        chfs_file_notify(chfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0021);

    /*notify all waiters*/
    chfs_file_notify(chfs_md_id, file_path); /*patch*/

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfs_write_cache(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CHFS_MD      *chfs_md;
    CHFSNP_FNODE  chfsnp_fnode;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__chfs_write_cache: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfsnp_fnode_init(&chfsnp_fnode);

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0022);

    if(EC_FALSE == chfs_write_dn_cache(chfs_md_id, cbytes, &chfsnp_fnode))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0023);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_write_cache: write file %s content to dn failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_write_cache: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
    chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDNULL, "[DEBUG] __chfs_write_cache: write file %s is %.*s\n", (char *)cstring_get_str(file_path), (uint32_t)DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));

    if(EC_FALSE == chfs_write_npp(chfs_md_id, file_path, &chfsnp_fnode))
    {
        __chfs_delete_dn(chfs_md_id, &chfsnp_fnode);
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0024);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_write_cache: write file %s to npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    CHFS_UNLOCK(chfs_md, LOC_CHFS_0025);
    return (EC_TRUE);
}

EC_BOOL chfs_write(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    if(SWITCH_ON == CHFS_DN_DEFER_WRITE_SWITCH)
    {
        return __chfs_write_cache(chfs_md_id, file_path, cbytes);
    }
    return __chfs_write(chfs_md_id, file_path, cbytes);
}

/**
*
*  read a file
*
**/
EC_BOOL chfs_read(const UINT32 chfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CHFS_MD      *chfs_md;
    CHFSNP_FNODE  chfsnp_fnode;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_read: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfsnp_fnode_init(&chfsnp_fnode);

    chfs_md = CHFS_MD_GET(chfs_md_id);

    CHFS_RDLOCK(chfs_md, LOC_CHFS_0026);
    if(EC_FALSE == chfs_read_npp(chfs_md_id, file_path, &chfsnp_fnode))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0027);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0023_CHFS, 9))
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_read: read file %s from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &chfsnp_fnode);
        chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);
    }

    if(EC_FALSE == chfs_read_dn(chfs_md_id, &chfsnp_fnode, cbytes))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0028);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read: read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
        chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0029);

    return (EC_TRUE);
}


/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL chfs_read_e(const UINT32 chfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CHFS_MD      *chfs_md;
    CHFSNP_FNODE  chfsnp_fnode;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_read_e: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfsnp_fnode_init(&chfsnp_fnode);
#if 0
    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        UINT32 offset_t;

        offset_t = (*offset);
        if(EC_TRUE == chfsmc_read_e(CHFS_MD_MCACHE(chfs_md), file_path, offset, max_len, cbytes))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_read_e: read file %s at offset %ld and max len %ld with size %ld from memcache done\n",
                               (char *)cstring_get_str(file_path), offset_t, max_len, cbytes_len(cbytes));
            return (EC_TRUE);
        }
    }
#endif
    CHFS_RDLOCK(chfs_md, LOC_CHFS_0030);

    if(EC_FALSE == chfs_read_npp(chfs_md_id, file_path, &chfsnp_fnode))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0031);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0023_CHFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chfs_read_e: read file %s from npp and fnode %p is \n",
                           (char *)cstring_get_str(file_path),
                           &chfsnp_fnode);
        chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);
    }

    /*exception*/
    if(0 == CHFSNP_FNODE_FILESZ(&chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_read_e: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &chfsnp_fnode);
        chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == chfs_read_e_dn(chfs_md_id, &chfsnp_fnode, offset, max_len, cbytes))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0032);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_e: offset read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
        chfsnp_fnode_print(LOGSTDOUT, &chfsnp_fnode);
        return (EC_FALSE);
    }

    CHFS_UNLOCK(chfs_md, LOC_CHFS_0033);
    return (EC_TRUE);
}

/**
*
*  update a file
*  (atomic operation)
*
**/
EC_BOOL chfs_update(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_update: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
#if 0
    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        if(EC_TRUE == chfsmc_update(CHFS_MD_MCACHE(chfs_md), file_path, cbytes, NULL_PTR))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update: update file %s with size %ld to memcache done\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        }
    }
#endif
    CHFS_WRLOCK(chfs_md, LOC_CHFS_0034);
    if(EC_FALSE == chfs_update_no_lock(chfs_md_id, file_path, cbytes))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0035);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_update: update file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0036);
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update: update file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL chfs_update_no_lock(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_update_no_lock: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(EC_FALSE == chfs_read_npp(chfs_md_id, file_path, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == chfs_write(chfs_md_id, file_path, cbytes))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_update_no_lock: write file %s failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update_no_lock: write file %s done\n", (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }


    /*file exist, update it*/
    if(EC_FALSE == chfs_delete(chfs_md_id, file_path))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_update_no_lock: delete old file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update_no_lock: delete old file %s done\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == chfs_write(chfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_update_no_lock: write new file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update_no_lock: write new file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL chfs_renew_http_header(const UINT32 chfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    char         *v;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_renew_http_header: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == chfs_read(chfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);

        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_header: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == chfs_update(chfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_header: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_renew_http_header: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));


    /*notify all waiters*/
    chfs_file_notify(chfs_md_id, file_path);
    return (EC_TRUE);
}

EC_BOOL chfs_renew_http_headers(const UINT32 chfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_renew_http_headers: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == chfs_read(chfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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

        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_renew_http_headers: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    cbytes_clean(&cbytes);
    if(EC_FALSE == chttp_rsp_encode(&chttp_rsp, &cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_headers: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == chfs_update(chfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_renew_http_headers: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_renew_http_headers: '%s' renew headers done\n",
                (char *)CSTRING_STR(file_path));

    /*notify all waiters*/
    chfs_file_notify(chfs_md_id, file_path);

    return (EC_TRUE);
}

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL chfs_wait_http_header(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_wait_http_header: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == chfs_read(chfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_wait_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_wait_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_wait_http_header: '%s' wait header '%s':'%s' => ready\n",
                    (char *)CSTRING_STR(file_path),
                    (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

        return (EC_TRUE);
    }

    if(EC_FALSE == chfs_file_wait(chfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_wait_http_header: '%s' wait header '%s':'%s' => OK\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

    return (EC_TRUE);
}

EC_BOOL chfs_wait_http_headers(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_wait_http_headers: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == chfs_read(chfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_wait_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_wait_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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

        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_wait_http_headers: '%s' wait '%s':'%s' done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    chttp_rsp_clean(&chttp_rsp);

    if(EC_TRUE == (*header_ready))
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_wait_http_headers: '%s' headers => ready\n",
                (char *)CSTRING_STR(file_path));

        return (EC_TRUE);
    }

    if(EC_FALSE == chfs_file_wait(chfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_wait_http_headers: '%s' wait headers => OK\n",
                (char *)CSTRING_STR(file_path));

    return (EC_TRUE);
}


/*------------------------------------------------ interface for file wait ------------------------------------------------*/
CHFS_WAIT_FILE *chfs_wait_file_new()
{
    CHFS_WAIT_FILE *chfs_wait_file;
    alloc_static_mem(MM_CHFS_WAIT_FILE, &chfs_wait_file, LOC_CHFS_0037);
    if(NULL_PTR != chfs_wait_file)
    {
        chfs_wait_file_init(chfs_wait_file);
    }
    return (chfs_wait_file);
}

EC_BOOL chfs_wait_file_init(CHFS_WAIT_FILE *chfs_wait_file)
{
    cstring_init(CHFS_WAIT_FILE_NAME(chfs_wait_file), NULL_PTR);

    clist_init(CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file), MM_MOD_NODE, LOC_CHFS_0038);

    return (EC_TRUE);
}

EC_BOOL chfs_wait_file_clean(CHFS_WAIT_FILE *chfs_wait_file)
{
    cstring_clean(CHFS_WAIT_FILE_NAME(chfs_wait_file));
    clist_clean(CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file), (CLIST_DATA_DATA_CLEANER)mod_node_free);
    return (EC_TRUE);
}

EC_BOOL chfs_wait_file_free(CHFS_WAIT_FILE *chfs_wait_file)
{
    if(NULL_PTR != chfs_wait_file)
    {
        chfs_wait_file_clean(chfs_wait_file);
        free_static_mem(MM_CHFS_WAIT_FILE, chfs_wait_file, LOC_CHFS_0039);
    }
    return (EC_TRUE);
}

EC_BOOL chfs_wait_file_init_0(const UINT32 md_id, CHFS_WAIT_FILE *chfs_wait_file)
{
    return chfs_wait_file_init(chfs_wait_file);
}

EC_BOOL chfs_wait_file_clean_0(const UINT32 md_id, CHFS_WAIT_FILE *chfs_wait_file)
{
    return chfs_wait_file_clean(chfs_wait_file);
}

EC_BOOL chfs_wait_file_free_0(const UINT32 md_id, CHFS_WAIT_FILE *chfs_wait_file)
{
    if(NULL_PTR != chfs_wait_file)
    {
        chfs_wait_file_clean(chfs_wait_file);
        free_static_mem(MM_CHFS_WAIT_FILE, chfs_wait_file, LOC_CHFS_0040);
    }
    return (EC_TRUE);
}

int chfs_wait_file_cmp(const CHFS_WAIT_FILE *chfs_wait_file_1st, const CHFS_WAIT_FILE *chfs_wait_file_2nd)
{
    return cstring_cmp(CHFS_WAIT_FILE_NAME(chfs_wait_file_1st), CHFS_WAIT_FILE_NAME(chfs_wait_file_2nd));
}

void chfs_wait_file_print(LOG *log, const CHFS_WAIT_FILE *chfs_wait_file)
{
    if(NULL_PTR != chfs_wait_file)
    {
        sys_log(log, "chfs_wait_file_print %p: file %s, owner list: ",
                        chfs_wait_file,
                        (char *)CHFS_WAIT_FILE_NAME_STR(chfs_wait_file)
                        );
        clist_print(log, CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file),(CLIST_DATA_DATA_PRINT)mod_node_print);
    }

    return;
}

void chfs_wait_files_print(const UINT32 chfs_md_id, LOG *log)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_wait_files_print: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    crb_tree_print(log, CHFS_MD_WAIT_FILES(chfs_md));

    return;
}

EC_BOOL chfs_wait_file_name_set(CHFS_WAIT_FILE *chfs_wait_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CHFS_WAIT_FILE_NAME(chfs_wait_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfs_wait_file_owner_cmp(const MOD_NODE *mod_node, const UINT32 tcid)
{
    if(MOD_NODE_TCID(mod_node) == tcid)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chfs_wait_file_owner_push(CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tcid)
{
    CLIST *owner_list;

    owner_list = CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file);
    if(
       CMPI_ERROR_TCID != tcid
    && CMPI_ANY_TCID != tcid
    && NULL_PTR == clist_search_data_front(owner_list, (void *)tcid, (CLIST_DATA_DATA_CMP)__chfs_wait_file_owner_cmp)
    )
    {
        MOD_NODE *mod_node;

        mod_node = mod_node_new();
        if(NULL_PTR == mod_node)
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_wait_file_owner_push: new mod_node failed\n");
            return (EC_FALSE);
        }

        MOD_NODE_TCID(mod_node) = tcid;
        MOD_NODE_COMM(mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(mod_node) = 0;/*SUPER modi always be 0*/

        clist_push_back(owner_list, (void *)mod_node);

        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_wait_file_owner_push: push %s to file '%.*s'\n",
                    c_word_to_ipv4(tcid), (uint32_t)CHFS_WAIT_FILE_NAME_LEN(chfs_wait_file), CHFS_WAIT_FILE_NAME_STR(chfs_wait_file));
    }

    return (EC_TRUE);
}

/**
*
*  wakeup remote waiter (over http)
*
**/
EC_BOOL chfs_wait_file_owner_wakeup (const UINT32 chfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    CHFS_MD     *chfs_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_wait_file_owner_wakeup: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)"/cond_wakeup");
    cstring_append_cstr(uri, path);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_wait_file_owner_wakeup: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "[DEBUG] chfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL chfs_wait_file_owner_notify_over_http (CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file)))
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
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one chfs module*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE   *mod_node;
            TASKS_CFG  *remote_tasks_cfg;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), MOD_NODE_TCID(mod_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "info:chfs_wait_file_owner_notify: not found tasks_cfg of node %s\n", c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
                mod_node_free(mod_node);
                continue;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, &recv_mod_node,
                        &ret,
                        FI_chfs_wait_file_owner_wakeup,
                        CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                        TASKS_CFG_CSRVPORT(remote_tasks_cfg),
                        CHFS_WAIT_FILE_NAME(chfs_wait_file));

            dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] chfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CHFS_WAIT_FILE_NAME_STR(chfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] chfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CHFS_WAIT_FILE_NAME_STR(chfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL chfs_wait_file_owner_notify_over_bgn (CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file)))
    {
        TASK_MGR *task_mgr;
        EC_BOOL   ret; /*ignore it*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE *mod_node;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CHFS_WAIT_FILE_OWNER_LIST(chfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node, &ret, FI_super_cond_wakeup, CMPI_ERROR_MODI, tag, CHFS_WAIT_FILE_NAME(chfs_wait_file));

            dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] chfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CHFS_WAIT_FILE_NAME_STR(chfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] chfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CHFS_WAIT_FILE_NAME_STR(chfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL chfs_wait_file_owner_notify(CHFS_WAIT_FILE *chfs_wait_file, const UINT32 tag)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return chfs_wait_file_owner_notify_over_http(chfs_wait_file, tag);
    }

    return chfs_wait_file_owner_notify_over_bgn(chfs_wait_file, tag);
}

STATIC_CAST static EC_BOOL __chfs_file_wait(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path)
{
    CHFS_MD          *chfs_md;

    CRB_NODE         *crb_node;
    CHFS_WAIT_FILE   *chfs_wait_file;

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfs_wait_file = chfs_wait_file_new();
    if(NULL_PTR == chfs_wait_file)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_file_wait: new chfs_wait_file failed\n");
        return (EC_FALSE);
    }

    chfs_wait_file_name_set(chfs_wait_file, file_path);

    crb_node = crb_tree_insert_data(CHFS_MD_WAIT_FILES(chfs_md), (void *)chfs_wait_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_file_wait: insert file %s to wait files tree failed\n",
                                (char *)cstring_get_str(file_path));
        chfs_wait_file_free(chfs_wait_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != chfs_wait_file)/*found duplicate*/
    {
        CHFS_WAIT_FILE *chfs_wait_file_duplicate;

        chfs_wait_file_duplicate = (CHFS_WAIT_FILE *)CRB_NODE_DATA(crb_node);

        chfs_wait_file_free(chfs_wait_file); /*no useful*/

        /*when found the file had been wait, register remote owner to it*/
        chfs_wait_file_owner_push(chfs_wait_file_duplicate, tcid);

        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_file_wait: push %s to duplicated file '%s' in wait files tree done\n",
                            c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*register remote token owner to it*/
    chfs_wait_file_owner_push(chfs_wait_file, tcid);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_file_wait: push %s to inserted file %s in wait files tree done\n",
                        c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL chfs_file_wait(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_wait: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == chfs_read(chfs_md_id, file_path, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __chfs_file_wait(chfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfs_file_wait_e(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_wait: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == chfs_read_e(chfs_md_id, file_path, offset, max_len, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __chfs_file_wait(chfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*notify all waiters*/
EC_BOOL chfs_file_notify(const UINT32 chfs_md_id, const CSTRING *file_path)
{
    CHFS_MD          *chfs_md;

    CHFS_WAIT_FILE   *chfs_wait_file;
    CHFS_WAIT_FILE   *chfs_wait_file_found;
    CRB_NODE         *crb_node;
    UINT32            tag;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_notify: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfs_wait_file = chfs_wait_file_new();
    if(NULL_PTR == chfs_wait_file)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_file_notify: new chfs_wait_file failed\n");
        return (EC_FALSE);
    }

    chfs_wait_file_name_set(chfs_wait_file, file_path);

    crb_node = crb_tree_search_data(CHFS_MD_WAIT_FILES(chfs_md), (void *)chfs_wait_file);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_file_notify: not found waiters of file '%s'\n",
                        (char *)CSTRING_STR(file_path));
        chfs_wait_file_free(chfs_wait_file);
        return (EC_TRUE);
    }

    chfs_wait_file_free(chfs_wait_file);

    chfs_wait_file_found = CRB_NODE_DATA(crb_node);
    tag = MD_CHFS;

    if(EC_FALSE == chfs_wait_file_owner_notify (chfs_wait_file_found, tag))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_file_notify: notify waiters of file '%s' failed\n",
                        (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    crb_tree_delete(CHFS_MD_WAIT_FILES(chfs_md), crb_node);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_file_notify: notify waiters of file '%s' done\n",
                    (char *)CSTRING_STR(file_path));
    return (EC_TRUE);
}

/*------------------------------------------------ interface for file lock ------------------------------------------------*/
CHFS_LOCKED_FILE *chfs_locked_file_new()
{
    CHFS_LOCKED_FILE *chfs_locked_file;
    alloc_static_mem(MM_CHFS_LOCKED_FILE, &chfs_locked_file, LOC_CHFS_0041);
    if(NULL_PTR != chfs_locked_file)
    {
        chfs_locked_file_init(chfs_locked_file);
    }
    return (chfs_locked_file);
}

EC_BOOL chfs_locked_file_init(CHFS_LOCKED_FILE *chfs_locked_file)
{
    cstring_init(CHFS_LOCKED_FILE_NAME(chfs_locked_file), NULL_PTR);
    cbytes_init(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file));

    CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL chfs_locked_file_clean(CHFS_LOCKED_FILE *chfs_locked_file)
{
    cstring_clean(CHFS_LOCKED_FILE_NAME(chfs_locked_file));
    cbytes_clean(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file));

    CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL chfs_locked_file_free(CHFS_LOCKED_FILE *chfs_locked_file)
{
    if(NULL_PTR != chfs_locked_file)
    {
        chfs_locked_file_clean(chfs_locked_file);
        free_static_mem(MM_CHFS_LOCKED_FILE, chfs_locked_file, LOC_CHFS_0042);
    }
    return (EC_TRUE);
}

EC_BOOL chfs_locked_file_init_0(const UINT32 md_id, CHFS_LOCKED_FILE *chfs_locked_file)
{
    return chfs_locked_file_init(chfs_locked_file);
}

EC_BOOL chfs_locked_file_clean_0(const UINT32 md_id, CHFS_LOCKED_FILE *chfs_locked_file)
{
    return chfs_locked_file_clean(chfs_locked_file);
}

EC_BOOL chfs_locked_file_free_0(const UINT32 md_id, CHFS_LOCKED_FILE *chfs_locked_file)
{
    if(NULL_PTR != chfs_locked_file)
    {
        chfs_locked_file_clean(chfs_locked_file);
        free_static_mem(MM_CHFS_LOCKED_FILE, chfs_locked_file, LOC_CHFS_0043);
    }
    return (EC_TRUE);
}

int chfs_locked_file_cmp(const CHFS_LOCKED_FILE *chfs_locked_file_1st, const CHFS_LOCKED_FILE *chfs_locked_file_2nd)
{
    return cstring_cmp(CHFS_LOCKED_FILE_NAME(chfs_locked_file_1st), CHFS_LOCKED_FILE_NAME(chfs_locked_file_2nd));
}

void chfs_locked_file_print(LOG *log, const CHFS_LOCKED_FILE *chfs_locked_file)
{
    if(NULL_PTR != chfs_locked_file)
    {
        sys_log(log, "chfs_locked_file_print %p: file %s, expire %ld seconds\n",
                        chfs_locked_file,
                        (char *)CHFS_LOCKED_FILE_NAME_STR(chfs_locked_file),
                        CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file)
                        );
        sys_log(log, "chfs_locked_file_print %p: file %s, token ",
                        chfs_locked_file,
                        (char *)CHFS_LOCKED_FILE_NAME_STR(chfs_locked_file)
                        );
        cbytes_print_chars(log, CHFS_LOCKED_FILE_TOKEN(chfs_locked_file));

        sys_log(log, "chfs_locked_file_print %p: file %s\n",
                        chfs_locked_file,
                        (char *)CHFS_LOCKED_FILE_NAME_STR(chfs_locked_file)
                        );
    }

    return;
}

void chfs_locked_files_print(const UINT32 chfs_md_id, LOG *log)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_locked_files_print: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    crb_tree_print(log, CHFS_MD_LOCKED_FILES(chfs_md));

    return;
}

/*generate token from file_path with time as random*/
EC_BOOL chfs_locked_file_token_gen(CHFS_LOCKED_FILE *chfs_locked_file, const CSTRING *file_name)
{
    uint8_t  digest[ CMD5_DIGEST_LEN ];
    CSTRING  cstr;

    cstring_init(&cstr, cstring_get_str(file_name));

    cstring_append_str(&cstr, (const UINT8 *)TASK_BRD_TIME_STR(task_brd_default_get()));

    cmd5_sum(cstring_get_len(&cstr), cstring_get_str(&cstr), digest);
    cstring_clean(&cstr);

    cbytes_set(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file), (const UINT8 *)digest, CMD5_DIGEST_LEN);

    return (EC_TRUE);
}

EC_BOOL chfs_locked_file_expire_set(CHFS_LOCKED_FILE *chfs_locked_file, const UINT32 expire_nsec)
{
    CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file) = expire_nsec;

    CTIMET_GET(CHFS_LOCKED_FILE_START_TIME(chfs_locked_file));
    CTIMET_GET(CHFS_LOCKED_FILE_LAST_TIME(chfs_locked_file));

    return (EC_TRUE);
}

EC_BOOL chfs_locked_file_is_expire(const CHFS_LOCKED_FILE *chfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CHFS_LOCKED_FILE_LAST_TIME(chfs_locked_file), cur_time);
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_locked_file_is_expire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file));
    if(diff_nsec >= 0.0 + CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL chfs_locked_file_name_set(CHFS_LOCKED_FILE *chfs_locked_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CHFS_LOCKED_FILE_NAME(chfs_locked_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfs_locked_file_need_retire(const CHFS_LOCKED_FILE *chfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CHFS_LOCKED_FILE_LAST_TIME(chfs_locked_file), cur_time);
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_locked_file_need_retire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file));
    if(diff_nsec >= 0.0 + 2 * CHFS_LOCKED_FILE_EXPIRE_NSEC(chfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __chfs_locked_file_retire(CRB_TREE *crbtree, const CRB_NODE *node)
{
    CHFS_LOCKED_FILE *chfs_locked_file;

    if(NULL_PTR == node)
    {
        return (EC_FALSE);
    }

    chfs_locked_file = CRB_NODE_DATA(node);
    if(EC_TRUE == __chfs_locked_file_need_retire(chfs_locked_file))
    {
        dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] __chfs_locked_file_retire: file %s was retired\n",
                            (char *)cstring_get_str(CHFS_LOCKED_FILE_NAME(chfs_locked_file)));

        crb_tree_delete(crbtree, (CRB_NODE *)node);
        return (EC_TRUE);/*succ and terminate*/
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_TRUE == __chfs_locked_file_retire(crbtree, CRB_NODE_LEFT(node)))
        {
            return (EC_TRUE);
        }
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_TRUE == __chfs_locked_file_retire(crbtree, CRB_NODE_RIGHT(node)))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*retire the expired locked files over 120 seconds which are garbage*/
EC_BOOL chfs_locked_file_retire(const UINT32 chfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num)
{
    CHFS_MD      *chfs_md;
    CRB_TREE     *crbtree;
    UINT32        retire_idx;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_locked_file_retire: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    crbtree = CHFS_MD_LOCKED_FILES(chfs_md);

    for(retire_idx = 0; retire_idx < retire_max_num; retire_idx ++)
    {
        if(EC_FALSE == __chfs_locked_file_retire(crbtree, CRB_TREE_ROOT(crbtree)))
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

STATIC_CAST static EC_BOOL __chfs_file_lock(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CBYTES *token, UINT32 *locked_already)
{
    CHFS_MD          *chfs_md;

    CRB_NODE         *crb_node;
    CHFS_LOCKED_FILE *chfs_locked_file;

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfs_locked_file = chfs_locked_file_new();
    if(NULL_PTR == chfs_locked_file)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_file_lock: new chfs_locked_file failed\n");
        return (EC_FALSE);
    }

    chfs_locked_file_name_set(chfs_locked_file, file_path);
    chfs_locked_file_token_gen(chfs_locked_file, file_path);/*generate token from file_path with time as random*/
    chfs_locked_file_expire_set(chfs_locked_file, expire_nsec);

    crb_node = crb_tree_insert_data(CHFS_MD_LOCKED_FILES(chfs_md), (void *)chfs_locked_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_file_lock: insert file %s to locked files tree failed\n",
                                (char *)cstring_get_str(file_path));
        chfs_locked_file_free(chfs_locked_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != chfs_locked_file)/*found duplicate*/
    {
        CHFS_LOCKED_FILE *chfs_locked_file_duplicate;

        chfs_locked_file_duplicate = (CHFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node);

        if(EC_FALSE == chfs_locked_file_is_expire(chfs_locked_file_duplicate))
        {
            dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] __chfs_file_lock: file %s already in locked files tree\n",
                                (char *)cstring_get_str(file_path));

            chfs_locked_file_free(chfs_locked_file); /*no useful*/

            (*locked_already) = EC_TRUE;/*means file had been locked by someone else*/
            return (EC_FALSE);
        }

        CRB_NODE_DATA(crb_node) = chfs_locked_file; /*mount new*/

        chfs_locked_file_free(chfs_locked_file_duplicate); /*free the duplicate which is also old*/

        cbytes_clone(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file), token);

        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_file_lock: update file %s to locked files tree done\n",
                            (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*now chfs_locked_file_tmp already insert and mount into tree*/
    cbytes_clone(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file), token);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_file_lock: insert file %s to locked files tree done\n",
                        (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL chfs_file_lock(const UINT32 chfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already)
{
    CHFS_MD      *chfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_lock: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    cbytes_init(&token_cbyte);

    CHFS_LOCKED_FILES_WRLOCK(chfs_md, LOC_CHFS_0044);
    if(EC_FALSE == __chfs_file_lock(chfs_md_id, tcid, file_path, expire_nsec, &token_cbyte, locked_already))
    {
        CHFS_LOCKED_FILES_UNLOCK(chfs_md, LOC_CHFS_0045);
        return (EC_FALSE);
    }

    CHFS_LOCKED_FILES_UNLOCK(chfs_md, LOC_CHFS_0046);

    cbase64_encode(CBYTES_BUF(&token_cbyte), CBYTES_LEN(&token_cbyte), auth_token, sizeof(auth_token), &auth_token_len);
    cstring_append_chars(token_str, auth_token_len, auth_token, LOC_CHFS_0047);
    cbytes_clean(&token_cbyte);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfs_file_unlock(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *token)
{
    CHFS_MD          *chfs_md;

    CRB_NODE         *crb_node_searched;

    CHFS_LOCKED_FILE *chfs_locked_file_tmp;
    CHFS_LOCKED_FILE *chfs_locked_file_searched;

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfs_locked_file_tmp = chfs_locked_file_new();
    if(NULL_PTR == chfs_locked_file_tmp)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_file_unlock: new CHFS_LOCKED_FILE failed\n");
        return (EC_FALSE);
    }

    chfs_locked_file_name_set(chfs_locked_file_tmp, file_path);

    crb_node_searched = crb_tree_search_data(CHFS_MD_LOCKED_FILES(chfs_md), (void *)chfs_locked_file_tmp);/*compare name*/
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] __chfs_file_unlock: file %s not in locked files tree\n",
                                (char *)cstring_get_str(file_path));
        chfs_locked_file_free(chfs_locked_file_tmp);
        return (EC_FALSE);
    }

    chfs_locked_file_free(chfs_locked_file_tmp); /*no useful*/

    chfs_locked_file_searched = (CHFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node_searched);

    /*if expired already, remove it as garbage, despite of token comparsion*/
    if(EC_TRUE == chfs_locked_file_is_expire(chfs_locked_file_searched))
    {
        crb_tree_delete(CHFS_MD_LOCKED_FILES(chfs_md), crb_node_searched);
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "info:__chfs_file_unlock: remove expired locked file %s\n",
                        (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*if exist, compare token. if not exist, unlock by force!*/
    if(NULL_PTR != token && EC_FALSE == cbytes_cmp(CHFS_LOCKED_FILE_TOKEN(chfs_locked_file_searched), token))
    {
        if(do_log(SEC_0023_CHFS, 9))
        {
            sys_log(LOGSTDOUT, "warn:__chfs_file_unlock: file %s, searched token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, CHFS_LOCKED_FILE_TOKEN(chfs_locked_file_searched));

            sys_log(LOGSTDOUT, "warn:__chfs_file_unlock: file %s, but input token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, token);
        }
        return (EC_FALSE);
    }

    if(do_log(SEC_0023_CHFS, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __chfs_file_unlock: file %s notify ...\n",
                                (char *)cstring_get_str(file_path));

        sys_log(LOGSTDOUT, "[DEBUG] __chfs_file_unlock: searched file:\n");
        chfs_locked_file_print(LOGSTDOUT, chfs_locked_file_searched);
    }

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] __chfs_file_unlock: file %s notify ... done\n",
                            (char *)cstring_get_str(file_path));

    crb_tree_delete(CHFS_MD_LOCKED_FILES(chfs_md), crb_node_searched);

    dbg_log(SEC_0023_CHFS, 5)(LOGSTDOUT, "[DEBUG] __chfs_file_unlock: file %s unlocked\n",
                            (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL chfs_file_unlock(const UINT32 chfs_md_id, const CSTRING *file_path, const CSTRING *token_str)
{
    CHFS_MD      *chfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_unlock: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    cbase64_decode((UINT8 *)CSTRING_STR(token_str), CSTRING_LEN(token_str), auth_token, sizeof(auth_token), &auth_token_len);
    cbytes_mount(&token_cbyte, auth_token_len, auth_token);
#if 0
    if(do_log(SEC_0023_CHFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chfs_file_unlock: auth_token str: %.*s\n", (uint32_t)CSTRING_LEN(token_str), CSTRING_STR(token_str));
        sys_log(LOGSTDOUT, "[DEBUG] chfs_file_unlock: auth_token str => token: ");
        cbytes_print_chars(LOGSTDOUT, &token_cbyte);

        sys_log(LOGSTDOUT, "[DEBUG] chfs_file_unlock: all locked files are: \n");
        chfs_locked_files_print(chfs_md_id, LOGSTDOUT);
    }
#endif
    CHFS_LOCKED_FILES_WRLOCK(chfs_md, LOC_CHFS_0048);
    if(EC_FALSE == __chfs_file_unlock(chfs_md_id, file_path, &token_cbyte))
    {
        cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
        CHFS_LOCKED_FILES_UNLOCK(chfs_md, LOC_CHFS_0049);
        return (EC_FALSE);
    }

    CHFS_LOCKED_FILES_UNLOCK(chfs_md, LOC_CHFS_0050);

    cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
    return (EC_TRUE);
}


/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL chfs_file_unlock_notify(const UINT32 chfs_md_id, const CSTRING *file_path)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_unlock_notify: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_file_unlock_notify: obsolete interface!!!!\n");

    return (EC_FALSE);
}

/**
*
*   load file from HFS to memcache
*
**/
EC_BOOL chfs_cache_file(const UINT32 chfs_md_id, const CSTRING *path)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_cache_file: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        CBYTES cbytes;

        cbytes_init(&cbytes);

        if(EC_FALSE == chfs_read(chfs_md_id, path, &cbytes))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_cache_file: read file %s from hfs failed\n",
                                   (char *)cstring_get_str(path));
            cbytes_clean(&cbytes);
            return (EC_FALSE);
        }
#if 0
        if(EC_FALSE == chfsmc_update(CHFS_MD_MCACHE(chfs_md), path, &cbytes, NULL_PTR))
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_cache_file: update file %s to memcache failed\n",
                                   (char *)cstring_get_str(path));
            cbytes_clean(&cbytes);
            return (EC_FALSE);
        }
#endif
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_cache_file: cache file %s done\n",
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
EC_BOOL chfs_create_dn(const UINT32 chfs_md_id, const CSTRING *root_dir)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_create_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    if(NULL_PTR != CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_create_dn: dn already exist\n");
        return (EC_FALSE);
    }

    CHFS_MD_DN(chfs_md) = crfsdn_create((char *)cstring_get_str(root_dir));
    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_create_dn: create dn failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  add a disk to data node
*
**/
EC_BOOL chfs_add_disk(const UINT32 chfs_md_id, const UINT32 disk_no)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_add_disk: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_add_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_add_disk: disk_no %ld is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0051);
    if(EC_FALSE == crfsdn_add_disk(CHFS_MD_DN(chfs_md), (uint16_t)disk_no))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0052);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_add_disk: add disk %ld to dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0053);
    return (EC_TRUE);
}

/**
*
*  delete a disk from data node
*
**/
EC_BOOL chfs_del_disk(const UINT32 chfs_md_id, const UINT32 disk_no)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_del_disk: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_del_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_del_disk: disk_no %ld is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0054);
    if(EC_FALSE == crfsdn_del_disk(CHFS_MD_DN(chfs_md), (uint16_t)disk_no))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0055);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_del_disk: del disk %ld from dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0056);
    return (EC_TRUE);
}

/**
*
*  mount a disk to data node
*
**/
EC_BOOL chfs_mount_disk(const UINT32 chfs_md_id, const UINT32 disk_no)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_mount_disk: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_mount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_mount_disk: disk_no %ld is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0057);
    if(EC_FALSE == crfsdn_mount_disk(CHFS_MD_DN(chfs_md), (uint16_t)disk_no))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0058);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_mount_disk: mount disk %ld to dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0059);
    return (EC_TRUE);
}

/**
*
*  umount a disk from data node
*
**/
EC_BOOL chfs_umount_disk(const UINT32 chfs_md_id, const UINT32 disk_no)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_umount_disk: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);
    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_umount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_umount_disk: disk_no %ld is invalid\n", disk_no);
        return (EC_FALSE);
    }

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0060);
    if(EC_FALSE == crfsdn_umount_disk(CHFS_MD_DN(chfs_md), (uint16_t)disk_no))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0061);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_umount_disk: umount disk %ld from dn failed\n", disk_no);
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0062);
    return (EC_TRUE);
}


/**
*
*  open data node
*
**/
EC_BOOL chfs_open_dn(const UINT32 chfs_md_id, const CSTRING *root_dir)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_open_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_open_dn: try to open dn %s  ...\n", (char *)cstring_get_str(root_dir));

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR != CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_open_dn: dn was open\n");
        return (EC_FALSE);
    }

    CHFS_MD_DN(chfs_md) = crfsdn_open((char *)cstring_get_str(root_dir));
    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_open_dn: open dn with root dir %s failed\n", (char *)cstring_get_str(root_dir));
        return (EC_FALSE);
    }
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_open_dn: open dn %s\n", (char *)cstring_get_str(root_dir));
    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL chfs_close_dn(const UINT32 chfs_md_id)
{
    CHFS_MD   *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_close_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_close_dn: no dn was open\n");
        return (EC_FALSE);
    }

    crfsdn_close(CHFS_MD_DN(chfs_md));
    CHFS_MD_DN(chfs_md) = NULL_PTR;
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_close_dn: dn was closed\n");

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL chfs_export_dn(const UINT32 chfs_md_id, const CBYTES *cbytes, const CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD      *chfs_md;
    const CHFSNP_INODE *chfsnp_inode;

    UINT32   offset;
    UINT32   data_len;
    uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_export_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    data_len = DMIN(CBYTES_LEN(cbytes), CHFSNP_FNODE_FILESZ(chfsnp_fnode));

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_export_dn: CBYTES_LEN %u or CHFSNP_FNODE_FILESZ %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CHFSNP_FNODE_FILESZ(chfsnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)data_len;

    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    disk_no  = CHFSNP_INODE_DISK_NO(chfsnp_inode) ;
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == crfsdn_write_o(CHFS_MD_DN(chfs_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_export_dn: write %ld bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_export_dn: write %ld bytes to disk %u block %u page %u done\n",
                        data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL chfs_write_dn(const UINT32 chfs_md_id, const CBYTES *cbytes, CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD      *chfs_md;
    CHFSNP_INODE *chfsnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_write_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_dn: buff len (or file size) %u overflow\n", (uint32_t)CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_write_p(CHFS_MD_DN(chfs_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_dn: write %u bytes to dn failed\n", (uint32_t)CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    chfsnp_fnode_init(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    CHFSNP_INODE_DISK_NO(chfsnp_inode)  = disk_no;
    CHFSNP_INODE_BLOCK_NO(chfsnp_inode) = block_no;
    CHFSNP_INODE_PAGE_NO(chfsnp_inode)  = page_no;

    CHFSNP_FNODE_FILESZ(chfsnp_fnode) = CBYTES_LEN(cbytes);
    CHFSNP_FNODE_REPNUM(chfsnp_fnode) = 1;

    return (EC_TRUE);
}

/**
*
*  write data node in cache
*
**/
EC_BOOL chfs_write_dn_cache(const UINT32 chfs_md_id, const CBYTES *cbytes, CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD      *chfs_md;
    CHFSNP_INODE *chfsnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_write_dn_cache: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_dn_cache: buff len (or file size) %u overflow\n", (uint32_t)CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_dn_cache: no dn was open\n");
        return (EC_FALSE);
    }

    chfsnp_fnode_init(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);

    if(EC_FALSE == crfsdn_write_p_cache(CHFS_MD_DN(chfs_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_dn_cache: write %u bytes to dn failed\n", (uint32_t)CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CHFSNP_INODE_DISK_NO(chfsnp_inode)    = disk_no;
    CHFSNP_INODE_BLOCK_NO(chfsnp_inode)   = block_no;
    CHFSNP_INODE_PAGE_NO(chfsnp_inode)    = page_no;

    CHFSNP_FNODE_FILESZ(chfsnp_fnode) = CBYTES_LEN(cbytes);
    CHFSNP_FNODE_REPNUM(chfsnp_fnode) = 1;

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL chfs_read_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode, CBYTES *cbytes)
{
    CHFS_MD *chfs_md;
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_read_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CHFSNP_FNODE_REPNUM(chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CHFSNP_FNODE_FILESZ(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    disk_no  = CHFSNP_INODE_DISK_NO(chfsnp_inode) ;
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_read_dn: file file %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CHFS_0066);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CHFS_0067);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == crfsdn_read_p(CHFS_MD_DN(chfs_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                           file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL chfs_read_e_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CHFS_MD *chfs_md;
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_read_e_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CHFSNP_FNODE_REPNUM(chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CHFSNP_FNODE_FILESZ(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    disk_no  = CHFSNP_INODE_DISK_NO(chfsnp_inode) ;
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:crfs_read_e_dn: due to offset %u >= file size %u\n", (uint32_t)(*offset), file_size);
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

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] crfs_read_e_dn: file size %u, disk %u, block %u, page %u offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CHFS_0071);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CHFS_0072);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == crfsdn_read_e(CHFS_MD_DN(chfs_md), disk_no, block_no, page_no, offset_t, max_len_t, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_e_dn: read %ld bytes from disk %u, block %u, page %u failed\n",
                           max_len_t, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}

/**
*
*  write a fnode to name node
*
**/
EC_BOOL chfs_write_npp(const UINT32 chfs_md_id, const CSTRING *file_path, const CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_write_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(0 == CHFSNP_FNODE_REPNUM(chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_npp: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_wrlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0076);
    if(EC_FALSE == chfsnp_mgr_write(CHFS_MD_NPP(chfs_md), file_path, chfsnp_fnode))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0077);

        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_write_npp: no name node accept file %s with %u replicas\n",
                            (char *)cstring_get_str(file_path), CHFSNP_FNODE_REPNUM(chfsnp_fnode));
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0078);
    return (EC_TRUE);
}

/**
*
*  read a fnode from name node
*
**/
EC_BOOL chfs_read_npp(const UINT32 chfs_md_id, const CSTRING *file_path, CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_read_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_read_npp: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0079);
    if(EC_FALSE == chfsnp_mgr_read(CHFS_MD_NPP(chfs_md), file_path, chfsnp_fnode))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0080);

        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_read_npp: chfsnp mgr read %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0081);

    return (EC_TRUE);
}

/**
*
*  delete a file from current npp
*
**/
EC_BOOL chfs_delete_npp(const UINT32 chfs_md_id, const CSTRING *path)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_delete_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_delete_npp: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_wrlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0082);
    if(EC_FALSE == chfsnp_mgr_delete(CHFS_MD_NPP(chfs_md), path))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0083);

        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_delete_npp: delete '%s' failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0084);

    return (EC_TRUE);
}

/**
*
*  delete file data from current dn
*
**/
STATIC_CAST static EC_BOOL __chfs_delete_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD *chfs_md;
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__chfs_delete_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_delete_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(0 == CHFSNP_FNODE_REPNUM(chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_delete_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CHFSNP_FNODE_FILESZ(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    disk_no  = CHFSNP_INODE_DISK_NO(chfsnp_inode) ;
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    if(EC_FALSE == crfsdn_remove(CHFS_MD_DN(chfs_md), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u failed\n", file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] __chfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u done\n", file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  delete file data from current dn
*
**/
EC_BOOL chfs_delete_dn(const UINT32 chfs_md_id, const CHFSNP_FNODE *chfsnp_fnode)
{
    CHFS_MD *chfs_md;
    const CHFSNP_INODE *chfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_delete_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_delete_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(0 == CHFSNP_FNODE_REPNUM(chfsnp_fnode))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_delete_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CHFSNP_FNODE_FILESZ(chfsnp_fnode);
    chfsnp_inode = CHFSNP_FNODE_INODE(chfsnp_fnode, 0);
    disk_no  = CHFSNP_INODE_DISK_NO(chfsnp_inode) ;
    block_no = CHFSNP_INODE_BLOCK_NO(chfsnp_inode);
    page_no  = CHFSNP_INODE_PAGE_NO(chfsnp_inode) ;

    if(EC_FALSE == crfsdn_remove(CHFS_MD_DN(chfs_md), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u failed\n", file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u done\n", file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  delete a file from all npp and all dn
*
**/
EC_BOOL chfs_delete(const UINT32 chfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_delete: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    /*delete inodes*/
    if(EC_FALSE == chfs_delete_npp(chfs_md_id, path))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_delete: delete %s from npp failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_delete: delete %s done\n", (char *)cstring_get_str(path));
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
EC_BOOL chfs_delete_dir(const UINT32 chfs_md_id, const CSTRING *dir_path, const UINT32 max_idx)
{
    CSTRING    file_path;
    UINT32     idx;

    CSTRING   *dir_path_dup;
    MOD_NODE   recv_mod_node;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_delete_dir: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    dir_path_dup = cstring_dup(dir_path);
    if(NULL_PTR == dir_path_dup)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_delete_dir: dup '%s' failed\n", (char *)cstring_get_str(dir_path));
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
    MOD_NODE_MODI(&recv_mod_node) = chfs_md_id;

    for(idx = 0; idx <= max_idx; idx ++)
    {
        char    *file_path_str;
        EC_BOOL  ret;

        file_path_str = c_str_cat((char *)cstring_get_str(dir_path_dup), c_word_to_str(idx));
        if(NULL_PTR == file_path_str)
        {
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_delete_dir: cat '%s' and '%ld' failed\n", (char *)cstring_get_str(dir_path_dup), idx);

            cstring_free(dir_path_dup);
            return (EC_FALSE);
        }
        cstring_set_str(&file_path, (UINT8 *)file_path_str);

#if 0
        /*delete inode*/
        if(EC_TRUE == chfs_delete_npp(chfs_md_id, &file_path))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_delete_dir: delete file '%s' done\n", (char *)cstring_get_str(&file_path));
        }
#endif
#if 1
        /*delete inode [optimized]*/
        task_p2p(chfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node,
                &ret, FI_chfs_delete, CMPI_ERROR_MODI, &file_path);
#endif
        cstring_clean(&file_path);
    }

    cstring_free(dir_path_dup);

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_delete_dir: delete dir '%s' done\n", (char *)cstring_get_str(dir_path));
    return (EC_TRUE);
}

/**
*
*  query a file
*
**/
EC_BOOL chfs_qfile(const UINT32 chfs_md_id, const CSTRING *file_path, CHFSNP_ITEM  *chfsnp_item)
{
    CHFS_MD      *chfs_md;
    CHFSNP_ITEM  *chfsnp_item_src;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_qfile: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_qfile: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0091);
    chfsnp_item_src = chfsnp_mgr_search_item(CHFS_MD_NPP(chfs_md),
                                             (uint32_t)cstring_get_len(file_path),
                                             cstring_get_str(file_path));
    if(NULL_PTR == chfsnp_item_src)
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0092);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_qfile: query file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0093);

    chfsnp_item_clone(chfsnp_item_src, chfsnp_item);

    return (EC_TRUE);
}

/**
*
*  flush name node pool
*
**/
EC_BOOL chfs_flush_npp(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_flush_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_flush_npp: npp was not open\n");
        return (EC_TRUE);
    }

    chfsnp_mgr_wrlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0094);
    if(EC_FALSE == chfsnp_mgr_flush(CHFS_MD_NPP(chfs_md)))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0095);

        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_flush_npp: flush failed\n");
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0096);
    return (EC_TRUE);
}

/**
*
*  flush data node
*
*
**/
EC_BOOL chfs_flush_dn(const UINT32 chfs_md_id)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_flush_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_flush_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_flush(CHFS_MD_DN(chfs_md)))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_flush_dn: flush dn failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL chfs_file_num(const UINT32 chfs_md_id, UINT32 *file_num)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_num: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_file_num: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_wrlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0100);
    if(EC_FALSE == chfsnp_mgr_file_num(CHFS_MD_NPP(chfs_md), file_num))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0101);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_file_num: count total file num failed\n");
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0102);

    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL chfs_file_size(const UINT32 chfs_md_id, const CSTRING *path_cstr, UINT32 *file_size)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_size: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_file_size: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_wrlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0103);
    if(EC_FALSE == chfsnp_mgr_file_size(CHFS_MD_NPP(chfs_md), path_cstr, file_size))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0104);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_file_size: count total file size failed\n");
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0105);
    return (EC_TRUE);
}

/**
*
*  search in current name node pool
*
**/
EC_BOOL chfs_search(const UINT32 chfs_md_id, const CSTRING *path_cstr)
{
    CHFS_MD      *chfs_md;
    uint32_t      chfsnp_id;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_search: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_search: npp was not open\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0106);
    if(EC_FALSE == chfsnp_mgr_search(CHFS_MD_NPP(chfs_md), (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &chfsnp_id))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0107);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_search: search '%s' failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0108);

    return (EC_TRUE);
}

/**
*
*  check file content on data node
*
**/
EC_BOOL chfs_check_file_content(const UINT32 chfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr)
{
    CHFS_MD *chfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_check_file_content: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_content: dn is null\n");
        return (EC_FALSE);
    }

    ASSERT(EC_TRUE == __chfs_check_is_uint16_t(disk_no));
    ASSERT(EC_TRUE == __chfs_check_is_uint16_t(block_no));
    ASSERT(EC_TRUE == __chfs_check_is_uint16_t(page_no));

    cbytes = cbytes_new(file_size);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_content: new chfs buff with len %ld failed\n", file_size);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_read_p(CHFS_MD_DN(chfs_md), (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no, file_size,
                                  CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_content: read %ld bytes from disk %ld, block %ld, page %ld failed\n",
                            file_size, disk_no, block_no, page_no);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < cstring_get_len(file_content_cstr))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_content: read %ld bytes from disk %ld, block %ld, page %ld to buff len %ld less than cstring len %ld to compare\n",
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
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_content: char at pos %ld not matched\n", pos);
            sys_print(LOGSTDOUT, "read buff: %.*s\n", (uint32_t)len, buff);
            sys_print(LOGSTDOUT, "expected : %.*s\n", (uint32_t)len, str);

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
EC_BOOL chfs_check_file_is(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *file_content)
{
    CHFS_MD *chfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_check_file_is: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_is: dn is null\n");
        return (EC_FALSE);
    }

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_is: new cbytes failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chfs_read(chfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_is: read file %s failed\n", (char *)cstring_get_str(file_path));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) != CBYTES_LEN(file_content))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_is: mismatched len: file %s read len %ld which should be %ld\n",
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
            dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_check_file_is: char at pos %ld not matched\n", pos);
            sys_print(LOGSTDOUT, "read buff: %.*s\n", (uint32_t)len, buff);
            sys_print(LOGSTDOUT, "expected : %.*s\n", (uint32_t)len, str);

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
EC_BOOL chfs_show_npp(const UINT32 chfs_md_id, LOG *log)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_show_npp: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0109);

    chfsnp_mgr_print(log, CHFS_MD_NPP(chfs_md));

    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0110);

    return (EC_TRUE);
}

/**
*
*  show crfsdn info if it is dn
*
*
**/
EC_BOOL chfs_show_dn(const UINT32 chfs_md_id, LOG *log)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_show_dn: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_DN(chfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    crfsdn_print(log, CHFS_MD_DN(chfs_md));

    return (EC_TRUE);
}

/*debug*/
EC_BOOL chfs_show_cached_np(const UINT32 chfs_md_id, LOG *log)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_show_cached_np: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0113);
    if(EC_FALSE == chfsnp_mgr_show_cached_np(log, CHFS_MD_NPP(chfs_md)))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0114);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_show_cached_np: show cached np but failed\n");
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0115);

    return (EC_TRUE);
}

EC_BOOL chfs_show_specific_np(const UINT32 chfs_md_id, const UINT32 chfsnp_id, LOG *log)
{
    CHFS_MD *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_show_specific_np: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == __chfs_check_is_uint32_t(chfsnp_id))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_show_specific_np: chfsnp_id %ld is invalid\n", chfsnp_id);
        return (EC_FALSE);
    }

    chfsnp_mgr_rdlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0116);
    if(EC_FALSE == chfsnp_mgr_show_np(log, CHFS_MD_NPP(chfs_md), (uint32_t)chfsnp_id))
    {
        chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0117);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_show_cached_np: show np %ld but failed\n", chfsnp_id);
        return (EC_FALSE);
    }
    chfsnp_mgr_unlock(CHFS_MD_NPP(chfs_md), LOC_CHFS_0118);

    return (EC_TRUE);
}

/* write memory cache only but Not hfs */
EC_BOOL chfs_write_memc(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_write_memc: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    CHFS_MD      *chfs_md;
    chfs_md = CHFS_MD_GET(chfs_md_id);

    /* ensure CHFS_MEMC_SWITCH is on */
    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        if(EC_TRUE == chfsmc_write(CHFS_MD_MCACHE(chfs_md), file_path, cbytes))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_write_memc: write file %s with size %ld to memcache done\n",
                (char *)cstring_get_str(file_path), cbytes_len(cbytes));

            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_write_memc: write file %s with size %ld to memcache failed\n",
                (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        }
    }
    else
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_write_memc: there is no memcache because CHFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // write to memcache failed, or CHFS_MEMC_SWITCH is off
}


/* check whether a file is in memory cache */
EC_BOOL chfs_check_memc(const UINT32 chfs_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_check_memc: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    CHFS_MD      *chfs_md;
    chfs_md = CHFS_MD_GET(chfs_md_id);

    /* ensure CHFS_MEMC_SWITCH is on */
    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        if(EC_TRUE == chfsmc_check_np(CHFS_MD_MCACHE(chfs_md), file_path))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_check_memc: file %s is in memcache\n",
                               (char *)cstring_get_str(file_path));
            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_check_memc: file %s is NOT in memcache\n",
                               (char *)cstring_get_str(file_path));
        }
    }
    else
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_check_memc: there is no memcache because CHFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // check path from memcache failed, or CHFS_MEMC_SWITCH is off
}

/**
*
*  read file from memory cache only but NOT hfs
*
**/
EC_BOOL chfs_read_memc(const UINT32 chfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_read_memc: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    CHFS_MD      *chfs_md;
    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        if(EC_TRUE == chfsmc_read(CHFS_MD_MCACHE(chfs_md), file_path, cbytes))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_read_memc: read file %s with size %ld from memcache done\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));
            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_read_memc: read file %s from memcache failed\n",
                               (char *)cstring_get_str(file_path));
        }
    }
    else
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_read_memc: there is no memcache because CHFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // read from memcache failed, or CHFS_MEMC_SWITCH is off
}

/**
*
*  update file in memory cache only but NOT hfs
*
**/
EC_BOOL chfs_update_memc(const UINT32 chfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_update_memc: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        if(EC_TRUE == chfsmc_update(CHFS_MD_MCACHE(chfs_md), file_path, cbytes))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update_memc: update file %s with size %ld to memcache done\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));

            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update_memc: update file %s with size %ld to memcache failed\n",
                               (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        }
    }
    else
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_update_memc: there is no memcache because CHFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE); // update to memcache failed, or CHFS_MEMC_SWITCH is off
}

/**
*
*  delete from memory cache only but NOT hfs
*
**/
EC_BOOL chfs_delete_memc(const UINT32 chfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_delete_memc: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    return chfs_delete_file_memc(chfs_md_id, path);
}

/**
*
*  delete file from memory cache only but NOT hfs
*
**/
EC_BOOL chfs_delete_file_memc(const UINT32 chfs_md_id, const CSTRING *path)
{
    CHFS_MD      *chfs_md;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_delete_file_memc: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(SWITCH_ON == CHFS_MEMC_SWITCH)
    {
        if(EC_TRUE == chfsmc_delete(CHFS_MD_MCACHE(chfs_md), path))
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_delete_file_memc: delete file %s from memcache done\n",
                               (char *)cstring_get_str(path));

            return (EC_TRUE);
        }
        else
        {
            dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_delete_file_memc: delete file %s from memcache failed\n",
                               (char *)cstring_get_str(path));
        }
    }
    else
    {
        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_delete_file_memc: there is no memcache because CHFS_MEMC_SWITCH is off\n");
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __chfs_retire_of_np(const UINT32 chfs_md_id, const uint32_t chfsnp_id, const UINT32 nsec, const UINT32 expect_retire_num, const UINT32 max_step, UINT32 *complete_retire_num)
{
    CHFS_MD      *chfs_md;

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:__chfs_retire_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0119);
    if(EC_FALSE == chfsnp_mgr_retire_np(CHFS_MD_NPP(chfs_md), chfsnp_id, nsec, expect_retire_num, max_step, complete_retire_num))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0120);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_retire_of_np: retire np %u failed where nsec %ld, expect retire num %ld\n",
                                            chfsnp_id, nsec, expect_retire_num);
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0121);
    return (EC_TRUE);
}

/**
*
*  retire regular files created before n seconds
*  note:
*    expect_retire_num is for per chfsnp but not all chfsnp(s)
*
**/
EC_BOOL chfs_retire(const UINT32 chfs_md_id, const UINT32 nsec, const UINT32 expect_retire_num, const UINT32 max_step_per_loop, UINT32 *complete_retire_num)
{
    CHFS_MD      *chfs_md;
    CHFSNP_MGR   *chfsnp_mgr;
    uint32_t      chfsnp_id;

    UINT32   total_num;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_retire: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfsnp_mgr = CHFS_MD_NPP(chfs_md);
    if(NULL_PTR == chfsnp_mgr)
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_retire: npp was not open\n");
        return (EC_FALSE);
    }

    for(chfsnp_id = 0, total_num = 0; chfsnp_id < CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr); chfsnp_id ++)
    {
        UINT32   complete_num;

        __chfs_retire_of_np(chfs_md_id, chfsnp_id, nsec, expect_retire_num, max_step_per_loop, &complete_num);
        total_num += complete_num;

        dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_retire: retire np %u done where nsec %ld, expect retire num %ld, complete %ld\n",
                                chfsnp_id, nsec, expect_retire_num, complete_num);
    }

    if(NULL_PTR != complete_retire_num)
    {
        (*complete_retire_num) = total_num;
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_retire: retire done where nsec %ld, complete %ld\n", nsec, total_num);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfs_recycle_of_np(const UINT32 chfs_md_id, const uint32_t chfsnp_id, const UINT32 max_num, UINT32 *complete_num)
{
    CHFS_MD      *chfs_md;
    CHFSNP_RECYCLE_DN chfsnp_recycle_dn;

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:__chfs_recycle_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    CHFSNP_RECYCLE_DN_ARG1(&chfsnp_recycle_dn)   = chfs_md_id;
    CHFSNP_RECYCLE_DN_FUNC(&chfsnp_recycle_dn)   = chfs_release_dn;

    CHFS_WRLOCK(chfs_md, LOC_CHFS_0122);
    if(EC_FALSE == chfsnp_mgr_recycle_np(CHFS_MD_NPP(chfs_md), chfsnp_id, max_num, NULL_PTR, &chfsnp_recycle_dn, complete_num))
    {
        CHFS_UNLOCK(chfs_md, LOC_CHFS_0123);
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:__chfs_recycle_of_np: recycle np %u failed\n", chfsnp_id);
        return (EC_FALSE);
    }
    CHFS_UNLOCK(chfs_md, LOC_CHFS_0124);
    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL chfs_recycle(const UINT32 chfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num)
{
    CHFS_MD      *chfs_md;
    CHFSNP_MGR   *chfsnp_mgr;

    uint32_t      chfsnp_id;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_recycle: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "[DEBUG] chfs_recycle: recycle beg\n");

    chfs_md = CHFS_MD_GET(chfs_md_id);

    chfsnp_mgr = CHFS_MD_NPP(chfs_md);
    if(NULL_PTR == chfsnp_mgr)
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_recycle: npp was not open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != complete_num)
    {
        (*complete_num) = 0; /*initialization*/
    }

    for(chfsnp_id = 0; chfsnp_id < CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr); chfsnp_id ++)
    {
        __chfs_recycle_of_np(chfs_md_id, chfsnp_id, max_num_per_np, complete_num);
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "[DEBUG] chfs_recycle: recycle np %u done\n", chfsnp_id);
    }

    dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "[DEBUG] chfs_recycle: recycle end\n");

    return (EC_TRUE);
}

/**
*
*  set file expired time to current time
*
**/
EC_BOOL chfs_file_expire(const UINT32 chfs_md_id, const CSTRING *path_cstr)
{
    CHFS_MD      *chfs_md;
    CSTRING       key;
    CSTRING       val;

#if ( SWITCH_ON == CHFS_DEBUG_SWITCH )
    if ( CHFS_MD_ID_CHECK_INVALID(chfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:chfs_file_expire: chfs module #%ld not started.\n",
                chfs_md_id);
        dbg_exit(MD_CHFS, chfs_md_id);
    }
#endif/*CHFS_DEBUG_SWITCH*/

    chfs_md = CHFS_MD_GET(chfs_md_id);

    if(NULL_PTR == CHFS_MD_NPP(chfs_md))
    {
        dbg_log(SEC_0023_CHFS, 1)(LOGSTDOUT, "warn:chfs_file_expire: npp was not open\n");
        return (EC_FALSE);
    }

    cstring_init(&key, (const UINT8 *)"Expires");
    cstring_init(&val, (const UINT8 *)c_http_time(task_brd_default_get_time()));

    if(EC_FALSE == chfs_renew_http_header(chfs_md_id, path_cstr, &key, &val))
    {
        dbg_log(SEC_0023_CHFS, 0)(LOGSTDOUT, "error:chfs_file_expire: expire %s failed\n", (char *)cstring_get_str(path_cstr));
        cstring_clean(&key);
        cstring_clean(&val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0023_CHFS, 9)(LOGSTDOUT, "[DEBUG] chfs_file_expire: expire %s done\n", (char *)cstring_get_str(path_cstr));
    cstring_clean(&key);
    cstring_clean(&val);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
