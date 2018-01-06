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

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "carray.h"
#include "cvector.h"

#include "cbc.h"
#include "ctimer.h"
#include "cbtimer.h"
#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "crb.h"
#include "chttp.h"
#include "chttps.h"
#include "ctdns.h"
#include "ctdnshttp.h"
//#include "ctdnshttps.h"

#include "cload.h"

#include "cmd5.h"
#include "cbase64code.h"

#include "findex.inc"

#define CTDNS_MD_CAPACITY()                  (cbc_md_capacity(MD_CTDNS))

#define CTDNS_MD_GET(ctdns_md_id)     ((CTDNS_MD *)cbc_md_get(MD_CTDNS, (ctdns_md_id)))

#define CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id)  \
    ((CMPI_ANY_MODI != (ctdns_md_id)) && ((NULL_PTR == CTDNS_MD_GET(ctdns_md_id)) || (0 == (CTDNS_MD_GET(ctdns_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CTDNS Module
*
**/
void ctdns_print_module_status(const UINT32 ctdns_md_id, LOG *log)
{
    CTDNS_MD *ctdns_md;
    UINT32 this_ctdns_md_id;

    for( this_ctdns_md_id = 0; this_ctdns_md_id < CTDNS_MD_CAPACITY(); this_ctdns_md_id ++ )
    {
        ctdns_md = CTDNS_MD_GET(this_ctdns_md_id);

        if ( NULL_PTR != ctdns_md && 0 < ctdns_md->usedcounter )
        {
            sys_log(log,"CTDNS Module # %u : %u refered\n",
                    this_ctdns_md_id,
                    ctdns_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CTDNS module
*
*
**/
UINT32 ctdns_free_module_static_mem(const UINT32 ctdns_md_id)
{
    CTDNS_MD  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_free_module_static_mem: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    free_module_static_mem(MD_CTDNS, ctdns_md_id);

    return 0;
}

/**
*
* start CTDNS module
*
**/
UINT32 ctdns_start(const CSTRING *ctdns_root_dir)
{
    CTDNS_MD *ctdns_md;
    UINT32    ctdns_md_id;

    TASK_BRD *task_brd;
    EC_BOOL   ret;

    CSTRING *ctdns_dir;
    CSTRING *ctdnsnp_root_dir;
    
    task_brd = task_brd_default_get();
 
    ctdns_md_id = cbc_md_new(MD_CTDNS, sizeof(CTDNS_MD));
    if(CMPI_ERROR_MODI == ctdns_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /*check validity*/
    if(CTDNS_MAX_MODI < ctdns_md_id) /*limited to 2-digital*/
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: ctdns_md_id %ld overflow\n", ctdns_md_id);

        cbc_md_free(MD_CTDNS, ctdns_md_id);
        return (CMPI_ERROR_MODI);
    }

    ctdns_dir = cstring_make("%s/tdns%02ld", (char *)cstring_get_str(ctdns_root_dir), ctdns_md_id);
    if(NULL_PTR == ctdns_dir)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: new ctdns_dir failed\n");

        cbc_md_free(MD_CTDNS, ctdns_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == c_dir_exist((char *)cstring_get_str(ctdns_dir)))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: TDNS %ld dir %s not exist\n",
                           ctdns_md_id, (char *)cstring_get_str(ctdns_dir));

        cbc_md_free(MD_CTDNS, ctdns_md_id);
        cstring_free(ctdns_dir);
        return (CMPI_ERROR_MODI);
    }
    cstring_free(ctdns_dir);

    ctdnsnp_root_dir = cstring_make("%s/tdns%02ld", (char *)cstring_get_str(ctdns_root_dir), ctdns_md_id);
    if(NULL_PTR == ctdnsnp_root_dir)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: new ctdnsnp_root_dir failed\n");

        cbc_md_free(MD_CTDNS, ctdns_md_id);
        return (CMPI_ERROR_MODI);
    }
  
    /* initialize new one CTDNS module */
    ctdns_md = (CTDNS_MD *)cbc_md_get(MD_CTDNS, ctdns_md_id);
    ctdns_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem(); 

    CTDNS_MD_NPP(ctdns_md) = NULL_PTR;

    ret = EC_TRUE;
    if(EC_TRUE  == ret && NULL_PTR != ctdnsnp_root_dir
    && EC_FALSE == cstring_is_empty(ctdnsnp_root_dir)
    && EC_TRUE  == ctdnsnp_mgr_exist(ctdnsnp_root_dir))
    {
        CTDNS_MD_NPP(ctdns_md) = ctdnsnp_mgr_open(ctdnsnp_root_dir);
        if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: open npp from root dir %s failed\n",
                               (char *)cstring_get_str(ctdnsnp_root_dir));
            ret = EC_FALSE;
        }
    }

    /*fix: to reduce the np loading time elapsed*/
    if(EC_TRUE == ret && NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        if(EC_FALSE == ctdnsnp_mgr_open_np_all(CTDNS_MD_NPP(ctdns_md)))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: open all np from root dir %s failed\n",
                               (char *)cstring_get_str(ctdnsnp_root_dir));

            ctdnsnp_mgr_close_np_all(CTDNS_MD_NPP(ctdns_md));/*roll back*/
         
            ret = EC_FALSE;
        }  
    }

    cstring_free(ctdnsnp_root_dir); 
 
    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
        {
            ctdnsnp_mgr_close(CTDNS_MD_NPP(ctdns_md));
            CTDNS_MD_NPP(ctdns_md) = NULL_PTR;
        }
     
        cbc_md_free(MD_CTDNS, ctdns_md_id);

        return (CMPI_ERROR_MODI);
    }

    ctdns_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)ctdns_end, ctdns_md_id);

    dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "[DEBUG] ctdns_start: start CTDNS module #%u\n", ctdns_md_id);

    if(SWITCH_ON == CTDNSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CTDNS module is allowed to launch tdns http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == ctdns_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: init ctdnshttp defer request queue failed\n");
                ctdns_end(ctdns_md_id);
                return (CMPI_ERROR_MODI);
            }

            ctdnshttp_log_start();
            task_brd_default_bind_http_srv_modi(ctdns_md_id);
            chttp_rest_list_push((const char *)CTDNSHTTP_REST_API_NAME, ctdnshttp_commit_request);
        }

        /*https server*/
#if 0
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled() && 0 == ctdns_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: init ctdnshttp defer request queue failed\n");
                ctdns_end(ctdns_md_id);
                return (CMPI_ERROR_MODI);
            }
            ctdnshttps_log_start();
            task_brd_default_bind_https_srv_modi(ctdns_md_id);
            chttps_rest_list_push((const char *)CTDNSHTTPS_REST_API_NAME, ctdnshttps_commit_request);
        }
#endif     

    } 

    return ( ctdns_md_id );
}

/**
*
* end CTDNS module
*
**/
void ctdns_end(const UINT32 ctdns_md_id)
{
    CTDNS_MD *ctdns_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)ctdns_end, ctdns_md_id);

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);
    if(NULL_PTR == ctdns_md)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_end: ctdns_md_id = %u not exist.\n", ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
 
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < ctdns_md->usedcounter )
    {
        ctdns_md->usedcounter --;
        return ;
    }

    if ( 0 == ctdns_md->usedcounter )
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_end: ctdns_md_id = %u is not started.\n", ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
    
#if 0
    /*stop server*/
    if(SWITCH_ON == CTDNSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CTDNS module is allowed to launch tdns http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == ctdns_md_id)
        {
            task_brd_default_stop_http_srv();
            chttp_defer_request_queue_clean();
        }
    }
#endif

    /* if nobody else occupied the module,then free its resource */
    if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        ctdnsnp_mgr_close(CTDNS_MD_NPP(ctdns_md));
        CTDNS_MD_NPP(ctdns_md) = NULL_PTR;
    }

    /* free module : */
    //ctdns_free_module_static_mem(ctdns_md_id);

    ctdns_md->usedcounter = 0;

    dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "ctdns_end: stop CTDNS module #%u\n", ctdns_md_id);
    cbc_md_free(MD_CTDNS, ctdns_md_id);

    return ;
}

EC_BOOL ctdns_flush(const UINT32 ctdns_md_id)
{
    CTDNS_MD  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_flush: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(EC_FALSE == ctdns_flush_npp(ctdns_md_id))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_flush: flush npp failed!\n");
        return (EC_FALSE); 
    }
    
    dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "[DEBUG] ctdns_flush: flush done\n");
    return (EC_TRUE);
}

/**
*
*  get name node pool of the module
*
**/
CTDNSNP_MGR *ctdns_get_npp(const UINT32 ctdns_md_id)
{
    CTDNS_MD   *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_get_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);
    return CTDNS_MD_NPP(ctdns_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL ctdns_open_npp(const UINT32 ctdns_md_id, const CSTRING *ctdnsnp_db_root_dir)
{
    CTDNS_MD   *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_open_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_open_npp: npp was open\n");
        return (EC_FALSE);
    }

    CTDNS_MD_NPP(ctdns_md) = ctdnsnp_mgr_open(ctdnsnp_db_root_dir);
    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_open_npp: open npp from root dir %s failed\n", (char *)cstring_get_str(ctdnsnp_db_root_dir));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  close name node pool
*
**/
EC_BOOL ctdns_close_npp(const UINT32 ctdns_md_id)
{
    CTDNS_MD   *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_close_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_close_npp: npp was not open\n");
        return (EC_FALSE);
    }

    ctdnsnp_mgr_close(CTDNS_MD_NPP(ctdns_md));
    CTDNS_MD_NPP(ctdns_md) = NULL_PTR;
    return (EC_TRUE);
}

/**
*
*  create name node pool
*
**/
EC_BOOL ctdns_create_npp(const UINT32 ctdns_md_id,
                             const UINT32 ctdnsnp_model,
                             const UINT32 ctdnsnp_max_num,
                             const UINT32 ctdnsnp_2nd_chash_algo_id,
                             const CSTRING *ctdnsnp_db_root_dir)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_create_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: npp already exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(ctdnsnp_model))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: ctdnsnp_model %u is invalid\n", ctdnsnp_model);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(ctdnsnp_max_num))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: ctdnsnp_disk_max_num %u is invalid\n", ctdnsnp_max_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(ctdnsnp_2nd_chash_algo_id))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: ctdnsnp_2nd_chash_algo_id %u is invalid\n", ctdnsnp_2nd_chash_algo_id);
        return (EC_FALSE);
    } 

    CTDNS_MD_NPP(ctdns_md) = ctdnsnp_mgr_create((uint8_t ) ctdnsnp_model,
                                             (uint32_t) ctdnsnp_max_num,
                                             (uint8_t ) ctdnsnp_2nd_chash_algo_id,
                                             ctdnsnp_db_root_dir);
    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: create npp failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check existing of a tcid
*
**/
EC_BOOL ctdns_exists(const UINT32 ctdns_md_id, const UINT32 tcid)
{ 
    CTDNS_MD      *ctdns_md;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_exists: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_exists: npp was not open\n");
        return (EC_FALSE);
    }
    
    return ctdnsnp_mgr_find(CTDNS_MD_NPP(ctdns_md), tcid);
}

/**
*
*  set a tcid
*
**/
EC_BOOL ctdns_set(const UINT32 ctdns_md_id, const UINT32 tcid, const UINT32 ipaddr, const CBYTES *key_cbytes)
{
    CTDNS_MD      *ctdns_md;

    const uint8_t *key;
    uint32_t       klen;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_set: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: npp was not open\n");
        return (EC_FALSE);
    }
    
    if(NULL_PTR == key_cbytes)
    {
        return ctdnsnp_mgr_set(CTDNS_MD_NPP(ctdns_md), tcid, ipaddr, 0, NULL_PTR);
    }

    klen = (uint32_t)CBYTES_LEN(key_cbytes);
    key  = CBYTES_BUF(key_cbytes);
    
    return ctdnsnp_mgr_set(CTDNS_MD_NPP(ctdns_md), tcid, ipaddr, klen, key);
}

/**
*
*  get a tcid
*
**/
EC_BOOL ctdns_get(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, CBYTES *key_cbytes)
{
    CTDNS_MD      *ctdns_md;
    
    uint8_t       *key;
    uint32_t       klen;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_get: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_get: npp was not open\n");
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdnsnp_mgr_get(CTDNS_MD_NPP(ctdns_md), tcid, ipaddr, &klen, &key))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == key_cbytes)
    {
        return (EC_TRUE);
    }

    return cbytes_append(key_cbytes, key, klen);
}


/**
*
*  delete a tcid
*
**/
EC_BOOL ctdns_delete(const UINT32 ctdns_md_id, const UINT32 tcid)
{
    CTDNS_MD      *ctdns_md;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_delete: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);
    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_delete: no npp\n");
        return (EC_FALSE);
    }
    
    return ctdnsnp_mgr_delete(CTDNS_MD_NPP(ctdns_md), tcid);
}

/**
*
*  flush name node pool
*
**/
EC_BOOL ctdns_flush_npp(const UINT32 ctdns_md_id)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_flush_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_flush_npp: npp was not open\n");
        return (EC_TRUE);
    }
 
    if(EC_FALSE == ctdnsnp_mgr_flush(CTDNS_MD_NPP(ctdns_md)))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_flush_npp: flush failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "[DEBUG] ctdns_flush_npp: flush done\n");
    return (EC_TRUE);
}

/**
*
*  count tcid num
*
**/
EC_BOOL ctdns_tcid_num(const UINT32 ctdns_md_id, UINT32 *tcid_num)
{
    CTDNS_MD      *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_tcid_num: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_tcid_num: npp was not open\n");
        return (EC_FALSE);
    }

    return ctdnsnp_mgr_tcid_num(CTDNS_MD_NPP(ctdns_md), tcid_num);
}

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL ctdns_show_npp(const UINT32 ctdns_md_id, LOG *log)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_show_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    ctdnsnp_mgr_print(log, CTDNS_MD_NPP(ctdns_md));
 
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

