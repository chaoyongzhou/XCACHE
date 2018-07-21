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
#include "crfs.h"
#include "crfshttp.h"
#include "crfshttps.h"
#include "crfsmc.h"
#include "crfsbk.h"

#include "cload.h"

#include "cmd5.h"
#include "cbase64code.h"
#include "crfsdt.h"
#include "crfsc.h"

#include "findex.inc"

#define CRFS_MD_CAPACITY()                  (cbc_md_capacity(MD_CRFS))

#define CRFS_MD_GET(crfs_md_id)     ((CRFS_MD *)cbc_md_get(MD_CRFS, (crfs_md_id)))

#define CRFS_MD_ID_CHECK_INVALID(crfs_md_id)  \
    ((CMPI_ANY_MODI != (crfs_md_id)) && ((NULL_PTR == CRFS_MD_GET(crfs_md_id)) || (0 == (CRFS_MD_GET(crfs_md_id)->usedcounter))))

STATIC_CAST static CRFSNP_FNODE * __crfs_reserve_npp(const UINT32 crfs_md_id, const CSTRING *file_path);
STATIC_CAST static EC_BOOL __crfs_release_npp(const UINT32 crfs_md_id, const CSTRING *file_path);
STATIC_CAST static EC_BOOL __crfs_collect_neighbors(const UINT32 crfs_md_id);
STATIC_CAST static EC_BOOL __crfs_recycle_of_np(const UINT32 crfs_md_id, const uint32_t crfsnp_id, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  delete file data from current dn
*
**/
STATIC_CAST static EC_BOOL __crfs_delete_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode);

STATIC_CAST static EC_BOOL __crfs_check_path_has_wildcard(const CSTRING *path);

/**
*   for test only
*
*   to query the status of CRFS Module
*
**/
void crfs_print_module_status(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;
    UINT32 this_crfs_md_id;

    for( this_crfs_md_id = 0; this_crfs_md_id < CRFS_MD_CAPACITY(); this_crfs_md_id ++ )
    {
        crfs_md = CRFS_MD_GET(this_crfs_md_id);

        if ( NULL_PTR != crfs_md && 0 < crfs_md->usedcounter )
        {
            sys_log(log,"CRFS Module # %ld : %ld refered\n",
                    this_crfs_md_id,
                    crfs_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CRFS module
*
*
**/
UINT32 crfs_free_module_static_mem(const UINT32 crfs_md_id)
{
    CRFS_MD  *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_free_module_static_mem: crfs module #%ld not started.\n",
                crfs_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    free_module_static_mem(MD_CRFS, crfs_md_id);

    return 0;
}

/**
*
* start CRFS module
*
**/
UINT32 crfs_start(const CSTRING *crfs_root_dir)
{
    CRFS_MD *crfs_md;
    UINT32   crfs_md_id;

    TASK_BRD *task_brd;
    EC_BOOL   ret;

    CSTRING *crfs_dir;
    CSTRING *crfsnp_root_dir;
    CSTRING *crfsdn_root_dir;

    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CRFS, 32);

    crfs_md_id = cbc_md_new(MD_CRFS, sizeof(CRFS_MD));
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /*check validity*/
    if(CRFS_MAX_MODI < crfs_md_id) /*limited to 2-digital*/
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: crfs_md_id %ld overflow\n", crfs_md_id);

        cbc_md_free(MD_CRFS, crfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    crfs_dir = cstring_make("%s/rfs%02ld", (char *)cstring_get_str(crfs_root_dir), crfs_md_id);
    if(NULL_PTR == crfs_dir)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: new crfs_dir failed\n");

        cbc_md_free(MD_CRFS, crfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == c_dir_exist((char *)cstring_get_str(crfs_dir)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: RFS %ld dir %s not exist\n",
                           crfs_md_id, (char *)cstring_get_str(crfs_dir));

        cbc_md_free(MD_CRFS, crfs_md_id);
        cstring_free(crfs_dir);
        return (CMPI_ERROR_MODI);
    }
    cstring_free(crfs_dir);

    crfsnp_root_dir = cstring_make("%s/rfs%02ld", (char *)cstring_get_str(crfs_root_dir), crfs_md_id);
    if(NULL_PTR == crfsnp_root_dir)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: new crfsnp_root_dir failed\n");

        cbc_md_free(MD_CRFS, crfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    crfsdn_root_dir = cstring_make("%s/rfs%02ld", (char *)cstring_get_str(crfs_root_dir), crfs_md_id);
    if(NULL_PTR == crfsdn_root_dir)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: new crfsdn_root_dir failed\n");

        cbc_md_free(MD_CRFS, crfs_md_id);

        cstring_free(crfsnp_root_dir);
        return (CMPI_ERROR_MODI);
    }


    /* initialize new one CRFS module */
    crfs_md = (CRFS_MD *)cbc_md_get(MD_CRFS, crfs_md_id);
    crfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /*initialize LOCK_REQ file RB TREE*/
    crb_tree_init(CRFS_MD_LOCKED_FILES(crfs_md),
                    (CRB_DATA_CMP)crfs_locked_file_cmp,
                    (CRB_DATA_FREE)crfs_locked_file_free,
                    (CRB_DATA_PRINT)crfs_locked_file_print);

    /*initialize WAIT file RB TREE*/
    crb_tree_init(CRFS_MD_WAIT_FILES(crfs_md),
                    (CRB_DATA_CMP)crfs_wait_file_cmp,
                    (CRB_DATA_FREE)crfs_wait_file_free,
                    (CRB_DATA_PRINT)crfs_wait_file_print);

    CRFS_MD_DN_MOD_MGR(crfs_md)  = mod_mgr_new(crfs_md_id, LOAD_BALANCING_QUE);
    CRFS_MD_NPP_MOD_MGR(crfs_md) = mod_mgr_new(crfs_md_id, LOAD_BALANCING_QUE);

    CRFS_MD_DN(crfs_md)  = NULL_PTR;
    CRFS_MD_NPP(crfs_md) = NULL_PTR;

    ret = EC_TRUE;
    if(EC_TRUE  == ret && NULL_PTR != crfsnp_root_dir
    && EC_FALSE == cstring_is_empty(crfsnp_root_dir)
    && EC_TRUE  == crfsnp_mgr_exist(crfsnp_root_dir))
    {
        CRFS_MD_NPP(crfs_md) = crfsnp_mgr_open(crfsnp_root_dir);
        if(NULL_PTR == CRFS_MD_NPP(crfs_md))
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: open npp from root dir %s failed\n",
                               (char *)cstring_get_str(crfsnp_root_dir));
            ret = EC_FALSE;
        }
    }

    /*fix: to reduce the np loading time elapsed*/
    if(EC_TRUE == ret && NULL_PTR != CRFS_MD_NPP(crfs_md))
    {
        if(EC_FALSE == crfsnp_mgr_open_np_all(CRFS_MD_NPP(crfs_md)))
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: open all np from root dir %s failed\n",
                               (char *)cstring_get_str(crfsnp_root_dir));

            crfsnp_mgr_close_np_all(CRFS_MD_NPP(crfs_md));/*roll back*/

            ret = EC_FALSE;
        }
    }

    if(EC_TRUE  == ret && NULL_PTR != crfsdn_root_dir
    && EC_FALSE == cstring_is_empty(crfsdn_root_dir)
    && EC_TRUE  == crfsdn_exist((char *)cstring_get_str(crfsdn_root_dir)))
    {
        CRFS_MD_DN(crfs_md) = crfsdn_open((char *)cstring_get_str(crfsdn_root_dir));
        if(NULL_PTR == CRFS_MD_DN(crfs_md))
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: open dn with root dir %s failed\n",
                               (char *)cstring_get_str(crfsdn_root_dir));
            ret = EC_FALSE;
        }
    }

    cstring_free(crfsnp_root_dir);
    cstring_free(crfsdn_root_dir);

    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CRFS_MD_DN(crfs_md))
        {
            crfsdn_close(CRFS_MD_DN(crfs_md));
            CRFS_MD_DN(crfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CRFS_MD_NPP(crfs_md))
        {
            crfsnp_mgr_close(CRFS_MD_NPP(crfs_md));
            CRFS_MD_NPP(crfs_md) = NULL_PTR;
        }

        cbc_md_free(MD_CRFS, crfs_md_id);

        return (CMPI_ERROR_MODI);
    }

    CRFS_MD_CBTIMER_NODE(crfs_md) = NULL_PTR;

    if(NULL_PTR != CRFS_MD_DN(crfs_md))
    {
        CBTIMER_NODE *cbtimer_node;

        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_start: crfs %ld try to add crfsdn cached nodes expire event\n", crfs_md_id);
        cbtimer_node = cbtimer_add(TASK_BRD_CBTIMER_LIST(task_brd_default_get()),
                                   (UINT8 *)"CRFS_EXPIRE_DN",
                                   CBTIMER_NEVER_EXPIRE,
                                   CRFS_CHECK_DN_EXPIRE_IN_NSEC,
                                   FI_crfs_expire_dn, crfs_md_id);

        CRFS_MD_CBTIMER_NODE(crfs_md) = cbtimer_node;
    }

    cvector_init(CRFS_MD_NEIGHBOR_VEC(crfs_md), 0, MM_MOD_NODE, CVECTOR_LOCK_ENABLE, LOC_CRFS_0001);

    CRFS_MD_STATE(crfs_md) = CRFS_WORK_STATE;

    crfs_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)crfs_end, crfs_md_id);

    __crfs_collect_neighbors(crfs_md_id);

    dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "[DEBUG] crfs_start: start CRFS module #%ld\n", crfs_md_id);

    if(SWITCH_ON == CRFS_DN_DEFER_WRITE_SWITCH && SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    {
        UINT32 core_max_num;
        UINT32 flush_thread_idx;

        CRFS_MD_TERMINATE_FLAG(crfs_md) = EC_FALSE;
        core_max_num = sysconf(_SC_NPROCESSORS_ONLN);

        ASSERT(0 < CRFS_DN_DEFER_WRITE_THREAD_NUM);

        for(flush_thread_idx = 0; flush_thread_idx < CRFS_DN_DEFER_WRITE_THREAD_NUM; flush_thread_idx ++)
        {
            cthread_new(CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                    (const char *)"crfsdn_flush_cache_nodes",
                    (UINT32)crfsdn_flush_cache_nodes,
                    (UINT32)(TASK_BRD_RANK(task_brd) % core_max_num), /*core #*/
                    (UINT32)2,/*para num*/
                    (UINT32)(&(CRFS_MD_DN(crfs_md))),
                    (UINT32)&(CRFS_MD_TERMINATE_FLAG(crfs_md))
                    );
        }
    }

    if(SWITCH_ON == CRFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CRFS module is allowed to launch rfs http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == crfs_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: init crfshttp defer request queue failed\n");
                crfs_end(crfs_md_id);
                return (CMPI_ERROR_MODI);
            }

            crfshttp_log_start();
            task_brd_default_bind_http_srv_modi(crfs_md_id);
            chttp_rest_list_push((const char *)CRFSHTTP_REST_API_NAME, crfshttp_commit_request);
        }

        /*https server*/
#if 1
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled() && 0 == crfs_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_start: init crfshttp defer request queue failed\n");
                crfs_end(crfs_md_id);
                return (CMPI_ERROR_MODI);
            }
            crfshttps_log_start();
            task_brd_default_bind_https_srv_modi(crfs_md_id);
            chttps_rest_list_push((const char *)CRFSHTTPS_REST_API_NAME, crfshttps_commit_request);
        }
#endif

    }

    return ( crfs_md_id );
}

/**
*
* end CRFS module
*
**/
void crfs_end(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)crfs_end, crfs_md_id);

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(NULL_PTR == crfs_md)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_end: crfs_md_id = %ld not exist.\n", crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < crfs_md->usedcounter )
    {
        crfs_md->usedcounter --;
        return ;
    }

    if ( 0 == crfs_md->usedcounter )
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_end: crfs_md_id = %ld is not started.\n", crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }

#if 0
    /*stop server*/
    if(SWITCH_ON == CRFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CRFS module is allowed to launch rfs http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == crfs_md_id)
        {
            task_brd_default_stop_http_srv();
            chttp_defer_request_queue_clean();
        }
    }
#endif

    if(NULL_PTR != CRFS_MD_CBTIMER_NODE(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_end: crfs %ld try to del crfsdn cached nodes expire event\n", crfs_md_id);
        cbtimer_unregister(TASK_BRD_CBTIMER_LIST(task_brd_default_get()), CRFS_MD_CBTIMER_NODE(crfs_md));
        CRFS_MD_CBTIMER_NODE(crfs_md) = NULL_PTR;
    }

    CRFS_MD_STATE(crfs_md) = CRFS_ERR_STATE;

    if(NULL_PTR != CRFS_MD_DN(crfs_md))
    {
        crfsdn_close(CRFS_MD_DN(crfs_md));
        CRFS_MD_DN(crfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CRFS_MD_NPP(crfs_md))
    {
        crfsnp_mgr_close(CRFS_MD_NPP(crfs_md));
        CRFS_MD_NPP(crfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CRFS_MD_DN_MOD_MGR(crfs_md))
    {
        mod_mgr_free(CRFS_MD_DN_MOD_MGR(crfs_md));
        CRFS_MD_DN_MOD_MGR(crfs_md)  = NULL_PTR;
    }

    if(NULL_PTR != CRFS_MD_NPP_MOD_MGR(crfs_md))
    {
        mod_mgr_free(CRFS_MD_NPP_MOD_MGR(crfs_md));
        CRFS_MD_NPP_MOD_MGR(crfs_md)  = NULL_PTR;
    }

    cvector_clean(CRFS_MD_NEIGHBOR_VEC(crfs_md), (CVECTOR_DATA_CLEANER)mod_node_free, LOC_CRFS_0002);

    crb_tree_clean(CRFS_MD_LOCKED_FILES(crfs_md));
    crb_tree_clean(CRFS_MD_WAIT_FILES(crfs_md));


    /* free module : */
    //crfs_free_module_static_mem(crfs_md_id);

    crfs_md->usedcounter = 0;

    dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "crfs_end: stop CRFS module #%ld\n", crfs_md_id);
    cbc_md_free(MD_CRFS, crfs_md_id);

    return ;
}

EC_BOOL crfs_flush(const UINT32 crfs_md_id)
{
    CRFS_MD  *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_flush: crfs module #%ld not started.\n",
                crfs_md_id);
        crfs_print_module_status(crfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(EC_FALSE == crfs_flush_npp(crfs_md_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_flush: flush npp failed!\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_flush_dn(crfs_md_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_flush: flush dn failed!\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_flush: flush done\n");
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_add_neighbor(const UINT32 crfs_md_id, TASKS_CFG *remote_tasks_cfg)
{
    CRFS_MD  *crfs_md;
    CVECTOR  *crfs_neighbor_vec;
    MOD_NODE *mod_node;

    crfs_md = CRFS_MD_GET(crfs_md_id);
    crfs_neighbor_vec = CRFS_MD_NEIGHBOR_VEC(crfs_md);

    mod_node = mod_node_new();
    if(NULL_PTR == mod_node)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_add_neighbor: new mod_node failed\n");
        return (EC_FALSE);
    }

    MOD_NODE_TCID(mod_node) = TASKS_CFG_TCID(remote_tasks_cfg);
    MOD_NODE_COMM(mod_node) = CMPI_COMM_NULL;
    MOD_NODE_RANK(mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(mod_node) = 0;

    if(CVECTOR_ERR_POS != cvector_search_front(crfs_neighbor_vec, (void *)mod_node, (CVECTOR_DATA_CMP)mod_node_cmp))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_add_neighbor: tcid %s already in neighbors\n", MOD_NODE_TCID_STR(mod_node));
        mod_node_free(mod_node);
        return (EC_FALSE);
    }

    cvector_push(crfs_neighbor_vec, (void *)mod_node);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_collect_neighbors_from_cluster(const UINT32 crfs_md_id, const UINT32 cluster_id)
{
    TASK_BRD    *task_brd;
    TASKS_CFG   *local_tasks_cfg;
    CLUSTER_CFG *cluster_cfg;

    task_brd = task_brd_default_get();
    local_tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

    cluster_cfg = sys_cfg_get_cluster_cfg_by_id(TASK_BRD_SYS_CFG(task_brd), cluster_id);
    if(NULL_PTR == cluster_cfg)
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:__crfs_collect_neighbors_from_cluster: not found cluter %ld definition\n", cluster_id);
        return (EC_TRUE);
    }

    if(MODEL_TYPE_HSRFS_CONNEC == CLUSTER_CFG_MODEL(cluster_cfg))
    {
        CVECTOR  *cluster_nodes;
        UINT32    pos;

        cluster_nodes = CLUSTER_CFG_NODES(cluster_cfg);

        CVECTOR_LOCK(cluster_nodes, LOC_CRFS_0003);
        for(pos = 0; pos < cvector_size(cluster_nodes); pos ++)
        {
            CLUSTER_NODE_CFG *cluster_node_cfg;
            TASKS_CFG *remote_tasks_cfg;

            cluster_node_cfg = (CLUSTER_NODE_CFG *)cvector_get_no_lock(cluster_nodes, pos);
            if(NULL_PTR == cluster_node_cfg)
            {
                continue;
            }

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), CLUSTER_NODE_CFG_TCID(cluster_node_cfg), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_collect_neighbors_from_cluster: not found tasks_cfg of cluster node %s\n", CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg));
                continue;
            }

            if(EC_TRUE == tasks_cfg_cmp(local_tasks_cfg, remote_tasks_cfg))
            {
                dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_collect_neighbors_from_cluster: skip local tcid %s\n", CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg));
                continue;
            }

            /*check whether remote_tasks_cfg belong to the intranet of local_tasks_cfg*/
            if(EC_FALSE == tasks_cfg_is_intranet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
            && EC_FALSE == tasks_cfg_is_externet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
            && EC_FALSE == tasks_cfg_is_lannet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
            && EC_FALSE == tasks_cfg_is_dbgnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
            && EC_FALSE == tasks_cfg_is_monnet(TASK_BRD_LOCAL_TASKS_CFG(task_brd), remote_tasks_cfg)
            )
            {
                continue;
            }

            if(EC_FALSE == __crfs_add_neighbor(crfs_md_id, remote_tasks_cfg))
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_collect_neighbors_from_cluster: add neighbor tcid %s failed\n", CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg));
                continue;
            }
            dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG]__crfs_collect_neighbors_from_cluster: add neighbor tcid %s done\n", CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg));
        }
        CVECTOR_UNLOCK(cluster_nodes, LOC_CRFS_0004);
    }
    else
    {
        dbg_log(SEC_0031_CRFS, 3)(LOGSTDOUT, "info:__crfs_collect_neighbors_from_cluster: skip cluster %ld due to mismatched model %ld\n",
                           cluster_id, CLUSTER_CFG_MODEL(cluster_cfg));
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_collect_neighbors(const UINT32 crfs_md_id)
{
    CRFS_MD     *crfs_md;

    TASK_BRD    *task_brd;
    TASKS_CFG   *tasks_cfg;

    EC_BOOL      ret;

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(NULL_PTR == crfs_md)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_collect_neighbors: crfs_md_id = %ld not exist.\n", crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }

    task_brd  = task_brd_default_get();
    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

    if(NULL_PTR != tasks_cfg)
    {
        cvector_loop(TASKS_CFG_CLUSTER_VEC(tasks_cfg), &ret, NULL_PTR,
                                (UINT32)2,
                                (UINT32)1,
                                (UINT32)__crfs_collect_neighbors_from_cluster,
                                crfs_md_id,
                                NULL_PTR);
    }
    return (EC_TRUE);
}

/**
*
* initialize mod mgr of CRFS module
*
**/
UINT32 crfs_set_npp_mod_mgr(const UINT32 crfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CRFS_MD *crfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_set_npp_mod_mgr: crfs module #%ld not started.\n",
                crfs_md_id);
        crfs_print_module_status(crfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    des_mod_mgr = CRFS_MD_NPP_MOD_MGR(crfs_md);

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "crfs_set_npp_mod_mgr: md_id %ld, input src_mod_mgr %p\n", crfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of crfsnp_tcid_vec and crfsnp_tcid_vec*/
    mod_mgr_limited_clone(crfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "====================================crfs_set_npp_mod_mgr: des_mod_mgr %p beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "====================================crfs_set_npp_mod_mgr: des_mod_mgr %p end====================================\n", des_mod_mgr);

    return (0);
}

UINT32 crfs_set_dn_mod_mgr(const UINT32 crfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CRFS_MD *crfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_set_dn_mod_mgr: crfs module #%ld not started.\n",
                crfs_md_id);
        crfs_print_module_status(crfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    des_mod_mgr = CRFS_MD_DN_MOD_MGR(crfs_md);

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "crfs_set_dn_mod_mgr: md_id %ld, input src_mod_mgr %p\n", crfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of crfsnp_tcid_vec and crfsnp_tcid_vec*/
    mod_mgr_limited_clone(crfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "====================================crfs_set_dn_mod_mgr: des_mod_mgr %p beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "====================================crfs_set_dn_mod_mgr: des_mod_mgr %p end====================================\n", des_mod_mgr);

    return (0);
}

/**
*
* get mod mgr of CRFS module
*
**/
MOD_MGR * crfs_get_npp_mod_mgr(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    crfs_md = CRFS_MD_GET(crfs_md_id);
    return CRFS_MD_NPP_MOD_MGR(crfs_md);
}

MOD_MGR * crfs_get_dn_mod_mgr(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    crfs_md = CRFS_MD_GET(crfs_md_id);
    return CRFS_MD_DN_MOD_MGR(crfs_md);
}

CRFSNP_FNODE *crfs_fnode_new(const UINT32 crfs_md_id)
{
    return crfsnp_fnode_new();
}

EC_BOOL crfs_fnode_init(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode)
{
    return crfsnp_fnode_init(crfsnp_fnode);
}

EC_BOOL crfs_fnode_clean(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode)
{
    return crfsnp_fnode_clean(crfsnp_fnode);
}

EC_BOOL crfs_fnode_free(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode)
{
    return crfsnp_fnode_free(crfsnp_fnode);
}

EC_BOOL crfs_set_state(const UINT32 crfs_md_id, const UINT32 crfs_state)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_set_state: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_set_state: crfs module #%ld: state %lx -> %lx\n",
                        crfs_md_id, CRFS_MD_STATE(crfs_md), crfs_state);

    CRFS_MD_STATE(crfs_md) = crfs_state;

    return (EC_TRUE);
}

UINT32 crfs_get_state(const UINT32 crfs_md_id)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_get_state: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    return CRFS_MD_STATE(crfs_md);
}

EC_BOOL crfs_is_state(const UINT32 crfs_md_id, const UINT32 crfs_state)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_is_state: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(CRFS_MD_STATE(crfs_md) == crfs_state)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/**
*
*  get name node pool of the module
*
**/
CRFSNP_MGR *crfs_get_npp(const UINT32 crfs_md_id)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_get_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    return CRFS_MD_NPP(crfs_md);
}

/**
*
*  get data node of the module
*
**/
CRFSDN *crfs_get_dn(const UINT32 crfs_md_id)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_get_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    return CRFS_MD_DN(crfs_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL crfs_open_npp(const UINT32 crfs_md_id, const CSTRING *crfsnp_db_root_dir)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_open_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR != CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_open_npp: npp was open\n");
        return (EC_FALSE);
    }

    CRFS_MD_NPP(crfs_md) = crfsnp_mgr_open(crfsnp_db_root_dir);
    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_open_npp: open npp from root dir %s failed\n", (char *)cstring_get_str(crfsnp_db_root_dir));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  close name node pool
*
**/
EC_BOOL crfs_close_npp(const UINT32 crfs_md_id)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_close_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_close_npp: npp was not open\n");
        return (EC_FALSE);
    }

    crfsnp_mgr_close(CRFS_MD_NPP(crfs_md));
    CRFS_MD_NPP(crfs_md) = NULL_PTR;
    return (EC_TRUE);
}

/**
*
*  check this CRFS is name node pool or not
*
*
**/
EC_BOOL crfs_is_npp(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_is_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CRFS is data node or not
*
*
**/
EC_BOOL crfs_is_dn(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_is_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CRFS is data node and namenode or not
*
*
**/
EC_BOOL crfs_is_npp_and_dn(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_is_npp_and_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md) || NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  create name node pool
*
**/
EC_BOOL crfs_create_npp(const UINT32 crfs_md_id,
                             const UINT32 crfsnp_model,
                             const UINT32 crfsnp_max_num,
                             const UINT32 crfsnp_2nd_chash_algo_id,
                             const CSTRING *crfsnp_db_root_dir)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_create_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR != CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_create_npp: npp already exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(crfsnp_model))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_create_npp: crfsnp_model %u is invalid\n", (uint32_t)crfsnp_model);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(crfsnp_max_num))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_create_npp: crfsnp_disk_max_num %u is invalid\n", (uint32_t)crfsnp_max_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(crfsnp_2nd_chash_algo_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_create_npp: crfsnp_2nd_chash_algo_id %u is invalid\n", (uint32_t)crfsnp_2nd_chash_algo_id);
        return (EC_FALSE);
    }

    CRFS_MD_NPP(crfs_md) = crfsnp_mgr_create((uint8_t ) crfsnp_model,
                                             (uint32_t) crfsnp_max_num,
                                             (uint8_t ) crfsnp_2nd_chash_algo_id,
                                             crfsnp_db_root_dir);
    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_create_npp: create npp failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_add_npp(const UINT32 crfs_md_id, const UINT32 crfsnpp_tcid, const UINT32 crfsnpp_rank)
{
    CRFS_MD   *crfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_add_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, crfsnpp_tcid))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_add_npp: crfsnpp_tcid %s not connected\n", c_word_to_ipv4(crfsnpp_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(crfsnpp_tcid, CMPI_ANY_COMM, crfsnpp_rank, 0, CRFS_MD_NPP_MOD_MGR(crfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), crfsnpp_tcid, crfsnpp_rank, 0);

    return (EC_TRUE);
}

EC_BOOL crfs_add_dn(const UINT32 crfs_md_id, const UINT32 crfsdn_tcid, const UINT32 crfsdn_rank)
{
    CRFS_MD   *crfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_add_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, crfsdn_tcid))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_add_dn: crfsdn_tcid %s not connected\n", c_word_to_ipv4(crfsdn_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(crfsdn_tcid, CMPI_ANY_COMM, crfsdn_rank, (UINT32)0, CRFS_MD_DN_MOD_MGR(crfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), crfsdn_tcid, crfsdn_rank, 0);

    return (EC_TRUE);
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfs_find_dir(const UINT32 crfs_md_id, const CSTRING *dir_path)
{
    CRFS_MD   *crfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_find_dir: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_find_dir: npp was not open\n");
        return (EC_FALSE);
    }

    ret = crfsnp_mgr_find_dir(CRFS_MD_NPP(crfs_md), dir_path);

    return (ret);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL crfs_find_file(const UINT32 crfs_md_id, const CSTRING *file_path)
{
    CRFS_MD   *crfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_find_file: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_find_file: npp was not open\n");
        return (EC_FALSE);
    }

    ret = crfsnp_mgr_find_file(CRFS_MD_NPP(crfs_md), file_path);
    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL crfs_find(const UINT32 crfs_md_id, const CSTRING *path)
{
    CRFS_MD   *crfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_find: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_find: npp was not open\n");
        return (EC_FALSE);
    }

    ret = crfsnp_mgr_find(CRFS_MD_NPP(crfs_md), path, CRFSNP_ITEM_FILE_IS_ANY/*xxx*/);

    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL crfs_exists(const UINT32 crfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_exists: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    return crfs_find(crfs_md_id, path);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL crfs_is_file(const UINT32 crfs_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_is_file: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    return crfs_find_file(crfs_md_id, file_path);
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfs_is_dir(const UINT32 crfs_md_id, const CSTRING *dir_path)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_is_dir: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    return crfs_find_dir(crfs_md_id, dir_path);
}

/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __crfs_reserve_hash_dn(const UINT32 crfs_md_id, const UINT32 data_len, const uint32_t path_hash, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;
    CRFSNP_INODE *crfsnp_inode;
    CPGV         *cpgv;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint16_t fail_tries;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__crfs_reserve_hash_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_hash_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFSDN_CPGV(CRFS_MD_DN(crfs_md)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cpgv = CRFSDN_CPGV(CRFS_MD_DN(crfs_md));
    if(NULL_PTR == CPGV_HEADER(cpgv))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CPGV_PAGE_DISK_NUM(cpgv))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_hash_dn: pgv has no disk yet\n");
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
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_hash_dn: "
                                                 "new %ld bytes space from vol failed\n",
                                                 data_len);
            return (EC_FALSE);
        }

        /*try to retire & recycle some files*/
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "warn:__crfs_reserve_hash_dn: "
                                             "no %ld bytes space, try to retire & recycle\n",
                                             data_len);
        crfs_retire(crfs_md_id, (UINT32)CRFSNP_TRY_RETIRE_MAX_NUM, NULL_PTR);
        crfs_recycle(crfs_md_id, (UINT32)CRFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    crfsnp_fnode_init(crfsnp_fnode);
    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = size;
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 1;

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_NOT_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = disk_no;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = block_no;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL crfs_reserve_dn(const UINT32 crfs_md_id, const UINT32 data_len, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;
    CRFSNP_INODE *crfsnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_reserve_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_reserve_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    if(EC_FALSE == cpgv_new_space(CRFSDN_CPGV(CRFS_MD_DN(crfs_md)), size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_reserve_dn: new %ld bytes space from vol failed\n", data_len);
        return (EC_FALSE);
    }

    crfsnp_fnode_init(crfsnp_fnode);
    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = size;
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 1;

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_NOT_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = disk_no;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = block_no;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  release space to dn
*
**/
EC_BOOL crfs_release_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD *crfs_md;
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_release_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_release_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);

    if(CPGB_CACHE_MAX_BYTE_SIZE < file_size)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_release_dn: file_size %u overflow\n", file_size);
        return (EC_FALSE);
    }

    /*refer __crfs_write: when file size is zero, only reserve npp but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_release_dn: file_size is zero\n");
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CRFSNP_INODE_DISK_NO(crfsnp_inode) ;
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    if(EC_FALSE == cpgv_free_space(CRFSDN_CPGV(CRFS_MD_DN(crfs_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_release_dn: free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_release_dn: remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write a file (version 0.3)
*
**/
STATIC_CAST static EC_BOOL __crfs_write(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE *crfsnp_fnode;
    uint32_t      path_hash;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfsnp_fnode = __crfs_reserve_npp(crfs_md_id, file_path);
    if(NULL_PTR == crfsnp_fnode)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write: file %s reserve npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    /*calculate hash value of file_path*/
    path_hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        crfsnp_fnode_init(crfsnp_fnode);
        CRFSNP_FNODE_HASH(crfsnp_fnode) = path_hash;

        if(do_log(SEC_0031_CRFS, 1))
        {
            sys_log(LOGSTDOUT, "warn:__crfs_write: write file %s with zero len to dn where fnode is \n", (char *)cstring_get_str(file_path));
            crfsnp_fnode_print(LOGSTDOUT, crfsnp_fnode);
        }

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path); /*patch*/

        return (EC_TRUE);
    }

    if(EC_FALSE == __crfs_reserve_hash_dn(crfs_md_id, CBYTES_LEN(cbytes), path_hash, crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write: reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __crfs_release_npp(crfs_md_id, file_path);

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path); /*patch*/

        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_export_dn(crfs_md_id, cbytes, crfsnp_fnode))
    {
        crfs_release_dn(crfs_md_id, crfsnp_fnode);

        __crfs_release_npp(crfs_md_id, file_path);

        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    CRFSNP_FNODE_HASH(crfsnp_fnode) = path_hash;

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __crfs_write: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        crfsnp_fnode_print(LOGSTDOUT, crfsnp_fnode);
    }

    /*notify all waiters*/
    crfs_file_notify(crfs_md_id, file_path);

    return (EC_TRUE);
}

/*Jan 16, 2017*/
STATIC_CAST static EC_BOOL __crfs_write_no_lock(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE *crfsnp_fnode;
    uint32_t      path_hash;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfsnp_fnode = __crfs_reserve_npp(crfs_md_id, file_path);
    if(NULL_PTR == crfsnp_fnode)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write_no_lock: file %s reserve npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path);/*patch*/

        return (EC_FALSE);
    }

    /*calculate hash value of file_path*/
    path_hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        crfsnp_fnode_init(crfsnp_fnode);
        /*CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 1; */
        CRFSNP_FNODE_HASH(crfsnp_fnode)   = path_hash;

        if(do_log(SEC_0031_CRFS, 1))
        {
            sys_log(LOGSTDOUT, "warn:__crfs_write_no_lock: write file %s with zero len to dn where fnode is \n", (char *)cstring_get_str(file_path));
            crfsnp_fnode_print(LOGSTDOUT, crfsnp_fnode);
        }

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path);

        return (EC_TRUE);
    }

    if(EC_FALSE == __crfs_reserve_hash_dn(crfs_md_id, CBYTES_LEN(cbytes), path_hash, crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write_no_lock: reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __crfs_release_npp(crfs_md_id, file_path);

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path);/*patch*/
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_export_dn(crfs_md_id, cbytes, crfsnp_fnode))
    {
        crfs_release_dn(crfs_md_id, crfsnp_fnode);

        __crfs_release_npp(crfs_md_id, file_path);

        /*notify all waiters*/
        crfs_file_notify(crfs_md_id, file_path);/*patch*/

        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write_no_lock: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    CRFSNP_FNODE_HASH(crfsnp_fnode) = path_hash;

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __crfs_write_no_lock: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        crfsnp_fnode_print(LOGSTDOUT, crfsnp_fnode);
    }

    /*notify all waiters*/
    crfs_file_notify(crfs_md_id, file_path);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_write_cache(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE  crfsnp_fnode;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfsnp_fnode_init(&crfsnp_fnode);

    if(EC_FALSE == crfs_write_dn_cache(crfs_md_id, cbytes, &crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write_cache: write file %s content to dn failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __crfs_write_cache: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
    }
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_write_cache: write file %s is %.*s\n", (char *)cstring_get_str(file_path), (uint32_t)DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));

    if(EC_FALSE == crfs_write_npp(crfs_md_id, file_path, &crfsnp_fnode))
    {
        __crfs_delete_dn(crfs_md_id, &crfsnp_fnode);
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write_cache: write file %s to npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_write_cache_no_lock(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE  crfsnp_fnode;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfsnp_fnode_init(&crfsnp_fnode);

    if(EC_FALSE == crfs_write_dn_cache(crfs_md_id, cbytes, &crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write_cache_no_lock: write file %s content to dn failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __crfs_write_cache_no_lock: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
    }
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_write_cache_no_lock: write file %s is %.*s\n", (char *)cstring_get_str(file_path), (uint32_t)DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));

    if(EC_FALSE == crfs_write_npp(crfs_md_id, file_path, &crfsnp_fnode))
    {
        __crfs_delete_dn(crfs_md_id, &crfsnp_fnode);
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_write_cache_no_lock: write file %s to npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_write(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(SWITCH_ON == CRFS_DN_DEFER_WRITE_SWITCH)
    {
        return __crfs_write_cache(crfs_md_id, file_path, cbytes);
    }

    return __crfs_write(crfs_md_id, file_path, cbytes);
}

EC_BOOL crfs_write_no_lock(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write_no_lock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(SWITCH_ON == CRFS_DN_DEFER_WRITE_SWITCH)
    {
        return __crfs_write_cache_no_lock(crfs_md_id, file_path, cbytes);
    }

    return __crfs_write_no_lock(crfs_md_id, file_path, cbytes);
}

/**
*
*  read a file
*
**/
EC_BOOL crfs_read_safe(const UINT32 crfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE  crfsnp_fnode;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_read_safe: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfsnp_fnode_init(&crfsnp_fnode);

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(EC_FALSE == crfs_read_npp(crfs_md_id, file_path, &crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_safe: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

#if 0
    else
    {
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_read_safe: read file %s from npp and fnode %p is \n",
                           (char *)cstring_get_str(file_path),
                           &crfsnp_fnode);
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
    }
#endif

    /*exception*/
    if(0 == CRFSNP_FNODE_FILESZ(&crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_read_safe: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &crfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_read_dn(crfs_md_id, &crfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_safe: read file %s from dn failed where fnode is \n", (char *)cstring_get_str(file_path));
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0031_CRFS, 9)(LOGSTDNULL, "[DEBUG] crfs_read_safe: read file %s is %.*s\n", (char *)cstring_get_str(file_path), (uint32_t)DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));
    return (EC_TRUE);
}

EC_BOOL crfs_read(const UINT32 crfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE  crfsnp_fnode;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_read: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfsnp_fnode_init(&crfsnp_fnode);

    crfs_md = CRFS_MD_GET(crfs_md_id);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_read: read file %s start\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == crfs_read_npp(crfs_md_id, file_path, &crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_read: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_read: read file %s from npp done\n", (char *)cstring_get_str(file_path));

    /**
    *
    * WARNING:
    * after unlock, crfsnp_fnode read from npp will be dangerous due to someone may delete the file without
    * notifying the reader, thus reader would read "dirty" data which is deleted yet in logical.
    *
    * but we can ignore and tolerant the short-term "dirty" data
    *
    **/

    /*exception*/
    if(0 == CRFSNP_FNODE_FILESZ(&crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_read: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &crfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_read_dn(crfs_md_id, &crfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read: read file %s from dn failed where fnode is \n", (char *)cstring_get_str(file_path));
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
        return (EC_FALSE);
    }

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfs_read: read file %s with size %ld done\n",
                            (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
    }
    return (EC_TRUE);
}

/**
*
*  write a file in cache
*
**/


/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a file at offset
*
**/
EC_BOOL crfs_write_e(const UINT32 crfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE  crfsnp_fnode;
    uint32_t      file_old_size;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write_e: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfsnp_fnode_init(&crfsnp_fnode);

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(EC_FALSE == crfs_read_npp(crfs_md_id, file_path, &crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    file_old_size = CRFSNP_FNODE_FILESZ(&crfsnp_fnode);

    if(EC_FALSE == crfs_write_e_dn(crfs_md_id, &crfsnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_e: offset write to dn failed\n");
        return (EC_FALSE);
    }

    if(file_old_size != CRFSNP_FNODE_FILESZ(&crfsnp_fnode))
    {
        if(EC_FALSE == crfs_update_npp(crfs_md_id, file_path, &crfsnp_fnode))
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_e: offset write file %s to npp failed\n", (char *)cstring_get_str(file_path));
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
EC_BOOL crfs_read_e(const UINT32 crfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE  crfsnp_fnode;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_read_e: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfsnp_fnode_init(&crfsnp_fnode);

    if(EC_FALSE == crfs_read_npp(crfs_md_id, file_path, &crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfs_read_e: read file %s from npp and fnode %p is \n",
                           (char *)cstring_get_str(file_path),
                           &crfsnp_fnode);
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
    }

    /*exception*/
    if(0 == CRFSNP_FNODE_FILESZ(&crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_read_e: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &crfsnp_fnode);
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_read_e_dn(crfs_md_id, &crfsnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_e: offset read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
        crfsnp_fnode_print(LOGSTDOUT, &crfsnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  create data node
*
**/
EC_BOOL crfs_create_dn(const UINT32 crfs_md_id, const CSTRING *root_dir)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_create_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(NULL_PTR != CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_create_dn: dn already exist\n");
        return (EC_FALSE);
    }

    CRFS_MD_DN(crfs_md) = crfsdn_create((char *)cstring_get_str(root_dir));
    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_create_dn: create dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_create_dn: crfs %ld try to add crfsdn cached nodes expirer\n", crfs_md_id);
    cbtimer_add(TASK_BRD_CBTIMER_LIST(task_brd_default_get()),
               (UINT8 *)"CRFS_EXPIRE_DN",
               CBTIMER_NEVER_EXPIRE,
               CRFS_CHECK_DN_EXPIRE_IN_NSEC,
               FI_crfs_expire_dn, crfs_md_id);

    return (EC_TRUE);
}

/**
*
*  add a disk to data node
*
**/
EC_BOOL crfs_add_disk(const UINT32 crfs_md_id, const UINT32 disk_no)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_add_disk: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_add_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_add_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_add_disk(CRFS_MD_DN(crfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_add_disk: add disk %u to dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_add_disk: add disk %u to dn done\n", (uint16_t)disk_no);
    return (EC_TRUE);
}

/**
*
*  delete a disk from data node
*
**/
EC_BOOL crfs_del_disk(const UINT32 crfs_md_id, const UINT32 disk_no)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_del_disk: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_del_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_del_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_del_disk(CRFS_MD_DN(crfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_del_disk: del disk %u from dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  mount a disk to data node
*
**/
EC_BOOL crfs_mount_disk(const UINT32 crfs_md_id, const UINT32 disk_no)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_mount_disk: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_mount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_mount_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_mount_disk(CRFS_MD_DN(crfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_mount_disk: mount disk %u to dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  umount a disk from data node
*
**/
EC_BOOL crfs_umount_disk(const UINT32 crfs_md_id, const UINT32 disk_no)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_umount_disk: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);
    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_umount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_umount_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_umount_disk(CRFS_MD_DN(crfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_umount_disk: umount disk %u from dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  open data node
*
**/
EC_BOOL crfs_open_dn(const UINT32 crfs_md_id, const CSTRING *root_dir)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_open_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_open_dn: try to open dn %s  ...\n", (char *)cstring_get_str(root_dir));

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR != CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_open_dn: dn was open\n");
        return (EC_FALSE);
    }

    CRFS_MD_DN(crfs_md) = crfsdn_open((char *)cstring_get_str(root_dir));
    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_open_dn: open dn with root dir %s failed\n", (char *)cstring_get_str(root_dir));
        return (EC_FALSE);
    }
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_open_dn: open dn %s\n", (char *)cstring_get_str(root_dir));
    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL crfs_close_dn(const UINT32 crfs_md_id)
{
    CRFS_MD   *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_close_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_close_dn: no dn was open\n");
        return (EC_FALSE);
    }

    crfsdn_close(CRFS_MD_DN(crfs_md));
    CRFS_MD_DN(crfs_md) = NULL_PTR;
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_close_dn: dn was closed\n");

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL crfs_export_dn(const UINT32 crfs_md_id, const CBYTES *cbytes, const CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;
    const CRFSNP_INODE *crfsnp_inode;

    UINT32   offset;
    UINT32   data_len;
    uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_export_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    data_len = DMIN(CBYTES_LEN(cbytes), CRFSNP_FNODE_FILESZ(crfsnp_fnode));

    if(CPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_export_dn: CBYTES_LEN %u or CRFSNP_FNODE_FILESZ %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CRFSNP_FNODE_FILESZ(crfsnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)data_len;

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    disk_no  = CRFSNP_INODE_DISK_NO(crfsnp_inode) ;
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == crfsdn_write_o(CRFS_MD_DN(crfs_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_export_dn: write %ld bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    //dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_export_dn: write %ld bytes to disk %u block %u page %u done\n",
    //                    data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL crfs_write_dn(const UINT32 crfs_md_id, const CBYTES *cbytes, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;
    CRFSNP_INODE *crfsnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_dn: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_dn: no dn was open\n");
        return (EC_FALSE);
    }

    crfsnp_fnode_init(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);

    if(EC_FALSE == crfsdn_write_p(CRFS_MD_DN(crfs_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_NOT_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = disk_no;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = block_no;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = page_no;

    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = CBYTES_LEN(cbytes);
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 1;

    return (EC_TRUE);
}

/**
*
*  write data node in cache
*
**/
EC_BOOL crfs_write_dn_cache(const UINT32 crfs_md_id, const CBYTES *cbytes, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;
    CRFSNP_INODE *crfsnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write_dn_cache: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_dn_cache: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_dn_cache: no dn was open\n");
        return (EC_FALSE);
    }

    crfsnp_fnode_init(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);

    if(EC_FALSE == crfsdn_write_p_cache(CRFS_MD_DN(crfs_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_dn_cache: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_IS_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = disk_no;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = block_no;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = page_no;

    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = CBYTES_LEN(cbytes);
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 1;

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL crfs_read_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode, CBYTES *cbytes)
{
    CRFS_MD *crfs_md;
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_read_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CRFSNP_FNODE_REPNUM(crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    disk_no  = CRFSNP_INODE_DISK_NO(crfsnp_inode) ;
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    //dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CRFS_0005);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CRFS_0006);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == crfsdn_read_p(CRFS_MD_DN(crfs_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
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
EC_BOOL crfs_write_e_dn(const UINT32 crfs_md_id, CRFSNP_FNODE *crfsnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;
    CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint32_t file_max_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write_e_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CPGB_CACHE_MAX_BYTE_SIZE <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_e_dn: offset %ld + buff len (or file size) %ld = %ld overflow\n",
                            (*offset), CBYTES_LEN(cbytes), (*offset) + CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_e_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    disk_no  = CRFSNP_INODE_DISK_NO(crfsnp_inode) ;
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CPGB_PAGE_BYTE_SIZE - 1) >> CPGB_PAGE_BIT_SIZE) << CPGB_PAGE_BIT_SIZE);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_e_dn: offset %ld overflow due to file max size is %u\n", (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(EC_FALSE == crfsdn_write_e(CRFS_MD_DN(crfs_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_e_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    (*offset) += max_len_t;
    if((*offset) > file_size)
    {
        /*update file size info*/
        CRFSNP_FNODE_FILESZ(crfsnp_fnode) = (uint32_t)(*offset);
    }

    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL crfs_read_e_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CRFS_MD *crfs_md;
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_read_e_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CRFSNP_FNODE_REPNUM(crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    disk_no  = CRFSNP_INODE_DISK_NO(crfsnp_inode) ;
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_e_dn: due to offset %ld >= file size %u\n", (*offset), file_size);
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

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_read_e_dn: file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    if(CBYTES_LEN(cbytes) < max_len_t)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CRFS_0007);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CRFS_0008);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == crfsdn_read_e(CRFS_MD_DN(crfs_md), disk_no, block_no, page_no, offset_t, max_len_t, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_read_e_dn: read %ld bytes from disk %u, block %u, offset %u failed\n",
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
STATIC_CAST static CRFSNP_FNODE * __crfs_reserve_npp(const UINT32 crfs_md_id, const CSTRING *file_path)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE *crfsnp_fnode;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__crfs_reserve_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_npp: npp was not open\n");
        return (NULL_PTR);
    }

    crfsnp_fnode = crfsnp_mgr_reserve(CRFS_MD_NPP(crfs_md), file_path);
    if(NULL_PTR == crfsnp_fnode)
    {
        /*try to retire & recycle some files*/
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "warn:__crfs_reserve_npp: no name node accept file %s, try to retire & recycle\n",
                            (char *)cstring_get_str(file_path));
        crfs_retire(crfs_md_id, (UINT32)CRFSNP_TRY_RETIRE_MAX_NUM, NULL_PTR);
        crfs_recycle(crfs_md_id, (UINT32)CRFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);

        /*try again*/
        crfsnp_fnode = crfsnp_mgr_reserve(CRFS_MD_NPP(crfs_md), file_path);
        if(NULL_PTR == crfsnp_fnode)/*Oops!*/
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_reserve_npp: no name node accept file %s\n",
                                (char *)cstring_get_str(file_path));
            return (NULL_PTR);
        }
    }

    return (crfsnp_fnode);
}


/**
*
*  release a fnode from name node
*
**/
STATIC_CAST static EC_BOOL __crfs_release_npp(const UINT32 crfs_md_id, const CSTRING *file_path)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__crfs_release_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_release_npp: npp was not open\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == crfsnp_mgr_release(CRFS_MD_NPP(crfs_md), file_path))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_release_npp: release file %s from npp failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  write a fnode to name node
*
**/
EC_BOOL crfs_write_npp(const UINT32 crfs_md_id, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(0 == CRFSNP_FNODE_REPNUM(crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_npp: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_write(CRFS_MD_NPP(crfs_md), file_path, crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_npp: no name node accept file %s with %u replicas writting\n",
                            (char *)cstring_get_str(file_path), CRFSNP_FNODE_REPNUM(crfsnp_fnode));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  read a fnode from name node
*
**/
EC_BOOL crfs_read_npp(const UINT32 crfs_md_id, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_read_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_read_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_read(CRFS_MD_NPP(crfs_md), file_path, crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_read_npp: crfsnp mgr read %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  update a fnode to name node
*
**/
EC_BOOL crfs_update_npp(const UINT32 crfs_md_id, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_update_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_update(CRFS_MD_NPP(crfs_md), file_path, crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_npp: no name node accept file %s with %u replicas updating\n",
                            (char *)cstring_get_str(file_path), CRFSNP_FNODE_REPNUM(crfsnp_fnode));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  renew a fnode to name node
*
**/
EC_BOOL crfs_renew(const UINT32 crfs_md_id, const CSTRING *file_path)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_renew: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew: obsolete interface\n");
    return (EC_FALSE);
}

/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL crfs_renew_http_header(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    char         *v;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_renew_http_header: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == crfs_read(crfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);

        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_header: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_update(crfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_header: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_renew_http_header: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));


    /*notify all waiters*/
    crfs_file_notify(crfs_md_id, file_path);
    return (EC_TRUE);
}

EC_BOOL crfs_renew_http_headers(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_renew_http_headers: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == crfs_read(crfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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

        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_renew_http_headers: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    cbytes_clean(&cbytes);
    if(EC_FALSE == chttp_rsp_encode(&chttp_rsp, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_headers: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_update(crfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_headers: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_renew_http_headers: '%s' renew headers done\n",
                (char *)CSTRING_STR(file_path));


    /*notify all waiters*/
    crfs_file_notify(crfs_md_id, file_path);
    return (EC_TRUE);
}

EC_BOOL crfs_renew_http_headers_with_token(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *token_str)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_renew_http_headers_with_token: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(EC_FALSE == crfs_renew_http_headers(crfs_md_id, file_path, cstrkv_mgr))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_http_headers_with_token: renew headers in '%s' failed\n", (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_is_empty(token_str))
    {
        crfs_file_unlock(crfs_md_id, file_path, token_str);
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_renew_http_headers_with_token: unlock '%s' done\n", (char *)CSTRING_STR(file_path));
    }

    return (EC_TRUE);
}

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL crfs_wait_http_header(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_wait_http_header: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == crfs_read(crfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_wait_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_wait_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_http_header: '%s' wait header '%s':'%s' => ready\n",
                    (char *)CSTRING_STR(file_path),
                    (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_file_wait(crfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_http_header: '%s' wait header '%s':'%s' => OK\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

    return (EC_TRUE);
}

EC_BOOL crfs_wait_http_headers(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_wait_http_headers: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == crfs_read(crfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_wait_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_wait_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
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

        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_http_headers: '%s' wait '%s':'%s' done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    chttp_rsp_clean(&chttp_rsp);

    if(EC_TRUE == (*header_ready))
    {
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_http_headers: '%s' headers => ready\n",
                (char *)CSTRING_STR(file_path));

        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_file_wait(crfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_http_headers: '%s' wait headers => OK\n",
                (char *)CSTRING_STR(file_path));

    return (EC_TRUE);
}

/**
*
*  delete file data from current dn
*
**/
STATIC_CAST static EC_BOOL __crfs_delete_dn(const UINT32 crfs_md_id, const CRFSNP_FNODE *crfsnp_fnode)
{
    CRFS_MD *crfs_md;
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__crfs_delete_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_delete_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(0 == CRFSNP_FNODE_REPNUM(crfsnp_fnode))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_delete_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    disk_no  = CRFSNP_INODE_DISK_NO(crfsnp_inode) ;
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    if(EC_FALSE == crfsdn_remove(CRFS_MD_DN(crfs_md), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u failed\n", file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u done\n", file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

EC_BOOL crfs_delete_dn(const UINT32 crfs_md_id, const UINT32 crfsnp_id, const CRFSNP_ITEM *crfsnp_item)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/


    if(NULL_PTR != crfsnp_item)
    {
        if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
        {
            if(EC_FALSE == __crfs_delete_dn(crfs_md_id, CRFSNP_ITEM_FNODE(crfsnp_item)))
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_dn: delete regular file from dn failed\n");
                return (EC_FALSE);
            }
            return (EC_TRUE);
        }

        /*Oops! not implement or not support yet ...*/
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_dn: crfsnp_item %p dflag flag 0x%x is unknown\n",
                            crfsnp_item, CRFSNP_ITEM_DIR_FLAG(crfsnp_item));
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_check_path_has_wildcard(const CSTRING *path)
{
    const char     *str;
    UINT32          len;

    if(NULL_PTR == path)
    {
        return (EC_FALSE);
    }

    str = (const char *)cstring_get_str(path);
    len = cstring_get_len(path);
    if(1 >= len || '/' != (*str))
    {
        return (EC_FALSE);
    }

    /*now len > 1*/
    if('*' == str[ len - 1 ] && '/' == str[ len - 2 ])
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != strstr(str, (const char *)"/*/"))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/**
*
*  delete a file
*
**/
EC_BOOL crfs_delete_file(const UINT32 crfs_md_id, const CSTRING *path)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_file: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(EC_TRUE == __crfs_check_path_has_wildcard(path))
    {
        return crfs_delete_file_wildcard(crfs_md_id, path);
    }

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_delete_file: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_file: crfs_md_id %ld, path %s ...\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == crfsnp_mgr_umount(CRFS_MD_NPP(crfs_md), path, CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_file: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_file: crfs_md_id %ld, path %s done\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    /*force to unlock the possible locked-file*/
    /*__crfs_file_unlock(crfs_md_id, path, NULL_PTR);*/
    return (EC_TRUE);
}

EC_BOOL crfs_delete_file_no_lock(const UINT32 crfs_md_id, const CSTRING *path)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_file_no_lock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_delete_file_no_lock: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_file_no_lock: crfs_md_id %ld, path %s ...\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == crfsnp_mgr_umount(CRFS_MD_NPP(crfs_md), path, CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_file_no_lock: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_file_no_lock: crfs_md_id %ld, path %s done\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfs_delete_file_wildcard(const UINT32 crfs_md_id, const CSTRING *path)
{
    CRFS_MD      *crfs_md;
    MOD_NODE      mod_node;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_file_wildcard: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_delete_file_wildcard: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_file_wildcard: crfs_md_id %ld, path %s ...\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == crfsnp_mgr_umount_wildcard(CRFS_MD_NPP(crfs_md), path, CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_delete_file_wildcard: umount %.*s failed or terminated\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));

        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_file_wildcard: crfs_md_id %ld, path %s succ\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    /*force to unlock the possible locked-file*/
    /*__crfs_file_unlock(crfs_md_id, path, NULL_PTR);*/

    /*try to delete next matched file*/
    MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_md_id;

    task_p2p_no_wait(crfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &mod_node,
             NULL_PTR,
             FI_crfs_delete_file_wildcard, CMPI_ERROR_MODI, path);

    return (EC_TRUE);
}

/**
*
*  delete a dir from all npp and all dn
*
**/
EC_BOOL crfs_delete_dir(const UINT32 crfs_md_id, const CSTRING *path)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_dir: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(EC_TRUE == __crfs_check_path_has_wildcard(path))
    {
        return crfs_delete_dir_wildcard(crfs_md_id, path);
    }

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_delete_dir: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_dir: crfs_md_id %ld, path %s ...\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == crfsnp_mgr_umount(CRFS_MD_NPP(crfs_md), path, CRFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_dir: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_dir: crfs_md_id %ld, path %s done\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfs_delete_dir_no_lock(const UINT32 crfs_md_id, const CSTRING *path)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_dir_no_lock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_delete_dir_no_lock: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_dir_no_lock: crfs_md_id %ld, path %s ...\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == crfsnp_mgr_umount(CRFS_MD_NPP(crfs_md), path, CRFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_dir_no_lock: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_dir_no_lock: crfs_md_id %ld, path %s done\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfs_delete_dir_wildcard(const UINT32 crfs_md_id, const CSTRING *path)
{
    CRFS_MD      *crfs_md;
    MOD_NODE      mod_node;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_dir_wildcard: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_delete_dir_wildcard: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_dir_wildcard: crfs_md_id %ld, path %s ...\n",
                        crfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == crfsnp_mgr_umount_wildcard(CRFS_MD_NPP(crfs_md), path, CRFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_dir_wildcard: umount %.*s failed or terminated\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_delete_dir_wildcard: crfs_md_id %ld, path %s succ\n",
                        crfs_md_id, (char *)cstring_get_str(path));

     /*try to delete next matched file*/
    MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&mod_node) = crfs_md_id;

    task_p2p_no_wait(crfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &mod_node,
             NULL_PTR,
             FI_crfs_delete_dir_wildcard, CMPI_ERROR_MODI, path);

    return (EC_TRUE);
}

/**
*
*  delete a file or dir from all npp and all dn
*
**/
EC_BOOL crfs_delete(const UINT32 crfs_md_id, const CSTRING *path, const UINT32 dflag)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return crfs_delete_file(crfs_md_id, path);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return crfs_delete_dir(crfs_md_id, path);
    }

    if(CRFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        crfs_delete_file(crfs_md_id, path);
        crfs_delete_dir(crfs_md_id, path);

        return (EC_TRUE);
    }

    dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete: crfs_md_id %ld, path [invalid 0x%lx] %s\n",
                        crfs_md_id, dflag, (char *)cstring_get_str(path));

    return (EC_FALSE);
}

EC_BOOL crfs_delete_no_lock(const UINT32 crfs_md_id, const CSTRING *path, const UINT32 dflag)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_no_lock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return crfs_delete_file_no_lock(crfs_md_id, path);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return crfs_delete_dir_no_lock(crfs_md_id, path);
    }

    if(CRFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        crfs_delete_file_no_lock(crfs_md_id, path);
        crfs_delete_dir_no_lock(crfs_md_id, path);

        return (EC_TRUE);
    }

    dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_no_lock: crfs_md_id %ld, path [invalid 0x%lx] %s\n",
                        crfs_md_id, dflag, (char *)cstring_get_str(path));

    return (EC_FALSE);
}

/**
*
*  update a file
*  (atomic operation)
*
**/
EC_BOOL crfs_update(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_update: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(EC_FALSE == crfs_update_no_lock(crfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update: update file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_update: update file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL crfs_update_no_lock(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_update_no_lock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(EC_FALSE == crfs_read_npp(crfs_md_id, file_path, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == crfs_write_no_lock(crfs_md_id, file_path, cbytes))
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_no_lock: write file %s failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_update_no_lock: write file %s done\n", (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }


    /*file exist, update it*/
    if(EC_FALSE == crfs_delete_no_lock(crfs_md_id, file_path, CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_no_lock: delete old file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_update_no_lock: delete old file %s done\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == crfs_write_no_lock(crfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_no_lock: write new file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_update_no_lock: write new file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL crfs_update_with_token(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *token_str)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_update_with_token: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(EC_FALSE == crfs_update(crfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_update_with_token: update '%s' failed\n", (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_is_empty(token_str))
    {
        crfs_file_unlock(crfs_md_id, file_path, token_str);
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_update_with_token: unlock '%s' done\n", (char *)CSTRING_STR(file_path));
    }

    return (EC_TRUE);
}

/**
*
*  query a file
*
**/
EC_BOOL crfs_qfile(const UINT32 crfs_md_id, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item, CRFSNP_KEY *crfsnp_key)
{
    CRFS_MD      *crfs_md;
    CRFSNP_ITEM  *crfsnp_item_src;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qfile: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qfile: npp was not open\n");
        return (EC_FALSE);
    }

    crfsnp_item_src = crfsnp_mgr_search_item(CRFS_MD_NPP(crfs_md),
                                             (uint32_t)cstring_get_len(file_path),
                                             cstring_get_str(file_path),
                                             CRFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == crfsnp_item_src)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qfile: query file %s from npp failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*clone*/
    if(NULL_PTR != crfsnp_item)
    {
        crfsnp_item_clone(crfsnp_item_src, crfsnp_item);
    }

    if(NULL_PTR != crfsnp_key)
    {
        crfsnp_key_clone(CRFSNP_ITEM_KEY(crfsnp_item_src), crfsnp_key);
    }

    return (EC_TRUE);
}

/**
*
*  query a dir
*
**/
EC_BOOL crfs_qdir(const UINT32 crfs_md_id, const CSTRING *dir_path, CRFSNP_ITEM  *crfsnp_item, CRFSNP_KEY *crfsnp_key)
{
    CRFS_MD      *crfs_md;
    CRFSNP_ITEM  *crfsnp_item_src;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qdir: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qdir: npp was not open\n");
        return (EC_FALSE);
    }

    crfsnp_item_src = crfsnp_mgr_search_item(CRFS_MD_NPP(crfs_md),
                                             (uint32_t)cstring_get_len(dir_path),
                                             cstring_get_str(dir_path),
                                             CRFSNP_ITEM_FILE_IS_DIR);
    if(NULL_PTR == crfsnp_item_src)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qdir: query dir %s from npp failed\n",
                            (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    /*clone*/
    if(NULL_PTR != crfsnp_item)
    {
        crfsnp_item_clone(crfsnp_item_src, crfsnp_item);
    }

    if(NULL_PTR != crfsnp_key)
    {
        crfsnp_key_clone(CRFSNP_ITEM_KEY(crfsnp_item_src), crfsnp_key);
    }

    return (EC_TRUE);
}

/**
*
*  query and list full path of a file or dir
*
**/
EC_BOOL crfs_qlist_path(const UINT32 crfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qlist_path: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_path: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_list_path(CRFS_MD_NPP(crfs_md), file_path, path_cstr_vec))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qlist_path: list path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query and list full path of a file or dir of one np
*
**/
EC_BOOL crfs_qlist_path_of_np(const UINT32 crfs_md_id, const CSTRING *file_path, const UINT32 crfsnp_id, CVECTOR  *path_cstr_vec)
{
    CRFS_MD      *crfs_md;
    uint32_t      crfsnp_id_t;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qlist_path_of_np: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_path_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    crfsnp_id_t = (uint32_t)crfsnp_id;

    if(EC_FALSE == crfsnp_mgr_list_path_of_np(CRFS_MD_NPP(crfs_md), file_path, crfsnp_id_t, path_cstr_vec))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qlist_path_of_np: list path '%s' of np %u failed\n",
                            (char *)cstring_get_str(file_path), crfsnp_id_t);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query and list short name of a file or dir
*
**/
EC_BOOL crfs_qlist_seg(const UINT32 crfs_md_id, const CSTRING *file_path, CVECTOR  *seg_cstr_vec)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qlist_seg: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_seg: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_list_seg(CRFS_MD_NPP(crfs_md), file_path, seg_cstr_vec))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qlist_seg: list seg of path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query and list short name of a file or dir of one np
*
**/
EC_BOOL crfs_qlist_seg_of_np(const UINT32 crfs_md_id, const CSTRING *file_path, const UINT32 crfsnp_id, CVECTOR  *seg_cstr_vec)
{
    CRFS_MD      *crfs_md;
    uint32_t      crfsnp_id_t;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qlist_seg_of_np: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_seg_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    crfsnp_id_t = (uint32_t)crfsnp_id;

    if(EC_FALSE == crfsnp_mgr_list_seg_of_np(CRFS_MD_NPP(crfs_md), file_path, crfsnp_id_t, seg_cstr_vec))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qlist_seg_of_np: list seg of path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_cat_path(const CRFSNP_ITEM *crfsnp_item, CSTRING *des_path)
{
    cstring_rtrim(des_path, (UINT8)'/');
    cstring_append_chars(des_path, (UINT32)1, (const UINT8 *)"/", LOC_CRFS_0009);
    cstring_append_chars(des_path, CRFSNP_ITEM_KLEN(crfsnp_item), CRFSNP_ITEM_KNAME(crfsnp_item), LOC_CRFS_0010);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_qlist_tree(CRFSNP_DIT_NODE *crfsnp_dit_node, CRFSNP *crfsnp, CRFSNP_ITEM *crfsnp_item, const uint32_t node_pos)
{
    if(CRFSNP_ITEM_IS_NOT_USED == CRFSNP_ITEM_USED_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_qlist_tree: item was not used\n");
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        CVECTOR *path_cstr_vec;
        CSTRING *base_dir;
        CSTRING *full_path;

        base_dir      = CRFSNP_DIT_NODE_ARG(crfsnp_dit_node, 1);
        path_cstr_vec = CRFSNP_DIT_NODE_ARG(crfsnp_dit_node, 2);

        full_path = cstring_new(cstring_get_str(base_dir), LOC_CRFS_0011);
        if(NULL_PTR == full_path)
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_qlist_tree: new cstring failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == cstack_walk(CRFSNP_DIT_NODE_STACK(crfsnp_dit_node), (void *)full_path, (CSTACK_DATA_DATA_WALKER)__crfs_cat_path))
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_qlist_tree: walk stack failed\n");

            cstring_free(full_path);
            return (EC_FALSE);
        }

        cvector_push(path_cstr_vec, (void *)full_path);
        return (EC_TRUE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        return (EC_TRUE);
    }

    dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_file_expire: invalid item dflag %u at node pos %u\n",
                        CRFSNP_ITEM_DIR_FLAG(crfsnp_item), node_pos);
    return (EC_FALSE);
}

/**
*
*  query and list full path of a file or  all files under a dir recursively
*  (looks like shell command: tree)
*
**/
EC_BOOL crfs_qlist_tree(const UINT32 crfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CRFS_MD        *crfs_md;
    CRFSNP_DIT_NODE crfsnp_dit_node;
    CSTRING        *base_dir;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qlist_tree: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_tree: npp was not open\n");
        return (EC_FALSE);
    }

    base_dir = cstring_new(cstring_get_str(file_path), LOC_CRFS_0012);
    if(NULL_PTR == base_dir)
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_tree: new cstring failed\n");
        return (EC_FALSE);
    }

    cstring_rtrim(base_dir, (UINT8)'/');
    cstring_erase_tail_until(base_dir, (UINT8)'/');

    crfsnp_dit_node_init(&crfsnp_dit_node);

    CRFSNP_DIT_NODE_HANDLER(&crfsnp_dit_node) = __crfs_qlist_tree;
    CRFSNP_DIT_NODE_ARG(&crfsnp_dit_node, 0)  = (void *)crfs_md_id;
    CRFSNP_DIT_NODE_ARG(&crfsnp_dit_node, 1)  = (void *)base_dir;
    CRFSNP_DIT_NODE_ARG(&crfsnp_dit_node, 2)  = (void *)path_cstr_vec;

    if(EC_FALSE == crfsnp_mgr_walk(CRFS_MD_NPP(crfs_md), file_path, CRFSNP_ITEM_FILE_IS_ANY, &crfsnp_dit_node))
    {
        cstring_free(base_dir);
        crfsnp_dit_node_clean(&crfsnp_dit_node);

        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qlist_path: list path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfs_qlist_path: after walk, stack is:\n");
        cstack_print(LOGSTDOUT, CRFSNP_DIT_NODE_STACK(&crfsnp_dit_node), (CSTACK_DATA_DATA_PRINT)crfsnp_item_and_key_print);
    }

    cstring_free(base_dir);
    crfsnp_dit_node_clean(&crfsnp_dit_node);
    return (EC_TRUE);
}

/**
*
*  query and list full path of a file or all files under a dir of one np
*  (looks like shell command: tree)
*
**/
EC_BOOL crfs_qlist_tree_of_np(const UINT32 crfs_md_id, const UINT32 crfsnp_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CRFS_MD        *crfs_md;

    CRFSNP_DIT_NODE crfsnp_dit_node;
    CSTRING        *base_dir;
    uint32_t        crfsnp_id_t;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_qlist_tree_of_np: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_tree_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    crfsnp_id_t = (uint32_t)crfsnp_id;

    base_dir = cstring_new(cstring_get_str(file_path), LOC_CRFS_0013);
    if(NULL_PTR == base_dir)
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_qlist_tree_of_np: new cstring failed\n");
        return (EC_FALSE);
    }

    cstring_rtrim(base_dir, (UINT8)'/');
    cstring_erase_tail_until(base_dir, (UINT8)'/');

    crfsnp_dit_node_init(&crfsnp_dit_node);

    CRFSNP_DIT_NODE_HANDLER(&crfsnp_dit_node) = __crfs_qlist_tree;
    CRFSNP_DIT_NODE_ARG(&crfsnp_dit_node, 0)  = (void *)crfs_md_id;
    CRFSNP_DIT_NODE_ARG(&crfsnp_dit_node, 1)  = (void *)file_path;
    CRFSNP_DIT_NODE_ARG(&crfsnp_dit_node, 2)  = (void *)path_cstr_vec;

    if(EC_FALSE == crfsnp_mgr_walk_of_np(CRFS_MD_NPP(crfs_md), crfsnp_id_t, file_path, CRFSNP_ITEM_FILE_IS_ANY, &crfsnp_dit_node))
    {
        cstring_free(base_dir);
        crfsnp_dit_node_clean(&crfsnp_dit_node);

        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_qlist_tree_of_np: list tree of path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfs_qlist_tree_of_np: after walk, stack is:\n");
        cstack_print(LOGSTDOUT, CRFSNP_DIT_NODE_STACK(&crfsnp_dit_node), (CSTACK_DATA_DATA_PRINT)crfsnp_item_print);
    }

    cstring_free(base_dir);
    crfsnp_dit_node_clean(&crfsnp_dit_node);
    return (EC_TRUE);
}

/**
*
*  flush name node pool
*
**/
EC_BOOL crfs_flush_npp(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_flush_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_flush_npp: npp was not open\n");
        return (EC_TRUE);
    }

    if(EC_FALSE == crfsnp_mgr_flush(CRFS_MD_NPP(crfs_md)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_flush_npp: flush failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_flush_npp: flush done\n");
    return (EC_TRUE);
}

/**
*
*  flush data node
*
*
**/
EC_BOOL crfs_flush_dn(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_flush_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_flush_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_flush(CRFS_MD_DN(crfs_md)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_flush_dn: flush dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_flush_dn: flush dn done\n");
    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL crfs_file_num(const UINT32 crfs_md_id, const CSTRING *path_cstr, UINT32 *file_num)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_num: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_file_num: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_file_num(CRFS_MD_NPP(crfs_md), path_cstr, file_num))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_num: get file num of path '%s' failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL crfs_file_size(const UINT32 crfs_md_id, const CSTRING *path_cstr, uint64_t *file_size)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_size: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_file_size: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_file_size(CRFS_MD_NPP(crfs_md), path_cstr, file_size))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_size: crfsnp mgr get size of %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_file_size: file %s, size %ld\n",
                             (char *)cstring_get_str(path_cstr),
                             (*file_size));
    return (EC_TRUE);
}

/**
*
*  set file expired time to current time
*
**/
EC_BOOL crfs_file_expire(const UINT32 crfs_md_id, const CSTRING *path_cstr)
{
    CRFS_MD      *crfs_md;
    CSTRING       key;
    CSTRING       val;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_expire: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_file_expire: npp was not open\n");
        return (EC_FALSE);
    }

    cstring_init(&key, (const UINT8 *)"Expires");
    cstring_init(&val, (const UINT8 *)c_http_time(task_brd_default_get_time()));

    if(EC_FALSE == crfs_renew_http_header(crfs_md_id, path_cstr, &key, &val))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_expire: expire %s failed\n", (char *)cstring_get_str(path_cstr));
        cstring_clean(&key);
        cstring_clean(&val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_file_expire: expire %s done\n", (char *)cstring_get_str(path_cstr));
    cstring_clean(&key);
    cstring_clean(&val);
    return (EC_TRUE);
}

/**
*
*  get file md5sum of specific file given full path name
*
**/
EC_BOOL crfs_file_md5sum(const UINT32 crfs_md_id, const CSTRING *path_cstr, CMD5_DIGEST *md5sum)
{
    CRFS_MD      *crfs_md;
    CBYTES        cbytes;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_md5sum: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_file_md5sum: npp was not open\n");
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);

    if(EC_FALSE == crfs_read(crfs_md_id, path_cstr, &cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_md5sum: read %s failed\n", (char *)cstring_get_str(path_cstr));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    cmd5_sum((uint32_t)CBYTES_LEN(&cbytes), CBYTES_BUF(&cbytes), CMD5_DIGEST_SUM(md5sum));
    cbytes_clean(&cbytes);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_file_md5sum: file %s, md5 %s\n",
                             (char *)cstring_get_str(path_cstr),
                             cmd5_digest_hex_str(md5sum));
    return (EC_TRUE);
}

/**
*
*  mkdir in current name node pool
*
**/
EC_BOOL crfs_mkdir(const UINT32 crfs_md_id, const CSTRING *path_cstr)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_mkdir: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_mkdir: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_mkdir(CRFS_MD_NPP(crfs_md), path_cstr))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_mkdir: mkdir '%s' failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  search in current name node pool
*
**/
EC_BOOL crfs_search(const UINT32 crfs_md_id, const CSTRING *path_cstr, const UINT32 dflag)
{
    CRFS_MD      *crfs_md;
    uint32_t      crfsnp_id;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_search: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_search: crfs_md_id %ld, path %s, dflag %lx\n", crfs_md_id, (char *)cstring_get_str(path_cstr), dflag);

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_search: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_search(CRFS_MD_NPP(crfs_md), (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag, &crfsnp_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_search: search '%s' with dflag %lx failed\n", (char *)cstring_get_str(path_cstr), dflag);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_recycle_of_np(const UINT32 crfs_md_id, const uint32_t crfsnp_id, const UINT32 max_num, UINT32 *complete_num)
{
    CRFS_MD      *crfs_md;
    CRFSNP_RECYCLE_DN crfsnp_recycle_dn;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:__crfs_recycle_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    CRFSNP_RECYCLE_DN_ARG1(&crfsnp_recycle_dn)   = crfs_md_id;
    CRFSNP_RECYCLE_DN_FUNC(&crfsnp_recycle_dn)   = crfs_release_dn;

    if(EC_FALSE == crfsnp_mgr_recycle_np(CRFS_MD_NPP(crfs_md), crfsnp_id, max_num, NULL_PTR, &crfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_recycle_of_np: recycle np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_recycle_of_np: recycle np %u done where complete %ld\n",
                    crfsnp_id, (*complete_num));

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL crfs_recycle(const UINT32 crfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num)
{
    CRFS_MD      *crfs_md;
    CRFSNP_MGR   *crfsnp_mgr;

    UINT32        complete_recycle_num;
    uint32_t      crfsnp_id;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_recycle: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_recycle: recycle beg\n");

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfsnp_mgr = CRFS_MD_NPP(crfs_md);
    if(NULL_PTR == crfsnp_mgr)
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_recycle: npp was not open\n");
        return (EC_FALSE);
    }

    complete_recycle_num = 0;/*initialization*/

    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        __crfs_recycle_of_np(crfs_md_id, crfsnp_id, max_num_per_np, &complete_recycle_num);
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_recycle: recycle np %u done\n", crfsnp_id);
    }

    dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_recycle: recycle end where complete %ld\n", complete_recycle_num);

    if(NULL_PTR != complete_num)
    {
        (*complete_num) = complete_recycle_num;
    }
    return (EC_TRUE);
}

/**
*
*  check file content on data node
*
**/
EC_BOOL crfs_check_file_content(const UINT32 crfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr)
{
    CRFS_MD *crfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_check_file_content: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_content: dn is null\n");
        return (EC_FALSE);
    }

    ASSERT(EC_TRUE == c_check_is_uint16_t(disk_no));
    ASSERT(EC_TRUE == c_check_is_uint16_t(block_no));
    ASSERT(EC_TRUE == c_check_is_uint16_t(page_no));

    cbytes = cbytes_new(file_size);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_content: new crfs buff with len %ld failed\n", file_size);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_read_p(CRFS_MD_DN(crfs_md), (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no, file_size,
                                  CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_content: read %ld bytes from disk %u, block %u, page %u failed\n",
                            file_size, (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < cstring_get_len(file_content_cstr))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_content: read %ld bytes from disk %u, block %u, page %u to buff len %u less than cstring len %u to compare\n",
                            file_size, (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no,
                            (uint32_t)CBYTES_LEN(cbytes), (uint32_t)cstring_get_len(file_content_cstr));
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
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_content: char at pos %ld not matched\n", pos);
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
EC_BOOL crfs_check_file_is(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *file_content)
{
    CRFS_MD *crfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_check_file_is: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_is: dn is null\n");
        return (EC_FALSE);
    }

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_is: new cbytes failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_read(crfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_is: read file %s failed\n", (char *)cstring_get_str(file_path));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) != CBYTES_LEN(file_content))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_is: mismatched len: file %s read len %ld which should be %ld\n",
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
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_check_file_is: char at pos %ld not matched\n", pos);
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
*  show name node lru list if it is npp
*
*
**/
EC_BOOL crfs_show_npp_lru_list(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_npp_lru_list: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    crfsnp_mgr_print_lru_list(log, CRFS_MD_NPP(crfs_md));

    return (EC_TRUE);
}

/**
*
*  show name node del list if it is npp
*
*
**/
EC_BOOL crfs_show_npp_del_list(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_npp_del_list: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    crfsnp_mgr_print_del_list(log, CRFS_MD_NPP(crfs_md));

    return (EC_TRUE);
}

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL crfs_show_npp(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_npp: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    crfsnp_mgr_print(log, CRFS_MD_NPP(crfs_md));

    return (EC_TRUE);
}

/*for debug only*/
EC_BOOL crfs_show_dn_no_lock(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_dn_no_lock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    crfsdn_print(log, CRFS_MD_DN(crfs_md));

    return (EC_TRUE);
}

/**
*
*  show crfsdn info if it is dn
*
*
**/
EC_BOOL crfs_show_dn(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    crfsdn_print(log, CRFS_MD_DN(crfs_md));

    return (EC_TRUE);
}

/*debug*/
EC_BOOL crfs_show_cached_np(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_cached_np: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_cached_np(log, CRFS_MD_NPP(crfs_md)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_cached_np: show cached np but failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_show_cached_np_lru_list(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_cached_np_lru_list: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_cached_np_lru_list(log, CRFS_MD_NPP(crfs_md)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_cached_np_lru_list: show cached np but failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_show_cached_np_del_list(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_cached_np_del_list: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_cached_np_del_list(log, CRFS_MD_NPP(crfs_md)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_cached_np_del_list: show cached np but failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_show_specific_np(const UINT32 crfs_md_id, const UINT32 crfsnp_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_specific_np: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(crfsnp_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_specific_np: crfsnp_id %ld is invalid\n", crfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_np(log, CRFS_MD_NPP(crfs_md), (uint32_t)crfsnp_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_specific_np: show np %ld but failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_show_specific_np_lru_list(const UINT32 crfs_md_id, const UINT32 crfsnp_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_specific_np_lru_list: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(crfsnp_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_specific_np_lru_list: crfsnp_id %ld is invalid\n", crfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_np_lru_list(log, CRFS_MD_NPP(crfs_md), (uint32_t)crfsnp_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_specific_np_lru_list: show np %ld but failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_show_specific_np_del_list(const UINT32 crfs_md_id, const UINT32 crfsnp_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_specific_np_del_list: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(crfsnp_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_specific_np_del_list: crfsnp_id %ld is invalid\n", crfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_np_del_list(log, CRFS_MD_NPP(crfs_md), (uint32_t)crfsnp_id))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_show_specific_np_del_list: show np %ld but failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_show_path_depth(const UINT32 crfs_md_id, const CSTRING *path, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_path_depth: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "error:crfs_show_path_depth: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_path_depth(log, CRFS_MD_NPP(crfs_md), path))
    {
        sys_log(log, "error:crfs_show_path_depth: show path %s in depth failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_show_path(const UINT32 crfs_md_id, const CSTRING *path, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_show_path: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        sys_log(log, "error:crfs_show_path: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_show_path(log, CRFS_MD_NPP(crfs_md), path))
    {
        sys_log(log, "error:crfs_show_path: show path %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_expire_dn(const UINT32 crfs_md_id)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_expire_dn: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_DN(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "info:crfs_expire_dn: no dn was open\n");
        return (EC_TRUE);/*return EC_FALSE will trigger cbtimer drop. ref cbtimer_handle*/
    }

    if(EC_FALSE == crfsdn_expire_open_nodes(CRFS_MD_DN(crfs_md)))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_expire_dn: expire open nodes failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


STATIC_CAST static EC_BOOL __crfs_retire_of_np(const UINT32 crfs_md_id, const uint32_t crfsnp_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CRFS_MD      *crfs_md;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(NULL_PTR == CRFS_MD_NPP(crfs_md))
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:__crfs_retire_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_mgr_retire_np(CRFS_MD_NPP(crfs_md), crfsnp_id, expect_retire_num, complete_retire_num))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_retire_of_np: retire np %u failed where expect retire num %ld\n",
                                            crfsnp_id, expect_retire_num);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  retire regular/big files created before n seconds and dirs which are empty without file
*  note:
*    expect_retire_num is for per crfsnp but not all crfsnp(s)
*
**/
EC_BOOL crfs_retire(const UINT32 crfs_md_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CRFS_MD      *crfs_md;
    CRFSNP_MGR   *crfsnp_mgr;
    uint32_t      crfsnp_id;

    UINT32   total_num;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_retire: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfsnp_mgr = CRFS_MD_NPP(crfs_md);
    if(NULL_PTR == crfsnp_mgr)
    {
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "warn:crfs_retire: npp was not open\n");
        return (EC_FALSE);
    }

    for(crfsnp_id = 0, total_num = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        UINT32   complete_num;

        __crfs_retire_of_np(crfs_md_id, crfsnp_id, expect_retire_num, &complete_num);
        total_num += complete_num;

        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_retire: retire np %u done wher expect retire num %ld, complete %ld\n",
                                crfsnp_id, expect_retire_num, complete_num);
    }

    if(NULL_PTR != complete_retire_num)
    {
        (*complete_retire_num) = total_num;
    }

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_retire: retire done where complete %ld\n", total_num);

    return (EC_TRUE);
}

/*------------------------------------------------ interface for file wait ------------------------------------------------*/
CRFS_WAIT_FILE *crfs_wait_file_new()
{
    CRFS_WAIT_FILE *crfs_wait_file;
    alloc_static_mem(MM_CRFS_WAIT_FILE, &crfs_wait_file, LOC_CRFS_0014);
    if(NULL_PTR != crfs_wait_file)
    {
        crfs_wait_file_init(crfs_wait_file);
    }
    return (crfs_wait_file);
}

EC_BOOL crfs_wait_file_init(CRFS_WAIT_FILE *crfs_wait_file)
{
    cstring_init(CRFS_WAIT_FILE_NAME(crfs_wait_file), NULL_PTR);

    clist_init(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file), MM_MOD_NODE, LOC_CRFS_0015);

    return (EC_TRUE);
}

EC_BOOL crfs_wait_file_clean(CRFS_WAIT_FILE *crfs_wait_file)
{
    cstring_clean(CRFS_WAIT_FILE_NAME(crfs_wait_file));
    clist_clean(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file), (CLIST_DATA_DATA_CLEANER)mod_node_free);
    return (EC_TRUE);
}

EC_BOOL crfs_wait_file_free(CRFS_WAIT_FILE *crfs_wait_file)
{
    if(NULL_PTR != crfs_wait_file)
    {
        crfs_wait_file_clean(crfs_wait_file);
        free_static_mem(MM_CRFS_WAIT_FILE, crfs_wait_file, LOC_CRFS_0016);
    }
    return (EC_TRUE);
}

int crfs_wait_file_cmp(const CRFS_WAIT_FILE *crfs_wait_file_1st, const CRFS_WAIT_FILE *crfs_wait_file_2nd)
{
    return cstring_cmp(CRFS_WAIT_FILE_NAME(crfs_wait_file_1st), CRFS_WAIT_FILE_NAME(crfs_wait_file_2nd));
}

void crfs_wait_file_print(LOG *log, const CRFS_WAIT_FILE *crfs_wait_file)
{
    if(NULL_PTR != crfs_wait_file)
    {
        sys_log(log, "crfs_wait_file_print %p: file %s, owner list: ",
                        crfs_wait_file,
                        (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file)
                        );
        clist_print(log, CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file),(CLIST_DATA_DATA_PRINT)mod_node_print);
    }

    return;
}

void crfs_wait_files_print(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_wait_files_print: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crb_tree_print(log, CRFS_MD_WAIT_FILES(crfs_md));

    return;
}

EC_BOOL crfs_wait_file_name_set(CRFS_WAIT_FILE *crfs_wait_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CRFS_WAIT_FILE_NAME(crfs_wait_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_wait_file_owner_cmp(const MOD_NODE *mod_node, const UINT32 tcid)
{
    if(MOD_NODE_TCID(mod_node) == tcid)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL crfs_wait_file_owner_push(CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tcid)
{
    CLIST *owner_list;

    owner_list = CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file);
    if(
       CMPI_ERROR_TCID != tcid
    && CMPI_ANY_TCID != tcid
    && NULL_PTR == clist_search_data_front(owner_list, (void *)tcid, (CLIST_DATA_DATA_CMP)__crfs_wait_file_owner_cmp)
    )
    {
        MOD_NODE *mod_node;

        mod_node = mod_node_new();
        if(NULL_PTR == mod_node)
        {
            dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_wait_file_owner_push: new mod_node failed\n");
            return (EC_FALSE);
        }

        MOD_NODE_TCID(mod_node) = tcid;
        MOD_NODE_COMM(mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(mod_node) = 0;/*SUPER modi always be 0*/

        clist_push_back(owner_list, (void *)mod_node);

        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_push: push %s to file '%.*s'\n",
                    c_word_to_ipv4(tcid), (uint32_t)CRFS_WAIT_FILE_NAME_LEN(crfs_wait_file), CRFS_WAIT_FILE_NAME_STR(crfs_wait_file));
    }

    return (EC_TRUE);
}

/**
*
*  wakeup remote waiter (over http)
*
**/
EC_BOOL crfs_wait_file_owner_wakeup (const UINT32 crfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    CRFS_MD     *crfs_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_wait_file_owner_wakeup: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/cond_wakeup");
    cstring_append_cstr(uri, path);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_wakeup: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL crfs_wait_file_owner_notify_over_http (CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file)))
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
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one crfs module*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE   *mod_node;
            TASKS_CFG  *remote_tasks_cfg;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), MOD_NODE_TCID(mod_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "info:crfs_wait_file_owner_notify: not found tasks_cfg of node %s\n", c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
                mod_node_free(mod_node);
                continue;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, &recv_mod_node,
                        &ret,
                        FI_crfs_wait_file_owner_wakeup,
                        CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                        TASKS_CFG_CSRVPORT(remote_tasks_cfg),
                        CRFS_WAIT_FILE_NAME(crfs_wait_file));

            dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL crfs_wait_file_owner_notify_over_bgn (CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file)))
    {
        TASK_MGR *task_mgr;
        EC_BOOL   ret; /*ignore it*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE *mod_node;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node, &ret, FI_super_cond_wakeup, CMPI_ERROR_MODI, tag, CRFS_WAIT_FILE_NAME(crfs_wait_file));

            dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL crfs_wait_file_owner_notify(CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return crfs_wait_file_owner_notify_over_http(crfs_wait_file, tag);
    }

    return crfs_wait_file_owner_notify_over_bgn(crfs_wait_file, tag);
}

/**
*
*  cancel remote waiter (over http)
*
**/
EC_BOOL crfs_wait_file_owner_cancel (const UINT32 crfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    CRFS_MD     *crfs_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_wait_file_owner_cancel: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/cond_terminate");
    cstring_append_cstr(uri, path);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_cancel: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_wait_file_owner_cancel: terminate '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_cancel: terminate '%.*s' on %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}
EC_BOOL crfs_wait_file_owner_terminate_over_http (CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file)))
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
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one crfs module*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE   *mod_node;
            TASKS_CFG  *remote_tasks_cfg;

            /*note : after terminate owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), MOD_NODE_TCID(mod_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "info:crfs_wait_file_owner_terminate: not found tasks_cfg of node %s\n", c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
                mod_node_free(mod_node);
                continue;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, &recv_mod_node,
                        &ret,
                        FI_crfs_wait_file_owner_cancel,
                        CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                        TASKS_CFG_CSRVPORT(remote_tasks_cfg),
                        CRFS_WAIT_FILE_NAME(crfs_wait_file));

            dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_terminate : file %s tag %ld terminate owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_terminate : file %s tag %ld terminate none due to no owner\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL crfs_wait_file_owner_terminate_over_bgn (CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file)))
    {
        TASK_MGR *task_mgr;
        EC_BOOL   ret; /*ignore it*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE *mod_node;

            /*note : after terminate owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CRFS_WAIT_FILE_OWNER_LIST(crfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node, &ret, FI_super_cond_terminate, CMPI_ERROR_MODI, tag, CRFS_WAIT_FILE_NAME(crfs_wait_file));

            dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_terminate : file %s tag %ld terminate owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] crfs_wait_file_owner_terminate : file %s tag %ld terminate none due to no owner\n",
                            (char *)CRFS_WAIT_FILE_NAME_STR(crfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL crfs_wait_file_owner_terminate(CRFS_WAIT_FILE *crfs_wait_file, const UINT32 tag)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return crfs_wait_file_owner_terminate_over_http(crfs_wait_file, tag);
    }

    return crfs_wait_file_owner_terminate_over_bgn(crfs_wait_file, tag);
}

STATIC_CAST static EC_BOOL __crfs_file_wait(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path)
{
    CRFS_MD          *crfs_md;

    CRB_NODE         *crb_node;
    CRFS_WAIT_FILE   *crfs_wait_file;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfs_wait_file = crfs_wait_file_new();
    if(NULL_PTR == crfs_wait_file)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_file_wait: new crfs_wait_file failed\n");
        return (EC_FALSE);
    }

    crfs_wait_file_name_set(crfs_wait_file, file_path);

    crb_node = crb_tree_insert_data(CRFS_MD_WAIT_FILES(crfs_md), (void *)crfs_wait_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_file_wait: insert file %s to wait files tree failed\n",
                                (char *)cstring_get_str(file_path));
        crfs_wait_file_free(crfs_wait_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != crfs_wait_file)/*found duplicate*/
    {
        CRFS_WAIT_FILE *crfs_wait_file_duplicate;

        crfs_wait_file_duplicate = (CRFS_WAIT_FILE *)CRB_NODE_DATA(crb_node);

        crfs_wait_file_free(crfs_wait_file); /*no useful*/

        /*when found the file had been wait, register remote owner to it*/
        crfs_wait_file_owner_push(crfs_wait_file_duplicate, tcid);

        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_file_wait: push %s to duplicated file '%s' in wait files tree done\n",
                            c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*register remote token owner to it*/
    crfs_wait_file_owner_push(crfs_wait_file, tcid);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_file_wait: push %s to inserted file %s in wait files tree done\n",
                        c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL crfs_file_wait(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_wait: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == crfs_read(crfs_md_id, file_path, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __crfs_file_wait(crfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfs_file_wait_ready(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *data_ready)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_wait_ready: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    return crfs_file_wait(crfs_md_id, tcid, file_path, NULL_PTR, data_ready);
}

EC_BOOL crfs_file_wait_e(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_wait: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == crfs_read_e(crfs_md_id, file_path, offset, max_len, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __crfs_file_wait(crfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*notify all waiters*/
EC_BOOL crfs_file_notify(const UINT32 crfs_md_id, const CSTRING *file_path)
{
    CRFS_MD          *crfs_md;

    CRFS_WAIT_FILE   *crfs_wait_file;
    CRFS_WAIT_FILE   *crfs_wait_file_found;
    CRB_NODE         *crb_node;
    UINT32            tag;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_notify: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfs_wait_file = crfs_wait_file_new();
    if(NULL_PTR == crfs_wait_file)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_notify: new crfs_wait_file failed\n");
        return (EC_FALSE);
    }

    crfs_wait_file_name_set(crfs_wait_file, file_path);

    crb_node = crb_tree_search_data(CRFS_MD_WAIT_FILES(crfs_md), (void *)crfs_wait_file);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_file_notify: not found waiters of file '%s'\n",
                        (char *)CSTRING_STR(file_path));
        crfs_wait_file_free(crfs_wait_file);
        return (EC_TRUE);
    }

    crfs_wait_file_free(crfs_wait_file);

    crfs_wait_file_found = CRB_NODE_DATA(crb_node);
    tag = MD_CRFS;

    if(EC_FALSE == crfs_wait_file_owner_notify (crfs_wait_file_found, tag))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_notify: notify waiters of file '%s' failed\n",
                        (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    crb_tree_delete(CRFS_MD_WAIT_FILES(crfs_md), crb_node);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_file_notify: notify waiters of file '%s' done\n",
                    (char *)CSTRING_STR(file_path));
    return (EC_TRUE);
}

/*terminate all waiters*/
EC_BOOL crfs_file_terminate(const UINT32 crfs_md_id, const CSTRING *file_path)
{
    CRFS_MD          *crfs_md;

    CRFS_WAIT_FILE   *crfs_wait_file;
    CRFS_WAIT_FILE   *crfs_wait_file_found;
    CRB_NODE         *crb_node;
    UINT32            tag;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_terminate: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfs_wait_file = crfs_wait_file_new();
    if(NULL_PTR == crfs_wait_file)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_terminate: new crfs_wait_file failed\n");
        return (EC_FALSE);
    }

    crfs_wait_file_name_set(crfs_wait_file, file_path);

    crb_node = crb_tree_search_data(CRFS_MD_WAIT_FILES(crfs_md), (void *)crfs_wait_file);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_file_terminate: not found waiters of file '%s'\n",
                        (char *)CSTRING_STR(file_path));
        crfs_wait_file_free(crfs_wait_file);
        return (EC_TRUE);
    }

    crfs_wait_file_free(crfs_wait_file);

    crfs_wait_file_found = CRB_NODE_DATA(crb_node);
    tag = MD_CRFS;

    if(EC_FALSE == crfs_wait_file_owner_terminate (crfs_wait_file_found, tag))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_terminate: terminate waiters of file '%s' failed\n",
                        (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    crb_tree_delete(CRFS_MD_WAIT_FILES(crfs_md), crb_node);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_file_terminate: terminate waiters of file '%s' done\n",
                    (char *)CSTRING_STR(file_path));
    return (EC_TRUE);
}

/*------------------------------------------------ interface for file lock ------------------------------------------------*/
CRFS_LOCKED_FILE *crfs_locked_file_new()
{
    CRFS_LOCKED_FILE *crfs_locked_file;
    alloc_static_mem(MM_CRFS_LOCKED_FILE, &crfs_locked_file, LOC_CRFS_0017);
    if(NULL_PTR != crfs_locked_file)
    {
        crfs_locked_file_init(crfs_locked_file);
    }
    return (crfs_locked_file);
}

EC_BOOL crfs_locked_file_init(CRFS_LOCKED_FILE *crfs_locked_file)
{
    cstring_init(CRFS_LOCKED_FILE_NAME(crfs_locked_file), NULL_PTR);
    cbytes_init(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file));

    CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL crfs_locked_file_clean(CRFS_LOCKED_FILE *crfs_locked_file)
{
    cstring_clean(CRFS_LOCKED_FILE_NAME(crfs_locked_file));
    cbytes_clean(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file));

    CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL crfs_locked_file_free(CRFS_LOCKED_FILE *crfs_locked_file)
{
    if(NULL_PTR != crfs_locked_file)
    {
        crfs_locked_file_clean(crfs_locked_file);
        free_static_mem(MM_CRFS_LOCKED_FILE, crfs_locked_file, LOC_CRFS_0018);
    }
    return (EC_TRUE);
}

int crfs_locked_file_cmp(const CRFS_LOCKED_FILE *crfs_locked_file_1st, const CRFS_LOCKED_FILE *crfs_locked_file_2nd)
{
    return cstring_cmp(CRFS_LOCKED_FILE_NAME(crfs_locked_file_1st), CRFS_LOCKED_FILE_NAME(crfs_locked_file_2nd));
}

void crfs_locked_file_print(LOG *log, const CRFS_LOCKED_FILE *crfs_locked_file)
{
    if(NULL_PTR != crfs_locked_file)
    {
        sys_log(log, "crfs_locked_file_print %p: file %s, expire %ld seconds\n",
                        crfs_locked_file,
                        (char *)CRFS_LOCKED_FILE_NAME_STR(crfs_locked_file),
                        CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file)
                        );
        sys_log(log, "crfs_locked_file_print %p: file %s, token ",
                        crfs_locked_file,
                        (char *)CRFS_LOCKED_FILE_NAME_STR(crfs_locked_file)
                        );
        cbytes_print_chars(log, CRFS_LOCKED_FILE_TOKEN(crfs_locked_file));

        sys_log(log, "crfs_locked_file_print %p: file %s\n",
                        crfs_locked_file,
                        (char *)CRFS_LOCKED_FILE_NAME_STR(crfs_locked_file)
                        );
    }

    return;
}

void crfs_locked_files_print(const UINT32 crfs_md_id, LOG *log)
{
    CRFS_MD *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_locked_files_print: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crb_tree_print(log, CRFS_MD_LOCKED_FILES(crfs_md));

    return;
}

/*generate token from file_path with time as random*/
EC_BOOL crfs_locked_file_token_gen(CRFS_LOCKED_FILE *crfs_locked_file, const CSTRING *file_name)
{
    uint8_t  digest[ CMD5_DIGEST_LEN ];
    CSTRING  cstr;

    cstring_init(&cstr, cstring_get_str(file_name));

    cstring_append_str(&cstr, (const UINT8 *)TASK_BRD_TIME_STR(task_brd_default_get()));

    cmd5_sum(cstring_get_len(&cstr), cstring_get_str(&cstr), digest);
    cstring_clean(&cstr);

    cbytes_set(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file), (const UINT8 *)digest, CMD5_DIGEST_LEN);

    return (EC_TRUE);
}

EC_BOOL crfs_locked_file_expire_set(CRFS_LOCKED_FILE *crfs_locked_file, const UINT32 expire_nsec)
{
    CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file) = expire_nsec;

    CTIMET_GET(CRFS_LOCKED_FILE_START_TIME(crfs_locked_file));
    CTIMET_GET(CRFS_LOCKED_FILE_LAST_TIME(crfs_locked_file));

    return (EC_TRUE);
}

EC_BOOL crfs_locked_file_is_expire(const CRFS_LOCKED_FILE *crfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CRFS_LOCKED_FILE_LAST_TIME(crfs_locked_file), cur_time);
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] crfs_locked_file_is_expire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file));
    if(diff_nsec >= 0.0 + CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL crfs_locked_file_name_set(CRFS_LOCKED_FILE *crfs_locked_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CRFS_LOCKED_FILE_NAME(crfs_locked_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_locked_file_need_retire(const CRFS_LOCKED_FILE *crfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CRFS_LOCKED_FILE_LAST_TIME(crfs_locked_file), cur_time);
    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_locked_file_need_retire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file));
    if(diff_nsec >= 0.0 + 2 * CRFS_LOCKED_FILE_EXPIRE_NSEC(crfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __crfs_locked_file_retire(CRB_TREE *crbtree, CRB_NODE *node)
{
    CRFS_LOCKED_FILE *crfs_locked_file;

    if(NULL_PTR == node)
    {
        return (EC_FALSE);
    }

    crfs_locked_file = CRB_NODE_DATA(node);
    if(EC_TRUE == __crfs_locked_file_need_retire(crfs_locked_file))
    {
        dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] __crfs_locked_file_retire: file %s was retired\n",
                            (char *)cstring_get_str(CRFS_LOCKED_FILE_NAME(crfs_locked_file)));

        crb_tree_delete(crbtree, node);
        return (EC_TRUE);/*succ and terminate*/
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_TRUE == __crfs_locked_file_retire(crbtree, CRB_NODE_LEFT(node)))
        {
            return (EC_TRUE);
        }
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_TRUE == __crfs_locked_file_retire(crbtree, CRB_NODE_RIGHT(node)))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*retire the expired locked files over 120 seconds which are garbage*/
EC_BOOL crfs_locked_file_retire(const UINT32 crfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num)
{
    CRFS_MD      *crfs_md;
    CRB_TREE     *crbtree;
    UINT32        retire_idx;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_locked_file_retire: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crbtree = CRFS_MD_LOCKED_FILES(crfs_md);

    for(retire_idx = 0; retire_idx < retire_max_num; retire_idx ++)
    {
        if(EC_FALSE == __crfs_locked_file_retire(crbtree, CRB_TREE_ROOT(crbtree)))
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

STATIC_CAST static EC_BOOL __crfs_file_lock(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CBYTES *token, UINT32 *locked_already)
{
    CRFS_MD          *crfs_md;

    CRB_NODE         *crb_node;
    CRFS_LOCKED_FILE *crfs_locked_file;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    (*locked_already) = EC_FALSE; /*init*/

    crfs_locked_file = crfs_locked_file_new();
    if(NULL_PTR == crfs_locked_file)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_file_lock: new crfs_locked_file failed\n");
        return (EC_FALSE);
    }

    crfs_locked_file_name_set(crfs_locked_file, file_path);
    crfs_locked_file_token_gen(crfs_locked_file, file_path);/*generate token from file_path with time as random*/
    crfs_locked_file_expire_set(crfs_locked_file, expire_nsec);

    crb_node = crb_tree_insert_data(CRFS_MD_LOCKED_FILES(crfs_md), (void *)crfs_locked_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_file_lock: insert file %s to locked files tree failed\n",
                                (char *)cstring_get_str(file_path));
        crfs_locked_file_free(crfs_locked_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != crfs_locked_file)/*found duplicate*/
    {
        CRFS_LOCKED_FILE *crfs_locked_file_duplicate;

        crfs_locked_file_duplicate = (CRFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node);

        if(EC_FALSE == crfs_locked_file_is_expire(crfs_locked_file_duplicate))
        {
            dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] __crfs_file_lock: file %s already in locked files tree\n",
                                (char *)cstring_get_str(file_path));

            crfs_locked_file_free(crfs_locked_file); /*no useful*/

            (*locked_already) = EC_TRUE;/*means file had been locked by someone else*/
            return (EC_FALSE);
        }

        CRB_NODE_DATA(crb_node) = crfs_locked_file; /*mount new*/

        crfs_locked_file_free(crfs_locked_file_duplicate); /*free the duplicate which is also old*/

        cbytes_clone(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file), token);

        dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_file_lock: update file %s to locked files tree done\n",
                            (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*now crfs_locked_file_tmp already insert and mount into tree*/
    cbytes_clone(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file), token);

    dbg_log(SEC_0031_CRFS, 9)(LOGSTDOUT, "[DEBUG] __crfs_file_lock: insert file %s to locked files tree done\n",
                        (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL crfs_file_lock(const UINT32 crfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already)
{
    CRFS_MD      *crfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_lock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    cbytes_init(&token_cbyte);

    if(EC_FALSE == __crfs_file_lock(crfs_md_id, tcid, file_path, expire_nsec, &token_cbyte, locked_already))
    {
        return (EC_FALSE);
    }

    cbase64_encode(CBYTES_BUF(&token_cbyte), CBYTES_LEN(&token_cbyte), auth_token, sizeof(auth_token), &auth_token_len);
    cstring_append_chars(token_str, auth_token_len, auth_token, LOC_CRFS_0019);
    cbytes_clean(&token_cbyte);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_file_unlock(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *token)
{
    CRFS_MD          *crfs_md;

    CRB_NODE         *crb_node_searched;

    CRFS_LOCKED_FILE *crfs_locked_file_tmp;
    CRFS_LOCKED_FILE *crfs_locked_file_searched;

    crfs_md = CRFS_MD_GET(crfs_md_id);

    crfs_locked_file_tmp = crfs_locked_file_new();
    if(NULL_PTR == crfs_locked_file_tmp)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_file_unlock: new CRFS_LOCKED_FILE failed\n");
        return (EC_FALSE);
    }

    crfs_locked_file_name_set(crfs_locked_file_tmp, file_path);

    crb_node_searched = crb_tree_search_data(CRFS_MD_LOCKED_FILES(crfs_md), (void *)crfs_locked_file_tmp);/*compare name*/
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] __crfs_file_unlock: file %s not in locked files tree\n",
                                (char *)cstring_get_str(file_path));
        crfs_locked_file_free(crfs_locked_file_tmp);
        return (EC_FALSE);
    }

    crfs_locked_file_free(crfs_locked_file_tmp); /*no useful*/

    crfs_locked_file_searched = (CRFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node_searched);

    /*if expired already, remove it as garbage, despite of token comparsion*/
    if(EC_TRUE == crfs_locked_file_is_expire(crfs_locked_file_searched))
    {
        crb_tree_delete(CRFS_MD_LOCKED_FILES(crfs_md), crb_node_searched);
        dbg_log(SEC_0031_CRFS, 1)(LOGSTDOUT, "info:__crfs_file_unlock: remove expired locked file %s\n",
                        (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*if exist, compare token. if not exist, unlock by force!*/
    if(NULL_PTR != token && EC_FALSE == cbytes_cmp(CRFS_LOCKED_FILE_TOKEN(crfs_locked_file_searched), token))
    {
        if(do_log(SEC_0031_CRFS, 9))
        {
            sys_log(LOGSTDOUT, "warn:__crfs_file_unlock: file %s, searched token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, CRFS_LOCKED_FILE_TOKEN(crfs_locked_file_searched));

            sys_log(LOGSTDOUT, "warn:__crfs_file_unlock: file %s, but input token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, token);
        }
        return (EC_FALSE);
    }

    if(do_log(SEC_0031_CRFS, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __crfs_file_unlock: file %s notify ...\n",
                                (char *)cstring_get_str(file_path));

        sys_log(LOGSTDOUT, "[DEBUG] __crfs_file_unlock: searched file:\n");
        crfs_locked_file_print(LOGSTDOUT, crfs_locked_file_searched);
    }

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] __crfs_file_unlock: file %s notify ... done\n",
                            (char *)cstring_get_str(file_path));

    crb_tree_delete(CRFS_MD_LOCKED_FILES(crfs_md), crb_node_searched);

    dbg_log(SEC_0031_CRFS, 5)(LOGSTDOUT, "[DEBUG] __crfs_file_unlock: file %s unlocked\n",
                            (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL crfs_file_unlock(const UINT32 crfs_md_id, const CSTRING *file_path, const CSTRING *token_str)
{
    CRFS_MD      *crfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_unlock: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    cbase64_decode((UINT8 *)CSTRING_STR(token_str), CSTRING_LEN(token_str), auth_token, sizeof(auth_token), &auth_token_len);
    cbytes_mount(&token_cbyte, auth_token_len, auth_token);
#if 0
    if(do_log(SEC_0031_CRFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfs_file_unlock: auth_token str: %.*s\n", (uint32_t)CSTRING_LEN(token_str), CSTRING_STR(token_str));
        sys_log(LOGSTDOUT, "[DEBUG] crfs_file_unlock: auth_token str => token: ");
        cbytes_print_chars(LOGSTDOUT, &token_cbyte);

        sys_log(LOGSTDOUT, "[DEBUG] crfs_file_unlock: all locked files are: \n");
        crfs_locked_files_print(crfs_md_id, LOGSTDOUT);
    }
#endif
    if(EC_FALSE == __crfs_file_unlock(crfs_md_id, file_path, &token_cbyte))
    {
        cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
        return (EC_FALSE);
    }

    cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
    return (EC_TRUE);
}


/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL crfs_file_unlock_notify(const UINT32 crfs_md_id, const CSTRING *file_path)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_file_unlock_notify: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_file_unlock_notify: obsolete interface!!!!\n");

    return (EC_FALSE);
}

/*------------------------------------------------ interface for replica ------------------------------------------------*/
EC_BOOL crfs_write_r(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const UINT32 replica_num)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_write_r: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CRFS_MAX_REPLICA_NUM < replica_num)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_r: reject to write file %s with invalid replica %ld\n",
                           (char *)cstring_get_str(file_path), replica_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_write(crfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_r: write file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(1 >= replica_num)/*at least one replica. zero means default replicas*/
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_is_state(crfs_md_id, CRFS_SYNC_STATE))
    {
        TASK_MGR *task_mgr;
        UINT32    mod_node_num;
        UINT32    mod_node_idx;
        EC_BOOL   ret[CRFS_MAX_REPLICA_NUM];

        mod_node_num = DMIN(replica_num, cvector_size(CRFS_MD_NEIGHBOR_VEC(crfs_md)));

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            ret[ mod_node_idx ] = EC_FALSE;
            task_p2p_inc(task_mgr, crfs_md_id, recv_mod_node,
                        &(ret[ mod_node_idx ]), FI_crfs_write,CMPI_ERROR_MODI, file_path, cbytes);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            if(EC_FALSE == ret[ mod_node_idx ])
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_write_r: write file %s to tcid %s rank %ld failed\n",
                                   (char *)cstring_get_str(file_path),
                                   MOD_NODE_TCID_STR(recv_mod_node),MOD_NODE_RANK(recv_mod_node));
            }
        }
    }
    return (EC_TRUE);
}

/**
*
*  update a file
*
**/
EC_BOOL crfs_update_r(const UINT32 crfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const UINT32 replica_num)
{
    CRFS_MD      *crfs_md;
    CRFSNP_FNODE  crfsnp_fnode;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_update_r: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfsnp_fnode_init(&crfsnp_fnode);

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CRFS_MAX_REPLICA_NUM < replica_num)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_r: reject to update file %s with invalid replica %ld\n",
                           (char *)cstring_get_str(file_path), replica_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_update(crfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_r: update file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(1 >= replica_num)/*at least one replica. zero means default replicas*/
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_is_state(crfs_md_id, CRFS_SYNC_STATE))
    {
        TASK_MGR *task_mgr;
        UINT32    mod_node_num;
        UINT32    mod_node_idx;
        EC_BOOL   ret_vec[CRFS_MAX_REPLICA_NUM];

        mod_node_num = DMIN(CRFS_MAX_REPLICA_NUM, cvector_size(CRFS_MD_NEIGHBOR_VEC(crfs_md)));

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            ret_vec[ mod_node_idx ] = EC_FALSE;
            task_p2p_inc(task_mgr, crfs_md_id, recv_mod_node,
                        &(ret_vec[ mod_node_idx ]), FI_crfs_update,CMPI_ERROR_MODI, file_path, cbytes);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            if(EC_FALSE == ret_vec[ mod_node_idx ])
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_update_r: update file %s at tcid %s rank %ld failed\n",
                                   (char *)cstring_get_str(file_path),
                                   MOD_NODE_TCID_STR(recv_mod_node), MOD_NODE_RANK(recv_mod_node));
            }
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfs_delete_r(const UINT32 crfs_md_id, const CSTRING *path, const UINT32 dflag, const UINT32 replica_num)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_delete_r: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CRFS_MAX_REPLICA_NUM < replica_num)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_r: reject to remove file %s with invalid replica %ld\n",
                           (char *)cstring_get_str(path), replica_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_delete(crfs_md_id, path, dflag))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_r: remove file %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    if(1 >= replica_num)/*at least one replica. zero means default replicas*/
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_is_state(crfs_md_id, CRFS_SYNC_STATE))
    {
        TASK_MGR *task_mgr;
        UINT32    mod_node_num;
        UINT32    mod_node_idx;
        EC_BOOL   ret_vec[CRFS_MAX_REPLICA_NUM];

        mod_node_num = DMIN(CRFS_MAX_REPLICA_NUM, cvector_size(CRFS_MD_NEIGHBOR_VEC(crfs_md)));

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            ret_vec[ mod_node_idx ] = EC_FALSE;
            task_p2p_inc(task_mgr, crfs_md_id, recv_mod_node,
                         &(ret_vec[ mod_node_idx ]), FI_crfs_delete,CMPI_ERROR_MODI, path, dflag);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            if(EC_FALSE == ret_vec[ mod_node_idx ])
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_delete_r: remove file %s at tcid %s rank %ld failed\n",
                                   (char *)cstring_get_str(path),
                                   MOD_NODE_TCID_STR(recv_mod_node), MOD_NODE_RANK(recv_mod_node));
            }
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfs_renew_r(const UINT32 crfs_md_id, const CSTRING *file_path, const UINT32 replica_num)
{
    CRFS_MD      *crfs_md;

#if ( SWITCH_ON == CRFS_DEBUG_SWITCH )
    if ( CRFS_MD_ID_CHECK_INVALID(crfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfs_renew_r: crfs module #%ld not started.\n",
                crfs_md_id);
        dbg_exit(MD_CRFS, crfs_md_id);
    }
#endif/*CRFS_DEBUG_SWITCH*/

    crfs_md = CRFS_MD_GET(crfs_md_id);

    if(CRFS_MAX_REPLICA_NUM < replica_num)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_r: reject to renew file %s with invalid replica %ld\n",
                           (char *)cstring_get_str(file_path), replica_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_renew(crfs_md_id, file_path))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_r: renew file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(1 >= replica_num)/*at least one replica. zero means default replicas*/
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == crfs_is_state(crfs_md_id, CRFS_SYNC_STATE))
    {
        TASK_MGR *task_mgr;
        UINT32    mod_node_num;
        UINT32    mod_node_idx;
        EC_BOOL   ret_vec[CRFS_MAX_REPLICA_NUM];

        mod_node_num = DMIN(CRFS_MAX_REPLICA_NUM, cvector_size(CRFS_MD_NEIGHBOR_VEC(crfs_md)));

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            ret_vec[ mod_node_idx ] = EC_FALSE;
            task_p2p_inc(task_mgr, crfs_md_id, recv_mod_node,
                         &(ret_vec[ mod_node_idx ]), FI_crfs_renew, CMPI_ERROR_MODI, file_path);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
        {
            MOD_NODE *recv_mod_node;

            recv_mod_node = cvector_get(CRFS_MD_NEIGHBOR_VEC(crfs_md), mod_node_idx);
            if(NULL_PTR == recv_mod_node)
            {
                continue;
            }

            if(EC_FALSE == ret_vec[ mod_node_idx ])
            {
                dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:crfs_renew_r: renew file %s at tcid %s rank %ld failed\n",
                                   (char *)cstring_get_str(file_path),
                                   MOD_NODE_TCID_STR(recv_mod_node), MOD_NODE_RANK(recv_mod_node));
            }
        }
    }

    return (EC_TRUE);
}


/*------------------------------------------------ interface for liburl ------------------------------------------------*/
STATIC_CAST static EC_BOOL __crfs_open_url_list_file(const char *fname, char **fmem, UINT32 *fsize, int *fd)
{
    char *cur_fmem;
    int   cur_fd;
    UINT32 cur_fsize;

    cur_fd = c_file_open(fname, O_RDONLY, 0666);
    if(ERR_FD == cur_fd)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_open_url_list_file: open url list file %s failed\n", fname);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(cur_fd, &cur_fsize))
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_open_url_list_file: get size of url list file %s failed\n", fname);
        c_file_close(cur_fd);
        return (EC_FALSE);
    }

    cur_fmem = (char *)mmap(NULL_PTR, cur_fsize, PROT_READ, MAP_SHARED, cur_fd, 0);
    if(MAP_FAILED == cur_fmem)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_open_url_list_file: mmap url list file %s with cur_fd %d failed, errno = %d, errorstr = %s\n",
                           fname, cur_fd, errno, strerror(errno));
        return (EC_FALSE);
    }

    (*fd)    = cur_fd;
    (*fmem)  = cur_fmem;
    (*fsize) = cur_fsize;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_close_url_list_file(char *fmem, const UINT32 fsize, const int fd)
{
    if(ERR_FD != fd)
    {
        close(fd);
    }

    if(NULL_PTR != fmem)
    {
        munmap(fmem, fsize);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfs_fetch_url_cstr(const char *fmem, const UINT32 fsize, UINT32 *offset, UINT32 *idx,CSTRING *url_cstr)
{
    UINT32 old_offset;
    UINT32 line_len;

    old_offset = (*offset);
    if(fsize <= old_offset)
    {
        dbg_log(SEC_0031_CRFS, 0)(LOGSTDOUT, "error:__crfs_fetch_url_cstr: offset %ld overflow fsize %ld\n", old_offset, fsize);
        return (EC_FALSE);
    }

    line_len = c_line_len(fmem + old_offset);
    cstring_append_chars(url_cstr, line_len, (UINT8 *)fmem + old_offset, LOC_CRFS_0020);
    cstring_append_char(url_cstr, '\0');

    (*offset) += line_len + 1;
    (*idx) ++;

    dbg_log(SEC_0031_CRFS, 0)(LOGCONSOLE, "[DEBUG] __crfs_fetch_url_cstr: [%8ld] %s\n", (*idx), (char *)cstring_get_str(url_cstr));

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

