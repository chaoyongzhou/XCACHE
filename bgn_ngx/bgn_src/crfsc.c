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

#include "crfs.h"
#include "crfshttp.h"
#include "crfsmc.h"
#include "crfsbk.h"
#include "crfsdt.h"
#include "crfsc.h"
#include "crfsconhash.h"

#include "cload.h"

#include "cmd5.h"

#include "chttp.h"
#include "crfschttp.h"

#include "findex.inc"

/*********************************************************************************
*
*   ep: end point
*
*
*********************************************************************************/

#define CRFSC_MD_CAPACITY()                  (cbc_md_capacity(MD_CRFSC))

#define CRFSC_MD_GET(crfsc_md_id)     ((CRFSC_MD *)cbc_md_get(MD_CRFSC, (crfsc_md_id)))

#define CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id)  \
    ((CMPI_ANY_MODI != (crfsc_md_id)) && ((NULL_PTR == CRFSC_MD_GET(crfsc_md_id)) || (0 == (CRFSC_MD_GET(crfsc_md_id)->usedcounter))))

STATIC_CAST static EC_BOOL __crfsc_start_all_rfs(UINT32 crfsc_md_id, const CSTRING *crfs_root_dir);
STATIC_CAST static EC_BOOL __crfsc_end_all_rfs(UINT32 crfsc_md_id);

STATIC_CAST static UINT32  __crfsc_get_modi(const UINT32 crfsc_md_id, const UINT32 crfs_pos);
STATIC_CAST static EC_BOOL __crfsc_set_modi(const UINT32 crfsc_md_id, const UINT32 crfs_md_id);

STATIC_CAST static UINT32  __crfsc_get_rfs_modi_of_file_path(const UINT32 crfsc_md_id, const CSTRING *file_path);
STATIC_CAST static EC_BOOL __crfsc_get_rfsc_mod_node_of_file_path(const UINT32 crfsc_md_id, const CRFSDT *crfsdt, const CSTRING *file_path, MOD_NODE *mod_node);

STATIC_CAST static MOD_MGR *__crfsc_make_mod_mgr_by_pnode(const UINT32 crfsc_md_id, CRFSDT_PNODE *crfsdt_pnode);
STATIC_CAST static EC_BOOL  __crfsc_make_mode_node_by_rnode(CRFSDT_RNODE *crfsdt_rnode, CRFSC_WALKER_ARG *crfsc_walker_arg);
STATIC_CAST static MOD_MGR *__crfsc_make_mod_mgr_by_rnode_tree(const UINT32 crfsc_md_id, CRB_TREE *rnode_tree);

STATIC_CAST static EC_BOOL __crfsc_exist_dt(const CSTRING *crfs_root_dir);
STATIC_CAST static EC_BOOL __crfsc_load_dt(CRFSDT *crfsdt_active, CRFSDT *crfsdt_standby, const CSTRING *crfs_root_dir);

/**
*   for test only
*
*   to query the status of CRFSC Module
*
**/
void crfsc_print_module_status(const UINT32 crfsc_md_id, LOG *log)
{
    CRFSC_MD *crfsc_md;
    UINT32 this_crfsc_md_id;

    for( this_crfsc_md_id = 0; this_crfsc_md_id < CRFSC_MD_CAPACITY(); this_crfsc_md_id ++ )
    {
        crfsc_md = CRFSC_MD_GET(this_crfsc_md_id);

        if ( NULL_PTR != crfsc_md && 0 < crfsc_md->usedcounter )
        {
            sys_log(log,"CRFS Module # %ld : %ld refered\n",
                    this_crfsc_md_id,
                    crfsc_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CRFSC module
*
*
**/
UINT32 crfsc_free_module_static_mem(const UINT32 crfsc_md_id)
{
    CRFSC_MD  *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_free_module_static_mem: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    free_module_static_mem(MD_CRFSC, crfsc_md_id);

    return 0;
}

STATIC_CAST static EC_BOOL __crfsc_start_all_rfs(UINT32 crfsc_md_id, const CSTRING *crfs_root_dir)
{
    EC_BOOL ret;

    ret = EC_FALSE;

    for(;;)
    {
        UINT32 crfs_md_id;

        crfs_md_id = crfs_start(crfs_root_dir);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            //dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_start_all_rfs: start RFS failed\n");
            break;
        }

        if(EC_FALSE == __crfsc_set_modi(crfsc_md_id, crfs_md_id))
        {
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_start_all_rfs: add RFS %ld# failed\n", crfs_md_id);

            crfs_end(crfs_md_id);
            //return (EC_FALSE);
            break;
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] __crfsc_start_all_rfs: add RFS %ld# done\n", crfs_md_id);

        ret = EC_TRUE;/*success*/
    }

    return (ret);
}

STATIC_CAST static EC_BOOL __crfsc_end_all_rfs(UINT32 crfsc_md_id)
{
    CRFSC_MD *crfsc_md;
    UINT32    crfs_num;
    UINT32    crfs_pos;

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        crfs_end(crfs_md_id);
    }
    return (EC_TRUE);
}

/**
*
* start CRFSC module
*
**/
UINT32 crfsc_start(const CSTRING *crfs_root_dir)
{
    CRFSC_MD *crfsc_md;
    UINT32   crfsc_md_id;

    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    crfsc_md_id = cbc_md_new(MD_CRFSC, sizeof(CRFSC_MD));
    if(CMPI_ERROR_MODI == crfsc_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CRFSC module */
    crfsc_md = (CRFSC_MD *)cbc_md_get(MD_CRFSC, crfsc_md_id);
    crfsc_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    cstring_init(CRFSC_MD_ROOT_DIR(crfsc_md), cstring_get_str(crfs_root_dir));
    cvector_init(CRFSC_MD_CRFS_VEC(crfsc_md), 0, MM_MOD_NODE, CVECTOR_LOCK_ENABLE, LOC_CRFSC_0001);

    CRFSC_MD_DT_ACTIVE_FLAG(crfsc_md) = 0;
    crfsdt_init(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md));
    crfsdt_init(CRFSC_MD_STANDBY_DIRTAB(crfsc_md));

    if(EC_TRUE == __crfsc_exist_dt(CRFSC_MD_ROOT_DIR(crfsc_md)))
    {
        if(EC_FALSE == __crfsc_load_dt(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), CRFSC_MD_STANDBY_DIRTAB(crfsc_md), CRFSC_MD_ROOT_DIR(crfsc_md)))
        {
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_start: load dt failed\n");

            cvector_clean(CRFSC_MD_CRFS_VEC(crfsc_md), (CVECTOR_DATA_CLEANER)mod_node_free, LOC_CRFSC_0002);
            crfsdt_clean(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md));
            crfsdt_clean(CRFSC_MD_STANDBY_DIRTAB(crfsc_md));
            cstring_clean(CRFSC_MD_ROOT_DIR(crfsc_md));

            return (CMPI_ERROR_MODI);
        }
    }

    if(EC_FALSE == __crfsc_start_all_rfs(crfsc_md_id, CRFSC_MD_ROOT_DIR(crfsc_md)))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_start: start all RFS failed\n");

        __crfsc_end_all_rfs(crfsc_md_id);

        cvector_clean(CRFSC_MD_CRFS_VEC(crfsc_md), (CVECTOR_DATA_CLEANER)mod_node_free, LOC_CRFSC_0003);
        crfsdt_clean(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md));
        crfsdt_clean(CRFSC_MD_STANDBY_DIRTAB(crfsc_md));
        cstring_clean(CRFSC_MD_ROOT_DIR(crfsc_md));

        cbc_md_free(MD_CRFSC, crfsc_md_id);

        return (CMPI_ERROR_MODI);
    }

    crfsc_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)crfsc_end, crfsc_md_id);

    dbg_log(SEC_0143_CRFSC, 5)(LOGSTDOUT, "crfsc_start: start CRFSC module #%ld\n", crfsc_md_id);

    CRFSC_INIT_LOCK(crfsc_md, LOC_CRFSC_0004);

    if(SWITCH_ON == CRFSCHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        if(EC_TRUE == task_brd_default_check_csrv_enabled())
        {
            if(EC_FALSE == crfschttp_defer_request_queue_init())
            {
                dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_start: init crfschttp defer request queue failed\n");
                crfsc_end(crfsc_md_id);
                return (CMPI_ERROR_MODI);
            }

            if(EC_FALSE == crfschttp_csocket_cnode_defer_close_list_init())
            {
                dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_start: init crfschttp node defer clean list failed\n");
                crfsc_end(crfsc_md_id);
                return (CMPI_ERROR_MODI);
            }

            crfschttp_log_start();
            task_brd_default_bind_http_srv_modi(crfsc_md_id);

            ASSERT(0); /*chttp_rest_list_push interface issue*/
            //chttp_rest_list_push((const char *)CRFSCHTTP_REST_API_NAME, crfschttp_commit_request);
        }
    }

    return ( crfsc_md_id );
}

/**
*
* end CRFSC module
*
**/
void crfsc_end(const UINT32 crfsc_md_id)
{
    CRFSC_MD *crfsc_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)crfsc_end, crfsc_md_id);

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);
    if(NULL_PTR == crfsc_md)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_end: crfsc_md_id = %ld not exist.\n", crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < crfsc_md->usedcounter )
    {
        crfsc_md->usedcounter --;
        return ;
    }

    if ( 0 == crfsc_md->usedcounter )
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_end: crfsc_md_id = %ld is not started.\n", crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }

    __crfsc_end_all_rfs(crfsc_md_id);

    if(EC_FALSE == crfsdt_is_empty(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md))
    || EC_FALSE == crfsdt_is_empty(CRFSC_MD_STANDBY_DIRTAB(crfsc_md))
    )
    {
        if(EC_FALSE == crfsc_flush_dt(crfsc_md_id))
        {
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_end: flush dt failed\n");
        }
    }

    cvector_clean(CRFSC_MD_CRFS_VEC(crfsc_md), (CVECTOR_DATA_CLEANER)mod_node_free, LOC_CRFSC_0005);
    crfsdt_clean(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md));
    crfsdt_clean(CRFSC_MD_STANDBY_DIRTAB(crfsc_md));
    cstring_clean(CRFSC_MD_ROOT_DIR(crfsc_md));

    /* free module : */
    //crfsc_free_module_static_mem(crfsc_md_id);

    crfsc_md->usedcounter = 0;
    CRFSC_CLEAN_LOCK(crfsc_md, LOC_CRFSC_0006);

    dbg_log(SEC_0143_CRFSC, 5)(LOGSTDOUT, "crfsc_end: stop CRFSC module #%ld\n", crfsc_md_id);
    cbc_md_free(MD_CRFSC, crfsc_md_id);

    return ;
}

STATIC_CAST static EC_BOOL __crfs_default_true_checker(const EC_BOOL ec_bool)
{
    return (ec_bool);
}

STATIC_CAST static EC_BOOL __crfs_default_false_checker(const EC_BOOL ec_bool)
{
    if(EC_TRUE == ec_bool)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static MOD_MGR *crfsc_make_mod_mgr_by_rnode_vec(const UINT32 crfsc_md_id, CVECTOR *crfsconhash_rnode_vec)
{
    UINT32   crfsconhash_rnode_pos;
    UINT32   crfsconhash_rnode_num;
    MOD_MGR *mod_mgr;

    mod_mgr = mod_mgr_new(crfsc_md_id, LOAD_BALANCING_LOOP);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_make_mod_mgr_by_rnode_vec: new mod_mgr failed\n");
        return (NULL_PTR);
    }

    CVECTOR_LOCK(crfsconhash_rnode_vec, LOC_CRFSC_0007);
    crfsconhash_rnode_num = cvector_size(crfsconhash_rnode_vec);
    for(crfsconhash_rnode_pos = 0; crfsconhash_rnode_pos < crfsconhash_rnode_num; crfsconhash_rnode_pos ++)
    {
        CRFSCONHASH_RNODE *crfsconhash_rnode;

        crfsconhash_rnode = (CRFSCONHASH_RNODE *)cvector_get_no_lock(crfsconhash_rnode_vec, crfsconhash_rnode_pos);
        if(NULL_PTR == crfsconhash_rnode)
        {
            continue;
        }

        mod_mgr_incl(CRFSCONHASH_RNODE_TCID(crfsconhash_rnode), CMPI_ANY_COMM, CMPI_CRFS_RANK, crfsc_md_id, mod_mgr);
    }
    CVECTOR_UNLOCK(crfsconhash_rnode_vec, LOC_CRFSC_0008);

    return (mod_mgr);
}

STATIC_CAST static MOD_MGR *__crfsc_make_mod_mgr_by_pnode(const UINT32 crfsc_md_id, CRFSDT_PNODE *crfsdt_pnode)
{
    CRFSCONHASH  *crfsconhash;

    crfsconhash = CRFSDT_PNODE_CONHASH(crfsdt_pnode);
    return crfsc_make_mod_mgr_by_rnode_vec(crfsc_md_id, CRFSCONHASH_RNODE_VEC(crfsconhash));
}

STATIC_CAST static EC_BOOL __crfsc_make_mode_node_by_rnode(CRFSDT_RNODE *crfsdt_rnode, CRFSC_WALKER_ARG *crfsc_walker_arg)
{
    mod_mgr_incl(CRFSDT_RNODE_TCID(crfsdt_rnode),
                  CMPI_LOCAL_COMM,
                  CMPI_CRFS_RANK,
                  CRFSC_WALKER_ARG_MODI(crfsc_walker_arg),
                  CRFSC_WALKER_ARG_MOD_MGR(crfsc_walker_arg));
    return (EC_TRUE);
}

STATIC_CAST static MOD_MGR *__crfsc_make_mod_mgr_by_rnode_tree(const UINT32 crfsc_md_id, CRB_TREE *rnode_tree)
{
    MOD_MGR *mod_mgr;

    CRFSC_WALKER_ARG crfsc_walker_arg;

    mod_mgr = mod_mgr_new(crfsc_md_id, LOAD_BALANCING_LOOP);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_make_mod_mgr_by_rnode_tree: new mod_mgr failed\n");
        return (NULL_PTR);
    }

    CRFSC_WALKER_ARG_MODI(&crfsc_walker_arg)    = crfsc_md_id;
    CRFSC_WALKER_ARG_MOD_MGR(&crfsc_walker_arg) = mod_mgr;
    crb_inorder_walk(rnode_tree, (CRB_DATA_HANDLE)__crfsc_make_mode_node_by_rnode, &crfsc_walker_arg);

    return (mod_mgr);
}

STATIC_CAST static UINT32 __crfsc_get_modi(const UINT32 crfsc_md_id, const UINT32 crfs_pos)
{
    CRFSC_MD     *crfsc_md;
    MOD_NODE     *mod_node;

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    mod_node = (MOD_NODE *)cvector_get(CRFSC_MD_CRFS_VEC(crfsc_md), crfs_pos);
    if(NULL_PTR == mod_node)
    {
        return (CMPI_ERROR_MODI);
    }

    return MOD_NODE_MODI(mod_node);
}

STATIC_CAST static EC_BOOL __crfsc_set_modi(const UINT32 crfsc_md_id, const UINT32 crfs_md_id)
{
    CRFSC_MD     *crfsc_md;
    MOD_NODE     *mod_node;

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    mod_node = mod_node_new();
    if(NULL_PTR == mod_node)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_set_modi: new mod_node failed\n");
        return (EC_FALSE);
    }

    MOD_NODE_TCID(mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(mod_node) = crfs_md_id;

    cvector_push(CRFSC_MD_CRFS_VEC(crfsc_md), (void *)mod_node);

    return (EC_TRUE);
}

/*get module id of CRFS*/
STATIC_CAST static UINT32 __crfsc_get_rfs_modi_of_file_path(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_md_id;

    UINT32        crfs_num;
    UINT32        crfs_pos;

    UINT32        hash;

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));
    if(0 == crfs_num)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_get_rfs_modi_of_file_path: no RFS open\n");
        return (CMPI_ERROR_MODI);
    }

    hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

    crfs_pos   = (hash % crfs_num);
    crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_get_rfs_modi_of_file_path: invalid RFS modi at %ld# (max %ld)\n",
                           crfs_pos, crfs_num);
        return (CMPI_ERROR_MODI);
    }

    return (crfs_md_id);
}

/*get mod_node of CRFSC*/
STATIC_CAST static EC_BOOL __crfsc_get_rfsc_mod_node_of_file_path(const UINT32 crfsc_md_id, const CRFSDT *crfsdt, const CSTRING *file_path, MOD_NODE *mod_node)
{
    CRFSDT_PNODE      *crfsdt_pnode;
    CRFSCONHASH_RNODE *crfsconhash_rnode;

    uint32_t           hash;

    crfsdt_pnode = crfsdt_lookup_pnode(crfsdt, file_path);
    if(NULL_PTR == crfsdt_pnode)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_get_rfsc_mod_node_of_file_path: search pnode of file '%s' failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*WARNING: the hash algorithm must be same as that in CRFS module*/
    hash = (uint32_t) MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));
    crfsconhash_rnode = crfsconhash_lookup_rnode(CRFSDT_PNODE_CONHASH(crfsdt_pnode), hash);

    MOD_NODE_TCID(mod_node) = CRFSCONHASH_RNODE_TCID(crfsconhash_rnode);
    MOD_NODE_COMM(mod_node) = CMPI_COMM_WORLD;
    MOD_NODE_RANK(mod_node) = CMPI_CRFS_RANK;
    MOD_NODE_MODI(mod_node) = 0;/*crfsc module id*/

    return (EC_TRUE);
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfsc_find_dir_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_find_dir_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        if(EC_TRUE == crfs_find_dir(crfs_md_id, dir_path))
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL crfsc_find_dir(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;

    CRFSDT_PNODE *crfsdt_pnode;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_find_dir: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfsdt_pnode = crfsdt_lookup_pnode(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_find_dir: search pnode of path '%s' failed\n",
                            (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    mod_mgr = __crfsc_make_mod_mgr_by_pnode(crfsc_md_id, crfsdt_pnode);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_find_dir: make mod_mgr by pnode '%s' failed\n",
                            CRFSDT_PNODE_PATH_STR(crfsdt_pnode));
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0009);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_find_dir: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, (UINT32)1/*one EC_TRUE is enough*/);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0010);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_find_dir_ep, CMPI_ERROR_MODI, dir_path);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, task_default_bool_checker);

    result = EC_FALSE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get(ret_vec, crfs_mod_node_idx);

        if(EC_TRUE == result)
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0011);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        if(EC_FALSE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0012);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_TRUE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_find_dir: find '%s' on tcid %s\n",
                                (char *)cstring_get_str(dir_path), MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0013);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0014);
    mod_mgr_free(mod_mgr);

    return (result);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL crfsc_find_file_ep(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_find_file_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_find_file_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_find_file(crfs_md_id, file_path);
}

EC_BOOL crfsc_find_file(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_find_file: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_find_file: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_find_file_ep, CMPI_ERROR_MODI, file_path);

    return (result);
}

/**
*
*  check existing of a big file
*
**/
EC_BOOL crfsc_find_file_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_find_file_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_find_file_b_ep: no RFS for bigfile '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_find_file_b(crfs_md_id, file_path);
}

EC_BOOL crfsc_find_file_b(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_find_file_b: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_find_file_b: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node, \
             &result, FI_crfsc_find_file_b_ep, CMPI_ERROR_MODI, file_path);

    return (result);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL crfsc_is_file(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_is_file: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    return crfsc_find_file(crfsc_md_id, file_path);;
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL crfsc_is_dir(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_is_dir: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    return crfsc_find_dir(crfsc_md_id, dir_path);
}

/**
*
*  write a file
*
**/
EC_BOOL crfsc_write_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_write_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_write_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_write(crfs_md_id, file_path, cbytes);
}

EC_BOOL crfsc_write(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_write: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_write: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_write_ep, CMPI_ERROR_MODI, file_path, cbytes);

    return (result);
}



/**
*
*  read a file
*
**/
EC_BOOL crfsc_read_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_read_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_read_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_read(crfs_md_id, file_path, cbytes);
}

EC_BOOL crfsc_read(const UINT32 crfsc_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_read: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_read: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_read_ep, CMPI_ERROR_MODI, file_path, cbytes);

    return (result);
}

/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a file at offset
*
**/
EC_BOOL crfsc_write_e_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_write_e_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_write_e_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_write_e(crfs_md_id, file_path, offset, max_len, cbytes);
}

EC_BOOL crfsc_write_e(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_write_e: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_write_e: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_write_e_ep, CMPI_ERROR_MODI, file_path, offset, max_len, cbytes);

    return (result);
}

/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL crfsc_read_e_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_read_e_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_read_e_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_read_e(crfs_md_id, file_path, offset, max_len, cbytes);
}

EC_BOOL crfsc_read_e(const UINT32 crfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_read_e: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_read_e: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_read_e_ep, CMPI_ERROR_MODI, file_path, offset, max_len, cbytes);

    return (result);
}

/*----------------------------------- BIG FILE interface -----------------------------------*/

/**
*
*  create a big file at offset
*
**/
EC_BOOL crfsc_create_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const uint64_t *file_size)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_create_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_create_b_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_create_b(crfs_md_id, file_path, file_size);
}

EC_BOOL crfsc_create_b(const UINT32 crfsc_md_id, const CSTRING *file_path, const uint64_t *file_size)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_create_b: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_create_b: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_create_b_ep, CMPI_ERROR_MODI, file_path, file_size);

    return (result);
}

/**
*
*  write a big file at offset
*
**/
EC_BOOL crfsc_write_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const CBYTES *cbytes)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_write_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_write_b_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_write_b(crfs_md_id, file_path, offset, cbytes);
}

EC_BOOL crfsc_write_b(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_write_b: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_write_b: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_write_b_ep, CMPI_ERROR_MODI, file_path, offset, cbytes);

    return (result);
}

/**
*
*  read a file from offset
*
**/
EC_BOOL crfsc_read_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const UINT32 max_len, CBYTES *cbytes)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_read_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_read_b_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_read_b(crfs_md_id, file_path, offset, max_len, cbytes);
}

EC_BOOL crfsc_read_b(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_read_b: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_read_b: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_read_b: file '%s' in (tcid %s,comm %ld,rank %ld,modi %ld)\n",
                        (char *)cstring_get_str(file_path),
                        MOD_NODE_TCID_STR(&recv_mod_node), MOD_NODE_COMM(&recv_mod_node), MOD_NODE_RANK(&recv_mod_node), MOD_NODE_MODI(&recv_mod_node));

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_read_b_ep, CMPI_ERROR_MODI, file_path, offset, max_len, cbytes);

    return (result);
}

EC_BOOL crfsc_fetch_block_fd_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const uint64_t offset, uint32_t *block_size, int *block_fd)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    UINT32             crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_fetch_block_fd_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_fetch_block_fd_b_ep: no CRFSC for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(MOD_NODE_TCID(&recv_mod_node) != CMPI_LOCAL_TCID)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_fetch_block_fd_b_ep: file '%s' not in current CRFSC\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_fetch_block_fd_b_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_fetch_block_fd_b(crfs_md_id, file_path, offset, block_size, block_fd);
}

/**
*
*  renew a fnode to name node
*
**/
EC_BOOL crfsc_renew_ep(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_renew_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_renew_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_renew(crfs_md_id, file_path);
}

EC_BOOL crfsc_renew(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_renew: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_renew: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_renew_ep, CMPI_ERROR_MODI, file_path);

    return (result);
}

/**
*
*  delete a file
*
**/
EC_BOOL crfsc_delete_file_ep(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_delete_file_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_file_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_delete_file(crfs_md_id, file_path);
}

EC_BOOL crfsc_delete_file(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_delete_file: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_file: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_delete_file_ep, CMPI_ERROR_MODI, file_path);

    return (result);
}

/**
*
*  delete a big file
*
**/
EC_BOOL crfsc_delete_file_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_delete_file_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_file_b_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_delete_file_b(crfs_md_id, file_path);
}

EC_BOOL crfsc_delete_file_b(const UINT32 crfsc_md_id, const CSTRING *file_path)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_delete_file_b: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_file_b: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_delete_file_b_ep, CMPI_ERROR_MODI, file_path);

    return (result);
}

/**
*
*  delete a dir from all npp and all dn
*
**/
EC_BOOL crfsc_delete_dir_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_delete_dir_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    result = EC_TRUE;
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        if(EC_FALSE == crfs_delete_dir(crfs_md_id, dir_path))
        {
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_dir_ep: del dir '%s' from RFS %ld# failed\n",
                                (char *)cstring_get_str(dir_path), crfs_md_id);

            result = EC_FALSE;
        }
    }
    return (result);
}

EC_BOOL crfsc_delete_dir(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;

    CRFSDT_PNODE *crfsdt_pnode;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_delete_dir: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfsdt_pnode = crfsdt_lookup_pnode(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_dir: search pnode of path '%s' failed\n",
                            (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    mod_mgr = __crfsc_make_mod_mgr_by_pnode(crfsc_md_id, crfsdt_pnode);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_dir: make mod_mgr by pnode '%s' failed\n",
                            CRFSDT_PNODE_PATH_STR(crfsdt_pnode));
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0015);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_dir: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0016);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_delete_dir_ep, CMPI_ERROR_MODI, dir_path);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, task_default_bool_checker);

    result = EC_TRUE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get_no_lock(ret_vec, crfs_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0017);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_FALSE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete_dir: del dir '%s' on tcid %s failed\n",
                                (char *)cstring_get_str(dir_path), MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0018);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0019);
    mod_mgr_free(mod_mgr);

    return (result);
}


/**
*
*  delete a file or dir from all npp and all dn
*
**/
EC_BOOL crfsc_delete(const UINT32 crfsc_md_id, const CSTRING *path, const UINT32 dflag)
{
#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_delete: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return crfsc_delete_file(crfsc_md_id, path);
    }

    if(CRFSNP_ITEM_FILE_IS_BIG == dflag)
    {
        return crfsc_delete_file_b(crfsc_md_id, path);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return crfsc_delete_dir(crfsc_md_id, path);
    }

    if(CRFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        crfsc_delete_file(crfsc_md_id, path);
        crfsc_delete_file_b(crfsc_md_id, path);
        crfsc_delete_dir(crfsc_md_id, path);

        return (EC_TRUE);
    }

    dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_delete: crfsc_md_id %u, path [invalid 0x%x] %s\n",
                        crfsc_md_id, dflag, (char *)cstring_get_str(path));

    return (EC_FALSE);
}

/**
*
*  update a file
*
**/
EC_BOOL crfsc_update_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_update_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_update_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_update(crfs_md_id, file_path, cbytes);
}

EC_BOOL crfsc_update(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_update: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_update: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_update_ep, CMPI_ERROR_MODI, file_path, cbytes);

    return (result);
}

/**
*
*  query a file
*
**/
EC_BOOL crfsc_qfile_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_qfile_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_qfile_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_qfile(crfs_md_id, file_path, crfsnp_item);
}

EC_BOOL crfsc_qfile(const UINT32 crfsc_md_id, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_qfile: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_qfile: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_qfile_ep, CMPI_ERROR_MODI, file_path, crfsnp_item);

    return (result);
}


/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL crfsc_file_size_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *file_size)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_file_size_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_file_size_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_file_size(crfs_md_id, file_path, file_size);
}

EC_BOOL crfsc_file_size(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *file_size)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_file_size: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_file_size: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_file_size_ep, CMPI_ERROR_MODI, file_path, file_size);

    return (result);
}

/**
*
*  get bigfile store size of specific file given full path name
*
**/
EC_BOOL crfsc_store_size_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *store_size)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_store_size_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_store_size_b_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_store_size_b(crfs_md_id, file_path, store_size);
}

EC_BOOL crfsc_store_size_b(const UINT32 crfsc_md_id, const CSTRING *file_path, uint64_t *store_size)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_store_size_b: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_store_size_b: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_store_size_b_ep, CMPI_ERROR_MODI, file_path, store_size);

    return (result);
}

/**
*
*  get file md5sum of specific file given full path name
*
**/
EC_BOOL crfsc_file_md5sum_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, CMD5_DIGEST *md5sum)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_file_md5sum_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_file_md5sum_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_file_md5sum(crfs_md_id, file_path, md5sum);
}

EC_BOOL crfsc_file_md5sum(const UINT32 crfsc_md_id, const CSTRING *file_path, CMD5_DIGEST *md5sum)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_file_md5sum: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_file_md5sum: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_file_md5sum_ep, CMPI_ERROR_MODI, file_path, md5sum);

    return (result);
}

/**
*
*  get a seg md5sum of specific bigfile given full path name
*
**/

EC_BOOL crfsc_file_md5sum_b_ep(const UINT32 crfsc_md_id, const CSTRING *file_path, const UINT32 seg_no, CMD5_DIGEST *md5sum)
{
    UINT32  crfs_md_id;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_file_md5sum_b_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfs_md_id = __crfsc_get_rfs_modi_of_file_path(crfsc_md_id, file_path);
    if(CMPI_ERROR_MODI == crfs_md_id)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_file_md5sum_b_ep: no RFS for file '%s'\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return crfs_file_md5sum_b(crfs_md_id, file_path, seg_no, md5sum);
}

EC_BOOL crfsc_file_md5sum_b(const UINT32 crfsc_md_id, const CSTRING *file_path, const UINT32 seg_no, CMD5_DIGEST *md5sum)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_file_md5sum_b: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_file_md5sum_b: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_file_md5sum_b_ep, CMPI_ERROR_MODI, file_path, seg_no, md5sum);

    return (result);
}

EC_BOOL crfsc_file_mod_node(const UINT32 crfsc_md_id, const CSTRING *file_path, MOD_NODE *mod_node)
{
    CRFSC_MD          *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_file_mod_node: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_file_mod_node: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL crfsc_recycle_ep(const UINT32 crfsc_md_id)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_recycle_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    result = EC_TRUE;
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        if(EC_FALSE == crfs_recycle(crfs_md_id, CRFS_RECYCLE_MAX_NUM, NULL_PTR))
        {
            result = EC_FALSE;

            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_recycle_ep: recycle RFS %ld# failed\n",
                                crfs_md_id);
        }
    }
    return (result);
}

EC_BOOL crfsc_recycle(const UINT32 crfsc_md_id)
{
    CRFSC_MD     *crfsc_md;
    CRFSDT       *crfsdt;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_recycle: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfsdt   = CRFSC_MD_ACTIVE_DIRTAB(crfsc_md);

    mod_mgr = __crfsc_make_mod_mgr_by_rnode_tree(crfsc_md_id, CRFSDT_RNODE_TREE(crfsdt));
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_recycle: make mod_mgr by rnode tree failed\n");
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0020);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_recycle: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0021);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_recycle_ep, CMPI_ERROR_MODI);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get_no_lock(ret_vec, crfs_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0022);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_FALSE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_recycle: recycle on tcid %s failed\n",
                                MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0023);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0024);
    mod_mgr_free(mod_mgr);

    return (result);
}

EC_BOOL crfsc_add_dir(const UINT32 crfsc_md_id, const UINT32 tcid, const CSTRING *path)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_add_dir: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);
    return crfsdt_add(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), tcid, path);
}

EC_BOOL crfsc_del_dir(const UINT32 crfsc_md_id, const UINT32 tcid, const CSTRING *path)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_del_dir: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);
    return crfsdt_del(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), tcid, path);
}

EC_BOOL crfsc_has_dir(const UINT32 crfsc_md_id, const UINT32 tcid, const CSTRING *path)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_has_dir: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    return crfsdt_has(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), tcid, path);
}

STATIC_CAST static EC_BOOL __crfsc_exist_dt(const CSTRING *crfs_root_dir)
{
    CSTRING  *dt_fname;

    dt_fname = cstring_make("%s/%s", (char *)cstring_get_str(crfs_root_dir), CRFSC_DIRTAB_FNAME);
    if(NULL_PTR == dt_fname)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_exist_dt: new dt_fname '%s/%s' failed\n",
                           (char *)cstring_get_str(crfs_root_dir), CRFSC_DIRTAB_FNAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)cstring_get_str(dt_fname), F_OK))
    {
        cstring_free(dt_fname);
        return (EC_FALSE);
    }

    cstring_free(dt_fname);
    return (EC_TRUE);
}

EC_BOOL crfsc_exist_dt(const UINT32 crfsc_md_id)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_exist_dt: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_exist_dt(CRFSC_MD_ROOT_DIR(crfsc_md)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*clone active dt to standby dt*/
EC_BOOL crfsc_clone_dt(const UINT32 crfsc_md_id)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_clone_dt: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);
    crfsdt_reset(CRFSC_MD_STANDBY_DIRTAB(crfsc_md));

    return crfsdt_clone(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), CRFSC_MD_STANDBY_DIRTAB(crfsc_md));
}

/*active dt ---> standby dt, standby dt ---> active dt*/
EC_BOOL crfsc_rollback_dt(const UINT32 crfsc_md_id)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_rollback_dt: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    CRFSC_MD_DT_ACTIVE_FLAG(crfsc_md) ^= 1;

    return (EC_TRUE);
}

EC_BOOL crfsc_flush_dt(const UINT32 crfsc_md_id)
{
    CRFSC_MD *crfsc_md;
    CSTRING  *dt_fname;
    UINT32    offset;
    int       dt_fd;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_flush_dt: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    dt_fname = cstring_make("%s/%s", (char *)cstring_get_str(CRFSC_MD_ROOT_DIR(crfsc_md)), CRFSC_DIRTAB_FNAME);
    if(NULL_PTR == dt_fname)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_flush_dt: new dt_fname '%s/%s' failed\n",
                           (char *)cstring_get_str(CRFSC_MD_ROOT_DIR(crfsc_md)), CRFSC_DIRTAB_FNAME);
        return (EC_FALSE);
    }

    dt_fd = c_file_open((char *)cstring_get_str(dt_fname), O_RDWR | O_CREAT, 0644);
    if(ERR_FD == dt_fd)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_flush_dt: open file '%s' failed\n",
                           (char *)cstring_get_str(dt_fname));
        cstring_free(dt_fname);
        return (EC_FALSE);
    }

    offset = 0;

    if(EC_FALSE == crfsdt_flush(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dt_fd, &offset))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_flush_dt: flush active dt to file '%s' failed and try to unlink it\n",
                           (char *)cstring_get_str(dt_fname));

        c_file_unlink((char *)cstring_get_str(dt_fname));

        cstring_free(dt_fname);
        c_file_close(dt_fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdt_flush(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), dt_fd, &offset))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_flush_dt: flush active dt to file '%s' failed and try to unlink it\n",
                           (char *)cstring_get_str(dt_fname));

        c_file_unlink((char *)cstring_get_str(dt_fname));

        cstring_free(dt_fname);
        c_file_close(dt_fd);
        return (EC_FALSE);
    }

    cstring_free(dt_fname);
    c_file_close(dt_fd);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsc_load_dt(CRFSDT *crfsdt_active, CRFSDT *crfsdt_standby, const CSTRING *crfs_root_dir)
{
    CSTRING  *dt_fname;
    UINT32    offset;
    int       dt_fd;

    if(EC_FALSE == crfsdt_is_empty(crfsdt_active))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_load_dt: active dt is not empty, give up loading\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdt_is_empty(crfsdt_standby))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_load_dt: standby dt is not empty, give up loading\n");
        return (EC_FALSE);
    }

    dt_fname = cstring_make("%s/%s", (char *)cstring_get_str(crfs_root_dir), CRFSC_DIRTAB_FNAME);
    if(NULL_PTR == dt_fname)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_load_dt: new dt_fname '%s/%s' failed\n",
                           (char *)cstring_get_str(crfs_root_dir), CRFSC_DIRTAB_FNAME);
        return (EC_FALSE);
    }

    dt_fd = c_file_open((char *)cstring_get_str(dt_fname), O_RDONLY, 0644);
    if(ERR_FD == dt_fd)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_load_dt: open file '%s' failed\n",
                           (char *)cstring_get_str(dt_fname));
        cstring_free(dt_fname);
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == crfsdt_load(crfsdt_active, dt_fd, &offset))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_load_dt: load active dt from file '%s' failed\n",
                           (char *)cstring_get_str(dt_fname));
        cstring_free(dt_fname);
        c_file_close(dt_fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdt_load(crfsdt_standby, dt_fd, &offset))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:__crfsc_load_dt: load standby dt from file '%s' failed\n",
                           (char *)cstring_get_str(dt_fname));
        cstring_free(dt_fname);
        c_file_close(dt_fd);
        return (EC_FALSE);
    }

    cstring_free(dt_fname);
    c_file_close(dt_fd);

    return (EC_TRUE);
}

EC_BOOL crfsc_load_dt(const UINT32 crfsc_md_id)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_load_dt: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    CRFSC_MD_DT_ACTIVE_FLAG(crfsc_md) = 0;

    if(EC_FALSE == __crfsc_load_dt(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), CRFSC_MD_STANDBY_DIRTAB(crfsc_md), CRFSC_MD_ROOT_DIR(crfsc_md)))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_load_dt: load  dt failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void crfsc_print_dt(const UINT32 crfsc_md_id, LOG *log)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_print_dt: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    sys_log(log, "active dirtab is \n");
    crfsdt_print(log, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md));

    sys_log(log, "standby dirtab is \n");
    crfsdt_print(log, CRFSC_MD_STANDBY_DIRTAB(crfsc_md));

    return;
}

/**
*
*  transfer dir prepare based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_pre_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_pre_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    result = EC_TRUE;
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_pre_ep: transfer dir '%s' in RFS %ld# beg\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);

        if(EC_FALSE == crfs_transfer_pre(crfs_md_id, crfsc_md_id, dir_path, crfsdt_pnode))
        {
            result = EC_FALSE;

            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_pre_ep: transfer dir '%s' in RFS %ld# failed\n",
                                (char *)cstring_get_str(dir_path), crfs_md_id);
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_pre_ep: transfer dir '%s' in RFS %ld# end\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);
    }
    return (result);
}

EC_BOOL crfsc_trans_dir_pre(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;

    CRFSDT_PNODE *crfsdt_pnode_src;
    CRFSDT_PNODE *crfsdt_pnode_des;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_pre: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    /*lookup pnode in ACTIVE dirtab*/
    crfsdt_pnode_src = crfsdt_lookup_pnode(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_src)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_pre: lookup pnode of dir '%s' in active dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    crfsdt_pnode_des = crfsdt_lookup_pnode(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_des)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_pre: lookup pnode of dir '%s' in standby dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    mod_mgr = __crfsc_make_mod_mgr_by_pnode(crfsc_md_id, crfsdt_pnode_src);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_pre: make mod_mgr by pnode failed\n");
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0025);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_pre: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0026);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_trans_dir_pre_ep, CMPI_ERROR_MODI, dir_path, crfsdt_pnode_des);
    }

    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get_no_lock(ret_vec, crfs_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0027);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_FALSE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            sys_log(LOGSTDOUT, "error:crfsc_trans_dir_pre: transfer dir '%s' on tcid %s failed\n",
                                (char *)cstring_get_str(dir_path), MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0028);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0029);
    mod_mgr_free(mod_mgr);

    return (result);
}


/**
*
*  transfer dir handle based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_handle_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_handle_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    result = EC_TRUE;
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_handle_ep: transfer dir '%s' handle in RFS %ld# beg\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);

        if(EC_FALSE == crfs_transfer_handle(crfs_md_id, crfsc_md_id, dir_path, crfsdt_pnode))
        {
            result = EC_FALSE;

            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_handle_ep: transfer dir '%s' handle in RFS %ld# failed\n",
                                (char *)cstring_get_str(dir_path), crfs_md_id);
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_handle_ep: transfer dir '%s' handle in RFS %ld# end\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);
    }
    return (result);
}

EC_BOOL crfsc_trans_dir_handle(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;

    CRFSDT_PNODE *crfsdt_pnode_src;
    CRFSDT_PNODE *crfsdt_pnode_des;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_handle: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfsdt_pnode_src = crfsdt_lookup_pnode(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_src)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_handle: lookup pnode of dir '%s' in active dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    crfsdt_pnode_des = crfsdt_lookup_pnode(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_des)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_handle: lookup pnode of dir '%s' in standby dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    mod_mgr = __crfsc_make_mod_mgr_by_pnode(crfsc_md_id, crfsdt_pnode_src);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_handle: make mod_mgr by pnode failed\n");
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0030);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_handle: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0031);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_trans_dir_handle_ep, CMPI_ERROR_MODI, dir_path, crfsdt_pnode_des);
    }

    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get_no_lock(ret_vec, crfs_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0032);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_FALSE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_handle: transfer dir '%s' handle on tcid %s failed\n",
                                (char *)cstring_get_str(dir_path), MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0033);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0034);
    mod_mgr_free(mod_mgr);

    return (result);
}

/**
*
*  transfer dir post clean based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_post_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_post_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    result = EC_TRUE;
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_post_ep: transfer dir '%s' post clean in RFS %ld# beg\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);

        if(EC_FALSE == crfs_transfer_post(crfs_md_id, crfsc_md_id, dir_path, crfsdt_pnode))
        {
            result = EC_FALSE;

            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_post_ep: transfer dir '%s' post clean in RFS %ld# failed\n",
                                (char *)cstring_get_str(dir_path), crfs_md_id);
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_post_ep: transfer dir '%s' post clean in RFS %ld# end\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);
    }
    return (result);
}

EC_BOOL crfsc_trans_dir_post(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;

    CRFSDT_PNODE *crfsdt_pnode_src;
    CRFSDT_PNODE *crfsdt_pnode_des;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_post: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfsdt_pnode_src = crfsdt_lookup_pnode(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_src)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_post: lookup pnode of dir '%s' in active dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    crfsdt_pnode_des = crfsdt_lookup_pnode(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_des)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_post: lookup pnode of dir '%s' in standby dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    mod_mgr = __crfsc_make_mod_mgr_by_pnode(crfsc_md_id, crfsdt_pnode_src);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_post: make mod_mgr by pnode failed\n");
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0035);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_post: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0036);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_trans_dir_post_ep, CMPI_ERROR_MODI, dir_path, crfsdt_pnode_des);
    }

    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get_no_lock(ret_vec, crfs_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0037);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_FALSE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_post: transfer dir '%s' post clean on tcid %s failed\n",
                                (char *)cstring_get_str(dir_path), MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0038);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0039);
    mod_mgr_free(mod_mgr);

    return (result);
}

/**
*
*  transfer dir recycle based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_recycle_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_recycle_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    result = EC_TRUE;
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_recycle_ep: transfer dir '%s' recycle in RFS %ld# beg\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);

        if(EC_FALSE == crfs_transfer_recycle(crfs_md_id, crfsc_md_id, dir_path, crfsdt_pnode))
        {
            result = EC_FALSE;

            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_recycle_ep: transfer dir '%s' recycle in RFS %ld# failed\n",
                                (char *)cstring_get_str(dir_path), crfs_md_id);
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_recycle_ep: transfer dir '%s' recycle in RFS %ld# end\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);
    }
    return (result);
}

EC_BOOL crfsc_trans_dir_recycle(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;

    CRFSDT_PNODE *crfsdt_pnode_src;
    CRFSDT_PNODE *crfsdt_pnode_des;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_recycle: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfsdt_pnode_src = crfsdt_lookup_pnode(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_src)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_recycle: lookup pnode of dir '%s' in active failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    crfsdt_pnode_des = crfsdt_lookup_pnode(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_des)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_recycle: lookup pnode of dir '%s' in standby failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    mod_mgr = __crfsc_make_mod_mgr_by_pnode(crfsc_md_id, crfsdt_pnode_src);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_recycle: make mod_mgr by pnode failed\n");
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0040);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_recycle: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0041);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_trans_dir_recycle_ep, CMPI_ERROR_MODI, dir_path, crfsdt_pnode_des);
    }

    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get_no_lock(ret_vec, crfs_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0042);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_FALSE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_recycle: transfer dir '%s' on tcid %s failed\n",
                                (char *)cstring_get_str(dir_path), MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0043);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0044);
    mod_mgr_free(mod_mgr);

    return (result);
}


/**
*
*  transfer dir based on consistency hash table
*
**/
EC_BOOL crfsc_trans_dir_whole_ep(const UINT32 crfsc_md_id, const CSTRING *dir_path, const CRFSDT_PNODE *crfsdt_pnode)
{
    CRFSC_MD     *crfsc_md;
    UINT32        crfs_num;
    UINT32        crfs_pos;

    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_whole_ep: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfs_num = cvector_size(CRFSC_MD_CRFS_VEC(crfsc_md));

    result = EC_TRUE;
    for(crfs_pos = 0; crfs_pos < crfs_num; crfs_pos ++)
    {
        UINT32 crfs_md_id;

        crfs_md_id = __crfsc_get_modi(crfsc_md_id, crfs_pos);
        if(CMPI_ERROR_MODI == crfs_md_id)
        {
            continue;
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_whole_ep: transfer dir '%s' in RFS %ld# beg\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);

        if(EC_FALSE == crfs_transfer(crfs_md_id, crfsc_md_id, dir_path, crfsdt_pnode))
        {
            result = EC_FALSE;

            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_whole_ep: transfer dir '%s' in RFS %ld# failed\n",
                                (char *)cstring_get_str(dir_path), crfs_md_id);
        }

        dbg_log(SEC_0143_CRFSC, 9)(LOGSTDOUT, "[DEBUG] crfsc_trans_dir_whole_ep: transfer dir '%s' in RFS %ld# end\n",
                            (char *)cstring_get_str(dir_path), crfs_md_id);
    }
    return (result);
}

EC_BOOL crfsc_trans_dir_whole(const UINT32 crfsc_md_id, const CSTRING *dir_path)
{
    CRFSC_MD     *crfsc_md;

    CRFSDT_PNODE *crfsdt_pnode_src;
    CRFSDT_PNODE *crfsdt_pnode_des;

    MOD_MGR      *mod_mgr;
    TASK_MGR     *task_mgr;

    UINT32        crfs_mod_node_num;
    UINT32        crfs_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_trans_dir_whole: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    crfsdt_pnode_src = crfsdt_lookup_pnode(CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_src)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_whole: lookup pnode of dir '%s' in active dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    crfsdt_pnode_des = crfsdt_lookup_pnode(CRFSC_MD_STANDBY_DIRTAB(crfsc_md), dir_path);
    if(NULL_PTR == crfsdt_pnode_des)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_whole: lookup pnode of dir '%s' in standby dt failed\n",
                           (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    mod_mgr = __crfsc_make_mod_mgr_by_pnode(crfsc_md_id, crfsdt_pnode_src);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_whole: make mod_mgr by pnode failed\n");
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CRFSC_0045);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_whole: new ret_vec failed\n");
        mod_mgr_free(mod_mgr);
        return (EC_FALSE);
    }

    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    crfs_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        MOD_NODE *recv_mod_node;
        UINT32   *ret;

        recv_mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);

        alloc_static_mem(MM_UINT32, &ret, LOC_CRFSC_0046);
        cvector_push(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;/*init*/

        task_p2p_inc(task_mgr, crfsc_md_id, recv_mod_node, ret, FI_crfsc_trans_dir_whole_ep, CMPI_ERROR_MODI, dir_path, crfsdt_pnode_des);
    }

    task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    for(crfs_mod_node_idx = 0; crfs_mod_node_idx < crfs_mod_node_num; crfs_mod_node_idx ++)
    {
        UINT32  *ret;

        ret = (UINT32  *)cvector_get_no_lock(ret_vec, crfs_mod_node_idx);
        if(EC_TRUE == (*ret))
        {
            free_static_mem(MM_UINT32, ret, LOC_CRFSC_0047);
            cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
            continue;
        }

        result = EC_FALSE;

        if(do_log(SEC_0143_CRFSC, 9))
        {
            MOD_NODE *mod_node;
            mod_node = MOD_MGR_REMOTE_MOD(mod_mgr, crfs_mod_node_idx);
            dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_trans_dir_whole: transfer dir '%s' on tcid %s failed\n",
                                (char *)cstring_get_str(dir_path), MOD_NODE_TCID_STR(mod_node));
        }

        free_static_mem(MM_UINT32, ret, LOC_CRFSC_0048);
        cvector_set(ret_vec, crfs_mod_node_idx, NULL_PTR);
    }

    cvector_free(ret_vec, LOC_CRFSC_0049);
    mod_mgr_free(mod_mgr);

    return (result);
}

/*------------------------------------------------ interface for replica ------------------------------------------------*/
#if 0
EC_BOOL crfsc_write_r(const UINT32 crfsc_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CRFSC_MD          *crfsc_md;

    MOD_NODE           recv_mod_node;
    EC_BOOL            result;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_write_r: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);

    if(EC_FALSE == __crfsc_get_rfsc_mod_node_of_file_path(crfsc_md_id, CRFSC_MD_ACTIVE_DIRTAB(crfsc_md), file_path, &recv_mod_node))
    {
        dbg_log(SEC_0143_CRFSC, 0)(LOGSTDOUT, "error:crfsc_write_r: no RFS for file '%s'\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    result = EC_FALSE;
    task_p2p(crfsc_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &result, FI_crfsc_write_ep, CMPI_ERROR_MODI, file_path, cbytes);

    return (result);
}
#endif
EC_BOOL crfsc_rdlock(const UINT32 crfsc_md_id, const UINT32 location)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_rdlock: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);
    CRFSC_RDLOCK(crfsc_md, location);
    return (EC_TRUE);
}

EC_BOOL crfsc_wrlock(const UINT32 crfsc_md_id, const UINT32 location)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_wrlock: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);
    CRFSC_WRLOCK(crfsc_md, location);
    return (EC_TRUE);
}

EC_BOOL crfsc_unlock(const UINT32 crfsc_md_id, const UINT32 location)
{
    CRFSC_MD *crfsc_md;

#if ( SWITCH_ON == CRFSC_DEBUG_SWITCH )
    if ( CRFSC_MD_ID_CHECK_INVALID(crfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsc_unlock: crfs module #0x%lx not started.\n",
                crfsc_md_id);
        dbg_exit(MD_CRFSC, crfsc_md_id);
    }
#endif/*CRFSC_DEBUG_SWITCH*/

    crfsc_md = CRFSC_MD_GET(crfsc_md_id);
    CRFSC_UNLOCK(crfsc_md, location);
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

