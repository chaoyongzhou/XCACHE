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

#include "cdfs.h"
#include "cload.h"

#include "findex.inc"

#define CDFS_MD_CAPACITY()                  (cbc_md_capacity(MD_CDFS))

#define CDFS_MD_GET(cdfs_md_id)     ((CDFS_MD *)cbc_md_get(MD_CDFS, (cdfs_md_id)))

#define CDFS_MD_ID_CHECK_INVALID(cdfs_md_id)  \
    ((CMPI_ANY_MODI != (cdfs_md_id)) && ((NULL_PTR == CDFS_MD_GET(cdfs_md_id)) || (0 == (CDFS_MD_GET(cdfs_md_id)->usedcounter))))


/**
*   for test only
*
*   to query the status of CDFS Module
*
**/
void cdfs_print_module_status(const UINT32 cdfs_md_id, LOG *log)
{
    CDFS_MD *cdfs_md;
    UINT32 this_cdfs_md_id;

    for( this_cdfs_md_id = 0; this_cdfs_md_id < CDFS_MD_CAPACITY(); this_cdfs_md_id ++ )
    {
        cdfs_md = CDFS_MD_GET(this_cdfs_md_id);

        if ( NULL_PTR != cdfs_md && 0 < cdfs_md->usedcounter )
        {
            sys_log(log,"CDFS Module # %ld : %ld refered\n",
                    this_cdfs_md_id,
                    cdfs_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CDFS module
*
*
**/
UINT32 cdfs_free_module_static_mem(const UINT32 cdfs_md_id)
{
    CDFS_MD  *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_free_module_static_mem: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    free_module_static_mem(MD_CDFS, cdfs_md_id);

    return 0;
}

/**
*
* start CDFS module
*
**/
UINT32 cdfs_start(const UINT32 cdfsnp_min_num)
{
    CDFS_MD *cdfs_md;
    UINT32 cdfs_md_id;

    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();

    cbc_md_reg(MD_CDFS    , 32);
 
    /*check rank validity*/
    if(CMPI_CDFS_RANK != TASK_BRD_RANK(task_brd))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_start: current rank is %ld but hsdfs should deploy on rank %ld\n",
                            TASK_BRD_RANK(task_brd), CMPI_CDFS_RANK);
        return (CMPI_ERROR_MODI);
    }

    cdfs_md_id = cbc_md_new(MD_CDFS, sizeof(CDFS_MD));
    if(CMPI_ERROR_MODI == cdfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CDFS module */
    cdfs_md = (CDFS_MD *)cbc_md_get(MD_CDFS, cdfs_md_id);
    cdfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem(); 

    CDFS_MD_DN_MOD_MGR(cdfs_md)  = mod_mgr_new(cdfs_md_id, /*LOAD_BALANCING_LOOP*//*LOAD_BALANCING_MOD*/LOAD_BALANCING_QUE);
    CDFS_MD_NPP_MOD_MGR(cdfs_md) = mod_mgr_new(cdfs_md_id, /*LOAD_BALANCING_LOOP*//*LOAD_BALANCING_MOD*/LOAD_BALANCING_QUE);

    CDFS_MD_DN(cdfs_md)  = NULL_PTR;
    CDFS_MD_NPP(cdfs_md) = NULL_PTR;

    CDFS_MD_NP_MIN_NUM(cdfs_md) = cdfsnp_min_num;

    cdfs_md->usedcounter = 1;

    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "cdfs_start: start CDFS module #%ld\n", cdfs_md_id);
    //dbg_log(SEC_0056_CDFS, 3)(LOGSTDOUT, "========================= cdfs_start: CDFS table info:\n");
    //cdfs_print_module_status(cdfs_md_id, LOGSTDOUT);
    //cbc_print();

    return ( cdfs_md_id );
}

/**
*
* end CDFS module
*
**/
void cdfs_end(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    if(NULL_PTR == cdfs_md)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT,"error:cdfs_end: cdfs_md_id = %ld not exist.\n", cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cdfs_md->usedcounter )
    {
        cdfs_md->usedcounter --;
        return ;
    }

    if ( 0 == cdfs_md->usedcounter )
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT,"error:cdfs_end: cdfs_md_id = %ld is not started.\n", cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }

    /* if nobody else occupied the module,then free its resource */
    if(NULL_PTR != CDFS_MD_DN(cdfs_md))
    {
        cdfsdn_free(CDFS_MD_DN(cdfs_md));
        CDFS_MD_DN(cdfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CDFS_MD_NPP(cdfs_md))
    {
        cdfsnp_mgr_free(CDFS_MD_NPP(cdfs_md));
        CDFS_MD_NPP(cdfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CDFS_MD_DN_MOD_MGR(cdfs_md))
    {
        mod_mgr_free(CDFS_MD_DN_MOD_MGR(cdfs_md));
        CDFS_MD_DN_MOD_MGR(cdfs_md)  = NULL_PTR;
    }

    if(NULL_PTR != CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        mod_mgr_free(CDFS_MD_NPP_MOD_MGR(cdfs_md));
        CDFS_MD_NPP_MOD_MGR(cdfs_md)  = NULL_PTR;
    }
 
    /* free module : */
    //cdfs_free_module_static_mem(cdfs_md_id);

    cdfs_md->usedcounter = 0;

    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "cdfs_end: stop CDFS module #%ld\n", cdfs_md_id);
    cbc_md_free(MD_CDFS, cdfs_md_id);

    breathing_static_mem();

    //dbg_log(SEC_0056_CDFS, 3)(LOGSTDOUT, "========================= cdfs_end: CDFS table info:\n");
    //cdfs_print_module_status(cdfs_md_id, LOGSTDOUT);
    //cbc_print();

    return ;
}

static EC_BOOL cdfs_tcid_is_connected(const UINT32 tcid)
{
    TASK_BRD *task_brd;

    task_brd = task_brd_default_get();
    return task_brd_check_tcid_connected(task_brd, tcid);
}

static EC_BOOL cdfs_dn_is_connected(const UINT32 cdfs_md_id, const UINT32 cdfsnp_tcid)
{
    CDFS_MD   *cdfs_md;
    UINT32     remote_mod_node_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_dn_is_connected: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    for(remote_mod_node_pos = 0; remote_mod_node_pos < MOD_MGR_REMOTE_NUM(CDFS_MD_DN_MOD_MGR(cdfs_md)); remote_mod_node_pos ++)
    {
        MOD_NODE *mod_node;

        mod_node = MOD_MGR_REMOTE_MOD(CDFS_MD_DN_MOD_MGR(cdfs_md), remote_mod_node_pos);

        if(cdfsnp_tcid == MOD_NODE_TCID(mod_node))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

static EC_BOOL cdfs_collect_fnode_all_tcid(const CDFSNP_FNODE *cdfsnp_fnode, const UINT32 cdfsnp_inode_num, CVECTOR *tcid_vec)
{
    UINT32 cdfsnp_inode_pos;

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_collect_fnode_all_tcid: cdfsnp_inode_num = %ld\n", cdfsnp_inode_num);

    for(cdfsnp_inode_pos = 0;
        cdfsnp_inode_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && cdfsnp_inode_pos < cdfsnp_inode_num && cdfsnp_inode_pos < CDFSNP_FILE_REPLICA_MAX_NUM;
        cdfsnp_inode_pos ++
        )
    {
        cvector_push(tcid_vec, (void *)CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos));
        dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_collect_fnode_all_tcid: replica num %ld, inode num %ld, inode pos %ld, push tcid = %s\n",
                            CDFSNP_FNODE_REPNUM(cdfsnp_fnode), cdfsnp_inode_num,
                            cdfsnp_inode_pos,
                            c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos))
                            );
    }

    return (EC_TRUE);
}

static EC_BOOL cdfs_collect_dn_mod_mgr_disable_tcid(MOD_MGR *dn_mod_mgr, CVECTOR *tcid_vec)
{
    UINT32 mod_node_pos;
    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(dn_mod_mgr), LOC_CDFS_0001);
    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(dn_mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *mod_node;

        mod_node = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(dn_mod_mgr), mod_node_pos);
        if(NULL_PTR == mod_node)
        {
            continue;
        }

        if(CDFS_MOD_NODE_WRITE_DISABLE == MOD_NODE_STAT(mod_node))
        {
            cvector_push(tcid_vec, (void *)MOD_NODE_TCID(mod_node));
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(dn_mod_mgr), LOC_CDFS_0002);
    return (EC_TRUE);
}

static EC_BOOL cdfs_get_next_succ_inode_pos(const UINT32 cdfs_md_id, const CDFSNP_FNODE *cdfsnp_fnode, const UINT32 cdfsnp_inode_beg_pos, UINT32 *cdfsnp_inode_next_pos)
{
    UINT32 cdfsnp_inode_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_get_next_succ_inode_pos: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        cdfs_print_module_status(cdfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    for(cdfsnp_inode_pos = cdfsnp_inode_beg_pos + 1;
        cdfsnp_inode_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) &&
        cdfsnp_inode_pos < CDFSNP_FILE_REPLICA_MAX_NUM;
        cdfsnp_inode_pos ++
        )
    {
        if(CDFSNP_ERR_PATH != CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) &&
           CDFSNP_ERR_FOFF != CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos)&&
           EC_TRUE == cdfs_dn_is_connected(cdfs_md_id, CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos))
           )
        {
            (*cdfsnp_inode_next_pos) = cdfsnp_inode_pos;
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/**
*
*   new a dn mod_mgr to write access
*   skip mod_node which are marked as CDFS_MOD_NODE_WRITE_DISABLE
*
**/
static MOD_MGR *cdfs_new_dn_mod_mgr_to_write(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;
    MOD_MGR *mod_mgr_src;
    MOD_MGR *mod_mgr_des;

    UINT32   mod_node_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_new_dn_mod_mgr: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        cdfs_print_module_status(cdfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    mod_mgr_src = CDFS_MD_DN_MOD_MGR(cdfs_md);
    if(NULL_PTR == mod_mgr_src)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_new_dn_mod_mgr: dn mod mgr is null\n");
        return (NULL_PTR);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_new_dn_mod_mgr: mod_mgr src is\n");
    //mod_mgr_print(LOGSTDOUT, mod_mgr_src);

    mod_mgr_des = mod_mgr_new(cdfs_md_id, MOD_MGR_LDB_CHOICE(mod_mgr_src));
    if(NULL_PTR == mod_mgr_des)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_new_dn_mod_mgr:  new mod mgr failed\n");
        return (NULL_PTR);
    }

    /*refer source code of function mod_mgr_limited_clone*/
    MOD_MGR_LDB_FUNCPTR(mod_mgr_des) = MOD_MGR_LDB_FUNCPTR(mod_mgr_src);

    /*clone local mod node*/
    mod_node_clone(MOD_MGR_LOCAL_MOD(mod_mgr_src), MOD_MGR_LOCAL_MOD(mod_mgr_des));

    /*fiter and clone remote mod node which permit write to dn*/
    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr_src), LOC_CDFS_0003);
    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr_src)); mod_node_pos ++)
    {
        MOD_NODE *mod_node_src;

        mod_node_src = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr_src), mod_node_pos);
        if(NULL_PTR == mod_node_src)
        {
            continue;
        }

        if(CDFS_MOD_NODE_WRITE_DISABLE != MOD_NODE_STAT(mod_node_src))
        {
            MOD_NODE *mod_node_des;

            alloc_static_mem(MM_MOD_NODE, &mod_node_des, LOC_CDFS_0004);
            mod_node_clone(mod_node_src, mod_node_des);
            cvector_push(MOD_MGR_REMOTE_LIST(mod_mgr_des), (void *)mod_node_des);
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr_src), LOC_CDFS_0005);

    MOD_MGR_REMOTE_POS(mod_mgr_des) = 0;/*reset*/

    MOD_MGR_LOCAL_MOD_POS(mod_mgr_des) = cvector_search_front(MOD_MGR_REMOTE_LIST(mod_mgr_des), MOD_MGR_LOCAL_MOD(mod_mgr_des), (CVECTOR_DATA_CMP)mod_node_cmp);

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_new_dn_mod_mgr: mod_mgr des is\n");
    mod_mgr_print(LOGSTDOUT, mod_mgr_des);

    return (mod_mgr_des);
}

/**
*
*   disable write access to a mod node in dn mod_mgr
*
**/
EC_BOOL cdfs_disable_write_access_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid)
{
    CDFS_MD *cdfs_md;
    MOD_MGR *mod_mgr;

    UINT32   mod_node_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_disable_write_access_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        cdfs_print_module_status(cdfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    mod_mgr = CDFS_MD_DN_MOD_MGR(cdfs_md);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_disable_write_access_dn: dn mod mgr is null\n");
        return (EC_FALSE);
    }

    CVECTOR_LOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_CDFS_0006);
    for(mod_node_pos = 0; mod_node_pos < cvector_size(MOD_MGR_REMOTE_LIST(mod_mgr)); mod_node_pos ++)
    {
        MOD_NODE *mod_node;

        mod_node = (MOD_NODE *)cvector_get_no_lock(MOD_MGR_REMOTE_LIST(mod_mgr), mod_node_pos);
        if(NULL_PTR == mod_node)
        {
            continue;
        }

        if(cdfsdn_tcid == MOD_NODE_TCID(mod_node))
        {
            MOD_NODE_STAT(mod_node) = CDFS_MOD_NODE_WRITE_DISABLE;
        }
    }
    CVECTOR_UNLOCK(MOD_MGR_REMOTE_LIST(mod_mgr), LOC_CDFS_0007);

    return (EC_TRUE);
}

/**
*
* initialize mod mgr of CDFS module
*
**/
UINT32 cdfs_set_npp_mod_mgr(const UINT32 cdfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CDFS_MD *cdfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_set_npp_mod_mgr: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        cdfs_print_module_status(cdfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    des_mod_mgr = CDFS_MD_NPP_MOD_MGR(cdfs_md);

    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "cdfs_set_npp_mod_mgr: md_id %d, input src_mod_mgr %lx\n", cdfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of cdfsnp_tcid_vec and cdfsnp_tcid_vec*/
    mod_mgr_limited_clone(cdfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "====================================cdfs_set_npp_mod_mgr: des_mod_mgr %lx beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "====================================cdfs_set_npp_mod_mgr: des_mod_mgr %lx end====================================\n", des_mod_mgr);

    return (0);
}

UINT32 cdfs_set_dn_mod_mgr(const UINT32 cdfs_md_id, const MOD_MGR * src_mod_mgr)
{
    CDFS_MD *cdfs_md;
    MOD_MGR  *des_mod_mgr;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_set_dn_mod_mgr: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        cdfs_print_module_status(cdfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    des_mod_mgr = CDFS_MD_DN_MOD_MGR(cdfs_md);

    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "cdfs_set_dn_mod_mgr: md_id %d, input src_mod_mgr %lx\n", cdfs_md_id, src_mod_mgr);
    mod_mgr_print(LOGSTDOUT, src_mod_mgr);

    /*figure out mod_nodes with tcid belong to set of cdfsnp_tcid_vec and cdfsnp_tcid_vec*/
    mod_mgr_limited_clone(cdfs_md_id, src_mod_mgr, des_mod_mgr);

    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "====================================cdfs_set_dn_mod_mgr: des_mod_mgr %lx beg====================================\n", des_mod_mgr);
    mod_mgr_print(LOGSTDOUT, des_mod_mgr);
    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "====================================cdfs_set_dn_mod_mgr: des_mod_mgr %lx end====================================\n", des_mod_mgr);

    return (0);
}

/**
*
* get mod mgr of CDFS module
*
**/
MOD_MGR * cdfs_get_npp_mod_mgr(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;

    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    return CDFS_MD_NPP_MOD_MGR(cdfs_md);
}

MOD_MGR * cdfs_get_dn_mod_mgr(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;

    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        return (MOD_MGR *)0;
    }

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    return CDFS_MD_DN_MOD_MGR(cdfs_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL cdfs_open_npp(const UINT32 cdfs_md_id, const CSTRING *cdfsnp_db_root_dir, const UINT32 cdfsnp_cached_max_num)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_open_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR != CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_open_npp: someone name node pool was open\n");
        return (EC_FALSE);
    }

    CDFS_MD_NPP(cdfs_md) = cdfsnp_mgr_open(cdfsnp_db_root_dir, cdfsnp_cached_max_num);
    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_open_npp: open name node pool from root dir %s failed\n", (char *)cstring_get_str(cdfsnp_db_root_dir));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  close name node pool
*
**/
EC_BOOL cdfs_close_npp(const UINT32 cdfs_md_id)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_close_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_close_npp: name node pool was not open\n");
        return (EC_FALSE);
    }

    cdfsnp_mgr_close(CDFS_MD_NPP(cdfs_md));
    CDFS_MD_NPP(cdfs_md) = NULL_PTR;
    return (EC_TRUE);
}

/**
*
*  flush and close name node pool
*
**/
EC_BOOL cdfs_close_with_flush_npp(const UINT32 cdfs_md_id)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_close_with_flush_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_close_with_flush_npp: name node pool was not open\n");
        return (EC_FALSE);
    }

    cdfsnp_mgr_close_with_flush(CDFS_MD_NPP(cdfs_md));
    CDFS_MD_NPP(cdfs_md) = NULL_PTR;
    return (EC_TRUE);
}



/*collect all dn tcid vec*/
EC_BOOL cdfs_collect_dn_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfsdn_tcid_vec)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_collect_dn_tcid_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    sys_cfg_collect_hsdfs_dn_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)),  cdfsdn_tcid_vec);

    return (EC_TRUE);
}

/*collect all npp tcid vec*/
EC_BOOL cdfs_collect_npp_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfsnpp_tcid_vec)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_collect_npp_tcid_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    sys_cfg_collect_hsdfs_np_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), cdfsnpp_tcid_vec);

    return (EC_TRUE);
}

/*collect all dn & npp tcid vec*/
EC_BOOL cdfs_collect_cluster_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfs_cluster_tcid_vec)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_collect_cluster_tcid_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    sys_cfg_collect_hsdfs_np_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), cdfs_cluster_tcid_vec);
    sys_cfg_collect_hsdfs_dn_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), cdfs_cluster_tcid_vec);
    return (EC_TRUE);
}

/*collect all dn & npp & client tcid vec*/
EC_BOOL cdfs_collect_all_tcid_vec(const UINT32 cdfs_md_id, CVECTOR *cdfs_all_tcid_vec)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_collect_all_tcid_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    sys_cfg_collect_hsdfs_np_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), cdfs_all_tcid_vec);
    sys_cfg_collect_hsdfs_dn_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), cdfs_all_tcid_vec);
    sys_cfg_collect_hsdfs_client_tcid_vec(TASK_BRD_SYS_CFG(task_brd), TASKS_CFG_CLUSTER_VEC(TASK_BRD_LOCAL_TASKS_CFG(task_brd)), cdfs_all_tcid_vec);
    return (EC_TRUE);
}

/**
*
*  create name node pool
*
**/
EC_BOOL cdfs_create_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnp_mode, const UINT32 cdfsnp_disk_max_num, const UINT32 cdfsnp_support_max_num, const UINT32 cdfsnp_first_chash_algo_id, const UINT32 cdfsnp_second_chash_algo_id, const CSTRING *cdfsnp_db_root_dir)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_create_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    return cdfsnp_mgr_create(cdfsnp_mode, cdfsnp_disk_max_num, cdfsnp_support_max_num, cdfsnp_first_chash_algo_id, cdfsnp_second_chash_algo_id, cdfsnp_db_root_dir);
}


EC_BOOL cdfs_add_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnpp_tcid)
{
    CDFS_MD   *cdfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_add_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, cdfsnpp_tcid))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_add_npp: cdfsnpp_tcid %s not connected\n", c_word_to_ipv4(cdfsnpp_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(cdfsnpp_tcid, CMPI_ANY_COMM, CMPI_CDFS_RANK, 0, CDFS_MD_NPP_MOD_MGR(cdfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), cdfsnpp_tcid, CMPI_CDFS_RANK, 0);

    return (EC_TRUE);
}

EC_BOOL cdfs_add_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid)
{
    CDFS_MD   *cdfs_md;

    TASK_BRD *task_brd;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_add_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    task_brd = task_brd_default_get();
#if 1
    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, cdfsdn_tcid))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_add_dn: cdfsdn_tcid %s not connected\n", c_word_to_ipv4(cdfsdn_tcid));
        return (EC_FALSE);
    }
#endif
    mod_mgr_incl(cdfsdn_tcid, CMPI_ANY_COMM, CMPI_CDFS_RANK, (UINT32)0, CDFS_MD_DN_MOD_MGR(cdfs_md));
    cload_mgr_set_que(TASK_BRD_CLOAD_MGR(task_brd), cdfsdn_tcid, CMPI_CDFS_RANK, 0);

    return (EC_TRUE);
}

EC_BOOL cdfs_add_dn_vec(const UINT32 cdfs_md_id)
{
    CVECTOR * cdfsdn_tcid_vec;
    UINT32    cdfsdn_tcid_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_add_dn_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfsdn_tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0008);
    if(NULL_PTR == cdfsdn_tcid_vec)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_add_dn_vec: new dn tcid vec failed\n");
        return (EC_FALSE);
    }

    cdfs_collect_dn_tcid_vec(cdfs_md_id, cdfsdn_tcid_vec);
    if(EC_FALSE == cdfs_collect_dn_tcid_vec(cdfs_md_id, cdfsdn_tcid_vec))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_add_dn_vec: collect dn tcid vec failed\n");
        cvector_free(cdfsdn_tcid_vec, LOC_CDFS_0009);
        return (EC_FALSE);
    }
    for(cdfsdn_tcid_pos = 0; cdfsdn_tcid_pos < cvector_size(cdfsdn_tcid_vec); cdfsdn_tcid_pos ++)
    {
        UINT32 cdfsdn_tcid;

        cdfsdn_tcid = (UINT32)cvector_get(cdfsdn_tcid_vec, cdfsdn_tcid_pos);
        dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_add_dn_vec: add dn %s\n", c_word_to_ipv4(cdfsdn_tcid));
        cdfs_add_dn(cdfs_md_id, cdfsdn_tcid);
    }

    cvector_clean(cdfsdn_tcid_vec, NULL_PTR, LOC_CDFS_0010);
    cvector_free(cdfsdn_tcid_vec, LOC_CDFS_0011);

    return (EC_TRUE);
}

EC_BOOL cdfs_add_npp_vec(const UINT32 cdfs_md_id)
{
    CVECTOR * cdfsnp_tcid_vec;
    UINT32    cdfsnp_tcid_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_add_npp_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfsnp_tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0012);
    if(NULL_PTR == cdfsnp_tcid_vec)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_add_npp_vec: new cdfsnp tcid vec failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfs_collect_npp_tcid_vec(cdfs_md_id, cdfsnp_tcid_vec))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_add_npp_vec: collect npp tcid vec failed\n");
        cvector_free(cdfsnp_tcid_vec, LOC_CDFS_0013);
        return (EC_FALSE);
    }

    for(cdfsnp_tcid_pos = 0; cdfsnp_tcid_pos < cvector_size(cdfsnp_tcid_vec); cdfsnp_tcid_pos ++)
    {
        UINT32 cdfsnp_tcid;

        cdfsnp_tcid = (UINT32)cvector_get(cdfsnp_tcid_vec, cdfsnp_tcid_pos);
        dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_add_npp_vec: add np %s\n", c_word_to_ipv4(cdfsnp_tcid));
        cdfs_add_npp(cdfs_md_id, cdfsnp_tcid);
    }

    cvector_clean(cdfsnp_tcid_vec, NULL_PTR, LOC_CDFS_0014);
    cvector_free(cdfsnp_tcid_vec, LOC_CDFS_0015);

    return (EC_TRUE);
}

EC_BOOL cdfs_reg_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnpp_tcid)
{
    CDFS_MD   *cdfs_md;

    TASK_BRD *task_brd;
    MOD_NODE recv_mod_node;
    EC_BOOL  ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_reg_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    task_brd = task_brd_default_get();

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, cdfsnpp_tcid))
    {
        return (EC_FALSE);
    }

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = cdfsnpp_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_reg_npp: register as np to %s\n", c_word_to_ipv4(cdfsnpp_tcid));
    task_super_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cdfs_add_npp, CMPI_ERROR_MODI, TASK_BRD_TCID(task_brd));
    return (ret);
}

EC_BOOL cdfs_reg_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid)
{
    CDFS_MD   *cdfs_md;

    TASK_BRD *task_brd;
    MOD_NODE recv_mod_node;
    EC_BOOL  ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_reg_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    task_brd = task_brd_default_get();

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, cdfsdn_tcid))
    {
        return (EC_FALSE);
    }

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = cdfsdn_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_reg_dn: register as dn to %s\n", c_word_to_ipv4(cdfsdn_tcid));
    task_super_mono(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cdfs_add_dn, CMPI_ERROR_MODI, TASK_BRD_TCID(task_brd));
    return (ret);
}

EC_BOOL cdfs_reg_dn_vec(const UINT32 cdfs_md_id)
{
    CDFS_MD   *cdfs_md;

    TASK_BRD *task_brd;
    MOD_NODE recv_mod_node;
    MOD_NODE send_mod_node;
    EC_BOOL  ret;

    CVECTOR *cdfs_cluster_tcid_vec;
    UINT32   cdfs_cluster_tcid_pos;

    TASK_MGR *task_mgr;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_reg_dn_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    task_brd = task_brd_default_get();

    cdfs_cluster_tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0016);
    if(NULL_PTR == cdfs_cluster_tcid_vec)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_reg_dn_vec: new cdfs cluster tcid vec failed\n");
        return (EC_FALSE);
    }

    cdfs_collect_cluster_tcid_vec(cdfs_md_id, cdfs_cluster_tcid_vec);

    MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&send_mod_node) = cdfs_md_id;

    task_mgr = task_new(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(cdfs_cluster_tcid_pos = 0; cdfs_cluster_tcid_pos < cvector_size(cdfs_cluster_tcid_vec); cdfs_cluster_tcid_pos ++)
    {
        UINT32 cdfsdn_tcid;

        cdfsdn_tcid = (UINT32)cvector_get(cdfs_cluster_tcid_vec, cdfs_cluster_tcid_pos);

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd, cdfsdn_tcid))
        {
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = cdfsdn_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_reg_dn_vec: register as dn to %s\n", c_word_to_ipv4(cdfsdn_tcid));
        task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, &ret, FI_cdfs_add_dn, CMPI_ERROR_MODI, TASK_BRD_TCID(task_brd));
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cvector_clean(cdfs_cluster_tcid_vec, NULL_PTR, LOC_CDFS_0017);
    cvector_free(cdfs_cluster_tcid_vec, LOC_CDFS_0018);

    return (EC_TRUE);
}

EC_BOOL cdfs_reg_npp_vec(const UINT32 cdfs_md_id)
{
    CDFS_MD   *cdfs_md;

    TASK_BRD *task_brd;
    MOD_NODE recv_mod_node;
    MOD_NODE send_mod_node;
    EC_BOOL  ret;

    CVECTOR *cdfs_cluster_tcid_vec;
    UINT32   cdfs_cluster_tcid_pos;

    TASK_MGR *task_mgr;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_reg_npp_vec: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    task_brd = task_brd_default_get();

    cdfs_cluster_tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0019);
    if(NULL_PTR == cdfs_cluster_tcid_vec)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_reg_npp_vec: new cdfs cluster tcid vec failed\n");
        return (EC_FALSE);
    }

    cdfs_collect_cluster_tcid_vec(cdfs_md_id, cdfs_cluster_tcid_vec);

    MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&send_mod_node) = cdfs_md_id;

    task_mgr = task_new(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(cdfs_cluster_tcid_pos = 0; cdfs_cluster_tcid_pos < cvector_size(cdfs_cluster_tcid_vec); cdfs_cluster_tcid_pos ++)
    {
        UINT32 cdfsnpp_tcid;

        cdfsnpp_tcid = (UINT32)cvector_get(cdfs_cluster_tcid_vec, cdfs_cluster_tcid_pos);

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd, cdfsnpp_tcid))
        {
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = cdfsnpp_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_reg_npp_vec: register as np to %s\n", TASK_BRD_TCID_STR(task_brd));
        task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, &ret, FI_cdfs_add_npp, CMPI_ERROR_MODI, TASK_BRD_TCID(task_brd));
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cvector_clean(cdfs_cluster_tcid_vec, NULL_PTR, LOC_CDFS_0020);
    cvector_free(cdfs_cluster_tcid_vec, LOC_CDFS_0021);

    return (EC_TRUE);
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL cdfs_find_dir(const UINT32 cdfs_md_id, const CSTRING *dir_path)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_find_dir: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_find_dir: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_find_dir(CDFS_MD_NPP(cdfs_md), dir_path);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL cdfs_find_file(const UINT32 cdfs_md_id, const CSTRING *file_path)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_find_file: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_find_file: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_find_file(CDFS_MD_NPP(cdfs_md), file_path);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL cdfs_find(const UINT32 cdfs_md_id, const CSTRING *path)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_find: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_find: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_find(CDFS_MD_NPP(cdfs_md), path, CDFSNP_ITEM_FILE_IS_ANY);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL cdfs_exists(const UINT32 cdfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_exists: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/
    return cdfs_find(cdfs_md_id, path);
}

EC_BOOL cdfs_exists_npp(const UINT32 cdfs_md_id, const CSTRING *path)
{
    CDFS_MD  *cdfs_md;
    TASK_MGR *task_mgr;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_exists_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_exists_npp: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    ret = EC_FALSE;

    task_mgr = task_new(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_inc(task_mgr, &ret, FI_cdfs_exists, CMPI_ERROR_MODI, path);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (ret);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL cdfs_is_file(const UINT32 cdfs_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_is_file: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    return cdfs_find_file(cdfs_md_id, file_path);;
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL cdfs_is_dir(const UINT32 cdfs_md_id, const CSTRING *dir_path)
{
#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_is_dir: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    return cdfs_find_dir(cdfs_md_id, dir_path);
}

/**
*
*  truncate a file
*
**/
EC_BOOL cdfs_truncate(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 fsize, const UINT32 replica_num)
{
    CDFSNP_FNODE  cdfsnp_fnode;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_truncate: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate: trunc %s to size %ld and replica %ld\n",
                        (char *)cstring_get_str(file_path), fsize, replica_num);

    cdfsnp_fnode_init(&cdfsnp_fnode);
    if(EC_FALSE == cdfs_truncate_dn_p(cdfs_md_id, fsize, replica_num, &cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate: truncate %ld bytes to data node failed\n", fsize);
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate: cdfsnp_fnode of %s is\n", (char *)cstring_get_str(file_path));
    cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);

    if(EC_FALSE == cdfs_write_npp_p(cdfs_md_id, file_path, replica_num, &cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate: truncate file %s to npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


/**
*
*  write a file
*
**/
EC_BOOL cdfs_write(const UINT32 cdfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const UINT32 replica_num)
{
    CDFSNP_FNODE  cdfsnp_fnode;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_write: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    if(EC_FALSE == cdfs_write_dn_p(cdfs_md_id, cbytes, replica_num, &cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write: write to data node failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfs_write_npp_p(cdfs_md_id, file_path, replica_num, &cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write: write file %s to npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  read a file
*
**/
EC_BOOL cdfs_read(const UINT32 cdfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CDFSNP_FNODE  cdfsnp_fnode;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_read: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    if(EC_FALSE == cdfs_read_npp_p(cdfs_md_id, file_path, &cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_read: cdfsnp_fnode of %s is\n", (char *)cstring_get_str(file_path));
    cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);

    if(CDFSNP_FNODE_IS_TRUNCATED == CDFSNP_FNODE_TRUNCF(&cdfsnp_fnode))
    {
        /*trick!! */
        /*WARNING: never update cdfsnp_fnode to npp after this trick*/
        CDFSNP_FNODE_FILESZ(&cdfsnp_fnode) = CDFSNP_FNODE_ACTFSZ(&cdfsnp_fnode);
    }

    if(EC_FALSE == cdfs_read_dn_p(cdfs_md_id, &cdfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read: read file %s from data node failed where fnode is\n", (char *)cstring_get_str(file_path));
        cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  update a file
*
**/
EC_BOOL cdfs_update(const UINT32 cdfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CDFSNP_FNODE  cdfsnp_fnode;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_update: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_update: update %s with size %ld\n",
                        (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    if(EC_FALSE == cdfs_read_npp_p(cdfs_md_id, file_path, &cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_update: cdfsnp_fnode of %s is\n", (char *)cstring_get_str(file_path));
    cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);

    if(EC_FALSE == cdfs_update_dn_p(cdfs_md_id, cbytes, &cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update: read file %s from data node failed where fnode is\n", (char *)cstring_get_str(file_path));
        cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);
        return (EC_FALSE);
    }

    if(CDFSNP_FNODE_IS_TRUNCATED == CDFSNP_FNODE_TRUNCF(&cdfsnp_fnode))
    {
        CDFSNP_FNODE_ACTFSZ(&cdfsnp_fnode) = cbytes_len(cbytes);/*update actual file size*/
        if(EC_FALSE == cdfs_update_npp_p(cdfs_md_id, file_path, &cdfsnp_fnode))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update: update npp of file %s failed where fnode is \n", (char *)cstring_get_str(file_path));
            cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


/**
*
*  log lost fnode info
*
**/
void cdfs_lost_fnode_log(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_lost_fnode_log: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR != CDFS_MD_NPP(cdfs_md) && NULL_PTR != CDFSNP_MGR_LOST_FNODE_LOG(CDFS_MD_NPP(cdfs_md)))
    {
        LOG *cdfsnp_mgr_lost_fnode_log;

        cdfsnp_mgr_lost_fnode_log = CDFSNP_MGR_LOST_FNODE_LOG(CDFS_MD_NPP(cdfs_md));

        LOG_FILE_LOCK(cdfsnp_mgr_lost_fnode_log, LOC_CDFS_0022);
        sys_log_no_lock(cdfsnp_mgr_lost_fnode_log, "path %s, ", (char *)cstring_get_str(file_path));
        cdfsnp_fnode_log_no_lock(cdfsnp_mgr_lost_fnode_log, cdfsnp_fnode);
        LOG_FILE_UNLOCK(cdfsnp_mgr_lost_fnode_log, LOC_CDFS_0023);
    }
    return;
}

/**
*
*  log lost replica info
*
**/
void cdfs_lost_replica_log(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 replica_num, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_lost_replica_log: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR != CDFS_MD_NPP(cdfs_md) && NULL_PTR != CDFSNP_MGR_LOST_REPLICA_LOG(CDFS_MD_NPP(cdfs_md)))
    {
        LOG *cdfsnp_lost_replica_log;

        cdfsnp_lost_replica_log = CDFSNP_MGR_LOST_REPLICA_LOG(CDFS_MD_NPP(cdfs_md));

        LOG_FILE_LOCK(cdfsnp_lost_replica_log, LOC_CDFS_0024);
        sys_log_no_lock(cdfsnp_lost_replica_log, "path: %s, expect %ld, ", (char *)cstring_get_str(file_path), replica_num);/*expect replica num*/
        cdfsnp_fnode_log_no_lock(cdfsnp_lost_replica_log, cdfsnp_fnode);
        LOG_FILE_UNLOCK(cdfsnp_lost_replica_log, LOC_CDFS_0025);
    }
    return;
}

/**
*
*  create data node
*
**/
EC_BOOL cdfs_create_dn(const UINT32 cdfs_md_id, const CSTRING *root_dir, const UINT32 disk_num, const UINT32 max_gb_num_of_disk_space)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_create_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    return cdfsdn_create((char *)cstring_get_str(root_dir), disk_num, max_gb_num_of_disk_space);
}

/**
*
*  open data node
*
**/
EC_BOOL cdfs_open_dn(const UINT32 cdfs_md_id, const CSTRING *root_dir)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_open_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/
    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_open_dn: try to open dn %s  ...\n", (char *)cstring_get_str(root_dir));

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR != CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_open_dn: someone data node was open\n");
        return (EC_FALSE);
    }

    CDFS_MD_DN(cdfs_md) = cdfsdn_open((char *)cstring_get_str(root_dir));
    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_open_dn: open data node with root dir %s failed\n", (char *)cstring_get_str(root_dir));
        return (EC_FALSE);
    }
    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_open_dn: open dn %s\n", (char *)cstring_get_str(root_dir));
    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL cdfs_close_dn(const UINT32 cdfs_md_id)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_close_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_close_dn: no data node was open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_close_dn was called\n");
    cdfsdn_close(CDFS_MD_DN(cdfs_md));
    CDFS_MD_DN(cdfs_md) = NULL_PTR;

    return (EC_TRUE);
}

/**
*
*  close and flush data node
*
**/
EC_BOOL cdfs_close_with_flush_dn(const UINT32 cdfs_md_id)
{
    CDFS_MD   *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_close_with_flush_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_close_with_flush_dn: no data node was open\n");
        return (EC_FALSE);
    }

    cdfsdn_close_with_flush(CDFS_MD_DN(cdfs_md));
    CDFS_MD_DN(cdfs_md) = NULL_PTR;

    return (EC_TRUE);
}

/**
*
*  truncate data node in pipe line
*
**/
EC_BOOL cdfs_truncate_dn_ppl(const UINT32 cdfs_md_id, const UINT32 fsize, const UINT32 cdfsnp_inode_pos, CDFSNP_FNODE *cdfsnp_fnode, CDFSDN_STAT *cdfsdn_stat)
{
    CDFS_MD *cdfs_md;

    UINT32 path_layout;
    UINT32 partition_beg;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_truncate_dn_ppl: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_ppl: no data node was open\n");
        return (EC_FALSE);
    }

    if(CDFSNP_FILE_REPLICA_MAX_NUM <= cdfsnp_inode_pos)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_ppl: cdfsnp_inode_pos %ld overflow\n", cdfsnp_inode_pos);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl: input cdfsnp_inode_pos = %ld\n", cdfsnp_inode_pos);

    if(1)/*debug*/
    {
        if(0 == fsize)
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_ppl: fsize is zero\n");
            return (EC_FALSE);
        }

        if(CDFSDN_BLOCK_DATA_MAX_SIZE <= fsize)
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_ppl: fsize %ld overflow\n", fsize);
            return (EC_FALSE);
        }
    }

    ret = cdfsdn_truncate(CDFS_MD_DN(cdfs_md), fsize, &path_layout, &partition_beg);
    if(EC_TRUE == ret)
    {
        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl[x]: cdfsnp_inode_pos = %ld\n", cdfsnp_inode_pos);

        CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos) = CMPI_LOCAL_TCID;
        CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) = (path_layout & CDFSNP_32BIT_MASK);
        CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos) = (partition_beg & CDFSNP_32BIT_MASK);

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl: [SUCC] truncate %ld bytes to %ld# (tcid %s, path %lx, offset %ld)\n",
                            fsize, cdfsnp_inode_pos,
                            c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos)),
                            CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) & CDFSNP_32BIT_MASK,
                            CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos) & CDFSNP_32BIT_MASK
                            );
    }
    else
    {
        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl[y]: cdfsnp_inode_pos = %ld\n", cdfsnp_inode_pos);

        CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos) = CMPI_LOCAL_TCID;
        CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) = CDFSNP_ERR_PATH;
        CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos) = CDFSNP_ERR_FOFF;

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl: [FAIL] truncate %ld bytes to %ld# (tcid %s)\n",
                            fsize, cdfsnp_inode_pos,
                            c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos))
                            );
    }

    /*when current dn is full, inform all np and dn*/
    if(EC_TRUE == cdfsdn_is_full(CDFS_MD_DN(cdfs_md)))
    {
        if(NULL_PTR != CDFS_MD_DN_MOD_MGR(cdfs_md) && 0 < MOD_MGR_REMOTE_NUM(CDFS_MD_DN_MOD_MGR(cdfs_md)))
        {
            task_bcast(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                       FI_cdfs_disable_write_access_dn, CMPI_ERROR_MODI, CMPI_LOCAL_TCID);
        }

        if(NULL_PTR != CDFS_MD_NPP_MOD_MGR(cdfs_md) && 0 < MOD_MGR_REMOTE_NUM(CDFS_MD_NPP_MOD_MGR(cdfs_md)))
        {
            task_bcast(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                       FI_cdfs_disable_write_access_dn, CMPI_ERROR_MODI, CMPI_LOCAL_TCID);
        }
    }

    /*fetch local dn stat*/
    if(NULL_PTR != cdfsdn_stat)
    {
        CDFSDN_STAT_TCID(cdfsdn_stat) = CMPI_LOCAL_TCID;
        CDFSDN_STAT_FULL(cdfsdn_stat) = cdfsdn_stat_fetch(CDFS_MD_DN(cdfs_md));
    }

    if(cdfsnp_inode_pos + 1 < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && cdfsnp_inode_pos + 1 < CDFSNP_FILE_REPLICA_MAX_NUM)
    {
        CVECTOR  *tcid_vec;
        MOD_MGR  *mod_mgr;
        TASK_MGR *task_mgr;

        CDFSDN_STAT    remote_cdfsdn_stat;

        tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0026);

        cdfs_collect_fnode_all_tcid(cdfsnp_fnode, cdfsnp_inode_pos + 1, tcid_vec);
        cdfs_collect_dn_mod_mgr_disable_tcid(CDFS_MD_DN_MOD_MGR(cdfs_md), tcid_vec);

        mod_mgr = mod_mgr_new(cdfs_md_id, LOAD_BALANCING_QUE);
        mod_mgr_limited_clone_with_tcid_excl_filter(cdfs_md_id, CDFS_MD_DN_MOD_MGR(cdfs_md), tcid_vec, mod_mgr);
        cvector_free(tcid_vec, LOC_CDFS_0027);

        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl: [1] mod mgr:\n");
        //mod_mgr_print(LOGSTDOUT, mod_mgr);

        if(0 == MOD_MGR_REMOTE_NUM(mod_mgr))
        {
            mod_mgr_free(mod_mgr);
            return (EC_FALSE);
        }

        cdfsdn_stat_init(&remote_cdfsdn_stat);
        ret = EC_FALSE;

        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        task_inc(task_mgr, &ret, FI_cdfs_truncate_dn_ppl, CMPI_ERROR_MODI, fsize, cdfsnp_inode_pos + 1, cdfsnp_fnode, &remote_cdfsdn_stat);
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

        mod_mgr_free(mod_mgr);

        if(CDFSDN_STAT_IS_FULL == CDFSDN_STAT_FULL(&remote_cdfsdn_stat))
        {
            cdfs_disable_write_access_dn(cdfs_md_id, CDFSDN_STAT_TCID(&remote_cdfsdn_stat));
        }

        if(EC_TRUE == ret)
        {
            dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl: [SUCC] remote truncate %ld bytes to %ld# (tcid %s, path %lx, offset %ld)\n",
                                fsize, cdfsnp_inode_pos + 1,
                                c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos + 1)),
                                CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos + 1) & CDFSNP_32BIT_MASK,
                                CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos + 1) & CDFSNP_32BIT_MASK
                                );
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_ppl: [FAIL] remote truncate %ld bytes to %ld# (tcid %s)\n",
                                fsize, cdfsnp_inode_pos + 1,
                                c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos + 1))
                                );
        }

        return (ret);
    }

    return (ret);
}

/**
*
*  truncate data node
*
**/
EC_BOOL cdfs_truncate_dn_p(const UINT32 cdfs_md_id, const UINT32 fsize, const UINT32 replica_num, CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD      *cdfs_md;

    CDFSDN_STAT    remote_cdfsdn_stat;
    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_truncate_dn_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_truncate_dn_p: dn mod mgr was null\n");
        return (EC_FALSE);
    }

    if(CDFSNP_FILE_REPLICA_MAX_NUM < replica_num)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_p: replica num %ld overflow\n", replica_num);
        return (EC_FALSE);
    }

    if(CDFSDN_BLOCK_MAX_SIZE <= fsize)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_p: file size %ld overflow\n", fsize);
        return (EC_FALSE);
    }

    cdfsnp_fnode_init(cdfsnp_fnode);

    /*fill file size and replica num of cdfsnp_fnode*/
    CDFSNP_FNODE_FILESZ(cdfsnp_fnode) = fsize;
    CDFSNP_FNODE_REPNUM(cdfsnp_fnode) = replica_num;
    CDFSNP_FNODE_TRUNCF(cdfsnp_fnode) = CDFSNP_FNODE_IS_TRUNCATED;
    CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode) = 0;

    /*fill tcids of cdfsnp_fnode*/
    ret = EC_FALSE;

    if(1)
    {
        MOD_MGR  *mod_mgr;
        TASK_MGR *task_mgr;

        mod_mgr = cdfs_new_dn_mod_mgr_to_write(cdfs_md_id);/*exclude all truncate-access-disabled dn*/
        if(0 == MOD_MGR_REMOTE_NUM(mod_mgr))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_p: no data node available or accessible\n");
            mod_mgr_free(mod_mgr);
            return (EC_FALSE);
        }

        cdfsdn_stat_init(&remote_cdfsdn_stat);

        /**
         * pay attention to "(UINT32)0" in parameter list
         * this is the undetermined parameter, if give "0" here, compiler, esp. for 64bit compiler, may regard it as "(int) 0"
         * which is only 32 bits.
         **/
        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        task_inc(task_mgr, &ret, FI_cdfs_truncate_dn_ppl, CMPI_ERROR_MODI, fsize, (UINT32)0, cdfsnp_fnode, &remote_cdfsdn_stat);
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

        mod_mgr_free(mod_mgr);

        if(CDFSDN_STAT_IS_FULL == CDFSDN_STAT_FULL(&remote_cdfsdn_stat))
        {
            dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_truncate_dn_p: cdfsdn %s is full\n", c_word_to_ipv4(CDFSDN_STAT_TCID(&remote_cdfsdn_stat)));
            cdfs_disable_write_access_dn(cdfs_md_id, CDFSDN_STAT_TCID(&remote_cdfsdn_stat));
        }
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_p: [1] cdfsnp_fnode ");
    cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    /*discard invalid inodes and adjust actual replica num*/
    cdfsnp_fnode_import(cdfsnp_fnode, cdfsnp_fnode);

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_truncate_dn_p: [2] cdfsnp_fnode ");
    cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    if(EC_FALSE == ret && 0 == CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_truncate_dn_p: no data node accept %ld bytes\n", fsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  update data node
*
**/
EC_BOOL cdfs_update_dn_p(const UINT32 cdfs_md_id, const CBYTES *cbytes, const CDFSNP_FNODE *cdfsnp_fnode)
{
    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_update_dn_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    if(CDFSDN_BLOCK_MAX_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_dn_p: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    /*fill tcids of cdfsnp_fnode*/
    ret = EC_FALSE;

    if(1)
    {
        MOD_NODE  recv_mod_node;

        UINT32 cdfsdn_inode_pos;
        const CDFSNP_INODE *cdfsnp_inode;

        cdfsdn_inode_pos = 0;
        cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, cdfsdn_inode_pos);

        MOD_NODE_TCID(&recv_mod_node) = CDFSNP_INODE_TCID(cdfsnp_inode);/*data node tcid*/
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p(cdfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cdfs_update_dn_ppl, CMPI_ERROR_MODI, cbytes, cdfsdn_inode_pos, cdfsnp_fnode);
    }

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_dn_p: update %ld bytes to someone data node failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  update data node in pipe line
*
**/
EC_BOOL cdfs_update_dn_ppl(const UINT32 cdfs_md_id, const CBYTES *cbytes, const UINT32 cdfsnp_inode_pos, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD *cdfs_md;

    UINT32 path_layout;
    UINT32 partition_beg;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_update_dn_ppl: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_dn_ppl: no data node was open\n");
        return (EC_FALSE);
    }

    if(CDFSNP_FILE_REPLICA_MAX_NUM <= cdfsnp_inode_pos)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_dn_ppl: cdfsnp_inode_pos %ld overflow\n", cdfsnp_inode_pos);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_update_dn_ppl: input cdfsnp_inode_pos = %ld\n", cdfsnp_inode_pos);

    if(1)/*debug*/
    {
        if(NULL_PTR == cbytes)
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_dn_ppl: cdfs buff is null\n");
            return (EC_FALSE);
        }

        if(NULL_PTR == CBYTES_BUF(cbytes))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_dn_ppl: cdfs buff data area is null\n");
            return (EC_FALSE);
        }

        if(0 == CBYTES_LEN(cbytes))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_dn_ppl: cdfs buff data len is zero\n");
            return (EC_FALSE);
        }
    }

    path_layout = CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos);
    partition_beg = CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos);

    ret = cdfsdn_update(CDFS_MD_DN(cdfs_md), CBYTES_LEN(cbytes), CBYTES_BUF(cbytes), path_layout, partition_beg);
    if(EC_TRUE == ret)
    {

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_update_dn_ppl: [SUCC] update %ld bytes to %ld# (tcid %s, path %lx, offset %ld)\n",
                            CBYTES_LEN(cbytes), cdfsnp_inode_pos,
                            c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos)),
                            CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) & CDFSNP_32BIT_MASK,
                            CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos) & CDFSNP_32BIT_MASK
                            );
    }
    else
    {
        dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_update_dn_ppl: [FAIL] update %ld bytes to %ld# (tcid %s)\n",
                            CBYTES_LEN(cbytes), cdfsnp_inode_pos,
                            c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos))
                            );
    }

    if(cdfsnp_inode_pos + 1 < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && cdfsnp_inode_pos + 1 < CDFSNP_FILE_REPLICA_MAX_NUM)
    {

        MOD_NODE  recv_mod_node;

        const CDFSNP_INODE *cdfsnp_inode;

        cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, cdfsnp_inode_pos + 1);

        MOD_NODE_TCID(&recv_mod_node) = CDFSNP_INODE_TCID(cdfsnp_inode);/*data node tcid*/
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p(cdfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cdfs_update_dn_ppl, CMPI_ERROR_MODI, cbytes, cdfsnp_inode_pos + 1, cdfsnp_fnode);

        if(EC_TRUE == ret)
        {
            dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_update_dn_ppl: [SUCC] remote update %ld bytes to %ld# (tcid %s, path %lx, offset %ld)\n",
                                CBYTES_LEN(cbytes), cdfsnp_inode_pos + 1,
                                c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos + 1)),
                                CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos + 1),
                                CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos + 1)
                                );
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_update_dn_ppl: [FAIL] remote update %ld bytes to %ld# (tcid %s)\n",
                                CBYTES_LEN(cbytes), cdfsnp_inode_pos + 1,
                                c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos + 1))
                                );
        }

        return (ret);
    }

    return (ret);
}

/**
*
*  write data node in pipe line
*
**/
EC_BOOL cdfs_write_dn_ppl(const UINT32 cdfs_md_id, const CBYTES *cbytes, const UINT32 cdfsnp_inode_pos, CDFSNP_FNODE *cdfsnp_fnode, CDFSDN_STAT *cdfsdn_stat)
{
    CDFS_MD *cdfs_md;

    UINT32 path_layout;
    UINT32 partition_beg;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_write_dn_ppl: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_ppl: no data node was open\n");
        return (EC_FALSE);
    }

    if(CDFSNP_FILE_REPLICA_MAX_NUM <= cdfsnp_inode_pos)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_ppl: cdfsnp_inode_pos %ld overflow\n", cdfsnp_inode_pos);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_write_dn_ppl: input cdfsnp_inode_pos = %ld\n", cdfsnp_inode_pos);

    if(1)/*debug*/
    {
        if(NULL_PTR == cbytes)
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_ppl: cdfs buff is null\n");
            return (EC_FALSE);
        }

        if(NULL_PTR == CBYTES_BUF(cbytes))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_ppl: cdfs buff data area is null\n");
            return (EC_FALSE);
        }

        if(0 == CBYTES_LEN(cbytes))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_ppl: cdfs buff data len is zero\n");
            return (EC_FALSE);
        }
    }

    ret = cdfsdn_write(CDFS_MD_DN(cdfs_md), CBYTES_LEN(cbytes), CBYTES_BUF(cbytes), &path_layout, &partition_beg);
    if(EC_TRUE == ret)
    {
        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_write_dn_ppl[x]: cdfsnp_inode_pos = %ld\n", cdfsnp_inode_pos);

        CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos) = CMPI_LOCAL_TCID;
        CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) = (path_layout & CDFSNP_32BIT_MASK);
        CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos) = (partition_beg & CDFSNP_32BIT_MASK);

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_write_dn_ppl: [SUCC] write %ld bytes to %ld# (tcid %s, path %lx, offset %ld)\n",
                            CBYTES_LEN(cbytes), cdfsnp_inode_pos,
                            c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos)),
                            CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) & CDFSNP_32BIT_MASK,
                            CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos) & CDFSNP_32BIT_MASK
                            );
    }
    else
    {
        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_write_dn_ppl[y]: cdfsnp_inode_pos = %ld\n", cdfsnp_inode_pos);

        CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos) = CMPI_LOCAL_TCID;
        CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos) = CDFSNP_ERR_PATH;
        CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos) = CDFSNP_ERR_FOFF;

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_write_dn_ppl: [FAIL] write %ld bytes to %ld# (tcid %s)\n",
                            CBYTES_LEN(cbytes), cdfsnp_inode_pos,
                            c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos))
                            );
    }

    /*when current dn is full, inform all np and dn*/
    if(EC_TRUE == cdfsdn_is_full(CDFS_MD_DN(cdfs_md)))
    {
        if(NULL_PTR != CDFS_MD_DN_MOD_MGR(cdfs_md) && 0 < MOD_MGR_REMOTE_NUM(CDFS_MD_DN_MOD_MGR(cdfs_md)))
        {
            task_bcast(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                       FI_cdfs_disable_write_access_dn, CMPI_ERROR_MODI, CMPI_LOCAL_TCID);
        }

        if(NULL_PTR != CDFS_MD_NPP_MOD_MGR(cdfs_md) && 0 < MOD_MGR_REMOTE_NUM(CDFS_MD_NPP_MOD_MGR(cdfs_md)))
        {
            task_bcast(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                       FI_cdfs_disable_write_access_dn, CMPI_ERROR_MODI, CMPI_LOCAL_TCID);
        }
    }

    /*fetch local dn stat*/
    if(NULL_PTR != cdfsdn_stat)
    {
        CDFSDN_STAT_TCID(cdfsdn_stat) = CMPI_LOCAL_TCID;
        CDFSDN_STAT_FULL(cdfsdn_stat) = cdfsdn_stat_fetch(CDFS_MD_DN(cdfs_md));
    }

    if(cdfsnp_inode_pos + 1 < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && cdfsnp_inode_pos + 1 < CDFSNP_FILE_REPLICA_MAX_NUM)
    {
        CVECTOR  *tcid_vec;
        MOD_MGR  *mod_mgr;
        TASK_MGR *task_mgr;

        CDFSDN_STAT    remote_cdfsdn_stat;

        tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0028);

        cdfs_collect_fnode_all_tcid(cdfsnp_fnode, cdfsnp_inode_pos + 1, tcid_vec);
        cdfs_collect_dn_mod_mgr_disable_tcid(CDFS_MD_DN_MOD_MGR(cdfs_md), tcid_vec);

        mod_mgr = mod_mgr_new(cdfs_md_id, LOAD_BALANCING_QUE);
        mod_mgr_limited_clone_with_tcid_excl_filter(cdfs_md_id, CDFS_MD_DN_MOD_MGR(cdfs_md), tcid_vec, mod_mgr);
        cvector_free(tcid_vec, LOC_CDFS_0029);

        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_write_dn_ppl: [1] mod mgr:\n");
        //mod_mgr_print(LOGSTDOUT, mod_mgr);

        if(0 == MOD_MGR_REMOTE_NUM(mod_mgr))
        {
            mod_mgr_free(mod_mgr);
            return (EC_FALSE);
        }

        cdfsdn_stat_init(&remote_cdfsdn_stat);
        ret = EC_FALSE;

        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        task_inc(task_mgr, &ret, FI_cdfs_write_dn_ppl, CMPI_ERROR_MODI, cbytes, cdfsnp_inode_pos + 1, cdfsnp_fnode, &remote_cdfsdn_stat);
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

        mod_mgr_free(mod_mgr);

        if(CDFSDN_STAT_IS_FULL == CDFSDN_STAT_FULL(&remote_cdfsdn_stat))
        {
            cdfs_disable_write_access_dn(cdfs_md_id, CDFSDN_STAT_TCID(&remote_cdfsdn_stat));
        }

        if(EC_TRUE == ret)
        {
            dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_write_dn_ppl: [SUCC] remote write %ld bytes to %ld# (tcid %s, path %lx, offset %ld)\n",
                                CBYTES_LEN(cbytes), cdfsnp_inode_pos + 1,
                                c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos + 1)),
                                CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos + 1),
                                CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos + 1)
                                );
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_write_dn_ppl: [FAIL] remote write %ld bytes to %ld# (tcid %s)\n",
                                CBYTES_LEN(cbytes), cdfsnp_inode_pos + 1,
                                c_word_to_ipv4(CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos + 1))
                                );
        }

        return (ret);
    }

    return (ret);
}

/**
*
*  read data node in pipe line
*
**/
EC_BOOL cdfs_read_dn_ppl(const UINT32 cdfs_md_id, const UINT32 cdfsnp_inode_pos, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes)
{
    CDFS_MD *cdfs_md;

    UINT32 file_size;
    UINT32 path_layout;
    UINT32 offset;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_read_dn_ppl: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    file_size   = CDFSNP_FNODE_FILESZ(cdfsnp_fnode);
    path_layout = CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos);
    offset      = CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos);

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_read_dn_ppl: file file %ld, path layout %lx, offset %ld\n", file_size, path_layout, offset);

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_read_dn_ppl: cbytes: len %ld, val %lx\n", CBYTES_LEN(cbytes), CBYTES_BUF(cbytes));

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read_dn_ppl: data node is null\n");
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CDFS_0030);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CDFS_0031);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cdfsdn_read(CDFS_MD_DN(cdfs_md), path_layout, offset, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        EC_BOOL   ret;
        UINT32    cdfsnp_inode_next_pos;

        CBYTES_LEN(cbytes) = 0;
        ret = EC_FALSE;

        if(EC_TRUE == cdfs_get_next_succ_inode_pos(cdfs_md_id, cdfsnp_fnode, cdfsnp_inode_pos, &cdfsnp_inode_next_pos))
        {
            MOD_NODE  recv_mod_node;

            MOD_NODE_TCID(&recv_mod_node) = CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_next_pos);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;

            cbytes_clean(cbytes);

            task_super_mono(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                            &recv_mod_node,
                            &ret, FI_cdfs_read_dn_ppl, CMPI_ERROR_MODI, cdfsnp_inode_next_pos, cdfsnp_fnode, cbytes);
        }
        return (ret);
    }
#if 0
    dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_read_dn_ppl: offset %ld, file size %ld, buff len %ld\n",
                        offset, file_size, CBYTES_LEN(cbytes));
    cdfs_buff_print_1(cdfs_md_id, LOGSTDNULL, cbytes);
#endif
    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL cdfs_write_dn_p(const UINT32 cdfs_md_id, const CBYTES *cbytes, const UINT32 replica_num, CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD      *cdfs_md;

    CDFSDN_STAT    remote_cdfsdn_stat;
    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_write_dn_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_write_dn_p: dn mod mgr was null\n");
        return (EC_FALSE);
    }

    if(CDFSNP_FILE_REPLICA_MAX_NUM < replica_num)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_p: replica num %ld overflow\n", replica_num);
        return (EC_FALSE);
    }

    if(CDFSDN_BLOCK_MAX_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_p: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    cdfsnp_fnode_init(cdfsnp_fnode);

    /*fill file size and replica num of cdfsnp_fnode*/
    CDFSNP_FNODE_FILESZ(cdfsnp_fnode) = CBYTES_LEN(cbytes);
    CDFSNP_FNODE_REPNUM(cdfsnp_fnode) = replica_num;

    /*fill tcids of cdfsnp_fnode*/
    ret = EC_FALSE;

    if(1)
    {
        MOD_MGR  *mod_mgr;
        TASK_MGR *task_mgr;

        mod_mgr = cdfs_new_dn_mod_mgr_to_write(cdfs_md_id);/*exclude all write-access-disabled dn*/
        if(0 == MOD_MGR_REMOTE_NUM(mod_mgr))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_p: no data node available or accessible\n");
            mod_mgr_free(mod_mgr);
            return (EC_FALSE);
        }

        cdfsdn_stat_init(&remote_cdfsdn_stat);

        /**
         * pay attention to "(UINT32)0" in parameter list
         * this is the undetermined parameter, if give "0" here, compiler, esp. for 64bit compiler, may regard it as "(int) 0"
         * which is only 32 bits.
         **/
        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        task_inc(task_mgr, &ret, FI_cdfs_write_dn_ppl, CMPI_ERROR_MODI, cbytes, (UINT32)0, cdfsnp_fnode, &remote_cdfsdn_stat);
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

        mod_mgr_free(mod_mgr);

        if(CDFSDN_STAT_IS_FULL == CDFSDN_STAT_FULL(&remote_cdfsdn_stat))
        {
            dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_write_dn_p: cdfsdn %s is full\n", c_word_to_ipv4(CDFSDN_STAT_TCID(&remote_cdfsdn_stat)));
            cdfs_disable_write_access_dn(cdfs_md_id, CDFSDN_STAT_TCID(&remote_cdfsdn_stat));
        }
    }

    /*discard invalid inodes and adjust actual replica num*/
    cdfsnp_fnode_import(cdfsnp_fnode, cdfsnp_fnode);

    if(EC_FALSE == ret && 0 == CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_dn_p: no data node accept %ld bytes\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL cdfs_read_dn_p_with_tcid_filter(const UINT32 cdfs_md_id, const CVECTOR *cdfsdn_tcid_vec, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes)
{
    CDFS_MD *cdfs_md;

    MOD_MGR  *mod_mgr;
    TASK_MGR *task_mgr;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_read_dn_p_with_tcid_filter: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    mod_mgr = mod_mgr_new(cdfs_md_id, MOD_MGR_LDB_CHOICE(CDFS_MD_DN_MOD_MGR(cdfs_md)));
    mod_mgr_limited_clone_with_tcid_filter(cdfs_md_id, CDFS_MD_DN_MOD_MGR(cdfs_md), cdfsdn_tcid_vec, mod_mgr);

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_read_dn_p_with_tcid_filter: mod_mgr is\n");
    //mod_mgr_print(LOGSTDOUT, mod_mgr);

    ret = EC_FALSE;
    task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_inc(task_mgr, &ret, FI_cdfs_read_dn, CMPI_ERROR_MODI, cdfsnp_fnode, cbytes);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

    mod_mgr_free(mod_mgr);

    return (ret);
}


/**
*
*  read data node
*
**/
EC_BOOL cdfs_read_dn_p(const UINT32 cdfs_md_id, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes)
{
    CDFS_MD *cdfs_md;

    CVECTOR  *cdfsdn_tcid_vec;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_read_dn_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    cdfsdn_tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0032);

    cdfs_collect_fnode_all_tcid(cdfsnp_fnode, CDFSNP_FNODE_REPNUM(cdfsnp_fnode), cdfsdn_tcid_vec);

    ret = cdfs_read_dn_p_with_tcid_filter(cdfs_md_id, cdfsdn_tcid_vec, cdfsnp_fnode, cbytes);
    cvector_free(cdfsdn_tcid_vec, LOC_CDFS_0033);

    return (ret);
}

/**
*
*  read data node
*
**/
EC_BOOL cdfs_read_dn(const UINT32 cdfs_md_id, const CDFSNP_FNODE *cdfsnp_fnode, CBYTES *cbytes)
{
    CDFS_MD *cdfs_md;

    UINT32 local_tcid;
    UINT32 cdfsnp_inode_pos;

    UINT32 file_size;
    UINT32 path_layout;
    UINT32 offset;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_read_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    local_tcid = CMPI_LOCAL_TCID;

    for(cdfsnp_inode_pos = 0; cdfsnp_inode_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode); cdfsnp_inode_pos ++)
    {
        if(local_tcid == CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, cdfsnp_inode_pos))
        {
            break;
        }
    }

    if(cdfsnp_inode_pos >= CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read_dn: local tcid %s not exist in cdfsnp_fnode %lx\n", c_word_to_ipv4(local_tcid), cdfsnp_fnode);
        cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);
        return (EC_FALSE);
    }

    file_size   = CDFSNP_FNODE_FILESZ(cdfsnp_fnode);
    path_layout = CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, cdfsnp_inode_pos);
    offset      = CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, cdfsnp_inode_pos);

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_read_dn: file file %ld, path layout %lx, offset %ld\n", file_size, path_layout, offset);

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDNULL, "[DEBUG] cdfs_read_dn: cbytes: len %ld, val %lx\n", CBYTES_LEN(cbytes), CBYTES_BUF(cbytes));

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read_dn: data node is null\n");
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CDFS_0034);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CDFS_0035);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cdfsdn_read(CDFS_MD_DN(cdfs_md), path_layout, offset, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read_dn: read path layout %ld, offset %ld, file size %ld failed\n", path_layout, offset, file_size);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  write a fnode to name node
*
**/
EC_BOOL cdfs_write_npp_p(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 replica_num, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD *cdfs_md;
    UINT32   succ_counter;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_write_npp_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_write_npp_p: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    if(0 == CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_npp_p: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_write_npp_p: cdfsnp_fnode is\n");
    //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    succ_counter = 0;
    if(1)
    {
        TASK_MGR *task_mgr;
        MOD_MGR  *mod_mgr;
        CVECTOR  *ret_vec;

        UINT32 remote_mod_node_num;
        UINT32 remote_mod_node_idx;

        mod_mgr = CDFS_MD_NPP_MOD_MGR(cdfs_md);

        ret_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0036);

        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL  *ret;

            alloc_static_mem(MM_UINT32, &ret, LOC_CDFS_0037);
            cvector_push_no_lock(ret_vec, (void *)ret);

            (*ret) = EC_FALSE;

            task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_cdfs_write_npp, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        remote_mod_node_num = cvector_size(ret_vec);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL *ret;

            ret = (EC_BOOL *)cvector_get_no_lock(ret_vec, remote_mod_node_idx);
            if(EC_TRUE == (*ret))
            {
                succ_counter ++;
            }
            else
            {
                /*mod mgr may be changed when connection broken happen, hence cannot ouput mod node info here*/
                dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_npp_p: %ld# write file %s with replica %ld (expect %ld) to some npp failed\n",
                                    remote_mod_node_idx, (char *)cstring_get_str(file_path),
                                    CDFSNP_FNODE_REPNUM(cdfsnp_fnode), replica_num);
            }
            cvector_set_no_lock(ret_vec, remote_mod_node_idx, NULL_PTR);
            free_static_mem(MM_UINT32, ret, LOC_CDFS_0038);
        }

        cvector_free_no_lock(ret_vec, LOC_CDFS_0039);
    }

    if(0 == succ_counter)
    {
        return (EC_FALSE);
    }

    if(succ_counter < CDFS_MD_NP_MIN_NUM(cdfs_md))/*when np replica not meet requirement, record it in log*/
    {
        /*warning: do not use task_mono_no_wait due to encoding would happen before sending*/
        if(0 < MOD_MGR_REMOTE_NUM(CDFS_MD_NPP_MOD_MGR(cdfs_md)))
        {
#if 1
            task_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH,
                        TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, TASK_NEED_RESCHEDULE_FLAG,
                        NULL_PTR, FI_cdfs_lost_fnode_log, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
#endif
#if 0
            TASK_MGR *task_mgr;
            task_new(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, &task_mgr);
            task_inc(task_mgr, NULL_PTR, FI_cdfs_lost_fnode_log, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
            task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[lost fnode] path %s, ", (char *)cstring_get_str(file_path));
            cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);
        }
    }

    if(replica_num > CDFSNP_FNODE_REPNUM(cdfsnp_fnode))/*when dn replica not meet requirement, record it in log*/
    {
        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_write_dn_p: cdfsnp_fnode is\n");
        //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);
        if(0 < MOD_MGR_REMOTE_NUM(CDFS_MD_NPP_MOD_MGR(cdfs_md)))
        {
#if 1
            task_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH,
                        TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, TASK_NEED_RESCHEDULE_FLAG,
                        NULL_PTR, FI_cdfs_lost_replica_log, CMPI_ERROR_MODI, file_path, replica_num, cdfsnp_fnode);
#endif
#if 0
            TASK_MGR *task_mgr;
            task_new(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, &task_mgr);
            task_inc(task_mgr, NULL_PTR, FI_cdfs_lost_replica_log, CMPI_ERROR_MODI, file_path, replica_num, cdfsnp_fnode);
            task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);
#endif
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[lost replica] path: %s, expect %ld, ", (char *)cstring_get_str(file_path), replica_num);/*expect replica num*/
            cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);
        }
    }
    return (EC_TRUE);
}

/**
*
*  read a fnode from name node
*
**/
EC_BOOL cdfs_read_npp_p(const UINT32 cdfs_md_id, const CSTRING *file_path, CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD *cdfs_md;
    EC_BOOL  ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_read_npp_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_read_npp_p: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_read_npp_p: npp mod mgr is:\n");
    mod_mgr_print(LOGSTDOUT, CDFS_MD_NPP_MOD_MGR(cdfs_md));

    ret = EC_FALSE;
    if(1)
    {
        TASK_MGR *task_mgr;

        task_mgr = task_new(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        task_inc(task_mgr, &ret, FI_cdfs_read_npp, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_read_npp_p: cdfsnp_fnode is\n");
    //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read_npp_p: read file %s from npp failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  update a fnode to name node
*
**/
EC_BOOL cdfs_update_npp_p(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD *cdfs_md;
    UINT32   succ_counter;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_update_npp_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_update_npp_p: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    if(0 == CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_npp_p: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_update_npp_p: cdfsnp_fnode is\n");
    //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    succ_counter = 0;
    if(1)
    {
        TASK_MGR *task_mgr;
        MOD_MGR  *mod_mgr;
        CVECTOR  *ret_vec;

        UINT32 remote_mod_node_num;
        UINT32 remote_mod_node_idx;

        mod_mgr = CDFS_MD_NPP_MOD_MGR(cdfs_md);

        ret_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0040);

        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL  *ret;

            alloc_static_mem(MM_UINT32, &ret, LOC_CDFS_0041);
            cvector_push(ret_vec, (void *)ret);

            (*ret) = EC_FALSE;

            task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_cdfs_update_npp, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        remote_mod_node_num = cvector_size(ret_vec);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL *ret;

            ret = (EC_BOOL *)cvector_get(ret_vec, remote_mod_node_idx);
            if(EC_TRUE == (*ret))
            {
                succ_counter ++;
            }
            else
            {
                /*mod mgr may be changed when connection broken happen, hence cannot ouput mod node info here*/
                dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_npp_p: %ld# update file %s with replica %ld to some npp failed\n",
                                    remote_mod_node_idx, (char *)cstring_get_str(file_path), CDFSNP_FNODE_REPNUM(cdfsnp_fnode));
            }
            cvector_set(ret_vec, remote_mod_node_idx, NULL_PTR);
            free_static_mem(MM_UINT32, ret, LOC_CDFS_0042);
        }

        cvector_free(ret_vec, LOC_CDFS_0043);
    }

    if(0 == succ_counter)
    {
        return (EC_FALSE);
    }

    if(succ_counter < CDFS_MD_NP_MIN_NUM(cdfs_md))
    {
        /*warning: do not use task_mono_no_wait due to encoding would happen before sending*/
        task_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, TASK_NEED_RESCHEDULE_FLAG,
                    NULL_PTR, FI_cdfs_lost_fnode_log, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
    }

    return (EC_TRUE);
}

/**
*
*  write a fnode to name node
*
**/
EC_BOOL cdfs_write_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_write_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_npp: name node pool was not open\n");
        return (EC_FALSE);
    }

    if(0 == CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_npp: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_write_npp: cdfsnp_fnode is\n");
    //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    if(
        EC_FALSE == cdfsnp_mgr_write(CDFS_MD_NPP(cdfs_md), file_path, cdfsnp_fnode)
     && EC_FALSE == cdfsnp_mgr_write(CDFS_MD_NPP(cdfs_md), file_path, cdfsnp_fnode)/*try twice to prevent np writting at tail*/
    )
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_write_npp: no name node accept file %s with %ld replicas\n",
                            (char *)cstring_get_str(file_path), CDFSNP_FNODE_REPNUM(cdfsnp_fnode));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  read a fnode from name node
*
**/
EC_BOOL cdfs_read_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_read_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_read_npp: name node pool was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_read(CDFS_MD_NPP(cdfs_md), file_path, cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_read_npp: cdfsnp mgr read %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_read_npp: cdfsnp_fnode is\n");
    //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    return (EC_TRUE);
}

/**
*
*  update a fnode to name node
*
**/
EC_BOOL cdfs_update_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_update_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_update_npp: name node pool was not open\n");
        return (EC_FALSE);
    }

    if(0 == CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_npp: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_update_npp: cdfsnp_fnode is\n");
    //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

    if(EC_FALSE == cdfsnp_mgr_update_np_fnode(CDFS_MD_NPP(cdfs_md), file_path, cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_npp: no name node update file %s with %ld replicas\n",
                            (char *)cstring_get_str(file_path), CDFSNP_FNODE_REPNUM(cdfsnp_fnode));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

#if 0
EC_BOOL cdfs_update_npp_p(const UINT32 cdfs_md_id, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFS_MD      *cdfs_md;
    TASK_MGR     *task_mgr;
    UINT32        remote_mod_node_num;
    UINT32        remote_mod_node_idx;

    CVECTOR      *ret_vec;
    EC_BOOL       result;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_update_npp_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_update_npp_p: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0044);

    task_mgr = task_new(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    remote_mod_node_num = MOD_MGR_REMOTE_NUM(CDFS_MD_NPP_MOD_MGR(cdfs_md));
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        EC_BOOL  *ret;

        alloc_static_mem(MM_UINT32, &ret, LOC_CDFS_0045);
        cvector_push_no_lock(ret_vec, (void *)ret);

        (*ret) = EC_FALSE;
        task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_cdfs_update_npp, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    remote_mod_node_num = cvector_size(ret_vec);
    for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
    {
        EC_BOOL *ret;

        ret = (EC_BOOL *)cvector_get_no_lock(ret_vec, remote_mod_node_idx);
        if(EC_FALSE == (*ret))
        {
            result = EC_FALSE;
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_npp_p: %ld# write file %s with replica %ld to some npp failed\n",
                                remote_mod_node_idx, (char *)cstring_get_str(file_path), CDFSNP_FNODE_REPNUM(cdfsnp_fnode));
        }
        cvector_set_no_lock(ret_vec, remote_mod_node_idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_CDFS_0046);
    }
    cvector_free_no_lock(ret_vec, LOC_CDFS_0047);

    if(EC_FALSE == result)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_update_npp_p: update file %s to npp failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}
#endif
/**
*
*  delete a file or dir from current npp
*
**/
EC_BOOL cdfs_delete_npp(const UINT32 cdfs_md_id, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec)
{
    CDFS_MD      *cdfs_md;
    //UINT32        cdfsnp_fnode_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_delete_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_delete_npp: name node pool was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_delete(CDFS_MD_NPP(cdfs_md), path, dflag, cdfsnp_fnode_vec))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_delete_npp: delete %s, dflag %lx failed\n", (char *)cstring_get_str(path), dflag);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_npp: cdfsnp_fnode_vec is:\n");
    //cvector_print_no_lock(LOGSTDOUT, cdfsnp_fnode_vec, (CVECTOR_DATA_PRINT)cdfsnp_fnode_print);
/*
    for(cdfsnp_fnode_pos = 0; cdfsnp_fnode_pos < cvector_size(cdfsnp_fnode_vec); cdfsnp_fnode_pos ++)
    {
        CDFSNP_FNODE *cdfsnp_fnode;

        cdfsnp_fnode = (CDFSNP_FNODE *)cvector_get_no_lock(cdfsnp_fnode_vec, cdfsnp_fnode_pos);
        if(NULL_PTR == cdfsnp_fnode)
        {
            continue;
        }
        cdfs_delete_dn_p(cdfs_md_id, cdfsnp_fnode);
    }
*/
    return (EC_TRUE);
}

/**
*
*  delete a file or dir from all npp
*
**/
EC_BOOL cdfs_delete_npp_p(const UINT32 cdfs_md_id, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec)
{
    CDFS_MD *cdfs_md;

    CVECTOR *collected_vec;
    UINT32   succ_counter;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_delete_npp_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_delete_npp_p: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_npp_p: beg: cdfsnp_fnode_vec size = %ld\n", cvector_size(cdfsnp_fnode_vec));

    succ_counter = 0;
    if(1)/*delete from all npp*/
    {
        TASK_MGR *task_mgr;
        MOD_MGR  *mod_mgr;
        CVECTOR  *ret_vec;

        UINT32 remote_mod_node_num;
        UINT32 remote_mod_node_idx;

        mod_mgr = CDFS_MD_NPP_MOD_MGR(cdfs_md);

        collected_vec = cvector_new(0, MM_CVECTOR, LOC_CDFS_0048);
        ret_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0049);

        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL  *ret;
            CVECTOR  *cdfsnp_fnode_vec_ret;

            cdfsnp_fnode_vec_ret = cvector_new(0, MM_CDFSNP_FNODE, LOC_CDFS_0050);
            cvector_push_no_lock(collected_vec, (void *)cdfsnp_fnode_vec_ret);

            alloc_static_mem(MM_UINT32, &ret, LOC_CDFS_0051);
            cvector_push_no_lock(ret_vec, (void *)ret);

            (*ret) = EC_FALSE;

            task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_cdfs_delete_npp, CMPI_ERROR_MODI, path, dflag, cdfsnp_fnode_vec_ret);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        remote_mod_node_num = cvector_size(ret_vec);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL *ret;
            CVECTOR  *cdfsnp_fnode_vec_ret;

            ret = (EC_BOOL *)cvector_get_no_lock(ret_vec, remote_mod_node_idx);
            cdfsnp_fnode_vec_ret = (CVECTOR *)cvector_get_no_lock(collected_vec, remote_mod_node_idx);
            if(EC_TRUE == (*ret))
            {
                succ_counter ++;
                //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_npp_p: cdfsnp_fnode_vec_ret size = %ld\n", cvector_size(cdfsnp_fnode_vec_ret));
                cvector_merge_with_move(cdfsnp_fnode_vec_ret, cdfsnp_fnode_vec, (CVECTOR_DATA_CMP)cdfsnp_fnode_cmp);
                //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_npp_p: ==> cdfsnp_fnode_vec size = %ld\n", cvector_size(cdfsnp_fnode_vec));
            }
            else
            {
                /*mod mgr may be changed when connection broken happen, hence cannot ouput mod node info here*/
                dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_delete_npp_p: %ld# delete %s from some npp failed\n",
                                    remote_mod_node_idx, (char *)cstring_get_str(path));
            }
            cvector_set_no_lock(ret_vec, remote_mod_node_idx, NULL_PTR);
            free_static_mem(MM_UINT32, ret, LOC_CDFS_0052);

            cvector_set_no_lock(collected_vec, remote_mod_node_idx, NULL_PTR);
            cvector_clean_no_lock(cdfsnp_fnode_vec_ret, (CVECTOR_DATA_CLEANER)cdfsnp_fnode_free, LOC_CDFS_0053);
            cvector_free_no_lock(cdfsnp_fnode_vec_ret, LOC_CDFS_0054);
        }

        cvector_free_no_lock(ret_vec, LOC_CDFS_0055);
        cvector_free_no_lock(collected_vec, LOC_CDFS_0056);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_npp_p: cdfsnp_fnode_vec is:\n");
    //cvector_print_no_lock(LOGSTDOUT, cdfsnp_fnode_vec, (CVECTOR_DATA_PRINT)cdfsnp_fnode_print);
    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_npp_p: end: cdfsnp_fnode_vec size = %ld\n", cvector_size(cdfsnp_fnode_vec));

    if(0 == succ_counter)
    {
        return (EC_FALSE);
    }

    if(succ_counter < CDFS_MD_NP_MIN_NUM(cdfs_md))/*when np replica not meet requirement, record it in log*/
    {
        dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[del path] %s\n", (char *)cstring_get_str(path));
#if 0
        /*warning: do not use task_mono_no_wait due to encoding would happen before sending*/
        if(0 < MOD_MGR_REMOTE_NUM(CDFS_MD_NPP_MOD_MGR(cdfs_md)))
        {
            task_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH,
                        TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, TASK_NEED_RESCHEDULE_FLAG,
                        NULL_PTR, FI_cdfs_lost_fnode_log, CMPI_ERROR_MODI, file_path, cdfsnp_fnode);
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[lost fnode] path %s, ", (char *)cstring_get_str(file_path));
            cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);
        }
#endif
    }

    return (EC_TRUE);
}

/**
*
*  delete file data from current dn
*
**/
EC_BOOL cdfs_delete_dn(const UINT32 cdfs_md_id, const UINT32 path_layout, const UINT32 offset)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_delete_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_delete_dn: no data node was open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_dn: path_layout %ld, offset %ld\n", path_layout, offset);
    return cdfsdn_remove(CDFS_MD_DN(cdfs_md), path_layout, offset);
}

/**
*
*  delete file data from all dn
*
**/
EC_BOOL cdfs_delete_dn_p(const UINT32 cdfs_md_id, const CVECTOR *cdfsnp_fnode_vec)
{
    CDFS_MD *cdfs_md;

    TASK_BRD *task_brd;
    UINT32 cdfsnp_fnode_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_delete_dn_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_delete_dn_p: dn mod mgr was null\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    for(cdfsnp_fnode_pos = 0; cdfsnp_fnode_pos < cvector_size(cdfsnp_fnode_vec); cdfsnp_fnode_pos ++)
    {
        TASK_MGR *task_mgr;
        CDFSNP_FNODE *cdfsnp_fnode;

        UINT32   replica_pos;

        MOD_NODE send_mod_node;
        MOD_NODE recv_mod_node;

        EC_BOOL ret[CDFSNP_FILE_REPLICA_MAX_NUM];

        cdfsnp_fnode = (CDFSNP_FNODE *)cvector_get_no_lock(cdfsnp_fnode_vec, cdfsnp_fnode_pos);
        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_dn_p: cdfsnp_fnode_pos %ld, cdfsnp_fnode is\n", cdfsnp_fnode_pos);
        //cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);

        task_mgr = task_new(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

        MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&send_mod_node) = cdfs_md_id;

        for(replica_pos = 0; replica_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode); replica_pos ++)
        {
            CDFSNP_INODE *cdfsnp_inode;
            UINT32 path_layout;
            UINT32 file_offset;

            cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, replica_pos);

            /*note: here must get value from macro and then transfer to task_xxx due to they are defined as bitmap and task_xxx task value as UINT32*/
            path_layout  = CDFSNP_INODE_PATH(cdfsnp_inode);
            file_offset  = CDFSNP_INODE_FOFF(cdfsnp_inode);

            MOD_NODE_TCID(&recv_mod_node) = CDFSNP_INODE_TCID(cdfsnp_inode);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;

            dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete_dn_p: replica_pos %ld, cdfsnp_inode is (tcid %s, path %lx, offset %ld)\n",
                                replica_pos,
                                c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode)),
                                CDFSNP_INODE_PATH(cdfsnp_inode),
                                CDFSNP_INODE_FOFF(cdfsnp_inode));

            ret[replica_pos] = EC_FALSE;
            task_super_inc(task_mgr, &send_mod_node, &recv_mod_node,
                            &(ret[replica_pos]), FI_cdfs_delete_dn, CMPI_ERROR_MODI, path_layout, file_offset);
        }

        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        for(replica_pos = 0; replica_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode); replica_pos ++)
        {
            CDFSNP_INODE *cdfsnp_inode;

            cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, replica_pos);

            if(EC_FALSE == ret[replica_pos])
            {
                dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_delete_dn_p: delete file content from dn %s, bid %ld, sid %ld failed\n",
                                c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode)),
                                CDFSNP_INODE_PATH(cdfsnp_inode),
                                CDFSNP_INODE_FOFF(cdfsnp_inode)
                                );
            }
        }
    }

    return (EC_TRUE);
}

/**
*
*  delete a file or dir from all npp and all dn
*
**/
EC_BOOL cdfs_delete(const UINT32 cdfs_md_id, const CSTRING *path, const UINT32 dflag)
{
    CVECTOR *cdfsnp_fnode_vec;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_delete: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfsnp_fnode_vec = cvector_new(0, MM_CDFSNP_FNODE, LOC_CDFS_0057);

    if(EC_FALSE == cdfs_delete_npp_p(cdfs_md_id, path, dflag, cdfsnp_fnode_vec))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_delete: delete %s from some npp failed\n", (char *)cstring_get_str(path));
        cvector_clean(cdfsnp_fnode_vec, (CVECTOR_DATA_CLEANER)cdfsnp_fnode_free, LOC_CDFS_0058);
        cvector_free(cdfsnp_fnode_vec, LOC_CDFS_0059);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_delete: cdfsnp_fnode_vec is:\n");
    //cvector_print_no_lock(LOGSTDOUT, cdfsnp_fnode_vec, (CVECTOR_DATA_PRINT)cdfsnp_fnode_print);

    if(EC_FALSE == cdfs_delete_dn_p(cdfs_md_id, cdfsnp_fnode_vec))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_delete: delete %s from some data node failed\n", (char *)cstring_get_str(path));
        cvector_clean(cdfsnp_fnode_vec, (CVECTOR_DATA_CLEANER)cdfsnp_fnode_free, LOC_CDFS_0060);
        cvector_free(cdfsnp_fnode_vec, LOC_CDFS_0061);
        return (EC_FALSE);
    }

    cvector_clean(cdfsnp_fnode_vec, (CVECTOR_DATA_CLEANER)cdfsnp_fnode_free, LOC_CDFS_0062);
    cvector_free(cdfsnp_fnode_vec, LOC_CDFS_0063);
    return (EC_TRUE);
}

/**
*
*  query a file
*
**/
EC_BOOL cdfs_qfile(const UINT32 cdfs_md_id, const CSTRING *file_path, CDFSNP_ITEM  *cdfsnp_item)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_qfile: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_qfile: name node pool was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_reserve_np_to_read(CDFS_MD_NPP(cdfs_md), file_path, CDFSNP_ITEM_FILE_IS_REG, cdfsnp_item))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_qfile: query file %s from name node pool failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query a dir
*
**/
EC_BOOL cdfs_qdir(const UINT32 cdfs_md_id, const CSTRING *dir_path, CVECTOR  *cdfsnp_item_vec)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_qdir: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_qdir: name node pool was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_collect_items(CDFS_MD_NPP(cdfs_md), dir_path, CDFSNP_ITEM_FILE_IS_DIR, cdfsnp_item_vec))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_qfile: query dir %s from name node pool failed\n", (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query and list full path of a file or dir
*
**/
EC_BOOL cdfs_qlist_path(const UINT32 cdfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_qlist_path: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_qlist_path: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_list_path(CDFS_MD_NPP(cdfs_md), file_path, path_cstr_vec);
}

EC_BOOL cdfs_qlist_path_npp(const UINT32 cdfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CDFS_MD  *cdfs_md;
    TASK_MGR *task_mgr;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_qlist_path_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_qlist_path_npp: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    ret = EC_FALSE;

    task_mgr = task_new(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_inc(task_mgr, &ret, FI_cdfs_qlist_path, CMPI_ERROR_MODI, file_path, path_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (ret);
}

/**
*
*  query and list short name of a file or dir
*
**/
EC_BOOL cdfs_qlist_seg(const UINT32 cdfs_md_id, const CSTRING *file_path, CVECTOR  *seg_cstr_vec)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_qlist_seg: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_qlist_seg: name node pool was not open\n");
        return (EC_FALSE);
    }
    return cdfsnp_mgr_list_seg(CDFS_MD_NPP(cdfs_md), file_path, seg_cstr_vec);
}

EC_BOOL cdfs_qlist_seg_npp(const UINT32 cdfs_md_id, const CSTRING *file_seg, CVECTOR  *seg_cstr_vec)
{
    CDFS_MD  *cdfs_md;
    TASK_MGR *task_mgr;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_qlist_seg_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_qlist_seg_npp: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    ret = EC_FALSE;

    task_mgr = task_new(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    task_inc(task_mgr, &ret, FI_cdfs_qlist_seg, CMPI_ERROR_MODI, file_seg, seg_cstr_vec);
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (ret);
}

/**
*
*  flush name node pool
*
**/
EC_BOOL cdfs_flush_npp(const UINT32 cdfs_md_id, const UINT32 cdfsnpp_tcid)
{
    CDFS_MD *cdfs_md;
    EC_BOOL  ret;
    MOD_NODE recv_mod_node;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_flush_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(CMPI_LOCAL_TCID == cdfsnpp_tcid)
    {
        if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_flush_npp: name node pool is null\n");
            return (EC_FALSE);
        }

        return cdfsnp_mgr_flush(CDFS_MD_NPP(cdfs_md));
    }

    if(EC_FALSE == cdfs_tcid_is_connected(cdfsnpp_tcid))
    {
        return (EC_FALSE);
    }

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = cdfsnpp_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_super_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cdfs_flush_npp, CMPI_ERROR_MODI, cdfsnpp_tcid);
    return (ret);
}

/**
*
*  flush data node
*
*
**/
EC_BOOL cdfs_flush_dn(const UINT32 cdfs_md_id, const UINT32 cdfsdn_tcid)
{
    CDFS_MD *cdfs_md;
    EC_BOOL  ret;
    MOD_NODE recv_mod_node;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_flush_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(CMPI_LOCAL_TCID == cdfsdn_tcid)
    {
        if(NULL_PTR == CDFS_MD_DN(cdfs_md))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_flush_dn: data node is null\n");
            return (EC_FALSE);
        }

        return cdfsdn_flush(CDFS_MD_DN(cdfs_md));
    }

    if(EC_FALSE == cdfs_tcid_is_connected(cdfsdn_tcid))
    {
        return (EC_FALSE);
    }

    ret = EC_FALSE;

    MOD_NODE_TCID(&recv_mod_node) = cdfsdn_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_CDFS_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_super_mono(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_cdfs_flush_dn, CMPI_ERROR_MODI, cdfsdn_tcid);
    return (ret);
}

/**
*
*  flush specific name node
*
*
**/
void cdfs_flush_np(const UINT32 cdfs_md_id, const UINT32 cdfsnp_path_layout)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_flush_np: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_flush_np: name node pool is null\n");
        return;
    }

    cdfsnp_mgr_flush_np(CDFS_MD_NPP(cdfs_md), cdfsnp_path_layout);
    return;
}

/**
*
*  check this CDFS is name node pool or not
*
*
**/
EC_BOOL cdfs_is_npp(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_is_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CDFS is data node or not
*
*
**/
EC_BOOL cdfs_is_dn(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_is_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  list all added or registed name node pool to this CDFS
*
*
**/
EC_BOOL cdfs_list_npp(const UINT32 cdfs_md_id, LOG *log)
{
    CDFS_MD *cdfs_md;
    MOD_MGR *cdfsnpp_mog_mgr;
    UINT32   remote_mod_node_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_list_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    cdfsnpp_mog_mgr = CDFS_MD_NPP_MOD_MGR(cdfs_md);

    if(NULL_PTR == cdfsnpp_mog_mgr)
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    for(remote_mod_node_pos = 0; remote_mod_node_pos < MOD_MGR_REMOTE_NUM(cdfsnpp_mog_mgr); remote_mod_node_pos ++)
    {
        MOD_NODE *remote_mod_node;

        remote_mod_node = MOD_MGR_REMOTE_MOD(cdfsnpp_mog_mgr, remote_mod_node_pos);
        sys_log(log, "%ld # (tcid %s, comm %ld, rank %ld, modi %ld)\n", remote_mod_node_pos,
                    MOD_NODE_TCID_STR(remote_mod_node),
                    MOD_NODE_COMM(remote_mod_node),
                    MOD_NODE_RANK(remote_mod_node),
                    MOD_NODE_MODI(remote_mod_node)
                );
    }

    return (EC_TRUE);
}

/**
*
*  list all added or registed data nodes to this CDFS
*
*
**/
EC_BOOL cdfs_list_dn(const UINT32 cdfs_md_id, LOG *log)
{
    CDFS_MD *cdfs_md;
    MOD_MGR *cdfsdn_mog_mgr;
    UINT32   remote_mod_node_pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_list_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    cdfsdn_mog_mgr = CDFS_MD_DN_MOD_MGR(cdfs_md);

    if(NULL_PTR == cdfsdn_mog_mgr)
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    for(remote_mod_node_pos = 0; remote_mod_node_pos < MOD_MGR_REMOTE_NUM(cdfsdn_mog_mgr); remote_mod_node_pos ++)
    {
        MOD_NODE *remote_mod_node;

        remote_mod_node = MOD_MGR_REMOTE_MOD(cdfsdn_mog_mgr, remote_mod_node_pos);
        sys_log(log, "%ld # (tcid %s, comm %ld, rank %ld, modi %ld)\n", remote_mod_node_pos,
                    MOD_NODE_TCID_STR(remote_mod_node),
                    MOD_NODE_COMM(remote_mod_node),
                    MOD_NODE_RANK(remote_mod_node),
                    MOD_NODE_MODI(remote_mod_node)
                );
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
EC_BOOL cdfs_file_num(const UINT32 cdfs_md_id, const CSTRING *path_cstr, UINT32 *file_num)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_file_num: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_file_num: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_file_num(CDFS_MD_NPP(cdfs_md), path_cstr, file_num);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cdfs_file_size(const UINT32 cdfs_md_id, const CSTRING *path_cstr, UINT32 *file_size)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_file_size: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_file_size: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_file_size(CDFS_MD_NPP(cdfs_md), path_cstr, file_size);
}

/**
*
*  mkdir in current name node pool
*
**/
EC_BOOL cdfs_mkdir(const UINT32 cdfs_md_id, const CSTRING *path_cstr)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_mkdir: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_mkdir: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_mkdir(CDFS_MD_NPP(cdfs_md), path_cstr);
}

/**
*
*  mkdir to all name node pool
*
**/
EC_BOOL cdfs_mkdir_npp(const UINT32 cdfs_md_id, const CSTRING *path_cstr)
{
    CDFS_MD *cdfs_md;
    UINT32   succ_counter;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_mkdir_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_mkdir_npp: npp mod mgr was null\n");
        return (EC_FALSE);
    }

    succ_counter = 0;
    if(1)
    {
        TASK_MGR *task_mgr;
        MOD_MGR  *mod_mgr;
        CVECTOR  *ret_vec;

        UINT32 remote_mod_node_num;
        UINT32 remote_mod_node_idx;

        mod_mgr = CDFS_MD_NPP_MOD_MGR(cdfs_md);

        ret_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0064);

        task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        remote_mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL  *ret;

            alloc_static_mem(MM_UINT32, &ret, LOC_CDFS_0065);
            cvector_push(ret_vec, (void *)ret);

            (*ret) = EC_FALSE;

            task_pos_inc(task_mgr, remote_mod_node_idx, ret, FI_cdfs_mkdir, CMPI_ERROR_MODI, path_cstr);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        remote_mod_node_num = cvector_size(ret_vec);
        for(remote_mod_node_idx = 0; remote_mod_node_idx < remote_mod_node_num; remote_mod_node_idx ++)
        {
            EC_BOOL *ret;

            ret = (EC_BOOL *)cvector_get(ret_vec, remote_mod_node_idx);
            if(EC_TRUE == (*ret))
            {
                succ_counter ++;
            }
            else
            {
                /*mod mgr may be changed when connection broken happen, hence cannot ouput mod node info here*/
                dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_mkdir_npp: %ld# mkdir %s to some npp failed\n",
                                    remote_mod_node_idx, (char *)cstring_get_str(path_cstr));
            }
            cvector_set(ret_vec, remote_mod_node_idx, NULL_PTR);
            free_static_mem(MM_UINT32, ret, LOC_CDFS_0066);
        }

        cvector_free(ret_vec, LOC_CDFS_0067);
    }

    if(0 == succ_counter)
    {
        return (EC_FALSE);
    }
#if 0
    if(succ_counter < CDFS_MD_NP_MIN_NUM(cdfs_md))/*when np replica not meet requirement, record it in log*/
    {
        /*warning: do not use task_mono_no_wait due to encoding would happen before sending*/
        if(0 < MOD_MGR_REMOTE_NUM(CDFS_MD_NPP_MOD_MGR(cdfs_md)))
        {
            task_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_HIGH,
                        TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP, TASK_NEED_RESCHEDULE_FLAG,
                        NULL_PTR, FI_cdfs_lost_fnode_log, CMPI_ERROR_MODI, path_cstr, cdfsnp_fnode);
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[lost fnode] path %s, ", (char *)cstring_get_str(path_cstr));
            cdfsnp_fnode_print(LOGSTDOUT, cdfsnp_fnode);
        }
    }
#endif
    return (EC_TRUE);
}

/*src data node do*/
EC_BOOL cdfs_transfer_out(const UINT32 cdfs_md_id, const UINT32 des_datanode_tcid, UINT32 *src_block_path_layout, UINT32 *des_block_path_layout)
{
    CDFS_MD      *cdfs_md;

    CDFSDN_BLOCK *cdfsdn_block;
    CDFSDN_RECORD *cdfsdn_record;

    EC_BOOL ret;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_transfer_out: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer_out: data node was not open\n");
        return (EC_FALSE);
    }

    cdfsdn_block = cdfsdn_transfer_out_start(CDFS_MD_DN(cdfs_md));
    if(NULL_PTR == cdfsdn_block)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer_out: no more block to transfer\n");
        return (EC_FALSE);
    }

    (*src_block_path_layout) = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
    cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(CDFS_MD_DN(cdfs_md)), CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
/*
    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_transfer_out: cdfsdn_record is\n");
    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "record #: cached flag %ld, updated flag %ld, write flag %ld, swapout flag %ld, reader num %ld, size %ld, room %ld, first free partition %ld, next record %ld\n",
                CDFSDN_RECORD_CACHED_FLAG(cdfsdn_record),
                CDFSDN_RECORD_UPDATED_FLAG(cdfsdn_record),
                CDFSDN_RECORD_WRITE_FLAG(cdfsdn_record),
                CDFSDN_RECORD_SWAPOUT_FLAG(cdfsdn_record),
                CDFSDN_RECORD_READER_NUM(cdfsdn_record) & CDFSDN_32BIT_MASK,
                CDFSDN_RECORD_SIZE(cdfsdn_record),
                CDFSDN_RECORD_ROOM(cdfsdn_record),
                CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record),
                CDFSDN_RECORD_NEXT(cdfsdn_record));

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_transfer_out: cdfsdn_block is\n");
    cdfsdn_block_print(LOGSTDOUT, cdfsdn_block);
*/
    ret = EC_FALSE;
    task_tcid_mono(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    des_datanode_tcid,
                    &ret, FI_cdfs_transfer_in, CMPI_ERROR_MODI, cdfsdn_record, cdfsdn_block, des_block_path_layout);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer_out: transfer block %ld to data node %s failed\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), c_word_to_ipv4(des_datanode_tcid));
        return (EC_FALSE);
    }

    cdfsdn_transfer_out_end(CDFS_MD_DN(cdfs_md), cdfsdn_block);/*cdfsdn_block will be free here*/
    return (EC_TRUE);
}

/*des data node do*/
EC_BOOL cdfs_transfer_in(const UINT32 cdfs_md_id, const CDFSDN_RECORD *cdfsdn_record, const CDFSDN_BLOCK *cdfsdn_block, UINT32 *des_block_path_layout)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_transfer_in: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer_in: data node was not open\n");
        return (EC_FALSE);
    }
/*
    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_transfer_in: cdfsdn_record is\n");
    dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "record #: cached flag %ld, updated flag %ld, write flag %ld, swapout flag %ld, reader num %ld, size %ld, room %ld, first free partition %ld, next record %ld\n",
                CDFSDN_RECORD_CACHED_FLAG(cdfsdn_record),
                CDFSDN_RECORD_UPDATED_FLAG(cdfsdn_record),
                CDFSDN_RECORD_WRITE_FLAG(cdfsdn_record),
                CDFSDN_RECORD_SWAPOUT_FLAG(cdfsdn_record),
                CDFSDN_RECORD_READER_NUM(cdfsdn_record) & CDFSDN_32BIT_MASK,
                CDFSDN_RECORD_SIZE(cdfsdn_record),
                CDFSDN_RECORD_ROOM(cdfsdn_record),
                CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record),
                CDFSDN_RECORD_NEXT(cdfsdn_record));

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_transfer_in: cdfsdn_block is\n");
    cdfsdn_block_print(LOGSTDOUT, cdfsdn_block);
*/
    return cdfsdn_transfer_in_do(CDFS_MD_DN(cdfs_md), CDFSDN_RECORD_SIZE(cdfsdn_record), CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record), cdfsdn_block, des_block_path_layout);
}

/*np do*/
EC_BOOL cdfs_transfer(const UINT32 cdfs_md_id, const UINT32 src_datanode_tcid, const UINT32 des_datanode_tcid, const UINT32 transfer_max_gb)
{
    CDFS_MD      *cdfs_md;

    UINT32 transfer_block_num;
    UINT32 transfer_block_idx;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_transfer: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer: name node was not open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFS_MD_DN_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer: dn mod mgr is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFS_MD_NPP_MOD_MGR(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer: npp mod mgr is null\n");
        return (EC_FALSE);
    }

    transfer_block_num = (transfer_max_gb * CDFSDN_MAX_BLOCKS_PER_GB);
    for(transfer_block_idx = 0; transfer_block_idx < transfer_block_num; transfer_block_idx ++)
    {
        UINT32 src_block_path_layout;
        UINT32 des_block_path_layout;
        EC_BOOL ret;

        ret = EC_FALSE;
        task_tcid_mono(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    src_datanode_tcid,
                    &ret, FI_cdfs_transfer_out, CMPI_ERROR_MODI, des_datanode_tcid, &src_block_path_layout, &des_block_path_layout);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer: transfer out of dn %s failed\n", c_word_to_ipv4(src_datanode_tcid));
            return (EC_FALSE);
        }

        dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_transfer: data was transfered from tcid %s block %ld to tcid %s block %ld\n",
                            c_word_to_ipv4(src_datanode_tcid), src_block_path_layout,
                            c_word_to_ipv4(des_datanode_tcid), des_block_path_layout);
        /*update all np*/
        task_bcast(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                   FI_cdfs_transfer_update, CMPI_ERROR_MODI, src_datanode_tcid, src_block_path_layout, des_datanode_tcid, des_block_path_layout);
    }
    return (EC_TRUE);
}

/*np do*/
EC_BOOL cdfs_transfer_update(const UINT32 cdfs_md_id, const UINT32 src_datanode_tcid, const UINT32 src_block_path_layout, const UINT32 des_datanode_tcid, const UINT32 des_block_path_layout)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_transfer_update: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);
    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_transfer_update: name node was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_update(CDFS_MD_NPP(cdfs_md), src_datanode_tcid, src_block_path_layout, des_datanode_tcid, des_block_path_layout);
}

static EC_BOOL cdfs_snapshot_make(const CSTRING *cmd_cstr)
{
    return exec_shell((char *)cstring_get_str(cmd_cstr), NULL_PTR, 0);
}

EC_BOOL cdfs_snapshot_dn(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;

    CDFSDN  *cdfsdn;
    CSTRING *cmd_cstr;
    char    *db_root_dir;

    UINT32 local_tcid;

    struct tm *cur_time;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_snapshot_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    /*flush data node*/
    local_tcid = CMPI_LOCAL_TCID;
    if(EC_FALSE == cdfs_flush_dn(cdfs_md_id, local_tcid))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_snapshot_dn: flush dn %s failed\n", c_word_to_ipv4(local_tcid));
        return (EC_FALSE);
    }

    /*mkdir ${DB_ROOT}/snapshot*/
    cdfs_md     = CDFS_MD_GET(cdfs_md_id);
    cdfsdn      = CDFS_MD_DN(cdfs_md);
    db_root_dir = (char *)CDFSDN_ROOT_DIR(cdfsdn);

    cmd_cstr = cstring_new(NULL_PTR, LOC_CDFS_0068);
    cstring_format(cmd_cstr, "%s/snapshot", db_root_dir);

    if(EC_FALSE == c_dir_create((char *)cstring_get_str(cmd_cstr)))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_snapshot_npp: create dir %s failed\n", (char *)cstring_get_str(cmd_cstr));
        cstring_free(cmd_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_snapshot_dn: create dir %s\n", (char *)cstring_get_str(cmd_cstr));

    cur_time = c_localtime_r(NULL_PTR);

    cstring_reset(cmd_cstr);
    cstring_format(cmd_cstr, "cd %s && tar zcvf snapshot/dn_%s_snapshot_%4d%02d%02d_%02d%02d%02d.tar.gz records.dat",
                            db_root_dir,
                            c_word_to_ipv4(local_tcid),
                            TIME_IN_YMDHMS(cur_time)
                            );

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_snapshot_dn: cmd line is: %s\n", (char *)cstring_get_str(cmd_cstr));

    /*make data node snapshot*/
    if(EC_FALSE == cdfs_snapshot_make(cmd_cstr))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_snapshot_dn: dn %s make snapshot failed\n", c_word_to_ipv4(local_tcid));
        cstring_free(cmd_cstr);
        return (EC_FALSE);
    }

    cstring_free(cmd_cstr);
    return (EC_TRUE);
}

EC_BOOL cdfs_snapshot_npp(const UINT32 cdfs_md_id)
{
    CDFS_MD *cdfs_md;

    CDFSNP_MGR *cdfsnp_mgr;
    CSTRING *cmd_cstr;
    char *db_root_dir;

    UINT32 local_tcid;

    struct tm *cur_time;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_snapshot_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    /*flush name node*/
    local_tcid = CMPI_LOCAL_TCID;
    if(EC_FALSE == cdfs_flush_npp(cdfs_md_id, local_tcid))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_snapshot_npp: flush npp %s failed\n", c_word_to_ipv4(local_tcid));
        return (EC_FALSE);
    }

    /*mkdir ${DB_ROOT}/snapshot*/
    cdfs_md     = CDFS_MD_GET(cdfs_md_id);
    cdfsnp_mgr  = CDFS_MD_NPP(cdfs_md);
    db_root_dir = (char *)cstring_get_str(CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr));

    cmd_cstr = cstring_new(NULL_PTR, LOC_CDFS_0069);
    cstring_format(cmd_cstr, "%s/snapshot", db_root_dir);

    if(EC_FALSE == c_dir_create((char *)cstring_get_str(cmd_cstr)))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_snapshot_npp: create dir %s failed\n", (char *)cstring_get_str(cmd_cstr));
        cstring_free(cmd_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_snapshot_npp: create dir %s\n", (char *)cstring_get_str(cmd_cstr));

    cur_time = c_localtime_r(NULL_PTR);

    cstring_reset(cmd_cstr);
    cstring_format(cmd_cstr, "cd %s && tar zcvf snapshot/npp_%s_snapshot_%4d%02d%02d_%02d%02d%02d.tar.gz *.db dsk*",
                            db_root_dir,
                            c_word_to_ipv4(local_tcid),
                            TIME_IN_YMDHMS(cur_time));

    dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_snapshot_npp: cmd line is: %s\n", (char *)cstring_get_str(cmd_cstr));

    /*make name node snapshot*/
    if(EC_FALSE == cdfs_snapshot_make(cmd_cstr))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_snapshot_npp: npp %s make snapshot failed\n", c_word_to_ipv4(local_tcid));
        cstring_free(cmd_cstr);
        return (EC_FALSE);
    }

    cstring_free(cmd_cstr);
    return (EC_TRUE);
}

EC_BOOL cdfs_snapshot(const UINT32 cdfs_md_id)
{
#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_snapshot: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    if(EC_TRUE == cdfs_is_dn(cdfs_md_id))
    {
        return cdfs_snapshot_dn(cdfs_md_id);
    }

    if(EC_TRUE == cdfs_is_npp(cdfs_md_id))
    {
        return cdfs_snapshot_npp(cdfs_md_id);
    }

    dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_snapshot: current node was neither data node nor name node\n");
    return (EC_FALSE);
}

/**
*
*  mkdir to all name node pool
*
**/
EC_BOOL cdfs_mkdir_p(const UINT32 cdfs_md_id, const CSTRING *path_cstr)
{
#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_mkdir_p: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    return cdfs_mkdir_npp(cdfs_md_id, path_cstr);
}

/**
*
*  check replica num and tcid set and path layout validity
*
**/
EC_BOOL cdfs_check_replicas(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 replica_num, const CVECTOR *tcid_vec)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_check_replicas: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_check_replicas: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_check_replicas(CDFS_MD_NPP(cdfs_md), file_path, replica_num, tcid_vec);
}

/**
*
*  check file content on data node
*
**/
EC_BOOL cdfs_check_file_content(const UINT32 cdfs_md_id, const UINT32 path_layout, const UINT32 offset, const UINT32 file_size, const CSTRING *file_content_cstr)
{
    CDFS_MD *cdfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_check_file_content: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_file_content: data node is null\n");
        return (EC_FALSE);
    }

    cbytes = cbytes_new(file_size);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_file_content: new cdfs buff with len %ld failed\n", file_size);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsdn_read(CDFS_MD_DN(cdfs_md), path_layout, offset, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_file_content: read path layout %ld, offset %ld, file size %ld failed\n", path_layout, offset, file_size);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < cstring_get_len(file_content_cstr))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_file_content: read path layout %ld, offset %ld, file size %ld to buff len %ld less than cstring len %ld to compare\n",
                            path_layout, offset, file_size, CBYTES_LEN(cbytes), cstring_get_len(file_content_cstr));
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
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_file_content: char at pos %ld not matched\n", pos);
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
*  check content with sepcific len of all replica files
*
**/
EC_BOOL cdfs_check_replica_files_content(const UINT32 cdfs_md_id, const CSTRING *file_path, const UINT32 file_size, const CSTRING *file_content_cstr)
{
    CDFS_MD      *cdfs_md;
    CDFSNP_ITEM   cdfsnp_item;
    CDFSNP_FNODE *cdfsnp_fnode;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_check_replica_files_content: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_check_replica_files_content: name node pool was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_reserve_np_to_read(CDFS_MD_NPP(cdfs_md), file_path, CDFSNP_ITEM_FILE_IS_REG, &cdfsnp_item))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_replica_files_content: query file %s from name node pool failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG != CDFSNP_ITEM_DFLG(&cdfsnp_item))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_replica_files_content: file path %s is not regular file\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    cdfsnp_fnode = CDFSNP_ITEM_FNODE(&cdfsnp_item);

    if(file_size != CDFSNP_FNODE_FILESZ(cdfsnp_fnode))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_replica_files_content: file path %s has file size %ld but expected is %ld\n",
                            (char *)cstring_get_str(file_path), CDFSNP_FNODE_FILESZ(cdfsnp_fnode), file_size);
        return (EC_FALSE);
    }

    if(1)
    {
        TASK_MGR *task_mgr;

        EC_BOOL ret[CDFSNP_FILE_REPLICA_MAX_NUM];

        UINT32 cdfsnp_inode_pos;

        task_mgr = task_new(CDFS_MD_DN_MOD_MGR(cdfs_md), TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        for(cdfsnp_inode_pos = 0;
            cdfsnp_inode_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && cdfsnp_inode_pos < CDFSNP_FILE_REPLICA_MAX_NUM;
            cdfsnp_inode_pos ++
            )
        {
            CDFSNP_INODE *cdfsnp_inode;

            cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, cdfsnp_inode_pos);
            ret[cdfsnp_inode_pos] = EC_FALSE;

            task_tcid_inc(task_mgr, CDFSNP_INODE_TCID(cdfsnp_inode),
                          &(ret[cdfsnp_inode_pos]), FI_cdfs_check_file_content, CMPI_ERROR_MODI,
                          CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK,
                          CDFSNP_INODE_FOFF(cdfsnp_inode) & CDFSNP_32BIT_MASK,
                          file_size, file_content_cstr);
        }
        task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        for(cdfsnp_inode_pos = 0;
            cdfsnp_inode_pos < CDFSNP_FNODE_REPNUM(cdfsnp_fnode) && cdfsnp_inode_pos < CDFSNP_FILE_REPLICA_MAX_NUM;
            cdfsnp_inode_pos ++
            )
        {
            if(EC_FALSE == ret[cdfsnp_inode_pos])
            {
                CDFSNP_INODE *cdfsnp_inode;

                cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, cdfsnp_inode_pos);
                dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_check_replica_files_content: file %s on tcid %s with path layout %ld, foff %ld not matched\n",
                                    (char *)cstring_get_str(file_path), c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode)),
                                    CDFSNP_INODE_PATH(cdfsnp_inode), CDFSNP_INODE_FOFF(cdfsnp_inode)
                        );
                return (EC_FALSE);
            }
        }
    }
    return (EC_TRUE);
}

/**
*
*  check inode info belong to specific cdfsdn block on some tcid
*
**/
EC_BOOL cdfs_figure_out_block(const UINT32 cdfs_md_id, const UINT32 tcid, const UINT32 path_layout, LOG *log)
{
    CDFS_MD      *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_figure_out_block: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        dbg_log(SEC_0056_CDFS, 1)(LOGSTDOUT, "warn:cdfs_figure_out_block: name node pool was not open\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_figure_out_block(CDFS_MD_NPP(cdfs_md), tcid, path_layout, log);
}
/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL cdfs_show_npp(const UINT32 cdfs_md_id, LOG *log)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_show_npp: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cdfsnp_mgr_print(log, CDFS_MD_NPP(cdfs_md));

    return (EC_TRUE);
}

/**
*
*  show cdfsdn info if it is dn
*
*
**/
EC_BOOL cdfs_show_dn(const UINT32 cdfs_md_id, LOG *log)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_show_dn: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_DN(cdfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cdfsdn_print(log, CDFS_MD_DN(cdfs_md));

    return (EC_TRUE);
}

/*debug*/
EC_BOOL cdfs_show_cached_np(const UINT32 cdfs_md_id, LOG *log)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_show_cached_np: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_show_cached_np(CDFS_MD_NPP(cdfs_md), log);
}

EC_BOOL cdfs_show_specific_np(const UINT32 cdfs_md_id, const UINT32 cdfsnp_path_layout, LOG *log)
{
    CDFS_MD *cdfs_md;

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_show_specific_np: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    if(NULL_PTR == CDFS_MD_NPP(cdfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    return cdfsnp_mgr_showup_np(CDFS_MD_NPP(cdfs_md), cdfsnp_path_layout, log);
}

/**
*
*  import lost fnode records from current np to remote np
*
*
**/
EC_BOOL cdfs_import_lost_fnode_from_file(const UINT32 cdfs_md_id, const CSTRING *file_name, const UINT32 des_tcid)
{
    CDFS_MD *cdfs_md;

    FILE *lost_fnode_fp;
    char  str_line[CDFS_LOST_FNODE_LINE_MAX_SIZE];
    UINT32 line_no;

    /*[2012-07-06 15:00:19] path /hansoul02/20120706_150235_00000005/775.dat, size 8192, replica 3,(tcid 10.10.10.2, path 68, offset 3440640),(tcid 10.10.10.3, path 67, offset 53141504),(tcid 10.10.10.4, path 68, offset 4190208),*/

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_import_lost_fnode_from_file: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    lost_fnode_fp = fopen((char *)cstring_get_str(file_name), "r");
    if(NULL_PTR == lost_fnode_fp)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_import_lost_fnode_from_file: open lost fnode log file %s failed\n",
                            (char *)cstring_get_str(file_name));
        return (EC_FALSE);
    }

    line_no = 1;

    fgets(str_line, CDFS_LOST_FNODE_LINE_MAX_SIZE, lost_fnode_fp);/*skip the first line*/
    if((char *)0 == strcasestr(str_line, "my pid ="))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_import_lost_fnode_from_file: fnode log file %s has invalid first line %s\n",
                            (char *)cstring_get_str(file_name), (char *)str_line);
        fclose(lost_fnode_fp);
        return (EC_FALSE);
    }

    line_no ++;

    while(fgets(str_line, CDFS_LOST_FNODE_LINE_MAX_SIZE, lost_fnode_fp))
    {
        CDFSNP_FNODE    cdfsnp_fnode;

        char  *fields[32];
        UINT32 field_num;
        UINT32 field_pos;

        UINT32 replica_pos;

        CSTRING *path;

        EC_BOOL ret;

        field_num = c_str_split(str_line, " ,()\t\r\n", fields, sizeof(fields)/sizeof(fields[ 0 ]));
        if(8 > field_num)
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import fnode error] line # %ld\n", line_no ++);
            continue;/*skip invalid line*/
        }

        /*file path*/
        path = cstring_new((UINT8 *)(fields[ 3 ]), LOC_CDFS_0070);

        /*file size*/
        CDFSNP_FNODE_FILESZ(&cdfsnp_fnode) = c_str_to_word(fields[ 5 ]);

        /*replica num*/
        CDFSNP_FNODE_REPNUM(&cdfsnp_fnode) = c_str_to_word(fields[ 7 ]);

        for(field_pos = 9, replica_pos = 0;
            field_pos + 4 < field_num && replica_pos < CDFSNP_FNODE_REPNUM(&cdfsnp_fnode);
            field_pos += 6, replica_pos ++)
        {
            CDFSNP_FNODE_INODE_TCID(&cdfsnp_fnode, replica_pos) = c_ipv4_to_word(fields[ field_pos + 0]);
            CDFSNP_FNODE_INODE_PATH(&cdfsnp_fnode, replica_pos) = c_str_to_word(fields[ field_pos + 2 ]);
            CDFSNP_FNODE_INODE_FOFF(&cdfsnp_fnode, replica_pos) = c_str_to_word(fields[ field_pos + 4 ]);
        }
#if 0
        /*CDFSNP_INODE 1#*/
        CDFSNP_FNODE_INODE_TCID(&cdfsnp_fnode, 0) = c_ipv4_to_word(fields[ 9 ]);
        CDFSNP_FNODE_INODE_PATH(&cdfsnp_fnode, 0) = c_str_to_word(fields[ 11 ]);
        CDFSNP_FNODE_INODE_FOFF(&cdfsnp_fnode, 0) = c_str_to_word(fields[ 13 ]);

        /*CDFSNP_INODE 2#*/
        CDFSNP_FNODE_INODE_TCID(&cdfsnp_fnode, 1) = c_ipv4_to_word(fields[ 15 ]);
        CDFSNP_FNODE_INODE_PATH(&cdfsnp_fnode, 1) = c_str_to_word(fields[ 17 ]);
        CDFSNP_FNODE_INODE_FOFF(&cdfsnp_fnode, 1) = c_str_to_word(fields[ 19 ]);

        /*CDFSNP_INODE 3#*/
        CDFSNP_FNODE_INODE_TCID(&cdfsnp_fnode, 2) = c_ipv4_to_word(fields[ 21 ]);
        CDFSNP_FNODE_INODE_PATH(&cdfsnp_fnode, 2) = c_str_to_word(fields[ 23 ]);
        CDFSNP_FNODE_INODE_FOFF(&cdfsnp_fnode, 2) = c_str_to_word(fields[ 25 ]);
#endif
        //dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "path: %s\n", (char *)cstring_get_str(path));
        //cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);

        if(des_tcid == CMPI_LOCAL_TCID)
        {
            ret = cdfs_write_npp(cdfs_md_id, path, &cdfsnp_fnode);
        }
        else
        {
            ret = EC_FALSE;
            task_tcid_mono(CDFS_MD_NPP_MOD_MGR(cdfs_md), TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                           des_tcid,
                           &ret, FI_cdfs_write_npp, CMPI_ERROR_MODI, path, &cdfsnp_fnode);
        }

        if(EC_TRUE == ret)
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import fnode succ] line # %ld\n", line_no ++);
        }
        else
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import fnode fail] line # %ld\n", line_no ++);
        }

        cstring_free(path);
    }

    fclose(lost_fnode_fp);

    return (EC_TRUE);
}

/**
*
*  import/complete lost replica from current dn
*
*
**/
EC_BOOL cdfs_import_lost_replica_from_file(const UINT32 cdfs_md_id, const CSTRING *file_name, const UINT32 des_tcid)
{
    CDFS_MD *cdfs_md;

    FILE *lost_replica_fp;
    char  str_line[CDFS_LOST_REPLICA_LINE_MAX_SIZE];
    UINT32 line_no;

    /*[2012-07-10 14:46:38] expect 3, size 16384, replica 2, (tcid 10.10.10.3, path 159, offset 6766592),(tcid 10.10.10.4, path 159, offset 6766592),*/

#if ( SWITCH_ON == CDFS_DEBUG_SWITCH )
    if ( CDFS_MD_ID_CHECK_INVALID(cdfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdfs_import_lost_replica_from_file: cdfs module #0x%lx not started.\n",
                cdfs_md_id);
        dbg_exit(MD_CDFS, cdfs_md_id);
    }
#endif/*CDFS_DEBUG_SWITCH*/

    cdfs_md = CDFS_MD_GET(cdfs_md_id);

    lost_replica_fp = fopen((char *)cstring_get_str(file_name), "r");
    if(NULL_PTR == lost_replica_fp)
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_import_lost_replica_from_file: open lost replica log file %s failed\n",
                            (char *)cstring_get_str(file_name));
        return (EC_FALSE);
    }

    line_no = 1;

    fgets(str_line, CDFS_LOST_REPLICA_LINE_MAX_SIZE, lost_replica_fp);/*skip the first line*/
    if((char *)0 == strcasestr(str_line, "my pid ="))
    {
        dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_import_lost_replica_from_file: replica log file %s has invalid first line %s\n",
                            (char *)cstring_get_str(file_name), (char *)str_line);
        fclose(lost_replica_fp);
        return (EC_FALSE);
    }

    line_no ++;

    while(fgets(str_line, CDFS_LOST_REPLICA_LINE_MAX_SIZE, lost_replica_fp))
    {
        CDFSNP_FNODE    cdfsnp_fnode;
        CBYTES      *cbytes;

        char  *fields[32];
        UINT32 field_num;
        UINT32 field_pos;

        UINT32 expect_replica_num;
        UINT32 replica_pos;
        UINT32 cdfsnp_inode_pos;

        EC_BOOL ret;

        CSTRING *path;

        dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "%s", str_line);
        field_num = c_str_split(str_line, " ,()\t\r\n", fields, sizeof(fields)/sizeof(fields[ 0 ]));

        if(8 > field_num)
        {
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import replica error] line # %ld\n", line_no ++);
            continue;/*skip invalid line*/
        }

        /*file path*/
        path = cstring_new((UINT8 *)(fields[ 3 ]), LOC_CDFS_0071);

        /*expect replica num*/
        expect_replica_num = c_str_to_word(fields[ 5 ]);

        /*file size*/
        CDFSNP_FNODE_FILESZ(&cdfsnp_fnode) = c_str_to_word(fields[ 7 ]);

        /*replica num*/
        CDFSNP_FNODE_REPNUM(&cdfsnp_fnode) = c_str_to_word(fields[ 9 ]);

        for(field_pos = 11, replica_pos = 0;
            field_pos + 4 < field_num && replica_pos < CDFSNP_FNODE_REPNUM(&cdfsnp_fnode);
            field_pos += 6, replica_pos ++)
        {
            CDFSNP_FNODE_INODE_TCID(&cdfsnp_fnode, replica_pos) = c_ipv4_to_word(fields[ field_pos + 0]);
            CDFSNP_FNODE_INODE_PATH(&cdfsnp_fnode, replica_pos) =  c_str_to_word(fields[ field_pos + 2 ]);
            CDFSNP_FNODE_INODE_FOFF(&cdfsnp_fnode, replica_pos) =  c_str_to_word(fields[ field_pos + 4 ]);
        }

        //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] path: %s, expect: %ld\n", (char *)cstring_get_str(path), expect_replica_num);
        //cdfsnp_fnode_print(LOGSTDOUT, &cdfsnp_fnode);

        cbytes = cbytes_new(0);
        if(EC_FALSE == cdfs_read_dn_p(cdfs_md_id, &cdfsnp_fnode, cbytes))
        {
            dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_import_lost_replica_from_file: read dn failed\n");
            dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import replica fail] line # %ld\n", line_no ++);

            cbytes_free(cbytes);
            continue;
        }

        cdfsnp_inode_pos = CDFSNP_FNODE_REPNUM(&cdfsnp_fnode);
        CDFSNP_FNODE_REPNUM(&cdfsnp_fnode) = expect_replica_num;/*modify replica num in fnode*/

        if(1)
        {
            CVECTOR  *cdfsdn_excl_tcid_vec;
            MOD_MGR  *mod_mgr;
            TASK_MGR *task_mgr;

            CDFSDN_STAT    remote_cdfsdn_stat;

            cdfsdn_excl_tcid_vec = cvector_new(0, MM_UINT32, LOC_CDFS_0072);

            cdfs_collect_fnode_all_tcid(&cdfsnp_fnode, cdfsnp_inode_pos, cdfsdn_excl_tcid_vec);
            cdfs_collect_dn_mod_mgr_disable_tcid(CDFS_MD_DN_MOD_MGR(cdfs_md), cdfsdn_excl_tcid_vec);

            mod_mgr = mod_mgr_new(cdfs_md_id, LOAD_BALANCING_QUE);
            mod_mgr_limited_clone_with_tcid_excl_filter(cdfs_md_id, CDFS_MD_DN_MOD_MGR(cdfs_md), cdfsdn_excl_tcid_vec, mod_mgr);
            cvector_free(cdfsdn_excl_tcid_vec, LOC_CDFS_0073);

            //dbg_log(SEC_0056_CDFS, 9)(LOGSTDOUT, "[DEBUG] cdfs_import_lost_replica_from_file: [1] mod mgr:\n");
            //mod_mgr_print(LOGSTDOUT, mod_mgr);

            if(0 == MOD_MGR_REMOTE_NUM(mod_mgr))
            {
                dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import replica fail] line # %ld\n", line_no ++);
                mod_mgr_free(mod_mgr);
                cbytes_free(cbytes);

                continue;
            }

            cdfsdn_stat_init(&remote_cdfsdn_stat);
            ret = EC_FALSE;

            task_mgr = task_new(mod_mgr, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
            task_inc(task_mgr, &ret, FI_cdfs_write_dn_ppl, CMPI_ERROR_MODI, cbytes, cdfsnp_inode_pos, &cdfsnp_fnode, &remote_cdfsdn_stat);
            task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NEED_RESCHEDULE_FLAG, NULL_PTR);

            mod_mgr_free(mod_mgr);
            cbytes_free(cbytes);

            if(CDFSDN_STAT_IS_FULL == CDFSDN_STAT_FULL(&remote_cdfsdn_stat))
            {
                cdfs_disable_write_access_dn(cdfs_md_id, CDFSDN_STAT_TCID(&remote_cdfsdn_stat));
            }

            if(EC_TRUE == ret)
            {
                dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import replica succ] line # %ld\n", line_no ++);

                /*when dn replica meet requirement, update np*/
                /*note: due to only update, we have to import lost fnode at first if have before import lost replica*/
                if(EC_FALSE == cdfs_update_npp_p(cdfs_md_id, path, &cdfsnp_fnode))
                {
                    dbg_log(SEC_0056_CDFS, 0)(LOGSTDOUT, "error:cdfs_import_lost_replica_from_file: update file %s replica failed\n", (char *)cstring_get_str(path));
                }
            }
            else
            {
                dbg_log(SEC_0056_CDFS, 5)(LOGSTDOUT, "[import replica fail] line # %ld\n", line_no ++);
            }
        }
    }

    fclose(lost_replica_fp);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
