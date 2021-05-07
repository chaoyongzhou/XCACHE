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

#include "cbc.h"
#include "ctimer.h"
#include "cmisc.h"

#include "task.h"

#include "cxfs.h"
#include "cxfsc.h"

#include "findex.inc"

#define CXFSC_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFSC))

#define CXFSC_MD_GET(cxfsc_md_id)     ((CXFSC_MD *)cbc_md_get(MD_CXFSC, (cxfsc_md_id)))

#define CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id)  \
    ((CMPI_ANY_MODI != (cxfsc_md_id)) && ((NULL_PTR == CXFSC_MD_GET(cxfsc_md_id)) || (0 == (CXFSC_MD_GET(cxfsc_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CXFSC Module
*
**/
void cxfsc_print_module_status(const UINT32 cxfsc_md_id, LOG *log)
{
    CXFSC_MD *cxfsc_md;
    UINT32 this_cxfsc_md_id;

    for( this_cxfsc_md_id = 0; this_cxfsc_md_id < CXFSC_MD_CAPACITY(); this_cxfsc_md_id ++ )
    {
        cxfsc_md = CXFSC_MD_GET(this_cxfsc_md_id);

        if ( NULL_PTR != cxfsc_md && 0 < cxfsc_md->usedcounter )
        {
            sys_log(log,"CXFSC Module # %ld : %ld refered\n",
                    this_cxfsc_md_id,
                    cxfsc_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CXFSC module
*
*
**/
UINT32 cxfsc_free_module_static_mem(const UINT32 cxfsc_md_id)
{
#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_free_module_static_mem: cxfs module #%ld not started.\n",
                cxfsc_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    free_module_static_mem(MD_CXFSC, cxfsc_md_id);

    return 0;
}

/**
*
* start CXFSC module
*
**/
UINT32 cxfsc_start()
{
    CXFSC_MD     *cxfsc_md;
    UINT32        cxfsc_md_id;
    uint32_t      idx;

    cbc_md_reg(MD_CXFSC, 16);

    cxfsc_md_id = cbc_md_new(MD_CXFSC, sizeof(CXFSC_MD));
    if(CMPI_ERROR_MODI == cxfsc_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CXFSC module */
    cxfsc_md = (CXFSC_MD *)cbc_md_get(MD_CXFSC, cxfsc_md_id);
    cxfsc_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFSC_MD_RNODE_POS(cxfsc_md)    = 0;
    CXFSC_MD_RNODE_NUM(cxfsc_md)    = 0;
    for(idx = 0; idx < CXFSC_REPLICA_NUM; idx ++)
    {
        cxfsc_rnode_init(CXFSC_MD_RNODE(cxfsc_md, idx));
    }

    cxfsc_md->usedcounter = 1;

    /* fetch config */

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfsc_end, cxfsc_md_id);

    dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "[DEBUG] cxfsc_start: "
                                          "start CXFSC module #%ld\n",
                                          cxfsc_md_id);

    return ( cxfsc_md_id );
}

/**
*
* end CXFSC module
*
**/
void cxfsc_end(const UINT32 cxfsc_md_id)
{
    CXFSC_MD *cxfsc_md;
    uint32_t  idx;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cxfsc_end, cxfsc_md_id);

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);
    if(NULL_PTR == cxfsc_md)
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_end: "
                                              "cxfsc_md_id = %ld not exist.\n",
                                              cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cxfsc_md->usedcounter )
    {
        cxfsc_md->usedcounter --;
        return ;
    }

    if ( 0 == cxfsc_md->usedcounter )
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_end: "
                                              "cxfsc_md_id = %ld is not started.\n",
                                              cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }

    /* free module : */
    //cxfsc_free_module_static_mem(cxfsc_md_id);

    for(idx = 0; idx < CXFSC_REPLICA_NUM; idx ++)
    {
        cxfsc_rnode_clean(CXFSC_MD_RNODE(cxfsc_md, idx));
    }

    CXFSC_MD_RNODE_POS(cxfsc_md)    = 0;
    CXFSC_MD_RNODE_NUM(cxfsc_md)    = 0;

    cxfsc_md->usedcounter = 0;

    cbc_md_free(MD_CXFSC, cxfsc_md_id);

    dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "[DEBUG] cxfsc_end: "
                                          "stop CXFSC module #%ld\n",
                                          cxfsc_md_id);

    return ;
}

CXFSC_RNODE *cxfsc_rnode_new()
{
    CXFSC_RNODE *cxfsc_rnode;

    alloc_static_mem(MM_CXFSC_RNODE, &cxfsc_rnode, LOC_CXFSC_0001);
    if(NULL_PTR == cxfsc_rnode)
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_rnode_new: "
                                              "new cxfsc_rnode failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsc_rnode_init(cxfsc_rnode))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_rnode_new: "
                                              "init cxfsc_rnode failed\n");
        free_static_mem(MM_CXFSC_RNODE, cxfsc_rnode, LOC_CXFSC_0002);
        return (NULL_PTR);
    }

    return (cxfsc_rnode);
}

EC_BOOL cxfsc_rnode_init(CXFSC_RNODE *cxfsc_rnode)
{
    if(NULL_PTR != cxfsc_rnode)
    {
        CXFSC_RNODE_CXFS_TCID(cxfsc_rnode)             = CMPI_ERROR_TCID;
        CXFSC_RNODE_CXFS_MODI(cxfsc_rnode)             = CMPI_ERROR_MODI;

        CXFSC_RNODE_EXT_RESULT(cxfsc_rnode)            = EC_FALSE;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsc_rnode_clean(CXFSC_RNODE *cxfsc_rnode)
{
    if(NULL_PTR != cxfsc_rnode)
    {
        CXFSC_RNODE_CXFS_TCID(cxfsc_rnode)             = CMPI_ERROR_TCID;
        CXFSC_RNODE_CXFS_MODI(cxfsc_rnode)             = CMPI_ERROR_MODI;

        CXFSC_RNODE_EXT_RESULT(cxfsc_rnode)            = EC_FALSE;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsc_rnode_free(CXFSC_RNODE *cxfsc_rnode)
{
    if(NULL_PTR != cxfsc_rnode)
    {
        cxfsc_rnode_clean(cxfsc_rnode);
        free_static_mem(MM_CXFSC_RNODE, cxfsc_rnode, LOC_CXFSC_0003);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsc_rnode_clone(const CXFSC_RNODE *cxfsc_rnode_src, CXFSC_RNODE *cxfsc_rnode_des)
{
    if(NULL_PTR != cxfsc_rnode_src
    && NULL_PTR != cxfsc_rnode_des)
    {
        CXFSC_RNODE_CXFS_TCID(cxfsc_rnode_des)   = CXFSC_RNODE_CXFS_TCID(cxfsc_rnode_src);
        CXFSC_RNODE_CXFS_MODI(cxfsc_rnode_des)   = CXFSC_RNODE_CXFS_MODI(cxfsc_rnode_src);

        CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_des)  = CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_src);

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

CXFSC_RNODE *cxfsc_rnode_dup(const CXFSC_RNODE *cxfsc_rnode)
{
    if(NULL_PTR != cxfsc_rnode)
    {
        CXFSC_RNODE *cxfsc_rnode_t;

        cxfsc_rnode_t = cxfsc_rnode_new();
        if(NULL_PTR == cxfsc_rnode_t)
        {
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_rnode_dup: "
                                                  "new cxfsc_rnode failed\n");

            return (NULL_PTR);
        }

        cxfsc_rnode_clone(cxfsc_rnode, cxfsc_rnode_t);
        return (cxfsc_rnode_t);
    }

    return (NULL_PTR);
}

void cxfsc_rnode_print(LOG *log, const CXFSC_RNODE *cxfsc_rnode)
{
    if(NULL_PTR != cxfsc_rnode)
    {
        sys_log(log, "cxfsc_rnode_print: "
                     "cxfsc_rnode %p, tcid %s, modi %ld\n",
                     cxfsc_rnode,
                     c_word_to_ipv4(CXFSC_RNODE_CXFS_TCID(cxfsc_rnode)),
                     CXFSC_RNODE_CXFS_MODI(cxfsc_rnode));
    }
    return;
}

EC_BOOL cxfsc_rnode_is_active(const CXFSC_RNODE *cxfsc_rnode)
{
    return super_check_tcid_connected(0, CXFSC_RNODE_CXFS_TCID(cxfsc_rnode));
}

EC_BOOL cxfsc_reg_xfs(const UINT32 cxfsc_md_id)
{
    TASK_BRD                *task_brd;

    const char              *cluster_name;
    CLUSTER_CFG             *cluster_cfg;           /*cluster xfs-nbd*/
    CLUSTER_NODE_CFG        *cluster_node_cfg_xfsc; /*xfsc node in cluster xfs-nbd*/
    CVECTOR                 *cluster_nodes;

    const char              *role_str_nbd;
    UINT32                   pos;
    UINT32                   num;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_reg_xfs: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    task_brd = task_brd_default_get();

    cluster_name = (const char *)"nbd-xfs:xfs-nbd";

    cluster_cfg = sys_cfg_get_cluster_cfg_by_name_str(TASK_BRD_SYS_CFG(task_brd), cluster_name);
    if(NULL_PTR == cluster_cfg)
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "warn:cxfsc_reg_xfs: no cluster %s\n", cluster_name);
        return (EC_FALSE);
    }

    cluster_node_cfg_xfsc = cluster_cfg_search_by_tcid_rank(cluster_cfg, TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
    if(NULL_PTR == cluster_node_cfg_xfsc)
    {
        dbg_log(SEC_0199_CXFSC, 1)(LOGSTDOUT, "warn:cxfsc_reg_xfs: "
                           "current tcid %s rank %ld not belong to cluster %ld\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), CLUSTER_CFG_ID(cluster_cfg));
        return (EC_FALSE);
    }

    /*determine nbd role*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg_xfsc, (const char *)"master"))
    {
        role_str_nbd = (const char *)"slave";
    }
    else
    {
        role_str_nbd = (const char *)"master";
    }

    num = 0;

    cluster_nodes = (CVECTOR *)CLUSTER_CFG_NODES(cluster_cfg);
    for(pos = 0; pos < cvector_size(cluster_nodes); pos ++)
    {
        CLUSTER_NODE_CFG *cluster_node_cfg;
        cluster_node_cfg = (CLUSTER_NODE_CFG *)cvector_get(cluster_nodes, pos);
        if(NULL_PTR == cluster_node_cfg)
        {
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_role_str(cluster_node_cfg, role_str_nbd))
        {
            dbg_log(SEC_0199_CXFSC, 5)(LOGSTDOUT, "[DEBUG] cxfsc_reg_xfs: "
                                                  "cfg %s, %s != %s => skip\n",
                                                  CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                                                  CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg),
                                                  role_str_nbd);
            continue;
        }

        if(EC_TRUE == cxfsc_has_rnode(cxfsc_md_id, CLUSTER_NODE_CFG_TCID(cluster_node_cfg), 0/*modi*/))
        {
            dbg_log(SEC_0199_CXFSC, 5)(LOGSTDOUT, "[DEBUG] cxfsc_reg_xfs: "
                                                  "cfg %s, %s exists => skip\n",
                                                  CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                                                  CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg));
            continue;
        }

        if(EC_FALSE == super_check_tcid_connected(0, CLUSTER_NODE_CFG_TCID(cluster_node_cfg)))
        {
            dbg_log(SEC_0199_CXFSC, 5)(LOGSTDOUT, "[DEBUG] cxfsc_reg_xfs: "
                                                  "cfg %s, %s not connected => skip\n",
                                                  CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg),
                                                  CLUSTER_NODE_CFG_ROLE_STR(cluster_node_cfg));
            continue;
        }

        if(EC_FALSE == cxfsc_reg_rnode(cxfsc_md_id, CLUSTER_NODE_CFG_TCID(cluster_node_cfg), 0/*modi*/))
        {
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_reg_xfs: "
                                                  "reg rnode %s failed\n",
                                                  CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg));
        }
        else
        {
            num ++;
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "[DEBUG] cxfsc_reg_xfs: "
                                                  "reg rnode %s done\n",
                                                  CLUSTER_NODE_CFG_TCID_STR(cluster_node_cfg));
        }
    }

    if(0 < num)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsc_has_rnode(const UINT32 cxfsc_md_id, const UINT32 tcid, const UINT32 modi)
{
    CXFSC_MD      *cxfsc_md;
    CXFSC_RNODE   *cxfsc_rnode;
    uint32_t       pos;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_has_rnode: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    for(pos = 0; pos < CXFSC_MD_RNODE_NUM(cxfsc_md); pos ++)
    {
        cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, pos);
        if(tcid == CXFSC_RNODE_CXFS_TCID(cxfsc_rnode)
        && modi == CXFSC_RNODE_CXFS_MODI(cxfsc_rnode))
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL cxfsc_reg_rnode(const UINT32 cxfsc_md_id, const UINT32 tcid, const UINT32 modi)
{
    CXFSC_MD      *cxfsc_md;
    CXFSC_RNODE   *cxfsc_rnode;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_reg_rnode: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    if(CXFSC_REPLICA_NUM <= CXFSC_MD_RNODE_NUM(cxfsc_md))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_reg_rnode: "
                                              "already full rnodes\n");

        return (EC_FALSE);
    }

    cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, CXFSC_MD_RNODE_NUM(cxfsc_md));
    cxfsc_rnode_init(cxfsc_rnode);

    CXFSC_RNODE_CXFS_TCID(cxfsc_rnode) = tcid;
    CXFSC_RNODE_CXFS_MODI(cxfsc_rnode) = modi;

    CXFSC_MD_RNODE_NUM(cxfsc_md) ++;

    dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "[DEBUG] cxfsc_reg_rnode: "
                                          "reg rnode %s done\n",
                                          CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode));
    return (EC_TRUE);
}

EC_BOOL cxfsc_file_size(const UINT32 cxfsc_md_id, const CSTRING *path_cstr, uint64_t *file_size)
{
    CXFSC_MD      *cxfsc_md;
    CXFSC_RNODE   *cxfsc_rnode;

    uint32_t       idx;
    uint32_t       pos;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_file_size: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    if(0 == CXFSC_MD_RNODE_NUM(cxfsc_md))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_file_size: "
                                              "no rnode\n");
        return (EC_FALSE);
    }

    pos = (CXFSC_MD_RNODE_POS(cxfsc_md) % CXFSC_MD_RNODE_NUM(cxfsc_md));
    for(idx = 0; idx < CXFSC_MD_RNODE_NUM(cxfsc_md); idx ++, pos = ((pos + 1) % CXFSC_MD_RNODE_NUM(cxfsc_md)))
    {
        cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, pos);
        if(EC_TRUE == cxfsc_rnode_is_active(cxfsc_rnode))
        {
            MOD_NODE         recv_mod_node;
            EC_BOOL          result;

            result = EC_FALSE;

            MOD_NODE_TCID(&recv_mod_node) = CXFSC_RNODE_CXFS_TCID(cxfsc_rnode);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
            MOD_NODE_MODI(&recv_mod_node) = CXFSC_RNODE_CXFS_MODI(cxfsc_rnode);

            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &recv_mod_node,
                     &result,
                     FI_cxfs_file_size, CMPI_ERROR_MODI, path_cstr, file_size);

            CXFSC_MD_RNODE_POS(cxfsc_md) = pos;
            return (result);
        }
    }

    CXFSC_MD_RNODE_POS(cxfsc_md) = pos;

    dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_file_size: "
                                          "no active rnode\n");

    return (EC_FALSE);
}

EC_BOOL cxfsc_is_file(const UINT32 cxfsc_md_id, const CSTRING *file_path)
{
    CXFSC_MD      *cxfsc_md;
    CXFSC_RNODE   *cxfsc_rnode;

    uint32_t       idx;
    uint32_t       pos;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_is_file: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    if(0 == CXFSC_MD_RNODE_NUM(cxfsc_md))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_is_file: "
                                              "no rnode\n");
        return (EC_FALSE);
    }

    pos = (CXFSC_MD_RNODE_POS(cxfsc_md) % CXFSC_MD_RNODE_NUM(cxfsc_md));
    for(idx = 0; idx < CXFSC_MD_RNODE_NUM(cxfsc_md); idx ++, pos = ((pos + 1) % CXFSC_MD_RNODE_NUM(cxfsc_md)))
    {
        cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, pos);
        if(EC_TRUE == cxfsc_rnode_is_active(cxfsc_rnode))
        {
            MOD_NODE         recv_mod_node;
            EC_BOOL          result;

            result = EC_FALSE;

            MOD_NODE_TCID(&recv_mod_node) = CXFSC_RNODE_CXFS_TCID(cxfsc_rnode);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
            MOD_NODE_MODI(&recv_mod_node) = CXFSC_RNODE_CXFS_MODI(cxfsc_rnode);

            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &recv_mod_node,
                     &result,
                     FI_cxfs_is_file, CMPI_ERROR_MODI, file_path);

            CXFSC_MD_RNODE_POS(cxfsc_md) = pos;
            return (result);
        }
    }

    CXFSC_MD_RNODE_POS(cxfsc_md) = pos;

    dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_is_file: "
                                          "no active rnode\n");

    return (EC_FALSE);
}

EC_BOOL cxfsc_delete_file(const UINT32 cxfsc_md_id, const CSTRING *path)
{
    CXFSC_MD      *cxfsc_md;
    TASK_MGR      *task_mgr;
    CLIST         *cxfsc_rnode_list;
    CXFSC_RNODE   *cxfsc_rnode;
    EC_BOOL        result;

    uint32_t       idx;
    uint32_t       pos;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_delete_file: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    if(0 == CXFSC_MD_RNODE_NUM(cxfsc_md))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_delete_file: "
                                              "no rnode\n");
        return (EC_FALSE);
    }

    cxfsc_rnode_list = clist_new(MM_CXFSC_RNODE, LOC_CXFSC_0004);
    if(NULL_PTR == cxfsc_rnode_list)
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_delete_file: "
                                              "new cxfsc_rnode_list failed\n");
        return (EC_FALSE);
    }

    pos = (CXFSC_MD_RNODE_POS(cxfsc_md) % CXFSC_MD_RNODE_NUM(cxfsc_md));
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(idx = 0; idx < CXFSC_MD_RNODE_NUM(cxfsc_md); idx ++, pos = ((pos + 1) % CXFSC_MD_RNODE_NUM(cxfsc_md)))
    {
        cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, pos);
        if(EC_TRUE == cxfsc_rnode_is_active(cxfsc_rnode))
        {
            CXFSC_RNODE     *cxfsc_rnode_t;
            MOD_NODE         recv_mod_node;

            cxfsc_rnode_t = cxfsc_rnode_dup(cxfsc_rnode);
            if(NULL_PTR == cxfsc_rnode_t)
            {
                dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_delete_file: "
                                                      "dup rnode failed\n");
                continue;
            }

            clist_push_back(cxfsc_rnode_list, (void *)cxfsc_rnode_t);

            CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_t) = EC_FALSE;

            MOD_NODE_TCID(&recv_mod_node) = CXFSC_RNODE_CXFS_TCID(cxfsc_rnode_t);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
            MOD_NODE_MODI(&recv_mod_node) = CXFSC_RNODE_CXFS_MODI(cxfsc_rnode_t);

            task_p2p_inc(task_mgr, cxfsc_md_id,
                         &recv_mod_node,
                         &CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_t),
                         FI_cxfs_delete_file, CMPI_ERROR_MODI, path);

            CXFSC_MD_RNODE_POS(cxfsc_md) = pos;
        }
        else
        {
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_delete_file: "
                                                  "inactive tcid %s, modi %ld, path %s\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(path));
        }
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    if(EC_TRUE == clist_is_empty(cxfsc_rnode_list))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_delete_file: "
                                              "no active rnode\n");

        clist_free(cxfsc_rnode_list, LOC_CXFSC_0005);

        return (EC_FALSE);
    }

    result = EC_TRUE;
    while(NULL_PTR != (cxfsc_rnode = clist_pop_front(cxfsc_rnode_list)))
    {
        if(EC_FALSE == CXFSC_RNODE_EXT_RESULT(cxfsc_rnode))
        {
            result = EC_FALSE;
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_delete_file: "
                                                  "fail tcid %s, modi %ld, path %s\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(path));
        }
        else
        {
            dbg_log(SEC_0199_CXFSC, 5)(LOGSTDOUT, "[DEBUG] cxfsc_delete_file: "
                                                  "succ tcid %s, modi %ld, path %s\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(path));
        }

        cxfsc_rnode_free(cxfsc_rnode);
    }

    clist_free(cxfsc_rnode_list, LOC_CXFSC_0006);

    return (result);
}

EC_BOOL cxfsc_truncate_file(const UINT32 cxfsc_md_id, const CSTRING *file_path, const UINT32 file_size)
{
    CXFSC_MD      *cxfsc_md;
    TASK_MGR      *task_mgr;
    CLIST         *cxfsc_rnode_list;
    CXFSC_RNODE   *cxfsc_rnode;
    EC_BOOL        result;

    uint32_t       idx;
    uint32_t       pos;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_truncate_file: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    if(0 == CXFSC_MD_RNODE_NUM(cxfsc_md))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_truncate_file: "
                                              "no rnode\n");
        return (EC_FALSE);
    }

    cxfsc_rnode_list = clist_new(MM_CXFSC_RNODE, LOC_CXFSC_0007);
    if(NULL_PTR == cxfsc_rnode_list)
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_truncate_file: "
                                              "new cxfsc_rnode_list failed\n");
        return (EC_FALSE);
    }

    pos = (CXFSC_MD_RNODE_POS(cxfsc_md) % CXFSC_MD_RNODE_NUM(cxfsc_md));
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(idx = 0; idx < CXFSC_MD_RNODE_NUM(cxfsc_md); idx ++, pos = ((pos + 1) % CXFSC_MD_RNODE_NUM(cxfsc_md)))
    {
        cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, pos);
        if(EC_TRUE == cxfsc_rnode_is_active(cxfsc_rnode))
        {
            CXFSC_RNODE     *cxfsc_rnode_t;
            MOD_NODE         recv_mod_node;

            cxfsc_rnode_t = cxfsc_rnode_dup(cxfsc_rnode);
            if(NULL_PTR == cxfsc_rnode_t)
            {
                dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_truncate_file: "
                                                      "dup rnode failed\n");
                continue;
            }

            clist_push_back(cxfsc_rnode_list, (void *)cxfsc_rnode_t);

            CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_t) = EC_FALSE;

            MOD_NODE_TCID(&recv_mod_node) = CXFSC_RNODE_CXFS_TCID(cxfsc_rnode_t);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
            MOD_NODE_MODI(&recv_mod_node) = CXFSC_RNODE_CXFS_MODI(cxfsc_rnode_t);

            task_p2p_inc(task_mgr, cxfsc_md_id,
                         &recv_mod_node,
                         &CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_t),
                         FI_cxfs_truncate_file, CMPI_ERROR_MODI, file_path, file_size);

            CXFSC_MD_RNODE_POS(cxfsc_md) = pos;
        }
        else
        {
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_truncate_file: "
                                                  "inactive tcid %s, modi %ld, path %s\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(file_path));
        }
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    if(EC_TRUE == clist_is_empty(cxfsc_rnode_list))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_truncate_file: "
                                              "no active rnode\n");

        clist_free(cxfsc_rnode_list, LOC_CXFSC_0008);

        return (EC_FALSE);
    }

    result = EC_TRUE;
    while(NULL_PTR != (cxfsc_rnode = clist_pop_front(cxfsc_rnode_list)))
    {
        if(EC_FALSE == CXFSC_RNODE_EXT_RESULT(cxfsc_rnode))
        {
            result = EC_FALSE;
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_truncate_file: "
                                                  "tcid %s, modi %ld, path %s, size %ld => fail\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(file_path), file_size);
        }
        else
        {
            dbg_log(SEC_0199_CXFSC, 5)(LOGSTDOUT, "[DEBUG] cxfsc_truncate_file: "
                                                  "tcid %s, modi %ld, path %s, size %ld => succ\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(file_path), file_size);
        }

        cxfsc_rnode_free(cxfsc_rnode);
    }

    clist_free(cxfsc_rnode_list, LOC_CXFSC_0009);

    return (result);
}

EC_BOOL cxfsc_read_e(const UINT32 cxfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CXFSC_MD      *cxfsc_md;
    CXFSC_RNODE   *cxfsc_rnode;

    uint32_t       idx;
    uint32_t       pos;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_read_e: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    if(0 == CXFSC_MD_RNODE_NUM(cxfsc_md))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_read_e: "
                                              "no rnode\n");
        return (EC_FALSE);
    }

    pos = (CXFSC_MD_RNODE_POS(cxfsc_md) % CXFSC_MD_RNODE_NUM(cxfsc_md));
    for(idx = 0; idx < CXFSC_MD_RNODE_NUM(cxfsc_md); idx ++, pos = ((pos + 1) % CXFSC_MD_RNODE_NUM(cxfsc_md)))
    {
        cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, pos);
        if(EC_TRUE == cxfsc_rnode_is_active(cxfsc_rnode))
        {
            MOD_NODE         recv_mod_node;
            EC_BOOL          result;

            result = EC_FALSE;

            MOD_NODE_TCID(&recv_mod_node) = CXFSC_RNODE_CXFS_TCID(cxfsc_rnode);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
            MOD_NODE_MODI(&recv_mod_node) = CXFSC_RNODE_CXFS_MODI(cxfsc_rnode);

            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &recv_mod_node,
                     &result,
                     FI_cxfs_read_e, CMPI_ERROR_MODI, file_path, offset, max_len, cbytes);

            CXFSC_MD_RNODE_POS(cxfsc_md) = pos;
            return (result);
        }
    }

    CXFSC_MD_RNODE_POS(cxfsc_md) = pos;

    dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_read_e: "
                                          "no active rnode\n");

    return (EC_FALSE);
}

EC_BOOL cxfsc_write_e(const UINT32 cxfsc_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CXFSC_MD      *cxfsc_md;
    TASK_MGR      *task_mgr;
    CLIST         *cxfsc_rnode_list;
    CXFSC_RNODE   *cxfsc_rnode;
    EC_BOOL        result;

    UINT32         offset_s;
    UINT32         offset_e;

    uint32_t       idx;
    uint32_t       pos;

#if (SWITCH_ON == CXFSC_DEBUG_SWITCH)
    if ( CXFSC_MD_ID_CHECK_INVALID(cxfsc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsc_write_e: cxfsc module #%ld not started.\n",
                cxfsc_md_id);
        dbg_exit(MD_CXFSC, cxfsc_md_id);
    }
#endif/*(SWITCH_ON == CXFSC_DEBUG_SWITCH)*/

    cxfsc_md = CXFSC_MD_GET(cxfsc_md_id);

    if(0 == CXFSC_MD_RNODE_NUM(cxfsc_md))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_write_e: "
                                              "no rnode\n");
        return (EC_FALSE);
    }

    cxfsc_rnode_list = clist_new(MM_CXFSC_RNODE, LOC_CXFSC_0010);
    if(NULL_PTR == cxfsc_rnode_list)
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_write_e: "
                                              "new cxfsc_rnode_list failed\n");
        return (EC_FALSE);
    }

    offset_s = (*offset);
    offset_e = (*offset) + max_len;

    pos = (CXFSC_MD_RNODE_POS(cxfsc_md) % CXFSC_MD_RNODE_NUM(cxfsc_md));

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(idx = 0; idx < CXFSC_MD_RNODE_NUM(cxfsc_md); idx ++, pos = ((pos + 1) % CXFSC_MD_RNODE_NUM(cxfsc_md)))
    {
        cxfsc_rnode = CXFSC_MD_RNODE(cxfsc_md, pos);
        if(EC_TRUE == cxfsc_rnode_is_active(cxfsc_rnode))
        {
            CXFSC_RNODE     *cxfsc_rnode_t;
            MOD_NODE         recv_mod_node;

            cxfsc_rnode_t = cxfsc_rnode_dup(cxfsc_rnode);
            if(NULL_PTR == cxfsc_rnode_t)
            {
                dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_write_e: "
                                                      "dup rnode failed\n");
                continue;
            }

            clist_push_back(cxfsc_rnode_list, (void *)cxfsc_rnode_t);

            CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_t) = EC_FALSE;

            MOD_NODE_TCID(&recv_mod_node) = CXFSC_RNODE_CXFS_TCID(cxfsc_rnode_t);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
            MOD_NODE_MODI(&recv_mod_node) = CXFSC_RNODE_CXFS_MODI(cxfsc_rnode_t);

            task_p2p_inc(task_mgr, cxfsc_md_id,
                         &recv_mod_node,
                         &CXFSC_RNODE_EXT_RESULT(cxfsc_rnode_t),
                         FI_cxfs_write_e, CMPI_ERROR_MODI, file_path, offset, max_len, cbytes);

            CXFSC_MD_RNODE_POS(cxfsc_md) = pos;
        }
        else
        {
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_write_e: "
                                                  "inactive tcid %s, modi %ld, path %s, range [%ld, %ld)\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(file_path),
                                                  offset_s, offset_e);
        }
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    if(EC_TRUE == clist_is_empty(cxfsc_rnode_list))
    {
        dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_write_e: "
                                              "no active rnode\n");

        clist_free(cxfsc_rnode_list, LOC_CXFSC_0011);

        return (EC_FALSE);
    }

    result = EC_TRUE;
    while(NULL_PTR != (cxfsc_rnode = clist_pop_front(cxfsc_rnode_list)))
    {
        if(EC_FALSE == CXFSC_RNODE_EXT_RESULT(cxfsc_rnode))
        {
            result = EC_FALSE;
            dbg_log(SEC_0199_CXFSC, 0)(LOGSTDOUT, "error:cxfsc_write_e: "
                                                  "tcid %s, modi %ld, path %s, range [%ld, %ld) => fail\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(file_path),
                                                  offset_s, offset_e);
        }
        else
        {
            dbg_log(SEC_0199_CXFSC, 5)(LOGSTDOUT, "[DEBUG] cxfsc_write_e: "
                                                  "tcid %s, modi %ld, path %s, range [%ld, %ld) => succ\n",
                                                  CXFSC_RNODE_CXFS_TCID_STR(cxfsc_rnode),
                                                  CXFSC_RNODE_CXFS_MODI(cxfsc_rnode),
                                                  (char *)cstring_get_str(file_path),
                                                  offset_s, offset_e);
        }
        cxfsc_rnode_free(cxfsc_rnode);
    }

    clist_free(cxfsc_rnode_list, LOC_CXFSC_0012);

    return (result);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

