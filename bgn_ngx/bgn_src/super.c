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
#include <stdarg.h>

#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "type.h"

#include "mm.h"
#include "log.h"
#include "debug.h"
#include "cmutex.h"

#include "clist.h"
#include "cvector.h"
#include "cstring.h"

#include "cbc.h"

#include "rank.h"

#include "task.inc"
#include "task.h"
#include "taskcfg.h"
#include "tasks.h"

#include "cparacfg.h"

#include "cmpie.h"
#include "tcnode.h"
#include "super.h"
#include "cproc.h"
#include "cmisc.h"
#include "cload.h"
#include "cbtimer.h"
#include "chttp.h"
#include "crfshttp.h"
#include "cxfshttp.h"
#include "chttps.h"
#include "crfshttps.h"
#include "cxfshttps.h"
#include "cdns.h"
#include "cdnscache.h"
#include "findex.inc"

#if (SWITCH_ON == NGX_BGN_SWITCH)
#include "cngx_mod.h"
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#define SUPER_MD_CAPACITY()          (cbc_md_capacity(MD_SUPER))

#define SUPER_MD_GET(super_md_id)     ((SUPER_MD *)cbc_md_get(MD_SUPER, (super_md_id)))

#define SUPER_MD_ID_CHECK_INVALID(super_md_id)  \
    ((CMPI_ANY_MODI != (super_md_id)) && ((NULL_PTR == SUPER_MD_GET(super_md_id)) || (0 == (SUPER_MD_GET(super_md_id)->usedcounter))))



STATIC_CAST static EC_BOOL __super_fnode_clean(SUPER_FNODE *super_fnode);

STATIC_CAST static EC_BOOL __super_fnode_free(SUPER_FNODE *super_fnode);

STATIC_CAST static EC_BOOL __super_fnode_match_fname(const SUPER_FNODE *super_fnode, const CSTRING *fname);

STATIC_CAST static int __super_make_open_flags(const UINT32 open_flags);

/**
*   for test only
*
*   to query the status of SUPER Module
*
**/
void super_print_module_status(const UINT32 super_md_id, LOG *log)
{
    SUPER_MD *super_md;
    UINT32 this_super_md_id;

    for( this_super_md_id = 0; this_super_md_id < SUPER_MD_CAPACITY(); this_super_md_id ++ )
    {
        super_md = SUPER_MD_GET(this_super_md_id);

        if ( NULL_PTR != super_md && 0 < super_md->usedcounter )
        {
            sys_log(log,"SUPER Module # %ld : %ld refered\n",
                    this_super_md_id,
                    super_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed SUPER module
*
*
**/
UINT32 super_free_module_static_mem(const UINT32 super_md_id)
{
    //SUPER_MD  *super_md;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_free_module_static_mem: super module #0x%lx not started.\n",
                super_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //super_md = SUPER_MD_GET(super_md_id);

    free_module_static_mem(MD_SUPER, super_md_id);

    return 0;
}

/**
*
* start super module
*
**/
UINT32 super_start()
{
    SUPER_MD *super_md;
    UINT32 super_md_id;

    super_md_id = cbc_md_new(MD_SUPER, sizeof(SUPER_MD));
    if(CMPI_ERROR_MODI == super_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one SUPER module */
    super_md = SUPER_MD_GET(super_md_id);
    super_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    clist_init(SUPER_MD_FNODE_LIST(super_md), MM_IGNORE, LOC_SUPER_0001);
    SUPER_MD_OBJ_ZONE(super_md) = NULL_PTR;
    SUPER_MD_OBJ_ZONE_SIZE(super_md) = 0;

    /*initialize SUPER_CCOND RB TREE*/
    crb_tree_init(SUPER_MD_COND_LOCKS(super_md),
                    (CRB_DATA_CMP)super_ccond_cmp,
                    (CRB_DATA_FREE)super_ccond_free_0,
                    (CRB_DATA_PRINT)super_ccond_print);

    super_md->usedcounter ++;

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_start: start SUPER module #%ld\n", super_md_id);

    return ( super_md_id );
}

/**
*
* end super module
*
**/
void super_end(const UINT32 super_md_id)
{
    SUPER_MD *super_md;

    super_md = SUPER_MD_GET(super_md_id);
    if(NULL_PTR == super_md)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT,"error:super_end: super_md_id = %ld not exist.\n", super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < super_md->usedcounter )
    {
        super_md->usedcounter --;
        return ;
    }

    if ( 0 == super_md->usedcounter )
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT,"error:super_end: super_md_id = %ld is not started.\n", super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }

    /* if nobody else occupied the module,then free its resource */
    clist_clean(SUPER_MD_FNODE_LIST(super_md), (CVECTOR_DATA_CLEANER)__super_fnode_free);
    if(NULL_PTR != SUPER_MD_OBJ_ZONE(super_md))
    {
        EC_BOOL ret;
        cvector_loop(SUPER_MD_OBJ_ZONE(super_md),
                    (void *)&ret,
                    CVECTOR_CHECKER_DEFAULT,
                    2,
                    0,
                    (UINT32)cvector_free,
                    NULL_PTR,
                    LOC_SUPER_0002);
        cvector_free(SUPER_MD_OBJ_ZONE(super_md), LOC_SUPER_0003);
        SUPER_MD_OBJ_ZONE(super_md) = NULL_PTR;
    }
    SUPER_MD_OBJ_ZONE_SIZE(super_md) = 0;

    crb_tree_clean(SUPER_MD_COND_LOCKS(super_md));

    /* free module : */
    //super_free_module_static_mem(super_md_id);
    super_md->usedcounter = 0;

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_end: stop SUPER module #%ld\n", super_md_id);
    cbc_md_free(MD_SUPER, super_md_id);

    breathing_static_mem();

    return ;
}

SUPER_CCOND *super_ccond_new(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key, const UINT32 timeout_msec)
{
    SUPER_CCOND *super_ccond;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ccond_new: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    alloc_static_mem(MM_SUPER_CCOND, &super_ccond, LOC_SUPER_0004);
    if(NULL_PTR != super_ccond)
    {
        super_ccond_init(super_md_id, super_ccond, tag, key, timeout_msec);
    }
    return (super_ccond);
}

EC_BOOL super_ccond_init(const UINT32 super_md_id, SUPER_CCOND *super_ccond, const UINT32 tag, const CSTRING *key, const UINT32 timeout_msec)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ccond_init: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    SUPER_CCOND_TAG(super_ccond) = tag;
    cstring_init(SUPER_CCOND_KEY(super_ccond), CSTRING_STR(key));
    croutine_cond_init(SUPER_CCOND_COND(super_ccond), timeout_msec, LOC_SUPER_0005);

    return (EC_TRUE);
}

EC_BOOL super_ccond_clean(const UINT32 super_md_id, SUPER_CCOND *super_ccond)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ccond_clean: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    SUPER_CCOND_TAG(super_ccond) = SUPER_CCOND_TAG_ERR;
    cstring_clean(SUPER_CCOND_KEY(super_ccond));
    croutine_cond_clean(SUPER_CCOND_COND(super_ccond), LOC_SUPER_0006);

    return (EC_TRUE);
}

EC_BOOL super_ccond_free(const UINT32 super_md_id, SUPER_CCOND *super_ccond)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ccond_free: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(NULL_PTR != super_ccond)
    {
        super_ccond_clean(super_md_id, super_ccond);
        free_static_mem(MM_SUPER_CCOND, super_ccond, LOC_SUPER_0007);
    }
    return (EC_TRUE);
}

EC_BOOL super_ccond_free_0(SUPER_CCOND *super_ccond)
{
    if(NULL_PTR != super_ccond)
    {
        super_ccond_clean(CMPI_ANY_MODI, super_ccond);
        free_static_mem(MM_SUPER_CCOND, super_ccond, LOC_SUPER_0008);
    }
    return (EC_TRUE);
}

void super_ccond_print(LOG *log, const SUPER_CCOND *super_ccond)
{
    sys_log(log, "super_ccond_print: %p: tag = %ld, key = %.*s\n", super_ccond,
                SUPER_CCOND_TAG(super_ccond),
                (uint32_t)SUPER_CCOND_KEY_LEN(super_ccond), (char *)SUPER_CCOND_KEY_STR(super_ccond));
    return;
}

int super_ccond_cmp(const SUPER_CCOND *super_ccond_1, const SUPER_CCOND *super_ccond_2)
{
    if(SUPER_CCOND_TAG(super_ccond_1) > SUPER_CCOND_TAG(super_ccond_2))
    {
        return (1);
    }

    if(SUPER_CCOND_TAG(super_ccond_1) < SUPER_CCOND_TAG(super_ccond_2))
    {
        return (-1);
    }

    return cstring_cmp(SUPER_CCOND_KEY(super_ccond_1), SUPER_CCOND_KEY(super_ccond_2));
}

SUPER_FNODE *super_fnode_new(const UINT32 super_md_id)
{
    SUPER_FNODE *super_fnode;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_fnode_new: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    alloc_static_mem(MM_SUPER_FNODE, &super_fnode, LOC_SUPER_0009);
    if(NULL_PTR != super_fnode)
    {
        super_fnode_init(super_md_id, super_fnode);
    }
    return (super_fnode);
}

EC_BOOL super_fnode_init(const UINT32 super_md_id, SUPER_FNODE *super_fnode)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_fnode_init: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    cstring_init(SUPER_FNODE_FNAME(super_fnode), NULL_PTR);
    SUPER_FNODE_FD(super_fnode) = ERR_FD;
    SUPER_FNODE_PROGRESS(super_fnode) = 0.0;
    SUPER_FNODE_CMUTEX_INIT(super_fnode, LOC_SUPER_0010);
    return (EC_TRUE);
}

EC_BOOL super_fnode_clean(const UINT32 super_md_id, SUPER_FNODE *super_fnode)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_fnode_clean: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    cstring_clean(SUPER_FNODE_FNAME(super_fnode));

    if(ERR_FD != SUPER_FNODE_FD(super_fnode))
    {
        c_file_close(SUPER_FNODE_FD(super_fnode));
        SUPER_FNODE_FD(super_fnode) = ERR_FD;
    }

    SUPER_FNODE_PROGRESS(super_fnode) = 0.0;
    SUPER_FNODE_CMUTEX_CLEAN(super_fnode, LOC_SUPER_0011);
    return (EC_TRUE);
}

EC_BOOL super_fnode_free(const UINT32 super_md_id, SUPER_FNODE *super_fnode)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_fnode_free: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(NULL_PTR != super_fnode)
    {
        super_fnode_clean(super_md_id, super_fnode);
        free_static_mem(MM_SUPER_FNODE, super_fnode, LOC_SUPER_0012);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_fnode_clean(SUPER_FNODE *super_fnode)
{
    cstring_clean(SUPER_FNODE_FNAME(super_fnode));

    if(ERR_FD != SUPER_FNODE_FD(super_fnode))
    {
        c_file_close(SUPER_FNODE_FD(super_fnode));
        SUPER_FNODE_FD(super_fnode) = ERR_FD;
    }
    SUPER_FNODE_PROGRESS(super_fnode) = 0;
    SUPER_FNODE_CMUTEX_CLEAN(super_fnode, LOC_SUPER_0013);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_fnode_free(SUPER_FNODE *super_fnode)
{
    if(NULL_PTR != super_fnode)
    {
        __super_fnode_clean(super_fnode);
        free_static_mem(MM_SUPER_FNODE, super_fnode, LOC_SUPER_0014);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_fnode_match_fname(const SUPER_FNODE *super_fnode, const CSTRING *fname)
{
    return cstring_is_equal(SUPER_FNODE_FNAME(super_fnode), fname);
}

STATIC_CAST static int __super_make_open_flags(const UINT32 open_flags)
{
    int flags;

    flags = 0;

    if(open_flags & SUPER_O_RDONLY)
    {
        flags |= O_RDONLY;
    }

    if(open_flags & SUPER_O_WRONLY)
    {
        flags |= O_WRONLY;
    }

    if(open_flags & SUPER_O_RDWR)
    {
        flags |= O_RDWR;
    }

    if(open_flags & SUPER_O_CREAT)
    {
        flags |= O_CREAT;
    }

    return flags;
}

SUPER_FNODE *super_search_fnode_by_fname_no_lock(const UINT32 super_md_id, const CSTRING *fname)
{
    SUPER_MD *super_md;
    CLIST_DATA *clist_data;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_search_fnode_by_fname_no_lock: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    clist_data = clist_search_front_no_lock(SUPER_MD_FNODE_LIST(super_md), (void *)fname, (CLIST_DATA_DATA_CMP)__super_fnode_match_fname);
    if(NULL_PTR == clist_data)
    {
        return (NULL_PTR);
    }
    return (SUPER_FNODE *)CLIST_DATA_DATA(clist_data);
}

SUPER_FNODE *super_search_fnode_by_fname(const UINT32 super_md_id, const CSTRING *fname)
{
    SUPER_MD *super_md;
    CLIST_DATA *clist_data;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_search_fnode_by_fname: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    clist_data = clist_search_front_no_lock(SUPER_MD_FNODE_LIST(super_md), (void *)fname, (CLIST_DATA_DATA_CMP)__super_fnode_match_fname);
    if(NULL_PTR == clist_data)
    {
        return (NULL_PTR);
    }
    return (SUPER_FNODE *)CLIST_DATA_DATA(clist_data);
}

SUPER_FNODE *super_open_fnode_by_fname(const UINT32 super_md_id, const CSTRING *fname, const UINT32 open_flags)
{
    SUPER_MD *super_md;
    SUPER_FNODE *super_fnode;
    int fd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_open_fnode_by_fname: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    CLIST_LOCK(SUPER_MD_FNODE_LIST(super_md), LOC_SUPER_0015);

    /*search cached*/
    super_fnode = super_search_fnode_by_fname_no_lock(super_md_id, fname);
    if(NULL_PTR != super_fnode)
    {
        CLIST_UNLOCK(SUPER_MD_FNODE_LIST(super_md), LOC_SUPER_0016);
        return (super_fnode);
    }

    /*open or create*/
    super_fnode = super_fnode_new(super_md_id);
    if(NULL_PTR == super_fnode)
    {
        CLIST_UNLOCK(SUPER_MD_FNODE_LIST(super_md), LOC_SUPER_0017);
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_open_fnode_by_fname: new super fnode failed\n");
        return (NULL_PTR);
    }

    if(open_flags & (SUPER_O_WRONLY | SUPER_O_RDWR | SUPER_O_CREAT))
    {
        if(EC_FALSE == c_basedir_create((char *)cstring_get_str(fname)))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_open_fnode_by_fname: create basedir of file %s failed\n",
                                (char *)cstring_get_str(fname));
            super_fnode_free(super_md_id, super_fnode);
            return (NULL_PTR);
        }
    }

    fd = c_file_open((char *)cstring_get_str(fname), __super_make_open_flags(open_flags), 0666);
    if(ERR_FD == fd)
    {
        CLIST_UNLOCK(SUPER_MD_FNODE_LIST(super_md), LOC_SUPER_0018);
        super_fnode_free(super_md_id, super_fnode);
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_open_fnode_by_fname: open file %s with flag %lx failed\n",
                            (char *)cstring_get_str(fname), open_flags);
        return (NULL_PTR);
    }

    cstring_clone(fname, SUPER_FNODE_FNAME(super_fnode));
    SUPER_FNODE_FD(super_fnode) = fd;

    clist_push_back_no_lock(SUPER_MD_FNODE_LIST(super_md), (void *)super_fnode);

    CLIST_UNLOCK(SUPER_MD_FNODE_LIST(super_md), LOC_SUPER_0019);

    return (super_fnode);
}

EC_BOOL super_close_fnode_by_fname(const UINT32 super_md_id, const CSTRING *fname)
{
    SUPER_MD *super_md;
    SUPER_FNODE *super_fnode;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_close_fnode_by_fname: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    super_fnode = (SUPER_FNODE *)clist_del(SUPER_MD_FNODE_LIST(super_md), (void *)fname, (CLIST_DATA_DATA_CMP)__super_fnode_match_fname);
    if(NULL_PTR == super_fnode)
    {
        return (EC_TRUE);
    }
    return super_fnode_free(super_md_id, super_fnode);
}

/**
*
* include taskc node info to SUPER module
*
**/
UINT32 super_incl_taskc_node(const UINT32 super_md_id, const UINT32 ipaddr, const UINT32 port, const int sockfd, const UINT32 taskc_id, const UINT32 taskc_comm, const UINT32 taskc_size)
{
    TASK_BRD  *task_brd;
    TASKS_CFG *tasks_cfg;

    CSOCKET_CNODE *csocket_cnode;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_incl_taskc_node: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

    if(do_log(SEC_0117_SUPER, 5))
    {
        sys_log(LOGSTDOUT, "============================== super_incl_taskc_node: before ==============================\n");
        super_show_work_client(super_md_id, LOGSTDOUT);
    }

    csocket_cnode = csocket_cnode_new(LOC_SUPER_0020);
    CSOCKET_CNODE_TCID(csocket_cnode  ) = taskc_id;
    CSOCKET_CNODE_SOCKFD(csocket_cnode) = sockfd;
    CSOCKET_CNODE_TYPE(csocket_cnode )  = CSOCKET_TYPE_TCP;
    CSOCKET_CNODE_IPADDR(csocket_cnode) = ipaddr;
    CSOCKET_CNODE_SRVPORT(csocket_cnode)= port;
    CSOCKET_CNODE_COMM(csocket_cnode)   = taskc_comm;
    CSOCKET_CNODE_SIZE(csocket_cnode)   = taskc_size;

    tasks_worker_add_csocket_cnode(TASKS_CFG_WORKER(tasks_cfg), csocket_cnode);

    if(do_log(SEC_0117_SUPER, 5))
    {
        sys_log(LOGSTDOUT, "============================== super_incl_taskc_node: after ==============================\n");
        super_show_work_client(super_md_id, LOGSTDOUT);
    }

    return (0);
}

/**
*
* exclude taskc node info to SUPER module
*
**/
UINT32 super_excl_taskc_node(const UINT32 super_md_id, const UINT32 tcid, const UINT32 comm)
{
    TASK_BRD        *task_brd;
    TASKS_CFG       *tasks_cfg;
    TASKS_WORKER    *tasks_worker;
    UINT32          pos;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_excl_taskc_node: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    tasks_cfg    = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    tasks_worker = TASKS_CFG_WORKER(tasks_cfg);

    if(do_log(SEC_0117_SUPER, 5))
    {
        sys_log(LOGSTDOUT, "============================== super_excl_taskc_node: before ==============================\n");
        //cvector_print(LOGSTDOUT, TASKS_WORK_CLIENTS(tasks_cfg), (CVECTOR_DATA_PRINT)csocket_cnode_print);
        super_show_work_client(super_md_id, LOGSTDOUT);
    }

    CVECTOR_LOCK(TASKS_WORKER_NODES(tasks_worker), LOC_SUPER_0021);
    for(pos = 0; pos < cvector_size(TASKS_WORKER_NODES(tasks_worker)); /*pos ++*/)
    {
        TASKS_NODE *tasks_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(TASKS_WORKER_NODES(tasks_worker), pos);
        if(NULL_PTR == tasks_node)
        {
            cvector_erase_no_lock(TASKS_WORKER_NODES(tasks_worker), pos);
            continue;
        }

        if((CMPI_ANY_TCID == tcid || TASKS_NODE_TCID(tasks_node) == tcid)
         &&(CMPI_ANY_COMM == comm || TASKS_NODE_COMM(tasks_node) == comm))
        {
            cvector_erase_no_lock(TASKS_WORKER_NODES(tasks_worker), pos);
            tasks_node_free(tasks_node);
            continue;
        }

        pos ++;
    }
    CVECTOR_UNLOCK(TASKS_WORKER_NODES(tasks_worker), LOC_SUPER_0022);

    if(do_log(SEC_0117_SUPER, 5))
    {
        sys_log(LOGSTDOUT, "============================== super_excl_taskc_node: after ==============================\n");
        super_show_work_client(super_md_id, LOGSTDOUT);
    }

    return (0);
}

/**
*
* sync taskc node mgr info by SUPER module
*
**/
UINT32 super_sync_taskc_mgr(const UINT32 super_md_id, TASKC_MGR *des_taskc_mgr)
{
    TASK_BRD        *task_brd;
    TASKS_CFG       *tasks_cfg;
    TASKS_WORKER    *tasks_worker;
    UINT32           tasks_node_pos;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_sync_taskc_mgr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(NULL_PTR == des_taskc_mgr)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_sync_taskc_mgr: des_taskc_mgr is null ptr\n");
        dbg_exit(MD_SUPER, super_md_id);
    }

    task_brd = task_brd_default_get();

    tasks_cfg    = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    tasks_worker = TASKS_CFG_WORKER(tasks_cfg);

    CVECTOR_LOCK(TASKS_WORKER_NODES(tasks_worker), LOC_SUPER_0023);
    for(tasks_node_pos = 0; tasks_node_pos < cvector_size(TASKS_WORKER_NODES(tasks_worker)); tasks_node_pos ++)
    {
        TASKS_NODE *tasks_node;
        TASKC_NODE *taskc_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(TASKS_WORKER_NODES(tasks_worker), tasks_node_pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_sync_taskc_mgr: tasks node: tcid %s, comm %ld, size %ld\n",
                            TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node), TASKS_NODE_SIZE(tasks_node));

        if(CMPI_ANY_COMM == TASKS_NODE_COMM(tasks_node))
        {
            continue;
        }

        taskc_node = taskc_node_new();

        TASKC_NODE_TCID(taskc_node) = TASKS_NODE_TCID(tasks_node);
        TASKC_NODE_COMM(taskc_node) = TASKS_NODE_COMM(tasks_node);
        TASKC_NODE_SIZE(taskc_node) = TASKS_NODE_SIZE(tasks_node);

        /*if duplicate, give up pushing to list*/
        if(NULL_PTR != clist_search_front(TASKC_MGR_NODE_LIST(des_taskc_mgr),
                                          (void *)taskc_node,
                                          (CLIST_DATA_DATA_CMP)taskc_node_cmp_tcid_comm))
        {
            taskc_node_free(taskc_node);
            continue;/*give up*/
        }

        clist_push_back(TASKC_MGR_NODE_LIST(des_taskc_mgr), (void *)taskc_node);
    }
    CVECTOR_UNLOCK(TASKS_WORKER_NODES(tasks_worker), LOC_SUPER_0024);

    return (0);
}

UINT32 super_sync_cload_mgr(const UINT32 super_md_id, const CVECTOR *tcid_vec, CLOAD_MGR *des_cload_mgr)
{
    TASK_BRD         *task_brd;
    TASKS_CFG        *tasks_cfg;
    TASKS_WORKER     *tasks_worker;
    UINT32            tasks_node_pos;

    TASK_MGR         *task_mgr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_sync_cload_mgr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(NULL_PTR == des_cload_mgr)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_sync_cload_mgr: des_taskc_mgr is null ptr\n");
        dbg_exit(MD_SUPER, super_md_id);
    }

    task_brd = task_brd_default_get();

    tasks_cfg    = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    tasks_worker = TASKS_CFG_WORKER(tasks_cfg);

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    CVECTOR_LOCK(TASKS_WORKER_NODES(tasks_worker), LOC_SUPER_0025);
    for(tasks_node_pos = 0; tasks_node_pos < cvector_size(TASKS_WORKER_NODES(tasks_worker)); tasks_node_pos ++)
    {
        TASKS_NODE *tasks_node;
        CLOAD_NODE *cload_node;
        MOD_NODE    recv_mod_node;

        tasks_node = (TASKS_NODE *)cvector_get_no_lock(TASKS_WORKER_NODES(tasks_worker), tasks_node_pos);
        if(NULL_PTR == tasks_node)
        {
            continue;
        }

        if(CMPI_ANY_COMM == TASKS_NODE_COMM(tasks_node))
        {
            continue;
        }

        if(CVECTOR_ERR_POS == cvector_search_front_no_lock(tcid_vec, (void *)TASKS_NODE_TCID(tasks_node), NULL_PTR))
        {
            continue;
        }

        dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_sync_cload_mgr: tasks node: tcid %s, comm %ld, size %ld\n",
                            TASKS_NODE_TCID_STR(tasks_node), TASKS_NODE_COMM(tasks_node), TASKS_NODE_SIZE(tasks_node));

        cload_node = cload_node_new(TASKS_NODE_TCID(tasks_node), TASKS_NODE_COMM(tasks_node), TASKS_NODE_SIZE(tasks_node));
        //dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_sync_cload_mgr: new cload_node is\n");
        //cload_node_print(LOGSTDOUT, cload_node);

        /*if duplicate, give up pushing to list*/
        if(NULL_PTR != clist_search_front(des_cload_mgr, (void *)cload_node, (CLIST_DATA_DATA_CMP)cload_node_cmp_tcid_comm))
        {
            cload_node_free(cload_node);
            continue;/*give up*/
        }

        MOD_NODE_TCID(&recv_mod_node) = TASKS_NODE_TCID(tasks_node);
        MOD_NODE_COMM(&recv_mod_node) = TASKS_NODE_COMM(tasks_node);
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, NULL_PTR, FI_super_sync_cload_node, CMPI_ERROR_MODI, cload_node);

        //task_brd_sync_cload_node(task_brd, cload_node);
        clist_push_back(des_cload_mgr, (void *)cload_node);
    }
    CVECTOR_UNLOCK(TASKS_WORKER_NODES(tasks_worker), LOC_SUPER_0026);

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    //dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_sync_cload_mgr: des_cload_mgr is\n");
    //cload_mgr_print(LOGSTDOUT, des_cload_mgr);

    return (0);
}

/**
*
* check taskc node connectivity by SUPER module
*
**/
EC_BOOL super_check_tcid_connected(const UINT32 super_md_id, const UINT32 tcid)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_check_tcid_connected: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(tcid == TASK_BRD_TCID(task_brd))
    {
        return (EC_TRUE);
    }

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *tasks_cfg;
        tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
        return tasks_worker_check_connected_by_tcid(TASKS_CFG_WORKER(tasks_cfg), tcid);
    }

    return (EC_FALSE);
}

/**
*
* check taskc node connectivity by SUPER module
*
**/
EC_BOOL super_check_ipaddr_connected(const UINT32 super_md_id, const UINT32 ipaddr)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_check_ipaddr_connected: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(ipaddr == TASK_BRD_IPADDR(task_brd))
    {
        return (EC_TRUE);
    }

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *tasks_cfg;
        tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
        return tasks_worker_check_connected_by_ipaddr(TASKS_CFG_WORKER(tasks_cfg), ipaddr);
    }

    return (EC_FALSE);
}


/**
*
* activate sysconfig
* import from config.xml
* note: only add new info but never delete or override the old ones
*
**/
void super_activate_sys_cfg(const UINT32 super_md_id)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_activate_sys_cfg: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_activate_sys_cfg: activate sysconfig from %s\n", (char *)task_brd_default_sys_cfg_xml());
    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_activate_sys_cfg: load sys cfg ---------------------------------------------------\n");
    sys_cfg_load(TASK_BRD_SYS_CFG(task_brd), (char *)task_brd_default_sys_cfg_xml());

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_activate_sys_cfg: setup config shortcut ------------------------------------------\n");
    /*not perfect, not must, do it better :-) Jan 25,2017*/
    if(EC_FALSE == task_brd_shortcut_config(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_activate_sys_cfg: shortcut config failed\n");
        task_brd_default_abort();
    }

    task_brd_bind_core(task_brd);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_activate_sys_cfg: import cparacfg ---------------------------------------------------\n");
    log_level_import(CPARACFG_LOG_LEVEL_TAB(TASK_BRD_CPARACFG(task_brd)), SEC_NONE_END);
    //log_level_print(LOGSTDOUT);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_activate_sys_cfg: reset routine pool size -------------------------------------------\n");
#if (SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)
    cthreadp_size_reset(TASK_REQ_CTHREAD_POOL(task_brd), TASK_REQ_THREAD_MAX_NUM);
    cthreadp_size_reset(TASK_RSP_CTHREAD_POOL(task_brd), TASK_RSP_THREAD_MAX_NUM);
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_CTHREAD_SWITCH)*/
#if (SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)
    coroutine_pool_size_reset(TASK_BRD_CROUTINE_POOL(task_brd), TASK_REQ_THREAD_MAX_NUM);
#endif/*(SWITCH_ON == CROUTINE_SUPPORT_COROUTINE_SWITCH)*/

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        task_brd_register_cluster(task_brd);
    }
    return;
}

/**
*
* show current sysconfig
*
**/
void super_show_sys_cfg(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_sys_cfg: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    sys_log(log, "sysconfig:\n");
    sys_cfg_print_xml(log, TASK_BRD_SYS_CFG(task_brd), 0);

    sys_log(log, "current paraconfig xml:\n");
    cparacfg_print_xml(log, TASK_BRD_CPARACFG(task_brd), 0);

    sys_log(log, "current paraconfig setting:\n");
    cparacfg_print(log, TASK_BRD_CPARACFG(task_brd));
    return;
}

/**
*
* print mem statistics info of current process
*
**/
void super_show_mem(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_mem: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory statistics info beg: log %lx =====================================\n", log);
    print_static_mem_status(log);
    //print_static_mem_status(LOGSTDOUT);
    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory statistics info end: =====================================\n");
    return;
}

/**
*
* print mem statistics info of current process
*
**/
void super_show_mem_of_type(const UINT32 super_md_id, const UINT32 type, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_mem_of_type: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory statistics info of type %ld beg: log %lx =====================================\n", type, log);
    print_static_mem_status_of_type(log, type);
    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory statistics info end: =====================================\n");
    return;
}


/**
*
* diagnostic mem of current process
*
**/
void super_diag_mem(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_diag_mem: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory diagnostic info beg: =====================================\n");
    print_static_mem_diag_info(log);
    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory diagnostic info end: =====================================\n");
    return;
}

void super_diag_csocket_cnode(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_diag_csocket_cnode: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory diagnostic info beg: =====================================\n");
    print_static_mem_diag_detail_of_type(log, MM_CSOCKET_CNODE, (SHOW_MEM_DETAIL)csocket_cnode_print);
    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory diagnostic info end: =====================================\n");
    return;
}

/**
*
* diagnostic mem of current process
*
**/
void super_diag_mem_of_type(const UINT32 super_md_id, const UINT32 type, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_diag_mem_of_type: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory diagnostic info beg: =====================================\n");
    print_static_mem_diag_info_of_type(log, type);
    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== memory diagnostic info end: =====================================\n");
    return;
}

/**
*
* clean mem of current process
*
**/
void super_clean_mem(const UINT32 super_md_id)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_clean_mem: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();
    task_brd_clean(task_brd);
    return;
}

/**
*
* breathe mem of current process
*
**/
void super_breathing_mem(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_breathing_mem: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    breathing_static_mem();
    return;
}

/**
*
* show log level info
*
**/
void super_show_log_level_tab(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_log_level_tab: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    log_level_print(log);
    return;
}

/**
*
* set log level
*
**/
EC_BOOL super_set_log_level_tab(const UINT32 super_md_id, const UINT32 level)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_log_level_tab: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    return log_level_set_all(level);
}

/**
*
* set log level of sector
*
**/
EC_BOOL super_set_log_level_sector(const UINT32 super_md_id, const UINT32 sector, const UINT32 level)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_log_level_sector: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    return log_level_set_sector(sector, level);
}


/**
*
* shutdown current taskComm
*
**/
void super_shutdown_taskcomm(const UINT32 super_md_id)
{
    TASK_BRD *task_brd;

    UINT32 this_tcid;
    UINT32 this_rank;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_shutdown_taskcomm: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "info: super_shutdown_taskcomm: try to shutdown ...\n");

    task_brd = task_brd_default_get();

    this_tcid = TASK_BRD_TCID(task_brd);
    this_rank = TASK_BRD_RANK(task_brd);

    if (EC_TRUE == task_brd_check_is_dbg_tcid(this_tcid) && CMPI_DBG_RANK == this_rank)
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "warn: super_shutdown_taskcomm: quit console\n");

        //TASK_BRD_ENABLE_FLAG(task_brd) = EC_FALSE;
        TASK_BRD_RESET_FLAG(task_brd) = EC_FALSE; /*disable do_slave reset*/

        TASK_BRD_SET_ABORT(task_brd);

        /*when stop TASKC, all packets in forwarding process will be unreachable to remote*/
        tasks_srv_end(TASK_BRD_LOCAL_TASKS_CFG(task_brd));

        csig_stop(SIGHUP);
    }

    if (EC_TRUE == task_brd_check_is_monitor_tcid(this_tcid) && CMPI_MON_RANK == this_rank)
    {
        //TASK_BRD_ENABLE_FLAG(task_brd) = EC_FALSE;
        TASK_BRD_RESET_FLAG(task_brd) = EC_FALSE; /*disable do_slave reset*/

        TASK_BRD_SET_ABORT(task_brd);

        /*when stop TASKC, all packets in forwarding process will be unreachable to remote*/
        tasks_srv_end(TASK_BRD_LOCAL_TASKS_CFG(task_brd));
        return;
    }

    if (EC_TRUE == task_brd_check_is_work_tcid(this_tcid) && CMPI_FWD_RANK == this_rank)
    {
#if (SWITCH_OFF == NGX_BGN_SWITCH)  /*must not allow to shudown bgn server on ngx*/
        //TASK_BRD_ENABLE_FLAG(task_brd) = EC_FALSE;
        TASK_BRD_RESET_FLAG(task_brd) = EC_FALSE; /*disable do_slave reset*/

        TASK_BRD_SET_ABORT(task_brd);

        /*when stop TASKC, all packets in forwarding process will be unreachable to remote*/
        tasks_srv_end(TASK_BRD_LOCAL_TASKS_CFG(task_brd));
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if (SWITCH_ON == NGX_BGN_SWITCH)
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "WARNING: MUST NOT ALLOW TO SHUTDOWN BGN SERVER ON NGX !\n");
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
        return;
    }
    //task_brd_default_abort();

    return;
}

EC_BOOL super_cancel_task_req(const UINT32 super_md_id, const UINT32 seqno, const UINT32 subseqno, const MOD_NODE *recv_mod_node)
{
    TASK_BRD   *task_brd;
    TASK_MGR   *task_mgr;
    TASK_REQ   *task_req;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_cancel_task_req: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    task_mgr = (TASK_MGR *)clist_search_data_front(TASK_BRD_RECV_TASK_MGR_LIST(task_brd), (void *)seqno, (CLIST_DATA_DATA_CMP)task_mgr_match_seqno);
    if(NULL_PTR == task_mgr)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_cancel_task_req: not found task_mgr with seqno %lx\n", seqno);
        return (EC_FALSE);
    }

    task_req = task_mgr_search_task_req_by_recver(task_mgr, seqno, subseqno, recv_mod_node);
    if(NULL_PTR == task_req)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_cancel_task_req: not found task_req with seqno %lx, subseqno %lx to (tcid %s,comm %ld,rank %ld,modi %ld)\n",
                            seqno, subseqno,
                            MOD_NODE_TCID_STR(recv_mod_node), MOD_NODE_COMM(recv_mod_node), MOD_NODE_RANK(recv_mod_node), MOD_NODE_MODI(recv_mod_node));
        return (EC_FALSE);
    }

    TASK_NODE_CMUTEX_LOCK(TASK_REQ_NODE(task_req), LOC_SUPER_0027);
    TASK_NODE_STATUS(TASK_REQ_NODE(task_req)) = TASK_REQ_DISCARD;
    TASK_MGR_COUNTER_INC_BY_TASK_REQ(TASK_REQ_MGR(task_req), TASK_MGR_COUNTER_TASK_REQ_DISCARD, task_req, LOC_SUPER_0028);
    TASK_NODE_CMUTEX_UNLOCK(TASK_REQ_NODE(task_req), LOC_SUPER_0029);

    return (EC_TRUE);
}

/**
*
* sync load info of current rank
*
**/
void super_sync_cload_stat(const UINT32 super_md_id, CLOAD_STAT *cload_stat)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_sync_cload_stat: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();
    task_brd_cload_stat_update_once(task_brd);
    cload_stat_clone(TASK_BRD_CLOAD_STAT(task_brd), cload_stat);

    return ;
}

/**
*
* sync load info of current comm
*
**/
void super_sync_cload_node(const UINT32 super_md_id, CLOAD_NODE *cload_node)
{
    TASK_BRD *task_brd;
    TASK_MGR *task_mgr;

    MOD_NODE  send_mod_node;
    MOD_NODE  recv_mod_node;

    UINT32    rank;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_sync_cload_node: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();
    if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd))
    {
        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                 NULL_PTR, FI_super_sync_cload_node, CMPI_ERROR_MODI, cload_node);
        return;
    }

    mod_node_init(&send_mod_node);
    MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&send_mod_node) = super_md_id;

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(rank = 0; rank < TASK_BRD_SIZE(task_brd); rank ++)
    {
        CLOAD_STAT *cload_stat;

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = rank;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        cload_stat = cload_node_get(cload_node, rank);
        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, NULL_PTR, FI_super_sync_cload_stat, CMPI_ERROR_MODI, cload_stat);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return ;
}

/*TODO: sync other ranks from fwd rank*/
STATIC_CAST static void super_sync_taskcomm_self(CVECTOR *collected_vec, TASK_MGR *task_mgr, MOD_NODE *send_mod_node)
{
    TASK_BRD *task_brd;
    CVECTOR  *new_mod_node_vec;
    UINT32 rank;

    task_brd = task_brd_default_get();

    if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd)
    || MOD_NODE_TCID(send_mod_node) != TASK_BRD_TCID(task_brd) || MOD_NODE_COMM(send_mod_node) != TASK_BRD_COMM(task_brd) || MOD_NODE_RANK(send_mod_node) || TASK_BRD_RANK(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_sync_taskcomm_self: FOR LOCAL FWD RANK ONLY!\n");
        return;
    }

    new_mod_node_vec = cvector_new(0, MM_MOD_NODE, LOC_SUPER_0030);
    cvector_push_no_lock(collected_vec, (void *)new_mod_node_vec);

    for(rank = 0; rank < TASK_BRD_SIZE(task_brd); rank ++)
    {
        MOD_NODE *recv_mod_node;

        recv_mod_node = mod_node_new();
        cvector_push(new_mod_node_vec, (void *)recv_mod_node);

        MOD_NODE_TCID(recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(recv_mod_node) = rank;/*des rank*/
        MOD_NODE_MODI(recv_mod_node) = 0;
        MOD_NODE_HOPS(recv_mod_node) = 0;
        MOD_NODE_LOAD(recv_mod_node) = 0;

        task_super_inc(task_mgr, send_mod_node, recv_mod_node,
                        NULL_PTR, FI_super_sync_cload_stat, CMPI_ERROR_MODI, MOD_NODE_CLOAD_STAT(recv_mod_node));
    }
    return;
}

/*TODO: search intranet of local_tasks_cfg with (local tcid, local maski, local maske)*/
STATIC_CAST static void super_sync_taskcomm_intranet(CVECTOR *collected_vec, CVECTOR *remote_tasks_cfg_vec, TASKS_CFG *local_tasks_cfg, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, TASK_MGR *task_mgr, MOD_NODE *send_mod_node)
{
    UINT32 pos;

    CVECTOR_LOCK(remote_tasks_cfg_vec, LOC_SUPER_0031);
    for(pos = 0; pos < cvector_size(remote_tasks_cfg_vec); pos ++)
    {
        TASKS_CFG *remote_tasks_cfg;
        CVECTOR *new_mod_node_vec;
        MOD_NODE recv_mod_node;

        remote_tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(remote_tasks_cfg_vec, pos);
        if(NULL_PTR == remote_tasks_cfg)
        {
            continue;
        }

        if(local_tasks_cfg == remote_tasks_cfg)
        {
            continue;
        }

        if(! DES_TCID_IS_INTRANET(TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg), TASKS_CFG_TCID(remote_tasks_cfg), TASKS_CFG_MASKE(remote_tasks_cfg)))
        {
            continue;
        }

        if(EC_FALSE == tasks_worker_check_connected_by_tcid(TASKS_CFG_WORKER(local_tasks_cfg), TASKS_CFG_TCID(remote_tasks_cfg)))
        {
            continue;
        }


        new_mod_node_vec = cvector_new(0, MM_MOD_NODE, LOC_SUPER_0032);
        cvector_push_no_lock(collected_vec, (void *)new_mod_node_vec);

        MOD_NODE_TCID(&recv_mod_node) = TASKS_CFG_TCID(remote_tasks_cfg);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_super_inc(task_mgr, send_mod_node, &recv_mod_node,
                        NULL_PTR, FI_super_sync_taskcomm, CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg),
                        max_hops, max_remotes, time_to_live,
                        new_mod_node_vec);
    }
    CVECTOR_UNLOCK(remote_tasks_cfg_vec, LOC_SUPER_0033);

    return;
}

/*TODO: search intranet of loca_tasks_cfg with (local tcid, local maski, local maske)*/
STATIC_CAST static void super_sync_taskcomm_lannet(CVECTOR *collected_vec, CVECTOR *remote_tasks_cfg_vec, TASKS_CFG *local_tasks_cfg, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, TASK_MGR *task_mgr, MOD_NODE *send_mod_node)
{
    UINT32 pos;

    CVECTOR_LOCK(remote_tasks_cfg_vec, LOC_SUPER_0034);
    for(pos = 0; pos < cvector_size(remote_tasks_cfg_vec); pos ++)
    {
        TASKS_CFG *remote_tasks_cfg;
        CVECTOR *new_mod_node_vec;
        MOD_NODE recv_mod_node;

        remote_tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(remote_tasks_cfg_vec, pos);
        if(NULL_PTR == remote_tasks_cfg)
        {
            continue;
        }

        if(local_tasks_cfg == remote_tasks_cfg)
        {
            continue;
        }

        if(! DES_TCID_IS_INTRANET(TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg), TASKS_CFG_TCID(remote_tasks_cfg), TASKS_CFG_MASKE(remote_tasks_cfg)))
        {
            continue;
        }

        if(EC_FALSE == tasks_worker_check_connected_by_tcid(TASKS_CFG_WORKER(local_tasks_cfg), TASKS_CFG_TCID(remote_tasks_cfg)))
        {
            continue;
        }

        new_mod_node_vec = cvector_new(0, MM_MOD_NODE, LOC_SUPER_0035);
        cvector_push_no_lock(collected_vec, (void *)new_mod_node_vec);

        MOD_NODE_TCID(&recv_mod_node) = TASKS_CFG_TCID(remote_tasks_cfg);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_super_inc(task_mgr, send_mod_node, &recv_mod_node,
                        NULL_PTR, FI_super_sync_taskcomm, CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg),
                        max_hops, max_remotes, time_to_live,
                        new_mod_node_vec);
    }
    CVECTOR_UNLOCK(remote_tasks_cfg_vec, LOC_SUPER_0036);
    return;
}

/*TODO: search lannet and extranet of local_tasks_cfg with (local tcid, local maski, local maske)*/
STATIC_CAST static void super_sync_taskcomm_externet(CVECTOR *collected_vec, CVECTOR *remote_tasks_cfg_vec, TASKS_CFG *local_tasks_cfg, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, TASK_MGR *task_mgr, MOD_NODE *send_mod_node)
{
    UINT32 pos;

    CVECTOR_LOCK(remote_tasks_cfg_vec, LOC_SUPER_0037);
    for(pos = 0; pos < cvector_size(remote_tasks_cfg_vec); pos ++)
    {
        TASKS_CFG *remote_tasks_cfg;
        CVECTOR *new_mod_node_vec;
        MOD_NODE recv_mod_node;

        remote_tasks_cfg = (TASKS_CFG *)cvector_get_no_lock(remote_tasks_cfg_vec, pos);
        if(NULL_PTR == remote_tasks_cfg)
        {
            continue;
        }

        if(local_tasks_cfg == remote_tasks_cfg)
        {
            continue;
        }

        if(
            (! DES_TCID_IS_LANNET(TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg), TASKS_CFG_TCID(remote_tasks_cfg), TASKS_CFG_MASKE(remote_tasks_cfg)))
        &&
            (! DES_TCID_IS_EXTERNET(TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg), TASKS_CFG_TCID(remote_tasks_cfg), TASKS_CFG_MASKI(remote_tasks_cfg)))
        )
        {
            continue;
        }

        if(EC_FALSE == tasks_worker_check_connected_by_tcid(TASKS_CFG_WORKER(local_tasks_cfg), TASKS_CFG_TCID(remote_tasks_cfg)))
        {
            continue;
        }

        new_mod_node_vec = cvector_new(0, MM_MOD_NODE, LOC_SUPER_0038);
        cvector_push_no_lock(collected_vec, (void *)new_mod_node_vec);

        MOD_NODE_TCID(&recv_mod_node) = TASKS_CFG_TCID(remote_tasks_cfg);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_super_inc(task_mgr, send_mod_node, &recv_mod_node,
                        NULL_PTR, FI_super_sync_taskcomm, CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg),
                        max_hops, max_remotes, time_to_live,
                        new_mod_node_vec);
    }
    CVECTOR_UNLOCK(remote_tasks_cfg_vec, LOC_SUPER_0039);
    return;
}

/**
*
* sync from remote taskcomms and the load info
*
* note: here the last cvector para always IO, otherwise the remote peer would have no idea its elements mem type when encoding rsp
*
**/
void super_sync_taskcomm(const UINT32 super_md_id, const UINT32 src_tcid, const UINT32 src_maski, const UINT32 src_maske, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, CVECTOR *mod_node_vec)
{
    TASK_BRD  *task_brd;
    TASK_CFG  *local_task_cfg;
    TASKS_CFG *local_tasks_cfg;

    CVECTOR  *remote_tasks_cfg_vec;
    CVECTOR  *collected_vec;
    TASK_MGR *task_mgr;

    MOD_NODE send_mod_node;

    UINT32   pos;
    UINT32   mod_node_pos_with_max_hops;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_sync_taskcomm: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_sync_taskcomm: FOR FWD RANK ONLY!\n");
        return;
    }

#if 0
    if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd))
    {
        MOD_NODE *mod_node;

        mod_node = mod_node_new();
        MOD_NODE_TCID(mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(mod_node) = CMPI_ERROR_MODI;
        MOD_NODE_HOPS(mod_node) = 0;
        MOD_NODE_LOAD(mod_node) = TASK_BRD_LOAD(task_brd);

        cvector_push(mod_node_vec, (void *)mod_node);
        return;
    }
    else/*for fwd*/
    {
        MOD_NODE *mod_node;

        mod_node = mod_node_new();
        MOD_NODE_TCID(mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(mod_node) = CMPI_ERROR_MODI;
        MOD_NODE_HOPS(mod_node) = 0;
        MOD_NODE_LOAD(mod_node) = TASK_BRD_LOAD(task_brd);

        cvector_push(mod_node_vec, (void *)mod_node);
    }
#endif
    if(1 >= max_hops)/*this is the last hop*/
    {
        return;
    }

    local_task_cfg = sys_cfg_filter_task_cfg(TASK_BRD_SYS_CFG(task_brd), TASK_BRD_TCID(task_brd));
    if(NULL_PTR == local_task_cfg)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_sync_taskcomm: filter task cfg of tcid %s from sys cfg failed\n", TASK_BRD_TCID_STR(task_brd));
        return;
    }

    local_tasks_cfg      = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
    remote_tasks_cfg_vec = TASK_CFG_TASKS_CFG_VEC(local_task_cfg);

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    collected_vec = cvector_new(0, MM_CVECTOR, LOC_SUPER_0040);

    MOD_NODE_TCID(&send_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&send_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&send_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&send_mod_node) = 0;
    MOD_NODE_HOPS(&send_mod_node) = 0;
    MOD_NODE_LOAD(&send_mod_node) = 0;

    /*TODO: search current taskcomm*/
    super_sync_taskcomm_self(collected_vec, task_mgr, &send_mod_node);

    /*when local_tasks_cfg belong to intranet of src tcid*/
    if(max_remotes > TASK_BRD_SIZE(task_brd)
    && DES_TCID_IS_INTRANET(src_tcid, src_maski, TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg)))
    {
        /*TODO: search intranet of local_tasks_cfg with (local tcid, local maski, local maske)*/
        super_sync_taskcomm_intranet(collected_vec, remote_tasks_cfg_vec, local_tasks_cfg,
                                    max_hops - 1, max_remotes - TASK_BRD_SIZE(task_brd), time_to_live,
                                    task_mgr, &send_mod_node);
    }

    /*when local_tasks_cfg belong to lannet of src tcid*/
    if(max_remotes > TASK_BRD_SIZE(task_brd)
    && DES_TCID_IS_LANNET(src_tcid, src_maske, TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg)))
    {
        /*TODO: search intranet of loca_tasks_cfg with (local tcid, local maski, local maske)*/
        super_sync_taskcomm_lannet(collected_vec, remote_tasks_cfg_vec, local_tasks_cfg,
                                    max_hops - 1, max_remotes - TASK_BRD_SIZE(task_brd), time_to_live,
                                    task_mgr, &send_mod_node);
    }

    /*when local_tasks_cfg belong to extranet of src tcid*/
    if(max_remotes > TASK_BRD_SIZE(task_brd)
    && DES_TCID_IS_EXTERNET(src_tcid, src_maske, TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg)))
    {
        /*TODO: search lannet and extranet of local_tasks_cfg with (local tcid, local maski, local maske)*/
        super_sync_taskcomm_externet(collected_vec, remote_tasks_cfg_vec, local_tasks_cfg,
                                    max_hops - 1, max_remotes - TASK_BRD_SIZE(task_brd), time_to_live,
                                    task_mgr, &send_mod_node);
    }

    task_wait(task_mgr, time_to_live, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    /*TODO: merge result*/
    mod_node_pos_with_max_hops = cvector_vote_pos(mod_node_vec, (CVECTOR_DATA_VOTER)mod_node_vote_gt_hops);
    for(pos = 0; pos < cvector_size(collected_vec); pos ++)
    {
        CVECTOR *new_mod_node_vec;
        UINT32 new_mod_node_pos;

        new_mod_node_vec = (CVECTOR *)cvector_get_no_lock(collected_vec, pos);
        if(NULL_PTR == new_mod_node_vec)
        {
            continue;
        }

        if(0 == cvector_size(new_mod_node_vec))
        {
            cvector_free(new_mod_node_vec, LOC_SUPER_0041);
            continue;
        }

        for(new_mod_node_pos = 0; new_mod_node_pos < cvector_size(new_mod_node_vec); new_mod_node_pos ++)
        {
            MOD_NODE *new_mod_node;
            MOD_NODE *max_hops_mod_node;

            new_mod_node = (MOD_NODE *)cvector_get_no_lock(new_mod_node_vec, new_mod_node_pos);
            if(NULL_PTR == new_mod_node)
            {
                continue;
            }

            cvector_set_no_lock(new_mod_node_vec, new_mod_node_pos, NULL_PTR);/*umount*/

            if(CVECTOR_ERR_POS != cvector_search_back(mod_node_vec, (void *)new_mod_node, (CVECTOR_DATA_CMP)mod_node_cmp))
            {
                mod_node_free(new_mod_node);
                continue;
            }

            if(MOD_NODE_TCID(new_mod_node) != TASK_BRD_TCID(task_brd))
            {
                MOD_NODE_HOPS(new_mod_node) ++;/*adjust*/
            }

            if(max_remotes > cvector_size(mod_node_vec))
            {
                UINT32 pushed_mod_node_pos;

                pushed_mod_node_pos = cvector_push(mod_node_vec, new_mod_node);

                if(CVECTOR_ERR_POS == mod_node_pos_with_max_hops)
                {
                    mod_node_pos_with_max_hops = pushed_mod_node_pos;
                    continue;
                }

                max_hops_mod_node = (MOD_NODE *)cvector_get(mod_node_vec, mod_node_pos_with_max_hops);
                if(EC_TRUE == mod_node_vote_gt_hops(new_mod_node, max_hops_mod_node))
                {
                    mod_node_pos_with_max_hops = pushed_mod_node_pos;
                    continue;
                }

                /*otherwise, do not update mod_node_pos_with_max_hops*/
                continue;
            }

            /*now max_remotes <= cvector_size(mod_node_vec), i.e., mod_node_vec is full*/
            max_hops_mod_node = (MOD_NODE *)cvector_get(mod_node_vec, mod_node_pos_with_max_hops);
            if(EC_TRUE == mod_node_vote_lt_hops(new_mod_node, max_hops_mod_node))
            {
                cvector_set(mod_node_vec, mod_node_pos_with_max_hops, (void *)new_mod_node);/*replace*/
                mod_node_free(max_hops_mod_node);

                /*re-compute mod_node_pos_with_max_hops*/
                mod_node_pos_with_max_hops = cvector_vote_pos(mod_node_vec, (CVECTOR_DATA_VOTER)mod_node_vote_gt_hops);
                continue;
            }

            mod_node_free(new_mod_node);
        }

        cvector_set_no_lock(collected_vec, pos, NULL_PTR);
        //cvector_clean(new_mod_node_vec, (CVECTOR_DATA_CLEANER)mod_node_free, LOC_SUPER_0042);
        cvector_free(new_mod_node_vec, LOC_SUPER_0043);
    }

    /*when reach here, collected_vec should have no more element*/
    cvector_free(collected_vec, LOC_SUPER_0044);

    task_cfg_free(local_task_cfg);

    return;
}

void super_sync_taskcomm_from_local(const UINT32 super_md_id, const UINT32 max_hops, const UINT32 max_remotes, const UINT32 time_to_live, CVECTOR *mod_node_vec)
{
    TASK_BRD  *task_brd;
    TASKS_CFG *local_tasks_cfg;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_sync_taskcomm_from_local: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    local_tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

    super_sync_taskcomm(TASK_BRD_SUPER_MD_ID(task_brd),
                        TASKS_CFG_TCID(local_tasks_cfg), TASKS_CFG_MASKI(local_tasks_cfg), TASKS_CFG_MASKE(local_tasks_cfg),
                        max_hops, max_remotes, time_to_live, mod_node_vec);
    return;
}

/**
*
* ping remote taskcomm with timeout
*
* if ping ack in timeout, remote taskcomm is reachable, otherwise, it is unreachable
*
**/
EC_BOOL super_ping_taskcomm(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ping_taskcomm: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    return (EC_TRUE);
}

EC_BOOL super_ping_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr)
{
    //TASK_BRD *task_brd;
    UINT32    ipaddr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ping_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_ping_ipaddr_cstr:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    //task_brd = task_brd_default_get();
    ipaddr   = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));

    return super_check_ipaddr_connected(super_md_id, ipaddr);
}

/**
*
* list queues in current taskComm
*
**/
void super_show_queues(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_queues: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    sys_log(log, "===============================[rank_%s_%ld] queues info beg: ===============================\n",
                TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd));

    sys_log(log, "[RECVING QUEUE]\n");
    task_queue_print(log, TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE));

    sys_log(log, "[IS_RECV QUEUE]\n");
    task_queue_print(log, TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE));

    sys_log(log, "[TO_SEND QUEUE]\n");
    task_queue_print(log, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE));

    sys_log(log, "[SENDING QUEUE]\n");
    task_queue_print(log, TASK_BRD_QUEUE(task_brd, TASK_SENDING_QUEUE));

    sys_log(log, "[RECV TASK MGR LIST]\n");
    clist_print(log, TASK_BRD_RECV_TASK_MGR_LIST(task_brd), (CLIST_DATA_DATA_PRINT)task_mgr_print);

    sys_log(log, "[AGING TASK MGR LIST]\n");
    clist_print(log, TASK_BRD_AGING_TASK_MGR_LIST(task_brd), (CLIST_DATA_DATA_PRINT)task_mgr_print);

    sys_log(log, "[MOD MGR LIST]\n");
    task_brd_mod_mgr_list_print(log, task_brd);

    sys_log(log, "[CONTEXT LIST]\n");
    task_brd_context_list_print(log, task_brd);

    sys_log(log, "===============================[rank_%s_%ld] queues info end: ===============================\n",
                 TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd));

    return;
}

/**
*
* list slow down checking conditions
*
**/
void super_check_slowdown(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_check_slowdown: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    sys_log(log, "===============================[rank_%s_%ld] slow down checking conditions: ===============================\n",
                TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd));

    task_brd_need_slow_down(task_brd, log, LOG_LEVEL_ALWAYS_HAPPEN);
    return;
}

void super_handle_broken_tcid_comm(const UINT32 super_md_id, const UINT32 broken_tcid, const UINT32 broken_comm)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_handle_broken_tcid_comm: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "[DEBUG] super_handle_broken_tcid_comm: beg: broken tcid %s comm %ld\n",
                                          c_word_to_ipv4(broken_tcid), broken_comm);
    //super_show_queues(super_md_id);/*debug only!*/

    task_brd = task_brd_default_get();

    /*keep recving packet on the road. does anyone keep sending to me without pause??*/
    //task_brd_keep_recving(task_brd);

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        //TASKS_CFG *tasks_cfg;

        /*clean TASKC_NODE list*/
        super_excl_taskc_node(super_md_id, broken_tcid, broken_comm);

        /*clean up all mod_mgr in task_brd. if found tcid in mod_node of some mod_mgr, then delete the mod_node*/
        task_brd_mod_mgr_list_excl(task_brd, broken_tcid, broken_comm);

        /*the socket to the broken taskComm would be closed automatically*/
        //tasks_cfg = taskc_get_local_tasks_cfg(TASK_BRD_TASKC_MD_ID(task_brd));

        /**
        *
        *  FROM the broken taskComm
        *  ---------------------------------------------------------------
        *  (QUEUE, TAG)       | TAG_TASK_REQ | TAG_TASK_RSP | TAG_TASK_FWD
        *  ---------------------------------------------------------------
        *  TASK_SENDING_QUEUE |      X       |      X       |     X
        *  ---------------------------------------------------------------
        *  TASK_RECVING_QUEUE |      X       |      X       |     X
        *  ---------------------------------------------------------------
        *  TASK_IS_RECV_QUEUE |      X       |      -       |     X
        *  ---------------------------------------------------------------
        * note: X means to discard, - means no such tag in the queue
        * note: when TAG_TASK_REQ in TASK_SENDING_QUEUE, it must from the broken taskComm be to forward in current taskComm
        * note: when TAG_TASK_REQ in TASK_RECVING_QUEUE, it must from the broken taskComm be to FWD rank of current taskComm
        *
        **/

        task_queue_discard_from(task_brd, TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), TAG_TASK_REQ, broken_tcid, broken_comm);
        task_queue_discard_from(task_brd, TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), TAG_TASK_FWD, broken_tcid, broken_comm);

        task_queue_discard_from(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_REQ, broken_tcid, broken_comm);/*new add*/
        task_queue_discard_from(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_RSP, broken_tcid, broken_comm);/*new add*/
        task_queue_discard_from(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_FWD, broken_tcid, broken_comm);/*new add*/

        /**
        *
        *  TO the broken taskComm
        *  ---------------------------------------------------------------
        *  (QUEUE, TAG)       | TAG_TASK_REQ | TAG_TASK_RSP | TAG_TASK_FWD
        *  ---------------------------------------------------------------
        *  TASK_SENDING_QUEUE |      X       |      X       |     X
        *  ---------------------------------------------------------------
        *  TASK_RECVING_QUEUE |      -       |      -       |     X
        *  ---------------------------------------------------------------
        *  TASK_IS_RECV_QUEUE |      -       |      -       |     X
        *  ---------------------------------------------------------------
        * note: X means to discard, - means no such tag in the queue
        *
        **/
        task_queue_discard_to(task_brd, TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), TAG_TASK_FWD, broken_tcid, broken_comm);

        task_queue_discard_to(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_REQ, broken_tcid, broken_comm);/*new add*/
        task_queue_discard_to(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_RSP, broken_tcid, broken_comm);/*new add*/
        task_queue_discard_to(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_FWD, broken_tcid, broken_comm);/*new add*/

        /*reschedule all TASK_REQ to the borken taskComm*/
        task_mgr_list_handle_broken(task_brd, broken_tcid, broken_comm);/*2014.09.14*/

        /*discard all contexts (end module) from the broken taskComm*/
        task_context_discard_from(task_brd, broken_tcid, broken_comm);

        task_brd_rank_load_tbl_pop_all(task_brd, broken_tcid, broken_comm);
    }

    else
    {
        /*clean up all mod_mgr in task_brd. if found tcid in mod_node of some mod_mgr, then delete the mod_node*/
        task_brd_mod_mgr_list_excl(task_brd, broken_tcid, broken_comm);

        /**
        *
        *  FROM the broken taskComm
        *  ---------------------------------------------------------------
        *  (QUEUE, TAG)       | TAG_TASK_REQ | TAG_TASK_RSP | TAG_TASK_FWD
        *  ---------------------------------------------------------------
        *  TASK_SENDING_QUEUE |      -       |      -       |     -
        *  ---------------------------------------------------------------
        *  TASK_RECVING_QUEUE |      X       |      X       |     -
        *  ---------------------------------------------------------------
        *  TASK_IS_RECV_QUEUE |      X       |      +       |     -
        *  ---------------------------------------------------------------
        * note: X means to discard, - means no such tag in the queue, + means keep this tag in the queue
        * note: when TAG_TASK_REQ in TASK_SENDING_QUEUE, it must from the broken taskComm be to forward in current taskComm
        * note: when TAG_TASK_REQ in TASK_RECVING_QUEUE, it must from the broken taskComm be to FWD rank of current taskComm
        *
        **/
        task_queue_discard_from(task_brd, TASK_BRD_QUEUE(task_brd, TASK_IS_RECV_QUEUE), TAG_TASK_REQ, broken_tcid, broken_comm);

        /**
        *
        *  TO the broken taskComm
        *  ---------------------------------------------------------------
        *  (QUEUE, TAG)       | TAG_TASK_REQ | TAG_TASK_RSP | TAG_TASK_FWD
        *  ---------------------------------------------------------------
        *  TASK_SENDING_QUEUE |      X       |      X       |     -
        *  ---------------------------------------------------------------
        *  TASK_RECVING_QUEUE |      -       |      -       |     -
        *  ---------------------------------------------------------------
        *  TASK_IS_RECV_QUEUE |      -       |      -       |     -
        *  ---------------------------------------------------------------
        * note: X means to discard, - means no such tag in the queue, + means keep this tag in the queue
        * note: when TAG_TASK_REQ in TASK_SENDING_QUEUE, it must from the broken taskComm be to forward in current taskComm
        * note: when TAG_TASK_REQ in TASK_RECVING_QUEUE, it must from the broken taskComm be to FWD rank of current taskComm
        *
        **/
        task_queue_discard_to(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_REQ, broken_tcid, broken_comm);/*new add*/
        task_queue_discard_to(task_brd, TASK_BRD_QUEUE(task_brd, TASK_TO_SEND_QUEUE), TAG_TASK_RSP, broken_tcid, broken_comm);/*new add*/

        /*reschedule all TASK_REQ to the borken taskComm*/
        task_mgr_list_handle_broken(task_brd, broken_tcid, broken_comm);

        /*process all TASK_RSP from the broken taskComm*/
        /*task_queue_process_from(task_brd, TASK_BRD_QUEUE(task_brd, TASK_RECVING_QUEUE), TAG_TASK_RSP, broken_tcid);*/

        /*discard all contexts (end module) from the broken taskComm*/
        task_context_discard_from(task_brd, broken_tcid, broken_comm);

        task_brd_rank_load_tbl_pop_all(task_brd, broken_tcid, broken_comm);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "[DEBUG] super_handle_broken_tcid_comm: end: broken tcid %s comm %ld\n",
                                          c_word_to_ipv4(broken_tcid), broken_comm);
    //super_show_queues(super_md_id);/*debug only!*/
    return;
}

/**
*
* when fwd rank found some broken taskcomm, then notify all ranks in current taskcomm
*
* note: here does not notify other taskcomm(s)
*
**/
void super_notify_broken_tcid_comm(const UINT32 super_md_id, const UINT32 broken_tcid, const UINT32 broken_comm)
{
    TASK_BRD  *task_brd;

    CSET      *rank_set;
    MOD_MGR   *mod_mgr;
    TASK_MGR  *task_mgr;

    UINT32 mod_node_num;
    UINT32 mod_node_idx;

    MOD_NODE *mod_node;
    UINT32 broken_tcid_pos;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_notify_broken_tcid_comm: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    mod_node = mod_node_new();
    if(NULL_PTR == mod_node)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_notify_broken_tcid_comm: new mod_node for broken tcid %s failed\n",
                            c_word_to_ipv4(broken_tcid));
        return;
    }

    MOD_NODE_TCID(mod_node) = broken_tcid;
    MOD_NODE_COMM(mod_node) = broken_comm;
    MOD_NODE_RANK(mod_node) = CMPI_ANY_RANK;
    MOD_NODE_MODI(mod_node) = CMPI_ANY_MODI;

    /*pre-checking*/
    CVECTOR_LOCK(TASK_BRD_BROKEN_TBL(task_brd), LOC_SUPER_0045);
    broken_tcid_pos = cvector_search_front_no_lock(TASK_BRD_BROKEN_TBL(task_brd), (void *)mod_node, (CVECTOR_DATA_CMP)mod_node_cmp);
    if(CVECTOR_ERR_POS != broken_tcid_pos)
    {
        mod_node_free(mod_node);
        /*okay, someone is working on this broken tcid, terminate on-going*/
        CVECTOR_UNLOCK(TASK_BRD_BROKEN_TBL(task_brd), LOC_SUPER_0046);
        return;
    }
    cvector_push_no_lock(TASK_BRD_BROKEN_TBL(task_brd), (void *)mod_node);
    CVECTOR_UNLOCK(TASK_BRD_BROKEN_TBL(task_brd), LOC_SUPER_0047);

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "[DEBUG] super_notify_broken_tcid_comm: beg: broken tcid %s comm %ld\n",
                                          c_word_to_ipv4(broken_tcid), broken_comm);

    mod_mgr = mod_mgr_new(super_md_id, LOAD_BALANCING_LOOP);
    if(NULL_PTR == mod_mgr)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_notify_broken_tcid_comm: "
                                              "new mod_mgr for broken tcid %s comm %ld failed\n",
                                              c_word_to_ipv4(broken_tcid), broken_comm);
        return;
    }

    /*set mod_mgr*/
    rank_set_new(&rank_set);
    rank_set_init(rank_set, TASK_BRD_SIZE(task_brd));
    mod_mgr_set(TASK_BRD_TCID(task_brd), TASK_BRD_COMM(task_brd), 0, rank_set, mod_mgr);
    //mod_mgr_excl(CMPI_ANY_DBG_TCID, CMPI_ANY_COMM, CMPI_ANY_RANK, CMPI_ANY_MODI, mod_mgr);/*ignore dbg process in dbg taskcomm*/
    rank_set_free(rank_set);

#if 1
    if(do_log(SEC_0117_SUPER, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] super_notify_broken_tcid_comm: beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "DEBUG] super_notify_broken_tcid_comm: end ----------------------------------\n");
    }
#endif

    /*set task_mgr*/
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

    mod_node_num = MOD_MGR_REMOTE_NUM(mod_mgr);
    for(mod_node_idx = 0; mod_node_idx < mod_node_num; mod_node_idx ++)
    {
        task_pos_inc(task_mgr, mod_node_idx, NULL_PTR, FI_super_handle_broken_tcid_comm, CMPI_ERROR_MODI, broken_tcid, broken_comm);
    }

    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    /*ok, complete the broken tcid handling, remove it from table*/
    CVECTOR_LOCK(TASK_BRD_BROKEN_TBL(task_brd), LOC_SUPER_0048);
    /*we have to search it again because the broken tcid position maybe changed under multiple thread environment*/
    broken_tcid_pos = cvector_search_front_no_lock(TASK_BRD_BROKEN_TBL(task_brd), (void *)mod_node, (CVECTOR_DATA_CMP)mod_node_cmp);
    mod_node = cvector_erase_no_lock(TASK_BRD_BROKEN_TBL(task_brd), broken_tcid_pos);
    if(NULL_PTR != mod_node)
    {
        mod_node_free(mod_node);
    }
    CVECTOR_UNLOCK(TASK_BRD_BROKEN_TBL(task_brd), LOC_SUPER_0049);

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "[DEBUG] super_notify_broken_tcid_comm: end: broken tcid %s comm %ld\n",
                        c_word_to_ipv4(broken_tcid), broken_comm);

    return;
}

/**
*
* when fwd rank found some broken route, then notify the src taskcomm
*
**/
void super_notify_broken_route(const UINT32 super_md_id, const UINT32 src_tcid, const UINT32 broken_tcid)
{
    TASK_BRD  *task_brd;

    MOD_MGR   *mod_mgr;
    TASK_MGR  *task_mgr;

    UINT32 local_mod_node_pos;
    UINT32 remote_mod_node_pos;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_notify_broken_route: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "============================== super_notify_broken_route beg: src tcid %s, broken tcid %s ==============================\n",
                        c_word_to_ipv4(src_tcid), c_word_to_ipv4(broken_tcid));

    task_brd = task_brd_default_get();

    mod_mgr = mod_mgr_new(super_md_id, LOAD_BALANCING_LOOP);

    /*set mod_mgr*/
    local_mod_node_pos  = mod_mgr_incl(TASK_BRD_TCID(task_brd), TASK_BRD_COMM(task_brd), CMPI_FWD_RANK, 0, mod_mgr);
    remote_mod_node_pos = mod_mgr_incl(src_tcid, CMPI_ANY_COMM, CMPI_FWD_RANK, 0, mod_mgr);

#if 1
    if(do_log(SEC_0117_SUPER, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ super_notify_broken_route beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ super_notify_broken_route end ----------------------------------\n");
    }
#endif

    /*set task_mgr*/
    task_mgr = task_new(mod_mgr, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    task_pos_inc(task_mgr, local_mod_node_pos , NULL_PTR, FI_super_handle_broken_tcid_comm, CMPI_ERROR_MODI, broken_tcid, CMPI_ANY_COMM);
    task_pos_inc(task_mgr, remote_mod_node_pos, NULL_PTR, FI_super_handle_broken_tcid_comm, CMPI_ERROR_MODI, broken_tcid, CMPI_ANY_COMM);
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "============================== super_notify_broken_route end: src tcid %s, broken tcid %s ==============================\n",
                        c_word_to_ipv4(src_tcid), c_word_to_ipv4(broken_tcid));

    return;
}

/**
*
* when fwd rank found some broken route, then register all cluster
*
**/
void super_register_cluster(const UINT32 super_md_id, const UINT32 src_tcid, const UINT32 broken_tcid)
{
    TASK_BRD  *task_brd;

    MOD_NODE   recv_mod_node;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_register_cluster: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "warn: super_register_cluster: src tcid %s, broken tcid %s\n",
                        c_word_to_ipv4(src_tcid), c_word_to_ipv4(broken_tcid));

    task_brd = task_brd_default_get();

    if (CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        task_brd_register_cluster(task_brd);
        return;
    }

    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = super_md_id;

    task_p2p_no_wait(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_PREEMPT, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                    &recv_mod_node,
                    NULL_PTR, FI_super_register_cluster, CMPI_ERROR_MODI, src_tcid, broken_tcid);
    return;
}

/**
*
* show work clients of tasks_cfg of taskc_cfg of task_brd
*
**/
void super_show_work_client(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_work_client: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *tasks_cfg;
        UINT32 index;

        tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);
        index     = 0;

        //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== working clients beg: =====================================\n");
        tasks_worker_print_csocket_cnode_list_in_plain(log, TASKS_CFG_WORKER(tasks_cfg), &index);
        //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "===================================== working clients end: =====================================\n");
    }
    return;
}

/**
*
* show work threads of tasks_cfg of taskc_cfg of task_brd
*
**/
void super_show_thread_num(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD  *task_brd;
    UINT32     idle_thread_num;
    UINT32     busy_thread_num;
    UINT32     total_thread_num;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_thread_num: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    croutine_pool_num_info(TASK_REQ_CTHREAD_POOL(task_brd), &idle_thread_num, &busy_thread_num, &total_thread_num);
    sys_log(log, "total req thread %ld, busy %ld, idle %ld\n", total_thread_num, busy_thread_num, idle_thread_num);

    return;
}

/**
*
* show route table of tasks_cfg of taskc_cfg of task_brd
*
**/
void super_show_route_table(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD  *task_brd;
    TASKS_CFG *tasks_cfg;

    UINT32 pos;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_route_table: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();
    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

    CVECTOR_LOCK(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), LOC_SUPER_0050);
    if(EC_TRUE == cvector_is_empty(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg)))
    {
        sys_log(log, "(no route)\n");
        CVECTOR_UNLOCK(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), LOC_SUPER_0051);
        return;
    }
    for(pos = 0; pos < cvector_size(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg)); pos ++)
    {
        TASKR_CFG *taskr_cfg;

        taskr_cfg = (TASKR_CFG *)cvector_get_no_lock(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), pos);
        if(NULL_PTR == taskr_cfg)
        {
            sys_log(log, "No. %ld: (null route)\n", pos);
            continue;
        }

        sys_log(log, "No. %ld: des_tcid = %s, maskr = %s, next_tcid = %s\n", pos,
                        TASKR_CFG_DES_TCID_STR(taskr_cfg),
                        TASKR_CFG_MASKR_STR(taskr_cfg),
                        TASKR_CFG_NEXT_TCID_STR(taskr_cfg));
    }
    CVECTOR_UNLOCK(TASKS_CFG_TASKR_CFG_VEC(tasks_cfg), LOC_SUPER_0052);
    return;
}

/**
*
* show rank node status of the rank
*
**/
void super_show_rank_node(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_rank_node: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    task_rank_tbl_print(log, TASK_BRD_RANK_TBL(task_brd));
    return;
}


/**
*
* switch/enable rank node light to green
*
**/
void super_switch_rank_node_green(const UINT32 super_md_id, const UINT32 rank)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_switch_rank_node_green: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_ANY_RANK == rank)
    {
        task_rank_tbl_enable_all(TASK_BRD_RANK_TBL(task_brd));
    }
    else
    {
        task_rank_tbl_enable(TASK_BRD_RANK_TBL(task_brd), rank);
    }
    return;
}

/**
*
* switch/disable rank node light to red
*
**/
void super_switch_rank_node_red(const UINT32 super_md_id, const UINT32 rank)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_switch_rank_node_red: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_ANY_RANK == rank)
    {
        task_rank_tbl_disable_all(TASK_BRD_RANK_TBL(task_brd));
    }
    else
    {
        task_rank_tbl_disable(TASK_BRD_RANK_TBL(task_brd), rank);
    }
    return;
}

/**
*
* output log by SUPER module
*
**/
void super_show_cstring(const UINT32 super_md_id, const UINT32 tcid, const UINT32 rank, const CSTRING *cstring)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_cstring: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    //fprintf(LOGSTDOUT, "[rank_%s_%ld] ", c_word_to_ipv4(tcid), rank);
    //fprintf(LOGSTDOUT, "%s", (char *)cstring_get_str(cstring));
    //fflush(LOGSTDOUT);
    fputs((char *)cstring_get_str(cstring), stdout);
    fflush(stdout);

    return;
}

/**
*
* switch log off
*
**/
void super_switch_log_off(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_switch_log_off: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    sys_log_switch_off();
    return;
}

/**
*
* switch log on
*
**/
void super_switch_log_on(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_switch_log_on: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    sys_log_switch_on();
    return;
}

/**
*
* rotate log
*
**/
EC_BOOL super_rotate_log(const UINT32 super_md_id, const UINT32 log_index)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_rotate_log: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(DEFAULT_END_LOG_INDEX <= log_index)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_rotate_log: log index %ld overflow\n", log_index);
        return (EC_FALSE);
    }

    if(0 != sys_log_rotate_by_index(log_index))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_rotate_log: log index %ld rotate failed\n", log_index);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_rotate_log: log index %ld rotate done\n", log_index);

    return (EC_TRUE);
}

/**
*
* send http request and recv http response
*
**/
EC_BOOL super_http_request(const UINT32 super_md_id, const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    uint32_t s_nsec; /*start time in second*/
    uint32_t s_msec; /*start time in micro-second*/

    uint32_t e_nsec; /*end time in second*/
    uint32_t e_msec; /*end time in micro-second*/

    uint32_t s2e_elapsed_msec;
    uint32_t need_log_flag;

    uint32_t redirect_times;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_http_request: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(NULL_PTR != chttp_store)
    {
        if(do_log(SEC_0117_SUPER, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] super_http_request: chttp_store %p:\n", chttp_store);
            chttp_store_print(LOGSTDOUT, chttp_store);
        }
    }

    if(NULL_PTR != chttp_store && BIT_TRUE == CHTTP_STORE_NEED_LOG_FLAG(chttp_store))
    {
        need_log_flag = BIT_TRUE;
    }
    else
    {
        need_log_flag = BIT_FALSE;
    }

    s_nsec = 0;
    s_msec = 0;

    e_nsec = 0;
    e_msec = 0;

    if(BIT_TRUE == need_log_flag)
    {
        /*trick: unset need log flag*/
        CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_FALSE;

        CHTTP_STAT_LOG_ORIG_TIME_WHEN_START(s_nsec, s_msec);
    }

    if(EC_FALSE == chttp_request(chttp_req, (CHTTP_STORE *)chttp_store, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_http_request: trigger request %p failed\n", chttp_req);

        if(BIT_TRUE == need_log_flag
        && NULL_PTR != chttp_stat)
        {
            /*trick: restore need log flag*/
            CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

            CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
            s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
            sys_log(LOGUSER07, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u %u %u\n",
                               (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                               CHTTP_REQ_PORT(chttp_req),
                               CHTTP_STATUS_NONE,
                               s2e_elapsed_msec,
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                               (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                               ((uint32_t)0), /*redirect times*/
                               CHTTP_STAT_S_SEND_LEN(chttp_stat),
                               CHTTP_STAT_S_RECV_LEN(chttp_stat)
                               );

        }

        if(BIT_TRUE == need_log_flag
        && NULL_PTR == chttp_stat)
        {
            /*trick: restore need log flag*/
            CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

            CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
            s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
            sys_log(LOGUSER07, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u - -\n",
                               (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                               CHTTP_REQ_PORT(chttp_req),
                               CHTTP_STATUS_NONE,
                               s2e_elapsed_msec,
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                               (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                               ((uint32_t)0) /*redirect times*/
                               );

        }

        return (EC_FALSE);
    }
    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_http_request: redirect_ctrl = %s, redirect_max_times = %ld\n",
                        c_bit_bool_str(CHTTP_STORE_REDIRECT_CTRL(chttp_store)),
                        CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store));
    for(redirect_times = 0;
        BIT_TRUE == CHTTP_STORE_REDIRECT_CTRL(chttp_store)
        && CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store) > redirect_times
        && (CHTTP_MOVED_PERMANENTLY == CHTTP_RSP_STATUS(chttp_rsp) || CHTTP_MOVED_TEMPORARILY == CHTTP_RSP_STATUS(chttp_rsp));
        redirect_times ++
    )
    {
        char      *loc;
        char      *host;
        char      *port;
        char      *uri;
        CHTTP_REQ  chttp_req_t;

        loc = chttp_rsp_get_header(chttp_rsp, (const char *)"Location");
        if(NULL_PTR == loc)
        {
            break;
        }
        dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "[DEBUG] super_http_request: [%u] redirect to '%s'\n", redirect_times, loc);

        host = NULL_PTR;
        port = NULL_PTR;
        uri  = NULL_PTR;

        if(EC_FALSE == c_parse_location(loc, &host, &port, &uri))
        {
            if(NULL_PTR != host)
            {
                safe_free(host, LOC_SUPER_0053);
            }
            if(NULL_PTR != port)
            {
                safe_free(port, LOC_SUPER_0054);
            }
            if(NULL_PTR != uri)
            {
                safe_free(uri, LOC_SUPER_0055);
            }
            break;
        }

        chttp_rsp_clean(chttp_rsp);
        chttp_stat_clean(chttp_stat);

        chttp_req_init(&chttp_req_t);
        chttp_req_clone(&chttp_req_t, chttp_req);

        if(NULL_PTR != host)
        {
            dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_http_request: location '%s' =>  host '%s'\n", loc, host);
            chttp_req_set_ipaddr(&chttp_req_t, host);
            safe_free(host, LOC_SUPER_0056);
        }

        if(NULL_PTR != port)
        {
            dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_http_request: location '%s' =>  port '%s'\n", loc, port);
            chttp_req_set_port(&chttp_req_t, port);
            safe_free(port, LOC_SUPER_0057);
        }

        if(NULL_PTR == uri)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_http_request: location '%s' =>  uri is null\n", loc);

            chttp_req_clean(&chttp_req_t);

            if(BIT_TRUE == need_log_flag
            && NULL_PTR != chttp_stat)
            {
                /*trick: restore need log flag*/
                CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

                CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
                s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
                sys_log(LOGUSER07, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u %u %u\n",
                                   (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                                   CHTTP_REQ_PORT(chttp_req),
                                   CHTTP_STATUS_NONE,
                                   s2e_elapsed_msec,
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                                   (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                                   ((uint32_t)redirect_times + 1), /*redirect times*/
                                   CHTTP_STAT_S_SEND_LEN(chttp_stat),
                                   CHTTP_STAT_S_RECV_LEN(chttp_stat)
                                   );
            }

            if(BIT_TRUE == need_log_flag
            && NULL_PTR == chttp_stat)
            {
                /*trick: restore need log flag*/
                CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

                CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
                s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
                sys_log(LOGUSER07, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u - -\n",
                                   (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                                   CHTTP_REQ_PORT(chttp_req),
                                   CHTTP_STATUS_NONE,
                                   s2e_elapsed_msec,
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                                   (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                                   ((uint32_t)redirect_times + 1) /*redirect times*/
                                   );
            }
            return (EC_FALSE);
        }

        dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_http_request: location '%s' =>  uri '%s'\n", loc, uri);

        cstring_clean(CHTTP_REQ_URI(&chttp_req_t));
        chttp_req_set_uri(&chttp_req_t, uri);
        safe_free(uri, LOC_SUPER_0058);

        if(do_log(SEC_0117_SUPER, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] super_http_request: redirect request is\n");
            chttp_req_print(LOGSTDOUT, &chttp_req_t);

            sys_log(LOGSTDOUT, "[DEBUG] super_http_request: redirect store is\n");
            chttp_store_print(LOGSTDOUT, chttp_store);
        }

        if(EC_FALSE == chttp_request(&chttp_req_t, (CHTTP_STORE *)chttp_store, chttp_rsp, chttp_stat))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_http_request: redirect request failed\n");
            chttp_req_print(LOGSTDOUT, &chttp_req_t);

            chttp_req_clean(&chttp_req_t);

            if(BIT_TRUE == need_log_flag
            && NULL_PTR != chttp_stat)
            {
                /*trick: restore need log flag*/
                CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

                CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
                s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
                sys_log(LOGUSER07, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u %u %u\n",
                                   (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                                   CHTTP_REQ_PORT(chttp_req),
                                   CHTTP_STATUS_NONE,
                                   s2e_elapsed_msec,
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                                   (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                                   ((uint32_t)redirect_times + 1), /*redirect times*/
                                   CHTTP_STAT_S_SEND_LEN(chttp_stat),
                                   CHTTP_STAT_S_RECV_LEN(chttp_stat)
                                   );

            }

            if(BIT_TRUE == need_log_flag
            && NULL_PTR == chttp_stat)
            {
                /*trick: restore need log flag*/
                CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

                CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
                s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
                sys_log(LOGUSER07, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u - -\n",
                                   (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                                   CHTTP_REQ_PORT(chttp_req),
                                   CHTTP_STATUS_NONE,
                                   s2e_elapsed_msec,
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                                   (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                                   ((uint32_t)redirect_times + 1) /*redirect times*/
                                   );

            }
            return (EC_FALSE);
        }

        if(do_log(SEC_0117_SUPER, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] super_http_request: redirect response is\n");
            chttp_rsp_print(LOGSTDOUT, chttp_rsp);
        }

        chttp_req_clean(&chttp_req_t);
    }

    /*check result cache_ctrl*/
    if(NULL_PTR != chttp_store)
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_http_request: restore cache_ctrl: result %#x\n",
                                              CHTTP_STORE_CACHE_CTRL(chttp_store));
    }

    if(BIT_TRUE == need_log_flag
    && NULL_PTR != chttp_stat)
    {
        /*trick: restore need log flag*/
        CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

        CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
        s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
        sys_log(LOGUSER07, "[SUCC] %s %ld %u %u \"http://%s%s\" %s %u %u %u\n",
                           (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                           CHTTP_REQ_PORT(chttp_req),
                           CHTTP_RSP_STATUS(chttp_rsp),
                           s2e_elapsed_msec,
                           (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                           (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                           (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                           ((uint32_t)redirect_times), /*redirect times*/
                           CHTTP_STAT_S_SEND_LEN(chttp_stat),
                           CHTTP_STAT_S_RECV_LEN(chttp_stat)
                           );
    }

    if(BIT_TRUE == need_log_flag
    && NULL_PTR == chttp_stat)
    {
        /*trick: restore need log flag*/
        CHTTP_STORE_NEED_LOG_FLAG((CHTTP_STORE *)chttp_store) = BIT_TRUE;

        CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_nsec, e_msec);
        s2e_elapsed_msec = (uint32_t)CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_nsec, e_msec, s_nsec, s_msec);
        sys_log(LOGUSER07, "[SUCC] %s %ld %u %u \"http://%s%s\" %s %u - -\n",
                           (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                           CHTTP_REQ_PORT(chttp_req),
                           CHTTP_RSP_STATUS(chttp_rsp),
                           s2e_elapsed_msec,
                           (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                           (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                           (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                           ((uint32_t)redirect_times) /*redirect times*/
                           );
    }

    return (EC_TRUE);
}

/**
*
* send http request and recv http response in merge procedure
*
**/
EC_BOOL super_http_request_merge(const UINT32 super_md_id, const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_http_request_merge: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_FALSE == super_http_request(super_md_id, chttp_req, chttp_store, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_http_request_merge: trigger request %p failed\n", chttp_req);
        chttp_store_waiter_terminate(chttp_store);
        return (EC_FALSE);
    }

    /*
    if((CHTTP_MOVED_PERMANENTLY == CHTTP_RSP_STATUS(chttp_rsp) || CHTTP_MOVED_TEMPORARILY == CHTTP_RSP_STATUS(chttp_rsp))
    && BIT_FALSE == CHTTP_STORE_REDIRECT_CTRL(chttp_store)
    && CHTTP_STORE_CACHE_NONE == CHTTP_STORE_CACHE_CTRL(chttp_store))
    */
    if(NULL_PTR != chttp_store)
    {
        dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_http_request_merge: request %p, cache_ctrl: 0x%x\n",
                        chttp_req, CHTTP_STORE_CACHE_CTRL(chttp_store));

        if(CHTTP_STORE_CACHE_NONE == CHTTP_STORE_CACHE_CTRL(chttp_store))
        {
            /*notify waiters*/
            chttp_node_store_no_next(NULL_PTR, (CHTTP_STORE *)chttp_store);
        }
    }

    return (EC_TRUE);
}

/**
*
* wait until current process of current taskComm is ready
*
**/
void super_wait_me_ready(const UINT32 super_md_id)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_wait_me_ready: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    task_brd = task_brd_default_get();

    TASK_BRD_FWD_CCOND_WAIT(task_brd, LOC_SUPER_0059);
    return;
}

/**
*
* add route
*
**/
void super_add_route(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 maskr, const UINT32 next_tcid)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_add_route: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *local_tasks_cfg;
        TASKR_CFG *taskr_cfg;

        local_tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

        taskr_cfg = taskr_cfg_new();
        taskr_cfg_set(taskr_cfg, des_tcid, maskr, next_tcid);

        if(EC_FALSE == tasks_cfg_add_taskr(local_tasks_cfg, taskr_cfg))
        {
            taskr_cfg_free(taskr_cfg);
        }
    }

    return;
}

/**
*
* del route
*
**/
void super_del_route(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 maskr, const UINT32 next_tcid)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_del_route: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_FWD_RANK == TASK_BRD_RANK(task_brd))
    {
        TASKS_CFG *local_tasks_cfg;
        TASKR_CFG *taskr_cfg;

        local_tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd);

        taskr_cfg = taskr_cfg_new();
        taskr_cfg_set(taskr_cfg, des_tcid, maskr, next_tcid);

        while(EC_TRUE == tasks_cfg_del_taskr(local_tasks_cfg, taskr_cfg))
        {
            /*do nothing*/
        }

        taskr_cfg_free(taskr_cfg);
    }

    return;
}

/**
*
* try to connect
*
**/
EC_BOOL super_connect(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 des_comm, const UINT32 conn_num)
{
    TASK_BRD  *task_brd;

    UINT32     des_ipv4;
    UINT32     des_port;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_connect: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_connect: current rank %ld is not fwd rank\n", TASK_BRD_RANK(task_brd));
        return (EC_FALSE);
    }

    if(des_tcid == TASK_BRD_TCID(task_brd)
    && (CMPI_ANY_COMM == des_comm || des_comm == TASK_BRD_COMM(task_brd)))
    {
        return (EC_TRUE);
    }

    if(TDNS_RESOLVE_SWITCH == SWITCH_ON)
    {
        if(EC_FALSE == c_tdns_resolve(des_tcid, &des_ipv4, &des_port))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_connect: tdns resolve tcid '%s' failed\n",
                                c_word_to_ipv4(des_tcid));

            /*DANGEROUS! if des_comm is any comm, all connections of tcid would be lost ...*/
            super_handle_broken_tcid_comm(super_md_id, des_tcid, des_comm);
            return (EC_FALSE);
        }

        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_connect: tdns resolve tcid '%s' => ip '%s', port %ld\n",
                            c_word_to_ipv4(des_tcid), c_word_to_ipv4(des_ipv4), des_port);
    }
    else
    {
        TASKS_CFG               *tasks_cfg;

        tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), des_tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);
        if(NULL_PTR == tasks_cfg)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "warn:super_connect: tcid '%s' not configured\n",
                                                 c_word_to_ipv4(des_tcid));
            return (EC_FALSE);
        }

        des_ipv4 = TASKS_CFG_SRVIPADDR(tasks_cfg);
        des_port = TASKS_CFG_SRVPORT(tasks_cfg);

        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_connect: configured tcid '%s' => ip '%s', port %ld\n",
                            c_word_to_ipv4(des_tcid), c_word_to_ipv4(des_ipv4), des_port);
    }

    if(EC_FALSE == task_brd_register_one(task_brd, des_tcid, des_ipv4, des_port, conn_num))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_connect: register to (tcid '%s', ip '%s', port %ld) failed\n",
                            c_word_to_ipv4(des_tcid), c_word_to_ipv4(des_ipv4), des_port);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
* add socket connection
*
**/
void super_add_connection(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 des_comm, const UINT32 des_srv_ipaddr, const UINT32 des_srv_port, const UINT32 conn_num)
{
    //UINT32     csocket_cnode_idx;
    TASK_BRD  *task_brd;
    //TASKS_CFG *local_tasks_cfg;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_add_connection: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(CMPI_FWD_RANK != TASK_BRD_RANK(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_add_connection: current rank %ld is not fwd rank\n", TASK_BRD_RANK(task_brd));
        return;
    }

    if(des_tcid == TASK_BRD_TCID(task_brd)
    && (CMPI_ANY_COMM == des_comm || des_comm == TASK_BRD_COMM(task_brd)))
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "warn:super_add_connection: giveup connect to itself\n");
        return;
    }

    task_brd_register_one(task_brd, des_tcid, des_srv_ipaddr, des_srv_port, conn_num);

    return;
}

/**
*
* execute shell command and return output as CSTRING
*
**/
void super_run_shell(const UINT32 super_md_id, const CSTRING *cmd_line, LOG *log)
{
    FILE   *rstream;
    CSTRING *result;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_run_shell: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_run_shell: execute shell command: %s\n", (char *)cstring_get_str(cmd_line));

    rstream = popen((char *)cstring_get_str(cmd_line), "r");

    result = cstring_new(NULL_PTR, LOC_SUPER_0060);
    cstring_set_capacity(result, 4096);/*4KB*/

    cstring_fread(result, rstream);

    pclose( rstream );

    //dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_run_shell: shell command output:\n %s\n", (char *)cstring_get_str(result));/*debug*/
    sys_print(log, "%s", (char *)cstring_get_str(result));
    cstring_free(result);

    return;
}


/**
*
* execute shell command and return output as CBYTES
*
**/
EC_BOOL super_exec_shell(const UINT32 super_md_id, const CSTRING *cmd_line, CBYTES *cbytes)
{
    FILE   *rstream;
    CSTRING *cmd_line_fix;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    cmd_line_fix = cstring_new(cstring_get_str(cmd_line), LOC_SUPER_0061);
    cstring_append_str(cmd_line_fix, (UINT8 *)" 2>&1");/*fix*/

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_exec_shell: execute shell command: %s\n", (char *)cstring_get_str(cmd_line_fix));

    rstream = popen((char *)cstring_get_str(cmd_line_fix), "r");

    //cbytes_expand_to(cbytes, 4096);/*4KB*/
    cbytes_fread(cbytes, rstream);

    pclose( rstream );

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDNULL, "super_exec_shell: execute shell command: \"%s\", output len %ld, content is\n%.*s\n",
                        (char *)cstring_get_str(cmd_line_fix), cbytes_len(cbytes),
                        (uint32_t)cbytes_len(cbytes), cbytes_buf(cbytes));

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_exec_shell: execute shell command: \"%s\", output len %ld\n",
                        (char *)cstring_get_str(cmd_line_fix), cbytes_len(cbytes));

    cstring_free(cmd_line_fix);
    return (EC_TRUE);
}

EC_BOOL super_exec_shell_tcid_cstr(const UINT32 super_md_id, const CSTRING *tcid_cstr, const CSTRING *cmd_line, CBYTES *output_cbytes)
{
    UINT32    tcid;
    MOD_NODE  recv_mod_node;

    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_tcid_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_exec_shell_tcid_cstr: execute shell command on tcid %s: %s\n",
                        (char *)cstring_get_str(tcid_cstr),
                        (char *)cstring_get_str(cmd_line));

    tcid = c_ipv4_to_word((char *)cstring_get_str(tcid_cstr));
    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_exec_shell(super_md_id, cmd_line, output_cbytes);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_tcid_cstr: tcid %s not connected\n", (char *)cstring_get_str(tcid_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_exec_shell, CMPI_ERROR_MODI, cmd_line, output_cbytes);
    return (ret);
}

/**
*
* execute shell command on several taskcomm and return each output as CBYTES
*
**/
EC_BOOL super_exec_shell_vec(const UINT32 super_md_id, const CVECTOR *tcid_vec, const CVECTOR *cmd_line_vec, CVECTOR *output_cbytes_vec)
{
    UINT32 tcid_num;
    UINT32 cmd_line_num;
    UINT32 pos;

    TASK_MGR *task_mgr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_vec: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    tcid_num = cvector_size(tcid_vec);
    cmd_line_num = cvector_size(cmd_line_vec);

    if(tcid_num != cmd_line_num)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec: mismatched tcid vec size %ld and cmd line vec size %ld\n", tcid_num, cmd_line_num);
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(pos = 0; pos < tcid_num; pos ++)
    {
        UINT32   tcid;
        CSTRING *cmd_line;
        CBYTES  *output_cbytes;

        MOD_NODE recv_mod_node;

        tcid = (UINT32)cvector_get_no_lock(tcid_vec, pos);
        cmd_line = (CSTRING *)cvector_get_no_lock(cmd_line_vec, pos);

        output_cbytes = cbytes_new(0);
        if(NULL_PTR == output_cbytes)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec: new output cbytes failed\n");
            cvector_clean_no_lock(output_cbytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_SUPER_0062);
            return (EC_FALSE);
        }

        cvector_push_no_lock(output_cbytes_vec, (void *)output_cbytes);

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, NULL_PTR, FI_super_exec_shell, CMPI_ERROR_MODI, cmd_line, output_cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (EC_TRUE);
}



/**
*
* execute shell command on several taskcomm and return each output as CBYTES
* note: where tcid_cstr_vec is tcid STRING vector
**/
EC_BOOL super_exec_shell_vec_tcid_cstr(const UINT32 super_md_id, const CVECTOR *tcid_cstr_vec, const CSTRING *cmd_line, CVECTOR *output_cbytes_vec)
{
    UINT32 tcid_pos;

    TASK_MGR *task_mgr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_vec_tcid_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(tcid_pos = 0; tcid_pos < cvector_size(tcid_cstr_vec); tcid_pos ++)
    {
        CSTRING *tcid_cstr;
        UINT32   tcid;
        CBYTES  *output_cbytes;

        MOD_NODE recv_mod_node;

        tcid_cstr = (CSTRING *)cvector_get_no_lock(tcid_cstr_vec, tcid_pos);
        tcid      = c_ipv4_to_word((char *)cstring_get_str(tcid_cstr));

        output_cbytes = cbytes_new(0);
        if(NULL_PTR == output_cbytes)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec_tcid_cstr: new output cbytes failed\n");
            cvector_clean_no_lock(output_cbytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_SUPER_0063);
            task_mgr_free(task_mgr);
            return (EC_FALSE);
        }

        /*if tcid not reachable, empty cbytes will return*/
        cvector_push_no_lock(output_cbytes_vec, (void *)output_cbytes);

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec_tcid_cstr: tcid %s not connected, skip it\n", (char *)cstring_get_str(tcid_cstr));
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, NULL_PTR, FI_super_exec_shell, CMPI_ERROR_MODI, cmd_line, output_cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    //dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_exec_shell_vec_tcid_cstr: result is\n");
    //cvector_print(LOGSTDOUT, output_cbytes_vec, (CVECTOR_DATA_PRINT)cbytes_print_str);

    return (EC_TRUE);
}

EC_BOOL super_exec_shell_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *cmd_line, CBYTES *output_cbytes)
{
    UINT32   ipaddr;
    UINT32   tcid;
    MOD_NODE recv_mod_node;

    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(cmd_line))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr:cmd_line is empty\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_exec_shell_ipaddr_cstr: execute shell command on ipaddr %s: %s\n",
                        (char *)cstring_get_str(ipaddr_cstr),
                        (char *)cstring_get_str(cmd_line));

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid = task_brd_get_tcid_by_ipaddr(task_brd_default_get(), ipaddr);
    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr: no tcid for ipaddr %s failed\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_exec_shell(super_md_id, cmd_line, output_cbytes);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr: ipaddr %s not connected\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_exec_shell, CMPI_ERROR_MODI, cmd_line, output_cbytes);
    return (ret);
}

EC_BOOL super_exec_shell_vec_ipaddr_cstr(const UINT32 super_md_id, const CVECTOR *ipaddr_cstr_vec, const CSTRING *cmd_line, CVECTOR *output_cbytes_vec)
{
    UINT32 ipaddr_pos;

    TASK_BRD *task_brd;
    TASK_MGR *task_mgr;

    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_vec_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(cmd_line))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec_ipaddr_cstr:cmd_line is empty\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(ipaddr_pos = 0; ipaddr_pos < cvector_size(ipaddr_cstr_vec); ipaddr_pos ++)
    {
        CSTRING *ipaddr_cstr;
        UINT32   ipaddr;
        UINT32   tcid;
        CBYTES  *output_cbytes;

        MOD_NODE recv_mod_node;

        ipaddr_cstr = (CSTRING *)cvector_get_no_lock(ipaddr_cstr_vec, ipaddr_pos);
        ipaddr      = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
        tcid        = task_brd_get_tcid_by_ipaddr(task_brd, ipaddr);

        output_cbytes = cbytes_new(0);
        if(NULL_PTR == output_cbytes)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec_ipaddr_cstr: new output cbytes failed\n");
            cvector_clean_no_lock(output_cbytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_SUPER_0064);
            task_mgr_free(task_mgr);
            return (EC_FALSE);
        }

        /*if ipaddr not reachable, empty cbytes will return*/
        cvector_push_no_lock(output_cbytes_vec, (void *)output_cbytes);

        if(CMPI_ERROR_TCID == tcid)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec_ipaddr_cstr: no tcid for ipaddr %s\n", (char *)cstring_get_str(ipaddr_cstr));
        }

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_vec_ipaddr_cstr: ipaddr %s not connected, skip it\n", (char *)cstring_get_str(ipaddr_cstr));
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, &ret, FI_super_exec_shell, CMPI_ERROR_MODI, cmd_line, output_cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    //dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_exec_shell_vec_ipaddr_cstr: result is\n");
    //cvector_print(LOGSTDOUT, output_cbytes_vec, (CVECTOR_DATA_PRINT)cbytes_print_str);

    return (EC_TRUE);
}

EC_BOOL super_exec_shell_cbtimer_reset(const UINT32 super_md_id, const CSTRING *cbtimer_name, const CSTRING *cmd_line, const UINT32 timeout)
{
    UINT32 timeout_func_id;
    CBTIMER_NODE   *cbtimer_node;
    FUNC_ADDR_NODE *func_addr_node;
    TASK_FUNC *handler;
    TASK_BRD  *task_brd;

    UINT32 mod_type;
    UINT32 delta;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_cbtimer_reset: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(cbtimer_name))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_reset:cbtimer_name is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(cmd_line))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_reset:cmd_line is empty\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    timeout_func_id = FI_super_exec_shell;
    mod_type = (timeout_func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDERR, "error:super_exec_shell_cbtimer_reset: invalid timeout_func_id %lx\n", timeout_func_id);
        return (EC_FALSE);
    }

    if(0 != dbg_fetch_func_addr_node_by_index(timeout_func_id, &func_addr_node))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_reset: failed to fetch func addr node by func id %lx\n", timeout_func_id);
        return (EC_FALSE);
    }

    cbtimer_node = cbtimer_search_by_name(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_name);
    if(NULL_PTR == cbtimer_node)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_reset: undefined cbtimer with name %s\n", (char *)cstring_get_str(cbtimer_name));
        return (EC_FALSE);
    }

    if(NULL_PTR != CBTIMER_NODE_NAME(cbtimer_node))
    {
        cstring_free(CBTIMER_NODE_NAME(cbtimer_node));
        CBTIMER_NODE_NAME(cbtimer_node) = NULL_PTR;
    }

    CBTIMER_NODE_NAME(cbtimer_node) = cstring_new(cstring_get_str(cbtimer_name), LOC_SUPER_0065);

    /*timeout < timeout + delta = expire_time < 2 * timeout*/
    /*delta should ensure timeout action must be executed once and only once, but not 100 percent :(*/
    delta = 60;
    if(delta >= timeout)
    {
        delta = (timeout / 2);
    }

    CBTIMER_NODE_EXPIRE_NSEC(cbtimer_node)   = timeout + delta;
    CBTIMER_NODE_TIMEOUT_NSEC(cbtimer_node)  = timeout;

    CBTIMER_NODE_EXPIRE_FUNC_ADDR_NODE(cbtimer_node)  = NULL_PTR;
    CBTIMER_NODE_TIMEOUT_FUNC_ADDR_NODE(cbtimer_node) = func_addr_node;

    handler = CBTIMER_NODE_TIMEOUT_HANDLER(cbtimer_node);

    handler->func_id       = timeout_func_id;
    handler->func_para_num = func_addr_node->func_para_num;
    handler->func_ret_val  = EC_TRUE;

    if(NULL_PTR != handler->func_para[ 1 ].para_val)
    {
        cstring_free((CSTRING *)(handler->func_para[ 1 ].para_val));
        handler->func_para[ 1 ].para_val = 0;
    }

    if(NULL_PTR != handler->func_para[ 2 ].para_val)
    {
        cbytes_free((CBYTES *)(handler->func_para[ 2 ].para_val));
        handler->func_para[ 2 ].para_val = 0;
    }

    handler->func_para[ 0 ].para_val = super_md_id;
    handler->func_para[ 1 ].para_val = (UINT32)cstring_new(cstring_get_str(cmd_line), LOC_SUPER_0066);
    handler->func_para[ 2 ].para_val = (UINT32)cbytes_new(0);

    CTIMET_GET(CBTIMER_NODE_START_TIME(cbtimer_node));
    CTIMET_GET(CBTIMER_NODE_LAST_TIME(cbtimer_node));
    return (EC_TRUE);
}

EC_BOOL super_exec_shell_cbtimer_set(const UINT32 super_md_id, const CSTRING *cbtimer_name, const CSTRING *cmd_line, const UINT32 timeout)
{
    UINT32 timeout_func_id;
    CBTIMER_NODE   *cbtimer_node;
    FUNC_ADDR_NODE *func_addr_node;
    TASK_FUNC *handler;
    TASK_BRD  *task_brd;

    UINT32 mod_type;
    UINT32 delta;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_cbtimer_set: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(cbtimer_name))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_set:cbtimer_name is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(cmd_line))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_set:cmd_line is empty\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    cbtimer_node = cbtimer_search_by_name(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_name);
    if(NULL_PTR != cbtimer_node)
    {
        dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_exec_shell_cbtimer_set: found cbtimer with name %s, try to reset it\n", (char *)cstring_get_str(cbtimer_name));
        return super_exec_shell_cbtimer_reset(super_md_id, cbtimer_name, cmd_line, timeout);
    }

    timeout_func_id = FI_super_exec_shell;
    mod_type = (timeout_func_id >> (WORDSIZE / 2));
    if( MD_END <= mod_type )
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDERR, "error:super_exec_shell_cbtimer_set: invalid timeout_func_id %lx\n", timeout_func_id);
        return (EC_FALSE);
    }

    if(0 != dbg_fetch_func_addr_node_by_index(timeout_func_id, &func_addr_node))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_set: failed to fetch func addr node by func id %lx\n", timeout_func_id);
        return (EC_FALSE);
    }

    cbtimer_node = cbtimer_node_new();
    if(NULL_PTR == cbtimer_node)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_set: new cbtimer node failed\n");
        return (EC_FALSE);
    }

    CBTIMER_NODE_NAME(cbtimer_node) = cstring_new(cstring_get_str(cbtimer_name), LOC_SUPER_0067);

    /*timeout < timeout + delta = expire_time < 2 * timeout*/
    /*delta should ensure timeout action must be executed once and only once, but not 100 percent :(*/
    delta = 60;
    if(delta >= timeout)
    {
        delta = (timeout / 2);
    }

    CBTIMER_NODE_EXPIRE_NSEC(cbtimer_node)   = timeout + delta;
    CBTIMER_NODE_TIMEOUT_NSEC(cbtimer_node)  = timeout;

    CBTIMER_NODE_EXPIRE_FUNC_ADDR_NODE(cbtimer_node)  = NULL_PTR;
    CBTIMER_NODE_TIMEOUT_FUNC_ADDR_NODE(cbtimer_node) = func_addr_node;

    handler = CBTIMER_NODE_TIMEOUT_HANDLER(cbtimer_node);

    handler->func_id       = timeout_func_id;
    handler->func_para_num = func_addr_node->func_para_num;
    handler->func_ret_val  = EC_TRUE;

    handler->func_para[ 0 ].para_val = super_md_id;
    handler->func_para[ 1 ].para_val = (UINT32)cstring_new(cstring_get_str(cmd_line), LOC_SUPER_0068);
    handler->func_para[ 2 ].para_val = (UINT32)cbytes_new(0);

    CTIMET_GET(CBTIMER_NODE_START_TIME(cbtimer_node));
    CTIMET_GET(CBTIMER_NODE_LAST_TIME(cbtimer_node));

    cbtimer_register(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_node);
    return (EC_TRUE);
}

EC_BOOL super_exec_shell_cbtimer_unset(const UINT32 super_md_id, const CSTRING *cbtimer_name)
{
    TASK_BRD     *task_brd;
    CBTIMER_NODE *cbtimer_node;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_cbtimer_unset: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(cbtimer_name))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_cbtimer_unset:cbtimer_name is empty\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();
    cbtimer_node = cbtimer_search_by_name(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_name);


    if(NULL_PTR != cbtimer_node)
    {
        cbtimer_unregister(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_node);
    }
    return (EC_TRUE);
}

EC_BOOL super_exec_shell_ipaddr_cstr_cbtimer_set(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *cbtimer_name, const CSTRING *cmd_line, const UINT32 timeout)
{
    UINT32   ipaddr;
    UINT32   tcid;
    MOD_NODE recv_mod_node;

    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_ipaddr_cstr_cbtimer_set: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr_cbtimer_set:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(cmd_line))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr_cbtimer_set:cmd_line is empty\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_exec_shell_ipaddr_cstr_cbtimer_set: execute shell command on ipaddr %s: %s with name %s and timeout %ld\n",
                        (char *)cstring_get_str(ipaddr_cstr),
                        (char *)cstring_get_str(cmd_line),
                        (char *)cstring_get_str(cbtimer_name),
                        timeout
                        );

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid = task_brd_get_tcid_by_ipaddr(task_brd_default_get(), ipaddr);
    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr_cbtimer_set: no tcid for ipaddr %s failed\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_exec_shell_cbtimer_set(super_md_id, cbtimer_name, cmd_line, timeout);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr_cbtimer_set: ipaddr %s not connected\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_exec_shell_cbtimer_set, CMPI_ERROR_MODI, cbtimer_name, cmd_line, timeout);
    return (ret);
}

EC_BOOL super_exec_shell_ipaddr_cstr_cbtimer_unset(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *cbtimer_name)
{
    UINT32   ipaddr;
    UINT32   tcid;
    MOD_NODE recv_mod_node;

    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_exec_shell_ipaddr_cstr_cbtimer_unset: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr_cbtimer_unset:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_exec_shell_ipaddr_cstr_cbtimer_set: cancel cbtimer %s on ipaddr %s\n",
                        (char *)cstring_get_str(cbtimer_name),
                        (char *)cstring_get_str(ipaddr_cstr)
                        );

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid = task_brd_get_tcid_by_ipaddr(task_brd_default_get(), ipaddr);
    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr_cbtimer_unset: no tcid for ipaddr %s failed\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_exec_shell_cbtimer_unset(super_md_id, cbtimer_name);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_exec_shell_ipaddr_cstr_cbtimer_unset: ipaddr %s not connected\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_exec_shell_cbtimer_unset, CMPI_ERROR_MODI, cbtimer_name);
    return (ret);
}
/**
*
* show rank load which is used for LOAD_BALANCING_RANK
*
**/
void super_show_rank_load(const UINT32 super_md_id, LOG *log)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_rank_load: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();
    cload_mgr_print(log, TASK_BRD_CLOAD_MGR(task_brd));
    return;
}

/**
*
* sync rank load which is used for LOAD_BALANCING_RANK
*
**/
void super_sync_rank_load(const UINT32 super_md_id, const UINT32 tcid, const UINT32 rank)
{
    MOD_MGR   *mod_mgr;

    MOD_NODE   recv_mod_node;
    CLOAD_STAT cload_stat;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_sync_rank_load: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    mod_mgr = mod_mgr_new(super_md_id, LOAD_BALANCING_LOOP);

    /*set mod_mgr*/
    mod_mgr_incl(tcid, CMPI_ANY_COMM, rank, 0, mod_mgr);

#if 1
    if(do_log(SEC_0117_SUPER, 5))
    {
        sys_log(LOGSTDOUT, "------------------------------------ super_sync_rank_load beg ----------------------------------\n");
        mod_mgr_print(LOGSTDOUT, mod_mgr);
        sys_log(LOGSTDOUT, "------------------------------------ super_sync_rank_load end ----------------------------------\n");
    }
#endif

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = rank;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    task_super_mono(mod_mgr, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    NULL_PTR, FI_super_sync_cload_stat, CMPI_ERROR_MODI, &cload_stat);

    task_brd_rank_load_set(task_brd_default_get(), tcid, CMPI_ANY_COMM, rank, &cload_stat);

    return;
}

/**
*
* forcely set rank load which is used for LOAD_BALANCING_RANK
*
**/
void super_set_rank_load(const UINT32 super_md_id, const UINT32 tcid, const UINT32 rank, const CLOAD_STAT *cload_stat)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_rank_load: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd_rank_load_set(task_brd_default_get(), tcid, CMPI_ANY_COMM, rank, cload_stat);

    return;
}

/**
*
* enable task brd by setting its load to real load
*
**/
void super_enable_task_brd(const UINT32 super_md_id)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_enable_task_brd: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    TASK_BRD_ENABLE_FLAG(task_brd) = EC_TRUE;
    return;
}

/**
*
* disable task brd by setting its load to -1
*
**/
void super_disable_task_brd(const UINT32 super_md_id)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_disable_task_brd: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    TASK_BRD_ENABLE_FLAG(task_brd) = EC_FALSE;
    return;
}

/**
*
* heartbeat
*
**/
void super_heartbeat_on_node(const UINT32 super_md_id, const CLOAD_NODE *cload_node)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_heartbeat_on_node: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();
    cload_mgr_update(TASK_BRD_CLOAD_MGR(task_brd), cload_node);

    return;
}

void super_heartbeat_on_rank(const UINT32 super_md_id, const UINT32 tcid, const UINT32 comm, const UINT32 rank, const CLOAD_STAT *cload_stat)
{
    TASK_BRD  *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_heartbeat_on_rank: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    cload_mgr_set(TASK_BRD_CLOAD_MGR(task_brd), tcid, comm, rank, cload_stat);
    return;
}

void super_heartbeat_all(const UINT32 super_md_id, const CLOAD_MGR *cload_mgr)
{
    TASK_BRD  *task_brd;
    CLIST_DATA *clist_data;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_heartbeat_all: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    CLIST_LOOP_NEXT(cload_mgr, clist_data)
    {
        CLOAD_NODE *cload_node;
        cload_node = (CLOAD_NODE *)CLIST_DATA_DATA(clist_data);
        cload_mgr_update(TASK_BRD_CLOAD_MGR(task_brd), cload_node);
    }

    return;
}

void super_heartbeat_none(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_heartbeat_none: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    /*do nothing, only socket connection heartbeat was triggered*/
    return;
}

void super_show_version(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_version: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    sys_log(log, "[DEBUG] super_show_version: not support yet\n");
    return;
}

void super_show_vendor(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_vendor: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    sys_log(log, "[DEBUG] super_show_vendor: not support yet\n");
    return;
}

/**
*
* OS info
*
**/
UINT32 super_get_wordsize(const UINT32 super_md_id)/*wordsize in bits*/
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_get_wordsize: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    return ((UINT32)WORDSIZE);
}

void super_show_wordsize(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_show_wordsize: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    sys_log(log, "wordsize = %ld\n", (UINT32)WORDSIZE);

    return;
}

/**
*
* download from local disk to remote
*
**/
EC_BOOL super_download(const UINT32 super_md_id, const CSTRING *fname, CBYTES *cbytes)
{
    int fd;
    UINT32 fsize;
    UINT8 *fbuf;
    UINT32 offset;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_download: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(0 != access((char *)cstring_get_str(fname), F_OK | R_OK))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download: inaccessable file %s, errno = %d, errstr = %s\n",
                            (char *)cstring_get_str(fname), errno, strerror(errno));
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(fname), O_RDONLY, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download: open file %s to read failed, errno = %d, errstr = %s\n",
                            (char *)cstring_get_str(fname), errno, strerror(errno));
        return (EC_FALSE);
    }

    fsize = lseek(fd, 0, SEEK_END);
    if(ERR_FD == fsize)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download: seek and get file size of %s failed\n",
                           (char *)cstring_get_str(fname));
        c_file_close(fd);
        return (EC_FALSE);
    }

    fbuf = (UINT8 *)SAFE_MALLOC(fsize, LOC_SUPER_0069);
    if(NULL_PTR == fbuf)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download: alloc %ld bytes for file %s buffer failed\n",
                            fsize, (char *)cstring_get_str(fname));
        c_file_close(fd);
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, fbuf))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download: load %ld bytes from file %s to buffer failed\n",
                            fsize, (char *)cstring_get_str(fname));
        SAFE_FREE(fbuf, LOC_SUPER_0070);
        c_file_close(fd);
        return (EC_FALSE);
    }

    c_file_close(fd);

    cbytes_mount(cbytes, fsize, fbuf);

    return (EC_TRUE);
}

EC_BOOL super_download_tcid_cstr(const UINT32 super_md_id, const CSTRING *tcid_cstr, const CSTRING *fname, CBYTES *output_cbytes)
{
    UINT32    tcid;
    MOD_NODE  recv_mod_node;
    EC_BOOL   ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_download_tcid_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_download_tcid_cstr: execute download file %s on tcid %s\n",
                        (char *)cstring_get_str(fname),
                        (char *)cstring_get_str(tcid_cstr));

    tcid = c_ipv4_to_word((char *)cstring_get_str(tcid_cstr));
    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_download(super_md_id, fname, output_cbytes);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_tcid_cstr: tcid %s not connected\n", (char *)cstring_get_str(tcid_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_download, CMPI_ERROR_MODI, fname, output_cbytes);
    return (ret);
}

/**
*
* download from local disk to remote
*
**/
EC_BOOL super_download_vec_tcid_cstr(const UINT32 super_md_id, const CVECTOR *tcid_cstr_vec, const CSTRING *fname, CVECTOR *output_cbytes_vec)
{
    UINT32 tcid_pos;

    TASK_MGR *task_mgr;
    EC_BOOL   ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_download_vec_tcid_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(tcid_pos = 0; tcid_pos < cvector_size(tcid_cstr_vec); tcid_pos ++)
    {
        CSTRING *tcid_cstr;
        UINT32   tcid;
        CBYTES  *output_cbytes;

        MOD_NODE recv_mod_node;

        tcid_cstr = (CSTRING *)cvector_get_no_lock(tcid_cstr_vec, tcid_pos);
        tcid      = c_ipv4_to_word((char *)cstring_get_str(tcid_cstr));

        output_cbytes = cbytes_new(0);
        if(NULL_PTR == output_cbytes)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_vec_tcid_cstr: new output cbytes failed\n");
            cvector_clean_no_lock(output_cbytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_SUPER_0071);
            task_mgr_free(task_mgr);
            return (EC_FALSE);
        }

        /*if tcid not reachable, empty cbytes will return*/
        cvector_push_no_lock(output_cbytes_vec, (void *)output_cbytes);

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_vec_tcid_cstr: tcid %s not connected, skip it\n", (char *)cstring_get_str(tcid_cstr));
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, &ret, FI_super_download, CMPI_ERROR_MODI, fname, output_cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    //dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_download_vec_tcid_cstr: result is\n");
    //cvector_print(LOGSTDOUT, output_cbytes_vec, (CVECTOR_DATA_PRINT)cbytes_print_str);

    return (EC_TRUE);
}

EC_BOOL super_download_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *fname, CBYTES *output_cbytes)
{
    UINT32    ipaddr;
    UINT32    tcid;
    TASK_BRD *task_brd;
    MOD_NODE  recv_mod_node;
    EC_BOOL   ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_download_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_ipaddr_cstr:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_ipaddr_cstr:fname cstr is empty\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_download_ipaddr_cstr: execute download file %s on ipaddr %s\n",
                        (char *)cstring_get_str(fname),
                        (char *)cstring_get_str(ipaddr_cstr));

    task_brd = task_brd_default_get();

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid   = task_brd_get_tcid_by_ipaddr(task_brd, ipaddr);
    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_ipaddr_cstr: no tcid for ipaddr %s\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_download(super_md_id, fname, output_cbytes);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_ipaddr_cstr: ipaddr %s not connected\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_download, CMPI_ERROR_MODI, fname, output_cbytes);
    return (ret);
}

EC_BOOL super_download_vec_ipaddr_cstr(const UINT32 super_md_id, const CVECTOR *ipaddr_cstr_vec, const CSTRING *fname, CVECTOR *output_cbytes_vec)
{
    UINT32 ipaddr_pos;

    TASK_BRD *task_brd;
    TASK_MGR *task_mgr;
    EC_BOOL   ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_download_vec_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_vec_ipaddr_cstr:fname cstr is empty\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(ipaddr_pos = 0; ipaddr_pos < cvector_size(ipaddr_cstr_vec); ipaddr_pos ++)
    {
        CSTRING *ipaddr_cstr;
        UINT32   ipaddr;
        UINT32   tcid;
        CBYTES  *output_cbytes;

        MOD_NODE recv_mod_node;

        ipaddr_cstr = (CSTRING *)cvector_get_no_lock(ipaddr_cstr_vec, ipaddr_pos);
        ipaddr      = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
        tcid        = task_brd_get_tcid_by_ipaddr(task_brd, ipaddr);

        output_cbytes = cbytes_new(0);
        if(NULL_PTR == output_cbytes)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_vec_ipaddr_cstr: new output cbytes failed\n");
            cvector_clean_no_lock(output_cbytes_vec, (CVECTOR_DATA_CLEANER)cbytes_free, LOC_SUPER_0072);
            task_mgr_free(task_mgr);
            return (EC_FALSE);
        }

        /*if ipaddr not reachable, empty cbytes will return*/
        cvector_push_no_lock(output_cbytes_vec, (void *)output_cbytes);

        if(CMPI_ERROR_TCID == tcid)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_vec_ipaddr_cstr: no tcid for ipaddr %s\n", (char *)cstring_get_str(ipaddr_cstr));
            continue;
        }

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd, tcid))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_download_vec_ipaddr_cstr: ipaddr %s not connected, skip it\n", (char *)cstring_get_str(ipaddr_cstr));
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, &ret, FI_super_download, CMPI_ERROR_MODI, fname, output_cbytes);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    //dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_download_vec_ipaddr_cstr: result is\n");
    //cvector_print(LOGSTDOUT, output_cbytes_vec, (CVECTOR_DATA_PRINT)cbytes_print_str);

    return (EC_TRUE);
}

EC_BOOL super_backup(const UINT32 super_md_id, const CSTRING *fname)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_backup: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_backup:fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(0 == access((char *)cstring_get_str(fname), F_OK))
    {
        CSTRING *cmd_line;

        cmd_line = cstring_new(NULL_PTR, LOC_SUPER_0073);
        if(NULL_PTR == cmd_line)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_backup: new cmd line failed\n");
            return (EC_FALSE);
        }

        cstring_format(cmd_line, "cp -p %s %s.bk",
                        (char *)cstring_get_str(fname), (char *)cstring_get_str(fname));
        if(EC_FALSE == exec_shell((char *)cstring_get_str(cmd_line), NULL_PTR, 0))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_backup: exec cmd %s failed\n", (char *)cstring_get_str(cmd_line));
            cstring_free(cmd_line);
            return (EC_FALSE);
        }
        cstring_free(cmd_line);
    }

    return (EC_TRUE);
}

/**
*
* upload from remote to local disk
*
**/
EC_BOOL super_upload(const UINT32 super_md_id, const CSTRING *fname, const CBYTES *cbytes, const UINT32 backup_flag)
{
    int fd;
    UINT32 fsize;
    UINT8 *fbuf;
    UINT32 offset;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_upload: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*( SWITCH_ON == SUPER_DEBUG_SWITCH )*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload:fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == backup_flag)
    {
        if(EC_FALSE == super_backup(super_md_id, fname))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload: backup file %s failed\n", (char *)cstring_get_str(fname));
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == super_rmv_file(super_md_id, fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload: rmv file %s failed\n", (char *)cstring_get_str(fname));
        return (EC_FALSE);
    }

    fsize = cbytes_len(cbytes);
    if(0 == fsize)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload: fsize is zero\n");
        return (EC_FALSE);
    }

    fbuf = cbytes_buf(cbytes);
    if(NULL_PTR == fbuf)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload: buf is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_basedir_create((char *)cstring_get_str(fname)))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload: create basedir of file %s failed\n", (char *)cstring_get_str(fname));
        return (EC_FALSE);
    }

    fd = c_file_open((char *)cstring_get_str(fname), O_WRONLY | O_CREAT, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload: open file %s to write failed, errno = %d, errstr = %s\n",
                            (char *)cstring_get_str(fname), errno, strerror(errno));
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_flush(fd, &offset, fsize, fbuf))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload: flush %ld bytes to file %s failed\n",
                            fsize, (char *)cstring_get_str(fname));
        c_file_close(fd);
        super_rmv_file(super_md_id, fname);/*remove it*/
        return (EC_FALSE);
    }

    c_file_close(fd);

    return (EC_TRUE);
}

EC_BOOL super_upload_tcid_cstr(const UINT32 super_md_id, const CSTRING *tcid_cstr, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag)
{
    UINT32    tcid;
    MOD_NODE  recv_mod_node;
    EC_BOOL   ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_upload_tcid_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_upload_tcid_cstr: execute upload command on tcid %s: %s\n",
                        (char *)cstring_get_str(tcid_cstr),
                        (char *)cstring_get_str(fname));

    tcid = c_ipv4_to_word((char *)cstring_get_str(tcid_cstr));
    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_upload(super_md_id, fname, input_cbytes, backup_flag);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_tcid_cstr: tcid %s not connected\n", (char *)cstring_get_str(tcid_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_upload, CMPI_ERROR_MODI, fname, input_cbytes, backup_flag);
    return (ret);
}

EC_BOOL super_upload_vec_tcid_cstr(const UINT32 super_md_id, const CVECTOR *tcid_cstr_vec, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag, CVECTOR *ret_vec)
{
    UINT32 pos;
    UINT32 tcid_pos;

    TASK_MGR *task_mgr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_upload_vec_tcid_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    for(pos = 0; pos < cvector_size(ret_vec); pos ++)
    {
        cvector_set_no_lock(ret_vec, pos, (void *)EC_FALSE);
    }

    for(;pos < cvector_size(tcid_cstr_vec); pos ++)
    {
        cvector_push_no_lock(ret_vec, (void *)EC_FALSE);
    }

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(tcid_pos = 0; tcid_pos < cvector_size(tcid_cstr_vec); tcid_pos ++)
    {
        CSTRING *tcid_cstr;
        UINT32   tcid;

        MOD_NODE recv_mod_node;
        UINT32  *ret;

        tcid_cstr = (CSTRING *)cvector_get_no_lock(tcid_cstr_vec, tcid_pos);
        tcid      = c_ipv4_to_word((char *)cstring_get_str(tcid_cstr));

        ret = (UINT32 *)cvector_get_addr_no_lock(ret_vec, tcid_pos);
        if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_vec_tcid_cstr: tcid %s not connected, skip it\n", (char *)cstring_get_str(tcid_cstr));
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, ret, FI_super_upload, CMPI_ERROR_MODI, fname, input_cbytes, backup_flag);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);


    return (EC_TRUE);
}

EC_BOOL super_upload_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag)
{
    UINT32    ipaddr;
    UINT32    tcid;
    TASK_BRD *task_brd;
    MOD_NODE  recv_mod_node;
    EC_BOOL   ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_upload_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_ipaddr_cstr:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_ipaddr_cstr:fname cstr is empty\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_upload_ipaddr_cstr: execute upload command on ipaddr %s: %s\n",
                        (char *)cstring_get_str(ipaddr_cstr),
                        (char *)cstring_get_str(fname));

    task_brd = task_brd_default_get();

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid   = task_brd_get_tcid_by_ipaddr(task_brd, ipaddr);

    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_ipaddr_cstr: no tcid for ipaddr %s\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_upload(super_md_id, fname, input_cbytes, backup_flag);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd, tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_ipaddr_cstr: ipaddr %s not connected\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_upload, CMPI_ERROR_MODI, fname, input_cbytes, backup_flag);
    return (ret);
}

EC_BOOL super_upload_vec_ipaddr_cstr(const UINT32 super_md_id, const CVECTOR *ipaddr_cstr_vec, const CSTRING *fname, const CBYTES *input_cbytes, const UINT32 backup_flag, CVECTOR *ret_vec)
{
    UINT32 pos;
    UINT32 ipaddr_pos;

    TASK_BRD *task_brd;
    TASK_MGR *task_mgr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_upload_vec_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_vec_ipaddr_cstr:fname cstr is empty\n");
        return (EC_FALSE);
    }

    for(pos = 0; pos < cvector_size(ret_vec); pos ++)
    {
        cvector_set_no_lock(ret_vec, pos, (void *)EC_FALSE);
    }

    for(;pos < cvector_size(ipaddr_cstr_vec); pos ++)
    {
        cvector_push_no_lock(ret_vec, (void *)EC_FALSE);
    }

    task_brd = task_brd_default_get();

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(ipaddr_pos = 0; ipaddr_pos < cvector_size(ipaddr_cstr_vec); ipaddr_pos ++)
    {
        CSTRING *ipaddr_cstr;
        UINT32   ipaddr;
        UINT32   tcid;
        EC_BOOL *ret;

        MOD_NODE recv_mod_node;

        ipaddr_cstr = (CSTRING *)cvector_get_no_lock(ipaddr_cstr_vec, ipaddr_pos);
        ipaddr      = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
        tcid        = task_brd_get_tcid_by_ipaddr(task_brd, ipaddr);

        ret = (UINT32 *)cvector_get_addr_no_lock(ret_vec, ipaddr_pos);
        //dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_upload_vec_ipaddr_cstr: ret = %ld (%lx) <== %lx\n", (*ret), (*ret), ret);

        if(CMPI_ERROR_TCID == tcid)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_vec_ipaddr_cstr: no tcid for ipaddr %s\n", (char *)cstring_get_str(ipaddr_cstr));
            continue;
        }

        if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_upload_vec_ipaddr_cstr: ipaddr %s not connected, skip it\n", (char *)cstring_get_str(ipaddr_cstr));
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, ret, FI_super_upload, CMPI_ERROR_MODI, fname, input_cbytes, backup_flag);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL super_collect_vec_ipaddr_cstr(const UINT32 super_md_id, CVECTOR *ipaddr_cstr_vec)
{
    TASK_BRD *task_brd;
    CVECTOR  *ipaddr_vec;

    UINT32 pos;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_collect_vec_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();
    ipaddr_vec = cvector_new(0, MM_UINT32, LOC_SUPER_0074);
    if(NULL_PTR == ipaddr_vec)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_collect_vec_ipaddr_cstr: new cvector failed\n");
        return (EC_FALSE);
    }

    task_brd_collect_ipaddr(task_brd, ipaddr_vec);

    for(pos = 0; pos < cvector_size(ipaddr_vec); pos ++)
    {
        UINT32 ipaddr;
        CSTRING *ipaddr_cstr;

        ipaddr = (UINT32)cvector_get_no_lock(ipaddr_vec, pos);
        ipaddr_cstr = (CSTRING *)cstring_new((UINT8 *)c_word_to_ipv4(ipaddr), LOC_SUPER_0075);
        if(NULL_PTR == ipaddr_cstr)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_collect_vec_ipaddr_cstr: new cstring failed\n");
            cvector_free(ipaddr_vec, LOC_SUPER_0076);
            return (EC_FALSE);
        }
        cvector_push_no_lock(ipaddr_cstr_vec, (void *)ipaddr_cstr);
    }
    cvector_free_no_lock(ipaddr_vec, LOC_SUPER_0077);
    return (EC_TRUE);
}

EC_BOOL super_write_fdata(const UINT32 super_md_id, const CSTRING *fname, const UINT32 offset, const CBYTES *cbytes)
{
    SUPER_FNODE *super_fnode;
    UINT32 cur_fsize;
    UINT32 write_offset;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_write_fdata: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_write_fdata:fname cstr is empty\n");
        return (EC_FALSE);
    }

    super_fnode = super_search_fnode_by_fname(super_md_id, fname);
    if(NULL_PTR == super_fnode)
    {
        super_fnode = super_open_fnode_by_fname(super_md_id, fname, SUPER_O_WRONLY | SUPER_O_CREAT);
    }

    if(NULL_PTR == super_fnode)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_write_fdata: open file %s failed\n", (char *)cstring_get_str(fname));
        return (EC_FALSE);
    }

    SUPER_FNODE_CMUTEX_LOCK(super_fnode, LOC_SUPER_0078);

    if(EC_FALSE == c_file_size(SUPER_FNODE_FD(super_fnode), &cur_fsize))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_write_fdata: get size of file %s failed\n", (char *)cstring_get_str(fname));
        SUPER_FNODE_CMUTEX_UNLOCK(super_fnode, LOC_SUPER_0079);
        return (EC_FALSE);
    }

    /*warning:not support disordered data writting!*/
    if(cur_fsize != offset && EC_FALSE == c_file_truncate(SUPER_FNODE_FD(super_fnode), offset))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_write_fdata: truncate file %s to %ld bytes failed\n", (char *)cstring_get_str(fname), offset);
        SUPER_FNODE_CMUTEX_UNLOCK(super_fnode, LOC_SUPER_0080);
        return (EC_FALSE);
    }

    write_offset = offset;
    if(EC_FALSE == c_file_flush(SUPER_FNODE_FD(super_fnode), &write_offset, cbytes_len(cbytes), cbytes_buf(cbytes)))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_write_fdata: flush %ld bytes at offset %ld of file %s failed\n",
                            cbytes_len(cbytes), write_offset, (char *)cstring_get_str(fname));
        SUPER_FNODE_CMUTEX_UNLOCK(super_fnode, LOC_SUPER_0081);
        return (EC_FALSE);
    }

    SUPER_FNODE_CMUTEX_UNLOCK(super_fnode, LOC_SUPER_0082);

    return (EC_TRUE);
}

EC_BOOL super_read_fdata(const UINT32 super_md_id, const CSTRING *fname, const UINT32 offset, const UINT32 max_len, CBYTES *cbytes)
{
    SUPER_FNODE *super_fnode;
    UINT32 read_offset;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_read_fdata: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_read_fdata:fname cstr is empty\n");
        return (EC_FALSE);
    }

    super_fnode = super_search_fnode_by_fname(super_md_id, fname);
    if(NULL_PTR == super_fnode)
    {
        super_fnode = super_open_fnode_by_fname(super_md_id, fname, SUPER_O_RDONLY);
    }

    if(NULL_PTR == super_fnode)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_read_fdata: open file %s failed\n", (char *)cstring_get_str(fname));
        return (EC_FALSE);
    }

    if(EC_FALSE == cbytes_resize(cbytes, max_len))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_read_fdata: cbytes resize to len %ld failed\n", max_len);
        return (EC_FALSE);
    }

    read_offset = offset;
    SUPER_FNODE_CMUTEX_LOCK(super_fnode, LOC_SUPER_0083);
    if(EC_FALSE == c_file_load(SUPER_FNODE_FD(super_fnode), &read_offset, max_len, cbytes_buf(cbytes)))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_read_fdata: load %ld bytes at offset %ld of file %s failed\n",
                            max_len, read_offset, (char *)cstring_get_str(fname));
        SUPER_FNODE_CMUTEX_UNLOCK(super_fnode, LOC_SUPER_0084);
        return (EC_FALSE);
    }

    SUPER_FNODE_CMUTEX_UNLOCK(super_fnode, LOC_SUPER_0085);

    return (EC_TRUE);
}

EC_BOOL super_set_progress(const UINT32 super_md_id, const CSTRING *fname, const REAL *progress)
{
    SUPER_FNODE *super_fnode;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_progress: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_progress:fname cstr is empty\n");
        return (EC_FALSE);
    }

    super_fnode = super_search_fnode_by_fname(super_md_id, fname);
    if(NULL_PTR == super_fnode)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_progress: not searched file %s\n", (char *)cstring_get_str(fname));
        return (EC_FALSE);
    }
    SUPER_FNODE_PROGRESS(super_fnode) = (*progress);
    return (EC_TRUE);
}

EC_BOOL super_get_progress(const UINT32 super_md_id, const CSTRING *fname, REAL *progress)
{
    SUPER_FNODE *super_fnode;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_get_progress: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_progress:fname cstr is empty\n");
        return (EC_FALSE);
    }

    super_fnode = super_search_fnode_by_fname(super_md_id, fname);
    if(NULL_PTR == super_fnode)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_progress: not searched file %s\n", (char *)cstring_get_str(fname));
        /*when the file was not on transfering, regard its progress is 100% */
        (*progress) = 1.0;
        return (EC_FALSE);
    }

    (*progress) = SUPER_FNODE_PROGRESS(super_fnode);
    return (EC_TRUE);
}

EC_BOOL super_size_file(const UINT32 super_md_id, const CSTRING *fname, UINT32 *fsize)
{
    SUPER_FNODE *super_fnode;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_size_file: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_size_file:fname cstr is empty\n");
        return (EC_FALSE);
    }

    /*search cached*/
    super_fnode = super_search_fnode_by_fname(super_md_id, fname);
    if(NULL_PTR != super_fnode)
    {
        return c_file_size(SUPER_FNODE_FD(super_fnode), fsize);
    }

    return (EC_FALSE);
}

EC_BOOL super_open_file(const UINT32 super_md_id, const CSTRING *fname, const UINT32 open_flags)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_open_file: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_open_file:fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == super_open_fnode_by_fname(super_md_id, fname, open_flags))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_open_file:open file %s with flags %lx failed\n",
                            (char *)cstring_get_str(fname), open_flags);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL super_close_file(const UINT32 super_md_id, const CSTRING *fname)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_close_file: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_close_file:fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == super_close_fnode_by_fname(super_md_id, fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_close_file:c_file_close file %s failed\n",
                            (char *)cstring_get_str(fname));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL super_rmv_file(const UINT32 super_md_id, const CSTRING *fname)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_rmv_file: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_rmv_file:fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(0 != access((char *)cstring_get_str(fname), F_OK))
    {
        dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_rmv_file: not exist file %s\n", (char *)cstring_get_str(fname));
        return (EC_TRUE);
    }

    if(0 != access((char *)cstring_get_str(fname), R_OK))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_rmv_file: not readable file %s, errno = %d, errstr = %s\n",
                            (char *)cstring_get_str(fname), errno, strerror(errno));
        return (EC_FALSE);
    }

    if(0 != unlink((char *)cstring_get_str(fname)))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_rmv_file: unlink file %s failed, errno = %d, errstr = %s\n",
                            (char *)cstring_get_str(fname), errno, strerror(errno));
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_rmv_file: removed file %s\n", (char *)cstring_get_str(fname));
    return (EC_TRUE);
}

EC_BOOL super_transfer_start(const UINT32 super_md_id, const CSTRING *src_fname, const UINT32 des_tcid, const CSTRING *des_fname)
{
    MOD_NODE recv_mod_node;
    EC_BOOL  ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer_start: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_start:src_fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_start:des_fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == super_open_file(super_md_id, src_fname, SUPER_O_RDONLY))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_start: open src file %s failed\n",
                           (char *)cstring_get_str(src_fname));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = des_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret, FI_super_open_file, CMPI_ERROR_MODI, des_fname, SUPER_O_WRONLY | SUPER_O_CREAT);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_start: open des file %s failed\n",
                           (char *)cstring_get_str(des_fname));
        super_close_file(super_md_id, src_fname);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL super_transfer_stop(const UINT32 super_md_id, const CSTRING *src_fname, const UINT32 des_tcid, const CSTRING *des_fname)
{
    MOD_NODE recv_mod_node;
    EC_BOOL  ret_src;
    EC_BOOL  ret_des;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer_stop: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_stop:src_fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_stop:des_fname cstr is empty\n");
        return (EC_FALSE);
    }

    ret_src = EC_TRUE;
    if(EC_FALSE == super_close_file(super_md_id, src_fname))
    {
        ret_src = EC_FALSE;
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_stop: c_file_close src file %s failed\n",
                           (char *)cstring_get_str(src_fname));
    }

    MOD_NODE_TCID(&recv_mod_node) = des_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret_des = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                    &recv_mod_node,
                    &ret_des, FI_super_close_file, CMPI_ERROR_MODI, des_fname);
    if(EC_FALSE == ret_des)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_stop: c_file_close des file %s failed\n",
                           (char *)cstring_get_str(des_fname));
    }

    if(EC_FALSE == ret_src || EC_FALSE == ret_des)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL super_transfer(const UINT32 super_md_id, const CSTRING *src_fname, const UINT32 des_tcid, const CSTRING *des_fname)
{
    UINT32 csize;/*read completed size*/
    UINT32 osize;/*read once size*/
    UINT32 rsize;
    MOD_NODE recv_mod_node;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer:src_fname cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer:des_fname cstr is empty\n");
        return (EC_FALSE);
    }

    /*when transfer file on current host to the same same, ignore it*/
    if(CMPI_LOCAL_TCID == des_tcid && EC_TRUE == cstring_is_equal(src_fname, des_fname))
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == super_transfer_start(super_md_id, src_fname, des_tcid, des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer: start transfer failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == super_size_file(super_md_id, src_fname, &rsize))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer: get size of file %s failed\n", (char *)cstring_get_str(src_fname));
        super_transfer_stop(super_md_id, src_fname, des_tcid, des_fname);
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = des_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    for(csize = 0, osize = SUPER_READ_ONCE_MAX_BYTES; csize < rsize; csize += osize)
    {
        CBYTES *cbytes;
        EC_BOOL ret;
        REAL    progress;

        if(csize + osize > rsize)
        {
            osize = rsize - csize;
        }

        cbytes = cbytes_new(osize);
        if(NULL_PTR == cbytes)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer: new cbytes with len %ld failed\n", osize);
            super_transfer_stop(super_md_id, src_fname, des_tcid, des_fname);
            return (EC_FALSE);
        }

        if(EC_FALSE == super_read_fdata(super_md_id, src_fname, csize, osize, cbytes))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer: read %ld bytes at offset %ld of src file %s failed\n",
                                osize, csize, (char *)cstring_get_str(src_fname));
            cbytes_free(cbytes);
            super_transfer_stop(super_md_id, src_fname, des_tcid, des_fname);
            return (EC_FALSE);
        }

        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                        &recv_mod_node,
                        &ret, FI_super_write_fdata, CMPI_ERROR_MODI, des_fname, csize, cbytes);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_write_fdata: write %ld bytes at offset %ld of des file %s failed\n",
                               osize, csize, (char *)cstring_get_str(des_fname));
            cbytes_free(cbytes);
            super_transfer_stop(super_md_id, src_fname, des_tcid, des_fname);
            return (EC_FALSE);
        }

        cbytes_free(cbytes);

        progress = (csize + 0.0) / (rsize + 0.0);
        super_set_progress(super_md_id, src_fname, &progress);
    }

    if(EC_FALSE == super_transfer_stop(super_md_id, src_fname, des_tcid, des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer: stop transfer failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL super_transfer_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *src_fname, const CSTRING *ipaddr_cstr, const CSTRING *des_fname)
{
    UINT32    ipaddr;
    UINT32    tcid;
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_ipaddr_cstr:src_fname is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_ipaddr_cstr:des_fname is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_ipaddr_cstr:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid   = task_brd_get_tcid_by_ipaddr(task_brd, ipaddr);

    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_ipaddr_cstr: no tcid for ipaddr %s\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    return super_transfer(super_md_id, src_fname, tcid, des_fname);
}

EC_BOOL super_transfer_vec_start(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *des_tcid_vec, const CSTRING *des_fname)
{
    UINT32   des_tcid_pos;
    EC_BOOL  ret;

    TASK_MGR *task_mgr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer_vec_start: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_start:src_fname is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_start:des_fname is empty\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == super_open_file(super_md_id, src_fname, SUPER_O_RDONLY))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_start: open src file %s failed\n",
                           (char *)cstring_get_str(src_fname));
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(des_tcid_pos = 0; des_tcid_pos < cvector_size(des_tcid_vec); des_tcid_pos ++)
    {
        UINT32 des_tcid;
        MOD_NODE recv_mod_node;

        des_tcid = (UINT32)cvector_get_no_lock(des_tcid_vec, des_tcid_pos);
        /*when transfer file on current host to the same same, ignore it*/
        if(CMPI_LOCAL_TCID == des_tcid && EC_TRUE == cstring_is_equal(src_fname, des_fname))
        {
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = des_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p_inc(task_mgr, super_md_id,
                    &recv_mod_node,
                    &ret, FI_super_open_file, CMPI_ERROR_MODI, des_fname, SUPER_O_WRONLY | SUPER_O_CREAT);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL super_transfer_vec_stop(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *des_tcid_vec, const CSTRING *des_fname)
{
    UINT32   des_tcid_pos;
    EC_BOOL  ret;

    TASK_MGR *task_mgr;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer_vec_stop: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_stop:src_fname is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_stop:des_fname is empty\n");
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(des_tcid_pos = 0; des_tcid_pos < cvector_size(des_tcid_vec); des_tcid_pos ++)
    {
        UINT32 des_tcid;
        MOD_NODE recv_mod_node;

        des_tcid = (UINT32)cvector_get_no_lock(des_tcid_vec, des_tcid_pos);
        /*when transfer file on current host to the same same, ignore it*/
        if(CMPI_LOCAL_TCID == des_tcid && EC_TRUE == cstring_is_equal(src_fname, des_fname))
        {
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = des_tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p_inc(task_mgr, super_md_id,
                    &recv_mod_node,
                    &ret, FI_super_close_file, CMPI_ERROR_MODI, des_fname);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);


    if(EC_FALSE == super_close_file(super_md_id, src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_stop: c_file_close src file %s failed\n",
                           (char *)cstring_get_str(src_fname));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_transfer_prepare(const CVECTOR *des_tcid_vec, CVECTOR *ret_vec)
{
    UINT32 pos;

    for(pos = 0; pos < cvector_size(ret_vec); pos ++)
    {
        UINT32 des_tcid;
        des_tcid = (UINT32)cvector_get_no_lock(des_tcid_vec, pos);
#if 0
        /*check connectivity*/
        if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), des_tcid))
        {
            dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "warn:__super_transfer_prepare: tcid %s not connected, skip it\n", c_word_to_ipv4(des_tcid));
            cvector_set_no_lock(ret_vec, pos, (void *)EC_FALSE);
        }
        else
        {
            cvector_set_no_lock(ret_vec, pos, (void *)EC_TRUE);
        }
#endif

#if 1
        if(CMPI_ERROR_TCID == des_tcid)
        {
            cvector_set_no_lock(ret_vec, pos, (void *)EC_FALSE);
        }
        else
        {
            cvector_set_no_lock(ret_vec, pos, (void *)EC_TRUE);
        }
#endif
    }

    for(pos = cvector_size(ret_vec); pos < cvector_size(des_tcid_vec); pos ++)
    {
        UINT32 des_tcid;
        des_tcid = (UINT32)cvector_get_no_lock(des_tcid_vec, pos);
#if 0
        /*check connectivity*/
        if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), des_tcid))
        {
            dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "warn:__super_transfer_prepare: tcid %s not connected, skip it\n", c_word_to_ipv4(des_tcid));
            cvector_push_no_lock(ret_vec, (void *)EC_FALSE);
        }
        else
        {
            cvector_push_no_lock(ret_vec, (void *)EC_TRUE);
        }
#endif
#if 1
        if(CMPI_ERROR_TCID == des_tcid)
        {
            cvector_push_no_lock(ret_vec, (void *)EC_FALSE);
        }
        else
        {
            cvector_push_no_lock(ret_vec, (void *)EC_TRUE);
        }
#endif
    }
    return (EC_TRUE);
}

EC_BOOL super_transfer_vec(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *des_tcid_vec, const CSTRING *des_fname, CVECTOR *ret_vec)
{
    UINT32 csize;/*read completed size*/
    UINT32 osize;/*read once size*/
    UINT32 rsize;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer_vec: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec:src_fname is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec:des_fname is empty\n");
        return (EC_FALSE);
    }

    __super_transfer_prepare(des_tcid_vec, ret_vec);

    if(EC_FALSE == super_transfer_vec_start(super_md_id, src_fname, des_tcid_vec, des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec: start transfer failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == super_size_file(super_md_id, src_fname, &rsize))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec: get size of file %s failed\n", (char *)cstring_get_str(src_fname));
        super_transfer_vec_stop(super_md_id, src_fname, des_tcid_vec, des_fname);
        return (EC_FALSE);
    }

    for(csize = 0, osize = SUPER_READ_ONCE_MAX_BYTES; csize < rsize; csize += osize)
    {
        CBYTES   *cbytes;
        TASK_MGR *task_mgr;
        UINT32 des_tcid_pos;

        if(csize + osize > rsize)
        {
            osize = rsize - csize;
        }

        cbytes = cbytes_new(osize);
        if(NULL_PTR == cbytes)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec: new cbytes with len %ld failed\n", osize);
            super_transfer_vec_stop(super_md_id, src_fname, des_tcid_vec, des_fname);
            return (EC_FALSE);
        }

        if(EC_FALSE == super_read_fdata(super_md_id, src_fname, csize, osize, cbytes))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec: read %ld bytes at offset %ld of src file %s failed\n",
                                osize, csize, (char *)cstring_get_str(src_fname));
            cbytes_free(cbytes);
            super_transfer_vec_stop(super_md_id, src_fname, des_tcid_vec, des_fname);
            return (EC_FALSE);
        }

        task_mgr = task_new(NULL, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
        for(des_tcid_pos = 0; des_tcid_pos < cvector_size(des_tcid_vec); des_tcid_pos ++)
        {
            MOD_NODE recv_mod_node;
            UINT32   des_tcid;
            UINT32  *ret;

            ret = (UINT32 *)cvector_get_addr_no_lock(ret_vec, des_tcid_pos);/*get address!*/
            if(EC_FALSE == (*ret))/*give up if it failed before*/
            {
                continue;
            }

            des_tcid = (UINT32)cvector_get_no_lock(des_tcid_vec, des_tcid_pos);
            /*when transfer file on current host to the same same, ignore it*/
            if(CMPI_LOCAL_TCID == des_tcid && EC_TRUE == cstring_is_equal(src_fname, des_fname))
            {
                continue;
            }

            MOD_NODE_TCID(&recv_mod_node) = des_tcid;
            MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0;

            task_p2p_inc(task_mgr, super_md_id,
                        &recv_mod_node,
                        ret, FI_super_write_fdata, CMPI_ERROR_MODI, des_fname, csize, cbytes);
        }
        task_wait(task_mgr, TASK_ALWAYS_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        cbytes_free(cbytes);
    }

    if(EC_FALSE == super_transfer_vec_stop(super_md_id, src_fname, des_tcid_vec, des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec: stop transfer failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL super_transfer_vec_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *src_fname, const CVECTOR *ipaddr_cstr_vec, const CSTRING *des_fname, CVECTOR *ret_vec)
{
    UINT32    pos;

    TASK_BRD *task_brd;
    CVECTOR  *tcid_vec;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_transfer_vec_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/
    if(EC_TRUE == cstring_is_empty(src_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_ipaddr_cstr:src_fname is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(des_fname))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_ipaddr_cstr:des_fname is empty\n");
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    tcid_vec = cvector_new(0, MM_UINT32, LOC_SUPER_0086);
    if(NULL_PTR == tcid_vec)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_ipaddr_cstr: new tcid vec failed\n");
        return (EC_FALSE);
    }

    for(pos = 0; pos < cvector_size(ipaddr_cstr_vec); pos ++)
    {
        CSTRING * ipaddr_cstr;
        UINT32    ipaddr;
        UINT32    tcid;

        ipaddr_cstr = (CSTRING *)cvector_get_no_lock(ipaddr_cstr_vec, pos);
        if(NULL_PTR == ipaddr_cstr)
        {
            continue;
        }

        ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
        tcid   = task_brd_get_tcid_by_ipaddr(task_brd, ipaddr);

        if(CMPI_ERROR_TCID == tcid)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_ipaddr_cstr: no tcid for ipaddr %s\n", (char *)cstring_get_str(ipaddr_cstr));
            continue;
        }

        cvector_push_no_lock(tcid_vec, (void *)tcid);
    }

    if(EC_FALSE == super_transfer_vec(super_md_id, src_fname, tcid_vec, des_fname, ret_vec))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_transfer_vec_ipaddr_cstr: transfer to tcid vec failed\n");
        cvector_free(tcid_vec, LOC_SUPER_0087);
        return (EC_FALSE);
    }
    cvector_free(tcid_vec, LOC_SUPER_0088);
    return (EC_TRUE);
}

EC_BOOL super_start_mcast_udp_server(const UINT32 super_md_id)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_start_mcast_udp_server: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(EC_FALSE == task_brd_is_mcast_udp_server(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_start_mcast_udp_server: I am not mcast udp server\n");
        return (EC_FALSE);
    }

    /*when not running, start it*/
    if(EC_FALSE == task_brd_status_mcast_udp_server(task_brd))
    {
        if(EC_FALSE == task_brd_start_mcast_udp_server(task_brd))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_start_mcast_udp_server: start mcast udp server failed\n");
            return (EC_FALSE);
        }
    }

    /*patch: for auto-connection the broken nodes*/
    super_activate_sys_cfg(super_md_id);

    return (EC_TRUE);
}

EC_BOOL super_stop_mcast_udp_server(const UINT32 super_md_id)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_stop_mcast_udp_server: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(EC_FALSE == task_brd_is_mcast_udp_server(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_stop_mcast_udp_server: I am not mcast udp server\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == task_brd_stop_mcast_udp_server(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_stop_mcast_udp_server: start mcast udp server failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL super_status_mcast_udp_server(const UINT32 super_md_id)
{
    TASK_BRD *task_brd;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_status_mcast_udp_server: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    if(EC_FALSE == task_brd_is_mcast_udp_server(task_brd))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_status_mcast_udp_server: I am not mcast udp server\n");
        return (EC_FALSE);
    }

    return task_brd_status_mcast_udp_server(task_brd);
}

EC_BOOL super_set_hostname(const UINT32 super_md_id, const CSTRING *hostname_cstr)
{
    char set_hostname_cmd[SUPER_CMD_BUFF_MAX_SIZE];
    const char *network_fname   = "/etc/sysconfig/network";
    const char *gmond_cfg_fname = "/usr/local/etc/gmond.conf";

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_hostname: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(hostname_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname: hostname cstr is empty\n");
        return (EC_FALSE);
    }

    snprintf(set_hostname_cmd, SUPER_CMD_BUFF_MAX_SIZE, "hostname %s", (char *)cstring_get_str(hostname_cstr));
    if(EC_FALSE == exec_shell(set_hostname_cmd, NULL_PTR, 0))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname: exec shell %s failed\n", set_hostname_cmd);
        return (EC_FALSE);
    }
    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_set_hostname: exec shell %s\n", set_hostname_cmd);

    if(0 == access(network_fname, F_OK | W_OK))
    {
        snprintf(set_hostname_cmd, SUPER_CMD_BUFF_MAX_SIZE, "sed -i s/HOSTNAME=.*/HOSTNAME=%s/g %s",
                 (char *)cstring_get_str(hostname_cstr), network_fname);
        if(EC_FALSE == exec_shell(set_hostname_cmd, NULL_PTR, 0))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname: exec shell %s failed\n", set_hostname_cmd);
            return (EC_FALSE);
        }
        dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_set_hostname: exec shell %s\n", set_hostname_cmd);
    }
    else
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "warn:super_set_hostname: %s not accessiable\n", network_fname);
    }

    if(0 == access(gmond_cfg_fname, F_OK | W_OK))
    {
        snprintf(set_hostname_cmd, SUPER_CMD_BUFF_MAX_SIZE, "sed -i \"/override_hostname/c\\  override_hostname = %s\" %s",
                (char *)cstring_get_str(hostname_cstr), gmond_cfg_fname);
        if(EC_FALSE == exec_shell(set_hostname_cmd, NULL_PTR, 0))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname: exec shell %s failed\n", set_hostname_cmd);
            return (EC_FALSE);
        }
        dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_set_hostname: exec shell %s\n", set_hostname_cmd);
    }
    else
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "warn:super_set_hostname: %s not accessiable\n", gmond_cfg_fname);
    }

    if(0 != sethostname((char *)cstring_get_str(hostname_cstr), cstring_get_len(hostname_cstr)))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname: sethostname %s failed\n", (char *)cstring_get_str(hostname_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL super_get_hostname(const UINT32 super_md_id, CSTRING *hostname_cstr)
{
    //const char *get_hostname_cmd = "hostname";
    char hostname[SUPER_CMD_BUFF_MAX_SIZE];

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_get_hostname: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(NULL_PTR == hostname_cstr)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_hostname: hostname cstr is null\n");
        return (EC_FALSE);
    }

    BSET(hostname, 0, SUPER_CMD_BUFF_MAX_SIZE);
#if 0
    if(EC_FALSE == exec_shell(get_hostname_cmd, hostname, SUPER_CMD_BUFF_MAX_SIZE))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_hostname: exec shell %s failed\n", get_hostname_cmd);
        return (EC_FALSE);
    }

    hostname[ strlen(hostname) - 1 ] = '\0'; /*discard the \r\n*/
#endif

    if(0 != gethostname(hostname, SUPER_CMD_BUFF_MAX_SIZE))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_hostname: gethostname failed\n");
        return (EC_FALSE);
    }

    cstring_format(hostname_cstr, "%s", hostname);

    return (EC_TRUE);
}

EC_BOOL super_set_hostname_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, const CSTRING *hostname_cstr)
{
    UINT32   ipaddr;
    UINT32   tcid;
    MOD_NODE recv_mod_node;

    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_hostname_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname_ipaddr_cstr:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cstring_is_empty(hostname_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname_ipaddr_cstr:hostname cstr is empty\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_set_hostname_ipaddr_cstr: set hostname on ipaddr %s: %s\n",
                        (char *)cstring_get_str(ipaddr_cstr),
                        (char *)cstring_get_str(hostname_cstr));

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid = task_brd_get_tcid_by_ipaddr(task_brd_default_get(), ipaddr);
    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname_ipaddr_cstr: no tcid for ipaddr %s failed\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_set_hostname(super_md_id, hostname_cstr);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_hostname_ipaddr_cstr: ipaddr %s not connected\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_set_hostname, CMPI_ERROR_MODI, hostname_cstr);
    return (ret);
}

EC_BOOL super_get_hostname_ipaddr_cstr(const UINT32 super_md_id, const CSTRING *ipaddr_cstr, CSTRING *hostname_cstr)
{
    UINT32   ipaddr;
    UINT32   tcid;
    MOD_NODE recv_mod_node;

    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_get_hostname_ipaddr_cstr: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(ipaddr_cstr))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_hostname_ipaddr_cstr:ipaddr cstr is empty\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == hostname_cstr)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_hostname_ipaddr_cstr:hostname cstr is null\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 5)(LOGSTDOUT, "super_get_hostname_ipaddr_cstr: get hostname on ipaddr %s\n",
                        (char *)cstring_get_str(ipaddr_cstr));

    ipaddr = c_ipv4_to_word((char *)cstring_get_str(ipaddr_cstr));
    tcid = task_brd_get_tcid_by_ipaddr(task_brd_default_get(), ipaddr);
    if(CMPI_ERROR_TCID == tcid)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_hostname_ipaddr_cstr: no tcid for ipaddr %s failed\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    if(CMPI_LOCAL_TCID == tcid)
    {
        return super_get_hostname(super_md_id, hostname_cstr);
    }

    if(EC_FALSE == task_brd_check_tcid_connected(task_brd_default_get(), tcid))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_hostname_ipaddr_cstr: ipaddr %s not connected\n", (char *)cstring_get_str(ipaddr_cstr));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, &recv_mod_node,
                &ret, FI_super_get_hostname, CMPI_ERROR_MODI, hostname_cstr);

    return (ret);
}

EC_BOOL super_say_hello(const UINT32 super_md_id, const UINT32 des_tcid, const UINT32 des_rank, CSTRING *cstring)
{
    MOD_NODE recv_mod_node;
    EC_BOOL ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_say_hello: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(CMPI_LOCAL_TCID == des_tcid && CMPI_LOCAL_RANK == des_rank)
    {
        cstring_format(cstring, "[%s] say hello!", c_word_to_ipv4(des_tcid));
        return (EC_TRUE);
    }

    MOD_NODE_TCID(&recv_mod_node) = des_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = des_rank;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    ret = EC_FALSE;
    task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
            &recv_mod_node,
            &ret, FI_super_say_hello, CMPI_ERROR_MODI, des_tcid, des_rank, cstring);
    return (ret);
}

EC_BOOL super_say_hello_batch(const UINT32 super_md_id, const UINT32 num, const UINT32 des_tcid, const UINT32 des_rank)
{
    TASK_MGR *task_mgr;
    MOD_NODE  recv_mod_node;
    UINT32    idx;

    CVECTOR  *report_vec;
    CVECTOR  *cstring_vec;
    EC_BOOL   result;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_say_hello_batch: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    MOD_NODE_TCID(&recv_mod_node) = des_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = des_rank;
    MOD_NODE_MODI(&recv_mod_node) = 0;

    report_vec  = cvector_new(0, MM_UINT32, LOC_SUPER_0089);
    cstring_vec = cvector_new(0, MM_CSTRING, LOC_SUPER_0090);

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(idx = 0; idx < num; idx ++)
    {
        UINT32 *ret;
        CSTRING *cstring;

        alloc_static_mem(MM_UINT32, &ret, LOC_SUPER_0091);
        cvector_push(report_vec, (void *)ret);

        cstring = cstring_new(NULL_PTR, LOC_SUPER_0092);
        cvector_push(cstring_vec, (void *)cstring);

        (*ret) = EC_FALSE;
        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node,
                     ret, FI_super_say_hello, CMPI_ERROR_MODI, des_tcid, des_rank, cstring);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    result = EC_TRUE;
    for(idx = 0; idx < num; idx ++)
    {
        UINT32 *ret;
        CSTRING *cstring;

        ret = (UINT32 *)cvector_get(report_vec, idx);
        cstring = (CSTRING *)cvector_get(cstring_vec, idx);

        if(EC_FALSE == (*ret))
        {
            result = EC_FALSE;
        }

        cvector_set(report_vec, idx, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_SUPER_0093);

        cvector_set(cstring_vec, idx, NULL_PTR);
        cstring_free(cstring);
    }

    cvector_free(report_vec, LOC_SUPER_0094);
    cvector_free(cstring_vec, LOC_SUPER_0095);

    return (result);
}

EC_BOOL super_say_hello_loop(const UINT32 super_md_id, const UINT32 loops, const UINT32 des_tcid, const UINT32 des_rank)
{
    UINT32   count;
    UINT32   step;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_say_hello_loop: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    for(count = 0, step = 1000; count + step < loops; count += step)
    {
        if(EC_FALSE == super_say_hello_batch(super_md_id, step, des_tcid, des_rank))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_say_hello_loop: say hello failed where count = %ld, step = %ld, loop = %ld\n", count, step, loops);
            return (EC_FALSE);
        }

        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_say_hello_loop: %ld - %ld done\n", count, count + step);
    }

    if(count < loops)
    {
        step = loops - count;
        if(EC_FALSE == super_say_hello_batch(super_md_id, step, des_tcid, des_rank))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_say_hello_loop: say hello failed where count = %ld, step = %ld, loop = %ld\n", count, step, loops);
            return (EC_FALSE);
        }

        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_say_hello_loop: %ld - %ld done\n", count, count + step);
    }
    return (EC_TRUE);
}

EC_BOOL super_say_hello_loop0(const UINT32 super_md_id, const UINT32 loops, const UINT32 des_tcid, const UINT32 des_rank)
{
    UINT32   count;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_say_hello_loop: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    for(count = 0; count < loops; count ++)
    {
        EC_BOOL  ret;
        CSTRING *cstring;

        cstring = cstring_new(NULL_PTR, LOC_SUPER_0096);
        ASSERT(NULL_PTR != cstring);
        ret = super_say_hello(super_md_id, des_tcid, des_rank, cstring);
        cstring_free(cstring);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_say_hello_loop: say hello failed where count = %ld, loop = %ld\n", count, loops);
            return (EC_FALSE);
        }

        if(0 == ((count + 1) % 1000))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_say_hello_loop: %ld - %ld done\n", count - 999, count);
        }
    }
    return (EC_TRUE);
}

/*------------------------------------------------------ test for ict -----------------------------------------------------------------------*/

#define __TCID_TO_ZONE_ID_MASK                         ((UINT32)0xFF)

#define __OBJ_DATA_BIT_OFFSET                          ((UINT32)(WORDSIZE / 2))

#define __GET_ZONE_ID_FROM_TCID(tcid)                  (((tcid) & __TCID_TO_ZONE_ID_MASK) - 1)

#define __MAKE_OBJ_ID(zone_id, zone_size, obj_idx)     ((zone_id) * (zone_size) + (obj_idx))

#define __MAKE_OBJ_DATA(obj_id, data_idx)              (((data_idx) << __OBJ_DATA_BIT_OFFSET) | (obj_id))

#define __MAKE_DES_TCID(tcid, zone_id)                 (((tcid) & (~__TCID_TO_ZONE_ID_MASK)) | ((zone_id) + 1))

#define __GET_ZONE_ID_FROM_OBJ_ID(obj_id, zone_size)   ((obj_id) / (zone_size))

#define __GET_OBJ_IDX_FROM_OBJ_ID(obj_id, zone_size)   ((obj_id) % (zone_size))

EC_BOOL super_set_zone_size(const UINT32 super_md_id, const UINT32 obj_zone_size)
{
    SUPER_MD  *super_md;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_zone_size: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);
    SUPER_MD_OBJ_ZONE_SIZE(super_md) = obj_zone_size;
    return (EC_TRUE);
}

EC_BOOL super_load_data(const UINT32 super_md_id)
{
    SUPER_MD  *super_md;

    TASK_BRD  *task_brd;
    UINT32     obj_zone_size;
    UINT32     obj_zone_id;
    UINT32     obj_idx;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_load_data: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);
    obj_zone_size = SUPER_MD_OBJ_ZONE_SIZE(super_md);

    task_brd = task_brd_default_get();
    obj_zone_id = __GET_ZONE_ID_FROM_TCID(TASK_BRD_TCID(task_brd));

    SUPER_MD_OBJ_ZONE(super_md) = cvector_new(obj_zone_size, MM_CVECTOR, LOC_SUPER_0097);
    if(NULL_PTR == SUPER_MD_OBJ_ZONE(super_md))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_load_data: new obj zone with size %ld failed\n", obj_zone_size);
        return (EC_FALSE);
    }

    for(obj_idx = 0; obj_idx < obj_zone_size; obj_idx ++)
    {
        CVECTOR *obj_vec;
        UINT32   obj_id;
        UINT32   obj_data_num;
        UINT32   obj_data_idx;

        obj_data_num = /*50*/5;

        obj_vec = cvector_new(obj_data_num, MM_UINT32, LOC_SUPER_0098);
        if(NULL_PTR == obj_vec)
        {
            EC_BOOL ret;

            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_load_data: new obj vec with size %ld failed\n", obj_data_num);

            cvector_loop(SUPER_MD_OBJ_ZONE(super_md),
                        (void *)&ret,
                        CVECTOR_CHECKER_DEFAULT,
                        2,
                        0,
                        (UINT32)cvector_free,
                        NULL_PTR,
                        LOC_SUPER_0099);
            cvector_free(SUPER_MD_OBJ_ZONE(super_md), LOC_SUPER_0100);
            return (EC_FALSE);
        }

        obj_id = __MAKE_OBJ_ID(obj_zone_id, SUPER_MD_OBJ_ZONE_SIZE(super_md), obj_idx);
        for(obj_data_idx = 0; obj_data_idx < obj_data_num; obj_data_idx ++)
        {
            UINT32 obj_data;
            obj_data = __MAKE_OBJ_DATA(obj_id, obj_data_idx);
            cvector_push_no_lock(obj_vec, (void *)obj_data);
        }

        cvector_push_no_lock(SUPER_MD_OBJ_ZONE(super_md), (void *)obj_vec);
    }

    return (EC_TRUE);
}

EC_BOOL super_load_data_all(const UINT32 super_md_id, const UINT32 obj_zone_num)
{
    TASK_BRD *task_brd;
    TASK_MGR *task_mgr;
    UINT32    obj_zone_id;
    UINT32    ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_load_data_all: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(obj_zone_id = 0; obj_zone_id < obj_zone_num; obj_zone_id ++)
    {
        UINT32 tcid;

        MOD_NODE recv_mod_node;

        tcid = __MAKE_DES_TCID(TASK_BRD_TCID(task_brd), obj_zone_id);
        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, &ret, FI_super_load_data, CMPI_ERROR_MODI);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL super_get_data(const UINT32 super_md_id, const UINT32 obj_id, CVECTOR *obj_data)
{
    SUPER_MD  *super_md;

    TASK_BRD  *task_brd;
    UINT32     obj_idx;
    CVECTOR   *obj_vec;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_get_data: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    task_brd = task_brd_default_get();

    /*check*/
    if(__GET_ZONE_ID_FROM_OBJ_ID(obj_id, SUPER_MD_OBJ_ZONE_SIZE(super_md)) !=  __GET_ZONE_ID_FROM_TCID(TASK_BRD_TCID(task_brd)))
    {
        //dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_data:mismatched obj_zone_id %lx and obj_id %lx\n", obj_zone_id, obj_id);
        //return (EC_FALSE);

        EC_BOOL ret;
        UINT32  tcid;
        MOD_NODE recv_mod_node;

        tcid = __MAKE_DES_TCID(TASK_BRD_TCID(task_brd), __GET_ZONE_ID_FROM_OBJ_ID(obj_id, SUPER_MD_OBJ_ZONE_SIZE(super_md)));
        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        ret = EC_FALSE;
        task_p2p(super_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                &recv_mod_node, &ret, FI_super_get_data, CMPI_ERROR_MODI, obj_id, obj_data);
        return (ret);
    }

    if(NULL_PTR == SUPER_MD_OBJ_ZONE(super_md))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_data:obj zone is null\n");
        return (EC_FALSE);
    }

    //dbg_log(SEC_0117_SUPER, 0)(LOGCONSOLE, "[DEBUG] super_get_data: obj_data %lx, mm type %ld\n", obj_data, obj_data->data_mm_type);

    obj_idx = __GET_OBJ_IDX_FROM_OBJ_ID(obj_id, SUPER_MD_OBJ_ZONE_SIZE(super_md));

    obj_vec = (CVECTOR *)cvector_get_no_lock(SUPER_MD_OBJ_ZONE(super_md), obj_idx);
    if(NULL_PTR == obj_vec)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_data: obj vec of obj id %ld or obj idx %ld is null\n", obj_id, obj_idx);
        return (EC_FALSE);
    }

    cvector_clone_no_lock(obj_vec, obj_data, NULL_PTR, NULL_PTR);

    //dbg_log(SEC_0117_SUPER, 0)(LOGCONSOLE, "[DEBUG] super_get_data: obj_vec %lx, mm type %ld\n", obj_vec, obj_vec->data_mm_type);
    //super_print_obj_vec(super_md_id, obj_vec, LOGCONSOLE);
    //dbg_log(SEC_0117_SUPER, 0)(LOGCONSOLE, "[DEBUG] super_get_data: obj_data %lx, mm type %ld\n", obj_data, obj_data->data_mm_type);
    //super_print_obj_vec(super_md_id, obj_data, LOGCONSOLE);

    return (EC_TRUE);
}

EC_BOOL super_get_data_vec(const UINT32 super_md_id, const CVECTOR *obj_id_vec, CVECTOR *obj_data_vec)
{
    SUPER_MD  *super_md;

    TASK_BRD *task_brd;
    TASK_MGR *task_mgr;
    UINT32    obj_id_pos;
    EC_BOOL   ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_get_data_vec: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    task_brd = task_brd_default_get();

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(obj_id_pos = 0; obj_id_pos < cvector_size(obj_id_vec); obj_id_pos ++)
    {
        UINT32 obj_id;
        UINT32 tcid;

        CVECTOR *obj_data;

        MOD_NODE recv_mod_node;

        obj_data = cvector_new(0, MM_UINT32, LOC_SUPER_0101);
        if(NULL_PTR == obj_data)
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_get_data_vec: new obj_data failed\n");
            task_mgr_free(task_mgr);

            cvector_loop_no_lock(obj_data_vec,
                        (void *)&ret,
                        CVECTOR_CHECKER_DEFAULT,
                        2,
                        0,
                        (UINT32)cvector_free_no_lock,
                        NULL_PTR,
                        LOC_SUPER_0102);
            cvector_clean_no_lock(obj_data_vec, NULL_PTR, LOC_SUPER_0103);
            return (EC_FALSE);
        }

        cvector_push_no_lock(obj_data_vec, (void *)obj_data);

        obj_id = (UINT32)cvector_get_no_lock(obj_id_vec, obj_id_pos);
        tcid = __MAKE_DES_TCID(TASK_BRD_TCID(task_brd), __GET_ZONE_ID_FROM_OBJ_ID(obj_id, SUPER_MD_OBJ_ZONE_SIZE(super_md)));

        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, &ret, FI_super_get_data, CMPI_ERROR_MODI, obj_id, obj_data);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL super_print_obj_vec(const UINT32 super_md_id, const CVECTOR *obj_vec, LOG *log)
{
    UINT32     obj_data_idx;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_print_obj_vec: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    for(obj_data_idx = 0; obj_data_idx < cvector_size(obj_vec); obj_data_idx ++)
    {
        UINT32     obj_data;
        obj_data = (UINT32)cvector_get_no_lock(obj_vec, obj_data_idx);
        sys_print(log, "%lx,", obj_data);
    }
    sys_print(log, "\n");

    return (EC_TRUE);
}

EC_BOOL super_print_data(const UINT32 super_md_id, LOG *log)
{
    SUPER_MD  *super_md;

    UINT32     obj_idx;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_print_data: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);
    for(obj_idx = 0; obj_idx < cvector_size(SUPER_MD_OBJ_ZONE(super_md)); obj_idx ++)
    {
        CVECTOR   *obj_vec;

        obj_vec = (CVECTOR *)cvector_get_no_lock(SUPER_MD_OBJ_ZONE(super_md), obj_idx);

        sys_print(log, "[%lx] ", obj_idx);
        super_print_obj_vec(super_md_id, obj_vec, log);
    }

    return (EC_TRUE);
}

EC_BOOL super_print_data_all(const UINT32 super_md_id, const UINT32 obj_zone_num, LOG *log)
{
    TASK_BRD *task_brd;
    TASK_MGR *task_mgr;
    UINT32    obj_zone_id;
    UINT32    ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_print_data_all: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    for(obj_zone_id = 0; obj_zone_id < obj_zone_num; obj_zone_id ++)
    {
        UINT32 tcid;

        MOD_NODE recv_mod_node;

        tcid = __MAKE_DES_TCID(TASK_BRD_TCID(task_brd), obj_zone_id);
        MOD_NODE_TCID(&recv_mod_node) = tcid;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;

        task_p2p_inc(task_mgr, super_md_id, &recv_mod_node, &ret, FI_super_print_data, CMPI_ERROR_MODI, log);
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL super_do_test(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_do_test: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    const char *headers[] = {
        "CC-Cache-Version:1493957359.183\r\n",
        "origin-server:223.202.201.159:80\r\n",
        "Date:Fri, 05 May 2017 04:09:22 GMT\r\n",
        "Response-Status:200\r\n",
        "Cache-Control:max-age=30\r\n",
        "ETag:\"57392004-0\"\r\n",
        "Content-Length:0\r\n",
        "Last-Modified:Mon, 16 May 2016 01:19:00 GMT\r\n",
        "Expires:Fri, 05 May 2017 04:09:52 GMT\r\n",
        "Content-Type:text/plain\r\n",
        "Accept-Ranges:bytes\r\n",
        "Server:openresty/1.9.3.1\r\n",
        "\r\n",
    };
    const char *body_data = "---- this is body content ----";
    UINT32 idx;

    CSTRING    path;
    CBYTES     body;

    cstring_init(&path, (UINT8 *)"/cc/304/0");
    cbytes_init(&body);

    for(idx = 0; idx < sizeof(headers)/sizeof(headers[0]); idx ++)
    {
        cbytes_append(&body, (UINT8 *)headers[ idx ], strlen(headers[ idx ]));
    }

    cbytes_append(&body, (UINT8 *)body_data, strlen(body_data));

    crfs_write(0, &path, &body);

    cstring_clean(&path);
    cbytes_clean(&body);

    return (EC_TRUE);
}

EC_BOOL super_cond_wait(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key, const UINT32 timeout_msec)
{
    SUPER_MD  *super_md;

    SUPER_CCOND *super_ccond;
    SUPER_CCOND *super_ccond_inserted;

    CRB_NODE    *crb_node;
    EC_BOOL      ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_cond_wait: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    super_ccond = super_ccond_new(super_md_id, tag, key, timeout_msec);
    if(NULL_PTR == super_ccond)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_cond_wait: new super_ccond [tag %ld, key '%.*s', timeout %ld ms] failed\n",
                    tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec);
        return (EC_FALSE);
    }

    crb_node = crb_tree_insert_data(SUPER_MD_COND_LOCKS(super_md), (void *)super_ccond);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_cond_wait: insert super_ccond [tag %ld, key '%.*s', timeout %ld ms] to tree failed\n",
                    tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec);
        super_ccond_free(super_md_id, super_ccond);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != super_ccond)
    {
        dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_cond_wait: insert super_ccond [tag %ld, key '%.*s', timeout %ld ms] to tree but found duplicate\n",
                    tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec);
        super_ccond_free(super_md_id, super_ccond);
    }

    super_ccond_inserted = CRB_NODE_DATA(crb_node);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_cond_wait: insert super_ccond [tag %ld, key '%.*s', timeout %ld ms] to tree done => cond %p\n",
                tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec, SUPER_CCOND_COND(super_ccond_inserted));

    croutine_cond_reserve(SUPER_CCOND_COND(super_ccond_inserted), 1, LOC_SUPER_0104);
    if(do_log(SEC_0117_SUPER, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] super_cond_wait: wait super_ccond [tag %ld, key '%.*s', timeout %ld ms] => cond %p\n",
                    tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec, SUPER_CCOND_COND(super_ccond_inserted));
    }

    ret = croutine_cond_wait(SUPER_CCOND_COND(super_ccond_inserted), LOC_SUPER_0105);
    if(EC_TIMEOUT == ret)
    {
        if(do_log(SEC_0117_SUPER, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] super_cond_wait: wait super_ccond [tag %ld, key '%.*s', timeout %ld ms] return due to timeout <= cond %p\n",
                      tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec, SUPER_CCOND_COND(super_ccond_inserted));
            /*here cannot print super_ccond due to it may be already free after wait*/
        }

        /*note: here initiatives to unlock*/
        /*super_cond_wakeup(super_md_id, tag, key);*//*xxx unuseful xxx*/

        /*super_ccond_searched will be free when delete its crb node from tree*/
        super_cond_delete(super_md_id, tag, key);

        return (EC_TRUE);
    }

    if(EC_TERMINATE == ret)
    {
        if(do_log(SEC_0117_SUPER, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] super_cond_wait: wait super_ccond [tag %ld, key '%.*s', timeout %ld ms] return due to terminate <= cond %p\n",
                      tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec, SUPER_CCOND_COND(super_ccond_inserted));
            /*here cannot print super_ccond due to it may be already free after wait*/
        }

        /*note: here initiatives to unlock*/
        /*super_cond_terminate(super_md_id, tag, key);*//*xxx unuseful xxx*/

        /*super_ccond_searched will be free when delete its crb node from tree*/
         super_cond_delete(super_md_id, tag, key);

        return (EC_FALSE);
    }

    if(do_log(SEC_0117_SUPER, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] super_cond_wait: wait super_ccond [tag %ld, key '%.*s', timeout %ld ms] return due to released <= cond %p\n",
                          tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), timeout_msec, SUPER_CCOND_COND(super_ccond_inserted));
        /*here cannot print super_ccond due to it may be already free after wait*/
    }

    /*super_ccond_searched will be free when delete its crb node from tree*/
     super_cond_delete(super_md_id, tag, key);
    return (EC_TRUE);
}

EC_BOOL super_cond_wakeup(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key)
{
    SUPER_MD    *super_md;

    SUPER_CCOND  super_ccond_t;
    SUPER_CCOND *super_ccond_searched;

    CRB_NODE    *crb_node_searched;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_cond_wakeup: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    super_ccond_init(super_md_id, &super_ccond_t, tag, key, 0/*any value*/);

    crb_node_searched = crb_tree_search_data(SUPER_MD_COND_LOCKS(super_md), (void *)&super_ccond_t);
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_cond_wakeup: not found super_ccond [tag %ld, key '%.*s']\n",
                    tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key));
        super_ccond_clean(super_md_id, &super_ccond_t);
        return (EC_TRUE);
    }

    super_ccond_clean(super_md_id, &super_ccond_t);/*no userful any longer*/

    super_ccond_searched = CRB_NODE_DATA(crb_node_searched);

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_cond_wakeup: release all super_ccond [tag %ld, key '%.*s'] <= cond %p\n",
                tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), SUPER_CCOND_COND(super_ccond_searched));

    croutine_cond_release_all(SUPER_CCOND_COND(super_ccond_searched), LOC_SUPER_0106);

    /*super_ccond_searched will be free when delete its crb node from tree*/
    //crb_tree_delete(SUPER_MD_COND_LOCKS(super_md), crb_node_searched);

    return (EC_TRUE);
}

EC_BOOL super_cond_terminate(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key)
{
    SUPER_MD    *super_md;

    SUPER_CCOND  super_ccond_t;
    SUPER_CCOND *super_ccond_searched;

    CRB_NODE    *crb_node_searched;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_cond_terminate: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    super_ccond_init(super_md_id, &super_ccond_t, tag, key, 0/*any value*/);

    crb_node_searched = crb_tree_search_data(SUPER_MD_COND_LOCKS(super_md), (void *)&super_ccond_t);
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_cond_terminate: not found super_ccond [tag %ld, key '%.*s']\n",
                    tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key));
        super_ccond_clean(super_md_id, &super_ccond_t);
        return (EC_TRUE);
    }

    super_ccond_clean(super_md_id, &super_ccond_t);/*no userful any longer*/

    super_ccond_searched = CRB_NODE_DATA(crb_node_searched);

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_cond_terminate: terminate super_ccond [tag %ld, key '%.*s'] <= cond %p\n",
                tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), SUPER_CCOND_COND(super_ccond_searched));

    croutine_cond_terminate(SUPER_CCOND_COND(super_ccond_searched), LOC_SUPER_0107);

    /*super_ccond_searched will be free when delete its crb node from tree*/
    //crb_tree_delete(SUPER_MD_COND_LOCKS(super_md), crb_node_searched);

    return (EC_TRUE);
}

EC_BOOL super_cond_delete(const UINT32 super_md_id, const UINT32 tag, const CSTRING *key)
{
    SUPER_MD    *super_md;

    SUPER_CCOND  super_ccond_t;
    SUPER_CCOND *super_ccond_searched;

    CRB_NODE    *crb_node_searched;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_cond_delete: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    super_md = SUPER_MD_GET(super_md_id);

    /*note: must confirm super_ccond existing and then delete it*/
    super_ccond_init(super_md_id, &super_ccond_t, tag, key, 0/*any value*/);

    crb_node_searched = crb_tree_search_data(SUPER_MD_COND_LOCKS(super_md), (void *)&super_ccond_t);
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_cond_delete: not found super_ccond [tag %ld, key '%.*s']\n",
                    tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key));
        return (EC_TRUE);
    }

    super_ccond_clean(super_md_id, &super_ccond_t);/*no userful any longer*/

    super_ccond_searched = CRB_NODE_DATA(crb_node_searched);

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_cond_delete: delete super_ccond [tag %ld, key '%.*s'] <= cond %p\n",
                tag, (uint32_t)CSTRING_LEN(key), CSTRING_STR(key), SUPER_CCOND_COND(super_ccond_searched));

    /*super_ccond_searched will be free when delete its crb node from tree*/
    crb_tree_delete(SUPER_MD_COND_LOCKS(super_md), crb_node_searched);

    return (EC_TRUE);
}

/**
*
* store data to storage
*
**/
EC_BOOL super_http_store(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CBYTES *cbytes, const CSTRING *auth_token)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_http_store: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"POST");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/update");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CXFSHTTP_REST_API_NAME"/update");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)c_word_to_str(CBYTES_LEN(cbytes)));

    cbytes_mount(CHTTP_REQ_BODY(&chttp_req), CBYTES_LEN(cbytes), CBYTES_BUF(cbytes));/*zero copy*/

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_http_store: store '%.*s' with size %ld to %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        CBYTES_LEN(cbytes),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        cbytes_umount(CHTTP_REQ_BODY(&chttp_req), NULL_PTR, NULL_PTR);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        if(EC_FALSE == cstring_is_empty(auth_token))
        {
            /*anyway, unlock the possible locked-file*/
            super_unlock(super_md_id, tcid, store_srv_ipaddr, store_srv_port, path, auth_token);
        }

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_http_store: store '%.*s' with size %ld to %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    CBYTES_LEN(cbytes),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    cbytes_umount(CHTTP_REQ_BODY(&chttp_req), NULL_PTR, NULL_PTR);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    if(EC_FALSE == cstring_is_empty(auth_token))
    {
        /*after store data, unlock the possible locked-file*/
        super_unlock(super_md_id, tcid, store_srv_ipaddr, store_srv_port, path, auth_token);
    }

    return (EC_TRUE);
}

/**
*
* store data to storage after delete dir
*
**/
STATIC_CAST static EC_BOOL __super_http_store_after_ddir(const CHTTP_STORE *chttp_store, const CSTRING *path)
{
    TASK_BRD    *task_brd;
    TASK_MGR    *task_mgr;

    UINT32       cmon_md_id;

    UINT32       pos;
    UINT32       num;
    EC_BOOL      ret;

    task_brd = task_brd_default_get();

    cmon_md_id = TASK_BRD_CMON_ID(task_brd);
    if(CMPI_ERROR_MODI == cmon_md_id)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_http_store_after_ddir: no cmon started\n");
        return (EC_FALSE);
    }

    cmon_count_nodes(cmon_md_id, &num);
    if(0 == num)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_http_store_after_ddir: store is empty\n");
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(pos = 0; pos < num; pos ++)
    {
        CMON_NODE      cmon_node;
        MOD_NODE       recv_mod_node;

        cmon_node_init(&cmon_node);
        if(EC_FALSE == cmon_get_node_by_pos(cmon_md_id, pos, &cmon_node))
        {
            cmon_node_clean(&cmon_node);
            continue;
        }

        if(EC_FALSE == cmon_node_is_up(&cmon_node))
        {
            dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_http_store_after_ddir: delete '%.*s' skip rfs %s which is not up\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(CMON_NODE_TCID(&cmon_node))
                    );
            cmon_node_clean(&cmon_node);
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

        task_p2p_inc(task_mgr, 0, &recv_mod_node,
                &ret, FI_super_delete_dir, CMPI_ERROR_MODI,
                CMON_NODE_TCID(&cmon_node), CMON_NODE_IPADDR(&cmon_node), CMON_NODE_PORT(&cmon_node), path);

        cmon_node_clean(&cmon_node);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_http_store_after_ddir: delete '%.*s' done\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));

    return (EC_TRUE);
}

EC_BOOL super_http_store_after_ddir(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CBYTES *cbytes, const CSTRING *auth_token, const CHTTP_STORE *chttp_store)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_http_store_after_ddir: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    __super_http_store_after_ddir(chttp_store, CHTTP_STORE_BASEDIR(chttp_store));/*blocking*/

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_http_store_after_ddir: delete '%.*s' done\n",
                    (uint32_t)CHTTP_STORE_BASEDIR_LEN(chttp_store), CHTTP_STORE_BASEDIR_STR(chttp_store));

    if(EC_FALSE == super_http_store(super_md_id, tcid, store_srv_ipaddr, store_srv_port, path, cbytes, auth_token))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_http_store_after_ddir: store '%.*s' done\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_http_store_after_ddir: store '%.*s' done\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_store_after_ddir(const CHTTP_STORE *chttp_store, const CSTRING *path)
{
    TASK_BRD    *task_brd;
    TASK_MGR    *task_mgr;

    UINT32       cmon_md_id;

    UINT32       pos;
    UINT32       num;
    EC_BOOL      ret;

    task_brd = task_brd_default_get();

    cmon_md_id = TASK_BRD_CMON_ID(task_brd);
    if(CMPI_ERROR_MODI == cmon_md_id)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_store_after_ddir: no cmon started\n");
        return (EC_FALSE);
    }

    cmon_count_nodes(cmon_md_id, &num);
    if(0 == num)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_store_after_ddir: store is empty\n");
        return (EC_FALSE);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    for(pos = 0; pos < num; pos ++)
    {
        CMON_NODE      cmon_node;
        MOD_NODE       recv_mod_node;

        cmon_node_init(&cmon_node);
        if(EC_FALSE == cmon_get_node_by_pos(cmon_md_id, pos, &cmon_node))
        {
            cmon_node_clean(&cmon_node);
            continue;
        }

        if(EC_FALSE == cmon_node_is_up(&cmon_node))
        {
            dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_store_after_ddir: delete '%.*s' skip rfs %s which is not up\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(CMON_NODE_TCID(&cmon_node))
                    );
            cmon_node_clean(&cmon_node);
            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = CMON_NODE_TCID(&cmon_node);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs*/

        task_p2p_inc(task_mgr, 0, &recv_mod_node, &ret, FI_crfs_delete, CMPI_ERROR_MODI, path, CRFSNP_ITEM_FILE_IS_DIR);

        cmon_node_clean(&cmon_node);
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_store_after_ddir: delete '%.*s' done\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));

    return (EC_TRUE);
}

/*over bgn*/
EC_BOOL super_store_after_ddir(const UINT32 super_md_id, const UINT32 tcid, const CSTRING *path, const CBYTES *cbytes, const CSTRING *auth_token, const CHTTP_STORE *chttp_store)
{
    MOD_NODE        recv_mod_node;
    EC_BOOL         ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_store_after_ddir: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    __super_store_after_ddir(chttp_store, CHTTP_STORE_BASEDIR(chttp_store));/*blocking*/

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_store_after_ddir: delete '%.*s' done\n",
                    (uint32_t)CHTTP_STORE_BASEDIR_LEN(chttp_store), CHTTP_STORE_BASEDIR_STR(chttp_store));


    /*make receiver*/
    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one rfs*/

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_store_after_ddir: p2p: [token %s] path '%.*s', data %p [len %ld] => tcid %s\n",
                (char *)cstring_get_str(auth_token),
                (uint32_t)CSTRING_LEN(path), CSTRING_STR(path), CBYTES_BUF(cbytes), CBYTES_LEN(cbytes),
                c_word_to_ipv4(tcid));

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
            &recv_mod_node,
            &ret, FI_crfs_update_with_token, CMPI_ERROR_MODI, path, cbytes, auth_token);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_store_after_ddir: store '%.*s' done\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));

    return (EC_TRUE);
}

/**
*
* notify local waiters  to wake up
*
**/
EC_BOOL super_notify(const UINT32 super_md_id, const UINT32 notify_flag, const CSTRING *notify_key)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_notify: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == notify_flag)
    {
        UINT32 tag;

        if(EC_TRUE == cstring_is_empty(notify_key))
        {
            dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_notify: not notify due to notify uri is empty\n");
            return (EC_FALSE);
        }

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            tag = MD_CXFS;
        }
        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            tag = MD_CRFS;
        }

        super_cond_wakeup(0, tag, notify_key);

        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_notify: wakeup waiters of '%.*s' done\n",
                    (uint32_t)CSTRING_LEN(notify_key), CSTRING_STR(notify_key));

        return (EC_TRUE);
    }

    if(do_log(SEC_0117_SUPER, 1) && EC_FALSE == cstring_is_empty(notify_key))
    {
        dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_notify: not notify waiters of '%.*s' due to flag is false\n",
                    (uint32_t)CSTRING_LEN(notify_key), CSTRING_STR(notify_key));
    }
    return (EC_TRUE);
}

/**
*
* notify remote waiters to wake up who are registered in locked-file owner list
* Note: it would not unlock the locked-file
*
**/
EC_BOOL super_unlock_notify(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    //SUPER_MD    *super_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_unlock_notify: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //super_md = SUPER_MD_GET(super_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/unlock_notify_req");
        cstring_append_cstr(uri, path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(uri, (uint8_t *)CXFSHTTP_REST_API_NAME"/unlock_notify_req");
        cstring_append_cstr(uri, path);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_unlock_notify: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    //chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_unlock_notify: notify '%.*s' to %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] super_unlock_notify: notify '%.*s' to %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

/**
*
* unlock the locked-file
*
**/
STATIC_CAST static EC_BOOL __super_unlock_over_http(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRING *auth_token)
{
    //SUPER_MD    *super_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__super_unlock_over_http: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //super_md = SUPER_MD_GET(super_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(uri, (uint8_t *)CRFSHTTP_REST_API_NAME"/unlock_req");
        cstring_append_cstr(uri, path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(uri, (uint8_t *)CXFSHTTP_REST_API_NAME"/unlock_req");
        cstring_append_cstr(uri, path);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_unlock_over_http: req uri '%.*s'\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    //chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"auth-token", (char *)CSTRING_STR(auth_token));

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_unlock_over_http: unlock '%.*s' to %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_unlock_over_http: unlock '%.*s' to %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_unlock_over_bgn(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRING *auth_token)
{
    MOD_NODE     mod_node;
    EC_BOOL      ret;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__super_unlock_over_bgn: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    ret = EC_FALSE;

    MOD_NODE_TCID(&mod_node) = tcid;
    MOD_NODE_COMM(&mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&mod_node) = 0;/*crfs_md_id = 0*/

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &mod_node,
             &ret,
             FI_crfs_file_unlock, CMPI_ERROR_MODI, path, auth_token);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_unlock_over_bgn: unlock '%.*s' to %s done => failed\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(tcid));

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_unlock_over_bgn: unlock '%.*s' to %s done => OK\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(tcid));

    return (EC_TRUE);
}

EC_BOOL super_unlock(const UINT32 super_md_id, const UINT32 tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRING *auth_token)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return __super_unlock_over_http(super_md_id, tcid, store_srv_ipaddr, store_srv_port, path, auth_token);
    }

    return __super_unlock_over_bgn(super_md_id, tcid, store_srv_ipaddr, store_srv_port, path, auth_token);
}

/**
*
* wait data on storage to be ready
*
**/
STATIC_CAST static EC_BOOL __super_wait_data_e(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const UINT32 store_offset, const UINT32 store_size, CBYTES *cbytes, UINT32 *data_ready)
{
    //SUPER_MD    *super_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    char        *v;

    //super_md = SUPER_MD_GET(super_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    (*data_ready) = EC_FALSE;

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/file_wait");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CXFSHTTP_REST_API_NAME"/file_wait");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"tcid", (char *)c_word_to_ipv4(task_brd_default_get_tcid()));
    chttp_req_add_header(&chttp_req, (const char *)"store-offset", (char *)c_word_to_str(store_offset));
    chttp_req_add_header(&chttp_req, (const char *)"store-size", (char *)c_word_to_str(store_size));

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_wait_data_e: file_wait '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_wait_data_e: file_wait '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    v = chttp_rsp_get_header(&chttp_rsp, (const char *)"data-ready");
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_wait_data_e: file_wait '%.*s' on %s:%ld => status %u but not found data-ready\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    (*data_ready) = c_str_to_bool(v);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_wait_data_e: file_wait '%.*s' on %s:%ld => OK, data_ready: %s [%ld]\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    v, (*data_ready));

    if(EC_TRUE == (*data_ready))
    {
        /*mount data to reduce data copy*/
        UINT8    *data;
        UINT32    len;

        cbytes_umount(CHTTP_RSP_BODY(&chttp_rsp), &len, &data);
        cbytes_mount(cbytes, len, data);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        return (EC_TRUE);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);


    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_read_data_e(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const UINT32 store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    UINT8       *data;
    UINT32       len;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] __super_read_data_e: read '%.*s' from %s:%ld start \n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/getsmf");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CXFSHTTP_REST_API_NAME"/getsmf");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"store-offset", (char *)c_word_to_str(store_offset));
    chttp_req_add_header(&chttp_req, (const char *)"store-size", (char *)c_word_to_str(store_size));

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_read_data_e: read '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_read_data_e: read '%.*s' on %s:%ld back\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_read_data_e: read '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] __super_read_data_e: read '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    cbytes_umount(CHTTP_RSP_BODY(&chttp_rsp), &len, &data);
    cbytes_mount(cbytes, len, data);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL super_wait_data_e(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const UINT32 store_offset, const UINT32 store_size, CBYTES *cbytes)
{
    //SUPER_MD    *super_md;

    UINT32       data_ready;

    UINT32       tag;
    UINT32       timeout_msec;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_wait_data_e: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //super_md = SUPER_MD_GET(super_md_id);

    data_ready = EC_FALSE;

    if(EC_FALSE == __super_wait_data_e(super_md_id, store_srv_ipaddr, store_srv_port, path, store_offset, store_size, cbytes, &data_ready))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_wait_data_e: wait data of '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    if(EC_TRUE == data_ready)
    {
        dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data_e: wait data of '%.*s' on %s:%ld done and data is ready\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_TRUE);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        tag = MD_CXFS;
    }
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        tag = MD_CRFS;
    }

    timeout_msec = 60 * 1000;

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data_e: cond wait of [tag %ld, key '%.*s', timeout %ld ms] on %s:%ld => start \n",
                    tag,
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    timeout_msec,
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(EC_FALSE == super_cond_wait(super_md_id, tag, path, timeout_msec))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_wait_data_e: cond wait of [tag %ld, key '%.*s', timeout %ld ms] on %s:%ld failed\n",
                        tag,
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        timeout_msec,
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data_e: cond wait of [tag %ld, key '%.*s', timeout %ld ms] on %s:%ld <= back\n",
                    tag,
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    timeout_msec,
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(EC_FALSE == __super_read_data_e(super_md_id, store_srv_ipaddr, store_srv_port, path, store_offset, store_size, cbytes))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_wait_data_e: read data of '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data_e: read data of '%.*s' on %s:%ld done\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    return (EC_TRUE);
}

/**
*
* wait data on storage to be ready
*
**/
STATIC_CAST static EC_BOOL __super_wait_data(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, CBYTES *cbytes, UINT32 *data_ready)
{
    //SUPER_MD    *super_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    char        *v;

    //super_md = SUPER_MD_GET(super_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    (*data_ready) = EC_FALSE;

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/file_wait");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CXFSHTTP_REST_API_NAME"/file_wait");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req, (const char *)"tcid", (char *)c_word_to_ipv4(task_brd_default_get_tcid()));

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_wait_data: file_wait '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_wait_data: file_wait '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    v = chttp_rsp_get_header(&chttp_rsp, (const char *)"data-ready");
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_wait_data: file_wait '%.*s' on %s:%ld => status %u but not found data-ready\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    (*data_ready) = c_str_to_bool(v);

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_wait_data: file_wait '%.*s' on %s:%ld => OK, data_ready: '%s' [%ld]\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    v, (*data_ready));

    if(EC_TRUE == (*data_ready))
    {
        /*mount data to reduce data copy*/
        UINT8    *data;
        UINT32    len;

        cbytes_umount(CHTTP_RSP_BODY(&chttp_rsp), &len, &data);
        cbytes_mount(cbytes, len, data);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);

        return (EC_TRUE);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);


    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __super_read_data(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, CBYTES *cbytes)
{
    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;

    UINT8       *data;
    UINT32       len;

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] __super_read_data: read '%.*s' from %s:%ld start \n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CRFSHTTP_REST_API_NAME"/getsmf");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req), (uint8_t *)CXFSHTTP_REST_API_NAME"/getsmf");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req), path);
    }

    chttp_req_add_header(&chttp_req, (const char *)"Host", (char *)"127.0.0.1");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    if(EC_FALSE == chttp_request_basic(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_read_data: read '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] __super_read_data: read '%.*s' on %s:%ld back\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:__super_read_data: read '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 1)(LOGSTDOUT, "[DEBUG] __super_read_data: read '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    cbytes_umount(CHTTP_RSP_BODY(&chttp_rsp), &len, &data);
    cbytes_mount(cbytes, len, data);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL super_wait_data(const UINT32 super_md_id, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, CBYTES *cbytes)
{
    //SUPER_MD    *super_md;

    UINT32       data_ready;

    UINT32       tag;
    UINT32       timeout_msec;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_wait_data: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    //super_md = SUPER_MD_GET(super_md_id);

    data_ready = EC_FALSE;

    if(EC_FALSE == __super_wait_data(super_md_id, store_srv_ipaddr, store_srv_port, path, cbytes, &data_ready))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_wait_data: wait data of '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    if(EC_TRUE == data_ready)
    {
        dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data: wait data of '%.*s' on %s:%ld done and data is ready\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_TRUE);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        tag = MD_CXFS;
    }
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        tag = MD_CRFS;
    }

    timeout_msec = 60 * 1000;

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data: cond wait of [tag %ld, key '%.*s', timeout %ld ms] on %s:%ld => start \n",
                    tag,
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    timeout_msec,
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(EC_FALSE == super_cond_wait(super_md_id, tag, path, timeout_msec))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] super_wait_data: cond wait of [tag %ld, key '%.*s', timeout %ld ms] on %s:%ld failed\n",
                        tag,
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        timeout_msec,
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data: cond wait of [tag %ld, key '%.*s', timeout %ld ms] on %s:%ld <= back\n",
                    tag,
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    timeout_msec,
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    if(EC_FALSE == __super_read_data(super_md_id, store_srv_ipaddr, store_srv_port, path, cbytes))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_wait_data: read data of '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_wait_data: read data of '%.*s' on %s:%ld done\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    return (EC_TRUE);
}

EC_BOOL super_renew_header(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRING *key, const CSTRING *val)
{
    CHTTP_REQ    chttp_req_t;
    CHTTP_RSP    chttp_rsp_t;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_renew_header: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    chttp_req_init(&chttp_req_t);
    chttp_rsp_init(&chttp_rsp_t);

    chttp_req_set_ipaddr_word(&chttp_req_t, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req_t, store_srv_port);
    chttp_req_set_method(&chttp_req_t, (const char *)"GET");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CRFSHTTP_REST_API_NAME"/renew_header");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CXFSHTTP_REST_API_NAME"/renew_header");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    chttp_req_add_header(&chttp_req_t, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req_t, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req_t, (const char *)"renew-key", (char *)CSTRING_STR(key));
    chttp_req_add_header(&chttp_req_t, (const char *)"renew-val", (char *)CSTRING_STR(val));

    if(EC_FALSE == chttp_request_basic(&chttp_req_t, NULL_PTR, &chttp_rsp_t, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_renew_header: renew_header '%s:%s' of '%.*s' on %s:%ld failed\n",
                        (char *)CSTRING_STR(key), (char *)CSTRING_STR(val),
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp_t))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_renew_header: renew_header '%s:%s' of '%.*s' on %s:%ld => status %u\n",
                        (char *)CSTRING_STR(key), (char *)CSTRING_STR(val),
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp_t));

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_renew_header: renew_header '%s:%s' of '%.*s' on %s:%ld => OK\n",
                    (char *)CSTRING_STR(key), (char *)CSTRING_STR(val),
                    (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req_t);
    chttp_rsp_clean(&chttp_rsp_t);

    return (EC_TRUE);
}

EC_BOOL super_renew_headers(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *auth_token)
{
    CHTTP_REQ    chttp_req_t;
    CHTTP_RSP    chttp_rsp_t;
    CLIST_DATA  *clist_data;

    uint32_t     idx;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_renew_headers: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    chttp_req_init(&chttp_req_t);
    chttp_rsp_init(&chttp_rsp_t);

    chttp_req_set_ipaddr_word(&chttp_req_t, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req_t, store_srv_port);
    chttp_req_set_method(&chttp_req_t, (const char *)"GET");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CRFSHTTP_REST_API_NAME"/renew_header");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CXFSHTTP_REST_API_NAME"/renew_header");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    chttp_req_add_header(&chttp_req_t, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req_t, (const char *)"Content-Length", (char *)"0");

    idx = 0;
    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV   *cstrkv;

        char     renew_key_tag[ 16 ];
        char     renew_val_tag[ 16 ];

        cstrkv = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        idx ++;
        snprintf(renew_key_tag, sizeof(renew_key_tag)/sizeof(renew_key_tag[ 0 ]), "renew-key-%u", idx);
        snprintf(renew_val_tag, sizeof(renew_val_tag)/sizeof(renew_val_tag[ 0 ]), "renew-val-%u", idx);

        chttp_req_add_header(&chttp_req_t, (const char *)renew_key_tag, (char *)CSTRKV_KEY_STR(cstrkv));
        chttp_req_add_header(&chttp_req_t, (const char *)renew_val_tag, (char *)CSTRKV_VAL_STR(cstrkv));
    }

    chttp_req_add_header(&chttp_req_t, (const char *)"renew-num", (char *)c_uint32_t_to_str(idx));

    if(EC_FALSE == chttp_request_basic(&chttp_req_t, NULL_PTR, &chttp_rsp_t, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_renew_headers: renew headers of '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp_t))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_renew_headers: renew headers of '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp_t));

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_renew_headers: renew headers of '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req_t);
    chttp_rsp_clean(&chttp_rsp_t);

    if(EC_FALSE == cstring_is_empty(auth_token))
    {
        /*after store data, unlock the possible locked-file*/
        super_unlock(super_md_id, store_srv_tcid, store_srv_ipaddr, store_srv_port, path, auth_token);
    }

    return (EC_TRUE);
}

EC_BOOL super_file_notify(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    CHTTP_REQ    chttp_req_t;
    CHTTP_RSP    chttp_rsp_t;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_file_notify: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    chttp_req_init(&chttp_req_t);
    chttp_rsp_init(&chttp_rsp_t);

    chttp_req_set_ipaddr_word(&chttp_req_t, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req_t, store_srv_port);
    chttp_req_set_method(&chttp_req_t, (const char *)"GET");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CRFSHTTP_REST_API_NAME"/file_notify");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CXFSHTTP_REST_API_NAME"/file_notify");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    chttp_req_add_header(&chttp_req_t, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req_t, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request_basic(&chttp_req_t, NULL_PTR, &chttp_rsp_t, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_file_notify: file_notify '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp_t))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_file_notify: file_notify '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp_t));

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_file_notify: file_notify '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req_t);
    chttp_rsp_clean(&chttp_rsp_t);

    return (EC_TRUE);
}

EC_BOOL super_delete_dir(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    CHTTP_REQ    chttp_req_t;
    CHTTP_RSP    chttp_rsp_t;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_delete_dir: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    chttp_req_init(&chttp_req_t);
    chttp_rsp_init(&chttp_rsp_t);

    chttp_req_set_ipaddr_word(&chttp_req_t, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req_t, store_srv_port);
    chttp_req_set_method(&chttp_req_t, (const char *)"GET");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CRFSHTTP_REST_API_NAME"/ddir");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CXFSHTTP_REST_API_NAME"/ddir");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    chttp_req_add_header(&chttp_req_t, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req_t, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request_basic(&chttp_req_t, NULL_PTR, &chttp_rsp_t, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_delete_dir: delete dir '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp_t))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_delete_dir: delete dir '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp_t));

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_delete_dir: delete dir '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req_t);
    chttp_rsp_clean(&chttp_rsp_t);

    return (EC_TRUE);
}

EC_BOOL super_delete_file(const UINT32 super_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    CHTTP_REQ    chttp_req_t;
    CHTTP_RSP    chttp_rsp_t;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_delete_file: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    chttp_req_init(&chttp_req_t);
    chttp_rsp_init(&chttp_rsp_t);

    chttp_req_set_ipaddr_word(&chttp_req_t, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req_t, store_srv_port);
    chttp_req_set_method(&chttp_req_t, (const char *)"GET");

    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CRFSHTTP_REST_API_NAME"/dsmf");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)CXFSHTTP_REST_API_NAME"/dsmf");
        cstring_append_cstr(CHTTP_REQ_URI(&chttp_req_t), path);
    }

    chttp_req_add_header(&chttp_req_t, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req_t, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request_basic(&chttp_req_t, NULL_PTR, &chttp_rsp_t, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_delete_file: delete file '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp_t))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_delete_file: delete file '%.*s' on %s:%ld => status %u\n",
                        (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(&chttp_rsp_t));

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_delete_file: delete file '%.*s' on %s:%ld => OK\n",
                    (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    chttp_req_clean(&chttp_req_t);
    chttp_rsp_clean(&chttp_rsp_t);

    return (EC_TRUE);
}

EC_BOOL super_set_billing(const UINT32 super_md_id, const UINT32 billing_srv_ipaddr, const UINT32 billing_srv_port, const CSTRING *billing_flags, const CSTRING *billing_domain, const CSTRING *billing_client_type, const UINT32 send_len, const UINT32 recv_len)
{
    CHTTP_REQ    chttp_req_t;
    CHTTP_RSP    chttp_rsp_t;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_set_billing: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    chttp_req_init(&chttp_req_t);
    chttp_rsp_init(&chttp_rsp_t);

    chttp_req_set_ipaddr_word(&chttp_req_t, billing_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req_t, billing_srv_port);
    chttp_req_set_method(&chttp_req_t, (const char *)"GET");

    cstring_append_str(CHTTP_REQ_URI(&chttp_req_t), (uint8_t *)"http://bill.hpcc/set_rtbilling");

    chttp_req_add_header(&chttp_req_t, (const char *)"Connection", (char *)"close");
    chttp_req_add_header(&chttp_req_t, (const char *)"Content-Length", (char *)"0");
    chttp_req_add_header(&chttp_req_t, (const char *)"Host" , (char *)"bill.hpcc");
    chttp_req_add_header(&chttp_req_t, (const char *)"bill-flags"   , (char *)CSTRING_STR(billing_flags));
    chttp_req_add_header(&chttp_req_t, (const char *)"bill-domain"   , (char *)CSTRING_STR(billing_domain));
    chttp_req_add_header(&chttp_req_t, (const char *)"client-type" , (char *)CSTRING_STR(billing_client_type));
    chttp_req_add_header(&chttp_req_t, (const char *)"send-bytes"  , (char *)c_word_to_str(send_len));
    chttp_req_add_header(&chttp_req_t, (const char *)"recv-bytes"  , (char *)c_word_to_str(recv_len));

    if(EC_FALSE == chttp_request_basic(&chttp_req_t, NULL_PTR, &chttp_rsp_t, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_billing: set billing of [%.*s] '%.*s' and send_len %ld, recv_len %ld failed\n",
                        (uint32_t)CSTRING_LEN(billing_client_type), (char *)CSTRING_STR(billing_client_type),
                        (uint32_t)CSTRING_LEN(billing_domain), (char *)CSTRING_STR(billing_domain),
                        send_len, recv_len);

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp_t))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_set_billing: set billing of [%.*s] '%.*s' and send_len %ld, recv_len %ld => status %u\n",
                        (uint32_t)CSTRING_LEN(billing_client_type), (char *)CSTRING_STR(billing_client_type),
                        (uint32_t)CSTRING_LEN(billing_domain), (char *)CSTRING_STR(billing_domain),
                        send_len, recv_len,
                        CHTTP_RSP_STATUS(&chttp_rsp_t));

        chttp_req_clean(&chttp_req_t);
        chttp_rsp_clean(&chttp_rsp_t);

        return (EC_FALSE);
    }

    dbg_log(SEC_0117_SUPER, 9)(LOGSTDOUT, "[DEBUG] super_set_billing: set billing of [%.*s] '%.*s' and send_len %ld, recv_len %ld => OK\n",
                    (uint32_t)CSTRING_LEN(billing_client_type), (char *)CSTRING_STR(billing_client_type),
                    (uint32_t)CSTRING_LEN(billing_domain), (char *)CSTRING_STR(billing_domain),
                    send_len, recv_len);

    chttp_req_clean(&chttp_req_t);
    chttp_rsp_clean(&chttp_rsp_t);

    return (EC_TRUE);
}

/*for debug*/
STATIC_CAST static EC_BOOL __super_dns_resolve_cleanup_handle(CDNS_NODE *cdns_node)
{
    if(NULL_PTR != cdns_node)
    {
        if(NULL_PTR != CDNS_NODE_RSP(cdns_node))
        {
            cdns_rsp_free(CDNS_NODE_RSP(cdns_node));
            CDNS_NODE_RSP(cdns_node) = NULL_PTR;
        }

        if(NULL_PTR != CDNS_NODE_REQ(cdns_node))
        {
            cdns_req_free(CDNS_NODE_REQ(cdns_node));
            CDNS_NODE_REQ(cdns_node) = NULL_PTR;
        }

        cdns_node_free(cdns_node);
    }

    return (EC_TRUE);
}

/*for debug*/
STATIC_CAST static EC_BOOL __super_dns_resolve_recv_handle(CDNS_NODE *cdns_node)
{
    if(NULL_PTR != CDNS_NODE_RSP(cdns_node) && BIT_TRUE == CDNS_NODE_RECV_COMPLETE(cdns_node))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "[DEBUG] __super_dns_resolve_recv_handle: cdns rsp\n");
        cdns_rsp_print(LOGSTDOUT, CDNS_NODE_RSP(cdns_node));
    }

    __super_dns_resolve_cleanup_handle(cdns_node);
    return (EC_TRUE);
}

/*for debug*/
STATIC_CAST EC_BOOL __super_dns_resolve_set_callback(CSOCKET_CNODE *csocket_cnode, CDNS_NODE *cdns_node)
{
    csocket_cnode_push_recv_callback(csocket_cnode,
                                     (const char *)"__super_dns_resolve_recv_handle",
                                     (UINT32)cdns_node, (UINT32)__super_dns_resolve_recv_handle);

    csocket_cnode_push_close_callback(csocket_cnode,
                                     (const char *)"__super_dns_resolve_cleanup_handle",
                                     (UINT32)cdns_node, (UINT32)__super_dns_resolve_cleanup_handle);

    csocket_cnode_push_timeout_callback(csocket_cnode,
                                     (const char *)"__super_dns_resolve_cleanup_handle",
                                     (UINT32)cdns_node, (UINT32)__super_dns_resolve_cleanup_handle);

    csocket_cnode_push_shutdown_callback(csocket_cnode,
                                     (const char *)"__super_dns_resolve_cleanup_handle",
                                     (UINT32)cdns_node, (UINT32)__super_dns_resolve_cleanup_handle);

    return (EC_TRUE);
}

/*for debug*/
EC_BOOL super_dns_resolve_demo(const UINT32 super_md_id, const CSTRING *dns_server, const CSTRING *domain)
{
    CDNS_REQ    *cdns_req;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_dns_resolve_demo: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    cdns_req = cdns_req_new();
    if(NULL_PTR == cdns_req)
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_dns_resolve_demo: new cdns_req failed\n");
        return (EC_FALSE);
    }

    CDNS_REQ_IPADDR(cdns_req) = c_ipv4_to_word((char *)cstring_get_str(dns_server));/*default*/
    CDNS_REQ_PORT(cdns_req)   = 53; /*default*/

    cstring_clone(domain, CDNS_REQ_HOST(cdns_req));

    if(EC_FALSE == cdns_request_basic(cdns_req, __super_dns_resolve_set_callback, NULL_PTR, NULL_PTR))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_dns_resolve_demo: request failed\n");
        cdns_req_free(cdns_req);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
* enable dns cache
*
**/
EC_BOOL super_dns_cache_switch_on(const UINT32 super_md_id)
{
    CPARACFG        *cparacfg;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_dns_cache_switch_on: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    cparacfg = CPARACFG_DEFAULT_GET();

    CPARACFG_DNS_CACHE_SWITCH(cparacfg) = SWITCH_ON;

    return (EC_TRUE);
}

/**
*
* disable dns cache
*
**/
EC_BOOL super_dns_cache_switch_off(const UINT32 super_md_id)
{
    CPARACFG        *cparacfg;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_dns_cache_switch_off: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    cparacfg = CPARACFG_DEFAULT_GET();

    CPARACFG_DNS_CACHE_SWITCH(cparacfg) = SWITCH_OFF;

    return (EC_TRUE);
}

/**
*
* set dns resolve result expired in nsec
*
**/
EC_BOOL super_dns_cache_expired_nsec_set(const UINT32 super_md_id, const UINT32 nsec)
{
    CPARACFG        *cparacfg;

#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_dns_cache_expired_nsec_set: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    cparacfg = CPARACFG_DEFAULT_GET();

    CPARACFG_DNS_CACHE_EXPIRED_NSEC(cparacfg) = nsec;

    return (EC_TRUE);
}

/**
*
* dns cache show
*
**/
EC_BOOL super_dns_cache_show(const UINT32 super_md_id, const CSTRING *domain, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_dns_cache_show: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(domain))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_dns_cache_show: domain is empty\n");
        return (EC_FALSE);
    }

    return cdnscache_dns_show(log, (const char *)cstring_get_str(domain));
}

/**
*
* dns cache resolver
*
**/
EC_BOOL super_dns_cache_resolve(const UINT32 super_md_id, const CSTRING *domain, UINT32 *ipv4)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_dns_cache_resolve: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(domain))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_dns_cache_resolve: domain is empty\n");
        return (EC_FALSE);
    }

    return cdnscache_dns_resolve((const char *)cstring_get_str(domain), ipv4);
}

/**
*
* dns cache retire one ipv4
*
**/
EC_BOOL super_dns_cache_retire(const UINT32 super_md_id, const CSTRING *domain, const UINT32 ipv4)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_dns_cache_retire: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

    if(EC_TRUE == cstring_is_empty(domain))
    {
        dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_dns_cache_retire: domain is empty\n");
        return (EC_FALSE);
    }

    return cdnscache_dns_retire((const char *)cstring_get_str(domain), ipv4);
}

/**
*
* ngx reload bgn module so libs
*
**/
void super_ngx_reload_so(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ngx_reload_so: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

#if (SWITCH_ON == NGX_BGN_SWITCH)
    cngx_bgn_mod_mgr_table_set_reload();
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_ngx_reload_so: not support\n");
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

    return;
}

/**
*
* ngx switch bgn module so libs
*
**/
void super_ngx_switch_so(const UINT32 super_md_id)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ngx_switch_so: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

#if (SWITCH_ON == NGX_BGN_SWITCH)
    cngx_bgn_mod_mgr_table_switch();
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_ngx_switch_so: not support\n");
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

    return;
}

/**
*
* ngx show bgn module so libs
*
**/
void super_ngx_show_so(const UINT32 super_md_id, LOG *log)
{
#if ( SWITCH_ON == SUPER_DEBUG_SWITCH )
    if ( SUPER_MD_ID_CHECK_INVALID(super_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:super_ngx_show_so: super module #0x%lx not started.\n",
                super_md_id);
        dbg_exit(MD_SUPER, super_md_id);
    }
#endif/*SUPER_DEBUG_SWITCH*/

#if (SWITCH_ON == NGX_BGN_SWITCH)
    cngx_bgn_mod_mgr_table_print(log);
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    dbg_log(SEC_0117_SUPER, 0)(LOGSTDOUT, "error:super_ngx_show_so: not support\n");
    sys_log(log, "error:super_ngx_show_so: not support\n");
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

    return;
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

