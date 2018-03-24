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

#include <pcre.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cbc.h"

#include "cmisc.h"
#include "clist.h"
#include "cmutex.h"
#include "cbytes.h"
#include "cstring.h"

#include "mod.inc"
#include "cmpic.inc"
#include "task.h"
#include "cbtimer.h"

#include "csession.h"

#include "findex.inc"

#define CSESSION_MD_CAPACITY()                  (cbc_md_capacity(MD_CSESSION))

#define CSESSION_MD_GET(csession_md_id)         ((CSESSION_MD *)cbc_md_get(MD_CSESSION, (csession_md_id)))

#define CSESSION_MD_ID_CHECK_INVALID(csession_md_id)  \
    ((CMPI_ANY_MODI != (csession_md_id)) && ((NULL_PTR == CSESSION_MD_GET(csession_md_id)) || (0 == (CSESSION_MD_GET(csession_md_id)->usedcounter))))


STATIC_CAST static UINT32 __csession_reserve_id(const UINT32 csession_md_id);

STATIC_CAST static EC_BOOL __csession_get_depth(const UINT32 csession_md_id, const CLIST *cache_tree,
                                            const char **segs, const UINT32 seg_idx, const UINT32 seg_num,
                                            CLIST *csession_item_list);

STATIC_CAST static EC_BOOL __csession_cbtimer_add(const UINT32 csession_md_id);

/**
*   for test only
*
*   to query the status of CSESSION Module
*
**/
void csession_print_module_status(const UINT32 csession_md_id, LOG *log)
{
    CSESSION_MD *csession_md;
    UINT32 this_csession_md_id;

    for( this_csession_md_id = 0; this_csession_md_id < CSESSION_MD_CAPACITY(); this_csession_md_id ++ )
    {
        csession_md = CSESSION_MD_GET(this_csession_md_id);

        if ( NULL_PTR != csession_md && 0 < csession_md->usedcounter )
        {
            sys_log(log,"CSESSION Module # %ld : %ld refered\n",
                    this_csession_md_id,
                    csession_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CSESSION module
*
*
**/
UINT32 csession_free_module_static_mem(const UINT32 csession_md_id)
{
    CSESSION_MD  *csession_md;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_free_module_static_mem: csession module #0x%lx not started.\n",
                csession_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    free_module_static_mem(MD_CSESSION, csession_md_id);

    return 0;
}

/**
*
* start CSESSION module
*
**/
UINT32 csession_start()
{
    CSESSION_MD *csession_md;
    UINT32 csession_md_id;

    TASK_BRD *task_brd;

    csession_md_id = cbc_md_new(MD_CSESSION, sizeof(CSESSION_MD));
    if(CMPI_ERROR_MODI == csession_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CSESSION module */
    csession_md = (CSESSION_MD *)cbc_md_get(MD_CSESSION, csession_md_id);
    csession_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    task_brd = task_brd_default_get();

    CSESSION_MD_MOD_MGR(csession_md) = mod_mgr_new(csession_md_id, LOAD_BALANCING_LOOP);

    CSESSION_MD_INIT_CRWLOCK(csession_md, LOC_CSESSION_0001);
    CSESSION_MD_INIT_ID_POOL_CMUTEX(csession_md, LOC_CSESSION_0002);
    CSESSION_MD_ID_POOL(csession_md) = CSESSION_BEGIN_ID; /*initialize session id pool*/
    clist_init(CSESSION_MD_SESSION_LIST(csession_md), MM_CSESSION_NODE, LOC_CSESSION_0003);

    csession_md->usedcounter = 1;

    dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_start: start CSESSION module #%ld\n", csession_md_id);
    //dbg_log(SEC_0025_CSESSION, 3)(LOGSTDOUT, "========================= csession_start: CSESSION table info:\n");
    //csession_print_module_status(csession_md_id, LOGSTDOUT);
    //cbc_print();

    __csession_cbtimer_add(csession_md_id);
    return ( csession_md_id );
}

/**
*
* end CSESSION module
*
**/
void csession_end(const UINT32 csession_md_id)
{
    CSESSION_MD *csession_md;

    csession_md = CSESSION_MD_GET(csession_md_id);
    if(NULL_PTR == csession_md)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT,"error:csession_end: csession_md_id = %ld not exist.\n", csession_md_id);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < csession_md->usedcounter )
    {
        csession_md->usedcounter --;
        return ;
    }

    if ( 0 == csession_md->usedcounter )
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT,"error:csession_end: csession_md_id = %ld is not started.\n", csession_md_id);
        dbg_exit(MD_CSESSION, csession_md_id);
    }

    /* if nobody else occupied the module,then free its resource */
    if(NULL_PTR != CSESSION_MD_MOD_MGR(csession_md))
    {
        mod_mgr_free(CSESSION_MD_MOD_MGR(csession_md));
        CSESSION_MD_MOD_MGR(csession_md)  = NULL_PTR;
    }

    CSESSION_MD_CLEAN_CRWLOCK(csession_md, LOC_CSESSION_0004);
    CSESSION_MD_CLEAN_ID_POOL_CMUTEX(csession_md, LOC_CSESSION_0005);
    CSESSION_MD_ID_POOL(csession_md) = CSESSION_ERROR_ID;
    clist_clean(CSESSION_MD_SESSION_LIST(csession_md), (CLIST_DATA_DATA_CLEANER)csession_node_free);

    /* free module : */
    //csession_free_module_static_mem(csession_md_id);

    csession_md->usedcounter = 0;

    dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_end: stop CSESSION module #%ld\n", csession_md_id);
    cbc_md_free(MD_CSESSION, csession_md_id);

    breathing_static_mem();

    //dbg_log(SEC_0025_CSESSION, 3)(LOGSTDOUT, "========================= csession_end: CSESSION table info:\n");
    //csession_print_module_status(csession_md_id, LOGSTDOUT);
    //cbc_print();

    return ;
}

void csession_print(LOG *log, const UINT32 csession_md_id, const UINT32 level)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;
    TASK_BRD    *task_brd;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_print: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    task_brd = task_brd_default_get();

    c_ident_print(log, level);
    sys_print(log, "<sessions tcid=\"%s\" rank=\"%ld\" modi=\"%ld\">\n",
                   TASK_BRD_TCID_STR(task_brd),
                   TASK_BRD_RANK(task_brd),
                   csession_md_id
              );

    CLIST_LOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0006);
    CLIST_LOOP_NEXT(CSESSION_MD_SESSION_LIST(csession_md), clist_data)
    {
        CSESSION_NODE *csession_node;
        csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
        csession_node_print(log, csession_node, level + 1);
    }
    CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0007);

    c_ident_print(log, level);
    sys_print(log, "</sessions>\n");

    return;
}

void csession_show(const UINT32 csession_md_id, LOG *log)
{
    csession_print(log, csession_md_id, 0);
    //csession_print(LOGSTDOUT, csession_md_id, 0);
    return;
}

STATIC_CAST static UINT32 __csession_reserve_id(const UINT32 csession_md_id)
{
    CSESSION_MD    *csession_md;
    UINT32 session_id;


    csession_md = CSESSION_MD_GET(csession_md_id);
    if(NULL_PTR == csession_md)
    {
        return (CSESSION_ERROR_ID);
    }

    CSESSION_MD_CMUTEX_ID_POOL_LOCK(csession_md, LOC_CSESSION_0008);
    while(CSESSION_ERROR_ID == CSESSION_MD_ID_POOL(csession_md) || CSESSION_BEGIN_ID == CSESSION_MD_ID_POOL(csession_md))
    {
        CSESSION_MD_ID_POOL(csession_md) ++;
    }
    session_id = CSESSION_MD_ID_POOL(csession_md) ++;
    CSESSION_MD_CMUTEX_ID_POOL_UNLOCK(csession_md, LOC_CSESSION_0009);

    return (session_id);
}

CSESSION_NODE *csession_node_new(const CSTRING *name, const UINT32 expire_nsec)
{
    CSESSION_NODE *csession_node;

    alloc_static_mem(MM_CSESSION_NODE, &csession_node, LOC_CSESSION_0010);
    if(NULL_PTR == csession_node)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_node_new:alloc csession node failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csession_node_init(csession_node))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_node_new: init csession node failed\n");
        free_static_mem(MM_CSESSION_NODE, csession_node, LOC_CSESSION_0011);
        return (NULL_PTR);
    }

    cstring_clone(name, CSESSION_NODE_NAME(csession_node));
    CSESSION_NODE_ID(csession_node) = CSESSION_ERROR_ID;
    CSESSION_NODE_EXPIRE_NSEC(csession_node) = expire_nsec;

    CTIMET_GET(CSESSION_NODE_CREATE_TIME(csession_node));
    CTIMET_GET(CSESSION_NODE_ACCESS_TIME(csession_node));
    return (csession_node);
}

EC_BOOL csession_node_init(CSESSION_NODE *csession_node)
{
    cstring_init(CSESSION_NODE_NAME(csession_node), NULL_PTR);
    CSESSION_NODE_INIT_ACCESS_CMUTEX(csession_node, LOC_CSESSION_0012);
    CSESSION_NODE_ID(csession_node) = CSESSION_ERROR_ID;
    CSESSION_NODE_EXPIRE_NSEC(csession_node) = CSESSION_NEVER_EXPIRE;
    clist_init(CSESSION_NODE_CACHE_TREE(csession_node), MM_CSESSION_ITEM, LOC_CSESSION_0013);
    return (EC_TRUE);
}

EC_BOOL csession_node_clean(CSESSION_NODE *csession_node)
{
    clist_clean(CSESSION_NODE_CACHE_TREE(csession_node), (CLIST_DATA_DATA_CLEANER)csession_item_free);
    cstring_clean(CSESSION_NODE_NAME(csession_node));
    CSESSION_NODE_CLEAN_ACCESS_CMUTEX(csession_node, LOC_CSESSION_0014);
    return (EC_TRUE);
}

EC_BOOL csession_node_free(CSESSION_NODE *csession_node)
{
    if(NULL_PTR != csession_node)
    {
        csession_node_clean(csession_node);
        free_static_mem(MM_CSESSION_NODE, csession_node, LOC_CSESSION_0015);
    }
    return (EC_TRUE);
}

EC_BOOL csession_node_is_expired(const UINT32 csession_md_id, const CSESSION_NODE *csession_node, const CTIMET *cur_time)
{
    if(0 < CSESSION_NODE_EXPIRE_NSEC(csession_node))
    {
        REAL diff_nsec;

        diff_nsec = CTIMET_DIFF(CSESSION_NODE_ACCESS_TIME(csession_node), (*cur_time));
        dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] cbtimer_node_is_expire: diff_nsec %.2f, expire_nsec %ld\n",
                            diff_nsec, CSESSION_NODE_EXPIRE_NSEC(csession_node));
        if(diff_nsec >= 0.0 + CSESSION_NODE_EXPIRE_NSEC(csession_node))
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

EC_BOOL csession_node_match_name(const CSESSION_NODE *csession_node, const CSTRING *name)
{
    if(EC_TRUE == cstring_is_equal(CSESSION_NODE_NAME(csession_node), name))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csession_node_match_id(const CSESSION_NODE *csession_node, const UINT32 session_id)
{
    if(CSESSION_NODE_ID(csession_node) == session_id)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void csession_node_print(LOG *log, const CSESSION_NODE *csession_node, const UINT32 level)
{
    struct tm *create_time;
    struct tm *access_time;

    create_time = c_localtime_r(&CSESSION_NODE_CREATE_TIME(csession_node));
    access_time = c_localtime_r(&CSESSION_NODE_ACCESS_TIME(csession_node));

    c_ident_print(log, level);
    sys_print(log, "<session name=\"%s\" id=\"%ld\" expire=\"%ld\" create_time=\"%4d-%02d-%02d %02d:%02d:%02d\" access_time=\"%4d-%02d-%02d %02d:%02d:%02d\">\n",
                   (char *)CSESSION_NODE_NAME_STR(csession_node),
                   CSESSION_NODE_ID(csession_node),
                   CSESSION_NODE_EXPIRE_NSEC(csession_node),
                   TIME_IN_YMDHMS(create_time),
                   TIME_IN_YMDHMS(access_time)
             );

    clist_print_level(log, CSESSION_NODE_CACHE_TREE(csession_node), level + 1, (CLIST_DATA_LEVEL_PRINT)csession_item_print);

    c_ident_print(log, level);
    sys_print(log, "</session>\n");
    return;
}

CSESSION_ITEM *csession_item_new(const CSTRING *key, const CBYTES *val)
{
    CSESSION_ITEM *csession_item;

    alloc_static_mem(MM_CSESSION_ITEM, &csession_item, LOC_CSESSION_0016);
    if(NULL_PTR == csession_item)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_item_new:alloc csession item failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csession_item_init(csession_item))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_item_new:init csession item failed\n");
        free_static_mem(MM_CSESSION_ITEM, csession_item, LOC_CSESSION_0017);
        return (NULL_PTR);
    }

    if(NULL_PTR != key)
    {
        cstring_clone(key, CSESSION_ITEM_KEY(csession_item));
    }

    if(NULL_PTR != val)
    {
        cbytes_clone(val, CSESSION_ITEM_VAL(csession_item));
    }

    return (csession_item);
}

EC_BOOL csession_item_init(CSESSION_ITEM *csession_item)
{
    cstring_init(CSESSION_ITEM_KEY(csession_item), NULL_PTR);
    cbytes_init(CSESSION_ITEM_VAL(csession_item));
    clist_init(CSESSION_ITEM_CHILDREN(csession_item), MM_CSESSION_ITEM, LOC_CSESSION_0018);

    return (EC_TRUE);
}

EC_BOOL csession_item_clean(CSESSION_ITEM *csession_item)
{
    cstring_clean(CSESSION_ITEM_KEY(csession_item));
    cbytes_clean(CSESSION_ITEM_VAL(csession_item));

    clist_clean(CSESSION_ITEM_CHILDREN(csession_item), (CLIST_DATA_DATA_CLEANER)csession_item_free);

    return (EC_TRUE);
}

EC_BOOL csession_item_free(CSESSION_ITEM *csession_item)
{
    if(NULL_PTR != csession_item)
    {
        csession_item_clean(csession_item);
        free_static_mem(MM_CSESSION_ITEM, csession_item, LOC_CSESSION_0019);
    }

    return (EC_TRUE);
}

EC_BOOL csession_item_match_key(const CSESSION_ITEM *csession_item, const CSTRING *key)
{
    if(EC_TRUE == cstring_is_equal(CSESSION_ITEM_KEY(csession_item), key))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csession_item_match_val(const CSESSION_ITEM *csession_item, const CBYTES *val)
{
    if(EC_TRUE == cbytes_cmp(CSESSION_ITEM_VAL(csession_item), val))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void csession_item_print(LOG *log, const CSESSION_ITEM *csession_item, const UINT32 level)
{
    CLIST_DATA *clist_data;

    c_ident_print(log, level);
    if(EC_TRUE == clist_is_empty(CSESSION_ITEM_CHILDREN(csession_item)))
    {
        sys_print(log, "<item key=\"%s\" val=\"%.*s\"/>\n",
                       (char *)CSESSION_ITEM_KEY_STR(csession_item),
                       cbytes_len(CSESSION_ITEM_VAL(csession_item)), (char *)cbytes_buf(CSESSION_ITEM_VAL(csession_item))
                 );
        return;
    }

    sys_print(log, "<item key=\"%s\" val=\"%.*s\">\n",
                   (char *)CSESSION_ITEM_KEY_STR(csession_item),
                   cbytes_len(CSESSION_ITEM_VAL(csession_item)), (char *)cbytes_buf(CSESSION_ITEM_VAL(csession_item))
             );

    CLIST_LOCK(CSESSION_ITEM_CHILDREN(csession_item), LOC_CSESSION_0020);
    CLIST_LOOP_NEXT(CSESSION_ITEM_CHILDREN(csession_item), clist_data)
    {
        CSESSION_ITEM *csession_item;
        csession_item = (CSESSION_ITEM *)CLIST_DATA_DATA(clist_data);
        csession_item_print(log, csession_item, level + 1);
    }
    CLIST_UNLOCK(CSESSION_ITEM_CHILDREN(csession_item), LOC_CSESSION_0021);

    c_ident_print(log, level);
    sys_print(log, "</item>\n");
    return;
}

CSESSION_NODE *csession_search_by_name(const UINT32 csession_md_id, const CSTRING *name)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_search_by_name: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    clist_data = clist_search_front(CSESSION_MD_SESSION_LIST(csession_md), name, (CLIST_DATA_DATA_CMP)csession_node_match_name);
    if(NULL_PTR == clist_data)
    {
        return (NULL_PTR);
    }

    csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0022);
    return (csession_node);
}

CSESSION_NODE *csession_search_by_id(const UINT32 csession_md_id, const UINT32 session_id)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_search_by_id: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    clist_data = clist_search_front(CSESSION_MD_SESSION_LIST(csession_md), (void *)session_id, (CLIST_DATA_DATA_CMP)csession_node_match_id);
    if(NULL_PTR == clist_data)
    {
        return (NULL_PTR);
    }

    csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0023);
    return (csession_node);
}

EC_BOOL csession_add(const UINT32 csession_md_id, const CSTRING *name, const UINT32 expire_nsec)
{
    CSESSION_MD *csession_md;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_add: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    CSESSION_MD_CRWLOCK_WRLOCK(csession_md, LOC_CSESSION_0024);

    csession_node = csession_search_by_name(csession_md_id, name);
    if(NULL_PTR != csession_node)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0025);
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_add: session %s already exists, refuse to add again\n", (char *)cstring_get_str(name));
        return (EC_FALSE);
    }

    csession_node = csession_node_new(name, expire_nsec);
    if(NULL_PTR == csession_node)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0026);
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_add: new csession node with name %s failed\n", (char *)cstring_get_str(name));
        return (EC_FALSE);
    }

    CSESSION_NODE_ID(csession_node) = __csession_reserve_id(csession_md_id);

    clist_push_back(CSESSION_MD_SESSION_LIST(csession_md), (void *)csession_node);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0027);
    return (EC_TRUE);
}

EC_BOOL csession_rmv_by_name(const UINT32 csession_md_id, const CSTRING *name)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_rmv_by_name: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    CSESSION_MD_CRWLOCK_WRLOCK(csession_md, LOC_CSESSION_0028);

    clist_data = clist_search_front(CSESSION_MD_SESSION_LIST(csession_md), name, (CLIST_DATA_DATA_CMP)csession_node_match_name);
    if(NULL_PTR == clist_data)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0029);
        dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_rmv_by_name: session %s not exist, remove nothing\n", (char *)cstring_get_str(name));
        return (EC_TRUE);
    }

    csession_node = (CSESSION_NODE *)clist_rmv(CSESSION_MD_SESSION_LIST(csession_md), clist_data);
    csession_node_free(csession_node);
    dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_rmv_by_name: session %s was removed\n", (char *)cstring_get_str(name));
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0030);
    return (EC_TRUE);
}

EC_BOOL csession_rmv_by_id(const UINT32 csession_md_id, const UINT32 session_id)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_rmv_by_id: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);
    CSESSION_MD_CRWLOCK_WRLOCK(csession_md, LOC_CSESSION_0031);

    clist_data = clist_search_front(CSESSION_MD_SESSION_LIST(csession_md), (void *)session_id, (CLIST_DATA_DATA_CMP)csession_node_match_id);
    if(NULL_PTR == clist_data)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0032);
        dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_rmv_by_id: session %ld not exist, remove nothing\n", session_id);
        return (EC_TRUE);
    }

    csession_node = (CSESSION_NODE *)clist_rmv(CSESSION_MD_SESSION_LIST(csession_md), clist_data);
    csession_node_free(csession_node);
    dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_rmv_by_id: session %ld was removed\n", session_id);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0033);
    return (EC_TRUE);
}

EC_BOOL csession_rmv_by_name_regex(const UINT32 csession_md_id, const CSTRING *session_name_regex)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;

    pcre *name_re;
    const char *errstr;
    int erroffset;

    int ovec[3];
    int ovec_count;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_rmv_by_name_regex: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    name_re = pcre_compile((char *)cstring_get_str(session_name_regex), 0, &errstr, &erroffset, NULL_PTR);
    if(NULL_PTR == name_re)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_rmv_by_name_regex: pcre compile name pattern %s at %d:%s failed\n",
                            (char *)cstring_get_str(session_name_regex), erroffset, errstr);
        return (EC_FALSE);
    }

    ovec_count = sizeof(ovec)/sizeof(ovec[0]);

    CSESSION_MD_CRWLOCK_WRLOCK(csession_md, LOC_CSESSION_0034);

    CLIST_LOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0035);
    CLIST_LOOP_NEXT(CSESSION_MD_SESSION_LIST(csession_md), clist_data)
    {
        CSESSION_NODE *csession_node;
        CSTRING *csession_node_name;
        CLIST_DATA *clist_data_rmv;

        csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == csession_node)
        {
            continue;
        }

        csession_node_name = CSESSION_NODE_NAME(csession_node);
        if(0 > pcre_exec(name_re, NULL_PTR, (char *)cstring_get_str(csession_node_name), cstring_get_len(csession_node_name), 0, 0, ovec, ovec_count))
        {
            dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] csession_rmv_by_name_regex: session name %s not matched regex %s\n",
                               (char *)cstring_get_str(csession_node_name),
                               (char *)cstring_get_str(session_name_regex));
            continue;
        }

        clist_data_rmv = clist_data;
        clist_data = CLIST_DATA_PREV(clist_data);
        clist_rmv_no_lock(CSESSION_MD_SESSION_LIST(csession_md), clist_data_rmv);

        dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_rmv_by_name_regex: session %s would be removed\n", (char *)cstring_get_str(csession_node_name));
        csession_node_free(csession_node);
    }
    CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0036);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0037);
    pcre_free(name_re);

    return (EC_TRUE);
}

EC_BOOL csession_rmv_by_id_regex(const UINT32 csession_md_id, const CSTRING *session_id_regex)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;

    pcre *id_re;
    const char *errstr;
    int erroffset;

    int ovec[3];
    int ovec_count;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_rmv_by_id_regex: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    id_re = pcre_compile((char *)cstring_get_str(session_id_regex), 0, &errstr, &erroffset, NULL_PTR);
    if(NULL_PTR == id_re)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_rmv_by_id_regex: pcre compile id pattern %s at %d:%s failed\n",
                            (char *)cstring_get_str(session_id_regex), erroffset, errstr);
        return (EC_FALSE);
    }

    ovec_count = sizeof(ovec)/sizeof(ovec[0]);

    CSESSION_MD_CRWLOCK_WRLOCK(csession_md, LOC_CSESSION_0038);

    CLIST_LOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0039);
    CLIST_LOOP_NEXT(CSESSION_MD_SESSION_LIST(csession_md), clist_data)
    {
        CSESSION_NODE *csession_node;
        char csession_node_id_str[64];
        CSTRING *csession_node_name;
        CLIST_DATA *clist_data_rmv;

        csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == csession_node)
        {
            continue;
        }

        csession_node_name = CSESSION_NODE_NAME(csession_node);

        snprintf(csession_node_id_str, sizeof(csession_node_id_str)/sizeof(csession_node_id_str[0]), "%ld", CSESSION_NODE_ID(csession_node));
        if(0 > pcre_exec(id_re, NULL_PTR, (char *)csession_node_id_str, strlen(csession_node_id_str), 0, 0, ovec, ovec_count))
        {
            dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] csession_rmv_by_id_regex: session id %ld not matched regex %s\n",
                               CSESSION_NODE_ID(csession_node),
                               (char *)cstring_get_str(session_id_regex));
            continue;
        }

        clist_data_rmv = clist_data;
        clist_data = CLIST_DATA_PREV(clist_data);
        clist_rmv_no_lock(CSESSION_MD_SESSION_LIST(csession_md), clist_data_rmv);

        dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_rmv_by_id_regex: session %s would be removed\n", (char *)cstring_get_str(csession_node_name));
        csession_node_free(csession_node);
    }
    CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0040);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0041);
    pcre_free(id_re);

    return (EC_TRUE);
}

EC_BOOL csession_get_name(const UINT32 csession_md_id, const UINT32 session_id, CSTRING *session_name)
{
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_name: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_node = csession_search_by_id(csession_md_id, session_id);
    if(NULL_PTR == csession_node)
    {
        return (EC_FALSE);
    }

    cstring_clone(CSESSION_NODE_NAME(csession_node), session_name);
    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0042);
    return (EC_TRUE);
}

EC_BOOL csession_get_id(const UINT32 csession_md_id, const CSTRING *session_name, UINT32 *session_id)
{
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_id: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_node = csession_search_by_name(csession_md_id, session_name);
    if(NULL_PTR == csession_node)
    {
        return (EC_FALSE);
    }

    (*session_id) = CSESSION_NODE_ID(csession_node);
    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0043);
    return (EC_TRUE);
}

/*note: path is the full path of key. e.g., top=root&level1=b&level2=c*/
EC_BOOL csession_set(const UINT32 csession_md_id, CSESSION_NODE *csession_node, const CSTRING *path, const CBYTES *val)
{
    CSTRING *path_cloned;
    char  *segs[ CSESSION_PATH_MAX_DEPTH ];
    UINT32 seg_num;
    UINT32 seg_idx;

    CLIST  *sub_cache_tree;
    CSESSION_ITEM *csession_item;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_set: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    path_cloned = cstring_new(cstring_get_str(path), LOC_CSESSION_0044);
    if(NULL_PTR == path_cloned)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_set: clone string %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    /*c_str_split will change path_cloned*/
    seg_num = c_str_split((char *)cstring_get_str(path_cloned), CSESSION_PATH_SEPARATORS, segs, CSESSION_PATH_MAX_DEPTH);

    sub_cache_tree = CSESSION_NODE_CACHE_TREE(csession_node);
    csession_item = NULL_PTR;

    for(seg_idx = 0; seg_idx < seg_num; seg_idx ++)
    {
        CSTRING key;
        CLIST_DATA *clist_data;

        cstring_set_str(&key, (UINT8 *)(segs[ seg_idx ]));
        clist_data = clist_search_front(sub_cache_tree, &key, (CLIST_DATA_DATA_CMP)csession_item_match_key);
        if(NULL_PTR != clist_data)
        {
            csession_item = (CSESSION_ITEM *)CLIST_DATA_DATA(clist_data);
            sub_cache_tree = CSESSION_ITEM_CHILDREN(csession_item);
            continue;
        }

        csession_item = csession_item_new(&key, NULL_PTR);
        if(NULL_PTR == csession_item)
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_set: new session item for key %s at %ld # failed\n",
                               (char *)cstring_get_str(&key),
                               seg_idx);
            cstring_free(path_cloned);
            return (EC_FALSE);
        }

        /*add new session item*/
        clist_push_back(sub_cache_tree, (void *)csession_item);

        /*move forward*/
        sub_cache_tree = CSESSION_ITEM_CHILDREN(csession_item);
    }

    if(NULL_PTR == csession_item)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_set: not found item for path %s\n", (char *)cstring_get_str(path));
        cstring_free(path_cloned);
        return (EC_FALSE);
    }

    cbytes_clean(CSESSION_ITEM_VAL(csession_item));
    if(EC_FALSE == cbytes_clone(val, CSESSION_ITEM_VAL(csession_item)))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_set: set val to path %s failed and maybe corrupted\n", (char *)cstring_get_str(path));
        cstring_free(path_cloned);
        return (EC_FALSE);
    }

    cstring_free(path_cloned);

    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0045);
    return (EC_TRUE);
}

EC_BOOL csession_set_by_name(const UINT32 csession_md_id, const CSTRING *session_name, const CSTRING *path, const CBYTES *val)
{
    CSESSION_MD   *csession_md;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_set_by_name: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    CSESSION_MD_CRWLOCK_WRLOCK(csession_md, LOC_CSESSION_0046);

    csession_node = csession_search_by_name(csession_md_id, session_name);
    if(NULL_PTR == csession_node)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0047);
        return (EC_FALSE);
    }

    if(EC_FALSE == csession_set(csession_md_id, csession_node, path, val))
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0048);
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_set_by_name: set val of %s to session %s failed\n",
                            (char *)cstring_get_str(path),
                            (char *)cstring_get_str(session_name)
                            );
        return (EC_FALSE);
    }

    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0049);
    return (EC_TRUE);
}

EC_BOOL csession_set_by_id(const UINT32 csession_md_id, const UINT32 session_id, const CSTRING *path, const CBYTES *val)
{
    CSESSION_MD   *csession_md;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_set_by_id: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    CSESSION_MD_CRWLOCK_WRLOCK(csession_md, LOC_CSESSION_0050);

    csession_node = csession_search_by_id(csession_md_id, session_id);
    if(NULL_PTR == csession_node)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0051);
        return (EC_FALSE);
    }

    if(EC_FALSE == csession_set(csession_md_id, csession_node, path, val))
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0052);
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_set_by_id: set val of %s to session %ld failed\n",
                            (char *)cstring_get_str(path),
                            session_id
                            );
        return (EC_FALSE);
    }

    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0053);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csession_get_depth(const UINT32 csession_md_id, const CLIST *cache_tree,
                                            const char **segs, const UINT32 seg_idx, const UINT32 seg_num,
                                            CLIST *csession_item_list)
{
    CLIST_DATA *clist_data;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__csession_get_depth: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    if(seg_idx >= seg_num)
    {
        return (EC_TRUE);
    }

    CLIST_LOCK(cache_tree, LOC_CSESSION_0054);
    CLIST_LOOP_NEXT(cache_tree, clist_data)
    {
        CSESSION_ITEM      *csession_item;
        CSESSION_ITEM      *new_csession_item;
        CSTRING *key;
        CBYTES  *val;

        csession_item = (CSESSION_ITEM *)CLIST_DATA_DATA(clist_data);
        key = CSESSION_ITEM_KEY(csession_item);
        val = CSESSION_ITEM_VAL(csession_item);

        //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_depth: seg = %s, check key %s\n", segs[ seg_idx ], cstring_get_str(key));

        if(0 != STRCMP(segs[ seg_idx ], (char *)cstring_get_str(key)))
        {
            continue;
        }

        /*in depth!*/
        new_csession_item = csession_item_new(key, val);
        if(NULL_PTR == new_csession_item)
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_depth: new csession item failed\n");
            CLIST_UNLOCK(cache_tree, LOC_CSESSION_0055);
            return (EC_FALSE);
        }

        if(EC_FALSE == __csession_get_depth(csession_md_id,
                                             CSESSION_ITEM_CHILDREN(csession_item),
                                             segs, seg_idx + 1, seg_num,
                                             CSESSION_ITEM_CHILDREN(new_csession_item)))
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_depth: get in depth failed\n");
            CLIST_UNLOCK(cache_tree, LOC_CSESSION_0056);
            csession_item_free(new_csession_item);
            return (EC_FALSE);
        }

        /*add new csession item to list for return*/
        //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_depth: seg = %s, check key %s [matched][pushed]\n", segs[ seg_idx ], cstring_get_str(key));
        //csession_item_print(LOGSTDNULL, new_csession_item, 0);
        clist_push_back(csession_item_list, (void *)new_csession_item);
    }
    CLIST_UNLOCK(cache_tree, LOC_CSESSION_0057);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csession_get_key_regex_depth(const UINT32 csession_md_id, const CLIST *cache_tree,
                                            const char **segs, const UINT32 seg_idx, const UINT32 seg_num,
                                            CLIST *csession_item_list)
{
    pcre *seg_re;
    const char *errstr;
    int erroffset;

    int ovec[3];
    int ovec_count;

    CLIST_DATA *clist_data;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__csession_get_key_regex_depth: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    if(seg_idx >= seg_num)
    {
        return (EC_TRUE);
    }

    //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_key_regex_depth: seg = %s\n", segs[ seg_idx ]);
    seg_re = pcre_compile(segs[ seg_idx ], 0, &errstr, &erroffset, NULL_PTR);
    if(NULL_PTR == seg_re)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_key_regex_depth: pcre compile seg pattern %s at %d:%s failed\n",
                            segs[ seg_idx ], erroffset, errstr);
        return (EC_FALSE);
    }

    ovec_count = sizeof(ovec)/sizeof(ovec[0]);

    CLIST_LOCK(cache_tree, LOC_CSESSION_0058);
    CLIST_LOOP_NEXT(cache_tree, clist_data)
    {
        CSESSION_ITEM      *csession_item;
        CSESSION_ITEM      *new_csession_item;
        CSTRING *key;
        CBYTES  *val;

        csession_item = (CSESSION_ITEM *)CLIST_DATA_DATA(clist_data);
        key = CSESSION_ITEM_KEY(csession_item);
        val = CSESSION_ITEM_VAL(csession_item);

        //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_key_regex_depth: seg = %s, check key %s\n", segs[ seg_idx ], cstring_get_str(key));
        if(0 > pcre_exec(seg_re, NULL_PTR, (char *)cstring_get_str(key), cstring_get_len(key), 0, 0, ovec, ovec_count))
        {
            //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_key_regex_depth: key %s not matched regex %s\n", (char *)cstring_get_str(key), segs[ seg_idx ]);
            continue;
        }
        //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_key_regex_depth: seg = %s, check key %s [matched]\n", segs[ seg_idx ], cstring_get_str(key));

        /*in depth!*/
        new_csession_item = csession_item_new(key, val);
        if(NULL_PTR == new_csession_item)
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_key_regex_depth: new csession item failed\n");
            CLIST_UNLOCK(cache_tree, LOC_CSESSION_0059);
            pcre_free(seg_re);
            return (EC_FALSE);
        }

        if(EC_FALSE == __csession_get_key_regex_depth(csession_md_id,
                                             CSESSION_ITEM_CHILDREN(csession_item),
                                             segs, seg_idx + 1, seg_num,
                                             CSESSION_ITEM_CHILDREN(new_csession_item)))
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_key_regex_depth: get in depth failed\n");
            CLIST_UNLOCK(cache_tree, LOC_CSESSION_0060);
            pcre_free(seg_re);
            csession_item_free(new_csession_item);
            return (EC_FALSE);
        }

        /*add new csession item to list for return*/
        //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_key_regex_depth: seg = %s, check key %s [matched][pushed]\n", segs[ seg_idx ], cstring_get_str(key));
        //csession_item_print(LOGSTDNULL, new_csession_item, 0);
        clist_push_back(csession_item_list, (void *)new_csession_item);
    }
    CLIST_UNLOCK(cache_tree, LOC_CSESSION_0061);

    pcre_free(seg_re);

    return (EC_TRUE);
}

/*note: path is the full path of key with wildcards. e.g., top=root&level1=*&level2=c*x*/
EC_BOOL csession_get(const UINT32 csession_md_id, const CSESSION_NODE *csession_node, const CSTRING *path, CLIST *csession_item_list)
{
    CSTRING *path_cloned;
    char    *segs[ CSESSION_PATH_MAX_DEPTH ];
    UINT32   seg_num;

    const CLIST  *sub_cache_tree;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    path_cloned = cstring_new(cstring_get_str(path), LOC_CSESSION_0062);
    if(NULL_PTR == path_cloned)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get: clone string %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    /*c_str_split will change path_cloned*/
    seg_num = c_str_split((char *)cstring_get_str(path_cloned), CSESSION_PATH_SEPARATORS, segs, CSESSION_PATH_MAX_DEPTH);

    sub_cache_tree = CSESSION_NODE_CACHE_TREE(csession_node);
    if(EC_FALSE == __csession_get_depth(csession_md_id, sub_cache_tree, (const char **)segs, 0, seg_num, csession_item_list))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get: get in depth failed\n");
        cstring_free(path_cloned);
        return (EC_FALSE);
    }

    cstring_free(path_cloned);
    return (EC_TRUE);
}

EC_BOOL csession_get_key_regex(const UINT32 csession_md_id, const CSESSION_NODE *csession_node, const CSTRING *path, CLIST *csession_item_list)
{
    CSTRING *path_cloned;
    char    *segs[ CSESSION_PATH_MAX_DEPTH ];
    UINT32   seg_num;

    const CLIST  *sub_cache_tree;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_key_regex: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    path_cloned = cstring_new(cstring_get_str(path), LOC_CSESSION_0063);
    if(NULL_PTR == path_cloned)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_key_regex: clone string %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    /*c_str_split will change path_cloned*/
    seg_num = c_str_split((char *)cstring_get_str(path_cloned), CSESSION_PATH_SEPARATORS, segs, CSESSION_PATH_MAX_DEPTH);

    sub_cache_tree = CSESSION_NODE_CACHE_TREE(csession_node);
    if(EC_FALSE == __csession_get_key_regex_depth(csession_md_id, sub_cache_tree, (const char **)segs, 0, seg_num, csession_item_list))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_key_regex: get in depth failed\n");
        cstring_free(path_cloned);
        return (EC_FALSE);
    }

    cstring_free(path_cloned);
    return (EC_TRUE);
}

EC_BOOL csession_get_by_name(const UINT32 csession_md_id, const CSTRING *session_name, const CSTRING *path, CLIST *csession_item_list)
{
    CSESSION_MD   *csession_md;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_by_name: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    CSESSION_MD_CRWLOCK_RDLOCK(csession_md, LOC_CSESSION_0064);

    csession_node = csession_search_by_name(csession_md_id, session_name);
    if(NULL_PTR == csession_node)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0065);
        return (EC_TRUE);
    }

    if(EC_FALSE == csession_get(csession_md_id, csession_node, path, csession_item_list))
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0066);
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_name: get items of %s from session %s failed\n",
                            (char *)cstring_get_str(path),
                            (char *)cstring_get_str(session_name)
                            );
        return (EC_FALSE);
    }

    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0067);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0068);
    return (EC_TRUE);
}

EC_BOOL csession_get_by_id(const UINT32 csession_md_id, const UINT32 session_id, const CSTRING *path, CLIST *csession_item_list)
{
    CSESSION_MD   *csession_md;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_by_id: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    CSESSION_MD_CRWLOCK_RDLOCK(csession_md, LOC_CSESSION_0069);

    csession_node = csession_search_by_id(csession_md_id, session_id);
    if(NULL_PTR == csession_node)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0070);
        return (EC_TRUE);
    }

    if(EC_FALSE == csession_get(csession_md_id, csession_node, path, csession_item_list))
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0071);
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_id: get items of %s from session %ld failed\n",
                            (char *)cstring_get_str(path),
                            session_id
                            );
        return (EC_FALSE);
    }

    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0072);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0073);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csession_get_children_depth(const UINT32 csession_md_id, const CLIST *cache_tree,
                                            const char **segs, const UINT32 seg_idx, const UINT32 seg_num,
                                            CLIST *csession_item_list)
{
    CLIST_DATA *clist_data;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__csession_get_children_depth: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    if(seg_idx >= seg_num)
    {
        CLIST_LOCK(cache_tree, LOC_CSESSION_0074);
        CLIST_LOOP_NEXT(cache_tree, clist_data)
        {
            CSESSION_ITEM      *csession_item;
            CSESSION_ITEM      *new_csession_item;
            CSTRING *key;
            CBYTES  *val;

            csession_item = (CSESSION_ITEM *)CLIST_DATA_DATA(clist_data);
            key = CSESSION_ITEM_KEY(csession_item);
            val = CSESSION_ITEM_VAL(csession_item);

            /*clone child*/
            new_csession_item = csession_item_new(key, val);
            if(NULL_PTR == new_csession_item)
            {
                dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_children_depth: new csession item failed\n");
                CLIST_UNLOCK(cache_tree, LOC_CSESSION_0075);
                return (EC_FALSE);
            }
            clist_push_back(csession_item_list, (void *)new_csession_item);
        }
        CLIST_UNLOCK(cache_tree, LOC_CSESSION_0076);

        return (EC_TRUE);
    }

    CLIST_LOCK(cache_tree, LOC_CSESSION_0077);
    CLIST_LOOP_NEXT(cache_tree, clist_data)
    {
        CSESSION_ITEM      *csession_item;
        CSESSION_ITEM      *new_csession_item;
        CSTRING *key;
        CBYTES  *val;

        csession_item = (CSESSION_ITEM *)CLIST_DATA_DATA(clist_data);
        key = CSESSION_ITEM_KEY(csession_item);
        val = CSESSION_ITEM_VAL(csession_item);

        if(0 != STRCMP(segs[ seg_idx ], (char *)cstring_get_str(key)))
        {
            continue;
        }

        /*in depth!*/
        new_csession_item = csession_item_new(key, val);
        if(NULL_PTR == new_csession_item)
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_children_depth: new csession item failed\n");
            CLIST_UNLOCK(cache_tree, LOC_CSESSION_0078);
            return (EC_FALSE);
        }

        if(EC_FALSE == __csession_get_children_depth(csession_md_id,
                                             CSESSION_ITEM_CHILDREN(csession_item),
                                             segs, seg_idx + 1, seg_num,
                                             CSESSION_ITEM_CHILDREN(new_csession_item)))
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:__csession_get_children_depth: get in depth failed\n");
            CLIST_UNLOCK(cache_tree, LOC_CSESSION_0079);
            csession_item_free(new_csession_item);
            return (EC_FALSE);
        }

        /*add new csession item to list for return*/
        //dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] __csession_get_children_depth: seg = %s, check key %s [matched][pushed]\n", segs[ seg_idx ], cstring_get_str(key));
        //csession_item_print(LOGSTDNULL, new_csession_item, 0);
        clist_push_back(csession_item_list, (void *)new_csession_item);
    }
    CLIST_UNLOCK(cache_tree, LOC_CSESSION_0080);

    return (EC_TRUE);
}

EC_BOOL csession_get_children(const UINT32 csession_md_id, const CSESSION_NODE *csession_node, const CSTRING *path, CLIST *csession_item_list)
{
    CSTRING *path_cloned;
    char    *segs[ CSESSION_PATH_MAX_DEPTH ];
    UINT32   seg_num;

    const CLIST  *sub_cache_tree;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_children: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    path_cloned = cstring_new(cstring_get_str(path), LOC_CSESSION_0081);
    if(NULL_PTR == path_cloned)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_children: clone string %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    /*c_str_split will change path_cloned*/
    seg_num = c_str_split((char *)cstring_get_str(path_cloned), CSESSION_PATH_SEPARATORS, segs, CSESSION_PATH_MAX_DEPTH);

    sub_cache_tree = CSESSION_NODE_CACHE_TREE(csession_node);
    if(EC_FALSE == __csession_get_children_depth(csession_md_id, sub_cache_tree, (const char **)segs, 0, seg_num, csession_item_list))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_children: get in depth failed\n");
        cstring_free(path_cloned);
        return (EC_FALSE);
    }

    cstring_free(path_cloned);
    return (EC_TRUE);
}

EC_BOOL csession_get_children_by_name(const UINT32 csession_md_id, const CSTRING *session_name, const CSTRING *path, CLIST *csession_item_list)
{
    CSESSION_MD   *csession_md;
    CSESSION_NODE *csession_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_children_by_name: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    CSESSION_MD_CRWLOCK_RDLOCK(csession_md, LOC_CSESSION_0082);

    csession_node = csession_search_by_name(csession_md_id, session_name);
    if(NULL_PTR == csession_node)
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0083);
        return (EC_TRUE);
    }

    if(EC_FALSE == csession_get_children(csession_md_id, csession_node, path, csession_item_list))
    {
        CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0084);
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_children_by_name: get items of %s from session %s failed\n",
                            (char *)cstring_get_str(path),
                            (char *)cstring_get_str(session_name)
                            );
        return (EC_FALSE);
    }

    CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0085);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0086);
    return (EC_TRUE);
}


EC_BOOL csession_get_by_name_regex(const UINT32 csession_md_id, const CSTRING *session_name_regex, const CSTRING *path, CLIST *csession_node_list)
{
    CSESSION_MD   *csession_md;
    CLIST_DATA    *clist_data;

    pcre *name_re;
    const char *errstr;
    int erroffset;

    int ovec[3];
    int ovec_count;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_by_name_regex: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    name_re = pcre_compile((char *)cstring_get_str(session_name_regex), 0, &errstr, &erroffset, NULL_PTR);
    if(NULL_PTR == name_re)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_name_regex: pcre compile name pattern %s at %d:%s failed\n",
                            (char *)cstring_get_str(session_name_regex), erroffset, errstr);
        return (EC_FALSE);
    }

    ovec_count = sizeof(ovec)/sizeof(ovec[0]);

    CSESSION_MD_CRWLOCK_RDLOCK(csession_md, LOC_CSESSION_0087);

    CLIST_LOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0088);
    CLIST_LOOP_NEXT(CSESSION_MD_SESSION_LIST(csession_md), clist_data)
    {
        CSESSION_NODE *csession_node;
        CSTRING *csession_node_name;
        CSESSION_NODE *new_csession_node;

        csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == csession_node)
        {
            continue;
        }

        csession_node_name = CSESSION_NODE_NAME(csession_node);
        if(0 > pcre_exec(name_re, NULL_PTR, (char *)cstring_get_str(csession_node_name), cstring_get_len(csession_node_name), 0, 0, ovec, ovec_count))
        {
            dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] csession_get_by_name_regex: session name %s not matched regex %s\n",
                               (char *)cstring_get_str(csession_node_name),
                               (char *)cstring_get_str(session_name_regex));
            continue;
        }

        /*to avoid wasting on session id, here new cession node on modi CMPI_ANY_MODI*/
        new_csession_node = csession_node_new(CSESSION_NODE_NAME(csession_node), CSESSION_NODE_EXPIRE_NSEC(csession_node));
        if(NULL_PTR == new_csession_node)
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_name_regex:alloc csession node failed\n");
            CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0089);
            CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0090);
            pcre_free(name_re);
            return (EC_FALSE);
        }

        CSESSION_NODE_ID(new_csession_node) = __csession_reserve_id(csession_md_id);

        /*clone cession node*/
        CSESSION_NODE_ID(new_csession_node)          = CSESSION_NODE_ID(csession_node);
        CSESSION_NODE_CREATE_TIME(new_csession_node) = CSESSION_NODE_CREATE_TIME(csession_node);
        CSESSION_NODE_ACCESS_TIME(new_csession_node) = CSESSION_NODE_ACCESS_TIME(csession_node);

        if(EC_FALSE == csession_get_key_regex(csession_md_id, csession_node, path, CSESSION_NODE_CACHE_TREE(new_csession_node)))
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_name_regex: get items of %s from session %s failed\n",
                                (char *)cstring_get_str(path),
                                (char *)cstring_get_str(csession_node_name)
                                );
            csession_node_free(new_csession_node);
            CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0091);
            CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0092);
            pcre_free(name_re);
            return (EC_FALSE);
        }

        clist_push_back(csession_node_list, (void *)new_csession_node);

        CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0093);
    }
    CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0094);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0095);
    pcre_free(name_re);

    return (EC_TRUE);
}

EC_BOOL csession_get_by_id_regex(const UINT32 csession_md_id, const CSTRING *session_id_regex, const CSTRING *path, CLIST *csession_node_list)
{
    CSESSION_MD   *csession_md;
    CLIST_DATA    *clist_data;

    pcre *id_re;
    const char *errstr;
    int erroffset;

    int ovec[3];
    int ovec_count;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:csession_get_by_id_regex: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    csession_md = CSESSION_MD_GET(csession_md_id);

    id_re = pcre_compile((char *)cstring_get_str(session_id_regex), 0, &errstr, &erroffset, NULL_PTR);
    if(NULL_PTR == id_re)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_id_regex: pcre compile id pattern %s at %d:%s failed\n",
                            (char *)cstring_get_str(session_id_regex), erroffset, errstr);
        return (EC_FALSE);
    }

    ovec_count = sizeof(ovec)/sizeof(ovec[0]);

    CSESSION_MD_CRWLOCK_RDLOCK(csession_md, LOC_CSESSION_0096);

    CLIST_LOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0097);
    CLIST_LOOP_NEXT(CSESSION_MD_SESSION_LIST(csession_md), clist_data)
    {
        CSESSION_NODE *csession_node;
        char csession_node_id_str[64];
        CSESSION_NODE *new_csession_node;

        csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == csession_node)
        {
            continue;
        }

        snprintf(csession_node_id_str, sizeof(csession_node_id_str)/sizeof(csession_node_id_str[0]), "%ld", CSESSION_NODE_ID(csession_node));
        if(0 > pcre_exec(id_re, NULL_PTR, (char *)csession_node_id_str, strlen(csession_node_id_str), 0, 0, ovec, ovec_count))
        {
            dbg_log(SEC_0025_CSESSION, 9)(LOGSTDNULL, "[DEBUG] csession_get_by_id_regex: session id %ld not matched regex %s\n",
                               CSESSION_NODE_ID(csession_node),
                               (char *)cstring_get_str(session_id_regex));
            continue;
        }

        /*to avoid wasting on session id, here new cession node on modi CMPI_ANY_MODI*/
        new_csession_node = csession_node_new(CSESSION_NODE_NAME(csession_node), CSESSION_NODE_EXPIRE_NSEC(csession_node));
        if(NULL_PTR == new_csession_node)
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_id_regex:alloc csession node failed\n");
            CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0098);
            CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0099);
            pcre_free(id_re);
            return (EC_FALSE);
        }

        CSESSION_NODE_ID(new_csession_node) = __csession_reserve_id(csession_md_id);

        /*clone cession node*/
        CSESSION_NODE_ID(new_csession_node)          = CSESSION_NODE_ID(csession_node);
        CSESSION_NODE_CREATE_TIME(new_csession_node) = CSESSION_NODE_CREATE_TIME(csession_node);
        CSESSION_NODE_ACCESS_TIME(new_csession_node) = CSESSION_NODE_ACCESS_TIME(csession_node);

        if(EC_FALSE == csession_get_key_regex(csession_md_id, csession_node, path, CSESSION_NODE_CACHE_TREE(new_csession_node)))
        {
            dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_get_by_id_regex: get items of %s from session %ld failed\n",
                                (char *)cstring_get_str(path),
                                CSESSION_NODE_ID(csession_node)
                                );
            csession_node_free(new_csession_node);
            CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0100);
            CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0101);
            pcre_free(id_re);
            return (EC_FALSE);
        }

        clist_push_back(csession_node_list, (void *)new_csession_node);

        CSESSION_NODE_UPDATE_ACCESS_TIME(csession_node, LOC_CSESSION_0102);
    }
    CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0103);
    CSESSION_MD_CRWLOCK_UNLOCK(csession_md, LOC_CSESSION_0104);

    pcre_free(id_re);

    return (EC_TRUE);
}

EC_BOOL csession_expire_handle(const UINT32 csession_md_id)
{
    CSESSION_MD *csession_md;
    CLIST_DATA  *clist_data;
    CTIMET cur_time;

    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        return (EC_FALSE);
    }

    csession_md = CSESSION_MD_GET(csession_md_id);
    CTIMET_GET(cur_time);

    CLIST_LOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0105);
    CLIST_LOOP_NEXT(CSESSION_MD_SESSION_LIST(csession_md), clist_data)
    {
        CSESSION_NODE *csession_node;
        CLIST_DATA    *clist_data_rmv;

        CTM *create_ctm;
        CTM *access_ctm;
        CTM *current_ctm;

        csession_node = (CSESSION_NODE *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == csession_node)
        {
            continue;
        }

        if(EC_FALSE == csession_node_is_expired(csession_md_id, csession_node, &cur_time))
        {
            continue;
        }

        create_ctm  = c_localtime_r(&CSESSION_NODE_CREATE_TIME(csession_node));
        access_ctm  = c_localtime_r(&CSESSION_NODE_ACCESS_TIME(csession_node));
        current_ctm = c_localtime_r(&cur_time);

        dbg_log(SEC_0025_CSESSION, 5)(LOGSTDOUT, "csession_expire_handle: session %s was expired which "
                           "create at %4d-%02d-%02d %02d:%02d:%02d, "
                           "last access at %4d-%02d-%02d %02d:%02d:%02d, "
                           "current is %4d-%02d-%02d %02d:%02d:%02d\n",
                           (char *)CSESSION_NODE_NAME_STR(csession_node),

                            TIME_IN_YMDHMS(create_ctm),
                            TIME_IN_YMDHMS(access_ctm),
                            TIME_IN_YMDHMS(current_ctm)
                           );

        clist_data_rmv = clist_data;
        clist_data = CLIST_DATA_PREV(clist_data);
        clist_rmv_no_lock(CSESSION_MD_SESSION_LIST(csession_md), clist_data_rmv);

        csession_node_free(csession_node);
    }
    CLIST_UNLOCK(CSESSION_MD_SESSION_LIST(csession_md), LOC_CSESSION_0106);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csession_cbtimer_add(const UINT32 csession_md_id)
{
    TASK_BRD *task_brd;
    CBTIMER_NODE *cbtimer_node;
    TASK_FUNC *timeout_handler;
    FUNC_ADDR_NODE *csession_expire_func_addr_node;

#if ( SWITCH_ON == CSESSION_DEBUG_SWITCH )
    if ( CSESSION_MD_ID_CHECK_INVALID(csession_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__csession_cbtimer_add: csession module #0x%lx not started.\n",
                csession_md_id);
        csession_print_module_status(csession_md_id, LOGSTDOUT);
        dbg_exit(MD_CSESSION, csession_md_id);
    }
#endif/*CSESSION_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    cbtimer_node = cbtimer_node_new();
    if(NULL_PTR == cbtimer_node)
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_cbtimer_add: new cbtimer node failed\n");
        return (EC_FALSE);
    }

    CBTIMER_NODE_NAME(cbtimer_node) = cstring_new(NULL_PTR, LOC_CSESSION_0107);
    if(NULL_PTR == CBTIMER_NODE_NAME(cbtimer_node))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_cbtimer_add: new name cstring failed\n");
        cbtimer_node_free(cbtimer_node);
        return (EC_FALSE);
    }
    cstring_format(CBTIMER_NODE_NAME(cbtimer_node), "session_rank_%ld_modi_%ld", TASK_BRD_RANK(task_brd), csession_md_id);

    if(0 != dbg_fetch_func_addr_node_by_index(FI_csession_expire_handle, &csession_expire_func_addr_node))
    {
        dbg_log(SEC_0025_CSESSION, 0)(LOGSTDOUT, "error:csession_cbtimer_add: failed to fetch func addr node by func id %lx\n", FI_csession_expire_handle);
        return (EC_FALSE);
    }

    CBTIMER_NODE_TIMEOUT_NSEC(cbtimer_node)  = CSESSION_TIMEOUT_CHECKER_INTVAL;
    if(NULL_PTR != csession_expire_func_addr_node)
    {
        /*check session list and rmv expired sessions when timeout was triggered*/
        CBTIMER_NODE_TIMEOUT_FUNC_ADDR_NODE(cbtimer_node) = csession_expire_func_addr_node;
        timeout_handler = CBTIMER_NODE_TIMEOUT_HANDLER(cbtimer_node);
        timeout_handler->func_id                = csession_expire_func_addr_node->func_index;
        timeout_handler->func_para_num          = 1;
        timeout_handler->func_para[0].para_val  = csession_md_id;
        timeout_handler->func_ret_val           = EC_TRUE;
    }

    CBTIMER_NODE_EXPIRE_NSEC(cbtimer_node)   = CBTIMER_NEVER_EXPIRE;

    CTIMET_GET(CBTIMER_NODE_START_TIME(cbtimer_node));
    CTIMET_GET(CBTIMER_NODE_LAST_TIME(cbtimer_node));

    cbtimer_register(TASK_BRD_CBTIMER_LIST(task_brd), cbtimer_node);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

