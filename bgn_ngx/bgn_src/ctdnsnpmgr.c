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
#include "cmpic.inc"
#include "clist.h"
#include "cstring.h"
#include "cmisc.h"

#include "task.inc"
#include "task.h"

#include "ctdnsnp.h"
#include "ctdnsnprb.h"
#include "ctdnsnpmgr.h"
#include "chashalgo.h"
#include "cmd5.h"
#include "findex.inc"


CTDNSNP_MGR *ctdnsnp_mgr_new()
{
    CTDNSNP_MGR *ctdnsnp_mgr;

    alloc_static_mem(MM_CTDNSNP_MGR, &ctdnsnp_mgr, LOC_CTDNSNPMGR_0001);
    if(NULL_PTR != ctdnsnp_mgr)
    {
        ctdnsnp_mgr_init(ctdnsnp_mgr);
    }

    return (ctdnsnp_mgr);
}

EC_BOOL ctdnsnp_mgr_init(CTDNSNP_MGR *ctdnsnp_mgr)
{
    cstring_init(CTDNSNP_MGR_DB_ROOT_DIR(ctdnsnp_mgr), NULL_PTR); 

    CTDNSNP_MGR_NP_MODEL(ctdnsnp_mgr) = CTDNSNP_ERR_MODEL;
    CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID(ctdnsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CTDNSNP_MGR_NP_ITEM_MAX_NUM(ctdnsnp_mgr)      = 0;
    CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr)           = 0;

    cvector_init(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), 0, MM_CTDNSNP, CVECTOR_LOCK_ENABLE, LOC_CTDNSNPMGR_0002);
 
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_clean(CTDNSNP_MGR *ctdnsnp_mgr)
{
    cstring_clean(CTDNSNP_MGR_DB_ROOT_DIR(ctdnsnp_mgr)); 

    CTDNSNP_MGR_NP_MODEL(ctdnsnp_mgr) = CTDNSNP_ERR_MODEL;
    CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID(ctdnsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CTDNSNP_MGR_NP_ITEM_MAX_NUM(ctdnsnp_mgr)      = 0;
    CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr)           = 0;

    cvector_clean(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), (CVECTOR_DATA_CLEANER)ctdnsnp_free, LOC_CTDNSNPMGR_0003);    

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_free(CTDNSNP_MGR *ctdnsnp_mgr)
{
    if(NULL_PTR != ctdnsnp_mgr)
    {
        ctdnsnp_mgr_clean(ctdnsnp_mgr);
        free_static_mem(MM_CTDNSNP_MGR, ctdnsnp_mgr, LOC_CTDNSNPMGR_0004);
    }
    return (EC_TRUE);
}

CTDNSNP *ctdnsnp_mgr_open_np(CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id)
{
    CTDNSNP *ctdnsnp;

    ctdnsnp = (CTDNSNP *)cvector_get_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), (UINT32)ctdnsnp_id);
    if(NULL_PTR != ctdnsnp)
    {
        return (ctdnsnp);
    }

    ctdnsnp = ctdnsnp_open((char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr), ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_open_np: open np %u from %s failed\n", ctdnsnp_id, (char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr));
        return (NULL_PTR);
    }

    if(NULL_PTR != cvector_set_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), (UINT32)(ctdnsnp_id), (ctdnsnp)))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_open_np: set np %u to vector but found old existence\n", ctdnsnp_id);
        return (ctdnsnp);
    }
    dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_mgr_open_np: set np %u to vector done\n", ctdnsnp_id);
    return (ctdnsnp);
}

EC_BOOL ctdnsnp_mgr_close_np(CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id)
{
    CTDNSNP *ctdnsnp;

    ctdnsnp = (CTDNSNP *)cvector_get_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), (UINT32)ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 1)(LOGSTDOUT, "warn:ctdnsnp_mgr_close_np: np %u not open yet\n", ctdnsnp_id);
        return (EC_TRUE);
    }

    cvector_set_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), ctdnsnp_id, NULL_PTR);
    ctdnsnp_close(ctdnsnp);
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_open_np_all(CTDNSNP_MGR *ctdnsnp_mgr)
{
    uint32_t ctdnsnp_num;
    uint32_t ctdnsnp_id;
 
    ctdnsnp_num = CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr);

    for(ctdnsnp_id = 0; ctdnsnp_id < ctdnsnp_num; ctdnsnp_id ++)
    {
        CTDNSNP *ctdnsnp;

        ctdnsnp = ctdnsnp_mgr_open_np(ctdnsnp_mgr, ctdnsnp_id);
        if(NULL_PTR == ctdnsnp)
        {
            dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_open_np_all: open np %u from %s failed\n",
                            ctdnsnp_id, (char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_close_np_all(CTDNSNP_MGR *ctdnsnp_mgr)
{
    uint32_t ctdnsnp_num;
    uint32_t ctdnsnp_id;
 
    ctdnsnp_num = CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr);

    for(ctdnsnp_id = 0; ctdnsnp_id < ctdnsnp_num; ctdnsnp_id ++)
    {
        if(EC_FALSE == ctdnsnp_mgr_close_np(ctdnsnp_mgr, ctdnsnp_id))
        {
            dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_close_np_all: close np %u ffailed\n",
                            ctdnsnp_id);
        }
    }

    return (EC_TRUE);
}

static char *__ctdnsnp_mgr_gen_db_name(const char *root_dir)
{
    const char *fields[ 2 ];
 
    fields[ 0 ] = root_dir;
    fields[ 1 ] = CTDNSNP_DB_NAME;
 
    return c_str_join((char *)"/", fields, 2);
}

static EC_BOOL __ctdnsnp_mgr_load_db(CTDNSNP_MGR *ctdnsnp_mgr, int ctdnsnp_mgr_fd)
{
    UINT32 ctdnsnp_mgr_db_size;
    UINT8* ctdnsnp_mgr_db_buff;
    UINT32 ctdnsnp_mgr_db_offset;
    UINT32 ctdnsnp_id;
 
    /*init offset*/
    ctdnsnp_mgr_db_offset = 0;

    /*CTDNSNP_MGR_NP_MODEL*/
    ctdnsnp_mgr_db_size   = sizeof(uint8_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_MODEL(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_load(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_load_db: load np model failed\n");
        return (EC_FALSE);
    }

    /*CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    ctdnsnp_mgr_db_size   = sizeof(uint8_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_load(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_load_db: load 2nd chash algo id failed\n");
        return (EC_FALSE);
    }  

    /*CTDNSNP_MGR_NP_ITEM_MAX_NUM*/
    ctdnsnp_mgr_db_size   = sizeof(uint32_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_ITEM_MAX_NUM(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_load(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_load_db: load item max num failed\n");
        return (EC_FALSE);
    }  

    /*CTDNSNP_MGR_NP_MAX_NUM*/
    ctdnsnp_mgr_db_size   = sizeof(uint32_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_load(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_load_db: load disk max num failed\n");
        return (EC_FALSE);
    }

    for(ctdnsnp_id = cvector_size(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr)); ctdnsnp_id < CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr); ctdnsnp_id ++)
    {
        cvector_push_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), NULL_PTR);
    }

    return (EC_TRUE);
}

static EC_BOOL __ctdnsnp_mgr_flush_db(CTDNSNP_MGR *ctdnsnp_mgr, int ctdnsnp_mgr_fd)
{
    UINT32 ctdnsnp_mgr_db_size;
    UINT8* ctdnsnp_mgr_db_buff;
    UINT32 ctdnsnp_mgr_db_offset;

    /*init offset*/
    ctdnsnp_mgr_db_offset = 0;

    /*CTDNSNP_MGR_NP_MODEL*/
    ctdnsnp_mgr_db_size   = sizeof(uint8_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_MODEL(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_flush(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_flush_db: flush np model failed");
        return (EC_FALSE);
    }

    /*CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    ctdnsnp_mgr_db_size   = sizeof(uint8_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_flush(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_flush_db: flush 2nd chash algo id failed");
        return (EC_FALSE);
    }  
 
    /*CTDNSNP_MGR_NP_ITEM_MAX_NUM*/
    ctdnsnp_mgr_db_size   = sizeof(uint32_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_ITEM_MAX_NUM(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_flush(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_flush_db: flush item max num failed");
        return (EC_FALSE);
    }  

    /*CTDNSNP_MGR_NP_MAX_NUM*/
    ctdnsnp_mgr_db_size   = sizeof(uint32_t);
    ctdnsnp_mgr_db_buff   = (UINT8 *)&(CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr)); 
    if(EC_FALSE == c_file_flush(ctdnsnp_mgr_fd, &ctdnsnp_mgr_db_offset, ctdnsnp_mgr_db_size, ctdnsnp_mgr_db_buff))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_flush_db: flush disk max num failed");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_load_db(CTDNSNP_MGR *ctdnsnp_mgr)
{
    char  *ctdnsnp_mgr_db_name;
    int    ctdnsnp_mgr_fd;

    ctdnsnp_mgr_db_name = __ctdnsnp_mgr_gen_db_name((char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr));
    if(NULL_PTR == ctdnsnp_mgr_db_name)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_load_db: new str %s/%s failed\n",
                            (char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr), CTDNSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(ctdnsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_load_db: ctdnsnp mgr db %s not exist\n", ctdnsnp_mgr_db_name);
        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0005);
        return (EC_FALSE);
    }

    ctdnsnp_mgr_fd = c_file_open(ctdnsnp_mgr_db_name, O_RDONLY, 0666);
    if(ERR_FD == ctdnsnp_mgr_fd)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_load_db: open ctdnsnp mgr db %s failed\n", ctdnsnp_mgr_db_name);
        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0006);
        return (EC_FALSE);
    }

    if(EC_FALSE == __ctdnsnp_mgr_load_db(ctdnsnp_mgr, ctdnsnp_mgr_fd))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_load_db: load db from ctdnsnp mgr db %s\n", ctdnsnp_mgr_db_name);
        c_file_close(ctdnsnp_mgr_fd);
        ctdnsnp_mgr_fd = ERR_FD;

        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0007);
        return (EC_FALSE);
    }

    c_file_close(ctdnsnp_mgr_fd);
    ctdnsnp_mgr_fd = ERR_FD;

    safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0008);
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_create_db(CTDNSNP_MGR *ctdnsnp_mgr, const CSTRING *ctdnsnp_db_root_dir)
{
    char  *ctdnsnp_mgr_db_name;
    int    ctdnsnp_mgr_fd;

    ctdnsnp_mgr_db_name = __ctdnsnp_mgr_gen_db_name((char *)cstring_get_str(ctdnsnp_db_root_dir));
    if(NULL_PTR == ctdnsnp_mgr_db_name)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create_db: new str %s/%s failed\n",
                            (char *)cstring_get_str(ctdnsnp_db_root_dir), CTDNSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_TRUE == c_file_access(ctdnsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create_db: ctdnsnp mgr db %s already exist\n", ctdnsnp_mgr_db_name);
        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0009);
        return (EC_FALSE);
    }

    ctdnsnp_mgr_fd = c_file_open(ctdnsnp_mgr_db_name, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == ctdnsnp_mgr_fd)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create_db: open ctdnsnp mgr db %s failed\n", ctdnsnp_mgr_db_name);
        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0010);
        return (EC_FALSE);
    }

    if(EC_FALSE == __ctdnsnp_mgr_flush_db(ctdnsnp_mgr, ctdnsnp_mgr_fd))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create_db: flush db to ctdnsnp mgr db %s\n", ctdnsnp_mgr_db_name);
        c_file_close(ctdnsnp_mgr_fd);
        ctdnsnp_mgr_fd = ERR_FD;

        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0011);
        return (EC_FALSE);
    } 

    c_file_close(ctdnsnp_mgr_fd);
    ctdnsnp_mgr_fd = ERR_FD;

    dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_mgr_create_db: flush db to ctdnsnp mgr db %s done\n", ctdnsnp_mgr_db_name);
 
    safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0012);
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_flush_db(CTDNSNP_MGR *ctdnsnp_mgr)
{
    char  *ctdnsnp_mgr_db_name;
    int    ctdnsnp_mgr_fd;

    ctdnsnp_mgr_db_name = __ctdnsnp_mgr_gen_db_name((char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr));
    if(NULL_PTR == ctdnsnp_mgr_db_name)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_flush_db: new str %s/%s failed\n",
                            (char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr), CTDNSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(ctdnsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_flush_db: ctdnsnp mgr db %s not exist\n", ctdnsnp_mgr_db_name);
        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0013);
        return (EC_FALSE);
    }

    ctdnsnp_mgr_fd = c_file_open(ctdnsnp_mgr_db_name, O_RDWR, 0666);
    if(ERR_FD == ctdnsnp_mgr_fd)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_flush_db: open ctdnsnp mgr db %s failed\n", ctdnsnp_mgr_db_name);
        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0014);
        return (EC_FALSE);
    }

    if(EC_FALSE == __ctdnsnp_mgr_flush_db(ctdnsnp_mgr, ctdnsnp_mgr_fd))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_flush_db: flush db to ctdnsnp mgr db %s\n", ctdnsnp_mgr_db_name);
        c_file_close(ctdnsnp_mgr_fd);
        ctdnsnp_mgr_fd = ERR_FD;

        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0015);
        return (EC_FALSE);
    }

    c_file_close(ctdnsnp_mgr_fd);
    ctdnsnp_mgr_fd = ERR_FD;

    dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_mgr_flush_db: flush db to ctdnsnp mgr db %s done\n", ctdnsnp_mgr_db_name);

    safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0016);
    return (EC_TRUE);
}

void ctdnsnp_mgr_print_db(LOG *log, const CTDNSNP_MGR *ctdnsnp_mgr)
{
    uint32_t ctdnsnp_num;
    uint32_t ctdnsnp_id;

    sys_log(log, "ctdnsnp mgr db root dir  : %s\n", (char *)CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr));
    sys_log(log, "ctdnsnp model            : %u\n", CTDNSNP_MGR_NP_MODEL(ctdnsnp_mgr));
    sys_log(log, "ctdnsnp hash algo id     : %u\n", CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID(ctdnsnp_mgr));
    sys_log(log, "ctdnsnp item max num     : %u\n", CTDNSNP_MGR_NP_ITEM_MAX_NUM(ctdnsnp_mgr));
    sys_log(log, "ctdnsnp max num          : %u\n", CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr));

    ctdnsnp_num = (uint32_t)cvector_size(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr));
    for(ctdnsnp_id = 0; ctdnsnp_id < ctdnsnp_num; ctdnsnp_id ++)
    {
        CTDNSNP *ctdnsnp;

        ctdnsnp = CTDNSNP_MGR_NP(ctdnsnp_mgr, ctdnsnp_id);
        if(NULL_PTR == ctdnsnp)
        {
            sys_log(log, "np %u #: (null)\n", ctdnsnp_id);
        }
        else
        {
            ctdnsnp_print(log, ctdnsnp);
        }
    }
    return;
}

void ctdnsnp_mgr_print(LOG *log, const CTDNSNP_MGR *ctdnsnp_mgr)
{
    sys_log(log, "ctdnsnp mgr:\n");
    ctdnsnp_mgr_print_db(log, ctdnsnp_mgr);
    return;
}

EC_BOOL ctdnsnp_mgr_load(CTDNSNP_MGR *ctdnsnp_mgr, const CSTRING *ctdnsnp_db_root_dir)
{
    cstring_clean(CTDNSNP_MGR_DB_ROOT_DIR(ctdnsnp_mgr));
    cstring_clone(ctdnsnp_db_root_dir, CTDNSNP_MGR_DB_ROOT_DIR(ctdnsnp_mgr));

    if(EC_FALSE == ctdnsnp_mgr_load_db(ctdnsnp_mgr))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_load: load cfg db failed from dir %s\n", (char *)cstring_get_str(ctdnsnp_db_root_dir));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_sync_np(CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id)
{
    CTDNSNP *ctdnsnp;
 
    ctdnsnp = (CTDNSNP *)cvector_get_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), ctdnsnp_id);
    if(NULL_PTR != ctdnsnp)
    {
        return ctdnsnp_sync(ctdnsnp);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_flush(CTDNSNP_MGR *ctdnsnp_mgr)
{
    uint32_t ctdnsnp_num;
    uint32_t ctdnsnp_id;
    EC_BOOL ret;

    ret = EC_TRUE;

    if(EC_FALSE == ctdnsnp_mgr_flush_db(ctdnsnp_mgr))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_flush: flush cfg db failed\n");
        ret = EC_FALSE;
    }

    ctdnsnp_num = CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr);
    for(ctdnsnp_id = 0; ctdnsnp_id < ctdnsnp_num; ctdnsnp_id ++)
    {
        ctdnsnp_mgr_sync_np(ctdnsnp_mgr, ctdnsnp_id);
    }
    return (ret);
}

EC_BOOL ctdnsnp_mgr_show_np(LOG *log, CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id)
{
    CTDNSNP *ctdnsnp;

    ctdnsnp = (CTDNSNP *)cvector_get_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {     
        /*try to open the np and print it*/
        ctdnsnp = ctdnsnp_mgr_open_np(ctdnsnp_mgr, ctdnsnp_id);
        if(NULL_PTR == ctdnsnp)
        {
            dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_show_np: open np %u failed\n", ctdnsnp_id);
            return (EC_FALSE);
        }

        ctdnsnp_print(log, ctdnsnp);

        ctdnsnp_mgr_close_np(ctdnsnp_mgr, ctdnsnp_id);
    }
    else
    {    
        ctdnsnp_print(log, ctdnsnp);
    }

    return (EC_TRUE);
}

static uint32_t __ctdnsnp_mgr_get_np_id_of_tcid(const CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid)
{
    uint32_t ctdnsnp_num;
    uint32_t ctdnsnp_id;

    ctdnsnp_num = CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr);
    ctdnsnp_id  = (uint32_t)(tcid % ctdnsnp_num);
    dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __ctdnsnp_mgr_get_np_id_of_tcid: tcid %ld, ctdnsnp num %u => ctdnsnp id %u\n", 
                        tcid, ctdnsnp_num, ctdnsnp_id);
    return (ctdnsnp_id);
}

static CTDNSNP *__ctdnsnp_mgr_get_np(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, uint32_t *np_id)
{
    CTDNSNP  * ctdnsnp;
    uint32_t  ctdnsnp_id;

    ctdnsnp_id = __ctdnsnp_mgr_get_np_id_of_tcid(ctdnsnp_mgr, tcid);
    if(CTDNSNP_ERR_ID == ctdnsnp_id)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_get_np: no np for tcid %s\n", c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    ctdnsnp = ctdnsnp_mgr_open_np(ctdnsnp_mgr, ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_get_np: tcid %s in np %u but cannot open\n", c_word_to_ipv4(tcid), ctdnsnp_id);
        return (NULL_PTR);
    }

    if(NULL_PTR != np_id)
    {
        (*np_id) = ctdnsnp_id;
    }
   
    return (ctdnsnp);        
}

static EC_BOOL __ctdnsnp_mgr_search(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, uint32_t *searched_ctdnsnp_id)
{
    uint32_t ctdnsnp_num;
    uint32_t ctdnsnp_id;
 
    ctdnsnp_num = CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr);
    for(ctdnsnp_id = 0; ctdnsnp_id < ctdnsnp_num; ctdnsnp_id ++)
    {
        CTDNSNP *ctdnsnp;
        uint32_t  node_pos;
     
        ctdnsnp = ctdnsnp_mgr_open_np(ctdnsnp_mgr, ctdnsnp_id);
        if(NULL_PTR == ctdnsnp)
        {
            dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:__ctdnsnp_mgr_search: open np %u failed\n", ctdnsnp_id);
            continue;
        }

        node_pos = ctdnsnp_search(ctdnsnp, tcid);
        if(CTDNSNPRB_ERR_POS == node_pos)
        {
            continue;
        }

        /*found*/
        dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __ctdnsnp_mgr_search: found tcid %s in np %u \n", c_word_to_ipv4(tcid), ctdnsnp_id);

        if(NULL_PTR != searched_ctdnsnp_id)
        {
            (*searched_ctdnsnp_id) = ctdnsnp_id;
        }
     
        return (EC_TRUE);/*succ*/
    }
 
    return (EC_FALSE);
}

EC_BOOL ctdnsnp_mgr_search(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, uint32_t *searched_ctdnsnp_id)
{
    return __ctdnsnp_mgr_search(ctdnsnp_mgr, tcid, searched_ctdnsnp_id);
}

CTDNSNP_ITEM *ctdnsnp_mgr_search_item(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid)
{
    CTDNSNP   *ctdnsnp;
    uint32_t  ctdnsnp_id; 
    uint32_t  node_pos;

    CTDNSNP_ITEM *ctdnsnp_item;
 
    ctdnsnp = __ctdnsnp_mgr_get_np(ctdnsnp_mgr, tcid, &ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_search_item: tcid %s in np %u but cannot open\n", c_word_to_ipv4(tcid), ctdnsnp_id);
        return (NULL_PTR);
    }

    node_pos = ctdnsnp_search(ctdnsnp, tcid);
    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_mgr_search_item: tcid %s in np %u but not found indeed\n", c_word_to_ipv4(tcid), ctdnsnp_id);
        return (NULL_PTR);
    }

    ctdnsnp_item = ctdnsnp_fetch(ctdnsnp, node_pos);
    return (ctdnsnp_item);
}

CTDNSNP_MGR *ctdnsnp_mgr_create(const uint8_t ctdnsnp_model,
                                const uint32_t ctdnsnp_max_num,
                                const uint8_t  ctdnsnp_2nd_chash_algo_id,
                                const CSTRING *ctdnsnp_db_root_dir)
{
    CTDNSNP     *src_ctdnsnp;
    CTDNSNP_MGR *ctdnsnp_mgr;
    uint32_t ctdnsnp_item_max_num;
    uint32_t ctdnsnp_id;
 
    if(EC_FALSE == ctdnsnp_model_item_max_num(ctdnsnp_model , &ctdnsnp_item_max_num))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create: invalid ctdnsnp model %u\n", ctdnsnp_model);
        return (NULL_PTR);
    }

    ctdnsnp_mgr = ctdnsnp_mgr_new();

    CTDNSNP_MGR_NP_MODEL(ctdnsnp_mgr)                = ctdnsnp_model;
    CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID(ctdnsnp_mgr)    = ctdnsnp_2nd_chash_algo_id;
    CTDNSNP_MGR_NP_ITEM_MAX_NUM(ctdnsnp_mgr)         = ctdnsnp_item_max_num;
    CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr)              = ctdnsnp_max_num;

    cstring_clone(ctdnsnp_db_root_dir, CTDNSNP_MGR_DB_ROOT_DIR(ctdnsnp_mgr));
    src_ctdnsnp = NULL_PTR;

    for(ctdnsnp_id = 0; ctdnsnp_id < 1/*ctdnsnp_max_num*/; ctdnsnp_id ++)
    {
        const char *np_root_dir;
        CTDNSNP *ctdnsnp;

        np_root_dir = (const char *)cstring_get_str(ctdnsnp_db_root_dir);/*Oops! int the same dire*/
        ctdnsnp = ctdnsnp_create(np_root_dir, ctdnsnp_id, ctdnsnp_model, ctdnsnp_2nd_chash_algo_id);
        if(NULL_PTR == ctdnsnp)
        {
            dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create: create np %u failed\n", ctdnsnp_id);
            return (NULL_PTR);
        }

        src_ctdnsnp = ctdnsnp;
        /*ctdnsnp_close(ctdnsnp);*/

        cvector_push_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), (void *)NULL_PTR);
    }

    for(ctdnsnp_id = /*0*/1; ctdnsnp_id < ctdnsnp_max_num; ctdnsnp_id ++)
    {
        const char *np_root_dir;
        CTDNSNP *des_ctdnsnp;

        np_root_dir = (const char *)cstring_get_str(ctdnsnp_db_root_dir);/*Oops! int the same dire*/
        des_ctdnsnp = ctdnsnp_clone(src_ctdnsnp, np_root_dir, ctdnsnp_id);
        if(NULL_PTR == des_ctdnsnp)
        {
            dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create: clone np %d -> %u failed\n", (uint32_t)0, ctdnsnp_id);
            ctdnsnp_close(src_ctdnsnp);
            return (NULL_PTR);
        }
        ctdnsnp_close(des_ctdnsnp);

        cvector_push_no_lock(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), (void *)NULL_PTR);
    }

    if(NULL_PTR != src_ctdnsnp)
    {
        ctdnsnp_close(src_ctdnsnp);
        src_ctdnsnp = NULL_PTR;
    }

    if(EC_FALSE == ctdnsnp_mgr_create_db(ctdnsnp_mgr, ctdnsnp_db_root_dir))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_create: create cfg db failed in root dir %s\n",
                            (char *)cstring_get_str(ctdnsnp_db_root_dir));
        ctdnsnp_mgr_free(ctdnsnp_mgr);
        return (NULL_PTR);
    }

    //ctdnsnp_mgr_free(ctdnsnp_mgr);
    return (ctdnsnp_mgr);
}

EC_BOOL ctdnsnp_mgr_exist(const CSTRING *ctdnsnp_db_root_dir)
{
    char  *ctdnsnp_mgr_db_name;

    ctdnsnp_mgr_db_name = __ctdnsnp_mgr_gen_db_name((char *)cstring_get_str(ctdnsnp_db_root_dir));
    if(NULL_PTR == ctdnsnp_mgr_db_name)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_exist: new str %s/%s failed\n",
                            (char *)cstring_get_str(ctdnsnp_db_root_dir), CTDNSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(ctdnsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 7)(LOGSTDOUT, "error:ctdnsnp_mgr_exist: ctdnsnp mgr db %s not exist\n", ctdnsnp_mgr_db_name);
        safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0017);
        return (EC_FALSE);
    }
    safe_free(ctdnsnp_mgr_db_name, LOC_CTDNSNPMGR_0018);
    return (EC_TRUE);
}

CTDNSNP_MGR * ctdnsnp_mgr_open(const CSTRING *ctdnsnp_db_root_dir)
{
    CTDNSNP_MGR *ctdnsnp_mgr;

    ctdnsnp_mgr = ctdnsnp_mgr_new();
    if(NULL_PTR == ctdnsnp_mgr)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_open: new ctdnsnp mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == ctdnsnp_mgr_load(ctdnsnp_mgr, ctdnsnp_db_root_dir))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_open: load failed\n");
        ctdnsnp_mgr_free(ctdnsnp_mgr);
        return (NULL_PTR);
    }
    dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_mgr_open: ctdnsnp mgr loaded from %s\n", (char *)cstring_get_str(ctdnsnp_db_root_dir));
    return (ctdnsnp_mgr);
}

EC_BOOL ctdnsnp_mgr_close(CTDNSNP_MGR *ctdnsnp_mgr)
{ 
    if(NULL_PTR != ctdnsnp_mgr)
    {
        ctdnsnp_mgr_flush(ctdnsnp_mgr);
        ctdnsnp_mgr_free(ctdnsnp_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_find(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid)
{
    return ctdnsnp_mgr_search(ctdnsnp_mgr, tcid, NULL_PTR);
}

EC_BOOL ctdnsnp_mgr_set(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, const UINT32 ipaddr, const uint32_t klen, const uint8_t *key)
{
    CTDNSNP *ctdnsnp;
    CTDNSNP_ITEM *ctdnsnp_item;
    uint32_t ctdnsnp_id;

    ctdnsnp = __ctdnsnp_mgr_get_np(ctdnsnp_mgr, tcid, &ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_set: no np for tcid %s\n", c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ctdnsnp_item = ctdnsnp_set(ctdnsnp, tcid, ipaddr, klen, key);
    if(NULL_PTR == ctdnsnp_item)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_set: set (tcid %s, ip %s, key %.*s) to np %u failed\n",
                            c_word_to_ipv4(tcid),c_word_to_ipv4(ipaddr), klen, key,
                            ctdnsnp_id);
        return (EC_FALSE);
    }

   
    if(do_log(SEC_0030_CTDNSNPMGR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] ctdnsnp_mgr_set: set item done:\n");
        ctdnsnp_item_print(LOGSTDOUT, ctdnsnp_item);
    }
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_get(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, UINT32 *ipaddr, uint32_t *klen, uint8_t **key)
{
    CTDNSNP *ctdnsnp;
    uint32_t ctdnsnp_id;
    uint32_t node_pos;

    ctdnsnp = __ctdnsnp_mgr_get_np(ctdnsnp_mgr, tcid, &ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_get: no np for tcid %s\n", c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }
 
    node_pos = ctdnsnp_search_no_lock(ctdnsnp, tcid);
    if(CTDNSNPRB_ERR_POS != node_pos)
    {
        CTDNSNP_ITEM *ctdnsnp_item;

        ctdnsnp_item = ctdnsnp_fetch(ctdnsnp, node_pos);
        if(NULL_PTR != ipaddr)
        {
            (*ipaddr) = CTDNSNP_ITEM_IPADDR(ctdnsnp_item);
        }

        if(NULL_PTR != klen)
        {
            (*klen) = CTDNSNP_ITEM_KLEN(ctdnsnp_item);
        }

        if(NULL_PTR != key)
        {
            (*key) = CTDNSNP_ITEM_KEY(ctdnsnp_item);
        }
        
        return (EC_TRUE);
    }
    return (EC_FALSE); 
}

EC_BOOL ctdnsnp_mgr_delete(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid)
{
    CTDNSNP         *ctdnsnp;
    uint32_t         ctdnsnp_id;

    ctdnsnp = __ctdnsnp_mgr_get_np(ctdnsnp_mgr, tcid, &ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_delete: no np for tcid %s\n", c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnsnp_delete(ctdnsnp, tcid))
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_delete: delete tcid %s to np %u failed\n",
                            c_word_to_ipv4(tcid), ctdnsnp_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0030_CTDNSNPMGR, 9)(LOGSTDOUT, "[DEBUG] ctdnsnp_mgr_delete: delete tcid %s to np %u done\n",
                        c_word_to_ipv4(tcid), ctdnsnp_id);    

    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_tcid_num_of_np(CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id, UINT32 *tcid_num)
{
    CTDNSNP  *ctdnsnp;
    UINT32    cur_tcid_num;
    uint32_t  node_pos;
    
 
    ctdnsnp = ctdnsnp_mgr_open_np(ctdnsnp_mgr, ctdnsnp_id);
    if(NULL_PTR == ctdnsnp)
    {
        dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_tcid_num_of_np: open np %u failed\n", ctdnsnp_id);
        return (EC_FALSE);
    }

    cur_tcid_num = 0;
    node_pos = ctdnsnp_tcid_num(ctdnsnp, &cur_tcid_num);
    if(CTDNSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    (*tcid_num) += cur_tcid_num;
    return (EC_TRUE);
}

EC_BOOL ctdnsnp_mgr_tcid_num(CTDNSNP_MGR *ctdnsnp_mgr, UINT32 *tcid_num)
{
    uint32_t ctdnsnp_num;
    uint32_t ctdnsnp_id;

    (*tcid_num) = 0;
 
    ctdnsnp_num = CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr);
    for(ctdnsnp_id = 0; ctdnsnp_id < ctdnsnp_num; ctdnsnp_id ++)
    {
        UINT32  cur_tcid_num;

        cur_tcid_num = 0;
        if(EC_FALSE == ctdnsnp_mgr_tcid_num_of_np(ctdnsnp_mgr, ctdnsnp_id, &cur_tcid_num))
        {
            dbg_log(SEC_0030_CTDNSNPMGR, 0)(LOGSTDOUT, "error:ctdnsnp_mgr_file_num: count tcid num of np %u failed\n",
                               ctdnsnp_id);
            return (EC_FALSE);
        }     

        (*tcid_num) += cur_tcid_num;
    } 

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

