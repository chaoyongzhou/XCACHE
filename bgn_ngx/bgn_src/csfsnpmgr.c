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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmpic.inc"
#include "cmutex.h"
#include "clist.h"
#include "cstring.h"
#include "cmisc.h"

#include "task.inc"
#include "task.h"

#include "csfsnp.h"
#include "csfsnprb.h"
#include "csfsnpmgr.h"
#include "chashalgo.h"

#include "findex.inc"

STATIC_CAST static uint32_t __csfsnp_mgr_path_hash(const uint32_t path_len, const uint8_t *path)
{
    uint8_t   digest[ CMD5_DIGEST_LEN ];
    uint32_t  hash_val;

    cmd5_sum(path_len, path, digest);

    hash_val = (
               ((uint32_t)(digest[ 0 ] << 24))
             | ((uint32_t)(digest[ 1 ] << 16))
             | ((uint32_t)(digest[ 2 ] <<  8))
             | ((uint32_t)(digest[ 3 ] <<  0))
             );
    return (hash_val);          
}

CSFSNP_MGR *csfsnp_mgr_new()
{
    CSFSNP_MGR *csfsnp_mgr;

    alloc_static_mem(MM_CSFSNP_MGR, &csfsnp_mgr, LOC_CSFSNPMGR_0001);
    if(NULL_PTR != csfsnp_mgr)
    {
        csfsnp_mgr_init(csfsnp_mgr);
    }

    return (csfsnp_mgr);
}

EC_BOOL csfsnp_mgr_init(CSFSNP_MGR *csfsnp_mgr)
{
    CSFSNP_MGR_CRWLOCK_INIT(csfsnp_mgr, LOC_CSFSNPMGR_0002);
    CSFSNP_MGR_CMUTEX_INIT(csfsnp_mgr, LOC_CSFSNPMGR_0003);
 
    cstring_init(CSFSNP_MGR_DB_ROOT_DIR(csfsnp_mgr), NULL_PTR); 

    CSFSNP_MGR_NP_MODEL(csfsnp_mgr) = CSFSNP_ERR_MODEL;
    CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID(csfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID(csfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CSFSNP_MGR_NP_ITEM_MAX_NUM(csfsnp_mgr)      = 0;
    CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr)           = 0;

    cvector_init(CSFSNP_MGR_NP_VEC(csfsnp_mgr), 0, MM_CSFSNP, CVECTOR_LOCK_ENABLE, LOC_CSFSNPMGR_0004);
 
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_clean(CSFSNP_MGR *csfsnp_mgr)
{
    CSFSNP_MGR_CRWLOCK_CLEAN(csfsnp_mgr, LOC_CSFSNPMGR_0005);
    CSFSNP_MGR_CMUTEX_CLEAN(csfsnp_mgr, LOC_CSFSNPMGR_0006);
 
    cstring_clean(CSFSNP_MGR_DB_ROOT_DIR(csfsnp_mgr)); 

    CSFSNP_MGR_NP_MODEL(csfsnp_mgr) = CSFSNP_ERR_MODEL;
    CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID(csfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID(csfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CSFSNP_MGR_NP_ITEM_MAX_NUM(csfsnp_mgr)      = 0;
    CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr)           = 0;

    cvector_clean(CSFSNP_MGR_NP_VEC(csfsnp_mgr), (CVECTOR_DATA_CLEANER)csfsnp_free, LOC_CSFSNPMGR_0007);    

    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_free(CSFSNP_MGR *csfsnp_mgr)
{
    if(NULL_PTR != csfsnp_mgr)
    {
        csfsnp_mgr_clean(csfsnp_mgr);
        free_static_mem(MM_CSFSNP_MGR, csfsnp_mgr, LOC_CSFSNPMGR_0008);
    }
    return (EC_TRUE);
}

CSFSNP *csfsnp_mgr_open_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id)
{
    CSFSNP *csfsnp;

    csfsnp = (CSFSNP *)cvector_get_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), csfsnp_id);
    if(NULL_PTR != csfsnp)
    {
        return (csfsnp);
    }

    csfsnp = csfsnp_open((char *)CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr), csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_open_np: open np %u from %s failed\n",
                           csfsnp_id, (char *)CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr));
        return (NULL_PTR);
    }

    cvector_set_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), csfsnp_id, csfsnp);
    return (csfsnp);
}

EC_BOOL csfsnp_mgr_close_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id)
{
    CSFSNP *csfsnp;

    csfsnp = (CSFSNP *)cvector_get_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 1)(LOGSTDOUT, "warn:csfsnp_mgr_close_np: np %u not open yet\n", csfsnp_id);
        return (EC_TRUE);
    }

    cvector_set_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), csfsnp_id, NULL_PTR);
    csfsnp_close(csfsnp);
    return (EC_TRUE);
}

STATIC_CAST static char *__csfsnp_mgr_gen_db_name(const char *root_dir)
{
    const char *fields[ 2 ];
 
    fields[ 0 ] = root_dir;
    fields[ 1 ] = CSFSNP_DB_NAME;
 
    return c_str_join((char *)"/", fields, 2);
}

STATIC_CAST static EC_BOOL __csfsnp_mgr_load_db(CSFSNP_MGR *csfsnp_mgr, int csfsnp_mgr_fd)
{
    UINT32 csfsnp_mgr_db_size;
    UINT8* csfsnp_mgr_db_buff;
    UINT32 csfsnp_mgr_db_offset;

    uint32_t csfsnp_id;
 
    /*init offset*/
    csfsnp_mgr_db_offset = 0;

    /*CSFSNP_MGR_NP_MODEL*/
    csfsnp_mgr_db_size   = sizeof(uint8_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_MODEL(csfsnp_mgr)); 
    if(EC_FALSE == c_file_load(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_load_db: load np model failed\n");
        return (EC_FALSE);
    }

    /*CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID*/
    csfsnp_mgr_db_size   = sizeof(uint8_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID(csfsnp_mgr)); 
    if(EC_FALSE == c_file_load(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_load_db: load 1st chash algo id failed\n");
        return (EC_FALSE);
    } 

    /*CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    csfsnp_mgr_db_size   = sizeof(uint8_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID(csfsnp_mgr)); 
    if(EC_FALSE == c_file_load(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_load_db: load 2nd chash algo id failed\n");
        return (EC_FALSE);
    }  

    /*CSFSNP_MGR_NP_ITEM_MAX_NUM*/
    csfsnp_mgr_db_size   = sizeof(uint32_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_ITEM_MAX_NUM(csfsnp_mgr)); 
    if(EC_FALSE == c_file_load(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_load_db: load item max num failed\n");
        return (EC_FALSE);
    }  

    /*CSFSNP_MGR_NP_MAX_NUM*/
    csfsnp_mgr_db_size   = sizeof(uint32_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr)); 
    if(EC_FALSE == c_file_load(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_load_db: load disk max num failed\n");
        return (EC_FALSE);
    }

    for(csfsnp_id = cvector_size(CSFSNP_MGR_NP_VEC(csfsnp_mgr)); csfsnp_id < CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr); csfsnp_id ++)
    {
        cvector_push_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), NULL_PTR);
    }


    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __csfsnp_mgr_flush_db(CSFSNP_MGR *csfsnp_mgr, int csfsnp_mgr_fd)
{
    UINT32 csfsnp_mgr_db_size;
    UINT8* csfsnp_mgr_db_buff;
    UINT32 csfsnp_mgr_db_offset;

    /*init offset*/
    csfsnp_mgr_db_offset = 0;

    /*CSFSNP_MGR_NP_MODEL*/
    csfsnp_mgr_db_size   = sizeof(uint8_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_MODEL(csfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_flush_db: flush np model failed");
        return (EC_FALSE);
    }

    /*CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID*/
    csfsnp_mgr_db_size   = sizeof(uint8_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID(csfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_flush_db: flush 1st chash algo id failed");
        return (EC_FALSE);
    } 

    /*CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    csfsnp_mgr_db_size   = sizeof(uint8_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID(csfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_flush_db: flush 2nd chash algo id failed");
        return (EC_FALSE);
    }  

    /*CSFSNP_MGR_NP_ITEM_MAX_NUM*/
    csfsnp_mgr_db_size   = sizeof(uint32_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_ITEM_MAX_NUM(csfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_flush_db: flush item max num failed");
        return (EC_FALSE);
    }  

    /*CSFSNP_MGR_NP_MAX_NUM*/
    csfsnp_mgr_db_size   = sizeof(uint32_t);
    csfsnp_mgr_db_buff   = (UINT8 *)&(CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(csfsnp_mgr_fd, &csfsnp_mgr_db_offset, csfsnp_mgr_db_size, csfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_flush_db: flush disk max num failed");
        return (EC_FALSE);
    }

    dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_mgr_flush_db: np max num = %u\n", CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr));

    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_load_db(CSFSNP_MGR *csfsnp_mgr)
{
    char  *csfsnp_mgr_db_name;
    int    csfsnp_mgr_fd;

    csfsnp_mgr_db_name = __csfsnp_mgr_gen_db_name((char *)CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr));
    if(NULL_PTR == csfsnp_mgr_db_name)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_load_db: new str %s/%s failed\n",
                            (char *)CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr), CSFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(csfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_load_db: csfsnp mgr db %s not exist\n", csfsnp_mgr_db_name);
        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0009);
        return (EC_FALSE);
    }

    csfsnp_mgr_fd = c_file_open(csfsnp_mgr_db_name, O_RDONLY, 0666);
    if(ERR_FD == csfsnp_mgr_fd)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_load_db: open csfsnp mgr db %s failed\n", csfsnp_mgr_db_name);
        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0010);
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfsnp_mgr_load_db(csfsnp_mgr, csfsnp_mgr_fd))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_load_db: load db from csfsnp mgr db %s\n", csfsnp_mgr_db_name);
        c_file_close(csfsnp_mgr_fd);
        csfsnp_mgr_fd = ERR_FD;

        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0011);
        return (EC_FALSE);
    }

    c_file_close(csfsnp_mgr_fd);
    csfsnp_mgr_fd = ERR_FD;

    dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mgr_load_db: load db from csfsnp mgr db %s done\n", csfsnp_mgr_db_name);

    safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0012);
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_create_db(CSFSNP_MGR *csfsnp_mgr, const CSTRING *csfsnp_db_root_dir)
{
    char  *csfsnp_mgr_db_name;
    int    csfsnp_mgr_fd;

    csfsnp_mgr_db_name = __csfsnp_mgr_gen_db_name((char *)cstring_get_str(csfsnp_db_root_dir));
    if(NULL_PTR == csfsnp_mgr_db_name)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_create_db: new str %s/%s failed\n",
                            (char *)cstring_get_str(csfsnp_db_root_dir), CSFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_TRUE == c_file_access(csfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_create_db: csfsnp mgr db %s already exist\n", csfsnp_mgr_db_name);
        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0013);
        return (EC_FALSE);
    }

    csfsnp_mgr_fd = c_file_open(csfsnp_mgr_db_name, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == csfsnp_mgr_fd)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_create_db: open csfsnp mgr db %s failed\n", csfsnp_mgr_db_name);
        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0014);
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfsnp_mgr_flush_db(csfsnp_mgr, csfsnp_mgr_fd))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_create_db: flush db to csfsnp mgr db %s\n", csfsnp_mgr_db_name);
        c_file_close(csfsnp_mgr_fd);
        csfsnp_mgr_fd = ERR_FD;

        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0015);
        return (EC_FALSE);
    } 

    c_file_close(csfsnp_mgr_fd);
    csfsnp_mgr_fd = ERR_FD;

    safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0016);
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_flush_db(CSFSNP_MGR *csfsnp_mgr)
{
    char  *csfsnp_mgr_db_name;
    int    csfsnp_mgr_fd;

    csfsnp_mgr_db_name = __csfsnp_mgr_gen_db_name((char *)CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr));
    if(NULL_PTR == csfsnp_mgr_db_name)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_flush_db: new str %s/%s failed\n",
                            (char *)CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr), CSFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(csfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_flush_db: csfsnp mgr db %s not exist\n", csfsnp_mgr_db_name);
        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0017);
        return (EC_FALSE);
    }

    csfsnp_mgr_fd = c_file_open(csfsnp_mgr_db_name, O_RDWR, 0666);
    if(ERR_FD == csfsnp_mgr_fd)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_flush_db: open csfsnp mgr db %s failed\n", csfsnp_mgr_db_name);
        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0018);
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfsnp_mgr_flush_db(csfsnp_mgr, csfsnp_mgr_fd))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_flush_db: flush db to csfsnp mgr db %s\n", csfsnp_mgr_db_name);
        c_file_close(csfsnp_mgr_fd);
        csfsnp_mgr_fd = ERR_FD;

        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0019);
        return (EC_FALSE);
    }

    c_file_close(csfsnp_mgr_fd);
    csfsnp_mgr_fd = ERR_FD;

    safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0020);
    return (EC_TRUE);
}

void csfsnp_mgr_print_db(LOG *log, const CSFSNP_MGR *csfsnp_mgr)
{
    uint32_t csfsnp_num;
    uint32_t csfsnp_id;

    sys_log(log, "csfsnp mgr db root dir  : %s\n", (char *)CSFSNP_MGR_DB_ROOT_DIR_STR(csfsnp_mgr));
    sys_log(log, "csfsnp model            : %u\n", CSFSNP_MGR_NP_MODEL(csfsnp_mgr));
    sys_log(log, "csfsnp 1st hash algo id : %u\n", CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID(csfsnp_mgr));
    sys_log(log, "csfsnp 2nd hash algo id : %u\n", CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID(csfsnp_mgr));
    sys_log(log, "csfsnp item max num     : %u\n", CSFSNP_MGR_NP_ITEM_MAX_NUM(csfsnp_mgr));
    sys_log(log, "csfsnp max num          : %u\n", CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr));

    csfsnp_num = (uint32_t)cvector_size(CSFSNP_MGR_NP_VEC(csfsnp_mgr));
    for(csfsnp_id = 0; csfsnp_id < csfsnp_num; csfsnp_id ++)
    {
        CSFSNP *csfsnp;

        csfsnp = CSFSNP_MGR_NP(csfsnp_mgr, csfsnp_id);
        if(NULL_PTR == csfsnp)
        {
            sys_log(log, "np %u #: (null)\n", csfsnp_id);
        }
        else
        {
            csfsnp_print(log, csfsnp);
        }
    }
    return;
}

void csfsnp_mgr_print(LOG *log, const CSFSNP_MGR *csfsnp_mgr)
{
    sys_log(log, "csfsnp mgr:\n");
    csfsnp_mgr_print_db(log, csfsnp_mgr);
    return;
}

EC_BOOL csfsnp_mgr_load(CSFSNP_MGR *csfsnp_mgr, const CSTRING *csfsnp_db_root_dir)
{
    cstring_clean(CSFSNP_MGR_DB_ROOT_DIR(csfsnp_mgr));
    cstring_clone(csfsnp_db_root_dir, CSFSNP_MGR_DB_ROOT_DIR(csfsnp_mgr));

    if(EC_FALSE == csfsnp_mgr_load_db(csfsnp_mgr))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_load: load cfg db failed from dir %s\n", (char *)cstring_get_str(csfsnp_db_root_dir));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_sync_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id)
{
    CSFSNP *csfsnp;
 
    csfsnp = (CSFSNP *)cvector_get_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), csfsnp_id);
    if(NULL_PTR != csfsnp)
    {
        return csfsnp_sync(csfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_flush(CSFSNP_MGR *csfsnp_mgr)
{
    uint32_t csfsnp_num;
    uint32_t csfsnp_id;
    EC_BOOL ret;

    ret = EC_TRUE;

    if(EC_FALSE == csfsnp_mgr_flush_db(csfsnp_mgr))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_flush: flush cfg db failed\n");
        ret = EC_FALSE;
    }

    csfsnp_num = CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr);
    for(csfsnp_id = 0; csfsnp_id < csfsnp_num; csfsnp_id ++)
    {
        csfsnp_mgr_sync_np(csfsnp_mgr, csfsnp_id);
    }
    return (ret);
}

EC_BOOL csfsnp_mgr_show_np(LOG *log, CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id)
{
    CSFSNP *csfsnp;

    csfsnp = (CSFSNP *)cvector_get_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), csfsnp_id);
    if(NULL_PTR == csfsnp)
    {     
        /*try to open the np and print it*/
        csfsnp = csfsnp_mgr_open_np(csfsnp_mgr, csfsnp_id);
        if(NULL_PTR == csfsnp)
        {
            dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_show_np: open np %u failed\n", csfsnp_id);
            return (EC_FALSE);
        }

        csfsnp_print(log, csfsnp);

        csfsnp_mgr_close_np(csfsnp_mgr, csfsnp_id);
    }
    else
    {    
        csfsnp_print(log, csfsnp);
    }

    return (EC_TRUE);
}

STATIC_CAST static uint32_t __csfsnp_mgr_get_np_id_of_path(const CSFSNP_MGR *csfsnp_mgr, const uint32_t path_len, const uint8_t *path)
{
    uint32_t csfsnp_num;
    uint32_t csfsnp_id;
    uint32_t hash_val;

    csfsnp_num = CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr);
    if(0 == csfsnp_num)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_get_np_id_of_path: csfsnp num is zero\n");
        return (CSFSNP_ERR_ID);
    }
 
    if(1 == csfsnp_num)
    {
        csfsnp_id = 0;
        return (csfsnp_id);
    }

    hash_val   = __csfsnp_mgr_path_hash(path_len, path);
    csfsnp_num = CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr);
    csfsnp_id  = (hash_val % csfsnp_num);
    dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_mgr_get_np_id_of_path: hash %u, csfsnp num %u => csfsnp id %u\n", hash_val, csfsnp_num, csfsnp_id);
    return (csfsnp_id);
}

STATIC_CAST static CSFSNP *__csfsnp_mgr_get_np_of_id(CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id)
{
    CSFSNP  * csfsnp;

    CSFSNP_MGR_CMUTEX_LOCK(csfsnp_mgr, LOC_CSFSNPMGR_0021);
    csfsnp = csfsnp_mgr_open_np(csfsnp_mgr, csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0022);
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_get_np_of_id: cannot open np %u\n", csfsnp_id);
        return (NULL_PTR);
    }
    CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0023);
 
    return (csfsnp);        
}

STATIC_CAST static CSFSNP *__csfsnp_mgr_get_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t path_len, const uint8_t *path, uint32_t *np_id)
{
    CSFSNP  * csfsnp;
    uint32_t  csfsnp_id;
 
    csfsnp_id = __csfsnp_mgr_get_np_id_of_path(csfsnp_mgr, path_len, path);
    if(CSFSNP_ERR_ID == csfsnp_id)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_get_np: no np for path %.*s\n", path_len, (char *)path);
        return (NULL_PTR);
    }

    CSFSNP_MGR_CMUTEX_LOCK(csfsnp_mgr, LOC_CSFSNPMGR_0024);
    csfsnp = csfsnp_mgr_open_np(csfsnp_mgr, csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0025);
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_get_np: path %.*s in np %u but cannot open\n", path_len, path, csfsnp_id);
        return (NULL_PTR);
    }
    CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0026);

    if(NULL_PTR != np_id)
    {
        (*np_id) = csfsnp_id;
    }
 
    return (csfsnp);        
}

EC_BOOL csfsnp_mgr_search(CSFSNP_MGR *csfsnp_mgr, const uint32_t path_len, const uint8_t *path, uint32_t *searched_csfsnp_id)
{
    CSFSNP   *csfsnp;
    uint32_t  csfsnp_id; 
    uint32_t  node_pos;
 
    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, path_len, path, &csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_search: path %.*s in np %u but cannot open\n", path_len, path, csfsnp_id);
        return (EC_FALSE);
    }

    node_pos = csfsnp_search(csfsnp, path_len, path);
    if(CSFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mgr_search: path %.*s in np %u but not found indeed\n", path_len, path, csfsnp_id);
        return (EC_FALSE);
    }

    if(NULL_PTR != searched_csfsnp_id)
    {
        (*searched_csfsnp_id) = csfsnp_id;
    }

    return (EC_TRUE);
}

CSFSNP_ITEM *csfsnp_mgr_search_item(CSFSNP_MGR *csfsnp_mgr, const uint32_t path_len, const uint8_t *path)
{
    CSFSNP   *csfsnp;
    uint32_t  csfsnp_id; 
    uint32_t  node_pos;
 
    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, path_len, path, &csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_search_item: path %.*s in np %u but cannot open\n", path_len, path, csfsnp_id);
        return (NULL_PTR);
    }

    node_pos = csfsnp_search(csfsnp, path_len, path);
    if(CSFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mgr_search_item: path %.*s in np %u but not found indeed\n", path_len, path, csfsnp_id);
        return (NULL_PTR);
    }

    return csfsnp_fetch(csfsnp, node_pos);
}

CSFSNP_MGR *csfsnp_mgr_create(const uint8_t csfsnp_model,
                                const uint32_t csfsnp_max_num,
                                const uint8_t  csfsnp_1st_chash_algo_id,
                                const uint8_t  csfsnp_2nd_chash_algo_id,
                                const CSTRING *csfsnp_db_root_dir)
{
    CSFSNP_MGR *csfsnp_mgr;
    uint32_t csfsnp_item_max_num;
    uint32_t csfsnp_id;
 
    if(EC_FALSE == csfsnp_model_item_max_num(csfsnp_model , &csfsnp_item_max_num))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_create: invalid csfsnp model %u\n", csfsnp_model);
        return (NULL_PTR);
    }

    csfsnp_mgr = csfsnp_mgr_new();

    CSFSNP_MGR_NP_MODEL(csfsnp_mgr)                = csfsnp_model;
    CSFSNP_MGR_NP_1ST_CHASH_ALGO_ID(csfsnp_mgr)    = csfsnp_1st_chash_algo_id;
    CSFSNP_MGR_NP_2ND_CHASH_ALGO_ID(csfsnp_mgr)    = csfsnp_2nd_chash_algo_id;
    CSFSNP_MGR_NP_ITEM_MAX_NUM(csfsnp_mgr)         = csfsnp_item_max_num;
    CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr)              = csfsnp_max_num;

    cstring_clone(csfsnp_db_root_dir, CSFSNP_MGR_DB_ROOT_DIR(csfsnp_mgr));

    for(csfsnp_id = 0; csfsnp_id < csfsnp_max_num; csfsnp_id ++)
    {
        const char *np_root_dir;
        CSFSNP *csfsnp;

        np_root_dir = (const char *)cstring_get_str(csfsnp_db_root_dir);/*Oops! int the same dire*/
        csfsnp = csfsnp_create(np_root_dir, csfsnp_id, csfsnp_model, csfsnp_1st_chash_algo_id, csfsnp_2nd_chash_algo_id);
        if(NULL_PTR == csfsnp)
        {
            dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_create: create np %u failed\n", csfsnp_id);
            return (NULL_PTR);
        }
        csfsnp_close(csfsnp);
     
        cvector_push_no_lock(CSFSNP_MGR_NP_VEC(csfsnp_mgr), (void *)NULL_PTR);
    }

    if(EC_FALSE == csfsnp_mgr_create_db(csfsnp_mgr, csfsnp_db_root_dir))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_create: create cfg db failed in root dir %s\n",
                            (char *)cstring_get_str(csfsnp_db_root_dir));
        csfsnp_mgr_free(csfsnp_mgr);
        return (NULL_PTR);
    }

    //csfsnp_mgr_free(csfsnp_mgr);
    return (csfsnp_mgr);
}

EC_BOOL csfsnp_mgr_exist(const CSTRING *csfsnp_db_root_dir)
{
    char  *csfsnp_mgr_db_name;

    csfsnp_mgr_db_name = __csfsnp_mgr_gen_db_name((char *)cstring_get_str(csfsnp_db_root_dir));
    if(NULL_PTR == csfsnp_mgr_db_name)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_exist: new str %s/%s failed\n",
                            (char *)cstring_get_str(csfsnp_db_root_dir), CSFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(csfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_exist: csfsnp mgr db %s not exist\n", csfsnp_mgr_db_name);
        safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0027);
        return (EC_FALSE);
    }
    safe_free(csfsnp_mgr_db_name, LOC_CSFSNPMGR_0028);
    return (EC_TRUE);
}

CSFSNP_MGR * csfsnp_mgr_open(const CSTRING *csfsnp_db_root_dir)
{
    CSFSNP_MGR *csfsnp_mgr;

    csfsnp_mgr = csfsnp_mgr_new();
    if(NULL_PTR == csfsnp_mgr)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_open: new csfsnp mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csfsnp_mgr_load(csfsnp_mgr, csfsnp_db_root_dir))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_open: load failed\n");
        csfsnp_mgr_free(csfsnp_mgr);
        return (NULL_PTR);
    }
    return (csfsnp_mgr);
}

EC_BOOL csfsnp_mgr_close(CSFSNP_MGR *csfsnp_mgr)
{ 
    if(NULL_PTR != csfsnp_mgr)
    {
        CSFSNP_MGR_CMUTEX_LOCK(csfsnp_mgr, LOC_CSFSNPMGR_0029);
        csfsnp_mgr_flush(csfsnp_mgr);
        CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0030);
        csfsnp_mgr_free(csfsnp_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_find(CSFSNP_MGR *csfsnp_mgr, const CSTRING *path)
{
    return csfsnp_mgr_search(csfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), NULL_PTR);
}

CSFSNP_FNODE *csfsnp_mgr_reserve(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path, uint32_t *csfsnp_id)
{
    CSFSNP      *csfsnp;
    CSFSNP_ITEM *csfsnp_item;
    uint32_t     csfsnp_id_t;

    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &csfsnp_id_t);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_reserve: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    csfsnp_item = csfsnp_set(csfsnp, cstring_get_len(file_path), cstring_get_str(file_path));
    if(NULL_PTR == csfsnp_item)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_reserve: set file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), csfsnp_id_t);
        return (NULL_PTR);
    }

    CSFSNP_ITEM_C_TIME(csfsnp_item) = task_brd_default_get_time();

    if(NULL_PTR != csfsnp_id)
    {
        (*csfsnp_id) = csfsnp_id_t;
    }

    /*not import yet*/ 
    return CSFSNP_ITEM_FNODE(csfsnp_item);
}

EC_BOOL csfsnp_mgr_release(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path)
{
    CSFSNP     *csfsnp;
    uint32_t    csfsnp_id;

    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_release: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsnp_delete(csfsnp, cstring_get_len(file_path), cstring_get_str(file_path)))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_release: delete file %s from np %u failed\n",
                            (char *)cstring_get_str(file_path), csfsnp_id);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_write(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path, const CSFSNP_FNODE *csfsnp_fnode, uint32_t *csfsnp_id, uint32_t *node_pos)
{
    CSFSNP         *csfsnp;
    CSFSNP_ITEM    *csfsnp_item;
    uint32_t        csfsnp_id_t;
    uint32_t        node_pos_t;

    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &csfsnp_id_t);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_write: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    node_pos_t = csfsnp_insert(csfsnp, cstring_get_len(file_path), cstring_get_str(file_path));
    if(CSFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_write: insert file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), csfsnp_id_t);
        return (EC_FALSE);
    }
 
    csfsnp_item = csfsnp_fetch(csfsnp, node_pos_t);
    if(NULL_PTR == csfsnp_item)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_write: set file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), csfsnp_id_t);
        return (EC_FALSE);
    }

    CSFSNP_ITEM_C_TIME(csfsnp_item) = task_brd_default_get_time();
 
    if(EC_FALSE == csfsnp_fnode_import(csfsnp_fnode, CSFSNP_ITEM_FNODE(csfsnp_item)))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_write: import fnode to item failed where path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(NULL_PTR != csfsnp_id)
    {
        (*csfsnp_id) = csfsnp_id_t;
    }

    if(NULL_PTR != node_pos)
    {
        (*node_pos) = node_pos_t;
    }

    if(do_log(SEC_0171_CSFSNPMGR, 9))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mgr_write: import fnode to item successfully where path %s\n", (char *)cstring_get_str(file_path));
        csfsnp_item_print(LOGSTDOUT, csfsnp_item);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_read(CSFSNP_MGR *csfsnp_mgr, const CSTRING *file_path, CSFSNP_FNODE *csfsnp_fnode)
{
    CSFSNP         *csfsnp;
    uint32_t        csfsnp_id;
    uint32_t        node_pos;

    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_read: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    node_pos = csfsnp_search_no_lock(csfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path));
    if(CSFSNPRB_ERR_POS != node_pos)
    {
        CSFSNP_ITEM *csfsnp_item;

        csfsnp_item = csfsnp_fetch(csfsnp, node_pos);
        return csfsnp_fnode_import(CSFSNP_ITEM_FNODE(csfsnp_item), csfsnp_fnode);
    }
 
    dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mgr_read: search nothing for path '%s'\n", (char *)cstring_get_str(file_path));
    return (EC_FALSE); 
}

EC_BOOL csfsnp_mgr_delete(CSFSNP_MGR *csfsnp_mgr, const CSTRING *path)
{
    CSFSNP         *csfsnp;
    uint32_t        csfsnp_id;

    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_delete: no np for path %s\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return csfsnp_delete(csfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path));
}

STATIC_CAST static EC_BOOL __csfsnp_mgr_delete_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t csfsnp_id, const uint32_t node_pos)
{
    CSFSNP *csfsnp;
 
    CSFSNP_MGR_CMUTEX_LOCK(csfsnp_mgr, LOC_CSFSNPMGR_0031);
    csfsnp = csfsnp_mgr_open_np(csfsnp_mgr, csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0032);
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_delete_np: open np %u failed\n", csfsnp_id);
        return (EC_FALSE);
    }
    if(EC_FALSE == csfsnp_delete_item(csfsnp, node_pos))
    {
        CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0033);

        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:__csfsnp_mgr_delete_np: delete node_pos %u from np %u failed\n",
                        node_pos, csfsnp_id);

        return (EC_FALSE);
    }
    CSFSNP_MGR_CMUTEX_UNLOCK(csfsnp_mgr, LOC_CSFSNPMGR_0034);

    dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __csfsnp_mgr_delete_np: delete node_pos %u from np %u done\n",
                        node_pos, csfsnp_id);
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_delete_np(CSFSNP_MGR *csfsnp_mgr, const uint32_t node_pos)
{
    uint32_t csfsnp_id;
    uint32_t node_pos_t;

    csfsnp_id  = (node_pos >> 30) & 0x3;
    node_pos_t = ((node_pos << 2) >> 2);

    if(EC_FALSE == __csfsnp_mgr_delete_np(csfsnp_mgr, csfsnp_id, node_pos_t))
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_delete_np: delete node_pos %u (%x) failed\n",
                        node_pos, node_pos);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0171_CSFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] csfsnp_mgr_delete_np: delete node_pos %u (%x) done\n",
                        node_pos, node_pos);
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_file_num(CSFSNP_MGR *csfsnp_mgr, UINT32 *file_num)
{
    uint32_t csfsnp_id;

    (*file_num) = 0;

    for(csfsnp_id = 0; csfsnp_id < CSFSNP_MGR_NP_MAX_NUM(csfsnp_mgr); csfsnp_id ++)
    {
        CSFSNP*csfsnp;
     
        csfsnp = csfsnp_mgr_open_np(csfsnp_mgr, csfsnp_id);
        if(NULL_PTR == csfsnp)
        {
            dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_file_num: open np %u failed\n", csfsnp_id);
            return (EC_FALSE);
        }
        (*file_num) += csfsnp_count_file_num(csfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_file_size(CSFSNP_MGR *csfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_size)
{
    CSFSNP  *csfsnp;
    uint32_t csfsnp_id;
    uint32_t node_pos;
    uint32_t cur_file_size;

    csfsnp = __csfsnp_mgr_get_np(csfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &csfsnp_id);
    if(NULL_PTR == csfsnp)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_file_size: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    node_pos = csfsnp_file_size(csfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_size);
    if(CSFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0171_CSFSNPMGR, 0)(LOGSTDOUT, "error:csfsnp_mgr_file_size: get size of file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    } 

    (*file_size) = cur_file_size;
 
    return (EC_TRUE); 
}

EC_BOOL csfsnp_mgr_show_cached_np(LOG *log, const CSFSNP_MGR *csfsnp_mgr)
{
    uint32_t csfsnp_num;
    uint32_t csfsnp_pos;

    csfsnp_num = cvector_size(CSFSNP_MGR_NP_VEC(csfsnp_mgr));
    for(csfsnp_pos = 0; csfsnp_pos < csfsnp_num; csfsnp_pos ++)
    {
        CSFSNP *csfsnp;

        csfsnp = CSFSNP_MGR_NP(csfsnp_mgr, csfsnp_pos);
        if(NULL_PTR != csfsnp)
        {
            csfsnp_print(log, csfsnp);
        }
    }
    return (EC_TRUE);
}

EC_BOOL csfsnp_mgr_rdlock(CSFSNP_MGR *csfsnp_mgr, const UINT32 location)
{
    return CSFSNP_MGR_CRWLOCK_RDLOCK(csfsnp_mgr, location);
}

EC_BOOL csfsnp_mgr_wrlock(CSFSNP_MGR *csfsnp_mgr, const UINT32 location)
{
    return CSFSNP_MGR_CRWLOCK_WRLOCK(csfsnp_mgr, location);
}

EC_BOOL csfsnp_mgr_unlock(CSFSNP_MGR *csfsnp_mgr, const UINT32 location)
{
    return CSFSNP_MGR_CRWLOCK_UNLOCK(csfsnp_mgr, location);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

