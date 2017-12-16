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

#include "chfsnp.h"
#include "chfsnprb.h"
#include "chfsnpmgr.h"
#include "chashalgo.h"

#include "findex.inc"

static uint32_t __chfsnp_mgr_path_hash(const uint32_t path_len, const uint8_t *path)
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

CHFSNP_MGR *chfsnp_mgr_new()
{
    CHFSNP_MGR *chfsnp_mgr;

    alloc_static_mem(MM_CHFSNP_MGR, &chfsnp_mgr, LOC_CHFSNPMGR_0001);
    if(NULL_PTR != chfsnp_mgr)
    {
        chfsnp_mgr_init(chfsnp_mgr);
    }

    return (chfsnp_mgr);
}

EC_BOOL chfsnp_mgr_init(CHFSNP_MGR *chfsnp_mgr)
{
    CHFSNP_MGR_CRWLOCK_INIT(chfsnp_mgr, LOC_CHFSNPMGR_0002);
    CHFSNP_MGR_CMUTEX_INIT(chfsnp_mgr, LOC_CHFSNPMGR_0003);
 
    cstring_init(CHFSNP_MGR_DB_ROOT_DIR(chfsnp_mgr), NULL_PTR); 

    CHFSNP_MGR_NP_MODEL(chfsnp_mgr) = CHFSNP_ERR_MODEL;
    CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID(chfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID(chfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CHFSNP_MGR_NP_ITEM_MAX_NUM(chfsnp_mgr)      = 0;
    CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr)           = 0;

    cvector_init(CHFSNP_MGR_NP_VEC(chfsnp_mgr), 0, MM_CHFSNP, CVECTOR_LOCK_ENABLE, LOC_CHFSNPMGR_0004);
 
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_clean(CHFSNP_MGR *chfsnp_mgr)
{
    CHFSNP_MGR_CRWLOCK_CLEAN(chfsnp_mgr, LOC_CHFSNPMGR_0005);
    CHFSNP_MGR_CMUTEX_CLEAN(chfsnp_mgr, LOC_CHFSNPMGR_0006);
 
    cstring_clean(CHFSNP_MGR_DB_ROOT_DIR(chfsnp_mgr)); 

    CHFSNP_MGR_NP_MODEL(chfsnp_mgr) = CHFSNP_ERR_MODEL;
    CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID(chfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID(chfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CHFSNP_MGR_NP_ITEM_MAX_NUM(chfsnp_mgr)      = 0;
    CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr)           = 0;

    cvector_clean(CHFSNP_MGR_NP_VEC(chfsnp_mgr), (CVECTOR_DATA_CLEANER)chfsnp_free, LOC_CHFSNPMGR_0007);    

    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_free(CHFSNP_MGR *chfsnp_mgr)
{
    if(NULL_PTR != chfsnp_mgr)
    {
        chfsnp_mgr_clean(chfsnp_mgr);
        free_static_mem(MM_CHFSNP_MGR, chfsnp_mgr, LOC_CHFSNPMGR_0008);
    }
    return (EC_TRUE);
}

CHFSNP *chfsnp_mgr_open_np(CHFSNP_MGR *chfsnp_mgr, const uint32_t chfsnp_id)
{
    CHFSNP *chfsnp;

    chfsnp = (CHFSNP *)cvector_get_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), chfsnp_id);
    if(NULL_PTR != chfsnp)
    {
        return (chfsnp);
    }

    chfsnp = chfsnp_open((char *)CHFSNP_MGR_DB_ROOT_DIR_STR(chfsnp_mgr), chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_open_np: open np %u from %s failed\n",
                           chfsnp_id, (char *)CHFSNP_MGR_DB_ROOT_DIR_STR(chfsnp_mgr));
        return (NULL_PTR);
    }

    cvector_set_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), chfsnp_id, chfsnp);
    return (chfsnp);
}

EC_BOOL chfsnp_mgr_close_np(CHFSNP_MGR *chfsnp_mgr, const uint32_t chfsnp_id)
{
    CHFSNP *chfsnp;

    chfsnp = (CHFSNP *)cvector_get_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 1)(LOGSTDOUT, "warn:chfsnp_mgr_close_np: np %u not open yet\n", chfsnp_id);
        return (EC_TRUE);
    }

    cvector_set_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), chfsnp_id, NULL_PTR);
    chfsnp_close(chfsnp);
    return (EC_TRUE);
}

static char *__chfsnp_mgr_gen_db_name(const char *root_dir)
{
    const char *fields[ 2 ];
 
    fields[ 0 ] = root_dir;
    fields[ 1 ] = CHFSNP_DB_NAME;
 
    return c_str_join((char *)"/", fields, 2);
}

static EC_BOOL __chfsnp_mgr_load_db(CHFSNP_MGR *chfsnp_mgr, int chfsnp_mgr_fd)
{
    UINT32 chfsnp_mgr_db_size;
    UINT8* chfsnp_mgr_db_buff;
    UINT32 chfsnp_mgr_db_offset;

    uint32_t chfsnp_id;
 
    /*init offset*/
    chfsnp_mgr_db_offset = 0;

    /*CHFSNP_MGR_NP_MODEL*/
    chfsnp_mgr_db_size   = sizeof(uint8_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_MODEL(chfsnp_mgr)); 
    if(EC_FALSE == c_file_load(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_load_db: load np model failed\n");
        return (EC_FALSE);
    }

    /*CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID*/
    chfsnp_mgr_db_size   = sizeof(uint8_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID(chfsnp_mgr)); 
    if(EC_FALSE == c_file_load(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_load_db: load 1st chash algo id failed\n");
        return (EC_FALSE);
    } 

    /*CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    chfsnp_mgr_db_size   = sizeof(uint8_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID(chfsnp_mgr)); 
    if(EC_FALSE == c_file_load(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_load_db: load 2nd chash algo id failed\n");
        return (EC_FALSE);
    }  

    /*CHFSNP_MGR_NP_ITEM_MAX_NUM*/
    chfsnp_mgr_db_size   = sizeof(uint32_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_ITEM_MAX_NUM(chfsnp_mgr)); 
    if(EC_FALSE == c_file_load(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_load_db: load item max num failed\n");
        return (EC_FALSE);
    }  

    /*CHFSNP_MGR_NP_MAX_NUM*/
    chfsnp_mgr_db_size   = sizeof(uint32_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr)); 
    if(EC_FALSE == c_file_load(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_load_db: load disk max num failed\n");
        return (EC_FALSE);
    }

    for(chfsnp_id = cvector_size(CHFSNP_MGR_NP_VEC(chfsnp_mgr)); chfsnp_id < CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr); chfsnp_id ++)
    {
        cvector_push_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), NULL_PTR);
    }


    return (EC_TRUE);
}

static EC_BOOL __chfsnp_mgr_flush_db(CHFSNP_MGR *chfsnp_mgr, int chfsnp_mgr_fd)
{
    UINT32 chfsnp_mgr_db_size;
    UINT8* chfsnp_mgr_db_buff;
    UINT32 chfsnp_mgr_db_offset;

    /*init offset*/
    chfsnp_mgr_db_offset = 0;

    /*CHFSNP_MGR_NP_MODEL*/
    chfsnp_mgr_db_size   = sizeof(uint8_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_MODEL(chfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_flush_db: flush np model failed");
        return (EC_FALSE);
    }

    /*CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID*/
    chfsnp_mgr_db_size   = sizeof(uint8_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID(chfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_flush_db: flush 1st chash algo id failed");
        return (EC_FALSE);
    } 

    /*CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    chfsnp_mgr_db_size   = sizeof(uint8_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID(chfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_flush_db: flush 2nd chash algo id failed");
        return (EC_FALSE);
    }  

    /*CHFSNP_MGR_NP_ITEM_MAX_NUM*/
    chfsnp_mgr_db_size   = sizeof(uint32_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_ITEM_MAX_NUM(chfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_flush_db: flush item max num failed");
        return (EC_FALSE);
    }  

    /*CHFSNP_MGR_NP_MAX_NUM*/
    chfsnp_mgr_db_size   = sizeof(uint32_t);
    chfsnp_mgr_db_buff   = (UINT8 *)&(CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr)); 
    if(EC_FALSE == c_file_flush(chfsnp_mgr_fd, &chfsnp_mgr_db_offset, chfsnp_mgr_db_size, chfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_flush_db: flush disk max num failed");
        return (EC_FALSE);
    }

    dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __chfsnp_mgr_flush_db: np max num = %u\n", CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr));

    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_load_db(CHFSNP_MGR *chfsnp_mgr)
{
    char  *chfsnp_mgr_db_name;
    int    chfsnp_mgr_fd;

    chfsnp_mgr_db_name = __chfsnp_mgr_gen_db_name((char *)CHFSNP_MGR_DB_ROOT_DIR_STR(chfsnp_mgr));
    if(NULL_PTR == chfsnp_mgr_db_name)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_load_db: new str %s/%s failed\n",
                            (char *)CHFSNP_MGR_DB_ROOT_DIR_STR(chfsnp_mgr), CHFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(chfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_load_db: chfsnp mgr db %s not exist\n", chfsnp_mgr_db_name);
        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0009);
        return (EC_FALSE);
    }

    chfsnp_mgr_fd = c_file_open(chfsnp_mgr_db_name, O_RDONLY, 0666);
    if(ERR_FD == chfsnp_mgr_fd)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_load_db: open chfsnp mgr db %s failed\n", chfsnp_mgr_db_name);
        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0010);
        return (EC_FALSE);
    }

    if(EC_FALSE == __chfsnp_mgr_load_db(chfsnp_mgr, chfsnp_mgr_fd))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_load_db: load db from chfsnp mgr db %s\n", chfsnp_mgr_db_name);
        c_file_close(chfsnp_mgr_fd);
        chfsnp_mgr_fd = ERR_FD;

        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0011);
        return (EC_FALSE);
    }

    c_file_close(chfsnp_mgr_fd);
    chfsnp_mgr_fd = ERR_FD;

    dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] chfsnp_mgr_load_db: load db from chfsnp mgr db %s done\n", chfsnp_mgr_db_name);

    safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0012);
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_create_db(CHFSNP_MGR *chfsnp_mgr, const CSTRING *chfsnp_db_root_dir)
{
    char  *chfsnp_mgr_db_name;
    int    chfsnp_mgr_fd;

    chfsnp_mgr_db_name = __chfsnp_mgr_gen_db_name((char *)cstring_get_str(chfsnp_db_root_dir));
    if(NULL_PTR == chfsnp_mgr_db_name)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_create_db: new str %s/%s failed\n",
                            (char *)cstring_get_str(chfsnp_db_root_dir), CHFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_TRUE == c_file_access(chfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_create_db: chfsnp mgr db %s already exist\n", chfsnp_mgr_db_name);
        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0013);
        return (EC_FALSE);
    }

    chfsnp_mgr_fd = c_file_open(chfsnp_mgr_db_name, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == chfsnp_mgr_fd)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_create_db: open chfsnp mgr db %s failed\n", chfsnp_mgr_db_name);
        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0014);
        return (EC_FALSE);
    }

    if(EC_FALSE == __chfsnp_mgr_flush_db(chfsnp_mgr, chfsnp_mgr_fd))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_create_db: flush db to chfsnp mgr db %s\n", chfsnp_mgr_db_name);
        c_file_close(chfsnp_mgr_fd);
        chfsnp_mgr_fd = ERR_FD;

        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0015);
        return (EC_FALSE);
    } 

    c_file_close(chfsnp_mgr_fd);
    chfsnp_mgr_fd = ERR_FD;

    safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0016);
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_flush_db(CHFSNP_MGR *chfsnp_mgr)
{
    char  *chfsnp_mgr_db_name;
    int    chfsnp_mgr_fd;

    chfsnp_mgr_db_name = __chfsnp_mgr_gen_db_name((char *)CHFSNP_MGR_DB_ROOT_DIR_STR(chfsnp_mgr));
    if(NULL_PTR == chfsnp_mgr_db_name)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_flush_db: new str %s/%s failed\n",
                            (char *)CHFSNP_MGR_DB_ROOT_DIR_STR(chfsnp_mgr), CHFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(chfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_flush_db: chfsnp mgr db %s not exist\n", chfsnp_mgr_db_name);
        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0017);
        return (EC_FALSE);
    }

    chfsnp_mgr_fd = c_file_open(chfsnp_mgr_db_name, O_RDWR, 0666);
    if(ERR_FD == chfsnp_mgr_fd)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_flush_db: open chfsnp mgr db %s failed\n", chfsnp_mgr_db_name);
        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0018);
        return (EC_FALSE);
    }

    if(EC_FALSE == __chfsnp_mgr_flush_db(chfsnp_mgr, chfsnp_mgr_fd))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_flush_db: flush db to chfsnp mgr db %s\n", chfsnp_mgr_db_name);
        c_file_close(chfsnp_mgr_fd);
        chfsnp_mgr_fd = ERR_FD;

        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0019);
        return (EC_FALSE);
    }

    c_file_close(chfsnp_mgr_fd);
    chfsnp_mgr_fd = ERR_FD;

    safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0020);
    return (EC_TRUE);
}

void chfsnp_mgr_print_db(LOG *log, const CHFSNP_MGR *chfsnp_mgr)
{
    uint32_t chfsnp_num;
    uint32_t chfsnp_id;

    sys_log(log, "chfsnp mgr db root dir  : %s\n", (char *)CHFSNP_MGR_DB_ROOT_DIR_STR(chfsnp_mgr));
    sys_log(log, "chfsnp model            : %u\n", CHFSNP_MGR_NP_MODEL(chfsnp_mgr));
    sys_log(log, "chfsnp 1st hash algo id : %u\n", CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID(chfsnp_mgr));
    sys_log(log, "chfsnp 2nd hash algo id : %u\n", CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID(chfsnp_mgr));
    sys_log(log, "chfsnp item max num     : %u\n", CHFSNP_MGR_NP_ITEM_MAX_NUM(chfsnp_mgr));
    sys_log(log, "chfsnp max num          : %u\n", CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr));

    chfsnp_num = (uint32_t)cvector_size(CHFSNP_MGR_NP_VEC(chfsnp_mgr));
    for(chfsnp_id = 0; chfsnp_id < chfsnp_num; chfsnp_id ++)
    {
        CHFSNP *chfsnp;

        chfsnp = CHFSNP_MGR_NP(chfsnp_mgr, chfsnp_id);
        if(NULL_PTR == chfsnp)
        {
            sys_log(log, "np %u #: (null)\n", chfsnp_id);
        }
        else
        {
            chfsnp_print(log, chfsnp);
        }
    }
    return;
}

void chfsnp_mgr_print(LOG *log, const CHFSNP_MGR *chfsnp_mgr)
{
    sys_log(log, "chfsnp mgr:\n");
    chfsnp_mgr_print_db(log, chfsnp_mgr);
    return;
}

EC_BOOL chfsnp_mgr_load(CHFSNP_MGR *chfsnp_mgr, const CSTRING *chfsnp_db_root_dir)
{
    cstring_clean(CHFSNP_MGR_DB_ROOT_DIR(chfsnp_mgr));
    cstring_clone(chfsnp_db_root_dir, CHFSNP_MGR_DB_ROOT_DIR(chfsnp_mgr));

    if(EC_FALSE == chfsnp_mgr_load_db(chfsnp_mgr))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_load: load cfg db failed from dir %s\n", (char *)cstring_get_str(chfsnp_db_root_dir));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_sync_np(CHFSNP_MGR *chfsnp_mgr, const uint32_t chfsnp_id)
{
    CHFSNP *chfsnp;
 
    chfsnp = (CHFSNP *)cvector_get_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), chfsnp_id);
    if(NULL_PTR != chfsnp)
    {
        return chfsnp_sync(chfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_flush(CHFSNP_MGR *chfsnp_mgr)
{
    uint32_t chfsnp_num;
    uint32_t chfsnp_id;
    EC_BOOL ret;

    ret = EC_TRUE;

    if(EC_FALSE == chfsnp_mgr_flush_db(chfsnp_mgr))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_flush: flush cfg db failed\n");
        ret = EC_FALSE;
    }

    chfsnp_num = CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr);
    for(chfsnp_id = 0; chfsnp_id < chfsnp_num; chfsnp_id ++)
    {
        chfsnp_mgr_sync_np(chfsnp_mgr, chfsnp_id);
    }
    return (ret);
}

EC_BOOL chfsnp_mgr_show_np(LOG *log, CHFSNP_MGR *chfsnp_mgr, const uint32_t chfsnp_id)
{
    CHFSNP *chfsnp;

    chfsnp = (CHFSNP *)cvector_get_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), chfsnp_id);
    if(NULL_PTR == chfsnp)
    {     
        /*try to open the np and print it*/
        chfsnp = chfsnp_mgr_open_np(chfsnp_mgr, chfsnp_id);
        if(NULL_PTR == chfsnp)
        {
            dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_show_np: open np %u failed\n", chfsnp_id);
            return (EC_FALSE);
        }

        chfsnp_print(log, chfsnp);

        chfsnp_mgr_close_np(chfsnp_mgr, chfsnp_id);
    }
    else
    {    
        chfsnp_print(log, chfsnp);
    }

    return (EC_TRUE);
}

static uint32_t __chfsnp_mgr_get_np_id_of_path(const CHFSNP_MGR *chfsnp_mgr, const uint32_t path_len, const uint8_t *path)
{
    uint32_t chfsnp_num;
    uint32_t chfsnp_id;
    uint32_t hash_val;

    chfsnp_num = CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr);
    if(0 == chfsnp_num)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_get_np_id_of_path: chfsnp num is zero\n");
        return (CHFSNP_ERR_ID);
    }
 
    if(1 == chfsnp_num)
    {
        chfsnp_id = 0;
        return (chfsnp_id);
    }

    hash_val   = __chfsnp_mgr_path_hash(path_len, path);
    chfsnp_num = CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr);
    chfsnp_id  = (hash_val % chfsnp_num);
    dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __chfsnp_mgr_get_np_id_of_path: hash %u, chfsnp num %u => chfsnp id %u\n", hash_val, chfsnp_num, chfsnp_id);
    return (chfsnp_id);
}

static CHFSNP *__chfsnp_mgr_get_np_of_id(CHFSNP_MGR *chfsnp_mgr, const uint32_t chfsnp_id)
{
    CHFSNP  * chfsnp;

    CHFSNP_MGR_CMUTEX_LOCK(chfsnp_mgr, LOC_CHFSNPMGR_0021);
    chfsnp = chfsnp_mgr_open_np(chfsnp_mgr, chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        CHFSNP_MGR_CMUTEX_UNLOCK(chfsnp_mgr, LOC_CHFSNPMGR_0022);
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_get_np_of_id: cannot open np %u\n", chfsnp_id);
        return (NULL_PTR);
    }
    CHFSNP_MGR_CMUTEX_UNLOCK(chfsnp_mgr, LOC_CHFSNPMGR_0023);
 
    return (chfsnp);        
}

static CHFSNP *__chfsnp_mgr_get_np(CHFSNP_MGR *chfsnp_mgr, const uint32_t path_len, const uint8_t *path, uint32_t *np_id)
{
    CHFSNP  * chfsnp;
    uint32_t  chfsnp_id;
 
    chfsnp_id = __chfsnp_mgr_get_np_id_of_path(chfsnp_mgr, path_len, path);
    if(CHFSNP_ERR_ID == chfsnp_id)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_get_np: no np for path %.*s\n", path_len, (char *)path);
        return (NULL_PTR);
    }

    CHFSNP_MGR_CMUTEX_LOCK(chfsnp_mgr, LOC_CHFSNPMGR_0024);
    chfsnp = chfsnp_mgr_open_np(chfsnp_mgr, chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        CHFSNP_MGR_CMUTEX_UNLOCK(chfsnp_mgr, LOC_CHFSNPMGR_0025);
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:__chfsnp_mgr_get_np: path %.*s in np %u but cannot open\n", path_len, path, chfsnp_id);
        return (NULL_PTR);
    }
    CHFSNP_MGR_CMUTEX_UNLOCK(chfsnp_mgr, LOC_CHFSNPMGR_0026);

    if(NULL_PTR != np_id)
    {
        (*np_id) = chfsnp_id;
    }
 
    return (chfsnp);        
}

EC_BOOL chfsnp_mgr_search(CHFSNP_MGR *chfsnp_mgr, const uint32_t path_len, const uint8_t *path, uint32_t *searched_chfsnp_id)
{
    CHFSNP   *chfsnp;
    uint32_t  chfsnp_id; 
    uint32_t  node_pos;
 
    chfsnp = __chfsnp_mgr_get_np(chfsnp_mgr, path_len, path, &chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_search: path %.*s in np %u but cannot open\n", path_len, path, chfsnp_id);
        return (EC_FALSE);
    }

    node_pos = chfsnp_search(chfsnp, path_len, path);
    if(CHFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] chfsnp_mgr_search: path %.*s in np %u but not found indeed\n", path_len, path, chfsnp_id);
        return (EC_FALSE);
    }

    if(NULL_PTR != searched_chfsnp_id)
    {
        (*searched_chfsnp_id) = chfsnp_id;
    }

    return (EC_TRUE);
}

CHFSNP_ITEM *chfsnp_mgr_search_item(CHFSNP_MGR *chfsnp_mgr, const uint32_t path_len, const uint8_t *path)
{
    CHFSNP   *chfsnp;
    uint32_t  chfsnp_id; 
    uint32_t  node_pos;
 
    chfsnp = __chfsnp_mgr_get_np(chfsnp_mgr, path_len, path, &chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_search_item: path %.*s in np %u but cannot open\n", path_len, path, chfsnp_id);
        return (NULL_PTR);
    }

    node_pos = chfsnp_search(chfsnp, path_len, path);
    if(CHFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] chfsnp_mgr_search_item: path %.*s in np %u but not found indeed\n", path_len, path, chfsnp_id);
        return (NULL_PTR);
    }

    return chfsnp_fetch(chfsnp, node_pos);
}

CHFSNP_MGR *chfsnp_mgr_create(const uint8_t chfsnp_model,
                                const uint32_t chfsnp_max_num,
                                const uint8_t  chfsnp_1st_chash_algo_id,
                                const uint8_t  chfsnp_2nd_chash_algo_id,
                                const CSTRING *chfsnp_db_root_dir)
{
    CHFSNP_MGR *chfsnp_mgr;
    uint32_t chfsnp_item_max_num;
    uint32_t chfsnp_id;
 
    if(EC_FALSE == chfsnp_model_item_max_num(chfsnp_model , &chfsnp_item_max_num))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_create: invalid chfsnp model %u\n", chfsnp_model);
        return (NULL_PTR);
    }

    chfsnp_mgr = chfsnp_mgr_new();

    CHFSNP_MGR_NP_MODEL(chfsnp_mgr)                = chfsnp_model;
    CHFSNP_MGR_NP_1ST_CHASH_ALGO_ID(chfsnp_mgr)    = chfsnp_1st_chash_algo_id;
    CHFSNP_MGR_NP_2ND_CHASH_ALGO_ID(chfsnp_mgr)    = chfsnp_2nd_chash_algo_id;
    CHFSNP_MGR_NP_ITEM_MAX_NUM(chfsnp_mgr)         = chfsnp_item_max_num;
    CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr)              = chfsnp_max_num;

    cstring_clone(chfsnp_db_root_dir, CHFSNP_MGR_DB_ROOT_DIR(chfsnp_mgr));

    for(chfsnp_id = 0; chfsnp_id < chfsnp_max_num; chfsnp_id ++)
    {
        const char *np_root_dir;
        CHFSNP *chfsnp;

        np_root_dir = (const char *)cstring_get_str(chfsnp_db_root_dir);/*Oops! int the same dire*/
        chfsnp = chfsnp_create(np_root_dir, chfsnp_id, chfsnp_model, chfsnp_1st_chash_algo_id, chfsnp_2nd_chash_algo_id);
        if(NULL_PTR == chfsnp)
        {
            dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_create: create np %u failed\n", chfsnp_id);
            return (NULL_PTR);
        }
        chfsnp_close(chfsnp);
     
        cvector_push_no_lock(CHFSNP_MGR_NP_VEC(chfsnp_mgr), (void *)NULL_PTR);
    }

    if(EC_FALSE == chfsnp_mgr_create_db(chfsnp_mgr, chfsnp_db_root_dir))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_create: create cfg db failed in root dir %s\n",
                            (char *)cstring_get_str(chfsnp_db_root_dir));
        chfsnp_mgr_free(chfsnp_mgr);
        return (NULL_PTR);
    }

    //chfsnp_mgr_free(chfsnp_mgr);
    return (chfsnp_mgr);
}

EC_BOOL chfsnp_mgr_exist(const CSTRING *chfsnp_db_root_dir)
{
    char  *chfsnp_mgr_db_name;

    chfsnp_mgr_db_name = __chfsnp_mgr_gen_db_name((char *)cstring_get_str(chfsnp_db_root_dir));
    if(NULL_PTR == chfsnp_mgr_db_name)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_exist: new str %s/%s failed\n",
                            (char *)cstring_get_str(chfsnp_db_root_dir), CHFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(chfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_exist: chfsnp mgr db %s not exist\n", chfsnp_mgr_db_name);
        safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0027);
        return (EC_FALSE);
    }
    safe_free(chfsnp_mgr_db_name, LOC_CHFSNPMGR_0028);
    return (EC_TRUE);
}

CHFSNP_MGR * chfsnp_mgr_open(const CSTRING *chfsnp_db_root_dir)
{
    CHFSNP_MGR *chfsnp_mgr;

    chfsnp_mgr = chfsnp_mgr_new();
    if(NULL_PTR == chfsnp_mgr)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_open: new chfsnp mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == chfsnp_mgr_load(chfsnp_mgr, chfsnp_db_root_dir))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_open: load failed\n");
        chfsnp_mgr_free(chfsnp_mgr);
        return (NULL_PTR);
    }
    return (chfsnp_mgr);
}

EC_BOOL chfsnp_mgr_close(CHFSNP_MGR *chfsnp_mgr)
{ 
    if(NULL_PTR != chfsnp_mgr)
    {
        CHFSNP_MGR_CMUTEX_LOCK(chfsnp_mgr, LOC_CHFSNPMGR_0029);
        chfsnp_mgr_flush(chfsnp_mgr);
        CHFSNP_MGR_CMUTEX_UNLOCK(chfsnp_mgr, LOC_CHFSNPMGR_0030);
        chfsnp_mgr_free(chfsnp_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_find(CHFSNP_MGR *chfsnp_mgr, const CSTRING *path)
{
    return chfsnp_mgr_search(chfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), NULL_PTR);
}

EC_BOOL chfsnp_mgr_write(CHFSNP_MGR *chfsnp_mgr, const CSTRING *file_path, const CHFSNP_FNODE *chfsnp_fnode)
{
    CHFSNP *chfsnp;
    CHFSNP_ITEM *chfsnp_item;
    uint32_t chfsnp_id;

    chfsnp = __chfsnp_mgr_get_np(chfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_write: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    chfsnp_item = chfsnp_set(chfsnp, cstring_get_len(file_path), cstring_get_str(file_path));
    if(NULL_PTR == chfsnp_item)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_write: set file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), chfsnp_id);
        return (EC_FALSE);
    }

    CHFSNP_ITEM_C_TIME(chfsnp_item) = task_brd_default_get_time();
 
    if(EC_FALSE == chfsnp_fnode_import(chfsnp_fnode, CHFSNP_ITEM_FNODE(chfsnp_item)))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_write: import fnode to item failed where path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0065_CHFSNPMGR, 9))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] chfsnp_mgr_write: import fnode to item successfully where path %s\n", (char *)cstring_get_str(file_path));
        chfsnp_item_print(LOGSTDOUT, chfsnp_item);
    }
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_read(CHFSNP_MGR *chfsnp_mgr, const CSTRING *file_path, CHFSNP_FNODE *chfsnp_fnode)
{
    CHFSNP *chfsnp;
    uint32_t chfsnp_id;
    uint32_t node_pos;

    chfsnp = __chfsnp_mgr_get_np(chfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_read: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    node_pos = chfsnp_search_no_lock(chfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path));
    if(CHFSNPRB_ERR_POS != node_pos)
    {
        CHFSNP_ITEM *chfsnp_item;

        chfsnp_item = chfsnp_fetch(chfsnp, node_pos);
        return chfsnp_fnode_import(CHFSNP_ITEM_FNODE(chfsnp_item), chfsnp_fnode);
    }
 
    dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] chfsnp_mgr_read: search nothing for path '%s'\n", (char *)cstring_get_str(file_path));
    return (EC_FALSE); 
}

EC_BOOL chfsnp_mgr_delete(CHFSNP_MGR *chfsnp_mgr, const CSTRING *path)
{
    CHFSNP *chfsnp;
    uint32_t chfsnp_id;

    chfsnp = __chfsnp_mgr_get_np(chfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_delete: no np for path %s\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return chfsnp_delete(chfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path));
}

/**
*
*   retire up to max_num files where created nsec
*   and return the actual complete num of retired files
*
**/
EC_BOOL chfsnp_mgr_retire_np(CHFSNP_MGR *chfsnp_mgr, const uint32_t chfsnp_id, const UINT32 nsec, const UINT32 expect_num, const UINT32 max_step, UINT32 *complete_num)
{
    CHFSNP  *chfsnp;

    chfsnp = __chfsnp_mgr_get_np_of_id(chfsnp_mgr, chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_retire_np: get np %u failed\n", chfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsnp_retire(chfsnp, nsec, expect_num, max_step, complete_num))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_retire_np: retire np %u failed where nsec %ld, expect num %ld, max step %ld\n",
                    chfsnp_id, nsec, expect_num, max_step);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] chfsnp_mgr_retire_np: retire np %u where nsec %ld done\n", chfsnp_id, nsec);
 
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_recycle_np(CHFSNP_MGR *chfsnp_mgr, const uint32_t chfsnp_id, const UINT32 max_num, CHFSNP_RECYCLE_NP *chfsnp_recycle_np, CHFSNP_RECYCLE_DN *chfsnp_recycle_dn, UINT32 *complete_num)
{
    CHFSNP  *chfsnp;

    chfsnp = __chfsnp_mgr_get_np_of_id(chfsnp_mgr, chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_recycle_np: get np %u failed\n", chfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsnp_recycle(chfsnp, max_num, chfsnp_recycle_np, chfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_recycle_np: recycle np %u failed\n", chfsnp_id);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0065_CHFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] chfsnp_mgr_recycle_np: recycle np %u done\n", chfsnp_id);
 
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_file_num(CHFSNP_MGR *chfsnp_mgr, UINT32 *file_num)
{
    uint32_t chfsnp_id;

    (*file_num) = 0;

    for(chfsnp_id = 0; chfsnp_id < CHFSNP_MGR_NP_MAX_NUM(chfsnp_mgr); chfsnp_id ++)
    {
        CHFSNP*chfsnp;
     
        chfsnp = chfsnp_mgr_open_np(chfsnp_mgr, chfsnp_id);
        if(NULL_PTR == chfsnp)
        {
            dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_file_num: open np %u failed\n", chfsnp_id);
            return (EC_FALSE);
        }
        (*file_num) += chfsnp_count_file_num(chfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_file_size(CHFSNP_MGR *chfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_size)
{
    CHFSNP  *chfsnp;
    uint32_t chfsnp_id;
    uint32_t node_pos;
    uint32_t cur_file_size;

    chfsnp = __chfsnp_mgr_get_np(chfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &chfsnp_id);
    if(NULL_PTR == chfsnp)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_file_size: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    node_pos = chfsnp_file_size(chfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_size);
    if(CHFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0065_CHFSNPMGR, 0)(LOGSTDOUT, "error:chfsnp_mgr_file_size: get size of file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    } 

    (*file_size) = cur_file_size;
 
    return (EC_TRUE); 
}

EC_BOOL chfsnp_mgr_show_cached_np(LOG *log, const CHFSNP_MGR *chfsnp_mgr)
{
    uint32_t chfsnp_num;
    uint32_t chfsnp_pos;

    chfsnp_num = cvector_size(CHFSNP_MGR_NP_VEC(chfsnp_mgr));
    for(chfsnp_pos = 0; chfsnp_pos < chfsnp_num; chfsnp_pos ++)
    {
        CHFSNP *chfsnp;

        chfsnp = CHFSNP_MGR_NP(chfsnp_mgr, chfsnp_pos);
        if(NULL_PTR != chfsnp)
        {
            chfsnp_print(log, chfsnp);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chfsnp_mgr_rdlock(CHFSNP_MGR *chfsnp_mgr, const UINT32 location)
{
    return CHFSNP_MGR_CRWLOCK_RDLOCK(chfsnp_mgr, location);
}

EC_BOOL chfsnp_mgr_wrlock(CHFSNP_MGR *chfsnp_mgr, const UINT32 location)
{
    return CHFSNP_MGR_CRWLOCK_WRLOCK(chfsnp_mgr, location);
}

EC_BOOL chfsnp_mgr_unlock(CHFSNP_MGR *chfsnp_mgr, const UINT32 location)
{
    return CHFSNP_MGR_CRWLOCK_UNLOCK(chfsnp_mgr, location);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

