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

#include "crfsnp.h"
#include "crfsnprb.h"
#include "crfsnpmgr.h"
#include "chashalgo.h"
#include "cmd5.h"
#include "crfsdt.h"
#include "findex.inc"

STATIC_CAST static uint32_t __crfsnp_mgr_path_hash(const uint32_t path_len, const uint8_t *path)
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

CRFSNP_MGR *crfsnp_mgr_new()
{
    CRFSNP_MGR *crfsnp_mgr;

    alloc_static_mem(MM_CRFSNP_MGR, &crfsnp_mgr, LOC_CRFSNPMGR_0001);
    if(NULL_PTR != crfsnp_mgr)
    {
        crfsnp_mgr_init(crfsnp_mgr);
    }

    return (crfsnp_mgr);
}

EC_BOOL crfsnp_mgr_init(CRFSNP_MGR *crfsnp_mgr)
{
    CRFSNP_MGR_CRWLOCK_INIT(crfsnp_mgr, LOC_CRFSNPMGR_0002);
    CRFSNP_MGR_CMUTEX_INIT(crfsnp_mgr, LOC_CRFSNPMGR_0003);

    cstring_init(CRFSNP_MGR_DB_ROOT_DIR(crfsnp_mgr), NULL_PTR);

    CRFSNP_MGR_NP_MODEL(crfsnp_mgr) = CRFSNP_ERR_MODEL;
    CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID(crfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CRFSNP_MGR_NP_ITEM_MAX_NUM(crfsnp_mgr)      = 0;
    CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr)           = 0;

    cvector_init(CRFSNP_MGR_NP_VEC(crfsnp_mgr), 0, MM_CRFSNP, CVECTOR_LOCK_ENABLE, LOC_CRFSNPMGR_0004);

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_clean(CRFSNP_MGR *crfsnp_mgr)
{
    CRFSNP_MGR_CRWLOCK_CLEAN(crfsnp_mgr, LOC_CRFSNPMGR_0005);
    CRFSNP_MGR_CMUTEX_CLEAN(crfsnp_mgr, LOC_CRFSNPMGR_0006);

    cstring_clean(CRFSNP_MGR_DB_ROOT_DIR(crfsnp_mgr));

    CRFSNP_MGR_NP_MODEL(crfsnp_mgr) = CRFSNP_ERR_MODEL;
    CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID(crfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CRFSNP_MGR_NP_ITEM_MAX_NUM(crfsnp_mgr)      = 0;
    CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr)           = 0;

    cvector_clean(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (CVECTOR_DATA_CLEANER)crfsnp_free, LOC_CRFSNPMGR_0007);

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_free(CRFSNP_MGR *crfsnp_mgr)
{
    if(NULL_PTR != crfsnp_mgr)
    {
        crfsnp_mgr_clean(crfsnp_mgr);
        free_static_mem(MM_CRFSNP_MGR, crfsnp_mgr, LOC_CRFSNPMGR_0008);
    }
    return (EC_TRUE);
}

CRFSNP *crfsnp_mgr_open_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id)
{
    CRFSNP *crfsnp;

    crfsnp = (CRFSNP *)cvector_get_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (UINT32)crfsnp_id);
    if(NULL_PTR != crfsnp)
    {
        return (crfsnp);
    }

    crfsnp = crfsnp_open((char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr), crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_open_np: open np %u from %s failed\n", crfsnp_id, (char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr));
        return (NULL_PTR);
    }

    if(NULL_PTR != cvector_set_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (UINT32)(crfsnp_id), (crfsnp)))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_open_np: set np %u to vector but found old existence\n", crfsnp_id);
        return (crfsnp);
    }
    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_open_np: set np %u to vector done\n", crfsnp_id);
    return (crfsnp);
}

EC_BOOL crfsnp_mgr_close_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id)
{
    CRFSNP *crfsnp;

    crfsnp = (CRFSNP *)cvector_get_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (UINT32)crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:crfsnp_mgr_close_np: np %u not open yet\n", crfsnp_id);
        return (EC_TRUE);
    }

    cvector_set_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), crfsnp_id, NULL_PTR);
    crfsnp_close(crfsnp);
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_open_np_all(CRFSNP_MGR *crfsnp_mgr)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);

    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_open_np_all: open np %u from %s failed\n",
                            crfsnp_id, (char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_close_np_all(CRFSNP_MGR *crfsnp_mgr)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);

    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        if(EC_FALSE == crfsnp_mgr_close_np(crfsnp_mgr, crfsnp_id))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_close_np_all: close np %u failed\n",
                            crfsnp_id);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static char *__crfsnp_mgr_gen_db_name(const char *root_dir)
{
    const char *fields[ 2 ];

    fields[ 0 ] = root_dir;
    fields[ 1 ] = CRFSNP_DB_NAME;

    return c_str_join((char *)"/", fields, 2);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_load_db(CRFSNP_MGR *crfsnp_mgr, int crfsnp_mgr_fd)
{
    UINT32 crfsnp_mgr_db_size;
    UINT8* crfsnp_mgr_db_buff;
    UINT32 crfsnp_mgr_db_offset;
    UINT32 crfsnp_id;

    /*init offset*/
    crfsnp_mgr_db_offset = 0;

    /*CRFSNP_MGR_NP_MODEL*/
    crfsnp_mgr_db_size   = sizeof(uint8_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_MODEL(crfsnp_mgr));
    if(EC_FALSE == c_file_load(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_load_db: load np model failed\n");
        return (EC_FALSE);
    }

    /*CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    crfsnp_mgr_db_size   = sizeof(uint8_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID(crfsnp_mgr));
    if(EC_FALSE == c_file_load(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_load_db: load 2nd chash algo id failed\n");
        return (EC_FALSE);
    }

    /*CRFSNP_MGR_NP_ITEM_MAX_NUM*/
    crfsnp_mgr_db_size   = sizeof(uint32_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_ITEM_MAX_NUM(crfsnp_mgr));
    if(EC_FALSE == c_file_load(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_load_db: load item max num failed\n");
        return (EC_FALSE);
    }

    /*CRFSNP_MGR_NP_MAX_NUM*/
    crfsnp_mgr_db_size   = sizeof(uint32_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr));
    if(EC_FALSE == c_file_load(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_load_db: load disk max num failed\n");
        return (EC_FALSE);
    }

    for(crfsnp_id = cvector_size(CRFSNP_MGR_NP_VEC(crfsnp_mgr)); crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        cvector_push_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), NULL_PTR);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_flush_db(CRFSNP_MGR *crfsnp_mgr, int crfsnp_mgr_fd)
{
    UINT32 crfsnp_mgr_db_size;
    UINT8* crfsnp_mgr_db_buff;
    UINT32 crfsnp_mgr_db_offset;

    /*init offset*/
    crfsnp_mgr_db_offset = 0;

    /*CRFSNP_MGR_NP_MODEL*/
    crfsnp_mgr_db_size   = sizeof(uint8_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_MODEL(crfsnp_mgr));
    if(EC_FALSE == c_file_flush(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_flush_db: flush np model failed");
        return (EC_FALSE);
    }

    /*CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID*/
    crfsnp_mgr_db_size   = sizeof(uint8_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID(crfsnp_mgr));
    if(EC_FALSE == c_file_flush(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_flush_db: flush 2nd chash algo id failed");
        return (EC_FALSE);
    }

    /*CRFSNP_MGR_NP_ITEM_MAX_NUM*/
    crfsnp_mgr_db_size   = sizeof(uint32_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_ITEM_MAX_NUM(crfsnp_mgr));
    if(EC_FALSE == c_file_flush(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_flush_db: flush item max num failed");
        return (EC_FALSE);
    }

    /*CRFSNP_MGR_NP_MAX_NUM*/
    crfsnp_mgr_db_size   = sizeof(uint32_t);
    crfsnp_mgr_db_buff   = (UINT8 *)&(CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr));
    if(EC_FALSE == c_file_flush(crfsnp_mgr_fd, &crfsnp_mgr_db_offset, crfsnp_mgr_db_size, crfsnp_mgr_db_buff))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_flush_db: flush disk max num failed");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_load_db(CRFSNP_MGR *crfsnp_mgr)
{
    char  *crfsnp_mgr_db_name;
    int    crfsnp_mgr_fd;

    crfsnp_mgr_db_name = __crfsnp_mgr_gen_db_name((char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr));
    if(NULL_PTR == crfsnp_mgr_db_name)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_load_db: new str %s/%s failed\n",
                            (char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr), CRFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(crfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_load_db: crfsnp mgr db %s not exist\n", crfsnp_mgr_db_name);
        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0009);
        return (EC_FALSE);
    }

    crfsnp_mgr_fd = c_file_open(crfsnp_mgr_db_name, O_RDONLY, 0666);
    if(ERR_FD == crfsnp_mgr_fd)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_load_db: open crfsnp mgr db %s failed\n", crfsnp_mgr_db_name);
        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0010);
        return (EC_FALSE);
    }

    if(EC_FALSE == __crfsnp_mgr_load_db(crfsnp_mgr, crfsnp_mgr_fd))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_load_db: load db from crfsnp mgr db %s\n", crfsnp_mgr_db_name);
        c_file_close(crfsnp_mgr_fd);
        crfsnp_mgr_fd = ERR_FD;

        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0011);
        return (EC_FALSE);
    }

    c_file_close(crfsnp_mgr_fd);
    crfsnp_mgr_fd = ERR_FD;

    safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0012);
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_create_db(CRFSNP_MGR *crfsnp_mgr, const CSTRING *crfsnp_db_root_dir)
{
    char  *crfsnp_mgr_db_name;
    int    crfsnp_mgr_fd;

    crfsnp_mgr_db_name = __crfsnp_mgr_gen_db_name((char *)cstring_get_str(crfsnp_db_root_dir));
    if(NULL_PTR == crfsnp_mgr_db_name)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create_db: new str %s/%s failed\n",
                            (char *)cstring_get_str(crfsnp_db_root_dir), CRFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_TRUE == c_file_access(crfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create_db: crfsnp mgr db %s already exist\n", crfsnp_mgr_db_name);
        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0013);
        return (EC_FALSE);
    }

    crfsnp_mgr_fd = c_file_open(crfsnp_mgr_db_name, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == crfsnp_mgr_fd)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create_db: open crfsnp mgr db %s failed\n", crfsnp_mgr_db_name);
        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0014);
        return (EC_FALSE);
    }

    if(EC_FALSE == __crfsnp_mgr_flush_db(crfsnp_mgr, crfsnp_mgr_fd))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create_db: flush db to crfsnp mgr db %s\n", crfsnp_mgr_db_name);
        c_file_close(crfsnp_mgr_fd);
        crfsnp_mgr_fd = ERR_FD;

        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0015);
        return (EC_FALSE);
    }

    c_file_close(crfsnp_mgr_fd);
    crfsnp_mgr_fd = ERR_FD;

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_create_db: flush db to crfsnp mgr db %s done\n", crfsnp_mgr_db_name);

    safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0016);
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_flush_db(CRFSNP_MGR *crfsnp_mgr)
{
    char  *crfsnp_mgr_db_name;
    int    crfsnp_mgr_fd;

    crfsnp_mgr_db_name = __crfsnp_mgr_gen_db_name((char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr));
    if(NULL_PTR == crfsnp_mgr_db_name)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_flush_db: new str %s/%s failed\n",
                            (char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr), CRFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(crfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_flush_db: crfsnp mgr db %s not exist\n", crfsnp_mgr_db_name);
        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0017);
        return (EC_FALSE);
    }

    crfsnp_mgr_fd = c_file_open(crfsnp_mgr_db_name, O_RDWR, 0666);
    if(ERR_FD == crfsnp_mgr_fd)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_flush_db: open crfsnp mgr db %s failed\n", crfsnp_mgr_db_name);
        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0018);
        return (EC_FALSE);
    }

    if(EC_FALSE == __crfsnp_mgr_flush_db(crfsnp_mgr, crfsnp_mgr_fd))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_flush_db: flush db to crfsnp mgr db %s\n", crfsnp_mgr_db_name);
        c_file_close(crfsnp_mgr_fd);
        crfsnp_mgr_fd = ERR_FD;

        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0019);
        return (EC_FALSE);
    }

    c_file_close(crfsnp_mgr_fd);
    crfsnp_mgr_fd = ERR_FD;

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_flush_db: flush db to crfsnp mgr db %s done\n", crfsnp_mgr_db_name);

    safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0020);
    return (EC_TRUE);
}

void crfsnp_mgr_print_db(LOG *log, const CRFSNP_MGR *crfsnp_mgr)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    sys_log(log, "crfsnp mgr db root dir  : %s\n", (char *)CRFSNP_MGR_DB_ROOT_DIR_STR(crfsnp_mgr));
    sys_log(log, "crfsnp model            : %u\n", CRFSNP_MGR_NP_MODEL(crfsnp_mgr));
    sys_log(log, "crfsnp hash algo id     : %u\n", CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID(crfsnp_mgr));
    sys_log(log, "crfsnp item max num     : %u\n", CRFSNP_MGR_NP_ITEM_MAX_NUM(crfsnp_mgr));
    sys_log(log, "crfsnp max num          : %u\n", CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr));

    crfsnp_num = (uint32_t)cvector_size(CRFSNP_MGR_NP_VEC(crfsnp_mgr));
    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        crfsnp = CRFSNP_MGR_NP(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            sys_log(log, "np %u #: (null)\n", crfsnp_id);
        }
        else
        {
            crfsnp_print(log, crfsnp);
        }
    }
    return;
}

void crfsnp_mgr_print(LOG *log, const CRFSNP_MGR *crfsnp_mgr)
{
    sys_log(log, "crfsnp mgr:\n");
    crfsnp_mgr_print_db(log, crfsnp_mgr);
    return;
}

EC_BOOL crfsnp_mgr_load(CRFSNP_MGR *crfsnp_mgr, const CSTRING *crfsnp_db_root_dir)
{
    cstring_clean(CRFSNP_MGR_DB_ROOT_DIR(crfsnp_mgr));
    cstring_clone(crfsnp_db_root_dir, CRFSNP_MGR_DB_ROOT_DIR(crfsnp_mgr));

    if(EC_FALSE == crfsnp_mgr_load_db(crfsnp_mgr))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_load: load cfg db failed from dir %s\n", (char *)cstring_get_str(crfsnp_db_root_dir));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_sync_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id)
{
    CRFSNP *crfsnp;

    crfsnp = (CRFSNP *)cvector_get_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), crfsnp_id);
    if(NULL_PTR != crfsnp)
    {
        return crfsnp_sync(crfsnp);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_flush(CRFSNP_MGR *crfsnp_mgr)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;
    EC_BOOL ret;

    ret = EC_TRUE;

    if(EC_FALSE == crfsnp_mgr_flush_db(crfsnp_mgr))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_flush: flush cfg db failed\n");
        ret = EC_FALSE;
    }

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);
    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        crfsnp_mgr_sync_np(crfsnp_mgr, crfsnp_id);
    }
    return (ret);
}

EC_BOOL crfsnp_mgr_show_np(LOG *log, CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id)
{
    CRFSNP *crfsnp;

    crfsnp = (CRFSNP *)cvector_get_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        /*try to open the np and print it*/
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_show_np: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }

        crfsnp_print(log, crfsnp);

        crfsnp_mgr_close_np(crfsnp_mgr, crfsnp_id);
    }
    else
    {
        crfsnp_print(log, crfsnp);
    }

    return (EC_TRUE);
}

STATIC_CAST static uint32_t __crfsnp_mgr_get_np_id_of_path(const CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;
    uint32_t hash_val;

    hash_val   = __crfsnp_mgr_path_hash(path_len, path);
    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);
    crfsnp_id  = (hash_val % crfsnp_num);
    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_get_np_id_of_path: hash %u, crfsnp num %u => crfsnp id %u\n", hash_val, crfsnp_num, crfsnp_id);
    return (crfsnp_id);
}

STATIC_CAST static CRFSNP *__crfsnp_mgr_get_np_of_id(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id)
{
    CRFSNP  * crfsnp;

    CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0021);
    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0022);
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_get_np_of_id: cannot open np %u\n", crfsnp_id);
        return (NULL_PTR);
    }
    CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0023);

    return (crfsnp);
}

STATIC_CAST static CRFSNP *__crfsnp_mgr_get_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path, uint32_t *np_id)
{
    CRFSNP  * crfsnp;
    uint32_t  crfsnp_id;

    crfsnp_id = __crfsnp_mgr_get_np_id_of_path(crfsnp_mgr, path_len, path);
    if(CRFSNP_ERR_ID == crfsnp_id)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_get_np: no np for path %.*s\n", path_len, (char *)path);
        return (NULL_PTR);
    }

    CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0024);
    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0025);
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_get_np: path %.*s in np %u but cannot open\n", path_len, path, crfsnp_id);
        return (NULL_PTR);
    }
    CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0026);

    if(NULL_PTR != np_id)
    {
        (*np_id) = crfsnp_id;
    }
    //dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_get_np: path %.*s was in np %u\n", path_len, path, crfsnp_id);

    return (crfsnp);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_search_file(CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_crfsnp_id)
{
    CRFSNP   *crfsnp;
    uint32_t  crfsnp_id;
    uint32_t  node_pos;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, path_len, path, &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_search_file: path %.*s in np %u but cannot open\n", path_len, path, crfsnp_id);
        return (EC_FALSE);
    }

    node_pos = crfsnp_search(crfsnp, path_len, path, dflag);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_search_file: path %.*s in np %u but not found indeed\n", path_len, path, crfsnp_id);
        return (EC_FALSE);
    }

    if(NULL_PTR != searched_crfsnp_id)
    {
        (*searched_crfsnp_id) = crfsnp_id;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_search_dir(CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_crfsnp_id)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);
    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        CRFSNP *crfsnp;
        uint32_t  node_pos;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0027);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0028);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_search_dir: open np %u failed\n", crfsnp_id);
            continue;
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0029);

        node_pos = crfsnp_search(crfsnp, path_len, path, dflag);
        if(CRFSNPRB_ERR_POS == node_pos)
        {
            continue;
        }

        /*found*/
        dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_search_dir: found path %.*s in np %u \n", path_len, path, crfsnp_id);

        if(NULL_PTR != searched_crfsnp_id)
        {
            (*searched_crfsnp_id) = crfsnp_id;
        }

        return (EC_TRUE);/*succ*/
    }

    return (EC_FALSE);
}

EC_BOOL crfsnp_mgr_search(CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_crfsnp_id)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __crfsnp_mgr_search_file(crfsnp_mgr, path_len, path, dflag, searched_crfsnp_id);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __crfsnp_mgr_search_dir(crfsnp_mgr, path_len, path, dflag, searched_crfsnp_id);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_search: path %.*s but dflag %x is not supported\n", path_len, path, dflag);
    return (EC_FALSE);
}

CRFSNP_ITEM *crfsnp_mgr_search_item(CRFSNP_MGR *crfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    CRFSNP   *crfsnp;
    uint32_t  crfsnp_id;
    uint32_t  node_pos;

    CRFSNP_ITEM *crfsnp_item;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, path_len, path, &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_search_item: path %.*s in np %u but cannot open\n", path_len, path, crfsnp_id);
        return (NULL_PTR);
    }

    node_pos = crfsnp_search(crfsnp, path_len, path, dflag);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_search_item: path %.*s in np %u but not found indeed\n", path_len, path, crfsnp_id);
        return (NULL_PTR);
    }

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
    return (crfsnp_item);
}

CRFSNP_MGR *crfsnp_mgr_create(const uint8_t crfsnp_model,
                                const uint32_t crfsnp_max_num,
                                const uint8_t  crfsnp_2nd_chash_algo_id,
                                const CSTRING *crfsnp_db_root_dir)
{
    CRFSNP     *src_crfsnp;
    CRFSNP_MGR *crfsnp_mgr;
    uint32_t crfsnp_item_max_num;
    uint32_t crfsnp_id;

    if(EC_FALSE == crfsnp_model_item_max_num(crfsnp_model , &crfsnp_item_max_num))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create: invalid crfsnp model %u\n", crfsnp_model);
        return (NULL_PTR);
    }

    crfsnp_mgr = crfsnp_mgr_new();

    CRFSNP_MGR_NP_MODEL(crfsnp_mgr)                = crfsnp_model;
    CRFSNP_MGR_NP_2ND_CHASH_ALGO_ID(crfsnp_mgr)    = crfsnp_2nd_chash_algo_id;
    CRFSNP_MGR_NP_ITEM_MAX_NUM(crfsnp_mgr)         = crfsnp_item_max_num;
    CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr)              = crfsnp_max_num;

    cstring_clone(crfsnp_db_root_dir, CRFSNP_MGR_DB_ROOT_DIR(crfsnp_mgr));
    src_crfsnp = NULL_PTR;

    for(crfsnp_id = 0; crfsnp_id < 1/*crfsnp_max_num*/; crfsnp_id ++)
    {
        const char *np_root_dir;
        CRFSNP *crfsnp;

        np_root_dir = (const char *)cstring_get_str(crfsnp_db_root_dir);/*Oops! int the same dir*/
        crfsnp = crfsnp_create(np_root_dir, crfsnp_id, crfsnp_model, crfsnp_2nd_chash_algo_id);
        if(NULL_PTR == crfsnp)
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create: create np %u failed\n", crfsnp_id);
            return (NULL_PTR);
        }

        src_crfsnp = crfsnp;
        /*crfsnp_close(crfsnp);*/

        cvector_push_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (void *)NULL_PTR);
    }

    for(crfsnp_id = /*0*/1; crfsnp_id < crfsnp_max_num; crfsnp_id ++)
    {
        const char *np_root_dir;
        CRFSNP *des_crfsnp;

        np_root_dir = (const char *)cstring_get_str(crfsnp_db_root_dir);/*Oops! int the same dir*/
        des_crfsnp = crfsnp_clone(src_crfsnp, np_root_dir, crfsnp_id);
        if(NULL_PTR == des_crfsnp)
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create: clone np %d -> %u failed\n", (uint32_t)0, crfsnp_id);
            crfsnp_close(src_crfsnp);
            return (NULL_PTR);
        }
        crfsnp_close(des_crfsnp);

        cvector_push_no_lock(CRFSNP_MGR_NP_VEC(crfsnp_mgr), (void *)NULL_PTR);
    }

    if(NULL_PTR != src_crfsnp)
    {
        crfsnp_close(src_crfsnp);
        src_crfsnp = NULL_PTR;
    }

    if(EC_FALSE == crfsnp_mgr_create_db(crfsnp_mgr, crfsnp_db_root_dir))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_create: create cfg db failed in root dir %s\n",
                            (char *)cstring_get_str(crfsnp_db_root_dir));
        crfsnp_mgr_free(crfsnp_mgr);
        return (NULL_PTR);
    }

    //crfsnp_mgr_free(crfsnp_mgr);
    return (crfsnp_mgr);
}

EC_BOOL crfsnp_mgr_exist(const CSTRING *crfsnp_db_root_dir)
{
    char  *crfsnp_mgr_db_name;

    crfsnp_mgr_db_name = __crfsnp_mgr_gen_db_name((char *)cstring_get_str(crfsnp_db_root_dir));
    if(NULL_PTR == crfsnp_mgr_db_name)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_exist: new str %s/%s failed\n",
                            (char *)cstring_get_str(crfsnp_db_root_dir), CRFSNP_DB_NAME);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(crfsnp_mgr_db_name, F_OK))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 7)(LOGSTDOUT, "error:crfsnp_mgr_exist: crfsnp mgr db %s not exist\n", crfsnp_mgr_db_name);
        safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0030);
        return (EC_FALSE);
    }
    safe_free(crfsnp_mgr_db_name, LOC_CRFSNPMGR_0031);
    return (EC_TRUE);
}

CRFSNP_MGR * crfsnp_mgr_open(const CSTRING *crfsnp_db_root_dir)
{
    CRFSNP_MGR *crfsnp_mgr;

    crfsnp_mgr = crfsnp_mgr_new();
    if(NULL_PTR == crfsnp_mgr)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_open: new crfsnp mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == crfsnp_mgr_load(crfsnp_mgr, crfsnp_db_root_dir))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_open: load failed\n");
        crfsnp_mgr_free(crfsnp_mgr);
        return (NULL_PTR);
    }
    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_open: crfsnp mgr loaded from %s\n", (char *)cstring_get_str(crfsnp_db_root_dir));
    return (crfsnp_mgr);
}

EC_BOOL crfsnp_mgr_close(CRFSNP_MGR *crfsnp_mgr)
{
    if(NULL_PTR != crfsnp_mgr)
    {
        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0032);
        crfsnp_mgr_flush(crfsnp_mgr);
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0033);
        crfsnp_mgr_free(crfsnp_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_collect_items(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *crfsnp_item_vec)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);
    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        CRFSNP   *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0034);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0035);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_collect_items: open np %u failed\n", crfsnp_id);
            continue;
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0036);

        crfsnp_collect_items_no_lock(crfsnp, path, dflag, crfsnp_item_vec);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_find_dir(CRFSNP_MGR *crfsnp_mgr, const CSTRING *dir_path)
{
    return __crfsnp_mgr_search_dir(crfsnp_mgr,
                                   (uint32_t)cstring_get_len(dir_path),
                                   cstring_get_str(dir_path),
                                   CRFSNP_ITEM_FILE_IS_DIR,
                                   NULL_PTR);
}

EC_BOOL crfsnp_mgr_find_file(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path)
{
    return __crfsnp_mgr_search_file(crfsnp_mgr,
                                    (uint32_t)cstring_get_len(file_path),
                                    cstring_get_str(file_path),
                                    CRFSNP_ITEM_FILE_IS_REG,
                                    NULL_PTR);
}

EC_BOOL crfsnp_mgr_find(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    if(0 == strcmp("/", (char *)cstring_get_str(path)))/*patch*/
    {
        if(CRFSNP_ITEM_FILE_IS_ANY == dflag || CRFSNP_ITEM_FILE_IS_DIR == dflag)
        {
            return (EC_TRUE);
        }
        return (EC_FALSE);
    }

    return crfsnp_mgr_search(crfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag, NULL_PTR);
}

CRFSNP_FNODE *crfsnp_mgr_reserve(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path)
{
    CRFSNP *crfsnp;
    CRFSNP_ITEM *crfsnp_item;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_reserve: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    crfsnp_item = crfsnp_set(crfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == crfsnp_item)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_reserve: set file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), crfsnp_id);
        return (NULL_PTR);
    }

    if(CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_reserve: file path %s is not regular file\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    CRFSNP_ITEM_CREATE_TIME(crfsnp_item) = task_brd_default_get_time();

    /*not import yet*/
    return CRFSNP_ITEM_FNODE(crfsnp_item);
}

EC_BOOL crfsnp_mgr_release(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path)
{
    CRFSNP *crfsnp;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_release: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_delete(crfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_release: delete file %s from np %u failed\n",
                            (char *)cstring_get_str(file_path), crfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*   retire up to max_num files where created nsec
*   and return the actual complete num of retired files
*
**/
EC_BOOL crfsnp_mgr_retire_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const uint32_t dflag, const UINT32 nsec, const UINT32 expect_num, const UINT32 max_step, UINT32 *complete_num)
{
    CRFSNP  *crfsnp;

    crfsnp = __crfsnp_mgr_get_np_of_id(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_retire_np: get np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_retire(crfsnp, dflag, nsec, expect_num, max_step, complete_num))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_retire_np: retire np %u failed where dflag 0x%x, nsec %ld, expect num %ld, max step %ld\n",
                    crfsnp_id, dflag, nsec, expect_num, max_step);
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_retire_np: retire np %u where dflag 0x%x, nsec %ld done\n", crfsnp_id, dflag, nsec);

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_write(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode)
{
    CRFSNP *crfsnp;
    CRFSNP_ITEM *crfsnp_item;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_write: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    crfsnp_item = crfsnp_set(crfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == crfsnp_item)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_write: set file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), crfsnp_id);
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_write: file path %s is not regular file\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_fnode_import(crfsnp_fnode, CRFSNP_ITEM_FNODE(crfsnp_item)))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_write: import fnode to item failed where path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0009_CRFSNPMGR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfsnp_mgr_write: import fnode to item successfully where path %s\n",
                           (char *)cstring_get_str(file_path));
        crfsnp_item_print(LOGSTDOUT, crfsnp_item);
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_read(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFSNP *crfsnp;
    uint32_t crfsnp_id;
    uint32_t node_pos;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_read: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    node_pos = crfsnp_search_no_lock(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        if(NULL_PTR != crfsnp_fnode)
        {
            crfsnp_fnode_import(CRFSNP_ITEM_FNODE(crfsnp_item), crfsnp_fnode);
        }

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL crfsnp_mgr_update(CRFSNP_MGR *crfsnp_mgr, const CSTRING *file_path, const CRFSNP_FNODE *crfsnp_fnode)
{
    CRFSNP *crfsnp;
    uint32_t crfsnp_id;
    uint32_t node_pos;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_update: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    node_pos = crfsnp_search_no_lock(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        return crfsnp_fnode_import(crfsnp_fnode, CRFSNP_ITEM_FNODE(crfsnp_item));
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_umount_file(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    CRFSNP  *crfsnp;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_umount_file: no np for path %.*s\n",
                           (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_umount_file: crfsnp %p, header %p, %s ...\n",
                        crfsnp, CRFSNP_HDR(crfsnp), (char *)cstring_get_str(path));

    if(EC_FALSE == crfsnp_umount(crfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_umount_file: np %u umount %.*s failed\n",
                            crfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_umount_file: np %u umount %.*s done\n",
                        crfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_umount_dir(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t crfsnp_id;

    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0037);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0038);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_umount_dir: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0039);

        if(EC_FALSE == crfsnp_umount(crfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:__crfsnp_mgr_umount_dir: np %u umount %.*s failed\n",
                                crfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_umount(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __crfsnp_mgr_umount_file(crfsnp_mgr, path, dflag);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __crfsnp_mgr_umount_dir(crfsnp_mgr, path, dflag);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_umount: found invalid dflag 0x%lx before umount %.*s\n",
                        dflag, (uint32_t)cstring_get_len(path), (char *)cstring_get_str(path));
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_umount_file_wildcard(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t crfsnp_id;
    EC_BOOL  ret;

    ret = EC_FALSE;
    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP  *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0040);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0041);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_umount_file_wildcard: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0042);

        if(EC_TRUE == crfsnp_umount_wildcard(crfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_umount_file_wildcard: np %u umount %.*s succ\n",
                                crfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            ret = EC_TRUE;
        }
    }

    /*return true if any np succ*/
    return (ret);
}

STATIC_CAST static EC_BOOL __crfsnp_mgr_umount_dir_wildcard(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t crfsnp_id;

    EC_BOOL  ret;

    ret = EC_FALSE;
    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0043);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0044);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_umount_dir_wildcard: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0045);

        if(EC_TRUE == crfsnp_umount_wildcard(crfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_umount_dir_wildcard: np %u umount %.*s succ\n",
                                crfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            ret = EC_TRUE;
        }
    }

    /*return true if any np succ*/
    return (ret);
}

EC_BOOL crfsnp_mgr_umount_wildcard(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __crfsnp_mgr_umount_file_wildcard(crfsnp_mgr, path, dflag);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __crfsnp_mgr_umount_dir_wildcard(crfsnp_mgr, path, dflag);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_umount_wildcard: found invalid dflag 0x%lx before umount %.*s\n",
                        dflag, (uint32_t)cstring_get_len(path), (char *)cstring_get_str(path));
    return (EC_FALSE);
}


/*note: only support move in same np!*/
STATIC_CAST static EC_BOOL __crfsnp_mgr_move_file(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_src, const CSTRING *path_des, const UINT32 dflag)
{
    CRFSNP  *crfsnp;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path_src), cstring_get_str(path_src), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_move_file: no np for path %.*s\n",
                           (uint32_t)cstring_get_len(path_src), cstring_get_str(path_src));
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_move_file: crfsnp %p, header %p, %s -> %s\n", crfsnp, CRFSNP_HDR(crfsnp), (char *)cstring_get_str(path_src), (char *)cstring_get_str(path_des));

    if(EC_FALSE == crfsnp_move(crfsnp, crfsnp,
                               (uint32_t)cstring_get_len(path_src), cstring_get_str(path_src),
                               (uint32_t)cstring_get_len(path_des), cstring_get_str(path_des),
                               dflag))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_move_file: np %u move %.*s to %.*s failed\n",
                            crfsnp_id,
                            (uint32_t)cstring_get_len(path_src), cstring_get_str(path_src),
                            (uint32_t)cstring_get_len(path_des), cstring_get_str(path_des));
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __crfsnp_mgr_move_file: np %u move %.*s to %.*s done\n",
                        crfsnp_id,
                        (uint32_t)cstring_get_len(path_src), cstring_get_str(path_src),
                        (uint32_t)cstring_get_len(path_des), cstring_get_str(path_des));

    return (EC_TRUE);
}

/*note: only support move in same np!*/
STATIC_CAST static EC_BOOL __crfsnp_mgr_move_dir(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_src, const CSTRING *path_des, const UINT32 dflag)
{
    uint32_t crfsnp_id;

    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0046);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0047);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:__crfsnp_mgr_move_dir: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0048);

        if(EC_FALSE == crfsnp_move(crfsnp,  crfsnp,
                                   (uint32_t)cstring_get_len(path_src), cstring_get_str(path_src),
                                   (uint32_t)cstring_get_len(path_des), cstring_get_str(path_des),
                                   dflag))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:__crfsnp_mgr_move_dir: np %u move %.*s to %.*s failed\n",
                                crfsnp_id,
                                (uint32_t)cstring_get_len(path_src), cstring_get_str(path_src),
                                (uint32_t)cstring_get_len(path_des), cstring_get_str(path_des));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


/*note: here path_des MUST be in /recycle directory !!!*/
EC_BOOL crfsnp_mgr_move(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_src, const CSTRING *path_des, const UINT32 dflag)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __crfsnp_mgr_move_file(crfsnp_mgr, path_src, path_des, dflag);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __crfsnp_mgr_move_dir(crfsnp_mgr, path_src, path_des, dflag);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_move: found invalid dflag 0x%lx before move %.*s to %.*s\n",
                        dflag,
                        (uint32_t)cstring_get_len(path_src), (char *)cstring_get_str(path_src),
                        (uint32_t)cstring_get_len(path_des), (char *)cstring_get_str(path_des));
    return (EC_FALSE);
}

EC_BOOL crfsnp_mgr_mkdir(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path)
{
    CRFSNP *crfsnp;
    CRFSNP_ITEM *crfsnp_item;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &crfsnp_id);;
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_mkdir: no np for path %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    crfsnp_item = crfsnp_set(crfsnp, cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_DIR);
    if(NULL_PTR == crfsnp_item)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_mkdir: mkdir %s in np %u failed\n",
                            (char *)cstring_get_str(path), crfsnp_id);
        return (EC_FALSE);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_mkdir: path %s is not dir in np %u\n", (char *)cstring_get_str(path), crfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_list_path_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const uint32_t crfsnp_id, CVECTOR  *path_cstr_vec)
{
    CRFSNP   *crfsnp;
    CVECTOR  *cur_path_cstr_vec;
    uint32_t  node_pos;

    CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0049);
    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0050);
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_path_of_np: open np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }
    CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0051);

    node_pos = crfsnp_search_no_lock(crfsnp, cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_ANY);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    cur_path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_CRFSNPMGR_0052);
    if(NULL_PTR == cur_path_cstr_vec)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_path_of_np: new cur_path_cstr_vec failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_list_path_vec(crfsnp, node_pos, cur_path_cstr_vec))
    {
        cvector_clean(cur_path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CRFSNPMGR_0053);
        cvector_free(cur_path_cstr_vec, LOC_CRFSNPMGR_0054);

        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_path_of_np: list path %s in np %u failed\n",
                           (char *)cstring_get_str(path), crfsnp_id);
        return (EC_FALSE);
    }

    if(0 < cvector_size(cur_path_cstr_vec))
    {
        /*merge*/
        cvector_merge_direct_no_lock(cur_path_cstr_vec, path_cstr_vec);
    }
    cvector_free(cur_path_cstr_vec, LOC_CRFSNPMGR_0055);

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_list_path(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, CVECTOR  *path_cstr_vec)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);
    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        if(EC_FALSE == crfsnp_mgr_list_path_of_np(crfsnp_mgr, path, crfsnp_id, path_cstr_vec))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_path: list path '%s' of np %u failed\n",
                               (char *)cstring_get_str(path), crfsnp_id);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_list_seg_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, const uint32_t crfsnp_id, CVECTOR  *seg_cstr_vec)
{
    CRFSNP   *crfsnp;
    CVECTOR  *cur_seg_cstr_vec;
    uint32_t  node_pos;

    CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0056);
    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0057);
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_seg_of_np: open np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }
    CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0058);

    node_pos = crfsnp_search_no_lock(crfsnp, cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_ANY);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    cur_seg_cstr_vec = cvector_new(0, MM_CSTRING, LOC_CRFSNPMGR_0059);
    if(NULL_PTR == cur_seg_cstr_vec)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_seg_of_np: new cur_seg_cstr_vec failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_list_seg_vec(crfsnp, node_pos, cur_seg_cstr_vec))
    {
        cvector_clean(cur_seg_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CRFSNPMGR_0060);
        cvector_free(cur_seg_cstr_vec, LOC_CRFSNPMGR_0061);

        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_seg_of_np: list seg of path %s in np %u failed\n",
                           (char *)cstring_get_str(path), crfsnp_id);
        return (EC_FALSE);
    }

    if(0 < cvector_size(cur_seg_cstr_vec))
    {
        /*merge*/
        cvector_merge_direct_no_lock(cur_seg_cstr_vec, seg_cstr_vec);
    }
    cvector_free(cur_seg_cstr_vec, LOC_CRFSNPMGR_0062);

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_list_seg(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path, CVECTOR  *seg_cstr_vec)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);
    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        if(EC_FALSE == crfsnp_mgr_list_seg_of_np(crfsnp_mgr, path, crfsnp_id, seg_cstr_vec))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_list_seg: list path '%s' of np %u failed\n",
                               (char *)cstring_get_str(path), crfsnp_id);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_file_num_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t crfsnp_id, UINT32 *file_num)
{
    CRFSNP *crfsnp;
    uint32_t  node_pos;
    uint32_t  cur_file_num;

    CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0063);
    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0064);
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_num_of_np: open np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }
    CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0065);

    cur_file_num = 0;
    node_pos = crfsnp_file_num(crfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_num);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    (*file_num) += cur_file_num;
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_file_num(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_num)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_id;

    (*file_num) = 0;

    crfsnp_num = CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr);
    for(crfsnp_id = 0; crfsnp_id < crfsnp_num; crfsnp_id ++)
    {
        UINT32  cur_file_num;

        cur_file_num = 0;
        if(EC_FALSE == crfsnp_mgr_file_num_of_np(crfsnp_mgr, path_cstr, crfsnp_id, &cur_file_num))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_num: count file num of path '%s' of np %u failed\n",
                               (char *)cstring_get_str(path_cstr), crfsnp_id);
            return (EC_FALSE);
        }

        (*file_num) += cur_file_num;
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_node_size(CRFSNP_MGR *crfsnp_mgr, CRFSNP *crfsnp, uint32_t node_pos, uint64_t *file_size)
{
    CRFSNPRB_POOL *pool;
    CRFSNPRB_NODE *node;
    CRFSNP_ITEM   *item;

    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CRFSNP_ITEMS_POOL(crfsnp);
    node  = CRFSNPRB_POOL_NODE(pool, node_pos);

    item = (CRFSNP_ITEM *)CRFSNP_RB_NODE_ITEM(node);
    if(CRFSNP_ITEM_FILE_IS_REG == CRFSNP_ITEM_DIR_FLAG(item))
    {
        CRFSNP_FNODE *crfsnp_fnode;
        crfsnp_fnode = CRFSNP_ITEM_FNODE(item);

        (*file_size) += CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    }
    else if(CRFSNP_ITEM_FILE_IS_DIR == CRFSNP_ITEM_DIR_FLAG(item))
    {
        /*skip it, never step down*/
    }
    else
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_node_size: invalid dflg %x\n", CRFSNP_ITEM_DIR_FLAG(item));
        return (EC_FALSE);
    }

    /*run through left subtree*/
    crfsnp_mgr_node_size(crfsnp_mgr, crfsnp, CRFSNPRB_NODE_LEFT_POS(node), file_size);

    /*run through right subtree*/
    crfsnp_mgr_node_size(crfsnp_mgr, crfsnp, CRFSNPRB_NODE_RIGHT_POS(node), file_size);

    return (EC_TRUE);
}

/*total file size under the directory, never search the directory in depth*/
EC_BOOL crfsnp_mgr_dir_size(CRFSNP_MGR *crfsnp_mgr, uint32_t crfsnp_id, const CRFSNP_DNODE *crfsnp_dnode, uint64_t *file_size)
{
    CRFSNP  *crfsnp;
    uint32_t node_pos;

    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_dir_size: open np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    node_pos = CRFSNP_DNODE_ROOT_POS(crfsnp_dnode);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        crfsnp_mgr_node_size(crfsnp_mgr, crfsnp, node_pos, file_size);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_file_size_of_np(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t crfsnp_id, uint64_t *file_size)
{
    CRFSNP *crfsnp;
    uint32_t  node_pos;
    uint64_t  cur_file_size;

    CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0066);
    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0067);
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_size_of_np: open np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }
    CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0068);

    cur_file_size = 0;
    node_pos = crfsnp_file_size(crfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_size);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    (*file_size) += cur_file_size;
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_file_size(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, uint64_t *file_size)
{
    CRFSNP  *crfsnp;
    uint32_t crfsnp_id;
    uint32_t node_pos;
    uint64_t cur_file_size;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_size: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    node_pos = crfsnp_file_size(crfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_size);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_size: get size of file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    (*file_size) = cur_file_size;

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_file_expire(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr)
{
    CRFSNP  *crfsnp;
    uint32_t crfsnp_id;
    uint32_t node_pos;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_expire: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    node_pos = crfsnp_expire(crfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), CRFSNP_ITEM_FILE_IS_REG);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_expire: expire file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_dir_expire(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr)
{
    uint32_t crfsnp_id;

    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0069);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0070);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_dir_expire: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0071);

        if(EC_FALSE == crfsnp_expire(crfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), CRFSNP_ITEM_FILE_IS_DIR))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:crfsnp_mgr_dir_expire: np %u expire %.*s failed\n",
                                crfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_expire(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag)
{
    uint32_t crfsnp_id;

    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0072);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0073);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_expire: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0074);

        if(EC_FALSE == crfsnp_expire(crfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:crfsnp_mgr_expire: np %u expire %.*s failed\n",
                                crfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_file_walk(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    CRFSNP  *crfsnp;
    uint32_t crfsnp_id;
    uint32_t node_pos;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_walk: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    node_pos = crfsnp_walk(crfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), CRFSNP_ITEM_FILE_IS_REG, crfsnp_dit_node);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_walk: walk file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_dir_walk(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    uint32_t crfsnp_id;

    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0075);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0076);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_dir_walk: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0077);

        if(EC_FALSE == crfsnp_walk(crfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), CRFSNP_ITEM_FILE_IS_DIR, crfsnp_dit_node))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:crfsnp_mgr_dir_walk: np %u walk %.*s failed\n",
                                crfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_walk(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    uint32_t crfsnp_id;

    for(crfsnp_id = 0; crfsnp_id < CRFSNP_MGR_NP_MAX_NUM(crfsnp_mgr); crfsnp_id ++)
    {
        CRFSNP *crfsnp;

        CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0078);
        crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
        if(NULL_PTR == crfsnp)
        {
            CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0079);
            dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_walk: open np %u failed\n", crfsnp_id);
            return (EC_FALSE);
        }
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0080);

        if(EC_FALSE == crfsnp_walk(crfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag, crfsnp_dit_node))
        {
            dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:crfsnp_mgr_walk: np %u walk %.*s failed\n",
                                crfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_walk_of_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const CSTRING *path_cstr, const uint32_t dflag, CRFSNP_DIT_NODE *crfsnp_dit_node)
{
    CRFSNP *crfsnp;

    CRFSNP_MGR_CMUTEX_LOCK(crfsnp_mgr, LOC_CRFSNPMGR_0081);
    crfsnp = crfsnp_mgr_open_np(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0082);
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_walk_of_np: open np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }
    CRFSNP_MGR_CMUTEX_UNLOCK(crfsnp_mgr, LOC_CRFSNPMGR_0083);

    if(EC_FALSE == crfsnp_walk(crfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag, crfsnp_dit_node))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 1)(LOGSTDOUT, "warn:crfsnp_mgr_walk_of_np: np %u walk %.*s failed\n",
                            crfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_file_md5sum(CRFSNP_MGR *crfsnp_mgr, const CSTRING *path_cstr, CMD5_DIGEST *md5sum)
{
    CRFSNP  *crfsnp;
    uint32_t crfsnp_id;
    uint32_t node_pos;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_md5sum: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    node_pos = crfsnp_file_md5sum(crfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), md5sum);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_file_md5sum: get md5sum of file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_show_cached_np(LOG *log, const CRFSNP_MGR *crfsnp_mgr)
{
    uint32_t crfsnp_num;
    uint32_t crfsnp_pos;

    crfsnp_num = cvector_size(CRFSNP_MGR_NP_VEC(crfsnp_mgr));
    for(crfsnp_pos = 0; crfsnp_pos < crfsnp_num; crfsnp_pos ++)
    {
        CRFSNP *crfsnp;

        crfsnp = CRFSNP_MGR_NP(crfsnp_mgr, crfsnp_pos);
        if(NULL_PTR != crfsnp)
        {
            crfsnp_print(log, crfsnp);
        }
    }
    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_show_path_depth(LOG *log, CRFSNP_MGR *crfsnp_mgr, const CSTRING *path)
{
    CRFSNP *crfsnp;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_show_path_depth: no np for path %s\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_show_path_depth: crfsnp %p, id %u\n", crfsnp, crfsnp_id);

    return crfsnp_show_path_depth(log, crfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path));
}

EC_BOOL crfsnp_mgr_show_path(LOG *log, CRFSNP_MGR *crfsnp_mgr, const CSTRING *path)
{
    CRFSNP *crfsnp;
    uint32_t crfsnp_id;

    crfsnp = __crfsnp_mgr_get_np(crfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_show_path: no np for path %s\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return crfsnp_show_path(log, crfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path));
}

EC_BOOL crfsnp_mgr_get_first_fname_of_path(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const CSTRING *path, CSTRING *fname, uint32_t *dflag)
{
    CRFSNP  *crfsnp;
    uint8_t *fname_str;

    crfsnp = __crfsnp_mgr_get_np_of_id(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_get_first_fname_of_path: get np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_get_first_fname_of_path(crfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), &fname_str, dflag))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_get_first_fname_of_path: get first fname of path %s from np %u failed\n",
                            (char *)cstring_get_str(path), crfsnp_id);
        return (EC_FALSE);
    }

    cstring_set_str(fname, fname_str);

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_recycle_np(CRFSNP_MGR *crfsnp_mgr, const uint32_t crfsnp_id, const UINT32 max_num, CRFSNP_RECYCLE_NP *crfsnp_recycle_np, CRFSNP_RECYCLE_DN *crfsnp_recycle_dn, UINT32 *complete_num)
{
    CRFSNP  *crfsnp;

    crfsnp = __crfsnp_mgr_get_np_of_id(crfsnp_mgr, crfsnp_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_recycle_np: get np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsnp_recycle(crfsnp, max_num, crfsnp_recycle_np, crfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0009_CRFSNPMGR, 0)(LOGSTDOUT, "error:crfsnp_mgr_recycle_np: recycle np %u failed\n", crfsnp_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CRFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] crfsnp_mgr_recycle_np: recycle np %u done\n", crfsnp_id);

    return (EC_TRUE);
}

EC_BOOL crfsnp_mgr_rdlock(CRFSNP_MGR *crfsnp_mgr, const UINT32 location)
{
    return CRFSNP_MGR_CRWLOCK_RDLOCK(crfsnp_mgr, location);
}

EC_BOOL crfsnp_mgr_wrlock(CRFSNP_MGR *crfsnp_mgr, const UINT32 location)
{
    return CRFSNP_MGR_CRWLOCK_WRLOCK(crfsnp_mgr, location);
}

EC_BOOL crfsnp_mgr_unlock(CRFSNP_MGR *crfsnp_mgr, const UINT32 location)
{
    return CRFSNP_MGR_CRWLOCK_UNLOCK(crfsnp_mgr, location);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

