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
#include "cmisc.h"

#include "real.h"

#include "clist.h"
#include "caio.h"
#include "task.h"

#include "cdsk.h"
#include "crb.h"
#include "crfsdn.h"
#include "cpgrb.h"
#include "cpgb.h"
#include "cpgd.h"
#include "cpgv.h"


/*Random File System Data Node*/
CRFSDN_NODE *crfsdn_node_new()
{
    CRFSDN_NODE *crfsdn_node;

    alloc_static_mem(MM_CRFSDN_NODE, &crfsdn_node, LOC_CRFSDN_0001);
    if(NULL_PTR != crfsdn_node)
    {
        crfsdn_node_init(crfsdn_node);
    }
    return (crfsdn_node);
}

EC_BOOL crfsdn_node_init(CRFSDN_NODE *crfsdn_node)
{
    CRFSDN_NODE_ID(crfsdn_node)             = CRFSDN_NODE_ERR_ID;
    CRFSDN_NODE_FD(crfsdn_node)             = ERR_FD;
    CRFSDN_NODE_ATIME(crfsdn_node)          = 0;

    CRFSDN_NODE_CMUTEX_INIT(crfsdn_node, LOC_CRFSDN_0002);

    return (EC_TRUE);
}

EC_BOOL crfsdn_node_clean(CRFSDN_NODE *crfsdn_node)
{
    if(ERR_FD != CRFSDN_NODE_FD(crfsdn_node))
    {
        c_file_close(CRFSDN_NODE_FD(crfsdn_node));
        CRFSDN_NODE_FD(crfsdn_node) = ERR_FD;
    }

    CRFSDN_NODE_ID(crfsdn_node)             = CRFSDN_NODE_ERR_ID;
    CRFSDN_NODE_ATIME(crfsdn_node)          = 0;

    CRFSDN_NODE_CMUTEX_CLEAN(crfsdn_node, LOC_CRFSDN_0003);

    return (EC_TRUE);
}

EC_BOOL crfsdn_node_free(CRFSDN_NODE *crfsdn_node)
{
    if(NULL_PTR != crfsdn_node)
    {
        crfsdn_node_clean(crfsdn_node);
        free_static_mem(MM_CRFSDN_NODE, crfsdn_node, LOC_CRFSDN_0004);
    }
    return (EC_TRUE);
}

int crfsdn_node_cmp(const CRFSDN_NODE *crfsdn_node_1st, const CRFSDN_NODE *crfsdn_node_2nd)
{
    UINT32 node_id_1st;
    UINT32 node_id_2nd;

    node_id_1st = CRFSDN_NODE_ID(crfsdn_node_1st);
    node_id_2nd = CRFSDN_NODE_ID(crfsdn_node_2nd);

    if(node_id_1st > node_id_2nd)
    {
        return (1);
    }

    if(node_id_1st < node_id_2nd)
    {
        return (-1);
    }

    return (0);
}

void crfsdn_node_print(LOG *log, const CRFSDN_NODE *crfsdn_node)
{
    if(NULL_PTR != crfsdn_node)
    {
        sys_log(log, "crfsdn_node %p: disk %u, block %u, fd %d\n",
                        crfsdn_node,
                        CRFSDN_NODE_DISK_NO(crfsdn_node),
                        CRFSDN_NODE_BLOCK_NO(crfsdn_node),
                        CRFSDN_NODE_FD(crfsdn_node)
                        );
    }

    return;
}

/*for debug only*/
void crfsdn_node_fname_print(LOG *log, const CRFSDN *crfsdn, const UINT32 node_id)
{
    uint16_t       disk_no;
    uint16_t       path_no;

    disk_no = CRFSDN_NODE_ID_GET_DISK_NO(node_id);
    path_no = CRFSDN_NODE_ID_GET_PATH_NO(node_id);

    sys_log(log, "${ROOT}/dsk%03X/%08ld\n",
                disk_no,
                path_no);
    return;
}

STATIC_CAST static EC_BOOL __crfsdn_node_fname_gen(const CRFSDN *crfsdn, const UINT32 node_id, char *path, const UINT32 max_len)
{
    uint16_t       disk_no;
    uint16_t       path_no;

    disk_no = CRFSDN_NODE_ID_GET_DISK_NO(node_id);
    path_no = CRFSDN_NODE_ID_GET_PATH_NO(node_id);

    if(NULL_PTR == CRFSDN_ROOT_DNAME(crfsdn))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:__crfsdn_node_fname_gen: crfsdn %p CRFSDN_ROOT_DNAME is null\n", crfsdn);
        return (EC_FALSE);
    }

    snprintf(path, max_len, "%s/dsk%03X/%08u",
                (char *)CRFSDN_ROOT_DNAME(crfsdn),
                disk_no,
                path_no);
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] __crfsdn_node_fname_gen: node %ld ==> path %s\n", node_id, path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsdn_node_dname_gen(const CRFSDN *crfsdn, const UINT32 node_id, char *path, const UINT32 max_len)
{
    uint16_t       disk_no;
    //uint16_t       block_no;

    disk_no  = CRFSDN_NODE_ID_GET_DISK_NO(node_id);
    //block_no = CRFSDN_NODE_ID_GET_BLOCK_NO(node_id);

    if(NULL_PTR == CRFSDN_ROOT_DNAME(crfsdn))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:__crfsdn_node_dname_gen: crfsdn %p CRFSDN_ROOT_DNAME is null\n", crfsdn);
        return (EC_FALSE);
    }

    snprintf(path, max_len, "%s/dsk%03X",
                (char *)CRFSDN_ROOT_DNAME(crfsdn),
                disk_no
                );
    return (EC_TRUE);
}

CRFSDN_NODE *crfsdn_node_fetch(const CRFSDN *crfsdn, const UINT32 node_id)
{
    CRFSDN_NODE crfsdn_node;
    CRB_NODE   *crb_node;

    CRFSDN_NODE_ID(&crfsdn_node) = (node_id >> CRFSDN_SEG_NO_NBITS);

    crb_node = crb_tree_search_data(CRFSDN_OPEN_NODES(crfsdn), (void *)&crfsdn_node);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    return ((CRFSDN_NODE *)CRB_NODE_DATA(crb_node));
}

EC_BOOL crfsdn_node_delete(CRFSDN *crfsdn, const UINT32 node_id)
{
    CRFSDN_NODE crfsdn_node;

    CRFSDN_NODE_ID(&crfsdn_node) = (node_id >> CRFSDN_SEG_NO_NBITS);
    return crb_tree_delete_data(CRFSDN_OPEN_NODES(crfsdn), (void *)&crfsdn_node);
}

CRFSDN_NODE *crfsdn_node_create(CRFSDN *crfsdn, const UINT32 node_id)
{
    CRFSDN_NODE *crfsdn_node;
    CRB_NODE   *crb_node;

    char path[ CRFSDN_NODE_NAME_MAX_SIZE ];

    crfsdn_node = CRFSDN_OPEN_NODE(crfsdn, node_id);
    if(NULL_PTR != crfsdn_node)
    {
        return (crfsdn_node);
    }

    /*create dir if needed*/
    if(EC_FALSE == __crfsdn_node_dname_gen(crfsdn, node_id, path, CRFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_create: crfsdn%p, generate dname failed\n", crfsdn);
        return (NULL_PTR);
    }

    if(EC_FALSE == c_dir_create(path))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_create: create dir %s failed\n", path);
        return (NULL_PTR);
    }

    /*if file exist, do nothing*/
    if(EC_FALSE == __crfsdn_node_fname_gen(crfsdn, node_id, path, CRFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_create: crfsdn%p, generate fname failed\n", crfsdn);
        return (NULL_PTR);
    }

    if(EC_TRUE == c_file_access(path, F_OK))
    {
        dbg_log(SEC_0024_CRFSDN, 1)(LOGSTDOUT, "warn:crfsdn_node_create: node file %s already exist\n", path);
        return (NULL_PTR);
    }

    crfsdn_node = crfsdn_node_new();
    if(NULL_PTR == crfsdn_node)
    {
        dbg_log(SEC_0024_CRFSDN, 1)(LOGSTDOUT, "warn:crfsdn_node_create: new crfsdn_node failed\n");
        return (NULL_PTR);
    }
    CRFSDN_NODE_ID(crfsdn_node) = (node_id >> CRFSDN_SEG_NO_NBITS);

    CRFSDN_NODE_ATIME(crfsdn_node) = task_brd_get_time(task_brd_default_get());

    /*creat file*/
    CRFSDN_NODE_FD(crfsdn_node) = c_file_open(path, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CRFSDN_NODE_FD(crfsdn_node))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_create: open node file %s failed\n", path);
        crfsdn_node_free(crfsdn_node);
        return (NULL_PTR);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_node_create: create file %s done\n", path);

    /*optimize*/
    if(EC_FALSE == c_file_truncate(CRFSDN_NODE_FD(crfsdn_node), CRFSDN_CACHE_MAX_BYTE_SIZE))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_create: truncate file %s failed\n", path);
        crfsdn_node_free(crfsdn_node);
        return (NULL_PTR);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_node_create: truncate file %s to %ld bytes done\n", path, CRFSDN_CACHE_MAX_BYTE_SIZE);

    crb_node = crb_tree_insert_data(CRFSDN_OPEN_NODES(crfsdn), (void *)crfsdn_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_create: insert new crfsdn_node into open nodes failed\n");
        crfsdn_node_free(crfsdn_node);
        return (NULL_PTR);
    }

    if(CRB_NODE_DATA(crb_node) != (void *)crfsdn_node)
    {
        dbg_log(SEC_0024_CRFSDN, 1)(LOGSTDOUT, "warn:crfsdn_node_create: inserted but crfsdn_node is not the newest one\n");
        crfsdn_node_free(crfsdn_node);
        return ((CRFSDN_NODE *)CRB_NODE_DATA(crb_node));
    }

    return (crfsdn_node);
}

CRFSDN_NODE *crfsdn_node_open(CRFSDN *crfsdn, const UINT32 node_id, const UINT32 open_flags)
{
    CRFSDN_NODE *crfsdn_node;
    CRB_NODE    *crb_node;
    char path[ CRFSDN_NODE_NAME_MAX_SIZE ];

    crfsdn_node = CRFSDN_OPEN_NODE(crfsdn, node_id);
    if(NULL_PTR != crfsdn_node)
    {
        /*update last access time*/
        CRFSDN_NODE_ATIME(crfsdn_node) = task_brd_get_time(task_brd_default_get());
        return (crfsdn_node);
    }

    if(EC_FALSE == __crfsdn_node_fname_gen(crfsdn, node_id, path, CRFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_open: crfsdn%p, generate fname failed\n", crfsdn);
        return (NULL_PTR);
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_node_open: path is %s\n", path);

    /*when node file not exit, then create it and return*/
    if(EC_FALSE == c_file_access(path, F_OK))
    {
        if(open_flags & CRFSDN_NODE_O_CREATE)
        {
            dbg_log(SEC_0024_CRFSDN, 1)(LOGSTDOUT, "warn:crfsdn_node_open: node file %s not exist, try to create it\n", path);
            crfsdn_node = crfsdn_node_create(crfsdn, node_id);
            if(NULL_PTR != crfsdn_node)
            {
                return (crfsdn_node);
            }
        }

        dbg_log(SEC_0024_CRFSDN, 1)(LOGSTDOUT, "warn:crfsdn_node_open: node file %s not exist\n", path);
        return (NULL_PTR);
    }

    crfsdn_node = crfsdn_node_new();
    if(NULL_PTR == crfsdn_node)
    {
        dbg_log(SEC_0024_CRFSDN, 1)(LOGSTDOUT, "warn:crfsdn_node_open: new crfsdn_node failed\n");
        return (NULL_PTR);
    }
    CRFSDN_NODE_ID(crfsdn_node) = (node_id >> CRFSDN_SEG_NO_NBITS);

    /*set/init last access time*/
    CRFSDN_NODE_ATIME(crfsdn_node) = task_brd_get_time(task_brd_default_get());

    /*when node file exit, then open it*/
    if(SWITCH_ON == CRFSDN_CAIO_SWITCH)
    {
        CRFSDN_NODE_FD(crfsdn_node) = c_file_open(path, O_RDWR | O_NONBLOCK, 0666);
        if(ERR_FD == CRFSDN_NODE_FD(crfsdn_node))
        {
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_open: open node file %s failed\n", path);
            crfsdn_node_free(crfsdn_node);
            return (NULL_PTR);
        }

        if(0 != c_file_direct_on(CRFSDN_NODE_FD(crfsdn_node)))
        {
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_open: direct on node file %s failed\n", path);
            crfsdn_node_free(crfsdn_node);
            return (NULL_PTR);
        }
    }
    else
    {
        CRFSDN_NODE_FD(crfsdn_node) = c_file_open(path, O_RDWR, 0666);
        if(ERR_FD == CRFSDN_NODE_FD(crfsdn_node))
        {
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_open: open node file %s failed\n", path);
            crfsdn_node_free(crfsdn_node);
            return (NULL_PTR);
        }
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_node_open: insert node %ld with path %s to open nodes(rbtree)\n", node_id, path);
    crb_node = crb_tree_insert_data(CRFSDN_OPEN_NODES(crfsdn), (void *)crfsdn_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_open: insert new crfsdn_node into open nodes failed\n");
        crfsdn_node_free(crfsdn_node);
        return (NULL_PTR);
    }

    if(CRB_NODE_DATA(crb_node) != (void *)crfsdn_node)
    {
        dbg_log(SEC_0024_CRFSDN, 1)(LOGSTDOUT, "warn:crfsdn_node_open: inserted but crfsdn_node is not the newest one\n");
        crfsdn_node_free(crfsdn_node);
        return ((CRFSDN_NODE *)CRB_NODE_DATA(crb_node));
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_node_open: insert node %ld with path %s to open nodes(rbtree) done\n", node_id, path);

    return (crfsdn_node);
}
#if 0
EC_BOOL crfsdn_node_unlink(CRFSDN *crfsdn, const UINT32 node_id)
{
    char path[ CRFSDN_NODE_NAME_MAX_SIZE ];

    if(EC_FALSE == __crfsdn_node_fname_gen(crfsdn, node_id, path, CRFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_unlink: crfsdn%p, generate fname failed\n", crfsdn);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(path, F_OK))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_unlink: node file %s not exist\n", path);
        return (EC_FALSE);
    }

    if( EC_FALSE == c_file_unlink(path))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_unlink: unlink node file %s failed\n", path);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_node_delete(crfsdn, node_id))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_unlink: delete node from cache failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_node_unlink: unlink node file %s successfully\n", path);
    return (EC_TRUE);
}
#endif

EC_BOOL crfsdn_node_write(CRFSDN *crfsdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset)
{
    CRFSDN_NODE *crfsdn_node;
    UINT32       offset_b; /*real base offset of block in physical file*/
    UINT32       offset_r; /*real offset in physical file*/

    crfsdn_node = crfsdn_node_open(crfsdn, node_id, CRFSDN_NODE_O_CREATE | CRFSDN_NODE_O_RDWR);
    if(NULL_PTR == crfsdn_node)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_write: open node %ld failed\n", node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CRFSDN_NODE_ID_GET_SEG_NO(node_id)) << CPGB_CACHE_BIT_SIZE);
    offset_r = offset_b + (*offset);

    CRFSDN_NODE_CMUTEX_LOCK(crfsdn_node, LOC_CRFSDN_0005);
    if(SWITCH_ON == CRFSDN_CAIO_SWITCH)
    {
        if(EC_FALSE == caio_file_flush(CRFSDN_NODE_FD(crfsdn_node), &offset_r, data_max_len, data_buff))
        {
            CRFSDN_NODE_CMUTEX_UNLOCK(crfsdn_node, LOC_CRFSDN_0006);
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_write: flush %ld bytes to node %ld at offset %ld failed\n",
                                data_max_len, node_id, offset_r);
            return (EC_FALSE);
        }
    }
    else
    {
        if(EC_FALSE == c_file_flush(CRFSDN_NODE_FD(crfsdn_node), &offset_r, data_max_len, data_buff))
        {
            CRFSDN_NODE_CMUTEX_UNLOCK(crfsdn_node, LOC_CRFSDN_0007);
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_write: flush %ld bytes to node %ld at offset %ld failed\n",
                                data_max_len, node_id, offset_r);
            return (EC_FALSE);
        }
    }

    CRFSDN_NODE_CMUTEX_UNLOCK(crfsdn_node, LOC_CRFSDN_0008);

    (*offset) = (offset_r - offset_b);
    return (EC_TRUE);
}

EC_BOOL crfsdn_node_read(CRFSDN *crfsdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset)
{
    CRFSDN_NODE *crfsdn_node;
    UINT32       offset_b; /*real base offset of block in physical file*/
    UINT32       offset_r; /*real offset in physical file*/

    crfsdn_node = crfsdn_node_open(crfsdn, node_id, /*CRFSDN_NODE_O_CREATE | */CRFSDN_NODE_O_RDWR);
    if(NULL_PTR == crfsdn_node)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_read: open node %ld failed\n", node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CRFSDN_NODE_ID_GET_SEG_NO(node_id)) << CPGB_CACHE_BIT_SIZE);
    offset_r = offset_b + (*offset);

    CRFSDN_NODE_CMUTEX_LOCK(crfsdn_node, LOC_CRFSDN_0009);

    if(SWITCH_ON == CRFSDN_CAIO_SWITCH)
    {
        if(EC_FALSE == caio_file_load(CRFSDN_NODE_FD(crfsdn_node), &offset_r, data_max_len, data_buff))
        {
            CRFSDN_NODE_CMUTEX_UNLOCK(crfsdn_node, LOC_CRFSDN_0010);
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_read: AIO load %ld bytes from node %ld at offset %ld failed\n",
                                data_max_len, node_id, offset_r);
            return (EC_FALSE);
        }
    }
    else
    {
        if(EC_FALSE == c_file_load(CRFSDN_NODE_FD(crfsdn_node), &offset_r, data_max_len, data_buff))
        {
            CRFSDN_NODE_CMUTEX_UNLOCK(crfsdn_node, LOC_CRFSDN_0011);
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_node_read: load %ld bytes from node %ld at offset %ld failed\n",
                                data_max_len, node_id, offset_r);
            return (EC_FALSE);
        }
    }

    CRFSDN_NODE_CMUTEX_UNLOCK(crfsdn_node, LOC_CRFSDN_0012);

    (*offset) = (offset_r - offset_b);
    return (EC_TRUE);
}

CRFSDN_CACHE_NODE *crfsdn_cache_node_new()
{
    CRFSDN_CACHE_NODE *crfsdn_cache_node;

    alloc_static_mem(MM_CRFSDN_CACHE_NODE, &crfsdn_cache_node, LOC_CRFSDN_0013);
    if(NULL_PTR != crfsdn_cache_node)
    {
        crfsdn_cache_node_init(crfsdn_cache_node);
    }
    return (crfsdn_cache_node);
}

EC_BOOL crfsdn_cache_node_init(CRFSDN_CACHE_NODE *crfsdn_cache_node)
{
    CRFSDN_CACHE_NODE_DISK_NO(crfsdn_cache_node)   = CPGRB_ERR_POS;
    CRFSDN_CACHE_NODE_BLOCK_NO(crfsdn_cache_node)  = CPGRB_ERR_POS;
    CRFSDN_CACHE_NODE_PAGE_NO(crfsdn_cache_node)   = CPGRB_ERR_POS;
    CRFSDN_CACHE_NODE_DATA_SIZE(crfsdn_cache_node) = 0;
    CRFSDN_CACHE_NODE_DATA_BUFF(crfsdn_cache_node) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL crfsdn_cache_node_clean(CRFSDN_CACHE_NODE *crfsdn_cache_node)
{
    CRFSDN_CACHE_NODE_DISK_NO(crfsdn_cache_node)   = CPGRB_ERR_POS;
    CRFSDN_CACHE_NODE_BLOCK_NO(crfsdn_cache_node)  = CPGRB_ERR_POS;
    CRFSDN_CACHE_NODE_PAGE_NO(crfsdn_cache_node)   = CPGRB_ERR_POS;

    if(NULL_PTR != CRFSDN_CACHE_NODE_DATA_BUFF(crfsdn_cache_node))
    {
        safe_free(CRFSDN_CACHE_NODE_DATA_BUFF(crfsdn_cache_node), LOC_CRFSDN_0014);
        CRFSDN_CACHE_NODE_DATA_BUFF(crfsdn_cache_node) = NULL_PTR;
    }
    CRFSDN_CACHE_NODE_DATA_SIZE(crfsdn_cache_node) = 0;

    return (EC_TRUE);
}

EC_BOOL crfsdn_cache_node_free(CRFSDN_CACHE_NODE *crfsdn_cache_node)
{
    if(NULL_PTR != crfsdn_cache_node)
    {
        crfsdn_cache_node_clean(crfsdn_cache_node);
        free_static_mem(MM_CRFSDN_CACHE_NODE, crfsdn_cache_node, LOC_CRFSDN_0015);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_has_no_cache_node(const CRFSDN *crfsdn)
{
    return clist_is_empty(CRFSDN_CACHED_NODES(crfsdn));
}

EC_BOOL crfsdn_push_cache_node(CRFSDN *crfsdn, CRFSDN_CACHE_NODE *crfsdn_cache_node)
{
    clist_push_back(CRFSDN_CACHED_NODES(crfsdn), (void *)crfsdn_cache_node);
    return (EC_TRUE);
}

CRFSDN_CACHE_NODE *crfsdn_pop_cache_node(CRFSDN *crfsdn)
{
    CRFSDN_CACHE_NODE *crfsdn_cache_node;
    crfsdn_cache_node = (CRFSDN_CACHE_NODE *)clist_pop_front(CRFSDN_CACHED_NODES(crfsdn));
    return (crfsdn_cache_node);
}

EC_BOOL crfsdn_flush_cache_node(CRFSDN *crfsdn, CRFSDN_CACHE_NODE *crfsdn_cache_node)
{
    UINT32 offset;
    uint16_t        disk_no;
    uint16_t        block_no;
    uint16_t        page_no;
    uint32_t        size;
    UINT32          data_size;
    uint8_t        *data_buff;

    disk_no   = CRFSDN_CACHE_NODE_DISK_NO(crfsdn_cache_node);
    block_no  = CRFSDN_CACHE_NODE_BLOCK_NO(crfsdn_cache_node);
    page_no   = CRFSDN_CACHE_NODE_PAGE_NO(crfsdn_cache_node);
    data_size = CRFSDN_CACHE_NODE_DATA_SIZE(crfsdn_cache_node);
    data_buff = CRFSDN_CACHE_NODE_DATA_BUFF(crfsdn_cache_node);

    size = (uint32_t)data_size;
    offset  = (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));

    if(EC_FALSE == crfsdn_write_o(crfsdn, data_size, data_buff, disk_no, block_no, &offset))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_flush_cache_node: write %ld bytes to disk %u block %u page %u failed\n",
                            data_size, (disk_no), (block_no), (page_no));

        cpgv_free_space(CRFSDN_CPGV(crfsdn), disk_no, block_no, page_no, size);
        return (EC_FALSE);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_flush_cache_node: write %ld bytes to disk %u block %u page %u done\n",
                        data_size, (disk_no), (block_no), (page_no));
    return (EC_TRUE);
}

void crfsdn_flush_cache_nodes(CRFSDN **crfsdn, EC_BOOL *terminate_flag)
{
    while(EC_FALSE == (*terminate_flag) && NULL_PTR == (*crfsdn))
    {
        c_usleep(200, LOC_CRFSDN_0016);
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_flush_cache_nodes: [1] terminate_flag %ld, crfsdn %p\n", (*terminate_flag), (*crfsdn));

    while(EC_FALSE == (*terminate_flag) && NULL_PTR != (*crfsdn))
    {
        CRFSDN_CACHE_NODE *crfsdn_cache_node;

        if(EC_TRUE == crfsdn_has_no_cache_node(*crfsdn))
        {
            c_usleep(200, LOC_CRFSDN_0017);
        }

        crfsdn_cache_node = crfsdn_pop_cache_node(*crfsdn);
        if(NULL_PTR != crfsdn_cache_node)
        {
            dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_flush_cache_nodes: [2] terminate_flag %ld, crfsdn %p, crfsdn_cache_node %p\n",
                                (*terminate_flag), (*crfsdn), crfsdn_cache_node);
            crfsdn_flush_cache_node(*crfsdn, crfsdn_cache_node);
            crfsdn_cache_node_free(crfsdn_cache_node);
        }
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_flush_cache_nodes: [3] terminate_flag %ld, crfsdn %p\n", (*terminate_flag), (*crfsdn));

    return;
}

STATIC_CAST static EC_BOOL __crfsdn_collect_expired_node(const CRFSDN_NODE *crfsdn_node, CLIST *expired_node_list)
{
    ctime_t     cur_time;

    cur_time = task_brd_get_time(task_brd_default_get());

    /*expired*/
    if(cur_time > CRFSDN_NODE_ATIME(crfsdn_node) + CRFSDN_EXPIRED_IN_NSEC)
    {
        clist_push_back_no_lock(expired_node_list, (void *)crfsdn_node);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_expire_open_nodes(CRFSDN *crfsdn)
{
    CLIST *expired_node_list;

    ctime_t     cur_time;

    cur_time = task_brd_get_time(task_brd_default_get());

    expired_node_list = clist_new(MM_CRFSDN_NODE, LOC_CRFSDN_0018);
    if(NULL_PTR == expired_node_list)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_expire_open_nodes: new clist failed\n");
        return (EC_FALSE);
    }

    /*collect open expired nodes*/
    crb_inorder_walk(CRFSDN_OPEN_NODES(crfsdn), (CRB_DATA_HANDLE)__crfsdn_collect_expired_node, expired_node_list);

    while(EC_FALSE == clist_is_empty_no_lock(expired_node_list))
    {
        CRFSDN_NODE *crfsdn_node;

        crfsdn_node = (CRFSDN_NODE *)clist_pop_front_no_lock(expired_node_list);
        if(NULL_PTR != crfsdn_node)
        {
            CTM   *cur_tm;
            CTM   *last_tm;

            cur_tm  = c_localtime_r(&cur_time);
            last_tm = c_localtime_r(&CRFSDN_NODE_ATIME(crfsdn_node));
            dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_expire_open_nodes: expire crfsdn_node %ld (%p) where "
                               "last access time %4d-%02d-%02d %02d:%02d:%02d, "
                               "current time %4d-%02d-%02d %02d:%02d:%02d\n",
                               CRFSDN_NODE_ID(crfsdn_node), crfsdn_node,
                               TIME_IN_YMDHMS(last_tm),
                               TIME_IN_YMDHMS(cur_tm));

            crb_tree_delete_data(CRFSDN_OPEN_NODES(crfsdn), (void *)crfsdn_node);
        }
    }

    clist_free_no_lock(expired_node_list, LOC_CRFSDN_0019);

    return (EC_TRUE);
}

STATIC_CAST static char * __crfsdn_vol_fname_gen(const char *root_dname)
{
    const char *field[ 2 ];
    char       *vol_fname;

    field[ 0 ] = root_dname;
    field[ 1 ] = CRFSDN_DB_NAME;

    vol_fname = c_str_join("/", field, 2);/*${root_dname}/${vol_basename}*/
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_vol_fname_gen: make vol_fname %s/%s failed\n", root_dname, CRFSDN_DB_NAME);
        return (NULL_PTR);
    }

    return (vol_fname);
}

CRFSDN *crfsdn_create(const char *root_dname)
{
    CRFSDN *crfsdn;
    uint8_t *vol_fname;

    crfsdn = crfsdn_new();
    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_create: new crfsdn failed\n");
        return (NULL_PTR);
    }

    CRFSDN_ROOT_DNAME(crfsdn) = (uint8_t *)c_str_dup(root_dname);
    if(NULL_PTR == CRFSDN_ROOT_DNAME(crfsdn))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_create: dup root_dname %s failed\n", root_dname);
        crfsdn_free(crfsdn);
        return (NULL_PTR);
    }

    vol_fname = (uint8_t *)__crfsdn_vol_fname_gen((char *)CRFSDN_ROOT_DNAME(crfsdn));
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_create: make vol_fname from root_dname %s failed\n", root_dname);
        crfsdn_free(crfsdn);
        return (NULL_PTR);
    }

    CRFSDN_CPGV(crfsdn) = cpgv_new((uint8_t *)vol_fname);
    if(NULL_PTR == CRFSDN_CPGV(crfsdn))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_create: new vol %s failed\n", vol_fname);
        crfsdn_free(crfsdn);
        safe_free(vol_fname, LOC_CRFSDN_0020);
        return (NULL_PTR);
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_create: vol %s was created\n", vol_fname);
    safe_free(vol_fname, LOC_CRFSDN_0021);

    if(EC_FALSE == crfsdn_flush(crfsdn))/*xxx*/
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_create:flush dn failed\n");
        crfsdn_free(crfsdn);
        return (NULL_PTR);
    }

    return (crfsdn);
}

EC_BOOL crfsdn_add_disk(CRFSDN *crfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == cpgv_add_disk(CRFSDN_CPGV(crfsdn), disk_no))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_add_disk: cpgv add disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_flush(crfsdn))/*xxx*/
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_add_disk: flush dn failed after add disk %u \n", disk_no);
        cpgv_del_disk(CRFSDN_CPGV(crfsdn), disk_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_del_disk(CRFSDN *crfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == cpgv_del_disk(CRFSDN_CPGV(crfsdn), disk_no))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_del_disk: cpgv del disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_flush(crfsdn))/*xxx*/
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_del_disk: flush dn failed after del disk %u \n", disk_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_mount_disk(CRFSDN *crfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == cpgv_mount_disk(CRFSDN_CPGV(crfsdn), disk_no))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_mount_disk: cpgv mount disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_flush(crfsdn))/*xxx*/
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_mount_disk: flush dn failed after mount disk %u \n", disk_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_umount_disk(CRFSDN *crfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == cpgv_umount_disk(CRFSDN_CPGV(crfsdn), disk_no))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_umount_disk: cpgv umount disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_flush(crfsdn))/*xxx*/
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_umount_disk: flush dn failed after umount disk %u \n", disk_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}


CRFSDN *crfsdn_new()
{
    CRFSDN *crfsdn;

    alloc_static_mem(MM_CRFSDN, &crfsdn, LOC_CRFSDN_0022);
    if(NULL_PTR != crfsdn)
    {
        crfsdn_init(crfsdn);
        return (crfsdn);
    }
    return (crfsdn);
}

EC_BOOL crfsdn_init(CRFSDN *crfsdn)
{
    crb_tree_init(CRFSDN_OPEN_NODES(crfsdn),
                  (CRB_DATA_CMP  )crfsdn_node_cmp,
                  (CRB_DATA_FREE )crfsdn_node_free,
                  (CRB_DATA_PRINT)crfsdn_node_print);
    clist_init(CRFSDN_CACHED_NODES(crfsdn), MM_CRFSDN_CACHE_NODE, LOC_CRFSDN_0023);

    CRFSDN_ROOT_DNAME(crfsdn)  = NULL_PTR;
    CRFSDN_CPGV(crfsdn)        = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL crfsdn_clean(CRFSDN *crfsdn)
{
    crb_tree_clean(CRFSDN_OPEN_NODES(crfsdn));

    if(NULL_PTR != CRFSDN_ROOT_DNAME(crfsdn))
    {
        safe_free(CRFSDN_ROOT_DNAME(crfsdn), LOC_CRFSDN_0024);
        CRFSDN_ROOT_DNAME(crfsdn) = NULL_PTR;
    }

    if(NULL_PTR != CRFSDN_CPGV(crfsdn))
    {
        cpgv_close(CRFSDN_CPGV(crfsdn));
        CRFSDN_CPGV(crfsdn) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL crfsdn_free(CRFSDN *crfsdn)
{
    if(NULL_PTR != crfsdn)
    {
        crfsdn_clean(crfsdn);
        free_static_mem(MM_CRFSDN, crfsdn, LOC_CRFSDN_0025);
    }
    return (EC_TRUE);
}

void crfsdn_print(LOG *log, const CRFSDN *crfsdn)
{
    if(NULL_PTR != crfsdn)
    {
        sys_log(log, "crfsdn_print: crfsdn %p: root dname: %s\n", crfsdn, (char *)CRFSDN_ROOT_DNAME(crfsdn));

        cpgv_print(log, CRFSDN_CPGV(crfsdn));
        if(0)
        {
            sys_log(log, "crfsdn_print: crfsdn %p: cached nodes: \n", crfsdn);
            crb_tree_print(log, CRFSDN_OPEN_NODES(crfsdn));
        }
    }
    return;
}

EC_BOOL crfsdn_is_full(CRFSDN *crfsdn)
{
    return cpgv_is_full(CRFSDN_CPGV(crfsdn));
}

EC_BOOL crfsdn_flush(CRFSDN *crfsdn)
{
    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_flush: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cpgv_sync(CRFSDN_CPGV(crfsdn)))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_flush: sync cpgv failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_load(CRFSDN *crfsdn, const char *root_dname)
{
    uint8_t *vol_fname;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_load: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CRFSDN_CPGV(crfsdn))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_load: CRFSDN_CPGV is not null\n");
        return (EC_FALSE);
    }

    CRFSDN_ROOT_DNAME(crfsdn) = (uint8_t *)c_str_dup(root_dname);
    if(NULL_PTR == CRFSDN_ROOT_DNAME(crfsdn))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_load: dup root_dname %s failed\n", root_dname);
        return (EC_FALSE);
    }

    vol_fname = (uint8_t *)__crfsdn_vol_fname_gen((char *)CRFSDN_ROOT_DNAME(crfsdn));
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_load: make vol_fname from root_dname %s failed\n", (char *)CRFSDN_ROOT_DNAME(crfsdn));
        return (EC_FALSE);
    }

    CRFSDN_CPGV(crfsdn) = cpgv_open(vol_fname);
    if(NULL_PTR == CRFSDN_CPGV(crfsdn))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_load: load/open vol from %s failed\n", (char *)vol_fname);
        safe_free(vol_fname, LOC_CRFSDN_0026);
        return (EC_FALSE);
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_load: load/open vol from %s done\n", (char *)vol_fname);
    safe_free(vol_fname, LOC_CRFSDN_0027);

    return (EC_TRUE);
}

EC_BOOL crfsdn_exist(const char *root_dname)
{
    char *vol_fname;

    vol_fname = __crfsdn_vol_fname_gen(root_dname);
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_exist: make vol_fname from root_dname %s failed\n", root_dname);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(vol_fname, F_OK))
    {
        dbg_log(SEC_0024_CRFSDN, 7)(LOGSTDOUT, "error:crfsdn_exist: vol file %s not exist\n", vol_fname);
        safe_free(vol_fname, LOC_CRFSDN_0028);
        return (EC_FALSE);
    }

    safe_free(vol_fname, LOC_CRFSDN_0029);
    return (EC_TRUE);
}

CRFSDN *crfsdn_open(const char *root_dname)
{
    CRFSDN *crfsdn;

    if(NULL_PTR == root_dname)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_open: root dir is null\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == c_dir_exist(root_dname))
    /*if(EC_FALSE == c_file_access(root_dname, F_OK))*/
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_open: root dir %s not exist\n", root_dname);
        return (NULL_PTR);
    }

    crfsdn = crfsdn_new();
    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_open: new crfsdn with root dir %s failed\n", root_dname);
        return (NULL_PTR);
    }

    if(EC_FALSE == crfsdn_load(crfsdn, root_dname))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_open: load crfsdn from root dir %s failed\n", root_dname);
        crfsdn_free(crfsdn);
        return (NULL_PTR);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_open: load crfsdn from root dir %s done\n", root_dname);

    return (crfsdn);
}

EC_BOOL crfsdn_close(CRFSDN *crfsdn)
{
    if(NULL_PTR != crfsdn)
    {
        crfsdn_flush(crfsdn);
        crfsdn_free(crfsdn);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_fetch_block_fd(CRFSDN *crfsdn, const uint16_t disk_no, const uint16_t block_no, int *block_fd)
{
    UINT32 node_id;

    CRFSDN_NODE *crfsdn_node;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_fetch_block_fd: crfsdn is null\n");
        return (EC_FALSE);
    }

    node_id = CRFSDN_NODE_ID_MAKE(disk_no, block_no);

    crfsdn_node = crfsdn_node_open(crfsdn, node_id, CRFSDN_NODE_O_RDWR);
    if(NULL_PTR == crfsdn_node)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_fetch_block_fd: open node %ld failed\n", node_id);
        return (EC_FALSE);
    }

    (*block_fd) = CRFSDN_NODE_FD(crfsdn_node);

    return (EC_TRUE);
}

/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL crfsdn_read_o(CRFSDN *crfsdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_o: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE <= offset)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_o: offset %ld overflow\n", offset);
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < offset + data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_o: offset %ld + data_max_len %ld = %ld overflow\n",
                            offset, data_max_len, offset + data_max_len);
        return (EC_FALSE);
    }

    node_id = CRFSDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = offset;
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_read_o: disk %u, block %u  ==> node %ld, start\n", disk_no, block_no, node_id);
    if(EC_FALSE == crfsdn_node_read(crfsdn, node_id, data_max_len, data_buff, &offset_t))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_o: read %ld bytes at offset %ld from node %ld failed\n",
                           data_max_len, offset, node_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_read_o: disk %u, block %u  ==> node %ld, end\n", disk_no, block_no, node_id);

    if(NULL_PTR != data_len)
    {
        (*data_len) = offset_t - offset;
    }

    return (EC_TRUE);
}

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL crfsdn_write_o(CRFSDN *crfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_o: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    node_id  = CRFSDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = (*offset);

    if(EC_FALSE == crfsdn_node_write(crfsdn, node_id, data_max_len, data_buff, offset))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_o: write %ld bytes to disk %u block %u offset %ld failed\n",
                            data_max_len, disk_no, block_no, offset_t);

        return (EC_FALSE);
    }

    //dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_write_o: write %ld bytes to disk %u block %u offset %ld done\n",
    //                    data_max_len, disk_no, block_no, offset_t);

    return (EC_TRUE);
}

EC_BOOL crfsdn_read_b(CRFSDN *crfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_b: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_b: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_b: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    ASSERT(0 == page_no);

    offset  = (((UINT32)page_no) << (CPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == crfsdn_read_o(crfsdn, disk_no, block_no, offset, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_b: read %ld bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_write_b(CRFSDN *crfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, UINT32 *offset)
{
    uint32_t size;
    uint16_t page_no;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_b: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_b: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len + (*offset))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_b: data max len %ld + offset %ld = %ld overflow\n",
                           data_max_len, (*offset), data_max_len + (*offset));
        return (EC_FALSE);
    }

    size = CPGB_CACHE_MAX_BYTE_SIZE;

    if(EC_FALSE == cpgv_new_space(CRFSDN_CPGV(crfsdn), size, disk_no, block_no, &page_no))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_b: new %ld bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }
    ASSERT(0 == page_no);

    if(EC_FALSE == crfsdn_write_o(crfsdn, data_max_len, data_buff, *disk_no, *block_no, offset))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_b: write %ld bytes to disk %u block %u page %u failed\n",
                            data_max_len, (*disk_no), (*block_no), (page_no));

        cpgv_free_space(CRFSDN_CPGV(crfsdn), *disk_no, *block_no, page_no, size);
        return (EC_FALSE);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_write_b: write %ld bytes to disk %u block %u page %u done\n",
                        data_max_len, (*disk_no), (*block_no), (page_no));

    return (EC_TRUE);
}

EC_BOOL crfsdn_update_b(CRFSDN *crfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset)
{
    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_update_b: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_update_b: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len + (*offset))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_update_b: data max len %ld + offset %ld = %ld overflow\n",
                           data_max_len, (*offset), data_max_len + (*offset));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdn_write_o(crfsdn, data_max_len, data_buff, disk_no, block_no, offset))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_update_b: write %ld bytes to disk %u block %u failed\n",
                            data_max_len, disk_no, block_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_update_b: write %ld bytes to disk %u block %u done\n",
                        data_max_len, disk_no, block_no);

    return (EC_TRUE);
}

EC_BOOL crfsdn_read_p(CRFSDN *crfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_p: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)page_no) << (CPGB_PAGE_BIT_SIZE));
    //dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_read_p: disk %u, block %u, page %u ==> offset %ld\n", disk_no, block_no, page_no, offset);
    if(EC_FALSE == crfsdn_read_o(crfsdn, disk_no, block_no, offset, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_p: read %ld bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_write_p(CRFSDN *crfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    UINT32   offset;
    uint32_t size;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    if(EC_FALSE == cpgv_new_space(CRFSDN_CPGV(crfsdn), size, disk_no, block_no,  page_no))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p: new %ld bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)(*page_no)) << (CPGB_PAGE_BIT_SIZE));

    if(EC_FALSE == crfsdn_write_o(crfsdn, data_max_len, data_buff, *disk_no, *block_no, &offset))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p: write %ld bytes to disk %u block %u page %u failed\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));

        cpgv_free_space(CRFSDN_CPGV(crfsdn), *disk_no, *block_no, *page_no, size);
        return (EC_FALSE);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_write_p: write %ld bytes to disk %u block %u page %u done\n",
                        data_max_len, (*disk_no), (*block_no), (*page_no));

    return (EC_TRUE);
}

EC_BOOL crfsdn_write_p_cache(CRFSDN *crfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CRFSDN_CACHE_NODE *crfsdn_cache_node;
    uint8_t           *data_buff_t;
    uint32_t size;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p_cache: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p_cache: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    if(EC_FALSE == cpgv_new_space(CRFSDN_CPGV(crfsdn), size, disk_no, block_no,  page_no))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p_cache: new %ld bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }

    crfsdn_cache_node = crfsdn_cache_node_new();
    if(NULL_PTR == crfsdn_cache_node)/*try all best*/
    {
        UINT32 offset;

        offset  = (((UINT32)(*page_no)) << (CPGB_PAGE_BIT_SIZE));

        if(EC_FALSE == crfsdn_write_o(crfsdn, data_max_len, data_buff, *disk_no, *block_no, &offset))
        {
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p_cache: write %ld bytes to disk %u block %u page %u failed\n",
                                data_max_len, (*disk_no), (*block_no), (*page_no));

            cpgv_free_space(CRFSDN_CPGV(crfsdn), *disk_no, *block_no, *page_no, size);
            return (EC_FALSE);
        }
        dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_write_p_cache: write %ld bytes to disk %u block %u page %u done\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));
        return (EC_TRUE);
    }

    data_buff_t = safe_malloc(data_max_len, LOC_CRFSDN_0030);
    if(NULL_PTR == data_buff_t)/*try all best*/
    {
        UINT32 offset;

        crfsdn_cache_node_free(crfsdn_cache_node);

        offset  = (((UINT32)(*page_no)) << (CPGB_PAGE_BIT_SIZE));

        if(EC_FALSE == crfsdn_write_o(crfsdn, data_max_len, data_buff, *disk_no, *block_no, &offset))
        {
            dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_p_cache: write %ld bytes to disk %u block %u page %u failed\n",
                                data_max_len, (*disk_no), (*block_no), (*page_no));

            cpgv_free_space(CRFSDN_CPGV(crfsdn), *disk_no, *block_no, *page_no, size);
            return (EC_FALSE);
        }
        dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_write_p_cache: write %ld bytes to disk %u block %u page %u done\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));
        return (EC_TRUE);
    }

    /*clone data*/
    BCOPY(data_buff, data_buff_t, data_max_len);

    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_write_p_cache: write %ld bytes to disk %u block %u page %u done\n",
                        data_max_len, (*disk_no), (*block_no), (*page_no));

    CRFSDN_CACHE_NODE_DISK_NO(crfsdn_cache_node)   = (*disk_no);
    CRFSDN_CACHE_NODE_BLOCK_NO(crfsdn_cache_node)  = (*block_no);
    CRFSDN_CACHE_NODE_PAGE_NO(crfsdn_cache_node)   = (*page_no);
    CRFSDN_CACHE_NODE_DATA_SIZE(crfsdn_cache_node) = data_max_len;
    CRFSDN_CACHE_NODE_DATA_BUFF(crfsdn_cache_node) = data_buff_t;

    crfsdn_push_cache_node(crfsdn, crfsdn_cache_node);

    return (EC_TRUE);
}

/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL crfsdn_read_e(CRFSDN *crfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CPGB_PAGE_BIT_SIZE)) + offset;
    if(EC_FALSE == crfsdn_read_o(crfsdn, disk_no, block_no, offset_t, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_read_e: read %ld bytes from disk %u block %u page %u offset %u failed\n",
                           data_max_len, disk_no, block_no, page_no, offset);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL crfsdn_write_e(CRFSDN *crfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CPGB_PAGE_BIT_SIZE)) + offset;
    if(EC_FALSE == crfsdn_write_o(crfsdn, data_max_len, data_buff, disk_no, block_no, &offset_t))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_write_e: write %ld bytes to disk %u block %u page %u offset %ld failed\n",
                           data_max_len, disk_no, block_no, page_no, offset_t);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdn_remove(CRFSDN *crfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len)
{
    uint32_t size;

    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_remove: crfsdn is null\n");
        return (EC_FALSE);
    }

    if(CPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_remove: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    if(EC_FALSE == cpgv_free_space(CRFSDN_CPGV(crfsdn), disk_no, block_no, page_no, size))
    {
        dbg_log(SEC_0024_CRFSDN, 0)(LOGSTDOUT, "error:crfsdn_remove: free %ld bytes space to vol failed\n", data_max_len);
        return (EC_FALSE);
    }
    dbg_log(SEC_0024_CRFSDN, 9)(LOGSTDOUT, "[DEBUG] crfsdn_remove: free %ld bytes to disk %u block %u page %u done\n",
                        data_max_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}


EC_BOOL crfsdn_show(LOG *log, const char *root_dir)
{
    CRFSDN *crfsdn;

    crfsdn = crfsdn_open(root_dir);
    if(NULL_PTR == crfsdn)
    {
        sys_log(log, "error:crfsdn_show: open crfsdn %s failed\n", root_dir);
        return (EC_FALSE);
    }

    crfsdn_print(log, crfsdn);

    crfsdn_close(crfsdn);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

