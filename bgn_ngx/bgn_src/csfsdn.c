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

#include "task.h"

#include "csfsdn.h"
#include "csfsv.h"
#include "csfsd.h"
#include "csfsb.h"


/*Random File System Data Node*/
CSFSDN_NODE *csfsdn_node_new()
{
    CSFSDN_NODE *csfsdn_node;

    alloc_static_mem(MM_CSFSDN_NODE, &csfsdn_node, LOC_CSFSDN_0001);
    if(NULL_PTR != csfsdn_node)
    {
        csfsdn_node_init(csfsdn_node);
    }
    return (csfsdn_node);
}

EC_BOOL csfsdn_node_init(CSFSDN_NODE *csfsdn_node)
{
    CSFSDN_NODE_ID(csfsdn_node)             = CSFSDN_NODE_ERR_ID;
    CSFSDN_NODE_FD(csfsdn_node)             = ERR_FD;
    CSFSDN_NODE_ATIME(csfsdn_node)          = 0;

    CSFSDN_NODE_CMUTEX_INIT(csfsdn_node, LOC_CSFSDN_0002);

    return (EC_TRUE);
}

EC_BOOL csfsdn_node_clean(CSFSDN_NODE *csfsdn_node)
{
    if(ERR_FD != CSFSDN_NODE_FD(csfsdn_node))
    {
        c_file_close(CSFSDN_NODE_FD(csfsdn_node));
        CSFSDN_NODE_FD(csfsdn_node) = ERR_FD;
    }

    CSFSDN_NODE_ID(csfsdn_node)             = CSFSDN_NODE_ERR_ID;
    CSFSDN_NODE_ATIME(csfsdn_node)          = 0;

    CSFSDN_NODE_CMUTEX_CLEAN(csfsdn_node, LOC_CSFSDN_0003);
 
    return (EC_TRUE);
}

EC_BOOL csfsdn_node_free(CSFSDN_NODE *csfsdn_node)
{
    if(NULL_PTR != csfsdn_node)
    {
        csfsdn_node_clean(csfsdn_node);
        free_static_mem(MM_CSFSDN_NODE, csfsdn_node, LOC_CSFSDN_0004);
    }
    return (EC_TRUE);
}

int csfsdn_node_cmp(const CSFSDN_NODE *csfsdn_node_1st, const CSFSDN_NODE *csfsdn_node_2nd)
{
    UINT32 node_id_1st;
    UINT32 node_id_2nd;

    node_id_1st = CSFSDN_NODE_ID(csfsdn_node_1st);
    node_id_2nd = CSFSDN_NODE_ID(csfsdn_node_2nd);

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

void csfsdn_node_print(LOG *log, const CSFSDN_NODE *csfsdn_node)
{
    if(NULL_PTR != csfsdn_node)
    {
        sys_log(log, "csfsdn_node %p: disk %u, block %u, fd %d\n",
                        csfsdn_node,
                        CSFSDN_NODE_DISK_NO(csfsdn_node),
                        CSFSDN_NODE_BLOCK_NO(csfsdn_node),
                        CSFSDN_NODE_FD(csfsdn_node)
                        );
    }

    return;
}

/*for debug only*/
void csfsdn_node_fname_print(LOG *log, const CSFSDN *csfsdn, const UINT32 node_id)
{
    UINT32       disk_no;
    UINT32       path_no;

    disk_no = CSFSDN_NODE_ID_GET_DISK_NO(node_id);
    path_no = CSFSDN_NODE_ID_GET_PATH_NO(node_id);

    sys_log(log, "${ROOT}/dsk%ld/%08ld\n",
                disk_no,
                path_no);
    return;
}

static EC_BOOL __csfsdn_node_fname_gen(const CSFSDN *csfsdn, const UINT32 node_id, char *path, const UINT32 max_len)
{
    UINT32       disk_no;
    UINT32       path_no;

    disk_no = CSFSDN_NODE_ID_GET_DISK_NO(node_id);
    path_no = CSFSDN_NODE_ID_GET_PATH_NO(node_id);

    if(NULL_PTR == CSFSDN_ROOT_DNAME(csfsdn))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:__csfsdn_node_fname_gen: csfsdn %p CSFSDN_ROOT_DNAME is null\n", csfsdn);
        return (EC_FALSE);
    }
 
    snprintf(path, max_len, "%s/dsk%ld/%08ld",
                (char *)CSFSDN_ROOT_DNAME(csfsdn),
                disk_no,
                path_no);
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] __csfsdn_node_fname_gen: node %u ==> path %s\n", node_id, path);
    return (EC_TRUE);
}

static EC_BOOL __csfsdn_node_dname_gen(const CSFSDN *csfsdn, const UINT32 node_id, char *path, const UINT32 max_len)
{
    UINT32       disk_no;
    UINT32       block_no;

    disk_no  = CSFSDN_NODE_ID_GET_DISK_NO(node_id);
    block_no = CSFSDN_NODE_ID_GET_BLOCK_NO(node_id);

    if(NULL_PTR == CSFSDN_ROOT_DNAME(csfsdn))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:__csfsdn_node_dname_gen: csfsdn %p CSFSDN_ROOT_DNAME is null\n", csfsdn);
        return (EC_FALSE);
    }
 
    snprintf(path, max_len, "%s/dsk%ld",
                (char *)CSFSDN_ROOT_DNAME(csfsdn),
                disk_no
                );
    return (EC_TRUE);
}

CSFSDN_NODE *csfsdn_node_fetch(const CSFSDN *csfsdn, const UINT32 node_id)
{
    CSFSDN_NODE csfsdn_node;
    CRB_NODE   *crb_node;

    CSFSDN_NODE_ID(&csfsdn_node) = (node_id >> CSFSDN_SEG_NO_NBITS);
 
    crb_node = crb_tree_search_data(CSFSDN_OPEN_NODES(csfsdn), (void *)&csfsdn_node);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    return ((CSFSDN_NODE *)CRB_NODE_DATA(crb_node));
}

EC_BOOL csfsdn_node_delete(CSFSDN *csfsdn, const UINT32 node_id)
{
    CSFSDN_NODE csfsdn_node;

    CSFSDN_NODE_ID(&csfsdn_node) = (node_id >> CSFSDN_SEG_NO_NBITS);
    return crb_tree_delete_data(CSFSDN_OPEN_NODES(csfsdn), (void *)&csfsdn_node);
}

CSFSDN_NODE *csfsdn_node_create(CSFSDN *csfsdn, const UINT32 node_id)
{
    CSFSDN_NODE *csfsdn_node;
    CRB_NODE   *crb_node;

    char path[ CSFSDN_NODE_NAME_MAX_SIZE ];

    csfsdn_node = CSFSDN_OPEN_NODE(csfsdn, node_id);
    if(NULL_PTR != csfsdn_node)
    {
        return (csfsdn_node);
    }

    /*create dir if needed*/
    if(EC_FALSE == __csfsdn_node_dname_gen(csfsdn, node_id, path, CSFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_create: csfsdn%p, generate dname failed\n", csfsdn);
        return (NULL_PTR);
    }
 
    if(EC_FALSE == c_dir_create(path))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_create: create dir %s failed\n", path);
        return (NULL_PTR);
    }

    /*if file exist, do nothing*/
    if(EC_FALSE == __csfsdn_node_fname_gen(csfsdn, node_id, path, CSFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_create: csfsdn%p, generate fname failed\n", csfsdn);
        return (NULL_PTR);
    }
 
    if(EC_TRUE == c_file_access(path, F_OK))
    {
        dbg_log(SEC_0163_CSFSDN, 1)(LOGSTDOUT, "warn:csfsdn_node_create: node file %s already exist\n", path);
        return (NULL_PTR);
    }

    csfsdn_node = csfsdn_node_new();
    if(NULL_PTR == csfsdn_node)
    {
        dbg_log(SEC_0163_CSFSDN, 1)(LOGSTDOUT, "warn:csfsdn_node_create: new csfsdn_node failed\n");
        return (NULL_PTR);
    }
    CSFSDN_NODE_ID(csfsdn_node) = (node_id >> CSFSDN_SEG_NO_NBITS);

    CSFSDN_NODE_ATIME(csfsdn_node) = task_brd_get_time(task_brd_default_get());

    /*creat file*/
    CSFSDN_NODE_FD(csfsdn_node) = c_file_open(path, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CSFSDN_NODE_FD(csfsdn_node))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_create: open node file %s failed\n", path);
        csfsdn_node_free(csfsdn_node);
        return (NULL_PTR);
    }
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_node_create: create file %s done\n", path);
 
    /*optimize*/
    if(EC_FALSE == c_file_truncate(CSFSDN_NODE_FD(csfsdn_node), CSFSDN_CACHE_MAX_BYTE_SIZE))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_create: truncate file %s failed\n", path);
        csfsdn_node_free(csfsdn_node);
        return (NULL_PTR);
    }
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_node_create: truncate file %s to %ld bytes done\n", path, CSFSDN_CACHE_MAX_BYTE_SIZE);

    crb_node = crb_tree_insert_data(CSFSDN_OPEN_NODES(csfsdn), (void *)csfsdn_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_create: insert new csfsdn_node into open nodes failed\n");
        csfsdn_node_free(csfsdn_node);
        return (NULL_PTR);
    }

    if(CRB_NODE_DATA(crb_node) != (void *)csfsdn_node)
    {
        dbg_log(SEC_0163_CSFSDN, 1)(LOGSTDOUT, "warn:csfsdn_node_create: inserted but csfsdn_node is not the newest one\n");
        csfsdn_node_free(csfsdn_node);
        return ((CSFSDN_NODE *)CRB_NODE_DATA(crb_node));
    }

    return (csfsdn_node);
}

CSFSDN_NODE *csfsdn_node_open(CSFSDN *csfsdn, const UINT32 node_id, const UINT32 open_flags)
{
    CSFSDN_NODE *csfsdn_node;
    CRB_NODE    *crb_node;
    char path[ CSFSDN_NODE_NAME_MAX_SIZE ];

    CSFSDN_CMUTEX_LOCK(csfsdn, LOC_CSFSDN_0005);
    csfsdn_node = CSFSDN_OPEN_NODE(csfsdn, node_id);
    if(NULL_PTR != csfsdn_node)
    {
        /*update last access time*/
        CSFSDN_NODE_ATIME(csfsdn_node) = task_brd_get_time(task_brd_default_get());
        CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0006);
        return (csfsdn_node);
    }

    if(EC_FALSE == __csfsdn_node_fname_gen(csfsdn, node_id, path, CSFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_open: csfsdn%p, generate fname failed\n", csfsdn);
        return (NULL_PTR);
    }
 
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_node_open: path is %s\n", path);
 
    /*when node file not exit, then create it and return*/
    if(EC_FALSE == c_file_access(path, F_OK))
    {
        if(open_flags & CSFSDN_NODE_O_CREATE)
        {
            dbg_log(SEC_0163_CSFSDN, 1)(LOGSTDOUT, "warn:csfsdn_node_open: node file %s not exist, try to create it\n", path);
            csfsdn_node = csfsdn_node_create(csfsdn, node_id);
            if(NULL_PTR != csfsdn_node)
            {
                CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0007);
                return (csfsdn_node);
            }
        }

        CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0008);
        dbg_log(SEC_0163_CSFSDN, 1)(LOGSTDOUT, "warn:csfsdn_node_open: node file %s not exist\n", path);     
        return (NULL_PTR);
    }

    csfsdn_node = csfsdn_node_new();
    if(NULL_PTR == csfsdn_node)
    {
        CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0009);
        dbg_log(SEC_0163_CSFSDN, 1)(LOGSTDOUT, "warn:csfsdn_node_open: new csfsdn_node failed\n");
        return (NULL_PTR);
    }
    CSFSDN_NODE_ID(csfsdn_node) = (node_id >> CSFSDN_SEG_NO_NBITS);

    /*set/init last access time*/
    CSFSDN_NODE_ATIME(csfsdn_node) = task_brd_get_time(task_brd_default_get());
 
    /*when node file exit, then open it*/
    CSFSDN_NODE_FD(csfsdn_node) = c_file_open(path, O_RDWR, 0666);
    if(ERR_FD == CSFSDN_NODE_FD(csfsdn_node))
    {
        CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0010);
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_open: open node file %s failed\n", path);
        csfsdn_node_free(csfsdn_node);
        return (NULL_PTR);
    }

    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_node_open: insert node %u with path %s to open nodes(rbtree)\n", node_id, path);
    crb_node = crb_tree_insert_data(CSFSDN_OPEN_NODES(csfsdn), (void *)csfsdn_node);
    if(NULL_PTR == crb_node)
    {
        CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0011);
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_open: insert new csfsdn_node into open nodes failed\n");
        csfsdn_node_free(csfsdn_node);
        return (NULL_PTR);
    }

    if(CRB_NODE_DATA(crb_node) != (void *)csfsdn_node)
    {
        CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0012);
        dbg_log(SEC_0163_CSFSDN, 1)(LOGSTDOUT, "warn:csfsdn_node_open: inserted but csfsdn_node is not the newest one\n");
        csfsdn_node_free(csfsdn_node);
        return ((CSFSDN_NODE *)CRB_NODE_DATA(crb_node));
    }
    CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0013);

    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_node_open: insert node %u with path %s to open nodes(rbtree) done\n", node_id, path);

    return (csfsdn_node);
}
#if 0
EC_BOOL csfsdn_node_unlink(CSFSDN *csfsdn, const UINT32 node_id)
{
    char path[ CSFSDN_NODE_NAME_MAX_SIZE ];

    if(EC_FALSE == __csfsdn_node_fname_gen(csfsdn, node_id, path, CSFSDN_NODE_NAME_MAX_SIZE))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_unlink: csfsdn%p, generate fname failed\n", csfsdn);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == c_file_access(path, F_OK))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_unlink: node file %s not exist\n", path);
        return (EC_FALSE);
    }

    if( EC_FALSE == c_file_unlink(path))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_unlink: unlink node file %s failed\n", path);
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsdn_node_delete(csfsdn, node_id))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_unlink: delete node from cache failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_node_unlink: unlink node file %s successfully\n", path);
    return (EC_TRUE);
}
#endif

EC_BOOL csfsdn_node_write(CSFSDN *csfsdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset)
{
    CSFSDN_NODE *csfsdn_node;
    UINT32       offset_b; /*real base offset of block in physical file*/
    UINT32       offset_r; /*real offset in physical file*/

    csfsdn_node = csfsdn_node_open(csfsdn, node_id, CSFSDN_NODE_O_CREATE | CSFSDN_NODE_O_RDWR);
    if(NULL_PTR == csfsdn_node)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_write: open node %ld failed\n", node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CSFSDN_NODE_ID_GET_SEG_NO(node_id)) << CSFSB_CACHE_BIT_SIZE);
    offset_r = offset_b + (*offset);
 
    CSFSDN_NODE_CMUTEX_LOCK(csfsdn_node, LOC_CSFSDN_0014);

    if(EC_FALSE == c_file_flush(CSFSDN_NODE_FD(csfsdn_node), &offset_r, data_max_len, data_buff))
    {
        CSFSDN_NODE_CMUTEX_UNLOCK(csfsdn_node, LOC_CSFSDN_0015);
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_write: flush %ld bytes to node %ld at offset %ld failed\n",
                            data_max_len, node_id, offset_r);
        return (EC_FALSE);
    }
 
    CSFSDN_NODE_CMUTEX_UNLOCK(csfsdn_node, LOC_CSFSDN_0016);

    (*offset) = (offset_r - offset_b);
    return (EC_TRUE);
}

EC_BOOL csfsdn_node_read(CSFSDN *csfsdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset)
{ 
    CSFSDN_NODE *csfsdn_node;
    UINT32       offset_b; /*real base offset of block in physical file*/
    UINT32       offset_r; /*real offset in physical file*/

    csfsdn_node = csfsdn_node_open(csfsdn, node_id, /*CSFSDN_NODE_O_CREATE | */CSFSDN_NODE_O_RDWR);
    if(NULL_PTR == csfsdn_node)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_read: open node %ld failed\n", node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CSFSDN_NODE_ID_GET_SEG_NO(node_id)) << CSFSB_CACHE_BIT_SIZE);
    offset_r = offset_b + (*offset);
                         
    CSFSDN_NODE_CMUTEX_LOCK(csfsdn_node, LOC_CSFSDN_0017);

    if(EC_FALSE == c_file_load(CSFSDN_NODE_FD(csfsdn_node), &offset_r, data_max_len, data_buff))
    {
        CSFSDN_NODE_CMUTEX_UNLOCK(csfsdn_node, LOC_CSFSDN_0018);
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_node_read: load %ld bytes from node %ld at offset %ld failed\n",
                            data_max_len, node_id, offset_r);     
        return (EC_FALSE);
    }

    CSFSDN_NODE_CMUTEX_UNLOCK(csfsdn_node, LOC_CSFSDN_0019);

    (*offset) = (offset_r - offset_b);
    return (EC_TRUE);
}

static EC_BOOL __csfsdn_collect_expired_node(const CSFSDN_NODE *csfsdn_node, CLIST *expired_node_list)
{
    ctime_t     cur_time;

    cur_time = task_brd_get_time(task_brd_default_get()); 

    /*expired*/
    if(cur_time > CSFSDN_NODE_ATIME(csfsdn_node) + CSFSDN_EXPIRED_IN_NSEC)
    {
        clist_push_back_no_lock(expired_node_list, (void *)csfsdn_node);
    }
    return (EC_TRUE);
}

EC_BOOL csfsdn_expire_open_nodes(CSFSDN *csfsdn)
{
    CLIST *expired_node_list;

    ctime_t     cur_time;

    cur_time = task_brd_get_time(task_brd_default_get());    

    expired_node_list = clist_new(MM_CSFSDN_NODE, LOC_CSFSDN_0020);
    if(NULL_PTR == expired_node_list)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_expire_open_nodes: new clist failed\n");
        return (EC_FALSE);
    }

    CSFSDN_CMUTEX_LOCK(csfsdn, LOC_CSFSDN_0021);

    /*collect open expired nodes*/
    crb_inorder_walk(CSFSDN_OPEN_NODES(csfsdn), (CRB_DATA_HANDLE)__csfsdn_collect_expired_node, expired_node_list);

    while(EC_FALSE == clist_is_empty_no_lock(expired_node_list))
    {
        CSFSDN_NODE *csfsdn_node;

        csfsdn_node = (CSFSDN_NODE *)clist_pop_front_no_lock(expired_node_list);
        if(NULL_PTR != csfsdn_node)
        {
            CTM   *cur_tm;
            CTM   *last_tm;

            cur_tm  = c_localtime_r(&cur_time);
            last_tm = c_localtime_r(&CSFSDN_NODE_ATIME(csfsdn_node));
            dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_expire_open_nodes: expire csfsdn_node %ld (%p) where "
                               "last access time %4d-%02d-%02d %02d:%02d:%02d, "
                               "current time %4d-%02d-%02d %02d:%02d:%02d\n",
                               CSFSDN_NODE_ID(csfsdn_node), csfsdn_node,
                               TIME_IN_YMDHMS(last_tm),
                               TIME_IN_YMDHMS(cur_tm));

            crb_tree_delete_data(CSFSDN_OPEN_NODES(csfsdn), (void *)csfsdn_node);
        }
    }
 
    CSFSDN_CMUTEX_UNLOCK(csfsdn, LOC_CSFSDN_0022);
 
    clist_free_no_lock(expired_node_list, LOC_CSFSDN_0023);
 
    return (EC_TRUE);
}

static char * __csfsdn_vol_fname_gen(const char *root_dname)
{
    const char *field[ 2 ];
    char       *vol_fname;

    field[ 0 ] = root_dname;
    field[ 1 ] = CSFSDN_DB_NAME;

    vol_fname = c_str_join("/", field, 2);/*${root_dname}/${vol_basename}*/
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_vol_fname_gen: make vol_fname %s/%s failed\n", root_dname, CSFSDN_DB_NAME);
        return (NULL_PTR);
    }

    return (vol_fname);
}

static uint16_t __csfsdn_count_disk_num_from_disk_space(const uint16_t max_gb_num_of_disk_space)
{
#if (CSFSD_TEST_SCENARIO_001T_DISK == CSFSD_DEBUG_CHOICE)
    uint16_t max_tb_num_of_disk_space;
    uint16_t disk_num;

    max_tb_num_of_disk_space = (max_gb_num_of_disk_space + 1024 - 1) / 1024;
    disk_num = max_tb_num_of_disk_space; /*one disk = 1 TB*/
#endif/*(CSFSD_TEST_SCENARIO_001T_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_256M_DISK == CSFSD_DEBUG_CHOICE)
    uint16_t max_mb_num_of_disk_space;
    uint16_t disk_num;

    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] __csfsdn_count_disk_num_from_disk_space: ### set 1 disk = %u MB for debug purpose \n", CSFSD_DEBUG_MB_PER_DISK);
    max_mb_num_of_disk_space = (max_gb_num_of_disk_space) * (1024 / CSFSD_DEBUG_MB_PER_DISK);
    disk_num = max_mb_num_of_disk_space;
 
#endif/*(CSFSD_TEST_SCENARIO_256M_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_512M_DISK == CSFSD_DEBUG_CHOICE)
    uint16_t max_mb_num_of_disk_space;
    uint16_t disk_num;

    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] __csfsdn_count_disk_num_from_disk_space: ### set 1 disk = %u MB for debug purpose \n", CSFSD_DEBUG_MB_PER_DISK);
    max_mb_num_of_disk_space = (max_gb_num_of_disk_space) * (1024 / CSFSD_DEBUG_MB_PER_DISK);
    disk_num = max_mb_num_of_disk_space;
 
#endif/*(CSFSD_TEST_SCENARIO_512M_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_032G_DISK == CSFSD_DEBUG_CHOICE)
    uint16_t disk_num;

    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] __csfsdn_count_disk_num_from_disk_space: ### set 1 disk = %u GB for debug purpose \n", CSFSD_DEBUG_GB_PER_DISK);
    disk_num = (max_gb_num_of_disk_space + CSFSD_DEBUG_GB_PER_DISK - 1) / CSFSD_DEBUG_GB_PER_DISK;
 
#endif/*(CSFSD_TEST_SCENARIO_032G_DISK == CSFSD_DEBUG_CHOICE)*/

#if (CSFSD_TEST_SCENARIO_512G_DISK == CSFSD_DEBUG_CHOICE)
    uint16_t disk_num;

    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] __csfsdn_count_disk_num_from_disk_space: ### set 1 disk = %u GB for debug purpose \n", CSFSD_DEBUG_GB_PER_DISK);
    disk_num = (max_gb_num_of_disk_space + CSFSD_DEBUG_GB_PER_DISK - 1) / CSFSD_DEBUG_GB_PER_DISK;
 
#endif/*(CSFSD_TEST_SCENARIO_032G_DISK == CSFSD_DEBUG_CHOICE)*/
    return (disk_num);
}

CSFSDN *csfsdn_create(const char *root_dname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp)
{
    CSFSDN *csfsdn;
    uint8_t *vol_fname;
 
    csfsdn = csfsdn_new();
    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_create: new csfsdn failed\n");
        return (NULL_PTR);
    }

    CSFSDN_ROOT_DNAME(csfsdn) = (uint8_t *)c_str_dup(root_dname);
    if(NULL_PTR == CSFSDN_ROOT_DNAME(csfsdn))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_create: dup root_dname %s failed\n", root_dname);
        csfsdn_free(csfsdn);
        return (NULL_PTR);
    }

    vol_fname = (uint8_t *)__csfsdn_vol_fname_gen((char *)CSFSDN_ROOT_DNAME(csfsdn));
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_create: make vol_fname from root_dname %s failed\n", root_dname);
        csfsdn_free(csfsdn);
        return (NULL_PTR);
    }

    CSFSDN_CSFSV(csfsdn) = csfsv_new((uint8_t *)vol_fname, np_node_err_pos, np_node_recycle, npp);
    if(NULL_PTR == CSFSDN_CSFSV(csfsdn))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_create: new vol %s failed\n", vol_fname);
        csfsdn_free(csfsdn);
        safe_free(vol_fname, LOC_CSFSDN_0024);
        return (NULL_PTR);
    }
 
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_create: vol %s was created\n", vol_fname);
    safe_free(vol_fname, LOC_CSFSDN_0025);

    if(EC_FALSE == csfsdn_flush(csfsdn))/*xxx*/
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_create:flush dn failed\n");
        csfsdn_free(csfsdn);
        return (NULL_PTR);
    }

    return (csfsdn);
}

EC_BOOL csfsdn_add_disk(CSFSDN *csfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == csfsv_add_disk(CSFSDN_CSFSV(csfsdn), disk_no))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_add_disk: csfsv add disk %u failed\n", disk_no);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == csfsdn_flush(csfsdn))/*xxx*/
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_add_disk: flush dn failed after add disk %u \n", disk_no);
        csfsv_del_disk(CSFSDN_CSFSV(csfsdn), disk_no);
        return (EC_FALSE);
    } 
    return (EC_TRUE);
}

EC_BOOL csfsdn_del_disk(CSFSDN *csfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == csfsv_del_disk(CSFSDN_CSFSV(csfsdn), disk_no))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_del_disk: csfsv del disk %u failed\n", disk_no);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == csfsdn_flush(csfsdn))/*xxx*/
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_del_disk: flush dn failed after del disk %u \n", disk_no);
        return (EC_FALSE);
    } 
    return (EC_TRUE);
}

EC_BOOL csfsdn_mount_disk(CSFSDN *csfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == csfsv_mount_disk(CSFSDN_CSFSV(csfsdn), disk_no))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_mount_disk: csfsv mount disk %u failed\n", disk_no);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == csfsdn_flush(csfsdn))/*xxx*/
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_mount_disk: flush dn failed after mount disk %u \n", disk_no);
        return (EC_FALSE);
    } 
    return (EC_TRUE);
}

EC_BOOL csfsdn_umount_disk(CSFSDN *csfsdn, const uint16_t disk_no)
{
    if(EC_FALSE == csfsv_umount_disk(CSFSDN_CSFSV(csfsdn), disk_no))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_umount_disk: csfsv umount disk %u failed\n", disk_no);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == csfsdn_flush(csfsdn))/*xxx*/
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_umount_disk: flush dn failed after umount disk %u \n", disk_no);
        return (EC_FALSE);
    } 
    return (EC_TRUE);
}


CSFSDN *csfsdn_new()
{
    CSFSDN *csfsdn;

    alloc_static_mem(MM_CSFSDN, &csfsdn, LOC_CSFSDN_0026);
    if(NULL_PTR != csfsdn)
    {
        csfsdn_init(csfsdn);
        return (csfsdn);
    }
    return (csfsdn);
}

EC_BOOL csfsdn_init(CSFSDN *csfsdn)
{
    CSFSDN_CRWLOCK_INIT(csfsdn, LOC_CSFSDN_0027);
    CSFSDN_CMUTEX_INIT(csfsdn, LOC_CSFSDN_0028);
 
    crb_tree_init(CSFSDN_OPEN_NODES(csfsdn),
                  (CRB_DATA_CMP  )csfsdn_node_cmp,
                  (CRB_DATA_FREE )csfsdn_node_free,
                  (CRB_DATA_PRINT)csfsdn_node_print);

    CSFSDN_ROOT_DNAME(csfsdn)  = NULL_PTR;
    CSFSDN_CSFSV(csfsdn)        = NULL_PTR;
 
    return (EC_TRUE);
}

EC_BOOL csfsdn_clean(CSFSDN *csfsdn)
{
    CSFSDN_CRWLOCK_CLEAN(csfsdn, LOC_CSFSDN_0029);
    CSFSDN_CMUTEX_CLEAN(csfsdn, LOC_CSFSDN_0030);
 
    crb_tree_clean(CSFSDN_OPEN_NODES(csfsdn));

    if(NULL_PTR != CSFSDN_ROOT_DNAME(csfsdn))
    {
        safe_free(CSFSDN_ROOT_DNAME(csfsdn), LOC_CSFSDN_0031);
        CSFSDN_ROOT_DNAME(csfsdn) = NULL_PTR;
    }

    if(NULL_PTR != CSFSDN_CSFSV(csfsdn))
    {
        csfsv_close(CSFSDN_CSFSV(csfsdn));
        CSFSDN_CSFSV(csfsdn) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL csfsdn_free(CSFSDN *csfsdn)
{
    if(NULL_PTR != csfsdn)
    {
        csfsdn_clean(csfsdn);
        free_static_mem(MM_CSFSDN, csfsdn, LOC_CSFSDN_0032);
    }
    return (EC_TRUE);
}

void csfsdn_print(LOG *log, const CSFSDN *csfsdn)
{
    if(NULL_PTR != csfsdn)
    {    
        sys_log(log, "csfsdn_print: csfsdn %p: root dname: %s\n", csfsdn, (char *)CSFSDN_ROOT_DNAME(csfsdn));

        csfsv_print(log, CSFSDN_CSFSV(csfsdn));
        if(0)
        {
            sys_log(log, "csfsdn_print: csfsdn %p: cached nodes: \n", csfsdn);
            crb_tree_print(log, CSFSDN_OPEN_NODES(csfsdn));
        }  
    }
    return;
}

EC_BOOL csfsdn_flush(CSFSDN *csfsdn)
{
    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_flush: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsv_sync(CSFSDN_CSFSV(csfsdn)))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_flush: sync csfsv failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csfsdn_load(CSFSDN *csfsdn, const char *root_dname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp)
{
    uint8_t *vol_fname;

    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_load: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CSFSDN_CSFSV(csfsdn))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_load: CSFSDN_CSFSV is not null\n");
        return (EC_FALSE);
    }

    CSFSDN_ROOT_DNAME(csfsdn) = (uint8_t *)c_str_dup(root_dname);
    if(NULL_PTR == CSFSDN_ROOT_DNAME(csfsdn))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_load: dup root_dname %s failed\n", root_dname);
        return (EC_FALSE);
    }  

    vol_fname = (uint8_t *)__csfsdn_vol_fname_gen((char *)CSFSDN_ROOT_DNAME(csfsdn));
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_load: make vol_fname from root_dname %s failed\n", (char *)CSFSDN_ROOT_DNAME(csfsdn));
        return (EC_FALSE);
    } 

    CSFSDN_CSFSV(csfsdn) = csfsv_open(vol_fname, np_node_err_pos, np_node_recycle, npp);
    if(NULL_PTR == CSFSDN_CSFSV(csfsdn))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_load: load/open vol from %s failed\n", (char *)vol_fname);
        safe_free(vol_fname, LOC_CSFSDN_0033);
        return (EC_FALSE);
    }
 
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_load: load/open vol from %s done\n", (char *)vol_fname);
    safe_free(vol_fname, LOC_CSFSDN_0034);

    return (EC_TRUE);
}

EC_BOOL csfsdn_exist(const char *root_dname)
{
    char *vol_fname;
 
    vol_fname = __csfsdn_vol_fname_gen(root_dname);
    if(NULL_PTR == vol_fname)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_exist: make vol_fname from root_dname %s failed\n", root_dname);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access(vol_fname, F_OK))
    {
        dbg_log(SEC_0163_CSFSDN, 7)(LOGSTDOUT, "error:csfsdn_exist: vol file %s not exist\n", vol_fname);
        safe_free(vol_fname, LOC_CSFSDN_0035);
        return (EC_FALSE);
    } 

    safe_free(vol_fname, LOC_CSFSDN_0036);
    return (EC_TRUE);
}

CSFSDN *csfsdn_open(const char *root_dname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp)
{
    CSFSDN *csfsdn;

    if(NULL_PTR == root_dname)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_open: root dir is null\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == c_dir_exist(root_dname))
    /*if(EC_FALSE == c_file_access(root_dname, F_OK))*/
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_open: root dir %s not exist\n", root_dname);
        return (NULL_PTR);
    }

    csfsdn = csfsdn_new();
    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_open: new csfsdn with root dir %s failed\n", root_dname);
        return (NULL_PTR);
    }
 
    if(EC_FALSE == csfsdn_load(csfsdn, root_dname, np_node_err_pos, np_node_recycle, npp))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_open: load csfsdn from root dir %s failed\n", root_dname);
        csfsdn_free(csfsdn);
        return (NULL_PTR);
    }
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_open: load csfsdn from root dir %s done\n", root_dname);
 
    return (csfsdn);
}

EC_BOOL csfsdn_close(CSFSDN *csfsdn)
{
    if(NULL_PTR != csfsdn)
    {
        CSFSDN_CRWLOCK_WRLOCK(csfsdn, LOC_CSFSDN_0037);
        csfsdn_flush(csfsdn);
        CSFSDN_CRWLOCK_UNLOCK(csfsdn, LOC_CSFSDN_0038);
        csfsdn_free(csfsdn);
    }
    return (EC_TRUE);
}

EC_BOOL csfsdn_fetch_block_fd(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, int *block_fd)
{
    UINT32 node_id;
 
    CSFSDN_NODE *csfsdn_node;

    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_fetch_block_fd: csfsdn is null\n");
        return (EC_FALSE);
    }

    node_id = CSFSDN_NODE_ID_MAKE(disk_no, block_no);

    csfsdn_node = csfsdn_node_open(csfsdn, node_id, CSFSDN_NODE_O_RDWR);
    if(NULL_PTR == csfsdn_node)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_fetch_block_fd: open node %ld failed\n", node_id);
        return (EC_FALSE);
    } 

    (*block_fd) = CSFSDN_NODE_FD(csfsdn_node);

    return (EC_TRUE);
}

/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL csfsdn_read_o(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_o: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CSFSB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    if(CSFSB_CACHE_MAX_BYTE_SIZE <= offset)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_o: offset %ld overflow\n", offset);
        return (EC_FALSE);
    }

    if(CSFSB_CACHE_MAX_BYTE_SIZE < offset + data_max_len)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_o: offset %ld + data_max_len %ld = %ld overflow\n",
                            offset, data_max_len, offset + data_max_len);
        return (EC_FALSE);
    }  

    node_id = CSFSDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = offset;
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_read_o: disk %u, block %u  ==> node %u, start\n", disk_no, block_no, node_id);
    if(EC_FALSE == csfsdn_node_read(csfsdn, node_id, data_max_len, data_buff, &offset_t))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_o: read %u bytes at offset %u from node %u failed\n",
                           data_max_len, offset, node_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_read_o: disk %u, block %u  ==> node %u, end\n", disk_no, block_no, node_id);

    if(NULL_PTR != data_len)
    {
        (*data_len) = offset_t - offset;
    }

    return (EC_TRUE);
}

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL csfsdn_write_o(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_o: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_o: data_buff is null\n");
        return (EC_FALSE);
    } 

    if(CSFSB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_o: data max len %u overflow\n", data_max_len);
        return (EC_FALSE);
    }

    node_id  = CSFSDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = (*offset);

    if(EC_FALSE == csfsdn_node_write(csfsdn, node_id, data_max_len, data_buff, offset))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_o: write %u bytes to disk %u block %u offset %u failed\n",
                            data_max_len, disk_no, block_no, offset_t);
                         
        return (EC_FALSE);
    }

    //dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_write_o: write %u bytes to disk %u block %u offset %u done\n",
    //                    data_max_len, disk_no, block_no, offset_t);

    return (EC_TRUE);
}

EC_BOOL csfsdn_read_b(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset;

    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_b: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_b: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CSFSB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_b: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    ASSERT(0 == page_no);

    offset  = (((UINT32)page_no) << (CSFSB_PAGE_BIT_SIZE));
    if(EC_FALSE == csfsdn_read_o(csfsdn, disk_no, block_no, offset, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_b: read %u bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csfsdn_write_b(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, UINT32 *offset)
{
    uint32_t size;

    //uint16_t page_num;
    uint16_t disk_no_t;
    uint16_t block_no_t;
    uint16_t page_no_t;
 
    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_b: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_b: data_buff is null\n");
        return (EC_FALSE);
    } 

    if(CSFSB_CACHE_MAX_BYTE_SIZE < data_max_len + (*offset))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_b: data max len %u + offset %u = %u overflow\n",
                           data_max_len, (*offset), data_max_len + (*offset));
        return (EC_FALSE);
    }

    size = CSFSB_CACHE_MAX_BYTE_SIZE;

    //page_num = (uint16_t)((size + CSFSB_PAGE_BYTE_SIZE - 1) >> CSFSB_PAGE_BIT_SIZE);

    if(EC_FALSE == csfsv_new_space(CSFSDN_CSFSV(csfsdn), size, &disk_no_t, &block_no_t, &page_no_t))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_b: new %u bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }
    ASSERT(0 == page_no_t);

    if(EC_FALSE == csfsdn_write_o(csfsdn, data_max_len, data_buff, disk_no_t, block_no_t, offset))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_b: write %u bytes to disk %u block %u page %u failed\n",
                            data_max_len, disk_no_t, block_no_t, page_no_t);
                         
        return (EC_FALSE);
    }
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_write_b: write %u bytes to disk %u block %u page %u done\n",
                        data_max_len, disk_no_t, block_no_t, page_no_t);

    //CSFSV_CUR_DISK_NO(CSFSDN_CSFSV(csfsdn))  = disk_no_t;
    //CSFSV_CUR_BLOCK_NO(CSFSDN_CSFSV(csfsdn)) = block_no_t;
    //CSFSV_CUR_PAGE_NO(CSFSDN_CSFSV(csfsdn))  = page_no_t + page_num;

    (*disk_no)  = disk_no_t;
    (*block_no) = block_no_t;

    return (EC_TRUE);
}

EC_BOOL csfsdn_read_p(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset;

    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_p: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CSFSB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)page_no) << (CSFSB_PAGE_BIT_SIZE));
    //dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_read_p: disk %u, block %u, page %u ==> offset %u\n", disk_no, block_no, page_no, offset);
    if(EC_FALSE == csfsdn_read_o(csfsdn, disk_no, block_no, offset, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_p: read %u bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csfsdn_write_p(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    UINT32   offset;
    uint32_t size;

    //uint16_t page_num;
    uint16_t disk_no_t;
    uint16_t block_no_t;
    uint16_t page_no_t; 

    if(NULL_PTR == csfsdn)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_p: csfsdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_p: data_buff is null\n");
        return (EC_FALSE);
    } 

    if(CSFSB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_p: data max len %u overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    //page_num = (uint16_t)((size + CSFSB_PAGE_BYTE_SIZE - 1) >> CSFSB_PAGE_BIT_SIZE);

    if(EC_FALSE == csfsv_new_space(CSFSDN_CSFSV(csfsdn), size, &disk_no_t, &block_no_t,  &page_no_t))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_p: new %u bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)(*page_no)) << (CSFSB_PAGE_BIT_SIZE));

    if(EC_FALSE == csfsdn_write_o(csfsdn, data_max_len, data_buff, disk_no_t, block_no_t, &offset))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_p: write %u bytes to disk %u block %u page %u failed\n",
                            data_max_len, disk_no_t, block_no_t, page_no_t);
        return (EC_FALSE);
    }
    dbg_log(SEC_0163_CSFSDN, 9)(LOGSTDOUT, "[DEBUG] csfsdn_write_p: write %u bytes to disk %u block %u page %u done\n",
                        data_max_len, disk_no_t, block_no_t, page_no_t);

    //CSFSV_CUR_DISK_NO(CSFSDN_CSFSV(csfsdn))  = disk_no_t;
    //CSFSV_CUR_BLOCK_NO(CSFSDN_CSFSV(csfsdn)) = block_no_t;
    //CSFSV_CUR_PAGE_NO(CSFSDN_CSFSV(csfsdn))  = page_no_t + page_num;

    (*disk_no)  = disk_no_t;
    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;
 
    return (EC_TRUE);
}


/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL csfsdn_read_e(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CSFSB_PAGE_BIT_SIZE)) + offset;
    if(EC_FALSE == csfsdn_read_o(csfsdn, disk_no, block_no, offset_t, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_read_e: read %u bytes from disk %u block %u page %u offset %u failed\n",
                           data_max_len, disk_no, block_no, page_no, offset);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL csfsdn_write_e(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CSFSB_PAGE_BIT_SIZE)) + offset;
    if(EC_FALSE == csfsdn_write_o(csfsdn, data_max_len, data_buff, disk_no, block_no, &offset_t))
    {
        dbg_log(SEC_0163_CSFSDN, 0)(LOGSTDOUT, "error:csfsdn_write_e: write %u bytes to disk %u block %u page %u offset %u failed\n",
                           data_max_len, disk_no, block_no, page_no, offset_t);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL csfsdn_show(LOG *log, const char *root_dir)
{
    CSFSDN *csfsdn;

    csfsdn = csfsdn_open(root_dir, 0, NULL_PTR, NULL_PTR);
    if(NULL_PTR == csfsdn)
    {
        sys_log(log, "error:csfsdn_show: open csfsdn %s failed\n", root_dir);
        return (EC_FALSE);
    }

    csfsdn_print(log, csfsdn);

    csfsdn_close(csfsdn);

    return (EC_TRUE);
}

EC_BOOL csfsdn_rdlock(CSFSDN *csfsdn, const UINT32 location)
{
    CSFSDN_CRWLOCK_RDLOCK(csfsdn, location);
    return (EC_TRUE);
}

EC_BOOL csfsdn_wrlock(CSFSDN *csfsdn, const UINT32 location)
{
    CSFSDN_CRWLOCK_WRLOCK(csfsdn, location);
    return (EC_TRUE);
}

EC_BOOL csfsdn_unlock(CSFSDN *csfsdn, const UINT32 location)
{
    CSFSDN_CRWLOCK_UNLOCK(csfsdn, location);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

