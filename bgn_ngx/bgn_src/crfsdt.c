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

#include "carray.h"
#include "cvector.h"

#include "cbc.h"
#include "ctimer.h"
#include "cbtimer.h"
#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "crfs.h"
#include "crfshttp.h"
#include "crfsmc.h"
#include "crfsbk.h"
#include "crfs.h"
#include "crfsdt.h"
#include "cload.h"
#include "chashalgo.h"

#include "cmd5.h"

#include "findex.inc"


CRFSDT_PNODE *crfsdt_pnode_new()
{
    CRFSDT_PNODE *crfsdt_pnode;

    alloc_static_mem(MM_CRFSDT_PNODE, &crfsdt_pnode, LOC_CRFSDT_0001);
    if(NULL_PTR == crfsdt_pnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_pnode_new: new crfsdt_pnode failed\n");
        return (NULL_PTR);
    }

    crfsdt_pnode_init(crfsdt_pnode);
    return (crfsdt_pnode);
}

EC_BOOL crfsdt_pnode_init(CRFSDT_PNODE *crfsdt_pnode)
{
    /*WARNING: do not change the hash algo!*/
    crfsconhash_init(CRFSDT_PNODE_CONHASH(crfsdt_pnode), CHASH_MD5_ALGO_ID);
    cstring_init(CRFSDT_PNODE_PATH(crfsdt_pnode), NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfsdt_pnode_clean(CRFSDT_PNODE *crfsdt_pnode)
{
    crfsconhash_clean(CRFSDT_PNODE_CONHASH(crfsdt_pnode));
    cstring_clean(CRFSDT_PNODE_PATH(crfsdt_pnode));

    return (EC_TRUE);
}

EC_BOOL crfsdt_pnode_free(CRFSDT_PNODE *crfsdt_pnode)
{
    if(NULL_PTR != crfsdt_pnode)
    {
        crfsdt_pnode_clean(crfsdt_pnode);
        free_static_mem(MM_CRFSDT_PNODE, crfsdt_pnode, LOC_CRFSDT_0002);
    }
    return (EC_TRUE);
}

void crfsdt_pnode_print(LOG *log, const CRFSDT_PNODE *crfsdt_pnode)
{
    sys_log(log, "crfsdt_pnode %p: path %s, crfsconhash %p\n",
                 crfsdt_pnode,
                 CRFSDT_PNODE_PATH_STR(crfsdt_pnode),
                 CRFSDT_PNODE_CONHASH(crfsdt_pnode));

    crfsconhash_print(log, CRFSDT_PNODE_CONHASH(crfsdt_pnode));
    return;
}

/*compare algorithm is low efficiency. need to adjust design of CRFSDT, but interfaces are not need change*/
int crfsdt_pnode_cmp(const CRFSDT_PNODE *crfsdt_pnode_1st, const CRFSDT_PNODE *crfsdt_pnode_2nd)
{
    UINT32 len;

    len = DMIN(CRFSDT_PNODE_PATH_LEN(crfsdt_pnode_1st), CRFSDT_PNODE_PATH_LEN(crfsdt_pnode_2nd));
    return cstring_ncmp(CRFSDT_PNODE_PATH(crfsdt_pnode_1st), CRFSDT_PNODE_PATH(crfsdt_pnode_2nd), len);
}

EC_BOOL crfsdt_pnode_clone(const CRFSDT_PNODE *crfsdt_pnode_src, CRFSDT_PNODE *crfsdt_pnode_des)
{
    cstring_clone(CRFSDT_PNODE_PATH(crfsdt_pnode_src), CRFSDT_PNODE_PATH(crfsdt_pnode_des));
    return crfsconhash_clone(CRFSDT_PNODE_CONHASH(crfsdt_pnode_src), CRFSDT_PNODE_CONHASH(crfsdt_pnode_des));
}

EC_BOOL crfsdt_pnode_set_path(CRFSDT_PNODE *crfsdt_pnode, const CSTRING *path)
{
    cstring_init(CRFSDT_PNODE_PATH(crfsdt_pnode), cstring_get_str(path));
    return (EC_TRUE);
}

EC_BOOL crfsdt_pnode_add_tcid(CRFSDT_PNODE *crfsdt_pnode, const UINT32 tcid)
{
    return crfsconhash_add_node(CRFSDT_PNODE_CONHASH(crfsdt_pnode), (uint32_t)tcid, CRFSCONHASH_DEFAULT_REPLICAS);
}

EC_BOOL crfsdt_pnode_del_tcid(CRFSDT_PNODE *crfsdt_pnode, const UINT32 tcid)
{
    return crfsconhash_del_node(CRFSDT_PNODE_CONHASH(crfsdt_pnode), (uint32_t)tcid);
}

EC_BOOL crfsdt_pnode_has_tcid(CRFSDT_PNODE *crfsdt_pnode, const UINT32 tcid)
{
    return crfsconhash_has_node(CRFSDT_PNODE_CONHASH(crfsdt_pnode), (uint32_t)tcid);
}

EC_BOOL crfsdt_pnode_flush(const CRFSDT_PNODE *crfsdt_pnode, int fd, UINT32 *offset)
{
    if(EC_FALSE == cstring_flush(CRFSDT_PNODE_PATH(crfsdt_pnode), fd, offset))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_pnode_flush: flush path '%s' at offset %u of fd %d failed\n",
                           CRFSDT_PNODE_PATH_STR(crfsdt_pnode), (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsconhash_flush(CRFSDT_PNODE_CONHASH(crfsdt_pnode), fd, offset))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_pnode_flush: flush conhash of path '%s' at offset %u of fd %d failed\n",
                           CRFSDT_PNODE_PATH_STR(crfsdt_pnode), (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdt_pnode_load(CRFSDT_PNODE *crfsdt_pnode, int fd, UINT32 *offset)
{
    if(EC_FALSE == cstring_load(CRFSDT_PNODE_PATH(crfsdt_pnode), fd, offset))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_pnode_load: load path at offset %u of fd %d failed\n",
                           (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsconhash_load(CRFSDT_PNODE_CONHASH(crfsdt_pnode), fd, offset))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_pnode_load: load conhash of path '%s' at offset %u of fd %d failed\n",
                           CRFSDT_PNODE_PATH_STR(crfsdt_pnode), (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CRFSDT_RNODE *crfsdt_rnode_new()
{
    CRFSDT_RNODE *crfsdt_rnode;

    alloc_static_mem(MM_CRFSDT_RNODE, &crfsdt_rnode, LOC_CRFSDT_0003);
    if(NULL_PTR == crfsdt_rnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_rnode_new: new crfsdt_rnode failed\n");
        return (NULL_PTR);
    }

    crfsdt_rnode_init(crfsdt_rnode);
    return (crfsdt_rnode);
}

EC_BOOL crfsdt_rnode_init(CRFSDT_RNODE *crfsdt_rnode)
{
    CRFSDT_RNODE_TCID(crfsdt_rnode) = CMPI_ERROR_TCID;
    crb_tree_init(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode), (CRB_DATA_CMP)cstring_ocmp, (CRB_DATA_FREE)cstring_free, (CRB_DATA_PRINT)cstring_print);

    return (EC_TRUE);
}

EC_BOOL crfsdt_rnode_clean(CRFSDT_RNODE *crfsdt_rnode)
{
    CRFSDT_RNODE_TCID(crfsdt_rnode) = CMPI_ERROR_TCID;
    crb_tree_clean(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode));

    return (EC_TRUE);
}

EC_BOOL crfsdt_rnode_free(CRFSDT_RNODE *crfsdt_rnode)
{
    if(NULL_PTR != crfsdt_rnode)
    {
        crfsdt_rnode_clean(crfsdt_rnode);
        free_static_mem(MM_CRFSDT_RNODE, crfsdt_rnode, LOC_CRFSDT_0004);
    }
    return (EC_TRUE);
}

void crfsdt_rnode_print(LOG *log, const CRFSDT_RNODE *crfsdt_rnode)
{
    sys_log(log, "crfsdt_rnode %p: tcid %s, path tree %p\n",
                 crfsdt_rnode,
                 c_word_to_ipv4(CRFSDT_RNODE_TCID(crfsdt_rnode)),
                 CRFSDT_RNODE_PATH_TREE(crfsdt_rnode)
                 );

    crb_tree_print(log, CRFSDT_RNODE_PATH_TREE(crfsdt_rnode));
    return;
}

int crfsdt_rnode_cmp(const CRFSDT_RNODE *crfsdt_rnode_1st, const CRFSDT_RNODE *crfsdt_rnode_2nd)
{
    if(CRFSDT_RNODE_TCID(crfsdt_rnode_1st) > CRFSDT_RNODE_TCID(crfsdt_rnode_2nd))
    {
        return (1);
    }

    if(CRFSDT_RNODE_TCID(crfsdt_rnode_1st) < CRFSDT_RNODE_TCID(crfsdt_rnode_2nd))
    {
        return (-1);
    }

    return (0);
}

EC_BOOL crfsdt_rnode_clone(const CRFSDT_RNODE *crfsdt_rnode_src, CRFSDT_RNODE *crfsdt_rnode_des)
{
    CRFSDT_RNODE_TCID(crfsdt_rnode_des) = CRFSDT_RNODE_TCID(crfsdt_rnode_src);
    return crb_tree_clone(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode_src),
                          CRFSDT_RNODE_PATH_TREE(crfsdt_rnode_des),
                          (CRB_DATA_NEW)cstring_new_0,
                          (CRB_DATA_CLONE)cstring_clone_0);
}


EC_BOOL crfsdt_rnode_set_tcid(CRFSDT_RNODE *crfsdt_rnode, const UINT32 tcid)
{
    CRFSDT_RNODE_TCID(crfsdt_rnode) = tcid;

    return (EC_TRUE);
}

EC_BOOL crfsdt_rnode_add_path(CRFSDT_RNODE *crfsdt_rnode, const CSTRING *path)
{
    CSTRING  *path_t;
    CRB_NODE *crb_node;

    path_t = cstring_new(cstring_get_str(path), LOC_CRFSDT_0005);
    if(NULL_PTR == path_t)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_rnode_add_path: clone path %s failed\n",
                            (const char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    crb_node = crb_tree_insert_data(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode), (void *)path_t);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_rnode_add_path: add path %s failed\n",
                            cstring_get_str(path_t));
        cstring_free(path_t);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != path_t)
    {
        /*duplicate insertion*/
        cstring_free(path_t);
    }

    return (EC_TRUE);
}

EC_BOOL crfsdt_rnode_del_path(CRFSDT_RNODE *crfsdt_rnode, const CSTRING *path)
{
    return crb_tree_delete_data(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode), (void *)path);
}

EC_BOOL crfsdt_rnode_has_path(CRFSDT_RNODE *crfsdt_rnode, const CSTRING *path)
{
    CRB_NODE *crb_node;

    crb_node = crb_tree_search_data(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode), (void *)path);
    if(NULL_PTR == crb_node)
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdt_rnode_flush(const CRFSDT_RNODE *crfsdt_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CRFSDT_RNODE_TCID(crfsdt_rnode))))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_rnode_flush: flush tcid %s at offset %u of fd %d failed\n",
                           c_word_to_ipv4(CRFSDT_RNODE_TCID(crfsdt_rnode)), (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crb_tree_flush(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode), fd, offset, (CRB_DATA_FLUSH)cstring_flush))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_rnode_flush: flush path tree of tcid %s at offset %u of fd %d failed\n",
                           c_word_to_ipv4(CRFSDT_RNODE_TCID(crfsdt_rnode)), (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdt_rnode_load(CRFSDT_RNODE *crfsdt_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CRFSDT_RNODE_TCID(crfsdt_rnode))))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_rnode_load: load tcid at offset %u of fd %d failed\n",
                           (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crb_tree_load(CRFSDT_RNODE_PATH_TREE(crfsdt_rnode), fd, offset, (CRB_DATA_NEW)cstring_new_0, (CRB_DATA_LOAD)cstring_load))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_rnode_load: load path tree of tcid %s at offset %u of fd %d failed\n",
                           c_word_to_ipv4(CRFSDT_RNODE_TCID(crfsdt_rnode)), (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CRFSDT *crfsdt_new()
{
    CRFSDT *crfsdt;

    alloc_static_mem(MM_CRFSDT, &crfsdt, LOC_CRFSDT_0006);
    if(NULL_PTR == crfsdt)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_new: new crfsdt failed\n");
        return (NULL_PTR);
    }

    crfsdt_init(crfsdt);
    return (crfsdt);
}

EC_BOOL crfsdt_init(CRFSDT *crfsdt)
{
    CRFSDT_CRWLOCK_INIT(crfsdt, LOC_CRFSDT_0007);

    crb_tree_init(CRFSDT_PNODE_TREE(crfsdt), (CRB_DATA_CMP)crfsdt_pnode_cmp, (CRB_DATA_FREE)crfsdt_pnode_free, (CRB_DATA_PRINT)crfsdt_pnode_print);

    crb_tree_init(CRFSDT_RNODE_TREE(crfsdt), (CRB_DATA_CMP)crfsdt_rnode_cmp, (CRB_DATA_FREE)crfsdt_rnode_free, (CRB_DATA_PRINT)crfsdt_rnode_print);

    return (EC_TRUE);
}

EC_BOOL crfsdt_clean(CRFSDT *crfsdt)
{
    CRFSDT_CRWLOCK_CLEAN(crfsdt, LOC_CRFSDT_0008);

    crb_tree_clean(CRFSDT_PNODE_TREE(crfsdt));

    crb_tree_clean(CRFSDT_RNODE_TREE(crfsdt));

    return (EC_TRUE);
}

EC_BOOL crfsdt_free(CRFSDT *crfsdt)
{
    if(NULL_PTR != crfsdt)
    {
        crfsdt_clean(crfsdt);
        free_static_mem(MM_CRFSDT, crfsdt, LOC_CRFSDT_0009);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdt_reset(CRFSDT *crfsdt)
{
    /*do not reset CRWLOCK*/
    crb_tree_clean(CRFSDT_PNODE_TREE(crfsdt));

    crb_tree_clean(CRFSDT_RNODE_TREE(crfsdt));

    return (EC_TRUE);
}

void crfsdt_print(LOG *log, const CRFSDT *crfsdt)
{
    sys_log(log, "crfsdt %p: pnode_tree %p, rnode_tree %p\n",
                 crfsdt,
                 CRFSDT_PNODE_TREE(crfsdt),
                 CRFSDT_RNODE_TREE(crfsdt));
    crb_tree_print(log, CRFSDT_PNODE_TREE(crfsdt));
    crb_tree_print(log, CRFSDT_RNODE_TREE(crfsdt));
    return;
}

EC_BOOL crfsdt_is_empty(const CRFSDT *crfsdt)
{
    if(EC_TRUE == crb_tree_is_empty(CRFSDT_PNODE_TREE(crfsdt))
    && EC_TRUE == crb_tree_is_empty(CRFSDT_RNODE_TREE(crfsdt)))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

CRFSDT_PNODE *crfsdt_search_pnode(const CRFSDT *crfsdt, const CSTRING *path)
{
    CRFSDT_PNODE  crfsdt_pnode_t;
    CRFSDT_PNODE *crfsdt_pnode;
    CRB_NODE     *crb_node;

    crfsdt_pnode_init(&crfsdt_pnode_t);
    crfsdt_pnode_set_path(&crfsdt_pnode_t, path);

    crb_node = crb_tree_search_data(CRFSDT_PNODE_TREE(crfsdt), (void *)&crfsdt_pnode_t);
    if(NULL_PTR == crb_node)
    {
        crfsdt_pnode_clean(&crfsdt_pnode_t);
        return (NULL_PTR);
    }

    crfsdt_pnode_clean(&crfsdt_pnode_t);

    crfsdt_pnode = (CRFSDT_PNODE *)CRB_NODE_DATA(crb_node);
    return (crfsdt_pnode);
}

CRFSDT_RNODE *crfsdt_search_rnode(const CRFSDT *crfsdt, const UINT32 tcid)
{
    CRFSDT_RNODE  crfsdt_rnode_t;
    CRB_NODE     *crb_node;

    crfsdt_rnode_init(&crfsdt_rnode_t);
    crfsdt_rnode_set_tcid(&crfsdt_rnode_t, tcid);

    crb_node = crb_tree_search_data(CRFSDT_RNODE_TREE(crfsdt), (void *)&crfsdt_rnode_t);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    return (CRFSDT_RNODE *)CRB_NODE_DATA(crb_node);
}

CRFSDT_PNODE *crfsdt_add_pnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_PNODE *crfsdt_pnode;
    CRB_NODE     *crb_node;

    crfsdt_pnode = crfsdt_search_pnode(crfsdt, path);
    if(NULL_PTR != crfsdt_pnode)
    {
        /*double confirm*/
        if(cstring_get_len(path) == cstring_get_len(CRFSDT_PNODE_PATH(crfsdt_pnode)))
        {
            crfsdt_pnode_add_tcid(crfsdt_pnode, tcid);
            return (crfsdt_pnode);
        }
        dbg_log(SEC_0142_CRFSDT, 6)(LOGSTDOUT, "warn:crfsdt_add_pnode: path %s confict to pnode %s\n",
                           (char *)cstring_get_str(path),
                           CRFSDT_PNODE_PATH_STR(crfsdt_pnode));
        return (NULL_PTR);
    }

    crfsdt_pnode = crfsdt_pnode_new();
    if(NULL_PTR == crfsdt_pnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_add_pnode: new crfsdt_pnode failed\n");
        return (NULL_PTR);
    }

    crfsdt_pnode_set_path(crfsdt_pnode, path);
    if(EC_FALSE == crfsdt_pnode_add_tcid(crfsdt_pnode, tcid))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_add_pnode: add new tcid %s pnode failed\n", c_word_to_ipv4(tcid));
        crfsdt_pnode_free(crfsdt_pnode);
        return (NULL_PTR);
    }

    crb_node =  crb_tree_insert_data(CRFSDT_PNODE_TREE(crfsdt), (void *)crfsdt_pnode);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_add_pnode: insert pnode (path %s, tcid %s) failed\n",
                            cstring_get_str(path), c_word_to_ipv4(tcid));
        crfsdt_pnode_free(crfsdt_pnode);
        return (NULL_PTR);
    }

   /*fix*/
   if(CRB_NODE_DATA(crb_node) != (void *)crfsdt_pnode)
   {
        crfsdt_pnode_free(crfsdt_pnode);
   }

    return (CRFSDT_PNODE *)CRB_NODE_DATA(crb_node);
}

CRFSDT_RNODE *crfsdt_add_rnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_RNODE *crfsdt_rnode;
    CRB_NODE     *crb_node;

    crfsdt_rnode = crfsdt_search_rnode(crfsdt, tcid);
    if(NULL_PTR != crfsdt_rnode)
    {
        crfsdt_rnode_add_path(crfsdt_rnode, path);
        return (crfsdt_rnode);
    }

    crfsdt_rnode = crfsdt_rnode_new();
    if(NULL_PTR == crfsdt_rnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_add_rnode: new crfsdt_rnode failed\n");
        return (NULL_PTR);
    }

    crfsdt_rnode_set_tcid(crfsdt_rnode, tcid);
    crfsdt_rnode_add_path(crfsdt_rnode, path);

    crb_node = crb_tree_insert_data(CRFSDT_RNODE_TREE(crfsdt), (void *)crfsdt_rnode);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_add_rnode: insert rnode (tcid %s, path %s ) failed\n",
                            c_word_to_ipv4(tcid), cstring_get_str(path));
        crfsdt_rnode_free(crfsdt_rnode);
        return (NULL_PTR);
    }

    /*fix*/
    if(CRB_NODE_DATA(crb_node) != (void *)crfsdt_rnode)
    {
        crfsdt_rnode_free(crfsdt_rnode);
    }

    return (CRFSDT_RNODE *)CRB_NODE_DATA(crb_node);
}

/*add path to some RFS*/
EC_BOOL crfsdt_add(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_PNODE *crfsdt_pnode;
    CRFSDT_RNODE *crfsdt_rnode;

    crfsdt_pnode = crfsdt_add_pnode(crfsdt, tcid, path);
    if(NULL_PTR == crfsdt_pnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_add: add pnode failed\n");
        return (EC_FALSE);
    }

    crfsdt_rnode = crfsdt_add_rnode(crfsdt, tcid, path);
    if(NULL_PTR == crfsdt_rnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_add: add rnode failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CRFSDT_PNODE *crfsdt_del_pnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_PNODE *crfsdt_pnode;

    crfsdt_pnode = crfsdt_search_pnode(crfsdt, path);
    if(NULL_PTR != crfsdt_pnode)
    {
        if(cstring_get_len(path) == cstring_get_len(CRFSDT_PNODE_PATH(crfsdt_pnode)))
        {
            crfsdt_pnode_del_tcid(crfsdt_pnode, tcid);
            return (crfsdt_pnode);
        }
        dbg_log(SEC_0142_CRFSDT, 6)(LOGSTDOUT, "warn:crfsdt_del_pnode: path %s is close to pnode %s\n",
                           (char *)cstring_get_str(path),
                           CRFSDT_PNODE_PATH_STR(crfsdt_pnode));
        return (NULL_PTR);
    }

    return (NULL_PTR);
}

CRFSDT_RNODE *crfsdt_del_rnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_RNODE *crfsdt_rnode;

    crfsdt_rnode = crfsdt_search_rnode(crfsdt, tcid);
    if(NULL_PTR != crfsdt_rnode)
    {
        crfsdt_rnode_del_path(crfsdt_rnode, path);
        return (crfsdt_rnode);
    }

    return (NULL_PTR);
}

/*del path from some RFS*/
EC_BOOL crfsdt_del(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_PNODE *crfsdt_pnode;
    CRFSDT_RNODE *crfsdt_rnode;

    crfsdt_pnode = crfsdt_del_pnode(crfsdt, tcid, path);
    if(NULL_PTR == crfsdt_pnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_del: del pnode failed\n");
        return (EC_FALSE);
    }

    crfsdt_rnode = crfsdt_del_rnode(crfsdt, tcid, path);
    if(NULL_PTR == crfsdt_rnode)
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_del: del rnode failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsdt_has_pnode(const CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_PNODE *crfsdt_pnode;

    crfsdt_pnode = crfsdt_search_pnode(crfsdt, path);
    if(NULL_PTR != crfsdt_pnode)
    {
        if(cstring_get_len(path) < cstring_get_len(CRFSDT_PNODE_PATH(crfsdt_pnode)))
        {
            dbg_log(SEC_0142_CRFSDT, 6)(LOGSTDOUT, "info:crfsdt_has_pnode: path %s is close to pnode %s\n",
                                (char *)cstring_get_str(path),
                                CRFSDT_PNODE_PATH_STR(crfsdt_pnode)
                                );
            return (EC_FALSE);
        }
        return crfsdt_pnode_has_tcid(crfsdt_pnode, tcid);
    }

    return (EC_FALSE);
}

EC_BOOL crfsdt_has_rnode(const CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    CRFSDT_RNODE *crfsdt_rnode;

    crfsdt_rnode = crfsdt_search_rnode(crfsdt, tcid);
    if(NULL_PTR != crfsdt_rnode)
    {
        dbg_log(SEC_0142_CRFSDT, 9)(LOGSTDOUT, "[DEBUG] crfsdt_has_rnode: has no rnode for tcid %s\n",
                            c_word_to_ipv4(tcid));

        return crfsdt_rnode_has_path(crfsdt_rnode, path);
    }

    return (EC_FALSE);
}

EC_BOOL crfsdt_has(const CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path)
{
    if(EC_FALSE == crfsdt_has_pnode(crfsdt, tcid, path))
    {
        dbg_log(SEC_0142_CRFSDT, 9)(LOGSTDOUT, "error:crfsdt_has: has no pnode for tcid %s, path %s\n",
                            c_word_to_ipv4(tcid), (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsdt_has_rnode(crfsdt, tcid, path))
    {
        dbg_log(SEC_0142_CRFSDT, 9)(LOGSTDOUT, "error:crfsdt_has: has no rnode for tcid %s, path %s\n",
                            c_word_to_ipv4(tcid), (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CRFSDT_PNODE *crfsdt_lookup_pnode(const CRFSDT *crfsdt, const CSTRING *path)
{
    CRFSDT_PNODE  crfsdt_pnode_t;
    CRFSDT_PNODE *crfsdt_pnode;
    CRB_NODE     *crb_node;

    crfsdt_pnode_init(&crfsdt_pnode_t);
    crfsdt_pnode_set_path(&crfsdt_pnode_t, path);

    crb_node = crb_tree_search_data(CRFSDT_PNODE_TREE(crfsdt), (void *)&crfsdt_pnode_t);
    if(NULL_PTR == crb_node)
    {
        crfsdt_pnode_clean(&crfsdt_pnode_t);
        return (NULL_PTR);
    }

    crfsdt_pnode_clean(&crfsdt_pnode_t);

    crfsdt_pnode = (CRFSDT_PNODE *)CRB_NODE_DATA(crb_node);

    if(cstring_get_len(path) < cstring_get_len(CRFSDT_PNODE_PATH(crfsdt_pnode)))
    {
        dbg_log(SEC_0142_CRFSDT, 6)(LOGSTDOUT, "info:crfsdt_lookup_pnode: path %s is close to pnode %s\n",
                            (char *)cstring_get_str(path),
                            CRFSDT_PNODE_PATH_STR(crfsdt_pnode)
                            );
        return (NULL_PTR);
    }
    return (crfsdt_pnode);
}

EC_BOOL crfsdt_flush(const CRFSDT *crfsdt, int fd, UINT32 *offset)
{
    if(EC_FALSE == crb_tree_flush(CRFSDT_PNODE_TREE(crfsdt), fd, offset, (CRB_DATA_FLUSH)crfsdt_pnode_flush))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_flush: flush pnode tree at offset %u of fd %d failed\n",
                           (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crb_tree_flush(CRFSDT_RNODE_TREE(crfsdt), fd, offset, (CRB_DATA_FLUSH)crfsdt_rnode_flush))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_flush: flush rnode tree at offset %u of fd %d failed\n",
                           (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdt_load(CRFSDT *crfsdt, int fd, UINT32 *offset)
{
    if(EC_FALSE == crb_tree_load(CRFSDT_PNODE_TREE(crfsdt), fd, offset, (CRB_DATA_NEW)crfsdt_pnode_new, (CRB_DATA_LOAD)crfsdt_pnode_load))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_load: load pnode tree at offset %u of fd %d failed\n",
                           (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == crb_tree_load(CRFSDT_RNODE_TREE(crfsdt), fd, offset, (CRB_DATA_NEW)crfsdt_rnode_new, (CRB_DATA_LOAD)crfsdt_rnode_load))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_load: load rnode tree at offset %u of fd %d failed\n",
                           (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsdt_clone(const CRFSDT *crfsdt_src, CRFSDT *crfsdt_des)
{
    if(EC_FALSE == crb_tree_clone(CRFSDT_PNODE_TREE(crfsdt_src), CRFSDT_PNODE_TREE(crfsdt_des), (CRB_DATA_NEW)crfsdt_pnode_new, (CRB_DATA_CLONE)crfsdt_pnode_clone))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_clone: clone pnode tree failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crb_tree_clone(CRFSDT_RNODE_TREE(crfsdt_src), CRFSDT_RNODE_TREE(crfsdt_des), (CRB_DATA_NEW)crfsdt_rnode_new, (CRB_DATA_CLONE)crfsdt_rnode_clone))
    {
        dbg_log(SEC_0142_CRFSDT, 0)(LOGSTDOUT, "error:crfsdt_clone: clone rnode tree failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

