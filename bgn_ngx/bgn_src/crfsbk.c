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
#include <sys/mman.h>
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
#include "cstring.h"
#include "cmisc.h"
#include "clist.h"
#include "crb.h"
#include "chashalgo.h"
#include "cdsk.h"
#include "cstack.h"
#include "cmd5.h"
#include "crb.h"
#include "cpgrb.h"
#include "cpgd.h"
#include "crfsnprb.h"
#include "crfsnp.inc"
#include "crfsnp.h"
#include "crfsbk.h"
#include "crfs.h"
#include "task.h"
#include "cmpie.h"

CRFSOP *crfsop_new()
{
    CRFSOP *crfsop;

    alloc_static_mem(MM_CRFSOP, &crfsop, LOC_CRFSBK_0001);
    if(NULL_PTR == crfsop)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_new: new crfsop failed\n");
        return (NULL_PTR);
    }

    crfsop_init(crfsop);
    return (crfsop);
}

EC_BOOL crfsop_init(CRFSOP *crfsop)
{
    CRFSOP_OP_TYPE(crfsop)   = CRFSOP_ERR_OP;
    CRFSOP_PATH_TYPE(crfsop) = CRFSOP_PATH_IS_ERR;
    CRFSOP_PATH_HASH(crfsop) = 0;

    cstring_init(CRFSOP_PATH_NAME(crfsop), NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL crfsop_clean(CRFSOP *crfsop)
{
    CRFSOP_OP_TYPE(crfsop)   = CRFSOP_ERR_OP;
    CRFSOP_PATH_TYPE(crfsop) = CRFSOP_PATH_IS_ERR;
    CRFSOP_PATH_HASH(crfsop) = 0;

    cstring_clean(CRFSOP_PATH_NAME(crfsop));

    return (EC_TRUE);
}

EC_BOOL crfsop_free(CRFSOP *crfsop)
{
    if(NULL_PTR != crfsop)
    {
        crfsop_clean(crfsop);
        free_static_mem(MM_CRFSOP, crfsop, LOC_CRFSBK_0002);
    }
    return (EC_TRUE);
}

EC_BOOL crfsop_set(CRFSOP *crfsop, const uint16_t op_type, const uint16_t path_type, const CSTRING *path)
{
    CRFSOP_OP_TYPE(crfsop)   = op_type;
    CRFSOP_PATH_TYPE(crfsop) = path_type;
    CRFSOP_PATH_HASH(crfsop) = (uint32_t)JS_hash(cstring_get_len(path), cstring_get_str(path));

    cstring_clone(path, CRFSOP_PATH_NAME(crfsop));
    return (EC_TRUE);
}

CRFSOP *crfsop_make(const uint16_t op_type, const uint16_t path_type, const CSTRING *path)
{
    CRFSOP *crfsop;

    crfsop = crfsop_new();
    if(NULL_PTR == crfsop)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsop_make: new crfsop failed\n");
        return (NULL_PTR);
    }

    crfsop_set(crfsop, op_type, path_type, path);

    return (crfsop);
}

int crfsop_cmp(const CRFSOP *crfsop_1st, const CRFSOP *crfsop_2nd)
{
    int ret;

    /*compare (path hash, path len, path str)*/
    if(CRFSOP_PATH_HASH(crfsop_1st) > CRFSOP_PATH_HASH(crfsop_2nd))
    {
        return (1);
    }

    if(CRFSOP_PATH_HASH(crfsop_1st) < CRFSOP_PATH_HASH(crfsop_2nd))
    {
        return (-1);
    }

    if(CRFSOP_PATH_LEN(crfsop_1st) > CRFSOP_PATH_LEN(crfsop_2nd))
    {
        return (1);
    }

    if(CRFSOP_PATH_LEN(crfsop_1st) < CRFSOP_PATH_LEN(crfsop_2nd))
    {
        return (-1);
    }

    ret = BCMP(CRFSOP_PATH_STR(crfsop_1st), CRFSOP_PATH_STR(crfsop_2nd), CRFSOP_PATH_LEN(crfsop_2nd));

    return (ret);
}

STATIC_CAST static const char *__crfsop_op_type(const uint16_t crfs_op)
{
    switch(crfs_op)
    {
        case CRFSOP_WR_REG_OP:
            return (const char *)"WR_REG";

        case CRFSOP_WR_BIG_OP:
            return (const char *)"WR_BIG";

        case CRFSOP_RM_REG_OP:
            return (const char *)"RM_REG";

        case CRFSOP_RM_BIG_OP:
            return (const char *)"RM_BIG";

        case CRFSOP_RM_DIR_OP:
            return (const char *)"RM_DIR";

        case CRFSOP_WR_REG_OP | CRFSOP_RM_REG_OP:
            return (const char *)"WR_REG|RM_REG";

        case CRFSOP_WR_REG_OP | CRFSOP_RM_DIR_OP:
            return (const char *)"WR_REG|RM_DIR";

        case CRFSOP_ERR_OP:
            return (const char *)"ERR";

        default:
            /*fall through*/
            break;
    }

    return (const char *)"unknow";
}

STATIC_CAST static const char *__crfsop_path_type(const uint16_t path_type)
{
    switch(path_type)
    {
        case CRFSOP_PATH_IS_REG:
            return (const char *)"REG";

        case CRFSOP_PATH_IS_BIG:
            return (const char *)"BIG";

        case CRFSOP_PATH_IS_DIR:
            return (const char *)"DIR";

        case CRFSOP_PATH_IS_ERR:
            return (const char *)"ERR";

        default:
            /*fall through*/
            break;
    }

    return (const char *)"unknow";
}

void crfsop_print(LOG *log, const CRFSOP *crfsop)
{
    sys_log(log, "crfsop %p: op %s, path [%s] %s, hash %x\n", crfsop,
                 __crfsop_op_type(CRFSOP_OP_TYPE(crfsop)),
                 __crfsop_path_type(CRFSOP_PATH_TYPE(crfsop)),
                 CRFSOP_PATH_STR(crfsop),
                 CRFSOP_PATH_HASH(crfsop));
    return;
}

STATIC_CAST static int __crfsop_clist_data_cmp(const CLIST_DATA *clist_data_1st, const CLIST_DATA *clist_data_2nd)
{
    return crfsop_cmp(CLIST_DATA_DATA(clist_data_1st), CLIST_DATA_DATA(clist_data_2nd));
}

STATIC_CAST static EC_BOOL __crfsop_clist_data_free(CLIST_DATA *clist_data)
{
    return crfsop_free(CLIST_DATA_DATA(clist_data));
}

STATIC_CAST static void __crfsop_clist_data_print(LOG *log, const CLIST_DATA *clist_data)
{
    crfsop_print(log, CLIST_DATA_DATA(clist_data));
    return;
}

EC_BOOL crfsoprec_init(CRFSOPREC *crfsoprec, const char *fname)
{
    cstring_init(CRFSOPREC_FILE(crfsoprec), (uint8_t *)fname);
    clist_init(CRFSOPREC_LIST(crfsoprec), MM_CRFSOP, LOC_CRFSBK_0003);

    crb_tree_init(CRFSOPREC_TREE(crfsoprec),
                  (CRB_DATA_CMP)__crfsop_clist_data_cmp,
                  /*(CRB_DATA_FREE)__crfsop_clist_data_free*/NULL_PTR, /*tree only record CLIST_DATA pointer info*/
                  (CRB_DATA_PRINT)__crfsop_clist_data_print);
    return (EC_TRUE);
}

EC_BOOL crfsoprec_clean(CRFSOPREC *crfsoprec)
{
    cstring_clean(CRFSOPREC_FILE(crfsoprec));
    clist_clean(CRFSOPREC_LIST(crfsoprec), (CLIST_DATA_DATA_CLEANER)crfsop_free);
    crb_tree_clean(CRFSOPREC_TREE(crfsoprec));
    return (EC_TRUE);
}

CLIST_DATA *crfsoprec_fetch(CRFSOPREC *crfsoprec, CRFSOP *crfsop)
{
    CRB_NODE   *crb_node;
    CLIST_DATA  clist_data_t;

    CLIST_DATA_DATA(&clist_data_t) = (void *)crfsop;

    crb_node = crb_tree_search_data(CRFSOPREC_TREE(crfsoprec), (void *)&clist_data_t);
    if(NULL_PTR == crb_node)
    {
        //dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_fetch: search crfsop in tree failed\n");
        return (NULL_PTR);
    }

    return (CLIST_DATA *)CRB_NODE_DATA(crb_node);
}

CLIST_DATA *crfsoprec_get(CRFSOPREC *crfsoprec, const uint16_t op_type, const uint16_t path_type, const CSTRING *path)
{
    CRFSOP     *crfsop;
    CLIST_DATA *clist_data;

    crfsop = crfsop_make(op_type, path_type, path);
    if(NULL_PTR == crfsop)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_get: make crfsop failed\n");
        return (NULL_PTR);
    }

    clist_data = crfsoprec_fetch(crfsoprec, crfsop);
    if(NULL_PTR == clist_data)
    {
        //dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_get: search crfsop in tree failed\n");
        crfsop_free(crfsop);
        return (NULL_PTR);
    }

    crfsop_free(crfsop);

    return (clist_data);
}

EC_BOOL crfsoprec_push(CRFSOPREC *crfsoprec, const uint16_t op_type, const uint16_t path_type, const CSTRING *path)
{
    CLIST_DATA *clist_data;
    CRFSOP     *crfsop;
    CRB_NODE   *crb_node;

    clist_data = crfsoprec_get(crfsoprec, op_type, path_type, path);
    if(NULL_PTR != clist_data)/*exist*/
    {
        /*update*/
        crfsop = (CRFSOP *)CLIST_DATA_DATA(clist_data);

        CRFSOP_OP_TYPE(crfsop)   |= op_type;
        CRFSOP_PATH_TYPE(crfsop)  = path_type;

        /*move list node from current to tail (latest)*/
        clist_move_back(CRFSOPREC_LIST(crfsoprec), clist_data);

        return (EC_TRUE);
    }

    crfsop = crfsop_make(op_type, path_type, path);
    if(NULL_PTR == crfsop)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_push: make crfsop failed\n");
        return (EC_FALSE);
    }

    /*add to tail*/
    clist_data = clist_push_back(CRFSOPREC_LIST(crfsoprec), (void *)crfsop);

    /*insert to tree*/
    crb_node = crb_tree_insert_data(CRFSOPREC_TREE(crfsoprec), (void *)clist_data);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_push: insert clist_data to tree failed\n");

        clist_rmv(CRFSOPREC_LIST(crfsoprec), clist_data);
        crfsop_free(crfsop);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != (void *)clist_data)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_push: (hash %x, path %s) already exist in tree\n",
                            CRFSOP_PATH_HASH(crfsop), CRFSOP_PATH_STR(crfsop));

        clist_rmv(CRFSOPREC_LIST(crfsoprec), clist_data);
        crfsop_free(crfsop);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CRFSOP *crfsoprec_pop(CRFSOPREC *crfsoprec)
{
    CRFSOP     *crfsop;
    CLIST_DATA  clist_data_t;

    crfsop = clist_pop_front(CRFSOPREC_LIST(crfsoprec));
    if(NULL_PTR == crfsop)
    {
        return (NULL_PTR);
    }

    CLIST_DATA_DATA(&clist_data_t) = (void *)crfsop;

    if(EC_FALSE == crb_tree_delete_data(CRFSOPREC_TREE(crfsoprec), (void *)&clist_data_t))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_pop: delete crfsop %p in tree failed\n", crfsop);

        //crfsop_free(crfsop);/*free crfsop*/
        //return (NULL_PTR);
        return (crfsop);
    }

    return (crfsop);
}

EC_BOOL crfsoprec_rmv(CRFSOPREC *crfsoprec, const CRFSOP *crfsop)
{
    CLIST_DATA  clist_data_t;
    CLIST_DATA *clist_data;
    CRB_NODE   *crb_node;
    CRFSOP     *crfsop_t;

    CLIST_DATA_DATA(&clist_data_t) = (void *)crfsop;

    crb_node = crb_tree_search_data(CRFSOPREC_TREE(crfsoprec), (void *)&clist_data_t);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_rmv: search crfsop in tree failed\n");
        return (EC_FALSE);
    }

    clist_data = (CLIST_DATA *)CRB_NODE_DATA(crb_node);

    /*remove from tree*/
    crb_tree_delete(CRFSOPREC_TREE(crfsoprec), crb_node);

    /*remove from list*/
    crfsop_t = (CRFSOP *)clist_rmv(CRFSOPREC_LIST(crfsoprec), clist_data);

    /*free crfsop*/
    crfsop_free(crfsop_t);
    return (EC_TRUE);
}

EC_BOOL crfsoprec_del(CRFSOPREC *crfsoprec, const uint16_t op_type, const uint16_t path_type, const CSTRING *path)
{
    CRFSOP *crfsop;

    crfsop = crfsop_make(op_type, path_type, path);
    if(NULL_PTR == crfsop)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_del: make crfsop failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsoprec_rmv(crfsoprec, crfsop))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_del: rmv crfsop failed\n");
        crfsop_free(crfsop);
        return (EC_FALSE);
    }

    crfsop_free(crfsop);

    return (EC_TRUE);
}

void crfsoprec_print(LOG *log, const CRFSOPREC *crfsoprec)
{
    clist_print(log, CRFSOPREC_LIST(crfsoprec), (CLIST_DATA_DATA_PRINT)crfsop_print);
    crb_postorder_print(log, CRFSOPREC_TREE(crfsoprec));
    //crb_preorder_print(log, CRFSOPREC_TREE(crfsoprec));
    //crb_tree_print(log, CRFSOPREC_TREE(crfsoprec));
    return;
}

EC_BOOL crfsoprec_export(const CRFSOPREC *crfsoprec)
{
    UINT32   esize; /*encode size*/
    UINT32   pos;
    char    *fname;
    uint8_t *ftext;
    int      fd;

    fname = (char *)cstring_get_str(CRFSOPREC_FILE(crfsoprec));
    fd = c_file_open(fname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_export: open file %s failed\n", fname);
        return (EC_FALSE);
    }

    esize = 0;
    cmpi_encode_clist_size(CMPI_ANY_COMM, CRFSOPREC_LIST(crfsoprec), &esize);

    if(EC_FALSE == c_file_truncate(fd, esize))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_export: truncate file %s to size %ld failed\n",
                           fname, esize);
        c_file_close(fd);
        return (EC_FALSE);
    }

    ftext = (uint8_t *)mmap(NULL_PTR, esize, PROT_WRITE, MAP_SHARED, fd, 0);
    if(MAP_FAILED == ftext)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_export: mmap file %s failed, errno = %d, errorstr = %s\n",
                           fname, errno, strerror(errno));
        c_file_close(fd);
        return (EC_FALSE);
    }

    pos = 0;
    cmpi_encode_clist(CMPI_ANY_COMM, CRFSOPREC_LIST(crfsoprec), ftext, esize, &pos);
    ASSERT(pos == esize);

    if(0 != msync(ftext, esize, MS_SYNC))
    {
        dbg_log(SEC_0141_CRFSBK, 1)(LOGSTDOUT, "warn:crfsoprec_export: sync file %s failed\n", fname);
    }

    if(0 != munmap(ftext, esize))
    {
        dbg_log(SEC_0141_CRFSBK, 1)(LOGSTDOUT, "warn:crfsoprec_export: munmap file %s failed\n", fname);
    }

    c_file_close(fd);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsoprec_export: export %ld bytes to file %s\n", esize, fname);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsoprec_import_to_tree(CRFSOPREC *crfsoprec)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CRFSOPREC_LIST(crfsoprec), LOC_CRFSBK_0004);
    CLIST_LOOP_NEXT(CRFSOPREC_LIST(crfsoprec), clist_data)
    {
        /*insert to tree*/
        if(NULL_PTR == crb_tree_insert_data(CRFSOPREC_TREE(crfsoprec), (void *)clist_data))
        {
            CLIST_UNLOCK(CRFSOPREC_LIST(crfsoprec), LOC_CRFSBK_0005);
            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:__crfsoprec_import_to_tree: insert clist_data to tree failed\n");
            return (EC_FALSE);
        }
    }
    CLIST_UNLOCK(CRFSOPREC_LIST(crfsoprec), LOC_CRFSBK_0006);
    return (EC_TRUE);
}
EC_BOOL crfsoprec_import(CRFSOPREC *crfsoprec)
{
    UINT32   fsize; /*encode size*/
    UINT32   pos;
    char    *fname;
    uint8_t *ftext;
    int      fd;

    fname = (char *)cstring_get_str(CRFSOPREC_FILE(crfsoprec));

    if(EC_FALSE == c_file_access(fname, F_OK))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_import: file %s not exist\n", fname);
        return (EC_FALSE);
    }

    fd = c_file_open(fname, O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_import: open file %s failed\n", fname);

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_import: get size of file %s failed\n", fname);
        c_file_close(fd);
        return (EC_FALSE);
    }

    ftext = (uint8_t *)mmap(NULL_PTR, fsize, PROT_READ, MAP_SHARED, fd, 0);
    if(MAP_FAILED == ftext)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_import: mmap file %s failed, errno = %d, errorstr = %s\n",
                           fname, errno, strerror(errno));
        c_file_close(fd);
        return (EC_FALSE);
    }

    pos = 0;
    cmpi_decode_clist(CMPI_ANY_COMM, ftext, fsize, &pos, CRFSOPREC_LIST(crfsoprec));
    ASSERT(pos == fsize);

    c_file_close(fd);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsoprec_import: import %ld bytes from file %s\n", fsize, fname);

    /*import to tree*/
    if(EC_FALSE == __crfsoprec_import_to_tree(crfsoprec))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsoprec_import: file %s export list to tree failed\n", fname);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CRFSBK *crfsbk_open(const UINT32 crfs_md_id, const char *np_root_dir, const char *dn_root_dir, const uint32_t np_id, const char *crfs_op_fname)
{
    CRFSBK   *crfsbk;

    CRFSNP   *crfsnp;
    CRFSDN   *crfsdn;

    crfsnp = crfsnp_open(np_root_dir, np_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_open: open np %u from %s failed\n",
                           np_id, np_root_dir);
        return (NULL_PTR);
    }

    crfsdn = crfsdn_open(dn_root_dir);
    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_open: open dn %s failed\n",
                           dn_root_dir);
        crfsnp_close(crfsnp);
        return (NULL_PTR);
    }

    crfsbk = (CRFSBK *)safe_malloc(sizeof(CRFSBK), LOC_CRFSBK_0007);
    if(NULL_PTR == crfsbk)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_open: new crfsbk failed\n");

        crfsnp_close(crfsnp);
        crfsdn_close(crfsdn);
        return (NULL_PTR);
    }

    crfsoprec_init(CRFSBK_OP_REC(crfsbk), crfs_op_fname);
    crfsoprec_import(CRFSBK_OP_REC(crfsbk));

    CRFSBK_CRFS_MD_ID(crfsbk) = crfs_md_id;
    CRFSBK_NP(crfsbk)         = crfsnp;
    CRFSBK_DN(crfsbk)         = crfsdn;

    CRFSBK_INIT_LOCK(crfsbk, LOC_CRFSBK_0008);

    return (crfsbk);
}

CRFSBK *crfsbk_new(const UINT32 crfs_md_id, const char *np_root_dir, const char *dn_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const char *crfs_op_fname)
{
    CRFSBK *crfsbk;

    crfsbk = (CRFSBK *)safe_malloc(sizeof(CRFSBK), LOC_CRFSBK_0009);
    if(NULL_PTR == crfsbk)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_new: new crfsbk failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == crfsbk_init(crfsbk, crfs_md_id, np_root_dir, dn_root_dir, np_id, np_model, hash_2nd_algo_id, crfs_op_fname))
    {
        safe_free(crfsbk, LOC_CRFSBK_0010);
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_new: init crfsbk failed\n");
        return (NULL_PTR);
    }

    return (crfsbk);
}

EC_BOOL crfsbk_init(CRFSBK *crfsbk, const UINT32 crfs_md_id, const char *np_root_dir, const char *dn_root_dir, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const char *crfs_op_fname)
{
    CRFSNP  *crfsnp;
    CRFSDN  *crfsdn;

    crfsnp = crfsnp_create(np_root_dir, np_id, np_model, hash_2nd_algo_id);
    if(NULL_PTR == crfsnp)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_init: create np %u with model %u, hash %u failed\n",
                           np_id, np_model, hash_2nd_algo_id);
        return (EC_FALSE);
    }

    crfsdn = crfsdn_create(dn_root_dir);
    if(NULL_PTR == crfsdn)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_init: create dn failed\n");
        crfsnp_free(crfsnp);
        return (EC_FALSE);
    }

    crfsoprec_init(CRFSBK_OP_REC(crfsbk), crfs_op_fname);
    crfsoprec_import(CRFSBK_OP_REC(crfsbk));

    CRFSBK_CRFS_MD_ID(crfsbk) = crfs_md_id;
    CRFSBK_NP(crfsbk)         = crfsnp;
    CRFSBK_DN(crfsbk)         = crfsdn;

    CRFSBK_INIT_LOCK(crfsbk, LOC_CRFSBK_0011);

    return (EC_TRUE);
}

EC_BOOL crfsbk_clean(CRFSBK *crfsbk)
{
    ASSERT(NULL_PTR != crfsbk);

    if(NULL_PTR != CRFSBK_NP(crfsbk))
    {
        crfsnp_close(CRFSBK_NP(crfsbk));
        CRFSBK_NP(crfsbk) = NULL_PTR;
    }

    if(NULL_PTR != CRFSBK_DN(crfsbk))
    {
        crfsdn_close(CRFSBK_DN(crfsbk));
        CRFSBK_DN(crfsbk) = NULL_PTR;
    }

    crfsoprec_export(CRFSBK_OP_REC(crfsbk));

    crfsoprec_clean(CRFSBK_OP_REC(crfsbk));

    CRFSBK_CLEAN_LOCK(crfsbk, LOC_CRFSBK_0012);

    return (EC_TRUE);
}

EC_BOOL crfsbk_free(CRFSBK *crfsbk)
{
    if(NULL_PTR != crfsbk)
    {
        crfsbk_clean(crfsbk);
        safe_free(crfsbk, LOC_CRFSBK_0013);
    }

    return (EC_TRUE);
}

EC_BOOL crfsbk_add_disk(CRFSBK *crfsbk, const uint16_t disk_no)
{
    if(EC_FALSE == crfsdn_add_disk(CRFSBK_DN(crfsbk), disk_no))
    {
        sys_log(LOGSTDOUT, "error:crfsbk_add_disk: add disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CRFSNP_FNODE *crfsbk_reserve_np_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, uint32_t *node_pos)
{
    CRFSNP *crfsnp;
    CRFSNP_ITEM *crfsnp_item;
    uint32_t node_pos_t;

    crfsnp = CRFSBK_NP(crfsbk);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_reserve_np_no_lock: set np beg\n");

    node_pos_t = crfsnp_insert(crfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(CRFSNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_reserve_np_no_lock: insert file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_reserve_np_no_lock: insert file %s to node_pos %u done\n",
                        (char *)cstring_get_str(file_path), node_pos_t);

    crfsnp_item = crfsnp_fetch(crfsnp, node_pos_t);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_reserve_np_no_lock: set np end\n");

    if(CRFSNP_ITEM_FILE_IS_REG != CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_reserve_np_no_lock: file path %s is not regular file\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    CRFSNP_ITEM_CREATE_TIME(crfsnp_item) = task_brd_default_get_time();

    if(do_log(SEC_0141_CRFSBK, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfsbk_reserve_np_no_lock: reserved crfsnp_item %p is\n", crfsnp_item);
        crfsnp_item_print(LOGSTDOUT, crfsnp_item);
    }

    (*node_pos) = node_pos_t;

    /*not import yet*/
    return CRFSNP_ITEM_FNODE(crfsnp_item);
}

EC_BOOL crfsbk_release_np_no_lock(CRFSBK *crfsbk, const CSTRING *file_path)
{
    CRFSNP *crfsnp;

    crfsnp = CRFSBK_NP(crfsbk);

    if(EC_FALSE == crfsnp_delete(crfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_release_np_no_lock: delete file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "[DEBUG] crfsbk_release_np_no_lock: delete file %s done\n",
                        (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL crfsbk_reserve_dn_no_lock(CRFSBK *crfsbk, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CRFSDN   *crfsdn;

    crfsdn = CRFSBK_DN(crfsbk);

    if(EC_FALSE == cpgv_new_space(CRFSDN_CPGV(crfsdn), size, disk_no, block_no, page_no))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_reserve_dn_no_lock: new %u bytes space from vol failed\n", size);
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_reserve_dn_no_lock: new %u bytes space from vol at disk %u, block %u, page %u done\n",
                        size, (*disk_no), (*block_no), (*page_no));

    return (EC_TRUE);
}

EC_BOOL crfsbk_release_dn_no_lock(CRFSBK *crfsbk, const uint32_t size, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no)
{
    CRFSDN   *crfsdn;

    crfsdn = CRFSBK_DN(crfsbk);

    if(EC_FALSE == cpgv_free_space(CRFSDN_CPGV(crfsdn), disk_no, block_no, page_no, size))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_release_dn_no_lock: release space of disk %u, block %u, page %u, size %u failed\n",
                           disk_no, block_no, page_no, size);
        return (EC_FALSE);
    }
    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_release_dn_no_lock: release space of disk %u, block %u, page %u, size %u done\n",
                       disk_no, block_no, page_no, size);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __crfsbk_release_dn_no_lock(CRFSBK *crfsbk, const CRFSNP_FNODE *crfsnp_fnode)
{
    const CRFSNP_INODE *crfsnp_inode;

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);

    /*note: disk_no was ignored*/
    return crfsbk_release_dn_no_lock(crfsbk,
                                     CRFSNP_FNODE_FILESZ(crfsnp_fnode),
                                     CRFSNP_INODE_DISK_NO(crfsnp_inode),
                                     CRFSNP_INODE_BLOCK_NO(crfsnp_inode),
                                     CRFSNP_INODE_PAGE_NO(crfsnp_inode));
}

/*for debug only*/
REAL crfsbk_room_ratio(CRFSBK *crfsbk)
{
    CRFSDN   *crfsdn;
    CPGV     *cpgv;
    double    ratio;

    crfsdn = CRFSBK_DN(crfsbk);
    cpgv   = CRFSDN_CPGV(crfsdn);

    ratio = (CPGV_PAGE_USED_NUM(cpgv) + 0.0) / (CPGV_PAGE_MAX_NUM(cpgv)  + 0.0);
    return (ratio);
}

EC_BOOL crfsbk_room_is_ok_no_lock(CRFSBK *crfsbk, const REAL level)
{
    CRFSNP   *crfsnp;
    CRFSDN   *crfsdn;
    CPGV     *cpgv;

    uint64_t  used_size;
    uint64_t  max_size;
    uint64_t  del_size;
    double    ratio;

    crfsnp = CRFSBK_NP(crfsbk);
    crfsdn = CRFSBK_DN(crfsbk);
    cpgv   = CRFSDN_CPGV(crfsdn);

    used_size = (((uint64_t)CPGV_PAGE_USED_NUM(cpgv)) << CPGB_PAGE_BIT_SIZE);
    max_size  = (((uint64_t)CPGV_PAGE_MAX_NUM(cpgv)) << CPGB_PAGE_BIT_SIZE);
    del_size  = CRFSNP_DEL_SIZE(crfsnp);

    if(used_size < del_size)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_room_is_ok_no_lock: invalid used size %ld < del size %ld\n",
                           used_size, del_size);
        return (EC_FALSE);
    }

    ratio = (used_size + 0.0 - del_size) / (max_size  + 0.0);

    if(ratio < level)
    {
        return (EC_TRUE); /*ok*/
    }
    return (EC_FALSE);/*NOT ok*/
}

EC_BOOL crfsbk_write_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum)
{
    CRFSNP_FNODE *crfsnp_fnode;
    CRFSNP_INODE *crfsnp_inode;

    uint32_t node_pos;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;

    crfsnp_fnode = crfsbk_reserve_np_no_lock(crfsbk, file_path, &node_pos);
    if(NULL_PTR == crfsnp_fnode)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_write_no_lock: file %s reserve np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    size = (uint32_t)cbytes_len(cbytes);

    if(EC_FALSE == crfsbk_reserve_dn_no_lock(crfsbk, size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_write_no_lock: file %s reserve dn with size %u failed\n",
                           (char *)cstring_get_str(file_path), size);
        crfsbk_release_np_no_lock(crfsbk, file_path);
        return (EC_FALSE);
    }

    /*init crfsnp_fnode*/
    crfsnp_fnode_init(crfsnp_fnode);
    CRFSNP_FNODE_FILESZ(crfsnp_fnode) = size;
    CRFSNP_FNODE_REPNUM(crfsnp_fnode) = 1;

    if(SWITCH_ON == CRFS_MD5_SWITCH)
    {
        BCOPY(md5sum, CRFSNP_FNODE_MD5SUM(crfsnp_fnode), CMD5_DIGEST_LEN);
    }

    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    CRFSNP_INODE_CACHE_FLAG(crfsnp_inode) = CRFSDN_DATA_NOT_IN_CACHE;
    CRFSNP_INODE_DISK_NO(crfsnp_inode)    = disk_no;
    CRFSNP_INODE_BLOCK_NO(crfsnp_inode)   = block_no;
    CRFSNP_INODE_PAGE_NO(crfsnp_inode)    = page_no;

    /*add to diskcache*/
    offset  = (((UINT32)(page_no)) << (CPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == crfsdn_write_o(CRFSBK_DN(crfsbk), cbytes_len(cbytes), CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_write_no_lock: write %ld bytes to disk %u block %u page %u failed\n",
                            cbytes_len(cbytes), disk_no, block_no, page_no);

        crfs_release_dn(CRFSBK_CRFS_MD_ID(crfsbk), crfsnp_fnode);
        crfsbk_release_np_no_lock(crfsbk, file_path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_write_no_lock: file %s write to disk %u block %u page %u done\n",
                       (char *)cstring_get_str(file_path), disk_no, block_no, page_no);

    return (EC_TRUE);
}

EC_BOOL crfsbk_read_np_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFSNP *crfsnp;

    uint32_t node_pos;

    crfsnp = CRFSBK_NP(crfsbk);

    node_pos = crfsnp_search_no_lock(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_REG);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        crfsnp_fnode_import(CRFSNP_ITEM_FNODE(crfsnp_item), crfsnp_fnode);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL crfsbk_read_np_b_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode)
{
    CRFSNP *crfsnp;

    uint32_t node_pos;

    crfsnp = CRFSBK_NP(crfsbk);

    node_pos = crfsnp_search_no_lock(crfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CRFSNP_ITEM_FILE_IS_BIG);
    if(CRFSNPRB_ERR_POS != node_pos)
    {
        CRFSNP_ITEM *crfsnp_item;

        crfsnp_item = crfsnp_fetch(crfsnp, node_pos);
        crfsnp_fnode_import(CRFSNP_ITEM_FNODE(crfsnp_item), crfsnp_fnode);

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL crfsbk_read_dn_no_lock(CRFSBK *crfsbk, const CRFSNP_FNODE *crfsnp_fnode, CBYTES *cbytes)
{
    const CRFSNP_INODE *crfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    UINT32   offset;
    UINT32   data_len;

    file_size    = CRFSNP_FNODE_FILESZ(crfsnp_fnode);
    crfsnp_inode = CRFSNP_FNODE_INODE(crfsnp_fnode, 0);
    disk_no  = CRFSNP_INODE_DISK_NO(crfsnp_inode);
    block_no = CRFSNP_INODE_BLOCK_NO(crfsnp_inode);
    page_no  = CRFSNP_INODE_PAGE_NO(crfsnp_inode) ;

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CRFSBK_0014);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CRFSBK_0015);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    offset  = (((UINT32)page_no) << (CPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == crfsdn_read_o(CRFSBK_DN(crfsbk), disk_no, block_no, offset, file_size, CBYTES_BUF(cbytes), &data_len))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_read_dn_no_lock: read %u bytes from disk %u block %u page %u failed\n",
                           file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    CBYTES_LEN(cbytes) = data_len;

    return (EC_TRUE);
}

EC_BOOL crfsbk_read_no_lock(CRFSBK *crfsbk, const CSTRING *file_path, CBYTES *cbytes)
{
    CRFSNP_FNODE crfsnp_fnode;

    crfsnp_fnode_init(&crfsnp_fnode);

    if(EC_FALSE == crfsbk_read_np_no_lock(crfsbk, file_path, &crfsnp_fnode))
    {
        dbg_log(SEC_0141_CRFSBK, 5)(LOGSTDOUT, "warn:crfsbk_read_no_lock: read file %s from np failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == crfsbk_read_dn_no_lock(crfsbk, &crfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_read_dn_no_lock: read file %s from dn failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfsbk_retire_no_lock(CRFSBK *crfsbk)
{
    return (EC_TRUE);
}

EC_BOOL crfsbk_recycle_no_lock(CRFSBK *crfsbk, const UINT32 max_num, UINT32 *complete_num)
{
    CRFSNP     *crfsnp;
    CRFSNP_RECYCLE_DN crfsnp_recycle_dn;

    crfsnp     = CRFSBK_NP(crfsbk);

    CRFSNP_RECYCLE_DN_ARG1(&crfsnp_recycle_dn)   = (UINT32)crfsbk;
    CRFSNP_RECYCLE_DN_FUNC(&crfsnp_recycle_dn)   = (CRFSNP_RECYCLE_DN_FUNC)__crfsbk_release_dn_no_lock;
    //CRFSNP_RECYCLE_DN_WRLOCK(&crfsnp_recycle_dn) = NULL_PTR;
    //CRFSNP_RECYCLE_DN_UNLOCK(&crfsnp_recycle_dn) = NULL_PTR;

    if(EC_FALSE == crfsnp_recycle(crfsnp, max_num, NULL_PTR, &crfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_recycle_no_lock: recycle failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfsbk_write(CRFSBK *crfsbk, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum)
{
    CRFSBK_WRLOCK(crfsbk, LOC_CRFSBK_0016);
    if(EC_FALSE == crfsbk_write_no_lock(crfsbk, file_path, cbytes, md5sum))
    {
        CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0017);
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_write: write %s with %ld bytes failed\n",
                           (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        return (EC_FALSE);
    }
    CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0018);

    crfsoprec_push(CRFSBK_OP_REC(crfsbk), CRFSOP_WR_REG_OP, CRFSOP_PATH_IS_REG, file_path);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_write: write %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL crfsbk_read(CRFSBK *crfsbk, const CSTRING *file_path, CBYTES *cbytes)
{
    CRFSBK_RDLOCK(crfsbk, LOC_CRFSBK_0019);
    if(EC_FALSE == crfsbk_read_no_lock(crfsbk, file_path, cbytes))
    {
        CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0020);
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_read: read %s failed\n",
                           (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0021);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_read: read %s with %ld bytes done\n",
                       (char *)cstring_get_str(file_path), cbytes_len(cbytes));

    return (EC_TRUE);
}

EC_BOOL crfsbk_remove_file(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsnp_umount(CRFSBK_NP(crfsbk), (uint32_t)cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove_file: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_remove_file: umount %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_remove_file_wildcard(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsnp_umount_wildcard(CRFSBK_NP(crfsbk), (uint32_t)cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove_file_wildcard: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_remove_file_wildcard: umount %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_remove_file_b(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsnp_umount(CRFSBK_NP(crfsbk), (uint32_t)cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_BIG))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove_file_b: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_remove_file_b: umount %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_remove_file_b_wildcard(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsnp_umount_wildcard(CRFSBK_NP(crfsbk), (uint32_t)cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_BIG))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove_file_b_wildcard: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_remove_file_b_wildcard: umount %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_remove_dir(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsnp_umount(CRFSBK_NP(crfsbk), (uint32_t)cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove_dir: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_remove_dir: umount %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_remove_dir_wildcard(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsnp_umount_wildcard(CRFSBK_NP(crfsbk), (uint32_t)cstring_get_len(path), cstring_get_str(path), CRFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove_dir_wildcard: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_remove_dir_wildcard: umount %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_remove(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return crfsbk_remove_file(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_BIG == dflag)
    {
        return crfsbk_remove_file_b(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return crfsbk_remove_dir(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        if(EC_TRUE == crfsbk_remove_file(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_remove_file_b(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_remove_dir(crfsbk, path))
        {
            return (EC_TRUE);
        }

        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove: path [invalid 0x%lx] %s\n",
                        dflag, (char *)cstring_get_str(path));
    return (EC_FALSE);
}

EC_BOOL crfsbk_remove_wildcard(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return crfsbk_remove_file_wildcard(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_BIG == dflag)
    {
        return crfsbk_remove_file_b_wildcard(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return crfsbk_remove_dir_wildcard(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        if(EC_TRUE == crfsbk_remove_file_wildcard(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_remove_file_b_wildcard(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_remove_dir_wildcard(crfsbk, path))
        {
            return (EC_TRUE);
        }

        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_remove_wildcard: path [invalid 0x%lx] %s\n",
                        dflag, (char *)cstring_get_str(path));
    return (EC_FALSE);
}

EC_BOOL crfsbk_delete_file(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsbk_remove_file(crfsbk, path))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete_file: delete %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    crfsoprec_push(CRFSBK_OP_REC(crfsbk), CRFSOP_RM_REG_OP, CRFSOP_PATH_IS_REG, path);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_delete_file: delete %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_delete_file_wildcard(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsbk_remove_file_wildcard(crfsbk, path))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete_file_wildcard: delete %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    crfsoprec_push(CRFSBK_OP_REC(crfsbk), CRFSOP_RM_REG_OP, CRFSOP_PATH_IS_REG, path);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_delete_file_wildcard: delete %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_delete_file_b(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsbk_remove_file_b(crfsbk, path))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete_file_b: delete %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    crfsoprec_push(CRFSBK_OP_REC(crfsbk), CRFSOP_RM_BIG_OP, CRFSOP_PATH_IS_BIG, path);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_delete_file_b: delete %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_delete_file_b_wildcard(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsbk_remove_file_b_wildcard(crfsbk, path))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete_file_b_wildcard: delete %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    crfsoprec_push(CRFSBK_OP_REC(crfsbk), CRFSOP_RM_BIG_OP, CRFSOP_PATH_IS_BIG, path);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_delete_file_b_wildcard: delete %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_delete_dir(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsbk_remove_dir(crfsbk, path))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete_dir: delete %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    crfsoprec_push(CRFSBK_OP_REC(crfsbk), CRFSOP_RM_DIR_OP, CRFSOP_PATH_IS_DIR, path);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_delete_dir: delete %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_delete_dir_wildcard(CRFSBK *crfsbk, const CSTRING *path)
{
    if(EC_FALSE == crfsbk_remove_dir_wildcard(crfsbk, path))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete_dir_wildcard: delete %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    crfsoprec_push(CRFSBK_OP_REC(crfsbk), CRFSOP_RM_DIR_OP, CRFSOP_PATH_IS_DIR, path);

    dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_delete_dir_wildcard: delete %.*s done\n",
                        (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL crfsbk_delete(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return crfsbk_delete_file(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_BIG == dflag)
    {
        return crfsbk_delete_file_b(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return crfsbk_delete_dir(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        if(EC_TRUE == crfsbk_delete_file(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_delete_file_b(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_delete_dir(crfsbk, path))
        {
            return (EC_TRUE);
        }

        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete: path [invalid 0x%lx] %s\n",
                        dflag, (char *)cstring_get_str(path));
    return (EC_FALSE);
}

EC_BOOL crfsbk_delete_wildcard(CRFSBK *crfsbk, const CSTRING *path, const UINT32 dflag)
{
    if(CRFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return crfsbk_delete_file_wildcard(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_BIG == dflag)
    {
        return crfsbk_delete_file_b_wildcard(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return crfsbk_delete_dir_wildcard(crfsbk, path);
    }

    if(CRFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        if(EC_TRUE == crfsbk_delete_file_wildcard(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_delete_file_b_wildcard(crfsbk, path))
        {
            return (EC_TRUE);
        }

        if(EC_TRUE == crfsbk_delete_dir_wildcard(crfsbk, path))
        {
            return (EC_TRUE);
        }

        return (EC_FALSE);
    }

    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_delete_wildcard: path [invalid 0x%lx] %s\n",
                        dflag, (char *)cstring_get_str(path));
    return (EC_FALSE);
}

STATIC_CAST static CRFSNP_ITEM * __crfsbk_search_item(CRFSBK *crfsbk, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    uint32_t  node_pos;

    CRFSNP_ITEM *crfsnp_item;

    node_pos = crfsnp_search(CRFSBK_NP(crfsbk), path_len, path, dflag);
    if(CRFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] __crfsbk_search_item: not found path %.*s\n",
                            path_len, path);
        return (NULL_PTR);
    }

    crfsnp_item = crfsnp_fetch(CRFSBK_NP(crfsbk), node_pos);
    return (crfsnp_item);
}

EC_BOOL crfsbk_qfile(CRFSBK *crfsbk, const CSTRING *file_path, CRFSNP_ITEM  *crfsnp_item)
{
    CRFSNP_ITEM *crfsnp_item_src;
    crfsnp_item_src = __crfsbk_search_item(crfsbk,
                                         (uint32_t)cstring_get_len(file_path),
                                         cstring_get_str(file_path),
                                         CRFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == crfsnp_item_src)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_qfile: query file %s failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*clone*/
    crfsnp_item_clone(crfsnp_item_src, crfsnp_item);
    return (EC_TRUE);
}

EC_BOOL crfsbk_qdir(CRFSBK *crfsbk, const CSTRING *dir_path, CRFSNP_ITEM  *crfsnp_item)
{
    CRFSNP_ITEM *crfsnp_item_src;
    crfsnp_item_src = __crfsbk_search_item(crfsbk,
                                         (uint32_t)cstring_get_len(dir_path),
                                         cstring_get_str(dir_path),
                                         CRFSNP_ITEM_FILE_IS_DIR);
    if(NULL_PTR == crfsnp_item_src)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_qdir: query dir %s failed\n",
                            (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    /*clone*/
    crfsnp_item_clone(crfsnp_item_src, crfsnp_item);
    return (EC_TRUE);
}

EC_BOOL crfsbk_retire(CRFSBK *crfsbk)
{
    CRFSBK_WRLOCK(crfsbk, LOC_CRFSBK_0022);
    if(EC_FALSE == crfsbk_retire_no_lock(crfsbk))
    {
        CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0023);
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_retire: retire failed\n");
        return (EC_FALSE);
    }
    CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0024);

    return (EC_TRUE);
}

EC_BOOL crfsbk_recycle(CRFSBK *crfsbk, const UINT32 max_num, UINT32 *complete_num)
{
    CRFSBK_WRLOCK(crfsbk, LOC_CRFSBK_0025);
    if(EC_FALSE == crfsbk_recycle_no_lock(crfsbk, max_num, complete_num))
    {
        CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0026);
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_recycle: recycle failed\n");
        return (EC_FALSE);
    }
    CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0027);

    return (EC_TRUE);
}

EC_BOOL crfsbk_ensure_room_safe_level(CRFSBK *crfsbk)/*Jan 5, 2017: obsolete! due to DEL_SIZE not reduced again!*/
{
    uint32_t retire_times;

    retire_times = 0;

    CRFSBK_WRLOCK(crfsbk, LOC_CRFSBK_0028);
    while(EC_FALSE == crfsbk_room_is_ok_no_lock(crfsbk, CRFSBK_ROOM_SAFE_LEVEL))
    {
        if(EC_FALSE == crfsbk_retire_no_lock(crfsbk))
        {
            crfsbk_recycle_no_lock(crfsbk, CRFS_RECYCLE_MAX_NUM, NULL_PTR);
            CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0029);

            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_ensure_room_safe_level: retire failed\n");
            return (EC_FALSE);
        }

        retire_times ++;
    }

    if(0 < retire_times)
    {
        dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_ensure_room_safe_level: retire times %u\n", retire_times);
        crfsbk_recycle_no_lock(crfsbk, CRFS_RECYCLE_MAX_NUM, NULL_PTR);
    }

    CRFSBK_UNLOCK(crfsbk, LOC_CRFSBK_0030);

    return (EC_TRUE);
}


void crfsbk_print(LOG *log, const CRFSBK *crfsbk)
{
    sys_log(log, "crfsbk %p: np %p is\n", crfsbk, CRFSBK_NP(crfsbk));
    crfsnp_print(log, CRFSBK_NP(crfsbk));

    sys_log(log, "crfsbk %p: dn %p is\n", crfsbk, CRFSBK_DN(crfsbk));
    crfsdn_print(log, CRFSBK_DN(crfsbk));

    sys_log(log, "crfsbk %p: oprec %p is\n", crfsbk, CRFSBK_OP_REC(crfsbk));
    crfsoprec_print(log, CRFSBK_OP_REC(crfsbk));
    return;
}

EC_BOOL crfsbk_replay_file(CRFSBK *crfsbk, const CSTRING *path)
{
    CBYTES  cbytes;

    CRFSNP_ITEM *crfsnp_item_master;

    /*beg: check file in backup RFS is newer than that in master RFS*/
    crfsnp_item_master = crfsnp_item_new();
    if(NULL_PTR == crfsnp_item_master)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_file: new master crfsnp_item failed\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == crfs_qfile(CRFSBK_CRFS_MD_ID(crfsbk), path, crfsnp_item_master))
    {
        CRFSNP_ITEM *crfsnp_item_backup;

        crfsnp_item_backup = crfsnp_item_new();
        if(NULL_PTR == crfsnp_item_backup)
        {
            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_file: new backup crfsnp_item failed\n");
            crfsnp_item_free(crfsnp_item_master);
            return (EC_FALSE);
        }

        if(EC_FALSE == crfsbk_qfile(crfsbk, path, crfsnp_item_backup))
        {
            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_file: qfile %s in backup RFS failed\n",
                                (char *)cstring_get_str(path));
            crfsnp_item_free(crfsnp_item_master);
            crfsnp_item_free(crfsnp_item_backup);
            return (EC_FALSE);
        }

        /*master is new, give up replay*/
        if(CRFSNP_ITEM_CREATE_TIME(crfsnp_item_master) > CRFSNP_ITEM_CREATE_TIME(crfsnp_item_backup))
        {
            dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_replay_file: file %s in master RFS is new, give up replaying\n",
                                (char *)cstring_get_str(path));
            crfsnp_item_free(crfsnp_item_master);
            crfsnp_item_free(crfsnp_item_backup);
            return (EC_TRUE);
        }

        crfsnp_item_free(crfsnp_item_backup);

        if(EC_FALSE == crfs_delete_file(CRFSBK_CRFS_MD_ID(crfsbk), path))
        {
            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_file: delete file %s from master RFS failed\n",
                                (char *)cstring_get_str(path));
            crfsnp_item_free(crfsnp_item_master);
            return (EC_FALSE);
        }
        dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_replay_file: rmv file %s in master RFS\n",
                            (char *)cstring_get_str(path));
    }

    crfsnp_item_free(crfsnp_item_master);
    /*end: check file in backup RFS is newer than that in master RFS*/

    cbytes_init(&cbytes);

    if(EC_FALSE == crfsbk_read(crfsbk, path, &cbytes))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_file: read file %s from backup RFS failed\n",
                            (char *)cstring_get_str(path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfs_write(CRFSBK_CRFS_MD_ID(crfsbk), path, &cbytes))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_file: replay file %s to master RFS failed\n",
                            (char *)cstring_get_str(path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);

    //crfsbk_remove_file(crfsbk, path);

    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "[DEBUG] crfsbk_replay_file: replay file %s done\n",
                        (char *)cstring_get_str(path));
    return (EC_TRUE);
}

EC_BOOL crfsbk_replay_file_b(CRFSBK *crfsbk, const CSTRING *path)
{
    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_file_b: not support replay big file yet\n");
    return (EC_FALSE);
}

EC_BOOL crfsbk_replay_rm_dir_op(CRFSBK *crfsbk, CRFSOP *crfsop)
{
    CSTRING *path;

    path = CRFSOP_PATH_NAME(crfsop);

    CRFSNP_ITEM *crfsnp_item_master;

    /*beg: check dir in backup RFS is newer than that in master RFS*/
    crfsnp_item_master = crfsnp_item_new();
    if(NULL_PTR == crfsnp_item_master)
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_rm_dir_op: new master crfsnp_item failed\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == crfs_qdir(CRFSBK_CRFS_MD_ID(crfsbk), path, crfsnp_item_master))
    {
        CRFSNP_ITEM *crfsnp_item_backup;

        crfsnp_item_backup = crfsnp_item_new();
        if(NULL_PTR == crfsnp_item_backup)
        {
            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_rm_dir_op: new backup crfsnp_item failed\n");
            crfsnp_item_free(crfsnp_item_master);
            return (EC_FALSE);
        }

        if(EC_FALSE == crfsbk_qfile(crfsbk, path, crfsnp_item_backup))
        {
            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_rm_dir_op: dir %s in backup RFS failed\n",
                                (char *)cstring_get_str(path));
            crfsnp_item_free(crfsnp_item_master);
            crfsnp_item_free(crfsnp_item_backup);
            return (EC_FALSE);
        }

        /*master is new, give up replay*/
        if(CRFSNP_ITEM_CREATE_TIME(crfsnp_item_master) > CRFSNP_ITEM_CREATE_TIME(crfsnp_item_backup))
        {
            dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_replay_rm_dir_op: dir %s in master RFS is new, give up replaying\n",
                                (char *)cstring_get_str(path));
            crfsnp_item_free(crfsnp_item_master);
            crfsnp_item_free(crfsnp_item_backup);
            return (EC_TRUE);
        }

        crfsnp_item_free(crfsnp_item_backup);

        crfs_delete_dir(CRFSBK_CRFS_MD_ID(crfsbk), path);/*rm dir from master RFS*/
        dbg_log(SEC_0141_CRFSBK, 9)(LOGSTDOUT, "[DEBUG] crfsbk_replay_rm_dir_op: rmv dir %s in master RFS\n",
                            (char *)cstring_get_str(path));
    }

    crfsnp_item_free(crfsnp_item_master);
    /*end: check dir in backup RFS is newer than that in master RFS*/

    //crfs_delete_dir(CRFSBK_CRFS_MD_ID(crfsbk), path);

    if(0 == ((~CRFSOP_RM_DIR_OP) & CRFSOP_OP_TYPE(crfsop)))/*only rm dir op*/
    {
        return (EC_TRUE);
    }

    if(CRFSOP_WR_BIG_OP & CRFSOP_OP_TYPE(crfsop))
    {
        uint32_t  node_pos;

        node_pos = crfsnp_search(CRFSBK_NP(crfsbk),
                                 cstring_get_len(path),
                                 cstring_get_str(path),
                                 CRFSNP_ITEM_FILE_IS_BIG);

        if(CRFSNPRB_ERR_POS != node_pos)
        {
            return crfsbk_replay_file_b(crfsbk, path);
        }
        /*fall through*/
    }

    if(CRFSOP_WR_REG_OP & CRFSOP_OP_TYPE(crfsop))
    {
        uint32_t  node_pos;

        node_pos = crfsnp_search(CRFSBK_NP(crfsbk),
                                 cstring_get_len(path),
                                 cstring_get_str(path),
                                 CRFSNP_ITEM_FILE_IS_REG);

        if(CRFSNPRB_ERR_POS != node_pos)
        {
            return crfsbk_replay_file(crfsbk, path);
        }
        /*fall through*/
    }

    return (EC_TRUE);
}

EC_BOOL crfsbk_replay_rm_big_op(CRFSBK *crfsbk, CRFSOP *crfsop)
{
    /*when reach here, no RM_DIR op*/

    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_rm_big_op: not support replay RM_BIG op yet\n");
    return (EC_FALSE);
}

EC_BOOL crfsbk_replay_rm_reg_op(CRFSBK *crfsbk, CRFSOP *crfsop)
{
    CSTRING *path;

    /*when reach here, no RM_DIR/RM_BIG op*/

    path = CRFSOP_PATH_NAME(crfsop);
    crfs_delete_file(CRFSBK_CRFS_MD_ID(crfsbk), path);/*rm reg file from master RFS*/

    if(0 == ((~CRFSOP_RM_REG_OP) & CRFSOP_OP_TYPE(crfsop)))/*only rm reg file op*/
    {
        return (EC_TRUE);
    }

    if(CRFSOP_WR_REG_OP & CRFSOP_OP_TYPE(crfsop))
    {
        uint32_t  node_pos;

        node_pos = crfsnp_search(CRFSBK_NP(crfsbk),
                                 cstring_get_len(path),
                                 cstring_get_str(path),
                                 CRFSNP_ITEM_FILE_IS_REG);

        if(CRFSNPRB_ERR_POS != node_pos)
        {
            return crfsbk_replay_file(crfsbk, path);
        }
        /*fall through*/
    }

    return (EC_TRUE);
}

EC_BOOL crfsbk_replay_wr_reg_op(CRFSBK *crfsbk, CRFSOP *crfsop)
{
    CSTRING *path;

    /*when reach here, no RM_DIR/RM_BIG/RM_REG op*/

    path = CRFSOP_PATH_NAME(crfsop);

    return crfsbk_replay_file(crfsbk, path);
}

EC_BOOL crfsbk_replay_wr_big_op(CRFSBK *crfsbk, CRFSOP *crfsop)
{
    CSTRING *path;

    /*when reach here, no RM_DIR/RM_BIG op*/

    path = CRFSOP_PATH_NAME(crfsop);

    return crfsbk_replay_file_b(crfsbk, path);
}

EC_BOOL crfsbk_replay_one(CRFSBK *crfsbk, CRFSOP *crfsop)
{
    /*WARNING: DO NOT CHANGE BELOW "IF" ORDER!!!*/

    if(CRFSOP_RM_DIR_OP & CRFSOP_OP_TYPE(crfsop))
    {
        return crfsbk_replay_rm_dir_op(crfsbk, crfsop);
    }

    if(CRFSOP_RM_BIG_OP & CRFSOP_OP_TYPE(crfsop))
    {
        return crfsbk_replay_rm_big_op(crfsbk, crfsop);
    }

    if(CRFSOP_RM_REG_OP & CRFSOP_OP_TYPE(crfsop))
    {
        return crfsbk_replay_rm_reg_op(crfsbk, crfsop);
    }

    if(CRFSOP_WR_BIG_OP & CRFSOP_OP_TYPE(crfsop))
    {
        return crfsbk_replay_wr_big_op(crfsbk, crfsop);
    }

    if(CRFSOP_WR_REG_OP & CRFSOP_OP_TYPE(crfsop))
    {
        return crfsbk_replay_wr_reg_op(crfsbk, crfsop);
    }

    dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay_one: invalid op type 0x%x\n", CRFSOP_OP_TYPE(crfsop));
    return (EC_FALSE);
}

EC_BOOL crfsbk_replay(CRFSBK *crfsbk)
{
    CRFSOP *crfsop;

    if(NULL_PTR == CRFSBK_NP(crfsbk))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay: npp was not open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CRFSBK_DN(crfsbk))
    {
        dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "error:crfsbk_replay: dn was not open\n");
        return (EC_FALSE);
    }

    for(;;)
    {
        crfsop = crfsoprec_pop(CRFSBK_OP_REC(crfsbk));
        if(NULL_PTR == crfsop)
        {
            break;
        }

        if(EC_FALSE == crfsbk_replay_one(crfsbk, crfsop))
        {
            dbg_log(SEC_0141_CRFSBK, 0)(LOGSTDOUT, "crfsbk_replay: replay crfsop %p failed where op %s, path [%s] %s, hash %x\n", crfsop,
                         __crfsop_op_type(CRFSOP_OP_TYPE(crfsop)),
                         __crfsop_path_type(CRFSOP_PATH_TYPE(crfsop)),
                         CRFSOP_PATH_STR(crfsop),
                         CRFSOP_PATH_HASH(crfsop));

            crfsop_free(crfsop);
            return (EC_FALSE);
        }

        crfsop_free(crfsop);
    }
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

