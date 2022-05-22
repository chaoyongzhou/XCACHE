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

#if (SWITCH_ON == CXFSFUSE_SWITCH)

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <linux/xattr.h>
#include <x86_64-linux-gnu/sys/xattr.h>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cbc.h"
#include "cmisc.h"
#include "task.h"

#include "cxfsfuseo.h"
#include "cxfsfusec.h"
#include "cxfsfuses.h"

#include "findex.inc"

/*----------------------------------------------------------------------------*\
 *                             CFUSE CLIENT                                   *
\*----------------------------------------------------------------------------*/

static CXFS_FUSEC_MD                *g_cxfs_fusec_md = NULL_PTR;

#define CXFS_FUSEC_ASSERT(cond)     ASSERT(cond)

#define CXFS_FUSEC_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0049_CXFS_FUSEC, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")

#define CXFS_FUSEC_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0049_CXFS_FUSEC, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")


/**
*
* start CXFS_FUSEC module
*
**/
CXFS_FUSEC_MD *cxfs_fusec_start(struct fuse_args *args, const UINT32 cxfsfuses_tcid, const UINT32 cxfsfuses_rank, const UINT32 cxfsfuses_modi)
{
    CXFS_FUSEC_MD *cxfs_fusec_md;

    cxfs_fusec_md = g_cxfs_fusec_md;

    if(NULL_PTR != cxfs_fusec_md)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "error:cxfs_fusec_start: "
                       "fuses (tcid %s, rank %ld modi %ld), "
                       "fuseo thread %ld "
                       "already exist\n",
                       MOD_NODE_TCID_STR(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)),
                       MOD_NODE_RANK(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)),
                       MOD_NODE_MODI(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)),
                       CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md)
                       );
        return (NULL_PTR);
    }

    cbc_md_reg(MD_CFUSES, 16);

    cxfs_fusec_md = safe_malloc(sizeof(CXFS_FUSEC_MD), LOC_CXFSFUSEC_0001);
    if(NULL_PTR == cxfs_fusec_md)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "error:cxfs_fusec_start: "
                                                   "new cxfs_fusec_md failed\n");
        return (NULL_PTR);
    }

    MOD_NODE_TCID(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = cxfsfuses_tcid;
    MOD_NODE_COMM(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = CMPI_ANY_COMM;
    MOD_NODE_RANK(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = cxfsfuses_rank;
    MOD_NODE_MODI(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = cxfsfuses_modi;

    dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_start: "
                   "set fuses (tcid %s, rank %ld modi %ld) done\n",
                   MOD_NODE_TCID_STR(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)),
                   MOD_NODE_RANK(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)),
                   MOD_NODE_MODI(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)));

    CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md) = cthread_new(
                                                CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                                                (const char *)"cxfs_fuseo_start",
                                                (UINT32)cxfs_fuseo_start,
                                                (UINT32)0,/*core # (ignore)*/
                                                (UINT32)1,/*para num*/
                                                args
                                                );

    dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_start: "
                                               "start fuseo thread %ld\n",
                                               CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md));

    /*note: register by cxfs_fusec (which on master thread) but not cfuseo (which on worker thread)*/
    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_fuseo_process,
                        (void *)cxfs_fuseo_md_default_get());

    dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_start: "
                                               "register cxfs_fuseo_process\n");


    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfs_fusec_end, NULL_PTR);
    g_cxfs_fusec_md = cxfs_fusec_md;

    dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_start: "
                                               "done\n");

    return (cxfs_fusec_md);
}

/**
*
* end CXFS_FUSEC module
*
**/
void cxfs_fusec_end(void *none)
{
    CXFS_FUSEC_MD *cxfs_fusec_md;

    cxfs_fusec_md = g_cxfs_fusec_md;

    (void)none;

    if(NULL_PTR != cxfs_fusec_md)
    {
        int signo;

        csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cxfs_fusec_end, NULL_PTR);

        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_end: "
                                                   "unregister cxfs_fuseo_process\n");

        task_brd_process_del(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_fuseo_process,
                            (void *)cxfs_fuseo_md_default_get());


        signo = SIGHUP;/*TODO: not perfect yet ...*/
        if(EC_FALSE == cthread_kill(CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md), signo))
        {
            dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "error:cxfs_fusec_end: "
                                                       "kill fuseo thread %ld with signo %d failed\n",
                                                       CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md),
                                                       signo);
        }
        else
        {
            dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_end: "
                                                       "kill fuseo thread %ld with signo %d done\n",
                                                       CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md),
                                                       signo);
        }
        CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md) = 0;

        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_end: "
                       "unset fuses (tcid %ld, rank %ld modi %ld)\n",
                       MOD_NODE_TCID(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)),
                       MOD_NODE_RANK(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)),
                       MOD_NODE_MODI(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)));

        MOD_NODE_TCID(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = CMPI_ERROR_TCID;
        MOD_NODE_COMM(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = CMPI_ERROR_COMM;
        MOD_NODE_RANK(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = CMPI_ERROR_RANK;
        MOD_NODE_MODI(CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)) = CMPI_ERROR_MODI;

        safe_free(cxfs_fusec_md, LOC_CXFSFUSEC_0002);
        cxfs_fusec_md = NULL_PTR;

        g_cxfs_fusec_md = NULL_PTR;

        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "[DEBUG] cxfs_fusec_end: "
                                               "done\n");
    }

    return ;
}


MOD_NODE *cxfs_fusec_get_remote_mod_node()
{
    return CXFS_FUSEC_MD_CFUSES_MOD_NODE(g_cxfs_fusec_md);
}

/*int (*getattr) (const char *, struct stat *);*/
int cxfs_fusec_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_getattr");

    (void)fi;

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_getattr, CMPI_ERROR_MODI, &path_arg, stat, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_getattr: return false\n");
    }

    return (res);
}

/*int (*readlink) (const char *, char *, size_t);*/
int cxfs_fusec_readlink(const char *path, char *buf, const UINT32 size)
{
    CSTRING         path_arg;
    CSTRING         buf_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_readlink");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_mount(&buf_arg, (UINT8 *)buf, size - 1, size);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_readlink, CMPI_ERROR_MODI, &path_arg, &buf_arg, size, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_readlink: return false\n");
    }

    return (res);
}

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cxfs_fusec_mknod(const char *path, const UINT32 mode, const UINT32 dev, const UINT32 uid, const UINT32 gid)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_mknod");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_mknod, CMPI_ERROR_MODI, &path_arg, mode, dev, uid, gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_mknod: return false\n");
    }

    return (res);
}

/*int (*mkdir) (const char *, mode_t);*/
int cxfs_fusec_mkdir(const char *path, const UINT32 mode, const UINT32 uid, const UINT32 gid)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_mkdir");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_mkdir, CMPI_ERROR_MODI, &path_arg, mode, uid, gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_mkdir: return false\n");
    }

    return (res);
}

/*int (*unlink) (const char *);*/
int cxfs_fusec_unlink(const char *path, const UINT32 op_uid, const UINT32 op_gid)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_unlink");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_unlink, CMPI_ERROR_MODI, &path_arg, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_unlink: return false\n");
    }

    return (res);
}

/*int (*rmdir) (const char *);*/
int cxfs_fusec_rmdir(const char *path, const UINT32 op_uid, const UINT32 op_gid)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_rmdir");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_rmdir, CMPI_ERROR_MODI, &path_arg, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_rmdir: return false\n");
    }

    return (res);
}

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cxfs_fusec_symlink(const char *src_path, const char *des_path, const UINT32 op_uid, const UINT32 op_gid)
{
    CSTRING         src_path_arg;
    CSTRING         des_path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_symlink");

    cstring_set_str(&src_path_arg, (UINT8 *)src_path);
    cstring_set_str(&des_path_arg, (UINT8 *)des_path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_symlink, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_symlink: return false\n");
    }

    return (res);
}

/*int (*rename) (const char *, const char *, unsigned int flags);*/
int cxfs_fusec_rename(const char *src_path, const char *des_path, const UINT32 flags /*RENAME_EXCHANGE|RENAME_NOREPLACE*/, const UINT32 op_uid, const UINT32 op_gid)
{
    CSTRING         src_path_arg;
    CSTRING         des_path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_rename");

    cstring_set_str(&src_path_arg, (UINT8 *)src_path);
    cstring_set_str(&des_path_arg, (UINT8 *)des_path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_rename, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_rename: return false\n");
    }

    return (res);
}

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cxfs_fusec_link(const char *src_path, const char *des_path, const UINT32 op_uid, const UINT32 op_gid)
{
    CSTRING         src_path_arg;
    CSTRING         des_path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_link");

    cstring_set_str(&src_path_arg, (UINT8 *)src_path);
    cstring_set_str(&des_path_arg, (UINT8 *)des_path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_link, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_link: return false\n");
    }

    return (res);
}

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t, struct fuse_file_info *fi);*/
int cxfs_fusec_chmod(const char *path, const UINT32 mode, const UINT32 op_uid, const UINT32 op_gid, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_chmod");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_chmod, CMPI_ERROR_MODI, &path_arg, mode, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_chmod: return false\n");
    }

    return (res);
}

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cxfs_fusec_chown(const char *path, const UINT32 owner, const UINT32 group, const UINT32 op_uid, const UINT32 op_gid, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_chown");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_chown, CMPI_ERROR_MODI, &path_arg, owner, group, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_chown: return false\n");
    }

    return (res);
}

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cxfs_fusec_truncate(const char *path, const UINT32 length, const UINT32 op_uid, const UINT32 op_gid, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_truncate");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_truncate, CMPI_ERROR_MODI, &path_arg, length, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_truncate: return false\n");
    }

    return (res);
}

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cxfs_fusec_utime(const char *path, /*const*/struct utimbuf *times)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_utime");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_utime, CMPI_ERROR_MODI, &path_arg, times, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_utime: return false\n");
    }

    return (res);
}

/*int (*open) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_open(const char *path, const UINT32 uid, const UINT32 gid, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_open");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_open, CMPI_ERROR_MODI, &path_arg, (UINT32)(fi->flags), uid, gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_open: return false\n");
    }

    return (res);
}

/*int (*create) (const char *, mode_t, struct fuse_file_info *);*/
int cxfs_fusec_create(const char *path, const UINT32 mode, const UINT32 uid, const UINT32 gid, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_create");

    (void)fi;

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_create, CMPI_ERROR_MODI, &path_arg, mode, uid, gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_create: return false\n");
    }

    return (res);
}

/*int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);*/
int cxfs_fusec_read(const char *path, char *buf, const UINT32 size, const UINT32 offset, struct fuse_file_info *fi)
{
    CSTRING         path_arg;
    CBYTES          buf_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_read");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cbytes_mount(&buf_arg, size, (UINT8 *)buf, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_read, CMPI_ERROR_MODI, &path_arg, &buf_arg, size, offset, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_read: return false\n");
    }

    return (res);
}

/*int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);*/
int cxfs_fusec_write(const char *path, const char *buf, const UINT32 size, const UINT32 offset, struct fuse_file_info *fi)
{
    CSTRING         path_arg;
    CBYTES          buf_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_write");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cbytes_mount(&buf_arg, size, (UINT8 *)buf, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_write, CMPI_ERROR_MODI, &path_arg, &buf_arg, offset, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_write: return false\n");
    }

    return (res);
}

/*int (*statfs) (const char *, struct statvfs *);*/
int cxfs_fusec_statfs(const char *path, struct statvfs *statvfs)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_statfs");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_statfs, CMPI_ERROR_MODI, &path_arg, statvfs, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_statfs: return false\n");
    }

    return (res);
}

/*int (*flush) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_flush(const char *path, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_flush");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_flush, CMPI_ERROR_MODI, &path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_flush: return false\n");
    }

    return (res);
}

/*int (*release) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_release(const char *path, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_release");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_release, CMPI_ERROR_MODI, &path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_release: return false\n");
    }

    return (res);
}

/*int (*fsync) (const char *, int);*/
int cxfs_fusec_fsync(const char * path, const UINT32 sync, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_fsync");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_fsync, CMPI_ERROR_MODI, &path_arg, sync, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_fsync: return false\n");
    }

    return (res);
}

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cxfs_fusec_setxattr(const char *path, const char *name, const char *value, const UINT32 size, const UINT32 flags)
{
    CSTRING         path_arg;
    CSTRING         name_arg;
    CBYTES          value_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_setxattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_set_str(&name_arg, (UINT8 *)name);
    cbytes_mount(&value_arg, size, (UINT8 *)value, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_setxattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &value_arg, flags, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_setxattr: return false\n");
    }

    return (res);
}

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cxfs_fusec_getxattr(const char *path, const char *name, char *value, const UINT32 size)
{
    CSTRING         path_arg;
    CSTRING         name_arg;
    CBYTES          value_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_getxattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_set_str(&name_arg, (UINT8 *)name);
    cbytes_mount(&value_arg, (UINT32)size, (UINT8 *)value, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_getxattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &value_arg, size, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_getxattr: return false\n");
    }

    return (res);
}

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cxfs_fusec_listxattr(const char *path, char *list, const UINT32 size)
{
    CSTRING         path_arg;
    CBYTES          list_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_listxattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cbytes_mount(&list_arg, (UINT32)size, (UINT8 *)list, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_listxattr, CMPI_ERROR_MODI, &path_arg, &list_arg, size, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_listxattr: return false\n");
    }

    return (res);
}

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cxfs_fusec_removexattr(const char *path, const char *name)
{
    CSTRING         path_arg;
    CSTRING         name_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_removexattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_set_str(&name_arg, (UINT8 *)name);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_removexattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_removexattr: return false\n");
    }

    return (res);
}

/*int (*access) (const char *, int);*/
int cxfs_fusec_access(const char *path, const UINT32 mask, UINT32 *mode)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_access");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_access, CMPI_ERROR_MODI, &path_arg, mask, mode, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_access: return false\n");
    }

    return (res);
}

/*int (*ftruncate) (const char *, off_t, struct fuse_file_info *);*/
int cxfs_fusec_ftruncate(const char *path, const UINT32 length, const UINT32 op_uid, const UINT32 op_gid)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_ftruncate");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_ftruncate, CMPI_ERROR_MODI, &path_arg, length, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_ftruncate: return false\n");
    }

    return (res);
}


/*int (*utimens) (const char *, const struct timespec tv[2], struct fuse_file_info *fi);*/
int cxfs_fusec_utimens(const char *path, const struct timespec *ts0, const struct timespec *ts1, const UINT32 op_uid, const UINT32 op_gid, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_utimens");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_utimens, CMPI_ERROR_MODI, &path_arg, ts0, ts1, op_uid, op_gid, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_utimens: return false\n");
    }

    return (res);
}

/* int (*fallocate) (const char *, int, off_t, off_t, struct fuse_file_info *); */
int cxfs_fusec_fallocate(const char * path, const UINT32 mode, const UINT32 offset, const UINT32 length, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_fallocate");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_fallocate, CMPI_ERROR_MODI, &path_arg, mode, offset, length, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_fallocate: return false\n");
    }

    return (res);
}

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_opendir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_opendir");

    return (0);
}

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cxfs_fusec_readdir(const char *path, void *buf, const UINT32 filler, const UINT32 offset, struct fuse_file_info *fi, const UINT32 eflags)
{
    CSTRING         path_arg;

    CLIST           dirnode_list;
    struct dirnode *dirnode;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_readdir");

    cstring_set_str(&path_arg, (UINT8 *)path);

    clist_init(&dirnode_list, MM_DIRNODE, LOC_CXFSFUSEC_0003);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cxfs_fusec_get_remote_mod_node(),
             &ret,
             FI_cxfs_fuses_readdir, CMPI_ERROR_MODI, &path_arg, offset, eflags, &dirnode_list, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 0)(LOGSTDOUT, "warn:cxfs_fusec_readdir: return false\n");
    }

    while(NULL_PTR != (dirnode = clist_pop_front(&dirnode_list)))
    {
        dbg_log(SEC_0049_CXFS_FUSEC, 9)(LOGSTDOUT, "[DEBUG] cxfs_fusec_readdir: "
                                                  "pop (name %s, offset %ld, flags %u)\n",
                                                  dirnode->name,
                                                  dirnode->offset,
                                                  dirnode->flags);

        if(((fuse_fill_dir_t)filler)(buf, dirnode->name,
                    &(dirnode->stat), dirnode->offset,
                    (enum fuse_fill_dir_flags)dirnode->flags))
        {
            c_dirnode_free(dirnode);
            break;
        }

        c_dirnode_free(dirnode);
    }

    clist_clean(&dirnode_list, (CLIST_DATA_DATA_CLEANER)c_dirnode_free);

    return (res);
}

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_releasedir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_releasedir");
    return (0);
}

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cxfs_fusec_fsyncdir(const char *path, const int datasync, struct fuse_file_info *fi)
{
    (void)path;
    (void)datasync;
    (void)fi;

    CXFS_FUSEC_DEBUG_ENTER("cxfs_fusec_fsyncdir");
    return (0);
}

#endif/*(SWITCH_ON == CXFSFUSE_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

