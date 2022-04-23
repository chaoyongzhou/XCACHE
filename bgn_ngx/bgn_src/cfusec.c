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

#if (SWITCH_ON == FUSE_SWITCH)

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

#include "cfuseo.h"
#include "cfusec.h"
#include "cfuses.h"

#include "findex.inc"

/*----------------------------------------------------------------------------*\
 *                             CFUSE CLIENT                                   *
\*----------------------------------------------------------------------------*/

static CFUSEC_MD                *g_cfusec_md = NULL_PTR;

#define CFUSEC_ASSERT(cond)     ASSERT(cond)

#define CFUSEC_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0031_CFUSEC, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")

#define CFUSEC_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0031_CFUSEC, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")


/**
*
* start CFUSEC module
*
**/
CFUSEC_MD *cfusec_start(struct fuse_args *args, const UINT32 cfuses_tcid, const UINT32 cfuses_rank, const UINT32 cfuses_modi)
{
    CFUSEC_MD *cfusec_md;

    cfusec_md = g_cfusec_md;

    if(NULL_PTR != cfusec_md)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "error:cfusec_start: "
                       "fuses (tcid %s, rank %ld modi %ld), "
                       "fuseo thread %ld "
                       "already exist\n",
                       MOD_NODE_TCID_STR(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)),
                       MOD_NODE_RANK(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)),
                       MOD_NODE_MODI(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)),
                       CFUSEC_MD_CFUSEO_THREAD_ID(cfusec_md)
                       );
        return (NULL_PTR);
    }

    cbc_md_reg(MD_CFUSES, 16);

    cfusec_md = safe_malloc(sizeof(CFUSEC_MD), LOC_CFUSEC_0001);
    if(NULL_PTR == cfusec_md)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "error:cfusec_start: "
                                               "new cfusec_md failed\n");
        return (NULL_PTR);
    }

    MOD_NODE_TCID(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = cfuses_tcid;
    MOD_NODE_COMM(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = CMPI_ANY_COMM;
    MOD_NODE_RANK(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = cfuses_rank;
    MOD_NODE_MODI(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = cfuses_modi;

    dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_start: "
                   "set fuses (tcid %s, rank %ld modi %ld) done\n",
                   MOD_NODE_TCID_STR(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)),
                   MOD_NODE_RANK(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)),
                   MOD_NODE_MODI(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)));

    CFUSEC_MD_CFUSEO_THREAD_ID(cfusec_md) = cthread_new(
                                                CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                                                (const char *)"cfuseo_start",
                                                (UINT32)cfuseo_start,
                                                (UINT32)0,/*core # (ignore)*/
                                                (UINT32)1,/*para num*/
                                                args
                                                );

    dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_start: "
                                           "start fuseo thread %ld\n",
                                           CFUSEC_MD_CFUSEO_THREAD_ID(cfusec_md));

    /*note: register by cfusec (which on master thread) but not cfuseo (which on worker thread)*/
    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cfuseo_process,
                        (void *)cfuseo_md_default_get());

    dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_start: "
                                           "register cfuseo_process\n");


    csig_atexit_register((CSIG_ATEXIT_HANDLER)cfusec_end, NULL_PTR);
    g_cfusec_md = cfusec_md;

    dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_start: "
                                           "done\n");

    return (cfusec_md);
}

/**
*
* end CFUSEC module
*
**/
void cfusec_end(void *none)
{
    CFUSEC_MD *cfusec_md;

    cfusec_md = g_cfusec_md;

    (void)none;

    if(NULL_PTR != cfusec_md)
    {
        int signo;

        csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cfusec_end, NULL_PTR);

        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_end: "
                                               "unregister cfuseo_process\n");

        task_brd_process_del(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cfuseo_process,
                            (void *)cfuseo_md_default_get());


        signo = SIGHUP;/*TODO: not perfect yet ...*/
        if(EC_FALSE == cthread_kill(CFUSEC_MD_CFUSEO_THREAD_ID(cfusec_md), signo))
        {
            dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "error:cfusec_end: "
                                                   "kill fuseo thread %ld with signo %d failed\n",
                                                   CFUSEC_MD_CFUSEO_THREAD_ID(cfusec_md),
                                                   signo);
        }
        else
        {
            dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_end: "
                                                   "kill fuseo thread %ld with signo %d done\n",
                                                   CFUSEC_MD_CFUSEO_THREAD_ID(cfusec_md),
                                                   signo);
        }
        CFUSEC_MD_CFUSEO_THREAD_ID(cfusec_md) = 0;

        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_end: "
                       "unset fuses (tcid %ld, rank %ld modi %ld)\n",
                       MOD_NODE_TCID(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)),
                       MOD_NODE_RANK(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)),
                       MOD_NODE_MODI(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)));

        MOD_NODE_TCID(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = CMPI_ERROR_TCID;
        MOD_NODE_COMM(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = CMPI_ERROR_COMM;
        MOD_NODE_RANK(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = CMPI_ERROR_RANK;
        MOD_NODE_MODI(CFUSEC_MD_CFUSES_MOD_NODE(cfusec_md)) = CMPI_ERROR_MODI;

        safe_free(cfusec_md, LOC_CFUSEC_0002);
        cfusec_md = NULL_PTR;

        g_cfusec_md = NULL_PTR;

        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_end: "
                                               "done\n");
    }

    return ;
}


MOD_NODE *cfusec_get_remote_mod_node()
{
    return CFUSEC_MD_CFUSES_MOD_NODE(g_cfusec_md);
}

/*int (*getattr) (const char *, struct stat *);*/
int cfusec_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_getattr");

    (void)fi;

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_getattr, CMPI_ERROR_MODI, &path_arg, stat, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_getattr: return false\n");
    }

    return (res);
}

/*int (*readlink) (const char *, char *, size_t);*/
int cfusec_readlink(const char *path, char *buf, UINT32 size)
{
    CSTRING         path_arg;
    CSTRING         buf_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_readlink");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_mount(&buf_arg, (UINT8 *)buf, size - 1, size);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_readlink, CMPI_ERROR_MODI, &path_arg, &buf_arg, size, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_readlink: return false\n");
    }

    return (res);
}

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cfusec_mknod(const char *path, UINT32 mode, UINT32 dev)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_mknod");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_mknod, CMPI_ERROR_MODI, &path_arg, mode, dev, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_mknod: return false\n");
    }

    return (res);
}

/*int (*mkdir) (const char *, mode_t);*/
int cfusec_mkdir(const char *path, UINT32 mode)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_mkdir");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_mkdir, CMPI_ERROR_MODI, &path_arg, mode, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_mkdir: return false\n");
    }

    return (res);
}

/*int (*unlink) (const char *);*/
int cfusec_unlink(const char *path)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_unlink");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_unlink, CMPI_ERROR_MODI, &path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_unlink: return false\n");
    }

    return (res);
}

/*int (*rmdir) (const char *);*/
int cfusec_rmdir(const char *path)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_rmdir");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_rmdir, CMPI_ERROR_MODI, &path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_rmdir: return false\n");
    }

    return (res);
}

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cfusec_symlink(const char *src_path, const char *des_path)
{
    CSTRING         src_path_arg;
    CSTRING         des_path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_symlink");

    cstring_set_str(&src_path_arg, (UINT8 *)src_path);
    cstring_set_str(&des_path_arg, (UINT8 *)des_path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_symlink, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_symlink: return false\n");
    }

    return (res);
}

/*int (*rename) (const char *, const char *, unsigned int flags);*/
int cfusec_rename(const char *src_path, const char *des_path, UINT32 flags /*RENAME_EXCHANGE|RENAME_NOREPLACE*/)
{
    CSTRING         src_path_arg;
    CSTRING         des_path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_rename");

    cstring_set_str(&src_path_arg, (UINT8 *)src_path);
    cstring_set_str(&des_path_arg, (UINT8 *)des_path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_rename, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_rename: return false\n");
    }

    return (res);
}

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cfusec_link(const char *src_path, const char *des_path)
{
    CSTRING         src_path_arg;
    CSTRING         des_path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_link");

    cstring_set_str(&src_path_arg, (UINT8 *)src_path);
    cstring_set_str(&des_path_arg, (UINT8 *)des_path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_link, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_link: return false\n");
    }

    return (res);
}

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t, struct fuse_file_info *fi);*/
int cfusec_chmod(const char *path, UINT32 mode, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_chmod");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_chmod, CMPI_ERROR_MODI, &path_arg, mode, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_chmod: return false\n");
    }

    return (res);
}

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cfusec_chown(const char *path, UINT32 owner, UINT32 group, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_chown");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_chown, CMPI_ERROR_MODI, &path_arg, owner, group, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_chown: return false\n");
    }

    return (res);
}

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cfusec_truncate(const char *path, UINT32 length, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_truncate");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_truncate, CMPI_ERROR_MODI, &path_arg, length, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_truncate: return false\n");
    }

    return (res);
}

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cfusec_utime(const char *path, /*const*/struct utimbuf *times)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_utime");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_utime, CMPI_ERROR_MODI, &path_arg, times, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_utime: return false\n");
    }

    return (res);
}

/*int (*open) (const char *, struct fuse_file_info *);*/
int cfusec_open(const char *path, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_open");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_open, CMPI_ERROR_MODI, &path_arg, (UINT32)(fi->flags), &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_open: return false\n");
    }

    return (res);
}

/*int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);*/
int cfusec_read(const char *path, char *buf, UINT32 size, UINT32 offset, struct fuse_file_info *fi)
{
    CSTRING         path_arg;
    CBYTES          buf_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_read");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cbytes_mount(&buf_arg, size, (UINT8 *)buf, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_read, CMPI_ERROR_MODI, &path_arg, &buf_arg, size, offset, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_read: return false\n");
    }

    return (res);
}

/*int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);*/
int cfusec_write(const char *path, const char *buf, UINT32 size, UINT32 offset, struct fuse_file_info *fi)
{
    CSTRING         path_arg;
    CBYTES          buf_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_write");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cbytes_mount(&buf_arg, size, (UINT8 *)buf, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_write, CMPI_ERROR_MODI, &path_arg, &buf_arg, offset, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_write: return false\n");
    }

    return (res);
}

/*int (*statfs) (const char *, struct statvfs *);*/
int cfusec_statfs(const char *path, struct statvfs *statvfs)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_statfs");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_statfs, CMPI_ERROR_MODI, &path_arg, statvfs, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_statfs: return false\n");
    }

    return (res);
}

/*int (*flush) (const char *, struct fuse_file_info *);*/
int cfusec_flush(const char *path, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_flush");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_flush, CMPI_ERROR_MODI, &path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_flush: return false\n");
    }

    return (res);
}

/*int (*release) (const char *, struct fuse_file_info *);*/
int cfusec_release(const char *path, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_release");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_release, CMPI_ERROR_MODI, &path_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_release: return false\n");
    }

    return (res);
}

/*int (*fsync) (const char *, int);*/
int cfusec_fsync(const char * path, UINT32 sync, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_fsync");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_fsync, CMPI_ERROR_MODI, &path_arg, sync, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_fsync: return false\n");
    }

    return (res);
}

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cfusec_setxattr(const char *path, const char *name, const char *value, UINT32 size, UINT32 flags)
{
    CSTRING         path_arg;
    CSTRING         name_arg;
    CBYTES          value_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_setxattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_set_str(&name_arg, (UINT8 *)name);
    cbytes_mount(&value_arg, size, (UINT8 *)value, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_setxattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &value_arg, flags, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_setxattr: return false\n");
    }

    return (res);
}

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cfusec_getxattr(const char *path, const char *name, char *value, UINT32 size)
{
    CSTRING         path_arg;
    CSTRING         name_arg;
    CBYTES          value_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_getxattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_set_str(&name_arg, (UINT8 *)name);
    cbytes_mount(&value_arg, (UINT32)size, (UINT8 *)value, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_getxattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &value_arg, size, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_getxattr: return false\n");
    }

    return (res);
}

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cfusec_listxattr(const char *path, char *list, UINT32 size)
{
    CSTRING         path_arg;
    CBYTES          list_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_listxattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cbytes_mount(&list_arg, (UINT32)size, (UINT8 *)list, BIT_FALSE);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_listxattr, CMPI_ERROR_MODI, &path_arg, &list_arg, size, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_listxattr: return false\n");
    }

    return (res);
}

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cfusec_removexattr(const char *path, const char *name)
{
    CSTRING         path_arg;
    CSTRING         name_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_removexattr");

    cstring_set_str(&path_arg, (UINT8 *)path);
    cstring_set_str(&name_arg, (UINT8 *)name);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_removexattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_removexattr: return false\n");
    }

    return (res);
}

/*int (*access) (const char *, int);*/
int cfusec_access(const char *path, UINT32 mask)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_access");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_access, CMPI_ERROR_MODI, &path_arg, mask, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_access: return false\n");
    }

    return (res);
}

/*int (*ftruncate) (const char *, off_t, struct fuse_file_info *);*/
int cfusec_ftruncate(const char *path, UINT32 offset)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_ftruncate");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_ftruncate, CMPI_ERROR_MODI, &path_arg, offset, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_ftruncate: return false\n");
    }

    return (res);
}


/*int (*utimens) (const char *, const struct timespec tv[2], struct fuse_file_info *fi);*/
int cfusec_utimens(const char *path, const struct timespec *ts0, const struct timespec *ts1, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_utimens");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_utimens, CMPI_ERROR_MODI, &path_arg, ts0, ts1, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_utimens: return false\n");
    }

    return (res);
}

/* int (*fallocate) (const char *, int, off_t, off_t, struct fuse_file_info *); */
int cfusec_fallocate(const char * path, UINT32 mode, UINT32 offset, UINT32 length, struct fuse_file_info *fi)
{
    CSTRING         path_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_fallocate");

    cstring_set_str(&path_arg, (UINT8 *)path);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_fallocate, CMPI_ERROR_MODI, &path_arg, mode, offset, length, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_fallocate: return false\n");
    }

    return (res);
}

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cfusec_opendir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_opendir");

    return (0);
}

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cfusec_readdir(const char *path, void *buf, UINT32 filler, UINT32 offset, struct fuse_file_info *fi, UINT32 eflags)
{
    CSTRING         path_arg;

    CLIST           dirnode_list;
    struct dirnode *dirnode;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_readdir");

    cstring_set_str(&path_arg, (UINT8 *)path);

    clist_init(&dirnode_list, MM_DIRNODE, LOC_CFUSEC_0003);

    ret = EC_FALSE;
    res = -ECOMM;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfusec_get_remote_mod_node(),
             &ret,
             FI_cfuses_readdir, CMPI_ERROR_MODI, &path_arg, offset, eflags, &dirnode_list, &res);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "warn:cfusec_readdir: return false\n");
    }

    while(NULL_PTR != (dirnode = clist_pop_front(&dirnode_list)))
    {
        dbg_log(SEC_0031_CFUSEC, 9)(LOGSTDOUT, "[DEBUG] cfusec_readdir: "
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
int cfusec_releasedir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_releasedir");
    return (0);
}

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cfusec_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    (void)path;
    (void)datasync;
    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_fsyncdir");
    return (0);
}

#endif/*(SWITCH_ON == FUSE_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

