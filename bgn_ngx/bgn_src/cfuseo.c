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
#include "cfused.h"

/*----------------------------------------------------------------------------*\
 *                             CFUSE ORIGIN                                   *
 *                                                                            *
 * cfuseo define interfaces which would be registered to fuse.                *
 * cfuseo interface is called by fuse and then emit task to cfusec.           *
 * cfuseo is running in a single thread and communicate with kernel FUSE MOD  *
 * in blocking mode.                                                          *
 * cfuseo must not alloc mem with BGN memory manager.                         *
 * cfuseo emit task to cfusec in atomic operation and shared memory to reduce *
 * encoding & decoding & data copying.                                        *
 * cfuseo emit task and then fall in thread suspending with condition lock.   *
 * the emitted task by cfuseo would be running in one coroutine by cfusec.    *
 * cfusec deploy and execute the emitted task from cfuseo and then unlock     *
 * cfuseo thread condition lock.                                              *
\*----------------------------------------------------------------------------*/

static CFUSEO_MD                g_cfuseo_md;

#define CFUSEO_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0036_CFUSEO, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")

#define CFUSEO_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0036_CFUSEO, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")

#define CFUSEO_TASK_DEFAULT() CFUSEO_MD_TASK(cfuseo_md_default_get())

#define CFUSEO_TASK_FUNC_SET(func)    do{                                     \
    CFUSEO_TASK_FUNC_ADDR(CFUSEO_TASK_DEFAULT()) = ((UINT32)func);            \
    CFUSEO_TASK_FUNC_NAME(CFUSEO_TASK_DEFAULT()) = ((const char *)# func );   \
}while(0)

#define CFUSEO_TASK_PARA_NUM_SET(num)    do{                                  \
    CFUSEO_TASK_PARA_NUM(CFUSEO_TASK_DEFAULT()) = ((UINT32)num);              \
}while(0)

#define CFUSEO_TASK_PARA_VAL_SET(idx, val)    do{                             \
    CFUSEO_TASK_PARA_VAL(CFUSEO_TASK_DEFAULT(), idx) = ((UINT32)val);         \
}while(0)

#define CFUSEO_TASK_EMIT()    do{                                             \
    cfuseo_task_num_inc(cfuseo_md_default_get());                             \
    task_brd_inc_notify_counter(task_brd_default_get());                      \
    cfuseo_task_wait(cfuseo_md_default_get());                                \
}while(0)

#define CFUSEO_TASK_RET_VAL_GET() CFUSEO_TASK_RET_VAL(CFUSEO_TASK_DEFAULT())

CFUSEO_MD *cfuseo_md_default_get()
{
    return &g_cfuseo_md;
}

/**
*
* start CFUSEO module
*
**/
EC_BOOL cfuseo_start(struct fuse_args *args)
{
    CFUSEO_MD *cfuseo_md;

    cfuseo_md = cfuseo_md_default_get();

    cfuseo_init_ops(cfuseo_md);

	c_cond_init(CFUSEO_MD_CCOND(cfuseo_md), LOC_CFUSEO_0001);

    cfused_start();

    dbg_log(SEC_0036_CFUSEO, 0)(LOGSTDOUT, "[DEBUG] cfuseo_start: launch fuse\n");

    /*block thread when communicate with kernel fuse*/
    fuse_main(args->argc, args->argv, CFUSEO_MD_OPS(cfuseo_md), NULL_PTR);

    return (EC_TRUE);
}

/**
*
* end CFUSEO module
*
**/
void cfuseo_end()
{
    CFUSEO_MD *cfuseo_md;

    cfuseo_md = cfuseo_md_default_get();

    cfuseo_clean_ops(cfuseo_md);

    cfused_end();

    c_cond_clean(CFUSEO_MD_CCOND(cfuseo_md), LOC_CFUSEO_0002);

    return;
}

void cfuseo_init_ops(CFUSEO_MD *cfuseo_md)
{
    struct fuse_operations     *fuse_ops;

    fuse_ops = CFUSEO_MD_OPS(cfuseo_md);

    BSET(fuse_ops, 0x00, sizeof(*fuse_ops));

	fuse_ops->getattr	        = cfuseo_getattr;
	fuse_ops->readlink	        = cfuseo_readlink;
	fuse_ops->mknod             = cfuseo_mknod;
	fuse_ops->mkdir		        = cfuseo_mkdir;
	fuse_ops->unlink		    = cfuseo_unlink;
	fuse_ops->rmdir		        = cfuseo_rmdir;
	fuse_ops->symlink	        = cfuseo_symlink;
	fuse_ops->rename		    = cfuseo_rename;
	fuse_ops->link		        = cfuseo_link;
	fuse_ops->chmod		        = cfuseo_chmod;
	fuse_ops->chown		        = cfuseo_chown;
	fuse_ops->truncate	        = cfuseo_truncate;
	fuse_ops->open		        = cfuseo_open;
	fuse_ops->read		        = cfuseo_read;
	fuse_ops->write		        = cfuseo_write;
	fuse_ops->statfs		    = cfuseo_statfs;
	fuse_ops->flush		        = cfuseo_flush;
	fuse_ops->release	        = cfuseo_release;
	fuse_ops->fsync		        = cfuseo_fsync;
	fuse_ops->setxattr	        = cfuseo_setxattr;
	fuse_ops->getxattr	        = cfuseo_getxattr;
	fuse_ops->listxattr	        = cfuseo_listxattr;
	fuse_ops->removexattr	    = cfuseo_removexattr;
	fuse_ops->opendir           = cfuseo_opendir;
	fuse_ops->readdir           = cfuseo_readdir;
	fuse_ops->releasedir        = cfuseo_releasedir;
	fuse_ops->fsyncdir          = cfuseo_fsyncdir;
	fuse_ops->access            = cfuseo_access;
	fuse_ops->create            = NULL_PTR;
	fuse_ops->lock              = NULL_PTR;
	fuse_ops->utimens           = cfuseo_utimens;

	fuse_ops->bmap              = NULL_PTR;
	fuse_ops->ioctl             = NULL_PTR;
	fuse_ops->poll              = NULL_PTR;
	fuse_ops->write_buf         = NULL_PTR;
	fuse_ops->read_buf          = NULL_PTR;
	fuse_ops->flock             = NULL_PTR;
	fuse_ops->fallocate         = cfuseo_fallocate;
	fuse_ops->copy_file_range   = NULL_PTR;
	fuse_ops->lseek             = NULL_PTR;

	return;
}

void cfuseo_clean_ops(CFUSEO_MD *cfuseo_md)
{
    struct fuse_operations     *fuse_ops;

    fuse_ops = CFUSEO_MD_OPS(cfuseo_md);

    BSET(fuse_ops, 0x00, sizeof(*fuse_ops));

	return;
}


CFUSEO_TASK *cfuseo_task_get(CFUSEO_MD *cfuseo_md)
{
    return CFUSEO_MD_TASK(cfuseo_md);
}

uint64_t cfuseo_task_num_inc(CFUSEO_MD *cfuseo_md)
{
    return __sync_fetch_and_add(CFUSEO_MD_TASK_NUM(cfuseo_md), 1);
}

uint64_t cfuseo_task_num_dec(CFUSEO_MD *cfuseo_md)
{
    return __sync_fetch_and_sub(CFUSEO_MD_TASK_NUM(cfuseo_md), 1);
}

uint64_t cfuseo_task_num_get(CFUSEO_MD *cfuseo_md)
{
    return __sync_fetch_and_sub(CFUSEO_MD_TASK_NUM(cfuseo_md), 0);
}

void cfuseo_task_wait(CFUSEO_MD *cfuseo_md)
{
    c_cond_reserve(CFUSEO_MD_CCOND(cfuseo_md), 1, LOC_CFUSEO_0003);
    c_cond_wait(CFUSEO_MD_CCOND(cfuseo_md), LOC_CFUSEO_0004);
    return;
}

void cfuseo_task_resume(CFUSEO_MD *cfuseo_md)
{
    c_cond_release(CFUSEO_MD_CCOND(cfuseo_md), LOC_CFUSEO_0005);
    return;
}

/*note: called by master thread but not worker thread*/
EC_BOOL cfuseo_task_caller(CFUSEO_MD *cfuseo_md)
{
    if(0 < cfuseo_task_num_get(cfuseo_md))
    {
        UINT32          res;

        cfuseo_task_num_dec(cfuseo_md);

        ASSERT(MAX_NUM_OF_FUNC_PARAS == 16);
        res = (int)dbg_tiny_caller(
                        CFUSEO_TASK_PARA_NUM(CFUSEO_MD_TASK(cfuseo_md)),
                        CFUSEO_TASK_FUNC_ADDR(CFUSEO_MD_TASK(cfuseo_md)),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  0),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  1),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  2),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  3),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  4),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  5),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  6),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  7),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  8),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md),  9),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md), 10),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md), 11),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md), 12),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md), 13),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md), 14),
                        CFUSEO_TASK_PARA_VAL(CFUSEO_MD_TASK(cfuseo_md), 15)
                        );

        CFUSEO_TASK_RET_VAL(CFUSEO_MD_TASK(cfuseo_md)) = (int)res;

        cfuseo_task_resume(cfuseo_md);
    }

    return (EC_TRUE);
}

EC_BOOL cfuseo_process(CFUSEO_MD *cfuseo_md)
{
    if(0 < cfuseo_task_num_get(cfuseo_md))
    {
        coroutine_pool_load(TASK_BRD_CROUTINE_POOL(task_brd_default_get()),
                            (UINT32)cfuseo_task_caller, (UINT32)1, cfuseo_md);
    }

    task_brd_process_add(task_brd_default_get(),
                         (TASK_BRD_CALLBACK)cfuseo_process,
                         (void *)cfuseo_md);

    return (EC_TRUE);
}

/*int (*getattr) (const char *, struct stat *);*/
int cfuseo_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_getattr");

    CFUSEO_TASK_FUNC_SET(cfusec_getattr);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, stat);
    CFUSEO_TASK_PARA_VAL_SET(2, fi);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*readlink) (const char *, char *, size_t);*/
int cfuseo_readlink(const char *path, char *buf, size_t size)
{
    CFUSEO_DEBUG_ENTER("cfuseo_readlink");

    CFUSEO_TASK_FUNC_SET(cfusec_readlink);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, buf);
    CFUSEO_TASK_PARA_VAL_SET(2, size);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cfuseo_mknod(const char *path, mode_t mode, dev_t dev)
{
    CFUSEO_DEBUG_ENTER("cfuseo_mknod");

    CFUSEO_TASK_FUNC_SET(cfusec_mknod);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, mode);
    CFUSEO_TASK_PARA_VAL_SET(2, dev);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*mkdir) (const char *, mode_t);*/
int cfuseo_mkdir(const char *path, mode_t mode)
{
    CFUSEO_DEBUG_ENTER("cfuseo_mkdir");

    CFUSEO_TASK_FUNC_SET(cfusec_mkdir);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, mode);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*unlink) (const char *);*/
int cfuseo_unlink(const char *path)
{
    CFUSEO_DEBUG_ENTER("cfuseo_unlink");

    CFUSEO_TASK_FUNC_SET(cfusec_unlink);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_NUM_SET(1);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*rmdir) (const char *);*/
int cfuseo_rmdir(const char *path)
{
    CFUSEO_DEBUG_ENTER("cfuseo_rmdir");

    CFUSEO_TASK_FUNC_SET(cfusec_rmdir);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_NUM_SET(1);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cfuseo_symlink(const char *src_path, const char *des_path)
{
    CFUSEO_DEBUG_ENTER("cfuseo_symlink");

    CFUSEO_TASK_FUNC_SET(cfusec_symlink);
    CFUSEO_TASK_PARA_VAL_SET(0, src_path);
    CFUSEO_TASK_PARA_VAL_SET(1, des_path);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*rename) (const char *, const char *, unsigned int flags);*/
int cfuseo_rename(const char *src_path, const char *des_path, unsigned int flags /*RENAME_EXCHANGE|RENAME_NOREPLACE*/)
{
    CFUSEO_DEBUG_ENTER("cfuseo_rename");

    CFUSEO_TASK_FUNC_SET(cfusec_rename);
    CFUSEO_TASK_PARA_VAL_SET(0, src_path);
    CFUSEO_TASK_PARA_VAL_SET(1, des_path);
    CFUSEO_TASK_PARA_VAL_SET(2, flags);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cfuseo_link(const char *src_path, const char *des_path)
{
    CFUSEO_DEBUG_ENTER("cfuseo_link");

    CFUSEO_TASK_FUNC_SET(cfusec_link);
    CFUSEO_TASK_PARA_VAL_SET(0, src_path);
    CFUSEO_TASK_PARA_VAL_SET(1, des_path);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t, struct fuse_file_info *fi);*/
int cfuseo_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_chmod");

    CFUSEO_TASK_FUNC_SET(cfusec_chmod);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, mode);
    CFUSEO_TASK_PARA_VAL_SET(2, fi);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cfuseo_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_chown");

    CFUSEO_TASK_FUNC_SET(cfusec_chown);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, owner);
    CFUSEO_TASK_PARA_VAL_SET(2, group);
    CFUSEO_TASK_PARA_VAL_SET(3, fi);
    CFUSEO_TASK_PARA_NUM_SET(4);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cfuseo_truncate(const char *path, off_t length, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_truncate");

    CFUSEO_TASK_FUNC_SET(cfusec_truncate);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, length);
    CFUSEO_TASK_PARA_VAL_SET(2, fi);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cfuseo_utime(const char *path, /*const*/struct utimbuf *times)
{
    CFUSEO_DEBUG_ENTER("cfuseo_utime");

    CFUSEO_TASK_FUNC_SET(cfusec_utime);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, times);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*open) (const char *, struct fuse_file_info *);*/
int cfuseo_open(const char *path, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_open");

    CFUSEO_TASK_FUNC_SET(cfusec_open);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, fi);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);*/
int cfuseo_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_read");

    CFUSEO_TASK_FUNC_SET(cfusec_read);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, buf);
    CFUSEO_TASK_PARA_VAL_SET(2, size);
    CFUSEO_TASK_PARA_VAL_SET(3, offset);
    CFUSEO_TASK_PARA_VAL_SET(4, fi);
    CFUSEO_TASK_PARA_NUM_SET(5);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);*/
int cfuseo_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_write");

    CFUSEO_TASK_FUNC_SET(cfusec_write);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, buf);
    CFUSEO_TASK_PARA_VAL_SET(2, size);
    CFUSEO_TASK_PARA_VAL_SET(3, offset);
    CFUSEO_TASK_PARA_VAL_SET(4, fi);
    CFUSEO_TASK_PARA_NUM_SET(5);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*statfs) (const char *, struct statvfs *);*/
int cfuseo_statfs(const char *path, struct statvfs *statvfs)
{
    CFUSEO_DEBUG_ENTER("cfuseo_statfs");

    CFUSEO_TASK_FUNC_SET(cfusec_statfs);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, statvfs);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*flush) (const char *, struct fuse_file_info *);*/
int cfuseo_flush(const char *path, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_flush");

    CFUSEO_TASK_FUNC_SET(cfusec_flush);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, fi);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*release) (const char *, struct fuse_file_info *);*/
int cfuseo_release(const char *path, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_release");

    CFUSEO_TASK_FUNC_SET(cfusec_release);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, fi);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*fsync) (const char *, int);*/
int cfuseo_fsync(const char * path, int sync, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_fsync");

    CFUSEO_TASK_FUNC_SET(cfusec_fsync);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, sync);
    CFUSEO_TASK_PARA_VAL_SET(2, fi);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cfuseo_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    CFUSEO_DEBUG_ENTER("cfuseo_setxattr");

    CFUSEO_TASK_FUNC_SET(cfusec_setxattr);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, name);
    CFUSEO_TASK_PARA_VAL_SET(2, value);
    CFUSEO_TASK_PARA_VAL_SET(3, size);
    CFUSEO_TASK_PARA_VAL_SET(4, flags);
    CFUSEO_TASK_PARA_NUM_SET(5);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cfuseo_getxattr(const char *path, const char *name, char *value, size_t size)
{
    CFUSEO_DEBUG_ENTER("cfuseo_getxattr");

    CFUSEO_TASK_FUNC_SET(cfusec_getxattr);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, name);
    CFUSEO_TASK_PARA_VAL_SET(2, value);
    CFUSEO_TASK_PARA_VAL_SET(3, size);
    CFUSEO_TASK_PARA_NUM_SET(4);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cfuseo_listxattr(const char *path, char *list, size_t size)
{
    CFUSEO_DEBUG_ENTER("cfuseo_listxattr");

    CFUSEO_TASK_FUNC_SET(cfusec_listxattr);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, list);
    CFUSEO_TASK_PARA_VAL_SET(2, size);
    CFUSEO_TASK_PARA_NUM_SET(3);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cfuseo_removexattr(const char *path, const char *name)
{
    CFUSEO_DEBUG_ENTER("cfuseo_removexattr");

    CFUSEO_TASK_FUNC_SET(cfusec_removexattr);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, name);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*access) (const char *, int);*/
int cfuseo_access(const char *path, int mask)
{
    CFUSEO_DEBUG_ENTER("cfuseo_access");

    CFUSEO_TASK_FUNC_SET(cfusec_access);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, mask);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*ftruncate) (const char *, off_t, struct fuse_file_info *);*/
int cfuseo_ftruncate(const char *path, off_t offset)
{
    CFUSEO_DEBUG_ENTER("cfuseo_ftruncate");

    CFUSEO_TASK_FUNC_SET(cfusec_ftruncate);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, offset);
    CFUSEO_TASK_PARA_NUM_SET(2);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}


/*int (*utimens) (const char *, const struct timespec tv[2], struct fuse_file_info *fi);*/
int cfuseo_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_utimens");

    CFUSEO_TASK_FUNC_SET(cfusec_utimens);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, &ts[0]);
    CFUSEO_TASK_PARA_VAL_SET(2, &ts[1]);
    CFUSEO_TASK_PARA_VAL_SET(3, fi);
    CFUSEO_TASK_PARA_NUM_SET(4);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/* int (*fallocate) (const char *, int, off_t, off_t, struct fuse_file_info *); */
int cfuseo_fallocate(const char * path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
    CFUSEO_DEBUG_ENTER("cfuseo_fallocate");

    CFUSEO_TASK_FUNC_SET(cfusec_fallocate);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, mode);
    CFUSEO_TASK_PARA_VAL_SET(2, offset);
    CFUSEO_TASK_PARA_VAL_SET(3, length);
    CFUSEO_TASK_PARA_VAL_SET(4, fi);
    CFUSEO_TASK_PARA_NUM_SET(5);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cfuseo_opendir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CFUSEO_DEBUG_ENTER("cfuseo_opendir");

    return (0);
}

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cfuseo_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags eflags)
{
    CFUSEO_DEBUG_ENTER("cfuseo_readdir");

    CFUSEO_TASK_FUNC_SET(cfusec_readdir);
    CFUSEO_TASK_PARA_VAL_SET(0, path);
    CFUSEO_TASK_PARA_VAL_SET(1, buf);
    CFUSEO_TASK_PARA_VAL_SET(2, filler);
    CFUSEO_TASK_PARA_VAL_SET(3, offset);
    CFUSEO_TASK_PARA_VAL_SET(4, fi);
    CFUSEO_TASK_PARA_VAL_SET(5, eflags);
    CFUSEO_TASK_PARA_NUM_SET(6);

    CFUSEO_TASK_EMIT();

    return CFUSEO_TASK_RET_VAL_GET();
}

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cfuseo_releasedir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CFUSEO_DEBUG_ENTER("cfuseo_releasedir");
    return (0);
}

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cfuseo_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    (void)path;
    (void)datasync;
    (void)fi;

    CFUSEO_DEBUG_ENTER("cfuseo_fsyncdir");
    return (0);
}

#endif/*(SWITCH_ON == FUSE_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

