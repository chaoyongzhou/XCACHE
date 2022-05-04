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
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

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

/*----------------------------------------------------------------------------*\
 *                             CFUSE ORIGIN                                   *
 *                                                                            *
 * cxfs_fuseo define interfaces which would be registered to fuse.                *
 * cxfs_fuseo interface is called by fuse and then emit task to cxfs_fusec.           *
 * cxfs_fuseo is running in a single thread and communicate with kernel FUSE MOD  *
 * in blocking mode.                                                          *
 * cxfs_fuseo must not alloc mem with BGN memory manager.                         *
 * cxfs_fuseo emit task to cxfs_fusec in atomic operation and shared memory to reduce *
 * encoding & decoding & data copying.                                        *
 * cxfs_fuseo emit task and then fall in thread suspending with condition lock.   *
 * the emitted task by cxfs_fuseo would be running in one coroutine by cxfs_fusec.    *
 * cxfs_fusec deploy and execute the emitted task from cxfs_fuseo and then unlock     *
 * cxfs_fuseo thread condition lock.                                              *
\*----------------------------------------------------------------------------*/

#define CXFS_FUSEO_PATH_MAX_SIZE   (8192) /*8K > PATH_MAX*/
#define CXFS_FUSEO_PATH_MAX_NUM    (8)

static CXFS_FUSEO_MD                g_cxfs_fuseo_md;
static char                         g_cwd[CXFS_FUSEO_PATH_MAX_SIZE];
static char                         g_path_cache[CXFS_FUSEO_PATH_MAX_NUM][CXFS_FUSEO_PATH_MAX_SIZE];
static uint32_t                     g_path_idx = 0;

#define CXFS_FUSEO_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0071_CXFS_FUSEO, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")

#define CXFS_FUSEO_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0071_CXFS_FUSEO, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")

#define CXFS_FUSEO_TASK_DEFAULT() CXFS_FUSEO_MD_TASK(cxfs_fuseo_md_default_get())

#define CXFS_FUSEO_TASK_FUNC_SET(func)    do{                                     \
    CXFS_FUSEO_TASK_FUNC_ADDR(CXFS_FUSEO_TASK_DEFAULT()) = ((UINT32)func);            \
    CXFS_FUSEO_TASK_FUNC_NAME(CXFS_FUSEO_TASK_DEFAULT()) = ((const char *)# func );   \
}while(0)

#define CXFS_FUSEO_TASK_PARA_NUM_SET(num)    do{                                  \
    CXFS_FUSEO_TASK_PARA_NUM(CXFS_FUSEO_TASK_DEFAULT()) = ((UINT32)num);              \
}while(0)

#define CXFS_FUSEO_TASK_PARA_VAL_SET(idx, val)    do{                             \
    CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_TASK_DEFAULT(), idx) = ((UINT32)val);         \
}while(0)

#define CXFS_FUSEO_TASK_EMIT()    do{                                             \
    cxfs_fuseo_task_num_inc(cxfs_fuseo_md_default_get());                             \
    task_brd_inc_notify_counter(task_brd_default_get());                      \
    cxfs_fuseo_task_wait(cxfs_fuseo_md_default_get());                                \
}while(0)

#define CXFS_FUSEO_TASK_RET_VAL_GET() CXFS_FUSEO_TASK_RET_VAL(CXFS_FUSEO_TASK_DEFAULT())

CXFS_FUSEO_MD *cxfs_fuseo_md_default_get()
{
    return &g_cxfs_fuseo_md;
}

STATIC_CAST const char *__cxfs_fuseo_set_cwd(const char *path)
{
    if(NULL_PTR != path)
    {
        strcpy((char *)g_cwd, path);
        c_realpath((char *)g_cwd);
        dbg_log(SEC_0071_CXFS_FUSEO, 9)(LOGSTDOUT, "[DEBUG]__cxfs_fuseo_set_cwd: "
                                                   "'%s' => realpath '%s'\n",
                                                   path, (char *)g_cwd);
    }

    return (const char *)g_cwd;
}

STATIC_CAST const char *__cxfs_fuseo_get_cwd()
{
    return (const char *)g_cwd;
}

/**
*
* start CXFS_FUSEO module
*
**/
EC_BOOL cxfs_fuseo_start(struct fuse_args *args)
{
    CXFS_FUSEO_MD *cxfs_fuseo_md;

    cxfs_fuseo_md = cxfs_fuseo_md_default_get();

    cxfs_fuseo_init_ops(cxfs_fuseo_md);

	c_cond_init(CXFS_FUSEO_MD_CCOND(cxfs_fuseo_md), LOC_CXFSFUSEO_0001);

	__cxfs_fuseo_set_cwd("/");

    dbg_log(SEC_0071_CXFS_FUSEO, 0)(LOGSTDOUT, "[DEBUG] cxfs_fuseo_start: launch fuse\n");

    /*block thread when communicate with kernel fuse*/
    fuse_main(args->argc, args->argv, CXFS_FUSEO_MD_OPS(cxfs_fuseo_md), NULL_PTR);

    return (EC_TRUE);
}

/**
*
* end CXFS_FUSEO module
*
**/
void cxfs_fuseo_end()
{
    CXFS_FUSEO_MD *cxfs_fuseo_md;

    cxfs_fuseo_md = cxfs_fuseo_md_default_get();

    cxfs_fuseo_clean_ops(cxfs_fuseo_md);

    c_cond_clean(CXFS_FUSEO_MD_CCOND(cxfs_fuseo_md), LOC_CXFSFUSEO_0002);

    return;
}

void cxfs_fuseo_init_ops(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    struct fuse_operations     *fuse_ops;

    fuse_ops = CXFS_FUSEO_MD_OPS(cxfs_fuseo_md);

    BSET(fuse_ops, 0x00, sizeof(*fuse_ops));

	fuse_ops->getattr	        = cxfs_fuseo_getattr;
	fuse_ops->readlink	        = cxfs_fuseo_readlink;
	fuse_ops->mknod             = cxfs_fuseo_mknod;
	fuse_ops->mkdir		        = cxfs_fuseo_mkdir;
	fuse_ops->unlink		    = cxfs_fuseo_unlink;
	fuse_ops->rmdir		        = cxfs_fuseo_rmdir;
	fuse_ops->symlink	        = cxfs_fuseo_symlink;
	fuse_ops->rename		    = cxfs_fuseo_rename;
	fuse_ops->link		        = cxfs_fuseo_link;
	fuse_ops->chmod		        = cxfs_fuseo_chmod;
	fuse_ops->chown		        = cxfs_fuseo_chown;
	fuse_ops->truncate	        = cxfs_fuseo_truncate;
	fuse_ops->open		        = cxfs_fuseo_open;
	fuse_ops->read		        = cxfs_fuseo_read;
	fuse_ops->write		        = cxfs_fuseo_write;
	fuse_ops->statfs		    = cxfs_fuseo_statfs;
	fuse_ops->flush		        = cxfs_fuseo_flush;
	fuse_ops->release	        = cxfs_fuseo_release;
	fuse_ops->fsync		        = cxfs_fuseo_fsync;
	fuse_ops->setxattr	        = cxfs_fuseo_setxattr;
	fuse_ops->getxattr	        = cxfs_fuseo_getxattr;
	fuse_ops->listxattr	        = cxfs_fuseo_listxattr;
	fuse_ops->removexattr	    = cxfs_fuseo_removexattr;
	fuse_ops->opendir           = cxfs_fuseo_opendir;
	fuse_ops->readdir           = cxfs_fuseo_readdir;
	fuse_ops->releasedir        = cxfs_fuseo_releasedir;
	fuse_ops->fsyncdir          = cxfs_fuseo_fsyncdir;
	fuse_ops->access            = cxfs_fuseo_access;
	fuse_ops->create            = NULL_PTR;
	fuse_ops->lock              = NULL_PTR;
	fuse_ops->utimens           = cxfs_fuseo_utimens;

	fuse_ops->bmap              = NULL_PTR;
	fuse_ops->ioctl             = NULL_PTR;
	fuse_ops->poll              = NULL_PTR;
	fuse_ops->write_buf         = NULL_PTR;
	fuse_ops->read_buf          = NULL_PTR;
	fuse_ops->flock             = NULL_PTR;
	fuse_ops->fallocate         = cxfs_fuseo_fallocate;
	fuse_ops->copy_file_range   = NULL_PTR;
	fuse_ops->lseek             = NULL_PTR;

	return;
}

void cxfs_fuseo_clean_ops(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    struct fuse_operations     *fuse_ops;

    fuse_ops = CXFS_FUSEO_MD_OPS(cxfs_fuseo_md);

    BSET(fuse_ops, 0x00, sizeof(*fuse_ops));

	return;
}


CXFS_FUSEO_TASK *cxfs_fuseo_task_get(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    return CXFS_FUSEO_MD_TASK(cxfs_fuseo_md);
}

uint64_t cxfs_fuseo_task_num_inc(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    return __sync_fetch_and_add(CXFS_FUSEO_MD_TASK_NUM(cxfs_fuseo_md), 1);
}

uint64_t cxfs_fuseo_task_num_dec(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    return __sync_fetch_and_sub(CXFS_FUSEO_MD_TASK_NUM(cxfs_fuseo_md), 1);
}

uint64_t cxfs_fuseo_task_num_get(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    return __sync_fetch_and_sub(CXFS_FUSEO_MD_TASK_NUM(cxfs_fuseo_md), 0);
}

void cxfs_fuseo_task_wait(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    c_cond_reserve(CXFS_FUSEO_MD_CCOND(cxfs_fuseo_md), 1, LOC_CXFSFUSEO_0003);
    c_cond_wait(CXFS_FUSEO_MD_CCOND(cxfs_fuseo_md), LOC_CXFSFUSEO_0004);
    return;
}

void cxfs_fuseo_task_resume(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    c_cond_release(CXFS_FUSEO_MD_CCOND(cxfs_fuseo_md), LOC_CXFSFUSEO_0005);
    return;
}

/*note: called by master thread but not worker thread*/
EC_BOOL cxfs_fuseo_task_caller(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    if(0 < cxfs_fuseo_task_num_get(cxfs_fuseo_md))
    {
        UINT32          res;

        cxfs_fuseo_task_num_dec(cxfs_fuseo_md);

        ASSERT(MAX_NUM_OF_FUNC_PARAS == 16);
        res = (int)dbg_tiny_caller(
                        CXFS_FUSEO_TASK_PARA_NUM(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md)),
                        CXFS_FUSEO_TASK_FUNC_ADDR(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md)),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  0),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  1),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  2),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  3),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  4),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  5),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  6),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  7),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  8),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md),  9),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md), 10),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md), 11),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md), 12),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md), 13),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md), 14),
                        CXFS_FUSEO_TASK_PARA_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md), 15)
                        );

        CXFS_FUSEO_TASK_RET_VAL(CXFS_FUSEO_MD_TASK(cxfs_fuseo_md)) = (int)res;

        cxfs_fuseo_task_resume(cxfs_fuseo_md);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_fuseo_process(CXFS_FUSEO_MD *cxfs_fuseo_md)
{
    if(0 < cxfs_fuseo_task_num_get(cxfs_fuseo_md))
    {
        coroutine_pool_load(TASK_BRD_CROUTINE_POOL(task_brd_default_get()),
                            (UINT32)cxfs_fuseo_task_caller, (UINT32)1, cxfs_fuseo_md);
    }

    task_brd_process_add(task_brd_default_get(),
                         (TASK_BRD_CALLBACK)cxfs_fuseo_process,
                         (void *)cxfs_fuseo_md);

    return (EC_TRUE);
}

STATIC_CAST char *__cxfs_fuseo_path_cache_get()
{
    char *path_cache;

    path_cache = (char *)g_path_cache[ g_path_idx % CXFS_FUSEO_PATH_MAX_NUM ];
    g_path_idx = (g_path_idx + 1) % CXFS_FUSEO_PATH_MAX_NUM;

    return (path_cache);
}

/*absoulte path*/
STATIC_CAST const char *__cxfs_fuseo_abs_path(const char *path)
{
    if(NULL_PTR != path && '/' != path[0])
    {
        char        *abs_path;

        abs_path = __cxfs_fuseo_path_cache_get();
        snprintf(abs_path, CXFS_FUSEO_PATH_MAX_SIZE - 1, "%s/%s", __cxfs_fuseo_get_cwd(), path);
        abs_path = c_realpath(abs_path);

        dbg_log(SEC_0071_CXFS_FUSEO, 9)(LOGSTDOUT, "[DEBUG]__cxfs_fuseo_abs_path: "
                                                   "cwd '%s' path '%s' => abs path '%s'\n",
                                                   __cxfs_fuseo_get_cwd(), path, abs_path);

        return (abs_path);
    }

    return (path);
}

/*int (*getattr) (const char *, struct stat *);*/
int cxfs_fuseo_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_getattr");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_getattr);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, stat);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*readlink) (const char *, char *, size_t);*/
int cxfs_fuseo_readlink(const char *path, char *buf, size_t size)
{
    const char    *abs_path;

    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_readlink");

    abs_path = __cxfs_fuseo_abs_path(path);

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_readlink);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, abs_path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, buf);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, size);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cxfs_fuseo_mknod(const char *path, mode_t mode, dev_t dev)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_mknod");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_mknod);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, mode);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, dev);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*mkdir) (const char *, mode_t);*/
int cxfs_fuseo_mkdir(const char *path, mode_t mode)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_mkdir");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_mkdir);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, mode);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*unlink) (const char *);*/
int cxfs_fuseo_unlink(const char *path)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_unlink");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_unlink);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_NUM_SET(1);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*rmdir) (const char *);*/
int cxfs_fuseo_rmdir(const char *path)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_rmdir");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_rmdir);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_NUM_SET(1);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cxfs_fuseo_symlink(const char *src_path, const char *des_path)
{
    const char    *src_abs_path;

    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_symlink");

    src_abs_path = __cxfs_fuseo_abs_path(src_path);

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_symlink);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, src_abs_path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, des_path);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*rename) (const char *, const char *, unsigned int flags);*/
int cxfs_fuseo_rename(const char *src_path, const char *des_path, unsigned int flags /*RENAME_EXCHANGE|RENAME_NOREPLACE*/)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_rename");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_rename);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, src_path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, des_path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, flags);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cxfs_fuseo_link(const char *src_path, const char *des_path)
{
    const char    *src_abs_path;

    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_link");

    src_abs_path = __cxfs_fuseo_abs_path(src_path);

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_link);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, src_abs_path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, des_path);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t, struct fuse_file_info *fi);*/
int cxfs_fuseo_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_chmod");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_chmod);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, mode);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cxfs_fuseo_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_chown");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_chown);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, owner);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, group);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(4);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cxfs_fuseo_truncate(const char *path, off_t length, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_truncate");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_truncate);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, length);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cxfs_fuseo_utime(const char *path, /*const*/struct utimbuf *times)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_utime");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_utime);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, times);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*open) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_open(const char *path, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_open");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_open);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    if(NULL_PTR != fi
    && 0 == CXFS_FUSEO_TASK_RET_VAL_GET())
    {
	/** In case of a write operation indicates if this was caused
	    by a delayed write from the page cache. If so, then the
	    context's pid, uid, and gid fields will not be valid, and
	    the *fh* value may not match the *fh* value that would
	    have been sent with the corresponding individual write
	    requests if write caching had been disabled. */
        fi->writepage           = 0;

        /** Can be filled in by open, to use direct I/O on this file. */
        fi->direct_io           = 0;

	/** Can be filled in by open. It signals the kernel that any
	    currently cached file data (ie., data that the filesystem
	    provided the last time the file was open) need not be
	    invalidated. Has no effect when set in other contexts (in
	    particular it does nothing when set by opendir()). */
        fi->keep_cache          = 0;

	/** Indicates a flush operation.  Set in flush operation, also
	    maybe set in highlevel lock operation and lowlevel release
	    operation. */
        fi->flush               = 0;

	/** Can be filled in by open, to indicate that the file is not
	    seekable. */
        fi->nonseekable         = 0;

	/* Indicates that flock locks for this file should be
	   released.  If set, lock_owner shall contain a valid value.
	   May only be set in ->release(). */
        fi->flock_release       = 0;

	/** Can be filled in by opendir. It signals the kernel to
	    enable caching of entries returned by readdir().  Has no
	    effect when set in other contexts (in particular it does
	    nothing when set by open()). */
        fi->cache_readdir       = 0;

	/** File handle id.  May be filled in by filesystem in create,
	 * open, and opendir().  Available in most other file operations on the
	 * same file handle. */
        fi->fh                  = 0;

	/** Lock owner id.  Available in locking operations and flush */
        fi->lock_owner          = 0;

	/** Requested poll events.  Available in ->poll.  Only set on kernels
	    which support it.  If unsupported, this field is set to zero. */
        fi->poll_events         = 0;

    }

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);*/
int cxfs_fuseo_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_read");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_read);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, buf);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, size);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, offset);
    CXFS_FUSEO_TASK_PARA_VAL_SET(4, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(5);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);*/
int cxfs_fuseo_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_write");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_write);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, buf);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, size);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, offset);
    CXFS_FUSEO_TASK_PARA_VAL_SET(4, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(5);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*statfs) (const char *, struct statvfs *);*/
int cxfs_fuseo_statfs(const char *path, struct statvfs *statvfs)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_statfs");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_statfs);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, statvfs);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*flush) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_flush(const char *path, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_flush");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_flush);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*release) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_release(const char *path, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_release");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_release);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*fsync) (const char *, int);*/
int cxfs_fuseo_fsync(const char * path, int sync, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_fsync");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_fsync);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, sync);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cxfs_fuseo_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_setxattr");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_setxattr);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, name);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, value);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, size);
    CXFS_FUSEO_TASK_PARA_VAL_SET(4, flags);
    CXFS_FUSEO_TASK_PARA_NUM_SET(5);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cxfs_fuseo_getxattr(const char *path, const char *name, char *value, size_t size)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_getxattr");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_getxattr);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, name);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, value);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, size);
    CXFS_FUSEO_TASK_PARA_NUM_SET(4);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cxfs_fuseo_listxattr(const char *path, char *list, size_t size)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_listxattr");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_listxattr);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, list);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, size);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cxfs_fuseo_removexattr(const char *path, const char *name)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_removexattr");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_removexattr);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, name);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*access) (const char *, int);*/
int cxfs_fuseo_access(const char *path, int mask)
{
    UINT32    mode;
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_access");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_access);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, mask);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, (uintptr_t)&mode);
    CXFS_FUSEO_TASK_PARA_NUM_SET(3);

    CXFS_FUSEO_TASK_EMIT();

    if(0 == CXFS_FUSEO_TASK_RET_VAL_GET() && (((uint16_t)mode) & S_IFDIR))
    {
        __cxfs_fuseo_set_cwd(path);
        dbg_log(SEC_0071_CXFS_FUSEO, 9)(LOGSTDOUT, "[DEBUG] cxfs_fuseo_access: "
                                                   "set cwd %s (%s)\n",
                                                   path, __cxfs_fuseo_get_cwd());
    }

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*ftruncate) (const char *, off_t, struct fuse_file_info *);*/
int cxfs_fuseo_ftruncate(const char *path, off_t offset)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_ftruncate");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_ftruncate);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, offset);
    CXFS_FUSEO_TASK_PARA_NUM_SET(2);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}


/*int (*utimens) (const char *, const struct timespec tv[2], struct fuse_file_info *fi);*/
int cxfs_fuseo_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_utimens");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_utimens);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, &ts[0]);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, &ts[1]);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(4);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/* int (*fallocate) (const char *, int, off_t, off_t, struct fuse_file_info *); */
int cxfs_fuseo_fallocate(const char * path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_fallocate");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_fallocate);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, mode);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, offset);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, length);
    CXFS_FUSEO_TASK_PARA_VAL_SET(4, fi);
    CXFS_FUSEO_TASK_PARA_NUM_SET(5);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_opendir(const char *path, struct fuse_file_info *fi)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_opendir");

    (void)path;

    if(NULL_PTR != fi)
    {
	/** In case of a write operation indicates if this was caused
	    by a delayed write from the page cache. If so, then the
	    context's pid, uid, and gid fields will not be valid, and
	    the *fh* value may not match the *fh* value that would
	    have been sent with the corresponding individual write
	    requests if write caching had been disabled. */
        fi->writepage           = 0;

        /** Can be filled in by open, to use direct I/O on this file. */
        fi->direct_io           = 0;

	/** Can be filled in by open. It signals the kernel that any
	    currently cached file data (ie., data that the filesystem
	    provided the last time the file was open) need not be
	    invalidated. Has no effect when set in other contexts (in
	    particular it does nothing when set by opendir()). */
        fi->keep_cache          = 0;

	/** Indicates a flush operation.  Set in flush operation, also
	    maybe set in highlevel lock operation and lowlevel release
	    operation. */
        fi->flush               = 0;

	/** Can be filled in by open, to indicate that the file is not
	    seekable. */
        fi->nonseekable         = 0;

	/* Indicates that flock locks for this file should be
	   released.  If set, lock_owner shall contain a valid value.
	   May only be set in ->release(). */
        fi->flock_release       = 0;

	/** Can be filled in by opendir. It signals the kernel to
	    enable caching of entries returned by readdir().  Has no
	    effect when set in other contexts (in particular it does
	    nothing when set by open()). */
        fi->cache_readdir       = 0;

	/** File handle id.  May be filled in by filesystem in create,
	 * open, and opendir().  Available in most other file operations on the
	 * same file handle. */
        fi->fh                  = 0;

	/** Lock owner id.  Available in locking operations and flush */
        fi->lock_owner          = 0;

	/** Requested poll events.  Available in ->poll.  Only set on kernels
	    which support it.  If unsupported, this field is set to zero. */
        fi->poll_events         = 0;

    }

    return (0);
}

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cxfs_fuseo_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags eflags)
{
    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_readdir");

    CXFS_FUSEO_TASK_FUNC_SET(cxfs_fusec_readdir);
    CXFS_FUSEO_TASK_PARA_VAL_SET(0, path);
    CXFS_FUSEO_TASK_PARA_VAL_SET(1, buf);
    CXFS_FUSEO_TASK_PARA_VAL_SET(2, filler);
    CXFS_FUSEO_TASK_PARA_VAL_SET(3, offset);
    CXFS_FUSEO_TASK_PARA_VAL_SET(4, fi);
    CXFS_FUSEO_TASK_PARA_VAL_SET(5, eflags);
    CXFS_FUSEO_TASK_PARA_NUM_SET(6);

    CXFS_FUSEO_TASK_EMIT();

    return CXFS_FUSEO_TASK_RET_VAL_GET();
}

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_releasedir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_releasedir");
    return (0);
}

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cxfs_fuseo_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    (void)path;
    (void)datasync;
    (void)fi;

    CXFS_FUSEO_DEBUG_ENTER("cxfs_fuseo_fsyncdir");
    return (0);
}

#endif/*(SWITCH_ON == CXFSFUSE_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

