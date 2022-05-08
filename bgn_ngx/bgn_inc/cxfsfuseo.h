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

#ifndef _CXFS_FUSEO_H
#define _CXFS_FUSEO_H

#if (SWITCH_ON == CXFSFUSE_SWITCH)

#include "type.h"
#include "mm.h"
#include "log.h"
#include "debug.h"

#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fuse.h>


typedef struct
{
    const char    *func_name;             /* func name*/
    UINT32         func_addr;             /* func address */
    UINT32         func_para_num;         /* func para num */

    int            func_ret_val;
    int            rsvd;
    UINT32         func_para[ MAX_NUM_OF_FUNC_PARAS ]; /*func parameter table*/
}CXFS_FUSEO_TASK;

#define CXFS_FUSEO_TASK_FUNC_NAME(cxfs_fuseo_task)          ((cxfs_fuseo_task)->func_name)
#define CXFS_FUSEO_TASK_FUNC_ADDR(cxfs_fuseo_task)          ((cxfs_fuseo_task)->func_addr)
#define CXFS_FUSEO_TASK_PARA_NUM(cxfs_fuseo_task)           ((cxfs_fuseo_task)->func_para_num)
#define CXFS_FUSEO_TASK_RET_VAL(cxfs_fuseo_task)            ((cxfs_fuseo_task)->func_ret_val)
#define CXFS_FUSEO_TASK_PARA_VAL(cxfs_fuseo_task, idx)      ((cxfs_fuseo_task)->func_para[ (idx) ])

typedef struct
{
    struct fuse_operations      fuse_ops;
    CCOND                       ccond;
    CXFS_FUSEO_TASK                 task_node;
    volatile uint64_t           task_num;
}CXFS_FUSEO_MD;

#define CXFS_FUSEO_MD_OPS(cxfs_fuseo_md)            (&((cxfs_fuseo_md)->fuse_ops))
#define CXFS_FUSEO_MD_CCOND(cxfs_fuseo_md)          (&((cxfs_fuseo_md)->ccond))
#define CXFS_FUSEO_MD_TASK(cxfs_fuseo_md)           (&((cxfs_fuseo_md)->task_node))
#define CXFS_FUSEO_MD_TASK_NUM(cxfs_fuseo_md)       (&((cxfs_fuseo_md)->task_num))


CXFS_FUSEO_MD *cxfs_fuseo_md_default_get();

/**
*
* start CXFS_FUSEO module
*
**/
EC_BOOL cxfs_fuseo_start(struct fuse_args *args);

/**
*
* end CXFS_FUSEO module
*
**/
void cxfs_fuseo_end();

void cxfs_fuseo_init_ops(CXFS_FUSEO_MD *cxfs_fuseo_md);

void cxfs_fuseo_clean_ops(CXFS_FUSEO_MD *cxfs_fuseo_md);

uint64_t cxfs_fuseo_task_num_inc(CXFS_FUSEO_MD *cxfs_fuseo_md);
uint64_t cxfs_fuseo_task_num_dec(CXFS_FUSEO_MD *cxfs_fuseo_md);
uint64_t cxfs_fuseo_task_num_get(CXFS_FUSEO_MD *cxfs_fuseo_md);

void cxfs_fuseo_task_wait(CXFS_FUSEO_MD *cxfs_fuseo_md);
void cxfs_fuseo_task_resume(CXFS_FUSEO_MD *cxfs_fuseo_md);

EC_BOOL cxfs_fuseo_task_caller(CXFS_FUSEO_MD *cxfs_fuseo_md);

EC_BOOL cxfs_fuseo_process(CXFS_FUSEO_MD *cxfs_fuseo_md);

/*int (*getattr) (const char *, struct stat *);*/
int cxfs_fuseo_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi);

/*int (*readlink) (const char *, char *, size_t);*/
int cxfs_fuseo_readlink(const char *path, char *buf, size_t size);

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cxfs_fuseo_mknod(const char *path, mode_t mode, dev_t dev);

/*int (*mkdir) (const char *, mode_t);*/
int cxfs_fuseo_mkdir(const char *path, mode_t mode);

/*int (*unlink) (const char *);*/
int cxfs_fuseo_unlink(const char *path);

/*int (*rmdir) (const char *);*/
int cxfs_fuseo_rmdir(const char *path);

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cxfs_fuseo_symlink(const char *src_path, const char *des_path);

/*int (*rename) (const char *, const char *);*/
int cxfs_fuseo_rename(const char *src_path, const char *des_path, unsigned int flags);

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cxfs_fuseo_link(const char *src_path, const char *des_path);

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t);*/
int cxfs_fuseo_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cxfs_fuseo_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi);

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cxfs_fuseo_truncate(const char *path, off_t length, struct fuse_file_info *fi);

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cxfs_fuseo_utime(const char *path, /*const*/struct utimbuf *times);

/*int (*open) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_open(const char *path, struct fuse_file_info *);

/*int (*create) (const char *, mode_t, struct fuse_file_info *);*/
int cxfs_fuseo_create(const char *path, mode_t mode, struct fuse_file_info *fi);

/*int (*read) (const char *, char *, size_t, off_t);*/
int cxfs_fuseo_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

/*int (*write) (const char *, const char *, size_t, off_t);*/
int cxfs_fuseo_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

/*int (*statfs) (const char *, struct statvfs *);*/
int cxfs_fuseo_statfs(const char *path, struct statvfs *statvfs);

/*int (*flush) (const char *);*/
int cxfs_fuseo_flush(const char *path, struct fuse_file_info *fi);

/*int (*release) (const char *, int flags);*/
int cxfs_fuseo_release(const char *path, struct fuse_file_info *fi);

/*int (*fsync) (const char *, int);*/
int cxfs_fuseo_fsync(const char * path, int sync, struct fuse_file_info *fi);

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cxfs_fuseo_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cxfs_fuseo_getxattr(const char *path, const char *name, char *value, size_t size);

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cxfs_fuseo_listxattr(const char *path, char *list, size_t size);

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cxfs_fuseo_removexattr(const char *path, const char *name);

/*int (*access) (const char *, int);*/
int cxfs_fuseo_access(const char *path, int mask);


/*int (*ftruncate) (const char *, off_t);*/
int cxfs_fuseo_ftruncate(const char *path, off_t offset);


/*int (*utimens) (const char *, const struct timespec tv[2]);*/
int cxfs_fuseo_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi);

/* int (*fallocate) (const char *, int, off_t, off_t); */
int cxfs_fuseo_fallocate(const char * path, int mode, off_t offset, off_t length, struct fuse_file_info *fi);

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_opendir(const char *path, struct fuse_file_info *fi);

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cxfs_fuseo_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cxfs_fuseo_releasedir(const char *path, struct fuse_file_info *fi);

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cxfs_fuseo_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi);

#endif/*(SWITCH_ON == FUSE_SWITCH)*/

#endif /*CXFSFUSE_SWITCH*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
