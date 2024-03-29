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

#ifndef _CFUSEO_H
#define _CFUSEO_H

#if (SWITCH_ON == FUSE_SWITCH)

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
}CFUSEO_TASK;

#define CFUSEO_TASK_FUNC_NAME(cfuseo_task)          ((cfuseo_task)->func_name)
#define CFUSEO_TASK_FUNC_ADDR(cfuseo_task)          ((cfuseo_task)->func_addr)
#define CFUSEO_TASK_PARA_NUM(cfuseo_task)           ((cfuseo_task)->func_para_num)
#define CFUSEO_TASK_RET_VAL(cfuseo_task)            ((cfuseo_task)->func_ret_val)
#define CFUSEO_TASK_PARA_VAL(cfuseo_task, idx)      ((cfuseo_task)->func_para[ (idx) ])

typedef struct
{
    struct fuse_operations      fuse_ops;
    CCOND                       ccond;
    CFUSEO_TASK                 task_node;
    volatile uint64_t           task_num;
}CFUSEO_MD;

#define CFUSEO_MD_OPS(cfuseo_md)            (&((cfuseo_md)->fuse_ops))
#define CFUSEO_MD_CCOND(cfuseo_md)          (&((cfuseo_md)->ccond))
#define CFUSEO_MD_TASK(cfuseo_md)           (&((cfuseo_md)->task_node))
#define CFUSEO_MD_TASK_NUM(cfuseo_md)       (&((cfuseo_md)->task_num))


CFUSEO_MD *cfuseo_md_default_get();

/**
*
* start CFUSEO module
*
**/
EC_BOOL cfuseo_start(struct fuse_args *args);

/**
*
* end CFUSEO module
*
**/
void cfuseo_end();

void cfuseo_init_ops(CFUSEO_MD *cfuseo_md);

void cfuseo_clean_ops(CFUSEO_MD *cfuseo_md);

uint64_t cfuseo_task_num_inc(CFUSEO_MD *cfuseo_md);
uint64_t cfuseo_task_num_dec(CFUSEO_MD *cfuseo_md);
uint64_t cfuseo_task_num_get(CFUSEO_MD *cfuseo_md);

void cfuseo_task_wait(CFUSEO_MD *cfuseo_md);
void cfuseo_task_resume(CFUSEO_MD *cfuseo_md);

EC_BOOL cfuseo_task_caller(CFUSEO_MD *cfuseo_md);

EC_BOOL cfuseo_process(CFUSEO_MD *cfuseo_md);

/*int (*getattr) (const char *, struct stat *);*/
int cfuseo_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi);

/*int (*readlink) (const char *, char *, size_t);*/
int cfuseo_readlink(const char *path, char *buf, size_t size);

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cfuseo_mknod(const char *path, mode_t mode, dev_t dev);

/*int (*mkdir) (const char *, mode_t);*/
int cfuseo_mkdir(const char *path, mode_t mode);

/*int (*unlink) (const char *);*/
int cfuseo_unlink(const char *path);

/*int (*rmdir) (const char *);*/
int cfuseo_rmdir(const char *path);

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cfuseo_symlink(const char *src_path, const char *des_path);

/*int (*rename) (const char *, const char *);*/
int cfuseo_rename(const char *src_path, const char *des_path, unsigned int flags);

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cfuseo_link(const char *src_path, const char *des_path);

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t);*/
int cfuseo_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cfuseo_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi);

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cfuseo_truncate(const char *path, off_t length, struct fuse_file_info *fi);

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cfuseo_utime(const char *path, /*const*/struct utimbuf *times);

/*int (*open) (const char *, struct fuse_file_info *);*/
int cfuseo_open(const char *path, struct fuse_file_info *);

/*int (*read) (const char *, char *, size_t, off_t);*/
int cfuseo_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

/*int (*write) (const char *, const char *, size_t, off_t);*/
int cfuseo_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

/*int (*statfs) (const char *, struct statvfs *);*/
int cfuseo_statfs(const char *path, struct statvfs *statvfs);

/*int (*flush) (const char *);*/
int cfuseo_flush(const char *path, struct fuse_file_info *fi);

/*int (*release) (const char *, int flags);*/
int cfuseo_release(const char *path, struct fuse_file_info *fi);

/*int (*fsync) (const char *, int);*/
int cfuseo_fsync(const char * path, int sync, struct fuse_file_info *fi);

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cfuseo_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cfuseo_getxattr(const char *path, const char *name, char *value, size_t size);

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cfuseo_listxattr(const char *path, char *list, size_t size);

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cfuseo_removexattr(const char *path, const char *name);

/*int (*access) (const char *, int);*/
int cfuseo_access(const char *path, int mask);


/*int (*ftruncate) (const char *, off_t);*/
int cfuseo_ftruncate(const char *path, off_t offset);


/*int (*utimens) (const char *, const struct timespec tv[2]);*/
int cfuseo_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi);

/* int (*fallocate) (const char *, int, off_t, off_t); */
int cfuseo_fallocate(const char * path, int mode, off_t offset, off_t length, struct fuse_file_info *fi);

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cfuseo_opendir(const char *path, struct fuse_file_info *fi);

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cfuseo_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cfuseo_releasedir(const char *path, struct fuse_file_info *fi);

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cfuseo_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi);

#endif/*(SWITCH_ON == FUSE_SWITCH)*/

#endif /*_CFUSEO_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
