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

#ifndef _CXFS_FUSEC_H
#define _CXFS_FUSEC_H

#if (SWITCH_ON == CXFSFUSE_SWITCH)

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cthread.h"

#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fuse.h>

typedef struct
{
    MOD_NODE        cxfsfuses_mod_node;
    CTHREAD_ID      cfuseo_thread_id;
}CXFS_FUSEC_MD;

#define CXFS_FUSEC_MD_CFUSES_MOD_NODE(cxfs_fusec_md)        (&((cxfs_fusec_md)->cxfsfuses_mod_node))
#define CXFS_FUSEC_MD_CFUSEO_THREAD_ID(cxfs_fusec_md)       ((cxfs_fusec_md)->cfuseo_thread_id)

/**
*
* start CXFS_FUSEC module
*
**/
CXFS_FUSEC_MD *cxfs_fusec_start(struct fuse_args *args, const UINT32 cxfsfuses_tcid, const UINT32 cxfsfuses_rank, const UINT32 cxfsfuses_modi);

/**
*
* end CXFS_FUSEC module
*
**/
void cxfs_fusec_end(void *none);

MOD_NODE *cxfs_fusec_get_remote_mod_node();

/*int (*getattr) (const char *, struct stat *);*/
int cxfs_fusec_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi);

/*int (*readlink) (const char *, char *, size_t);*/
int cxfs_fusec_readlink(const char *path, char *buf, UINT32 size);

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cxfs_fusec_mknod(const char *path, UINT32 mode, UINT32 dev);

/*int (*mkdir) (const char *, mode_t);*/
int cxfs_fusec_mkdir(const char *path, UINT32 mode);

/*int (*unlink) (const char *);*/
int cxfs_fusec_unlink(const char *path);

/*int (*rmdir) (const char *);*/
int cxfs_fusec_rmdir(const char *path);

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cxfs_fusec_symlink(const char *src_path, const char *des_path);

/*int (*rename) (const char *, const char *);*/
int cxfs_fusec_rename(const char *src_path, const char *des_path, UINT32 flags);

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cxfs_fusec_link(const char *src_path, const char *des_path);

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t);*/
int cxfs_fusec_chmod(const char *path, UINT32 mode, struct fuse_file_info *fi);

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cxfs_fusec_chown(const char *path, UINT32 owner, UINT32 group, struct fuse_file_info *fi);

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cxfs_fusec_truncate(const char *path, UINT32 length, struct fuse_file_info *fi);

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cxfs_fusec_utime(const char *path, /*const*/struct utimbuf *times);

/*int (*open) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_open(const char *path, struct fuse_file_info *);

/*int (*read) (const char *, char *, size_t, off_t);*/
int cxfs_fusec_read(const char *path, char *buf, UINT32 size, UINT32 offset, struct fuse_file_info *fi);

/*int (*write) (const char *, const char *, size_t, off_t);*/
int cxfs_fusec_write(const char *path, const char *buf, UINT32 size, UINT32 offset, struct fuse_file_info *fi);

/*int (*statfs) (const char *, struct statvfs *);*/
int cxfs_fusec_statfs(const char *path, struct statvfs *statvfs);

/*int (*flush) (const char *);*/
int cxfs_fusec_flush(const char *path, struct fuse_file_info *fi);

/*int (*release) (const char *, int flags);*/
int cxfs_fusec_release(const char *path, struct fuse_file_info *fi);

/*int (*fsync) (const char *, int);*/
int cxfs_fusec_fsync(const char * path, UINT32 sync, struct fuse_file_info *fi);

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cxfs_fusec_setxattr(const char *path, const char *name, const char *value, UINT32 size, UINT32 flags);

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cxfs_fusec_getxattr(const char *path, const char *name, char *value, UINT32 size);

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cxfs_fusec_listxattr(const char *path, char *list, UINT32 size);

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cxfs_fusec_removexattr(const char *path, const char *name);

/*int (*access) (const char *, int);*/
int cxfs_fusec_access(const char *path, UINT32 mask);


/*int (*ftruncate) (const char *, off_t);*/
int cxfs_fusec_ftruncate(const char *path, UINT32 length);


/*int (*utimens) (const char *, const struct timespec tv[2]);*/
int cxfs_fusec_utimens(const char *path, const struct timespec *ts0, const struct timespec *ts1, struct fuse_file_info *fi);

/* int (*fallocate) (const char *, int, off_t, off_t); */
int cxfs_fusec_fallocate(const char * path, UINT32 mode, UINT32 offset, UINT32 length, struct fuse_file_info *fi);

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_opendir(const char *path, struct fuse_file_info *fi);

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cxfs_fusec_readdir(const char *path, void *buf, UINT32 filler, UINT32 offset, struct fuse_file_info *fi, UINT32 eflags);

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cxfs_fusec_releasedir(const char *path, struct fuse_file_info *fi);

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cxfs_fusec_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi);

#endif/*(SWITCH_ON == CXFSFUSE_SWITCH)*/

#endif /*_CXFS_FUSEC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
