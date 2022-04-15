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

#ifndef _CFUSEC_H
#define _CFUSEC_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fuse.h>

struct fuse_operations *cfusec_get_ops();

/**
*
* start CFUSEC module
*
**/
EC_BOOL cfusec_start(struct fuse_args *args, const UINT32 cfuses_tcid, const UINT32 cfuses_rank, const UINT32 cfuses_modi);

/**
*
* end CFUSEC module
*
**/
void cfusec_end();

MOD_NODE *cfusec_get_remote_mod_node();

/*int (*getattr) (const char *, struct stat *);*/
int cfusec_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi);

/*int (*readlink) (const char *, char *, size_t);*/
int cfusec_readlink(const char *path, char *buf, size_t size);

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cfusec_mknod(const char *path, mode_t mode, dev_t dev);

/*int (*mkdir) (const char *, mode_t);*/
int cfusec_mkdir(const char *path, mode_t mode);

/*int (*unlink) (const char *);*/
int cfusec_unlink(const char *path);

/*int (*rmdir) (const char *);*/
int cfusec_rmdir(const char *path);

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cfusec_symlink(const char *src_path, const char *des_path);

/*int (*rename) (const char *, const char *);*/
int cfusec_rename(const char *src_path, const char *des_path, unsigned int flags);

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cfusec_link(const char *src_path, const char *des_path);

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t);*/
int cfusec_chmod(const char *path, mode_t mode, struct fuse_file_info *fi);

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cfusec_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi);

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cfusec_truncate(const char *path, off_t length, struct fuse_file_info *fi);

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cfusec_utime(const char *path, /*const*/struct utimbuf *times);

/*int (*open) (const char *, struct fuse_file_info *);*/
int cfusec_open(const char *path, struct fuse_file_info *);

/*int (*read) (const char *, char *, size_t, off_t);*/
int cfusec_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

/*int (*write) (const char *, const char *, size_t, off_t);*/
int cfusec_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);

/*int (*statfs) (const char *, struct statvfs *);*/
int cfusec_statfs(const char *path, struct statvfs *statvfs);

/*int (*flush) (const char *);*/
int cfusec_flush(const char *path, struct fuse_file_info *fi);

/*int (*release) (const char *, int flags);*/
int cfusec_release(const char *path, struct fuse_file_info *fi);

/*int (*fsync) (const char *, int);*/
int cfusec_fsync(const char * path, int sync, struct fuse_file_info *fi);

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cfusec_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cfusec_getxattr(const char *path, const char *name, char *value, size_t size);

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cfusec_listxattr(const char *path, char *list, size_t size);

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cfusec_removexattr(const char *path, const char *name);

/*int (*access) (const char *, int);*/
int cfusec_access(const char *path, int mask);


/*int (*ftruncate) (const char *, off_t);*/
int cfusec_ftruncate(const char *path, off_t offset);


/*int (*utimens) (const char *, const struct timespec tv[2]);*/
int cfusec_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi);

/* int (*fallocate) (const char *, int, off_t, off_t); */
int cfusec_fallocate(const char * path, int mode, off_t offset, off_t length, struct fuse_file_info *fi);

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cfusec_opendir(const char *path, struct fuse_file_info *fi);

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cfusec_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cfusec_releasedir(const char *path, struct fuse_file_info *fi);

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cfusec_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi);

#endif /*_CFUSEC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
