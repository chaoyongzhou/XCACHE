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

#ifndef _CFUSES_H
#define _CFUSES_H

#if (SWITCH_ON == FUSE_SWITCH)

#include "type.h"
#include "mm.h"
#include "log.h"

#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct
{
    /* used counter >= 0 */
    UINT32                      usedcounter;
    CSTRING                    *mount_point;

}CFUSES_MD;

#define CFUSES_MD_MOUNT_POINT(cfuses_md)        ((cfuses_md)->mount_point)
#define CFUSES_MD_MOUNT_POINT_STR(cfuses_md)    (cstring_get_str(CFUSES_MD_MOUNT_POINT(cfuses_md)))

/**
*   for test only
*
*   to query the status of CFUSES Module
*
**/
void cfuses_print_module_status(const UINT32 cfuses_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CFUSES module
*
*
**/
UINT32 cfuses_free_module_static_mem(const UINT32 cfuses_md_id);

/**
*
* start CFUSES module
*
**/
UINT32 cfuses_start(const CSTRING *mount_point);

/**
*
* end CFUSES module
*
**/
void cfuses_end(const UINT32 cfuses_md_id);


EC_BOOL cfuses_getattr(const UINT32 cfuses_md_id, const CSTRING *path, struct stat *stat, int *res);

EC_BOOL cfuses_readlink(const UINT32 cfuses_md_id, const CSTRING *path, CSTRING *buf, const UINT32 bufsize, int *res);

EC_BOOL cfuses_mknod(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, const UINT32 dev, int *res);

EC_BOOL cfuses_mkdir(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, int *res);

EC_BOOL cfuses_unlink(const UINT32 cfuses_md_id, const CSTRING *path, int *res);

EC_BOOL cfuses_rmdir(const UINT32 cfuses_md_id, const CSTRING *path, int *res);

EC_BOOL cfuses_symlink(const UINT32 cfuses_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res);

EC_BOOL cfuses_rename(const UINT32 cfuses_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res);

EC_BOOL cfuses_link(const UINT32 cfuses_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res);

EC_BOOL cfuses_chmod(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, int *res);

EC_BOOL cfuses_chown(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 owner, const UINT32 group, int *res);

EC_BOOL cfuses_truncate(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 length, int *res);

EC_BOOL cfuses_utime(const UINT32 cfuses_md_id, const CSTRING *path, const struct utimbuf *times, int *res);

EC_BOOL cfuses_open(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 flags, int *res);

EC_BOOL cfuses_read(const UINT32 cfuses_md_id, const CSTRING *path, CBYTES *buf, const UINT32 size, const UINT32 offset, int *res);

EC_BOOL cfuses_write(const UINT32 cfuses_md_id, const CSTRING *path, const CBYTES *buf, const UINT32 offset, int *res);

EC_BOOL cfuses_statfs(const UINT32 cfuses_md_id, const CSTRING *path, struct statvfs *statfs, int *res);

EC_BOOL cfuses_flush(const UINT32 cfuses_md_id, const CSTRING *path, int *res);

EC_BOOL cfuses_release(const UINT32 cfuses_md_id, const CSTRING *path, int *res);

EC_BOOL cfuses_fsync(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 datasync, int *res);

EC_BOOL cfuses_setxattr(const UINT32 cfuses_md_id, const CSTRING *path, const CSTRING *name, const CBYTES *value, const UINT32 flags, int *res);

EC_BOOL cfuses_getxattr(const UINT32 cfuses_md_id, const CSTRING *path, const CSTRING *name, CBYTES *value, const UINT32 size, int *res);

EC_BOOL cfuses_listxattr(const UINT32 cfuses_md_id, const CSTRING *path, CBYTES *value_list, const UINT32 size, int *res);

EC_BOOL cfuses_removexattr(const UINT32 cfuses_md_id, const CSTRING *path, const CSTRING *name, int *res);

EC_BOOL cfuses_access(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mask, int *res);

EC_BOOL cfuses_ftruncate(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 length, int *res);

EC_BOOL cfuses_utimens(const UINT32 cfuses_md_id, const CSTRING *path, const struct timespec *tv0, const struct timespec *tv1, int *res);

EC_BOOL cfuses_fallocate(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, const UINT32 offset, const UINT32 length, int *res);

EC_BOOL cfuses_readdir(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 offset, const UINT32 flags, CLIST *dirnode_list, int *res);

#endif/*(SWITCH_ON == FUSE_SWITCH)*/

#endif /*_CFUSES_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
