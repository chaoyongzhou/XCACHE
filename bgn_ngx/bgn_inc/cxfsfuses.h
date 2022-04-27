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

#ifndef _CXFSFUSES_H
#define _CXFSFUSES_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "carray.h"
#include "cvector.h"

EC_BOOL cxfs_fuses_getattr(const UINT32 cxfs_md_id, const CSTRING *file_path, struct stat *stat, int *res);

EC_BOOL cxfs_fuses_readlink(const UINT32 cxfs_md_id, const CSTRING *path, CSTRING *buf, const UINT32 bufsize, int *res);

EC_BOOL cxfs_fuses_mknod(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 dev, int *res);

EC_BOOL cxfs_fuses_mkdir(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, int *res);

EC_BOOL cxfs_fuses_unlink(const UINT32 cxfs_md_id, const CSTRING *path, int *res);

EC_BOOL cxfs_fuses_rmdir(const UINT32 cxfs_md_id, const CSTRING *path, int *res);

EC_BOOL cxfs_fuses_symlink(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res);

EC_BOOL cxfs_fuses_rename(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res);

EC_BOOL cxfs_fuses_link(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res);

EC_BOOL cxfs_fuses_chmod(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, int *res);

EC_BOOL cxfs_fuses_chown(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 owner, const UINT32 group, int *res);

EC_BOOL cxfs_fuses_truncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, int *res);

EC_BOOL cxfs_fuses_utime(const UINT32 cxfs_md_id, const CSTRING *path, const struct utimbuf *times, int *res);

EC_BOOL cxfs_fuses_open(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 flags, int *res);

EC_BOOL cxfs_fuses_read(const UINT32 cxfs_md_id, const CSTRING *path, CBYTES *buf, const UINT32 size, const UINT32 offset, int *res);

EC_BOOL cxfs_fuses_write(const UINT32 cxfs_md_id, const CSTRING *path, const CBYTES *buf, const UINT32 offset, int *res);

EC_BOOL cxfs_fuses_statfs(const UINT32 cxfs_md_id, const CSTRING *path, struct statvfs *statfs, int *res);

EC_BOOL cxfs_fuses_flush(const UINT32 cxfs_md_id, const CSTRING *path, int *res);

EC_BOOL cxfs_fuses_release(const UINT32 cxfs_md_id, const CSTRING *path, int *res);

EC_BOOL cxfs_fuses_fsync(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 datasync, int *res);

EC_BOOL cxfs_fuses_setxattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, const CBYTES *value, const UINT32 flags, int *res);

EC_BOOL cxfs_fuses_getxattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, CBYTES *value, const UINT32 size, int *res);

EC_BOOL cxfs_fuses_listxattr(const UINT32 cxfs_md_id, const CSTRING *path, CBYTES *value_list, const UINT32 size, int *res);

EC_BOOL cxfs_fuses_removexattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, int *res);

EC_BOOL cxfs_fuses_access(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mask, int *res);

EC_BOOL cxfs_fuses_ftruncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, int *res);

EC_BOOL cxfs_fuses_utimens(const UINT32 cxfs_md_id, const CSTRING *path, const struct timespec *tv0, const struct timespec *tv1, int *res);

EC_BOOL cxfs_fuses_fallocate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 offset, const UINT32 length, int *res);

EC_BOOL cxfs_fuses_readdir(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 offset, const UINT32 flags, CLIST *dirnode_list, int *res);

#endif /*_CXFSFUSES_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


