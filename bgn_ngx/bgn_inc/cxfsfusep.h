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

#ifndef _CXFSFUSEP_H
#define _CXFSFUSEP_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "cstring.h"
#include "clist.h"
#include "carray.h"
#include "cvector.h"

#include "cxfs.h"


#define CXFS_FUSEP_UID_ROOT             0x0000
#define CXFS_FUSEP_GID_ROOT             0x0000

#define CXFS_FUSEP_UID_NOBODY           0xFFFE
#define CXFS_FUSEP_GID_NOBODY           0xFFFE

#define CXFS_FUSEP_UID_ERR              0xFFFF
#define CXFS_FUSEP_GID_ERR              0xFFFF

#define CXFS_FUSEP_UID_MASK             0xFFFF
#define CXFS_FUSEP_GID_MASK             0xFFFF

#define CXFS_FUSEP_EAGAIN              ((int) 1)
#define CXFS_FUSEP_EEXIST              ((int) 2) /*delete des*/
#define CXFS_FUSEP_ECGID               ((int) 3) /*clear S_ISGID*/
#define CXFS_FUSEP_ENOTIME             ((int) 4) /*not update time*/
#define CXFS_FUSEP_EUGID               ((int) 5) /*update gid only*/

int cxfs_fusep_mknod(CXFSNP_MGR *cxfsnp_mgr, const uint64_t parent_ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_mkdir(CXFSNP_MGR *cxfsnp_mgr, const uint64_t parent_ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_unlink(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_rmdir(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_symlink(CXFSNP_MGR *cxfsnp_mgr, const uint64_t src_ino, const uint64_t des_parent_ino, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_rename(CXFSNP_MGR *cxfsnp_mgr, const uint64_t src_ino, const uint64_t des_ino, const uint64_t des_parent_ino, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_link(CXFSNP_MGR *cxfsnp_mgr, const uint64_t src_ino, const uint64_t des_parent_ino, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_chmod(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_chown(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const UINT32 des_uid, const uint32_t des_gid, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_truncate(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_open(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t flags, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_create(CXFSNP_MGR *cxfsnp_mgr, const uint64_t parent_ino, const uint16_t mode, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_access(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint16_t mask);

int cxfs_fusep_ftruncate(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const uint32_t op_uid, const uint32_t op_gid);

int cxfs_fusep_utimens(CXFSNP_MGR *cxfsnp_mgr, const uint64_t ino, const struct timespec *tv0, const struct timespec *tv1, const uint32_t op_uid, const uint32_t op_gid);

#endif /*_CXFSFUSEP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


