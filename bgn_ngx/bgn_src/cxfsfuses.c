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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>

#include <sys/stat.h>

#include <fuse.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cbc.h"
#include "ctimer.h"
#include "cbtimer.h"
#include "cmisc.h"

#include "real.h"

#include "task.h"
#include "coroutine.h"

#include "cmpie.h"

#include "crb.h"

#include "cxfs.h"

#include "findex.inc"


#define CXFS_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFS))

#define CXFS_MD_GET(cxfs_md_id)     ((CXFS_MD *)cbc_md_get(MD_CXFS, (cxfs_md_id)))

#define CXFS_MD_ID_CHECK_INVALID(cxfs_md_id)  \
    ((CMPI_ANY_MODI != (cxfs_md_id)) && ((NULL_PTR == CXFS_MD_GET(cxfs_md_id)) || (0 == (CXFS_MD_GET(cxfs_md_id)->usedcounter))))

#define CXFS_FUSES_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")

#define CXFS_FUSES_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")

EC_BOOL cxfs_fuses_getattr(const UINT32 cxfs_md_id, const CSTRING *file_path, struct stat *stat, int *res)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_ITEM  *cxfsnp_item;
    CXFSNP_ATTR  *cxfsnp_attr;
    uint64_t      ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_getattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_getattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getattr: npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_getattr: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_getattr: wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_READ_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), file_path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getattr: cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(file_path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_getattr: %s => ino %lu\n",
                                         (char *)cstring_get_str(file_path), ino);

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getattr: %s => ino %lu => no item\n",
                                             (char *)cstring_get_str(file_path), ino);

        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    if(NULL_PTR != stat)
    {
        stat->st_ino        = ino;

        stat->st_uid        = CXFSNP_ATTR_UID(cxfsnp_attr);
        stat->st_gid        = CXFSNP_ATTR_GID(cxfsnp_attr);
        stat->st_rdev       = CXFSNP_ATTR_RDEV(cxfsnp_attr);

        stat->st_atime      = CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr);
        stat->st_mtime      = CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr);
        stat->st_ctime      = CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr);
        stat->st_nlink      = CXFSNP_ATTR_NLINK(cxfsnp_attr);

        stat->st_dev        = 0;/*xxx*/

        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            CXFSNP_FNODE       *cxfsnp_fnode;

            cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);

            stat->st_mode       = /*CXFSNP_ATTR_MODE(cxfsnp_attr)*/S_IFREG;
            stat->st_size       = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
            stat->st_blksize    = 4096;
            stat->st_blocks     = (CXFSNP_FNODE_FILESZ(cxfsnp_fnode) + 512 - 1) / 512;
        }
        else
        {
            CXFSNP_DNODE        *cxfsnp_dnode;

            cxfsnp_dnode = CXFSNP_ITEM_DNODE(cxfsnp_item);

            stat->st_mode       = /*CXFSNP_ATTR_MODE(cxfsnp_attr)*/S_IFDIR;
            stat->st_size       = 4096; /*xxx*/
            stat->st_blksize    = 4096; /*xxx*/
            stat->st_blocks     = 8; /*xxx*/
            stat->st_nlink      = CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode);
        }
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_readlink(const UINT32 cxfs_md_id, const CSTRING *path, CSTRING *buf, const UINT32 bufsize, int *res)
{
    (void)cxfs_md_id;
    (void)path;
    (void)buf;
    (void)bufsize;
    (void)res;

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_readlink:TODO");
    return (EC_FALSE);
}

EC_BOOL cxfs_fuses_mknod(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 dev, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_mknod: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_mknod");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_mknod: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfsnp_mgr_mkdir(CXFS_MD_NPP(cxfs_md), path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "mkdir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mknod: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);
    CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
    CXFSNP_ATTR_RDEV(cxfsnp_attr)       = (uint32_t)dev;
    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mknod: %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_mkdir(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_mkdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_mkdir");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_mkdir: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfsnp_mgr_mkdir(CXFS_MD_NPP(cxfs_md), path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                             "mkdir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_mkdir: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);
    CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
    CXFSNP_ATTR_RDEV(cxfsnp_attr)       = 0; /*xxx*/
    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_mkdir: "
                                         "mkdir %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_unlink(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_unlink: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_unlink");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_unlink: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfs_delete_file(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_unlink: "
                                             "delete file '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_unlink: "
                                         "delete file %s => done\n",
                                         (char *)cstring_get_str(path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_rmdir(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_rmdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_rmdir");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_rmdir: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rmdir: "
                                             "delete dir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rmdir: "
                                         "delete dir %s => done\n",
                                         (char *)cstring_get_str(path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_symlink(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_symlink: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_symlink");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_symlink: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfs_link(cxfs_md_id, from_path, to_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_symlink: "
                                             "link '%s' to '%s' failed\n",
                                             (char *)cstring_get_str(from_path),
                                             (char *)cstring_get_str(to_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_symlink: "
                                         "link '%s' to '%s' done\n",
                                         (char *)cstring_get_str(from_path),
                                         (char *)cstring_get_str(to_path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_rename(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_rename: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_rename");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_rename: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfs_rename(cxfs_md_id, from_path, to_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_rename: "
                                             "rename '%s' to '%s' failed\n",
                                             (char *)cstring_get_str(from_path),
                                             (char *)cstring_get_str(to_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_rename: "
                                         "rename '%s' to '%s' done\n",
                                         (char *)cstring_get_str(from_path),
                                         (char *)cstring_get_str(to_path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_link(const UINT32 cxfs_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_link: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_link");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_link: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfs_link(cxfs_md_id, from_path, to_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_link: "
                                             "link '%s' to '%s' failed\n",
                                             (char *)cstring_get_str(from_path),
                                             (char *)cstring_get_str(to_path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_link: "
                                         "link '%s' to '%s' done\n",
                                         (char *)cstring_get_str(from_path),
                                         (char *)cstring_get_str(to_path));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_chmod(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_chmod: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_chmod");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_chmod: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chmod: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chmod: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chmod: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chmod: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);
    CXFSNP_ATTR_MODE(cxfsnp_attr)       = (uint16_t)mode;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chmod: "
                                         "chmod %s => ino %lu, mod %u => done\n",
                                         (char *)cstring_get_str(path), ino, (uint16_t)mode);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_chown(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 owner, const UINT32 group, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_chown: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_chown");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_chown: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chown: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chown: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chown: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_chown: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_UID(cxfsnp_attr)        = (uint32_t)owner;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = (uint32_t)group;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_chown: "
                                         "chown %s => ino %lu, uid %u, gid %u => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         (uint32_t)owner, (uint32_t)group);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_truncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_truncate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_truncate");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_truncate: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfs_delete_file(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                             "delete %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_reserve(cxfs_md_id, path, length))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                             "reserve %s len %ld failed\n",
                                             (char *)cstring_get_str(path),
                                             length);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_truncate: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_truncate: "
                                         "reserve %s len %ld => ino %lu => done\n",
                                         (char *)cstring_get_str(path), length, ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_utime(const UINT32 cxfs_md_id, const CSTRING *path, const struct utimbuf *times, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_utime: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_utime");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_utime: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utime: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utime: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utime: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utime: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)times->actime;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)times->modtime;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utime: "
                                         "utime %s => ino %lu, atime_sec %lu, mtime_sec %lu => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr),
                                         CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_open(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 flags, int *res)
{
    CXFS_MD         *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_open: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_open");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_open: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    (void)flags;

    if(EC_TRUE == cxfsnp_mgr_find_file(CXFS_MD_NPP(cxfs_md), path))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_open: "
                                             "find file '%s'\n",
                                             (char *)cstring_get_str(path));
        (*res) = 0;
        return (EC_TRUE);
    }

    if(EC_TRUE == cxfsnp_mgr_find_dir(CXFS_MD_NPP(cxfs_md), path))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_open: "
                                             "find dir '%s'\n",
                                             (char *)cstring_get_str(path));
        (*res) = 0;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_open: "
                                         "no file or dir '%s'\n",
                                         (char *)cstring_get_str(path));
    (*res) = -ENOENT;
    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_read(const UINT32 cxfs_md_id, const CSTRING *path, CBYTES *buf, const UINT32 size, const UINT32 offset, int *res)
{
    CXFS_MD         *cxfs_md;
    UINT32           offset_t;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_read: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_read");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_read: "
                                             "npp was not read\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    offset_t = offset;

    if(EC_FALSE == cxfs_read_e(cxfs_md_id, path, &offset_t, size, buf))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                             "read file '%s' offset %ld size %ld failed\n",
                                             (char *)cstring_get_str(path), offset, size);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "error:cxfs_fuses_read: "
                                         "read file '%s' offset %ld size %ld done\n",
                                         (char *)cstring_get_str(path), offset, size);

    ASSERT((offset_t - offset) == CBYTES_LEN(buf));
    (*res) = (int)(offset_t - offset);

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_write(const UINT32 cxfs_md_id, const CSTRING *path, const CBYTES *buf, const UINT32 offset, int *res)
{
    CXFS_MD         *cxfs_md;
    UINT32           offset_t;
    UINT32           size;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_write: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_write");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_write: "
                                             "npp was not write\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    offset_t = offset;
    size     = CBYTES_LEN(buf);

    if(EC_FALSE == cxfs_write_e(cxfs_md_id, path, &offset_t, size, buf))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                             "write file '%s' offset %ld size %ld failed\n",
                                             (char *)cstring_get_str(path), offset, size);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "error:cxfs_fuses_write: "
                                         "write file '%s' offset %ld size %ld done\n",
                                         (char *)cstring_get_str(path), offset, size);

    (*res) = (int)(offset_t - offset);

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_statfs(const UINT32 cxfs_md_id, const CSTRING *path, struct statvfs *statfs, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_statfs: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_statfs");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_statfs: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_statfs: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_statfs: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_statfs: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_statfs: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        statfs->f_bsize     = 4096;                 /* Filesystem block size */
        statfs->f_frsize    = 4096;                 /* Fragment size */
        statfs->f_blocks    = 0x00FFFFFF;           /* Size of fs in f_frsize units */
        statfs->f_bfree     = 0x00FFFFFF;           /* Number of free blocks */
        statfs->f_bavail    = 0x00FFFFFF;           /* Number of free blocks for unprivileged users */
        statfs->f_files     = 0x00FFFFFF;           /* Number of inodes */
        statfs->f_ffree     = 0x0FFFFFFF;           /* Number of free inodes */
        statfs->f_favail    = 0x0FFFFFFF;           /* Number of free inodes for unprivileged users */
        statfs->f_fsid      = 0x0FEFEFEF;           /* Filesystem ID */
        statfs->f_flag      = 4096;                 /* Mount flags */
        statfs->f_namemax   = CXFSNP_KEY_MAX_SIZE;  /* Maximum filename length */

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_statfs: "
                                             "statfs %s => file ino %lu => done\n",
                                             (char *)cstring_get_str(path), ino);
        (*res) = 0;

        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        statfs->f_bsize     = 4096;                 /* Filesystem block size */
        statfs->f_frsize    = 4096;                 /* Fragment size */
        statfs->f_blocks    = 0x00FFFFFF;           /* Size of fs in f_frsize units */
        statfs->f_bfree     = 0x00FFFFFF;           /* Number of free blocks */
        statfs->f_bavail    = 0x00FFFFFF;           /* Number of free blocks for unprivileged users */
        statfs->f_files     = 0x00FFFFFF;           /* Number of inodes */
        statfs->f_ffree     = 0x0FFFFFFF;           /* Number of free inodes */
        statfs->f_favail    = 0x0FFFFFFF;           /* Number of free inodes for unprivileged users */
        statfs->f_fsid      = 0x0FEFEFEF;           /* Filesystem ID */
        statfs->f_flag      = 4096;                 /* Mount flags */
        statfs->f_namemax   = CXFSNP_KEY_MAX_SIZE;  /* Maximum filename length */

        dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_statfs: "
                                             "statfs %s => dir ino %lu => done\n",
                                             (char *)cstring_get_str(path), ino);

        (*res) = 0;

        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_statfs: "
                                         "statfs %s => ino %lu, dir flag %x => unsupported\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));

    (*res) = -ENOENT;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_flush(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_flush: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_flush");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_flush: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_flush: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_flush: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_flush: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_flush: "
                                         "flush %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_release(const UINT32 cxfs_md_id, const CSTRING *path, int *res)
{
    CXFS_MD         *cxfs_md;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_release: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_release");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_release: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_release: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_release: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_release: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_release: "
                                         "release %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_fsync(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 datasync, int *res)
{
    CXFS_MD         *cxfs_md;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_fsync: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_fsync");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_fsync: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fsync: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fsync: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fsync: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_fsync: "
                                         "fsync %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_setxattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, const CBYTES *value, const UINT32 flags, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_setxattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_setxattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_setxattr: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_setxattr: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_setxattr: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    (void)name;
    (void)value;
    (void)flags;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_setxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_setxattr: "
                                         "setxattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENOTSUP;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_getxattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, CBYTES *value, const UINT32 size, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_getxattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_getxattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getxattr: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_getxattr: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_getxattr: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    (void)name;
    (void)value;
    (void)size;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_getxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_getxattr: "
                                         "getxattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENODATA;
    cbytes_clean(value);

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_listxattr(const UINT32 cxfs_md_id, const CSTRING *path, CBYTES *value_list, const UINT32 size, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_listxattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_listxattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_listxattr: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_listxattr: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_listxattr: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    (void)value_list;
    (void)size;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_listxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_listxattr: "
                                         "listxattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENOTSUP;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_removexattr(const UINT32 cxfs_md_id, const CSTRING *path, const CSTRING *name, int *res)
{
    CXFS_MD        *cxfs_md;
    uint64_t        ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_removexattr: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_removexattr");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_removexattr: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_removexattr: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_removexattr: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    (void)name;

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_removexattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_removexattr: "
                                         "removexattr %s => ino %lu => not support\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = -ENOTSUP;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_access(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mask, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_access: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_access");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_access: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_access: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_access: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_access: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_access: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);
    if(((uint16_t)mask) == (CXFSNP_ATTR_MODE(cxfsnp_attr) & ((uint16_t)mask)))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_access: "
                                             "access %s => ino %lu, mode %o & mask %o = mask\n",
                                             (char *)cstring_get_str(path), ino,
                                             CXFSNP_ATTR_MODE(cxfsnp_attr),
                                             ((uint16_t)mask));

        (*res) = 0;

        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_access: "
                                         "access %s => ino %lu, mode %o & mask %o != mask\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_MODE(cxfsnp_attr),
                                         ((uint16_t)mask));

    (*res) = -EACCES;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_ftruncate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 length, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    CBYTES           content;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_ftruncate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_ftruncate");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_ftruncate: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_ftruncate: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_ftruncate: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        if(EC_FALSE == cxfs_reserve(cxfs_md_id, path, length))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_ftruncate: "
                                                 "file %s reserve %ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 length);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_setxattr: "
                                                 "cxfsnp mgr ino %s failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_setxattr: "
                                                 "path '%s' ino %lu fetch item failed\n",
                                                 (char *)cstring_get_str(path),
                                                 ino);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_ftruncate: "
                                             "ftruncate %s => ino %lu => done\n",
                                             (char *)cstring_get_str(path), ino);

        (*res) = 0;

        return (EC_TRUE);
    }

    cbytes_init(&content);

    if(EC_FALSE == cxfs_read(cxfs_md_id, path, &content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_ftruncate: "
                                             "read %s failed\n",
                                             (char *)cstring_get_str(path));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    if(CBYTES_LEN(&content) > length)
    {
        CBYTES_LEN(&content) = length;
    }
    else
    {
        if(EC_FALSE == cbytes_expand_to(&content, length))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_ftruncate: "
                                                 "file %s expand to %ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 length);

            cbytes_clean(&content);

            (*res) = -ENOMEM;
            return (EC_TRUE);
        }
    }

    if(EC_FALSE == cxfs_delete_file(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_ftruncate: "
                                             "delete %s failed\n",
                                             (char *)cstring_get_str(path));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfs_write(cxfs_md_id, path, &content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_ftruncate: "
                                             "write %s length %ld failed\n",
                                             (char *)cstring_get_str(path),
                                             CBYTES_LEN(&content));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    cbytes_clean(&content);

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_setxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_setxattr: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_ftruncate: "
                                         "ftruncate %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_utimens(const UINT32 cxfs_md_id, const CSTRING *path, const struct timespec *tv0, const struct timespec *tv1, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    uint64_t         ino;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_utimens: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_utimens");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_utimens: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_utimens: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)   = (uint64_t)tv0->tv_sec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)   = (uint64_t)tv1->tv_sec;

    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr)  = (uint64_t)tv0->tv_nsec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr)  = (uint64_t)tv1->tv_nsec;

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_utimens: "
                                         "utimens %s => ino %lu, atime %lu:%u, mtime %lu:%u => done\n",
                                         (char *)cstring_get_str(path), ino,
                                         CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr),
                                         CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr),
                                         CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr),
                                         CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr));

    (*res) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_fuses_fallocate(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 mode, const UINT32 offset, const UINT32 length, int *res)
{
    CXFS_MD         *cxfs_md;
    CXFSNP_ITEM     *cxfsnp_item;
    CXFSNP_ATTR     *cxfsnp_attr;
    CBYTES           content;
    uint64_t         ino;

    uint64_t         nsec;  /*seconds*/
    uint64_t         nanosec;/*nanosecond*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_fallocate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_fallocate");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_fallocate: "
                                             "npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

        if(EC_FALSE == cxfs_reserve(cxfs_md_id, path, length))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                                 "file %s reserve %ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 length);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_setxattr: "
                                                 "cxfsnp mgr ino %s failed\n",
                                                 (char *)cstring_get_str(path));
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
        if(NULL_PTR == cxfsnp_item)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_setxattr: "
                                                 "path '%s' ino %lu fetch item failed\n",
                                                 (char *)cstring_get_str(path),
                                                 ino);
            (*res) = -ENOENT;
            return (EC_TRUE);
        }

        cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

        CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;
        CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
        CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
        CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_fallocate: "
                                             "fallocate %s => ino %lu => done\n",
                                             (char *)cstring_get_str(path), ino);

        (*res) = 0;

        return (EC_TRUE);
    }

    (void)offset;
    cbytes_init(&content);

    if(EC_FALSE == cxfs_read(cxfs_md_id, path, &content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "read %s failed\n",
                                             (char *)cstring_get_str(path));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    if(CBYTES_LEN(&content) > length)
    {
        CBYTES_LEN(&content) = length;
    }
    else
    {
        if(EC_FALSE == cbytes_expand_to(&content, length))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                                 "file %s expand to %ld failed\n",
                                                 (char *)cstring_get_str(path),
                                                 length);

            cbytes_clean(&content);

            (*res) = -ENOMEM;
            return (EC_TRUE);
        }
    }

    if(EC_FALSE == cxfs_delete_file(cxfs_md_id, path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "delete %s failed\n",
                                             (char *)cstring_get_str(path));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    c_get_cur_time_nsec_and_nanosec(&nsec, &nanosec);

    if(EC_FALSE == cxfs_write(cxfs_md_id, path, &content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_fallocate: "
                                             "write %s length %ld failed\n",
                                             (char *)cstring_get_str(path),
                                             CBYTES_LEN(&content));

        cbytes_clean(&content);

        (*res) = -EIO;
        return (EC_TRUE);
    }

    cbytes_clean(&content);

    if(EC_FALSE == cxfsnp_mgr_ino(CXFS_MD_NPP(cxfs_md), path, &ino))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_setxattr: "
                                             "cxfsnp mgr ino %s failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_item = cxfsnp_mgr_fetch_item(CXFS_MD_NPP(cxfs_md), ino);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_setxattr: "
                                             "path '%s' ino %lu fetch item failed\n",
                                             (char *)cstring_get_str(path),
                                             ino);
        (*res) = -ENOENT;
        return (EC_TRUE);
    }

    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    CXFSNP_ATTR_UID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_GID(cxfsnp_attr)        = 0;
    CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr)  = (uint64_t)nsec;
    CXFSNP_ATTR_ATIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_MTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_CTIME_NSEC(cxfsnp_attr) = (uint32_t)nanosec;
    CXFSNP_ATTR_NLINK(cxfsnp_attr)      = 1;

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_fuses_fallocate: "
                                         "fallocate %s => ino %lu => done\n",
                                         (char *)cstring_get_str(path), ino);

    (*res) = 0;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_fuses_readdir_walker(CXFSNP_DIT_NODE *cxfsnp_dit_node, CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos)
{
    CXFSNP_KEY                 *cxfsnp_key;
    CXFSNP_ATTR                *cxfsnp_attr;
    struct dirnode             *dirnode;
    CLIST                      *dirnode_list;

    uint64_t                    ino;
    uint32_t                    cxfsnp_id;

    enum fuse_readdir_flags     flags_t;

    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_readdir_walker: item was not used\n");
        return (EC_FALSE);
    }

    if(0 == node_pos)/*root item*/
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_readdir_walker: skip root item\n");
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)
    && 1 == CXFSNP_DIT_NODE_MAX_DEPTH(cxfsnp_dit_node))
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_fuses_readdir_walker: skip entrance dir item\n");
        return (EC_TRUE);
    }

    cxfsnp_id    = CXFSNP_DIT_NODE_CUR_NP_ID(cxfsnp_dit_node);

    flags_t      = (enum fuse_readdir_flags)CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, 1);
    dirnode_list = (CLIST                 *)CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, 2);

    cxfsnp_key  = CXFSNP_ITEM_KEY(cxfsnp_item);
    cxfsnp_attr = CXFSNP_ITEM_ATTR(cxfsnp_item);

    ASSERT(0 != CXFSNP_KEY_LEN(cxfsnp_key));

    dirnode = c_dirnode_new();
    if(NULL_PTR == dirnode)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_readdir_walker: "
                                             "new dirnode failed\n");
        return (EC_FALSE);
    }

    dirnode->flags = 0; /*enum fuse_fill_dir_flags*/

    dirnode->name = c_str_n_dup((char *)CXFSNP_KEY_NAME(cxfsnp_key), (uint32_t)CXFSNP_KEY_LEN(cxfsnp_key));
    if(NULL_PTR == dirnode->name)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fuses_readdir_walker: "
                                             "dup '%.*s' failed\n",
                                             (uint32_t)CXFSNP_KEY_LEN(cxfsnp_key),
                                             (char   *)CXFSNP_KEY_NAME(cxfsnp_key));
        c_dirnode_free(dirnode);
        return (EC_FALSE);
    }

    ino = CXFSNP_ATTR_INO_MAKE(cxfsnp_id, node_pos);

    if(flags_t & FUSE_READDIR_PLUS)
    {
        dirnode->flags |= FUSE_FILL_DIR_PLUS;

        dirnode->stat.st_ino        = ino;
        dirnode->stat.st_mode       = CXFSNP_ATTR_MODE(cxfsnp_attr);
        dirnode->stat.st_uid        = CXFSNP_ATTR_UID(cxfsnp_attr);
        dirnode->stat.st_gid        = CXFSNP_ATTR_GID(cxfsnp_attr);
        dirnode->stat.st_rdev       = CXFSNP_ATTR_RDEV(cxfsnp_attr);

        dirnode->stat.st_atime      = CXFSNP_ATTR_ATIME_SEC(cxfsnp_attr);
        dirnode->stat.st_mtime      = CXFSNP_ATTR_MTIME_SEC(cxfsnp_attr);
        dirnode->stat.st_ctime      = CXFSNP_ATTR_CTIME_SEC(cxfsnp_attr);
        dirnode->stat.st_nlink      = CXFSNP_ATTR_NLINK(cxfsnp_attr);

        dirnode->stat.st_dev        = 0;/*xxx*/

        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            CXFSNP_FNODE       *cxfsnp_fnode;

            cxfsnp_fnode = CXFSNP_ITEM_FNODE(cxfsnp_item);

            dirnode->stat.st_size       = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
            dirnode->stat.st_blksize    = 512;
            dirnode->stat.st_blocks     = (CXFSNP_FNODE_FILESZ(cxfsnp_fnode) + 512 - 1) / 512;
        }
        else
        {
            dirnode->stat.st_size       = 0; /*xxx*/
            dirnode->stat.st_blksize    = 0; /*xxx*/
            dirnode->stat.st_blocks     = 0; /*xxx*/
        }
    }

	if(!(dirnode->flags & FUSE_FILL_DIR_PLUS))
	{
		dirnode->stat.st_ino  = ino;
		dirnode->stat.st_mode = CXFSNP_ATTR_MODE(cxfsnp_attr);
	}

	clist_push_back(dirnode_list, (void *)dirnode);

    return (EC_FALSE);
}

EC_BOOL cxfs_fuses_readdir(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 offset, const UINT32 flags, CLIST *dirnode_list, int *res)
{
    CXFS_MD   *cxfs_md;

    CXFSNP_DIT_NODE cxfsnp_dit_node;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_fuses_readdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    CXFS_FUSES_DEBUG_ENTER("cxfs_fuses_readdir");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    (void)offset;

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_fuses_readdir: npp was not open\n");
        (*res) = -EACCES;
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_readdir: "
                                             "xfs is in op-replay mode\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_readdir: wait syncing timeout\n");
        (*res) = -EBUSY;
        return (EC_TRUE);
    }

    clist_codec_set(dirnode_list, MM_DIRNODE);

    cxfsnp_dit_node_init(&cxfsnp_dit_node);

    CXFSNP_DIT_NODE_HANDLER(&cxfsnp_dit_node)   = __cxfs_fuses_readdir_walker;
    CXFSNP_DIT_NODE_CUR_NP_ID(&cxfsnp_dit_node) = CXFSNP_ERR_ID;
    CXFSNP_DIT_NODE_MAX_DEPTH(&cxfsnp_dit_node) = 1;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 0)    = (void *)cxfs_md_id;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 1)    = (void *)flags;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 2)    = (void *)dirnode_list;

    if(EC_FALSE == cxfsnp_mgr_walk(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR, &cxfsnp_dit_node))
    {
        cxfsnp_dit_node_clean(&cxfsnp_dit_node);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_fuses_readdir: "
                                             "readdir '%s' failed\n",
                                             (char *)cstring_get_str(path));
        (*res) = -EACCES;
        return (EC_FALSE);
    }

    cxfsnp_dit_node_clean(&cxfsnp_dit_node);

    dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] cxfs_fuses_readdir: "
                                         "readdir '%s' done\n",
                                         (char *)cstring_get_str(path));

    (*res) = 0;
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
