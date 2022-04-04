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

#include "type.h"
#include "mm.h"
#include "log.h"

#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#define CFUSES_ARG_TYPE_CHAR            ((uint32_t) 1)
#define CFUSES_ARG_TYPE_BYTE            ((uint32_t) 2)
#define CFUSES_ARG_TYPE_MODE            ((uint32_t) 3)
#define CFUSES_ARG_TYPE_DEV             ((uint32_t) 4)
#define CFUSES_ARG_TYPE_UID             ((uint32_t) 5)
#define CFUSES_ARG_TYPE_GID             ((uint32_t) 6)
#define CFUSES_ARG_TYPE_OFFT            ((uint32_t) 7)
#define CFUSES_ARG_TYPE_SIZE            ((uint32_t) 8)
#define CFUSES_ARG_TYPE_INT             ((uint32_t) 9)
#define CFUSES_ARG_TYPE_LONG            ((uint32_t)10)
#define CFUSES_ARG_TYPE_UTIME           ((uint32_t)11)
#define CFUSES_ARG_TYPE_STATVFS         ((uint32_t)12)
#define CFUSES_ARG_TYPE_STAT            ((uint32_t)13)
#define CFUSES_ARG_TYPE_TS              ((uint32_t)14)
#define CFUSES_ARG_TYPE_FUSE_DH         ((uint32_t)15)

#define CFUSE_ARG_FLAG_ERR              ((uint32_t)0xFF00)
#define CFUSE_ARG_FLAG_IS_MOUNT         ((uint32_t)0x0001)
#define CFUSE_ARG_FLAG_IS_ALLOC         ((uint32_t)0x0002)

typedef struct
{
    uint32_t                        type;
    uint32_t                        flag;  /*mount(true) or not(false)*/
    UINT32                          vlen;
    union
    {
        char                       *v_char;
        char                       *v_byte;
        mode_t                      v_mode;
        dev_t                       v_dev;
        uid_t                       v_uid;
        gid_t                       v_gid;
        off_t                       v_offt;
        size_t                      v_size;
        int                         v_int;
        long int                    v_long;
        struct utimbuf             *v_utime;
        struct statvfs             *v_statvfs;
        struct stat                *v_stat;
        struct timespec             v_ts[2];
        void                       *v_fuse_dh;
    }u;
}CFUSES_ARG; /*len = 32*/

#define CFUSES_ARG_TYPE(cfuses_arg)             ((cfuses_arg)->type)
#define CFUSES_ARG_FLAG(cfuses_arg)             ((cfuses_arg)->flag)
#define CFUSES_ARG_VLEN(cfuses_arg)             ((cfuses_arg)->vlen)
#define CFUSES_ARG_V_CHAR(cfuses_arg)           ((cfuses_arg)->u.v_char)
#define CFUSES_ARG_V_BYTE(cfuses_arg)           ((cfuses_arg)->u.v_byte)
#define CFUSES_ARG_V_MODE(cfuses_arg)           ((cfuses_arg)->u.v_mode)
#define CFUSES_ARG_V_DEV(cfuses_arg)            ((cfuses_arg)->u.v_dev)
#define CFUSES_ARG_V_UID(cfuses_arg)            ((cfuses_arg)->u.v_uid)
#define CFUSES_ARG_V_GID(cfuses_arg)            ((cfuses_arg)->u.v_gid)
#define CFUSES_ARG_V_OFFT(cfuses_arg)           ((cfuses_arg)->u.v_offt)
#define CFUSES_ARG_V_SIZE(cfuses_arg)           ((cfuses_arg)->u.v_size)
#define CFUSES_ARG_V_INT(cfuses_arg)            ((cfuses_arg)->u.v_int)
#define CFUSES_ARG_V_LONG(cfuses_arg)           ((cfuses_arg)->u.v_long)
#define CFUSES_ARG_V_UTIME(cfuses_arg)          ((cfuses_arg)->u.v_utime)
#define CFUSES_ARG_V_STATVFS(cfuses_arg)        ((cfuses_arg)->u.v_statvfs)
#define CFUSES_ARG_V_STAT(cfuses_arg)           ((cfuses_arg)->u.v_stat)
#define CFUSES_ARG_V_TS_0(cfuses_arg)           (&((cfuses_arg)->u.v_ts[0]))
#define CFUSES_ARG_V_TS_1(cfuses_arg)           (&((cfuses_arg)->u.v_ts[1]))
#define CFUSES_ARG_V_TS_BOTH(cfuses_arg)        ((cfuses_arg)->u.v_ts)
#define CFUSES_ARG_V_FUSE_DH(cfuses_arg)        ((cfuses_arg)->u.v_fuse_dh)

typedef struct
{
    /* used counter >= 0 */
    UINT32                      usedcounter;

    char                       *mount_path;

}CFUSES_MD;

#define CFUSES_MD_MOUNT_PATH(cfuses_md)         ((cfuses_md)->mount_path)

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
UINT32 cfuses_start(const CSTRING *mount_path);

/**
*
* end CFUSES module
*
**/
void cfuses_end(const UINT32 cfuses_md_id);

CFUSES_ARG *cfuses_arg_new();

EC_BOOL cfuses_arg_init(CFUSES_ARG *cfuses_arg);

EC_BOOL cfuses_arg_clean(CFUSES_ARG *cfuses_arg);

EC_BOOL cfuses_arg_free(CFUSES_ARG *cfuses_arg);

EC_BOOL cfuses_arg_set(CFUSES_ARG *cfuses_arg, const UINT32 type, const void *data, const UINT32 data_len);

EC_BOOL cfuses_arg_mount(CFUSES_ARG *cfuses_arg, const UINT32 type, const void *data, const UINT32 data_len);

EC_BOOL cfuses_getattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *stat_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_readlink(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *buf_arg, const CFUSES_ARG *bufsize_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_mknod(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mode_arg, const CFUSES_ARG *dev_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_mkdir(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mode_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_unlink(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_rmdir(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_symlink(const UINT32 cfuses_md_id, const CFUSES_ARG *from_path_arg, const CFUSES_ARG *to_path_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_rename(const UINT32 cfuses_md_id, const CFUSES_ARG *from_path_arg, const CFUSES_ARG *to_path_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_link(const UINT32 cfuses_md_id, const CFUSES_ARG *from_path_arg, const CFUSES_ARG *to_path_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_chmod(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mod_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_chown(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *owner_arg, const CFUSES_ARG *group_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_truncate(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *length_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_utime(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *times_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_open(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *flags_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_read(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *buf_arg, const CFUSES_ARG *size_arg, const CFUSES_ARG *offset_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_write(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *buf_arg, const CFUSES_ARG *size_arg, const CFUSES_ARG *offset_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_statfs(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *statfs_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_flush(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_release(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *flag_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_fsync(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *datasync_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_setxattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *name_arg, const CFUSES_ARG *value_arg, const CFUSES_ARG *size_arg, const CFUSES_ARG *flags_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_getxattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *name_arg, CFUSES_ARG *value_arg, const CFUSES_ARG *size_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_listxattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *list_arg, const CFUSES_ARG *size_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_removexattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *name_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_access(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mask_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_ftruncate(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *offset_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_utimens(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *ts_arg, CFUSES_ARG *ret_arg);

EC_BOOL cfuses_fallocate(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mode_arg, const CFUSES_ARG *offset_arg, const CFUSES_ARG *length_arg, CFUSES_ARG *ret_arg);

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
EC_BOOL cfuses_readdir(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *buf_arg/*IO*//*type: struct fuse_dh*/, const CFUSES_ARG *filler_arg/*for test only*/, const CFUSES_ARG *offset_arg, const CFUSES_ARG *flags_arg, CFUSES_ARG *ret_arg);

#endif /*_CFUSES_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
