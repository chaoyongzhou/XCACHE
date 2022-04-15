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

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/xattr.h>
#include <x86_64-linux-gnu/sys/xattr.h>
#include <dirent.h>

#include <fuse.h>
#include <pthread.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmpie.h"
#include "task.h"
#include "creg.h"
#include "cmisc.h"
#include "list_base.h"

#include "cfused.h"

static EC_BOOL cfused_init_flag = EC_FALSE;

void cfused_start()
{
    if(EC_FALSE == cfused_init_flag)
    {
        creg_type_conv_vec_add(TASK_BRD_TYPE_CONV_VEC(task_brd_default_get()),
            /* type                   */e_dbg_int_ptr,
            /* type_sizeof            */sizeof(int *),
            /* pointer_flag           */EC_TRUE,
            /* var_mm_type            */MM_END,
            /* new_type_func          */(UINT32)c_i32_new,
            /* init_type_func         */(UINT32)c_i32_init,
            /* clean_type_func        */(UINT32)c_i32_clean,
            /* free_type_func         */(UINT32)c_i32_free,
            /* cmpi_encode_type_func  */(UINT32)cmpi_encode_i32,
            /* cmpi_decode_type_func  */(UINT32)cmpi_decode_i32,
            /* cmpi_encode_type_size  */(UINT32)cmpi_encode_i32_size
        );

        creg_type_conv_vec_add(TASK_BRD_TYPE_CONV_VEC(task_brd_default_get()),
            /* type                   */e_dbg_struct_stat_ptr,
            /* type_sizeof            */sizeof(struct stat *),
            /* pointer_flag           */EC_TRUE,
            /* var_mm_type            */MM_END,
            /* new_type_func          */(UINT32)c_stat_new,
            /* init_type_func         */(UINT32)c_stat_init,
            /* clean_type_func        */(UINT32)c_stat_clean,
            /* free_type_func         */(UINT32)c_stat_free,
            /* cmpi_encode_type_func  */(UINT32)cmpi_encode_stat,
            /* cmpi_decode_type_func  */(UINT32)cmpi_decode_stat,
            /* cmpi_encode_type_size  */(UINT32)cmpi_encode_stat_size
        );

        creg_type_conv_vec_add(TASK_BRD_TYPE_CONV_VEC(task_brd_default_get()),
            /* type                   */e_dbg_struct_statvfs_ptr,
            /* type_sizeof            */sizeof(struct statvfs *),
            /* pointer_flag           */EC_TRUE,
            /* var_mm_type            */MM_END,
            /* new_type_func          */(UINT32)c_statvfs_new,
            /* init_type_func         */(UINT32)c_statvfs_init,
            /* clean_type_func        */(UINT32)c_statvfs_clean,
            /* free_type_func         */(UINT32)c_statvfs_free,
            /* cmpi_encode_type_func  */(UINT32)cmpi_encode_statvfs,
            /* cmpi_decode_type_func  */(UINT32)cmpi_decode_statvfs,
            /* cmpi_encode_type_size  */(UINT32)cmpi_encode_statvfs_size
        );

        creg_type_conv_vec_add(TASK_BRD_TYPE_CONV_VEC(task_brd_default_get()),
            /* type                   */e_dbg_struct_timespec_ptr,
            /* type_sizeof            */sizeof(struct timespec *),
            /* pointer_flag           */EC_TRUE,
            /* var_mm_type            */MM_END,
            /* new_type_func          */(UINT32)c_timespec_new,
            /* init_type_func         */(UINT32)c_timespec_init,
            /* clean_type_func        */(UINT32)c_timespec_clean,
            /* free_type_func         */(UINT32)c_timespec_free,
            /* cmpi_encode_type_func  */(UINT32)cmpi_encode_timespec,
            /* cmpi_decode_type_func  */(UINT32)cmpi_decode_timespec,
            /* cmpi_encode_type_size  */(UINT32)cmpi_encode_timespec_size
        );

        creg_type_conv_vec_add(TASK_BRD_TYPE_CONV_VEC(task_brd_default_get()),
            /* type                   */e_dbg_struct_utimbuf_ptr,
            /* type_sizeof            */sizeof(struct utimbuf *),
            /* pointer_flag           */EC_TRUE,
            /* var_mm_type            */MM_END,
            /* new_type_func          */(UINT32)c_utimbuf_new,
            /* init_type_func         */(UINT32)c_utimbuf_init,
            /* clean_type_func        */(UINT32)c_utimbuf_clean,
            /* free_type_func         */(UINT32)c_utimbuf_free,
            /* cmpi_encode_type_func  */(UINT32)cmpi_encode_utimbuf,
            /* cmpi_decode_type_func  */(UINT32)cmpi_decode_utimbuf,
            /* cmpi_encode_type_size  */(UINT32)cmpi_encode_utimbuf_size
        );

        creg_type_conv_vec_add(TASK_BRD_TYPE_CONV_VEC(task_brd_default_get()),
            /* type                   */e_dbg_struct_dirnode_ptr,
            /* type_sizeof            */sizeof(struct dirnode *),
            /* pointer_flag           */EC_TRUE,
            /* var_mm_type            */MM_DIRNODE,
            /* new_type_func          */(UINT32)c_dirnode_new,
            /* init_type_func         */(UINT32)c_dirnode_init,
            /* clean_type_func        */(UINT32)c_dirnode_clean,
            /* free_type_func         */(UINT32)c_dirnode_free,
            /* cmpi_encode_type_func  */(UINT32)cmpi_encode_dirnode,
            /* cmpi_decode_type_func  */(UINT32)cmpi_decode_dirnode,
            /* cmpi_encode_type_size  */(UINT32)cmpi_encode_dirnode_size
        );

        cfused_init_flag = EC_TRUE;
    }
    return;
}

void cfused_end()
{
    /*do nothing*/
    return;
}


#if 1
int *c_i32_new()
{
    int *i32;

    i32 = safe_malloc(sizeof(int), LOC_CFUSED_0001);
    if(NULL_PTR == i32)
    {
        dbg_log(SEC_0034_CFUSED, 0)(LOGSTDOUT, "error:c_i32_new: no memory\n");
        return (NULL_PTR);
    }

    c_i32_init(i32);
    return (i32);
}

EC_BOOL c_i32_init(int *i32)
{
    if(NULL_PTR != i32)
    {
        (*i32) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL c_i32_clean(int *i32)
{
    if(NULL_PTR != i32)
    {
        (*i32) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL c_i32_free(int *i32)
{
    if(NULL_PTR != i32)
    {
        c_i32_clean(i32);
        safe_free(i32, LOC_CFUSED_0002);
    }
    return (EC_TRUE);
}


UINT32 cmpi_encode_i32(const UINT32 comm, const int *i32, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_encode_uint8_array(comm, (UINT8 *)i32, sizeof(int), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_i32_size(const UINT32 comm, const int *i32, UINT32 *size)
{
    cmpi_encode_uint8_array_size(comm, (UINT8 *)i32, sizeof(int), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_i32(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, int *i32)
{
    UINT32      len;
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, (UINT8 *)i32, &len);
    ASSERT(sizeof(int) == len);

    return ((UINT32)0);
}
#endif


#if 1
struct stat *c_stat_new()
{
    struct stat *stat;

    stat = safe_malloc(sizeof(struct stat), LOC_CFUSED_0003);
    if(NULL_PTR == stat)
    {
        dbg_log(SEC_0034_CFUSED, 0)(LOGSTDOUT, "error:c_stat_new: no memory\n");
        return (NULL_PTR);
    }

    c_stat_init(stat);
    return (stat);
}

EC_BOOL c_stat_init(struct stat *stat)
{
    if(NULL_PTR != stat)
    {
        BSET(stat, 0x00, sizeof(struct stat));
    }

    return (EC_TRUE);
}

EC_BOOL c_stat_clean(struct stat *stat)
{
    if(NULL_PTR != stat)
    {
        BSET(stat, 0x00, sizeof(struct stat));
    }

    return (EC_TRUE);
}

EC_BOOL c_stat_free(struct stat *stat)
{
    if(NULL_PTR != stat)
    {
        c_stat_clean(stat);
        safe_free(stat, LOC_CFUSED_0004);
    }
    return (EC_TRUE);
}


UINT32 cmpi_encode_stat(const UINT32 comm, const struct stat *stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_encode_uint8_array(comm, (UINT8 *)stat, sizeof(struct stat), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_stat_size(const UINT32 comm, const struct stat *stat, UINT32 *size)
{
    cmpi_encode_uint8_array_size(comm, (UINT8 *)stat, sizeof(struct stat), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct stat *stat)
{
    UINT32      len;
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, (UINT8 *)stat, &len);
    ASSERT(sizeof(struct stat) == len);

    return ((UINT32)0);
}
#endif


#if 1
struct statvfs *c_statvfs_new()
{
    struct statvfs *statvfs;

    statvfs = safe_malloc(sizeof(struct statvfs), LOC_CFUSED_0005);
    if(NULL_PTR == statvfs)
    {
        dbg_log(SEC_0034_CFUSED, 0)(LOGSTDOUT, "error:c_statvfs_new: no memory\n");
        return (NULL_PTR);
    }

    c_statvfs_init(statvfs);
    return (statvfs);
}

EC_BOOL c_statvfs_init(struct statvfs *statvfs)
{
    if(NULL_PTR != statvfs)
    {
        BSET(statvfs, 0x00, sizeof(struct statvfs));
    }

    return (EC_TRUE);
}

EC_BOOL c_statvfs_clean(struct statvfs *statvfs)
{
    if(NULL_PTR != statvfs)
    {
        BSET(statvfs, 0x00, sizeof(struct statvfs));
    }

    return (EC_TRUE);
}

EC_BOOL c_statvfs_free(struct statvfs *statvfs)
{
    if(NULL_PTR != statvfs)
    {
        c_statvfs_clean(statvfs);
        safe_free(statvfs, LOC_CFUSED_0006);
    }
    return (EC_TRUE);
}


UINT32 cmpi_encode_statvfs(const UINT32 comm, const struct statvfs *statvfs, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_encode_uint8_array(comm, (UINT8 *)statvfs, sizeof(struct statvfs), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_statvfs_size(const UINT32 comm, const struct statvfs *statvfs, UINT32 *size)
{
    cmpi_encode_uint8_array_size(comm, (UINT8 *)statvfs, sizeof(struct statvfs), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_statvfs(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct statvfs *statvfs)
{
    UINT32      len;
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, (UINT8 *)statvfs, &len);
    ASSERT(sizeof(struct statvfs) == len);

    return ((UINT32)0);
}
#endif

#if 1
struct timespec *c_timespec_new()
{
    struct timespec *timespec;

    timespec = safe_malloc(sizeof(struct timespec), LOC_CFUSED_0007);
    if(NULL_PTR == timespec)
    {
        dbg_log(SEC_0034_CFUSED, 0)(LOGSTDOUT, "error:c_timespec_new: no memory\n");
        return (NULL_PTR);
    }

    c_timespec_init(timespec);
    return (timespec);
}

EC_BOOL c_timespec_init(struct timespec *timespec)
{
    if(NULL_PTR != timespec)
    {
        BSET(timespec, 0x00, sizeof(struct timespec));
    }

    return (EC_TRUE);
}

EC_BOOL c_timespec_clean(struct timespec *timespec)
{
    if(NULL_PTR != timespec)
    {
        BSET(timespec, 0x00, sizeof(struct timespec));
    }

    return (EC_TRUE);
}

EC_BOOL c_timespec_free(struct timespec *timespec)
{
    if(NULL_PTR != timespec)
    {
        c_timespec_clean(timespec);
        safe_free(timespec, LOC_CFUSED_0008);
    }
    return (EC_TRUE);
}


UINT32 cmpi_encode_timespec(const UINT32 comm, const struct timespec *timespec, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_encode_uint8_array(comm, (UINT8 *)timespec, sizeof(struct timespec), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_timespec_size(const UINT32 comm, const struct timespec *timespec, UINT32 *size)
{
    cmpi_encode_uint8_array_size(comm, (UINT8 *)timespec, sizeof(struct timespec), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_timespec(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct timespec *timespec)
{
    UINT32      len;
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, (UINT8 *)timespec, &len);
    ASSERT(sizeof(struct timespec) == len);

    return ((UINT32)0);
}
#endif


#if 1
struct utimbuf *c_utimbuf_new()
{
    struct utimbuf *utimbuf;

    utimbuf = safe_malloc(sizeof(struct utimbuf), LOC_CFUSED_0009);
    if(NULL_PTR == utimbuf)
    {
        dbg_log(SEC_0034_CFUSED, 0)(LOGSTDOUT, "error:c_utimbuf_new: no memory\n");
        return (NULL_PTR);
    }

    c_utimbuf_init(utimbuf);
    return (utimbuf);
}

EC_BOOL c_utimbuf_init(struct utimbuf *utimbuf)
{
    if(NULL_PTR != utimbuf)
    {
        BSET(utimbuf, 0x00, sizeof(struct utimbuf));
    }

    return (EC_TRUE);
}

EC_BOOL c_utimbuf_clean(struct utimbuf *utimbuf)
{
    if(NULL_PTR != utimbuf)
    {
        BSET(utimbuf, 0x00, sizeof(struct utimbuf));
    }

    return (EC_TRUE);
}

EC_BOOL c_utimbuf_free(struct utimbuf *utimbuf)
{
    if(NULL_PTR != utimbuf)
    {
        c_utimbuf_clean(utimbuf);
        safe_free(utimbuf, LOC_CFUSED_0010);
    }
    return (EC_TRUE);
}


UINT32 cmpi_encode_utimbuf(const UINT32 comm, const struct utimbuf *utimbuf, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    cmpi_encode_uint8_array(comm, (UINT8 *)utimbuf, sizeof(struct utimbuf), out_buff, out_buff_max_len, position);
    return ((UINT32)0);
}

UINT32 cmpi_encode_utimbuf_size(const UINT32 comm, const struct utimbuf *utimbuf, UINT32 *size)
{
    cmpi_encode_uint8_array_size(comm, (UINT8 *)utimbuf, sizeof(struct utimbuf), size);
    return ((UINT32)0);
}

UINT32 cmpi_decode_utimbuf(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct utimbuf *utimbuf)
{
    UINT32      len;
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, (UINT8 *)utimbuf, &len);
    ASSERT(sizeof(struct utimbuf) == len);

    return ((UINT32)0);
}
#endif


#if 1
struct dirnode *c_dirnode_new()
{
    struct dirnode *dirnode;

    dirnode = safe_malloc(sizeof(struct dirnode), LOC_CFUSED_0011);
    if(NULL_PTR == dirnode)
    {
        dbg_log(SEC_0034_CFUSED, 0)(LOGSTDOUT, "error:c_dirnode_new: no memory\n");
        return (NULL_PTR);
    }

    c_dirnode_init(dirnode);
    return (dirnode);
}

EC_BOOL c_dirnode_init(struct dirnode *dirnode)
{
    if(NULL_PTR != dirnode)
    {
        dirnode->name      = NULL_PTR;
        dirnode->offset    = 0;
        dirnode->flags     = 0;
        BSET(&(dirnode->stat), 0x00, sizeof(struct stat));
    }

    return (EC_TRUE);
}

EC_BOOL c_dirnode_clean(struct dirnode *dirnode)
{
    if(NULL_PTR != dirnode)
    {
        if(NULL_PTR != dirnode->name)
        {
            c_str_free(dirnode->name);
            dirnode->name     = NULL_PTR;
        }

        dirnode->offset    = 0;
        dirnode->flags     = 0;

        BSET(&(dirnode->stat), 0x00, sizeof(struct stat));
    }

    return (EC_TRUE);
}

EC_BOOL c_dirnode_free(struct dirnode *dirnode)
{
    if(NULL_PTR != dirnode)
    {
        c_dirnode_clean(dirnode);
        safe_free(dirnode, LOC_CFUSED_0012);
    }
    return (EC_TRUE);
}

UINT32 cmpi_encode_dirnode(const UINT32 comm, const struct dirnode *dirnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32      num;
    UINT32      len;
    UINT8      *data;
    uint32_t    u32;

    if(NULL_PTR != dirnode->name)
    {
        len  = strlen(dirnode->name);
        data = (UINT8 *)(dirnode->name);
        cmpi_encode_uint32(comm, len, out_buff, out_buff_max_len, position);
        cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);
    }
    else
    {
        len = 0;
        cmpi_encode_uint32(comm, len, out_buff, out_buff_max_len, position);
    }

    len  = sizeof(struct stat);
    data = (UINT8 *)&(dirnode->stat);
    cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);

    num = (UINT32)(dirnode->offset);
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    u32 = dirnode->flags;
    cmpi_encode_uint32_t(comm, u32, out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_dirnode_size(const UINT32 comm, const struct dirnode *dirnode, UINT32 *size)
{
    UINT32      num;
    UINT32      len;
    UINT8      *data;
    uint32_t    u32;

    if(NULL_PTR != dirnode->name)
    {
        len  = strlen(dirnode->name);
        data = (UINT8 *)(dirnode->name);
        cmpi_encode_uint32_size(comm, len, size);
        cmpi_encode_uint8_array_size(comm, data, len, size);
    }
    else
    {
        len = 0;
        cmpi_encode_uint32_size(comm, len, size);
    }

    len  = sizeof(struct stat);
    data = (UINT8 *)&(dirnode->stat);
    cmpi_encode_uint8_array_size(comm, data, len, size);

    num = (UINT32)(dirnode->offset);
    cmpi_encode_uint32_size(comm, num, size);

    u32 = dirnode->flags;
    cmpi_encode_uint32_t_size(comm, u32, size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_dirnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct dirnode *dirnode)
{
    UINT32      num;
    UINT32      len;
    UINT8      *data;
    uint32_t    u32;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &len);
    if(0 != len)
    {
        data = safe_malloc(len + 1, LOC_CFUSED_0013);
        num  = len;
        ASSERT(NULL_PTR != data);
        cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
        ASSERT(num == len);
        data[ len ] = 0x00;

        dirnode->name = (char *)data;
    }
    else
    {
        dirnode->name = NULL_PTR;
    }

    data = (UINT8 *)&(dirnode->stat);
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
    ASSERT(sizeof(struct stat) == len);

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    dirnode->offset = (off_t)num;

    cmpi_decode_uint32_t(comm, in_buff, in_buff_max_len, position, &u32);
    dirnode->flags = u32;

    return ((UINT32)0);
}

#endif

#ifdef __cplusplus
}
#endif/*__cplusplus*/

