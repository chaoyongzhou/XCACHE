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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/xattr.h>
#include <x86_64-linux-gnu/sys/xattr.h>
#include <dirent.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cbc.h"
#include "cmisc.h"
#include "task.h"

#include "cfuses.h"
#include "cfused.h"

#include "findex.inc"

/*----------------------------------------------------------------------------*\
 *                             CFUSE SERVER                                   *
\*----------------------------------------------------------------------------*/

#define CFUSES_MD_CAPACITY()                  (cbc_md_capacity(MD_CFUSES))

#define CFUSES_MD_GET(cfuses_md_id)     ((CFUSES_MD *)cbc_md_get(MD_CFUSES, (cfuses_md_id)))

#define CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id)  \
    ((CMPI_ANY_MODI != (cfuses_md_id)) && ((NULL_PTR == CFUSES_MD_GET(cfuses_md_id)) || (0 == (CFUSES_MD_GET(cfuses_md_id)->usedcounter))))

#define CFUSES_ASSERT(cond)     ASSERT(cond)
#define CFUSES_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0024_CFUSES, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")
#define CFUSES_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0024_CFUSES, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")

/**
*   for test only
*
*   to query the status of CFUSES Module
*
**/
void cfuses_print_module_status(const UINT32 cfuses_md_id, LOG *log)
{
    CFUSES_MD *cfuses_md;
    UINT32 this_cfuses_md_id;

    for( this_cfuses_md_id = 0; this_cfuses_md_id < CFUSES_MD_CAPACITY(); this_cfuses_md_id ++ )
    {
        cfuses_md = CFUSES_MD_GET(this_cfuses_md_id);

        if ( NULL_PTR != cfuses_md && 0 < cfuses_md->usedcounter )
        {
            sys_log(log,"CFUSES Module # %ld : %ld refered\n",
                    this_cfuses_md_id,
                    cfuses_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CFUSES module
*
*
**/
UINT32 cfuses_free_module_static_mem(const UINT32 cfuses_md_id)
{
#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_free_module_static_mem: cxfs module #%ld not started.\n",
                cfuses_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    free_module_static_mem(MD_CFUSES, cfuses_md_id);

    return 0;
}

/**
*
* start CFUSES module
*
**/
UINT32 cfuses_start(const CSTRING *mount_path)
{
    CFUSES_MD       *cfuses_md;
    UINT32           cfuses_md_id;
    char            *mount_path_str;

    cbc_md_reg(MD_CFUSES, 16);

    mount_path_str = c_str_dup((const char *)cstring_get_str(mount_path));
    if(NULL_PTR == mount_path_str)
    {
        return (CMPI_ERROR_MODI);
    }

    cfuses_md_id = cbc_md_new(MD_CFUSES, sizeof(CFUSES_MD));
    if(CMPI_ERROR_MODI == cfuses_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CFUSES module */
    cfuses_md = (CFUSES_MD *)cbc_md_get(MD_CFUSES, cfuses_md_id);
    cfuses_md->usedcounter   = 0;
    CFUSES_MD_MOUNT_PATH(cfuses_md) = mount_path_str;

    /* create a new module node */
    init_static_mem();

    cfuses_md->usedcounter = 1;

    cfused_start();

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cfuses_end, cfuses_md_id);

    dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "[DEBUG] cfuses_start: "
                                           "start CFUSES module #%ld\n",
                                           cfuses_md_id);

    return ( cfuses_md_id );
}

/**
*
* end CFUSES module
*
**/
void cfuses_end(const UINT32 cfuses_md_id)
{
    CFUSES_MD *cfuses_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cfuses_end, cfuses_md_id);

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    if(NULL_PTR == cfuses_md)
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_end: "
                                               "cfuses_md_id = %ld not exist.\n",
                                               cfuses_md_id);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cfuses_md->usedcounter )
    {
        cfuses_md->usedcounter --;
        return ;
    }

    if ( 0 == cfuses_md->usedcounter )
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_end: "
                                               "cfuses_md_id = %ld is not started.\n",
                                               cfuses_md_id);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }

    if(NULL_PTR != CFUSES_MD_MOUNT_PATH(cfuses_md))
    {
        c_str_free(CFUSES_MD_MOUNT_PATH(cfuses_md));
        CFUSES_MD_MOUNT_PATH(cfuses_md) = NULL_PTR;
    }

    cfused_end();

    /* free module : */
    //cfuses_free_module_static_mem(cfuses_md_id);

    cfuses_md->usedcounter = 0;

    cbc_md_free(MD_CFUSES, cfuses_md_id);

    dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "[DEBUG] cfuses_end: "
                                           "stop CFUSES module #%ld\n",
                                           cfuses_md_id);

    return ;
}

CFUSES_ARG *cfuses_arg_new()
{
    CFUSES_ARG *cfuses_arg;

    alloc_static_mem(MM_CFUSES_ARG, &cfuses_arg, LOC_CFUSES_0001);
    if(NULL_PTR == cfuses_arg)
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_new: no memory\n");
        return (NULL_PTR);
    }

    cfuses_arg_init(cfuses_arg);
    return (cfuses_arg);
}

EC_BOOL cfuses_arg_init(CFUSES_ARG *cfuses_arg)
{
    if(NULL_PTR != cfuses_arg)
    {
        BSET(cfuses_arg, 0x00, sizeof(CFUSES_ARG));

        CFUSES_ARG_FLAG(cfuses_arg) = CFUSE_ARG_FLAG_ERR;
    }

    return (EC_TRUE);
}

EC_BOOL cfuses_arg_clean(CFUSES_ARG *cfuses_arg)
{
    CFUSES_ASSERT(NULL_PTR != cfuses_arg);

    switch(CFUSES_ARG_TYPE(cfuses_arg))
    {
        case CFUSES_ARG_TYPE_CHAR:
        {
            if(NULL_PTR != CFUSES_ARG_V_CHAR(cfuses_arg)
            && CFUSE_ARG_FLAG_IS_ALLOC == CFUSES_ARG_FLAG(cfuses_arg))
            {
                c_str_free(CFUSES_ARG_V_CHAR(cfuses_arg));
                CFUSES_ARG_V_CHAR(cfuses_arg) = NULL_PTR;
            }
            else
            {
                CFUSES_ARG_V_CHAR(cfuses_arg) = NULL_PTR;
            }
            break;
        }
        case CFUSES_ARG_TYPE_BYTE:
        {
            if(NULL_PTR != CFUSES_ARG_V_BYTE(cfuses_arg)
            && CFUSE_ARG_FLAG_IS_ALLOC == CFUSES_ARG_FLAG(cfuses_arg))
            {
                safe_free(CFUSES_ARG_V_BYTE(cfuses_arg), LOC_CFUSES_0002);
                CFUSES_ARG_V_BYTE(cfuses_arg) = NULL_PTR;
            }
            else
            {
                CFUSES_ARG_V_BYTE(cfuses_arg) = NULL_PTR;
            }
            break;
        }
        case CFUSES_ARG_TYPE_MODE:
        {
            break;
        }
        case CFUSES_ARG_TYPE_DEV:
        {
            break;
        }
        case CFUSES_ARG_TYPE_UID:
        {
            break;
        }
        case CFUSES_ARG_TYPE_GID:
        {
            break;
        }
        case CFUSES_ARG_TYPE_OFFT:
        {
            break;
        }
        case CFUSES_ARG_TYPE_SIZE:
        {
            break;
        }
        case CFUSES_ARG_TYPE_INT:
        {
            break;
        }
        case CFUSES_ARG_TYPE_LONG:
        {
            break;
        }
        case CFUSES_ARG_TYPE_UTIME:
        {
            if(NULL_PTR != CFUSES_ARG_V_UTIME(cfuses_arg)
            && CFUSE_ARG_FLAG_IS_ALLOC == CFUSES_ARG_FLAG(cfuses_arg))
            {
                safe_free(CFUSES_ARG_V_UTIME(cfuses_arg), LOC_CFUSES_0003);
                CFUSES_ARG_V_UTIME(cfuses_arg) = NULL_PTR;
            }
            else
            {
                CFUSES_ARG_V_UTIME(cfuses_arg) = NULL_PTR;
            }
            break;
        }
        case CFUSES_ARG_TYPE_STATVFS:
        {
            if(NULL_PTR != CFUSES_ARG_V_STATVFS(cfuses_arg)
            && CFUSE_ARG_FLAG_IS_ALLOC == CFUSES_ARG_FLAG(cfuses_arg))
            {
                safe_free(CFUSES_ARG_V_STATVFS(cfuses_arg), LOC_CFUSES_0004);
                CFUSES_ARG_V_STATVFS(cfuses_arg) = NULL_PTR;
            }
            else
            {
                CFUSES_ARG_V_STATVFS(cfuses_arg) = NULL_PTR;
            }
            break;
        }
        case CFUSES_ARG_TYPE_STAT:
        {
            if(NULL_PTR != CFUSES_ARG_V_STAT(cfuses_arg)
            && CFUSE_ARG_FLAG_IS_ALLOC == CFUSES_ARG_FLAG(cfuses_arg))
            {
                safe_free(CFUSES_ARG_V_STAT(cfuses_arg), LOC_CFUSES_0005);
                CFUSES_ARG_V_STAT(cfuses_arg) = NULL_PTR;
            }
            else
            {
                CFUSES_ARG_V_STAT(cfuses_arg) = NULL_PTR;
            }
            break;
        }
        case CFUSES_ARG_TYPE_TS:
        {
            break;
        }
        case CFUSES_ARG_TYPE_FUSE_DH:
        {
            if(NULL_PTR != CFUSES_ARG_V_FUSE_DH(cfuses_arg)
            && CFUSE_ARG_FLAG_IS_ALLOC == CFUSES_ARG_FLAG(cfuses_arg))
            {
                c_fuse_dh_free(CFUSES_ARG_V_FUSE_DH(cfuses_arg));
                CFUSES_ARG_V_FUSE_DH(cfuses_arg) = NULL_PTR;
            }
            else
            {
                CFUSES_ARG_V_FUSE_DH(cfuses_arg) = NULL_PTR;
            }
            break;
        }
        default:
        {
            dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_clean: "
                                                   "unknown type %ld\n",
                                                   CFUSES_ARG_TYPE(cfuses_arg));
            return (EC_FALSE);
        }
    }

    BSET(cfuses_arg, 0x00, sizeof(CFUSES_ARG));
    CFUSES_ARG_FLAG(cfuses_arg) = CFUSE_ARG_FLAG_ERR;

    return (EC_TRUE);
}

EC_BOOL cfuses_arg_free(CFUSES_ARG *cfuses_arg)
{
    if(NULL_PTR != cfuses_arg)
    {
        cfuses_arg_clean(cfuses_arg);
        free_static_mem(MM_CFUSES_ARG, cfuses_arg, LOC_CFUSES_0006);
    }
    return (EC_TRUE);
}

EC_BOOL cfuses_arg_set(CFUSES_ARG *cfuses_arg, const UINT32 type, const void *data, const UINT32 data_len)
{
    CFUSES_ASSERT(NULL_PTR != cfuses_arg);

    CFUSES_ARG_TYPE(cfuses_arg) = type;
    CFUSES_ARG_VLEN(cfuses_arg) = data_len;

    switch(CFUSES_ARG_TYPE(cfuses_arg))
    {
        case CFUSES_ARG_TYPE_CHAR:
        {
            if(NULL_PTR == data)
            {
                CFUSES_ASSERT(0 == data_len);
                CFUSES_ARG_V_CHAR(cfuses_arg) = NULL_PTR;
                return (EC_TRUE);
            }

            CFUSES_ASSERT(strlen((const char *)data) == CFUSES_ARG_VLEN(cfuses_arg));

            CFUSES_ARG_V_CHAR(cfuses_arg) = c_str_dup((const char *)data);
            if(NULL_PTR == CFUSES_ARG_V_CHAR(cfuses_arg))
            {
                dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                                       "dup str '%s' failed\n",
                                                       (const char *)data);
                return (EC_FALSE);
            }
            CFUSES_ARG_FLAG(cfuses_arg) = CFUSE_ARG_FLAG_IS_ALLOC;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_BYTE:
        {
            if(NULL_PTR == data)
            {
                CFUSES_ASSERT(0 == data_len);
                CFUSES_ARG_V_BYTE(cfuses_arg) = NULL_PTR;
                return (EC_TRUE);
            }

            CFUSES_ARG_V_BYTE(cfuses_arg) = safe_malloc(data_len, LOC_CFUSES_0007);
            if(NULL_PTR == CFUSES_ARG_V_BYTE(cfuses_arg))
            {
                dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                                       "malloc %ld bytes failed\n",
                                                       data_len);
                return (EC_FALSE);
            }
            BCOPY(data, CFUSES_ARG_V_BYTE(cfuses_arg), data_len);
            CFUSES_ARG_FLAG(cfuses_arg) = CFUSE_ARG_FLAG_IS_ALLOC;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_MODE:
        {
            CFUSES_ARG_V_MODE(cfuses_arg) = (mode_t)(uintptr_t)data;
            CFUSES_ASSERT(sizeof(mode_t) == data_len);
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_DEV:
        {
            CFUSES_ARG_V_DEV(cfuses_arg) = (dev_t)(uintptr_t)data;
            CFUSES_ASSERT(sizeof(dev_t) == data_len);
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_UID:
        {
            CFUSES_ASSERT(sizeof(uid_t) == data_len);
            CFUSES_ARG_V_UID(cfuses_arg) = (uid_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_GID:
        {
            CFUSES_ASSERT(sizeof(gid_t) == data_len);
            CFUSES_ARG_V_GID(cfuses_arg) = (gid_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_OFFT:
        {
            CFUSES_ASSERT(sizeof(off_t) == data_len);
            CFUSES_ARG_V_OFFT(cfuses_arg) = (off_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_SIZE:
        {
            CFUSES_ASSERT(sizeof(size_t) == data_len);
            CFUSES_ARG_V_SIZE(cfuses_arg) = (size_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_INT:
        {
            CFUSES_ASSERT(sizeof(int) == data_len);
            CFUSES_ARG_V_INT(cfuses_arg) = (int)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_LONG:
        {
            CFUSES_ASSERT(sizeof(long int) == data_len);
            CFUSES_ARG_V_LONG(cfuses_arg) = (long int)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_UTIME:
        {
            CFUSES_ASSERT(sizeof(struct utimbuf) == data_len);
            CFUSES_ARG_V_UTIME(cfuses_arg) = safe_malloc(sizeof(struct utimbuf), LOC_CFUSES_0008);
            if(NULL_PTR == CFUSES_ARG_V_UTIME(cfuses_arg))
            {
                dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                                       "alloc type %ld failed\n",
                                                       CFUSES_ARG_TYPE(cfuses_arg));
                return (EC_FALSE);
            }
            CFUSES_ARG_FLAG(cfuses_arg) = CFUSE_ARG_FLAG_IS_ALLOC;

            if(NULL_PTR != data)
            {
                BCOPY(data, (void *)CFUSES_ARG_V_UTIME(cfuses_arg), sizeof(struct utimbuf));
            }
            else
            {
                BSET((void *)CFUSES_ARG_V_UTIME(cfuses_arg), 0x00, data_len);
            }
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_STATVFS:
        {
            CFUSES_ASSERT(sizeof(struct statvfs) == data_len);
            CFUSES_ARG_V_STATVFS(cfuses_arg) = safe_malloc(sizeof(struct statvfs), LOC_CFUSES_0009);
            if(NULL_PTR == CFUSES_ARG_V_STATVFS(cfuses_arg))
            {
                dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                                       "alloc type %ld failed\n",
                                                       CFUSES_ARG_TYPE(cfuses_arg));
                return (EC_FALSE);
            }
            CFUSES_ARG_FLAG(cfuses_arg) = CFUSE_ARG_FLAG_IS_ALLOC;

            if(NULL_PTR != data)
            {
                BCOPY(data, (void *)CFUSES_ARG_V_STATVFS(cfuses_arg), sizeof(struct statvfs));
            }
            else
            {
                BSET((void *)CFUSES_ARG_V_STATVFS(cfuses_arg), 0x00, data_len);
            }
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_STAT:
        {
            CFUSES_ASSERT(sizeof(struct stat) == data_len);
            CFUSES_ARG_V_STAT(cfuses_arg) = safe_malloc(sizeof(struct stat), LOC_CFUSES_0010);
            if(NULL_PTR == CFUSES_ARG_V_STAT(cfuses_arg))
            {
                dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                                       "alloc type %ld failed\n",
                                                       CFUSES_ARG_TYPE(cfuses_arg));
                return (EC_FALSE);
            }
            CFUSES_ARG_FLAG(cfuses_arg) = CFUSE_ARG_FLAG_IS_ALLOC;

            if(NULL_PTR != data)
            {
                BCOPY(data, (void *)CFUSES_ARG_V_STAT(cfuses_arg), sizeof(struct stat));
            }
            else
            {
                BSET((void *)CFUSES_ARG_V_STAT(cfuses_arg), 0x00, data_len);
            }
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_TS:
        {
            CFUSES_ASSERT(sizeof(struct timespec) == data_len);
            if(NULL_PTR != data)
            {
                BCOPY(((struct timespec **)data)[0], (void *)CFUSES_ARG_V_TS_0(cfuses_arg), data_len);
                BCOPY(((struct timespec **)data)[1], (void *)CFUSES_ARG_V_TS_1(cfuses_arg), data_len);
            }
            else
            {
                BSET((void *)CFUSES_ARG_V_TS_0(cfuses_arg), 0x00, data_len);
                BSET((void *)CFUSES_ARG_V_TS_1(cfuses_arg), 0x00, data_len);
            }
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_FUSE_DH:
        {
            dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                                   "should never reach here, type %ld\n",
                                                   CFUSES_ARG_TYPE(cfuses_arg));
            return (EC_FALSE);
        }
        default:
        {
            dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                                   "unknown type %ld\n",
                                                   CFUSES_ARG_TYPE(cfuses_arg));
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_set: "
                                           "should never reach here, type %ld\n",
                                           CFUSES_ARG_TYPE(cfuses_arg));
    return (EC_FALSE);
}

EC_BOOL cfuses_arg_mount(CFUSES_ARG *cfuses_arg, const UINT32 type, const void *data, const UINT32 data_len)
{
    CFUSES_ASSERT(NULL_PTR != cfuses_arg);

    CFUSES_ARG_TYPE(cfuses_arg) = type;
    CFUSES_ARG_VLEN(cfuses_arg) = data_len;

    switch(CFUSES_ARG_TYPE(cfuses_arg))
    {
        case CFUSES_ARG_TYPE_CHAR:
        {
            CFUSES_ASSERT(NULL_PTR == CFUSES_ARG_V_CHAR(cfuses_arg));
            CFUSES_ARG_V_CHAR(cfuses_arg) = (char *)(uintptr_t)data;
            CFUSES_ARG_FLAG(cfuses_arg)   = CFUSE_ARG_FLAG_IS_MOUNT;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_BYTE:
        {
            CFUSES_ASSERT(NULL_PTR == CFUSES_ARG_V_BYTE(cfuses_arg));
            CFUSES_ARG_V_BYTE(cfuses_arg) = (char *)(uintptr_t)data;
            CFUSES_ARG_FLAG(cfuses_arg)   = CFUSE_ARG_FLAG_IS_MOUNT;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_MODE:
        {
            CFUSES_ARG_V_MODE(cfuses_arg) = (mode_t)(uintptr_t)data;
            CFUSES_ASSERT(sizeof(mode_t) == data_len);
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_DEV:
        {
            CFUSES_ARG_V_DEV(cfuses_arg) = (dev_t)(uintptr_t)data;
            CFUSES_ASSERT(sizeof(dev_t) == data_len);
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_UID:
        {
            CFUSES_ASSERT(sizeof(uid_t) == data_len);
            CFUSES_ARG_V_UID(cfuses_arg) = (uid_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_GID:
        {
            CFUSES_ASSERT(sizeof(gid_t) == data_len);
            CFUSES_ARG_V_GID(cfuses_arg) = (gid_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_OFFT:
        {
            CFUSES_ASSERT(sizeof(off_t) == data_len);
            CFUSES_ARG_V_OFFT(cfuses_arg) = (off_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_SIZE:
        {
            CFUSES_ASSERT(sizeof(size_t) == data_len);
            CFUSES_ARG_V_SIZE(cfuses_arg) = (size_t)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_INT:
        {
            CFUSES_ASSERT(sizeof(int) == data_len);
            CFUSES_ARG_V_INT(cfuses_arg) = (int)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_LONG:
        {
            CFUSES_ASSERT(sizeof(long int) == data_len);
            CFUSES_ARG_V_LONG(cfuses_arg) = (long int)(uintptr_t)data;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_UTIME:
        {
            CFUSES_ASSERT(sizeof(struct utimbuf) == data_len);
            CFUSES_ASSERT(NULL_PTR == CFUSES_ARG_V_UTIME(cfuses_arg));
            CFUSES_ARG_V_UTIME(cfuses_arg) = (struct utimbuf *)(uintptr_t)data;
            CFUSES_ARG_FLAG(cfuses_arg)    = CFUSE_ARG_FLAG_IS_MOUNT;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_STATVFS:
        {
            CFUSES_ASSERT(sizeof(struct statvfs) == data_len);
            CFUSES_ASSERT(NULL_PTR == CFUSES_ARG_V_STATVFS(cfuses_arg));
            CFUSES_ARG_V_STATVFS(cfuses_arg) = (struct statvfs *)(uintptr_t)data;
            CFUSES_ARG_FLAG(cfuses_arg)     = CFUSE_ARG_FLAG_IS_MOUNT;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_STAT:
        {
            CFUSES_ASSERT(sizeof(struct stat) == data_len);
            CFUSES_ASSERT(NULL_PTR == CFUSES_ARG_V_STAT(cfuses_arg));
            CFUSES_ARG_V_STAT(cfuses_arg) = (struct stat *)(uintptr_t)data;
            CFUSES_ARG_FLAG(cfuses_arg)   = CFUSE_ARG_FLAG_IS_MOUNT;
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_TS:
        {
            CFUSES_ASSERT(sizeof(struct timespec) == data_len);
            if(NULL_PTR != data)
            {
                BCOPY(((struct timespec **)data)[0], (void *)CFUSES_ARG_V_TS_0(cfuses_arg), data_len);
                BCOPY(((struct timespec **)data)[1], (void *)CFUSES_ARG_V_TS_1(cfuses_arg), data_len);
            }
            else
            {
                BSET((void *)CFUSES_ARG_V_TS_0(cfuses_arg), 0x00, data_len);
                BSET((void *)CFUSES_ARG_V_TS_1(cfuses_arg), 0x00, data_len);
            }
            return (EC_TRUE);
        }
        case CFUSES_ARG_TYPE_FUSE_DH:
        {
            CFUSES_ASSERT(sizeof(struct fuse_dh) == data_len);
            CFUSES_ASSERT(NULL_PTR == CFUSES_ARG_V_FUSE_DH(cfuses_arg));
            CFUSES_ARG_V_FUSE_DH(cfuses_arg) = (struct fuse_dh *)(uintptr_t)data;
            CFUSES_ARG_FLAG(cfuses_arg)   = CFUSE_ARG_FLAG_IS_MOUNT;
            return (EC_TRUE);
        }
        default:
        {
            dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_mount: "
                                                   "unknown type %ld\n",
                                                   CFUSES_ARG_TYPE(cfuses_arg));
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_arg_mount: "
                                           "should never reach here, type %ld\n",
                                           CFUSES_ARG_TYPE(cfuses_arg));
    return (EC_FALSE);
}

/*int (*getattr) (const char *, struct stat *);*/
EC_BOOL cfuses_getattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *stat_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_getattr: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_STAT == CFUSES_ARG_TYPE(stat_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_getattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    res = lstat(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_STAT(stat_arg));
    if(0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.	If the linkname is too long to fit in the
 * buffer, it should be truncated.	The return value should be 0
 * for success.
 */
/*int (*readlink) (const char *, char *, size_t);*/
EC_BOOL cfuses_readlink(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *buf_arg, const CFUSES_ARG *bufsize_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_readlink: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_BYTE == CFUSES_ARG_TYPE(buf_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_SIZE == CFUSES_ARG_TYPE(bufsize_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_readlink");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = readlink(CFUSES_ARG_V_CHAR(path_arg),
	                CFUSES_ARG_V_CHAR(buf_arg),
	                CFUSES_ARG_V_LONG(bufsize_arg) - 1);
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

	CFUSES_ARG_V_CHAR(buf_arg)[ res ] = '\0';

    return (EC_TRUE);
}



/*------------- ignore -------------*/
/* Deprecated, use readdir() instead */
/*int (*getdir) (const char *, fuse_dirh_t, fuse_dirfil_t);*/

/*------------- ignore -------------*/
/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
/*int (*mknod) (const char *, mode_t, dev_t);*/
EC_BOOL cfuses_mknod(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mode_arg, const CFUSES_ARG *dev_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_mknod: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_MODE == CFUSES_ARG_TYPE(mode_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_DEV  == CFUSES_ARG_TYPE(dev_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_mknod");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = mknod(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_MODE(mode_arg), CFUSES_ARG_V_DEV(mode_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
/*int (*mkdir) (const char *, mode_t);*/
EC_BOOL cfuses_mkdir(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mode_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_mkdir: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_MODE == CFUSES_ARG_TYPE(mode_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_mkdir");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = mkdir(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_MODE(mode_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Remove a file */
/*int (*unlink) (const char *);*/
EC_BOOL cfuses_unlink(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_unlink: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_unlink");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = unlink(CFUSES_ARG_V_CHAR(path_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Remove a directory */
/*int (*rmdir) (const char *);*/
EC_BOOL cfuses_rmdir(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_rmdir: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_rmdir");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);

    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = rmdir(CFUSES_ARG_V_CHAR(path_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
EC_BOOL cfuses_symlink(const UINT32 cfuses_md_id, const CFUSES_ARG *from_path_arg, const CFUSES_ARG *to_path_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;
    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_symlink: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(from_path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(to_path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_symlink");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = symlink(CFUSES_ARG_V_CHAR(from_path_arg), CFUSES_ARG_V_CHAR(to_path_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Rename a file */
/*int (*rename) (const char *, const char *);*/
EC_BOOL cfuses_rename(const UINT32 cfuses_md_id, const CFUSES_ARG *from_path_arg, const CFUSES_ARG *to_path_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;
    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_rename: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(from_path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(to_path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_rename");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = rename(CFUSES_ARG_V_CHAR(from_path_arg), CFUSES_ARG_V_CHAR(to_path_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
EC_BOOL cfuses_link(const UINT32 cfuses_md_id, const CFUSES_ARG *from_path_arg, const CFUSES_ARG *to_path_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;
    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_link: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(from_path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(to_path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_link");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = link(CFUSES_ARG_V_CHAR(from_path_arg), CFUSES_ARG_V_CHAR(to_path_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t);*/
EC_BOOL cfuses_chmod(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mod_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_chmod: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_MODE == CFUSES_ARG_TYPE(mod_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_chmod");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = chmod(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_MODE(mod_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
EC_BOOL cfuses_chown(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *owner_arg, const CFUSES_ARG *group_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_chown: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_UID  == CFUSES_ARG_TYPE(owner_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_GID  == CFUSES_ARG_TYPE(group_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_chown");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = lchown(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_UID(owner_arg), CFUSES_ARG_V_GID(group_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
EC_BOOL cfuses_truncate(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *length_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_truncate: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_OFFT  == CFUSES_ARG_TYPE(length_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_truncate");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = truncate(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_SIZE(length_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
EC_BOOL cfuses_utime(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *times_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_utime: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR  == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_UTIME == CFUSES_ARG_TYPE(times_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG  == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_utime");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = utime(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_UTIME(times_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
    }

    return (EC_TRUE);
}

/** File open operation
 *
 * No creation (O_CREAT, O_EXCL) and by default also no
 * truncation (O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 *
 * Changed in version 2.2
 */
/*int (*open) (const char *, struct fuse_file_info *);*/
EC_BOOL cfuses_open(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *flags_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_open: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_INT  == CFUSES_ARG_TYPE(flags_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_open");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = open(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_INT(flags_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    close(res);

    return (EC_TRUE);
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
/*int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);*/
EC_BOOL cfuses_read(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *buf_arg, const CFUSES_ARG *size_arg, const CFUSES_ARG *offset_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;
    int          fd;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_read: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_BYTE == CFUSES_ARG_TYPE(buf_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_SIZE == CFUSES_ARG_TYPE(size_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_OFFT == CFUSES_ARG_TYPE(offset_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_read");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	fd = open(CFUSES_ARG_V_CHAR(path_arg), O_RDONLY);
	if (0 > fd)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

	res = pread(fd,
	            CFUSES_ARG_V_CHAR(buf_arg),
	            CFUSES_ARG_V_SIZE(size_arg),
	            CFUSES_ARG_V_OFFT(offset_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;
        close(fd);
        return (EC_TRUE);
    }

    CFUSES_ARG_V_LONG(ret_arg) = res;
	close(fd);
    return (EC_TRUE);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.	 An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
/*int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);*/
EC_BOOL cfuses_write(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *buf_arg, const CFUSES_ARG *size_arg, const CFUSES_ARG *offset_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;
    int          fd;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_write: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_BYTE == CFUSES_ARG_TYPE(buf_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_SIZE == CFUSES_ARG_TYPE(size_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_OFFT == CFUSES_ARG_TYPE(offset_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_write");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	fd = open(CFUSES_ARG_V_CHAR(path_arg), O_WRONLY);
	if (0 > fd)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

	res = pwrite(fd,
	            CFUSES_ARG_V_CHAR(buf_arg),
	            CFUSES_ARG_V_SIZE(size_arg),
	            CFUSES_ARG_V_OFFT(offset_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        close(fd);
        return (EC_TRUE);
    }

    CFUSES_ARG_V_LONG(ret_arg) = res;
	close(fd);
    return (EC_TRUE);
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
/*int (*statfs) (const char *, struct statvfs *);*/
EC_BOOL cfuses_statfs(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *statfs_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_statfs: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR   == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_STATVFS== CFUSES_ARG_TYPE(statfs_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG   == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_statfs");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = statvfs(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_STATVFS(statfs_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().	This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.	It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
/*int (*flush) (const char *, struct fuse_file_info *);*/
EC_BOOL cfuses_flush(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_flush: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_flush");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    /*do nothing*/

    return (EC_TRUE);
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.	 It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
/*int (*release) (const char *, struct fuse_file_info *);*/
EC_BOOL cfuses_release(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *flag_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_release: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_INT  == CFUSES_ARG_TYPE(flag_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_release");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    /*do nothing*/

    return (EC_TRUE);
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
/*int (*fsync) (const char *, int, struct fuse_file_info *);*/
EC_BOOL cfuses_fsync(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *datasync_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_fsync: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_INT  == CFUSES_ARG_TYPE(datasync_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_fsync");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    /*do nothing*/

    return (EC_TRUE);
}

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
EC_BOOL cfuses_setxattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *name_arg, const CFUSES_ARG *value_arg, const CFUSES_ARG *size_arg, const CFUSES_ARG *flags_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_setxattr: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(name_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(value_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_SIZE == CFUSES_ARG_TYPE(size_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_INT  == CFUSES_ARG_TYPE(flags_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_setxattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    /*ENOTSUP*/
	res = lsetxattr(CFUSES_ARG_V_CHAR(path_arg),
	                CFUSES_ARG_V_CHAR(name_arg),
	                CFUSES_ARG_V_CHAR(value_arg),
	                CFUSES_ARG_V_SIZE(size_arg),
	                CFUSES_ARG_V_INT(flags_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }


    return (EC_TRUE);
}

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
EC_BOOL cfuses_getxattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *name_arg, CFUSES_ARG *value_arg, const CFUSES_ARG *size_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_getxattr: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(name_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(value_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_SIZE == CFUSES_ARG_TYPE(size_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_getxattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    /*ENOTSUP*/
	res = lgetxattr(CFUSES_ARG_V_CHAR(path_arg),
	                CFUSES_ARG_V_CHAR(name_arg),
	                CFUSES_ARG_V_CHAR(value_arg),
	                CFUSES_ARG_V_SIZE(size_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    CFUSES_ARG_V_LONG(ret_arg) = res;

    return (EC_TRUE);
}

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
EC_BOOL cfuses_listxattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *list_arg, const CFUSES_ARG *size_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_listxattr: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(list_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_SIZE == CFUSES_ARG_TYPE(size_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_listxattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = llistxattr(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_CHAR(list_arg), CFUSES_ARG_V_SIZE(size_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    CFUSES_ARG_V_LONG(ret_arg) = res;

    return (EC_TRUE);
}

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
EC_BOOL cfuses_removexattr(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *name_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_removexattr: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(name_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_removexattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	res = lremovexattr(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_CHAR(name_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

/*------------- ignore -------------*/
/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, closedir and fsyncdir.
 *
 * Introduced in version 2.3
 */
/*int (*opendir) (const char *, struct fuse_file_info *);*/

/*------------- ignore -------------*/
/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */
/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/

/*------------- ignore -------------*/
/** Release directory
 *
 * Introduced in version 2.3
 */
/*int (*releasedir) (const char *, struct fuse_file_info *);*/

/*------------- ignore -------------*/
/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/

/*------------- ignore -------------*/
/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
/*void *(*init) (struct fuse_conn_info *conn);*/

/*------------- ignore -------------*/
/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
/*void (*destroy) (void *);*/

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
/*int (*access) (const char *, int);*/
EC_BOOL cfuses_access(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mask_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_access: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_INT  == CFUSES_ARG_TYPE(mask_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_access");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    /*mask: R_OK|W_OK|X_OK|F_OK*/
	res = access(CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_INT(mask_arg));
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

/*------------- ignore -------------*/
/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
/*int (*create) (const char *, mode_t, struct fuse_file_info *);*/

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
/*int (*ftruncate) (const char *, off_t, struct fuse_file_info *);*/
EC_BOOL cfuses_ftruncate(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *offset_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          fd;
    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_ftruncate: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_OFFT == CFUSES_ARG_TYPE(offset_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_ftruncate");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	fd = open(CFUSES_ARG_V_CHAR(path_arg), O_WRONLY);
	if(0 > fd)
	{
	    CFUSES_ARG_V_LONG(ret_arg) = -errno;

	    return (EC_TRUE);
	}

	res = ftruncate(fd, CFUSES_ARG_V_OFFT(offset_arg));
	if(0 > res)
	{
	    CFUSES_ARG_V_LONG(ret_arg) = -errno;

	    close(fd);
	    return (EC_TRUE);
	}

	close(fd);
    return (EC_TRUE);
}

/*------------- ignore -------------*/
/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
/*int (*fgetattr) (const char *, struct stat *, struct fuse_file_info *);*/


/*------------- ignore -------------*/
/**
 * Perform POSIX file locking operation
 *
 * The cmd argument will be either F_GETLK, F_SETLK or F_SETLKW.
 *
 * For the meaning of fields in 'struct flock' see the man page
 * for fcntl(2).  The l_whence field will always be set to
 * SEEK_SET.
 *
 * For checking lock ownership, the 'fuse_file_info->owner'
 * argument must be used.
 *
 * For F_GETLK operation, the library will first check currently
 * held locks, and if a conflicting lock is found it will return
 * information without calling this method.	 This ensures, that
 * for local locks the l_pid field is correctly filled in.	The
 * results may not be accurate in case of race conditions and in
 * the presence of hard links, but it's unlikely that an
 * application would rely on accurate GETLK results in these
 * cases.  If a conflicting lock is not found, this method will be
 * called, and the filesystem may fill out l_pid by a meaningful
 * value, or it may leave this field zero.
 *
 * For F_SETLK and F_SETLKW the l_pid field will be set to the pid
 * of the process performing the locking operation.
 *
 * Note: if this method is not implemented, the kernel will still
 * allow file locking to work locally.  Hence it is only
 * interesting for network filesystems and similar.
 *
 * Introduced in version 2.6
 */
/*
int (*lock) (const char *, struct fuse_file_info *, int cmd,
	     struct flock *);
*/

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * See the utimensat(2) man page for details.
 *
 * Introduced in version 2.6
 */
/*int (*utimens) (const char *, const struct timespec tv[2]);*/
EC_BOOL cfuses_utimens(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *ts_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_utimens: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_TS   == CFUSES_ARG_TYPE(ts_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_utimens");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, CFUSES_ARG_V_CHAR(path_arg), CFUSES_ARG_V_TS_BOTH(ts_arg), AT_SYMLINK_NOFOLLOW);
	if (0 > res)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

/*------------- ignore -------------*/
/**
 * Map block index within file to block index within device
 *
 * Note: This makes sense only for block device backed filesystems
 * mounted with the 'blkdev' option
 *
 * Introduced in version 2.6
 */
/*int (*bmap) (const char *, size_t blocksize, uint64_t *idx);*/

/**
 * Flag indicating that the filesystem can accept a NULL path
 * as the first argument for the following operations:
 *
 * read, write, flush, release, fsync, readdir, releasedir,
 * fsyncdir, ftruncate, fgetattr, lock, ioctl and poll
 *
 * If this flag is set these operations continue to work on
 * unlinked files even if "-ohard_remove" option was specified.
 */
//unsigned int flag_nullpath_ok:1;

/**
 * Flag indicating that the path need not be calculated for
 * the following operations:
 *
 * read, write, flush, release, fsync, readdir, releasedir,
 * fsyncdir, ftruncate, fgetattr, lock, ioctl and poll
 *
 * Closely related to flag_nullpath_ok, but if this flag is
 * set then the path will not be calculaged even if the file
 * wasn't unlinked.  However the path can still be non-NULL if
 * it needs to be calculated for some other reason.
 */
//unsigned int flag_nopath:1;

/**
 * Flag indicating that the filesystem accepts special
 * UTIME_NOW and UTIME_OMIT values in its utimens operation.
 */
//unsigned int flag_utime_omit_ok:1;

/**
 * Reserved flags, don't set
 */
//unsigned int flag_reserved:29;

/*------------- ignore -------------*/
/**
 * Ioctl
 *
 * flags will have FUSE_IOCTL_COMPAT set for 32bit ioctls in
 * 64bit environment.  The size and direction of data is
 * determined by _IOC_*() decoding of cmd.  For _IOC_NONE,
 * data will be NULL, for _IOC_WRITE data is out area, for
 * _IOC_READ in area and if both are set in/out area.  In all
 * non-NULL cases, the area is of _IOC_SIZE(cmd) bytes.
 *
 * If flags has FUSE_IOCTL_DIR then the fuse_file_info refers to a
 * directory file handle.
 *
 * Introduced in version 2.8
 */
/*
int (*ioctl) (const char *, int cmd, void *arg,
	      struct fuse_file_info *, unsigned int flags, void *data);
*/

/*------------- ignore -------------*/
/**
 * Poll for IO readiness events
 *
 * Note: If ph is non-NULL, the client should notify
 * when IO readiness events occur by calling
 * fuse_notify_poll() with the specified ph.
 *
 * Regardless of the number of times poll with a non-NULL ph
 * is received, single notification is enough to clear all.
 * Notifying more times incurs overhead but doesn't harm
 * correctness.
 *
 * The callee is responsible for destroying ph with
 * fuse_pollhandle_destroy() when no longer in use.
 *
 * Introduced in version 2.8
 */
/*
int (*poll) (const char *, struct fuse_file_info *,
	     struct fuse_pollhandle *ph, unsigned *reventsp);
*/

/*------------- ignore -------------*/
/** Write contents of buffer to an open file
 *
 * Similar to the write() method, but data is supplied in a
 * generic buffer.  Use fuse_buf_copy() to transfer data to
 * the destination.
 *
 * Introduced in version 2.9
 */
/*
int (*write_buf) (const char *, struct fuse_bufvec *buf, off_t off,
		  struct fuse_file_info *);
*/

/*------------- ignore -------------*/
/** Store data from an open file in a buffer
 *
 * Similar to the read() method, but data is stored and
 * returned in a generic buffer.
 *
 * No actual copying of data has to take place, the source
 * file descriptor may simply be stored in the buffer for
 * later data transfer.
 *
 * The buffer must be allocated dynamically and stored at the
 * location pointed to by bufp.  If the buffer contains memory
 * regions, they too must be allocated using malloc().  The
 * allocated memory will be freed by the caller.
 *
 * Introduced in version 2.9
 */
/*
int (*read_buf) (const char *, struct fuse_bufvec **bufp,
		 size_t size, off_t off, struct fuse_file_info *);
*/

/*------------- ignore -------------*/
/**
 * Perform BSD file locking operation
 *
 * The op argument will be either LOCK_SH, LOCK_EX or LOCK_UN
 *
 * Nonblocking requests will be indicated by ORing LOCK_NB to
 * the above operations
 *
 * For more information see the flock(2) manual page.
 *
 * Additionally fi->owner will be set to a value unique to
 * this open file.  This same value will be supplied to
 * ->release() when the file is released.
 *
 * Note: if this method is not implemented, the kernel will still
 * allow file locking to work locally.  Hence it is only
 * interesting for network filesystems and similar.
 *
 * Introduced in version 2.9
 */
/*
int (*flock) (const char *, struct fuse_file_info *, int op);
*/


/**
 * Allocates space for an open file
 *
 * This function ensures that required space is allocated for specified
 * file.  If this function returns success then any subsequent write
 * request to specified range is guaranteed not to fail because of lack
 * of space on the file system media.
 *
 * Introduced in version 2.9.1
 */
/*
int (*fallocate) (const char *, int, off_t, off_t,
		  struct fuse_file_info *);
*/
EC_BOOL cfuses_fallocate(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, const CFUSES_ARG *mode_arg, const CFUSES_ARG *offset_arg, const CFUSES_ARG *length_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;

    int          res;
    int          fd;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_fallocate: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_INT  == CFUSES_ARG_TYPE(mode_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_OFFT == CFUSES_ARG_TYPE(offset_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_OFFT == CFUSES_ARG_TYPE(length_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_fallocate");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

	if (CFUSES_ARG_V_MODE(mode_arg))
	{
	    CFUSES_ARG_V_LONG(ret_arg) = -EOPNOTSUPP;

	    return (EC_TRUE);
	}

	fd = open(CFUSES_ARG_V_CHAR(path_arg), O_WRONLY);
	if(0 > fd)
	{
	    CFUSES_ARG_V_LONG(ret_arg) = -errno;

	    return (EC_TRUE);
	}


    /*ENOSUP*/
	res = -posix_fallocate(fd,
	                       CFUSES_ARG_V_OFFT(offset_arg),
	                       CFUSES_ARG_V_OFFT(length_arg));
    CFUSES_ARG_V_LONG(ret_arg) = res;

	close(fd);
    return (EC_TRUE);
}

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
/*note: buf_arg: IO, struct fuse_dh*/
/*note: filler_arg: for test only*/
EC_BOOL cfuses_readdir(const UINT32 cfuses_md_id, const CFUSES_ARG *path_arg, CFUSES_ARG *buf_arg, const CFUSES_ARG *filler_arg/*for test only*/, const CFUSES_ARG *offset_arg, const CFUSES_ARG *flags_arg, CFUSES_ARG *ret_arg)
{
    CFUSES_MD   *cfuses_md;
    DIR         *dp;

    enum fuse_readdir_flags flags;
    fuse_fill_dir_t         filler;

#if (SWITCH_ON == CFUSES_DEBUG_SWITCH)
    if ( CFUSES_MD_ID_CHECK_INVALID(cfuses_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cfuses_readdir: cfuses module #%ld not started.\n",
                cfuses_md_id);
        cfuses_print_module_status(cfuses_md_id, LOGSTDOUT);
        dbg_exit(MD_CFUSES, cfuses_md_id);
    }
#endif/*(SWITCH_ON == CFUSES_DEBUG_SWITCH)*/

    CFUSES_ASSERT(CFUSES_ARG_TYPE_CHAR    == CFUSES_ARG_TYPE(path_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_FUSE_DH == CFUSES_ARG_TYPE(buf_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG    == CFUSES_ARG_TYPE(filler_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_OFFT    == CFUSES_ARG_TYPE(offset_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_INT     == CFUSES_ARG_TYPE(flags_arg));
    CFUSES_ASSERT(CFUSES_ARG_TYPE_LONG    == CFUSES_ARG_TYPE(ret_arg));

    CFUSES_DEBUG_ENTER("cfuses_readdir");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);


    (void)cfuses_md;

    CFUSES_ARG_V_LONG(ret_arg) = 0;

    flags = CFUSES_ARG_V_INT(flags_arg);

    /*for debug only!!!!*/
    filler = (fuse_fill_dir_t)(uintptr_t)CFUSES_ARG_V_LONG(filler_arg);
    CFUSES_ASSERT(NULL_PTR != filler);

    dp = opendir(CFUSES_ARG_V_CHAR(path_arg));
    if(NULL_PTR == dp)
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    seekdir(dp, CFUSES_ARG_V_OFFT(offset_arg) - 1);

    while(1)
    {
        struct dirent              *entry;
        struct stat                 st;
        off_t                       nextoff;
        enum fuse_fill_dir_flags    fill_flags;

        fill_flags = 0;

        entry = readdir(dp);
        if(NULL_PTR == entry)
        {
            break;
        }

		if(flags & FUSE_READDIR_PLUS)
		{
			if(-1 != fstatat(dirfd(dp), entry->d_name, &st, AT_SYMLINK_NOFOLLOW))
			{
				fill_flags |= FUSE_FILL_DIR_PLUS;
            }
		}

		if(!(fill_flags & FUSE_FILL_DIR_PLUS))
		{
			memset(&st, 0, sizeof(st));
			st.st_ino  = entry->d_ino;
			st.st_mode = entry->d_type << 12;
		}

		nextoff = telldir(dp);
        if(filler(CFUSES_ARG_V_FUSE_DH(buf_arg), entry->d_name, &st, nextoff, fill_flags))
        {
			break;
		}
    }

    if(0 != closedir(dp))
    {
        CFUSES_ARG_V_LONG(ret_arg) = -errno;

        return (EC_TRUE);
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

