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

#if (SWITCH_ON == FUSE_SWITCH)

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
#define CFUSES_DEBUG_CWD(func_name)   \
    dbg_log(SEC_0024_CFUSES, 9)(LOGSTDOUT, "[DEBUG] " func_name ": cwd: %s\n", c_get_cwd())
#define CFUSES_DEBUG_ENTER(func_name) \
    CFUSES_DEBUG_CWD(func_name);    \
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
UINT32 cfuses_start(const CSTRING *mount_point)
{
    CFUSES_MD       *cfuses_md;
    UINT32           cfuses_md_id;

    cbc_md_reg(MD_CFUSES, 16);

    cfuses_md_id = cbc_md_new(MD_CFUSES, sizeof(CFUSES_MD));
    if(CMPI_ERROR_MODI == cfuses_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CFUSES module */
    cfuses_md = (CFUSES_MD *)cbc_md_get(MD_CFUSES, cfuses_md_id);
    cfuses_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CFUSES_MD_MOUNT_POINT(cfuses_md) = cstring_dup(mount_point);
    if(NULL_PTR == CFUSES_MD_MOUNT_POINT(cfuses_md))
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_start: "
                                               "dup mount point %s failed\n",
                                               (char *)cstring_get_str(mount_point));
        cbc_md_free(MD_CFUSES, cfuses_md_id);
        return (CMPI_ERROR_MODI);
    }

    cfuses_md->usedcounter = 1;

    cfused_start();

    if(0 != chroot((char *)CFUSES_MD_MOUNT_POINT_STR(cfuses_md)))
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_start: "
                                               "chroot to '%s' failed, "
                                               "errno = %d, errstr = %s\n",
                                               (char *)CFUSES_MD_MOUNT_POINT_STR(cfuses_md),
                                               errno, strerror(errno));

        cfuses_end(cfuses_md_id);

        return (CMPI_ERROR_MODI);
    }

    dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "[DEBUG] cfuses_start: "
                                           "chroot to '%s' done\n",
                                           (char *)CFUSES_MD_MOUNT_POINT_STR(cfuses_md));

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

    cfused_end();

    /* free module : */
    //cfuses_free_module_static_mem(cfuses_md_id);

    if(NULL_PTR != CFUSES_MD_MOUNT_POINT(cfuses_md))
    {
        cstring_free(CFUSES_MD_MOUNT_POINT(cfuses_md));
        CFUSES_MD_MOUNT_POINT(cfuses_md) = NULL_PTR;
    }

    cfuses_md->usedcounter = 0;

    cbc_md_free(MD_CFUSES, cfuses_md_id);

    dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "[DEBUG] cfuses_end: "
                                           "stop CFUSES module #%ld\n",
                                           cfuses_md_id);

    return ;
}

EC_BOOL cfuses_getattr(const UINT32 cfuses_md_id, const CSTRING *path, struct stat *stat, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_getattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = lstat((char *)cstring_get_str(path), stat);
    if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_readlink(const UINT32 cfuses_md_id, const CSTRING *path, CSTRING *buf, const UINT32 bufsize, int *res)
{
    CFUSES_MD   *cfuses_md;
    char        *data;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_readlink");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    data = safe_calloc(bufsize, LOC_CFUSES_0001);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_readlink: "
                                               "malloc %ld failed\n",
                                               bufsize);
        (*res) = -ENOMEM;
        return (EC_TRUE);
    }

	ret = readlink((char *)cstring_get_str(path), data, bufsize - 1);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;

	data[ ret ] = '\0';

	cstring_set_str(buf, (const UINT8 *)data);

    return (EC_TRUE);
}

EC_BOOL cfuses_mknod(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, const UINT32 dev, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_mknod");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = mknod((char *)cstring_get_str(path), (mode_t)mode, (dev_t)dev);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_mkdir(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_mkdir");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = mkdir((char *)cstring_get_str(path), (mode_t)mode);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_unlink(const UINT32 cfuses_md_id, const CSTRING *path, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_unlink");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = unlink((char *)cstring_get_str(path));
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_rmdir(const UINT32 cfuses_md_id, const CSTRING *path, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_rmdir");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = rmdir((char *)cstring_get_str(path));
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_symlink(const UINT32 cfuses_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_symlink");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = symlink((char *)cstring_get_str(from_path),
	              (char *)cstring_get_str(to_path));
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_rename(const UINT32 cfuses_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_rename");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = rename((char *)cstring_get_str(from_path),
	             (char *)cstring_get_str(to_path));
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_link(const UINT32 cfuses_md_id, const CSTRING *from_path, const CSTRING *to_path, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_link");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = link((char *)cstring_get_str(from_path),
	           (char *)cstring_get_str(to_path));
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_chmod(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_chmod");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = chmod((char *)cstring_get_str(path), (mode_t)mode);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_chown(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 owner, const UINT32 group, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_chown");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = lchown((char *)cstring_get_str(path),
                 (uid_t)owner,
                 (gid_t)group);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_truncate(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 length, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_truncate");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = truncate((char *)cstring_get_str(path), (off_t)length);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_utime(const UINT32 cfuses_md_id, const CSTRING *path, const struct utimbuf *times, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_utime");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = utime((char *)cstring_get_str(path), times);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_open(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 flags, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          fd;

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

    CFUSES_DEBUG_ENTER("cfuses_open");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

	fd = open((char *)cstring_get_str(path), (int)flags);
	if(0 > fd)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;

    close(fd);

    return (EC_TRUE);
}

EC_BOOL cfuses_read(const UINT32 cfuses_md_id, const CSTRING *path, CBYTES *buf, const UINT32 size, const UINT32 offset, int *res)
{
    CFUSES_MD   *cfuses_md;
    void        *data;
    ssize_t      ret;
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

    CFUSES_DEBUG_ENTER("cfuses_read");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

	fd = open((char *)cstring_get_str(path), O_RDONLY);
	if(0 > fd)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    data = safe_malloc(size, LOC_CFUSES_0002);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_read: "
                                               "malloc %ld failed\n",
                                               size);

        (*res) = -ENOMEM;

        close(fd);

        return (EC_TRUE);
    }

	ret = pread(fd, data, (size_t)size, (off_t)offset);
	if(0 > ret)
    {
        (*res) = -errno;

        close(fd);

        safe_free(data, LOC_CFUSES_0003);
        return (EC_TRUE);
    }

    (*res) = ret;

    cbytes_mount(buf, (UINT32)ret, data, BIT_FALSE);

	close(fd);
    return (EC_TRUE);
}

EC_BOOL cfuses_write(const UINT32 cfuses_md_id, const CSTRING *path, const CBYTES *buf, const UINT32 offset, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;
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

    CFUSES_DEBUG_ENTER("cfuses_write");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

	fd = open((char *)cstring_get_str(path), O_WRONLY);
	if(0 > fd)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

	ret = pwrite(fd, (void *)CBYTES_BUF(buf), (size_t)CBYTES_LEN(buf), (off_t)offset);
	if(0 > ret)
    {
        (*res) = -errno;

        close(fd);
        return (EC_TRUE);
    }

    (*res) = ret;

	close(fd);
    return (EC_TRUE);
}

EC_BOOL cfuses_statfs(const UINT32 cfuses_md_id, const CSTRING *path, struct statvfs *statfs, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_statfs");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = statvfs((char *)cstring_get_str(path), statfs);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_flush(const UINT32 cfuses_md_id, const CSTRING *path, int *res)
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

    CFUSES_DEBUG_ENTER("cfuses_flush");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    (*res) = 0;

    /*do nothing*/

    return (EC_TRUE);
}

EC_BOOL cfuses_release(const UINT32 cfuses_md_id, const CSTRING *path, int *res)
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

    CFUSES_DEBUG_ENTER("cfuses_release");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    (*res) = 0;

    /*do nothing*/

    return (EC_TRUE);
}

EC_BOOL cfuses_fsync(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 datasync, int *res)
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

    CFUSES_DEBUG_ENTER("cfuses_fsync");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    (*res) = 0;

    /*do nothing*/

    return (EC_TRUE);
}

EC_BOOL cfuses_setxattr(const UINT32 cfuses_md_id, const CSTRING *path, const CSTRING *name, const CBYTES *value, const UINT32 flags, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_setxattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    /*ENOTSUP*/
    ret = lsetxattr((char *)cstring_get_str(path),
	                (char *)cstring_get_str(name),
	                (char *)CBYTES_BUF(value),
	                (size_t)CBYTES_LEN(value),
	                (int   )flags);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_getxattr(const UINT32 cfuses_md_id, const CSTRING *path, const CSTRING *name, CBYTES *value, const UINT32 size, int *res)
{
    CFUSES_MD   *cfuses_md;
    void        *data;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_getxattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    data = safe_calloc(size, LOC_CFUSES_0004);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_getxattr: "
                                               "malloc %ld failed\n",
                                               size);

        (*res) = -ENOMEM;
        return (EC_TRUE);
    }

    /*ENOTSUP*/
    ret = lgetxattr((char *)cstring_get_str(path),
	                (char *)cstring_get_str(name),
	                (void *)data,
	                (size_t)size);
	if(0 > ret)
    {
        (*res) = -errno;

        safe_free(data, LOC_CFUSES_0005);
        return (EC_TRUE);
    }

    (*res) = 0;

    cbytes_mount(value, (UINT32)(*res), data, BIT_FALSE);

    return (EC_TRUE);
}

EC_BOOL cfuses_listxattr(const UINT32 cfuses_md_id, const CSTRING *path, CBYTES *value_list, const UINT32 size, int *res)
{
    CFUSES_MD   *cfuses_md;
    void        *data;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_listxattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    data = safe_calloc(size, LOC_CFUSES_0006);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_listxattr: "
                                               "malloc %ld failed\n",
                                               size);

        (*res) = -ENOMEM;
        return (EC_TRUE);
    }

    ret = llistxattr((char *)cstring_get_str(path),
  	                  (char *)data,
  	                  (size_t)size);
	if(0 > ret)
    {
        (*res) = -errno;
        safe_free(data, LOC_CFUSES_0007);
        return (EC_TRUE);
    }

    (*res) = 0;

    cbytes_mount(value_list, (UINT32)(*res), data, BIT_FALSE);

    return (EC_TRUE);
}

EC_BOOL cfuses_removexattr(const UINT32 cfuses_md_id, const CSTRING *path, const CSTRING *name, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_removexattr");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    ret = lremovexattr((char *)cstring_get_str(path),
	                   (char *)cstring_get_str(name));
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_access(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mask, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

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

    CFUSES_DEBUG_ENTER("cfuses_access");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    /*mask: R_OK|W_OK|X_OK|F_OK*/
    ret = access((char *)cstring_get_str(path), (int)mask);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_ftruncate(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 offset, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;
    int          fd;

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

    CFUSES_DEBUG_ENTER("cfuses_ftruncate");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

	fd = open((char *)cstring_get_str(path), O_WRONLY);
	if(0 > fd)
	{
	    (*res) = -errno;
	    return (EC_TRUE);
	}

    ret = ftruncate(fd, (off_t)offset);
	if(0 > ret)
	{
	    (*res) = -errno;

	    close(fd);
	    return (EC_TRUE);
	}

	(*res) = 0;

	close(fd);
    return (EC_TRUE);
}

EC_BOOL cfuses_utimens(const UINT32 cfuses_md_id, const CSTRING *path, const struct timespec *tv0, const struct timespec *tv1, int *res)
{
    CFUSES_MD   *cfuses_md;
    int          ret;

    struct timespec tv[2];

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

    CFUSES_DEBUG_ENTER("cfuses_utimens");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    tv[0] = *tv0;
    tv[1] = *tv1;

	/* don't use utime/utimes since they follow symlinks */
	ret = utimensat(0, (char *)cstring_get_str(path), tv, AT_SYMLINK_NOFOLLOW);
	if(0 > ret)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

EC_BOOL cfuses_fallocate(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 mode, const UINT32 offset, const UINT32 length, int *res)
{
    CFUSES_MD   *cfuses_md;
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

    CFUSES_DEBUG_ENTER("cfuses_fallocate");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

	if((int)mode)
	{
	    (*res) = -EOPNOTSUPP;
	    return (EC_TRUE);
	}

	fd = open((char *)cstring_get_str(path), O_WRONLY);
	if(0 > fd)
	{
	    (*res) = -errno;
	    return (EC_TRUE);
	}

    /*ENOSUP*/
	(*res) = -posix_fallocate(fd, (off_t)offset, (off_t)length);
	/*note: no errno is set*/

	close(fd);
    return (EC_TRUE);
}

EC_BOOL cfuses_readdir(const UINT32 cfuses_md_id, const CSTRING *path, const UINT32 offset, const UINT32 flags, CLIST *dirnode_list, int *res)
{
    CFUSES_MD   *cfuses_md;
    DIR         *dp;

    enum fuse_readdir_flags flags_t;

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

    CFUSES_DEBUG_ENTER("cfuses_readdir");

    cfuses_md = CFUSES_MD_GET(cfuses_md_id);
    (void)cfuses_md;

    flags_t = (enum fuse_readdir_flags)flags;

    clist_codec_set(dirnode_list, MM_DIRNODE);

    dp = opendir((char *)cstring_get_str(path));
    if(NULL_PTR == dp)
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    /*note: void seekdir(DIR *dirp, long loc);*/
    seekdir(dp, (off_t)offset);

    while(1)
    {
        struct dirent              *entry;
        struct dirnode             *dirnode;

        entry = readdir(dp);
        if(NULL_PTR == entry)
        {
            break;
        }

        dirnode = c_dirnode_new();
        if(NULL_PTR == dirnode)
        {
            dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_readdir: "
                                                   "new dirnode failed\n");
            break;
        }

        dirnode->flags = 0; /*enum fuse_fill_dir_flags*/

        if(NULL_PTR != entry->d_name)
        {
            dirnode->name = c_str_dup(entry->d_name);
            if(NULL_PTR == dirnode->name)
            {
                dbg_log(SEC_0024_CFUSES, 0)(LOGSTDOUT, "error:cfuses_readdir: "
                                                       "dup d_name '%s' failed\n",
                                                       entry->d_name);
                c_dirnode_free(dirnode);
                break;
            }
        }

		if(flags_t & FUSE_READDIR_PLUS)
		{
			if(-1 != fstatat(dirfd(dp), entry->d_name, &(dirnode->stat), AT_SYMLINK_NOFOLLOW))
			{
				dirnode->flags |= FUSE_FILL_DIR_PLUS;
            }
		}

		if(!(dirnode->flags & FUSE_FILL_DIR_PLUS))
		{
			dirnode->stat.st_ino  = entry->d_ino;
			dirnode->stat.st_mode = entry->d_type << 12;
		}

		dirnode->offset = telldir(dp);

		clist_push_back(dirnode_list, (void *)dirnode);

        dbg_log(SEC_0024_CFUSES, 9)(LOGSTDOUT, "[DEBUG] cfuses_readdir: "
                                               "push (name %s, offset %ld, flags %u)\n",
                                               dirnode->name,
                                               dirnode->offset,
                                               dirnode->flags);
    }

    if(0 != closedir(dp))
    {
        (*res) = -errno;
        return (EC_TRUE);
    }

    (*res) = 0;
    return (EC_TRUE);
}

#endif/*(SWITCH_ON == FUSE_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

