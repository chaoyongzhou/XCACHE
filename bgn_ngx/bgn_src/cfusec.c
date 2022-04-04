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
#include <sys/ioctl.h>

#include <linux/xattr.h>
#include <x86_64-linux-gnu/sys/xattr.h>

#include <fuse.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cbc.h"
#include "cmisc.h"
#include "task.h"

#include "cfusec.h"
#include "cfuses.h"
#include "cfused.h"

#include "findex.inc"

/*----------------------------------------------------------------------------*\
 *                             CFUSE CLIENT                                   *
\*----------------------------------------------------------------------------*/

#define CFUSEC_ASSERT(cond)     ASSERT(cond)

#define CFUSEC_DEBUG_ENTER(func_name) \
    dbg_log(SEC_0031_CFUSEC, 9)(LOGSTDOUT, "[DEBUG] " func_name ": enter\n")

#define CFUSEC_DEBUG_LEAVE(func_name) \
    dbg_log(SEC_0031_CFUSEC, 9)(LOGSTDOUT, "[DEBUG] " func_name ": leave\n")

#define CFUSEC_DEBUG_INIT(param)    cfuses_arg_init(param)
#define CFUSEC_DEBUG_CLEAN(param)   cfuses_arg_clean(param)

static struct fuse_operations g_cfusec_op;
static EC_BOOL  g_cfuses_mod_node_init_flag = EC_FALSE;
static MOD_NODE g_cfuses_mod_node;

#if 0
/** Major version of FUSE library interface */
#define FUSE_MAJOR_VERSION 3

/** Minor version of FUSE library interface */
#define FUSE_MINOR_VERSION 10

struct fuse_operations {
	/** Get file attributes.
	 *
	 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
	 * ignored. The 'st_ino' field is ignored except if the 'use_ino'
	 * mount option is given. In that case it is passed to userspace,
	 * but libfuse and the kernel will still assign a different
	 * inode for internal use (called the "nodeid").
	 *
	 * `fi` will always be NULL if the file is not currently open, but
	 * may also be NULL if the file is open.
	 */
	int (*getattr) (const char *, struct stat *, struct fuse_file_info *fi);

	/** Read the target of a symbolic link
	 *
	 * The buffer should be filled with a null terminated string.  The
	 * buffer size argument includes the space for the terminating
	 * null character.	If the linkname is too long to fit in the
	 * buffer, it should be truncated.	The return value should be 0
	 * for success.
	 */
	int (*readlink) (const char *, char *, size_t);

	/** Create a file node
	 *
	 * This is called for creation of all non-directory, non-symlink
	 * nodes.  If the filesystem defines a create() method, then for
	 * regular files that will be called instead.
	 */
	int (*mknod) (const char *, mode_t, dev_t);

	/** Create a directory
	 *
	 * Note that the mode argument may not have the type specification
	 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
	 * correct directory type bits use  mode|S_IFDIR
	 * */
	int (*mkdir) (const char *, mode_t);

	/** Remove a file */
	int (*unlink) (const char *);

	/** Remove a directory */
	int (*rmdir) (const char *);

	/** Create a symbolic link */
	int (*symlink) (const char *, const char *);

	/** Rename a file
	 *
	 * *flags* may be `RENAME_EXCHANGE` or `RENAME_NOREPLACE`. If
	 * RENAME_NOREPLACE is specified, the filesystem must not
	 * overwrite *newname* if it exists and return an error
	 * instead. If `RENAME_EXCHANGE` is specified, the filesystem
	 * must atomically exchange the two files, i.e. both must
	 * exist and neither may be deleted.
	 */
	int (*rename) (const char *, const char *, unsigned int flags);

	/** Create a hard link to a file */
	int (*link) (const char *, const char *);

	/** Change the permission bits of a file
	 *
	 * `fi` will always be NULL if the file is not currently open, but
	 * may also be NULL if the file is open.
	 */
	int (*chmod) (const char *, mode_t, struct fuse_file_info *fi);

	/** Change the owner and group of a file
	 *
	 * `fi` will always be NULL if the file is not currently open, but
	 * may also be NULL if the file is open.
	 *
	 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
	 * expected to reset the setuid and setgid bits.
	 */
	int (*chown) (const char *, uid_t, gid_t, struct fuse_file_info *fi);

	/** Change the size of a file
	 *
	 * `fi` will always be NULL if the file is not currently open, but
	 * may also be NULL if the file is open.
	 *
	 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
	 * expected to reset the setuid and setgid bits.
	 */
	int (*truncate) (const char *, off_t, struct fuse_file_info *fi);

	/** Open a file
	 *
	 * Open flags are available in fi->flags. The following rules
	 * apply.
	 *
	 *  - Creation (O_CREAT, O_EXCL, O_NOCTTY) flags will be
	 *    filtered out / handled by the kernel.
	 *
	 *  - Access modes (O_RDONLY, O_WRONLY, O_RDWR, O_EXEC, O_SEARCH)
	 *    should be used by the filesystem to check if the operation is
	 *    permitted.  If the ``-o default_permissions`` mount option is
	 *    given, this check is already done by the kernel before calling
	 *    open() and may thus be omitted by the filesystem.
	 *
	 *  - When writeback caching is enabled, the kernel may send
	 *    read requests even for files opened with O_WRONLY. The
	 *    filesystem should be prepared to handle this.
	 *
	 *  - When writeback caching is disabled, the filesystem is
	 *    expected to properly handle the O_APPEND flag and ensure
	 *    that each write is appending to the end of the file.
	 *
	 *  - When writeback caching is enabled, the kernel will
	 *    handle O_APPEND. However, unless all changes to the file
	 *    come through the kernel this will not work reliably. The
	 *    filesystem should thus either ignore the O_APPEND flag
	 *    (and let the kernel handle it), or return an error
	 *    (indicating that reliably O_APPEND is not available).
	 *
	 * Filesystem may store an arbitrary file handle (pointer,
	 * index, etc) in fi->fh, and use this in other all other file
	 * operations (read, write, flush, release, fsync).
	 *
	 * Filesystem may also implement stateless file I/O and not store
	 * anything in fi->fh.
	 *
	 * There are also some flags (direct_io, keep_cache) which the
	 * filesystem may set in fi, to change the way the file is opened.
	 * See fuse_file_info structure in <fuse_common.h> for more details.
	 *
	 * If this request is answered with an error code of ENOSYS
	 * and FUSE_CAP_NO_OPEN_SUPPORT is set in
	 * `fuse_conn_info.capable`, this is treated as success and
	 * future calls to open will also succeed without being send
	 * to the filesystem process.
	 *
	 */
	int (*open) (const char *, struct fuse_file_info *);

	/** Read data from an open file
	 *
	 * Read should return exactly the number of bytes requested except
	 * on EOF or error, otherwise the rest of the data will be
	 * substituted with zeroes.	 An exception to this is when the
	 * 'direct_io' mount option is specified, in which case the return
	 * value of the read system call will reflect the return value of
	 * this operation.
	 */
	int (*read) (const char *, char *, size_t, off_t,
		     struct fuse_file_info *);

	/** Write data to an open file
	 *
	 * Write should return exactly the number of bytes requested
	 * except on error.	 An exception to this is when the 'direct_io'
	 * mount option is specified (see read operation).
	 *
	 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
	 * expected to reset the setuid and setgid bits.
	 */
	int (*write) (const char *, const char *, size_t, off_t,
		      struct fuse_file_info *);

	/** Get file system statistics
	 *
	 * The 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
	 */
	int (*statfs) (const char *, struct statvfs *);

	/** Possibly flush cached data
	 *
	 * BIG NOTE: This is not equivalent to fsync().  It's not a
	 * request to sync dirty data.
	 *
	 * Flush is called on each close() of a file descriptor, as opposed to
	 * release which is called on the close of the last file descriptor for
	 * a file.  Under Linux, errors returned by flush() will be passed to
	 * userspace as errors from close(), so flush() is a good place to write
	 * back any cached dirty data. However, many applications ignore errors
	 * on close(), and on non-Linux systems, close() may succeed even if flush()
	 * returns an error. For these reasons, filesystems should not assume
	 * that errors returned by flush will ever be noticed or even
	 * delivered.
	 *
	 * NOTE: The flush() method may be called more than once for each
	 * open().  This happens if more than one file descriptor refers to an
	 * open file handle, e.g. due to dup(), dup2() or fork() calls.  It is
	 * not possible to determine if a flush is final, so each flush should
	 * be treated equally.  Multiple write-flush sequences are relatively
	 * rare, so this shouldn't be a problem.
	 *
	 * Filesystems shouldn't assume that flush will be called at any
	 * particular point.  It may be called more times than expected, or not
	 * at all.
	 *
	 * [close]: http://pubs.opengroup.org/onlinepubs/9699919799/functions/close.html
	 */
	int (*flush) (const char *, struct fuse_file_info *);

	/** Release an open file
	 *
	 * Release is called when there are no more references to an open
	 * file: all file descriptors are closed and all memory mappings
	 * are unmapped.
	 *
	 * For every open() call there will be exactly one release() call
	 * with the same flags and file handle.  It is possible to
	 * have a file opened more than once, in which case only the last
	 * release will mean, that no more reads/writes will happen on the
	 * file.  The return value of release is ignored.
	 */
	int (*release) (const char *, struct fuse_file_info *);

	/** Synchronize file contents
	 *
	 * If the datasync parameter is non-zero, then only the user data
	 * should be flushed, not the meta data.
	 */
	int (*fsync) (const char *, int, struct fuse_file_info *);

	/** Set extended attributes */
	int (*setxattr) (const char *, const char *, const char *, size_t, int);

	/** Get extended attributes */
	int (*getxattr) (const char *, const char *, char *, size_t);

	/** List extended attributes */
	int (*listxattr) (const char *, char *, size_t);

	/** Remove extended attributes */
	int (*removexattr) (const char *, const char *);

	/** Open directory
	 *
	 * Unless the 'default_permissions' mount option is given,
	 * this method should check if opendir is permitted for this
	 * directory. Optionally opendir may also return an arbitrary
	 * filehandle in the fuse_file_info structure, which will be
	 * passed to readdir, releasedir and fsyncdir.
	 */
	int (*opendir) (const char *, struct fuse_file_info *);

	/** Read directory
	 *
	 * The filesystem may choose between two modes of operation:
	 *
	 * 1) The readdir implementation ignores the offset parameter, and
	 * passes zero to the filler function's offset.  The filler
	 * function will not return '1' (unless an error happens), so the
	 * whole directory is read in a single readdir operation.
	 *
	 * 2) The readdir implementation keeps track of the offsets of the
	 * directory entries.  It uses the offset parameter and always
	 * passes non-zero offset to the filler function.  When the buffer
	 * is full (or an error happens) the filler function will return
	 * '1'.
	 */
	int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t,
			struct fuse_file_info *, enum fuse_readdir_flags);

	/** Release directory
	 */
	int (*releasedir) (const char *, struct fuse_file_info *);

	/** Synchronize directory contents
	 *
	 * If the datasync parameter is non-zero, then only the user data
	 * should be flushed, not the meta data
	 */
	int (*fsyncdir) (const char *, int, struct fuse_file_info *);

	/**
	 * Initialize filesystem
	 *
	 * The return value will passed in the `private_data` field of
	 * `struct fuse_context` to all file operations, and as a
	 * parameter to the destroy() method. It overrides the initial
	 * value provided to fuse_main() / fuse_new().
	 */
	void *(*init) (struct fuse_conn_info *conn,
		       struct fuse_config *cfg);

	/**
	 * Clean up filesystem
	 *
	 * Called on filesystem exit.
	 */
	void (*destroy) (void *private_data);

	/**
	 * Check file access permissions
	 *
	 * This will be called for the access() system call.  If the
	 * 'default_permissions' mount option is given, this method is not
	 * called.
	 *
	 * This method is not called under Linux kernel versions 2.4.x
	 */
	int (*access) (const char *, int);

	/**
	 * Create and open a file
	 *
	 * If the file does not exist, first create it with the specified
	 * mode, and then open it.
	 *
	 * If this method is not implemented or under Linux kernel
	 * versions earlier than 2.6.15, the mknod() and open() methods
	 * will be called instead.
	 */
	int (*create) (const char *, mode_t, struct fuse_file_info *);

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
	 */
	int (*lock) (const char *, struct fuse_file_info *, int cmd,
		     struct flock *);

	/**
	 * Change the access and modification times of a file with
	 * nanosecond resolution
	 *
	 * This supersedes the old utime() interface.  New applications
	 * should use this.
	 *
	 * `fi` will always be NULL if the file is not currently open, but
	 * may also be NULL if the file is open.
	 *
	 * See the utimensat(2) man page for details.
	 */
	 int (*utimens) (const char *, const struct timespec tv[2],
			 struct fuse_file_info *fi);

	/**
	 * Map block index within file to block index within device
	 *
	 * Note: This makes sense only for block device backed filesystems
	 * mounted with the 'blkdev' option
	 */
	int (*bmap) (const char *, size_t blocksize, uint64_t *idx);

#if FUSE_USE_VERSION < 35
	int (*ioctl) (const char *, int cmd, void *arg,
		      struct fuse_file_info *, unsigned int flags, void *data);
#else
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
	 * Note : the unsigned long request submitted by the application
	 * is truncated to 32 bits.
	 */
	int (*ioctl) (const char *, unsigned int cmd, void *arg,
		      struct fuse_file_info *, unsigned int flags, void *data);
#endif

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
	 */
	int (*poll) (const char *, struct fuse_file_info *,
		     struct fuse_pollhandle *ph, unsigned *reventsp);

	/** Write contents of buffer to an open file
	 *
	 * Similar to the write() method, but data is supplied in a
	 * generic buffer.  Use fuse_buf_copy() to transfer data to
	 * the destination.
	 *
	 * Unless FUSE_CAP_HANDLE_KILLPRIV is disabled, this method is
	 * expected to reset the setuid and setgid bits.
	 */
	int (*write_buf) (const char *, struct fuse_bufvec *buf, off_t off,
			  struct fuse_file_info *);

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
	 */
	int (*read_buf) (const char *, struct fuse_bufvec **bufp,
			 size_t size, off_t off, struct fuse_file_info *);
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
	 */
	int (*flock) (const char *, struct fuse_file_info *, int op);

	/**
	 * Allocates space for an open file
	 *
	 * This function ensures that required space is allocated for specified
	 * file.  If this function returns success then any subsequent write
	 * request to specified range is guaranteed not to fail because of lack
	 * of space on the file system media.
	 */
	int (*fallocate) (const char *, int, off_t, off_t,
			  struct fuse_file_info *);

	/**
	 * Copy a range of data from one file to another
	 *
	 * Performs an optimized copy between two file descriptors without the
	 * additional cost of transferring data through the FUSE kernel module
	 * to user space (glibc) and then back into the FUSE filesystem again.
	 *
	 * In case this method is not implemented, applications are expected to
	 * fall back to a regular file copy.   (Some glibc versions did this
	 * emulation automatically, but the emulation has been removed from all
	 * glibc release branches.)
	 */
	ssize_t (*copy_file_range) (const char *path_in,
				    struct fuse_file_info *fi_in,
				    off_t offset_in, const char *path_out,
				    struct fuse_file_info *fi_out,
				    off_t offset_out, size_t size, int flags);

	/**
	 * Find next data or hole after the specified offset
	 */
	off_t (*lseek) (const char *, off_t off, int whence, struct fuse_file_info *);
};
#endif

struct fuse_operations *cfusec_get_ops()
{
    if(EC_FALSE == g_cfuses_mod_node_init_flag)
    {
        return (NULL_PTR);
    }
    return (&g_cfusec_op);
}

/**
*
* start CFUSEC module
*
**/
EC_BOOL cfusec_start(const UINT32 cfuses_tcid, const UINT32 cfuses_rank, const UINT32 cfuses_modi)
{
    if(EC_TRUE == g_cfuses_mod_node_init_flag)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "error:cfusec_start: "
                                               "target cfuses (tcid %ld, rank %ld modi %ld) exist\n",
                                               MOD_NODE_TCID(&g_cfuses_mod_node),
                                               MOD_NODE_RANK(&g_cfuses_mod_node),
                                               MOD_NODE_MODI(&g_cfuses_mod_node));
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&g_cfuses_mod_node) = cfuses_tcid;
    MOD_NODE_COMM(&g_cfuses_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&g_cfuses_mod_node) = cfuses_rank;
    MOD_NODE_MODI(&g_cfuses_mod_node) = cfuses_modi;

#if 1
    BSET(&g_cfusec_op, 0x00, sizeof(g_cfusec_op));
	g_cfusec_op.getattr	        = cfusec_getattr;
	g_cfusec_op.readlink	    = cfusec_readlink;
	g_cfusec_op.mknod           = cfusec_mknod;
	g_cfusec_op.mkdir		    = cfusec_mkdir;
	g_cfusec_op.unlink		    = cfusec_unlink;
	g_cfusec_op.rmdir		    = cfusec_rmdir;
	g_cfusec_op.symlink	        = cfusec_symlink;
	g_cfusec_op.rename		    = cfusec_rename;
	g_cfusec_op.link		    = cfusec_link;
	g_cfusec_op.chmod		    = cfusec_chmod;
	g_cfusec_op.chown		    = cfusec_chown;
	g_cfusec_op.truncate	    = cfusec_truncate;
	g_cfusec_op.open		    = cfusec_open;
	g_cfusec_op.read		    = cfusec_read;
	g_cfusec_op.write		    = cfusec_write;
	g_cfusec_op.statfs		    = cfusec_statfs;
	g_cfusec_op.flush		    = cfusec_flush;
	g_cfusec_op.release	        = cfusec_release;
	g_cfusec_op.fsync		    = cfusec_fsync;
	g_cfusec_op.setxattr	    = cfusec_setxattr;
	g_cfusec_op.getxattr	    = cfusec_getxattr;
	g_cfusec_op.listxattr	    = cfusec_listxattr;
	g_cfusec_op.removexattr	    = cfusec_removexattr;
	g_cfusec_op.opendir         = cfusec_opendir;
	g_cfusec_op.readdir         = cfusec_readdir;
	g_cfusec_op.releasedir      = cfusec_releasedir;
	g_cfusec_op.fsyncdir        = cfusec_fsyncdir;
	g_cfusec_op.access          = cfusec_access;
	g_cfusec_op.create          = NULL_PTR;
	g_cfusec_op.lock            = NULL_PTR;
	g_cfusec_op.utimens         = cfusec_utimens;

	g_cfusec_op.bmap            = NULL_PTR;
	g_cfusec_op.ioctl           = NULL_PTR;
	g_cfusec_op.poll            = NULL_PTR;
	g_cfusec_op.write_buf       = NULL_PTR;
	g_cfusec_op.read_buf        = NULL_PTR;
	g_cfusec_op.flock           = NULL_PTR;
	g_cfusec_op.fallocate       = cfusec_fallocate;
	g_cfusec_op.copy_file_range = NULL_PTR;
	g_cfusec_op.lseek           = NULL_PTR;

#endif

    g_cfuses_mod_node_init_flag = EC_TRUE;

    cfused_start();

    dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_start: "
                                           "set target cfuses (tcid %ld, rank %ld modi %ld)\n",
                                           MOD_NODE_TCID(&g_cfuses_mod_node),
                                           MOD_NODE_RANK(&g_cfuses_mod_node),
                                           MOD_NODE_MODI(&g_cfuses_mod_node));

    return (EC_TRUE);
}

/**
*
* end CFUSEC module
*
**/
void cfusec_end()
{
    if(EC_FALSE == g_cfuses_mod_node_init_flag)
    {
        dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "error:cfusec_end: "
                                               "target cfuses_md_id not exist\n");
        return;
    }

    dbg_log(SEC_0031_CFUSEC, 0)(LOGSTDOUT, "[DEBUG] cfusec_end: "
                                           "unset target cfuses (tcid %ld, rank %ld modi %ld)\n",
                                           MOD_NODE_TCID(&g_cfuses_mod_node),
                                           MOD_NODE_RANK(&g_cfuses_mod_node),
                                           MOD_NODE_MODI(&g_cfuses_mod_node));

    MOD_NODE_TCID(&g_cfuses_mod_node) = CMPI_ERROR_TCID;
    MOD_NODE_COMM(&g_cfuses_mod_node) = CMPI_ERROR_COMM;
    MOD_NODE_RANK(&g_cfuses_mod_node) = CMPI_ERROR_RANK;
    MOD_NODE_MODI(&g_cfuses_mod_node) = CMPI_ERROR_MODI;

    BSET(&g_cfusec_op, 0x00, sizeof(g_cfusec_op));

    g_cfuses_mod_node_init_flag = EC_FALSE;

    cfused_end();

    return ;
}

MOD_NODE *cfuses_get_remote_mod_node()
{
    return &g_cfuses_mod_node;
}

/*int (*getattr) (const char *, struct stat *);*/
int cfusec_getattr(const char *path, struct stat *stat, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      stat_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_getattr");

    (void)fi;

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&stat_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR, (void *)path, strlen(path));
    cfuses_arg_mount(&stat_arg, CFUSES_ARG_TYPE_STAT, (void *)stat, sizeof(struct stat));
    cfuses_arg_mount(&ret_arg , CFUSES_ARG_TYPE_LONG, (void *)   0, sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_getattr, CMPI_ERROR_MODI, &path_arg, &stat_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&stat_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*readlink) (const char *, char *, size_t);*/
int cfusec_readlink(const char *path, char *buf, size_t size)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      buf_arg;
    CFUSES_ARG      size_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_readlink");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&buf_arg);
    CFUSEC_DEBUG_INIT(&size_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&buf_arg , CFUSES_ARG_TYPE_BYTE, (void *)(uintptr_t)buf   , size);
    cfuses_arg_mount(&size_arg, CFUSES_ARG_TYPE_SIZE, (void *)(uintptr_t)size  , sizeof(size_t));
    cfuses_arg_mount(&ret_arg , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_readlink, CMPI_ERROR_MODI, &path_arg, &buf_arg, &size_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);
    if(0 == CFUSES_ARG_V_LONG(&ret_arg))
    {
        STRCOPY(CFUSES_ARG_V_CHAR(&buf_arg), buf);
    }

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&buf_arg);
    CFUSEC_DEBUG_CLEAN(&size_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*mknod)       (const char *, mode_t, dev_t);*/
int cfusec_mknod(const char *path, mode_t mode, dev_t dev)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      mode_arg;
    CFUSES_ARG      dev_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_mknod");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&mode_arg);
    CFUSEC_DEBUG_INIT(&dev_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&mode_arg, CFUSES_ARG_TYPE_MODE, (void *)(uintptr_t)mode  , sizeof(mode_t));
    cfuses_arg_mount(&dev_arg , CFUSES_ARG_TYPE_DEV , (void *)(uintptr_t)dev   , sizeof(dev_t));
    cfuses_arg_mount(&ret_arg , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_mknod, CMPI_ERROR_MODI, &path_arg, &mode_arg, &dev_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&mode_arg);
    CFUSEC_DEBUG_CLEAN(&dev_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*mkdir) (const char *, mode_t);*/
int cfusec_mkdir(const char *path, mode_t mode)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      mode_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_mkdir");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&mode_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&mode_arg, CFUSES_ARG_TYPE_MODE, (void *)(uintptr_t)mode  , sizeof(mode_t));
    cfuses_arg_mount(&ret_arg , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_mkdir, CMPI_ERROR_MODI, &path_arg, &mode_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&mode_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*unlink) (const char *);*/
int cfusec_unlink(const char *path)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_unlink");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&ret_arg , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_unlink, CMPI_ERROR_MODI, &path_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*rmdir) (const char *);*/
int cfusec_rmdir(const char *path)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_rmdir");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&ret_arg , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_rmdir, CMPI_ERROR_MODI, &path_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Create a symbolic link */
/*int (*symlink) (const char *, const char *);*/
int cfusec_symlink(const char *src_path, const char *des_path)
{
    CFUSES_ARG      src_path_arg;
    CFUSES_ARG      des_path_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_symlink");

    CFUSEC_DEBUG_INIT(&src_path_arg);
    CFUSEC_DEBUG_INIT(&des_path_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&src_path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)src_path, strlen(src_path));
    cfuses_arg_mount(&des_path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)des_path, strlen(des_path));
    cfuses_arg_mount(&ret_arg     , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_symlink, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&src_path_arg);
    CFUSEC_DEBUG_CLEAN(&des_path_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*rename) (const char *, const char *, unsigned int flags);*/
int cfusec_rename(const char *src_path, const char *des_path, unsigned int flags /*RENAME_EXCHANGE|RENAME_NOREPLACE*/)
{
    CFUSES_ARG      src_path_arg;
    CFUSES_ARG      des_path_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_rename");

    CFUSEC_DEBUG_INIT(&src_path_arg);
    CFUSEC_DEBUG_INIT(&des_path_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&src_path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)src_path, strlen(src_path));
    cfuses_arg_mount(&des_path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)des_path, strlen(des_path));
    cfuses_arg_mount(&ret_arg     , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_rename, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&src_path_arg);
    CFUSEC_DEBUG_CLEAN(&des_path_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Create a hard link to a file */
/*int (*link) (const char *, const char *);*/
int cfusec_link(const char *src_path, const char *des_path)
{
    CFUSES_ARG      src_path_arg;
    CFUSES_ARG      des_path_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_link");

    CFUSEC_DEBUG_INIT(&src_path_arg);
    CFUSEC_DEBUG_INIT(&des_path_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&src_path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)src_path, strlen(src_path));
    cfuses_arg_mount(&des_path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)des_path, strlen(des_path));
    cfuses_arg_mount(&ret_arg     , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_link, CMPI_ERROR_MODI, &src_path_arg, &des_path_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&src_path_arg);
    CFUSEC_DEBUG_CLEAN(&des_path_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Change the permission bits of a file */
/*int (*chmod) (const char *, mode_t, struct fuse_file_info *fi);*/
int cfusec_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      mode_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_chmod");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&mode_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path, strlen(path));
    cfuses_arg_mount(&mode_arg, CFUSES_ARG_TYPE_MODE, (void *)(uintptr_t)mode, sizeof(mode_t));
    cfuses_arg_mount(&ret_arg , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0   , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_chmod, CMPI_ERROR_MODI, &path_arg, &mode_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&mode_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Change the owner and group of a file */
/*int (*chown) (const char *, uid_t, gid_t);*/
int cfusec_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      owner_arg;
    CFUSES_ARG      group_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_chown");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&owner_arg);
    CFUSEC_DEBUG_INIT(&group_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg, CFUSES_ARG_TYPE_CHAR , (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&owner_arg, CFUSES_ARG_TYPE_UID , (void *)(uintptr_t)owner , sizeof(uid_t));
    cfuses_arg_mount(&group_arg, CFUSES_ARG_TYPE_GID , (void *)(uintptr_t)group , sizeof(gid_t));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_chown, CMPI_ERROR_MODI, &path_arg, &owner_arg, &group_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&owner_arg);
    CFUSEC_DEBUG_CLEAN(&group_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Change the size of a file */
/*int (*truncate) (const char *, off_t);*/
int cfusec_truncate(const char *path, off_t length, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      length_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_truncate");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&length_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg  , CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&length_arg, CFUSES_ARG_TYPE_OFFT, (void *)(uintptr_t)length, sizeof(off_t));
    cfuses_arg_mount(&ret_arg   , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_truncate, CMPI_ERROR_MODI, &path_arg, &length_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&length_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Change the access and/or modification times of a file
 *
 * Deprecated, use utimens() instead.
 */
/*int (*utime) (const char *, struct utimbuf *);*/
int cfusec_utime(const char *path, /*const*/struct utimbuf *times)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      times_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_utime");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&times_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR , (void *)(uintptr_t)path   , strlen(path));
    cfuses_arg_mount(&times_arg, CFUSES_ARG_TYPE_UTIME, (void *)(uintptr_t)times  , sizeof(struct utimbuf));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG , (void *)(uintptr_t)0      , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_utime, CMPI_ERROR_MODI, &path_arg, &times_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&times_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*open) (const char *, struct fuse_file_info *);*/
int cfusec_open(const char *path, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      flags_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;
    int             flags;

    CFUSEC_DEBUG_ENTER("cfusec_open");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&flags_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    if(NULL_PTR != fi)
    {
        flags = fi->flags;
    }
    else
    {
        flags = O_RDONLY;
    }

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&flags_arg, CFUSES_ARG_TYPE_INT , (void *)(uintptr_t)flags , sizeof(int));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_open, CMPI_ERROR_MODI, &path_arg, &flags_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&flags_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*read) (const char *, char *, size_t, off_t, struct fuse_file_info *);*/
int cfusec_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      buf_arg;
    CFUSES_ARG      size_arg;
    CFUSES_ARG      offset_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_read");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&buf_arg);
    CFUSEC_DEBUG_INIT(&size_arg);
    CFUSEC_DEBUG_INIT(&offset_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg  , CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&buf_arg   , CFUSES_ARG_TYPE_BYTE, (void *)(uintptr_t)buf   , size);
    cfuses_arg_mount(&size_arg  , CFUSES_ARG_TYPE_SIZE, (void *)(uintptr_t)size  , sizeof(size_t));
    cfuses_arg_mount(&offset_arg, CFUSES_ARG_TYPE_OFFT, (void *)(uintptr_t)offset, sizeof(off_t));
    cfuses_arg_mount(&ret_arg   , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_read, CMPI_ERROR_MODI, &path_arg, &buf_arg, &size_arg, &offset_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&buf_arg);
    CFUSEC_DEBUG_CLEAN(&size_arg);
    CFUSEC_DEBUG_CLEAN(&offset_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *);*/
int cfusec_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      buf_arg;
    CFUSES_ARG      size_arg;
    CFUSES_ARG      offset_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_write");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&buf_arg);
    CFUSEC_DEBUG_INIT(&size_arg);
    CFUSEC_DEBUG_INIT(&offset_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg  , CFUSES_ARG_TYPE_CHAR, (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&buf_arg   , CFUSES_ARG_TYPE_BYTE, (void *)(uintptr_t)buf   , size);
    cfuses_arg_mount(&size_arg  , CFUSES_ARG_TYPE_SIZE, (void *)(uintptr_t)size  , sizeof(size_t));
    cfuses_arg_mount(&offset_arg, CFUSES_ARG_TYPE_OFFT, (void *)(uintptr_t)offset, sizeof(off_t));
    cfuses_arg_mount(&ret_arg   , CFUSES_ARG_TYPE_LONG, (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_write, CMPI_ERROR_MODI, &path_arg, &buf_arg, &size_arg, &offset_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&buf_arg);
    CFUSEC_DEBUG_CLEAN(&size_arg);
    CFUSEC_DEBUG_CLEAN(&offset_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*statfs) (const char *, struct statvfs *);*/
int cfusec_statfs(const char *path, struct statvfs *statvfs)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      statvfs_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_statfs");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&statvfs_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg   , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path   , strlen(path));
    cfuses_arg_mount(&statvfs_arg, CFUSES_ARG_TYPE_STATVFS, (void *)(uintptr_t)statvfs, sizeof(struct statvfs));
    cfuses_arg_mount(&ret_arg    , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0      , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_statfs, CMPI_ERROR_MODI, &path_arg, &statvfs_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&statvfs_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*flush) (const char *, struct fuse_file_info *);*/
int cfusec_flush(const char *path, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_flush");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg   , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&ret_arg    , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_flush, CMPI_ERROR_MODI, &path_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*release) (const char *, struct fuse_file_info *);*/
int cfusec_release(const char *path, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      flag_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_release");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&flag_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg   , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&flag_arg   , CFUSES_ARG_TYPE_INT    , (void *)(uintptr_t)0     , sizeof(int));
    cfuses_arg_mount(&ret_arg    , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_release, CMPI_ERROR_MODI, &path_arg, &flag_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&flag_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*fsync) (const char *, int);*/
int cfusec_fsync(const char * path, int sync, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      sync_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;
    CFUSEC_DEBUG_ENTER("cfusec_fsync");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg   , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path  , strlen(path));
    cfuses_arg_mount(&sync_arg   , CFUSES_ARG_TYPE_INT    , (void *)(uintptr_t)sync  , sizeof(int));
    cfuses_arg_mount(&ret_arg    , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0     , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_fsync, CMPI_ERROR_MODI, &path_arg, &sync_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Set extended attributes */
/*int (*setxattr) (const char *, const char *, const char *, size_t, int);*/
int cfusec_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      name_arg;
    CFUSES_ARG      value_arg;
    CFUSES_ARG      size_arg;
    CFUSES_ARG      flags_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_setxattr");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&name_arg);
    CFUSEC_DEBUG_INIT(&value_arg);
    CFUSEC_DEBUG_INIT(&size_arg);
    CFUSEC_DEBUG_INIT(&flags_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&name_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)name    , strlen(name));
    cfuses_arg_mount(&value_arg, CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)value   , size);
    cfuses_arg_mount(&size_arg , CFUSES_ARG_TYPE_SIZE   , (void *)(uintptr_t)size    , sizeof(size_t));
    cfuses_arg_mount(&flags_arg, CFUSES_ARG_TYPE_INT    , (void *)(uintptr_t)flags   , sizeof(int));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_setxattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &value_arg, &size_arg, &flags_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&name_arg);
    CFUSEC_DEBUG_CLEAN(&value_arg);
    CFUSEC_DEBUG_CLEAN(&size_arg);
    CFUSEC_DEBUG_CLEAN(&flags_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Get extended attributes */
/*int (*getxattr) (const char *, const char *, char *, size_t);*/
int cfusec_getxattr(const char *path, const char *name, char *value, size_t size)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      name_arg;
    CFUSES_ARG      value_arg;
    CFUSES_ARG      size_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_getxattr");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&name_arg);
    CFUSEC_DEBUG_INIT(&value_arg);
    CFUSEC_DEBUG_INIT(&size_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&name_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)name    , strlen(name));
    cfuses_arg_mount(&value_arg, CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)value   , size);
    cfuses_arg_mount(&size_arg , CFUSES_ARG_TYPE_SIZE   , (void *)(uintptr_t)size    , sizeof(size_t));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_getxattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &value_arg, &size_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&name_arg);
    CFUSEC_DEBUG_CLEAN(&value_arg);
    CFUSEC_DEBUG_CLEAN(&size_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** List extended attributes */
/*int (*listxattr) (const char *, char *, size_t);*/
int cfusec_listxattr(const char *path, char *list, size_t size)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      list_arg;
    CFUSES_ARG      size_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_listxattr");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&list_arg);
    CFUSEC_DEBUG_INIT(&size_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&list_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)list    , size);
    cfuses_arg_mount(&size_arg , CFUSES_ARG_TYPE_SIZE   , (void *)(uintptr_t)size    , sizeof(size_t));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_listxattr, CMPI_ERROR_MODI, &path_arg, &list_arg, &size_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&list_arg);
    CFUSEC_DEBUG_CLEAN(&size_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/** Remove extended attributes */
/*int (*removexattr) (const char *, const char *);*/
int cfusec_removexattr(const char *path, const char *name)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      name_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_removexattr");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&name_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&name_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)name    , strlen(name));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_removexattr, CMPI_ERROR_MODI, &path_arg, &name_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&name_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*access) (const char *, int);*/
int cfusec_access(const char *path, int mask)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      mask_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_access");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&mask_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&mask_arg , CFUSES_ARG_TYPE_INT    , (void *)(uintptr_t)mask    , sizeof(int));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_access, CMPI_ERROR_MODI, &path_arg, &mask_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&mask_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*ftruncate) (const char *, off_t, struct fuse_file_info *);*/
int cfusec_ftruncate(const char *path, off_t offset)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      offset_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    CFUSEC_DEBUG_ENTER("cfusec_ftruncate");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&offset_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg  , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&offset_arg, CFUSES_ARG_TYPE_OFFT   , (void *)(uintptr_t)offset  , sizeof(off_t));
    cfuses_arg_mount(&ret_arg   , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_ftruncate, CMPI_ERROR_MODI, &path_arg, &offset_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&offset_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}


/*int (*utimens) (const char *, const struct timespec tv[2], struct fuse_file_info *fi);*/
int cfusec_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      ts_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_utimens");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&ts_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&ts_arg   , CFUSES_ARG_TYPE_TS     , (void *)(uintptr_t)&ts     , sizeof(struct timespec));
    cfuses_arg_mount(&ret_arg  , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_utimens, CMPI_ERROR_MODI, &path_arg, &ts_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&ts_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/* int (*fallocate) (const char *, int, off_t, off_t, struct fuse_file_info *); */
int cfusec_fallocate(const char * path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      mode_arg;
    CFUSES_ARG      offset_arg;
    CFUSES_ARG      length_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_fallocate");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&mode_arg);
    CFUSEC_DEBUG_INIT(&offset_arg);
    CFUSEC_DEBUG_INIT(&length_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    cfuses_arg_mount(&path_arg  , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&mode_arg  , CFUSES_ARG_TYPE_INT    , (void *)(uintptr_t)mode    , sizeof(int));
    cfuses_arg_mount(&offset_arg, CFUSES_ARG_TYPE_OFFT   , (void *)(uintptr_t)offset  , sizeof(off_t));
    cfuses_arg_mount(&length_arg, CFUSES_ARG_TYPE_OFFT   , (void *)(uintptr_t)length  , sizeof(off_t));
    cfuses_arg_mount(&ret_arg   , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_fallocate, CMPI_ERROR_MODI, &path_arg, &mode_arg, &offset_arg, &length_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&mode_arg);
    CFUSEC_DEBUG_CLEAN(&offset_arg);
    CFUSEC_DEBUG_CLEAN(&length_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*opendir) (const char *, struct fuse_file_info *);*/
int cfusec_opendir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_opendir");

    return (0);
}

/*int (*readdir) (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);*/
int cfusec_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags eflags)
{
    CFUSES_ARG      path_arg;
    CFUSES_ARG      buf_arg;
    CFUSES_ARG      filler_arg;
    CFUSES_ARG      offset_arg;
    CFUSES_ARG      flags_arg;
    CFUSES_ARG      ret_arg;

    EC_BOOL         ret;
    int             res;
    int             flags;

    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_readdir");

    CFUSEC_DEBUG_INIT(&path_arg);
    CFUSEC_DEBUG_INIT(&buf_arg);
    CFUSEC_DEBUG_INIT(&filler_arg);
    CFUSEC_DEBUG_INIT(&offset_arg);
    CFUSEC_DEBUG_INIT(&flags_arg);
    CFUSEC_DEBUG_INIT(&ret_arg);

    flags = (int)eflags;

    cfuses_arg_mount(&path_arg  , CFUSES_ARG_TYPE_CHAR   , (void *)(uintptr_t)path    , strlen(path));
    cfuses_arg_mount(&buf_arg   , CFUSES_ARG_TYPE_FUSE_DH, (void *)(uintptr_t)buf     , sizeof(struct fuse_dh));
    cfuses_arg_mount(&filler_arg, CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)filler  , sizeof(long int));
    cfuses_arg_mount(&offset_arg, CFUSES_ARG_TYPE_OFFT   , (void *)(uintptr_t)offset  , sizeof(off_t));
    cfuses_arg_mount(&flags_arg , CFUSES_ARG_TYPE_INT    , (void *)(uintptr_t)flags   , sizeof(int));
    cfuses_arg_mount(&ret_arg   , CFUSES_ARG_TYPE_LONG   , (void *)(uintptr_t)0       , sizeof(long int));

    ret = EC_FALSE;

    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             cfuses_get_remote_mod_node(),
             &ret,
             FI_cfuses_readdir, CMPI_ERROR_MODI, &path_arg, &buf_arg, &filler_arg, &offset_arg, &flags_arg, &ret_arg);

    res = (int)CFUSES_ARG_V_LONG(&ret_arg);

    CFUSEC_DEBUG_CLEAN(&path_arg);
    CFUSEC_DEBUG_CLEAN(&buf_arg);
    CFUSEC_DEBUG_CLEAN(&filler_arg);
    CFUSEC_DEBUG_CLEAN(&offset_arg);
    CFUSEC_DEBUG_CLEAN(&flags_arg);
    CFUSEC_DEBUG_CLEAN(&ret_arg);

    return (res);
}

/*int (*releasedir) (const char *, struct fuse_file_info *);*/
int cfusec_releasedir(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_releasedir");
    return (0);
}

/*int (*fsyncdir) (const char *, int, struct fuse_file_info *);*/
int cfusec_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    (void)path;
    (void)datasync;
    (void)fi;

    CFUSEC_DEBUG_ENTER("cfusec_fsyncdir");
    return (0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

