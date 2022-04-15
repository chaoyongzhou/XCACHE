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

#ifndef _CFUSED_H
#define _CFUSED_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/xattr.h>
#include <x86_64-linux-gnu/sys/xattr.h>
#include <dirent.h>

#include <fuse.h>
#include <pthread.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

/** Inode number type */
typedef uint64_t fuse_ino_t;

struct node {
	struct node         *name_next;
	struct node         *id_next;
	fuse_ino_t           nodeid;
	unsigned int         generation;
	int                  refctr;
	struct node         *parent;
	char                *name;
	uint64_t             nlookup;
	int                  open_count;
	struct timespec      stat_updated;
	struct timespec      mtime;
	off_t                size;
	void                *locks;
	unsigned int         is_hidden : 1;
	unsigned int         cache_valid : 1;
	int                  treelock;
	char                 inline_name[32];
};

struct node_table {
	struct node         **array;
	size_t                use;
	size_t                size;
	size_t                split;
};

struct fuse_direntry {
	struct stat             stat;
	char                   *name;
	struct fuse_direntry   *next;
};

struct fuse_dh {
	pthread_mutex_t         lock;
	struct fuse            *fuse;
	void                   *req;
	char                   *contents;
	struct fuse_direntry   *first;
	struct fuse_direntry  **last;
	unsigned                len;
	unsigned                size;
	unsigned                needlen;
	int                     filled;
	uint64_t                fh;
	int                     error;
	fuse_ino_t              nodeid;
};

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct fuse {
	void                   *se;
	struct node_table       name_table;
	struct node_table       id_table;
	struct list_head        lru_table;
	fuse_ino_t              ctr;
	unsigned int            generation;
	unsigned int            hidectr;
	pthread_mutex_t         lock;
	struct fuse_config      conf;
	int                     intr_installed;
	void                   *fs;
	void                   *lockq;
	int                     pagesize;
	struct list_head        partial_slabs;
	struct list_head        full_slabs;
	pthread_t               prune_thread;
};

/*definition for readdir interface*/
struct dirnode
{
    char                   *name;
    struct stat             stat;
    off_t                   offset;
    uint32_t                flags;
    uint32_t                rsvd;
};

void cfused_start();
void cfused_end();

#if 1
int *c_i32_new();
EC_BOOL c_i32_init(int *i32);
EC_BOOL c_i32_clean(int *i32);
EC_BOOL c_i32_free(int *i32);

UINT32 cmpi_encode_i32(const UINT32 comm, const int *i32, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_i32_size(const UINT32 comm, const int *i32, UINT32 *size);
UINT32 cmpi_decode_i32(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, int *i32);
#endif

#if 1
struct stat *c_stat_new();
EC_BOOL c_stat_init(struct stat *stat);
EC_BOOL c_stat_clean(struct stat *stat);
EC_BOOL c_stat_free(struct stat *stat);

UINT32 cmpi_encode_stat(const UINT32 comm, const struct stat *stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_stat_size(const UINT32 comm, const struct stat *stat, UINT32 *size);
UINT32 cmpi_decode_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct stat *stat);
#endif


#if 1
struct statvfs *c_statvfs_new();
EC_BOOL c_statvfs_init(struct statvfs *statvfs);
EC_BOOL c_statvfs_clean(struct statvfs *statvfs);
EC_BOOL c_statvfs_free(struct statvfs *statvfs);

UINT32 cmpi_encode_statvfs(const UINT32 comm, const struct statvfs *statvfs, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_statvfs_size(const UINT32 comm, const struct statvfs *statvfs, UINT32 *size);
UINT32 cmpi_decode_statvfs(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct statvfs *statvfs);
#endif

#if 1
struct timespec *c_timespec_new();
EC_BOOL c_timespec_init(struct timespec *timespec);
EC_BOOL c_timespec_clean(struct timespec *timespec);
EC_BOOL c_timespec_free(struct timespec *timespec);

UINT32 cmpi_encode_timespec(const UINT32 comm, const struct timespec *timespec, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_timespec_size(const UINT32 comm, const struct timespec *timespec, UINT32 *size);
UINT32 cmpi_decode_timespec(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct timespec *timespec);
#endif

#if 1
struct utimbuf *c_utimbuf_new();
EC_BOOL c_utimbuf_init(struct utimbuf *utimbuf);
EC_BOOL c_utimbuf_clean(struct utimbuf *utimbuf);
EC_BOOL c_utimbuf_free(struct utimbuf *utimbuf);

UINT32 cmpi_encode_utimbuf(const UINT32 comm, const struct utimbuf *utimbuf, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_utimbuf_size(const UINT32 comm, const struct utimbuf *utimbuf, UINT32 *size);
UINT32 cmpi_decode_utimbuf(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct utimbuf *utimbuf);
#endif


#if 1
struct dirnode *c_dirnode_new();
EC_BOOL c_dirnode_init(struct dirnode *dirnode);
EC_BOOL c_dirnode_clean(struct dirnode *dirnode);
EC_BOOL c_dirnode_free(struct dirnode *dirnode);

UINT32 cmpi_encode_dirnode(const UINT32 comm, const struct dirnode *dirnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_dirnode_size(const UINT32 comm, const struct dirnode *dirnode, UINT32 *size);
UINT32 cmpi_decode_dirnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct dirnode *dirnode);
#endif

#endif /*_CFUSED_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

