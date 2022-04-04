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

void cfused_start();
void cfused_end();

struct fuse_dh *c_fuse_dh_new();
EC_BOOL c_fuse_dh_init(struct fuse_dh *dh);
EC_BOOL c_fuse_dh_clean(struct fuse_dh *dh);
EC_BOOL c_fuse_dh_free(struct fuse_dh *dh);

struct fuse *c_fuse_new();
EC_BOOL c_fuse_init(struct fuse *f);
EC_BOOL c_fuse_clean(struct fuse *f);
EC_BOOL c_fuse_free(struct fuse *f);

UINT32 cmpi_encode_fuse_direntry(const UINT32 comm, const struct fuse_direntry *de, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_fuse_direntry_size(const UINT32 comm, const struct fuse_direntry *de, UINT32 *size);
UINT32 cmpi_decode_fuse_direntry(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct fuse_direntry *de);

UINT32 cmpi_encode_fuse_dh(const UINT32 comm, const struct fuse_dh *dh, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_fuse_dh_size(const UINT32 comm, const struct fuse_dh *dh, UINT32 *size);
UINT32 cmpi_decode_fuse_dh(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct fuse_dh *dh);

UINT32 cmpi_encode_fuse_node(const UINT32 comm, const struct node *node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_fuse_node_size(const UINT32 comm, const struct node *node, UINT32 *size);
UINT32 cmpi_decode_fuse_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct node *node);

UINT32 cmpi_encode_fuse_node_table(const UINT32 comm, const struct node_table *node_table, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_fuse_node_table_size(const UINT32 comm, const struct node_table *node_table, UINT32 *size);
UINT32 cmpi_decode_fuse_node_table(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct node_table *node_table);

UINT32 cmpi_encode_fuse(const UINT32 comm, const struct fuse *f, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_fuse_size(const UINT32 comm, const struct fuse *f, UINT32 *size);
UINT32 cmpi_decode_fuse(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct fuse *f);


#endif /*_CFUSED_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

