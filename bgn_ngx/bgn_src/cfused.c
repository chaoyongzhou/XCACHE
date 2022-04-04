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
            /* type                   */e_dbg_FUSE_DH_ptr,
            /* type_sizeof            */sizeof(struct fuse_dh *),
            /* pointer_flag           */EC_TRUE,
            /* var_mm_type            */MM_FUSE_DH,
            /* init_type_func         */(UINT32)c_fuse_dh_init,
            /* clean_type_func        */(UINT32)c_fuse_dh_clean,
            /* free_type_func         */(UINT32)c_fuse_dh_free,
            /* cmpi_encode_type_func  */(UINT32)cmpi_encode_fuse_dh,
            /* cmpi_decode_type_func  */(UINT32)cmpi_decode_fuse_dh,
            /* cmpi_encode_type_size  */(UINT32)cmpi_encode_fuse_dh_size
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

struct fuse_dh *c_fuse_dh_new()
{
    struct fuse_dh  *dh;
	dh = (struct fuse_dh *)malloc(sizeof(struct fuse_dh));
	if (NULL_PTR == dh)
	{
		return (NULL_PTR);
	}

    c_fuse_dh_init(dh);

	return (dh);
}

EC_BOOL c_fuse_dh_init(struct fuse_dh *dh)
{
    if(NULL_PTR != dh)
    {
    	memset(dh, 0, sizeof(struct fuse_dh));
    	dh->fuse        = NULL_PTR;
    	dh->contents    = NULL_PTR;
    	dh->first       = NULL_PTR;
    	dh->len         = 0;
    	dh->filled      = 0;
    	dh->nodeid      = 0;
    	pthread_mutex_init(&dh->lock, NULL);
    }
    return (EC_TRUE);
}

EC_BOOL c_fuse_dh_clean(struct fuse_dh *dh)
{
    if(NULL_PTR != dh)
    {
        struct fuse_direntry *de;

    	pthread_mutex_lock(&dh->lock);
    	pthread_mutex_unlock(&dh->lock);
    	pthread_mutex_destroy(&dh->lock);

        /*free_direntries(dh->first);*/
        de = dh->first;
    	while (de)
    	{
    		struct fuse_direntry *next = de->next;
    		free(de->name);
    		free(de);
    		de = next;
	    }
	    dh->first = NULL_PTR;

	    if(NULL_PTR != dh->fuse)
	    {
	        c_fuse_free(dh->fuse);
	        dh->fuse = NULL_PTR;
	    }

        if(NULL_PTR != dh->contents)
        {
    	    free(dh->contents);
    	    dh->contents = NULL_PTR;
    	}
    	dh->size = 0;
	}

	return (EC_TRUE);
}

EC_BOOL c_fuse_dh_free(struct fuse_dh *dh)
{
    if(NULL_PTR != dh)
    {
        c_fuse_dh_clean(dh);
    	free(dh);
	}

	return (EC_TRUE);
}

struct fuse *c_fuse_new()
{
    struct fuse *f;

	f = (struct fuse *)calloc(1, sizeof(struct fuse));
	if (NULL_PTR == f)
	{
		return (NULL_PTR);
	}

    c_fuse_init(f);

	return (f);
}

EC_BOOL c_fuse_init(struct fuse *f)
{
    if(NULL_PTR != f)
    {
    	INIT_LIST_BASE_HEAD(&f->partial_slabs);
    	INIT_LIST_BASE_HEAD(&f->full_slabs);
    	INIT_LIST_BASE_HEAD(&f->lru_table);
    }

    return (EC_TRUE);
}

EC_BOOL c_fuse_clean(struct fuse *f)
{
    if(NULL_PTR != f)
    {
        if(NULL_PTR != f->id_table.array)
        {
    	    free(f->id_table.array);
    	    f->id_table.array = NULL_PTR;
    	}

    	if(NULL_PTR != f->name_table.array)
    	{
    	    free(f->name_table.array);
    	    f->name_table.array = NULL_PTR;
    	}

        if(NULL_PTR != f->fs)
        {
    	    free(f->fs);
    	    f->fs = NULL_PTR;
    	}

    	if(NULL_PTR != f->conf.modules)
    	{
    	    free(f->conf.modules);
    	    f->conf.modules = NULL_PTR;
    	}
    }

    return (EC_TRUE);
}

EC_BOOL c_fuse_free(struct fuse *f)
{
    if(NULL_PTR != f)
    {
        c_fuse_clean(f);
        free(f);
    }

    return (EC_TRUE);
}

UINT32 cmpi_encode_fuse_direntry(const UINT32 comm, const struct fuse_direntry *de, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32  len;
    UINT8  *data;

    len  = sizeof(struct stat);
    data = (UINT8 *)&de->stat;
    cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);

    len  = strlen(de->name);
    data = (UINT8 *)de->name;
    cmpi_encode_uint32(comm, len, out_buff, out_buff_max_len, position);
    cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_direntry_size(const UINT32 comm, const struct fuse_direntry *de, UINT32 *size)
{
    UINT32  len;
    UINT8  *data;

    len  = sizeof(struct stat);
    data = (UINT8 *)&de->stat;
    cmpi_encode_uint8_array_size(comm, data, len, size);

    len  = strlen(de->name);
    data = (UINT8 *)de->name;
    cmpi_encode_uint32_size(comm, len, size);
    cmpi_encode_uint8_array_size(comm, data, len, size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_fuse_direntry(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct fuse_direntry *de)
{
    UINT32  len;
    UINT8  *data;

    data = (UINT8 *)&de->stat;
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
    ASSERT(len == sizeof(struct stat));

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &len);
    data = malloc(len + 1);
    ASSERT(NULL_PTR != data);
    data[ len ] = 0x00;
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
    de->name = (char *)data;

    de->next = NULL_PTR;

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_dh(const UINT32 comm, const struct fuse_dh *dh, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32      num;
    uint64_t    nodeid;

    struct fuse_direntry    *de;

    ASSERT(NULL_PTR != dh->fuse);
    cmpi_encode_fuse(comm, dh->fuse, out_buff, out_buff_max_len, position);

    num = dh->len;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = dh->needlen;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = dh->filled;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = dh->size;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = dh->error;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    nodeid = dh->nodeid;
    cmpi_encode_uint64(comm, nodeid, out_buff, out_buff_max_len, position);

    num = dh->size;
    cmpi_encode_uint8_array(comm, (UINT8 *)dh->contents, num, out_buff, out_buff_max_len, position);

    for(de = dh->first, num = 0; NULL_PTR != de; de = de->next, num ++)
    {
        /*do nothing*/
    }
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    for(de = dh->first; NULL_PTR != de; de = de->next)
    {
        cmpi_encode_fuse_direntry(comm, de, out_buff, out_buff_max_len, position);
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_dh_size(const UINT32 comm, const struct fuse_dh *dh, UINT32 *size)
{
    UINT32      num;
    uint64_t    nodeid;

    struct fuse_direntry    *de;

    ASSERT(NULL_PTR != dh->fuse);
    cmpi_encode_fuse_size(comm, dh->fuse, size);

    num = dh->len;
    cmpi_encode_uint32_size(comm, num, size);

    num = dh->needlen;
    cmpi_encode_uint32_size(comm, num, size);

    num = dh->filled;
    cmpi_encode_uint32_size(comm, num, size);

    num = dh->size;
    cmpi_encode_uint32_size(comm, num, size);

    num = dh->error;
    cmpi_encode_uint32_size(comm, num, size);

    nodeid = dh->nodeid;
    cmpi_encode_uint64_size(comm, nodeid, size);

    num = dh->size;
    cmpi_encode_uint8_array_size(comm, (UINT8 *)dh->contents, num, size);

    for(de = dh->first, num = 0; NULL_PTR != de; de = de->next, num ++)
    {
        /*do nothing*/
    }
    cmpi_encode_uint32_size(comm, num, size);

    for(de = dh->first; NULL_PTR != de; de = de->next)
    {
        cmpi_encode_fuse_direntry_size(comm, de, size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_fuse_dh(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct fuse_dh *dh)
{
    UINT32      num;
    uint64_t    nodeid;
    char       *contents;

    struct fuse_direntry    *de;

    if(NULL_PTR == dh->fuse)
    {
        dh->fuse = c_fuse_new();
        ASSERT(NULL_PTR != dh->fuse);
    }
    cmpi_decode_fuse(comm, in_buff, in_buff_max_len, position, dh->fuse);

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    dh->len = (unsigned)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    dh->needlen = (unsigned)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    dh->filled = (int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    dh->size = (unsigned)num;

    contents = (char *)realloc(dh->contents, dh->size);
    ASSERT(NULL_PTR != contents);
    dh->contents = contents;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    dh->error = (int)num;

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &nodeid);
    dh->nodeid = nodeid;

    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, (UINT8 *)dh->contents, &num);
    ASSERT(num == (UINT32)dh->size);

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);

    if(NULL_PTR == dh->last)
    {
        dh->last = &dh->first;
    }

    for(;num -- > 0;)
    {
        de = calloc(1, sizeof(struct fuse_direntry));
        cmpi_decode_fuse_direntry(comm, in_buff, in_buff_max_len, position,de);

    	*dh->last = de;
    	dh->last = &de->next;
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_node(const UINT32 comm, const struct node *node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32      num;
    UINT32      len;
    UINT8      *data;
    uint64_t    u64;

    u64 = node->nodeid;
    cmpi_encode_uint64(comm, u64, out_buff, out_buff_max_len, position);

    num = node->generation;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = node->refctr;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    data = (UINT8 *)(node->name);
    len  = strlen(node->name);
    cmpi_encode_uint32(comm, len, out_buff, out_buff_max_len, position);
    cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);

    u64 = node->nlookup;
    cmpi_encode_uint64(comm, u64, out_buff, out_buff_max_len, position);

    num = node->open_count;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    data = (UINT8 *)&(node->stat_updated);
    len  = sizeof(struct timespec);
    cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);

    data = (UINT8 *)&(node->mtime);
    len  = sizeof(struct timespec);
    cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);

    u64 = node->size;
    cmpi_encode_uint64(comm, u64, out_buff, out_buff_max_len, position);

    num = node->is_hidden;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = node->cache_valid;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = node->treelock;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    data = (UINT8 *)(node->inline_name);
    len  = 32;
    cmpi_encode_uint8_array(comm, data, len, out_buff, out_buff_max_len, position);

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_node_size(const UINT32 comm, const struct node *node, UINT32 *size)
{
    UINT32      num;
    UINT32      len;
    UINT8      *data;
    uint64_t    u64;

    u64 = node->nodeid;
    cmpi_encode_uint64_size(comm, u64, size);

    num = node->generation;
    cmpi_encode_uint32_size(comm, num, size);

    num = node->refctr;
    cmpi_encode_uint32_size(comm, num, size);

    data = (UINT8 *)(node->name);
    len  = strlen(node->name);
    cmpi_encode_uint32_size(comm, len, size);
    cmpi_encode_uint8_array_size(comm, data, len, size);

    u64 = node->nlookup;
    cmpi_encode_uint64_size(comm, u64, size);

    num = node->open_count;
    cmpi_encode_uint32_size(comm, num, size);

    data = (UINT8 *)&(node->stat_updated);
    len  = sizeof(struct timespec);
    cmpi_encode_uint8_array_size(comm, data, len, size);

    data = (UINT8 *)&(node->mtime);
    len  = sizeof(struct timespec);
    cmpi_encode_uint8_array_size(comm, data, len, size);

    u64 = node->size;
    cmpi_encode_uint64_size(comm, u64, size);

    num = node->is_hidden;
    cmpi_encode_uint32_size(comm, num, size);

    num = node->cache_valid;
    cmpi_encode_uint32_size(comm, num, size);

    num = node->treelock;
    cmpi_encode_uint32_size(comm, num, size);

    data = (UINT8 *)(node->inline_name);
    len  = 32;
    cmpi_encode_uint8_array_size(comm, data, len, size);

    return ((UINT32)0);
}

UINT32 cmpi_decode_fuse_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct node *node)
{
    UINT32      num;
    UINT32      len;
    UINT8      *data;
    uint64_t    u64;

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &u64);
    node->nodeid = u64;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node->generation = (unsigned int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node->refctr = (int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &len);
    data = malloc(len + 1);
    ASSERT(NULL_PTR != data);
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
    data[ len ] = 0x00;

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &u64);
    node->nlookup = u64;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node->open_count = (int)num;

    data = (UINT8 *)&(node->stat_updated);
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
    ASSERT(sizeof(struct timespec) == len);

    data = (UINT8 *)&(node->mtime);
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
    ASSERT(sizeof(struct timespec) == len);

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &u64);
    node->size = (off_t)u64;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node->is_hidden = (unsigned int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node->cache_valid = (unsigned int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node->treelock = (int)num;

    data = (UINT8 *)(node->inline_name);
    cmpi_decode_uint8_array(comm, in_buff, in_buff_max_len, position, data, &len);
    ASSERT(32 == len);

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_node_table(const UINT32 comm, const struct node_table *node_table, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32      num;
    size_t      idx;

    num = node_table->use;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = node_table->size;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = node_table->split;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    for(idx = 0; idx < node_table->size; idx ++)
    {
        struct node * node;

        node = node_table->array[ idx ];
        if(NULL_PTR != node)
        {
            num = EC_TRUE;
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);
            cmpi_encode_fuse_node(comm, node, out_buff, out_buff_max_len, position);
        }
        else
        {
            num = EC_FALSE;
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);
        }
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_node_table_size(const UINT32 comm, const struct node_table *node_table, UINT32 *size)
{
    UINT32      num;
    size_t      idx;

    num = node_table->use;
    cmpi_encode_uint32_size(comm, num, size);

    num = node_table->size;
    cmpi_encode_uint32_size(comm, num, size);

    num = node_table->split;
    cmpi_encode_uint32_size(comm, num, size);

    for(idx = 0; idx < node_table->size; idx ++)
    {
        struct node * node;

        node = node_table->array[ idx ];
        if(NULL_PTR != node)
        {
            num = EC_TRUE;
            cmpi_encode_uint32_size(comm, num, size);
            cmpi_encode_fuse_node_size(comm, node, size);
        }
        else
        {
            num = EC_FALSE;
            cmpi_encode_uint32_size(comm, num, size);
        }
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_fuse_node_table(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct node_table *node_table)
{
    UINT32      num;
    size_t      idx;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node_table->use = (size_t)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node_table->size = (size_t)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    node_table->split = (size_t)num;

    node_table->array = calloc(node_table->size, sizeof(struct node *));
    ASSERT(NULL_PTR != node_table->array);

    for(idx = 0; idx < node_table->size; idx ++)
    {
        struct node * node;

        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
        if(EC_FALSE == num)
        {
            node_table->array[ idx ] = NULL_PTR;
            continue;
        }

        node = (struct node *) calloc(1, sizeof(struct node));
        ASSERT(NULL_PTR != node);
        cmpi_decode_fuse_node(comm, in_buff, in_buff_max_len, position, node);
        node_table->array[ idx ] = node;
    }

    return ((UINT32)0);
}

STATIC_CAST size_t __cmpi_fuse_node_table_locate(const struct node_table *node_table, struct node * node)
{
    size_t      idx;

    for(idx = 0; idx < node_table->size; idx ++)
    {
        if(NULL_PTR != node_table->array[ idx ]
        && node == node_table->array[ idx ])
        {
            return (idx);
        }
    }

    return ((size_t)~0);
}

UINT32 cmpi_encode_fuse(const UINT32 comm, const struct fuse *f, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position)
{
    UINT32      num;
    REAL        real;
    uint64_t    n64;

    size_t      idx;
    size_t      name_idx;
    size_t      id_next_idx;
    size_t      name_next_idx;

    const struct node_table   *id_node_table;
    const struct node_table   *name_node_table;

    num = f->conf.use_ino;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = f->conf.readdir_ino;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = f->conf.auto_cache;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    num = f->conf.remember;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    real = f->conf.entry_timeout;
    cmpi_encode_real(comm, &real, out_buff, out_buff_max_len, position);

    real = f->conf.attr_timeout;
    cmpi_encode_real(comm, &real, out_buff, out_buff_max_len, position);

    n64 = f->ctr;
    cmpi_encode_uint64(comm, n64, out_buff, out_buff_max_len, position);

    num = f->generation;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    id_node_table = &(f->id_table);
    cmpi_encode_fuse_node_table(comm, id_node_table, out_buff, out_buff_max_len, position);

    name_node_table = &(f->name_table);
    //cmpi_encode_fuse_node_table(comm, name_node_table, out_buff, out_buff_max_len, position);

    ASSERT(name_node_table->use == id_node_table->use);
    num = name_node_table->use;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    ASSERT(name_node_table->size == id_node_table->size);
    num = name_node_table->size;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    ASSERT(name_node_table->split == id_node_table->split);
    num = name_node_table->split;
    cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

    for(idx = 0; idx < name_node_table->size; idx ++)
    {
        struct node * name_node;

        name_node = name_node_table->array[ idx ];
        if(NULL_PTR == name_node)
        {
            num = ((size_t)~0);
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);
        }
        else
        {
            name_idx = __cmpi_fuse_node_table_locate(id_node_table, name_node);
            ASSERT(((size_t)~0) != name_idx);

            name_next_idx = __cmpi_fuse_node_table_locate(id_node_table, name_node->name_next);
            ASSERT(((size_t)~0) != name_next_idx);

            id_next_idx   = __cmpi_fuse_node_table_locate(id_node_table  , name_node->id_next);
            ASSERT(((size_t)~0) != id_next_idx);

            /*{name_idx, name_next_idx, id_next_idx}*/
            num = name_idx;
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

            num = name_next_idx;
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);

            num = id_next_idx;
            cmpi_encode_uint32(comm, num, out_buff, out_buff_max_len, position);
        }
    }

    return ((UINT32)0);
}

UINT32 cmpi_encode_fuse_size(const UINT32 comm, const struct fuse *f, UINT32 *size)
{
    UINT32      num;
    REAL        real;
    uint64_t    n64;

    size_t      idx;

    const struct node_table   *id_node_table;
    const struct node_table   *name_node_table;

    num = f->conf.use_ino;
    cmpi_encode_uint32_size(comm, num, size);

    num = f->conf.readdir_ino;
    cmpi_encode_uint32_size(comm, num, size);

    num = f->conf.auto_cache;
    cmpi_encode_uint32_size(comm, num, size);

    num = f->conf.remember;
    cmpi_encode_uint32_size(comm, num, size);

    real = f->conf.entry_timeout;
    cmpi_encode_real_size(comm, &real, size);

    real = f->conf.attr_timeout;
    cmpi_encode_real_size(comm, &real, size);

    n64 = f->ctr;
    cmpi_encode_uint64_size(comm, n64, size);

    num = f->generation;
    cmpi_encode_uint32_size(comm, num, size);

    id_node_table = &(f->id_table);
    cmpi_encode_fuse_node_table_size(comm, id_node_table, size);

    name_node_table = &(f->name_table);
    //cmpi_encode_fuse_node_table_size(comm, node_table, size);

    ASSERT(name_node_table->use == id_node_table->use);
    num = name_node_table->use;
    cmpi_encode_uint32_size(comm, num, size);

    ASSERT(name_node_table->size == id_node_table->size);
    num = name_node_table->size;
    cmpi_encode_uint32_size(comm, num, size);

    ASSERT(name_node_table->split == id_node_table->split);
    num = name_node_table->split;
    cmpi_encode_uint32_size(comm, num, size);

    for(idx = 0; idx < name_node_table->size; idx ++)
    {
        /*{name_idx, name_next_idx, id_next_idx}*/
        num = idx; /*any thing*/
        cmpi_encode_uint32_size(comm, num, size);

        num = idx;/*any thing*/
        cmpi_encode_uint32_size(comm, num, size);

        num = idx;/*any thing*/
        cmpi_encode_uint32_size(comm, num, size);
    }

    return ((UINT32)0);
}

UINT32 cmpi_decode_fuse(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct fuse *f)
{
    UINT32      num;
    REAL        real;
    uint64_t    n64;

    size_t      idx;
    size_t      name_idx;
    size_t      id_next_idx;
    size_t      name_next_idx;

    struct node_table   *id_node_table;
    struct node_table   *name_node_table;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    f->conf.use_ino = (int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    f->conf.readdir_ino = (int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    f->conf.auto_cache = (int)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    f->conf.remember = (int)num;

    cmpi_decode_real(comm, in_buff, in_buff_max_len, position, &real);
    f->conf.entry_timeout = real;

    cmpi_decode_real(comm, in_buff, in_buff_max_len, position, &real);
    f->conf.attr_timeout = real;

    cmpi_decode_uint64(comm, in_buff, in_buff_max_len, position, &n64);
    f->ctr = n64;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    f->generation = (unsigned)num;

    id_node_table = &(f->id_table);
    cmpi_decode_fuse_node_table(comm, in_buff, in_buff_max_len, position, id_node_table);

    name_node_table = &(f->name_table);
    //cmpi_decode_fuse_node_table(comm, in_buff, in_buff_max_len, position, node_table);

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    ASSERT((UINT32)id_node_table->use == num);
    name_node_table->use = (size_t)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    ASSERT((UINT32)id_node_table->size == num);
    name_node_table->size = (size_t)num;

    cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
    ASSERT((UINT32)id_node_table->split == num);
    name_node_table->split = (size_t)num;

    name_node_table->array = calloc(name_node_table->size, sizeof(struct node *));
    ASSERT(NULL_PTR != name_node_table->array);

    for(idx = 0; idx < name_node_table->size; idx ++)
    {
        struct node     *node;
        /*{name_idx, name_next_idx, id_next_idx}*/

        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
        name_idx = (size_t)num;

        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
        name_next_idx = (size_t)num;

        cmpi_decode_uint32(comm, in_buff, in_buff_max_len, position, &num);
        id_next_idx = (size_t)num;

        if((UINT32)((size_t)~0) == name_idx
        && (UINT32)((size_t)~0) == name_next_idx
        && (UINT32)((size_t)~0) == id_next_idx)
        {
            continue;
        }

        node = id_node_table->array[ name_idx ];
        ASSERT(NULL_PTR != node);

        name_node_table->array[ idx ] = node;
        node->name_next = id_node_table->array[ name_next_idx ];
        node->id_next   = id_node_table->array[ id_next_idx ];
    }

    return ((UINT32)0);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

