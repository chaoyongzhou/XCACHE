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

#ifndef _CMMAP_H
#define _CMMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <math.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#define CMMAP_PROTO              (PROT_READ | PROT_WRITE)
#define CMMAP_FLAGS              (/*MAP_SHARED | */MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED | MAP_NORESERVE)

#define CMMAP_SHM_FNAME_MAX_LEN  (256)

#define CMMAP_MEM_ALIGNMENT      (UINT32_ONE << 13) /*8K alignment*/

#define CMMAP_SYNC_SIZE_NBYTES   (1 << 20) /*1M*/

typedef struct
{
    void            *s_addr;
    void            *e_addr;

    void            *c_addr;  /*for space dynamic allocation */
                              /*point to start address of free space*/
}CMMAP_NODE;

#define CMMAP_NODE_S_ADDR(cmmap_node)               ((cmmap_node)->s_addr)
#define CMMAP_NODE_E_ADDR(cmmap_node)               ((cmmap_node)->e_addr)
#define CMMAP_NODE_C_ADDR(cmmap_node)               ((cmmap_node)->c_addr)

CMMAP_NODE *cmmap_node_new();

EC_BOOL cmmap_node_init(CMMAP_NODE *cmmap_node);

EC_BOOL cmmap_node_clean(CMMAP_NODE *cmmap_node);

EC_BOOL cmmap_node_free(CMMAP_NODE *cmmap_node);

void cmmap_node_print(LOG *log, const CMMAP_NODE *cmmap_node);

CMMAP_NODE *cmmap_node_create(const UINT32 size, const UINT32 align);

EC_BOOL cmmap_node_shrink(CMMAP_NODE *cmmap_node);

void *cmmap_node_alloc(CMMAP_NODE *cmmap_node, const UINT32 size, const UINT32 align, const char *tip);

EC_BOOL cmmap_node_peek(CMMAP_NODE *cmmap_node, const UINT32 size, void *data);

UINT32 cmmap_node_space(const CMMAP_NODE *cmmap_node);

UINT32 cmmap_node_room(const CMMAP_NODE *cmmap_node);

UINT32 cmmap_node_used(const CMMAP_NODE *cmmap_node);

EC_BOOL cmmap_node_dump_shm(CMMAP_NODE *cmmap_node, const char *shm_root_dir, const UINT32 shm_file_size);

EC_BOOL cmmap_node_restore_shm(CMMAP_NODE *cmmap_node, const char *shm_root_dir, const UINT32 align);

EC_BOOL cmmap_node_import(CMMAP_NODE *cmmap_node, const void *data, const UINT32 size);

EC_BOOL cmmap_node_sync(CMMAP_NODE *cmmap_node, void *camd_md, const UINT32 offset);

#endif /*_CMMAP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

