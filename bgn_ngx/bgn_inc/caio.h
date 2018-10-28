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

#ifndef _CAIO_H
#define _CAIO_H

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/aio_abi.h>

#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "coroutine.h"

#define CAIO_REQ_MAX_NUM            (64)

#define CAIO_BLOCK_SIZE_NBIT        (18) /*256KB = 2 ^ 18*/
#define CAIO_BLOCK_SIZE_NBYTE       (UINT32_ONE << CAIO_BLOCK_SIZE_NBIT)
#define CAIO_BLOCK_SIZE_MASK        (CAIO_BLOCK_SIZE_NBYTE - 1)

#define CAIO_RW_TIMEOUT_NSEC        (30)

#define CAIO_NODE_READ_OP           ((UINT32) 1)
#define CAIO_NODE_WRITE_OP          ((UINT32) 2)
#define CAIO_NODE_ERR_OP            ((UINT32)~0)

typedef struct
{
    COROUTINE_COND     *coroutine_cond; /*mount point*/

    UINT32              op;

    struct iocb         aiocb;  /*64B*/
    
    UINT8              *f_cache;    /*read or write cache for file operation*/
    
    UINT8              *m_cache;    /*read or write cache for application. only mount point!*/
    UINT32              f_s_offset; /*start offset in file*/
    UINT32              f_e_offset; /*end offset in file*/
    UINT32              b_s_offset; /*start offset in block*/
    UINT32              b_e_offset; /*end offset in block*/
    
    CTIMET              next_access_time;  /*next access in second*/
#if (32 == WORDSIZE)
    uint32_t            rsvd02;
#endif
}CAIO_NODE;

#define CAIO_NODE_CCOND(caio_node)           ((caio_node)->coroutine_cond)
#define CAIO_NODE_OP(caio_node)              ((caio_node)->op)
#define CAIO_NODE_AIOCB(caio_node)           (&((caio_node)->aiocb))
#define CAIO_NODE_F_CACHE(caio_node)         ((caio_node)->f_cache)
#define CAIO_NODE_M_CACHE(caio_node)         ((caio_node)->m_cache)
#define CAIO_NODE_F_S_OFFSET(caio_node)      ((caio_node)->f_s_offset)
#define CAIO_NODE_F_E_OFFSET(caio_node)      ((caio_node)->f_e_offset)
#define CAIO_NODE_B_S_OFFSET(caio_node)      ((caio_node)->b_s_offset)
#define CAIO_NODE_B_E_OFFSET(caio_node)      ((caio_node)->b_e_offset)
#define CAIO_NODE_NTIME_TS(caio_node)        ((caio_node)->next_access_time)

#define CAIO_AIOCB_NODE(__aiocb)     \
        ((CAIO_NODE *)((char *)(__aiocb)-(unsigned long)(&((CAIO_NODE *)0)->aiocb)))

typedef struct
{
    int                   aio_eventfd;
    int                   rsvd;
    aio_context_t         aio_context;
}CAIO_MD;

#define CAIO_MD_AIO_EVENTFD(caio_md)        ((caio_md)->aio_eventfd)
#define CAIO_MD_AIO_CONTEXT(caio_md)        ((caio_md)->aio_context)

CAIO_NODE *caio_node_new();

EC_BOOL caio_node_init(CAIO_NODE *caio_node);

EC_BOOL caio_node_clean(CAIO_NODE *caio_node);

EC_BOOL caio_node_free(CAIO_NODE *caio_node);

void caio_node_print(LOG *log, const CAIO_NODE *caio_node);

EC_BOOL caio_event_handler(CAIO_MD *caio_md);

CAIO_MD *caio_start();

void caio_end(CAIO_MD *caio_md);

EC_BOOL caio_file_load(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff);

EC_BOOL caio_file_flush(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff);

#endif /*_CAIO_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
