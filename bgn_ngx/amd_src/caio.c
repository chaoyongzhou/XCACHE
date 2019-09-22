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

#include <sys/time.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "cbadbitmap.h"

#include "caio.h"

#if (SWITCH_ON == CAIO_ASSERT_SWITCH)
#define CAIO_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CAIO_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CAIO_ASSERT_SWITCH)
#define CAIO_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CAIO_ASSERT_SWITCH)*/

static const CAIO_CFG g_caio_cfg_tbl[] = {
    {(const char *)"512B"  , (const char *)"CAIO_512B_MODEL", CAIO_512B_BLOCK_SIZE_NBIT,  CAIO_512B_BLOCK_SIZE_NBYTE, CAIO_512B_BLOCK_SIZE_MASK },
    {(const char *)"1K"    , (const char *)"CAIO_001K_MODEL", CAIO_001K_BLOCK_SIZE_NBIT,  CAIO_001K_BLOCK_SIZE_NBYTE, CAIO_001K_BLOCK_SIZE_MASK },
    {(const char *)"2K"    , (const char *)"CAIO_002K_MODEL", CAIO_002K_BLOCK_SIZE_NBIT,  CAIO_002K_BLOCK_SIZE_NBYTE, CAIO_002K_BLOCK_SIZE_MASK },
    {(const char *)"4K"    , (const char *)"CAIO_004K_MODEL", CAIO_004K_BLOCK_SIZE_NBIT,  CAIO_004K_BLOCK_SIZE_NBYTE, CAIO_004K_BLOCK_SIZE_MASK },
    {(const char *)"8K"    , (const char *)"CAIO_008K_MODEL", CAIO_008K_BLOCK_SIZE_NBIT,  CAIO_008K_BLOCK_SIZE_NBYTE, CAIO_008K_BLOCK_SIZE_MASK },
    {(const char *)"16K"   , (const char *)"CAIO_016K_MODEL", CAIO_016K_BLOCK_SIZE_NBIT,  CAIO_016K_BLOCK_SIZE_NBYTE, CAIO_016K_BLOCK_SIZE_MASK },
    {(const char *)"32K"   , (const char *)"CAIO_032K_MODEL", CAIO_032K_BLOCK_SIZE_NBIT,  CAIO_032K_BLOCK_SIZE_NBYTE, CAIO_032K_BLOCK_SIZE_MASK },
    {(const char *)"64K"   , (const char *)"CAIO_064K_MODEL", CAIO_064K_BLOCK_SIZE_NBIT,  CAIO_064K_BLOCK_SIZE_NBYTE, CAIO_064K_BLOCK_SIZE_MASK },
    {(const char *)"128K"  , (const char *)"CAIO_128K_MODEL", CAIO_128K_BLOCK_SIZE_NBIT,  CAIO_128K_BLOCK_SIZE_NBYTE, CAIO_128K_BLOCK_SIZE_MASK },
    {(const char *)"256K"  , (const char *)"CAIO_256K_MODEL", CAIO_256K_BLOCK_SIZE_NBIT,  CAIO_256K_BLOCK_SIZE_NBYTE, CAIO_256K_BLOCK_SIZE_MASK },
    {(const char *)"512K"  , (const char *)"CAIO_512K_MODEL", CAIO_512K_BLOCK_SIZE_NBIT,  CAIO_512K_BLOCK_SIZE_NBYTE, CAIO_512K_BLOCK_SIZE_MASK },
    {(const char *)"1M"    , (const char *)"CAIO_001M_MODEL", CAIO_001M_BLOCK_SIZE_NBIT,  CAIO_001M_BLOCK_SIZE_NBYTE, CAIO_001M_BLOCK_SIZE_MASK },
};

static const UINT32 g_caio_cfg_len = sizeof(g_caio_cfg_tbl)/sizeof(g_caio_cfg_tbl[ 0 ]);

#define CAIO_STAT_DEBUG (SWITCH_ON)

#if (SWITCH_ON == CAIO_STAT_DEBUG)
static uint64_t g_caio_stat_tbl[ 12 ] = {
    0, /* 0 ms */
    0, /* 1 ms */
    0, /* 2 ms */
    0, /* 3 ms */
    0, /* 4 ms */
    0, /* 5 ms */
    0, /* 6 ms */
    0, /* 7 ms */
    0, /* 8 ms */
    0, /* 9 ms */
    0, /* 10 ms */
    0, /*>10 ms */
};

static uint64_t g_caio_stat_sum = 0;
#endif/*(SWITCH_ON == CAIO_STAT_DEBUG)*/

#if 0
#define CAIO_CRC32(data, len)   c_crc32_long((data), (len))
#else
#define CAIO_CRC32(data, len)   0
#endif

/*----------------------------------- syscall interface -----------------------------------*/
/*
*
*  long syscall(long number, ...);
*
*  RETURN VALUE:
*
*   The return value is defined by the system call being invoked.
*
*/
STATIC_CAST EC_BOOL __caio_setup(unsigned nr_reqs, aio_context_t *ctx)
{
    /*
    *
    * ref: http://www.man7.org/linux/man-pages/man2/io_setup.2.html
    * int io_setup(unsigned nr_events, aio_context_t *ctx_idp);
    *
    */

    int err;

    if(0 == syscall(__NR_io_setup, nr_reqs, ctx))
    {
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_setup: "
                                             "nr_reqs = %d, ctx = %lx\n",
                                             nr_reqs, (*ctx));
        return (EC_TRUE);
    }

    err = errno;
    switch(err)
    {
        case EAGAIN:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_setup: "
                                                 "not support EAGAIN yet\n");
            break;
        }
        case EFAULT:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_setup: "
                                                 "invalid ctx %p\n",
                                                 ctx);
            break;
        }
        case EINVAL:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_setup: "
                                                 "not initialized ctx %p or nr_reqs %d overflow\n",
                                                 ctx, nr_reqs);
            break;
        }
        case ENOMEM:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_setup: "
                                                 "Insufficient kernel resources are available\n");
            break;
        }
        case ENOSYS:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_setup: "
                                                 "io_setup() is not implemented on this architecture\n");
            break;
        }
        default:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_setup:"
                                                 "unknown errno = %d, errstr = %s\n",
                                                 err, strerror(err));
            break;
        }
    }

    return (EC_FALSE);
}

STATIC_CAST EC_BOOL __caio_destroy(aio_context_t ctx)
{
    /*
    *
    * ref: http://www.man7.org/linux/man-pages/man2/io_destroy.2.html
    * int io_destroy(aio_context_t ctx_id);
    *
    */

    int err;

    if(0 == syscall(__NR_io_destroy, ctx))
    {
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_destroy: done\n");
        return (EC_TRUE);
    }

    err = errno;

    switch(err)
    {
        case EFAULT:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_destroy: "
                                                 "The context %lx pointed to is invalid\n",
                                                 ctx);
            break;
        }
        case EINVAL:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_destroy: "
                                                 "The AIO context specified by ctx %lx is invalid\n",
                                                 ctx);
            break;
        }
        case ENOSYS:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_destroy: "
                                                 "io_destroy() is not implemented on this architecture\n");
            break;
        }
        default:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_destroy: "
                                                 "unknown errno = %d, errstr = %s\n",
                                                 err, strerror(err));
            break;
        }
    }

    return (EC_FALSE);
}

STATIC_CAST EC_BOOL __caio_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events, struct timespec *timeout, int *nevents)
{
    /*
    *
    * ref: http://www.man7.org/linux/man-pages/man2/io_getevents.2.html
    * int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout);
    *
    */

    int num;
    int err;

    num = syscall(__NR_io_getevents, ctx, min_nr, nr, events, timeout);
    if(0 <= num)
    {
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_getevents: num = %d\n", num);
        (*nevents) = num;
        return (EC_TRUE);
    }

    err = errno;

    switch(err)
    {
        case EFAULT:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_getevents: "
                                                 "Either events or timeout is an invalid pointer\n");
            break;
        }
        case EINTR:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_getevents: "
                                                 "Interrupted by a signal handler\n");
            break;
        }
        case EINVAL:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_getevents: "
                                                 "ctx %lx is invalid.  min_nr %ld is out of range or nr %ld is out of range\n",
                                                 ctx, min_nr, nr);
            break;
        }
        case ENOSYS:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_getevents: "
                                                 "__NR_io_getevents is not implemented on this architecture\n");
            break;
        }
        default:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_getevents: "
                                                 "unknown errno = %d, errstr = %s\n",
                                                 err, strerror(err));
            break;
        }
    }
    return (EC_FALSE);
}

STATIC_CAST EC_BOOL __caio_submit(aio_context_t ctx, long nr, long *succ_nr, struct iocb **iocbpp)
{
    /*
    *
    * ref: http://www.man7.org/linux/man-pages/man2/io_submit.2.html
    * int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
    *
    */

    long ret;
    int  err;

    if(do_log(SEC_0093_CAIO, 9))
    {
        long idx;
        for(idx = 0; idx < nr; idx ++)
        {
            struct iocb        *aiocb;

            aiocb = iocbpp[ idx ];

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: aio_data       = %p\n",
                            idx, (void *)aiocb->aio_data);

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: aio_lio_opcode = %d\n",
                            idx, aiocb->aio_lio_opcode);

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: aio_fildes     = %d\n",
                            idx, aiocb->aio_fildes);

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: buf            = %p\n",
                            idx, (void *)aiocb->aio_buf);

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: aio_nbytes     = %llu\n",
                            idx, aiocb->aio_nbytes);

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: aio_offset     = %llu\n",
                            idx, aiocb->aio_offset);

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: aio_flags      = %u\n",
                            idx, aiocb->aio_flags);

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: aiocb[ %ld ]: aio_resfd      = %d\n",
                            idx, aiocb->aio_resfd);
        }
    }

    ret = syscall(__NR_io_submit, ctx, nr, iocbpp);
    if(nr == ret || 0 < ret)
    {
        if(NULL_PTR != succ_nr)
        {
            (*succ_nr) = ret;
        }

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_submit: done\n");
        return (EC_TRUE);
    }

    if(NULL_PTR != succ_nr)
    {
        (*succ_nr) = 0;
    }

    err = errno;
    switch(err)
    {
        case EAGAIN:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_submit: "
                                                 "Insufficient resources are available to queue any iocbs\n");
            break;
        }
        case EBADF:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_submit: "
                                                 "The file descriptor specified in the first iocb is invalid\n");
            break;
        }
        case EFAULT:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_submit: "
                                                 "One of the data structures points to invalid data\n");
            break;
        }
        case EINVAL:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_submit: "
                                                 "The AIO context specified by ctx %lx is invalid\n",
                                                 ctx);
            break;
        }
        case ENOSYS:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_submit: "
                                                 "__NR_io_submit is not implemented on this architecture\n");
            break;
        }
        default:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_submit: "
                                                 "unknown errno = %d, errstr = %s\n",
                                                 err, strerror(err));
            break;
        }
    }
    return (EC_FALSE);
}

STATIC_CAST EC_BOOL __caio_cancel(aio_context_t ctx, struct iocb *iocb, struct io_event *event)
{
    /*
    *
    * ref: http://www.man7.org/linux/man-pages/man2/io_cancel.2.html
    * int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
    *
    */

    int err;

    if(0 == syscall(__NR_io_cancel, ctx, iocb, event))
    {
        dbg_log(SEC_0093_CAIO, 1)(LOGSTDOUT, "[DEBUG] __caio_cancel: done\n");
        return (EC_TRUE);
    }

    err = errno;

    switch(err)
    {
        case EAGAIN:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_cancel: "
                                                 "The iocb specified was not canceled\n");
            break;
        }
        case EFAULT:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_cancel: "
                                                 "One of the data structures points to invalid data\n");
            break;
        }
        case EINVAL:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_cancel: "
                                                 "The AIO context specified by ctx %lx is invalid\n",
                                                 ctx);
            break;
        }
        case ENOSYS:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_cancel: "
                                                 "io_cancel() is not implemented on this architecture\n");
            break;
        }
        default:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_cancel: "
                                                 "unknown errno = %d, errstr = %s\n",
                                                 err, strerror(err));
            break;
        }
    }

    return (EC_FALSE);
}

/*----------------------------------- caio cfg interface -----------------------------------*/

STATIC_CAST const char *__caio_cfg_model_str(const UINT32 model)
{
    if(model < g_caio_cfg_len)
    {
        return CAIO_CFG_MODEL_STR(&g_caio_cfg_tbl[ model ]);
    }

    return ((const char *)"UNKNOWN");
}

STATIC_CAST const char *__caio_cfg_model_alias_str(const UINT32 model)
{
    if(model < g_caio_cfg_len)
    {
        return CAIO_CFG_ALIAS_STR(&g_caio_cfg_tbl[ model ]);
    }

    return ((const char *)"UNKNOWN");
}

STATIC_CAST EC_BOOL __caio_cfg_model_is_valid(const UINT32 model)
{
    if(model < g_caio_cfg_len)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST const CAIO_CFG *__caio_cfg_fetch(const UINT32 model)
{
    if(model < g_caio_cfg_len)
    {
        return &(g_caio_cfg_tbl[ model ]);
    }

    return (NULL_PTR);
}

STATIC_CAST void __caio_cfg_print(LOG *log, const CAIO_CFG *caio_cfg)
{
    if(NULL_PTR != caio_cfg)
    {
        sys_log(log, "__caio_cfg_print: caio_cfg %p: model %s, alias %s, nbits %ld, nbytes %ld, mask 0x%lx\n",
                     caio_cfg,
                     CAIO_CFG_MODEL_STR(caio_cfg),
                     CAIO_CFG_ALIAS_STR(caio_cfg),
                     CAIO_CFG_BLOCK_SIZE_NBITS(caio_cfg),
                     CAIO_CFG_BLOCK_SIZE_NBYTES(caio_cfg),
                     CAIO_CFG_BLOCK_SIZE_MASK(caio_cfg));
    }
    else
    {
        sys_log(log, "__caio_cfg_print: caio_cfg is null\n");
    }
    return;
}


STATIC_CAST const char *__caio_op_str(const UINT32 op)
{
    if(CAIO_OP_RD == op)
    {
        return ((const char *)"RD");
    }

    if(CAIO_OP_WR == op)
    {
        return ((const char *)"WR");
    }

    if(CAIO_OP_RW == op)
    {
        return ((const char *)"RW");
    }

    if(CAIO_OP_ERR == op)
    {
        return ((const char *)"ERR");
    }

    return ((const char *)"UNKNOWN");
}

/*----------------------------------- caio mem cache (posix memalign) interface -----------------------------------*/
static UINT32 g_caio_mem_cache_counter = 0;
static UINT8 *g_caio_mem_cache_tab[ CAIO_MEM_CACHE_MAX_NUM] = {NULL_PTR};

#if 0
STATIC_CAST static UINT8 *__caio_mem_cache_new(const UINT32 size, const UINT32 align)
{
    if(g_caio_mem_cache_counter < CAIO_MEM_CACHE_MAX_NUM)
    {
        UINT8    *mem_cache;

        mem_cache = (UINT8 *)c_memalign_new(size, align);
        if(NULL_PTR == mem_cache)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_mem_cache_new: alloc memory failed\n");

            return (NULL_PTR);
        }

        rlog(SEC_0093_CAIO, 8)(LOGSTDOUT, "[DEBUG] __caio_mem_cache_new: mem_cache = %p\n", mem_cache);
        g_caio_mem_cache_counter ++;

        return (mem_cache);
    }

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_mem_cache_new: counter %ld reached max\n",
                                         g_caio_mem_cache_counter);
    return (NULL_PTR);
}

STATIC_CAST static EC_BOOL __caio_mem_cache_free(UINT8 *mem_cache)
{
    if(NULL_PTR != mem_cache)
    {
        rlog(SEC_0093_CAIO, 8)(LOGSTDOUT, "[DEBUG] __caio_mem_cache_free: mem_cache = %p\n", mem_cache);
        c_memalign_free(mem_cache);
        g_caio_mem_cache_counter --;
    }
    return (EC_TRUE);
}
#endif

#if 1
STATIC_CAST static UINT8 *__caio_mem_cache_new(const UINT32 size, const UINT32 align)
{
    UINT8    *mem_cache;

    if(0 < g_caio_mem_cache_counter)
    {
        mem_cache = g_caio_mem_cache_tab[ -- g_caio_mem_cache_counter ];

        ASSERT(NULL_PTR != mem_cache);

        return (mem_cache);
    }

    mem_cache = (UINT8 *)c_memalign_new(size, align);
    if(NULL_PTR == mem_cache)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_mem_cache_new: alloc memory failed\n");

        return (NULL_PTR);
    }

    return (mem_cache);
}

STATIC_CAST static EC_BOOL __caio_mem_cache_free(UINT8 *mem_cache)
{
    if(NULL_PTR != mem_cache)
    {
        if(CAIO_MEM_CACHE_MAX_NUM <= g_caio_mem_cache_counter)
        {
            c_memalign_free(mem_cache);
        }
        else
        {
            g_caio_mem_cache_tab[ g_caio_mem_cache_counter ++ ] = mem_cache;
        }
    }
    return (EC_TRUE);
}
#endif

STATIC_CAST static EC_BOOL __caio_mem_cache_check(UINT8 *mem_cache, const UINT32 align)
{
    UINT32      addr;
    UINT32      mask;

    addr = ((UINT32)mem_cache);
    mask = (align - 1);

    if(0 == (addr & mask))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void caio_mem_cache_counter_print(LOG *log)
{
    sys_log(log, "g_caio_mem_cache_counter: %ld\n", g_caio_mem_cache_counter);
}


/*----------------------------------- caio callback interface -----------------------------------*/

EC_BOOL caio_cb_handler_init(CAIO_CB_HANDLER *caio_cb_handler)
{
    CAIO_CB_HANDLER_FUNC(caio_cb_handler)   = NULL_PTR;
    CAIO_CB_HANDLER_ARG(caio_cb_handler)    = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL caio_cb_handler_clean(CAIO_CB_HANDLER *caio_cb_handler)
{
    CAIO_CB_HANDLER_FUNC(caio_cb_handler)   = NULL_PTR;
    CAIO_CB_HANDLER_ARG(caio_cb_handler)    = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL caio_cb_handler_set(CAIO_CB_HANDLER *caio_cb_handler, CAIO_CALLBACK func, void *arg)
{
    if(NULL_PTR != caio_cb_handler)
    {
        CAIO_CB_HANDLER_FUNC(caio_cb_handler)   = func;
        CAIO_CB_HANDLER_ARG(caio_cb_handler)    = arg;

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL caio_cb_handler_clone(const CAIO_CB_HANDLER *caio_cb_handler_src, CAIO_CB_HANDLER *caio_cb_handler_des)
{
    if(NULL_PTR != caio_cb_handler_src && NULL_PTR != caio_cb_handler_des)
    {
        CAIO_CB_HANDLER_FUNC(caio_cb_handler_des)   = CAIO_CB_HANDLER_FUNC(caio_cb_handler_src);
        CAIO_CB_HANDLER_ARG(caio_cb_handler_des)    = CAIO_CB_HANDLER_ARG(caio_cb_handler_src);

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void caio_cb_handler_print(LOG *log, const CAIO_CB_HANDLER *caio_cb_handler)
{
    sys_log(log, "caio_cb_handler_print: func %p, arg %p \n",
                 CAIO_CB_HANDLER_FUNC(caio_cb_handler),
                 CAIO_CB_HANDLER_ARG(caio_cb_handler));

    return;
}

EC_BOOL caio_cb_handler_exec(CAIO_CB_HANDLER *caio_cb_handler)
{
    if(NULL_PTR != caio_cb_handler && NULL_PTR != CAIO_CB_HANDLER_FUNC(caio_cb_handler))
    {
        return CAIO_CB_HANDLER_FUNC(caio_cb_handler)(CAIO_CB_HANDLER_ARG(caio_cb_handler));
    }

    return (EC_TRUE);
}

EC_BOOL caio_cb_init(CAIO_CB *caio_cb)
{
    CAIO_CB_TIMEOUT_NSEC(caio_cb) = 0;
    caio_cb_handler_init(CAIO_CB_TIMEOUT_HANDLER(caio_cb));
    caio_cb_handler_init(CAIO_CB_TERMINATE_HANDLER(caio_cb));
    caio_cb_handler_init(CAIO_CB_COMPLETE_HANDLER(caio_cb));

    return (EC_TRUE);
}

EC_BOOL caio_cb_clean(CAIO_CB *caio_cb)
{
    CAIO_CB_TIMEOUT_NSEC(caio_cb) = 0;
    caio_cb_handler_clean(CAIO_CB_TIMEOUT_HANDLER(caio_cb));
    caio_cb_handler_clean(CAIO_CB_TERMINATE_HANDLER(caio_cb));
    caio_cb_handler_clean(CAIO_CB_COMPLETE_HANDLER(caio_cb));

    return (EC_TRUE);
}

EC_BOOL caio_cb_set_timeout_handler(CAIO_CB *caio_cb, const UINT32 timeout_nsec, CAIO_CALLBACK func, void *arg)
{
    if(NULL_PTR != caio_cb)
    {
        CAIO_CB_TIMEOUT_NSEC(caio_cb) = timeout_nsec;
        return caio_cb_handler_set(CAIO_CB_TIMEOUT_HANDLER(caio_cb), func, arg);
    }

    return (EC_FALSE);
}

EC_BOOL caio_cb_set_terminate_handler(CAIO_CB *caio_cb, CAIO_CALLBACK func, void *arg)
{
    if(NULL_PTR != caio_cb)
    {
        return caio_cb_handler_set(CAIO_CB_TERMINATE_HANDLER(caio_cb), func, arg);
    }

    return (EC_FALSE);
}

EC_BOOL caio_cb_set_complete_handler(CAIO_CB *caio_cb, CAIO_CALLBACK func, void *arg)
{
    if(NULL_PTR != caio_cb)
    {
        return caio_cb_handler_set(CAIO_CB_COMPLETE_HANDLER(caio_cb), func, arg);
    }

    return (EC_FALSE);
}

EC_BOOL caio_cb_exec_timeout_handler(CAIO_CB *caio_cb)
{
    if(NULL_PTR != caio_cb)
    {
        return caio_cb_handler_exec(CAIO_CB_TIMEOUT_HANDLER(caio_cb));
    }

    return (EC_FALSE);
}

EC_BOOL caio_cb_exec_terminate_handler(CAIO_CB *caio_cb)
{
    if(NULL_PTR != caio_cb)
    {
        return caio_cb_handler_exec(CAIO_CB_TERMINATE_HANDLER(caio_cb));
    }

    return (EC_FALSE);
}

EC_BOOL caio_cb_exec_complete_handler(CAIO_CB *caio_cb)
{
    if(NULL_PTR != caio_cb)
    {
        return caio_cb_handler_exec(CAIO_CB_COMPLETE_HANDLER(caio_cb));
    }

    return (EC_FALSE);
}

EC_BOOL caio_cb_clone(const CAIO_CB *caio_cb_src, CAIO_CB *caio_cb_des)
{
    if(NULL_PTR == caio_cb_src || NULL_PTR == caio_cb_des)
    {
        return (EC_FALSE);
    }

    CAIO_CB_TIMEOUT_NSEC(caio_cb_des) = CAIO_CB_TIMEOUT_NSEC(caio_cb_src);

    if(EC_FALSE == caio_cb_handler_clone(CAIO_CB_TERMINATE_HANDLER(caio_cb_src),
                                          CAIO_CB_TERMINATE_HANDLER(caio_cb_des)))
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == caio_cb_handler_clone(CAIO_CB_TIMEOUT_HANDLER(caio_cb_src),
                                          CAIO_CB_TIMEOUT_HANDLER(caio_cb_des)))
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == caio_cb_handler_clone(CAIO_CB_COMPLETE_HANDLER(caio_cb_src),
                                          CAIO_CB_COMPLETE_HANDLER(caio_cb_des)))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void caio_cb_print(LOG *log, const CAIO_CB *caio_cb)
{
    sys_log(log, "caio_cb_print: caio_cb %p: terminate_handler: \n", caio_cb);
    caio_cb_handler_print(log, CAIO_CB_TERMINATE_HANDLER(caio_cb));

    sys_log(log, "caio_cb_print: caio_cb %p: timeout_nsec %ld, timeout_handler: \n",
                 caio_cb, CAIO_CB_TIMEOUT_NSEC(caio_cb));
    caio_cb_handler_print(log, CAIO_CB_TIMEOUT_HANDLER(caio_cb));

    sys_log(log, "caio_cb_print: caio_cb %p: complete_handler: \n", caio_cb);
    caio_cb_handler_print(log, CAIO_CB_COMPLETE_HANDLER(caio_cb));

    return;
}

/*----------------------------------- caio disk interface -----------------------------------*/

CAIO_DISK *caio_disk_new()
{
    CAIO_DISK *caio_disk;

    alloc_static_mem(MM_CAIO_DISK, &caio_disk, LOC_CAIO_0001);
    if(NULL_PTR == caio_disk)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_disk_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    caio_disk_init(caio_disk);
    return (caio_disk);
}

EC_BOOL caio_disk_init(CAIO_DISK *caio_disk)
{
    CAIO_DISK_FD(caio_disk)                     = ERR_FD;
    CAIO_DISK_MAX_REQ_NUM(caio_disk)            = NULL_PTR;
    CAIO_DISK_CUR_REQ_NUM(caio_disk)            = 0;
    CAIO_DISK_BAD_BITMAP(caio_disk)             = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL caio_disk_clean(CAIO_DISK *caio_disk)
{
    if(NULL_PTR != caio_disk)
    {
        CAIO_DISK_FD(caio_disk)                     = ERR_FD;
        CAIO_DISK_MAX_REQ_NUM(caio_disk)            = NULL_PTR;
        CAIO_DISK_CUR_REQ_NUM(caio_disk)            = 0;
        CAIO_DISK_BAD_BITMAP(caio_disk)             = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL caio_disk_free(CAIO_DISK *caio_disk)
{
    if(NULL_PTR != caio_disk)
    {
        caio_disk_clean(caio_disk);
        free_static_mem(MM_CAIO_DISK, caio_disk, LOC_CAIO_0002);
    }
    return (EC_TRUE);
}

void caio_disk_print(LOG *log, const CAIO_DISK *caio_disk)
{
    sys_log(log, "caio_disk_print: caio_disk %p: fd %d, max req num %ld, cur req num %ld, bad bitmap %p\n",
                 caio_disk,
                 CAIO_DISK_FD(caio_disk),
                 NULL_PTR != CAIO_DISK_MAX_REQ_NUM(caio_disk) ? *(CAIO_DISK_MAX_REQ_NUM(caio_disk)): (UINT32)-1,
                 CAIO_DISK_CUR_REQ_NUM(caio_disk),
                 CAIO_DISK_BAD_BITMAP(caio_disk));

    return;
}

EC_BOOL caio_disk_is_fd(const CAIO_DISK *caio_disk, const int fd)
{
    if(fd == CAIO_DISK_FD(caio_disk))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL caio_disk_set_bad_page(CAIO_DISK *caio_disk, const uint32_t page_no)
{
    if(NULL_PTR != caio_disk
    && NULL_PTR != CAIO_DISK_BAD_BITMAP(caio_disk)
    && CAIO_PAGE_NO_ERR != page_no)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_disk_set_bad_page: "
                                             "set disk bad page: fd %d, page %u\n",
                                             CAIO_DISK_FD(caio_disk), page_no);

        if(EC_FALSE == cbad_bitmap_set(CAIO_DISK_BAD_BITMAP(caio_disk), page_no))
        {
            return (EC_FALSE);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL caio_disk_clear_bad_page(CAIO_DISK *caio_disk, const uint32_t page_no)
{
    if(NULL_PTR != caio_disk
    && NULL_PTR != CAIO_DISK_BAD_BITMAP(caio_disk)
    && CAIO_PAGE_NO_ERR != page_no)
    {
        return cbad_bitmap_clear(CAIO_DISK_BAD_BITMAP(caio_disk), page_no);
    }

    return (EC_FALSE);
}

EC_BOOL caio_disk_check_bad_page(CAIO_DISK *caio_disk, const uint32_t page_no)
{
    if(NULL_PTR != caio_disk
    && NULL_PTR != CAIO_DISK_BAD_BITMAP(caio_disk)
    && CAIO_PAGE_NO_ERR != page_no)
    {
        return cbad_bitmap_is(CAIO_DISK_BAD_BITMAP(caio_disk), page_no, (uint8_t)1);
    }

    return (EC_FALSE);
}


/*----------------------------------- caio page interface -----------------------------------*/

CAIO_PAGE *caio_page_new()
{
    CAIO_PAGE *caio_page;

    alloc_static_mem(MM_CAIO_PAGE, &caio_page, LOC_CAIO_0003);
    if(NULL_PTR == caio_page)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_page_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    caio_page_init(caio_page);
    return (caio_page);
}

EC_BOOL caio_page_init(CAIO_PAGE *caio_page)
{
    BSET(CAIO_PAGE_AIOCB(caio_page), 0, sizeof(struct iocb));

    CAIO_PAGE_WORKING_FLAG(caio_page)       = BIT_FALSE;
    CAIO_PAGE_MEM_CACHE_FLAG(caio_page)     = BIT_FALSE;

    CAIO_PAGE_FD(caio_page)                 = ERR_FD;

    CAIO_PAGE_F_S_OFFSET(caio_page)         = 0;
    CAIO_PAGE_F_E_OFFSET(caio_page)         = 0;
    CAIO_PAGE_NO(caio_page)                 = CAIO_PAGE_NO_ERR;

    CAIO_PAGE_OP(caio_page)                 = CAIO_OP_ERR;

    CAIO_PAGE_M_CACHE(caio_page)            = NULL_PTR;

    CAIO_PAGE_CAIO_MD(caio_page)            = NULL_PTR;
    CAIO_PAGE_CAIO_DISK(caio_page)          = NULL_PTR;

    CAIO_PAGE_MOUNTED_PAGES(caio_page)      = NULL_PTR;
    CAIO_PAGE_MOUNTED_LIST_IDX(caio_page)   = CAIO_PAGE_LIST_IDX_ERR;

    clist_init(CAIO_PAGE_OWNERS(caio_page), MM_CAIO_NODE, LOC_CAIO_0004);

    return (EC_TRUE);
}

EC_BOOL caio_page_clean(CAIO_PAGE *caio_page)
{
    if(NULL_PTR != caio_page)
    {
        /*clean up owners*/
        caio_page_cleanup_nodes(caio_page);

        if(NULL_PTR != CAIO_PAGE_M_CACHE(caio_page))
        {
            if(BIT_FALSE == CAIO_PAGE_MEM_CACHE_FLAG(caio_page))
            {
                c_memalign_free(CAIO_PAGE_M_CACHE(caio_page));
            }
            else
            {
                __caio_mem_cache_free(CAIO_PAGE_M_CACHE(caio_page));
            }

            CAIO_PAGE_M_CACHE(caio_page) = NULL_PTR;
        }

        if(NULL_PTR != CAIO_PAGE_MOUNTED_PAGES(caio_page)
        && NULL_PTR != CAIO_PAGE_CAIO_MD(caio_page)
        && CAIO_PAGE_LIST_IDX_ERR != CAIO_PAGE_MOUNTED_LIST_IDX(caio_page))
        {
            CAIO_MD     *caio_md;

            caio_md = CAIO_PAGE_CAIO_MD(caio_page);
            caio_del_page(caio_md, CAIO_PAGE_MOUNTED_LIST_IDX(caio_page), caio_page);
        }

        CAIO_PAGE_WORKING_FLAG(caio_page)       = BIT_FALSE;
        CAIO_PAGE_MEM_CACHE_FLAG(caio_page)     = BIT_FALSE;

        CAIO_PAGE_FD(caio_page)                 = ERR_FD;

        CAIO_PAGE_F_S_OFFSET(caio_page)         = 0;
        CAIO_PAGE_F_E_OFFSET(caio_page)         = 0;
        CAIO_PAGE_NO(caio_page)                 = CAIO_PAGE_NO_ERR;

        CAIO_PAGE_OP(caio_page)                 = CAIO_OP_ERR;

        CAIO_PAGE_CAIO_MD(caio_page)            = NULL_PTR;
        CAIO_PAGE_CAIO_DISK(caio_page)          = NULL_PTR;

        BSET(CAIO_PAGE_AIOCB(caio_page), 0, sizeof(struct iocb));
    }

    return (EC_TRUE);
}

EC_BOOL caio_page_free(CAIO_PAGE *caio_page)
{
    if(NULL_PTR != caio_page)
    {
        caio_page_clean(caio_page);
        free_static_mem(MM_CAIO_PAGE, caio_page, LOC_CAIO_0005);
    }
    return (EC_TRUE);
}

void caio_page_print(LOG *log, const CAIO_PAGE *caio_page)
{
    sys_log(log, "caio_page_print: caio_page %p: page range [%ld, %ld), "
                 "m_cache %p, mounted pages %p, mounted page list %ld\n",
                 caio_page,
                 CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                 CAIO_PAGE_M_CACHE(caio_page),
                 CAIO_PAGE_MOUNTED_PAGES(caio_page),
                 CAIO_PAGE_MOUNTED_LIST_IDX(caio_page));

    sys_log(log, "caio_page_print: caio_page %p: owners:\n", caio_page);
    clist_print(log, CAIO_PAGE_OWNERS(caio_page), (CLIST_DATA_DATA_PRINT)caio_node_print);

    return;
}

void caio_page_print_range(LOG *log, const CAIO_PAGE *caio_page)
{
    sys_log(log, "caio_page_print_range: caio_page %p: [%ld, %ld)\n",
                 caio_page,
                 CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page));

    return;
}

/**
 *  note:
 *      caio request comes from CAMD or CDC which indicates that
 *      caio request may be for sata access or ssd access.
 *      therefore, caio_page_cmp should distinguish fd as well as [start offset, end offset)
 *
**/
EC_BOOL caio_page_cmp(const CAIO_PAGE *caio_page_1st, const CAIO_PAGE *caio_page_2nd)
{
    if(CAIO_PAGE_FD(caio_page_1st) == CAIO_PAGE_FD(caio_page_2nd)
    && CAIO_PAGE_F_S_OFFSET(caio_page_1st) == CAIO_PAGE_F_S_OFFSET(caio_page_2nd)
    && CAIO_PAGE_F_E_OFFSET(caio_page_1st) == CAIO_PAGE_F_E_OFFSET(caio_page_2nd))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL caio_page_add_node(CAIO_PAGE *caio_page, CAIO_NODE *caio_node)
{
    CAIO_ASSERT(NULL_PTR == CAIO_NODE_MOUNTED_OWNERS(caio_node));

    /*mount*/
    CAIO_NODE_MOUNTED_OWNERS(caio_node) = clist_push_back(CAIO_PAGE_OWNERS(caio_page), (void *)caio_node);
    if(NULL_PTR == CAIO_NODE_MOUNTED_OWNERS(caio_node))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_page_add_node: "
                         "add node %ld/%ld of req %ld, "
                         "block range [%ld, %ld), file range [%ld, %ld) op %s "
                         "to page [%ld, %ld) failed\n",
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node),
                         CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                         CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                         __caio_op_str(CAIO_NODE_OP(caio_node)),
                         CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page));
        return (EC_FALSE);
    }

    CAIO_NODE_CAIO_PAGE(caio_node) = caio_page; /*bind*/

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_page_add_node: "
                     "add node (%p) %ld/%ld of req %ld, "
                     "block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "to page [%ld, %ld) done\n", caio_node,
                     CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                     CAIO_NODE_SEQ_NO(caio_node),
                     CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                     CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                     __caio_op_str(CAIO_NODE_OP(caio_node)),
                     CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page));

    return (EC_TRUE);
}

EC_BOOL caio_page_del_node(CAIO_PAGE *caio_page, CAIO_NODE *caio_node)
{
    CAIO_ASSERT(NULL_PTR != CAIO_NODE_MOUNTED_OWNERS(caio_node));

    clist_erase(CAIO_PAGE_OWNERS(caio_page), CAIO_NODE_MOUNTED_OWNERS(caio_node));
    CAIO_NODE_MOUNTED_OWNERS(caio_node) = NULL_PTR; /*umount*/
    CAIO_NODE_CAIO_PAGE(caio_node)      = NULL_PTR; /*unbind*/

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_page_del_node: "
                     "del node (%p) %ld/%ld of req %ld, "
                     "block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "from page [%ld, %ld) done\n", caio_node,
                     CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                     CAIO_NODE_SEQ_NO(caio_node),
                     CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                     CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                     __caio_op_str(CAIO_NODE_OP(caio_node)),
                     CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page));

    return (EC_TRUE);
}

CAIO_NODE *caio_page_first_node(CAIO_PAGE *caio_page)
{
    return (CAIO_NODE *)clist_first_data(CAIO_PAGE_OWNERS(caio_page));
}

EC_BOOL caio_page_cleanup_nodes(CAIO_PAGE *caio_page)
{
    CAIO_NODE       *caio_node;

    /*clean up owners*/
    while(NULL_PTR != (caio_node = caio_page_pop_node_back(caio_page)))
    {
        caio_node_free(caio_node);
    }

    return (EC_TRUE);
}

CAIO_NODE *caio_page_pop_node_front(CAIO_PAGE *caio_page)
{
    CAIO_NODE *caio_node;

    caio_node = clist_pop_front(CAIO_PAGE_OWNERS(caio_page));
    if(NULL_PTR == caio_node)
    {
        return (NULL_PTR);
    }

    CAIO_NODE_MOUNTED_OWNERS(caio_node) = NULL_PTR; /*umount*/
    CAIO_NODE_CAIO_PAGE(caio_node)      = NULL_PTR; /*ubind*/

    return (caio_node);
}

CAIO_NODE *caio_page_pop_node_back(CAIO_PAGE *caio_page)
{
    CAIO_NODE *caio_node;

    caio_node = clist_pop_back(CAIO_PAGE_OWNERS(caio_page));
    if(NULL_PTR == caio_node)
    {
        return (NULL_PTR);
    }

    CAIO_NODE_MOUNTED_OWNERS(caio_node) = NULL_PTR; /*umount*/
    CAIO_NODE_CAIO_PAGE(caio_node)      = NULL_PTR; /*ubind*/

    return (caio_node);
}

EC_BOOL caio_page_terminate(CAIO_PAGE *caio_page)
{
    CAIO_NODE       *caio_node;

    dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_page_terminate: "
                     "page [%ld, %ld), fd %d terminate nodes\n",
                     CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                     CAIO_PAGE_FD(caio_page));

    while(NULL_PTR != (caio_node = caio_page_pop_node_front(caio_page)))
    {
        caio_node_terminate(caio_node);
    }

    caio_page_free(caio_page);

    return (EC_TRUE);
}

EC_BOOL caio_page_complete(CAIO_PAGE *caio_page)
{
    CAIO_MD         *caio_md;
    CAIO_NODE       *caio_node;
    UINT32           dirty_flag;

    dirty_flag = BIT_FALSE;

    while(NULL_PTR != (caio_node = caio_page_pop_node_front(caio_page)))
    {
        CAIO_ASSERT(CAIO_NODE_FD(caio_node) == CAIO_PAGE_FD(caio_page));
        if(CAIO_OP_RD == CAIO_NODE_OP(caio_node))
        {
            CAIO_ASSERT(NULL_PTR != CAIO_PAGE_M_CACHE(caio_page));

            if(NULL_PTR != CAIO_NODE_M_BUFF(caio_node))
            {
                dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_page_complete: "
                                "[RD] node %ld/%ld of req %ld, "
                                "copy from page [%ld, %ld), fd %d to app cache [%ld, %ld)\n",
                                CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                                CAIO_NODE_SEQ_NO(caio_node),
                                CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                                CAIO_NODE_FD(caio_node),
                                CAIO_NODE_F_S_OFFSET(caio_node),
                                CAIO_NODE_F_E_OFFSET(caio_node));

                /*copy data from mem cache to application mem buff*/
                FCOPY(CAIO_PAGE_M_CACHE(caio_page) + CAIO_NODE_B_S_OFFSET(caio_node),
                      CAIO_NODE_M_BUFF(caio_node),
                      CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node));
            }
            else
            {
                dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_page_complete: "
                                "[RD] node %ld/%ld of req %ld, "
                                "ignore copy from page [%ld, %ld), fd %d to app cache [%ld, %ld)\n",
                                CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                                CAIO_NODE_SEQ_NO(caio_node),
                                CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                                CAIO_NODE_FD(caio_node),
                                CAIO_NODE_F_S_OFFSET(caio_node),
                                CAIO_NODE_F_E_OFFSET(caio_node));
            }

            caio_node_complete(caio_node);
        }

        else if(CAIO_OP_WR == CAIO_NODE_OP(caio_node))
        {
            CAIO_ASSERT(NULL_PTR != CAIO_PAGE_M_CACHE(caio_page));
            CAIO_ASSERT(NULL_PTR != CAIO_NODE_M_BUFF(caio_node));

            dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_page_complete: "
                            "[WR] node %ld/%ld of req %ld, "
                            "copy from app [%ld, %ld) to page [%ld, %ld), fd %d\n",
                            CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                            CAIO_NODE_SEQ_NO(caio_node),
                            CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                            CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                            CAIO_NODE_FD(caio_node));

            /*copy data from application mem buff to mem cache*/
            FCOPY(CAIO_NODE_M_BUFF(caio_node),
                  CAIO_PAGE_M_CACHE(caio_page) + CAIO_NODE_B_S_OFFSET(caio_node),
                  CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node));

            caio_node_complete(caio_node);

            dirty_flag = BIT_TRUE; /*set dirty*/
        }
        else
        {
            /*should never reach here*/
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_page_complete: "
                             "invalid op: node %ld/%ld of req %ld, "
                             "block range [%ld, %ld), file range [%ld, %ld) op %s "
                             "in page [%ld, %ld)\n",
                             CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                             CAIO_NODE_SEQ_NO(caio_node),
                             CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                             CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                             __caio_op_str(CAIO_NODE_OP(caio_node)),
                             CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page));

            caio_node_free(caio_node);
            caio_page_free(caio_page);
            return (EC_FALSE);
        }
    }

    if(BIT_FALSE == dirty_flag)
    {
        dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_page_complete: "
                         "process page %s, [%ld, %ld), fd %d done\n",
                         __caio_op_str(CAIO_PAGE_OP(caio_page)),
                         CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                         CAIO_PAGE_FD(caio_page));

        caio_page_free(caio_page);
        return (EC_TRUE);
    }

    CAIO_PAGE_WORKING_FLAG(caio_page) = BIT_FALSE;/*clear*/

    /*add page to caio module again*/
    CAIO_PAGE_OP(caio_page) = CAIO_OP_WR;  /*reset flag*/
    caio_md = CAIO_PAGE_CAIO_MD(caio_page);
    if(EC_FALSE == caio_add_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), caio_page))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_page_complete: "
                         "add page [%ld, %ld), fd %d to caio module failed\n",
                         CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                         CAIO_PAGE_FD(caio_page));


        caio_page_free(caio_page);
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_page_complete: "
                     "add page [%ld, %ld), fd %d to caio module done\n",
                     CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                     CAIO_PAGE_FD(caio_page));
    return (EC_TRUE);
}

/*----------------------------------- caio node interface -----------------------------------*/

CAIO_NODE *caio_node_new()
{
    CAIO_NODE *caio_node;

    alloc_static_mem(MM_CAIO_NODE, &caio_node, LOC_CAIO_0006);
    if(NULL_PTR == caio_node)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_node_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    caio_node_init(caio_node);
    return (caio_node);
}

EC_BOOL caio_node_init(CAIO_NODE *caio_node)
{
    CAIO_NODE_CAIO_REQ(caio_node)       = NULL_PTR;
    CAIO_NODE_CAIO_PAGE(caio_node)      = NULL_PTR;

    CAIO_NODE_SEQ_NO(caio_node)         = 0;
    CAIO_NODE_SUB_SEQ_NO(caio_node)     = 0;
    CAIO_NODE_SUB_SEQ_NUM(caio_node)    = 0;
    CAIO_NODE_OP(caio_node)             = CAIO_OP_ERR;

    CAIO_NODE_CAIO_MD(caio_node)        = NULL_PTR;
    CAIO_NODE_FD(caio_node)             = ERR_FD;
    CAIO_NODE_M_CACHE(caio_node)        = NULL_PTR;
    CAIO_NODE_M_BUFF(caio_node)         = NULL_PTR;
    CAIO_NODE_F_S_OFFSET(caio_node)     = 0;
    CAIO_NODE_F_E_OFFSET(caio_node)     = 0;
    CAIO_NODE_B_S_OFFSET(caio_node)     = 0;
    CAIO_NODE_B_E_OFFSET(caio_node)     = 0;
    CAIO_NODE_TIMEOUT_NSEC(caio_node)   = 0;
    CAIO_NODE_NTIME_MS(caio_node)       = 0;

    CAIO_NODE_MOUNTED_NODES(caio_node)  = NULL_PTR;
    CAIO_NODE_MOUNTED_OWNERS(caio_node) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL caio_node_clean(CAIO_NODE *caio_node)
{
    if(NULL_PTR != caio_node)
    {
        if(NULL_PTR != CAIO_NODE_MOUNTED_NODES(caio_node)
        && NULL_PTR != CAIO_NODE_CAIO_REQ(caio_node))
        {
            caio_req_del_node(CAIO_NODE_CAIO_REQ(caio_node), caio_node);
        }

        if(NULL_PTR != CAIO_NODE_MOUNTED_OWNERS(caio_node)
        && NULL_PTR != CAIO_NODE_CAIO_PAGE(caio_node))
        {
            caio_page_del_node(CAIO_NODE_CAIO_PAGE(caio_node), caio_node);
        }

        CAIO_NODE_CAIO_REQ(caio_node)       = NULL_PTR;
        CAIO_NODE_CAIO_PAGE(caio_node)      = NULL_PTR;

        CAIO_NODE_SEQ_NO(caio_node)         = 0;
        CAIO_NODE_SUB_SEQ_NO(caio_node)     = 0;
        CAIO_NODE_SUB_SEQ_NUM(caio_node)    = 0;
        CAIO_NODE_OP(caio_node)             = CAIO_OP_ERR;

        CAIO_NODE_CAIO_MD(caio_node)        = NULL_PTR;
        CAIO_NODE_FD(caio_node)             = ERR_FD;
        CAIO_NODE_M_CACHE(caio_node)        = NULL_PTR;
        CAIO_NODE_M_BUFF(caio_node)         = NULL_PTR;
        CAIO_NODE_F_S_OFFSET(caio_node)     = 0;
        CAIO_NODE_F_E_OFFSET(caio_node)     = 0;
        CAIO_NODE_B_S_OFFSET(caio_node)     = 0;
        CAIO_NODE_B_E_OFFSET(caio_node)     = 0;
        CAIO_NODE_TIMEOUT_NSEC(caio_node)   = 0;
        CAIO_NODE_NTIME_MS(caio_node)       = 0;
    }

    return (EC_TRUE);
}

EC_BOOL caio_node_free(CAIO_NODE *caio_node)
{
    if(NULL_PTR != caio_node)
    {
        caio_node_clean(caio_node);
        free_static_mem(MM_CAIO_NODE, caio_node, LOC_CAIO_0007);
    }
    return (EC_TRUE);
}

EC_BOOL caio_node_is(const CAIO_NODE *caio_node, const UINT32 sub_seq_no)
{
    if(sub_seq_no == CAIO_NODE_SUB_SEQ_NO(caio_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void caio_node_print(LOG *log, const CAIO_NODE *caio_node)
{
    sys_log(log, "caio_node_print: caio_node %p: req %p, mounted at %p\n",
                 caio_node,
                 CAIO_NODE_CAIO_REQ(caio_node), CAIO_NODE_MOUNTED_NODES(caio_node));

    sys_log(log, "caio_node_print: caio_node %p: page %p, mounted at %p\n",
                 caio_node,
                 CAIO_NODE_CAIO_PAGE(caio_node), CAIO_NODE_MOUNTED_OWNERS(caio_node));

    sys_log(log, "caio_node_print: caio_node %p: seq no %ld, sub seq no %ld, sub seq num %ld, op %s\n",
                 caio_node,
                 CAIO_NODE_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NO(caio_node),
                 CAIO_NODE_SUB_SEQ_NUM(caio_node),
                 __caio_op_str(CAIO_NODE_OP(caio_node)));

    sys_log(log, "caio_node_print: caio_node %p: fd %d, m_cache %p, m_buff %p, "
                 "file range [%ld, %ld), block range [%ld, %ld), "
                 "timeout %ld seconds, next access time %ld\n",
                 caio_node, CAIO_NODE_FD(caio_node),
                 CAIO_NODE_M_CACHE(caio_node), CAIO_NODE_M_BUFF(caio_node),
                 CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                 CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                 CAIO_NODE_TIMEOUT_NSEC(caio_node), CAIO_NODE_NTIME_MS(caio_node));

    return;
}

EC_BOOL caio_node_timeout(CAIO_NODE *caio_node)
{
    CAIO_REQ        *caio_req;

    if(do_log(SEC_0093_CAIO, 9))
    {
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_node_timeout: "
                         "node %ld/%ld of req %ld => timeout\n",
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node));
        caio_node_print(LOGSTDOUT, caio_node);

        caio_req_print(LOGSTDOUT, CAIO_NODE_CAIO_REQ(caio_node));
    }

    /*exception*/
    if(NULL_PTR == CAIO_NODE_CAIO_REQ(caio_node))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_node_timeout: "
                         "node %ld/%ld of req %ld => timeout but req is null => free caio_node\n",
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node));

        caio_node_free(caio_node);
        return (EC_TRUE);
    }

    CAIO_ASSERT(NULL_PTR != CAIO_NODE_CAIO_REQ(caio_node));
    caio_req = CAIO_NODE_CAIO_REQ(caio_node);

    /*update parent request*/
    if(CAIO_NODE_F_S_OFFSET(caio_node) < CAIO_REQ_U_S_OFFSET(caio_req))
    {
        CAIO_REQ_U_S_OFFSET(caio_req) = CAIO_NODE_F_S_OFFSET(caio_node);
    }

    caio_req_del_node(caio_req, caio_node);
    caio_node_free(caio_node);

    return caio_req_timeout(caio_req);
}

EC_BOOL caio_node_terminate(CAIO_NODE *caio_node)
{
    CAIO_REQ        *caio_req;

    if(do_log(SEC_0093_CAIO, 9))
    {
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_node_terminate: "
                         "node %ld/%ld of req %ld => terminate\n",
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node));
        caio_node_print(LOGSTDOUT, caio_node);
    }

    /*exception*/
    if(NULL_PTR == CAIO_NODE_CAIO_REQ(caio_node))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_node_terminate: "
                         "node %ld/%ld of req %ld => terminate but req is null => free caio_node\n",
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node));

        caio_node_free(caio_node);
        return (EC_TRUE);
    }

    CAIO_ASSERT(NULL_PTR != CAIO_NODE_CAIO_REQ(caio_node));
    caio_req = CAIO_NODE_CAIO_REQ(caio_node);

    /*update parent request*/
    if(CAIO_NODE_F_S_OFFSET(caio_node) < CAIO_REQ_U_S_OFFSET(caio_req))
    {
        CAIO_REQ_U_S_OFFSET(caio_req) = CAIO_NODE_F_S_OFFSET(caio_node);
    }

    caio_req_del_node(caio_req, caio_node);
    caio_node_free(caio_node);

    return caio_req_terminate(caio_req);
}

EC_BOOL caio_node_complete(CAIO_NODE *caio_node)
{
    CAIO_REQ        *caio_req;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_node_complete: "
                     "node %ld/%ld of req %ld => complete\n",
                     CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                     CAIO_NODE_SEQ_NO(caio_node));

    CAIO_ASSERT(NULL_PTR != CAIO_NODE_CAIO_REQ(caio_node));
    caio_req = CAIO_NODE_CAIO_REQ(caio_node);

    /*update parent request*/
    CAIO_REQ_SUCC_NUM(caio_req) ++;

    caio_req_del_node(caio_req, caio_node);
    caio_node_free(caio_node);

    if(CAIO_REQ_SUCC_NUM(caio_req) == CAIO_REQ_SUB_SEQ_NUM(caio_req))
    {
        return caio_req_complete(caio_req);
    }

    return (EC_TRUE);
}

/*----------------------------------- caio req interface -----------------------------------*/

CAIO_REQ *caio_req_new()
{
    CAIO_REQ *caio_req;

    alloc_static_mem(MM_CAIO_REQ, &caio_req, LOC_CAIO_0008);
    if(NULL_PTR == caio_req)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    caio_req_init(caio_req);
    return (caio_req);
}

EC_BOOL caio_req_init(CAIO_REQ *caio_req)
{
    caio_cb_init(CAIO_REQ_CB(caio_req));

    CAIO_REQ_MODEL(caio_req)                    = CAIO_MODEL_DEFAULT;
    CAIO_REQ_SEQ_NO(caio_req)                   = 0;
    CAIO_REQ_OP(caio_req)                       = CAIO_OP_ERR;

    CAIO_REQ_SUB_SEQ_NUM(caio_req)              = 0;
    CAIO_REQ_SUCC_NUM(caio_req)                 = 0;
    CAIO_REQ_U_S_OFFSET(caio_req)               = 0;

    CAIO_REQ_CAIO_MD(caio_req)                  = NULL_PTR;

    CAIO_REQ_FD(caio_req)                       = ERR_FD;
    CAIO_REQ_M_CACHE(caio_req)                  = NULL_PTR;
    CAIO_REQ_M_BUFF(caio_req)                   = NULL_PTR;
    CAIO_REQ_OFFSET(caio_req)                   = NULL_PTR;
    CAIO_REQ_F_S_OFFSET(caio_req)               = 0;
    CAIO_REQ_F_E_OFFSET(caio_req)               = 0;
    CAIO_REQ_TIMEOUT_NSEC(caio_req)             = 0;
    CAIO_REQ_NTIME_MS(caio_req)                 = 0;

    CAIO_REQ_S_MSEC(caio_req)                   = 0;
    CAIO_REQ_E_MSEC(caio_req)                   = 0;

    CAIO_REQ_POST_EVENT_HANDLER(caio_req)       = NULL_PTR;
    CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req)  = NULL_PTR;

    clist_init(CAIO_REQ_NODES(caio_req), MM_CAIO_NODE, LOC_CAIO_0009);

    CAIO_REQ_MOUNTED_REQS(caio_req)             = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL caio_req_clean(CAIO_REQ *caio_req)
{
    if(NULL_PTR != caio_req)
    {
        if(NULL_PTR != CAIO_REQ_MOUNTED_REQS(caio_req)
        && NULL_PTR != CAIO_REQ_CAIO_MD(caio_req))
        {
            caio_del_req(CAIO_REQ_CAIO_MD(caio_req), caio_req);
        }

        if(NULL_PTR != CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req))
        {
            caio_req_del_post_event(caio_req);
        }

        caio_req_cleanup_nodes(caio_req);

        caio_cb_clean(CAIO_REQ_CB(caio_req));

        CAIO_REQ_MODEL(caio_req)                    = CAIO_MODEL_DEFAULT;
        CAIO_REQ_SEQ_NO(caio_req)                   = 0;
        CAIO_REQ_OP(caio_req)                       = CAIO_OP_ERR;

        CAIO_REQ_SUB_SEQ_NUM(caio_req)              = 0;
        CAIO_REQ_SUCC_NUM(caio_req)                 = 0;
        CAIO_REQ_U_S_OFFSET(caio_req)               = 0;

        CAIO_REQ_CAIO_MD(caio_req)                  = NULL_PTR;

        CAIO_REQ_FD(caio_req)                       = ERR_FD;
        CAIO_REQ_M_CACHE(caio_req)                  = NULL_PTR;
        CAIO_REQ_M_BUFF(caio_req)                   = NULL_PTR;
        CAIO_REQ_OFFSET(caio_req)                   = NULL_PTR;
        CAIO_REQ_F_S_OFFSET(caio_req)               = 0;
        CAIO_REQ_F_E_OFFSET(caio_req)               = 0;
        CAIO_REQ_TIMEOUT_NSEC(caio_req)             = 0;
        CAIO_REQ_NTIME_MS(caio_req)                 = 0;

        CAIO_REQ_S_MSEC(caio_req)                   = 0;
        CAIO_REQ_E_MSEC(caio_req)                   = 0;
    }

    return (EC_TRUE);
}

EC_BOOL caio_req_free(CAIO_REQ *caio_req)
{
    if(NULL_PTR != caio_req)
    {
        caio_req_clean(caio_req);
        free_static_mem(MM_CAIO_REQ, caio_req, LOC_CAIO_0010);
    }
    return (EC_TRUE);
}

EC_BOOL caio_req_exec_timeout_handler(CAIO_REQ *caio_req)
{
    if(NULL_PTR != caio_req)
    {
        CAIO_CB     caio_cb;

        CAIO_REQ_E_MSEC(caio_req) = c_get_cur_time_msec();

        dbg_log(SEC_0093_CAIO, 1)(LOGSTDOUT, "[DEBUG] caio_req_exec_timeout_handler: "
                                             "req %ld, op %s, fd %d, file range [%ld, %ld), "
                                             "sub %ld, succ %ld, "
                                             "elapsed %ld msec\n",
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)),
                                             CAIO_REQ_FD(caio_req),
                                             CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                                             CAIO_REQ_SUB_SEQ_NUM(caio_req), CAIO_REQ_SUCC_NUM(caio_req),
                                             CAIO_REQ_E_MSEC(caio_req) - CAIO_REQ_S_MSEC(caio_req));

        caio_cb_clone(CAIO_REQ_CB(caio_req), &caio_cb);
        caio_req_free(caio_req);

        return caio_cb_exec_timeout_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL caio_req_exec_terminate_handler(CAIO_REQ *caio_req)
{
    if(NULL_PTR != caio_req)
    {
        CAIO_CB     caio_cb;

        CAIO_REQ_E_MSEC(caio_req) = c_get_cur_time_msec();

        dbg_log(SEC_0093_CAIO, 1)(LOGSTDOUT, "[DEBUG] caio_req_exec_terminate_handler: "
                                             "req %ld, op %s, fd %d, file range [%ld, %ld), "
                                             "sub %ld, succ %ld, "
                                             "elapsed %ld msec\n",
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)),
                                             CAIO_REQ_FD(caio_req),
                                             CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                                             CAIO_REQ_SUB_SEQ_NUM(caio_req), CAIO_REQ_SUCC_NUM(caio_req),
                                             CAIO_REQ_E_MSEC(caio_req) - CAIO_REQ_S_MSEC(caio_req));

        caio_cb_clone(CAIO_REQ_CB(caio_req), &caio_cb);
        caio_req_free(caio_req);

        return caio_cb_exec_terminate_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL caio_req_exec_complete_handler(CAIO_REQ *caio_req)
{
    if(NULL_PTR != caio_req)
    {
        CAIO_CB     caio_cb;

        CAIO_REQ_E_MSEC(caio_req) = c_get_cur_time_msec();

        dbg_log(SEC_0093_CAIO, 1)(LOGSTDOUT, "[DEBUG] caio_req_exec_complete_handler: "
                                             "req %ld, op %s, fd %d, file range [%ld, %ld), "
                                             "sub %ld, succ %ld, "
                                             "elapsed %ld msec\n",
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)),
                                             CAIO_REQ_FD(caio_req),
                                             CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                                             CAIO_REQ_SUB_SEQ_NUM(caio_req), CAIO_REQ_SUCC_NUM(caio_req),
                                             CAIO_REQ_E_MSEC(caio_req) - CAIO_REQ_S_MSEC(caio_req));

        caio_cb_clone(CAIO_REQ_CB(caio_req), &caio_cb);
        caio_req_free(caio_req);

        return caio_cb_exec_complete_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL caio_req_set_post_event(CAIO_REQ *caio_req, CAIO_EVENT_HANDLER handler)
{
    CAIO_MD     *caio_md;

    if(NULL_PTR == CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req))
    {
        CAIO_ASSERT(NULL_PTR != CAIO_REQ_CAIO_MD(caio_req));

        caio_md = CAIO_REQ_CAIO_MD(caio_req);

        CAIO_REQ_POST_EVENT_HANDLER(caio_req) = handler;

        CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req) =
                clist_push_back(CAIO_MD_POST_EVENT_REQS(caio_md), (void *)caio_req);
    }
    return (EC_TRUE);
}

EC_BOOL caio_req_del_post_event(CAIO_REQ *caio_req)
{
    CAIO_MD         *caio_md;

    CAIO_ASSERT(NULL_PTR != CAIO_REQ_CAIO_MD(caio_req));

    caio_md = CAIO_REQ_CAIO_MD(caio_req);

    CAIO_REQ_POST_EVENT_HANDLER(caio_req) = NULL_PTR;

    if(NULL_PTR != CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req))
    {
        clist_erase(CAIO_MD_POST_EVENT_REQS(caio_md), CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req));
        CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL caio_req_is(const CAIO_REQ *caio_req, const UINT32 seq_no)
{
    if(seq_no == CAIO_REQ_SEQ_NO(caio_req))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


void caio_req_print(LOG *log, const CAIO_REQ *caio_req)
{
    sys_log(log, "caio_req_print: caio_req %p: caio_cb: \n", caio_req);
    caio_cb_print(log, CAIO_REQ_CB(caio_req));

    sys_log(log, "caio_req_print: caio_req %p: seq no %ld, sub seq num %ld, op %s\n",
                 caio_req, CAIO_REQ_SEQ_NO(caio_req), CAIO_REQ_SUB_SEQ_NUM(caio_req),
                 __caio_op_str(CAIO_REQ_OP(caio_req)));

    sys_log(log, "caio_req_print: caio_req %p: fd %d, m_cache %p, m_buff %p, offset %p (%ld), range [%ld, %ld), "
                 "timeout %ld seconds, next access time %ld\n",
                 caio_req, CAIO_REQ_FD(caio_req), CAIO_REQ_M_CACHE(caio_req), CAIO_REQ_M_BUFF(caio_req),
                 CAIO_REQ_OFFSET(caio_req), (*CAIO_REQ_OFFSET(caio_req)),
                 CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                 CAIO_REQ_TIMEOUT_NSEC(caio_req), CAIO_REQ_NTIME_MS(caio_req));

    sys_log(log, "caio_req_print: caio_req %p: nodes: \n", caio_req);
    clist_print(log, CAIO_REQ_NODES(caio_req), (CLIST_DATA_DATA_PRINT)caio_node_print);
    return;
}

EC_BOOL caio_req_cleanup_nodes(CAIO_REQ *caio_req)
{
    CAIO_NODE       *caio_node;

    /*clean up nodes*/
    while(NULL_PTR != (caio_node = caio_req_pop_node_back(caio_req)))
    {
        caio_node_free(caio_node);
    }

    return (EC_TRUE);
}

EC_BOOL caio_req_push_node_back(CAIO_REQ *caio_req, CAIO_NODE *caio_node)
{
    CAIO_ASSERT(CAIO_NODE_SEQ_NO(caio_node) == CAIO_REQ_SEQ_NO(caio_req));

    /*mount*/
    CAIO_NODE_MOUNTED_NODES(caio_node) = clist_push_back(CAIO_REQ_NODES(caio_req), (void *)caio_node);
    if(NULL_PTR == CAIO_NODE_MOUNTED_NODES(caio_node))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_push_node_back: "
                                             "push node %ld, op %s to req %ld, op %s, "
                                             "file range [%ld, %ld), block range [%ld, %ld) failed\n",
                                             CAIO_NODE_SUB_SEQ_NO(caio_node),
                                             __caio_op_str(CAIO_NODE_OP(caio_node)),
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)),
                                             CAIO_NODE_F_S_OFFSET(caio_node),
                                             CAIO_NODE_F_E_OFFSET(caio_node),
                                             CAIO_NODE_B_S_OFFSET(caio_node),
                                             CAIO_NODE_B_E_OFFSET(caio_node));
        return (EC_FALSE);
    }

    CAIO_NODE_CAIO_REQ(caio_node) = caio_req; /*bind*/

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_push_node_back: "
                                         "push node %ld, op %s to req %ld, op %s, "
                                         "file range [%ld, %ld), block range [%ld, %ld) done\n",
                                         CAIO_NODE_SUB_SEQ_NO(caio_node),
                                         __caio_op_str(CAIO_NODE_OP(caio_node)),
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)),
                                         CAIO_NODE_F_S_OFFSET(caio_node),
                                         CAIO_NODE_F_E_OFFSET(caio_node),
                                         CAIO_NODE_B_S_OFFSET(caio_node),
                                         CAIO_NODE_B_E_OFFSET(caio_node));
    return (EC_TRUE);
}

CAIO_NODE *caio_req_pop_node_back(CAIO_REQ *caio_req)
{
    if(NULL_PTR != caio_req)
    {
        CAIO_NODE *caio_node;

        caio_node = clist_pop_back(CAIO_REQ_NODES(caio_req));
        if(NULL_PTR != caio_node)
        {
            CAIO_ASSERT(CAIO_NODE_CAIO_REQ(caio_node) == caio_req);

            CAIO_NODE_MOUNTED_NODES(caio_node) = NULL_PTR; /*umount*/
            CAIO_NODE_CAIO_REQ(caio_node)      = NULL_PTR; /*unbind*/
            return (caio_node);
        }
        return (NULL_PTR);
    }

    return (NULL_PTR);
}

EC_BOOL caio_req_push_node_front(CAIO_REQ *caio_req, CAIO_NODE *caio_node)
{
    CAIO_ASSERT(CAIO_NODE_SEQ_NO(caio_node) == CAIO_REQ_SEQ_NO(caio_req));

    /*mount*/
    CAIO_NODE_MOUNTED_NODES(caio_node) = clist_push_front(CAIO_REQ_NODES(caio_req), (void *)caio_node);
    if(NULL_PTR == CAIO_NODE_MOUNTED_NODES(caio_node))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_push_node_front: "
                                             "push node %ld, op %s to req %ld, op %s, "
                                             "file range [%ld, %ld), block range [%ld, %ld) failed\n",
                                             CAIO_NODE_SUB_SEQ_NO(caio_node),
                                             __caio_op_str(CAIO_NODE_OP(caio_node)),
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)),
                                             CAIO_NODE_F_S_OFFSET(caio_node),
                                             CAIO_NODE_F_E_OFFSET(caio_node),
                                             CAIO_NODE_B_S_OFFSET(caio_node),
                                             CAIO_NODE_B_E_OFFSET(caio_node));
        return (EC_FALSE);
    }

    CAIO_NODE_CAIO_REQ(caio_node) = caio_req; /*bind*/

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_push_node_front: "
                                         "push node %ld, op %s to req %ld, op %s, "
                                         "file range [%ld, %ld), block range [%ld, %ld) done\n",
                                         CAIO_NODE_SUB_SEQ_NO(caio_node),
                                         __caio_op_str(CAIO_NODE_OP(caio_node)),
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)),
                                         CAIO_NODE_F_S_OFFSET(caio_node),
                                         CAIO_NODE_F_E_OFFSET(caio_node),
                                         CAIO_NODE_B_S_OFFSET(caio_node),
                                         CAIO_NODE_B_E_OFFSET(caio_node));
    return (EC_TRUE);
}

CAIO_NODE *caio_req_pop_node_front(CAIO_REQ *caio_req)
{
    if(NULL_PTR != caio_req)
    {
        CAIO_NODE *caio_node;

        caio_node = clist_pop_front(CAIO_REQ_NODES(caio_req));
        if(NULL_PTR != caio_node)
        {
            CAIO_ASSERT(CAIO_NODE_CAIO_REQ(caio_node) == caio_req);

            CAIO_NODE_MOUNTED_NODES(caio_node) = NULL_PTR; /*umount*/
            CAIO_NODE_CAIO_REQ(caio_node)      = NULL_PTR; /*unbind*/
            return (caio_node);
        }
        return (NULL_PTR);
    }

    return (NULL_PTR);
}

EC_BOOL caio_req_del_node(CAIO_REQ *caio_req, CAIO_NODE *caio_node)
{
    CAIO_ASSERT(CAIO_NODE_SEQ_NO(caio_node) == CAIO_REQ_SEQ_NO(caio_req));

    if(NULL_PTR != CAIO_NODE_MOUNTED_NODES(caio_node))
    {
        clist_erase(CAIO_REQ_NODES(caio_req), CAIO_NODE_MOUNTED_NODES(caio_node));
        CAIO_NODE_MOUNTED_NODES(caio_node) = NULL_PTR; /*umount*/
        CAIO_NODE_CAIO_REQ(caio_node)      = NULL_PTR; /*unbind*/

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_del_node: pop node %ld from req %ld, op %s done\n",
                                             CAIO_NODE_SUB_SEQ_NO(caio_node),
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)));

    }
    return (EC_TRUE);
}

EC_BOOL caio_req_reorder_sub_seq_no(CAIO_REQ *caio_req)
{
    UINT32       sub_seq_no;
    UINT32       sub_seq_num;
    CLIST_DATA  *clist_data;

    sub_seq_no  = 0;
    sub_seq_num = CAIO_REQ_SUB_SEQ_NUM(caio_req);

    CLIST_LOOP_NEXT(CAIO_REQ_NODES(caio_req), clist_data)
    {
        CAIO_NODE *caio_node;

        caio_node = (CAIO_NODE *)CLIST_DATA_DATA(clist_data);

        CAIO_NODE_SUB_SEQ_NO(caio_node)  = ++ sub_seq_no;
        CAIO_NODE_SUB_SEQ_NUM(caio_node) = sub_seq_num;

        dbg_log(SEC_0093_CAIO, 6)(LOGSTDOUT, "[DEBUG] caio_req_reorder_sub_seq_no: "
                                             "node %ld to req %ld, op %s, "
                                             "file range [%ld, %ld), block range [%ld, %ld)\n",
                                             CAIO_NODE_SUB_SEQ_NO(caio_node),
                                             CAIO_NODE_SEQ_NO(caio_node),
                                             __caio_op_str(CAIO_NODE_OP(caio_node)),
                                             CAIO_NODE_F_S_OFFSET(caio_node),
                                             CAIO_NODE_F_E_OFFSET(caio_node),
                                             CAIO_NODE_B_S_OFFSET(caio_node),
                                             CAIO_NODE_B_E_OFFSET(caio_node));
    }

    CAIO_ASSERT(sub_seq_no == sub_seq_num);

    return (EC_TRUE);
}

EC_BOOL caio_req_make_read_op(CAIO_REQ *caio_req)
{
    UINT32              f_s_offset;
    UINT32              f_e_offset;

    UINT8              *m_buff;

    const CAIO_CFG     *caio_cfg;
    UINT32              caio_block_size_nbytes;
    UINT32              caio_block_size_mask;

    CAIO_ASSERT(NULL_PTR != CAIO_REQ_CAIO_MD(caio_req));

    caio_cfg   = __caio_cfg_fetch(CAIO_REQ_MODEL(caio_req));
    caio_block_size_nbytes = CAIO_CFG_BLOCK_SIZE_NBYTES(caio_cfg);
    caio_block_size_mask   = CAIO_CFG_BLOCK_SIZE_MASK(caio_cfg);

    f_s_offset = CAIO_REQ_F_S_OFFSET(caio_req);
    f_e_offset = CAIO_REQ_F_E_OFFSET(caio_req);
    m_buff     = (UINT8 *)CAIO_REQ_M_BUFF(caio_req);

    while(f_s_offset < f_e_offset)
    {
        UINT32              b_s_offset;
        UINT32              b_e_offset;

        CAIO_NODE          *caio_node;

        b_s_offset = f_s_offset & ((UINT32)caio_block_size_mask);
        f_s_offset = f_s_offset & (~((UINT32)caio_block_size_mask)); /*align to page starting*/

        b_e_offset = DMIN(f_s_offset + caio_block_size_nbytes, f_e_offset) & ((UINT32)caio_block_size_mask);
        if(0 == b_e_offset) /*adjust to next page boundary*/
        {
            b_e_offset = caio_block_size_nbytes;
        }

        /*set up sub request*/
        caio_node = caio_node_new();
        if(NULL_PTR == caio_node)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_read_op: "
                                                 "new caio_node failed\n");
            return (EC_FALSE);
        }

        CAIO_NODE_OP(caio_node)           = CAIO_OP_RD;

        /*inherited data from caio req*/
        CAIO_NODE_CAIO_REQ(caio_node)     = caio_req;
        CAIO_NODE_SEQ_NO(caio_node)       = CAIO_REQ_SEQ_NO(caio_req);
        CAIO_NODE_SUB_SEQ_NO(caio_node)   = ++ CAIO_REQ_SUB_SEQ_NUM(caio_req);
        CAIO_NODE_CAIO_MD(caio_node)      = CAIO_REQ_CAIO_MD(caio_req);
        CAIO_NODE_FD(caio_node)           = CAIO_REQ_FD(caio_req);
        CAIO_NODE_M_CACHE(caio_node)      = NULL_PTR;
        CAIO_NODE_M_BUFF(caio_node)       = m_buff;
        CAIO_NODE_F_S_OFFSET(caio_node)   = f_s_offset;
        CAIO_NODE_F_E_OFFSET(caio_node)   = f_s_offset + caio_block_size_nbytes;
        CAIO_NODE_B_S_OFFSET(caio_node)   = b_s_offset;
        CAIO_NODE_B_E_OFFSET(caio_node)   = b_e_offset;
        CAIO_NODE_TIMEOUT_NSEC(caio_node) = CAIO_REQ_TIMEOUT_NSEC(caio_req);
        CAIO_NODE_NTIME_MS(caio_node)     = CAIO_REQ_NTIME_MS(caio_req);

        /*bind: push back & mount*/
        if(EC_FALSE == caio_req_push_node_back(caio_req, caio_node))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_read_op: "
                                                 "push node %ld to req %ld, op %s failed\n",
                                                 CAIO_NODE_SUB_SEQ_NO(caio_node),
                                                 CAIO_REQ_SEQ_NO(caio_req),
                                                 __caio_op_str(CAIO_REQ_OP(caio_req)));
            caio_node_free(caio_node);
            return (EC_FALSE);
        }

        m_buff     += b_e_offset - b_s_offset;
        f_s_offset += caio_block_size_nbytes;/*align to next page starting*/
    }

    return (EC_TRUE);
}

EC_BOOL caio_req_make_write_op(CAIO_REQ *caio_req)
{
    UINT32              f_s_offset;
    UINT32              f_e_offset;

    UINT8              *m_buff;

    const CAIO_CFG     *caio_cfg;
    UINT32              caio_block_size_nbytes;
    UINT32              caio_block_size_mask;

    CAIO_ASSERT(NULL_PTR != CAIO_REQ_CAIO_MD(caio_req));

    caio_cfg   = __caio_cfg_fetch(CAIO_REQ_MODEL(caio_req));
    caio_block_size_nbytes = CAIO_CFG_BLOCK_SIZE_NBYTES(caio_cfg);
    caio_block_size_mask   = CAIO_CFG_BLOCK_SIZE_MASK(caio_cfg);

    f_s_offset = CAIO_REQ_F_S_OFFSET(caio_req);
    f_e_offset = CAIO_REQ_F_E_OFFSET(caio_req);
    m_buff     = (UINT8 *)CAIO_REQ_M_BUFF(caio_req);

    while(f_s_offset < f_e_offset)
    {
        UINT32              b_s_offset;
        UINT32              b_e_offset;

        CAIO_NODE          *caio_node;

        b_s_offset  = f_s_offset & ((UINT32)caio_block_size_mask);
        f_s_offset  = f_s_offset & (~((UINT32)caio_block_size_mask)); /*align to page starting*/

        b_e_offset  = DMIN(f_s_offset + caio_block_size_nbytes, f_e_offset) & ((UINT32)caio_block_size_mask);
        if(0 == b_e_offset) /*adjust to next page boundary*/
        {
            b_e_offset = caio_block_size_nbytes;
        }

        /*set up sub request*/
        caio_node = caio_node_new();
        if(NULL_PTR == caio_node)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_write_op: "
                                                 "new caio_node failed\n");
            return (EC_FALSE);
        }

        CAIO_NODE_OP(caio_node)           = CAIO_OP_WR;

        /*inherited data from caio req*/
        CAIO_NODE_CAIO_REQ(caio_node)     = caio_req;
        CAIO_NODE_SEQ_NO(caio_node)       = CAIO_REQ_SEQ_NO(caio_req);
        CAIO_NODE_SUB_SEQ_NO(caio_node)   = ++ CAIO_REQ_SUB_SEQ_NUM(caio_req);
        CAIO_NODE_CAIO_MD(caio_node)      = CAIO_REQ_CAIO_MD(caio_req);
        CAIO_NODE_FD(caio_node)           = CAIO_REQ_FD(caio_req);
        CAIO_NODE_M_CACHE(caio_node)      = NULL_PTR;
        CAIO_NODE_M_BUFF(caio_node)       = m_buff;
        CAIO_NODE_F_S_OFFSET(caio_node)   = f_s_offset;
        CAIO_NODE_F_E_OFFSET(caio_node)   = f_s_offset + caio_block_size_nbytes;
        CAIO_NODE_B_S_OFFSET(caio_node)   = b_s_offset;
        CAIO_NODE_B_E_OFFSET(caio_node)   = b_e_offset;
        CAIO_NODE_TIMEOUT_NSEC(caio_node) = CAIO_REQ_TIMEOUT_NSEC(caio_req);
        CAIO_NODE_NTIME_MS(caio_node)     = CAIO_REQ_NTIME_MS(caio_req);

        /*bind: push back & mount*/
        if(EC_FALSE == caio_req_push_node_back(caio_req, caio_node))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_write_op: "
                                                 "push node %ld to req %ld, op %s failed\n",
                                                 CAIO_NODE_SUB_SEQ_NO(caio_node),
                                                 CAIO_REQ_SEQ_NO(caio_req),
                                                 __caio_op_str(CAIO_REQ_OP(caio_req)));
            caio_node_free(caio_node);
            return (EC_FALSE);
        }

        m_buff     += b_e_offset - b_s_offset;
        f_s_offset += caio_block_size_nbytes;/*align to next page starting*/
    }

    return (EC_TRUE);
}

EC_BOOL caio_req_make_read(CAIO_REQ *caio_req)
{
    if(EC_FALSE == caio_req_make_read_op(caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_read: "
                                             "make read op of req %ld failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req));
        return (EC_FALSE);
    }

    /*here re-order always for debug purpose due to recording sub seq num info in node*/
    caio_req_reorder_sub_seq_no(caio_req);

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_make_read: "
                                         "make %ld ops of req %ld, op %s done\n",
                                         CAIO_REQ_SUB_SEQ_NUM(caio_req),
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)));

    return (EC_TRUE);
}

EC_BOOL caio_req_make_write(CAIO_REQ *caio_req)
{
    UINT32              caio_node_num;
    UINT32              s_offset;
    UINT32              e_offset;
    UINT32              rd_flag;

    const CAIO_CFG     *caio_cfg;
    UINT32              caio_block_size_nbytes;
    UINT32              caio_block_size_mask;

    if(EC_FALSE == caio_req_make_write_op(caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_write: "
                                             "make write op of req %ld failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req));
        return (EC_FALSE);
    }

    caio_cfg   = __caio_cfg_fetch(CAIO_REQ_MODEL(caio_req));
    caio_block_size_nbytes = CAIO_CFG_BLOCK_SIZE_NBYTES(caio_cfg);
    caio_block_size_mask   = CAIO_CFG_BLOCK_SIZE_MASK(caio_cfg);

    s_offset = CAIO_REQ_F_S_OFFSET(caio_req);
    e_offset = CAIO_REQ_F_E_OFFSET(caio_req);

    CAIO_ASSERT(clist_size(CAIO_REQ_NODES(caio_req)) == CAIO_REQ_SUB_SEQ_NUM(caio_req));

    caio_node_num = clist_size(CAIO_REQ_NODES(caio_req)); /*save node num*/
    rd_flag       = BIT_FALSE; /*init*/

    if(1 == caio_node_num)
    {
        if((((UINT32)caio_block_size_mask) & s_offset) || (((UINT32)caio_block_size_mask) & e_offset))
        {
            CAIO_NODE          *caio_node;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read sub request*/
            caio_node = caio_node_new();
            if(NULL_PTR == caio_node)
            {
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_write: "
                                                     "new caio_node failed\n");
                return (EC_FALSE);
            }

            /*the unique page*/
            f_s_offset = s_offset & (~((UINT32)caio_block_size_mask)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = caio_block_size_nbytes;

            CAIO_NODE_OP(caio_node)           = CAIO_OP_RD;

            /*inherited data from caio req*/
            CAIO_NODE_CAIO_REQ(caio_node)     = caio_req;
            CAIO_NODE_SEQ_NO(caio_node)       = CAIO_REQ_SEQ_NO(caio_req);
            CAIO_NODE_SUB_SEQ_NO(caio_node)   = ++ CAIO_REQ_SUB_SEQ_NUM(caio_req); /*would re-order later*/
            CAIO_NODE_CAIO_MD(caio_node)      = CAIO_REQ_CAIO_MD(caio_req);
            CAIO_NODE_FD(caio_node)           = CAIO_REQ_FD(caio_req);
            CAIO_NODE_M_CACHE(caio_node)      = NULL_PTR;
            CAIO_NODE_M_BUFF(caio_node)       = NULL_PTR; /*inherit only for write operation*/
            CAIO_NODE_F_S_OFFSET(caio_node)   = f_s_offset;
            CAIO_NODE_F_E_OFFSET(caio_node)   = f_s_offset + caio_block_size_nbytes;
            CAIO_NODE_B_S_OFFSET(caio_node)   = b_s_offset;
            CAIO_NODE_B_E_OFFSET(caio_node)   = b_e_offset;
            CAIO_NODE_TIMEOUT_NSEC(caio_node) = CAIO_REQ_TIMEOUT_NSEC(caio_req);
            CAIO_NODE_NTIME_MS(caio_node)     = CAIO_REQ_NTIME_MS(caio_req);

            /*push front & bind*/
            caio_req_push_node_front(caio_req, caio_node);

            rd_flag = BIT_TRUE;
        }
    }

    if(1 < caio_node_num)
    {
        if(((UINT32)caio_block_size_mask) & s_offset)
        {
            CAIO_NODE          *caio_node;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read aio request*/
            caio_node = caio_node_new();
            if(NULL_PTR == caio_node)
            {
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_write: "
                                                     "new caio_node failed\n");
                return (EC_FALSE);
            }

            /*the first page*/
            f_s_offset = s_offset & (~((UINT32)caio_block_size_mask)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = caio_block_size_nbytes;

            CAIO_NODE_OP(caio_node)           = CAIO_OP_RD;

            /*inherited data from caio req*/
            CAIO_NODE_CAIO_REQ(caio_node)     = caio_req;
            CAIO_NODE_SEQ_NO(caio_node)       = CAIO_REQ_SEQ_NO(caio_req);
            CAIO_NODE_SUB_SEQ_NO(caio_node)   = ++ CAIO_REQ_SUB_SEQ_NUM(caio_req); /*would re-order later*/
            CAIO_NODE_CAIO_MD(caio_node)      = CAIO_REQ_CAIO_MD(caio_req);
            CAIO_NODE_FD(caio_node)           = CAIO_REQ_FD(caio_req);
            CAIO_NODE_M_CACHE(caio_node)      = NULL_PTR;
            CAIO_NODE_M_BUFF(caio_node)       = NULL_PTR; /*inherit only for write operation*/
            CAIO_NODE_F_S_OFFSET(caio_node)   = f_s_offset;
            CAIO_NODE_F_E_OFFSET(caio_node)   = f_s_offset + caio_block_size_nbytes;
            CAIO_NODE_B_S_OFFSET(caio_node)   = b_s_offset;
            CAIO_NODE_B_E_OFFSET(caio_node)   = b_e_offset;
            CAIO_NODE_TIMEOUT_NSEC(caio_node) = CAIO_REQ_TIMEOUT_NSEC(caio_req);
            CAIO_NODE_NTIME_MS(caio_node)     = CAIO_REQ_NTIME_MS(caio_req);

            /*bind: push front & mount*/
            caio_req_push_node_front(caio_req, caio_node);

            rd_flag = BIT_TRUE;
        }

        if(((UINT32)caio_block_size_mask) & e_offset)
        {
            CAIO_NODE          *caio_node;
            CAIO_NODE          *caio_node_saved;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read sub request*/
            caio_node = caio_node_new();
            if(NULL_PTR == caio_node)
            {
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_make_write: "
                                                     "new caio_node failed\n");
                return (EC_FALSE);
            }

            /*the last page*/
            f_s_offset = e_offset & (~((UINT32)caio_block_size_mask)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = caio_block_size_nbytes;

            CAIO_NODE_OP(caio_node)           = CAIO_OP_RD;

            /*inherited data from caio req*/
            CAIO_NODE_CAIO_REQ(caio_node)     = caio_req;
            CAIO_NODE_SEQ_NO(caio_node)       = CAIO_REQ_SEQ_NO(caio_req);
            CAIO_NODE_SUB_SEQ_NO(caio_node)   = ++ CAIO_REQ_SUB_SEQ_NUM(caio_req); /*would re-order later*/
            CAIO_NODE_CAIO_MD(caio_node)      = CAIO_REQ_CAIO_MD(caio_req);
            CAIO_NODE_FD(caio_node)           = CAIO_REQ_FD(caio_req);
            CAIO_NODE_M_CACHE(caio_node)      = NULL_PTR;
            CAIO_NODE_M_BUFF(caio_node)       = NULL_PTR; /*inherit only for write operation*/
            CAIO_NODE_F_S_OFFSET(caio_node)   = f_s_offset;
            CAIO_NODE_F_E_OFFSET(caio_node)   = f_s_offset + caio_block_size_nbytes;
            CAIO_NODE_B_S_OFFSET(caio_node)   = b_s_offset;
            CAIO_NODE_B_E_OFFSET(caio_node)   = b_e_offset;
            CAIO_NODE_TIMEOUT_NSEC(caio_node) = CAIO_REQ_TIMEOUT_NSEC(caio_req);
            CAIO_NODE_NTIME_MS(caio_node)     = CAIO_REQ_NTIME_MS(caio_req);

            /*pop the last one and save it*/
            caio_node_saved  = caio_req_pop_node_back(caio_req);

            /*bind: push back & mount*/
            caio_req_push_node_back(caio_req, caio_node);

            /*bind: push back & mount the saved one*/
            caio_req_push_node_back(caio_req, caio_node_saved);

            rd_flag = BIT_TRUE;
        }
    }

    CAIO_ASSERT(clist_size(CAIO_REQ_NODES(caio_req)) == CAIO_REQ_SUB_SEQ_NUM(caio_req));

    /*if some read op inserted, re-order sub seq no. */
    /*here re-order always for debug purpose due to recording sub seq num info in node*/
    if(BIT_TRUE == rd_flag)
    {
        caio_req_reorder_sub_seq_no(caio_req);
    }
    else
    {
        caio_req_reorder_sub_seq_no(caio_req);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_make_write: "
                                         "make %ld ops of req %ld, op %s done\n",
                                         CAIO_REQ_SUB_SEQ_NUM(caio_req),
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)));
    return (EC_TRUE);
}

EC_BOOL caio_req_timeout(CAIO_REQ *caio_req)
{
    CAIO_NODE       *caio_node;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_timeout: "
                     "req %ld, file range [%ld, %ld), op %s, "
                     "timeout %ld seconds, next access time %ld => timeout\n",
                     CAIO_REQ_SEQ_NO(caio_req),
                     CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                     __caio_op_str(CAIO_REQ_OP(caio_req)),
                     CAIO_REQ_TIMEOUT_NSEC(caio_req), CAIO_REQ_NTIME_MS(caio_req));

    /*determine offset & clean up nodes*/
    while(NULL_PTR != (caio_node = caio_req_pop_node_back(caio_req)))
    {
        /*update upper offset at most*/
        if(CAIO_NODE_F_S_OFFSET(caio_node) < CAIO_REQ_U_S_OFFSET(caio_req))
        {
            CAIO_REQ_U_S_OFFSET(caio_req) = CAIO_NODE_F_S_OFFSET(caio_node);
        }

        caio_node_free(caio_node);
    }

    if(CAIO_REQ_U_S_OFFSET(caio_req) < CAIO_REQ_F_S_OFFSET(caio_req))
    {
        CAIO_REQ_U_S_OFFSET(caio_req) = CAIO_REQ_F_S_OFFSET(caio_req);
    }

    (*CAIO_REQ_OFFSET(caio_req)) = CAIO_REQ_U_S_OFFSET(caio_req);

    /*post timeout event*/
    caio_req_set_post_event(caio_req, (CAIO_EVENT_HANDLER)caio_req_exec_timeout_handler);

    return (EC_TRUE);
}

EC_BOOL caio_req_terminate(CAIO_REQ *caio_req)
{
    CAIO_NODE       *caio_node;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_terminate: "
                     "req %ld, file range [%ld, %ld), op %s terminate\n",
                     CAIO_REQ_SEQ_NO(caio_req),
                     CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                     __caio_op_str(CAIO_REQ_OP(caio_req)));

    /*determine offset & clean up nodes*/
    while(NULL_PTR != (caio_node = caio_req_pop_node_back(caio_req)))
    {
        /*update upper offset at most*/
        if(CAIO_NODE_F_S_OFFSET(caio_node) < CAIO_REQ_U_S_OFFSET(caio_req))
        {
            CAIO_REQ_U_S_OFFSET(caio_req) = CAIO_NODE_F_S_OFFSET(caio_node);
        }

        caio_node_free(caio_node);
    }

    if(CAIO_REQ_U_S_OFFSET(caio_req) < CAIO_REQ_F_S_OFFSET(caio_req))
    {
        CAIO_REQ_U_S_OFFSET(caio_req) = CAIO_REQ_F_S_OFFSET(caio_req);
    }

    (*CAIO_REQ_OFFSET(caio_req)) = CAIO_REQ_U_S_OFFSET(caio_req);

    /*post terminate event*/
    caio_req_set_post_event(caio_req, (CAIO_EVENT_HANDLER)caio_req_exec_terminate_handler);

    return (EC_TRUE);
}

EC_BOOL caio_req_complete(CAIO_REQ *caio_req)
{
    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_complete: "
                     "req %ld, file range [%ld, %ld), op %s complete\n",
                     CAIO_REQ_SEQ_NO(caio_req),
                     CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                     __caio_op_str(CAIO_REQ_OP(caio_req)));

    /*determine offset*/

    /*check validity*/
    CAIO_ASSERT(0 == clist_size(CAIO_REQ_NODES(caio_req)));
    CAIO_ASSERT(CAIO_REQ_SUCC_NUM(caio_req) == CAIO_REQ_SUB_SEQ_NUM(caio_req));

    if(CAIO_REQ_U_S_OFFSET(caio_req) < CAIO_REQ_F_S_OFFSET(caio_req))
    {
        CAIO_REQ_U_S_OFFSET(caio_req) = CAIO_REQ_F_S_OFFSET(caio_req);
    }

    (*CAIO_REQ_OFFSET(caio_req)) = CAIO_REQ_U_S_OFFSET(caio_req);

    /*post complete event*/
    caio_req_set_post_event(caio_req, (CAIO_EVENT_HANDLER)caio_req_exec_complete_handler);

    return (EC_TRUE);
}

EC_BOOL caio_req_dispatch_node(CAIO_REQ *caio_req, CAIO_NODE *caio_node)
{
    CAIO_MD            *caio_md;
    CAIO_PAGE          *caio_page;

    const CAIO_CFG     *caio_cfg;
    UINT32              caio_block_size_nbytes;

    caio_cfg   = __caio_cfg_fetch(CAIO_REQ_MODEL(caio_req));
    caio_block_size_nbytes = CAIO_CFG_BLOCK_SIZE_NBYTES(caio_cfg);

    caio_md = CAIO_REQ_CAIO_MD(caio_req);

    caio_page = caio_search_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), CAIO_NODE_FD(caio_node),
                                CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node));
    if(NULL_PTR != caio_page)
    {
        if(EC_FALSE == caio_page_add_node(caio_page, caio_node))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_dispatch_node: "
                             "dispatch node %ld/%ld of req %ld, op %s to existing page [%ld, %ld), fd %d failed\n",
                             CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                             CAIO_NODE_SEQ_NO(caio_node),
                             __caio_op_str(CAIO_NODE_OP(caio_node)),
                             CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                             CAIO_PAGE_FD(caio_page));
            return (EC_FALSE);
        }

        dbg_log(SEC_0093_CAIO, 6)(LOGSTDOUT, "[DEBUG] caio_req_dispatch_node: "
                         "dispatch node %ld/%ld of req %ld, op %s to existing page [%ld, %ld), fd %d done\n",
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node),
                         __caio_op_str(CAIO_NODE_OP(caio_node)),
                         CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                         CAIO_PAGE_FD(caio_page));

        return (EC_TRUE);
    }

    /*create new page*/

    caio_page = caio_page_new();
    if(NULL_PTR == caio_page)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_dispatch_node: "
                         "new page [%ld, %ld) for node %ld/%ld of req %ld, op %s failed\n",
                         CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node),
                         __caio_op_str(CAIO_NODE_OP(caio_node)));

        return (EC_FALSE);
    }

    /*inherited data from node*/
    CAIO_PAGE_FD(caio_page)             = CAIO_NODE_FD(caio_node);
    CAIO_PAGE_F_S_OFFSET(caio_page)     = CAIO_NODE_F_S_OFFSET(caio_node);
    CAIO_PAGE_F_E_OFFSET(caio_page)     = CAIO_NODE_F_E_OFFSET(caio_node);
    CAIO_PAGE_CAIO_MD(caio_page)        = CAIO_NODE_CAIO_MD(caio_node);
    CAIO_PAGE_OP(caio_page)             = CAIO_NODE_OP(caio_node);
    CAIO_PAGE_NO(caio_page)             = (uint32_t)(CAIO_PAGE_F_S_OFFSET(caio_page)
                                                  >> CAIO_CFG_BLOCK_SIZE_NBITS(caio_cfg));

    CAIO_PAGE_CAIO_DISK(caio_page) = caio_find_disk(caio_md, CAIO_PAGE_FD(caio_page));
    if(NULL_PTR == CAIO_PAGE_CAIO_DISK(caio_page))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_dispatch_node: "
                         "find no disk for page [%ld, %ld), fd %d failed\n",
                         CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                         CAIO_PAGE_FD(caio_page));


        caio_page_free(caio_page);
        return (EC_FALSE);
    }

    if(CAIO_MODEL_CHOICE == CAIO_REQ_MODEL(caio_req))
    {
        /*scenario: not shortcut to mem cache*/
        CAIO_PAGE_M_CACHE(caio_page) = __caio_mem_cache_new(caio_block_size_nbytes, caio_block_size_nbytes);
        if(NULL_PTR == CAIO_PAGE_M_CACHE(caio_page))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_dispatch_node: "
                             "new mem cache for page [%ld, %ld), fd %d failed\n",
                             CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                             CAIO_PAGE_FD(caio_page));

            caio_page_free(caio_page);
            return (EC_FALSE);
        }
        CAIO_PAGE_MEM_CACHE_FLAG(caio_page)     = BIT_TRUE;
    }
    else
    {
        /*scenario: not shortcut to mem cache*/
        CAIO_PAGE_M_CACHE(caio_page) = c_memalign_new(caio_block_size_nbytes, caio_block_size_nbytes);
        if(NULL_PTR == CAIO_PAGE_M_CACHE(caio_page))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_dispatch_node: "
                             "new mem cache for page [%ld, %ld), fd %d failed\n",
                             CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                             CAIO_PAGE_FD(caio_page));

            caio_page_free(caio_page);
            return (EC_FALSE);
        }
    }

    /*add page to caio module*/
    if(EC_FALSE == caio_add_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), caio_page))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_dispatch_node: "
                         "add page [%ld, %ld), fd %d to caio module failed\n",
                         CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                         CAIO_PAGE_FD(caio_page));

        caio_page_free(caio_page);
        return (EC_FALSE);
    }

    /*add node to page*/
    if(EC_FALSE == caio_page_add_node(caio_page, caio_node))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_req_dispatch_node: "
                         "dispatch node %ld/%ld of req %ld, op %s to new page [%ld, %ld), fd %d failed\n",
                         CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                         CAIO_NODE_SEQ_NO(caio_node),
                         __caio_op_str(CAIO_NODE_OP(caio_node)),
                         CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                         CAIO_PAGE_FD(caio_page));

        caio_del_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), caio_page);
        caio_page_free(caio_page);
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 6)(LOGSTDOUT, "[DEBUG] caio_req_dispatch_node: "
                     "dispatch node %ld/%ld of req %ld, op %s to new page [%ld, %ld), fd %d done\n",
                     CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                     CAIO_NODE_SEQ_NO(caio_node),
                     __caio_op_str(CAIO_NODE_OP(caio_node)),
                     CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                     CAIO_PAGE_FD(caio_page));

    return (EC_TRUE);
}

EC_BOOL caio_req_cancel_node(CAIO_REQ *caio_req, CAIO_NODE *caio_node)
{
    if(NULL_PTR != CAIO_NODE_MOUNTED_OWNERS(caio_node)
    && NULL_PTR != CAIO_NODE_CAIO_PAGE(caio_node))
    {
        /*delete node from page*/
        caio_page_del_node(CAIO_NODE_CAIO_PAGE(caio_node), caio_node);
    }

    /*delete node from req*/
    caio_req_del_node(caio_req, caio_node);

    CAIO_ASSERT(CAIO_NODE_SEQ_NO(caio_node) == CAIO_REQ_SEQ_NO(caio_req));

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_req_cancel_node: "
                    "cancel node %ld/%ld of req %ld, op %s done\n",
                    CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                    CAIO_NODE_SEQ_NO(caio_node),
                    __caio_op_str(CAIO_REQ_OP(caio_req)));

    return (EC_TRUE);
}

/*----------------------------------- caio module interface -----------------------------------*/

CAIO_MD *caio_start(const UINT32 model)
{
    CAIO_MD      *caio_md;

    /* initialize new one caio module */
    caio_md = safe_malloc(sizeof(CAIO_MD), LOC_CAIO_0011);
    if(NULL_PTR == caio_md)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: malloc caio module failed\n");
        return (NULL_PTR);
    }

    CAIO_MD_MODEL(caio_md)       = model;
    CAIO_MD_SEQ_NO(caio_md)      = 0;
    CAIO_MD_AIO_EVENTFD(caio_md) = ERR_FD;
    CAIO_MD_AIO_CONTEXT(caio_md) = 0;
    CAIO_MD_RDONLY_FLAG(caio_md) = BIT_FALSE;

    clist_init(CAIO_MD_DISK_LIST(caio_md), MM_CAIO_DISK, LOC_CAIO_0012);

    clist_init(CAIO_MD_REQ_LIST(caio_md), MM_CAIO_REQ, LOC_CAIO_0013);

    CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md) = 0; /*set page list[0] is active*/
    clist_init(CAIO_MD_PAGE_LIST(caio_md, 0), MM_CAIO_PAGE, LOC_CAIO_0014);/*init active page list*/
    clist_init(CAIO_MD_PAGE_LIST(caio_md, 1), MM_CAIO_PAGE, LOC_CAIO_0015);/*init standby page list*/

    clist_init(CAIO_MD_POST_EVENT_REQS(caio_md), MM_CAIO_REQ, LOC_CAIO_0016);

    CAIO_MD_AIO_EVENTFD(caio_md) = syscall(__NR_eventfd2, 0, O_NONBLOCK | O_CLOEXEC);
    if(ERR_FD == CAIO_MD_AIO_EVENTFD(caio_md))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: "
                                             "get eventfd failed, errno = %d, errstr = %s\n",
                                             errno, strerror(errno));

        caio_end(caio_md);
        return (NULL_PTR);
    }
    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_start: eventfd %d\n",
                                         CAIO_MD_AIO_EVENTFD(caio_md));

    /*aio context*/
    if(EC_FALSE == __caio_setup((unsigned)CAIO_REQ_MAX_NUM, &CAIO_MD_AIO_CONTEXT(caio_md)))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: nr_reqs = %d\n",
                                            (unsigned)CAIO_REQ_MAX_NUM);

        CAIO_MD_AIO_CONTEXT(caio_md) = 0;

        caio_end(caio_md);
        return (NULL_PTR);
    }
    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_start: aio context %ld\n",
                                         CAIO_MD_AIO_CONTEXT(caio_md));

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_start: start caio done\n");

    return (caio_md);
}

void caio_end(CAIO_MD *caio_md)
{
    if(NULL_PTR != caio_md)
    {
        if(BIT_FALSE == CAIO_MD_RDONLY_FLAG(caio_md))
        {
            caio_poll(caio_md);
        }

        caio_cleanup_pages(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md));
        caio_cleanup_pages(caio_md, CAIO_MD_STANDBY_PAGE_LIST_IDX(caio_md));
        CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md) = 0;

        caio_cleanup_reqs(caio_md);
        caio_cleanup_post_event_reqs(caio_md);

        clist_clean(CAIO_MD_DISK_LIST(caio_md), (CLIST_DATA_CLEAN)caio_disk_free);

        CAIO_MD_MODEL(caio_md)       = CAIO_MODEL_DEFAULT;
        CAIO_MD_SEQ_NO(caio_md)      = 0;

        if(ERR_FD != CAIO_MD_AIO_EVENTFD(caio_md))
        {
            close(CAIO_MD_AIO_EVENTFD(caio_md));
            CAIO_MD_AIO_EVENTFD(caio_md) = ERR_FD;
        }

        if(0 != CAIO_MD_AIO_CONTEXT(caio_md))
        {
            __caio_destroy(CAIO_MD_AIO_CONTEXT(caio_md));
            CAIO_MD_AIO_CONTEXT(caio_md) = 0;
        }

        CAIO_MD_RDONLY_FLAG(caio_md)    = BIT_FALSE;

        safe_free(caio_md, LOC_CAIO_0017);
    }

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_end: stop caio done\n");

    return;
}



void caio_print(LOG *log, const CAIO_MD *caio_md)
{
    if(NULL_PTR != caio_md)
    {
        sys_log(log, "caio_print: caio_md %p: seq_no: %ld\n", caio_md, CAIO_MD_SEQ_NO(caio_md));

        sys_log(log, "caio_print: caio_md %p: %ld disks:\n",
                     caio_md, clist_size(CAIO_MD_DISK_LIST(caio_md)));
        if(1)
        {
            caio_show_disks(log, caio_md);
        }

        sys_log(log, "caio_print: caio_md %p: %ld reqs:\n",
                     caio_md, clist_size(CAIO_MD_REQ_LIST(caio_md)));
        if(1)
        {
            caio_show_reqs(log, caio_md);
        }

        sys_log(log, "caio_print: caio_md %p: %u active pages:\n",
                     caio_md,
                     clist_size(CAIO_MD_PAGE_LIST(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md))));
        clist_print(log, CAIO_MD_PAGE_LIST(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md)),
                    (CLIST_DATA_DATA_PRINT)caio_page_print);

        sys_log(log, "caio_print: caio_md %p: %u standby pages:\n",
                     caio_md,
                     clist_size(CAIO_MD_PAGE_LIST(caio_md, CAIO_MD_STANDBY_PAGE_LIST_IDX(caio_md))));
        clist_print(log, CAIO_MD_PAGE_LIST(caio_md, CAIO_MD_STANDBY_PAGE_LIST_IDX(caio_md)),
                    (CLIST_DATA_DATA_PRINT)caio_page_print);

        if(0)
        {
            caio_show_pages(log, caio_md);
        }

        sys_log(log, "caio_print: caio_md %p: %ld post event reqs: \n",
                     caio_md, clist_size(CAIO_MD_POST_EVENT_REQS(caio_md)));

        if(1)
        {
            caio_show_post_event_reqs(log, caio_md);
        }

        sys_log(log, "caio_print: caio_md %p: mem cache: \n", caio_md);
        caio_mem_cache_counter_print(log);

        sys_log(log, "caio_print: caio_md %p: read-only:%u\n", caio_md, CAIO_MD_RDONLY_FLAG(caio_md));
    }

    return;
}

/*for debug only*/
UINT32 caio_block_size_nbytes(const CAIO_MD *caio_md)
{
    const CAIO_CFG     *caio_cfg;

    caio_cfg   = __caio_cfg_fetch(CAIO_MD_MODEL(caio_md));

    return CAIO_CFG_BLOCK_SIZE_NBYTES(caio_cfg);
}

/*for debug only*/
UINT32 caio_block_size_nbits(const CAIO_MD *caio_md)
{
    const CAIO_CFG     *caio_cfg;

    caio_cfg   = __caio_cfg_fetch(CAIO_MD_MODEL(caio_md));

    return CAIO_CFG_BLOCK_SIZE_NBITS(caio_cfg);
}

/*for debug only*/
UINT32 caio_block_size_mask(const CAIO_MD *caio_md)
{
    const CAIO_CFG     *caio_cfg;

    caio_cfg   = __caio_cfg_fetch(CAIO_MD_MODEL(caio_md));

    return CAIO_CFG_BLOCK_SIZE_MASK(caio_cfg);
}

EC_BOOL caio_event_handler(CAIO_MD *caio_md)
{
    int                 nread;
    int                 nevent;
    uint64_t            nready;
    struct io_event     event[ CAIO_EVENT_MAX_NUM ];

    nread = read(CAIO_MD_AIO_EVENTFD(caio_md), &nready, sizeof(uint64_t));

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                         "nread = %d\n",
                                         nread);

    if(sizeof(uint64_t) != nread)
    {
        if(-1 == nread)
        {
            if(EAGAIN == errno)
            {
                return (EC_AGAIN);
            }

            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_event_handler: "
                                                 "read %d failed\n",
                                                 CAIO_MD_AIO_EVENTFD(caio_md));
            return (EC_FALSE);
        }

        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_event_handler: "
                                             "read only %d bytes\n",
                                             nread);
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                         "nready = %"PRId64"\n",
                                         nready);

    while(0 < nready)
    {
        int idx;

#if (SWITCH_ON == CAIO_STAT_DEBUG)
        uint64_t    cur_usec;
#endif/*(SWITCH_ON == CAIO_STAT_DEBUG)*/
        if(EC_FALSE == __caio_getevents(CAIO_MD_AIO_CONTEXT(caio_md), 0, CAIO_EVENT_MAX_NUM, event, NULL_PTR, &nevent))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_event_handler: "
                                                 "io get events failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                             "io get events %d\n",
                                             nevent);

        if(0 == nevent)
        {
            return (EC_TRUE);
        }

        /*else*/
#if (SWITCH_ON == CAIO_STAT_DEBUG)
        cur_usec = c_get_cur_time_usec();
#endif/*(SWITCH_ON == CAIO_STAT_DEBUG)*/
        if(nready >= nevent)
        {
            nready -= nevent;
        }
        else
        {
            nready = 0;
        }

        for(idx = 0; idx < nevent; idx ++)
        {
            CAIO_PAGE *caio_page;
            CAIO_DISK *caio_disk;

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                                 "data: %p, obj %p, res %lld, res2 %lld\n",
                                                 (void *)event[ idx ].data, (void *)event[ idx ].obj,
                                                 event[ idx ].res , event[ idx ].res2);

            caio_page = (CAIO_PAGE *)(event[ idx ].data);

            CAIO_ASSERT(NULL_PTR != caio_page);

            if(do_log(SEC_0093_CAIO, 9))
            {
                dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: page is\n");
                caio_page_print(LOGSTDOUT, caio_page);
            }

            dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                            "page %s, [%ld, %ld), fd %d => [crc %u]\n",
                            __caio_op_str(CAIO_PAGE_OP(caio_page)),
                            CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                            CAIO_PAGE_FD(caio_page),
                            CAIO_CRC32(CAIO_PAGE_M_CACHE(caio_page),
                                         CAIO_PAGE_F_E_OFFSET(caio_page)- CAIO_PAGE_F_S_OFFSET(caio_page)));

            CAIO_ASSERT(NULL_PTR != CAIO_PAGE_CAIO_DISK(caio_page));

            caio_disk = CAIO_PAGE_CAIO_DISK(caio_page);
            CAIO_DISK_CUR_REQ_NUM(caio_disk) --;

            caio_del_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), caio_page);

            CAIO_PAGE_WORKING_FLAG(caio_page) = BIT_FALSE; /*clear*/

            /*WARNING: sometimes res2 = 0, but res stores the negative value of errno*/
            if(0 != event[ idx ].res2 || 0 > event[ idx ].res)
            {
                int err;

                err = (int)(-event[ idx ].res);
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_event_handler: "
                                                     "errno = %d, errstr = %s\n",
                                                     err, strerror(err));

                /*set bad page*/
                caio_disk_set_bad_page(CAIO_PAGE_CAIO_DISK(caio_page), CAIO_PAGE_NO(caio_page));
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                                     "set disk (fd %d) bad page %u, range [%ld, %ld) done\n",
                                                     CAIO_PAGE_FD(caio_page),
                                                     CAIO_PAGE_NO(caio_page),
                                                     CAIO_PAGE_F_S_OFFSET(caio_page),
                                                     CAIO_PAGE_F_E_OFFSET(caio_page));

                caio_page_terminate(caio_page);
            }
            else
            {
#if (SWITCH_ON == CAIO_STAT_DEBUG)
                uint64_t elapsed_msec;

                elapsed_msec = ((cur_usec - CAIO_PAGE_SUBMIT_USEC(caio_page)) /  1000);

                if(10 < elapsed_msec)
                {
                    g_caio_stat_tbl[ 10 + 1 ] ++;
                }
                else
                {
                    g_caio_stat_tbl[ elapsed_msec ] ++;
                }

                g_caio_stat_sum ++;

#endif/*(SWITCH_ON == CAIO_STAT_DEBUG)*/

                dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                                     "trigger complete handler\n");

                caio_page_complete(caio_page);
            }
        }
    }

#if (SWITCH_ON == CAIO_STAT_DEBUG)
    if(0 < g_caio_stat_sum)
    {
        dbg_log(SEC_0093_CAIO, 1)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                             "0:%.2f,1:%.2f,2:%.2f,3:%.2f,4:%.2f,5:%.2f,6:%.2f,"
                                             "7:%.2f,8:%.2f,9:%.2f,10:%.2f,O:%.2f\n",
                                             ((0.0 + g_caio_stat_tbl[0]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[1]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[2]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[3]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[4]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[5]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[6]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[7]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[8]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[9]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[10]) / (0.0 + g_caio_stat_sum)),
                                             ((0.0 + g_caio_stat_tbl[10 + 1]) / (0.0 + g_caio_stat_sum)));
    }
#endif/*(SWITCH_ON == CAIO_STAT_DEBUG)*/
    return (EC_TRUE);
}


int caio_get_eventfd(CAIO_MD *caio_md)
{
    return CAIO_MD_AIO_EVENTFD(caio_md);
}

EC_BOOL caio_try_quit(CAIO_MD *caio_md)
{
    UINT32  page_list_idx;

    static UINT32  warning_counter = 0; /*suppress warning report*/

    caio_event_handler(caio_md); /*handle once*/
    caio_process(caio_md);       /*process once*/

    page_list_idx = 0;
    if(EC_TRUE == caio_has_page(caio_md, page_list_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_quit: "
                                                 "page list %ld# is not empty\n",
                                                 page_list_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    page_list_idx = 1;
    if(EC_TRUE == caio_has_page(caio_md, page_list_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_quit: "
                                                 "page list %ld# is not empty\n",
                                                 page_list_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    if(EC_TRUE == caio_has_event(caio_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_quit: "
                                                 "has event yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    if(EC_TRUE == caio_has_req(caio_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_quit: "
                                                 "has req yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    warning_counter = 0;

    return (EC_TRUE);
}

/*copy from caio_try_quit*/
EC_BOOL caio_try_restart(CAIO_MD *caio_md)
{
    UINT32  page_list_idx;

    static UINT32  warning_counter = 0; /*suppress warning report*/

    caio_event_handler(caio_md); /*handle once*/
    caio_process(caio_md);       /*process once*/

    page_list_idx = 0;
    if(EC_TRUE == caio_has_wr_page(caio_md, page_list_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_restart: "
                                                 "page list %ld# has wr page\n",
                                                 page_list_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    page_list_idx = 1;
    if(EC_TRUE == caio_has_wr_page(caio_md, page_list_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_restart: "
                                                 "page list %ld# is not empty\n",
                                                 page_list_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

#if 0
    if(EC_TRUE == caio_has_event(caio_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_restart: "
                                                 "has event yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }
#endif

    if(EC_TRUE == caio_has_wr_req(caio_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_try_restart: "
                                                 "has wr req yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    warning_counter = 0;

    return (EC_TRUE);
}

EC_BOOL caio_set_read_only(CAIO_MD *caio_md)
{
    if(BIT_TRUE == CAIO_MD_RDONLY_FLAG(caio_md))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_set_read_only: "
                                             "caio is set already read-only\n");

        return (EC_FALSE);
    }

    CAIO_MD_RDONLY_FLAG(caio_md) = BIT_TRUE;

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_set_read_only: "
                                         "set caio read-only\n");

    return (EC_TRUE);
}

EC_BOOL caio_unset_read_only(CAIO_MD *caio_md)
{
    if(BIT_FALSE == CAIO_MD_RDONLY_FLAG(caio_md))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_unset_read_only: "
                                             "caio was not set read-only\n");

        return (EC_FALSE);
    }

    CAIO_MD_RDONLY_FLAG(caio_md) = BIT_FALSE;

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_unset_read_only: "
                                         "unset caio read-only\n");

    return (EC_TRUE);
}

EC_BOOL caio_is_read_only(const CAIO_MD *caio_md)
{
    if(BIT_FALSE == CAIO_MD_RDONLY_FLAG(caio_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


/*for debug*/
EC_BOOL caio_poll(CAIO_MD *caio_md)
{
    caio_event_handler(caio_md);

    caio_process(caio_md);

    return (EC_TRUE);
}

void caio_process(CAIO_MD *caio_md)
{
    caio_process_pages(caio_md);
    caio_process_events(caio_md);
    caio_process_reqs(caio_md);

   return;
}

void caio_process_reqs(CAIO_MD *caio_md)
{
    caio_process_timeout_reqs(caio_md);
    return;
}

/*check and process timeout reqs*/
void caio_process_timeout_reqs(CAIO_MD *caio_md)
{
    CLIST_DATA      *clist_data;

    UINT32           req_num;
    uint64_t         cur_time_ms;

    cur_time_ms = c_get_cur_time_msec();
    req_num     = 0;

    CLIST_LOOP_NEXT(CAIO_MD_REQ_LIST(caio_md), clist_data)
    {
        CAIO_REQ       *caio_req;

        caio_req = (CAIO_REQ *)CLIST_DATA_DATA(clist_data);
        CAIO_ASSERT(CAIO_REQ_MOUNTED_REQS(caio_req) == clist_data);

        if(cur_time_ms >= CAIO_REQ_NTIME_MS(caio_req))
        {
            clist_data = CLIST_DATA_PREV(clist_data);

            req_num ++;

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_process_timeout_reqs: "
                             "req %ld, file range [%ld, %ld), op %s "
                             "timeout %ld seconds, next access time %ld, cur time %ld => timeout\n",
                             CAIO_REQ_SEQ_NO(caio_req),
                             CAIO_REQ_F_S_OFFSET(caio_req), CAIO_REQ_F_E_OFFSET(caio_req),
                             __caio_op_str(CAIO_REQ_OP(caio_req)),
                             CAIO_REQ_TIMEOUT_NSEC(caio_req),
                             CAIO_REQ_NTIME_MS(caio_req),
                             cur_time_ms);

            caio_del_req(caio_md, caio_req);
            caio_req_timeout(caio_req);
        }
    }

    dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_timeout_reqs: "
                                         "process %ld timeout reqs\n",
                                         req_num);

    return;
}

EC_BOOL caio_process_page(CAIO_MD *caio_md, CAIO_PAGE *caio_page)
{
    struct iocb     *aiocb;

    if(CAIO_OP_RD == CAIO_PAGE_OP(caio_page))
    {
        aiocb = CAIO_PAGE_AIOCB(caio_page);
        aiocb->aio_data          = (uint64_t)((uintptr_t)(caio_page));
        aiocb->aio_lio_opcode    = IOCB_CMD_PREAD;
        aiocb->aio_fildes        = CAIO_PAGE_FD(caio_page);
        aiocb->aio_buf           = (uint64_t)((uintptr_t)CAIO_PAGE_M_CACHE(caio_page));
        aiocb->aio_nbytes        = (size_t)(CAIO_PAGE_F_E_OFFSET(caio_page) - CAIO_PAGE_F_S_OFFSET(caio_page));
        aiocb->aio_offset        = (off_t )(CAIO_PAGE_F_S_OFFSET(caio_page));
        aiocb->aio_flags         = IOCB_FLAG_RESFD;
        aiocb->aio_resfd         = CAIO_MD_AIO_EVENTFD(caio_md);

        return (EC_TRUE);
    }

    if(CAIO_OP_WR == CAIO_PAGE_OP(caio_page))
    {
        CAIO_NODE       *caio_node;

        aiocb = CAIO_PAGE_AIOCB(caio_page);
        aiocb->aio_data          = (uint64_t)((uintptr_t)(caio_page));
        aiocb->aio_lio_opcode    = IOCB_CMD_PWRITE;
        aiocb->aio_fildes        = CAIO_PAGE_FD(caio_page);
        aiocb->aio_buf           = (uint64_t)((uintptr_t)CAIO_PAGE_M_CACHE(caio_page));
        aiocb->aio_nbytes        = (size_t)(CAIO_PAGE_F_E_OFFSET(caio_page) - CAIO_PAGE_F_S_OFFSET(caio_page));
        aiocb->aio_offset        = (off_t )(CAIO_PAGE_F_S_OFFSET(caio_page));
        aiocb->aio_flags         = IOCB_FLAG_RESFD;
        aiocb->aio_resfd         = CAIO_MD_AIO_EVENTFD(caio_md);

        while(NULL_PTR != (caio_node = caio_page_pop_node_front(caio_page)))
        {
            CAIO_ASSERT(CAIO_NODE_FD(caio_node) == CAIO_PAGE_FD(caio_page));

            if(CAIO_OP_WR == CAIO_NODE_OP(caio_node))
            {
                dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_page: "
                                "[WR] node %ld/%ld of req %ld, "
                                "copy from app [%ld, %ld) to page [%ld, %ld), fd %d\n",
                                CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                                CAIO_NODE_SEQ_NO(caio_node),
                                CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                                CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                                CAIO_PAGE_FD(caio_page));

                /*copy data from application mem buff to mem cache*/
                FCOPY(CAIO_NODE_M_BUFF(caio_node),
                      CAIO_PAGE_M_CACHE(caio_page) + CAIO_NODE_B_S_OFFSET(caio_node),
                      CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node));

                caio_node_complete(caio_node);
            }
            else if(CAIO_OP_RD == CAIO_NODE_OP(caio_node))
            {
                if(NULL_PTR != CAIO_NODE_M_BUFF(caio_node))
                {
                    dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_page: "
                                    "[RD] node %ld/%ld of req %ld, "
                                    "copy from page [%ld, %ld), fd %d to app [%ld, %ld)\n",
                                    CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                                    CAIO_NODE_SEQ_NO(caio_node),
                                    CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                                    CAIO_PAGE_FD(caio_page),
                                    CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node));

                    /*copy data from mem cache to application mem buff*/
                    FCOPY(CAIO_PAGE_M_CACHE(caio_page) + CAIO_NODE_B_S_OFFSET(caio_node),
                          CAIO_NODE_M_BUFF(caio_node),
                          CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node));
                }
                else
                {
                    dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_page: "
                                    "[RD] node %ld/%ld of req %ld, "
                                    "ignore copy from page [%ld, %ld), fd %d to app [%ld, %ld)\n",
                                    CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                                    CAIO_NODE_SEQ_NO(caio_node),
                                    CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                                    CAIO_PAGE_FD(caio_page),
                                    CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node));
                }

                caio_node_complete(caio_node);
            }
            else
            {
                /*should never reach here*/
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_process_page: "
                                 "invalid op: node %ld/%ld of req %ld, "
                                 "block range [%ld, %ld), file range [%ld, %ld) op %s "
                                 "in page [%ld, %ld)\n",
                                 CAIO_NODE_SUB_SEQ_NO(caio_node), CAIO_NODE_SUB_SEQ_NUM(caio_node),
                                 CAIO_NODE_SEQ_NO(caio_node),
                                 CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                                 CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                                 __caio_op_str(CAIO_NODE_OP(caio_node)),
                                 CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page));

                caio_node_free(caio_node);
                return (EC_FALSE);
            }
        }

        dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_page: "
                        "page %s, [%ld, %ld), fd %d => [crc %u]\n",
                        __caio_op_str(CAIO_PAGE_OP(caio_page)),
                        CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                        CAIO_PAGE_FD(caio_page),
                        CAIO_CRC32(CAIO_PAGE_M_CACHE(caio_page),
                                     CAIO_PAGE_F_E_OFFSET(caio_page)- CAIO_PAGE_F_S_OFFSET(caio_page)));

        return (EC_TRUE);
    }

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_process_page: invalid page:\n");
    caio_page_print(LOGSTDOUT, caio_page);

    return (EC_FALSE);
}

void caio_process_pages(CAIO_MD *caio_md)
{
    CAIO_PAGE       *caio_page;

    struct iocb     *piocb[ CAIO_REQ_MAX_NUM ];
    UINT32           aio_req_num_saved;
    UINT32           aio_req_num;
    UINT32           aio_req_idx;
    long             aio_total_nr;
    long             aio_succ_nr;
    UINT32           page_num;

    aio_req_num_saved = caio_count_req_num(caio_md);
    aio_req_num       = aio_req_num_saved;

    page_num          = caio_count_page_num(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md));

    while(NULL_PTR != (caio_page = caio_pop_first_page(caio_md,
                                        CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md))))
    {
        CAIO_DISK   *caio_disk;

        CAIO_ASSERT(NULL_PTR != CAIO_PAGE_CAIO_DISK(caio_page));
        caio_disk = CAIO_PAGE_CAIO_DISK(caio_page);

        if(BIT_TRUE == CAIO_PAGE_WORKING_FLAG(caio_page)
        || CAIO_REQ_MAX_NUM <= aio_req_num
        || (NULL_PTR != CAIO_DISK_MAX_REQ_NUM(caio_disk) && (*CAIO_DISK_MAX_REQ_NUM(caio_disk)) <= CAIO_DISK_CUR_REQ_NUM(caio_disk))
        )
        {
            /*add to standby page list temporarily*/
            caio_add_page(caio_md, CAIO_MD_STANDBY_PAGE_LIST_IDX(caio_md), caio_page);
            continue;
        }

        if(do_log(SEC_0093_CAIO, 9))
        {
            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_process_pages: process page:\n");
            caio_page_print_range(LOGSTDOUT, caio_page);
        }

        /*check bad page before submit aio request*/
        if(EC_TRUE == caio_disk_check_bad_page(caio_disk, CAIO_PAGE_NO(caio_page)))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_process_pages: "
                                                 "found disk (fd %d) bad page %u, range [%ld, %ld)\n",
                                                 CAIO_PAGE_FD(caio_page),
                                                 CAIO_PAGE_NO(caio_page),
                                                 CAIO_PAGE_F_S_OFFSET(caio_page),
                                                 CAIO_PAGE_F_E_OFFSET(caio_page));
            caio_page_terminate(caio_page);
            continue;
        }

        if(EC_FALSE == caio_process_page(caio_md, caio_page))
        {
            caio_page_terminate(caio_page);
            continue;
        }

        aio_req_idx = aio_req_num - aio_req_num_saved;
        piocb[ aio_req_idx ] = CAIO_PAGE_AIOCB(caio_page);

#if (SWITCH_ON == CAIO_STAT_DEBUG)
        CAIO_PAGE_SUBMIT_USEC(caio_page) = c_get_cur_time_usec();
#endif/*(SWITCH_ON == CAIO_STAT_DEBUG)*/
        aio_req_num ++;

        if(NULL_PTR != caio_disk)
        {
            CAIO_DISK_CUR_REQ_NUM(caio_disk) ++;
        }
    }

    /*switch page list*/
    CAIO_MD_SWITCH_PAGE_LIST(caio_md);

    CAIO_ASSERT(EC_FALSE == caio_has_page(caio_md, CAIO_MD_STANDBY_PAGE_LIST_IDX(caio_md)));

    aio_total_nr = (long)(aio_req_num - aio_req_num_saved);
    if(0 == aio_total_nr)
    {
        dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_pages: "
                                             "submit %ld aio requests\n",
                                             aio_total_nr);
        return;
    }

    if(EC_FALSE == __caio_submit(CAIO_MD_AIO_CONTEXT(caio_md), aio_total_nr, &aio_succ_nr, piocb))
    {
        UINT32  req_idx;

        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_process_pages: "
                                             "submit %ld requests to eventfd %d failed\n",
                                             aio_total_nr,
                                             CAIO_MD_AIO_EVENTFD(caio_md));

        /*restore fail nodes*/
        for(req_idx = 0; req_idx < (UINT32)aio_total_nr; req_idx ++)
        {
            CAIO_DISK       *caio_disk;

            caio_page = CAIO_AIOCB_PAGE(piocb[ req_idx ]);
            piocb[ req_idx ] = NULL_PTR;

            /*add back to active page list*/
            caio_add_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), caio_page);

            CAIO_ASSERT(NULL_PTR != CAIO_PAGE_CAIO_DISK(caio_page));
            caio_disk = CAIO_PAGE_CAIO_DISK(caio_page);

            CAIO_DISK_CUR_REQ_NUM(caio_disk) --;
        }

        return;
    }

    if(0 <= aio_succ_nr)
    {
        UINT32          req_idx;
        UINT32          req_succ_num;
        UINT32          req_fail_num;

        req_succ_num = (UINT32)(aio_succ_nr);
        req_fail_num = (UINT32)(aio_total_nr - aio_succ_nr);

        /*add succ nodes back to active page list for page searching by other request*/
        for(req_idx = 0; req_idx < (UINT32)aio_succ_nr; req_idx ++)
        {
            caio_page = CAIO_AIOCB_PAGE(piocb[ req_idx ]);
            piocb[ req_idx ] = NULL_PTR;

            CAIO_PAGE_WORKING_FLAG(caio_page) = BIT_TRUE;

            /*add back to active page list*/
            caio_add_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), caio_page);/*xxx*/

            dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_pages: "
                            "submit aio: page %s, [%ld, %ld), fd %d\n",
                            __caio_op_str(CAIO_PAGE_OP(caio_page)),
                            CAIO_PAGE_F_S_OFFSET(caio_page), CAIO_PAGE_F_E_OFFSET(caio_page),
                            CAIO_PAGE_FD(caio_page));
        }

        /*restore fail nodes*/
        for(; req_idx < (UINT32)aio_total_nr; req_idx ++)
        {
            CAIO_DISK       *caio_disk;

            caio_page = CAIO_AIOCB_PAGE(piocb[ req_idx ]);
            piocb[ req_idx ] = NULL_PTR;

            /*add back to active page list*/
            caio_add_page(caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), caio_page);

            CAIO_ASSERT(NULL_PTR != CAIO_PAGE_CAIO_DISK(caio_page));
            caio_disk = CAIO_PAGE_CAIO_DISK(caio_page);

            CAIO_DISK_CUR_REQ_NUM(caio_disk) --;
        }

        dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_pages: "
                                             "submit aio to eventfd %d: pages %ld, total %ld, succ %ld, fail %ld\n",
                                             CAIO_MD_AIO_EVENTFD(caio_md),
                                             page_num, aio_total_nr, req_succ_num, req_fail_num);

#if (SWITCH_ON == CAIO_STAT_DEBUG)
        dbg_log(SEC_0093_CAIO, 2)(LOGSTDOUT, "[DEBUG] caio_process_pages: "
                                             "submit aio to eventfd %d: pages %ld, %ld => %ld, total %ld, succ %ld, fail %ld\n",
                                             CAIO_MD_AIO_EVENTFD(caio_md),
                                             page_num, aio_req_num_saved, aio_req_num,
                                             aio_total_nr, req_succ_num, req_fail_num);
#endif/*(SWITCH_ON == CAIO_STAT_DEBUG)*/
        return;
    }

    /*should never reach here*/
    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_process_pages: "
                                         "submit %ld aio requests failed\n",
                                         aio_total_nr);

    return;
}

void caio_process_events(CAIO_MD *caio_md)
{
    caio_process_post_event_reqs(caio_md, CAIO_PROCESS_EVENT_ONCE_NUM);

    return;
}

void caio_process_post_event_reqs(CAIO_MD *caio_md, const UINT32 process_event_max_num)
{
    CAIO_REQ        *caio_req;
    UINT32           counter;
    UINT32           event_num;
    UINT32           max_num;

    event_num = clist_size(CAIO_MD_POST_EVENT_REQS(caio_md));
    max_num   = DMIN(event_num, process_event_max_num);
    counter   = 0;

    while(counter < max_num
    && NULL_PTR != (caio_req = clist_pop_front(CAIO_MD_POST_EVENT_REQS(caio_md))))
    {
        CAIO_EVENT_HANDLER      handler;

        counter ++;

        CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req) = NULL_PTR;

        handler = CAIO_REQ_POST_EVENT_HANDLER(caio_req);  /*save*/
        CAIO_REQ_POST_EVENT_HANDLER(caio_req) = NULL_PTR; /*clear*/

        /*note: node may be push back to list*/
        handler(caio_req);
    }

    dbg_log(SEC_0093_CAIO, 5)(LOGSTDOUT, "[DEBUG] caio_process_post_event_reqs: process %ld reqs\n", counter);

    return;
}

EC_BOOL caio_has_post_event_req(CAIO_MD *caio_md)
{
    if(EC_TRUE == clist_is_empty(CAIO_MD_POST_EVENT_REQS(caio_md)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL caio_has_event(CAIO_MD *caio_md)
{
    return caio_has_post_event_req(caio_md);
}

EC_BOOL caio_has_req(CAIO_MD *caio_md)
{
    if(EC_TRUE == clist_is_empty(CAIO_MD_REQ_LIST(caio_md)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL caio_has_wr_req(CAIO_MD *caio_md)
{
    CLIST_DATA  *clist_data;

    CLIST_LOOP_NEXT(CAIO_MD_REQ_LIST(caio_md), clist_data)
    {
        CAIO_REQ    *caio_req;

        caio_req = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == caio_req)
        {
            continue;
        }

        if(CAIO_OP_WR == CAIO_REQ_OP(caio_req))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

void caio_show_pages(LOG *log, const CAIO_MD *caio_md)
{
    //crb_list_print(log, CAIO_MD_PAGE_LIST(caio_md));
    clist_print(log, CAIO_MD_PAGE_LIST(caio_md, 0), (CLIST_DATA_DATA_PRINT)caio_page_print);
    clist_print(log, CAIO_MD_PAGE_LIST(caio_md, 1), (CLIST_DATA_DATA_PRINT)caio_page_print);
    return;
}

void caio_show_post_event_reqs(LOG *log, const CAIO_MD *caio_md)
{
    clist_print(log, CAIO_MD_POST_EVENT_REQS(caio_md), (CLIST_DATA_DATA_PRINT)caio_req_print);
    return;
}

void caio_show_page(LOG *log, const CAIO_MD *caio_md, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CAIO_PAGE   *caio_page;

    caio_page = caio_search_page((CAIO_MD *)caio_md, CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md), fd, f_s_offset, f_e_offset);
    if(NULL_PTR == caio_page)
    {
        sys_log(log, "caio_show_req: (no matched req)\n");
        return;
    }

    caio_page_print(log, caio_page);
    return;
}

void caio_show_disks(LOG *log, const CAIO_MD *caio_md)
{
    clist_print(log, CAIO_MD_DISK_LIST(caio_md), (CLIST_DATA_DATA_PRINT)caio_disk_print);
    return;
}

void caio_show_reqs(LOG *log, const CAIO_MD *caio_md)
{
    clist_print(log, CAIO_MD_REQ_LIST(caio_md), (CLIST_DATA_DATA_PRINT)caio_req_print);
    return;
}

void caio_show_req(LOG *log, const CAIO_MD *caio_md, const UINT32 seq_no)
{
    CAIO_REQ  *caio_req;

    caio_req = clist_search_data_front(CAIO_MD_REQ_LIST(caio_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)caio_req_is);


    if(NULL_PTR == caio_req)
    {
        sys_log(log, "caio_show_req: (none)\n");
        return;
    }

    caio_req_print(log, caio_req);
    return;
}

void caio_show_node(LOG *log, const CAIO_MD *caio_md, const UINT32 seq_no, const UINT32 sub_seq_no)
{
    CAIO_REQ  *caio_req;
    CAIO_NODE *caio_node;

    caio_req = clist_search_data_front(CAIO_MD_REQ_LIST(caio_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)caio_req_is);


    if(NULL_PTR == caio_req)
    {
        sys_log(log, "caio_show_req: (no matched req)\n");
        return;
    }

    caio_node = clist_search_data_front(CAIO_REQ_NODES(caio_req), (const void *)sub_seq_no,
                                        (CLIST_DATA_DATA_CMP)caio_node_is);

    if(NULL_PTR == caio_node)
    {
        sys_log(log, "caio_show_req: (none)\n");
        return;
    }

    caio_node_print(log, caio_node);
    return;
}

EC_BOOL caio_submit_req(CAIO_MD *caio_md, CAIO_REQ *caio_req)
{
    /*add req to request list of caio module*/
    if(EC_FALSE == caio_add_req(caio_md, caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_submit_req: add req %ld, op %s failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)));
        return (EC_FALSE);
    }

    /*make r/w ops of req*/
    if(EC_FALSE == caio_make_req_op(caio_md, caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_submit_req: make ops of req %ld, op %s failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)));
        return (EC_FALSE);
    }

    /*dispatch req which would bind each r/w op to specific page*/
    if(EC_FALSE == caio_dispatch_req(caio_md, caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_submit_req: dispatch req %ld, op %s failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_submit_req: submit req %ld, op %s done\n",
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)));
    return (EC_TRUE);
}

EC_BOOL caio_add_req(CAIO_MD *caio_md, CAIO_REQ *caio_req)
{
    CAIO_ASSERT(NULL_PTR == CAIO_REQ_MOUNTED_REQS(caio_req));

    /*push back*/
    CAIO_REQ_MOUNTED_REQS(caio_req) = clist_push_back(CAIO_MD_REQ_LIST(caio_md), (void *)caio_req);
    if(NULL_PTR == CAIO_REQ_MOUNTED_REQS(caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_add_req: push req %ld, op %s failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req),
                                             __caio_op_str(CAIO_REQ_OP(caio_req)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_add_req: push req %ld, op %s done\n",
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)));
    return (EC_TRUE);
}

EC_BOOL caio_del_req(CAIO_MD *caio_md, CAIO_REQ *caio_req)
{
    if(NULL_PTR != CAIO_REQ_MOUNTED_REQS(caio_req))
    {
        clist_erase(CAIO_MD_REQ_LIST(caio_md), CAIO_REQ_MOUNTED_REQS(caio_req));
        CAIO_REQ_MOUNTED_REQS(caio_req) = NULL_PTR;

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_del_req: req %ld, op %s\n",
                     CAIO_REQ_SEQ_NO(caio_req),
                     __caio_op_str(CAIO_REQ_OP(caio_req)));

    }
    return (EC_TRUE);
}

EC_BOOL caio_make_req_op(CAIO_MD *caio_md, CAIO_REQ *caio_req)
{
    if(CAIO_OP_RD == CAIO_REQ_OP(caio_req))
    {
        if(EC_FALSE == caio_req_make_read(caio_req))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_make_req_op: make read req %ld ops failed\n",
                                                 CAIO_REQ_SEQ_NO(caio_req));
            return (EC_FALSE);
        }

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_make_req_op: make read req %ld ops done\n",
                                             CAIO_REQ_SEQ_NO(caio_req));

        return (EC_TRUE);
    }

    if(CAIO_OP_WR == CAIO_REQ_OP(caio_req))
    {
        if(EC_FALSE == caio_req_make_write(caio_req))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_make_req_op: make write req %ld ops failed\n",
                                                 CAIO_REQ_SEQ_NO(caio_req));
            return (EC_FALSE);
        }

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_make_req_op: make write req %ld ops done\n",
                                             CAIO_REQ_SEQ_NO(caio_req));

        return (EC_TRUE);
    }

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_make_req_op: invalid req %ld, op %s\n",
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)));
    return (EC_FALSE);
}

EC_BOOL caio_dispatch_req(CAIO_MD *caio_md, CAIO_REQ *caio_req)
{
    CLIST_DATA  *clist_data;

    CLIST_LOOP_NEXT(CAIO_REQ_NODES(caio_req), clist_data)
    {
        CAIO_NODE *caio_node;

        caio_node = (CAIO_NODE *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == caio_req_dispatch_node(caio_req, caio_node))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_dispatch_req: "
                                                 "dispatch %ld of req %ld, op %s failed\n",
                                                 CAIO_NODE_SUB_SEQ_NO(caio_node),
                                                 CAIO_REQ_SEQ_NO(caio_req),
                                                 __caio_op_str(CAIO_REQ_OP(caio_req)));

            caio_cancel_req(caio_md, caio_req);

            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_dispatch_req: "
                                         "dispatch req %ld, op %s done\n",
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)));

    return (EC_TRUE);
}

EC_BOOL caio_cancel_req(CAIO_MD *caio_md, CAIO_REQ *caio_req)
{
    CAIO_NODE *caio_node;

    while(NULL_PTR != (caio_node = caio_req_pop_node_back(caio_req)))
    {
        caio_req_cancel_node(caio_req, caio_node);
        caio_node_free(caio_node);
    }

    /*delete post event regarding this req*/
    caio_req_del_post_event(caio_req);

    /*delete req from caio module*/
    caio_del_req(caio_md, caio_req);

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_cancel_req: "
                                         "cancel req %ld, op %s done\n",
                                         CAIO_REQ_SEQ_NO(caio_req),
                                         __caio_op_str(CAIO_REQ_OP(caio_req)));
    return (EC_TRUE);
}

UINT32 caio_count_page_num(const CAIO_MD *caio_md, const UINT32 page_list_idx)
{
    return clist_size(CAIO_MD_PAGE_LIST(caio_md, page_list_idx));
}

EC_BOOL caio_add_page(CAIO_MD *caio_md, const UINT32 page_list_idx, CAIO_PAGE *caio_page)
{
    CLIST_DATA    *clist_data;

    CAIO_ASSERT(NULL_PTR == CAIO_PAGE_MOUNTED_PAGES(caio_page));

    clist_data = clist_push_back(CAIO_MD_PAGE_LIST(caio_md, page_list_idx), (void *)caio_page);
    if(NULL_PTR == clist_data)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_add_page: "
                                             "add page [%ld, %ld), fd %d to %ld (%s) list failed\n",
                                             CAIO_PAGE_F_S_OFFSET(caio_page),
                                             CAIO_PAGE_F_E_OFFSET(caio_page),
                                             CAIO_PAGE_FD(caio_page),
                                             page_list_idx,
                                             ((CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md) == page_list_idx)?
                                            (const char *)"active" : (const char *)"standby"));
        return (EC_FALSE);
    }

    CAIO_PAGE_MOUNTED_PAGES(caio_page)    = clist_data;
    CAIO_PAGE_MOUNTED_LIST_IDX(caio_page) = page_list_idx;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_add_page: "
                                         "add page [%ld, %ld), fd %d to %ld (%s) list done\n",
                                         CAIO_PAGE_F_S_OFFSET(caio_page),
                                         CAIO_PAGE_F_E_OFFSET(caio_page),
                                         CAIO_PAGE_FD(caio_page),
                                         page_list_idx,
                                         ((CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md) == page_list_idx)?
                                         (const char *)"active" : (const char *)"standby"));
    return (EC_TRUE);
}

EC_BOOL caio_del_page(CAIO_MD *caio_md, const UINT32 page_list_idx, CAIO_PAGE *caio_page)
{
    if(NULL_PTR != CAIO_PAGE_MOUNTED_PAGES(caio_page))
    {
        CAIO_ASSERT(page_list_idx == CAIO_PAGE_MOUNTED_LIST_IDX(caio_page));
        CAIO_ASSERT(caio_page == CLIST_DATA_DATA(CAIO_PAGE_MOUNTED_PAGES(caio_page)));

        clist_erase(CAIO_MD_PAGE_LIST(caio_md, page_list_idx), CAIO_PAGE_MOUNTED_PAGES(caio_page));

        CAIO_PAGE_MOUNTED_PAGES(caio_page)    = NULL_PTR;
        CAIO_PAGE_MOUNTED_LIST_IDX(caio_page) = CAIO_PAGE_LIST_IDX_ERR;

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_del_page: "
                                             "del page [%ld, %ld), fd %d from %ld (%s) list done\n",
                                             CAIO_PAGE_F_S_OFFSET(caio_page),
                                             CAIO_PAGE_F_E_OFFSET(caio_page),
                                             CAIO_PAGE_FD(caio_page),
                                             page_list_idx,
                                            ((CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md) == page_list_idx)?
                                            (const char *)"active" : (const char *)"standby"));
    }
    return (EC_TRUE);
}

EC_BOOL caio_has_page(CAIO_MD *caio_md, const UINT32 page_list_idx)
{
    if(EC_TRUE == clist_is_empty(CAIO_MD_PAGE_LIST(caio_md, page_list_idx)))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*writting page*/
EC_BOOL caio_has_wr_page(CAIO_MD *caio_md, const UINT32 page_list_idx)
{
    CLIST_DATA  *clist_data;

    CLIST_LOOP_NEXT(CAIO_MD_PAGE_LIST(caio_md, page_list_idx), clist_data)
    {
        CAIO_PAGE   *caio_page;

        caio_page = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == caio_page)
        {
            continue;
        }

        if(CAIO_OP_WR == CAIO_PAGE_OP(caio_page))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

CAIO_PAGE *caio_pop_first_page(CAIO_MD *caio_md, const UINT32 page_list_idx)
{
    CAIO_PAGE   *caio_page;

    caio_page = clist_pop_front(CAIO_MD_PAGE_LIST(caio_md, page_list_idx));
    if(NULL_PTR == caio_page)
    {
        return (NULL_PTR);
    }

    CAIO_ASSERT(caio_page == CLIST_DATA_DATA(CAIO_PAGE_MOUNTED_PAGES(caio_page)));
    CAIO_PAGE_MOUNTED_PAGES(caio_page)    = NULL_PTR;
    CAIO_PAGE_MOUNTED_LIST_IDX(caio_page) = CAIO_PAGE_LIST_IDX_ERR;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_pop_first_page: "
                                         "pop page [%ld, %ld), fd %d from %ld (%s) list done\n",
                                         CAIO_PAGE_F_S_OFFSET(caio_page),
                                         CAIO_PAGE_F_E_OFFSET(caio_page),
                                         CAIO_PAGE_FD(caio_page),
                                         page_list_idx,
                                        ((CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md) == page_list_idx)?
                                        (const char *)"active" : (const char *)"standby"));
    return (caio_page);
}

CAIO_PAGE *caio_pop_last_page(CAIO_MD *caio_md, const UINT32 page_list_idx)
{
    CAIO_PAGE   *caio_page;

    caio_page = clist_pop_back(CAIO_MD_PAGE_LIST(caio_md, page_list_idx));
    if(NULL_PTR == caio_page)
    {
        return (NULL_PTR);
    }

    CAIO_ASSERT(caio_page == CLIST_DATA_DATA(CAIO_PAGE_MOUNTED_PAGES(caio_page)));
    CAIO_PAGE_MOUNTED_PAGES(caio_page)    = NULL_PTR;
    CAIO_PAGE_MOUNTED_LIST_IDX(caio_page) = CAIO_PAGE_LIST_IDX_ERR;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_pop_last_page: "
                                         "pop page [%ld, %ld), fd %d from %ld (%s) list done\n",
                                         CAIO_PAGE_F_S_OFFSET(caio_page),
                                         CAIO_PAGE_F_E_OFFSET(caio_page),
                                         CAIO_PAGE_FD(caio_page),
                                         page_list_idx,
                                        ((CAIO_MD_ACTIVE_PAGE_LIST_IDX(caio_md) == page_list_idx)?
                                        (const char *)"active" : (const char *)"standby"));
    return (caio_page);
}

CAIO_PAGE *caio_search_page(CAIO_MD *caio_md, const UINT32 page_list_idx, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CAIO_PAGE       caio_page_t;

    CAIO_PAGE_FD(&caio_page_t)         = fd;
    CAIO_PAGE_F_S_OFFSET(&caio_page_t) = f_s_offset;
    CAIO_PAGE_F_E_OFFSET(&caio_page_t) = f_e_offset;

    return clist_search_data_front(CAIO_MD_PAGE_LIST(caio_md, page_list_idx),
                                  (void *)&caio_page_t,
                                  (CLIST_DATA_DATA_CMP)caio_page_cmp);
}

EC_BOOL caio_cleanup_reqs(CAIO_MD *caio_md)
{
    CAIO_REQ        *caio_req;

    while(NULL_PTR != (caio_req = clist_pop_front(CAIO_MD_REQ_LIST(caio_md))))
    {
        CAIO_REQ_MOUNTED_REQS(caio_req) = NULL_PTR;

        caio_req_free(caio_req);
    }

    return (EC_TRUE);
}

EC_BOOL caio_cleanup_pages(CAIO_MD *caio_md, const UINT32 page_list_idx)
{
    CAIO_PAGE        *caio_page;

    while(NULL_PTR != (caio_page = caio_pop_first_page(caio_md, page_list_idx)))
    {
        caio_page_free(caio_page);
    }

    return (EC_TRUE);
}

EC_BOOL caio_cleanup_post_event_reqs(CAIO_MD *caio_md)
{
    CAIO_REQ        *caio_req;

    while(NULL_PTR != (caio_req = clist_pop_front(CAIO_MD_POST_EVENT_REQS(caio_md))))
    {
        CAIO_REQ_POST_EVENT_HANDLER(caio_req)      = NULL_PTR;
        CAIO_REQ_MOUNTED_POST_EVENT_REQS(caio_req) = NULL_PTR;

        caio_req_free(caio_req);
    }

    return (EC_TRUE);
}

CAIO_REQ *caio_search_req(CAIO_MD *caio_md, const UINT32 seq_no)
{
    CAIO_REQ       *caio_req;

    caio_req = clist_search_data_front(CAIO_MD_REQ_LIST(caio_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)caio_req_is);

    return (caio_req);
}

EC_BOOL caio_add_disk(CAIO_MD *caio_md, const int fd, UINT32 *max_req_num)
{
    if(NULL_PTR == caio_find_disk(caio_md, fd))
    {
        CAIO_DISK   *caio_disk;

        caio_disk = caio_disk_new();
        if(NULL_PTR == caio_disk)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_add_disk: new caio_disk failed\n");
            return (EC_FALSE);
        }

        CAIO_DISK_FD(caio_disk)             = fd;
        CAIO_DISK_MAX_REQ_NUM(caio_disk)    = max_req_num;
        CAIO_DISK_BAD_BITMAP(caio_disk)     = NULL_PTR;

        clist_push_back(CAIO_MD_DISK_LIST(caio_md), (void *)caio_disk);
    }

    return (EC_TRUE);
}

EC_BOOL caio_del_disk(CAIO_MD *caio_md, const int fd)
{
    CAIO_DISK   *caio_disk;

    caio_disk = clist_del(CAIO_MD_DISK_LIST(caio_md),
                          (void *)((UINT32)fd),
                          (CLIST_DATA_DATA_CMP)caio_disk_is_fd);

    if(NULL_PTR == caio_disk)
    {
        return (EC_FALSE);
    }

    caio_disk_free(caio_disk);
    return (EC_TRUE);
}

CAIO_DISK *caio_find_disk(CAIO_MD *caio_md, const int fd)
{
    CAIO_DISK   *caio_disk;

    caio_disk = clist_search_data_front(CAIO_MD_DISK_LIST(caio_md),
                          (void *)((UINT32)fd),
                          (CLIST_DATA_DATA_CMP)caio_disk_is_fd);

    return (caio_disk);
}

EC_BOOL caio_mount_disk_bad_bitmap(CAIO_MD *caio_md, const int fd, CBAD_BITMAP *cbad_bitmap)
{
    CAIO_DISK   *caio_disk;

    caio_disk = caio_find_disk(caio_md, fd);
    if(NULL_PTR == caio_disk)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_mount_disk_bad_bitmap: "
                                             "no disk for fd %d\n",
                                             fd);
        return (EC_FALSE);
    }

    if(NULL_PTR != CAIO_DISK_BAD_BITMAP(caio_disk))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_mount_disk_bad_bitmap: "
                                             "disk of fd %d has already bad bitmap\n",
                                             fd);
        return (EC_FALSE);
    }

    CAIO_DISK_BAD_BITMAP(caio_disk)             = cbad_bitmap;

    return (EC_TRUE);
}

EC_BOOL caio_umount_disk_bad_bitmap(CAIO_MD *caio_md, const int fd)
{
    CAIO_DISK   *caio_disk;

    caio_disk = caio_find_disk(caio_md, fd);
    if(NULL_PTR == caio_disk)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_umount_disk_bad_bitmap: "
                                             "no disk for fd %d\n",
                                             fd);
        return (EC_FALSE);
    }

    if(NULL_PTR == CAIO_DISK_BAD_BITMAP(caio_disk))
    {

        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_umount_disk_bad_bitmap: "
                                             "disk of fd %d has no bad bitmap\n",
                                             fd);
        return (EC_FALSE);
    }

    CAIO_DISK_BAD_BITMAP(caio_disk)             = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL caio_is_disk_bad_page(CAIO_MD *caio_md, const int fd, const uint32_t page_no)
{
    CAIO_DISK   *caio_disk;

    caio_disk = caio_find_disk(caio_md, fd);
    if(NULL_PTR == caio_disk || NULL_PTR == CAIO_DISK_BAD_BITMAP(caio_disk))
    {
        return (EC_FALSE);
    }

    return cbad_bitmap_is(CAIO_DISK_BAD_BITMAP(caio_disk), page_no, (uint8_t)1);
}

EC_BOOL caio_set_disk_bad_page(CAIO_MD *caio_md, const int fd, const uint32_t page_no)
{
    CAIO_DISK   *caio_disk;

    caio_disk = caio_find_disk(caio_md, fd);
    if(NULL_PTR == caio_disk || NULL_PTR == CAIO_DISK_BAD_BITMAP(caio_disk))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] caio_set_disk_bad_page: "
                                         "set disk bad page: fd %d, page %u\n",
                                         fd, page_no);

    if(EC_FALSE == cbad_bitmap_set(CAIO_DISK_BAD_BITMAP(caio_disk), page_no))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL caio_clear_disk_bad_page(CAIO_MD *caio_md, const int fd, const uint32_t page_no)
{
    CAIO_DISK   *caio_disk;

    caio_disk = caio_find_disk(caio_md, fd);
    if(NULL_PTR == caio_disk || NULL_PTR == CAIO_DISK_BAD_BITMAP(caio_disk))
    {
        return (EC_FALSE);
    }

    return cbad_bitmap_clear(CAIO_DISK_BAD_BITMAP(caio_disk), page_no);
}

UINT32 caio_count_req_num(CAIO_MD *caio_md)
{
    UINT32       cur_req_num;
    CLIST_DATA  *clist_data;

    cur_req_num = 0;

    CLIST_LOOP_NEXT(CAIO_MD_DISK_LIST(caio_md), clist_data)
    {
        CAIO_DISK   *caio_disk;

        caio_disk = CLIST_DATA_DATA(clist_data);

        cur_req_num += CAIO_DISK_CUR_REQ_NUM(caio_disk);
    }

    return (cur_req_num);
}

/*----------------------------------- caio external interface -----------------------------------*/

EC_BOOL caio_file_read(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CAIO_REQ  *caio_req;
    UINT32     timeout_nsec;

    CAIO_ASSERT(NULL_PTR != offset);

    caio_req = caio_req_new();
    if(NULL_PTR == caio_req)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_read: new caio_req failed\n");

        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    if(NULL_PTR != caio_cb)
    {
        if(EC_FALSE == caio_cb_clone(caio_cb, CAIO_REQ_CB(caio_req)))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_read: clone caio_cb to caio_req failed\n");

            caio_req_free(caio_req);
            caio_cb_exec_terminate_handler(caio_cb);
            return (EC_FALSE);
        }
    }

    /*set timeout*/
    if(NULL_PTR != caio_cb && 0 < CAIO_CB_TIMEOUT_NSEC(caio_cb))
    {
        timeout_nsec = CAIO_CB_TIMEOUT_NSEC(caio_cb);
    }
    else
    {
        timeout_nsec = CAIO_TIMEOUT_NSEC_DEFAULT;
    }

    CAIO_REQ_S_MSEC(caio_req)       = c_get_cur_time_msec();

    CAIO_REQ_SEQ_NO(caio_req)       = ++ CAIO_MD_SEQ_NO(caio_md);
    CAIO_REQ_OP(caio_req)           = CAIO_OP_RD;

    CAIO_REQ_CAIO_MD(caio_req)      = caio_md;
    CAIO_REQ_MODEL(caio_req)        = CAIO_MD_MODEL(caio_md);
    CAIO_REQ_FD(caio_req)           = fd;
    CAIO_REQ_M_BUFF(caio_req)       = buff;
    CAIO_REQ_M_CACHE(caio_req)      = NULL_PTR;
    CAIO_REQ_OFFSET(caio_req)       = offset;
    CAIO_REQ_F_S_OFFSET(caio_req)   = (*offset);
    CAIO_REQ_F_E_OFFSET(caio_req)   = (*offset) + rsize;
    CAIO_REQ_U_S_OFFSET(caio_req)   = CAIO_REQ_F_E_OFFSET(caio_req);
    CAIO_REQ_TIMEOUT_NSEC(caio_req) = timeout_nsec;
    CAIO_REQ_NTIME_MS(caio_req)     = c_get_cur_time_msec() + timeout_nsec * 1000;

    if(EC_FALSE == caio_submit_req(caio_md, caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_read: submit req %ld failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req));

        caio_req_free(caio_req);
        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_read: submit req %ld done\n",
                                         CAIO_REQ_SEQ_NO(caio_req));

    return (EC_TRUE);
}

EC_BOOL caio_file_write(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CAIO_REQ  *caio_req;
    UINT32     timeout_nsec;

    CAIO_ASSERT(NULL_PTR != offset);

    caio_req = caio_req_new();
    if(NULL_PTR == caio_req)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_write: new caio_req failed\n");

        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    if(NULL_PTR != caio_cb)
    {
        if(EC_FALSE == caio_cb_clone(caio_cb, CAIO_REQ_CB(caio_req)))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_write: clone caio_cb to caio_req failed\n");

            caio_req_free(caio_req);
            caio_cb_exec_terminate_handler(caio_cb);
            return (EC_FALSE);
        }
    }

    /*set timeout*/
    if(NULL_PTR != caio_cb && 0 < CAIO_CB_TIMEOUT_NSEC(caio_cb))
    {
        timeout_nsec = CAIO_CB_TIMEOUT_NSEC(caio_cb);
    }
    else
    {
        timeout_nsec = CAIO_TIMEOUT_NSEC_DEFAULT;
    }

    CAIO_REQ_S_MSEC(caio_req)       = c_get_cur_time_msec();

    CAIO_REQ_SEQ_NO(caio_req)       = ++ CAIO_MD_SEQ_NO(caio_md);
    CAIO_REQ_OP(caio_req)           = CAIO_OP_WR;

    CAIO_REQ_CAIO_MD(caio_req)      = caio_md;
    CAIO_REQ_MODEL(caio_req)        = CAIO_MD_MODEL(caio_md);
    CAIO_REQ_FD(caio_req)           = fd;
    CAIO_REQ_M_BUFF(caio_req)       = buff;
    CAIO_REQ_M_CACHE(caio_req)      = NULL_PTR;
    CAIO_REQ_OFFSET(caio_req)       = offset;
    CAIO_REQ_F_S_OFFSET(caio_req)   = (*offset);
    CAIO_REQ_F_E_OFFSET(caio_req)   = (*offset) + wsize;
    CAIO_REQ_U_S_OFFSET(caio_req)   = CAIO_REQ_F_E_OFFSET(caio_req);
    CAIO_REQ_TIMEOUT_NSEC(caio_req) = timeout_nsec;
    CAIO_REQ_NTIME_MS(caio_req)     = c_get_cur_time_msec() + timeout_nsec * 1000;

    if(EC_FALSE == caio_submit_req(caio_md, caio_req))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_write: submit req %ld failed\n",
                                             CAIO_REQ_SEQ_NO(caio_req));

        caio_req_free(caio_req);
        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_write: submit req %ld done\n",
                                         CAIO_REQ_SEQ_NO(caio_req));

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

