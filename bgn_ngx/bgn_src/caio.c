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

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"
#include "coroutine.h"
#include "task.h"

#include "cepoll.h"
#include "caio.h"


CAIO_NODE *caio_node_new()
{
    CAIO_NODE *caio_node;
    alloc_static_mem(MM_CAIO_NODE, &caio_node, LOC_CAIO_0001);
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
    CAIO_NODE_CCOND(caio_node)   = NULL_PTR;
    CAIO_NODE_OP(caio_node)      = CAIO_NODE_ERR_OP;
    
    BSET(CAIO_NODE_AIOCB(caio_node), 0, sizeof(struct iocb));
    
    CAIO_NODE_F_CACHE(caio_node) = NULL_PTR;
    if(0 != posix_memalign((void **)&CAIO_NODE_F_CACHE(caio_node), CAIO_BLOCK_SIZE_NBYTE, CAIO_BLOCK_SIZE_NBYTE))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_node_init: alloc memory failed\n");

        return (EC_FALSE);
    }

    CAIO_NODE_M_CACHE(caio_node)    = NULL_PTR;
    CAIO_NODE_F_S_OFFSET(caio_node) = 0;
    CAIO_NODE_F_E_OFFSET(caio_node) = 0;
    CAIO_NODE_B_S_OFFSET(caio_node) = 0;
    CAIO_NODE_B_E_OFFSET(caio_node) = 0;
    
    CAIO_NODE_NTIME_TS(caio_node)   = 0;
    
    return (EC_TRUE);
}

EC_BOOL caio_node_clean(CAIO_NODE *caio_node)
{
    if(NULL_PTR != caio_node)
    {
        CAIO_NODE_CCOND(caio_node)   = NULL_PTR;
        CAIO_NODE_OP(caio_node)      = CAIO_NODE_ERR_OP;
        
        BSET(CAIO_NODE_AIOCB(caio_node), 0, sizeof(struct iocb));

        if(NULL_PTR != CAIO_NODE_F_CACHE(caio_node))
        {
            free(CAIO_NODE_F_CACHE(caio_node));
            CAIO_NODE_F_CACHE(caio_node) = NULL_PTR;
        }

        CAIO_NODE_M_CACHE(caio_node)    = NULL_PTR;
        CAIO_NODE_F_S_OFFSET(caio_node) = 0;
        CAIO_NODE_F_E_OFFSET(caio_node) = 0;
        CAIO_NODE_B_S_OFFSET(caio_node) = 0;
        CAIO_NODE_B_E_OFFSET(caio_node) = 0;
        
        CAIO_NODE_NTIME_TS(caio_node)   = 0;
    }
    return (EC_TRUE);
}

EC_BOOL caio_node_free(CAIO_NODE *caio_node)
{
    if(NULL_PTR != caio_node)
    {
        caio_node_clean(caio_node);
        free_static_mem(MM_CAIO_NODE, caio_node, LOC_CAIO_0002);
    }
    return (EC_TRUE);
}

void caio_node_print(LOG *log, const CAIO_NODE *caio_node)
{
    sys_log(log, "caio_node_print: caio_node %p: ccond %p, file cache %p, mem cache %p, "
                 "file range [%ld, %ld), block range [%ld, %ld), "
                 "next access time %ld\n", 
                 caio_node, CAIO_NODE_CCOND(caio_node), 
                 CAIO_NODE_F_CACHE(caio_node), CAIO_NODE_M_CACHE(caio_node),
                 CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                 CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node),
                 (UINT32)CAIO_NODE_NTIME_TS(caio_node));
    return;
}

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
                                             "nr_reqs = %d\n",
                                             nr_reqs);
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
        return (EC_TRUE);
    }

    err = errno;

    switch(err)
    {
        case EFAULT:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_destroy: "
                                                 "The context %p pointed to is invalid\n",
                                                 ctx);
            break;
        }
        case EINVAL:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_destroy: "
                                                 "The AIO context specified by ctx %p is invalid\n",
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
                                                 "ctx %p is invalid.  min_nr %ld is out of range or nr %ld is out of range\n",
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

STATIC_CAST EC_BOOL __caio_submit(aio_context_t ctx, long nr, struct iocb **iocbpp)
{
    /*
    *
    * ref: http://www.man7.org/linux/man-pages/man2/io_submit.2.html
    * int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
    *
    */

    int err;

    if(nr == syscall(__NR_io_submit, ctx, nr, iocbpp))
    {
        return (EC_TRUE);
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
                                                 "The AIO context specified by ctx %p is invalid\n",
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
                                                 "One of the data structures points to invalid data\n",
                                                 ctx);
            break;
        }
        case EINVAL:
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_cancel: "
                                                 "The AIO context specified by ctx %p is invalid\n",
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

STATIC_CAST EC_BOOL __caio_cancel_all(aio_context_t ctx, struct iocb **piocb, const UINT32 idx_from, const UINT32 idx_to)
{
    UINT32 idx;

    for(idx = idx_from; idx < idx_to; idx ++)
    {
        struct io_event     event;
        
        __caio_cancel(ctx, piocb[ idx ], &event);    
    }

    return (EC_TRUE);
}

STATIC_CAST void __caio_termination_handler(CAIO_MD *caio_md, CAIO_NODE *caio_node)
{
    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_termination_handler: caio_node %p\n", caio_node);

    if(NULL_PTR != caio_node)
    {
        if(NULL_PTR != CAIO_NODE_CCOND(caio_node))
        {
            coroutine_cond_terminate(CAIO_NODE_CCOND(caio_node), LOC_CAIO_0001);
            CAIO_NODE_CCOND(caio_node) = NULL_PTR;        
        }

        caio_node_free(caio_node);
    }

    return;
}

STATIC_CAST void __caio_completion_handler(CAIO_MD *caio_md, CAIO_NODE *caio_node)
{
    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_completion_handler: caio_node %p\n", caio_node);

    if(NULL_PTR != caio_node)
    {
        if(NULL_PTR != CAIO_NODE_CCOND(caio_node))
        {
            coroutine_cond_release(CAIO_NODE_CCOND(caio_node), LOC_CAIO_0001);
            CAIO_NODE_CCOND(caio_node) = NULL_PTR;
        }

        if(CAIO_NODE_READ_OP == CAIO_NODE_OP(caio_node))
        {
            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_completion_handler: "
                            "fcache %p, mcache %p, "
                            "file [%ld, %ld), block [%ld, %ld)\n", 
                            CAIO_NODE_F_CACHE(caio_node), CAIO_NODE_M_CACHE(caio_node),
                            CAIO_NODE_F_S_OFFSET(caio_node), CAIO_NODE_F_E_OFFSET(caio_node),
                            CAIO_NODE_B_S_OFFSET(caio_node), CAIO_NODE_B_E_OFFSET(caio_node));
                            
            BCOPY(CAIO_NODE_F_CACHE(caio_node) + CAIO_NODE_B_S_OFFSET(caio_node), 
                  CAIO_NODE_M_CACHE(caio_node), 
                  CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node));
        }

        caio_node_free(caio_node);
    }

    return;
}

EC_BOOL caio_event_handler(CAIO_MD *caio_md)
{
    int                 nread;
    int                 nevent;
    uint64_t            nready;
    struct io_event     event[64];
    struct timespec     timeout;

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

    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;

    while(0 < nready)
    {
        int idx;

        if(EC_FALSE == __caio_getevents(CAIO_MD_AIO_CONTEXT(caio_md), 1, 64, event, &timeout, &nevent))
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

        nready -= nevent;

        for(idx = 0; idx < nevent; idx ++)
        {
            CAIO_NODE *caio_node;

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                                 "data: %lx, obj %lx, res %"PRId64", res2 %"PRId64"\n",
                                                 event[ idx ].data, event[ idx ].obj,
                                                 event[ idx ].res , event[ idx ].res2);

            caio_node = (CAIO_NODE *)(event[ idx ].data);

            /*WARNING: sometimes res2 = 0, but res stores the negative value of errno*/
            if(0 != event[ idx ].res2 || 0 > event[ idx ].res)
            {
                int err;

                err = (int)(-event[ idx ].res);
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_event_handler: "
                                                     "errno = %d, errstr = %s\n",
                                                     err, strerror(err));
                __caio_termination_handler(caio_md, caio_node);
            }
            else
            {
                __caio_completion_handler(caio_md, caio_node);
            }
        }
    }

    return (EC_TRUE);
}

CAIO_MD *caio_start()
{
    CAIO_MD      *caio_md;

    /* initialize new one CMC module */
    caio_md = safe_malloc(sizeof(CAIO_MD), LOC_CAIO_0003);
    if(NULL_PTR == caio_md)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: malloc caio module failed\n");
        return (NULL_PTR);
    }
    
    CAIO_MD_AIO_EVENTFD(caio_md) = ERR_FD;
    CAIO_MD_AIO_CONTEXT(caio_md) = 0;

    /*aio eventfd*/
    CAIO_MD_AIO_EVENTFD(caio_md) = syscall(__NR_eventfd2, 0, O_NONBLOCK | O_CLOEXEC);
    if(ERR_FD == CAIO_MD_AIO_EVENTFD(caio_md))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: get eventfd failed, errno = %d, errstr = %s\n",
                        errno, strerror(errno));

        caio_end(caio_md);
        return (NULL_PTR);
    }

    /*aio context*/
    if(EC_FALSE == __caio_setup((unsigned)CAIO_REQ_MAX_NUM, &CAIO_MD_AIO_CONTEXT(caio_md)))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: nr_reqs = %d\n", (unsigned)CAIO_REQ_MAX_NUM);

        caio_end(caio_md);
        return (NULL_PTR);
    }

    csig_atexit_register((CSIG_ATEXIT_HANDLER)caio_end, (UINT32)caio_md);

    /*set RD event*/
    cepoll_set_event(task_brd_default_get_cepoll(),
                      CAIO_MD_AIO_EVENTFD(caio_md),
                      CEPOLL_RD_EVENT,
                      (const char *)"caio_event_handler",
                      (CEPOLL_EVENT_HANDLER)caio_event_handler,
                      (void *)caio_md);

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_start: nr_reqs = %d\n", (unsigned)CAIO_REQ_MAX_NUM);

    return (caio_md);
}

void caio_end(CAIO_MD *caio_md)
{  
    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)caio_end, (UINT32)caio_md);
   
    if(ERR_FD != CAIO_MD_AIO_EVENTFD(caio_md))
    {
        cepoll_del_event(task_brd_default_get_cepoll(),
                         CAIO_MD_AIO_EVENTFD(caio_md),
                         CEPOLL_RD_EVENT);
        close(CAIO_MD_AIO_EVENTFD(caio_md));
        CAIO_MD_AIO_EVENTFD(caio_md) = ERR_FD;
    }

    if(0 != CAIO_MD_AIO_CONTEXT(caio_md))
    {
        __caio_destroy(CAIO_MD_AIO_CONTEXT(caio_md));
        CAIO_MD_AIO_CONTEXT(caio_md) = 0;
    }

    safe_free(caio_md, LOC_CAIO_0004);

    return;
}

STATIC_CAST static EC_BOOL __caio_cleanup_all(struct iocb **piocb, const UINT32 idx_from, const UINT32 idx_to)
{
    UINT32 idx;

    for(idx = idx_from; idx < idx_to; idx ++)
    {
        CAIO_NODE          *caio_node;

        caio_node = CAIO_AIOCB_NODE(piocb[ idx ]);
        piocb[ idx ] = NULL_PTR;
        caio_node_free(caio_node);
    }

    return (EC_TRUE);
}

STATIC_CAST static CAIO_NODE *__caio_file_load_req(CAIO_MD *caio_md, int fd, 
                            const UINT32 f_s_offset, const UINT32 f_e_offset, /*range in file*/
                            const UINT32 b_s_offset, const UINT32 b_e_offset, /*range in block*/
                            UINT8 *m_cache)
{
    CAIO_NODE          *caio_node;
    struct iocb        *aiocb;

    ASSERT(0 == (CAIO_BLOCK_SIZE_MASK & (f_s_offset)));

    /*set up aio request*/
    caio_node = caio_node_new();
    if(NULL_PTR == caio_node)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load_req: "
                                             "new caio_node failed\n");
        return (NULL_PTR);
    }

    aiocb = CAIO_NODE_AIOCB(caio_node);
    aiocb->aio_data          = (uint64_t)((uintptr_t)(caio_node));
    aiocb->aio_lio_opcode    = IOCB_CMD_PREAD;
    aiocb->aio_fildes        = fd;
    aiocb->aio_buf           = (uint64_t)((uintptr_t)CAIO_NODE_F_CACHE(caio_node));
    aiocb->aio_nbytes        = (size_t)(f_e_offset - f_s_offset);
    aiocb->aio_offset        = (off_t )(f_s_offset);
    aiocb->aio_flags         = IOCB_FLAG_RESFD;
    aiocb->aio_resfd         = CAIO_MD_AIO_EVENTFD(caio_md);

    CAIO_NODE_OP(caio_node)         = CAIO_NODE_READ_OP;
    CAIO_NODE_M_CACHE(caio_node)    = m_cache;
    CAIO_NODE_F_S_OFFSET(caio_node) = f_s_offset;
    CAIO_NODE_F_E_OFFSET(caio_node) = f_e_offset;
    CAIO_NODE_B_S_OFFSET(caio_node) = b_s_offset;
    CAIO_NODE_B_E_OFFSET(caio_node) = b_e_offset;
    CAIO_NODE_NTIME_TS(caio_node)   = task_brd_default_get_time() + CAIO_RW_TIMEOUT_NSEC;

    return (caio_node);
}

STATIC_CAST static EC_BOOL __caio_file_load(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    COROUTINE_COND      coroutine_cond;
    
    struct iocb        *piocb[ CAIO_REQ_MAX_NUM ];
    UINT32              req_num;
    UINT32              req_idx;
    
    UINT32              f_s_offset;
    UINT32              f_e_offset;

    UINT8              *m_cache;

    coroutine_cond_init(&coroutine_cond, CAIO_RW_TIMEOUT_NSEC * 1000, LOC_CAIO_0003);

    f_s_offset = (*offset);
    f_e_offset = f_s_offset + rsize;
    m_cache    = buff;

    for(req_num = 0; req_num < CAIO_REQ_MAX_NUM && f_s_offset < f_e_offset; req_num ++)
    {
        UINT32              b_s_offset;
        UINT32              b_e_offset;
    
        CAIO_NODE          *caio_node;
        
        b_s_offset  = f_s_offset & CAIO_BLOCK_SIZE_MASK;
        f_s_offset  = f_s_offset & (~CAIO_BLOCK_SIZE_MASK); /*align to block starting*/
                                             
        b_e_offset  = DMIN(f_s_offset + CAIO_BLOCK_SIZE_NBYTE, f_e_offset) & CAIO_BLOCK_SIZE_MASK;
        if(0 == b_e_offset) /*adjust to next block boundary*/
        {
            b_e_offset = CAIO_BLOCK_SIZE_NBYTE;
        }

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_load: "
                                             "request %ld #, fd %d, eventfd %d, "
                                             "file range [%ld, %ld), "
                                             "block range [%ld, %ld), "
                                             "mcache %p\n",
                                             req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md),
                                             f_s_offset, f_e_offset,
                                             b_s_offset, b_e_offset,
                                             m_cache);
                                             
        caio_node = __caio_file_load_req(caio_md, fd, 
                                         f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE, 
                                         b_s_offset, b_e_offset, m_cache);
        if(NULL_PTR == caio_node)
        {
            break;
        } 

        CAIO_NODE_CCOND(caio_node) = &coroutine_cond; /*mount*/
        piocb[ req_num ] = CAIO_NODE_AIOCB(caio_node);

        m_cache    += b_e_offset - b_s_offset;
        f_s_offset += CAIO_BLOCK_SIZE_NBYTE;/*align to next block starting*/
    }
  
    if(0 == req_num)
    {
        return (EC_FALSE);
    }

    if(f_s_offset > f_e_offset) /*adjust file start offset which would be used by offset calculation*/
    {
        f_s_offset = f_e_offset;
    }

    if(EC_TRUE == __caio_submit(CAIO_MD_AIO_CONTEXT(caio_md), (long)req_num, piocb))
    {   
        EC_BOOL             ret;
        
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_load: "
                                             "io submit %ld requests done, fd %d, eventfd %d\n",
                                             req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));    

        coroutine_cond_reserve(&coroutine_cond, req_num, LOC_CAIO_0004);

        ret = coroutine_cond_wait(&coroutine_cond, LOC_CAIO_0006);

        __COROUTINE_IF_EXCEPTION() {/*exception*/
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load: coroutine was cancelled\n");

            __caio_cancel_all(CAIO_MD_AIO_CONTEXT(caio_md), (struct iocb **)piocb, 0, req_num);
            __caio_cleanup_all((struct iocb **)piocb, 0, req_num);
            coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);

            return (EC_FALSE);
        }

        if(EC_TIMEOUT == ret)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load: coroutine was timeout\n");
            
            __caio_cancel_all(CAIO_MD_AIO_CONTEXT(caio_md), (struct iocb **)piocb, 0, req_num);
            __caio_cleanup_all((struct iocb **)piocb, 0, req_num);
            coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);

            return (EC_FALSE);
        }

        if(EC_TERMINATE == ret)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load: coroutine was terminated\n");
            __caio_cancel_all(CAIO_MD_AIO_CONTEXT(caio_md), (struct iocb **)piocb, 0, req_num);
            __caio_cleanup_all((struct iocb **)piocb, 0, req_num);
            coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);

            return (EC_FALSE);
        }

        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0010);

        (*offset) = f_s_offset;
        return (EC_TRUE);
    }

    coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load: "
                                         "io submit %ld requests failed, fd %d, eventfd %d\n",
                                         req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));

    /*switch to block-mode*/
    for(req_idx = 0; req_idx < req_num; req_idx ++)
    {
        CAIO_NODE          *caio_node;
        UINT32              f_offset;
        UINT32              f_rsize;

        caio_node = CAIO_AIOCB_NODE(piocb[ req_idx ]);

        f_offset  = CAIO_NODE_F_S_OFFSET(caio_node);
        f_rsize   = CAIO_NODE_F_E_OFFSET(caio_node) - CAIO_NODE_F_S_OFFSET(caio_node);

        if(EC_FALSE == c_file_pread(fd, &f_offset, f_rsize, CAIO_NODE_F_CACHE(caio_node)))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load: "
                                                 "pread %ld/%ld request failed, fd %d, eventfd %d\n",
                                                 req_idx, req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));        
            break;
        }

        /*copy data*/
        BCOPY(CAIO_NODE_F_CACHE(caio_node) + CAIO_NODE_B_S_OFFSET(caio_node), 
              CAIO_NODE_M_CACHE(caio_node), 
              CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node));

        (*offset) += CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node);
        
        piocb[ req_idx ] = NULL_PTR;
        caio_node_free(caio_node);
    }

    /*clean up residue*/
    __caio_cleanup_all((struct iocb **)piocb, req_idx, req_num);
    
    /*no pread succ, return false*/
    if(0 == req_idx)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load: "
                                             "pread failed, fd %d, eventfd %d\n",
                                             fd, CAIO_MD_AIO_EVENTFD(caio_md));
        
        return (EC_FALSE);
    }

    /*one or more pread succ, return true*/

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_load: "
                                         "pread succ %ld of %ld requests, fd %d, eventfd %d\n",
                                         req_idx + 1, req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));
    return (EC_TRUE);
}

EC_BOOL caio_file_load(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    UINT32              s_offset;
    UINT32              e_offset;
    UINT8              *m_cache;

    s_offset = (*offset);
    e_offset = s_offset + rsize;
    m_cache  = buff;

    while(s_offset < e_offset)
    {
        UINT32  offset_t;

        offset_t = s_offset; /*save*/
        
        if(EC_FALSE ==__caio_file_load(caio_md, fd, &offset_t, e_offset - s_offset, m_cache))
        {
            break;
        }

        m_cache += (offset_t - s_offset);

        s_offset = offset_t;
    }

    if(s_offset == (*offset))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_load: load failed where offset %ld, rsize %ld\n",
                        (*offset), rsize);
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_load: offset %ld => %ld done\n", 
                    (*offset), s_offset);

    (*offset) = s_offset;
    
    return (EC_TRUE);
}

STATIC_CAST static CAIO_NODE *__caio_file_flush_req(CAIO_MD *caio_md, int fd, 
                            const UINT32 f_s_offset, const UINT32 f_e_offset, /*range in file*/
                            const UINT32 b_s_offset, const UINT32 b_e_offset, /*range in block*/
                            UINT8 *m_cache)
{
    CAIO_NODE          *caio_node;
    struct iocb        *aiocb;

    ASSERT(0 == (CAIO_BLOCK_SIZE_MASK & (f_s_offset)));

    /*set up aio request*/
    caio_node = caio_node_new();
    if(NULL_PTR == caio_node)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush_req: "
                                             "new caio_node failed\n");
        return (NULL_PTR);
    }

    aiocb = CAIO_NODE_AIOCB(caio_node);
    aiocb->aio_data          = (uint64_t)((uintptr_t)(caio_node));
    aiocb->aio_lio_opcode    = IOCB_CMD_PWRITE;
    aiocb->aio_fildes        = fd;
    aiocb->aio_buf           = (uint64_t)((uintptr_t)CAIO_NODE_F_CACHE(caio_node));
    aiocb->aio_nbytes        = (size_t)(f_e_offset - f_s_offset);
    aiocb->aio_offset        = (off_t )(f_s_offset);
    aiocb->aio_flags         = IOCB_FLAG_RESFD;
    aiocb->aio_resfd         = CAIO_MD_AIO_EVENTFD(caio_md);

    CAIO_NODE_OP(caio_node)         = CAIO_NODE_WRITE_OP;
    CAIO_NODE_M_CACHE(caio_node)    = m_cache;
    CAIO_NODE_F_S_OFFSET(caio_node) = f_s_offset;
    CAIO_NODE_F_E_OFFSET(caio_node) = f_e_offset;
    CAIO_NODE_B_S_OFFSET(caio_node) = b_s_offset;
    CAIO_NODE_B_E_OFFSET(caio_node) = b_e_offset;
    CAIO_NODE_NTIME_TS(caio_node)   = task_brd_default_get_time() + CAIO_RW_TIMEOUT_NSEC;

    return (caio_node);
}

STATIC_CAST static EC_BOOL __caio_file_flush(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff)
{
    COROUTINE_COND      coroutine_cond;
    
    struct iocb        *piocb[ CAIO_REQ_MAX_NUM ];
    UINT32              req_num;
    UINT32              req_idx;
    
    UINT32              s_offset;
    UINT32              e_offset;
    UINT32              f_s_offset;
    UINT32              f_e_offset;
    UINT8              *m_buff;

    coroutine_cond_init(&coroutine_cond, CAIO_RW_TIMEOUT_NSEC * 1000, LOC_CAIO_0003);

    s_offset    = (*offset);
    e_offset    = (*offset) + wsize;

    f_s_offset  = (*offset) & (~CAIO_BLOCK_SIZE_MASK); /*align to block starting*/
    f_e_offset  = ((*offset) + wsize) & (~CAIO_BLOCK_SIZE_MASK); /*align to previous block of ending*/

    m_buff      = (UINT8 *)buff;

    req_num     = 0;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [1] "
                    "m_buff %p, req_num %ld, "
                    "raw [%ld, %ld) => file [%ld, %ld)\n",
                    m_buff, req_num,
                    s_offset, e_offset,
                    f_s_offset, f_e_offset);

    if(f_s_offset != s_offset)
    {
        UINT8              *head_block;
        
        UINT32              head_offset;
        UINT32              head_size;

        UINT32              b_s_offset;
        UINT32              b_e_offset;
    
        CAIO_NODE          *caio_node;
        
        head_block = safe_malloc(CAIO_BLOCK_SIZE_NBYTE, LOC_CAIO_0001);
        if(NULL_PTR == head_block)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: malloc head block failed\n");
            return (EC_FALSE);
        }

        head_offset = f_s_offset;
        head_size   = (s_offset & CAIO_BLOCK_SIZE_MASK);

        if(EC_FALSE == caio_file_load(caio_md, fd, &head_offset, head_size, head_block))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: load head block [%ld, %ld) failed\n",
                            f_s_offset, f_s_offset + head_size);

            safe_free(head_block, LOC_CAIO_0001);
            return (EC_FALSE);
        }

        if(head_offset != f_s_offset + head_size)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: load head block [%ld, %ld) but head offset reach %ld only\n",
                            f_s_offset, f_s_offset + head_size, head_offset);

            safe_free(head_block, LOC_CAIO_0001);
            return (EC_FALSE);
        }

        /*--------------------------------------------------------------------*/
        b_s_offset  = (s_offset & CAIO_BLOCK_SIZE_MASK);
        b_e_offset  = DMIN(f_s_offset + CAIO_BLOCK_SIZE_NBYTE, f_e_offset) & CAIO_BLOCK_SIZE_MASK;
        if(0 == b_e_offset) /*adjust to next block boundary*/
        {
            b_e_offset = CAIO_BLOCK_SIZE_NBYTE;
        }

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [2] "
                        "m_buff %p, req_num %ld, "
                        "raw [%ld, %ld), flush file [%ld, %ld), block [%ld, %ld)\n",
                        m_buff, req_num,
                        s_offset, e_offset,
                        f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE,
                        b_s_offset, b_e_offset);
                    
        caio_node = __caio_file_flush_req(caio_md, fd, 
                                          f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE, 
                                          b_s_offset, b_e_offset, NULL_PTR);
        if(NULL_PTR == caio_node)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: "
                                                 "new caio_node failed\n");

            safe_free(head_block, LOC_CAIO_0001);
            return (EC_FALSE);
        }

        CAIO_NODE_CCOND(caio_node) = &coroutine_cond; /*mount*/

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [2.1] "
                        "m_buff %p, req_num %ld, "
                        "copy %ld bytes from head block to f_cache %p\n",
                        m_buff, req_num,
                        head_size, CAIO_NODE_F_CACHE(caio_node));
                        
        BCOPY(head_block, CAIO_NODE_F_CACHE(caio_node), head_size);
        safe_free(head_block, LOC_CAIO_0001);

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [2.1] "
                        "m_buff %p, req_num %ld, "
                        "copy %ld bytes from m_buff to f_cache %p\n",
                        m_buff, req_num,
                        b_e_offset - b_s_offset, CAIO_NODE_F_CACHE(caio_node) + head_size);
                        
        BCOPY(m_buff, CAIO_NODE_F_CACHE(caio_node) + head_size, b_e_offset - b_s_offset);
        f_s_offset += b_e_offset;
        m_buff     += b_e_offset - b_s_offset;

        piocb[ req_num ++ ] = CAIO_NODE_AIOCB(caio_node); /*push*/
    }

    for(; req_num < CAIO_REQ_MAX_NUM && f_s_offset < f_e_offset;)
    {
        CAIO_NODE          *caio_node;

        UINT32              b_s_offset;
        UINT32              b_e_offset;

        b_s_offset = 0;
        b_e_offset = CAIO_BLOCK_SIZE_NBYTE;
        
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [3] "
                        "m_buff %p, req_num %ld, "
                        "raw [%ld, %ld), flush file [%ld, %ld), block [%ld, %ld)\n",
                        m_buff, req_num,
                        s_offset, e_offset,
                        f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE,
                        b_s_offset, b_e_offset);
                        
        caio_node = __caio_file_flush_req(caio_md, fd, 
                                          f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE, 
                                          b_s_offset, b_e_offset, NULL_PTR);
        if(NULL_PTR == caio_node)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: "
                                                 "new caio_node failed\n");

            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }

        CAIO_NODE_CCOND(caio_node) = &coroutine_cond; /*mount*/

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [3.1] "
                        "m_buff %p, req_num %ld, "
                        "copy %ld bytes from m_buff to f_cache %p\n",
                        m_buff, req_num,
                        b_e_offset - b_s_offset, CAIO_NODE_F_CACHE(caio_node) + b_s_offset);
                        
        BCOPY(m_buff, CAIO_NODE_F_CACHE(caio_node) + b_s_offset, b_e_offset - b_s_offset);
        f_s_offset += b_e_offset;
        m_buff     += b_e_offset - b_s_offset;

        piocb[ req_num ++ ] = CAIO_NODE_AIOCB(caio_node); /*push*/    
    }

    /*if s_offset and e_offset in same block, then reuse the previouse caio_node*/
    if((s_offset & (~CAIO_BLOCK_SIZE_MASK)) == (e_offset & (~CAIO_BLOCK_SIZE_MASK)))
    {
        UINT8              *tail_block;
        UINT32              tail_offset;
        UINT32              tail_size; 

        UINT32              b_s_offset;
        UINT32              b_e_offset;
    
        CAIO_NODE          *caio_node;

        ASSERT(0 == req_num || 1 == req_num);
        
        tail_block = safe_malloc(CAIO_BLOCK_SIZE_NBYTE, LOC_CAIO_0001);
        if(NULL_PTR == tail_block)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: malloc tail block failed\n");

            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }

        tail_offset = e_offset;
        tail_size   = CAIO_BLOCK_SIZE_NBYTE - (e_offset & CAIO_BLOCK_SIZE_MASK);  

        if(EC_FALSE == caio_file_load(caio_md, fd, &tail_offset, tail_size, tail_block))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: load tail block [%ld, %ld) failed\n",
                            e_offset, e_offset + tail_size);
            safe_free(tail_block, LOC_CAIO_0001);
            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }

        if(tail_offset != e_offset + tail_size)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: load head block [%ld, %ld) but tail offset reach %ld only\n",
                            e_offset, e_offset + tail_size, tail_offset);

            safe_free(tail_block, LOC_CAIO_0001);
            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }    

        /*--------------------------------------------------------------------*/
        b_s_offset = (s_offset & CAIO_BLOCK_SIZE_MASK);
        b_e_offset = (e_offset & CAIO_BLOCK_SIZE_MASK);

        if(0 == req_num)
        {
            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [4] "
                            "m_buff %p, req_num %ld, "
                            "raw [%ld, %ld), flush file [%ld, %ld), block [%ld, %ld)\n",
                            m_buff, req_num,
                            s_offset, e_offset,
                            f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE,
                            b_s_offset, b_e_offset);
                        
            caio_node = __caio_file_flush_req(caio_md, fd, 
                                              f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE, 
                                              b_s_offset, b_e_offset, NULL_PTR);
            if(NULL_PTR == caio_node)
            {
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: "
                                                     "new caio_node failed\n");

                safe_free(tail_block, LOC_CAIO_0001);
                __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
                return (EC_FALSE);
            }   

            CAIO_NODE_CCOND(caio_node) = &coroutine_cond; /*mount*/

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [4.1] "
                            "m_buff %p, req_num %ld, "
                            "copy %ld bytes from m_buff to f_cache %p\n",
                            m_buff, req_num,
                            b_e_offset - b_s_offset, CAIO_NODE_F_CACHE(caio_node) + b_s_offset);
                        
            BCOPY(m_buff, CAIO_NODE_F_CACHE(caio_node) + b_s_offset, b_e_offset - b_s_offset);
            f_s_offset += b_e_offset;
            m_buff     += b_e_offset - b_s_offset;

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [4.2] "
                            "m_buff %p, req_num %ld, "
                            "copy %ld bytes from tail block to f_cache %p\n",
                            m_buff, req_num,
                            tail_size, CAIO_NODE_F_CACHE(caio_node) + b_e_offset);
                            
            BCOPY(tail_block, CAIO_NODE_F_CACHE(caio_node) + b_e_offset, tail_size);
            //f_s_offset += tail_size;/*xxx*/
            
            safe_free(tail_block, LOC_CAIO_0001); 

            piocb[ req_num ++ ] = CAIO_NODE_AIOCB(caio_node); /*push*/
        }
        else
        {
            caio_node = CAIO_AIOCB_NODE(piocb[ req_num - 1 ]); /*reuse*/

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [4.3] "
                            "m_buff %p, req_num %ld, "
                            "copy %ld bytes from m_buff to f_cache %p\n",
                            m_buff, req_num,
                            b_e_offset - b_s_offset, CAIO_NODE_F_CACHE(caio_node) + b_s_offset);
                            
            BCOPY(m_buff, CAIO_NODE_F_CACHE(caio_node) + b_s_offset, b_e_offset - b_s_offset);
            f_s_offset += b_e_offset;
            m_buff     += b_e_offset - b_s_offset;

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [4.4] "
                            "m_buff %p, req_num %ld, "
                            "copy %ld bytes from tail block to f_cache %p\n",
                            m_buff, req_num,
                            tail_size, CAIO_NODE_F_CACHE(caio_node) + b_e_offset);
                        
            BCOPY(tail_block, CAIO_NODE_F_CACHE(caio_node) + b_e_offset, tail_size);
            //f_s_offset += tail_size;/*xxx*/
            
            safe_free(tail_block, LOC_CAIO_0001);
        }
    }

    else if(f_e_offset < e_offset && req_num < CAIO_REQ_MAX_NUM)
    {
        UINT8              *tail_block;
        UINT32              tail_offset;
        UINT32              tail_size; 

        UINT32              b_s_offset;
        UINT32              b_e_offset;
    
        CAIO_NODE          *caio_node;
        
        tail_block = safe_malloc(CAIO_BLOCK_SIZE_NBYTE, LOC_CAIO_0001);
        if(NULL_PTR == tail_block)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: malloc tail block failed\n");

            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }

        tail_offset = e_offset;
        tail_size   = CAIO_BLOCK_SIZE_NBYTE - (e_offset & CAIO_BLOCK_SIZE_MASK);  

        if(EC_FALSE == caio_file_load(caio_md, fd, &tail_offset, tail_size, tail_block))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: load tail block [%ld, %ld) failed\n",
                            e_offset, e_offset + tail_size);
            safe_free(tail_block, LOC_CAIO_0001);
            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }

        if(tail_offset != e_offset + tail_size)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: load head block [%ld, %ld) but tail offset reach %ld only\n",
                            e_offset, e_offset + tail_size, tail_offset);

            safe_free(tail_block, LOC_CAIO_0001);
            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }    

        /*--------------------------------------------------------------------*/
        b_s_offset = 0;
        b_e_offset = (e_offset & CAIO_BLOCK_SIZE_MASK);

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [5] "
                        "m_buff %p, req_num %ld, "
                        "raw [%ld, %ld), flush file [%ld, %ld), block [%ld, %ld)\n",
                        m_buff, req_num,
                        s_offset, e_offset,
                        f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE,
                        b_s_offset, b_e_offset);
                        
        caio_node = __caio_file_flush_req(caio_md, fd, 
                                          f_s_offset, f_s_offset + CAIO_BLOCK_SIZE_NBYTE, 
                                          b_s_offset, b_e_offset, NULL_PTR);
        if(NULL_PTR == caio_node)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: "
                                                 "new caio_node failed\n");

            safe_free(tail_block, LOC_CAIO_0001);
            __caio_cleanup_all((struct iocb * *)piocb, 0, req_num);
            return (EC_FALSE);
        }

        CAIO_NODE_CCOND(caio_node) = &coroutine_cond; /*mount*/

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [5.1] "
                        "m_buff %p, req_num %ld, "
                        "copy %ld bytes from m_buff to f_cache %p\n",
                        m_buff, req_num,
                        b_e_offset - b_s_offset, CAIO_NODE_F_CACHE(caio_node) + b_s_offset);
                            
        BCOPY(m_buff, CAIO_NODE_F_CACHE(caio_node) + b_s_offset, b_e_offset - b_s_offset);
        f_s_offset += b_e_offset;
        m_buff     += b_e_offset - b_s_offset;

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: [5.2] "
                        "m_buff %p, req_num %ld, "
                        "copy %ld bytes from tail block to f_cache %p\n",
                        m_buff, req_num,
                        tail_size, CAIO_NODE_F_CACHE(caio_node) + b_e_offset);
                            
        BCOPY(tail_block, CAIO_NODE_F_CACHE(caio_node) + b_e_offset, tail_size);
        //f_s_offset += tail_size;/*xxx*/
        
        safe_free(tail_block, LOC_CAIO_0001);
        
        piocb[ req_num ++ ] = CAIO_NODE_AIOCB(caio_node); /*push*/        
    }

    if(0 == req_num)
    {
        return (EC_FALSE);
    }

    if(EC_TRUE == __caio_submit(CAIO_MD_AIO_CONTEXT(caio_md), (long)req_num, piocb))
    {
        EC_BOOL             ret;
        
        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_flush: "
                                             "io submit %ld requests done, fd %d, eventfd %d\n",
                                             req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));    

        coroutine_cond_reserve(&coroutine_cond, req_num, LOC_CAIO_0004);

        ret = coroutine_cond_wait(&coroutine_cond, LOC_CAIO_0006);

        __COROUTINE_IF_EXCEPTION() {/*exception*/
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: coroutine was cancelled\n");

            __caio_cancel_all(CAIO_MD_AIO_CONTEXT(caio_md), (struct iocb **)piocb, 0, req_num);
            __caio_cleanup_all((struct iocb **)piocb, 0, req_num);
            coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);

            return (EC_FALSE);
        }

        if(EC_TIMEOUT == ret)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: coroutine was timeout\n");
            
            __caio_cancel_all(CAIO_MD_AIO_CONTEXT(caio_md), (struct iocb **)piocb, 0, req_num);
            __caio_cleanup_all((struct iocb **)piocb, 0, req_num);
            coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);

            return (EC_FALSE);
        }

        if(EC_TERMINATE == ret)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: coroutine was terminated\n");
            __caio_cancel_all(CAIO_MD_AIO_CONTEXT(caio_md), (struct iocb **)piocb, 0, req_num);
            __caio_cleanup_all((struct iocb **)piocb, 0, req_num);
            coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);

            return (EC_FALSE);
        }

        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0010);

        (*offset) = f_s_offset;
        return (EC_TRUE);
    }   

    coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0010);

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: "
                                         "io submit %ld requests failed, fd %d, eventfd %d\n",
                                         req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));

    /*switch to block-mode*/
    for(req_idx = 0; req_idx < req_num; req_idx ++)
    {
        CAIO_NODE          *caio_node;
        
        UINT32              f_offset;
        UINT32              f_wsize;

        caio_node = CAIO_AIOCB_NODE(piocb[ req_idx ]);

        f_offset  = CAIO_NODE_F_S_OFFSET(caio_node);
        f_wsize   = CAIO_NODE_F_E_OFFSET(caio_node) - CAIO_NODE_F_S_OFFSET(caio_node);

        if(EC_FALSE == c_file_pwrite(fd, &f_offset, f_wsize, CAIO_NODE_F_CACHE(caio_node)))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_flush: "
                                                 "pwrite %ld/%ld request failed, fd %d, eventfd %d\n",
                                                 req_idx, req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));        
            break;
        }

        (*offset) += CAIO_NODE_B_E_OFFSET(caio_node) - CAIO_NODE_B_S_OFFSET(caio_node);
        
        piocb[ req_idx ] = NULL_PTR;
        caio_node_free(caio_node);
    }

    /*clean up residue*/
    __caio_cleanup_all((struct iocb **)piocb, req_idx, req_num);
    
    /*no pread succ, return false*/
    if(0 == req_idx)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:__caio_file_load: "
                                             "pwrite failed of %ld requests, fd %d, eventfd %d\n",
                                             req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));
        
        return (EC_FALSE);
    }

    /*one or more pread succ, return true*/

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_file_load: "
                                         "pwrite %ld of %ld requests succ, fd %d, eventfd %d\n",
                                         req_idx + 1, req_num, fd, CAIO_MD_AIO_EVENTFD(caio_md));

    return (EC_TRUE);
}

EC_BOOL caio_file_flush(CAIO_MD *caio_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff)
{
    UINT32              s_offset;
    UINT32              e_offset;
    const UINT8        *m_cache;

    s_offset = (*offset);
    e_offset = s_offset + wsize;
    m_cache  = buff;

    while(s_offset < e_offset)
    {
        UINT32      offset_t;

        offset_t = s_offset;
        
        if(EC_FALSE ==__caio_file_flush(caio_md, fd, &offset_t, e_offset - s_offset, m_cache))
        {
            break;
        }

        m_cache += (offset_t - s_offset);
        s_offset = offset_t;
    }

    if(s_offset == (*offset))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_flush: flush failed where offset %ld, wsize %ld\n",
                        (*offset), wsize);
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_flush: offset %ld => %ld done\n", 
                    (*offset), s_offset);

    (*offset) = s_offset;
    
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

