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

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/aio_abi.h>

#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"
#include "coroutine.h"
#include "task.h"

#include "cepoll.h"
#include "caio.h"


static int g_caio_eventfd = ERR_FD;
static aio_context_t g_caio_ctx = 0;

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

STATIC_CAST void __caio_termination_handler(COROUTINE_COND *coroutine_cond)
{
    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_termination_handler: coroutine_cond %p\n", coroutine_cond);

    if(NULL_PTR != coroutine_cond)
    {
        coroutine_cond_terminate(coroutine_cond, LOC_CAIO_0001);
    }

    return;
}

STATIC_CAST void __caio_completion_handler(COROUTINE_COND *coroutine_cond)
{
    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] __caio_completion_handler: coroutine_cond %p\n", coroutine_cond);

    if(NULL_PTR != coroutine_cond)
    {
        coroutine_cond_release(coroutine_cond, LOC_CAIO_0002);
    }

    return;
}

EC_BOOL caio_event_handler(void *UNUSED(none))
{
    int                 nread;
    int                 nevent;
    uint64_t            nready;
    struct io_event     event[64];
    struct timespec     timeout;

    nread = read(g_caio_eventfd, &nready, sizeof(uint64_t));

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
                                                 g_caio_eventfd);
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

        if(EC_FALSE == __caio_getevents(g_caio_ctx, 1, 64, event, &timeout, &nevent))
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
            COROUTINE_COND *coroutine_cond;

            dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_event_handler: "
                                                 "data: %lx, obj %lx, res %"PRId64", res2 %"PRId64"\n",
                                                 event[ idx ].data, event[ idx ].obj,
                                                 event[ idx ].res , event[ idx ].res2);

            coroutine_cond = (COROUTINE_COND *)(event[ idx ].data);

            /*WARNING: sometimes res2 = 0, but res stores the negative value of errno*/
            if(0 != event[ idx ].res2 || 0 > event[ idx ].res)
            {
                int err;

                err = (int)(-event[ idx ].res);
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_event_handler: "
                                                     "errno = %d, errstr = %s\n",
                                                     err, strerror(err));
                __caio_termination_handler(coroutine_cond);
            }
            else
            {
                __caio_completion_handler(coroutine_cond);
            }
        }
    }

    return (EC_TRUE);
}

EC_BOOL caio_start(const UINT32 max_req_num)
{
    if(ERR_FD == g_caio_eventfd)
    {
        unsigned nr_reqs;

        g_caio_eventfd = syscall(__NR_eventfd2, 0, O_NONBLOCK | O_CLOEXEC);
        if(ERR_FD == g_caio_eventfd)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: get eventfd failed, errno = %d, errstr = %s\n",
                            errno, strerror(errno));
            return (EC_FALSE);
        }

        nr_reqs = (unsigned)max_req_num;

        if(EC_FALSE == __caio_setup(nr_reqs, &g_caio_ctx))
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_start: nr_reqs = %d\n", nr_reqs);

            close(g_caio_eventfd);
            g_caio_eventfd = ERR_FD;
            g_caio_ctx     = 0;
            return (EC_FALSE);
        }

        cepoll_set_event(task_brd_default_get_cepoll(),
                          g_caio_eventfd,
                          CEPOLL_RD_EVENT,
                          (const char *)"caio_event_handler",
                          (CEPOLL_EVENT_HANDLER)caio_event_handler,
                          (void *)NULL_PTR);

        dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_start: nr_reqs = %d\n", nr_reqs);
    }

    return (EC_TRUE);
}

void caio_end()
{
    if(ERR_FD != g_caio_eventfd)
    {
        cepoll_del_event(task_brd_default_get_cepoll(),
                         g_caio_eventfd,
                         CEPOLL_RD_EVENT);
        close(g_caio_eventfd);
        g_caio_eventfd = ERR_FD;
    }

    if(0 != g_caio_ctx)
    {
        __caio_destroy(g_caio_ctx);
        g_caio_ctx = 0;
    }

    return;
}

EC_BOOL caio_file_load(int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    struct iocb         aiocb;
    struct iocb        *piocb[1];
    COROUTINE_COND      coroutine_cond;
    EC_BOOL             ret;

    void               *buff_t;
    size_t              buff_len;
    off_t               offset_t;
    off_t               offset_diff;

    /*buff address and offset value must be aligned to block size!*/
    offset_t    = (off_t)((*offset) & (~CAIO_PAGE_SIZE));
    offset_diff = (off_t)(offset_t - (*offset));
    buff_len    = ((size_t)(offset_diff + rsize));
    buff_len    = VAL_ALIGN(buff_len, CAIO_PAGE_SIZE);

    if(0 != posix_memalign(&buff_t, CAIO_PAGE_SIZE, buff_len))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_load: posix_memalign failed where page %d, len %d\n",
                        CAIO_PAGE_SIZE, buff_len);

        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_load: offset %ld, offset_t %ld, offset_diff %ld, buff_len %d\n",
                        (*offset), offset_t, offset_diff, buff_len);

    coroutine_cond_init(&coroutine_cond, 0, LOC_CAIO_0003);
    coroutine_cond_reserve(&coroutine_cond, 1, LOC_CAIO_0004);

    /*set up aio request*/
    BSET(&aiocb, 0, sizeof(struct iocb));
    aiocb.aio_data          = (uint64_t)((uintptr_t)(&coroutine_cond));
    aiocb.aio_lio_opcode    = IOCB_CMD_PREAD;
    aiocb.aio_fildes        = fd;
    aiocb.aio_buf           = (uint64_t)((uintptr_t)buff_t);
    aiocb.aio_nbytes        = (size_t)buff_len;
    aiocb.aio_offset        = (off_t)offset_t;
    aiocb.aio_flags         = IOCB_FLAG_RESFD;
    aiocb.aio_resfd         = g_caio_eventfd;

    piocb[0] = &aiocb;

    if(EC_FALSE == __caio_submit(g_caio_ctx, 1, piocb))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_load: "
                                             "io submit failed, fd %d, eventfd %d\n",
                                             fd, g_caio_eventfd);

        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0005);
        free(buff_t);

        /*switch to block-mode*/
        return c_file_load(fd, offset, rsize, buff);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_load: "
                                         "io submit done, fd %d, eventfd %d, coroutine_cond %p, buff %p, offset %ld\n",
                                         fd, g_caio_eventfd, (void *)&coroutine_cond, buff_t, offset_t);

    ret = coroutine_cond_wait(&coroutine_cond, LOC_CAIO_0006);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_load: coroutine was cancelled\n");
        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0007);
        free(buff_t);

        return (EC_FALSE);
    }

    if(EC_TIMEOUT == ret)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_load: coroutine was timeout\n");
        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0008);
        free(buff_t);

        return (EC_FALSE);
    }

    if(EC_TERMINATE == ret)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_load: coroutine was terminated\n");
        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0009);

        free(buff_t);

        return (EC_FALSE);
    }

    coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0010);

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_load: '%.*s'\n", (uint32_t)rsize, (char *)(buff_t + offset_diff));
    BCOPY(buff_t + offset_diff, buff, rsize);

    (*offset) += (size_t)rsize;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_load: done\n");

    free(buff_t);

    return (EC_TRUE);
}

EC_BOOL caio_file_flush(int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff)
{
    struct iocb         aiocb;
    struct iocb        *piocb[1];
    COROUTINE_COND      coroutine_cond;
    EC_BOOL             ret;

    void               *buff_t;
    size_t              buff_len;
    off_t               offset_t;
    off_t               offset_diff;

    /*buff address and offset value must be aligned to block size!*/
    offset_t    = (off_t)((*offset) & (~CAIO_PAGE_SIZE));
    offset_diff = (off_t)(offset_t - (*offset));
    buff_len    = ((size_t)(offset_diff + wsize));
    buff_len    = VAL_ALIGN(buff_len, CAIO_PAGE_SIZE);

    if(0 != posix_memalign(&buff_t, CAIO_PAGE_SIZE, buff_len))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_flush: posix_memalign failed where page %d, len %d\n",
                        CAIO_PAGE_SIZE, buff_len);

        return (EC_FALSE);
    }

    BCOPY(buff, buff_t + offset_diff, wsize);

    coroutine_cond_init(&coroutine_cond, 0, LOC_CAIO_0011);
    coroutine_cond_reserve(&coroutine_cond, 1, LOC_CAIO_0012);

    /*set up aio request*/
    BSET(&aiocb, 0, sizeof(struct iocb));
    aiocb.aio_data          = (uint64_t)((uintptr_t)(&coroutine_cond));
    aiocb.aio_lio_opcode    = IOCB_CMD_PWRITE;
    aiocb.aio_fildes        = fd;
    aiocb.aio_buf           = (uint64_t)((uintptr_t)buff_t);
    aiocb.aio_nbytes        = (size_t)buff_len;
    aiocb.aio_offset        = (size_t)offset_t;
    aiocb.aio_flags         = IOCB_FLAG_RESFD;
    aiocb.aio_resfd         = g_caio_eventfd;

    piocb[0] = &aiocb;

    if(EC_FALSE == __caio_submit(g_caio_ctx, 1, piocb))
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_flush: "
                                             "io submit failed, fd %d, eventfd %d\n",
                                             fd, g_caio_eventfd);

        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0013);
        free(buff_t);

        /*switch to block-mode*/
        return c_file_flush(fd, offset, wsize, buff);
    }

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_flush: "
                                         "io submit done, fd %d, eventfd %d, coroutine_cond %p\n",
                                         fd, g_caio_eventfd, (void *)&coroutine_cond);

    ret = coroutine_cond_wait(&coroutine_cond, LOC_CAIO_0014);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_flush: coroutine was cancelled\n");
        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0015);
        free(buff_t);
        return (EC_FALSE);
    }

    if(EC_TIMEOUT == ret)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_flush: coroutine was timeout\n");
        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0016);
        free(buff_t);
        return (EC_FALSE);
    }

    if(EC_TERMINATE == ret)
    {
        dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:caio_file_flush: coroutine was terminated\n");
        coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0017);
        free(buff_t);
        return (EC_FALSE);
    }

    coroutine_cond_clean(&coroutine_cond, LOC_CAIO_0018);
    free(buff_t);

    (*offset) += (size_t)wsize;

    dbg_log(SEC_0093_CAIO, 9)(LOGSTDOUT, "[DEBUG] caio_file_flush: done\n");
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

