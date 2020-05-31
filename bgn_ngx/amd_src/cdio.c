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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>

#include <sys/stat.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cdio.h"

#include "caio.h"

#if (SWITCH_ON == CDIO_ASSERT_SWITCH)
#define CDIO_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDIO_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDIO_ASSERT_SWITCH)
#define CDIO_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDIO_ASSERT_SWITCH)*/

STATIC_CAST const char *__cdio_file_req_op_str(const UINT32 op)
{
    if(CDIO_OP_RD == op)
    {
        return ((const char *)"RD");
    }

    if(CDIO_OP_WR == op)
    {
        return ((const char *)"WR");
    }

    if(CDIO_OP_ERR == op)
    {
        return ((const char *)"ERR");
    }

    return ((const char *)"UNKNOWN");
}

/**
*
* start CDIO module
*
**/
CDIO_MD *cdio_start(const int disk_fd, const UINT32 disk_offset, const UINT32 disk_size/*in byte*/)
{
    CDIO_MD  *cdio_md;

    UINT32   f_s_offset;
    UINT32   f_e_offset;
    UINT32   f_size;

    init_static_mem();

    if(ERR_FD == disk_fd)
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_start: no disk_fd\n");
        return (NULL_PTR);
    }

    f_s_offset  = disk_offset;
    f_e_offset  = f_s_offset + disk_size;

    /*adjust f_e_offset*/
    if(EC_FALSE == c_file_size(disk_fd, &f_size))
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_start: "
                                             "file size of disk_fd %d failed\n",
                                             disk_fd);
        return (NULL_PTR);
    }
    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "[DEBUG] cdio_start: "
                                         "disk_fd %d => disk size %ld\n",
                                         disk_fd, f_size);

    if(f_s_offset >= f_size)
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_start: "
                                             "f_s_offset %ld >= f_size %ld of disk_fd %d\n",
                                             f_s_offset, f_size, disk_fd);
        return (NULL_PTR);
    }

    if(f_e_offset > f_size)
    {
        dbg_log(SEC_0211_CDIO, 9)(LOGSTDOUT, "[DEBUG] cdio_start: "
                                             "f_e_offset: %ld => %ld of disk_fd %d\n",
                                             f_e_offset, f_size, disk_fd);
        f_e_offset = f_size;
    }

    /* create a new module node */
    cdio_md = safe_malloc(sizeof(CDIO_MD), LOC_CDIO_0001);
    if(NULL_PTR == cdio_md)
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_start: "
                                             "start cdio module failed\n");
        return (NULL_PTR);
    }

    /* initialize new one CDIO module */
    CDIO_MD_DISK_FD(cdio_md)              = disk_fd;
    CDIO_MD_S_OFFSET(cdio_md)             = f_s_offset;
    CDIO_MD_E_OFFSET(cdio_md)             = f_e_offset;
    CDIO_MD_AIO_REQ_MAX_NUM(cdio_md)      = CDIO_AIO_REQ_MAX_NUM;
    CDIO_MD_CAIO_MD(cdio_md)              = NULL_PTR;

    clist_init(CDIO_MD_POST_FILE_REQS(cdio_md), MM_CDIO_FILE_REQ, LOC_CDIO_0002);

    CDIO_MD_CAIO_MD(cdio_md) = caio_start((UINT32)CAIO_512B_MODEL);
    if(NULL_PTR == CDIO_MD_CAIO_MD(cdio_md))
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_start: "
                                             "start caio failed\n");
        cdio_end(cdio_md);
        return (NULL_PTR);
    }

    if(0 != disk_size)
    {
        caio_add_disk(CDIO_MD_CAIO_MD(cdio_md), disk_fd, &CDIO_MD_AIO_REQ_MAX_NUM(cdio_md));
    }

    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "[DEBUG] cdio_start: "
                                         "disk fd %d, offset %ld, size %ld\n",
                                         disk_fd, disk_offset, disk_size);

    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "[DEBUG] cdio_start: start cdio done\n");

    return (cdio_md);
}

/**
*
* end CDIO module
*
**/
void cdio_end(CDIO_MD *cdio_md)
{
    if(NULL_PTR != cdio_md)
    {
        CDIO_MD_S_OFFSET(cdio_md)             = CDIO_ERR_OFFSET;
        CDIO_MD_E_OFFSET(cdio_md)             = CDIO_ERR_OFFSET;
        CDIO_MD_AIO_REQ_MAX_NUM(cdio_md)      = 0;

        if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
        {
            caio_end(CDIO_MD_CAIO_MD(cdio_md));
            CDIO_MD_CAIO_MD(cdio_md) = NULL_PTR;
        }

        safe_free(cdio_md, LOC_CDIO_0003);

        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "[DEBUG] cdio_end: stop cdio done\n");
    }

    return;
}

/*note: register eventfd and event handler to epoll READ event*/
int cdio_get_eventfd(CDIO_MD *cdio_md)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_get_eventfd(CDIO_MD_CAIO_MD(cdio_md));
    }
    return (ERR_FD);
}

/*note: register eventfd and event handler to epoll READ event*/
EC_BOOL cdio_event_handler(CDIO_MD *cdio_md)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_event_handler(CDIO_MD_CAIO_MD(cdio_md));
    }
    return (EC_TRUE);
}

/**
*
* try to quit cdio
*
**/
EC_BOOL cdio_try_quit(CDIO_MD *cdio_md)
{
    if(EC_TRUE == cdio_has_post_file_req(cdio_md))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_try_quit(CDIO_MD_CAIO_MD(cdio_md));
    }

    return (EC_TRUE);
}

EC_BOOL cdio_try_restart(CDIO_MD *cdio_md)
{
    if(EC_TRUE == cdio_has_post_file_req(cdio_md))
    {
        return (EC_FALSE);
    }

    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_try_restart(CDIO_MD_CAIO_MD(cdio_md));
    }

    return (EC_TRUE);
}

EC_BOOL cdio_set_read_only(CDIO_MD *cdio_md)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_set_read_only(CDIO_MD_CAIO_MD(cdio_md));
    }

    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "[DEBUG] cdio_set_read_only: "
                                         "set cdio read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdio_unset_read_only(CDIO_MD *cdio_md)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_unset_read_only(CDIO_MD_CAIO_MD(cdio_md));
    }

    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "[DEBUG] cdio_unset_read_only: "
                                         "unset cdio read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdio_is_read_only(const CDIO_MD *cdio_md)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_is_read_only(CDIO_MD_CAIO_MD(cdio_md));
    }

    return (EC_TRUE);
}

void cdio_process(CDIO_MD *cdio_md)
{
    cdio_process_files(cdio_md);

    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        caio_process(CDIO_MD_CAIO_MD(cdio_md));
    }

   return;
}


/*for debug*/
EC_BOOL cdio_poll(CDIO_MD *cdio_md)
{
    cdio_process_files(cdio_md);

    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        caio_poll(CDIO_MD_CAIO_MD(cdio_md));
    }

    return (EC_TRUE);
}

void cdio_print(LOG *log, const CDIO_MD *cdio_md)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        caio_print(log, CDIO_MD_CAIO_MD(cdio_md));
    }

    cdio_show_post_file_reqs(log, cdio_md);

    return;
}

EC_BOOL cdio_has_post_file_req(CDIO_MD *cdio_md)
{
    if(EC_TRUE == clist_is_empty(CDIO_MD_POST_FILE_REQS(cdio_md)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void cdio_show_post_file_reqs(LOG *log, const CDIO_MD *cdio_md)
{
    clist_print(log, CDIO_MD_POST_FILE_REQS(cdio_md), (CLIST_DATA_DATA_PRINT)cdio_file_req_print);
    return;
}

EC_BOOL cdio_is_barried(CDIO_MD *cdio_md)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        CAIO_MD        *caio_md;
        UINT32          aio_req_num;

        caio_md     = CDIO_MD_CAIO_MD(cdio_md);
        aio_req_num = caio_count_req_num(caio_md);

        if(CDIO_MD_AIO_REQ_MAX_NUM(cdio_md) <= aio_req_num)
        {
            return (EC_TRUE); /*barried*/
        }
    }

    return (EC_FALSE);
}

void cdio_process_files(CDIO_MD *cdio_md)
{
    if(EC_FALSE == cdio_is_barried(cdio_md)
    && 0 < clist_size(CDIO_MD_POST_FILE_REQS(cdio_md)))
    {
        cdio_process_post_file_reqs(cdio_md);
    }

    return;
}

void cdio_process_post_file_reqs(CDIO_MD *cdio_md)
{
    CAIO_MD                *caio_md;
    UINT32                  aio_req_num;

    CDIO_FILE_REQ          *cdio_file_req;

    UINT32                  process_file_max_num;

    ASSERT(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md));

    caio_md     = CDIO_MD_CAIO_MD(cdio_md);
    aio_req_num = caio_count_req_num(caio_md);

    process_file_max_num = 0;

    while(CDIO_MD_AIO_REQ_MAX_NUM(cdio_md) > aio_req_num
    && NULL_PTR != (cdio_file_req = clist_pop_front(CDIO_MD_POST_FILE_REQS(cdio_md))))
    {
        if(CDIO_OP_RD == CDIO_FILE_REQ_OP(cdio_file_req))
        {
            cdio_file_read_do(cdio_md,
                              CDIO_FILE_REQ_OFFSET(cdio_file_req),
                              CDIO_FILE_REQ_RWSIZE(cdio_file_req),
                              CDIO_FILE_REQ_BUFF(cdio_file_req),
                              CDIO_FILE_REQ_CAIO_CB(cdio_file_req));

            aio_req_num ++;

            process_file_max_num ++;

            cdio_file_req_free(cdio_file_req);

            continue;
        }

        if(CDIO_OP_WR == CDIO_FILE_REQ_OP(cdio_file_req))
        {
            cdio_file_write_do(cdio_md,
                               CDIO_FILE_REQ_OFFSET(cdio_file_req),
                               CDIO_FILE_REQ_RWSIZE(cdio_file_req),
                               CDIO_FILE_REQ_BUFF(cdio_file_req),
                               CDIO_FILE_REQ_CAIO_CB(cdio_file_req));

            aio_req_num ++;

            process_file_max_num ++;

            cdio_file_req_free(cdio_file_req);

            continue;
        }

        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_process_post_file_reqs: "
                                             "invalid file req op %ld\n",
                                             CDIO_FILE_REQ_OP(cdio_file_req));

        cdio_file_req_free(cdio_file_req);
    }

    if(0 < process_file_max_num)
    {
        dbg_log(SEC_0211_CDIO, 5)(LOGSTDOUT, "[DEBUG] cdio_process_post_file_reqs: "
                                             "process %ld file reqs, left %ld file reqs\n",
                                             process_file_max_num,
                                             clist_size(CDIO_MD_POST_FILE_REQS(cdio_md)));
    }
    return;
}

/*----------------------------------- cdio file req interface -----------------------------------*/

CDIO_FILE_REQ *cdio_file_req_new()
{
    CDIO_FILE_REQ *cdio_file_req;

    alloc_static_mem(MM_CDIO_FILE_REQ, &cdio_file_req, LOC_CDIO_0004);
    if(NULL_PTR == cdio_file_req)
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_req_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    cdio_file_req_init(cdio_file_req);
    return (cdio_file_req);
}

EC_BOOL cdio_file_req_init(CDIO_FILE_REQ *cdio_file_req)
{
    CDIO_FILE_REQ_OP(cdio_file_req)                 = CDIO_OP_ERR;

    CDIO_FILE_REQ_OFFSET(cdio_file_req)             = NULL_PTR;
    CDIO_FILE_REQ_RWSIZE(cdio_file_req)             = 0;
    CDIO_FILE_REQ_BUFF(cdio_file_req)               = NULL_PTR;

    caio_cb_init(CDIO_FILE_REQ_CAIO_CB(cdio_file_req));

    return (EC_TRUE);
}

EC_BOOL cdio_file_req_clean(CDIO_FILE_REQ *cdio_file_req)
{
    if(NULL_PTR != cdio_file_req)
    {
        CDIO_FILE_REQ_OP(cdio_file_req)                 = CDIO_OP_ERR;

        CDIO_FILE_REQ_OFFSET(cdio_file_req)             = NULL_PTR;
        CDIO_FILE_REQ_RWSIZE(cdio_file_req)             = 0;
        CDIO_FILE_REQ_BUFF(cdio_file_req)               = NULL_PTR;

        caio_cb_clean(CDIO_FILE_REQ_CAIO_CB(cdio_file_req));
    }

    return (EC_TRUE);
}

EC_BOOL cdio_file_req_free(CDIO_FILE_REQ *cdio_file_req)
{
    if(NULL_PTR != cdio_file_req)
    {
        cdio_file_req_clean(cdio_file_req);
        free_static_mem(MM_CDIO_FILE_REQ, cdio_file_req, LOC_CDIO_0005);
    }
    return (EC_TRUE);
}

void cdio_file_req_print(LOG *log, const CDIO_FILE_REQ *cdio_file_req)
{
    sys_log(log, "cdio_file_req_print: cdio_file_req %p: op %s, offset %p, rwsize %ld, buff %p, "
                 "timeout %ld seconds\n",
                 cdio_file_req,
                 __cdio_file_req_op_str(CDIO_FILE_REQ_OP(cdio_file_req)),
                 CDIO_FILE_REQ_OFFSET(cdio_file_req),
                 CDIO_FILE_REQ_RWSIZE(cdio_file_req),
                 CDIO_FILE_REQ_BUFF(cdio_file_req),
                 CAIO_CB_TIMEOUT_NSEC(CDIO_FILE_REQ_CAIO_CB(cdio_file_req)));

    return;
}

/*----------------------------------- cdio external interface -----------------------------------*/

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_read_do(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        if(((*offset) +     0) < CDIO_MD_S_OFFSET(cdio_md)
        || ((*offset) + rsize) > CDIO_MD_E_OFFSET(cdio_md))
        {
            dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_read_do: "
                                                 "access [%ld, %ld) out of disk range [%ld, %ld)\n",
                                                 ((*offset) +     0),
                                                 ((*offset) +     rsize),
                                                 CDIO_MD_S_OFFSET(cdio_md),
                                                 CDIO_MD_E_OFFSET(cdio_md));
            return (EC_FALSE);
        }

        return caio_file_read(CDIO_MD_CAIO_MD(cdio_md),
                              CDIO_MD_DISK_FD(cdio_md),
                              offset,
                              rsize,
                              buff,
                              caio_cb);
    }

    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_read_do: no caio\n");
    return (EC_FALSE);
}

EC_BOOL cdio_file_read(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CDIO_FILE_REQ  *cdio_file_req;

    cdio_file_req = cdio_file_req_new();
    if(NULL_PTR == cdio_file_req)
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_read_aio: new cdio_file_req failed\n");

        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    CDIO_FILE_REQ_OP(cdio_file_req)                 = CDIO_OP_RD;

    CDIO_FILE_REQ_OFFSET(cdio_file_req)             = offset;
    CDIO_FILE_REQ_RWSIZE(cdio_file_req)             = rsize;
    CDIO_FILE_REQ_BUFF(cdio_file_req)               = buff;

    caio_cb_clone(caio_cb, CDIO_FILE_REQ_CAIO_CB(cdio_file_req));

    clist_push_back(CDIO_MD_POST_FILE_REQS(cdio_md), (void *)cdio_file_req);

    return (EC_TRUE);
}

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_write_do(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        if(((*offset) +     0) < CDIO_MD_S_OFFSET(cdio_md)
        || ((*offset) + wsize) > CDIO_MD_E_OFFSET(cdio_md))
        {
            dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_write_do: "
                                                 "access [%ld, %ld) out of disk range [%ld, %ld)\n",
                                                 ((*offset) +     0),
                                                 ((*offset) +     wsize),
                                                 CDIO_MD_S_OFFSET(cdio_md),
                                                 CDIO_MD_E_OFFSET(cdio_md));
            return (EC_FALSE);
        }

        return caio_file_write(CDIO_MD_CAIO_MD(cdio_md),
                               CDIO_MD_DISK_FD(cdio_md),
                               offset,
                               wsize,
                               buff,
                               caio_cb);
    }

    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_read: no caio\n");
    return (EC_FALSE);
}

EC_BOOL cdio_file_write(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CDIO_FILE_REQ  *cdio_file_req;

    cdio_file_req = cdio_file_req_new();
    if(NULL_PTR == cdio_file_req)
    {
        dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_write_aio: new cdio_file_req failed\n");

        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    CDIO_FILE_REQ_OP(cdio_file_req)                 = CDIO_OP_WR;

    CDIO_FILE_REQ_OFFSET(cdio_file_req)             = offset;
    CDIO_FILE_REQ_RWSIZE(cdio_file_req)             = rsize;
    CDIO_FILE_REQ_BUFF(cdio_file_req)               = buff;

    caio_cb_clone(caio_cb, CDIO_FILE_REQ_CAIO_CB(cdio_file_req));

    clist_push_back(CDIO_MD_POST_FILE_REQS(cdio_md), (void *)cdio_file_req);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

