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

        safe_free(cdio_md, LOC_CDIO_0002);

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
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        return caio_try_quit(CDIO_MD_CAIO_MD(cdio_md));
    }

    return (EC_TRUE);
}

EC_BOOL cdio_try_restart(CDIO_MD *cdio_md)
{
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
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        caio_process(CDIO_MD_CAIO_MD(cdio_md));
    }

   return;
}


/*for debug*/
EC_BOOL cdio_poll(CDIO_MD *cdio_md)
{
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
    return;
}

/*----------------------------------- cdio external interface -----------------------------------*/

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_read(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        if(((*offset) +     0) < CDIO_MD_S_OFFSET(cdio_md)
        || ((*offset) + rsize) > CDIO_MD_E_OFFSET(cdio_md))
        {
            dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_read: "
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

    dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_read: no caio\n");
    return (EC_FALSE);
}

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_write(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    if(NULL_PTR != CDIO_MD_CAIO_MD(cdio_md))
    {
        if(((*offset) +     0) < CDIO_MD_S_OFFSET(cdio_md)
        || ((*offset) + wsize) > CDIO_MD_E_OFFSET(cdio_md))
        {
            dbg_log(SEC_0211_CDIO, 0)(LOGSTDOUT, "error:cdio_file_write: "
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

#ifdef __cplusplus
}
#endif/*__cplusplus*/

