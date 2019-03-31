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

#ifndef _CDIO_H
#define _CDIO_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"

#include "caio.h"

#include "cparacfg.h"

#define CDIO_ERR_OFFSET                                 ((UINT32)~0)

#define CDIO_AIO_REQ_MAX_NUM                            (2)

typedef struct
{
    int                 disk_fd;
    int                 rsvd01;

    UINT32              s_offset;
    UINT32              e_offset;

    UINT32              aio_req_max_num;

    CAIO_MD            *caio_md;
}CDIO_MD;

#define CDIO_MD_DISK_FD(cdio_md)                        ((cdio_md)->disk_fd)
#define CDIO_MD_S_OFFSET(cdio_md)                       ((cdio_md)->s_offset)
#define CDIO_MD_E_OFFSET(cdio_md)                       ((cdio_md)->e_offset)
#define CDIO_MD_AIO_REQ_MAX_NUM(cdio_md)                ((cdio_md)->aio_req_max_num)
#define CDIO_MD_CAIO_MD(cdio_md)                        ((cdio_md)->caio_md)

/**
*
* start CDIO module
*
**/
CDIO_MD *cdio_start(const int disk_fd, const UINT32 disk_offset, const UINT32 disk_size/*in byte*/);

/**
*
* end CDIO module
*
**/
void cdio_end(CDIO_MD *cdio_md);


int cdio_get_eventfd(CDIO_MD *cdio_md);

EC_BOOL cdio_event_handler(CDIO_MD *cdio_md);


/**
*
* try to quit cdio
*
**/
EC_BOOL cdio_try_quit(CDIO_MD *cdio_md);

EC_BOOL cdio_try_restart(CDIO_MD *cdio_md);

EC_BOOL cdio_set_read_only(CDIO_MD *cdio_md);

EC_BOOL cdio_unset_read_only(CDIO_MD *cdio_md);

EC_BOOL cdio_is_read_only(const CDIO_MD *cdio_md);

void cdio_process(CDIO_MD *cdio_md);

/*for debug*/
EC_BOOL cdio_poll(CDIO_MD *cdio_md);

void cdio_print(LOG *log, const CDIO_MD *cdio_md);


/*----------------------------------- cdio external interface -----------------------------------*/

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_read(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_write(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb);

#endif /*_CDIO_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

