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

#define CDIO_OP_ERR                                     ((UINT32)0x0000) /*bitmap: 00*/
#define CDIO_OP_RD                                      ((UINT32)0x0001) /*bitmap: 01*/
#define CDIO_OP_WR                                      ((UINT32)0x0002) /*bitmap: 10*/

typedef struct
{
    int                 disk_fd;
    int                 rsvd01;

    UINT32              s_offset;
    UINT32              e_offset;

    UINT32              aio_req_max_num;

    CLIST               post_file_reqs;    /*item is CDIO_FILE_REQ*/

    CAIO_MD            *caio_md;
}CDIO_MD;

#define CDIO_MD_DISK_FD(cdio_md)                        ((cdio_md)->disk_fd)
#define CDIO_MD_S_OFFSET(cdio_md)                       ((cdio_md)->s_offset)
#define CDIO_MD_E_OFFSET(cdio_md)                       ((cdio_md)->e_offset)
#define CDIO_MD_AIO_REQ_MAX_NUM(cdio_md)                ((cdio_md)->aio_req_max_num)
#define CDIO_MD_POST_FILE_REQS(cdio_md)                 (&((cdio_md)->post_file_reqs))
#define CDIO_MD_CAIO_MD(cdio_md)                        ((cdio_md)->caio_md)

typedef struct
{
    UINT32              file_op;        /*CDIO_OP_xx*/

    UINT32             *offset;         /*mounted of application*/
    UINT32              rwsize;
    UINT8              *buff;           /*mounted of application*/

    CAIO_CB             caio_cb;
}CDIO_FILE_REQ;

#define CDIO_FILE_REQ_OP(cdio_file_req)             ((cdio_file_req)->file_op)
#define CDIO_FILE_REQ_OFFSET(cdio_file_req)         ((cdio_file_req)->offset)
#define CDIO_FILE_REQ_RWSIZE(cdio_file_req)         ((cdio_file_req)->rwsize)
#define CDIO_FILE_REQ_BUFF(cdio_file_req)           ((cdio_file_req)->buff)
#define CDIO_FILE_REQ_CAIO_CB(cdio_file_req)        (&((cdio_file_req)->caio_cb))

/**
*
* start CDIO module
*
**/
CDIO_MD *cdio_start(const int disk_fd, const char *disk_tag, const UINT32 disk_offset, const UINT32 disk_size/*in byte*/);

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

EC_BOOL cdio_has_post_file_req(CDIO_MD *cdio_md);

void cdio_show_post_file_reqs(LOG *log, const CDIO_MD *cdio_md);

EC_BOOL cdio_is_barried(CDIO_MD *cdio_md);

void cdio_process_files(CDIO_MD *cdio_md);

void cdio_process_post_file_reqs(CDIO_MD *cdio_md);

/*----------------------------------- cdio file req interface -----------------------------------*/

CDIO_FILE_REQ *cdio_file_req_new();

EC_BOOL cdio_file_req_init(CDIO_FILE_REQ *cdio_file_req);

EC_BOOL cdio_file_req_clean(CDIO_FILE_REQ *cdio_file_req);

EC_BOOL cdio_file_req_free(CDIO_FILE_REQ *cdio_file_req);

void cdio_file_req_print(LOG *log, const CDIO_FILE_REQ *cdio_file_req);

/*----------------------------------- cdio external interface -----------------------------------*/

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_read_do(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);
EC_BOOL cdio_file_read(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb);

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdio_file_write_do(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb);
EC_BOOL cdio_file_write(CDIO_MD *cdio_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb);

#endif /*_CDIO_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

