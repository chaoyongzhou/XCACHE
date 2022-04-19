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

#ifndef _CNBD_H
#define _CNBD_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"
#include "cthread.h"

#include <linux/nbd.h>

/*nbd req magic and rsp magic*/
#define CNBD_REQ_MAGIC_NUM       ((uint32_t)NBD_REQUEST_MAGIC)   /*0x25609513*/
#define CNBD_RSP_MAGIC_NUM       ((uint32_t)NBD_REPLY_MAGIC)     /*0x67446698*/

/*nbd cmd*/
#define CNBD_CMD_READ            ((uint16_t)NBD_CMD_READ)        /*0*/
#define CNBD_CMD_WRITE           ((uint16_t)NBD_CMD_WRITE)       /*1*/
#define CNBD_CMD_DISC            ((uint16_t)NBD_CMD_DISC)        /*2*/
#define CNBD_CMD_FLUSH           ((uint16_t)NBD_CMD_FLUSH)       /*3*/
#define CNBD_CMD_TRIM            ((uint16_t)NBD_CMD_TRIM)        /*4*/

/*ioctl*/
#define CNBD_SET_SOCK            (NBD_SET_SOCK)                  /*_IO( 0xab, 0 */
#define CNBD_SET_BLKSIZE         (NBD_SET_BLKSIZE)               /*_IO( 0xab, 1 */
#define CNBD_SET_SIZE            (NBD_SET_SIZE)                  /*_IO( 0xab, 2 */
#define CNBD_DO_IT               (NBD_DO_IT)                     /*_IO( 0xab, 3 */
#define CNBD_CLEAR_SOCK          (NBD_CLEAR_SOCK)                /*_IO( 0xab, 4 */
#define CNBD_CLEAR_QUE           (NBD_CLEAR_QUE)                 /*_IO( 0xab, 5 */
#define CNBD_PRINT_DEBUG         (NBD_PRINT_DEBUG)               /*_IO( 0xab, 6 */
#define CNBD_SET_SIZE_BLOCKS     (NBD_SET_SIZE_BLOCKS)           /*_IO( 0xab, 7 */
#define CNBD_DISCONNECT          (NBD_DISCONNECT)                /*_IO( 0xab, 8 */
#define CNBD_SET_TIMEOUT         (NBD_SET_TIMEOUT)               /*_IO( 0xab, 9 */
#define CNBD_SET_FLAGS           (NBD_SET_FLAGS)                 /*_IO( 0xab, 10 */

/*nbd flags*/
#define CNBD_FLAG_HAS_FLAGS      ((uint64_t)NBD_FLAG_HAS_FLAGS)          /*(1 << 0)*/    /* Flags are there */
#define CNBD_FLAG_READ_ONLY      ((uint64_t)NBD_FLAG_READ_ONLY)          /*(1 << 1)*/    /* Device is read-only */
#define CNBD_FLAG_SEND_FLUSH     ((uint64_t)NBD_FLAG_SEND_FLUSH)         /*(1 << 2)*/    /* Send FLUSH */
#define CNBD_FLAG_SEND_FUA       ((uint64_t)NBD_FLAG_SEND_FUA)           /*(1 << 3)*/    /* Send FUA (Force Unit Access) */
#define CNBD_FLAG_ROTATIONAL     ((uint64_t)NBD_FLAG_ROTATIONAL)         /*(1 << 4)*/    /* Use elevator algorithm - rotational media */
#define CNBD_FLAG_SEND_TRIM      ((uint64_t)NBD_FLAG_SEND_TRIM)          /*(1 << 5)*/    /* Send TRIM (discard) */
#define CNBD_FLAG_SEND_WZEROS    ((uint64_t)NBD_FLAG_SEND_WRITE_ZEROES)  /*(1 << 6)*/    /* Send NBD_CMD_WRITE_ZEROES */
#define CNBD_FLAG_CAN_MULTIC     ((uint64_t)NBD_FLAG_CAN_MULTI_CONN)     /*(1 << 8)*/    /* multiple connections are okay */

typedef struct
{
    uint32_t            magic;
    uint32_t            type;        /* == READ || == WRITE  */
    union
    {
        uint8_t         handle[8];
        uint64_t        seqno;
    }u;
    uint64_t            offset;
    uint32_t            len;

    uint32_t            header_pos;  /*header recved position*/
    uint32_t            rsvd;

    uint32_t            data_pos;    /*data recved position*/
    uint8_t            *data_zone;
}CNBD_REQ;

#define CNBD_REQ_MAGIC(cnbd_req)              ((cnbd_req)->magic)
#define CNBD_REQ_TYPE(cnbd_req)               ((cnbd_req)->type)
#define CNBD_REQ_HANDLE(cnbd_req)             ((cnbd_req)->u.handle)
#define CNBD_REQ_SEQNO(cnbd_req)              ((cnbd_req)->u.seqno)
#define CNBD_REQ_OFFSET(cnbd_req)             ((cnbd_req)->offset)
#define CNBD_REQ_LEN(cnbd_req)                ((cnbd_req)->len)

#define CNBD_REQ_HEADER_POS(cnbd_req)         ((cnbd_req)->header_pos)

#define CNBD_REQ_DATA_POS(cnbd_req)           ((cnbd_req)->data_pos)
#define CNBD_REQ_DATA_ZONE(cnbd_req)          ((cnbd_req)->data_zone)

#define CNBD_REQ_HEADER_SIZE (        sizeof(uint32_t) /*magic */   \
                                    + sizeof(uint32_t) /*type  */   \
                                    + sizeof(uint64_t) /*handle*/   \
                                    + sizeof(uint64_t) /*offset*/   \
                                    + sizeof(uint32_t) /*len   */   \
                                    )

typedef struct
{
    uint32_t            magic;
    uint32_t            status;        /* 0 = ok, else error          */

    union
    {
        uint8_t         handle[8];    /* handle you got from request */
        uint64_t        seqno;
    }u;

    uint32_t            header_pos;   /*header sent position*/
    uint32_t            rsvd;

    uint32_t            data_pos;     /*data sent position*/
    uint32_t            data_len;
    uint8_t            *data_zone;
}CNBD_RSP;

#define CNBD_RSP_MAGIC(cnbd_rsp)              ((cnbd_rsp)->magic)
#define CNBD_RSP_STATUS(cnbd_rsp)             ((cnbd_rsp)->status)
#define CNBD_RSP_HANDLE(cnbd_rsp)             ((cnbd_rsp)->u.handle)
#define CNBD_RSP_SEQNO(cnbd_rsp)              ((cnbd_rsp)->u.seqno)

#define CNBD_RSP_HEADER_POS(cnbd_rsp)         ((cnbd_rsp)->header_pos)

#define CNBD_RSP_DATA_POS(cnbd_rsp)           ((cnbd_rsp)->data_pos)
#define CNBD_RSP_DATA_LEN(cnbd_rsp)           ((cnbd_rsp)->data_len)
#define CNBD_RSP_DATA_ZONE(cnbd_rsp)          ((cnbd_rsp)->data_zone)

#define CNBD_RSP_HEADER_SIZE (        sizeof(uint32_t) /*magic */   \
                                    + sizeof(uint32_t) /*status*/   \
                                    + sizeof(uint64_t) /*handle*/   \
                                    )

typedef EC_BOOL (*CNBD_REQ_HANDLER)(const UINT32 , const CNBD_REQ *);

typedef struct
{
    uint32_t            type;        /*req type*/
    uint32_t            rsvd;

    const char         *name;        /*req name*/

    CNBD_REQ_HANDLER handler;       /*req handler*/
}CNBD_CB;

#define CNBD_CB_TYPE(cnbd_cb)                 ((cnbd_cb)->type)
#define CNBD_CB_NAME(cnbd_cb)                 ((cnbd_cb)->name)
#define CNBD_CB_HANDLER(cnbd_cb)              ((cnbd_cb)->handler)

typedef struct
{
    /* used counter >= 0 */
    UINT32                      usedcounter;

    int                         c_sockfd;      /*set to kernel and listen it*/
    int                         d_sockfd;      /*listen it in user space, kernel would forward IO request to it*/
    int                         nbd_fd;
    int                         demo_fd;       /*DEBUG ONLY!*/

    CTHREAD_ID                  nbd_thread_id;
    volatile uint32_t           nbd_thread_counter; /*running: > 0, not running: 0*/
    int                         nbd_thread_errno;

    CSTRING                    *nbd_dev_name;
    CSTRING                    *bucket_name;

    uint64_t                    nbd_blk_size;
    uint64_t                    nbd_dev_size;
    uint64_t                    nbd_timeout;
    uint64_t                    nbd_t_flags;   /*transmission flags*/

    CLIST                       nbd_req_list;
    CLIST                       nbd_rsp_list;

    CNBD_REQ                   *nbd_req_ongoing;
    CNBD_RSP                   *nbd_rsp_ongoing;

    EC_BOOL (*bucket_read_handler)(const UINT32, const CNBD_REQ *, CNBD_RSP *);
    EC_BOOL (*bucket_write_handler)(const UINT32, const CNBD_REQ *, CNBD_RSP *);

}CNBD_MD;

#define CNBD_MD_C_SOCKFD(cnbd_md)                 ((cnbd_md)->c_sockfd)
#define CNBD_MD_D_SOCKFD(cnbd_md)                 ((cnbd_md)->d_sockfd)
#define CNBD_MD_NBD_FD(cnbd_md)                   ((cnbd_md)->nbd_fd)

#define CNBD_MD_DEMO_FD(cnbd_md)                  ((cnbd_md)->demo_fd)
#define CNBD_MD_NBD_THREAD_ID(cnbd_md)            ((cnbd_md)->nbd_thread_id)
#define CNBD_MD_NBD_THREAD_COUNTER(cnbd_md)       (&((cnbd_md)->nbd_thread_counter))
#define CNBD_MD_NBD_THREAD_ERRNO(cnbd_md)         ((cnbd_md)->nbd_thread_errno)

#define CNBD_MD_NBD_DEV_NAME(cnbd_md)             ((cnbd_md)->nbd_dev_name)
#define CNBD_MD_NBD_DEV_NAME_STR(cnbd_md)         (cstring_get_str(CNBD_MD_NBD_DEV_NAME(cnbd_md)))

#define CNBD_MD_BUCKET_NAME(cnbd_md)              ((cnbd_md)->bucket_name)
#define CNBD_MD_BUCKET_NAME_STR(cnbd_md)          (cstring_get_str(CNBD_MD_BUCKET_NAME(cnbd_md)))

#define CNBD_MD_NBD_BLK_SIZE(cnbd_md)             ((cnbd_md)->nbd_blk_size)
#define CNBD_MD_NBD_DEV_SIZE(cnbd_md)             ((cnbd_md)->nbd_dev_size)
#define CNBD_MD_NBD_TIMEOUT(cnbd_md)              ((cnbd_md)->nbd_timeout)
#define CNBD_MD_NBD_T_FLAGS(cnbd_md)              ((cnbd_md)->nbd_t_flags)

#define CNBD_MD_NBD_REQ_LIST(cnbd_md)             (&((cnbd_md)->nbd_req_list))
#define CNBD_MD_NBD_RSP_LIST(cnbd_md)             (&((cnbd_md)->nbd_rsp_list))

#define CNBD_MD_NBD_REQ_ONGOING(cnbd_md)          ((cnbd_md)->nbd_req_ongoing)
#define CNBD_MD_NBD_RSP_ONGOING(cnbd_md)          ((cnbd_md)->nbd_rsp_ongoing)

#define CNBD_MD_BUCKET_READ_FUNC(cnbd_md)         ((cnbd_md)->bucket_read_handler)
#define CNBD_MD_BUCKET_WRITE_FUNC(cnbd_md)        ((cnbd_md)->bucket_write_handler)


/**
*   for test only
*
*   to query the status of CNBD Module
*
**/
void cnbd_print_module_status(const UINT32 cnbd_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CNBD module
*
*
**/
UINT32 cnbd_free_module_static_mem(const UINT32 cnbd_md_id);

/**
*
* start CNBD module
*
**/
UINT32 cnbd_start(const CSTRING *nbd_dev_name,
                  const UINT32   nbd_blk_size,
                  const UINT32   nbd_dev_size,
                  const UINT32   nbd_timeout,
                  const CSTRING *bucket_name);

/**
*
* end CNBD module
*
**/
void cnbd_end(const UINT32 cnbd_md_id);

EC_BOOL cnbd_thread_check_running(const UINT32 cnbd_md_id);

EC_BOOL cnbd_thread_set_running(const UINT32 cnbd_md_id);

EC_BOOL cnbd_thread_set_stopped(const UINT32 cnbd_md_id);

EC_BOOL cnbd_thread_check_listen(const UINT32 cnbd_md_id);

EC_BOOL cnbd_bucket_open(const UINT32 cnbd_md_id);

EC_BOOL cnbd_bucket_create(const UINT32 cnbd_md_id);

EC_BOOL cnbd_bucket_close(const UINT32 cnbd_md_id);

EC_BOOL cnbd_bucket_read(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_bucket_write(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_set_bucket_read_handler(const UINT32 cnbd_md_id, EC_BOOL (*bucket_read_handler)(const UINT32, const CNBD_REQ *, CNBD_RSP *));

EC_BOOL cnbd_set_bucket_write_handler(const UINT32 cnbd_md_id, EC_BOOL (*bucket_write_handler)(const UINT32, const CNBD_REQ *, CNBD_RSP *));

CNBD_REQ *cnbd_req_new();

EC_BOOL cnbd_req_init(CNBD_REQ *cnbd_req);

EC_BOOL cnbd_req_clean(CNBD_REQ *cnbd_req);

EC_BOOL cnbd_req_free(CNBD_REQ *cnbd_req);

EC_BOOL cnbd_req_encode(CNBD_REQ *cnbd_req);

EC_BOOL cnbd_req_decode(CNBD_REQ *cnbd_req);

void cnbd_req_print(LOG *log, const CNBD_REQ *cnbd_req);

CNBD_RSP *cnbd_rsp_new();

EC_BOOL cnbd_rsp_init(CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_rsp_clean(CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_rsp_free(CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_rsp_encode(CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_rsp_decode(CNBD_RSP *cnbd_rsp);

void cnbd_rsp_print(LOG *log, const CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_push_req(const UINT32 cnbd_md_id, CNBD_REQ *cnbd_req);

CNBD_REQ *cnbd_pop_req(const UINT32 cnbd_md_id);

EC_BOOL cnbd_push_rsp(const UINT32 cnbd_md_id, CNBD_RSP *cnbd_rsp);

CNBD_RSP *cnbd_pop_rsp(const UINT32 cnbd_md_id);

EC_BOOL cnbd_recv_req(const UINT32 cnbd_md_id, CNBD_REQ *cnbd_req);

EC_BOOL cnbd_send_rsp(const UINT32 cnbd_md_id, CNBD_RSP *cnbd_rsp);

EC_BOOL cnbd_handle_req_read(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req);

EC_BOOL cnbd_handle_req_write(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req);

EC_BOOL cnbd_handle_req_disc(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req);

EC_BOOL cnbd_handle_req_flush(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req);

EC_BOOL cnbd_handle_req_trim(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req);

EC_BOOL cnbd_handle_req(const UINT32 cnbd_md_id, CNBD_REQ *cnbd_req);

EC_BOOL cnbd_handle_reqs(const UINT32 cnbd_md_id);

EC_BOOL cnbd_device_open(const UINT32 cnbd_md_id);

EC_BOOL cnbd_device_close(const UINT32 cnbd_md_id);

EC_BOOL cnbd_device_set(const UINT32 cnbd_md_id);

EC_BOOL cnbd_device_listen(const UINT32 cnbd_md_id);

EC_BOOL cnbd_device_disconnect(const UINT32 cnbd_md_id);

EC_BOOL cnbd_socket_recv(const UINT32 cnbd_md_id);

EC_BOOL cnbd_socket_send(const UINT32 cnbd_md_id);

#endif /*_CNBD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
