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

#ifndef _CXFSNBD_H
#define _CXFSNBD_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"

#include <linux/nbd.h>

#define CXFSNBD_DEMO_FNAME          ((const char *)"/tmp/nbd0.dsk")
#define CXFSNBD_DEV_SIZE            (((uint64_t)128) << 20) /*128MB*/

//#define CXFSNBD_DEMO_DEVNAME        ((const char *)"/dev/nbd0")

#define CXFSNBD_BLK_SIZE            (512)
#define CXFSNBD_TIMEOUT             (30)

/*nbd req magic and rsp magic*/
#define CXFSNBD_REQ_MAGIC_NUM       ((uint32_t)NBD_REQUEST_MAGIC)   /*0x25609513*/
#define CXFSNBD_RSP_MAGIC_NUM       ((uint32_t)NBD_REPLY_MAGIC)     /*0x67446698*/

/*nbd cmd*/
#define CXFSNBD_CMD_READ            ((uint16_t)NBD_CMD_READ)        /*0*/
#define CXFSNBD_CMD_WRITE           ((uint16_t)NBD_CMD_WRITE)       /*1*/
#define CXFSNBD_CMD_DISC            ((uint16_t)NBD_CMD_DISC)        /*2*/
#define CXFSNBD_CMD_FLUSH           ((uint16_t)NBD_CMD_FLUSH)       /*3*/
#define CXFSNBD_CMD_TRIM            ((uint16_t)NBD_CMD_TRIM)        /*4*/

/*ioctl*/
#define CXFSNBD_SET_SOCK            (NBD_SET_SOCK)                  /*_IO( 0xab, 0 */
#define CXFSNBD_SET_BLKSIZE         (NBD_SET_BLKSIZE)               /*_IO( 0xab, 1 */
#define CXFSNBD_SET_SIZE            (NBD_SET_SIZE)                  /*_IO( 0xab, 2 */
#define CXFSNBD_DO_IT               (NBD_DO_IT)                     /*_IO( 0xab, 3 */
#define CXFSNBD_CLEAR_SOCK          (NBD_CLEAR_SOCK)                /*_IO( 0xab, 4 */
#define CXFSNBD_CLEAR_QUE           (NBD_CLEAR_QUE)                 /*_IO( 0xab, 5 */
#define CXFSNBD_PRINT_DEBUG         (NBD_PRINT_DEBUG)               /*_IO( 0xab, 6 */
#define CXFSNBD_SET_SIZE_BLOCKS     (NBD_SET_SIZE_BLOCKS)           /*_IO( 0xab, 7 */
#define CXFSNBD_DISCONNECT          (NBD_DISCONNECT)                /*_IO( 0xab, 8 */
#define CXFSNBD_SET_TIMEOUT         (NBD_SET_TIMEOUT)               /*_IO( 0xab, 9 */
#define CXFSNBD_SET_FLAGS           (NBD_SET_FLAGS)                 /*_IO( 0xab, 10 */

/*nbd flags*/
#define CXFSNBD_FLAG_HAS_FLAGS      ((uint64_t)NBD_FLAG_HAS_FLAGS)          /*(1 << 0)*/    /* Flags are there */
#define CXFSNBD_FLAG_READ_ONLY      ((uint64_t)NBD_FLAG_READ_ONLY)          /*(1 << 1)*/    /* Device is read-only */
#define CXFSNBD_FLAG_SEND_FLUSH     ((uint64_t)NBD_FLAG_SEND_FLUSH)         /*(1 << 2)*/    /* Send FLUSH */
#define CXFSNBD_FLAG_SEND_FUA       ((uint64_t)NBD_FLAG_SEND_FUA)           /*(1 << 3)*/    /* Send FUA (Force Unit Access) */
#define CXFSNBD_FLAG_ROTATIONAL     ((uint64_t)NBD_FLAG_ROTATIONAL)         /*(1 << 4)*/    /* Use elevator algorithm - rotational media */
#define CXFSNBD_FLAG_SEND_TRIM      ((uint64_t)NBD_FLAG_SEND_TRIM)          /*(1 << 5)*/    /* Send TRIM (discard) */
#define CXFSNBD_FLAG_SEND_WZEROS    ((uint64_t)NBD_FLAG_SEND_WRITE_ZEROES)  /*(1 << 6)*/    /* Send NBD_CMD_WRITE_ZEROES */
#define CXFSNBD_FLAG_CAN_MULTIC     ((uint64_t)NBD_FLAG_CAN_MULTI_CONN)     /*(1 << 8)*/    /* multiple connections are okay */

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
}CXFSNBD_REQ;

#define CXFSNBD_REQ_MAGIC(cxfsnbd_req)              ((cxfsnbd_req)->magic)
#define CXFSNBD_REQ_TYPE(cxfsnbd_req)               ((cxfsnbd_req)->type)
#define CXFSNBD_REQ_HANDLE(cxfsnbd_req)             ((cxfsnbd_req)->u.handle)
#define CXFSNBD_REQ_SEQNO(cxfsnbd_req)              ((cxfsnbd_req)->u.seqno)
#define CXFSNBD_REQ_OFFSET(cxfsnbd_req)             ((cxfsnbd_req)->offset)
#define CXFSNBD_REQ_LEN(cxfsnbd_req)                ((cxfsnbd_req)->len)

#define CXFSNBD_REQ_HEADER_POS(cxfsnbd_req)         ((cxfsnbd_req)->header_pos)

#define CXFSNBD_REQ_DATA_POS(cxfsnbd_req)           ((cxfsnbd_req)->data_pos)
#define CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req)          ((cxfsnbd_req)->data_zone)

#define CXFSNBD_REQ_HEADER_SIZE (     sizeof(uint32_t) /*magic */   \
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
}CXFSNBD_RSP;

#define CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)              ((cxfsnbd_rsp)->magic)
#define CXFSNBD_RSP_STATUS(cxfsnbd_rsp)             ((cxfsnbd_rsp)->status)
#define CXFSNBD_RSP_HANDLE(cxfsnbd_rsp)             ((cxfsnbd_rsp)->u.handle)
#define CXFSNBD_RSP_SEQNO(cxfsnbd_rsp)              ((cxfsnbd_rsp)->u.seqno)

#define CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp)         ((cxfsnbd_rsp)->header_pos)

#define CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp)           ((cxfsnbd_rsp)->data_pos)
#define CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp)           ((cxfsnbd_rsp)->data_len)
#define CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp)          ((cxfsnbd_rsp)->data_zone)

#define CXFSNBD_RSP_HEADER_SIZE (     sizeof(uint32_t) /*magic */   \
                                    + sizeof(uint32_t) /*status*/   \
                                    + sizeof(uint64_t) /*handle*/   \
                                    )

typedef EC_BOOL (*CXFSNBD_REQ_HANDLER)(const UINT32 , const CXFSNBD_REQ *);

typedef struct
{
    uint32_t            type;        /*req type*/
    uint32_t            rsvd;

    const char         *name;        /*req name*/

    CXFSNBD_REQ_HANDLER handler;     /*req handler*/
}CXFSNBD_CB;

#define CXFSNBD_CB_TYPE(cxfsnbd_cb)                 ((cxfsnbd_cb)->type)
#define CXFSNBD_CB_NAME(cxfsnbd_cb)                 ((cxfsnbd_cb)->name)
#define CXFSNBD_CB_HANDLER(cxfsnbd_cb)              ((cxfsnbd_cb)->handler)


typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;

    int                  c_sockfd;      /*set to kernel and listen it*/
    int                  d_sockfd;      /*listen it in user space, kernel would forward IO request to it*/
    int                  nbd_fd;
    //int                  rsvd01;
    int                  demo_fd;       /*DEBUG ONLY!*/

    uint64_t             nbd_blk_size;
    uint64_t             nbd_dev_size;
    uint64_t             nbd_timeout;
    uint64_t             nbd_t_flags;   /*transmission flags*/
    CSTRING             *nbd_dev_name;

    CLIST                nbd_req_list;
    CLIST                nbd_rsp_list;

    CXFSNBD_REQ         *nbd_req_ongoing;
    CXFSNBD_RSP         *nbd_rsp_ongoing;
}CXFSNBD_MD;

#define CXFSNBD_MD_C_SOCKFD(cxfsnbd_md)                 ((cxfsnbd_md)->c_sockfd)
#define CXFSNBD_MD_D_SOCKFD(cxfsnbd_md)                 ((cxfsnbd_md)->d_sockfd)
#define CXFSNBD_MD_NBD_FD(cxfsnbd_md)                   ((cxfsnbd_md)->nbd_fd)

#define CXFSNBD_MD_DEMO_FD(cxfsnbd_md)                  ((cxfsnbd_md)->demo_fd)

#define CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md)             ((cxfsnbd_md)->nbd_blk_size)
#define CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md)             ((cxfsnbd_md)->nbd_dev_size)
#define CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)              ((cxfsnbd_md)->nbd_timeout)
#define CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)              ((cxfsnbd_md)->nbd_t_flags)
#define CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md)             ((cxfsnbd_md)->nbd_dev_name)
#define CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md)         (cstring_get_str(CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md)))

#define CXFSNBD_MD_NBD_REQ_LIST(cxfsnbd_md)             (&((cxfsnbd_md)->nbd_req_list))
#define CXFSNBD_MD_NBD_RSP_LIST(cxfsnbd_md)             (&((cxfsnbd_md)->nbd_rsp_list))

#define CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md)          ((cxfsnbd_md)->nbd_req_ongoing)
#define CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md)          ((cxfsnbd_md)->nbd_rsp_ongoing)



/**
*   for test only
*
*   to query the status of CXFSNBD Module
*
**/
void cxfsnbd_print_module_status(const UINT32 cxfsnbd_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CXFSNBD module
*
*
**/
UINT32 cxfsnbd_free_module_static_mem(const UINT32 cxfsnbd_md_id);

/**
*
* start CXFSNBD module
*
**/
UINT32 cxfsnbd_start(const CSTRING *nbd_dev_name);

/**
*
* end CXFSNBD module
*
**/
void cxfsnbd_end(const UINT32 cxfsnbd_md_id);

CXFSNBD_REQ *cxfsnbd_req_new();

EC_BOOL cxfsnbd_req_init(CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_req_clean(CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_req_free(CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_req_encode(CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_req_decode(CXFSNBD_REQ *cxfsnbd_req);

void cxfsnbd_req_print(LOG *log, const CXFSNBD_REQ *cxfsnbd_req);

CXFSNBD_RSP *cxfsnbd_rsp_new();

EC_BOOL cxfsnbd_rsp_init(CXFSNBD_RSP *cxfsnbd_rsp);

EC_BOOL cxfsnbd_rsp_clean(CXFSNBD_RSP *cxfsnbd_rsp);

EC_BOOL cxfsnbd_rsp_free(CXFSNBD_RSP *cxfsnbd_rsp);

EC_BOOL cxfsnbd_rsp_encode(CXFSNBD_RSP *cxfsnbd_rsp);

EC_BOOL cxfsnbd_rsp_decode(CXFSNBD_RSP *cxfsnbd_rsp);

void cxfsnbd_rsp_print(LOG *log, const CXFSNBD_RSP *cxfsnbd_rsp);

EC_BOOL cxfsnbd_push_req(const UINT32 cxfsnbd_md_id, CXFSNBD_REQ *cxfsnbd_req);

CXFSNBD_REQ *cxfsnbd_pop_req(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_push_rsp(const UINT32 cxfsnbd_md_id, CXFSNBD_RSP *cxfsnbd_rsp);

CXFSNBD_RSP *cxfsnbd_pop_rsp(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_recv_req(const UINT32 cxfsnbd_md_id, CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_send_rsp(const UINT32 cxfsnbd_md_id, CXFSNBD_RSP *cxfsnbd_rsp);

EC_BOOL cxfsnbd_handle_req_read(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_handle_req_write(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_handle_req_disc(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_handle_req_flush(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_handle_req_trim(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req);

EC_BOOL cxfsnbd_handle_req(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_device_open(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_device_close(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_device_set(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_device_listen(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_device_disconnect(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_socket_recv(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_socket_send(const UINT32 cxfsnbd_md_id);

#endif /*_CXFSNBD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
