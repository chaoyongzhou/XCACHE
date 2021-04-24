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

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cbc.h"
#include "cmisc.h"
#include "task.h"

#include "cepoll.h"

#include "cnbd.h"

#include "findex.inc"

/*nbd: network block device*/

#define CNBD_MD_CAPACITY()                  (cbc_md_capacity(MD_CNBD))

#define CNBD_MD_GET(cnbd_md_id)     ((CNBD_MD *)cbc_md_get(MD_CNBD, (cnbd_md_id)))

#define CNBD_MD_ID_CHECK_INVALID(cnbd_md_id)  \
    ((CMPI_ANY_MODI != (cnbd_md_id)) && ((NULL_PTR == CNBD_MD_GET(cnbd_md_id)) || (0 == (CNBD_MD_GET(cnbd_md_id)->usedcounter))))

static const CNBD_CB g_cnbd_cb_list[] = {
    {CNBD_CMD_READ , 0, "NBD_CMD_READ" , cnbd_handle_req_read},
    {CNBD_CMD_WRITE, 0, "NBD_CMD_WRITE", cnbd_handle_req_write},
    {CNBD_CMD_DISC , 0, "NBD_CMD_DISC" , cnbd_handle_req_disc},
    {CNBD_CMD_FLUSH, 0, "NBD_CMD_FLUSH", cnbd_handle_req_flush},
    {CNBD_CMD_TRIM , 0, "NBD_CMD_TRIM" , cnbd_handle_req_trim},
};


/**
*   for test only
*
*   to query the status of CNBD Module
*
**/
void cnbd_print_module_status(const UINT32 cnbd_md_id, LOG *log)
{
    CNBD_MD *cnbd_md;
    UINT32 this_cnbd_md_id;

    for( this_cnbd_md_id = 0; this_cnbd_md_id < CNBD_MD_CAPACITY(); this_cnbd_md_id ++ )
    {
        cnbd_md = CNBD_MD_GET(this_cnbd_md_id);

        if ( NULL_PTR != cnbd_md && 0 < cnbd_md->usedcounter )
        {
            sys_log(log,"CNBD Module # %ld : %ld refered\n",
                    this_cnbd_md_id,
                    cnbd_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CNBD module
*
*
**/
UINT32 cnbd_free_module_static_mem(const UINT32 cnbd_md_id)
{
#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_free_module_static_mem: cxfs module #%ld not started.\n",
                cnbd_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    free_module_static_mem(MD_CNBD, cnbd_md_id);

    return 0;
}

/**
*
* start CNBD module
*
**/
UINT32 cnbd_start(const CSTRING *nbd_dev_name,
                        const CSTRING *bucket_name,
                        const UINT32   nbd_blk_size,
                        const UINT32   nbd_dev_size,
                        const UINT32   nbd_timeout)
{
    CNBD_MD     *cnbd_md;
    UINT32       cnbd_md_id;
    int          sockfd[2]; /*socket pair*/

    cbc_md_reg(MD_CNBD, 16);

    cnbd_md_id = cbc_md_new(MD_CNBD, sizeof(CNBD_MD));
    if(CMPI_ERROR_MODI == cnbd_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CNBD module */
    cnbd_md = (CNBD_MD *)cbc_md_get(MD_CNBD, cnbd_md_id);
    cnbd_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CNBD_MD_C_SOCKFD(cnbd_md)     = ERR_FD;
    CNBD_MD_D_SOCKFD(cnbd_md)     = ERR_FD;
    CNBD_MD_NBD_FD(cnbd_md)       = ERR_FD;

    CNBD_MD_DEMO_FD(cnbd_md)      = ERR_FD;

    CNBD_MD_NBD_BLK_SIZE(cnbd_md) = 0;
    CNBD_MD_NBD_DEV_SIZE(cnbd_md) = 0;
    CNBD_MD_NBD_TIMEOUT(cnbd_md)  = 0;
    CNBD_MD_NBD_T_FLAGS(cnbd_md)  = 0;/*xxx*/
    CNBD_MD_NBD_DEV_NAME(cnbd_md) = NULL_PTR;
    CNBD_MD_BUCKET_NAME(cnbd_md)  = NULL_PTR;

    clist_init(CNBD_MD_NBD_REQ_LIST(cnbd_md), MM_CNBD_REQ, LOC_CNBD_0001);
    clist_init(CNBD_MD_NBD_RSP_LIST(cnbd_md), MM_CNBD_RSP, LOC_CNBD_0002);

    CNBD_MD_NBD_REQ_ONGOING(cnbd_md) = NULL_PTR;
    CNBD_MD_NBD_RSP_ONGOING(cnbd_md) = NULL_PTR;

    CNBD_MD_BUCKET_OPEN_FUNC(cnbd_md)     = NULL_PTR;
    CNBD_MD_BUCKET_CLOSE_FUNC(cnbd_md)    = NULL_PTR;
    CNBD_MD_BUCKET_TRUNCATE_FUNC(cnbd_md) = NULL_PTR;

    CNBD_MD_BUCKET_READ_FUNC(cnbd_md)     = NULL_PTR;
    CNBD_MD_BUCKET_WRITE_FUNC(cnbd_md)    = NULL_PTR;

    cnbd_md->usedcounter = 1;

    if(NULL_PTR == nbd_dev_name)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_start:"
                                             "nbd_dev_name is null\n");

        cnbd_end(cnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CNBD_MD_NBD_DEV_NAME(cnbd_md) = cstring_dup(nbd_dev_name);
    if(NULL_PTR == CNBD_MD_NBD_DEV_NAME(cnbd_md))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_start:"
                                             "new nbd_dev_name '%s' failed\n",
                                             (char *)cstring_get_str(nbd_dev_name));

        cnbd_end(cnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(NULL_PTR == bucket_name)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_start:"
                                             "bucket_name is null\n");

        cnbd_end(cnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CNBD_MD_BUCKET_NAME(cnbd_md) = cstring_dup(bucket_name);
    if(NULL_PTR == CNBD_MD_BUCKET_NAME(cnbd_md))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_start:"
                                             "new bucket_name '%s' failed\n",
                                             (char *)cstring_get_str(bucket_name));

        cnbd_end(cnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CNBD_MD_NBD_BLK_SIZE(cnbd_md) = (uint64_t)nbd_blk_size;
    CNBD_MD_NBD_DEV_SIZE(cnbd_md) = (uint64_t)nbd_dev_size;
    CNBD_MD_NBD_TIMEOUT(cnbd_md)  = (uint64_t)nbd_timeout;

    if(0 > socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_start:"
                                             "create unix socket pair failed\n");

        cnbd_end(cnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CNBD_MD_C_SOCKFD(cnbd_md) = sockfd[0];
    CNBD_MD_D_SOCKFD(cnbd_md) = sockfd[1];

    c_socket_nonblock_enable(CNBD_MD_C_SOCKFD(cnbd_md));
    c_socket_nonblock_enable(CNBD_MD_D_SOCKFD(cnbd_md));

    cepoll_set_event(task_brd_default_get_cepoll(),
                      CNBD_MD_D_SOCKFD(cnbd_md),
                      CEPOLL_RD_EVENT,
                      (const char *)"cnbd_socket_recv",
                      (CEPOLL_EVENT_HANDLER)cnbd_socket_recv,
                      (void *)cnbd_md_id);

    cepoll_set_event(task_brd_default_get_cepoll(),
                      CNBD_MD_D_SOCKFD(cnbd_md),
                      CEPOLL_WR_EVENT,
                      (const char *)"cnbd_socket_send",
                      (CEPOLL_EVENT_HANDLER)cnbd_socket_send,
                      (void *)cnbd_md_id);

    if(EC_FALSE == cnbd_device_open(cnbd_md_id))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_start:"
                                             "open device failed\n");

        cnbd_end(cnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == cnbd_device_set(cnbd_md_id))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_start:"
                                             "set device failed\n");

        cnbd_end(cnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    /*cnbd_device_listen(cnbd_md_id);*/
    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_start: "
                                         "CNBD module #%ld, launch device listen\n",
                                         cnbd_md_id);
    cthread_new(CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                 (const char *)"cnbd_device_listen",
                 (UINT32)cnbd_device_listen,
                 (UINT32)0,/*core # (ignore)*/
                 (UINT32)1,/*para num*/
                 cnbd_md_id
                 );

    /*cnbd_device_close(cnbd_md_id);*/

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cnbd_end, cnbd_md_id);

    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_start: "
                                         "start CNBD module #%ld\n",
                                         cnbd_md_id);

    return ( cnbd_md_id );
}

/**
*
* end CNBD module
*
**/
void cnbd_end(const UINT32 cnbd_md_id)
{
    CNBD_MD *cnbd_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cnbd_end, cnbd_md_id);

    cnbd_md = CNBD_MD_GET(cnbd_md_id);
    if(NULL_PTR == cnbd_md)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_end: "
                                             "cnbd_md_id = %ld not exist.\n",
                                             cnbd_md_id);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cnbd_md->usedcounter )
    {
        cnbd_md->usedcounter --;
        return ;
    }

    if ( 0 == cnbd_md->usedcounter )
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_end: "
                                             "cnbd_md_id = %ld is not started.\n",
                                             cnbd_md_id);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }

    clist_clean(CNBD_MD_NBD_REQ_LIST(cnbd_md), (CLIST_DATA_DATA_CLEANER)cnbd_req_free);
    clist_clean(CNBD_MD_NBD_RSP_LIST(cnbd_md), (CLIST_DATA_DATA_CLEANER)cnbd_rsp_free);

    if(NULL_PTR != CNBD_MD_NBD_REQ_ONGOING(cnbd_md))
    {
        cnbd_req_free(CNBD_MD_NBD_REQ_ONGOING(cnbd_md));
        CNBD_MD_NBD_REQ_ONGOING(cnbd_md) = NULL_PTR;
    }

    if(NULL_PTR != CNBD_MD_NBD_RSP_ONGOING(cnbd_md))
    {
        cnbd_rsp_free(CNBD_MD_NBD_RSP_ONGOING(cnbd_md));
        CNBD_MD_NBD_RSP_ONGOING(cnbd_md) = NULL_PTR;
    }

    if(ERR_FD != CNBD_MD_C_SOCKFD(cnbd_md))
    {
        cnbd_device_disconnect(cnbd_md_id);

        close(CNBD_MD_C_SOCKFD(cnbd_md));
        CNBD_MD_C_SOCKFD(cnbd_md) = ERR_FD;
    }

    if(ERR_FD != CNBD_MD_D_SOCKFD(cnbd_md))
    {
        cepoll_del_event(task_brd_default_get_cepoll(),
                         CNBD_MD_D_SOCKFD(cnbd_md),
                         CEPOLL_RD_EVENT);

        cepoll_del_event(task_brd_default_get_cepoll(),
                         CNBD_MD_D_SOCKFD(cnbd_md),
                         CEPOLL_WR_EVENT);

        close(CNBD_MD_D_SOCKFD(cnbd_md));
        CNBD_MD_D_SOCKFD(cnbd_md) = ERR_FD;
    }

    if(ERR_FD != CNBD_MD_NBD_FD(cnbd_md))
    {
        cnbd_device_close(cnbd_md_id);
    }

    if(NULL_PTR != CNBD_MD_NBD_DEV_NAME(cnbd_md))
    {
        cstring_free(CNBD_MD_NBD_DEV_NAME(cnbd_md));
        CNBD_MD_NBD_DEV_NAME(cnbd_md) = NULL_PTR;
    }

    if(NULL_PTR != CNBD_MD_BUCKET_NAME(cnbd_md))
    {
        cstring_free(CNBD_MD_BUCKET_NAME(cnbd_md));
        CNBD_MD_BUCKET_NAME(cnbd_md) = NULL_PTR;
    }

    if(ERR_FD != CNBD_MD_DEMO_FD(cnbd_md))
    {
        c_file_close(CNBD_MD_DEMO_FD(cnbd_md));
        CNBD_MD_DEMO_FD(cnbd_md) = ERR_FD;
    }

    CNBD_MD_NBD_BLK_SIZE(cnbd_md) = 0;
    CNBD_MD_NBD_DEV_SIZE(cnbd_md) = 0;
    CNBD_MD_NBD_TIMEOUT(cnbd_md)  = 0;
    CNBD_MD_NBD_T_FLAGS(cnbd_md)  = 0;

    CNBD_MD_BUCKET_OPEN_FUNC(cnbd_md)     = NULL_PTR;
    CNBD_MD_BUCKET_CLOSE_FUNC(cnbd_md)    = NULL_PTR;
    CNBD_MD_BUCKET_TRUNCATE_FUNC(cnbd_md) = NULL_PTR;

    CNBD_MD_BUCKET_READ_FUNC(cnbd_md)     = NULL_PTR;
    CNBD_MD_BUCKET_WRITE_FUNC(cnbd_md)    = NULL_PTR;

    /* free module : */
    //cnbd_free_module_static_mem(cnbd_md_id);

    cnbd_md->usedcounter = 0;

    cbc_md_free(MD_CNBD, cnbd_md_id);

    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_end: "
                                         "stop CNBD module #%ld\n",
                                         cnbd_md_id);

    return ;
}

EC_BOOL cnbd_bucket_open(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_open: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(EC_TRUE == cstring_is_empty(CNBD_MD_BUCKET_NAME(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_open:"
                                             "no bucket name\n");
        return (EC_FALSE);
    }

    CNBD_MD_DEMO_FD(cnbd_md) = c_file_open((char *)CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                                 O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CNBD_MD_DEMO_FD(cnbd_md))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_open:"
                                             "create bucket %s failed\n",
                                             CNBD_MD_BUCKET_NAME_STR(cnbd_md));

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_truncate(CNBD_MD_DEMO_FD(cnbd_md),
                                    (UINT32)CNBD_MD_NBD_DEV_SIZE(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_open:"
                                             "truncate bucket %s size %ld failed\n",
                                             CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_DEV_SIZE(cnbd_md));

        c_file_close(CNBD_MD_DEMO_FD(cnbd_md));
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_bucket_open:"
                                         "create bucket %s, truncate size %ld\n",
                                         CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_DEV_SIZE(cnbd_md));

    return (EC_TRUE);
}

EC_BOOL cnbd_bucket_truncate(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;
    UINT32    bucket_size;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_truncate: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(EC_TRUE == cstring_is_empty(CNBD_MD_BUCKET_NAME(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_truncate:"
                                             "no bucket name\n");
        return (EC_FALSE);
    }

    if(ERR_FD == CNBD_MD_DEMO_FD(cnbd_md))
    {
        CNBD_MD_DEMO_FD(cnbd_md) = c_file_open((char *)CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                                     O_RDWR | O_CREAT, 0666);
        if(ERR_FD == CNBD_MD_DEMO_FD(cnbd_md))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_truncate:"
                                                 "open bucket %s failed\n",
                                                 CNBD_MD_BUCKET_NAME_STR(cnbd_md));

            return (EC_FALSE);
        }
        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_bucket_truncate:"
                                             "open bucket %s, fd %d done\n",
                                             CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                             CNBD_MD_DEMO_FD(cnbd_md));
    }

    bucket_size = (UINT32)CNBD_MD_NBD_DEV_SIZE(cnbd_md);

    if(EC_FALSE == c_file_truncate(CNBD_MD_DEMO_FD(cnbd_md), bucket_size))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_truncate:"
                                             "truncate bucket %s, size %ld failed\n",
                                             CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                             bucket_size);

        c_file_close(CNBD_MD_DEMO_FD(cnbd_md));
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_bucket_truncate:"
                                         "create bucket %s, size %ld done\n",
                                         CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                         bucket_size);

    return (EC_TRUE);
}

EC_BOOL cnbd_bucket_close(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_close: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(EC_TRUE == cstring_is_empty(CNBD_MD_BUCKET_NAME(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_close:"
                                             "no bucket name\n");
        return (EC_FALSE);
    }

    if(ERR_FD == CNBD_MD_DEMO_FD(cnbd_md))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_bucket_close:"
                                             "bucket %s not open yet\n",
                                             CNBD_MD_BUCKET_NAME_STR(cnbd_md));
        return (EC_TRUE);
    }

    c_file_close(CNBD_MD_DEMO_FD(cnbd_md));

    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_bucket_close:"
                                         "close bucket %s, fd %d done\n",
                                         CNBD_MD_BUCKET_NAME_STR(cnbd_md),
                                         CNBD_MD_DEMO_FD(cnbd_md));
    CNBD_MD_DEMO_FD(cnbd_md) = ERR_FD;

    return (EC_TRUE);
}

EC_BOOL cnbd_bucket_read(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_read: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(0 < CNBD_REQ_LEN(cnbd_req))
    {
        uint8_t             *data;
        UINT32               rd_offset;
        UINT32               rd_size;

        data = safe_malloc(CNBD_REQ_LEN(cnbd_req), LOC_CNBD_0003);
        if(NULL_PTR == data)
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_read: "
                                                 "alloc %u bytes failed\n",
                                                 CNBD_REQ_LEN(cnbd_req));

            return (EC_FALSE);
        }

        rd_offset = CNBD_REQ_OFFSET(cnbd_req);
        rd_size   = CNBD_REQ_LEN(cnbd_req);

        if(EC_FALSE == c_file_read(CNBD_MD_DEMO_FD(cnbd_md), &rd_offset, rd_size, data))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_bucket_read: "
                                                 "read (fd %d, offset %u, len %u) failed\n",
                                                 CNBD_MD_DEMO_FD(cnbd_md),
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_LEN(cnbd_req));

            safe_free(data, LOC_CNBD_0004);
            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_bucket_read: "
                                             "read (fd %d, offset %u, len %u) done\n",
                                             CNBD_MD_DEMO_FD(cnbd_md),
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));

        CNBD_RSP_DATA_LEN(cnbd_rsp)   = CNBD_REQ_LEN(cnbd_req);
        CNBD_RSP_DATA_ZONE(cnbd_rsp)  = data;
    }

    CNBD_RSP_MAGIC(cnbd_rsp)  = CNBD_RSP_MAGIC_NUM;
    CNBD_RSP_STATUS(cnbd_rsp) = 0;
    CNBD_RSP_SEQNO(cnbd_rsp)  = CNBD_REQ_SEQNO(cnbd_req);

    return (EC_TRUE);
}

EC_BOOL cnbd_bucket_write(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_write: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(0 < CNBD_REQ_LEN(cnbd_req)
    && NULL_PTR != CNBD_REQ_DATA_ZONE(cnbd_req))
    {
        uint8_t     *data;
        UINT32       wr_offset;
        UINT32       wr_size;

        data        = CNBD_REQ_DATA_ZONE(cnbd_req);
        wr_offset   = CNBD_REQ_OFFSET(cnbd_req);
        wr_size     = CNBD_REQ_LEN(cnbd_req);

        if(EC_FALSE == c_file_write(CNBD_MD_DEMO_FD(cnbd_md), &wr_offset, wr_size, data))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_write: "
                                                 "write (fd %d, offset %u, len %u) failed\n",
                                                 CNBD_MD_DEMO_FD(cnbd_md),
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_LEN(cnbd_req));

            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_handle_req_write: "
                                             "write (fd %d, offset %u, len %u) done\n",
                                             CNBD_MD_DEMO_FD(cnbd_md),
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));
    }

    CNBD_RSP_MAGIC(cnbd_rsp)  = CNBD_RSP_MAGIC_NUM;
    CNBD_RSP_STATUS(cnbd_rsp) = 0;
    CNBD_RSP_SEQNO(cnbd_rsp)  = CNBD_REQ_SEQNO(cnbd_req);

    return (EC_TRUE);
}

EC_BOOL cnbd_set_bucket_open_handler(const UINT32 cnbd_md_id, EC_BOOL (*bucket_open_handler)(const UINT32))
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_write: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    CNBD_MD_BUCKET_OPEN_FUNC(cnbd_md) = bucket_open_handler;

    return (EC_TRUE);
}

EC_BOOL cnbd_set_bucket_truncate_handler(const UINT32 cnbd_md_id, EC_BOOL (*bucket_truncate_handler)(const UINT32))
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_write: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    CNBD_MD_BUCKET_TRUNCATE_FUNC(cnbd_md) = bucket_truncate_handler;

    return (EC_TRUE);
}

EC_BOOL cnbd_set_bucket_close_handler(const UINT32 cnbd_md_id, EC_BOOL (*bucket_close_handler)(const UINT32))
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_write: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    CNBD_MD_BUCKET_CLOSE_FUNC(cnbd_md) = bucket_close_handler;

    return (EC_TRUE);
}

EC_BOOL cnbd_set_bucket_read_handler(const UINT32 cnbd_md_id, EC_BOOL (*bucket_read_handler)(const UINT32, const CNBD_REQ *, CNBD_RSP *))
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_write: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    CNBD_MD_BUCKET_READ_FUNC(cnbd_md) = bucket_read_handler;

    return (EC_TRUE);
}

EC_BOOL cnbd_set_bucket_write_handler(const UINT32 cnbd_md_id, EC_BOOL (*bucket_write_handler)(const UINT32, const CNBD_REQ *, CNBD_RSP *))
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_bucket_write: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    CNBD_MD_BUCKET_WRITE_FUNC(cnbd_md) = bucket_write_handler;

    return (EC_TRUE);
}

CNBD_REQ *cnbd_req_new()
{
    CNBD_REQ *cnbd_req;

    alloc_static_mem(MM_CNBD_REQ, &cnbd_req, LOC_CNBD_0005);
    if(NULL_PTR == cnbd_req)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_req_new: "
                                             "new cnbd_req failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cnbd_req_init(cnbd_req))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_req_new: "
                                             "init cnbd_req failed\n");
        free_static_mem(MM_CNBD_REQ, cnbd_req, LOC_CNBD_0006);
        return (NULL_PTR);
    }

    return (cnbd_req);
}

EC_BOOL cnbd_req_init(CNBD_REQ *cnbd_req)
{
    if(NULL_PTR != cnbd_req)
    {
        CNBD_REQ_MAGIC(cnbd_req)              = 0;
        CNBD_REQ_TYPE(cnbd_req)               = 0;
        CNBD_REQ_SEQNO(cnbd_req)              = 0;
        CNBD_REQ_OFFSET(cnbd_req)             = 0;
        CNBD_REQ_LEN(cnbd_req)                = 0;

        CNBD_REQ_HEADER_POS(cnbd_req)         = 0;
        CNBD_REQ_DATA_POS(cnbd_req)           = 0;
        CNBD_REQ_DATA_ZONE(cnbd_req)          = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_req_clean(CNBD_REQ *cnbd_req)
{
    if(NULL_PTR != cnbd_req)
    {
        CNBD_REQ_MAGIC(cnbd_req)              = 0;
        CNBD_REQ_TYPE(cnbd_req)               = 0;
        CNBD_REQ_SEQNO(cnbd_req)              = 0;
        CNBD_REQ_OFFSET(cnbd_req)             = 0;
        CNBD_REQ_LEN(cnbd_req)                = 0;

        CNBD_REQ_HEADER_POS(cnbd_req)         = 0;
        CNBD_REQ_DATA_POS(cnbd_req)           = 0;

        if(NULL_PTR != CNBD_REQ_DATA_ZONE(cnbd_req))
        {
            safe_free(CNBD_REQ_DATA_ZONE(cnbd_req), LOC_CNBD_0007);
            CNBD_REQ_DATA_ZONE(cnbd_req) = NULL_PTR;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_req_free(CNBD_REQ *cnbd_req)
{
    if(NULL_PTR != cnbd_req)
    {
        cnbd_req_clean(cnbd_req);
        free_static_mem(MM_CNBD_REQ, cnbd_req, LOC_CNBD_0008);
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_req_encode(CNBD_REQ *cnbd_req)
{
    CNBD_REQ_MAGIC(cnbd_req)   = c_hton32(CNBD_REQ_MAGIC(cnbd_req));
    CNBD_REQ_TYPE(cnbd_req)    = c_hton32(CNBD_REQ_TYPE(cnbd_req));
    CNBD_REQ_OFFSET(cnbd_req)  = c_hton64(CNBD_REQ_OFFSET(cnbd_req));
    CNBD_REQ_LEN(cnbd_req)     = c_hton32(CNBD_REQ_LEN(cnbd_req));

    return (EC_TRUE);
}

EC_BOOL cnbd_req_decode(CNBD_REQ *cnbd_req)
{
    CNBD_REQ_MAGIC(cnbd_req)   = c_ntoh32(CNBD_REQ_MAGIC(cnbd_req));
    CNBD_REQ_TYPE(cnbd_req)    = c_ntoh32(CNBD_REQ_TYPE(cnbd_req));
    CNBD_REQ_OFFSET(cnbd_req)  = c_ntoh64(CNBD_REQ_OFFSET(cnbd_req));
    CNBD_REQ_LEN(cnbd_req)     = c_ntoh32(CNBD_REQ_LEN(cnbd_req));

    return (EC_TRUE);
}

void cnbd_req_print(LOG *log, const CNBD_REQ *cnbd_req)
{
    if(NULL_PTR != cnbd_req)
    {
        sys_log(log, "cnbd_req_print: "
                     "req %p: "
                     "magic %u, type %#x, seqno %#lx, offset %ld, len %u, "
                     "(pos %u, data %p)\n",
                     cnbd_req,
                     CNBD_REQ_MAGIC(cnbd_req),
                     CNBD_REQ_TYPE(cnbd_req),
                     CNBD_REQ_SEQNO(cnbd_req),
                     CNBD_REQ_OFFSET(cnbd_req),
                     CNBD_REQ_LEN(cnbd_req),
                     CNBD_REQ_DATA_POS(cnbd_req),
                     CNBD_REQ_DATA_ZONE(cnbd_req));
    }
    return;
}

CNBD_RSP *cnbd_rsp_new()
{
    CNBD_RSP *cnbd_rsp;

    alloc_static_mem(MM_CNBD_RSP, &cnbd_rsp, LOC_CNBD_0009);
    if(NULL_PTR == cnbd_rsp)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_rsp_new: "
                                             "new cnbd_rsp failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cnbd_rsp_init(cnbd_rsp))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_rsp_new: "
                                             "init cnbd_rsp failed\n");
        free_static_mem(MM_CNBD_RSP, cnbd_rsp, LOC_CNBD_0010);
        return (NULL_PTR);
    }

    return (cnbd_rsp);
}

EC_BOOL cnbd_rsp_init(CNBD_RSP *cnbd_rsp)
{
    if(NULL_PTR != cnbd_rsp)
    {
        CNBD_RSP_MAGIC(cnbd_rsp)              = 0;
        CNBD_RSP_STATUS(cnbd_rsp)             = 0;
        CNBD_RSP_SEQNO(cnbd_rsp)              = 0;

        CNBD_RSP_HEADER_POS(cnbd_rsp)         = 0;
        CNBD_RSP_DATA_POS(cnbd_rsp)           = 0;
        CNBD_RSP_DATA_LEN(cnbd_rsp)           = 0;
        CNBD_RSP_DATA_ZONE(cnbd_rsp)          = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_rsp_clean(CNBD_RSP *cnbd_rsp)
{
    if(NULL_PTR != cnbd_rsp)
    {
        CNBD_RSP_MAGIC(cnbd_rsp)              = 0;
        CNBD_RSP_STATUS(cnbd_rsp)             = 0;
        CNBD_RSP_SEQNO(cnbd_rsp)              = 0;

        CNBD_RSP_HEADER_POS(cnbd_rsp)         = 0;
        CNBD_RSP_DATA_POS(cnbd_rsp)           = 0;
        CNBD_RSP_DATA_LEN(cnbd_rsp)           = 0;

        if(NULL_PTR != CNBD_RSP_DATA_ZONE(cnbd_rsp))
        {
            safe_free(CNBD_RSP_DATA_ZONE(cnbd_rsp), LOC_CNBD_0011);
            CNBD_RSP_DATA_ZONE(cnbd_rsp) = NULL_PTR;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_rsp_free(CNBD_RSP *cnbd_rsp)
{
    if(NULL_PTR != cnbd_rsp)
    {
        cnbd_rsp_clean(cnbd_rsp);
        free_static_mem(MM_CNBD_RSP, cnbd_rsp, LOC_CNBD_0012);
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_rsp_encode(CNBD_RSP *cnbd_rsp)
{
    CNBD_RSP_MAGIC(cnbd_rsp)  = c_hton32(CNBD_RSP_MAGIC(cnbd_rsp));
    CNBD_RSP_STATUS(cnbd_rsp) = c_hton32(CNBD_RSP_STATUS(cnbd_rsp));

    return (EC_TRUE);
}

EC_BOOL cnbd_rsp_decode(CNBD_RSP *cnbd_rsp)
{
    CNBD_RSP_MAGIC(cnbd_rsp)  = c_ntoh32(CNBD_RSP_MAGIC(cnbd_rsp));
    CNBD_RSP_STATUS(cnbd_rsp) = c_ntoh32(CNBD_RSP_STATUS(cnbd_rsp));

    return (EC_TRUE);
}

void cnbd_rsp_print(LOG *log, const CNBD_RSP *cnbd_rsp)
{
    if(NULL_PTR != cnbd_rsp)
    {
        sys_log(log, "cnbd_rsp_print: "
                     "rsp %p: "
                     "magic %u, status %#x, seqno %#lx, "
                     "(len %u, data %p)\n",
                     cnbd_rsp,
                     CNBD_RSP_MAGIC(cnbd_rsp),
                     CNBD_RSP_STATUS(cnbd_rsp),
                     CNBD_RSP_SEQNO(cnbd_rsp),
                     CNBD_RSP_DATA_LEN(cnbd_rsp),
                     CNBD_RSP_DATA_ZONE(cnbd_rsp));
    }
    return;
}

STATIC_CAST const char *__cnbd_req_type_str(const uint32_t type)
{
    switch (type)
    {
        case CNBD_CMD_READ:              return ((const char *)"NBD_CMD_READ");
        case CNBD_CMD_WRITE:             return ((const char *)"NBD_CMD_WRITE");
        case CNBD_CMD_DISC:              return ((const char *)"NBD_CMD_DISC");
        case CNBD_CMD_FLUSH:             return ((const char *)"NBD_CMD_FLUSH");
        case CNBD_CMD_TRIM:              return ((const char *)"NBD_CMD_TRIM");
        default:                            break;
    }
    return ((const char *)"UNKNOWN");
}

STATIC_CAST const CNBD_CB *__cnbd_req_cb_fetch(const uint32_t type)
{
    uint32_t     cnbd_req_cb_num;
    uint32_t     cnbd_req_cb_idx;

    cnbd_req_cb_num = sizeof(g_cnbd_cb_list)/sizeof(g_cnbd_cb_list[0]);
    for(cnbd_req_cb_idx = 0; cnbd_req_cb_idx < cnbd_req_cb_num; cnbd_req_cb_idx ++)
    {
        const CNBD_CB      *cnbd_cb;

        cnbd_cb = &(g_cnbd_cb_list[ cnbd_req_cb_idx ]);
        if(CNBD_CB_TYPE(cnbd_cb) == type)
        {
            return (cnbd_cb);
        }
    }

    return (NULL_PTR);
}

EC_BOOL cnbd_push_req(const UINT32 cnbd_md_id, CNBD_REQ *cnbd_req)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_push_req: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    clist_push_back(CNBD_MD_NBD_REQ_LIST(cnbd_md), (void *)cnbd_req);

    dbg_log(SEC_0206_CNBD, 6)(LOGSTDOUT, "[DEBUG] cnbd_push_req: "
                "push req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d) "
                "(header pos %u, data pos %u)\n",
                cnbd_req,
                CNBD_REQ_MAGIC(cnbd_req),
                __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                CNBD_REQ_SEQNO(cnbd_req),
                CNBD_REQ_OFFSET(cnbd_req),
                CNBD_REQ_LEN(cnbd_req),
                CNBD_REQ_HEADER_POS(cnbd_req),
                CNBD_REQ_DATA_POS(cnbd_req));

    return (EC_TRUE);
}

CNBD_REQ *cnbd_pop_req(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;
    CNBD_REQ *cnbd_req;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_pop_req: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    cnbd_req = clist_pop_front(CNBD_MD_NBD_REQ_LIST(cnbd_md));

    if(NULL_PTR != cnbd_req)
    {
        dbg_log(SEC_0206_CNBD, 6)(LOGSTDOUT, "[DEBUG] cnbd_pop_req: "
                    "pop req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d) "
                    "(header pos %u, data pos %u)\n",
                    cnbd_req,
                    CNBD_REQ_MAGIC(cnbd_req),
                    __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                    CNBD_REQ_SEQNO(cnbd_req),
                    CNBD_REQ_OFFSET(cnbd_req),
                    CNBD_REQ_LEN(cnbd_req),
                    CNBD_REQ_HEADER_POS(cnbd_req),
                    CNBD_REQ_DATA_POS(cnbd_req));
    }

    return (cnbd_req);
}

EC_BOOL cnbd_push_rsp(const UINT32 cnbd_md_id, CNBD_RSP *cnbd_rsp)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_push_rsp: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    clist_push_back(CNBD_MD_NBD_RSP_LIST(cnbd_md), (void *)cnbd_rsp);

    dbg_log(SEC_0206_CNBD, 6)(LOGSTDOUT, "[DEBUG] cnbd_push_rsp: "
                    "push rsp %p (magic %u, status %#x, seqno %#lx, len %u) "
                    "(header pos %u, data pos %u)\n",
                    cnbd_rsp,
                    CNBD_RSP_MAGIC(cnbd_rsp),
                    CNBD_RSP_STATUS(cnbd_rsp),
                    CNBD_RSP_SEQNO(cnbd_rsp),
                    CNBD_RSP_DATA_LEN(cnbd_rsp),
                    CNBD_RSP_HEADER_POS(cnbd_rsp),
                    CNBD_RSP_DATA_POS(cnbd_rsp));

    return (EC_TRUE);
}

CNBD_RSP *cnbd_pop_rsp(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;
    CNBD_RSP *cnbd_rsp;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_pop_rsp: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    cnbd_rsp = clist_pop_front(CNBD_MD_NBD_RSP_LIST(cnbd_md));

    if(NULL_PTR != cnbd_rsp)
    {
        dbg_log(SEC_0206_CNBD, 6)(LOGSTDOUT, "[DEBUG] cnbd_pop_rsp: "
                        "pop rsp %p (magic %u, status %#x, seqno %#lx, len %u) "
                        "(header pos %u, data pos %u)\n",
                        cnbd_rsp,
                        CNBD_RSP_MAGIC(cnbd_rsp),
                        CNBD_RSP_STATUS(cnbd_rsp),
                        CNBD_RSP_SEQNO(cnbd_rsp),
                        CNBD_RSP_DATA_LEN(cnbd_rsp),
                        CNBD_RSP_HEADER_POS(cnbd_rsp),
                        CNBD_RSP_DATA_POS(cnbd_rsp));
    }

    return (cnbd_rsp);
}

EC_BOOL cnbd_recv_req(const UINT32 cnbd_md_id, CNBD_REQ *cnbd_req)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_recv_req: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    /*recv header*/
    if(CNBD_REQ_HEADER_SIZE > CNBD_REQ_HEADER_POS(cnbd_req))
    {
        if(EC_FALSE == c_socket_recv(CNBD_MD_D_SOCKFD(cnbd_md),
                                        (uint8_t *)cnbd_req,
                                        CNBD_REQ_HEADER_SIZE,
                                        &CNBD_REQ_HEADER_POS(cnbd_req)))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_recv_req: "
                                                 "recv req header failed, "
                                                 "pos %u, expected header size %u\n",
                                                 CNBD_REQ_HEADER_POS(cnbd_req),
                                                 CNBD_REQ_HEADER_SIZE);

            return (EC_FALSE);
        }

        if(CNBD_REQ_HEADER_SIZE > CNBD_REQ_HEADER_POS(cnbd_req))
        {
            dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_recv_req: "
                                                 "recv req header incompleted, "
                                                 "pos %u, expected header size %u\n",
                                                 CNBD_REQ_HEADER_POS(cnbd_req),
                                                 CNBD_REQ_HEADER_SIZE);

            return (EC_AGAIN);
        }

        cnbd_req_decode(cnbd_req);

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_recv_req: "
                    "recv req header "
                    "(magic %#x, type %s, seqno %#lx, offset %ld, len %d) done\n",
                    CNBD_REQ_MAGIC(cnbd_req),
                    __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                    CNBD_REQ_SEQNO(cnbd_req),
                    CNBD_REQ_OFFSET(cnbd_req),
                    CNBD_REQ_LEN(cnbd_req));
    }

    /*recv data*/
    if(CNBD_CMD_WRITE == CNBD_REQ_TYPE(cnbd_req)
    && 0 < CNBD_REQ_LEN(cnbd_req)
    && CNBD_REQ_DATA_POS(cnbd_req) < CNBD_REQ_LEN(cnbd_req))
    {
        if(NULL_PTR == CNBD_REQ_DATA_ZONE(cnbd_req))
        {
            uint8_t     *data;

            data = safe_malloc(CNBD_REQ_LEN(cnbd_req), LOC_CNBD_0013);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_recv_req: "
                                                     "alloc %u bytes failed\n",
                                                     CNBD_REQ_LEN(cnbd_req));

                return (EC_FALSE);
            }

            CNBD_REQ_DATA_ZONE(cnbd_req)   = data;
        }

        if(EC_FALSE == c_socket_recv(CNBD_MD_D_SOCKFD(cnbd_md),
                                     CNBD_REQ_DATA_ZONE(cnbd_req),
                                     CNBD_REQ_LEN(cnbd_req),
                                     &CNBD_REQ_DATA_POS(cnbd_req)))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_recv_req: "
                                                 "read dsock %d len %u failed\n",
                                                 CNBD_MD_D_SOCKFD(cnbd_md),
                                                 CNBD_REQ_LEN(cnbd_req));
            return (EC_FALSE);
        }

        if(CNBD_REQ_DATA_POS(cnbd_req) < CNBD_REQ_LEN(cnbd_req))
        {
            dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_recv_req: "
                                                 "recv req data incompleted, "
                                                 "pos %u, expected len %u\n",
                                                 CNBD_REQ_DATA_POS(cnbd_req),
                                                 CNBD_REQ_LEN(cnbd_req));

            return (EC_AGAIN);
        }


        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_recv_req: "
                                             "read dsock %d len %u done\n",
                                             CNBD_MD_D_SOCKFD(cnbd_md),
                                             CNBD_REQ_LEN(cnbd_req));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_send_rsp(const UINT32 cnbd_md_id, CNBD_RSP *cnbd_rsp)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_send_rsp: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    /*send header*/
    if(CNBD_RSP_HEADER_SIZE > CNBD_RSP_HEADER_POS(cnbd_rsp))
    {
        cnbd_rsp_encode(cnbd_rsp);

        if(EC_FALSE == c_socket_send(CNBD_MD_D_SOCKFD(cnbd_md),
                                        (uint8_t *)cnbd_rsp,
                                        CNBD_RSP_HEADER_SIZE,
                                        &CNBD_RSP_HEADER_POS(cnbd_rsp)))
        {
            /*restore*/
            cnbd_rsp_decode(cnbd_rsp);

            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_send_rsp: "
                                                 "send rsp header failed, "
                                                 "pos %u, expected header size %u\n",
                                                 CNBD_RSP_HEADER_POS(cnbd_rsp),
                                                 CNBD_RSP_HEADER_SIZE);

            return (EC_FALSE);
        }

        /*restore*/
        cnbd_rsp_decode(cnbd_rsp);

        if(CNBD_RSP_HEADER_SIZE > CNBD_RSP_HEADER_POS(cnbd_rsp))
        {
            dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_send_rsp: "
                                                 "send rsp header incompleted, "
                                                 "pos %u, expected header size %u\n",
                                                 CNBD_RSP_HEADER_POS(cnbd_rsp),
                                                 CNBD_RSP_HEADER_SIZE);

            return (EC_AGAIN);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_send_rsp: "
                                             "send rsp header "
                                             "(magic %#x, status %#x, seqno %#lx) done\n",
                                             CNBD_RSP_MAGIC(cnbd_rsp),
                                             CNBD_RSP_STATUS(cnbd_rsp),
                                             CNBD_RSP_SEQNO(cnbd_rsp));
    }

    /*send data*/
    if(0 < CNBD_RSP_DATA_LEN(cnbd_rsp)
    && CNBD_RSP_DATA_POS(cnbd_rsp) < CNBD_RSP_DATA_LEN(cnbd_rsp)
    && NULL_PTR != CNBD_RSP_DATA_ZONE(cnbd_rsp))
    {
        if(EC_FALSE == c_socket_send(CNBD_MD_D_SOCKFD(cnbd_md),
                                    CNBD_RSP_DATA_ZONE(cnbd_rsp),
                                    CNBD_RSP_DATA_LEN(cnbd_rsp),
                                    &CNBD_RSP_DATA_POS(cnbd_rsp)))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_send_rsp: "
                                                 "send rsp data len %u failed\n",
                                                 CNBD_RSP_DATA_LEN(cnbd_rsp));

            return (EC_FALSE);
        }

        if(CNBD_RSP_DATA_POS(cnbd_rsp) < CNBD_RSP_DATA_LEN(cnbd_rsp))
        {
            dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_send_rsp: "
                                                 "send rsp data incompleted, "
                                                 "pos %u, expected len %u\n",
                                                 CNBD_RSP_DATA_POS(cnbd_rsp),
                                                 CNBD_RSP_DATA_LEN(cnbd_rsp));

            return (EC_AGAIN);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_send_rsp: "
                                             "send rsp data len %u done\n",
                                             CNBD_RSP_DATA_LEN(cnbd_rsp));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_handle_req_read(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req)
{
    CNBD_MD  *cnbd_md;
    CNBD_RSP *cnbd_rsp;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_handle_req_read: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    cnbd_rsp = cnbd_rsp_new();
    if(NULL_PTR == cnbd_rsp)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_read: "
                                             "new cnbd_rsp failed\n");
        return (EC_FALSE);
    }

    /*default reader*/
    if(NULL_PTR == CNBD_MD_BUCKET_READ_FUNC(cnbd_md))
    {
        if(EC_FALSE == cnbd_bucket_read(cnbd_md_id, cnbd_req, cnbd_rsp))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_read: "
                                                 "read (fd %d, offset %u, len %u) failed\n",
                                                 CNBD_MD_DEMO_FD(cnbd_md),
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_LEN(cnbd_req));

            cnbd_rsp_free(cnbd_rsp);
            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_handle_req_read: "
                                             "read (fd %d, offset %u, len %u) done\n",
                                             CNBD_MD_DEMO_FD(cnbd_md),
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));
    }
    /*specific reader*/
    else
    {
        if(EC_FALSE == CNBD_MD_BUCKET_READ_FUNC(cnbd_md)(cnbd_md_id, cnbd_req, cnbd_rsp))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_read: "
                                                 "read (fd %d, offset %u, len %u) failed\n",
                                                 CNBD_MD_DEMO_FD(cnbd_md),
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_LEN(cnbd_req));

            cnbd_rsp_free(cnbd_rsp);
            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_handle_req_read: "
                                             "read (fd %d, offset %u, len %u) done\n",
                                             CNBD_MD_DEMO_FD(cnbd_md),
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));
    }

    cnbd_push_rsp(cnbd_md_id, cnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cnbd_handle_req_write(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req)
{
    CNBD_MD  *cnbd_md;
    CNBD_RSP *cnbd_rsp;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_handle_req_write: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    cnbd_rsp = cnbd_rsp_new();
    if(NULL_PTR == cnbd_rsp)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_write: "
                                             "new cnbd_rsp failed\n");
        return (EC_FALSE);
    }

    /*default writer*/
    if(NULL_PTR == CNBD_MD_BUCKET_WRITE_FUNC(cnbd_md))
    {
        if(EC_FALSE == cnbd_bucket_write(cnbd_md_id, cnbd_req, cnbd_rsp))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_write: "
                                                 "write (fd %d, offset %u, len %u) failed\n",
                                                 CNBD_MD_DEMO_FD(cnbd_md),
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_LEN(cnbd_req));

            cnbd_rsp_free(cnbd_rsp);
            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_handle_req_write: "
                                             "write (fd %d, offset %u, len %u) done\n",
                                             CNBD_MD_DEMO_FD(cnbd_md),
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));
    }
    else
    {
        if(EC_FALSE == CNBD_MD_BUCKET_WRITE_FUNC(cnbd_md)(cnbd_md_id, cnbd_req, cnbd_rsp))
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_write: "
                                                 "write (fd %d, offset %u, len %u) failed\n",
                                                 CNBD_MD_DEMO_FD(cnbd_md),
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_LEN(cnbd_req));

            cnbd_rsp_free(cnbd_rsp);
            return (EC_FALSE);
        }

        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_handle_req_write: "
                                             "write (fd %d, offset %u, len %u) done\n",
                                             CNBD_MD_DEMO_FD(cnbd_md),
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));
    }

    cnbd_push_rsp(cnbd_md_id, cnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cnbd_handle_req_disc(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req)
{
#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_handle_req_flush: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    return cnbd_device_disconnect(cnbd_md_id);
}

EC_BOOL cnbd_handle_req_flush(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req)
{
    CNBD_RSP *cnbd_rsp;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_handle_req_flush: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_rsp = cnbd_rsp_new();
    if(NULL_PTR == cnbd_rsp)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_flush: "
                                             "new cnbd_rsp failed\n");
        return (EC_FALSE);
    }

    CNBD_RSP_MAGIC(cnbd_rsp)  = CNBD_RSP_MAGIC_NUM;
    CNBD_RSP_STATUS(cnbd_rsp) = 0;
    CNBD_RSP_SEQNO(cnbd_rsp)  = CNBD_REQ_SEQNO(cnbd_req);;

    cnbd_push_rsp(cnbd_md_id, cnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cnbd_handle_req_trim(const UINT32 cnbd_md_id, const CNBD_REQ *cnbd_req)
{
    CNBD_RSP *cnbd_rsp;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_handle_req_trim: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_rsp = cnbd_rsp_new();
    if(NULL_PTR == cnbd_rsp)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req_trim: "
                                             "new cnbd_rsp failed\n");
        return (EC_FALSE);
    }

    CNBD_RSP_MAGIC(cnbd_rsp)  = CNBD_RSP_MAGIC_NUM;
    CNBD_RSP_STATUS(cnbd_rsp) = 0;
    CNBD_RSP_SEQNO(cnbd_rsp)  = CNBD_REQ_SEQNO(cnbd_req);;

    cnbd_push_rsp(cnbd_md_id, cnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cnbd_handle_req(const UINT32 cnbd_md_id, CNBD_REQ *cnbd_req)
{
    const CNBD_CB  *cnbd_cb;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_handle_req: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_handle_req: "
                " req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d) "
                "(header pos %u, data pos %u)\n",
                cnbd_req,
                CNBD_REQ_MAGIC(cnbd_req),
                __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                CNBD_REQ_SEQNO(cnbd_req),
                CNBD_REQ_OFFSET(cnbd_req),
                CNBD_REQ_LEN(cnbd_req),
                CNBD_REQ_HEADER_POS(cnbd_req),
                CNBD_REQ_DATA_POS(cnbd_req));

    ASSERT(CNBD_REQ_HEADER_POS(cnbd_req) == CNBD_REQ_HEADER_SIZE);
    ASSERT(CNBD_CMD_WRITE != CNBD_REQ_TYPE(cnbd_req)
        || CNBD_REQ_DATA_POS(cnbd_req) == CNBD_REQ_LEN(cnbd_req));

    cnbd_cb = __cnbd_req_cb_fetch(CNBD_REQ_TYPE(cnbd_req));
    if(NULL_PTR == cnbd_cb)
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req: "
                    "handle req (magic %#x, type %s, seqno %#lx, offset %ld, len %d)"
                    " => invalid type\n",
                    CNBD_REQ_MAGIC(cnbd_req),
                    __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                    CNBD_REQ_SEQNO(cnbd_req),
                    CNBD_REQ_OFFSET(cnbd_req),
                    CNBD_REQ_LEN(cnbd_req));


        cnbd_req_free(cnbd_req);
        return (EC_FALSE);
    }

    if(EC_FALSE == CNBD_CB_HANDLER(cnbd_cb)(cnbd_md_id, cnbd_req))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_handle_req: "
                    "handle req (magic %#x, type %s, seqno %#lx, offset %ld, len %d) failed\n",
                    CNBD_REQ_MAGIC(cnbd_req),
                    __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                    CNBD_REQ_SEQNO(cnbd_req),
                    CNBD_REQ_OFFSET(cnbd_req),
                    CNBD_REQ_LEN(cnbd_req));

        cnbd_req_free(cnbd_req);
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_handle_req: "
                "handle req (magic %#x, type %s, seqno %#lx, offset %ld, len %d) done\n",
                CNBD_REQ_MAGIC(cnbd_req),
                __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                CNBD_REQ_SEQNO(cnbd_req),
                CNBD_REQ_OFFSET(cnbd_req),
                CNBD_REQ_LEN(cnbd_req));

    cnbd_req_free(cnbd_req);

    return (EC_TRUE);
}

EC_BOOL cnbd_handle_req_list(const UINT32 cnbd_md_id)
{
    CNBD_REQ       *cnbd_req;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_handle_req_list: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    while(NULL_PTR != (cnbd_req = cnbd_pop_req(cnbd_md_id)))
    {
        MOD_NODE        recv_mod_node;

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&recv_mod_node) = cnbd_md_id;

        task_p2p_no_wait(cnbd_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                 &recv_mod_node,
                 NULL_PTR,
                 FI_cnbd_handle_req, CMPI_ERROR_MODI, (UINT32)cnbd_req/*trick*/);
    }

    return (EC_TRUE);
}

EC_BOOL cnbd_device_open(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_device_open: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    CNBD_MD_NBD_FD(cnbd_md) = c_file_open((char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md), O_RDWR, 0666);
    if(ERR_FD == CNBD_MD_NBD_FD(cnbd_md))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_open: "
                                             "open nbd device '%s' failed\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md));
        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_open: "
                                         "open nbd device '%s', fd %d\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md));

    return (EC_TRUE);
}

EC_BOOL cnbd_device_close(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_device_close: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(ERR_FD != CNBD_MD_NBD_FD(cnbd_md))
    {
        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_close: "
                                             "close nbd device '%s', fd %d\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md));

        c_file_close(CNBD_MD_NBD_FD(cnbd_md));
        CNBD_MD_NBD_FD(cnbd_md) = ERR_FD;
        return (EC_TRUE);
    }

    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_close: "
                                         "nbd device '%s' not open\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md));
    return (EC_TRUE);
}

EC_BOOL cnbd_device_set(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_device_set: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(ERR_FD == CNBD_MD_NBD_FD(cnbd_md))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_set: "
                                             "nbd device '%s' not open yet\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md));
        return (EC_FALSE);
    }

    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_CLEAR_SOCK))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_set: "
                                             "nbd device '%s', fd %d, ioctl %s failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             "CNBD_CLEAR_SOCK",
                                             errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_device_set: "
                                         "nbd device '%s', fd %d, clear sock\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md));

    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_SET_SOCK, CNBD_MD_C_SOCKFD(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_set: "
                                             "nbd device '%s', fd %d, ioctl %s (%d) failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             "CNBD_SET_SOCK",
                                             CNBD_MD_C_SOCKFD(cnbd_md),
                                             errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_set: "
                                         "nbd device '%s', fd %d, set sock %d\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md),
                                         CNBD_MD_C_SOCKFD(cnbd_md));


    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_SET_BLKSIZE, CNBD_MD_NBD_BLK_SIZE(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_set: "
                                             "nbd device '%s', fd %d, ioctl %s (%ld) failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             "CNBD_SET_BLKSIZE",
                                             CNBD_MD_NBD_BLK_SIZE(cnbd_md),
                                             errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_set: "
                                         "nbd device '%s', fd %d, set block size %ld\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md),
                                         CNBD_MD_NBD_BLK_SIZE(cnbd_md));

    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_SET_SIZE, CNBD_MD_NBD_DEV_SIZE(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_set: "
                                             "nbd device '%s', fd %d, ioctl %s (%ld) failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             "CNBD_SET_SIZE",
                                             CNBD_MD_NBD_DEV_SIZE(cnbd_md),
                                             errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_set: "
                                         "nbd device '%s', fd %d, set device size %ld\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md),
                                         CNBD_MD_NBD_DEV_SIZE(cnbd_md));

    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_SET_FLAGS, CNBD_MD_NBD_T_FLAGS(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_set: "
                                             "nbd device '%s', fd %d, ioctl %s (%#lx) failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             "CNBD_SET_FLAGS",
                                             CNBD_MD_NBD_T_FLAGS(cnbd_md),
                                             errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_set: "
                                         "nbd device '%s', fd %d, set flags %#lx\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md),
                                         CNBD_MD_NBD_T_FLAGS(cnbd_md));

    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_SET_TIMEOUT, CNBD_MD_NBD_TIMEOUT(cnbd_md)))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_set: "
                                             "nbd device '%s', fd %d, ioctl %s (%#lx) failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             "CNBD_SET_TIMEOUT",
                                             CNBD_MD_NBD_TIMEOUT(cnbd_md),
                                             errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_set: "
                                         "nbd device '%s', fd %d, set timeout %ld\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md),
                                         CNBD_MD_NBD_TIMEOUT(cnbd_md));

    return (EC_TRUE);
}

EC_BOOL cnbd_device_listen(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_device_listen: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_device_listen: "
                                         "nbd device '%s', fd %d, listen and block\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md));

    /*block*/
    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_DO_IT))
    {
        int err;

        err = errno;
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_listen: "
                                             "nbd device '%s', fd %d, listen failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             errno, strerror(errno));

        if(EBUSY == err)
        {
            cnbd_device_disconnect(cnbd_md_id);
        }

        /*terminate thread and terminate cnbd module*/
        cnbd_end(cnbd_md_id);

        return (EC_FALSE);
    }

    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_device_listen: "
                                         "nbd device '%s', fd %d, listen terminated\n",
                                         (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                         CNBD_MD_NBD_FD(cnbd_md));

    /*terminate thread and terminate cnbd module*/
    cnbd_end(cnbd_md_id);

    return (EC_TRUE);
}

EC_BOOL cnbd_device_disconnect(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

    EC_BOOL      ret;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_device_disconnect: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    ret = EC_TRUE;

    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_CLEAR_SOCK))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_disconnect: "
                                             "nbd device '%s', fd %d, clear sock failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             errno, strerror(errno));
        ret = EC_FALSE;
    }
    else
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "[DEBUG] cnbd_device_disconnect: "
                                             "nbd device '%s', fd %d, clear sock done\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md));
    }

    if(0 > ioctl(CNBD_MD_NBD_FD(cnbd_md), CNBD_DISCONNECT))
    {
        dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_device_disconnect: "
                                             "nbd device '%s', fd %d, disconnect failed, "
                                             "errno %d, errstr %s\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md),
                                             errno, strerror(errno));
        ret = EC_FALSE;
    }
    else
    {
        dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_device_disconnect: "
                                             "nbd device '%s', fd %d, disconnect done\n",
                                             (char *)CNBD_MD_NBD_DEV_NAME_STR(cnbd_md),
                                             CNBD_MD_NBD_FD(cnbd_md));
    }
    return (ret);
}

EC_BOOL cnbd_socket_recv(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_socket_recv: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(NULL_PTR != CNBD_MD_NBD_REQ_ONGOING(cnbd_md))
    {
        CNBD_REQ *cnbd_req;
        EC_BOOL      ret;

        cnbd_req = CNBD_MD_NBD_REQ_ONGOING(cnbd_md);
        CNBD_MD_NBD_REQ_ONGOING(cnbd_md) = NULL_PTR;

        ret = cnbd_recv_req(cnbd_md_id, cnbd_req);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_socket_recv: "
                                                 "recv ongoing req failed\n");

            cnbd_req_free(cnbd_req);

            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_socket_recv: "
                                                 "recv ongoing req again\n");

            CNBD_MD_NBD_REQ_ONGOING(cnbd_md) = cnbd_req;

            return cnbd_handle_req_list(cnbd_md_id);
        }

        cnbd_push_req(cnbd_md_id, cnbd_req);

        dbg_log(SEC_0206_CNBD, 5)(LOGSTDOUT, "[DEBUG] cnbd_socket_recv: "
                    "recv ongoing req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d)\n",
                    cnbd_req,
                    CNBD_REQ_MAGIC(cnbd_req),
                    __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                    CNBD_REQ_SEQNO(cnbd_req),
                    CNBD_REQ_OFFSET(cnbd_req),
                    CNBD_REQ_LEN(cnbd_req));
    }

    for(;;)
    {
        CNBD_REQ *cnbd_req;
        EC_BOOL      ret;

        cnbd_req = cnbd_req_new();
        if(NULL_PTR == cnbd_req)
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_socket_recv: "
                                                 "new cnbd_req failed\n");
            return (EC_FALSE);
        }

        ret = cnbd_recv_req(cnbd_md_id, cnbd_req);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_socket_recv: "
                                                 "recv req failed\n");

            cnbd_req_free(cnbd_req);

            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            /*recv nothing*/
            if(0 == CNBD_REQ_HEADER_POS(cnbd_req))
            {
                dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_socket_recv: "
                                                     "recv req no more\n");

                cnbd_req_free(cnbd_req);

                return cnbd_handle_req_list(cnbd_md_id);
            }

            /*recv partial*/
            dbg_log(SEC_0206_CNBD, 9)(LOGSTDOUT, "[DEBUG] cnbd_socket_recv: "
                                                 "recv req again\n");

            CNBD_MD_NBD_REQ_ONGOING(cnbd_md) = cnbd_req;

            return cnbd_handle_req_list(cnbd_md_id);
        }

        cnbd_push_req(cnbd_md_id, cnbd_req);

        dbg_log(SEC_0206_CNBD, 5)(LOGSTDOUT, "[DEBUG] cnbd_socket_recv: "
                    "recv req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d)\n",
                    cnbd_req,
                    CNBD_REQ_MAGIC(cnbd_req),
                    __cnbd_req_type_str(CNBD_REQ_TYPE(cnbd_req)),
                    CNBD_REQ_SEQNO(cnbd_req),
                    CNBD_REQ_OFFSET(cnbd_req),
                    CNBD_REQ_LEN(cnbd_req));
    }

    /*should never reach here*/
    dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_socket_recv: "
                                         "should never reach here\n");
    return (EC_FALSE);
}

EC_BOOL cnbd_socket_send(const UINT32 cnbd_md_id)
{
    CNBD_MD  *cnbd_md;
    CNBD_RSP *cnbd_rsp;

#if (SWITCH_ON == CNBD_DEBUG_SWITCH)
    if ( CNBD_MD_ID_CHECK_INVALID(cnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cnbd_socket_send: cnbd module #%ld not started.\n",
                cnbd_md_id);
        cnbd_print_module_status(cnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CNBD, cnbd_md_id);
    }
#endif/*(SWITCH_ON == CNBD_DEBUG_SWITCH)*/

    cnbd_md = CNBD_MD_GET(cnbd_md_id);

    if(NULL_PTR != CNBD_MD_NBD_RSP_ONGOING(cnbd_md))
    {
        EC_BOOL      ret;

        cnbd_rsp = CNBD_MD_NBD_RSP_ONGOING(cnbd_md);

        ret = cnbd_send_rsp(cnbd_md_id, cnbd_rsp);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_socket_send: "
                        "send ongoing rsp (magic %u, status %#x, seqno %#lx, len %u) failed\n",
                        CNBD_RSP_MAGIC(cnbd_rsp),
                        CNBD_RSP_STATUS(cnbd_rsp),
                        CNBD_RSP_SEQNO(cnbd_rsp),
                        CNBD_RSP_DATA_LEN(cnbd_rsp));

            CNBD_MD_NBD_RSP_ONGOING(cnbd_md) = NULL_PTR;
            cnbd_rsp_free(cnbd_rsp);

            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            dbg_log(SEC_0206_CNBD, 5)(LOGSTDOUT, "[DEBUG] cnbd_socket_send: "
                        "send ongoing rsp (magic %u, status %#x, seqno %#lx, len %u) again\n",
                        CNBD_RSP_MAGIC(cnbd_rsp),
                        CNBD_RSP_STATUS(cnbd_rsp),
                        CNBD_RSP_SEQNO(cnbd_rsp),
                        CNBD_RSP_DATA_LEN(cnbd_rsp));

            return (EC_TRUE);
        }

        dbg_log(SEC_0206_CNBD, 5)(LOGSTDOUT, "[DEBUG] cnbd_socket_send: "
                        "send ongoing rsp (magic %u, status %#x, seqno %#lx, len %u) done\n",
                        CNBD_RSP_MAGIC(cnbd_rsp),
                        CNBD_RSP_STATUS(cnbd_rsp),
                        CNBD_RSP_SEQNO(cnbd_rsp),
                        CNBD_RSP_DATA_LEN(cnbd_rsp));

        CNBD_MD_NBD_RSP_ONGOING(cnbd_md) = NULL_PTR;
        cnbd_rsp_free(cnbd_rsp);
    }

    while(NULL_PTR != (cnbd_rsp = cnbd_pop_rsp(cnbd_md_id)))
    {
        EC_BOOL      ret;

        if(CNBD_RSP_HEADER_POS(cnbd_rsp) == CNBD_RSP_HEADER_SIZE
        && CNBD_RSP_DATA_POS(cnbd_rsp) == CNBD_RSP_DATA_LEN(cnbd_rsp))
        {
            /*never reach here*/
            cnbd_rsp_free(cnbd_rsp);
            continue;
        }

        ret = cnbd_send_rsp(cnbd_md_id, cnbd_rsp);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0206_CNBD, 0)(LOGSTDOUT, "error:cnbd_socket_send: "
                        "send rsp (magic %u, status %#x, seqno %#lx, len %u) failed\n",
                        CNBD_RSP_MAGIC(cnbd_rsp),
                        CNBD_RSP_STATUS(cnbd_rsp),
                        CNBD_RSP_SEQNO(cnbd_rsp),
                        CNBD_RSP_DATA_LEN(cnbd_rsp));

            cnbd_rsp_free(cnbd_rsp);
            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            CNBD_MD_NBD_RSP_ONGOING(cnbd_md) = cnbd_rsp;

            dbg_log(SEC_0206_CNBD, 5)(LOGSTDOUT, "[DEBUG] cnbd_socket_send: "
                        "send rsp (magic %u, status %#x, seqno %#lx, len %u) again\n",
                        CNBD_RSP_MAGIC(cnbd_rsp),
                        CNBD_RSP_STATUS(cnbd_rsp),
                        CNBD_RSP_SEQNO(cnbd_rsp),
                        CNBD_RSP_DATA_LEN(cnbd_rsp));

            return (EC_TRUE);
        }

        dbg_log(SEC_0206_CNBD, 5)(LOGSTDOUT, "[DEBUG] cnbd_socket_send: "
                        "send rsp (magic %u, status %#x, seqno %#lx, len %u) done\n",
                        CNBD_RSP_MAGIC(cnbd_rsp),
                        CNBD_RSP_STATUS(cnbd_rsp),
                        CNBD_RSP_SEQNO(cnbd_rsp),
                        CNBD_RSP_DATA_LEN(cnbd_rsp));

        cnbd_rsp_free(cnbd_rsp);

        /*continue*/
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

