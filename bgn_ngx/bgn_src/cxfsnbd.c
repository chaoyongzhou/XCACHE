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

#include "cxfsnbd.h"

#include "findex.inc"

#define CXFSNBD_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFSNBD))

#define CXFSNBD_MD_GET(cxfsnbd_md_id)     ((CXFSNBD_MD *)cbc_md_get(MD_CXFSNBD, (cxfsnbd_md_id)))

#define CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id)  \
    ((CMPI_ANY_MODI != (cxfsnbd_md_id)) && ((NULL_PTR == CXFSNBD_MD_GET(cxfsnbd_md_id)) || (0 == (CXFSNBD_MD_GET(cxfsnbd_md_id)->usedcounter))))

static const CXFSNBD_CB g_cxfsnbd_cb_list[] = {
    {CXFSNBD_CMD_READ , 0, "NBD_CMD_READ" , cxfsnbd_handle_req_read},
    {CXFSNBD_CMD_WRITE, 0, "NBD_CMD_WRITE", cxfsnbd_handle_req_write},
    {CXFSNBD_CMD_DISC , 0, "NBD_CMD_DISC" , cxfsnbd_handle_req_disc},
    {CXFSNBD_CMD_FLUSH, 0, "NBD_CMD_FLUSH", cxfsnbd_handle_req_flush},
    {CXFSNBD_CMD_TRIM , 0, "NBD_CMD_TRIM" , cxfsnbd_handle_req_trim},
};


/**
*   for test only
*
*   to query the status of CXFSNBD Module
*
**/
void cxfsnbd_print_module_status(const UINT32 cxfsnbd_md_id, LOG *log)
{
    CXFSNBD_MD *cxfsnbd_md;
    UINT32 this_cxfsnbd_md_id;

    for( this_cxfsnbd_md_id = 0; this_cxfsnbd_md_id < CXFSNBD_MD_CAPACITY(); this_cxfsnbd_md_id ++ )
    {
        cxfsnbd_md = CXFSNBD_MD_GET(this_cxfsnbd_md_id);

        if ( NULL_PTR != cxfsnbd_md && 0 < cxfsnbd_md->usedcounter )
        {
            sys_log(log,"CXFSNBD Module # %ld : %ld refered\n",
                    this_cxfsnbd_md_id,
                    cxfsnbd_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CXFSNBD module
*
*
**/
UINT32 cxfsnbd_free_module_static_mem(const UINT32 cxfsnbd_md_id)
{
#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_free_module_static_mem: cxfs module #%ld not started.\n",
                cxfsnbd_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    free_module_static_mem(MD_CXFSNBD, cxfsnbd_md_id);

    return 0;
}

/**
*
* start CXFSNBD module
*
**/
UINT32 cxfsnbd_start(const CSTRING *nbd_dev_name)
{
    CXFSNBD_MD     *cxfsnbd_md;
    UINT32          cxfsnbd_md_id;
    int             sockfd[2]; /*socket pair*/

    cbc_md_reg(MD_CXFSNBD, 16);

    cxfsnbd_md_id = cbc_md_new(MD_CXFSNBD, sizeof(CXFSNBD_MD));
    if(CMPI_ERROR_MODI == cxfsnbd_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CXFSNBD module */
    cxfsnbd_md = (CXFSNBD_MD *)cbc_md_get(MD_CXFSNBD, cxfsnbd_md_id);
    cxfsnbd_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFSNBD_MD_C_SOCKFD(cxfsnbd_md)     = ERR_FD;
    CXFSNBD_MD_D_SOCKFD(cxfsnbd_md)     = ERR_FD;
    CXFSNBD_MD_NBD_FD(cxfsnbd_md)       = ERR_FD;

    CXFSNBD_MD_DEMO_FD(cxfsnbd_md)      = ERR_FD;

    CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)  = 0;
    CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)  = 0;
    CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md) = NULL_PTR;

    clist_init(CXFSNBD_MD_NBD_REQ_LIST(cxfsnbd_md), MM_CXFSNBD_REQ, LOC_CXFSNBD_0001);
    clist_init(CXFSNBD_MD_NBD_RSP_LIST(cxfsnbd_md), MM_CXFSNBD_RSP, LOC_CXFSNBD_0002);

    CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md) = NULL_PTR;
    CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md) = NULL_PTR;

    cxfsnbd_md->usedcounter = 1;

    if(NULL_PTR == nbd_dev_name)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "nbd_dev_name is null\n");

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md) = cstring_dup(nbd_dev_name);
    if(NULL_PTR == CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "new nbd_dev_name '%s' failed\n",
                                                (char *)cstring_get_str(nbd_dev_name));

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }
#if 0
    if(EC_FALSE == c_file_exist(CXFSNBD_DEMO_FNAME))
#endif
    {
        CXFSNBD_MD_DEMO_FD(cxfsnbd_md) = c_file_open(CXFSNBD_DEMO_FNAME, O_RDWR | O_CREAT, 0666);
        if(ERR_FD == CXFSNBD_MD_DEMO_FD(cxfsnbd_md))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                    "create %s failed\n",
                                                    CXFSNBD_DEMO_FNAME);

            cxfsnbd_end(cxfsnbd_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_truncate(CXFSNBD_MD_DEMO_FD(cxfsnbd_md), (UINT32)CXFSNBD_DEV_SIZE))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                    "truncate %s size %ld failed\n",
                                                    CXFSNBD_DEMO_FNAME, CXFSNBD_DEV_SIZE);

            cxfsnbd_end(cxfsnbd_md_id);
            return (CMPI_ERROR_MODI);
        }

        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start:"
                                                "create %s, truncate size %ld\n",
                                                CXFSNBD_DEMO_FNAME,
                                                CXFSNBD_DEV_SIZE);
    }
#if 0
    else
    {
        UINT32  demo_fsize;

        CXFSNBD_MD_DEMO_FD(cxfsnbd_md) = c_file_open(CXFSNBD_DEMO_FNAME, O_RDWR, 0666);
        if(ERR_FD == CXFSNBD_MD_DEMO_FD(cxfsnbd_md))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                    "open %s failed\n",
                                                    CXFSNBD_DEMO_FNAME);

            cxfsnbd_end(cxfsnbd_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_size(CXFSNBD_MD_DEMO_FD(cxfsnbd_md), &demo_fsize))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                    "size of %s failed\n",
                                                    CXFSNBD_DEMO_FNAME);

            cxfsnbd_end(cxfsnbd_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(demo_fsize != ((UINT32)CXFSNBD_DEV_SIZE))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                    "%s size %ld != %ld failed\n",
                                                    CXFSNBD_DEMO_FNAME,
                                                    demo_fsize,
                                                    CXFSNBD_DEV_SIZE);

            cxfsnbd_end(cxfsnbd_md_id);
            return (CMPI_ERROR_MODI);
        }

        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start:"
                                                "open %s, size %ld\n",
                                                CXFSNBD_DEMO_FNAME,
                                                demo_fsize);
    }
#endif
    CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md) = CXFSNBD_BLK_SIZE;
    CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md) = CXFSNBD_DEV_SIZE;
    CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)  = CXFSNBD_TIMEOUT;

    if(0 > socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "create unix socket pair failed\n");

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBD_MD_C_SOCKFD(cxfsnbd_md) = sockfd[0];
    CXFSNBD_MD_D_SOCKFD(cxfsnbd_md) = sockfd[1];

    c_socket_nonblock_enable(CXFSNBD_MD_C_SOCKFD(cxfsnbd_md));
    c_socket_nonblock_enable(CXFSNBD_MD_D_SOCKFD(cxfsnbd_md));

    cepoll_set_event(task_brd_default_get_cepoll(),
                      CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                      CEPOLL_RD_EVENT,
                      (const char *)"cxfsnbd_socket_recv",
                      (CEPOLL_EVENT_HANDLER)cxfsnbd_socket_recv,
                      (void *)cxfsnbd_md_id);
#if 1
    cepoll_set_event(task_brd_default_get_cepoll(),
                      CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                      CEPOLL_WR_EVENT,
                      (const char *)"cxfsnbd_socket_send",
                      (CEPOLL_EVENT_HANDLER)cxfsnbd_socket_send,
                      (void *)cxfsnbd_md_id);
#endif
    if(EC_FALSE == cxfsnbd_device_open(cxfsnbd_md_id))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "open device failed\n");

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == cxfsnbd_device_set(cxfsnbd_md_id))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "set device failed\n");

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    /*cxfsnbd_device_listen(cxfsnbd_md_id);*/
    dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start: "
                                            "CXFSNBD module #%ld, launch device listen\n",
                                            cxfsnbd_md_id);
    cthread_new(CTHREAD_DETACHABLE | CTHREAD_SYSTEM_LEVEL,
                 (const char *)"cxfsnbd_device_listen",
                 (UINT32)cxfsnbd_device_listen,
                 (UINT32)0,/*core # (ignore)*/
                 (UINT32)1,/*para num*/
                 cxfsnbd_md_id
                 );

    /*cxfsnbd_device_close(cxfsnbd_md_id);*/

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfsnbd_end, cxfsnbd_md_id);

    dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start: "
                                            "start CXFSNBD module #%ld\n",
                                            cxfsnbd_md_id);

    return ( cxfsnbd_md_id );
}

/**
*
* end CXFSNBD module
*
**/
void cxfsnbd_end(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD *cxfsnbd_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cxfsnbd_end, cxfsnbd_md_id);

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);
    if(NULL_PTR == cxfsnbd_md)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_end: "
                                                "cxfsnbd_md_id = %ld not exist.\n",
                                                cxfsnbd_md_id);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cxfsnbd_md->usedcounter )
    {
        cxfsnbd_md->usedcounter --;
        return ;
    }

    if ( 0 == cxfsnbd_md->usedcounter )
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_end: "
                                                "cxfsnbd_md_id = %ld is not started.\n",
                                                cxfsnbd_md_id);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }

    clist_clean(CXFSNBD_MD_NBD_REQ_LIST(cxfsnbd_md), (CLIST_DATA_DATA_CLEANER)cxfsnbd_req_free);
    clist_clean(CXFSNBD_MD_NBD_RSP_LIST(cxfsnbd_md), (CLIST_DATA_DATA_CLEANER)cxfsnbd_rsp_free);

    if(NULL_PTR != CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md))
    {
        cxfsnbd_req_free(CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md));
        CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md))
    {
        cxfsnbd_rsp_free(CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md));
        CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md) = NULL_PTR;
    }

    if(ERR_FD != CXFSNBD_MD_C_SOCKFD(cxfsnbd_md))
    {
        cxfsnbd_device_disconnect(cxfsnbd_md_id);

        close(CXFSNBD_MD_C_SOCKFD(cxfsnbd_md));
        CXFSNBD_MD_C_SOCKFD(cxfsnbd_md) = ERR_FD;
    }

    if(ERR_FD != CXFSNBD_MD_D_SOCKFD(cxfsnbd_md))
    {
        cepoll_del_event(task_brd_default_get_cepoll(),
                         CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                         CEPOLL_RD_EVENT);

        cepoll_del_event(task_brd_default_get_cepoll(),
                         CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                         CEPOLL_WR_EVENT);

        close(CXFSNBD_MD_D_SOCKFD(cxfsnbd_md));
        CXFSNBD_MD_D_SOCKFD(cxfsnbd_md) = ERR_FD;
    }

    if(ERR_FD != CXFSNBD_MD_NBD_FD(cxfsnbd_md))
    {
        cxfsnbd_device_close(cxfsnbd_md_id);
    }

    if(NULL_PTR != CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md))
    {
        cstring_free(CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md));
        CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md) = NULL_PTR;
    }

    if(ERR_FD != CXFSNBD_MD_DEMO_FD(cxfsnbd_md))
    {
        c_file_close(CXFSNBD_MD_DEMO_FD(cxfsnbd_md));
        CXFSNBD_MD_DEMO_FD(cxfsnbd_md) = ERR_FD;
    }

    CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)  = 0;
    CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)  = 0;

    /* free module : */
    //cxfsnbd_free_module_static_mem(cxfsnbd_md_id);

    cxfsnbd_md->usedcounter = 0;

    cbc_md_free(MD_CXFSNBD, cxfsnbd_md_id);

    dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_end: "
                                            "stop CXFSNBD module #%ld\n",
                                            cxfsnbd_md_id);

    return ;
}

CXFSNBD_REQ *cxfsnbd_req_new()
{
    CXFSNBD_REQ *cxfsnbd_req;

    alloc_static_mem(MM_CXFSNBD_REQ, &cxfsnbd_req, LOC_CXFSNBD_0003);
    if(NULL_PTR == cxfsnbd_req)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_req_new: "
                                                "new cxfsnbd_req failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsnbd_req_init(cxfsnbd_req))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_req_new: "
                                                "init cxfsnbd_req failed\n");
        free_static_mem(MM_CXFSNBD_REQ, cxfsnbd_req, LOC_CXFSNBD_0004);
        return (NULL_PTR);
    }

    return (cxfsnbd_req);
}

EC_BOOL cxfsnbd_req_init(CXFSNBD_REQ *cxfsnbd_req)
{
    if(NULL_PTR != cxfsnbd_req)
    {
        CXFSNBD_REQ_MAGIC(cxfsnbd_req)              = 0;
        CXFSNBD_REQ_TYPE(cxfsnbd_req)               = 0;
        CXFSNBD_REQ_SEQNO(cxfsnbd_req)              = 0;
        CXFSNBD_REQ_OFFSET(cxfsnbd_req)             = 0;
        CXFSNBD_REQ_LEN(cxfsnbd_req)                = 0;

        CXFSNBD_REQ_HEADER_POS(cxfsnbd_req)         = 0;
        CXFSNBD_REQ_DATA_POS(cxfsnbd_req)           = 0;
        CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req)          = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_req_clean(CXFSNBD_REQ *cxfsnbd_req)
{
    if(NULL_PTR != cxfsnbd_req)
    {
        CXFSNBD_REQ_MAGIC(cxfsnbd_req)              = 0;
        CXFSNBD_REQ_TYPE(cxfsnbd_req)               = 0;
        CXFSNBD_REQ_SEQNO(cxfsnbd_req)              = 0;
        CXFSNBD_REQ_OFFSET(cxfsnbd_req)             = 0;
        CXFSNBD_REQ_LEN(cxfsnbd_req)                = 0;

        CXFSNBD_REQ_HEADER_POS(cxfsnbd_req)         = 0;
        CXFSNBD_REQ_DATA_POS(cxfsnbd_req)           = 0;

        if(NULL_PTR != CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req))
        {
            safe_free(CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req), LOC_CXFSNBD_0005);
            CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req) = NULL_PTR;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_req_free(CXFSNBD_REQ *cxfsnbd_req)
{
    if(NULL_PTR != cxfsnbd_req)
    {
        cxfsnbd_req_clean(cxfsnbd_req);
        free_static_mem(MM_CXFSNBD_REQ, cxfsnbd_req, LOC_CXFSNBD_0006);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_req_encode(CXFSNBD_REQ *cxfsnbd_req)
{
    CXFSNBD_REQ_MAGIC(cxfsnbd_req)   = c_hton32(CXFSNBD_REQ_MAGIC(cxfsnbd_req));
    CXFSNBD_REQ_TYPE(cxfsnbd_req)    = c_hton32(CXFSNBD_REQ_TYPE(cxfsnbd_req));
    CXFSNBD_REQ_OFFSET(cxfsnbd_req)  = c_hton64(CXFSNBD_REQ_OFFSET(cxfsnbd_req));
    CXFSNBD_REQ_LEN(cxfsnbd_req)     = c_hton32(CXFSNBD_REQ_LEN(cxfsnbd_req));

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_req_decode(CXFSNBD_REQ *cxfsnbd_req)
{
    CXFSNBD_REQ_MAGIC(cxfsnbd_req)   = c_ntoh32(CXFSNBD_REQ_MAGIC(cxfsnbd_req));
    CXFSNBD_REQ_TYPE(cxfsnbd_req)    = c_ntoh32(CXFSNBD_REQ_TYPE(cxfsnbd_req));
    CXFSNBD_REQ_OFFSET(cxfsnbd_req)  = c_ntoh64(CXFSNBD_REQ_OFFSET(cxfsnbd_req));
    CXFSNBD_REQ_LEN(cxfsnbd_req)     = c_ntoh32(CXFSNBD_REQ_LEN(cxfsnbd_req));

    return (EC_TRUE);
}

void cxfsnbd_req_print(LOG *log, const CXFSNBD_REQ *cxfsnbd_req)
{
    if(NULL_PTR != cxfsnbd_req)
    {
        sys_log(log, "cxfsnbd_req_print: "
                     "req %p: "
                     "magic %u, type %#x, seqno %#lx, offset %ld, len %u, "
                     "(pos %u, data %p)\n",
                     cxfsnbd_req,
                     CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                     CXFSNBD_REQ_TYPE(cxfsnbd_req),
                     CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                     CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                     CXFSNBD_REQ_LEN(cxfsnbd_req),
                     CXFSNBD_REQ_DATA_POS(cxfsnbd_req),
                     CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req));
    }
    return;
}

CXFSNBD_RSP *cxfsnbd_rsp_new()
{
    CXFSNBD_RSP *cxfsnbd_rsp;

    alloc_static_mem(MM_CXFSNBD_RSP, &cxfsnbd_rsp, LOC_CXFSNBD_0007);
    if(NULL_PTR == cxfsnbd_rsp)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_rsp_new: "
                                                "new cxfsnbd_rsp failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsnbd_rsp_init(cxfsnbd_rsp))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_rsp_new: "
                                                "init cxfsnbd_rsp failed\n");
        free_static_mem(MM_CXFSNBD_RSP, cxfsnbd_rsp, LOC_CXFSNBD_0008);
        return (NULL_PTR);
    }

    return (cxfsnbd_rsp);
}

EC_BOOL cxfsnbd_rsp_init(CXFSNBD_RSP *cxfsnbd_rsp)
{
    if(NULL_PTR != cxfsnbd_rsp)
    {
        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)              = 0;
        CXFSNBD_RSP_STATUS(cxfsnbd_rsp)             = 0;
        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp)              = 0;

        CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp)         = 0;
        CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp)           = 0;
        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp)           = 0;
        CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp)          = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_rsp_clean(CXFSNBD_RSP *cxfsnbd_rsp)
{
    if(NULL_PTR != cxfsnbd_rsp)
    {
        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)              = 0;
        CXFSNBD_RSP_STATUS(cxfsnbd_rsp)             = 0;
        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp)              = 0;

        CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp)         = 0;
        CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp)           = 0;
        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp)           = 0;

        if(NULL_PTR != CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp))
        {
            safe_free(CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp), LOC_CXFSNBD_0009);
            CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp) = NULL_PTR;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_rsp_free(CXFSNBD_RSP *cxfsnbd_rsp)
{
    if(NULL_PTR != cxfsnbd_rsp)
    {
        cxfsnbd_rsp_clean(cxfsnbd_rsp);
        free_static_mem(MM_CXFSNBD_RSP, cxfsnbd_rsp, LOC_CXFSNBD_0010);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_rsp_encode(CXFSNBD_RSP *cxfsnbd_rsp)
{
    CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)  = c_hton32(CXFSNBD_RSP_MAGIC(cxfsnbd_rsp));
    CXFSNBD_RSP_STATUS(cxfsnbd_rsp) = c_hton32(CXFSNBD_RSP_STATUS(cxfsnbd_rsp));

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_rsp_decode(CXFSNBD_RSP *cxfsnbd_rsp)
{
    CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)  = c_ntoh32(CXFSNBD_RSP_MAGIC(cxfsnbd_rsp));
    CXFSNBD_RSP_STATUS(cxfsnbd_rsp) = c_ntoh32(CXFSNBD_RSP_STATUS(cxfsnbd_rsp));

    return (EC_TRUE);
}

void cxfsnbd_rsp_print(LOG *log, const CXFSNBD_RSP *cxfsnbd_rsp)
{
    if(NULL_PTR != cxfsnbd_rsp)
    {
        sys_log(log, "cxfsnbd_rsp_print: "
                     "rsp %p: "
                     "magic %u, status %#x, seqno %#lx, "
                     "(len %u, data %p)\n",
                     cxfsnbd_rsp,
                     CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                     CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                     CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                     CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp),
                     CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp));
    }
    return;
}

STATIC_CAST const char *__cxfsnbd_req_type_str(const uint32_t type)
{
    switch (type)
    {
        case CXFSNBD_CMD_READ:              return ((const char *)"NBD_CMD_READ");
        case CXFSNBD_CMD_WRITE:             return ((const char *)"NBD_CMD_WRITE");
        case CXFSNBD_CMD_DISC:              return ((const char *)"NBD_CMD_DISC");
        case CXFSNBD_CMD_FLUSH:             return ((const char *)"NBD_CMD_FLUSH");
        case CXFSNBD_CMD_TRIM:              return ((const char *)"NBD_CMD_TRIM");
        default:                            break;
    }
    return ((const char *)"UNKNOWN");
}

STATIC_CAST const CXFSNBD_CB *__cxfsnbd_req_cb_fetch(const uint32_t type)
{
    uint32_t     cxfsnbd_req_cb_num;
    uint32_t     cxfsnbd_req_cb_idx;

    cxfsnbd_req_cb_num = sizeof(g_cxfsnbd_cb_list)/sizeof(g_cxfsnbd_cb_list[0]);
    for(cxfsnbd_req_cb_idx = 0; cxfsnbd_req_cb_idx < cxfsnbd_req_cb_num; cxfsnbd_req_cb_idx ++)
    {
        const CXFSNBD_CB      *cxfsnbd_cb;

        cxfsnbd_cb = &(g_cxfsnbd_cb_list[ cxfsnbd_req_cb_idx ]);
        if(CXFSNBD_CB_TYPE(cxfsnbd_cb) == type)
        {
            return (cxfsnbd_cb);
        }
    }

    return (NULL_PTR);
}

EC_BOOL cxfsnbd_push_req(const UINT32 cxfsnbd_md_id, CXFSNBD_REQ *cxfsnbd_req)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_push_req: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    clist_push_back(CXFSNBD_MD_NBD_REQ_LIST(cxfsnbd_md), (void *)cxfsnbd_req);

    dbg_log(SEC_0199_CXFSNBD, 6)(LOGSTDOUT, "[DEBUG] cxfsnbd_push_req: "
                "push req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d) "
                "(header pos %u, data pos %u)\n",
                cxfsnbd_req,
                CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                CXFSNBD_REQ_LEN(cxfsnbd_req),
                CXFSNBD_REQ_HEADER_POS(cxfsnbd_req),
                CXFSNBD_REQ_DATA_POS(cxfsnbd_req));

    return (EC_TRUE);
}

CXFSNBD_REQ *cxfsnbd_pop_req(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_REQ *cxfsnbd_req;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_pop_req: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    cxfsnbd_req = clist_pop_front(CXFSNBD_MD_NBD_REQ_LIST(cxfsnbd_md));

    if(NULL_PTR != cxfsnbd_req)
    {
        dbg_log(SEC_0199_CXFSNBD, 6)(LOGSTDOUT, "[DEBUG] cxfsnbd_pop_req: "
                    "pop req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d) "
                    "(header pos %u, data pos %u)\n",
                    cxfsnbd_req,
                    CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                    __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                    CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                    CXFSNBD_REQ_LEN(cxfsnbd_req),
                    CXFSNBD_REQ_HEADER_POS(cxfsnbd_req),
                    CXFSNBD_REQ_DATA_POS(cxfsnbd_req));
    }

    return (cxfsnbd_req);
}

EC_BOOL cxfsnbd_push_rsp(const UINT32 cxfsnbd_md_id, CXFSNBD_RSP *cxfsnbd_rsp)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_push_rsp: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    clist_push_back(CXFSNBD_MD_NBD_RSP_LIST(cxfsnbd_md), (void *)cxfsnbd_rsp);

    dbg_log(SEC_0199_CXFSNBD, 6)(LOGSTDOUT, "[DEBUG] cxfsnbd_push_rsp: "
                    "push rsp %p (magic %u, status %#x, seqno %#lx, len %u) "
                    "(header pos %u, data pos %u)\n",
                    cxfsnbd_rsp,
                    CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                    CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                    CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                    CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp),
                    CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp),
                    CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp));

    return (EC_TRUE);
}

CXFSNBD_RSP *cxfsnbd_pop_rsp(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_RSP *cxfsnbd_rsp;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_pop_rsp: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    cxfsnbd_rsp = clist_pop_front(CXFSNBD_MD_NBD_RSP_LIST(cxfsnbd_md));

    if(NULL_PTR != cxfsnbd_rsp)
    {
        dbg_log(SEC_0199_CXFSNBD, 6)(LOGSTDOUT, "[DEBUG] cxfsnbd_pop_rsp: "
                        "pop rsp %p (magic %u, status %#x, seqno %#lx, len %u) "
                        "(header pos %u, data pos %u)\n",
                        cxfsnbd_rsp,
                        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                        CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp),
                        CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp));
    }

    return (cxfsnbd_rsp);
}

EC_BOOL cxfsnbd_recv_req(const UINT32 cxfsnbd_md_id, CXFSNBD_REQ *cxfsnbd_req)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_recv_req: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    /*recv header*/
    if(CXFSNBD_REQ_HEADER_SIZE > CXFSNBD_REQ_HEADER_POS(cxfsnbd_req))
    {
        if(EC_FALSE == c_socket_recv(CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                                        (uint8_t *)cxfsnbd_req,
                                        CXFSNBD_REQ_HEADER_SIZE,
                                        &CXFSNBD_REQ_HEADER_POS(cxfsnbd_req)))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_recv_req: "
                                                    "recv req header failed, "
                                                    "pos %u, expected header size %u\n",
                                                    CXFSNBD_REQ_HEADER_POS(cxfsnbd_req),
                                                    CXFSNBD_REQ_HEADER_SIZE);

            return (EC_FALSE);
        }

        if(CXFSNBD_REQ_HEADER_SIZE > CXFSNBD_REQ_HEADER_POS(cxfsnbd_req))
        {
            dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_recv_req: "
                                                    "recv req header incompleted, "
                                                    "pos %u, expected header size %u\n",
                                                    CXFSNBD_REQ_HEADER_POS(cxfsnbd_req),
                                                    CXFSNBD_REQ_HEADER_SIZE);

            return (EC_AGAIN);
        }

        cxfsnbd_req_decode(cxfsnbd_req);

        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_recv_req: "
                    "recv req header "
                    "(magic %#x, type %s, seqno %#lx, offset %ld, len %d) done\n",
                    CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                    __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                    CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                    CXFSNBD_REQ_LEN(cxfsnbd_req));
    }

    /*recv data*/
    if(CXFSNBD_CMD_WRITE == CXFSNBD_REQ_TYPE(cxfsnbd_req)
    && 0 < CXFSNBD_REQ_LEN(cxfsnbd_req)
    && CXFSNBD_REQ_DATA_POS(cxfsnbd_req) < CXFSNBD_REQ_LEN(cxfsnbd_req))
    {
        if(NULL_PTR == CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req))
        {
            uint8_t     *data;

            data = safe_malloc(CXFSNBD_REQ_LEN(cxfsnbd_req), LOC_CXFSNBD_0011);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_recv_req: "
                                                        "alloc %u bytes failed\n",
                                                        CXFSNBD_REQ_LEN(cxfsnbd_req));

                return (EC_FALSE);
            }

            CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req)   = data;
        }

        if(EC_FALSE == c_socket_recv(CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                                     CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req),
                                     CXFSNBD_REQ_LEN(cxfsnbd_req),
                                     &CXFSNBD_REQ_DATA_POS(cxfsnbd_req)))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_recv_req: "
                                                    "read dsock %d len %u failed\n",
                                                    CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                                                    CXFSNBD_REQ_LEN(cxfsnbd_req));
            return (EC_FALSE);
        }

        if(CXFSNBD_REQ_DATA_POS(cxfsnbd_req) < CXFSNBD_REQ_LEN(cxfsnbd_req))
        {
            dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_recv_req: "
                                                    "recv req data incompleted, "
                                                    "pos %u, expected len %u\n",
                                                    CXFSNBD_REQ_DATA_POS(cxfsnbd_req),
                                                    CXFSNBD_REQ_LEN(cxfsnbd_req));

            return (EC_AGAIN);
        }


        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_recv_req: "
                                                "read dsock %d len %u done\n",
                                                CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                                                CXFSNBD_REQ_LEN(cxfsnbd_req));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_send_rsp(const UINT32 cxfsnbd_md_id, CXFSNBD_RSP *cxfsnbd_rsp)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_send_rsp: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    /*send header*/
    if(CXFSNBD_RSP_HEADER_SIZE > CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp))
    {
        cxfsnbd_rsp_encode(cxfsnbd_rsp);

        if(EC_FALSE == c_socket_send(CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                                        (uint8_t *)cxfsnbd_rsp,
                                        CXFSNBD_RSP_HEADER_SIZE,
                                        &CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp)))
        {
            /*restore*/
            cxfsnbd_rsp_decode(cxfsnbd_rsp);

            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_send_rsp: "
                                                    "send rsp header failed, "
                                                    "pos %u, expected header size %u\n",
                                                    CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp),
                                                    CXFSNBD_RSP_HEADER_SIZE);

            return (EC_FALSE);
        }

        /*restore*/
        cxfsnbd_rsp_decode(cxfsnbd_rsp);

        if(CXFSNBD_RSP_HEADER_SIZE > CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp))
        {
            dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_send_rsp: "
                                                    "send rsp header incompleted, "
                                                    "pos %u, expected header size %u\n",
                                                    CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp),
                                                    CXFSNBD_RSP_HEADER_SIZE);

            return (EC_AGAIN);
        }

        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_send_rsp: "
                                                "send rsp header "
                                                "(magic %#x, status %#x, seqno %#lx) done\n",
                                                CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                                                CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                                                CXFSNBD_RSP_SEQNO(cxfsnbd_rsp));
    }

    /*send data*/
    if(0 < CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp)
    && CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp) < CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp)
    && NULL_PTR != CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp))
    {
        if(EC_FALSE == c_socket_send(CXFSNBD_MD_D_SOCKFD(cxfsnbd_md),
                                    CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp),
                                    CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp),
                                    &CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp)))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_send_rsp: "
                                                    "send rsp data len %u failed\n",
                                                    CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

            return (EC_FALSE);
        }

        if(CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp) < CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp))
        {
            dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_send_rsp: "
                                                    "send rsp data incompleted, "
                                                    "pos %u, expected len %u\n",
                                                    CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp),
                                                    CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

            return (EC_AGAIN);
        }

        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_send_rsp: "
                                                "send rsp data len %u done\n",
                                                CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_handle_req_read(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req)
{
    CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_RSP *cxfsnbd_rsp;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_handle_req_read: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    cxfsnbd_rsp = cxfsnbd_rsp_new();
    if(NULL_PTR == cxfsnbd_rsp)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req_read: "
                                                "new cxfsnbd_rsp failed\n");
        return (EC_FALSE);
    }

    if(0 < CXFSNBD_REQ_LEN(cxfsnbd_req))
    {
        uint8_t     *data;
        UINT32       offset;
        UINT32       rsize;

        data = safe_malloc(CXFSNBD_REQ_LEN(cxfsnbd_req), LOC_CXFSNBD_0012);
        if(NULL_PTR == data)
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req_read: "
                                                    "alloc %u bytes failed\n",
                                                    CXFSNBD_REQ_LEN(cxfsnbd_req));

            cxfsnbd_rsp_free(cxfsnbd_rsp);
            return (EC_FALSE);
        }

        offset = CXFSNBD_REQ_OFFSET(cxfsnbd_req);
        rsize  = CXFSNBD_REQ_LEN(cxfsnbd_req);

        if(EC_FALSE == c_file_read(CXFSNBD_MD_DEMO_FD(cxfsnbd_md), &offset, rsize, data))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req_read: "
                                                    "read (fd %d, offset %u, len %u) failed\n",
                                                    CXFSNBD_MD_DEMO_FD(cxfsnbd_md),
                                                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                                                    CXFSNBD_REQ_LEN(cxfsnbd_req));

            safe_free(data, LOC_CXFSNBD_0013);
            cxfsnbd_rsp_free(cxfsnbd_rsp);
            return (EC_FALSE);
        }

        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_handle_req_read: "
                                                "read (fd %d, offset %u, len %u) done\n",
                                                CXFSNBD_MD_DEMO_FD(cxfsnbd_md),
                                                CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                                                CXFSNBD_REQ_LEN(cxfsnbd_req));

        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp)   = CXFSNBD_REQ_LEN(cxfsnbd_req);
        CXFSNBD_RSP_DATA_ZONE(cxfsnbd_rsp)  = data;
    }

    CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)  = CXFSNBD_RSP_MAGIC_NUM;
    CXFSNBD_RSP_STATUS(cxfsnbd_rsp) = 0;
    CXFSNBD_RSP_SEQNO(cxfsnbd_rsp)  = CXFSNBD_REQ_SEQNO(cxfsnbd_req);

    cxfsnbd_push_rsp(cxfsnbd_md_id, cxfsnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_handle_req_write(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req)
{
    CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_RSP *cxfsnbd_rsp;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_handle_req_write: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    cxfsnbd_rsp = cxfsnbd_rsp_new();
    if(NULL_PTR == cxfsnbd_rsp)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req_write: "
                                                "new cxfsnbd_rsp failed\n");
        return (EC_FALSE);
    }

    if(0 < CXFSNBD_REQ_LEN(cxfsnbd_req)
    && NULL_PTR != CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req))
    {
        uint8_t     *data;
        UINT32       offset;
        UINT32       wsize;

        data   = CXFSNBD_REQ_DATA_ZONE(cxfsnbd_req);
        offset = CXFSNBD_REQ_OFFSET(cxfsnbd_req);
        wsize  = CXFSNBD_REQ_LEN(cxfsnbd_req);

        if(EC_FALSE == c_file_write(CXFSNBD_MD_DEMO_FD(cxfsnbd_md), &offset, wsize, data))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req_write: "
                                                    "write (fd %d, offset %u, len %u) failed\n",
                                                    CXFSNBD_MD_DEMO_FD(cxfsnbd_md),
                                                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                                                    CXFSNBD_REQ_LEN(cxfsnbd_req));

            cxfsnbd_rsp_free(cxfsnbd_rsp);
            return (EC_FALSE);
        }

        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_handle_req_write: "
                                                "write (fd %d, offset %u, len %u) done\n",
                                                CXFSNBD_MD_DEMO_FD(cxfsnbd_md),
                                                CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                                                CXFSNBD_REQ_LEN(cxfsnbd_req));
    }

    CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)  = CXFSNBD_RSP_MAGIC_NUM;
    CXFSNBD_RSP_STATUS(cxfsnbd_rsp) = 0;
    CXFSNBD_RSP_SEQNO(cxfsnbd_rsp)  = CXFSNBD_REQ_SEQNO(cxfsnbd_req);;

    cxfsnbd_push_rsp(cxfsnbd_md_id, cxfsnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_handle_req_disc(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req)
{
#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_handle_req_flush: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    return cxfsnbd_device_disconnect(cxfsnbd_md_id);
}

EC_BOOL cxfsnbd_handle_req_flush(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req)
{
    //CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_RSP *cxfsnbd_rsp;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_handle_req_flush: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    //cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    cxfsnbd_rsp = cxfsnbd_rsp_new();
    if(NULL_PTR == cxfsnbd_rsp)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req_flush: "
                                                "new cxfsnbd_rsp failed\n");
        return (EC_FALSE);
    }

    CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)  = CXFSNBD_RSP_MAGIC_NUM;
    CXFSNBD_RSP_STATUS(cxfsnbd_rsp) = 0;
    CXFSNBD_RSP_SEQNO(cxfsnbd_rsp)  = CXFSNBD_REQ_SEQNO(cxfsnbd_req);;

    cxfsnbd_push_rsp(cxfsnbd_md_id, cxfsnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_handle_req_trim(const UINT32 cxfsnbd_md_id, const CXFSNBD_REQ *cxfsnbd_req)
{
    //CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_RSP *cxfsnbd_rsp;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_handle_req_trim: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    //cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    cxfsnbd_rsp = cxfsnbd_rsp_new();
    if(NULL_PTR == cxfsnbd_rsp)
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req_trim: "
                                                "new cxfsnbd_rsp failed\n");
        return (EC_FALSE);
    }

    CXFSNBD_RSP_MAGIC(cxfsnbd_rsp)  = CXFSNBD_RSP_MAGIC_NUM;
    CXFSNBD_RSP_STATUS(cxfsnbd_rsp) = 0;
    CXFSNBD_RSP_SEQNO(cxfsnbd_rsp)  = CXFSNBD_REQ_SEQNO(cxfsnbd_req);;

    cxfsnbd_push_rsp(cxfsnbd_md_id, cxfsnbd_rsp);

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_handle_req(const UINT32 cxfsnbd_md_id)
{
    //CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_REQ       *cxfsnbd_req;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_handle_req: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    //cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    while(NULL_PTR != (cxfsnbd_req = cxfsnbd_pop_req(cxfsnbd_md_id)))
    {
        const CXFSNBD_CB  *cxfsnbd_cb;

        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_handle_req: "
                    " req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d) "
                    "(header pos %u, data pos %u)\n",
                    cxfsnbd_req,
                    CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                    __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                    CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                    CXFSNBD_REQ_LEN(cxfsnbd_req),
                    CXFSNBD_REQ_HEADER_POS(cxfsnbd_req),
                    CXFSNBD_REQ_DATA_POS(cxfsnbd_req));

        ASSERT(CXFSNBD_REQ_HEADER_POS(cxfsnbd_req) == CXFSNBD_REQ_HEADER_SIZE);
        ASSERT(CXFSNBD_CMD_WRITE != CXFSNBD_REQ_TYPE(cxfsnbd_req)
            || CXFSNBD_REQ_DATA_POS(cxfsnbd_req) == CXFSNBD_REQ_LEN(cxfsnbd_req));

        cxfsnbd_cb = __cxfsnbd_req_cb_fetch(CXFSNBD_REQ_TYPE(cxfsnbd_req));
        if(NULL_PTR == cxfsnbd_cb)
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req: "
                        "handle req (magic %#x, type %s, seqno %#lx, offset %ld, len %d)"
                        " => invalid type\n",
                        CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                        __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                        CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                        CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                        CXFSNBD_REQ_LEN(cxfsnbd_req));


            cxfsnbd_req_free(cxfsnbd_req);
            return (EC_FALSE);
        }

        if(EC_FALSE == CXFSNBD_CB_HANDLER(cxfsnbd_cb)(cxfsnbd_md_id, cxfsnbd_req))
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_handle_req: "
                        "handle req (magic %#x, type %s, seqno %#lx, offset %ld, len %d) failed\n",
                        CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                        __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                        CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                        CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                        CXFSNBD_REQ_LEN(cxfsnbd_req));

            cxfsnbd_req_free(cxfsnbd_req);
            return (EC_FALSE);
        }

        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_handle_req: "
                    "handle req (magic %#x, type %s, seqno %#lx, offset %ld, len %d) done\n",
                    CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                    __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                    CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                    CXFSNBD_REQ_LEN(cxfsnbd_req));

        cxfsnbd_req_free(cxfsnbd_req);
        /*continue*/
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_device_open(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_device_open: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    CXFSNBD_MD_NBD_FD(cxfsnbd_md) = c_file_open((char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md), O_RDWR, 0666);
    if(ERR_FD == CXFSNBD_MD_NBD_FD(cxfsnbd_md))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_open: "
                                                "open nbd device '%s' failed\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md));
        return (EC_FALSE);
    }

    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_open: "
                                            "open nbd device '%s', fd %d\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md));

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_device_close(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_device_close: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(ERR_FD != CXFSNBD_MD_NBD_FD(cxfsnbd_md))
    {
        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_close: "
                                                "close nbd device '%s', fd %d\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md));

        c_file_close(CXFSNBD_MD_NBD_FD(cxfsnbd_md));
        CXFSNBD_MD_NBD_FD(cxfsnbd_md) = ERR_FD;
        return (EC_TRUE);
    }

    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_close: "
                                            "nbd device '%s' not open\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md));
    return (EC_TRUE);
}

EC_BOOL cxfsnbd_device_set(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_device_set: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(ERR_FD == CXFSNBD_MD_NBD_FD(cxfsnbd_md))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_set: "
                                                "nbd device '%s' not open yet\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md));
        return (EC_FALSE);
    }

    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_CLEAR_SOCK))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_set: "
                                                "nbd device '%s', fd %d, ioctl %s failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                "CXFSNBD_CLEAR_SOCK",
                                                errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_set: "
                                            "nbd device '%s', fd %d, clear sock\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md));

    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_SET_SOCK, CXFSNBD_MD_C_SOCKFD(cxfsnbd_md)))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_set: "
                                                "nbd device '%s', fd %d, ioctl %s (%d) failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                "CXFSNBD_SET_SOCK",
                                                CXFSNBD_MD_C_SOCKFD(cxfsnbd_md),
                                                errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_set: "
                                            "nbd device '%s', fd %d, set sock %d\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                            CXFSNBD_MD_C_SOCKFD(cxfsnbd_md));


    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_SET_BLKSIZE, CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md)))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_set: "
                                                "nbd device '%s', fd %d, ioctl %s (%ld) failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                "CXFSNBD_SET_BLKSIZE",
                                                CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md),
                                                errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_set: "
                                            "nbd device '%s', fd %d, set block size %ld\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md));

    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_SET_SIZE, CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md)))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_set: "
                                                "nbd device '%s', fd %d, ioctl %s (%ld) failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                "CXFSNBD_SET_SIZE",
                                                CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md),
                                                errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_set: "
                                            "nbd device '%s', fd %d, set device size %ld\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md));

    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_SET_FLAGS, CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_set: "
                                                "nbd device '%s', fd %d, ioctl %s (%#lx) failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                "CXFSNBD_SET_FLAGS",
                                                CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md),
                                                errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_set: "
                                            "nbd device '%s', fd %d, set flags %#lx\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md));

    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_SET_TIMEOUT, CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_set: "
                                                "nbd device '%s', fd %d, ioctl %s (%#lx) failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                "CXFSNBD_SET_TIMEOUT",
                                                CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md),
                                                errno, strerror(errno));
        return (EC_FALSE);
    }
    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_set: "
                                            "nbd device '%s', fd %d, set timeout %ld\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md));

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_device_listen(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_device_listen: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    /*block*/
    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_DO_IT))
    {
        int err;

        err = errno;
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_listen: "
                                                "nbd device '%s', fd %d, listen failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                errno, strerror(errno));

        if(EBUSY == err)
        {
            cxfsnbd_device_disconnect(cxfsnbd_md_id);
        }

        /*terminate thread and terminate cxfsnbd module*/
        cxfsnbd_end(cxfsnbd_md_id);

        return (EC_FALSE);
    }

    dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_listen: "
                                            "nbd device '%s', fd %d, listen terminated\n",
                                            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                            CXFSNBD_MD_NBD_FD(cxfsnbd_md));

    /*terminate thread and terminate cxfsnbd module*/
    cxfsnbd_end(cxfsnbd_md_id);

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_device_disconnect(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;

    EC_BOOL      ret;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_device_disconnect: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    ret = EC_TRUE;

    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_CLEAR_SOCK))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_disconnect: "
                                                "nbd device '%s', fd %d, clear sock failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                errno, strerror(errno));
        ret = EC_FALSE;
    }
    else
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_disconnect: "
                                                "nbd device '%s', fd %d, clear sock done\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md));
    }

    if(0 > ioctl(CXFSNBD_MD_NBD_FD(cxfsnbd_md), CXFSNBD_DISCONNECT))
    {
        dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_device_disconnect: "
                                                "nbd device '%s', fd %d, disconnect failed, "
                                                "errno %d, errstr %s\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md),
                                                errno, strerror(errno));
        ret = EC_FALSE;
    }
    else
    {
        dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_device_disconnect: "
                                                "nbd device '%s', fd %d, disconnect done\n",
                                                (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
                                                CXFSNBD_MD_NBD_FD(cxfsnbd_md));
    }
    return (ret);
}

EC_BOOL cxfsnbd_socket_recv(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_socket_recv: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(NULL_PTR != CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md))
    {
        CXFSNBD_REQ *cxfsnbd_req;
        EC_BOOL      ret;

        cxfsnbd_req = CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md);
        CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md) = NULL_PTR;

        ret = cxfsnbd_recv_req(cxfsnbd_md_id, cxfsnbd_req);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_socket_recv: "
                                                    "recv ongoing req failed\n");

            cxfsnbd_req_free(cxfsnbd_req);

            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_recv: "
                                                    "recv ongoing req again\n");

            CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md) = cxfsnbd_req;

            return cxfsnbd_handle_req(cxfsnbd_md_id);
        }

        cxfsnbd_push_req(cxfsnbd_md_id, cxfsnbd_req);

        dbg_log(SEC_0199_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_recv: "
                    "recv ongoing req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d)\n",
                    cxfsnbd_req,
                    CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                    __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                    CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                    CXFSNBD_REQ_LEN(cxfsnbd_req));
    }

    for(;;)
    {
        CXFSNBD_REQ *cxfsnbd_req;
        EC_BOOL      ret;

        cxfsnbd_req = cxfsnbd_req_new();
        if(NULL_PTR == cxfsnbd_req)
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_socket_recv: "
                                                    "new cxfsnbd_req failed\n");
            return (EC_FALSE);
        }

        ret = cxfsnbd_recv_req(cxfsnbd_md_id, cxfsnbd_req);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_socket_recv: "
                                                    "recv req failed\n");

            cxfsnbd_req_free(cxfsnbd_req);

            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            /*recv nothing*/
            if(0 == CXFSNBD_REQ_HEADER_POS(cxfsnbd_req))
            {
                dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_recv: "
                                                        "recv req no more\n");

                cxfsnbd_req_free(cxfsnbd_req);

                return cxfsnbd_handle_req(cxfsnbd_md_id);
            }

            /*recv partial*/
            dbg_log(SEC_0199_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_recv: "
                                                    "recv req again\n");

            CXFSNBD_MD_NBD_REQ_ONGOING(cxfsnbd_md) = cxfsnbd_req;

            return cxfsnbd_handle_req(cxfsnbd_md_id);
        }

        cxfsnbd_push_req(cxfsnbd_md_id, cxfsnbd_req);

        dbg_log(SEC_0199_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_recv: "
                    "recv req %p (magic %#x, type %s, seqno %#lx, offset %ld, len %d)\n",
                    cxfsnbd_req,
                    CXFSNBD_REQ_MAGIC(cxfsnbd_req),
                    __cxfsnbd_req_type_str(CXFSNBD_REQ_TYPE(cxfsnbd_req)),
                    CXFSNBD_REQ_SEQNO(cxfsnbd_req),
                    CXFSNBD_REQ_OFFSET(cxfsnbd_req),
                    CXFSNBD_REQ_LEN(cxfsnbd_req));
    }

    /*should never reach here*/
    dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_socket_recv: "
                                            "should never reach here\n");
    return (EC_FALSE);
}

EC_BOOL cxfsnbd_socket_send(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;
    CXFSNBD_RSP *cxfsnbd_rsp;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_socket_send: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(NULL_PTR != CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md))
    {
        EC_BOOL      ret;

        cxfsnbd_rsp = CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md);

        ret = cxfsnbd_send_rsp(cxfsnbd_md_id, cxfsnbd_rsp);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_socket_send: "
                        "send ongoing rsp (magic %u, status %#x, seqno %#lx, len %u) failed\n",
                        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                        CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

            CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md) = NULL_PTR;
            cxfsnbd_rsp_free(cxfsnbd_rsp);

            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            dbg_log(SEC_0199_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_send: "
                        "send ongoing rsp (magic %u, status %#x, seqno %#lx, len %u) again\n",
                        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                        CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

            return (EC_TRUE);
        }

        dbg_log(SEC_0199_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_send: "
                        "send ongoing rsp (magic %u, status %#x, seqno %#lx, len %u) done\n",
                        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                        CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

        CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md) = NULL_PTR;
        cxfsnbd_rsp_free(cxfsnbd_rsp);
    }

    while(NULL_PTR != (cxfsnbd_rsp = cxfsnbd_pop_rsp(cxfsnbd_md_id)))
    {
        EC_BOOL      ret;

        if(CXFSNBD_RSP_HEADER_POS(cxfsnbd_rsp) == CXFSNBD_RSP_HEADER_SIZE
        && CXFSNBD_RSP_DATA_POS(cxfsnbd_rsp) == CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp))
        {
            /*never reach here*/
            cxfsnbd_rsp_free(cxfsnbd_rsp);
            continue;
        }

        ret = cxfsnbd_send_rsp(cxfsnbd_md_id, cxfsnbd_rsp);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0199_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_socket_send: "
                        "send rsp (magic %u, status %#x, seqno %#lx, len %u) failed\n",
                        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                        CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

            cxfsnbd_rsp_free(cxfsnbd_rsp);
            return (EC_FALSE);
        }

        if(EC_AGAIN == ret)
        {
            CXFSNBD_MD_NBD_RSP_ONGOING(cxfsnbd_md) = cxfsnbd_rsp;

            dbg_log(SEC_0199_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_send: "
                        "send rsp (magic %u, status %#x, seqno %#lx, len %u) again\n",
                        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                        CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

            return (EC_TRUE);
        }

        dbg_log(SEC_0199_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_socket_send: "
                        "send rsp (magic %u, status %#x, seqno %#lx, len %u) done\n",
                        CXFSNBD_RSP_MAGIC(cxfsnbd_rsp),
                        CXFSNBD_RSP_STATUS(cxfsnbd_rsp),
                        CXFSNBD_RSP_SEQNO(cxfsnbd_rsp),
                        CXFSNBD_RSP_DATA_LEN(cxfsnbd_rsp));

        cxfsnbd_rsp_free(cxfsnbd_rsp);

        /*continue*/
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

