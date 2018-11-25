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

#include "cbytes.h"
#include "cdc.h"

#include "caio.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDC_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDC_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/


STATIC_CAST static EC_BOOL __cdc_file_read_aio(CDC_FILE_AIO *cdc_file_aio);
STATIC_CAST static EC_BOOL __cdc_file_write_aio(CDC_FILE_AIO *cdc_file_aio);

/**
*
* start CDC module
*
**/
CDC_MD *cdc_start(const int fd, const UINT32 offset, const UINT32 rdisk_size/*in GB*/)
{
    CDC_MD  *cdc_md;

    UINT32   f_s_offset;
    UINT32   f_e_offset;
    UINT32   f_size;

    init_static_mem();

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: no fd\n");
        return (NULL_PTR);
    }

    f_s_offset  = offset;
    f_e_offset  = f_s_offset + (rdisk_size << 30);/*1GB = 2^30 B*/

    /*adjust f_e_offset*/
    if(EC_FALSE == c_file_size(fd, &f_size))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: file size of fd %d failed\n", fd);
        return (NULL_PTR);
    }

    if(f_s_offset >= f_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: f_s_offset %ld >= f_size %ld of fd %d\n",
                                            f_s_offset, f_size, fd);
        return (NULL_PTR);
    }

    if(f_e_offset > f_size)
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_start: f_e_offset: %ld => %ld of fd %d\n",
                                            f_e_offset, f_size, fd);
        f_e_offset = f_size;
    }

    /* create a new module node */
    cdc_md = safe_malloc(sizeof(CDC_MD), LOC_CDC_0001);
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: start cdc module failed\n");
        return (NULL_PTR);
    }

    /* initialize new one CDC module */
    CDC_MD_FD(cdc_md)                   = fd;
    CDC_MD_S_OFFSET(cdc_md)             = f_s_offset;
    CDC_MD_E_OFFSET(cdc_md)             = f_e_offset;
    CDC_MD_C_OFFSET(cdc_md)             = CDC_OFFSET_ERR;
    CDC_MD_DN(cdc_md)                   = NULL_PTR;
    CDC_MD_NP(cdc_md)                   = NULL_PTR;
    CDC_MD_CAIO_MD(cdc_md)              = NULL_PTR;

    CDC_MD_DN_FLUSHING_FLAG(cdc_md)     = BIT_FALSE;
    CDC_MD_DN_LOADING_FLAG(cdc_md)      = BIT_FALSE;
    CDC_MD_NP_FLUSHING_FLAG(cdc_md)     = BIT_FALSE;
    CDC_MD_NP_LOADING_FLAG(cdc_md)      = BIT_FALSE;

    CDC_MD_FLUSHING_FLAG(cdc_md)        = BIT_FALSE;
    CDC_MD_LOADING_FLAG(cdc_md)         = BIT_FALSE;

#if 0
    CDC_MD_CAIO_MD(cdc_md) = caio_start(CAIO_256K_MODEL);
    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: start caio module failed\n");
        safe_free(cdc_md, LOC_CDC_0002);
        return (NULL_PTR);
    }
#endif
    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_start: start cdc module %p\n", cdc_md);

    return (cdc_md);
}

/**
*
* end CDC module
*
**/
void cdc_end(CDC_MD *cdc_md)
{
    if(NULL_PTR != cdc_md)
    {
        cdc_flush_dn(cdc_md);
        cdc_flush_np(cdc_md);

        cdc_close_np(cdc_md);
        cdc_close_dn(cdc_md);

        CDC_MD_FLUSHING_FLAG(cdc_md)        = BIT_FALSE;
        CDC_MD_LOADING_FLAG(cdc_md)         = BIT_FALSE;

        CDC_MD_DN_FLUSHING_FLAG(cdc_md)     = BIT_FALSE;
        CDC_MD_DN_LOADING_FLAG(cdc_md)      = BIT_FALSE;

        CDC_MD_NP_FLUSHING_FLAG(cdc_md)     = BIT_FALSE;
        CDC_MD_NP_LOADING_FLAG(cdc_md)      = BIT_FALSE;

        CDC_MD_S_OFFSET(cdc_md)             = CDC_OFFSET_ERR;
        CDC_MD_E_OFFSET(cdc_md)             = CDC_OFFSET_ERR;
        CDC_MD_C_OFFSET(cdc_md)             = CDC_OFFSET_ERR;

        if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
        {
            caio_end(CDC_MD_CAIO_MD(cdc_md));
            CDC_MD_CAIO_MD(cdc_md) = NULL_PTR;
        }

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "cdc_end: stop cdc module %p\n", cdc_md);
        safe_free(cdc_md, LOC_CDC_0003);
    }

    return;
}

/**
*
* create CDC
*
**/
EC_BOOL cdc_create(CDC_MD *cdc_md)
{
    UINT32   f_s_offset;
    UINT32   f_e_offset;

    f_s_offset  = CDC_MD_S_OFFSET(cdc_md);
    f_e_offset  = CDC_MD_E_OFFSET(cdc_md);

    if(EC_FALSE == cdc_create_np(cdc_md, &f_s_offset, f_e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create: cdc module %p create np failed\n", cdc_md);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_create: after create np, f_s_offset = %ld\n", f_s_offset);

    if(EC_FALSE == cdc_create_dn(cdc_md, &f_s_offset, f_e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create: cdc module %p create dn failed\n", cdc_md);

        cdc_close_np(cdc_md);

        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_create: after create dn, f_s_offset = %ld\n", f_s_offset);

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_create: start cdc module %p\n", cdc_md);

    return (EC_TRUE);
}

/**
*
* load CDC
*
**/
EC_BOOL cdc_load(CDC_MD *cdc_md)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load: no cdc module\n");
        return (EC_FALSE);
    }

    CDC_MD_C_OFFSET(cdc_md) = CDC_MD_S_OFFSET(cdc_md);

    if(EC_FALSE == cdc_load_np(cdc_md, &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load: load np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load: load np done\n");

    if(EC_FALSE == cdc_load_dn(cdc_md, &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load: load dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load: load dn done\n");


    return (EC_TRUE);
}

EC_BOOL cdc_load_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_aio: no cdc module\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_aio: load is on-going\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != CDC_MD_CAIO_MD(cdc_md));

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        CDC_MD_C_OFFSET(cdc_md) = CDC_MD_S_OFFSET(cdc_md);

        if(EC_FALSE == cdc_load_np(cdc_md, &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_aio: load np failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_aio: load np done\n");

        if(EC_FALSE == cdc_load_dn(cdc_md, &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_aio: load dn failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_aio: load dn done\n");
    }
    else
    {
        CDC_MD_C_OFFSET(cdc_md) = CDC_MD_S_OFFSET(cdc_md);

        CDC_MD_LOADING_FLAG(cdc_md) = BIT_TRUE;

        if(EC_FALSE == cdc_load_np_aio(cdc_md, caio_cb))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_aio: load np failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_aio: load np done\n");
    }

    return (EC_TRUE);
}

/**
*
* flush CDC
*
**/
EC_BOOL cdc_flush(CDC_MD *cdc_md)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush: no cdc module\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdc_flush_np(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush: flush np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush: flush np done\n");

    if(EC_FALSE == cdc_flush_dn(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush: flush dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush: flush dn done\n");

    return (EC_TRUE);
}

EC_BOOL cdc_flush_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_aio: no cdc module\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_aio: flush is on-going\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != CDC_MD_CAIO_MD(cdc_md));

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdc_flush_np(cdc_md))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_aio: flush np failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_aio: flush np done\n");

        if(EC_FALSE == cdc_flush_dn(cdc_md))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_aio: flush dn failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_aio: flush dn done\n");
    }
    else
    {
        CDC_MD_C_OFFSET(cdc_md) = CDC_MD_S_OFFSET(cdc_md);

        if(EC_FALSE == cdc_flush_np_aio(cdc_md, caio_cb))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_aio: flush np failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_aio: flush np done\n");
    }

    return (EC_TRUE);
}

/**
*
* print CDC module
*
**/
void cdc_print(LOG *log, const CDC_MD *cdc_md)
{
    cdc_show_np(cdc_md, log);
    cdc_show_dn(cdc_md, log);

    return;
}
/*note: register eventfd and event handler to epoll READ event*/
int cdc_get_eventfd(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        return caio_get_eventfd(CDC_MD_CAIO_MD(cdc_md));
    }

    return (ERR_FD);
}

/*note: register eventfd and event handler to epoll READ event*/
EC_BOOL cdc_event_handler(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        return caio_event_handler(CDC_MD_CAIO_MD(cdc_md));
    }

    return (EC_TRUE);
}

/**
*
* process CDC
* 1, recycle deleted or retired space
* 2, process CAIO
*
**/
void cdc_process(CDC_MD *cdc_md)
{
    cdc_recycle(cdc_md, CDC_TRY_RECYCLE_MAX_NUM, NULL_PTR);

    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        caio_process(CDC_MD_CAIO_MD(cdc_md));
    }
    return;
}

/*for debug*/
EC_BOOL cdc_poll(CDC_MD *cdc_md)
{
    cdc_process(cdc_md);

    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        caio_poll(CDC_MD_CAIO_MD(cdc_md));
    }


    return (EC_TRUE);
}

/**
*
*  create name node
*
**/
EC_BOOL cdc_create_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP      *cdcnp;
    UINT32      page_max_num;
    UINT32      size;
    uint8_t     np_model;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: np already exist\n");
        return (EC_FALSE);
    }

    size = e_offset - (*s_offset);

    page_max_num = (size >> CDCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_create_np: "
                                        "range [%ld, %ld), page size %u => page num %ld\n",
                                        (*s_offset), e_offset, CDCPGB_PAGE_SIZE_NBYTES, page_max_num);

    if(CDCNP_PAGE_MAX_NUM < page_max_num)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: "
                                            "range [%ld, %ld), page size %u B => page num %ld overflow!\n",
                                            (*s_offset), e_offset, CDCPGB_PAGE_SIZE_NBYTES, page_max_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_model_search(size, &np_model))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: size %ld => no matched np_model\n",
                                            size);
        return (EC_FALSE);
    }

    cdcnp = cdcnp_create((uint32_t)0/*cdcnp_id*/, (uint8_t)np_model, page_max_num, s_offset, e_offset);
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: create np failed\n");
        return (EC_FALSE);
    }

    /*inherit from cdc module*/
    CDCNP_FD(cdcnp)      = CDC_MD_FD(cdc_md);
    CDCNP_CAIO_MD(cdcnp) = CDC_MD_CAIO_MD(cdc_md);

    CDC_MD_NP(cdc_md) = cdcnp;

    return (EC_TRUE);
}


/**
*
*  close name node
*
**/
EC_BOOL cdc_close_np(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        cdcnp_free(CDC_MD_NP(cdc_md));
        CDC_MD_NP(cdc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_load_np_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_load_np_aio_timeout: "
                                        "load np timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_NP_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        cdcnp_free(CDC_MD_NP(cdc_md));
        CDC_MD_NP(cdc_md) = NULL_PTR;
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_load_np_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_load_np_aio_terminate: "
                                        "load np terminated\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_NP_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        cdcnp_free(CDC_MD_NP(cdc_md));
        CDC_MD_NP(cdc_md) = NULL_PTR;
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_load_np_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_load_np_aio_complete: "
                                        "load np completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_NP_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    //caio_cb_exec_complete_handler(&caio_cb);

    cdc_load_dn_aio(cdc_md, &caio_cb); /*load data node next*/

    return (EC_TRUE);
}


/**
*
*  load name node from disk
*
**/
EC_BOOL cdc_load_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP   *cdcnp;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np: np already exist\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_NP_LOADING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_np: load np is on-going\n");
        return (EC_FALSE);
    }

    cdcnp = cdcnp_new();
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np: new cdncp failed\n");
        return (EC_FALSE);
    }

    /*inherit caio from cdc*/
    CDCNP_FD(cdcnp)      = CDC_MD_FD(cdc_md);
    CDCNP_CAIO_MD(cdcnp) = CDC_MD_CAIO_MD(cdc_md);

    CDC_MD_NP(cdc_md) = cdcnp;/*bind*/

    if(EC_FALSE == cdcnp_load(cdcnp, 0 /*np id*/, CDC_MD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np: load np failed\n");

        CDC_MD_NP(cdc_md) = NULL_PTR;/*unbind*/
        cdcnp_free(cdcnp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_np: load np done\n");

    return (EC_TRUE);
}

EC_BOOL cdc_load_np_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb)
{
    CDCNP   *cdcnp;
    UINT32   f_s_offset;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_aio: np already exist\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_NP_LOADING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_np_aio: load np is on-going\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != CDC_MD_CAIO_MD(cdc_md));

    cdcnp = cdcnp_new();
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_aio: new cdncp failed\n");
        return (EC_FALSE);
    }

    /*inherit caio from cdc*/
    CDCNP_FD(cdcnp)      = CDC_MD_FD(cdc_md);
    CDCNP_CAIO_MD(cdcnp) = CDC_MD_CAIO_MD(cdc_md);

    CDC_MD_NP(cdc_md) = cdcnp; /*bind*/

    f_s_offset = CDC_MD_C_OFFSET(cdc_md);

    if(NULL_PTR == CDCNP_CAIO_MD(cdcnp))
    {
        if(EC_FALSE == cdcnp_load(cdcnp, 0 /*np id*/, CDC_MD_FD(cdc_md),
                                    &CDC_MD_C_OFFSET(cdc_md),
                                    CDC_MD_E_OFFSET(cdc_md)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_aio: load np failed\n");

            CDC_MD_NP(cdc_md) = NULL_PTR;/*unbind*/
            cdcnp_free(cdcnp);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_np_aio: load np done\n");
    }
    else
    {
        CDC_FILE_AIO   *cdc_file_aio;
        CAIO_CB         caio_cb_t;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_aio: "
                                                "new cdc_file_aio failed\n");

            CDC_MD_NP(cdc_md) = NULL_PTR;/*unbind*/
            cdcnp_free(cdcnp);
            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio) = cdc_md;
        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        CDC_MD_NP_LOADING_FLAG(cdc_md) = BIT_TRUE; /*set flag*/

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, CDC_LOADING_NP_TIMEOUT_NSEC,
                                     (CAIO_CALLBACK)__cdc_load_np_aio_timeout,
                                     (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t,
                                       (CAIO_CALLBACK)__cdc_load_np_aio_terminate,
                                       (void *)cdc_file_aio);

        caio_cb_set_complete_handler(&caio_cb_t,
                                      (CAIO_CALLBACK)__cdc_load_np_aio_complete,
                                      (void *)cdc_file_aio);

        if(EC_FALSE == cdcnp_load_aio(cdcnp, 0 /*np id*/, CDC_MD_FD(cdc_md),
                                        &CDC_MD_C_OFFSET(cdc_md),
                                        CDC_MD_E_OFFSET(cdc_md),
                                        &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_aio: "
                                                "aio load np from fd %d, offset %ld failed\n",
                                                CDC_MD_FD(cdc_md), f_s_offset);

            CDC_MD_NP_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

            cdc_file_aio_free(cdc_file_aio);

            CDC_MD_NP(cdc_md) = NULL_PTR;/*unbind*/
            cdcnp_free(cdcnp);

            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_np_aio: "
                                            "aio load np from fd %d, offset %ld => %ld done\n",
                                            CDC_MD_FD(cdc_md), f_s_offset, CDC_MD_C_OFFSET(cdc_md));

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_np_aio: aio load np done\n");
    }

    return (EC_TRUE);
}

/**
*
*  flush name node to disk
*
**/
EC_BOOL cdc_flush_np(CDC_MD *cdc_md)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np: no np to flush\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_flush(CDC_MD_NP(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np: flush np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_np: flush np done\n");
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_flush_np_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_flush_np_aio_timeout: "
                                        "flush np timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_NP_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/
    CDC_MD_FLUSHING_FLAG(cdc_md)    = BIT_FALSE; /*reset*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_flush_np_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_flush_np_aio_terminate: "
                                        "flush np terminated\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_NP_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/
    CDC_MD_FLUSHING_FLAG(cdc_md)    = BIT_FALSE; /*reset*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_flush_np_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_flush_np_aio_complete: "
                                        "flush np completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_NP_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    //caio_cb_exec_complete_handler(&caio_cb);

    cdc_flush_dn_aio(cdc_md, &caio_cb); /*flush data node next*/

    return (EC_TRUE);
}

EC_BOOL cdc_flush_np_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb)
{
    CDCNP       *cdcnp;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_np_aio: no np to flush\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_NP_FLUSHING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_np_aio: flush np is on-going\n");
        return (EC_FALSE);
    }

    cdcnp = CDC_MD_NP(cdc_md);

    ASSERT(NULL_PTR != CDCNP_CAIO_MD(cdcnp));

    if(NULL_PTR == CDCNP_CAIO_MD(cdcnp))
    {
        if(EC_FALSE == cdcnp_flush(cdcnp))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np_aio: flush np failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_np_aio: flush np done\n");
    }
    else
    {
        CDC_FILE_AIO   *cdc_file_aio;
        CAIO_CB         caio_cb_t;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio) = cdc_md;
        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        CDC_MD_NP_FLUSHING_FLAG(cdc_md) = BIT_TRUE; /*set flag*/

        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, CDC_FLUSHING_NP_TIMEOUT_NSEC,
                                 (CAIO_CALLBACK)__cdc_flush_np_aio_timeout,
                                 (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t,
                                    (CAIO_CALLBACK)__cdc_flush_np_aio_terminate,
                                    (void *)cdc_file_aio);

        caio_cb_set_complete_handler(&caio_cb_t,
                                    (CAIO_CALLBACK)__cdc_flush_np_aio_complete,
                                    (void *)cdc_file_aio);

        if(EC_FALSE == cdcnp_flush_aio(cdcnp, &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np_aio: aio flush np failed\n");

            CDC_MD_NP_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

            cdc_file_aio_free(cdc_file_aio);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_np_aio: aio flush np done\n");
    }

    return (EC_TRUE);
}

/**
*
*  create data node
*
**/
EC_BOOL cdc_create_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN           *cdcdn;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_dn: dn already exist\n");
        return (EC_FALSE);
    }

    cdcdn = cdcdn_create(s_offset, e_offset);
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_dn: create dn failed\n");
        return (EC_FALSE);
    }

    /*inherit data from cdc module*/
    CDCDN_NODE_FD(cdcdn)      = CDC_MD_FD(cdc_md);
    CDCDN_NODE_CAIO_MD(cdcdn) = CDC_MD_CAIO_MD(cdc_md);

    CDC_MD_DN(cdc_md) = cdcdn;

    return (EC_TRUE);
}


STATIC_CAST static EC_BOOL __cdc_load_dn_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_load_dn_aio_timeout: "
                                        "load dn timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_DN_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        cdcdn_free(CDC_MD_DN(cdc_md));
        CDC_MD_DN(cdc_md) = NULL_PTR;
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_load_dn_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_load_dn_aio_terminate: "
                                        "load dn terminated\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_DN_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        cdcdn_free(CDC_MD_DN(cdc_md));
        CDC_MD_DN(cdc_md) = NULL_PTR;
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_load_dn_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_load_dn_aio_complete: "
                                        "load dn completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_DN_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/
    CDC_MD_LOADING_FLAG(cdc_md)    = BIT_FALSE; /*reset*/
    CDC_MD_C_OFFSET(cdc_md)        = 0; /*reset*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

/**
*
*  load data node from disk
*
**/
EC_BOOL cdc_load_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN   *cdcdn;
    UINT32   f_s_offset;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn: dn already exist\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_DN_LOADING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_dn: load dn is on-going\n");
        return (EC_FALSE);
    }

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn: new dn failed\n");
        return (EC_FALSE);
    }

    /*inherit from cdc*/
    CDCDN_NODE_FD(cdcdn)      = CDC_MD_FD(cdc_md);
    CDCDN_NODE_CAIO_MD(cdcdn) = CDC_MD_CAIO_MD(cdc_md);

    CDC_MD_DN(cdc_md) = cdcdn; /*bind*/

    f_s_offset = (*s_offset);/*save*/

    if(EC_FALSE == cdcdn_load(cdcdn, CDC_MD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn: "
                                            "load dn from fd %d, offset %ld failed\n",
                                            CDC_MD_FD(cdc_md), f_s_offset);

        CDC_MD_DN(cdc_md) = NULL_PTR; /*unbind*/

        cdcdn_free(cdcdn);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn: "
                                        "load dn from fd %d, offset %ld => %ld done\n",
                                        CDC_MD_FD(cdc_md), f_s_offset, (*s_offset));

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn: load dn done\n");


    return (EC_TRUE);
}

EC_BOOL cdc_load_dn_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb)
{
    CDCDN   *cdcdn;
    UINT32   f_s_offset;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_aio: dn already exist\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_DN_LOADING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_dn_aio: load dn is on-going\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != CDC_MD_CAIO_MD(cdc_md));

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_aio: new dn failed\n");
        return (EC_FALSE);
    }

    /*inherit from cdc*/
    CDCDN_NODE_FD(cdcdn)      = CDC_MD_FD(cdc_md);
    CDCDN_NODE_CAIO_MD(cdcdn) = CDC_MD_CAIO_MD(cdc_md);

    CDC_MD_DN(cdc_md) = cdcdn; /*bind*/

    f_s_offset = CDC_MD_C_OFFSET(cdc_md);/*save*/

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        if(EC_FALSE == cdcdn_load(cdcdn, CDC_MD_FD(cdc_md), &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_aio: "
                                                "load dn from fd %d, offset %ld failed\n",
                                                CDC_MD_FD(cdc_md), f_s_offset);

            CDC_MD_DN(cdc_md) = cdcdn; /*unbind*/
            cdcdn_free(cdcdn);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn_aio: "
                                            "load dn from fd %d, offset %ld => %ld done\n",
                                            CDC_MD_FD(cdc_md), f_s_offset, CDC_MD_C_OFFSET(cdc_md));

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn_aio: load dn done\n");
    }
    else
    {
        CDC_FILE_AIO   *cdc_file_aio;
        CAIO_CB         caio_cb_t;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_aio: "
                                                "new cdc_file_aio failed\n");

            CDC_MD_DN(cdc_md) = cdcdn; /*unbind*/
            cdcdn_free(cdcdn);
            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio) = cdc_md;
        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        CDC_MD_NP_LOADING_FLAG(cdc_md) = BIT_TRUE; /*set flag*/

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, CDC_LOADING_DN_TIMEOUT_NSEC,
                                         (CAIO_CALLBACK)__cdc_load_dn_aio_timeout,
                                         (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t,
                                            (CAIO_CALLBACK)__cdc_load_dn_aio_terminate,
                                            (void *)cdc_file_aio);

        caio_cb_set_complete_handler(&caio_cb_t,
                                            (CAIO_CALLBACK)__cdc_load_dn_aio_complete,
                                            (void *)cdc_file_aio);

        if(EC_FALSE == cdcdn_load_aio(cdcdn, CDC_MD_FD(cdc_md),
                                     &CDC_MD_C_OFFSET(cdc_md),
                                     CDC_MD_E_OFFSET(cdc_md),
                                     &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_aio: "
                                                "aio load dn from fd %d, offset %ld failed\n",
                                                CDC_MD_FD(cdc_md), f_s_offset);

            CDC_MD_DN_LOADING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

            cdc_file_aio_free(cdc_file_aio);

            CDC_MD_DN(cdc_md) = cdcdn; /*unbind*/
            cdcdn_free(cdcdn);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn_aio: "
                                            "aio load dn from fd %d, offset %ld => %ld done\n",
                                            CDC_MD_FD(cdc_md), f_s_offset, CDC_MD_C_OFFSET(cdc_md));

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn_aio: aio load dn done\n");
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_flush_dn_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_flush_dn_aio_timeout: "
                                        "flush dn timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_DN_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/
    CDC_MD_FLUSHING_FLAG(cdc_md)    = BIT_FALSE; /*reset*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_flush_dn_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_flush_dn_aio_terminate: "
                                        "flush dn terminated\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_DN_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/
    CDC_MD_FLUSHING_FLAG(cdc_md)    = BIT_FALSE; /*reset*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_flush_dn_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB      caio_cb;
    CDC_MD      *cdc_md;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_flush_dn_aio_complete: "
                                        "flush dn completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    CDC_MD_DN_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/
    CDC_MD_FLUSHING_FLAG(cdc_md)    = BIT_FALSE; /*reset*/

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

/**
*
*  flush data node to disk
*
**/
EC_BOOL cdc_flush_dn(CDC_MD *cdc_md)
{
    CDCDN       *cdcdn;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_dn: no dn to flush\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_DN_FLUSHING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_dn: flush dn is on-going\n");
        return (EC_FALSE);
    }

    cdcdn = CDC_MD_DN(cdc_md);

    if(EC_FALSE == cdcdn_flush(cdcdn))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_dn: flush dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_dn: flush dn done\n");


    return (EC_TRUE);
}

EC_BOOL cdc_flush_dn_aio(CDC_MD *cdc_md, CAIO_CB *caio_cb)
{
    CDCDN       *cdcdn;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_dn_aio: no dn to flush\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_DN_FLUSHING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_dn_aio: flush dn is on-going\n");
        return (EC_FALSE);
    }

    cdcdn = CDC_MD_DN(cdc_md);

    ASSERT(NULL_PTR != CDCDN_NODE_CAIO_MD(cdcdn));

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        if(EC_FALSE == cdcdn_flush(cdcdn))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_dn_aio: flush dn failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_dn_aio: flush dn done\n");
    }
    else
    {
        CDC_FILE_AIO   *cdc_file_aio;
        CAIO_CB         caio_cb_t;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_dn_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)  = cdc_md;
        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        CDC_MD_DN_FLUSHING_FLAG(cdc_md) = BIT_TRUE; /*set flag*/

        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, CDC_FLUSHING_DN_TIMEOUT_NSEC,
                                     (CAIO_CALLBACK)__cdc_flush_dn_aio_timeout,
                                     (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t,
                                    (CAIO_CALLBACK)__cdc_flush_dn_aio_terminate,
                                    (void *)cdc_file_aio);

        caio_cb_set_complete_handler(&caio_cb_t,
                                    (CAIO_CALLBACK)__cdc_flush_dn_aio_complete,
                                    (void *)cdc_file_aio);

        if(EC_FALSE == cdcdn_flush_aio(cdcdn, &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_dn_aio: aio flush dn failed\n");

            CDC_MD_DN_FLUSHING_FLAG(cdc_md) = BIT_FALSE; /*clear flag*/

            cdc_file_aio_free(cdc_file_aio);

            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush_dn_aio: aio flush dn done\n");
    }

    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL cdc_close_dn(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        cdcdn_free(CDC_MD_DN(cdc_md));
        CDC_MD_DN(cdc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}

STATIC_CAST static void __cdc_find_intersected_print(const CDCNP_KEY *cdcnp_key, const CDCNP_KEY *cdcnp_key_intersected, const CDCNP_KEY *cdcnp_key_next)
{
    sys_log(LOGSTDOUT, "[DEBUG] __cdc_find_intersected_print: key [%u, %u), intersected [%u, %u), next [%u, %u)\n",
                       CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key),
                       CDCNP_KEY_S_PAGE(cdcnp_key_intersected), CDCNP_KEY_E_PAGE(cdcnp_key_intersected),
                       CDCNP_KEY_S_PAGE(cdcnp_key_next), CDCNP_KEY_E_PAGE(cdcnp_key_next));
}

/**
*
*  find intersected range
*
**/
EC_BOOL cdc_find_intersected(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ITEM       *cdcnp_item_intersected;
    CDCNP_KEY        *cdcnp_key_intersected;
    uint32_t          node_pos_intersected;

    if(EC_FALSE == cdcnp_key_is_valid(cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_find_intersected: invalid key [%ld, %ld)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_find_intersected: np was not open\n");
        return (EC_FALSE);
    }

    node_pos_intersected = cdcnp_find_intersected(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS == node_pos_intersected)
    {
        return (EC_FALSE);
    }

    cdcnp_item_intersected = cdcnp_fetch(CDC_MD_NP(cdc_md), node_pos_intersected);
    if(NULL_PTR == cdcnp_item_intersected)
    {
        return (EC_FALSE);
    }

    cdcnp_key_intersected = CDCNP_ITEM_KEY(cdcnp_item_intersected);

    if(CDCNP_KEY_S_PAGE(cdcnp_key) >= CDCNP_KEY_S_PAGE(cdcnp_key_intersected))
    {
        if(CDCNP_KEY_E_PAGE(cdcnp_key) >= CDCNP_KEY_E_PAGE(cdcnp_key_intersected))
        {
            CDCNP_KEY  cdcnp_key_next;

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key_intersected);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key);

            if(CDCNP_KEY_S_PAGE(&cdcnp_key_next) < CDCNP_KEY_E_PAGE(&cdcnp_key_next))
            {
                __cdc_find_intersected_print(cdcnp_key, cdcnp_key_intersected, &cdcnp_key_next);

                cdc_find_intersected(cdc_md, &cdcnp_key_next);
            }

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key_intersected);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key);

            if(CDCNP_KEY_S_PAGE(&cdcnp_key_next) < CDCNP_KEY_E_PAGE(&cdcnp_key_next))
            {
                __cdc_find_intersected_print(cdcnp_key, cdcnp_key_intersected, &cdcnp_key_next);

                cdc_find_intersected(cdc_md, &cdcnp_key_next);
            }
        }
        else
        {
            /*no next*/
        }
    }
    else
    {
        if(CDCNP_KEY_E_PAGE(cdcnp_key) >= CDCNP_KEY_E_PAGE(cdcnp_key_intersected))
        {
            CDCNP_KEY  cdcnp_key_next;

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key_intersected);

            if(CDCNP_KEY_S_PAGE(&cdcnp_key_next) < CDCNP_KEY_E_PAGE(&cdcnp_key_next))
            {
                __cdc_find_intersected_print(cdcnp_key, cdcnp_key_intersected, &cdcnp_key_next);

                cdc_find_intersected(cdc_md, &cdcnp_key_next);
            }

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key_intersected);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key);

            if(CDCNP_KEY_S_PAGE(&cdcnp_key_next) < CDCNP_KEY_E_PAGE(&cdcnp_key_next))
            {
                __cdc_find_intersected_print(cdcnp_key, cdcnp_key_intersected, &cdcnp_key_next);

                cdc_find_intersected(cdc_md, &cdcnp_key_next);
            }
        }
        else
        {
            CDCNP_KEY  cdcnp_key_next;

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key_intersected);

            if(CDCNP_KEY_S_PAGE(&cdcnp_key_next) < CDCNP_KEY_E_PAGE(&cdcnp_key_next))
            {
                __cdc_find_intersected_print(cdcnp_key, cdcnp_key_intersected, &cdcnp_key_next);

                cdc_find_intersected(cdc_md, &cdcnp_key_next);
            }
        }
    }

    return (EC_TRUE);
}

/**
*
*  find closest range
*
**/
EC_BOOL cdc_find_closest(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CDCNP_KEY *cdcnp_key_closest)
{
    uint32_t          node_pos_closest;

    if(EC_FALSE == cdcnp_key_is_valid(cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_find_closest: invalid key [%ld, %ld)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_find_closest: np was not open\n");
        return (EC_FALSE);
    }

    node_pos_closest = cdcnp_find_closest(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS == node_pos_closest)
    {
        return (EC_FALSE);
    }

    if(NULL_PTR != cdcnp_key_closest)
    {
        const CDCNP_ITEM *cdcnp_item_closest;

        cdcnp_item_closest = cdcnp_fetch(CDC_MD_NP(cdc_md), node_pos_closest);
        if(NULL_PTR == cdcnp_item_closest)
        {
            return (EC_FALSE);
        }
        cdcnp_key_clone(CDCNP_ITEM_KEY(cdcnp_item_closest), cdcnp_key_closest);
    }

    return (EC_TRUE);
}


/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __cdc_reserve_hash_dn(CDC_MD *cdc_md, const UINT32 data_len, const uint32_t path_hash, CDCNP_FNODE *cdcnp_fnode)
{
    CDCNP_INODE *cdcnp_inode;
    CDCPGV      *cdcpgv;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint16_t fail_tries;

    if(CDCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDCDN_CDCPGV(CDC_MD_DN(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cdcpgv = CDCDN_CDCPGV(CDC_MD_DN(cdc_md));
    if(NULL_PTR == CDCPGV_HEADER(cdcpgv))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCPGV_PAGE_DISK_NUM(cdcpgv))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: pgv has no disk yet\n");
        return (EC_FALSE);
    }

    fail_tries = 0;
    for(;;)
    {
        size    = (uint32_t)(data_len);
        disk_no = (uint16_t)(path_hash % CDCPGV_PAGE_DISK_NUM(cdcpgv));

        if(EC_TRUE == cdcpgv_new_space_from_disk(cdcpgv, size, disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        /*try again*/
        if(EC_TRUE == cdcpgv_new_space(cdcpgv, size, &disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        fail_tries ++;

        if(1 < fail_tries) /*try once only*/
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: "
                                                "new %ld bytes space from vol failed\n",
                                                data_len);
            return (EC_FALSE);
        }

        /*try to retire & recycle some files*/
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "warn:__cdc_reserve_hash_dn: "
                                            "no %ld bytes space, try to retire & recycle\n",
                                            data_len);
        cdc_retire(cdc_md, (UINT32)CDC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cdc_recycle(cdc_md, (UINT32)CDC_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    cdcnp_fnode_init(cdcnp_fnode);
    CDCNP_FNODE_FILESZ(cdcnp_fnode) = size;
    CDCNP_FNODE_REPNUM(cdcnp_fnode) = 1;

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    CDCNP_INODE_DISK_NO(cdcnp_inode)    = disk_no;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = block_no;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL cdc_reserve_dn(CDC_MD *cdc_md, const UINT32 data_len, CDCNP_FNODE *cdcnp_fnode)
{
    CDCNP_INODE *cdcnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(CDCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    if(EC_FALSE == cdcpgv_new_space(CDCDN_CDCPGV(CDC_MD_DN(cdc_md)), size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_dn: new %ld bytes space from vol failed\n", data_len);
        return (EC_FALSE);
    }

    cdcnp_fnode_init(cdcnp_fnode);
    CDCNP_FNODE_FILESZ(cdcnp_fnode) = size;
    CDCNP_FNODE_REPNUM(cdcnp_fnode) = 1;

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    CDCNP_INODE_DISK_NO(cdcnp_inode)    = disk_no;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = block_no;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  release space to dn
*
**/
EC_BOOL cdc_release_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_release_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size    = CDCNP_FNODE_FILESZ(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

    if(CDCPGB_SIZE_NBYTES < file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_release_dn: file_size %u overflow\n", file_size);
        return (EC_FALSE);
    }

    /*refer cdc_page_write: when file size is zero, only reserve np but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_release_dn: file_size is zero\n");
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    if(EC_FALSE == cdcpgv_free_space(CDCDN_CDCPGV(CDC_MD_DN(cdc_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_release_dn: free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_release_dn: remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  reserve a fnode from name node
*
**/
STATIC_CAST static CDCNP_FNODE * __cdc_reserve_np(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_FNODE *cdcnp_fnode;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_np: np was not open\n");
        return (NULL_PTR);
    }

    cdcnp_fnode = cdcnp_reserve(CDC_MD_NP(cdc_md), cdcnp_key);
    if(NULL_PTR == cdcnp_fnode)
    {
        /*try to retire & recycle some files*/
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "warn:__cdc_reserve_np: no name node accept key, try to retire & recycle\n");
        cdc_retire(cdc_md, (UINT32)CDC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cdc_recycle(cdc_md, (UINT32)CDC_TRY_RECYCLE_MAX_NUM, NULL_PTR);

        /*try again*/
        cdcnp_fnode = cdcnp_reserve(CDC_MD_NP(cdc_md), cdcnp_key);
        if(NULL_PTR == cdcnp_fnode)/*Oops!*/
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_np: no name node accept key\n");
            return (NULL_PTR);
        }
    }

    return (cdcnp_fnode);
}


/**
*
*  release a fnode from name node
*
**/
STATIC_CAST static EC_BOOL __cdc_release_np(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_release_np: np was not open\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdcnp_release(CDC_MD_NP(cdc_md), cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_release_np: release key from np failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

CDC_FILE_AIO *cdc_file_aio_new()
{
    CDC_FILE_AIO *cdc_file_aio;

    alloc_static_mem(MM_CDC_FILE_AIO, &cdc_file_aio, LOC_CDC_0004);
    if(NULL_PTR != cdc_file_aio)
    {
        cdc_file_aio_init(cdc_file_aio);
        return (cdc_file_aio);
    }
    return (cdc_file_aio);
}

EC_BOOL cdc_file_aio_init(CDC_FILE_AIO *cdc_file_aio)
{
    CDC_FILE_AIO_CDC_MD(cdc_file_aio)           = NULL_PTR;
    CDC_FILE_AIO_I_DATA_LEN(cdc_file_aio)       = NULL_PTR;
    CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)       = NULL_PTR;
    CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio)       = CDC_OFFSET_ERR;
    CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio)       = CDC_OFFSET_ERR;
    CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio)       = CDC_OFFSET_ERR;
    CDC_FILE_AIO_F_SIZE(cdc_file_aio)           = 0;
    CDC_FILE_AIO_F_OLD_SIZE(cdc_file_aio)       = 0;
    CDC_FILE_AIO_M_BUFF(cdc_file_aio)           = NULL_PTR;
    CDC_FILE_AIO_M_LEN(cdc_file_aio)            = 0;
    CDC_FILE_AIO_T_CDCNP_FNODE(cdc_file_aio)    = NULL_PTR;

    cbytes_init(CDC_FILE_AIO_CBYTES(cdc_file_aio));
    cdcnp_key_init(CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio));
    cdcnp_fnode_init(CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio));
    caio_cb_init(CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

    return (EC_TRUE);
}

EC_BOOL cdc_file_aio_clean(CDC_FILE_AIO *cdc_file_aio)
{
    CDC_FILE_AIO_CDC_MD(cdc_file_aio)           = NULL_PTR;
    CDC_FILE_AIO_I_DATA_LEN(cdc_file_aio)       = NULL_PTR;
    CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)       = NULL_PTR;
    CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio)       = CDC_OFFSET_ERR;
    CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio)       = CDC_OFFSET_ERR;
    CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio)       = CDC_OFFSET_ERR;
    CDC_FILE_AIO_F_SIZE(cdc_file_aio)           = 0;
    CDC_FILE_AIO_F_OLD_SIZE(cdc_file_aio)       = 0;
    CDC_FILE_AIO_M_BUFF(cdc_file_aio)           = NULL_PTR;
    CDC_FILE_AIO_M_LEN(cdc_file_aio)            = 0;
    CDC_FILE_AIO_T_CDCNP_FNODE(cdc_file_aio)    = NULL_PTR;

    cbytes_clean(CDC_FILE_AIO_CBYTES(cdc_file_aio));
    cdcnp_key_clean(CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio));
    cdcnp_fnode_clean(CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio));
    caio_cb_clean(CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

    return (EC_TRUE);
}

EC_BOOL cdc_file_aio_free(CDC_FILE_AIO *cdc_file_aio)
{
    if(NULL_PTR != cdc_file_aio)
    {
        cdc_file_aio_clean(cdc_file_aio);
        free_static_mem(MM_CDC_FILE_AIO, cdc_file_aio, LOC_CDC_0005);
    }
    return (EC_TRUE);
}

void cdc_file_aio_print(LOG *log, const CDC_FILE_AIO *cdc_file_aio)
{
    if(NULL_PTR != cdc_file_aio)
    {
        sys_log(log, "cdc_file_aio_print: cdc_file_aio %p: range [%ld, %ld), reached %ld\n",
                     cdc_file_aio,
                     CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                     CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                     CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio));
    }
    return;
}

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_read(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    s_offset = (*offset);
    e_offset = (*offset) + rsize;
    m_buff   = buff;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_read: "
                                        "offset %ld, rsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), rsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES        cbytes;

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(&cdcnp_key) = s_page + 1;

        if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
        {
            dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_file_read: ssd miss page %ld\n",
                            s_page);
            break;
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_read: ssd hit page %ld\n",
                        s_page);

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        CBYTES_BUF(&cbytes) = m_buff;
        CBYTES_LEN(&cbytes) = e_offset - s_offset;

        if(EC_FALSE == cdc_page_read_e(cdc_md, &cdcnp_key, &offset_t, max_len, &cbytes))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_read: "
                            "read page %ld, offset %ld, len %ld failed\n",
                            s_page, (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK)), max_len);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_read: "
                        "read page %ld => offset %ld, len %ld\n",
                        s_page, offset_t, CBYTES_LEN(&cbytes));

        CDC_ASSERT(CBYTES_BUF(&cbytes) == m_buff);

        s_offset += CBYTES_LEN(&cbytes);
        m_buff   += CBYTES_LEN(&cbytes);
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_write(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    s_offset = (*offset);
    e_offset = (*offset) + wsize;
    m_buff   = buff;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES        cbytes;

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(&cdcnp_key) = s_page + 1;

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        CBYTES_BUF(&cbytes) = m_buff;
        CBYTES_LEN(&cbytes) = max_len;

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CDCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdc_page_write_e(cdc_md, &cdcnp_key, &offset_t, max_len, &cbytes))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "override page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                            "override page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            if(EC_FALSE == cdc_page_write(cdc_md, &cdcnp_key, &cbytes))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "write page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                            "write page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        CDC_ASSERT(CBYTES_BUF(&cbytes) == m_buff);

        s_offset += CBYTES_LEN(&cbytes);
        m_buff   += CBYTES_LEN(&cbytes);
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  delete a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_delete(CDC_MD *cdc_md, UINT32 *offset, const UINT32 dsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    s_offset = (*offset);
    e_offset = (*offset) + dsize;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                        "offset %ld, dsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), dsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(&cdcnp_key) = s_page + 1;

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        /*skip non-existence*/
        if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
        {
            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                            "page %ld absent, [%ld, %ld), offset %ld, len %ld in page\n",
                            s_page,
                            s_offset, e_offset,
                            offset_t, max_len);
            s_offset += max_len;
            continue;
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                        "ssd hit page %ld, [%ld, %ld), offset %ld, len %ld in page\n",
                        s_page,
                        s_offset, e_offset,
                        offset_t, max_len);

        /*when partial delete, need the whole page exists*/
        if(0 < offset_t || CDCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            CDCNP_FNODE   cdcnp_fnode;
            UINT32        file_size;

            cdcnp_fnode_init(&cdcnp_fnode);

            /*found inconsistency*/
            if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), &cdcnp_key, &cdcnp_fnode))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                "read page %ld failed, [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
                return (EC_FALSE);
            }

            file_size = CDCNP_FNODE_FILESZ(&cdcnp_fnode);

            if(file_size > offset_t + max_len)
            {
                /*do nothing*/
                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "ignore page %ld (file size %ld > %ld + %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t, max_len,
                                s_offset, e_offset,
                                offset_t, max_len);
            }

            else if (file_size <= offset_t)
            {
                /*do nothing*/
                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "ignore page %ld (file size %ld <= %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t,
                                s_offset, e_offset,
                                offset_t, max_len);
            }

            /*now: offset_t < file_size <= offset_t + max_len*/

            else if(0 == offset_t)
            {
                if(EC_FALSE == cdc_page_delete(cdc_md, &cdcnp_key))
                {
                    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                    "delete page %ld failed, [%ld, %ld), offset %ld, len %ld in page\n",
                                    s_page,
                                    s_offset, e_offset,
                                    offset_t, max_len);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "delete page %ld done, [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
            }
            else
            {
                CDCNP_FNODE_FILESZ(&cdcnp_fnode) = (uint32_t)offset_t;

                if(EC_FALSE == cdcnp_update(CDC_MD_NP(cdc_md), &cdcnp_key, &cdcnp_fnode))
                {
                    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                    "update page %ld failed (file size %ld => %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                    s_page,
                                    file_size, offset_t,
                                    s_offset, e_offset,
                                    offset_t, max_len);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "update page %ld done (file size %ld => %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t,
                                s_offset, e_offset,
                                offset_t, max_len);
            }
        }

        else
        {
            if(EC_FALSE == cdc_page_delete(cdc_md, &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                "delete page %ld failed, [%ld, %ld), offset %ld, len %ld\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                            "delete page %ld done, [%ld, %ld), offset %ld, len %ld\n",
                            s_page,
                            s_offset, e_offset,
                            offset_t, max_len);
        }

        s_offset += max_len;
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_read_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_file_read_aio_timeout: "
                  "page read timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_read_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_file_read_aio_terminate: "
                  "page read terminate\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));;

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_read_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CBYTES          *cbytes;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_file_read_aio_complete: "
                  "page read completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cbytes = CDC_FILE_AIO_CBYTES(cdc_file_aio);

    CDC_ASSERT(CBYTES_BUF(cbytes) == CDC_FILE_AIO_M_BUFF(cdc_file_aio));

    CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio) += CBYTES_LEN(cbytes);
    CDC_FILE_AIO_M_BUFF(cdc_file_aio)     += CBYTES_LEN(cbytes);

    if(NULL_PTR != CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio))
    {
        (*CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)) = CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio);/*xxx*/
    }

    __cdc_file_read_aio(cdc_file_aio);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_read_aio(CDC_FILE_AIO *cdc_file_aio)
{
    CDC_MD     *cdc_md;
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    s_offset = CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio);
    e_offset = CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio);
    m_buff   = CDC_FILE_AIO_M_BUFF(cdc_file_aio);

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] __cdc_file_read_aio: "
                                        "offset %ld, rsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                                        CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio) - CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                                        s_offset, e_offset,
                                        s_page, e_page);

    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    if(s_page < e_page)
    {
        CDCNP_KEY    *cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES       *cbytes;
        CAIO_CB       caio_cb_t;

        cdcnp_key = CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio);

        /*one page only*/
        CDCNP_KEY_S_PAGE(cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(cdcnp_key) = s_page + 1;

        if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), cdcnp_key))
        {
            dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:__cdc_file_read_aio: ssd miss page %ld\n",
                            s_page);

            __cdc_file_read_aio_terminate(cdc_file_aio);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] __cdc_file_read_aio: ssd hit page %ld\n",
                        s_page);

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        cbytes = CDC_FILE_AIO_CBYTES(cdc_file_aio);

        CBYTES_BUF(cbytes) = m_buff;
        CBYTES_LEN(cbytes) = e_offset - s_offset;

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_file_read_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_file_read_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_file_read_aio_complete, (void *)cdc_file_aio);

        if(EC_FALSE == cdc_page_read_e_aio(cdc_md, cdcnp_key, &offset_t, max_len, cbytes, &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_read_aio: "
                            "read page %ld, offset %ld, len %ld failed\n",
                            s_page, (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK)), max_len);

            __cdc_file_read_aio_terminate(cdc_file_aio);
            return (EC_FALSE);
        }
    }
    else
    {
        CAIO_CB          caio_cb;

        caio_cb_init(&caio_cb);
        caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

        cdc_file_aio_free(cdc_file_aio);
        caio_cb_exec_complete_handler(&caio_cb);
    }
    return (EC_TRUE);
}

/**
*
*  read a file (aio interface)
*
**/
EC_BOOL cdc_file_read_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CDC_FILE_AIO    *cdc_file_aio;

    /*set cdc file aio*/
    cdc_file_aio = cdc_file_aio_new();
    if(NULL_PTR == cdc_file_aio)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_read_aio: "
                                            "new cdc_file_aio failed\n");

        return (EC_FALSE);
    }

    CDC_FILE_AIO_CDC_MD(cdc_file_aio)      = cdc_md;
    CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)  = offset;
    CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio)  = (*offset);
    CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio)  = (*offset) + rsize;
    CDC_FILE_AIO_M_BUFF(cdc_file_aio)      = buff;

    caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

    __cdc_file_read_aio(cdc_file_aio);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_write_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_file_write_aio_timeout: "
                  "page write timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_write_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_file_write_aio_terminate: "
                  "page write terminate\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));;

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_write_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CBYTES          *cbytes;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_file_write_aio_complete: "
                  "page write completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cbytes = CDC_FILE_AIO_CBYTES(cdc_file_aio);

    CDC_ASSERT(CBYTES_BUF(cbytes) == CDC_FILE_AIO_M_BUFF(cdc_file_aio));

    CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio) += CBYTES_LEN(cbytes);
    CDC_FILE_AIO_M_BUFF(cdc_file_aio)     += CBYTES_LEN(cbytes);

    if(NULL_PTR != CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio))
    {
        (*CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)) = CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio);/*xxx*/
    }

    __cdc_file_write_aio(cdc_file_aio);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_file_write_aio(CDC_FILE_AIO *cdc_file_aio)
{
    CDC_MD     *cdc_md;
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    s_offset = CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio);
    e_offset = CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio);
    m_buff   = CDC_FILE_AIO_M_BUFF(cdc_file_aio);

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] __cdc_file_write_aio: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                                        CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio) - CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                                        s_offset, e_offset,
                                        s_page, e_page);

    cdc_md = CDC_FILE_AIO_CDC_MD(cdc_file_aio);

    if(s_page < e_page)
    {
        CDCNP_KEY    *cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES       *cbytes;
        CAIO_CB       caio_cb_t;

        cdcnp_key = CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio);

        /*one page only*/
        CDCNP_KEY_S_PAGE(cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(cdcnp_key) = s_page + 1;

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        cbytes = CDC_FILE_AIO_CBYTES(cdc_file_aio);

        CBYTES_BUF(cbytes) = m_buff;
        CBYTES_LEN(cbytes) = max_len;

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_file_write_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_file_write_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_file_write_aio_complete, (void *)cdc_file_aio);

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CDCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);

                __cdc_file_write_aio_terminate(cdc_file_aio);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdc_page_write_e_aio(cdc_md, cdcnp_key, &offset_t, max_len, cbytes, &caio_cb_t))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "override page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);

                __cdc_file_write_aio_terminate(cdc_file_aio);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                            "override page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            if(EC_FALSE == cdc_page_write_aio(cdc_md, cdcnp_key, cbytes, &caio_cb_t))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "write page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);

                __cdc_file_write_aio_terminate(cdc_file_aio);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                            "write page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
    }
    else
    {
        CAIO_CB          caio_cb;

        caio_cb_init(&caio_cb);
        caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

        cdc_file_aio_free(cdc_file_aio);
        caio_cb_exec_complete_handler(&caio_cb);
    }

    return (EC_TRUE);
}

/**
*
*  write a file (aio interface)
*
**/
EC_BOOL cdc_file_write_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CDC_FILE_AIO    *cdc_file_aio;

    /*set cdc file aio*/
    cdc_file_aio = cdc_file_aio_new();
    if(NULL_PTR == cdc_file_aio)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write_aio: "
                                            "new cdc_file_aio failed\n");

        return (EC_FALSE);
    }

    CDC_FILE_AIO_CDC_MD(cdc_file_aio)      = cdc_md;
    CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)  = offset;
    CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio)  = (*offset);
    CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio)  = (*offset) + wsize;
    CDC_FILE_AIO_M_BUFF(cdc_file_aio)      = buff;

    caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

    __cdc_file_write_aio(cdc_file_aio);

    return (EC_TRUE);
}

/**
*
*  write a page
*
**/
EC_BOOL cdc_page_write(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes)
{
    CDCNP_FNODE  *cdcnp_fnode;
    UINT32        page_num;
    UINT32        space_len;
    UINT32        data_len;
    uint32_t      path_hash;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode = __cdc_reserve_np(cdc_md, cdcnp_key);
    if(NULL_PTR == cdcnp_fnode)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write: reserve np failed\n");

        return (EC_FALSE);
    }

    path_hash = cdcnp_key_hash(cdcnp_key);

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cdcnp_fnode_init(cdcnp_fnode);
        CDCNP_FNODE_HASH(cdcnp_fnode) = path_hash;

        if(do_log(SEC_0182_CDC, 1))
        {
            sys_log(LOGSTDOUT, "warn:cdc_page_write: write with zero len to dn where fnode is \n");
            cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        }

        return (EC_TRUE);
    }

    /*note: when reserve space from data node, the length depends on cdcnp_key but not cbytes*/
    page_num  = (CDCNP_KEY_E_PAGE(cdcnp_key) - CDCNP_KEY_S_PAGE(cdcnp_key));
    space_len = (page_num << CDCPGB_PAGE_SIZE_NBITS);
    data_len  = DMIN(space_len, CBYTES_LEN(cbytes));/*xxx*/

    /*when fnode is duplicate, do not reserve data node anymore*/
    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        if(EC_FALSE == __cdc_reserve_hash_dn(cdc_md, data_len, path_hash, cdcnp_fnode))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write: reserve dn %ld bytes failed\n",
                            data_len);

            __cdc_release_np(cdc_md, cdcnp_key);

            return (EC_FALSE);
        }
        CDCNP_FNODE_HASH(cdcnp_fnode)   = path_hash;
    }
    else
    {
        /*when fnode is duplicate, update file size*/
        CDCNP_FNODE_FILESZ(cdcnp_fnode) = data_len;
    }

    if(EC_FALSE == cdc_export_dn(cdc_md, cbytes, cdcnp_fnode))
    {
        cdc_release_dn(cdc_md, cdcnp_fnode);

        __cdc_release_np(cdc_md, cdcnp_key);

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write: export content to dn failed\n");

        return (EC_FALSE);
    }

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_write: write to dn where fnode is \n");
        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_write_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;
    CDC_MD          *cdc_md;
    CDCNP_FNODE     *cdcnp_fnode;
    CDCNP_KEY       *cdcnp_key;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_page_write_aio_timeout: "
                  "page write timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md      = CDC_FILE_AIO_CDC_MD(cdc_file_aio);
    cdcnp_fnode = CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio);
    cdcnp_key   = CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio);

    cdc_release_dn(cdc_md, cdcnp_fnode);
    __cdc_release_np(cdc_md, cdcnp_key);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_write_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;
    CDC_MD          *cdc_md;
    CDCNP_FNODE     *cdcnp_fnode;
    CDCNP_KEY       *cdcnp_key;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_page_write_aio_terminate: "
                  "page write terminated\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md      = CDC_FILE_AIO_CDC_MD(cdc_file_aio);
    cdcnp_fnode = CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio);
    cdcnp_key   = CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio);

    cdc_release_dn(cdc_md, cdcnp_fnode);
    __cdc_release_np(cdc_md, cdcnp_key);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_write_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;
    CDCNP_FNODE     *cdcnp_fnode;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_page_write_aio_complete: "
                  "page write completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdcnp_fnode = CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio);

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cdc_page_write_aio_complete: write to dn where fnode is \n");
        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);
    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}


EC_BOOL cdc_page_write_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes, CAIO_CB *caio_cb)
{
    CDCNP_FNODE  *cdcnp_fnode;
    UINT32        page_num;
    UINT32        space_len;
    UINT32        data_len;
    uint32_t      path_hash;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode = __cdc_reserve_np(cdc_md, cdcnp_key);
    if(NULL_PTR == cdcnp_fnode)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_aio: reserve np failed\n");

        return (EC_FALSE);
    }

    path_hash = cdcnp_key_hash(cdcnp_key);

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cdcnp_fnode_init(cdcnp_fnode);
        CDCNP_FNODE_HASH(cdcnp_fnode) = path_hash;

        if(do_log(SEC_0182_CDC, 1))
        {
            sys_log(LOGSTDOUT, "warn:cdc_page_write_aio: write with zero len to dn where fnode is \n");
            cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        }

        return (EC_TRUE);
    }

    /*note: when reserve space from data node, the length depends on cdcnp_key but not cbytes*/
    page_num  = (CDCNP_KEY_E_PAGE(cdcnp_key) - CDCNP_KEY_S_PAGE(cdcnp_key));
    space_len = (page_num << CDCPGB_PAGE_SIZE_NBITS);
    data_len  = DMIN(space_len, CBYTES_LEN(cbytes));/*xxx*/

    /*when fnode is duplicate, do not reserve data node anymore*/
    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        if(EC_FALSE == __cdc_reserve_hash_dn(cdc_md, data_len, path_hash, cdcnp_fnode))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_aio: reserve dn %ld bytes failed\n",
                            data_len);

            __cdc_release_np(cdc_md, cdcnp_key);

            return (EC_FALSE);
        }
        CDCNP_FNODE_HASH(cdcnp_fnode)   = path_hash;
    }
    else
    {
        /*when fnode is duplicate, update file size*/
        CDCNP_FNODE_FILESZ(cdcnp_fnode) = data_len;
    }

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdc_export_dn(cdc_md, cbytes, cdcnp_fnode))
        {
            cdc_release_dn(cdc_md, cdcnp_fnode);

            __cdc_release_np(cdc_md, cdcnp_key);

            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_aio: export content to dn failed\n");

            return (EC_FALSE);
        }

        if(do_log(SEC_0182_CDC, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cdc_page_write_aio: write to dn where fnode is \n");
            cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        }
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDC_FILE_AIO    *cdc_file_aio;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)      = cdc_md;

        cdcnp_key_clone(cdcnp_key, CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio));
        cdcnp_fnode_clone(cdcnp_fnode, CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio));

        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_page_write_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_page_write_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_page_write_aio_complete, (void *)cdc_file_aio);

        if(EC_FALSE == cdc_export_dn_aio(cdc_md, cbytes, cdcnp_fnode, &caio_cb_t))
        {
            cdc_file_aio_free(cdc_file_aio);

            cdc_release_dn(cdc_md, cdcnp_fnode);

            __cdc_release_np(cdc_md, cdcnp_key);

            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_aio: export content to dn failed\n");

            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  read a page
*
**/
EC_BOOL cdc_page_read(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CBYTES *cbytes)
{
    CDCNP_FNODE   cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_read: read start\n");

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read: read from np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_read: read from np done\n");

    /*exception*/
    if(0 == CDCNP_FNODE_FILESZ(&cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read: read with zero len from np and fnode %p is \n", &cdcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cdc_read_dn(cdc_md, &cdcnp_fnode, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read: read from dn failed where fnode is \n");
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        return (EC_FALSE);
    }

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_read: read with size %ld done\n",
                            cbytes_len(cbytes));
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_read_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_page_read_aio_timeout: "
                  "page read timeout\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_read_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_page_read_aio_terminate: "
                  "page read terminate\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));;

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_read_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;
    CDCNP_FNODE     *cdcnp_fnode;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_page_read_aio_complete: "
                  "page read completed\n");

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdcnp_fnode = CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio);

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cdc_page_read_aio_complete: read to dn where fnode is \n");
        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);
    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdc_page_read_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CBYTES *cbytes, CAIO_CB *caio_cb)
{
    CDCNP_FNODE   cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio: read start\n");

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read_aio: read from np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio: read from np done\n");

    /*exception*/
    if(0 == CDCNP_FNODE_FILESZ(&cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read_aio: read with zero len from np and fnode %p is \n", &cdcnp_fnode);
        return (EC_TRUE);
    }

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdc_read_dn(cdc_md, &cdcnp_fnode, cbytes))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_aio: read from dn failed where fnode is \n");
            cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
            return (EC_FALSE);
        }

        if(do_log(SEC_0182_CDC, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cdc_page_read_aio: read with size %ld done\n",
                                cbytes_len(cbytes));
            cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        }
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDC_FILE_AIO    *cdc_file_aio;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)      = cdc_md;

        cdcnp_fnode_clone(&cdcnp_fnode, CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio));

        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_page_read_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_page_read_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_page_read_aio_complete, (void *)cdc_file_aio);

        if(EC_FALSE == cdc_read_dn_aio(cdc_md,
                                      CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio),
                                      cbytes,
                                      &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_aio: read from dn failed where fnode is \n");
            cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);

            cdc_file_aio_free(cdc_file_aio);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a page at offset
*
**/
EC_BOOL cdc_page_write_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CDCNP_FNODE   cdcnp_fnode;
    uint32_t      file_old_size;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e: read from np failed\n");
        return (EC_FALSE);
    }

    file_old_size = CDCNP_FNODE_FILESZ(&cdcnp_fnode);

    if(EC_FALSE == cdc_write_e_dn(cdc_md, &cdcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e: offset write to dn failed\n");
        return (EC_FALSE);
    }

    if(file_old_size != CDCNP_FNODE_FILESZ(&cdcnp_fnode))
    {
        if(EC_FALSE == cdcnp_update(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e: offset write to np failed\n");
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_write_e_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_page_write_e_aio_timeout: "
                  "write data from range [%ld, %ld), size %ld timeout\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_write_e_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_page_write_e_aio_terminate: "
                  "write data from range [%ld, %ld), size %ld terminated\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_page_write_e_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;
    CDC_MD          *cdc_md;
    CDCNP_FNODE     *cdcnp_fnode;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_page_write_e_aio_complete: "
                  "write data from range [%ld, %ld), size %ld completed\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio));

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));
    cdc_md      = CDC_FILE_AIO_CDC_MD(cdc_file_aio);
    cdcnp_fnode = CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio);

    if(CDC_FILE_AIO_F_OLD_SIZE(cdc_file_aio) != CDCNP_FNODE_FILESZ(cdcnp_fnode))
    {
        if(EC_FALSE == cdcnp_update(CDC_MD_NP(cdc_md), CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio), cdcnp_fnode))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_page_write_e_aio_complete: offset write to np failed\n");

            caio_cb_init(&caio_cb);
            caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

            cdc_file_aio_free(cdc_file_aio);
            caio_cb_exec_terminate_handler(&caio_cb);
            return (EC_FALSE);
        }
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);
    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdc_page_write_e_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes, CAIO_CB *caio_cb)
{
    CDCNP_FNODE   cdcnp_fnode;
    uint32_t      file_old_size;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e_aio: read from np failed\n");
        return (EC_FALSE);
    }

    file_old_size = CDCNP_FNODE_FILESZ(&cdcnp_fnode);

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdc_write_e_dn(cdc_md, &cdcnp_fnode, offset, max_len, cbytes))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e_aio: offset write to dn failed\n");
            return (EC_FALSE);
        }

        if(file_old_size != CDCNP_FNODE_FILESZ(&cdcnp_fnode))
        {
            if(EC_FALSE == cdcnp_update(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e_aio: offset write to np failed\n");
                return (EC_FALSE);
            }
        }
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDC_FILE_AIO    *cdc_file_aio;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)      = cdc_md;
        CDC_FILE_AIO_F_OLD_SIZE(cdc_file_aio)  = file_old_size;

        cdcnp_fnode_clone(&cdcnp_fnode, CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio));
        cdcnp_key_clone(cdcnp_key, CDC_FILE_AIO_CDCNP_KEY(cdc_file_aio));
        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_page_write_e_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_page_write_e_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_page_write_e_aio_complete, (void *)cdc_file_aio);

        /*send aio request*/
        if(EC_FALSE == cdc_write_e_dn_aio(cdc_md, CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio),
                                          offset, max_len, cbytes, &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e_aio: offset write to dn failed\n");
            cdc_file_aio_free(cdc_file_aio);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

/**
*
*  read a page from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL cdc_page_read_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CDCNP_FNODE   cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_e: read from np failed\n");
        return (EC_FALSE);
    }

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_read_e: read from np and fnode %p is \n",
                           &cdcnp_fnode);
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
    }

    /*exception*/
    if(0 == CDCNP_FNODE_FILESZ(&cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read_e: read with zero len from np and fnode %p is \n", &cdcnp_fnode);
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cdc_read_e_dn(cdc_md, &cdcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_e: offset read from dn failed where fnode is\n");
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_page_read_e_aio(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, CAIO_CB *caio_cb)
{
    CDCNP_FNODE   cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_e_aio: read from np failed\n");
        return (EC_FALSE);
    }

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_read_e_aio: read from np and fnode %p is \n",
                           &cdcnp_fnode);
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
    }

    /*exception*/
    if(0 == CDCNP_FNODE_FILESZ(&cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read_e_aio: read with zero len from np and fnode %p is \n", &cdcnp_fnode);
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        return (EC_TRUE);
    }

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdc_read_e_dn(cdc_md, &cdcnp_fnode, offset, max_len, cbytes))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_e_aio: offset read from dn failed where fnode is\n");
            cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
            return (EC_FALSE);
        }
    }
    else
    {
        if(EC_FALSE == cdc_read_e_dn_aio(cdc_md, &cdcnp_fnode, offset, max_len, cbytes, caio_cb))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_e_aio: offset read from dn failed where fnode is\n");
            cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL cdc_export_dn(CDC_MD *cdc_md, const CBYTES *cbytes, const CDCNP_FNODE *cdcnp_fnode)
{
    const CDCNP_INODE *cdcnp_inode;

    UINT32   offset;
    UINT32   data_len;
    //uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    data_len = DMIN(CBYTES_LEN(cbytes), CDCNP_FNODE_FILESZ(cdcnp_fnode));

    if(CDCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn: CBYTES_LEN %u or CDCNP_FNODE_FILESZ %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CDCNP_FNODE_FILESZ(cdcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    //size = (uint32_t)data_len;

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CDCPGB_PAGE_SIZE_NBITS));
    if(EC_FALSE == cdcdn_write_o(CDC_MD_DN(cdc_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn: write %ld bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    //dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_export_dn: write %ld bytes to disk %u block %u page %u done\n",
    //                    data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_export_dn_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_export_dn_aio_timeout: "
                  "write data to offset %ld, size %ld timeout, "
                  "offset reached %ld\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio),
                  CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_export_dn_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_export_dn_aio_terminate: "
                  "write data to offset %ld, size %ld terminated, "
                  "offset reached %ld\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio),
                  CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_export_dn_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_export_dn_aio_complete: "
                  "write data to offset %ld, size %ld completed, "
                  "offset reached %ld\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio),
                  CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio));

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);
    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdc_export_dn_aio(CDC_MD *cdc_md, const CBYTES *cbytes, const CDCNP_FNODE *cdcnp_fnode, CAIO_CB *caio_cb)
{
    const CDCNP_INODE *cdcnp_inode;

    UINT32   offset;
    UINT32   data_len;
    //uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    data_len = DMIN(CBYTES_LEN(cbytes), CDCNP_FNODE_FILESZ(cdcnp_fnode));

    if(CDCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn_aio: CBYTES_LEN %u or CDCNP_FNODE_FILESZ %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CDCNP_FNODE_FILESZ(cdcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn_aio: no dn was open\n");
        return (EC_FALSE);
    }

    //size = (uint32_t)data_len;

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CDCPGB_PAGE_SIZE_NBITS));
    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdcdn_write_o(CDC_MD_DN(cdc_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn_aio: write %ld bytes to disk %u block %u page %u failed\n",
                                data_len, disk_no, block_no, page_no);
            return (EC_FALSE);
        }
        //dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_export_dn_aio: write %ld bytes to disk %u block %u page %u done\n",
        //                    data_len, disk_no, block_no, page_no);
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDC_FILE_AIO    *cdc_file_aio;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn_e_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)      = cdc_md;
        CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio)  = offset;
        CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio)  = offset;
        CDC_FILE_AIO_M_BUFF(cdc_file_aio)      = CBYTES_BUF(cbytes);
        CDC_FILE_AIO_M_LEN(cdc_file_aio)       = data_len;

        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_export_dn_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_export_dn_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_export_dn_aio_complete, (void *)cdc_file_aio);


        if(EC_FALSE == cdcdn_write_o_aio(CDC_MD_DN(cdc_md),
                                         CDC_FILE_AIO_M_LEN(cdc_file_aio),
                                         CDC_FILE_AIO_M_BUFF(cdc_file_aio),
                                         disk_no, block_no,
                                         &CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio),
                                         caio_cb))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn_aio: write %ld bytes to disk %u block %u page %u failed\n",
                                data_len, disk_no, block_no, page_no);

            cdc_file_aio_free(cdc_file_aio);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL cdc_write_dn(CDC_MD *cdc_md, const CBYTES *cbytes, CDCNP_FNODE *cdcnp_fnode)
{
    CDCNP_INODE *cdcnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(CDCPGB_SIZE_NBYTES <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn: no dn was open\n");
        return (EC_FALSE);
    }

    cdcnp_fnode_init(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

    if(EC_FALSE == cdcdn_write_p(CDC_MD_DN(cdc_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CDCNP_INODE_DISK_NO(cdcnp_inode)    = disk_no;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = block_no;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = page_no;

    CDCNP_FNODE_FILESZ(cdcnp_fnode) = CBYTES_LEN(cbytes);
    CDCNP_FNODE_REPNUM(cdcnp_fnode) = 1;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_write_dn_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_write_dn_aio_timeout: "
                  "write data to offset %ld, size %ld timeout, "
                  "offset reached %ld\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio),
                  CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_write_dn_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_write_dn_aio_terminate: "
                  "write data to offset %ld, size %ld terminated, "
                  "offset reached %ld\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio),
                  CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_write_dn_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB          caio_cb;
    CDCNP_FNODE     *cdcnp_fnode_des;
    CDCNP_INODE     *cdcnp_inode_des;

    CDCNP_FNODE     *cdcnp_fnode_src;
    CDCNP_INODE     *cdcnp_inode_src;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_write_dn_aio_complete: "
                  "write data to offset %ld, size %ld completed, "
                  "offset reached %ld\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio),
                  CDC_FILE_AIO_F_C_OFFSET(cdc_file_aio));

    ASSERT(NULL_PTR != CDC_FILE_AIO_CDC_MD(cdc_file_aio));

    cdcnp_fnode_des = CDC_FILE_AIO_T_CDCNP_FNODE(cdc_file_aio);
    cdcnp_inode_des = CDCNP_FNODE_INODE(cdcnp_fnode_des, 0);

    cdcnp_fnode_src = CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio);
    cdcnp_inode_src = CDCNP_FNODE_INODE(cdcnp_fnode_src, 0);

    CDCNP_INODE_DISK_NO(cdcnp_inode_des)  = CDCNP_INODE_DISK_NO(cdcnp_inode_src);
    CDCNP_INODE_BLOCK_NO(cdcnp_inode_des) = CDCNP_INODE_BLOCK_NO(cdcnp_inode_src);
    CDCNP_INODE_PAGE_NO(cdcnp_inode_des)  = CDCNP_INODE_PAGE_NO(cdcnp_inode_src);

    CDCNP_FNODE_FILESZ(cdcnp_fnode_des) = CDC_FILE_AIO_M_LEN(cdc_file_aio);
    CDCNP_FNODE_REPNUM(cdcnp_fnode_des) = 1;

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);
    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdc_write_dn_aio(CDC_MD *cdc_md, const CBYTES *cbytes, CDCNP_FNODE *cdcnp_fnode, CAIO_CB *caio_cb)
{
    CDCNP_INODE *cdcnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(CDCPGB_SIZE_NBYTES <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn_aio: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn_aio: no dn was open\n");
        return (EC_FALSE);
    }

    cdcnp_fnode_init(cdcnp_fnode);

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

        if(EC_FALSE == cdcdn_write_p(CDC_MD_DN(cdc_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn_aio: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
            return (EC_FALSE);
        }

        CDCNP_INODE_DISK_NO(cdcnp_inode)    = disk_no;
        CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = block_no;
        CDCNP_INODE_PAGE_NO(cdcnp_inode)    = page_no;

        CDCNP_FNODE_FILESZ(cdcnp_fnode) = CBYTES_LEN(cbytes);
        CDCNP_FNODE_REPNUM(cdcnp_fnode) = 1;
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDC_FILE_AIO    *cdc_file_aio;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        cdcnp_inode = CDCNP_FNODE_INODE(CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio), 0);

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)           = cdc_md;
        CDC_FILE_AIO_T_CDCNP_FNODE(cdc_file_aio)    = cdcnp_fnode;
        CDC_FILE_AIO_M_BUFF(cdc_file_aio)           = CBYTES_BUF(cbytes);
        CDC_FILE_AIO_M_LEN(cdc_file_aio)            = CBYTES_LEN(cbytes);

        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_write_dn_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_write_dn_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_write_dn_aio_complete, (void *)cdc_file_aio);

        if(EC_FALSE == cdcdn_write_p_aio(CDC_MD_DN(cdc_md),
                                          CDC_FILE_AIO_M_LEN(cdc_file_aio),
                                          CDC_FILE_AIO_M_BUFF(cdc_file_aio),
                                          &CDCNP_INODE_DISK_NO(cdcnp_inode),
                                          &CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                          &CDCNP_INODE_PAGE_NO(cdcnp_inode),
                                          &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn_aio: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
            cdc_file_aio_free(cdc_file_aio);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL cdc_read_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, CBYTES *cbytes)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = CDCNP_FNODE_FILESZ(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    //dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

#if 0
    if(0 == CBYTES_LEN(cbytes))/*scenario: cbytes is not initialized*/
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CDC_0006);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CDC_0007);
        CBYTES_LEN(cbytes) = 0;
    }

    else if(CBYTES_LEN(cbytes) < (UINT32)file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: cbytes len %ld < file size %ld\n",
                        CBYTES_LEN(cbytes), (UINT32)file_size);
        return (EC_FALSE);
    }
#endif
#if 1
    ASSERT(0 < CBYTES_LEN(cbytes));

    if(CBYTES_LEN(cbytes) < (UINT32)file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: cbytes len %ld < file size %ld\n",
                        CBYTES_LEN(cbytes), (UINT32)file_size);
        return (EC_FALSE);
    }
#endif
    if(EC_FALSE == cdcdn_read_p(CDC_MD_DN(cdc_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                           file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_read_dn_aio(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, CBYTES *cbytes, CAIO_CB *caio_cb)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = CDCNP_FNODE_FILESZ(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    //dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

#if 0
    if(0 == CBYTES_LEN(cbytes))/*scenario: cbytes is not initialized*/
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CDC_0008);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CDC_0009);
        CBYTES_LEN(cbytes) = 0;
    }

    else if(CBYTES_LEN(cbytes) < (UINT32)file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: cbytes len %ld < file size %ld\n",
                        CBYTES_LEN(cbytes), (UINT32)file_size);
        return (EC_FALSE);
    }
#endif
#if 1
    ASSERT(0 < CBYTES_LEN(cbytes));

    if(CBYTES_LEN(cbytes) < (UINT32)file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: cbytes len %ld < file size %ld\n",
                        CBYTES_LEN(cbytes), (UINT32)file_size);
        return (EC_FALSE);
    }
#endif

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdcdn_read_p(CDC_MD_DN(cdc_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                               file_size, disk_no, block_no, page_no);
            return (EC_FALSE);
        }
    }
    else
    {
        if(EC_FALSE == cdcdn_read_p_aio(CDC_MD_DN(cdc_md),
                                        disk_no, block_no, page_no, file_size,
                                        CBYTES_BUF(cbytes),
                                        &(CBYTES_LEN(cbytes)),
                                        caio_cb))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                               file_size, disk_no, block_no, page_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cdc_write_e_dn(CDC_MD *cdc_md, CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint32_t file_max_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    if(CDCPGB_SIZE_NBYTES <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: offset %ld + buff len (or file size) %ld = %ld overflow\n",
                            (*offset), CBYTES_LEN(cbytes), (*offset) + CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size   = CDCNP_FNODE_FILESZ(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS) << CDCPGB_PAGE_SIZE_NBITS);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: offset %ld overflow due to file max size is %u\n", (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(EC_FALSE == cdcdn_write_e(CDC_MD_DN(cdc_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    (*offset) += max_len_t;
    if((*offset) > file_size)
    {
        /*update file size info*/
        CDCNP_FNODE_FILESZ(cdcnp_fnode) = (uint32_t)(*offset);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_write_e_dn_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_write_e_dn_aio_timeout: "
                  "write data from range [%ld, %ld), size %ld timeout\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_write_e_dn_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_write_e_dn_aio_terminate: "
                  "write data from range [%ld, %ld), size %ld terminated\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_write_e_dn_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_write_e_dn_aio_complete: "
                  "write data from range [%ld, %ld), size %ld completed\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_M_LEN(cdc_file_aio));

    if(NULL_PTR != CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio))
    {
        CDCNP_FNODE         *cdcnp_fnode;;

        cdcnp_fnode = CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio);

        (*CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)) += CDC_FILE_AIO_M_LEN(cdc_file_aio);

        if((*CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)) > CDCNP_FNODE_FILESZ(cdcnp_fnode))
        {
            /*update file size info*/
            CDCNP_FNODE_FILESZ(cdcnp_fnode) = (uint32_t)(*CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio));
        }
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdc_write_e_dn_aio(CDC_MD *cdc_md, CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes, CAIO_CB *caio_cb)
{
    CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint32_t file_max_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    if(CDCPGB_SIZE_NBYTES <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn_aio: offset %ld + buff len (or file size) %ld = %ld overflow\n",
                            (*offset), CBYTES_LEN(cbytes), (*offset) + CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn_aio: no dn was open\n");
        return (EC_FALSE);
    }

    file_size   = CDCNP_FNODE_FILESZ(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS) << CDCPGB_PAGE_SIZE_NBITS);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn_aio: offset %ld overflow due to file max size is %u\n", (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdcdn_write_e(CDC_MD_DN(cdc_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn_aio: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
            return (EC_FALSE);
        }

        (*offset) += max_len_t;
        if((*offset) > file_size)
        {
            /*update file size info*/
            CDCNP_FNODE_FILESZ(cdcnp_fnode) = (uint32_t)(*offset);
        }
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDC_FILE_AIO    *cdc_file_aio;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)      = cdc_md;
        CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)  = offset;
        CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio)  = offset_t;
        CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio)  = offset_t + max_len_t;
        CDC_FILE_AIO_M_BUFF(cdc_file_aio)      = CBYTES_BUF(cbytes);
        CDC_FILE_AIO_M_LEN(cdc_file_aio)       = max_len_t;

        cdcnp_fnode_clone(cdcnp_fnode, CDC_FILE_AIO_CDCNP_FNODE(cdc_file_aio));
        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_write_e_dn_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_write_e_dn_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_write_e_dn_aio_complete, (void *)cdc_file_aio);

        /*send aio request*/
        if(EC_FALSE == cdcdn_write_e_aio(CDC_MD_DN(cdc_md), max_len_t,
                                        CBYTES_BUF(cbytes),
                                        disk_no, block_no, page_no, offset_t,
                                        &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn_aio: "
                                                "write %ld bytes from disk %u, block %u, offset %u failed\n",
                                                max_len_t, disk_no, block_no, offset_t);
            cdc_file_aio_free(cdc_file_aio);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cdc_read_e_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = CDCNP_FNODE_FILESZ(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: due to offset %ld >= file size %u\n", (*offset), file_size);
        return (EC_FALSE);
    }

    offset_t = (uint32_t)(*offset);
    if(0 == max_len)
    {
        max_len_t = file_size - offset_t;
    }
    else
    {
        max_len_t = DMIN(max_len, file_size - offset_t);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_read_e_dn: file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

#if 0
    if(0 == CBYTES_LEN(cbytes))/*scenario: cbytes is not initialized*/
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CDC_0010);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CDC_0011);
        CBYTES_LEN(cbytes) = 0;
    }

    else if(CBYTES_LEN(cbytes) < max_len_t)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: cbytes len %ld < max len %ld\n",
                        CBYTES_LEN(cbytes), max_len_t);
        return (EC_FALSE);
    }
#endif
#if 1
    ASSERT(0 < CBYTES_LEN(cbytes));
    if(CBYTES_LEN(cbytes) < max_len_t)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: cbytes len %ld < max len %ld\n",
                        CBYTES_LEN(cbytes), max_len_t);
        return (EC_FALSE);
    }
#endif
    if(EC_FALSE == cdcdn_read_e(CDC_MD_DN(cdc_md), disk_no, block_no, page_no, offset_t, max_len_t,
                                CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: read %ld bytes from disk %u, block %u, offset %u failed\n",
                           max_len_t, disk_no, block_no, offset_t);
        return (EC_FALSE);
    }

    (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_read_e_dn_aio_timeout(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_read_e_dn_aio_timeout: "
                  "read data from range [%ld, %ld), size %ld timeout\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio) - CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_read_e_dn_aio_terminate(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_read_e_dn_aio_terminate: "
                  "read data from range [%ld, %ld), size %ld terminated\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio) - CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_read_e_dn_aio_complete(CDC_FILE_AIO *cdc_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] __cdc_read_e_dn_aio_complete: "
                  "read data from range [%ld, %ld), size %ld completed\n",
                  CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio), CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio),
                  CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio) - CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio));

    if(NULL_PTR != CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio))
    {
        (*CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio)) = CDC_FILE_AIO_M_LEN(cdc_file_aio);
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDC_FILE_AIO_CAIO_CB(cdc_file_aio), &caio_cb);

    cdc_file_aio_free(cdc_file_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdc_read_e_dn_aio(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, CAIO_CB *caio_cb)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn_aio: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn_aio: no replica\n");
        return (EC_FALSE);
    }

    file_size   = CDCNP_FNODE_FILESZ(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn_aio: due to offset %ld >= file size %u\n", (*offset), file_size);
        return (EC_FALSE);
    }

    offset_t = (uint32_t)(*offset);
    if(0 == max_len)
    {
        max_len_t = file_size - offset_t;
    }
    else
    {
        max_len_t = DMIN(max_len, file_size - offset_t);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_read_e_dn_aio: file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    ASSERT(0 < CBYTES_LEN(cbytes));
    if(CBYTES_LEN(cbytes) < max_len_t)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn_aio: cbytes len %ld < max len %ld\n",
                        CBYTES_LEN(cbytes), max_len_t);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        if(EC_FALSE == cdcdn_read_e(CDC_MD_DN(cdc_md), disk_no, block_no, page_no, offset_t, max_len_t,
                                    CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn_aio: read %ld bytes from disk %u, block %u, offset %u failed\n",
                               max_len_t, disk_no, block_no, offset_t);
            return (EC_FALSE);
        }

        (*offset) += CBYTES_LEN(cbytes);
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDC_FILE_AIO    *cdc_file_aio;

        /*set cdc file aio*/
        cdc_file_aio = cdc_file_aio_new();
        if(NULL_PTR == cdc_file_aio)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn_aio: "
                                                "new cdc_file_aio failed\n");

            return (EC_FALSE);
        }

        CDC_FILE_AIO_CDC_MD(cdc_file_aio)     = cdc_md;
        CDC_FILE_AIO_F_I_OFFSET(cdc_file_aio) = offset;
        CDC_FILE_AIO_F_S_OFFSET(cdc_file_aio) = offset_t;
        CDC_FILE_AIO_F_E_OFFSET(cdc_file_aio) = offset_t + max_len_t;
        CDC_FILE_AIO_M_BUFF(cdc_file_aio)     = CBYTES_BUF(cbytes);
        CDC_FILE_AIO_M_LEN(cdc_file_aio)      = CBYTES_LEN(cbytes);
        caio_cb_clone(caio_cb, CDC_FILE_AIO_CAIO_CB(cdc_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDC_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdc_read_e_dn_aio_timeout, (void *)cdc_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_read_e_dn_aio_terminate, (void *)cdc_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdc_read_e_dn_aio_complete, (void *)cdc_file_aio);

        /*send aio request*/
        if(EC_FALSE == cdcdn_read_e_aio(CDC_MD_DN(cdc_md), disk_no, block_no, page_no, offset_t, max_len_t,
                                    CDC_FILE_AIO_M_BUFF(cdc_file_aio),
                                    &(CDC_FILE_AIO_M_LEN(cdc_file_aio)),
                                    &caio_cb_t))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn_aio: "
                                                "read %ld bytes from disk %u, block %u, offset %u failed\n",
                                                max_len_t, disk_no, block_no, offset_t);
            cdc_file_aio_free(cdc_file_aio);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}


/**
*
*  delete all intersected file
*
**/
EC_BOOL cdc_delete_intersected(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ITEM       *cdcnp_item_intersected;
    CDCNP_KEY        *cdcnp_key_intersected;
    uint32_t          node_pos_intersected;

    if(EC_FALSE == cdcnp_key_is_valid(cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_delete_intersected: invalid key [%ld, %ld)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_delete_intersected: np was not open\n");
        return (EC_FALSE);
    }

    node_pos_intersected = cdcnp_find_intersected(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS == node_pos_intersected)
    {
        /*not found*/
        return (EC_TRUE);
    }

    cdcnp_item_intersected = cdcnp_fetch(CDC_MD_NP(cdc_md), node_pos_intersected);
    if(NULL_PTR == cdcnp_item_intersected)
    {
        return (EC_FALSE);
    }

    cdcnp_key_intersected = CDCNP_ITEM_KEY(cdcnp_item_intersected);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_delete_intersected: key [%u, %u), intersected [%u, %u) => delete\n",
                       CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key),
                       CDCNP_KEY_S_PAGE(cdcnp_key_intersected), CDCNP_KEY_E_PAGE(cdcnp_key_intersected));

    if(EC_FALSE == cdcnp_umount_item(CDC_MD_NP(cdc_md), node_pos_intersected))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_delete_intersected: umount failed\n");
        return (EC_FALSE);
    }

    if(CDCNP_KEY_S_PAGE(cdcnp_key) >= CDCNP_KEY_S_PAGE(cdcnp_key_intersected))
    {
        if(CDCNP_KEY_E_PAGE(cdcnp_key) >= CDCNP_KEY_E_PAGE(cdcnp_key_intersected))
        {
            CDCNP_KEY  cdcnp_key_next;

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key_intersected);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key);

            cdc_delete_intersected(cdc_md, &cdcnp_key_next);

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key_intersected);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key);

            cdc_delete_intersected(cdc_md, &cdcnp_key_next);
        }
        else
        {
            /*no next*/
        }
    }
    else
    {
        if(CDCNP_KEY_E_PAGE(cdcnp_key) >= CDCNP_KEY_E_PAGE(cdcnp_key_intersected))
        {
            CDCNP_KEY  cdcnp_key_next;

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key_intersected);

            cdc_delete_intersected(cdc_md, &cdcnp_key_next);

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key_intersected);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_E_PAGE(cdcnp_key);

            cdc_delete_intersected(cdc_md, &cdcnp_key_next);
        }
        else
        {
            CDCNP_KEY  cdcnp_key_next;

            CDCNP_KEY_S_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key);
            CDCNP_KEY_E_PAGE(&cdcnp_key_next) = CDCNP_KEY_S_PAGE(cdcnp_key_intersected);

            cdc_delete_intersected(cdc_md, &cdcnp_key_next);
        }
    }

    return (EC_TRUE);
}

/**
*
*  delete a page
*
**/
EC_BOOL cdc_page_delete(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    uint32_t     node_pos;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_delete: np was not open\n");
        return (EC_FALSE);
    }

    node_pos = cdcnp_search(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS == node_pos)
    {
        /*not found*/

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_delete: cdc %p, not found key [%u, %u)\n",
                            cdc_md, CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));

        return (EC_TRUE);
    }

    if(EC_FALSE == cdcnp_umount_item(CDC_MD_NP(cdc_md), node_pos))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_delete: umount failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_delete: cdc %p, key [%u, %u) done\n",
                        cdc_md, CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));

    return (EC_TRUE);
}

/**
*
*  update a page
*
**/
EC_BOOL cdc_page_update(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes)
{
    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == cdc_page_write(cdc_md, cdcnp_key, cbytes))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_update: write failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_update: write done\n");
        return (EC_TRUE);
    }

    /*file exist, update it*/
    if(EC_FALSE == cdc_page_delete(cdc_md, cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_update: delete old failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_update: delete old done\n");

    if(EC_FALSE == cdc_page_write(cdc_md, cdcnp_key, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_update: write new failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_update: write new done\n");

    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cdc_file_num(CDC_MD *cdc_md, UINT32 *file_num)
{
    uint32_t     file_num_t;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_file_num: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_file_num(CDC_MD_NP(cdc_md), &file_num_t))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_num: get file num of key failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != file_num)
    {
        (*file_num) = file_num_t;
    }
    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cdc_file_size(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *file_size)
{
    if(EC_FALSE == cdcnp_key_is_valid(cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_size: invalid key [%ld, %ld)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_file_size: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_file_size(CDC_MD_NP(cdc_md), cdcnp_key, file_size))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_size: cdcnp mgr get size of key [%ld, %ld) failed\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_size: key [%ld, %ld), size %ld\n",
                    CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key), (*file_size));
    return (EC_TRUE);
}

/**
*
*  search in current name node
*
**/
EC_BOOL cdc_search(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    if(EC_FALSE == cdcnp_key_is_valid(cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_search: invalid key [%ld, %ld)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_search: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_search: miss key [%ld, %ld)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(CDCNPRB_ERR_POS == cdcnp_search(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_search: search failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL cdc_recycle(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num)
{
    CDCNP_RECYCLE_DN cdcnp_recycle_dn;
    UINT32           complete_recycle_num;

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] cdc_recycle: recycle beg\n");

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_recycle: np was not open\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_recycle: cdc is loading\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_recycle: cdc is flushing\n");
        return (EC_FALSE);
    }

    CDCNP_RECYCLE_DN_ARG1(&cdcnp_recycle_dn)   = (void *)cdc_md;
    CDCNP_RECYCLE_DN_FUNC(&cdcnp_recycle_dn)   = (CDCNP_RECYCLE_DN_FUNC)cdc_release_dn;

    complete_recycle_num = 0;/*initialization*/

    if(EC_FALSE == cdcnp_recycle(CDC_MD_NP(cdc_md),  max_num, NULL_PTR, &cdcnp_recycle_dn, &complete_recycle_num))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_recycle: recycle np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "[DEBUG] cdc_recycle: recycle end where complete %ld\n", complete_recycle_num);

    if(NULL_PTR != complete_num)
    {
        (*complete_num) = complete_recycle_num;
    }
    return (EC_TRUE);
}

/**
*
*  retire files
*
**/
EC_BOOL cdc_retire(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num)
{
    UINT32      complete_retire_num;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_retire: np was not open\n");
        return (EC_FALSE);
    }

    complete_retire_num = 0;/*initialization*/

    cdcnp_retire(CDC_MD_NP(cdc_md), max_num, &complete_retire_num);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_retire: retire done where complete %ld\n", complete_retire_num);

    if(NULL_PTR != complete_num)
    {
        (*complete_num) = complete_retire_num;
    }

    return (EC_TRUE);
}

/**
*
*  show name node
*
*
**/
EC_BOOL cdc_show_np(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is loading)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is flushing)\n");
        return (EC_TRUE);
    }

    cdcnp_print(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show name node LRU
*
*
**/
EC_BOOL cdc_show_np_lru_list(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is loading)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is flushing)\n");
        return (EC_TRUE);
    }

    cdcnp_print_lru_list(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cdc_show_np_del_list(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is loading)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is flushing)\n");
        return (EC_TRUE);
    }

    cdcnp_print_del_list(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show name node BITMAP
*
*
**/
EC_BOOL cdc_show_np_bitmap(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is loading)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is flushing)\n");
        return (EC_TRUE);
    }

    cdcnp_print_bitmap(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show cdcdn info if it is dn
*
*
**/
EC_BOOL cdc_show_dn(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is loading)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is flushing)\n");
        return (EC_TRUE);
    }

    cdcdn_print(log, CDC_MD_DN(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show all files
*
**/

EC_BOOL cdc_show_files(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_show_files: np was not open\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_LOADING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is loading)\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CDC_MD_FLUSHING_FLAG(cdc_md))
    {
        sys_log(log, "(cdc is flushing)\n");
        return (EC_TRUE);
    }

    cdcnp_walk(CDC_MD_NP(cdc_md), (CDCNPRB_WALKER)cdcnp_file_print, (void *)log);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_show_files: walk cdcnp done\n");
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

