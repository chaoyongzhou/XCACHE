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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "real.h"

#include "cdcdn.h"
#include "cdcpgrb.h"
#include "cdcpgb.h"
#include "cdcpgd.h"
#include "cdcpgv.h"

#include "caio.h"

CDCDN_AIO *cdcdn_aio_new()
{
    CDCDN_AIO *cdcdn_aio;

    alloc_static_mem(MM_CDCDN_AIO, &cdcdn_aio, LOC_CDCDN_0001);
    if(NULL_PTR != cdcdn_aio)
    {
        cdcdn_aio_init(cdcdn_aio);
        return (cdcdn_aio);
    }
    return (cdcdn_aio);
}

EC_BOOL cdcdn_aio_init(CDCDN_AIO *cdcdn_aio)
{
    CDCDN_AIO_CDCDN(cdcdn_aio)     = NULL_PTR;
    CDCDN_AIO_S_OFFSET(cdcdn_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_AIO_E_OFFSET(cdcdn_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_AIO_C_OFFSET(cdcdn_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_AIO_M_BUFF(cdcdn_aio)    = NULL_PTR;

    caio_cb_init(CDCDN_AIO_CAIO_CB(cdcdn_aio));

    return (EC_TRUE);
}

EC_BOOL cdcdn_aio_clean(CDCDN_AIO *cdcdn_aio)
{
    CDCDN_AIO_CDCDN(cdcdn_aio)     = NULL_PTR;
    CDCDN_AIO_S_OFFSET(cdcdn_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_AIO_E_OFFSET(cdcdn_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_AIO_C_OFFSET(cdcdn_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_AIO_M_BUFF(cdcdn_aio)    = NULL_PTR;

    caio_cb_clean(CDCDN_AIO_CAIO_CB(cdcdn_aio));
    return (EC_TRUE);
}

EC_BOOL cdcdn_aio_free(CDCDN_AIO *cdcdn_aio)
{
    if(NULL_PTR != cdcdn_aio)
    {
        cdcdn_aio_clean(cdcdn_aio);
        free_static_mem(MM_CDCDN_AIO, cdcdn_aio, LOC_CDCDN_0002);
    }
    return (EC_TRUE);
}

void cdcdn_aio_print(LOG *log, const CDCDN_AIO *cdcdn_aio)
{
    if(NULL_PTR != cdcdn_aio)
    {
        sys_log(log, "cdcdn_aio_print: cdcdn_aio %p: range [%ld, %ld), reached %ld\n",
                     cdcdn_aio,
                     CDCDN_AIO_S_OFFSET(cdcdn_aio),
                     CDCDN_AIO_E_OFFSET(cdcdn_aio),
                     CDCDN_AIO_C_OFFSET(cdcdn_aio));
    }
    return;
}

CDCDN_FILE_AIO *cdcdn_file_aio_new()
{
    CDCDN_FILE_AIO *cdcdn_file_aio;

    alloc_static_mem(MM_CDCDN_FILE_AIO, &cdcdn_file_aio, LOC_CDCDN_0003);
    if(NULL_PTR != cdcdn_file_aio)
    {
        cdcdn_file_aio_init(cdcdn_file_aio);
        return (cdcdn_file_aio);
    }
    return (cdcdn_file_aio);
}

EC_BOOL cdcdn_file_aio_init(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio)       = NULL_PTR;
    CDCDN_FILE_AIO_NODE_ID(cdcdn_file_aio)     = CDCDN_NODE_ERR_ID;
    CDCDN_FILE_AIO_FD(cdcdn_file_aio)          = ERR_FD;
    CDCDN_FILE_AIO_I_DATA_LEN(cdcdn_file_aio)  = NULL_PTR;
    CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio)  = NULL_PTR;
    CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_FILE_AIO_M_BUFF(cdcdn_file_aio)      = NULL_PTR;

    CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio)   = CDCPGRB_ERR_POS;
    CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio)  = CDCPGRB_ERR_POS;
    CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio)   = CDCPGRB_ERR_POS;
    CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio)      = 0;

    caio_cb_init(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio));

    return (EC_TRUE);
}

EC_BOOL cdcdn_file_aio_clean(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio)       = NULL_PTR;
    CDCDN_FILE_AIO_NODE_ID(cdcdn_file_aio)     = CDCDN_NODE_ERR_ID;
    CDCDN_FILE_AIO_FD(cdcdn_file_aio)          = ERR_FD;
    CDCDN_FILE_AIO_I_DATA_LEN(cdcdn_file_aio)  = NULL_PTR;
    CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio)  = NULL_PTR;
    CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio)  = CDCDN_NODE_ERR_OFFSET;
    CDCDN_FILE_AIO_M_BUFF(cdcdn_file_aio)      = NULL_PTR;

    CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio)   = CDCPGRB_ERR_POS;
    CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio)  = CDCPGRB_ERR_POS;
    CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio)   = CDCPGRB_ERR_POS;
    CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio)      = 0;

    caio_cb_clean(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio));

    return (EC_TRUE);
}

EC_BOOL cdcdn_file_aio_free(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    if(NULL_PTR != cdcdn_file_aio)
    {
        cdcdn_file_aio_clean(cdcdn_file_aio);
        free_static_mem(MM_CDCDN_FILE_AIO, cdcdn_file_aio, LOC_CDCDN_0004);
    }
    return (EC_TRUE);
}

void cdcdn_file_aio_print(LOG *log, const CDCDN_FILE_AIO *cdcdn_file_aio)
{
    if(NULL_PTR != cdcdn_file_aio)
    {
        sys_log(log, "cdcdn_file_aio_print: cdcdn_file_aio %p: range [%ld, %ld), reached %ld\n",
                     cdcdn_file_aio,
                     CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                     CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio),
                     CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio));
    }
    return;
}

/*Data Node*/
UINT32 cdcdn_node_fetch(const CDCDN *cdcdn, const UINT32 node_id)
{
    UINT32      node_id_t;

    node_id_t = (node_id >> CDCDN_SEG_NO_NBITS);
    if(node_id_t >= CDCDN_NODE_NUM(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_fetch: node_id %ld overflow\n", node_id);
        return (CDCDN_NODE_ERR_OFFSET);
    }

    return (CDCDN_NODE_S_OFFSET(cdcdn) + (node_id_t << CDCDN_NODE_SIZE_NBITS));
}

EC_BOOL cdcdn_node_write(CDCDN *cdcdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset)
{
    UINT32       offset_n; /*offset of cdcdn_node*/
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/
    UINT32       offset_f; /*real offset in file*/

    offset_n = cdcdn_node_fetch(cdcdn, node_id);
    if(CDCDN_NODE_ERR_OFFSET == offset_n)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_write: open node %ld failed\n",
                                              node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CDCDN_NODE_ID_GET_SEG_NO(node_id)) << CDCPGB_SIZE_NBITS);
    offset_r = offset_b + (*offset);

    //BCOPY(data_buff, cdcdn_node + offset_r, data_max_len);

    offset_f = offset_n + offset_r;

    if(EC_FALSE == c_file_write(CDCDN_NODE_FD(cdcdn), &offset_f, data_max_len, data_buff))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_write: "
                                              "write node %ld to offset %ld, size %ld failed\n",
                                              node_id, offset_f, data_max_len);
        return (EC_FALSE);
    }

    (*offset) += data_max_len;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_node_write_aio_timeout(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_node_write_aio_timeout: "
                  "write data to offset %ld, size %ld timeout, "
                  "offset reaches %ld v.s. expected %ld\n",
                  CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_node_write_aio_terminate(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_node_write_aio_terminate: "
                  "write data to offset %ld, size %ld terminated, "
                  "offset reaches %ld v.s. expected %ld\n",
                  CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_node_write_aio_complete(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 1)(LOGSTDOUT, "[DEBUG] __cdcdn_node_write_aio_complete: "
                  "write data to offset %ld, size %ld completed, "
                  "offset reaches %ld v.s. expected %ld\n",
                  CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio));

    if(NULL_PTR != CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio))
    {
        (*CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio)) = CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio);
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdcdn_node_write_aio(CDCDN *cdcdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset, CAIO_CB *caio_cb)
{
    UINT32       offset_n; /*offset of cdcdn_node*/
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/
    UINT32       offset_f; /*real offset in file*/

    offset_n = cdcdn_node_fetch(cdcdn, node_id);
    if(CDCDN_NODE_ERR_OFFSET == offset_n)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_write_aio: open node %ld failed\n",
                                              node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CDCDN_NODE_ID_GET_SEG_NO(node_id)) << CDCPGB_SIZE_NBITS);
    offset_r = offset_b + (*offset);

    //BCOPY(data_buff, cdcdn_node + offset_r, data_max_len);

    offset_f = offset_n + offset_r;

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        if(EC_FALSE == c_file_write(CDCDN_NODE_FD(cdcdn), &offset_f, data_max_len, data_buff))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_write_aio: "
                                                  "write node %ld to offset %ld, size %ld failed\n",
                                                  node_id, offset_f, data_max_len);
            return (EC_FALSE);
        }

        (*offset) += data_max_len;
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDCDN_FILE_AIO  *cdcdn_file_aio;

        /*set cdcdn file aio*/
        cdcdn_file_aio = cdcdn_file_aio_new();
        if(NULL_PTR == cdcdn_file_aio)
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_write_aio: "
                                                  "new cdcdn_file_aio failed\n");

            return (EC_FALSE);
        }

        CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio)      = cdcdn;
        CDCDN_FILE_AIO_NODE_ID(cdcdn_file_aio)    = node_id;
        CDCDN_FILE_AIO_FD(cdcdn_file_aio)         = CDCDN_NODE_FD(cdcdn);
        CDCDN_FILE_AIO_I_DATA_LEN(cdcdn_file_aio) = NULL_PTR;
        CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio) = offset;
        CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio) = offset_f;
        CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) = offset_f + data_max_len;
        CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio) = offset_f;
        CDCDN_FILE_AIO_M_BUFF(cdcdn_file_aio)     = (UINT8 *)data_buff;
        caio_cb_clone(caio_cb, CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCDN_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdcdn_node_write_aio_timeout, (void *)cdcdn_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_node_write_aio_terminate, (void *)cdcdn_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_node_write_aio_complete, (void *)cdcdn_file_aio);

        /*send aio request*/
        caio_file_write(CDCDN_NODE_CAIO_MD(cdcdn), CDCDN_NODE_FD(cdcdn),
                        &CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                        CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                        CDCDN_FILE_AIO_M_BUFF(cdcdn_file_aio),
                        &caio_cb_t);
    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_node_read(CDCDN *cdcdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset)
{
    UINT32       offset_n; /*offset of cdcdn_node*/
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/
    UINT32       offset_f; /*real offset in file*/

    offset_n = cdcdn_node_fetch(cdcdn, node_id);
    if(CDCDN_NODE_ERR_OFFSET == offset_n)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_read: open node %ld failed\n",
                                              node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CDCDN_NODE_ID_GET_SEG_NO(node_id)) << CDCPGB_SIZE_NBITS);
    offset_r = offset_b + (*offset);

    //BCOPY(cdcdn_node + offset_r, data_buff, data_max_len);

    offset_f = offset_n + offset_r;
    if(EC_FALSE == c_file_read(CDCDN_NODE_FD(cdcdn), &offset_f, data_max_len, data_buff))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_read: "
                                              "read node %ld from offset %ld, size %ld failed\n",
                                              node_id, offset_f, data_max_len);
        return (EC_FALSE);
    }

    (*offset) += data_max_len;
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_node_read_aio_timeout(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_node_read_aio_timeout: "
                  "read data from offset %ld, size %ld timeout, "
                  "offset reaches %ld v.s. expected %ld\n",
                  CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_node_read_aio_terminate(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_node_read_aio_terminate: "
                  "read data from offset %ld, size %ld terminated, "
                  "offset reaches %ld v.s. expected %ld\n",
                  CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_node_read_aio_complete(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 1)(LOGSTDOUT, "[DEBUG] __cdcdn_node_read_aio_complete: "
                  "read data from offset %ld, size %ld completed, "
                  "offset reaches %ld v.s. expected %ld\n",
                  CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                  CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio));

    if(NULL_PTR != CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio))
    {
        (*CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio)) = CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio);
    }

    if(NULL_PTR != CDCDN_FILE_AIO_I_DATA_LEN(cdcdn_file_aio))
    {
        (*CDCDN_FILE_AIO_I_DATA_LEN(cdcdn_file_aio)) =
            CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio);
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdcdn_node_read_aio(CDCDN *cdcdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset, CAIO_CB *caio_cb)
{
    UINT32       offset_n; /*offset of cdcdn_node*/
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/
    UINT32       offset_f; /*real offset in file*/

    offset_n = cdcdn_node_fetch(cdcdn, node_id);
    if(CDCDN_NODE_ERR_OFFSET == offset_n)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_read_aio: open node %ld failed\n",
                                              node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CDCDN_NODE_ID_GET_SEG_NO(node_id)) << CDCPGB_SIZE_NBITS);
    offset_r = offset_b + (*offset);

    //BCOPY(cdcdn_node + offset_r, data_buff, data_max_len);

    offset_f = offset_n + offset_r;

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        if(EC_FALSE == c_file_read(CDCDN_NODE_FD(cdcdn), &offset_f, data_max_len, data_buff))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_read_aio: "
                                                  "read node %ld from offset %ld, size %ld failed\n",
                                                  node_id, offset_f, data_max_len);
            return (EC_FALSE);
        }

        (*offset) += data_max_len;
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDCDN_FILE_AIO  *cdcdn_file_aio;

        /*set cdcdn file aio*/
        cdcdn_file_aio = cdcdn_file_aio_new();
        if(NULL_PTR == cdcdn_file_aio)
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_read_aio: "
                                                  "new cdcdn_file_aio failed\n");

            return (EC_FALSE);
        }

        CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio)      = cdcdn;
        CDCDN_FILE_AIO_NODE_ID(cdcdn_file_aio)    = node_id;
        CDCDN_FILE_AIO_FD(cdcdn_file_aio)         = CDCDN_NODE_FD(cdcdn);
        CDCDN_FILE_AIO_I_DATA_LEN(cdcdn_file_aio) = NULL_PTR;
        CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio) = offset;
        CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio) = offset_f;
        CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) = offset_f + data_max_len;
        CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio) = offset_f;
        CDCDN_FILE_AIO_M_BUFF(cdcdn_file_aio)     = data_buff;
        caio_cb_clone(caio_cb, CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCDN_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdcdn_node_read_aio_timeout, (void *)cdcdn_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_node_read_aio_terminate, (void *)cdcdn_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_node_read_aio_complete, (void *)cdcdn_file_aio);

        /*send aio request*/
        caio_file_read(CDCDN_NODE_CAIO_MD(cdcdn), CDCDN_NODE_FD(cdcdn),
                        &CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio),
                        CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) - CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio),
                        CDCDN_FILE_AIO_M_BUFF(cdcdn_file_aio),
                        &caio_cb_t);
    }
    return (EC_TRUE);
}

CDCDN *cdcdn_create(UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN           *cdcdn;
    CDCPGV_HDR      *cdcpgv_hdr;

    UINT32           f_s_offset;
    UINT32           f_e_offset;

    UINT8           *base;
    UINT32           pos;

    UINT32           disk_max_size;
    UINT32           block_max_num;

    UINT32           cdcpgv_size;
    UINT32           disk_size;
    UINT32           node_num;
    UINT32           block_num;
    uint16_t         disk_num;

    uint16_t         disk_no;

    if(1)
    {
        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGV_HDR_SIZE           = %ld\n",
                                              CDCPGV_HDR_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGV_MAX_DISK_NUM       = %u\n",
                                              CDCPGV_MAX_DISK_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGD_HDR_SIZE           = %u\n",
                                              CDCPGD_HDR_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGD_MAX_BLOCK_NUM      = %u\n",
                                              CDCPGD_MAX_BLOCK_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_SIZE               = %u\n",
                                              CDCPGB_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_PAGE_SIZE_NBYTES   = %u\n",
                                              CDCPGB_PAGE_SIZE_NBYTES);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_PAGE_NUM           = %u\n",
                                              CDCPGB_PAGE_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_RB_BITMAP_SIZE     = %u\n",
                                              CDCPGB_RB_BITMAP_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_RB_BITMAP_PAD_SIZE = %u\n",
                                              CDCPGB_RB_BITMAP_PAD_SIZE);
    }

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "range [%ld, %ld) aligned to invalid [%ld, %ld)\n",
                                              (*s_offset), e_offset,
                                              f_s_offset, f_e_offset);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "range [%ld, %ld) aligned to [%ld, %ld)\n",
                                          (*s_offset), e_offset,
                                          f_s_offset, f_e_offset);

    /*calculate data node header size in storage*/
    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "cdcpgv_size %ld\n",
                                          cdcpgv_size);

    //ASSERT(CDCPGB_SIZE_NBYTES >= cdcpgv_size);

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (NULL_PTR);
    }

    disk_max_size = (f_e_offset - f_s_offset - cdcpgv_size);
    block_max_num = (disk_max_size >> CDCPGB_SIZE_NBITS);

    disk_num      = (uint16_t)(block_max_num / CDCPGD_MAX_BLOCK_NUM);
    block_num     = ((UINT32)disk_num) * ((UINT32)CDCPGD_MAX_BLOCK_NUM);
    node_num      = (block_num >> CDCDN_SEG_NO_NBITS);/*num of nodes.  one node = several continuous blocks*/

    disk_size     = block_num * CDCPGB_SIZE_NBYTES;

    if(0 == disk_num)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "no enough space for one disk: "
                                              "disk_max_size %ld, block_max_num %ld => disk_num %u\n",
                                              disk_max_size, block_max_num, disk_num);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "disk_max_size %ld, block_max_num %ld => disk_num %u\n",
                                          disk_max_size, block_max_num, disk_num);

    ASSERT(0 == (block_num % node_num));

    base = cdcpgv_mcache_new(cdcpgv_size);
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "new header cache with size %ld failed\n",
                                              cdcpgv_size);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "new header cache [%p, %p), size %ld\n",
                                          base, base + cdcpgv_size, cdcpgv_size);

    pos = 0; /*initialize*/

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: new cdcdn failed\n");
        cdcpgv_mcache_free(base);
        return (NULL_PTR);
    }

    CDCDN_NODE_FD(cdcdn)       = ERR_FD;
    CDCDN_NODE_NUM(cdcdn)      = node_num;
    CDCDN_BASE_S_OFFSET(cdcdn) = f_s_offset;
    CDCDN_BASE_E_OFFSET(cdcdn) = f_s_offset + cdcpgv_size;
    CDCDN_NODE_S_OFFSET(cdcdn) = VAL_ALIGN_NEXT(CDCDN_BASE_E_OFFSET(cdcdn), ((UINT32)CDCPGB_SIZE_MASK));
    CDCDN_NODE_E_OFFSET(cdcdn) = CDCDN_NODE_S_OFFSET(cdcdn) + disk_size;

    ASSERT(f_e_offset >= CDCDN_NODE_E_OFFSET(cdcdn));

    CDCDN_CDCPGV(cdcdn) = cdcpgv_new();
    if(NULL_PTR == CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: new vol failed\n");

        cdcpgv_mcache_free(base);
        cdcdn_free(cdcdn);
        return (NULL_PTR);
    }

    CDCPGV_HEADER(CDCDN_CDCPGV(cdcdn)) = (CDCPGV_HDR *)base;
    if(EC_FALSE == cdcpgv_hdr_init(CDCDN_CDCPGV(cdcdn)))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: init hdr failed\n");

        cdcdn_free(cdcdn);
        return (NULL_PTR);
    }

    /*cdcpgv header inherit data from data node where header would be flushed to disk*/
    cdcpgv_hdr = CDCPGV_HEADER(CDCDN_CDCPGV(cdcdn));
    CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)      = CDCDN_NODE_NUM(cdcdn);
    CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr) = CDCDN_BASE_S_OFFSET(cdcdn);
    CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr) = CDCDN_BASE_E_OFFSET(cdcdn);
    CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr) = CDCDN_NODE_S_OFFSET(cdcdn);
    CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr) = CDCDN_NODE_E_OFFSET(cdcdn);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "cdcpgv nodes: %ld, offset: base %ld, start %ld, end %ld\n",
                                          CDCPGV_HDR_NODE_NUM(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr));

    pos += CDCPGV_HDR_SIZE;

    for(disk_no = 0; disk_no < disk_num; disk_no ++)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "[DEBUG] cdcdn_create: add disk_no %u to pos %ld\n",
                                               disk_no, pos);

        if(EC_FALSE == cdcdn_add_disk(cdcdn, disk_no, base, &pos))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: add disk %u failed\n",
                                                  disk_no);
            cdcdn_free(cdcdn);
            return (NULL_PTR);
        }
    }

    (*s_offset) = CDCDN_BASE_E_OFFSET(cdcdn);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: create vol done\n");

    return (cdcdn);
}

EC_BOOL cdcdn_add_disk(CDCDN *cdcdn, const uint16_t disk_no, UINT8 *base, UINT32 *pos)
{
    if(EC_FALSE == cdcpgv_add_disk(CDCDN_CDCPGV(cdcdn), disk_no, base, pos))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_add_disk: cdcpgv add disk %u failed\n",
                                              disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_del_disk(CDCDN *cdcdn, const uint16_t disk_no)
{
    if(EC_FALSE == cdcpgv_del_disk(CDCDN_CDCPGV(cdcdn), disk_no))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_del_disk: cdcpgv del disk %u failed\n",
                                              disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CDCDN *cdcdn_new()
{
    CDCDN *cdcdn;

    alloc_static_mem(MM_CDCDN, &cdcdn, LOC_CDCDN_0005);
    if(NULL_PTR != cdcdn)
    {
        cdcdn_init(cdcdn);
        return (cdcdn);
    }
    return (cdcdn);
}

EC_BOOL cdcdn_init(CDCDN *cdcdn)
{
    CDCDN_NODE_FD(cdcdn)       = ERR_FD;
    CDCDN_NODE_CAIO_MD(cdcdn)  = NULL_PTR;

    CDCDN_NODE_NUM(cdcdn)      = 0;

    CDCDN_BASE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_BASE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    CDCDN_NODE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_NODE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    CDCDN_CDCPGV(cdcdn)        = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdcdn_clean(CDCDN *cdcdn)
{
    CDCDN_NODE_FD(cdcdn)       = ERR_FD;
    CDCDN_NODE_CAIO_MD(cdcdn)  = NULL_PTR;

    CDCDN_NODE_NUM(cdcdn)      = 0;

    CDCDN_BASE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_BASE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    CDCDN_NODE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_NODE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        cdcpgv_free(CDCDN_CDCPGV(cdcdn));
        CDCDN_CDCPGV(cdcdn) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_free(CDCDN *cdcdn)
{
    if(NULL_PTR != cdcdn)
    {
        cdcdn_clean(cdcdn);
        free_static_mem(MM_CDCDN, cdcdn, LOC_CDCDN_0006);
    }
    return (EC_TRUE);
}

void cdcdn_print(LOG *log, const CDCDN *cdcdn)
{
    if(NULL_PTR != cdcdn)
    {
        sys_log(log, "cdcdn_print: cdcdn %p: fd %d, node num %ld, base offset %ld, size %ld, range [%ld, %ld)\n",
                     cdcdn,
                     CDCDN_NODE_FD(cdcdn),
                     CDCDN_NODE_NUM(cdcdn),
                     CDCDN_BASE_S_OFFSET(cdcdn),
                     CDCDN_NODE_E_OFFSET(cdcdn) - CDCDN_NODE_S_OFFSET(cdcdn),
                     CDCDN_NODE_S_OFFSET(cdcdn), CDCDN_NODE_E_OFFSET(cdcdn));

        cdcpgv_print(log, CDCDN_CDCPGV(cdcdn));
    }
    return;
}

EC_BOOL cdcdn_is_full(CDCDN *cdcdn)
{
    return cdcpgv_is_full(CDCDN_CDCPGV(cdcdn));
}

/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL cdcdn_read_o(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES <= offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: offset %ld overflow\n", offset);
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < offset + data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: offset %ld + data_max_len %ld = %ld overflow\n",
                            offset, data_max_len, offset + data_max_len);
        return (EC_FALSE);
    }

    node_id  = CDCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = offset;
    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_o: disk %u, block %u  ==> node %ld, start\n", disk_no, block_no, node_id);
    if(EC_FALSE == cdcdn_node_read(cdcdn, node_id, data_max_len, data_buff, &offset_t))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: read %ld bytes at offset %ld from node %ld failed\n",
                           data_max_len, offset, node_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_o: disk %u, block %u  ==> node %ld, end\n", disk_no, block_no, node_id);

    if(NULL_PTR != data_len)
    {
        (*data_len) = offset_t - offset;
    }

    return (EC_TRUE);
}


EC_BOOL cdcdn_read_o_aio(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len, CAIO_CB *caio_cb)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES <= offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: offset %ld overflow\n", offset);
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < offset + data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: "
                                              "offset %ld + data_max_len %ld = %ld overflow\n",
                                              offset, data_max_len, offset + data_max_len);
        return (EC_FALSE);
    }

    node_id  = CDCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = offset;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_o_aio: "
                                          "disk %u, block %u  ==> node %ld, start\n",
                                          disk_no, block_no, node_id);

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        if(EC_FALSE == cdcdn_node_read(cdcdn, node_id, data_max_len, data_buff, &offset_t))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: "
                                                  "read %ld bytes at offset %ld from node %ld failed\n",
                                                  data_max_len, offset, node_id);
            return (EC_FALSE);
        }
        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_o_aio: "
                                              "disk %u, block %u  ==> node %ld, end\n",
                                              disk_no, block_no, node_id);

        if(NULL_PTR != data_len)
        {
            (*data_len) = offset_t - offset;
        }
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDCDN_FILE_AIO  *cdcdn_file_aio;

        /*set cdcdn file aio*/
        cdcdn_file_aio = cdcdn_file_aio_new();
        if(NULL_PTR == cdcdn_file_aio)
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: "
                                                  "new cdcdn_file_aio failed\n");

            return (EC_FALSE);
        }

        CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio)      = cdcdn;
        CDCDN_FILE_AIO_I_DATA_LEN(cdcdn_file_aio) = data_len;
        CDCDN_FILE_AIO_F_I_OFFSET(cdcdn_file_aio) = NULL_PTR;
        CDCDN_FILE_AIO_F_S_OFFSET(cdcdn_file_aio) = offset;
        CDCDN_FILE_AIO_F_E_OFFSET(cdcdn_file_aio) = offset + data_max_len;
        CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio) = offset;
        caio_cb_clone(caio_cb, CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCDN_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdcdn_node_read_aio_timeout, (void *)cdcdn_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_node_read_aio_terminate, (void *)cdcdn_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_node_read_aio_complete, (void *)cdcdn_file_aio);


        if(EC_FALSE == cdcdn_node_read_aio(cdcdn, node_id, data_max_len, data_buff,
                                            &CDCDN_FILE_AIO_F_C_OFFSET(cdcdn_file_aio), &caio_cb_t))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o_aio: "
                                                  "read %ld bytes at offset %ld from node %ld failed\n",
                                                  data_max_len, offset, node_id);
            return (EC_FALSE);
        }
        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_o_aio: "
                                              "disk %u, block %u  ==> node %ld, end\n",
                                              disk_no, block_no, node_id);
    }

    return (EC_TRUE);
}

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL cdcdn_write_o(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    node_id  = CDCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = (*offset);

    if(EC_FALSE == cdcdn_node_write(cdcdn, node_id, data_max_len, data_buff, offset))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: write %ld bytes to disk %u block %u offset %ld failed\n",
                            data_max_len, disk_no, block_no, offset_t);

        return (EC_FALSE);
    }

    //dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_write_o: write %ld bytes to disk %u block %u offset %ld done\n",
    //                    data_max_len, disk_no, block_no, offset_t);

    return (EC_TRUE);
}

EC_BOOL cdcdn_write_o_aio(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset, CAIO_CB *caio_cb)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o_aio: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o_aio: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o_aio: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    node_id  = CDCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = (*offset);

    if(EC_FALSE == cdcdn_node_write_aio(cdcdn, node_id, data_max_len, data_buff, offset, caio_cb))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o_aio: write %ld bytes to disk %u block %u offset %ld failed\n",
                            data_max_len, disk_no, block_no, offset_t);

        return (EC_FALSE);
    }

    //dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_write_o: write %ld bytes to disk %u block %u offset %ld done\n",
    //                    data_max_len, disk_no, block_no, offset_t);

    return (EC_TRUE);
}

/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cdcdn_read_e(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS)) + offset;
    if(EC_FALSE == cdcdn_read_o(cdcdn, disk_no, block_no, offset_t, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_e: read %ld bytes from disk %u block %u page %u offset %u failed\n",
                           data_max_len, disk_no, block_no, page_no, offset);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_read_e_aio(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len, CAIO_CB *caio_cb)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS)) + offset;
    if(EC_FALSE == cdcdn_read_o_aio(cdcdn, disk_no, block_no, offset_t, data_max_len, data_buff, data_len, caio_cb))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_e_aio: read %ld bytes from disk %u block %u page %u offset %u failed\n",
                           data_max_len, disk_no, block_no, page_no, offset);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cdcdn_write_e(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS)) + offset;
    if(EC_FALSE == cdcdn_write_o(cdcdn, data_max_len, data_buff, disk_no, block_no, &offset_t))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_e: write %ld bytes to disk %u block %u page %u offset %ld failed\n",
                           data_max_len, disk_no, block_no, page_no, offset_t);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_write_e_aio(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, CAIO_CB *caio_cb)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS)) + offset;
    if(EC_FALSE == cdcdn_write_o_aio(cdcdn, data_max_len, data_buff, disk_no, block_no, &offset_t, caio_cb))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_e_aio: write %ld bytes to disk %u block %u page %u offset %ld failed\n",
                           data_max_len, disk_no, block_no, page_no, offset_t);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_read_p(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS));
    //dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_p: disk %u, block %u, page %u ==> offset %ld\n", disk_no, block_no, page_no, offset);
    if(EC_FALSE == cdcdn_read_o(cdcdn, disk_no, block_no, offset, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: read %ld bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_read_p_aio(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len, CAIO_CB *caio_cb)
{
    UINT32 offset;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p_aio: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p_aio: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p_aio: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS));
    //dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_p_aio: disk %u, block %u, page %u ==> offset %ld\n", disk_no, block_no, page_no, offset);
    if(EC_FALSE == cdcdn_read_o_aio(cdcdn, disk_no, block_no, offset, data_max_len, data_buff, data_len, caio_cb))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p_aio: read %ld bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_write_p(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    UINT32   offset;
    uint32_t size;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    if(EC_FALSE == cdcpgv_new_space(CDCDN_CDCPGV(cdcdn), size, disk_no, block_no,  page_no))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: new %ld bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)(*page_no)) << (CDCPGB_PAGE_SIZE_NBITS));

    if(EC_FALSE == cdcdn_write_o(cdcdn, data_max_len, data_buff, *disk_no, *block_no, &offset))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: write %ld bytes to disk %u block %u page %u failed\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));

        cdcpgv_free_space(CDCDN_CDCPGV(cdcdn), *disk_no, *block_no, *page_no, size);
        return (EC_FALSE);
    }
    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_write_p: write %ld bytes to disk %u block %u page %u done\n",
                        data_max_len, (*disk_no), (*block_no), (*page_no));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_write_p_aio_timeout(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CDCDN      *cdcdn;
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_write_p_aio_timeout: "
                  "disk %u, block %u, page %u, size %u timeout\n",
                  CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio));

    ASSERT(NULL_PTR != CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio));
    cdcdn = CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio);

    cdcpgv_free_space(CDCDN_CDCPGV(cdcdn),
                      CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio),
                      CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio),
                      CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio),
                      CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_write_p_aio_terminate(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CDCDN      *cdcdn;
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_write_p_aio_terminate: "
                  "disk %u, block %u, page %u, size %u terminated\n",
                  CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio));

    ASSERT(NULL_PTR != CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio));
    cdcdn = CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio);

    cdcpgv_free_space(CDCDN_CDCPGV(cdcdn),
                      CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio),
                      CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio),
                      CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio),
                      CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_write_p_aio_complete(CDCDN_FILE_AIO *cdcdn_file_aio)
{
    CAIO_CB     caio_cb;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_write_p_aio_complete: "
                  "disk %u, block %u, page %u, size %u completed\n",
                  CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio),
                  CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio));

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio), &caio_cb);

    cdcdn_file_aio_free(cdcdn_file_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdcdn_write_p_aio(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no, CAIO_CB *caio_cb)
{
    UINT32   offset;
    uint32_t size;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p_aio: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p_aio: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p_aio: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    if(EC_FALSE == cdcpgv_new_space(CDCDN_CDCPGV(cdcdn), size, disk_no, block_no,  page_no))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p_aio: new %ld bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)(*page_no)) << (CDCPGB_PAGE_SIZE_NBITS));

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        if(EC_FALSE == cdcdn_write_o(cdcdn, data_max_len, data_buff, *disk_no, *block_no, &offset))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p_aio: write %ld bytes to disk %u block %u page %u failed\n",
                                data_max_len, (*disk_no), (*block_no), (*page_no));

            cdcpgv_free_space(CDCDN_CDCPGV(cdcdn), *disk_no, *block_no, *page_no, size);
            return (EC_FALSE);
        }
        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_write_p_aio: write %ld bytes to disk %u block %u page %u done\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));
    }
    else
    {
        CAIO_CB          caio_cb_t;
        CDCDN_FILE_AIO  *cdcdn_file_aio;

        /*set cdcdn file aio*/
        cdcdn_file_aio = cdcdn_file_aio_new();
        if(NULL_PTR == cdcdn_file_aio)
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p_aio: "
                                                  "new cdcdn_file_aio failed\n");

            return (EC_FALSE);
        }

        CDCDN_FILE_AIO_CDCDN(cdcdn_file_aio)      = cdcdn;
        CDCDN_FILE_AIO_T_DISK_NO(cdcdn_file_aio)  = *disk_no;
        CDCDN_FILE_AIO_T_BLOCK_NO(cdcdn_file_aio) = *block_no;
        CDCDN_FILE_AIO_T_PAGE_NO(cdcdn_file_aio)  = *page_no;
        CDCDN_FILE_AIO_T_SIZE(cdcdn_file_aio)     = size;

        caio_cb_clone(caio_cb, CDCDN_FILE_AIO_CAIO_CB(cdcdn_file_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCDN_FILE_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdcdn_write_p_aio_timeout, (void *)cdcdn_file_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_write_p_aio_terminate, (void *)cdcdn_file_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_write_p_aio_complete, (void *)cdcdn_file_aio);

        if(EC_FALSE == cdcdn_write_o_aio(cdcdn, data_max_len, data_buff, *disk_no, *block_no, &offset, &caio_cb_t))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p_aio: write %ld bytes to disk %u block %u page %u failed\n",
                                data_max_len, (*disk_no), (*block_no), (*page_no));

            cdcpgv_free_space(CDCDN_CDCPGV(cdcdn), *disk_no, *block_no, *page_no, size);
            return (EC_FALSE);
        }
        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_write_p_aio: write %ld bytes to disk %u block %u page %u done\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));

    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_flush(CDCDN *cdcdn)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       cdcpgv_size;
    UINT32       cdcpgv_offset;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(ERR_FD == CDCDN_NODE_FD(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: cdcpgv is null\n");
        return (EC_FALSE);
    }

    cdcpgv     = CDCDN_CDCPGV(cdcdn);
    cdcpgv_hdr = CDCPGV_HEADER(cdcpgv);

    base       = (UINT8 *)cdcpgv_hdr;
    f_s_offset = CDCDN_BASE_S_OFFSET(cdcdn);

    ASSERT(0 == (f_s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush: "
                                          "f_s_offset %ld\n",
                                          f_s_offset);

    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);
    ASSERT(CDCDN_BASE_S_OFFSET(cdcdn) + cdcpgv_size == CDCDN_BASE_E_OFFSET(cdcdn));
    ASSERT(CDCDN_NODE_S_OFFSET(cdcdn) == VAL_ALIGN_NEXT(CDCDN_BASE_E_OFFSET(cdcdn), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv_offset = f_s_offset;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush: "
                                          "cdcpgv node num: %ld, cdcpgv header: base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr));

    ASSERT(CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)      == CDCDN_NODE_NUM(cdcdn));
    ASSERT(CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr) == CDCDN_BASE_S_OFFSET(cdcdn));
    ASSERT(CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr) == CDCDN_BASE_E_OFFSET(cdcdn));
    ASSERT(CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr) == CDCDN_NODE_S_OFFSET(cdcdn));
    ASSERT(CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr) == CDCDN_NODE_E_OFFSET(cdcdn));

    if(EC_FALSE == c_file_flush(CDCDN_NODE_FD(cdcdn), &cdcpgv_offset, cdcpgv_size, base))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: "
                                              "flush cdcpgv to offset %ld, size %ld failed\n",
                                              f_s_offset, cdcpgv_size);
        return (EC_FALSE);
    }

    ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush: "
                                          "flush cdcpgv to fd %d, offset %ld => %ld, size %ld done\n",
                                          CDCDN_NODE_FD(cdcdn), f_s_offset, cdcpgv_offset, cdcpgv_size);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_flush_aio_timeout(CDCDN_AIO *cdcdn_aio)
{
    CAIO_CB      caio_cb;
    //CDCDN       *cdcdn;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_flush_aio_timeout: "
                                          "flush cdcpgv to offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_C_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio));

    ASSERT(NULL_PTR != CDCDN_AIO_CDCDN(cdcdn_aio));
    //cdcdn = CDCDN_AIO_CDCDN(cdcdn_aio);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

    cdcdn_aio_free(cdcdn_aio);

    caio_cb_exec_timeout_handler(&caio_cb);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_flush_aio_terminate(CDCDN_AIO *cdcdn_aio)
{
    CAIO_CB      caio_cb;
    //CDCDN       *cdcdn;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_flush_aio_terminate: "
                                          "flush cdcpgv to offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_C_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio));

    ASSERT(NULL_PTR != CDCDN_AIO_CDCDN(cdcdn_aio));
    //cdcdn = CDCDN_AIO_CDCDN(cdcdn_aio);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

    cdcdn_aio_free(cdcdn_aio);

    caio_cb_exec_terminate_handler(&caio_cb);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_flush_aio_complete(CDCDN_AIO *cdcdn_aio)
{
    CAIO_CB      caio_cb;
    //CDCDN       *cdcdn;

    dbg_log(SEC_0187_CDCDN, 1)(LOGSTDOUT, "[DEBUG] __cdcdn_flush_aio_complete: "
                                          "flush cdcpgv to offset %ld, size %ld done, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_C_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio));

    ASSERT(NULL_PTR != CDCDN_AIO_CDCDN(cdcdn_aio));
    //cdcdn = CDCDN_AIO_CDCDN(cdcdn_aio);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

    cdcdn_aio_free(cdcdn_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdcdn_flush_aio(CDCDN *cdcdn, CAIO_CB *caio_cb)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       cdcpgv_size;
    UINT32       cdcpgv_offset;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush_aio: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(ERR_FD == CDCDN_NODE_FD(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush_aio: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush_aio: cdcpgv is null\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != CDCDN_NODE_CAIO_MD(cdcdn));

    cdcpgv     = CDCDN_CDCPGV(cdcdn);
    cdcpgv_hdr = CDCPGV_HEADER(cdcpgv);

    base       = (UINT8 *)cdcpgv_hdr;
    f_s_offset = CDCDN_BASE_S_OFFSET(cdcdn);

    ASSERT(0 == (f_s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush_aio: "
                                          "f_s_offset %ld\n",
                                          f_s_offset);

    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);
    ASSERT(CDCDN_BASE_S_OFFSET(cdcdn) + cdcpgv_size == CDCDN_BASE_E_OFFSET(cdcdn));
    ASSERT(CDCDN_NODE_S_OFFSET(cdcdn) == VAL_ALIGN_NEXT(CDCDN_BASE_E_OFFSET(cdcdn), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv_offset = f_s_offset;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush_aio: "
                                          "cdcpgv node num: %ld, cdcpgv header: base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr));

    ASSERT(CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)      == CDCDN_NODE_NUM(cdcdn));
    ASSERT(CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr) == CDCDN_BASE_S_OFFSET(cdcdn));
    ASSERT(CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr) == CDCDN_BASE_E_OFFSET(cdcdn));
    ASSERT(CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr) == CDCDN_NODE_S_OFFSET(cdcdn));
    ASSERT(CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr) == CDCDN_NODE_E_OFFSET(cdcdn));

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        if(EC_FALSE == c_file_flush(CDCDN_NODE_FD(cdcdn), &cdcpgv_offset, cdcpgv_size, base))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush_aio: "
                                                  "flush cdcpgv to offset %ld, size %ld failed\n",
                                                  f_s_offset, cdcpgv_size);
            return (EC_FALSE);
        }

        ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush_aio: "
                                              "flush cdcpgv to fd %d, offset %ld => %ld, size %ld done\n",
                                              CDCDN_NODE_FD(cdcdn), f_s_offset, cdcpgv_offset, cdcpgv_size);
    }
    else
    {
        CAIO_CB     caio_cb_t;
        CDCDN_AIO  *cdcdn_aio;

        /*set cdcdn aio*/
        cdcdn_aio = cdcdn_aio_new();
        if(NULL_PTR == cdcdn_aio)
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush_aio: new cdcdn_aio failed\n");
            return (EC_FALSE);
        }

        CDCDN_AIO_CDCDN(cdcdn_aio)    = cdcdn;
        CDCDN_AIO_S_OFFSET(cdcdn_aio) = cdcpgv_offset;
        CDCDN_AIO_E_OFFSET(cdcdn_aio) = cdcpgv_offset + cdcpgv_size;
        CDCDN_AIO_C_OFFSET(cdcdn_aio) = cdcpgv_offset;

        caio_cb_clone(caio_cb, CDCDN_AIO_CAIO_CB(cdcdn_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCDN_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdcdn_flush_aio_timeout, (void *)cdcdn_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_flush_aio_terminate, (void *)cdcdn_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_flush_aio_complete, (void *)cdcdn_aio);

        /*send aio request*/
        caio_file_write(CDCDN_NODE_CAIO_MD(cdcdn), CDCDN_NODE_FD(cdcdn),
                        &CDCDN_AIO_C_OFFSET(cdcdn_aio),
                        CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                        base,
                        &caio_cb_t);
    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_load(CDCDN *cdcdn, int fd, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       f_e_offset;
    UINT32       cdcpgv_size;
    UINT32       cdcpgv_offset;
    UINT32       pos;

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: cdcpgv is not null\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: "
                                          "enter: fd %d, s_offset %ld, e_offset %ld\n",
                                          fd, (*s_offset), e_offset);

    /*determine data node header size*/
    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);

    /*determine data node header offset in storage*/
    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (EC_FALSE);
    }

    cdcpgv_offset = f_s_offset;

    base = cdcpgv_mcache_new(cdcpgv_size);
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: new mem cache with size %ld failed\n",
                                              cdcpgv_size);
        return (EC_FALSE);
    }

    /*load data node header from storage*/
    if(EC_FALSE == c_file_load(fd, &cdcpgv_offset, cdcpgv_size, (UINT8 *)base))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: "
                                              "load cdcpgv from fd %d, offset %ld, size %ld failed\n",
                                              fd, f_s_offset, cdcpgv_size);

        cdcpgv_mcache_free(base);
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: "
                                          "load cdcpgv from fd %d, offset %ld => %ld, size %ld done\n",
                                          fd, f_s_offset, cdcpgv_offset, cdcpgv_size);

    ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: "
                                          "cdcpgv node num: %ld, base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_E_OFFSET((CDCPGV_HDR *)base));

    ASSERT(f_s_offset == CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base));
    ASSERT(f_s_offset + cdcpgv_size == CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base));
    ASSERT(CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base)
            == VAL_ALIGN_NEXT(CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv = cdcpgv_new();
    if(NULL_PTR == cdcpgv)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: new cdcpgv failed\n");

        cdcpgv_mcache_free(base);
        return (EC_FALSE);
    }

    pos = 0;

    CDCPGV_HEADER(cdcpgv) = (CDCPGV_HDR *)base;
    pos += CDCPGV_HDR_SIZE;

    if(EC_FALSE == cdcpgv_load(cdcpgv, base, &pos))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: load cdcpgv failed\n");

        cdcpgv_free(cdcpgv);
        return (EC_FALSE);
    }
    CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;

    cdcpgv_hdr = (CDCPGV_HDR *)CDCPGV_HEADER(cdcpgv);

    CDCDN_CDCPGV(cdcdn)         = cdcpgv;

    CDCDN_NODE_NUM(cdcdn)       = CDCPGV_HDR_NODE_NUM(cdcpgv_hdr);
    CDCDN_BASE_S_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr);
    CDCDN_BASE_E_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_S_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_E_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr);

    (*s_offset) = f_s_offset + cdcpgv_size;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: load vol from %d, offset %ld done\n",
                                          fd, f_s_offset);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_load_aio_timeout(CDCDN_AIO *cdcdn_aio)
{
    CAIO_CB      caio_cb;
    //CDCDN       *cdcdn;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_load_aio_timeout: "
                                          "load cdcpgv from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_C_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio));

    ASSERT(NULL_PTR != CDCDN_AIO_CDCDN(cdcdn_aio));
    //cdcdn = CDCDN_AIO_CDCDN(cdcdn_aio);

    if(NULL_PTR != CDCDN_AIO_M_BUFF(cdcdn_aio))
    {
        cdcpgv_mcache_free(CDCDN_AIO_M_BUFF(cdcdn_aio));
        CDCDN_AIO_M_BUFF(cdcdn_aio) = NULL_PTR;
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

    cdcdn_aio_free(cdcdn_aio);

    caio_cb_exec_timeout_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_load_aio_terminate(CDCDN_AIO *cdcdn_aio)
{
    CAIO_CB      caio_cb;
    //CDCDN       *cdcdn;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_load_aio_terminate: "
                                          "load cdcpgv from offset %ld, size %ld failed, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_C_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio));

    ASSERT(NULL_PTR != CDCDN_AIO_CDCDN(cdcdn_aio));
    //cdcdn = CDCDN_AIO_CDCDN(cdcdn_aio);

    if(NULL_PTR != CDCDN_AIO_M_BUFF(cdcdn_aio))
    {
        cdcpgv_mcache_free(CDCDN_AIO_M_BUFF(cdcdn_aio));
        CDCDN_AIO_M_BUFF(cdcdn_aio) = NULL_PTR;
    }

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

    cdcdn_aio_free(cdcdn_aio);

    caio_cb_exec_terminate_handler(&caio_cb);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcdn_load_aio_complete(CDCDN_AIO *cdcdn_aio)
{
    CAIO_CB      caio_cb;

    CDCDN       *cdcdn;
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT32       pos;

    dbg_log(SEC_0187_CDCDN, 1)(LOGSTDOUT, "[DEBUG] __cdcdn_load_aio_complete: "
                                          "load cdcpgv from offset %ld, size %ld done, "
                                          "offset reaches %ld v.s. expected %ld\n",
                                          CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_C_OFFSET(cdcdn_aio),
                                          CDCDN_AIO_E_OFFSET(cdcdn_aio));

    ASSERT(NULL_PTR != CDCDN_AIO_CDCDN(cdcdn_aio));
    cdcdn = CDCDN_AIO_CDCDN(cdcdn_aio);

    ASSERT(CDCDN_AIO_C_OFFSET(cdcdn_aio) == CDCDN_AIO_E_OFFSET(cdcdn_aio));

    cdcpgv_hdr = (CDCPGV_HDR *)CDCDN_AIO_M_BUFF(cdcdn_aio);
    CDCDN_AIO_M_BUFF(cdcdn_aio) = NULL_PTR;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] __cdcdn_load_aio_complete: "
                                          "cdcpgv node num: %ld, base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr));

    ASSERT(CDCDN_AIO_S_OFFSET(cdcdn_aio) == CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr));
    ASSERT(CDCDN_AIO_E_OFFSET(cdcdn_aio) == CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr));
    ASSERT(CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr)
            == VAL_ALIGN_NEXT(CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv = cdcpgv_new();
    if(NULL_PTR == cdcpgv)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_load_aio_complete: new cdcpgv failed\n");

        cdcpgv_mcache_free((UINT8 *)cdcpgv_hdr);

        caio_cb_init(&caio_cb);
        caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

        cdcdn_aio_free(cdcdn_aio);

        caio_cb_exec_terminate_handler(&caio_cb);
        return (EC_FALSE);
    }

    pos = 0;

    CDCPGV_HEADER(cdcpgv) = cdcpgv_hdr;
    pos += CDCPGV_HDR_SIZE;

    if(EC_FALSE == cdcpgv_load(cdcpgv, (UINT8 *)cdcpgv_hdr, &pos))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:__cdcdn_load_aio_complete: load cdcpgv failed\n");

        cdcpgv_free(cdcpgv);

        caio_cb_init(&caio_cb);
        caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

        cdcdn_aio_free(cdcdn_aio);

        caio_cb_exec_terminate_handler(&caio_cb);
        return (EC_FALSE);
    }
    CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;

    CDCDN_CDCPGV(cdcdn)         = cdcpgv;

    CDCDN_NODE_NUM(cdcdn)       = CDCPGV_HDR_NODE_NUM(cdcpgv_hdr);
    CDCDN_BASE_S_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr);
    CDCDN_BASE_E_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_S_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_E_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr);

    caio_cb_init(&caio_cb);
    caio_cb_clone(CDCDN_AIO_CAIO_CB(cdcdn_aio), &caio_cb);

    cdcdn_aio_free(cdcdn_aio);

    caio_cb_exec_complete_handler(&caio_cb);

    return (EC_TRUE);
}

EC_BOOL cdcdn_load_aio(CDCDN *cdcdn, int fd, UINT32 *s_offset, const UINT32 e_offset, CAIO_CB *caio_cb)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       f_e_offset;
    UINT32       cdcpgv_size;
    UINT32       cdcpgv_offset;
    UINT32       pos;

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: cdcpgv is not null\n");
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != CDCDN_NODE_CAIO_MD(cdcdn));

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_aio: "
                                          "enter: fd %d, s_offset %ld, e_offset %ld\n",
                                          fd, (*s_offset), e_offset);

    /*determine data node header size*/
    cdcpgv_aligned_size(&cdcpgv_size, ((UINT32)CDCPGB_PAGE_SIZE_MASK));

    /*determine data node header offset in storage*/
    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (EC_FALSE);
    }

    cdcpgv_offset = f_s_offset;

    base = cdcpgv_mcache_new(cdcpgv_size);
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: new mem cache with size %ld failed\n",
                                              cdcpgv_size);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDCDN_NODE_CAIO_MD(cdcdn))
    {
        /*load data node header from storage*/
        if(EC_FALSE == c_file_load(fd, &cdcpgv_offset, cdcpgv_size, (UINT8 *)base))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: "
                                                  "load cdcpgv from fd %d, offset %ld, size %ld failed\n",
                                                  fd, f_s_offset, cdcpgv_size);

            cdcpgv_mcache_free(base);
            return (EC_FALSE);
        }

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_aio: "
                                              "load cdcpgv from fd %d, offset %ld => %ld, size %ld done\n",
                                              fd, f_s_offset, cdcpgv_offset, cdcpgv_size);

        ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_aio: "
                                              "cdcpgv node num: %ld, base [%ld, %ld), node [%ld, %ld)\n",
                                              CDCPGV_HDR_NODE_NUM((CDCPGV_HDR *)base),
                                              CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base),
                                              CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base),
                                              CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base),
                                              CDCPGV_HDR_NODE_E_OFFSET((CDCPGV_HDR *)base));

        ASSERT(f_s_offset == CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base));
        ASSERT(f_s_offset + cdcpgv_size == CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base));
        ASSERT(CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base)
                == VAL_ALIGN_NEXT(CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base), ((UINT32)CDCPGB_SIZE_MASK)));

        cdcpgv = cdcpgv_new();
        if(NULL_PTR == cdcpgv)
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: new cdcpgv failed\n");

            cdcpgv_mcache_free(base);
            return (EC_FALSE);
        }

        pos = 0;

        CDCPGV_HEADER(cdcpgv) = (CDCPGV_HDR *)base;
        pos += CDCPGV_HDR_SIZE;

        if(EC_FALSE == cdcpgv_load(cdcpgv, base, &pos))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: load cdcpgv failed\n");

            cdcpgv_free(cdcpgv);
            return (EC_FALSE);
        }
        CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;

        cdcpgv_hdr = (CDCPGV_HDR *)CDCPGV_HEADER(cdcpgv);

        CDCDN_CDCPGV(cdcdn)         = cdcpgv;

        CDCDN_NODE_NUM(cdcdn)       = CDCPGV_HDR_NODE_NUM(cdcpgv_hdr);
        CDCDN_BASE_S_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr);
        CDCDN_BASE_E_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr);
        CDCDN_NODE_S_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr);
        CDCDN_NODE_E_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr);

        (*s_offset) = f_s_offset + cdcpgv_size;

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_aio: load vol from %d, offset %ld done\n",
                                              fd, f_s_offset);
    }
    else
    {
        CAIO_CB     caio_cb_t;
        CDCDN_AIO  *cdcdn_aio;

        /*set cdcdn aio*/
        cdcdn_aio = cdcdn_aio_new();
        if(NULL_PTR == cdcdn_aio)
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_aio: new cdcdn_aio failed\n");

            cdcpgv_mcache_free(base);
            return (EC_FALSE);
        }

        CDCDN_AIO_CDCDN(cdcdn_aio)    = cdcdn;
        CDCDN_AIO_S_OFFSET(cdcdn_aio) = cdcpgv_offset;
        CDCDN_AIO_E_OFFSET(cdcdn_aio) = cdcpgv_offset + cdcpgv_size;
        CDCDN_AIO_C_OFFSET(cdcdn_aio) = cdcpgv_offset;
        CDCDN_AIO_M_BUFF(cdcdn_aio)   = base;

        caio_cb_clone(caio_cb, CDCDN_AIO_CAIO_CB(cdcdn_aio));

        /*set caio callback*/
        caio_cb_init(&caio_cb_t);

        caio_cb_set_timeout_handler(&caio_cb_t, (UINT32)CDCDN_AIO_TIMEOUT_NSEC /*seconds*/,
                                    (CAIO_CALLBACK)__cdcdn_load_aio_timeout, (void *)cdcdn_aio);

        caio_cb_set_terminate_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_load_aio_terminate, (void *)cdcdn_aio);
        caio_cb_set_complete_handler(&caio_cb_t, (CAIO_CALLBACK)__cdcdn_load_aio_complete, (void *)cdcdn_aio);

        /*send aio request*/
        caio_file_read(CDCDN_NODE_CAIO_MD(cdcdn), CDCDN_NODE_FD(cdcdn),
                        &CDCDN_AIO_C_OFFSET(cdcdn_aio),
                        CDCDN_AIO_E_OFFSET(cdcdn_aio) - CDCDN_AIO_S_OFFSET(cdcdn_aio),
                        CDCDN_AIO_M_BUFF(cdcdn_aio),
                        &caio_cb_t);

        (*s_offset) = f_s_offset + cdcpgv_size;
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

