
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

/*----------------------------------------------------------------------------*\
 *                             LOG AGENT                                      *
 *              based on unix domain socket with unix packet                  *
\*----------------------------------------------------------------------------*/

#if (SWITCH_OFF == NGX_BGN_SWITCH)

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"

#include "cbc.h"
#include "cmisc.h"

#include "ctimeout.h"

#include "task.h"

#include "csocket.h"
#include "cepoll.h"

#include "chttp.h"

#include "cparacfg.h"

#include "cunixpacket_agent.h"

#include "findex.inc"

#define CUNIXPACKET_AGENT_ASSERT(condition)   ASSERT(condition)

#define CUNIXPACKET_AGENT_MD_CAPACITY()                  (cbc_md_capacity(MD_CUNIXPACKET))

#define CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id)     ((CUNIXPACKET_AGENT_MD *)cbc_md_get(MD_CUNIXPACKET, (cunixpacket_agent_md_id)))

#define CUNIXPACKET_AGENT_MD_ID_CHECK_INVALID(cunixpacket_agent_md_id)  \
    ((CMPI_ANY_MODI != (cunixpacket_agent_md_id)) && ((NULL_PTR == CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id)) || (0 == (CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id)->usedcounter))))

/*-------------------------------------------------------------------*\
config.xml example:
===================================
//TODO:
\*-------------------------------------------------------------------*/

STATIC_CAST EC_BOOL __cunixpacket_agent_recv_packet(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node);
STATIC_CAST EC_BOOL __cunixpacket_agent_send_packet(const UINT32 cunixpacket_agent_md_id, CBUFFER *uds_packet_data);

/**
*   for test only
*
*   to query the status of CUNIXPACKET_AGENT Module
*
**/
void cunixpacket_agent_print_module_status(const UINT32 cunixpacket_agent_md_id, LOG *log)
{
    CUNIXPACKET_AGENT_MD  *cunixpacket_agent_md;
    UINT32                 this_cunixpacket_agent_md_id;

    for( this_cunixpacket_agent_md_id = 0; this_cunixpacket_agent_md_id < CUNIXPACKET_AGENT_MD_CAPACITY(); this_cunixpacket_agent_md_id ++ )
    {
        cunixpacket_agent_md = CUNIXPACKET_AGENT_MD_GET(this_cunixpacket_agent_md_id);

        if(NULL_PTR != cunixpacket_agent_md && 0 < cunixpacket_agent_md->usedcounter )
        {
            sys_log(log,"CUNIXPACKET_AGENT Module # %u : %u refered\n",
                    this_cunixpacket_agent_md_id,
                    cunixpacket_agent_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CUNIXPACKET_AGENT module
*
**/
EC_BOOL cunixpacket_agent_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CUNIXPACKET , 1);
}

/**
*
* unregister CUNIXPACKET_AGENT module
*
**/
EC_BOOL cunixpacket_agent_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CUNIXPACKET);
}

/**
*
* start CUNIXPACKET_AGENT module
*
**/
UINT32 cunixpacket_agent_start(const CSTRING *uds_path)
{
    CUNIXPACKET_AGENT_MD       *cunixpacket_agent_md;
    UINT32                      cunixpacket_agent_md_id;
    int                         uds_listen_socket;

    init_static_mem();

    cbc_md_reg(MD_CUNIXPACKET, 32);

    /*start listen*/
    if(EC_FALSE == csocket_unixpacket_listen((char *)cstring_get_str(uds_path), &uds_listen_socket))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_agent_start: "
                                                    "listen uds '%s' failed\n",
                                                    (char *)cstring_get_str(uds_path));
        return (CMPI_ERROR_MODI);
    }

    dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_agent_start: "
                                                "listen uds '%s' on socket %d done\n",
                                                (char *)cstring_get_str(uds_path),
                                                uds_listen_socket);

    cunixpacket_agent_md_id = cbc_md_new(MD_CUNIXPACKET, sizeof(CUNIXPACKET_AGENT_MD));
    if(CMPI_ERROR_MODI == cunixpacket_agent_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CUNIXPACKET_AGENT module */
    cunixpacket_agent_md = (CUNIXPACKET_AGENT_MD *)cbc_md_get(MD_CUNIXPACKET, cunixpacket_agent_md_id);
    cunixpacket_agent_md->usedcounter   = 0;

    /* create a new module node */

    /* init */

    CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md)  = cstring_dup(uds_path);
    if(NULL_PTR == CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_agent_start: "
                                                    "dup uds path '%s' failed\n",
                                                    (char *)cstring_get_str(uds_path));

        cbc_md_free(MD_CUNIXPACKET, cunixpacket_agent_md_id);
        return (CMPI_ERROR_MODI);
    }

    CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md)    = uds_listen_socket;

    CUNIXPACKET_AGENT_MD_UDS_PACKET_SENDING(cunixpacket_agent_md)   = BIT_FALSE;

    clist_init(CUNIXPACKET_AGENT_MD_UDS_PACKET_LIST(cunixpacket_agent_md), MM_CBUFFER, LOC_CUNIXPACKET_0001);


    /*TODO: load all variables into module*/

    cunixpacket_agent_md->usedcounter = 1;

    cepoll_set_event(task_brd_default_get_cepoll(),
                      CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md),
                      CEPOLL_RD_EVENT,
                      (const char *)"cunixpacket_agent_accept",
                      (CEPOLL_EVENT_HANDLER)cunixpacket_agent_accept,
                      (void *)cunixpacket_agent_md_id);

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cunixpacket_agent_process,
                        (void *)cunixpacket_agent_md_id);

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cunixpacket_agent_end, cunixpacket_agent_md_id);

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_agent_start: "
                                                "start CUNIXPACKET_AGENT module #%ld\n",
                                                cunixpacket_agent_md_id);

    return ( cunixpacket_agent_md_id );
}

/**
*
* end CUNIXPACKET_AGENT module
*
**/
void cunixpacket_agent_end(const UINT32 cunixpacket_agent_md_id)
{
    CUNIXPACKET_AGENT_MD  *cunixpacket_agent_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cunixpacket_agent_end, cunixpacket_agent_md_id);

    task_brd_process_del(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cunixpacket_agent_process,
                        (void *)cunixpacket_agent_md_id);

    cunixpacket_agent_md = CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id);
    if(NULL_PTR == cunixpacket_agent_md)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_agent_end: "
                                                    "cunixpacket_agent_md_id = %ld not exist.\n",
                                                    cunixpacket_agent_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_agent_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cunixpacket_agent_md->usedcounter )
    {
        cunixpacket_agent_md->usedcounter --;
        return ;
    }

    if ( 0 == cunixpacket_agent_md->usedcounter )
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_agent_end: "
                                                    "cunixpacket_agent_md_id = %ld is not started.\n",
                                                    cunixpacket_agent_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_agent_md_id);
    }

    if(NULL_PTR != CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md))
    {
        cstring_free(CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md));
        CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md)     = NULL_PTR;
    }

    if(ERR_FD != CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md))
    {
        cepoll_del_all(task_brd_default_get_cepoll(), CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md));
        csocket_close(CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md));
        CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md) = ERR_FD;
    }

    CUNIXPACKET_AGENT_MD_UDS_PACKET_SENDING(cunixpacket_agent_md)   = BIT_FALSE;

    clist_clean(CUNIXPACKET_AGENT_MD_UDS_PACKET_LIST(cunixpacket_agent_md), (CLIST_DATA_DATA_CLEANER)cbuffer_free);

    /* free module */
    cunixpacket_agent_md->usedcounter = 0;

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "cunixpacket_agent_end: "
                                                "stop CUNIXPACKET_AGENT module #%ld\n",
                                                cunixpacket_agent_md_id);
    cbc_md_free(MD_CUNIXPACKET, cunixpacket_agent_md_id);

    return ;
}

CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node_new()
{
    CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node;

    alloc_static_mem(MM_CUNIXPACKET_AGENT_NODE, &cunixpacket_agent_node, LOC_CUNIXPACKET_0002);
    if(NULL_PTR == cunixpacket_agent_node)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_agent_node_new: "
                                                    "new  cunixpacket_agent_node failed\n");
        return (NULL_PTR);
    }

    cunixpacket_agent_node_init(cunixpacket_agent_node);
    return (cunixpacket_agent_node);
}

EC_BOOL cunixpacket_agent_node_init(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node)
{
    if(NULL_PTR != cunixpacket_agent_node)
    {
        CUNIXPACKET_AGENT_NODE_UDS_MODI(cunixpacket_agent_node)   = CMPI_ERROR_MODI;
        CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node) = ERR_FD;
    }

    return (EC_TRUE);
}

EC_BOOL cunixpacket_agent_node_clean(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node)
{
    if(NULL_PTR != cunixpacket_agent_node)
    {
        CUNIXPACKET_AGENT_NODE_UDS_MODI(cunixpacket_agent_node)   = CMPI_ERROR_MODI;

        if(ERR_FD != CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node))
        {
            cepoll_del_all(task_brd_default_get_cepoll(), CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node));
            csocket_close(CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node));

            CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node) = ERR_FD;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cunixpacket_agent_node_free(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node)
{
    if(NULL_PTR != cunixpacket_agent_node)
    {
        cunixpacket_agent_node_clean(cunixpacket_agent_node);
        free_static_mem(MM_CUNIXPACKET_AGENT_NODE, cunixpacket_agent_node, LOC_CUNIXPACKET_0003);
    }

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cunixpacket_agent_shutdown_socket(void *arg)
{
    int sockfd;

    sockfd = (int)((uint64_t)arg);

    dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_shutdown_socket: "
                                                "shutdown socket %d\n",
                                                sockfd);
    return csocket_close(sockfd);
}

/**
*
* listen on unix domain socket with unixpacket and accept new connection
*
**/
EC_BOOL cunixpacket_agent_accept(const UINT32 cunixpacket_agent_md_id)
{
    CUNIXPACKET_AGENT_MD        *cunixpacket_agent_md;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_AGENT_MD_ID_CHECK_INVALID(cunixpacket_agent_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_agent_accept: cunixpacket_agent module #0x%lx not started.\n",
                cunixpacket_agent_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_agent_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_agent_md = CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id);

    for(;;)
    {
        CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node;

        int conn_socket;

        if(EC_FALSE == csocket_unixpacket_accept(
                                CUNIXPACKET_AGENT_MD_UDS_LISTEN_SOCKET(cunixpacket_agent_md),
                                &conn_socket, CSOCKET_IS_NONBLOCK_MODE))
        {
            break;
        }

        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_agent_accept: "
                                                    "uds path '%s' accept socket %d\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                    conn_socket);

        cunixpacket_agent_node = cunixpacket_agent_node_new();
        if(NULL_PTR == cunixpacket_agent_node)
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_agent_accept: "
                                                        "uds path '%s', new cunixpacket_agent_node failed "
                                                        "=> close socket %d => terminate\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        conn_socket);
             csocket_close(conn_socket);
             break;
        }

        CUNIXPACKET_AGENT_NODE_UDS_MODI(cunixpacket_agent_node)   = cunixpacket_agent_md_id;
        CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node) = conn_socket;


        cepoll_set_event(task_brd_default_get_cepoll(),
                          conn_socket,
                          CEPOLL_RD_EVENT,
                          (const char *)"__cunixpacket_agent_recv_packet",
                          (CEPOLL_EVENT_HANDLER)__cunixpacket_agent_recv_packet,
                          (void *)cunixpacket_agent_node);

        cepoll_set_shutdown(task_brd_default_get_cepoll(),
                        conn_socket,
                        (const char *)"__cunixpacket_agent_shutdown_socket",
                        (CEPOLL_EVENT_HANDLER)__cunixpacket_agent_shutdown_socket,
                        (void *)(uint64_t)conn_socket);
    }

    return (EC_TRUE);
}

/**
*
* recv data from unix domain socket with unixpacket
*
**/
STATIC_CAST EC_BOOL __cunixpacket_agent_recv_packet(CUNIXPACKET_AGENT_NODE *cunixpacket_agent_node)
{
    UINT32                       cunixpacket_agent_md_id;
    CUNIXPACKET_AGENT_MD        *cunixpacket_agent_md;
    CBUFFER                     *uds_packet_data;
    uint32_t                     used_pos;
    uint32_t                     recv_len;
    uint32_t                     recv_packet_max_num;
    uint32_t                     recv_packet_cur_num;

    if(NULL_PTR == cunixpacket_agent_node)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_recv_packet: "
                                                    "cunixpacket_agent_node is null\n");
        return (EC_FALSE);
    }

    cunixpacket_agent_md_id = CUNIXPACKET_AGENT_NODE_UDS_MODI(cunixpacket_agent_node);

    if ( CUNIXPACKET_AGENT_MD_ID_CHECK_INVALID(cunixpacket_agent_md_id) )
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_recv_packet: "
                                                    "cunixpacket_agent module #0x%lx not started.\n",
                                                    cunixpacket_agent_md_id);
        return (EC_FALSE);
    }

    cunixpacket_agent_md = CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id);

    /*check validity*/
    if(NULL_PTR == CUNIXPACKET_AGENT_MD_UDS_PATH(cunixpacket_agent_md))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_recv_packet: "
                                                    "no uds path\n");
        return (EC_FALSE);
    }

    recv_len = 0;

    recv_packet_max_num = CUNIXPACKET_AGENT_UDS_PACKET_RECV_MAX_NUM;
    for(recv_packet_cur_num = 0;
        recv_packet_cur_num < recv_packet_max_num;
        recv_packet_cur_num ++)
    {
        UINT32      pos;

        /*check latest packet*/
        uds_packet_data = clist_last_data(CUNIXPACKET_AGENT_MD_UDS_PACKET_LIST(cunixpacket_agent_md));
        if(NULL_PTR == uds_packet_data
        || cbuffer_used(uds_packet_data) + CUNIXPACKET_AGENT_UDS_PACKET_MAX_SIZE > cbuffer_size(uds_packet_data))
        {
            uds_packet_data = cbuffer_new((uint32_t)CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE);
            if(NULL_PTR == uds_packet_data)
            {
                dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_recv_packet: "
                                                            "uds path '%s', new buffer with size %u failed\n",
                                                            (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                            (uint32_t)CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE);
                return (EC_FALSE);
            }

            clist_push_back(CUNIXPACKET_AGENT_MD_UDS_PACKET_LIST(cunixpacket_agent_md), (void *)uds_packet_data);

            dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_recv_packet: "
                                                        "uds path '%s', new buffer with size %u done\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        (uint32_t)CUNIXPACKET_AGENT_UDS_PACKET_BUF_SIZE);
        }

        /*save used position*/
        used_pos = CBUFFER_USED(uds_packet_data);
        pos      = CBUFFER_USED(uds_packet_data); /*pos is tmp variable to avoid parameter type issue*/
        if(EC_FALSE == csocket_unixpacket_recv(CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node),
                                               CBUFFER_DATA(uds_packet_data),
                                               CBUFFER_SIZE(uds_packet_data),
                                               &pos))
        {
            CBUFFER_USED(uds_packet_data) = (uint32_t)pos; /*update at once*/

            recv_len += CBUFFER_USED(uds_packet_data) - used_pos;

            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_recv_packet: "
                                                        "uds path '%s' recv on socket %d failed, "
                                                        "last packet size %u used %u, "
                                                        "once recv %u => total recv %u bytes\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        CUNIXPACKET_AGENT_NODE_UDS_SOCKET(cunixpacket_agent_node),
                                                        CBUFFER_SIZE(uds_packet_data),
                                                        CBUFFER_USED(uds_packet_data),
                                                        CBUFFER_USED(uds_packet_data) - used_pos,
                                                        recv_len);

            /*return false would trigger shutdown handler and delete event and close socket*/
            return (EC_FALSE);
        }
        CBUFFER_USED(uds_packet_data) = (uint32_t)pos; /*update at once*/

        if(used_pos == CBUFFER_USED(uds_packet_data))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_recv_packet: "
                                                        "uds path '%s' recv nothing => complete\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md));
            break;
        }

        recv_len += CBUFFER_USED(uds_packet_data) - used_pos;

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_recv_packet: "
                                                    "uds path '%s' last packet size %u used %u, "
                                                    "once recv %u => total recv %u\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                    CBUFFER_SIZE(uds_packet_data),
                                                    CBUFFER_USED(uds_packet_data),
                                                    CBUFFER_USED(uds_packet_data) - used_pos,
                                                    recv_len);
    }

    dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_recv_packet: "
                                                "uds path '%s' => complete recv %u\n",
                                                (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                recv_len);
    return (EC_TRUE);
}

/**
*
* send one packet data to remote http server
*
**/
STATIC_CAST EC_BOOL __cunixpacket_agent_send_packet(const UINT32 cunixpacket_agent_md_id, CBUFFER *uds_packet_data)
{
    CUNIXPACKET_AGENT_MD        *cunixpacket_agent_md;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_AGENT_MD_ID_CHECK_INVALID(cunixpacket_agent_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cunixpacket_agent_send_packet: cunixpacket_agent module #0x%lx not started.\n",
                cunixpacket_agent_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_agent_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_agent_md = CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id);

    chttp_req = chttp_req_new();
    if(NULL_PTR == chttp_req)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                    "uds path '%s' new http req failed\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md));

        return (EC_FALSE);
    }

    chttp_rsp = chttp_rsp_new();
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                    "uds path '%s' new http rsp failed\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md));

        chttp_req_free(chttp_req);

        return (EC_FALSE);
    }

    do
    {
        const char                  *v;

        v = (const char *)CUNIXPACKET_AGENT_HTTP_REQ_SERVER;
        if(EC_FALSE == chttp_req_set_server(chttp_req, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', set server '%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }
        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_send_packet: "
                                                    "uds path '%s', set server '%s' done\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                    v);
    }while(0);

    do
    {
        const char                  *k;
        const char                  *v;

        v = (const char *)"POST";
        if(EC_FALSE == chttp_req_set_method(chttp_req, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', add '%s' method failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }

        v = (const char *)CUNIXPACKET_AGENT_HTTP_REQ_URI;
        if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', add uri '%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }

        k = (const char *)"Host";
        v = (const char *)CUNIXPACKET_AGENT_HTTP_REQ_DOMAIN;
        if(EC_FALSE == chttp_req_add_header(chttp_req, k, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', add header '%s':'%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        k, v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }
        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_send_packet: "
                                                    "uds path '%s', add header '%s':'%s' done\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                    k, v);

        k = (const char *)"Accept";
        v = (const char *)"*/*";
        if(EC_FALSE == chttp_req_add_header(chttp_req, k, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', add header '%s':'%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        k, v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }

        k = (const char *)"Connection";
        v = (const char *)"keep-alive";
        if(EC_FALSE == chttp_req_add_header(chttp_req, k, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', add header '%s':'%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        k, v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }
    }while(0);

    /*add params*/
    do
    {
        const char                  *k;
        const char                  *v;

        uint64_t                     expired_time_nsec;

        uint8_t                      digest[ CMD5_DIGEST_LEN ];
        char                        *digest_str;


        uint32_t                     data_len;/*format: <token>@<op><path>@<time>*/
        char                        *data;     /*format: <token>@<op><path>@<time>*/

        expired_time_nsec = c_get_cur_time_nsec() + CUNIXPACKET_AGENT_HTTP_REQ_EXPIRED_NSEC;

        data_len = 0;

        data_len += strlen(CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN); /*<token>*/
        data_len ++; /*@*/

        k = (const char *)"op";
        v = (const char *)CUNIXPACKET_AGENT_HTTP_REQ_OP;
        if(EC_FALSE == chttp_req_add_param(chttp_req, k, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', http req add para '%s':'%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        k, v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }
        data_len += strlen(v); /*<op>*/
        data_len += strlen(CUNIXPACKET_AGENT_HTTP_REQ_URI); /*<path>*/

        k = (const char *)"t";
        v = (const char *)c_uint64_t_to_str(expired_time_nsec);
        if(EC_FALSE == chttp_req_add_param(chttp_req, k, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', http req add para '%s':'%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        k, v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }
        data_len += 1 + strlen(v); /*@<time>*/

        /*md5(<token>@<op><path>@<time>)*/
        do
        {
            data = safe_malloc(data_len + 1, LOC_CUNIXPACKET_0004);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                            "uds path '%s', new %u bytes failed\n",
                                                            (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                            data_len + 1);

                chttp_rsp_free(chttp_rsp);
                chttp_req_free(chttp_req);

                return (EC_FALSE);
            }

            snprintf(data, data_len + 1, "%s@%s%s@%s",
                                         CUNIXPACKET_AGENT_HTTP_REQ_ACL_TOKEN,
                                         CUNIXPACKET_AGENT_HTTP_REQ_OP,
                                         CUNIXPACKET_AGENT_HTTP_REQ_URI,
                                         c_uint64_t_to_str(expired_time_nsec));

            cmd5_sum(data_len, (uint8_t *)data, digest);
            digest_str = c_md5_to_hex_str(digest);

            dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_send_packet: "
                                                        "uds path '%s', md5('%s', len %u) => '%s'\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        data, data_len,
                                                        digest_str);
            safe_free(data, LOC_CUNIXPACKET_0005);
        }while(0);


        k = (const char *)"sig";
        v = (const char *)digest_str;

        if(EC_FALSE == chttp_req_add_param(chttp_req, k, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', http req add para '%s':'%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        k, v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }
    }while(0);

    do
    {
        const char                  *k;
        const char                  *v;

        if(EC_FALSE == chttp_req_set_body(chttp_req, CBUFFER_DATA(uds_packet_data), CBUFFER_USED(uds_packet_data)))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', make body with %u bytes failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        CBUFFER_USED(uds_packet_data));

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }

        k = (const char *)"Content-Length";
        v = (const char *)c_uint32_t_to_str(CBUFFER_USED(uds_packet_data));

        if(EC_FALSE == chttp_req_add_header(chttp_req, k, v))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                        "uds path '%s', add header '%s':'%s' failed\n",
                                                        (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                        k, v);

            chttp_rsp_free(chttp_rsp);
            chttp_req_free(chttp_req);

            return (EC_FALSE);
        }
    }while(0);

    if(do_log(SEC_0009_CUNIXPACKET, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_send_packet: "
                           "uds path '%s', http req:\n",
                           (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md));

        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, NULL_PTR/*chttp_store*/, chttp_rsp, NULL_PTR/*chttp_stat*/))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:__cunixpacket_agent_send_packet: "
                                                    "uds path '%s', http request failed\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md));

        chttp_rsp_free(chttp_rsp);
        chttp_req_free(chttp_req);

        return (EC_FALSE);
    }

    if(do_log(SEC_0009_CUNIXPACKET, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_send_packet: "
                           "uds path '%s', http rsp:\n",
                           (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md));

        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] __cunixpacket_agent_send_packet: "
                                                "uds path '%s', send request done\n",
                                                (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md));

    chttp_rsp_free(chttp_rsp);
    chttp_req_free(chttp_req);

    return (EC_TRUE);
}

/**
*
* send all packet data to remote http server
*
**/
EC_BOOL cunixpacket_agent_process_packet(const UINT32 cunixpacket_agent_md_id)
{
    CUNIXPACKET_AGENT_MD        *cunixpacket_agent_md;
    CBUFFER                     *uds_packet_data;

    CLIST                       *uds_packet_list;

    uint32_t                     sent_packet_num;
    uint32_t                     sent_packet_len;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_AGENT_MD_ID_CHECK_INVALID(cunixpacket_agent_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_agent_process_packet: cunixpacket_agent module #0x%lx not started.\n",
                cunixpacket_agent_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_agent_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_agent_md = CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id);

    CUNIXPACKET_AGENT_MD_UDS_PACKET_SENDING(cunixpacket_agent_md) = BIT_TRUE;

    uds_packet_list = CUNIXPACKET_AGENT_MD_UDS_PACKET_LIST(cunixpacket_agent_md);

    sent_packet_num = 0;
    sent_packet_len = 0;

    while(BIT_TRUE == CUNIXPACKET_AGENT_MD_UDS_PACKET_SENDING(cunixpacket_agent_md)
    && CUNIXPACKET_AGENT_UDS_PACKET_SENT_MAX_NUM > sent_packet_num
    && NULL_PTR != (uds_packet_data = clist_pop_front(uds_packet_list)))
    {
        if(EC_FALSE == __cunixpacket_agent_send_packet(cunixpacket_agent_md_id, uds_packet_data))
        {
            clist_push_front(uds_packet_list, uds_packet_data);
            break;
        }

        sent_packet_num ++;
        sent_packet_len += CBUFFER_USED(uds_packet_data);

        cbuffer_free(uds_packet_data);
    }

    CUNIXPACKET_AGENT_MD_UDS_PACKET_SENDING(cunixpacket_agent_md) = BIT_FALSE;

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_agent_process_packet: "
                                                "uds path '%s', sent packet num %u, packet len %u\n",
                                                (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                sent_packet_num, sent_packet_len);

    return (EC_TRUE);
}

EC_BOOL cunixpacket_agent_process(const UINT32 cunixpacket_agent_md_id)
{
    CUNIXPACKET_AGENT_MD        *cunixpacket_agent_md;

    CLIST                       *uds_packet_list;
    uint32_t                     uds_packet_cache_max_num;
    uint32_t                     discard_len;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_AGENT_MD_ID_CHECK_INVALID(cunixpacket_agent_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_agent_process: cunixpacket_agent module #0x%lx not started.\n",
                cunixpacket_agent_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_agent_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_agent_md = CUNIXPACKET_AGENT_MD_GET(cunixpacket_agent_md_id);

    uds_packet_list = CUNIXPACKET_AGENT_MD_UDS_PACKET_LIST(cunixpacket_agent_md);

    discard_len = 0;
    uds_packet_cache_max_num = CUNIXPACKET_AGENT_UDS_PACKET_CACHE_MAX_NUM;
    while((UINT32)uds_packet_cache_max_num < clist_size(uds_packet_list))
    {
        CBUFFER                     *uds_packet_data;

        uds_packet_data = clist_pop_front(uds_packet_list);

        /*discard packet data*/
        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_agent_process: "
                                                    "uds path '%s', discard data len %u\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                    CBUFFER_USED(uds_packet_data));

        discard_len += CBUFFER_USED(uds_packet_data);
        cbuffer_free(uds_packet_data);
    }

    if(0 < discard_len)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_agent_process: "
                                                    "uds path '%s', discard data total len: %u\n",
                                                    (char *)CUNIXPACKET_AGENT_MD_UDS_PATH_STR(cunixpacket_agent_md),
                                                    discard_len);
    }

    if(BIT_FALSE == CUNIXPACKET_AGENT_MD_UDS_PACKET_SENDING(cunixpacket_agent_md)
    && 0 < clist_size(uds_packet_list))
    {
        MOD_NODE      recv_mod_node;

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&recv_mod_node) = cunixpacket_agent_md_id;

        task_p2p_no_wait(cunixpacket_agent_md_id, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                     &recv_mod_node,
                     NULL_PTR,
                     FI_cunixpacket_agent_process_packet, CMPI_ERROR_MODI);
    }

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cunixpacket_agent_process,
                        (void *)cunixpacket_agent_md_id);

    return (EC_TRUE);
}

#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


