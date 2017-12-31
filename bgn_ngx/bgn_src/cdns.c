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
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"
#include "cqueue.h"

#include "cbc.h"

#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "cepoll.h"

#include "cbuffer.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"

#include "db_internal.h"
#include "cdns.inc"
#include "cdns.h"
#include "coroutine.h"
#include "findex.inc"


/*private interface, not for dns parser*/
static EC_BOOL __cdns_on_recv_complete(CDNS_NODE *cdns_node)
{
    CSOCKET_CNODE *csocket_cnode;

    csocket_cnode = CDNS_NODE_CSOCKET_CNODE(cdns_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:__cdns_on_recv_complete: cdns_node %p -> csocket_cnode is null\n", cdns_node);
        return (EC_FALSE);/*error*/
    } 
 
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] __cdns_on_recv_complete: sockfd %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
 
    /*note: dns request is ready now. stop read from socket to prevent recving during handling request*/
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    
    if(NULL_PTR != CDNS_NODE_CROUTINE_COND(cdns_node) && BIT_FALSE == CDNS_NODE_COROUTINE_RESTORE(cdns_node))
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] __cdns_on_recv_complete: sockfd %d retore coroutine %p\n",
                CSOCKET_CNODE_SOCKFD(csocket_cnode), CDNS_NODE_CROUTINE_COND(cdns_node)); 

        CDNS_NODE_COROUTINE_RESTORE(cdns_node) = BIT_TRUE;     
        croutine_cond_release(CDNS_NODE_CROUTINE_COND(cdns_node), LOC_CDNS_0001);
    }

    CDNS_NODE_RECV_COMPLETE(cdns_node) = BIT_TRUE;

    return (EC_TRUE);
}

/*---------------------------------------- INTERFACE WITH DNS NODE  ----------------------------------------*/
EC_BOOL cdns_header_init(CDNS_HEADER *cdns_header)
{
    BSET(cdns_header, 0x00, sizeof(CDNS_HEADER));
    return (EC_TRUE);
}

EC_BOOL cdns_header_clean(CDNS_HEADER *cdns_header)
{
    BSET(cdns_header, 0x00, sizeof(CDNS_HEADER));
    return (EC_TRUE);
}

void cdns_header_print(LOG *log, const CDNS_HEADER *cdns_header)
{
    sys_log(log, "cdns_header_print:header : \n");
    sys_log(log, "cdns_header_print:      id : %u\n", CDNS_HEADER_ID(cdns_header));
    sys_log(log, "cdns_header_print:      QR : [1b] %u\n", CDNS_HEADER_FLAG_QR(cdns_header));
    sys_log(log, "cdns_header_print:  OPCODE : [4b] %u\n", CDNS_HEADER_FLAG_OPCODE(cdns_header));
    sys_log(log, "cdns_header_print:      AA : [1b] %u\n", CDNS_HEADER_FLAG_AA(cdns_header));
    sys_log(log, "cdns_header_print:      TC : [1b] %u\n", CDNS_HEADER_FLAG_TC(cdns_header));
    sys_log(log, "cdns_header_print:      RD : [1b] %u\n", CDNS_HEADER_FLAG_RD(cdns_header));
    sys_log(log, "cdns_header_print:      RA : [1b] %u\n", CDNS_HEADER_FLAG_RA(cdns_header));
    sys_log(log, "cdns_header_print:    ZERO : [3b] %u\n", CDNS_HEADER_FLAG_ZERO(cdns_header));
    sys_log(log, "cdns_header_print:   RCODE : [4b] %u\n", CDNS_HEADER_FLAG_RCODE(cdns_header));
    sys_log(log, "cdns_header_print:   Q_NUM : %u\n", CDNS_HEADER_Q_NUM(cdns_header));
    sys_log(log, "cdns_header_print:   R_NUM : %u\n", CDNS_HEADER_R_NUM(cdns_header));
    sys_log(log, "cdns_header_print:   O_NUM : %u\n", CDNS_HEADER_O_NUM(cdns_header));
    sys_log(log, "cdns_header_print:   E_NUM : %u\n", CDNS_HEADER_E_NUM(cdns_header));

    return;
}

/*---------------------------------------- INTERFACE WITH DNS NODE  ----------------------------------------*/
CDNS_NODE *cdns_node_new()
{
    CDNS_NODE *cdns_node;

    alloc_static_mem(MM_CDNS_NODE, &cdns_node, LOC_CDNS_0002);
    if(NULL_PTR == cdns_node)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_new: new cdns_node failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdns_node_init(cdns_node))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_new: init cdns_node failed\n");
        free_static_mem(MM_CDNS_NODE, cdns_node, LOC_CDNS_0003);
        return (NULL_PTR);
    }

    return (cdns_node);
}

EC_BOOL cdns_node_init(CDNS_NODE *cdns_node)
{
    if(NULL_PTR != cdns_node)
    {
        CDNS_NODE_CROUTINE_NODE(cdns_node) = NULL_PTR;

        CDNS_NODE_CROUTINE_COND(cdns_node) = NULL_PTR;

        CDNS_NODE_CSOCKET_CNODE(cdns_node)     = NULL_PTR;

        cbuffer_init(CDNS_NODE_IN_BUF(cdns_node), CDNS_IN_BUF_SIZE);
        chunk_init(CDNS_NODE_SEND_BUF(cdns_node), CDNS_OUT_BUF_SIZE);

        CDNS_NODE_REQ(cdns_node)  = NULL_PTR;
        CDNS_NODE_RSP(cdns_node)  = NULL_PTR;

        CDNS_NODE_ID(cdns_node)   = 0;
        CDNS_NODE_QLEN(cdns_node) = 0;

        CDNS_NODE_RECV_COMPLETE(cdns_node)     = BIT_FALSE;
        CDNS_NODE_COROUTINE_RESTORE(cdns_node) = BIT_FALSE;
    }
 
    return (EC_TRUE);
}

EC_BOOL cdns_node_clean(CDNS_NODE *cdns_node)
{
    if(NULL_PTR != cdns_node)
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_clean: try to clean cdns_node %p\n", cdns_node);

        if(NULL_PTR != CDNS_NODE_CROUTINE_NODE(cdns_node))
        {
            croutine_pool_unload(TASK_REQ_CTHREAD_POOL(task_brd_default_get()), CDNS_NODE_CROUTINE_NODE(cdns_node));
            CDNS_NODE_CROUTINE_NODE(cdns_node) = NULL_PTR;
        }

        if(NULL_PTR != CDNS_NODE_CROUTINE_COND(cdns_node))
        {
            croutine_cond_free(CDNS_NODE_CROUTINE_COND(cdns_node), LOC_CDNS_0004);
            CDNS_NODE_CROUTINE_COND(cdns_node) = NULL_PTR;
        }

        cbuffer_clean(CDNS_NODE_IN_BUF(cdns_node));
        chunk_clean(CDNS_NODE_SEND_BUF(cdns_node));
     
        CDNS_NODE_CSOCKET_CNODE(cdns_node)     = NULL_PTR; /*not handle the mounted csocket_cnode*/

        CDNS_NODE_REQ(cdns_node)  = NULL_PTR; /*not handle the mounted cdns_req*/
        CDNS_NODE_RSP(cdns_node)  = NULL_PTR; /*not handle the mounted cdns_rsp*/

        CDNS_NODE_ID(cdns_node)   = 0;
        CDNS_NODE_QLEN(cdns_node) = 0;

        CDNS_NODE_RECV_COMPLETE(cdns_node)     = BIT_FALSE;
        CDNS_NODE_COROUTINE_RESTORE(cdns_node) = BIT_FALSE;
    }
 
    return (EC_TRUE);
}

EC_BOOL cdns_node_free(CDNS_NODE *cdns_node)
{
    if(NULL_PTR != cdns_node)
    {
        cdns_node_clean(cdns_node);
        free_static_mem(MM_CDNS_NODE, cdns_node, LOC_CDNS_0005);
    }

    return (EC_TRUE);
}

EC_BOOL cdns_node_recv(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode)
{
    CBUFFER *dns_in_buffer;
    UINT32   pos;

    dns_in_buffer = CDNS_NODE_IN_BUF(cdns_node);
 
    pos = CBUFFER_USED(dns_in_buffer);
    if(EC_FALSE == csocket_cnode_recv(csocket_cnode,
                                CBUFFER_DATA(dns_in_buffer),
                                CBUFFER_SIZE(dns_in_buffer),
                                &pos))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_recv: read on sockfd %d failed where size %d and used %d\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CBUFFER_SIZE(dns_in_buffer),
                            CBUFFER_USED(dns_in_buffer));

        return (EC_FALSE);                         
    }

    if(CBUFFER_USED(dns_in_buffer) == pos)/*Exception!*/
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT,
                            "error:cdns_node_recv: read nothing on sockfd %d failed whence buffer size %d and used %d\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CBUFFER_SIZE(dns_in_buffer),
                            CBUFFER_USED(dns_in_buffer));

        __cdns_on_recv_complete(cdns_node);
        return (EC_DONE);      
    }

    CBUFFER_USED(dns_in_buffer) = (uint32_t)pos;
    return (EC_TRUE);
}

EC_BOOL cdns_node_send(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode)
{
    CHUNK *chunk;
    UINT32 pos;
 
    chunk = CDNS_NODE_SEND_BUF(cdns_node);
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_send: sockfd %d chunk %p offset %d, buffer used %d\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        chunk, CHUNK_OFFSET(chunk), CHUNK_USED(chunk));
    if(CHUNK_OFFSET(chunk) >= CHUNK_USED(chunk))
    {
        /*send completely*/
        chunk_clean(chunk);
        return (EC_TRUE);
    }

    pos = CHUNK_OFFSET(chunk);
    if(EC_FALSE == csocket_cnode_send(csocket_cnode, CHUNK_DATA(chunk), CHUNK_USED(chunk), &pos))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_send: sockfd %d send %ld bytes failed\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CHUNK_USED(chunk) - CHUNK_OFFSET(chunk)
                           );
     
        return (EC_FALSE);                        
    }

    if(CHUNK_OFFSET(chunk) == (uint32_t)pos)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT,
                            "error:cdns_node_send: send nothing on sockfd %d failed whence chunk offset %d and used %d\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CHUNK_OFFSET(chunk),
                            CHUNK_USED(chunk));

        return (EC_FALSE);
    }
 
    CHUNK_OFFSET(chunk) = (uint32_t)pos;
    if(CHUNK_OFFSET(chunk) < CHUNK_USED(chunk))
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_send: sockfd %d continous chunk %p, offset %u size %u\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode), chunk, CHUNK_OFFSET(chunk), CHUNK_USED(chunk)); 
 
        return (EC_FALSE);
    }

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_send: sockfd %d clean chunk %p, size %u\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode), chunk, CHUNK_USED(chunk)); 
 
    /*chunk is sent completely*/
    chunk_clean(chunk);

    return (EC_TRUE);
}

EC_BOOL cdns_node_need_send(CDNS_NODE *cdns_node)
{
    if(EC_TRUE == chunk_is_empty(CDNS_NODE_SEND_BUF(cdns_node)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdns_node_send_req(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode)
{
    if(EC_FALSE == cdns_node_send(cdns_node, csocket_cnode))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_send_req: sockfd %d send req failed\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(EC_TRUE == cdns_node_need_send(cdns_node))
    {
        //return (EC_AGAIN);
        return (EC_FALSE);
    }

    chunk_clean(CDNS_NODE_SEND_BUF(cdns_node));/*clean up asap*/

    //CDNS_NODE_LOG_TIME_WHEN_SENT(cdns_node);
 
    /*now all data had been sent out, del WR event and set RD event*/
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_send_req: sockfd %d had sent out all req data\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));  
    return (EC_TRUE);
}

EC_BOOL cdns_node_recv_rsp(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode)
{
    EC_BOOL     ret;

    ret = cdns_node_recv(cdns_node, csocket_cnode);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_recv_rsp: recv req on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);                         
    }

    if(EC_DONE == ret)
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_recv_rsp: sockfd %d, no more data to recv or parse\n",
                CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_DONE);
    }

    if(EC_FALSE == cdns_parse_rsp(cdns_node, CDNS_NODE_RSP(cdns_node)))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_recv_rsp: parse on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);                         
    }

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_recv_rsp: sockfd %d, recv and parse done\n",
            CSOCKET_CNODE_SOCKFD(csocket_cnode));

    /*note: here if return EC_DONE, one must set CDNS_NODE_RECV_COMPLETE flag to true at first*/
    __cdns_on_recv_complete(cdns_node);
    
    return (EC_DONE);
}

/*dns is over udp. disconnect means umount csocket_cnode from cdns_node*/
EC_BOOL cdns_node_disconnect(CDNS_NODE *cdns_node)
{
    if(NULL_PTR != CDNS_NODE_CSOCKET_CNODE(cdns_node))
    {
        CSOCKET_CNODE       *csocket_cnode;

        csocket_cnode = CDNS_NODE_CSOCKET_CNODE(cdns_node);

        /*unmount*/
        CDNS_NODE_CSOCKET_CNODE(cdns_node) = NULL_PTR;
        
        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);            
    }

    return (EC_TRUE);
}

EC_BOOL cdns_node_set_callback(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode)
{
    /*set callback*/
    csocket_cnode_push_recv_callback(csocket_cnode, 
                                     (const char *)"cdns_node_recv_rsp", 
                                     (UINT32)cdns_node, (UINT32)cdns_node_recv_rsp);
                                     
    csocket_cnode_push_send_callback(csocket_cnode, 
                                     (const char *)"cdns_node_send_req", 
                                     (UINT32)cdns_node, (UINT32)cdns_node_send_req);

    csocket_cnode_push_close_callback(csocket_cnode, 
                                     (const char *)"cdns_node_close", 
                                     (UINT32)cdns_node, (UINT32)cdns_node_close);

    csocket_cnode_push_timeout_callback(csocket_cnode, 
                                     (const char *)"cdns_node_timeout", 
                                     (UINT32)cdns_node, (UINT32)cdns_node_close);

    csocket_cnode_push_shutdown_callback(csocket_cnode, 
                                     (const char *)"cdns_node_shutdown", 
                                     (UINT32)cdns_node, (UINT32)cdns_node_close);
    return (EC_TRUE);
}

EC_BOOL cdns_node_set_epoll(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode)
{
#if 0
    cepoll_set_event(task_brd_default_get_cepoll(),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    CEPOLL_WR_EVENT,
                    (const char *)"csocket_cnode_isend",
                    (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                    (void *)csocket_cnode);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
#endif               
    cepoll_set_complete(task_brd_default_get_cepoll(),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    (const char *)"csocket_cnode_iclose",
                    (CEPOLL_EVENT_HANDLER)csocket_cnode_iclose,
                    (void *)csocket_cnode);

    cepoll_set_shutdown(task_brd_default_get_cepoll(),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    (const char *)"csocket_cnode_ishutdown",
                    (CEPOLL_EVENT_HANDLER)csocket_cnode_ishutdown,
                    (void *)csocket_cnode);

    cepoll_set_timeout(task_brd_default_get_cepoll(),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    (uint32_t)CONN_TIMEOUT_NSEC,
                    (const char *)"csocket_cnode_itimeout",
                    (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                    (void *)csocket_cnode);

    return (EC_TRUE);
}

EC_BOOL cdns_node_create(CDNS_NODE *cdns_node, const CDNS_REQ * cdns_req)
{
    int sockfd;
    UINT32 ipaddr;
    UINT32 port;
 
    CSOCKET_CNODE *csocket_cnode;
    EC_BOOL ret;

    ipaddr = CDNS_REQ_IPADDR(cdns_req);
    port   = CDNS_REQ_PORT(cdns_req);
 
    if(EC_FALSE == csocket_udp_create( ipaddr, port , CSOCKET_IS_NONBLOCK_MODE, &sockfd ))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_create: connect server %s:%ld failed\n",
                            c_word_to_ipv4(ipaddr), port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_create: socket %d created for udp server %s:%ld\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);

    csocket_cnode = csocket_cnode_new(CMPI_ERROR_TCID, sockfd, CSOCKET_TYPE_UDP, ipaddr, port);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_create:new csocket cnode for socket %d to server %s:%ld failed\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);
        csocket_close(sockfd);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdns_make_req(cdns_node, cdns_req))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_create:make req for socket %d to server %s:%ld failed\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);

        csocket_cnode_free(csocket_cnode);
        return (EC_FALSE);
    }

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_create:make req for socket %d to server %s:%ld done\n",
                    sockfd, c_word_to_ipv4(ipaddr), port); 
                 
    ret = cdns_node_send_req(cdns_node, csocket_cnode);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_node_create:send req on socket %d to server %s:%ld failed\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);

        csocket_cnode_close(csocket_cnode);
        return (EC_FALSE);
    }

    /* mount */
    CDNS_NODE_CSOCKET_CNODE(cdns_node) = csocket_cnode;    

    cdns_node_set_callback(cdns_node, csocket_cnode);
    cdns_node_set_epoll(cdns_node, csocket_cnode);    

    if(EC_AGAIN == ret)
    {
        /*never reach here*/
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_WR_EVENT,
                        (const char *)"csocket_cnode_isend",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                        (void *)csocket_cnode);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_create: sockfd %d set event WR\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_TRUE);
    }

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_create:send req on socket %d to server %s:%ld done\n",
                    sockfd, c_word_to_ipv4(ipaddr), port);
                 
    cepoll_set_event(task_brd_default_get_cepoll(), 
                     CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                     CEPOLL_RD_EVENT,
                     (const char *)"csocket_cnode_irecv",
                     (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv, 
                     (void *)csocket_cnode);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
    
    return (EC_TRUE);
}

/*---------------------------------------- DNS HEADER parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_header(const CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CDNS_HEADER *cdns_header)
{
    uint8_t       *data;
    UINT32         left;
    uint16_t      *p;
    uint16_t       flag;

    data = CBUFFER_DATA(CDNS_NODE_IN_BUF(cdns_node)) + (*pos);
    left = CBUFFER_USED(CDNS_NODE_IN_BUF(cdns_node)) - (*pos);

    if(12 > left)
    {
        return (EC_FALSE);
    }

    p = (uint16_t *)data;

    CDNS_HEADER_ID(cdns_header) = gdb_ntoh_uint16(*p);
    p ++;

    flag = gdb_ntoh_uint16(*p);
    p ++;

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_header: flag = %0x \n", flag);
 
    /*parse flag beg*/
    CDNS_HEADER_FLAG_RCODE(cdns_header)  = (uint16_t)(flag & 0x000F);
    flag >>= 4;

    CDNS_HEADER_FLAG_ZERO(cdns_header)   = (uint16_t)(flag & 0x0007);
    flag >>= 3;

    CDNS_HEADER_FLAG_RA(cdns_header)     = (uint16_t)(flag & 0x0001);
    flag >>= 1;

    CDNS_HEADER_FLAG_RD(cdns_header)     = (uint16_t)(flag & 0x0001);
    flag >>= 1;

    CDNS_HEADER_FLAG_TC(cdns_header)     = (uint16_t)(flag & 0x0001);
    flag >>= 1;

    CDNS_HEADER_FLAG_AA(cdns_header)     = (uint16_t)(flag & 0x0001);
    flag >>= 1;

    CDNS_HEADER_FLAG_OPCODE(cdns_header) = (uint16_t)(flag & 0x000F);
    flag >>= 4;
 
    CDNS_HEADER_FLAG_QR(cdns_header)     = (uint16_t)(flag & 0x0001);
    flag >>= 1;
    /*parse flag end*/
 
    CDNS_HEADER_Q_NUM(cdns_header) = gdb_ntoh_uint16(*p);
    p ++;
 
    CDNS_HEADER_R_NUM(cdns_header) = gdb_ntoh_uint16(*p);
    p ++;

    CDNS_HEADER_O_NUM(cdns_header) = gdb_ntoh_uint16(*p);
    p ++;

    CDNS_HEADER_E_NUM(cdns_header) = gdb_ntoh_uint16(*p);
    p ++;

    if(do_log(SEC_0150_CDNS, 9))
    {
        uint32_t idx;

        sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_header: header in byte => ");
        for(idx = 0; idx < 12; idx ++)
        {
            sys_print(LOGSTDOUT, "%02x ", data[ idx ]);
        }
        sys_print(LOGSTDOUT, "\n");
     
        sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_header: dns rsp header\n");
        cdns_header_print(LOGSTDOUT, cdns_header);
    }

    ASSERT(12 == ((void *)p - (void *)data));
    (*pos) += 12;
    return (EC_TRUE);
}

EC_BOOL cdns_make_header(CDNS_NODE *cdns_node, CDNS_HEADER *cdns_header)
{
    uint8_t        data[12];
    uint16_t      *p;
    uint16_t       flag;
 
    p = (uint16_t *)data;

    (*p) = gdb_hton_uint16(CDNS_HEADER_ID(cdns_header));
    p ++;

    /*make flag beg*/
    flag = 0;

    flag |= CDNS_HEADER_FLAG_QR(cdns_header);
    flag <<= 1;

    flag |= CDNS_HEADER_FLAG_OPCODE(cdns_header);
    flag <<= 4;   

    flag |= CDNS_HEADER_FLAG_AA(cdns_header);
    flag <<= 1;

    flag |= CDNS_HEADER_FLAG_TC(cdns_header);
    flag <<= 1;
 
    flag |= CDNS_HEADER_FLAG_RD(cdns_header);
    flag <<= 1;

    flag |= CDNS_HEADER_FLAG_RA(cdns_header);
    flag <<= 1;

    flag |= CDNS_HEADER_FLAG_ZERO(cdns_header);
    flag <<= 3;
 
    flag |= CDNS_HEADER_FLAG_RCODE(cdns_header);
    /*flag <<= 4;*/

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_make_header: flag = %0x \n", flag);
    (*p) = gdb_hton_uint16(flag);
    p ++;
    /*make flag end*/
 
    (*p) = gdb_hton_uint16(CDNS_HEADER_Q_NUM(cdns_header));
    p ++;

    (*p) = gdb_hton_uint16(CDNS_HEADER_R_NUM(cdns_header));
    p ++;

    (*p) = gdb_hton_uint16(CDNS_HEADER_O_NUM(cdns_header));
    p ++;

    (*p) = gdb_hton_uint16(CDNS_HEADER_E_NUM(cdns_header));
    p ++;

    if(do_log(SEC_0150_CDNS, 9))
    {
        uint32_t idx;

        sys_log(LOGSTDOUT, "[DEBUG] cdns_make_header: dns req header\n");
        cdns_header_print(LOGSTDOUT, cdns_header);

        sys_log(LOGSTDOUT, "[DEBUG] cdns_make_header: make header => ");
        for(idx = 0; idx < 12; idx ++)
        {
            sys_print(LOGSTDOUT, "%02x ", data[ idx ]);
        }
        sys_print(LOGSTDOUT, "\n");

    }
 
    if(EC_FALSE == chunk_append(CDNS_NODE_SEND_BUF(cdns_node), (uint8_t *)data, 12))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_make_header: append dns header to chunks failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*---------------------------------------- DNS HOST parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_host(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CSTRING *host)
{
    uint8_t       *data;
    UINT32         left;
 
    uint8_t       *p;
    uint8_t       *q;
    UINT32         len;

    data = CBUFFER_DATA(CDNS_NODE_IN_BUF(cdns_node)) + (*pos);
    left = CBUFFER_USED(CDNS_NODE_IN_BUF(cdns_node)) - (*pos);

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_host: pos = %ld\n", (*pos));

    if(do_log(SEC_0150_CDNS, 9))
    {
        UINT32   idx;

        sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_host: left bytes: [left %ld]\n", left);

        for(idx = 0; idx < left; idx ++)
        {
            sys_print(LOGSTDOUT, "%02x ", data[ idx ]);
        }
        sys_print(LOGSTDOUT, "\n");
    }
 
    len = 0;
    for(q = data; 0 != (*q) && len < left;)
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_host: count len: inc %u\n", (*q));
        len += (*q) + 1;
        q   += (*q) + 1;
    }
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_host: count len = %ld\n", len);

    cstring_expand_to(host, len, LOC_CDNS_0006);

    p = CSTRING_STR(host);
    BCOPY(data + 1, p, len);
    CSTRING_LEN(host) = len;

    len = (*data) + 1;
    for(q = p + (*data); 0 != (*q) && len < left;)
    {
        uint8_t seg_len;

        seg_len = (*q);
        (*q) = '.';
     
        len += seg_len + 1;
        q   += seg_len + 1;
    }
    len ++; /*skip the last 0x00*/

    (*pos) += len;
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_host: pos inc %ld\n", len);
    return (EC_TRUE);
}

EC_BOOL cdns_make_host(CDNS_NODE *cdns_node, const CSTRING *host)
{
    uint8_t       *beg;
    uint8_t       *end;
    UINT32         len;
    uint8_t       *s;
    uint8_t       *p;
    uint8_t       *c;/*counter*/

    len = CSTRING_LEN(host);
    if(CHUNK_ROOM(CDNS_NODE_SEND_BUF(cdns_node)) < len)
    {
        return (EC_FALSE);
    }
 
    beg = CSTRING_STR(host);
    end = beg + len;

    s = CHUNK_DATA(CDNS_NODE_SEND_BUF(cdns_node)) + CHUNK_USED(CDNS_NODE_SEND_BUF(cdns_node));

    p = s;
    c = p ++;/*c is counter*/

    (*c) = 0;

    for(; beg < end; beg ++, p ++)
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_make_host: handle %c\n", (*beg));
        if('.' == (*beg))
        {
            c = p;
            (*c) = 0;
            continue;
        }

        (*p) = (*beg);
        (*c) ++;
    }
    (*p ++) = 0x00; /*end*/

    len = (p - s);

    if(do_log(SEC_0150_CDNS, 9))
    {
        uint32_t idx;
        uint8_t *q;

        sys_log(LOGSTDOUT, "[DEBUG] cdns_make_host: query host: %.*s\n", CSTRING_LEN(host), CSTRING_STR(host));

        q = CHUNK_DATA(CDNS_NODE_SEND_BUF(cdns_node)) + CHUNK_USED(CDNS_NODE_SEND_BUF(cdns_node));
     
        sys_log(LOGSTDOUT, "[DEBUG] cdns_make_host: make host => [len %ld] ", len);
        for(idx = 0; idx < len; idx ++)
        {
            sys_print(LOGSTDOUT, "%02x ", q[ idx ]);
        }
        sys_print(LOGSTDOUT, "\n");
    }

    CHUNK_USED(CDNS_NODE_SEND_BUF(cdns_node)) += len;

    return (EC_TRUE);
}

/*---------------------------------------- general uint16_t parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_uint16(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, uint16_t *num)
{
    uint8_t       *data;
    UINT32         left;
 
    uint16_t      *p;

    data = CBUFFER_DATA(CDNS_NODE_IN_BUF(cdns_node)) + (*pos);
    left = CBUFFER_USED(CDNS_NODE_IN_BUF(cdns_node)) - (*pos);

    if(2 > left)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_uint16: left %ld bytes is insufficient to parse\n", left);
        return (EC_FALSE);
    }

    p = (uint16_t *)data;
    (*num) = gdb_ntoh_uint16(*p);

    (*pos) += 2;
    return (EC_TRUE);
}

EC_BOOL cdns_make_uint16(CDNS_NODE *cdns_node, const uint16_t num)
{
    uint8_t   data[2];
    uint16_t *p;

    p = (uint16_t *)data;

    (*p) = gdb_hton_uint16(num);
    if(EC_FALSE == chunk_append(CDNS_NODE_SEND_BUF(cdns_node), (uint8_t *)data, 2))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_make_uint16: append uint16 %u to chunks failed\n", num);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}
/*---------------------------------------- DNS QUERY parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_query(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CSTRING *host, uint16_t *qt, uint16_t *qc)
{
    if(EC_FALSE == cdns_parse_host(cdns_node, max_len, pos, host))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_query: parse host failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_query: parsed host: '%.*s'\n", CSTRING_LEN(host), CSTRING_STR(host));

    if(EC_FALSE == cdns_parse_uint16(cdns_node, max_len, pos, qt))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_query: parse QT failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_query: parsed QT: %x\n", (*qt));

    if(EC_FALSE == cdns_parse_uint16(cdns_node, max_len, pos, qc))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_query: parse QC failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_query: parsed QC: %x\n", (*qc));
 
    return (EC_TRUE);
}

EC_BOOL cdns_make_query(CDNS_NODE *cdns_node, const CSTRING *host, const uint16_t qt, const uint16_t qc)
{
    uint8_t        data[2];
    uint16_t      *p;
    UINT32         used;
 
    p = (uint16_t *)data;

    used = CHUNK_USED(CDNS_NODE_SEND_BUF(cdns_node));
 
    if(EC_FALSE == cdns_make_host(cdns_node, host))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_make_query: make host failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdns_make_uint16(cdns_node, qt))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_make_query: append dns QT to chunks failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdns_make_uint16(cdns_node, qc))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_make_query: append dns QC to chunks failed\n");
        return (EC_FALSE);
    }
 
    CDNS_NODE_QLEN(cdns_node) = CHUNK_USED(CDNS_NODE_SEND_BUF(cdns_node)) - used;

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_make_query: query len %ld\n", CDNS_NODE_QLEN(cdns_node));

    return (EC_TRUE);
}

/*---------------------------------------- DNS ANSWER parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_answer(CDNS_NODE *cdns_node, const uint32_t max_len, uint32_t *pos, CSTRING *host, uint16_t *at, uint16_t *ac, uint32_t *live, uint16_t *len, UINT32 *resource)
{
    uint8_t       *data;
    UINT32         left;
 
    uint16_t      *p;
    uint8_t       *q;
    uint16_t       check;
    uint16_t       idx;

    data = CBUFFER_DATA(CDNS_NODE_IN_BUF(cdns_node)) + (*pos);
    left = CBUFFER_USED(CDNS_NODE_IN_BUF(cdns_node)) - (*pos);

    if(do_log(SEC_0150_CDNS, 9))
    {
        UINT32 idx;
        sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_answer: when enter, left bytes: ");
        for(idx = 0; idx < left; idx ++)
        {
            sys_print(LOGSTDOUT, "%02x ", data[ idx ]);
        }
        sys_print(LOGSTDOUT, "\n");
    }

    p = (uint16_t *)data;

    check = gdb_ntoh_uint16(*p);
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_answer: check = %x\n", check);
    if(0 != (check & 0xC000))
    {
        uint32_t max_len_t;
        uint32_t pos_t;
        uint16_t qt;
        uint16_t qc;

        pos_t     = (uint32_t)(check & (~0xC000));
        max_len_t = (uint32_t)(CBUFFER_USED(CDNS_NODE_IN_BUF(cdns_node)) - pos_t);
     
        cdns_parse_query(cdns_node, max_len_t, &pos_t, host, &qt, &qc);

        p += 1; /*skip 0xCXXX*/

        if(do_log(SEC_0150_CDNS, 9))
        {
            UINT32 idx;
            sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_answer: after parse query, left bytes: ");
            for(idx = ((void *)p - (void *)data); idx < left; idx ++)
            {
                sys_print(LOGSTDOUT, "%02x ", data[ idx ]);
            }
            sys_print(LOGSTDOUT, "\n");
        }     
    }
    else
    {
        cdns_parse_host(cdns_node, max_len, pos, host);
        p = (uint16_t *)(data + (*pos));

        if(do_log(SEC_0150_CDNS, 9))
        {
            UINT32 idx;
            sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_answer: after parse host, left bytes: ");
            for(idx = ((void *)p - (void *)data); idx < left; idx ++)
            {
                sys_print(LOGSTDOUT, "%02x ", data[ idx ]);
            }
            sys_print(LOGSTDOUT, "\n");
        }      
    }

    if(do_log(SEC_0150_CDNS, 9))
    {
        uint32_t idx;
        sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_answer: after parse query, left bytes: ");
        for(idx = 0; idx < left; idx ++)
        {
            sys_print(LOGSTDOUT, "%02x ", data[ idx ]);
        }
        sys_print(LOGSTDOUT, "\n");
    }

    (*at) = gdb_ntoh_uint16(*p);
    p ++;
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_answer: at = %x\n", (*at));

    (*ac) = gdb_ntoh_uint16(*p);
    p ++;
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_answer: ac = %x\n", (*ac));

    (*live) = gdb_ntoh_uint32(*(uint32_t *)p);
    p ++;
    p ++;
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_answer: live = %x\n", (*live));

    (*len) = gdb_ntoh_uint16(*p);
    p ++;
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_answer: len = %x\n", (*len));

    q = (uint8_t *)p;
    (*resource) = 0;
    for(idx = 0; idx < (*len); idx ++, q ++)
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_answer: resource[%u] = %x\n", idx, (*q));
        (*resource) = ((*resource) << 8) | (*q);
    }
    p = (uint16_t *)q;
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_answer: resource = %x\n", (*resource));

    (*pos) += ((void *)p - (void *)data);
    return (EC_TRUE);
}

EC_BOOL cdns_make_answer(CDNS_NODE *cdns_node, const CSTRING *host, const uint16_t at, const uint16_t ac, const uint32_t live, const UINT32 resource, const uint16_t len)
{
    return (EC_FALSE);
}

/*---------------------------------------- DNS REQ/RSP parser and coder ----------------------------------------*/
EC_BOOL cdns_parse_rsp(CDNS_NODE *cdns_node, CDNS_RSP *cdns_rsp)
{
    CSOCKET_CNODE  *csocket_cnode;

    CDNS_HEADER     cdns_header;
 
    uint32_t max_len;
    uint32_t pos;

    uint16_t idx;

    csocket_cnode = CDNS_NODE_CSOCKET_CNODE(cdns_node);

    max_len = CBUFFER_USED(CDNS_NODE_IN_BUF(cdns_node));
    pos     = 0;

    cdns_header_init(&cdns_header);
    if(EC_FALSE == cdns_parse_header(cdns_node, max_len, &pos, &cdns_header))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_rsp: parse header failed\n");
        return (EC_FALSE);
    }

    /*check validity*/
    if(CDNS_NODE_ID(cdns_node) != CDNS_HEADER_ID(&cdns_header))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_rsp: parsed id %x but expect id %x\n",
                            CDNS_HEADER_ID(&cdns_header), CDNS_NODE_ID(cdns_node));
        return (EC_FALSE);
    }
 
    /*parse query*/
    if(0 < CDNS_HEADER_Q_NUM(&cdns_header))
    {
        dbg_log(SEC_0150_CDNS, 5)(LOGSTDOUT, "info:cdns_parse_rsp: ignore query questions\n");
        pos += CDNS_NODE_QLEN(cdns_node);
    }

    if(0 == CDNS_HEADER_R_NUM(&cdns_header))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_rsp: answer is empty\n");
        return (EC_FALSE);
    } 

    /*parse resource*/
    for(idx = 0; idx < CDNS_HEADER_R_NUM(&cdns_header); idx ++)
    {
        CSTRING     host;
        UINT32      resource;
        uint16_t    at;
        uint16_t    ac;
        uint32_t    live;
        uint16_t    len;

        CDNS_RSP_NODE *cdns_rsp_node;

        cstring_init(&host, NULL_PTR);
     
        if(EC_FALSE == cdns_parse_answer(cdns_node, max_len, &pos, &host, &at, &ac, &live, &len, &resource))
        {
            dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_rsp: parse %u# resource failed\n", idx);

            cstring_clean(&host);
            return (EC_FALSE);
        }

        cdns_rsp_node = cdns_rsp_node_new();
        if(NULL_PTR == cdns_rsp_node)
        {
            dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_parse_rsp: new cdns_rsp_node for host %.*s resource %x failed\n",
                                CSTRING_LEN(&host), CSTRING_STR(&host), resource);

            cstring_clean(&host);
            return (EC_FALSE);
        }

        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse_rsp: push host '%.*s' and resource %x\n",
                            CSTRING_LEN(&host), CSTRING_STR(&host), resource);

        cstring_init(CDNS_RSP_NODE_HOST(cdns_rsp_node)  , (UINT8 *)cstring_get_str(&host));
        cstring_init(CDNS_RSP_NODE_IPADDR(cdns_rsp_node), (UINT8 *)c_word_to_ipv4(resource));

        cstring_clean(&host);

        clist_push_back(cdns_rsp, (void *)cdns_rsp_node);

        if(do_log(SEC_0150_CDNS, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cdns_parse_rsp: push cdns_rsp_node %p is\n", cdns_rsp_node);
            cdns_rsp_node_print(LOGSTDOUT, cdns_rsp_node);
        }
    }

    /*parse oauth*/
    if(0 < CDNS_HEADER_O_NUM(&cdns_header))
    {
        dbg_log(SEC_0150_CDNS, 5)(LOGSTDOUT, "info:cdns_parse_rsp: ignore oauth\n");
    }

    /*parse extra*/
    if(0 < CDNS_HEADER_E_NUM(&cdns_header))
    {
        dbg_log(SEC_0150_CDNS, 5)(LOGSTDOUT, "info:cdns_parse_rsp: ignore extra\n");
    }

    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_parse: sockfd %d parse rsp done\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
         
    return (EC_TRUE);         
}

static uint16_t __cdns_gen_id()
{
    CTM   *cur_time;
    CTMV  *cur_timev;
    CTMV   ctmv;
 
    int tv_msec;
    int tv_usec;

    cur_timev = &ctmv;
    gettimeofday(cur_timev, NULL_PTR);
 
    cur_time = c_localtime_r(&(cur_timev->tv_sec));
    tv_msec = (int)(cur_timev->tv_usec / 1000);
    tv_usec = (int)(cur_timev->tv_usec % 1000);

    return (uint16_t)(((tv_msec << 8) | (tv_usec & 0xFF)) & 0xFFFF);
}

EC_BOOL cdns_make_req(CDNS_NODE *cdns_node, const CDNS_REQ *cdns_req)
{
    CDNS_HEADER     cdns_header;


    cdns_header_init(&cdns_header);

    CDNS_HEADER_ID(&cdns_header)            = __cdns_gen_id();
 
    CDNS_HEADER_FLAG_QR(&cdns_header)       = 0; /*0: query, 1: answer*/
    CDNS_HEADER_FLAG_OPCODE(&cdns_header)   = 0;
    CDNS_HEADER_FLAG_AA(&cdns_header)       = 0;
    CDNS_HEADER_FLAG_TC(&cdns_header)       = 0;
    CDNS_HEADER_FLAG_RD(&cdns_header)       = 1;
    CDNS_HEADER_FLAG_RA(&cdns_header)       = 0; /*0 for req*/
 
    CDNS_HEADER_Q_NUM(&cdns_header)    = 1;
    CDNS_HEADER_R_NUM(&cdns_header)    = 0;
    CDNS_HEADER_O_NUM(&cdns_header)    = 0;
    CDNS_HEADER_E_NUM(&cdns_header)    = 0;

    if(EC_FALSE == cdns_make_header(cdns_node, &cdns_header))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_make_req: make header failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdns_make_query(cdns_node, CDNS_REQ_HOST(cdns_req), CDNS_QT_A, CDNS_QC_INET))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_make_req: make query failed\n");
        return (EC_FALSE);
    }

    CDNS_NODE_ID(cdns_node) = CDNS_HEADER_ID(&cdns_header);/*save req id*/
    return (EC_TRUE);
}

/*---------------------------------------- CONNECTION INIT and CLOSE HANDLER ----------------------------------------*/
EC_BOOL cdns_node_close(CDNS_NODE *cdns_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;

    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    /* umount */
    CDNS_NODE_CSOCKET_CNODE(cdns_node) = NULL_PTR;

    /**
     * not free cdns_node but release ccond
     * which will pull routine to the starting point of sending dns request
     **/
    if(NULL_PTR != CDNS_NODE_CROUTINE_COND(cdns_node) && BIT_FALSE == CDNS_NODE_COROUTINE_RESTORE(cdns_node))
    {
        dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_close: socket %d retore coroutine %p\n", sockfd, CDNS_NODE_CROUTINE_COND(cdns_node));

        CDNS_NODE_COROUTINE_RESTORE(cdns_node) = BIT_TRUE;
        croutine_cond_release(CDNS_NODE_CROUTINE_COND(cdns_node), LOC_CDNS_0007);
    }

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;/*trigger socket closing*/
 
    dbg_log(SEC_0150_CDNS, 9)(LOGSTDOUT, "[DEBUG] cdns_node_close: release cdns_node and unmount socket %d done\n", sockfd);
    return (EC_TRUE);
}


/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * CDNS_REQ and CDNS_RSP interfaces
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
CDNS_REQ *cdns_req_new()
{
    CDNS_REQ *cdns_req;

    alloc_static_mem(MM_CDNS_REQ, &cdns_req, LOC_CDNS_0008);
    if(NULL_PTR == cdns_req)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_req_new: new cdns_req failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdns_req_init(cdns_req))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_req_new: init cdns_req failed\n");
        free_static_mem(MM_CDNS_REQ, cdns_req, LOC_CDNS_0009);
        return (NULL_PTR);
    }

    return (cdns_req);
}

EC_BOOL cdns_req_init(CDNS_REQ *cdns_req)
{
    CDNS_REQ_IPADDR(cdns_req) = CMPI_ERROR_IPADDR;
    CDNS_REQ_PORT(cdns_req)   = CMPI_ERROR_SRVPORT;

    cstring_init(CDNS_REQ_HOST(cdns_req), NULL_PTR);

    return (EC_TRUE);
}

EC_BOOL cdns_req_clean(CDNS_REQ *cdns_req)
{
    CDNS_REQ_IPADDR(cdns_req) = CMPI_ERROR_IPADDR;
    CDNS_REQ_PORT(cdns_req)   = CMPI_ERROR_SRVPORT;

    cstring_clean(CDNS_REQ_HOST(cdns_req));
    return (EC_TRUE);
}

EC_BOOL cdns_req_free(CDNS_REQ *cdns_req)
{
    if(NULL_PTR != cdns_req)
    {
        cdns_req_clean(cdns_req);
        free_static_mem(MM_CDNS_REQ, cdns_req, LOC_CDNS_0010);
    }
 
    return (EC_TRUE);
}

void cdns_req_print(LOG *log, const CDNS_REQ *cdns_req)
{
    sys_log(log, "cdns_req_print: ipaddr: %s\n", CDNS_REQ_IPADDR_STR(cdns_req));
    sys_log(log, "cdns_req_print: port  : %ld\n" , CDNS_REQ_PORT(cdns_req));

    sys_log(log, "cdns_req_print: host  : %.*s\n",
                        CSTRING_LEN(CDNS_REQ_HOST(cdns_req)), CSTRING_STR(CDNS_REQ_HOST(cdns_req)));

    return;
}

EC_BOOL cdns_req_set_server(CDNS_REQ *cdns_req, const char *server)
{
    char  server_saved[128];
    char *fields[2];
    size_t len;

    len = strlen(server);
    if(len >= sizeof(server_saved)/sizeof(server_saved[0]))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_req_set_server: server '%s' too long\n",
                            server);
        return (EC_FALSE);
    }
 
    BCOPY(server, (char *)server_saved, len + 1);
 
    if(2 != c_str_split(server_saved, ":", fields, 2))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_req_set_server: invalid server '%s'\n",
                            server_saved);
        return (EC_FALSE);
    }
 
    CDNS_REQ_IPADDR(cdns_req) = c_ipv4_to_word(fields[0]);
    CDNS_REQ_PORT(cdns_req)   = c_str_to_word(fields[1]);

    return (EC_TRUE);
}

EC_BOOL cdns_req_set_ipaddr(CDNS_REQ *cdns_req, const char *ipaddr)
{
    CDNS_REQ_IPADDR(cdns_req) = c_ipv4_to_word(ipaddr);

    return (EC_TRUE);
}

EC_BOOL cdns_req_set_port(CDNS_REQ *cdns_req, const char *port)
{
    CDNS_REQ_PORT(cdns_req) = c_str_to_word(port);

    return (EC_TRUE);
}

EC_BOOL cdns_req_set_host(CDNS_REQ *cdns_req, const char *host)
{
    cstring_append_str(CDNS_REQ_HOST(cdns_req), (UINT8 *)host);
    return (EC_TRUE);
}

CDNS_RSP *cdns_rsp_new()
{
    CDNS_RSP *cdns_rsp;

    alloc_static_mem(MM_CDNS_RSP, &cdns_rsp, LOC_CDNS_0011);
    if(NULL_PTR == cdns_rsp)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_rsp_new: new cdns_rsp failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdns_rsp_init(cdns_rsp))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_rsp_new: init cdns_rsp failed\n");
        free_static_mem(MM_CDNS_RSP, cdns_rsp, LOC_CDNS_0012);
        return (NULL_PTR);
    }

    return (cdns_rsp);
}

EC_BOOL cdns_rsp_init(CDNS_RSP *cdns_rsp)
{
    clist_init(cdns_rsp, MM_CDNS_RSP_NODE, LOC_CDNS_0013);

    return (EC_TRUE);
}

EC_BOOL cdns_rsp_clean(CDNS_RSP *cdns_rsp)
{
    clist_clean(cdns_rsp, (CLIST_DATA_DATA_CLEANER)cdns_rsp_node_free);
    return (EC_TRUE);
}

EC_BOOL cdns_rsp_free(CDNS_RSP *cdns_rsp)
{
    if(NULL_PTR != cdns_rsp)
    {
        cdns_rsp_clean(cdns_rsp);
        free_static_mem(MM_CDNS_RSP, cdns_rsp, LOC_CDNS_0014);
    }
 
    return (EC_TRUE);
}

void cdns_rsp_print(LOG *log, const CDNS_RSP *cdns_rsp)
{
    sys_log(log, "cdns_rsp_print: rsp: \n");
    clist_print(log, cdns_rsp, (CLIST_DATA_DATA_PRINT)cdns_rsp_node_print);
    return;
}

CDNS_RSP_NODE *cdns_rsp_node_new()
{
    CDNS_RSP_NODE *cdns_rsp_node;

    alloc_static_mem(MM_CDNS_RSP_NODE, &cdns_rsp_node, LOC_CDNS_0015);
    if(NULL_PTR == cdns_rsp_node)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_rsp_node_new: new cdns_rsp_node failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdns_rsp_node_init(cdns_rsp_node))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_rsp_node_new: init cdns_rsp_node failed\n");
        free_static_mem(MM_CDNS_RSP_NODE, cdns_rsp_node, LOC_CDNS_0016);
        return (NULL_PTR);
    }

    return (cdns_rsp_node);
}

EC_BOOL cdns_rsp_node_init(CDNS_RSP_NODE *cdns_rsp_node)
{
    cstring_init(CDNS_RSP_NODE_HOST(cdns_rsp_node), NULL_PTR);
    cstring_init(CDNS_RSP_NODE_IPADDR(cdns_rsp_node), NULL_PTR);
    return (EC_TRUE);
}

EC_BOOL cdns_rsp_node_clean(CDNS_RSP_NODE *cdns_rsp_node)
{
    cstring_clean(CDNS_RSP_NODE_HOST(cdns_rsp_node));
    cstring_clean(CDNS_RSP_NODE_IPADDR(cdns_rsp_node));
    return (EC_TRUE);
}

EC_BOOL cdns_rsp_node_free(CDNS_RSP_NODE *cdns_rsp_node)
{
    if(NULL_PTR != cdns_rsp_node)
    {
        cdns_rsp_node_clean(cdns_rsp_node);
        free_static_mem(MM_CDNS_RSP_NODE, cdns_rsp_node, LOC_CDNS_0017);
    }
 
    return (EC_TRUE);
}

void cdns_rsp_node_print(LOG *log, const CDNS_RSP_NODE *cdns_rsp_node)
{
    sys_log(log, "cdns_rsp_node_print: host  : %.*s\n",
                        CSTRING_LEN(CDNS_RSP_NODE_HOST(cdns_rsp_node)), CSTRING_STR(CDNS_RSP_NODE_HOST(cdns_rsp_node)));

    sys_log(log, "cdns_rsp_node_print: ipaddr: %.*s\n",
                        CSTRING_LEN(CDNS_RSP_NODE_IPADDR(cdns_rsp_node)), CSTRING_STR(CDNS_RSP_NODE_IPADDR(cdns_rsp_node)));

    return;
}

EC_BOOL cdns_request(const CDNS_REQ *cdns_req, CDNS_RSP *cdns_rsp)
{
    CDNS_NODE     *cdns_node;
    CROUTINE_COND *croutine_cond;
  
    cdns_node = cdns_node_new();
    if(NULL_PTR == cdns_node)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_request: new cdns_node failed\n");
        return (EC_FALSE);
    }

    croutine_cond = croutine_cond_new(0/*never timeout*/, LOC_CDNS_0018);
    if(NULL_PTR == croutine_cond)
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_request: new croutine_cond failed\n");
        cdns_node_free(cdns_node);
        return (EC_FALSE);
    }
    CDNS_NODE_CROUTINE_COND(cdns_node) = croutine_cond;
 
    if(EC_FALSE == cdns_node_create(cdns_node, cdns_req))
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_request: connect server %s:%ld failed\n",
                            CDNS_REQ_IPADDR_STR(cdns_req), CDNS_REQ_PORT(cdns_req));
                         
        cdns_node_free(cdns_node);
        return (EC_FALSE);
    }

    CDNS_NODE_REQ(cdns_node) = (CDNS_REQ *)cdns_req;
    CDNS_NODE_RSP(cdns_node) = (CDNS_RSP *)cdns_rsp;
 
    croutine_cond_reserve(croutine_cond, 1, LOC_CDNS_0019);
    croutine_cond_wait(croutine_cond, LOC_CDNS_0020);

    __COROUTINE_CATCH_EXCEPTION() { /*exception*/
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error: cdns_request: coroutine was cancelled\n"); 

        cdns_node_disconnect(cdns_node);
        
    }__COROUTINE_HANDLE_EXCEPTION();

    ASSERT(NULL_PTR == CDNS_NODE_CSOCKET_CNODE(cdns_node));
 
    /**
     *  when come back, check CDNS_NODE_RECV_COMPLETE flag.
     *  if false, exception happened. and return false
     **/
    if(BIT_FALSE == CDNS_NODE_RECV_COMPLETE(cdns_node)) /*exception happened*/
    {
        dbg_log(SEC_0150_CDNS, 0)(LOGSTDOUT, "error:cdns_request: exception happened\n");

        cdns_node_free(cdns_node);
        return (EC_FALSE);
    }

    cdns_node_disconnect(cdns_node);

    /*unmount cdns_req and cdns_rsp from cdns_node*/
    CDNS_NODE_REQ(cdns_node) = NULL_PTR;
    CDNS_NODE_RSP(cdns_node) = NULL_PTR; 

    cdns_node_free(cdns_node);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

