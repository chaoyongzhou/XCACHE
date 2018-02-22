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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "csocket.h"
#include "clist.h"

#include "cmpic.inc"
#include "task.h"
#include "cthread.h"

#include "csrv.h"
#include "cssl.h"
#include "cepoll.h"

CSRV *csrv_new()
{
    CSRV *csrv;
    alloc_static_mem(MM_CSRV, &csrv, LOC_CSRV_0001);
    if(NULL_PTR == csrv)
    {
        dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_new: new csrv failed\n");
        return (NULL_PTR);
    }
    csrv_init(csrv);
    return (csrv);
}

EC_BOOL csrv_init(CSRV *csrv)
{
    CSRV_IPADDR(csrv)               = CMPI_ERROR_IPADDR;
    CSRV_PORT(csrv)                 = CMPI_ERROR_SRVPORT;
    CSRV_SOCKFD(csrv)               = CMPI_ERROR_SOCKFD;
    CSRV_UNIX_SOCKFD(csrv)          = CMPI_ERROR_SOCKFD;
    CSRV_MD_ID(csrv)                = CMPI_ERROR_MODI;

    CSRV_INIT_CSOCKET_CNODE(csrv)   = NULL_PTR;
    CSRV_ADD_CSOCKET_CNODE(csrv)    = NULL_PTR;
    CSRV_DEL_CSOCKET_CNODE(csrv)    = NULL_PTR;

    CSRV_RD_NAME(csrv)              = NULL_PTR;
    CSRV_WR_NAME(csrv)              = NULL_PTR;
    CSRV_TIMEOUT_NAME(csrv)         = NULL_PTR;
    CSRV_COMPLETE_NAME(csrv)        = NULL_PTR;
    CSRV_CLOSE_NAME(csrv)           = NULL_PTR;    
 
    CSRV_RD_EVENT_HANDLER(csrv)     = NULL_PTR;
    CSRV_WR_EVENT_HANDLER(csrv)     = NULL_PTR;
    CSRV_TIMEOUT_HANDLER(csrv)      = NULL_PTR;
    CSRV_COMPLETE_HANDLER(csrv)     = NULL_PTR;
    CSRV_CLOSE_HANDLER(csrv)        = NULL_PTR;

    CSRV_CSSL_NODE(csrv)            = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL csrv_clean(CSRV *csrv)
{
    if(CMPI_ERROR_SOCKFD != CSRV_SOCKFD(csrv))
    {
        csocket_close(CSRV_SOCKFD(csrv));
        CSRV_SOCKFD(csrv)  = CMPI_ERROR_SOCKFD;
    }

    if(CMPI_ERROR_SOCKFD != CSRV_UNIX_SOCKFD(csrv))
    {
        csocket_close(CSRV_UNIX_SOCKFD(csrv));
        CSRV_UNIX_SOCKFD(csrv)  = CMPI_ERROR_SOCKFD;
    }

    CSRV_IPADDR(csrv)  = CMPI_ERROR_IPADDR;
    CSRV_PORT(csrv)    = CMPI_ERROR_SRVPORT;
    CSRV_MD_ID(csrv)   = CMPI_ERROR_MODI;

    CSRV_INIT_CSOCKET_CNODE(csrv)   = NULL_PTR;
    CSRV_ADD_CSOCKET_CNODE(csrv)    = NULL_PTR;
    CSRV_DEL_CSOCKET_CNODE(csrv)    = NULL_PTR;

    CSRV_RD_NAME(csrv)              = NULL_PTR;
    CSRV_WR_NAME(csrv)              = NULL_PTR;
    CSRV_TIMEOUT_NAME(csrv)         = NULL_PTR;
    CSRV_COMPLETE_NAME(csrv)        = NULL_PTR;
    CSRV_CLOSE_NAME(csrv)           = NULL_PTR;     
 
    CSRV_RD_EVENT_HANDLER(csrv)     = NULL_PTR;
    CSRV_WR_EVENT_HANDLER(csrv)     = NULL_PTR;
    CSRV_TIMEOUT_HANDLER(csrv)      = NULL_PTR;
    CSRV_COMPLETE_HANDLER(csrv)     = NULL_PTR;
    CSRV_CLOSE_HANDLER(csrv)        = NULL_PTR;

    if(NULL_PTR != CSRV_CSSL_NODE(csrv))
    {
        cssl_node_free(CSRV_CSSL_NODE(csrv));
        CSRV_CSSL_NODE(csrv) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL csrv_free(CSRV *csrv)
{
    if(NULL_PTR != csrv)
    {
        csrv_clean(csrv);
        free_static_mem(MM_CSRV, csrv, LOC_CSRV_0002);
    }
    return (EC_TRUE);
}

CSRV * csrv_start(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 md_id)
{
    CSRV *csrv;
    int srv_sockfd;
    int srv_unix_sockfd;

    if(CMPI_ERROR_MODI == md_id)
    {
        dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_start: md id is invalid\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == csocket_listen(srv_ipaddr, srv_port, &srv_sockfd))
    {
        dbg_log(SEC_0112_CSRV, 0)(LOGSTDERR, "error:csrv_start: failed to listen on %s:%ld\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port);
        return (NULL_PTR);
    }

    srv_unix_sockfd = CMPI_ERROR_SOCKFD;
#if 0
    if(EC_FALSE == csocket_unix_listen(srv_ipaddr, srv_port, &srv_unix_sockfd))
    {
        dbg_log(SEC_0112_CSRV, 0)(LOGSTDERR, "error:csrv_start: failed to listen on unix@%s:%ld\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port);
    }
#endif
    csrv = csrv_new();
    if(NULL_PTR == csrv)
    {
        dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_start: new csrv failed, close srv sockfd %d\n", srv_sockfd);
        csocket_close(srv_sockfd);
        return (NULL_PTR);
    }

    CSRV_IPADDR(csrv)               = srv_ipaddr;
    CSRV_PORT(csrv)                 = srv_port;
    CSRV_SOCKFD(csrv)               = srv_sockfd;
    CSRV_UNIX_SOCKFD(csrv)          = srv_unix_sockfd;

    CSRV_MD_ID(csrv)                = md_id;
    
    CSRV_CSSL_NODE(csrv)            = NULL_PTR;

    cepoll_set_event(task_brd_default_get_cepoll(),
                      CSRV_SOCKFD(csrv),
                      CEPOLL_RD_EVENT,
                      (const char *)"csrv_accept",
                      (CEPOLL_EVENT_HANDLER)csrv_accept,
                      (void *)csrv);
#if 0
    if(CMPI_ERROR_SOCKFD != CSRV_UNIX_SOCKFD(csrv))
    {
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSRV_UNIX_SOCKFD(csrv),
                          CEPOLL_RD_EVENT,
                          (const char *)"csrv_unix_accept",
                          (CEPOLL_EVENT_HANDLER)csrv_unix_accept,
                          (void *)csrv); 
    }
#endif 

    dbg_log(SEC_0112_CSRV, 5)(LOGSTDOUT, "csrv_start: start srv sockfd %d on port %s:%ld\n",
                       srv_sockfd, c_word_to_ipv4(srv_ipaddr), srv_port);
    return (csrv);
}

EC_BOOL csrv_end(CSRV *csrv)
{
    return csrv_free(csrv);
}

EC_BOOL csrv_set_init_csocket_cnode_handler(CSRV *csrv, CSRV_INIT_CSOCKET_CNODE init_csocket_cnode)
{
    CSRV_INIT_CSOCKET_CNODE(csrv)   = init_csocket_cnode;
    return (EC_TRUE);
}

EC_BOOL csrv_set_add_csocket_cnode_handler(CSRV *csrv, CSRV_ADD_CSOCKET_CNODE add_csocket_cnode)
{
    CSRV_ADD_CSOCKET_CNODE(csrv)   = add_csocket_cnode;
    return (EC_TRUE);
}

EC_BOOL csrv_set_del_csocket_cnode_handler(CSRV *csrv, CSRV_DEL_CSOCKET_CNODE del_csocket_cnode)
{
    CSRV_DEL_CSOCKET_CNODE(csrv)   = del_csocket_cnode;
    return (EC_TRUE);
}

EC_BOOL csrv_set_read_handler(CSRV *csrv, const char *name, CSRV_RD_HANDLER_FUNC handler)
{
    CSRV_RD_NAME(csrv)              = name;
    CSRV_RD_EVENT_HANDLER(csrv)     = handler;
    return (EC_TRUE);
}

EC_BOOL csrv_set_write_handler(CSRV *csrv, const char *name, CSRV_WR_HANDLER_FUNC handler)
{
    CSRV_WR_NAME(csrv)              = name;
    CSRV_WR_EVENT_HANDLER(csrv)     = handler;
    return (EC_TRUE);
}

EC_BOOL csrv_set_timeout_handler(CSRV *csrv, const uint32_t timeout_nsec, const char *name, CSRV_TIMEOUT_HANDLER_FUNC handler)
{
    CSRV_TIMEOUT_NSEC(csrv)         = timeout_nsec;
    CSRV_TIMEOUT_NAME(csrv)         = name;
    CSRV_TIMEOUT_HANDLER(csrv)      = handler;
    return (EC_TRUE);
}

EC_BOOL csrv_set_complete_handler(CSRV *csrv, const char *name, CSRV_COMPLETE_HANDLER_FUNC handler)
{
    CSRV_COMPLETE_NAME(csrv)        = name;
    CSRV_COMPLETE_HANDLER(csrv)     = handler;
    return (EC_TRUE);
}

EC_BOOL csrv_set_close_handler(CSRV *csrv, const char *name, CSRV_CLOSE_HANDLER_FUNC handler)
{
    CSRV_CLOSE_NAME(csrv)        = name;
    CSRV_CLOSE_HANDLER(csrv)     = handler;
    return (EC_TRUE);
}

EC_BOOL csrv_accept_once(CSRV *csrv, EC_BOOL *continue_flag)
{
    UINT32  client_ipaddr; 
    UINT32  client_port;
    EC_BOOL ret;
    int     client_conn_sockfd; 

    ret = csocket_accept(CSRV_SOCKFD(csrv), &(client_conn_sockfd), CSOCKET_IS_NONBLOCK_MODE, &(client_ipaddr), &(client_port));

    if(EC_TRUE == ret)
    {
        CSOCKET_CNODE *csocket_cnode;
     
        dbg_log(SEC_0112_CSRV, 1)(LOGSTDOUT, "csrv_accept_once: handle new sockfd %d\n", client_conn_sockfd);

        csocket_cnode = csocket_cnode_new(LOC_CSRV_0003);/*here do not know the remote client srv port*/
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_accept_once:failed to alloc csocket cnode for sockfd %d, hence close it\n", client_conn_sockfd);
            csocket_close(client_conn_sockfd);
            return (EC_FALSE);
        }

        CSOCKET_CNODE_SOCKFD(csocket_cnode) = client_conn_sockfd;
        CSOCKET_CNODE_TYPE(csocket_cnode )  = CSOCKET_TYPE_TCP;
        CSOCKET_CNODE_IPADDR(csocket_cnode) = client_ipaddr;

        if(NULL_PTR != CSRV_ADD_CSOCKET_CNODE(csrv))
        {
            CSRV_ADD_CSOCKET_CNODE(csrv)(CSRV_MD_ID(csrv), csocket_cnode);
        }
     

        /*note: CSOCKET_CNODE_PKT_HDR will be used for specific purpose*/
        BSET(CSOCKET_CNODE_PKT_HDR(csocket_cnode), 0, CSOCKET_CNODE_PKT_HDR_SIZE);

        CSOCKET_CNODE_MODI(csocket_cnode) = CSRV_MD_ID(csrv);
     
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          CSRV_RD_NAME(csrv),
                          (CEPOLL_EVENT_HANDLER)CSRV_RD_EVENT_HANDLER(csrv),
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
        
        cepoll_set_complete(task_brd_default_get_cepoll(),
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CSRV_COMPLETE_NAME(csrv),
                           (CEPOLL_EVENT_HANDLER)CSRV_COMPLETE_HANDLER(csrv),
                           (void *)csocket_cnode);
                        
        cepoll_set_shutdown(task_brd_default_get_cepoll(),
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CSRV_CLOSE_NAME(csrv),
                           (CEPOLL_EVENT_HANDLER)CSRV_CLOSE_HANDLER(csrv),
                           (void *)csocket_cnode);

        cepoll_set_timeout(task_brd_default_get_cepoll(),
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CSRV_TIMEOUT_NSEC(csrv),
                           CSRV_TIMEOUT_NAME(csrv),
                           (CEPOLL_EVENT_HANDLER)CSRV_TIMEOUT_HANDLER(csrv),
                           (void *)csocket_cnode);

    }

    (*continue_flag) = ret;
 
    return (EC_TRUE);
}

EC_BOOL csrv_accept(CSRV *csrv)
{
    UINT32   idx;
    UINT32   num;
    EC_BOOL  continue_flag;

    num = CSRV_ACCEPT_MAX_NUM;
    for(idx = 0; idx < num; idx ++)
    {
        if(EC_FALSE == csrv_accept_once(csrv, &continue_flag))
        {
            dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_accept: accept No. %ld client failed where expect %ld clients\n", idx, num);
            return (EC_FALSE);
        }

        if(EC_FALSE == continue_flag)
        {
            dbg_log(SEC_0112_CSRV, 9)(LOGSTDOUT, "[DEBUG] csrv_accept: accept No. %ld client terminate where expect %ld clients\n", idx, num);
            break;
        }     
    }

    return (EC_TRUE);
}

EC_BOOL csrv_unix_accept_once(CSRV *csrv, EC_BOOL *continue_flag)
{
    UINT32  client_ipaddr; 
    EC_BOOL ret;
    int     client_conn_sockfd; 

    ret = csocket_unix_accept(CSRV_UNIX_SOCKFD(csrv), &(client_conn_sockfd), CSOCKET_IS_NONBLOCK_MODE);
    if(EC_TRUE == ret)
    {
        CSOCKET_CNODE *csocket_cnode;

        client_ipaddr = c_ipv4_to_word((const char *)"127.0.0.1");
     
        dbg_log(SEC_0112_CSRV, 1)(LOGSTDOUT, "csrv_unix_accept_once: handle new sockfd %d\n", client_conn_sockfd);

        csocket_cnode = csocket_cnode_unix_new(CMPI_ERROR_TCID, client_conn_sockfd, CSOCKET_TYPE_TCP, client_ipaddr, CMPI_ERROR_SRVPORT);/*here do not know the remote client srv port*/
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_unix_accept_once:failed to alloc csocket cnode for sockfd %d, hence close it\n", client_conn_sockfd);
            csocket_close(client_conn_sockfd);
            return (EC_FALSE);
        }

        if(NULL_PTR != CSRV_ADD_CSOCKET_CNODE(csrv))
        {
            CSRV_ADD_CSOCKET_CNODE(csrv)(CSRV_MD_ID(csrv), csocket_cnode);
        }

        /*note: CSOCKET_CNODE_PKT_HDR will be used for specific purpose*/
        BSET(CSOCKET_CNODE_PKT_HDR(csocket_cnode), 0, CSOCKET_CNODE_PKT_HDR_SIZE);

        CSOCKET_CNODE_MODI(csocket_cnode) = CSRV_MD_ID(csrv);
     
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          CSRV_RD_NAME(csrv),
                          (CEPOLL_EVENT_HANDLER)CSRV_RD_EVENT_HANDLER(csrv),
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
        
        cepoll_set_complete(task_brd_default_get_cepoll(),
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CSRV_COMPLETE_NAME(csrv),
                           (CEPOLL_EVENT_HANDLER)CSRV_COMPLETE_HANDLER(csrv),
                           (void *)csocket_cnode);
                        
        cepoll_set_shutdown(task_brd_default_get_cepoll(),
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CSRV_CLOSE_NAME(csrv),
                           (CEPOLL_EVENT_HANDLER)CSRV_CLOSE_HANDLER(csrv),
                           (void *)csocket_cnode);

        cepoll_set_timeout(task_brd_default_get_cepoll(),
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CSRV_TIMEOUT_NSEC(csrv),
                           CSRV_TIMEOUT_NAME(csrv),
                           (CEPOLL_EVENT_HANDLER)CSRV_TIMEOUT_HANDLER(csrv),
                           (void *)csocket_cnode);

    }

    (*continue_flag) = ret;
 
    return (EC_TRUE);
}
EC_BOOL csrv_unix_accept(CSRV *csrv)
{
    UINT32   idx;
    UINT32   num;
    EC_BOOL  continue_flag;

    num = CSRV_ACCEPT_MAX_NUM;
    for(idx = 0; idx < num; idx ++)
    {
        if(EC_FALSE == csrv_unix_accept_once(csrv, &continue_flag))
        {
            dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_unix_accept: accept No. %ld client failed where expect %ld clients\n", idx, num);
            return (EC_FALSE);
        }

        if(EC_FALSE == continue_flag)
        {
            dbg_log(SEC_0112_CSRV, 9)(LOGSTDOUT, "[DEBUG] csrv_unix_accept: accept No. %ld client terminate where expect %ld clients\n", idx, num);
            break;
        }     
    }

    return (EC_TRUE);
}


EC_BOOL csrv_select(CSRV *csrv, int *ret)
{
    FD_CSET *fd_cset;
    int max_sockfd;

    struct timeval tv;

    tv.tv_sec  = 0;
    tv.tv_usec = /*1*/0;

    max_sockfd = 0;

    fd_cset = safe_malloc(sizeof(FD_CSET), LOC_CSRV_0004);
    if(NULL_PTR == fd_cset)
    {
        dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_select: malloc FD_CSET with size %d failed\n", sizeof(FD_CSET));
        return (EC_FALSE);
    }
 
    csocket_fd_clean(fd_cset);
    csocket_fd_set(CSRV_SOCKFD(csrv), fd_cset, &max_sockfd);
    if(EC_FALSE == csocket_select(max_sockfd + 1, fd_cset, NULL_PTR, NULL_PTR, &tv, ret))
    {
        safe_free(fd_cset, LOC_CSRV_0005);
        return (EC_FALSE);
    }
 
    safe_free(fd_cset, LOC_CSRV_0006);
    return (EC_TRUE);
}

EC_BOOL csrv_process(CSRV *csrv, struct _CSOCKET_CNODE *csocket_cnode)
{
    /*TODO:*/
    dbg_log(SEC_0112_CSRV, 0)(LOGSTDERR, "error:csrv_process: TO BO DO!!!\n");
    return (EC_FALSE);
}

EC_BOOL csrv_handle(CSRV *csrv, CSOCKET_CNODE *csocket_cnode)
{
    for(;;)
    {
        if(EC_FALSE == csocket_is_connected(CSOCKET_CNODE_SOCKFD(csocket_cnode)))
        {
            if(NULL_PTR != CSRV_DEL_CSOCKET_CNODE(csrv))
            {
                CSRV_DEL_CSOCKET_CNODE(csrv)(CSRV_MD_ID(csrv), csocket_cnode);
            }
            csocket_cnode_close(csocket_cnode);
         
            break;
        }
        dbg_log(SEC_0112_CSRV, 9)(LOGSTDOUT, "[DEBUG] csrv_handle: CSOCKET_CNODE_SOCKFD %d is connected\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));

        if(EC_FALSE == csrv_process(csrv, csocket_cnode))
        {
            dbg_log(SEC_0112_CSRV, 0)(LOGSTDOUT, "error:csrv_handle: process failed on sockfd %d where md id %ld, close it\n",
                                CSOCKET_CNODE_SOCKFD(csocket_cnode), CSRV_MD_ID(csrv));
         
            if(NULL_PTR != CSRV_DEL_CSOCKET_CNODE(csrv))
            {
                CSRV_DEL_CSOCKET_CNODE(csrv)(CSRV_MD_ID(csrv), csocket_cnode);
            }
            csocket_cnode_close(csocket_cnode);
            break;
        }
    }
    return (EC_FALSE);
}

EC_BOOL csrv_do_once(CSRV *csrv)
{
    int      ret;
    EC_BOOL  continue_flag;
    if(EC_FALSE == csrv_select(csrv, &ret))
    {
        dbg_log(SEC_0112_CSRV, 0)(LOGSTDERR, "error:csrv_do_once: select failed\n");

        return (EC_FALSE);
    }

    if( 0 < ret )
    {
        csrv_accept_once(csrv, &continue_flag);
    }
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

