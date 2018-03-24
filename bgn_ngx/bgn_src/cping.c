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
#include "cmisc.h"
#include "cmpic.inc"

#include "task.h"
#include "tasks.h"
#include "csocket.h"

#include "cepoll.h"

#include "coroutine.h"

#include "ccallback.h"

#include "cping.h"

CPING_NODE *cping_node_new()
{
    CPING_NODE *cping_node;

    alloc_static_mem(MM_CPING_NODE, &cping_node, LOC_CPING_0001);
    if(NULL_PTR == cping_node)
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_node_new: new cping_node failed\n");
        return (NULL_PTR);
    }
    cping_node_init(cping_node);
    return (cping_node);
}
EC_BOOL cping_node_init(CPING_NODE *cping_node)
{
    CPING_NODE_SRV_IPADDR(cping_node)           = CMPI_ERROR_IPADDR;
    CPING_NODE_SRV_PORT(cping_node)             = CMPI_ERROR_SRVPORT;

    CPING_NODE_COMPLETE_FLAG(cping_node)        = BIT_FALSE;

    CPING_NODE_CSOCKET_CNODE(cping_node)        = NULL_PTR;
    CPING_NODE_CROUTINE_COND(cping_node)        = NULL_PTR;

    CPING_NODE_S_NSEC(cping_node)               = 0;
    CPING_NODE_S_MSEC(cping_node)               = 0;

    CPING_NODE_E_NSEC(cping_node)               = 0;
    CPING_NODE_E_MSEC(cping_node)               = 0;

    return (EC_TRUE);
}

EC_BOOL cping_node_clean(CPING_NODE *cping_node)
{
    if(NULL_PTR != CPING_NODE_CROUTINE_COND(cping_node))
    {
        croutine_cond_free(CPING_NODE_CROUTINE_COND(cping_node), LOC_CPING_0002);
        CPING_NODE_CROUTINE_COND(cping_node) = NULL_PTR;
    }

    CPING_NODE_SRV_IPADDR(cping_node)           = CMPI_ERROR_IPADDR;
    CPING_NODE_SRV_PORT(cping_node)             = CMPI_ERROR_SRVPORT;

    CPING_NODE_COMPLETE_FLAG(cping_node)        = BIT_FALSE;

    CPING_NODE_CSOCKET_CNODE(cping_node)        = NULL_PTR;

    CPING_NODE_S_NSEC(cping_node)               = 0;
    CPING_NODE_S_MSEC(cping_node)               = 0;

    CPING_NODE_E_NSEC(cping_node)               = 0;
    CPING_NODE_E_MSEC(cping_node)               = 0;

    return (EC_TRUE);
}

EC_BOOL cping_node_free(CPING_NODE *cping_node)
{
    if(NULL_PTR != cping_node)
    {
        cping_node_clean(cping_node);
        free_static_mem(MM_CPING_NODE, cping_node, LOC_CPING_0003);
    }

    return (EC_TRUE);
}

void cping_node_print(LOG *log, const CPING_NODE *cping_node)
{
    sys_log(log, "cping_node_print: cping_node: %p, server '%s:%ld'\n",
                 cping_node,
                 CPING_NODE_SRV_IPADDR_STR(cping_node),
                 CPING_NODE_SRV_PORT(cping_node));

    return;
}

EC_BOOL cping_node_icheck(CPING_NODE *cping_node, CSOCKET_CNODE *csocket_cnode)
{
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_node_icheck: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    CPING_NODE_COMPLETE_FLAG(cping_node) = BIT_TRUE;
    CPING_NODE_REQ_TIME_WHEN_END(cping_node); /*record end time*/

    /* unbind */
    CPING_NODE_CSOCKET_CNODE(cping_node) = NULL_PTR;

    /*note: return EC_DONE will trigger connection complete*/

    dbg_log(SEC_0063_CPING, 9)(LOGSTDOUT, "[DEBUG] cping_node_icheck: sockfd %d return done\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return (EC_DONE);
}

EC_BOOL cping_node_complete(CPING_NODE *cping_node, CSOCKET_CNODE *csocket_cnode)
{
    /* unbind */
    CPING_NODE_CSOCKET_CNODE(cping_node) = NULL_PTR;

    /**
     * not free cping_node but release ccond
     * which will pull routine to the starting point of sending ping request
     **/
    if(NULL_PTR != CPING_NODE_CROUTINE_COND(cping_node))
    {
        croutine_cond_release(CPING_NODE_CROUTINE_COND(cping_node), LOC_CPING_0004);
    }

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;

    dbg_log(SEC_0063_CPING, 9)(LOGSTDOUT, "[DEBUG] cping_node_complete: sockfd %d return true\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return (EC_TRUE);

}

EC_BOOL cping_node_shutdown(CPING_NODE *cping_node, CSOCKET_CNODE *csocket_cnode)
{
    /*not unbind*/

    /**
     * not free cping_node but release ccond
     * which will pull routine to the starting point of sending ping request
     **/
    if(NULL_PTR != CPING_NODE_CROUTINE_COND(cping_node))
    {
        croutine_cond_release(CPING_NODE_CROUTINE_COND(cping_node), LOC_CPING_0005);
    }

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;

    dbg_log(SEC_0063_CPING, 9)(LOGSTDOUT, "[DEBUG] cping_node_shutdown: sockfd %d return true\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return (EC_TRUE);
}

EC_BOOL cping_node_close(CPING_NODE *cping_node, CSOCKET_CNODE *csocket_cnode)
{
    /*not unbind*/

    /**
     * not free cping_node but release ccond
     * which will pull routine to the starting point of sending http request
     **/
    if(NULL_PTR != CPING_NODE_CROUTINE_COND(cping_node))
    {
        croutine_cond_release(CPING_NODE_CROUTINE_COND(cping_node), LOC_CPING_0006);
    }

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;

    dbg_log(SEC_0063_CPING, 9)(LOGSTDOUT, "[DEBUG] cping_node_close: sockfd %d return true\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return (EC_TRUE);
}

/*disconnect socket connection*/
EC_BOOL cping_node_disconnect(CPING_NODE *cping_node)
{
    if(NULL_PTR != CPING_NODE_CSOCKET_CNODE(cping_node))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CPING_NODE_CSOCKET_CNODE(cping_node);

        /*umount*/
        CPING_NODE_CSOCKET_CNODE(cping_node) = NULL_PTR;

        dbg_log(SEC_0063_CPING, 5)(LOGSTDOUT, "[DEBUG] cping_node_disconnect: close sockfd %d\n",
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));

        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);
    }

    return (EC_TRUE);
}

EC_BOOL cping_node_set_socket_callback(CPING_NODE *cping_node, CSOCKET_CNODE *csocket_cnode)
{
    csocket_cnode_push_send_callback(csocket_cnode,
                                     (const char *)"cping_node_icheck",
                                     (UINT32)cping_node, (UINT32)cping_node_icheck);

    csocket_cnode_push_complete_callback(csocket_cnode,
                                     (const char *)"cping_node_complete",
                                     (UINT32)cping_node, (UINT32)cping_node_complete);

    csocket_cnode_push_close_callback(csocket_cnode,
                                     (const char *)"cping_node_close",
                                     (UINT32)cping_node, (UINT32)cping_node_close);

    csocket_cnode_push_timeout_callback(csocket_cnode,
                                     (const char *)"cping_node_close",
                                     (UINT32)cping_node, (UINT32)cping_node_close);

    csocket_cnode_push_shutdown_callback(csocket_cnode,
                                     (const char *)"cping_node_shutdown",
                                     (UINT32)cping_node, (UINT32)cping_node_shutdown);

    return (EC_TRUE);
}

EC_BOOL cping_node_set_socket_epoll(CPING_NODE *cping_node, CSOCKET_CNODE *csocket_cnode)
{
    cepoll_set_event(task_brd_default_get_cepoll(),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    CEPOLL_WR_EVENT,
                    (const char *)"csocket_cnode_isend",
                    (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                    (void *)csocket_cnode);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;

    cepoll_set_complete(task_brd_default_get_cepoll(),
                   CSOCKET_CNODE_SOCKFD(csocket_cnode),
                   (const char *)"csocket_cnode_icomplete",
                   (CEPOLL_EVENT_HANDLER)csocket_cnode_icomplete,
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

EC_BOOL cping_node_check(CPING_NODE *cping_node)
{
    CSOCKET_CNODE *csocket_cnode;

    UINT32         client_ipaddr;
    UINT32         client_port;
    int            sockfd;

    if(EC_FALSE == csocket_connect(CPING_NODE_SRV_IPADDR(cping_node), CPING_NODE_SRV_PORT(cping_node),
                                   CSOCKET_IS_NONBLOCK_MODE,
                                   &sockfd, &client_ipaddr, &client_port ))
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_node_check: connect server %s:%ld failed\n",
                            CPING_NODE_SRV_IPADDR_STR(cping_node),
                            CPING_NODE_SRV_PORT(cping_node));
        return (EC_FALSE);
    }

    dbg_log(SEC_0063_CPING, 9)(LOGSTDOUT, "[DEBUG] cping_node_check: sockfd %d connecting to server %s:%ld\n",
                        sockfd,
                        CPING_NODE_SRV_IPADDR_STR(cping_node),
                        CPING_NODE_SRV_PORT(cping_node));

    if(EC_FALSE == csocket_is_connected(sockfd))/*not adaptive to unix domain socket*/
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_node_check: sockfd %d to server %s:%ld is not connected\n",
                        sockfd,
                        CPING_NODE_SRV_IPADDR_STR(cping_node),
                        CPING_NODE_SRV_PORT(cping_node));
        csocket_close(sockfd);
        return (EC_FALSE);
    }

    if(do_log(SEC_0063_CPING, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cping_node_check: client tcp stat:\n");
        csocket_tcpi_stat_print(LOGSTDOUT, sockfd);
    }

    csocket_cnode = csocket_cnode_new(LOC_CPING_0007);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_node_check:new csocket cnode for sockfd %d to server %s:%ld failed\n",
                        sockfd,
                        CPING_NODE_SRV_IPADDR_STR(cping_node),
                        CPING_NODE_SRV_PORT(cping_node));
        csocket_close(sockfd);
        return (EC_FALSE);
    }

    CSOCKET_CNODE_SOCKFD(csocket_cnode)         = sockfd;
    CSOCKET_CNODE_TYPE(csocket_cnode )          = CSOCKET_TYPE_TCP;
    CSOCKET_CNODE_IPADDR(csocket_cnode)         = CPING_NODE_SRV_IPADDR(cping_node);
    CSOCKET_CNODE_SRVPORT(csocket_cnode)        = CPING_NODE_SRV_PORT(cping_node);
    CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode)  = client_ipaddr;
    CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)    = client_port;

    /* mount */
    CPING_NODE_CSOCKET_CNODE(cping_node)        = csocket_cnode;

    return (EC_TRUE);
}

EC_BOOL cping_check(const UINT32 srv_ipaddr, const UINT32 srv_port, UINT32 *elapsed_msec)
{
    CPING_NODE    *cping_node;
    CROUTINE_COND *croutine_cond;

    cping_node = cping_node_new();
    if(NULL_PTR == cping_node)
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_check: new cping_node failed\n");
        return (EC_FALSE);
    }
    CPING_NODE_SRV_IPADDR(cping_node) = srv_ipaddr;
    CPING_NODE_SRV_PORT(cping_node)   = srv_port;

    croutine_cond = croutine_cond_new(0/*never timeout*/, LOC_CPING_0008);
    if(NULL_PTR == croutine_cond)
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_check: new croutine_cond failed\n");

        cping_node_free(cping_node);
        return (EC_FALSE);
    }
    CPING_NODE_CROUTINE_COND(cping_node) = croutine_cond;

    CPING_NODE_REQ_TIME_WHEN_START(cping_node); /*record start time*/

    if(EC_FALSE == cping_node_check(cping_node))
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_check: check server %s:%ld failed\n",
                            CPING_NODE_SRV_IPADDR_STR(cping_node),
                            CPING_NODE_SRV_PORT(cping_node));

        cping_node_free(cping_node);
        return (EC_FALSE);
    }

    cping_node_set_socket_callback(cping_node, CPING_NODE_CSOCKET_CNODE(cping_node));
    cping_node_set_socket_epoll(cping_node, CPING_NODE_CSOCKET_CNODE(cping_node));

    croutine_cond_reserve(croutine_cond, 1, LOC_CPING_0009);
    croutine_cond_wait(croutine_cond, LOC_CPING_0010);

    __COROUTINE_CATCH_EXCEPTION() { /*exception*/
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_check: coroutine was cancelled\n");

        cping_node_disconnect(cping_node);

    }__COROUTINE_HANDLE_EXCEPTION();

    if(BIT_FALSE == CPING_NODE_COMPLETE_FLAG(cping_node))/*exception happened*/
    {
        dbg_log(SEC_0063_CPING, 0)(LOGSTDOUT, "error:cping_check: exception happened\n");

        cping_node_free(cping_node);
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR == CPING_NODE_CSOCKET_CNODE(cping_node));

    if(NULL_PTR != elapsed_msec)
    {
        (*elapsed_msec) = CPING_NODE_REQ_ELAPSED_MSEC(cping_node);
    }

    cping_node_disconnect(cping_node);

    cping_node_free(cping_node);

    dbg_log(SEC_0063_CPING, 9)(LOGSTDOUT, "[DEBUG] cping_check: %s:%ld OK\n",
                     c_word_to_ipv4(srv_ipaddr), srv_port);

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

