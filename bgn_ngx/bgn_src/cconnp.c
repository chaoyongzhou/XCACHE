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
#include <unistd.h>
#include <string.h>

#include "type.h"
#include "log.h"

#include "cstring.h"

#include "csocket.h"

#include "cmpic.inc"
#include "cmpie.h"
#include "cmisc.h"

#include "cparacfg.inc"

#include "cepoll.h"
#include "cconnp.h"

CCONNP *cconnp_new()
{
    CCONNP *cconnp;
    alloc_static_mem(MM_CCONNP, &cconnp, LOC_CCONNP_0001);
    if(NULL_PTR == cconnp)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_new: failed to alloc CCONNP\n");
        return (NULL_PTR);
    }

    cconnp_init(cconnp);
    return (cconnp);
}

EC_BOOL cconnp_init(CCONNP *cconnp)
{
    if(NULL_PTR != cconnp)
    {
        CCONNP_SRV_IPADDR(cconnp)              = CMPI_ERROR_IPADDR;
        CCONNP_SRV_PORT(cconnp)                = CMPI_ERROR_SRVPORT;

        CCONNP_SRV_TCID(cconnp)                = CMPI_ERROR_TCID;
        CCONNP_SRV_COMM(cconnp)                = CMPI_ERROR_COMM;
        CCONNP_SRV_SIZE(cconnp)                = 0;

        cqueue_init(CCONNP_IDLE_CONN_QUEUE(cconnp), MM_CSOCKET_CNODE, LOC_CCONNP_0002);
    }

    return (EC_TRUE);
}

EC_BOOL cconnp_clean(CCONNP *cconnp)
{
    if(NULL_PTR != cconnp)
    {
        CCONNP_SRV_IPADDR(cconnp)              = CMPI_ERROR_IPADDR;
        CCONNP_SRV_PORT(cconnp)                = CMPI_ERROR_SRVPORT;

        CCONNP_SRV_TCID(cconnp)                = CMPI_ERROR_TCID;
        CCONNP_SRV_COMM(cconnp)                = CMPI_ERROR_COMM;
        CCONNP_SRV_SIZE(cconnp)                = 0;

        cqueue_clean(CCONNP_IDLE_CONN_QUEUE(cconnp), (CQUEUE_DATA_DATA_CLEANER)csocket_cnode_free);
    }

    return (EC_TRUE);
}

EC_BOOL cconnp_free(CCONNP *cconnp)
{
    if(NULL_PTR != cconnp)
    {
        cconnp_clean(cconnp);
        free_static_mem(MM_CCONNP, cconnp, LOC_CCONNP_0003);
    }
    return (EC_TRUE);
}

CSOCKET_CNODE *cconnp_reserve(CCONNP *cconnp)
{
    CSOCKET_CNODE *csocket_cnode;

    /*reserve one idle*/
    csocket_cnode = cqueue_pop(CCONNP_IDLE_CONN_QUEUE(cconnp));
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_reserve: server %s:%ld has no idle conn\n",
                        CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp));
        return (NULL_PTR);
    }

    ASSERT(BIT_TRUE == CSOCKET_CNODE_REUSING(csocket_cnode));

    if(BIT_TRUE == CSOCKET_CNODE_READING(csocket_cnode))
    {   
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode)     = BIT_FALSE;
    }

    /*when csocket_cnode was released into connp, some handlers were pushed to callback. */
    /*here need to clear it*/
    csocket_cnode_reset_recv_callback(csocket_cnode);
    csocket_cnode_reset_timeout_callback(csocket_cnode);
    csocket_cnode_reset_shutdown_callback(csocket_cnode);

    /*not sure the csocket_cnode would be returned back or not*/
  
    dbg_log(SEC_0154_CCONNP, 5)(LOGSTDOUT, "[DEBUG] cconnp_reserve: pop sockfd %d to server %s:%ld done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp));  
    return (csocket_cnode);
}

/*return csocket_cnode to connection pool*/
EC_BOOL cconnp_release(CCONNP *cconnp, CSOCKET_CNODE *csocket_cnode)
{
    CQUEUE_DATA *cqueue_data;

    ASSERT(BIT_TRUE == CSOCKET_CNODE_REUSING(csocket_cnode));
 
    cqueue_data = cqueue_push(CCONNP_IDLE_CONN_QUEUE(cconnp), (void *)csocket_cnode);
    if(NULL_PTR == cqueue_data)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_release: push sockfd %d to server %s:%ld failed\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp));
                        
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;
        return (EC_TRUE);
    }

    /*clean event*/
    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode)     = BIT_FALSE;   
    CSOCKET_CNODE_WRITING(csocket_cnode)     = BIT_FALSE;   
   
    /*reset*/
    csocket_cnode_reset_recv_callback(csocket_cnode);
    csocket_cnode_reset_send_callback(csocket_cnode);
    csocket_cnode_reset_complete_callback(csocket_cnode);
    csocket_cnode_reset_close_callback(csocket_cnode);
    csocket_cnode_reset_timeout_callback(csocket_cnode);

    /*push*/
    csocket_cnode_push_recv_callback(csocket_cnode, 
                                      (const char *)"cconnp_erase", 
                                      (UINT32)cconnp,
                                      (UINT32)cconnp_erase); 

     csocket_cnode_push_timeout_callback(csocket_cnode, 
                                      (const char *)"cconnp_erase", 
                                      (UINT32)cconnp,
                                      (UINT32)cconnp_erase);

    csocket_cnode_push_shutdown_callback(csocket_cnode, 
                                      (const char *)"cconnp_erase", 
                                      (UINT32)cconnp,
                                      (UINT32)cconnp_erase);
                                      
    /*when idle, client should never receive data to server. if RD event happen, connection must be broken*/
    cepoll_set_event(task_brd_default_get_cepoll(),
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    CEPOLL_RD_EVENT,
                    (const char *)"csocket_cnode_irecv",
                    (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                    (void *)csocket_cnode);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
    
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
                 
    dbg_log(SEC_0154_CCONNP, 5)(LOGSTDOUT, "[DEBUG] cconnp_release: push sockfd %d to server %s:%ld done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp)); 
    return (EC_TRUE);
}

EC_BOOL cconnp_erase(CCONNP *cconnp, CSOCKET_CNODE *csocket_cnode)
{
    CQUEUE_DATA *cqueue_data;
    
    if(BIT_TRUE == CSOCKET_CNODE_REUSING(csocket_cnode))
    {
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;
    }
    
    cqueue_data = cqueue_search(CCONNP_IDLE_CONN_QUEUE(cconnp), (void *)csocket_cnode, NULL_PTR);
    if(NULL_PTR == cqueue_data)
    {
        dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_erase: not found sockfd %d to server %s:%ld\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp));     
        return (EC_TRUE);
    }
    cqueue_erase(CCONNP_IDLE_CONN_QUEUE(cconnp), cqueue_data);

    dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_erase: erase sockfd %d to server %s:%ld done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                    CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp)); 
    
    return (EC_TRUE);
}

void cconnp_print(LOG *log, const CCONNP *cconnp)
{
    if(NULL_PTR != cconnp)
    {
        sys_log(LOGSTDOUT, "cconnp_print: cconnp %p: srv %s:%ld, tcid %s, idle num %ld\n",
                            cconnp,
                            CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp),
                            CCONNP_SRV_TCID_STR(cconnp),
                            cqueue_size(CCONNP_IDLE_CONN_QUEUE(cconnp)));
    }

    return;
}

int cconnp_cmp(const CCONNP *cconnp_1, const CCONNP *cconnp_2)
{
    if(do_log(SEC_0154_CCONNP, 9))
    {
        if(CMPI_ANY_TCID != CCONNP_SRV_TCID(cconnp_1) && CMPI_ANY_TCID != CCONNP_SRV_TCID(cconnp_2))
        {
            dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_cmp: "
                                                   "(tcid %s, ip %s, port %ld) <---> (tcid %s, ip %s, port %ld)\n",
                                                   c_word_to_ipv4(CCONNP_SRV_TCID(cconnp_1)), 
                                                   c_word_to_ipv4(CCONNP_SRV_IPADDR(cconnp_1)),
                                                   CCONNP_SRV_PORT(cconnp_1),
                                                   
                                                   c_word_to_ipv4(CCONNP_SRV_TCID(cconnp_2)), 
                                                   c_word_to_ipv4(CCONNP_SRV_IPADDR(cconnp_2)),
                                                   CCONNP_SRV_PORT(cconnp_2));
        }
        else
        {
            dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_cmp: "
                                                   "(ip %s, port %ld) <---> (ip %s, port %ld)\n",
                                                   c_word_to_ipv4(CCONNP_SRV_IPADDR(cconnp_1)),
                                                   CCONNP_SRV_PORT(cconnp_1),
                                                   
                                                   c_word_to_ipv4(CCONNP_SRV_IPADDR(cconnp_2)),
                                                   CCONNP_SRV_PORT(cconnp_2));
        }
    }                                       
    if(CMPI_ANY_TCID != CCONNP_SRV_TCID(cconnp_1) && CMPI_ANY_TCID != CCONNP_SRV_TCID(cconnp_2))
    {
        if(CCONNP_SRV_TCID(cconnp_1) > CCONNP_SRV_TCID(cconnp_2))
        {
            return (1);
        }
        if(CCONNP_SRV_TCID(cconnp_1) < CCONNP_SRV_TCID(cconnp_2))
        {
            return (-1);
        }
    }

    if(CCONNP_SRV_IPADDR(cconnp_1) > CCONNP_SRV_IPADDR(cconnp_2))
    {
        return (1);
    }
    if(CCONNP_SRV_IPADDR(cconnp_1) < CCONNP_SRV_IPADDR(cconnp_2))
    {
        return (-1);
    }

    if(CCONNP_SRV_PORT(cconnp_1) > CCONNP_SRV_PORT(cconnp_2))
    {
        return (1);
    }
    if(CCONNP_SRV_PORT(cconnp_1) < CCONNP_SRV_PORT(cconnp_2))
    {
        return (-1);
    }

    return (0);
}

/*------------------------------------------------------------------------------------------------------------------*/
CCONNP_MGR *cconnp_mgr_new()
{
    CCONNP_MGR *cconnp_mgr;
    alloc_static_mem(MM_CCONNP_MGR, &cconnp_mgr, LOC_CCONNP_0004);
    if(NULL_PTR == cconnp_mgr)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_mgr_new: failed to alloc CCONNP_MGR\n");
        return (NULL_PTR);
    }

    cconnp_mgr_init(cconnp_mgr);
    return (cconnp_mgr);
}

EC_BOOL cconnp_mgr_init(CCONNP_MGR *cconnp_mgr)
{
    if(NULL_PTR != cconnp_mgr)
    {
        crb_tree_init(CCONNP_MGR_TREE(cconnp_mgr), (CRB_DATA_CMP)cconnp_cmp, (CRB_DATA_FREE)cconnp_free, (CRB_DATA_PRINT)cconnp_print);
    }

    return (EC_TRUE);
}

EC_BOOL cconnp_mgr_clean(CCONNP_MGR *cconnp_mgr)
{
    if(NULL_PTR != cconnp_mgr)
    {
        crb_tree_clean(CCONNP_MGR_TREE(cconnp_mgr));
    }

    return (EC_TRUE);
}

EC_BOOL cconnp_mgr_free(CCONNP_MGR *cconnp_mgr)
{
    if(NULL_PTR != cconnp_mgr)
    {
        cconnp_mgr_clean(cconnp_mgr);
        free_static_mem(MM_CCONNP_MGR, cconnp_mgr, LOC_CCONNP_0005);
    }
    return (EC_TRUE);
}

void cconnp_mgr_print(LOG *log, const CCONNP_MGR *cconnp_mgr)
{
    if(NULL_PTR != cconnp_mgr)
    {
        sys_log(LOGSTDOUT, "cconnp_mgr_print: cconnp_mgr %p: cconnp tree:\n", cconnp_mgr);
        crb_tree_print(log, CCONNP_MGR_TREE(cconnp_mgr));
    }

    return;
}

CCONNP *cconnp_mgr_add(CCONNP_MGR *cconnp_mgr, const UINT32 srv_tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    CCONNP      *cconnp;
    CRB_NODE    *crb_node;

    cconnp = cconnp_new();
    if(NULL_PTR == cconnp)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_mgr_add: new cconnp failed\n");
        return (NULL_PTR);
    }

    CCONNP_SRV_TCID(cconnp)   = srv_tcid;
    CCONNP_SRV_IPADDR(cconnp) = srv_ipaddr;
    CCONNP_SRV_PORT(cconnp)   = srv_port;
 
    crb_node = crb_tree_insert_data(CCONNP_MGR_TREE(cconnp_mgr), (void *)cconnp);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_mgr_add: insert cconnp srv %s:%ld, tcid %s failed\n",
                            CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp),
                            CCONNP_SRV_TCID_STR(cconnp));
        cconnp_free(cconnp);
        return (NULL_PTR);
    }

    if(CRB_NODE_DATA(crb_node) != cconnp)
    {
        dbg_log(SEC_0154_CCONNP, 1)(LOGSTDOUT, "[DEBUG] cconnp_mgr_add: found duplicate cconnp srv %s:%ld, tcid %s\n",
                            CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp),
                            CCONNP_SRV_TCID_STR(cconnp));
        cconnp_free(cconnp);
        return (CRB_NODE_DATA(crb_node));
    }

    dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_mgr_add: add cconnp srv %s:%ld, tcid %s done\n",
                        CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp),
                        CCONNP_SRV_TCID_STR(cconnp));
    return (cconnp);
}

CCONNP *cconnp_mgr_search(CCONNP_MGR *cconnp_mgr, const UINT32 srv_tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    CCONNP      *cconnp;
    CCONNP      *cconnp_searched;
    CRB_NODE    *crb_node;

    cconnp = cconnp_new();
    if(NULL_PTR == cconnp)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_mgr_search: new cconnp failed\n");
        return (NULL_PTR);
    }

    CCONNP_SRV_TCID(cconnp)   = srv_tcid;
    CCONNP_SRV_IPADDR(cconnp) = srv_ipaddr;
    CCONNP_SRV_PORT(cconnp)   = srv_port;
 
    crb_node = crb_tree_search_data(CCONNP_MGR_TREE(cconnp_mgr), (void *)cconnp);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_mgr_search: search cconnp srv %s:%ld, tcid %s failed\n",
                            CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp),
                            CCONNP_SRV_TCID_STR(cconnp));
        cconnp_free(cconnp);
        return (NULL_PTR);
    }

    cconnp_free(cconnp);

    cconnp_searched = CRB_NODE_DATA(crb_node);
    dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_mgr_search: found cconnp srv %s:%ld, tcid %s\n",
                        CCONNP_SRV_IPADDR_STR(cconnp_searched), CCONNP_SRV_PORT(cconnp_searched),
                        CCONNP_SRV_TCID_STR(cconnp_searched));
    return (cconnp_searched);
}

CSOCKET_CNODE *cconnp_mgr_reserve(CCONNP_MGR *cconnp_mgr, const UINT32 srv_tcid, const UINT32 srv_ipaddr, const UINT32 srv_port)
{
    CCONNP        *cconnp;
    CSOCKET_CNODE *csocket_cnode;

    cconnp = cconnp_mgr_search(cconnp_mgr, srv_tcid, srv_ipaddr, srv_port);
    if(NULL_PTR == cconnp)
    {
        dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_mgr_reserve: not found cconnp srv %s:%ld, tcid %s\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port,
                            c_word_to_ipv4(srv_tcid)); 
        return (NULL_PTR);
    }

    csocket_cnode = cconnp_reserve(cconnp);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_mgr_reserve: reserve csocket_cnode from cconnp srv %s:%ld, tcid %s failed\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port,
                            c_word_to_ipv4(srv_tcid)); 
        return (NULL_PTR);
    }

    dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_mgr_reserve: reserve csocket_cnode from cconnp srv %s:%ld, tcid %s done\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port,
                            c_word_to_ipv4(srv_tcid)); 
    return (csocket_cnode);
}

/*return csocket_cnode to connection pool*/
EC_BOOL cconnp_mgr_release(CCONNP_MGR *cconnp_mgr, CSOCKET_CNODE *csocket_cnode)
{
    CCONNP        *cconnp;

    if(BIT_FALSE == CSOCKET_CNODE_REUSING(csocket_cnode))
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_mgr_release: sockfd %d to srv %s:%ld, tcid %s is not reusing\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                            CSOCKET_CNODE_TCID_STR(csocket_cnode)); 
        return (EC_FALSE);
    }

    cconnp = cconnp_mgr_search(cconnp_mgr, CSOCKET_CNODE_TCID(csocket_cnode), CSOCKET_CNODE_IPADDR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode));
    if(NULL_PTR == cconnp)
    {
        dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_mgr_release: not found cconnp srv %s:%ld, tcid %s for sockfd %d => unset reusing\n",
                            CSOCKET_CNODE_IPADDR_STR(csocket_cnode), CSOCKET_CNODE_SRVPORT(csocket_cnode),
                            CSOCKET_CNODE_TCID_STR(csocket_cnode),
                            CSOCKET_CNODE_SOCKFD(csocket_cnode)); 
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;
        return (EC_TRUE);
    }

    if(EC_FALSE == cconnp_release(cconnp, csocket_cnode))
    {
        dbg_log(SEC_0154_CCONNP, 0)(LOGSTDOUT, "error:cconnp_mgr_reserve: release sockfd %d to cconnp srv %s:%ld, tcid %s failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp),
                            CCONNP_SRV_TCID_STR(cconnp));   
        return (EC_FALSE);
    }

    dbg_log(SEC_0154_CCONNP, 9)(LOGSTDOUT, "[DEBUG] cconnp_mgr_reserve: reserve sockfd %d to cconnp srv %s:%ld, tcid %s done\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CCONNP_SRV_IPADDR_STR(cconnp), CCONNP_SRV_PORT(cconnp),
                        CCONNP_SRV_TCID_STR(cconnp));

    /*
     * note:
     *  here return EC_DONE would prevent ccallback_list_run_and_check from running more
     *  due to callback-list being reset in cconnp_release
     */
    return (EC_DONE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

